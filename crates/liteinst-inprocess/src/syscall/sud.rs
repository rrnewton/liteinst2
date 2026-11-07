//! Linux Syscall User Dispatch trap substrate.
//!
//! This module installs the gateway/restorer, SIGSYS custody, per-thread
//! registration, first-profile trap forwarding, and site recording. With the
//! `trap` strategy it never rewrites a syscall site. With the `lazypoline`
//! strategy, each first trap additionally marks the recorded site pending;
//! a later explicit normal-context [`SudInstallation::apply_pending_patches`]
//! call publishes caller-certified zpoline rewrites for pending sites (the
//! handler itself never patches), and patched sites then execute through
//! the sled with genuine forwarding through this substrate's gateway.

use std::ffi::c_void;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use liteinst::contracts::{FailureStage, QuiescenceLease};
use liteinst::trampoline::{HookCallback, HookContext};

use crate::raw;
use crate::syscall::zpoline::{
    DualMapping, InstalledZpolineSet, PreparedZpolineSet, ZpolineMetrics, ZpolineSite,
};
use crate::syscall::{
    DiscoverySubstrate, FallbackPolicy, SiteOutcome, SyscallRefusal, SyscallStrategy,
    SyscallStrategyConfig, first_profile_supports,
};

const PR_SET_SYSCALL_USER_DISPATCH: i32 = 59;
const PR_SYS_DISPATCH_OFF: usize = 0;
const PR_SYS_DISPATCH_ON: usize = 1;
const SYS_USER_DISPATCH_CODE: i32 = 2;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const SA_RESTORER: usize = 0x0400_0000;
const ALT_STACK_BYTES: usize = 256 * 1024;
const MAX_ACTIVE_THREADS: usize = 64;
const GATEWAY_RAW_OFFSET: usize = 0;
const GATEWAY_RESTORER_OFFSET: usize = 32;

const OWNER_EMPTY: u8 = 0;
const OWNER_INSTALLING: u8 = 1;
const OWNER_INSTALLED: u8 = 2;
const OWNER_POISONED: u8 = 3;

static SUD_OWNER: AtomicU8 = AtomicU8::new(OWNER_EMPTY);
static SUD_HANDLER_ACTIVE: AtomicUsize = AtomicUsize::new(0);
static SUD_CLOSING: AtomicBool = AtomicBool::new(false);

fn wait_for_handler_quiescence() {
    while SUD_HANDLER_ACTIVE.load(Ordering::Acquire) != 0 {
        std::thread::yield_now();
    }
}
static SUD_STATE: AtomicPtr<SudState> = AtomicPtr::new(std::ptr::null_mut());

type GatewaySyscall = unsafe extern "C" fn(i64, i64, i64, i64, i64, i64, i64) -> i64;

#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct KernelAction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

#[repr(C)]
struct KernelSiginfo {
    signo: i32,
    errno: i32,
    code: i32,
    _pad: i32,
    call_addr: usize,
    syscall: i32,
    arch: u32,
    _rest: [u8; 96],
}

const PATCH_TRAPPING: u8 = 0;
const PATCH_PENDING: u8 = 1;
const PATCH_REWRITTEN: u8 = 2;
const PATCH_TRAP_PERMANENT: u8 = 3;

struct SudSiteSlot {
    site_pc: AtomicU64,
    last_nr: AtomicU64,
    hits: AtomicU64,
    patch_state: AtomicU8,
}

struct SudState {
    lazy: bool,
    gateway_start: AtomicU64,
    gateway_end: AtomicU64,
    sites: Box<[SudSiteSlot]>,
    site_count: AtomicUsize,
    registered_tids: [AtomicU64; MAX_ACTIVE_THREADS],
    active_tids: [AtomicU64; MAX_ACTIVE_THREADS],
    traps: AtomicU64,
    forwarded: AtomicU64,
    signal_returns: AtomicU64,
    fast_path_calls: AtomicU64,
    refused: AtomicU64,
    nested: AtomicU64,
    active_overflow: AtomicU64,
    foreign: AtomicU64,
    overflow: AtomicU64,
}

/// One syscall site observed through the SUD trap substrate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SudSiteRecord {
    /// Native `syscall` instruction address (`call_addr - 2`).
    pub site_pc: u64,
    /// Most recent low-32-bit syscall number observed at this site.
    pub last_syscall_nr: u32,
    /// Number of authenticated traps recorded for this site.
    pub hits: u64,
}

/// Lazypoline disposition of one recorded site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LazyPatchState {
    /// Trap strategy (or lazypoline before the first-trap transition is
    /// observed): the site only traps and forwards.
    Trapping,
    /// Discovered by a first trap and awaiting certified patch application.
    Pending,
    /// Rewritten by a successful patch batch; executions take the sled.
    Rewritten,
    /// Patch application left this site to the trap outcome permanently
    /// (ineligible or a before-write failure under the trap fallback).
    TrapPermanent,
}

fn lazy_patch_state(byte: u8) -> LazyPatchState {
    match byte {
        PATCH_PENDING => LazyPatchState::Pending,
        PATCH_REWRITTEN => LazyPatchState::Rewritten,
        PATCH_TRAP_PERMANENT => LazyPatchState::TrapPermanent,
        _ => LazyPatchState::Trapping,
    }
}

/// One recorded site with its lazypoline disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LazySiteRecord {
    /// Native `syscall` instruction address (`call_addr - 2`).
    pub site_pc: u64,
    /// Most recent low-32-bit syscall number observed at this site.
    pub last_syscall_nr: u32,
    /// Number of authenticated traps recorded for this site.
    pub hits: u64,
    /// Current lazypoline disposition.
    pub patch_state: LazyPatchState,
}

/// Ledgered result of one `apply_pending_patches` call that did not fail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LazyApplyReport {
    /// One outcome per certified site, in submission order.
    pub outcomes: Vec<(u64, SiteOutcome)>,
    /// Batch outcome/placement summary when a batch was installed; zeroes
    /// with `trap` set from `outcomes` when every site stayed trapping.
    pub metrics: ZpolineMetrics,
}

/// Signal-handler counters. `traps` counts authenticated first-profile traps;
/// a refused authentication or policy failure is counted before fail-stop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SudCounters {
    /// Authenticated SUD traps that reached policy handling.
    pub traps: u64,
    /// Traps whose genuine syscall completed through the gateway.
    pub forwarded: u64,
    /// Nested application-signal `rt_sigreturn`s redirected to the gateway
    /// restorer so the original signal frame can resume the forwarded call.
    pub signal_returns: u64,
    /// Patched-site executions forwarded through the gateway delegate
    /// without a SUD trap (lazypoline fast path).
    pub fast_path_calls: u64,
    /// Distinct recorded sites currently awaiting patch application.
    pub pending_patches: usize,
    /// Distinct recorded sites currently rewritten by a patch batch.
    pub rewritten_sites: usize,
    /// Distinct recorded sites left permanently to the trap outcome.
    pub trap_permanent_sites: usize,
    /// Authenticated traps refused by the first-profile or registry policy.
    pub refused: u64,
    /// Same-thread nested-handler detections.
    pub nested: u64,
    /// Handler entries rejected because every active-thread slot was busy.
    pub active_overflow: u64,
    /// SIGSYS deliveries that were not authenticated SUD contexts.
    pub foreign: u64,
    /// Authenticated traps whose site could not fit in the registry.
    pub overflow: u64,
    /// Distinct sites in the current snapshot after duplicate merging.
    pub recorded_sites: usize,
}

/// Builds the one-page SUD gateway image. Offset 0 is `raw6`; offset 32 is
/// the signal restorer, whose `rt_sigreturn` syscall also executes inside the
/// allowed gateway range.
pub fn build_gateway_image(page_size: usize) -> Vec<u8> {
    let mut image = vec![0x90; page_size];
    let raw6: &[u8] = &[
        0x48, 0x89, 0xf8, // mov rax, rdi
        0x48, 0x89, 0xf7, // mov rdi, rsi
        0x48, 0x89, 0xd6, // mov rsi, rdx
        0x48, 0x89, 0xca, // mov rdx, rcx
        0x4d, 0x89, 0xc2, // mov r10, r8
        0x4d, 0x89, 0xc8, // mov r8, r9
        0x4c, 0x8b, 0x4c, 0x24, 0x08, // mov r9, [rsp+8]
        0x0f, 0x05, // syscall
        0xc3, // ret
    ];
    image[GATEWAY_RAW_OFFSET..GATEWAY_RAW_OFFSET + raw6.len()].copy_from_slice(raw6);
    let restorer: &[u8] = &[
        0xb8, 0x0f, 0x00, 0x00, 0x00, // mov eax, SYS_rt_sigreturn
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    image[GATEWAY_RESTORER_OFFSET..GATEWAY_RESTORER_OFFSET + restorer.len()]
        .copy_from_slice(restorer);
    image
}

fn qualify_host() -> Result<usize, SyscallRefusal> {
    // One shared APX/MVEX/CET/page envelope for zpoline and SUD.
    crate::syscall::zpoline::qualify_host()
}

fn signal_bit(signal: i32) -> u64 {
    1_u64 << (signal - 1)
}

fn query_mask() -> Result<u64, SyscallRefusal> {
    let mut mask = 0_u64;
    // SAFETY: exactly one kernel mask word is written before SUD is enabled.
    let result = unsafe {
        raw::syscall4(
            libc::SYS_rt_sigprocmask as usize,
            libc::SIG_SETMASK as usize,
            0,
            (&mut mask as *mut u64) as usize,
            8,
        )
    };
    if result != 0 {
        return Err(SyscallRefusal::SignalContract);
    }
    Ok(mask)
}

fn query_action(signal: i32) -> Result<KernelAction, SyscallRefusal> {
    let mut action = KernelAction::default();
    // SAFETY: exact Linux x86-64 rt_sigaction layout and eight-byte mask.
    let result = unsafe {
        raw::syscall4(
            libc::SYS_rt_sigaction as usize,
            signal as usize,
            0,
            (&mut action as *mut KernelAction) as usize,
            8,
        )
    };
    if result != 0 {
        return Err(SyscallRefusal::SignalContract);
    }
    Ok(action)
}

fn install_action(signal: i32, action: &KernelAction) -> Result<(), SyscallRefusal> {
    // SAFETY: action is the complete exact kernel layout supplied by caller.
    let result = unsafe {
        raw::syscall4(
            libc::SYS_rt_sigaction as usize,
            signal as usize,
            (action as *const KernelAction) as usize,
            0,
            8,
        )
    };
    if result != 0 {
        return Err(SyscallRefusal::SignalContract);
    }
    Ok(())
}

unsafe fn gateway_syscall(state: &SudState, nr: i64, args: [i64; 6]) -> i64 {
    let start = state.gateway_start.load(Ordering::Acquire);
    if start == 0 {
        // SAFETY: no genuine gateway exists; fail closed without a syscall.
        unsafe { core::arch::asm!("ud2", options(noreturn, nostack)) }
    }
    // SAFETY: the gateway page starts with the exact raw6 stub published by
    // build_gateway_image and remains mapped for the installation lifetime.
    let raw6: GatewaySyscall = unsafe { core::mem::transmute(start as usize) };
    // SAFETY: callers supply one genuine syscall number and six arguments
    // satisfying that syscall's contract.
    unsafe { raw6(nr, args[0], args[1], args[2], args[3], args[4], args[5]) }
}

unsafe fn fail_stop(state: Option<&SudState>) -> ! {
    if let Some(state) = state {
        // SAFETY: exit_group is forwarded through the allowed gateway.
        unsafe { gateway_syscall(state, libc::SYS_exit_group, [126, 0, 0, 0, 0, 0]) };
    }
    // SAFETY: fail closed if no genuine gateway can be used.
    unsafe { core::arch::asm!("ud2", options(noreturn, nostack)) }
}

/// Genuine-syscall delegate for lazypoline-patched sites.
///
/// This mirrors the selected syscall callback's closed first-profile
/// completion rules exactly (number and flags validation, all six arguments
/// forwarded, raw result in RAX, RCX = site + 2, R11 = saved flags), except
/// the genuine syscall executes through the SUD gateway page: while SUD is
/// enabled on the executing thread, the selected callback's own syscall
/// instruction would trap, but the gateway range is always allowed. No
/// allocation, locking, TLS errno, or other syscall happens here.
unsafe extern "C" fn lazy_gateway_delegate(context: *mut HookContext) {
    let state_ptr = SUD_STATE.load(Ordering::Acquire);
    if state_ptr.is_null() || context.is_null() {
        // SAFETY: no genuine gateway exists; fail closed.
        unsafe { fail_stop(None) }
    }
    // SAFETY: the installation retains state while any patched site can
    // route here; uninstall refuses until the batch is retired.
    let state = unsafe { &*state_ptr };
    // SAFETY: the exact trampoline passes one live HookContext.
    let context = unsafe { &mut *context };
    let number = context.rax;
    if !first_profile_supports(number as u32) || number != u64::from(number as u32) {
        // SAFETY: refused before any genuine syscall.
        unsafe { fail_stop(Some(state)) }
    }
    // Same admitted-flags envelope as the selected syscall callback.
    const FLAGS: u64 = (1 << 0)
        | (1 << 1)
        | (1 << 2)
        | (1 << 4)
        | (1 << 6)
        | (1 << 7)
        | (1 << 9)
        | (1 << 10)
        | (1 << 11);
    const REQUIRED: u64 = (1 << 1) | (1 << 9);
    let flags = context.rflags;
    if flags & !FLAGS != 0 || flags & REQUIRED != REQUIRED {
        // SAFETY: refused before any genuine syscall.
        unsafe { fail_stop(Some(state)) }
    }
    let Some(next) = context.instruction_pointer.checked_add(2) else {
        // SAFETY: refused before any genuine syscall.
        unsafe { fail_stop(Some(state)) }
    };
    let args = [
        context.rdi as i64,
        context.rsi as i64,
        context.rdx as i64,
        context.r10 as i64,
        context.r8 as i64,
        context.r9 as i64,
    ];
    // SAFETY: number is first-profile and the context carries the genuine
    // syscall arguments under the installation contract.
    let result = unsafe { gateway_syscall(state, number as i64, args) };
    context.rax = result as u64;
    context.rcx = next;
    context.r11 = flags;
    state.fast_path_calls.fetch_add(1, Ordering::AcqRel);
}

const LAZY_GATEWAY_DELEGATE: HookCallback = lazy_gateway_delegate;

enum ActiveClaim {
    Claimed(usize),
    Nested,
    Full,
}

fn claim_active_slot(state: &SudState, tid: u64) -> ActiveClaim {
    // Scan the whole active set first: an earlier hole must not hide this
    // same thread in a later slot and admit a nested handler invocation.
    if state
        .active_tids
        .iter()
        .any(|slot| slot.load(Ordering::Acquire) == tid)
    {
        return ActiveClaim::Nested;
    }
    for (index, slot) in state.active_tids.iter().enumerate() {
        match slot.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return ActiveClaim::Claimed(index),
            Err(existing) if existing == tid => return ActiveClaim::Nested,
            Err(_) => {}
        }
    }
    ActiveClaim::Full
}

fn record_site(state: &SudState, site_pc: u64, nr: u32) -> bool {
    let count = state
        .site_count
        .load(Ordering::Acquire)
        .min(state.sites.len());
    for slot in &state.sites[..count] {
        if slot.site_pc.load(Ordering::Acquire) == site_pc {
            slot.last_nr.store(u64::from(nr), Ordering::Release);
            slot.hits.fetch_add(1, Ordering::AcqRel);
            return true;
        }
    }
    let index = state.site_count.fetch_add(1, Ordering::AcqRel);
    if index >= state.sites.len() {
        state.overflow.fetch_add(1, Ordering::AcqRel);
        return false;
    }
    let slot = &state.sites[index];
    slot.last_nr.store(u64::from(nr), Ordering::Release);
    slot.hits.store(1, Ordering::Release);
    if state.lazy {
        slot.patch_state.store(PATCH_PENDING, Ordering::Release);
    }
    slot.site_pc.store(site_pc, Ordering::Release);
    true
}

/// Validates one lazypoline certificate against the trapped observation.
/// `slot` is `(patch-state byte, last observed syscall number)` for the
/// certified address, or `None` when no trap recorded that address. The
/// trap proves one execution's number only; the certificate asserts every
/// execution's number, so a disagreement means the certificate does not
/// describe the discovered site and refuses by name.
fn classify_lazy_cert(slot: Option<(u8, u32)>, certified_nr: u32) -> Result<(), SyscallRefusal> {
    let Some((patch_state, last_nr)) = slot else {
        return Err(SyscallRefusal::InvalidConfig {
            field: "logical_pc",
            reason: "site was not discovered by a lazypoline first trap",
        });
    };
    if patch_state != PATCH_PENDING {
        return Err(SyscallRefusal::InvalidConfig {
            field: "logical_pc",
            reason: "site is not pending lazypoline patch application",
        });
    }
    if certified_nr != last_nr {
        return Err(SyscallRefusal::SyscallNumberRangeUnproven);
    }
    Ok(())
}

unsafe extern "C" fn sud_handler(signal: i32, info: *mut KernelSiginfo, context: *mut c_void) {
    SUD_HANDLER_ACTIVE.fetch_add(1, Ordering::AcqRel);
    if SUD_CLOSING.load(Ordering::Acquire) {
        SUD_HANDLER_ACTIVE.fetch_sub(1, Ordering::AcqRel);
        // SAFETY: teardown is in progress; do not dereference handler state.
        unsafe { fail_stop(None) }
    }
    let state_ptr = SUD_STATE.load(Ordering::Acquire);
    if state_ptr.is_null() || info.is_null() || context.is_null() {
        // SAFETY: an unauthenticated delivery has no genuine forwarding path.
        unsafe { fail_stop(None) }
    }
    // SAFETY: installation publishes state before the handler and retains it
    // until after exact handler restoration and registration drain.
    let state = unsafe { &*state_ptr };
    // SAFETY: the gateway gettid has no pointer arguments.
    let tid = unsafe { gateway_syscall(state, libc::SYS_gettid, [0; 6]) };
    if tid <= 0 {
        state.foreign.fetch_add(1, Ordering::AcqRel);
        // SAFETY: no trustworthy thread identity is available.
        unsafe { fail_stop(Some(state)) }
    }
    let tid = tid as u64;

    // An ordinary application-signal restorer outside the gateway traps its
    // own rt_sigreturn while this thread's first SUD handler is still active.
    // Do not forward that call from this nested frame (it would pop the wrong
    // signal frame). Instead redirect the trapped restorer context to the
    // gateway restorer; when this nested handler returns, that rt_sigreturn
    // consumes the application-signal frame and resumes the first handler.
    {
        // SAFETY: kernel signal ABI arguments were checked nonnull above.
        let info_ref = unsafe { &*info };
        let context_ref = unsafe { &mut *context.cast::<libc::ucontext_t>() };
        let registers = &mut context_ref.uc_mcontext.gregs;
        let rip = registers[libc::REG_RIP as usize] as u64;
        let rax = registers[libc::REG_RAX as usize] as u64;
        let rcx = registers[libc::REG_RCX as usize] as u64;
        let same_thread_active = state
            .active_tids
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == tid);
        if same_thread_active
            && signal == libc::SIGSYS
            && info_ref.signo == libc::SIGSYS
            && info_ref.code == SYS_USER_DISPATCH_CODE
            && info_ref.arch == AUDIT_ARCH_X86_64
            && info_ref.call_addr as u64 == rip
            && rip >= 2
            && rax == u64::from(info_ref.syscall as u32)
            && rcx == rip
            && info_ref.syscall as u32 == libc::SYS_rt_sigreturn as u32
        {
            // SAFETY: the authenticated trap identifies the mapped restorer
            // syscall site and the installation keeps admitted code mapped.
            let opcode = unsafe { std::ptr::read_unaligned((rip - 2) as *const u16) };
            if opcode == 0x050f {
                registers[libc::REG_RIP as usize] = (state.gateway_start.load(Ordering::Acquire)
                    + GATEWAY_RESTORER_OFFSET as u64)
                    as libc::greg_t;
                state.signal_returns.fetch_add(1, Ordering::AcqRel);
                SUD_HANDLER_ACTIVE.fetch_sub(1, Ordering::AcqRel);
                return;
            }
        }
    }

    let active_index = match claim_active_slot(state, tid) {
        ActiveClaim::Claimed(index) => index,
        ActiveClaim::Nested => {
            state.nested.fetch_add(1, Ordering::AcqRel);
            // SAFETY: same-thread nested handler execution is fail-closed.
            unsafe { fail_stop(Some(state)) }
        }
        ActiveClaim::Full => {
            state.active_overflow.fetch_add(1, Ordering::AcqRel);
            // SAFETY: over-capacity handler execution is fail-closed.
            unsafe { fail_stop(Some(state)) }
        }
    };

    // SAFETY: kernel signal ABI arguments were checked nonnull above.
    let info = unsafe { &*info };
    let context = unsafe { &mut *context.cast::<libc::ucontext_t>() };
    let registers = &mut context.uc_mcontext.gregs;
    let rip = registers[libc::REG_RIP as usize] as u64;
    let rax = registers[libc::REG_RAX as usize] as u64;
    let rcx = registers[libc::REG_RCX as usize] as u64;
    let authenticated = signal == libc::SIGSYS
        && info.signo == libc::SIGSYS
        && info.code == SYS_USER_DISPATCH_CODE
        && info.arch == AUDIT_ARCH_X86_64
        && info.call_addr as u64 == rip
        && rip >= 2
        && rax == u64::from(info.syscall as u32)
        && rcx == rip;
    if !authenticated {
        state.foreign.fetch_add(1, Ordering::AcqRel);
        state.active_tids[active_index].store(0, Ordering::Release);
        // SAFETY: foreign SIGSYS is not forwarded or resumed.
        unsafe { fail_stop(Some(state)) }
    }
    let site_pc = rip - 2;
    // SAFETY: authenticated SUD context identifies a mapped syscall site;
    // the installation contract keeps admitted code mapped while registered.
    let opcode = unsafe { std::ptr::read_unaligned(site_pc as *const u16) };
    if opcode != 0x050f {
        state.foreign.fetch_add(1, Ordering::AcqRel);
        state.active_tids[active_index].store(0, Ordering::Release);
        // SAFETY: this was not an authenticated native syscall site.
        unsafe { fail_stop(Some(state)) }
    }

    state.traps.fetch_add(1, Ordering::AcqRel);
    let nr = info.syscall as u32;
    if !first_profile_supports(nr) || !record_site(state, site_pc, nr) {
        state.refused.fetch_add(1, Ordering::AcqRel);
        state.active_tids[active_index].store(0, Ordering::Release);
        // SAFETY: unsupported or unrecordable syscalls are not forwarded.
        unsafe { fail_stop(Some(state)) }
    }

    let args = [
        registers[libc::REG_RDI as usize],
        registers[libc::REG_RSI as usize],
        registers[libc::REG_RDX as usize],
        registers[libc::REG_R10 as usize],
        registers[libc::REG_R8 as usize],
        registers[libc::REG_R9 as usize],
    ];
    // SAFETY: nr is in the first profile and the saved argument registers are
    // the genuine syscall arguments under the caller's installation contract.
    let result = unsafe { gateway_syscall(state, i64::from(nr), args) };
    registers[libc::REG_RAX as usize] = result as libc::greg_t;
    registers[libc::REG_RCX as usize] = rip as libc::greg_t;
    registers[libc::REG_R11 as usize] = registers[libc::REG_EFL as usize];
    state.forwarded.fetch_add(1, Ordering::AcqRel);
    state.active_tids[active_index].store(0, Ordering::Release);
    SUD_HANDLER_ACTIVE.fetch_sub(1, Ordering::AcqRel);
}

fn claim_owner() -> Result<(), SyscallRefusal> {
    match SUD_OWNER.compare_exchange(
        OWNER_EMPTY,
        OWNER_INSTALLING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => Ok(()),
        Err(OWNER_INSTALLED) => Err(SyscallRefusal::StrategyAlreadyInstalled),
        Err(OWNER_POISONED) => Err(SyscallRefusal::PublicationPoisoned),
        Err(_) => Err(SyscallRefusal::ConflictingStrategyInstalled),
    }
}

fn release_owner() {
    let _ = SUD_OWNER.compare_exchange(
        OWNER_INSTALLING,
        OWNER_EMPTY,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

// Linux UAPI AT_MINSIGSTKSZ.
const AT_MINSIGSTKSZ: libc::c_ulong = 51;

/// One thread's guarded alternate signal stack and exact prior custody.
struct AltStackOwner {
    prior: libc::stack_t,
    mapping: *mut c_void,
    mapping_len: usize,
    stack: *mut c_void,
    installed: bool,
}

impl AltStackOwner {
    fn install(page: usize) -> Result<Self, SyscallRefusal> {
        let mut prior: libc::stack_t = unsafe { std::mem::zeroed() };
        // SAFETY: sigaltstack query writes one complete native stack_t.
        if unsafe { libc::sigaltstack(std::ptr::null(), &mut prior) } != 0
            || prior.ss_flags & libc::SS_ONSTACK != 0
        {
            return Err(SyscallRefusal::SignalContract);
        }
        let minimum = unsafe { libc::getauxval(AT_MINSIGSTKSZ) } as usize;
        if minimum == 0
            || minimum
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(64 * 1024))
                .is_none_or(|bytes| bytes > ALT_STACK_BYTES)
        {
            return Err(SyscallRefusal::SignalContract);
        }
        let total = ALT_STACK_BYTES + 2 * page;
        // SAFETY: a fresh anonymous guard mapping owned by this owner.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(SyscallRefusal::AllocationUnavailable);
        }
        let mut owner = Self {
            prior,
            mapping,
            mapping_len: total,
            stack: std::ptr::null_mut(),
            installed: false,
        };
        let stack = unsafe { mapping.cast::<u8>().add(page).cast::<c_void>() };
        owner.stack = stack;
        // SAFETY: the middle ALT_STACK_BYTES are inside the owned mapping.
        if unsafe { libc::mprotect(stack, ALT_STACK_BYTES, libc::PROT_READ | libc::PROT_WRITE) }
            != 0
        {
            return Err(SyscallRefusal::AllocationUnavailable);
        }
        // SAFETY: touch every owned writable page before signal delivery.
        for offset in (0..ALT_STACK_BYTES).step_by(page) {
            unsafe { std::ptr::write_volatile(stack.cast::<u8>().add(offset), 0) };
        }
        let next = libc::stack_t {
            ss_sp: stack,
            ss_flags: 0,
            ss_size: ALT_STACK_BYTES,
        };
        // SAFETY: owned stack storage remains retained through restoration.
        if unsafe { libc::sigaltstack(&next, std::ptr::null_mut()) } != 0 {
            return Err(SyscallRefusal::SignalContract);
        }
        owner.installed = true;
        if let Err(error) = owner.verify_current() {
            let _ = owner.restore();
            return Err(error);
        }
        Ok(owner)
    }

    fn verify_current(&self) -> Result<(), SyscallRefusal> {
        let mut actual: libc::stack_t = unsafe { std::mem::zeroed() };
        // SAFETY: sigaltstack query writes one complete native stack_t.
        if unsafe { libc::sigaltstack(std::ptr::null(), &mut actual) } != 0
            || actual.ss_sp != self.stack
            || actual.ss_size != ALT_STACK_BYTES
            || actual.ss_flags != 0
        {
            return Err(SyscallRefusal::SignalContract);
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<(), SyscallRefusal> {
        if self.installed {
            self.verify_current()?;
            // SAFETY: the owning thread is not executing on this stack now.
            if unsafe { libc::sigaltstack(&self.prior, std::ptr::null_mut()) } != 0 {
                return Err(SyscallRefusal::SignalContract);
            }
            let mut restored: libc::stack_t = unsafe { std::mem::zeroed() };
            // SAFETY: sigaltstack query writes one complete native stack_t.
            if unsafe { libc::sigaltstack(std::ptr::null(), &mut restored) } != 0
                || restored.ss_sp != self.prior.ss_sp
                || restored.ss_size != self.prior.ss_size
                || restored.ss_flags != self.prior.ss_flags
            {
                return Err(SyscallRefusal::SignalContract);
            }
            self.installed = false;
        }
        if !self.mapping.is_null() {
            // SAFETY: the restored stack no longer names this mapping.
            if unsafe { libc::munmap(self.mapping, self.mapping_len) } != 0 {
                return Err(SyscallRefusal::AllocationUnavailable);
            }
            self.mapping = std::ptr::null_mut();
            self.mapping_len = 0;
            self.stack = std::ptr::null_mut();
        }
        Ok(())
    }
}

impl Drop for AltStackOwner {
    fn drop(&mut self) {
        if self.installed || !self.mapping.is_null() {
            // Partial-install cleanup only; successful owners restore through
            // their explicit token/installation paths and mark installed false.
            let _ = self.restore();
        }
    }
}

/// Process-lifetime owner of the SUD gateway, handler, altstack, and site
/// registry. Retain it until every thread token is unregistered and
/// `uninstall` succeeds; dropping it intentionally leaks live custody.
pub struct SudInstallation {
    config: SyscallStrategyConfig,
    state: *mut SudState,
    gateway: Option<DualMapping>,
    gateway_range: (u64, usize),
    prior_action: KernelAction,
    installed_action: KernelAction,
    installer_stack: Option<AltStackOwner>,
    page_size: usize,
    installer_tid: u64,
    action_installed: bool,
    closed: bool,
    lazy_batch: Option<Box<InstalledZpolineSet>>,
    // Publication failures hand back `Box<InstalledZpolineSet>` owners whose
    // custody must be retained verbatim, hence the boxed element type.
    #[allow(clippy::vec_box)]
    lazy_retained: Vec<Box<InstalledZpolineSet>>,
    lazy_poisoned: bool,
}

// SAFETY: shared references only read immutable custody data, call the
// gateway, and mutate handler state through atomics. Mutable uninstall and
// mapping ownership remain behind `&mut self`/consuming APIs.
unsafe impl Sync for SudInstallation {}

impl SudInstallation {
    /// Installs the SUD handler/gateway without enabling dispatch on any
    /// thread. Call `register_current_thread` on each participating thread.
    pub fn install(config: SyscallStrategyConfig) -> Result<Self, SyscallRefusal> {
        config.validate()?;
        if !matches!(
            config.strategy(),
            SyscallStrategy::Trap | SyscallStrategy::Lazypoline
        ) {
            return Err(SyscallRefusal::InvalidConfig {
                field: "strategy",
                reason: "SUD substrate requires the trap or lazypoline strategy",
            });
        }
        if config.discovery() != DiscoverySubstrate::Sud {
            return Err(SyscallRefusal::InvalidConfig {
                field: "discovery",
                reason: "SUD substrate requires DiscoverySubstrate::Sud",
            });
        }
        let page = qualify_host()?;
        let prior_action = query_action(libc::SIGSYS)?;
        if prior_action.handler != libc::SIG_DFL {
            return Err(SyscallRefusal::SignalContract);
        }
        if query_mask()? & signal_bit(libc::SIGSYS) != 0 {
            return Err(SyscallRefusal::SignalContract);
        }
        claim_owner()?;
        if SUD_HANDLER_ACTIVE.load(Ordering::Acquire) != 0 {
            SUD_OWNER.store(OWNER_POISONED, Ordering::Release);
            return Err(SyscallRefusal::PublicationPoisoned);
        }
        SUD_CLOSING.store(false, Ordering::Release);
        let mut owner = Self {
            config,
            state: std::ptr::null_mut(),
            gateway: None,
            gateway_range: (0, 0),
            prior_action,
            installed_action: KernelAction::default(),
            installer_stack: None,
            page_size: page,
            installer_tid: 0,
            action_installed: false,
            closed: false,
            lazy_batch: None,
            lazy_retained: Vec::new(),
            lazy_poisoned: false,
        };
        if let Err(error) = owner.install_inner(page) {
            if owner.rollback_partial().is_ok() {
                release_owner();
            } else {
                // Restoration is uncertain: retain every kernel-referenced
                // mapping/state and poison the process-wide owner instead of
                // freeing storage or releasing custody.
                SUD_OWNER.store(OWNER_POISONED, Ordering::Release);
                std::mem::forget(owner);
            }
            return Err(error);
        }
        SUD_OWNER.store(OWNER_INSTALLED, Ordering::Release);
        Ok(owner)
    }

    fn install_inner(&mut self, page: usize) -> Result<(), SyscallRefusal> {
        let sites: Vec<SudSiteSlot> = (0..self.config.max_sites())
            .map(|_| SudSiteSlot {
                site_pc: AtomicU64::new(0),
                last_nr: AtomicU64::new(0),
                hits: AtomicU64::new(0),
                patch_state: AtomicU8::new(PATCH_TRAPPING),
            })
            .collect();
        let state = Box::new(SudState {
            lazy: self.config.strategy() == SyscallStrategy::Lazypoline,
            gateway_start: AtomicU64::new(0),
            gateway_end: AtomicU64::new(0),
            sites: sites.into_boxed_slice(),
            site_count: AtomicUsize::new(0),
            registered_tids: [const { AtomicU64::new(0) }; MAX_ACTIVE_THREADS],
            active_tids: [const { AtomicU64::new(0) }; MAX_ACTIVE_THREADS],
            traps: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            signal_returns: AtomicU64::new(0),
            fast_path_calls: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            nested: AtomicU64::new(0),
            active_overflow: AtomicU64::new(0),
            foreign: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
        });
        self.state = Box::into_raw(state);

        let mut gateway = DualMapping::probe_anywhere(page, b"liteinst-sud-gateway\0")?;
        let gateway_start = gateway.address();
        let gateway_image = build_gateway_image(page);
        gateway.publish_bytes(&gateway_image)?;
        self.gateway_range = (gateway_start, page);
        // SAFETY: state was just allocated and is not yet published.
        unsafe {
            (*self.state)
                .gateway_start
                .store(gateway_start, Ordering::Release);
            (*self.state)
                .gateway_end
                .store(gateway_start + page as u64, Ordering::Release);
        }
        self.gateway = Some(gateway.commit());

        self.installer_stack = Some(AltStackOwner::install(page)?);
        // Publish state before installing the action so no delivered SIGSYS
        // can observe a null handler state.
        SUD_STATE.store(self.state, Ordering::Release);
        self.installer_tid = {
            // SAFETY: gettid through the just-published genuine gateway.
            let state = unsafe { &*self.state };
            let tid = unsafe { gateway_syscall(state, libc::SYS_gettid, [0; 6]) };
            u64::try_from(tid).map_err(|_| SyscallRefusal::SudUnavailable { errno: 0 })?
        };

        let action = KernelAction {
            handler: sud_handler as *const () as usize,
            flags: libc::SA_SIGINFO as usize
                | libc::SA_ONSTACK as usize
                | libc::SA_NODEFER as usize
                | SA_RESTORER,
            restorer: (gateway_start as usize) + GATEWAY_RESTORER_OFFSET,
            // Preserve the interrupted thread's ordinary signal mask while a
            // forwarded syscall blocks. SA_NODEFER still lets a nested SIGSYS
            // reach the authentication path and fail closed.
            mask: 0,
        };
        install_action(libc::SIGSYS, &action)?;
        self.action_installed = true;
        let installed = query_action(libc::SIGSYS)?;
        let mut expected = action;
        expected.mask &= !(signal_bit(libc::SIGKILL) | signal_bit(libc::SIGSTOP));
        if installed != expected {
            return Err(SyscallRefusal::SignalContract);
        }
        self.installed_action = installed;
        Ok(())
    }

    fn rollback_partial(&mut self) -> Result<(), SyscallRefusal> {
        SUD_CLOSING.store(true, Ordering::Release);
        if self.action_installed {
            install_action(libc::SIGSYS, &self.prior_action)?;
            if query_action(libc::SIGSYS)? != self.prior_action {
                return Err(SyscallRefusal::SignalContract);
            }
            self.action_installed = false;
        }
        // No handler may still reference state, gateway, or alternate stack
        // storage before any of it is unmapped or freed.
        wait_for_handler_quiescence();
        SUD_STATE.store(std::ptr::null_mut(), Ordering::Release);
        if let Some(stack) = &mut self.installer_stack {
            stack.restore()?;
        }
        if let Some(gateway) = &mut self.gateway {
            gateway.unmap()?;
        }
        if !self.state.is_null() {
            // SAFETY: action is restored, state is unpublished, and active
            // handler count is zero.
            unsafe { drop(Box::from_raw(self.state)) };
            self.state = std::ptr::null_mut();
        }
        self.closed = true;
        Ok(())
    }

    /// Gateway `[start, end)` range registered with SUD for each thread.
    pub const fn gateway_range(&self) -> (u64, u64) {
        (
            self.gateway_range.0,
            self.gateway_range.0 + self.gateway_range.1 as u64,
        )
    }

    /// Current handler counters, including distinct recorded sites.
    pub fn counters(&self) -> SudCounters {
        // SAFETY: state remains retained until uninstall after drain.
        let state = unsafe { &*self.state };
        let lazy = self.lazy_sites();
        SudCounters {
            traps: state.traps.load(Ordering::Acquire),
            forwarded: state.forwarded.load(Ordering::Acquire),
            signal_returns: state.signal_returns.load(Ordering::Acquire),
            fast_path_calls: state.fast_path_calls.load(Ordering::Acquire),
            pending_patches: lazy
                .iter()
                .filter(|record| record.patch_state == LazyPatchState::Pending)
                .count(),
            rewritten_sites: lazy
                .iter()
                .filter(|record| record.patch_state == LazyPatchState::Rewritten)
                .count(),
            trap_permanent_sites: lazy
                .iter()
                .filter(|record| record.patch_state == LazyPatchState::TrapPermanent)
                .count(),
            refused: state.refused.load(Ordering::Acquire),
            nested: state.nested.load(Ordering::Acquire),
            active_overflow: state.active_overflow.load(Ordering::Acquire),
            foreign: state.foreign.load(Ordering::Acquire),
            overflow: state.overflow.load(Ordering::Acquire),
            recorded_sites: lazy.len(),
        }
    }

    /// Sorted snapshot of recorded sites with lazypoline dispositions,
    /// merging any concurrent duplicate slot allocations for the same site.
    /// Duplicate slots for one address can only coexist transiently before
    /// patch application; the strongest disposition wins the merge
    /// (Rewritten, then TrapPermanent, then Pending).
    pub fn lazy_sites(&self) -> Vec<LazySiteRecord> {
        // SAFETY: state remains retained until uninstall after drain.
        let state = unsafe { &*self.state };
        let count = state
            .site_count
            .load(Ordering::Acquire)
            .min(state.sites.len());
        let rank = |value: LazyPatchState| match value {
            LazyPatchState::Trapping => 0,
            LazyPatchState::Pending => 1,
            LazyPatchState::TrapPermanent => 2,
            LazyPatchState::Rewritten => 3,
        };
        let mut merged: Vec<LazySiteRecord> = Vec::new();
        for slot in &state.sites[..count] {
            let site_pc = slot.site_pc.load(Ordering::Acquire);
            if site_pc == 0 {
                continue;
            }
            let record = LazySiteRecord {
                site_pc,
                last_syscall_nr: slot.last_nr.load(Ordering::Acquire) as u32,
                hits: slot.hits.load(Ordering::Acquire),
                patch_state: lazy_patch_state(slot.patch_state.load(Ordering::Acquire)),
            };
            if let Some(existing) = merged.iter_mut().find(|item| item.site_pc == site_pc) {
                existing.hits += record.hits;
                existing.last_syscall_nr = record.last_syscall_nr;
                if rank(record.patch_state) > rank(existing.patch_state) {
                    existing.patch_state = record.patch_state;
                }
            } else {
                merged.push(record);
            }
        }
        merged.sort_by_key(|record| record.site_pc);
        merged
    }

    fn slot_for(&self, site_pc: u64) -> Option<(u8, u32)> {
        // SAFETY: state remains retained until uninstall after drain.
        let state = unsafe { &*self.state };
        let count = state
            .site_count
            .load(Ordering::Acquire)
            .min(state.sites.len());
        let mut found = None;
        for slot in &state.sites[..count] {
            if slot.site_pc.load(Ordering::Acquire) == site_pc {
                let candidate = (
                    slot.patch_state.load(Ordering::Acquire),
                    slot.last_nr.load(Ordering::Acquire) as u32,
                );
                // Prefer a pending duplicate so certification can proceed;
                // any duplicate left behind is merged in snapshots.
                if candidate.0 == PATCH_PENDING {
                    return Some(candidate);
                }
                found = Some(candidate);
            }
        }
        found
    }

    fn set_patch_state(&self, site_pc: u64, patch_state: u8) {
        // SAFETY: state remains retained until uninstall after drain.
        let state = unsafe { &*self.state };
        let count = state
            .site_count
            .load(Ordering::Acquire)
            .min(state.sites.len());
        for slot in &state.sites[..count] {
            if slot.site_pc.load(Ordering::Acquire) == site_pc {
                slot.patch_state.store(patch_state, Ordering::Release);
            }
        }
    }

    fn require_lazy_applier(&self) -> Result<(), SyscallRefusal> {
        if self.config.strategy() != SyscallStrategy::Lazypoline {
            return Err(SyscallRefusal::InvalidConfig {
                field: "strategy",
                reason: "patch application requires the lazypoline strategy",
            });
        }
        if self.lazy_poisoned {
            return Err(SyscallRefusal::PublicationPoisoned);
        }
        // SAFETY: state remains retained until uninstall after drain.
        let state = unsafe { &*self.state };
        // SAFETY: gettid through the genuine gateway has no pointers and is
        // allowed whether or not this thread is dispatched.
        let tid = unsafe { gateway_syscall(state, libc::SYS_gettid, [0; 6]) };
        if tid != self.installer_tid as i64
            || state
                .registered_tids
                .iter()
                .any(|slot| slot.load(Ordering::Acquire) == tid as u64)
        {
            // Patch publication performs ordinary syscalls; it must run on
            // the unregistered installing thread.
            return Err(SyscallRefusal::ThreadNotRegistered);
        }
        Ok(())
    }

    /// Publishes zpoline rewrites for caller-certified pending sites.
    ///
    /// Every certificate must name a site this installation discovered by a
    /// first trap and still holds `Pending`, must carry this installation's
    /// exact config, and its certified syscall number must equal the number
    /// the trap last observed at that site. Certificates must form one
    /// batch (one snapshot and code identity, as `PreparedZpolineSet`
    /// requires). At most one batch is live at a time; retire it before
    /// applying another.
    ///
    /// Per-site eligibility or before-write publication failures follow the
    /// configured fallback policy: `Trap` marks the site `TrapPermanent`
    /// and reports the `Trap` outcome; `Refuse` returns the named refusal
    /// before any write with pending states unchanged. A keep-gated
    /// publication failure poisons patch application under either policy.
    /// Sites discovered after a successful batch keep trapping and
    /// forwarding; they are pending for a later batch only after the live
    /// batch is retired.
    ///
    /// `finalize` runs inside publication only after the source write, so
    /// when this call ledgers a before-write failure as `Trap` (or returns
    /// a refusal) the caller still owns restoring the source mapping's
    /// final permissions before executing it again.
    ///
    /// The config placement budget must cover the batch (one handler
    /// mapping per site plus sled and dispatcher, and their mapped bytes);
    /// the vocabulary default budget only fits the single eager site, so a
    /// lazypoline installation that will patch needs an explicit larger
    /// `PlacementBudget`, or every apply is ledgered/refused as
    /// `AllocationUnavailable`.
    ///
    /// # Safety
    /// The same alias, lease-exclusion, finalizer, stack, signal, CET, and
    /// saved-continuation contract as eager zpoline publication applies.
    /// The calling thread must be the unregistered installing thread; the
    /// lease must exclude execution of the certified code by every thread
    /// (registered threads included) until this call returns.
    pub unsafe fn apply_pending_patches(
        &mut self,
        certs: Vec<ZpolineSite<'_>>,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), SyscallRefusal>,
    ) -> Result<LazyApplyReport, SyscallRefusal> {
        self.require_lazy_applier()?;
        if self.lazy_batch.is_some() {
            return Err(SyscallRefusal::StrategyAlreadyInstalled);
        }
        if certs.is_empty() {
            return Err(SyscallRefusal::InvalidConfig {
                field: "sites",
                reason: "patch application requires at least one certificate",
            });
        }
        let refuse = self.config.fallback() == FallbackPolicy::Refuse;
        let mut outcomes: Vec<Option<(u64, SiteOutcome)>> = certs.iter().map(|_| None).collect();
        let mut eligible: Vec<(usize, ZpolineSite<'_>)> = Vec::new();
        let mut seen: Vec<u64> = Vec::new();
        for (position, cert) in certs.into_iter().enumerate() {
            let pc = cert.logical_pc;
            let ineligible = if seen.contains(&pc) {
                Some(SyscallRefusal::OwnershipConflict)
            } else if cert.config != self.config {
                Some(SyscallRefusal::InvalidConfig {
                    field: "config",
                    reason: "certificate config differs from the installation",
                })
            } else if let Err(reason) = classify_lazy_cert(self.slot_for(pc), cert.syscall_nr) {
                Some(reason)
            } else {
                seen.push(pc);
                // Probe per-site eligibility with a rebuilt certificate so
                // the batch preparation below only sees eligible sites.
                let probe = ZpolineSite {
                    config: cert.config,
                    identity: cert.identity,
                    code: cert.code,
                    base_address: cert.base_address,
                    logical_pc: cert.logical_pc,
                    entries: cert.entries,
                    syscall_nr: cert.syscall_nr,
                };
                crate::syscall::zpoline::PreparedZpoline::prepare_lazy(probe, LAZY_GATEWAY_DELEGATE)
                    .map(|_| ())
                    .err()
            };
            match ineligible {
                Some(reason) => {
                    if refuse {
                        return Err(reason);
                    }
                    self.set_patch_state(pc, PATCH_TRAP_PERMANENT);
                    outcomes[position] = Some((pc, SiteOutcome::Trap));
                }
                None => eligible.push((position, cert)),
            }
        }
        let finish = |outcomes: Vec<Option<(u64, SiteOutcome)>>,
                      metrics: ZpolineMetrics|
         -> LazyApplyReport {
            LazyApplyReport {
                outcomes: outcomes
                    .into_iter()
                    .map(|outcome| outcome.expect("every certificate receives an outcome"))
                    .collect(),
                metrics,
            }
        };
        if eligible.is_empty() {
            let trap = outcomes.len();
            return Ok(finish(
                outcomes,
                ZpolineMetrics {
                    trap,
                    ..ZpolineMetrics::default()
                },
            ));
        }
        let eligible_pcs: Vec<u64> = eligible.iter().map(|(_, cert)| cert.logical_pc).collect();
        let (positions, batch_certs): (Vec<usize>, Vec<ZpolineSite<'_>>) =
            eligible.into_iter().unzip();
        let prepared = PreparedZpolineSet::prepare_lazy_batch(batch_certs, LAZY_GATEWAY_DELEGATE)?;
        // SAFETY: the caller supplies the complete contract above.
        match unsafe { prepared.publish_with(writable_base, lease, finalize) } {
            Ok(installed) => {
                for (position, &pc) in positions.iter().zip(&eligible_pcs) {
                    let outcome = installed
                        .outcomes()
                        .iter()
                        .find(|(address, _)| *address == pc)
                        .map(|(_, outcome)| *outcome)
                        .expect("installed batch reports every prepared site");
                    outcomes[*position] = Some((pc, outcome));
                }
                for &pc in &eligible_pcs {
                    self.set_patch_state(pc, PATCH_REWRITTEN);
                }
                let metrics = installed.metrics();
                self.lazy_batch = Some(installed);
                Ok(finish(outcomes, metrics))
            }
            Err(failure) => {
                let reason = failure.failure.reason;
                let stage = failure.failure.stage;
                self.lazy_retained.push(failure.retained);
                if stage == FailureStage::KeepGated {
                    self.lazy_poisoned = true;
                    return Err(reason);
                }
                if refuse {
                    return Err(reason);
                }
                for (position, &pc) in positions.iter().zip(&eligible_pcs) {
                    self.set_patch_state(pc, PATCH_TRAP_PERMANENT);
                    outcomes[*position] = Some((pc, SiteOutcome::Trap));
                }
                let trap = outcomes.len();
                Ok(finish(
                    outcomes,
                    ZpolineMetrics {
                        trap,
                        ..ZpolineMetrics::default()
                    },
                ))
            }
        }
    }

    /// Restores the live patch batch's original `syscall` bytes and sled,
    /// returning its sites to `Pending` so they trap (and can be certified
    /// again) on next execution.
    ///
    /// # Safety
    /// The same contract as [`Self::apply_pending_patches`] applies.
    pub unsafe fn retire_lazy_batch(
        &mut self,
        writable_base: *mut u8,
        lease: &mut QuiescenceLease<'_>,
        finalize: impl FnMut() -> Result<(), SyscallRefusal>,
    ) -> Result<(), SyscallRefusal> {
        self.require_lazy_applier()?;
        let Some(batch) = self.lazy_batch.take() else {
            return Err(SyscallRefusal::InvalidConfig {
                field: "lazy_batch",
                reason: "no lazypoline patch batch is installed",
            });
        };
        let pcs: Vec<u64> = batch
            .outcomes()
            .iter()
            .filter(|(_, outcome)| *outcome == SiteOutcome::RewrittenLazypoline)
            .map(|(pc, _)| *pc)
            .collect();
        // SAFETY: the caller supplies the complete contract above.
        match unsafe { batch.retire(writable_base, lease, finalize) } {
            Ok(()) => {
                for pc in pcs {
                    self.set_patch_state(pc, PATCH_PENDING);
                }
                Ok(())
            }
            Err(failure) => {
                let reason = failure.failure.reason;
                if failure.failure.stage == FailureStage::KeepGated {
                    self.lazy_poisoned = true;
                }
                self.lazy_batch = Some(failure.retained);
                Err(reason)
            }
        }
    }

    /// Sorted snapshot of recorded sites, merging any concurrent duplicate
    /// slot allocations for the same first-trap site.
    pub fn sites(&self) -> Vec<SudSiteRecord> {
        // SAFETY: state remains retained until uninstall after drain.
        let state = unsafe { &*self.state };
        let count = state
            .site_count
            .load(Ordering::Acquire)
            .min(state.sites.len());
        let mut merged: Vec<SudSiteRecord> = Vec::new();
        for slot in &state.sites[..count] {
            let site_pc = slot.site_pc.load(Ordering::Acquire);
            if site_pc == 0 {
                continue;
            }
            let record = SudSiteRecord {
                site_pc,
                last_syscall_nr: slot.last_nr.load(Ordering::Acquire) as u32,
                hits: slot.hits.load(Ordering::Acquire),
            };
            if let Some(existing) = merged.iter_mut().find(|item| item.site_pc == site_pc) {
                existing.hits += record.hits;
                existing.last_syscall_nr = record.last_syscall_nr;
            } else {
                merged.push(record);
            }
        }
        merged.sort_by_key(|record| record.site_pc);
        merged
    }

    /// Enables SUD on the current thread only.
    ///
    /// After this returns, every syscall instruction outside the gateway on
    /// this thread traps. Until the token is unregistered, the thread may
    /// execute only code whose syscalls are first-profile guest calls or are
    /// made through this substrate's gateway; ordinary Rust/libc syscalls can
    /// therefore fail closed. The token is intentionally not `Send`.
    pub fn register_current_thread(&self) -> Result<SudThreadRegistration, SyscallRefusal> {
        if self.closed || SUD_OWNER.load(Ordering::Acquire) != OWNER_INSTALLED {
            return Err(SyscallRefusal::StrategyUnavailableOnBackend);
        }
        // SAFETY: state remains retained for the installation lifetime.
        let state = unsafe { &*self.state };
        // SAFETY: gettid through the genuine gateway has no pointers. This is
        // safe on both new and already-registered threads because the gateway
        // range is always allowed by SUD.
        let tid = unsafe { gateway_syscall(state, libc::SYS_gettid, [0; 6]) };
        let tid = u64::try_from(tid).map_err(|_| SyscallRefusal::SudUnavailable { errno: 0 })?;
        // Duplicate detection is atomic-only and deliberately precedes every
        // un-gated syscall below, so a duplicate call from an already
        // dispatched thread returns this named refusal instead of trapping in
        // its own mask query.
        if state
            .registered_tids
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == tid)
        {
            return Err(SyscallRefusal::ConflictingStrategyInstalled);
        }
        if query_mask()? & signal_bit(libc::SIGSYS) != 0 {
            return Err(SyscallRefusal::SignalContract);
        }
        // Install this thread's own guarded stack while it is not yet
        // dispatched; all setup syscalls above are therefore still genuine.
        let alt_stack = AltStackOwner::install(self.page_size)?;
        let mut slot_index = None;
        for (index, slot) in state.registered_tids.iter().enumerate() {
            match slot.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    slot_index = Some(index);
                    break;
                }
                Err(existing) if existing == tid => {
                    return Err(SyscallRefusal::ConflictingStrategyInstalled);
                }
                Err(_) => {}
            }
        }
        let Some(slot_index) = slot_index else {
            return Err(SyscallRefusal::RegistryExhausted);
        };
        // SAFETY: prctl arguments are integers; the gateway range is retained.
        let result = unsafe {
            gateway_syscall(
                state,
                libc::SYS_prctl,
                [
                    PR_SET_SYSCALL_USER_DISPATCH as i64,
                    PR_SYS_DISPATCH_ON as i64,
                    self.gateway_range.0 as i64,
                    self.gateway_range.1 as i64,
                    0,
                    0,
                ],
            )
        };
        if result != 0 {
            state.registered_tids[slot_index].store(0, Ordering::Release);
            let errno = i32::try_from(-result).unwrap_or(0);
            return Err(SyscallRefusal::SudUnavailable { errno });
        }
        Ok(SudThreadRegistration {
            tid,
            slot_index,
            alt_stack: Some(alt_stack),
            active: true,
            _not_send: PhantomData,
        })
    }

    /// Restores SIGSYS and altstack custody after all thread tokens drain.
    /// Must be called by the installing thread.
    pub fn uninstall(mut self) -> Result<(), SyscallRefusal> {
        // SAFETY: state remains retained until the checks below complete.
        let state = unsafe { &*self.state };
        // SAFETY: gettid through the genuine gateway has no pointers. The
        // installing thread must already have unregistered itself.
        let tid = unsafe { gateway_syscall(state, libc::SYS_gettid, [0; 6]) };
        if tid != self.installer_tid as i64
            || self.lazy_batch.is_some()
            || self.lazy_poisoned
            || state
                .registered_tids
                .iter()
                .any(|slot| slot.load(Ordering::Acquire) != 0)
        {
            // A live lazypoline batch routes patched sites through this
            // gateway; retire it before uninstalling. Poisoned patch state
            // likewise retains every mapping.
            std::mem::forget(self);
            return Err(SyscallRefusal::SignalContract);
        }
        let result = self.uninstall_inner();
        if result.is_ok() {
            SUD_OWNER.store(OWNER_EMPTY, Ordering::Release);
        } else {
            SUD_OWNER.store(OWNER_POISONED, Ordering::Release);
            std::mem::forget(self);
        }
        result
    }

    fn uninstall_inner(&mut self) -> Result<(), SyscallRefusal> {
        if self.closed {
            return Ok(());
        }
        SUD_CLOSING.store(true, Ordering::Release);
        if query_action(libc::SIGSYS)? != self.installed_action {
            return Err(SyscallRefusal::SignalContract);
        }
        install_action(libc::SIGSYS, &self.prior_action)?;
        if query_action(libc::SIGSYS)? != self.prior_action {
            return Err(SyscallRefusal::SignalContract);
        }
        self.action_installed = false;
        // A pending foreign SIGSYS may already have entered the handler
        // before disposition restoration. Drain it before clearing state or
        // unmapping any storage it can reference.
        wait_for_handler_quiescence();
        SUD_STATE.store(std::ptr::null_mut(), Ordering::Release);

        if let Some(stack) = &mut self.installer_stack {
            stack.restore()?;
        }
        if let Some(gateway) = &mut self.gateway {
            gateway.unmap()?;
        }
        if !self.state.is_null() {
            // SAFETY: handler was restored and all registrations drained.
            unsafe { drop(Box::from_raw(self.state)) };
            self.state = std::ptr::null_mut();
        }
        self.closed = true;
        Ok(())
    }
}

/// RAII per-thread SUD registration token. It is neither `Send` nor `Sync`.
pub struct SudThreadRegistration {
    tid: u64,
    slot_index: usize,
    alt_stack: Option<AltStackOwner>,
    active: bool,
    _not_send: PhantomData<*mut ()>,
}

impl SudThreadRegistration {
    /// Linux thread ID registered for SUD.
    pub const fn tid(&self) -> u64 {
        self.tid
    }

    /// Disables SUD on this thread through the gateway and releases its slot.
    pub fn unregister(mut self) -> Result<(), SyscallRefusal> {
        let result = self.unregister_inner();
        if result.is_err() {
            std::mem::forget(self);
        }
        result
    }

    fn unregister_inner(&mut self) -> Result<(), SyscallRefusal> {
        if self.active {
            let state_ptr = SUD_STATE.load(Ordering::Acquire);
            if state_ptr.is_null() {
                return Err(SyscallRefusal::StrategyUnavailableOnBackend);
            }
            // SAFETY: installation retains state until all tokens drain.
            let state = unsafe { &*state_ptr };
            // SAFETY: gettid/prctl through the genuine gateway have integer args.
            let current = unsafe { gateway_syscall(state, libc::SYS_gettid, [0; 6]) };
            if current != self.tid as i64 {
                return Err(SyscallRefusal::ThreadNotRegistered);
            }
            // SAFETY: disabling SUD for this thread through its allowed gateway.
            let result = unsafe {
                gateway_syscall(
                    state,
                    libc::SYS_prctl,
                    [
                        PR_SET_SYSCALL_USER_DISPATCH as i64,
                        PR_SYS_DISPATCH_OFF as i64,
                        0,
                        0,
                        0,
                        0,
                    ],
                )
            };
            if result != 0 {
                let errno = i32::try_from(-result).unwrap_or(0);
                return Err(SyscallRefusal::SudUnavailable { errno });
            }
            state.registered_tids[self.slot_index].store(0, Ordering::Release);
            self.active = false;
        }
        if let Some(stack) = &mut self.alt_stack {
            stack.restore()?;
        }
        self.alt_stack = None;
        Ok(())
    }
}

impl Drop for SudThreadRegistration {
    fn drop(&mut self) {
        if self.unregister_inner().is_err() {
            let state_ptr = SUD_STATE.load(Ordering::Acquire);
            if !state_ptr.is_null() {
                // SAFETY: a token that cannot prove unregistration leaves the
                // process in an uncertain dispatch state and fails closed.
                unsafe { fail_stop(Some(&*state_ptr)) }
            }
            // SAFETY: no genuine gateway is available for a clean exit.
            unsafe { core::arch::asm!("ud2", options(noreturn, nostack)) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_claim_scans_all_slots_before_taking_an_earlier_hole() {
        let state = SudState {
            lazy: false,
            gateway_start: AtomicU64::new(0),
            gateway_end: AtomicU64::new(0),
            sites: Box::new([]),
            site_count: AtomicUsize::new(0),
            registered_tids: [const { AtomicU64::new(0) }; MAX_ACTIVE_THREADS],
            active_tids: [const { AtomicU64::new(0) }; MAX_ACTIVE_THREADS],
            traps: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            signal_returns: AtomicU64::new(0),
            fast_path_calls: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            nested: AtomicU64::new(0),
            active_overflow: AtomicU64::new(0),
            foreign: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
        };
        state.active_tids[1].store(77, Ordering::Release);
        assert!(matches!(claim_active_slot(&state, 77), ActiveClaim::Nested));
        assert_eq!(state.active_tids[0].load(Ordering::Acquire), 0);
        assert!(matches!(
            claim_active_slot(&state, 78),
            ActiveClaim::Claimed(0)
        ));
    }

    #[test]
    fn lazy_cert_classification_matches_trap_observation() {
        assert_eq!(classify_lazy_cert(Some((PATCH_PENDING, 39)), 39), Ok(()));
        assert_eq!(
            classify_lazy_cert(Some((PATCH_PENDING, 39)), 186),
            Err(SyscallRefusal::SyscallNumberRangeUnproven)
        );
        assert_eq!(
            classify_lazy_cert(None, 39),
            Err(SyscallRefusal::InvalidConfig {
                field: "logical_pc",
                reason: "site was not discovered by a lazypoline first trap",
            })
        );
        for state in [PATCH_TRAPPING, PATCH_REWRITTEN, PATCH_TRAP_PERMANENT] {
            assert_eq!(
                classify_lazy_cert(Some((state, 39)), 39),
                Err(SyscallRefusal::InvalidConfig {
                    field: "logical_pc",
                    reason: "site is not pending lazypoline patch application",
                })
            );
        }
    }

    #[test]
    fn lazy_record_site_marks_only_new_slots_pending() {
        let mut state = SudState {
            lazy: true,
            gateway_start: AtomicU64::new(0),
            gateway_end: AtomicU64::new(0),
            sites: (0..2)
                .map(|_| SudSiteSlot {
                    site_pc: AtomicU64::new(0),
                    last_nr: AtomicU64::new(0),
                    hits: AtomicU64::new(0),
                    patch_state: AtomicU8::new(PATCH_TRAPPING),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            site_count: AtomicUsize::new(0),
            registered_tids: [const { AtomicU64::new(0) }; MAX_ACTIVE_THREADS],
            active_tids: [const { AtomicU64::new(0) }; MAX_ACTIVE_THREADS],
            traps: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            signal_returns: AtomicU64::new(0),
            fast_path_calls: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            nested: AtomicU64::new(0),
            active_overflow: AtomicU64::new(0),
            foreign: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
        };
        assert!(record_site(&state, 0x4000, 39));
        assert_eq!(
            state.sites[0].patch_state.load(Ordering::Acquire),
            PATCH_PENDING
        );
        state.sites[0]
            .patch_state
            .store(PATCH_TRAP_PERMANENT, Ordering::Release);
        assert!(record_site(&state, 0x4000, 39));
        assert_eq!(
            state.sites[0].patch_state.load(Ordering::Acquire),
            PATCH_TRAP_PERMANENT,
            "a re-trap must not resurrect a trap-permanent site to pending"
        );
        assert_eq!(state.sites[0].hits.load(Ordering::Acquire), 2);
        state.lazy = false;
        assert!(record_site(&state, 0x5000, 39));
        assert_eq!(
            state.sites[1].patch_state.load(Ordering::Acquire),
            PATCH_TRAPPING,
            "trap strategy never marks sites pending"
        );
    }

    #[test]
    fn gateway_image_has_exact_raw_and_restorer_bytes() {
        let image = build_gateway_image(4096);
        assert_eq!(image.len(), 4096);
        assert_eq!(
            &image[0..26],
            &[
                0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xca, 0x4d, 0x89,
                0xc2, 0x4d, 0x89, 0xc8, 0x4c, 0x8b, 0x4c, 0x24, 0x08, 0x0f, 0x05, 0xc3,
            ]
        );
        assert_eq!(
            &image[GATEWAY_RESTORER_OFFSET..GATEWAY_RESTORER_OFFSET + 9],
            &[0xb8, 0x0f, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b]
        );
        let raw = liteinst::x86::decode64(0x700000, &image);
        assert_eq!(raw.instruction.mnemonic(), liteinst::x86::Mnemonic::Mov);
        let restorer = liteinst::x86::decode64(
            0x700000 + GATEWAY_RESTORER_OFFSET as u64,
            &image[GATEWAY_RESTORER_OFFSET..],
        );
        assert_eq!(
            restorer.instruction.mnemonic(),
            liteinst::x86::Mnemonic::Mov
        );
        assert_eq!(restorer.instruction.immediate32(), 15);
        assert!(
            image[GATEWAY_RESTORER_OFFSET + 9..]
                .iter()
                .all(|byte| *byte == 0x90)
        );
    }

    #[test]
    fn siginfo_layout_has_kernel_syscall_offsets() {
        assert_eq!(std::mem::offset_of!(KernelSiginfo, signo), 0);
        assert_eq!(std::mem::offset_of!(KernelSiginfo, code), 8);
        assert_eq!(std::mem::offset_of!(KernelSiginfo, call_addr), 16);
        assert_eq!(std::mem::offset_of!(KernelSiginfo, syscall), 24);
        assert_eq!(std::mem::offset_of!(KernelSiginfo, arch), 28);
        assert_eq!(std::mem::size_of::<KernelSiginfo>(), 128);
    }

    #[test]
    fn install_refuses_wrong_strategy_and_substrate_without_claiming_owner() {
        let zpoline = SyscallStrategyConfig::new(SyscallStrategy::Zpoline)
            .with_discovery(DiscoverySubstrate::Sud)
            .unwrap();
        assert_eq!(
            SudInstallation::install(zpoline).err(),
            Some(SyscallRefusal::InvalidConfig {
                field: "strategy",
                reason: "SUD substrate requires the trap or lazypoline strategy",
            })
        );
        let lazy_seccomp = SyscallStrategyConfig::new(SyscallStrategy::Lazypoline);
        assert_eq!(
            SudInstallation::install(lazy_seccomp).err(),
            Some(SyscallRefusal::InvalidConfig {
                field: "discovery",
                reason: "SUD substrate requires DiscoverySubstrate::Sud",
            }),
            "lazypoline has no in-process seccomp substrate in this slice"
        );
        let seccomp = SyscallStrategyConfig::new(SyscallStrategy::Trap);
        assert_eq!(
            SudInstallation::install(seccomp).err(),
            Some(SyscallRefusal::InvalidConfig {
                field: "discovery",
                reason: "SUD substrate requires DiscoverySubstrate::Sud",
            })
        );
        assert_eq!(SUD_OWNER.load(Ordering::Acquire), OWNER_EMPTY);
    }
}
