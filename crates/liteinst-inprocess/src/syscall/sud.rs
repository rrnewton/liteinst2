//! Linux Syscall User Dispatch trap substrate.
//!
//! This slice installs the gateway/restorer, SIGSYS custody, per-thread
//! registration, first-profile trap forwarding, and site recording. It never
//! rewrites a syscall site; lazypoline patch-on-first-trap is a later slice.

use std::ffi::c_void;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use crate::raw;
use crate::syscall::zpoline::DualMapping;
use crate::syscall::{
    DiscoverySubstrate, SyscallRefusal, SyscallStrategy, SyscallStrategyConfig,
    first_profile_supports,
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

struct SudSiteSlot {
    site_pc: AtomicU64,
    last_nr: AtomicU64,
    hits: AtomicU64,
}

struct SudState {
    gateway_start: AtomicU64,
    gateway_end: AtomicU64,
    sites: Box<[SudSiteSlot]>,
    site_count: AtomicUsize,
    registered_tids: [AtomicU64; MAX_ACTIVE_THREADS],
    active_tids: [AtomicU64; MAX_ACTIVE_THREADS],
    traps: AtomicU64,
    forwarded: AtomicU64,
    refused: AtomicU64,
    nested: AtomicU64,
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

/// Signal-handler counters. `traps` counts authenticated first-profile traps;
/// a refused authentication or policy failure is counted before fail-stop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SudCounters {
    /// Authenticated SUD traps that reached policy handling.
    pub traps: u64,
    /// Traps whose genuine syscall completed through the gateway.
    pub forwarded: u64,
    /// Authenticated traps refused by the first-profile or registry policy.
    pub refused: u64,
    /// Nested-handler detections.
    pub nested: u64,
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

fn page_size() -> Result<usize, SyscallRefusal> {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = usize::try_from(value).map_err(|_| SyscallRefusal::AllocationUnavailable)?;
    if !page.is_power_of_two() || page < 4096 {
        return Err(SyscallRefusal::AllocationUnavailable);
    }
    Ok(page)
}

fn qualify_host() -> Result<usize, SyscallRefusal> {
    let page = page_size()?;
    let leaf = core::arch::x86_64::__cpuid_count(7, 1);
    if leaf.edx & (1 << 21) != 0 {
        return Err(SyscallRefusal::StrategyUnavailableOnArch);
    }
    let cpu = core::arch::x86_64::__cpuid(1).eax;
    let model = ((cpu >> 4) & 15) | ((cpu >> 12) & 0xf0);
    if ((cpu >> 8) & 15) == 6 && matches!(model, 0x57 | 0x85) {
        return Err(SyscallRefusal::StrategyUnavailableOnArch);
    }
    let mut status = 0_u64;
    // SAFETY: arch_prctl writes one status word to the initialized slot.
    let result = unsafe {
        raw::syscall3(
            libc::SYS_arch_prctl as usize,
            0x5005,
            (&mut status as *mut u64) as usize,
            0,
        )
    };
    if result == 0 && status != 0 {
        return Err(SyscallRefusal::CetUnsupported);
    }
    Ok(page)
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

fn claim_active_slot(state: &SudState, tid: u64) -> Option<usize> {
    for (index, slot) in state.active_tids.iter().enumerate() {
        match slot.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(index),
            Err(existing) if existing == tid => return None,
            Err(_) => {}
        }
    }
    None
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
    slot.site_pc.store(site_pc, Ordering::Release);
    true
}

unsafe extern "C" fn sud_handler(signal: i32, info: *mut KernelSiginfo, context: *mut c_void) {
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
    let Some(active_index) = claim_active_slot(state, tid) else {
        state.nested.fetch_add(1, Ordering::AcqRel);
        // SAFETY: nested or over-capacity handler execution is fail-closed.
        unsafe { fail_stop(Some(state)) }
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
    prior_stack: libc::stack_t,
    alt_mapping: *mut c_void,
    alt_mapping_len: usize,
    alt_stack: *mut c_void,
    installer_tid: u64,
    action_installed: bool,
    stack_installed: bool,
    closed: bool,
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
        if config.strategy() != SyscallStrategy::Trap {
            return Err(if config.strategy() == SyscallStrategy::Lazypoline {
                SyscallRefusal::StrategyUnavailableOnBackend
            } else {
                SyscallRefusal::InvalidConfig {
                    field: "strategy",
                    reason: "SUD substrate slice requires the trap strategy",
                }
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
        let mut prior_stack: libc::stack_t = unsafe { std::mem::zeroed() };
        // SAFETY: sigaltstack query writes one complete native stack_t.
        if unsafe { libc::sigaltstack(std::ptr::null(), &mut prior_stack) } != 0 {
            return Err(SyscallRefusal::SignalContract);
        }
        if prior_stack.ss_flags & libc::SS_ONSTACK != 0 {
            return Err(SyscallRefusal::SignalContract);
        }
        let minimum = unsafe { libc::getauxval(51) } as usize;
        if minimum == 0
            || minimum
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(64 * 1024))
                .is_none_or(|bytes| bytes > ALT_STACK_BYTES)
        {
            return Err(SyscallRefusal::SignalContract);
        }

        claim_owner()?;
        let mut owner = Self {
            config,
            state: std::ptr::null_mut(),
            gateway: None,
            gateway_range: (0, 0),
            prior_action,
            installed_action: KernelAction::default(),
            prior_stack,
            alt_mapping: std::ptr::null_mut(),
            alt_mapping_len: 0,
            alt_stack: std::ptr::null_mut(),
            installer_tid: 0,
            action_installed: false,
            stack_installed: false,
            closed: false,
        };
        if let Err(error) = owner.install_inner(page) {
            owner.rollback_partial();
            release_owner();
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
            })
            .collect();
        let state = Box::new(SudState {
            gateway_start: AtomicU64::new(0),
            gateway_end: AtomicU64::new(0),
            sites: sites.into_boxed_slice(),
            site_count: AtomicUsize::new(0),
            registered_tids: [const { AtomicU64::new(0) }; MAX_ACTIVE_THREADS],
            active_tids: [const { AtomicU64::new(0) }; MAX_ACTIVE_THREADS],
            traps: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            nested: AtomicU64::new(0),
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

        self.install_altstack(page)?;
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
            mask: !signal_bit(libc::SIGSYS),
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

    fn install_altstack(&mut self, page: usize) -> Result<(), SyscallRefusal> {
        let total = ALT_STACK_BYTES + 2 * page;
        // SAFETY: a fresh anonymous guard mapping owned by this installation.
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
        self.alt_mapping = mapping;
        self.alt_mapping_len = total;
        let stack = unsafe { mapping.cast::<u8>().add(page).cast::<c_void>() };
        // SAFETY: the middle ALT_STACK_BYTES are inside the owned mapping.
        if unsafe { libc::mprotect(stack, ALT_STACK_BYTES, libc::PROT_READ | libc::PROT_WRITE) }
            != 0
        {
            return Err(SyscallRefusal::AllocationUnavailable);
        }
        self.alt_stack = stack;
        // SAFETY: touch every data page before any thread can take a signal.
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
        self.stack_installed = true;
        Ok(())
    }

    fn rollback_partial(&mut self) {
        if self.action_installed {
            let _ = install_action(libc::SIGSYS, &self.prior_action);
            self.action_installed = false;
        }
        SUD_STATE.store(std::ptr::null_mut(), Ordering::Release);
        if self.stack_installed {
            // SAFETY: partial install did not enable SUD or admit execution.
            unsafe { libc::sigaltstack(&self.prior_stack, std::ptr::null_mut()) };
            self.stack_installed = false;
        }
        if !self.alt_mapping.is_null() {
            // SAFETY: altstack storage is owned only by this partial owner.
            unsafe { libc::munmap(self.alt_mapping, self.alt_mapping_len) };
            self.alt_mapping = std::ptr::null_mut();
            self.alt_mapping_len = 0;
        }
        if let Some(gateway) = &mut self.gateway {
            let _ = gateway.unmap();
        }
        if !self.state.is_null() {
            // SAFETY: state was allocated by install_inner and is unpublished.
            unsafe { drop(Box::from_raw(self.state)) };
            self.state = std::ptr::null_mut();
        }
        self.closed = true;
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
        SudCounters {
            traps: state.traps.load(Ordering::Acquire),
            forwarded: state.forwarded.load(Ordering::Acquire),
            refused: state.refused.load(Ordering::Acquire),
            nested: state.nested.load(Ordering::Acquire),
            foreign: state.foreign.load(Ordering::Acquire),
            overflow: state.overflow.load(Ordering::Acquire),
            recorded_sites: self.sites().len(),
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
        if query_mask()? & signal_bit(libc::SIGSYS) != 0 {
            return Err(SyscallRefusal::SignalContract);
        }
        // SAFETY: state remains retained for the installation lifetime.
        let state = unsafe { &*self.state };
        // SAFETY: gettid through the genuine gateway has no pointers.
        let tid = unsafe { gateway_syscall(state, libc::SYS_gettid, [0; 6]) };
        let tid = u64::try_from(tid).map_err(|_| SyscallRefusal::SudUnavailable { errno: 0 })?;
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
            || state
                .registered_tids
                .iter()
                .any(|slot| slot.load(Ordering::Acquire) != 0)
        {
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
        if query_action(libc::SIGSYS)? != self.installed_action {
            return Err(SyscallRefusal::SignalContract);
        }
        install_action(libc::SIGSYS, &self.prior_action)?;
        if query_action(libc::SIGSYS)? != self.prior_action {
            return Err(SyscallRefusal::SignalContract);
        }
        self.action_installed = false;
        SUD_STATE.store(std::ptr::null_mut(), Ordering::Release);

        let mut actual: libc::stack_t = unsafe { std::mem::zeroed() };
        // SAFETY: sigaltstack query writes one complete native stack_t.
        if unsafe { libc::sigaltstack(std::ptr::null(), &mut actual) } != 0
            || actual.ss_sp != self.alt_stack
            || actual.ss_size != ALT_STACK_BYTES
            || actual.ss_flags != 0
        {
            return Err(SyscallRefusal::SignalContract);
        }
        // SAFETY: installer thread is not executing on the alternate stack.
        if unsafe { libc::sigaltstack(&self.prior_stack, std::ptr::null_mut()) } != 0 {
            return Err(SyscallRefusal::SignalContract);
        }
        let mut restored: libc::stack_t = unsafe { std::mem::zeroed() };
        // SAFETY: sigaltstack query writes one complete native stack_t.
        if unsafe { libc::sigaltstack(std::ptr::null(), &mut restored) } != 0
            || restored.ss_sp != self.prior_stack.ss_sp
            || restored.ss_size != self.prior_stack.ss_size
            || restored.ss_flags != self.prior_stack.ss_flags
        {
            return Err(SyscallRefusal::SignalContract);
        }
        self.stack_installed = false;
        if !self.alt_mapping.is_null() {
            // SAFETY: the restored stack no longer names this mapping.
            if unsafe { libc::munmap(self.alt_mapping, self.alt_mapping_len) } != 0 {
                return Err(SyscallRefusal::AllocationUnavailable);
            }
            self.alt_mapping = std::ptr::null_mut();
            self.alt_mapping_len = 0;
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
        if !self.active {
            return Ok(());
        }
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
                reason: "SUD substrate slice requires the trap strategy",
            })
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
