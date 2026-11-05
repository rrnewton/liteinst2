//! Executable cache allocation, the entry bridge, dispatcher loop,
//! and fault recovery through the PC map.
//!
//! Execution model (P1a): in-process. The dispatcher loads full guest
//! state, enters the cache, and the cache returns only at exit stubs
//! (return / indirect / syscall / nondet) or via the fault handler.
//! A synchronous fault inside copied code is reported at the precise
//! source PC recovered through the PC map; it is never delivered as
//! a cache PC.

use std::sync::atomic::{AtomicPtr, Ordering};

use crate::cache::{CacheIndex, CacheRecord};
#[cfg(test)]
use crate::pcmap::{CallStage, CommonStage, Recovery, StubStage};
use crate::recovery::RecoveryInput;
use crate::refuse::Refuse;

pub use crate::recovery::{FaultInput, FaultKind};
use crate::state::{
    GuestState, JitData, OFF_HOST_R12, OFF_HOST_R13, OFF_HOST_R14, OFF_HOST_R15, OFF_HOST_RBP,
    OFF_HOST_RBX, OFF_HOST_RSP, OFF_STATE, ST_R8, ST_R9, ST_R10, ST_R11, ST_R12, ST_R13, ST_R14,
    ST_R15, ST_RAX, ST_RBP, ST_RBX, ST_RCX, ST_RDI, ST_RDX, ST_RFLAGS, ST_RSI, ST_RSP, exit_kind,
};
use crate::translate::{Translation, translate};
use crate::types::{CacheKey, CountProfile, Generation, RegionFacts, byte_hash};

pub const CODE_CAP: usize = 1 << 18;
/// Block entries between pending-signal polls (progress bound).
pub const POLL_BUDGET: u64 = 16384;
const PAGE: usize = 4096;

core::arch::global_asm!(
    ".global liteinst_jit_enter",
    "liteinst_jit_enter:",
    "mov [rdi + {host_rsp}], rsp",
    "mov [rdi + {host_rbx}], rbx",
    "mov [rdi + {host_rbp}], rbp",
    "mov [rdi + {host_r12}], r12",
    "mov [rdi + {host_r13}], r13",
    "mov [rdi + {host_r14}], r14",
    "mov [rdi + {host_r15}], r15",
    // Build the iret frame on the HOST stack (SS, guest RSP, guest
    // RFLAGS, CS, entry) so entry writes no guest memory at all,
    // including the red zone below guest RSP.
    "xor eax, eax",
    "mov ax, ss",
    "push rax",
    "push qword ptr [rdi + {rsp}]",
    "push qword ptr [rdi + {flags}]",
    "xor eax, eax",
    "mov ax, cs",
    "push rax",
    "push rsi",
    "mov rax, [rdi + {rax}]",
    "mov rbx, [rdi + {rbx}]",
    "mov rcx, [rdi + {rcx}]",
    "mov rdx, [rdi + {rdx}]",
    "mov rsi, [rdi + {rsi}]",
    "mov rbp, [rdi + {rbp}]",
    "mov r8, [rdi + {r8}]",
    "mov r9, [rdi + {r9}]",
    "mov r10, [rdi + {r10}]",
    "mov r11, [rdi + {r11}]",
    "mov r12, [rdi + {r12}]",
    "mov r13, [rdi + {r13}]",
    "mov r14, [rdi + {r14}]",
    "mov r15, [rdi + {r15}]",
    "mov rdi, [rdi + {rdi}]",
    "iretq",
    ".global liteinst_jit_enter_end",
    "liteinst_jit_enter_end:",
    host_rsp = const OFF_HOST_RSP,
    host_rbx = const OFF_HOST_RBX,
    host_rbp = const OFF_HOST_RBP,
    host_r12 = const OFF_HOST_R12,
    host_r13 = const OFF_HOST_R13,
    host_r14 = const OFF_HOST_R14,
    host_r15 = const OFF_HOST_R15,
    flags = const OFF_STATE + ST_RFLAGS,
    rsp = const OFF_STATE + ST_RSP,
    rax = const OFF_STATE + ST_RAX,
    rbx = const OFF_STATE + ST_RBX,
    rcx = const OFF_STATE + ST_RCX,
    rdx = const OFF_STATE + ST_RDX,
    rsi = const OFF_STATE + ST_RSI,
    rdi = const OFF_STATE + ST_RDI,
    rbp = const OFF_STATE + ST_RBP,
    r8 = const OFF_STATE + ST_R8,
    r9 = const OFF_STATE + ST_R9,
    r10 = const OFF_STATE + ST_R10,
    r11 = const OFF_STATE + ST_R11,
    r12 = const OFF_STATE + ST_R12,
    r13 = const OFF_STATE + ST_R13,
    r14 = const OFF_STATE + ST_R14,
    r15 = const OFF_STATE + ST_R15,
);

unsafe extern "C" {
    fn liteinst_jit_enter(data: *mut JitData, entry: *const u8);
    fn liteinst_jit_enter_end();
}

fn bridge_range() -> (u64, u64) {
    (
        liteinst_jit_enter as *const () as usize as u64,
        liteinst_jit_enter_end as *const () as usize as u64,
    )
}

/// What a handler asks the dispatcher to do after an exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resume {
    At(u64),
    Done,
}

/// Serves instructions that exit their block. Implementors must leave
/// `state` exactly as native execution of the instruction would
/// (including the `RCX`/`R11` syscall clobbers when they emulate a
/// syscall) and name the resume PC.
pub trait Handler {
    fn syscall(
        &mut self,
        state: &mut GuestState,
        insn_pc: u64,
        next_pc: u64,
    ) -> Result<Resume, Refuse>;
    fn nondet(
        &mut self,
        _state: &mut GuestState,
        _kind: crate::decode::NondetKind,
        insn_pc: u64,
        _next_pc: u64,
    ) -> Result<Resume, Refuse> {
        Err(Refuse::NoHandler { src_pc: insn_pc })
    }
}

/// Guest memory reads the dispatcher needs (return targets).
pub trait GuestMemory {
    fn read_u64(&self, addr: u64) -> Option<u64>;
}

/// In-process guest memory via `process_vm_readv` on this process, so
/// a bad guest address fails cleanly instead of faulting the
/// dispatcher.
pub struct ProcessMemory;

impl GuestMemory for ProcessMemory {
    fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut buf = [0u8; 8];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: 8,
        };
        let remote = libc::iovec {
            iov_base: addr as usize as *mut libc::c_void,
            iov_len: 8,
        };
        // SAFETY: both iovecs describe live 8-byte buffers for the
        // duration of the call; failure is reported, never faults.
        let n = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
        (n == 8).then(|| u64::from_ne_bytes(buf))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub state: GuestState,
    pub branches: u64,
    pub instructions: u64,
    pub exits: u64,
    /// Pending async signals taken into custody during the return
    /// transition (dequeued while blocked, reported, not lost).
    pub also_pending: Vec<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fault {
    pub kind: FaultKind,
    /// Additional pending async signals taken into custody with
    /// this stop (dequeued while blocked, reported, not lost).
    pub also_pending: Vec<i32>,
    pub src_pc: u64,
    pub addr: u64,
    pub signum: i32,
    pub state: GuestState,
    pub branches: u64,
    pub instructions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunError {
    Refuse(Refuse),
    Fault(Box<Fault>),
}

impl From<Refuse> for RunError {
    fn from(r: Refuse) -> RunError {
        RunError::Refuse(r)
    }
}
impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "liteinst-jit run: {self:?}")
    }
}
impl std::error::Error for RunError {}

struct Arena {
    base: *mut u8,
    total: usize,
}

impl Arena {
    fn new() -> Result<Arena, Refuse> {
        let total = CODE_CAP + 64 * PAGE;
        // SAFETY: anonymous private mapping of `total` bytes.
        let p = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(Refuse::MappingPolicy {
                operation: "mmap cache",
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        Ok(Arena {
            base: p.cast(),
            total,
        })
    }
    fn data_addr(&self) -> u64 {
        self.base as u64 + CODE_CAP as u64
    }
    fn install_code(&mut self, code: &[u8]) -> Result<(), Refuse> {
        if code.len() > CODE_CAP {
            return Err(Refuse::BudgetExceeded { what: "code cache" });
        }
        // SAFETY: the mapping is RW and at least CODE_CAP bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), self.base, code.len());
            if libc::mprotect(
                self.base.cast(),
                CODE_CAP,
                libc::PROT_READ | libc::PROT_EXEC,
            ) != 0
            {
                return Err(Refuse::MappingPolicy {
                    operation: "mprotect cache RX",
                    errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                });
            }
        }
        Ok(())
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: owned mapping from `new`.
        unsafe {
            libc::munmap(self.base.cast(), self.total);
        }
    }
}

struct ActiveRun {
    gen_lo: u64,
    gen_hi: u64,
    bridge_lo: u64,
    bridge_hi: u64,
    data: *mut JitData,
    fault_gen_pc: u64,
    fault_addr: u64,
    fault_sig: i32,
    fault_si_code: i32,
    fault_err: u64,
}

// SAFETY discipline: `ACTIVE` is set only by the single-threaded P1a
// dispatcher around cache entry, and cleared before any other code
// runs guest state. The handler treats it as read-only except for
// the fault record fields of the pointee.
static ACTIVE: AtomicPtr<ActiveRun> = AtomicPtr::new(core::ptr::null_mut());
// glibc sigjmp_buf is opaque (jmp_buf + saved mask); 512 bytes is
// comfortably larger than the x86-64 layout. Bound directly because
// the libc crate does not export the sigjmp family.
static mut JMP_BUF: [u64; 64] = [0; 64];

unsafe extern "C" {
    #[link_name = "__sigsetjmp"]
    fn sigsetjmp_raw(env: *mut u8, savemask: i32) -> i32;
    fn siglongjmp(env: *mut u8, val: i32) -> !;
}

/// Previous dispositions, chained for faults outside the cache
/// (notably the Rust runtime's stack-overflow SIGSEGV handler).
/// Entries are `(handler, flags)` per signal in `FAULT_SIGNALS`.
static mut PREV_HANDLERS: [(usize, i32); 4] = [(usize::MAX, 0); 4];
const FAULT_SIGNALS: [i32; 4] = [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE];

fn chain_previous(sig: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    let idx = FAULT_SIGNALS.iter().position(|&s| s == sig).unwrap_or(0);
    // SAFETY: PREV_HANDLERS is written once at install time before
    // any guest code runs, single-threaded dispatcher discipline.
    let (handler, flags) = unsafe { PREV_HANDLERS[idx] };
    if handler == libc::SIG_IGN {
        return; // An ignored signal stays ignored, exactly.
    }
    if handler == usize::MAX || handler == libc::SIG_DFL {
        // SAFETY: default disposition and re-raise reproduces the
        // kernel-visible fault exactly.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
        return;
    }
    if flags & libc::SA_SIGINFO != 0 {
        // SAFETY: the previous action was installed with SA_SIGINFO,
        // so its handler has the three-argument signature.
        let f: extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) =
            unsafe { core::mem::transmute(handler) };
        f(sig, info, ctx);
    } else {
        // SAFETY: classic one-argument signal handler.
        let f: extern "C" fn(i32) = unsafe { core::mem::transmute(handler) };
        f(sig);
    }
}

/// Establish the SysV host direction-flag state. First action in
/// any Rust code reached with guest flags live.
fn clear_df() {
    // SAFETY: CLD affects only DF, which the host ABI requires clear.
    unsafe {
        core::arch::asm!("cld");
    }
}

extern "C" fn fault_handler(sig: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    clear_df();
    let active = ACTIVE.load(Ordering::SeqCst);
    if active.is_null() || ctx.is_null() {
        chain_previous(sig, info, ctx);
        return;
    }
    // SAFETY: ctx is the kernel-provided ucontext for this signal.
    let gregs = unsafe { (*(ctx as *const libc::ucontext_t)).uc_mcontext.gregs };
    let rip = gregs[libc::REG_RIP as usize] as u64;
    // SAFETY: `active` is live for the whole cache-entry window.
    let run = unsafe { &mut *active };
    let in_bridge = rip >= run.bridge_lo && rip < run.bridge_hi;
    if !in_bridge && (rip < run.gen_lo || rip >= run.gen_hi) {
        chain_previous(sig, info, ctx);
        return;
    }
    run.fault_gen_pc = rip;
    run.fault_err = gregs[libc::REG_ERR as usize] as u64;
    run.fault_sig = sig;
    run.fault_si_code = if info.is_null() {
        0
    } else {
        // SAFETY: info is kernel-provided for this signal.
        unsafe { (*info).si_code }
    };
    run.fault_addr = if info.is_null() {
        0
    } else {
        // SAFETY: info is kernel-provided for this signal.
        unsafe { (*info).si_addr() as usize as u64 }
    };
    // SAFETY: `data` points at the allocation-resident JitData.
    let st = unsafe { &mut (*run.data).interrupted };
    st.rax = gregs[libc::REG_RAX as usize] as u64;
    st.rbx = gregs[libc::REG_RBX as usize] as u64;
    st.rcx = gregs[libc::REG_RCX as usize] as u64;
    st.rdx = gregs[libc::REG_RDX as usize] as u64;
    st.rsi = gregs[libc::REG_RSI as usize] as u64;
    st.rdi = gregs[libc::REG_RDI as usize] as u64;
    st.rbp = gregs[libc::REG_RBP as usize] as u64;
    st.rsp = gregs[libc::REG_RSP as usize] as u64;
    st.r8 = gregs[libc::REG_R8 as usize] as u64;
    st.r9 = gregs[libc::REG_R9 as usize] as u64;
    st.r10 = gregs[libc::REG_R10 as usize] as u64;
    st.r11 = gregs[libc::REG_R11 as usize] as u64;
    st.r12 = gregs[libc::REG_R12 as usize] as u64;
    st.r13 = gregs[libc::REG_R13 as usize] as u64;
    st.r14 = gregs[libc::REG_R14 as usize] as u64;
    st.r15 = gregs[libc::REG_R15 as usize] as u64;
    st.rflags = gregs[libc::REG_EFL as usize] as u64;
    // SAFETY: JMP_BUF was armed by sigsetjmp in the dispatcher for
    // exactly this cache-entry window.
    unsafe {
        siglongjmp(core::ptr::addr_of_mut!(JMP_BUF).cast(), 1);
    }
}

/// In-process adapter over the backend-neutral recovery core
/// in [`crate::recovery`]: snapshots the cache data page into a
/// plain [`RecoveryInput`], runs the shared recovery rules, and
/// maps the recovered stop into this dispatcher's
/// custody-carrying [`Fault`] (with no additional pending
/// signals recorded yet; the return transition in
/// [`Executable::run`] owns custody bookkeeping). Output is
/// identical to the pre-extraction in-process implementation.
pub fn recover_fault(
    t: &Translation,
    profile: CountProfile,
    data: &JitData,
    input: FaultInput,
) -> Fault {
    let stop = crate::recovery::recover(
        t,
        profile,
        RecoveryInput {
            provenance: input,
            interrupted: data.interrupted,
            saved: data.state,
            spill_rax: data.spill_rax,
            spill_flags: data.spill_flags,
            branches: data.branch_count,
            instructions: data.instruction_count,
            exit_kind: data.exit_kind,
            exit_src: data.exit_src,
        },
    );
    Fault {
        also_pending: Vec::new(),
        kind: stop.kind,
        src_pc: stop.src_pc,
        addr: stop.addr,
        signum: stop.signum,
        state: stop.state,
        branches: stop.branches,
        instructions: stop.instructions,
    }
}

/// Alternate signal stack so faults with a wild guest RSP (whose
/// signal frame could not be built on the guest stack at all) still
/// reach the recovery handler.
fn ensure_altstack() -> Result<(), Refuse> {
    // Revalidated on every call: a first successful setup is not
    // permanent ownership proof if the thread later disables or
    // replaces its alternate stack.
    static ALT_BASE: std::sync::atomic::AtomicPtr<u8> =
        std::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
    const ALT_LEN: usize = 1 << 20;
    let mut old: libc::stack_t = unsafe { core::mem::zeroed() };
    // SAFETY: query-only sigaltstack with a null new stack.
    if unsafe { libc::sigaltstack(core::ptr::null(), &mut old) } != 0 {
        return Err(Refuse::MappingPolicy {
            operation: "sigaltstack query",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    if old.ss_flags & libc::SS_DISABLE == 0 {
        // An enabled stack (ours, or the Rust runtime's): preserve
        // and reuse it, never replace it.
        if old.ss_size >= 8192 {
            return Ok(());
        }
        return Err(Refuse::SignalOwnership {
            signum: 0,
            taken: Vec::new(),
        });
    }
    let mut base = ALT_BASE.load(Ordering::SeqCst);
    if base.is_null() {
        // SAFETY: leaked anonymous mapping used only as sigaltstack.
        let mapped = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                ALT_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(Refuse::MappingPolicy {
                operation: "mmap altstack",
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        base = mapped as *mut u8;
        ALT_BASE.store(base, Ordering::SeqCst);
    }
    let stack = libc::stack_t {
        ss_sp: base.cast(),
        ss_flags: 0,
        ss_size: ALT_LEN,
    };
    // SAFETY: installing our leaked mapping while disabled.
    if unsafe { libc::sigaltstack(&stack, core::ptr::null_mut()) } != 0 {
        return Err(Refuse::MappingPolicy {
            operation: "sigaltstack install",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    Ok(())
}

/// Application signal range: standard signals plus the real-time
/// range. 32/33 are reserved internally by glibc and cannot carry
/// application handlers, so they are the only documented skip.
pub(crate) fn async_signal_range() -> impl Iterator<Item = i32> {
    (1..=64).filter(|&sig| {
        sig != libc::SIGKILL
            && sig != libc::SIGSTOP
            && sig != 32
            && sig != 33
            && !FAULT_SIGNALS.contains(&sig)
    })
}

fn pending_async_signals() -> Result<Vec<i32>, Refuse> {
    let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
    // SAFETY: sigpending fills the set.
    if unsafe { libc::sigpending(&mut set) } != 0 {
        return Err(Refuse::SignalOwnership {
            signum: 0,
            taken: Vec::new(),
        });
    }
    Ok(async_signal_range()
        .filter(|&sig| {
            // SAFETY: membership query on a filled set.
            (unsafe { libc::sigismember(&set, sig) } == 1)
        })
        .collect())
}

fn pending_async_signal() -> Result<Option<i32>, Refuse> {
    Ok(pending_async_signals()?.into_iter().next())
}

/// Result of `run_masked`, retaining custody-error provenance.
/// `poll_custody_error` means the returned custody refusal came
/// from the Poll arm's own observation/dequeue path. It is kept
/// distinct from a same-shaped refusal returned by the Handler so
/// only custody-origin errors take the wrapper's full-mask
/// fallback.
struct MaskedOutcome {
    result: Result<Outcome, RunError>,
    poll_custody_error: bool,
}

/// Canonical custody-record form promised by `SignalOwnership`:
/// distinct signal numbers in ascending order, at every exit.
fn canonicalize_taken(mut taken: Vec<i32>) -> Vec<i32> {
    taken.sort_unstable();
    taken.dedup();
    taken
}

/// Take custody of *every* pending async signal: dequeue all
/// queued instances of each pending number while still blocked,
/// so restoring the caller's mask cannot deliver a leftover
/// default-terminate signal before the stop is observable.
/// Returns the taken numbers in ascending order (each once).
fn take_all_pending_async() -> Result<Vec<i32>, Refuse> {
    let mut taken = Vec::new();
    loop {
        let Some(sig) = pending_async_signal().map_err(|mut e| {
            // A later observation failure must not erase custody
            // already taken in earlier iterations.
            if let Refuse::SignalOwnership { taken: prior, .. } = &mut e {
                *prior = canonicalize_taken(taken.clone());
            }
            e
        })?
        else {
            return Ok(canonicalize_taken(taken));
        };
        if taken.contains(&sig) {
            // Dequeue below must make progress; bail out rather
            // than spin if the kernel keeps reporting it.
            return Err(Refuse::SignalOwnership {
                signum: sig,
                taken: canonicalize_taken(taken),
            });
        }
        let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, sig);
        }
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
            // SAFETY: dequeue one pending instance of the blocked sig.
            let r = unsafe { libc::sigtimedwait(&set, &mut info, &ts) };
            if r == sig {
                // Record custody immediately, before waiting for
                // any further instance: a failure on the *next*
                // wait must still report this consumed signal.
                // Insert in canonical position so a lower number
                // arriving later cannot make the record descend.
                if let Err(position) = taken.binary_search(&sig) {
                    taken.insert(position, sig);
                }
                continue;
            }
            let errno = std::io::Error::last_os_error().raw_os_error();
            if r == -1 && errno == Some(libc::EAGAIN) {
                break;
            }
            if r == -1 && errno == Some(libc::EINTR) {
                continue;
            }
            return Err(Refuse::SignalOwnership {
                signum: sig,
                taken: canonicalize_taken(taken),
            });
        }
        if !taken.contains(&sig) {
            // The pending query reported this number but no wait
            // consumed it; do not spin on a contradictory custody
            // observation, and do not claim it as taken.
            return Err(Refuse::SignalOwnership {
                signum: sig,
                taken: canonicalize_taken(taken),
            });
        }
    }
}
/// P1a signal envelope admission: asynchronous signals are
/// blocked (not guest-delivered) during a run, so a process that
/// has installed a handler for one is refused before execution
/// rather than having delivery silently deferred. Default and
/// ignore dispositions are admitted (and preserved on restore).
fn check_async_handlers() -> Result<(), Refuse> {
    for sig in async_signal_range() {
        let mut old: libc::sigaction = unsafe { core::mem::zeroed() };
        // SAFETY: query-only sigaction.
        if unsafe { libc::sigaction(sig, core::ptr::null(), &mut old) } != 0 {
            return Err(Refuse::SignalOwnership {
                signum: sig,
                taken: Vec::new(),
            });
        }
        if old.sa_sigaction != libc::SIG_DFL && old.sa_sigaction != libc::SIG_IGN {
            return Err(Refuse::SignalOwnership {
                signum: sig,
                taken: Vec::new(),
            });
        }
    }
    Ok(())
}

fn install_fault_handlers() -> Result<(), Refuse> {
    ensure_altstack()?;
    for (idx, sig) in FAULT_SIGNALS.into_iter().enumerate() {
        let mut old: libc::sigaction = unsafe { core::mem::zeroed() };
        // SAFETY: query-only sigaction with a null new action.
        if unsafe { libc::sigaction(sig, core::ptr::null(), &mut old) } != 0 {
            return Err(Refuse::SignalOwnership {
                signum: sig,
                taken: Vec::new(),
            });
        }
        if old.sa_sigaction == fault_handler as *const () as usize {
            continue;
        }
        // Record whatever was there (including the Rust runtime's
        // stack-overflow handler) for chaining; P1a intercepts only
        // cache-range PCs, everything else forwards untouched.
        // SAFETY: written before guest execution, read by the
        // handler under the same single-threaded discipline.
        unsafe {
            if PREV_HANDLERS[idx].0 == usize::MAX {
                PREV_HANDLERS[idx] = (old.sa_sigaction, old.sa_flags);
            }
        }
        let mut act: libc::sigaction = unsafe { core::mem::zeroed() };
        act.sa_sigaction = fault_handler as *const () as usize;
        act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        // SAFETY: previous disposition recorded above for chaining.
        if unsafe { libc::sigaction(sig, &act, core::ptr::null_mut()) } != 0 {
            return Err(Refuse::SignalOwnership {
                signum: sig,
                taken: Vec::new(),
            });
        }
    }
    Ok(())
}

/// True when a CET shadow stack is active for this process, where
/// synthesized call/return stack effects would desynchronize it.
/// Old or CET-less kernels answer EINVAL, treated as inactive
/// (probed on this host against asm/prctl.h ARCH_SHSTK_STATUS).
fn cet_shadow_stack_active() -> Result<bool, Refuse> {
    const ARCH_SHSTK_STATUS: i32 = 0x5005;
    let mut features: u64 = 0;
    // SAFETY: arch_prctl status query writing one u64 through the
    // provided pointer.
    let r = unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            ARCH_SHSTK_STATUS,
            core::ptr::addr_of_mut!(features),
        )
    };
    if r == 0 {
        return Ok(features & 1 != 0);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        // Known CET-unavailable answers are inactive proof; every
        // other failure is unknown state and refuses (R5).
        Some(libc::EINVAL) | Some(libc::ENODEV) | Some(libc::ENOSYS) => Ok(false),
        _ => Err(Refuse::Arch {
            what: "CET shadow-stack status unknown",
        }),
    }
}

fn check_cet_inactive() -> Result<(), Refuse> {
    if cet_shadow_stack_active()? {
        return Err(Refuse::Arch {
            what: "CET shadow stack active (call/ret rewriting unadmitted)",
        });
    }
    Ok(())
}

/// Shared syscall entry-kind + lifecycle guard, used by every
/// dispatcher backend before a syscall-class exit is served or
/// stepped. The syscall-class also contains compat entry
/// instructions, whose numbers are a different ABI (for example
/// int 0x80 execve is 11, the x86-64 munmap number). Linux
/// routes SYSENTER to the IA32 compat entry (or an invalid/#UD
/// path where compat is unavailable), never to native x86-64
/// dispatch. The actual entry kind is therefore resolved from
/// the decoded terminator before interpreting RAX: only Syscall
/// proceeds to the native-number guard; Sysenter and Int are
/// refused by distinct names. Lifecycle syscalls are then
/// reserved by the executor envelope and refused by name before
/// any backend can observe or service them; clone-family calls
/// are reserved regardless of flags. Linux native dispatch
/// examines only the low 32 bits of RAX, so classification uses
/// those bits for the guard alone and leaves raw RAX untouched.
pub(crate) fn syscall_guard(t: &Translation, exit_src: u64, rax: u64) -> Result<(), Refuse> {
    let entry_mnemonic = t.blocks.values().find_map(|b| {
        b.term
            .as_ref()
            .filter(|term| term.pc == exit_src)
            .map(|term| term.instruction.mnemonic())
    });
    match entry_mnemonic {
        Some(iced_x86::Mnemonic::Syscall) => {}
        Some(iced_x86::Mnemonic::Sysenter) => {
            return Err(Refuse::Arch {
                what: "sysenter compat entry outside P1a envelope",
            });
        }
        Some(iced_x86::Mnemonic::Int) => {
            return Err(Refuse::Arch {
                what: "ia32 compat syscall entry outside P1a envelope",
            });
        }
        _ => {
            return Err(Refuse::Unrelocatable {
                src_pc: exit_src,
                reason: "syscall entry kind outside P1a envelope",
            });
        }
    }
    let syscall_nr = rax as u32;
    let lifecycle = match syscall_nr {
        x if x == libc::SYS_execve as u32 || x == libc::SYS_execveat as u32 => {
            Some(Refuse::ExecSuccessor)
        }
        x if x == libc::SYS_clone as u32 => Some(Refuse::ThreadLifecycle { what: "clone" }),
        x if x == libc::SYS_fork as u32 => Some(Refuse::ThreadLifecycle { what: "fork" }),
        x if x == libc::SYS_vfork as u32 => Some(Refuse::ThreadLifecycle { what: "vfork" }),
        x if x == libc::SYS_clone3 as u32 => Some(Refuse::ThreadLifecycle { what: "clone3" }),
        _ => None,
    };
    match lifecycle {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

fn lahf_available() -> bool {
    let r = core::arch::x86_64::__cpuid_count(0x8000_0001, 0);
    r.ecx & 1 != 0
}

/// A prepared executable translation plus its cache index.
pub struct Executable {
    // Kept alive for the mapping's lifetime; dropped last.
    #[allow(dead_code)]
    arena: Arena,
    translation: Translation,
    index: CacheIndex,
    data: *mut JitData,
    profile: CountProfile,
    valid: bool,
}

impl Executable {
    pub fn prepare(
        region: &RegionFacts,
        entry: u64,
        profile: CountProfile,
    ) -> Result<Executable, Refuse> {
        if !lahf_available() {
            return Err(Refuse::Arch {
                what: "LAHF/SAHF unavailable in 64-bit mode",
            });
        }
        check_cet_inactive()?;
        let mut arena = Arena::new()?;
        let base = arena.base as u64;
        let data_addr = arena.data_addr();
        let translation = translate(region, entry, profile, base, data_addr)?;
        arena.install_code(&translation.code)?;
        let mut index = CacheIndex::new(region.generation);
        for block in translation.blocks.values() {
            let end = block
                .insns
                .last()
                .map(|i| i.pc + i.len as u64)
                .unwrap_or(block.start)
                .max(
                    block
                        .term
                        .as_ref()
                        .map_or(block.start, |t| t.pc + t.len as u64),
                );
            let bytes = region
                .slice_from(block.start)
                .map(|s| &s[..(end - block.start) as usize])
                .unwrap_or(&[]);
            index.insert(CacheRecord {
                key: CacheKey {
                    src_pc: block.start,
                    byte_hash: byte_hash(bytes),
                    generation: region.generation,
                    profile,
                },
                src_start: block.start,
                src_end: end,
                gen_entry: translation.block_gen[&block.start],
            })?;
        }
        Ok(Executable {
            arena,
            translation,
            index,
            data: data_addr as *mut JitData,
            profile,
            valid: true,
        })
    }

    /// Retired-instruction total when execution stopped *before*
    /// the instruction at `src_pc`, correcting the block-head
    /// pre-credit under the instruction-counting profile.
    fn retired_instructions_at(&self, counted: u64, src_pc: u64) -> u64 {
        crate::recovery::instructions_retired_at(&self.translation, self.profile, counted, src_pc)
    }

    pub fn translation(&self) -> &Translation {
        &self.translation
    }

    /// Invalidate overlapping entries and advance the generation.
    /// After any invalidation the executable refuses to run: P1a
    /// eviction is flush-and-reprepare, never patch-in-place.
    pub fn invalidate(
        &mut self,
        src_start: u64,
        src_end: u64,
        new_generation: Generation,
    ) -> Result<usize, Refuse> {
        let n = self.index.invalidate(src_start, src_end, new_generation)?;
        self.valid = false;
        Ok(n)
    }

    /// Run from `state.rip` until a return pops `return_sentinel`, a
    /// handler says `Done`, a named refusal, or a fault.
    ///
    /// Signal envelope (explicit, P1a): asynchronous signals are
    /// blocked while translated code runs and are never
    /// guest-delivered mid-cache. A per-block poll (every
    /// `POLL_BUDGET` block entries) bounds deferral: a pending
    /// async signal stops the run as `FaultKind::AsyncSignal`
    /// with recovered state. Installed async handlers are refused
    /// at admission. No signal transparency is claimed; accepting
    /// this reduction vs transparent delivery remains an explicit
    /// owner scope decision (see status note).
    ///
    /// Return-transition custody: after `run_masked` returns, this
    /// wrapper never restores the caller's mask until every
    /// pending async signal is dequeued and reported (success and
    /// fault returns, in `also_pending`) or explicitly retained
    /// blocked (refusal returns). On a refusal, the exact refusal
    /// is returned and the handed-back mask is the caller's old
    /// mask plus only the bits for signals that were pending at
    /// the transition; those signals are not dequeued and remain
    /// both pending and blocked under the caller's custody. The
    /// caller is expected to `sigwait`/dequeue them or explicitly
    /// unblock them after observing the refusal. They cannot be
    /// delivered merely by starting a later run: that run
    /// snapshots this handed-back mask as its own `old` mask and
    /// restores it, subject to the same custody rules (a later
    /// run may report still-pending signals under its own custody
    /// transition, but it never unblocks them silently). If the
    /// pending set cannot even be observed or dequeued, the whole
    /// async range stays blocked in the handed-back mask and the
    /// named custody error is returned instead.
    pub fn run(
        &mut self,
        state: GuestState,
        handler: &mut dyn Handler,
        mem: &dyn GuestMemory,
        return_sentinel: u64,
    ) -> Result<Outcome, RunError> {
        if !self.valid {
            return Err(Refuse::StaleGeneration {
                expected: self.index.generation().0,
                found: self.index.generation().0,
            }
            .into());
        }
        install_fault_handlers()?;
        check_cet_inactive()?;
        check_async_handlers()?;
        // SAFETY: sigset locals live for both mask calls.
        let (mut set, mut old): (libc::sigset_t, libc::sigset_t) =
            unsafe { (core::mem::zeroed(), core::mem::zeroed()) };
        unsafe {
            libc::sigfillset(&mut set);
            for sig in FAULT_SIGNALS
                .into_iter()
                .chain([libc::SIGKILL, libc::SIGSTOP])
            {
                libc::sigdelset(&mut set, sig);
            }
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        }
        let MaskedOutcome {
            result: mut r,
            poll_custody_error,
        } = self.run_masked(state, handler, mem, return_sentinel);
        // Custody transition for *every* return after this run
        // installed the blocked mask. Until pending async signals
        // are proven absent, dequeued/reported, or explicitly
        // retained blocked, restoring `old` could let a
        // default-terminate signal kill the caller before it can
        // observe this return.
        let mut restore = old;
        let mut custody_error: Option<Refuse> = None;
        if poll_custody_error {
            // Provenance is retained across run_masked: a
            // poll-origin custody failure uses the same full-mask
            // fallback as a wrapper-origin failure below, instead
            // of being flattened into the ordinary Refuse arm
            // (which would retain only the pending bits). The
            // error itself already carries signals consumed
            // before the failure.
            for sig in async_signal_range() {
                // SAFETY: adding one signal to a local set.
                unsafe {
                    libc::sigaddset(&mut restore, sig);
                }
            }
            // SAFETY: install old mask plus the custody bits.
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &restore, core::ptr::null_mut());
            }
            return r;
        }
        match pending_async_signals() {
            Err(e) => {
                // Without a reliable pending set, the only safe
                // mask to hand back blocks the whole async range.
                for sig in async_signal_range() {
                    // SAFETY: adding one signal to a local set.
                    unsafe {
                        libc::sigaddset(&mut restore, sig);
                    }
                }
                custody_error = Some(e);
            }
            Ok(pending) if !pending.is_empty() => match &mut r {
                Ok(outcome) => match take_all_pending_async() {
                    Ok(taken) => outcome.also_pending = taken,
                    Err(e) => {
                        for sig in async_signal_range() {
                            // SAFETY: adding one signal to a local set.
                            unsafe {
                                libc::sigaddset(&mut restore, sig);
                            }
                        }
                        custody_error = Some(e);
                    }
                },
                Err(RunError::Fault(f)) => match take_all_pending_async() {
                    Ok(extra) => {
                        for sig in extra {
                            if sig != f.signum && !f.also_pending.contains(&sig) {
                                f.also_pending.push(sig);
                            }
                        }
                    }
                    Err(e) => {
                        for sig in async_signal_range() {
                            // SAFETY: adding one signal to a local set.
                            unsafe {
                                libc::sigaddset(&mut restore, sig);
                            }
                        }
                        custody_error = Some(e);
                    }
                },
                Err(RunError::Refuse(_)) => {
                    // Preserve the exact refusal and the caller's
                    // pending signals: keep only the actually
                    // pending numbers blocked in the handed-back
                    // mask instead of silently dequeuing them.
                    for sig in pending {
                        // SAFETY: adding one signal to a local set.
                        unsafe {
                            libc::sigaddset(&mut restore, sig);
                        }
                    }
                }
            },
            Ok(_) => {}
        }
        // SAFETY: install the exact caller mask plus any custody
        // bits retained above and documented on this method.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &restore, core::ptr::null_mut());
        }
        if let Some(mut e) = custody_error {
            // Superseding an earlier stop must not erase custody
            // it already recorded (e.g. a Poll AsyncSignal fault).
            if let Err(RunError::Fault(f)) = &r
                && let Refuse::SignalOwnership { taken, .. } = &mut e
            {
                let prior = taken.clone();
                taken.clear();
                if f.kind == FaultKind::AsyncSignal {
                    taken.push(f.signum);
                }
                for sig in f.also_pending.iter().chain(prior.iter()) {
                    if !taken.contains(sig) {
                        taken.push(*sig);
                    }
                }
                taken.sort_unstable();
            }
            return Err(e.into());
        }
        r
    }

    fn run_masked(
        &mut self,
        state: GuestState,
        handler: &mut dyn Handler,
        mem: &dyn GuestMemory,
        return_sentinel: u64,
    ) -> MaskedOutcome {
        let mut poll_custody_error = false;
        let result = self.run_masked_inner(
            state,
            handler,
            mem,
            return_sentinel,
            &mut poll_custody_error,
        );
        MaskedOutcome {
            result,
            poll_custody_error,
        }
    }

    fn run_masked_inner(
        &mut self,
        mut state: GuestState,
        handler: &mut dyn Handler,
        mem: &dyn GuestMemory,
        return_sentinel: u64,
        poll_custody_error: &mut bool,
    ) -> Result<Outcome, RunError> {
        let mut exits: u64 = 0;
        // Counters accumulate across dispatcher re-entries: each
        // entry seeds JitData with the running totals.
        let (mut tot_branches, mut tot_instructions) = (0u64, 0u64);
        let mut poll_remaining = POLL_BUDGET;
        loop {
            let Some(&gen_entry) = self.translation.block_gen.get(&state.rip) else {
                return Err(Refuse::IndirectUnresolved { src_pc: state.rip }.into());
            };
            // SAFETY: `data` is the RW data page of the live arena.
            unsafe {
                let mut fresh = JitData::new(state);
                fresh.branch_count = tot_branches;
                fresh.instruction_count = tot_instructions;
                fresh.poll_remaining = poll_remaining;
                core::ptr::write(self.data, fresh);
            }
            let (bridge_lo, bridge_hi) = bridge_range();
            let mut active = ActiveRun {
                bridge_lo,
                bridge_hi,
                gen_lo: self.translation.gen_base,
                gen_hi: self
                    .translation
                    .gen_base
                    .wrapping_add(self.translation.code.len() as u64),
                data: self.data,
                fault_gen_pc: 0,
                fault_addr: 0,
                fault_sig: 0,
                fault_si_code: 0,
                fault_err: 0,
            };
            ACTIVE.store(&mut active, Ordering::SeqCst);
            // SAFETY: sigsetjmp arms the fault return; liteinst_jit_enter
            // transfers full state to generated code which returns only
            // through the common exit or the fault handler.
            let jumped = unsafe { sigsetjmp_raw(core::ptr::addr_of_mut!(JMP_BUF).cast(), 1) };
            if jumped == 0 {
                unsafe {
                    liteinst_jit_enter(self.data, gen_entry as *const u8);
                }
            }
            ACTIVE.store(core::ptr::null_mut(), Ordering::SeqCst);
            // SAFETY: reading the data page after exit/fault.
            let data = unsafe { core::ptr::read(self.data) };
            state = data.state;
            if jumped != 0 {
                clear_df();
                if active.fault_gen_pc >= active.bridge_lo && active.fault_gen_pc < active.bridge_hi
                {
                    // Entry bridge: no guest instruction has run in
                    // this entry, so the seeded entry state in
                    // data.state is the exact guest state.
                    return Err(RunError::Fault(Box::new(Fault {
                        also_pending: Vec::new(),
                        kind: if active.fault_si_code <= 0 {
                            FaultKind::AsyncSignal
                        } else {
                            FaultKind::ExecutorError
                        },
                        src_pc: data.state.rip,
                        addr: active.fault_addr,
                        signum: active.fault_sig,
                        state: data.state,
                        branches: data.branch_count,
                        instructions: data.instruction_count,
                    })));
                }
                return Err(RunError::Fault(Box::new(recover_fault(
                    &self.translation,
                    self.profile,
                    &data,
                    FaultInput {
                        gen_pc: active.fault_gen_pc,
                        addr: active.fault_addr,
                        signum: active.fault_sig,
                        si_code: active.fault_si_code,
                        err: active.fault_err,
                    },
                ))));
            }
            exits += 1;
            poll_remaining = data.poll_remaining;
            tot_branches = data.branch_count;
            tot_instructions = data.instruction_count;
            let done = Outcome {
                state,
                branches: tot_branches,
                instructions: tot_instructions,
                exits,
                also_pending: Vec::new(),
            };
            match data.exit_kind {
                exit_kind::RETURN => {
                    let Some(target) = mem.read_u64(state.rsp) else {
                        // The return did not retire: exclude its
                        // block-head pre-credit (F3).
                        state.rip = data.exit_src;
                        return Err(RunError::Fault(Box::new(Fault {
                            also_pending: Vec::new(),
                            kind: FaultKind::GuestFault,
                            src_pc: data.exit_src,
                            addr: state.rsp,
                            signum: libc::SIGSEGV,
                            state,
                            branches: data.branch_count,
                            instructions: self
                                .retired_instructions_at(data.instruction_count, data.exit_src),
                        })));
                    };
                    state.rsp = state.rsp.wrapping_add(8).wrapping_add(data.exit_next);
                    state.rip = target;
                    if target == return_sentinel {
                        let mut out = done;
                        out.state = state;
                        return Ok(out);
                    }
                    // Loop: the block_gen lookup above resolves the
                    // return target or refuses it by name.
                }
                exit_kind::POLL => {
                    state.rip = data.exit_src;
                    let taken = match take_all_pending_async() {
                        Ok(taken) => taken,
                        Err(e) => {
                            *poll_custody_error = true;
                            return Err(e.into());
                        }
                    };
                    if let Some((&sig, rest)) = taken.split_first() {
                        return Err(RunError::Fault(Box::new(Fault {
                            also_pending: rest.to_vec(),
                            kind: FaultKind::AsyncSignal,
                            src_pc: data.exit_src,
                            addr: 0,
                            signum: sig,
                            state,
                            branches: done.branches,
                            instructions: done.instructions,
                        })));
                    }
                    // No signal pending: re-enter with a fresh budget.
                    poll_remaining = POLL_BUDGET;
                }
                exit_kind::INDIRECT => {
                    return Err(Refuse::IndirectUnresolved {
                        src_pc: data.exit_src,
                    }
                    .into());
                }
                exit_kind::SYSCALL => {
                    state.rip = data.exit_src;
                    syscall_guard(&self.translation, data.exit_src, state.rax)?;
                    let resume = handler.syscall(&mut state, data.exit_src, data.exit_next)?;
                    tot_instructions += 1;
                    match resume {
                        Resume::Done => {
                            let mut out = done;
                            out.state = state;
                            out.instructions = tot_instructions;
                            return Ok(out);
                        }
                        Resume::At(pc) => {
                            state.rip = pc;
                        }
                    }
                }
                exit_kind::NONDET => {
                    state.rip = data.exit_src;
                    let kind = self
                        .translation
                        .blocks
                        .values()
                        .find_map(|b| match &b.term {
                            Some(t) if t.pc == data.exit_src => match t.class {
                                crate::decode::InsnClass::Nondet(k) => Some(k),
                                _ => None,
                            },
                            _ => None,
                        })
                        .ok_or(Refuse::NoHandler {
                            src_pc: data.exit_src,
                        })?;
                    let resume = handler.nondet(&mut state, kind, data.exit_src, data.exit_next)?;
                    tot_instructions += 1;
                    match resume {
                        Resume::Done => {
                            let mut out = done;
                            out.state = state;
                            out.instructions = tot_instructions;
                            return Ok(out);
                        }
                        Resume::At(pc) => {
                            state.rip = pc;
                        }
                    }
                }
                other => {
                    return Err(Refuse::Unrelocatable {
                        src_pc: data.exit_src,
                        reason: if other == 0 {
                            "cache returned without exit kind"
                        } else {
                            "unknown exit kind"
                        },
                    }
                    .into());
                }
            }
        }
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use crate::types::{Generation, RegionFacts};

    fn setup(fix_bytes: &[u8], profile: CountProfile) -> Translation {
        let region = RegionFacts {
            base: 0x10_0000,
            bytes: fix_bytes.to_vec(),
            generation: Generation(1),
            immutable_private: true,
        };
        translate(&region, 0x10_0000, profile, 0x80_0000, 0x81_0000).unwrap()
    }

    fn fake_data() -> JitData {
        let mut d = JitData::new(GuestState::default());
        d.branch_count = 10;
        d.instruction_count = 1000;
        d.spill_rax = 0x1111;
        d.spill_flags = (0x80 << 8) | 1; // AH: SF, AL: OF=1
        d.interrupted.rax = 0xdead;
        d.interrupted.rflags = 0x202;
        d.interrupted.rsp = 0x7000;
        d
    }

    fn find(t: &Translation, pred: impl Fn(&Recovery) -> bool) -> &crate::pcmap::PcMapEntry {
        t.pcmap
            .entries()
            .iter()
            .find(|e| pred(&e.recovery))
            .expect("entry exists")
    }

    #[test]
    fn branch_stub_credit_timing_and_spill_recovery() {
        let fix = crate::fixtures::by_name("call_helper");
        let t = setup(&fix.bytes, CountProfile::BranchesAndInstructions);
        // Before the credit store: pending branch counts, RAX from spill.
        let e = find(&t, |r| {
            matches!(
                r,
                Recovery::BranchStub {
                    stage: StubStage::BeforeCreditSpilled,
                    ..
                }
            )
        });
        let Recovery::BranchStub { successor, .. } = e.recovery else {
            unreachable!()
        };
        let f = recover_fault(
            &t,
            CountProfile::BranchesAndInstructions,
            &fake_data(),
            FaultInput {
                gen_pc: e.gen_start,
                addr: 0,
                signum: libc::SIGSEGV,
                si_code: 1,
                err: 0,
            },
        );
        assert_eq!(f.branches, 11, "retired branch credited exactly once");
        assert_eq!(f.state.rax, 0x1111);
        assert_eq!(f.state.rip, successor);
        assert_eq!(f.state.rflags, 0x202, "flags pristine before INC");
        assert_eq!(f.kind, FaultKind::ExecutorError, "private stub access");
        // After the credit store: no second credit, flags rebuilt.
        let e = find(&t, |r| {
            matches!(
                r,
                Recovery::BranchStub {
                    stage: StubStage::AfterCreditSpilled,
                    ..
                }
            )
        });
        let f = recover_fault(
            &t,
            CountProfile::BranchesAndInstructions,
            &fake_data(),
            FaultInput {
                gen_pc: e.gen_start,
                addr: 0,
                signum: libc::SIGSEGV,
                si_code: 1,
                err: 0,
            },
        );
        assert_eq!(f.branches, 10, "no double credit after INC");
        assert_eq!(f.state.rax, 0x1111);
        assert_eq!(
            f.state.rflags,
            0x202 | 0x80 | 0x800,
            "SF+OF from spill image"
        );
        // Asynchronous provenance is classified, not called a fault.
        let f = recover_fault(
            &t,
            CountProfile::BranchesAndInstructions,
            &fake_data(),
            FaultInput {
                gen_pc: e.gen_start,
                addr: 0,
                signum: libc::SIGSEGV,
                si_code: 0,
                err: 0,
            },
        );
        assert_eq!(f.kind, FaultKind::AsyncSignal);
    }

    #[test]
    fn call_store_boundary_restores_pre_call_state() {
        let fix = crate::fixtures::by_name("call_helper");
        let t = setup(&fix.bytes, CountProfile::BranchesAndInstructions);
        let e = find(&t, |r| {
            matches!(
                r,
                Recovery::Call {
                    stage: CallStage::RspDecremented,
                    ..
                }
            )
        });
        let Recovery::Call { call_pc, .. } = e.recovery else {
            unreachable!()
        };
        let f = recover_fault(
            &t,
            CountProfile::BranchesAndInstructions,
            &fake_data(),
            FaultInput {
                gen_pc: e.gen_start,
                addr: 0x7000,
                signum: libc::SIGSEGV,
                si_code: 1,
                err: 0,
            },
        );
        assert_eq!(f.state.rax, 0x1111, "guest rax from spill, not return pc");
        assert_eq!(f.state.rsp, 0x7008, "decrement undone");
        assert_eq!(f.state.rip, call_pc);
        // Entry block is exactly the call: pre-credit removed.
        assert_eq!(f.instructions, 999);
    }

    #[test]
    fn data_address_equal_to_gen_pc_is_preserved() {
        // T7: numerical equality with a generated PC does not make
        // a data address an instruction address; only the
        // page-fault fetch bit (or FPE/ILL class) translates it.
        let fix = crate::fixtures::by_name("sum_loop");
        let t = setup(&fix.bytes, CountProfile::Branches);
        let e = t
            .pcmap
            .entries()
            .iter()
            .find(|e| matches!(e.recovery, Recovery::Copied))
            .expect("copied entry");
        let data = fake_data();
        let f = recover_fault(
            &t,
            CountProfile::Branches,
            &data,
            FaultInput {
                gen_pc: e.gen_start,
                addr: e.gen_start,
                signum: libc::SIGSEGV,
                si_code: 1,
                err: 0x7, // present | write | user: a data store, no fetch bit
            },
        );
        assert_eq!(f.addr, e.gen_start, "raw data address preserved");
        let f = recover_fault(
            &t,
            CountProfile::Branches,
            &data,
            FaultInput {
                gen_pc: e.gen_start,
                addr: e.gen_start,
                signum: libc::SIGSEGV,
                si_code: 1,
                err: 0x14, // user | instruction-fetch
            },
        );
        assert_eq!(f.addr, e.src_pc, "fetch address translated");
    }

    #[test]
    fn poll_budget_fires_without_signal() {
        use crate::handler::CaptureHandler;
        use crate::harness::{MappedGuest, RETURN_SENTINEL};
        let fix = crate::fixtures::by_name("loop_insn");
        let guest = MappedGuest::map(&fix.bytes).expect("map");
        let region = RegionFacts {
            base: guest.base,
            bytes: fix.bytes.clone(),
            generation: Generation(1),
            immutable_private: true,
        };
        let mut exec =
            Executable::prepare(&region, guest.base, CountProfile::Branches).expect("prepare");
        let mut state = guest.initial_state();
        state.rsi = 40_000;
        let mut handler = CaptureHandler::default();
        let out = exec
            .run(state, &mut handler, &ProcessMemory, RETURN_SENTINEL)
            .expect("run");
        assert_eq!(out.branches, 40_000);
        assert!(out.exits >= 3, "poll exits fired, got {} exits", out.exits);
    }

    #[test]
    fn every_entry_boundary_recovers_and_common_is_executor_error() {
        let fix = crate::fixtures::by_name("call_helper");
        let t = setup(&fix.bytes, CountProfile::BranchesAndInstructions);
        let mut data = fake_data();
        data.exit_src = 0x10_0000;
        data.state.rax = 0x7777;
        for e in t.pcmap.entries() {
            let f = recover_fault(
                &t,
                CountProfile::BranchesAndInstructions,
                &data,
                FaultInput {
                    gen_pc: e.gen_start,
                    addr: 0,
                    signum: libc::SIGSEGV,
                    si_code: 1,
                    err: 0,
                },
            );
            let is_machinery = matches!(
                e.recovery,
                Recovery::BranchStub { .. }
                    | Recovery::InsnCountStub { .. }
                    | Recovery::PollStub { .. }
                    | Recovery::ExitStub { .. }
                    | Recovery::PollExitStub { .. }
                    | Recovery::CommonExit { .. }
                    | Recovery::Call {
                        stage: CallStage::Pristine | CallStage::CommittedSpilled,
                        ..
                    }
            );
            assert_eq!(
                f.kind == FaultKind::ExecutorError,
                is_machinery,
                "entry {e:?}"
            );
            assert_ne!(f.state.rip, 0, "entry {e:?} recovers a source pc");
            if matches!(
                e.recovery,
                Recovery::CommonExit {
                    stage: CommonStage::AllSaved
                }
            ) {
                assert_eq!(f.state.rax, 0x7777, "saved state wins over host regs");
            }
        }
        // R4: an asynchronous signal at a common-exit byte stays
        // AsyncSignal; location does not relabel provenance.
        let e = find(&t, |r| {
            matches!(
                r,
                Recovery::CommonExit {
                    stage: CommonStage::BeforeRspSave
                }
            )
        });
        let f = recover_fault(
            &t,
            CountProfile::BranchesAndInstructions,
            &data,
            FaultInput {
                gen_pc: e.gen_start,
                addr: 0,
                signum: libc::SIGSEGV,
                si_code: 0,
                err: 0,
            },
        );
        assert_eq!(f.kind, FaultKind::AsyncSignal);
    }

    #[test]
    fn recovery_core_matches_adapter_at_every_boundary() {
        // I1-A boundary pin: the backend-neutral core and the
        // in-process JitData adapter must produce identical
        // recovered stops at every PC-map entry (plus an
        // unmapped PC), across sync/async/fetch provenances and
        // both common-exit exit kinds. Any future backend that
        // fills RecoveryInput from another snapshot source gets
        // exactly these recovery rules.
        for fixture in ["call_helper", "sum_loop"] {
            let fix = crate::fixtures::by_name(fixture);
            for profile in [
                CountProfile::Branches,
                CountProfile::BranchesAndInstructions,
            ] {
                let t = setup(&fix.bytes, profile);
                for exit_kind_word in [0, crate::state::exit_kind::POLL] {
                    let mut data = fake_data();
                    data.exit_src = 0x10_0000;
                    data.exit_kind = exit_kind_word;
                    data.state.rax = 0x7777;
                    data.state.rsp = 0x6000;
                    data.state.rflags = 0x246;
                    let mut gen_pcs: Vec<u64> =
                        t.pcmap.entries().iter().map(|e| e.gen_start).collect();
                    gen_pcs.push(0xdead_0000);
                    for gen_pc in gen_pcs {
                        for (signum, si_code, err) in [
                            (libc::SIGSEGV, 1, 0u64),
                            (libc::SIGUSR1, 0, 0),
                            (libc::SIGSEGV, 1, 0x10),
                            (libc::SIGFPE, 1, 0),
                        ] {
                            let input = FaultInput {
                                gen_pc,
                                addr: gen_pc,
                                signum,
                                si_code,
                                err,
                            };
                            let via_adapter = recover_fault(&t, profile, &data, input);
                            let via_core = crate::recovery::recover(
                                &t,
                                profile,
                                RecoveryInput {
                                    provenance: input,
                                    interrupted: data.interrupted,
                                    saved: data.state,
                                    spill_rax: data.spill_rax,
                                    spill_flags: data.spill_flags,
                                    branches: data.branch_count,
                                    instructions: data.instruction_count,
                                    exit_kind: data.exit_kind,
                                    exit_src: data.exit_src,
                                },
                            );
                            assert_eq!(via_adapter.kind, via_core.kind, "{fixture} {gen_pc:#x}");
                            assert_eq!(
                                via_adapter.src_pc, via_core.src_pc,
                                "{fixture} {gen_pc:#x}"
                            );
                            assert_eq!(via_adapter.addr, via_core.addr, "{fixture} {gen_pc:#x}");
                            assert_eq!(via_adapter.signum, via_core.signum);
                            assert_eq!(via_adapter.state, via_core.state, "{fixture} {gen_pc:#x}");
                            assert_eq!(via_adapter.branches, via_core.branches);
                            assert_eq!(via_adapter.instructions, via_core.instructions);
                            assert!(via_adapter.also_pending.is_empty());
                        }
                    }
                }
            }
        }
    }
}
