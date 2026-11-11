//! Remote ptrace direct-block substrate (P1b I1-B through
//! I1-G2, internal and unstable).
//!
//! A traced fixture child executes the same translations as
//! the in-process executor, with this tracer as dispatcher:
//! common exits trap (`ExitStyle::TrapToDispatcher`), faults
//! and signal stops are turned into exact source state by the
//! shared recovery core (`crate::recovery`), and the corpus
//! syscalls/nondeterministic instructions the stage admits are
//! serviced by stepping the original instruction in the child.
//! I1-C mirrors the guest signal registry from kernel
//! readback. I1-D through I1-G1 add genuine delivery on top
//! of that mirror (async SIGUSR1/SIGUSR2 and the real-time
//! range 34..=64 with masks, altstack, nesting to an 8-frame
//! cap, and kernel back-to-back frame setup; guest
//! self-queueing through `rt_sigqueueinfo` /
//! `rt_tgsigqueueinfo` with `SI_QUEUE` payloads; synchronous
//! SIGSEGV/SIGFPE at copied insns on an empty frame stack; an
//! `SA_SIGINFO` handler at a translated block start; recovery
//! to a block start or an exact mid-block generated re-entry;
//! and, I1-G2, delivery at a stepped syscall's exit when a
//! signal interrupted it, with the kernel applying the
//! `SA_RESTART`/`-EINTR` rule — see `P1B-DESIGN.md` §8): custom
//! handlers are stubbed in the kernel disposition, the kernel
//! queues, orders, and builds the frame at the recovered
//! source PC, the handler runs translated, and the guest
//! restorer's `rt_sigreturn` resumes in cache.
//! Every other delivery shape still stops as a recovered
//! outcome by name — including async stops in common-exit
//! spilled stages and at generated PCs with no pcmap entry
//! (entry-loader bridge class), which arbitrary-phase
//! delivery here explicitly does not cover; no transparency
//! claim is made beyond the tested shapes. Indirect resolution, threads, and exec
//! successors stay refused exactly as in-process. This module
//! is a substrate for later P1b stages, not a public API
//! contract, and makes no whole-program claim.

use std::io::Read;
use std::process::{Child, Command, Stdio};

use crate::decode::{InsnClass, NondetKind};
use crate::exec::{CODE_CAP, Fault, Outcome, POLL_BUDGET, RunError, syscall_guard};
use crate::pcmap::{CallStage, CommonStage, ExitStage, Phase as MapPhase, Recovery as MapRecovery};
use crate::recovery::{FaultInput, RecoveryInput};
use crate::refuse::Refuse;
use crate::state::{GuestState, JitData, exit_kind};
use crate::translate::{ExitStyle, Translation, translate_with_exit_style};
use crate::types::{CountProfile, RegionFacts};

const PAGE: usize = 4096;
/// Child arena layout mirrors the in-process arena: code in the
/// first `CODE_CAP` bytes, `JitData` immediately after.
pub const ARENA_LEN: usize = CODE_CAP + 64 * PAGE;
/// Mailbox command: publish the code region RX, then park again.
pub const MAILBOX_PUBLISH: u64 = 1;
/// Mailbox acknowledgement written by the child after publish.
pub const MAILBOX_PUBLISHED: u64 = 2;
/// The exact syscall numbers pass-through stepping may execute
/// in this stage: `SYS_write` (the sole corpus syscall from
/// I1-B), the I1-C registry set (`rt_sigaction`,
/// `rt_sigprocmask`, `rt_sigpending`, `sigaltstack`, each
/// observed for the tracer mirror), the I1-F self-send
/// pair (`getpid`, `kill` — kill is additionally gated at the
/// dispatch site to the traced child's own pid, so a guest
/// can only signal itself), and the I1-G1 queueing pair
/// (`rt_sigqueueinfo`, `rt_tgsigqueueinfo` — gated by
/// `prepare_sigqueue_step` to `SI_QUEUE` self-sends of an
/// admitted signal, or to forged-code calls the kernel itself
/// refuses), and the I1-G2 blocking set that a signal can
/// interrupt (`rt_sigsuspend`; `futex` gated at the dispatch
/// site to `FUTEX_WAIT_PRIVATE` with a NULL timeout; plain
/// relative `nanosleep` — `clock_nanosleep` is not listed).
/// The lifecycle guard always runs first; any other number
/// stops by name (`NoHandler`) rather than executing. This is
/// a stage bound, not a generic guest-syscall claim.
const PASS_THROUGH_SYSCALLS: &[u32] = &[
    libc::SYS_write as u32,
    libc::SYS_rt_sigaction as u32,
    libc::SYS_rt_sigprocmask as u32,
    libc::SYS_rt_sigpending as u32,
    libc::SYS_sigaltstack as u32,
    libc::SYS_getpid as u32,
    libc::SYS_kill as u32,
    libc::SYS_rt_sigqueueinfo as u32,
    libc::SYS_rt_tgsigqueueinfo as u32,
    libc::SYS_rt_sigsuspend as u32,
    libc::SYS_futex as u32,
    libc::SYS_nanosleep as u32,
];

/// The only `futex` operation passed through (I1-G2):
/// `FUTEX_WAIT | FUTEX_PRIVATE_FLAG`, and only with a NULL
/// timeout (a timed wait would restart through
/// `restart_syscall`, which stays refused).
const FUTEX_WAIT_PRIVATE: u64 = 128;

/// The syscalls whose interruption is delivered (I1-G2): the
/// tested blocking set. Any other pass-through call that
/// returns a restart code (a blocking `write`, say) keeps the
/// named stop at its exit. Classified by the low 32 bits of
/// `orig_rax`, as the kernel dispatches and as pass-through
/// admission classifies (`0x1_000000ca` runs futex); the full
/// `orig_rax` stays the provenance check and the predicted
/// frame RAX of a restart.
const RESTART_DELIVERY_SYSCALLS: &[u32] = &[
    libc::SYS_rt_sigsuspend as u32,
    libc::SYS_futex as u32,
    libc::SYS_nanosleep as u32,
];

/// Kernel syscall-restart codes (`include/linux/errno.h`).
const ERESTARTSYS: i64 = -512;
const ERESTARTNOINTR: i64 = -513;
const ERESTARTNOHAND: i64 = -514;
const ERESTART_RESTARTBLOCK: i64 = -516;

/// Real-time signals admitted for delivery and self-queueing
/// (I1-G1): glibc's SIGRTMIN (34) through SIGRTMAX (64). The
/// kernel's 32 and 33 are reserved by glibc/NPTL and stay
/// outside, for delivery and for queueing alike.
const RT_ADMITTED: core::ops::RangeInclusive<i32> = 34..=64;

/// The asynchronous signals this stage delivers, and the only
/// signals a guest may queue with `rt_(tg)sigqueueinfo`:
/// SIGUSR1/SIGUSR2 (I1-D/I1-F) and `RT_ADMITTED` (I1-G1). One
/// predicate for both, so delivery and queueing cannot drift.
fn async_delivery_admitted(sig: i32) -> bool {
    sig == libc::SIGUSR1 || sig == libc::SIGUSR2 || RT_ADMITTED.contains(&sig)
}

/// Kernel `si_code` values (`asm-generic/siginfo.h`) the
/// sigqueue gate distinguishes: `SI_QUEUE` is what `sigqueue(3)`
/// sends; `SI_TKILL` is the code the kernel reserves for
/// `tkill`/`tgkill`, which `rt_(tg)sigqueueinfo` treats as forged
/// like any `si_code >= 0`.
const SI_QUEUE: i32 = -1;
const SI_TKILL: i32 = -6;
/// Bytes of a user `siginfo_t` the sigqueue gate reads and
/// stages: the whole 128-byte user record. This is a
/// conservative admission policy, not the kernel's copy size:
/// `__copy_siginfo_from_user` copies the 48-byte
/// `kernel_siginfo` prefix and checks the remaining expansion
/// bytes only for an unknown layout, so a failed 128-byte read
/// here does not establish that the kernel would fail with
/// `EFAULT` (hence `NoHandler`, not a stepped call).
const SIGINFO_LEN: usize = 128;

/// Bytes reserved at the tail of the child code arena for the
/// I1-D common signal-entry stub (a single `int3` at the tail
/// start; the rest is padding). Translations must fit in
/// `CODE_CAP - STUB_TAIL`.
const STUB_TAIL: usize = 16;

/// Byte offsets of `uc_mcontext` gregs inside a kernel
/// `rt_sigframe` ucontext (`uc_flags`/`uc_link`/`uc_stack`
/// precede `uc_mcontext` at 40; gregs order is the kernel
/// `sigcontext` order r8..r15, rdi, rsi, rbp, rbx, rdx, rax,
/// rcx, rsp, rip, eflags). These are never trusted blindly:
/// delivery validates the frame RIP/RSP read through them
/// against the independently recovered source state before
/// the handler is entered, and sigreturn validates the
/// restored registers, so a wrong offset fails closed by name.
const UC_GREG: u64 = 40;
const GREG_R8: u64 = 0;
const GREG_R9: u64 = 1;
const GREG_R10: u64 = 2;
const GREG_R11: u64 = 3;
const GREG_R12: u64 = 4;
const GREG_R13: u64 = 5;
const GREG_R14: u64 = 6;
const GREG_R15: u64 = 7;
const GREG_RDI: u64 = 8;
const GREG_RSI: u64 = 9;
const GREG_RBP: u64 = 10;
const GREG_RBX: u64 = 11;
const GREG_RDX: u64 = 12;
const GREG_RAX: u64 = 13;
const GREG_RCX: u64 = 14;
const GREG_RSP: u64 = 15;
const GREG_RIP: u64 = 16;
const GREG_EFLAGS: u64 = 17;

const fn uc_greg_addr(uc: u64, greg: u64) -> u64 {
    uc + UC_GREG + greg * 8
}

/// `SA_RESTORER` flag word (not exported by libc on this
/// target; value from the kernel `signal.h` ABI).
const SA_RESTORER_FLAG: u64 = 0x0400_0000;

/// The only restorer shape I1-D ever executes: exactly
/// `mov eax, __NR_rt_sigreturn (15); syscall` (7 bytes). Its
/// two retired instructions are the sigreturn credit; any
/// other restorer bytes make the action ineligible before
/// anything is injected (translating arbitrary restorers is
/// later-stage work).
const SIGRETURN_RESTORER: [u8; 7] = [0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05];

/// One guest signal action exactly as the kernel reports it:
/// all four `rt_sigaction` words are retained for every
/// disposition, including `SIG_DFL`/`SIG_IGN`, whose
/// flags/restorer/mask words are part of the queried state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub sa_mask: u64,
}

impl GuestAction {
    pub fn is_default(&self) -> bool {
        self.handler == 0
    }
    pub fn is_ignore(&self) -> bool {
        self.handler == 1
    }
    /// A guest-installed handler address (neither `SIG_DFL`
    /// nor `SIG_IGN`). Only custom actions are stubbed in the
    /// kernel disposition by I1-D.
    pub fn is_custom(&self) -> bool {
        self.handler > 1
    }
}

/// Guest alternate signal stack triple (`SS_DISABLE` in flags
/// means disabled, with zeroed sp/size as the kernel reports).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestAltstack {
    pub sp: u64,
    pub flags: i32,
    pub size: u64,
}

/// Tracer mirror of the guest's kernel-owned signal registry.
/// The child kernel is authoritative; this mirror is populated
/// only from verified kernel readback (initial child state at
/// spawn and post-call reconciliation after stepped registry
/// syscalls), never from raw guest input, so dispatcher queries
/// answer with the same values the guest kernel holds. Index
/// 0 is unused; signals are 1..=64.
#[derive(Clone, Debug)]
pub struct SignalRegistry {
    actions: [GuestAction; 65],
    mask: u64,
    altstack: GuestAltstack,
}

impl Default for SignalRegistry {
    fn default() -> Self {
        Self {
            actions: [GuestAction::default(); 65],
            mask: 0,
            altstack: GuestAltstack {
                sp: 0,
                flags: libc::SS_DISABLE,
                size: 0,
            },
        }
    }
}

impl SignalRegistry {
    pub fn action(&self, sig: i32) -> GuestAction {
        self.actions.get(sig as usize).copied().unwrap_or_default()
    }
    pub fn is_blocked(&self, sig: i32) -> bool {
        (1..=64).contains(&sig) && self.mask & (1u64 << (sig - 1)) != 0
    }
    pub fn mask(&self) -> u64 {
        self.mask
    }
    pub fn altstack(&self) -> GuestAltstack {
        self.altstack
    }

    /// Record an action read back from the child kernel.
    /// Changing SIGKILL/SIGSTOP dispositions is rejected by
    /// the kernel with EINVAL, so a readback for them always
    /// yields the prior (default) words.
    fn set_action(&mut self, sig: i32, act: GuestAction) {
        if (1..=64).contains(&sig) {
            self.actions[sig as usize] = act;
        }
    }

    /// Record the blocked mask read back from the child kernel
    /// (`SigBlk`), exactly as reported.
    fn set_mask(&mut self, mask: u64) {
        self.mask = mask;
    }

    /// Record the altstack triple read back from the child
    /// kernel, exactly as queried (including dynamic flags).
    fn set_altstack(&mut self, alt: GuestAltstack) {
        self.altstack = alt;
    }
}

/// Outcome of one stepped guest syscall.
enum Stepped {
    Done(GuestState),
    /// Exit stop with a kernel restart code; the child is still
    /// stopped there (I1-G2).
    Interrupted(libc::user_regs_struct),
}

/// Which registry state (if any) a stepped syscall must have
/// reconciled from post-call kernel readback. Identified at
/// the generated common-exit stop, before stepping, from
/// registers alone — no guest memory is read speculatively, so
/// an unreadable guest argument can never replace the
/// kernel's own result for an admitted call.
#[derive(Clone, Copy, Debug)]
enum SyscallObs {
    None,
    Sigprocmask,
    Sigaltstack,
}

/// Prepared `rt_sigaction` step (I1-D stubbing). `prev_visible`
/// is the guest-visible action before the call (the old-action
/// value the guest must observe); `requested` is the source
/// handler of a custom install whose kernel copy was stubbed
/// through `JitData` scratch (`step_rsi`), with the scratch
/// bytes saved for exact restoration. When the guest act is
/// unreadable no stub copy is made and the call steps
/// genuinely so the kernel produces the guest's own `EFAULT`.
#[derive(Clone, Copy, Debug)]
struct SigactionStep {
    sig: i32,
    oldact_addr: u64,
    prev_visible: GuestAction,
    requested: Option<u64>,
    step_rsi: Option<u64>,
    saved_scratch: Option<[u8; 32]>,
}

/// Prepared `rt_sigqueueinfo` / `rt_tgsigqueueinfo` step
/// (I1-G1). The guest siginfo is copied verbatim into tracer
/// scratch and the call steps with its pointer argument
/// (`rdx`, or `r10` for the tg form) replaced by `staged`, so
/// the kernel copies in exactly the bytes the gate classified
/// — no later write to guest memory can change `si_code`
/// between the check and the copy. `step_redirected_syscall`
/// puts the guest's own pointer back into every returned guest
/// state and `saved` into scratch on every path.
/// `kernel_refuses` marks a call the kernel must answer with
/// an error (forged code to a foreign target, or the tg form
/// with the caller's TID and a foreign TGID).
#[derive(Clone, Copy, Debug)]
struct SigqueueStep {
    tg: bool,
    staged: u64,
    saved: [u8; SIGINFO_LEN],
    kernel_refuses: bool,
}

/// Syscall argument register a redirected step rewrites.
#[derive(Clone, Copy, Debug)]
enum ArgReg {
    Rsi,
    Rdx,
    R10,
}

impl ArgReg {
    fn get(self, s: &GuestState) -> u64 {
        match self {
            ArgReg::Rsi => s.rsi,
            ArgReg::Rdx => s.rdx,
            ArgReg::R10 => s.r10,
        }
    }

    fn set(self, s: &mut GuestState, v: u64) {
        match self {
            ArgReg::Rsi => s.rsi = v,
            ArgReg::Rdx => s.rdx = v,
            ArgReg::R10 => s.r10 = v,
        }
    }
}

/// Kernel handler word -> guest-visible handler word. A
/// readback equal to the stub stands for `requested` only
/// when the install provably landed: result 0, or `-EFAULT`
/// after a stubbed step (copy-in read tracer scratch, which
/// cannot fault, so `EFAULT` there is copy-out after a real
/// install). Any other error (`EINVAL`) installed nothing and
/// the stub still stands for the previous visible handler.
/// `None` means the readback cannot be named guest-visibly
/// and the caller fails closed.
fn visible_handler(
    kernel_handler: u64,
    stub: u64,
    requested: Option<u64>,
    prev_visible: GuestAction,
    step_rax: u64,
) -> Option<u64> {
    if kernel_handler != stub {
        return Some(kernel_handler);
    }
    let landed = step_rax == 0 || step_rax == (-(libc::EFAULT as i64)) as u64;
    match (landed, requested) {
        (true, Some(handler)) => Some(handler),
        _ if prev_visible.is_custom() => Some(prev_visible.handler),
        _ => None,
    }
}

/// One in-flight genuine signal frame (I1-D admits at most
/// one; nesting is I1-F). Populated at the signal-entry stub
/// trap from kernel-supplied registers and validated frame
/// words; popped exactly once by the restorer sigreturn flow.
#[derive(Clone, Copy, Debug)]
struct ActiveFrame {
    restorer: u64,
    frame_rsp: u64,
    uc_addr: u64,
    resume_src_pc: u64,
    /// Counters exactly as credited in `JitData` at the
    /// interruption (block precredit included), for exact
    /// mid-block generated re-entry.
    raw_branches: u64,
    raw_instructions: u64,
    raw_poll: u64,
    /// Recovery-resolved counters the handler run was
    /// seeded from; the handler delta is re-based onto the
    /// raw totals for a mid-block resume.
    resolved_branches: u64,
    resolved_instructions: u64,
    /// Generated entry for `resume_src_pc` when it is not a
    /// block start (exact insn re-entry); `None` for the
    /// normal block-start resume.
    gen_mid: Option<u64>,
}

/// Child-to-tracer setup report (7 little-endian u64s): fixture
/// base, stack top, data buffer, rep destination, rep source,
/// arena base, publish mailbox address.
#[derive(Clone, Copy, Debug, Default)]
pub struct RemoteChildInfo {
    pub base: u64,
    pub stack_top: u64,
    pub data: u64,
    pub dst: u64,
    pub src: u64,
    pub arena_base: u64,
    pub mailbox: u64,
}

impl RemoteChildInfo {
    pub fn to_bytes(&self) -> [u8; 56] {
        let mut b = [0u8; 56];
        for (i, v) in [
            self.base,
            self.stack_top,
            self.data,
            self.dst,
            self.src,
            self.arena_base,
            self.mailbox,
        ]
        .iter()
        .enumerate()
        {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }
    pub fn from_bytes(b: &[u8; 56]) -> RemoteChildInfo {
        let get = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        RemoteChildInfo {
            base: get(0),
            stack_top: get(1),
            data: get(2),
            dst: get(3),
            src: get(4),
            arena_base: get(5),
            mailbox: get(6),
        }
    }
}

fn remote_err(operation: &'static str) -> Refuse {
    Refuse::RemoteSubstrate {
        operation,
        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    }
}

fn ptrace(req: u32, pid: i32, addr: *mut u8, data: *mut u8) -> i64 {
    // SAFETY: raw ptrace passthrough; callers pass valid operands
    // for the specific request.
    unsafe { libc::ptrace(req as libc::c_uint, pid, addr, data) }
}

fn ptrace_ok(
    req: u32,
    pid: i32,
    addr: *mut u8,
    data: *mut u8,
    op: &'static str,
) -> Result<(), Refuse> {
    if ptrace(req, pid, addr, data) == 0 {
        Ok(())
    } else {
        Err(remote_err(op))
    }
}

fn get_regs(pid: i32) -> Result<libc::user_regs_struct, Refuse> {
    let mut regs: libc::user_regs_struct = unsafe { core::mem::zeroed() };
    ptrace_ok(
        libc::PTRACE_GETREGS,
        pid,
        core::ptr::null_mut(),
        core::ptr::addr_of_mut!(regs).cast(),
        "PTRACE_GETREGS",
    )?;
    Ok(regs)
}

fn set_regs(pid: i32, regs: &libc::user_regs_struct) -> Result<(), Refuse> {
    ptrace_ok(
        libc::PTRACE_SETREGS,
        pid,
        core::ptr::null_mut(),
        (regs as *const libc::user_regs_struct).cast_mut().cast(),
        "PTRACE_SETREGS",
    )
}

fn get_siginfo(pid: i32) -> Result<libc::siginfo_t, Refuse> {
    let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
    ptrace_ok(
        libc::PTRACE_GETSIGINFO,
        pid,
        core::ptr::null_mut(),
        core::ptr::addr_of_mut!(info).cast(),
        "PTRACE_GETSIGINFO",
    )?;
    Ok(info)
}

fn read_mem(pid: i32, addr: u64, buf: &mut [u8]) -> Result<(), Refuse> {
    let mut done = 0usize;
    while done < buf.len() {
        let local = libc::iovec {
            iov_base: buf[done..].as_mut_ptr().cast(),
            iov_len: buf.len() - done,
        };
        let remote = libc::iovec {
            iov_base: (addr + done as u64) as usize as *mut libc::c_void,
            iov_len: buf.len() - done,
        };
        // SAFETY: both iovecs describe the live remaining ranges.
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n <= 0 {
            return Err(remote_err("process_vm_readv"));
        }
        done += n as usize;
    }
    Ok(())
}

/// Test seam (record only): every attempted tracer write into
/// a child, as `(pid, addr, len)`. `write_mem` is the tracer's
/// only guest-memory write path, so a test can prove the tracer
/// never wrote a guest range (for example the `nanosleep`
/// remainder, which must be the kernel's own value). Compiled
/// only with the test-only `test-seams` feature.
#[cfg(feature = "test-seams")]
static TRACER_WRITES: std::sync::Mutex<Vec<(i32, u64, usize)>> = std::sync::Mutex::new(Vec::new());

fn write_mem(pid: i32, addr: u64, buf: &[u8]) -> Result<(), Refuse> {
    #[cfg(feature = "test-seams")]
    TRACER_WRITES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((pid, addr, buf.len()));
    let mut done = 0usize;
    while done < buf.len() {
        let local = libc::iovec {
            iov_base: buf[done..].as_ptr().cast_mut().cast(),
            iov_len: buf.len() - done,
        };
        let remote = libc::iovec {
            iov_base: (addr + done as u64) as usize as *mut libc::c_void,
            iov_len: buf.len() - done,
        };
        // SAFETY: both iovecs describe the live remaining ranges;
        // the remote range is a writable child mapping by the
        // substrate setup contract.
        let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
        if n <= 0 {
            return Err(remote_err("process_vm_writev"));
        }
        done += n as usize;
    }
    Ok(())
}

/// The child thread's actual blocked mask from procfs
/// (`SigBlk`), the authoritative kernel answer used both for
/// initial mirror seeding and post-`rt_sigprocmask`
/// reconciliation. Reading it neither dequeues nor delivers
/// anything.
fn read_sigblk(pid: i32) -> Result<u64, Refuse> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| remote_err("read child SigBlk"))?;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("SigBlk:") {
            return u64::from_str_radix(v.trim(), 16).map_err(|_| Refuse::RemoteSubstrate {
                operation: "parse child SigBlk",
                errno: 0,
            });
        }
    }
    Err(Refuse::RemoteSubstrate {
        operation: "child SigBlk absent",
        errno: 0,
    })
}

fn wait_stop(pid: i32) -> Result<i32, Refuse> {
    loop {
        let mut status: i32 = 0;
        // SAFETY: waiting for our own traced child.
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w == pid {
            return Ok(status);
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(Refuse::RemoteSubstrate {
                operation: "waitpid",
                errno: e.raw_os_error().unwrap_or(0),
            });
        }
    }
}

fn regs_to_state(r: &libc::user_regs_struct) -> GuestState {
    GuestState {
        rax: r.rax,
        rbx: r.rbx,
        rcx: r.rcx,
        rdx: r.rdx,
        rsi: r.rsi,
        rdi: r.rdi,
        rbp: r.rbp,
        rsp: r.rsp,
        r8: r.r8,
        r9: r.r9,
        r10: r.r10,
        r11: r.r11,
        r12: r.r12,
        r13: r.r13,
        r14: r.r14,
        r15: r.r15,
        rflags: r.eflags,
        rip: r.rip,
    }
}

fn apply_state(r: &mut libc::user_regs_struct, s: &GuestState) {
    r.rax = s.rax;
    r.rbx = s.rbx;
    r.rcx = s.rcx;
    r.rdx = s.rdx;
    r.rsi = s.rsi;
    r.rdi = s.rdi;
    r.rbp = s.rbp;
    r.rsp = s.rsp;
    r.r8 = s.r8;
    r.r9 = s.r9;
    r.r10 = s.r10;
    r.r11 = s.r11;
    r.r12 = s.r12;
    r.r13 = s.r13;
    r.r14 = s.r14;
    r.r15 = s.r15;
    r.eflags = s.rflags;
    r.rip = s.rip;
}

/// Which address space the child was executing when a stop
/// arrived. Generated stops are recovered through the shared
/// recovery core against the generated PC map; original stops
/// are recovered as exact source state and never touch that
/// map. Mixing the two was the delta-review provenance defect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Generated,
    OriginalStep,
    SyscallEntry,
    SyscallExit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopClass {
    /// Proven common-exit breakpoint trap (Generated only).
    ExitTrap,
    /// Proven single-step completion (OriginalStep only).
    StepComplete,
    /// Proven syscall entry/exit stop (syscall phases only).
    SyscallStop,
    /// User-sent signal (`si_code <= 0`): asynchronous in
    /// every phase that can establish its exact state.
    Async,
    /// Kernel fault/trap while executing generated code.
    GeneratedFault,
    /// Kernel fault/trap while executing an original
    /// instruction or its syscall entry.
    SourceFault,
    /// Provenance cannot be established: fail closed.
    Unexpected,
}

const TRAP_BRKPT: i32 = 1;
const TRAP_TRACE: i32 = 2;
/// Ptrace-report int3 stops carry SI_KERNEL on this kernel
/// (observed live), while the in-process signal frame names
/// the same breakpoint cause TRAP_BRKPT. Both are kernel
/// breakpoint conventions with RIP after the trap byte.
/// A signal another process sends cannot carry a positive
/// si_code (the kernel refuses `si_code >= 0` aimed at another
/// task), but a task's `rt_(tg)sigqueueinfo` aimed at itself
/// can carry any code, including SI_KERNEL. Positive codes
/// stay unforgeable here only because the pass-through gate
/// (`prepare_sigqueue_step`) admits self-queueing with exactly
/// `SI_QUEUE` and refuses every forged self-send by name.
const SI_KERNEL: i32 = 128;

fn is_breakpoint_cause(si_code: i32) -> bool {
    matches!(si_code, TRAP_BRKPT | SI_KERNEL)
}

/// Linux syscall-restart results visible at a ptrace
/// syscall-exit stop while a signal is pending
/// (`-ERESTARTSYS`, `-ERESTARTNOINTR`, `-ERESTARTNOHAND`,
/// `-ERESTART_RESTARTBLOCK`). The syscall has not completed
/// and would restart on resume; it must never be credited.
fn is_syscall_restart(rax: u64) -> bool {
    matches!(rax as i64, -512 | -513 | -514 | -516)
}

/// Classify one ptrace stop from wait status **and** siginfo
/// cause. `exact_exit_trap` is the caller-computed exactness
/// proof for the common-exit trap byte (PC-map entry is the
/// final `AllSaved` common-exit segment and `rip - 1` is its
/// exact start); it is only consulted for a kernel breakpoint
/// trap in the generated phase. User-sent SIGTRAP
/// (`si_code <= 0`) is asynchronous in every phase and never
/// completes a step, a syscall, or a dispatcher exit.
fn classify_stop(
    phase: Phase,
    sig: i32,
    event: i32,
    si: Option<(i32, i32)>,
    exact_exit_trap: bool,
) -> StopClass {
    if event != 0 {
        return StopClass::Unexpected;
    }
    if sig == (libc::SIGTRAP | 0x80) {
        return if matches!(phase, Phase::SyscallEntry | Phase::SyscallExit) {
            StopClass::SyscallStop
        } else {
            StopClass::Unexpected
        };
    }
    let Some((si_signo, si_code)) = si else {
        return StopClass::Unexpected;
    };
    if si_signo != sig {
        return StopClass::Unexpected;
    }
    if si_code <= 0 {
        // At syscall-exit the kernel orders the exit stop
        // before signal delivery on this substrate; an async
        // stop here cannot establish whether the syscall
        // completed, so it fails closed instead of guessing.
        return if phase == Phase::SyscallExit {
            StopClass::Unexpected
        } else {
            StopClass::Async
        };
    }
    match phase {
        Phase::Generated => {
            if sig == libc::SIGTRAP && is_breakpoint_cause(si_code) && exact_exit_trap {
                StopClass::ExitTrap
            } else if sig == libc::SIGTRAP && si_code == TRAP_TRACE {
                StopClass::Unexpected // no step was issued
            } else {
                StopClass::GeneratedFault
            }
        }
        Phase::OriginalStep => {
            if sig == libc::SIGTRAP && si_code == TRAP_TRACE {
                StopClass::StepComplete
            } else {
                StopClass::SourceFault
            }
        }
        Phase::SyscallEntry => {
            if sig == libc::SIGTRAP {
                StopClass::Unexpected // not a syscall-enter stop
            } else {
                StopClass::SourceFault
            }
        }
        Phase::SyscallExit => StopClass::Unexpected,
    }
}

/// Siginfo cause for a stop, as `(si_signo, si_code, si_addr)`.
/// Syscall stops carry no siginfo and return `None` by design;
/// any other stop without retrievable siginfo also returns
/// `None` and classifies `Unexpected` (fail closed).
/// Generated entry that re-executes exactly the source
/// instruction at `src` from its pre-insn state, for a
/// mid-block resume: a copied insn start, a pristine direct
/// call sequence start, or a pristine exit-stub start.
/// Block starts are served by `block_gen` and return `None`
/// here only in the sense that callers check those first;
/// machinery interiors have no exact re-entry and miss.
/// Resume entry for an asynchronous stop at generated PC
/// `gen_pc` recovered to source PC `src`: `Some(None)` =
/// block-start entry through the block index,
/// `Some(Some(gen))` = exact mid-block re-entry, `None` =
/// not resumable in I1-E. Common-exit machinery stops and
/// generated PCs with no pcmap entry at all (entry-loader
/// bridge / executor-error stops, recovered src 0) are
/// excluded here by construction: arbitrary-phase delivery
/// in this stage means every *guest-instruction* phase
/// (copied, count/poll stubs, call and exit sequences via
/// their recovered successors), not the dispatcher's own
/// epilogue or unmapped entry bytes. Those keep the
/// recovered named stop.
fn resume_gen(t: &Translation, gen_pc: u64, src: u64) -> Option<Option<u64>> {
    let entry = t.pcmap.lookup(gen_pc)?;
    if matches!(entry.recovery, MapRecovery::CommonExit { .. }) {
        return None;
    }
    if t.block_gen.contains_key(&src) {
        return Some(None);
    }
    gen_for_midblock(t, src).map(Some)
}

fn gen_for_midblock(t: &Translation, src: u64) -> Option<u64> {
    t.pcmap.entries().iter().find_map(|e| match e.recovery {
        MapRecovery::Copied if e.src_pc == src => Some(e.gen_start),
        MapRecovery::Call {
            call_pc,
            stage: CallStage::Pristine,
            ..
        } if call_pc == src => Some(e.gen_start),
        MapRecovery::ExitStub {
            stage: ExitStage::Pristine,
        } if e.src_pc == src => Some(e.gen_start),
        _ => None,
    })
}

/// Rewrite the pending signal's `si_addr` (offset 16 in the
/// kernel `siginfo` layout) via `PTRACE_SETSIGINFO`, for
/// instruction-address faults whose generated address must
/// be presented in source form. All other siginfo words are
/// preserved byte-for-byte from the kernel's own record.
fn set_siginfo_addr(pid: i32, addr: u64) -> Result<(), Refuse> {
    let mut info = get_siginfo(pid)?;
    // SAFETY: byte view over the plain-data siginfo record;
    // its size covers the si_addr word by the ABI layout.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(info).cast::<u8>(),
            core::mem::size_of::<libc::siginfo_t>(),
        )
    };
    bytes[16..24].copy_from_slice(&addr.to_le_bytes());
    ptrace_ok(
        libc::PTRACE_SETSIGINFO,
        pid,
        core::ptr::null_mut(),
        core::ptr::addr_of_mut!(info).cast(),
        "PTRACE_SETSIGINFO",
    )
}

fn stop_siginfo(pid: i32, sig: i32) -> Option<(i32, i32, u64)> {
    if sig == (libc::SIGTRAP | 0x80) {
        return None;
    }
    let info = get_siginfo(pid).ok()?;
    // SAFETY: filled by PTRACE_GETSIGINFO above.
    let addr = unsafe { info.si_addr() } as usize as u64;
    Some((info.si_signo, info.si_code, addr))
}

/// Owns the traced child: every drop path — success, refusal,
/// fault, or substrate error — kills and reaps it, so no early
/// return can leak a process.
struct ChildGuard {
    child: Child,
    pid: i32,
    reaped: bool,
}

impl ChildGuard {
    fn kill_reap(&mut self) {
        if self.reaped {
            return;
        }
        self.reaped = true;
        ptrace(
            libc::PTRACE_KILL,
            self.pid,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        let mut status: i32 = 0;
        // SAFETY: reaping our own traced child.
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);
        }
        let _ = self.child.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_reap();
    }
}

/// Test seam (I1-H H1): deterministic signal arrival at a
/// generated PC. One hardware execute breakpoint (DR0, local
/// enable in DR7) is armed at `gen_pc` for the run; on its
/// `hit`-th execution the tracer disarms it, clears the RF flag
/// the breakpoint left in RFLAGS, sends `sig` to its own traced
/// child, and resumes, so the kernel presents that signal's
/// delivery stop exactly at `gen_pc` before the instruction
/// there executes. No trace flag is used, so nothing can leak
/// into spilled guest flags. Earlier hits only resume (with RF
/// set, so the instruction runs once without re-trapping).
#[cfg(feature = "test-seams")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArrivalSeam {
    pub gen_pc: u64,
    pub hit: u64,
    pub sig: i32,
}

/// One genuine delivery made from a generated-phase stop,
/// recorded by the test seam (records only).
#[cfg(feature = "test-seams")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeamDelivery {
    pub signum: i32,
    pub gen_pc: u64,
    /// The recovered source state's PC and the retired totals
    /// before it, as the frame was built.
    pub src_pc: u64,
    pub instructions: u64,
    pub branches: u64,
}

/// What the test seams observed during the last run.
#[cfg(feature = "test-seams")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArrivalReport {
    /// Arrival breakpoint hits, firing hit included.
    pub hits: u64,
    /// The arrival signal was sent.
    pub sent: bool,
    /// RFLAGS.RF as the kernel left it at each hit, in order.
    pub rf_at_hits: Vec<bool>,
    /// Every delivery from a generated-phase stop, in order.
    pub deliveries: Vec<SeamDelivery>,
}

/// `PTRACE_POKEUSER` offset of debug register `n`.
#[cfg(feature = "test-seams")]
fn debugreg_offset(n: usize) -> usize {
    core::mem::offset_of!(libc::user, u_debugreg) + 8 * n
}

#[cfg(feature = "test-seams")]
fn poke_debugreg(pid: i32, n: usize, value: u64) -> Result<(), Refuse> {
    ptrace_ok(
        libc::PTRACE_POKEUSER,
        pid,
        debugreg_offset(n) as *mut u8,
        value as usize as *mut u8,
        "PTRACE_POKEUSER debug register",
    )
}

#[cfg(feature = "test-seams")]
fn peek_debugreg(pid: i32, n: usize) -> Option<u64> {
    // SAFETY: errno is thread-local; cleared so a legitimate
    // all-ones value is told apart from a failed peek.
    unsafe { *libc::__errno_location() = 0 };
    let v = ptrace(
        libc::PTRACE_PEEKUSER,
        pid,
        debugreg_offset(n) as *mut u8,
        core::ptr::null_mut(),
    );
    // SAFETY: as above.
    let errno = unsafe { *libc::__errno_location() };
    (v != -1 || errno == 0).then_some(v as u64)
}

/// DR7 local-enable bit for DR0 (execute, length 1: RW0 and
/// LEN0 both zero).
#[cfg(feature = "test-seams")]
const DR7_L0: u64 = 1;
/// RFLAGS.RF: suppresses an instruction breakpoint for one
/// instruction.
#[cfg(feature = "test-seams")]
const RFLAGS_RF: u64 = 0x1_0000;
/// `si_code` of a hardware-breakpoint SIGTRAP.
#[cfg(feature = "test-seams")]
const TRAP_HWBKPT: i32 = 4;

/// Clears DR7 then DR0 on every exit path of a run that armed
/// the arrival breakpoint: success, refusal, fault, substrate
/// error, and panic unwinding. Errors are ignored (a child that
/// already ended has no debug registers left to clear).
#[cfg(feature = "test-seams")]
struct DebugRegGuard {
    pid: i32,
}

#[cfg(feature = "test-seams")]
impl Drop for DebugRegGuard {
    fn drop(&mut self) {
        let _ = poke_debugreg(self.pid, 7, 0);
        let _ = poke_debugreg(self.pid, 0, 0);
    }
}

/// A prepared remote direct-block executable. Dropping it
/// kills and reaps the child on every path.
pub struct RemoteExecutable {
    guard: ChildGuard,
    info: RemoteChildInfo,
    translation: Option<Translation>,
    profile: CountProfile,
    registry: SignalRegistry,
    /// Test seam, inert unless set: see
    /// `set_pre_redirected_step_signal_for_test`.
    #[cfg(feature = "test-seams")]
    pre_redirected_step_signal: Option<i32>,
    /// Test seams, inert unless set: see
    /// `set_pre_original_step_signal_for_test` and
    /// `set_arrival_for_test`.
    #[cfg(feature = "test-seams")]
    pre_original_step_signal: Option<i32>,
    #[cfg(feature = "test-seams")]
    arrival: Option<ArrivalSeam>,
    #[cfg(feature = "test-seams")]
    arrival_report: std::cell::RefCell<ArrivalReport>,
    #[cfg(feature = "test-seams")]
    poll_budget: Option<u64>,
}

impl RemoteExecutable {
    pub fn spawn_named(child_bin: &std::path::Path, fixture_name: &str) -> Result<Self, Refuse> {
        Self::spawn(child_bin, vec![fixture_name.to_string()])
    }

    /// Spawn with the named signals blocked in the child from
    /// the start (a legitimate guest initial mask): queued
    /// signals then stay pending until a poll exit observes
    /// them, which is how tests arrange a genuine poll-boundary
    /// stop deterministically.
    pub fn spawn_named_with_blocked(
        child_bin: &std::path::Path,
        fixture_name: &str,
        blocked: &[i32],
    ) -> Result<Self, Refuse> {
        let list: Vec<String> = blocked.iter().map(i32::to_string).collect();
        let exe = Self::spawn(
            child_bin,
            vec![
                fixture_name.to_string(),
                format!("block:{}", list.join(",")),
            ],
        )?;
        Self::verify_initial_blocked(&exe.registry, blocked)?;
        Ok(exe)
    }

    /// The mirror mask was seeded from the child's actual
    /// SigBlk at spawn; a requested signal the child could
    /// not actually block (e.g. glibc-reserved 32/33, or
    /// SIGKILL/SIGSTOP) is refused by name here instead of
    /// being replayed into the mirror as if honored.
    fn verify_initial_blocked(registry: &SignalRegistry, blocked: &[i32]) -> Result<(), Refuse> {
        let mut requested: u64 = 0;
        for &sig in blocked {
            if (1..=64).contains(&sig) {
                requested |= 1u64 << (sig - 1);
            } else {
                return Err(Refuse::RemoteSubstrate {
                    operation: "initial blocked signal out of range",
                    errno: 0,
                });
            }
        }
        if registry.mask & requested != requested {
            return Err(Refuse::RemoteSubstrate {
                operation: "initial blocked mask not honored",
                errno: 0,
            });
        }
        Ok(())
    }

    pub fn spawn_bytes(child_bin: &std::path::Path, bytes: &[u8]) -> Result<Self, Refuse> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Self::spawn(child_bin, vec![format!("hex:{hex}")])
    }

    /// `spawn_bytes` with the named signals blocked in the
    /// child from the start, for deterministic I1-D delivery:
    /// a signal sent before the run stays pending until the
    /// guest itself unblocks it after installing its handler.
    pub fn spawn_bytes_with_blocked(
        child_bin: &std::path::Path,
        bytes: &[u8],
        blocked: &[i32],
    ) -> Result<Self, Refuse> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let list: Vec<String> = blocked.iter().map(i32::to_string).collect();
        let exe = Self::spawn(
            child_bin,
            vec![format!("hex:{hex}"), format!("block:{}", list.join(","))],
        )?;
        Self::verify_initial_blocked(&exe.registry, blocked)?;
        Ok(exe)
    }

    /// Spawn with the child's destination buffer backed by an
    /// explicit two-page guarded allocation (usable tail plus
    /// an inaccessible second page), for partial-input tests
    /// that must prove an exact readable byte count.
    pub fn spawn_bytes_guarded(child_bin: &std::path::Path, bytes: &[u8]) -> Result<Self, Refuse> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Self::spawn(
            child_bin,
            vec![format!("hex:{hex}"), "guarded-dst".to_string()],
        )
    }

    fn spawn(child_bin: &std::path::Path, spawn_args: Vec<String>) -> Result<Self, Refuse> {
        let child = Command::new(child_bin)
            .args(&spawn_args)
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| remote_err("spawn remote child"))?;
        let pid = child.id() as i32;
        // A reused pid must not inherit an earlier child's
        // recorded writes.
        #[cfg(feature = "test-seams")]
        TRACER_WRITES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|w| w.0 != pid);
        let mut guard = ChildGuard {
            child,
            pid,
            reaped: false,
        };
        let mut raw = [0u8; 56];
        let mut dump = [0u8; 65 * 32];
        {
            let out = guard.child.stdout.as_mut().ok_or(Refuse::RemoteSubstrate {
                operation: "remote child stdout",
                errno: 0,
            })?;
            out.read_exact(&mut raw)
                .map_err(|_| Refuse::RemoteSubstrate {
                    operation: "read remote child setup",
                    errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                })?;
            out.read_exact(&mut dump)
                .map_err(|_| Refuse::RemoteSubstrate {
                    operation: "read remote child action dump",
                    errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                })?;
        }
        let info = RemoteChildInfo::from_bytes(&raw);
        // Seed every action from the child's kernel answers
        // verbatim, before the initial stop is serviced. No
        // action word is invented by the tracer.
        let mut seeded_actions = [GuestAction::default(); 65];
        for (sig, slot) in seeded_actions.iter_mut().enumerate().skip(1) {
            let w = |word: usize| {
                let o = sig * 32 + word * 8;
                u64::from_le_bytes(dump[o..o + 8].try_into().unwrap())
            };
            *slot = GuestAction {
                handler: w(0),
                flags: w(1),
                restorer: w(2),
                sa_mask: w(3),
            };
        }
        let status = wait_stop(pid)?;
        if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP {
            return Err(Refuse::RemoteSubstrate {
                operation: "remote child initial stop",
                errno: 0,
            });
        }
        // Syscall stops must be distinguishable from plain traps.
        ptrace_ok(
            libc::PTRACE_SETOPTIONS,
            pid,
            core::ptr::null_mut(),
            libc::PTRACE_O_TRACESYSGOOD as usize as *mut u8,
            "PTRACE_SETOPTIONS",
        )?;
        // Seed the mirror mask from the stopped child's actual
        // kernel state, never from the request that produced it.
        let mut registry = SignalRegistry {
            actions: seeded_actions,
            ..SignalRegistry::default()
        };
        registry.set_mask(read_sigblk(pid)?);
        Ok(RemoteExecutable {
            guard,
            info,
            translation: None,
            profile: CountProfile::BranchesAndInstructions,
            registry,
            #[cfg(feature = "test-seams")]
            pre_redirected_step_signal: None,
            #[cfg(feature = "test-seams")]
            pre_original_step_signal: None,
            #[cfg(feature = "test-seams")]
            arrival: None,
            #[cfg(feature = "test-seams")]
            arrival_report: std::cell::RefCell::new(ArrivalReport::default()),
            #[cfg(feature = "test-seams")]
            poll_budget: None,
        })
    }

    pub fn info(&self) -> RemoteChildInfo {
        self.info
    }

    /// Tracer mirror of the guest's kernel-owned signal
    /// registry (see module docs for the ownership rules).
    pub fn registry(&self) -> &SignalRegistry {
        &self.registry
    }

    /// Identify which registry state (if any) a stepped
    /// syscall must have reconciled from post-call kernel
    /// readback, from registers alone at the generated
    /// common-exit stop (before stepping). No guest memory is
    /// read here: an unreadable guest argument must reach the
    /// kernel and produce the guest's own errno, never an
    /// observer refusal.
    fn observe_syscall_entry(&self, nr: u32, _state: &GuestState) -> SyscallObs {
        match nr {
            x if x == libc::SYS_rt_sigprocmask as u32 => SyscallObs::Sigprocmask,
            x if x == libc::SYS_sigaltstack as u32 => SyscallObs::Sigaltstack,
            _ => SyscallObs::None,
        }
    }

    /// Prepare one stepped `rt_sigaction` (I1-D). A readable
    /// custom-handler act is copied to tracer scratch with
    /// only its handler word replaced by the common stub, so
    /// the kernel disposition traps to this dispatcher while
    /// flags/restorer/mask stay guest-genuine; guest act
    /// memory is never written. An unreadable act prepares no
    /// copy and steps genuinely (kernel `EFAULT`). A source
    /// handler equal to the stub address cannot be told apart
    /// from the stub on readback and is refused by name before
    /// anything steps.
    fn prepare_sigaction_step(&self, state: &GuestState) -> Result<SigactionStep, Refuse> {
        let sig = state.rdi as i32;
        let mut step = SigactionStep {
            sig,
            oldact_addr: state.rdx,
            prev_visible: self.registry.action(sig),
            requested: None,
            step_rsi: None,
            saved_scratch: None,
        };
        if state.rsi == 0 {
            return Ok(step);
        }
        let mut raw = [0u8; 32];
        if read_mem(self.guard.pid, state.rsi, &mut raw).is_err() {
            return Ok(step);
        }
        let handler = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        if handler <= 1 {
            return Ok(step);
        }
        if handler == self.signal_stub_addr() {
            return Err(Refuse::RemoteSubstrate {
                operation: "guest handler aliases signal stub",
                errno: 0,
            });
        }
        let scratch = self.scratch_addr();
        let mut saved = [0u8; 32];
        read_mem(self.guard.pid, scratch, &mut saved)?;
        raw[0..8].copy_from_slice(&self.signal_stub_addr().to_le_bytes());
        write_mem(self.guard.pid, scratch, &raw)?;
        step.requested = Some(handler);
        step.step_rsi = Some(scratch);
        step.saved_scratch = Some(saved);
        Ok(step)
    }

    /// The traced child's own pid exactly as its kernel
    /// compares it (`task_pid_vnr(current)`), proven equal to
    /// the tracer's view: `/proc/<pid>/status` `NSpid` must list
    /// exactly one pid, ours. Any other shape (a nested pid
    /// namespace, unreadable status) is `None` and the caller
    /// fails closed.
    fn own_pid_in_child_ns(&self) -> Option<i32> {
        let text = std::fs::read_to_string(format!("/proc/{}/status", self.guard.pid)).ok()?;
        let line = text.lines().find_map(|l| l.strip_prefix("NSpid:"))?;
        let mut fields = line.split_whitespace();
        let first: i32 = fields.next()?.parse().ok()?;
        (fields.next().is_none() && first == self.guard.pid).then_some(first)
    }

    /// Gate one guest `rt_sigqueueinfo` (`pid, sig, info`) or
    /// `rt_tgsigqueueinfo` (`tgid, tid, sig, info`) at its
    /// syscall exit, before anything steps (I1-G1). Target ids
    /// are compared as the kernel sees them (low 32 bits as
    /// `pid_t`); the guest is single-threaded (thread creation
    /// is refused), so its own TID and TGID both equal its pid.
    ///
    /// Calls the kernel provably refuses with no side effect
    /// step genuinely, so the guest sees the kernel's own errno
    /// (`kernel/signal.c`): a forged code (`si_code >= 0` or
    /// `SI_TKILL`) whose compared target (`pid`, or `tid` for
    /// the tg form) is not the caller gets `-EPERM` before any
    /// lookup (`do_rt_sigqueueinfo`, `do_rt_tgsigqueueinfo`;
    /// the tg form answers `-EINVAL` first for a non-positive
    /// id); and the tg form with the caller's own TID but a
    /// foreign TGID gets `-ESRCH` from `do_send_specific`
    /// whatever the code. A forged code aimed at the caller
    /// itself is accepted by Linux but would forge kernel
    /// provenance on delivery (`SI_KERNEL` SIGTRAP reads as an
    /// exit trap, a positive SIGSEGV code as a synchronous
    /// fault), so it is refused by name — a deliberate
    /// divergence from native. Every other call steps only as
    /// the tested shape: `si_code == SI_QUEUE`, an admitted
    /// signal, and every target word (full 64-bit register)
    /// equal to the child's own pid. `si_signo` is not checked:
    /// the kernel overwrites it with the requested signal
    /// (`__copy_siginfo_from_user`), as natively. A non-forged
    /// call to another task is refused by name even where
    /// native might fail (a nonexistent pid gets `ESRCH`),
    /// because nothing proves the kernel would not queue it; so
    /// is an unreadable siginfo.
    ///
    /// Invariant: staging is sound only while the guest cannot
    /// change the arena's or its own pages' protections —
    /// `mprotect` and `pkey_*` are not passed through. The
    /// kernel reads the tracer-written copy, so readability of
    /// the guest buffer is decided by this tracer's
    /// `process_vm_readv` (which does not apply protection
    /// keys), not by the guest's own `copy_from_user`.
    fn prepare_sigqueue_step(
        &self,
        state: &GuestState,
        src_pc: u64,
    ) -> Result<SigqueueStep, Refuse> {
        let refuse = Refuse::NoHandler { src_pc };
        let tg = state.rax as u32 == libc::SYS_rt_tgsigqueueinfo as u32;
        let (sig_word, info_addr) = if tg {
            (state.rdx, state.r10)
        } else {
            (state.rsi, state.rdx)
        };
        let mut info = [0u8; SIGINFO_LEN];
        if read_mem(self.guard.pid, info_addr, &mut info).is_err() {
            return Err(refuse);
        }
        let si_code = i32::from_le_bytes(info[8..12].try_into().unwrap());
        let own = self.own_pid_in_child_ns().ok_or(refuse.clone())?;
        let forged = si_code >= 0 || si_code == SI_TKILL;
        // Kernel views: `pid` (tgid for the tg form) and `tid`.
        let k_pid = state.rdi as u32 as i32;
        let k_tid = state.rsi as u32 as i32;
        let kernel_target = if tg { k_tid } else { k_pid };
        let kernel_refuses =
            (forged && kernel_target != own) || (tg && k_tid == own && k_pid != own);
        if !kernel_refuses {
            if forged {
                return Err(refuse);
            }
            let own_word = own as u64;
            let self_target = state.rdi == own_word && (!tg || state.rsi == own_word);
            let sig_ok = i32::try_from(sig_word).is_ok_and(async_delivery_admitted);
            if si_code != SI_QUEUE || !self_target || !sig_ok {
                return Err(refuse);
            }
        }
        let staged = self.scratch_addr();
        let mut saved = [0u8; SIGINFO_LEN];
        read_mem(self.guard.pid, staged, &mut saved)?;
        write_mem(self.guard.pid, staged, &info)?;
        Ok(SigqueueStep {
            tg,
            staged,
            saved,
            kernel_refuses,
        })
    }

    /// Finish one stepped `rt_sigaction` (the caller restores
    /// scratch on every path first): virtualize the old-action
    /// handler word the guest observes, and reconcile the
    /// mirror from post-call kernel readback translated
    /// through `visible_handler`. The old-action rewrite
    /// ignores write failure: a bad old-action pointer already
    /// produced the guest's own copy-out `EFAULT`, and the
    /// mirror still follows the real mutation through readback.
    fn finish_sigaction_step(
        &self,
        registry: &mut SignalRegistry,
        step: &SigactionStep,
        step_rax: u64,
        gadget_pc: u64,
    ) -> Result<(), Refuse> {
        // Only a successful call copied the previous kernel
        // action out; an errored call (EINVAL/EFAULT) left
        // guest oldact memory untouched and so must we.
        if step_rax == 0 && step.oldact_addr != 0 && step.prev_visible.is_custom() {
            let _ = write_mem(
                self.guard.pid,
                step.oldact_addr,
                &step.prev_visible.handler.to_le_bytes(),
            );
        }
        if !(1..=64).contains(&step.sig) {
            return Ok(());
        }
        let mut act = Self::query_action(self.guard.pid, self.data_addr(), step.sig, gadget_pc)?;
        act.handler = visible_handler(
            act.handler,
            self.signal_stub_addr(),
            step.requested,
            step.prev_visible,
            step_rax,
        )
        .ok_or(Refuse::RemoteSubstrate {
            operation: "registry action readback unnamed",
            errno: 0,
        })?;
        registry.set_action(step.sig, act);
        Ok(())
    }

    /// Execute one query syscall in the stopped child at a
    /// known syscall instruction, restoring the full register
    /// set and the scratch bytes it used afterwards, on every
    /// path. Returns the query result register and the 32
    /// scratch bytes the kernel wrote. The guest's own result
    /// from the preceding stepped syscall lives in tracer-side
    /// state and is never disturbed: child registers are
    /// restored byte-exact before returning.
    fn injected_query(
        pid: i32,
        data_addr: u64,
        nr: u64,
        args: [u64; 4],
        gadget_pc: u64,
    ) -> Result<(i64, [u8; 32]), Refuse> {
        let [rdi, rsi, rdx, r10] = args;
        let saved = get_regs(pid)?;
        let scratch = data_addr + core::mem::offset_of!(JitData, scratch) as u64;
        let mut saved_scratch = [0u8; 32];
        read_mem(pid, scratch, &mut saved_scratch)?;
        let run = (|| -> Result<(i64, [u8; 32]), Refuse> {
            let mut regs = saved;
            regs.rax = nr;
            regs.rdi = rdi;
            regs.rsi = rsi;
            regs.rdx = rdx;
            regs.r10 = r10;
            regs.rip = gadget_pc;
            set_regs(pid, &regs)?;
            for phase in [Phase::SyscallEntry, Phase::SyscallExit] {
                ptrace_ok(
                    libc::PTRACE_SYSCALL,
                    pid,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    "PTRACE_SYSCALL readback",
                )?;
                let status = wait_stop(pid)?;
                if !libc::WIFSTOPPED(status) {
                    return Err(Refuse::RemoteSubstrate {
                        operation: "remote guest ended during registry readback",
                        errno: 0,
                    });
                }
                let sig = libc::WSTOPSIG(status);
                let si = stop_siginfo(pid, sig);
                if classify_stop(
                    phase,
                    sig,
                    status >> 16,
                    si.map(|(signo, code, _)| (signo, code)),
                    false,
                ) != StopClass::SyscallStop
                {
                    return Err(Refuse::RemoteSubstrate {
                        operation: "registry readback stop provenance",
                        errno: 0,
                    });
                }
            }
            let out_regs = get_regs(pid)?;
            if is_syscall_restart(out_regs.rax) {
                return Err(Refuse::RemoteSubstrate {
                    operation: "registry readback restart pending",
                    errno: 0,
                });
            }
            let mut out = [0u8; 32];
            read_mem(pid, scratch, &mut out)?;
            Ok((out_regs.rax as i64, out))
        })();
        // Restore guest registers and scratch exactly, whatever
        // the query did; a restore failure is itself fatal.
        let restore = set_regs(pid, &saved).and_then(|()| write_mem(pid, scratch, &saved_scratch));
        match (run, restore) {
            (Ok(v), Ok(())) => Ok(v),
            (Err(e), _) => Err(e),
            (Ok(_), Err(e)) => Err(e),
        }
    }

    fn query_action(
        pid: i32,
        data_addr: u64,
        sig: i32,
        gadget_pc: u64,
    ) -> Result<GuestAction, Refuse> {
        let scratch = data_addr + core::mem::offset_of!(JitData, scratch) as u64;
        let (ret, raw) = Self::injected_query(
            pid,
            data_addr,
            libc::SYS_rt_sigaction as u64,
            [sig as u64, 0, scratch, 8],
            gadget_pc,
        )?;
        if ret != 0 {
            return Err(Refuse::RemoteSubstrate {
                operation: "registry action readback failed",
                errno: 0,
            });
        }
        let w = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
        Ok(GuestAction {
            handler: w(0),
            flags: w(8),
            restorer: w(16),
            sa_mask: w(24),
        })
    }

    fn query_altstack(pid: i32, data_addr: u64, gadget_pc: u64) -> Result<GuestAltstack, Refuse> {
        let scratch = data_addr + core::mem::offset_of!(JitData, scratch) as u64;
        let (ret, raw) = Self::injected_query(
            pid,
            data_addr,
            libc::SYS_sigaltstack as u64,
            [0, scratch, 0, 0],
            gadget_pc,
        )?;
        if ret != 0 {
            return Err(Refuse::RemoteSubstrate {
                operation: "registry altstack readback failed",
                errno: 0,
            });
        }
        Ok(GuestAltstack {
            sp: u64::from_le_bytes(raw[0..8].try_into().unwrap()),
            flags: i32::from_le_bytes(raw[8..12].try_into().unwrap()),
            size: u64::from_le_bytes(raw[16..24].try_into().unwrap()),
        })
    }

    /// Reconcile the mirror with authoritative post-call
    /// kernel state after a stepped registry syscall, whatever
    /// its result (including copy-out `EFAULT` after a real
    /// mutation). A readback that cannot be performed fails
    /// closed by name; the mirror is never updated by guessing
    /// from raw guest input.
    fn reconcile_registry(
        registry: &mut SignalRegistry,
        pid: i32,
        data_addr: u64,
        obs: &SyscallObs,
        gadget_pc: u64,
    ) -> Result<(), Refuse> {
        match *obs {
            SyscallObs::Sigprocmask => {
                let mask = read_sigblk(pid)?;
                registry.set_mask(mask);
                Ok(())
            }
            SyscallObs::Sigaltstack => {
                let alt = Self::query_altstack(pid, data_addr, gadget_pc)?;
                registry.set_altstack(alt);
                Ok(())
            }
            SyscallObs::None => Ok(()),
        }
    }

    #[doc(hidden)]
    pub fn child_pid_for_test(&self) -> i32 {
        self.guard.pid
    }

    /// Test seam: when set, the tracer sends `sig` to its own
    /// traced child after a redirected syscall's argument has
    /// been staged and immediately before the step resumes the
    /// child, so an asynchronous stop lands deterministically
    /// at that boundary (before syscall entry). Inert (`None`)
    /// by default; it never signals any other process. Compiled
    /// only with the test-only `test-seams` feature.
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    pub fn set_pre_redirected_step_signal_for_test(&mut self, sig: Option<i32>) {
        self.pre_redirected_step_signal = sig;
    }

    /// Current test-seam setting (`None` unless a test set it).
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    pub fn pre_redirected_step_signal_for_test(&self) -> Option<i32> {
        self.pre_redirected_step_signal
    }

    /// Test seam (I1-H W3 evidence): when set, the tracer sends
    /// `sig` to its own traced child immediately before it
    /// single-steps an original (nondeterministic) instruction,
    /// so an asynchronous stop lands deterministically in that
    /// step. Inert (`None`) by default.
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    pub fn set_pre_original_step_signal_for_test(&mut self, sig: Option<i32>) {
        self.pre_original_step_signal = sig;
    }

    /// Test seam: arm (or clear) the [`ArrivalSeam`] for the
    /// next run, and reset the [`ArrivalReport`].
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    pub fn set_arrival_for_test(&mut self, arrival: Option<ArrivalSeam>) {
        self.arrival = arrival;
        *self.arrival_report.borrow_mut() = ArrivalReport::default();
    }

    /// Test seam: replace `POLL_BUDGET` (block entries between
    /// poll exits) for later runs, so a short loop crosses many
    /// poll exits; the poll machinery is otherwise unchanged.
    /// `None` restores the production budget.
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    pub fn set_poll_budget_for_test(&mut self, budget: Option<u64>) {
        self.poll_budget = budget;
    }

    /// Block entries between poll exits for a run.
    fn poll_budget(&self) -> u64 {
        #[cfg(feature = "test-seams")]
        {
            self.poll_budget.unwrap_or(POLL_BUDGET)
        }
        #[cfg(not(feature = "test-seams"))]
        {
            POLL_BUDGET
        }
    }

    /// Test seam: what the seams observed during the last run.
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    pub fn arrival_report_for_test(&self) -> ArrivalReport {
        self.arrival_report.borrow().clone()
    }

    /// Test seam: the child's DR0 and DR7 as `PTRACE_PEEKUSER`
    /// reads them now (`None` if the child cannot be read).
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    pub fn debug_regs_for_test(&self) -> Option<(u64, u64)> {
        Some((
            peek_debugreg(self.guard.pid, 0)?,
            peek_debugreg(self.guard.pid, 7)?,
        ))
    }

    /// Test seam: the prepared translation (read-only), for
    /// enumerating generated PCs by PC-map class.
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    pub fn translation_for_test(&self) -> Option<&Translation> {
        self.translation.as_ref()
    }

    /// Arm the arrival breakpoint for one run; the guard clears
    /// it on every exit path.
    #[cfg(feature = "test-seams")]
    fn arm_arrival(&self) -> Result<Option<DebugRegGuard>, Refuse> {
        let Some(seam) = self.arrival else {
            return Ok(None);
        };
        let guard = DebugRegGuard {
            pid: self.guard.pid,
        };
        poke_debugreg(self.guard.pid, 0, seam.gen_pc)?;
        poke_debugreg(self.guard.pid, 7, DR7_L0)?;
        Ok(Some(guard))
    }

    /// Consume arrival-breakpoint stops after a generated-phase
    /// wait and return the first other stop. Fails closed on a
    /// hardware-breakpoint stop at any other PC.
    #[cfg(feature = "test-seams")]
    fn filter_arrival_stops(&self, mut status: i32) -> Result<i32, Refuse> {
        let Some(seam) = self.arrival else {
            return Ok(status);
        };
        let pid = self.guard.pid;
        loop {
            if !libc::WIFSTOPPED(status)
                || libc::WSTOPSIG(status) != libc::SIGTRAP
                || status >> 16 != 0
                || stop_siginfo(pid, libc::SIGTRAP).map(|s| s.1) != Some(TRAP_HWBKPT)
            {
                return Ok(status);
            }
            let mut regs = get_regs(pid)?;
            let mut report = self.arrival_report.borrow_mut();
            if regs.rip != seam.gen_pc || report.sent {
                return Err(remote_err("arrival breakpoint stop at an unexpected pc"));
            }
            report.hits += 1;
            report.rf_at_hits.push(regs.eflags & RFLAGS_RF != 0);
            if report.hits < seam.hit {
                // Not yet: let the instruction run once without
                // re-trapping, and suppress the SIGTRAP.
                if regs.eflags & RFLAGS_RF == 0 {
                    regs.eflags |= RFLAGS_RF;
                    set_regs(pid, &regs)?;
                }
            } else {
                poke_debugreg(pid, 7, 0)?;
                poke_debugreg(pid, 0, 0)?;
                if regs.eflags & RFLAGS_RF != 0 {
                    regs.eflags &= !RFLAGS_RF;
                    set_regs(pid, &regs)?;
                }
                // SAFETY: signalling this tracer's own traced,
                // stopped, unreaped child.
                if unsafe { libc::kill(pid, seam.sig) } != 0 {
                    return Err(remote_err("arrival seam signal"));
                }
                report.sent = true;
            }
            drop(report);
            self.cont(0)?;
            status = wait_stop(pid)?;
        }
    }

    /// Test seam log: one delivery from a generated-phase stop.
    #[cfg(feature = "test-seams")]
    fn record_seam_delivery(
        &self,
        signum: i32,
        gen_pc: u64,
        recovered: &crate::recovery::RecoveredStop,
    ) {
        self.arrival_report
            .borrow_mut()
            .deliveries
            .push(SeamDelivery {
                signum,
                gen_pc,
                src_pc: recovered.src_pc,
                instructions: recovered.instructions,
                branches: recovered.branches,
            });
    }

    /// Test seam: every guest-memory write this tracer attempted
    /// into its child since spawn, as `(addr, len)`, in order
    /// (see `TRACER_WRITES`). Compiled only with the test-only
    /// `test-seams` feature.
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    pub fn tracer_writes_for_test(&self) -> Vec<(u64, usize)> {
        TRACER_WRITES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|w| w.0 == self.guard.pid)
            .map(|w| (w.1, w.2))
            .collect()
    }

    /// Step one guest syscall at `pc` whose pointer argument in
    /// `reg` was redirected to tracer scratch (`staged`):
    /// `rt_sigaction` stubbing (I1-D) and `rt_(tg)sigqueueinfo`
    /// staging (I1-G1). On every path the saved scratch bytes
    /// are restored first, and the guest's own register value is
    /// put back into the returned guest state — including a
    /// recovered `Fault` (an asynchronous stop before syscall
    /// entry), whose live registers would otherwise carry the
    /// private scratch address. A failed scratch restore is a
    /// named substrate refusal, never a clean step.
    fn step_redirected_syscall(
        &self,
        state: GuestState,
        reg: ArgReg,
        staged: u64,
        saved: &[u8],
        pc: u64,
        data: &JitData,
    ) -> Result<GuestState, RunError> {
        let mut step_state = state;
        reg.set(&mut step_state, staged);
        #[cfg(feature = "test-seams")]
        if let Some(sig) = self.pre_redirected_step_signal {
            // SAFETY: signalling this tracer's own traced child.
            if unsafe { libc::kill(self.guard.pid, sig) } != 0 {
                // Cleanup first: the staged bytes never stay.
                write_mem(self.guard.pid, self.scratch_addr(), saved)?;
                return Err(remote_err("test pre-step signal").into());
            }
        }
        let stepped = self.step_syscall(step_state, pc, data);
        let restored = write_mem(self.guard.pid, self.scratch_addr(), saved);
        let orig = reg.get(&state);
        let stepped = match stepped {
            Ok(mut s) => {
                reg.set(&mut s, orig);
                Ok(s)
            }
            Err(RunError::Fault(mut f)) => {
                reg.set(&mut f.state, orig);
                Err(RunError::Fault(f))
            }
            Err(e) => Err(e),
        };
        if restored.is_err() {
            return Err(remote_err("restore staged scratch").into());
        }
        stepped
    }

    pub fn initial_state(&self) -> GuestState {
        GuestState {
            rsp: self.info.stack_top,
            rflags: 0x202,
            rip: self.info.base,
            ..GuestState::default()
        }
    }

    fn data_addr(&self) -> u64 {
        self.info.arena_base + CODE_CAP as u64
    }

    /// Child address of the I1-D common signal-entry stub
    /// (`int3` at the reserved arena tail, published RX with
    /// the translation by `prepare`).
    fn signal_stub_addr(&self) -> u64 {
        self.info.arena_base + (CODE_CAP - STUB_TAIL) as u64
    }

    fn scratch_addr(&self) -> u64 {
        self.data_addr() + core::mem::offset_of!(JitData, scratch) as u64
    }

    fn read_word(&self, addr: u64) -> Result<u64, Refuse> {
        let mut buf = [0u8; 8];
        read_mem(self.guard.pid, addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn cont(&self, sig: i32) -> Result<(), Refuse> {
        ptrace_ok(
            libc::PTRACE_CONT,
            self.guard.pid,
            core::ptr::null_mut(),
            sig as usize as *mut u8,
            "PTRACE_CONT",
        )
    }

    fn read_jit_data(&self) -> Result<JitData, Refuse> {
        let mut buf = vec![0u8; core::mem::size_of::<JitData>()];
        read_mem(self.guard.pid, self.data_addr(), &mut buf)?;
        // SAFETY: JitData is repr(C) plain data; the buffer holds
        // exactly one child-written image of it.
        Ok(unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<JitData>()) })
    }

    fn write_jit_data(&self, data: &JitData) -> Result<(), Refuse> {
        // SAFETY: byte view of the repr(C) plain-data struct.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (data as *const JitData).cast::<u8>(),
                core::mem::size_of::<JitData>(),
            )
        };
        write_mem(self.guard.pid, self.data_addr(), bytes)
    }

    /// Read child memory (test/differential support).
    pub fn read_mem(&self, addr: u64, buf: &mut [u8]) -> bool {
        read_mem(self.guard.pid, addr, buf).is_ok()
    }

    /// Translate for the child arena, copy the code in, and have
    /// the child publish it RX (mailbox handshake in the child
    /// park loop). One-shot per spawn, mirroring flush-and-
    /// reprepare: a second prepare refuses by name.
    pub fn prepare(
        &mut self,
        region: &RegionFacts,
        entry: u64,
        profile: CountProfile,
    ) -> Result<(), Refuse> {
        if self.translation.is_some() {
            return Err(Refuse::Arch {
                what: "remote executable already prepared",
            });
        }
        if region.base != self.info.base {
            return Err(Refuse::Unrelocatable {
                src_pc: entry,
                reason: "remote region base does not match child fixture mapping",
            });
        }
        let translation = translate_with_exit_style(
            region,
            entry,
            profile,
            self.info.arena_base,
            self.data_addr(),
            ExitStyle::TrapToDispatcher,
        )?;
        if translation.code.len() > CODE_CAP - STUB_TAIL {
            return Err(Refuse::BudgetExceeded { what: "code cache" });
        }
        write_mem(self.guard.pid, self.info.arena_base, &translation.code)?;
        // Common signal-entry stub at the reserved tail; the
        // publish handshake below makes it RX with the rest of
        // the code region. Only the first byte is ever entered.
        let mut stub = [0x90u8; STUB_TAIL];
        stub[0] = 0xcc;
        write_mem(self.guard.pid, self.signal_stub_addr(), &stub)?;
        // Publish: command the parked child to mprotect the code
        // region RX and park again; resume only on its ack.
        write_mem(
            self.guard.pid,
            self.info.mailbox,
            &MAILBOX_PUBLISH.to_le_bytes(),
        )?;
        self.cont(0)?;
        let status = wait_stop(self.guard.pid)?;
        if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP {
            return Err(Refuse::RemoteSubstrate {
                operation: "remote publish stop",
                errno: 0,
            });
        }
        let mut ack = [0u8; 8];
        read_mem(self.guard.pid, self.info.mailbox, &mut ack)?;
        if u64::from_le_bytes(ack) != MAILBOX_PUBLISHED {
            return Err(Refuse::RemoteSubstrate {
                operation: "remote publish ack",
                errno: 0,
            });
        }
        self.translation = Some(translation);
        self.profile = profile;
        Ok(())
    }

    fn set_guest_regs(&self, state: &GuestState) -> Result<(), Refuse> {
        let mut regs = get_regs(self.guard.pid)?;
        apply_state(&mut regs, state);
        set_regs(self.guard.pid, &regs)
    }

    fn pending_async(&self) -> Result<Vec<i32>, Refuse> {
        // Pending masks are observer-visible in /proc status;
        // this neither dequeues nor delivers anything.
        let text = std::fs::read_to_string(format!("/proc/{}/status", self.guard.pid))
            .map_err(|_| remote_err("read child pending mask"))?;
        let mut mask: u64 = 0;
        for line in text.lines() {
            if let Some(v) = line
                .strip_prefix("SigPnd:")
                .or_else(|| line.strip_prefix("ShdPnd:"))
            {
                mask |= u64::from_str_radix(v.trim(), 16).unwrap_or(0);
            }
        }
        Ok(crate::exec::async_signal_range()
            .filter(|&sig| mask & (1u64 << (sig - 1)) != 0)
            .collect())
    }

    /// Generated-phase fault: recover through the shared core
    /// against the generated PC map. `gen_pc` has already had
    /// the cause-specific breakpoint adjustment applied by the
    /// caller (subtract one only for a proven TRAP_BRKPT).
    /// Ptrace has no REG_ERR, so fetch-provenance address
    /// translation is unavailable on this substrate (err stays
    /// 0); the I1-B fault fixtures are data faults and FPE,
    /// which do not need it.
    fn recovered_stop(
        &self,
        sig: i32,
        si_code: i32,
        addr: u64,
        gen_pc: u64,
        regs: &libc::user_regs_struct,
        data: &JitData,
    ) -> crate::recovery::RecoveredStop {
        let t = self.translation.as_ref().expect("prepared");
        crate::recovery::recover(
            t,
            self.profile,
            RecoveryInput {
                provenance: FaultInput {
                    gen_pc,
                    addr,
                    signum: sig,
                    si_code,
                    err: 0,
                },
                interrupted: regs_to_state(regs),
                saved: data.state,
                spill_rax: data.spill_rax,
                spill_flags: data.spill_flags,
                branches: data.branch_count,
                instructions: data.instruction_count,
                exit_kind: data.exit_kind,
                exit_src: data.exit_src,
            },
        )
    }

    fn fault_from(stop: crate::recovery::RecoveredStop) -> Fault {
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

    /// I1-D admitted delivery shape for `sig`, or `None` when
    /// this stop must keep the pre-I1-D recovered-async
    /// outcome. Registry/translation checks plus the exact
    /// restorer-bytes proof; frame and resume facts are
    /// validated in `deliver_signal`/`sigreturn_resume`.
    /// Every exclusion here is a named stage boundary, not a
    /// silent fallback: frames past the 8-frame cap, signals
    /// outside the admitted sets (including the glibc-reserved
    /// 32/33), flag words beyond `SA_SIGINFO` plus optional
    /// `SA_NODEFER`/`SA_ONSTACK`/`SA_RESTART`, an
    /// enabled altstack below the size floor, synchronous
    /// delivery on a non-empty stack, and handlers outside the
    /// translated block set.
    fn delivery_action(
        &self,
        sig: i32,
        active: &[ActiveFrame],
        synchronous: bool,
    ) -> Option<GuestAction> {
        // Explicit frame-stack cap (I1-F bound) and, in this
        // slice, synchronous delivery only on an empty stack.
        const MAX_ACTIVE_FRAMES: usize = 8;
        if active.len() >= MAX_ACTIVE_FRAMES || (synchronous && !active.is_empty()) {
            return None;
        }
        // Tested sets only: asynchronous delivery admits
        // exactly SIGUSR1/SIGUSR2 (I1-D/I1-F) and the RT range
        // 34..=64 (I1-G1); synchronous fault delivery admits
        // exactly SIGSEGV/SIGFPE at copied insns (I1-E, phase
        // checked by the caller). Broadening either set needs
        // its own witnesses.
        let admitted = if synchronous {
            sig == libc::SIGSEGV || sig == libc::SIGFPE
        } else {
            async_delivery_admitted(sig)
        };
        if !admitted {
            return None;
        }
        let action = self.registry.action(sig);
        if !action.is_custom() || action.restorer == 0 {
            return None;
        }
        // Tested flag words only: the I1-D base plus,
        // independently, SA_NODEFER and/or SA_ONSTACK (I1-F)
        // and SA_RESTART (I1-G2: it only decides whether an
        // interrupted `-ERESTARTSYS` call restarts). Anything
        // else (RESETHAND would stale the mirror when the
        // kernel resets the disposition on delivery; NOCLD*)
        // keeps the stop. sa_mask is arbitrary: the kernel
        // applies it and the mirror retains its readback
        // verbatim.
        let base_flags = SA_RESTORER_FLAG | (libc::SA_SIGINFO as u64);
        let allowed_flags = base_flags
            | (libc::SA_NODEFER as u64)
            | (libc::SA_ONSTACK as u64)
            | (libc::SA_RESTART as u64);
        if action.flags & base_flags != base_flags || action.flags & !allowed_flags != 0 {
            return None;
        }
        // SA_ONSTACK onto an enabled altstack needs the
        // witnessed size floor; onto a disabled altstack the
        // kernel's normal-stack fallback is admitted as-is.
        if action.flags & (libc::SA_ONSTACK as u64) != 0 {
            let alt = self.registry.altstack();
            let enabled = alt.flags & libc::SS_DISABLE == 0;
            if enabled && (alt.sp == 0 || alt.size < 8192) {
                return None;
            }
        }
        let t = self.translation.as_ref()?;
        if !t.block_gen.contains_key(&action.handler) {
            return None;
        }
        // The restorer is the only guest code the sigreturn
        // flow executes untranslated, so its bytes are proven
        // to be exactly the two-instruction sigreturn
        // trampoline here, before injection. Any other shape
        // (extra insns, unreadable) keeps the recovered stop.
        let mut restorer_bytes = [0u8; 7];
        if read_mem(self.guard.pid, action.restorer, &mut restorer_bytes).is_err()
            || restorer_bytes != SIGRETURN_RESTORER
        {
            return None;
        }
        Some(action)
    }

    /// One genuine delivery's front half: rewrite the stopped
    /// tracee to exact recovered source state, inject the
    /// signal so the kernel builds the real frame and enters
    /// the common stub, validate the frame against recovery,
    /// and return the handler-entry source state (kernel
    /// arguments intact, RIP at the source handler) together
    /// with the frames built, bottom first.
    ///
    /// Back-to-back setup (I1-G1): when another signal is
    /// pending and unblocked under the handler-entry mask, the
    /// kernel builds that signal's frame immediately on top,
    /// before the stub ever runs, and reports its delivery
    /// stop with RIP at the stub entry. The frame just built is
    /// validated and recorded exactly as at a stub trap; its
    /// guest-visible handler entry (the source handler, never
    /// the stub address) becomes the interrupted state the next
    /// signal is injected over, so the next frame's ucontext
    /// names the source handler as Linux would natively. An
    /// ineligible next signal is a recovered `AsyncSignal`
    /// stop at that handler entry (no handler insn retired);
    /// any other provenance mismatch once injection starts is
    /// a named substrate refusal with the guest left stopped.
    fn deliver_signal(
        &self,
        action: GuestAction,
        recovered: &crate::recovery::RecoveredStop,
        data: &JitData,
        gen_mid: Option<u64>,
        active: &[ActiveFrame],
    ) -> Result<(GuestState, Vec<ActiveFrame>), RunError> {
        let mut regs = get_regs(self.guard.pid)?;
        apply_state(&mut regs, &recovered.state);
        set_regs(self.guard.pid, &regs)?;
        let stub = self.signal_stub_addr();
        let mut frames: Vec<ActiveFrame> = Vec::new();
        // What the frame about to be built must record: the
        // signal, its action, and the interrupted source PC/RSP
        // (plus the exact mid-block re-entry for the first).
        let (mut sig, mut action) = (recovered.signum, action);
        let (mut resume_src, mut resume_rsp) = (recovered.src_pc, recovered.state.rsp);
        let mut resume_gen_mid = gen_mid;
        self.cont(sig)?;
        loop {
            let status = wait_stop(self.guard.pid)?;
            if !libc::WIFSTOPPED(status) {
                return Err(self.unexpected_stop("signal stub stop provenance"));
            }
            let stop_sig = libc::WSTOPSIG(status);
            let stub_regs = get_regs(self.guard.pid)?;
            let si = stop_siginfo(self.guard.pid, stop_sig);
            let stub_trap = stop_sig == libc::SIGTRAP
                && stub_regs.rip == stub + 1
                && si.is_some_and(|(signo, code, _)| {
                    signo == libc::SIGTRAP && is_breakpoint_cause(code)
                });
            let back_to_back = !stub_trap
                && stub_regs.rip == stub
                && classify_stop(
                    Phase::Generated,
                    stop_sig,
                    status >> 16,
                    si.map(|(signo, code, _)| (signo, code)),
                    false,
                ) == StopClass::Async;
            if !stub_trap && !back_to_back {
                return Err(self.unexpected_stop("signal stub stop provenance"));
            }
            // Either way the kernel has just built `sig`'s frame
            // and set up its handler arguments: validate it.
            let frame_rsp = stub_regs.rsp;
            let uc_addr = stub_regs.rdx;
            let frame_rip = self.read_word(uc_greg_addr(uc_addr, GREG_RIP))?;
            let frame_rsp_word = self.read_word(uc_greg_addr(uc_addr, GREG_RSP))?;
            let pretcode = self.read_word(frame_rsp)?;
            if uc_addr != frame_rsp + 8
                || frame_rip != resume_src
                || frame_rsp_word != resume_rsp
                || pretcode != action.restorer
                || stub_regs.rdi != sig as u64
            {
                return Err(self.unexpected_stop("signal frame state mismatch"));
            }
            frames.push(ActiveFrame {
                restorer: action.restorer,
                frame_rsp,
                uc_addr,
                resume_src_pc: resume_src,
                raw_branches: data.branch_count,
                raw_instructions: data.instruction_count,
                raw_poll: data.poll_remaining,
                resolved_branches: recovered.branches,
                resolved_instructions: recovered.instructions,
                gen_mid: resume_gen_mid,
            });
            let mut handler_state = regs_to_state(&stub_regs);
            handler_state.rip = action.handler;
            if stub_trap {
                return Ok((handler_state, frames));
            }
            // Back-to-back: `stop_sig` interrupts `sig`'s handler
            // before its first instruction. Same eligibility as
            // any async stop, against the stack including every
            // frame built so far.
            let mut stack = active.to_vec();
            stack.extend_from_slice(&frames);
            let Some(next_action) = self.delivery_action(stop_sig, &stack, false) else {
                return Err(RunError::Fault(Box::new(Fault {
                    also_pending: Vec::new(),
                    kind: crate::recovery::FaultKind::AsyncSignal,
                    src_pc: action.handler,
                    addr: si.map_or(0, |s| s.2),
                    signum: stop_sig,
                    state: handler_state,
                    branches: recovered.branches,
                    instructions: recovered.instructions,
                })));
            };
            let mut next_regs = stub_regs;
            next_regs.rip = action.handler;
            set_regs(self.guard.pid, &next_regs)?;
            resume_src = action.handler;
            resume_rsp = frame_rsp;
            resume_gen_mid = None;
            sig = stop_sig;
            action = next_action;
            self.cont(sig)?;
        }
    }

    /// Read the full resume state from a live signal frame's
    /// ucontext gregs (handler mutations included, by design).
    fn frame_resume_state(&self, uc_addr: u64) -> Result<GuestState, Refuse> {
        let g = |greg: u64| self.read_word(uc_greg_addr(uc_addr, greg));
        Ok(GuestState {
            rax: g(GREG_RAX)?,
            rbx: g(GREG_RBX)?,
            rcx: g(GREG_RCX)?,
            rdx: g(GREG_RDX)?,
            rsi: g(GREG_RSI)?,
            rdi: g(GREG_RDI)?,
            rbp: g(GREG_RBP)?,
            rsp: g(GREG_RSP)?,
            r8: g(GREG_R8)?,
            r9: g(GREG_R9)?,
            r10: g(GREG_R10)?,
            r11: g(GREG_R11)?,
            r12: g(GREG_R12)?,
            r13: g(GREG_R13)?,
            r14: g(GREG_R14)?,
            r15: g(GREG_R15)?,
            rflags: g(GREG_EFLAGS)?,
            rip: g(GREG_RIP)?,
        })
    }

    /// Back half of the round trip, entered at the translated
    /// handler's return exit (`handler_state` is the common
    /// exit's saved state, RSP still at the frame): read the
    /// resume state from the frame, require a block start
    /// there (mid-block splitting is I1-E), rewrite only the
    /// frame resume RIP to that block's generated entry, and
    /// execute the guest restorer's `rt_sigreturn` genuinely
    /// under syscall stops. Returns the resume source state;
    /// the dispatcher loop re-enters it through the normal
    /// JitData write, so no generated code runs on stale data.
    /// The restorer's two retired instructions (`mov` +
    /// `syscall`) are credited by the caller: they are guest
    /// code the kernel really executed.
    /// Returns the resume source state plus the one-shot
    /// generated-entry override for an exact mid-block
    /// re-entry (`None` = normal block-start entry).
    fn sigreturn_resume(
        &self,
        registry: &mut SignalRegistry,
        frame: &ActiveFrame,
        handler_state: &GuestState,
    ) -> Result<(GuestState, Option<u64>), RunError> {
        let t = self.translation.as_ref().expect("prepared");
        let resume = self.frame_resume_state(frame.uc_addr)?;
        // Disposition changes under a live frame (I1-F)
        // affect future deliveries only; this frame's
        // recorded restorer stays authoritative for its pop.
        // Re-prove the exact restorer shape at resume time:
        // admission-time proof alone would credit +2 to
        // whatever the handler left at the restorer address.
        let mut restorer_now = [0u8; 7];
        if read_mem(self.guard.pid, frame.restorer, &mut restorer_now).is_err()
            || restorer_now != SIGRETURN_RESTORER
        {
            return Err(self.unexpected_stop("restorer shape changed under live frame"));
        }
        // Block-start resume (including a handler-mutated RIP
        // that lands on a block start) re-enters through the
        // normal dispatcher credit path. Mid-block resume is
        // admitted only at the exact interrupted insn, whose
        // block precredit is already in the raw totals the
        // caller re-bases onto; a mutated mid-block RIP would
        // miscount the skipped prefix and fails closed.
        let (gen_entry, gen_override) = if let Some(&gpc) = t.block_gen.get(&resume.rip) {
            (gpc, None)
        } else if resume.rip == frame.resume_src_pc {
            match frame.gen_mid {
                Some(gpc) => (gpc, Some(gpc)),
                None => {
                    return Err(self.unexpected_stop("sigreturn resume has no exact re-entry"));
                }
            }
        } else {
            return Err(self.unexpected_stop("sigreturn resume PC mutated off block start"));
        };
        write_mem(
            self.guard.pid,
            uc_greg_addr(frame.uc_addr, GREG_RIP),
            &gen_entry.to_le_bytes(),
        )?;
        if self.read_word(uc_greg_addr(frame.uc_addr, GREG_RIP))? != gen_entry {
            return Err(self.unexpected_stop("sigreturn frame rewrite"));
        }
        let mut regs = get_regs(self.guard.pid)?;
        apply_state(&mut regs, handler_state);
        regs.rip = frame.restorer;
        regs.rsp = frame.frame_rsp + 8;
        set_regs(self.guard.pid, &regs)?;
        for phase in [Phase::SyscallEntry, Phase::SyscallExit] {
            ptrace_ok(
                libc::PTRACE_SYSCALL,
                self.guard.pid,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                "PTRACE_SYSCALL sigreturn",
            )?;
            let status = wait_stop(self.guard.pid)?;
            if !libc::WIFSTOPPED(status) {
                return Err(Refuse::RemoteSubstrate {
                    operation: "remote guest ended during sigreturn",
                    errno: 0,
                }
                .into());
            }
            let sig = libc::WSTOPSIG(status);
            let si = stop_siginfo(self.guard.pid, sig);
            if classify_stop(
                phase,
                sig,
                status >> 16,
                si.map(|(signo, code, _)| (signo, code)),
                false,
            ) != StopClass::SyscallStop
            {
                return Err(self.unexpected_stop("sigreturn stop provenance"));
            }
            if phase == Phase::SyscallEntry {
                let entry = get_regs(self.guard.pid)?;
                if entry.orig_rax != libc::SYS_rt_sigreturn as u64 {
                    return Err(self.unexpected_stop("restorer did not enter rt_sigreturn"));
                }
            }
        }
        let restored = get_regs(self.guard.pid)?;
        let mut expected = resume;
        expected.rip = gen_entry;
        let got = regs_to_state(&restored);
        // Full GPR equality against the frame; flags compare
        // only guest-visible status/DF bits (the kernel
        // sanitizes privilege-adjacent flag bits on restore).
        const FLAG_CMP: u64 = 0x8d5 | 0x400;
        let gprs_match = got.rax == expected.rax
            && got.rbx == expected.rbx
            && got.rcx == expected.rcx
            && got.rdx == expected.rdx
            && got.rsi == expected.rsi
            && got.rdi == expected.rdi
            && got.rbp == expected.rbp
            && got.rsp == expected.rsp
            && got.r8 == expected.r8
            && got.r9 == expected.r9
            && got.r10 == expected.r10
            && got.r11 == expected.r11
            && got.r12 == expected.r12
            && got.r13 == expected.r13
            && got.r14 == expected.r14
            && got.r15 == expected.r15
            && got.rip == expected.rip;
        if !gprs_match || got.rflags & FLAG_CMP != expected.rflags & FLAG_CMP {
            return Err(self.unexpected_stop("sigreturn restored state mismatch"));
        }
        // The kernel restored the pre-delivery mask from the
        // frame; re-mirror it from authoritative readback.
        let mask = read_sigblk(self.guard.pid)?;
        registry.set_mask(mask);
        Ok((resume, gen_override))
    }

    /// Original-phase stop: exact source state at `src_pc`,
    /// never a generated-map lookup. The stepped instruction
    /// has not retired, so instruction credit is the exact
    /// retired-before total for its block; branches stand as
    /// credited at the preceding exit trap.
    fn source_fault(
        &self,
        class: StopClass,
        sig: i32,
        addr: u64,
        src_pc: u64,
        regs: &libc::user_regs_struct,
        data: &JitData,
    ) -> Fault {
        let t = self.translation.as_ref().expect("prepared");
        let mut state = regs_to_state(regs);
        state.rip = src_pc;
        Fault {
            also_pending: Vec::new(),
            kind: if class == StopClass::Async {
                crate::recovery::FaultKind::AsyncSignal
            } else {
                crate::recovery::FaultKind::GuestFault
            },
            src_pc,
            addr,
            signum: sig,
            state,
            branches: data.branch_count,
            instructions: crate::recovery::instructions_retired_at(
                t,
                self.profile,
                data.instruction_count,
                src_pc,
            ),
        }
    }

    fn unexpected_stop(&self, operation: &'static str) -> RunError {
        Refuse::RemoteSubstrate {
            operation,
            errno: 0,
        }
        .into()
    }

    /// Single-step one original instruction at `pc` in the child
    /// (nondet pass-through). Returns the resulting guest state.
    fn step_original(
        &self,
        mut state: GuestState,
        pc: u64,
        data: &JitData,
    ) -> Result<GuestState, RunError> {
        state.rip = pc;
        self.set_guest_regs(&state)?;
        #[cfg(feature = "test-seams")]
        if let Some(sig) = self.pre_original_step_signal {
            // SAFETY: signalling this tracer's own traced child.
            if unsafe { libc::kill(self.guard.pid, sig) } != 0 {
                return Err(remote_err("test pre-original-step signal").into());
            }
        }
        ptrace_ok(
            libc::PTRACE_SINGLESTEP,
            self.guard.pid,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            "PTRACE_SINGLESTEP",
        )?;
        let status = wait_stop(self.guard.pid)?;
        if !libc::WIFSTOPPED(status) {
            return Err(Refuse::RemoteSubstrate {
                operation: "remote guest ended during step",
                errno: 0,
            }
            .into());
        }
        let regs = get_regs(self.guard.pid)?;
        let sig = libc::WSTOPSIG(status);
        let si = stop_siginfo(self.guard.pid, sig);
        match classify_stop(
            Phase::OriginalStep,
            sig,
            status >> 16,
            si.map(|(signo, code, _)| (signo, code)),
            false,
        ) {
            StopClass::StepComplete => Ok(regs_to_state(&regs)),
            class @ (StopClass::Async | StopClass::SourceFault) => Err(RunError::Fault(Box::new(
                self.source_fault(class, sig, si.map_or(0, |s| s.2), pc, &regs, data),
            ))),
            _ => Err(self.unexpected_stop("unexpected original-step stop provenance")),
        }
    }

    /// Execute one genuine guest syscall at `pc` via
    /// PTRACE_SYSCALL entry/exit stops. Returns the resulting
    /// guest state (kernel-produced clobbers included). An
    /// interrupted call (restart code at the exit stop) fails
    /// closed by name here; only the I1-G2 pass-through arm
    /// handles it, through `step_syscall_or_interrupt`.
    fn step_syscall(
        &self,
        state: GuestState,
        pc: u64,
        data: &JitData,
    ) -> Result<GuestState, RunError> {
        match self.step_syscall_or_interrupt(state, pc, data)? {
            Stepped::Done(s) => Ok(s),
            Stepped::Interrupted(_) => {
                Err(self.unexpected_stop("syscall restart pending at exit stop"))
            }
        }
    }

    /// `step_syscall`, but an exit stop whose result is a
    /// kernel restart code returns `Stepped::Interrupted` with
    /// the child still at that stop: a signal interrupted the
    /// call in the kernel, which has not yet decided between
    /// restarting it and `-EINTR`. Nothing is credited.
    fn step_syscall_or_interrupt(
        &self,
        mut state: GuestState,
        pc: u64,
        data: &JitData,
    ) -> Result<Stepped, RunError> {
        state.rip = pc;
        self.set_guest_regs(&state)?;
        for phase in [Phase::SyscallEntry, Phase::SyscallExit] {
            ptrace_ok(
                libc::PTRACE_SYSCALL,
                self.guard.pid,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                "PTRACE_SYSCALL",
            )?;
            let status = wait_stop(self.guard.pid)?;
            if !libc::WIFSTOPPED(status) {
                return Err(Refuse::RemoteSubstrate {
                    operation: "remote guest ended during syscall",
                    errno: 0,
                }
                .into());
            }
            let sig = libc::WSTOPSIG(status);
            let si = stop_siginfo(self.guard.pid, sig);
            match classify_stop(
                phase,
                sig,
                status >> 16,
                si.map(|(signo, code, _)| (signo, code)),
                false,
            ) {
                StopClass::SyscallStop => {}
                class @ (StopClass::Async | StopClass::SourceFault) => {
                    let regs = get_regs(self.guard.pid)?;
                    return Err(RunError::Fault(Box::new(self.source_fault(
                        class,
                        sig,
                        si.map_or(0, |s| s.2),
                        pc,
                        &regs,
                        data,
                    ))));
                }
                _ => return Err(self.unexpected_stop("unexpected syscall stop provenance")),
            }
        }
        // A syscall-exit stop whose result is a kernel restart
        // code is not completion: a signal interrupted the
        // syscall in the kernel and it would restart on resume.
        // Never credit it, never translate it into an async
        // fault, and never resume the child on presumed
        // completion: the caller either delivers the signal
        // (I1-G2) or fails closed.
        let regs = get_regs(self.guard.pid)?;
        if is_syscall_restart(regs.rax) {
            return Ok(Stepped::Interrupted(regs));
        }
        Ok(Stepped::Done(regs_to_state(&regs)))
    }

    /// I1-G2: deliver the signal that interrupted the syscall
    /// at `pc`, from its exit stop (`regs`, result a restart
    /// code). The child resumes once and must stop for the
    /// interrupting signal with the restart code intact; that
    /// signal must be eligible for delivery, or the run stops
    /// by name without injecting anything (no transparent
    /// no-handler restart, no `restart_syscall`). It is
    /// injected with RAX still holding the restart code, so the
    /// kernel's `handle_signal` applies the restart rule itself:
    /// `-ERESTARTNOHAND`/`-ERESTART_RESTARTBLOCK` become
    /// `-EINTR`, `-ERESTARTSYS` restarts only under
    /// `SA_RESTART`. The tracer predicts the outcome and the
    /// frame must match it: ucontext RIP at the syscall (restart)
    /// or after it (`-EINTR`), ucontext RAX the syscall number
    /// or `-EINTR`. A `-EINTR` completion credits the syscall
    /// instruction once (returned as `credit`); a restarted
    /// attempt is not credited, and its frame resumes at the
    /// syscall through the existing exact re-entry (the exit
    /// stub's pristine entry, counters exact) so the call steps
    /// again after the handler.
    fn deliver_at_syscall_exit(
        &self,
        regs: libc::user_regs_struct,
        pc: u64,
        data: &JitData,
        active: &[ActiveFrame],
    ) -> Result<(GuestState, Vec<ActiveFrame>, u64), RunError> {
        let t = self.translation.as_ref().expect("prepared");
        let code = regs.rax as i64;
        let nr = regs.orig_rax;
        // PTRACE_SYSCALL, not CONT: if no signal were pending,
        // the kernel's no-handler restart must stop at the next
        // syscall entry instead of running the guest.
        ptrace_ok(
            libc::PTRACE_SYSCALL,
            self.guard.pid,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            "PTRACE_SYSCALL restart",
        )?;
        let status = wait_stop(self.guard.pid)?;
        if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) == (libc::SIGTRAP | 0x80) {
            return Err(self.unexpected_stop("syscall restart without a delivery stop"));
        }
        let sig = libc::WSTOPSIG(status);
        let si = stop_siginfo(self.guard.pid, sig);
        let stop = get_regs(self.guard.pid)?;
        let async_stop =
            status >> 16 == 0 && si.is_some_and(|(signo, si_code, _)| signo == sig && si_code <= 0);
        if !async_stop || stop.rip != pc + 2 || stop.rax != regs.rax || stop.orig_rax != nr {
            return Err(self.unexpected_stop("syscall restart stop provenance"));
        }
        let Some(action) = self.delivery_action(sig, active, false) else {
            return Err(self.unexpected_stop("syscall restart: signal not eligible for delivery"));
        };
        let restart = match code {
            ERESTARTSYS => action.flags & (libc::SA_RESTART as u64) != 0,
            ERESTARTNOHAND | ERESTART_RESTARTBLOCK => false,
            // Always restarts, even with a handler; no admitted
            // syscall produces it.
            ERESTARTNOINTR => {
                return Err(self.unexpected_stop("syscall restart code not admitted"));
            }
            _ => return Err(self.unexpected_stop("syscall restart code unknown")),
        };
        let eintr = (-(libc::EINTR as i64)) as u64;
        let (resume_pc, uc_rax) = if restart { (pc, nr) } else { (pc + 2, eintr) };
        let gen_mid = if restart && !t.block_gen.contains_key(&pc) {
            let Some(gpc) = gen_for_midblock(t, pc) else {
                return Err(self.unexpected_stop("syscall restart has no exact re-entry"));
            };
            Some(gpc)
        } else {
            None
        };
        let credit = u64::from(!restart);
        let recovered = crate::recovery::RecoveredStop {
            kind: crate::recovery::FaultKind::AsyncSignal,
            src_pc: resume_pc,
            addr: si.map_or(0, |s| s.2),
            signum: sig,
            state: regs_to_state(&stop),
            branches: data.branch_count,
            instructions: data.instruction_count + credit,
        };
        let (handler_state, frames) =
            self.deliver_signal(action, &recovered, data, gen_mid, active)?;
        if self.read_word(uc_greg_addr(frames[0].uc_addr, GREG_RAX))? != uc_rax {
            return Err(self.unexpected_stop("syscall restart frame state mismatch"));
        }
        Ok((handler_state, frames, credit))
    }

    /// Run from `state.rip` until a return pops
    /// `return_sentinel`, a named refusal, or a fault — the
    /// remote mirror of the in-process dispatcher loop, with
    /// pass-through stepping in place of handler emulation.
    pub fn run(
        &mut self,
        mut state: GuestState,
        return_sentinel: u64,
    ) -> Result<Outcome, RunError> {
        let Some(t) = self.translation.as_ref() else {
            return Err(Refuse::Arch {
                what: "remote executable not prepared",
            }
            .into());
        };
        let mut exits: u64 = 0;
        let (mut tot_branches, mut tot_instructions) = (0u64, 0u64);
        let mut poll_remaining = self.poll_budget();
        let mut active: Vec<ActiveFrame> = Vec::new();
        let mut pending_gen: Option<u64> = None;
        #[cfg(feature = "test-seams")]
        let _debug_regs = self.arm_arrival()?;
        loop {
            // A mid-block sigreturn resume supplies its exact
            // generated entry once; every other entry resolves
            // through the block index.
            let gen_entry = match pending_gen.take() {
                Some(gpc) => gpc,
                None => {
                    let Some(&gpc) = t.block_gen.get(&state.rip) else {
                        return Err(Refuse::IndirectUnresolved { src_pc: state.rip }.into());
                    };
                    gpc
                }
            };
            let mut fresh = JitData::new(state);
            fresh.branch_count = tot_branches;
            fresh.instruction_count = tot_instructions;
            fresh.poll_remaining = poll_remaining;
            self.write_jit_data(&fresh)?;
            // The guest state written by the common exit is the
            // source-PC state; only the register RIP is generated.
            let mut entry_state = state;
            entry_state.rip = gen_entry;
            self.set_guest_regs(&entry_state)?;
            self.cont(0)?;
            let status = wait_stop(self.guard.pid)?;
            #[cfg(feature = "test-seams")]
            let status = self.filter_arrival_stops(status)?;
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.guard.reaped = true;
                return Err(Refuse::RemoteSubstrate {
                    operation: "remote guest ended during run",
                    errno: 0,
                }
                .into());
            }
            if !libc::WIFSTOPPED(status) {
                return Err(Refuse::RemoteSubstrate {
                    operation: "remote guest wait state",
                    errno: 0,
                }
                .into());
            }
            let sig = libc::WSTOPSIG(status);
            let regs = get_regs(self.guard.pid)?;
            let data = self.read_jit_data()?;
            let si = stop_siginfo(self.guard.pid, sig);
            // Exact exit-trap proof: the byte before the stopped
            // RIP is itself the final AllSaved common-exit
            // segment (complete save by construction), not
            // merely somewhere inside the common-exit recipe.
            let exact_exit_trap = t.pcmap.lookup(regs.rip.saturating_sub(1)).is_some_and(|e| {
                e.gen_start == regs.rip.saturating_sub(1)
                    && matches!(
                        e.recovery,
                        MapRecovery::CommonExit {
                            stage: CommonStage::AllSaved
                        }
                    )
            });
            match classify_stop(
                Phase::Generated,
                sig,
                status >> 16,
                si.map(|(signo, code, _)| (signo, code)),
                exact_exit_trap,
            ) {
                StopClass::ExitTrap => {}
                StopClass::Async => {
                    let (si_code, addr) = si.map_or((0, 0), |(_, c, a)| (c, a));
                    let gen_pc = if sig == libc::SIGTRAP && is_breakpoint_cause(si_code) {
                        regs.rip.saturating_sub(1)
                    } else {
                        regs.rip
                    };
                    let recovered = self.recovered_stop(sig, si_code, addr, gen_pc, &regs, &data);
                    // I1-E: block-start recovery resumes through
                    // the block index; any other recovered PC
                    // needs an exact mid-block generated
                    // re-entry. Common-exit machinery stops
                    // and unmapped generated PCs are excluded
                    // by `resume_gen` and keep the outcome below.
                    let resume = resume_gen(t, gen_pc, recovered.src_pc);
                    let gen_mid = resume.unwrap_or_default();
                    let resumable = resume.is_some();
                    let action = self.delivery_action(sig, &active, false).filter(|_| {
                        recovered.kind == crate::recovery::FaultKind::AsyncSignal && resumable
                    });
                    if let Some(action) = action {
                        #[cfg(feature = "test-seams")]
                        self.record_seam_delivery(sig, gen_pc, &recovered);
                        let (handler_state, frames) =
                            self.deliver_signal(action, &recovered, &data, gen_mid, &active)?;
                        active.extend(frames);
                        state = handler_state;
                        exits += 1;
                        poll_remaining = data.poll_remaining;
                        tot_branches = recovered.branches;
                        tot_instructions = recovered.instructions;
                        continue;
                    }
                    return Err(RunError::Fault(Box::new(Self::fault_from(recovered))));
                }
                StopClass::GeneratedFault => {
                    let (si_code, addr) = si.map_or((0, 0), |(_, c, a)| (c, a));
                    let gen_pc = if sig == libc::SIGTRAP && is_breakpoint_cause(si_code) {
                        regs.rip.saturating_sub(1)
                    } else {
                        regs.rip
                    };
                    // I1-E synchronous delivery: guest faults
                    // (never executor/machinery faults) at
                    // copied insns with an exact resume entry
                    // go through the same genuine frame flow;
                    // instruction-address siginfo is first
                    // rewritten to source form so the kernel
                    // frame the handler sees is source-faithful.
                    let recovered = self.recovered_stop(sig, si_code, addr, gen_pc, &regs, &data);
                    let copied_fault = t
                        .pcmap
                        .lookup(gen_pc)
                        .is_some_and(|e| e.phase == MapPhase::Copied);
                    let gen_mid = if t.block_gen.contains_key(&recovered.src_pc) {
                        None
                    } else {
                        gen_for_midblock(t, recovered.src_pc)
                    };
                    let resumable =
                        t.block_gen.contains_key(&recovered.src_pc) || gen_mid.is_some();
                    let action = self.delivery_action(sig, &active, true).filter(|_| {
                        recovered.kind == crate::recovery::FaultKind::GuestFault
                            && copied_fault
                            && resumable
                    });
                    if let Some(action) = action {
                        if recovered.addr != addr {
                            set_siginfo_addr(self.guard.pid, recovered.addr)?;
                        }
                        #[cfg(feature = "test-seams")]
                        self.record_seam_delivery(sig, gen_pc, &recovered);
                        let (handler_state, frames) =
                            self.deliver_signal(action, &recovered, &data, gen_mid, &active)?;
                        active.extend(frames);
                        state = handler_state;
                        exits += 1;
                        poll_remaining = data.poll_remaining;
                        tot_branches = recovered.branches;
                        tot_instructions = recovered.instructions;
                        continue;
                    }
                    return Err(RunError::Fault(Box::new(Self::fault_from(recovered))));
                }
                _ => return Err(self.unexpected_stop("unexpected generated stop provenance")),
            }
            state = data.state;
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
                    let mut buf = [0u8; 8];
                    if read_mem(self.guard.pid, state.rsp, &mut buf).is_err() {
                        state.rip = data.exit_src;
                        return Err(RunError::Fault(Box::new(Fault {
                            also_pending: Vec::new(),
                            kind: crate::recovery::FaultKind::GuestFault,
                            src_pc: data.exit_src,
                            addr: state.rsp,
                            signum: libc::SIGSEGV,
                            state,
                            branches: data.branch_count,
                            instructions: crate::recovery::instructions_retired_at(
                                t,
                                self.profile,
                                data.instruction_count,
                                data.exit_src,
                            ),
                        })));
                    }
                    let target = u64::from_ne_bytes(buf);
                    // Handler return to the frame restorer is
                    // the sigreturn interception point, proven
                    // by target, exact frame RSP, and a plain
                    // `ret` (no imm16 pop).
                    if let Some(frame) = active.last().copied()
                        && target == frame.restorer
                        && state.rsp == frame.frame_rsp
                        && data.exit_next == 0
                    {
                        let mut registry = std::mem::take(&mut self.registry);
                        let resumed = self.sigreturn_resume(&mut registry, &frame, &state);
                        self.registry = registry;
                        let (resume_state, gen_override) = resumed?;
                        active.pop();
                        state = resume_state;
                        if let Some(gpc) = gen_override {
                            // Mid-block re-entry: the block's
                            // precredit is already inside the
                            // raw totals, so re-base the handler
                            // delta onto them (no double credit,
                            // no lost credit) and restore the
                            // interrupted poll budget.
                            tot_branches =
                                frame.raw_branches + (tot_branches - frame.resolved_branches);
                            tot_instructions = frame.raw_instructions
                                + (tot_instructions - frame.resolved_instructions);
                            poll_remaining = frame.raw_poll;
                            pending_gen = Some(gpc);
                        }
                        tot_instructions += 2;
                        continue;
                    }
                    state.rsp = state.rsp.wrapping_add(8).wrapping_add(data.exit_next);
                    state.rip = target;
                    if target == return_sentinel {
                        let mut out = done;
                        out.state = state;
                        return Ok(out);
                    }
                }
                exit_kind::POLL => {
                    // Delivery happens only from ptrace
                    // signal-delivery stops. An eligible
                    // UNBLOCKED pending signal observed here is
                    // therefore deferred one entry: re-entering
                    // the cache makes the kernel present its
                    // delivery stop at the block head, where the
                    // Async arm delivers it. A pending signal the
                    // MIRROR shows as blocked is not an event:
                    // natively it just stays pending until the
                    // guest unblocks it, and the kernel then
                    // presents it (the I1-F unblock path), so it
                    // does not stop the run here. An ineligible
                    // pending signal the mirror shows as
                    // unblocked keeps the recovered stop. Known
                    // limit (I1-H W5, closed in H2): the mirror
                    // is not refreshed at handler entry, so a
                    // signal blocked only by a running handler's
                    // `sa_mask` (or its own signal without
                    // `SA_NODEFER`) reads as unblocked here and,
                    // if ineligible, still stops the run early.
                    state.rip = data.exit_src;
                    let pending = self.pending_async()?;
                    let unblocked: Vec<i32> = pending
                        .iter()
                        .copied()
                        .filter(|&sig| !self.registry.is_blocked(sig))
                        .collect();
                    // The kernel presents the lowest-numbered
                    // UNBLOCKED pending signal first, so any
                    // eligible unblocked pending entry defers,
                    // even behind a blocked lower signal.
                    let defer = unblocked
                        .iter()
                        .any(|&sig| self.delivery_action(sig, &active, false).is_some());
                    if !defer && let Some(&sig) = unblocked.first() {
                        return Err(RunError::Fault(Box::new(Fault {
                            also_pending: pending.iter().copied().filter(|&s| s != sig).collect(),
                            kind: crate::recovery::FaultKind::AsyncSignal,
                            src_pc: data.exit_src,
                            addr: 0,
                            signum: sig,
                            state,
                            branches: done.branches,
                            instructions: done.instructions,
                        })));
                    }
                    poll_remaining = self.poll_budget();
                }
                exit_kind::INDIRECT => {
                    return Err(Refuse::IndirectUnresolved {
                        src_pc: data.exit_src,
                    }
                    .into());
                }
                exit_kind::SYSCALL => {
                    state.rip = data.exit_src;
                    syscall_guard(t, data.exit_src, state.rax)?;
                    if !PASS_THROUGH_SYSCALLS.contains(&(state.rax as u32)) {
                        return Err(Refuse::NoHandler {
                            src_pc: data.exit_src,
                        }
                        .into());
                    }
                    // Self-send bound: kill may target only
                    // the traced child's own pid in this stage.
                    if state.rax as u32 == libc::SYS_kill as u32
                        && state.rdi != self.guard.pid as u64
                    {
                        return Err(Refuse::NoHandler {
                            src_pc: data.exit_src,
                        }
                        .into());
                    }
                    // futex bound (I1-G2): FUTEX_WAIT_PRIVATE
                    // with a NULL timeout only, full words.
                    if state.rax as u32 == libc::SYS_futex as u32
                        && (state.rsi != FUTEX_WAIT_PRIVATE || state.r10 != 0)
                    {
                        return Err(Refuse::NoHandler {
                            src_pc: data.exit_src,
                        }
                        .into());
                    }
                    // Step the call genuinely whatever its
                    // arguments point at, then reconcile the
                    // mirror from post-call kernel readback —
                    // a copy-out failure after a real mutation
                    // is a genuine guest completion here, not
                    // an observer refusal, and the mirror still
                    // follows it. `rt_sigaction` additionally
                    // stubs custom handlers through scratch
                    // (I1-D) and virtualizes the old action.
                    // Same low-32 syscall-number classification
                    // as admission (`syscall_guard` and the
                    // pass-through list): a high-32 alias like
                    // 0x1_0000000d is rt_sigaction to the kernel
                    // and must take the stubbing path too.
                    if state.rax as u32 == libc::SYS_rt_sigaction as u32 {
                        let step = self.prepare_sigaction_step(&state)?;
                        state = match (step.step_rsi, step.saved_scratch) {
                            (Some(rsi), Some(saved)) => self.step_redirected_syscall(
                                state,
                                ArgReg::Rsi,
                                rsi,
                                &saved,
                                data.exit_src,
                                &data,
                            )?,
                            _ => self.step_syscall(state, data.exit_src, &data)?,
                        };
                        let step_rax = state.rax;
                        let mut registry = std::mem::take(&mut self.registry);
                        let finished = self.finish_sigaction_step(
                            &mut registry,
                            &step,
                            step_rax,
                            data.exit_src,
                        );
                        self.registry = registry;
                        finished?;
                    } else if state.rax as u32 == libc::SYS_rt_sigqueueinfo as u32
                        || state.rax as u32 == libc::SYS_rt_tgsigqueueinfo as u32
                    {
                        let step = self.prepare_sigqueue_step(&state, data.exit_src)?;
                        let reg = if step.tg { ArgReg::R10 } else { ArgReg::Rdx };
                        state = self.step_redirected_syscall(
                            state,
                            reg,
                            step.staged,
                            &step.saved,
                            data.exit_src,
                            &data,
                        )?;
                        // A kernel-refused call (forged code to a
                        // foreign target, or own TID with a foreign
                        // TGID) stepped only on the kernel's
                        // documented refusal; an accepted one means
                        // the model is wrong and fails closed by
                        // name.
                        if step.kernel_refuses && (state.rax as i64) >= 0 {
                            return Err(self.unexpected_stop("kernel accepted forged sigqueue"));
                        }
                    } else {
                        let obs = self.observe_syscall_entry(state.rax as u32, &state);
                        match self.step_syscall_or_interrupt(state, data.exit_src, &data)? {
                            Stepped::Done(s) => state = s,
                            Stepped::Interrupted(regs)
                                if !RESTART_DELIVERY_SYSCALLS.contains(&(regs.orig_rax as u32)) =>
                            {
                                return Err(
                                    self.unexpected_stop("syscall restart pending at exit stop")
                                );
                            }
                            Stepped::Interrupted(regs) => {
                                // I1-G2: deliver the interrupting
                                // signal at the syscall exit; the
                                // credit is 1 for -EINTR, 0 for a
                                // restart (the call steps again).
                                let (handler_state, frames, credit) = self
                                    .deliver_at_syscall_exit(regs, data.exit_src, &data, &active)?;
                                active.extend(frames);
                                state = handler_state;
                                exits += 1;
                                tot_instructions += credit;
                                continue;
                            }
                        }
                        let pid = self.guard.pid;
                        let da = self.data_addr();
                        Self::reconcile_registry(&mut self.registry, pid, da, &obs, data.exit_src)?;
                    }
                    tot_instructions += 1;
                }
                exit_kind::NONDET => {
                    state.rip = data.exit_src;
                    let kind = t.blocks.values().find_map(|b| match &b.term {
                        Some(term) if term.pc == data.exit_src => match term.class {
                            InsnClass::Nondet(k) => Some(k),
                            _ => None,
                        },
                        _ => None,
                    });
                    if kind != Some(NondetKind::Cpuid) {
                        return Err(Refuse::NoHandler {
                            src_pc: data.exit_src,
                        }
                        .into());
                    }
                    state = self.step_original(state, data.exit_src, &data)?;
                    tot_instructions += 1;
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
mod tests {
    use super::*;

    fn class(phase: Phase, sig: i32, si: Option<(i32, i32)>, exact: bool) -> StopClass {
        classify_stop(phase, sig, 0, si, exact)
    }

    #[test]
    fn stop_classification_requires_proven_cause() {
        let user_trap = Some((libc::SIGTRAP, 0)); // SI_USER via kill
        let tkill_trap = Some((libc::SIGTRAP, -6)); // SI_TKILL
        let brk = Some((libc::SIGTRAP, TRAP_BRKPT));
        let trace = Some((libc::SIGTRAP, TRAP_TRACE));
        let user_usr1 = Some((libc::SIGUSR1, 0));
        let kern_segv = Some((libc::SIGSEGV, 1));
        // Genuine user SIGTRAP is asynchronous in every phase
        // that can establish its state; never an exit or a step.
        assert_eq!(
            class(Phase::Generated, libc::SIGTRAP, user_trap, true),
            StopClass::Async
        );
        assert_eq!(
            class(Phase::Generated, libc::SIGTRAP, tkill_trap, true),
            StopClass::Async
        );
        assert_eq!(
            class(Phase::OriginalStep, libc::SIGTRAP, user_trap, false),
            StopClass::Async
        );
        assert_eq!(
            class(Phase::SyscallEntry, libc::SIGTRAP, user_trap, false),
            StopClass::Async
        );
        assert_eq!(
            class(Phase::SyscallExit, libc::SIGTRAP, user_trap, false),
            StopClass::Unexpected
        );
        // Breakpoint traps need the exact final-byte proof.
        assert_eq!(
            class(Phase::Generated, libc::SIGTRAP, brk, true),
            StopClass::ExitTrap
        );
        assert_eq!(
            class(
                Phase::Generated,
                libc::SIGTRAP,
                Some((libc::SIGTRAP, SI_KERNEL)),
                true
            ),
            StopClass::ExitTrap
        );
        assert_eq!(
            class(Phase::Generated, libc::SIGTRAP, brk, false),
            StopClass::GeneratedFault
        );
        assert_eq!(
            class(Phase::OriginalStep, libc::SIGTRAP, brk, false),
            StopClass::SourceFault
        );
        // Step completion requires TRAP_TRACE in the step phase.
        assert_eq!(
            class(Phase::OriginalStep, libc::SIGTRAP, trace, false),
            StopClass::StepComplete
        );
        assert_eq!(
            class(Phase::Generated, libc::SIGTRAP, trace, false),
            StopClass::Unexpected
        );
        assert_eq!(
            class(Phase::SyscallEntry, libc::SIGTRAP, trace, false),
            StopClass::Unexpected
        );
        // Syscall stops are phase-bound; async at entry is exact,
        // async at exit cannot establish completion.
        assert_eq!(
            class(Phase::SyscallEntry, libc::SIGTRAP | 0x80, None, false),
            StopClass::SyscallStop
        );
        assert_eq!(
            class(Phase::SyscallExit, libc::SIGTRAP | 0x80, None, false),
            StopClass::SyscallStop
        );
        assert_eq!(
            class(Phase::Generated, libc::SIGTRAP | 0x80, None, false),
            StopClass::Unexpected
        );
        assert_eq!(
            class(Phase::SyscallEntry, libc::SIGUSR1, user_usr1, false),
            StopClass::Async
        );
        assert_eq!(
            class(Phase::SyscallExit, libc::SIGUSR1, user_usr1, false),
            StopClass::Unexpected
        );
        // Kernel faults split by executing address space.
        assert_eq!(
            class(Phase::Generated, libc::SIGSEGV, kern_segv, false),
            StopClass::GeneratedFault
        );
        assert_eq!(
            class(Phase::OriginalStep, libc::SIGSEGV, kern_segv, false),
            StopClass::SourceFault
        );
        assert_eq!(
            class(Phase::SyscallEntry, libc::SIGSEGV, kern_segv, false),
            StopClass::SourceFault
        );
        // No siginfo, mismatched signo, or a ptrace event fails closed.
        assert_eq!(
            class(Phase::Generated, libc::SIGUSR1, None, false),
            StopClass::Unexpected
        );
        assert_eq!(
            class(
                Phase::Generated,
                libc::SIGUSR1,
                Some((libc::SIGUSR2, 0)),
                false
            ),
            StopClass::Unexpected
        );
        assert_eq!(
            classify_stop(Phase::Generated, libc::SIGUSR1, 1, user_usr1, false),
            StopClass::Unexpected
        );
    }

    #[test]
    fn registry_mirror_retains_full_kernel_words() {
        // Readback setters record exactly what the kernel
        // reported, for every disposition: a Default action
        // with nonzero flags/restorer/mask words round-trips
        // instead of collapsing to a unit variant.
        let mut reg = SignalRegistry::default();
        assert!(reg.action(libc::SIGUSR1).is_default());
        let full = GuestAction {
            handler: 0,
            flags: 0x0400_0004,
            restorer: 0x401008,
            sa_mask: 0x800,
        };
        reg.set_action(libc::SIGUSR1, full);
        assert_eq!(reg.action(libc::SIGUSR1), full);
        assert!(reg.action(libc::SIGUSR1).is_default());
        reg.set_action(libc::SIGUSR1, GuestAction { handler: 1, ..full });
        assert!(reg.action(libc::SIGUSR1).is_ignore());
        assert_eq!(reg.action(libc::SIGUSR1).flags, 0x0400_0004);
        reg.set_mask(0x1800_0000_0000_0a00);
        assert_eq!(reg.mask(), 0x1800_0000_0000_0a00);
        reg.set_altstack(GuestAltstack {
            sp: 0x500000,
            flags: 0,
            size: 8192,
        });
        assert_eq!(reg.altstack().sp, 0x500000);
        // Out-of-range signals are never recorded.
        reg.set_action(0, full);
        reg.set_action(65, full);
        assert_eq!(reg.action(0), GuestAction::default());
    }

    #[test]
    fn stub_readback_maps_only_on_proven_install() {
        let stub = 0x7000_0000u64;
        let prev = GuestAction {
            handler: 0x401000,
            ..GuestAction::default()
        };
        let efault = (-(libc::EFAULT as i64)) as u64;
        let einval = (-(libc::EINVAL as i64)) as u64;
        // Non-stub readbacks are already guest-visible.
        assert_eq!(visible_handler(0, stub, None, prev, 0), Some(0));
        assert_eq!(visible_handler(1, stub, None, prev, 0), Some(1));
        // Successful or copy-out-failed stubbed installs land.
        assert_eq!(
            visible_handler(stub, stub, Some(0x402000), prev, 0),
            Some(0x402000)
        );
        assert_eq!(
            visible_handler(stub, stub, Some(0x402000), prev, efault),
            Some(0x402000)
        );
        // EINVAL installed nothing: stub still means previous.
        assert_eq!(
            visible_handler(stub, stub, Some(0x402000), prev, einval),
            Some(0x401000)
        );
        // Query with no request keeps the previous handler.
        assert_eq!(visible_handler(stub, stub, None, prev, 0), Some(0x401000));
        // Stub with neither source fails closed.
        assert_eq!(
            visible_handler(stub, stub, None, GuestAction::default(), 0),
            None
        );
        assert_eq!(uc_greg_addr(0x1000, GREG_RIP), 0x1000 + 168);
        assert_eq!(uc_greg_addr(0x1000, GREG_R13), 0x1000 + 80);
    }

    #[test]
    fn midblock_gen_entry_recovers_exact_insn() {
        let fix = crate::fixtures::by_name("sum_loop");
        let region = crate::types::RegionFacts {
            base: 0x10_0000,
            bytes: fix.bytes,
            generation: crate::types::Generation(1),
            immutable_private: true,
        };
        let t = crate::translate::translate(
            &region,
            0x10_0000,
            CountProfile::BranchesAndInstructions,
            0x80_0000,
            0x81_0000,
        )
        .unwrap();
        // Every non-block-start copied insn in the fixture
        // has an exact generated re-entry recovering to it.
        let mut checked = 0;
        for block in t.blocks.values() {
            for &pc in block.insn_pcs().iter().skip(1) {
                if t.block_gen.contains_key(&pc) {
                    continue;
                }
                let gpc = gen_for_midblock(&t, pc).expect("midblock entry");
                assert_eq!(t.pcmap.recover(gpc), Some(pc));
                checked += 1;
            }
        }
        assert!(checked > 0, "fixture has mid-block insns");
        assert_eq!(gen_for_midblock(&t, 0xdead_0000), None);
        // Named exclusions by construction: a common-exit
        // machinery stop never resumes (even for a source PC
        // that otherwise has an exact re-entry), and an
        // unmapped generated PC (entry-loader bridge class)
        // never resumes.
        let common = t
            .pcmap
            .entries()
            .iter()
            .find(|e| matches!(e.recovery, MapRecovery::CommonExit { .. }))
            .expect("translation has common exit");
        let mut any_mid = None;
        for block in t.blocks.values() {
            for pc in block.insn_pcs().iter().skip(1) {
                if !t.block_gen.contains_key(pc) {
                    any_mid = Some(*pc);
                    break;
                }
            }
            if any_mid.is_some() {
                break;
            }
        }
        let any_mid = any_mid.expect("a mid-block insn");
        assert_eq!(resume_gen(&t, common.gen_start, any_mid), None);
        assert_eq!(resume_gen(&t, 0xdead_0000, any_mid), None);
        let copied_gen = gen_for_midblock(&t, any_mid).expect("midblock gen");
        assert_eq!(resume_gen(&t, copied_gen, any_mid), Some(Some(copied_gen)));
        let block_src = *t.block_gen.keys().next().expect("a block");
        let block_gen_pc = t.block_gen[&block_src];
        assert_eq!(resume_gen(&t, block_gen_pc, block_src), Some(None));
    }

    #[test]
    fn syscall_restart_family_is_not_completion() {
        for code in [512u64, 513, 514, 516] {
            assert!(is_syscall_restart(code.wrapping_neg()), "-{code}");
        }
        for rax in [0u64, 1, 5, (-9i64) as u64, (-4i64) as u64, (-11i64) as u64] {
            assert!(!is_syscall_restart(rax), "rax {rax:#x}");
        }
    }
}
