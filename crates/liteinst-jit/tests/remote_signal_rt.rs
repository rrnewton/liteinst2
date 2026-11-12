//! I1-G1: real-time ordering, RT queue retention vs standard
//! coalescing, `rt_sigqueueinfo` / `rt_tgsigqueueinfo` payloads
//! and sender words, and kernel back-to-back frame setup. The
//! same fixture bytes run translated in the remote child and
//! natively in the signal native child; handler logs, syscall
//! results, and ucontext RIPs must agree and match the pinned
//! expected kernel order, and translated counts are pinned to
//! the fixture's own instruction list (the native child is not
//! a count oracle). Refusal cases assert the named outcome,
//! and the forged-code-to-foreign-pid case asserts the native
//! errno, not a refusal.
//!
//! I1-G2 (the last group of tests): syscall restart. A signal
//! interrupts `rt_sigsuspend`, `FUTEX_WAIT_PRIVATE` or
//! `nanosleep`, sent either before an `rt_sigsuspend` unblocks
//! it or by a test thread once the child is blocked (see
//! `Sender`); the frame's ucontext RIP, RAX and saved mask and
//! the syscall result must match native.
//!
//! Fixtures are assembled with iced-x86 `CodeAssembler`.
//! Layout: one `SA_SIGINFO` handler per installed signal (same
//! body, distinct offsets, so a frame naming the wrong handler
//! is visible), the restorer (`mov eax,15; syscall`), then
//! straight-line main code (every main instruction retires
//! exactly once). Buffer offsets are `[rbx]` (rbx = dst; only
//! `dst[0..1024]` is reported by the native child):
//! - `0..32` act, `0x80` new mask, `0x88` old mask,
//!   `0x90` rt_sigpending set (end probe), `0x40`
//!   rt_sigpending set (mid-run probe);
//! - `152 + 8*k` the pointer argument register (`rsi` for
//!   `rt_sigaction`, `rdx`/`r10` for the queue calls, `rsi`
//!   for `nanosleep`'s remainder) right after the k-th such
//!   syscall;
//! - `256 + 8*k` result of the k-th recorded syscall;
//! - `376` next log entry pointer, `384` log entry count,
//!   `392 + 56*i` entry i: siginfo words 0, 8, 16, 24, then the
//!   ucontext RIP, RAX, and saved signal mask;
//! - I1-G2: `944` rt_sigsuspend mask, `960` nanosleep request,
//!   `984` futex word (every handler sets it to 1), `1000`
//!   nanosleep remainder (sentinel-filled, compared by range);
//! - `1024..1152` the siginfo a queue call sends (unreported).
//!
//! Each test holds `SERIAL`: ptrace children and signals from
//! different tests must not overlap.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[path = "common/corpus.rs"]
mod corpus;
#[path = "common/deadline.rs"]
mod deadline;

use iced_x86::BlockEncoderOptions;
use iced_x86::code_asm::*;
use liteinst_jit::exec::{FaultKind, Outcome, RunError};
use liteinst_jit::harness::RETURN_SENTINEL;
use liteinst_jit::o1::O1sEnd;
use liteinst_jit::refuse::Refuse;
use liteinst_jit::remote::{RemoteChildInfo, RemoteExecutable};
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};

const REMOTE_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-remote-child");
const NATIVE_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-signal-native-child");

static SERIAL: Mutex<()> = Mutex::new(());

const USR1: i32 = libc::SIGUSR1;
const USR2: i32 = libc::SIGUSR2;
const RTMIN: i32 = 34;
const RTMAX: i32 = 64;

/// SA_RESTORER | SA_SIGINFO, the I1-D base flag word.
const FLAGS: u32 = 0x0400_0004;
const SA_RESTART: u32 = 0x1000_0000;
/// Unmodelled by the tracer: keeps an action ineligible.
const SA_RESETHAND: u32 = 0x8000_0000;
const SI_USER: i32 = 0;
const SI_QUEUE: i32 = -1;
const SI_TKILL: i32 = -6;
const SI_KERNEL: i32 = 128;
/// Above any pid_max (at most 2^22), so no process can own it:
/// even a mutant that steps a call aimed here signals nobody.
const FOREIGN_PID: u32 = 0x3fff_ffff;
/// si_uid the conventional queue entries carry (any value is
/// passed through verbatim for a self-directed SI_QUEUE).
const UID_WORD: u32 = 0x0000_5151;
/// Forged sender words: si_pid/si_uid that are not the child.
const FORGED_PID: u32 = 0x7777_0001;
const FORGED_UID: u32 = 0x7777_0002;

const PENDING_MID: i32 = 0x40;
const ARG_BASE: i32 = 152;
const RC_BASE: i32 = 256;
const LOG_PTR: i32 = 376;
const LOG_COUNT: i32 = 384;
const LOG_BASE: i32 = 392;
const ENTRY_LEN: i32 = 56;
const REPORT: usize = 1024;
const SUSPEND_MASK: i32 = 944;
const NANO_REQ: i32 = 960;
const FUTEX_WORD: i32 = 984;
const NANO_REM: i32 = 1000;
const INFO: i32 = 1024;

fn sig_bit(sig: i32) -> u64 {
    1u64 << (sig - 1)
}

#[derive(Clone, Copy)]
enum Pid {
    Own,
    Raw(u32),
}

#[derive(Clone, Copy)]
enum Send {
    Kill(i32),
    Queue {
        pid: Pid,
        sig: i32,
        signo: i32,
        code: i32,
        forged_sender: bool,
        value: u64,
    },
    TgQueue {
        tgid: Pid,
        tid: Pid,
        sig: i32,
        code: i32,
        forged_sender: bool,
        value: u64,
    },
    /// rt_sigqueueinfo with an unreadable siginfo pointer.
    QueueBadPtr(i32),
    /// I1-G2: rt_sigsuspend with this temporary mask.
    Suspend(u64),
    /// I1-G2: futex(FUTEX_WORD, op, 0, timeout) — the admitted
    /// shape is op FUTEX_WAIT_PRIVATE (128) with no timeout.
    Futex {
        op: u32,
        timeout: bool,
    },
    /// The admitted futex wait reached by a direct `jmp` to the
    /// syscall, so the syscall starts its own block (a restart
    /// resumes through the block-start path, not the mid-block
    /// re-entry whose re-base would hide a miscredit).
    FutexWaitAtBlockStart,
    /// The admitted futex wait with RAX `0x1_000000ca`: the
    /// kernel dispatches on the low 32 bits and keeps the full
    /// value in `orig_rax` (review: syscall identity).
    FutexWaitHighAlias,
    /// I1-G2: nanosleep({secs, 0}, &rem).
    Nanosleep(u32),
    /// clock_nanosleep(CLOCK_MONOTONIC, 0, &req, &rem): never
    /// passed through.
    ClockNanosleep,
    /// rt_sigprocmask(SIG_BLOCK, NULL, &old at 0x88): query.
    QueryMask,
    /// No syscall: a counted loop `mov ecx, n; top: dec ecx;
    /// jnz top`, entering its block `n` times (W4: runs past
    /// poll exits, one every `POLL_BUDGET` = 16384 block
    /// entries). Records no result.
    Spin(u32),
    /// rt_sigpending into `PENDING_MID` (a pending probe placed
    /// among the sends, before any unblock).
    PendingNow,
    /// write(fd, dst + INFO, 1) to a test-owned inherited fd. The
    /// fd is an immediate (`mov edi, imm32`), so a runtime fd makes
    /// run-dependent bytes: pin a [`FD_TEMPLATE`] build and check
    /// the runtime build with [`assert_fd_patch`].
    WriteFd(i32),
}

/// The fd a pinned `WriteFd` template carries. If template bytes
/// ever ran, `write(-1, ..)` would only fail with EBADF.
const FD_TEMPLATE: i32 = -1;

fn futex_wait() -> Send {
    Send::Futex {
        op: 128,
        timeout: false,
    }
}

struct Spec {
    /// (signal, flags, sa_mask) per handler install.
    installs: Vec<(i32, u32, u64)>,
    /// Mask set before any send.
    block: u64,
    sends: Vec<Send>,
    /// Unblock everything (SETMASK 0) after the sends.
    unblock: bool,
    /// Record rt_sigpending into `0x90` at the end.
    pending_probe: bool,
}

struct Fx {
    bytes: Vec<u8>,
    /// Offset of each install's handler, in install order.
    handler_offs: Vec<u64>,
    restorer_off: u64,
    main_off: u64,
    /// First instruction after the unblock syscall (where the
    /// kernel delivers what the unblock released).
    resume_off: u64,
    /// Offset of each send's syscall instruction.
    send_pcs: Vec<u64>,
    /// Main instructions retired before each send's syscall.
    send_before: Vec<u64>,
    /// Offset of each install's `rt_sigaction` syscall, and the
    /// main instructions retired before it.
    install_pcs: Vec<u64>,
    install_before: Vec<u64>,
    /// Retired main instructions (straight line).
    main_insns: u64,
    /// Main instructions retired before `resume_off`.
    main_insns_before_resume: u64,
    handler_insns: u64,
    /// Never-taken `jne handler` devices in main (one per
    /// handler).
    main_branches: u64,
    /// `Spin` loops: retired instructions beyond the straight-line
    /// count, and retired conditional branches (one `jnz` per
    /// iteration).
    spin_extra_insns: u64,
    spin_branches: u64,
    /// Offset of a `WriteFd` send's `mov edi, imm32` (at most one).
    write_fd_mov: Option<u64>,
}

/// One `SA_SIGINFO` handler body: append one log entry. No
/// branches, so its size is position-independent.
fn emit_handler(a: &mut CodeAssembler) {
    a.mov(rcx, qword_ptr(rbx + LOG_PTR)).unwrap();
    for off in [0, 8, 16, 24] {
        a.mov(r8, qword_ptr(rsi + off)).unwrap();
        a.mov(qword_ptr(rcx + off), r8).unwrap();
    }
    a.mov(r8, qword_ptr(rdx + 168)).unwrap(); // uc_mcontext RIP
    a.mov(qword_ptr(rcx + 32), r8).unwrap();
    a.mov(r8, qword_ptr(rdx + 144)).unwrap(); // uc_mcontext RAX
    a.mov(qword_ptr(rcx + 40), r8).unwrap();
    a.mov(r8, qword_ptr(rdx + 296)).unwrap(); // uc_sigmask
    a.mov(qword_ptr(rcx + 48), r8).unwrap();
    a.mov(qword_ptr(rbx + FUTEX_WORD), 1).unwrap();
    a.add(rcx, ENTRY_LEN).unwrap();
    a.mov(qword_ptr(rbx + LOG_PTR), rcx).unwrap();
    a.inc(qword_ptr(rbx + LOG_COUNT)).unwrap();
    a.ret().unwrap();
}

/// Recorded syscall results, in order.
struct Rc(i32);

impl Rc {
    fn store(&mut self, a: &mut CodeAssembler) {
        a.mov(qword_ptr(rbx + (RC_BASE + 8 * self.0)), rax).unwrap();
        self.0 += 1;
    }
}

/// Assemble `spec` and pin its bytes under corpus ID `id`
/// (SIGNAL-CORPUS.md) before anything runs.
fn build(spec: &Spec, id: &str) -> Fx {
    let fx = build_unpinned(spec);
    corpus::check(id, &fx.bytes);
    fx
}

/// [`build`] without the pin, only for fixtures whose bytes embed
/// a run-dependent value: a live helper's pid (SIGNAL-CORPUS.md
/// lists it as unpinned), or a runtime fd, whose pinned
/// [`FD_TEMPLATE`] build [`assert_fd_patch`] checks it against.
fn build_unpinned(spec: &Spec) -> Fx {
    let (hlen, handler_insns) = {
        let mut h = CodeAssembler::new(64).unwrap();
        emit_handler(&mut h);
        let n = h.instructions().len() as u64;
        (h.assemble(0).unwrap().len() as u64, n)
    };
    let mut a = CodeAssembler::new(64).unwrap();
    let mut restorer = a.create_label();
    let mut main = a.create_label();
    let mut resume = a.create_label();
    // One handler per install (at least one), back to back
    // from offset 0: handler i is at i * hlen.
    let n_handlers = spec.installs.len().max(1);
    let mut handlers = Vec::new();
    for _ in 0..n_handlers {
        let mut l = a.create_label();
        a.set_label(&mut l).unwrap();
        emit_handler(&mut a);
        handlers.push(l);
    }
    a.set_label(&mut restorer).unwrap();
    a.db(&[0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05]).unwrap();
    // Main.
    a.set_label(&mut main).unwrap();
    let m0 = a.instructions().len();
    let mut rc = Rc(0);
    a.lea(rax, qword_ptr(rbx + LOG_BASE)).unwrap();
    a.mov(qword_ptr(rbx + LOG_PTR), rax).unwrap();
    a.mov(eax, libc::SYS_getpid as u32).unwrap();
    a.syscall().unwrap();
    a.mov(r14, rax).unwrap();
    // Translator reachability for each handler block.
    for h in &handlers {
        a.cmp(rcx, rcx).unwrap();
        a.jne(*h).unwrap();
    }
    let main_branches = n_handlers as u64;
    let mut args = 0;
    let mut install_labels = Vec::new();
    let mut install_before = Vec::new();
    for (i, &(sig, flags, mask)) in spec.installs.iter().enumerate() {
        let mut at = a.create_label();
        a.lea(rax, qword_ptr(rbp + (i as u64 * hlen) as i32))
            .unwrap();
        a.mov(qword_ptr(rbx), rax).unwrap();
        a.mov(dword_ptr(rbx + 8), flags).unwrap();
        a.mov(dword_ptr(rbx + 12), 0u32).unwrap();
        a.mov(qword_ptr(rbx + 16), r12).unwrap();
        a.mov(dword_ptr(rbx + 24), mask as u32).unwrap();
        a.mov(dword_ptr(rbx + 28), (mask >> 32) as u32).unwrap();
        a.mov(edi, sig as u32).unwrap();
        a.mov(rsi, rbx).unwrap();
        a.xor(edx, edx).unwrap();
        a.mov(r10d, 8u32).unwrap();
        a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
        a.set_label(&mut at).unwrap();
        install_before.push((a.instructions().len() - m0) as u64);
        a.syscall().unwrap();
        rc.store(&mut a);
        a.mov(qword_ptr(rbx + (ARG_BASE + 8 * args)), rsi).unwrap();
        args += 1;
        install_labels.push(at);
    }
    let setmask = |a: &mut CodeAssembler, mask: u64, old: bool| {
        a.mov(dword_ptr(rbx + 0x80), mask as u32).unwrap();
        a.mov(dword_ptr(rbx + 0x84), (mask >> 32) as u32).unwrap();
        a.mov(edi, libc::SIG_SETMASK as u32).unwrap();
        a.lea(rsi, qword_ptr(rbx + 0x80)).unwrap();
        if old {
            a.lea(rdx, qword_ptr(rbx + 0x88)).unwrap();
        } else {
            a.xor(edx, edx).unwrap();
        }
        a.mov(r10d, 8u32).unwrap();
        a.mov(eax, libc::SYS_rt_sigprocmask as u32).unwrap();
    };
    setmask(&mut a, spec.block, false);
    a.syscall().unwrap();
    rc.store(&mut a);
    // Raw pids load through the 32-bit register (zero-extended).
    let pid_to =
        |a: &mut CodeAssembler, reg: AsmRegister64, reg32: AsmRegister32, pid: Pid| match pid {
            Pid::Own => a.mov(reg, r14).unwrap(),
            Pid::Raw(p) => a.mov(reg32, p).unwrap(),
        };
    let info = |a: &mut CodeAssembler, signo: i32, code: i32, forged: bool, value: u64| {
        a.mov(dword_ptr(rbx + INFO), signo as u32).unwrap();
        a.mov(dword_ptr(rbx + (INFO + 4)), 0u32).unwrap();
        a.mov(dword_ptr(rbx + (INFO + 8)), code as u32).unwrap();
        a.mov(dword_ptr(rbx + (INFO + 12)), 0u32).unwrap();
        if forged {
            a.mov(dword_ptr(rbx + (INFO + 16)), FORGED_PID).unwrap();
            a.mov(dword_ptr(rbx + (INFO + 20)), FORGED_UID).unwrap();
        } else {
            a.mov(dword_ptr(rbx + (INFO + 16)), r14d).unwrap();
            a.mov(dword_ptr(rbx + (INFO + 20)), UID_WORD).unwrap();
        }
        a.mov(dword_ptr(rbx + (INFO + 24)), value as u32).unwrap();
        a.mov(dword_ptr(rbx + (INFO + 28)), (value >> 32) as u32)
            .unwrap();
    };
    let mut send_labels = Vec::new();
    let mut send_before = Vec::new();
    let mut write_fd_mov = None;
    let (mut spin_extra_insns, mut spin_branches) = (0u64, 0u64);
    for send in &spec.sends {
        let mut at = a.create_label();
        if let Send::Spin(n) = *send {
            assert!(n >= 1, "spin count");
            a.mov(ecx, n).unwrap();
            a.set_label(&mut at).unwrap();
            send_before.push((a.instructions().len() - m0) as u64);
            a.dec(ecx).unwrap();
            a.jnz(at).unwrap();
            spin_extra_insns += 2 * (u64::from(n) - 1);
            spin_branches += u64::from(n);
            send_labels.push(at);
            continue;
        }
        match *send {
            Send::Kill(sig) => {
                a.mov(rdi, r14).unwrap();
                a.mov(esi, sig as u32).unwrap();
                a.mov(eax, libc::SYS_kill as u32).unwrap();
            }
            Send::Queue {
                pid,
                sig,
                signo,
                code,
                forged_sender,
                value,
            } => {
                info(&mut a, signo, code, forged_sender, value);
                pid_to(&mut a, rdi, edi, pid);
                a.mov(esi, sig as u32).unwrap();
                a.lea(rdx, qword_ptr(rbx + INFO)).unwrap();
                a.mov(eax, libc::SYS_rt_sigqueueinfo as u32).unwrap();
            }
            Send::TgQueue {
                tgid,
                tid,
                sig,
                code,
                forged_sender,
                value,
            } => {
                info(&mut a, sig, code, forged_sender, value);
                pid_to(&mut a, rdi, edi, tgid);
                pid_to(&mut a, rsi, esi, tid);
                a.mov(edx, sig as u32).unwrap();
                a.lea(r10, qword_ptr(rbx + INFO)).unwrap();
                a.mov(eax, libc::SYS_rt_tgsigqueueinfo as u32).unwrap();
            }
            Send::QueueBadPtr(sig) => {
                a.mov(rdi, r14).unwrap();
                a.mov(esi, sig as u32).unwrap();
                a.mov(edx, 0x10u32).unwrap();
                a.mov(eax, libc::SYS_rt_sigqueueinfo as u32).unwrap();
            }
            Send::Suspend(mask) => {
                a.mov(dword_ptr(rbx + SUSPEND_MASK), mask as u32).unwrap();
                a.mov(dword_ptr(rbx + (SUSPEND_MASK + 4)), (mask >> 32) as u32)
                    .unwrap();
                a.lea(rdi, qword_ptr(rbx + SUSPEND_MASK)).unwrap();
                a.mov(esi, 8u32).unwrap();
                a.mov(eax, libc::SYS_rt_sigsuspend as u32).unwrap();
            }
            Send::FutexWaitHighAlias => {
                a.lea(rdi, qword_ptr(rbx + FUTEX_WORD)).unwrap();
                a.mov(esi, 128u32).unwrap();
                a.xor(edx, edx).unwrap();
                a.xor(r10d, r10d).unwrap();
                a.mov(rax, (1u64 << 32) | libc::SYS_futex as u64).unwrap();
            }
            Send::FutexWaitAtBlockStart => {
                a.lea(rdi, qword_ptr(rbx + FUTEX_WORD)).unwrap();
                a.mov(esi, 128u32).unwrap();
                a.xor(edx, edx).unwrap();
                a.xor(r10d, r10d).unwrap();
                a.mov(eax, libc::SYS_futex as u32).unwrap();
                a.jmp(at).unwrap();
            }
            Send::Futex { op, timeout } => {
                a.lea(rdi, qword_ptr(rbx + FUTEX_WORD)).unwrap();
                a.mov(esi, op).unwrap();
                a.xor(edx, edx).unwrap();
                if timeout {
                    a.mov(qword_ptr(rbx + NANO_REQ), 1).unwrap();
                    a.lea(r10, qword_ptr(rbx + NANO_REQ)).unwrap();
                } else {
                    a.xor(r10d, r10d).unwrap();
                }
                a.mov(eax, libc::SYS_futex as u32).unwrap();
            }
            Send::Nanosleep(secs) => {
                a.mov(qword_ptr(rbx + NANO_REQ), secs as i32).unwrap();
                a.mov(qword_ptr(rbx + (NANO_REQ + 8)), 0).unwrap();
                a.mov(qword_ptr(rbx + NANO_REM), -1).unwrap();
                a.mov(qword_ptr(rbx + (NANO_REM + 8)), -1).unwrap();
                a.lea(rdi, qword_ptr(rbx + NANO_REQ)).unwrap();
                a.lea(rsi, qword_ptr(rbx + NANO_REM)).unwrap();
                a.mov(eax, libc::SYS_nanosleep as u32).unwrap();
            }
            Send::ClockNanosleep => {
                a.mov(qword_ptr(rbx + NANO_REQ), 1).unwrap();
                a.mov(qword_ptr(rbx + (NANO_REQ + 8)), 0).unwrap();
                a.mov(edi, 1u32).unwrap(); // CLOCK_MONOTONIC
                a.xor(esi, esi).unwrap();
                a.lea(rdx, qword_ptr(rbx + NANO_REQ)).unwrap();
                a.lea(r10, qword_ptr(rbx + NANO_REM)).unwrap();
                a.mov(eax, libc::SYS_clock_nanosleep as u32).unwrap();
            }
            Send::WriteFd(fd) => {
                assert!(write_fd_mov.is_none(), "one WriteFd per fixture");
                let mut l = a.create_label();
                a.set_label(&mut l).unwrap();
                a.mov(edi, fd as u32).unwrap();
                write_fd_mov = Some(l);
                a.lea(rsi, qword_ptr(rbx + INFO)).unwrap();
                a.mov(edx, 1u32).unwrap();
                a.mov(eax, libc::SYS_write as u32).unwrap();
            }
            Send::Spin(_) => unreachable!("handled above"),
            Send::PendingNow => {
                a.lea(rdi, qword_ptr(rbx + PENDING_MID)).unwrap();
                a.mov(esi, 8u32).unwrap();
                a.mov(eax, libc::SYS_rt_sigpending as u32).unwrap();
            }
            Send::QueryMask => {
                a.mov(edi, libc::SIG_BLOCK as u32).unwrap();
                a.xor(esi, esi).unwrap();
                a.lea(rdx, qword_ptr(rbx + 0x88)).unwrap();
                a.mov(r10d, 8u32).unwrap();
                a.mov(eax, libc::SYS_rt_sigprocmask as u32).unwrap();
            }
        }
        a.set_label(&mut at).unwrap();
        send_before.push((a.instructions().len() - m0) as u64);
        a.syscall().unwrap();
        rc.store(&mut a);
        let arg = match send {
            Send::Queue { .. } => Some(rdx),
            Send::TgQueue { .. } => Some(r10),
            // The remainder pointer after the call: the kernel
            // wrote through the guest's own pointer.
            Send::Nanosleep(_) => Some(rsi),
            _ => None,
        };
        if let Some(reg) = arg {
            a.mov(qword_ptr(rbx + (ARG_BASE + 8 * args)), reg).unwrap();
            args += 1;
        }
        send_labels.push(at);
    }
    let mut before_resume = a.instructions().len() - m0;
    if spec.unblock {
        setmask(&mut a, 0, true);
        a.syscall().unwrap();
        before_resume = a.instructions().len() - m0;
        a.set_label(&mut resume).unwrap();
        rc.store(&mut a);
    }
    if spec.pending_probe {
        a.lea(rdi, qword_ptr(rbx + 0x90)).unwrap();
        a.mov(esi, 8u32).unwrap();
        a.mov(eax, libc::SYS_rt_sigpending as u32).unwrap();
        a.syscall().unwrap();
        rc.store(&mut a);
    }
    if !spec.unblock {
        a.set_label(&mut resume).unwrap();
    }
    a.mov(eax, 42u32).unwrap();
    a.ret().unwrap();
    let main_insns = (a.instructions().len() - m0) as u64;
    let res = a
        .assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .unwrap();
    let handler_offs: Vec<u64> = handlers.iter().map(|l| res.label_ip(l).unwrap()).collect();
    for (i, &off) in handler_offs.iter().enumerate() {
        assert_eq!(off, i as u64 * hlen, "handler {i} offset");
    }
    assert!(args <= 13, "argument slots {args}");
    Fx {
        bytes: res.inner.code_buffer.clone(),
        handler_offs: handler_offs[..spec.installs.len()].to_vec(),
        restorer_off: res.label_ip(&restorer).unwrap(),
        main_off: res.label_ip(&main).unwrap(),
        resume_off: res.label_ip(&resume).unwrap(),
        send_pcs: send_labels
            .iter()
            .map(|l| res.label_ip(l).unwrap())
            .collect(),
        send_before,
        install_pcs: install_labels
            .iter()
            .map(|l| res.label_ip(l).unwrap())
            .collect(),
        install_before,
        main_insns,
        main_insns_before_resume: before_resume as u64,
        handler_insns,
        main_branches,
        spin_extra_insns,
        spin_branches,
        write_fd_mov: write_fd_mov.map(|l| res.label_ip(&l).unwrap()),
    }
}

/// `runtime` is the pinned `template` (built with
/// [`FD_TEMPLATE`]) with exactly one change: `fd` patched into the
/// imm32 of the `WriteFd` send's `mov edi, imm32` (encoding `BF
/// imm32`). Every other byte and every recorded offset is equal.
fn assert_fd_patch(template: &Fx, runtime: &Fx, fd: i32, label: &str) {
    let at = template.write_fd_mov.expect("template has a WriteFd") as usize;
    assert_eq!(runtime.write_fd_mov, Some(at as u64), "{label}: mov offset");
    assert_eq!(template.bytes[at], 0xbf, "{label}: mov edi, imm32 opcode");
    assert_eq!(
        template.bytes[at + 1..at + 5],
        FD_TEMPLATE.to_le_bytes(),
        "{label}: template immediate"
    );
    let mut want = template.bytes.clone();
    want[at + 1..at + 5].copy_from_slice(&fd.to_le_bytes());
    assert_eq!(
        runtime.bytes, want,
        "{label}: runtime bytes = template + fd patch"
    );
    let offs = |f: &Fx| {
        (
            f.handler_offs.clone(),
            f.restorer_off,
            f.main_off,
            f.resume_off,
            f.send_pcs.clone(),
            f.send_before.clone(),
            f.install_pcs.clone(),
            f.main_insns,
        )
    };
    assert_eq!(offs(runtime), offs(template), "{label}: layout");
}

fn word(data: &[u8], off: i32) -> u64 {
    let off = off as usize;
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

/// Sender pid word normalized across children.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SenderPid {
    Own,
    Other(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    signo: u64,
    code: i32,
    pid: SenderPid,
    uid: u32,
    value: u64,
    uc_rip_off: u64,
}

/// Normalized witness: recorded syscall results, the pointer
/// argument registers after redirected syscalls (as offsets
/// from dst), the old mask at unblock, the rt_sigpending probe,
/// the handler log, per entry the ucontext RAX and saved mask
/// (`frames`), and the I1-G2 words (suspend mask, nanosleep
/// request, futex word). The nanosleep remainder is elapsed-
/// time dependent and compared separately by range.
#[derive(Debug, Eq, PartialEq)]
struct Witness {
    rcs: Vec<u64>,
    args: Vec<u64>,
    frames: Vec<(u64, u64)>,
    g2: [u64; 4],
    old_mask: u64,
    pending: u64,
    /// rt_sigpending set from a `PendingNow` probe.
    pending_mid: u64,
    log: Vec<Entry>,
}

fn witness(data: &[u8], spec: &Spec, base: u64, dst: u64, own_pid: u32) -> Witness {
    let count = word(data, LOG_COUNT);
    assert!(count <= 6, "log count {count}");
    let log = (0..count as i32)
        .map(|i| {
            let e = LOG_BASE + ENTRY_LEN * i;
            let w2 = word(data, e + 16);
            let pid = w2 as u32;
            Entry {
                signo: word(data, e),
                code: word(data, e + 8) as u32 as i32,
                pid: if pid == own_pid {
                    SenderPid::Own
                } else {
                    SenderPid::Other(pid)
                },
                uid: (w2 >> 32) as u32,
                value: word(data, e + 24),
                uc_rip_off: word(data, e + 32).wrapping_sub(base),
            }
        })
        .collect();
    let frames = (0..count as i32)
        .map(|i| {
            let e = LOG_BASE + ENTRY_LEN * i;
            (word(data, e + 40), word(data, e + 48))
        })
        .collect();
    Witness {
        frames,
        g2: [
            word(data, SUSPEND_MASK),
            word(data, NANO_REQ),
            word(data, NANO_REQ + 8),
            word(data, FUTEX_WORD),
        ],
        rcs: (0..n_rc(spec) as i32)
            .map(|k| word(data, RC_BASE + 8 * k))
            .collect(),
        args: (0..n_args(spec) as i32)
            .map(|k| word(data, ARG_BASE + 8 * k).wrapping_sub(dst))
            .collect(),
        old_mask: word(data, 0x88),
        pending: word(data, 0x90),
        pending_mid: word(data, PENDING_MID),
        log,
    }
}

fn n_args(spec: &Spec) -> usize {
    spec.installs.len()
        + spec
            .sends
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    Send::Queue { .. } | Send::TgQueue { .. } | Send::Nanosleep(_)
                )
            })
            .count()
}

fn n_rc(spec: &Spec) -> usize {
    spec.installs.len()
        + 1
        + spec
            .sends
            .iter()
            .filter(|s| !matches!(s, Send::Spin(_)))
            .count()
        + usize::from(spec.unblock)
        + usize::from(spec.pending_probe)
}

struct Translated {
    remote: RemoteExecutable,
    info: RemoteChildInfo,
    out: Result<Outcome, RunError>,
    data: Vec<u8>,
    /// Taken before the run started and after it returned.
    span: (Instant, Instant),
    seen: Option<Seen>,
}

fn run_translated(fx: &Fx) -> Translated {
    run_translated_with(fx, None)
}

fn run_translated_with(fx: &Fx, pre_step_signal: Option<i32>) -> Translated {
    run_translated_full(fx, pre_step_signal, Ext::None)
}

/// What a test thread does to a running child (I1-G2).
#[derive(Clone, Copy)]
enum Ext {
    None,
    /// Only bound the run: 10 s, then fail by name.
    Watchdog,
    /// Send `sig` once the child is asleep in syscall `nr`.
    Send(i64, i32),
}

/// How long the child must stay asleep in the syscall, after
/// it is first seen asleep, before the signal is sent. The
/// `nanosleep` remainder bound uses it.
const DWELL: Duration = Duration::from_millis(50);

/// What the sender saw before it signalled.
#[derive(Clone, Debug)]
struct Seen {
    /// Taken right after the first `/proc` read that showed the
    /// child asleep in the syscall: the sleep began before it.
    asleep_at: Instant,
    /// Taken right before the signal was sent (after the dwell
    /// and a second asleep check): the interruption came after.
    sent_at: Instant,
    /// `/proc/<pid>/wchan` at the first sighting (evidence).
    wchan: String,
}

/// I1-G2 external interruption. Once the child is asleep in
/// syscall `nr` (see [`asleep_in`]; a ptrace syscall-entry stop
/// does not count), this test process waits [`DWELL`], checks
/// the child is still asleep there, and sends it `sig` through
/// a pidfd opened while the child was known alive and unreaped,
/// so no signal can reach a reused pid. The signal therefore
/// lands only while the call is truly blocked. Bounded both
/// ways, failing by name: a child that never sleeps in `nr`
/// within 5 s is SIGKILLed through the same pidfd (so the run
/// returns) and the test fails; so is a run still going 10 s
/// after the send. A run that ends before the child ever slept
/// there fails too, as does a child that left the syscall
/// during the dwell. As a bare watchdog (no `nr`), the 10 s
/// bound runs from start.
struct Sender {
    done: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<Result<Option<Seen>, String>>,
}

/// `/proc/<pid>/syscall` names syscall `nr`. This alone is
/// also true at a ptrace syscall-entry stop, before the call
/// runs; see [`asleep_in`].
fn blocked_in(pid: u32, nr: i64) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/syscall"))
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<i64>().ok())
        == Some(nr)
}

/// The child is asleep inside syscall `nr`: `/proc/<pid>/syscall`
/// names it, the scheduler state is `S` (interruptible sleep; a
/// ptrace stop reads `t`), and `/proc/<pid>/wchan` names a
/// kernel sleep site (non-empty, not `0`, not a ptrace or
/// job-control stop). Returns that wchan.
fn asleep_in(pid: u32, nr: i64) -> Option<String> {
    if !blocked_in(pid, nr) || try_proc_state(pid as i32) != Some('S') {
        return None;
    }
    let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan")).ok()?;
    let stop = ["", "0", "ptrace_stop", "do_signal_stop"].contains(&wchan.trim());
    if stop || !blocked_in(pid, nr) {
        return None;
    }
    Some(wchan.trim().to_string())
}

impl Sender {
    /// Call while `pid` is this test's own live, unreaped child.
    fn start(pid: u32, ext: Ext) -> Option<Sender> {
        let send = match ext {
            Ext::None => return None,
            Ext::Watchdog => None,
            Ext::Send(nr, sig) => Some((nr, sig)),
        };
        // SAFETY: pidfd_open has no memory arguments.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        assert!(
            fd >= 0,
            "G2 sender: pidfd_open {pid}: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: a fresh descriptor this test now owns.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let handle = std::thread::spawn(move || {
            let signal = |s: i32| {
                // SAFETY: pidfd_send_signal with a NULL siginfo
                // (kernel-filled SI_USER, like kill(2)).
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        s,
                        core::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                }
            };
            let t0 = Instant::now();
            let mut seen = None;
            let mut sig = 0;
            if let Some((nr, s)) = send {
                sig = s;
                let wchan = loop {
                    if let Some(w) = asleep_in(pid, nr) {
                        break w;
                    }
                    if flag.load(Ordering::SeqCst) {
                        return Err(format!(
                            "G2 sender: run ended before the guest slept in syscall {nr}"
                        ));
                    }
                    if t0.elapsed() > Duration::from_secs(5) {
                        signal(libc::SIGKILL);
                        return Err(format!(
                            "G2 sender: guest never slept in syscall {nr} within 5 s"
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                };
                let asleep_at = Instant::now();
                std::thread::sleep(DWELL);
                if asleep_in(pid, nr).is_none() {
                    signal(libc::SIGKILL);
                    return Err(format!(
                        "G2 sender: guest left syscall {nr} during the {DWELL:?} dwell"
                    ));
                }
                let sent_at = Instant::now();
                if signal(sig) != 0 {
                    return Err(format!(
                        "G2 sender: pidfd_send_signal {sig}: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                seen = Some(Seen {
                    asleep_at,
                    sent_at,
                    wchan,
                });
            }
            let t1 = Instant::now();
            while !flag.load(Ordering::SeqCst) {
                if t1.elapsed() > Duration::from_secs(10) {
                    signal(libc::SIGKILL);
                    return Err(if send.is_some() {
                        format!("G2 sender: run still going 10 s after sending signal {sig}")
                    } else {
                        "G2 watchdog: run still going after 10 s".to_string()
                    });
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(seen)
        });
        Some(Sender { done, handle })
    }

    /// Stop the sender and report its verdict; call before the
    /// child is reaped.
    fn finish(self) -> Result<Option<Seen>, String> {
        self.done.store(true, Ordering::SeqCst);
        self.handle.join().expect("sender thread")
    }
}

fn ext(send: Option<(i64, i32)>) -> Ext {
    send.map_or(Ext::None, |(nr, sig)| Ext::Send(nr, sig))
}

fn finish_sender(sender: Option<Sender>) -> Option<Seen> {
    match sender.map(Sender::finish) {
        Some(Err(e)) => panic!("{e}"),
        Some(Ok(seen)) => seen,
        None => None,
    }
}

/// `pre_step_signal`: the tracer's test seam sends this signal
/// to its own child after a redirected syscall argument is
/// staged and just before the step resumes the child.
/// `ext`: what a [`Sender`] thread does to the child.
fn run_translated_full(fx: &Fx, pre_step_signal: Option<i32>, ext: Ext) -> Translated {
    run_translated_cfg(fx, pre_step_signal, ext, |_| {})
}

/// [`run_translated_full`], with `configure` applied to the
/// spawned executable before it is prepared (other test seams).
fn run_translated_cfg(
    fx: &Fx,
    pre_step_signal: Option<i32>,
    ext: Ext,
    configure: impl FnOnce(&mut RemoteExecutable),
) -> Translated {
    let (mut remote, deadline) =
        deadline::remote_bytes(REMOTE_CHILD, &fx.bytes).expect("spawn remote");
    assert_eq!(
        remote.pre_redirected_step_signal_for_test(),
        None,
        "test seam inert at spawn"
    );
    remote.set_pre_redirected_step_signal_for_test(pre_step_signal);
    configure(&mut remote);
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: fx.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(
            &region,
            info.base + fx.main_off,
            CountProfile::BranchesAndInstructions,
        )
        .expect("prepare remote");
    let mut s = remote.initial_state();
    s.rip = info.base + fx.main_off;
    s.rbx = info.dst;
    s.rbp = info.base;
    s.r12 = info.base + fx.restorer_off;
    s.r13 = info.src;
    let sender = Sender::start(remote.child_pid_for_test() as u32, ext);
    let started = Instant::now();
    let out = remote.run(s, RETURN_SENTINEL);
    let ended = Instant::now();
    // A run past its deadline fails here, by name.
    drop(deadline);
    let seen = finish_sender(sender);
    let mut data = vec![0u8; REPORT];
    assert!(remote.read_mem(info.dst, &mut data));
    Translated {
        remote,
        info,
        out,
        data,
        span: (started, ended),
        seen,
    }
}

struct Native {
    result: u64,
    data: Vec<u8>,
    base: u64,
    dst: u64,
    pid: u32,
    /// Taken before the child was spawned and after its report.
    span: (Instant, Instant),
    seen: Option<Seen>,
}

fn run_native(fx: &Fx) -> Native {
    run_native_sent(fx, Ext::None)
}

fn run_native_sent(fx: &Fx, ext: Ext) -> Native {
    let hex: String = fx.bytes.iter().map(|b| format!("{b:02x}")).collect();
    let started = Instant::now();
    let (mut child, deadline) = deadline::command_child(
        Command::new(NATIVE_CHILD)
            .args([
                format!("hex:{hex}"),
                fx.main_off.to_string(),
                fx.restorer_off.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    )
    .expect("spawn native child");
    let pid = child.id();
    let sender = Sender::start(pid, ext);
    let mut stdout = child.stdout.take().expect("native stdout");
    let mut raw = [0u8; 32];
    stdout.read_exact(&mut raw).expect("native info");
    let base = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let dst = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    child
        .stdin
        .as_mut()
        .expect("native stdin")
        .write_all(&[1u8])
        .expect("native go byte");
    let mut out = vec![0u8; 8 + REPORT];
    let read = stdout.read_exact(&mut out);
    let ended = Instant::now();
    // The sender's verdict (a named bound) explains a short
    // read better than the read error; both precede the reap.
    let seen = finish_sender(sender);
    read.expect("native result");
    let status = child.wait().expect("wait native child");
    drop(deadline);
    assert!(status.success(), "native child status {status}");
    Native {
        result: u64::from_le_bytes(out[0..8].try_into().unwrap()),
        data: out[8..].to_vec(),
        base,
        dst,
        pid,
        span: (started, ended),
        seen,
    }
}

/// Kernel pending words (SigPnd | ShdPnd) of a live child.
fn proc_pending(pid: i32) -> u64 {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("child status");
    text.lines()
        .filter_map(|l| {
            l.strip_prefix("SigPnd:")
                .or_else(|| l.strip_prefix("ShdPnd:"))
        })
        .map(|v| u64::from_str_radix(v.trim(), 16).expect("pending hex"))
        .fold(0, |acc, v| acc | v)
}

fn real_uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

/// Run both children; assert both returned 42 with equal
/// witnesses, pin translated counts, and return the witness.
fn differential(spec: &Spec, deliveries: u64, label: &str) -> (Fx, Witness, Translated) {
    let (fx, w, t, _) = differential_sent(spec, deliveries, label, None);
    (fx, w, t)
}

/// [`differential`] with an optional [`Sender`] `(nr, sig)`
/// aimed at each child; also returns the native run.
fn differential_sent(
    spec: &Spec,
    deliveries: u64,
    label: &str,
    send: Option<(i64, i32)>,
) -> (Fx, Witness, Translated, Native) {
    let fx = build(spec, label);
    let n = run_native_sent(&fx, ext(send));
    assert_eq!(n.result, 42, "{label}: native result");
    let nw = witness(&n.data, spec, n.base, n.dst, n.pid);
    // Guest-visible witness first, whatever the translated
    // outcome: a tracer that stops early or corrupts a frame
    // fails on the substantive difference, not on an unwrap.
    let t = run_translated_full(&fx, None, ext(send));
    assert_no_tracer_write_in_dst(&t, label);
    let own = t.remote.child_pid_for_test() as u32;
    let tw = witness(&t.data, spec, t.info.base, t.info.dst, own);
    assert_eq!(
        tw,
        nw,
        "{label}: translated vs native witness (translated error: {:?})",
        t.out.as_ref().err()
    );
    let out = t
        .out
        .clone()
        .unwrap_or_else(|e| panic!("{label}: translated run: {e:?}"));
    assert_eq!(out.state.rax, 42, "{label}: translated result");
    assert_eq!(tw.log.len() as u64, deliveries, "{label}: deliveries");
    // Enumerated: straight-line main, one handler run and the
    // two-insn restorer per delivery; branches are the main
    // reachability devices only (the handler has none).
    assert_eq!(
        out.instructions,
        fx.main_insns + fx.spin_extra_insns + deliveries * (fx.handler_insns + 2),
        "{label}: instructions"
    );
    assert_eq!(
        out.branches,
        fx.main_branches + fx.spin_branches,
        "{label}: branches"
    );
    if send.is_some() {
        assert_slept(&n.seen, "native", label);
        assert_slept(&t.seen, "translated", label);
    }
    o1s_check(&fx, spec, deliveries, label, send, &nw, &t, &out);
    (fx, tw, t, n)
}

/// I1-H, the I1-D completion: O1-S steps the same bytes natively
/// in the remote child, with every delivery made by the kernel
/// for real. It must reproduce the native child's witness (a
/// sanity check of O1-S itself), match the fixture enumeration
/// on its own (its self-check), and equal the translated counts
/// and final register image (addresses as region offsets; the
/// child's pid as a token).
#[allow(clippy::too_many_arguments)]
fn o1s_check(
    fx: &Fx,
    spec: &Spec,
    deliveries: u64,
    label: &str,
    send: Option<(i64, i32)>,
    nw: &Witness,
    t: &Translated,
    out: &Outcome,
) {
    let mut sender = None;
    let (main, restorer) = (fx.main_off, fx.restorer_off);
    let o = deadline::o1s(
        REMOTE_CHILD,
        &fx.bytes,
        &[],
        |r, info| {
            r.rip = info.base + main;
            r.rbx = info.dst;
            r.rbp = info.base;
            r.r12 = info.base + restorer;
            r.r13 = info.src;
        },
        None,
        |pid| sender = Sender::start(pid as u32, ext(send)),
    );
    let seen = finish_sender(sender);
    assert_eq!(o.end, O1sEnd::Returned, "{label}: O1-S end");
    let ow = witness(
        &o.dst_bytes[..REPORT],
        spec,
        o.info.base,
        o.info.dst,
        o.pid as u32,
    );
    assert_eq!(&ow, nw, "{label}: O1-S vs native witness");
    assert_eq!(
        o.deliveries.len() as u64,
        deliveries,
        "{label}: O1-S deliveries"
    );
    assert_eq!(
        o.instructions,
        fx.main_insns + fx.spin_extra_insns + deliveries * (fx.handler_insns + 2),
        "{label}: O1-S instructions vs enumeration"
    );
    assert_eq!(
        o.branches,
        fx.main_branches + fx.spin_branches,
        "{label}: O1-S branches vs enumeration"
    );
    assert_eq!(
        (out.instructions, out.branches),
        (o.instructions, o.branches),
        "{label}: translated vs O1-S counts"
    );
    let code_len = fx.bytes.len().div_ceil(4096) as u64 * 4096;
    let own = t.remote.child_pid_for_test() as u32;
    let tn = norm_state(&out.state, &t.info, own, code_len);
    let on = norm_state(&o.state, &o.info, o.pid as u32, code_len);
    for (i, name) in GREG_NAMES.iter().enumerate() {
        assert_eq!(
            tn[i], on[i],
            "{label}: final {name}: translated vs O1-S (normalized)"
        );
    }
    if send.is_some() {
        assert_slept(&seen, "O1-S", label);
    }
}

const GREG_NAMES: [&str; 18] = [
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp", "rbx", "rdx", "rax",
    "rcx", "rsp", "rip", "rflags",
];

/// A register image with addresses as `(region << 56) | offset`
/// (code, stack, dst, src, data) and the child's own pid as a
/// token. RFLAGS compares exactly (no observer flag may leak).
fn norm_state(
    s: &liteinst_jit::GuestState,
    info: &RemoteChildInfo,
    pid: u32,
    code_len: u64,
) -> [u64; 18] {
    let regs = [
        s.r8, s.r9, s.r10, s.r11, s.r12, s.r13, s.r14, s.r15, s.rdi, s.rsi, s.rbp, s.rbx, s.rdx,
        s.rax, s.rcx, s.rsp, s.rip, s.rflags,
    ];
    let stack_lo = info.stack_top - 64 * 1024 + 8;
    let regions = [
        (info.base, code_len),
        (stack_lo, info.stack_top + 8 - stack_lo),
        (info.dst, 8192),
        (info.src, 8192),
        (info.data, 128),
    ];
    core::array::from_fn(|i| {
        let v = regs[i];
        if i == 17 {
            return v;
        }
        if v == u64::from(pid) {
            return 0x7e00_0000_0000_0000;
        }
        for (r, &(lo, len)) in regions.iter().enumerate() {
            if v >= lo && v <= lo + len {
                return ((r as u64 + 1) << 56) | (v - lo);
            }
        }
        v
    })
}

/// Positive sleep witness: the sender saw the child asleep in
/// the syscall (state `S`, a kernel sleep site in `wchan`) and
/// still asleep after the dwell, before it signalled. The wchan
/// goes to stderr for the evidence logs (`--nocapture`).
fn assert_slept(seen: &Option<Seen>, who: &str, label: &str) {
    let seen = seen
        .as_ref()
        .unwrap_or_else(|| panic!("{label}: {who} sender saw the sleep"));
    let dwell = seen.sent_at.duration_since(seen.asleep_at);
    assert!(dwell >= DWELL, "{label}: {who} slept through the dwell");
    eprintln!(
        "{label}: {who} asleep in the syscall: state S, wchan {}, {dwell:?} before the signal",
        seen.wchan
    );
}

/// The tracer wrote nothing into the guest's 8 KiB data buffer:
/// every guest-visible word there (results, handler log, the
/// `nanosleep` remainder) came from the guest or the kernel.
/// `write_mem` is the tracer's only guest-memory write path and
/// the test seam records every call.
fn assert_no_tracer_write_in_dst(t: &Translated, label: &str) {
    let (lo, hi) = (t.info.dst, t.info.dst + 8192);
    let writes = t.remote.tracer_writes_for_test();
    assert!(
        !writes.is_empty(),
        "{label}: write log recorded the setup writes"
    );
    let hits: Vec<_> = writes
        .iter()
        .filter(|&&(a, n)| a < hi && a + n as u64 > lo)
        .collect();
    assert!(
        hits.is_empty(),
        "{label}: tracer wrote into the guest data buffer: {hits:x?}"
    );
}

fn queue(sig: i32, value: u64) -> Send {
    Send::Queue {
        pid: Pid::Own,
        sig,
        signo: sig,
        code: SI_QUEUE,
        forged_sender: false,
        value,
    }
}

fn queued(signo: i32, value: u64, uc_rip_off: u64) -> Entry {
    Entry {
        signo: signo as u64,
        code: SI_QUEUE,
        pid: SenderPid::Own,
        uid: UID_WORD,
        value,
        uc_rip_off,
    }
}

fn killed(signo: i32, uc_rip_off: u64) -> Entry {
    Entry {
        signo: signo as u64,
        code: SI_USER,
        pid: SenderPid::Own,
        uid: real_uid(),
        value: 0,
        uc_rip_off,
    }
}

/// One test's hold: the serial lock, and the corpus guard every
/// pinning test carries (see `corpus`).
struct Serial {
    _corpus: corpus::Guard,
    _lock: std::sync::MutexGuard<'static, ()>,
}

fn lock() -> Serial {
    Serial {
        _lock: SERIAL.lock().unwrap_or_else(|e| e.into_inner()),
        _corpus: corpus::guard(),
    }
}

/// E1: lowest-numbered first, FIFO within an RT number, a
/// second pending standard signal coalesced (first payload
/// kept, second call still returns 0), kill-sent RT entries
/// queued with kernel sender words, and a forged-sender
/// SI_QUEUE entry carried verbatim.
#[test]
fn rt_order_retention_and_coalescing_match_native() {
    let _g = lock();
    let all = sig_bit(USR1) | sig_bit(RTMIN) | sig_bit(RTMIN + 1) | sig_bit(RTMAX);
    let spec = Spec {
        installs: [USR1, RTMIN, RTMIN + 1, RTMAX]
            .into_iter()
            .map(|s| (s, FLAGS, all))
            .collect(),
        block: all,
        sends: vec![
            queue(RTMIN + 1, 0x11),
            queue(RTMIN, 0x22),
            Send::Kill(RTMIN + 1),
            queue(USR1, 0x44),
            queue(USR1, 0x55),
            Send::Queue {
                pid: Pid::Own,
                sig: RTMAX,
                signo: RTMAX,
                code: SI_QUEUE,
                forged_sender: true,
                value: 0x66,
            },
            queue(RTMIN, 0x77),
        ],
        unblock: true,
        pending_probe: true,
    };
    let (fx, w, _t) = differential(&spec, 6, "E1");
    let r = fx.resume_off;
    assert_eq!(
        w.log,
        vec![
            queued(USR1, 0x44, r),
            queued(RTMIN, 0x22, r),
            queued(RTMIN, 0x77, r),
            queued(RTMIN + 1, 0x11, r),
            killed(RTMIN + 1, r),
            Entry {
                signo: RTMAX as u64,
                code: SI_QUEUE,
                pid: SenderPid::Other(FORGED_PID),
                uid: FORGED_UID,
                value: 0x66,
                uc_rip_off: r,
            },
        ],
        "E1 kernel order"
    );
    assert!(w.rcs.iter().all(|&rc| rc == 0), "E1 results {:x?}", w.rcs);
    assert_eq!(w.old_mask, all, "E1 old mask");
    assert_eq!(w.pending, 0, "E1 nothing left pending");
}

/// E2a: two standard signals released together with empty
/// handler masks. The kernel builds SIGUSR2's frame on top of
/// SIGUSR1's before SIGUSR1's handler runs, so SIGUSR2's
/// handler runs first and its ucontext names SIGUSR1's source
/// handler entry — not SIGUSR2's own handler (each signal has
/// a distinct one) and never the executor stub.
#[test]
fn back_to_back_standard_frames_match_native() {
    let _g = lock();
    let both = sig_bit(USR1) | sig_bit(USR2);
    let spec = Spec {
        installs: vec![(USR1, FLAGS, 0), (USR2, FLAGS, 0)],
        block: both,
        sends: vec![Send::Kill(USR1), Send::Kill(USR2)],
        unblock: true,
        pending_probe: false,
    };
    let (fx, w, _t) = differential(&spec, 2, "E2a");
    // USR1's handler is handler 0, USR2's handler 1: B's frame
    // must name A's source handler, not its own or the stub.
    assert_ne!(fx.handler_offs[0], fx.handler_offs[1], "distinct handlers");
    assert_eq!(
        w.log,
        vec![
            killed(USR2, fx.handler_offs[0]),
            killed(USR1, fx.resume_off)
        ],
        "E2a handler order and ucontext RIPs"
    );
}

/// E2b: the same back-to-back setup for two queued RT
/// signals with payloads.
#[test]
fn back_to_back_rt_frames_match_native() {
    let _g = lock();
    let both = sig_bit(RTMIN) | sig_bit(RTMIN + 1);
    let spec = Spec {
        installs: vec![(RTMIN, FLAGS, 0), (RTMIN + 1, FLAGS, 0)],
        block: both,
        sends: vec![queue(RTMIN, 0xa1), queue(RTMIN + 1, 0xb2)],
        unblock: true,
        pending_probe: false,
    };
    let (fx, w, _t) = differential(&spec, 2, "E2b");
    assert_ne!(fx.handler_offs[0], fx.handler_offs[1], "distinct handlers");
    assert_eq!(
        w.log,
        vec![
            queued(RTMIN + 1, 0xb2, fx.handler_offs[0]),
            queued(RTMIN, 0xa1, fx.resume_off)
        ],
        "E2b handler order and ucontext RIPs"
    );
}

/// E2c: back-to-back onto an ineligible second action
/// (SA_RESETHAND is unmodelled): a recovered async stop at the
/// first handler's source entry, before any handler
/// instruction retired.
#[test]
fn back_to_back_ineligible_stops_at_source_handler_entry() {
    let _g = lock();
    let both = sig_bit(USR1) | sig_bit(USR2);
    let spec = Spec {
        installs: vec![(USR1, FLAGS, 0), (USR2, FLAGS | SA_RESETHAND, 0)],
        block: both,
        sends: vec![Send::Kill(USR1), Send::Kill(USR2)],
        unblock: true,
        pending_probe: false,
    };
    let fx = build(&spec, "E2c");
    let t = run_translated(&fx);
    let Err(RunError::Fault(f)) = t.out else {
        panic!("E2c: expected recovered stop, got {:?}", t.out);
    };
    assert_eq!(f.kind, FaultKind::AsyncSignal, "E2c kind");
    assert_eq!(f.signum, USR2, "E2c signal");
    assert_ne!(fx.handler_offs[0], fx.handler_offs[1], "distinct handlers");
    let usr1_handler = t.info.base + fx.handler_offs[0];
    assert_eq!(f.src_pc, usr1_handler, "E2c src pc is USR1 source handler");
    assert_eq!(f.state.rip, usr1_handler, "E2c state rip");
    assert_eq!(f.state.rdi, USR1 as u64, "E2c handler-entry rdi");
    assert_eq!(
        f.instructions, fx.main_insns_before_resume,
        "E2c instructions"
    );
    assert_eq!(f.branches, fx.main_branches, "E2c branches");
    assert_eq!(word(&t.data, LOG_COUNT), 0, "E2c no handler ran");
}

/// E3: a thread-directed rt_tgsigqueueinfo entry (private
/// pending) is dequeued before a lower-numbered
/// process-directed entry; a 64-bit sival_ptr and forged
/// sender words arrive verbatim.
#[test]
fn tgsigqueue_private_first_and_payload_match_native() {
    let _g = lock();
    let both = sig_bit(RTMIN) | sig_bit(RTMAX);
    let ptr_value = 0xfedc_ba98_7654_3210;
    let spec = Spec {
        installs: vec![(RTMIN, FLAGS, both), (RTMAX, FLAGS, both)],
        block: both,
        sends: vec![
            queue(RTMIN, 0x31),
            Send::TgQueue {
                tgid: Pid::Own,
                tid: Pid::Own,
                sig: RTMAX,
                code: SI_QUEUE,
                forged_sender: true,
                value: ptr_value,
            },
        ],
        unblock: true,
        pending_probe: false,
    };
    let (fx, w, _t) = differential(&spec, 2, "E3");
    assert_eq!(
        w.log,
        vec![
            Entry {
                signo: RTMAX as u64,
                code: SI_QUEUE,
                pid: SenderPid::Other(FORGED_PID),
                uid: FORGED_UID,
                value: ptr_value,
                uc_rip_off: fx.resume_off,
            },
            queued(RTMIN, 0x31, fx.resume_off),
        ],
        "E3 order and payload"
    );
}

fn queue_to(pid: Pid, sig: i32, code: i32) -> Send {
    Send::Queue {
        pid,
        sig,
        signo: sig,
        code,
        forged_sender: false,
        value: 0x99,
    }
}

/// E4a: calls the kernel refuses with no side effect step and
/// get the kernel's own errno in both children: a forged code
/// (SI_USER, SI_TKILL) aimed at another pid or TID gets -EPERM
/// (`do_rt_sigqueueinfo` / `do_rt_tgsigqueueinfo` refuse
/// before any lookup), and the tg form with the child's own
/// TID but a foreign TGID gets -ESRCH from `do_send_specific`
/// whatever the code (forged SI_USER and SI_QUEUE alike).
/// Nothing is queued anywhere.
#[test]
fn kernel_refused_queue_calls_get_native_errno() {
    let _g = lock();
    let spec = Spec {
        installs: vec![],
        block: 0,
        sends: vec![
            queue_to(Pid::Raw(FOREIGN_PID), RTMIN, SI_USER),
            queue_to(Pid::Raw(FOREIGN_PID), RTMIN, SI_TKILL),
            Send::TgQueue {
                tgid: Pid::Own,
                tid: Pid::Raw(FOREIGN_PID),
                sig: RTMIN,
                code: SI_USER,
                forged_sender: false,
                value: 0x99,
            },
            Send::TgQueue {
                tgid: Pid::Raw(FOREIGN_PID),
                tid: Pid::Own,
                sig: RTMIN,
                code: SI_USER,
                forged_sender: false,
                value: 0x99,
            },
            Send::TgQueue {
                tgid: Pid::Raw(FOREIGN_PID),
                tid: Pid::Own,
                sig: RTMIN,
                code: SI_QUEUE,
                forged_sender: false,
                value: 0x99,
            },
            Send::TgQueue {
                tgid: Pid::Raw(FOREIGN_PID),
                tid: Pid::Raw(FOREIGN_PID),
                sig: RTMIN,
                code: SI_USER,
                forged_sender: false,
                value: 0x99,
            },
        ],
        unblock: false,
        pending_probe: true,
    };
    // Errno first, from guest memory whatever the outcome: a
    // tracer that refused instead of stepping leaves the
    // result slots unwritten and fails here, not later.
    let fx = build(&spec, "E3b kernel-refused queues");
    let n = run_native(&fx);
    assert_eq!(n.result, 42, "E4a native result");
    let nw = witness(&n.data, &spec, n.base, n.dst, n.pid);
    let t = run_translated(&fx);
    let tw = witness(
        &t.data,
        &spec,
        t.info.base,
        t.info.dst,
        t.remote.child_pid_for_test() as u32,
    );
    let eperm = (-(libc::EPERM as i64)) as u64;
    let esrch = (-(libc::ESRCH as i64)) as u64;
    assert_eq!(
        nw.rcs[1..7],
        [eperm, eperm, eperm, esrch, esrch, eperm],
        "E4a native errno"
    );
    assert_eq!(tw.rcs, nw.rcs, "E4a translated errno equals native");
    assert_eq!(tw, nw, "E4a translated vs native witness");
    assert_eq!(tw.pending, 0, "E4a nothing queued (guest view)");
    let out = t.out.clone().expect("E4a translated run");
    assert_eq!(out.state.rax, 42, "E4a translated result");
    assert_eq!(out.instructions, fx.main_insns, "E4a instructions");
    assert_eq!(out.branches, fx.main_branches, "E4a branches");
    assert_eq!(
        proc_pending(t.remote.child_pid_for_test()),
        0,
        "E4a nothing queued (kernel view)"
    );
}

/// Translated run that must stop with `NoHandler` at the
/// syscall of send `idx`, with nothing queued.
fn expect_refused(spec: &Spec, idx: usize, label: &str) {
    expect_refused_ext(spec, idx, label, Ext::None);
}

fn expect_refused_ext(spec: &Spec, idx: usize, label: &str, ext: Ext) {
    let fx = build(spec, label);
    let t = run_translated_full(&fx, None, ext);
    let want = RunError::Refuse(Refuse::NoHandler {
        src_pc: t.info.base + fx.send_pcs[idx],
    });
    assert_eq!(t.out.as_ref().err(), Some(&want), "{label}: outcome");
    assert_eq!(
        proc_pending(t.remote.child_pid_for_test()),
        0,
        "{label}: nothing queued"
    );
}

fn single(send: Send) -> Spec {
    Spec {
        installs: vec![],
        block: 0,
        sends: vec![send],
        unblock: false,
        pending_probe: false,
    }
}

/// E4b: a forged code aimed at the child itself. Linux
/// accepts it (self-directed rt_sigqueueinfo may carry any
/// si_code), but delivering it would forge kernel provenance,
/// so the gate refuses it by name. Deliberate divergence from
/// native; no native comparison is made.
#[test]
fn forged_sicode_to_self_refused_by_name_diverging_from_native() {
    let _g = lock();
    for (code, label) in [
        (SI_KERNEL, "E4b SI_KERNEL"),
        (SI_USER, "E4b SI_USER"),
        (SI_TKILL, "E4b SI_TKILL"),
        (1, "E4b positive 1"),
    ] {
        expect_refused(&single(queue_to(Pid::Own, USR1, code)), 0, label);
    }
    expect_refused(
        &single(Send::TgQueue {
            tgid: Pid::Own,
            tid: Pid::Own,
            sig: RTMIN,
            code: SI_KERNEL,
            forged_sender: false,
            value: 0,
        }),
        0,
        "E4b tg SI_KERNEL",
    );
}

/// A real foreign target this test spawns itself: the signal
/// native child with `sig` blocked (so a wrongly queued signal
/// stays pending and observable instead of killing it), parked
/// reading a go byte that is never sent. Its 32-byte setup
/// report is read first, which proves the mask is in place.
/// Killed and reaped on drop, so a failed assert cannot leak it.
/// `_deadline` is held only for its Drop (the run deadline).
struct Helper {
    child: Child,
    _deadline: deadline::Deadline,
}

impl Helper {
    fn spawn(sig: i32) -> Helper {
        let (child, deadline) = deadline::command_child(
            Command::new(NATIVE_CHILD)
                .args(["hex:c3", "0", "0", &sig.to_string()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped()),
        )
        .expect("spawn helper");
        let mut h = Helper {
            child,
            _deadline: deadline,
        };
        let mut raw = [0u8; 32];
        h.child
            .stdout
            .as_mut()
            .expect("helper stdout")
            .read_exact(&mut raw)
            .expect("helper setup report");
        h
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Process-level and thread-level pending words.
    fn pending(&self) -> (u64, u64) {
        let pid = self.pid();
        let words = |path: String| {
            let text = std::fs::read_to_string(&path).expect("helper status");
            text.lines()
                .filter_map(|l| {
                    l.strip_prefix("SigPnd:")
                        .or_else(|| l.strip_prefix("ShdPnd:"))
                })
                .map(|v| u64::from_str_radix(v.trim(), 16).expect("pending hex"))
                .fold(0, |acc, v| acc | v)
        };
        (
            words(format!("/proc/{pid}/status")),
            words(format!("/proc/{pid}/task/{pid}/status")),
        )
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// E4c: SI_QUEUE aimed at another task (pid, or TID for the
/// tg form) could really queue there, so the pid gate refuses
/// it by name — even for this nonexistent pid, where native
/// gets ESRCH (a conservative, disclosed divergence: the
/// tracer cannot prove the kernel would not queue). The tg
/// form with BOTH ids foreign is aimed at a real process the
/// test spawned: nothing may be queued in it.
#[test]
fn sigqueue_to_foreign_target_refused_by_name_even_where_native_errs() {
    let _g = lock();
    let helper = Helper::spawn(RTMIN);
    let hp = helper.pid();
    // Not pinned: the bytes embed this run's helper pid.
    let fx = build_unpinned(&single(Send::TgQueue {
        tgid: Pid::Raw(hp),
        tid: Pid::Raw(hp),
        sig: RTMIN,
        code: SI_QUEUE,
        forged_sender: false,
        value: 0x77,
    }));
    let t = run_translated(&fx);
    assert_eq!(
        helper.pending(),
        (0, 0),
        "E4c real foreign tgid+tid: nothing queued in the helper"
    );
    let want = RunError::Refuse(Refuse::NoHandler {
        src_pc: t.info.base + fx.send_pcs[0],
    });
    assert_eq!(
        t.out.as_ref().err(),
        Some(&want),
        "E4c real foreign tgid+tid: outcome"
    );
    assert_eq!(
        proc_pending(t.remote.child_pid_for_test()),
        0,
        "E4c real foreign tgid+tid: nothing queued in the child"
    );
    drop(t);
    drop(helper);
    expect_refused(
        &single(queue_to(Pid::Raw(FOREIGN_PID), RTMIN, SI_QUEUE)),
        0,
        "E4c pid",
    );
    expect_refused(
        &single(Send::TgQueue {
            tgid: Pid::Own,
            tid: Pid::Raw(FOREIGN_PID),
            sig: RTMIN,
            code: SI_QUEUE,
            forged_sender: false,
            value: 0,
        }),
        0,
        "E4c tid",
    );
}

/// E4d/E4e: the glibc/NPTL-reserved 32 and 33 stay outside
/// the admitted range for queueing (named refusal at the
/// syscall) and for delivery (a custom handler installed for
/// them still yields a recovered async stop, no handler run).
#[test]
fn reserved_32_33_refused_for_queue_and_delivery() {
    let _g = lock();
    for sig in [32, 33] {
        expect_refused(&single(queue(sig, 0x32)), 0, &format!("E4d queue {sig}"));
        let spec = Spec {
            installs: vec![(sig, FLAGS, 0)],
            block: 0,
            sends: vec![Send::Kill(sig)],
            unblock: false,
            pending_probe: false,
        };
        let fx = build(&spec, &format!("E4e deliver {sig}"));
        let t = run_translated(&fx);
        let Err(RunError::Fault(f)) = &t.out else {
            panic!("E4e {sig}: expected recovered stop, got {:?}", t.out);
        };
        assert_eq!(f.kind, FaultKind::AsyncSignal, "E4e {sig} kind");
        assert_eq!(f.signum, sig, "E4e {sig} signal");
        assert_eq!(word(&t.data, LOG_COUNT), 0, "E4e {sig} no handler ran");
    }
}

/// E4f, E4g, E4i: an RT handler with SA_RESETHAND (unmodelled)
/// keeps the recovered stop; an unreadable siginfo and an
/// unadmitted signal (SIGTERM) are refused by name. E4f+: with
/// I1-G2, SA_RESTART alone is admitted and changes nothing
/// outside a syscall restart (delivery matches native).
#[test]
fn rt_resethand_unreadable_unadmitted_refused() {
    let _g = lock();
    let spec = Spec {
        installs: vec![(RTMIN, FLAGS | SA_RESTART, 0)],
        block: sig_bit(RTMIN),
        sends: vec![queue(RTMIN, 0x5b)],
        unblock: true,
        pending_probe: false,
    };
    let (fx, w, _t) = differential(&spec, 1, "E4f+ SA_RESTART admitted");
    assert_eq!(
        w.log,
        vec![queued(RTMIN, 0x5b, fx.resume_off)],
        "E4f+ SA_RESTART RT delivery"
    );
    let spec = Spec {
        installs: vec![(RTMIN, FLAGS | SA_RESETHAND, 0)],
        block: 0,
        sends: vec![queue(RTMIN, 0x5a)],
        unblock: false,
        pending_probe: false,
    };
    let fx = build(&spec, "E4f RESETHAND");
    let t = run_translated(&fx);
    let Err(RunError::Fault(f)) = &t.out else {
        panic!("E4f: expected recovered stop, got {:?}", t.out);
    };
    assert_eq!(
        (f.kind, f.signum),
        (FaultKind::AsyncSignal, RTMIN),
        "E4f SA_RESETHAND RT"
    );
    expect_refused(&single(Send::QueueBadPtr(RTMIN)), 0, "E4g unreadable");
    expect_refused(
        &single(queue(libc::SIGTERM, 0)),
        0,
        "E4i unadmitted SIGTERM",
    );
}

/// E5 (review P1): an asynchronous stop that lands after a
/// redirected syscall argument was staged and before syscall
/// entry is a recovered `AsyncSignal` at the syscall's source
/// PC whose state carries the guest's own pointer, never the
/// tracer scratch address; the syscall did not execute and
/// counts stand at the instructions retired before it.
fn check_pre_entry_stop(
    fx: &Fx,
    pc_off: u64,
    retired_before: u64,
    pointer: impl Fn(&liteinst_jit::GuestState) -> u64,
    want_pointer: impl Fn(&RemoteChildInfo) -> u64,
    label: &str,
) {
    let t = run_translated_with(fx, Some(USR2));
    let Err(RunError::Fault(f)) = &t.out else {
        panic!("{label}: expected recovered stop, got {:?}", t.out);
    };
    assert_eq!(
        (f.kind, f.signum),
        (FaultKind::AsyncSignal, USR2),
        "{label}: kind/signal"
    );
    assert_eq!(f.src_pc, t.info.base + pc_off, "{label}: src pc");
    assert_eq!(f.state.rip, f.src_pc, "{label}: state rip");
    assert_eq!(
        pointer(&f.state),
        want_pointer(&t.info),
        "{label}: guest pointer argument in recovered state"
    );
    assert_eq!(f.instructions, retired_before, "{label}: instructions");
    assert_eq!(f.branches, fx.main_branches, "{label}: branches");
    assert_eq!(
        proc_pending(t.remote.child_pid_for_test()),
        0,
        "{label}: syscall did not execute"
    );
    assert_eq!(
        t.remote.pre_redirected_step_signal_for_test(),
        None,
        "{label}: seam spent (one-shot, I1-H H2c)"
    );
}

#[test]
fn async_stop_before_sigqueue_entry_keeps_guest_info_pointer() {
    let _g = lock();
    let fx = build(&single(queue(RTMIN, 0x5a)), "E5a rt_sigqueueinfo rdx");
    check_pre_entry_stop(
        &fx,
        fx.send_pcs[0],
        fx.send_before[0],
        |s| s.rdx,
        |i| i.dst + INFO as u64,
        "E5a rt_sigqueueinfo rdx",
    );
}

#[test]
fn async_stop_before_tgsigqueue_entry_keeps_guest_info_pointer() {
    let _g = lock();
    let fx = build(
        &single(Send::TgQueue {
            tgid: Pid::Own,
            tid: Pid::Own,
            sig: RTMIN,
            code: SI_QUEUE,
            forged_sender: false,
            value: 0x5a,
        }),
        "E5b rt_tgsigqueueinfo r10",
    );
    check_pre_entry_stop(
        &fx,
        fx.send_pcs[0],
        fx.send_before[0],
        |s| s.r10,
        |i| i.dst + INFO as u64,
        "E5b rt_tgsigqueueinfo r10",
    );
}

/// The same boundary on the I1-D `rt_sigaction` stubbing path,
/// which redirects the act pointer (rsi) through the same
/// scratch staging.
#[test]
fn async_stop_before_sigaction_entry_keeps_guest_act_pointer() {
    let _g = lock();
    let fx = build(
        &Spec {
            installs: vec![(RTMIN, FLAGS, 0)],
            block: 0,
            sends: vec![],
            unblock: false,
            pending_probe: false,
        },
        "E5c rt_sigaction rsi",
    );
    check_pre_entry_stop(
        &fx,
        fx.install_pcs[0],
        fx.install_before[0],
        |s| s.rsi,
        |i| i.dst,
        "E5c rt_sigaction rsi",
    );
}

/// E4h: a `si_signo` that disagrees with the requested signal
/// steps like native: the kernel overwrites it with the
/// requested signal (`__copy_siginfo_from_user`), so the
/// handler sees the requested number in both children.
#[test]
fn mismatched_si_signo_is_overwritten_like_native() {
    let _g = lock();
    let spec = Spec {
        installs: vec![(RTMIN, FLAGS, 0)],
        block: sig_bit(RTMIN),
        sends: vec![Send::Queue {
            pid: Pid::Own,
            sig: RTMIN,
            signo: RTMIN + 1,
            code: SI_QUEUE,
            forged_sender: false,
            value: 0x48,
        }],
        unblock: true,
        pending_probe: false,
    };
    let (fx, w, _t) = differential(&spec, 1, "E4h");
    assert_eq!(
        w.log,
        vec![queued(RTMIN, 0x48, fx.resume_off)],
        "E4h kernel-overwritten si_signo"
    );
}

/// The test seam is inert unless a test sets it: a fresh spawn
/// reports `None`, and every test above that does not set it
/// steps redirected syscalls without any injected signal.
#[test]
fn pre_step_test_seam_is_inert_by_default() {
    let _g = lock();
    let fx = build(&single(queue(RTMIN, 0)), "E5d seam inert");
    let (mut remote, _deadline) =
        deadline::remote_bytes(REMOTE_CHILD, &fx.bytes).expect("spawn remote");
    assert_eq!(
        remote.pre_redirected_step_signal_for_test(),
        None,
        "default"
    );
    remote.set_pre_redirected_step_signal_for_test(Some(USR2));
    assert_eq!(remote.pre_redirected_step_signal_for_test(), Some(USR2));
}

// ---- I1-G2: syscall restart (SA_RESTART and -ERESTART* codes) ----
//
// Kernel rules with a handler (arch/x86/kernel/signal.c
// `handle_signal`): -ERESTARTNOHAND and -ERESTART_RESTARTBLOCK
// become -EINTR; -ERESTARTSYS restarts (ip -= 2, ax = orig_ax)
// only under SA_RESTART. The interrupted syscall is credited
// once, at completion: an EINTR return counts, a restarted
// attempt does not, so counts keep the differential formula.

/// A signal this test process sent with a NULL-siginfo
/// pidfd_send_signal (kernel SI_USER words, sender = us).
fn sent(signo: i32, uc_rip_off: u64) -> Entry {
    Entry {
        signo: signo as u64,
        code: SI_USER,
        pid: SenderPid::Other(std::process::id()),
        uid: real_uid(),
        value: 0,
        uc_rip_off,
    }
}

fn neg(errno: i32) -> u64 {
    (-(errno as i64)) as u64
}

const NR_SUSPEND: i64 = libc::SYS_rt_sigsuspend;
const NR_FUTEX: i64 = libc::SYS_futex;
const NR_NANOSLEEP: i64 = libc::SYS_nanosleep;

/// The nanosleep remainder the kernel wrote on interruption,
/// bracketed by this child's measured times. The kernel's value
/// is `expiry - now` at the interruption, with `expiry = start +
/// req + slack` (`hrtimer_nanosleep` arms `[req, req + slack]`
/// and reports from the hard end). The sleep started after the
/// run began and no later than the sender's first asleep
/// sighting; the interruption came after the send and before
/// the run ended. So
///   req - (ended - started) <= rem
///   rem <= req + slack + res - (sent_at - asleep_at)
/// where `sent_at - asleep_at >= DWELL` (50 ms). A copied
/// request (`rem == req`) or any value not reduced by the
/// measured sleep fails; the sentinel fails `ns < 1e9`. Slack
/// is this test thread's timer slack, which both children
/// inherit (they are spawned from this thread and never change
/// it); res is the CLOCK_MONOTONIC resolution.
fn check_rem(data: &[u8], secs: u64, span: (Instant, Instant), seen: &Seen, label: &str) {
    let (s, ns) = (word(data, NANO_REM), word(data, NANO_REM + 8));
    assert!(
        ns < 1_000_000_000 && s <= secs,
        "{label}: nanosleep remainder {s}.{ns:09} written, for request {secs}"
    );
    let rem = i128::from(s) * 1_000_000_000 + i128::from(ns);
    let req = i128::from(secs) * 1_000_000_000;
    // SAFETY: prctl(PR_GET_TIMERSLACK) and clock_getres take no
    // memory arguments besides the out-struct.
    let slack = i128::from(unsafe { libc::prctl(libc::PR_GET_TIMERSLACK, 0, 0, 0, 0) });
    let mut ts: libc::timespec = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC, &mut ts) },
        0
    );
    let res = i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec);
    assert!(
        slack >= 0 && 2 * (slack + res) < DWELL.as_nanos() as i128,
        "{label}: timer slack {slack} ns + resolution {res} ns small against the dwell"
    );
    let dwell = seen.sent_at.duration_since(seen.asleep_at).as_nanos() as i128;
    let total = span.1.duration_since(span.0).as_nanos() as i128;
    let (lo, hi) = (req - total, req + slack + res - dwell);
    assert!(
        lo <= rem && rem <= hi,
        "{label}: remainder {rem} ns outside the measured bracket [{lo}, {hi}] \
         (request {req}, asleep-to-send {dwell}, run {total}, slack {slack}, res {res})"
    );
}

/// G2a: rt_sigsuspend blocked in the kernel and interrupted by
/// an external signal returns -ERESTARTNOHAND, which a handler
/// turns into -EINTR with or without SA_RESTART. The frame
/// saves the pre-suspend mask (USR1), the handler runs with
/// that mask's replacement, and sigreturn restores USR1.
#[test]
fn sigsuspend_interrupted_returns_eintr_like_native() {
    let _g = lock();
    for (flags, label) in [(FLAGS, "G2a"), (FLAGS | SA_RESTART, "G2a SA_RESTART")] {
        let spec = Spec {
            installs: vec![(USR1, flags, 0)],
            block: sig_bit(USR1),
            sends: vec![Send::Suspend(0), Send::QueryMask],
            unblock: false,
            pending_probe: false,
        };
        let (fx, w, _t, _) = differential_sent(&spec, 1, label, Some((NR_SUSPEND, USR1)));
        let pc = fx.send_pcs[0];
        assert_eq!(w.log, vec![sent(USR1, pc + 2)], "{label}: log");
        assert_eq!(
            w.frames,
            vec![(neg(libc::EINTR), sig_bit(USR1))],
            "{label}: uc RAX and saved mask"
        );
        assert_eq!(w.rcs[2], neg(libc::EINTR), "{label}: rt_sigsuspend result");
        assert_eq!(w.old_mask, sig_bit(USR1), "{label}: mask after sigreturn");
    }
}

/// G2e: two signals already pending when rt_sigsuspend
/// unblocks them: the syscall returns at once, USR1's frame
/// records -EINTR and the saved mask, and USR2's frame is
/// built back to back on top (handler mask USR1, RAX 0 as the
/// kernel leaves it at handler entry) naming USR1's source
/// handler.
#[test]
fn sigsuspend_back_to_back_frames_match_native() {
    let _g = lock();
    let both = sig_bit(USR1) | sig_bit(USR2);
    let spec = Spec {
        installs: vec![(USR1, FLAGS, 0), (USR2, FLAGS, 0)],
        block: both,
        sends: vec![
            Send::Kill(USR1),
            Send::Kill(USR2),
            Send::Suspend(0),
            Send::QueryMask,
        ],
        unblock: false,
        pending_probe: false,
    };
    let (fx, w, _t) = differential(&spec, 2, "G2e");
    let pc = fx.send_pcs[2];
    assert_ne!(
        fx.handler_offs[0], fx.handler_offs[1],
        "G2e distinct handlers"
    );
    assert_eq!(
        w.log,
        vec![killed(USR2, fx.handler_offs[0]), killed(USR1, pc + 2)],
        "G2e handler order and ucontext RIPs"
    );
    assert_eq!(
        w.frames,
        vec![(0, sig_bit(USR1)), (neg(libc::EINTR), both)],
        "G2e uc RAX and saved masks"
    );
    assert_eq!(w.rcs[5], neg(libc::EINTR), "G2e rt_sigsuspend result");
    assert_eq!(w.old_mask, both, "G2e mask after sigreturn");
}

/// G2b/G2c: FUTEX_WAIT_PRIVATE with no timeout, interrupted,
/// returns -ERESTARTSYS. With SA_RESTART the kernel rewinds to
/// the syscall (uc RIP = the syscall, uc RAX = its number); the
/// handler changed the futex word, so the restarted wait
/// returns -EAGAIN. Without SA_RESTART it returns -EINTR. The
/// restart runs both mid-block (exact re-entry) and with the
/// syscall at a block start; the pinned count credits the
/// syscall once in each.
#[test]
fn futex_wait_restarts_only_with_sa_restart_like_native() {
    let _g = lock();
    for (flags, send, restart, label) in [
        (FLAGS | SA_RESTART, futex_wait(), true, "G2b restart"),
        (
            FLAGS | SA_RESTART,
            Send::FutexWaitAtBlockStart,
            true,
            "G2b restart at block start",
        ),
        (FLAGS, futex_wait(), false, "G2c no SA_RESTART"),
    ] {
        let spec = Spec {
            installs: vec![(USR1, flags, 0)],
            block: 0,
            sends: vec![send],
            unblock: false,
            pending_probe: false,
        };
        let (fx, w, _t, _) = differential_sent(&spec, 1, label, Some((NR_FUTEX, USR1)));
        let pc = fx.send_pcs[0];
        let (uc_rip, uc_rax, rc) = if restart {
            (pc, NR_FUTEX as u64, neg(libc::EAGAIN))
        } else {
            (pc + 2, neg(libc::EINTR), neg(libc::EINTR))
        };
        assert_eq!(w.log, vec![sent(USR1, uc_rip)], "{label}: log");
        assert_eq!(w.frames, vec![(uc_rax, 0)], "{label}: uc RAX and mask");
        assert_eq!(w.rcs[2], rc, "{label}: futex result");
        assert_eq!(w.g2[3], 1, "{label}: handler set the futex word");
    }
}

/// G2d (review addition a): nanosleep returns
/// -ERESTART_RESTARTBLOCK, which is NOT -ERESTARTSYS: with a
/// handler it is -EINTR even under SA_RESTART, and the kernel
/// writes the remainder. Its value depends on elapsed time, so
/// each child's is bracketed by that child's measured sleep
/// (`check_rem`; a copied request fails); that it is the
/// kernel's own value is also shown directly: the guest's
/// pointer reached the kernel and no tracer write touched it.
#[test]
fn nanosleep_restartblock_is_eintr_even_with_sa_restart() {
    let _g = lock();
    let spec = Spec {
        installs: vec![(USR1, FLAGS | SA_RESTART, 0)],
        block: 0,
        sends: vec![Send::Nanosleep(1000)],
        unblock: false,
        pending_probe: false,
    };
    let (fx, w, t, n) = differential_sent(&spec, 1, "G2d", Some((NR_NANOSLEEP, USR1)));
    let pc = fx.send_pcs[0];
    // rem is the kernel's own value, passed straight through:
    // the call stepped with the guest's own remainder pointer
    // (rsi after the call, equal to native), and the tracer
    // wrote nothing into the guest buffer holding it (checked
    // in `differential_sent`, restated here for this range).
    assert_eq!(w.args[1], NANO_REM as u64, "G2d remainder pointer");
    let rem = t.info.dst + NANO_REM as u64;
    assert!(
        t.remote
            .tracer_writes_for_test()
            .iter()
            .all(|&(a, n)| a + n as u64 <= rem || a >= rem + 16),
        "G2d: the tracer never wrote the remainder"
    );
    assert_eq!(w.log, vec![sent(USR1, pc + 2)], "G2d log");
    assert_eq!(w.frames, vec![(neg(libc::EINTR), 0)], "G2d uc RAX and mask");
    assert_eq!(w.rcs[2], neg(libc::EINTR), "G2d nanosleep result");
    check_rem(
        &n.data,
        1000,
        n.span,
        n.seen.as_ref().unwrap(),
        "G2d native",
    );
    check_rem(
        &t.data,
        1000,
        t.span,
        t.seen.as_ref().unwrap(),
        "G2d translated",
    );
}

/// G2f (review addition a, Q4 deferral): an interrupting
/// signal with no handler (SIGWINCH, default ignore; queued
/// only because the child is traced) is a named refusal at the
/// restart exit, never injected. For nanosleep the kernel
/// would set up restart_syscall; for the futex it would
/// rewind. Neither is modelled yet.
#[test]
fn no_handler_restart_refused_by_name() {
    let _g = lock();
    for (send, nr, label) in [
        (
            Send::Nanosleep(1000),
            NR_NANOSLEEP,
            "G2f nanosleep RESTARTBLOCK",
        ),
        (futex_wait(), NR_FUTEX, "G2f futex RESTARTSYS"),
    ] {
        let fx = build(&single(send), label);
        let t = run_translated_full(&fx, None, Ext::Send(nr, libc::SIGWINCH));
        assert_slept(&t.seen, "translated", label);
        let want = RunError::Refuse(Refuse::RemoteSubstrate {
            operation: "syscall restart: signal not eligible for delivery",
            errno: 0,
        });
        assert_eq!(t.out.as_ref().err(), Some(&want), "{label}: outcome");
        assert_eq!(word(&t.data, LOG_COUNT), 0, "{label}: no handler ran");
        assert_eq!(word(&t.data, RC_BASE + 8), 0, "{label}: no result stored");
        assert_eq!(
            proc_state(t.remote.child_pid_for_test()),
            't',
            "{label}: child still in its delivery stop (nothing injected)"
        );
    }
}

/// Scheduler state letter of a live child (`/proc/<pid>/stat`
/// field 3; `t` is a ptrace stop).
fn proc_state(pid: i32) -> char {
    try_proc_state(pid).expect("child stat state")
}

fn try_proc_state(pid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    after.trim_start().chars().next()
}

/// G2g: only FUTEX_WAIT_PRIVATE with a NULL timeout and plain
/// nanosleep pass through; other futex shapes and
/// clock_nanosleep are refused at the syscall before it runs.
/// Watchdog-bounded: a gate that let the shared FUTEX_WAIT run
/// would block forever on the zero word.
#[test]
fn unadmitted_blocking_shapes_refused_at_syscall() {
    let _g = lock();
    for (send, label) in [
        (
            Send::Futex {
                op: 0,
                timeout: false,
            },
            "G2g FUTEX_WAIT (shared)",
        ),
        (
            Send::Futex {
                op: 128,
                timeout: true,
            },
            "G2g FUTEX_WAIT_PRIVATE with timeout",
        ),
        (
            Send::Futex {
                op: 129,
                timeout: false,
            },
            "G2g FUTEX_WAKE_PRIVATE",
        ),
        (Send::ClockNanosleep, "G2g clock_nanosleep"),
    ] {
        expect_refused_ext(&single(send), 0, label, Ext::Watchdog);
    }
}

/// A test-owned pipe already filled to `F_GETPIPE_SZ`, so the
/// next write to it blocks. The write end has no `FD_CLOEXEC`,
/// so every child spawned while this lives (only under
/// `SERIAL`, so only this test's children) inherits it at the
/// same descriptor number; the read end is close-on-exec, so no
/// child can drain it. Both ends close on drop.
struct FullPipe {
    _read: OwnedFd,
    write: OwnedFd,
}

impl FullPipe {
    fn new() -> FullPipe {
        let mut fds = [0i32; 2];
        // SAFETY: pipe writes two new descriptors into `fds`.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: both descriptors are fresh and owned here.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let (r, w) = (read.as_raw_fd(), write.as_raw_fd());
        // SAFETY: fcntl and write on descriptors owned here.
        unsafe {
            assert_eq!(
                libc::fcntl(r, libc::F_SETFD, libc::FD_CLOEXEC),
                0,
                "read end cloexec"
            );
            let cap = libc::fcntl(w, libc::F_GETPIPE_SZ);
            assert!(cap > 0, "F_GETPIPE_SZ");
            let fill = vec![0x5au8; cap as usize];
            assert_eq!(
                libc::write(w, fill.as_ptr().cast(), fill.len()),
                cap as isize,
                "fill the pipe to F_GETPIPE_SZ"
            );
            // Prove full: a one-byte non-blocking write is
            // refused with EAGAIN. Then clear O_NONBLOCK (it is
            // shared with every inheritor) and read it back.
            let fl = libc::fcntl(w, libc::F_GETFL);
            assert_eq!(libc::fcntl(w, libc::F_SETFL, fl | libc::O_NONBLOCK), 0);
            let one = 0u8;
            let rc = libc::write(w, (&one as *const u8).cast(), 1);
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert_eq!((rc, errno), (-1, Some(libc::EAGAIN)), "pipe is full");
            assert_eq!(libc::fcntl(w, libc::F_SETFL, fl), 0);
            assert_eq!(
                libc::fcntl(w, libc::F_GETFL) & libc::O_NONBLOCK,
                0,
                "blocking again"
            );
            assert_eq!(
                libc::fcntl(w, libc::F_GETFD) & libc::FD_CLOEXEC,
                0,
                "write end inherited"
            );
        }
        FullPipe { _read: read, write }
    }

    fn write_fd(&self) -> i32 {
        self.write.as_raw_fd()
    }
}

/// G2h (review: the restart-delivery set is a real bound): a
/// pass-through call outside {rt_sigsuspend, futex,
/// nanosleep} that a signal interrupts with a restart code
/// keeps the pre-existing named stop at its exit, with nothing
/// delivered. The harness hands both children a pipe already
/// full (`FullPipe`), so the guest's one-byte write blocks; the
/// sender interrupts it. Natively the handler runs and the
/// write returns -EINTR (no SA_RESTART), which proves the call
/// really blocked and was interrupted with -ERESTARTSYS;
/// translated, the guard stops by name. A deliberate,
/// fail-closed divergence until another call is admitted.
///
/// The pipe's fd is whatever `pipe` returns in this process, so
/// the corpus pins the fixture built with [`FD_TEMPLATE`], and the
/// bytes that run must be that template with only the fd patched
/// in ([`assert_fd_patch`]).
#[test]
fn interrupted_write_outside_restart_set_keeps_named_stop() {
    let _g = lock();
    let template = build(
        &single_with_handler(Send::WriteFd(FD_TEMPLATE)),
        "G2h interrupted write",
    );
    let pipe = FullPipe::new();
    let fd = pipe.write_fd();
    let spec = single_with_handler(Send::WriteFd(fd));
    let fx = build_unpinned(&spec);
    assert_fd_patch(&template, &fx, fd, "G2h");
    eprintln!("G2h: runtime write fd {fd} patched into the pinned template");
    let n = run_native_sent(&fx, Ext::Send(libc::SYS_write, USR1));
    assert_eq!(n.result, 42, "G2h native result");
    let nw = witness(&n.data, &spec, n.base, n.dst, n.pid);
    let pc = fx.send_pcs[0];
    assert_eq!(nw.log, vec![sent(USR1, pc + 2)], "G2h native handler ran");
    assert_eq!(nw.frames, vec![(neg(libc::EINTR), 0)], "G2h native frame");
    assert_eq!(nw.rcs[2], neg(libc::EINTR), "G2h native write result");
    assert_slept(&n.seen, "native", "G2h");
    let t = run_translated_full(&fx, None, Ext::Send(libc::SYS_write, USR1));
    assert_slept(&t.seen, "translated", "G2h");
    let want = RunError::Refuse(Refuse::RemoteSubstrate {
        operation: "syscall restart pending at exit stop",
        errno: 0,
    });
    assert_eq!(t.out.as_ref().err(), Some(&want), "G2h translated outcome");
    assert_eq!(word(&t.data, LOG_COUNT), 0, "G2h no handler ran");
    assert_eq!(word(&t.data, RC_BASE + 16), 0, "G2h no write result stored");
}

/// One USR1 handler (no SA_RESTART), nothing blocked, one send.
fn single_with_handler(send: Send) -> Spec {
    Spec {
        installs: vec![(USR1, FLAGS, 0)],
        block: 0,
        sends: vec![send],
        unblock: false,
        pending_probe: false,
    }
}

/// G2i (review: syscall identity): RAX `0x1_000000ca` runs the
/// admitted FUTEX_WAIT_PRIVATE (the kernel dispatches on the low
/// 32 bits), so its interruption is delivered like G2b's: under
/// SA_RESTART the frame rewinds to the syscall with the FULL
/// `orig_rax` in RAX, and the restarted wait returns -EAGAIN.
/// The restart set is classified by the low 32 bits, as
/// admission is; a full-width compare would stop by name here.
#[test]
fn futex_high_alias_restarts_like_native() {
    let _g = lock();
    let spec = Spec {
        installs: vec![(USR1, FLAGS | SA_RESTART, 0)],
        block: 0,
        sends: vec![Send::FutexWaitHighAlias],
        unblock: false,
        pending_probe: false,
    };
    let (fx, w, _t, _n) = differential_sent(&spec, 1, "G2i", Some((NR_FUTEX, USR1)));
    let alias = (1u64 << 32) | NR_FUTEX as u64;
    assert_eq!(w.log, vec![sent(USR1, fx.send_pcs[0])], "G2i log");
    assert_eq!(
        w.frames,
        vec![(alias, 0)],
        "G2i uc RAX is the full orig_rax"
    );
    assert_eq!(w.rcs[2], neg(libc::EAGAIN), "G2i restarted futex result");
}

/// The sender's sleep predicate (review): a child held at its
/// futex ptrace syscall-entry stop, before futex runs, already
/// shows syscall 202 in `/proc/<pid>/syscall` (so `blocked_in`
/// alone would accept it), but it is in a ptrace stop (`t`), so
/// [`asleep_in`] refuses it. The traced child is this test
/// thread's own (it spawned it), so the raw ptrace calls are
/// this thread's to make.
#[test]
fn sender_waits_for_sleep_not_syscall_entry_stop() {
    let _g = lock();
    let fx = build(&single(futex_wait()), "G2j sender sleep proof");
    let (remote, _deadline) =
        deadline::remote_bytes(REMOTE_CHILD, &fx.bytes).expect("spawn remote");
    let pid = remote.child_pid_for_test();
    let info = remote.info();
    // SAFETY: ptrace on this thread's own stopped tracee, with a
    // register struct owned here.
    let regs = unsafe {
        let mut regs: libc::user_regs_struct = core::mem::zeroed();
        let null = core::ptr::null_mut::<libc::c_void>();
        assert_eq!(libc::ptrace(libc::PTRACE_GETREGS, pid, null, &mut regs), 0);
        regs.rip = info.base + fx.send_pcs[0];
        regs.rax = libc::SYS_futex as u64;
        regs.rdi = info.dst + FUTEX_WORD as u64;
        regs.rsi = 128;
        regs.rdx = 0;
        regs.r10 = 0;
        assert_eq!(libc::ptrace(libc::PTRACE_SETREGS, pid, null, &regs), 0);
        assert_eq!(libc::ptrace(libc::PTRACE_SYSCALL, pid, null, null), 0);
        let mut status = 0;
        assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
        assert!(libc::WIFSTOPPED(status), "stopped");
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP | 0x80, "syscall stop");
        assert_eq!(libc::ptrace(libc::PTRACE_GETREGS, pid, null, &mut regs), 0);
        regs
    };
    assert_eq!(
        regs.orig_rax,
        libc::SYS_futex as u64,
        "entry stop for futex"
    );
    assert_eq!(
        regs.rax as i64,
        -(libc::ENOSYS as i64),
        "entry-stop -ENOSYS sentinel"
    );
    assert_eq!(proc_state(pid), 't', "held in a ptrace stop");
    assert!(
        blocked_in(pid as u32, NR_FUTEX),
        "the syscall number alone is visible"
    );
    assert_eq!(
        asleep_in(pid as u32, NR_FUTEX),
        None,
        "not asleep: no signal may be sent"
    );
}

/// W4 (I1-H review order, standalone fix): a BLOCKED pending
/// signal is not an event. The guest blocks USR1, sends it to
/// itself (so it is pending), then runs a loop entering its
/// block 40000 times, past two poll exits (one every 16384
/// block entries). Natively USR1 just stays pending: the
/// mid-run rt_sigpending probe shows it, in both children.
/// Only then does the guest unblock it, and the kernel delivers
/// it at the unblock's resume point, as natively. Before the
/// fix the translated run stopped at the first poll with a
/// recovered AsyncSignal.
#[test]
fn blocked_pending_signal_survives_polls_and_delivers_on_unblock() {
    let _g = lock();
    let spins = 40_000;
    assert!(
        u64::from(spins) > 2 * liteinst_jit::exec::POLL_BUDGET,
        "the loop crosses at least two poll exits"
    );
    let spec = Spec {
        installs: vec![(USR1, FLAGS, 0)],
        block: sig_bit(USR1),
        sends: vec![Send::Kill(USR1), Send::Spin(spins), Send::PendingNow],
        unblock: true,
        pending_probe: false,
    };
    let (fx, w, _t) = differential(&spec, 1, "W4");
    assert_eq!(
        w.pending_mid,
        sig_bit(USR1),
        "W4 USR1 still pending after the loop"
    );
    assert_eq!(
        w.log,
        vec![killed(USR1, fx.resume_off)],
        "W4 delivered at the unblock resume point"
    );
    assert_eq!(
        w.frames,
        vec![(0, 0)],
        "W4 uc RAX (unblock result) and saved mask"
    );
    assert!(w.rcs.iter().all(|&rc| rc == 0), "W4 results {:x?}", w.rcs);
    assert_eq!(w.old_mask, sig_bit(USR1), "W4 mask before unblock");
}

/// W4, real-time variant (review P3): the same shape with
/// SIGRTMIN, whose pending instance is queued rather than a bit.
/// It stays pending across two poll exits and is delivered at
/// the unblock resume point, as natively.
#[test]
fn blocked_pending_rt_signal_survives_polls_and_delivers_on_unblock() {
    let _g = lock();
    let spins = 40_000;
    assert!(u64::from(spins) > 2 * liteinst_jit::exec::POLL_BUDGET);
    let spec = Spec {
        installs: vec![(RTMIN, FLAGS, 0)],
        block: sig_bit(RTMIN),
        sends: vec![Send::Kill(RTMIN), Send::Spin(spins), Send::PendingNow],
        unblock: true,
        pending_probe: false,
    };
    let (fx, w, _t) = differential(&spec, 1, "W4-RT");
    assert_eq!(w.pending_mid, sig_bit(RTMIN), "W4-RT still pending");
    assert_eq!(
        w.log,
        vec![killed(RTMIN, fx.resume_off)],
        "W4-RT delivered at the unblock resume point"
    );
    assert_eq!(w.frames, vec![(0, 0)], "W4-RT uc RAX and saved mask");
    assert_eq!(w.old_mask, sig_bit(RTMIN), "W4-RT mask before unblock");
}

/// I1-H H2 (NSpid proof): the `kill` self-send gate takes the
/// same `NSpid` proof as the queueing gate. Through the test
/// seam, the proof reads a nested-namespace line (our pid, then
/// 1: the shape a child in a nested pid namespace shows), and
/// both gates must then refuse the self-send by name, with
/// nothing queued. Only the proof reads the seam's text. Without
/// the seam the same shapes deliver (the kill and queue
/// differentials above). Unreachable for real here: the tracer
/// spawns the child in its own pid namespace and guest namespace
/// changes are refused, so `rdi` equal to the tracer's pid while
/// `NSpid` disagrees needs the seam.
#[test]
fn self_sends_refused_by_name_when_nspid_shows_a_nested_namespace() {
    let _g = lock();
    for (label, send) in [
        ("H2 NSpid kill", Send::Kill(USR1)),
        ("H2 NSpid queue", queue(USR1, 0x5eed)),
    ] {
        let spec = single_with_handler(send);
        let fx = build(&spec, label);
        let t = run_translated_cfg(&fx, None, Ext::None, |r| {
            let pid = r.child_pid_for_test();
            r.set_nspid_status_for_test(Some(format!("Name:\tchild\nNSpid:\t{pid}\t1\n")));
        });
        let want = RunError::Refuse(Refuse::NoHandler {
            src_pc: t.info.base + fx.send_pcs[0],
        });
        assert_eq!(t.out.as_ref().err(), Some(&want), "{label}: outcome");
        assert_eq!(
            proc_pending(t.remote.child_pid_for_test()),
            0,
            "{label}: nothing queued"
        );
        assert_eq!(
            word(&t.data, LOG_COUNT),
            0,
            "{label}: the handler never ran"
        );
        // The same fixture without the seam delivers.
        let quiet = run_translated(&fx);
        assert!(
            quiet.out.is_ok(),
            "{label}: delivers without the seam: {:?}",
            quiet.out
        );
        assert_eq!(
            word(&quiet.data, LOG_COUNT),
            1,
            "{label}: one delivery without the seam"
        );
    }
}

/// The run deadline kills a child that outlives it and fails by
/// name (I1-H H2c; see `deadline::self_test`).
#[test]
fn deadline_self_test() {
    deadline::self_test();
}

/// Spawn census (I1-H H2c): every child this binary starts carries
/// a run deadline (`common/deadline.rs`).
#[test]
fn spawn_census() {
    deadline::spawn_census(include_str!("remote_signal_rt.rs"), "remote_signal_rt.rs");
}
