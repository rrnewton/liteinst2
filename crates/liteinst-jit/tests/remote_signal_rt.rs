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
//! Fixtures are assembled with iced-x86 `CodeAssembler`.
//! Layout: one `SA_SIGINFO` handler per installed signal (same
//! body, distinct offsets, so a frame naming the wrong handler
//! is visible), the restorer (`mov eax,15; syscall`), then
//! straight-line main code (every main instruction retires
//! exactly once). Buffer offsets are `[rbx]` (rbx = dst; only
//! `dst[0..640]` is reported by the native child):
//! - `0..32` act, `0x80` new mask, `0x88` old mask,
//!   `0x90` rt_sigpending set;
//! - `152 + 8*k` the pointer argument register (`rsi` for
//!   `rt_sigaction`, `rdx`/`r10` for the queue calls) right
//!   after the k-th redirected syscall;
//! - `256 + 8*k` result of the k-th recorded syscall;
//! - `376` next log entry pointer, `384` log entry count,
//!   `392 + 40*i` entry i: siginfo words 0, 8, 16, 24 and the
//!   ucontext RIP;
//! - `1024..1152` the siginfo a queue call sends (unreported).
//!
//! Each test holds `SERIAL`: ptrace children and signals from
//! different tests must not overlap.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use iced_x86::BlockEncoderOptions;
use iced_x86::code_asm::*;
use liteinst_jit::exec::{FaultKind, Outcome, RunError};
use liteinst_jit::harness::RETURN_SENTINEL;
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

const ARG_BASE: i32 = 152;
const RC_BASE: i32 = 256;
const LOG_PTR: i32 = 376;
const LOG_COUNT: i32 = 384;
const LOG_BASE: i32 = 392;
const ENTRY_LEN: i32 = 40;
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

fn build(spec: &Spec) -> Fx {
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
        a.mov(qword_ptr(rbx + 8), flags as i32).unwrap();
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
    for send in &spec.sends {
        let mut at = a.create_label();
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
        }
        a.set_label(&mut at).unwrap();
        send_before.push((a.instructions().len() - m0) as u64);
        a.syscall().unwrap();
        rc.store(&mut a);
        let arg = match send {
            Send::Queue { .. } => Some(rdx),
            Send::TgQueue { .. } => Some(r10),
            Send::Kill(_) | Send::QueueBadPtr(_) => None,
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
    }
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
/// and the handler log.
#[derive(Debug, Eq, PartialEq)]
struct Witness {
    rcs: Vec<u64>,
    args: Vec<u64>,
    old_mask: u64,
    pending: u64,
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
    Witness {
        rcs: (0..n_rc(spec) as i32)
            .map(|k| word(data, RC_BASE + 8 * k))
            .collect(),
        args: (0..n_args(spec) as i32)
            .map(|k| word(data, ARG_BASE + 8 * k).wrapping_sub(dst))
            .collect(),
        old_mask: word(data, 0x88),
        pending: word(data, 0x90),
        log,
    }
}

fn n_args(spec: &Spec) -> usize {
    spec.installs.len()
        + spec
            .sends
            .iter()
            .filter(|s| matches!(s, Send::Queue { .. } | Send::TgQueue { .. }))
            .count()
}

fn n_rc(spec: &Spec) -> usize {
    spec.installs.len()
        + 1
        + spec.sends.len()
        + usize::from(spec.unblock)
        + usize::from(spec.pending_probe)
}

struct Translated {
    remote: RemoteExecutable,
    info: RemoteChildInfo,
    out: Result<Outcome, RunError>,
    data: Vec<u8>,
}

fn run_translated(fx: &Fx) -> Translated {
    run_translated_with(fx, None)
}

/// `pre_step_signal`: the tracer's test seam sends this signal
/// to its own child after a redirected syscall argument is
/// staged and just before the step resumes the child.
fn run_translated_with(fx: &Fx, pre_step_signal: Option<i32>) -> Translated {
    let mut remote = RemoteExecutable::spawn_bytes(std::path::Path::new(REMOTE_CHILD), &fx.bytes)
        .expect("spawn remote");
    assert_eq!(
        remote.pre_redirected_step_signal_for_test(),
        None,
        "test seam inert at spawn"
    );
    remote.set_pre_redirected_step_signal_for_test(pre_step_signal);
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
    let out = remote.run(s, RETURN_SENTINEL);
    let mut data = vec![0u8; 640];
    assert!(remote.read_mem(info.dst, &mut data));
    Translated {
        remote,
        info,
        out,
        data,
    }
}

struct Native {
    result: u64,
    data: Vec<u8>,
    base: u64,
    dst: u64,
    pid: u32,
}

fn run_native(fx: &Fx) -> Native {
    let hex: String = fx.bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut child = Command::new(NATIVE_CHILD)
        .args([
            format!("hex:{hex}"),
            fx.main_off.to_string(),
            fx.restorer_off.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn native child");
    let pid = child.id();
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
    let mut out = vec![0u8; 8 + 640];
    stdout.read_exact(&mut out).expect("native result");
    let status = child.wait().expect("wait native child");
    assert!(status.success(), "native child status {status}");
    Native {
        result: u64::from_le_bytes(out[0..8].try_into().unwrap()),
        data: out[8..].to_vec(),
        base,
        dst,
        pid,
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
    let fx = build(spec);
    let n = run_native(&fx);
    assert_eq!(n.result, 42, "{label}: native result");
    let nw = witness(&n.data, spec, n.base, n.dst, n.pid);
    // Guest-visible witness first, whatever the translated
    // outcome: a tracer that stops early or corrupts a frame
    // fails on the substantive difference, not on an unwrap.
    let t = run_translated(&fx);
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
        fx.main_insns + deliveries * (fx.handler_insns + 2),
        "{label}: instructions"
    );
    assert_eq!(out.branches, fx.main_branches, "{label}: branches");
    (fx, tw, t)
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

fn lock() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
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
/// (SA_RESTART stays refused until I1-G2): a recovered async
/// stop at the first handler's source entry, before any
/// handler instruction retired.
#[test]
fn back_to_back_ineligible_stops_at_source_handler_entry() {
    let _g = lock();
    let both = sig_bit(USR1) | sig_bit(USR2);
    let spec = Spec {
        installs: vec![(USR1, FLAGS, 0), (USR2, FLAGS | SA_RESTART, 0)],
        block: both,
        sends: vec![Send::Kill(USR1), Send::Kill(USR2)],
        unblock: true,
        pending_probe: false,
    };
    let fx = build(&spec);
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
        ],
        unblock: false,
        pending_probe: true,
    };
    // Errno first, from guest memory whatever the outcome: a
    // tracer that refused instead of stepping leaves the
    // result slots unwritten and fails here, not later.
    let fx = build(&spec);
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
        nw.rcs[1..6],
        [eperm, eperm, eperm, esrch, esrch],
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
    let fx = build(spec);
    let t = run_translated(&fx);
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

/// E4c: SI_QUEUE aimed at another task (pid, or TID for the
/// tg form) could really queue there, so the pid gate refuses
/// it by name — even for this nonexistent pid, where native
/// gets ESRCH (a conservative, disclosed divergence: the
/// tracer cannot prove the kernel would not queue).
#[test]
fn sigqueue_to_foreign_target_refused_by_name_even_where_native_errs() {
    let _g = lock();
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
        let fx = build(&spec);
        let t = run_translated(&fx);
        let Err(RunError::Fault(f)) = &t.out else {
            panic!("E4e {sig}: expected recovered stop, got {:?}", t.out);
        };
        assert_eq!(f.kind, FaultKind::AsyncSignal, "E4e {sig} kind");
        assert_eq!(f.signum, sig, "E4e {sig} signal");
        assert_eq!(word(&t.data, LOG_COUNT), 0, "E4e {sig} no handler ran");
    }
}

/// E4f, E4g, E4i: an RT handler with SA_RESTART (I1-G2) keeps
/// the recovered stop; an unreadable siginfo and an unadmitted
/// signal (SIGTERM) are refused by name.
#[test]
fn rt_restart_unreadable_unadmitted_refused() {
    let _g = lock();
    let spec = Spec {
        installs: vec![(RTMIN, FLAGS | SA_RESTART, 0)],
        block: 0,
        sends: vec![queue(RTMIN, 0x5a)],
        unblock: false,
        pending_probe: false,
    };
    let fx = build(&spec);
    let t = run_translated(&fx);
    let Err(RunError::Fault(f)) = &t.out else {
        panic!("E4f: expected recovered stop, got {:?}", t.out);
    };
    assert_eq!(
        (f.kind, f.signum),
        (FaultKind::AsyncSignal, RTMIN),
        "E4f SA_RESTART RT"
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
}

#[test]
fn async_stop_before_sigqueue_entry_keeps_guest_info_pointer() {
    let _g = lock();
    let fx = build(&single(queue(RTMIN, 0x5a)));
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
    let fx = build(&single(Send::TgQueue {
        tgid: Pid::Own,
        tid: Pid::Own,
        sig: RTMIN,
        code: SI_QUEUE,
        forged_sender: false,
        value: 0x5a,
    }));
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
    let fx = build(&Spec {
        installs: vec![(RTMIN, FLAGS, 0)],
        block: 0,
        sends: vec![],
        unblock: false,
        pending_probe: false,
    });
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
    let fx = build(&single(queue(RTMIN, 0)));
    let mut remote = RemoteExecutable::spawn_bytes(std::path::Path::new(REMOTE_CHILD), &fx.bytes)
        .expect("spawn remote");
    assert_eq!(
        remote.pre_redirected_step_signal_for_test(),
        None,
        "default"
    );
    remote.set_pre_redirected_step_signal_for_test(Some(USR2));
    assert_eq!(remote.pre_redirected_step_signal_for_test(), Some(USR2));
}
