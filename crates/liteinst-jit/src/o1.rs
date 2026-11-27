//! O1 oracle: exact retired-branch and retired-instruction counts
//! by ptrace single-stepping the same fixture bytes natively in a
//! traced child. This is the primary correctness oracle for P1a;
//! counts come from the stepped instruction stream itself, never
//! from PMU counters (skid makes those a witness, not an oracle).
//!
//! Independence: step classification here is local to this module
//! (shared liteinst::x86 decoder construction, own
//! branch/return/syscall tests); it does not reuse the translator's
//! `decode` classification or envelope.
//! Step traps are qualified by `PTRACE_GETSIGINFO` provenance: only
//! `TRAP_TRACE` counts as a completed step (a stepped-over syscall
//! may report `SI_KERNEL`); any other SIGTRAP is a guest trap and
//! the instruction does not retire. REP recognition uses iced's
//! prefix flags, not a first-byte test.
//!
//! RIP-delta check (lead review Q4(b), I1-H): every retired step's
//! observed successor is checked against its decode. A
//! non-control instruction must land at `pc + len`; a conditional
//! branch at `pc + len` or its decoded target; a direct
//! `jmp`/`call` at its target; `ret` at the word at `[rsp]` before
//! the step; a syscall at `pc + len`, except `rt_sigreturn`, which
//! lands at the frame's saved RIP. An indirect `jmp r/m64` or
//! `call r/m64` must land at its operand's value read before the
//! step: the register, or the 8 bytes at the effective address,
//! which iced's own `virtual_address` computes here from the
//! step's registers (the translator's indirect resolver is not
//! used). Any other indirect form, or an operand this
//! oracle cannot read, has no prediction and fails if it retires.
//! A mismatch panics (never skipped). This verifies the decoded
//! length only where the successor depends on it (not on a taken
//! branch, a direct or indirect `jmp`/`call`, `ret` or
//! `rt_sigreturn`); SIGNAL-CORPUS.md lists the limits.
//!
//! O1-S (I1-H): [`run_o1s`] steps the same bytes in the remote
//! fixture child (so the process signal state matches a
//! translated run's) and lets the kernel deliver every signal for
//! real: each signal-delivery stop is re-injected with
//! `PTRACE_SINGLESTEP(sig)`, the kernel builds the native frame,
//! and stepping continues through the handler, the restorer and
//! `rt_sigreturn`. It can also send one signal of its own after
//! exactly `k` retired instructions ("arrival at k").

use std::io::Read;
use std::process::{Child, Command, Stdio};

use liteinst_x86::{Code, Instruction, Mnemonic, OpKind, Register, decoder64};

use crate::harness::{MappedGuest, RETURN_SENTINEL};
use crate::remote::RemoteChildInfo;
use crate::state::GuestState;

/// Child-to-parent setup report: code base, stack top, data buffer,
/// rep destination, rep/syscall source buffer (8 bytes each, LE).
#[derive(Clone, Copy, Debug, Default)]
pub struct ChildInfo {
    pub base: u64,
    pub stack_top: u64,
    pub data: u64,
    pub dst: u64,
    pub src: u64,
}

impl ChildInfo {
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        for (i, v) in [self.base, self.stack_top, self.data, self.dst, self.src]
            .iter()
            .enumerate()
        {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }
    pub fn from_bytes(b: &[u8; 40]) -> ChildInfo {
        let get = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        ChildInfo {
            base: get(0),
            stack_top: get(1),
            data: get(2),
            dst: get(3),
            src: get(4),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OracleOutcome {
    pub base: u64,
    pub stack_top: u64,
    pub info: ChildInfo,
    pub branches: u64,
    pub instructions: u64,
    pub state: GuestState,
    /// `(faulting source pc, signum)` when the guest faulted/trapped.
    pub fault: Option<(u64, i32)>,
    /// Raw `si_addr` of the faulting stop (0 when none).
    pub fault_addr: u64,
    pub dst_bytes: Vec<u8>,
    pub data_bytes: Vec<u8>,
    pub stack_window: Vec<u8>,
    pub stdout_tail: Vec<u8>,
    /// `PTRACE_SINGLESTEP` requests made by this run.
    pub steps: u64,
    /// Retired conditional branches by class:
    /// `[Jcc, LOOP/LOOPE/LOOPNE, JECXZ/JRCXZ]`.
    pub by_class: [u64; 3],
    /// The run ended on its [`O1Stop`] target.
    pub stopped_at_target: bool,
}

/// Stop condition for the k-branch oracle (remaining-RCB budget
/// experiment). The run stops at the first state, before the next
/// instruction, where exactly `branches` conditional branches have
/// retired and, when `at_offset` is set, RIP equals the child's
/// fixture base plus that offset. With `at_offset` unset that is the
/// successor of the branch that retired last (the entry state for 0);
/// with it set, it is a handoff point. The offset is base-relative
/// because every child maps the fixture at its own address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct O1Stop {
    pub branches: u64,
    pub at_offset: Option<u64>,
}

const STEP_CAP: u64 = 2_000_000;
const TRAP_BRKPT: i32 = 1;
const TRAP_TRACE: i32 = 2;
/// `si_code` of the step stop at a handler's entry after an
/// injected delivery: `signal_delivered` calls
/// `ptrace_notify(SIGTRAP, 0)` for a stepping tracee and
/// `ptrace_do_notify` reports the exit code as `si_code`, so it
/// is SIGTRAP (5), never TRAP_TRACE (2) or TRAP_BRKPT (1).
const SI_CODE_HANDLER_ENTRY: i32 = libc::SIGTRAP;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StepClass {
    Branch,
    Return,
    Syscall,
    Other,
}

fn classify_step(ins: &Instruction) -> StepClass {
    let code = ins.code();
    if code == Code::Syscall {
        return StepClass::Syscall;
    }
    if ins.mnemonic() == Mnemonic::Ret {
        return StepClass::Return;
    }
    if code.is_jcc_short()
        || code.is_jcc_near()
        || matches!(
            ins.mnemonic(),
            Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne
        )
        || matches!(code, Code::Jecxz_rel8_64 | Code::Jrcxz_rel8_64)
    {
        return StepClass::Branch;
    }
    StepClass::Other
}

/// Index into [`OracleOutcome::by_class`] for a retired branch.
fn branch_class(ins: &Instruction) -> usize {
    if matches!(
        ins.mnemonic(),
        Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne
    ) {
        1
    } else if matches!(ins.code(), Code::Jecxz_rel8_64 | Code::Jrcxz_rel8_64) {
        2
    } else {
        0
    }
}

fn decode_step(bytes: &[u8], pc: u64) -> Instruction {
    let mut decoder = decoder64(bytes, pc);
    let ins = decoder.decode();
    assert!(!ins.is_invalid(), "oracle decode at {pc:#x}");
    ins
}

/// `rt_sigreturn`, classified by the low 32 bits of RAX as the
/// kernel dispatches.
const NR_RT_SIGRETURN: u32 = 15;
/// Offset of the saved RIP in a native signal frame's ucontext
/// (`uc_mcontext` at 40, RIP is greg 16). At the restorer's
/// `syscall`, RSP points at that ucontext (the handler's `ret`
/// popped `pretcode`), which is where `rt_sigreturn` reads it.
const UC_RIP: u64 = 40 + 16 * 8;

/// The next RIP a retired step must report (see the module
/// doc's RIP-delta check).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NextRip {
    Exact(u64),
    FallOrTaken {
        fall: u64,
        taken: u64,
    },
    /// An indirect transfer with no independent prediction: a form
    /// other than `jmp r/m64` and `call r/m64` (a far `jmp`, for
    /// example), or an operand naming a register this oracle does
    /// not read (32-bit addressing, for example). Fails if it
    /// retires.
    Unverifiable,
    /// The prediction's memory read failed; the step can only
    /// fault, never retire.
    Unreadable,
}

fn read_u64(pid: i32, addr: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    read_mem(pid, addr, &mut buf).then(|| u64::from_le_bytes(buf))
}

/// Predict, before the step, where `ins` at `regs.rip` must land
/// if it retires.
fn predict_next(
    pid: i32,
    ins: &Instruction,
    class: StepClass,
    regs: &libc::user_regs_struct,
) -> NextRip {
    predict_next_with(ins, class, regs, &mut |addr: u64| read_u64(pid, addr))
}

/// [`predict_next`] with the child's memory read through
/// `read_word` (the 8 bytes at an address, `None` when they cannot
/// be read), so a test can drive the same prediction with a faked
/// child.
fn predict_next_with(
    ins: &Instruction,
    class: StepClass,
    regs: &libc::user_regs_struct,
    read_word: &mut dyn FnMut(u64) -> Option<u64>,
) -> NextRip {
    let fall = regs.rip.wrapping_add(ins.len() as u64);
    let read = |word: Option<u64>| word.map_or(NextRip::Unreadable, NextRip::Exact);
    match class {
        StepClass::Branch => NextRip::FallOrTaken {
            fall,
            taken: ins.near_branch_target(),
        },
        StepClass::Return => read(read_word(regs.rsp)),
        StepClass::Syscall if regs.rax as u32 == NR_RT_SIGRETURN => {
            read(read_word(regs.rsp.wrapping_add(UC_RIP)))
        }
        StepClass::Syscall => NextRip::Exact(fall),
        StepClass::Other => match ins.mnemonic() {
            Mnemonic::Jmp | Mnemonic::Call if ins.op0_kind() == OpKind::NearBranch64 => {
                NextRip::Exact(ins.near_branch_target())
            }
            Mnemonic::Jmp | Mnemonic::Call => predict_indirect(ins, regs, read_word),
            _ => NextRip::Exact(fall),
        },
    }
}

/// The successor of a retired indirect `jmp r/m64` or `call r/m64`
/// is the value of its operand before the step, which is
/// where the CPU transfers (a `call` reads its operand before it
/// pushes). A register operand is read from `regs`; a memory
/// operand is the 8 bytes `read_word` returns at the effective
/// address, which iced's own `virtual_address` computes from
/// `regs` (independent of the translator's indirect resolver).
/// Any other form, or a register [`ea_register`] does not read,
/// is [`NextRip::Unverifiable`]; a failed operand read is
/// [`NextRip::Unreadable`]. Both fail if the step retires.
fn predict_indirect(
    ins: &Instruction,
    regs: &libc::user_regs_struct,
    read_word: &mut dyn FnMut(u64) -> Option<u64>,
) -> NextRip {
    if !matches!(ins.code(), Code::Jmp_rm64 | Code::Call_rm64) {
        return NextRip::Unverifiable;
    }
    let target = match ins.op0_kind() {
        OpKind::Register => match gpr64(regs, ins.op0_register()) {
            Some(value) => value,
            None => return NextRip::Unverifiable,
        },
        OpKind::Memory => {
            let address = ins.virtual_address(0, 0, |reg, _, _| ea_register(regs, reg));
            let Some(address) = address else {
                return NextRip::Unverifiable;
            };
            match read_word(address) {
                Some(value) => value,
                None => return NextRip::Unreadable,
            }
        }
        _ => return NextRip::Unverifiable,
    };
    NextRip::Exact(target)
}

/// A 64-bit general register's value in `regs`; `None` for any
/// other register (a 32-bit or 16-bit name, a segment, RIP).
fn gpr64(regs: &libc::user_regs_struct, reg: Register) -> Option<u64> {
    Some(match reg {
        Register::RAX => regs.rax,
        Register::RBX => regs.rbx,
        Register::RCX => regs.rcx,
        Register::RDX => regs.rdx,
        Register::RSI => regs.rsi,
        Register::RDI => regs.rdi,
        Register::RBP => regs.rbp,
        Register::RSP => regs.rsp,
        Register::R8 => regs.r8,
        Register::R9 => regs.r9,
        Register::R10 => regs.r10,
        Register::R11 => regs.r11,
        Register::R12 => regs.r12,
        Register::R13 => regs.r13,
        Register::R14 => regs.r14,
        Register::R15 => regs.r15,
        _ => return None,
    })
}

/// A register as a 64-bit effective address reads it: a 64-bit
/// general register's value, or a segment's base (0 for ES, CS,
/// SS and DS; the thread's `fs_base` and `gs_base` for FS and GS).
/// `None` for any other register, which leaves the prediction
/// Unverifiable.
fn ea_register(regs: &libc::user_regs_struct, reg: Register) -> Option<u64> {
    match reg {
        Register::ES | Register::CS | Register::SS | Register::DS => Some(0),
        Register::FS => Some(regs.fs_base),
        Register::GS => Some(regs.gs_base),
        _ => gpr64(regs, reg),
    }
}

/// The RIP-delta check for one retired step: fails the oracle on
/// any disagreement between the decode and the trap.
fn check_next_rip(ins: &Instruction, pc: u64, predicted: NextRip, after: u64) {
    let ok = match predicted {
        NextRip::Exact(x) => after == x,
        NextRip::FallOrTaken { fall, taken } => after == fall || after == taken,
        NextRip::Unverifiable | NextRip::Unreadable => false,
    };
    assert!(
        ok,
        "O1 RIP-delta check failed: {:?} at {pc:#x} decoded len {} predicted {predicted:x?}, \
         trap reported next RIP {after:#x}",
        ins.code(),
        ins.len()
    );
}

/// True when `ins` carries a REP/REPE/REPNE prefix (any prefix
/// order), for the partially-stepped-REP retirement rule.
pub fn instruction_has_rep(ins: &Instruction) -> bool {
    let string_op = matches!(
        ins.mnemonic(),
        Mnemonic::Movsb
            | Mnemonic::Movsw
            | Mnemonic::Movsd
            | Mnemonic::Movsq
            | Mnemonic::Stosb
            | Mnemonic::Stosw
            | Mnemonic::Stosd
            | Mnemonic::Stosq
            | Mnemonic::Lodsb
            | Mnemonic::Lodsw
            | Mnemonic::Lodsd
            | Mnemonic::Lodsq
            | Mnemonic::Cmpsb
            | Mnemonic::Cmpsw
            | Mnemonic::Cmpsd
            | Mnemonic::Cmpsq
            | Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
            | Mnemonic::Insb
            | Mnemonic::Insw
            | Mnemonic::Insd
            | Mnemonic::Outsb
            | Mnemonic::Outsw
            | Mnemonic::Outsd
    );
    string_op && (ins.has_rep_prefix() || ins.has_repne_prefix())
}

/// The `ptrace` request type of the target libc: glibc declares
/// `ptrace(c_uint, ...)` with `c_uint` `PTRACE_*` constants, musl
/// declares `ptrace(c_int, ...)` with `c_int` constants. Naming the
/// libc's own type lets call sites pass `PTRACE_*` constants with no
/// cast on either libc.
#[cfg(target_env = "musl")]
type PtraceRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type PtraceRequest = libc::c_uint;

fn ptrace(req: PtraceRequest, pid: i32, addr: *mut u8, data: *mut u8) -> i64 {
    // SAFETY: raw ptrace passthrough; callers pass valid operands
    // for the specific request.
    unsafe { libc::ptrace(req, pid, addr, data) }
}

/// Make the traced child die with this tracer: with
/// `PTRACE_O_EXITKILL` the kernel sends it SIGKILL when the tracer
/// exits (kernel/ptrace.c, `exit_ptrace`), so a tracer that dies never
/// leaves its child to run on untraced. Set at the initial stop, before
/// the registers are written and before `on_spawn`.
fn set_exitkill(pid: i32) {
    let r = ptrace(
        libc::PTRACE_SETOPTIONS,
        pid,
        core::ptr::null_mut(),
        libc::PTRACE_O_EXITKILL as usize as *mut u8,
    );
    assert_eq!(
        r,
        0,
        "PTRACE_SETOPTIONS: {}",
        std::io::Error::last_os_error()
    );
}

fn get_regs(pid: i32) -> libc::user_regs_struct {
    let mut regs: libc::user_regs_struct = unsafe { core::mem::zeroed() };
    let r = ptrace(
        libc::PTRACE_GETREGS,
        pid,
        core::ptr::null_mut(),
        core::ptr::addr_of_mut!(regs).cast(),
    );
    assert_eq!(r, 0, "PTRACE_GETREGS: {}", std::io::Error::last_os_error());
    regs
}

fn set_regs(pid: i32, regs: &libc::user_regs_struct) {
    let r = ptrace(
        libc::PTRACE_SETREGS,
        pid,
        core::ptr::null_mut(),
        (regs as *const libc::user_regs_struct).cast_mut().cast(),
    );
    assert_eq!(r, 0, "PTRACE_SETREGS: {}", std::io::Error::last_os_error());
}

fn get_siginfo(pid: i32) -> libc::siginfo_t {
    let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
    let r = ptrace(
        libc::PTRACE_GETSIGINFO,
        pid,
        core::ptr::null_mut(),
        core::ptr::addr_of_mut!(info).cast(),
    );
    assert_eq!(
        r,
        0,
        "PTRACE_GETSIGINFO: {}",
        std::io::Error::last_os_error()
    );
    info
}

fn read_mem(pid: i32, addr: u64, buf: &mut [u8]) -> bool {
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: both iovecs are live for the call.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    n == buf.len() as isize
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

/// Run one named fixture natively under the oracle.
pub fn run_o1(
    child_bin: &std::path::Path,
    fixture_name: &str,
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
) -> OracleOutcome {
    run_o1_observed(child_bin, fixture_name, tweaks, |_| {})
}

/// [`run_o1`] with `on_spawn`, which gets the child pid once it is
/// stopped and ready, before the first guest step (as in
/// [`run_o1s`]); tests arm a run deadline there (I1-H H2c).
pub fn run_o1_observed(
    child_bin: &std::path::Path,
    fixture_name: &str,
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
    on_spawn: impl FnOnce(i32),
) -> OracleOutcome {
    run_o1_impl(
        child_bin,
        fixture_name.to_string(),
        Some(fixture_name),
        tweaks,
        on_spawn,
        None,
    )
}

/// [`run_o1_observed`] that stops on `stop` (the k-branch oracle):
/// see [`O1Stop`]. A run that reaches the sentinel or a fault first
/// ends there with `stopped_at_target` false.
pub fn run_o1_until_observed(
    child_bin: &std::path::Path,
    fixture_name: &str,
    stop: O1Stop,
    on_spawn: impl FnOnce(i32),
) -> OracleOutcome {
    run_o1_impl(
        child_bin,
        fixture_name.to_string(),
        Some(fixture_name),
        |_, _| {},
        on_spawn,
        Some(stop),
    )
}

/// Run arbitrary bytes natively under the oracle (generated cases).
/// Argument registers start zeroed; `tweaks` sets what it needs.
pub fn run_o1_bytes(
    child_bin: &std::path::Path,
    bytes: &[u8],
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
) -> OracleOutcome {
    run_o1_bytes_observed(child_bin, bytes, tweaks, |_| {})
}

/// [`run_o1_bytes`] with `on_spawn` (see [`run_o1_observed`]).
pub fn run_o1_bytes_observed(
    child_bin: &std::path::Path,
    bytes: &[u8],
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
    on_spawn: impl FnOnce(i32),
) -> OracleOutcome {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    run_o1_impl(
        child_bin,
        format!("hex:{hex}"),
        None,
        tweaks,
        on_spawn,
        None,
    )
}

fn run_o1_impl(
    child_bin: &std::path::Path,
    spawn_arg: String,
    named: Option<&str>,
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
    on_spawn: impl FnOnce(i32),
    stop: Option<O1Stop>,
) -> OracleOutcome {
    let mut child: Child = Command::new(child_bin)
        .arg(&spawn_arg)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn o1 child");
    let pid = child.id() as i32;
    let mut out = child.stdout.take().expect("child stdout");
    let mut raw = [0u8; 40];
    out.read_exact(&mut raw).expect("child setup report");
    let info = ChildInfo::from_bytes(&raw);
    let mut status: i32 = 0;
    // SAFETY: waiting for our own traced child.
    let w = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(w, pid, "waitpid for initial stop");
    assert!(libc::WIFSTOPPED(status), "child did not stop: {status:#x}");
    set_exitkill(pid);

    let mut regs = get_regs(pid);
    regs.rip = info.base;
    regs.rsp = info.stack_top;
    regs.eflags = 0x202; // IF set (ptrace rejects clearing it); status zero
    regs.rax = 0;
    regs.rbx = 0;
    regs.rcx = 0;
    regs.rdx = 0;
    regs.rsi = 0;
    regs.rdi = 0;
    regs.rbp = 0;
    regs.r8 = 0;
    regs.r9 = 0;
    regs.r10 = 0;
    regs.r11 = 0;
    regs.r12 = 0;
    regs.r13 = 0;
    regs.r14 = 0;
    regs.r15 = 0;
    if let Some(name) = named {
        let (rdi, rsi, rdx, rax, rcx) =
            MappedGuest::fixture_args(name, info.base, info.data, info.dst, info.src);
        regs.rdi = rdi;
        regs.rsi = rsi;
        regs.rdx = rdx;
        regs.rax = rax;
        regs.rcx = rcx;
        if name == "rep_stosb_partial" {
            regs.rdi = info.dst;
        }
    }
    tweaks(&mut regs, &info);
    set_regs(pid, &regs);
    on_spawn(pid);

    let mut branches: u64 = 0;
    let mut instructions: u64 = 0;
    let mut fault: Option<(u64, i32)> = None;
    let mut fault_addr: u64 = 0;
    let mut steps: u64 = 0;
    let mut by_class = [0u64; 3];
    let mut stopped_at_target = false;
    let final_state = loop {
        let cur = get_regs(pid);
        if let Some(s) = stop
            && branches == s.branches
            && s.at_offset
                .is_none_or(|off| info.base.wrapping_add(off) == cur.rip)
        {
            stopped_at_target = true;
            break regs_to_state(&cur);
        }
        if cur.rip == RETURN_SENTINEL {
            break regs_to_state(&cur);
        }
        let mut bytes = [0u8; 15];
        assert!(
            read_mem(pid, cur.rip, &mut bytes),
            "read insn at {:#x}",
            cur.rip
        );
        let insn = decode_step(&bytes, cur.rip);
        let class = classify_step(&insn);
        let predicted = predict_next(pid, &insn, class, &cur);
        let prev_pc = cur.rip;
        let r = ptrace(
            libc::PTRACE_SINGLESTEP,
            pid,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        assert_eq!(
            r,
            0,
            "PTRACE_SINGLESTEP: {}",
            std::io::Error::last_os_error()
        );
        steps += 1;
        assert!(steps < STEP_CAP, "oracle step cap exceeded");
        // SAFETY: waiting for our own traced child.
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            panic!("child ended unexpectedly mid-run: {status:#x}");
        }
        assert!(libc::WIFSTOPPED(status));
        let sig = libc::WSTOPSIG(status);
        let after = get_regs(pid);
        if sig == libc::SIGTRAP {
            let si_code = get_siginfo(pid).si_code;
            // Observed on this kernel: an ordinary step reports
            // TRAP_TRACE, a stepped-over syscall reports si_code 1
            // (TRAP_BRKPT); the RIP-delta check below then pins
            // where the syscall landed.
            let stepped =
                si_code == TRAP_TRACE || (class == StepClass::Syscall && si_code == TRAP_BRKPT);
            if !stepped {
                // A guest trap (int3/hardware trap), not our step:
                // the instruction does not retire.
                // SAFETY: siginfo was filled by PTRACE_GETSIGINFO.
                fault_addr = unsafe { get_siginfo(pid).si_addr() } as usize as u64;
                fault = Some((prev_pc, sig));
                break regs_to_state(&after);
            }
            let rep_still_running = after.rip == prev_pc && instruction_has_rep(&insn);
            if !rep_still_running {
                check_next_rip(&insn, prev_pc, predicted, after.rip);
                instructions += 1;
                if class == StepClass::Branch {
                    branches += 1;
                    by_class[branch_class(&insn)] += 1;
                }
            }
            continue;
        }
        if class == StepClass::Return && after.rip == RETURN_SENTINEL {
            check_next_rip(&insn, prev_pc, predicted, after.rip);
            instructions += 1;
            break regs_to_state(&after);
        }
        // SAFETY: siginfo was filled by PTRACE_GETSIGINFO.
        fault_addr = unsafe { get_siginfo(pid).si_addr() } as usize as u64;
        fault = Some((prev_pc, sig));
        break regs_to_state(&after);
    };

    let dst_len = if named == Some("rep_stosb_partial") {
        16
    } else {
        32
    };
    let mut dst_bytes = vec![0u8; dst_len];
    let _ = read_mem(pid, info.dst, &mut dst_bytes);
    let mut data_bytes = vec![0u8; 128];
    let _ = read_mem(pid, info.data, &mut data_bytes);
    let mut stack_window = vec![0u8; 136];
    let _ = read_mem(pid, info.stack_top - 128, &mut stack_window);
    ptrace(
        libc::PTRACE_KILL,
        pid,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    // SAFETY: reaping our own child.
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    let mut stdout_tail = Vec::new();
    let _ = out.read_to_end(&mut stdout_tail);
    // Already reaped via waitpid above; releases the std handle.
    let _ = child.wait();
    OracleOutcome {
        base: info.base,
        stack_top: info.stack_top,
        info,
        branches,
        instructions,
        state: final_state,
        fault,
        fault_addr,
        dst_bytes,
        data_bytes,
        stack_window,
        stdout_tail,
        steps,
        by_class,
        stopped_at_target,
    }
}

/// Kernel syscall-restart results visible at a syscall step's
/// trap while a signal is pending (`-ERESTARTSYS`,
/// `-ERESTARTNOINTR`, `-ERESTARTNOHAND`,
/// `-ERESTART_RESTARTBLOCK`): the call has not completed yet.
fn is_restart_code(rax: u64) -> bool {
    matches!(rax as i64, -512 | -513 | -514 | -516)
}

const EINTR_RAX: u64 = (-libc::EINTR) as i64 as u64;
const RFLAGS_TF: u64 = 0x100;
/// The ucontext offsets O1-S reads at handler entry: 18
/// general registers from `uc_mcontext` (40), then `uc_sigmask`.
const UC_GREGS: u64 = 40;
const UC_SIGMASK: u64 = 40 + 256;

/// One genuine delivery O1-S observed, read from the native
/// frame at the handler's entry (before its first instruction).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct O1Delivery {
    pub signo: i32,
    /// RIP at handler entry (the kernel's handler address).
    pub handler: u64,
    /// RSP at handler entry (the frame's `pretcode` slot).
    pub frame_rsp: u64,
    /// The frame's siginfo, first four words.
    pub siginfo: [u64; 4],
    /// `uc_mcontext` general registers in kernel order: r8..r15,
    /// rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags.
    pub gregs: [u64; 18],
    pub uc_sigmask: u64,
    /// Retired instructions and conditional branches before the
    /// delivery (an interrupted call converted to `-EINTR` is
    /// already credited, as it completed).
    pub instructions: u64,
    pub branches: u64,
}

/// One step O1-S took while injecting a signal (I1-H H2b, P3-A),
/// recorded whatever the step turned out to be: a handler entry,
/// or a retirement when the kernel dropped the signal (ignored
/// disposition). Records only; O1-S behaves the same.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct O1Injection {
    pub signo: i32,
    /// The PC before the step.
    pub rip: u64,
    /// Retired instructions before the step.
    pub instructions: u64,
    /// The stop's si_code (SIGTRAP 5 at a handler entry,
    /// TRAP_TRACE 2 for an ordinary step).
    pub si_code: i32,
    /// The handler-argument register shape after the step, the
    /// same value the handler-entry check uses.
    pub entry_shape: bool,
}

/// How an O1-S run ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum O1sEnd {
    /// The fixture returned to the sentinel.
    Returned,
    /// A SIGTRAP that was neither a step nor a handler entry
    /// (a guest `int3` or other trap), at this source PC.
    Trap {
        pc: u64,
    },
    /// The kernel terminated the child with this signal (for
    /// example the default action of an undelivered signal).
    Killed(i32),
    Exited(i32),
}

#[derive(Clone, Debug)]
pub struct O1sOutcome {
    pub info: RemoteChildInfo,
    /// The child's pid (reaped by the time this is returned).
    pub pid: i32,
    pub end: O1sEnd,
    pub branches: u64,
    pub instructions: u64,
    /// Final registers (meaningful for `Returned` and `Trap`).
    pub state: GuestState,
    pub deliveries: Vec<O1Delivery>,
    /// Every step taken with a signal injected, in order.
    pub injections: Vec<O1Injection>,
    /// Whether the arrival signal was sent (its `k` was reached).
    pub arrival_sent: bool,
    /// The 8 KiB destination buffer at the end (empty when the
    /// child was already gone).
    pub dst_bytes: Vec<u8>,
}

fn word_at(bytes: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap())
}

/// O1-S: run `bytes` natively under single-step in the remote
/// fixture child `child_bin`, delivering every signal for real.
/// `child_args` follow the `hex:` argument (for example
/// `block:10`, the child's initial-mask option).
///
/// The child starts from the same normalized signal state as a
/// translated run (zero dispositions, empty mask, altstack
/// disabled) and the same register preset as
/// `RemoteExecutable::initial_state` (RSP at the stack top,
/// RFLAGS 0x202, other registers zero), then `setup` adjusts it.
/// `on_spawn` gets the child pid once it is stopped and ready,
/// before the first step (for a test's external sender).
/// `arrival = Some((k, sig))` sends `sig` to the child itself
/// once exactly `k` instructions have retired, so the kernel
/// presents it before instruction `k + 1` executes.
///
/// Counting rules (the translated substrate's, stated
/// independently): every retired step counts one instruction
/// (handler and restorer included; `rt_sigreturn` is one); a
/// conditional branch counts one branch when it retires; a
/// syscall whose step trap shows a restart code is credited
/// only if the delivery that follows converts it to `-EINTR`,
/// and not if the kernel rewinds it to restart (its re-execution
/// is then the one that counts).
pub fn run_o1s(
    child_bin: &std::path::Path,
    bytes: &[u8],
    child_args: &[&str],
    setup: impl FnOnce(&mut libc::user_regs_struct, &RemoteChildInfo),
    arrival: Option<(u64, i32)>,
    on_spawn: impl FnOnce(i32),
) -> O1sOutcome {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut child: Child = Command::new(child_bin)
        .arg(format!("hex:{hex}"))
        .args(child_args)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn o1s child");
    let pid = child.id() as i32;
    let mut out = child.stdout.take().expect("child stdout");
    let mut raw = [0u8; 56];
    out.read_exact(&mut raw).expect("o1s child setup report");
    let mut dump = vec![0u8; 65 * 32];
    out.read_exact(&mut dump).expect("o1s child action dump");
    let info = RemoteChildInfo::from_bytes(&raw);
    let mut status: i32 = 0;
    // SAFETY: waiting for our own traced child.
    let w = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(w, pid, "waitpid for initial stop");
    assert!(
        libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP,
        "o1s child did not stop: {status:#x}"
    );
    set_exitkill(pid);

    let mut regs = get_regs(pid);
    regs.rip = info.base;
    regs.rsp = info.stack_top;
    regs.eflags = 0x202;
    regs.rax = 0;
    regs.rbx = 0;
    regs.rcx = 0;
    regs.rdx = 0;
    regs.rsi = 0;
    regs.rdi = 0;
    regs.rbp = 0;
    regs.r8 = 0;
    regs.r9 = 0;
    regs.r10 = 0;
    regs.r11 = 0;
    regs.r12 = 0;
    regs.r13 = 0;
    regs.r14 = 0;
    regs.r15 = 0;
    setup(&mut regs, &info);
    set_regs(pid, &regs);
    on_spawn(pid);

    let (mut branches, mut instructions) = (0u64, 0u64);
    let mut deliveries: Vec<O1Delivery> = Vec::new();
    let mut injections: Vec<O1Injection> = Vec::new();
    let mut arrival_sent = false;
    // Signal to inject with the next step (0 = none), and the
    // syscall `(pc, orig_rax)` whose restart code awaits its
    // delivery's verdict.
    let mut inject: i32 = 0;
    let mut restart: Option<(u64, u64)> = None;
    let mut steps: u64 = 0;
    let mut cur = get_regs(pid);
    let (end, final_regs) = loop {
        if cur.rip == RETURN_SENTINEL {
            break (O1sEnd::Returned, cur);
        }
        if let Some((k, sig)) = arrival
            && !arrival_sent
            && inject == 0
            && restart.is_none()
            && instructions == k
        {
            // SAFETY: signalling our own live, stopped,
            // unreaped traced child.
            let rc = unsafe { libc::kill(pid, sig) };
            assert_eq!(rc, 0, "o1s arrival kill");
            arrival_sent = true;
        }
        let mut code = [0u8; 15];
        assert!(
            read_mem(pid, cur.rip, &mut code),
            "read insn at {:#x}",
            cur.rip
        );
        let insn = decode_step(&code, cur.rip);
        let class = classify_step(&insn);
        let predicted = predict_next(pid, &insn, class, &cur);
        let delivering = inject;
        inject = 0;
        let r = ptrace(
            libc::PTRACE_SINGLESTEP,
            pid,
            core::ptr::null_mut(),
            delivering as usize as *mut u8,
        );
        assert_eq!(
            r,
            0,
            "PTRACE_SINGLESTEP: {}",
            std::io::Error::last_os_error()
        );
        steps += 1;
        assert!(steps < STEP_CAP, "o1s step cap exceeded");
        // SAFETY: waiting for our own traced child.
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        if libc::WIFSIGNALED(status) {
            break (O1sEnd::Killed(libc::WTERMSIG(status)), cur);
        }
        if libc::WIFEXITED(status) {
            break (O1sEnd::Exited(libc::WEXITSTATUS(status)), cur);
        }
        assert!(libc::WIFSTOPPED(status));
        let sig = libc::WSTOPSIG(status);
        let after = get_regs(pid);
        let si_code = get_siginfo(pid).si_code;
        // Handler entry after an injection: the kernel built the
        // frame, set RDI/RSI/RDX to the handler arguments and RSP
        // to the frame, and reports the step before the handler's
        // first instruction (no instruction retired), with
        // si_code SIGTRAP (pinned, I1-H H2). A stop with that
        // frame shape and any other non-step si_code fails here
        // by name instead of falling through as something else.
        let entry_shape = after.rdi == delivering as u64 && after.rdx == after.rsp.wrapping_add(8);
        let handler_entry = delivering != 0
            && sig == libc::SIGTRAP
            && si_code == SI_CODE_HANDLER_ENTRY
            && entry_shape;
        assert!(
            handler_entry
                || delivering == 0
                || sig != libc::SIGTRAP
                || si_code == TRAP_TRACE
                || !entry_shape,
            "o1s: handler-entry-shaped stop after injecting {delivering} at {:#x} has si_code \
             {si_code}, not SIGTRAP ({SI_CODE_HANDLER_ENTRY})",
            cur.rip
        );
        if delivering != 0 {
            injections.push(O1Injection {
                signo: delivering,
                rip: cur.rip,
                instructions,
                si_code,
                entry_shape,
            });
        }
        if handler_entry {
            let mut frame = [0u8; 8 * 18];
            assert!(
                read_mem(pid, after.rdx.wrapping_add(UC_GREGS), &mut frame),
                "o1s frame gregs"
            );
            let gregs: [u64; 18] = core::array::from_fn(|i| word_at(&frame, i));
            let mut si = [0u8; 32];
            assert!(read_mem(pid, after.rsi, &mut si), "o1s frame siginfo");
            let uc_sigmask =
                read_u64(pid, after.rdx.wrapping_add(UC_SIGMASK)).expect("o1s frame mask");
            if let Some((pc, orig)) = restart.take() {
                let (uc_rip, uc_rax) = (gregs[16], gregs[13]);
                if uc_rip == pc && uc_rax == orig {
                    // Rewound to restart: its re-execution counts.
                } else if uc_rip == pc.wrapping_add(2) && uc_rax == EINTR_RAX {
                    instructions += 1;
                } else {
                    panic!(
                        "o1s: interrupted syscall at {pc:#x} resolved to neither restart \
                         nor -EINTR (uc rip {uc_rip:#x}, rax {uc_rax:#x})"
                    );
                }
            }
            deliveries.push(O1Delivery {
                signo: delivering,
                handler: after.rip,
                frame_rsp: after.rsp,
                siginfo: core::array::from_fn(|i| word_at(&si, i)),
                gregs,
                uc_sigmask,
                instructions,
                branches,
            });
            cur = after;
            continue;
        }
        // A pending restart's next stop must be the interrupting
        // signal's delivery stop (re-injected below), never a step.
        assert!(
            restart.is_none() || sig != libc::SIGTRAP,
            "o1s: syscall restart code at {:#x} not followed by a delivery",
            restart.map_or(0, |r| r.0)
        );
        if sig == libc::SIGTRAP && si_code == TRAP_TRACE {
            let rep_still_running = after.rip == cur.rip && instruction_has_rep(&insn);
            if !rep_still_running {
                check_next_rip(&insn, cur.rip, predicted, after.rip);
                instructions += 1;
                if class == StepClass::Branch {
                    branches += 1;
                }
            }
            cur = after;
            continue;
        }
        if sig == libc::SIGTRAP && class == StepClass::Syscall && si_code == TRAP_BRKPT {
            check_next_rip(&insn, cur.rip, predicted, after.rip);
            let mut after = after;
            if cur.rax as u32 != NR_RT_SIGRETURN
                && after.r11 & RFLAGS_TF != 0
                && cur.eflags & RFLAGS_TF == 0
            {
                // `syscall` saved RFLAGS into R11 with the trap
                // flag this oracle set for the step; the guest's
                // own TF is clear, so the untraced value has it
                // clear too. Remove the observer's bit.
                after.r11 &= !RFLAGS_TF;
                set_regs(pid, &after);
            }
            if cur.rax as u32 != NR_RT_SIGRETURN && is_restart_code(after.rax) {
                restart = Some((cur.rip, after.orig_rax));
            } else {
                instructions += 1;
            }
            cur = after;
            continue;
        }
        if sig == libc::SIGTRAP {
            break (O1sEnd::Trap { pc: cur.rip }, after);
        }
        if class == StepClass::Return && after.rip == RETURN_SENTINEL {
            check_next_rip(&insn, cur.rip, predicted, after.rip);
            instructions += 1;
            break (O1sEnd::Returned, after);
        }
        // Any other stop is a signal the kernel is about to
        // deliver (sent, or a fault of the instruction, which did
        // not retire): re-inject it so the kernel acts on it with
        // the real disposition.
        assert_eq!(
            after.rip, cur.rip,
            "o1s: signal {sig} stop moved RIP without a step trap"
        );
        inject = sig;
        cur = after;
    };
    let mut dst_bytes = vec![0u8; 8192];
    let alive = !matches!(end, O1sEnd::Killed(_) | O1sEnd::Exited(_));
    if !alive || !read_mem(pid, info.dst, &mut dst_bytes) {
        dst_bytes.clear();
    }
    if alive {
        ptrace(
            libc::PTRACE_KILL,
            pid,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        // SAFETY: reaping our own child.
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
    }
    let mut rest = Vec::new();
    let _ = out.read_to_end(&mut rest);
    let _ = child.wait();
    O1sOutcome {
        info,
        pid,
        end,
        branches,
        instructions,
        state: regs_to_state(&final_regs),
        deliveries,
        injections,
        arrival_sent,
        dst_bytes,
    }
}

#[cfg(test)]
mod tests {
    //! Controls for the indirect RIP-delta prediction.
    //! Each drives the production path a step takes before it
    //! single-steps (`decode_step`, `classify_step`,
    //! `predict_next_with`) and then `check_next_rip`; only the child
    //! is faked: its registers and its memory words.

    use super::*;

    const PC: u64 = 0x10_0000;
    /// `jmp qword ptr [rax*8+0x3000]`, 7 bytes.
    const JMP_TABLE: [u8; 7] = [0xff, 0x24, 0xc5, 0x00, 0x30, 0x00, 0x00];

    /// Zeroed registers at `PC`, then `set` adjusts them.
    fn regs_at_pc(set: impl FnOnce(&mut libc::user_regs_struct)) -> libc::user_regs_struct {
        // SAFETY: user_regs_struct is plain integers; all zeros is a
        // valid value.
        let mut regs: libc::user_regs_struct = unsafe { core::mem::zeroed() };
        regs.rip = PC;
        set(&mut regs);
        regs
    }

    /// The faked child's memory: 8-byte words by address.
    fn word_at(memory: &[(u64, u64)], addr: u64) -> Option<u64> {
        memory.iter().find(|&&(a, _)| a == addr).map(|&(_, v)| v)
    }

    /// Decode `bytes` at RIP, classify and predict, as a step does.
    fn predict(
        bytes: &[u8],
        regs: &libc::user_regs_struct,
        memory: &[(u64, u64)],
    ) -> (Instruction, NextRip) {
        let ins = decode_step(bytes, regs.rip);
        let class = classify_step(&ins);
        let mut read_word = |addr: u64| word_at(memory, addr);
        let predicted = predict_next_with(&ins, class, regs, &mut read_word);
        (ins, predicted)
    }

    /// Whether the RIP-delta check fails a retirement at `after`. A
    /// failure must be the check's own assertion.
    fn check_fails(ins: &Instruction, predicted: NextRip, after: u64) -> bool {
        let step = || check_next_rip(ins, PC, predicted, after);
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)) {
            Ok(()) => false,
            Err(payload) => {
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or_default();
                assert!(
                    message.starts_with("O1 RIP-delta check failed"),
                    "the check panicked with something else: {message}"
                );
                true
            }
        }
    }

    /// `jmp rax` predicts exactly RAX, and a retirement there passes.
    #[test]
    fn indirect_register_target_is_exact() {
        let target = PC + 0x40;
        let regs = regs_at_pc(|r| r.rax = target);
        let (ins, predicted) = predict(&[0xff, 0xe0], &regs, &[]);
        assert_eq!(ins.code(), Code::Jmp_rm64);
        assert_eq!(
            predicted,
            NextRip::Exact(target),
            "O1 indirect prediction: jmp rax"
        );
        assert!(!check_fails(&ins, predicted, target));
    }

    /// `jmp [rax*8+0x3000]` predicts the table entry RAX selects,
    /// read from the faked child's memory.
    #[test]
    fn indirect_memory_target_is_the_table_entry() {
        let (entry, other) = (PC + 0x80, PC + 0xc0);
        let regs = regs_at_pc(|r| r.rax = 2);
        let memory = [(0x3008, other), (0x3010, entry)];
        let (ins, predicted) = predict(&JMP_TABLE, &regs, &memory);
        assert_eq!(ins.code(), Code::Jmp_rm64);
        assert_eq!(
            predicted,
            NextRip::Exact(entry),
            "O1 indirect prediction: jmp [rax*8+0x3000]"
        );
        assert!(!check_fails(&ins, predicted, entry));
    }

    /// `jmp [rip+0x10]` reads its operand after the 6-byte
    /// instruction, at `PC + 6 + 0x10`.
    #[test]
    fn indirect_rip_relative_target_is_read_after_the_instruction() {
        let target = PC + 0x100;
        let regs = regs_at_pc(|_| {});
        let memory = [(PC + 0x16, target)];
        let (ins, predicted) = predict(&[0xff, 0x25, 0x10, 0, 0, 0], &regs, &memory);
        assert_eq!(
            predicted,
            NextRip::Exact(target),
            "O1 indirect prediction: jmp [rip+0x10]"
        );
        assert!(!check_fails(&ins, predicted, target));
    }

    /// `call [rsp]` reads its operand at RSP before it pushes.
    #[test]
    fn indirect_call_reads_its_operand_before_the_push() {
        let target = PC + 0x200;
        let regs = regs_at_pc(|r| r.rsp = 0x7000);
        let memory = [(0x7000, target), (0x6ff8, PC + 3)];
        let (ins, predicted) = predict(&[0xff, 0x14, 0x24], &regs, &memory);
        assert_eq!(ins.code(), Code::Call_rm64);
        assert_eq!(
            predicted,
            NextRip::Exact(target),
            "O1 indirect prediction: call [rsp]"
        );
        assert!(!check_fails(&ins, predicted, target));
    }

    /// `jmp fs:[0x10]` adds the thread's FS base.
    #[test]
    fn indirect_fs_relative_target_adds_the_fs_base() {
        let target = PC + 0x300;
        let regs = regs_at_pc(|r| r.fs_base = 0x9000);
        let memory = [(0x9010, target), (0x10, PC)];
        let bytes = [0x64, 0xff, 0x24, 0x25, 0x10, 0, 0, 0];
        let (ins, predicted) = predict(&bytes, &regs, &memory);
        assert_eq!(
            predicted,
            NextRip::Exact(target),
            "O1 indirect prediction: jmp fs:[0x10]"
        );
        assert!(!check_fails(&ins, predicted, target));
    }

    /// The wrong-target control: `jmp rax` passes at RAX, and fails
    /// one past it, at the fall-through `pc + len` a non-control
    /// instruction would take, and at zero.
    #[test]
    fn indirect_wrong_register_target_fails() {
        let target = PC + 0x40;
        let regs = regs_at_pc(|r| r.rax = target);
        let (ins, predicted) = predict(&[0xff, 0xe0], &regs, &[]);
        assert_eq!(predicted, NextRip::Exact(target));
        assert!(!check_fails(&ins, predicted, target));
        for wrong in [target + 1, PC + 2, 0] {
            assert!(
                check_fails(&ins, predicted, wrong),
                "jmp rax: wrong target {wrong:#x} passed the RIP-delta check"
            );
        }
    }

    /// The wrong-target control for a memory operand: it passes at
    /// the selected table entry, and fails on the neighbouring entry
    /// and on the fall-through.
    #[test]
    fn indirect_wrong_memory_target_fails() {
        let (entry, other) = (PC + 0x80, PC + 0xc0);
        let regs = regs_at_pc(|r| r.rax = 2);
        let memory = [(0x3008, other), (0x3010, entry)];
        let (ins, predicted) = predict(&JMP_TABLE, &regs, &memory);
        assert_eq!(predicted, NextRip::Exact(entry));
        assert!(!check_fails(&ins, predicted, entry));
        for wrong in [other, PC + 7] {
            assert!(
                check_fails(&ins, predicted, wrong),
                "jmp [rax*8+0x3000]: wrong target {wrong:#x} passed the RIP-delta check"
            );
        }
    }

    /// An operand that cannot be read predicts Unreadable: the step
    /// could only fault, so a retirement fails the check.
    #[test]
    fn indirect_unreadable_operand_fails_if_it_retires() {
        let regs = regs_at_pc(|r| r.rax = 2);
        let (ins, predicted) = predict(&JMP_TABLE, &regs, &[]);
        assert_eq!(predicted, NextRip::Unreadable);
        assert!(
            check_fails(&ins, predicted, PC + 7),
            "unreadable operand: a retirement passed the RIP-delta check"
        );
    }

    /// Forms this oracle does not predict stay Unverifiable and fail
    /// if they retire, even where the CPU would really land: 32-bit
    /// addressing (`jmp [eax]`) and a far `jmp m16:32`.
    #[test]
    fn indirect_unpredicted_forms_fail_if_they_retire() {
        let regs = regs_at_pc(|r| r.rax = 0x3000);
        let memory = [(0x3000, PC + 0x40)];
        for bytes in [&[0x67, 0xff, 0x20][..], &[0xff, 0x2c, 0x24][..]] {
            let (ins, predicted) = predict(bytes, &regs, &memory);
            assert_eq!(predicted, NextRip::Unverifiable, "{:?}", ins.code());
            assert!(
                check_fails(&ins, predicted, PC + 0x40),
                "{:?}: an unpredicted form passed the RIP-delta check",
                ins.code()
            );
        }
    }
}
