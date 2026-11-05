//! O1 oracle: exact retired-branch and retired-instruction counts
//! by ptrace single-stepping the same fixture bytes natively in a
//! traced child. This is the primary correctness oracle for P1a;
//! counts come from the stepped instruction stream itself, never
//! from PMU counters (skid makes those a witness, not an oracle).
//!
//! Independence: step classification here is local to this module
//! (iced decoder directly, own branch/return/syscall tests); it does
//! not reuse the translator's `decode` classification or envelope.
//! Step traps are qualified by `PTRACE_GETSIGINFO` provenance: only
//! `TRAP_TRACE` counts as a completed step (a stepped-over syscall
//! may report `SI_KERNEL`); any other SIGTRAP is a guest trap and
//! the instruction does not retire. REP recognition uses iced's
//! prefix flags, not a first-byte test.

use std::io::Read;
use std::process::{Child, Command, Stdio};

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic};

use crate::harness::{MappedGuest, RETURN_SENTINEL};
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
    pub dst_bytes: Vec<u8>,
    pub data_bytes: Vec<u8>,
    pub stack_window: Vec<u8>,
    pub stdout_tail: Vec<u8>,
}

const STEP_CAP: u64 = 4_000_000;
const TRAP_TRACE: i32 = 2;

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

fn decode_step(bytes: &[u8], pc: u64) -> Instruction {
    let mut decoder = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE);
    let ins = decoder.decode();
    assert!(!ins.is_invalid(), "oracle decode at {pc:#x}");
    ins
}

/// True when `ins` carries a REP/REPE/REPNE prefix (any prefix
/// order), for the partially-stepped-REP retirement rule.
pub fn instruction_has_rep(ins: &Instruction) -> bool {
    ins.has_rep_prefix() || ins.has_repne_prefix()
}

fn ptrace(req: u32, pid: i32, addr: *mut u8, data: *mut u8) -> i64 {
    // SAFETY: raw ptrace passthrough; callers pass valid operands
    // for the specific request.
    unsafe { libc::ptrace(req as libc::c_uint, pid, addr, data) }
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
    run_o1_impl(
        child_bin,
        fixture_name.to_string(),
        Some(fixture_name),
        tweaks,
    )
}

/// Run arbitrary bytes natively under the oracle (generated cases).
/// Argument registers start zeroed; `tweaks` sets what it needs.
pub fn run_o1_bytes(
    child_bin: &std::path::Path,
    bytes: &[u8],
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
) -> OracleOutcome {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    run_o1_impl(child_bin, format!("hex:{hex}"), None, tweaks)
}

fn run_o1_impl(
    child_bin: &std::path::Path,
    spawn_arg: String,
    named: Option<&str>,
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
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

    let mut branches: u64 = 0;
    let mut instructions: u64 = 0;
    let mut fault: Option<(u64, i32)> = None;
    let mut steps: u64 = 0;
    let final_state = loop {
        let cur = get_regs(pid);
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
            // TRAP_TRACE, a stepped-over syscall reports si_code 1.
            // A guest int3 (class Other) reports neither as a step.
            let stepped = si_code == TRAP_TRACE || class == StepClass::Syscall;
            if !stepped {
                // A guest trap (int3/hardware trap), not our step:
                // the instruction does not retire.
                fault = Some((prev_pc, sig));
                break regs_to_state(&after);
            }
            let rep_still_running = after.rip == prev_pc && instruction_has_rep(&insn);
            if !rep_still_running {
                instructions += 1;
                if class == StepClass::Branch {
                    branches += 1;
                }
            }
            continue;
        }
        if class == StepClass::Return && after.rip == RETURN_SENTINEL {
            instructions += 1;
            break regs_to_state(&after);
        }
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
        dst_bytes,
        data_bytes,
        stack_window,
        stdout_tail,
    }
}
