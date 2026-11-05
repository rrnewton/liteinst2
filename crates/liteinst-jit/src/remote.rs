//! Remote ptrace direct-block substrate (P1b I1-B, internal
//! and unstable).
//!
//! A traced fixture child executes the same translations as
//! the in-process executor, with this tracer as dispatcher:
//! common exits trap (`ExitStyle::TrapToDispatcher`), faults
//! and signal stops are turned into exact source state by the
//! shared recovery core (`crate::recovery`), and the corpus
//! syscalls/nondeterministic instructions the stage admits are
//! serviced by stepping the original instruction in the child.
//! No signal delivery, indirect resolution, thread, or exec
//! support is added here; those stay refused by name exactly
//! as in-process. This module is a substrate for later P1b
//! stages, not a public API contract.

use std::io::Read;
use std::process::{Child, Command, Stdio};

use crate::decode::{InsnClass, NondetKind};
use crate::exec::{CODE_CAP, Fault, Outcome, POLL_BUDGET, RunError, syscall_guard};
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
/// The only syscall number the I1-B fixture corpus uses and the
/// only one pass-through stepping may execute (`SYS_write` from
/// `syscall_write`). The lifecycle guard always runs first;
/// any other number stops by name (`NoHandler`) rather than
/// executing. This is a stage bound, not a generic
/// guest-syscall claim.
const PASS_THROUGH_SYSCALLS: &[u32] = &[libc::SYS_write as u32];

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

fn write_mem(pid: i32, addr: u64, buf: &[u8]) -> Result<(), Refuse> {
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

/// A prepared remote direct-block executable. Dropping it
/// kills and reaps the child on every path.
pub struct RemoteExecutable {
    guard: ChildGuard,
    info: RemoteChildInfo,
    translation: Option<Translation>,
    profile: CountProfile,
}

impl RemoteExecutable {
    pub fn spawn_named(child_bin: &std::path::Path, fixture_name: &str) -> Result<Self, Refuse> {
        Self::spawn(child_bin, fixture_name.to_string())
    }

    pub fn spawn_bytes(child_bin: &std::path::Path, bytes: &[u8]) -> Result<Self, Refuse> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Self::spawn(child_bin, format!("hex:{hex}"))
    }

    fn spawn(child_bin: &std::path::Path, spawn_arg: String) -> Result<Self, Refuse> {
        let child = Command::new(child_bin)
            .arg(&spawn_arg)
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| remote_err("spawn remote child"))?;
        let pid = child.id() as i32;
        let mut guard = ChildGuard {
            child,
            pid,
            reaped: false,
        };
        let mut raw = [0u8; 56];
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
        }
        let info = RemoteChildInfo::from_bytes(&raw);
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
        Ok(RemoteExecutable {
            guard,
            info,
            translation: None,
            profile: CountProfile::BranchesAndInstructions,
        })
    }

    pub fn info(&self) -> RemoteChildInfo {
        self.info
    }

    #[doc(hidden)]
    pub fn child_pid_for_test(&self) -> i32 {
        self.guard.pid
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
        if translation.code.len() > CODE_CAP {
            return Err(Refuse::BudgetExceeded { what: "code cache" });
        }
        write_mem(self.guard.pid, self.info.arena_base, &translation.code)?;
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

    fn fault_from_stop(
        &self,
        sig: i32,
        regs: &libc::user_regs_struct,
        data: &JitData,
    ) -> Result<Fault, Refuse> {
        let t = self.translation.as_ref().expect("prepared");
        let info = get_siginfo(self.guard.pid)?;
        // SAFETY: siginfo was filled by PTRACE_GETSIGINFO.
        let addr = unsafe { info.si_addr() } as usize as u64;
        // An int3 stop reports the PC after the trap byte; other
        // stops report the interrupted PC directly. Ptrace has
        // no REG_ERR, so fetch-provenance address translation is
        // unavailable on this substrate (err stays 0); the I1-B
        // fault fixtures are data faults and FPE, which do not
        // need it.
        let gen_pc = if sig == libc::SIGTRAP {
            regs.rip.saturating_sub(1)
        } else {
            regs.rip
        };
        let stop = crate::recovery::recover(
            t,
            self.profile,
            RecoveryInput {
                provenance: FaultInput {
                    gen_pc,
                    addr,
                    signum: sig,
                    si_code: info.si_code,
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
        );
        Ok(Fault {
            also_pending: Vec::new(),
            kind: stop.kind,
            src_pc: stop.src_pc,
            addr: stop.addr,
            signum: stop.signum,
            state: stop.state,
            branches: stop.branches,
            instructions: stop.instructions,
        })
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
        if sig == libc::SIGTRAP {
            return Ok(regs_to_state(&regs));
        }
        Err(RunError::Fault(Box::new(
            self.fault_from_stop(sig, &regs, data)?,
        )))
    }

    /// Execute one genuine guest syscall at `pc` via
    /// PTRACE_SYSCALL entry/exit stops. Returns the resulting
    /// guest state (kernel-produced clobbers included).
    fn step_syscall(
        &self,
        mut state: GuestState,
        pc: u64,
        data: &JitData,
    ) -> Result<GuestState, RunError> {
        state.rip = pc;
        self.set_guest_regs(&state)?;
        for _ in 0..2 {
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
            if sig != (libc::SIGTRAP | 0x80) {
                let regs = get_regs(self.guard.pid)?;
                return Err(RunError::Fault(Box::new(
                    self.fault_from_stop(sig, &regs, data)?,
                )));
            }
        }
        Ok(regs_to_state(&get_regs(self.guard.pid)?))
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
        let mut poll_remaining = POLL_BUDGET;
        loop {
            let Some(&gen_entry) = t.block_gen.get(&state.rip) else {
                return Err(Refuse::IndirectUnresolved { src_pc: state.rip }.into());
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
            let is_exit_trap = sig == libc::SIGTRAP
                && t.pcmap.lookup(regs.rip.saturating_sub(1)).is_some_and(|e| {
                    matches!(e.recovery, crate::pcmap::Recovery::CommonExit { .. })
                });
            if !is_exit_trap {
                return Err(RunError::Fault(Box::new(
                    self.fault_from_stop(sig, &regs, &data)?,
                )));
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
                    state.rsp = state.rsp.wrapping_add(8).wrapping_add(data.exit_next);
                    state.rip = target;
                    if target == return_sentinel {
                        let mut out = done;
                        out.state = state;
                        return Ok(out);
                    }
                }
                exit_kind::POLL => {
                    state.rip = data.exit_src;
                    let pending = self.pending_async()?;
                    if let Some((&sig, rest)) = pending.split_first() {
                        return Err(RunError::Fault(Box::new(Fault {
                            also_pending: rest.to_vec(),
                            kind: crate::recovery::FaultKind::AsyncSignal,
                            src_pc: data.exit_src,
                            addr: 0,
                            signum: sig,
                            state,
                            branches: done.branches,
                            instructions: done.instructions,
                        })));
                    }
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
                    syscall_guard(t, data.exit_src, state.rax)?;
                    if !PASS_THROUGH_SYSCALLS.contains(&(state.rax as u32)) {
                        return Err(Refuse::NoHandler {
                            src_pc: data.exit_src,
                        }
                        .into());
                    }
                    state = self.step_syscall(state, data.exit_src, &data)?;
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
