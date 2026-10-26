//! Scoped Linux i386 INT80 execution from native long mode. This module never
//! relaxes the ordinary owner's x86-64 syscall-event parser or allowlist.

use super::*;
use crate::selected::{
    SelectedArguments, SelectedInput, SelectedResult, SyscallAbi, SyscallAliases, SyscallResult,
    decode,
};

const AUDIT_ARCH_I386: u32 = 0x4000_0003;

enum Int80Event {
    Syscall(libc::ptrace_syscall_info),
    Other(ProcessEvent),
}

impl SingleThreadStop<'_> {
    /// Executes one declared Linux i386 INT80 getpid (20) or gettid (224) from
    /// CS 0x33, without executing the application continuation or setting TF.
    ///
    /// The exact complete encoding, including valid ignored prefixes, must be
    /// present at `expected_pc` under an acknowledged owned stop. The request
    /// is the low 32 bits of RAX. Only the ordinary TF/RF-clear flag profile and
    /// positive current-task identity results are qualified. Other INT80 calls
    /// and SYSENTER refuse; this does not authorize i386 syscalls in the normal
    /// resume loop. Entry/exit authentication compares every GPR, flags, segment,
    /// XSTATE byte and both the raw saved and truncated semantic argument views.
    ///
    /// Linux kernel bookkeeping changes orig_rax to the zero-extended low32
    /// number. After verifying the complete native return profile, an actual
    /// private INT3 materializes user return and restores that exact state.
    /// An uncertain execution, unexpected result or bridge failure closes the
    /// owner. An actual application signal remains pending and unacknowledged.
    pub fn execute_linux_int80_getid(
        &mut self,
        expected_pc: u64,
        expected_bytes: &[u8],
        timeout: Duration,
    ) -> Result<NativeSyscallOutcome, LaunchError> {
        let until = deadline(timeout)?;
        self.process.owned_signal_stop()?;
        if expected_bytes.is_empty() || expected_bytes.len() > 15 {
            return Err(LaunchError::Invalid("invalid INT80 encoding length"));
        }
        let mut aliases = SyscallAliases::new();
        aliases
            .declare(expected_pc, SyscallAbi::LinuxI386Int80)
            .map_err(|_| LaunchError::Invalid("invalid INT80 declaration"))?;
        let decoded = decode(expected_pc, expected_bytes, &aliases)
            .map_err(|_| LaunchError::Invalid("requires one Linux INT80 instruction"))?;
        if decoded.bytes() != expected_bytes {
            return Err(LaunchError::Invalid("INT80 encoding has trailing bytes"));
        }
        let next_pc = decoded.next_pc();
        let before = self.read_registers()?;
        let input = SelectedInput::new(decoded, before)
            .map_err(|_| LaunchError::Invalid("INT80 needs exact PC and native CS"))?;
        let mut expected = input
            .complete(SelectedResult::Syscall(
                SyscallResult::LinuxI386Int80GetId {
                    value: self.pid() as u32,
                },
            ))
            .map_err(|_| LaunchError::Invalid("unqualified INT80 getid input"))?
            .after;
        let number = u64::from(before.rax as u32);
        expected.orig_rax = number;
        let raw_arguments = [
            before.rbx, before.rcx, before.rdx, before.rsi, before.rdi, before.rbp,
        ];
        let semantic_arguments = raw_arguments.map(|value| u64::from(value as u32));
        if input.arguments()
            != (SelectedArguments::Syscall {
                abi: SyscallAbi::LinuxI386Int80,
                number,
                arguments: semantic_arguments,
            })
        {
            return Err(LaunchError::Invalid("INT80 semantic input differs"));
        }
        if self.read_memory(expected_pc, expected_bytes.len())? != expected_bytes {
            return Err(LaunchError::Invalid("INT80 source bytes differ"));
        }
        let before_xstate = self.read_xstate()?;
        let outcome = (|| {
            single_task(self.pid())?;
            verify_island(self.pid(), &self.mappings(), &self.process.island)?;
            let entry = match resume_int80(self.process, until)? {
                Int80Event::Syscall(info) => info,
                Int80Event::Other(event) => return self.native_syscall_terminal(event),
            };
            let mut expected_entry = before;
            expected_entry.rip = next_pc;
            expected_entry.rax = (-i64::from(libc::ENOSYS)) as u64;
            expected_entry.orig_rax = number;
            if entry.op != libc::PTRACE_SYSCALL_INFO_ENTRY
                || entry.instruction_pointer != next_pc
                || entry.stack_pointer != before.rsp
                || self.read_registers()? != expected_entry
                || self.read_xstate()? != before_xstate
            {
                return Err(LaunchError::Invalid(
                    "INT80 entry state did not authenticate",
                ));
            }
            // SAFETY: ENTRY above authenticates this initialized union member.
            let entry = unsafe { entry.u.entry };
            if entry.nr != number
                || entry.args != raw_arguments
                || entry.args.map(|value| u64::from(value as u32)) != semantic_arguments
            {
                return Err(LaunchError::Invalid(
                    "INT80 raw or semantic arguments differ",
                ));
            }
            let exit = match resume_int80(self.process, until)? {
                Int80Event::Syscall(info) => info,
                Int80Event::Other(event) => return self.native_syscall_terminal(event),
            };
            let registers = self.read_registers()?;
            let extended = self.read_xstate()?;
            if exit.op != libc::PTRACE_SYSCALL_INFO_EXIT
                || exit.instruction_pointer != next_pc
                || exit.stack_pointer != before.rsp
                || registers != expected
                || extended != before_xstate
            {
                return Err(LaunchError::Invalid(
                    "INT80 exit state did not authenticate",
                ));
            }
            // SAFETY: EXIT above authenticates this initialized union member.
            let exit = unsafe { exit.u.exit };
            if exit.is_error != 0 || exit.sval != i64::from(self.pid()) {
                return Err(LaunchError::Invalid(
                    "INT80 did not return the owned identity",
                ));
            }
            single_task(self.pid())?;
            let island = self.process.island.clone();
            verify_island(self.pid(), &self.mappings(), &island)?;
            self.process.state = State::Running;
            syscall_return_bridge(
                &mut self.process.checkpoint.child,
                island.start + 2,
                &registers,
                &extended,
                until,
            )?;
            single_task(self.pid())?;
            verify_island(self.pid(), &self.mappings(), &island)?;
            syscall_time_left(until)?;
            self.process.state = State::Stopped(Phase::OwnedTrap);
            Ok(NativeSyscallOutcome::Completed(Box::new(
                NativeSyscallCompletion {
                    registers,
                    xstate: extended,
                    result: exit.sval,
                    is_error: false,
                },
            )))
        })();
        match outcome {
            Ok(outcome) => Ok(outcome),
            Err(error) => self.process.fail(error),
        }
    }
}

// This parser is reachable only within the checked operation above. No ABI
// permission survives its return, and no public pending i386 entry is exposed.
fn resume_int80(process: &mut StoppedProcess, until: Instant) -> Result<Int80Event, LaunchError> {
    process.ensure_stopped()?;
    syscall_time_left(until)?;
    single_task(process.pid())?;
    if process.island.contains(&process.read_registers()?.rip) {
        return Err(LaunchError::Invalid(
            "application entered private INT80 island",
        ));
    }
    ptrace(libc::PTRACE_SYSCALL, process.pid(), 0, 0)?;
    process.state = State::Running;
    let status = process.checkpoint.child.wait(until, "owned INT80 event")?;
    if libc::WIFSTOPPED(status)
        && status >> 16 == 0
        && libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80
    {
        let info = syscall_info(process.pid())?;
        if info.arch != AUDIT_ARCH_I386 || process.island.contains(&info.instruction_pointer) {
            return Err(LaunchError::Invalid(
                "INT80 syscall ABI did not authenticate",
            ));
        }
        process.state = State::Stopped(match info.op {
            libc::PTRACE_SYSCALL_INFO_ENTRY => Phase::SyscallEntry,
            libc::PTRACE_SYSCALL_INFO_EXIT => Phase::SyscallExit,
            _ => return Err(LaunchError::Invalid("missing INT80 syscall phase")),
        });
        Ok(Int80Event::Syscall(info))
    } else {
        process.event(status).map(Int80Event::Other)
    }
}
