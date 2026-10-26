//! Genuine rt_sigreturn transport. A restored RAX is not an ordinary syscall
//! semantic result, and an actual EXIT remains distinct from the private bridge.
use super::lifecycle::NativeLifecycle;
use super::signal_journal::{SignalJournalFact, SignalJournalPhase, SignalJournalWriter};
use super::trusted::{AdmissionPhase, AdmissionStop, TaskStateSnapshot, TrustedIsland};
use super::*;
use crate::selected::{Operation, SelectedInput, SyscallAbi};

pub(super) struct NativeSignalReturn {
    pub(super) entry: DynamicEvent,
    pub(super) entry_state: TaskStateSnapshot,
    pub(super) exit: DynamicEvent,
    pub(super) returned: TaskStateSnapshot,
    pub(super) information: DynamicSignalReturnInfo,
    pub(super) syscall_bytes: [u8; 88],
    pub(super) syscall_count: usize,
}

pub(super) struct ReturnStates<'a> {
    pub(super) before: &'a TaskStateSnapshot,
    pub(super) expected: &'a TaskStateSnapshot,
    /// Caller-authenticated immutable native ABI extent, not a caller budget.
    pub(super) extent: usize,
}

struct Capture {
    event: DynamicEvent,
    state: TaskStateSnapshot,
    information: libc::ptrace_syscall_info,
    bytes: [u8; 88],
    count: usize,
}

fn next(
    owner: &mut Owner,
    native: &mut NativeLifecycle,
    journal: &SignalJournalWriter,
    original_tid: i32,
    extent: usize,
    until: Instant,
) -> Result<Capture, LaunchError> {
    let (tid, status) = owner.wait_raw(until, "original rt_sigreturn syscall phase")?;
    // Capture both results before interpreting either; an invalid/failed info
    // query does not discard an independently observed register/XSTATE prefix.
    let ((information, bytes, count), state) = journal.capture_syscall_state(tid, status)?;
    if tid != original_tid
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != (libc::SIGTRAP | 0x80)
        || status >> 16 != 0
        || state.registers.cs != 0x33
        || state.xstate.len() != extent
    {
        return Err(LaunchError::Invalid(
            "rt_sigreturn reached another raw native phase",
        ));
    }
    let event = native
        .observe_admission_other(owner, tid, status)?
        .ok_or(LaunchError::Invalid(
            "rt_sigreturn native syscall observation is unresolved",
        ))?;
    if TaskStateSnapshot::read(tid)? != state
        || information.arch != AUDIT_ARCH_X86_64
        || information.instruction_pointer != state.registers.rip
        || information.stack_pointer != state.registers.rsp
    {
        return Err(LaunchError::Invalid(
            "rt_sigreturn raw observation changed during authentication",
        ));
    }
    Ok(Capture {
        event,
        state,
        information,
        bytes,
        count,
    })
}

/// # Safety
/// The caller closed original release, holds the exact singleton mm, restored
/// the complete original SYSCALL bytes/RX under exclusion, authenticated every
/// live frame byte and both retained landing routes, and reserved all evidence.
/// No publication lease is retained across this one native invocation.
pub(super) unsafe fn execute(
    owner: &mut Owner,
    native: &mut NativeLifecycle,
    island: &TrustedIsland,
    current: &AdmissionStop,
    input: &SelectedInput,
    states: ReturnStates<'_>,
    until: Instant,
) -> Result<NativeSignalReturn, LaunchError> {
    let ReturnStates {
        before,
        expected,
        extent,
    } = states;
    let result = (|| {
        let tid = current.token.tid;
        owner.time_left(until, "original rt_sigreturn source")?;
        let membership = native.check_admission_mm(owner, current.identity.task)?;
        if membership.candidate.tasks != vec![current.identity.task]
            || membership.generation != island.generation
            || membership.address_space != island.address_space
            || !native.admission_events_empty()
            || native.admission_interrupt_credit(tid)? != 0
            || input.instruction().operation()
                != (Operation::Syscall {
                    abi: SyscallAbi::LinuxX64,
                })
            || input.instruction().bytes() != [0x0f, 0x05]
            || input.registers() != &before.registers
            || before.registers.rax != libc::SYS_rt_sigreturn as u64
            || before.registers.orig_rax != u64::MAX
            || before.registers.eflags & (0x100 | 0x10000) != 0
            || expected.registers.orig_rax != u64::MAX
            || expected.registers.cs != 0x33
            || extent < 512
            || extent >= MAX_XSTATE
            || extent % 8 != 0
            || before.xstate.len() != extent
            || expected.xstate.len() != extent
            || TaskStateSnapshot::read(tid)? != *before
        {
            return Err(LaunchError::Invalid("rt_sigreturn original permit differs"));
        }
        native.require_admission_stop(current)?;
        island.verify(tid)?;
        let pc = before.registers.rip;
        if read_memory(tid, pc, 2)? != [0x0f, 0x05]
            || !read_maps(tid)?.iter().any(|map| {
                map.start <= pc && pc + 2 <= map.end && map.permissions.as_bytes() == b"r-xp"
            })
        {
            return Err(LaunchError::Invalid(
                "rt_sigreturn original bytes/RX changed",
            ));
        }
        let journal = owner
            .signal_journal
            .as_ref()
            .ok_or(LaunchError::Invalid("rt_sigreturn journal is absent"))?
            .clone();
        journal.phase(SignalJournalPhase::ReturnEntry)?;
        journal.append(SignalJournalFact::ReleaseAttempt {
            token: (&current.token).into(),
        })?;
        owner.time_left(until, "original rt_sigreturn instruction release")?;
        unsafe {
            native.begin_admission_original(owner, current, libc::PTRACE_SYSCALL)?;
        }
        journal.append(SignalJournalFact::Released {
            token: (&current.token).into(),
        })?;
        let entry = next(owner, native, &journal, tid, extent, until)?;
        let next_pc = input.instruction().next_pc();
        let mut expected_entry = before.registers;
        expected_entry.rip = next_pc;
        expected_entry.rcx = next_pc;
        expected_entry.r11 = before.registers.eflags;
        expected_entry.orig_rax = libc::SYS_rt_sigreturn as u64;
        expected_entry.rax = (-i64::from(libc::ENOSYS)) as u64;
        if entry.event.task != Some(current.identity)
            || entry.event.kind
                != (DynamicEventKind::SyscallEntry {
                    number: libc::SYS_rt_sigreturn as u64,
                    arguments: arguments(&before.registers),
                })
            || entry.information.op != libc::PTRACE_SYSCALL_INFO_ENTRY
            || entry.state.registers != expected_entry
            || entry.state.xstate != before.xstate
            || entry.state.mask != before.mask
        {
            return Err(LaunchError::Invalid(
                "original rt_sigreturn ENTRY full state differs",
            ));
        }
        journal.append(SignalJournalFact::Validated {
            phase: SignalJournalPhase::ReturnEntry,
        })?;
        let entry_token = entry
            .event
            .stop_token()
            .ok_or(LaunchError::Invalid("rt_sigreturn ENTRY lacks token"))?
            .clone();
        journal.phase(SignalJournalPhase::ReturnRelease)?;
        journal.append(SignalJournalFact::ReleaseAttempt {
            token: (&entry_token).into(),
        })?;
        owner.time_left(until, "original rt_sigreturn kernel release")?;
        unsafe {
            native.resume_admission_event(owner, &entry_token, DynamicResume::Continue)?;
        }
        journal.append(SignalJournalFact::Released {
            token: (&entry_token).into(),
        })?;
        journal.phase(SignalJournalPhase::ReturnObserved)?;
        let exit = next(owner, native, &journal, tid, extent, until)?;
        if exit.information.op != libc::PTRACE_SYSCALL_INFO_EXIT
            || exit.event.task != Some(current.identity)
            || exit.state != *expected
        {
            return Err(LaunchError::Invalid(
                "original rt_sigreturn restored full state differs from the complete frame",
            ));
        }
        let raw_exit = unsafe { exit.information.u.exit };
        if raw_exit.is_error > 1
            || raw_exit.sval as u64 != expected.registers.rax
            || exit.event.kind
                != (DynamicEventKind::SyscallExit {
                    result: raw_exit.sval,
                    is_error: raw_exit.is_error != 0,
                })
        {
            return Err(LaunchError::Invalid(
                "original rt_sigreturn raw EXIT result differs",
            ));
        }
        journal.append(SignalJournalFact::Validated {
            phase: SignalJournalPhase::ReturnObserved,
        })?;
        Ok(NativeSignalReturn {
            entry: entry.event,
            entry_state: entry.state,
            exit: exit.event,
            returned: exit.state,
            information: DynamicSignalReturnInfo {
                architecture: exit.information.arch,
                instruction_pointer: exit.information.instruction_pointer,
                stack_pointer: exit.information.stack_pointer,
                result: raw_exit.sval,
                is_error: raw_exit.is_error != 0,
            },
            syscall_bytes: exit.bytes,
            syscall_count: exit.count,
        })
    })();
    if let Err(error) = &result {
        if let Some(journal) = &owner.signal_journal {
            journal.fail_error(error);
        }
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
    }
    result
}

/// Convert this already authenticated actual signal return to a genuine neutral
/// user checkpoint without executing the restored landing instruction. The
/// original EXIT evidence remains separate and unchanged in the archive.
pub(super) fn bridge(
    owner: &mut Owner,
    native: &mut NativeLifecycle,
    island: &TrustedIsland,
    returned: &NativeSignalReturn,
    until: Instant,
) -> Result<AdmissionStop, LaunchError> {
    let result = (|| {
        let token = returned
            .exit
            .stop_token()
            .ok_or(LaunchError::Invalid("signal return EXIT lacks token"))?;
        let task = token.task.ok_or(LaunchError::Invalid(
            "signal return EXIT lacks task identity",
        ))?;
        let membership = native.check_admission_mm(owner, task)?;
        if membership.candidate.tasks != vec![task]
            || native.admission_held_event(task)? != returned.exit
            || TaskStateSnapshot::read(token.tid)? != returned.returned
        {
            return Err(LaunchError::Invalid(
                "signal return bridge lost its actual full EXIT",
            ));
        }
        island.verify(token.tid)?;
        let journal = owner.signal_journal.as_ref().unwrap().clone();
        journal.phase(SignalJournalPhase::ReturnBridge)?;
        let saved = &returned.returned;
        let injected = trusted::temporary(&saved.registers, island.trap());
        // SAFETY: execute above retained actual ENTRY/EXIT and independently
        // compared every restored field to the complete qualified saved frame.
        unsafe {
            native.begin_admission_sigreturn_bridge(token, saved)?;
        }
        set_registers(token.tid, &injected)?;
        let setup = TaskStateSnapshot {
            registers: injected,
            xstate: saved.xstate.clone(),
            mask: saved.mask,
        };
        if TaskStateSnapshot::read(token.tid)? != setup {
            return Err(LaunchError::Invalid(
                "signal return bridge setup changed unrelated state",
            ));
        }
        owner.time_left(until, "signal return neutral release")?;
        ptrace(libc::PTRACE_CONT, token.tid, 0, 0)?;
        owner.released(token.tid);
        let (tid, status) = owner.wait_raw(until, "signal return neutral stop")?;
        let (raw_info, actual) = journal.capture_signal_state(tid, status)?;
        let info = DynamicSignalInfo { raw: raw_info };
        let mut expected = setup;
        expected.registers.rip = island
            .trap()
            .checked_add(1)
            .ok_or(LaunchError::Invalid("signal return trap overflows"))?;
        if tid != token.tid
            || !libc::WIFSTOPPED(status)
            || status >> 16 != 0
            || libc::WSTOPSIG(status) != libc::SIGTRAP
            || info.signal() != libc::SIGTRAP
            || !matches!(info.code(), libc::SI_KERNEL | libc::TRAP_BRKPT)
            || actual != expected
            || read_memory(tid, island.trap(), 1)? != [0xcc]
        {
            return Err(LaunchError::Invalid(
                "signal return neutral trap or full state differs",
            ));
        }
        saved.restore(tid)?;
        let current = native.finish_admission_execution(
            tid,
            saved.registers.rip,
            AdmissionPhase::Restored,
        )?;
        let after = native.check_admission_mm(owner, task)?;
        if after.address_space != membership.address_space
            || after.generation != membership.generation
            || after.tids != membership.tids
            || after.process != membership.process
            || after.tgid != membership.tgid
            || after.candidate.tasks != membership.candidate.tasks
            || after.candidate.obligations != membership.candidate.obligations
        {
            return Err(LaunchError::Invalid(
                "signal return neutral bridge changed membership/obligations",
            ));
        }
        island.verify(tid)?;
        Ok(current)
    })();
    if let Err(error) = &result {
        if let Some(journal) = &owner.signal_journal {
            journal.fail_error(error);
        }
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
    }
    result
}
