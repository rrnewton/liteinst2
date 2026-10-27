//! Allocation-free semantic checks of prepaid, retained actual journal copies.
//! The view and all expected facts are descriptions, never execution authority.
use super::admitted::AdmittedView;
use super::observe::Frame;
use super::{Experiment, OracleError};
use crate::linux::remote::dynamic::admission::AdmissionReply;
use crate::linux::remote::dynamic::owner::kernel_journal::{
    JournalAttemptView, JournalBindingView, JournalCounts, JournalPartialView, JournalStateView,
    JournalWriterTransition, KernelAttemptId, KernelStopIdentity, KernelWriterStatus,
    RuntimeKernelFact as Fact, RuntimeKernelJournalStage as Stage, RuntimeKernelMapsSummary,
    RuntimeKernelRawRecord as Raw, RuntimeKernelReleasePhase as Release,
    RuntimeKernelReleaseSource as Source, RuntimeKernelRequest as Request,
    RuntimeKernelStateSlot as Slot,
};
use crate::linux::remote::dynamic::owner::trusted::TaskStateSnapshot;
use crate::selected::{SelectedArguments, SelectedInput, SyscallAbi};
use crate::{DynamicAdmissionEvent, DynamicTask, RegisterSnapshot, SelectedExecution};
use std::mem::size_of;

type Result<T> = std::result::Result<T, OracleError>;
const MAX: usize = 65536;
const SLOTS: [Slot; 8] = [
    Slot::Original,
    Slot::Entry,
    Slot::Exit,
    Slot::BridgeTrap,
    Slot::RestoredReturn,
    Slot::Closed,
    Slot::PreExit,
    Slot::Unexpected,
];
fn require(value: bool, message: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(OracleError::Invalid(message))
    }
}
fn zero() -> Option<Request> {
    Some(Request {
        result: 0,
        errno: None,
    })
}

#[derive(Eq, PartialEq)]
struct State<'a> {
    registers: RegisterSnapshot,
    xstate: &'a [u8],
    mask: u64,
}
fn registers(bytes: &[u8; 216]) -> RegisterSnapshot {
    // Decode all27 native UAPI words without a query, pointer cast or allocation.
    let word =
        |i: usize| u64::from_ne_bytes(bytes[i * 8..i * 8 + 8].try_into().expect("fixed ABI word"));
    RegisterSnapshot {
        r15: word(0),
        r14: word(1),
        r13: word(2),
        r12: word(3),
        rbp: word(4),
        rbx: word(5),
        r11: word(6),
        r10: word(7),
        r9: word(8),
        r8: word(9),
        rax: word(10),
        rcx: word(11),
        rdx: word(12),
        rsi: word(13),
        rdi: word(14),
        orig_rax: word(15),
        rip: word(16),
        cs: word(17),
        eflags: word(18),
        rsp: word(19),
        ss: word(20),
        fs_base: word(21),
        gs_base: word(22),
        ds: word(23),
        es: word(24),
        fs: word(25),
        gs: word(26),
    }
}
fn state<'a>(record: &JournalStateView<'a>) -> Result<State<'a>> {
    let h = record
        .header
        .ok_or(OracleError::Invalid("journal state header absent"))?;
    require(
        record.complete
            && record.copied_prefix.len() == MAX
            && record.initialized.len() == MAX
            && record.copied_prefix == record.initialized
            && record.installed == Some(record.allocation)
            && record.allocation.capacity == MAX
            && record
                .source
                .is_some_and(|s| s.address != 0 && s.length == MAX && s.capacity == MAX)
            && h.captured
            && h.finalized
            && h.complete
            && h.registers_request == zero()
            && h.xstate_request == zero()
            && h.mask_request == zero()
            && h.requested_length == MAX
            && h.requested_pointer != 0
            && h.requested_pointer == h.returned_pointer
            && (512..MAX).contains(&h.returned_length),
        "journal_state",
    )?;
    Ok(State {
        registers: registers(&h.registers),
        xstate: &record.initialized[..h.returned_length],
        mask: u64::from_ne_bytes(h.mask),
    })
}
fn slot<'a>(attempt: &'a JournalAttemptView<'_>, wanted: Slot) -> Result<JournalStateView<'a>> {
    let index = SLOTS
        .iter()
        .position(|s| *s == wanted)
        .ok_or(OracleError::Invalid("journal_slots"))?;
    let value = attempt
        .state(index)
        .ok_or(OracleError::Invalid("journal_slots"))?;
    require(
        value.header.is_some_and(|h| h.slot == wanted),
        "journal_slots",
    )?;
    Ok(value)
}
fn raw<'a>(attempt: &'a JournalAttemptView<'_>, ordinal: usize) -> Result<&'a Raw> {
    attempt
        .raw
        .get(ordinal)
        .and_then(Option::as_ref)
        .ok_or(OracleError::Invalid("journal_wait"))
}
fn stop(value: KernelStopIdentity, b: &JournalBindingView<'_>, pid: i32) -> Result<()> {
    require(
        value.session == b.pending.stop.session
            && value.tid == pid
            && value.task == Some(b.pending.task.task),
        "journal_stop_identity",
    )
}
fn validated(attempt: &JournalAttemptView<'_>, stage: Stage) -> Result<KernelStopIdentity> {
    let mut found = None;
    for fact in attempt.facts.iter().flatten() {
        if let Fact::Validated {
            stage: actual,
            stop,
        } = fact
        {
            if *actual == stage {
                require(found.is_none(), "journal_validated")?;
                found = Some(*stop);
            }
        }
    }
    found.ok_or(OracleError::Invalid("journal_validated"))
}
fn info(raw: &Raw, expected: &State<'_>, number: u64, args: [u64; 6], entry: bool) -> Result<()> {
    let request = raw
        .syscall_request
        .ok_or(OracleError::Invalid("journal_syscall_info"))?;
    let bytes = &raw.syscall_info;
    let word =
        |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().expect("fixed ABI word"));
    require(
        request.errno.is_none()
            && ((if entry { 80 } else { 33 })..=88).contains(&request.result)
            && bytes[0] == if entry { 1 } else { 2 }
            && u32::from_ne_bytes(bytes[4..8].try_into().expect("fixed ABI architecture"))
                == 0xc000_003e
            && word(8) == expected.registers.rip
            && word(16) == expected.registers.rsp,
        "journal_syscall_info",
    )?;
    if entry {
        require(
            word(24) == number && args.iter().enumerate().all(|(i, v)| word(32 + i * 8) == *v),
            "journal_syscall_info",
        )
    } else {
        require(
            word(24) == expected.registers.rax && bytes[32] == 0,
            "journal_syscall_info",
        )
    }
}
/// Each expected fact consumes exactly one copied position. Finish rejects any
/// omitted/extra fact, nonempty suffix or count mismatch; no growing Vec.
struct Facts<'a> {
    actual: &'a [Option<Fact>; 32],
    count: usize,
    next: usize,
}
impl<'a> Facts<'a> {
    fn new(attempt: &'a JournalAttemptView<'_>) -> Result<Self> {
        let h = attempt
            .header
            .ok_or(OracleError::Invalid("journal header absent"))?;
        Ok(Self {
            actual: attempt.facts,
            count: h.fact_count,
            next: 0,
        })
    }
    fn push(&mut self, fact: Fact) -> Result<()> {
        require(
            self.next < self.count && self.actual.get(self.next) == Some(&Some(fact)),
            "journal_fact_chain",
        )?;
        self.next += 1;
        Ok(())
    }
    fn release(&mut self, phase: Release, source: Source) -> Result<()> {
        self.push(Fact::ReleaseAttempt { phase, source })?;
        self.push(Fact::ReleaseResult {
            phase,
            request: Request {
                result: 0,
                errno: None,
            },
        })
    }
    fn finish(self) -> Result<()> {
        require(
            self.next == self.count
                && self
                    .actual
                    .get(self.next..)
                    .is_some_and(|tail| tail.iter().all(Option::is_none)),
            "journal_fact_chain",
        )
    }
}
fn last(attempt: &JournalAttemptView<'_>) -> Result<Fact> {
    let h = attempt
        .header
        .ok_or(OracleError::Invalid("journal header absent"))?;
    h.fact_count
        .checked_sub(1)
        .and_then(|i| attempt.facts.get(i))
        .and_then(|v| *v)
        .ok_or(OracleError::Invalid("journal_commit"))
}

fn check(
    attempt: &JournalAttemptView<'_>,
    input: &SelectedInput,
    xstate: &[u8],
    mask: u64,
    returned: Option<&TaskStateSnapshot>,
    task: &DynamicTask,
    pid: i32,
) -> Result<()> {
    let b = attempt
        .binding
        .as_ref()
        .ok_or(OracleError::Invalid("journal binding absent"))?;
    let h = attempt
        .header
        .ok_or(OracleError::Invalid("journal header absent"))?;
    let id = KernelAttemptId {
        session: b.pending.stop.session,
        invocation: b.pending.invocation,
    };
    let original = KernelStopIdentity::from(&b.original.token);
    let SelectedArguments::Syscall {
        abi: SyscallAbi::LinuxX64,
        number,
        arguments,
    } = input.arguments()
    else {
        return Err(OracleError::Invalid("journal_input"));
    };
    require(
        b.pending.task == *task
            && task.generation == 0
            && *b.registers == *input.registers()
            && b.pending.pc == input.instruction().logical_pc()
            && input.instruction().bytes() == [0x0f, 0x05]
            && b.number == number
            && b.arguments == arguments
            && h.failure.is_none()
            && id.session != 0
            && id.invocation != 0
            && h.charge > 0
            && b.execution.0 == id.session
            && b.execution.1 > 0
            && b.origin.0 == id.session
            && b.origin.1 > 0
            && b.source.generation == task.generation
            && b.source.mapping != 0,
        "journal_input",
    )?;
    stop(original, b, pid)?;
    let before = State {
        registers: *input.registers(),
        xstate,
        mask,
    };
    let original_record = slot(attempt, Slot::Original)?;
    let oh = original_record
        .header
        .ok_or(OracleError::Invalid("journal_original"))?;
    require(
        oh.stop == Some(original) && oh.raw_ordinal.is_none() && state(&original_record)? == before,
        "journal_original",
    )?;
    require(
        attempt.complete
            && attempt.raw_slots_copied == 9
            && attempt.state_slots_copied == 8
            && attempt.fact_slots_copied == 32
            && h.completed
            && h.stage == Stage::Committed,
        "journal copied attempt incomplete",
    )?;
    for (index, wanted) in SLOTS.iter().enumerate() {
        let record = attempt
            .state(index)
            .ok_or(OracleError::Invalid("journal_slots"))?;
        let header = record.header.ok_or(OracleError::Invalid("journal_slots"))?;
        require(
            header.slot == *wanted
                && record.complete
                && record.initialized.len() == MAX
                && record.copied_prefix.len() == MAX
                && record.copied_prefix == record.initialized
                && record.installed == Some(record.allocation)
                && record.allocation.capacity == MAX
                && record
                    .source
                    .is_some_and(|s| s.length == MAX && s.capacity == MAX && s.address != 0),
            "journal_slots",
        )?;
        let used = if returned.is_some() {
            index < 6
        } else {
            matches!(header.slot, Slot::Original | Slot::Entry | Slot::PreExit)
        };
        require(header.captured == used, "journal_slots")?;
        if used {
            let _ = state(&record)?;
        } else {
            require(
                !header.complete
                    && !header.finalized
                    && header.registers_request.is_none()
                    && header.xstate_request.is_none()
                    && header.mask_request.is_none(),
                "journal_unused_state",
            )?;
        }
    }
    let count = if returned.is_some() { 9 } else { 6 };
    require(
        h.raw_count == count && h.fact_count == if returned.is_some() { 25 } else { 20 },
        "journal counts",
    )?;
    for (ordinal, record) in attempt.raw.iter().enumerate() {
        if ordinal >= count {
            require(record.is_none(), "journal_extra_wait")?;
            continue;
        }
        let record = record
            .as_ref()
            .ok_or(OracleError::Invalid("journal_wait"))?;
        require(
            record.ordinal == ordinal
                && record.tid == pid
                && record.finalized
                && record.failure.is_none()
                && record.custody.session == id.session
                && record.custody.expected_tid == pid
                && record.custody.retained_pin.is_some()
                && !record.custody.lost_wait
                && !record.custody.missing_pin,
            "journal_wait",
        )?;
        if returned.is_none() && ordinal == 5 {
            require(
                libc::WIFEXITED(record.status)
                    && libc::WEXITSTATUS(record.status) == 7
                    && record.custody.tracer_terminal == Some(record.status)
                    && !record.queries_started
                    && record.registers_request.is_none()
                    && record.xstate_request.is_none()
                    && record.mask_request.is_none()
                    && record.syscall_request.is_none()
                    && record.event_request.is_none()
                    && record.signal_request.is_none()
                    && record.state_slot.is_none()
                    && record.maps.is_none(),
                "journal_terminal_wait",
            )?;
            continue;
        }
        let syscall = ordinal == 3 || (returned.is_some() && ordinal == 4);
        require(
            libc::WIFSTOPPED(record.status)
                && record.queries_started
                && libc::WSTOPSIG(record.status)
                    == if syscall {
                        libc::SIGTRAP | 0x80
                    } else {
                        libc::SIGTRAP
                    }
                && record.status >> 16
                    == if returned.is_none() && ordinal == 4 {
                        libc::PTRACE_EVENT_EXIT
                    } else {
                        0
                    }
                && record.custody.owned
                && record.custody.stopped_status == Some(record.status)
                && record.registers_request == zero()
                && record.xstate_request == zero()
                && record.mask_request == zero()
                && record.requested_length == MAX
                && record.requested_pointer != 0
                && record.requested_pointer == record.returned_pointer
                && (512..MAX).contains(&record.returned_length)
                && record.syscall_request.is_some()
                && record.event_request.is_some()
                && record.signal_request.is_some(),
            "journal_held_wait",
        )?;
        let maps = record
            .maps
            .ok_or(OracleError::Invalid("journal_maps_summary"))?;
        require(
            maps.complete
                && (1..MAX).contains(&maps.observed_bytes)
                && maps.filesystem == Some(0x9fa0)
                && maps.filesystem_request == zero()
                && maps
                    .directory_open
                    .is_some_and(|r| r.result >= 0 && r.errno.is_none())
                && maps
                    .maps_open
                    .is_some_and(|r| r.result >= 0 && r.errno.is_none())
                && maps.last_read == zero()
                && maps.read_calls > 0,
            "journal_maps_summary",
        )?;
        if let Some(purpose) = record.state_slot {
            let copied = slot(attempt, purpose)?;
            let copied = copied
                .header
                .ok_or(OracleError::Invalid("journal_copy_binding"))?;
            require(
                copied.raw_ordinal == Some(ordinal)
                    && copied.registers == record.registers
                    && copied.mask == record.mask
                    && copied.requested_pointer == record.requested_pointer
                    && copied.returned_pointer == record.returned_pointer
                    && copied.returned_length == record.returned_length,
                "journal_copy_binding",
            )?;
        }
    }
    let mut entry = State {
        registers: before.registers,
        xstate: before.xstate,
        mask,
    };
    entry.registers.rip = input.instruction().next_pc();
    entry.registers.rcx = entry.registers.rip;
    entry.registers.r11 = before.registers.eflags & !0x10000;
    entry.registers.eflags &= !0x10000;
    entry.registers.orig_rax = number;
    entry.registers.rax = (-libc::ENOSYS as i64) as u64;
    require(
        state(&slot(attempt, Slot::Entry)?)? == entry,
        "journal_entry_state",
    )?;
    info(raw(attempt, 3)?, &entry, number, arguments, true)?;
    let opened = validated(attempt, Stage::Opened)?;
    let entered = validated(attempt, Stage::Entry)?;
    stop(opened, b, pid)?;
    stop(entered, b, pid)?;
    require(
        original.sequence < opened.sequence && opened.sequence < entered.sequence,
        "journal_sequence",
    )?;
    let entry_record = slot(attempt, Slot::Entry)?;
    let entry_header = entry_record
        .header
        .ok_or(OracleError::Invalid("journal_entry_stop"))?;
    require(
        entry_header.stop.is_none() && entry_header.raw_ordinal == Some(3),
        "journal_entry_stop",
    )?;
    let mut facts = Facts::new(attempt)?;
    facts.push(Fact::State {
        slot: Slot::Original,
    })?;
    for ordinal in 0..3 {
        facts.push(Fact::Wait { ordinal })?;
    }
    facts.push(Fact::Validated {
        stage: Stage::Opened,
        stop: opened,
    })?;
    facts.release(Release::Original, Source::Stop(opened))?;
    facts.push(Fact::Wait { ordinal: 3 })?;
    facts.push(Fact::State { slot: Slot::Entry })?;
    facts.push(Fact::Validated {
        stage: Stage::Entry,
        stop: entered,
    })?;
    facts.release(Release::Entry, Source::Stop(entered))?;
    if let Some(after) = returned {
        let expected = State {
            registers: after.registers,
            xstate: &after.xstate,
            mask: after.mask,
        };
        for purpose in [Slot::Exit, Slot::RestoredReturn, Slot::Closed] {
            require(
                state(&slot(attempt, purpose)?)? == expected,
                "journal_return_state",
            )?;
        }
        info(raw(attempt, 4)?, &expected, number, arguments, false)?;
        let exited = validated(attempt, Stage::Exit)?;
        let closed = validated(attempt, Stage::Closed)?;
        let bridge_record = slot(attempt, Slot::RestoredReturn)?;
        let bridge = bridge_record
            .header
            .and_then(|h| h.stop)
            .ok_or(OracleError::Invalid("journal_bridge_stop"))?;
        for checkpoint in [exited, bridge, closed] {
            stop(checkpoint, b, pid)?;
        }
        let exit_record = slot(attempt, Slot::Exit)?;
        let exit_header = exit_record
            .header
            .ok_or(OracleError::Invalid("journal_sequence"))?;
        let closed_record = slot(attempt, Slot::Closed)?;
        require(
            entered.sequence < exited.sequence
                && exited.sequence < bridge.sequence
                && bridge.sequence < closed.sequence
                && exit_header.stop.is_none()
                && exit_header.raw_ordinal == Some(4)
                && closed_record.header.is_some_and(|h| h.stop == Some(closed)),
            "journal_sequence",
        )?;
        let Fact::ReturnCommitted {
            current,
            stop: committed,
        } = last(attempt)?
        else {
            return Err(OracleError::Invalid("journal_commit"));
        };
        require(
            committed == closed && current.0 == b.origin.0 && current.1 > b.origin.1,
            "journal_commit",
        )?;
        facts.push(Fact::Wait { ordinal: 4 })?;
        facts.push(Fact::State { slot: Slot::Exit })?;
        facts.push(Fact::Validated {
            stage: Stage::Exit,
            stop: exited,
        })?;
        facts.push(Fact::Wait { ordinal: 5 })?;
        facts.push(Fact::State {
            slot: Slot::BridgeTrap,
        })?;
        facts.push(Fact::State {
            slot: Slot::RestoredReturn,
        })?;
        for ordinal in 6..9 {
            facts.push(Fact::Wait { ordinal })?;
        }
        facts.push(Fact::State { slot: Slot::Closed })?;
        facts.push(Fact::Validated {
            stage: Stage::Closed,
            stop: closed,
        })?;
        facts.push(Fact::Returned { stop: closed })?;
        facts.push(Fact::ReturnCommitted {
            current,
            stop: closed,
        })?;
    } else {
        require(number == 231 && arguments[0] == 7, "journal_terminal_input")?;
        let pre = raw(attempt, 4)?;
        let terminal = raw(attempt, 5)?;
        require(
            pre.event_request == zero() && pre.event_message == 7 << 8,
            "journal_pre_exit",
        )?;
        let Fact::TerminalCommitted { sequence, status } = last(attempt)? else {
            return Err(OracleError::Invalid("journal_commit"));
        };
        require(
            sequence > entered.sequence && status == terminal.status,
            "journal_terminal_commit",
        )?;
        facts.push(Fact::Wait { ordinal: 4 })?;
        facts.push(Fact::State {
            slot: Slot::PreExit,
        })?;
        facts.push(Fact::PreExit {
            ordinal: 4,
            message: 7 << 8,
        })?;
        facts.release(
            Release::PreExit,
            Source::PreExit {
                ordinal: 4,
                tid: pid,
                status: pre.status,
            },
        )?;
        facts.push(Fact::Wait { ordinal: 5 })?;
        facts.push(Fact::Terminal {
            ordinal: 5,
            sequence,
            status,
            physical_status: status,
            pin_revents: libc::POLLIN | libc::POLLHUP,
        })?;
        facts.push(Fact::TerminalCommitted { sequence, status })?;
    }
    facts.finish()
}

fn chain(first: &JournalAttemptView<'_>, next: &JournalAttemptView<'_>) -> Result<()> {
    let a = first
        .binding
        .as_ref()
        .ok_or(OracleError::Invalid("journal_chain"))?;
    let b = next
        .binding
        .as_ref()
        .ok_or(OracleError::Invalid("journal_chain"))?;
    let Fact::ReturnCommitted { stop, .. } = last(first)? else {
        return Err(OracleError::Invalid("journal_chain"));
    };
    let original = KernelStopIdentity::from(&b.original.token);
    require(
        a.pending.task == b.pending.task
            && a.pending.stop.session == b.pending.stop.session
            && a.pending.invocation < b.pending.invocation
            && a.execution.0 == b.execution.0
            && a.execution.1 < b.execution.1
            && a.origin.0 == b.origin.0
            && a.origin.1 < b.origin.1
            && original.session == stop.session
            && original.tid == stop.tid
            && original.task == stop.task
            && original.sequence > stop.sequence,
        "journal_chain",
    )
}

pub(super) fn require_complete(experiment: &Experiment) -> Result<()> {
    let view = experiment.journal.partial_view();
    let transition = experiment
        .journal_transition
        .ok_or(OracleError::Invalid("journal cleanup transition absent"))?;
    let archive = view
        .header
        .ok_or(OracleError::Invalid("journal archive header absent"))?;
    require(
        view.progress.allocation_complete
            && view.progress.capture_complete
            && view.progress.headers_copied == 3
            && view.progress.first_failure.is_none()
            && view.progress.retention_started
            && view.progress.retention == Some(transition)
            && transition.before == KernelWriterStatus::Active
            && transition.after == KernelWriterStatus::Cleaned
            && archive.writer == transition.before
            && !archive.poisoned
            && !archive.lock_poisoned
            && archive.legacy_index.length == 0
            && archive.legacy_active.is_none()
            && archive.runtime_active.is_none()
            && archive.runtime_index.length == 3,
        "journal successful retained archive differs",
    )?;
    experiment.admitted_owner.cleanup()?;
    let owner = experiment.admitted_owner.owner_ref()?;
    let plan = experiment
        .plan
        .as_ref()
        .ok_or(OracleError::Invalid("journal actual plan absent"))?;
    let admitted = experiment.admitted.partial_view();
    require(
        archive.session == owner.anchor_session()
            && archive.session != 0
            && admitted.progress.first_failure.is_none()
            && admitted.progress.segment == 3,
        "journal owner or admitted completion differs",
    )?;
    let counts = experiment.journal.counts()?;
    require(
        counts.attempts == 3
            && counts.raw_waits == 24
            && counts.captured_states == 15
            && counts.finalized_states == 15
            && counts.complete_states == 15,
        "journal complete inventory differs",
    )?;
    let runtime = owner
        .runtime
        .as_ref()
        .ok_or(OracleError::Invalid("journal actual runtime absent"))?;
    require(
        runtime.kernel_attempts.len() == 3,
        "journal actual native attempt count differs",
    )?;
    for i in 0..3 {
        let a = view
            .attempt(i)
            .ok_or(OracleError::Invalid("journal attempt absent"))?;
        let b = a
            .binding
            .as_ref()
            .ok_or(OracleError::Invalid("journal binding absent"))?;
        let input = admitted.providers[i]
            .as_deref()
            .ok_or(OracleError::Invalid("journal actual provider absent"))?;
        let until = admitted.deadlines[i]
            .ok_or(OracleError::Invalid("journal original deadline absent"))?;
        let ordinal = plan.syscalls[i];
        let instruction = plan.instruction(ordinal)?;
        let before = admitted.lane.frame(ordinal, false)?;
        require_frame(before, ordinal, false, until)?;
        let (identity, original) = runtime
            .consumer_journal_binding(i)
            .ok_or(OracleError::Invalid("journal actual kernel binding absent"))?;
        require(
            b.pending == &input.token
                && b.original == original
                && b.original.token == input.token.stop
                && b.original.identity == input.token.task
                && b.pending.stop.session == owner.anchor_session()
                && b.pending.stop.tid == owner.pid
                && b.pending.stop.task == Some(input.token.task.task)
                && b.pending.generation.0 == input.token.task.generation
                && b.pending.task.generation == 0
                && b.pending.window == b.window
                && b.pending.mapping.0 == b.source.mapping
                && b.pending.generation.0 == b.source.generation
                && identity.pending() == b.pending
                && identity.attempt()
                    == (KernelAttemptId {
                        session: archive.session,
                        invocation: b.pending.invocation,
                    })
                && identity.journal_source() == (b.source, b.window)
                && identity.journal_origin() == b.origin
                && identity.journal_execution() == b.execution
                && identity.task() == b.pending.task
                && identity.number() == b.number
                && identity.arguments() == b.arguments
                && identity.until() == b.until
                && identity.pc() == b.pending.pc
                && identity.encoding() == [0x0f, 0x05]
                && identity.next_pc() == input.input.instruction().next_pc()
                && b.number == [39, 186, 231][i]
                && b.until == until
                && b.pending.pc == instruction.pc()
                && input.input.instruction().bytes() == instruction.bytes()
                && input.input.instruction().next_pc() == instruction.next_pc()
                && *b.registers == before.state.state.registers
                && b.original_mask == before.state.state.mask
                && b.original_xstate_len == before.state.state.xstate.len(),
            "journal retained invocation binding differs",
        )?;
        if i == 0 {
            require(
                Some(until) == experiment.admitted_until,
                "journal first launch deadline differs",
            )?;
        }
        let row = counts.per_attempt[i].ok_or(OracleError::Invalid("journal count row absent"))?;
        let states = if i < 2 { 6 } else { 3 };
        require(
            row.id == identity.attempt()
                && row.number == b.number
                && row.raw == if i < 2 { 9 } else { 6 }
                && row.captured_states == states
                && row.finalized_states == states
                && row.complete_states == states
                && row.facts == if i < 2 { 25 } else { 20 }
                && row.completed
                && row.failure.is_none(),
            "journal attempt inventory differs",
        )?;
        let returned = if i < 2 {
            let after = admitted.lane.frame(ordinal, true)?;
            require_frame(after, ordinal, true, until)?;
            let Some(AdmissionReply::Event(DynamicAdmissionEvent::Completed(event))) =
                &admitted.completions[i]
            else {
                return Err(OracleError::Invalid(
                    "journal actual return completion absent",
                ));
            };
            require(
                event.before_task == input.token.task
                    && event.after_task == input.token.task
                    && event.selected.execution == SelectedExecution::Native
                    && event.selected.input == input.input
                    && event.selected.before_xstate == before.state.state.xstate
                    && event.before_signal_mask == before.state.state.mask
                    && event.selected.after == after.state.state.registers
                    && event.selected.xstate == after.state.state.xstate
                    && event.signal_mask == after.state.state.mask,
                "journal actual completion state differs",
            )?;
            Some(&after.state.state)
        } else {
            let Some(AdmissionReply::Event(DynamicAdmissionEvent::TaskTerminal {
                task,
                status,
                all_terminal,
            })) = &admitted.completions[i]
            else {
                return Err(OracleError::Invalid(
                    "journal actual terminal completion absent",
                ));
            };
            require(
                *task == input.token.task
                    && *status == crate::lifecycle::ExitStatus::Code(7)
                    && *all_terminal
                    && admitted.lane.frame(ordinal, true).is_err()
                    && before.state.state.registers.rdi == 7,
                "journal terminal has fabricated after-state or status",
            )?;
            None
        };
        check(
            &a,
            &input.input,
            &before.state.state.xstate,
            before.state.state.mask,
            returned,
            &input.token.task,
            owner.pid,
        )?;
        if i > 0 {
            chain(
                &view
                    .attempt(i - 1)
                    .ok_or(OracleError::Invalid("journal prior attempt absent"))?,
                &a,
            )?;
        }
    }
    Ok(())
}
fn require_frame(
    frame: &Frame,
    ordinal: usize,
    after: bool,
    until: std::time::Instant,
) -> Result<()> {
    require(
        frame.complete
            && frame.state.complete
            && frame.ordinal == ordinal
            && frame.after == after
            && frame.until == Some(until),
        "journal actual frame association differs",
    )
}

pub(super) fn temporary_bytes() -> Result<usize> {
    // Additive fixed managed scratch, not a measured host-stack/RSS assertion.
    let parts = [
        size_of::<JournalPartialView<'_>>(),
        3 * size_of::<JournalAttemptView<'_>>(),
        12 * size_of::<JournalStateView<'_>>(),
        3 * size_of::<JournalBindingView<'_>>(),
        size_of::<JournalCounts>(),
        size_of::<JournalWriterTransition>(),
        size_of::<AdmittedView<'_>>(),
        5 * size_of::<State<'_>>(),
        4 * size_of::<RegisterSnapshot>(),
        size_of::<Facts<'_>>(),
        8 * size_of::<Fact>(),
        10 * size_of::<KernelStopIdentity>(),
        2 * size_of::<KernelAttemptId>(),
        2 * size_of::<Request>(),
        size_of::<[Slot; 8]>(),
        size_of::<[u64; 6]>(),
        20 * size_of::<&[u8]>(),
        48 * size_of::<usize>(),
        20 * size_of::<bool>(),
        6 * size_of::<std::ops::Range<usize>>(),
        6 * size_of::<std::time::Instant>(),
        size_of::<std::slice::Iter<'_, Option<Raw>>>(),
        size_of::<std::slice::Iter<'_, Option<Fact>>>(),
        size_of::<std::slice::Iter<'_, Slot>>(),
        size_of::<std::slice::Iter<'_, u64>>(),
        16 * size_of::<Option<&Frame>>(),
        12 * size_of::<Result<()>>(),
        4 * size_of::<Result<JournalStateView<'_>>>(),
        4 * size_of::<Result<State<'_>>>(),
        4 * size_of::<Result<Fact>>(),
        4 * size_of::<Option<KernelStopIdentity>>(),
        size_of::<RuntimeKernelMapsSummary>(),
        size_of::<SelectedArguments>(),
        size_of::<std::iter::Flatten<std::slice::Iter<'_, Option<Fact>>>>(),
        size_of::<std::iter::Enumerate<std::slice::Iter<'_, Option<Raw>>>>(),
        size_of::<std::iter::Enumerate<std::slice::Iter<'_, Slot>>>(),
        size_of::<std::iter::Enumerate<std::slice::Iter<'_, u64>>>(),
        size_of::<std::ops::RangeInclusive<i64>>(),
        8 * size_of::<&Frame>(),
        size_of::<[u8; 8]>(),
        4 * size_of::<[u64; 3]>(),
        size_of::<[usize; 43]>(),
        size_of::<std::array::IntoIter<usize, 43>>(),
    ];
    parts.into_iter().try_fold(0usize, |sum, value| {
        sum.checked_add(value).ok_or(OracleError::Invalid(
            "journal validator temporary size overflows",
        ))
    })
}
