//! Closed, allocation-free descriptions of retained evidence. Output grants no
//! native authority. Unattempted observations stay null, including after failure.
use super::{
    Experiment, OracleError,
    artifact::PlannedKind,
    custody::{Custody, Outcome, Step},
    observe::PreparedLane,
    owner::{ArtifactOwner, OwnerView, PinView},
    protocol::{Digest, Mode, Row},
};
use crate::linux::remote::dynamic::admission::AdmissionReply;
use crate::linux::remote::dynamic::owner::admission::runtime_native::InstructionEffect;
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native;
use crate::linux::remote::dynamic::owner::bootstrap::StateSlot;
use crate::linux::remote::dynamic::owner::kernel_journal::{
    JournalAttemptView, JournalPartialView, JournalStateView,
};
use crate::{DynamicAdmissionEvent, lifecycle::ExitStatus};
use std::{
    fmt::{self, Write},
    mem::{size_of, size_of_val},
};

type Number = Option<u64>;
type Check = Option<bool>;
const COMMON: [&str; 9] = [
    "instructions",
    "ordinary",
    "calls",
    "returns",
    "syscall_entries",
    "syscall_returns",
    "terminal_syscall",
    "terminal_argument",
    "terminal_code",
];
const RAW: [&str; 6] = [
    "raw_waits",
    "requests",
    "frames",
    "separate_phase_states",
    "namespace_records",
    "state_read_groups",
];
const ADMITTED: [&str; 13] = [
    "frames",
    "own_lane_state_read_groups",
    "stack_commits",
    "stack_raw_waits",
    "stack_private_calls",
    "stack_original_steps",
    "stack_word_captures",
    "stack_census_checks",
    "call_rows",
    "kernel_attempts",
    "kernel_raw_waits",
    "kernel_state_copies",
    "kernel_failures",
];
const CHECKS: [&str; 14] = [
    "identity",
    "artifact",
    "own_state",
    "whole_source",
    "whole_stack",
    "helper_dataflow",
    "stack_access",
    "syscall_architecture",
    "terminal",
    "call_before_opening",
    "call_retained",
    "stack_census",
    "final_current",
    "history_after_cleanup",
];
const CLEANUP: [&str; 7] = [
    "receipt",
    "application_hup",
    "application_echild",
    "broker_hup",
    "broker_echild",
    "mask_restored",
    "retained_prefix",
];
const COMPARISON: [&str; 5] = [
    "artifact_plan",
    "own_lane_equations",
    "structural",
    "helper_dataflow",
    "terminal",
];
const INSPECT: [&str; 4] = ["elf", "closed_path", "dataflow", "artifact_unchanged"];
const ACCOUNT_NUMBERS: [&str; 6] = [
    "reservation_bytes",
    "allocated_bytes",
    "charged_before",
    "charged_after",
    "retained_before",
    "retained_after",
];
const ACCOUNT_CHECKS: [&str; 3] = ["settled", "finished", "formula_checked"];

#[derive(Clone, Copy)]
struct Path {
    instructions: u64,
    ordinary: u64,
    calls: u64,
    returns: u64,
    syscalls: [u64; 3],
    syscall_count: usize,
}
#[derive(Clone, Copy)]
struct Lane {
    error: Option<&'static str>,
    common: [Number; 9],
    checks: [Check; 14],
    cleanup: [Check; 7],
}
#[derive(Clone, Copy)]
struct Raw {
    lane: Lane,
    counts: [Number; 6],
}
#[derive(Clone, Copy)]
struct Facts {
    values: [u64; 3],
    length: usize,
}
#[derive(Clone, Copy)]
struct Admitted {
    lane: Lane,
    counts: [Number; 13],
    facts: Option<Facts>,
}
#[derive(Clone, Copy)]
struct Accounting {
    numbers: [Number; 6],
    checks: [Check; 3],
}
#[derive(Clone, Copy)]
struct Projection {
    inspect: bool,
    error: Option<&'static str>,
    artifact: Option<Digest>,
    artifact_bytes: Number,
    plan: Option<Digest>,
    path: Option<Path>,
    inspect_checks: [Check; 4],
    raw: Option<Raw>,
    admitted: Option<Admitted>,
    comparison: Option<[Check; 5]>,
    accounting: Option<Accounting>,
}

fn observed(value: usize) -> Number {
    Some(value as u64)
}
fn proven(value: bool) -> Check {
    value.then_some(true)
}
fn success(custody: &Custody, step: Step) -> bool {
    custody.outcome(step).succeeded()
}
fn first_error(custody: &Custody, steps: &[Step]) -> Option<&'static str> {
    steps.iter().find_map(|&step| match custody.outcome(step) {
        Outcome::Returned(Err(_)) => Some(step.code()),
        Outcome::Unwound(_) => Some("caught_panic"),
        _ => None,
    })
}
fn state_attempted(state: &StateSlot) -> bool {
    state.registers_request.is_some()
        || state.xstate_request.is_some()
        || state.mask_request.is_some()
}
fn frame_groups(lane: &PreparedLane) -> u64 {
    let mut count = 0;
    // Installed but unused frames do not count. No query, parser or capture is
    // performed by this traversal; each successful lookup borrows retained data.
    for ordinal in 0..super::artifact::PLAN_CAP {
        for after in [false, true] {
            if let Ok(frame) = lane.frame(ordinal, after) {
                count += u64::from(state_attempted(&frame.state));
            }
        }
    }
    count
}
fn state_groups(lane: &PreparedLane) -> u64 {
    u64::from(state_attempted(&lane.metadata.state)) + frame_groups(lane)
}
fn common(this: &Experiment, lane: &PreparedLane, completed: usize) -> [Number; 9] {
    let mut values = [None; 9];
    if let Some(plan) = this.plan.as_ref().filter(|plan| completed <= plan.len()) {
        values[..4].fill(Some(0));
        values[0] = observed(completed);
        for instruction in plan.instructions().take(completed) {
            let index = match instruction.kind() {
                PlannedKind::Ordinary => Some(1),
                PlannedKind::Call => Some(2),
                PlannedKind::Ret => Some(3),
                PlannedKind::Syscall { .. } => None,
            };
            if let Some(index) = index {
                values[index] = values[index].map(|n| n + 1);
            }
        }
        if let Ok(frame) = lane.frame(plan.syscalls[2], false) {
            if frame.state.complete {
                // This is the full actual before-terminal RAX/RDI, including a
                // failed invocation. It is never derived from an eight-bit exit.
                values[6] = Some(frame.state.state.registers.rax);
                values[7] = Some(frame.state.state.registers.rdi);
            }
        }
    }
    values
}
fn syscall_op(bytes: &[u8; 88], result: i64, errno_clear: bool, op: u8) -> bool {
    let minimum = if op == 1 { 80 } else { 33 };
    errno_clear && (minimum..=88).contains(&result) && bytes[0] == op
}
fn hup(pin: PinView) -> Check {
    pin.polled.map(|request| {
        request.result == 1
            && request.errno == 0
            && pin.revents == Some(libc::POLLIN | libc::POLLHUP)
    })
}
fn echild(pin: PinView) -> Check {
    pin.waited
        .map(|request| request.result == -1 && request.errno == libc::ECHILD)
}
fn cleanup(owner: &ArtifactOwner, retained: Check) -> [Check; 7] {
    let view = owner.partial_view();
    [
        view.cleanup.map(Result::is_ok),
        hup(view.application),
        echild(view.application),
        hup(view.helper),
        echild(view.helper),
        view.mask_restore.map(Result::is_ok),
        retained,
    ]
}
fn raw(this: &Experiment) -> Option<Raw> {
    if !this.custody.outcome(Step::RawLaunch).attempted() {
        return None;
    }
    let progress = this.raw.progress();
    let mut lane = Lane {
        error: first_error(
            &this.custody,
            &[
                Step::RawLaunch,
                Step::RawExecution,
                Step::RawAborted,
                Step::RawBeforeCleanup,
                Step::RawCleanup,
                Step::RawRetention,
                Step::RawMask,
            ],
        ),
        common: common(this, &this.raw.lane, progress.next),
        checks: [None; 14],
        cleanup: cleanup(
            &this.raw_owner,
            this.custody.outcome(Step::RawRetention).check(),
        ),
    };
    // The first two waits are bootstrap EXIT and the entry INT3. Only subsequent
    // actual syscall-info request records describe original selected operations.
    if !progress.initialized {
        lane.common[..4].fill(None);
    }
    let mut entries = 0;
    let mut returns = 0;
    let mut queried = false;
    for wait in this.raw.waits.iter().take(progress.waits).skip(2) {
        if let Some(request) = wait.syscall_request.filter(|_| wait.actual.is_some()) {
            queried = true;
            entries += u64::from(syscall_op(
                &wait.syscall,
                request.result,
                request.errno == 0,
                1,
            ));
            returns += u64::from(syscall_op(
                &wait.syscall,
                request.result,
                request.errno == 0,
                2,
            ));
        }
    }
    lane.common[4] = queried.then_some(entries);
    lane.common[5] = queried.then_some(returns);
    lane.common[8] = this
        .raw
        .terminal
        .and_then(|(_, status)| libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status) as u64));
    // require_complete inside RawExecution checks all nine semantic groups. A
    // failure of that combined check supplies no per-group failure diagnosis.
    lane.checks[..9].fill(proven(success(&this.custody, Step::RawExecution)));
    let separate = this
        .raw
        .states
        .iter()
        .filter(|state| state.complete)
        .count();
    let separate_groups = this
        .raw
        .states
        .iter()
        .filter(|state| state_attempted(state))
        .count();
    let groups = state_groups(&this.raw.lane) + separate_groups as u64;
    Some(Raw {
        lane,
        counts: [
            (progress.waits > 0).then_some(progress.waits as u64),
            (progress.requests > 0).then_some(progress.requests as u64),
            (frame_groups(&this.raw.lane) > 0).then_some(this.raw.lane.completed as u64),
            (separate_groups > 0).then_some(separate as u64),
            (progress.namespaces > 0).then_some(progress.namespaces as u64),
            (groups > 0).then_some(groups),
        ],
    })
}

fn kernel(this: &Experiment, result: &mut Admitted) {
    let view = this.journal.partial_view();
    if view.header.is_none() {
        return;
    }
    let mut attempts = 0;
    let mut waits = 0;
    let mut states = 0;
    let mut failures = 0;
    let mut entries = 0;
    let mut returns = 0;
    let mut facts = Facts {
        values: [0; 3],
        length: 0,
    };
    for index in 0..3 {
        let Some(attempt) = view.attempt(index) else {
            break;
        };
        let Some(header) = attempt.header else {
            break;
        };
        if attempt.binding.is_none() {
            break;
        }
        attempts += 1;
        failures += u64::from(header.failure.is_some());
        for raw in attempt.raw.iter().take(attempt.raw_slots_copied).flatten() {
            waits += 1;
            if let Some(request) = raw.syscall_request {
                entries += u64::from(
                    raw.ordinal == 3
                        && syscall_op(
                            &raw.syscall_info,
                            request.result,
                            request.errno.is_none(),
                            1,
                        ),
                );
                returns += u64::from(
                    raw.ordinal == 4
                        && syscall_op(
                            &raw.syscall_info,
                            request.result,
                            request.errno.is_none(),
                            2,
                        ),
                );
            }
        }
        for index in 0..attempt.state_slots_copied {
            if let Some(state) = attempt.state(index) {
                states +=
                    u64::from(state.complete && state.header.is_some_and(|header| header.captured));
            }
        }
        facts.values[facts.length] = attempt
            .facts
            .iter()
            .take(attempt.fact_slots_copied)
            .filter(|fact| fact.is_some())
            .count() as u64;
        facts.length += 1;
    }
    // These are copied prefixes, not inferred full totals from the archive's
    // allocation capacity. Successful JournalRetention also validates the full
    // original binding, phase, state and fact schedule before publication.
    result.lane.common[4] = Some(entries);
    result.lane.common[5] = Some(returns);
    result.counts[9] = Some(attempts);
    result.counts[10] = Some(waits);
    result.counts[11] = Some(states);
    result.counts[12] = Some(failures);
    result.facts = Some(facts);
}
fn admitted(this: &Experiment) -> Option<Admitted> {
    if !this.custody.outcome(Step::AdmittedLaunch).attempted() {
        return None;
    }
    let view = this.admitted.partial_view();
    let mut result = Admitted {
        lane: Lane {
            error: first_error(
                &this.custody,
                &[
                    Step::AdmittedLaunch,
                    Step::AdmittedStart,
                    Step::AdmittedAllocation,
                    Step::AdmittedExecution,
                    Step::AdmittedAborted,
                    Step::AdmittedSeal,
                    Step::StackPrefix0Capture,
                    Step::StackPrefix1Capture,
                    Step::CallPrefixCapture,
                    Step::JournalBeforeCleanup,
                    Step::AdmittedCleanup,
                    Step::AdmittedRetention,
                    Step::StackPrefix0Retention,
                    Step::StackPrefix1Retention,
                    Step::CallPrefixRetention,
                    Step::JournalRetention,
                    Step::SinkRetirement,
                    Step::CallRetirementRetention,
                    Step::AdmittedMask,
                ],
            ),
            common: common(this, view.lane, view.progress.next),
            checks: [None; 14],
            cleanup: cleanup(
                &this.admitted_owner,
                combined_checks([
                    this.custody.outcome(Step::AdmittedRetention).check(),
                    this.custody.outcome(Step::StackPrefix0Capture).check(),
                    this.custody.outcome(Step::StackPrefix1Capture).check(),
                    this.custody.outcome(Step::CallPrefixCapture).check(),
                    this.custody.outcome(Step::StackPrefix0Retention).check(),
                    this.custody.outcome(Step::StackPrefix1Retention).check(),
                    this.custody.outcome(Step::CallPrefixRetention).check(),
                    this.custody.outcome(Step::CallRetirementRetention).check(),
                    this.custody.outcome(Step::JournalRetention).check(),
                    this.custody.outcome(Step::SinkRetirement).check(),
                ]),
            ),
        },
        counts: [None; 13],
        facts: None,
    };
    result.lane.common[8] = match view.completions[2].as_ref() {
        Some(AdmissionReply::Event(DynamicAdmissionEvent::TaskTerminal {
            status: ExitStatus::Code(code),
            ..
        })) => Some(u64::from(*code)),
        _ => None,
    };
    if !view.progress.initialized {
        result.lane.common[..4].fill(None);
    }
    result.counts[0] = (frame_groups(view.lane) > 0).then_some(view.lane.completed as u64);
    let groups = state_groups(view.lane);
    result.counts[1] = (groups > 0).then_some(groups);
    result.counts[7] = view
        .progress
        .initialized
        .then_some(view.progress.stack_copies as u64);
    if let Some(stack) = this
        .admitted_owner
        .partial_view()
        .owner
        .and_then(|owner| owner.runtime.as_ref())
        .and_then(|runtime| runtime.stack.as_ref())
        .filter(|_| this.custody.outcome(Step::AdmittedExecution).attempted())
    {
        let mut commits = 0;
        let mut waits = 0;
        let mut calls = 0;
        let mut steps = 0;
        let mut words = 0;
        for attempt in stack.attempts.iter().flatten() {
            commits += u64::from(attempt.stage == super::super::AttemptStage::Complete);
            let native = attempt.native.consumer_view();
            waits += native
                .progress
                .waits
                .iter()
                .filter(|wait| wait.is_some())
                .count() as u64;
            for record in native.effects.iter().take(native.effects_len).flatten() {
                if record.complete {
                    match record.effect {
                        InstructionEffect::PrivateRelease { .. } => calls += 1,
                        InstructionEffect::OriginalRelease => steps += 1,
                        _ => (),
                    }
                }
            }
            words += u64::from(attempt.operand.consumer_view().progress.complete);
            words += native
                .words
                .iter()
                .filter(|word| word.capture.complete)
                .count() as u64;
        }
        result.counts[2..7].copy_from_slice(&[
            Some(commits),
            Some(waits),
            Some(calls),
            Some(steps),
            Some(words),
        ]);
        result.counts[8] = observed(stack.calls.consumer_count());
    }
    kernel(this, &mut result);
    let complete = success(&this.custody, Step::AdmittedExecution);
    result.lane.checks[..9].fill(proven(complete));
    result.lane.checks[9] = view.sink.progress().ok().and_then(|progress| {
        proven(progress.callback_complete && progress.first_failure.is_none())
    });
    result.lane.checks[10] = proven(view.progress.call_checks > 0);
    result.lane.checks[11] = proven(
        complete
            && view
                .snapshots
                .iter()
                .all(|snapshot| snapshot.progress().1.complete),
    );
    result.lane.checks[12] = proven(complete);
    result.lane.checks[13] = combined_checks([
        this.custody.outcome(Step::AdmittedRetention).check(),
        this.custody.outcome(Step::StackPrefix0Capture).check(),
        this.custody.outcome(Step::StackPrefix1Capture).check(),
        this.custody.outcome(Step::CallPrefixCapture).check(),
        this.custody.outcome(Step::StackPrefix0Retention).check(),
        this.custody.outcome(Step::StackPrefix1Retention).check(),
        this.custody.outcome(Step::CallPrefixRetention).check(),
        this.custody.outcome(Step::CallRetirementRetention).check(),
        this.custody.outcome(Step::JournalRetention).check(),
        this.custody.outcome(Step::SinkRetirement).check(),
    ]);
    Some(result)
}
fn combined_checks<const N: usize>(values: [Check; N]) -> Check {
    if values.contains(&Some(false)) {
        Some(false)
    } else if values.iter().all(|value| *value == Some(true)) {
        Some(true)
    } else {
        None
    }
}
fn accounting(q: &super::storage::ObserverReservation) -> Option<Accounting> {
    if !q.started {
        return None;
    }
    Some(Accounting {
        numbers: [
            q.reservation_bytes.map(|v| v as u64),
            q.measured
                .as_ref()
                .and_then(|v| v.as_ref().ok())
                .map(|&v| v as u64),
            q.before.map(|v| v.charged.source_fact_bytes as u64),
            q.after.map(|v| v.charged.source_fact_bytes as u64),
            q.before.map(|v| v.used.source_fact_bytes as u64),
            q.after.map(|v| v.used.source_fact_bytes as u64),
        ],
        checks: [
            q.debit
                .as_ref()
                .map(Result::is_ok)
                .or(q.debit_unwound.then_some(false)),
            q.finish
                .as_ref()
                .map(Result::is_ok)
                .or(q.finish_unwound.then_some(false)),
            q.formula_checked,
        ],
    })
}
fn required(custody: &Custody, inspect: bool) -> bool {
    let common = [
        Step::Arguments,
        Step::Artifact,
        Step::Plan,
        Step::FinalArtifact,
        Step::ArtifactClose,
    ];
    common.into_iter().all(|step| success(custody, step))
        && (inspect
            || [
                Step::RawLaunch,
                Step::RawExecution,
                Step::RawBeforeCleanup,
                Step::RawCleanup,
                Step::RawRetention,
                Step::RawMask,
                Step::AdmittedLaunch,
                Step::AdmittedStart,
                Step::AdmittedAllocation,
                Step::AdmittedExecution,
                Step::StackPrefix0Capture,
                Step::StackPrefix1Capture,
                Step::CallPrefixCapture,
                Step::JournalBeforeCleanup,
                Step::AdmittedCleanup,
                Step::AdmittedRetention,
                Step::StackPrefix0Retention,
                Step::StackPrefix1Retention,
                Step::CallPrefixRetention,
                Step::JournalRetention,
                Step::SinkRetirement,
                Step::CallRetirementRetention,
                Step::AdmittedMask,
                Step::Comparison,
            ]
            .into_iter()
            .all(|step| success(custody, step)))
}
fn project(this: &Experiment) -> Projection {
    // Only an authenticated Inspect request gets the plan role. A malformed
    // CLI has a failed oracle row with no lane and cannot qualify as a run.
    let inspect = matches!(this.input.mode(), Ok(Mode::Inspect));
    let path = this.plan.as_ref().map(|plan| {
        let mut path = Path {
            instructions: plan.len() as u64,
            ordinary: 0,
            calls: 0,
            returns: 0,
            syscalls: [0; 3],
            syscall_count: 0,
        };
        for instruction in plan.instructions() {
            match instruction.kind() {
                PlannedKind::Ordinary => path.ordinary += 1,
                PlannedKind::Call => path.calls += 1,
                PlannedKind::Ret => path.returns += 1,
                PlannedKind::Syscall { number } => {
                    if let Some(slot) = path.syscalls.get_mut(path.syscall_count) {
                        *slot = number;
                    }
                    path.syscall_count += 1;
                }
            }
        }
        path
    });
    let mut result = Projection {
        inspect,
        error: this
            .custody
            .first_code()
            .or_else(|| (!required(&this.custody, inspect)).then_some("output")),
        artifact: this.file_digest,
        artifact_bytes: this.file_bytes.map(|v| v as u64),
        plan: this.plan_digest,
        path,
        inspect_checks: [
            proven(this.plan.is_some()),
            proven(this.plan.is_some()),
            proven(this.contract.is_some()),
            this.custody.outcome(Step::FinalArtifact).check(),
        ],
        raw: raw(this),
        admitted: admitted(this),
        comparison: this
            .custody
            .outcome(Step::Comparison)
            .attempted()
            .then(|| [proven(success(&this.custody, Step::Comparison)); 5]),
        accounting: accounting(&this.reservation),
    };
    if result.error.is_none() && !complete(&result) {
        result.error = Some("output");
    }
    result
}

fn all_checks(values: &[Check]) -> bool {
    values.iter().all(|value| *value == Some(true))
}
fn complete(value: &Projection) -> bool {
    let Some(path) = value.path else {
        return false;
    };
    if value.artifact.is_none()
        || !value
            .artifact_bytes
            .is_some_and(|bytes| (1..=1024 * 1024).contains(&bytes))
        || value.plan.is_none()
        || path.instructions != path.ordinary + 5
        || path.instructions > 35
        || path.calls != 1
        || path.returns != 1
        || path.syscall_count != 3
        || path.syscalls != [39, 186, 231]
    {
        return false;
    }
    if value.inspect {
        return all_checks(&value.inspect_checks);
    }
    let (Some(raw), Some(admitted), Some(comparison), Some(account)) = (
        value.raw,
        value.admitted,
        value.comparison,
        value.accounting,
    ) else {
        return false;
    };
    let expected = [path.instructions, path.ordinary, 1, 1, 3, 2, 231, 7, 7].map(Some);
    let Some(facts) = admitted.facts else {
        return false;
    };
    let [
        Some(reserved),
        Some(allocated),
        Some(charged_before),
        Some(charged_after),
        Some(retained_before),
        Some(retained_after),
    ] = account.numbers
    else {
        return false;
    };
    raw.lane.error.is_none()
        && admitted.lane.error.is_none()
        && raw.lane.common == expected
        && admitted.lane.common == expected
        && raw.counts
            == [
                path.instructions + 5,
                path.instructions + 11,
                2 * path.instructions - 1,
                6,
                5,
                2 * path.instructions + 6,
            ]
            .map(Some)
        && admitted.counts
            == [
                2 * path.instructions - 1,
                2 * path.instructions,
                2,
                14,
                12,
                2,
                8,
                2,
                1,
                3,
                24,
                15,
                0,
            ]
            .map(Some)
        && facts.length == 3
        && facts.values == [25, 25, 20]
        && all_checks(&raw.lane.checks[..9])
        && all_checks(&admitted.lane.checks)
        && all_checks(&raw.lane.cleanup)
        && all_checks(&admitted.lane.cleanup)
        && all_checks(&comparison)
        && all_checks(&account.checks)
        && charged_after <= 64 * 1024 * 1024
        && retained_before <= charged_before
        && retained_after <= charged_after
        && allocated <= reserved
        && charged_after.checked_sub(charged_before) == Some(reserved)
        && retained_after.checked_sub(retained_before) == Some(allocated)
}

fn number(row: &mut Row, value: Number) -> fmt::Result {
    match value {
        Some(value) => write!(row, "{value}"),
        None => row.write_str("null"),
    }
}
fn check(row: &mut Row, value: Check) -> fmt::Result {
    row.write_str(match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    })
}
fn code(row: &mut Row, value: Option<&'static str>) -> fmt::Result {
    match value {
        Some(value) => write!(row, "\"{value}\""),
        None => row.write_str("null"),
    }
}
fn digest(row: &mut Row, value: Option<Digest>) -> fmt::Result {
    match value {
        None => row.write_str("null"),
        Some(value) => {
            row.write_char('"')?;
            for byte in value.0 {
                write!(row, "{byte:02x}")?;
            }
            row.write_char('"')
        }
    }
}
fn numbers(row: &mut Row, names: &[&str], values: &[Number], leading: bool) -> fmt::Result {
    for (index, (name, value)) in names.iter().zip(values).enumerate() {
        if leading || index != 0 {
            row.write_char(',')?;
        }
        write!(row, "\"{name}\":")?;
        number(row, *value)?;
    }
    Ok(())
}
fn checks(row: &mut Row, names: &[&str], values: &[Check]) -> fmt::Result {
    row.write_char('{')?;
    for (index, (name, value)) in names.iter().zip(values).enumerate() {
        if index != 0 {
            row.write_char(',')?;
        }
        write!(row, "\"{name}\":")?;
        check(row, *value)?;
    }
    row.write_char('}')
}
fn lane_start(row: &mut Row, lane: &Lane) -> fmt::Result {
    row.write_str("{\"error\":")?;
    code(row, lane.error)?;
    row.write_str(",\"observations\":{")?;
    numbers(row, &COMMON, &lane.common, false)
}
fn lane_end(row: &mut Row, lane: &Lane, admitted: bool) -> fmt::Result {
    row.write_str("},\"checks\":")?;
    let count = if admitted { 14 } else { 9 };
    checks(row, &CHECKS[..count], &lane.checks[..count])?;
    row.write_str(",\"cleanup\":")?;
    checks(row, &CLEANUP, &lane.cleanup)?;
    row.write_char('}')
}
fn render(row: &mut Row, value: &Projection) -> fmt::Result {
    row.write_str("{\"schema_version\":1,\"experiment\":\"runtime-stack-consumer\",\"role\":")?;
    code(
        row,
        Some(if value.inspect {
            "artifact_plan"
        } else {
            "oracle"
        }),
    )?;
    row.write_str(",\"status\":")?;
    code(
        row,
        Some(if value.error.is_none() {
            "passed"
        } else {
            "failed"
        }),
    )?;
    row.write_str(",\"error\":")?;
    code(row, value.error)?;
    row.write_str(",\"artifact_sha256\":")?;
    digest(row, value.artifact)?;
    row.write_str(",\"artifact_bytes\":")?;
    number(row, value.artifact_bytes)?;
    row.write_str(",\"plan_sha256\":")?;
    digest(row, value.plan)?;
    row.write_str(",\"path\":")?;
    if let Some(path) = value.path {
        write!(
            row,
            "{{\"instructions\":{},\"ordinary\":{},\"calls\":{},\"returns\":{},\"syscalls\":[",
            path.instructions, path.ordinary, path.calls, path.returns
        )?;
        for (index, value) in path.syscalls.iter().take(path.syscall_count).enumerate() {
            if index != 0 {
                row.write_char(',')?;
            }
            write!(row, "{value}")?;
        }
        row.write_str("]}")?;
    } else {
        row.write_str("null")?;
    }
    if value.inspect {
        row.write_str(",\"checks\":")?;
        checks(row, &INSPECT, &value.inspect_checks)?;
        return row.write_str("}\n");
    }
    row.write_str(",\"raw\":")?;
    if let Some(raw) = value.raw {
        lane_start(row, &raw.lane)?;
        numbers(row, &RAW, &raw.counts, true)?;
        lane_end(row, &raw.lane, false)?;
    } else {
        row.write_str("null")?;
    }
    row.write_str(",\"admitted\":")?;
    if let Some(admitted) = value.admitted {
        lane_start(row, &admitted.lane)?;
        numbers(row, &ADMITTED, &admitted.counts, true)?;
        row.write_str(",\"kernel_fact_counts\":")?;
        if let Some(facts) = admitted.facts {
            row.write_char('[')?;
            for (index, value) in facts.values.iter().take(facts.length).enumerate() {
                if index != 0 {
                    row.write_char(',')?;
                }
                write!(row, "{value}")?;
            }
            row.write_char(']')?;
        } else {
            row.write_str("null")?;
        }
        lane_end(row, &admitted.lane, true)?;
    } else {
        row.write_str("null")?;
    }
    row.write_str(",\"comparison\":")?;
    if let Some(value) = value.comparison {
        checks(row, &COMPARISON, &value)?;
    } else {
        row.write_str("null")?;
    }
    row.write_str(",\"accounting\":")?;
    if let Some(value) = value.accounting {
        row.write_char('{')?;
        numbers(row, &ACCOUNT_NUMBERS, &value.numbers, false)?;
        for (name, value) in ACCOUNT_CHECKS.iter().zip(value.checks) {
            write!(row, ",\"{name}\":")?;
            check(row, value)?;
        }
        row.write_char('}')?;
    } else {
        row.write_str("null")?;
    }
    row.write_str(",\"limits\":{\"epochs\":256,\"source_fact_bytes\":67108864,\"reports\":4096,\"origins\":4096,\"witnesses\":4096,\"plan_history\":4096},\"invocation_seconds\":3,\"cleanup_seconds\":3,\"cleanup_scope\":\"outer_supervisor\"}\n")
}
pub(super) fn protocol(this: &mut Experiment) -> Result<(), OracleError> {
    this.row.write_str("{\"protocol\":\"liteinst-runtime-stack-consumer-oracle\",\"version\":1,\"role\":\"oracle\"}\n")?;
    this.row.publish()
}
pub(super) fn result(this: &mut Experiment) -> Result<(), OracleError> {
    let projection = project(this);
    render(&mut this.row, &projection)?;
    this.row.publish()?;
    if projection.error == Some("output") && !this.custody.failed() {
        return Err(OracleError::Invalid(
            "oracle output lacks required actual outcomes",
        ));
    }
    Ok(())
}

/// Explicit managed temporary envelope, not an RSS/compiler-frame claim. Sum
/// both projection return/construction owners and all nested borrowed views,
/// fixed counters and formatting/iteration metadata conservatively. Payloads
/// are never cloned; the persistent Row is already part of Experiment/Q.
pub(super) fn temporary_bytes() -> Result<usize, OracleError> {
    let terms = [
        2 * size_of::<Projection>(),
        size_of::<Raw>(),
        size_of::<Admitted>(),
        2 * size_of::<Lane>(),
        size_of::<Path>(),
        size_of::<Facts>(),
        size_of::<Accounting>(),
        2 * size_of::<OwnerView<'static>>(),
        2 * size_of::<PinView>(),
        size_of::<super::admitted::AdmittedView<'static>>(),
        size_of::<super::raw::RawProgress>(),
        size_of::<JournalPartialView<'static>>(),
        size_of::<JournalAttemptView<'static>>(),
        size_of::<JournalStateView<'static>>(),
        runtime_stack_native::consumer_oracle::temporary_bytes()?,
        size_of::<super::call_sink::SinkProgress>(),
        size_of::<[Number; 9]>(),
        size_of::<[Number; 6]>(),
        size_of::<[Number; 13]>(),
        size_of::<[Check; 14]>(),
        size_of::<[Check; 7]>(),
        size_of::<[Check; 5]>(),
        // Added independent prefix custody gates and both ten-result retention arrays.
        size_of::<[Step; 24]>(),
        size_of::<std::array::IntoIter<Step, 24>>(),
        size_of::<[Step; 19]>(),
        2 * size_of::<[Check; 10]>(),
        2 * size_of::<std::array::IntoIter<Check, 10>>(),
        size_of::<[Step; 17]>(),
        size_of::<[Step; 14]>(),
        size_of::<[Step; 7]>(),
        size_of::<[Step; 5]>(),
        size_of::<[usize; 24]>(),
        size_of::<[u64; 16]>(),
        8 * size_of::<&[u8]>(),
        8 * size_of::<&str>(),
        8 * size_of::<fmt::Arguments<'static>>(),
        4 * size_of::<fmt::Result>(),
        size_of::<[u8; 32]>(),
        size_of::<std::array::IntoIter<u8, 32>>(),
        8 * size_of::<std::ops::Range<usize>>(),
        size_of::<Result<(), OracleError>>(),
    ];
    let mut total = size_of_val(&terms) + size_of_val(&terms.into_iter());
    for term in terms {
        total = total.checked_add(term).ok_or(OracleError::Invalid(
            "oracle output temporary size overflows",
        ))?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supplied(inspect: bool) -> Projection {
        Projection {
            inspect,
            error: Some("allocation"),
            artifact: None,
            artifact_bytes: None,
            plan: None,
            path: None,
            inspect_checks: [None; 4],
            raw: None,
            admitted: None,
            comparison: None,
            accounting: None,
        }
    }

    #[test]
    fn consumer_oracle_output_closed_null_and_integer_projection() {
        let mut row = Row::empty();
        let mut value = supplied(false);
        value.accounting = Some(Accounting {
            numbers: [Some(u64::MAX), None, Some(0), Some(0), Some(0), Some(0)],
            checks: [None, Some(true), Some(false)],
        });
        render(&mut row, &value).unwrap();
        let text = std::str::from_utf8(row.initialized()).unwrap();
        assert!(text.starts_with("{\"schema_version\":1,"));
        assert!(text.ends_with("}\n"));
        assert_eq!(text.lines().count(), 1);
        assert!(
            text.contains("\"reservation_bytes\":18446744073709551615,\"allocated_bytes\":null")
        );
        assert!(text.contains("\"settled\":null,\"finished\":true,\"formula_checked\":false"));
        assert!(text.contains("\"raw\":null,\"admitted\":null,\"comparison\":null"));
        assert!(text.contains("\"cleanup_scope\":\"outer_supervisor\""));
        assert!(row.published().is_none());
        assert!(!complete(&value));
    }

    #[test]
    fn consumer_oracle_output_failed_measurement_keeps_actual_finish() {
        let mut q = super::super::storage::ObserverReservation::empty();
        assert!(accounting(&q).is_none());
        q.started = true;
        q.reservation_bytes = Some(9000);
        q.measured = Some(Err(OracleError::Invalid("actual measurement failed")));
        q.measurement_failed = true;
        q.finish = Some(Ok(()));
        q.formula_checked = Some(false);
        let projected = accounting(&q).unwrap();
        assert_eq!(
            projected.numbers,
            [Some(9000), None, None, None, None, None]
        );
        assert_eq!(projected.checks, [None, Some(true), Some(false)]);
        q.debit_unwound = true;
        assert_eq!(
            accounting(&q).unwrap().checks,
            [Some(false), Some(true), Some(false)]
        );
    }

    #[test]
    fn consumer_oracle_output_first_failure_precedes_secondary_cleanup() {
        let mut custody = Custody::empty();
        assert!(custody.begin(Step::RawExecution));
        assert!(!custody.finish(
            Step::RawExecution,
            Ok(Err(OracleError::Invalid("first actual body failure")))
        ));
        assert!(custody.begin(Step::RawCleanup));
        assert!(!custody.finish(Step::RawCleanup, Err(Box::new(23_u32))));
        assert_eq!(custody.first_code(), Some("raw_execution"));
        assert_eq!(
            first_error(&custody, &[Step::RawExecution, Step::RawCleanup]),
            Some("raw_execution")
        );
        assert_eq!(
            first_error(&custody, &[Step::RawCleanup]),
            Some("caught_panic")
        );
        assert!(!required(&custody, false));
        assert_eq!(combined_checks([Some(true), None]), None);
        assert_eq!(combined_checks([None, Some(false)]), Some(false));
    }

    #[test]
    fn consumer_oracle_output_success_requires_complete_observations() {
        let mut custody = Custody::empty();
        for step in [
            Step::Arguments,
            Step::Artifact,
            Step::Plan,
            Step::FinalArtifact,
        ] {
            assert!(custody.begin(step));
            assert!(custody.finish(step, Ok(Ok(()))));
        }
        assert!(!required(&custody, true));
        assert!(custody.begin(Step::ArtifactClose));
        assert!(custody.finish(Step::ArtifactClose, Ok(Ok(()))));
        assert!(required(&custody, true));
        assert!(!required(&custody, false));
        let mut value = supplied(true);
        value.error = None;
        value.artifact = Some(Digest([0x19; 32]));
        value.artifact_bytes = Some(8872);
        value.plan = Some(Digest([0xa6; 32]));
        value.path = Some(Path {
            instructions: 9,
            ordinary: 4,
            calls: 1,
            returns: 1,
            syscalls: [39, 186, 231],
            syscall_count: 3,
        });
        assert!(!complete(&value));
        value.inspect_checks = [Some(true); 4];
        assert!(complete(&value));
        value.inspect = false;
        assert!(!complete(&value));
        let lane = Lane {
            error: None,
            common: [9, 4, 1, 1, 3, 2, 231, 7, 7].map(Some),
            checks: [Some(true); 14],
            cleanup: [Some(true); 7],
        };
        value.raw = Some(Raw {
            lane,
            counts: [14, 20, 17, 6, 5, 24].map(Some),
        });
        value.admitted = Some(Admitted {
            lane,
            counts: [17, 18, 2, 14, 12, 2, 8, 2, 1, 3, 24, 15, 0].map(Some),
            facts: Some(Facts {
                values: [25, 25, 20],
                length: 3,
            }),
        });
        value.comparison = Some([Some(true); 5]);
        value.accounting = Some(Accounting {
            numbers: [8000, 6000, 1000, 9000, 500, 6500].map(Some),
            checks: [Some(true); 3],
        });
        assert!(complete(&value));
        for index in 0..9 {
            let mut changed = value;
            changed.raw.as_mut().unwrap().lane.common[index] = None;
            assert!(!complete(&changed));
        }
        for index in 0..13 {
            let mut changed = value;
            changed.admitted.as_mut().unwrap().counts[index] = None;
            assert!(!complete(&changed));
        }
        for index in 0..14 {
            let mut changed = value;
            changed.admitted.as_mut().unwrap().lane.checks[index] = Some(false);
            assert!(!complete(&changed));
        }
        for index in 0..6 {
            let mut changed = value;
            changed.accounting.as_mut().unwrap().numbers[index] = None;
            assert!(!complete(&changed));
        }
        let mut row = Row::empty();
        digest(&mut row, value.artifact).unwrap();
        assert_eq!(
            row.initialized(),
            b"\"1919191919191919191919191919191919191919191919191919191919191919\""
        );
    }
}
