//! Borrow only the real owner's committed attempt. No seal is consumed here.
use super::*;
use crate::DynamicTask;
use crate::linux::remote::dynamic::owner::admission::census::StackConsumerInput;
use crate::linux::remote::dynamic::owner::admission::runtime::stack::AttemptStage;
use crate::linux::remote::dynamic::owner::admission::runtime_native::{
    NativeCheckpoint, NativeTrace,
};
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::{
    StackPhase, StackWordViews,
};
use crate::linux::remote::dynamic::owner::trusted::AdmissionStop;
use crate::linux::remote::dynamic::owner::trusted::TaskStateSnapshot;

pub(super) fn temporary_bytes() -> usize {
    size_of::<StackConsumerInput<'_>>()
        + 7 * size_of::<NativeCheckpoint<'_>>()
        + size_of::<StackWordViews<'_>>()
        + size_of::<NativeTrace>()
        + size_of::<AdmissionStop>()
        + 8 * size_of::<usize>()
}
pub(super) fn require_current(
    owner: &Owner,
    state: &TaskStateSnapshot,
    task: Option<DynamicTask>,
) -> Result<(), OracleError> {
    let runtime = owner
        .runtime
        .as_ref()
        .ok_or(OracleError::Invalid("admitted real runtime absent"))?;
    let census = runtime
        .census
        .as_ref()
        .ok_or(OracleError::Invalid("admitted real census absent"))?;
    let current = runtime
        .initial_origin
        .ok_or(OracleError::Invalid("admitted real current absent"))?;
    let observation = census
        .current_observation(current)
        .map_err(|_| OracleError::Invalid("admitted current observation missing"))?;
    let actual = runtime
        .native
        .as_ref()
        .ok_or(OracleError::Invalid("admitted native custody absent"))?
        .admission_current(observation.task.task)?;
    require(
        runtime.stage == RuntimeStage::Ready
            && census.active().count() == 1
            && observation.token == actual.token
            && observation.task == actual.identity
            && actual.token.tid == owner.pid
            && actual.token.session == owner.anchor_session()
            && observation.registers == state.registers
            && observation.xstate == state.xstate
            && observation.signal_mask == state.mask
            && observation.logical_pc == state.registers.rip
            && task.is_none_or(|task| task == observation.task)
            && runtime.pages.iter().all(|p| !p.executable),
        "admitted full actual state or current native/census identity differs",
    )
}
pub(super) fn before_stack(owner: &Owner) -> Result<(usize, usize), OracleError> {
    let runtime = owner
        .runtime
        .as_ref()
        .ok_or(OracleError::Invalid("admitted runtime absent"))?;
    let census = runtime
        .census
        .as_ref()
        .ok_or(OracleError::Invalid("admitted census absent"))?;
    let stack = runtime
        .stack
        .as_ref()
        .ok_or(OracleError::Invalid("admitted stack owner absent"))?;
    require(
        stack.failure.is_none() && stack.settlement_failure.is_none() && stack.pending.is_none(),
        "admitted stack preparation remains pending",
    )?;
    Ok((census.history().len(), stack.count))
}
fn valid(value: bool) -> Result<(), CensusConsumerError> {
    if value {
        Ok(())
    } else {
        Err(CensusConsumerError::Mismatch)
    }
}
pub(super) fn copy(
    owner: &Owner,
    plan: &ArtifactPlan,
    ordinal: usize,
    step: StepProgress,
    shape: AdmittedShape,
    out: &mut PreparedStackObservation,
) -> Result<(), CensusConsumerError> {
    let runtime = owner
        .runtime
        .as_ref()
        .ok_or(CensusConsumerError::Incomplete)?;
    let stack = runtime
        .stack
        .as_ref()
        .ok_or(CensusConsumerError::Incomplete)?;
    let prior = step.attempt_before.ok_or(CensusConsumerError::Incomplete)?;
    valid(
        stack.count == prior.checked_add(1).ok_or(CensusConsumerError::Capacity)?
            && stack.failure.is_none()
            && stack.settlement_failure.is_none()
            && stack.pending.is_none(),
    )?;
    let attempt = stack
        .attempts
        .get(prior)
        .and_then(Option::as_deref)
        .ok_or(CensusConsumerError::Incomplete)?;
    valid(
        attempt.stage == AttemptStage::Complete
            && attempt.failure.is_none()
            && attempt.settlement_failure.is_none()
            && step.until == Some(attempt.until),
    )?;
    let native = attempt.native.consumer_view();
    valid(
        native.claimed
            && native.progress.phase == StackPhase::Closed
            && native.progress.first_failure.is_none()
            && native.progress.instruction_completed
            && native.progress.nx_closed
            && !native.progress.failed_held_attempted
            && native.progress.failed_held_failure.is_none()
            && native.progress.waits.iter().all(Option::is_some)
            && native
                .progress
                .queries_started
                .iter()
                .all(|started| *started)
            && native.stops.iter().all(Option::is_some),
    )?;
    let initial = stack
        .profile
        .identity()
        .map_err(|_| CensusConsumerError::Mismatch)?;
    let operand = attempt
        .operand
        .operand()
        .map_err(|_| CensusConsumerError::Mismatch)?;
    let instruction = plan
        .instruction(ordinal)
        .map_err(|_| CensusConsumerError::Mismatch)?;
    valid(
        attempt.is_call == (instruction.kind() == PlannedKind::Call)
            && native.call_id.is_some() == attempt.is_call
            && native.encoding.get(..native.encoding_len) == Some(instruction.bytes())
            && attempt.before.logical_pc == instruction.pc(),
    )?;
    if attempt.is_call {
        valid(
            native.source == Some(shape.call_window) && attempt.window_bytes == shape.window_bytes,
        )?;
    }
    let (original, progress) = runtime.sources.original_maps();
    valid(progress.complete && progress.failure.is_none())?;
    let original = original
        .get(..progress.copied_bytes)
        .ok_or(CensusConsumerError::Mismatch)?;
    // Every stop was checked present above; these immutable references cannot
    // change between the check and construction of the descriptive array.
    let checkpoints = std::array::from_fn(|i| NativeCheckpoint {
        stop: native.stops[i]
            .as_ref()
            .expect("all actual seven stops present"),
        state: &native.states[if i < 3 { 0 } else { 4 }].state,
    });
    let current = runtime
        .initial_origin
        .ok_or(CensusConsumerError::Incomplete)?;
    let actual = runtime
        .native
        .as_ref()
        .ok_or(CensusConsumerError::Incomplete)?
        .admission_current(attempt.stop.identity.task)
        .map_err(|_| CensusConsumerError::Mismatch)?;
    let census = runtime
        .census
        .as_ref()
        .ok_or(CensusConsumerError::Incomplete)?;
    let observation = census.current_observation(current)?;
    valid(
        observation.token == actual.token
            && observation.task == actual.identity
            && native.stops[6].as_ref() == Some(&actual),
    )?;
    census.copy_stack_consumer_observation_into(
        StackConsumerInput {
            start: step.history_start.ok_or(CensusConsumerError::Incomplete)?,
            reservation: attempt.reservation,
            identity: native.identity.ok_or(CensusConsumerError::Incomplete)?,
            logical_before: &attempt.before,
            checkpoints,
            trace: native.trace.ok_or(CensusConsumerError::Incomplete)?,
            words: StackWordViews {
                profile: initial.description(),
                operand: operand.description(),
                original_maps: original,
                baseline_maps: native.maps[0]
                    .ok_or(CensusConsumerError::Incomplete)?
                    .bytes(),
                opened_maps: native.maps[1]
                    .ok_or(CensusConsumerError::Incomplete)?
                    .bytes(),
                captures: [
                    attempt.operand.view(),
                    native.words[0].capture,
                    native.words[1].capture,
                    native.words[2].capture,
                ],
            },
            call_id: native.call_id,
            sources: &runtime.sources,
            current,
            native_current: &actual,
        },
        out,
    )
}
pub(super) fn require_call(owner: &Owner, sink: &CallSink) -> Result<(), CheckFailure> {
    let runtime = owner
        .runtime
        .as_ref()
        .ok_or(CheckFailure::Census(CensusConsumerError::Incomplete))?;
    let stack = runtime
        .stack
        .as_ref()
        .ok_or(CheckFailure::Census(CensusConsumerError::Incomplete))?;
    let progress = sink.progress().map_err(CheckFailure::Sink)?;
    if !progress.callback_complete || progress.first_failure.is_some() {
        return Err(CheckFailure::Sink(SinkError::Unavailable));
    }
    let checked = sink
        .with_snapshot(|snapshot| {
            let snapshot = snapshot.ok_or(CensusConsumerError::Incomplete)?;
            stack
                .calls
                .require_consumer_observation(snapshot, &runtime.sources)?;
            // This exact one-CALL artifact must name the same actual retained row
            // in the first real stack attempt and in the pre-opening copy.
            let call = stack
                .attempts
                .first()
                .and_then(Option::as_deref)
                .ok_or(CensusConsumerError::Incomplete)?;
            let native = call.native.consumer_view();
            valid(
                call.is_call
                    && snapshot.call_id().is_some()
                    && snapshot.call_id() == native.call_id,
            )
        })
        .map_err(CheckFailure::Sink)?;
    checked.map_err(CheckFailure::Census)
}
