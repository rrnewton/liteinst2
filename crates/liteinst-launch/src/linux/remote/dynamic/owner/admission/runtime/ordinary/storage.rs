//! Retained root/native preparation. No source/native read is performed here.
use super::super::super::census::CensusError;
use super::super::super::exact_storage;
use super::*;

const STAGES: usize = 23;
#[cfg(test)]
const PANIC: u32 = 0x4f52_4441;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    Control(runtime_native::InstructionFailure),
    Refused(&'static str),
    Other,
    Unwound,
}
impl Failure {
    fn of(error: &GateError) -> Self {
        match error {
            GateError::Refused(reason) => Self::Refused(reason),
            GateError::Control(error) => Self::Control(match error {
                LaunchError::Invalid(reason) => runtime_native::InstructionFailure::Invalid(reason),
                LaunchError::System { operation, source } => {
                    runtime_native::InstructionFailure::System(operation, source.raw_os_error())
                }
                LaunchError::Timeout(operation) => {
                    runtime_native::InstructionFailure::Timeout(operation)
                }
                LaunchError::Child { status } => runtime_native::InstructionFailure::Child(*status),
            }),
            _ => Self::Other,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AllocationRecord {
    pub(super) reservation: Reservation,
    pub(super) origin: OriginId,
    pub(super) serial: u64,
    pub(super) until: Instant,
    window_bytes: usize,
    temporary: usize,
    new_slots: usize,
    new_slots_pointer: usize,
    ordinal: Option<usize>,
    copied: [usize; 2],
    pub(super) allocated: bool,
    started: bool,
    settled: [usize; 4],
    pub(super) first_failure: Option<Failure>,
    measurement_failure: Option<Failure>,
    settlement_failure: Option<CensusError>,
    finish: Option<Result<(), CensusError>>,
    #[cfg(test)]
    fault: AllocationFault,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AllocationFault {
    before: Option<usize>,
    after: Option<usize>,
    // 0 before transfer, 1 after transfer, 2/3 after each actual state copy,
    // 4 before native conversion, 5 after conversion. No hook inside a move.
    point: Option<(usize, bool)>,
}

pub(in crate::linux::remote::dynamic::owner::admission::runtime) struct PendingOrdinaryPreparation {
    record: AllocationRecord,
    stop: AdmissionStop,
    shape: InstructionAttemptShape,
    expected_capacity: usize,
    replacement: Option<Vec<Box<RuntimeOrdinaryAttempt>>>,
    attempt: Option<Box<RuntimeOrdinaryAttempt>>,
}

pub(super) struct PreparationRequest {
    pub(super) reservation: Reservation,
    pub(super) origin: OriginId,
    pub(super) serial: u64,
    pub(super) stop: AdmissionStop,
    pub(super) until: Instant,
    pub(super) shape: InstructionAttemptShape,
    pub(super) window_bytes: usize,
    pub(super) temporary: usize,
    pub(super) expected_capacity: usize,
}
impl PendingOrdinaryPreparation {
    pub(super) fn new(request: PreparationRequest) -> Self {
        let PreparationRequest {
            reservation,
            origin,
            serial,
            stop,
            until,
            shape,
            window_bytes,
            temporary,
            expected_capacity,
        } = request;
        Self {
            record: AllocationRecord {
                reservation,
                origin,
                serial,
                until,
                window_bytes,
                temporary,
                new_slots: 0,
                new_slots_pointer: 0,
                ordinal: None,
                copied: [0; 2],
                allocated: false,
                started: false,
                settled: [0; 4],
                first_failure: None,
                measurement_failure: None,
                settlement_failure: None,
                finish: None,
                #[cfg(test)]
                fault: AllocationFault::default(),
            },
            stop,
            shape,
            expected_capacity,
            replacement: None,
            attempt: None,
        }
    }
}

fn allocation_error(value: exact_storage::AllocationError) -> GateError {
    match value {
        exact_storage::AllocationError::Capacity => {
            GateError::Refused("ordinary exact allocation capacity differs")
        }
        exact_storage::AllocationError::Allocation => {
            GateError::Refused("ordinary exact allocation failed")
        }
    }
}
fn empty_observation(source: &ObservedStop) -> ObservedStop {
    ObservedStop {
        token: source.token.clone(),
        task: source.task,
        logical_pc: source.logical_pc,
        registers: source.registers,
        xstate: Vec::new(),
        signal_mask: source.signal_mask,
        phase: source.phase,
        signal: source.signal.clone(),
    }
}
impl RuntimeOrdinaryAttempt {
    fn empty(pending: &PendingOrdinaryPreparation, before: &ObservedStop) -> Self {
        Self {
            reservation: pending.record.reservation,
            stop: pending.stop.clone(),
            before: empty_observation(before),
            source: SourceChecks {
                bytes: [Vec::new(), Vec::new(), Vec::new()],
                progress: std::array::from_fn(|_| SourceReadProgress::default()),
                identity: Vec::new(),
                checkpoint: empty_observation(before),
                checkpoint_stop: pending.stop.clone(),
            },
            native: runtime_native::NativeInstructionStorage::empty(
                pending.shape,
                pending.record.until,
            ),
            census: SharedOrdinaryPreparation::empty(),
            allocation: pending.record,
            prior_slots: Vec::new(),
            stage: AttemptStage::Allocated,
            failed: false,
            unwound: false,
        }
    }
    fn payload_bytes(&self) -> Result<usize, GateError> {
        let mut amount = add(
            self.before.xstate.capacity(),
            self.source.checkpoint.xstate.capacity(),
        )?;
        amount = add(amount, self.source.identity.capacity())?;
        for bytes in &self.source.bytes {
            amount = add(amount, bytes.capacity())?;
        }
        add(amount, self.native.payload_bytes()?)
    }
    fn allocate_one(&mut self, ordinal: usize) -> Result<(), GateError> {
        let (bytes, capacity) = match ordinal {
            2 => (&mut self.before.xstate, MAX_XSTATE),
            3..=5 => (
                &mut self.source.bytes[ordinal - 3],
                self.allocation.window_bytes,
            ),
            6 => (&mut self.source.identity, MAP_BYTES),
            7 => (&mut self.source.checkpoint.xstate, MAX_XSTATE),
            8..=22 => {
                return self
                    .native
                    .allocate_one(ordinal - 8)
                    .map_err(GateError::Control);
            }
            _ => {
                return Err(GateError::Refused(
                    "ordinary root allocation ordinal differs",
                ));
            }
        };
        if !bytes.is_empty() || bytes.capacity() != 0 {
            return Err(GateError::Refused("ordinary root payload reused"));
        }
        *bytes = exact_storage::empty_bytes(capacity).map_err(allocation_error)?;
        // Installed before validating or initializing; zero resize cannot allocate.
        if bytes.capacity() != capacity {
            return Err(GateError::Refused("ordinary root payload capacity differs"));
        }
        bytes.resize(capacity, 0);
        Ok(())
    }
    fn copy_one(&mut self, before: &ObservedStop, index: usize) -> Result<(), GateError> {
        if index >= 2
            || self.allocation.copied[index] != 0
            || !(512..MAX_XSTATE).contains(&before.xstate.len())
        {
            return Err(GateError::Refused(
                "ordinary prior state copy extent differs",
            ));
        }
        let target = if index == 0 {
            &mut self.before
        } else {
            &mut self.source.checkpoint
        };
        if target.token != before.token
            || target.task != before.task
            || target.logical_pc != before.logical_pc
            || target.registers != before.registers
            || target.signal_mask != before.signal_mask
            || target.phase != before.phase
            || target.signal != before.signal
            || target.xstate.capacity() != MAX_XSTATE
            || target.xstate.len() != MAX_XSTATE
        {
            return Err(GateError::Refused(
                "ordinary prior state copy binding differs",
            ));
        }
        target.xstate[..before.xstate.len()].copy_from_slice(&before.xstate);
        target.xstate.truncate(before.xstate.len());
        self.allocation.copied[index] = before.xstate.len();
        Ok(())
    }
}

fn record<'a>(
    attempts: &'a [Box<RuntimeOrdinaryAttempt>],
    pending: &'a Option<PendingOrdinaryPreparation>,
) -> Result<&'a AllocationRecord, GateError> {
    if let Some(value) = pending {
        Ok(&value.record)
    } else {
        attempts
            .last()
            .map(|value| &value.allocation)
            .ok_or(GateError::Refused("ordinary allocation record absent"))
    }
}
fn record_mut<'a>(
    attempts: &'a mut [Box<RuntimeOrdinaryAttempt>],
    pending: &'a mut Option<PendingOrdinaryPreparation>,
) -> Result<&'a mut AllocationRecord, GateError> {
    if let Some(value) = pending {
        Ok(&mut value.record)
    } else {
        attempts
            .last_mut()
            .map(|value| &mut value.allocation)
            .ok_or(GateError::Refused("ordinary allocation record absent"))
    }
}
fn before(record: &mut AllocationRecord, ordinal: usize) -> Result<(), GateError> {
    if ordinal >= STAGES || record.ordinal.is_some_and(|old| old >= ordinal) {
        return Err(GateError::Refused("ordinary allocation stage reused"));
    }
    record.ordinal = Some(ordinal);
    #[cfg(test)]
    if record.fault.before == Some(ordinal) {
        return Err(GateError::Refused("injected ordinary allocation failure"));
    }
    Ok(())
}
fn after(_record: &AllocationRecord, _ordinal: usize) {
    #[cfg(test)]
    if _record.fault.after == Some(_ordinal) {
        std::panic::panic_any(PANIC);
    }
}
fn point(_record: &AllocationRecord, _point: usize) -> Result<(), GateError> {
    #[cfg(test)]
    if let Some((point, panic)) = _record.fault.point {
        if point == _point {
            if panic {
                std::panic::panic_any(PANIC);
            }
            return Err(GateError::Refused(
                "injected ordinary preparation boundary failure",
            ));
        }
    }
    Ok(())
}

fn prepare_inner(
    attempts: &mut Vec<Box<RuntimeOrdinaryAttempt>>,
    pending: &mut Option<PendingOrdinaryPreparation>,
    census: &ResumeCensus,
) -> Result<(), GateError> {
    let value = pending
        .as_mut()
        .ok_or(GateError::Refused("ordinary pending preparation absent"))?;
    if value.record.started || value.record.first_failure.is_some() {
        return Err(GateError::Refused("ordinary preparation reused"));
    }
    value.record.started = true;
    if attempts.len() == attempts.capacity() {
        before(&mut value.record, 0)?;
        value.replacement =
            Some(exact_storage::empty_vec(value.expected_capacity).map_err(allocation_error)?);
        if let Some(slots) = &value.replacement {
            value.record.new_slots = slots.capacity();
            value.record.new_slots_pointer = slots.as_ptr() as usize;
        }
        after(&value.record, 0);
    }
    before(&mut value.record, 1)?;
    let current = census
        .current_observation(value.record.origin)
        .map_err(census_error)?;
    value.attempt = Some(
        exact_storage::value(RuntimeOrdinaryAttempt::empty(value, current))
            .map_err(allocation_error)?,
    );
    after(&value.record, 1);
    point(&value.record, 0)?;
    if value.attempt.is_none()
        || attempts.len() >= value.expected_capacity
        || value
            .replacement
            .as_ref()
            .is_some_and(|slots| slots.capacity() != value.expected_capacity || !slots.is_empty())
        || (value.replacement.is_none() && attempts.capacity() != value.expected_capacity)
    {
        return Err(GateError::Refused("ordinary installation shape differs"));
    }
    // Everything which can fail is above. Existing Box values only move.
    if let (Some(replacement), Some(attempt)) = (&mut value.replacement, &mut value.attempt) {
        replacement.append(attempts);
        std::mem::swap(attempts, replacement);
        std::mem::swap(&mut attempt.prior_slots, replacement);
    }
    if let Some(mut attempt) = value.attempt.take() {
        attempt.allocation = value.record;
        attempts.push(attempt);
    }
    *pending = None;
    let attempt = attempts
        .last_mut()
        .ok_or(GateError::Refused("ordinary installed attempt absent"))?;
    point(&attempt.allocation, 1)?;
    for ordinal in 2..STAGES {
        before(&mut attempt.allocation, ordinal)?;
        attempt.allocate_one(ordinal)?;
        after(&attempt.allocation, ordinal);
    }
    let current = census
        .current_observation(attempt.allocation.origin)
        .map_err(census_error)?;
    for index in 0..2 {
        attempt.copy_one(current, index)?;
        point(&attempt.allocation, index + 2)?;
    }
    point(&attempt.allocation, 4)?;
    attempt.native.finish_allocation()?;
    point(&attempt.allocation, 5)?;
    if attempt.allocation.ordinal != Some(STAGES - 1)
        || attempt.allocation.copied != [current.xstate.len(); 2]
    {
        return Err(GateError::Refused("ordinary allocation prefix incomplete"));
    }
    attempt.allocation.allocated = true;
    Ok(())
}

fn measured(
    attempts: &Vec<Box<RuntimeOrdinaryAttempt>>,
    pending: &Option<PendingOrdinaryPreparation>,
) -> Result<[usize; 4], GateError> {
    let record = record(attempts, pending)?;
    let attempt = match pending {
        Some(value) => value.attempt.as_deref(),
        None => attempts.last().map(Box::as_ref),
    };
    let slots = if record.new_slots == 0 {
        0
    } else {
        let actual = pending
            .as_ref()
            .and_then(|value| value.replacement.as_ref())
            .unwrap_or(attempts);
        if actual.capacity() != record.new_slots
            || actual.as_ptr() as usize != record.new_slots_pointer
        {
            return Err(GateError::Refused(
                "ordinary installed slot identity differs",
            ));
        }
        mul(actual.capacity(), size_of::<Box<RuntimeOrdinaryAttempt>>())?
    };
    Ok([
        record.temporary,
        slots,
        if attempt.is_some() {
            size_of::<RuntimeOrdinaryAttempt>()
        } else {
            0
        },
        attempt
            .map(RuntimeOrdinaryAttempt::payload_bytes)
            .transpose()?
            .unwrap_or(0),
    ])
}

pub(super) fn settle(
    attempts: &mut Vec<Box<RuntimeOrdinaryAttempt>>,
    pending: &mut Option<PendingOrdinaryPreparation>,
    census: &mut ResumeCensus,
) -> Result<(), GateError> {
    let amounts = match measured(attempts, pending) {
        Ok(value) => value,
        Err(error) => {
            record_mut(attempts, pending)?
                .measurement_failure
                .get_or_insert(Failure::of(&error));
            return Err(error);
        }
    };
    let record = record_mut(attempts, pending)?;
    let mut failure = None;
    for (index, actual) in amounts.into_iter().enumerate() {
        let result = actual
            .checked_sub(record.settled[index])
            .ok_or(CensusError::ProjectionMismatch)
            .and_then(|delta| {
                census.account_external(
                    record.reservation,
                    BudgetCharge {
                        source_fact_bytes: delta,
                        ..BudgetCharge::default()
                    },
                )
            });
        match result {
            Ok(()) => record.settled[index] = actual,
            Err(error) => {
                record.settlement_failure.get_or_insert(error);
                failure.get_or_insert(error);
            }
        }
    }
    match failure {
        Some(error) => Err(census_error(error)),
        None => Ok(()),
    }
}

fn mark_failure(
    attempts: &mut [Box<RuntimeOrdinaryAttempt>],
    pending: &mut Option<PendingOrdinaryPreparation>,
    failure: Failure,
) {
    if let Ok(record) = record_mut(attempts, pending) {
        record.first_failure.get_or_insert(failure);
    }
    let attempt = if let Some(value) = pending {
        value.attempt.as_deref_mut()
    } else {
        attempts.last_mut().map(Box::as_mut)
    };
    if let Some(attempt) = attempt {
        attempt.failed = true;
        if failure == Failure::Unwound {
            attempt.unwound = true;
            attempt.native.mark_aborted();
        }
    }
}
fn finish_failure(
    attempts: &mut [Box<RuntimeOrdinaryAttempt>],
    pending: &mut Option<PendingOrdinaryPreparation>,
    census: &mut ResumeCensus,
) {
    if let Ok(record) = record_mut(attempts, pending) {
        if record.finish.is_none() {
            record.finish = Some(census.finish_reservation(record.reservation));
        }
    }
}

pub(super) fn prepare(
    attempts: &mut Vec<Box<RuntimeOrdinaryAttempt>>,
    pending: &mut Option<PendingOrdinaryPreparation>,
    census: &mut ResumeCensus,
) -> Result<(), GateError> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prepare_inner(attempts, pending, census)
    }));
    let settlement = settle(attempts, pending, census);
    match outcome {
        Ok(Ok(())) => match settlement {
            Ok(()) => Ok(()),
            Err(error) => {
                mark_failure(attempts, pending, Failure::of(&error));
                finish_failure(attempts, pending, census);
                Err(error)
            }
        },
        Ok(Err(error)) => {
            mark_failure(attempts, pending, Failure::of(&error));
            finish_failure(attempts, pending, census);
            Err(error)
        }
        Err(payload) => {
            mark_failure(attempts, pending, Failure::Unwound);
            finish_failure(attempts, pending, census);
            std::panic::resume_unwind(payload)
        }
    }
}

pub(super) fn finish_success(
    attempt: &mut RuntimeOrdinaryAttempt,
    census: &mut ResumeCensus,
) -> Result<(), GateError> {
    if attempt.allocation.finish.is_some() {
        return Err(GateError::Refused("ordinary reservation already finalized"));
    }
    let result = census.finish_reservation(attempt.reservation);
    attempt.allocation.finish = Some(result);
    result.map_err(census_error)
}
pub(super) fn fail_registered(
    attempt: &mut RuntimeOrdinaryAttempt,
    census: &mut ResumeCensus,
    failure: Failure,
) {
    attempt.allocation.first_failure.get_or_insert(failure);
    attempt.failed = true;
    if failure == Failure::Unwound {
        attempt.unwound = true;
        attempt.native.mark_aborted();
        attempt.census.mark_aborted();
    }
    if attempt.allocation.finish.is_none() {
        attempt.allocation.finish = Some(census.finish_reservation(attempt.reservation));
    }
}
pub(super) fn fail_returned(
    attempt: &mut RuntimeOrdinaryAttempt,
    census: &mut ResumeCensus,
    error: &GateError,
) {
    fail_registered(attempt, census, Failure::of(error));
}

pub(super) fn temporary_bytes() -> Result<usize, GateError> {
    let terms = [
        size_of::<PendingOrdinaryPreparation>(),
        size_of::<PreparationRequest>(),
        size_of::<RuntimeOrdinaryAttempt>(),
        size_of::<RuntimeOrdinaryAttempt>(),
        runtime_native::NativeInstructionStorage::temporary_bytes()?,
        size_of::<AllocationRecord>(),
        size_of::<[AllocationRecord; 2]>(),
        size_of::<[Option<Failure>; 4]>(),
        size_of::<[Option<CensusError>; 4]>(),
        size_of::<[Result<(), CensusError>; 4]>(),
        size_of::<Result<(), GateError>>(),
        size_of::<Result<Result<(), GateError>, Box<dyn std::any::Any + Send>>>(),
        size_of::<[usize; 16]>(),
        size_of::<[bool; 8]>(),
        size_of::<[Option<usize>; 4]>(),
        size_of::<Result<Vec<Box<RuntimeOrdinaryAttempt>>, exact_storage::AllocationError>>(),
        size_of::<Result<Box<RuntimeOrdinaryAttempt>, exact_storage::AllocationError>>(),
        size_of::<Result<Vec<u8>, exact_storage::AllocationError>>(),
        size_of::<(
            std::alloc::Layout,
            *mut u8,
            *mut Box<RuntimeOrdinaryAttempt>,
        )>(),
        size_of::<[Vec<Box<RuntimeOrdinaryAttempt>>; 3]>(),
        size_of::<[Option<Box<RuntimeOrdinaryAttempt>>; 2]>(),
        size_of::<std::ops::Range<usize>>(),
        size_of::<std::iter::Enumerate<std::array::IntoIter<usize, 4>>>(),
        size_of::<[&ObservedStop; 4]>(),
        size_of::<[&mut RuntimeOrdinaryAttempt; 4]>(),
        size_of::<[&ResumeCensus; 4]>(),
        size_of::<[&PendingOrdinaryPreparation; 4]>(),
        size_of::<(
            InstructionAttemptShape,
            AdmissionStop,
            OriginId,
            Reservation,
            Instant,
        )>(),
        size_of::<[&[u8]; 6]>(),
        size_of::<Result<[usize; 4], GateError>>(),
    ];
    let mut total = size_of::<[usize; 30]>()
        + size_of::<std::array::IntoIter<usize, 30>>()
        + size_of::<([usize; 6], Option<usize>, Result<usize, GateError>)>();
    for item in terms {
        total = add(total, item)?;
    }
    Ok(total)
}

/// Actual partial owners; absent fields are not zero-valued observations.
#[cfg(test)]
struct AllocationView<'a> {
    record: &'a AllocationRecord,
    pending: bool,
    slots: &'a Vec<Box<RuntimeOrdinaryAttempt>>,
    replacement: Option<&'a Vec<Box<RuntimeOrdinaryAttempt>>>,
    attempt: Option<&'a RuntimeOrdinaryAttempt>,
    native: Option<runtime_native::NativeAllocationView<'a>>,
}
#[cfg(test)]
fn partial_view<'a>(
    attempts: &'a Vec<Box<RuntimeOrdinaryAttempt>>,
    pending: &'a Option<PendingOrdinaryPreparation>,
) -> Result<AllocationView<'a>, GateError> {
    let attempt = match pending {
        Some(value) => value.attempt.as_deref(),
        None => attempts.last().map(Box::as_ref),
    };
    Ok(AllocationView {
        record: record(attempts, pending)?,
        pending: pending.is_some(),
        slots: attempts,
        replacement: pending
            .as_ref()
            .and_then(|value| value.replacement.as_ref()),
        native: attempt.map(|value| value.native.partial_view()),
        attempt,
    })
}
#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission::runtime) mod native_oracle;
#[cfg(test)]
mod tests;
