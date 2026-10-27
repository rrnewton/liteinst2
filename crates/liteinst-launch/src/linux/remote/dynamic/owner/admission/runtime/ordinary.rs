//! Prospective ordinary-attempt storage and the connected consuming route.
//! Every attempt is installed before native reads/effects; failure and unwind
//! retain it beside the physical native owner for the outer cleanup path.
use super::super::census::{Reservation, SharedOrdinaryPreparation, ordinary_shared_census_charge};
use super::super::runtime_capture::{CapturedRuntimeRead, RuntimeCatalogCheckpoint};
use super::super::runtime_instruction::{DebugDisposition, classify};
use super::super::runtime_native::{
    self, ControlLineage, InstructionAttemptShape, InstructionEffect, InstructionObservation,
    NativeInstructionStorage,
};
use super::super::source_identity::SourceReadProgress;
use super::instruction::RuntimeInstructionBinding;
use super::*;
use crate::selected::SyscallAliases;

const MAP_BYTES: usize = 64 * 1024;
mod storage;
pub(super) use storage::PendingOrdinaryPreparation;
#[cfg(test)]
pub(super) use storage::native_oracle::OrdinaryAllocationFault;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptStage {
    Allocated,
    Source,
    Census,
    Native,
    Commit,
    Complete,
}

pub(super) struct RuntimeOrdinaryAttempt {
    reservation: Reservation,
    stop: AdmissionStop,
    before: ObservedStop,
    source: SourceChecks,
    native: NativeInstructionStorage,
    allocation: storage::AllocationRecord,
    // Already charged old slot storage, retained empty after Box-owner transfer.
    prior_slots: Vec<Box<RuntimeOrdinaryAttempt>>,
    census: SharedOrdinaryPreparation,
    stage: AttemptStage,
    failed: bool,
    unwound: bool,
}

struct SourceChecks {
    bytes: [Vec<u8>; 3],
    progress: [SourceReadProgress; 3],
    identity: Vec<u8>,
    checkpoint: ObservedStop,
    checkpoint_stop: AdmissionStop,
}

fn root_temporary_bytes() -> Result<usize, GateError> {
    let temporary = add(
        CapturedRuntimeRead::temporary_bytes(),
        add(
            size_of::<RuntimeInstructionBinding<'_>>(),
            size_of::<SourceObserver<'_, '_>>(),
        )?,
    )?;
    let temporary = add(temporary, size_of::<maps::FetchGeometry>())?;
    let temporary = add(
        temporary,
        runtime_native::ControlProfile::temporary_bytes()?,
    )?;
    let temporary = add(
        temporary,
        add(size_of::<ControlLineage>(), size_of::<ControlLineage>())?,
    )?;
    add(temporary, storage::temporary_bytes()?)
}
fn root_bytes(window: usize, shape: InstructionAttemptShape) -> Result<usize, GateError> {
    // The complete wrapper, pending metadata and prior-slot Vec header are
    // embedded here once. Native's independent payloads remain unchanged.
    let payload = add(mul(3, window)?, add(2 * MAX_XSTATE, MAP_BYTES)?)?;
    add(
        add(size_of::<RuntimeOrdinaryAttempt>(), payload)?,
        add(
            NativeInstructionStorage::payload_reservation(shape)?,
            root_temporary_bytes()?,
        )?,
    )
}

impl RuntimeOwner {
    pub(super) fn ordinary(
        &mut self,
        owner: &mut Owner,
        index: usize,
        until: Instant,
    ) -> Result<(), GateError> {
        owner.time_left(until, "runtime ordinary preparation")?;
        if self.stage != RuntimeStage::Ready
            || self.ordinary_preparation.is_some()
            || self.selected_pending.is_some()
            || self.ordinary_attempts.last().is_some_and(|attempt| {
                attempt.stage != AttemptStage::Complete
                    || attempt.failed
                    || attempt.unwound
                    || attempt.allocation.first_failure.is_some()
            })
        {
            return Err(GateError::Refused(
                "runtime ordinary operation is not ready",
            ));
        }
        let origin = self
            .initial_origin
            .ok_or(GateError::Refused("runtime current origin is absent"))?;
        let census = self
            .census
            .as_mut()
            .ok_or(GateError::Refused("runtime census is absent"))?;
        let before = census.current_observation(origin).map_err(census_error)?;
        let stop = self
            .native
            .as_ref()
            .ok_or(GateError::Refused("runtime native custody absent"))?
            .admission_current(before.task.task)?;
        let window = self
            .sources
            .window(index)
            .ok_or(GateError::Refused("runtime source window absent"))?;
        // Pure tentative classification sizes the operation. Absent describes
        // the required native profile; native positively reads that profile
        // before any effect. This result grants no release permission.
        let candidate = classify(
            window.snapshot,
            &before.registers,
            DebugDisposition::Absent,
            &SyscallAliases::default(),
        )
        .map_err(|_| GateError::Refused("runtime ordinary encoding or mode is unqualified"))?;
        let geometry =
            maps::FetchGeometry::for_initial_source(window.initial_source(), candidate.range())?;
        geometry.projected_rows(self.sources.runtime_baseline_maps()?)?;
        let shape = InstructionAttemptShape::from_geometry(&geometry)?;
        let window_bytes = window.snapshot.bytes().len();
        let spare = usize::from(self.ordinary_attempts.len() == self.ordinary_attempts.capacity());
        let new_capacity = add(self.ordinary_attempts.capacity(), spare)?;
        let retained = add(
            root_bytes(window_bytes, shape)?,
            mul(
                if spare != 0 { new_capacity } else { 0 },
                size_of::<Box<RuntimeOrdinaryAttempt>>(),
            )?,
        )?;
        let mut charge = ordinary_shared_census_charge().map_err(census_error)?;
        charge.source_fact_bytes = add(charge.source_fact_bytes, retained)?;
        let serial = self.next_execution;
        let next = serial
            .checked_add(1)
            .ok_or(GateError::Refused("runtime execution identity exhausted"))?;
        let temporary = root_temporary_bytes()?;
        let reservation = census.reserve(charge).map_err(census_error)?;
        self.next_execution = next;
        let pending = PendingOrdinaryPreparation::new(storage::PreparationRequest {
            reservation,
            origin,
            serial,
            stop,
            until,
            shape,
            window_bytes,
            temporary,
            expected_capacity: new_capacity,
        });
        #[cfg(test)]
        let pending = pending.with_test_fault(self.ordinary_allocation_fault.take());
        self.ordinary_preparation = Some(pending);
        storage::prepare(
            &mut self.ordinary_attempts,
            &mut self.ordinary_preparation,
            census,
        )?;
        let attempt = self
            .ordinary_attempts
            .last_mut()
            .expect("installed ordinary attempt");
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), GateError> {
                if !attempt.allocation.allocated
                    || attempt.allocation.until != until
                    || attempt.allocation.serial != serial
                {
                    return Err(GateError::Refused(
                        "ordinary retained allocation binding differs",
                    ));
                }
                let native = self
                    .native
                    .as_mut()
                    .ok_or(GateError::Refused("runtime native custody absent"))?;
                let island = &self
                    .bootstrap
                    .as_ref()
                    .and_then(PreparedInitialBootstrap::completed)
                    .ok_or(GateError::Refused("runtime bootstrap custody absent"))?
                    .island;
                attempt.stage = AttemptStage::Source;
                let proof = {
                    let reader = self.sources.runtime_read(
                        owner,
                        native,
                        island,
                        &attempt.stop,
                        &attempt.before,
                        until,
                    )?;
                    reader.verify_window(
                        index,
                        &mut attempt.source.bytes[0],
                        &mut attempt.source.progress[0],
                        &mut attempt.source.identity,
                    )?
                };
                let candidate = classify(
                    proof.window().snapshot,
                    &attempt.before.registers,
                    DebugDisposition::Absent,
                    &SyscallAliases::default(),
                )
                .map_err(|_| {
                    GateError::Refused("runtime ordinary source classification changed")
                })?;
                let lineage = self
                    .control_lineage
                    .as_ref()
                    .ok_or(GateError::Refused("runtime control lineage absent"))?;
                let binding = RuntimeInstructionBinding::new(
                    proof, candidate, census, origin, serial, island, lineage,
                )?;
                attempt.stage = AttemptStage::Census;
                attempt
                    .census
                    .prepare(census, reservation, &binding)
                    .map_err(census_error)?;
                let prepared = attempt.census.prepared_mut().map_err(census_error)?;
                let remaining = prepared.remaining_charge().map_err(census_error)?;
                {
                    let mut observer = SourceObserver {
                        sources: &self.sources,
                        binding: &binding,
                        census,
                        reservation: attempt.reservation,
                        remaining,
                        storage: &mut attempt.source,
                    };
                    attempt.stage = AttemptStage::Native;
                    // SAFETY: binding consumes the current full source proof and exact
                    // census input. Native additionally authenticates control lineage,
                    // every real stop and the complete restoration/permission outcome.
                    unsafe {
                        runtime_native::execute_owned_instruction(
                            owner,
                            native,
                            &binding,
                            attempt.native.require_complete_mut()?,
                            &mut observer,
                        )?;
                    }
                }
                drop(binding);
                attempt.stage = AttemptStage::Commit;
                let completed = attempt.native.take_completed()?;
                let lineage = ControlLineage::from_completion(&completed)?;
                let result = census
                    .commit_shared_ordinary(reservation, completed, prepared)
                    .map_err(census_error)?;
                storage::finish_success(attempt, census)?;
                self.initial_origin = Some(result.current);
                self.control_lineage = Some(lineage);
                attempt.stage = AttemptStage::Complete;
                Ok(())
            }));
        match outcome {
            Ok(result) => {
                if let Err(error) = &result {
                    storage::fail_returned(attempt, census, error);
                }
                result
            }
            Err(payload) => {
                storage::fail_registered(attempt, census, storage::Failure::Unwound);
                std::panic::resume_unwind(payload)
            }
        }
    }
}

struct SourceObserver<'a, 'binding> {
    sources: &'a PreparedInitialSources,
    binding: &'a RuntimeInstructionBinding<'binding>,
    census: &'a ResumeCensus,
    reservation: Reservation,
    remaining: BudgetCharge,
    storage: &'a mut SourceChecks,
}

fn native_error(error: GateError) -> LaunchError {
    match error {
        GateError::Control(error) => error,
        GateError::Refused(reason) => LaunchError::Invalid(reason),
        _ => LaunchError::Invalid("runtime original source verification failed"),
    }
}

impl SourceChecks {
    fn checkpoint(
        &mut self,
        stop: &AdmissionStop,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        if !(512..MAX_XSTATE).contains(&state.xstate.len())
            || state.xstate.len() > self.checkpoint.xstate.capacity()
            || stop.signal.is_some()
            || stop.phase != AdmissionPhase::Restored
        {
            return Err(LaunchError::Invalid(
                "runtime source recheck checkpoint differs",
            ));
        }
        self.checkpoint.xstate.clear();
        self.checkpoint.xstate.extend_from_slice(&state.xstate);
        self.checkpoint.token = stop.token.clone();
        self.checkpoint.task = stop.identity;
        self.checkpoint.logical_pc = state.registers.rip;
        self.checkpoint.registers = state.registers;
        self.checkpoint.signal_mask = state.mask;
        self.checkpoint.phase = StopPhase::UserCheckpoint;
        self.checkpoint.signal = None;
        self.checkpoint_stop = stop.clone();
        Ok(())
    }
}

impl InstructionObservation for SourceObserver<'_, '_> {
    fn before_effect(
        &mut self,
        owner: &Owner,
        _native: &NativeLifecycle,
        _effect: InstructionEffect,
        _current: &AdmissionStop,
        until: Instant,
    ) -> Result<(), LaunchError> {
        if until != self.binding.until() {
            return Err(LaunchError::Invalid("runtime ordinary deadline changed"));
        }
        self.census
            .check_reserved(self.reservation, self.remaining)
            .map_err(census_error)
            .map_err(native_error)?;
        owner.time_left(until, "runtime ordinary native effect")?;
        Ok(())
    }

    fn opened(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        current: &AdmissionStop,
        state: &TaskStateSnapshot,
        actual_maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError> {
        if until != self.binding.until()
            || state.registers != self.binding.before().registers
            || state.xstate != self.binding.before().xstate
            || state.mask != self.binding.before().signal_mask
        {
            return Err(LaunchError::Invalid(
                "runtime opening changed original application state",
            ));
        }
        self.storage.checkpoint(current, state)?;
        let reader = self
            .sources
            .runtime_read_opened(
                owner,
                native,
                RuntimeCatalogCheckpoint {
                    island: self.binding.island(),
                    stop: &self.storage.checkpoint_stop,
                    observed: &self.storage.checkpoint,
                },
                self.binding.geometry(),
                actual_maps,
                until,
            )
            .map_err(native_error)?;
        reader
            .recheck_window(
                self.binding.source_id(),
                &mut self.storage.bytes[1],
                &mut self.storage.progress[1],
                &mut self.storage.identity,
            )
            .map_err(native_error)
    }

    fn closed(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        current: &AdmissionStop,
        state: &TaskStateSnapshot,
        actual_maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError> {
        if until != self.binding.until() {
            return Err(LaunchError::Invalid("runtime closing deadline changed"));
        }
        maps::verify_closed(self.binding.baseline_maps(), actual_maps).map_err(native_error)?;
        self.storage.checkpoint(current, state)?;
        let reader = self
            .sources
            .runtime_read(
                owner,
                native,
                self.binding.island(),
                &self.storage.checkpoint_stop,
                &self.storage.checkpoint,
                until,
            )
            .map_err(native_error)?;
        reader
            .recheck_window(
                self.binding.source_id(),
                &mut self.storage.bytes[2],
                &mut self.storage.progress[2],
                &mut self.storage.identity,
            )
            .map_err(native_error)
    }
}

#[cfg(test)]
pub(super) mod native_tests;
