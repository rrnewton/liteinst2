//! Consuming stack bookkeeping. Native authority enters only through the
//! non-Clone completion seal; private models cannot construct that seal.
use super::super::super::trusted::{AdmissionPhase, AdmissionStop, TaskStateSnapshot};
use super::super::exact_storage::{self, AllocationError};
use super::super::runtime::maps::FetchGeometry;
use super::super::runtime::stack::RuntimeStackBinding;
use super::super::runtime_capture::{PreparedInitialSources, SourceWindowId};
use super::super::runtime_instruction::CandidateKind;
use super::super::runtime_native::{NativeCheckpoint, NativeTrace};
use super::super::runtime_stack::access::{PkuLayout, validate_state};
use super::super::runtime_stack::metadata::{StackDescriptor, StackMetadata, validate_smaps};
use super::super::runtime_stack::operand::{
    OperandDescription, OperandGeometry, StackOperation, validate_effect,
};
use super::super::runtime_stack::profile::ProfileDescription;
use super::super::runtime_stack_native::acquire::{StackCaptureAssociation, StackWordView};
use super::super::runtime_stack_native::{OwnedStackCompletion, StackWordViews};
use super::stack_calls::{PotentialCallId, RuntimeCallLedger};
use super::*;
use std::mem::size_of;
use std::time::Instant;

pub(super) mod binding;
#[cfg(test)]
pub(super) mod native_oracle;
pub(super) mod storage;
#[cfg(test)]
pub(super) mod tests;
mod validate;
use binding::{Binding, ProfileRecord, SourceRecord, encoding, validate_operand};
use storage::PayloadProgress;

const STATES: usize = 16;
const WITNESSES: usize = 7;
const TRACE_DR6: u64 = 0xffff0ff0 ^ 0x4000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StackEvidence {
    binding: Option<Binding>,
    trace: Option<NativeTrace>,
    words: Option<[[u8; 16]; 4]>,
    call: Option<PotentialCallId>,
}

/// Installed before payload allocation. Every allocated prefix survives an
/// error/unwind; after transfer the empty owner remains retained as metadata.
pub(in super::super) struct PreparedStackCensus {
    binding: Option<Binding>,
    before: Option<ObservedStop>,
    buffers: [Vec<u8>; STATES],
    evidence: Option<Box<[StackEvidence]>>,
    allocation: PayloadProgress,
    settled_bytes: usize,
    prepared: bool,
    committed: bool,
    #[cfg(test)]
    allocation_fail_before: Option<usize>,
    #[cfg(test)]
    allocation_panic_after: Option<usize>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct StackCensusResult {
    pub(in super::super) current: OriginId,
}

pub(super) fn add(a: usize, b: usize) -> Result<usize, CensusError> {
    a.checked_add(b).ok_or(CensusError::Capacity)
}
pub(super) fn mul(a: usize, b: usize) -> Result<usize, CensusError> {
    a.checked_mul(b).ok_or(CensusError::Capacity)
}
pub(super) fn allocation_error(error: AllocationError) -> CensusError {
    match error {
        AllocationError::Capacity => CensusError::Capacity,
        AllocationError::Allocation => CensusError::Allocation,
    }
}
fn fixed_commit_bytes() -> Result<usize, CensusError> {
    add(
        add(
            mul(STATES, size_of::<ObservedStop>())?,
            mul(6, size_of::<HistoryRecord>())?,
        )?,
        add(size_of::<OwnerConsumption>(), size_of::<StoredOrigin>())?,
    )
}
fn preparation_bytes() -> Result<usize, CensusError> {
    add(
        add(
            size_of::<PreparedStackCensus>(),
            mul(STATES, MAX_XSTATE_BYTES)?,
        )?,
        size_of::<StackEvidence>(),
    )
}
pub(in super::super) fn stack_census_charge() -> Result<BudgetCharge, CensusError> {
    Ok(BudgetCharge {
        source_fact_bytes: add(preparation_bytes()?, fixed_commit_bytes()?)?,
        origins: 1,
        witnesses: WITNESSES,
        ..BudgetCharge::default()
    })
}
/// Fixed managed temporary values, separate from retained owners. The shared
/// acquisition bound also covers the same pure stack/state/metadata validators;
/// adding it conservatively does not claim those read operations run again.
pub(in super::super) fn stack_census_temporary_bytes() -> Result<usize, CensusError> {
    use super::super::mapping::maps::{MapEntries, MapEntry, ParsedMaps};
    let mut bytes = super::super::runtime_stack_native::acquire::temporary_bytes()
        .map_err(|_| CensusError::Capacity)?;
    for size in [
        3 * size_of::<Binding>(),
        2 * size_of::<ProfileRecord>(),
        2 * size_of::<SourceRecord>(),
        size_of::<CompletionModel<'_>>(),
        size_of::<StackWordViews<'_>>(),
        8 * size_of::<NativeCheckpoint<'_>>(),
        2 * size_of::<NativeTrace>(),
        2 * size_of::<DynamicSignalInfo>(),
        2 * size_of::<ObservedStop>(),
        4 * size_of::<BudgetCharge>(),
        size_of::<Result<(usize, u64, BudgetCharge, BudgetCharge), CensusError>>(),
        size_of::<Result<StackCensusResult, CensusError>>(),
        3 * size_of::<ParsedMaps<'_>>(),
        4 * size_of::<MapEntries<'_>>(),
        6 * size_of::<MapEntry<'_>>(),
        2 * size_of::<FetchGeometry>(),
        4 * size_of::<std::ops::Range<u64>>(),
        size_of::<[[u8; 16]; 4]>(),
        8 * size_of::<&[u8]>(),
        size_of::<[usize; 16]>(),
    ] {
        bytes = add(bytes, size)?;
    }
    Ok(bytes)
}
pub(super) fn copy_observed(source: &ObservedStop, mut bytes: Vec<u8>) -> ObservedStop {
    bytes.extend_from_slice(&source.xstate);
    ObservedStop {
        token: source.token.clone(),
        task: source.task,
        logical_pc: source.logical_pc,
        registers: source.registers,
        xstate: bytes,
        signal_mask: source.signal_mask,
        phase: source.phase,
        signal: source.signal.clone(),
    }
}
fn copy_checkpoint(
    source: NativeCheckpoint<'_>,
    mut bytes: Vec<u8>,
    phase: StopPhase,
    signal: Option<DynamicSignalInfo>,
) -> ObservedStop {
    bytes.extend_from_slice(&source.state.xstate);
    ObservedStop {
        token: source.stop.token.clone(),
        task: source.stop.identity,
        logical_pc: source.state.registers.rip,
        registers: source.state.registers,
        xstate: bytes,
        signal_mask: source.state.mask,
        phase,
        signal,
    }
}
fn same_architecture(observed: &ObservedStop, state: &TaskStateSnapshot) -> bool {
    observed.registers == state.registers
        && observed.xstate == state.xstate
        && observed.signal_mask == state.mask
}

/// Borrowed model data, private to this leaf. Production constructs it only
/// from the consumed real completion; tests exercise comparisons, not permits.
pub(super) struct CompletionModel<'a> {
    source: SourceWindowId,
    origin: OriginId,
    execution: ExecutionId,
    until: Instant,
    operand: &'a OperandDescription,
    profile: &'a ProfileDescription,
    identity_stop: &'a AdmissionStop,
    identity_initial: &'a AdmissionStop,
    identity_stack: StackDescriptor,
    identity_metadata: StackMetadata,
    identity_layout: PkuLayout,
    identity_rsp: u64,
    logical: NativeCheckpoint<'a>,
    opening: [NativeCheckpoint<'a>; 3],
    step: NativeCheckpoint<'a>,
    closing: [NativeCheckpoint<'a>; 3],
    trace: NativeTrace,
    words: StackWordViews<'a>,
    call: Option<PotentialCallId>,
}

impl ResumeCensus {
    pub(in super::super) fn prepare_stack(
        &mut self,
        reservation: Reservation,
        actual: &RuntimeStackBinding<'_, '_>,
        prepared: &mut PreparedStackCensus,
    ) -> Result<(), CensusError> {
        let binding = Binding::from_actual(self, reservation, actual)?;
        self.prepare_stack_model(binding, prepared)
    }
    fn prepare_stack_model(
        &self,
        binding: Binding,
        prepared: &mut PreparedStackCensus,
    ) -> Result<(), CensusError> {
        if prepared.prepared || prepared.committed {
            return Err(CensusError::InvalidConsumption);
        }
        prepared.require_allocated()?;
        if prepared.settled_bytes != preparation_bytes()? {
            return Err(CensusError::ReservationExhausted);
        }
        binding.validate_current(self)?;
        self.check_reserved(
            binding.reservation,
            BudgetCharge {
                source_fact_bytes: fixed_commit_bytes()?,
                origins: 1,
                witnesses: WITNESSES,
                ..BudgetCharge::default()
            },
        )?;
        if self.state.origins.len() == self.state.origins.capacity()
            || self
                .state
                .history
                .capacity()
                .saturating_sub(self.state.history.len())
                < WITNESSES
        {
            return Err(CensusError::Capacity);
        }
        self.state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        let before = self.current_observation(binding.origin)?;
        // No fallible operation follows these transfers into already-owned storage.
        prepared.before = Some(copy_observed(
            before,
            std::mem::take(&mut prepared.buffers[0]),
        ));
        prepared.evidence.as_mut().expect("allocated evidence")[0].binding = Some(binding.clone());
        prepared.binding = Some(binding);
        prepared.prepared = true;
        Ok(())
    }
    pub(in super::super) fn commit_stack(
        &mut self,
        reservation: Reservation,
        actual: OwnedStackCompletion<'_>,
        prepared: &mut PreparedStackCensus,
        calls: &RuntimeCallLedger,
        sources: &PreparedInitialSources,
    ) -> Result<StackCensusResult, CensusError> {
        let identity = actual.identity();
        let words = actual.words();
        let model = CompletionModel {
            source: identity.source_id(),
            origin: identity.origin(),
            execution: identity.execution(),
            until: identity.until(),
            operand: identity.operand_description(),
            profile: words.profile,
            identity_stop: identity.stop(),
            identity_initial: identity.initial_stop(),
            identity_stack: identity.stack_descriptor(),
            identity_metadata: identity.stack_metadata(),
            identity_layout: identity.pku_layout(),
            identity_rsp: identity.initial_rsp(),
            logical: actual.logical_before(),
            opening: actual.opening(),
            step: actual.step(),
            closing: actual.closing(),
            trace: actual.trace(),
            words,
            call: actual.call_id(),
        };
        validate::require_catalog_maps(sources, &model.words)?;
        calls.audit(sources)?;
        prepared
            .binding
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?
            .require_source(sources)?;
        self.commit_stack_model(reservation, &model, prepared, calls)
    }
}

impl ResumeCensus {
    fn commit_stack_model(
        &mut self,
        reservation: Reservation,
        actual: &CompletionModel<'_>,
        prepared: &mut PreparedStackCensus,
        calls: &RuntimeCallLedger,
    ) -> Result<StackCensusResult, CensusError> {
        let (old, next, remaining, used) =
            self.validate_stack_model(reservation, actual, prepared, calls)?;
        let binding = prepared.binding.as_ref().expect("validated stack binding");
        let id = OriginId {
            census: self.identity,
            serial: self.state.next_serial,
        };
        let phase = StopPhase::OwnedStackComplete {
            execution: binding.execution,
        };
        let signal = Some(DynamicSignalInfo {
            raw: actual.trace.signal,
        });
        let mut slot = 1;
        // All identity, phase, state, source, word, CALL, capacity, serial and
        // debit checks precede mutation. Everything below moves fixed owners
        // or copies into their exact prepaid capacity; there is no callback.
        for index in 0..3 {
            let before = if index == 0 {
                let retained = prepared.before.as_mut().expect("validated stack before");
                ObservedStop {
                    token: retained.token.clone(),
                    task: retained.task,
                    logical_pc: retained.logical_pc,
                    registers: retained.registers,
                    xstate: std::mem::take(&mut retained.xstate),
                    signal_mask: retained.signal_mask,
                    phase: retained.phase,
                    signal: retained.signal.clone(),
                }
            } else {
                copy_checkpoint(
                    actual.opening[index - 1],
                    next_buffer(&mut prepared.buffers, &mut slot),
                    StopPhase::UserCheckpoint,
                    None,
                )
            };
            let after = copy_checkpoint(
                actual.opening[index],
                next_buffer(&mut prepared.buffers, &mut slot),
                StopPhase::UserCheckpoint,
                None,
            );
            self.state.history.push(HistoryRecord::Refreshed {
                origin: binding.origin,
                before,
                after,
            });
        }
        self.state.origins[old].current.token = actual.opening[2].stop.token.clone();
        let before = copy_checkpoint(
            actual.opening[2],
            next_buffer(&mut prepared.buffers, &mut slot),
            StopPhase::UserCheckpoint,
            None,
        );
        let successor = copy_checkpoint(
            actual.step,
            next_buffer(&mut prepared.buffers, &mut slot),
            phase,
            signal.clone(),
        );
        let mut records = prepared.evidence.take().expect("validated stack evidence");
        records[0].trace = Some(actual.trace);
        records[0].words = Some(actual.words.captures.map(|view| view.word.bytes));
        records[0].call = actual.call;
        self.state.history.push(HistoryRecord::Consumed {
            origin: binding.origin,
            evidence: OwnerConsumption {
                before,
                successor,
                evidence: Consumption::OwnedStack(records),
            },
        });
        self.state.origins[old].active = false;
        let initial = copy_checkpoint(
            actual.step,
            next_buffer(&mut prepared.buffers, &mut slot),
            phase,
            signal.clone(),
        );
        let current = copy_checkpoint(
            actual.closing[2],
            next_buffer(&mut prepared.buffers, &mut slot),
            StopPhase::UserCheckpoint,
            None,
        );
        self.state.origins.push(StoredOrigin {
            row: OriginRow {
                id,
                kind: OriginKind::CurrentHeldPc,
                pc: initial.logical_pc,
                created_generation: self.state.generation,
                initial,
            },
            current,
            active: true,
            frame: None,
            runtime_kernel: None,
        });
        for index in 0..3 {
            let before = if index == 0 {
                copy_checkpoint(
                    actual.step,
                    next_buffer(&mut prepared.buffers, &mut slot),
                    phase,
                    signal.clone(),
                )
            } else {
                copy_checkpoint(
                    actual.closing[index - 1],
                    next_buffer(&mut prepared.buffers, &mut slot),
                    StopPhase::UserCheckpoint,
                    None,
                )
            };
            let after = copy_checkpoint(
                actual.closing[index],
                next_buffer(&mut prepared.buffers, &mut slot),
                StopPhase::UserCheckpoint,
                None,
            );
            self.state.history.push(HistoryRecord::Refreshed {
                origin: id,
                before,
                after,
            });
        }
        self.state.next_serial = next;
        self.commit_debit(reservation, remaining, used);
        prepared.committed = true;
        Ok(StackCensusResult { current: id })
    }
}
fn next_buffer(buffers: &mut [Vec<u8>; STATES], index: &mut usize) -> Vec<u8> {
    let result = std::mem::take(&mut buffers[*index]);
    *index += 1;
    result
}
