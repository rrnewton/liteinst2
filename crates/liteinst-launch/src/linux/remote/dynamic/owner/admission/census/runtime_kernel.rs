//! Prepaid, atomic bookkeeping for one sealed original-site kernel invocation.
//! This module cannot release a task or manufacture a native outcome seal.
use super::super::super::bootstrap::Request;
use super::super::super::kernel_journal::{KernelAttemptId, KernelStopIdentity};
use super::super::super::trusted::{AdmissionPhase, TaskStateSnapshot};
use super::super::exact_storage::{self, AllocationError};
use super::super::runtime::kernel::{
    RuntimeKernelBinding, RuntimeKernelIdentity, RuntimeKernelOperation,
};
use super::super::runtime_kernel_native::{
    NativeKernelReturnTrace, NativeKernelTerminalTrace, NativePreExitCheckpoint,
    NativeSyscallCheckpoint, OwnedRuntimeKernelReturn, OwnedRuntimeKernelTerminal,
};
use super::super::runtime_native::NativeCheckpoint;
use super::*;
use crate::linux::remote::dynamic::admission::RuntimePendingToken;
use crate::{DynamicEvent, DynamicEventKind};
use liteinst2::contracts::CodeIdentity;
use std::mem::size_of;
use std::time::Instant;

mod commit;
mod lineage;
mod validate;
pub(super) use lineage::KernelOriginLineage;
// Insert before the existing cfg(test) tests declaration; do not append after it.
#[cfg(test)]
mod native_oracle;

#[cfg(test)]
pub(super) mod tests;

const RETURN_STATES: usize = 19;
const TERMINAL_STATES: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Binding {
    census: u64,
    reservation: Reservation,
    candidate_serial: u64,
    identity: RuntimeKernelIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedOutcome {
    returned: Option<(OriginId, NativeKernelReturnTrace)>,
    terminal: Option<RetainedTerminal>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedTerminal {
    exiting: DynamicEvent,
    terminal: DynamicEvent,
    trace: NativeKernelTerminalTrace,
}

/// The additional actual ENTRY is independent of the retained actual EXIT in
/// OwnerConsumption.successor. The one-element box is prepared before effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in super::super) struct KernelEvidence {
    identity: RuntimeKernelIdentity,
    entry: Option<ObservedStop>,
    outcome: Option<RetainedOutcome>,
}
impl KernelEvidence {
    pub(super) fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self
                .entry
                .as_ref()
                .map_or(0, |value| value.xstate.capacity())
    }
}

/// Descriptive commit result for the journal. Only the private receipt below
/// proves that this view was produced after the complete atomic census commit.
pub(in crate::linux::remote::dynamic::owner) enum RuntimeKernelCommitOutcome<'a> {
    Returned {
        current: (u64, u64),
        stop: &'a DynamicStop,
    },
    Terminal {
        event: &'a DynamicEvent,
        sequence: u64,
        wait_status: i32,
        physical_status: i32,
        pin_revents: i16,
    },
}

pub(in crate::linux::remote::dynamic::owner) struct RuntimeKernelCommitView<'a> {
    pub(in crate::linux::remote::dynamic::owner) attempt: KernelAttemptId,
    pub(in crate::linux::remote::dynamic::owner) pending: &'a RuntimePendingToken,
    pub(in crate::linux::remote::dynamic::owner) source: CodeIdentity,
    pub(in crate::linux::remote::dynamic::owner) window: usize,
    pub(in crate::linux::remote::dynamic::owner) origin: (u64, u64),
    pub(in crate::linux::remote::dynamic::owner) execution: (u64, u64),
    pub(in crate::linux::remote::dynamic::owner) task: DynamicTask,
    pub(in crate::linux::remote::dynamic::owner) number: u64,
    pub(in crate::linux::remote::dynamic::owner) arguments: [u64; 6],
    pub(in crate::linux::remote::dynamic::owner) until: Instant,
    pub(in crate::linux::remote::dynamic::owner) outcome: RuntimeKernelCommitOutcome<'a>,
}

struct CommittedOutcome {
    returned: Option<(OriginId, DynamicStop)>,
    terminal: Option<(DynamicEvent, NativeKernelTerminalTrace)>,
}

/// Non-Clone acknowledgement. No constructor is exposed outside this module.
/// It contains fixed metadata only and cannot replace native raw evidence.
pub(in crate::linux::remote::dynamic::owner) struct RuntimeKernelCommitReceipt {
    identity: RuntimeKernelIdentity,
    outcome: CommittedOutcome,
}
impl RuntimeKernelCommitReceipt {
    pub(in crate::linux::remote::dynamic::owner) fn view(&self) -> RuntimeKernelCommitView<'_> {
        let identity = &self.identity;
        RuntimeKernelCommitView {
            attempt: identity.attempt(),
            pending: identity.pending(),
            source: identity.source_id().identity(),
            window: identity.source_id().index(),
            origin: (identity.origin().census, identity.origin().serial),
            execution: (identity.execution().session, identity.execution().serial),
            task: identity.task(),
            number: identity.number(),
            arguments: identity.arguments(),
            until: identity.until(),
            outcome: match (&self.outcome.returned, &self.outcome.terminal) {
                (Some((current, stop)), None) => RuntimeKernelCommitOutcome::Returned {
                    current: (current.census, current.serial),
                    stop,
                },
                (None, Some((event, trace))) => RuntimeKernelCommitOutcome::Terminal {
                    event,
                    sequence: trace.terminal_sequence,
                    wait_status: trace.terminal_status,
                    physical_status: trace.physical_status,
                    pin_revents: trace.pin_revents,
                },
                _ => unreachable!("private completed census receipt has one outcome"),
            },
        }
    }
}

pub(in super::super) struct RuntimeKernelCensusResult<'a> {
    pub(in super::super) current: Option<OriginId>,
    pub(in super::super) receipt: &'a RuntimeKernelCommitReceipt,
}

/// Empty buffer/header storage stays retained after payload transfers. Neither
/// failure nor successful commit refunds any original reservation or debit.
pub(in super::super) struct PreparedRuntimeKernelCensus {
    binding: Binding,
    before: ObservedStop,
    buffers: [Vec<u8>; RETURN_STATES - 1],
    evidence: Option<Box<[KernelEvidence]>>,
    preparation_debit: usize,
    receipt: Option<RuntimeKernelCommitReceipt>,
}

fn add(a: usize, b: usize) -> Result<usize, CensusError> {
    a.checked_add(b).ok_or(CensusError::Capacity)
}
fn mul(a: usize, b: usize) -> Result<usize, CensusError> {
    a.checked_mul(b).ok_or(CensusError::Capacity)
}
fn states(operation: RuntimeKernelOperation) -> usize {
    if operation.returns() {
        RETURN_STATES
    } else {
        TERMINAL_STATES
    }
}
fn witnesses(operation: RuntimeKernelOperation) -> usize {
    if operation.returns() { 8 } else { 4 }
}
fn fixed_commit_bytes(operation: RuntimeKernelOperation) -> Result<usize, CensusError> {
    // ENTRY's header is already part of the prepaid evidence allocation.
    // The other endpoint headers follow the existing logical census formulas.
    let observations = mul(states(operation) - 1, size_of::<ObservedStop>())?;
    if operation.returns() {
        add(
            add(observations, mul(7, size_of::<HistoryRecord>())?)?,
            add(size_of::<OwnerConsumption>(), size_of::<StoredOrigin>())?,
        )
    } else {
        add(observations, mul(4, size_of::<HistoryRecord>())?)
    }
}
fn preparation_bytes(capacities: usize) -> Result<usize, CensusError> {
    add(
        add(size_of::<PreparedRuntimeKernelCensus>(), capacities)?,
        size_of::<KernelEvidence>(),
    )
}
pub(in super::super) fn runtime_kernel_census_charge(
    operation: RuntimeKernelOperation,
) -> Result<BudgetCharge, CensusError> {
    Ok(BudgetCharge {
        origins: usize::from(operation.returns()),
        witnesses: witnesses(operation),
        source_fact_bytes: add(
            preparation_bytes(mul(states(operation), MAX_XSTATE_BYTES)?)?,
            fixed_commit_bytes(operation)?,
        )?,
        ..BudgetCharge::default()
    })
}
impl PreparedRuntimeKernelCensus {
    pub(in super::super) fn allocated_bytes(&self) -> Result<usize, CensusError> {
        let payload = self
            .buffers
            .iter()
            .try_fold(self.before.xstate.capacity(), |sum, value| {
                add(sum, value.capacity())
            })?;
        let evidence = self
            .evidence
            .as_ref()
            .map_or(0, |value| value.len() * size_of::<KernelEvidence>());
        add(add(size_of::<Self>(), payload)?, evidence)
    }
    pub(in super::super) fn remaining_charge(&self) -> Result<BudgetCharge, CensusError> {
        if self.receipt.is_some() || self.evidence.is_none() {
            return Err(CensusError::InvalidConsumption);
        }
        let operation = self.binding.identity.operation();
        Ok(BudgetCharge {
            origins: usize::from(operation.returns()),
            witnesses: witnesses(operation),
            source_fact_bytes: fixed_commit_bytes(operation)?,
            ..BudgetCharge::default()
        })
    }
}

fn allocation_error(error: AllocationError) -> CensusError {
    match error {
        AllocationError::Capacity => CensusError::Capacity,
        AllocationError::Allocation => CensusError::Allocation,
    }
}
fn buffer() -> Result<Vec<u8>, CensusError> {
    exact_storage::empty_bytes(MAX_XSTATE_BYTES).map_err(allocation_error)
}
fn evidence_box(value: KernelEvidence) -> Result<Box<[KernelEvidence]>, CensusError> {
    exact_storage::one(value).map_err(allocation_error)
}
fn copy_observed(value: &ObservedStop, mut bytes: Vec<u8>) -> ObservedStop {
    bytes.extend_from_slice(&value.xstate);
    ObservedStop {
        token: value.token.clone(),
        task: value.task,
        logical_pc: value.logical_pc,
        registers: value.registers,
        xstate: bytes,
        signal_mask: value.signal_mask,
        phase: value.phase,
        signal: value.signal.clone(),
    }
}
fn copy_state(
    token: &DynamicStop,
    task: DynamicTask,
    state: &TaskStateSnapshot,
    mut bytes: Vec<u8>,
    phase: StopPhase,
) -> ObservedStop {
    bytes.extend_from_slice(&state.xstate);
    ObservedStop {
        token: token.clone(),
        task,
        logical_pc: state.registers.rip,
        registers: state.registers,
        xstate: bytes,
        signal_mask: state.mask,
        phase,
        signal: None,
    }
}
fn copy_checkpoint(value: NativeCheckpoint<'_>, bytes: Vec<u8>) -> ObservedStop {
    copy_state(
        &value.stop.token,
        value.stop.identity,
        value.state,
        bytes,
        StopPhase::UserCheckpoint,
    )
}
fn next_buffer(prepared: &mut PreparedRuntimeKernelCensus, index: &mut usize) -> Vec<u8> {
    let value = std::mem::take(&mut prepared.buffers[*index]);
    *index += 1;
    value
}

struct Model<'a> {
    identity: &'a RuntimeKernelIdentity,
    logical: NativeCheckpoint<'a>,
    opening: [NativeCheckpoint<'a>; 3],
    entry: NativeSyscallCheckpoint<'a>,
    outcome: Outcome<'a>,
}
struct Outcome<'a> {
    returned: Option<ReturnModel<'a>>,
    terminal: Option<TerminalModel<'a>>,
}
struct ReturnModel<'a> {
    exit: NativeSyscallCheckpoint<'a>,
    bridge: NativeCheckpoint<'a>,
    closing: [NativeCheckpoint<'a>; 3],
    trace: NativeKernelReturnTrace,
}
struct TerminalModel<'a> {
    pre_exit: NativePreExitCheckpoint<'a>,
    exiting: &'a DynamicEvent,
    terminal: &'a DynamicEvent,
    trace: NativeKernelTerminalTrace,
}

impl ResumeCensus {
    pub(in super::super) fn prepare_runtime_kernel(
        &mut self,
        reservation: Reservation,
        actual: &RuntimeKernelBinding<'_>,
    ) -> Result<Box<PreparedRuntimeKernelCensus>, CensusError> {
        let before = self.current_observation(actual.origin())?;
        if before != actual.before()
            || actual.stop().token != before.token
            || actual.stop().identity != before.task
            || actual.stop().signal.is_some()
            || !matches!(
                actual.stop().phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
        {
            return Err(CensusError::StaleObservation);
        }
        input_matches(before, actual.input(), actual.execution())?;
        if actual.input().arguments()
            != (crate::selected::SelectedArguments::Syscall {
                abi: crate::selected::SyscallAbi::LinuxX64,
                number: actual.identity().number(),
                arguments: actual.identity().arguments(),
            })
            || actual.input().instruction().bytes() != actual.identity().encoding()
            || actual.input().instruction().next_pc() != actual.identity().next_pc()
        {
            return Err(CensusError::InvalidConsumption);
        }
        self.prepare_kernel_model(reservation, actual.identity())
    }

    fn prepare_kernel_model(
        &mut self,
        reservation: Reservation,
        identity: &RuntimeKernelIdentity,
    ) -> Result<Box<PreparedRuntimeKernelCensus>, CensusError> {
        self.check_reserved(
            reservation,
            runtime_kernel_census_charge(identity.operation())?,
        )?;
        let before = self.current_observation(identity.origin())?;
        validate::binding(self, identity, before)?;
        validate::capacity(self, identity.operation())?;
        if identity.operation().returns() {
            self.state
                .next_serial
                .checked_add(1)
                .ok_or(CensusError::Capacity)?;
        }
        let before = copy_observed(before, buffer()?);
        let mut buffers = std::array::from_fn(|_| Vec::new());
        for bytes in &mut buffers[..states(identity.operation()) - 1] {
            *bytes = buffer()?;
        }
        let evidence = evidence_box(KernelEvidence {
            identity: identity.clone(),
            entry: None,
            outcome: None,
        })?;
        let mut result = Box::new(PreparedRuntimeKernelCensus {
            binding: Binding {
                census: self.identity,
                reservation,
                candidate_serial: self.state.next_serial,
                identity: identity.clone(),
            },
            before,
            buffers,
            evidence: Some(evidence),
            preparation_debit: 0,
            receipt: None,
        });
        let bytes = result.allocated_bytes()?;
        if add(bytes, fixed_commit_bytes(identity.operation())?)?
            > runtime_kernel_census_charge(identity.operation())?.source_fact_bytes
        {
            return Err(CensusError::Capacity);
        }
        self.account_external(
            reservation,
            BudgetCharge {
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )?;
        result.preparation_debit = bytes;
        Ok(result)
    }
}
