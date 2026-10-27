//! Explicit original-stack custody. The native producer supplies all permits;
//! fixed descriptions, byte budgets and CALL records supply none.
use super::super::census::stack_calls::{PreparedCallRecord, RuntimeCallLedger};
use super::super::census::{
    ExecutionId, PreparedStackCensus, Reservation, stack_census_charge,
    stack_census_temporary_bytes,
};
use super::super::exact_storage;
use super::super::runtime_capture::{CapturedRuntimeRead, RuntimeCatalogCheckpoint};
use super::super::runtime_instruction::{CandidateKind, DebugDisposition, classify};
use super::super::runtime_native::{
    ControlLineage, ControlProfile, InstructionEffect, InstructionObservation,
};
use super::super::runtime_stack_native::acquire::{
    PreparedStackOperandCapture, PreparedStackProfileCapture,
};
use super::super::runtime_stack_native::{self, PreparedStackNative};
use super::super::source_identity::SourceReadProgress;
use super::*;
use crate::selected::SyscallAliases;
use iced_x86::Code;

mod binding;
pub(in crate::linux::remote::dynamic::owner::admission) use binding::{
    RuntimeStackBinding, RuntimeStackIdentity, StackBeforeContext,
};
mod observer;
use binding::StackRequest;
mod storage;
use observer::SourceObserver;
mod execute;
#[cfg(test)]
mod native_tests;
#[cfg(test)]
mod test_config;
#[cfg(test)]
mod tests;
#[cfg(test)]
use runtime_stack_native::{InterventionKind, InterventionPoint};
#[cfg(test)]
use test_config::{StackAllocationFault, StackAllocationTarget};

const MAP_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptStage {
    Allocated,
    Source,
    Operand,
    Census,
    Native,
    Commit,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Refused(&'static str),
    Invalid(&'static str),
    System(&'static str, Option<i32>),
    Timeout(&'static str),
    Child(i32),
    Other,
    Unwound,
}
impl Failure {
    fn from_gate(error: &GateError) -> Self {
        match error {
            GateError::Refused(reason) => Self::Refused(reason),
            GateError::Control(LaunchError::Invalid(reason)) => Self::Invalid(reason),
            GateError::Control(LaunchError::System { operation, source }) => {
                Self::System(operation, source.raw_os_error())
            }
            GateError::Control(LaunchError::Timeout(operation)) => Self::Timeout(operation),
            GateError::Control(LaunchError::Child { status }) => Self::Child(*status),
            _ => Self::Other,
        }
    }
}

/// Installed inline before startup payload allocation. Both owning index
/// arrays are exact and permanent; no successful or failed attempt is removed.
pub(super) struct RuntimeStackState {
    profile: PreparedStackProfileCapture,
    attempts: Box<[Option<Box<RuntimeStackAttempt>>]>,
    calls: RuntimeCallLedger,
    capacity: usize,
    count: usize,
    startup_started: bool,
    startup_complete: bool,
    startup_ordinal: Option<usize>,
    #[cfg(test)]
    startup_fault: AllocationFault,
    startup_reserved: usize,
    startup_actual: usize,
    startup_settled: usize,
    #[cfg(test)]
    intervention: Option<RootIntervention>,
    #[cfg(test)]
    before_opening: Option<BeforeOpening>,
    #[cfg(test)]
    fail_attempt_header: bool,
    #[cfg(test)]
    panic_after_attempt_header: bool,
    #[cfg(test)]
    allocation_config: Option<StackAllocationFault>,
    #[cfg(test)]
    allocation_config_used: bool,
    #[cfg(test)]
    native_intervention: Option<(InterventionPoint, InterventionKind)>,
    pending: Option<PendingPreparation>,
    failure: Option<Failure>,
    settlement_failure: Option<Failure>,
}

/// Retained even when allocation of the empty attempt header fails.
struct PendingPreparation {
    reservation: Reservation,
    origin: OriginId,
    serial: u64,
    until: Instant,
    stage: AttemptStage,
    failure: Option<Failure>,
}

pub(super) struct RuntimeStackAttempt {
    reservation: Reservation,
    origin: OriginId,
    serial: u64,
    until: Instant,
    stop: AdmissionStop,
    before: ObservedStop,
    source: SourceChecks,
    native: PreparedStackNative,
    operand: PreparedStackOperandCapture,
    census: Option<Box<PreparedStackCensus>>,
    call: Option<Box<PreparedCallRecord>>,
    geometry: maps::FetchGeometry,
    window_bytes: usize,
    is_call: bool,
    allocated: bool,
    allocation_started: bool,
    allocation_ordinal: Option<usize>,
    #[cfg(test)]
    allocation_fault: AllocationFault,
    #[cfg(test)]
    nested_fault: Option<StackAllocationFault>,
    settled: usize,
    stage: AttemptStage,
    failure: Option<Failure>,
    settlement_failure: Option<Failure>,
}

struct SourceChecks {
    bytes: [Vec<u8>; 3],
    progress: [SourceReadProgress; 3],
    identity: Vec<u8>,
    checkpoint: ObservedStop,
    checkpoint_stop: AdmissionStop,
}

fn allocation_error(_: exact_storage::AllocationError) -> GateError {
    GateError::Refused("runtime stack exact allocation failed")
}
fn native_error(error: GateError) -> LaunchError {
    match error {
        GateError::Control(error) => error,
        GateError::Refused(reason) => LaunchError::Invalid(reason),
        _ => LaunchError::Invalid("runtime stack source verification failed"),
    }
}
fn payload(total: usize, header: usize) -> Result<usize, GateError> {
    total.checked_sub(header).ok_or(GateError::Refused(
        "runtime stack header accounting differs",
    ))
}
pub(super) fn stack_candidate(
    candidate: &super::super::runtime_instruction::InstructionCandidate<'_>,
) -> bool {
    let CandidateKind::Ordinary(instruction) = candidate.kind() else {
        return false;
    };
    matches!(
        (candidate.bytes(), instruction.decoded().code()),
        ([0xe8, _, _, _, _], Code::Call_rel32_64) | ([0xc3], Code::Retnq)
    )
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct AllocationFault {
    before: Option<usize>,
    after: Option<usize>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootIntervention {
    AfterCallRecordPanic,
    RefuseClosedObserver,
}
#[cfg(test)]
type BeforeOpening = fn(
    &Owner,
    &NativeLifecycle,
    &super::super::census::stack_calls::RecordedCall<'_>,
    &RuntimeStackBinding<'_, '_>,
    &PreparedStackNative,
    &ResumeCensus,
    &PreparedInitialSources,
) -> Result<(), GateError>;
