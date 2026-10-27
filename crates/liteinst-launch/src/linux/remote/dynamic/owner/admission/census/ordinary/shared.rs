//! Three census-owned ordinary-history payloads. This storage grants no native
//! authority. The unchanged ordinary validator must run before publication.
use super::*;
use crate::linux::remote::dynamic::owner::admission::exact_storage;
use std::mem::size_of_val;
mod capture;
#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
mod clone;
#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
pub(in crate::linux::remote::dynamic::owner::admission::census) mod snapshot;
mod storage;
#[cfg(test)]
mod tests;
mod view;
pub(in crate::linux::remote::dynamic::owner::admission::census) use view::{
    ArchivePartialView, BindingView, PartialView, PayloadView, ResolutionContext,
    SharedHistoryRecord, SharedObservationRef, SharedRowView,
};

#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
pub(in crate::linux::remote::dynamic::owner::admission::census) use snapshot::ArchiveSnapshot;
#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission) use snapshot::PreparedSnapshot;
pub(in crate::linux::remote::dynamic::owner::admission) use view::ObservationView;

const PAYLOADS: usize = 3;
const ENDPOINTS: usize = 14;
const COPY_CHUNK: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum SharedError {
    Capacity,
    Allocation,
    Reused,
    Incomplete,
    Identity,
    Extent,
    Provenance,
    Endpoint,
    Aborted,
}
impl From<SharedError> for CensusError {
    fn from(value: SharedError) -> Self {
        match value {
            SharedError::Capacity => Self::Capacity,
            SharedError::Allocation => Self::Allocation,
            SharedError::Identity => Self::IdentityMismatch,
            SharedError::Extent => Self::InvalidObservation,
            SharedError::Reused
            | SharedError::Incomplete
            | SharedError::Provenance
            | SharedError::Endpoint
            | SharedError::Aborted => Self::InvalidConsumption,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) enum CaptureRole {
    Prior,
    Before,
    Step,
}
impl CaptureRole {
    fn index(self) -> usize {
        match self {
            Self::Prior => 0,
            Self::Before => 1,
            Self::Step => 2,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct Progress {
    pub(in crate::linux::remote::dynamic::owner::admission) started: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) complete: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) filled: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) first_failure: Option<SharedError>,
}
impl Progress {
    fn begin(&mut self) -> Result<(), SharedError> {
        if self.started || self.complete || self.first_failure.is_some() {
            return Err(SharedError::Reused);
        }
        self.started = true;
        Ok(())
    }
    fn fail(&mut self, error: SharedError) {
        if !self.complete {
            self.first_failure.get_or_insert(error);
        }
    }
    fn require_complete(self) -> Result<(), SharedError> {
        if self.started && self.complete && self.first_failure.is_none() {
            Ok(())
        } else {
            Err(SharedError::Incomplete)
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct PayloadIdentity {
    pub(in crate::linux::remote::dynamic::owner::admission::census) pointer: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::census) length: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::census) capacity: usize,
}
impl PayloadIdentity {
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    fn of(bytes: &Vec<u8>) -> Self {
        Self {
            pointer: bytes.as_ptr() as usize,
            length: bytes.len(),
            capacity: bytes.capacity(),
        }
    }
}
// Fixed headers may be copied; no payload Vec is hidden in an observation header.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservationHeader {
    token: DynamicStop,
    task: DynamicTask,
    logical_pc: u64,
    registers: RegisterSnapshot,
    signal_mask: u64,
    phase: StopPhase,
    signal: Option<DynamicSignalInfo>,
}
#[derive(Debug, Eq, PartialEq)]
struct Payload {
    bytes: Vec<u8>,
    copy: Progress,
}
impl Payload {
    fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            copy: Progress::default(),
        }
    }
}
/// Non-Clone without the explicit test/dev diagnostic feature, and privately
/// mutable only while installed in preparation. The
/// successor origin eventually owns this same Box; views never copy payloads.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct OrdinaryHistoryPayloads {
    binding: Binding,
    owner: OriginId,
    trace: Option<NativeTrace>,
    payloads: [Payload; PAYLOADS],
    headers: [Option<ObservationHeader>; ENDPOINTS],
    prior: Progress,
    native: Progress,
}
impl OrdinaryHistoryPayloads {
    fn empty(binding: Binding, owner: OriginId) -> Self {
        Self {
            binding,
            owner,
            trace: None,
            payloads: std::array::from_fn(|_| Payload::empty()),
            headers: std::array::from_fn(|_| None),
            prior: Progress::default(),
            native: Progress::default(),
        }
    }
}
/// Installed allocation-free header. Successful payload ownership is recorded
/// before another fallible operation. Moved bytes are not a budget refund.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedOrdinaryHistory {
    archive: Option<Box<OrdinaryHistoryPayloads>>,
    allocation: Progress,
    installed_bytes: usize,
    transferred: bool,
}
type CopyPoint = (Option<CaptureRole>, usize);
fn checked(a: usize, b: usize) -> Result<usize, SharedError> {
    a.checked_add(b).ok_or(SharedError::Capacity)
}
fn allocation_error(error: exact_storage::AllocationError) -> SharedError {
    match error {
        exact_storage::AllocationError::Capacity => SharedError::Capacity,
        exact_storage::AllocationError::Allocation => SharedError::Allocation,
    }
}
fn require(condition: bool, error: SharedError) -> Result<(), SharedError> {
    if condition { Ok(()) } else { Err(error) }
}

/// Checked additive source-contract temporary bound, not measured stack usage.
/// Count constructor overlap, all fixed borrowed projections, seal/model
/// wrappers, seven row staging, one cloned fixed header, and calculator locals.
pub(in crate::linux::remote::dynamic::owner::admission) fn shared_temporary_bytes()
-> Result<usize, SharedError> {
    let terms = [
        size_of::<OrdinaryHistoryPayloads>(), // empty-constructor result
        size_of::<OrdinaryHistoryPayloads>(), // exact_storage::value argument
        size_of::<[Option<ObservationHeader>; ENDPOINTS]>(), // array construction
        size_of::<[Payload; PAYLOADS]>(),     // empty slot construction
        size_of::<PreparedOrdinaryHistory>(),
        size_of::<Binding>(),
        size_of::<BindingView>(),
        size_of::<CompletionModel<'_>>(),
        size_of::<OwnedInstructionCompletion<'_>>(),
        size_of::<[NativeCheckpoint<'_>; 8]>(),
        size_of::<[SharedHistoryRecord; 7]>(),
        size_of::<[SharedObservationRef; ENDPOINTS]>(),
        size_of::<PartialView<'_>>(),
        size_of::<ArchivePartialView<'_>>(),
        size_of::<[PayloadView<'_>; PAYLOADS]>(),
        size_of::<[Option<ObservationView<'_>>; ENDPOINTS]>(),
        size_of::<ObservationHeader>(),
        size_of::<ObservationView<'_>>(),
        size_of::<ResolutionContext<'_>>(),
        size_of::<SharedRowView<'_>>(),
        size_of::<[Progress; PAYLOADS + 3]>(),
        size_of::<std::slice::Chunks<'_, u8>>(),
        size_of::<std::slice::Iter<'_, Payload>>(),
        size_of::<std::slice::Iter<'_, NativeCheckpoint<'_>>>(),
        size_of::<std::slice::Iter<'_, Option<ObservationHeader>>>(),
        size_of::<std::ops::Range<usize>>(),
        size_of::<CopyPoint>(),
        size_of::<Option<DynamicSignalInfo>>(),
        size_of::<std::alloc::Layout>(),
        size_of::<Result<Box<OrdinaryHistoryPayloads>, exact_storage::AllocationError>>(),
        size_of::<Result<Vec<u8>, exact_storage::AllocationError>>(),
        size_of::<[Result<(), SharedError>; 8]>(),
        size_of::<[usize; 16]>(),
        size_of::<[&[u8]; 8]>(),
        size_of::<[bool; 8]>(),
    ];
    // Includes the array/consuming iterator and checked calculator control
    // operands/results themselves. All previous terms remain additive.
    let mut total = checked(
        size_of_val(&terms),
        size_of::<std::array::IntoIter<usize, 35>>(),
    )?;
    total = checked(
        total,
        size_of::<([usize; 4], Option<usize>, Result<usize, SharedError>)>(),
    )?;
    for term in terms {
        total = checked(total, term)?;
    }
    Ok(total)
}

/// Additional inner resolver locals beyond the parent history adapter's views
/// and contexts. This is a checked source envelope, not measured stack usage.
/// It does not charge archive payloads or execute their validation here.
pub(in crate::linux::remote::dynamic::owner::admission::census) fn resolution_temporary_bytes()
-> Result<usize, SharedError> {
    let terms = [
        size_of::<[SharedHistoryRecord; 2]>(),
        size_of::<[SharedObservationRef; 4]>(),
        size_of::<[Progress; 3]>(),
        size_of::<[CaptureRole; 2]>(),
        size_of::<[Option<&ObservationHeader>; 2]>(),
        size_of::<[&Payload; 2]>(),
        size_of::<std::slice::Iter<'_, Payload>>(),
        size_of::<std::slice::Iter<'_, Option<ObservationHeader>>>(),
        size_of::<[std::ops::Range<usize>; 2]>(),
        size_of::<Result<ObservationView<'_>, SharedError>>(),
        size_of::<Result<CaptureRole, SharedError>>(),
        size_of::<[Result<(), SharedError>; 6]>(),
        size_of::<[OriginId; 3]>(),
        size_of::<[usize; 8]>(),
        size_of::<[bool; 8]>(),
        size_of::<[&[u8]; 4]>(),
    ];
    let mut total = checked(
        size_of_val(&terms),
        size_of::<std::array::IntoIter<usize, 16>>(),
    )?;
    total = checked(
        total,
        size_of::<([usize; 4], Option<usize>, Result<usize, SharedError>)>(),
    )?;
    for term in terms {
        total = checked(total, term)?;
    }
    Ok(total)
}
