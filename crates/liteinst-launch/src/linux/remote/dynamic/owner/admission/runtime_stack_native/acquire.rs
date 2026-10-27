//! Actual held acquisition, distinct from the descriptive stack validators.
//! No constructor here grants original execution or creates a completion seal.
use super::super::super::Owner;
use super::super::super::bootstrap::{self, BootstrapMm, StateSlot};
use super::super::super::lifecycle::NativeLifecycle;
use super::super::super::trusted::{AdmissionPhase, AdmissionStop, TaskStateSnapshot};
use super::super::census::{ExecutionId, OriginId};
use super::super::runtime::stack::StackBeforeContext;
use super::super::runtime_capture::{PreparedInitialSources, SourceWindowId};
use super::super::runtime_stack::access::{PkuLayoutEvidence, validate_state};
use super::super::runtime_stack::metadata::validate_smaps;
use super::super::runtime_stack::operand::{
    OperandDescription, OperandGeometry, OperandInput, PreparedStackOperand, WordObservation,
};
use super::super::runtime_stack::profile::{
    PreparedStackProfile, ProfileDescription, ProfileInput,
};
use super::super::runtime_stack::storage::StackObservationStorage;
use super::super::runtime_stack::{BYTES, StackError};
use super::super::source_identity::require_initial_task_identity;
use super::io::{self, PagemapAccess};
use super::{NativeStackBeforeView, NativeStackHeldView};
use crate::LaunchError;
use crate::gate::GateError;
use std::mem::size_of;
use std::time::Instant;

mod operand;
mod profile;
mod word;
#[cfg(test)]
pub(in super::super) use super::io::PagemapAccess as ModelPagemapAccess;
#[cfg(test)]
pub(in super::super) use super::io::{RawIoFault, RawIoRecord, RawStoppedIo};
pub(super) use word::{FailedHeldStackRead, SettledStackRead, TraceStackRead};
#[cfg(feature = "dev-owned-stack-consumer-oracle")]
pub(in crate::linux::remote::dynamic::owner::admission) mod consumer_oracle;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum StackCaptureStage {
    Empty,
    Allocated,
    Authority,
    Layout,
    Smaps,
    Pagemap,
    Word,
    State,
    Maps,
    Recheck,
    Validate,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum StackCaptureFailure {
    Invalid(&'static str),
    System(&'static str, Option<i32>),
    Timeout(&'static str),
    Child(i32),
    Validation(StackError),
    Unwound,
}
#[derive(Clone, Copy, Debug)]
pub(in super::super) struct StackCaptureProgress {
    pub(in super::super) stage: StackCaptureStage,
    pub(in super::super) started: bool,
    pub(in super::super) complete: bool,
    pub(in super::super) first_failure: Option<(StackCaptureStage, StackCaptureFailure)>,
}
impl StackCaptureProgress {
    fn empty() -> Self {
        Self {
            stage: StackCaptureStage::Empty,
            started: false,
            complete: false,
            first_failure: None,
        }
    }
    fn fail(&mut self, error: &LaunchError) {
        let failure = match error {
            LaunchError::Invalid(reason) => StackCaptureFailure::Invalid(reason),
            LaunchError::System { operation, source } => {
                StackCaptureFailure::System(operation, source.raw_os_error())
            }
            LaunchError::Timeout(operation) => StackCaptureFailure::Timeout(operation),
            LaunchError::Child { status } => StackCaptureFailure::Child(*status),
        };
        self.first_failure.get_or_insert((self.stage, failure));
    }
    fn validate<T>(&mut self, result: Result<T, StackError>) -> Result<T, LaunchError> {
        result.map_err(|error| {
            self.first_failure
                .get_or_insert((self.stage, StackCaptureFailure::Validation(error)));
            invalid("owned stack captured evidence is outside the qualified profile")
        })
    }
    fn begin(&mut self) -> Result<(), LaunchError> {
        if self.stage != StackCaptureStage::Allocated
            || self.started
            || self.first_failure.is_some()
        {
            return Err(invalid(
                "owned stack native capture is unallocated or reused",
            ));
        }
        self.started = true;
        self.stage = StackCaptureStage::Authority;
        Ok(())
    }
    fn aborted(&mut self) {
        self.first_failure
            .get_or_insert((self.stage, StackCaptureFailure::Unwound));
    }
}

/// Diagnostic phase association. Only private acquisition stamps establish
/// that a value was actually read; constructing this enum grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in super::super) enum StackCaptureAssociation {
    A {
        stop: AdmissionStop,
        source_id: SourceWindowId,
        until: Instant,
    },
    B {
        stop: AdmissionStop,
        until: Instant,
    },
    C {
        original: AdmissionStop,
        raw_wait: (i32, i32),
        ordinal: usize,
        until: Instant,
    },
    D {
        stop: AdmissionStop,
        until: Instant,
    },
    FailedHeld {
        original: AdmissionStop,
        raw_wait: (i32, i32),
        ordinal: usize,
        until: Instant,
    },
}
#[derive(Clone, Copy)]
pub(in super::super) struct StackWordView<'a> {
    pub(in super::super) observation: &'a StackObservationStorage,
    pub(in super::super) word: &'a WordObservation,
    pub(in super::super) pagemap_access: &'a PagemapAccess,
    pub(in super::super) association: Option<&'a StackCaptureAssociation>,
    pub(in super::super) complete: bool,
    pub(in super::super) first_failure: Option<(StackCaptureStage, StackCaptureFailure)>,
}

struct ProfileCaptureStamp {
    stop: AdmissionStop,
    original_pointer: usize,
    original_length: usize,
    until: Instant,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BufferIdentity {
    pointer: usize,
    length: usize,
    capacity: usize,
}
impl BufferIdentity {
    fn of(bytes: &Vec<u8>) -> Self {
        Self {
            pointer: bytes.as_ptr() as usize,
            length: bytes.len(),
            capacity: bytes.capacity(),
        }
    }
}
/// Stable allocated payload identities survive moving/reinstalling the inline
/// RuntimeOwner header. These addresses are compared only, never dereferenced.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProfileIdentityKey {
    payloads: [BufferIdentity; 3],
    original: (usize, usize),
    stop: AdmissionStop,
    until: Instant,
    stack: super::super::runtime_stack::metadata::StackDescriptor,
    metadata: super::super::runtime_stack::metadata::StackMetadata,
    layout: super::super::runtime_stack::access::PkuLayout,
    raw_layout: PkuLayoutEvidence,
    initial_rsp: u64,
    island: std::ops::Range<u64>,
}
struct OperandCaptureStamp {
    origin: OriginId,
    execution: ExecutionId,
    profile: ProfileIdentityKey,
}

pub(in super::super) struct PreparedStackProfileCapture {
    diagnostic: PreparedStackProfile,
    progress: StackCaptureProgress,
    eof: [u8; 2],
    association: Option<ProfileCaptureStamp>,
    provenance: bool,
}
/// Borrowed actual startup capture. No constructor from a description exists.
pub(in super::super) struct OriginalStackIdentity<'a> {
    captured: &'a PreparedStackProfileCapture,
}
pub(in super::super) struct PreparedStackOperandCapture {
    diagnostic: PreparedStackOperand,
    progress: StackCaptureProgress,
    pagemap_access: PagemapAccess,
    eof: [u8; 2],
    association: Option<StackCaptureAssociation>,
    provenance: Option<OperandCaptureStamp>,
}
/// Borrowed actual A capture. Neither a data description nor a supplied state
/// can construct it. Its proof is independent of future original execution.
pub(in super::super) struct OwnedStackOperand<'a> {
    captured: &'a PreparedStackOperandCapture,
}

pub(in super::super) struct NativeStackWordCapture {
    observation: StackObservationStorage,
    word: WordObservation,
    pagemap_access: PagemapAccess,
    progress: StackCaptureProgress,
    eof: [u8; 2],
    association: Option<StackCaptureAssociation>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SettledWordPhase {
    B,
    D,
}
/// Immutable expectations are descriptions. Native phase authority is checked
/// independently and is never derived from these public-to-parent fields.
pub(super) struct StackWordExpected<'a> {
    pub(super) profile: &'a ProfileDescription,
    pub(super) original_maps: &'a [u8],
    pub(super) geometry: &'a OperandGeometry,
    pub(super) state: &'a StateSlot,
    pub(super) maps: &'a [u8],
    pub(super) word: &'a [u8; 16],
}

fn invalid(reason: &'static str) -> LaunchError {
    LaunchError::Invalid(reason)
}
fn gate_error(error: GateError) -> LaunchError {
    match error {
        GateError::Control(error) => error,
        GateError::Refused(reason) => invalid(reason),
        _ => invalid("owned stack source prerequisite failed"),
    }
}
fn add(left: usize, right: usize) -> Result<usize, LaunchError> {
    left.checked_add(right)
        .ok_or_else(|| invalid("owned stack acquisition storage overflows"))
}
fn retain(
    progress: &mut StackCaptureProgress,
    first: &mut Option<LaunchError>,
    result: Result<(), LaunchError>,
) {
    if let Err(error) = result {
        progress.fail(&error);
        if first.is_none() {
            *first = Some(error);
        }
    }
}
fn current(
    owner: &Owner,
    native: &NativeLifecycle,
    stop: &AdmissionStop,
    membership: &mut [u8],
    until: Instant,
) -> Result<(), LaunchError> {
    native.require_initial_source_mm(owner, stop, until, membership)?;
    if native.admission_interrupt_credit(owner.pid)? != 0 {
        return Err(invalid(
            "owned stack current stop has interrupt uncertainty",
        ));
    }
    bootstrap::physical(owner, until)
}
fn held(
    owner: &Owner,
    native: &NativeLifecycle,
    view: &NativeStackHeldView<'_>,
    membership: &mut [u8],
    trace: bool,
) -> Result<(), LaunchError> {
    let (tid, status) = view.raw_wait();
    let original = view.original();
    bootstrap::physical(owner, view.until())?;
    if tid != owner.pid
        || original.token.tid != tid
        || original.token.session != owner.session
        || original.token.task != Some(original.identity.task)
        || original.identity.generation != 0
        || original.signal.is_some()
        || original.phase != AdmissionPhase::Restored
        || !libc::WIFSTOPPED(status)
        || owner.stopped.get(&tid) != Some(&status)
        || native.admission_interrupt_credit(tid)? != 0
        || (trace && (libc::WSTOPSIG(status) != libc::SIGTRAP || status >> 16 != 0))
    {
        return Err(invalid(
            "owned stack raw wait lacks the actual original held lineage",
        ));
    }
    // This does not pretend the running registry has a new AdmissionStop.
    // The private producer view binds the issued release and consumed ordinal3.
    require_initial_task_identity(owner, view.until(), membership)?;
    bootstrap::physical(owner, view.until())?;
    if owner.stopped.get(&tid) != Some(&status) {
        return Err(invalid(
            "owned stack raw wait changed during membership capture",
        ));
    }
    Ok(())
}

pub(in super::super) fn temporary_bytes() -> Result<usize, LaunchError> {
    // Count concrete fixed acquisition/control views conservatively in addition
    // to the I/O boundary's own locals. Parsers borrow the already charged
    // buffers; their concrete iterator/value types are included below.
    let mut bytes = add(io::temporary_bytes()?, word::temporary_bytes()?)?;
    for size in [
        size_of::<OriginalStackIdentity<'_>>(),
        size_of::<OwnedStackOperand<'_>>(),
        size_of::<NativeStackBeforeView<'_>>(),
        size_of::<NativeStackHeldView<'_>>(),
        size_of::<StackBeforeContext<'_, '_>>(),
        size_of::<StackWordExpected<'_>>(),
        size_of::<ProfileIdentityKey>(),
        3 * size_of::<BufferIdentity>(),
        size_of::<ProfileInput<'_>>(),
        size_of::<OperandInput<'_>>(),
        3 * size_of::<OperandGeometry>(),
        2 * size_of::<StackCaptureAssociation>(),
        8 * size_of::<Option<LaunchError>>(),
        size_of::<libc::iovec>(),
        size_of::<libc::user_regs_struct>(),
        3 * size_of::<crate::RegisterSnapshot>(),
        2 * size_of::<super::super::mapping::maps::ParsedMaps<'_>>(),
        2 * size_of::<super::super::mapping::maps::MapEntries<'_>>(),
        3 * size_of::<super::super::mapping::maps::MapEntry<'_>>(),
        2 * size_of::<ProfileDescription>(),
        2 * size_of::<OperandDescription>(),
        2 * size_of::<iced_x86::Decoder<'_>>(),
        2 * size_of::<iced_x86::Instruction>(),
        2 * size_of::<std::slice::Split<'_, u8, fn(&u8) -> bool>>(),
        16 * size_of::<&[u8]>(),
        10 * size_of::<std::ops::Range<u64>>(),
        2 * size_of::<PkuLayoutEvidence>(),
        5 * 4 * size_of::<u32>(),
    ] {
        bytes = add(bytes, size)?;
    }
    Ok(bytes)
}
