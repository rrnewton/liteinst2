//! One sealed no-memory original instruction. Failed held outcomes retain all
//! diagnostics; only the physical owner may kill/reap them, never retry them.
use super::super::bootstrap::{
    self, MapBuffer, MemoryObservation, Request, SignalObservation, StateSlot,
};
use super::runtime::instruction::RuntimeInstructionBinding;
use super::runtime::maps::{FetchGeometry, verify_closed};
use super::runtime_capture::SourceWindowId;
use super::runtime_instruction::{CandidateKind, OrdinaryFamily};
use super::*;
use crate::linux::remote::{MAX_XSTATE, NT_X86_XSTATE, STUB, SYNC_CORE};
use std::mem::size_of;

mod profile;
mod runner;
mod storage;
#[cfg(test)]
pub(super) use profile::ControlLineageSnapshot;
#[cfg(test)]
pub(super) use storage::NativeAllocationView;
pub(super) use storage::NativeInstructionStorage;
#[cfg(test)]
pub(super) use storage::NativeStorageSnapshot;
#[cfg(test)]
mod tests;
pub(super) use profile::{ControlLineage, ControlProfile};
pub(super) use profile::{DR_TRACE, DebugRead};

const MAP_BYTES: usize = 64 * 1024;
const WAITS: usize = 7;
const STATES: usize = 9; // before, seven independent raw waits, restoration scratch
const BEFORE: usize = 0;
const STEP: usize = 4;
const WORK: usize = 8;
const BASELINE_MAP: usize = 0;
const OPEN_MAP: usize = 1;
const STEP_MAP: usize = 2;
const CLOSED_MAP: usize = 3;
const WORK_MAP: usize = 4;
const EFFECTS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InstructionEffect {
    SetRegisters { wait: usize },
    RestoreXstate { wait: usize },
    RestoreRegisters { wait: usize },
    RestoreMask { wait: usize },
    PrivateRelease { wait: usize },
    OriginalRelease,
}
pub(super) trait InstructionObservation {
    fn before_effect(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        effect: InstructionEffect,
        current: &AdmissionStop,
        until: Instant,
    ) -> Result<(), LaunchError>;
    fn opened(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        current: &AdmissionStop,
        state: &TaskStateSnapshot,
        maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError>;
    fn closed(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        current: &AdmissionStop,
        state: &TaskStateSnapshot,
        maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InstructionPhase {
    Allocated,
    Profile,
    Opening,
    Opened,
    Original,
    Closing,
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InstructionFailure {
    Invalid(&'static str),
    System(&'static str, Option<i32>),
    Timeout(&'static str),
    Child(i32),
    Unwound,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InstructionEffectRecord {
    pub(super) effect: InstructionEffect,
    pub(super) complete: bool,
    /// OriginalRelease completion is the existing native helper returning Ok;
    /// it exposes no raw request. All private ptrace effects retain actual rc.
    pub(super) result: Option<Request>,
}
pub(super) struct InstructionProgress {
    pub(super) phase: InstructionPhase,
    pub(super) first_failure: Option<(InstructionPhase, InstructionFailure)>,
    pub(super) waits: [Option<(i32, i32)>; WAITS],
    pub(super) queries_started: [bool; WAITS],
    pub(super) instruction_completed: bool,
    pub(super) nx_closed: bool,
    effects: [Option<InstructionEffectRecord>; EFFECTS],
    effects_len: usize,
}
impl InstructionProgress {
    #[cfg(test)]
    pub(super) fn effects(&self) -> &[Option<InstructionEffectRecord>] {
        &self.effects[..self.effects_len]
    }
    fn fail(&mut self, error: Option<&LaunchError>) {
        if self.first_failure.is_some() {
            return;
        }
        let failure = match error {
            Some(LaunchError::Invalid(reason)) => InstructionFailure::Invalid(reason),
            Some(LaunchError::System { operation, source }) => {
                InstructionFailure::System(operation, source.raw_os_error())
            }
            Some(LaunchError::Timeout(operation)) => InstructionFailure::Timeout(operation),
            Some(LaunchError::Child { status }) => InstructionFailure::Child(*status),
            None => InstructionFailure::Unwound,
        };
        self.first_failure = Some((self.phase, failure));
    }
}
#[derive(Clone, Copy)]
pub(super) struct InstructionAttemptShape {
    fetch_start: u64,
    fetch_end: u64,
}
impl InstructionAttemptShape {
    pub(super) fn from_geometry(geometry: &FetchGeometry) -> Result<Self, LaunchError> {
        let pages = geometry.pages();
        let length = pages
            .end()
            .checked_sub(pages.start())
            .ok_or(LaunchError::Invalid("owned fetch extent underflows"))?;
        if pages.start() % 4096 != 0 || !matches!(length, 4096 | 8192) {
            return Err(LaunchError::Invalid("owned fetch extent differs"));
        }
        Ok(Self {
            fetch_start: pages.start(),
            fetch_end: pages.end(),
        })
    }
    pub(super) fn reservation_bytes(self) -> Result<usize, LaunchError> {
        size_of::<PreparedInstructionAttempt>()
            .checked_add(STATES * MAX_XSTATE)
            .and_then(|bytes| bytes.checked_add(6 * MAP_BYTES))
            .and_then(|bytes| bytes.checked_add(size_of::<ControlProfile>()))
            .ok_or(LaunchError::Invalid("owned instruction storage overflows"))
    }
}
pub(super) struct PreparedInstructionAttempt {
    shape: InstructionAttemptShape,
    until: Instant,
    states: [StateSlot; STATES],
    maps: [MapBuffer; 5],
    membership: Box<[u8; MAP_BYTES]>,
    signals: [SignalObservation; WAITS],
    debug: [DebugRead; WAITS],
    profile: Box<ControlProfile>,
    peek: MemoryObservation,
    progress: InstructionProgress,
    initial: Option<AdmissionStop>,
    stops: [Option<AdmissionStop>; WAITS],
    source: Option<SourceWindowId>,
    origin: Option<OriginId>,
    execution: Option<ExecutionId>,
    encoding: [u8; 15],
    encoding_len: usize,
    trace: Option<NativeTrace>,
    claimed: bool,
}
impl PreparedInstructionAttempt {
    #[cfg(test)]
    pub(super) fn allocate(
        shape: InstructionAttemptShape,
        until: Instant,
    ) -> Result<Self, LaunchError> {
        let value = Self {
            shape,
            until,
            states: [
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
            ],
            maps: [
                MapBuffer::allocate()?,
                MapBuffer::allocate()?,
                MapBuffer::allocate()?,
                MapBuffer::allocate()?,
                MapBuffer::allocate()?,
            ],
            membership: fixed_buffer()?,
            signals: std::array::from_fn(|_| SignalObservation::default()),
            debug: [DebugRead::default(); WAITS],
            profile: storage::allocate_profile()?,
            peek: MemoryObservation::default(),
            progress: InstructionProgress {
                phase: InstructionPhase::Allocated,
                first_failure: None,
                waits: [None; WAITS],
                queries_started: [false; WAITS],
                instruction_completed: false,
                nx_closed: false,
                effects: [None; EFFECTS],
                effects_len: 0,
            },
            initial: None,
            stops: std::array::from_fn(|_| None),
            source: None,
            origin: None,
            execution: None,
            encoding: [0; 15],
            encoding_len: 0,
            trace: None,
            claimed: false,
        };
        if value.allocated_bytes()? > shape.reservation_bytes()? {
            return Err(LaunchError::Invalid(
                "owned instruction allocation exceeds reservation",
            ));
        }
        Ok(value)
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize, LaunchError> {
        self.states.iter().try_fold(
            size_of::<Self>() + 6 * MAP_BYTES + size_of::<ControlProfile>(),
            |bytes, state| {
                bytes
                    .checked_add(state.allocated_bytes() - size_of::<StateSlot>())
                    .ok_or(LaunchError::Invalid(
                        "owned instruction allocation overflows",
                    ))
            },
        )
    }
    #[cfg(test)]
    pub(super) fn progress(&self) -> &InstructionProgress {
        &self.progress
    }
    #[cfg(test)]
    pub(super) fn diagnostics(&self) -> InstructionDiagnostics<'_> {
        InstructionDiagnostics {
            states: &self.states,
            maps: &self.maps,
            signals: &self.signals,
            debug: &self.debug,
            profile: &self.profile,
            memory: &self.peek,
        }
    }
    #[cfg(test)]
    pub(super) fn completed(&self) -> Option<InstructionCompletionView<'_>> {
        (self.progress.nx_closed && self.progress.first_failure.is_none())
            .then_some(InstructionCompletionView { attempt: self })
    }
    pub(super) fn take_completed(&mut self) -> Result<OwnedInstructionCompletion<'_>, LaunchError> {
        if self.claimed || !(self.progress.nx_closed && self.progress.first_failure.is_none()) {
            return Err(LaunchError::Invalid(
                "owned instruction completion unavailable",
            ));
        }
        self.claimed = true;
        Ok(OwnedInstructionCompletion { attempt: self })
    }
}
#[cfg(test)]
pub(super) struct InstructionDiagnostics<'a> {
    pub(super) states: &'a [StateSlot; STATES],
    pub(super) maps: &'a [MapBuffer; 5],
    pub(super) signals: &'a [SignalObservation; WAITS],
    pub(super) debug: &'a [DebugRead; WAITS],
    pub(super) profile: &'a ControlProfile,
    pub(super) memory: &'a MemoryObservation,
}
#[cfg(test)]
pub(super) struct InstructionCompletionView<'a> {
    attempt: &'a PreparedInstructionAttempt,
}
#[cfg(test)]
impl InstructionCompletionView<'_> {
    pub(super) fn final_stop(&self) -> &AdmissionStop {
        self.attempt.stops[6]
            .as_ref()
            .expect("completed final stop")
    }
}
#[derive(Clone, Copy)]
pub(super) struct NativeCheckpoint<'a> {
    pub(super) stop: &'a AdmissionStop,
    pub(super) state: &'a TaskStateSnapshot,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NativeTrace {
    pub(super) ordinal: usize,
    pub(super) tid: i32,
    pub(super) status: i32,
    pub(super) signal: [u8; 128],
    pub(super) dr6: u64,
}
pub(super) struct OwnedInstructionCompletion<'a> {
    attempt: &'a PreparedInstructionAttempt,
}
impl<'a> OwnedInstructionCompletion<'a> {
    pub(super) fn source_id(&self) -> SourceWindowId {
        self.attempt.source.expect("completed source")
    }
    pub(super) fn origin(&self) -> OriginId {
        self.attempt.origin.expect("completed origin")
    }
    pub(super) fn execution(&self) -> ExecutionId {
        self.attempt.execution.expect("completed execution")
    }
    pub(super) fn until(&self) -> Instant {
        self.attempt.until
    }
    pub(super) fn encoding(&self) -> &'a [u8] {
        &self.attempt.encoding[..self.attempt.encoding_len]
    }
    pub(super) fn logical_before(&self) -> NativeCheckpoint<'a> {
        NativeCheckpoint {
            stop: self
                .attempt
                .initial
                .as_ref()
                .expect("completed initial stop"),
            state: &self.attempt.states[BEFORE].state,
        }
    }
    pub(super) fn opening(&self) -> [NativeCheckpoint<'a>; 3] {
        std::array::from_fn(|index| NativeCheckpoint {
            stop: self.attempt.stops[index]
                .as_ref()
                .expect("completed opening stop"),
            state: &self.attempt.states[BEFORE].state,
        })
    }
    pub(super) fn step(&self) -> NativeCheckpoint<'a> {
        NativeCheckpoint {
            stop: self.attempt.stops[3].as_ref().expect("completed step stop"),
            state: &self.attempt.states[STEP].state,
        }
    }
    pub(super) fn closing(&self) -> [NativeCheckpoint<'a>; 3] {
        std::array::from_fn(|index| NativeCheckpoint {
            stop: self.attempt.stops[index + 4]
                .as_ref()
                .expect("completed closing stop"),
            state: &self.attempt.states[STEP].state,
        })
    }
    pub(super) fn trace(&self) -> NativeTrace {
        self.attempt.trace.expect("completed native trace")
    }
}
fn fixed_buffer() -> Result<Box<[u8; MAP_BYTES]>, LaunchError> {
    let layout = std::alloc::Layout::new::<[u8; MAP_BYTES]>();
    let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
    if pointer.is_null() {
        return Err(LaunchError::Invalid(
            "owned instruction buffer allocation refused",
        ));
    }
    // Exactly the initialized array layout; no Vec growth or conversion peak.
    Ok(unsafe { Box::from_raw(pointer.cast()) })
}
fn request(operation: u32, tid: i32, address: usize, data: usize) -> Request {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let result = unsafe { libc::ptrace(operation, tid, address, data) };
    let errno = if result == -1 {
        let code = unsafe { *libc::__errno_location() };
        (code != 0).then_some(code)
    } else {
        None
    };
    Request { result, errno }
}
fn checked(request: Request, operation: &'static str) -> Result<(), LaunchError> {
    if let Some(errno) = request.errno {
        return Err(io_error(
            operation,
            std::io::Error::from_raw_os_error(errno),
        ));
    }
    if request.result != 0 {
        return Err(LaunchError::Invalid(
            "owned instruction ptrace result differs",
        ));
    }
    Ok(())
}
fn mapped(error: GateError) -> LaunchError {
    match error {
        GateError::Control(error) => error,
        _ => LaunchError::Invalid("owned instruction source projection differs"),
    }
}
/// # Safety
/// Binding is issued only under the runtime source/census/no-unowned-writer
/// contract. The caller retains attempt and physical owner through all errors.
pub(super) unsafe fn execute_owned_instruction(
    owner: &mut Owner,
    native: &mut NativeLifecycle,
    binding: &RuntimeInstructionBinding<'_>,
    attempt: &mut PreparedInstructionAttempt,
    observation: &mut dyn InstructionObservation,
) -> Result<(), LaunchError> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runner::execute(owner, native, binding, attempt, observation)
    }));
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            attempt.progress.fail(Some(&error));
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
            Err(error)
        }
        Err(payload) => {
            attempt.progress.fail(None);
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
            std::panic::resume_unwind(payload)
        }
    }
}
