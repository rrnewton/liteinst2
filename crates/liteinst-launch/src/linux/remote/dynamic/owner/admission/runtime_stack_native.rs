//! One actual E8/C3 instruction over an acquired original resident stack word.
//! All buffers remain installed through failure and cleanup; this module alone
//! produces the borrowed completion after actual trace, effect and NX closure.
use super::super::bootstrap::{
    self, MapBuffer, MemoryObservation, Request, SignalObservation, StateSlot,
};
use super::census::stack_calls::{PotentialCallId, RecordedCall};
use super::runtime::maps::{FetchGeometry, verify_closed};
use super::runtime::stack::{RuntimeStackBinding, RuntimeStackIdentity, StackBeforeContext};
use super::runtime_capture::SourceWindowId;
use super::runtime_instruction::CandidateKind;
use super::runtime_native::{
    ControlLineage, ControlProfile, DR_TRACE, DebugRead, InstructionEffect,
    InstructionEffectRecord, InstructionFailure, NativeCheckpoint, NativeTrace,
};
use super::runtime_stack::operand::{OperandDescription, StackOperation, validate_effect};
use super::runtime_stack::profile::ProfileDescription;
use super::*;
use crate::linux::remote::{MAX_XSTATE, NT_X86_XSTATE, STUB, SYNC_CORE};
use std::mem::size_of;

pub(super) mod acquire;
#[cfg(feature = "dev-owned-stack-consumer-oracle")]
pub(super) mod consumer_oracle;
mod io;
mod runner;
mod storage;
#[cfg(test)]
mod tests;
pub(super) use super::runtime_native::InstructionObservation as StackSourceObservation;
use acquire::{
    NativeStackWordCapture, OriginalStackIdentity, PreparedStackOperandCapture, StackWordView,
};
#[cfg(test)]
use storage::AllocationFault;
use storage::{StackMapSlot, StackNativeShape};
#[cfg(test)]
pub(super) use tests::{InterventionKind, InterventionPoint};

const MAP_BYTES: usize = 64 * 1024;
const WAITS: usize = 7;
const STATES: usize = 9;
const MAPS: usize = 5;
const BEFORE: usize = 0;
const STEP: usize = 4;
const WORK: usize = 8;
const BASELINE_MAP: usize = 0;
const OPEN_MAP: usize = 1;
const STEP_MAP: usize = 2;
const CLOSED_MAP: usize = 3;
const WORK_MAP: usize = 4;
// Six calls have at most five actual effects each, plus one original release.
// The old ordinary producer's independent fixed array is unchanged.
const EFFECTS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StackPhase {
    Empty,
    Allocating,
    Allocated,
    BeforeCapture,
    BeforeCaptured,
    Opening,
    Opened,
    Original,
    Closing,
    Closed,
}
pub(super) struct StackProgress {
    pub(super) phase: StackPhase,
    pub(super) first_failure: Option<(StackPhase, InstructionFailure)>,
    pub(super) waits: [Option<(i32, i32)>; WAITS],
    pub(super) queries_started: [bool; WAITS],
    pub(super) instruction_completed: bool,
    pub(super) nx_closed: bool,
    pub(super) failed_held_attempted: bool,
    pub(super) failed_held_failure: Option<InstructionFailure>,
    effects: [Option<InstructionEffectRecord>; EFFECTS],
    effects_len: usize,
}
impl Default for StackProgress {
    fn default() -> Self {
        Self {
            phase: StackPhase::Empty,
            first_failure: None,
            waits: [None; WAITS],
            queries_started: [false; WAITS],
            instruction_completed: false,
            nx_closed: false,
            failed_held_attempted: false,
            failed_held_failure: None,
            effects: [None; EFFECTS],
            effects_len: 0,
        }
    }
}
impl StackProgress {
    #[cfg(test)]
    pub(super) fn effects(&self) -> &[Option<InstructionEffectRecord>] {
        &self.effects[..self.effects_len]
    }
    fn fail(&mut self, error: Option<&LaunchError>) {
        if self.first_failure.is_some() {
            return;
        }
        let failure = failure_kind(error);
        self.first_failure = Some((self.phase, failure));
    }
}
fn failure_kind(error: Option<&LaunchError>) -> InstructionFailure {
    match error {
        Some(LaunchError::Invalid(reason)) => InstructionFailure::Invalid(reason),
        Some(LaunchError::System { operation, source }) => {
            InstructionFailure::System(operation, source.raw_os_error())
        }
        Some(LaunchError::Timeout(operation)) => InstructionFailure::Timeout(operation),
        Some(LaunchError::Child { status }) => InstructionFailure::Child(*status),
        None => InstructionFailure::Unwound,
    }
}

pub(super) struct PreparedStackNative {
    shape: Option<StackNativeShape>,
    until: Option<Instant>,
    states: [StateSlot; STATES],
    maps: [StackMapSlot; MAPS],
    membership: Vec<u8>,
    signals: [SignalObservation; WAITS],
    debug: [DebugRead; WAITS],
    profile: ControlProfile,
    peek: MemoryObservation,
    words: [NativeStackWordCapture; 3],
    progress: StackProgress,
    initial: Option<AdmissionStop>,
    stops: [Option<AdmissionStop>; WAITS],
    source: Option<SourceWindowId>,
    origin: Option<OriginId>,
    execution: Option<ExecutionId>,
    encoding: [u8; 5],
    encoding_len: usize,
    identity: Option<RuntimeStackIdentity>,
    trace: Option<NativeTrace>,
    call_id: Option<PotentialCallId>,
    claimed: bool,
    native_payload_bytes: usize,
    #[cfg(test)]
    allocation_fault: AllocationFault,
    #[cfg(test)]
    intervention: Option<tests::Intervention>,
}

/// Parent-private actual native views. No caller can construct either from
/// a snapshot, a copied stop, or a descriptive stack record.
pub(super) struct NativeStackBeforeView<'a> {
    stop: &'a AdmissionStop,
    state: &'a StateSlot,
    work: &'a StateSlot,
    baseline_maps: &'a [u8],
    until: Instant,
}
impl NativeStackBeforeView<'_> {
    pub(super) fn stop(&self) -> &AdmissionStop {
        self.stop
    }
    pub(super) fn state(&self) -> &StateSlot {
        self.state
    }
    pub(super) fn work(&self) -> &StateSlot {
        self.work
    }
    pub(super) fn baseline_maps(&self) -> &[u8] {
        self.baseline_maps
    }
    pub(super) fn until(&self) -> Instant {
        self.until
    }
}
pub(super) struct NativeStackHeldView<'a> {
    original: &'a AdmissionStop,
    raw_wait: (i32, i32),
    state: &'a StateSlot,
    maps: &'a [u8],
    until: Instant,
}
impl NativeStackHeldView<'_> {
    pub(super) fn original(&self) -> &AdmissionStop {
        self.original
    }
    pub(super) fn raw_wait(&self) -> (i32, i32) {
        self.raw_wait
    }
    pub(super) fn state(&self) -> &StateSlot {
        self.state
    }
    pub(super) fn maps(&self) -> &[u8] {
        self.maps
    }
    pub(super) fn until(&self) -> Instant {
        self.until
    }
}

pub(super) struct StackWordViews<'a> {
    pub(super) profile: &'a ProfileDescription,
    pub(super) operand: &'a OperandDescription,
    pub(super) original_maps: &'a [u8],
    pub(super) baseline_maps: &'a [u8],
    pub(super) opened_maps: &'a [u8],
    pub(super) captures: [StackWordView<'a>; 4],
}
/// Non-Clone, no scalar constructor, and issued at most once. The actual A and
/// initial profile remain borrowed from the final authenticated root binding.
pub(super) struct OwnedStackCompletion<'a> {
    attempt: &'a PreparedStackNative,
    words: StackWordViews<'a>,
}
impl<'a> OwnedStackCompletion<'a> {
    pub(super) fn identity(&self) -> &'a RuntimeStackIdentity {
        self.attempt
            .identity
            .as_ref()
            .expect("completed stack identity")
    }
    pub(super) fn logical_before(&self) -> NativeCheckpoint<'a> {
        NativeCheckpoint {
            stop: self
                .attempt
                .initial
                .as_ref()
                .expect("completed stack before"),
            state: &self.attempt.states[BEFORE].state,
        }
    }
    pub(super) fn opening(&self) -> [NativeCheckpoint<'a>; 3] {
        std::array::from_fn(|index| NativeCheckpoint {
            stop: self.attempt.stops[index]
                .as_ref()
                .expect("completed stack opening"),
            state: &self.attempt.states[BEFORE].state,
        })
    }
    pub(super) fn step(&self) -> NativeCheckpoint<'a> {
        NativeCheckpoint {
            stop: self.attempt.stops[3]
                .as_ref()
                .expect("completed stack trace"),
            state: &self.attempt.states[STEP].state,
        }
    }
    pub(super) fn closing(&self) -> [NativeCheckpoint<'a>; 3] {
        std::array::from_fn(|index| NativeCheckpoint {
            stop: self.attempt.stops[index + 4]
                .as_ref()
                .expect("completed stack closing"),
            state: &self.attempt.states[STEP].state,
        })
    }
    pub(super) fn trace(&self) -> NativeTrace {
        self.attempt.trace.expect("completed stack native trace")
    }
    pub(super) fn words(&self) -> StackWordViews<'a> {
        StackWordViews {
            profile: self.words.profile,
            operand: self.words.operand,
            original_maps: self.words.original_maps,
            baseline_maps: self.words.baseline_maps,
            opened_maps: self.words.opened_maps,
            captures: self.words.captures,
        }
    }
    pub(super) fn call_id(&self) -> Option<PotentialCallId> {
        self.attempt.call_id
    }
}
impl PreparedStackNative {
    /// All owned source/state/capture storage has already been allocated and
    /// charged before this first actual native read. No original release here.
    pub(super) fn prepare_before_and_operand(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        context: &StackBeforeContext<'_, '_>,
        initial: &OriginalStackIdentity<'_>,
        operand: &mut PreparedStackOperandCapture,
    ) -> Result<(), LaunchError> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runner::prepare(owner, native, context, initial, self, operand)
        }));
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.progress.fail(Some(&error));
                Err(error)
            }
            Err(payload) => {
                self.mark_aborted();
                operand.mark_aborted();
                std::panic::resume_unwind(payload)
            }
        }
    }
    pub(super) fn take_completed<'a>(
        &'a mut self,
        binding: &'a RuntimeStackBinding<'_, '_>,
    ) -> Result<OwnedStackCompletion<'a>, LaunchError> {
        if self.claimed
            || self.progress.phase != StackPhase::Closed
            || !self.progress.nx_closed
            || !self.progress.instruction_completed
            || self.progress.first_failure.is_some()
            || self.identity.as_ref() != Some(binding.identity())
        {
            return Err(LaunchError::Invalid("owned stack completion unavailable"));
        }
        runner::require_binding(binding, self)?;
        runner::require_completed_words(binding, self)?;
        self.claimed = true;
        let words = StackWordViews {
            profile: binding.profile_description(),
            operand: binding.operand_description(),
            original_maps: binding.original_maps(),
            baseline_maps: self.maps[BASELINE_MAP].bytes(),
            opened_maps: self.maps[OPEN_MAP].bytes(),
            captures: [
                binding.operand().view(),
                self.words[0].view(),
                self.words[1].view(),
                self.words[2].view(),
            ],
        };
        Ok(OwnedStackCompletion {
            attempt: self,
            words,
        })
    }
    /// New fixed managed temporary evidence; root separately accounts the
    /// existing ControlProfile/source-reader peak and its binding/observer.
    pub(super) fn temporary_bytes() -> Result<usize, LaunchError> {
        let mut total = acquire::temporary_bytes()?;
        for bytes in [
            runner::temporary_bytes(),
            2 * size_of::<RuntimeStackIdentity>(),
            size_of::<OwnedStackCompletion<'_>>(),
            2 * size_of::<StackWordViews<'_>>(),
            2 * size_of::<Option<InstructionFailure>>(),
            2 * size_of::<Option<Request>>(),
        ] {
            total = total.checked_add(bytes).ok_or(LaunchError::Invalid(
                "owned stack temporary evidence overflows",
            ))?;
        }
        Ok(total)
    }
    #[cfg(test)]
    pub(super) fn progress(&self) -> &StackProgress {
        &self.progress
    }
    #[cfg(test)]
    pub(super) fn diagnostics(&self) -> StackNativeDiagnostics<'_> {
        StackNativeDiagnostics {
            states: &self.states,
            maps: std::array::from_fn(|i| self.maps[i].retained()),
            signals: &self.signals,
            debug: &self.debug,
            profile: &self.profile,
            memory: &self.peek,
            words: std::array::from_fn(|i| self.words[i].view()),
            initial: self.initial.as_ref(),
            stops: &self.stops,
            identity: self.identity.as_ref(),
            trace: self.trace,
            call_id: self.call_id,
            encoding: &self.encoding[..self.encoding_len],
            claimed: self.claimed,
            membership: &self.membership,
            membership_capacity: self.membership.capacity(),
            native_payload_bytes: self.native_payload_bytes,
        }
    }
}

#[cfg(test)]
pub(super) struct StackNativeDiagnostics<'a> {
    pub(super) states: &'a [StateSlot; STATES],
    pub(super) maps: [Option<&'a MapBuffer>; MAPS],
    pub(super) signals: &'a [SignalObservation; WAITS],
    pub(super) debug: &'a [DebugRead; WAITS],
    pub(super) profile: &'a ControlProfile,
    pub(super) memory: &'a MemoryObservation,
    pub(super) words: [StackWordView<'a>; 3],
    pub(super) initial: Option<&'a AdmissionStop>,
    pub(super) stops: &'a [Option<AdmissionStop>; WAITS],
    pub(super) identity: Option<&'a RuntimeStackIdentity>,
    pub(super) trace: Option<NativeTrace>,
    pub(super) call_id: Option<PotentialCallId>,
    pub(super) encoding: &'a [u8],
    pub(super) claimed: bool,
    pub(super) membership: &'a [u8],
    pub(super) membership_capacity: usize,
    pub(super) native_payload_bytes: usize,
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
        return Err(LaunchError::Invalid("owned stack ptrace result differs"));
    }
    Ok(())
}
fn mapped(error: GateError) -> LaunchError {
    match error {
        GateError::Control(error) => error,
        _ => LaunchError::Invalid("owned stack source projection differs"),
    }
}
fn stack_error(_: super::runtime_stack::StackError) -> LaunchError {
    LaunchError::Invalid("owned stack effect or captured word differs")
}
/// # Safety
/// Root retains the actual source/profile/A, sole physical owner and attempt
/// through all outcomes. CALL has already recorded its potential return before
/// any opening effect. Failed outcomes never release another original fetch.
pub(super) unsafe fn execute_owned_stack(
    owner: &mut Owner,
    native: &mut NativeLifecycle,
    binding: &RuntimeStackBinding<'_, '_>,
    recorded: Option<RecordedCall<'_>>,
    attempt: &mut PreparedStackNative,
    observation: &mut dyn StackSourceObservation,
) -> Result<(), LaunchError> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runner::execute(owner, native, binding, recorded, attempt, observation)
    }));
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            // Preserve the actual first refusal before bounded diagnostic reads.
            attempt.progress.fail(Some(&error));
            let diagnostic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                runner::failed_held(owner, native, binding, attempt)
            }));
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
            match diagnostic {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    attempt.progress.failed_held_failure = Some(failure_kind(Some(&error)));
                }
                Err(payload) => {
                    attempt.progress.failed_held_failure = Some(InstructionFailure::Unwound);
                    attempt.words[1].mark_aborted();
                    std::panic::resume_unwind(payload);
                }
            }
            Err(error)
        }
        Err(payload) => {
            attempt.mark_aborted();
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
            std::panic::resume_unwind(payload)
        }
    }
}
