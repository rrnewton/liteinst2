//! One original native64 identity/termination syscall at its captured site.
//! Only consumed native outcomes certify return or terminal; diagnostic views
//! and allocated storage grant no execution/source authority.
use super::super::bootstrap::{self, MemoryObservation, Request};
use super::runtime::kernel::namespace::{
    NamespaceObservation, NativeNamespaceIdentity, capture_namespace,
};
use super::runtime::kernel::{RuntimeKernelBinding, RuntimeKernelIdentity, RuntimeKernelOperation};
use super::runtime::maps::{FetchGeometry, verify_closed};
use super::runtime_native::{ControlProfile, NativeCheckpoint};
use super::*;
use crate::linux::remote::dynamic::owner::kernel_journal::{KernelAttemptId, KernelStopIdentity};
use crate::linux::remote::{MAX_XSTATE, NT_X86_XSTATE, STUB, SYNC_CORE};
use std::mem::size_of;

mod io;
mod runner;
#[cfg(test)]
mod tests;
use io::{FixedReads, MapsRead, StateRead};

const MAP_BYTES: usize = 65536;
const WAITS: usize = 9;
const STATES: usize = 11;
const MAPS: usize = 11;
const EFFECTS: usize = 37;
const BEFORE: usize = 0;
const WORK: usize = 10;
const BASELINE: usize = 0;
const WORK_MAP: usize = 10;
const ENTRY: usize = 3;
const EXIT: usize = 4;
const BRIDGE: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeKernelEffect {
    SetRegisters { ordinal: usize },
    PrivateRelease { ordinal: usize },
    RestoreXstate { ordinal: usize },
    RestoreRegisters { ordinal: usize },
    RestoreMask { ordinal: usize },
    OriginalRelease,
    EntryRelease,
    PreExitRelease,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum RuntimeKernelFailure {
    Invalid(&'static str),
    System(&'static str, Option<i32>),
    Timeout(&'static str),
    Child(i32),
    Unwound,
}
impl RuntimeKernelFailure {
    fn from_error(error: &LaunchError) -> Self {
        match error {
            LaunchError::Invalid(reason) => Self::Invalid(reason),
            LaunchError::System { operation, source } => {
                Self::System(operation, source.raw_os_error())
            }
            LaunchError::Timeout(operation) => Self::Timeout(operation),
            LaunchError::Child { status } => Self::Child(*status),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeKernelPhase {
    Allocating,
    BeforeProvider,
    Pending,
    AfterProvider,
    Opening,
    Opened,
    Entry,
    Exit,
    Bridge,
    Closing,
    Closed,
    PreExit,
    Terminal,
    Physical,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RuntimeKernelEffectRecord {
    pub(super) effect: RuntimeKernelEffect,
    pub(super) result: Option<Request>,
    pub(super) complete: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct RuntimeWaitCustody {
    pub(in crate::linux::remote::dynamic::owner) session: u64,
    pub(in crate::linux::remote::dynamic::owner) expected_tid: i32,
    pub(in crate::linux::remote::dynamic::owner) retained_pin: Option<i32>,
    pub(in crate::linux::remote::dynamic::owner) process_pin: Option<bool>,
    pub(in crate::linux::remote::dynamic::owner) owned: bool,
    pub(in crate::linux::remote::dynamic::owner) stopped_status: Option<i32>,
    pub(in crate::linux::remote::dynamic::owner) tracer_terminal: Option<i32>,
    pub(in crate::linux::remote::dynamic::owner) lost_wait: bool,
    pub(in crate::linux::remote::dynamic::owner) missing_pin: bool,
}
#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner) struct RuntimeStateReadView<'a> {
    pub(in crate::linux::remote::dynamic::owner) registers: &'a [u8; 216],
    pub(in crate::linux::remote::dynamic::owner) registers_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) xstate_initialized: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner) xstate_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) requested_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner) returned_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner) requested_length: usize,
    pub(in crate::linux::remote::dynamic::owner) returned_length: usize,
    pub(in crate::linux::remote::dynamic::owner) mask: &'a [u8; 8],
    pub(in crate::linux::remote::dynamic::owner) mask_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
    pub(in crate::linux::remote::dynamic::owner) state: Option<&'a TaskStateSnapshot>,
}
#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner) struct RuntimeFixedReads<'a> {
    pub(in crate::linux::remote::dynamic::owner) syscall_info: &'a [u8; 88],
    pub(in crate::linux::remote::dynamic::owner) syscall_info_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) event_message: u64,
    pub(in crate::linux::remote::dynamic::owner) event_message_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) signal: &'a [u8; 128],
    pub(in crate::linux::remote::dynamic::owner) signal_request: Option<Request>,
}
#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner) struct RuntimeMapsReadView<'a> {
    pub(in crate::linux::remote::dynamic::owner) initialized: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner) length: usize,
    pub(in crate::linux::remote::dynamic::owner) directory_open: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) filesystem_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) filesystem: Option<i64>,
    pub(in crate::linux::remote::dynamic::owner) maps_open: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) read_calls: usize,
    pub(in crate::linux::remote::dynamic::owner) last_read: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) overflow_probe: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
}
#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner) struct RuntimeRawWaitView<'a> {
    pub(in crate::linux::remote::dynamic::owner) ordinal: usize,
    pub(in crate::linux::remote::dynamic::owner) tid: i32,
    pub(in crate::linux::remote::dynamic::owner) status: i32,
    pub(in crate::linux::remote::dynamic::owner) queries_started: bool,
    pub(in crate::linux::remote::dynamic::owner) state: Option<RuntimeStateReadView<'a>>,
    pub(in crate::linux::remote::dynamic::owner) fixed: RuntimeFixedReads<'a>,
    pub(in crate::linux::remote::dynamic::owner) maps: Option<RuntimeMapsReadView<'a>>,
    pub(super) control: &'a ControlProfile,
    pub(in crate::linux::remote::dynamic::owner) failure: Option<RuntimeKernelFailure>,
}
#[derive(Clone, Copy)]
pub(super) struct NativeSyscallCheckpoint<'a> {
    pub(super) event: &'a DynamicEvent,
    pub(super) state: &'a TaskStateSnapshot,
    pub(super) raw: RuntimeRawWaitView<'a>,
}
#[derive(Clone, Copy)]
pub(super) struct NativePreExitCheckpoint<'a> {
    pub(super) raw: RuntimeRawWaitView<'a>,
    pub(super) state: &'a TaskStateSnapshot,
    pub(super) event_message: u64,
    pub(super) event_message_request: Request,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct NativeKernelReturnTrace {
    pub(in crate::linux::remote::dynamic::owner) attempt: KernelAttemptId,
    pub(in crate::linux::remote::dynamic::owner) entry_ordinal: usize,
    pub(in crate::linux::remote::dynamic::owner) exit_ordinal: usize,
    pub(in crate::linux::remote::dynamic::owner) bridge_ordinal: usize,
    pub(in crate::linux::remote::dynamic::owner) closed_ordinal: usize,
    pub(in crate::linux::remote::dynamic::owner) released: KernelStopIdentity,
    pub(in crate::linux::remote::dynamic::owner) entry: KernelStopIdentity,
    pub(in crate::linux::remote::dynamic::owner) exit: KernelStopIdentity,
    pub(in crate::linux::remote::dynamic::owner) bridge: KernelStopIdentity,
    pub(in crate::linux::remote::dynamic::owner) closed: KernelStopIdentity,
    pub(in crate::linux::remote::dynamic::owner) original_release: Request,
    pub(in crate::linux::remote::dynamic::owner) entry_release: Request,
    pub(in crate::linux::remote::dynamic::owner) namespace: NativeNamespaceIdentity,
    pub(in crate::linux::remote::dynamic::owner) dr6: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct NativeKernelTerminalTrace {
    pub(in crate::linux::remote::dynamic::owner) attempt: KernelAttemptId,
    pub(in crate::linux::remote::dynamic::owner) released: KernelStopIdentity,
    pub(in crate::linux::remote::dynamic::owner) entry: KernelStopIdentity,
    pub(in crate::linux::remote::dynamic::owner) pre_exit_ordinal: usize,
    pub(in crate::linux::remote::dynamic::owner) pre_exit_tid: i32,
    pub(in crate::linux::remote::dynamic::owner) pre_exit_status: i32,
    pub(in crate::linux::remote::dynamic::owner) event_message: u64,
    pub(in crate::linux::remote::dynamic::owner) event_message_request: Request,
    pub(in crate::linux::remote::dynamic::owner) original_release: Request,
    pub(in crate::linux::remote::dynamic::owner) entry_release: Request,
    pub(in crate::linux::remote::dynamic::owner) pre_exit_release: Request,
    pub(in crate::linux::remote::dynamic::owner) exiting_sequence: u64,
    pub(in crate::linux::remote::dynamic::owner) terminal_ordinal: usize,
    pub(in crate::linux::remote::dynamic::owner) terminal_tid: i32,
    pub(in crate::linux::remote::dynamic::owner) terminal_status: i32,
    pub(in crate::linux::remote::dynamic::owner) terminal_sequence: u64,
    pub(in crate::linux::remote::dynamic::owner) physical_status: i32,
    pub(in crate::linux::remote::dynamic::owner) pin_fd: i32,
    pub(in crate::linux::remote::dynamic::owner) pin_poll: Request,
    pub(in crate::linux::remote::dynamic::owner) pin_revents: i16,
    pub(in crate::linux::remote::dynamic::owner) namespace: NativeNamespaceIdentity,
}
#[derive(Clone, Copy)]
pub(super) enum RuntimeKernelEffectContext<'a> {
    Settled(NativeCheckpoint<'a>),
    Syscall(NativeSyscallCheckpoint<'a>),
    PreExit(NativePreExitCheckpoint<'a>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum RuntimeKernelReadback {
    Original,
    RestoredReturn,
    Closed,
    Unexpected,
}
pub(super) trait RuntimeKernelObservation {
    fn before_effect(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        binding: &RuntimeKernelIdentity,
        effect: RuntimeKernelEffect,
        current: RuntimeKernelEffectContext<'_>,
        until: Instant,
    ) -> Result<(), LaunchError>;
    fn effect_result(
        &mut self,
        binding: &RuntimeKernelIdentity,
        effect: RuntimeKernelEffect,
        actual: Request,
    ) -> Result<(), LaunchError>;
    fn wait(
        &mut self,
        binding: &RuntimeKernelIdentity,
        ordinal: usize,
        tid: i32,
        status: i32,
        custody: RuntimeWaitCustody,
    ) -> Result<(), LaunchError>;
    fn raw(
        &mut self,
        binding: &RuntimeKernelIdentity,
        raw: RuntimeRawWaitView<'_>,
    ) -> Result<(), LaunchError>;
    fn readback(
        &mut self,
        binding: &RuntimeKernelIdentity,
        kind: RuntimeKernelReadback,
        stop: Option<&AdmissionStop>,
        state: RuntimeStateReadView<'_>,
    ) -> Result<(), LaunchError>;
    fn opened(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        binding: &RuntimeKernelIdentity,
        checkpoint: NativeCheckpoint<'_>,
        maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError>;
    fn entry(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        binding: &RuntimeKernelIdentity,
        checkpoint: NativeSyscallCheckpoint<'_>,
        until: Instant,
    ) -> Result<(), LaunchError>;
    fn exit(
        &mut self,
        binding: &RuntimeKernelIdentity,
        checkpoint: NativeSyscallCheckpoint<'_>,
    ) -> Result<(), LaunchError>;
    fn closed(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        binding: &RuntimeKernelIdentity,
        checkpoint: NativeCheckpoint<'_>,
        maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError>;
    fn pre_exit(
        &mut self,
        binding: &RuntimeKernelIdentity,
        checkpoint: NativePreExitCheckpoint<'_>,
    ) -> Result<(), LaunchError>;
    fn terminal(
        &mut self,
        binding: &RuntimeKernelIdentity,
        event: &DynamicEvent,
        trace: NativeKernelTerminalTrace,
    ) -> Result<(), LaunchError>;
}

#[derive(Clone, Copy)]
pub(super) struct RuntimeKernelShape {
    operation: RuntimeKernelOperation,
    fetch_start: u64,
    fetch_end: u64,
}
impl RuntimeKernelShape {
    pub(super) fn new(
        operation: RuntimeKernelOperation,
        geometry: &FetchGeometry,
    ) -> Result<Self, LaunchError> {
        let pages = geometry.pages();
        if pages.start() % 4096 != 0
            || !matches!(pages.end().checked_sub(pages.start()), Some(4096 | 8192))
        {
            return Err(LaunchError::Invalid("runtime kernel fetch shape differs"));
        }
        Ok(Self {
            operation,
            fetch_start: pages.start(),
            fetch_end: pages.end(),
        })
    }
    /// Complete native retained managed evidence; parent separately adds the
    /// concurrent ControlProfile/source/binding/observer temporary peak.
    pub(super) fn reservation_bytes() -> Result<usize, LaunchError> {
        add(
            size_of::<PreparedRuntimeKernel>(),
            add(mul(STATES, MAX_XSTATE)?, mul(MAPS + 1, MAP_BYTES)?)?,
        )
    }
    /// Fixed named source-evidence values nested in this producer. This is
    /// separate from retained H and from the existing control/namespace/source
    /// helpers. It is not a compiler frame-size or process-RSS claim.
    pub(super) fn temporary_bytes() -> Result<usize, LaunchError> {
        add(runner::temporary_bytes()?, io::temporary_bytes()?)
    }
}
struct RawWait {
    wait: Option<(i32, i32)>,
    custody: Option<RuntimeWaitCustody>,
    queries_started: bool,
    fixed: FixedReads,
    failure: Option<RuntimeKernelFailure>,
}
impl Default for RawWait {
    fn default() -> Self {
        Self {
            wait: None,
            custody: None,
            queries_started: false,
            fixed: FixedReads::default(),
            failure: None,
        }
    }
}
struct Readback {
    kind: RuntimeKernelReadback,
    stop: Option<AdmissionStop>,
    state: usize,
}

pub(super) struct PreparedRuntimeKernel {
    shape: RuntimeKernelShape,
    until: Instant,
    states: [StateRead; STATES],
    maps: [MapsRead; MAPS],
    membership: Option<Box<[u8; MAP_BYTES]>>,
    profiles: [ControlProfile; 11],
    namespaces: [NamespaceObservation; 5],
    raw: [RawWait; WAITS],
    effects: [Option<RuntimeKernelEffectRecord>; EFFECTS],
    effects_len: usize,
    memory: MemoryObservation,
    initial: Option<AdmissionStop>,
    // opening0..2, bridge3, closing4..6. Original has its own initial field.
    stops: [Option<AdmissionStop>; 7],
    // ENTRY, actual EXIT or TaskExiting, actual terminal.
    events: [Option<DynamicEvent>; 3],
    exiting_sequence: Option<u64>,
    terminal_sequence: Option<u64>,
    identity: Option<RuntimeKernelIdentity>,
    return_trace: Option<NativeKernelReturnTrace>,
    terminal_trace: Option<NativeKernelTerminalTrace>,
    namespace: Option<NativeNamespaceIdentity>,
    last_readback: Option<Readback>,
    phase: RuntimeKernelPhase,
    first_failure: Option<(RuntimeKernelPhase, RuntimeKernelFailure)>,
    allocated: bool,
    provider_ready: bool,
    original_completed: bool,
    nx_closed: bool,
    physical_complete: bool,
    claimed: bool,
}
impl PreparedRuntimeKernel {
    // Add within the existing PreparedRuntimeKernel impl; diagnostics only.
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_effects(
        &self,
    ) -> &[Option<RuntimeKernelEffectRecord>] {
        &self.effects[..self.effects_len]
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_failure(
        &self,
    ) -> Option<(RuntimeKernelPhase, RuntimeKernelFailure)> {
        self.first_failure
    }

    fn can_begin_effect(&self) -> bool {
        self.first_failure.is_none()
            && self.effects_len < EFFECTS
            && (self.effects_len == 0
                || self
                    .effects
                    .get(self.effects_len - 1)
                    .is_some_and(|record| record.is_some_and(|record| record.complete)))
    }
    pub(super) fn new(shape: RuntimeKernelShape, until: Instant) -> Self {
        Self {
            shape,
            until,
            states: std::array::from_fn(|_| StateRead::default()),
            maps: std::array::from_fn(|_| MapsRead::default()),
            membership: None,
            profiles: std::array::from_fn(|_| ControlProfile::default()),
            namespaces: std::array::from_fn(|_| NamespaceObservation::default()),
            raw: std::array::from_fn(|_| RawWait::default()),
            effects: [None; EFFECTS],
            effects_len: 0,
            memory: MemoryObservation::default(),
            initial: None,
            stops: std::array::from_fn(|_| None),
            events: std::array::from_fn(|_| None),
            exiting_sequence: None,
            terminal_sequence: None,
            identity: None,
            return_trace: None,
            terminal_trace: None,
            namespace: None,
            last_readback: None,
            phase: RuntimeKernelPhase::Allocating,
            first_failure: None,
            allocated: false,
            provider_ready: false,
            original_completed: false,
            nx_closed: false,
            physical_complete: false,
            claimed: false,
        }
    }
    pub(super) fn allocate_payloads(&mut self) -> Result<(), LaunchError> {
        let result = (|| {
            if self.allocated || self.first_failure.is_some() || self.identity.is_some() {
                return Err(LaunchError::Invalid("runtime kernel allocation reused"));
            }
            for state in &mut self.states {
                state.allocate()?;
            }
            for maps in &mut self.maps {
                maps.allocate()?;
            }
            if self.membership.is_some() {
                return Err(LaunchError::Invalid(
                    "runtime kernel membership allocation reused",
                ));
            }
            self.membership = Some(fixed_buffer()?);
            if self.allocated_bytes()? != RuntimeKernelShape::reservation_bytes()? {
                return Err(LaunchError::Invalid(
                    "runtime kernel allocation differs from reservation",
                ));
            }
            self.allocated = true;
            Ok(())
        })();
        if let Err(error) = &result {
            self.fail(error);
        }
        result
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize, LaunchError> {
        add(size_of::<Self>(), self.payload_bytes()?)
    }
    pub(super) fn payload_bytes(&self) -> Result<usize, LaunchError> {
        let mut bytes = usize::from(self.membership.is_some()) * MAP_BYTES;
        for state in &self.states {
            bytes = add(bytes, state.capacity())?;
        }
        for maps in &self.maps {
            bytes = add(bytes, maps.capacity())?;
        }
        Ok(bytes)
    }
    pub(super) fn before_provider(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        binding: &RuntimeKernelBinding<'_>,
        observer: &mut dyn RuntimeKernelObservation,
    ) -> Result<(), LaunchError> {
        self.guarded(|attempt| runner::before_provider(owner, native, binding, attempt, observer))
    }
    pub(super) fn execute(
        &mut self,
        owner: &mut Owner,
        native: &mut NativeLifecycle,
        binding: &RuntimeKernelBinding<'_>,
        observer: &mut dyn RuntimeKernelObservation,
    ) -> Result<(), LaunchError> {
        let result =
            self.guarded(|attempt| runner::execute(owner, native, binding, attempt, observer));
        if result.is_err() {
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
        }
        result
    }
    fn guarded(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<(), LaunchError>,
    ) -> Result<(), LaunchError> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self))) {
            Ok(result) => {
                if let Err(error) = &result {
                    self.fail(error);
                }
                result
            }
            Err(payload) => {
                self.first_failure
                    .get_or_insert((self.phase, RuntimeKernelFailure::Unwound));
                std::panic::resume_unwind(payload)
            }
        }
    }
    fn fail(&mut self, error: &LaunchError) {
        self.first_failure
            .get_or_insert((self.phase, RuntimeKernelFailure::from_error(error)));
    }
    pub(super) fn raw_view(&self, ordinal: usize) -> Option<RuntimeRawWaitView<'_>> {
        let raw = self.raw.get(ordinal)?;
        let (tid, status) = raw.wait?;
        Some(RuntimeRawWaitView {
            ordinal,
            tid,
            status,
            queries_started: raw.queries_started,
            state: raw.queries_started.then(|| self.states[ordinal + 1].view()),
            fixed: raw.fixed.view(),
            maps: if raw.queries_started {
                self.maps[ordinal + 1].view()
            } else {
                None
            },
            control: &self.profiles[ordinal + 2],
            failure: raw.failure,
        })
    }
    pub(super) fn last_readback_view(
        &self,
    ) -> Option<(
        RuntimeKernelReadback,
        Option<&AdmissionStop>,
        RuntimeStateReadView<'_>,
    )> {
        self.last_readback.as_ref().map(|view| {
            (
                view.kind,
                view.stop.as_ref(),
                self.states[view.state].view(),
            )
        })
    }
    pub(super) fn take_returned(&mut self) -> Result<OwnedRuntimeKernelReturn<'_>, LaunchError> {
        if self.claimed
            || self.first_failure.is_some()
            || !self.original_completed
            || !self.nx_closed
            || self.return_trace.is_none()
            || !self.shape.operation.returns()
        {
            return Err(LaunchError::Invalid(
                "runtime kernel return is not claimable",
            ));
        }
        self.claimed = true;
        Ok(OwnedRuntimeKernelReturn { attempt: self })
    }
    pub(super) fn take_terminal(&mut self) -> Result<OwnedRuntimeKernelTerminal<'_>, LaunchError> {
        if self.claimed
            || self.first_failure.is_some()
            || !self.physical_complete
            || !self.terminal_trace.is_some_and(|trace| {
                Some(trace.exiting_sequence) == self.exiting_sequence
                    && Some(trace.terminal_sequence) == self.terminal_sequence
            })
            || self.shape.operation.returns()
            || self.nx_closed
        {
            return Err(LaunchError::Invalid(
                "runtime kernel terminal is not claimable",
            ));
        }
        self.claimed = true;
        Ok(OwnedRuntimeKernelTerminal { attempt: self })
    }
    fn binding(&self) -> &RuntimeKernelIdentity {
        self.identity.as_ref().expect("bound native attempt")
    }
    fn initial(&self) -> NativeCheckpoint<'_> {
        NativeCheckpoint {
            stop: self.initial.as_ref().expect("actual initial stop"),
            state: &self.states[BEFORE].state,
        }
    }
    fn opening(&self) -> [NativeCheckpoint<'_>; 3] {
        std::array::from_fn(|index| NativeCheckpoint {
            stop: self.stops[index].as_ref().expect("actual opening stop"),
            state: &self.states[BEFORE].state,
        })
    }
    fn syscall(&self, ordinal: usize) -> NativeSyscallCheckpoint<'_> {
        NativeSyscallCheckpoint {
            event: self.events[ordinal - ENTRY]
                .as_ref()
                .expect("actual syscall event"),
            state: &self.states[ordinal + 1].state,
            raw: self.raw_view(ordinal).expect("actual syscall wait"),
        }
    }
    fn pre_exit(&self) -> NativePreExitCheckpoint<'_> {
        NativePreExitCheckpoint {
            raw: self.raw_view(EXIT).expect("actual pre-exit wait"),
            state: &self.states[EXIT + 1].state,
            event_message: self.raw[EXIT].fixed.event_message,
            event_message_request: self.raw[EXIT]
                .fixed
                .event_message_request
                .expect("actual event message"),
        }
    }
}
pub(super) struct OwnedRuntimeKernelReturn<'a> {
    attempt: &'a PreparedRuntimeKernel,
}
impl<'a> OwnedRuntimeKernelReturn<'a> {
    pub(super) fn binding(&self) -> &'a RuntimeKernelIdentity {
        self.attempt.binding()
    }
    pub(super) fn logical_before(&self) -> NativeCheckpoint<'a> {
        self.attempt.initial()
    }
    pub(super) fn opening(&self) -> [NativeCheckpoint<'a>; 3] {
        self.attempt.opening()
    }
    pub(super) fn entry(&self) -> NativeSyscallCheckpoint<'a> {
        self.attempt.syscall(ENTRY)
    }
    pub(super) fn exit(&self) -> NativeSyscallCheckpoint<'a> {
        self.attempt.syscall(EXIT)
    }
    pub(super) fn bridge(&self) -> NativeCheckpoint<'a> {
        NativeCheckpoint {
            stop: self.attempt.stops[3].as_ref().expect("actual bridge"),
            state: &self.attempt.states[EXIT + 1].state,
        }
    }
    pub(super) fn closing(&self) -> [NativeCheckpoint<'a>; 3] {
        std::array::from_fn(|index| NativeCheckpoint {
            stop: self.attempt.stops[index + 4]
                .as_ref()
                .expect("actual closing stop"),
            state: &self.attempt.states[EXIT + 1].state,
        })
    }
    pub(super) fn trace(&self) -> NativeKernelReturnTrace {
        self.attempt.return_trace.expect("actual return trace")
    }
}
pub(super) struct OwnedRuntimeKernelTerminal<'a> {
    attempt: &'a PreparedRuntimeKernel,
}
impl<'a> OwnedRuntimeKernelTerminal<'a> {
    pub(super) fn binding(&self) -> &'a RuntimeKernelIdentity {
        self.attempt.binding()
    }
    pub(super) fn logical_before(&self) -> NativeCheckpoint<'a> {
        self.attempt.initial()
    }
    pub(super) fn opening(&self) -> [NativeCheckpoint<'a>; 3] {
        self.attempt.opening()
    }
    pub(super) fn entry(&self) -> NativeSyscallCheckpoint<'a> {
        self.attempt.syscall(ENTRY)
    }
    pub(super) fn pre_exit(&self) -> NativePreExitCheckpoint<'a> {
        self.attempt.pre_exit()
    }
    pub(super) fn exiting_event(&self) -> &'a DynamicEvent {
        self.attempt.events[1]
            .as_ref()
            .expect("actual exiting event")
    }
    pub(super) fn terminal_event(&self) -> &'a DynamicEvent {
        self.attempt.events[2]
            .as_ref()
            .expect("actual terminal event")
    }
    pub(super) fn trace(&self) -> NativeKernelTerminalTrace {
        self.attempt.terminal_trace.expect("actual terminal trace")
    }
}

fn add(left: usize, right: usize) -> Result<usize, LaunchError> {
    left.checked_add(right)
        .ok_or(LaunchError::Invalid("runtime kernel storage overflows"))
}
fn mul(left: usize, right: usize) -> Result<usize, LaunchError> {
    left.checked_mul(right)
        .ok_or(LaunchError::Invalid("runtime kernel storage overflows"))
}
fn fixed_buffer() -> Result<Box<[u8; MAP_BYTES]>, LaunchError> {
    let layout = std::alloc::Layout::new::<[u8; MAP_BYTES]>();
    let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
    if pointer.is_null() {
        return Err(LaunchError::Invalid(
            "runtime kernel fixed allocation failed",
        ));
    }
    // The exact initialized array allocation is owned immediately by one Box.
    Ok(unsafe { Box::from_raw(pointer.cast()) })
}
