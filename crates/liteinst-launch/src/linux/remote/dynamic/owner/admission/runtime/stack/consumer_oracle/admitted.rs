//! One original production operation per observed frame. All diagnostics are
//! installed under Q before any observation; this module creates no permits.
use super::{
    OracleError,
    artifact::{ArtifactPlan, PlannedKind},
    call_sink::{CallSink, SinkError},
    dataflow::{self, DataflowContract, FrameObservation},
    dispatch,
    observe::{DebugExpectation, LaneShape, PreparedLane},
};
use crate::linux::remote::dynamic::admission::{AdmissionReply, RuntimeProviderInput};
use crate::linux::remote::dynamic::owner::Owner;
use crate::linux::remote::dynamic::owner::admission::census::{
    CensusConsumerError, PreparedStackObservation, consumer_observation_temporary_bytes,
};
use crate::linux::remote::dynamic::owner::admission::runtime::{RuntimeOwner, RuntimeStage};
use crate::linux::remote::dynamic::owner::admission::runtime_capture::SourceWindowId;
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native;
use crate::{DynamicAdmissionEvent, RuntimeKernelProfile};
use std::{mem::size_of, time::Instant};
mod checkpoints;
mod selected;

const STEPS: usize = 35;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AdmittedShape {
    pub(super) stack_bytes: usize,
    pub(super) window_bytes: usize,
    pub(super) lane: LaneShape,
    pub(super) call_window: SourceWindowId,
    pub(super) initial_rsp: u64,
    pub(super) first_until: Instant,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdmittedBoundary {
    Returned {
        ordinal: usize,
        number: u64,
    },
    Terminal {
        status: crate::lifecycle::ExitStatus,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Empty,
    Ready,
    Allocating,
    Allocated,
    Metadata,
    Original,
    Dispatch,
    Provider,
    Completion,
    Snapshot,
    Comparison,
    Terminal,
    Complete,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct StepProgress {
    pub(super) until: Option<Instant>,
    pub(super) before: bool,
    pub(super) provider_started: bool,
    pub(super) provider_received: bool,
    pub(super) dispatch_started: bool,
    pub(super) dispatched: bool,
    pub(super) after: bool,
    pub(super) compared: bool,
    pub(super) history_start: Option<usize>,
    pub(super) attempt_before: Option<usize>,
    pub(super) snapshot: Option<usize>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Progress {
    pub(super) phase: Phase,
    pub(super) first_failure: Option<Phase>,
    pub(super) census_failure: Option<CensusConsumerError>,
    pub(super) sink_failure: Option<SinkError>,
    pub(super) allocation_started: bool,
    pub(super) allocated: bool,
    pub(super) initialized: bool,
    pub(super) next: usize,
    pub(super) segment: usize,
    pub(super) stack_copies: usize,
    pub(super) call_checks: usize,
}
/// Inline owners must be installed in root's Experiment before any method.
/// The response owners are moved from production, never cloned; their existing
/// producer debits are distinct from this component's new diagnostic payloads.
pub(super) struct PreparedAdmitted {
    pub(super) lane: PreparedLane,
    pub(super) snapshots: [PreparedStackObservation; 2],
    pub(super) sink: CallSink,
    ready: Option<AdmissionReply>,
    providers: [Option<Box<RuntimeProviderInput>>; 3],
    completions: [Option<AdmissionReply>; 3],
    shape: Option<AdmittedShape>,
    first_until: Option<Instant>,
    deadlines: [Option<Instant>; 3],
    steps: [StepProgress; STEPS],
    frame: Option<FrameObservation>,
    progress: Progress,
}
/// Borrowed partial data, including a reply whose validation failed. No
/// allocation, live task query or inferred completion occurs in this view.
pub(super) struct AdmittedView<'a> {
    pub(super) lane: &'a PreparedLane,
    pub(super) snapshots: &'a [PreparedStackObservation; 2],
    pub(super) sink: &'a CallSink,
    pub(super) providers: &'a [Option<Box<RuntimeProviderInput>>; 3],
    pub(super) completions: &'a [Option<AdmissionReply>; 3],
    pub(super) deadlines: &'a [Option<Instant>; 3],
    pub(super) progress: Progress,
}
fn require(value: bool, message: &'static str) -> Result<(), OracleError> {
    if value {
        Ok(())
    } else {
        Err(OracleError::Invalid(message))
    }
}
fn add(a: usize, b: usize) -> Result<usize, OracleError> {
    a.checked_add(b)
        .ok_or(OracleError::Invalid("admitted capacity overflow"))
}
fn payload(total: usize, header: usize) -> Result<usize, OracleError> {
    total
        .checked_sub(header)
        .ok_or(OracleError::Invalid("admitted header exceeds total"))
}
impl PreparedAdmitted {
    pub(super) fn empty() -> Self {
        Self {
            lane: PreparedLane::empty(),
            snapshots: std::array::from_fn(|_| PreparedStackObservation::empty()),
            sink: CallSink::empty(),
            ready: None,
            providers: std::array::from_fn(|_| None),
            completions: std::array::from_fn(|_| None),
            shape: None,
            first_until: None,
            deadlines: [None; 3],
            steps: [StepProgress::default(); STEPS],
            frame: None,
            progress: Progress {
                phase: Phase::Empty,
                first_failure: None,
                census_failure: None,
                sink_failure: None,
                allocation_started: false,
                allocated: false,
                initialized: false,
                next: 0,
                segment: 0,
                stack_copies: 0,
                call_checks: 0,
            },
        }
    }
    pub(super) fn partial_view(&self) -> AdmittedView<'_> {
        AdmittedView {
            lane: &self.lane,
            snapshots: &self.snapshots,
            sink: &self.sink,
            providers: &self.providers,
            completions: &self.completions,
            deadlines: &self.deadlines,
            progress: self.progress,
        }
    }
    fn outcome<T>(&mut self, value: Result<T, OracleError>) -> Result<T, OracleError> {
        if value.is_err() {
            self.progress
                .first_failure
                .get_or_insert(self.progress.phase);
        }
        value
    }
    fn census<T>(&mut self, value: Result<T, CensusConsumerError>) -> Result<T, OracleError> {
        value.map_err(|error| {
            self.progress.census_failure.get_or_insert(error);
            OracleError::Invalid("admitted census observation failed")
        })
    }
    fn sink_result<T>(&mut self, value: Result<T, SinkError>) -> Result<T, OracleError> {
        value.map_err(|error| {
            self.progress.sink_failure.get_or_insert(error);
            OracleError::Invalid("admitted CALL observation failed")
        })
    }
    pub(super) fn mark_aborted(&mut self) {
        self.progress
            .first_failure
            .get_or_insert(self.progress.phase);
        for snapshot in &mut self.snapshots {
            snapshot.mark_aborted();
        }
        if let Err(error) = self.sink.mark_aborted() {
            self.progress.sink_failure.get_or_insert(error);
        }
    }
    /// Caller moves the actual dispatch::invoke(StartRuntime) result here even
    /// when its variant is unexpected, before another fallible observation.
    pub(super) fn install_ready(
        &mut self,
        reply: AdmissionReply,
        until: Instant,
    ) -> Result<(), OracleError> {
        if self.ready.is_some() || self.first_until.is_some() {
            return Err(OracleError::Invalid("admitted Ready owner reused"));
        }
        self.ready = Some(reply);
        self.first_until = Some(until);
        self.deadlines[0] = Some(until);
        self.progress.phase = Phase::Ready;
        let result = require(
            matches!(&self.ready, Some(AdmissionReply::RuntimeReady(..))),
            "admitted startup did not return RuntimeReady",
        );
        self.outcome(result)
    }
    pub(super) fn shape(
        runtime: &RuntimeOwner,
        plan: &ArtifactPlan,
    ) -> Result<AdmittedShape, OracleError> {
        require(
            runtime.stage == RuntimeStage::Ready
                && runtime.ready_issued
                && runtime.kernel_profile == RuntimeKernelProfile::IdentityAndTermination
                && runtime.kernel_pending.is_none()
                && runtime.selected_pending.is_none()
                && runtime.ordinary_attempts.is_empty()
                && runtime.kernel_attempts.is_empty()
                && runtime.selected_attempts.is_empty()
                && runtime.pages.iter().all(|p| !p.executable),
            "admitted shape is not untouched production Ready",
        )?;
        let stack = runtime
            .stack
            .as_ref()
            .ok_or(OracleError::Invalid("admitted stack profile absent"))?;
        require(
            stack.startup_complete
                && stack.count == 0
                && stack.failure.is_none()
                && stack.settlement_failure.is_none(),
            "admitted initial stack profile incomplete",
        )?;
        let initial = stack.profile.identity()?;
        let description = initial.description();
        let stack_bytes = description
            .stack
            .end
            .checked_sub(description.stack.start)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(OracleError::Invalid("admitted stack extent differs"))?;
        let census = runtime
            .census
            .as_ref()
            .ok_or(OracleError::Invalid("admitted census absent"))?;
        let origin = runtime
            .initial_origin
            .ok_or(OracleError::Invalid("admitted current origin absent"))?;
        let before = census
            .current_observation(origin)
            .map_err(|_| OracleError::Invalid("admitted current observation absent"))?;
        require(
            before.logical_pc == plan.entry
                && before.registers.rip == plan.entry
                && before.registers.rsp == description.initial_rsp
                && census.active().count() == 1,
            "admitted initial PC or stack identity differs",
        )?;
        let call = plan.instruction(plan.call)?;
        require(
            call.kind() == PlannedKind::Call,
            "admitted CALL descriptor differs",
        )?;
        let page = runtime
            .pages
            .iter()
            .find(|p| p.address == (call.pc() & !4095))
            .ok_or(OracleError::Invalid("admitted CALL page absent"))?;
        let window = runtime
            .sources
            .window(page.window)
            .ok_or(OracleError::Invalid("admitted CALL source absent"))?;
        let offset = call
            .pc()
            .checked_sub(window.snapshot.range().start())
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(OracleError::Invalid("admitted CALL offset differs"))?;
        require(
            offset
                .checked_add(call.bytes().len())
                .and_then(|end| window.snapshot.bytes().get(offset..end))
                == Some(call.bytes()),
            "admitted CALL actual immutable bytes differ",
        )?;
        Ok(AdmittedShape {
            stack_bytes,
            window_bytes: window.snapshot.bytes().len(),
            lane: LaneShape::for_plan(plan, stack_bytes)?,
            call_window: window.id,
            initial_rsp: description.initial_rsp,
            first_until: runtime.until,
        })
    }
    /// Already charged by RuntimeOwner startup and moved inline in Ready.
    /// Root subtracts this once from its complete Experiment-header charge.
    pub(super) const fn producer_inline_bytes() -> usize {
        size_of::<crate::DynamicAdmissionState>()
    }
    pub(super) fn reservation_bytes(shape: AdmittedShape) -> Result<usize, OracleError> {
        let mut total = size_of::<Self>();
        total = add(
            total,
            payload(shape.lane.retained_bytes, size_of::<PreparedLane>())?,
        )?;
        let snapshot = PreparedStackObservation::reservation_bytes()
            .map_err(|_| OracleError::Invalid("admitted snapshot shape overflow"))?;
        for _ in 0..2 {
            total = add(
                total,
                payload(snapshot, size_of::<PreparedStackObservation>())?,
            )?;
        }
        let sink = CallSink::reservation_bytes(shape.window_bytes)
            .map_err(|_| OracleError::Invalid("admitted CALL shape overflow"))?;
        add(total, payload(sink, size_of::<CallSink>())?)
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize, OracleError> {
        let mut total = add(
            size_of::<Self>(),
            payload(self.lane.allocated_bytes()?, size_of::<PreparedLane>())?,
        )?;
        for snapshot in &self.snapshots {
            let bytes = snapshot
                .allocated_bytes()
                .map_err(|_| OracleError::Invalid("admitted snapshot tally differs"))?;
            total = add(
                total,
                payload(bytes, size_of::<PreparedStackObservation>())?,
            )?;
        }
        let sink = self
            .sink
            .allocated_bytes()
            .map_err(|_| OracleError::Invalid("admitted CALL tally differs"))?;
        add(total, payload(sink, size_of::<CallSink>())?)
    }
    pub(super) fn temporary_bytes(shape: AdmittedShape) -> Result<usize, OracleError> {
        let mut total = shape.lane.temporary_bytes;
        for bytes in [
            size_of::<Self>(),
            size_of::<AdmittedView<'_>>(),
            size_of::<AdmittedShape>(),
            size_of::<PreparedStackObservation>(),
            size_of::<AdmissionReply>(),
            size_of::<Option<AdmissionReply>>(),
            3 * size_of::<Progress>(),
            8 * size_of::<StepProgress>(),
            32 * size_of::<usize>(),
            checkpoints::temporary_bytes(),
            consumer_observation_temporary_bytes()
                .map_err(|_| OracleError::Invalid("admitted snapshot temporary overflow"))?,
            runtime_stack_native::consumer_oracle::temporary_bytes()?,
            CallSink::temporary_bytes()
                .map_err(|_| OracleError::Invalid("admitted CALL temporary overflow"))?,
        ] {
            total = add(total, bytes)?;
        }
        Ok(total)
    }
    /// Root must reserve Q before this call and settle its actual installed
    /// prefix on every Result/unwind. This method never finishes Q itself.
    pub(super) fn allocate_payloads(
        &mut self,
        shape: AdmittedShape,
        plan: &ArtifactPlan,
        owner: &Owner,
    ) -> Result<(), OracleError> {
        let result = (|| {
            require(
                !self.progress.allocation_started
                    && self.progress.first_failure.is_none()
                    && self.first_until == Some(shape.first_until),
                "admitted allocation reused or deadline differs",
            )?;
            let runtime = owner
                .runtime
                .as_ref()
                .ok_or(OracleError::Invalid("admitted owner runtime absent"))?;
            require(
                shape == Self::shape(runtime, plan)?,
                "admitted supplied allocation shape differs",
            )?;
            Self::reservation_bytes(shape)?;
            self.progress.allocation_started = true;
            self.progress.phase = Phase::Allocating;
            self.shape = Some(shape);
            self.lane.allocate_metadata()?;
            self.lane.allocate_frames(plan, shape.lane)?;
            for index in 0..2 {
                let allocated = self.snapshots[index].allocate_payloads();
                self.census(allocated)?;
            }
            let installed = self.sink.install(shape.window_bytes, owner);
            self.sink_result(installed)?;
            require(
                self.allocated_bytes()? == Self::reservation_bytes(shape)?,
                "admitted actual allocation differs from Q",
            )?;
            self.progress.allocated = true;
            self.progress.phase = Phase::Allocated;
            Ok(())
        })();
        self.outcome(result)
    }
    /// Only after Q has been settled/finished. Real metadata/access/pagemap
    /// eligibility precedes the first whole-stack observation; no seed exists.
    pub(super) fn initialize(
        &mut self,
        owner: &Owner,
        plan: &ArtifactPlan,
        file: &[u8],
        until: Instant,
    ) -> Result<(), OracleError> {
        let result = (|| {
            require(
                self.progress.allocated
                    && !self.progress.initialized
                    && self.progress.first_failure.is_none()
                    && self.first_until == Some(until),
                "admitted initialization phase or original deadline differs",
            )?;
            owner.time_left(until, "admitted initial diagnostics")?;
            self.progress.phase = Phase::Metadata;
            self.lane
                .capture_metadata(owner, plan, file, DebugExpectation::Initial, until)?;
            let shape = self
                .shape
                .ok_or(OracleError::Invalid("admitted shape absent"))?;
            require(
                self.lane.observed_shape(plan)? == shape.lane
                    && self.lane.metadata.state.state.registers.rsp == shape.initial_rsp,
                "admitted actual metadata differs from reserved shape",
            )?;
            let Some(AdmissionReply::RuntimeReady(ready, _)) = &self.ready else {
                return Err(OracleError::Invalid("admitted RuntimeReady absent"));
            };
            let state = &self.lane.metadata.state.state;
            require(
                ready.registers == state.registers
                    && ready.xstate == state.xstate
                    && ready.signal_mask == state.mask,
                "admitted actual initial state differs from Ready",
            )?;
            self.frame = Some(dataflow::require_frame(plan, state)?);
            checkpoints::require_current(owner, state, Some(ready.task))?;
            self.progress.initialized = true;
            Ok(())
        })();
        self.outcome(result)
    }
    pub(super) fn run_segment(
        &mut self,
        owner: &mut Owner,
        plan: &ArtifactPlan,
        until: Instant,
    ) -> Result<AdmittedBoundary, OracleError> {
        let result = self.segment(owner, plan, until);
        self.outcome(result)
    }
    fn segment(
        &mut self,
        owner: &mut Owner,
        plan: &ArtifactPlan,
        until: Instant,
    ) -> Result<AdmittedBoundary, OracleError> {
        require(
            self.progress.initialized
                && self.progress.first_failure.is_none()
                && self.progress.segment < 3,
            "admitted segment phase differs",
        )?;
        let segment = self.progress.segment;
        if segment == 0 {
            require(
                self.deadlines[0] == Some(until),
                "admitted first absolute deadline changed",
            )?;
        } else {
            require(
                self.deadlines[segment].is_none(),
                "admitted segment deadline reused",
            )?;
            self.deadlines[segment] = Some(until);
        }
        loop {
            owner.time_left(until, "admitted closed-path step")?;
            let ordinal = self.progress.next;
            let instruction = plan.instruction(ordinal)?;
            require(
                ordinal < STEPS && self.steps[ordinal] == StepProgress::default(),
                "admitted step reused",
            )?;
            self.steps[ordinal].until = Some(until);
            self.progress.phase = Phase::Original;
            self.lane.capture(
                owner,
                plan,
                ordinal,
                false,
                if ordinal == 0 {
                    DebugExpectation::Initial
                } else {
                    DebugExpectation::Trace
                },
                until,
            )?;
            self.steps[ordinal].before = true;
            checkpoints::require_current(
                owner,
                &self.lane.frame(ordinal, false)?.state.state,
                None,
            )?;
            match instruction.kind() {
                PlannedKind::Ordinary | PlannedKind::Call | PlannedKind::Ret => {
                    let is_stack =
                        matches!(instruction.kind(), PlannedKind::Call | PlannedKind::Ret);
                    if is_stack {
                        let (history, count) = checkpoints::before_stack(owner)?;
                        self.steps[ordinal].history_start = Some(history);
                        self.steps[ordinal].attempt_before = Some(count);
                    }
                    self.progress.phase = Phase::Dispatch;
                    self.steps[ordinal].dispatch_started = true;
                    dispatch::run_one(owner, instruction, until)?;
                    self.steps[ordinal].dispatched = true;
                    if is_stack {
                        self.progress.phase = Phase::Snapshot;
                        let index = usize::from(instruction.kind() == PlannedKind::Ret);
                        require(
                            index == self.progress.stack_copies,
                            "admitted stack copy order differs",
                        )?;
                        let copied = checkpoints::copy(
                            owner,
                            plan,
                            ordinal,
                            self.steps[ordinal],
                            self.shape
                                .ok_or(OracleError::Invalid("admitted shape absent"))?,
                            &mut self.snapshots[index],
                        );
                        self.census(copied)?;
                        self.steps[ordinal].snapshot = Some(index);
                        self.progress.stack_copies += 1;
                        self.require_call(owner)?;
                    }
                    self.lane.capture(
                        owner,
                        plan,
                        ordinal,
                        true,
                        DebugExpectation::Trace,
                        until,
                    )?;
                    self.steps[ordinal].after = true;
                    checkpoints::require_current(
                        owner,
                        &self.lane.frame(ordinal, true)?.state.state,
                        None,
                    )?;
                    self.progress.phase = Phase::Comparison;
                    self.lane.require_transition(
                        plan,
                        ordinal,
                        self.frame
                            .ok_or(OracleError::Invalid("admitted ABI frame absent"))?,
                    )?;
                    self.steps[ordinal].compared = true;
                    self.progress.next += 1;
                }
                PlannedKind::Syscall { number } => {
                    return self.selected(owner, plan, ordinal, number, until);
                }
            }
        }
    }
    fn require_call(&mut self, owner: &Owner) -> Result<(), OracleError> {
        let check = checkpoints::require_call(owner, &self.sink);
        match check {
            Ok(()) => {
                self.progress.call_checks += 1;
                Ok(())
            }
            Err(CheckFailure::Sink(error)) => self.sink_result(Err(error)),
            Err(CheckFailure::Census(error)) => self.census(Err(error)),
        }
    }
    /// Immutable comparisons remain valid after actual cleanup. Incomplete
    /// snapshots stay available through partial_view and never become complete.
    pub(super) fn require_retained(&self, owner: &Owner) -> Result<(), OracleError> {
        let runtime = owner
            .runtime
            .as_ref()
            .ok_or(OracleError::Invalid("admitted retained runtime absent"))?;
        let census = runtime
            .census
            .as_ref()
            .ok_or(OracleError::Invalid("admitted retained census absent"))?;
        for snapshot in &self.snapshots {
            if snapshot.progress().1.complete {
                census
                    .require_stack_consumer_observation(snapshot, &runtime.sources)
                    .map_err(|_| {
                        OracleError::Invalid("admitted immutable stack history changed")
                    })?;
            }
        }
        if self
            .sink
            .progress()
            .map_err(|_| OracleError::Invalid("admitted sink unavailable"))?
            .callback_complete
        {
            checkpoints::require_call(owner, &self.sink)
                .map_err(|_| OracleError::Invalid("admitted immutable CALL row changed"))?;
        }
        Ok(())
    }
    pub(super) fn require_complete(
        &self,
        owner: &Owner,
        plan: &ArtifactPlan,
        contract: &DataflowContract,
    ) -> Result<(), OracleError> {
        require(
            self.progress.phase == Phase::Complete
                && self.progress.first_failure.is_none()
                && self.progress.segment == 3
                && self.progress.next == plan.len()
                && self.progress.stack_copies == 2
                && self.progress.call_checks == 3,
            "admitted full path incomplete",
        )?;
        for (ordinal, step) in self.steps[..plan.len()].iter().enumerate() {
            require(
                step.before
                    && step.dispatch_started
                    && step.dispatched
                    && step.compared
                    && step.provider_started
                        == matches!(
                            plan.instruction(ordinal)?.kind(),
                            PlannedKind::Syscall { .. }
                        )
                    && step.provider_received == step.provider_started
                    && step.after == (ordinal != plan.syscalls[2])
                    && step.until
                        == self.deadlines[plan
                            .syscalls
                            .iter()
                            .position(|&end| ordinal <= end)
                            .ok_or(OracleError::Invalid("admitted step outside segments"))?],
                "admitted retained step or segment deadline differs",
            )?;
        }
        for snapshot in &self.snapshots {
            let (allocation, capture) = snapshot.progress();
            require(
                allocation.complete
                    && allocation.first_failure.is_none()
                    && capture.complete
                    && capture.first_failure.is_none(),
                "admitted stack copy incomplete",
            )?;
        }
        let runtime = owner
            .runtime
            .as_ref()
            .ok_or(OracleError::Invalid("admitted completed runtime absent"))?;
        require(
            runtime.ordinary_attempts.len()
                == plan
                    .instructions()
                    .filter(|i| i.kind() == PlannedKind::Ordinary)
                    .count()
                && runtime.kernel_attempts.len() == 3
                && runtime.selected_attempts.is_empty()
                && runtime.stack.as_ref().is_some_and(|stack| stack.count == 2),
            "admitted actual production attempt counts differ",
        )?;
        self.require_retained(owner)?;
        self.lane.require_complete(
            plan,
            contract,
            self.frame
                .ok_or(OracleError::Invalid("admitted frame absent"))?,
            owner.pid,
        )?;
        selected::require_replies(self, owner, plan)
    }
}
enum CheckFailure {
    Sink(SinkError),
    Census(CensusConsumerError),
}
