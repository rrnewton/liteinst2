//! Non-default finite consumer observer. It uses the real production owner,
//! preserves independent raw/admitted runs, and cannot create execution permits.
use super::*;
use crate::{DynamicRuntimeOptions, RuntimeKernelProfile, RuntimeStackProfile};
use std::process::ExitCode;

mod admitted;
mod artifact;
mod call_sink;
mod custody;
mod dataflow;
mod dispatch;
mod journal;
mod native_checks;
mod observe;
mod output;
mod owner;
mod prefix;
mod protocol;
mod raw;
mod storage;

use crate::linux::remote::dynamic::owner::admission::census::CensusConsumerError;
use crate::linux::remote::dynamic::owner::kernel_journal::{
    JournalWriterTransition, PreparedKernelObservation,
};
use admitted::{AdmittedBoundary, PreparedAdmitted};
use artifact::{ArtifactPlan, PinnedArtifact};
use custody::{Custody, Step};
use dataflow::DataflowContract;
use owner::ArtifactOwner;
use prefix::PrefixMirrors;
use protocol::{Digest, Input, Mode, Row};
use raw::{PreparedRawLane, RawBoundary};
use storage::ObserverReservation;

#[derive(Debug)]
enum OracleError {
    Invalid(&'static str),
    Io {
        operation: &'static str,
        errno: Option<i32>,
    },
    Launch(LaunchError),
    Gate(GateError),
    Sink(call_sink::SinkError),
    Observer(CensusConsumerError),
}
impl From<LaunchError> for OracleError {
    fn from(value: LaunchError) -> Self {
        Self::Launch(value)
    }
}
impl From<GateError> for OracleError {
    fn from(value: GateError) -> Self {
        Self::Gate(value)
    }
}
impl From<call_sink::SinkError> for OracleError {
    fn from(value: call_sink::SinkError) -> Self {
        Self::Sink(value)
    }
}
impl From<CensusConsumerError> for OracleError {
    fn from(value: CensusConsumerError) -> Self {
        Self::Observer(value)
    }
}
impl From<std::fmt::Error> for OracleError {
    fn from(_: std::fmt::Error) -> Self {
        Self::Invalid("oracle output exceeds fixed row")
    }
}
impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::Io { operation, errno } => write!(f, "{operation}: errno {errno:?}"),
            Self::Launch(error) => write!(f, "{error}"),
            Self::Gate(error) => write!(f, "{error}"),
            Self::Sink(error) => write!(f, "CALL observer: {error:?}"),
            Self::Observer(error) => write!(f, "prefix observer: {error:?}"),
        }
    }
}
impl std::error::Error for OracleError {}

/// All owners are installed before their first fallible operation. Q includes
/// this whole header and every newly retained payload; only already-charged
/// production owners/moved replies have the precise exclusions in storage.rs.
struct Experiment {
    input: Input,
    file: PinnedArtifact,
    file_digest: Option<Digest>,
    file_bytes: Option<usize>,
    plan_digest: Option<Digest>,
    plan: Option<ArtifactPlan>,
    contract: Option<DataflowContract>,
    raw_owner: ArtifactOwner,
    raw: PreparedRawLane,
    raw_until: Option<Instant>,
    raw_boundaries: [Option<RawBoundary>; 3],
    raw_retained_before: Option<usize>,
    raw_retained_after: Option<usize>,
    admitted_owner: ArtifactOwner,
    admitted: PreparedAdmitted,
    admitted_until: Option<Instant>,
    admitted_boundaries: [Option<AdmittedBoundary>; 3],
    prefix: PrefixMirrors,
    journal: PreparedKernelObservation,
    journal_transition: Option<JournalWriterTransition>,
    reservation: ObserverReservation,
    custody: Custody,
    row: Row,
}

impl Experiment {
    fn empty() -> Self {
        Self {
            input: Input::empty(),
            file: PinnedArtifact::empty(),
            file_digest: None,
            file_bytes: None,
            plan_digest: None,
            plan: None,
            contract: None,
            raw_owner: ArtifactOwner::empty(),
            raw: PreparedRawLane::empty(),
            raw_until: None,
            raw_boundaries: [None; 3],
            raw_retained_before: None,
            raw_retained_after: None,
            admitted_owner: ArtifactOwner::empty(),
            admitted: PreparedAdmitted::empty(),
            admitted_until: None,
            admitted_boundaries: [None; 3],
            prefix: PrefixMirrors::empty(),
            journal: PreparedKernelObservation::empty(),
            journal_transition: None,
            reservation: ObserverReservation::empty(),
            custody: Custody::empty(),
            row: Row::empty(),
        }
    }

    fn step(
        &mut self,
        step: Step,
        body: impl FnOnce(&mut Self) -> Result<(), OracleError>,
    ) -> bool {
        if !self.custody.begin(step) {
            return false;
        }
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self)));
        if observed.is_err() {
            match step {
                Step::StackPrefix0Capture => self.prefix.stack[0].mark_aborted(),
                Step::StackPrefix1Capture => self.prefix.stack[1].mark_aborted(),
                Step::CallPrefixCapture => self.prefix.call.mark_aborted(),
                Step::JournalBeforeCleanup | Step::JournalRetention => self.journal.mark_aborted(),
                _ => {}
            }
        }
        self.custody.finish(step, observed)
    }

    fn artifact(&mut self) -> Result<(), OracleError> {
        self.file.open_in_place(self.input.path()?)?;
        let bytes = self.file.bytes()?;
        self.file_bytes = Some(bytes.len());
        self.file_digest = Some(Digest::file(bytes));
        if self.file_digest != self.input.expected_file() {
            return Err(OracleError::Invalid("oracle full artifact digest differs"));
        }
        Ok(())
    }

    fn plan(&mut self) -> Result<(), OracleError> {
        self.plan = Some(artifact::inspect_artifact(&self.file)?);
        let plan = self
            .plan
            .as_ref()
            .ok_or(OracleError::Invalid("oracle plan missing"))?;
        self.contract = Some(dataflow::prove_dataflow(plan)?);
        self.plan_digest = Some(Digest::plan(
            plan,
            self.file_digest
                .ok_or(OracleError::Invalid("oracle file digest missing"))?,
        )?);
        if self.input.mode()? == Mode::Run && self.plan_digest != self.input.expected_plan() {
            return Err(OracleError::Invalid("oracle actual plan digest differs"));
        }
        Ok(())
    }

    fn raw_launch(&mut self) -> Result<(), OracleError> {
        // This one deadline includes launch, metadata, allocation, entry bridge
        // and all original instructions through the first selected return.
        let until = deadline()?;
        self.raw_until = Some(until);
        self.raw_owner.launch_in_place(&self.file, until)
    }

    fn raw_execution(&mut self) -> Result<(), OracleError> {
        let first = self
            .raw_until
            .ok_or(OracleError::Invalid("raw deadline missing"))?;
        let plan = self
            .plan
            .as_ref()
            .ok_or(OracleError::Invalid("raw plan missing"))?;
        let contract = self
            .contract
            .as_ref()
            .ok_or(OracleError::Invalid("raw proof missing"))?;
        self.raw.allocate_metadata()?;
        let (owner, initial) = self.raw_owner.owner_and_initial()?;
        let shape = self
            .raw
            .capture_initial(owner, &initial.event, plan, &self.file, first)?;
        self.raw.allocate_remainder(plan, shape)?;
        if self.raw.allocated_bytes()? != PreparedRawLane::reservation_bytes(shape)? {
            return Err(OracleError::Invalid(
                "raw actual allocation differs from fixed shape",
            ));
        }
        self.raw.initialize(owner, &initial.event, plan, first)?;
        for index in 0..3 {
            // Only a completed real selected return reaches the next deadline.
            let until = if index == 0 { first } else { deadline()? };
            let actual = raw::run_segment(owner, &mut self.raw, plan, until)?;
            self.raw_boundaries[index] = Some(actual);
            match (index, actual) {
                (0 | 1, RawBoundary::Returned { ordinal, number })
                    if ordinal == plan.syscalls[index] && number == [39, 186][index] => {}
                (2, RawBoundary::Terminal { status }) if status == 7 << 8 => {}
                _ => return Err(OracleError::Invalid("raw real selected boundary differs")),
            }
        }
        raw::require_complete(&self.raw, plan, contract)
    }

    fn raw_epilogue(&mut self) {
        if !self.custody.outcome(Step::RawExecution).succeeded() {
            self.step(Step::RawAborted, |this| {
                this.raw.mark_aborted();
                Ok(())
            });
        }
        self.step(Step::RawBeforeCleanup, |this| {
            this.raw_retained_before = Some(this.raw.allocated_bytes()?);
            Ok(())
        });
        // Each step executes independently; a failure never suppresses an
        // attempted physical drain, retained-prefix check or mask restoration.
        self.step(Step::RawCleanup, |this| this.raw_owner.finish());
        self.step(Step::RawRetention, |this| {
            this.raw_retained_after = Some(this.raw.allocated_bytes()?);
            if this.raw_retained_after != this.raw_retained_before {
                return Err(OracleError::Invalid(
                    "raw retained allocation changed during cleanup",
                ));
            }
            if this.custody.outcome(Step::RawExecution).succeeded() {
                this.raw_owner.cleanup()?;
                raw::require_complete(
                    &this.raw,
                    this.plan
                        .as_ref()
                        .ok_or(OracleError::Invalid("raw retained plan missing"))?,
                    this.contract
                        .as_ref()
                        .ok_or(OracleError::Invalid("raw retained proof missing"))?,
                )?;
            }
            Ok(())
        });
        self.step(Step::RawMask, |this| this.raw_owner.restore_mask());
    }

    fn admitted_launch(&mut self) -> Result<(), OracleError> {
        let until = deadline()?;
        self.admitted_until = Some(until);
        self.admitted_owner.launch_in_place(&self.file, until)
    }

    fn admitted_start(&mut self) -> Result<(), OracleError> {
        let until = self
            .admitted_until
            .ok_or(OracleError::Invalid("admitted deadline missing"))?;
        let initial = self
            .admitted_owner
            .initial()?
            .event
            .stop_token()
            .ok_or(OracleError::Invalid("admitted original stop missing"))?
            .clone();
        let reply = dispatch::invoke(
            self.admitted_owner.owner()?,
            AdmissionRequest::StartRuntime {
                initial,
                options: DynamicRuntimeOptions {
                    kernel: RuntimeKernelProfile::IdentityAndTermination,
                    stack: RuntimeStackProfile::OriginalResidentWord,
                    ..DynamicRuntimeOptions::default()
                },
            },
            until,
        )?;
        // Move the genuine response before any fallible variant/shape check.
        self.admitted.install_ready(reply, until)
    }

    fn admitted_execution(&mut self) -> Result<(), OracleError> {
        let first = self
            .admitted_until
            .ok_or(OracleError::Invalid("admitted deadline missing"))?;
        let plan = self
            .plan
            .as_ref()
            .ok_or(OracleError::Invalid("admitted plan missing"))?;
        let contract = self
            .contract
            .as_ref()
            .ok_or(OracleError::Invalid("admitted proof missing"))?;
        // No producer reservation may intervene between this real Q check and
        // observer initialization. The callback itself never reserves or grows.
        self.reservation.require_finished()?;
        let owner = self.admitted_owner.owner()?;
        let runtime = owner
            .runtime
            .as_mut()
            .ok_or(OracleError::Invalid("admitted runtime missing"))?;
        let stack = runtime
            .stack
            .as_mut()
            .ok_or(OracleError::Invalid("admitted stack missing"))?;
        if stack.before_opening.is_some() {
            return Err(OracleError::Invalid(
                "admitted CALL observer already installed",
            ));
        }
        stack.before_opening = Some(call_sink::before_opening);
        self.admitted
            .initialize(owner, plan, self.file.bytes()?, first)?;
        for index in 0..3 {
            let until = if index == 0 { first } else { deadline()? };
            let actual = self.admitted.run_segment(owner, plan, until)?;
            self.admitted_boundaries[index] = Some(actual);
            match (index, actual) {
                (0 | 1, AdmittedBoundary::Returned { ordinal, number })
                    if ordinal == plan.syscalls[index] && number == [39, 186][index] => {}
                (
                    2,
                    AdmittedBoundary::Terminal {
                        status: crate::lifecycle::ExitStatus::Code(7),
                    },
                ) => {}
                _ => {
                    return Err(OracleError::Invalid(
                        "admitted real selected boundary differs",
                    ));
                }
            }
        }
        self.admitted.require_complete(owner, plan, contract)?;
        native_checks::require_complete(self)
    }

    fn admitted_epilogue(&mut self) {
        if !self.custody.outcome(Step::AdmittedExecution).succeeded() {
            self.step(Step::AdmittedAborted, |this| {
                this.admitted.mark_aborted();
                Ok(())
            });
            self.step(Step::AdmittedSeal, |this| {
                use crate::linux::remote::dynamic::owner::kernel_journal::{
                    self, KernelFailureKind,
                };
                let failure = this.custody.first_outcome();
                let owner = this.admitted_owner.owner()?;
                match failure {
                    Some(custody::Outcome::Returned(Err(OracleError::Gate(error)))) => {
                        owner.kernel_journal.fail_gate(error)
                    }
                    Some(custody::Outcome::Returned(Err(OracleError::Launch(error)))) => owner
                        .kernel_journal
                        .fail_active(kernel_journal::failure_kind(error)),
                    Some(custody::Outcome::Returned(Err(OracleError::Io { errno, .. }))) => owner
                        .kernel_journal
                        .fail_active(KernelFailureKind::NativeIo(*errno)),
                    Some(custody::Outcome::Unwound(_)) => owner
                        .kernel_journal
                        .fail_active(KernelFailureKind::CaughtPanic),
                    _ => owner
                        .kernel_journal
                        .fail_active(KernelFailureKind::AdmissionRejected),
                }
                owner.closing = true;
                owner.cancel.store(true, Ordering::Release);
                Ok(())
            });
        }
        // Independent captures preserve partial observers before physical
        // cleanup. A failure or panic in one never suppresses the other two.
        self.step(Step::StackPrefix0Capture, |this| {
            this.prefix.stack[0]
                .capture(&this.admitted.snapshots[0])
                .map_err(Into::into)
        });
        self.step(Step::StackPrefix1Capture, |this| {
            this.prefix.stack[1]
                .capture(&this.admitted.snapshots[1])
                .map_err(Into::into)
        });
        self.step(Step::CallPrefixCapture, |this| {
            this.admitted
                .sink
                .with_snapshot(|value| this.prefix.call.capture(value))??;
            Ok(())
        });
        // A failed body is sealed above before this immutable history copy, so
        // cleanup cannot replace its original failure with generic cancellation.
        self.step(Step::JournalBeforeCleanup, |this| {
            this.journal
                .capture(&this.admitted_owner.owner_ref()?.kernel_journal)
                .map_err(Into::into)
        });
        self.step(Step::AdmittedCleanup, |this| this.admitted_owner.finish());
        self.step(Step::AdmittedRetention, |this| {
            if this.admitted_owner.owner_ref()?.runtime.is_some() {
                this.admitted
                    .require_retained(this.admitted_owner.owner_ref()?)?;
            }
            if this.custody.outcome(Step::AdmittedExecution).succeeded() {
                this.admitted_owner.cleanup()?;
                this.admitted.require_complete(
                    this.admitted_owner.owner_ref()?,
                    this.plan
                        .as_ref()
                        .ok_or(OracleError::Invalid("admitted retained plan missing"))?,
                    this.contract
                        .as_ref()
                        .ok_or(OracleError::Invalid("admitted retained proof missing"))?,
                )?;
                native_checks::require_complete(this)?;
            }
            Ok(())
        });
        self.step(Step::StackPrefix0Retention, |this| {
            this.prefix.stack[0]
                .require_preserved(&this.admitted.snapshots[0])
                .map_err(Into::into)
        });
        self.step(Step::StackPrefix1Retention, |this| {
            this.prefix.stack[1]
                .require_preserved(&this.admitted.snapshots[1])
                .map_err(Into::into)
        });
        self.step(Step::CallPrefixRetention, |this| {
            this.admitted
                .sink
                .with_snapshot(|value| this.prefix.call.require_preserved(value))??;
            Ok(())
        });
        self.step(Step::JournalRetention, |this| {
            let transition = this
                .journal
                .require_retained(&this.admitted_owner.owner_ref()?.kernel_journal)?;
            // Preserve the real transition, including FailedCleanup, before
            // deciding whether this lane can qualify as a successful run.
            this.journal_transition = Some(transition);
            if this.custody.outcome(Step::AdmittedExecution).succeeded() {
                journal::require_complete(this)?;
            }
            Ok(())
        });
        self.step(Step::SinkRetirement, |this| {
            this.admitted
                .sink
                .retire_after_cleanup(&this.admitted_owner)
                .map_err(Into::into)
        });
        self.step(Step::CallRetirementRetention, |this| {
            this.admitted
                .sink
                .with_snapshot(|value| this.prefix.call.require_preserved(value))??;
            Ok(())
        });
        self.step(Step::AdmittedMask, |this| {
            this.admitted_owner.restore_mask()
        });
    }

    fn compare(&self) -> Result<(), OracleError> {
        let plan = self
            .plan
            .as_ref()
            .ok_or(OracleError::Invalid("comparison plan missing"))?;
        let contract = self
            .contract
            .as_ref()
            .ok_or(OracleError::Invalid("comparison proof missing"))?;
        self.reservation.require_finished()?;
        self.raw_owner.cleanup()?;
        self.admitted_owner.cleanup()?;
        raw::require_complete(&self.raw, plan, contract)?;
        self.admitted
            .require_complete(self.admitted_owner.owner_ref()?, plan, contract)?;
        journal::require_complete(self)?;
        native_checks::require_complete(self)?;
        self.prefix.require_complete()?;
        self.prefix.stack[0].require_preserved(&self.admitted.snapshots[0])?;
        self.prefix.stack[1].require_preserved(&self.admitted.snapshots[1])?;
        self.admitted
            .sink
            .with_snapshot(|value| self.prefix.call.require_preserved(value))??;
        // Own-lane exact equations establish the comparison. Absolute PIDs,
        // register addresses and stacks from different launches are never equated.
        for index in 0..3 {
            match (self.raw_boundaries[index], self.admitted_boundaries[index]) {
                (
                    Some(RawBoundary::Returned {
                        ordinal: a,
                        number: n,
                    }),
                    Some(AdmittedBoundary::Returned {
                        ordinal: b,
                        number: m,
                    }),
                ) if a == b && n == m && index < 2 && a == plan.syscalls[index] => {}
                (
                    Some(RawBoundary::Terminal { status }),
                    Some(AdmittedBoundary::Terminal {
                        status: crate::lifecycle::ExitStatus::Code(7),
                    }),
                ) if index == 2 && status == 7 << 8 => {}
                _ => return Err(OracleError::Invalid("independent lane structure differs")),
            }
        }
        Ok(())
    }

    fn run(&mut self) {
        let parsed = self.step(Step::Arguments, |this| {
            this.input.capture(std::env::args_os())
        });
        if parsed && matches!(self.input.mode(), Ok(Mode::Protocol)) {
            self.step(Step::Output, output::protocol);
            return;
        }
        if parsed
            && self.step(Step::Artifact, Self::artifact)
            && self.step(Step::Plan, Self::plan)
            && matches!(self.input.mode(), Ok(Mode::Run))
        {
            let launched = self.step(Step::RawLaunch, Self::raw_launch);
            if launched {
                self.step(Step::RawExecution, Self::raw_execution);
            }
            self.raw_epilogue();
            if !self.custody.failed() {
                if self.step(Step::AdmittedLaunch, Self::admitted_launch)
                    && self.step(Step::AdmittedStart, Self::admitted_start)
                    && self.step(Step::AdmittedAllocation, |this| {
                        this.prepare_observer(
                            this.admitted_until
                                .ok_or(OracleError::Invalid("admitted deadline missing"))?,
                        )
                    })
                {
                    self.step(Step::AdmittedExecution, Self::admitted_execution);
                }
                self.admitted_epilogue();
                if !self.custody.failed() {
                    self.step(Step::Comparison, |this| this.compare());
                }
            }
        }
        if self.file.bytes().is_ok() {
            self.step(Step::FinalArtifact, |this| this.file.verify());
        }
        self.step(Step::ArtifactClose, |this| this.file.close_in_place());
        self.step(Step::Output, output::result);
    }

    fn cleanup_known(&self) -> bool {
        let raw = self.raw_owner.partial_view();
        let admitted = self.admitted_owner.partial_view();
        (!raw.launch_started || raw.cleanup_complete)
            && (!admitted.launch_started || admitted.cleanup_complete)
            && (!admitted.launch_started || self.custody.outcome(Step::SinkRetirement).succeeded())
    }
}

fn deadline() -> Result<Instant, OracleError> {
    Instant::now()
        .checked_add(Duration::from_secs(3))
        .ok_or(OracleError::Invalid("oracle original deadline overflows"))
}

pub(super) fn run() -> ExitCode {
    let mut experiment = Experiment::empty();
    experiment.run();
    // Unknown physical/sink custody is fail-stop only after all independent
    // epilogues and the bounded observation attempt. No false successful exit.
    if !experiment.cleanup_known() {
        std::process::abort();
    }
    if let Some(payload) = experiment.custody.take_primary_unwind() {
        std::panic::resume_unwind(payload);
    }
    if experiment.custody.failed() {
        if let Some(custody::Outcome::Returned(Err(error))) = experiment.custody.first_outcome() {
            write_failure_diagnostic(error);
        }
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

// Only static messages/operations and numeric errno are projected. Never
// format the dynamic error, its payload, a path, a PID or a native address.
fn failure_reason(error: &OracleError) -> (&'static str, &'static str, Option<i32>) {
    match error {
        OracleError::Invalid(reason) => ("invalid", reason, None),
        OracleError::Io { operation, errno } => ("io", operation, *errno),
        OracleError::Launch(LaunchError::Invalid(reason)) => ("launch_invalid", reason, None),
        OracleError::Launch(LaunchError::System { operation, source }) => {
            ("launch_system", operation, source.raw_os_error())
        }
        OracleError::Launch(LaunchError::Timeout(operation)) => ("launch_timeout", operation, None),
        OracleError::Launch(LaunchError::Child { .. }) => ("launch_child", "child failure", None),
        OracleError::Gate(GateError::Control(LaunchError::Invalid(reason))) => {
            ("gate_control_invalid", reason, None)
        }
        OracleError::Gate(GateError::Control(LaunchError::System { operation, source })) => {
            ("gate_control_system", operation, source.raw_os_error())
        }
        OracleError::Gate(GateError::Control(LaunchError::Timeout(operation))) => {
            ("gate_control_timeout", operation, None)
        }
        OracleError::Gate(GateError::Control(LaunchError::Child { .. })) => {
            ("gate_control_child", "child failure", None)
        }
        OracleError::Gate(GateError::Refused(reason)) => ("gate_refused", reason, None),
        OracleError::Gate(GateError::Coverage(_)) => ("gate_coverage", "coverage refusal", None),
        OracleError::Gate(GateError::Scan(_)) => ("gate_scan", "scan refusal", None),
        OracleError::Gate(GateError::Core(_)) => ("gate_core", "core refusal", None),
        OracleError::Gate(GateError::Selected(_)) => ("gate_selected", "selected refusal", None),
        OracleError::Sink(_) => ("sink", "CALL observer refusal", None),
        OracleError::Observer(_) => ("observer", "census observer refusal", None),
    }
}

fn diagnostic_iovec(bytes: &[u8]) -> libc::iovec {
    libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    }
}

// Called only for the original retained returned error after physical cleanup
// is known and primary unwind handling has run. One best-effort write cannot
// replace that error, change the typed stdout row, or make this run successful.
fn write_failure_diagnostic(error: &OracleError) {
    let (class, reason, errno) = failure_reason(error);
    let reason = if reason.len() <= 256 && reason.bytes().all(|byte| matches!(byte, b' '..=b'~')) {
        reason
    } else {
        "static reason is outside diagnostic bound"
    };
    let mut number = [0_u8; 12];
    let errno_bytes: &[u8] = match errno {
        Some(value) => {
            // unsigned_abs handles i32::MIN without signed overflow. At most
            // ten decimal digits and one minus sign occupy this twelve-byte buffer.
            let mut magnitude = value.unsigned_abs();
            let mut at = number.len();
            loop {
                at -= 1;
                number[at] = b'0' + (magnitude % 10) as u8;
                magnitude /= 10;
                if magnitude == 0 {
                    break;
                }
            }
            if value < 0 {
                at -= 1;
                number[at] = b'-';
            }
            &number[at..]
        }
        None => b"none",
    };
    let vectors = [
        diagnostic_iovec(b"runtime-stack-consumer failure "),
        diagnostic_iovec(class.as_bytes()),
        diagnostic_iovec(b": "),
        diagnostic_iovec(reason.as_bytes()),
        diagnostic_iovec(b" errno="),
        diagnostic_iovec(errno_bytes),
        diagnostic_iovec(b"\n"),
    ];
    let mut total = 0_usize;
    for vector in &vectors {
        let Some(next) = total.checked_add(vector.iov_len) else {
            return;
        };
        total = next;
    }
    if total > 512 {
        return;
    }
    // SAFETY: all seven initialized vectors borrow live immutable bytes for
    // this one synchronous call; writev does not mutate their source buffers.
    // No retry, allocation, formatting or tracee operation follows its result.
    let _ = unsafe { libc::writev(libc::STDERR_FILENO, vectors.as_ptr(), 7) };
}
