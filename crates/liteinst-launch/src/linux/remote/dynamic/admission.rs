//! Client boundary for the native dynamic page-admission owner.
//!
//! The wrapper never lends its underlying session. Provider code runs on the
//! caller's thread, while the tracer retains the pending deadline and cleanup.
use super::*;
use crate::gate::{
    GateError, GateMetrics, GateOracleMetrics, ImageFacts, SelectedCompletion, SelectedMetrics,
};
use crate::lifecycle::{ExitStatus, TaskId};
use crate::selected::{FaultedInstruction, InstructionProvider, ProviderDecision, SelectedInput};
use crate::trap_coverage::TrapCoverageBudget;
use liteinst_admission::oracle_chain::CacheLimits;

/// Explicit trap backend; neither choice is an implicit fallback from A1.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DynamicAdmissionBackend {
    /// Preserve strict scanner refusals except for separately proved native
    /// saved-resume routes. Embedded candidates still refuse.
    #[default]
    StrictTrap,
    /// Compute the complete overlapping-head guard closure. Original scanner
    /// refusals remain in the report; native resume proofs remain separate.
    CoverageTrap(TrapCoverageBudget),
}

/// Lifetime storage ceilings. Retirement and invalidation never refund these.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicAdmissionLimits {
    /// Retained admission generations, including the initial generation.
    pub epochs: usize,
    /// Retained original source, entry facts and complete native-state evidence.
    pub source_fact_bytes: usize,
    /// Original immutable scan reports, including refused reports.
    pub reports: usize,
    /// Separately identified continuation origins, including consumed history.
    pub origins: usize,
    /// Explicit continuation-consumption witnesses retained for the whole run.
    pub witnesses: usize,
    /// Pending and installed plan-history entries, including invalidated plans.
    pub plan_history: usize,
}

impl Default for DynamicAdmissionLimits {
    fn default() -> Self {
        Self {
            epochs: 256,
            source_fact_bytes: 64 * 1024 * 1024,
            reports: 4096,
            origins: 4096,
            witnesses: 4096,
            plan_history: 4096,
        }
    }
}

impl DynamicAdmissionLimits {
    pub(super) fn validate(self) -> Result<Self, GateError> {
        // These are implementation bounds, not automatic enlargements after a
        // refusal. A caller may reduce them to force each exhaustion path.
        if self.epochs == 0
            || self.epochs > 4096
            || self.source_fact_bytes == 0
            || self.source_fact_bytes > 256 * 1024 * 1024
            || self.reports == 0
            || self.reports > 16384
            || self.origins == 0
            || self.origins > 16384
            || self.witnesses == 0
            || self.witnesses > 16384
            || self.plan_history == 0
            || self.plan_history > 16384
        {
            return Err(GateError::Refused(
                "invalid dynamic admission lifetime bounds",
            ));
        }
        Ok(self)
    }
}

/// Closed static-image profile for the first dynamic admission path.
/// All seven default selected classes remain selected. General mapping changes,
/// application signal frames, later exec and fork require later qualification.
#[derive(Clone, Debug, Default)]
pub struct DynamicAdmissionOptions {
    /// Strict or explicitly requested overlapping-head trap coverage.
    pub backend: DynamicAdmissionBackend,
    /// Refuse creation, or allow the exact bounded native thread-clone profile.
    pub lifecycle: DynamicLifecycleOptions,
    /// In-memory immutable-report cache. Cache hits confer no native authority.
    pub cache: CacheLimits,
    /// Append-only evidence and planning ceilings.
    pub limits: DynamicAdmissionLimits,
}

impl DynamicAdmissionOptions {
    pub(super) fn validate(&self) -> Result<(), GateError> {
        self.lifecycle.validate()?;
        self.limits.validate()?;
        if self.lifecycle.creation == DynamicCreationPolicy::Fork {
            return Err(GateError::Refused(
                "fork address spaces require separate admission qualification",
            ));
        }
        if let DynamicAdmissionBackend::CoverageTrap(budget) = self.backend {
            if budget.page_size != 4096 {
                return Err(GateError::Refused(
                    "dynamic admission requires native page geometry",
                ));
            }
        }
        // The full cache and coverage geometry checks remain in the original
        // constructors. No invalid option is fixed up or silently substituted.
        Ok(())
    }
}

/// Complete state at an authenticated held task; this is an observation, not a
/// release token, a saved-frame census or a publication capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicAdmissionState {
    /// Exact task/process/mm incarnation and current admission generation.
    pub task: DynamicTask,
    /// Complete native GPR, flags, segment and kernel-bookkeeping image.
    pub registers: RegisterSnapshot,
    /// Complete kernel NT_X86_XSTATE image.
    pub xstate: Vec<u8>,
    /// Exact eight-byte native signal mask.
    pub signal_mask: u64,
}

/// Completed original selected invocation across a possible generation change.
#[derive(Clone, Debug)]
pub struct DynamicAdmissionCompletion {
    /// Identity at provider invocation, retained even when clone changes facts.
    pub before_task: DynamicTask,
    /// Same logical task at completed, rearmed source generation.
    pub after_task: DynamicTask,
    /// Typed original instruction and complete before/after GPR/XSTATE evidence.
    pub selected: SelectedCompletion,
    /// Exact mask supplied to the original selected invocation.
    pub before_signal_mask: u64,
    /// Exact mask after original completion and source rearming.
    pub signal_mask: u64,
}

/// Diagnostic events from the admission owner. None permits raw task resume.
#[derive(Clone, Debug)]
pub enum DynamicAdmissionEvent {
    /// One provider decision and one completed instruction, with guards rearmed.
    Completed(Box<DynamicAdmissionCompletion>),
    /// Provider-generated fault; no native signal or completion is fabricated.
    Fault {
        /// Task on which the invocation remains incomplete.
        task: DynamicTask,
        /// Exact selected input and the provider's architectural fault.
        fault: Box<FaultedInstruction>,
    },
    /// An original application signal, held with its complete native information.
    /// The finite profile closes; this is not signal-delivery qualification.
    ApplicationSignal {
        /// Complete actual stopped state.
        state: Box<DynamicAdmissionState>,
        /// Exact 128-byte native signal information.
        signal: DynamicSignalInfo,
        /// Original selected invocation, if the signal interrupted one.
        input: Option<Box<SelectedInput>>,
    },
    /// A native lifecycle notification. Its old stop token is diagnostic only;
    /// the wrapper has no raw-session escape or generic resume method.
    Lifecycle(DynamicEvent),
    /// Actual task terminal status. Complete physical cleanup is reported only
    /// by terminate(), including process/thread pidfds and the natural reaper.
    TaskTerminal {
        /// Exact retired task incarnation.
        task: DynamicTask,
        /// Actual terminal status, never the earlier PTRACE_EVENT_EXIT payload.
        status: ExitStatus,
        /// True only when the owner has observed every application task terminal.
        all_terminal: bool,
    },
}

/// Live counters, not evidence that any complete research claim is established.
#[derive(Clone, Debug, Default)]
pub struct DynamicAdmissionMetrics {
    /// Page publication work and actual admitted/untouched pages.
    pub pages: GateMetrics,
    /// Provider and completion counts by explicit mechanism.
    pub selected: SelectedMetrics,
    /// Original report preparation and demand work.
    pub oracle: GateOracleMetrics,
    /// Once-per-domain full-source scan work for retention bounds, separate
    /// from demand scans, cache preparation and cache hits in `oracle`.
    pub resource_scan_decoded_starts: usize,
    /// Retained independently identified origins, including consumed history.
    pub retained_origins: usize,
    /// Retained origin-refresh, consumption, and epoch records.
    pub continuation_history_records: usize,
    /// Retained potential CALL returns across all source generations. These
    /// records do not prove that the corresponding CALLs actually executed.
    pub retained_call_obligations: usize,
    /// Oldest retained CALL source generation, or None for an empty ledger.
    pub oldest_call_generation: Option<u64>,
    /// Reserved lifetime source-evidence bytes, including unused reservations.
    pub charged_source_bytes: usize,
    /// Source-evidence bytes actually retained under those reservations.
    pub retained_source_bytes: usize,
    /// Complete initialized bootstrap XSTATE payload retained across all four phases.
    pub bootstrap_xstate_bytes: usize,
    /// Actual authenticated original fetch faults, including same-page siblings.
    pub fetch_faults: usize,
    /// Actual authenticated original source INT3 stops, including collateral.
    pub guard_stops: usize,
    /// Actual completed source-generation invalidations.
    pub generation_changes: usize,
}

// These values are transport data only. The owner compares the complete value
// with its retained pending transaction and reauthenticates the current native
// stop, source, membership and routes before any decision can mutate a task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingToken {
    pub(super) stop: DynamicStop,
    pub(super) task: DynamicTask,
    pub(super) epoch: u64,
    pub(super) plan: u64,
    pub(super) invocation: u64,
}

#[derive(Clone, Debug)]
pub(super) struct ProviderInput {
    pub(super) token: PendingToken,
    pub(super) input: SelectedInput,
}

pub(super) enum AdmissionRequest {
    Start {
        initial: DynamicStop,
        facts: Vec<ImageFacts>,
        options: DynamicAdmissionOptions,
    },
    Advance,
    Complete {
        token: PendingToken,
        decision: ProviderDecision,
    },
    State(TaskId),
    Memory {
        task: TaskId,
        address: u64,
        len: usize,
    },
    Metrics,
}

pub(super) enum AdmissionReply {
    Ready(DynamicAdmissionState),
    Provider(Box<ProviderInput>),
    Event(DynamicAdmissionEvent),
    State(DynamicAdmissionState),
    Bytes(Vec<u8>),
    Metrics(DynamicAdmissionMetrics),
}

/// Native page admission from the first original user instruction, with a
/// private raw owner and a client-thread provider. No method transfers wait,
/// publication or raw-resume authority to its caller.
///
/// A provider which blocks can block its own calling thread. The tracer still
/// expires the immutable pending transaction and performs owned cleanup. Provider
/// failure, panic, timeout or an owner error permanently closes this wrapper.
pub struct DynamicAdmissionSession<P: InstructionProvider> {
    session: DynamicSession,
    provider: P,
    initial: DynamicAdmissionState,
    timeout: Duration,
    closed: bool,
}

// The guard is armed before fallible work or a callback. It owns only the
// cancellation flag, so it cannot lend the raw session or run ptrace on drop.
struct CancelOnFailure {
    cancel: Arc<AtomicBool>,
    armed: bool,
}
impl Drop for CancelOnFailure {
    fn drop(&mut self) {
        if self.armed {
            self.cancel.store(true, Ordering::Release);
        }
    }
}

impl<P: InstructionProvider> DynamicAdmissionSession<P> {
    /// Launches through the seized owner, before any original user instruction.
    /// The initial state includes the kernel's actual first-user XSTATE.
    ///
    /// # Safety
    /// The caller certifies every original instruction head and saved-context
    /// origin within the supplied immutable private images, including alternate
    /// entries. No external writer, writable alias, code-as-data dependency,
    /// independent tracer/reaper or opaque saved context may access the envelope.
    /// TF/RF must be clear at original guarded entries; an observed INT3 cannot
    /// prove their pre-trap value. The finite profile has no application signal
    /// frames, exception/nonlocal contexts or later mapping/exec transitions.
    /// These certifications supplement actual native exclusion; NX history alone
    /// is never a saved-resume census. Refusal does not authorize a raw fallback.
    pub unsafe fn launch(
        command: &LaunchCommand,
        facts: Vec<ImageFacts>,
        options: DynamicAdmissionOptions,
        provider: P,
        timeout: Duration,
    ) -> Result<Self, GateError> {
        options.validate()?;
        // Starts the whole construction budget before launching the owner.
        let (until, response_until) = command_deadlines(timeout, timeout)?;
        let mut session = DynamicSession::launch_options_until(
            command,
            timeout,
            Some(options.lifecycle),
            DynamicExecPolicy::Refuse,
            until,
        )?;
        let mut cancel = CancelOnFailure {
            cancel: Arc::clone(&session.cancel),
            armed: true,
        };
        let initial = session
            .initial_event()
            .stop_token()
            .ok_or(GateError::Refused(
                "dynamic launch lacks its pristine exec stop",
            ))?
            .clone();
        let reply = session.admission_call(
            AdmissionRequest::Start {
                initial,
                facts,
                options,
            },
            until,
            response_until,
        )?;
        let AdmissionReply::Ready(initial) = reply else {
            return Err(GateError::Refused(
                "dynamic admission bootstrap returned the wrong phase",
            ));
        };
        cancel.armed = false;
        Ok(Self {
            session,
            provider,
            initial,
            timeout,
            closed: false,
        })
    }

    /// Numeric leader PID for diagnostics and read-only observation, not control authority.
    pub fn pid(&self) -> libc::pid_t {
        self.session.pid()
    }

    /// Initial authenticated state before original execution, retained as history.
    pub fn initial_state(&self) -> &DynamicAdmissionState {
        &self.initial
    }
    /// Read-only access to the caller's provider state.
    pub fn provider(&self) -> &P {
        &self.provider
    }
    /// Update caller-owned provider policy between completed operations.
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }
    /// Whether this wrapper has permanently lost original-execution authority.
    pub fn is_closed(&self) -> bool {
        self.closed || self.session.cancel.load(Ordering::Acquire)
    }

    /// Advances through native admission to one selected completion or diagnostic
    /// event. The event/provider/completion exchange shares one absolute deadline.
    pub fn next_event(&mut self) -> Result<DynamicAdmissionEvent, GateError> {
        self.require_open()?;
        let (until, response_until) = command_deadlines(self.timeout, self.timeout)?;
        self.closed = true;
        let mut cancel = CancelOnFailure {
            cancel: Arc::clone(&self.session.cancel),
            armed: true,
        };
        let reply =
            self.session
                .admission_call(AdmissionRequest::Advance, until, response_until)?;
        let event = self.finish_advance(reply, until, response_until)?;
        let continuing = matches!(
            &event,
            DynamicAdmissionEvent::Completed(_)
                | DynamicAdmissionEvent::Lifecycle(_)
                | DynamicAdmissionEvent::TaskTerminal {
                    all_terminal: false,
                    ..
                }
        );
        if continuing {
            self.closed = false;
            cancel.armed = false;
        }
        Ok(event)
    }

    // Separate the reply boundary so queued data is checked against the
    // original absolute budget before invoking any client provider code.
    // next_event retains the close/cancel guard around this entire operation.
    fn finish_advance(
        &mut self,
        reply: AdmissionReply,
        until: Instant,
        response_until: Instant,
    ) -> Result<DynamicAdmissionEvent, GateError> {
        let event = match reply {
            AdmissionReply::Event(event) => event,
            AdmissionReply::Provider(input) => {
                // recv_timeout may take an already queued reply after this
                // caller was descheduled past the original deadline. Expired
                // ownership cannot start a fresh provider invocation.
                if Instant::now() >= until || self.session.cancel.load(Ordering::Acquire) {
                    return Err(LaunchError::Timeout("dynamic admission provider").into());
                }
                let decision = self.provider.decide(&input.input)?;
                // No new timeout is allocated after user code. Even if the owner
                // has already cleaned up, a stale reply cannot create a command
                // with a renewed transaction lifetime.
                if Instant::now() >= until {
                    return Err(LaunchError::Timeout("dynamic admission provider").into());
                }
                match self.session.admission_call(
                    AdmissionRequest::Complete {
                        token: input.token,
                        decision,
                    },
                    until,
                    response_until,
                )? {
                    AdmissionReply::Event(event) => event,
                    _ => {
                        return Err(GateError::Refused(
                            "provider reply did not finish its pending invocation",
                        ));
                    }
                }
            }
            _ => {
                return Err(GateError::Refused(
                    "dynamic admission advance returned the wrong phase",
                ));
            }
        };
        Ok(event)
    }

    fn require_open(&self) -> Result<(), GateError> {
        if self.is_closed() {
            Err(GateError::Refused("dynamic admission session is closed"))
        } else {
            Ok(())
        }
    }

    fn inspect<T>(
        &mut self,
        request: AdmissionRequest,
        expected: impl FnOnce(AdmissionReply) -> Result<T, GateError>,
    ) -> Result<T, GateError> {
        self.require_open()?;
        let (until, response_until) = command_deadlines(self.timeout, self.timeout)?;
        let result = self
            .session
            .admission_call(request, until, response_until)
            .and_then(expected);
        if result.is_err() {
            self.closed = true;
            self.session.cancel.store(true, Ordering::Release);
        }
        result
    }
    /// Reads complete held native state. Running or stale tasks refuse.
    pub fn state(&mut self, task: TaskId) -> Result<DynamicAdmissionState, GateError> {
        self.inspect(AdmissionRequest::State(task), |reply| match reply {
            AdmissionReply::State(value) => Ok(value),
            _ => Err(GateError::Refused("dynamic admission state reply differs")),
        })
    }
    /// Reads bounded memory through a current held task, without mutation access.
    pub fn read_memory(
        &mut self,
        task: TaskId,
        address: u64,
        len: usize,
    ) -> Result<Vec<u8>, GateError> {
        self.inspect(
            AdmissionRequest::Memory { task, address, len },
            |reply| match reply {
                AdmissionReply::Bytes(value) => Ok(value),
                _ => Err(GateError::Refused("dynamic admission memory reply differs")),
            },
        )
    }
    /// Current diagnostic counters; these do not grant publication authority.
    pub fn metrics(&mut self) -> Result<DynamicAdmissionMetrics, GateError> {
        self.inspect(AdmissionRequest::Metrics, |reply| match reply {
            AdmissionReply::Metrics(value) => Ok(value),
            _ => Err(GateError::Refused(
                "dynamic admission metrics reply differs",
            )),
        })
    }
    /// Cancels and waits for the same complete physical cleanup as DynamicSession.
    pub fn terminate(self, timeout: Duration) -> Result<DynamicCleanup, LaunchError> {
        self.session.terminate(timeout)
    }
}

impl DynamicSession {
    // Unlike call_with_response_timeout, this private transport receives already
    // established absolute budgets and must not recreate them after callbacks.
    fn admission_call(
        &mut self,
        request: AdmissionRequest,
        until: Instant,
        response_until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(LaunchError::Invalid("dynamic session is closing").into());
        }
        if Instant::now() >= until || response_until < until {
            self.cancel.store(true, Ordering::Release);
            return Err(LaunchError::Timeout("dynamic admission command").into());
        }
        let (reply, response) = channel();
        if self
            .commands
            .send(Command {
                request: Request::Admission(Box::new(request)),
                until,
                reply,
            })
            .is_err()
        {
            self.cancel.store(true, Ordering::Release);
            return Err(LaunchError::Invalid("dynamic tracer is closed").into());
        }
        match response.recv_timeout(response_until.saturating_duration_since(Instant::now())) {
            Ok(Ok(Response::Admission(reply))) => *reply,
            Ok(Ok(_)) => {
                self.cancel.store(true, Ordering::Release);
                Err(GateError::Refused(
                    "dynamic admission response type differs",
                ))
            }
            Ok(Err(error)) => {
                self.cancel.store(true, Ordering::Release);
                Err(error.into())
            }
            Err(error) => {
                self.cancel.store(true, Ordering::Release);
                Err(match error {
                    std::sync::mpsc::RecvTimeoutError::Timeout => {
                        LaunchError::Timeout("dynamic tracer response")
                    }
                    std::sync::mpsc::RecvTimeoutError::Disconnected => {
                        LaunchError::Invalid("dynamic tracer is closed")
                    }
                }
                .into())
            }
        }
    }
}

#[cfg(test)]
mod tests;
