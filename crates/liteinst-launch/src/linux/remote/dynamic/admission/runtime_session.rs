//! Initial owner-captured runtime sources and their private transport.
use super::*;
use liteinst_admission::{Generation, MappingId};

/// Bounded initial executable/interpreter byte capture. Whole VMA identities
/// remain distinct from the overlapping byte windows used for decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicRuntimeCaptureLimits {
    /// Maximum complete executable/interpreter VMA descriptors, at most 64.
    pub max_vmas: usize,
    /// Maximum retained source windows, at most 64.
    pub max_windows: usize,
    /// Complete window bytes including dependency context, at most 64 KiB.
    /// Must be a multiple of 4096 and leave space for at least one target page.
    pub max_window_bytes: usize,
    /// Total copied bytes including every overlapping dependency byte.
    pub max_total_capture_bytes: usize,
}
impl Default for DynamicRuntimeCaptureLimits {
    fn default() -> Self {
        Self {
            max_vmas: 64,
            max_windows: 64,
            max_window_bytes: 64 * 1024,
            max_total_capture_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Initial singleton runtime profile with owner-captured Partial entry evidence.
/// All seven selected classes remain selected. These limits do not certify
/// instruction-head completeness, absence of writers or executable permission.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DynamicRuntimeOptions {
    /// Initial immutable source-storage bounds.
    pub capture: DynamicRuntimeCaptureLimits,
    /// Existing six lifetime limits; retirement never refunds them.
    pub limits: DynamicAdmissionLimits,
}

/// Private wire identity. This is separate from a legacy installed-plan token;
/// the owner also retains and authenticates its full consume-once permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimePendingToken {
    pub(super) stop: DynamicStop,
    pub(super) task: DynamicTask,
    pub(super) generation: Generation,
    pub(super) mapping: MappingId,
    pub(super) window: usize,
    pub(super) pc: u64,
    pub(super) invocation: u64,
}
pub(super) struct RuntimeProviderInput {
    pub(super) token: RuntimePendingToken,
    pub(super) input: SelectedInput,
}

impl<P: InstructionProvider> DynamicAdmissionSession<P> {
    /// Launches with owner-captured original executable/interpreter bytes and
    /// positive entry hints. No caller-supplied head list is required. Unknown
    /// entries remain Partial and each execution path requires its own proof.
    ///
    /// # Safety
    /// The immutable private source envelope has no external writer, writable
    /// alias, independent tracer/reaper, external perf/uprobe interposition or code observer of the temporary
    /// original-entry bootstrap patch. Original execution cannot enter the
    /// private island or fixed vsyscall mapping. Native x86-64 ABI and architectural
    /// control state must satisfy the qualified runtime instruction profile;
    /// unqualified instructions/effects refuse before release. The initial
    /// profile is a single task with no application signal frames, opaque saved
    /// contexts, nonlocal returns or later mapping/exec transitions. These
    /// obligations supply no instruction-head or saved-return completeness.
    /// Diagnostic memory requests are bounded to 64 KiB. The initial ordinary
    /// profile covers register/immediate operations, LEA, NOP and relative
    /// branches; memory/stack operations and indirect transfers require further
    /// native footprint proof. Selected CPU operations accept typed emulation;
    /// native syscall effects and composed lifecycle transitions are not yet
    /// admitted by this constructor.
    pub unsafe fn launch_runtime(
        command: &LaunchCommand,
        options: DynamicRuntimeOptions,
        provider: P,
        timeout: Duration,
    ) -> Result<Self, GateError> {
        options.limits.validate()?;
        // One original absolute budget covers launch, capture, real bootstrap,
        // immutable source reauthentication and initial census commitment.
        let (until, response_until) = command_deadlines(timeout, timeout)?;
        let mut session = DynamicSession::launch_options_until(
            command,
            timeout,
            Some(DynamicLifecycleOptions::default()),
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
                "runtime launch lacks its pristine exec stop",
            ))?
            .clone();
        let reply = session.admission_call(
            AdmissionRequest::StartRuntime { initial, options },
            until,
            response_until,
        )?;
        let AdmissionReply::RuntimeReady(initial, kernel_progress) = reply else {
            return Err(GateError::Refused(
                "runtime startup returned the wrong phase",
            ));
        };
        cancel.armed = false;
        Ok(Self {
            session,
            provider,
            initial,
            kernel_progress,
            timeout,
            closed: false,
        })
    }

    pub(super) fn finish_runtime_provider(
        &mut self,
        input: Box<RuntimeProviderInput>,
        until: Instant,
        response_until: Instant,
    ) -> Result<DynamicAdmissionEvent, GateError> {
        if Instant::now() >= until || self.session.cancel.load(Ordering::Acquire) {
            return Err(LaunchError::Timeout("runtime admission provider").into());
        }
        let decision = self.provider.decide(&input.input)?;
        if Instant::now() >= until || self.session.cancel.load(Ordering::Acquire) {
            return Err(LaunchError::Timeout("runtime admission provider").into());
        }
        match self.session.admission_call(
            AdmissionRequest::CompleteRuntime {
                token: input.token,
                decision,
            },
            until,
            response_until,
        )? {
            AdmissionReply::Event(event) => Ok(event),
            _ => Err(GateError::Refused(
                "runtime provider reply did not finish its invocation",
            )),
        }
    }
}
