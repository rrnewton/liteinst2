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

/// Native original-site syscall choices for the initial singleton runtime.
/// Every allowed operation still requires an explicit provider Native decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RuntimeKernelProfile {
    /// Native syscall effects remain refused.
    #[default]
    Refuse,
    /// Exact native64 SYSCALL for getpid, gettid, exit and exit_group only.
    /// PID namespace identity, full state, source and physical custody are
    /// independently authenticated before an original instruction is released.
    IdentityAndTermination,
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
    /// Explicit finite original-site native syscall policy.
    pub kernel: RuntimeKernelProfile,
}

/// Private wire identity. This is separate from a legacy installed-plan token;
/// the owner also retains and authenticates its full consume-once permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic) struct RuntimePendingToken {
    pub(in crate::linux::remote::dynamic) stop: DynamicStop,
    pub(in crate::linux::remote::dynamic) task: DynamicTask,
    pub(in crate::linux::remote::dynamic) generation: Generation,
    pub(in crate::linux::remote::dynamic) mapping: MappingId,
    pub(in crate::linux::remote::dynamic) window: usize,
    pub(in crate::linux::remote::dynamic) pc: u64,
    pub(in crate::linux::remote::dynamic) invocation: u64,
}
pub(in crate::linux::remote::dynamic) struct RuntimeProviderInput {
    pub(in crate::linux::remote::dynamic) token: RuntimePendingToken,
    pub(in crate::linux::remote::dynamic) input: SelectedInput,
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
    /// the optional IdentityAndTermination kernel profile admits only native64
    /// getpid/gettid and terminal exit/exit_group under separate native proofs.
    /// Other syscall effects and composed lifecycle transitions remain refused.
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

    /// Launches the same runtime profile while retaining cleanup observation
    /// on an ordinary returned construction error, including failures before
    /// the initial Ready handshake. The error's bounded cleanup waits are
    /// separate from the one original startup deadline.
    ///
    /// Unlike a cleanup receipt, returning an error does not mean that the
    /// tracees are gone. Keep the host alive and inspect/wait the error until
    /// its cleanup status is Complete or NotStarted. Failed/Disconnected and
    /// wait timeouts remain failures. Dropping the error only cancels.
    ///
    /// # Safety
    /// All immutable-source, alias, control, task, signal and native-profile
    /// obligations of [`Self::launch_runtime`] apply unchanged. This adds no
    /// source, execution, lifecycle or raw-session authority. Provider Drop
    /// panics propagate; cancellation is armed before provider destruction,
    /// but arbitrary caller unwinding/process lifetime remains caller custody.
    pub unsafe fn launch_runtime_with_cleanup(
        command: &LaunchCommand,
        options: DynamicRuntimeOptions,
        provider: P,
        timeout: Duration,
    ) -> Result<Self, DynamicRuntimeLaunchFailure> {
        // SAFETY: this is exactly the caller's documented runtime envelope.
        unsafe {
            Self::launch_runtime_with_cleanup_inner(
                command,
                options,
                provider,
                timeout,
                #[cfg(test)]
                None,
            )
        }
    }

    pub(in crate::linux::remote::dynamic) unsafe fn launch_runtime_with_cleanup_inner(
        command: &LaunchCommand,
        options: DynamicRuntimeOptions,
        provider: P,
        timeout: Duration,
        #[cfg(test)] cleanup_probe: Option<owner::launch_cleanup_probe::Probe>,
    ) -> Result<Self, DynamicRuntimeLaunchFailure> {
        options
            .limits
            .validate()
            .map_err(DynamicRuntimeLaunchFailure::not_started)?;
        let (until, response_until) = command_deadlines(timeout, timeout)
            .map_err(DynamicRuntimeLaunchFailure::not_started)?;
        // Fixed client-control metadata is allocated before any owner thread.
        // Success drops the unused holder; error transfer performs no allocation.
        let cleanup = launch_cleanup::PreparedCleanup::new();
        let mut session = match DynamicSession::launch_options_until_retained(
            command,
            timeout,
            Some(DynamicLifecycleOptions::default()),
            DynamicExecPolicy::Refuse,
            until,
            #[cfg(test)]
            cleanup_probe,
        ) {
            Ok(session) => session,
            Err(failure) => return Err(cleanup.finish_launch(failure)),
        };
        let mut cancel = CancelOnFailure {
            cancel: Arc::clone(&session.cancel),
            armed: true,
        };
        let outcome = (|| -> Result<_, GateError> {
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
            Ok((initial, kernel_progress))
        })();
        let (initial, kernel_progress) = match outcome {
            Ok(ready) => ready,
            Err(error) => {
                return Err(cleanup.finish_session(error, session));
            }
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
