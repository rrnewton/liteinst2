//! Opt-in wrapper; no raw session or publication permit escapes to the client.
use super::*;

/// An admitted singleton session supporting one declared original signal
/// delivery and return. The wrapper retains the admission owner's exclusive
/// control; its observations do not grant raw execution or frame-write access.
pub struct DynamicSignalSession<P: InstructionProvider> {
    inner: DynamicAdmissionSession<P>,
    anchor: AnchorReader,
    progress: SignalProgressReader,
    delivery: Option<(SignalDeliveryToken, Instant)>,
}

impl<P: InstructionProvider> DynamicAdmissionSession<P> {
    /// Launch the finite native signal profile. The returned wrapper has no raw
    /// session escape. Constructor failure may leave physical cleanup owned by
    /// the tracer; consult the typed failure and its retained archive.
    ///
    /// # Safety
    /// The ordinary launch source/head/no-writer/no-code-as-data contract still
    /// applies. The profile declares every handler/restorer/landing head and the
    /// whole private normal/alternate stacks. Only the declared original handler
    /// may edit its frame, and only the typed fields and target are possible.
    /// There are no competing senders, nested signals, opaque contexts, other
    /// tasks or kernel writers. Handler entry begins with original CPUID. Both
    /// original and prospective edited resume targets remain guarded or NX
    /// before any handler release; declared intent alone never proves an edit.
    /// The conforming native Linux x86-64 GETREGSET ABI must retain its fixed
    /// host XSTATE extent. An actual maximum-capacity initial query certifies
    /// that extent; every later relying observation must match it exactly.
    /// This does not certify a vendor kernel from its reported version string.
    pub unsafe fn launch_with_signals(
        command: &LaunchCommand,
        facts: Vec<ImageFacts>,
        options: DynamicAdmissionOptions,
        profile: DynamicSignalProfile,
        provider: P,
        timeout: Duration,
    ) -> Result<DynamicSignalSession<P>, DynamicSignalLaunchFailure> {
        options
            .validate()
            .map_err(DynamicSignalLaunchFailure::before_anchor)?;
        profile
            .validate(&options, &facts)
            .map_err(DynamicSignalLaunchFailure::before_anchor)?;
        crate::gate::domain::validate_image_count(&facts)
            .map_err(DynamicSignalLaunchFailure::before_anchor)?;
        let budget = signal::SignalBudget::new(&facts, &options)
            .map_err(DynamicSignalLaunchFailure::before_anchor)?;
        let request = launch::anchor::AnchorRequest::new(options.limits.source_fact_bytes)
            .map_err(DynamicSignalLaunchFailure::before_anchor)?;
        let (until, response_until) = command_deadlines(timeout, timeout)
            .map_err(DynamicSignalLaunchFailure::before_anchor)?;
        let (mut session, archive, progress) = DynamicSession::launch_options_until_with_anchor(
            command,
            timeout,
            options.lifecycle,
            until,
            request,
        )?;
        let anchor = archive.reader();
        let result = (|| -> Result<DynamicAdmissionSession<P>, GateError> {
            let mut cancel = CancelOnFailure {
                cancel: Arc::clone(&session.cancel),
                armed: true,
            };
            let initial = session
                .initial_event()
                .stop_token()
                .ok_or(GateError::Refused("signal launch lacks original EXEC stop"))?
                .clone();
            let reply = session.admission_call(
                AdmissionRequest::StartSignals {
                    initial,
                    facts,
                    options,
                    profile,
                    budget,
                },
                until,
                response_until,
            )?;
            let AdmissionReply::ReadySignals(initial, kernel_progress) = reply else {
                return Err(GateError::Refused(
                    "signal bootstrap returned the wrong phase",
                ));
            };
            cancel.armed = false;
            Ok(DynamicAdmissionSession {
                session,
                provider,
                initial,
                kernel_progress,
                timeout,
                closed: false,
            })
        })();
        result
            .map(|inner| DynamicSignalSession {
                inner,
                anchor: anchor.clone(),
                progress,
                delivery: None,
            })
            .map_err(|error| {
                match &error {
                    GateError::Control(error) => archive.record_initial_failure(error),
                    _ => archive.record_initial_failure(&LaunchError::Invalid(
                        "signal admission constructor refused",
                    )),
                }
                DynamicSignalLaunchFailure {
                    error,
                    anchor: Some(anchor),
                    native_owner_started: true,
                }
            })
    }
}

impl<P: InstructionProvider> DynamicSignalSession<P> {
    /// Numeric leader PID for diagnostics, without control authority.
    pub fn pid(&self) -> libc::pid_t {
        self.inner.pid()
    }
    /// Initial authenticated state before original execution, retained as history.
    pub fn initial_state(&self) -> &DynamicAdmissionState {
        self.inner.initial_state()
    }
    /// Read-only access to the caller's provider state.
    pub fn provider(&self) -> &P {
        self.inner.provider()
    }
    /// Update caller-owned provider policy between completed operations.
    pub fn provider_mut(&mut self) -> &mut P {
        self.inner.provider_mut()
    }
    /// Whether this wrapper has permanently lost original-execution authority.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
    /// Retained launch-anchor observations, including failures and cleanup.
    pub fn anchor_progress(&self) -> AnchorReader {
        self.anchor.clone()
    }
    /// Retained signal observations; partial evidence never authorizes release.
    pub fn signal_progress(&self) -> SignalProgressReader {
        self.progress.clone()
    }
    /// Retained original-kernel progress, independently of signal completion.
    pub fn kernel_progress(&self) -> KernelProgressReader {
        self.inner.kernel_progress()
    }
    /// Read complete held native state. Running or stale tasks refuse.
    pub fn state(&mut self, task: TaskId) -> Result<DynamicAdmissionState, GateError> {
        self.inner.state(task)
    }
    /// Read bounded memory through a current held task, without mutation access.
    pub fn read_memory(
        &mut self,
        task: TaskId,
        address: u64,
        len: usize,
    ) -> Result<Vec<u8>, GateError> {
        self.inner.read_memory(task, address, len)
    }
    /// Current diagnostic counters; these grant no publication authority.
    pub fn metrics(&mut self) -> Result<DynamicAdmissionMetrics, GateError> {
        self.inner.metrics()
    }

    /// Advance admitted execution to its next event. A pending signal must be
    /// delivered with its exact token before its existing deadline; advancing
    /// past an unfinished delivery closes the session and requests cleanup.
    pub fn next_event(&mut self) -> Result<DynamicAdmissionEvent, GateError> {
        self.inner.require_open()?;
        self.inner.closed = true;
        let mut cancel = CancelOnFailure {
            cancel: Arc::clone(&self.inner.session.cancel),
            armed: true,
        };
        if self.delivery.is_some() {
            return Err(GateError::Refused(
                "signal delivery must finish under its original deadline",
            ));
        }
        let (until, response_until) = command_deadlines(self.inner.timeout, self.inner.timeout)?;
        let reply =
            self.inner
                .session
                .admission_call(AdmissionRequest::Advance, until, response_until)?;
        let event = self.inner.finish_advance(reply, until, response_until)?;
        if let DynamicAdmissionEvent::SignalPending(pending) = &event {
            if pending.token.until != until {
                return Err(GateError::Refused("signal pending deadline differs"));
            }
            self.delivery = Some((pending.token.clone(), response_until));
        }
        if matches!(
            &event,
            DynamicAdmissionEvent::Completed(_)
                | DynamicAdmissionEvent::Lifecycle(_)
                | DynamicAdmissionEvent::SignalPending(_)
                | DynamicAdmissionEvent::SignalReturned(_)
                | DynamicAdmissionEvent::TaskTerminal {
                    all_terminal: false,
                    ..
                }
        ) {
            self.inner.closed = false;
            cancel.armed = false;
        }
        Ok(event)
    }

    /// Deliver the pending original signal and return the authenticated handler
    /// entry. A stale, replayed or expired token refuses without a new deadline.
    pub fn deliver_signal(
        &mut self,
        token: &SignalDeliveryToken,
    ) -> Result<DynamicSignalEntry, GateError> {
        self.inner.require_open()?;
        self.inner.closed = true;
        let mut cancel = CancelOnFailure {
            cancel: Arc::clone(&self.inner.session.cancel),
            armed: true,
        };
        let (expected, response_until) = self
            .delivery
            .as_ref()
            .ok_or(GateError::Refused("signal session has no pending delivery"))?;
        if expected != token || Instant::now() >= token.until {
            return Err(GateError::Refused(
                "signal delivery identity is stale or expired",
            ));
        }
        let reply = self.inner.session.admission_call(
            AdmissionRequest::DeliverSignal(token.clone()),
            token.until,
            *response_until,
        )?;
        let AdmissionReply::SignalEntered(entry) = reply else {
            return Err(GateError::Refused(
                "signal delivery returned the wrong phase",
            ));
        };
        self.delivery = None;
        self.inner.closed = false;
        cancel.armed = false;
        Ok(*entry)
    }

    /// Cancel execution and wait for the underlying session's physical cleanup.
    pub fn terminate(self, timeout: Duration) -> Result<DynamicCleanup, LaunchError> {
        self.inner.terminate(timeout)
    }
}
