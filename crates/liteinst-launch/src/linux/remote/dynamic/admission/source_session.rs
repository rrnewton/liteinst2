//! Client-thread source resolution with one unchanged admission deadline.
use super::*;

#[cfg(test)]
mod tests;

/// Opt-in singleton mapping or exec session with a caller-thread source resolver.
/// Its private inner session cannot lend native or publication authority.
pub struct DynamicSourceSession<P: InstructionProvider, S: DynamicSourceResolver> {
    inner: DynamicAdmissionSession<P>,
    sources: S,
    profile: SourceProfile,
}

// A closed constructor-selected profile; it cannot be changed or composed by
// callbacks. The exec reader belongs only to the exec wrapper variant.
enum SourceProfile {
    Mapping(DynamicMappingProfile),
    Exec {
        profile: DynamicExecProfile,
        progress: crate::ExecProgressReader,
    },
}

impl<P: InstructionProvider> DynamicAdmissionSession<P> {
    /// Launch the explicit bounded anonymous/private mapping profile. The
    /// returned wrapper keeps mapping execution and source commit on the owner.
    ///
    /// # Safety
    /// The ordinary launch source/head/no-writer/no-code-as-data contract still
    /// applies to the initial images. Every resolver answer must certify all
    /// possible heads in its actual captured source, including alternate and
    /// indirect entries. There are no external writers, writable aliases,
    /// untracked mm sharers, opaque saved contexts, signals or independent
    /// tracers/reapers. Only the original singleton program writes its owned RW
    /// anonymous ranges. The complete original mapping, continuation and source
    /// effects must remain within the explicit profile; unsupported effects
    /// refuse, rather than authorizing another execution mechanism.
    pub unsafe fn launch_with_mappings<S: DynamicSourceResolver>(
        command: &LaunchCommand,
        facts: Vec<ImageFacts>,
        options: DynamicAdmissionOptions,
        profile: DynamicMappingProfile,
        provider: P,
        sources: S,
        timeout: Duration,
    ) -> Result<DynamicSourceSession<P, S>, GateError> {
        profile.validate(&options, &facts)?;
        crate::gate::domain::validate_image_count(&facts)?;
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
            AdmissionRequest::StartMappings {
                initial,
                facts,
                options,
                profile: profile.clone(),
            },
            until,
            response_until,
        )?;
        let AdmissionReply::ReadyMappings(initial, kernel_progress) = reply else {
            return Err(GateError::Refused(
                "mapping bootstrap returned the wrong phase",
            ));
        };
        cancel.armed = false;
        Ok(DynamicSourceSession {
            inner: DynamicAdmissionSession {
                session,
                provider,
                initial,
                kernel_progress,
                timeout,
                closed: false,
            },
            sources,
            profile: SourceProfile::Mapping(profile),
        })
    }

    /// Launch the explicit singleton one-exec profile with runtime source
    /// capture. The original native64 exec instruction executes once; its
    /// replacement image is admitted under a fresh task/mm identity.
    ///
    /// # Safety
    /// The ordinary launch source/head/no-writer/no-code-as-data contract still
    /// applies. Every resolver answer must give complete original, alternate
    /// and indirect heads for each owner's actual immutable captured VMA.
    /// There are no external writers, aliases, untracked mm sharers, opaque
    /// saved contexts, signals, independent tracers/reapers, or mapping-profile
    /// composition. Original filename/argv/envp storage is bounded immutable
    /// application data outside instrumented source and private owner storage.
    /// Runtime main/interpreter identity and permissions are authenticated by
    /// the owner, never by pathname or resolver-supplied versions. Unsupported
    /// images or effects close the transaction under the original deadline.
    pub unsafe fn launch_with_exec<S: DynamicSourceResolver>(
        command: &LaunchCommand,
        facts: Vec<ImageFacts>,
        options: DynamicAdmissionOptions,
        profile: DynamicExecProfile,
        provider: P,
        sources: S,
        timeout: Duration,
    ) -> Result<DynamicSourceSession<P, S>, GateError> {
        profile.validate(&options)?;
        crate::gate::domain::validate_image_count(&facts)?;
        let (until, response_until) = command_deadlines(timeout, timeout)?;
        let mut session = DynamicSession::launch_options_until(
            command,
            timeout,
            Some(options.lifecycle),
            DynamicExecPolicy::ExecveOnce,
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
            AdmissionRequest::StartExec {
                initial,
                facts,
                options,
                profile: profile.clone(),
            },
            until,
            response_until,
        )?;
        let AdmissionReply::ReadyExec(initial, kernel_progress, progress) = reply else {
            return Err(GateError::Refused(
                "exec bootstrap returned the wrong phase",
            ));
        };
        cancel.armed = false;
        Ok(DynamicSourceSession {
            inner: DynamicAdmissionSession {
                session,
                provider,
                initial,
                kernel_progress,
                timeout,
                closed: false,
            },
            sources,
            profile: SourceProfile::Exec { profile, progress },
        })
    }
}

impl<P: InstructionProvider, S: DynamicSourceResolver> DynamicSourceSession<P, S> {
    /// Numeric leader PID for diagnostics only.
    pub fn pid(&self) -> libc::pid_t {
        self.inner.pid()
    }
    /// Actual initial state, retained as immutable history.
    pub fn initial_state(&self) -> &DynamicAdmissionState {
        self.inner.initial_state()
    }
    /// Read caller-owned instruction-provider state.
    pub fn provider(&self) -> &P {
        self.inner.provider()
    }
    /// Update instruction-provider policy between completed operations.
    pub fn provider_mut(&mut self) -> &mut P {
        self.inner.provider_mut()
    }
    /// Read caller-owned source-resolver state.
    pub fn source_resolver(&self) -> &S {
        &self.sources
    }
    /// Update source resolution policy between completed operations.
    pub fn source_resolver_mut(&mut self) -> &mut S {
        &mut self.sources
    }
    /// Whether original execution authority is permanently closed.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
    /// Retained original kernel progress; partial records grant no release.
    pub fn kernel_progress(&self) -> KernelProgressReader {
        self.inner.kernel_progress()
    }
    /// Retained exec progress for the explicit exec profile. Mapping sessions
    /// return None; cloning this reader cannot request or resume native work.
    pub fn exec_progress(&self) -> Option<crate::ExecProgressReader> {
        match &self.profile {
            SourceProfile::Mapping(_) => None,
            SourceProfile::Exec { progress, .. } => Some(progress.clone()),
        }
    }
    /// Read complete held native state without a resume capability.
    pub fn state(&mut self, task: TaskId) -> Result<DynamicAdmissionState, GateError> {
        self.inner.state(task)
    }
    /// Read bounded memory through a held task without mutation authority.
    pub fn read_memory(
        &mut self,
        task: TaskId,
        address: u64,
        len: usize,
    ) -> Result<Vec<u8>, GateError> {
        self.inner.read_memory(task, address, len)
    }
    /// Read current diagnostic counters; these are not qualification claims.
    pub fn metrics(&mut self) -> Result<DynamicAdmissionMetrics, GateError> {
        self.inner.metrics()
    }
    /// Cancel and await the original native owner's complete physical cleanup.
    pub fn terminate(self, timeout: Duration) -> Result<DynamicCleanup, LaunchError> {
        self.inner.terminate(timeout)
    }

    /// Advance one original operation. Mapping or exec can require one
    /// source-resolution batch on this caller thread before its final event.
    /// Both callbacks and all owner commands share the original absolute budget.
    pub fn next_event(&mut self) -> Result<DynamicAdmissionEvent, GateError> {
        self.inner.require_open()?;
        let (until, response_until) = command_deadlines(self.inner.timeout, self.inner.timeout)?;
        self.inner.closed = true;
        let mut cancel = CancelOnFailure {
            cancel: Arc::clone(&self.inner.session.cancel),
            armed: true,
        };
        let reply =
            self.inner
                .session
                .admission_call(AdmissionRequest::Advance, until, response_until)?;
        let event = self.finish_advance(reply, until, response_until)?;
        if matches!(
            &event,
            DynamicAdmissionEvent::Completed(_)
                | DynamicAdmissionEvent::ImageReplaced(_)
                | DynamicAdmissionEvent::Lifecycle(_)
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

    fn ordinary_event(
        &self,
        event: DynamicAdmissionEvent,
    ) -> Result<DynamicAdmissionEvent, GateError> {
        if matches!(&event, DynamicAdmissionEvent::ImageReplaced(_)) {
            return Err(GateError::Refused(
                "image replacement lacks its pending exec acquisition",
            ));
        }
        Ok(event)
    }

    fn before_callback(&self, until: Instant, label: &'static str) -> Result<(), GateError> {
        if Instant::now() >= until || self.inner.session.cancel.load(Ordering::Acquire) {
            Err(LaunchError::Timeout(label).into())
        } else {
            Ok(())
        }
    }

    fn finish_advance(
        &mut self,
        reply: AdmissionReply,
        until: Instant,
        response_until: Instant,
    ) -> Result<DynamicAdmissionEvent, GateError> {
        let input = match reply {
            AdmissionReply::Event(event) => return self.ordinary_event(event),
            AdmissionReply::Provider(input) => input,
            _ => {
                return Err(GateError::Refused(
                    "dynamic admission advance returned the wrong phase",
                ));
            }
        };
        self.before_callback(until, "dynamic admission provider")?;
        let decision = self.inner.provider.decide(&input.input)?;
        self.before_callback(until, "dynamic admission provider")?;
        let reply = self.inner.session.admission_call(
            AdmissionRequest::Complete {
                token: input.token.clone(),
                decision,
            },
            until,
            response_until,
        )?;
        let request = match reply {
            AdmissionReply::Event(event) => {
                if matches!(&self.profile, SourceProfile::Exec { .. })
                    && matches!(decision, ProviderDecision::Native)
                    && is_exec_input(&input.input)
                {
                    return Err(GateError::Refused(
                        "exec completion lacks source acquisition",
                    ));
                }
                return self.ordinary_event(event);
            }
            AdmissionReply::AcquireSources(request) => request,
            _ => {
                return Err(GateError::Refused(
                    "provider reply did not finish its pending invocation",
                ));
            }
        };
        match &self.profile {
            SourceProfile::Mapping(profile) => {
                // Only an original native mprotect(RX) in this explicit profile can
                // request source facts. Native policy and actual capture remain owner
                // duties; this closed client check prevents contradictory dispatch.
                if !matches!(decision, ProviderDecision::Native)
                    || !matches!(
                        input.input.instruction().operation(),
                        crate::selected::Operation::Syscall {
                            abi: crate::selected::SyscallAbi::LinuxX64
                        }
                    )
                    || input.input.registers().rax != libc::SYS_mprotect as u64
                    || input.input.registers().rdx != (libc::PROT_READ | libc::PROT_EXEC) as u64
                {
                    return Err(GateError::Refused(
                        "source acquisition lacks an original native RX mapping request",
                    ));
                }
                request.check_mapping_binding(&input.token, profile, until)?;
                let end = input
                    .input
                    .registers()
                    .rdi
                    .checked_add(input.input.registers().rsi);
                let image = &request.images()[0]; // exact one-VMA shape checked above
                if image.range().start != input.input.registers().rdi
                    || Some(image.range().end) != end
                {
                    return Err(GateError::Refused(
                        "source capture differs from original mapping range",
                    ));
                }
            }
            SourceProfile::Exec { profile, .. } => {
                if !matches!(decision, ProviderDecision::Native) || !is_exec_input(&input.input) {
                    return Err(GateError::Refused(
                        "source acquisition lacks an original native exec request",
                    ));
                }
                request.check_exec_binding(&input.token, profile, until)?;
            }
        }
        self.before_callback(until, "dynamic source acquisition")?;
        let facts = self.sources.resolve(&request)?;
        self.before_callback(until, "dynamic source acquisition")?;
        request.check_facts(&facts)?;
        let token = request.token.clone();
        let binding = token.clone();
        drop(request); // release caller's shared view before owner staging
        match self.inner.session.admission_call(
            AdmissionRequest::ResolveSources { token, facts },
            until,
            response_until,
        )? {
            AdmissionReply::Event(event) => match &self.profile {
                SourceProfile::Mapping(_) => self.ordinary_event(event),
                SourceProfile::Exec { .. } => checked_exec_event(event, &input, &binding),
            },
            _ => Err(GateError::Refused(
                "source reply did not finish its pending acquisition",
            )),
        }
    }
}

fn is_exec_input(input: &SelectedInput) -> bool {
    matches!(
        input.instruction().operation(),
        crate::selected::Operation::Syscall {
            abi: crate::selected::SyscallAbi::LinuxX64
        }
    ) && input.registers().rax == libc::SYS_execve as u64
}

// Client dispatch consistency only: all full states and actual native phase
// witnesses are reauthenticated by the owner before it constructs the event.
fn checked_exec_event(
    event: DynamicAdmissionEvent,
    input: &ProviderInput,
    binding: &PendingSourceToken,
) -> Result<DynamicAdmissionEvent, GateError> {
    let DynamicAdmissionEvent::ImageReplaced(replaced) = &event else {
        return Err(GateError::Refused(
            "exec source reply lacks image replacement",
        ));
    };
    let SourceTransitionBinding::Exec(transition) = &binding.transition else {
        return Err(GateError::Refused("image replacement binding differs"));
    };
    let ExecSourceBinding {
        previous,
        replacement,
        attempt,
        ..
    } = transition.as_ref();
    if binding.original != input.token
        || replaced.input != input.input
        || replaced.before.task != *previous
        || replaced.before.registers != *input.input.registers()
        || replaced.ready.task != *replacement
        || replaced.ready.task != binding.task
        || replaced.ready.task.generation != 0
        || replaced.attempt != *attempt
    {
        return Err(GateError::Refused("image replacement binding differs"));
    }
    Ok(event)
}
