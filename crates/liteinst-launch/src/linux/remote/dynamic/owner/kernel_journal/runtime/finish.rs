use super::*;

fn validated(
    attempt: &RuntimeAttempt,
    stage: RuntimeKernelJournalStage,
) -> Option<KernelStopIdentity> {
    attempt.facts().find_map(|fact| match fact {
        RuntimeKernelFact::Validated { stage: old, stop } if *old == stage => Some(*stop),
        _ => None,
    })
}
fn successful_release(
    attempt: &RuntimeAttempt,
    phase: RuntimeKernelReleasePhase,
    actual: Request,
) -> bool {
    let request: RuntimeKernelRequest = actual.into();
    request.zero() && attempt.facts().any(|fact| matches!(fact,RuntimeKernelFact::ReleaseResult {phase:old,request:seen} if *old == phase && *seen == request))
}
fn exact_trace_stop(attempt: &RuntimeAttempt, stop: KernelStopIdentity) -> bool {
    stop.session == attempt.binding.pending.stop.session
        && stop.tid == attempt.binding.pending.stop.tid
        && stop.task == Some(attempt.binding.pending.task.task)
}
impl RuntimeJournalSink {
    /// A copied native trace cannot finish census admission. It must agree with
    /// every already retained phase; the later private census receipt is separate.
    pub(in crate::linux::remote::dynamic::owner) fn returned(
        &mut self,
        identity: &RuntimeKernelIdentity,
        trace: NativeKernelReturnTrace,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            let bridge = &attempt.states[RuntimeKernelStateSlot::RestoredReturn.index()];
            let trace_stops = [
                trace.released,
                trace.entry,
                trace.exit,
                trace.bridge,
                trace.closed,
            ];
            if attempt.failure.is_some()
                || !attempt.binding.returns()
                || attempt.raw_count != 9
                || trace.attempt != attempt.binding.id()
                || trace.entry_ordinal != 3
                || trace.exit_ordinal != 4
                || trace.bridge_ordinal != 5
                || trace.closed_ordinal != 8
                || trace_stops
                    .iter()
                    .any(|stop| !exact_trace_stop(attempt, *stop))
                || trace_stops
                    .windows(2)
                    .any(|pair| pair[0].sequence >= pair[1].sequence)
                || validated(attempt, RuntimeKernelJournalStage::Opened) != Some(trace.released)
                || validated(attempt, RuntimeKernelJournalStage::Entry) != Some(trace.entry)
                || validated(attempt, RuntimeKernelJournalStage::Exit) != Some(trace.exit)
                || validated(attempt, RuntimeKernelJournalStage::Closed) != Some(trace.closed)
                || bridge.stop != Some(trace.bridge)
                || !successful_release(
                    attempt,
                    RuntimeKernelReleasePhase::Original,
                    trace.original_release,
                )
                || !successful_release(
                    attempt,
                    RuntimeKernelReleasePhase::Entry,
                    trace.entry_release,
                )
                || attempt.facts().any(|fact| {
                    matches!(
                        fact,
                        RuntimeKernelFact::Returned { .. } | RuntimeKernelFact::Terminal { .. }
                    )
                })
            {
                return Err(invalid("runtime journal return trace differs"));
            }
            for ordinal in 0..9 {
                attempt.raw(ordinal)?;
            }
            for slot in [
                RuntimeKernelStateSlot::Original,
                RuntimeKernelStateSlot::Entry,
                RuntimeKernelStateSlot::Exit,
                RuntimeKernelStateSlot::BridgeTrap,
                RuntimeKernelStateSlot::RestoredReturn,
                RuntimeKernelStateSlot::Closed,
            ] {
                if !attempt.states[slot.index()].complete || !attempt.states[slot.index()].finalized
                {
                    return Err(invalid("runtime journal returning state is incomplete"));
                }
            }
            attempt.stage = RuntimeKernelJournalStage::Returned;
            attempt.append(RuntimeKernelFact::Returned { stop: trace.closed })
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn terminal(
        &mut self,
        identity: &RuntimeKernelIdentity,
        event: &DynamicEvent,
        trace: NativeKernelTerminalTrace,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            let pre = attempt.raw(4)?;
            let terminal = attempt.raw(5)?;
            if attempt.failure.is_some() || attempt.binding.returns() || attempt.raw_count != 6
                || trace.attempt != attempt.binding.id() || trace.pre_exit_ordinal != 4 || trace.terminal_ordinal != 5
                || trace.pre_exit_tid != pre.tid || trace.pre_exit_status != pre.status
                || trace.terminal_tid != terminal.tid || trace.terminal_status != terminal.status
                || trace.event_message != pre.event_message || Some(trace.event_message_request.into()) != pre.event_request
                || !RuntimeKernelRequest::from(trace.event_message_request).zero()
                || !exact_trace_stop(attempt,trace.released) || !exact_trace_stop(attempt,trace.entry)
                || trace.released.sequence >= trace.entry.sequence || trace.entry.sequence >= trace.exiting_sequence
                || trace.exiting_sequence >= trace.terminal_sequence
                || validated(attempt,RuntimeKernelJournalStage::Opened) != Some(trace.released)
                || validated(attempt,RuntimeKernelJournalStage::Entry) != Some(trace.entry)
                || !attempt.facts().any(|fact| matches!(fact,RuntimeKernelFact::PreExit {ordinal:4,message} if *message == trace.event_message))
                || !successful_release(attempt,RuntimeKernelReleasePhase::Original,trace.original_release)
                || !successful_release(attempt,RuntimeKernelReleasePhase::Entry,trace.entry_release)
                || !successful_release(attempt,RuntimeKernelReleasePhase::PreExit,trace.pre_exit_release)
                || event.tid != terminal.tid || event.task != Some(attempt.binding.pending.task) || event.stop_token().is_some()
                || !matches!(event.kind,DynamicEventKind::TaskTerminal {..})
                || terminal.queries_started || terminal.state_slot.is_some()
                || !terminal_status(event,terminal.status) || terminal.custody.tracer_terminal != Some(terminal.status)
                || trace.physical_status != terminal.status || trace.pin_poll.result != 1 || trace.pin_poll.errno.is_some()
                || trace.pin_revents & libc::POLLHUP == 0 || trace.pin_revents & libc::POLLNVAL != 0
                || terminal.custody.retained_pin != Some(trace.pin_fd)
                || attempt.facts().any(|fact| matches!(fact,RuntimeKernelFact::Terminal {..} | RuntimeKernelFact::Returned {..}))
            { return Err(invalid("runtime journal terminal trace differs")); }
            for ordinal in 0..6 { attempt.raw(ordinal)?; }
            for slot in [RuntimeKernelStateSlot::Original,RuntimeKernelStateSlot::Entry,RuntimeKernelStateSlot::PreExit] {
                let state = &attempt.states[slot.index()];
                if !state.complete || !state.finalized { return Err(invalid("runtime journal terminal precursor state is incomplete")); }
            }
            attempt.stage = RuntimeKernelJournalStage::Terminal;
            attempt.append(RuntimeKernelFact::Terminal {ordinal:5,sequence:trace.terminal_sequence,
                status:trace.terminal_status,physical_status:trace.physical_status,pin_revents:trace.pin_revents})
        })
    }
}
fn terminal_status(event: &DynamicEvent, status: i32) -> bool {
    match event.kind {
        DynamicEventKind::TaskTerminal {
            status: crate::lifecycle::ExitStatus::Code(code),
        } => libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == i32::from(code),
        DynamicEventKind::TaskTerminal {
            status: crate::lifecycle::ExitStatus::Signal(signal),
        } => libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == i32::from(signal),
        _ => false,
    }
}
impl KernelJournalWriter {
    pub(in crate::linux::remote::dynamic::owner) fn finish_runtime_return(
        &mut self,
        handle: RuntimeKernelHandle,
        receipt: &RuntimeKernelCommitReceipt,
    ) -> Result<(), LaunchError> {
        self.finish_runtime(handle, receipt, true)
    }
    pub(in crate::linux::remote::dynamic::owner) fn finish_runtime_terminal(
        &mut self,
        handle: RuntimeKernelHandle,
        receipt: &RuntimeKernelCommitReceipt,
    ) -> Result<(), LaunchError> {
        self.finish_runtime(handle, receipt, false)
    }
    fn finish_runtime(
        &mut self,
        handle: RuntimeKernelHandle,
        receipt: &RuntimeKernelCommitReceipt,
        returning: bool,
    ) -> Result<(), LaunchError> {
        let view = receipt.view();
        let mut archive = self.lock();
        if self.active.is_some()
            || archive.poisoned
            || archive.status != KernelWriterStatus::Active
            || archive.runtime.active != Some(handle)
        {
            return Err(invalid("runtime journal census finish is inactive"));
        }
        let attempt = archive
            .runtime
            .attempts
            .get_mut(handle.index)
            .ok_or(invalid("runtime journal finish handle absent"))?;
        if attempt.binding.id() != handle.id {
            return Err(invalid("runtime journal finish identity differs"));
        }
        let fact = attempt.committed_fact(&view, returning)?;
        attempt.stage = RuntimeKernelJournalStage::Committed;
        attempt.append(fact)?;
        attempt.completed = true;
        archive.runtime.active = None;
        Ok(())
    }
}

impl RuntimeAttempt {
    // A descriptive projection is sufficient to test comparisons, but only
    // finish_runtime's private receipt parameter can reach an actual commit.
    pub(super) fn committed_fact(
        &self,
        view: &RuntimeKernelCommitView<'_>,
        returning: bool,
    ) -> Result<RuntimeKernelFact, LaunchError> {
        let attempt = self;
        let b = &attempt.binding;
        if attempt.completed
            || attempt.failure.is_some()
            || view.attempt != b.id()
            || view.pending != &b.pending
            || view.source != b.source
            || view.window != b.window
            || view.origin != b.origin
            || view.execution != b.execution
            || view.task != b.pending.task
            || view.number != b.number
            || view.arguments != b.arguments
            || view.until != b.until
            || b.returns() != returning
        {
            return Err(invalid("runtime journal committed identity differs"));
        }
        let fact = match &view.outcome {
            RuntimeKernelCommitOutcome::Returned { current, stop } if returning => {
                let closed = KernelStopIdentity::from(*stop);
                if !attempt.stop_matches(stop) || current.0 != b.origin.0 || current.1 <= b.origin.1
                    || !attempt.facts().any(|fact| matches!(fact,RuntimeKernelFact::Returned {stop:seen} if *seen == closed))
                { return Err(invalid("runtime journal committed return differs")); }
                RuntimeKernelFact::ReturnCommitted {
                    current: *current,
                    stop: closed,
                }
            }
            RuntimeKernelCommitOutcome::Terminal {
                event,
                sequence,
                wait_status,
                physical_status,
                pin_revents,
            } if !returning => {
                if event.task != Some(b.pending.task) || event.tid != b.pending.stop.tid || event.stop_token().is_some()
                    || !terminal_status(event,*wait_status)
                    || !attempt.facts().any(|fact| matches!(fact,RuntimeKernelFact::Terminal {sequence:s,status:w,physical_status:p,pin_revents:r,..}
                        if s == sequence && w == wait_status && p == physical_status && r == pin_revents))
                { return Err(invalid("runtime journal committed terminal differs")); }
                RuntimeKernelFact::TerminalCommitted {
                    sequence: *sequence,
                    status: *wait_status,
                }
            }
            _ => return Err(invalid("runtime journal census outcome differs")),
        };
        Ok(fact)
    }
}
