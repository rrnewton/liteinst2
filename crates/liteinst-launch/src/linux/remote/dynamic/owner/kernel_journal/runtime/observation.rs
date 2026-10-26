use super::*;

pub(super) fn registers_bytes(value: &RegisterSnapshot) -> [u8; 216] {
    let words = [
        value.r15,
        value.r14,
        value.r13,
        value.r12,
        value.rbp,
        value.rbx,
        value.r11,
        value.r10,
        value.r9,
        value.r8,
        value.rax,
        value.rcx,
        value.rdx,
        value.rsi,
        value.rdi,
        value.orig_rax,
        value.rip,
        value.cs,
        value.eflags,
        value.rsp,
        value.ss,
        value.fs_base,
        value.gs_base,
        value.ds,
        value.es,
        value.fs,
        value.gs,
    ];
    let mut bytes = [0; 216];
    for (part, value) in bytes.chunks_exact_mut(8).zip(words) {
        part.copy_from_slice(&value.to_ne_bytes());
    }
    bytes
}
impl RuntimeKernelStateRecord {
    pub(super) fn equals(&self, state: &TaskStateSnapshot) -> bool {
        self.captured
            && self.complete
            && self.finalized
            && self.registers == registers_bytes(&state.registers)
            && self.mask == state.mask.to_ne_bytes()
            && self.returned_length == state.xstate.len()
            && self.initialized_xstate.get(..self.returned_length) == Some(state.xstate.as_slice())
    }
    pub(super) fn same_state(&self, other: &Self) -> bool {
        self.complete
            && other.complete
            && self.finalized
            && other.finalized
            && self.registers == other.registers
            && self.mask == other.mask
            && self.returned_length == other.returned_length
            && self.initialized_xstate.get(..self.returned_length)
                == other.initialized_xstate.get(..other.returned_length)
    }
    pub(super) fn copy(
        &mut self,
        raw: RuntimeStateReadView<'_>,
        ordinal: Option<usize>,
        stop: Option<KernelStopIdentity>,
        finalized: bool,
    ) -> Result<bool, LaunchError> {
        if self.finalized {
            return Err(invalid("runtime journal state copy is repeated"));
        }
        if self.captured && (self.raw_ordinal != ordinal || self.stop != stop) {
            return Err(invalid("runtime journal partial state identity differs"));
        }
        if raw.xstate_initialized.len() != MAX_XSTATE || self.initialized_xstate.len() != MAX_XSTATE
        {
            return Err(invalid("runtime journal state substrate shape differs"));
        }
        let first = !self.captured;
        // Preserve the entire initialized substrate and all independent outcomes
        // before interpreting the complete-state claim.
        self.captured = true;
        self.raw_ordinal = ordinal;
        self.stop = stop;
        self.registers = *raw.registers;
        self.registers_request = raw.registers_request.map(Into::into);
        self.initialized_xstate
            .copy_from_slice(raw.xstate_initialized);
        self.xstate_request = raw.xstate_request.map(Into::into);
        self.requested_pointer = raw.requested_pointer;
        self.returned_pointer = raw.returned_pointer;
        self.requested_length = raw.requested_length;
        self.returned_length = raw.returned_length;
        self.mask = *raw.mask;
        self.mask_request = raw.mask_request.map(Into::into);
        self.finalized = finalized;
        self.complete = raw.complete
            && self
                .registers_request
                .is_some_and(RuntimeKernelRequest::zero)
            && self.xstate_request.is_some_and(RuntimeKernelRequest::zero)
            && self.mask_request.is_some_and(RuntimeKernelRequest::zero)
            && self.requested_pointer != 0
            && self.requested_pointer == self.returned_pointer
            && self.requested_length == MAX_XSTATE
            && (512..MAX_XSTATE).contains(&self.returned_length)
            && raw.state.is_some_and(|state| {
                self.registers == registers_bytes(&state.registers)
                    && self.mask == state.mask.to_ne_bytes()
                    && self.returned_length == state.xstate.len()
                    && self.initialized_xstate[..self.returned_length] == state.xstate
            });
        if raw.complete != self.complete || raw.state.is_some() != self.complete {
            return Err(invalid("runtime journal complete state claim differs"));
        }
        Ok(first)
    }
}
impl From<RuntimeWaitCustody> for RuntimeKernelWaitCustody {
    fn from(value: RuntimeWaitCustody) -> Self {
        Self {
            session: value.session,
            expected_tid: value.expected_tid,
            retained_pin: value.retained_pin,
            pin: value.process_pin.map(|process| {
                if process {
                    KernelPinKind::Process
                } else {
                    KernelPinKind::Thread
                }
            }),
            owned: value.owned,
            stopped_status: value.stopped_status,
            tracer_terminal: value.tracer_terminal,
            lost_wait: value.lost_wait,
            missing_pin: value.missing_pin,
        }
    }
}
impl From<RuntimeMapsReadView<'_>> for RuntimeKernelMapsSummary {
    fn from(value: RuntimeMapsReadView<'_>) -> Self {
        Self {
            observed_bytes: value.length,
            directory_open: value.directory_open.map(Into::into),
            filesystem_request: value.filesystem_request.map(Into::into),
            filesystem: value.filesystem,
            maps_open: value.maps_open.map(Into::into),
            read_calls: value.read_calls,
            last_read: value.last_read.map(Into::into),
            overflow_probe: value.overflow_probe.map(Into::into),
            complete: value.complete,
        }
    }
}
impl RuntimeKernelRawRecord {
    pub(super) fn new(ordinal: usize, tid: i32, status: i32, custody: RuntimeWaitCustody) -> Self {
        Self {
            ordinal,
            tid,
            status,
            custody: custody.into(),
            queries_started: false,
            finalized: false,
            registers: [0; 216],
            registers_request: None,
            xstate_request: None,
            requested_pointer: 0,
            returned_pointer: 0,
            requested_length: 0,
            returned_length: 0,
            mask: [0; 8],
            mask_request: None,
            syscall_info: [0; 88],
            syscall_request: None,
            event_message: 0,
            event_request: None,
            signal: [0; 128],
            signal_request: None,
            maps: None,
            state_slot: None,
            failure: None,
        }
    }
    fn copy(&mut self, raw: RuntimeRawWaitView<'_>, finalized: bool) -> Result<(), LaunchError> {
        if self.finalized
            || self.ordinal != raw.ordinal
            || self.tid != raw.tid
            || self.status != raw.status
        {
            return Err(invalid(
                "runtime journal raw header differs or is finalized",
            ));
        }
        self.queries_started = raw.queries_started;
        self.syscall_info = *raw.fixed.syscall_info;
        self.syscall_request = raw.fixed.syscall_info_request.map(Into::into);
        self.event_message = raw.fixed.event_message;
        self.event_request = raw.fixed.event_message_request.map(Into::into);
        self.signal = *raw.fixed.signal;
        self.signal_request = raw.fixed.signal_request.map(Into::into);
        self.maps = raw.maps.map(Into::into);
        self.failure = self.failure.or(raw.failure.map(native_failure));
        if let Some(state) = raw.state {
            self.registers = *state.registers;
            self.registers_request = state.registers_request.map(Into::into);
            self.xstate_request = state.xstate_request.map(Into::into);
            self.requested_pointer = state.requested_pointer;
            self.returned_pointer = state.returned_pointer;
            self.requested_length = state.requested_length;
            self.returned_length = state.returned_length;
            self.mask = *state.mask;
            self.mask_request = state.mask_request.map(Into::into);
        }
        self.finalized = finalized;
        self.validate_custody(raw.state.is_some())?;
        if raw.maps.is_some_and(|maps| {
            maps.initialized.len() != 65536 || maps.length > maps.initialized.len()
        }) {
            return Err(invalid("runtime journal raw maps shape differs"));
        }
        Ok(())
    }
    pub(super) fn validate_custody(&self, has_state: bool) -> Result<(), LaunchError> {
        // Never use a terminal/unheld numeric task to justify a query. These
        // assertions audit the collector's copied provenance, not native custody.
        if self.queries_started
            && (!libc::WIFSTOPPED(self.status)
                || !self.custody.owned
                || self.custody.stopped_status != Some(self.status)
                || self.custody.retained_pin.is_none()
                || self.custody.lost_wait
                || self.custody.missing_pin)
        {
            return Err(invalid("runtime journal raw queries lack held custody"));
        }
        if !self.queries_started
            && (has_state
                || self.registers_request.is_some()
                || self.xstate_request.is_some()
                || self.mask_request.is_some()
                || self.syscall_request.is_some()
                || self.event_request.is_some()
                || self.signal_request.is_some()
                || self.maps.is_some())
        {
            return Err(invalid(
                "runtime journal unheld record contains query attempts",
            ));
        }
        Ok(())
    }
}
impl RuntimeAttempt {
    fn copy_state(
        &mut self,
        slot: RuntimeKernelStateSlot,
        raw: RuntimeStateReadView<'_>,
        ordinal: Option<usize>,
        stop: Option<KernelStopIdentity>,
        finalized: bool,
    ) -> Result<(), LaunchError> {
        let index = slot.index();
        let was_captured = self.states[index].captured;
        let result = self.states[index].copy(raw, ordinal, stop, finalized);
        // Even an invalid completeness claim retains its initialized payload and
        // first State fact; the subsequent failure is separate.
        if !was_captured && self.states[index].captured {
            self.append(RuntimeKernelFact::State { slot })?;
        }
        result.map(|_| ())
    }
    fn copy_raw(
        &mut self,
        raw: RuntimeRawWaitView<'_>,
        finalized: bool,
    ) -> Result<(), LaunchError> {
        self.stage = RuntimeKernelJournalStage::Raw;
        let record = self
            .raw
            .get_mut(raw.ordinal)
            .and_then(Option::as_mut)
            .ok_or(invalid("runtime journal raw view lacks immediate wait"))?;
        if record.finalized
            || record.ordinal != raw.ordinal
            || record.tid != raw.tid
            || record.status != raw.status
        {
            return Err(invalid(
                "runtime journal raw copy identity differs or is finalized",
            ));
        }
        let copied = record.copy(raw, finalized);
        let slot = if !finalized
            || raw.failure.is_some()
            || (!self.binding.returns() && raw.ordinal > 5)
        {
            Some(RuntimeKernelStateSlot::Unexpected)
        } else {
            match (self.binding.returns(), raw.ordinal) {
                (_, 3) => Some(RuntimeKernelStateSlot::Entry),
                (true, 4) => Some(RuntimeKernelStateSlot::Exit),
                (true, 5) => Some(RuntimeKernelStateSlot::BridgeTrap),
                (false, 4) => Some(RuntimeKernelStateSlot::PreExit),
                _ => None,
            }
        };
        let state_result = match (slot, raw.state) {
            (Some(slot), Some(state)) => {
                self.raw[raw.ordinal].as_mut().unwrap().state_slot = Some(slot);
                self.copy_state(slot, state, Some(raw.ordinal), None, finalized)
            }
            _ => Ok(()),
        };
        if let Some(failure) = raw.failure {
            self.fail(native_failure(failure));
        }
        // Independent scalar and state copying both ran before propagating the
        // first diagnostic error. A native first failure is never overwritten.
        copied.and(state_result)
    }
    pub(super) fn stop_matches(&self, stop: &DynamicStop) -> bool {
        stop.session == self.binding.pending.stop.session
            && stop.tid == self.binding.pending.stop.tid
            && stop.task == Some(self.binding.pending.task.task)
    }
    pub(super) fn raw(&self, ordinal: usize) -> Result<&RuntimeKernelRawRecord, LaunchError> {
        self.raw
            .get(ordinal)
            .and_then(Option::as_ref)
            .filter(|raw| raw.finalized && raw.failure.is_none())
            .ok_or(invalid("runtime journal raw observation incomplete"))
    }
    fn validation(
        &mut self,
        stage: RuntimeKernelJournalStage,
        stop: &DynamicStop,
    ) -> Result<(), LaunchError> {
        if self.failure.is_some() || !self.stop_matches(stop)
            || stop.sequence <= self.binding.pending.stop.sequence
            || self.facts().any(|fact| matches!(fact,RuntimeKernelFact::Validated {stage:seen,..} if *seen == stage))
        { return Err(invalid("runtime journal validated checkpoint differs")); }
        self.stage = stage;
        self.append(RuntimeKernelFact::Validated {
            stage,
            stop: stop.into(),
        })
    }
}

impl RuntimeJournalSink {
    pub(in crate::linux::remote::dynamic::owner) fn wait(
        &mut self,
        identity: &RuntimeKernelIdentity,
        ordinal: usize,
        tid: i32,
        status: i32,
        custody: RuntimeWaitCustody,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            attempt.stage = RuntimeKernelJournalStage::Raw;
            if ordinal >= RAW || ordinal != attempt.raw_count || attempt.raw[ordinal].is_some() {
                attempt.fail(KernelFailureKind::Capacity);
                return Err(invalid("runtime journal raw ordinal differs"));
            }
            attempt.raw[ordinal] = Some(RuntimeKernelRawRecord::new(ordinal, tid, status, custody));
            attempt.raw_count += 1;
            attempt.append(RuntimeKernelFact::Wait { ordinal })?;
            // Header is retained even if its observed task/custody is foreign.
            if tid != attempt.binding.pending.stop.tid
                || custody.session != identity.session()
                || custody.expected_tid != identity.tid()
            {
                return Err(invalid("runtime journal raw identity differs"));
            }
            Ok(())
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn raw(
        &mut self,
        identity: &RuntimeKernelIdentity,
        raw: RuntimeRawWaitView<'_>,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| attempt.copy_raw(raw, true))
    }
    /// Catch-unwind synchronization copies only an unfinished record; it neither
    /// reads native state nor changes a completed observation or first failure.
    pub(in crate::linux::remote::dynamic::owner) fn sync_raw(
        &mut self,
        identity: &RuntimeKernelIdentity,
        raw: RuntimeRawWaitView<'_>,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            if attempt
                .raw
                .get(raw.ordinal)
                .and_then(Option::as_ref)
                .is_some_and(|value| value.finalized)
            {
                return Ok(());
            }
            attempt.copy_raw(raw, false)
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn readback(
        &mut self,
        identity: &RuntimeKernelIdentity,
        kind: RuntimeKernelReadback,
        stop: Option<&AdmissionStop>,
        state: RuntimeStateReadView<'_>,
    ) -> Result<(), LaunchError> {
        self.readback_inner(identity, kind, stop, state, true)
    }
    pub(in crate::linux::remote::dynamic::owner) fn sync_readback(
        &mut self,
        identity: &RuntimeKernelIdentity,
        kind: RuntimeKernelReadback,
        stop: Option<&AdmissionStop>,
        state: RuntimeStateReadView<'_>,
    ) -> Result<(), LaunchError> {
        self.readback_inner(identity, kind, stop, state, false)
    }
    fn readback_inner(
        &mut self,
        identity: &RuntimeKernelIdentity,
        kind: RuntimeKernelReadback,
        stop: Option<&AdmissionStop>,
        state: RuntimeStateReadView<'_>,
        finalized: bool,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            let (slot, stage) = match kind {
                RuntimeKernelReadback::Original => (
                    RuntimeKernelStateSlot::Original,
                    RuntimeKernelJournalStage::Original,
                ),
                RuntimeKernelReadback::RestoredReturn => (
                    RuntimeKernelStateSlot::RestoredReturn,
                    RuntimeKernelJournalStage::RestoredReturn,
                ),
                RuntimeKernelReadback::Closed => (
                    RuntimeKernelStateSlot::Closed,
                    RuntimeKernelJournalStage::Closed,
                ),
                RuntimeKernelReadback::Unexpected => (
                    RuntimeKernelStateSlot::Unexpected,
                    RuntimeKernelJournalStage::Raw,
                ),
            };
            if !finalized && attempt.states[slot.index()].finalized {
                return Ok(());
            }
            attempt.stage = stage;
            attempt.copy_state(
                slot,
                state,
                None,
                stop.map(|stop| (&stop.token).into()),
                finalized,
            )?;
            if slot == RuntimeKernelStateSlot::Unexpected {
                return Ok(());
            }
            let stop = stop.ok_or(invalid("runtime journal readback lacks actual stop"))?;
            if !attempt.stop_matches(&stop.token)
                || stop.identity != attempt.binding.pending.task
                || stop.signal.is_some()
                || !matches!(
                    stop.phase,
                    trusted::AdmissionPhase::Restored | trusted::AdmissionPhase::EntryReady
                )
                || !state.complete
            {
                return Err(invalid("runtime journal settled readback differs"));
            }
            if slot == RuntimeKernelStateSlot::Original
                && (stop != &attempt.binding.original
                    || state.state.is_none_or(|state| {
                        state.registers != attempt.binding.registers
                            || state.mask != attempt.binding.original_mask
                            || state.xstate.len() != attempt.binding.original_xstate_len
                    }))
            {
                return Err(invalid("runtime journal original readback differs"));
            }
            Ok(())
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn release_attempt(
        &mut self,
        identity: &RuntimeKernelIdentity,
        phase: RuntimeKernelReleasePhase,
        from: &DynamicStop,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            if attempt.failure.is_some() || !attempt.stop_matches(from)
                || attempt.facts().any(|fact| matches!(fact,RuntimeKernelFact::ReleaseAttempt {phase:old,..} if *old == phase))
            { return Err(invalid("runtime journal release is repeated or foreign")); }
            let stage = match phase { RuntimeKernelReleasePhase::Original => RuntimeKernelJournalStage::Opened,
                RuntimeKernelReleasePhase::Entry => RuntimeKernelJournalStage::Entry,
                RuntimeKernelReleasePhase::PreExit => return Err(invalid("runtime pre-exit has no held stop token")), };
            if !attempt.facts().any(|fact| matches!(fact,RuntimeKernelFact::Validated {stage:old,stop} if *old == stage && *stop == from.into())) {
                return Err(invalid("runtime journal release lacks exact preceding phase"));
            }
            attempt.append(RuntimeKernelFact::ReleaseAttempt { phase,source:RuntimeKernelReleaseSource::Stop(from.into()) })
        })
    }
    /// Pre-exit is a genuine raw held event with no fabricated DynamicStop.
    pub(in crate::linux::remote::dynamic::owner) fn pre_exit_release(
        &mut self,
        identity: &RuntimeKernelIdentity,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            if attempt.failure.is_some()
                || attempt.binding.returns()
                || !attempt
                    .facts()
                    .any(|fact| matches!(fact, RuntimeKernelFact::PreExit { ordinal: 4, .. }))
                || attempt.facts().any(|fact| {
                    matches!(
                        fact,
                        RuntimeKernelFact::ReleaseAttempt {
                            phase: RuntimeKernelReleasePhase::PreExit,
                            ..
                        }
                    )
                })
            {
                return Err(invalid("runtime journal pre-exit release lacks event"));
            }
            let raw = attempt.raw(4)?;
            let source = RuntimeKernelReleaseSource::PreExit {
                ordinal: 4,
                tid: raw.tid,
                status: raw.status,
            };
            attempt.append(RuntimeKernelFact::ReleaseAttempt {
                phase: RuntimeKernelReleasePhase::PreExit,
                source,
            })
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn release_result(
        &mut self,
        identity: &RuntimeKernelIdentity,
        phase: RuntimeKernelReleasePhase,
        request: Request,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            if !attempt.facts().any(|fact| matches!(fact,RuntimeKernelFact::ReleaseAttempt {phase:old,..} if *old == phase))
                || attempt.facts().any(|fact| matches!(fact,RuntimeKernelFact::ReleaseResult {phase:old,..} if *old == phase))
            { return Err(invalid("runtime journal release result lacks unique attempt")); }
            attempt.append(RuntimeKernelFact::ReleaseResult {phase,request:request.into()})
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn opened(
        &mut self,
        identity: &RuntimeKernelIdentity,
        stop: &AdmissionStop,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            if attempt.raw_count != 3
                || stop.identity != attempt.binding.pending.task
                || stop.signal.is_some()
                || stop.phase != trusted::AdmissionPhase::Restored
                || !attempt.states[RuntimeKernelStateSlot::Original.index()].equals(state)
            {
                return Err(invalid("runtime journal opened observation differs"));
            }
            attempt.validation(RuntimeKernelJournalStage::Opened, &stop.token)
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn entry(
        &mut self,
        identity: &RuntimeKernelIdentity,
        event: &DynamicEvent,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            validate_syscall(attempt, event, state, true)
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn exit(
        &mut self,
        identity: &RuntimeKernelIdentity,
        event: &DynamicEvent,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            validate_syscall(attempt, event, state, false)
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn pre_exit(
        &mut self,
        identity: &RuntimeKernelIdentity,
        message: u64,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            let raw = attempt.raw(4)?;
            if attempt.binding.returns()
                || raw.status != (libc::PTRACE_EVENT_EXIT << 16 | libc::SIGTRAP << 8 | 0x7f)
                || raw.event_message != message
                || !raw.event_request.is_some_and(RuntimeKernelRequest::zero)
                || !attempt.states[RuntimeKernelStateSlot::PreExit.index()].complete
                || attempt
                    .facts()
                    .any(|fact| matches!(fact, RuntimeKernelFact::PreExit { .. }))
            {
                return Err(invalid("runtime journal pre-exit observation differs"));
            }
            attempt.stage = RuntimeKernelJournalStage::PreExit;
            attempt.append(RuntimeKernelFact::PreExit {
                ordinal: 4,
                message,
            })
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn closed(
        &mut self,
        identity: &RuntimeKernelIdentity,
        stop: &AdmissionStop,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        self.with(identity, |attempt| {
            let closed = &attempt.states[RuntimeKernelStateSlot::Closed.index()];
            if !attempt.binding.returns()
                || attempt.raw_count != 9
                || stop.identity != attempt.binding.pending.task
                || stop.signal.is_some()
                || stop.phase != trusted::AdmissionPhase::Restored
                || closed.stop != Some((&stop.token).into())
                || !closed.equals(state)
                || !closed.same_state(&attempt.states[RuntimeKernelStateSlot::Exit.index()])
                || !closed
                    .same_state(&attempt.states[RuntimeKernelStateSlot::RestoredReturn.index()])
            {
                return Err(invalid("runtime journal closed observation differs"));
            }
            attempt.validation(RuntimeKernelJournalStage::Closed, &stop.token)
        })
    }
}
fn validate_syscall(
    attempt: &mut RuntimeAttempt,
    event: &DynamicEvent,
    state: &TaskStateSnapshot,
    entry: bool,
) -> Result<(), LaunchError> {
    let (ordinal, slot, tag, stage) = if entry {
        (
            3,
            RuntimeKernelStateSlot::Entry,
            1,
            RuntimeKernelJournalStage::Entry,
        )
    } else {
        (
            4,
            RuntimeKernelStateSlot::Exit,
            2,
            RuntimeKernelJournalStage::Exit,
        )
    };
    let raw = attempt.raw(ordinal)?;
    let token = event
        .stop_token()
        .ok_or(invalid("runtime journal syscall lacks actual token"))?;
    let kind = if entry {
        event.kind
            == (DynamicEventKind::SyscallEntry {
                number: attempt.binding.number,
                arguments: attempt.binding.arguments,
            })
    } else {
        matches!(event.kind,DynamicEventKind::SyscallExit {result,is_error:false} if result == state.registers.rax as i64)
            && attempt.binding.returns()
    };
    let enough = if entry { 80 } else { 33 };
    if !kind
        || event.tid != raw.tid
        || event.task != Some(attempt.binding.pending.task)
        || raw.status != ((libc::SIGTRAP | 0x80) << 8 | 0x7f)
        || raw.syscall_info[0] != tag
        || !raw.syscall_request.is_some_and(|request| {
            request.errno.is_none() && request.result >= enough && request.result <= 88
        })
        || !attempt.states[slot.index()].equals(state)
    {
        return Err(invalid(
            "runtime journal actual syscall observation differs",
        ));
    }
    attempt.validation(stage, token)
}
