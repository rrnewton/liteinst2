use super::*;

pub(super) fn zero_registers() -> RegisterSnapshot {
    // SAFETY: all native register fields are scalar integers, fully initialized.
    let raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    raw.into()
}
pub(super) fn buffer(length: usize) -> Result<Vec<u8>, LaunchError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| invalid("exec journal allocation failed"))?;
    bytes.resize(length, 0);
    Ok(bytes)
}
pub(super) fn base_bytes() -> Result<usize, LaunchError> {
    // Managed Arc allocation: the two control words, required data alignment,
    // and inline mutex/archive. No allocator-private bookkeeping is claimed.
    let controls = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>();
    let (layout, _) = controls
        .extend(std::alloc::Layout::new::<Mutex<Archive>>())
        .map_err(|_| invalid("exec journal allocation size overflows"))?;
    Ok(layout.pad_to_align().size())
}
impl StoredState {
    pub(super) fn empty() -> Self {
        Self {
            registers: zero_registers(),
            mask: 0,
            xstate: Vec::new(),
            length: 0,
            complete: false,
        }
    }
    pub(super) fn allocate(&mut self) -> Result<(), LaunchError> {
        self.xstate = buffer(MAX_XSTATE)?;
        Ok(())
    }
    pub(super) fn save(&mut self, state: &TaskStateSnapshot) -> Result<(), LaunchError> {
        if self.complete
            || !(512..MAX_XSTATE).contains(&state.xstate.len())
            || self.xstate.len() != MAX_XSTATE
        {
            return Err(invalid(
                "exec journal copied state is repeated or incomplete",
            ));
        }
        self.xstate[..state.xstate.len()].copy_from_slice(&state.xstate);
        self.registers = state.registers;
        self.mask = state.mask;
        self.length = state.xstate.len();
        self.complete = true;
        Ok(())
    }
    pub(super) fn equals(&self, state: &TaskStateSnapshot) -> bool {
        self.complete
            && self.registers == state.registers
            && self.mask == state.mask
            && self.xstate[..self.length] == state.xstate
    }
    pub(super) fn snapshot(&self) -> KernelCapturedState {
        KernelCapturedState {
            registers: self.registers,
            xstate: self.xstate[..self.length].to_vec(),
            signal_mask: self.mask,
        }
    }
}
impl StoredMaps {
    pub(super) fn empty() -> Self {
        Self {
            record: ExecMapsRecord {
                status: ExecMapsStatus::Unused,
                tid: 0,
                raw_status: 0,
                open: None,
                filesystem: None,
                filesystem_type: 0,
                read_calls: 0,
                last_read: None,
                overflow_byte: 0,
                close: None,
                observed_bytes: 0,
                initialized: Vec::new(),
            },
        }
    }
    pub(super) fn allocate(&mut self) -> Result<(), LaunchError> {
        self.record.initialized = buffer(MAP_BYTES)?;
        Ok(())
    }
}
impl RawBuffer {
    pub(super) fn empty() -> Self {
        Self {
            record: ExecRawRecord {
                ordinal: 0,
                tid: 0,
                status: 0,
                pin: KernelPinKind::Process,
                held: false,
                complete: false,
                registers_read: None,
                registers: zero_registers(),
                xstate_query: None,
                initialized_xstate: Vec::new(),
                mask_read: None,
                signal_mask: 0,
                syscall_read: None,
                syscall_info: [0; 88],
                event_read: None,
                event_message: 0,
                siginfo_read: None,
                siginfo: [0; 128],
                maps: StoredMaps::empty().record,
            },
        }
    }
    pub(super) fn allocate(&mut self) -> Result<(), LaunchError> {
        self.record.initialized_xstate = buffer(MAX_XSTATE)?;
        self.record.maps.initialized = buffer(MAP_BYTES)?;
        Ok(())
    }
    pub(super) fn state_equals(&self, state: &TaskStateSnapshot) -> bool {
        let record = &self.record;
        record.complete
            && record.registers == state.registers
            && record.signal_mask == state.mask
            && record.xstate_query.is_some_and(|query| {
                query.outcome.result == 0
                    && query.pointer_unchanged
                    && (512..MAX_XSTATE).contains(&query.reported_bytes)
                    && record.initialized_xstate[..query.reported_bytes] == state.xstate
            })
    }
}
impl Attempt {
    pub(super) fn append(&mut self, fact: ExecJournalFact) -> Result<(), LaunchError> {
        if self.fact_count == FACTS {
            return Err(invalid("exec journal fact capacity exhausted"));
        }
        self.facts[self.fact_count] = Some(fact);
        self.fact_count += 1;
        Ok(())
    }
    pub(super) fn dynamic_bytes(&self) -> Result<usize, LaunchError> {
        let mut bytes = std::mem::size_of::<Self>();
        for count in self
            .raw
            .iter()
            .flat_map(|raw| {
                [
                    raw.record.initialized_xstate.capacity(),
                    raw.record.maps.initialized.capacity(),
                ]
            })
            .chain([
                self.before.xstate.capacity(),
                self.restored_entry.xstate.capacity(),
                self.final_state.xstate.capacity(),
                self.final_maps.record.initialized.capacity(),
            ])
        {
            bytes = bytes
                .checked_add(count)
                .ok_or(invalid("exec journal allocation size overflows"))?;
        }
        Ok(bytes)
    }
    pub(super) fn snapshot(&self) -> ExecAttemptSnapshot {
        ExecAttemptSnapshot {
            id: self.id,
            pending_stop: (&self.pending.stop).into(),
            previous: self.pending.task,
            source_epoch: self.pending.epoch,
            source_plan: self.pending.plan,
            original_until: self.until,
            input: self.input,
            before: self.before.snapshot(),
            restored_original_stop: self.original_stop,
            replacement: self.replacement,
            facts: self.facts[..self.fact_count]
                .iter()
                .flatten()
                .copied()
                .collect(),
            raw: self.raw[..self.raw_count]
                .iter()
                .map(|raw| raw.record.clone())
                .collect(),
            restored_entry: self
                .restored_entry
                .complete
                .then(|| self.restored_entry.snapshot()),
            final_state: self
                .final_state
                .complete
                .then(|| self.final_state.snapshot()),
            quarantined_maps: self.final_maps.record.clone(),
        }
    }
}
impl Archive {
    pub(super) fn fail(&mut self, kind: KernelFailureKind) {
        if self.first_failure.is_none() {
            self.first_failure = Some((self.stage, kind));
        }
    }
}
pub(super) fn lock(archive: &Arc<Mutex<Archive>>) -> MutexGuard<'_, Archive> {
    match archive.lock() {
        Ok(guard) => guard,
        Err(error) => {
            let mut guard = error.into_inner();
            guard.poisoned = true;
            guard.fail(KernelFailureKind::ArchivePoisoned);
            guard
        }
    }
}
pub(super) fn handle_matches(archive: &Arc<Mutex<Archive>>, handle: ExecAttemptHandle) -> bool {
    Arc::as_ptr(archive) as usize == handle.archive
}
pub(super) fn attempt(
    archive: &mut Archive,
    handle: ExecAttemptHandle,
) -> Result<&mut Attempt, LaunchError> {
    if archive.session != handle.id.session
        || archive.poisoned
        || archive.closing
        || archive.first_failure.is_some()
    {
        return Err(invalid("exec journal archive is foreign, closed or failed"));
    }
    let attempt = archive
        .attempt
        .as_deref_mut()
        .ok_or(invalid("exec journal attempt is absent"))?;
    if attempt.id != handle.id {
        return Err(invalid("exec journal attempt identity differs"));
    }
    Ok(attempt)
}
pub(super) fn mutate<T>(
    archive: &Arc<Mutex<Archive>>,
    handle: ExecAttemptHandle,
    stage: ExecJournalStage,
    action: impl FnOnce(&mut Attempt) -> Result<T, LaunchError>,
) -> Result<T, LaunchError> {
    if !handle_matches(archive, handle) {
        return Err(invalid("exec journal handle belongs to another archive"));
    }
    let mut guard = lock(archive);
    guard.stage = stage;
    let result = attempt(&mut guard, handle).and_then(action);
    if let Err(error) = &result {
        guard.fail(failure(error));
    }
    result
}
pub(super) fn check_time(until: Instant) -> Result<(), LaunchError> {
    if Instant::now() >= until {
        Err(LaunchError::Timeout("admitted exec journal"))
    } else {
        Ok(())
    }
}
pub(super) fn original_input(input: &SelectedInput) -> Result<ExecOriginalInput, LaunchError> {
    let instruction = input.instruction();
    let regs = *input.registers();
    if instruction.operation()
        != (Operation::Syscall {
            abi: SyscallAbi::LinuxX64,
        })
        || regs.rax != libc::SYS_execve as u64
        || regs.cs != 0x33
        || instruction.bytes().is_empty()
        || instruction.bytes().len() > 15
        || instruction.logical_pc() != regs.rip
        || instruction
            .logical_pc()
            .checked_add(instruction.bytes().len() as u64)
            != Some(instruction.next_pc())
    {
        return Err(invalid("exec journal input is not exact native execve"));
    }
    let mut initialized_instruction = [0; 15];
    initialized_instruction[..instruction.bytes().len()].copy_from_slice(instruction.bytes());
    Ok(ExecOriginalInput {
        logical_pc: instruction.logical_pc(),
        next_pc: instruction.next_pc(),
        initialized_instruction,
        instruction_bytes: instruction.bytes().len(),
        registers: regs,
        arguments: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
    })
}
impl PreparedExecAttempt {
    pub(in crate::linux::remote::dynamic::owner) fn allocated_bytes(&self) -> usize {
        self.bytes
    }
}
impl ExecJournalWriter {
    pub(in crate::linux::remote::dynamic) fn new(session: u64) -> Self {
        // Layout cannot overflow for these statically sized types.
        let bytes = base_bytes().expect("fixed exec archive layout");
        Self {
            archive: Arc::new(Mutex::new(Archive {
                session,
                allocated_bytes: bytes,
                prepared: false,
                attempt: None,
                stage: ExecJournalStage::Prepared,
                first_failure: None,
                closing: false,
                cleanup_complete: None,
                poisoned: false,
            })),
            _thread: PhantomData,
        }
    }
    pub(in crate::linux::remote::dynamic) fn reader(&self) -> ExecProgressReader {
        ExecProgressReader {
            archive: Arc::clone(&self.archive),
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn allocated_bytes(&self) -> usize {
        lock(&self.archive).allocated_bytes
    }
    pub(in crate::linux::remote::dynamic::owner) fn prepare(
        &mut self,
        pending: &PendingToken,
        input: &SelectedInput,
        before: &TaskStateSnapshot,
        until: Instant,
    ) -> Result<PreparedExecAttempt, LaunchError> {
        check_time(until)?;
        let input = original_input(input)?;
        let mut guard = lock(&self.archive);
        if guard.prepared
            || guard.attempt.is_some()
            || guard.closing
            || guard.poisoned
            || guard.first_failure.is_some()
            || guard.session == 0
            || pending.stop.session != guard.session
            || pending.stop.tid <= 0
            || pending.stop.task != Some(pending.task.task)
            || pending.epoch != pending.task.generation
            || pending.invocation == 0
            || before.registers != input.registers
            || !(512..MAX_XSTATE).contains(&before.xstate.len())
        {
            return Err(invalid(
                "exec journal binding is not an exact finite invocation",
            ));
        }
        let mut stored = Box::new(Attempt {
            id: KernelAttemptId {
                session: guard.session,
                invocation: pending.invocation,
            },
            pending: pending.clone(),
            input,
            until,
            facts: [None; FACTS],
            fact_count: 0,
            raw: std::array::from_fn(|_| RawBuffer::empty()),
            raw_count: 0,
            pending_raw: None,
            before: StoredState::empty(),
            restored_entry: StoredState::empty(),
            final_state: StoredState::empty(),
            final_maps: StoredMaps::empty(),
            native_phase: NativePhase::Attached,
            original_stop: None,
            entry_stop: None,
            exec_stop: None,
            exit_stop: None,
            final_stop: None,
            replacement: None,
            trap_raw: None,
            effect_index: 0,
            quarantine_count: 0,
            quarantine_end: 0,
            outstanding_effect: None,
            island: None,
            source_request: None,
        });
        for raw in &mut stored.raw {
            raw.allocate()?;
        }
        for state in [
            &mut stored.before,
            &mut stored.restored_entry,
            &mut stored.final_state,
        ] {
            state.allocate()?;
        }
        stored.final_maps.allocate()?;
        stored.before.save(before)?;
        let bytes = base_bytes()?
            .checked_add(stored.dynamic_bytes()?)
            .ok_or(invalid("exec journal allocation size overflows"))?;
        check_time(until)?;
        // Burning preparation is irreversible, including a later abandoned box.
        guard.prepared = true;
        guard.allocated_bytes = bytes;
        Ok(PreparedExecAttempt {
            archive: Arc::clone(&self.archive),
            attempt: stored,
            bytes,
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn attach(
        &mut self,
        mut prepared: PreparedExecAttempt,
    ) -> Result<ExecAttemptHandle, LaunchError> {
        if !Arc::ptr_eq(&self.archive, &prepared.archive) {
            return Err(invalid("exec journal prepared archive differs"));
        }
        let mut guard = lock(&self.archive);
        if !guard.prepared
            || guard.attempt.is_some()
            || guard.closing
            || guard.poisoned
            || guard.first_failure.is_some()
            || guard.session != prepared.attempt.id.session
            || guard.allocated_bytes != prepared.bytes
        {
            return Err(invalid("exec journal attachment is stale or closed"));
        }
        check_time(prepared.attempt.until)?;
        prepared.attempt.append(ExecJournalFact::Attached)?;
        let handle = ExecAttemptHandle {
            id: prepared.attempt.id,
            archive: Arc::as_ptr(&self.archive) as usize,
        };
        guard.attempt = Some(prepared.attempt);
        Ok(handle)
    }
    pub(in crate::linux::remote::dynamic::owner) fn observer(
        &self,
        handle: ExecAttemptHandle,
    ) -> Result<ExecJournalObserver, LaunchError> {
        if !handle_matches(&self.archive, handle) {
            return Err(invalid("exec journal handle belongs to another archive"));
        }
        attempt(&mut lock(&self.archive), handle)?;
        Ok(ExecJournalObserver {
            archive: Arc::clone(&self.archive),
            handle,
            _thread: PhantomData,
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn original_restore_attempt(
        &self,
        handle: ExecAttemptHandle,
    ) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            handle,
            ExecJournalStage::OriginalRestore,
            |attempt| {
                check_time(attempt.until)?;
                if attempt.native_phase != NativePhase::Attached {
                    return Err(invalid("exec journal original restoration order differs"));
                }
                if attempt
                    .fact_count
                    .checked_add(2)
                    .is_none_or(|count| count > FACTS)
                {
                    return Err(invalid("exec journal restoration pair capacity exhausted"));
                }
                attempt.append(ExecJournalFact::RestoreAttempt)?;
                attempt.native_phase = NativePhase::RestoreStarted;
                Ok(())
            },
        )
    }
    pub(in crate::linux::remote::dynamic::owner) fn original_restore_complete(
        &self,
        handle: ExecAttemptHandle,
    ) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            handle,
            ExecJournalStage::OriginalRestore,
            |attempt| {
                if attempt.native_phase != NativePhase::RestoreStarted {
                    return Err(invalid("exec journal restoration completion differs"));
                }
                attempt.append(ExecJournalFact::RestoreComplete)?;
                attempt.native_phase = NativePhase::Restored;
                Ok(())
            },
        )
    }
    pub(in crate::linux::remote::dynamic::owner) fn sources_requested(
        &self,
        handle: ExecAttemptHandle,
        request: u64,
        stop: &AdmissionStop,
        image_count: usize,
        byte_count: usize,
    ) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            handle,
            ExecJournalStage::Sources,
            |attempt| {
                check_time(attempt.until)?;
                if attempt.native_phase != NativePhase::MapsComplete
                    || request == 0
                    || !(1..=64).contains(&image_count)
                    || byte_count == 0
                    || byte_count > 64 * MAP_BYTES
                    || attempt.final_stop != Some((&stop.token).into())
                    || attempt.replacement != Some(stop.identity)
                    || stop.signal.is_some()
                {
                    return Err(invalid("exec journal source request binding differs"));
                }
                attempt.append(ExecJournalFact::SourcesRequested {
                    request,
                    stop: (&stop.token).into(),
                    images: image_count,
                    bytes: byte_count,
                })?;
                attempt.source_request = Some(request);
                attempt.native_phase = NativePhase::SourcesRequested;
                Ok(())
            },
        )
    }
    pub(in crate::linux::remote::dynamic::owner) fn sources_accepted(
        &self,
        handle: ExecAttemptHandle,
        request: u64,
        heads: usize,
    ) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            handle,
            ExecJournalStage::Sources,
            |attempt| {
                check_time(attempt.until)?;
                if attempt.native_phase != NativePhase::SourcesRequested
                    || attempt.source_request != Some(request)
                    || heads == 0
                {
                    return Err(invalid("exec journal source acceptance differs"));
                }
                attempt.append(ExecJournalFact::SourcesAccepted { request, heads })?;
                attempt.native_phase = NativePhase::SourcesAccepted;
                Ok(())
            },
        )
    }
    pub(in crate::linux::remote::dynamic::owner) fn admission_complete(
        &self,
        handle: ExecAttemptHandle,
        stop: &AdmissionStop,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            handle,
            ExecJournalStage::Admission,
            |attempt| {
                check_time(attempt.until)?;
                if attempt.native_phase != NativePhase::SourcesAccepted
                    || !attempt.final_state.equals(state)
                    || attempt.final_stop != Some((&stop.token).into())
                    || attempt.replacement != Some(stop.identity)
                    || stop.signal.is_some()
                {
                    return Err(invalid("exec journal admission completion differs"));
                }
                attempt.append(ExecJournalFact::AdmissionComplete {
                    stop: (&stop.token).into(),
                })?;
                attempt.native_phase = NativePhase::Complete;
                Ok(())
            },
        )
    }
    pub(in crate::linux::remote::dynamic::owner) fn fail_error(&self, error: &LaunchError) {
        lock(&self.archive).fail(failure(error));
    }
    pub(in crate::linux::remote::dynamic::owner) fn fail_panic(&self) {
        lock(&self.archive).fail(KernelFailureKind::CaughtPanic);
    }
    pub(in crate::linux::remote::dynamic::owner) fn fail_gate(&self, error: &GateError) {
        lock(&self.archive).fail(match error {
            GateError::Control(error) => failure(error),
            _ => KernelFailureKind::AdmissionRejected,
        });
    }
    pub(in crate::linux::remote::dynamic::owner) fn panic_scope(&self) -> ExecJournalUnwind {
        ExecJournalUnwind {
            archive: Arc::clone(&self.archive),
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn begin_cleanup(&self) {
        let mut guard = lock(&self.archive);
        if guard
            .attempt
            .as_ref()
            .is_some_and(|attempt| attempt.native_phase != NativePhase::Complete)
        {
            guard.fail(KernelFailureKind::Cancelled);
        }
        guard.closing = true;
        guard.stage = ExecJournalStage::Closing;
    }
    pub(in crate::linux::remote::dynamic::owner) fn finish_cleanup(&self, complete: bool) {
        self.begin_cleanup();
        let mut guard = lock(&self.archive);
        guard.cleanup_complete = Some(guard.cleanup_complete.unwrap_or(true) && complete);
    }
    /// The closure may only interpret borrowed evidence. It must not recurse
    /// into this archive or perform native/control operations while locked.
    pub(in crate::linux::remote::dynamic::owner) fn with_raw_maps<T>(
        &self,
        handle: ExecAttemptHandle,
        ordinal: u8,
        view: impl FnOnce(&ExecMapsRecord, &[u8]) -> T,
    ) -> Result<T, LaunchError> {
        self.with_maps(handle, Some(ordinal), view)
    }
    /// Same evidence-only borrowing contract as with_raw_maps; no snapshot copy.
    pub(in crate::linux::remote::dynamic::owner) fn with_quarantined_maps<T>(
        &self,
        handle: ExecAttemptHandle,
        view: impl FnOnce(&ExecMapsRecord, &[u8]) -> T,
    ) -> Result<T, LaunchError> {
        self.with_maps(handle, None, view)
    }
    pub(super) fn with_maps<T>(
        &self,
        handle: ExecAttemptHandle,
        ordinal: Option<u8>,
        view: impl FnOnce(&ExecMapsRecord, &[u8]) -> T,
    ) -> Result<T, LaunchError> {
        if !handle_matches(&self.archive, handle) {
            return Err(invalid("exec journal handle belongs to another archive"));
        }
        let guard = lock(&self.archive);
        let stored = guard
            .attempt
            .as_deref()
            .filter(|attempt| attempt.id == handle.id)
            .ok_or(invalid("exec journal map attempt differs"))?;
        let maps = if let Some(ordinal) = ordinal {
            &stored
                .raw
                .get(usize::from(ordinal))
                .filter(|_| usize::from(ordinal) < stored.raw_count)
                .ok_or(invalid("exec journal raw map ordinal is absent"))?
                .record
                .maps
        } else {
            &stored.final_maps.record
        };
        Ok(view(maps, &maps.initialized[..maps.observed_bytes]))
    }
}
impl Drop for ExecJournalUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let mut guard = lock(&self.archive);
            if guard
                .attempt
                .as_ref()
                .is_some_and(|attempt| attempt.native_phase != NativePhase::Complete)
            {
                guard.fail(KernelFailureKind::CaughtPanic);
            }
        }
    }
}

impl ExecJournalWriter {
    /// Borrows both source-acquisition map observations under one lock. Only
    /// interpret/copy explicitly budgeted metadata here; no native operation.
    pub(in crate::linux::remote::dynamic::owner) fn with_source_maps<T>(
        &self,
        handle: ExecAttemptHandle,
        view: impl FnOnce(ExecSourceMaps<'_>) -> T,
    ) -> Result<T, LaunchError> {
        if !handle_matches(&self.archive, handle) {
            return Err(invalid("exec journal handle belongs to another archive"));
        }
        let guard = lock(&self.archive);
        if guard.poisoned || guard.closing || guard.first_failure.is_some() {
            return Err(invalid(
                "exec journal source map archive is closed or failed",
            ));
        }
        let stored = guard
            .attempt
            .as_deref()
            .filter(|attempt| attempt.id == handle.id)
            .ok_or(invalid("exec journal source map attempt differs"))?;
        let (ordinal, exit_stop, replacement) = stored.facts[..stored.fact_count]
            .iter()
            .flatten()
            .find_map(|fact| match fact {
                ExecJournalFact::Validated {
                    phase: ExecValidatedPhase::Exit,
                    ordinal,
                    stop,
                    identity,
                } => Some((*ordinal, *stop, *identity)),
                _ => None,
            })
            .ok_or(invalid("exec journal validated EXIT maps are absent"))?;
        let final_stop = stored
            .final_stop
            .ok_or(invalid("exec journal final maps stop is absent"))?;
        let exit = &stored.raw[usize::from(ordinal)].record.maps;
        let quarantine = &stored.final_maps.record;
        if exit.status != ExecMapsStatus::Complete || quarantine.status != ExecMapsStatus::Complete
        {
            return Err(invalid("exec journal source maps are incomplete"));
        }
        Ok(view(ExecSourceMaps {
            previous: stored.pending.task,
            replacement,
            exit_ordinal: ordinal,
            exit_stop,
            final_stop,
            exit,
            exit_bytes: &exit.initialized[..exit.observed_bytes],
            quarantine,
            quarantine_bytes: &quarantine.initialized[..quarantine.observed_bytes],
        }))
    }
}
