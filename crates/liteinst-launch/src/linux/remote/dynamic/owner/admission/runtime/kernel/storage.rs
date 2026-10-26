//! Pre-effect storage and monotone charging for one original-site invocation.
use super::*;

pub(super) const MAP_BYTES: usize = 64 * 1024;
pub(super) const SOURCE_READS: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KernelStage {
    Allocated,
    SourceBefore,
    Prepared,
    Pending,
    SourceAfterProvider,
    Native,
    Census,
    Returned,
    Terminal,
    Fault,
}

pub(in crate::linux::remote::dynamic::owner::admission::runtime) struct RuntimeKernelAttempt {
    pub(super) until: Instant,
    pub(super) stage: KernelStage,
    pub(super) first_failure: Option<(KernelStage, selected::SelectedFailure)>,
    pub(super) reservation: Reservation,
    pub(super) origin: OriginId,
    pub(super) token: RuntimePendingToken,
    pub(super) stop: AdmissionStop,
    pub(super) before: ObservedStop,
    pub(super) source: SourceWindowId,
    pub(super) operation: RuntimeKernelOperation,
    pub(super) identity: Option<RuntimeKernelIdentity>,
    pub(super) input: Option<SelectedInput>,
    pub(super) decision: Option<ProviderDecision>,
    pub(super) checks: KernelSourceChecks,
    pub(super) native: PreparedRuntimeKernel,
    pub(super) prepared: Option<Box<PreparedRuntimeKernelCensus>>,
    pub(super) journal: Option<PreparedRuntimeJournal>,
    pub(super) handle: Option<RuntimeKernelHandle>,
    pub(super) sink: Option<RuntimeJournalSink>,
    pub(super) public: Option<Box<DynamicAdmissionCompletion>>,
    // Includes detached public payloads and journal payloads after transfer.
    pub(super) transferred: usize,
    pub(super) journal_bytes: usize,
    pub(super) debited: usize,
}

pub(super) struct KernelSourceChecks {
    pub(super) bytes: [Vec<u8>; SOURCE_READS],
    pub(super) progress: [SourceReadProgress; SOURCE_READS],
    pub(super) identity: Vec<u8>,
    pub(super) checkpoint: ObservedStop,
    pub(super) stop: AdmissionStop,
}

pub(super) fn exact_vec<T>(capacity: usize) -> Result<Vec<T>, GateError> {
    if capacity == 0 {
        return Ok(Vec::new());
    }
    let layout = std::alloc::Layout::array::<T>(capacity)
        .map_err(|_| refused("runtime kernel allocation layout overflows"))?;
    if layout.size() == 0 {
        return Err(refused("runtime kernel zero-sized storage differs"));
    }
    // SAFETY: checked nonzero global allocation with T's alignment. A null
    // result returns before any native observation or effect can begin.
    let pointer = unsafe { std::alloc::alloc(layout) }.cast::<T>();
    if pointer.is_null() {
        return Err(refused("runtime kernel allocation failed"));
    }
    // SAFETY: no element is initialized. Vec owns this exact capacity and uses
    // the same global allocator/alignment/Layout for destruction. Hidden
    // allocator metadata is outside the managed evidence capacity claim.
    Ok(unsafe { Vec::from_raw_parts(pointer, 0, capacity) })
}
pub(super) fn bytes(length: usize) -> Result<Vec<u8>, GateError> {
    let mut result = exact_vec(length)?;
    result.resize(length, 0);
    Ok(result)
}
pub(super) fn refused(reason: &'static str) -> GateError {
    GateError::Refused(reason)
}
pub(super) fn native_error(error: GateError) -> LaunchError {
    match error {
        GateError::Control(error) => error,
        GateError::Refused(reason) => LaunchError::Invalid(reason),
        _ => LaunchError::Invalid("runtime kernel source or budget verification failed"),
    }
}
pub(super) fn empty_observed(before: &ObservedStop) -> ObservedStop {
    ObservedStop {
        token: before.token.clone(),
        task: before.task,
        logical_pc: before.logical_pc,
        registers: before.registers,
        xstate: Vec::new(),
        signal_mask: before.signal_mask,
        phase: before.phase,
        signal: before.signal.clone(),
    }
}
pub(super) fn copy_state(target: &mut Vec<u8>, value: &[u8]) -> Result<(), GateError> {
    if !(512..MAX_XSTATE).contains(&value.len()) || target.capacity() != MAX_XSTATE {
        return Err(refused(
            "runtime kernel state extent exceeds exact allocation",
        ));
    }
    target.clear();
    target.extend_from_slice(value);
    Ok(())
}
pub(super) fn input_bytes(input: &SelectedInput) -> Result<usize, GateError> {
    let bytes = input.instruction().retained_capacity();
    if input.instruction().bytes() != [0x0f, 0x05] || bytes > 15 {
        return Err(refused("runtime kernel encoding capacity differs"));
    }
    Ok(bytes)
}
pub(super) fn public_bytes(public: &DynamicAdmissionCompletion) -> Result<usize, GateError> {
    add(
        size_of::<DynamicAdmissionCompletion>(),
        add(
            input_bytes(&public.selected.input)?,
            add(
                public.selected.before_xstate.capacity(),
                public.selected.xstate.capacity(),
            )?,
        )?,
    )
}

pub(super) fn reservation_charge(
    window: usize,
    index_capacity: usize,
    operation: RuntimeKernelOperation,
    journal: &RuntimeJournalShape,
) -> Result<BudgetCharge, GateError> {
    if window == 0 || window > MAP_BYTES {
        return Err(refused("runtime kernel source reservation differs"));
    }
    // Inline native and unattached journal headers already live in the root
    // shell. Their own shapes supply only the separately allocated remainder.
    let native = RuntimeKernelShape::reservation_bytes()?
        .checked_sub(size_of::<PreparedRuntimeKernel>())
        .ok_or_else(|| refused("runtime kernel native embedded header differs"))?;
    let journal_payload = journal
        .reservation_bytes()
        .checked_sub(size_of::<PreparedRuntimeJournal>())
        .ok_or_else(|| refused("runtime kernel journal embedded header differs"))?;
    let mut root = add(
        size_of::<RuntimeKernelAttempt>(),
        mul(index_capacity, size_of::<Box<RuntimeKernelAttempt>>())?,
    )?;
    root = add(root, add(native, journal_payload)?)?;
    root = add(
        root,
        add(mul(SOURCE_READS, window)?, MAP_BYTES + 2 * MAX_XSTATE)?,
    )?;
    root = add(root, 15)?; // retained original SelectedInput encoding
    root = add(root, size_of::<RuntimeProviderInput>() + 15)?;
    root = add(root, size_of::<crate::selected::FaultedInstruction>() + 15)?;
    if operation.returns() {
        root = add(
            root,
            size_of::<DynamicAdmissionCompletion>() + 2 * MAX_XSTATE + 15,
        )?;
    }
    // Fixed managed query/evidence temporaries, separate from retained payload.
    // Additive bounds cover nesting without claiming whole process RSS/stack.
    let mut temporary = add(
        CapturedRuntimeRead::temporary_bytes(),
        CapturedKernelRead::temporary_bytes(),
    )?;
    temporary = add(
        temporary,
        size_of::<RuntimeKernelBinding<'_>>()
            + size_of::<FetchGeometry>()
            + size_of::<BindingRequest<'_>>()
            + size_of::<KernelObserver<'_, '_>>()
            + 2 * size_of::<ControlLineage>()
            + size_of::<crate::selected::DecodedSelected>()
            + 15,
    )?;
    temporary = add(temporary, RuntimeKernelShape::temporary_bytes()?)?;
    temporary = add(temporary, ControlProfile::temporary_bytes()?)?;
    temporary = add(temporary, namespace::temporary_bytes())?;
    root = add(root, temporary)?;
    let mut charge = runtime_kernel_census_charge(operation).map_err(census_error)?;
    charge.source_fact_bytes = add(charge.source_fact_bytes, root)?;
    Ok(charge)
}

impl RuntimeKernelAttempt {
    pub(super) fn root_bytes(&self) -> Result<usize, GateError> {
        let mut total = add(size_of::<Self>(), self.native.payload_bytes()?)?;
        total = add(total, self.before.xstate.capacity())?;
        total = add(total, self.checks.checkpoint.xstate.capacity())?;
        total = add(total, self.checks.identity.capacity())?;
        for bytes in &self.checks.bytes {
            total = add(total, bytes.capacity())?;
        }
        if let Some(input) = &self.input {
            total = add(total, input_bytes(input)?)?;
        }
        if let Some(public) = &self.public {
            total = add(total, public_bytes(public)?)?;
        }
        add(total, add(self.transferred, self.journal_bytes)?)
    }
    pub(super) fn account(&mut self, census: &mut ResumeCensus) -> Result<(), GateError> {
        let actual = self.root_bytes()?;
        let delta = actual
            .checked_sub(self.debited)
            .ok_or_else(|| refused("runtime kernel evidence debit regressed"))?;
        if delta == 0 {
            return Ok(());
        }
        census
            .account_external(
                self.reservation,
                BudgetCharge {
                    source_fact_bytes: delta,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        self.debited = actual;
        Ok(())
    }
    pub(super) fn fail(&mut self, error: Option<&GateError>) {
        if self.first_failure.is_some() {
            return;
        }
        use selected::SelectedFailure as Failure;
        let failure = match error {
            None => Failure::Unwound,
            Some(GateError::Refused(reason)) => Failure::Refused(reason),
            Some(GateError::Selected(error)) => Failure::Semantics(*error),
            Some(GateError::Control(LaunchError::Invalid(reason))) => Failure::Invalid(reason),
            Some(GateError::Control(LaunchError::System { operation, source })) => {
                Failure::System(operation, source.raw_os_error())
            }
            Some(GateError::Control(LaunchError::Timeout(operation))) => {
                Failure::Timeout(operation)
            }
            Some(GateError::Control(LaunchError::Child { status })) => Failure::Child(*status),
            Some(_) => Failure::Other,
        };
        self.first_failure = Some((self.stage, failure));
    }
    pub(super) fn sync_journal(&mut self) {
        let (Some(identity), Some(sink)) = (&self.identity, &mut self.sink) else {
            return;
        };
        // Synchronization performs no native request and never replaces a
        // finalized observation. Preserve available prefixes independently.
        for ordinal in 0..9 {
            if let Some(raw) = self.native.raw_view(ordinal) {
                let _ = sink.sync_raw(identity, raw);
            }
        }
        if let Some((kind, stop, state)) = self.native.last_readback_view() {
            let _ = sink.sync_readback(identity, kind, stop, state);
        }
    }
}

impl KernelSourceChecks {
    pub(super) fn checkpoint(
        &mut self,
        checkpoint: NativeCheckpoint<'_>,
    ) -> Result<(), LaunchError> {
        let stop = checkpoint.stop;
        let state = checkpoint.state;
        if stop.signal.is_some() || stop.phase != AdmissionPhase::Restored {
            return Err(LaunchError::Invalid(
                "runtime kernel source checkpoint phase differs",
            ));
        }
        copy_state(&mut self.checkpoint.xstate, &state.xstate).map_err(native_error)?;
        self.checkpoint.token = stop.token.clone();
        self.checkpoint.task = stop.identity;
        self.checkpoint.logical_pc = state.registers.rip;
        self.checkpoint.registers = state.registers;
        self.checkpoint.signal_mask = state.mask;
        self.checkpoint.phase = StopPhase::UserCheckpoint;
        self.checkpoint.signal = None;
        self.stop = stop.clone();
        Ok(())
    }
}
