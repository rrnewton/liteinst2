//! Prospective bounds, installed prefixes and monotone actual-byte settlement.
use super::*;

fn empty_observed(before: &ObservedStop) -> ObservedStop {
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
fn initialize_bytes(slot: &mut Vec<u8>, size: usize) -> Result<(), GateError> {
    if slot.capacity() != 0 || !slot.is_empty() {
        return Err(GateError::Refused("runtime stack allocation slot reused"));
    }
    *slot = exact_storage::empty_bytes(size).map_err(allocation_error)?;
    // The owner is installed before initialization, which cannot allocate.
    slot.resize(size, 0);
    Ok(())
}

// Fixed root request/error/result records in addition to the borrowed source,
// native and census components' explicitly owned temporary bounds.
fn root_request_temporary_bytes() -> Result<usize, GateError> {
    let mut bytes = 0;
    for term in [
        2 * size_of::<Failure>(),
        2 * size_of::<GateError>(),
        size_of::<PendingPreparation>(),
        2 * size_of::<BudgetCharge>(),
        size_of::<Reservation>(),
        size_of::<Option<OriginId>>(),
    ] {
        bytes = add(bytes, term)?;
    }
    Ok(bytes)
}

impl RuntimeStackState {
    pub(super) fn empty(capacity: usize, reservation: usize) -> Self {
        Self {
            profile: PreparedStackProfileCapture::empty(),
            attempts: Box::default(),
            calls: RuntimeCallLedger::empty(),
            capacity,
            count: 0,
            startup_started: false,
            startup_complete: false,
            startup_ordinal: None,
            #[cfg(test)]
            startup_fault: AllocationFault::default(),
            startup_reserved: reservation,
            startup_actual: 0,
            startup_settled: 0,
            #[cfg(test)]
            intervention: None,
            #[cfg(test)]
            before_opening: None,
            #[cfg(test)]
            fail_attempt_header: false,
            #[cfg(test)]
            panic_after_attempt_header: false,
            #[cfg(test)]
            allocation_config: None,
            #[cfg(test)]
            allocation_config_used: false,
            #[cfg(test)]
            native_intervention: None,
            pending: None,
            failure: None,
            settlement_failure: None,
        }
    }
    /// The whole RuntimeOwner charges every embedded header once. Only new
    /// separately owned payload and the explicit acquisition temporary remain.
    pub(super) fn startup_reservation(capacity: usize) -> Result<usize, GateError> {
        if capacity == 0 {
            return Err(GateError::Refused("runtime stack history is empty"));
        }
        let slots = mul(capacity, size_of::<Option<Box<RuntimeStackAttempt>>>())?;
        std::alloc::Layout::array::<Option<Box<RuntimeStackAttempt>>>(capacity)
            .map_err(|_| GateError::Refused("runtime stack history layout overflows"))?;
        let calls = payload(
            RuntimeCallLedger::reservation_bytes(capacity).map_err(census_error)?,
            size_of::<RuntimeCallLedger>(),
        )?;
        let profile = payload(
            PreparedStackProfileCapture::reservation_bytes()?,
            size_of::<PreparedStackProfileCapture>(),
        )?;
        add(
            add(profile, add(slots, calls)?)?,
            add(
                runtime_stack_native::acquire::temporary_bytes()?,
                root_request_temporary_bytes()?,
            )?,
        )
    }
    pub(super) fn startup_payload_bytes(&self) -> Result<usize, GateError> {
        let profile = payload(
            self.profile.allocated_bytes()?,
            size_of::<PreparedStackProfileCapture>(),
        )?;
        let calls = payload(
            self.calls.allocated_bytes().map_err(census_error)?,
            size_of::<RuntimeCallLedger>(),
        )?;
        add(
            profile,
            add(
                mul(
                    self.attempts.len(),
                    size_of::<Option<Box<RuntimeStackAttempt>>>(),
                )?,
                calls,
            )?,
        )
    }
    fn startup_before(&mut self, ordinal: usize) -> Result<(), GateError> {
        self.startup_ordinal = Some(ordinal);
        #[cfg(test)]
        if self.startup_fault.before == Some(ordinal) {
            return Err(GateError::Refused(
                "injected stack startup allocation failure",
            ));
        }
        Ok(())
    }
    fn startup_after(&self, _ordinal: usize) {
        #[cfg(test)]
        if self.startup_fault.after == Some(_ordinal) {
            std::panic::panic_any(0x5354_4152_u32);
        }
    }

    pub(super) fn allocate_startup(&mut self) -> Result<(), GateError> {
        if self.startup_started
            || self.failure.is_some()
            || self.pending.is_some()
            || self.count != 0
            || !self.attempts.is_empty()
            || self.startup_reserved != Self::startup_reservation(self.capacity)?
        {
            return Err(GateError::Refused(
                "runtime stack startup allocation reused",
            ));
        }
        self.startup_started = true;
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), GateError> {
                self.startup_before(0)?;
                self.profile.allocate_payloads()?;
                self.startup_actual = self.startup_payload_bytes()?;
                self.startup_after(0);
                self.startup_before(1)?;
                self.attempts =
                    exact_storage::empty_slots(self.capacity).map_err(allocation_error)?;
                self.startup_actual = self.startup_payload_bytes()?;
                self.startup_after(1);
                self.startup_before(2)?;
                self.calls
                    .allocate_payloads(self.capacity)
                    .map_err(census_error)?;
                self.startup_actual = self.startup_payload_bytes()?;
                self.startup_after(2);
                if self.startup_actual > self.startup_reserved || self.startup_ordinal != Some(2) {
                    return Err(GateError::Refused(
                        "runtime stack startup exceeds reservation",
                    ));
                }
                self.startup_complete = true;
                Ok(())
            }));
        let measured = self.startup_payload_bytes();
        if let Ok(bytes) = &measured {
            self.startup_actual = *bytes;
        }
        if let Err(error) = &measured {
            self.settlement_failure
                .get_or_insert(Failure::from_gate(error));
        }
        match result {
            Ok(Ok(())) => measured.map(|_| ()),
            Ok(Err(error)) => {
                self.failure.get_or_insert(Failure::from_gate(&error));
                Err(error)
            }
            Err(panic) => {
                self.failure.get_or_insert(Failure::Unwound);
                self.profile.mark_aborted();
                self.calls.mark_aborted();
                std::panic::resume_unwind(panic)
            }
        }
    }
    pub(super) fn capture_profile(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        boot: &super::super::super::super::bootstrap::BootstrapMm,
        sources: &PreparedInitialSources,
        until: Instant,
    ) -> Result<(), GateError> {
        if !self.startup_complete
            || self.failure.is_some()
            || self.settlement_failure.is_some()
            || self.startup_actual != self.startup_payload_bytes()?
            || self.startup_actual > self.startup_reserved
        {
            return Err(GateError::Refused(
                "runtime stack startup payload is incomplete",
            ));
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.profile
                .acquire(owner, native, boot, sources, until)
                .map_err(GateError::from)
        }));
        match result {
            Ok(result) => {
                if let Err(error) = &result {
                    self.failure.get_or_insert(Failure::from_gate(error));
                }
                result
            }
            Err(panic) => {
                self.failure.get_or_insert(Failure::Unwound);
                self.profile.mark_aborted();
                std::panic::resume_unwind(panic)
            }
        }
    }
    pub(super) fn settle_startup(
        &mut self,
        census: &mut ResumeCensus,
        reservation: Reservation,
    ) -> Result<(), GateError> {
        let actual = self.startup_payload_bytes()?;
        if !self.startup_complete
            || self.startup_settled != 0
            || self.failure.is_some()
            || self.settlement_failure.is_some()
            || actual != self.startup_actual
            || actual > self.startup_reserved
        {
            return Err(GateError::Refused(
                "runtime stack startup settlement differs",
            ));
        }
        census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: actual,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        self.startup_settled = actual;
        Ok(())
    }
}

pub(super) fn attempt_charge(window: usize, call: bool) -> Result<BudgetCharge, GateError> {
    let mut charge = stack_census_charge().map_err(census_error)?;
    let root_header = payload(
        payload(
            size_of::<RuntimeStackAttempt>(),
            size_of::<PreparedStackNative>(),
        )?,
        size_of::<PreparedStackOperandCapture>(),
    )?;
    let root_payload = add(mul(3, window)?, add(2 * MAX_XSTATE, MAP_BYTES)?)?;
    let mut bytes = add(
        add(root_header, root_payload)?,
        add(
            PreparedStackNative::reservation_bytes()?,
            PreparedStackOperandCapture::reservation_bytes()?,
        )?,
    )?;
    if call {
        bytes = add(
            bytes,
            PreparedCallRecord::reservation_bytes().map_err(census_error)?,
        )?;
    }
    let mut temporary = CapturedRuntimeRead::temporary_bytes();
    for term in [
        ControlProfile::temporary_bytes()?,
        size_of::<RuntimeStackBinding<'_, '_>>(),
        size_of::<StackBeforeContext<'_, '_>>(),
        size_of::<StackRequest<'_>>(),
        size_of::<SourceObserver<'_, '_, '_>>(),
        size_of::<maps::FetchGeometry>(),
        // The empty owning header exists before its exact Box is installed.
        // This managed temporary is distinct from the retained boxed header.
        size_of::<RuntimeStackAttempt>(),
        2 * size_of::<ControlLineage>(),
        PreparedStackNative::temporary_bytes()?,
        stack_census_temporary_bytes().map_err(census_error)?,
        root_request_temporary_bytes()?,
    ] {
        temporary = add(temporary, term)?;
    }
    charge.source_fact_bytes = add(charge.source_fact_bytes, add(bytes, temporary)?)?;
    Ok(charge)
}

impl RuntimeStackAttempt {
    pub(super) fn empty(
        pending: &PendingPreparation,
        stop: AdmissionStop,
        before: &ObservedStop,
        geometry: maps::FetchGeometry,
        window_bytes: usize,
        is_call: bool,
    ) -> Self {
        Self {
            reservation: pending.reservation,
            origin: pending.origin,
            serial: pending.serial,
            until: pending.until,
            source: SourceChecks {
                bytes: [Vec::new(), Vec::new(), Vec::new()],
                progress: [
                    SourceReadProgress::default(),
                    SourceReadProgress::default(),
                    SourceReadProgress::default(),
                ],
                identity: Vec::new(),
                checkpoint: empty_observed(before),
                checkpoint_stop: stop.clone(),
            },
            before: empty_observed(before),
            stop,
            native: PreparedStackNative::empty(),
            operand: PreparedStackOperandCapture::empty(),
            census: None,
            call: None,
            geometry,
            window_bytes,
            is_call,
            allocated: false,
            allocation_started: false,
            allocation_ordinal: None,
            #[cfg(test)]
            allocation_fault: AllocationFault::default(),
            #[cfg(test)]
            nested_fault: None,
            settled: 0,
            stage: pending.stage,
            failure: pending.failure,
            settlement_failure: None,
        }
    }
    fn allocation_before(&mut self, ordinal: usize) -> Result<(), GateError> {
        self.allocation_ordinal = Some(ordinal);
        #[cfg(test)]
        if self.allocation_fault.before == Some(ordinal) {
            return Err(GateError::Refused("injected root stack allocation failure"));
        }
        Ok(())
    }
    fn allocation_after(&self, _ordinal: usize) {
        #[cfg(test)]
        if self.allocation_fault.after == Some(_ordinal) {
            std::panic::panic_any(0x5354_4143_u32);
        }
    }
    fn allocate_payloads(&mut self) -> Result<(), GateError> {
        self.allocation_before(0)?;
        initialize_bytes(&mut self.before.xstate, MAX_XSTATE)?;
        self.allocation_after(0);
        self.allocation_before(1)?;
        initialize_bytes(&mut self.source.checkpoint.xstate, MAX_XSTATE)?;
        self.allocation_after(1);
        self.allocation_before(2)?;
        initialize_bytes(&mut self.source.identity, MAP_BYTES)?;
        self.allocation_after(2);
        for index in 0..3 {
            self.allocation_before(index + 3)?;
            initialize_bytes(&mut self.source.bytes[index], self.window_bytes)?;
            self.allocation_after(index + 3);
        }
        self.allocation_before(6)?;
        self.native.allocate_payloads(&self.geometry, self.until)?;
        self.allocation_after(6);
        self.allocation_before(7)?;
        self.operand.allocate_payloads()?;
        self.allocation_after(7);
        self.allocation_before(8)?;
        self.census =
            Some(exact_storage::value(PreparedStackCensus::empty()).map_err(allocation_error)?);
        self.allocation_after(8);
        #[cfg(test)]
        if let Some(fault) = self
            .nested_fault
            .filter(|fault| fault.target == StackAllocationTarget::Census)
        {
            let (before, after) = fault.pair();
            self.census
                .as_mut()
                .expect("installed stack census")
                .set_allocation_fault(before, after);
        }
        self.allocation_before(9)?;
        self.census
            .as_mut()
            .expect("installed stack census")
            .allocate_payloads()
            .map_err(census_error)?;
        self.allocation_after(9);
        if self.is_call {
            self.allocation_before(10)?;
            self.call =
                Some(exact_storage::value(PreparedCallRecord::empty()).map_err(allocation_error)?);
            self.allocation_after(10);
            #[cfg(test)]
            if let Some(fault) = self
                .nested_fault
                .filter(|fault| fault.target == StackAllocationTarget::Call)
            {
                let (before, after) = fault.pair();
                self.call
                    .as_mut()
                    .expect("installed stack call")
                    .set_allocation_fault(before, after);
            }
            self.allocation_before(11)?;
            self.call
                .as_mut()
                .expect("installed stack call")
                .allocate_payloads()
                .map_err(census_error)?;
            self.allocation_after(11);
        }
        if self.allocation_ordinal != Some(if self.is_call { 11 } else { 9 }) {
            return Err(GateError::Refused(
                "runtime stack allocation prefix is incomplete",
            ));
        }
        self.allocated = true;
        Ok(())
    }
    /// Header and root/native/A payload only. Separately boxed census and CALL
    /// owners settle themselves; moving a CALL to its ledger changes no debit.
    fn root_allocated_bytes(&self) -> Result<usize, GateError> {
        let mut bytes = size_of::<Self>();
        for amount in [
            self.before.xstate.capacity(),
            self.source.checkpoint.xstate.capacity(),
            self.source.identity.capacity(),
            payload(
                self.native.allocated_bytes()?,
                size_of::<PreparedStackNative>(),
            )?,
            payload(
                self.operand.allocated_bytes()?,
                size_of::<PreparedStackOperandCapture>(),
            )?,
        ] {
            bytes = add(bytes, amount)?;
        }
        for source in &self.source.bytes {
            bytes = add(bytes, source.capacity())?;
        }
        Ok(bytes)
    }
    fn settle_allocations(&mut self, census: &mut ResumeCensus) -> Result<(), GateError> {
        // Try each independent installed owner even after one settlement error.
        // Markers advance only after its actual census debit succeeds.
        let mut failure = None;
        let root = (|| {
            let actual = self.root_allocated_bytes()?;
            let delta = payload(actual, self.settled)?;
            census
                .account_external(
                    self.reservation,
                    BudgetCharge {
                        source_fact_bytes: delta,
                        ..BudgetCharge::default()
                    },
                )
                .map_err(census_error)?;
            self.settled = actual;
            Ok::<_, GateError>(())
        })();
        if let Err(error) = root {
            failure = Some(error);
        }
        if let Some(prepared) = &mut self.census {
            if let Err(error) = prepared
                .settle_storage(census, self.reservation)
                .map_err(census_error)
            {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        if let Some(call) = &mut self.call {
            if let Err(error) = call
                .settle_storage(census, self.reservation)
                .map_err(census_error)
            {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        match failure {
            None => Ok(()),
            Some(error) => {
                self.settlement_failure
                    .get_or_insert(Failure::from_gate(&error));
                Err(error)
            }
        }
    }
    pub(super) fn settle_unstarted_header(&mut self, census: &mut ResumeCensus) {
        if !self.allocation_started {
            // A test hook or future fallible step can fail after installation
            // but before the allocation wrapper begins. Preserve the primary
            // failure; settle_allocations retains any secondary discrepancy.
            let _ = self.settle_allocations(census);
        }
    }

    pub(super) fn allocate_and_settle(
        &mut self,
        census: &mut ResumeCensus,
    ) -> Result<(), GateError> {
        if self.allocation_started
            || self.allocated
            || self.failure.is_some()
            || self.settlement_failure.is_some()
            || self.stage != AttemptStage::Allocated
        {
            return Err(GateError::Refused(
                "runtime stack attempt allocation reused",
            ));
        }
        self.allocation_started = true;
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.allocate_payloads()));
        let settlement = self.settle_allocations(census);
        match result {
            Ok(Ok(())) => settlement,
            Ok(Err(error)) => {
                self.failure.get_or_insert(Failure::from_gate(&error));
                Err(error)
            }
            Err(panic) => {
                self.failure.get_or_insert(Failure::Unwound);
                self.native.mark_aborted();
                self.operand.mark_aborted();
                if let Some(prepared) = &mut self.census {
                    prepared.mark_aborted();
                }
                if let Some(call) = &mut self.call {
                    call.mark_aborted();
                }
                std::panic::resume_unwind(panic)
            }
        }
    }
    pub(super) fn copy_before(&mut self, before: &ObservedStop) -> Result<(), GateError> {
        if !self.allocated
            || self.failure.is_some()
            || self.settlement_failure.is_some()
            || self.before.token != before.token
            || self.before.task != before.task
            || self.before.registers != before.registers
            || self.before.logical_pc != before.logical_pc
            || self.before.signal_mask != before.signal_mask
            || self.before.phase != before.phase
            || self.before.signal != before.signal
            || !(512..MAX_XSTATE).contains(&before.xstate.len())
            || self.before.xstate.capacity() != MAX_XSTATE
            || self.source.checkpoint.xstate.capacity() != MAX_XSTATE
        {
            return Err(GateError::Refused(
                "runtime stack full input binding differs",
            ));
        }
        for bytes in [&mut self.before.xstate, &mut self.source.checkpoint.xstate] {
            bytes[..before.xstate.len()].copy_from_slice(&before.xstate);
            bytes.truncate(before.xstate.len());
        }
        Ok(())
    }
}
