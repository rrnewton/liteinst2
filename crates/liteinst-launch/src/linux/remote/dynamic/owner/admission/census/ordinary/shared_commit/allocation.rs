use super::*;

impl SharedOrdinaryPreparation {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            prepared: None,
            started: false,
            first_failure: None,
            unwound: false,
            settlement: None,
            #[cfg(test)]
            fault: AllocationFault::default(),
        }
    }

    /// The runtime installs `self` before this call. Every new owner is
    /// installed immediately, and even a failed/unwound allocation is settled
    /// once from actual retained capacities before returning/rethrowing.
    pub(in crate::linux::remote::dynamic::owner::admission) fn prepare(
        &mut self,
        census: &mut ResumeCensus,
        reservation: Reservation,
        actual: &RuntimeInstructionBinding<'_>,
    ) -> Result<(), CensusError> {
        self.prepare_with(census, reservation, |census, prepared| {
            census.prepare_shared_ordinary(reservation, actual, prepared)
        })
    }

    fn prepare_with(
        &mut self,
        census: &mut ResumeCensus,
        reservation: Reservation,
        prepare: impl FnOnce(
            &ResumeCensus,
            &mut PreparedSharedOrdinaryCensus,
        ) -> Result<(), CensusError>,
    ) -> Result<(), CensusError> {
        if self.started
            || self.prepared.is_some()
            || self.settlement.is_some()
            || self.first_failure.is_some()
            || self.unwound
        {
            return Err(CensusError::InvalidConsumption);
        }
        self.started = true;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[cfg(test)]
            if self.fault.before == Some(0) {
                return Err(CensusError::Allocation);
            }
            self.prepared = Some(
                exact_storage::value(PreparedSharedOrdinaryCensus::empty())
                    .map_err(allocation_error)?,
            );
            #[cfg(test)]
            {
                self.prepared
                    .as_mut()
                    .expect("installed shared preparation")
                    .fault = self.fault;
                if self.fault.after == Some(0) {
                    std::panic::panic_any(0x5348_4152_u32);
                }
            }
            prepare(
                census,
                self.prepared
                    .as_mut()
                    .expect("installed shared preparation"),
            )
        }));
        match &outcome {
            Ok(Err(error)) => {
                self.first_failure.get_or_insert(*error);
                if let Some(value) = self.prepared.as_mut() {
                    value.fail(*error);
                }
            }
            Err(_) => self.mark_aborted(),
            Ok(Ok(())) => {}
        }
        let settlement = self.settle(census, reservation);
        match outcome {
            Ok(Ok(())) => settlement.map(|_| ()),
            // Settlement has its own retained result. It never replaces the
            // original preparation error or the original unwind payload.
            Ok(Err(error)) => Err(error),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn settle(
        &mut self,
        census: &mut ResumeCensus,
        reservation: Reservation,
    ) -> Result<usize, CensusError> {
        if self.settlement.is_some() {
            return Err(CensusError::InvalidConsumption);
        }
        let result = (|| {
            let actual = self
                .prepared
                .as_ref()
                .map_or(Ok(0), |p| p.allocated_bytes())?;
            if actual > shared_preparation_bytes()? {
                return Err(CensusError::Capacity);
            }
            if let Some(prepared) = &self.prepared {
                let installed = add(
                    size_of::<PreparedSharedOrdinaryCensus>(),
                    add(prepared.installed_bytes, prepared.history.installed_bytes())?,
                )?;
                if actual != installed {
                    return Err(CensusError::Capacity);
                }
                if prepared.preparation_debit.is_some() {
                    return Err(CensusError::InvalidConsumption);
                }
            }
            census.account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: actual,
                    ..BudgetCharge::default()
                },
            )?;
            if let Some(prepared) = self.prepared.as_mut() {
                prepared.preparation_debit = Some(actual);
            }
            Ok(actual)
        })();
        self.settlement = Some(result);
        result
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn prepared_mut(
        &mut self,
    ) -> Result<&mut PreparedSharedOrdinaryCensus, CensusError> {
        if self.first_failure.is_some() || self.unwound || !matches!(self.settlement, Some(Ok(_))) {
            return Err(CensusError::InvalidConsumption);
        }
        let value = self
            .prepared
            .as_deref_mut()
            .ok_or(CensusError::InvalidConsumption)?;
        if value.stage != Stage::Ready || value.first_failure.is_some() || value.unwound {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(value)
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        if !self.started {
            return;
        }
        // Completed historical preparation is not rewritten by a later native
        // unwind. The runtime/native owners retain that later failure.
        if let Some(value) = self.prepared.as_mut() {
            if matches!(value.stage, Stage::Ready | Stage::Committed) {
                return;
            }
            value.mark_aborted();
        }
        self.unwound = true;
    }
}

impl PreparedSharedOrdinaryCensus {
    fn before_allocation(&mut self, ordinal: usize) -> Result<(), CensusError> {
        self.allocation_ordinal = Some(ordinal);
        #[cfg(test)]
        if self.fault.before == Some(ordinal) {
            return Err(CensusError::Allocation);
        }
        Ok(())
    }
    fn after_allocation(&self, _ordinal: usize) {
        #[cfg(test)]
        if self.fault.after == Some(_ordinal) {
            std::panic::panic_any(0x5348_4152_u32);
        }
    }
    fn allocate(&mut self, binding: Binding) -> Result<(), CensusError> {
        if self.stage != Stage::Empty
            || self.binding.is_some()
            || self.first_failure.is_some()
            || self.unwound
            || self.preparation_debit.is_some()
            || self.installed_bytes != 0
        {
            return Err(CensusError::InvalidConsumption);
        }
        self.stage = Stage::Allocating;
        self.binding = Some(binding);
        let owner = OriginId {
            census: binding.census,
            serial: binding.candidate_serial,
        };
        self.before_allocation(1)?;
        self.history.allocate_payloads(binding, owner)?;
        self.after_allocation(1);
        for index in 0..2 {
            let next = add(self.installed_bytes, MAX_XSTATE_BYTES)?;
            self.before_allocation(index + 2)?;
            self.origins[index] =
                exact_storage::empty_bytes(MAX_XSTATE_BYTES).map_err(allocation_error)?;
            self.installed_bytes = next;
            self.after_allocation(index + 2);
        }
        let next = add(self.installed_bytes, size_of::<OrdinaryEvidence>())?;
        self.before_allocation(4)?;
        self.evidence = Some(
            exact_storage::one(OrdinaryEvidence {
                binding,
                trace: None,
            })
            .map_err(allocation_error)?,
        );
        self.installed_bytes = next;
        self.after_allocation(4);
        if self.allocated_bytes()? != shared_preparation_bytes()? {
            return Err(CensusError::Capacity);
        }
        Ok(())
    }
}

impl ResumeCensus {
    fn prepare_shared_ordinary(
        &self,
        reservation: Reservation,
        actual: &RuntimeInstructionBinding<'_>,
        prepared: &mut PreparedSharedOrdinaryCensus,
    ) -> Result<(), CensusError> {
        let before = self.current_observation(actual.origin())?;
        if actual.before() != before
            || actual.stop().token != before.token
            || actual.stop().identity != before.task
            || actual.stop().signal.is_some()
            || !matches!(
                actual.stop().phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
        {
            return Err(CensusError::StaleObservation);
        }
        let source = SourceRecord::from(actual.source_id());
        let encoding = validate_candidate(source, actual.candidate(), before)?;
        self.prepare_shared_model(
            reservation,
            SharedRequest {
                origin: actual.origin(),
                execution: actual.execution(),
                source,
                encoding,
                until: actual.until(),
            },
            prepared,
        )
    }

    fn prepare_shared_model(
        &self,
        reservation: Reservation,
        request: SharedRequest,
        prepared: &mut PreparedSharedOrdinaryCensus,
    ) -> Result<(), CensusError> {
        let SharedRequest {
            origin,
            execution,
            source,
            encoding,
            until,
        } = request;
        self.check_reserved(reservation, ordinary_shared_census_charge()?)?;
        let before = self.current_observation(origin)?;
        if execution.session != self.session
            || execution.serial == 0
            || source.identity.mapping == 0
            || source.identity.generation != self.state.generation
        {
            return Err(CensusError::IdentityMismatch);
        }
        if before.phase != StopPhase::UserCheckpoint
            || before.signal.is_some()
            || before.task.generation != 0
            || before.logical_pc != encoding.pc
            || Instant::now() >= until
            || !(512..MAX_XSTATE_BYTES).contains(&before.xstate.len())
        {
            return Err(CensusError::StaleObservation);
        }
        self.runtime_register_provenance(origin)?;
        if self.state.origins.len() == self.state.origins.capacity()
            || self
                .state
                .history
                .capacity()
                .saturating_sub(self.state.history.len())
                < WITNESSES
        {
            return Err(CensusError::Capacity);
        }
        self.state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        let binding = Binding {
            census: self.identity,
            reservation,
            candidate_serial: self.state.next_serial,
            origin,
            execution,
            source,
            encoding,
            until,
        };
        prepared.allocate(binding)?;
        prepared.history.stage_prior(before)?;
        prepared.stage = Stage::Ready;
        Ok(())
    }
}
