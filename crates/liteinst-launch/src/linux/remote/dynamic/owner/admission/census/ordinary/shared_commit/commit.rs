use super::*;

fn checkpoint_with_payload(
    source: NativeCheckpoint<'_>,
    xstate: Vec<u8>,
    phase: StopPhase,
    signal: Option<DynamicSignalInfo>,
) -> ObservedStop {
    ObservedStop {
        token: source.stop.token.clone(),
        task: source.stop.identity,
        logical_pc: source.state.registers.rip,
        registers: source.state.registers,
        xstate,
        signal_mask: source.state.mask,
        phase,
        signal,
    }
}

impl PreparedSharedOrdinaryCensus {
    fn storage_matches(
        &self,
        binding: Binding,
        actual: &CompletionModel<'_>,
    ) -> Result<bool, CensusError> {
        if self.allocated_bytes()? != shared_preparation_bytes()?
            || self.preparation_debit != Some(shared_preparation_bytes()?)
            || self.installed_bytes
                != add(mul(2, MAX_XSTATE_BYTES)?, size_of::<OrdinaryEvidence>())?
            || self
                .origins
                .iter()
                .any(|bytes| bytes.capacity() != MAX_XSTATE_BYTES)
            || self
                .evidence
                .as_ref()
                .is_none_or(|v| v.len() != 1 || v[0].binding != binding)
        {
            return Ok(false);
        }
        // `archive()` checks exact installed capacities and its allocation
        // progress; `prior()` checks the actual initialized Prior payload.
        let archive = self.history.archive()?;
        let transferred = add(
            archive.allocated_bytes()?,
            add(mul(2, MAX_XSTATE_BYTES)?, size_of::<OrdinaryEvidence>())?,
        )?;
        if add(size_of::<Self>(), transferred)? != shared_preparation_bytes()? {
            return Ok(false);
        }
        self.history.prior()?;
        let trace = self.evidence.as_ref().expect("one retained evidence")[0].trace;
        match self.stage {
            Stage::Ready => Ok(trace.is_none()
                && self.origins.iter().all(Vec::is_empty)
                && self.copies == [CopyProgress::default(); 2]),
            Stage::Copied => Ok(trace == Some(actual.trace)
                && self.origins.iter().all(|v| v == &actual.step.state.xstate)
                && self.copies.iter().all(|p| {
                    p.started
                        && p.complete
                        && p.copied == actual.step.state.xstate.len()
                        && p.requested == p.copied
                })),
            _ => Ok(false),
        }
    }

    pub(super) fn copy_origins(&mut self, actual: &CompletionModel<'_>) -> Result<(), CensusError> {
        for index in 0..2 {
            let bytes = &mut self.origins[index];
            let progress = &mut self.copies[index];
            if !bytes.is_empty()
                || bytes.capacity() != MAX_XSTATE_BYTES
                || *progress != CopyProgress::default()
                || !(512..MAX_XSTATE_BYTES).contains(&actual.step.state.xstate.len())
            {
                return Err(CensusError::Capacity);
            }
            progress.started = true;
            progress.requested = actual.step.state.xstate.len();
            for part in actual.step.state.xstate.chunks(256) {
                bytes.extend_from_slice(part);
                progress.copied = bytes.len();
                #[cfg(test)]
                if self.copy_fault == Some((index, progress.copied)) {
                    return Err(CensusError::InvalidConsumption);
                }
            }
            progress.complete = true;
        }
        self.evidence
            .as_mut()
            .ok_or(CensusError::InvalidConsumption)?[0]
            .trace = Some(actual.trace);
        self.stage = Stage::Copied;
        Ok(())
    }
}

impl ResumeCensus {
    /// Sole production adapter: consumes the genuine completion once. Neither
    /// a shared reference nor a privately supplied model is a native permit.
    pub(in crate::linux::remote::dynamic::owner::admission) fn commit_shared_ordinary(
        &mut self,
        reservation: Reservation,
        actual: OwnedInstructionCompletion<'_>,
        prepared: &mut PreparedSharedOrdinaryCensus,
    ) -> Result<OrdinaryCensusResult, CensusError> {
        let model = CompletionModel {
            source: actual.source_id().into(),
            origin: actual.origin(),
            execution: actual.execution(),
            until: actual.until(),
            encoding: actual.encoding(),
            logical: actual.logical_before(),
            opening: actual.opening(),
            step: actual.step(),
            closing: actual.closing(),
            trace: actual.trace(),
        };
        let result = (|| {
            if prepared.stage != Stage::Ready {
                return Err(CensusError::InvalidConsumption);
            }
            self.validate_shared_model(reservation, &model, prepared)?;
            prepared.stage = Stage::Copying;
            // This additional predicate is capture provenance, not byte
            // interning: logical/opening and step/closing must borrow their
            // respective actual native canonical StateSlot snapshots.
            prepared.history.stage_native(&actual)?;
            prepared.copy_origins(&model)?;
            self.publish_shared_ordinary(reservation, &model, prepared)
        })();
        if let Err(error) = result {
            prepared.fail(error);
        }
        result
    }

    pub(super) fn publish_shared_ordinary(
        &mut self,
        reservation: Reservation,
        actual: &CompletionModel<'_>,
        prepared: &mut PreparedSharedOrdinaryCensus,
    ) -> Result<OrdinaryCensusResult, CensusError> {
        // Repeat all original full-state/identity/deadline and capacity/debit
        // predicates after the bounded copies. No live logical state changed.
        let plan = self.validate_shared_model(reservation, actual, prepared)?;
        let rows = prepared.history.archive()?.records()?;
        let binding = prepared.binding.ok_or(CensusError::InvalidConsumption)?;
        let id = OriginId {
            census: self.identity,
            serial: self.state.next_serial,
        };
        if rows.iter().any(|row| row.owner() != Ok(id)) {
            return Err(CensusError::IdentityMismatch);
        }
        // Last fallible operation. On success the exact Box and each already
        // copied payload move directly into the successor. No allocation,
        // callback, fallible query or injected panic occurs in this tail.
        let archive = prepared.history.take_complete()?;
        let evidence = prepared
            .evidence
            .take()
            .expect("validated ordinary evidence");
        let initial = checkpoint_with_payload(
            actual.step,
            std::mem::take(&mut prepared.origins[0]),
            StopPhase::OwnedOrdinaryComplete {
                execution: binding.execution,
            },
            Some(DynamicSignalInfo {
                raw: actual.trace.signal,
            }),
        );
        let current = checkpoint_with_payload(
            actual.closing[2],
            std::mem::take(&mut prepared.origins[1]),
            StopPhase::UserCheckpoint,
            None,
        );
        self.state.origins.push(StoredOrigin {
            row: OriginRow {
                id,
                kind: OriginKind::CurrentHeldPc,
                pc: initial.logical_pc,
                created_generation: self.state.generation,
                initial,
            },
            current,
            active: true,
            frame: None,
            runtime_kernel: None,
            ordinary_history: Some(SharedOrdinaryOwner { archive, evidence }),
        });
        self.state.origins[plan.old].current.token = actual.opening[2].stop.token.clone();
        self.state.origins[plan.old].active = false;
        for row in rows {
            self.state
                .history
                .push(HistoryRecord::SharedOrdinary(SharedOrdinaryRecord { row }));
        }
        self.state.next_serial = plan.next;
        self.commit_debit(reservation, plan.remaining, plan.used);
        prepared.stage = Stage::Committed;
        Ok(OrdinaryCensusResult { current: id })
    }

    pub(super) fn validate_shared_model(
        &self,
        reservation: Reservation,
        actual: &CompletionModel<'_>,
        prepared: &PreparedSharedOrdinaryCensus,
    ) -> Result<CommitPlan, CensusError> {
        let expected = prepared.binding.ok_or(CensusError::InvalidConsumption)?;
        if !matches!(prepared.stage, Stage::Ready | Stage::Copied)
            || prepared.first_failure.is_some()
            || prepared.unwound
            || expected.census != self.identity
            || expected.reservation != reservation
            || actual.origin != expected.origin
            || actual.execution != expected.execution
            || actual.source != expected.source
            || actual.until != expected.until
            || actual.encoding != expected.encoding.bytes()
        {
            return Err(CensusError::IdentityMismatch);
        }
        let index = self.active_index(expected.origin)?;
        let before = self.current_observation(expected.origin)?;
        if shared::ObservationView::of(before) != prepared.history.prior()?
            || Instant::now() >= expected.until
            || before.task.generation != self.state.generation
        {
            return Err(CensusError::StaleObservation);
        }
        self.runtime_register_provenance(expected.origin)?;
        if !opening_checkpoint_identity(before, actual.logical)
            || actual.logical.stop.token != before.token
            || actual.logical.stop.signal.is_some()
            || !matches!(
                actual.logical.stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || !same_architecture(before, actual.logical.state)
        {
            return Err(CensusError::InvalidConsumption);
        }
        let mut sequence = before.token.sequence;
        for stop in actual.opening {
            if !opening_checkpoint_identity(before, stop)
                || stop.stop.token.sequence <= sequence
                || stop.stop.phase != AdmissionPhase::Restored
                || stop.stop.signal.is_some()
                || !same_architecture(before, stop.state)
            {
                return Err(CensusError::InvalidConsumption);
            }
            sequence = stop.stop.token.sequence;
        }
        let step = actual.step;
        let signal = DynamicSignalInfo {
            raw: actual.trace.signal,
        };
        if !checkpoint_identity(before, step) || step.stop.token.sequence <= sequence
            || step.stop.phase != AdmissionPhase::NativeCompleted
            // NativeCompleted is an owned control stop, not a queued application
            // signal. Actual trace siginfo is retained separately by the seal.
            || step.stop.signal.is_some()
            || actual.trace.ordinal != 3 || actual.trace.tid != before.token.tid
            || !libc::WIFSTOPPED(actual.trace.status)
            || libc::WSTOPSIG(actual.trace.status) != libc::SIGTRAP
            || actual.trace.status >> 16 != 0 || actual.trace.dr6 != TRACE_DR6
            || signal.signal() != libc::SIGTRAP || signal.errno() != 0
            || signal.code() != libc::TRAP_TRACE
            || u64::from_ne_bytes(actual.trace.signal[16..24].try_into().unwrap()) != step.state.registers.rip
        {
            return Err(CensusError::InvalidConsumption);
        }
        sequence = step.stop.token.sequence;
        for stop in actual.closing {
            if !checkpoint_identity(before, stop)
                || stop.stop.token.sequence <= sequence
                || stop.stop.phase != AdmissionPhase::Restored
                || stop.stop.signal.is_some()
                || stop.state != step.state
            {
                return Err(CensusError::InvalidConsumption);
            }
            sequence = stop.stop.token.sequence;
        }
        if !prepared.storage_matches(expected, actual)?
            || self.state.origins.len() == self.state.origins.capacity()
            || self
                .state
                .history
                .capacity()
                .saturating_sub(self.state.history.len())
                < WITNESSES
        {
            return Err(CensusError::Capacity);
        }
        let next = self
            .state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        if self.state.next_serial != expected.candidate_serial {
            return Err(CensusError::StaleObservation);
        }
        let (remaining, used) = self.prepare_debit(reservation, prepared.remaining_charge()?)?;
        Ok(CommitPlan {
            old: index,
            next,
            remaining,
            used,
        })
    }
}
