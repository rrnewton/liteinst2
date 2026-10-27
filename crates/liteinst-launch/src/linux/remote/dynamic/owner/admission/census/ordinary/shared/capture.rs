use super::*;

impl ObservationHeader {
    fn observed(source: &ObservedStop) -> Self {
        Self {
            token: source.token.clone(),
            task: source.task,
            logical_pc: source.logical_pc,
            registers: source.registers,
            signal_mask: source.signal_mask,
            phase: source.phase,
            signal: source.signal.clone(),
        }
    }
    fn checkpoint(
        source: NativeCheckpoint<'_>,
        phase: StopPhase,
        signal: Option<DynamicSignalInfo>,
    ) -> Self {
        Self {
            token: source.stop.token.clone(),
            task: source.stop.identity,
            logical_pc: source.state.registers.rip,
            registers: source.state.registers,
            signal_mask: source.state.mask,
            phase,
            signal,
        }
    }
}
impl Payload {
    fn copy_with(
        &mut self,
        role: CaptureRole,
        source: &[u8],
        hook: &mut impl FnMut(CopyPoint) -> Result<(), SharedError>,
    ) -> Result<(), SharedError> {
        self.copy.begin()?;
        let result = (|| {
            require(
                self.bytes.is_empty()
                    && self.bytes.capacity() == MAX_XSTATE_BYTES
                    && (512..MAX_XSTATE_BYTES).contains(&source.len()),
                SharedError::Extent,
            )?;
            for part in source.chunks(COPY_CHUNK) {
                // Capacity and the complete extent were checked before copying.
                // Record the initialized prefix before any injected failure.
                self.bytes.extend_from_slice(part);
                self.copy.filled = self.bytes.len();
                hook((Some(role), self.copy.filled))?;
            }
            self.copy.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.copy.fail(error);
        }
        result
    }
}
impl PreparedOrdinaryHistory {
    pub(in crate::linux::remote::dynamic::owner::admission::census::ordinary) fn stage_prior(
        &mut self,
        source: &ObservedStop,
    ) -> Result<(), SharedError> {
        self.prior_with(source, &mut |_| Ok(()))
    }

    pub(super) fn prior_with(
        &mut self,
        source: &ObservedStop,
        hook: &mut impl FnMut(CopyPoint) -> Result<(), SharedError>,
    ) -> Result<(), SharedError> {
        self.require_allocation()?;
        let archive = self.archive.as_mut().ok_or(SharedError::Incomplete)?;
        archive.prior.begin()?;
        let result = (|| {
            require(
                !archive.native.started
                    && source.token.session == archive.binding.execution.session
                    && source.token.task == Some(source.task.task)
                    && source.token.tid > 0
                    && source.logical_pc == archive.binding.encoding.pc
                    && source.registers.rip == source.logical_pc
                    && source.task.generation == archive.binding.source.identity.generation,
                SharedError::Identity,
            )?;
            archive.payloads[0].copy_with(CaptureRole::Prior, &source.xstate, hook)?;
            archive.headers[0] = Some(ObservationHeader::observed(source));
            archive.prior.filled = 1;
            hook((None, 0))?;
            archive.prior.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            archive.prior.fail(error);
        }
        result
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census::ordinary) fn prior(
        &self,
    ) -> Result<ObservationView<'_>, SharedError> {
        let archive = self.archive()?;
        archive.prior.require_complete()?;
        let payload = &archive.payloads[0];
        payload.copy.require_complete()?;
        require(
            payload.bytes.len() == payload.copy.filled
                && payload.bytes.capacity() == MAX_XSTATE_BYTES,
            SharedError::Extent,
        )?;
        Ok(archive.headers[0]
            .as_ref()
            .ok_or(SharedError::Incomplete)?
            .view(&payload.bytes))
    }
    /// Borrows, but does not consume or recreate, the actual private native
    /// completion. Integration must still call every existing validate_model
    /// predicate and consume that same seal once in the census transaction.
    pub(in crate::linux::remote::dynamic::owner::admission::census::ordinary) fn stage_native(
        &mut self,
        actual: &OwnedInstructionCompletion<'_>,
    ) -> Result<(), SharedError> {
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
        self.native_with(&model, &mut |_| Ok(()))
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission::census::ordinary) fn stage_model(
        &mut self,
        actual: &CompletionModel<'_>,
    ) -> Result<(), SharedError> {
        self.native_with(actual, &mut |_| Ok(()))
    }

    pub(super) fn native_with(
        &mut self,
        actual: &CompletionModel<'_>,
        hook: &mut impl FnMut(CopyPoint) -> Result<(), SharedError>,
    ) -> Result<(), SharedError> {
        self.require_allocation()?;
        let archive = self.archive.as_mut().ok_or(SharedError::Incomplete)?;
        archive.prior.require_complete()?;
        archive.native.begin()?;
        let result = (|| {
            let binding = archive.binding;
            require(
                actual.source == binding.source
                    && actual.origin == binding.origin
                    && actual.execution == binding.execution
                    && actual.until == binding.until
                    && actual.encoding == binding.encoding.bytes(),
                SharedError::Identity,
            )?;
            // Content equality alone cannot establish shared capture provenance.
            require(
                actual
                    .opening
                    .iter()
                    .all(|p| std::ptr::eq(p.state, actual.logical.state))
                    && actual
                        .closing
                        .iter()
                        .all(|p| std::ptr::eq(p.state, actual.step.state))
                    && !std::ptr::eq(actual.logical.state, actual.step.state),
                SharedError::Provenance,
            )?;
            archive.trace = Some(actual.trace);
            archive.payloads[1].copy_with(
                CaptureRole::Before,
                &actual.logical.state.xstate,
                hook,
            )?;
            archive.payloads[2].copy_with(CaptureRole::Step, &actual.step.state.xstate, hook)?;
            let phase = StopPhase::OwnedOrdinaryComplete {
                execution: binding.execution,
            };
            for index in 1..ENDPOINTS {
                let (checkpoint, is_step) = match index {
                    1 | 2 => (actual.opening[0], false),
                    3 | 4 => (actual.opening[1], false),
                    5 | 6 => (actual.opening[2], false),
                    7 | 8 => (actual.step, true),
                    9 | 10 => (actual.closing[0], false),
                    11 | 12 => (actual.closing[1], false),
                    13 => (actual.closing[2], false),
                    _ => return Err(SharedError::Endpoint),
                };
                let signal = is_step.then_some(DynamicSignalInfo {
                    raw: actual.trace.signal,
                });
                archive.headers[index] = Some(ObservationHeader::checkpoint(
                    checkpoint,
                    if is_step {
                        phase
                    } else {
                        StopPhase::UserCheckpoint
                    },
                    signal,
                ));
                archive.native.filled = index;
                hook((None, index))?;
            }
            archive.native.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            archive.native.fail(error);
        }
        result
    }
}
