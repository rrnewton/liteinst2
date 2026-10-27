//! Whole-window source rechecks and prospective gates at native boundaries.
use super::*;

pub(super) struct SourceObserver<'a, 'binding, 'operand> {
    pub(super) sources: &'a PreparedInitialSources,
    pub(super) binding: &'a RuntimeStackBinding<'binding, 'operand>,
    pub(super) census: &'a ResumeCensus,
    pub(super) reservation: Reservation,
    pub(super) remaining: BudgetCharge,
    pub(super) storage: &'a mut SourceChecks,
    #[cfg(test)]
    pub(super) refuse_closed: bool,
}

impl SourceChecks {
    fn checkpoint(
        &mut self,
        stop: &AdmissionStop,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        if !(512..MAX_XSTATE).contains(&state.xstate.len())
            || state.xstate.len() > self.checkpoint.xstate.capacity()
            || stop.signal.is_some()
            || stop.phase != AdmissionPhase::Restored
        {
            return Err(LaunchError::Invalid(
                "runtime source recheck checkpoint differs",
            ));
        }
        self.checkpoint.xstate.clear();
        self.checkpoint.xstate.extend_from_slice(&state.xstate);
        self.checkpoint.token = stop.token.clone();
        self.checkpoint.task = stop.identity;
        self.checkpoint.logical_pc = state.registers.rip;
        self.checkpoint.registers = state.registers;
        self.checkpoint.signal_mask = state.mask;
        self.checkpoint.phase = StopPhase::UserCheckpoint;
        self.checkpoint.signal = None;
        self.checkpoint_stop = stop.clone();
        Ok(())
    }
}

impl InstructionObservation for SourceObserver<'_, '_, '_> {
    fn before_effect(
        &mut self,
        owner: &Owner,
        _native: &NativeLifecycle,
        _effect: InstructionEffect,
        _current: &AdmissionStop,
        until: Instant,
    ) -> Result<(), LaunchError> {
        if until != self.binding.until() {
            return Err(LaunchError::Invalid("runtime stack deadline changed"));
        }
        self.census
            .check_reserved(self.reservation, self.remaining)
            .map_err(census_error)
            .map_err(native_error)?;
        owner.time_left(until, "runtime stack native effect")?;
        Ok(())
    }

    fn opened(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        current: &AdmissionStop,
        state: &TaskStateSnapshot,
        actual_maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError> {
        if until != self.binding.until()
            || state.registers != self.binding.before().registers
            || state.xstate != self.binding.before().xstate
            || state.mask != self.binding.before().signal_mask
        {
            return Err(LaunchError::Invalid(
                "runtime opening changed original application state",
            ));
        }
        self.storage.checkpoint(current, state)?;
        let reader = self
            .sources
            .runtime_read_opened(
                owner,
                native,
                RuntimeCatalogCheckpoint {
                    island: self.binding.island(),
                    stop: &self.storage.checkpoint_stop,
                    observed: &self.storage.checkpoint,
                },
                self.binding.geometry(),
                actual_maps,
                until,
            )
            .map_err(native_error)?;
        reader
            .recheck_window(
                self.binding.source_id(),
                &mut self.storage.bytes[1],
                &mut self.storage.progress[1],
                &mut self.storage.identity,
            )
            .map_err(native_error)
    }

    fn closed(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        current: &AdmissionStop,
        state: &TaskStateSnapshot,
        actual_maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError> {
        if until != self.binding.until() {
            return Err(LaunchError::Invalid("runtime closing deadline changed"));
        }
        maps::verify_closed(self.binding.baseline_maps(), actual_maps).map_err(native_error)?;
        self.storage.checkpoint(current, state)?;
        let reader = self
            .sources
            .runtime_read(
                owner,
                native,
                self.binding.island(),
                &self.storage.checkpoint_stop,
                &self.storage.checkpoint,
                until,
            )
            .map_err(native_error)?;
        reader
            .recheck_window(
                self.binding.source_id(),
                &mut self.storage.bytes[2],
                &mut self.storage.progress[2],
                &mut self.storage.identity,
            )
            .map_err(native_error)?;
        #[cfg(test)]
        if self.refuse_closed {
            return Err(LaunchError::Invalid(
                "injected stack closed-source observer refusal",
            ));
        }
        Ok(())
    }
}
