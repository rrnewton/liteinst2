//! Startup-only source identity guard for the actual native stack acquisition.
use super::*;

impl PreparedInitialSources {
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_stack_start(
        &self,
        owner: &Owner,
        native: &NativeLifecycle,
        boot: &BootstrapMm,
        until: Instant,
    ) -> Result<(), LaunchError> {
        let storage = &self.storage;
        let current = storage.current.as_ref().ok_or(LaunchError::Invalid(
            "initial stack source current identity is absent",
        ))?;
        if until != storage.until
            || storage.failure.is_some()
            || !storage.original_complete
            || !storage.capture_complete
            || !storage.recheck_complete
            || storage.original.is_none()
            || storage.executable.is_none()
            || current.stop != boot.stop
            || current.registers != boot.evidence.restored_entry.registers
            || current.signal_mask != boot.evidence.restored_entry.mask
            || current.xstate_len != boot.evidence.restored_entry.xstate.len()
            || storage.xstate.get(..current.xstate_len)
                != Some(boot.evidence.restored_entry.xstate.as_slice())
        {
            return Err(LaunchError::Invalid(
                "initial stack source identity differs",
            ));
        }
        self.authentication
            .require_initial_source_stop(owner, native, &boot.stop, until)
    }
}
