//! Read-only initial-singleton guard using the source owner's prepaid scratch.
//! This returns no stack permit and does not widen any native phase predicate.
use super::*;

impl InitialReadScratch {
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_initial_source_stop(
        &self,
        owner: &Owner,
        native: &NativeLifecycle,
        stop: &AdmissionStop,
        until: Instant,
    ) -> Result<(), LaunchError> {
        let mut storage = self.bytes.try_borrow_mut().map_err(|_| {
            LaunchError::Invalid("initial stack source scratch is already borrowed")
        })?;
        native.require_initial_source_mm(owner, stop, until, storage.as_mut_slice())
    }
}
