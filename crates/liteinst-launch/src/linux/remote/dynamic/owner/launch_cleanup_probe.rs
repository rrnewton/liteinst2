//! Per-launch test observations only. No release or cleanup result is supplied.
use super::*;

type ReadyObservation = dyn FnOnce(&Owner, &Ready, Instant) -> Result<(), LaunchError> + Send;
type CleanupObservation = dyn FnOnce(&Owner, Instant) + Send;

pub(in crate::linux::remote::dynamic) struct Probe {
    ready: Option<Box<ReadyObservation>>,
    cleanup: Box<CleanupObservation>,
}

impl Probe {
    pub(in crate::linux::remote::dynamic) fn new(
        ready: Box<ReadyObservation>,
        cleanup: Box<CleanupObservation>,
    ) -> Self {
        Self {
            ready: Some(ready),
            cleanup,
        }
    }

    pub(super) fn before_ready(
        &mut self,
        owner: &Owner,
        ready: &Ready,
        until: Instant,
    ) -> Result<(), LaunchError> {
        self.ready
            .take()
            .expect("one actual initial Ready observation")(owner, ready, until)
    }

    pub(super) fn before_cleanup(self, owner: &Owner, until: Instant) {
        (self.cleanup)(owner, until);
    }
}
