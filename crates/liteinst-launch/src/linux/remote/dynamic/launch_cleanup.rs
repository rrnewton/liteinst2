//! Optional client ownership of the original cleanup-completion receiver.
//! This module never issues a native command or manufactures a cleanup receipt.
use super::*;
use crate::gate::GateError;

/// Observed cleanup status after a failed opt-in runtime construction.
#[derive(Debug)]
pub enum DynamicRuntimeCleanupStatus<'a> {
    /// No dedicated tracer thread was successfully created.
    NotStarted,
    /// The original tracer still has not supplied its cleanup result.
    Pending,
    /// The tracer supplied its actual complete physical-cleanup receipt.
    Complete(&'a DynamicCleanup),
    /// The tracer supplied an actual failed physical-cleanup result.
    Failed(&'a LaunchError),
    /// The original sender ended without supplying a cleanup result.
    Disconnected,
}

/// An opt-in runtime launch failure with its original cleanup observation.
///
/// The first launch error is independent of all later cleanup results. A failed
/// wait retains the receiver for another bounded observation. Neither waiting
/// nor inspecting this value can resume a task or renew an execution deadline.
/// Dropping it only cancels, without waiting or asserting cleanup completion.
/// The caller must keep its host process alive until cleanup is established.
/// This guarantee covers returned errors; arbitrary caller unwinding, provider
/// destructor panics, allocation abort and process death remain caller custody.
#[must_use = "a failed runtime launch may still own asynchronous cleanup"]
pub struct DynamicRuntimeLaunchFailure {
    error: GateError,
    cleanup: Option<Box<CleanupObservation>>,
}

impl std::fmt::Debug for DynamicRuntimeLaunchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicRuntimeLaunchFailure")
            .field("error", &self.error)
            .field("cleanup", &self.cleanup_status())
            .finish()
    }
}

impl DynamicRuntimeLaunchFailure {
    /// The original construction error, never replaced by a cleanup error.
    pub fn error(&self) -> &GateError {
        &self.error
    }

    /// Current observation; Pending does not claim that no child exists.
    pub fn cleanup_status(&self) -> DynamicRuntimeCleanupStatus<'_> {
        self.cleanup
            .as_ref()
            .map_or(DynamicRuntimeCleanupStatus::NotStarted, |cleanup| {
                cleanup.status()
            })
    }

    /// Waits under a separate bounded observation deadline for the original
    /// cleanup result. A timeout leaves the same receiver and launch error in
    /// this value. Complete/Failed results are cached, not received twice.
    /// A returned Failed or Disconnected status is never complete cleanup.
    pub fn wait_cleanup(
        &mut self,
        timeout: Duration,
    ) -> Result<DynamicRuntimeCleanupStatus<'_>, LaunchError> {
        let until = deadline(timeout)?;
        if let Some(cleanup) = &mut self.cleanup {
            cleanup.wait_until(until)?;
        }
        Ok(self.cleanup_status())
    }

    pub(super) fn not_started(error: impl Into<GateError>) -> Self {
        Self {
            error: error.into(),
            cleanup: None,
        }
    }
}

// Allocated by the new opt-in constructor before spawning, not by the legacy
// constructor or on a failure path. The fixed holder receives moved client
// metadata only; no source/state evidence or native authority is copied.
pub(super) struct PreparedCleanup(Box<CleanupObservation>);
impl PreparedCleanup {
    pub(super) fn new() -> Self {
        Self(Box::new(CleanupObservation::not_started()))
    }

    pub(super) fn finish_launch(
        mut self,
        failure: OwnedLaunchFailure,
    ) -> DynamicRuntimeLaunchFailure {
        self.0.started = failure.cleanup.is_some();
        self.0.before_ready = failure.cleanup;
        DynamicRuntimeLaunchFailure {
            error: failure.error.into(),
            cleanup: Some(self.0),
        }
    }

    pub(super) fn finish_session(
        mut self,
        error: GateError,
        session: DynamicSession,
    ) -> DynamicRuntimeLaunchFailure {
        // Cancel before any caller provider may be destroyed on this Err path.
        // Move the exact session into storage allocated before it existed.
        session.cancel.store(true, Ordering::Release);
        self.0.started = true;
        self.0.session = Some(session);
        DynamicRuntimeLaunchFailure {
            error,
            cleanup: Some(self.0),
        }
    }
}

struct BeforeReadyCleanup {
    cancel: Arc<AtomicBool>,
    done: Receiver<Result<DynamicCleanup, LaunchError>>,
}
impl Drop for BeforeReadyCleanup {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

// before_ready and session are mutually exclusive, assigned only by the two
// consuming PreparedCleanup methods. Exactly one remains while Pending; it is
// cleared only after caching an actual result or observing sender loss. This
// fixed boxed header avoids a large Result error and any allocation on failure.
struct CleanupObservation {
    started: bool,
    before_ready: Option<BeforeReadyCleanup>,
    session: Option<DynamicSession>,
    result: Option<Result<DynamicCleanup, LaunchError>>,
    disconnected: bool,
}
impl CleanupObservation {
    fn not_started() -> Self {
        Self {
            started: false,
            before_ready: None,
            session: None,
            result: None,
            disconnected: false,
        }
    }

    fn status(&self) -> DynamicRuntimeCleanupStatus<'_> {
        if !self.started {
            DynamicRuntimeCleanupStatus::NotStarted
        } else if let Some(result) = &self.result {
            match result {
                Ok(receipt) => DynamicRuntimeCleanupStatus::Complete(receipt),
                Err(error) => DynamicRuntimeCleanupStatus::Failed(error),
            }
        } else if self.disconnected {
            DynamicRuntimeCleanupStatus::Disconnected
        } else {
            DynamicRuntimeCleanupStatus::Pending
        }
    }

    fn wait_until(&mut self, until: Instant) -> Result<(), LaunchError> {
        let receiver = self
            .before_ready
            .as_ref()
            .map(|owner| &owner.done)
            .or_else(|| self.session.as_ref().map(|session| &session.done));
        let Some(receiver) = receiver else {
            return Ok(());
        };
        let received = receiver.recv_timeout(until.saturating_duration_since(Instant::now()));
        match received {
            Ok(result) => self.result = Some(result),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.disconnected = true;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(LaunchError::Timeout(
                    "dynamic cleanup remains owned by tracer",
                ));
            }
        }
        // Drop the cancelled transport only after retaining the actual result
        // (or the distinct sender-loss observation). Timeout never reaches here.
        self.before_ready = None;
        self.session = None;
        Ok(())
    }
}

// The raw launcher only fails before returning a Session, so this error needs
// only the original small pre-Ready receiver. Legacy launch adds no allocation.
pub(super) struct OwnedLaunchFailure {
    pub(super) error: LaunchError,
    cleanup: Option<BeforeReadyCleanup>,
}
impl OwnedLaunchFailure {
    pub(super) fn not_started(error: LaunchError) -> Self {
        Self {
            error,
            cleanup: None,
        }
    }

    pub(super) fn after_spawn(
        error: LaunchError,
        cancel: Arc<AtomicBool>,
        done: Receiver<Result<DynamicCleanup, LaunchError>>,
        spawned: bool,
    ) -> Self {
        // Cancel before the failure is returned or any provider is destroyed.
        cancel.store(true, Ordering::Release);
        // A failed spawn has no native owner even if channels already existed.
        // A successful spawn retains done even if Ready never arrived.
        let cleanup = if spawned {
            Some(BeforeReadyCleanup { cancel, done })
        } else {
            None
        };
        Self { error, cleanup }
    }
}

pub(super) struct CancelConstruction {
    pub(super) cancel: Arc<AtomicBool>,
    pub(super) armed: bool,
}
impl Drop for CancelConstruction {
    fn drop(&mut self) {
        if self.armed {
            self.cancel.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests;
