//! Stable data controls for observing callbacks in immutable generated code.
//!
//! Control changes request whether a future dispatch calls its callback. They
//! do not drain a callback that already observed `true`, establish quiescence,
//! or make generated code reclaimable. The observing emitter saves full state
//! before testing the control, so a disabled callback still pays that cost.
//! Controls are process-local heap objects. A fork inherits a snapshot, not
//! shared enable state; new controlled images must not be published into another
//! process. The fork-shared trampoline arena therefore refuses controlled plans.

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::trampoline::HookCallback;
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use crate::trampoline::HookContext;

/// One stable observing-callback identity, independent of executable storage.
///
/// Clones share the same callback and Boolean. Equality compares that identity,
/// never the changing enabled value. The callback remains immutable; construct
/// another control to select a different callback.
#[derive(Clone)]
pub struct ProbeControl {
    inner: Arc<ControlBlock>,
}

pub(crate) struct ControlBlock {
    callback: HookCallback,
    enabled: AtomicBool,
}

impl ProbeControl {
    /// Creates a stable callback and its initial enabled state.
    pub fn new(callback: HookCallback, enabled: bool) -> Self {
        Self {
            inner: Arc::new(ControlBlock {
                callback,
                enabled: AtomicBool::new(enabled),
            }),
        }
    }

    /// Updates the dispatch Boolean with a release store.
    ///
    /// This is a release store, not callback drainage: a dispatch that already
    /// observed `true` may invoke or finish its callback after this returns.
    /// Execution/lifetime exclusion remains a separate caller obligation.
    pub fn set_enabled(&self, enabled: bool) {
        self.inner.enabled.store(enabled, Ordering::Release);
    }

    /// Reads the observed control state with acquire ordering.
    ///
    /// This reports the Boolean only; it does not count or drain dispatches.
    pub fn is_enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::Acquire)
    }

    /// Bytes in one control payload, excluding Arc bookkeeping and allocation
    /// overhead. Count each distinct identity once; cloned handles share it.
    pub const fn payload_bytes() -> usize {
        core::mem::size_of::<ControlBlock>()
    }

    pub(crate) fn callback(&self) -> HookCallback {
        self.inner.callback
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn block_address(&self) -> u64 {
        Arc::as_ptr(&self.inner) as usize as u64
    }

    #[cfg(test)]
    pub(crate) fn downgrade(&self) -> std::sync::Weak<ControlBlock> {
        Arc::downgrade(&self.inner)
    }
}

impl PartialEq for ProbeControl {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}
impl Eq for ProbeControl {}

impl fmt::Debug for ProbeControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProbeControl")
            .field("identity", &Arc::as_ptr(&self.inner))
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

/// An observing callback at one original instruction head.
///
/// There is deliberately no replacement flag. Disabled observing actions still
/// execute their original instruction; conditional replacement requires a
/// different two-body-path contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlledAction {
    /// Original instruction head receiving this callback.
    pub logical_pc: u64,
    /// Independently owned callback control for this head.
    pub control: ProbeControl,
}

/// Called only by a generated observing frame after complete state capture.
///
/// # Safety
/// `context` must be the live, exclusively borrowed saved frame and `block`
/// must identify a retained control for this generated image. The image's
/// control ownership must cover the entire dispatch, including callback code.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) unsafe extern "C" fn dispatch(context: *mut HookContext, block: *const ControlBlock) {
    // SAFETY: the emitter passes its retained stable block after frame capture.
    let control = unsafe { &*block };
    if control.enabled.load(Ordering::Acquire) {
        // SAFETY: the generated frame satisfies the existing callback contract.
        unsafe { (control.callback)(context) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn callback(_: *mut HookContext) {}

    #[test]
    fn identity_is_shared_by_clones_and_independent_of_enabled_state() {
        let first = ProbeControl::new(callback, false);
        let clone = first.clone();
        let second = ProbeControl::new(callback, false);
        assert_eq!(first, clone);
        assert_ne!(first, second);
        clone.set_enabled(true);
        assert!(first.is_enabled());
        assert!(!second.is_enabled());
        assert_eq!(first, clone);
        first.set_enabled(false);
        assert!(!clone.is_enabled());
        let weak = first.downgrade();
        drop(first);
        assert_eq!(weak.strong_count(), 1);
        drop(clone);
        assert!(weak.upgrade().is_none(), "unused controls are not leaked");
    }
}
