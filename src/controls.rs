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
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::trampoline::{HookCallback, HookContext};

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
    managed: bool,
    bound_callback: Option<ManagedCallback>,
}

/// Opaque identity borrowed only for the active managed callback. The dispatch
/// image retains the block for this lifetime. A token cannot be safely retained
/// beyond that call, so an allocation reused later cannot match an escaped token.
/// It conveys neither write authority nor a dereferenceable pointer.
///
/// ```compile_fail
/// use liteinst2::controls::ControlIdentity;
/// fn escape<'dispatch>(token: ControlIdentity<'dispatch>) -> ControlIdentity<'static> {
///     token
/// }
/// ```
///
/// The higher-ranked callback also prevents storage in a static TLS slot:
///
/// ```compile_fail
/// use std::cell::Cell;
/// use liteinst2::controls::{ControlIdentity, ProbeControl};
/// use liteinst2::trampoline::HookContext;
/// thread_local! { static SAVED: Cell<Option<ControlIdentity<'static>>> = const { Cell::new(None) }; }
/// unsafe extern "C" fn retain<'dispatch>(_: *mut HookContext, token: ControlIdentity<'dispatch>) {
///     SAVED.with(|slot| slot.set(Some(token)));
/// }
/// let _ = ProbeControl::new_managed_bound(retain, false);
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlIdentity<'dispatch> {
    address: usize,
    lifetime: PhantomData<&'dispatch ControlBlock>,
}

impl<'dispatch> ControlIdentity<'dispatch> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn from_control(control: &'dispatch ControlBlock) -> Self {
        Self {
            address: control as *const ControlBlock as usize,
            lifetime: PhantomData,
        }
    }
}

/// Managed callback with a fresh borrow of the exact retained block. The token
/// is one transparent machine word; the lifetime adds no runtime state.
pub type ManagedCallback =
    for<'dispatch> unsafe extern "C" fn(*mut HookContext, ControlIdentity<'dispatch>);

unsafe extern "C" fn managed_requires_dispatch(_: *mut HookContext) {
    // A managed action must retain its control and use the controlled emitter.
    // Calling its static placeholder is an invariant violation, not observation.
    std::process::abort();
}

/// A planner-readable managed control cannot be changed through its public handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedControl;

/// Unique write authority for one managed control. There is no Clone or
/// conversion from a planner-readable ProbeControl back to this capability.
///
/// ```compile_fail,E0277
/// use liteinst2::controls::ControlWriter;
/// fn needs_clone<T: Clone>() {}
/// fn duplicate() { needs_clone::<ControlWriter>(); }
/// ```
pub struct ControlWriter {
    inner: Arc<ControlBlock>,
}

impl ControlWriter {
    pub(crate) fn matches(&self, control: &ProbeControl) -> bool {
        Arc::ptr_eq(&self.inner, &control.inner)
    }
    /// Make a release-store request for this exact control. Completion/drain
    /// still belongs to the controller's admission protocol.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.inner.enabled.store(enabled, Ordering::Release);
    }
}

impl ProbeControl {
    /// Creates a stable callback and its initial enabled state.
    pub fn new(callback: HookCallback, enabled: bool) -> Self {
        Self {
            inner: Arc::new(ControlBlock {
                callback,
                enabled: AtomicBool::new(enabled),
                managed: false,
                bound_callback: None,
            }),
        }
    }

    /// Create a managed control and its unique writer. Clones of the returned
    /// ProbeControl remain suitable for planning but cannot change its Boolean.
    /// Keep the writer private to the actual controller/publication authority.
    pub fn new_managed(callback: HookCallback, enabled: bool) -> (Self, ControlWriter) {
        Self::managed(callback, None, enabled)
    }

    /// Managed variant whose callback also receives the exact retained owner
    /// identity. Ordinary callback ABI and ordinary controls are unchanged.
    pub fn new_managed_bound(callback: ManagedCallback, enabled: bool) -> (Self, ControlWriter) {
        Self::managed(managed_requires_dispatch, Some(callback), enabled)
    }

    fn managed(
        callback: HookCallback,
        bound_callback: Option<ManagedCallback>,
        enabled: bool,
    ) -> (Self, ControlWriter) {
        let inner = Arc::new(ControlBlock {
            callback,
            enabled: AtomicBool::new(enabled),
            managed: true,
            bound_callback,
        });
        (
            Self {
                inner: Arc::clone(&inner),
            },
            ControlWriter { inner },
        )
    }

    /// Compare this retained owner with a managed callback's opaque token.
    /// The token cannot recover a writer or access an object after its lifetime.
    pub fn has_identity(&self, identity: ControlIdentity<'_>) -> bool {
        Arc::as_ptr(&self.inner) as usize == identity.address
    }

    /// Change an ordinary control, or refuse a managed handle before any store.
    pub fn try_set_enabled(&self, enabled: bool) -> Result<(), ManagedControl> {
        if self.inner.managed {
            return Err(ManagedControl);
        }
        self.inner.enabled.store(enabled, Ordering::Release);
        Ok(())
    }

    /// Updates the dispatch Boolean with a release store.
    ///
    /// This is a release store, not callback drainage: a dispatch that already
    /// observed `true` may invoke or finish its callback after this returns.
    /// Execution/lifetime exclusion remains a separate caller obligation.
    ///
    /// # Panics
    /// A managed handle has no write authority and panics before any store.
    /// Use try_set_enabled for an explicit refusal, or its unique ControlWriter.
    pub fn set_enabled(&self, enabled: bool) {
        self.try_set_enabled(enabled)
            .expect("managed control requires its unique writer");
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

    pub(crate) fn is_managed_bound(&self) -> bool {
        self.inner.managed && self.inner.bound_callback.is_some()
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
        if let Some(callback) = control.bound_callback {
            // SAFETY: the retained block is the exact dispatcher owner; the
            // managed callback has the same context/lifetime contract.
            unsafe { callback(context, ControlIdentity::from_control(control)) };
            return;
        }
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

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn borrowed_token_has_one_word_layout_and_matches_only_its_live_owner() {
        assert_eq!(
            core::mem::size_of::<ControlIdentity<'_>>(),
            core::mem::size_of::<usize>()
        );
        assert_eq!(
            core::mem::align_of::<ControlIdentity<'_>>(),
            core::mem::align_of::<usize>()
        );
        let first = ProbeControl::new(callback, false);
        let second = ProbeControl::new(callback, false);
        let identity = ControlIdentity::from_control(&first.inner);
        assert!(first.has_identity(identity));
        assert!(first.clone().has_identity(identity));
        assert!(!second.has_identity(identity));
    }

    #[test]
    fn managed_clones_refuse_both_setters_and_writer_is_exactly_bound() {
        unsafe extern "C" fn managed(_: *mut HookContext, _: ControlIdentity<'_>) {}
        let (first, mut writer) = ProbeControl::new_managed_bound(managed, false);
        let clone = first.clone();
        let (second, mut other) = ProbeControl::new_managed_bound(managed, true);
        assert_eq!(clone.try_set_enabled(true), Err(ManagedControl));
        let panic = std::panic::catch_unwind(|| clone.set_enabled(true));
        assert!(
            panic.is_err(),
            "legacy setter must visibly refuse managed state"
        );
        assert!(!first.is_enabled());
        assert!(second.is_enabled());
        writer.set_enabled(true);
        assert!(first.is_enabled() && clone.is_enabled());
        other.set_enabled(false);
        assert!(first.is_enabled());
        assert!(!second.is_enabled());
        drop(writer);
        assert_eq!(first.try_set_enabled(false), Err(ManagedControl));
        assert!(
            first.is_enabled(),
            "dropping authority does not grant it to readers"
        );
    }
}
