//! Optional, per-call observation selection before full context capture.
//!
//! This is a separate unsafe execution profile, not a faster implementation of
//! mandatory observing controls. It supplies no callable gate, source/CFG lease,
//! physical-return proof, epoch admission, or executable reclamation authority.
//! The owner must establish those before using the generated instructions.

use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};
use std::rc::Rc;
use std::sync::Arc;

use crate::controls::{ManagedCallback, ProbeControl};

/// One aligned, process-local selector retained independently of immutable code.
///
/// Only the entry stencil loads it. A selected Slow call still executes its
/// permanent RET observer after a later disable/rearm. Selection is not epoch
/// reservation, and a release store is not an all-executor visibility receipt.
#[derive(Clone)]
pub struct PreContextSelector(Arc<AtomicU64>);

/// Unique publication authority for one selector; it cannot disable callbacks.
pub struct PreContextWriter(Arc<AtomicU64>);

impl PreContextSelector {
    /// Creates separate retained read ownership and unique release-store authority.
    pub fn new(enabled: bool) -> (Self, PreContextWriter) {
        let word = Arc::new(AtomicU64::new(u64::from(enabled)));
        (Self(word.clone()), PreContextWriter(word))
    }

    /// An acquire observation, not the decision of a future call or its owner.
    pub fn is_enabled(&self) -> bool {
        self.0.load(Ordering::Acquire) == 1
    }

    /// Distinct selector payload bytes, excluding Arc bookkeeping/allocation.
    pub const fn payload_bytes() -> usize {
        core::mem::size_of::<AtomicU64>()
    }

    pub(crate) fn address(&self) -> u64 {
        Arc::as_ptr(&self.0) as usize as u64
    }

    #[cfg(test)]
    pub(crate) fn downgrade(&self) -> std::sync::Weak<AtomicU64> {
        Arc::downgrade(&self.0)
    }
}

impl PreContextWriter {
    /// Requests the choice for future entry loads, without changing old calls.
    /// Generation/transaction authorization belongs to the enclosing controller.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.0.store(u64::from(enabled), Ordering::Release);
    }
}

impl PartialEq for PreContextSelector {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for PreContextSelector {}
impl fmt::Debug for PreContextSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PreContextSelector")
            .field(&self.address())
            .finish()
    }
}

/// The only two supported logical roles. Return means one literal original C3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreContextRole {
    /// The sole admitted function entry; chooses once for this invocation.
    Entry,
    /// An admitted original RET; follows the saved choice, never the selector.
    Return,
}

/// A typed optional observer with a fresh permanently enabled managed control.
///
/// Construction does not certify the callback. The unsafe plan constructor
/// requires a preserving callback and the complete private-frame/leaf contract.
/// There is no conversion from an arbitrary mutable control or replacement action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreContextAction {
    pub(crate) logical_pc: u64,
    pub(crate) role: PreContextRole,
    pub(crate) selector: PreContextSelector,
    pub(crate) control: ProbeControl,
}

impl PreContextAction {
    /// Retains the selector and creates a fresh, permanently enabled callback.
    /// No writer for that callback is exposed or retained.
    pub fn new(
        logical_pc: u64,
        role: PreContextRole,
        selector: &PreContextSelector,
        callback: ManagedCallback,
    ) -> Self {
        let (control, writer) = ProbeControl::new_managed_bound(callback, true);
        drop(writer);
        Self {
            logical_pc,
            role,
            selector: selector.clone(),
            control,
        }
    }

    /// Original head, not a generated address or arbitrary resume entry.
    pub fn logical_pc(&self) -> u64 {
        self.logical_pc
    }
    /// Exact entry/RET role to authenticate when constructing a complete site.
    pub fn role(&self) -> PreContextRole {
        self.role
    }
    /// Read-only callback identity for a bound callback's existing identity check.
    pub fn control(&self) -> &ProbeControl {
        &self.control
    }
    /// The separate atomic selector retained by this action.
    pub fn selector(&self) -> &PreContextSelector {
        &self.selector
    }
}

pub(crate) const ARMED: u64 = 1;
pub(crate) const ENTERED: u64 = 2;
pub(crate) const RETURN_OBSERVED: u64 = 3;
pub(crate) const FAST: u64 = 1;
pub(crate) const SLOW: u64 = 2;

/// Exact scratch ABI at the RBX address on every admitted original instruction.
///
/// Embed this header at offset zero in the actual thread's private UnsafeCell
/// frame. No Rust reference to the frame/scratch may span execution. Callbacks
/// preserve the saved application RBX and all other restored state, and never
/// access this header. The subject must not read/write RBX even as an address
/// operand. A call owns the scratch exclusively until
/// its real outer return (or retains it on failure). There is no Send/Sync impl.
/// Arbitrary invalid RBX cannot be made safe by an after-the-fact phase check.
///
/// The stencil writes only these nine aligned words, never the application
/// stack/red zone. ReturnObserved is a *pre-RET* acknowledgement, not proof that
/// a RET executed, a worker joined, or input/code can be reclaimed.
///
/// ```compile_fail
/// use liteinst2::precontext::CallScratch;
/// fn send<T: Send>() {}
/// send::<CallScratch>();
/// ```
/// ```compile_fail
/// use liteinst2::precontext::CallScratch;
/// fn share<T: Sync>() {}
/// share::<CallScratch>();
/// ```
#[repr(C, align(8))]
pub struct CallScratch {
    pub(crate) saved_rcx: u64,
    pub(crate) phase: u64,
    pub(crate) disposition: u64,
    pub(crate) entry_pc: u64,
    pub(crate) entry_rsp: u64,
    pub(crate) entry_word: u64,
    pub(crate) return_pc: u64,
    pub(crate) return_rsp: u64,
    pub(crate) return_word: u64,
    thread: PhantomData<Rc<()>>,
}

/// Immutable choice made by the actual entry load, not by an earlier wrapper hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Skips only this optional action's full context and callback.
    FastBypass,
    /// Runs the permanent entry and RET observers, regardless of later updates.
    Slow,
}

/// Scratch protocol phase; none of these states alone proves a physical return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScratchPhase {
    /// Caller initialized, with no decision or entry/return record yet.
    Armed,
    /// Original entry stencil selected and recorded its actual stack words.
    Entered,
    /// Original RET stencil recorded its words, before executing the actual RET.
    ReturnObserved,
}

/// Malformed scratch tags/phase fields; no automatic repair or bypass is allowed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScratchError;

/// Copied observations for a caller-owned identity/physical-return check.
/// This carries no generation, timestamp, receipt, completion or reclamation token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScratchSnapshot {
    /// Exact decoded scratch phase.
    pub phase: ScratchPhase,
    /// Absent only before selection; immutable during an admitted invocation.
    pub disposition: Option<Disposition>,
    /// Original entry PC written by its stencil.
    pub entry_pc: u64,
    /// Actual RSP on the original entry boundary.
    pub entry_rsp: u64,
    /// Unmodified application return word read at that RSP.
    pub entry_word: u64,
    /// Original C3 PC written by the RET stencil.
    pub return_pc: u64,
    /// Actual RSP at that RET boundary.
    pub return_rsp: u64,
    /// Unmodified application return word read at that RSP.
    pub return_word: u64,
}

impl CallScratch {
    /// Fresh header for a caller-owned invocation; does not acquire its lifetime.
    /// Never replace a header until prior execution is actually drained.
    pub const fn armed() -> Self {
        Self {
            saved_rcx: 0,
            phase: ARMED,
            disposition: 0,
            entry_pc: 0,
            entry_rsp: 0,
            entry_word: 0,
            return_pc: 0,
            return_rsp: 0,
            return_word: 0,
            thread: PhantomData,
        }
    }

    /// Copies checked tags/fields at an exclusive, already-proven safe handoff.
    /// Full PID/TID/site/sequence/stack/continuation joins remain the caller's job.
    pub fn snapshot(&self) -> Result<ScratchSnapshot, ScratchError> {
        let disposition = match self.disposition {
            0 => None,
            FAST => Some(Disposition::FastBypass),
            SLOW => Some(Disposition::Slow),
            _ => return Err(ScratchError),
        };
        let phase = match self.phase {
            ARMED
                if disposition.is_none()
                    && self.entry_pc == 0
                    && self.entry_rsp == 0
                    && self.entry_word == 0
                    && self.return_pc == 0
                    && self.return_rsp == 0
                    && self.return_word == 0 =>
            {
                ScratchPhase::Armed
            }
            ENTERED
                if disposition.is_some()
                    && self.return_pc == 0
                    && self.return_rsp == 0
                    && self.return_word == 0 =>
            {
                ScratchPhase::Entered
            }
            RETURN_OBSERVED if disposition.is_some() => ScratchPhase::ReturnObserved,
            _ => return Err(ScratchError),
        };
        Ok(ScratchSnapshot {
            phase,
            disposition,
            entry_pc: self.entry_pc,
            entry_rsp: self.entry_rsp,
            entry_word: self.entry_word,
            return_pc: self.return_pc,
            return_rsp: self.return_rsp,
            return_word: self.return_word,
        })
    }
}

// The machine-code ABI is independent of enums, ProbeControl and frontend TLS.
const _: () = assert!(core::mem::size_of::<CallScratch>() == 72);
const _: () = assert!(core::mem::align_of::<CallScratch>() == 8);
const _: () = assert!(core::mem::size_of::<AtomicU64>() == 8);
const _: () = assert!(core::mem::align_of::<AtomicU64>() >= 8);

/// Verified addresses for one optional stencil and its independent slow/body joins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreContextGateLayout {
    /// Original action head.
    pub logical_pc: u64,
    /// Exact role used for this stencil.
    pub role: PreContextRole,
    /// Generated gate entry (the original head's entry route).
    pub entry: u64,
    /// Full context/callback path, selected only by Slow.
    pub observing_entry: u64,
    /// Common original-instruction boundary after the observer or fast branch.
    pub original_body: u64,
    /// Local UD2 for malformed scratch; never an entry-router original key.
    pub fault: u64,
}
