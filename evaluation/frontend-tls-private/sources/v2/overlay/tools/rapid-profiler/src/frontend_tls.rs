//! Ordinary Rust intervals backed by real, pre-registered thread-local storage.
//!
//! The body runs exactly once even when observation is refused. Synthetic model
//! slots are private data: no application return address is read or modified.
//! There is no C ABI entry, signal-safe path, clock, patch, or module-unmap proof.
//! Ordinary Rust unwinding cancels the exact top frame before releasing its owner.
//!
//! Setup consumes the session's existing lifetime T budget and preallocates its
//! bounded D-frame model. E, A, M and K keep their existing frontend meanings.
//! Registration and synthetic-slot identities never wrap or recycle. Refused
//! observations may consume an attempt/slot identity, but create no new frame or
//! record. Caller-provided values are reference data, not qualified timestamps.
//!
//! An exit-invariant failure poisons further admission. Its remaining model
//! frames stay owned until ordinary TLS destruction, where their data-only Drop
//! cancellations run. This does not restore machine return slots or prove that
//! generated code or a module can be unmapped. Foreign unwinding, longjmp, signal
//! handlers, fork and abrupt thread/process termination are outside this API.
#![forbid(unsafe_code)]

use crate::frontend::{
    EntryError, ExitError, ModelReturnSlot, Observation, Payload, Session, SetupError, ThreadModel,
};
use crate::generation::{Admission, Completion, FunctionId};
use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, ThreadId};

static NEXT_REGISTRATION: AtomicU64 = AtomicU64::new(1);
const ORIGINAL_TOKEN: u64 = 0x51a7_0b5e_1122_3344;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Refusal before an attachment becomes usable by this thread.
pub enum AttachError {
    /// The platform is destroying this TLS key.
    TlsUnavailable,
    /// Another bridge operation currently borrows the TLS state.
    Busy,
    /// This actual thread already has an attachment, including a forgotten one.
    AlreadyAttached,
    /// A previous invariant failure forbids further attachment.
    Poisoned,
    /// The process-local registration identity must not wrap or reuse zero.
    IdentityExhausted,
    /// The unchanged session registration contract refused.
    Setup(SetupError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// An explicit observation refusal or an invariant failure; never a fake sample.
pub enum BridgeError {
    /// The platform is destroying this TLS key.
    TlsUnavailable,
    /// Bookkeeping is already borrowing this actual thread's state.
    Busy,
    /// This registration no longer owns the TLS attachment.
    Detached,
    /// The actual Rust thread identity differs from the registration owner.
    WrongThread,
    /// An earlier invariant failure made further admission invalid.
    Poisoned,
    /// A fresh synthetic slot identity cannot be assigned without wrapping.
    SlotIdentityExhausted,
    /// The unchanged frontend refused before admission.
    Entry(EntryError),
    /// The unchanged frontend rejected the exact exit slot.
    Exit(ExitError),
    /// Completion did not retain the admission's full original identity.
    IdentityMismatch,
    /// Completion/cancellation did not restore the original synthetic token.
    RestorationMismatch,
    /// An attachment with an outstanding frame cannot be detached.
    NonEmpty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Result of observation, separate from the body's returned value.
pub enum IntervalOutcome {
    /// The exact admitting owner published its terminal and payload.
    Completed {
        /// The unchanged generation completion result.
        completion: Completion,
        /// The corresponding original-owner frontend payload.
        payload: Payload,
    },
    /// No interval was admitted; the body still ran exactly once.
    Refused(BridgeError),
    /// An admitted interval could not satisfy the exit invariant. TLS is poisoned.
    InvariantFailure(BridgeError),
}

struct Attached {
    identity: u64,
    thread: ThreadId,
    model: Option<ThreadModel>,
    next_slot: u64,
    #[cfg(test)]
    drop_witness: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl Attached {
    fn model(&mut self) -> &mut ThreadModel {
        self.model.as_mut().expect("live attached model")
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        // The test witness follows actual model destruction, not just detach.
        drop(self.model.take());
        #[cfg(test)]
        if let Some(witness) = &self.drop_witness {
            witness.fetch_add(1, Ordering::Release);
        }
    }
}

struct Local {
    attached: RefCell<Option<Attached>>,
    poisoned: Cell<bool>,
}

thread_local! {
    static LOCAL: Local = const {
        Local {
            attached: RefCell::new(None),
            poisoned: Cell::new(false),
        }
    };
}

/// A private actual-thread attachment. It exposes no model, ticket, or epoch Arc.
/// Dropping it detaches only an empty stack. Forgetting it retains its TLS state
/// until ordinary thread teardown; session T registration slots are never freed.
///
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_tls::ThreadRegistration;
/// fn move_to_thread(registration: ThreadRegistration) {
///     std::thread::spawn(move || drop(registration));
/// }
/// ```
///
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_tls::ThreadRegistration;
/// fn share_with_thread(registration: &ThreadRegistration) {
///     std::thread::scope(|scope| {
///         scope.spawn(move || registration.identity());
///     });
/// }
/// ```
pub struct ThreadRegistration {
    identity: u64,
    thread: ThreadId,
    active: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

fn next_registration(counter: &AtomicU64) -> Result<u64, AttachError> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            if value == 0 || value == u64::MAX {
                None
            } else {
                Some(value + 1)
            }
        })
        .map_err(|_| AttachError::IdentityExhausted)
}

/// Allocate the bounded model stack and register this actual Rust thread.
/// Call this during setup, before entering any observed body. Direct callers of
/// Session::register_thread share T and can cause an explicit identity collision;
/// the bridge never searches for a replacement identity or retries registration.
pub fn attach_current_thread(session: &Session) -> Result<ThreadRegistration, AttachError> {
    attach_with_counter(session, &NEXT_REGISTRATION)
}

fn attach_with_counter(
    session: &Session,
    counter: &AtomicU64,
) -> Result<ThreadRegistration, AttachError> {
    LOCAL
        .try_with(|local| {
            if local.poisoned.get() {
                return Err(AttachError::Poisoned);
            }
            let mut storage = local
                .attached
                .try_borrow_mut()
                .map_err(|_| AttachError::Busy)?;
            if storage.is_some() {
                return Err(AttachError::AlreadyAttached);
            }
            let identity = next_registration(counter)?;
            let model = session
                .register_thread(identity)
                .map_err(AttachError::Setup)?;
            let actual_thread = thread::current().id();
            *storage = Some(Attached {
                identity,
                thread: actual_thread,
                model: Some(model),
                next_slot: 1,
                #[cfg(test)]
                drop_witness: None,
            });
            Ok(ThreadRegistration {
                identity,
                thread: actual_thread,
                active: true,
                _thread_bound: PhantomData,
            })
        })
        .unwrap_or(Err(AttachError::TlsUnavailable))
}

fn poison() {
    let _ = LOCAL.try_with(|local| local.poisoned.set(true));
}

impl ThreadRegistration {
    /// Return the process-local, nonrecycled registration key stored in payloads.
    pub fn identity(&self) -> u64 {
        self.identity
    }

    /// Return the actual Rust thread identity captured at setup, not a Linux TID.
    pub fn thread_id(&self) -> ThreadId {
        self.thread
    }

    fn access<R>(
        &self,
        action: impl FnOnce(&mut Attached) -> Result<R, BridgeError>,
    ) -> Result<R, BridgeError> {
        if thread::current().id() != self.thread {
            return Err(BridgeError::WrongThread);
        }
        LOCAL
            .try_with(|local| {
                if local.poisoned.get() {
                    return Err(BridgeError::Poisoned);
                }
                let mut storage = local
                    .attached
                    .try_borrow_mut()
                    .map_err(|_| BridgeError::Busy)?;
                let attached = storage.as_mut().ok_or(BridgeError::Detached)?;
                if !self.active || attached.identity != self.identity {
                    return Err(BridgeError::Detached);
                }
                if attached.thread != self.thread {
                    return Err(BridgeError::WrongThread);
                }
                action(attached)
            })
            .unwrap_or(Err(BridgeError::TlsUnavailable))
    }

    fn begin(
        &self,
        install: u64,
        function: FunctionId,
        start: u64,
    ) -> Result<IntervalGuard<'_>, BridgeError> {
        self.access(|attached| {
            let identity = attached.next_slot;
            let next = identity
                .checked_add(1)
                .filter(|_| identity != 0)
                .ok_or(BridgeError::SlotIdentityExhausted)?;
            attached.next_slot = next;
            let mut slot = ModelReturnSlot {
                identity,
                word: ORIGINAL_TOKEN,
            };
            let admission = attached
                .model()
                .enter(install, function, start, &mut slot)
                .map_err(BridgeError::Entry)?;
            Ok(IntervalGuard {
                registration: self,
                slot,
                admission,
                active: true,
            })
        })
    }

    /// Run body exactly once, independently of whether admission succeeds.
    /// Caller-supplied reference values are not qualified timestamps. The TLS
    /// borrow is released before body; ordinary recursion is therefore allowed.
    /// A body panic propagates after exact-frame ordinary-Drop cancellation.
    pub fn observe<R>(
        &self,
        install: u64,
        function: FunctionId,
        start: u64,
        body: impl FnOnce() -> (R, Observation),
    ) -> (R, IntervalOutcome) {
        match self.begin(install, function, start) {
            Ok(guard) => {
                let (value, end) = body();
                (value, guard.finish(end))
            }
            Err(error) => {
                let (value, _) = body();
                (value, IntervalOutcome::Refused(error))
            }
        }
    }

    fn detach_once(&self) -> Result<(), BridgeError> {
        if thread::current().id() != self.thread {
            return Err(BridgeError::WrongThread);
        }
        LOCAL
            .try_with(|local| {
                if local.poisoned.get() {
                    return Err(BridgeError::Poisoned);
                }
                let mut storage = local
                    .attached
                    .try_borrow_mut()
                    .map_err(|_| BridgeError::Busy)?;
                let attached = storage.as_mut().ok_or(BridgeError::Detached)?;
                if !self.active || attached.identity != self.identity {
                    return Err(BridgeError::Detached);
                }
                if attached.thread != self.thread {
                    return Err(BridgeError::WrongThread);
                }
                if attached.model().depth() != 0 {
                    return Err(BridgeError::NonEmpty);
                }
                let old = storage.take();
                drop(storage);
                drop(old);
                Ok(())
            })
            .unwrap_or(Err(BridgeError::TlsUnavailable))
    }

    /// Detach exactly once. A failure retains TLS state and poisons admission;
    /// it is not retried by this consumed registration's destructor.
    pub fn detach(mut self) -> Result<(), BridgeError> {
        let result = self.detach_once();
        self.active = false;
        if result.is_err() {
            poison();
        }
        result
    }
}

impl Drop for ThreadRegistration {
    fn drop(&mut self) {
        if self.active {
            let result = self.detach_once();
            self.active = false;
            if result.is_err() {
                poison();
            }
        }
    }
}

struct IntervalGuard<'a> {
    registration: &'a ThreadRegistration,
    slot: ModelReturnSlot,
    admission: Admission,
    active: bool,
}

impl IntervalGuard<'_> {
    fn finish(mut self, end: Observation) -> IntervalOutcome {
        let result = self.registration.access(|attached| {
            let (completion, payload) = attached
                .model()
                .finish(&mut self.slot, end)
                .map_err(BridgeError::Exit)?;
            if completion.admission != self.admission
                || payload.admission != self.admission
                || payload.thread != self.registration.identity
            {
                return Err(BridgeError::IdentityMismatch);
            }
            if self.slot.word != ORIGINAL_TOKEN {
                return Err(BridgeError::RestorationMismatch);
            }
            Ok((completion, payload))
        });
        self.active = false;
        match result {
            Ok((completion, payload)) => IntervalOutcome::Completed {
                completion,
                payload,
            },
            Err(error) => {
                poison();
                IntervalOutcome::InvariantFailure(error)
            }
        }
    }
}

impl Drop for IntervalGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let result = self.registration.access(|attached| {
                attached
                    .model()
                    .cancel_on_unwind(&mut self.slot)
                    .map_err(BridgeError::Exit)?;
                if self.slot.word != ORIGINAL_TOKEN {
                    return Err(BridgeError::RestorationMismatch);
                }
                Ok(())
            });
            self.active = false;
            if result.is_err() {
                // No double panic, retry, wrong-frame pop, or fabricated report.
                // The model stays owned until ordinary TLS destruction.
                poison();
            }
        }
    }
}

#[cfg(test)]
mod tests;
