//! One installed, prepaid copy of the real pre-opening CALL row. TLS owns the
//! box until the matching physical owner has completed cleanup. No raw pointer,
//! caller-supplied permit, thread-local vector or growing callback allocation.
use super::owner::ArtifactOwner;
use crate::gate::GateError;
use crate::linux::remote::dynamic::owner::Owner;
use crate::linux::remote::dynamic::owner::admission::census::{
    CensusConsumerError, PreparedCallObservation, ResumeCensus, stack_calls::RecordedCall,
};
use crate::linux::remote::dynamic::owner::admission::exact_storage;
use crate::linux::remote::dynamic::owner::admission::runtime::stack::RuntimeStackBinding;
use crate::linux::remote::dynamic::owner::admission::runtime_capture::PreparedInitialSources;
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::PreparedStackNative;
use crate::linux::remote::dynamic::owner::lifecycle::NativeLifecycle;
use std::cell::{Cell, Ref, RefCell, RefMut};
use std::marker::PhantomData;
use std::mem::size_of;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
mod tests;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SinkError {
    Capacity,
    Allocation,
    Reused,
    ForeignOwner,
    Borrowed,
    Unavailable,
    CleanupIncomplete,
    Aborted,
    ThreadId,
    Census(CensusConsumerError),
}
impl From<CensusConsumerError> for SinkError {
    fn from(value: CensusConsumerError) -> Self {
        Self::Census(value)
    }
}
impl From<exact_storage::AllocationError> for SinkError {
    fn from(value: exact_storage::AllocationError) -> Self {
        match value {
            exact_storage::AllocationError::Capacity => Self::Capacity,
            exact_storage::AllocationError::Allocation => Self::Allocation,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SinkIdentity {
    pub(super) id: u64,
    pub(super) host_tid: i32,
    pub(super) owner_session: u64,
    pub(super) application: i32,
}
impl SinkIdentity {
    fn matches_owner(self, owner: &Owner) -> bool {
        self.owner_session == owner.anchor_session() && self.application == owner.pid
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ThreadObservation {
    pub(super) result: i64,
    pub(super) errno: i32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SinkProgress {
    pub(super) install_started: bool,
    pub(super) identity: Option<SinkIdentity>,
    pub(super) thread: Option<ThreadObservation>,
    pub(super) claimed: bool,
    pub(super) retired: bool,
    pub(super) box_installed: bool,
    pub(super) allocation_complete: bool,
    pub(super) callback_started: bool,
    pub(super) callback_complete: bool,
    pub(super) first_failure: Option<SinkError>,
}
impl SinkProgress {
    const fn empty() -> Self {
        Self {
            install_started: false,
            identity: None,
            thread: None,
            claimed: false,
            retired: false,
            box_installed: false,
            allocation_complete: false,
            callback_started: false,
            callback_complete: false,
            first_failure: None,
        }
    }
}
struct Slot {
    ever_used: bool,
    identity: Option<SinkIdentity>,
    retired: bool,
    allocation_complete: bool,
    callback_started: bool,
    callback_complete: bool,
    observation: Option<Box<PreparedCallObservation>>,
}
impl Slot {
    const fn empty() -> Self {
        Self {
            ever_used: false,
            identity: None,
            retired: false,
            allocation_complete: false,
            callback_started: false,
            callback_complete: false,
            observation: None,
        }
    }
    fn require(&self, identity: SinkIdentity) -> Result<(), SinkError> {
        if !self.ever_used || self.identity != Some(identity) {
            return Err(SinkError::ForeignOwner);
        }
        Ok(())
    }
}
struct ThreadSlot {
    busy: Cell<bool>,
    first_failure: Cell<Option<SinkError>>,
    slot: RefCell<Slot>,
}
impl ThreadSlot {
    const fn empty() -> Self {
        Self {
            busy: Cell::new(false),
            first_failure: Cell::new(None),
            slot: RefCell::new(Slot::empty()),
        }
    }
    fn fail(&self, error: SinkError) {
        if self.first_failure.get().is_none() {
            self.first_failure.set(Some(error));
        }
    }
    fn enter(&self) -> Result<Busy<'_>, SinkError> {
        if self.busy.replace(true) {
            self.fail(SinkError::Borrowed);
            return Err(SinkError::Borrowed);
        }
        Ok(Busy(self))
    }
}
struct Busy<'a>(&'a ThreadSlot);
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.busy.set(false);
    }
}
impl Drop for ThreadSlot {
    fn drop(&mut self) {
        // Also catches a forgotten outer sink at thread destruction: TLS must
        // never silently free an installed prefix before physical cleanup.
        let slot = self.slot.get_mut();
        if slot.ever_used && (!slot.retired || slot.observation.is_some()) {
            std::process::abort();
        }
    }
}
thread_local! {
    static TLS: ThreadSlot = const { ThreadSlot::empty() };
}

pub(super) struct CallSink {
    progress: SinkProgress,
    retained: Option<Box<PreparedCallObservation>>,
    // Moving this guard to another thread would detach its real TLS owner.
    _thread: PhantomData<Rc<()>>,
}
fn add(a: usize, b: usize) -> Result<usize, SinkError> {
    a.checked_add(b).ok_or(SinkError::Capacity)
}
fn headers() -> Result<usize, SinkError> {
    add(
        add(size_of::<CallSink>(), size_of::<ThreadSlot>())?,
        size_of::<AtomicU64>(),
    )
}
impl CallSink {
    pub(super) const fn empty() -> Self {
        Self {
            progress: SinkProgress::empty(),
            retained: None,
            _thread: PhantomData,
        }
    }
    pub(super) fn reservation_bytes(source_capacity: usize) -> Result<usize, SinkError> {
        add(
            headers()?,
            PreparedCallObservation::reservation_bytes(source_capacity)?,
        )
    }
    pub(super) fn temporary_bytes() -> Result<usize, SinkError> {
        let mut total = size_of::<PreparedCallObservation>();
        for bytes in [
            3 * size_of::<SinkProgress>(),
            2 * size_of::<SinkIdentity>(),
            size_of::<ThreadObservation>(),
            size_of::<Ref<'static, Slot>>(),
            size_of::<RefMut<'static, Slot>>(),
            size_of::<Busy<'static>>(),
            6 * size_of::<Result<(), SinkError>>(),
        ] {
            total = add(total, bytes)?;
        }
        Ok(total)
    }
    fn fail(&mut self, error: SinkError) {
        // The callback can have recorded an earlier error without borrowing
        // this outer guard. Preserve that earlier failure when reconciling.
        let first = if self.progress.claimed {
            TLS.try_with(|tls| {
                tls.fail(error);
                tls.first_failure.get().unwrap_or(error)
            })
            .unwrap_or(error)
        } else {
            error
        };
        self.progress.first_failure.get_or_insert(first);
    }
    // Shared closed entry gate. No owner/native/TLS claim is introduced here.
    // Pure controls can inspect refusal before the production owner argument
    // is ever observed; successful claimed retirement still needs real cleanup.
    fn start_install(&mut self) -> Result<(), SinkError> {
        if self.progress.install_started || self.progress.retired || self.retained.is_some() {
            self.fail(SinkError::Reused);
            return Err(SinkError::Reused);
        }
        self.progress.install_started = true;
        Ok(())
    }
    /// Caller has already reserved complete Q. It must settle installed bytes
    /// on Ok/Err/unwind and finish Q before any production operation reserves.
    pub(super) fn install(
        &mut self,
        source_capacity: usize,
        owner: &Owner,
    ) -> Result<(), SinkError> {
        self.start_install()?;
        let result = (|| {
            Self::reservation_bytes(source_capacity)?;
            if owner.pid <= 0
                || owner.anchor_session() == 0
                || owner.closing
                || owner.cancel.load(Ordering::Acquire)
            {
                return Err(SinkError::ForeignOwner);
            }
            // SAFETY: one argument-free Linux gettid observation. It confers
            // no task/stop authority and is never repeated by the callback.
            let result = unsafe {
                *libc::__errno_location() = 0;
                libc::syscall(libc::SYS_gettid)
            };
            let errno = unsafe { *libc::__errno_location() };
            self.progress.thread = Some(ThreadObservation { result, errno });
            if result <= 0 || result > i64::from(i32::MAX) || errno != 0 {
                return Err(SinkError::ThreadId);
            }
            let id = NEXT_ID
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| SinkError::Capacity)?;
            let identity = SinkIdentity {
                id,
                host_tid: result as i32,
                owner_session: owner.anchor_session(),
                application: owner.pid,
            };
            self.progress.identity = Some(identity);
            TLS.try_with(|tls| {
                let _busy = tls.enter()?;
                let mut slot = tls.slot.try_borrow_mut().map_err(|_| SinkError::Borrowed)?;
                if slot.ever_used || tls.first_failure.get().is_some() {
                    return Err(SinkError::Reused);
                }
                // Fixed ownership installed before header allocation, payload
                // allocation or a subsequent fallible operation.
                slot.ever_used = true;
                slot.identity = Some(identity);
                self.progress.claimed = true;
                slot.observation = Some(exact_storage::value(PreparedCallObservation::empty())?);
                self.progress.box_installed = true;
                slot.observation
                    .as_mut()
                    .ok_or(SinkError::Unavailable)?
                    .allocate_payloads(source_capacity)?;
                slot.allocation_complete = true;
                self.progress.allocation_complete = true;
                Ok(())
            })
            .map_err(|_| SinkError::Unavailable)?
        })();
        if let Err(error) = result {
            self.fail(error);
        }
        result
    }
    fn identity(&self) -> Result<SinkIdentity, SinkError> {
        self.progress.identity.ok_or(SinkError::Unavailable)
    }
    /// HRTB forbids the result from borrowing the snapshot. The closure may
    /// inspect/copy only its own prepaid data; it may not invoke this sink again.
    pub(super) fn with_snapshot<R>(
        &self,
        read: impl for<'a> FnOnce(Option<&'a PreparedCallObservation>) -> R,
    ) -> Result<R, SinkError> {
        if !self.progress.claimed {
            return Ok(read(None));
        }
        let identity = self.identity()?;
        TLS.try_with(|tls| {
            let _busy = tls.enter()?;
            let slot = tls.slot.try_borrow().map_err(|_| SinkError::Borrowed)?;
            slot.require(identity)?;
            if self.progress.retired {
                if !slot.retired || slot.observation.is_some() {
                    return Err(SinkError::Unavailable);
                }
                Ok(read(self.retained.as_deref()))
            } else {
                if slot.retired {
                    return Err(SinkError::Reused);
                }
                Ok(read(slot.observation.as_deref()))
            }
        })
        .map_err(|_| SinkError::Unavailable)?
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize, SinkError> {
        self.with_snapshot(|snapshot| {
            add(
                headers()?,
                match snapshot {
                    Some(value) => value.allocated_bytes()?,
                    None => 0,
                },
            )
        })?
    }
    pub(super) fn progress(&self) -> Result<SinkProgress, SinkError> {
        if !self.progress.claimed {
            return Ok(self.progress);
        }
        let identity = self.identity()?;
        TLS.try_with(|tls| {
            let _busy = tls.enter()?;
            let slot = tls.slot.try_borrow().map_err(|_| SinkError::Borrowed)?;
            slot.require(identity)?;
            let mut result = self.progress;
            result.box_installed = slot.observation.is_some() || self.retained.is_some();
            result.allocation_complete = slot.allocation_complete;
            result.callback_started = slot.callback_started;
            result.callback_complete = slot.callback_complete;
            result.first_failure = result.first_failure.or(tls.first_failure.get());
            Ok(result)
        })
        .map_err(|_| SinkError::Unavailable)?
    }
    pub(super) fn mark_aborted(&mut self) -> Result<(), SinkError> {
        if !self.progress.claimed || self.progress.retired {
            if self.progress.install_started && !self.progress.allocation_complete {
                self.progress
                    .first_failure
                    .get_or_insert(SinkError::Aborted);
            }
            return Ok(());
        }
        let identity = self.identity()?;
        TLS.try_with(|tls| {
            let _busy = tls.enter()?;
            let mut slot = tls.slot.try_borrow_mut().map_err(|_| SinkError::Borrowed)?;
            slot.require(identity)?;
            if !slot.allocation_complete || (slot.callback_started && !slot.callback_complete) {
                tls.fail(SinkError::Aborted);
            }
            if let Some(value) = &mut slot.observation {
                value.mark_aborted();
            }
            Ok(())
        })
        .map_err(|_| SinkError::Unavailable)?
    }
    /// Called on every outcome only after the matching original physical owner
    /// was drained. Moving the Box retains its address/capacity with no allocation.
    pub(super) fn retire_after_cleanup(&mut self, owner: &ArtifactOwner) -> Result<(), SinkError> {
        let result = self.retire_inner(owner);
        if let Err(error) = result {
            self.fail(error);
        }
        result
    }
    fn retire_inner(&mut self, owner: &ArtifactOwner) -> Result<(), SinkError> {
        if self.progress.retired {
            return Err(SinkError::Reused);
        }
        let guard = owner.partial_view();
        if !guard.cleanup_complete {
            return Err(SinkError::CleanupIncomplete);
        }
        if let Some(identity) = self.progress.identity {
            let actual = guard.owner.ok_or(SinkError::ForeignOwner)?;
            if !identity.matches_owner(actual)
                || guard.application.pid != Some(identity.application)
                || !guard.application.complete
                || !guard.helper.complete
            {
                return Err(SinkError::ForeignOwner);
            }
        }
        if !self.progress.claimed {
            self.progress.retired = true;
            return Ok(());
        }
        let identity = self.identity()?;
        TLS.try_with(|tls| {
            let _busy = tls.enter()?;
            let mut slot = tls.slot.try_borrow_mut().map_err(|_| SinkError::Borrowed)?;
            slot.require(identity)?;
            if slot.retired || self.retained.is_some() {
                return Err(SinkError::Reused);
            }
            self.progress.box_installed = slot.observation.is_some();
            self.progress.allocation_complete = slot.allocation_complete;
            self.progress.callback_started = slot.callback_started;
            self.progress.callback_complete = slot.callback_complete;
            self.progress.first_failure = self.progress.first_failure.or(tls.first_failure.get());
            self.retained = slot.observation.take();
            slot.retired = true;
            self.progress.retired = true;
            Ok(())
        })
        .map_err(|_| SinkError::Unavailable)?
    }
}
impl Drop for CallSink {
    fn drop(&mut self) {
        if self.progress.claimed && !self.progress.retired {
            std::process::abort();
        }
    }
}

/// Exact existing BeforeOpening signature. Unused arguments stay immutable;
/// the authentic row/binding helper performs all copy validation. No queries,
/// reservations, debit, allocation, token/permit construction or retry occur.
pub(super) fn before_opening(
    owner: &Owner,
    _native: &NativeLifecycle,
    record: &RecordedCall<'_>,
    binding: &RuntimeStackBinding<'_, '_>,
    _prepared: &PreparedStackNative,
    _census: &ResumeCensus,
    _sources: &PreparedInitialSources,
) -> Result<(), GateError> {
    let result = TLS
        .try_with(|tls| {
            let operation = (|| {
                let _busy = tls.enter()?;
                let mut slot = tls.slot.try_borrow_mut().map_err(|_| SinkError::Borrowed)?;
                let identity = slot.identity.ok_or(SinkError::Unavailable)?;
                if !slot.ever_used
                    || slot.retired
                    || slot.callback_started
                    || !slot.allocation_complete
                {
                    return Err(SinkError::Reused);
                }
                if !identity.matches_owner(owner)
                    || binding.stop().token.session != identity.owner_session
                    || binding.stop().token.tid != identity.application
                {
                    return Err(SinkError::ForeignOwner);
                }
                if let Some(error) = tls.first_failure.get() {
                    return Err(error);
                }
                slot.callback_started = true;
                record.copy_consumer_observation_into(
                    binding,
                    slot.observation.as_mut().ok_or(SinkError::Unavailable)?,
                )?;
                slot.callback_complete = true;
                Ok(())
            })();
            if let Err(error) = operation {
                tls.fail(error);
            }
            operation
        })
        .map_err(|_| SinkError::Unavailable)
        .and_then(|result| result);
    result.map_err(|_| GateError::Refused("consumer CALL observation sink refused"))
}
