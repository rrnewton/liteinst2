//! Bounded pure frontend/session/controller model. All return slots and physical
//! states below are data: this module installs no TLS, return hook, trap, or code.
//! Frontend owners retain their permit until their actual last strong owner drops.
//! Crate-private point-adapter updates may store managed flags while the existing
//! writer/registry locks are held; model Booleans still are not physical receipts.

use crate::generation::{
    Admission, AdmissionRefusal, CancelReason, Completion, Config, CreateError,
    DeactivationRequest, Epoch, FunctionId, GenerationId, OwnedTicket, PopulationObservation,
    Record,
};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};

/// Maximum simultaneously retained frontend epochs in this first model.
pub const MAX_EPOCHS: usize = 8;
/// Maximum registered identities in a session; identities are never recycled.
pub const MAX_THREADS: usize = 8;
/// Maximum model frames preallocated for one registered thread.
pub const MAX_DEPTH: usize = 32;
/// Maximum immutable function/group rows in this first model.
pub const MAX_MODEL_FUNCTIONS: usize = 16;
/// Maximum per-epoch payload slots, independent of its M reservation limit.
pub const MAX_MODEL_RECORDS: usize = 4096;
/// Maximum checked E times A payload slots for a session.
pub const MAX_TOTAL_RECORDS: usize = 16_384;
/// Maximum controller history entries, allocated before publication.
pub const MAX_ACTIONS: usize = 256;
const MODEL_CONTINUATION: u64 = 0xfedc_ba98_7654_3210;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Finite allocation and history limits fixed before model admission.
pub struct Limits {
    /// E: simultaneously retained frontend epochs, including handles/reports.
    pub epochs: usize,
    /// T: lifetime registered thread identities.
    pub threads: usize,
    /// D: simultaneous frames per registered thread.
    pub depth: usize,
    /// A ceiling for each epoch's preallocated payload slots.
    pub records_per_epoch: usize,
    /// Finite controller action history; exhaustion refuses before mutation.
    pub actions: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Function membership in a caller-declared physical group.
pub struct FunctionSpec {
    /// Immutable function identity.
    pub function: FunctionId,
    /// Zero-based group index.
    pub group: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A permanent action prevents this model from disabling its shared group.
pub struct GroupSpec {
    /// True when a mandatory action remains active regardless of profiling K.
    pub mandatory: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Refusal constructing bounded metadata, before entry is possible.
pub enum SetupError {
    /// An invalid zero, maximum, arithmetic or group-ownership limit.
    InvalidLimits,
    /// Duplicate or empty function identities.
    InvalidFunctions,
    /// Failed bounded Vec allocation. Arc's standard OOM behavior is unchanged.
    Allocation,
    /// All E permits are retained by actual live owners.
    EpochLimit,
    /// T lifetime registration slots are assigned.
    ThreadLimit,
    /// The caller attempted to reuse a registered thread identity.
    DuplicateThread,
    /// A registry or controller was poisoned.
    Poisoned,
    /// The existing generation constructor refused its own exact contract.
    Generation(CreateError),
    /// This operation does not belong to the once-issued storage mode.
    StorageMode,
    /// Storage identity or pristine preparation state differs.
    InvalidStorage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Entry refusal, with no model return-slot or record mutation by that entry.
pub enum EntryError {
    /// Another controller/acquisition owns the short registry lock.
    RegistryBusy,
    /// Registry poison is explicit and never treated as an empty binding.
    RegistryPoisoned,
    /// The registry has no current epoch.
    NoCurrent,
    /// The thread identity was not registered.
    UnknownThread,
    /// Installed-site identity differs from this session.
    WrongInstall,
    /// An acquired handle belongs to another session or thread.
    ForeignHandle,
    /// Entry was attempted while this model thread was already in its callback.
    Reentry,
    /// D preallocated frame slots are occupied.
    Depth,
    /// A model return-slot identity is already owned by an active frame.
    SlotInUse,
    /// A nonwrapping attempt/completion sequence cannot accept another interval.
    CounterExhausted,
    /// The unchanged generation admission contract refused.
    Generation(AdmissionRefusal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Exit contract violation; existing frame and model slot remain unchanged.
pub enum ExitError {
    /// No frame owns an exit.
    Empty,
    /// The provided model slot or continuation does not match the top frame.
    SlotMismatch,
    /// Checked sequence arithmetic is exhausted or inconsistent.
    Sequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A test observation value; neither variant is a qualified timestamp.
pub enum Observation {
    /// Explicit caller-supplied reference data.
    Value(u64),
    /// Explicit unavailable measurement reason, still a completed invocation.
    Unavailable(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Payload publication preceding the corresponding generation terminal.
pub enum PayloadOutcome {
    /// Ordinary model completion, including observed children across epochs.
    Completed {
        end: Observation,
        completed_children: u64,
    },
    /// Explicit or ordinary-Drop cancellation, without consuming K.
    Cancelled(CancelReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Raw preallocated payload keyed by the immutable admission slot.
pub struct Payload {
    /// Original epoch/function/invocation and entry data.
    pub admission: Admission,
    /// Pre-registered model thread identity.
    pub thread: u64,
    /// Thread completion sequence observed at admission.
    pub start_sequence: u64,
    /// Exact completion or cancellation observation.
    pub outcome: PayloadOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Record/payload pair. Partial records explicitly have absent fields.
pub struct RecordObservation {
    /// Underlying unchanged generation record.
    pub record: Record,
    /// Payload may precede terminal publication in a partial observation.
    pub payload: Option<Payload>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A data-only stand-in for a return slot. No pointer is read or written.
pub struct ModelReturnSlot {
    /// Caller-supplied stable identity, unique among simultaneous frames.
    pub identity: u64,
    /// Original continuation token, restored exactly by model finish/cancel.
    pub word: u64,
}

struct PermitPool {
    active: AtomicUsize,
    limit: usize,
}
struct Permit {
    pool: Arc<PermitPool>,
}
impl PermitPool {
    fn reserve(self: &Arc<Self>) -> Result<Permit, SetupError> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n < self.limit { Some(n + 1) } else { None }
            })
            .map_err(|_| SetupError::EpochLimit)?;
        Ok(Permit {
            pool: Arc::clone(self),
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        assert!(self.pool.active.fetch_sub(1, Ordering::AcqRel) > 0);
    }
}
struct Spec {
    install: u64,
    limits: Limits,
    functions: Vec<FunctionSpec>,
    ids: Vec<FunctionId>,
    groups: Vec<GroupSpec>,
}
struct FrontendEpoch {
    epoch: Arc<Epoch>,
    spec: Arc<Spec>,
    payloads: Vec<OnceLock<Payload>>,
    storage_bank: Option<usize>,
    // Some for every live owner; only a private recycled bank holds None.
    _permit: Option<Permit>,
}
impl FrontendEpoch {
    fn records(&self) -> impl Iterator<Item = RecordObservation> + '_ {
        self.epoch.records().map(|record| RecordObservation {
            payload: self.payloads[record.admission.invocation].get().copied(),
            record,
        })
    }
}

#[derive(Clone)]
/// Retained frontend owner, never exposing a live ticket or bare epoch Arc.
/// Keeping this handle after drain still consumes E.
///
/// ```compile_fail,E0616
/// use rapid_profiler::frontend::EpochHandle;
/// fn escape(handle: EpochHandle) { let epoch = handle.owner.epoch; }
/// ```
pub struct EpochHandle {
    owner: Arc<FrontendEpoch>,
}
impl EpochHandle {
    /// Return immutable generation identity.
    pub fn generation(&self) -> GenerationId {
        self.owner.epoch.id()
    }
    /// Close metadata admission only. This performs no code change or unmapping.
    pub fn close(&self) -> usize {
        self.owner.epoch.close()
    }
    /// Observe outstanding reservation/release obligations, not strong owners.
    pub fn reservations(&self) -> usize {
        self.owner.epoch.reservations()
    }
    /// Observe partial records without pretending they are an atomic snapshot.
    pub fn records(&self) -> impl Iterator<Item = RecordObservation> + '_ {
        self.owner.records()
    }
    /// Observe the existing partial/final per-function population contract.
    pub fn population(&self, function: FunctionId) -> Option<PopulationObservation> {
        self.owner.epoch.population(function)
    }
    /// Acquire final report access after closed+zero; the report retains E.
    pub fn try_report(&self) -> Option<Report> {
        self.owner.epoch.try_drain()?;
        Some(Report {
            owner: Arc::clone(&self.owner),
        })
    }
}

/// A retained final-report owner; payloads and terminals precede admission here.
/// This reports metadata drain, never code/execution drain.
///
/// ```compile_fail,E0616
/// use rapid_profiler::frontend::Report;
/// fn escape(report: Report) { let epoch = report.owner.epoch; }
/// ```
pub struct Report {
    owner: Arc<FrontendEpoch>,
}
impl Report {
    /// Return the original generation.
    pub fn generation(&self) -> GenerationId {
        self.owner.epoch.id()
    }
    /// Iterate exact final records without allocating or releasing the owner.
    pub fn records(&self) -> impl Iterator<Item = RecordObservation> + '_ {
        self.owner.records().inspect(|row| {
            assert!(row.record.terminal.is_some() && row.payload.is_some());
        })
    }
}

/// Acquired but not yet admitted owner; it also retains its frontend permit.
/// No operation extracts its bare epoch or a live ticket.
///
/// ```compile_fail,E0616
/// use rapid_profiler::frontend::AdmissionHandle;
/// fn escape(handle: AdmissionHandle) { let epoch = handle.owner.epoch; }
/// ```
pub struct AdmissionHandle {
    owner: Arc<FrontendEpoch>,
    thread: u64,
}
impl AdmissionHandle {
    /// Return the acquired epoch, which may close before later admission.
    pub fn generation(&self) -> GenerationId {
        self.owner.epoch.id()
    }
}

struct Registry {
    current: Option<Arc<FrontendEpoch>>,
    threads: Vec<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Explicit injected outcomes of a pure controller transition, not real barriers.
pub enum FailurePoint {
    /// Model the successful metadata transition.
    None,
    /// Refuse before changing binding/group data.
    BeforeMutation,
    /// Change model data, then retain terminal failed ownership without retry.
    AfterMutation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Controller state; terminal failure cannot be retried by this session.
pub enum ControllerStatus {
    Ready,
    TerminalFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// One data-only controller action in its finite history.
pub enum ActionKind {
    Published,
    Removed,
    Stale,
    Deferred,
    Disabled,
    FailedBefore,
    FailedAfter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Exact recorded action identity, separate from the model's final state.
pub struct Action {
    /// Action classification.
    pub kind: ActionKind,
    /// Requested/new generation.
    pub generation: GenerationId,
    /// Physical group's function, where applicable.
    pub function: Option<FunctionId>,
    /// Current generation when evaluating this action.
    pub current: Option<GenerationId>,
    /// The group concerned, or none for binding publication/removal.
    pub group: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Bounded controller refusal, with no implicit retry or fallback.
pub enum ControlError {
    Poisoned,
    ForeignEpoch,
    TerminalFailure,
    HistoryFull,
    NoCurrent,
    UnknownFunction,
    FunctionOpen,
    ClosedEpoch,
    AlreadyCurrent,
    InjectedBefore,
    InjectedAfter,
    /// This operation requires the explicit absolute-history policy.
    HistoryMode,
    HistoryExhausted,
    HistoryInvariant,
    HistoryAllocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Bounded diagnostic copy taken outside the entry path.
pub struct ControllerSnapshot {
    /// Current model controller state.
    pub status: ControllerStatus,
    /// Published metadata generation.
    pub current: Option<GenerationId>,
    /// One Boolean per immutable group; these are not executable bytes.
    pub enabled: Vec<bool>,
    /// Exact bounded action sequence.
    pub actions: Vec<Action>,
    /// Failed transition owner retained by controller until session destruction.
    pub retained_failed_generation: Option<GenerationId>,
}
struct Controller {
    status: ControllerStatus,
    current: Option<GenerationId>,
    enabled: Vec<bool>,
    actions: Vec<Action>,
    history: history_stream::HistoryState,
    failed_owner: Option<Arc<FrontendEpoch>>,
}
struct SessionInner {
    spec: Arc<Spec>,
    pool: Arc<PermitPool>,
    registry: Mutex<Registry>,
    writer: Mutex<Controller>,
    history_mode: HistoryMode,
    committed_end: AtomicU64,
    storage_mode: Option<Config>,
    ever_staged: AtomicBool,
    #[cfg(test)]
    entry_waits: [AtomicUsize; 2],
}

/// Bounded session with writer-before-registry lock order. No destructor takes
/// either lock, and there is no owner-to-session cycle through FrontendEpoch.
pub struct Session {
    inner: Arc<SessionInner>,
}
fn reserved<T>(n: usize) -> Result<Vec<T>, SetupError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| SetupError::Allocation)?;
    Ok(v)
}
impl Session {
    /// Allocate finite metadata. Vec failures are typed; Arc uses standard Rust OOM.
    pub fn new(
        install: u64,
        functions: &[FunctionSpec],
        groups: &[GroupSpec],
        limits: Limits,
    ) -> Result<Self, SetupError> {
        if install == 0
            || limits.epochs == 0
            || limits.epochs > MAX_EPOCHS
            || limits.threads == 0
            || limits.threads > MAX_THREADS
            || limits.depth == 0
            || limits.depth > MAX_DEPTH
            || limits.records_per_epoch == 0
            || limits.records_per_epoch > MAX_MODEL_RECORDS
            || limits.actions == 0
            || limits.actions > MAX_ACTIONS
            || limits
                .epochs
                .checked_mul(limits.records_per_epoch)
                .is_none_or(|n| n > MAX_TOTAL_RECORDS)
            || groups.is_empty()
            || groups.len() > MAX_MODEL_FUNCTIONS
        {
            return Err(SetupError::InvalidLimits);
        }
        if functions.is_empty()
            || functions.len() > MAX_MODEL_FUNCTIONS
            || functions
                .iter()
                .enumerate()
                .any(|(i, f)| functions[..i].iter().any(|p| p.function == f.function))
        {
            return Err(SetupError::InvalidFunctions);
        }
        if functions.iter().any(|f| f.group >= groups.len())
            || (0..groups.len()).any(|g| !functions.iter().any(|f| f.group == g))
        {
            return Err(SetupError::InvalidLimits);
        }
        let mut fs = reserved(functions.len())?;
        fs.extend_from_slice(functions);
        let mut ids = reserved(functions.len())?;
        ids.extend(functions.iter().map(|f| f.function));
        let mut gs = reserved(groups.len())?;
        gs.extend_from_slice(groups);
        let mut enabled = reserved(groups.len())?;
        enabled.resize(groups.len(), false);
        let spec = Arc::new(Spec {
            install,
            limits,
            functions: fs,
            ids,
            groups: gs,
        });
        Ok(Self {
            inner: Arc::new(SessionInner {
                spec,
                pool: Arc::new(PermitPool {
                    active: AtomicUsize::new(0),
                    limit: limits.epochs,
                }),
                registry: Mutex::new(Registry {
                    current: None,
                    threads: reserved(limits.threads)?,
                }),
                writer: Mutex::new(Controller {
                    status: ControllerStatus::Ready,
                    current: None,
                    enabled,
                    actions: reserved(limits.actions)?,
                    history: history_stream::HistoryState::new(),
                    failed_owner: None,
                }),
                history_mode: HistoryMode::Legacy,
                committed_end: AtomicU64::new(0),
                storage_mode: None,
                ever_staged: AtomicBool::new(false),
                #[cfg(test)]
                entry_waits: [const { AtomicUsize::new(0) }; 2],
            }),
        })
    }

    /// Observe actual retained frontend owners, not registry entries or tickets.
    pub fn retained_epochs(&self) -> usize {
        self.inner.pool.active.load(Ordering::Acquire)
    }

    /// Allocate an epoch before admission. Error drops any acquired permit.
    pub fn stage(&self, config: Config) -> Result<EpochHandle, SetupError> {
        if self.inner.storage_mode.is_some() {
            return Err(SetupError::StorageMode);
        }
        if config.max_invocations > self.inner.spec.limits.records_per_epoch {
            return Err(SetupError::InvalidLimits);
        }
        let permit = self.inner.pool.reserve()?;
        let epoch =
            Arc::new(Epoch::new(&self.inner.spec.ids, config).map_err(SetupError::Generation)?);
        let mut payloads = reserved(config.max_invocations)?;
        payloads.resize_with(config.max_invocations, OnceLock::new);
        let handle = EpochHandle {
            owner: Arc::new(FrontendEpoch {
                epoch,
                spec: Arc::clone(&self.inner.spec),
                payloads,
                storage_bank: None,
                _permit: Some(permit),
            }),
        };
        self.inner.ever_staged.store(true, Ordering::Release);
        Ok(handle)
    }

    /// Preallocate D frames before registering a never-reused thread identity.
    pub fn register_thread(&self, identity: u64) -> Result<ThreadModel, SetupError> {
        let frames = reserved(self.inner.spec.limits.depth)?;
        let mut r = self
            .inner
            .registry
            .lock()
            .map_err(|_| SetupError::Poisoned)?;
        if r.threads.contains(&identity) {
            return Err(SetupError::DuplicateThread);
        }
        if r.threads.len() == self.inner.spec.limits.threads {
            return Err(SetupError::ThreadLimit);
        }
        r.threads.push(identity);
        Ok(ThreadModel {
            session: Arc::clone(&self.inner),
            identity,
            frames,
            completed_sequence: 0,
            attempts: 0,
            in_callback: false,
            exhausted: false,
        })
    }

    /// Safely acquire a current owner with one try-lock, never a raw Arc pointer.
    pub fn acquire(&self, thread: u64, install: u64) -> Result<AdmissionHandle, EntryError> {
        self.inner.acquire(thread, install)
    }

    /// Publish staged metadata under uninterrupted writer then registry authority.
    /// Injected failures concern model data only, never real instruction visibility.
    pub fn publish(&self, next: &EpochHandle, failure: FailurePoint) -> Result<(), ControlError> {
        self.publish_with_controls(next, failure, |_| {})
    }

    // Only crate-owned infallible atomic stores run here; never caller callbacks.
    // Writer and registry authority remain held through all control changes.
    pub(crate) fn publish_with_controls(
        &self,
        next: &EpochHandle,
        failure: FailurePoint,
        update: impl FnOnce(&[bool]),
    ) -> Result<(), ControlError> {
        if !Arc::ptr_eq(&self.inner.spec, &next.owner.spec) {
            return Err(ControlError::ForeignEpoch);
        }
        let mut w = self
            .inner
            .writer
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        self.inner.preflight_writer(&w, 1)?;
        let mut r = self
            .inner
            .registry
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        let generation = next.generation();
        if w.current == Some(generation) {
            return Err(ControlError::AlreadyCurrent);
        }
        if next.owner.epoch.is_closed() {
            return Err(ControlError::ClosedEpoch);
        }
        if failure == FailurePoint::BeforeMutation {
            let current = w.current;
            self.inner.append_action(
                &mut w,
                Action {
                    kind: ActionKind::FailedBefore,
                    generation,
                    function: None,
                    current,
                    group: None,
                },
            );
            return Err(ControlError::InjectedBefore);
        }
        if let Some(old) = &r.current {
            old.epoch.close();
        }
        r.current = Some(Arc::clone(&next.owner));
        w.current = Some(generation);
        w.enabled.fill(true);
        if failure == FailurePoint::AfterMutation {
            next.owner.epoch.close();
            w.failed_owner = Some(Arc::clone(&next.owner));
            w.status = ControllerStatus::TerminalFailure;
            self.inner.append_action(
                &mut w,
                Action {
                    kind: ActionKind::FailedAfter,
                    generation,
                    function: None,
                    current: Some(generation),
                    group: None,
                },
            );
            return Err(ControlError::InjectedAfter);
        }
        self.inner.append_action(
            &mut w,
            Action {
                kind: ActionKind::Published,
                generation,
                function: None,
                current: Some(generation),
                group: None,
            },
        );
        self.inner.update_controls(&r, update);
        Ok(())
    }

    /// Remove current metadata and close admission; this does not retire code.
    pub fn remove_current(&self) -> Result<(), ControlError> {
        self.remove_with_controls(None, |_| {})
    }

    pub(crate) fn remove_with_controls(
        &self,
        expected: Option<GenerationId>,
        update: impl FnOnce(&[bool]),
    ) -> Result<(), ControlError> {
        let mut w = self
            .inner
            .writer
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        self.inner.preflight_writer(&w, 1)?;
        let mut r = self
            .inner
            .registry
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        if expected.is_some() && w.current != expected {
            return Err(ControlError::ForeignEpoch);
        }
        let old = r.current.take().ok_or(ControlError::NoCurrent)?;
        old.epoch.close();
        let generation = old.epoch.id();
        w.current = None;
        self.inner.append_action(
            &mut w,
            Action {
                kind: ActionKind::Removed,
                generation,
                function: None,
                current: None,
                group: None,
            },
        );
        self.inner.update_controls(&r, update);
        Ok(())
    }

    /// Evaluate a generation-bound request under the same authority used to act.
    pub fn deactivate(
        &self,
        request: DeactivationRequest,
        failure: FailurePoint,
    ) -> Result<(), ControlError> {
        self.deactivate_with_controls(request, failure, |_| {})
    }

    pub(crate) fn deactivate_with_controls(
        &self,
        request: DeactivationRequest,
        failure: FailurePoint,
        update: impl FnOnce(&[bool]),
    ) -> Result<(), ControlError> {
        let mut w = self
            .inner
            .writer
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        self.inner.preflight_writer(&w, 1)?;
        let r = self
            .inner
            .registry
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        self.inner.apply_request(&mut w, &r, request, failure)?;
        if w.current == Some(request.generation) {
            self.inner.update_controls(&r, update);
        }
        Ok(())
    }

    // A data-admission completion barrier, not an instruction-stream barrier.
    // The same locks serialize publication/physical stores and owner acquisition.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn confirm_controls(
        &self,
        expected: Option<GenerationId>,
    ) -> Result<(), ControlError> {
        let w = self
            .inner
            .writer
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        self.inner.preflight_writer(&w, 0)?;
        let r = self
            .inner
            .registry
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        if w.current != expected || r.current.as_ref().map(|o| o.epoch.id()) != expected {
            return Err(ControlError::ForeignEpoch);
        }
        Ok(())
    }

    // Exact group intent for the separate code-point transaction. This takes
    // only metadata locks and returns data; it never invokes a publisher.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn code_groups(
        &self,
        expected: Option<GenerationId>,
    ) -> Result<Vec<bool>, ControlError> {
        let w = self
            .inner
            .writer
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        self.inner.preflight_writer(&w, 0)?;
        let r = self
            .inner
            .registry
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        if w.current != expected || r.current.as_ref().map(|o| o.epoch.id()) != expected {
            return Err(ControlError::ForeignEpoch);
        }
        Ok(self
            .inner
            .spec
            .groups
            .iter()
            .enumerate()
            .map(|(group, spec)| {
                let all_closed = r.current.as_ref().is_none_or(|owner| {
                    owner.epoch.is_closed()
                        || self
                            .inner
                            .spec
                            .functions
                            .iter()
                            .filter(|f| f.group == group)
                            .all(|f| owner.epoch.function_closed(f.function) == Some(true))
                });
                !all_closed || spec.mandatory
            })
            .collect())
    }

    /// Bounded closed-function scan; no notification queue can silently lose work.
    /// Capacity for every function is checked before any action, since completion
    /// may close another function while the scan holds writer authority.
    pub fn scan_closed(&self) -> Result<usize, ControlError> {
        self.scan_with_controls(|_| {})
    }

    pub(crate) fn scan_with_controls(
        &self,
        update: impl FnOnce(&[bool]),
    ) -> Result<usize, ControlError> {
        let mut w = self
            .inner
            .writer
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        self.inner.preflight_writer(&w, 0)?;
        let r = self
            .inner
            .registry
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        let owner = r.current.as_ref().ok_or(ControlError::NoCurrent)?;
        self.inner.preflight_writer(&w, self.inner.spec.ids.len())?;
        let mut count = 0;
        for &function in &self.inner.spec.ids {
            if owner.epoch.function_closed(function) == Some(true) {
                self.inner.apply_request(
                    &mut w,
                    &r,
                    DeactivationRequest {
                        generation: owner.epoch.id(),
                        function,
                    },
                    FailurePoint::None,
                )?;
                count += 1;
            }
        }
        self.inner.update_controls(&r, update);
        Ok(count)
    }

    /// Take bounded diagnostic copies outside admission. No physical proof results.
    pub fn snapshot(&self) -> Result<ControllerSnapshot, ControlError> {
        if self.history_mode() != HistoryMode::Legacy {
            return Err(ControlError::HistoryMode);
        }
        self.snapshot_for_bridge()
    }

    // Internal pristine/current/retirement checks never expose an unqualified suffix.
    pub(crate) fn snapshot_for_bridge(&self) -> Result<ControllerSnapshot, ControlError> {
        let w = self
            .inner
            .writer
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        Ok(ControllerSnapshot {
            status: w.status,
            current: w.current,
            enabled: w.enabled.clone(),
            actions: w.actions.clone(),
            retained_failed_generation: w.failed_owner.as_ref().map(|owner| owner.epoch.id()),
        })
    }
}
impl SessionInner {
    fn update_controls(&self, registry: &Registry, update: impl FnOnce(&[bool])) {
        let mut states = [false; MAX_MODEL_FUNCTIONS];
        if let Some(owner) = &registry.current {
            for (i, function) in self.spec.ids.iter().enumerate() {
                states[i] = !owner.epoch.is_closed()
                    && owner.epoch.function_closed(*function) == Some(false);
            }
        }
        update(&states[..self.spec.ids.len()]);
    }

    fn acquire(&self, thread: u64, install: u64) -> Result<AdmissionHandle, EntryError> {
        if install != self.spec.install {
            return Err(EntryError::WrongInstall);
        }
        let r = match self.registry.try_lock() {
            Ok(r) => r,
            Err(TryLockError::WouldBlock) => return Err(EntryError::RegistryBusy),
            Err(TryLockError::Poisoned(_)) => return Err(EntryError::RegistryPoisoned),
        };
        if !r.threads.contains(&thread) {
            return Err(EntryError::UnknownThread);
        }
        let owner = r.current.as_ref().ok_or(EntryError::NoCurrent)?;
        Ok(AdmissionHandle {
            owner: Arc::clone(owner),
            thread,
        })
    }
    fn preflight_writer(&self, w: &Controller, count: usize) -> Result<(), ControlError> {
        if w.status == ControllerStatus::TerminalFailure {
            return Err(ControlError::TerminalFailure);
        }
        if count > self.spec.limits.actions - w.actions.len() {
            return Err(ControlError::HistoryFull);
        }
        self.preflight_absolute(w, count)?;
        Ok(())
    }
    fn apply_request(
        &self,
        w: &mut Controller,
        r: &Registry,
        request: DeactivationRequest,
        failure: FailurePoint,
    ) -> Result<(), ControlError> {
        let current = w.current;
        if current != Some(request.generation) {
            self.append_action(
                w,
                Action {
                    kind: ActionKind::Stale,
                    generation: request.generation,
                    function: Some(request.function),
                    current,
                    group: None,
                },
            );
            return Ok(());
        }
        let owner = r.current.as_ref().ok_or(ControlError::NoCurrent)?;
        let spec = self
            .spec
            .functions
            .iter()
            .find(|f| f.function == request.function)
            .ok_or(ControlError::UnknownFunction)?;
        if owner.epoch.function_closed(request.function) != Some(true) {
            return Err(ControlError::FunctionOpen);
        }
        let group = spec.group;
        let all_closed = self
            .spec
            .functions
            .iter()
            .filter(|f| f.group == group)
            .all(|f| owner.epoch.function_closed(f.function) == Some(true));
        let action = |kind| Action {
            kind,
            generation: request.generation,
            function: Some(request.function),
            current,
            group: Some(group),
        };
        if !all_closed || self.spec.groups[group].mandatory {
            self.append_action(w, action(ActionKind::Deferred));
            return Ok(());
        }
        if failure == FailurePoint::BeforeMutation {
            self.append_action(w, action(ActionKind::FailedBefore));
            return Err(ControlError::InjectedBefore);
        }
        w.enabled[group] = false;
        if failure == FailurePoint::AfterMutation {
            owner.epoch.close();
            w.failed_owner = Some(Arc::clone(owner));
            w.status = ControllerStatus::TerminalFailure;
            self.append_action(w, action(ActionKind::FailedAfter));
            return Err(ControlError::InjectedAfter);
        }
        self.append_action(w, action(ActionKind::Disabled));
        Ok(())
    }
}

struct Frame {
    ticket: Option<OwnedTicket>,
    owner: Arc<FrontendEpoch>,
    thread: u64,
    start_sequence: u64,
    slot: ModelReturnSlot,
}
impl Frame {
    fn publish_payload(&self, ticket: &OwnedTicket, outcome: PayloadOutcome) -> Payload {
        let admission = ticket.admission();
        let payload = Payload {
            admission,
            thread: self.thread,
            start_sequence: self.start_sequence,
            outcome,
        };
        assert!(
            self.owner.payloads[admission.invocation]
                .set(payload)
                .is_ok()
        );
        payload
    }
    fn complete(
        mut self,
        end: Observation,
        children: u64,
        before_release: impl FnOnce(),
        before_close: impl FnOnce(),
    ) -> (Completion, Payload) {
        let ticket = self.ticket.take().expect("live private frame");
        let payload = self.publish_payload(
            &ticket,
            PayloadOutcome::Completed {
                end,
                completed_children: children,
            },
        );
        before_release();
        let completion =
            ticket.complete_before_close(payload.admission.invocation as u64, before_close);
        (completion, payload)
    }
    fn cancel(mut self) -> Payload {
        let ticket = self.ticket.take().expect("live private frame");
        let payload =
            self.publish_payload(&ticket, PayloadOutcome::Cancelled(CancelReason::Explicit));
        ticket.cancel();
        payload
    }
}
impl Drop for Frame {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.publish_payload(
                &ticket,
                PayloadOutcome::Cancelled(CancelReason::DroppedTicket),
            );
            // The frontend owner is still a field of this live Frame while the
            // ticket's ordinary Drop publishes its cancellation and releases.
            drop(ticket);
        }
    }
}

/// A pre-registered thread's bounded data-only frame stack. No actual TLS exists.
/// Public methods cannot return or extract live Frame/ticket/epoch ownership.
///
/// ```compile_fail,E0616
/// use rapid_profiler::frontend::ThreadModel;
/// fn escape(mut thread: ThreadModel) { let ticket = thread.frames.pop().unwrap().ticket; }
/// ```
pub struct ThreadModel {
    session: Arc<SessionInner>,
    identity: u64,
    frames: Vec<Frame>,
    completed_sequence: u64,
    attempts: u64,
    in_callback: bool,
    exhausted: bool,
}
impl ThreadModel {
    /// Return the lifetime registered identity.
    pub fn identity(&self) -> u64 {
        self.identity
    }
    /// Count currently owned model frames.
    pub fn depth(&self) -> usize {
        self.frames.len()
    }
    /// Return the nonwrapping sequence of observed completions across all epochs.
    pub fn completed_sequence(&self) -> u64 {
        self.completed_sequence
    }
    fn preflight(&mut self, slot: &ModelReturnSlot) -> Result<(), EntryError> {
        if self.exhausted {
            return Err(EntryError::CounterExhausted);
        }
        if self.in_callback {
            return Err(EntryError::Reentry);
        }
        let Some(attempts) = self.attempts.checked_add(1) else {
            self.exhausted = true;
            return Err(EntryError::CounterExhausted);
        };
        self.attempts = attempts;
        if self.frames.len() == self.session.spec.limits.depth {
            return Err(EntryError::Depth);
        }
        if self.frames.iter().any(|f| f.slot.identity == slot.identity) {
            return Err(EntryError::SlotInUse);
        }
        if self
            .completed_sequence
            .checked_add(self.frames.len() as u64 + 1)
            .is_none()
        {
            self.exhausted = true;
            return Err(EntryError::CounterExhausted);
        }
        Ok(())
    }
    /// Obtain current owner and admit without allocation or fallible work after
    /// the model return-token write. Every refusal preserves that token.
    pub fn enter(
        &mut self,
        install: u64,
        function: FunctionId,
        value: u64,
        slot: &mut ModelReturnSlot,
    ) -> Result<Admission, EntryError> {
        self.preflight(slot)?;
        self.in_callback = true;
        let result = self
            .session
            .acquire(self.identity, install)
            .and_then(|h| self.enter_inner(&h, function, value, slot));
        self.in_callback = false;
        result
    }
    /// Admit through a previously acquired owner, which may have since closed.
    pub fn enter_acquired(
        &mut self,
        handle: &AdmissionHandle,
        function: FunctionId,
        value: u64,
        slot: &mut ModelReturnSlot,
    ) -> Result<Admission, EntryError> {
        self.preflight(slot)?;
        self.in_callback = true;
        let result = self.enter_inner(handle, function, value, slot);
        self.in_callback = false;
        result
    }
    fn enter_inner(
        &mut self,
        handle: &AdmissionHandle,
        function: FunctionId,
        value: u64,
        slot: &mut ModelReturnSlot,
    ) -> Result<Admission, EntryError> {
        if handle.thread != self.identity || !Arc::ptr_eq(&handle.owner.spec, &self.session.spec) {
            return Err(EntryError::ForeignHandle);
        }
        let ticket = handle
            .owner
            .epoch
            .enter_owned(function, value)
            .map_err(EntryError::Generation)?;
        let admission = ticket.admission();
        self.frames.push(Frame {
            ticket: Some(ticket),
            owner: Arc::clone(&handle.owner),
            thread: self.identity,
            start_sequence: self.completed_sequence,
            slot: *slot,
        });
        slot.word = MODEL_CONTINUATION;
        Ok(admission)
    }
    fn exit_check(&self, slot: &ModelReturnSlot) -> Result<(u64, u64), ExitError> {
        let frame = self.frames.last().ok_or(ExitError::Empty)?;
        if frame.slot.identity != slot.identity || slot.word != MODEL_CONTINUATION {
            return Err(ExitError::SlotMismatch);
        }
        let children = self
            .completed_sequence
            .checked_sub(frame.start_sequence)
            .ok_or(ExitError::Sequence)?;
        let next = self
            .completed_sequence
            .checked_add(1)
            .ok_or(ExitError::Sequence)?;
        Ok((children, next))
    }
    /// Complete the top frame using its original owner, independent of registry.
    pub fn finish(
        &mut self,
        slot: &mut ModelReturnSlot,
        end: Observation,
    ) -> Result<(Completion, Payload), ExitError> {
        self.finish_inner(slot, end, || {}, || {})
    }
    fn finish_inner(
        &mut self,
        slot: &mut ModelReturnSlot,
        end: Observation,
        before_release: impl FnOnce(),
        before_close: impl FnOnce(),
    ) -> Result<(Completion, Payload), ExitError> {
        let (children, next) = self.exit_check(slot)?;
        let frame = self.frames.pop().expect("checked frame");
        let original = frame.slot.word;
        let result = frame.complete(end, children, before_release, before_close);
        self.completed_sequence = next;
        slot.word = original;
        Ok(result)
    }
    /// Explicit cancellation does not increment the completed-child sequence.
    pub fn cancel(&mut self, slot: &mut ModelReturnSlot) -> Result<Payload, ExitError> {
        self.exit_check(slot)?;
        let frame = self.frames.pop().expect("checked frame");
        let original = frame.slot.word;
        let payload = frame.cancel();
        slot.word = original;
        Ok(payload)
    }
}
impl Drop for ThreadModel {
    fn drop(&mut self) {
        // Explicit LIFO cancellation; no claim that this restores external model
        // slot tokens, actual return words, or nonlocal/thread-death machine state.
        while let Some(frame) = self.frames.pop() {
            drop(frame);
        }
    }
}

impl ThreadModel {
    // Ordinary Rust unwinding cancels precisely the authenticated top frame.
    // Keeping this separate preserves the public Explicit cancellation API.
    pub(crate) fn cancel_on_unwind(&mut self, slot: &mut ModelReturnSlot) -> Result<(), ExitError> {
        self.exit_check(slot)?;
        let frame = self.frames.pop().expect("checked unwind frame");
        let original = frame.slot.word;
        drop(frame);
        slot.word = original;
        Ok(())
    }
}

mod history_stream;
pub use history_stream::HistoryBinding;
pub(crate) use history_stream::{HistoryChunk, HistoryMode, HistoryView, MAX_HISTORY_POSITION};

mod interval_entry;
pub(crate) use interval_entry::{
    BindingChange, IntervalEntry, IntervalEntryError, IntervalEntrySummary, IntervalExit,
    IntervalExitError, UnsampledSummary,
};

#[cfg(test)]
mod tests;

mod epoch_storage;
pub(crate) use epoch_storage::{EpochStorage, StorageReclaimError};
