//! Exclusive point-only metadata/physical transactions. No interval exits,
//! saved-PC translation, code reclamation or staleness-delay fallback.
//!
//! Construction consumes already-active, qualified installations. Optional
//! callbacks remain admission-closed until ARM; mandatory callbacks stay live.
//! The managed data gates are permanently true. Every physical operation runs
//! after both frontend locks have been released. Failed or abandoned transitions
//! close metadata and retain their history; nothing rolls code or old epochs back.

use super::{Binding, PointSpec, PointThread, attach_binding, point_callback};
use crate::frontend::{self, EpochHandle, FailurePoint, FunctionSpec, GroupSpec, Session};
use crate::generation::{Config, DeactivationRequest};
use liteinst2::contracts::{Epoch, Refusal, ToggleProbe, Visibility};
use liteinst2::controls::{ControlWriter, ControlledAction, ProbeControl};
use liteinst2::patcher::synchronized::{
    Direction, Phase, Receipt, SyncJumpPatch, SyncPatchError, SynchronizedBatch,
};
use liteinst2::rapid::RapidProbe;
use liteinst2::sync_core::{SyncCore, SyncCoreError};
use liteinst2::trampoline::{ExecutableTrampoline, TrampolinePlan};
use std::any::Any;
use std::mem::ManuallyDrop;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

/// Refusal never certifies rollback, drainage or a completed physical operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidInstallation,
    DifferentProcess,
    Busy,
    Terminal,
    Stale,
    HistoryFull,
    Metadata(String),
    Synchronize(SyncCoreError),
    Patch(SyncPatchError),
    Abandoned,
    Unwound,
    FinalConfirmation,
}
fn metadata(e: impl std::fmt::Debug) -> Error {
    Error::Metadata(format!("{e:?}"))
}
fn refusal(e: Error) -> Refusal {
    Refusal::Backend(format!("{e:?}"))
}
fn matches_point(pc: u64, actual: &[ControlledAction], expected: &ControlledAction) -> bool {
    pc == expected.logical_pc && actual == std::slice::from_ref(expected)
}

/// Separate physical observations; a word receipt is sampled before batch Drop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Progress {
    /// No terminal physical observation yet. Stores may be in flight; this is
    /// never evidence that source remains unchanged or rollback is safe.
    Pending,
    NoStore,
    /// A store is marked possible before invoking it; completed counts only
    /// returned stores. Sync failure after stores does not restore the byte.
    Bytes {
        stores_completed: usize,
        store_may_have_started: bool,
        synchronized: bool,
    },
    /// On an untouched unwind Drop subsequently releases leases. A mutated
    /// Drop retains WRITING forever; this exact pre-Drop receipt is not changed.
    Words {
        receipt: Receipt,
    },
    PreparationRefused(SyncPatchError),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Arm,
    Disarm,
    Deactivate,
    Scan,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Pending,
    Complete,
    Failed,
}
/// Finite diagnostic history. Owners named here remain in the controller's
/// retained epoch set; callback reservations independently retain their owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub sequence: u64,
    pub operation: Operation,
    pub requested: Epoch,
    pub old_current: Option<Epoch>,
    pub new_current: Option<Epoch>,
    pub before_groups: Vec<bool>,
    pub desired_groups: Vec<bool>,
    pub changed_points: Vec<usize>,
    pub metadata_changed: bool,
    pub progress: Progress,
    pub status: Status,
    pub failure: Option<Error>,
}

/// Retains one already-active synchronized patch, its exact observing image
/// and immutable action identities. No raw patch or image accessor is exposed.
pub struct WordMember {
    patch: SyncJumpPatch,
    _image: ExecutableTrampoline,
    actions: Vec<ControlledAction>,
}
impl WordMember {
    /// Authenticate an existing active image before transferring exclusive
    /// ownership. Only one complete first instruction and one point are admitted.
    ///
    /// # Safety
    /// All SyncJumpPatch::bind/prepare contracts still hold, including complete
    /// original entries and saved resumes, exact permanent aliases and targets,
    /// all-thread SIGTRAP availability, cache geometry and exclusive writers.
    /// The image and template came from the same authenticated original scan.
    /// No executing writer or its signal handler may enter guarded source.
    /// This transfers ownership, not a new host/entry qualification.
    pub unsafe fn from_active(
        patch: SyncJumpPatch,
        image: ExecutableTrampoline,
        template: TrampolinePlan,
    ) -> Result<Self, Error> {
        if template.execute_address() != patch.plan().execute_address()
            || template.displaced_len() != patch.plan().displaced_len()
            || template.replaces_first()
            || template.controlled_actions().len() != 1
            || patch.plan().target_address() != image.address()
        {
            return Err(Error::InvalidInstallation);
        }
        let expected = template.emit_at(image.address()).map_err(metadata)?;
        if expected.bytes().len() != image.code_len() {
            return Err(Error::InvalidInstallation);
        }
        // SAFETY: ExecutableTrampoline retains this initialized RX extent.
        let actual =
            unsafe { std::slice::from_raw_parts(image.address() as *const u8, image.code_len()) };
        if actual != expected.bytes() {
            return Err(Error::InvalidInstallation);
        }
        // Revert preparation authenticates the ACTIVE source and complete
        // writable envelope. Dropping this untouched batch makes no code store.
        let batch = unsafe { SynchronizedBatch::prepare(&[&patch], Direction::Revert) }
            .map_err(Error::Patch)?;
        drop(batch);
        let actions = template.controlled_actions().to_vec();
        Ok(Self {
            patch,
            _image: image,
            actions,
        })
    }
}

enum Physical {
    Bytes {
        probes: Vec<RapidProbe>,
        capability: SyncCore,
    },
    Words(Vec<WordMember>),
    #[cfg(test)]
    Contract(tests::Contract),
}
struct State {
    epochs: Vec<EpochHandle>,
    current: Option<Epoch>,
    sequence: u64,
    pending: Option<u64>,
    terminal: bool,
    groups: Vec<bool>,
    history: Vec<Record>,
    limit: usize,
}
struct Inner {
    process: u32,
    binding: ManuallyDrop<Arc<Binding>>,
    _writers: ManuallyDrop<Vec<ControlWriter>>,
    physical: ManuallyDrop<Physical>,
    state: ManuallyDrop<Mutex<State>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        if self.process != std::process::id() {
            return;
        }
        // Close admission, never perform a physical transition. Terminal or
        // stranded-pending controllers retain all owning allocations for
        // process lifetime, including history and old epochs. No last-handle
        // Drop may erase the owners of a partially published word/byte state.
        let state = self.state.get_mut().unwrap_or_else(|p| p.into_inner());
        for owner in &state.epochs {
            owner.close();
        }
        if !state.terminal && state.pending.is_none() {
            // SAFETY: each field is dropped exactly once on this sole normal
            // path. ExecutableTrampoline itself retains published RX code and
            // embedded controls; this still does not reclaim generated code.
            unsafe {
                ManuallyDrop::drop(&mut self.state);
                ManuallyDrop::drop(&mut self.physical);
                ManuallyDrop::drop(&mut self._writers);
                ManuallyDrop::drop(&mut self.binding);
            }
        }
    }
}

/// Planning-only owner. Actions are read-only managed clones; there is no
/// conversion from those clones to a writer or mutable physical installation.
pub struct Builder {
    binding: Arc<Binding>,
    writers: Vec<ControlWriter>,
    limits: frontend::Limits,
}
impl Builder {
    pub fn new(install: u64, specs: &[PointSpec], limits: frontend::Limits) -> Result<Self, Error> {
        if specs.is_empty()
            || specs.len() > frontend::MAX_MODEL_FUNCTIONS
            || specs
                .iter()
                .any(|s| s.pc == 0 || s.group >= frontend::MAX_MODEL_FUNCTIONS)
            || specs.windows(2).any(|w| w[0].pc >= w[1].pc)
        {
            return Err(Error::InvalidInstallation);
        }
        let count = specs.iter().map(|s| s.group).max().unwrap() + 1;
        let groups: Vec<_> = (0..count)
            .map(|group| GroupSpec {
                mandatory: specs
                    .iter()
                    .any(|s| s.group == group && s.function.is_none()),
            })
            .collect();
        let functions: Vec<_> = specs
            .iter()
            .filter_map(|s| {
                s.function.map(|function| FunctionSpec {
                    function,
                    group: s.group,
                })
            })
            .collect();
        let session = Session::new(install, &functions, &groups, limits).map_err(metadata)?;
        let mut controls = Vec::with_capacity(specs.len());
        let mut writers = Vec::with_capacity(specs.len());
        for spec in specs {
            let (control, writer) = match spec.function {
                Some(_) => ProbeControl::new_managed_bound(point_callback, true),
                None => ProbeControl::new_managed(spec.callback, true),
            };
            controls.push(control);
            writers.push(writer);
        }
        Ok(Self {
            binding: Arc::new(Binding {
                session,
                install,
                specs: specs.to_vec(),
                controls,
                #[cfg(test)]
                pause: Mutex::new(None),
            }),
            writers,
            limits,
        })
    }
    pub fn actions(&self) -> Vec<ControlledAction> {
        self.binding
            .specs
            .iter()
            .zip(&self.binding.controls)
            .map(|(s, c)| ControlledAction {
                logical_pc: s.pc,
                control: c.clone(),
            })
            .collect()
    }
    fn finish(self, physical: Physical) -> Result<CodePointSession, Error> {
        let mut history = Vec::new();
        history
            .try_reserve_exact(self.limits.actions)
            .map_err(metadata)?;
        let groups = vec![true; self.binding.specs.iter().map(|s| s.group).max().unwrap() + 1];
        Ok(CodePointSession {
            inner: Arc::new(Inner {
                process: std::process::id(),
                binding: ManuallyDrop::new(self.binding),
                _writers: ManuallyDrop::new(self.writers),
                physical: ManuallyDrop::new(physical),
                state: ManuallyDrop::new(Mutex::new(State {
                    epochs: Vec::with_capacity(self.limits.epochs),
                    current: None,
                    sequence: 0,
                    pending: None,
                    terminal: false,
                    groups,
                    history,
                    limit: self.limits.actions,
                })),
            }),
        })
    }
    /// Consume exact, already active Rapid installations. Mixed backends and
    /// general puns are unsupported. A qualified caller must keep every original
    /// entry/resume/alias/source and non-unwinding callback contract valid for
    /// process lifetime, including future transitions and fork exclusion.
    /// SyncCore is required, but is NOT that entry/resume/host proof.
    ///
    /// # Safety
    /// All RapidProbe::install obligations and the qualifications above hold;
    /// only this controller may subsequently publish these opcode bytes.
    pub unsafe fn bind_bytes(
        self,
        probes: Vec<RapidProbe>,
        capability: SyncCore,
    ) -> Result<CodePointSession, Error> {
        let actions = self.actions();
        if probes.len() != actions.len()
            || probes.iter().zip(&actions).any(|(p, a)| {
                !matches_point(p.plan().execute_address(), p.plan().controlled_actions(), a)
                    || !p.is_enabled()
            })
        {
            return Err(Error::InvalidInstallation);
        }
        capability.synchronize().map_err(Error::Synchronize)?;
        self.finish(Physical::Bytes { probes, capability })
    }
    /// Consume the exact active word owners, in point order. The complete
    /// batch preflight retains all executable/writable overlap and byte checks.
    ///
    /// # Safety
    /// Every WordMember::from_active obligation remains true for every future
    /// transition; no second writer or guarded-source signal handler is allowed.
    pub unsafe fn bind_words(self, members: Vec<WordMember>) -> Result<CodePointSession, Error> {
        let actions = self.actions();
        if members.len() != actions.len()
            || members
                .iter()
                .zip(&actions)
                .any(|(m, a)| !matches_point(m.patch.plan().execute_address(), &m.actions, a))
        {
            return Err(Error::InvalidInstallation);
        }
        let patches: Vec<_> = members.iter().map(|m| &m.patch).collect();
        let batch = unsafe { SynchronizedBatch::prepare(&patches, Direction::Revert) }
            .map_err(Error::Patch)?;
        drop(batch);
        self.finish(Physical::Words(members))
    }
}

/// No Session, physical member, writer or mutable image escapes this owner.
/// Concurrent/reentrant callers use try-lock and the pending identity; neither
/// can steal a transition while its physical executor is outside frontend locks.
pub struct CodePointSession {
    inner: Arc<Inner>,
}
/// Non-Clone transaction owner. Dropping it closes metadata and records failure,
/// never rollback. Forgetting it strands a pending transition, not a completion.
pub struct Transition {
    inner: Arc<Inner>,
    sequence: u64,
    done: bool,
}
/// Completion belongs to exactly this retained installation and latest sequence.
pub struct Ticket {
    inner: Arc<Inner>,
    sequence: u64,
    current: Option<Epoch>,
}

impl CodePointSession {
    fn state(&self) -> Result<MutexGuard<'_, State>, Error> {
        if self.inner.process != std::process::id() {
            return Err(Error::DifferentProcess);
        }
        match self.inner.state.try_lock() {
            Ok(s) => Ok(s),
            Err(TryLockError::WouldBlock) => Err(Error::Busy),
            Err(TryLockError::Poisoned(_)) => Err(Error::Terminal),
        }
    }
    fn writable(s: &State) -> Result<(), Error> {
        if s.terminal {
            Err(Error::Terminal)
        } else if s.pending.is_some() {
            Err(Error::Busy)
        } else if s.history.len() == s.limit {
            Err(Error::HistoryFull)
        } else {
            Ok(())
        }
    }
    fn owner(s: &State, epoch: Epoch) -> Result<&EpochHandle, Error> {
        s.epochs
            .iter()
            .find(|e| e.generation().get() == epoch.0)
            .ok_or(Error::Stale)
    }
    pub fn stage(&self, config: Config) -> Result<Epoch, Error> {
        let mut s = self.state()?;
        Self::writable(&s)?;
        let owner = self.inner.binding.session.stage(config).map_err(metadata)?;
        let epoch = Epoch(owner.generation().get());
        s.epochs.push(owner);
        Ok(epoch)
    }
    pub fn attach_current_thread(&self) -> Result<PointThread, Refusal> {
        if self.inner.process != std::process::id() {
            return Err(refusal(Error::DifferentProcess));
        }
        attach_binding(&self.inner.binding)
    }
    pub fn report(&self, epoch: Epoch) -> Result<Option<frontend::Report>, Error> {
        Ok(Self::owner(&self.state()?, epoch)?.try_report())
    }
    pub fn history(&self) -> Result<Vec<Record>, Error> {
        if self.inner.process != std::process::id() {
            return Err(Error::DifferentProcess);
        }
        match self.inner.state.try_lock() {
            Ok(s) => Ok(s.history.clone()),
            Err(TryLockError::Poisoned(p)) => Ok(p.into_inner().history.clone()),
            Err(TryLockError::WouldBlock) => Err(Error::Busy),
        }
    }
    pub fn begin_arm(&self, epoch: Epoch) -> Result<Transition, Error> {
        self.begin(Operation::Arm, epoch, None)
            .map(|t| t.expect("ARM reserves one transition"))
    }
    pub fn begin_disarm(&self, epoch: Epoch) -> Result<Transition, Error> {
        self.begin(Operation::Disarm, epoch, None)
            .map(|t| t.expect("DISARM reserves one transition"))
    }
    /// Stale K requests keep the existing Stale action and return no physical
    /// token. Complete group closure, not one function Boolean, selects removal.
    pub fn begin_deactivate(
        &self,
        request: DeactivationRequest,
    ) -> Result<Option<Transition>, Error> {
        self.begin(
            Operation::Deactivate,
            Epoch(request.generation.get()),
            Some(request),
        )
    }
    pub fn begin_scan(&self) -> Result<Transition, Error> {
        let epoch = self.state()?.current.ok_or(Error::Stale)?;
        self.begin(Operation::Scan, epoch, None)
            .map(|t| t.expect("scan reserves one transition"))
    }
    fn begin(
        &self,
        operation: Operation,
        epoch: Epoch,
        request: Option<DeactivationRequest>,
    ) -> Result<Option<Transition>, Error> {
        let mut s = self.state()?;
        Self::writable(&s)?;
        let next = s.sequence.checked_add(1).ok_or(Error::HistoryFull)?;
        let old = s.current;
        let session = &self.inner.binding.session;
        if operation == Operation::Deactivate && old != Some(epoch) {
            session
                .deactivate(request.expect("private request"), FailurePoint::None)
                .map_err(metadata)?;
            return Ok(None);
        }
        let owner = Self::owner(&s, epoch)?.clone();
        let mut metadata_changed = true;
        match operation {
            Operation::Arm => session
                .publish(&owner, FailurePoint::None)
                .map_err(metadata)?,
            Operation::Disarm => {
                if old != Some(epoch) {
                    return Err(Error::Stale);
                }
                session
                    .remove_with_controls(Some(owner.generation()), |_| {})
                    .map_err(metadata)?;
            }
            Operation::Deactivate => {
                session
                    .deactivate(request.expect("private request"), FailurePoint::None)
                    .map_err(metadata)?;
                if old != Some(epoch) {
                    return Ok(None);
                }
            }
            Operation::Scan => {
                if old != Some(epoch) {
                    return Err(Error::Stale);
                }
                metadata_changed = session.scan_closed().map_err(metadata)? != 0;
            }
        }
        // All Session writer/registry guards have ended before returning this
        // token. The physical executor never runs in an update callback.
        let current = match operation {
            Operation::Arm => Some(epoch),
            Operation::Disarm => None,
            _ => old,
        };
        let desired = match session.code_groups(current.map(|_| owner.generation())) {
            Ok(groups) => groups,
            Err(e) => {
                owner.close();
                s.terminal = true;
                s.current = current;
                let error = metadata(e);
                let before = s.groups.clone();
                s.sequence = next;
                // Empty desired_groups means selection never completed; no
                // code action is authorized by this retained failed row.
                s.history.push(Record {
                    sequence: next,
                    operation,
                    requested: epoch,
                    old_current: old,
                    new_current: current,
                    before_groups: before,
                    desired_groups: Vec::new(),
                    changed_points: Vec::new(),
                    metadata_changed,
                    progress: Progress::NoStore,
                    status: Status::Failed,
                    failure: Some(error.clone()),
                });
                return Err(error);
            }
        };
        let points = self
            .inner
            .binding
            .specs
            .iter()
            .enumerate()
            .filter_map(|(i, p)| (s.groups[p.group] != desired[p.group]).then_some(i))
            .collect();
        let record = Record {
            sequence: next,
            operation,
            requested: epoch,
            old_current: old,
            new_current: current,
            before_groups: s.groups.clone(),
            desired_groups: desired,
            changed_points: points,
            metadata_changed,
            progress: Progress::Pending,
            status: Status::Pending,
            failure: None,
        };
        s.current = current;
        s.sequence = next;
        s.pending = Some(next);
        s.history.push(record);
        Ok(Some(Transition {
            inner: Arc::clone(&self.inner),
            sequence: next,
            done: false,
        }))
    }
    pub fn complete(&self, ticket: &Ticket) -> Result<Visibility, Error> {
        if !Arc::ptr_eq(&self.inner, &ticket.inner) {
            return Err(Error::Stale);
        }
        let s = self.state()?;
        if s.terminal
            || s.pending.is_some()
            || s.sequence != ticket.sequence
            || s.current != ticket.current
            || s.history
                .last()
                .is_none_or(|r| r.status != Status::Complete)
        {
            return Err(Error::Stale);
        }
        let expected = match s.current {
            Some(e) => Some(Self::owner(&s, e)?.generation()),
            None => None,
        };
        self.inner
            .binding
            .session
            .confirm_controls(expected)
            .map_err(metadata)?;
        // Conditional on the explicit unsafe installation qualifications. This
        // establishes code synchronization only, never callback/code drainage.
        Ok(Visibility::Complete)
    }
}

impl Transition {
    pub fn execute(mut self) -> Result<Ticket, Error> {
        let record = {
            if self.inner.process != std::process::id() {
                return Err(Error::DifferentProcess);
            }
            let s = self.inner.state.lock().map_err(|_| Error::Terminal)?;
            if s.pending != Some(self.sequence) {
                return Err(Error::Stale);
            }
            s.history.last().expect("pending record").clone()
        };
        let changes: Vec<_> = record
            .changed_points
            .iter()
            .map(|&i| (i, record.desired_groups[self.inner.binding.specs[i].group]))
            .collect();
        let mut progress = Progress::NoStore;
        let performed = catch_unwind(AssertUnwindSafe(|| {
            perform(&self.inner.physical, &changes, &mut progress)
        }));
        let (error, panic): (Option<Error>, Option<Box<dyn Any + Send>>) = match performed {
            Ok(Ok(())) => (None, None),
            Ok(Err((e, p))) => (Some(e), p),
            Err(p) => (Some(Error::Unwound), Some(p)),
        };
        let result = finish(&self.inner, self.sequence, progress, error);
        self.done = true;
        if let Some(payload) = panic {
            resume_unwind(payload)
        }
        result.map(|current| Ticket {
            inner: Arc::clone(&self.inner),
            sequence: self.sequence,
            current,
        })
    }
}
impl Drop for Transition {
    fn drop(&mut self) {
        if !self.done && self.inner.process == std::process::id() {
            let _ = finish(
                &self.inner,
                self.sequence,
                Progress::NoStore,
                Some(Error::Abandoned),
            );
        }
    }
}

fn finish(
    inner: &Inner,
    sequence: u64,
    progress: Progress,
    mut error: Option<Error>,
) -> Result<Option<Epoch>, Error> {
    // Even poisoned local metadata retains the exact failure instead of losing
    // physical progress. No fallible physical operation occurs under this lock.
    let mut s = match inner.state.lock() {
        Ok(s) => s,
        Err(p) => {
            error = Some(Error::FinalConfirmation);
            p.into_inner()
        }
    };
    if s.pending != Some(sequence) || s.sequence != sequence {
        error = Some(Error::FinalConfirmation)
    }
    if error.is_none() {
        let expected = match s.current {
            Some(epoch) => match s.epochs.iter().find(|o| o.generation().get() == epoch.0) {
                Some(owner) => Some(owner.generation()),
                None => {
                    error = Some(Error::FinalConfirmation);
                    None
                }
            },
            None => None,
        };
        if error.is_none() && inner.binding.session.confirm_controls(expected).is_err() {
            error = Some(Error::FinalConfirmation)
        }
    }
    if let Some(e) = &error {
        for owner in &s.epochs {
            owner.close();
        }
        s.terminal = true;
        if let Some(record) = s.history.iter_mut().find(|r| r.sequence == sequence) {
            record.progress = progress;
            record.status = Status::Failed;
            record.failure = Some(e.clone());
        }
    } else {
        let record = s
            .history
            .iter_mut()
            .find(|r| r.sequence == sequence)
            .expect("reserved record");
        record.progress = progress;
        record.status = Status::Complete;
        let desired = record.desired_groups.clone();
        s.groups = desired;
    }
    s.pending = None;
    match error {
        Some(e) => Err(e),
        None => Ok(s.current),
    }
}

type PhysicalResult = Result<(), (Error, Option<Box<dyn Any + Send>>)>;
fn perform(
    physical: &Physical,
    changes: &[(usize, bool)],
    progress: &mut Progress,
) -> PhysicalResult {
    if changes.is_empty() {
        return Ok(());
    }
    let enabled = changes[0].1;
    if changes.iter().any(|p| p.1 != enabled) {
        return Err((Error::InvalidInstallation, None));
    }
    match physical {
        Physical::Bytes { probes, capability } => {
            *progress = Progress::Bytes {
                stores_completed: 0,
                store_may_have_started: false,
                synchronized: false,
            };
            for (completed, &(i, enabled)) in changes.iter().enumerate() {
                *progress = Progress::Bytes {
                    stores_completed: completed,
                    store_may_have_started: true,
                    synchronized: false,
                };
                probes[i].set_enabled(enabled);
                *progress = Progress::Bytes {
                    stores_completed: completed + 1,
                    store_may_have_started: true,
                    synchronized: false,
                };
            }
            capability
                .synchronize()
                .map_err(|e| (Error::Synchronize(e), None))?;
            *progress = Progress::Bytes {
                stores_completed: changes.len(),
                store_may_have_started: true,
                synchronized: true,
            };
            Ok(())
        }
        Physical::Words(members) => {
            let patches: Vec<_> = changes.iter().map(|&(i, _)| &members[i].patch).collect();
            // SAFETY: constructors consumed the exact qualified owners; the
            // private pending token excludes every second frontend writer.
            let mut batch = match unsafe {
                SynchronizedBatch::prepare(
                    &patches,
                    if enabled {
                        Direction::Apply
                    } else {
                        Direction::Revert
                    },
                )
            } {
                Ok(b) => b,
                Err(e) => {
                    *progress = Progress::PreparationRefused(e);
                    return Err((Error::Patch(e), None));
                }
            };
            *progress = Progress::Words {
                receipt: batch.receipt(),
            };
            for _ in 0..6 {
                let step = catch_unwind(AssertUnwindSafe(|| unsafe { batch.advance() }));
                *progress = Progress::Words {
                    receipt: batch.receipt(),
                };
                match step {
                    Ok(Ok(_)) => {}
                    Ok(Err(f)) => return Err((Error::Patch(f.error), None)),
                    Err(p) => return Err((Error::Unwound, Some(p))),
                }
            }
            let r = batch.receipt();
            if r.phase != Phase::Complete
                || r.synchronizations != 3
                || r.writer_ownership_retained
                || r.failure.is_some()
            {
                return Err((Error::FinalConfirmation, None));
            }
            Ok(())
        }
        #[cfg(test)]
        Physical::Contract(contract) => contract.perform(changes, progress),
    }
}

impl ToggleProbe for CodePointSession {
    type Ticket = Ticket;
    fn arm(&mut self, epoch: Epoch) -> Result<Ticket, Refusal> {
        self.begin_arm(epoch)
            .and_then(Transition::execute)
            .map_err(refusal)
    }
    fn disarm(&mut self, epoch: Epoch) -> Result<Ticket, Refusal> {
        self.begin_disarm(epoch)
            .and_then(Transition::execute)
            .map_err(refusal)
    }
    fn complete(&mut self, ticket: &Ticket) -> Result<Visibility, Refusal> {
        CodePointSession::complete(self, ticket).map_err(refusal)
    }
    fn close_and_drain(&mut self, epoch: Epoch) -> Result<(), Refusal> {
        let current = {
            let s = self.state().map_err(refusal)?;
            if s.terminal {
                return Err(refusal(Error::Terminal));
            }
            if s.pending.is_some() {
                return Err(refusal(Error::Busy));
            }
            s.current
        };
        if current == Some(epoch) {
            self.begin_disarm(epoch)
                .and_then(Transition::execute)
                .map_err(refusal)?;
        }
        let s = self.state().map_err(refusal)?;
        let owner = Self::owner(&s, epoch).map_err(refusal)?;
        owner.close();
        if owner.try_report().is_none() {
            return Err(refusal(Error::Metadata(
                "point callbacks still admitted".into(),
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
