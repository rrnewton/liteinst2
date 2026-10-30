//! Bounded leaf-set profile using the existing NORMAL receipt and bank paths.
use super::*;
use crate::frontend_native::backoff::Policy;
use liteinst2::contracts::CodeIdentity;
mod history;
pub use history::{
    NormalLeafSetHistoryBatch, NormalLeafSetHistoryStream, NormalLeafSetHistoryWindow,
};

// Canonical inactive slots are zero; zero is a valid active FunctionId.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::frontend_native::always_on) struct LeafFunctions {
    len: u8,
    ids: [FunctionId; 4],
}
impl LeafFunctions {
    fn new(ids: &[FunctionId]) -> Result<Self, BridgeError> {
        if !(1..=4).contains(&ids.len())
            || ids.iter().enumerate().any(|(i, id)| ids[..i].contains(id))
        {
            return Err(error(Cause::Identity));
        }
        let mut value = Self {
            len: ids.len() as u8,
            ids: [FunctionId(0); 4],
        };
        value.ids[..ids.len()].copy_from_slice(ids);
        Ok(value)
    }
    pub(super) fn as_slice(&self) -> &[FunctionId] {
        &self.ids[..usize::from(self.len)]
    }
    fn valid(&self) -> bool {
        (1..=4).contains(&self.len)
            && self.ids[usize::from(self.len)..]
                .iter()
                .all(|id| *id == FunctionId(0))
            && self
                .as_slice()
                .iter()
                .enumerate()
                .all(|(i, id)| !self.as_slice()[..i].contains(id))
    }
}
fn fixed(n: usize, k: usize) -> Option<(Limits, Config)> {
    if !(1..=4).contains(&n) || !matches!(k, 10 | 1000) {
        return None;
    }
    limits_for(n, k)
}
fn limits_for(n: usize, k: usize) -> Option<(Limits, Config)> {
    let a = n.checked_mul(k)?;
    Some((
        Limits {
            epochs: 3,
            threads: 1,
            depth: 1,
            records_per_epoch: a,
            actions: 8,
        },
        Config {
            retained_per_function: k,
            max_inflight: 1,
            max_invocations: a,
        },
    ))
}
fn fixed_for(n: usize, k: usize, accuracy: Option<Policy>) -> Option<(Limits, Config)> {
    match accuracy {
        None => fixed(n, k),
        Some(policy) if policy.is_accuracy() && policy.retained() == k && (1..=4).contains(&n) => {
            limits_for(n, k)
        }
        Some(_) => None,
    }
}
pub(in crate::frontend_native::always_on) fn profile_matches(
    profile: &BindingProfile,
    limits: Limits,
    config: Config,
) -> bool {
    let BindingProfile::LeafSet {
        site,
        functions,
        accuracy,
    } = profile
    else {
        return false;
    };
    functions.valid()
        && site.functions().len() == functions.as_slice().len()
        && site.identity().generation != 0
        && site.identity().mapping == site.functions()[0].entry()
        && fixed_for(
            functions.as_slice().len(),
            config.retained_per_function,
            *accuracy,
        ) == Some((limits, config))
}
pub(in crate::frontend_native::always_on) fn binding_matches(binding: &Binding) -> bool {
    let BindingProfile::LeafSet {
        functions,
        accuracy,
        ..
    } = &binding.profile
    else {
        return false;
    };
    if !functions.valid() {
        return false;
    }
    let n = functions.as_slice().len();
    let k = binding.limits.records_per_epoch / n;
    let Some((_, config)) = fixed_for(n, k, *accuracy) else {
        return false;
    };
    profile_matches(&binding.profile, binding.limits, config)
        && matches!(binding.entry_mode, EntryMode::Concurrent)
        && binding.session.history_mode() == HistoryMode::Absolute
}
/// Separate pristine streaming preparation. No finite, Single or gated conversion.
pub struct PreparedNormalLeafSetSessionController {
    inner: PreparedIntervalController,
    config: Config,
    banks_prepared: bool,
}
impl PreparedNormalLeafSetSessionController {
    /// One to four distinct IDs in sealed ELF order, mandatory group 0, E3/T1/D1,
    /// K10 or K1000 per function, global M1/A=nK and eight resident actions.
    pub fn new(
        site: site::ordinary::InstalledNormalLeafSetSite,
        install: u64,
        functions: &[FunctionId],
        k: usize,
    ) -> Result<Self, BridgeError> {
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        Self::prepare(site.site, install, functions, k)
    }
    /// Explicit accuracy preparation using the same NORMAL worker, E3 banks,
    /// mandatory hooks and absolute history. Accepts only Policy::accuracy.
    /// K is bound into the sealed profile and fixed Config; the caller must drive
    /// Schedule with this same policy. This constructor does not run a clock or
    /// certify accuracy, residency, cadence or native return.
    pub fn new_accuracy(
        site: site::ordinary::InstalledNormalLeafSetSite,
        install: u64,
        functions: &[FunctionId],
        policy: Policy,
    ) -> Result<Self, BridgeError> {
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        Self::prepare_for(
            site.site,
            install,
            functions,
            policy.retained(),
            Some(policy),
        )
    }
    // Also used by nonexecuting metadata controls; never fabricates a loaded owner.
    fn prepare(
        site: Arc<site::ordinary::LeafSetSite>,
        install: u64,
        functions: &[FunctionId],
        k: usize,
    ) -> Result<Self, BridgeError> {
        Self::prepare_for(site, install, functions, k, None)
    }
    fn prepare_for(
        site: Arc<site::ordinary::LeafSetSite>,
        install: u64,
        functions: &[FunctionId],
        k: usize,
        accuracy: Option<Policy>,
    ) -> Result<Self, BridgeError> {
        let functions = LeafFunctions::new(functions)?;
        let (limits, config) =
            fixed_for(functions.as_slice().len(), k, accuracy).ok_or(error(Cause::Identity))?;
        if site.functions().len() != functions.as_slice().len() {
            return Err(error(Cause::Identity));
        }
        let specs = functions
            .ids
            .map(|function| FunctionSpec { function, group: 0 });
        let session = Session::new_streaming_history(
            install,
            &specs[..functions.as_slice().len()],
            &[GroupSpec { mandatory: true }],
            limits,
        )
        .map_err(|e| error(Cause::Setup(e)))?;
        let mut epochs = Vec::new();
        epochs
            .try_reserve_exact(limits.epochs)
            .map_err(|_| error(Cause::Capacity))?;
        Ok(Self {
            inner: PreparedIntervalController {
                session,
                profile: BindingProfile::LeafSet {
                    site,
                    functions,
                    accuracy,
                },
                key: Arc::new(()),
                install,
                limits,
                epochs,
                _exclusive: PhantomData,
            },
            config,
            banks_prepared: false,
        })
    }
    /// Prepare exactly three fixed-Config banks once, before activation or use.
    /// All fallible Vec reservations precede the bank-mode commit. Initialization
    /// touches initialized slot state only: neither full-byte residency nor a
    /// deadline guarantee follows. Lost banks are not replaced.
    pub fn prepare_epoch_storage(&mut self) -> Result<Vec<IntervalEpochStorage>, BridgeError> {
        let banks = super::super::epoch_storage::prepare_leaf_set(&mut self.inner, self.config)?;
        self.banks_prepared = true;
        Ok(banks)
    }
    /// # Safety
    /// The original pristine process/fork, concurrent-entry, no-reentry/signal
    /// and no callback-dependent-lock contracts hold. All sealed leaves and all
    /// source/generated/control owners remain immutable and process-lived.
    /// One actual caller attaches before work, owns its stack/input/journal and
    /// observes ordinary nonnested CALL/RET. No cancellation, unwind, nonlocal
    /// exit, CET, fork, alias writer or unload is permitted. Publication changes
    /// only the shared metadata epoch; it grants no executable quiescence.
    pub unsafe fn activate_concurrent(
        self,
    ) -> Result<(NormalLeafSetSessionController, NormalLeafSetClient), BridgeError> {
        if !self.banks_prepared {
            return Err(error(Cause::Setup(SetupError::StorageMode)));
        }
        if !profile_matches(&self.inner.profile, self.inner.limits, self.config)
            || self.inner.session.history_mode() != HistoryMode::Absolute
            || !self.inner.epochs.is_empty()
        {
            return Err(error(Cause::Identity));
        }
        PreparedNormalController::available()?;
        let (controller, binding) = self.inner.activate_binding(EntryMode::Concurrent)?;
        Ok((
            NormalLeafSetSessionController(controller),
            NormalLeafSetClient { binding },
        ))
    }
}

/// One metadata controller, Send but not Sync; only prepared storage may stage.
/// Reports/history never prove a physical RET or authorize code reclamation.
pub struct NormalLeafSetSessionController(pub(super) IntervalController);
impl NormalLeafSetSessionController {
    fn check(&self) -> Result<(), BridgeError> {
        self.0.binding.process()?;
        if !binding_matches(&self.0.binding) {
            return Err(error(Cause::Identity));
        }
        Ok(())
    }
    /// Consume one fixed bank, returning that same bank on every Result refusal.
    /// Uses the existing Arc-bank transaction; no scheduling/residency bound is promised.
    #[allow(clippy::result_large_err)] // Keep the returned bank inline until custody is restored.
    pub fn stage_prepared(
        &mut self,
        bank: IntervalEpochStorage,
    ) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)> {
        super::super::epoch_storage::stage_leaf_set(&mut self.0, bank)
    }
    /// Reclaim only closed, noncurrent, drained, exclusively owned metadata.
    /// Refusal preserves the same token. A pending FunctionClosed receipt or
    /// retained Report may prevent reclamation; no waiting for owners is added.
    pub fn reclaim_storage(
        &mut self,
        epoch: IntervalEpoch,
    ) -> Result<IntervalEpochStorage, (EpochStorageReclaimError, IntervalEpoch)> {
        if let Err(e) = self.check() {
            return Err((EpochStorageReclaimError::Bridge(e), epoch));
        }
        self.0.reclaim_storage(epoch)
    }
    pub fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        self.check()?;
        self.0.arm(epoch)
    }
    pub fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        self.check()?;
        self.0.disarm(epoch)
    }
    pub fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        self.check()?;
        self.0.report(epoch)
    }
    /// Transfer the bounded resident actions; retain unsent batches yourself.
    /// No epoch/receipt is released and no sink or native-return acknowledgement occurs.
    pub fn drain_history(&mut self) -> Result<Option<NormalLeafSetHistoryBatch>, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.check()?;
        let stream = history::stream_for(&self.0.binding).ok_or(error(Cause::Identity))?;
        self.0
            .binding
            .session
            .drain_history()
            .map_err(|e| error(Cause::Control(e)))
            .map(|chunk| chunk.map(|chunk| NormalLeafSetHistoryBatch::from_checked(stream, chunk)))
    }
    /// Read a qualified resident suffix, including terminal diagnostics; never
    /// substitute it for the complete chained stream or permission to drain.
    pub fn history_window(&self) -> Result<NormalLeafSetHistoryWindow, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.check()?;
        let stream = history::stream_for(&self.0.binding).ok_or(error(Cause::Identity))?;
        let view = self
            .0
            .binding
            .session
            .history_window()
            .map_err(|e| error(Cause::Control(e)))?;
        Ok(NormalLeafSetHistoryWindow::from_checked(stream, view))
    }
}

/// Attachment authority only, retaining the exact immutable leaf-set table.
#[derive(Clone)]
pub struct NormalLeafSetClient {
    binding: Arc<Binding>,
}
impl NormalLeafSetClient {
    /// Opt in to lossless instructions:u endpoints for every real invocation.
    /// PMU refusal is retained as acquisition/endpoint evidence, not a work skip.
    /// # Safety
    /// All attach obligations below hold, including the actual-thread, no-fork,
    /// no-signal, readable-stack and full-state-save contracts. This separately
    /// instrumented path requires native state validation before measurement.
    /// The admitted AMD reference-clock feature set and enabled actual-thread
    /// TSC policy must remain valid throughout attachment. Migration grants no
    /// synchronized-clock claim; both AUX words remain part of each endpoint.
    pub unsafe fn attach_accuracy(
        &self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<NormalLeafSetAccuracyThread, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        if self.accuracy_policy().is_none()
            || !binding_matches(&self.binding)
            || registration == 0
            || journal.page.0.iter().any(|&word| word != 0)
        {
            return Err(error(Cause::Attachment));
        }
        super::super::gate::reference::check_clock().map_err(|_| error(Cause::ClockProfile))?;
        accuracy::attach(&self.binding, registration, stack, journal)
    }
    /// Immutable constructor policy, or None for the original leaf-set profile.
    /// This grants no execution, counter, scheduling or return authority.
    pub fn accuracy_policy(&self) -> Option<Policy> {
        match &self.binding.profile {
            BindingProfile::LeafSet { accuracy, .. } => *accuracy,
            _ => None,
        }
    }
    /// # Safety
    /// The sealed union-wide module contract holds continuously. This actual
    /// caller owns all valid input/stack/journal storage and sufficient callback
    /// save space; RDTSCP remains supported. All functions return normally, with
    /// no nested entry, signals, cancellation, unwind or nonlocal exit. No source,
    /// image or input scan is supplied here. At most 32 calls occur per checkpoint;
    /// actual returns and full source/image/input postflight precede checkpoint.
    /// Only explicit empty detach releases TLS; all code owners are process-lived.
    pub unsafe fn attach(
        &self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<NormalLeafSetThread, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        if !binding_matches(&self.binding)
            || registration == 0
            || journal.page.0.iter().any(|&word| word != 0)
        {
            return Err(error(Cause::Attachment));
        }
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        attach_ready(&self.binding, registration, stack, journal).map(NormalLeafSetThread)
    }
}

/// Actual-thread-only module handle; no conversion to a single-function handle.
pub struct NormalLeafSetThread(NormalThread);
impl NormalLeafSetThread {
    pub fn totals(&self) -> Result<NormalTotals, BridgeError> {
        self.0.totals_profile(TransferProfile::LeafSet)
    }
    /// # Safety
    /// All calls on this actual thread returned normally; no subject/callback
    /// remains active. Full module/source/image and guarded-input postflight has
    /// succeeded before this acknowledgement. Continuous attachment obligations
    /// remain. Pre-RET, Report readiness and metadata drain prove no physical RET
    /// or executable quiescence. The old stack slot is not reread here.
    pub unsafe fn checkpoint_after_returns(
        &mut self,
    ) -> Result<Option<NormalLeafSetBatch>, BridgeError> {
        self.0.checkpoint_with::<LeafSetOutput>()
    }
    pub fn detach(&mut self) -> Result<NormalTotals, BridgeError> {
        self.0.detach_profile(TransferProfile::LeafSet)
    }
}

/// Complete leaf-set transfer with required absolute-history identity.
/// Slots/sequences/ordinals are global;
/// the function tag does not change the existing seven-word journal events.
#[derive(Debug, Eq, PartialEq)]
pub struct NormalLeafSetBatch {
    stream: NormalLeafSetHistoryStream,
    history_end: u64,
    identity: CodeIdentity,
    functions: LeafFunctions,
    entries: [u64; 4],
    pid: u32,
    tid: u64,
    registration: u64,
    install: u64,
    before: Cursor,
    after: Cursor,
    next: u64,
    records: Vec<NormalModuleRecord>,
    journal: Vec<u64>,
}
impl NormalLeafSetBatch {
    /// Required identity, retaining only copied metadata and a key; no epoch or code.
    pub fn history_stream(&self) -> &NormalLeafSetHistoryStream {
        &self.stream
    }
    /// Captured before final receipt consumption; not proof of retained history.
    pub fn history_high_water(&self) -> u64 {
        self.history_end
    }
    pub fn identity(&self) -> CodeIdentity {
        self.identity
    }
    pub fn functions(&self) -> &[FunctionId] {
        self.functions.as_slice()
    }
    pub fn entries(&self) -> &[u64] {
        &self.entries[..self.functions.as_slice().len()]
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn tid(&self) -> u64 {
        self.tid
    }
    pub fn registration(&self) -> u64 {
        self.registration
    }
    pub fn install(&self) -> u64 {
        self.install
    }
    pub fn number(&self) -> u64 {
        self.after.number
    }
    pub fn totals(&self) -> (NormalTotals, NormalTotals) {
        (self.before.totals, self.after.totals)
    }
    pub fn completed_sequences(&self) -> (u64, u64) {
        (self.before.sequence, self.after.sequence)
    }
    pub fn next_ordinal(&self) -> u64 {
        self.next
    }
    pub fn records(&self) -> &[NormalModuleRecord] {
        &self.records
    }
    pub fn journal(&self) -> &[u64] {
        &self.journal
    }
}

pub(super) struct LeafSetOutput {
    records: Vec<NormalModuleRecord>,
}
pub(super) struct LeafSetIdentity {
    stream: NormalLeafSetHistoryStream,
    history_end: u64,
    identity: CodeIdentity,
    functions: LeafFunctions,
    entries: [u64; 4],
}
impl TransferOutput for LeafSetOutput {
    type Batch = NormalLeafSetBatch;
    type Identity = LeafSetIdentity;
    const PROFILE: TransferProfile = TransferProfile::LeafSet;
    fn allocate() -> Result<(Self, Vec<u64>), BridgeError> {
        let (records, journal) = output_buffers()?;
        Ok((Self { records }, journal))
    }
    fn capacity(&self) -> bool {
        self.records.is_empty() && self.records.capacity() >= CALLS
    }
    fn identity(&self, state: &NormalState) -> Result<Self::Identity, BridgeError> {
        if !binding_matches(&state.binding) {
            return Err(error(Cause::Identity));
        }
        let stream = history::stream_for(&state.binding).ok_or(error(Cause::Identity))?;
        let history_end = state.history_bound();
        if history_end > crate::frontend::MAX_HISTORY_POSITION {
            return Err(error(Cause::Capacity));
        }
        // All identity capture precedes pending receipt consumption. finish only moves it.
        Ok(LeafSetIdentity {
            identity: stream.identity(),
            functions: stream.functions,
            entries: stream.entries,
            stream,
            history_end,
        })
    }
    fn push(&mut self, record: NormalRecord, selected: SelectedFunction) {
        self.records.push(NormalModuleRecord {
            function: selected.function,
            record,
        });
    }
    fn finish(self, id: Self::Identity, h: TransferHeader, journal: Vec<u64>) -> Self::Batch {
        NormalLeafSetBatch {
            stream: id.stream,
            history_end: id.history_end,
            identity: id.identity,
            functions: id.functions,
            entries: id.entries,
            pid: h.pid,
            tid: h.tid,
            registration: h.registration,
            install: h.install,
            before: h.before,
            after: h.after,
            next: h.next,
            records: self.records,
            journal,
        }
    }
}

#[cfg(test)]
pub(super) mod tests;

#[cfg(test)]
mod accuracy_tests;

// Reuse the existing real Session/receipt metadata fixture without changing any
// old test body or granting loaded-code/native authority.
#[cfg(test)]
pub(super) fn accuracy_fixture() -> (
    NormalState,
    NormalLeafSetSessionController,
    Option<IntervalEpoch>,
    Vec<IntervalEpochStorage>,
) {
    let f = tests::Fixture::new(2, 10);
    (f.state, f.controller, f.epoch, f.banks)
}
