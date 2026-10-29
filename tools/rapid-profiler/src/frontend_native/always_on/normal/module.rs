//! Two sequential leaves share the normal TLS/receipt/controller runtime.
//! This finite facade grants neither a gate nor nested/concurrent execution.
use super::*;
use liteinst2::contracts::CodeIdentity;
mod session;
mod session_history;
pub use session::{NormalModuleSessionController, PreparedNormalModuleSessionController};
pub use session_history::{
    NormalModuleHistoryBatch, NormalModuleHistoryStream, NormalModuleHistoryWindow,
};

pub(super) fn session_profile_matches(
    profile: &BindingProfile,
    limits: Limits,
    config: Config,
) -> bool {
    session::profile_matches(profile, limits, config)
}
pub(super) fn session_binding_matches(binding: &Binding) -> bool {
    session::binding_matches(binding)
}
pub(super) fn module_runtime_matches(binding: &Binding) -> bool {
    binding_matches(binding) || session::binding_matches(binding)
}

const LIMITS: Limits = Limits {
    epochs: 1,
    threads: 1,
    depth: 1,
    records_per_epoch: 32,
    actions: 2,
};
fn config_matches(config: Config) -> bool {
    matches!(config.retained_per_function, 1 | 16)
        && config.max_inflight == 1
        && config.max_invocations == 32
}
pub(super) fn binding_matches(binding: &Binding) -> bool {
    matches!(&binding.profile, BindingProfile::Module { functions, .. }
        if functions[0] != functions[1])
        && binding.limits == LIMITS
        && matches!(binding.entry_mode, EntryMode::NonBlocking)
        && binding.session.history_mode() == HistoryMode::Legacy
}

/// One module-bound normal preparation. Old leaf clients cannot be extracted.
pub struct PreparedNormalModuleController(PreparedIntervalController);
impl PreparedNormalModuleController {
    /// Require E1/T1/D1, 32 global payload slots, two action slots and two
    /// distinct IDs in the sealed table's ELF order. Both share mandatory group 0.
    pub fn new(
        site: site::ordinary::InstalledNormalModuleSite,
        install: u64,
        functions: [FunctionId; 2],
        limits: Limits,
    ) -> Result<Self, BridgeError> {
        if limits != LIMITS || functions[0] == functions[1] {
            return Err(error(Cause::Identity));
        }
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        let session = Session::new(
            install,
            &functions.map(|function| FunctionSpec { function, group: 0 }),
            &[GroupSpec { mandatory: true }],
            limits,
        )
        .map_err(|e| error(Cause::Setup(e)))?;
        let mut epochs = Vec::new();
        epochs
            .try_reserve_exact(1)
            .map_err(|_| error(Cause::Capacity))?;
        Ok(Self(PreparedIntervalController {
            session,
            profile: BindingProfile::Module {
                site: site.site,
                functions,
            },
            key: Arc::new(()),
            install,
            limits,
            epochs,
            _exclusive: PhantomData,
        }))
    }
    /// Stage once before activation: K is 16 or 1 per function; M1/A32 are global.
    pub fn stage(&mut self, config: Config) -> Result<IntervalEpoch, BridgeError> {
        if !config_matches(config) {
            return Err(error(Cause::Identity));
        }
        self.0.stage(config)
    }
    /// # Safety
    /// The original pristine process/fork activation contract applies, and the
    /// complete sealed module union remains immutable and process-lived. Neither
    /// function may execute until the same actual thread successfully attaches.
    /// Both leaves use normal SysV CALL/RET with no nesting, CALL between them,
    /// reentry, signal, cancellation, unwind, CET, fork, alias writer or unload.
    pub unsafe fn activate(
        self,
    ) -> Result<(NormalModuleController, NormalModuleClient), BridgeError> {
        if self.0.epochs.len() != 1 || self.0.epochs[0].is_none() {
            return Err(error(Cause::Epoch));
        }
        PreparedNormalController::available()?;
        let (controller, binding) = self.0.activate_binding(EntryMode::NonBlocking)?;
        Ok((
            NormalModuleController(controller),
            NormalModuleClient { binding },
        ))
    }
}

/// One finite module controller. No gate, deactivation, further staging or bank
/// API is exposed. Its retained owner/drop behavior is the existing controller's.
pub struct NormalModuleController(IntervalController);
impl NormalModuleController {
    pub fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        self.0.arm(epoch)
    }
    pub fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        self.0.disarm(epoch)
    }
    pub fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        self.0.report(epoch)
    }
    pub fn history(&self) -> Result<ControllerSnapshot, BridgeError> {
        self.0.history()
    }
}

/// Attachment authority only, retaining the exact immutable two-function table.
#[derive(Clone)]
pub struct NormalModuleClient {
    binding: Arc<Binding>,
}
impl NormalModuleClient {
    /// # Safety
    /// The sealed union-wide module contract holds continuously. This actual
    /// caller owns all valid input/stack/journal storage and sufficient callback
    /// save space; RDTSCP remains supported. Both functions return normally, with
    /// no nested entry, signals, cancellation, unwind or nonlocal exit. No source,
    /// image or input scan is supplied here. At most 32 calls occur per checkpoint;
    /// actual returns and full source/image/input postflight precede checkpoint.
    /// Only explicit empty detach releases TLS; all code owners are process-lived.
    pub unsafe fn attach(
        &self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<NormalModuleThread, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        if !module_runtime_matches(&self.binding)
            || registration == 0
            || journal.page.0.iter().any(|&word| word != 0)
        {
            return Err(error(Cause::Attachment));
        }
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        attach_ready(&self.binding, registration, stack, journal).map(NormalModuleThread)
    }
}

/// Actual-thread-only module handle; no conversion to a single-function handle.
pub struct NormalModuleThread(NormalThread);
impl NormalModuleThread {
    pub fn totals(&self) -> Result<NormalTotals, BridgeError> {
        self.0.totals_for(true)
    }
    /// # Safety
    /// All calls on this actual thread returned normally; no subject/callback
    /// remains active. Full module/source/image and guarded-input postflight has
    /// succeeded before this acknowledgement. Continuous attachment obligations
    /// remain. Pre-RET, Report readiness and metadata drain prove no physical RET
    /// or executable quiescence. The old stack slot is not reread here.
    pub unsafe fn checkpoint_after_returns(
        &mut self,
    ) -> Result<Option<NormalModuleBatch>, BridgeError> {
        self.0.checkpoint_with::<ModuleOutput>()
    }
    pub fn detach(&mut self) -> Result<NormalTotals, BridgeError> {
        self.0.detach_for(true)
    }
}

/// Immutable function-tagged observation, without receipt or executable authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalModuleRecord {
    pub function: FunctionId,
    pub record: NormalRecord,
}
/// Complete module transfer, with optional absolute-history identity.
/// Slots/sequences/ordinals are global;
/// the function tag does not change the existing seven-word journal events.
#[derive(Debug, Eq, PartialEq)]
pub struct NormalModuleBatch {
    stream: Option<NormalModuleHistoryStream>,
    history_end: Option<u64>,
    identity: CodeIdentity,
    functions: [FunctionId; 2],
    entries: [u64; 2],
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
impl NormalModuleBatch {
    /// None for the unchanged finite profile; this identity owns no epoch or code.
    pub fn history_stream(&self) -> Option<&NormalModuleHistoryStream> {
        self.stream.as_ref()
    }
    /// Captured before final receipt consumption; not proof of retained history.
    pub fn history_high_water(&self) -> Option<u64> {
        self.history_end
    }
    pub fn identity(&self) -> CodeIdentity {
        self.identity
    }
    pub fn functions(&self) -> &[FunctionId; 2] {
        &self.functions
    }
    pub fn entries(&self) -> &[u64; 2] {
        &self.entries
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

pub(super) struct ModuleOutput {
    records: Vec<NormalModuleRecord>,
}
pub(super) struct ModuleIdentity {
    stream: Option<NormalModuleHistoryStream>,
    history_end: Option<u64>,
    identity: CodeIdentity,
    functions: [FunctionId; 2],
    entries: [u64; 2],
}
impl TransferOutput for ModuleOutput {
    type Batch = NormalModuleBatch;
    type Identity = ModuleIdentity;
    const MODULE: bool = true;
    fn allocate() -> Result<(Self, Vec<u64>), BridgeError> {
        let (records, journal) = output_buffers()?;
        Ok((Self { records }, journal))
    }
    fn capacity(&self) -> bool {
        self.records.is_empty() && self.records.capacity() >= CALLS
    }
    fn identity(&self, state: &NormalState) -> Result<Self::Identity, BridgeError> {
        if !module_runtime_matches(&state.binding) {
            return Err(error(Cause::Identity));
        }
        let BindingProfile::Module { site, functions } = &state.binding.profile else {
            return Err(error(Cause::Identity));
        };
        let stream = session_history::stream_for(&state.binding);
        let history_end = stream.as_ref().map(|_| state.history_bound());
        if history_end.is_some_and(|end| end > crate::frontend::MAX_HISTORY_POSITION) {
            return Err(error(Cause::Capacity));
        }
        Ok(ModuleIdentity {
            stream,
            history_end,
            identity: site.identity(),
            functions: *functions,
            entries: [site.functions()[0].entry(), site.functions()[1].entry()],
        })
    }
    fn push(&mut self, record: NormalRecord, selected: SelectedFunction) {
        self.records.push(NormalModuleRecord {
            function: selected.function,
            record,
        });
    }
    fn finish(self, id: Self::Identity, h: TransferHeader, journal: Vec<u64>) -> Self::Batch {
        NormalModuleBatch {
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
mod tests;
