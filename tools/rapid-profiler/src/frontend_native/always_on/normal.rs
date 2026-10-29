//! Normal application CALLs: mandatory entry/pre-RET observations, no CALL gate.
//! A receipt remains pending until a later authenticated entry or an unsafe
//! caller checkpoint acknowledges return. Neither acknowledgement observes C3
//! execution or grants executable reclamation. All code owners are process-lived.
use super::*;
pub(super) mod leaf_set;
mod module;
pub use leaf_set::{
    NormalLeafSetBatch, NormalLeafSetClient, NormalLeafSetHistoryBatch, NormalLeafSetHistoryStream,
    NormalLeafSetHistoryWindow, NormalLeafSetSessionController, NormalLeafSetThread,
    PreparedNormalLeafSetSessionController,
};
mod two_callers;
pub use module::{
    NormalModuleBatch, NormalModuleClient, NormalModuleController, NormalModuleHistoryBatch,
    NormalModuleHistoryStream, NormalModuleHistoryWindow, NormalModuleRecord,
    NormalModuleSessionController, NormalModuleThread, PreparedNormalModuleController,
    PreparedNormalModuleSessionController,
};
pub use two_callers::PreparedTwoCallerNormalController;

// Closed private bridges for the separately guarded module bank facade.
pub(super) fn module_session_profile_matches(
    profile: &BindingProfile,
    limits: Limits,
    config: Config,
) -> bool {
    module::session_profile_matches(profile, limits, config)
}
pub(super) fn module_session_binding_matches(binding: &Binding) -> bool {
    module::session_binding_matches(binding)
}

const CALLS: usize = EVENTS / 2;

/// Contract-based return acknowledgement, distinct from an observed physical RET.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalAcknowledgement {
    /// A later genuine entry under the sole-entry, no-CALL/no-reentry contract.
    /// This next reservation coordinate may subsequently refuse admission.
    NextEntry { ordinal: u64 },
    /// The attached caller explicitly attested that all previous calls returned.
    CallerCheckpoint,
}

/// Immutable observation, without a ticket, source owner or executable authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalRecord {
    /// Entry and pre-RET callback endpoints, not a physical-return timestamp.
    pub raw: RawInterval,
    pub entry_rsp: u64,
    /// Copied at entry and matched at pre-RET; never reread after another CALL.
    pub return_word: u64,
    pub history_prefix: u64,
    pub acknowledgement: NormalAcknowledgement,
}

/// Lifetime counters. Observing a RET does not yet increment confirmed/completed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NormalTotals {
    pub entered: u64,
    pub ret_observed: u64,
    pub confirmed: u64,
    pub completed: u64,
    pub unsampled: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Cursor {
    number: u64,
    totals: NormalTotals,
    sequence: u64,
}

/// Complete immutable transfer, including all 512 journal words. Ordinals,
/// totals and sampled completion sequences are lifetime values; rows are local.
/// Construction selects finite legacy history or opt-in absolute history. An
/// absolute prefix must be joined with contiguous HistoryBatches from this stream.
#[derive(Debug, Eq, PartialEq)]
pub struct NormalBatch {
    stream: Option<HistoryStream>,
    history_end: Option<u64>,
    pid: u32,
    tid: u64,
    registration: u64,
    install: u64,
    function: FunctionId,
    before: Cursor,
    after: Cursor,
    next: u64,
    records: Vec<NormalRecord>,
    journal: Vec<u64>,
}
impl NormalBatch {
    /// None is the unchanged legacy format. This opaque identity owns no epoch,
    /// Session or executable mapping and does not acknowledge external export.
    pub fn history_stream(&self) -> Option<&HistoryStream> {
        self.stream.as_ref()
    }
    /// Absolute mode only: committed action bound captured before transfer.
    /// This is not proof that a consumer retained or replayed those actions.
    pub fn history_high_water(&self) -> Option<u64> {
        self.history_end
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
    pub fn function(&self) -> FunctionId {
        self.function
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
    pub fn records(&self) -> &[NormalRecord] {
        &self.records
    }
    pub fn journal(&self) -> &[u64] {
        &self.journal
    }
}

struct TransferHeader {
    pid: u32,
    tid: u64,
    registration: u64,
    install: u64,
    before: Cursor,
    after: Cursor,
    next: u64,
}
#[derive(Clone, Copy)]
enum TransferProfile {
    Single,
    Pair,
    LeafSet,
}
impl TransferProfile {
    fn from_pair(module: bool) -> Self {
        if module { Self::Pair } else { Self::Single }
    }
}

trait TransferOutput {
    type Batch;
    type Identity;
    const PROFILE: TransferProfile;
    fn allocate() -> Result<(Self, Vec<u64>), BridgeError>
    where
        Self: Sized;
    fn capacity(&self) -> bool;
    fn identity(&self, state: &NormalState) -> Result<Self::Identity, BridgeError>;
    fn push(&mut self, record: NormalRecord, selected: SelectedFunction);
    fn finish(
        self,
        identity: Self::Identity,
        header: TransferHeader,
        journal: Vec<u64>,
    ) -> Self::Batch;
}
struct SingleOutput {
    records: Vec<NormalRecord>,
}
struct SingleIdentity {
    function: FunctionId,
    stream: Option<HistoryStream>,
    history_end: Option<u64>,
}
impl TransferOutput for SingleOutput {
    type Batch = NormalBatch;
    type Identity = SingleIdentity;
    const PROFILE: TransferProfile = TransferProfile::Single;
    fn allocate() -> Result<(Self, Vec<u64>), BridgeError> {
        let (records, journal) = outputs()?;
        Ok((Self { records }, journal))
    }
    fn capacity(&self) -> bool {
        self.records.is_empty() && self.records.capacity() >= CALLS
    }
    fn identity(&self, state: &NormalState) -> Result<Self::Identity, BridgeError> {
        let function = state.binding.single_function()?;
        let stream = history::stream_for(&state.binding);
        let history_end = stream.as_ref().map(|_| state.history_bound());
        Ok(SingleIdentity {
            function,
            stream,
            history_end,
        })
    }
    fn push(&mut self, record: NormalRecord, _selected: SelectedFunction) {
        self.records.push(record);
    }
    fn finish(self, id: Self::Identity, h: TransferHeader, journal: Vec<u64>) -> Self::Batch {
        NormalBatch {
            stream: id.stream,
            history_end: id.history_end,
            function: id.function,
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

/// Pristine single-calling-thread preparation; no gated client can be extracted.
pub struct PreparedNormalController(PreparedIntervalController);
impl PreparedNormalController {
    pub fn new(
        site: site::ordinary::InstalledNormalSite,
        install: u64,
        function: FunctionId,
        limits: Limits,
    ) -> Result<Self, BridgeError> {
        Self::prepare(site, install, function, limits, HistoryMode::Legacy)
    }
    /// Opt in to bounded resident history with absolute entry prefixes. Requires
    /// activate_concurrent. Limits.actions bounds resident actions; the caller
    /// must explicitly drain and retain history before that capacity is exhausted.
    /// Draining history never acknowledges a native return or releases its owner.
    pub fn new_streaming_history(
        site: site::ordinary::InstalledNormalSite,
        install: u64,
        function: FunctionId,
        limits: Limits,
    ) -> Result<Self, BridgeError> {
        Self::prepare(site, install, function, limits, HistoryMode::Absolute)
    }
    fn prepare(
        site: site::ordinary::InstalledNormalSite,
        install: u64,
        function: FunctionId,
        limits: Limits,
        mode: HistoryMode,
    ) -> Result<Self, BridgeError> {
        if !site.site.is_normal() || limits.threads != 1 || limits.depth != 1 {
            return Err(error(Cause::Identity));
        }
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        let constructor = match mode {
            HistoryMode::Legacy => PreparedIntervalController::new,
            HistoryMode::Absolute => PreparedIntervalController::new_streaming_history,
        };
        constructor(
            site::InstalledIntervalSite { site: site.site },
            install,
            function,
            limits,
        )
        .map(Self)
    }
    pub fn stage(&mut self, config: Config) -> Result<IntervalEpoch, BridgeError> {
        self.0.stage(config)
    }
    /// Prepare exactly Limits.epochs non-Clone fixed-Config banks once, before
    /// activation, staging or registration, in pristine streaming-history mode.
    /// All fallible allocation finishes before this commits banked mode; ordinary
    /// allocating stage then refuses. Initialized slot state is touched, not every
    /// byte of storage capacity: this promises neither residency nor a 2 ms bound.
    /// Dropped/forgotten banks and legacy retirement permanently lose capacity.
    pub fn prepare_epoch_storage(
        &mut self,
        config: Config,
    ) -> Result<Vec<IntervalEpochStorage>, BridgeError> {
        super::epoch_storage::prepare(&mut self.0, config)
    }
    /// # Safety
    /// The pristine fork/activation obligations of PreparedIntervalController
    /// apply. NormalLeafContract, successful publication and continuous source,
    /// input, stack and single-calling-thread custody remain caller obligations.
    pub unsafe fn activate(self) -> Result<(IntervalController, NormalClient), BridgeError> {
        Self::available()?;
        // SAFETY: forwarded pristine activation contract, without exposing its client.
        let (controller, client) = unsafe { self.0.activate()? };
        Ok((
            controller,
            NormalClient {
                binding: client.binding,
            },
        ))
    }
    /// # Safety
    /// All activate obligations apply, plus the existing concurrent-controller
    /// no-reentry/no-signal/no-callback-dependent-lock obligations. There is still
    /// exactly one calling thread. Contention has no bounded-latency guarantee.
    pub unsafe fn activate_concurrent(
        self,
    ) -> Result<(IntervalController, NormalClient), BridgeError> {
        Self::available()?;
        // SAFETY: the caller supplies both activation and concurrency contracts.
        let (controller, client) = unsafe { self.0.activate_concurrent()? };
        Ok((
            controller,
            NormalClient {
                binding: client.binding,
            },
        ))
    }
    fn available() -> Result<(), BridgeError> {
        NORMAL
            .try_with(|cell| {
                if NORMAL_POISON.get()
                    || cell
                        .try_borrow()
                        .map_err(|_| error(Cause::Attachment))?
                        .0
                        .is_some()
                {
                    Err(error(Cause::Attachment))
                } else {
                    Ok(())
                }
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}

/// Attachment authority only. Contains no call gate, original callable pointer,
/// controller methods or conversion to IntervalClient.
#[derive(Clone)]
pub struct NormalClient {
    binding: Arc<Binding>,
}

/// !Send/!Sync actual-thread attachment. It never wraps individual application calls.
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::NormalThread;
/// fn send<T: Send>() {}
/// send::<NormalThread>();
/// ```
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::NormalThread;
/// fn sync<T: Sync>() {}
/// sync::<NormalThread>();
/// ```
pub struct NormalThread {
    key: Arc<()>,
    pid: u32,
    thread: ThreadId,
    tid: u64,
    registration: u64,
    active: bool,
    _local: PhantomData<Rc<()>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectedFunction {
    index: usize,
    function: FunctionId,
}
struct Pending {
    selected: SelectedFunction,
    ordinal: u64,
    rsp: u64,
    word: u64,
    entry_pc: u64,
    start: RawTimestamp,
    receipt: IntervalEntry,
    slot: ModelReturnSlot,
    summary: Option<IntervalEntrySummary>,
    returned: Option<RawInterval>,
}
struct NormalState {
    binding: Arc<Binding>,
    actual_thread: ThreadId,
    tid: u64,
    registration: u64,
    stack: ReadableStack,
    model: ThreadModel,
    pending: Option<Pending>,
    records: [Option<NormalRecord>; CALLS],
    functions: [Option<SelectedFunction>; CALLS],
    len: usize,
    next: u64,
    totals: NormalTotals,
    cursor: Cursor,
    journal: IntervalJournal,
    failure: Option<BridgeError>,
    busy: bool,
}

// A lost/failed handle and actual TLS teardown must not cancel a pending model
// frame or release a FunctionClosed permit. Explicit empty detach is the only
// path that takes/drops this allocation. Each TLS contains at most one attachment.
struct Storage(Option<Box<NormalState>>);
impl Drop for Storage {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            let _ = Box::leak(state);
        }
    }
}
thread_local! {
    static NORMAL: RefCell<Storage> = const { RefCell::new(Storage(None)) };
    static NORMAL_POISON: Cell<bool> = const { Cell::new(false) };
}

impl NormalClient {
    /// # Safety
    /// The sealed NormalLeafContract holds continuously until explicit empty
    /// detach. Every call is on this actual thread, to the sole original entry,
    /// with a normal matching return; no recursion, signal, cancellation, unwind,
    /// tail entry or nonlocal exit. All valid inputs, source/image/file bytes and
    /// mappings remain caller-owned and immutable. This API performs no per-call
    /// input/source scan. Stack covers every saved return word and callbacks have
    /// sufficient writable full-state-save space. RDTSCP remains available to
    /// this actual thread. The caller ensures finite batches <= 32 calls and
    /// quiescence before attach/checkpoint/detach; metadata is not code quiescence.
    pub unsafe fn attach(
        &self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<NormalThread, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        if !self.binding.single_site()?.is_normal()
            || self.binding.limits.threads != 1
            || self.binding.limits.depth != 1
            || registration == 0
            || journal.page.0.iter().any(|&word| word != 0)
        {
            return Err(error(Cause::Attachment));
        }
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        self.attach_ready(registration, stack, journal)
    }
    // Both public unsafe routes have authenticated their immutable profile,
    // process, limits, journal and clock under a live ControllerScope first.
    fn attach_ready(
        &self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<NormalThread, BridgeError> {
        attach_ready(&self.binding, registration, stack, journal)
    }
}
fn attach_ready(
    binding: &Arc<Binding>,
    registration: u64,
    stack: ReadableStack,
    journal: IntervalJournal,
) -> Result<NormalThread, BridgeError> {
    NORMAL
        .try_with(|cell| {
            if NORMAL_POISON.get() {
                return Err(error(Cause::Attachment));
            }
            let mut storage = cell
                .try_borrow_mut()
                .map_err(|_| error(Cause::Attachment))?;
            if storage.0.is_some() {
                return Err(error(Cause::Attachment));
            }
            // No registration is consumed before all local attachment checks.
            let model = binding
                .session
                .register_thread(registration)
                .map_err(|e| error(Cause::Setup(e)))?;
            let thread = thread::current().id();
            let tid = tid();
            let mut state = Box::new(NormalState::new(
                Arc::clone(binding),
                registration,
                stack,
                journal,
                model,
            ));
            state.journal.header(tid, 0);
            storage.0 = Some(state);
            Ok(NormalThread {
                key: Arc::clone(&binding.key),
                pid: binding.pid,
                thread,
                tid,
                registration,
                active: true,
                _local: PhantomData,
            })
        })
        .unwrap_or(Err(error(Cause::Attachment)))
}

fn normal_binding_matches(binding: &Binding) -> bool {
    (binding.single_site().is_ok_and(|site| site.is_normal())
        && binding.limits.threads == 1
        && binding.limits.depth == 1)
        || two_callers::binding_matches(binding)
}

fn stack_word_ok(stack: &ReadableStack, rsp: u64, word: u64) -> bool {
    rsp >= stack.start
        && rsp & 15 == 8
        && rsp.checked_add(8).is_some_and(|end| end <= stack.end)
        && word != 0
}
fn balanced(t: NormalTotals) -> bool {
    t.entered == t.ret_observed
        && t.ret_observed == t.confirmed
        && t.completed.checked_add(t.unsampled) == Some(t.confirmed)
}
fn reserve_entry(len: usize, used: usize) -> Result<(), BridgeError> {
    if len >= CALLS || used != len * 2 || used.checked_add(2).is_none_or(|n| n > EVENTS) {
        Err(error(Cause::Capacity))
    } else {
        Ok(())
    }
}
fn acknowledgement_ok(ack: NormalAcknowledgement, ordinal: u64) -> bool {
    match ack {
        NormalAcknowledgement::NextEntry { ordinal: next } => ordinal.checked_add(1) == Some(next),
        NormalAcknowledgement::CallerCheckpoint => true,
    }
}
fn record_words(
    record: &NormalRecord,
    mode: HistoryMode,
) -> Result<([u64; 7], [u64; 7]), BridgeError> {
    let prefix = record.history_prefix;
    let (kind, generation, invocation, reason) = match record.raw.owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => (
            1,
            generation,
            invocation.checked_add(1).ok_or(error(Cause::Capacity))? as u64,
            0,
        ),
        RawIntervalOwner::InitialDisarmed => (3, 0, 0, 1),
        RawIntervalOwner::Removed { generation } => (3, generation, 0, 2),
        RawIntervalOwner::FunctionClosed { generation } => (3, generation, 0, 3),
    };
    let limit = match mode {
        HistoryMode::Legacy => 256,
        HistoryMode::Absolute => crate::frontend::MAX_HISTORY_POSITION,
    };
    if prefix > limit
        || invocation > 4096
        || (kind == 1 && invocation == 0)
        || ((reason == 1) != (generation == 0))
        || (reason != 1 && prefix == 0)
        || !acknowledgement_ok(record.acknowledgement, record.raw.ordinal)
    {
        return Err(error(Cause::Invariant));
    }
    let bits = invocation | ((prefix & 0x1ff) << 13) | (reason << 22) | ((prefix >> 9) << 24);
    let entry = [
        kind,
        record.raw.ordinal,
        record.raw.entry_pc,
        record.entry_rsp,
        record.return_word,
        generation,
        bits,
    ];
    let exit = [
        kind + 1,
        record.raw.ordinal,
        record.raw.return_pc,
        record.entry_rsp,
        record.return_word,
        generation,
        bits,
    ];
    Ok((entry, exit))
}

fn finished_function_matches(result: IntervalExit, function: FunctionId) -> bool {
    match result {
        IntervalExit::Completed {
            completion,
            payload,
            ..
        } => {
            completion.admission.function == function
                && payload.admission.function == function
                && completion.admission == payload.admission
        }
        IntervalExit::Unsampled {
            reason:
                UnsampledSummary::FunctionClosed {
                    function: actual, ..
                },
            ..
        } => actual == function,
        IntervalExit::Unsampled { .. } => true,
    }
}

impl NormalState {
    fn selection(&self, index: usize) -> Result<SelectedFunction, BridgeError> {
        let function = match &self.binding.profile {
            BindingProfile::Single { function, .. } if index == 0 => *function,
            BindingProfile::Module { functions, .. } => {
                *functions.get(index).ok_or(error(Cause::Identity))?
            }
            BindingProfile::LeafSet { functions, .. } => *functions
                .as_slice()
                .get(index)
                .ok_or(error(Cause::Identity))?,
            _ => return Err(error(Cause::Identity)),
        };
        Ok(SelectedFunction { index, function })
    }
    fn selected_geometry(
        &self,
        selected: SelectedFunction,
        entry_pc: u64,
        return_pc: Option<u64>,
    ) -> Result<(), BridgeError> {
        if self.selection(selected.index)? != selected {
            return Err(error(Cause::Identity));
        }
        if let BindingProfile::Module { site, .. } = &self.binding.profile {
            let function = &site.functions()[selected.index];
            if entry_pc != function.entry()
                || return_pc.is_some_and(|pc| !function.returns().contains(&pc))
            {
                return Err(error(Cause::Identity));
            }
        }
        if let BindingProfile::LeafSet { site, .. } = &self.binding.profile {
            let function = site
                .functions()
                .get(selected.index)
                .ok_or(error(Cause::Identity))?;
            if entry_pc != function.entry()
                || return_pc.is_some_and(|pc| !function.returns().contains(&pc))
            {
                return Err(error(Cause::Identity));
            }
        }
        Ok(())
    }
    fn history_bound(&self) -> u64 {
        match self.binding.session.history_mode() {
            HistoryMode::Legacy => self.binding.limits.actions as u64,
            HistoryMode::Absolute => self.binding.session.history_committed_end(),
        }
    }
    fn history_prefix(&self, bits: u64) -> Result<u64, BridgeError> {
        let prefix = match self.binding.session.history_mode() {
            HistoryMode::Legacy if bits >> 24 == 0 => (bits >> 13) & 0x1ff,
            HistoryMode::Absolute => {
                history::decode_absolute(bits, self.history_bound())
                    .ok_or(error(Cause::Invariant))?
                    .1
            }
            _ => return Err(error(Cause::Invariant)),
        };
        if prefix > self.history_bound() {
            return Err(error(Cause::Invariant));
        }
        Ok(prefix)
    }
    fn new(
        binding: Arc<Binding>,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
        model: ThreadModel,
    ) -> Self {
        Self {
            binding,
            actual_thread: thread::current().id(),
            tid: tid(),
            registration,
            stack,
            model,
            pending: None,
            records: [None; CALLS],
            functions: [None; CALLS],
            len: 0,
            next: 1,
            totals: NormalTotals::default(),
            cursor: Cursor::default(),
            journal,
            failure: None,
            busy: false,
        }
    }
    fn fail(&mut self, e: BridgeError) -> BridgeError {
        let first = *self.failure.get_or_insert(e);
        self.journal.poison();
        first
    }
    fn health(&self) -> Result<(), BridgeError> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if self.busy || NORMAL_POISON.get() {
            return Err(error(Cause::Outstanding));
        }
        Ok(())
    }
    // Pure metadata invariants do not inspect the previous application's stack.
    fn shape(&self) -> Result<(), BridgeError> {
        let outstanding = u64::from(self.pending.is_some());
        let returned = u64::from(self.pending.as_ref().is_some_and(|p| p.returned.is_some()));
        let sampled = self
            .pending
            .as_ref()
            .and_then(|p| p.summary)
            .is_some_and(|s| matches!(s, IntervalEntrySummary::Admitted { .. }));
        if self.len > CALLS
            || self.totals.completed.checked_add(self.totals.unsampled)
                != Some(self.totals.confirmed)
            || self.totals.confirmed.checked_add(outstanding) != Some(self.totals.entered)
            || self.totals.confirmed.checked_add(returned) != Some(self.totals.ret_observed)
            || self.totals.entered.checked_add(1) != Some(self.next)
            || self
                .totals
                .confirmed
                .checked_sub(self.cursor.totals.confirmed)
                != Some(self.len as u64)
            || self.model.completed_sequence() != self.totals.completed
            || self.model.identity() != self.registration
            || self.model.depth() != usize::from(sampled)
            || self.journal.used() != self.len * 2 + outstanding as usize + returned as usize
            || self.records[..self.len].iter().any(Option::is_none)
            || self.records[self.len..].iter().any(Option::is_some)
            || self.functions[..self.len].iter().any(Option::is_none)
            || self.functions[self.len..].iter().any(Option::is_some)
        {
            return Err(error(Cause::Invariant));
        }
        Ok(())
    }
    fn identity(
        &self,
        context: &HookContext,
        control: ControlIdentity<'_>,
        entry: bool,
    ) -> Result<(u64, SelectedFunction), BridgeError> {
        self.binding.process()?;
        if !(normal_binding_matches(&self.binding)
            || module::module_runtime_matches(&self.binding)
            || leaf_set::binding_matches(&self.binding))
            || self.actual_thread != thread::current().id()
            || self.tid != tid()
            || context.stack_pointer < self.stack.start
            || context.stack_pointer & 15 != 8
            || context
                .stack_pointer
                .checked_add(8)
                .is_none_or(|end| end > self.stack.end)
        {
            return Err(error(Cause::Identity));
        }
        let index = match &self.binding.profile {
            BindingProfile::Single { site, .. } => {
                if !site.matches(context.instruction_pointer, control, entry) {
                    return Err(error(Cause::Identity));
                }
                0
            }
            BindingProfile::Module { site, .. } => site
                .resolve(context.instruction_pointer, control, entry)
                .ok_or(error(Cause::Identity))?,
            BindingProfile::LeafSet { site, .. } => site
                .resolve(context.instruction_pointer, control, entry)
                .ok_or(error(Cause::Identity))?,
        };
        let selected = self.selection(index)?;
        // SAFETY: unsafe attachment certifies the current exact eight-byte slot.
        let word = unsafe { (context.stack_pointer as usize as *const u64).read_unaligned() };
        if !stack_word_ok(&self.stack, context.stack_pointer, word) {
            return Err(error(Cause::Return));
        }
        Ok((word, selected))
    }
    #[cfg(test)]
    fn enter(
        &mut self,
        pc: u64,
        rsp: u64,
        word: u64,
        start: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.enter_function(self.selection(0)?, pc, rsp, word, start)
    }
    fn enter_function(
        &mut self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        start: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.selected_geometry(selected, pc, None)?;
        self.shape()?;
        if self.pending.is_some() {
            // identity() already authenticated a new real entry. Never reread the
            // old stack slot: this new CALL may have overwritten it legitimately.
            self.confirm(NormalAcknowledgement::NextEntry { ordinal: self.next })?;
        }
        reserve_entry(self.len, self.journal.used())?;
        let next = self.next.checked_add(1).ok_or(error(Cause::Capacity))?;
        let entered = self
            .totals
            .entered
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        let mut slot = ModelReturnSlot {
            identity: self.next,
            word: TOKEN,
        };
        let enter = match self.binding.entry_mode {
            EntryMode::NonBlocking => ThreadModel::enter_interval,
            EntryMode::Concurrent => ThreadModel::enter_interval_waiting,
        };
        let receipt = enter(
            &mut self.model,
            self.binding.install,
            selected.function,
            start.ticks,
            &mut slot,
        )
        .map_err(|e| error(Cause::Entry(e)))?;
        // Custody precedes every fallible postcondition, including history packing.
        self.pending = Some(Pending {
            selected,
            ordinal: self.next,
            rsp,
            word,
            entry_pc: pc,
            start,
            receipt,
            slot,
            summary: None,
            returned: None,
        });
        let p = self.pending.as_mut().ok_or(error(Cause::Invariant))?;
        let summary = p.receipt.summary().ok_or(error(Cause::Invariant))?;
        p.summary = Some(summary);
        let (kind, generation, bits) =
            history::packed_for_function(&self.binding.session, p.selected.function, summary)?;
        self.journal
            .row([kind, p.ordinal, pc, rsp, word, generation, bits]);
        self.journal.header(self.tid, 1);
        self.next = next;
        self.totals.entered = entered;
        Ok(())
    }
    #[cfg(test)]
    fn observe(
        &mut self,
        pc: u64,
        rsp: u64,
        word: u64,
        end: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.observe_function(self.selection(0)?, pc, rsp, word, end)
    }
    fn observe_function(
        &mut self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        end: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.shape()?;
        let pending = self.pending.as_ref().ok_or(error(Cause::Return))?;
        self.selected_geometry(selected, pending.entry_pc, Some(pc))?;
        let p = self.pending.as_mut().ok_or(error(Cause::Return))?;
        if p.selected != selected
            || p.returned.is_some()
            || p.rsp != rsp
            || p.word != word
            || p.slot.identity != p.ordinal
        {
            return Err(error(Cause::Return));
        }
        let summary = p.summary.ok_or(error(Cause::Invariant))?;
        let (kind, generation, bits) =
            history::packed_for_function(&self.binding.session, p.selected.function, summary)?;
        let observed = self
            .totals
            .ret_observed
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        if self.journal.used() >= EVENTS || self.len >= CALLS {
            return Err(error(Cause::Capacity));
        }
        let raw = RawInterval {
            ordinal: p.ordinal,
            entry_pc: p.entry_pc,
            return_pc: pc,
            owner: timing::owner(summary),
            start: p.start,
            end,
        };
        self.journal
            .row([kind + 1, p.ordinal, pc, rsp, word, generation, bits]);
        p.returned = Some(raw);
        self.totals.ret_observed = observed;
        // Receipt, sampled frame and FunctionClosed owner remain untouched.
        Ok(())
    }
    fn confirmation(
        &self,
        acknowledgement: NormalAcknowledgement,
    ) -> Result<(NormalRecord, NormalTotals), BridgeError> {
        let p = self.pending.as_ref().ok_or(error(Cause::Return))?;
        let summary = p.summary.ok_or(error(Cause::Invariant))?;
        let raw = p.returned.ok_or(error(Cause::Return))?;
        self.selected_geometry(p.selected, p.entry_pc, Some(raw.return_pc))?;
        let (_, _, bits) =
            history::packed_for_function(&self.binding.session, p.selected.function, summary)?;
        let history_prefix = self.history_prefix(bits)?;
        if self.len >= CALLS
            || self.records[self.len].is_some()
            || self.functions[self.len].is_some()
            || p.slot.identity != p.ordinal
            || p.ordinal.checked_add(1) != Some(self.next)
            || self
                .cursor
                .totals
                .confirmed
                .checked_add(self.len as u64 + 1)
                != Some(p.ordinal)
            || raw.ordinal != p.ordinal
            || raw.entry_pc != p.entry_pc
            || raw.start != p.start
            || raw.owner != timing::owner(summary)
            || !stack_word_ok(&self.stack, p.rsp, p.word)
            || !acknowledgement_ok(acknowledgement, p.ordinal)
        {
            return Err(error(Cause::Invariant));
        }
        let record = NormalRecord {
            raw,
            entry_rsp: p.rsp,
            return_word: p.word,
            history_prefix,
            acknowledgement,
        };
        let (entry, exit) = record_words(&record, self.binding.session.history_mode())?;
        let at = 4 + self.len * 14;
        if self.journal.page.0[at..at + 7] != entry || self.journal.page.0[at + 7..at + 14] != exit
        {
            return Err(error(Cause::Invariant));
        }
        let mut totals = self.totals;
        totals.confirmed = totals
            .confirmed
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        let sampled = matches!(summary, IntervalEntrySummary::Admitted { .. });
        totals.completed = totals
            .completed
            .checked_add(u64::from(sampled))
            .ok_or(error(Cause::Capacity))?;
        totals.unsampled = totals
            .unsampled
            .checked_add(u64::from(!sampled))
            .ok_or(error(Cause::Capacity))?;
        if !balanced(totals) {
            return Err(error(Cause::Invariant));
        }
        Ok((record, totals))
    }
    fn confirm(&mut self, acknowledgement: NormalAcknowledgement) -> Result<(), BridgeError> {
        let (record, totals) = self.confirmation(acknowledgement)?;
        let p = self.pending.as_mut().ok_or(error(Cause::Invariant))?;
        let result = self
            .model
            .finish_interval(&mut p.receipt, &mut p.slot, record.raw.observation())
            .map_err(|e| error(Cause::Exit(e)))?;
        // A consumed receipt is never retried after a postcondition failure.
        if !finished_function_matches(result, p.selected.function)
            || Some(result.summary()) != p.summary
            || p.slot
                != (ModelReturnSlot {
                    identity: p.ordinal,
                    word: TOKEN,
                })
            || self.model.completed_sequence() != totals.completed
        {
            return Err(error(Cause::Invariant));
        }
        self.records[self.len] = Some(record);
        self.functions[self.len] = Some(p.selected);
        self.len += 1;
        self.totals = totals;
        self.pending = None;
        self.journal.header(self.tid, 0);
        Ok(())
    }
    fn transfer_check(&self) -> Result<(NormalTotals, usize, u64), BridgeError> {
        self.shape()?;
        if !balanced(self.cursor.totals)
            || self.cursor.sequence != self.cursor.totals.completed
            || self.journal.page.0[1..4] != [0, self.tid, u64::from(self.pending.is_some())]
        {
            return Err(error(Cause::Invariant));
        }
        let (totals, count) = if self.pending.is_some() {
            (
                self.confirmation(NormalAcknowledgement::CallerCheckpoint)?
                    .1,
                self.len + 1,
            )
        } else {
            (self.totals, self.len)
        };
        if !balanced(totals)
            || totals.confirmed.checked_sub(self.cursor.totals.confirmed) != Some(count as u64)
            || self.journal.used() != count * 2
            || self.journal.page.0[4 + count * 14..]
                .iter()
                .any(|&x| x != 0)
        {
            return Err(error(Cause::Invariant));
        }
        let mut sampled = usize::from(
            self.pending
                .as_ref()
                .and_then(|p| p.summary)
                .is_some_and(|s| matches!(s, IntervalEntrySummary::Admitted { .. })),
        );
        for (i, record) in self.records[..self.len].iter().enumerate() {
            let record = record.ok_or(error(Cause::Invariant))?;
            self.selected_geometry(
                self.functions[i].ok_or(error(Cause::Invariant))?,
                record.raw.entry_pc,
                Some(record.raw.return_pc),
            )?;
            let expected = self
                .cursor
                .totals
                .confirmed
                .checked_add(i as u64 + 1)
                .ok_or(error(Cause::Capacity))?;
            let (entry, exit) = record_words(&record, self.binding.session.history_mode())?;
            let at = 4 + i * 14;
            sampled += usize::from(matches!(record.raw.owner, RawIntervalOwner::Sampled { .. }));
            if record.raw.ordinal != expected
                || record.acknowledgement
                    != (NormalAcknowledgement::NextEntry {
                        ordinal: expected.checked_add(1).ok_or(error(Cause::Capacity))?,
                    })
                || !stack_word_ok(&self.stack, record.entry_rsp, record.return_word)
                || record.history_prefix > self.history_bound()
                || self.journal.page.0[at..at + 7] != entry
                || self.journal.page.0[at + 7..at + 14] != exit
            {
                return Err(error(Cause::Invariant));
            }
        }
        if totals.completed.checked_sub(self.cursor.totals.completed) != Some(sampled as u64)
            || totals.unsampled.checked_sub(self.cursor.totals.unsampled)
                != Some((count - sampled) as u64)
        {
            return Err(error(Cause::Invariant));
        }
        let number = if count == 0 {
            self.cursor.number
        } else {
            self.cursor
                .number
                .checked_add(1)
                .ok_or(error(Cause::Capacity))?
        };
        Ok((totals, count, number))
    }
    #[cfg(test)]
    fn transfer(
        &mut self,
        records: Vec<NormalRecord>,
        journal: Vec<u64>,
    ) -> Result<Option<NormalBatch>, BridgeError> {
        self.transfer_into(SingleOutput { records }, journal)
    }
    fn transfer_into<O: TransferOutput>(
        &mut self,
        mut output: O,
        mut journal: Vec<u64>,
    ) -> Result<Option<O::Batch>, BridgeError> {
        if !output.capacity() || !journal.is_empty() || journal.capacity() < 512 {
            return Err(error(Cause::Capacity));
        }
        let (totals, count, number) = self.transfer_check()?;
        let identity = output.identity(self)?;
        if count == 0 {
            return Ok(None);
        }
        if self.pending.is_some() {
            self.confirm(NormalAcknowledgement::CallerCheckpoint)?;
        }
        // All profile/geometry/tag checks and allocation precede consumption.
        // Both occupied prefixes were checked, including the pending final row.
        // These fixed-buffer copies and typed construction cannot look up/fail.
        for (record, selected) in self.records[..self.len]
            .iter()
            .flatten()
            .zip(self.functions[..self.len].iter().flatten())
        {
            output.push(*record, *selected);
        }
        // SAFETY: this exclusive TLS transaction owns the entire live page.
        journal.extend(
            self.journal
                .page
                .0
                .iter()
                .map(|p| unsafe { std::ptr::read_volatile(p) }),
        );
        let before = self.cursor;
        let after = Cursor {
            number,
            totals,
            sequence: totals.completed,
        };
        let header = TransferHeader {
            pid: self.binding.pid,
            tid: self.tid,
            registration: self.registration,
            install: self.binding.install,
            before,
            after,
            next: self.next,
        };
        self.records = [None; CALLS];
        self.functions = [None; CALLS];
        self.len = 0;
        for i in 0..512 {
            self.journal.word(i, 0);
        }
        self.journal.header(self.tid, 0);
        self.cursor = after;
        Ok(Some(output.finish(identity, header, journal)))
    }
}

impl NormalThread {
    fn matches(&self, s: &NormalState) -> bool {
        self.matches_identity(s) && normal_binding_matches(&s.binding)
    }
    fn matches_for(&self, s: &NormalState, module: bool) -> bool {
        if module {
            self.matches_identity(s) && module::module_runtime_matches(&s.binding)
        } else {
            self.matches(s)
        }
    }
    fn matches_profile(&self, s: &NormalState, profile: TransferProfile) -> bool {
        match profile {
            TransferProfile::Single => self.matches_for(s, false),
            TransferProfile::Pair => self.matches_for(s, true),
            TransferProfile::LeafSet => {
                self.matches_identity(s) && leaf_set::binding_matches(&s.binding)
            }
        }
    }
    fn matches_identity(&self, s: &NormalState) -> bool {
        self.active
            && self.pid == std::process::id()
            && self.thread == thread::current().id()
            && self.tid == tid()
            && self.registration == s.registration
            && s.tid == self.tid
            && s.actual_thread == self.thread
            && Arc::ptr_eq(&self.key, &s.binding.key)
    }
    /// Snapshot only; a pending pre-RET remains pending and holds its owner.
    pub fn totals(&self) -> Result<NormalTotals, BridgeError> {
        self.totals_for(false)
    }
    fn totals_for(&self, module: bool) -> Result<NormalTotals, BridgeError> {
        self.totals_profile(TransferProfile::from_pair(module))
    }
    fn totals_profile(&self, profile: TransferProfile) -> Result<NormalTotals, BridgeError> {
        NORMAL
            .try_with(|cell| {
                let storage = cell.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let state = storage.0.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches_profile(state, profile) {
                    return Err(error(Cause::Attachment));
                }
                state.health()?;
                state.shape()?;
                Ok(state.totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    /// Confirm the last pending call and atomically transfer the local buffers.
    /// Allocation refusal leaves receipts, records, counters and journal unchanged.
    /// A logical failure is sticky; no second finish/retry can create completion.
    ///
    /// # Safety
    /// On this same attached thread, every previously entered subject has
    /// actually returned normally to application code, and no subject/callback
    /// is active or can reenter during this operation. This is an external caller
    /// attestation, not an observed RET or executable-quiescence certificate.
    /// All continuous attachment/source/input/signal contracts still hold. The
    /// caller performs its required source/image and guarded-input checks before
    /// this checkpoint or exposing records; a failed check withholds checkpoint.
    /// No file, mapping or input scan is performed here. The caller must not
    /// infer return from a ready Report or pre-RET counter.
    pub unsafe fn checkpoint_after_returns(&mut self) -> Result<Option<NormalBatch>, BridgeError> {
        self.checkpoint_with::<SingleOutput>()
    }
    fn checkpoint_with<O: TransferOutput>(&mut self) -> Result<Option<O::Batch>, BridgeError> {
        let _scope = ControllerScope::enter()?;
        // Preserve a prior sticky failure before any new allocation refusal.
        self.totals_profile(O::PROFILE)?;
        let (output, journal) = O::allocate()?;
        NORMAL
            .try_with(|cell| {
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let state = storage.0.as_mut().ok_or(error(Cause::Attachment))?;
                if !self.matches_profile(state, O::PROFILE) {
                    return Err(error(Cause::Attachment));
                }
                state.health()?;
                state.busy = true;
                match state.transfer_into(output, journal) {
                    Ok(batch) => {
                        state.busy = false;
                        Ok(batch)
                    }
                    Err(e) => Err(state.fail(e)),
                }
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    /// No pending receipt or unexported row/event may be discarded. Failure keeps
    /// the handle and TLS intact. Detach does not assert native/code quiescence.
    pub fn detach(&mut self) -> Result<NormalTotals, BridgeError> {
        self.detach_for(false)
    }
    fn detach_for(&mut self, module: bool) -> Result<NormalTotals, BridgeError> {
        self.detach_profile(TransferProfile::from_pair(module))
    }
    fn detach_profile(&mut self, profile: TransferProfile) -> Result<NormalTotals, BridgeError> {
        let _scope = ControllerScope::enter()?;
        NORMAL
            .try_with(|cell| {
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let state = storage.0.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches_profile(state, profile) {
                    return Err(error(Cause::Attachment));
                }
                state.health()?;
                state.shape()?;
                if state.pending.is_some() || state.len != 0 || state.journal.used() != 0 {
                    return Err(error(Cause::Outstanding));
                }
                let totals = state.totals;
                drop(storage.0.take());
                self.active = false;
                Ok(totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
impl Drop for NormalThread {
    fn drop(&mut self) {
        if self.active {
            let _ = NORMAL_POISON.try_with(|p| p.set(true));
            let _ = NORMAL.try_with(|cell| {
                if let Ok(mut storage) = cell.try_borrow_mut() {
                    if let Some(state) = storage.0.as_mut() {
                        state.fail(error(Cause::Outstanding));
                    }
                }
            });
        }
    }
}

#[cfg(test)]
thread_local! { static FAIL_RESERVE: Cell<Option<usize>> = const { Cell::new(None) }; }
fn outputs() -> Result<(Vec<NormalRecord>, Vec<u64>), BridgeError> {
    output_buffers()
}
fn output_buffers<R>() -> Result<(Vec<R>, Vec<u64>), BridgeError> {
    fn reserve<T>(v: &mut Vec<T>, n: usize, _slot: usize) -> Result<(), BridgeError> {
        #[cfg(test)]
        if FAIL_RESERVE.get() == Some(_slot) {
            return Err(error(Cause::Capacity));
        }
        v.try_reserve_exact(n).map_err(|_| error(Cause::Capacity))
    }
    let mut records = Vec::new();
    let mut journal = Vec::new();
    reserve(&mut records, CALLS, 0)?;
    reserve(&mut journal, 512, 1)?;
    Ok((records, journal))
}

fn callback(
    context: &HookContext,
    control: ControlIdentity<'_>,
    entry: bool,
    stamp: RawTimestamp,
) -> Result<(), BridgeError> {
    if CONTROLLER_ACTIVE.try_with(Cell::get).unwrap_or(true) {
        return Err(error(Cause::ControllerReentry));
    }
    NORMAL
        .try_with(|cell| {
            if NORMAL_POISON.get() {
                return Err(error(Cause::Attachment));
            }
            let mut storage = cell
                .try_borrow_mut()
                .map_err(|_| error(Cause::Attachment))?;
            let state = storage.0.as_mut().ok_or(error(Cause::Attachment))?;
            state.health()?;
            state.busy = true;
            let result = (|| {
                let (word, selected) = state.identity(context, control, entry)?;
                if entry {
                    state.enter_function(
                        selected,
                        context.instruction_pointer,
                        context.stack_pointer,
                        word,
                        stamp,
                    )
                } else {
                    state.observe_function(
                        selected,
                        context.instruction_pointer,
                        context.stack_pointer,
                        word,
                        stamp,
                    )
                }
            })();
            match result {
                Ok(()) => {
                    state.busy = false;
                    Ok(())
                }
                Err(e) => Err(state.fail(e)),
            }
        })
        .unwrap_or(Err(error(Cause::Attachment)))
}
fn fatal() -> ! {
    let _ = NORMAL_POISON.try_with(|p| p.set(true));
    // SAFETY: never unwind through a trampoline or continue an invalid call.
    unsafe { libc::_exit(123) }
}
pub(super) unsafe extern "C" fn entry_callback(
    context: *mut HookContext,
    control: ControlIdentity<'_>,
) {
    // SAFETY: the sealed normal factory and actual-thread attachment admit RDTSCP.
    let stamp = unsafe { timing::read() };
    if context.is_null() {
        fatal();
    }
    // SAFETY: sealed dispatcher provides a live complete saved HookContext.
    if callback(unsafe { &*context }, control, true, stamp).is_err() {
        fatal();
    }
}
pub(super) unsafe extern "C" fn exit_callback(
    context: *mut HookContext,
    control: ControlIdentity<'_>,
) {
    // SAFETY: identical sealed instruction-support contract to entry.
    let stamp = unsafe { timing::read() };
    if context.is_null() {
        fatal();
    }
    // SAFETY: sealed dispatcher at an authenticated original C3.
    if callback(unsafe { &*context }, control, false, stamp).is_err() {
        fatal();
    }
}

#[cfg(test)]
mod tests;
