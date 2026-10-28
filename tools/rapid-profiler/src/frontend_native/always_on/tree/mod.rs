//! Closed depth-two tree; metadata remains the existing Session engine.
pub use super::gate::tree::{OriginalTreeCallResult, TreeCallGate, TreeCallResult};
pub use super::site::SiteError;
use super::*;
use liteinst2::controls::ManagedCallback;
mod drain;
mod postflight;
mod prepared;
mod runtime;
mod site;
pub use drain::TreeBatch;
pub use prepared::PreparedTreeCall;
pub use site::{InstalledTreeSite, PreparedOriginalTreeCall, TreeSitePreparation};

#[derive(Debug)]
pub enum TreeError {
    Site(SiteError),
    Bridge(BridgeError),
    Gate(GateError),
}
impl From<SiteError> for TreeError {
    fn from(e: SiteError) -> Self {
        Self::Site(e)
    }
}
impl From<BridgeError> for TreeError {
    fn from(e: BridgeError) -> Self {
        Self::Bridge(e)
    }
}
impl From<GateError> for TreeError {
    fn from(e: GateError) -> Self {
        Self::Gate(e)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TreeTotals {
    pub roots: u64,
    pub pairs: PairTotals,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
enum RoleKind {
    RootEntry,
    ChildEntry,
    ChildRet,
    ChildAck,
    RootRet,
}

/// Immutable scalar proof, never a ticket, model owner or mutable return slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeRecord {
    external_id: u64,
    node: u8,
    function: FunctionId,
    registration: u64,
    gate_sequence: u64,
    callsite: Option<u64>,
    raw: RawInterval,
    entry_rsp: u64,
    word: u64,
    resume_pc: u64,
    resume_rsp: u64,
    value: u64,
    summary: IntervalEntrySummary,
    start_sequence: Option<u64>,
    children: Option<u64>,
}
impl TreeRecord {
    pub fn external_id(&self) -> u64 {
        self.external_id
    }
    pub fn node(&self) -> u8 {
        self.node
    }
    pub fn parent(&self) -> Option<(u64, u8)> {
        (self.node == 1).then_some((self.external_id, 0))
    }
    pub fn function(&self) -> FunctionId {
        self.function
    }
    /// Zero-based node depth: root 0, child 1; not the active frame count.
    pub fn depth(&self) -> usize {
        usize::from(self.node)
    }
    pub fn registration(&self) -> u64 {
        self.registration
    }
    pub fn gate_sequence(&self) -> u64 {
        self.gate_sequence
    }
    pub fn callsite(&self) -> Option<u64> {
        self.callsite
    }
    pub fn raw(&self) -> &RawInterval {
        &self.raw
    }
    pub fn entry_rsp(&self) -> u64 {
        self.entry_rsp
    }
    pub fn return_word(&self) -> u64 {
        self.word
    }
    pub fn resume_pc(&self) -> u64 {
        self.resume_pc
    }
    pub fn resume_rsp(&self) -> u64 {
        self.resume_rsp
    }
    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn model_start_sequence(&self) -> Option<u64> {
        self.start_sequence
    }
    pub fn model_completed_children(&self) -> Option<u64> {
        self.children
    }
    pub fn history_prefix(&self) -> usize {
        match self.summary {
            IntervalEntrySummary::Admitted { history_len, .. }
            | IntervalEntrySummary::Unsampled { history_len, .. } => history_len,
        }
    }
}
fn input_copy(bytes: &[u8]) -> Result<[u8; 1024], BridgeError> {
    if bytes.len() != 1024 || bytes.as_ptr() as usize & 63 != 0 {
        return Err(error(Cause::Identity));
    }
    let mut before = [0; 1024];
    before.copy_from_slice(bytes);
    Ok(before)
}
struct Binding {
    session: Session,
    site: Arc<site::Site>,
    key: Arc<()>,
    pid: u32,
    install: u64,
    functions: [FunctionId; 2],
    limits: Limits,
    #[cfg(test)]
    native_pauses: std::sync::OnceLock<[Arc<super::tests::concurrent_native::EntryPause>; 3]>,
}
impl Binding {
    fn process(&self) -> Result<(), BridgeError> {
        if self.pid == std::process::id() && self.site.gate.process_matches() {
            Ok(())
        } else {
            Err(error(Cause::Process))
        }
    }
}
/// One local source owner and pristine bounded metadata; no tree call authority.
pub struct PreparedTreeController {
    session: Session,
    site: Arc<site::Site>,
    live: &'static mut site::Live,
    key: Arc<()>,
    install: u64,
    functions: [FunctionId; 2],
    limits: Limits,
    epochs: Vec<Option<EpochHandle>>,
    _local: PhantomData<Rc<()>>,
}
fn config(c: Config) -> Result<(), BridgeError> {
    if c.max_inflight < 2 || c.max_invocations < 2 {
        Err(error(Cause::Setup(SetupError::InvalidLimits)))
    } else {
        Ok(())
    }
}
impl PreparedTreeController {
    pub fn new(
        site: InstalledTreeSite,
        install: u64,
        functions: [FunctionId; 2],
        limits: Limits,
    ) -> Result<Self, BridgeError> {
        if limits.threads != 1 || limits.depth != 2 {
            return Err(error(Cause::Setup(SetupError::InvalidLimits)));
        }
        let session = Session::new(
            install,
            &[
                FunctionSpec {
                    function: functions[0],
                    group: 0,
                },
                FunctionSpec {
                    function: functions[1],
                    group: 1,
                },
            ],
            &[GroupSpec { mandatory: true }; 2],
            limits,
        )
        .map_err(|e| error(Cause::Setup(e)))?;
        let mut epochs = Vec::new();
        epochs
            .try_reserve_exact(limits.epochs)
            .map_err(|_| error(Cause::Capacity))?;
        Ok(Self {
            session,
            site: site.site,
            live: site.live,
            key: Arc::new(()),
            install,
            functions,
            limits,
            epochs,
            _local: PhantomData,
        })
    }
    pub fn stage(&mut self, c: Config) -> Result<IntervalEpoch, BridgeError> {
        let _scope = ControllerScope::enter()?;
        config(c)?;
        staged(&self.session, &self.key, &mut self.epochs, self.limits, c)
    }
    /// # Safety
    /// Complete five-role publication/Tree144 stack contract holds. No active
    /// metadata crosses fork; controller locks may not wait for callbacks. Native
    /// callback waiting has no bounded-latency or cancellation guarantee.
    pub unsafe fn activate_concurrent(self) -> Result<(TreeController, TreeClient), BridgeError> {
        let _scope = ControllerScope::enter()?;
        if !self.site.gate.process_matches() {
            return Err(error(Cause::Process));
        }
        TREE_STATE
            .try_with(|s| {
                if s.try_borrow()
                    .map_err(|_| error(Cause::Attachment))?
                    .is_some()
                    || TREE_POISON.get()
                {
                    Err(error(Cause::Attachment))
                } else {
                    Ok(())
                }
            })
            .unwrap_or(Err(error(Cause::Attachment)))?;
        let snapshot = self
            .session
            .snapshot_for_bridge()
            .map_err(|e| error(Cause::Control(e)))?;
        if snapshot.status != ControllerStatus::Ready
            || snapshot.current.is_some()
            || !snapshot.actions.is_empty()
            || snapshot.retained_failed_generation.is_some()
            || snapshot.enabled != [false, false]
            || self.epochs.iter().any(Option::is_none)
            || self.session.retained_epochs() != self.epochs.len()
        {
            return Err(error(Cause::Invariant));
        }
        let binding = Arc::new(Binding {
            session: self.session,
            site: self.site,
            key: self.key,
            pid: std::process::id(),
            install: self.install,
            functions: self.functions,
            limits: self.limits,
            #[cfg(test)]
            native_pauses: std::sync::OnceLock::new(),
        });
        Ok((
            TreeController {
                binding: Arc::clone(&binding),
                epochs: self.epochs,
                _exclusive: PhantomData,
            },
            TreeClient {
                binding,
                live: self.live,
                _local: PhantomData,
            },
        ))
    }
}
/// Send, not Sync: metadata only, with no loader/file or caller-local token.
pub struct TreeController {
    binding: Arc<Binding>,
    epochs: Vec<Option<EpochHandle>>,
    _exclusive: PhantomData<Cell<()>>,
}
impl TreeController {
    fn owner(&self, epoch: &IntervalEpoch) -> Result<&EpochHandle, BridgeError> {
        self.binding.process()?;
        let owner = self
            .epochs
            .get(epoch.index)
            .and_then(Option::as_ref)
            .ok_or(error(Cause::Epoch))?;
        if !Arc::ptr_eq(&epoch.key, &self.binding.key) || epoch.generation != owner.generation() {
            return Err(error(Cause::Epoch));
        }
        Ok(owner)
    }
    pub fn stage(&mut self, c: Config) -> Result<IntervalEpoch, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        config(c)?;
        staged(
            &self.binding.session,
            &self.binding.key,
            &mut self.epochs,
            self.binding.limits,
            c,
        )
    }
    pub fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding
            .session
            .publish(self.owner(epoch)?, FailurePoint::None)
            .map_err(|e| error(Cause::Control(e)))
    }
    pub fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding
            .session
            .remove_with_controls(Some(self.owner(epoch)?.generation()), |_| {})
            .map_err(|e| error(Cause::Control(e)))
    }
    pub fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        Ok(self.owner(epoch)?.try_report())
    }
    pub fn retire(&mut self, epoch: &IntervalEpoch) -> Result<Report, BridgeError> {
        let _scope = ControllerScope::enter()?;
        let owner = self.owner(epoch)?;
        {
            let snapshot = self
                .binding
                .session
                .snapshot_for_bridge()
                .map_err(|e| error(Cause::Control(e)))?;
            if snapshot.status != ControllerStatus::Ready {
                return Err(error(Cause::Control(ControlError::TerminalFailure)));
            }
            if snapshot.current == Some(owner.generation()) {
                return Err(error(Cause::CurrentEpoch));
            }
        }
        let report = owner.try_report().ok_or(error(Cause::NotDrained))?;
        drop(self.epochs[epoch.index].take());
        Ok(report)
    }
    pub fn history(&self) -> Result<ControllerSnapshot, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        self.binding
            .session
            .snapshot()
            .map_err(|e| error(Cause::Control(e)))
    }
}
impl Drop for TreeController {
    fn drop(&mut self) {
        for owner in self.epochs.iter().flatten() {
            owner.close();
        }
    }
}
#[cfg(test)]
impl TreeController {
    // Three fixed bounded rendezvous, no user callback and no production field.
    // A child of concurrent_native can reuse its unchanged EntryPause constructor
    // and readiness/release atomics. No Session lock spans any wait.
    pub(in crate::frontend_native) fn native_pauses(
        &self,
        pauses: [Arc<super::tests::concurrent_native::EntryPause>; 3],
    ) -> Result<(), BridgeError> {
        self.binding
            .native_pauses
            .set(pauses)
            .map_err(|_| error(Cause::Invariant))
    }
}
/// Unique !Send/!Sync attachment; the mutable loader verifier never crosses threads.
pub struct TreeClient {
    binding: Arc<Binding>,
    live: &'static mut site::Live,
    _local: PhantomData<Rc<()>>,
}
pub struct TreeThread {
    binding: Arc<Binding>,
    live: &'static mut site::Live,
    thread: ThreadId,
    tid: u64,
    registration: u64,
    active: bool,
    finished: Option<TreeTotals>,
    cursor: drain::Cursor,
    _local: PhantomData<Rc<()>>,
}
thread_local! {
    static TREE_STATE: RefCell<Option<runtime::State>> = const { RefCell::new(None) };
    static TREE_POISON: Cell<bool> = const { Cell::new(false) };
}
impl TreeClient {
    /// # Safety
    /// One actual caller thread, complete source/stack/ABI/no-foreign-entry
    /// contracts through detach; no signals, nonlocal exits, fork or reentry.
    pub unsafe fn attach(
        self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<TreeThread, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        if registration == 0 || journal.page.0.iter().any(|&x| x != 0) {
            return Err(error(Cause::Attachment));
        }
        let base = self
            .binding
            .site
            .gate
            .idle_checkpoint()
            .map_err(|e| error(Cause::Gate(e)))?;
        TREE_STATE
            .try_with(|cell| {
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                if storage.is_some() || TREE_POISON.get() {
                    return Err(error(Cause::Attachment));
                }
                let actual = tid();
                if actual == 0 || actual > i32::MAX as u64 {
                    return Err(error(Cause::Identity));
                }
                let model = self
                    .binding
                    .session
                    .register_thread(registration)
                    .map_err(|e| error(Cause::Setup(e)))?;
                let mut state = runtime::State::new(
                    Arc::clone(&self.binding),
                    registration,
                    stack,
                    journal,
                    model,
                    base,
                );
                state.journal.header(actual, 0);
                *storage = Some(state);
                Ok(TreeThread {
                    binding: self.binding,
                    live: self.live,
                    thread: thread::current().id(),
                    tid: actual,
                    registration,
                    active: true,
                    finished: Some(TreeTotals::default()),
                    cursor: drain::Cursor::default(),
                    _local: PhantomData,
                })
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
impl TreeThread {
    fn matches(&self, state: &runtime::State) -> bool {
        self.active
            && self.binding.pid == std::process::id()
            && self.thread == thread::current().id()
            && self.tid == tid()
            && state.tid == self.tid
            && state.thread == self.thread
            && state.registration == self.registration
            && Arc::ptr_eq(&self.binding.key, &state.binding.key)
    }
    pub fn totals(&self) -> Result<TreeTotals, BridgeError> {
        TREE_STATE
            .try_with(|cell| {
                let s = cell.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let state = s.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) {
                    return Err(error(Cause::Attachment));
                }
                state.empty()?;
                if self.finished != Some(state.totals) {
                    return Err(error(Cause::Outstanding));
                }
                self.binding
                    .site
                    .gate
                    .idle_checkpoint()
                    .map_err(|e| error(Cause::Gate(e)))?;
                Ok(state.totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    /// Complete source/input preflight without beginning a tree invocation.
    /// The guard holds this thread and the immutable input until consumed/dropped.
    /// Dropping it unused consumes no gate sequence, external ID or reservation.
    ///
    /// # Safety
    /// Exact certified tree/immutable offset-linked1024-byte input and writable
    /// Tree144 callback stack; pinned actual thread, no foreign entry, signal,
    /// nonlocal exit, alias writer, unload, fork or reentry until guard drop/return.
    /// A controlled tracer stop is permitted only while those invariants remain
    /// intact: no handler, application call or source/input mutation may run.
    pub unsafe fn prepare_tree_call<'call>(
        &'call mut self,
        bytes: &'call [u8],
        external_id: u64,
    ) -> Result<PreparedTreeCall<'call>, TreeError> {
        let input = input_copy(bytes)?;
        let before = self.totals()?;
        {
            let _scope = ControllerScope::enter()?;
            self.live.verify()?;
        }
        Ok(PreparedTreeCall {
            thread: self,
            bytes,
            external_id,
            input,
            before,
            _local: PhantomData,
        })
    }
    /// Prepare and consume one tree call without exposing its guarded interval.
    ///
    /// # Safety
    /// Exact certified tree/immutable offset-linked1024-byte input and writable
    /// Tree144 callback stack; normal returns, pinned actual thread, no foreign
    /// entry/signal/nonlocal exit/alias writer/unload/fork. No subject reference
    /// or TLS borrow crosses the actual assembly CALL.
    pub unsafe fn invoke_tree(
        &mut self,
        bytes: &[u8],
        external_id: u64,
    ) -> Result<TreeCallResult, TreeError> {
        unsafe { self.prepare_tree_call(bytes, external_id)?.invoke() }
    }
    // Only the consumed local guard can supply these exact preflight snapshots.
    unsafe fn invoke_prepared(
        &mut self,
        bytes: &[u8],
        input: [u8; 1024],
        external_id: u64,
        before: TreeTotals,
    ) -> Result<TreeCallResult, TreeError> {
        let gate = Arc::clone(&self.binding.site.gate);
        let (stack, sequence) = TREE_STATE
            .try_with(|cell| {
                let mut s = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let state = s.as_mut().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) {
                    return Err(error(Cause::Attachment));
                }
                let sequence = gate
                    .idle_checkpoint()
                    .map_err(|e| error(Cause::Gate(e)))?
                    .checked_add(1)
                    .ok_or(error(Cause::Capacity))?;
                state.begin(external_id, sequence)?;
                Ok((
                    ReadableStack {
                        start: state.stack.start,
                        end: state.stack.end,
                    },
                    sequence,
                ))
            })
            .unwrap_or(Err(error(Cause::Attachment)))?;
        self.finished = None;
        let outcome = (|| {
            let pending = unsafe { gate.invoke(bytes, &stack, external_id) };
            let pending = postflight::check(
                pending.map_err(TreeError::Gate),
                || {
                    let _scope = ControllerScope::enter()?;
                    self.live.verify().map_err(TreeError::Site)
                },
                || {
                    if bytes == input {
                        Ok(())
                    } else {
                        Err(TreeError::Bridge(error(Cause::Invariant)))
                    }
                },
            )?;
            let call = *pending.result();
            if call.gate_sequence != sequence || call.external_id != external_id {
                return Err(TreeError::Bridge(error(Cause::Invariant)));
            }
            let ready = pending.validate()?;
            let totals = TREE_STATE
                .try_with(|cell| {
                    let mut s = cell
                        .try_borrow_mut()
                        .map_err(|_| error(Cause::Attachment))?;
                    let state = s.as_mut().ok_or(error(Cause::Attachment))?;
                    if !self.matches(state) {
                        return Err(error(Cause::Attachment));
                    }
                    state.finish_root(call, before)
                })
                .unwrap_or(Err(error(Cause::Attachment)))?;
            let call = ready.commit();
            self.finished = Some(totals);
            Ok(call)
        })();
        if outcome.is_err() {
            let _ = TREE_STATE.try_with(|cell| {
                if let Ok(mut s) = cell.try_borrow_mut() {
                    if let Some(state) = s.as_mut() {
                        state.fail(error(Cause::Outstanding));
                    }
                }
            });
        }
        outcome
    }
    /// Only an empty, healthy, explicitly drained attachment can detach.
    pub fn detach(&mut self) -> Result<TreeTotals, BridgeError> {
        let totals = self.totals()?;
        TREE_STATE
            .try_with(|cell| {
                let mut s = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let state = s.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) || state.len != 0 || state.journal.used() != 0 {
                    return Err(error(Cause::Outstanding));
                }
                s.take();
                self.active = false;
                Ok(totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
impl Drop for TreeThread {
    fn drop(&mut self) {
        if self.active && self.detach().is_err() {
            let _ = TREE_POISON.try_with(|p| p.set(true));
            let _ = TREE_STATE.try_with(|cell| {
                if let Ok(mut s) = cell.try_borrow_mut() {
                    if let Some(state) = s.as_mut() {
                        state.fail(error(Cause::Outstanding));
                    }
                }
            });
        }
    }
}

const CALLBACKS: [ManagedCallback; 5] = [root_entry, child_entry, child_ret, child_ack, root_ret];
unsafe extern "C" fn root_entry(c: *mut HookContext, id: ControlIdentity<'_>) {
    dispatch(c, id, RoleKind::RootEntry);
}
unsafe extern "C" fn child_entry(c: *mut HookContext, id: ControlIdentity<'_>) {
    dispatch(c, id, RoleKind::ChildEntry);
}
unsafe extern "C" fn child_ret(c: *mut HookContext, id: ControlIdentity<'_>) {
    dispatch(c, id, RoleKind::ChildRet);
}
unsafe extern "C" fn child_ack(c: *mut HookContext, id: ControlIdentity<'_>) {
    dispatch(c, id, RoleKind::ChildAck);
}
unsafe extern "C" fn root_ret(c: *mut HookContext, id: ControlIdentity<'_>) {
    dispatch(c, id, RoleKind::RootRet);
}
fn dispatch(c: *mut HookContext, id: ControlIdentity<'_>, role: RoleKind) {
    let stamp = (role != RoleKind::ChildAck).then(|| unsafe { timing::read() });
    if c.is_null() {
        fatal();
    }
    // SAFETY: only the exact retained managed Tree144 actions call this function.
    let context = unsafe { &*c };
    let result = TREE_STATE
        .try_with(|cell| {
            let mut storage = cell
                .try_borrow_mut()
                .map_err(|_| error(Cause::Attachment))?;
            let state = storage.as_mut().ok_or(error(Cause::Attachment))?;
            let result = state.callback(context, id, role, stamp);
            if let Err(e) = result {
                state.fail(e);
            }
            result
        })
        .unwrap_or(Err(error(Cause::Attachment)));
    if result.is_err() {
        fatal();
    }
}
