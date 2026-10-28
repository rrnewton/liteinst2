//! Finite optional ordinary intervals. FastBypass is not an unsampled interval.
mod drain;
mod gate;
mod history;
#[cfg(test)]
pub(crate) use history::metadata_site;
mod site;
use super::*;
pub use drain::OptionalIntervalBatch;
pub use gate::OptionalCallGate;
use liteinst2::precontext::{Disposition, PreContextWriter};
pub use site::{InstalledOptionalSite, OptionalSitePreparation, PreparedOptionalOriginalCall};
use std::sync::atomic::{AtomicBool, Ordering};

/// Successfully checked physical returns and unchanged Slow-only pair accounting.
/// A failed invocation remains a failure even if its application RET already ran.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OptionalTotals {
    pub physical: u64,
    pub bypassed: u64,
    pub observed: PairTotals,
}
/// One real returned call. Slow's ordinal joins one raw/journal pair; Fast has none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionalPath {
    FastBypass,
    Slow { ordinal: u64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionalCallResult {
    pub physical: u64,
    pub gate_sequence: u64,
    pub path: OptionalPath,
    pub value: u64,
    pub pre_call_rsp: u64,
    pub entry_rsp: u64,
    pub resumed_rsp: u64,
    pub return_pc: u64,
}
struct Binding {
    session: Session,
    site: Arc<site::Site>,
    key: Arc<()>,
    pid: u32,
    install: u64,
    function: FunctionId,
    limits: Limits,
    failed: AtomicBool,
    #[cfg(test)]
    native_entry_pause: std::sync::OnceLock<Arc<tests::native::EntryPause>>,
}
impl Binding {
    fn process(&self) -> Result<(), BridgeError> {
        if self.pid != std::process::id() {
            return Err(error(Cause::Process));
        }
        Ok(())
    }
    fn healthy(&self) -> Result<(), BridgeError> {
        self.process()?;
        if self.failed.load(Ordering::Acquire) {
            return Err(error(Cause::Control(ControlError::TerminalFailure)));
        }
        Ok(())
    }
    fn mutation<T>(&self, r: Result<T, BridgeError>) -> Result<T, BridgeError> {
        // An optional controller mutation error is sticky, including pre-mutation
        // refusals. Expected stage/report/retire refusals do not use this policy.
        if r.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        r
    }
}
/// One-function finite legacy-history preparation; no selector writer escapes.
pub struct PreparedOptionalController {
    session: Session,
    site: Arc<site::Site>,
    writer: PreContextWriter,
    key: Arc<()>,
    install: u64,
    function: FunctionId,
    limits: Limits,
    epochs: Vec<Option<EpochHandle>>,
    _exclusive: PhantomData<Cell<()>>,
}
impl PreparedOptionalController {
    pub fn new(
        site: InstalledOptionalSite,
        install: u64,
        function: FunctionId,
        limits: Limits,
    ) -> Result<Self, BridgeError> {
        let session = Session::new(
            install,
            &[FunctionSpec { function, group: 0 }],
            &[GroupSpec { mandatory: false }],
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
            writer: site.writer,
            key: Arc::new(()),
            install,
            function,
            limits,
            epochs,
            _exclusive: PhantomData,
        })
    }
    pub fn stage(&mut self, c: Config) -> Result<IntervalEpoch, BridgeError> {
        staged(&self.session, &self.key, &mut self.epochs, self.limits, c)
    }
    /// # Safety
    /// Complete process-lived publication is valid; no fork since gate creation,
    /// signal, cancellation, allocator reentry or callback/controller lock cycle.
    /// Controller operations may not wait for a callback while owning metadata locks.
    pub unsafe fn activate_concurrent(
        self,
    ) -> Result<(OptionalController, OptionalClient), BridgeError> {
        if !self.site.gate.process_matches() || self.site.selector.is_enabled() {
            return Err(error(Cause::Identity));
        }
        let snap = self
            .session
            .snapshot_for_bridge()
            .map_err(|e| error(Cause::Control(e)))?;
        if snap.status != ControllerStatus::Ready
            || snap.current.is_some()
            || !snap.actions.is_empty()
            || snap.enabled != [false]
            || snap.retained_failed_generation.is_some()
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
            function: self.function,
            limits: self.limits,
            failed: AtomicBool::new(false),
            #[cfg(test)]
            native_entry_pause: std::sync::OnceLock::new(),
        });
        Ok((
            OptionalController {
                binding: binding.clone(),
                writer: self.writer,
                epochs: self.epochs,
                _exclusive: PhantomData,
            },
            OptionalClient { binding },
        ))
    }
}
/// Unique writer. Scan lag is explicit; K completion alone never stores to the selector.
pub struct OptionalController {
    binding: Arc<Binding>,
    writer: PreContextWriter,
    epochs: Vec<Option<EpochHandle>>,
    _exclusive: PhantomData<Cell<()>>,
}
impl OptionalController {
    fn owner(&self, e: &IntervalEpoch) -> Result<&EpochHandle, BridgeError> {
        self.binding.healthy()?;
        let o = self
            .epochs
            .get(e.index)
            .and_then(Option::as_ref)
            .ok_or(error(Cause::Epoch))?;
        if !Arc::ptr_eq(&e.key, &self.binding.key) || e.generation != o.generation() {
            return Err(error(Cause::Epoch));
        }
        Ok(o)
    }
    pub fn stage(&mut self, c: Config) -> Result<IntervalEpoch, BridgeError> {
        self.binding.healthy()?;
        staged(
            &self.binding.session,
            &self.binding.key,
            &mut self.epochs,
            self.binding.limits,
            c,
        )
    }
    pub fn arm(&mut self, e: &IntervalEpoch) -> Result<(), BridgeError> {
        self.publish(e, FailurePoint::None)
    }
    fn publish(&mut self, e: &IntervalEpoch, failure: FailurePoint) -> Result<(), BridgeError> {
        let result = (|| {
            let _scope = ControllerScope::enter()?;
            let owner = self.owner(e)?.clone();
            self.binding
                .session
                .publish_with_controls(&owner, failure, |enabled| {
                    self.writer.set_enabled(enabled[0])
                })
                .map_err(|e| error(Cause::Control(e)))
        })();
        self.binding.mutation(result)
    }
    pub fn disarm(&mut self, e: &IntervalEpoch) -> Result<(), BridgeError> {
        let result = (|| {
            let _scope = ControllerScope::enter()?;
            let generation = self.owner(e)?.generation();
            self.binding
                .session
                .remove_with_controls(Some(generation), |enabled| {
                    self.writer.set_enabled(enabled[0])
                })
                .map_err(|e| error(Cause::Control(e)))
        })();
        self.binding.mutation(result)
    }
    pub fn scan_closed(&mut self) -> Result<usize, BridgeError> {
        let result = (|| {
            let _scope = ControllerScope::enter()?;
            self.binding.healthy()?;
            self.binding
                .session
                .scan_with_controls(|enabled| self.writer.set_enabled(enabled[0]))
                .map_err(|e| error(Cause::Control(e)))
        })();
        self.binding.mutation(result)
    }
    pub fn report(&self, e: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        Ok(self.owner(e)?.try_report())
    }
    pub fn retire(&mut self, e: &IntervalEpoch) -> Result<Report, BridgeError> {
        let _scope = ControllerScope::enter()?;
        let owner = self.owner(e)?;
        let snapshot = self.binding.session.snapshot_for_bridge().map_err(|e| {
            self.binding.failed.store(true, Ordering::Release);
            error(Cause::Control(e))
        })?;
        if snapshot.status != ControllerStatus::Ready {
            self.binding.failed.store(true, Ordering::Release);
            return Err(error(Cause::Control(ControlError::TerminalFailure)));
        }
        if snapshot.current == Some(owner.generation()) {
            return Err(error(Cause::CurrentEpoch));
        }
        drop(snapshot);
        let report = owner.try_report().ok_or(error(Cause::NotDrained))?;
        drop(self.epochs[e.index].take());
        Ok(report)
    }
    pub fn history(&self) -> Result<ControllerSnapshot, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        self.binding.session.snapshot().map_err(|e| {
            self.binding.failed.store(true, Ordering::Release);
            error(Cause::Control(e))
        })
    }
}
impl Drop for OptionalController {
    fn drop(&mut self) {
        self.binding.failed.store(true, Ordering::Release);
        for epoch in self.epochs.iter().flatten() {
            epoch.close();
        }
        // No fabricated Removed action, selector update or native quiescence.
    }
}
#[derive(Clone)]
pub struct OptionalClient {
    binding: Arc<Binding>,
}
struct Pair {
    ordinal: u64,
    sequence: u64,
    rsp: u64,
    word: u64,
    slot: ModelReturnSlot,
    receipt: IntervalEntry,
    summary: Option<IntervalEntrySummary>,
    token: gate::Entry,
    start: RawTimestamp,
    entry_pc: u64,
}
struct State {
    binding: Arc<Binding>,
    thread: ThreadId,
    tid: u64,
    registration: u64,
    stack: ReadableStack,
    model: ThreadModel,
    pair: Option<Pair>,
    next: u64,
    totals: OptionalTotals,
    journal: IntervalJournal,
    rows: timing::Rows,
    joins: [u64; EVENTS / 2],
    gate_base: u64,
    failure: Option<BridgeError>,
}
thread_local! {
    static STATE:RefCell<Option<State>>=const{RefCell::new(None)};
    static POISONED:Cell<bool>=const{Cell::new(false)};
}
/// Actual-thread attachment; a failed invocation never restores its completion latch.
/// It cannot be transferred or shared:
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::OptionalThread;
/// fn send<T: Send>() {}
/// send::<OptionalThread>();
/// ```
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::OptionalThread;
/// fn share<T: Sync>() {}
/// share::<OptionalThread>();
/// ```
pub struct OptionalThread {
    key: Arc<()>,
    pid: u32,
    thread: ThreadId,
    tid: u64,
    registration: u64,
    active: bool,
    finished: Cell<Option<OptionalTotals>>,
    cursor: drain::Cursor,
    _local: PhantomData<Rc<()>>,
}
impl OptionalClient {
    /// # Safety
    /// Exact source/publication/input/stack contracts last until empty detach.
    /// Only this gate may call the leaf; no nesting, signal, unwind or cross-profile
    /// reentry. Metadata transitions use the separate concurrent controller.
    pub unsafe fn attach(
        &self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<OptionalThread, BridgeError> {
        self.binding.healthy()?;
        if registration == 0 || journal.page.0.iter().any(|&v| v != 0) {
            return Err(error(Cause::Attachment));
        }
        let gate_base = self
            .binding
            .site
            .gate
            .idle_checkpoint()
            .map_err(|e| error(Cause::Gate(e)))?;
        STATE
            .try_with(|cell| {
                if POISONED.get() {
                    return Err(error(Cause::Attachment));
                }
                let mut slot = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                if slot.is_some() {
                    return Err(error(Cause::Attachment));
                }
                let model = self
                    .binding
                    .session
                    .register_thread(registration)
                    .map_err(|e| {
                        if e == SetupError::Poisoned {
                            self.binding.failed.store(true, Ordering::Release);
                        }
                        error(Cause::Setup(e))
                    })?;
                let thread = thread::current().id();
                let tid = tid();
                let mut journal = journal;
                journal.header(tid, 0);
                *slot = Some(State {
                    binding: self.binding.clone(),
                    thread,
                    tid,
                    registration,
                    stack,
                    model,
                    pair: None,
                    next: 1,
                    totals: OptionalTotals::default(),
                    journal,
                    rows: timing::Rows::new(),
                    joins: [0; EVENTS / 2],
                    gate_base,
                    failure: None,
                });
                Ok(OptionalThread {
                    key: self.binding.key.clone(),
                    pid: self.binding.pid,
                    thread,
                    tid,
                    registration,
                    active: true,
                    finished: Cell::new(Some(OptionalTotals::default())),
                    cursor: drain::Cursor::default(),
                    _local: PhantomData,
                })
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
impl State {
    fn fail(&mut self, e: BridgeError) {
        if self.failure.is_none() {
            self.failure = Some(e);
        }
        self.journal.poison();
    }
    fn empty(&self) -> Result<(), BridgeError> {
        self.binding.process()?;
        if self.failure.is_some()
            || POISONED.get()
            || self.pair.is_some()
            || self.model.depth() != 0
        {
            return Err(error(Cause::Outstanding));
        }
        Ok(())
    }
    fn reserve(&self) -> Result<(), BridgeError> {
        self.empty()?;
        self.binding.healthy()?;
        if CONTROLLER_ACTIVE.try_with(Cell::get).unwrap_or(true) {
            return Err(error(Cause::ControllerReentry));
        }
        self.rows.reserve(0)?;
        if self
            .journal
            .used()
            .checked_add(2)
            .is_none_or(|n| n > EVENTS)
            || self.journal.used() % 2 != 0
            || self.totals.physical == u64::MAX
            || self.next == u64::MAX
        {
            return Err(error(Cause::Capacity));
        }
        Ok(())
    }
    fn identity(
        &self,
        c: &HookContext,
        control: ControlIdentity<'_>,
        entry: bool,
    ) -> Result<u64, BridgeError> {
        self.binding.process()?;
        if self.thread != thread::current().id()
            || self.tid != tid()
            || self.failure.is_some()
            || CONTROLLER_ACTIVE.try_with(Cell::get).unwrap_or(true)
            || !self
                .binding
                .site
                .matches(c.instruction_pointer, control, entry)
            || c.stack_pointer < self.stack.start
            || c.stack_pointer
                .checked_add(8)
                .is_none_or(|n| n > self.stack.end)
        {
            return Err(error(Cause::Identity));
        }
        let word = unsafe { (c.stack_pointer as usize as *const u64).read_unaligned() };
        if word != self.binding.site.gate.continuation() {
            return Err(error(Cause::Return));
        }
        Ok(word)
    }
    fn enter(
        &mut self,
        pc: u64,
        rsp: u64,
        word: u64,
        start: RawTimestamp,
        token: gate::Entry,
    ) -> Result<(), BridgeError> {
        // Do not consult the controller failure flag here: a genuinely selected
        // Slow call must finish its real model protocol or refuse, never bypass.
        self.empty()?;
        self.rows.reserve(0)?;
        if self
            .journal
            .used()
            .checked_add(2)
            .is_none_or(|n| n > EVENTS)
        {
            return Err(error(Cause::Capacity));
        }
        let next = self.next.checked_add(1).ok_or(error(Cause::Capacity))?;
        let entries = self
            .totals
            .observed
            .entries
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        let sequence = self
            .gate_base
            .checked_add(self.totals.physical)
            .and_then(|n| n.checked_add(1))
            .ok_or(error(Cause::Capacity))?;
        let mut slot = ModelReturnSlot {
            identity: self.next,
            word: TOKEN,
        };
        let receipt = self
            .model
            .enter_interval_waiting(
                self.binding.install,
                self.binding.function,
                start.ticks,
                &mut slot,
            )
            .map_err(|e| error(Cause::Entry(e)))?;
        self.pair = Some(Pair {
            ordinal: self.next,
            sequence,
            rsp,
            word,
            slot,
            receipt,
            summary: None,
            token,
            start,
            entry_pc: pc,
        });
        let pair = self.pair.as_mut().ok_or(error(Cause::Invariant))?;
        let summary = pair.receipt.summary().ok_or(error(Cause::Invariant))?;
        pair.summary = Some(summary);
        let (kind, generation, bits) = history::packed_for(&self.binding, summary)?;
        self.journal.row([
            kind,
            pair.ordinal,
            pair.entry_pc,
            pair.rsp,
            pair.word,
            generation,
            bits,
        ]);
        self.next = next;
        self.totals.observed.entries = entries;
        self.journal.header(self.tid, 1);
        // Qualification-only atomic pause after actual owner/pair/journal publication.
        // Production builds have no field, branch or callback here.
        #[cfg(test)]
        if let Some(pause) = self.binding.native_entry_pause.get() {
            pause.wait(next - 1)?;
        }
        Ok(())
    }
    fn finish(
        &mut self,
        pc: u64,
        rsp: u64,
        word: u64,
        end: RawTimestamp,
        returned: gate::Return,
    ) -> Result<(), BridgeError> {
        if self.failure.is_some() {
            return Err(error(Cause::Attachment));
        }
        let pair = self.pair.as_mut().ok_or(error(Cause::Return))?;
        if pair.rsp != rsp || pair.word != word || pair.slot.identity != pair.ordinal {
            return Err(error(Cause::Return));
        }
        let summary = pair.summary.ok_or(error(Cause::Invariant))?;
        let (kind, generation, bits) = history::packed_for(&self.binding, summary)?;
        self.rows.reserve(0)?;
        if self.journal.used() >= EVENTS {
            return Err(error(Cause::Capacity));
        }
        let mut totals = self.totals.observed;
        totals.returns = totals
            .returns
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        totals.completed = totals
            .completed
            .checked_add(u64::from(kind == 1))
            .ok_or(error(Cause::Capacity))?;
        totals.unsampled = totals
            .unsampled
            .checked_add(u64::from(kind == 3))
            .ok_or(error(Cause::Capacity))?;
        let row = RawInterval {
            ordinal: pair.ordinal,
            entry_pc: pair.entry_pc,
            return_pc: pc,
            owner: timing::owner(summary),
            start: pair.start,
            end,
        };
        let result = self
            .model
            .finish_interval(&mut pair.receipt, &mut pair.slot, row.observation())
            .map_err(|e| error(Cause::Exit(e)))?;
        if result.summary() != summary
            || pair.slot
                != (ModelReturnSlot {
                    identity: pair.ordinal,
                    word: TOKEN,
                })
        {
            return Err(error(Cause::Invariant));
        }
        self.binding
            .site
            .gate
            .complete_ret(returned)
            .map_err(|e| error(Cause::Gate(e)))?;
        let join = self.journal.used() / 2;
        self.rows.push(row)?;
        self.joins[join] = pair.sequence;
        self.journal.row([
            kind + 1,
            pair.ordinal,
            pc,
            pair.rsp,
            pair.word,
            generation,
            bits,
        ]);
        self.pair = None;
        self.totals.observed = totals;
        self.journal.header(self.tid, 0);
        Ok(())
    }
}
impl OptionalThread {
    fn matches(&self, s: &State) -> bool {
        self.active
            && self.pid == std::process::id()
            && self.thread == thread::current().id()
            && self.tid == tid()
            && self.registration == s.registration
            && s.tid == self.tid
            && s.thread == self.thread
            && Arc::ptr_eq(&self.key, &s.binding.key)
    }
    pub fn totals(&self) -> Result<OptionalTotals, BridgeError> {
        STATE
            .try_with(|cell| {
                let b = cell.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let s = b.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches(s) {
                    return Err(error(Cause::Attachment));
                }
                s.empty()?;
                Ok(s.totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    /// # Safety
    /// Exact admitted input/stack/normal-return/no-signal/reentry/fork/CET and
    /// process-lived source obligations hold. The thread stays on one CPU.
    /// Capacity is checked even when a later entry might choose FastBypass.
    pub unsafe fn invoke_integer_leaf(
        &self,
        bytes: &[u8],
    ) -> Result<OptionalCallResult, BridgeError> {
        let (gate, extent, before) = STATE
            .try_with(|cell| {
                let b = cell.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let s = b.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches(s) {
                    return Err(error(Cause::Attachment));
                }
                s.reserve()?;
                let sequence = s
                    .binding
                    .site
                    .gate
                    .idle_checkpoint()
                    .map_err(|e| error(Cause::Gate(e)))?;
                if s.gate_base.checked_add(s.totals.physical) != Some(sequence) {
                    return Err(error(Cause::Invariant));
                }
                Ok((
                    s.binding.site.gate.clone(),
                    ReadableStack {
                        start: s.stack.start,
                        end: s.stack.end,
                    },
                    Checkpoint::new(s),
                ))
            })
            .unwrap_or(Err(error(Cause::Attachment)))?;
        let previous = self.finished.replace(None);
        let result = unsafe { gate.invoke(bytes.as_ptr(), bytes.len(), &extent) }
            .map_err(|e| error(Cause::Gate(e)));
        let result = result.and_then(|returned| {
            STATE
                .try_with(|cell| {
                    let mut b = cell
                        .try_borrow_mut()
                        .map_err(|_| error(Cause::Attachment))?;
                    let s = b.as_mut().ok_or(error(Cause::Attachment))?;
                    if !self.matches(s) {
                        return Err(error(Cause::Attachment));
                    }
                    s.empty()?;
                    s.binding.healthy()?;
                    let after = account(&before, s, returned)?;
                    s.totals = after;
                    self.finished
                        .set((previous == Some(before.totals)).then_some(after));
                    Ok(OptionalCallResult {
                        physical: after.physical,
                        gate_sequence: returned.sequence,
                        path: match returned.disposition {
                            Disposition::FastBypass => OptionalPath::FastBypass,
                            Disposition::Slow => OptionalPath::Slow {
                                ordinal: s.totals.observed.returns,
                            },
                        },
                        value: returned.value,
                        pre_call_rsp: returned.pre_rsp,
                        entry_rsp: returned.entry_rsp,
                        resumed_rsp: returned.resumed_rsp,
                        return_pc: returned.return_pc,
                    })
                })
                .unwrap_or(Err(error(Cause::Attachment)))
        });
        if let Err(e) = result {
            self.poison(e);
        }
        result
    }
    fn poison(&self, e: BridgeError) {
        let _ = STATE.try_with(|cell| {
            if let Ok(mut b) = cell.try_borrow_mut() {
                if let Some(s) = b.as_mut() {
                    if self.matches(s) {
                        s.fail(e);
                    }
                }
            }
        });
        let _ = POISONED.try_with(|p| p.set(true));
    }
    pub fn detach(&mut self) -> Result<OptionalTotals, BridgeError> {
        let totals = self.totals()?;
        STATE
            .try_with(|cell| {
                let mut b = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let s = b.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches(s) || self.finished.get() != Some(totals) {
                    return Err(error(Cause::Outstanding));
                }
                let n = s
                    .binding
                    .site
                    .gate
                    .idle_checkpoint()
                    .map_err(|e| error(Cause::Gate(e)))?;
                if s.gate_base.checked_add(totals.physical) != Some(n) {
                    return Err(error(Cause::Invariant));
                }
                b.take();
                self.active = false;
                Ok(totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
impl Drop for OptionalThread {
    fn drop(&mut self) {
        if self.active && self.detach().is_err() {
            self.poison(error(Cause::Outstanding));
        }
    }
}
struct Checkpoint {
    totals: OptionalTotals,
    next: u64,
    completed: u64,
    rows: timing::Rows,
    journal: [u64; 512],
    joins: [u64; EVENTS / 2],
    base: u64,
}
impl Checkpoint {
    fn new(s: &State) -> Self {
        Self {
            totals: s.totals,
            next: s.next,
            completed: s.model.completed_sequence(),
            rows: s.rows,
            journal: s.journal.page.0,
            joins: s.joins,
            base: s.gate_base,
        }
    }
}
fn account(b: &Checkpoint, s: &State, r: gate::Returned) -> Result<OptionalTotals, BridgeError> {
    let physical = b
        .totals
        .physical
        .checked_add(1)
        .ok_or(error(Cause::Capacity))?;
    if b.base != s.gate_base
        || b.base.checked_add(physical) != Some(r.sequence)
        || s.totals.physical != b.totals.physical
        || s.totals.bypassed != b.totals.bypassed
    {
        return Err(error(Cause::Invariant));
    }
    let bypassed = match r.disposition {
        Disposition::FastBypass => {
            if s.totals != b.totals
                || s.next != b.next
                || s.model.completed_sequence() != b.completed
                || s.rows != b.rows
                || s.journal.page.0 != b.journal
                || s.joins != b.joins
            {
                return Err(error(Cause::Invariant));
            }
            b.totals
                .bypassed
                .checked_add(1)
                .ok_or(error(Cause::Capacity))?
        }
        Disposition::Slow => {
            if b.totals.observed.entries.checked_add(1) != Some(s.totals.observed.entries)
                || b.totals.observed.returns.checked_add(1) != Some(s.totals.observed.returns)
                || b.next.checked_add(1) != Some(s.next)
            {
                return Err(error(Cause::Invariant));
            }
            let row = s.rows.one_after(&b.rows).ok_or(error(Cause::Invariant))?;
            let old_used = usize::try_from(b.journal[0]).map_err(|_| error(Cause::Invariant))?;
            if old_used % 2 != 0 || old_used > EVENTS - 2 {
                return Err(error(Cause::Invariant));
            }
            let at = 4 + old_used * 7;
            let entry = &s.journal.page.0[at..at + 7];
            let exit = &s.journal.page.0[at + 7..at + 14];
            let mut expected = b.journal;
            expected[0] = old_used as u64 + 2;
            expected[at..at + 14].copy_from_slice(&s.journal.page.0[at..at + 14]);
            let mut joins = b.joins;
            joins[old_used / 2] = r.sequence;
            let sampled = u64::from(matches!(row.owner, RawIntervalOwner::Sampled { .. }));
            if row.ordinal != s.totals.observed.returns
                || row.return_pc != r.return_pc
                || !drain::pair_matches(&row, entry, exit, s)
                || expected != s.journal.page.0
                || joins != s.joins
                || b.totals.observed.completed.checked_add(sampled)
                    != Some(s.totals.observed.completed)
                || b.totals.observed.unsampled.checked_add(1 - sampled)
                    != Some(s.totals.observed.unsampled)
            {
                return Err(error(Cause::Invariant));
            }
            b.totals.bypassed
        }
    };
    let after = OptionalTotals {
        physical,
        bypassed,
        observed: s.totals.observed,
    };
    if !balanced(after) || s.model.completed_sequence() != after.observed.completed {
        return Err(error(Cause::Invariant));
    }
    Ok(after)
}
fn balanced(t: OptionalTotals) -> bool {
    t.observed.entries == t.observed.returns
        && t.observed.completed.checked_add(t.observed.unsampled) == Some(t.observed.returns)
        && t.bypassed.checked_add(t.observed.returns) == Some(t.physical)
}
fn callback(
    c: &HookContext,
    id: ControlIdentity<'_>,
    entry: bool,
    stamp: RawTimestamp,
) -> Result<(), BridgeError> {
    STATE
        .try_with(|cell| {
            if POISONED.get() {
                return Err(error(Cause::Attachment));
            }
            let mut b = cell
                .try_borrow_mut()
                .map_err(|_| error(Cause::Attachment))?;
            let s = b.as_mut().ok_or(error(Cause::Attachment))?;
            let result = (|| {
                let word = s.identity(c, id, entry)?;
                let gate = s.binding.site.gate.clone();
                if entry {
                    let token = gate.enter(c).map_err(|e| error(Cause::Gate(e)))?;
                    s.enter(c.instruction_pointer, c.stack_pointer, word, stamp, token)
                } else {
                    let p = s.pair.as_ref().ok_or(error(Cause::Return))?;
                    let token = gate
                        .validate_ret(&p.token, c)
                        .map_err(|e| error(Cause::Gate(e)))?;
                    s.finish(c.instruction_pointer, c.stack_pointer, word, stamp, token)
                }
            })();
            if let Err(e) = result {
                s.fail(e);
            }
            result
        })
        .unwrap_or(Err(error(Cause::Attachment)))
}
unsafe extern "C" fn entry_callback(c: *mut HookContext, id: ControlIdentity<'_>) {
    let stamp = unsafe { timing::read() };
    if c.is_null() {
        super::fatal();
    }
    if callback(unsafe { &*c }, id, true, stamp).is_err() {
        super::fatal();
    }
}
unsafe extern "C" fn exit_callback(c: *mut HookContext, id: ControlIdentity<'_>) {
    let stamp = unsafe { timing::read() };
    if c.is_null() {
        super::fatal();
    }
    if callback(unsafe { &*c }, id, false, stamp).is_err() {
        super::fatal();
    }
}
#[cfg(test)]
mod tests;
