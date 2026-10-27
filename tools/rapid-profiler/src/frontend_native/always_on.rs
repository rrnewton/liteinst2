//! Always-on fixed-grammar callbacks. The old point and native adapters are separate.
//! This facade owns metadata only; site::seal retains the actual publication.
pub(super) mod site;

use crate::frontend::{
    BindingChange, ControlError, ControllerSnapshot, ControllerStatus, EpochHandle, FailurePoint,
    FunctionSpec, GroupSpec, IntervalEntry, IntervalEntryError, IntervalEntrySummary,
    IntervalExitError, Limits, ModelReturnSlot, Observation, Report, Session, SetupError,
    ThreadModel, UnsampledSummary,
};
use crate::generation::{Config, FunctionId, GenerationId};
use liteinst2::controls::ControlIdentity;
use liteinst2::trampoline::HookContext;
use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::thread::{self, ThreadId};

const PAIRS: usize = 4;
const EVENTS: usize = 64;
const TOKEN: u64 = 0x71a1_5eaf_1188_2244;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cause {
    Setup(SetupError),
    Control(ControlError),
    Entry(IntervalEntryError),
    Exit(IntervalExitError),
    Process,
    Epoch,
    Attachment,
    Identity,
    Capacity,
    Return,
    Invariant,
    Outstanding,
}
/// Opaque typed failure. Debug retains the exact original model error; no
/// FunctionClosed/NoCurrent fallback converts an unrelated error into a sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeError {
    cause: Cause,
}
fn error(cause: Cause) -> BridgeError {
    BridgeError { cause }
}

struct Binding {
    session: Session,
    site: Arc<site::Site>,
    key: Arc<()>,
    pid: u32,
    install: u64,
    function: FunctionId,
    limits: Limits,
}
impl Binding {
    fn process(&self) -> Result<(), BridgeError> {
        if self.pid == std::process::id() {
            Ok(())
        } else {
            Err(error(Cause::Process))
        }
    }
}
/// Non-extractable identity of one retained staged owner. Not Clone.
pub struct IntervalEpoch {
    key: Arc<()>,
    index: usize,
    generation: GenerationId,
}
impl IntervalEpoch {
    /// Immutable diagnostic identity, never an owner or admission token.
    pub fn generation(&self) -> GenerationId {
        self.generation
    }
}
/// Pristine metadata preparation. No client, PID, registration, publication or
/// receipt exists before activation. Only completed allocations may cross fork.
pub struct PreparedIntervalController {
    session: Session,
    site: Arc<site::Site>,
    key: Arc<()>,
    install: u64,
    function: FunctionId,
    limits: Limits,
    epochs: Vec<EpochHandle>,
    _exclusive: PhantomData<Cell<()>>,
}
fn staged(
    session: &Session,
    key: &Arc<()>,
    epochs: &mut Vec<EpochHandle>,
    limits: Limits,
    config: Config,
) -> Result<IntervalEpoch, BridgeError> {
    if epochs.len() == limits.epochs {
        return Err(error(Cause::Capacity));
    }
    let owner = session.stage(config).map_err(|e| error(Cause::Setup(e)))?;
    let token = IntervalEpoch {
        key: Arc::clone(key),
        index: epochs.len(),
        generation: owner.generation(),
    };
    epochs.push(owner); // Exact capacity was reserved before any publication.
    Ok(token)
}
impl PreparedIntervalController {
    /// Consume a sealed process-lived installation; one mandatory model group
    /// never disables physical entry or RET processing.
    pub fn new(
        site: site::InstalledIntervalSite,
        install: u64,
        function: FunctionId,
        limits: Limits,
    ) -> Result<Self, BridgeError> {
        let session = Session::new(
            install,
            &[FunctionSpec { function, group: 0 }],
            &[GroupSpec { mandatory: true }],
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
            key: Arc::new(()),
            install,
            function,
            limits,
            epochs,
            _exclusive: PhantomData,
        })
    }
    /// Allocate and retain one bounded staged epoch without publishing it.
    pub fn stage(&mut self, config: Config) -> Result<IntervalEpoch, BridgeError> {
        staged(
            &self.session,
            &self.key,
            &mut self.epochs,
            self.limits,
            config,
        )
    }
    /// Consume pristine preparation into one actual-process binding.
    ///
    /// # Safety
    /// Either no fork occurred, or the caller forked from a certified single-thread
    /// parent with no acquired lock, client/TLS registration, callback, outstanding
    /// ticket or publication. Only these pristine allocations may be inherited;
    /// the parent's copy must not be activated/reused. Installation and managed
    /// controls are process-private snapshots. Active controllers cannot be rebound.
    pub unsafe fn activate(self) -> Result<(IntervalController, IntervalClient), BridgeError> {
        STATE
            .try_with(|cell| {
                if POISONED.get()
                    || cell
                        .try_borrow()
                        .map_err(|_| error(Cause::Attachment))?
                        .is_some()
                {
                    return Err(error(Cause::Attachment));
                }
                Ok(())
            })
            .unwrap_or(Err(error(Cause::Attachment)))?;
        let snapshot = self
            .session
            .snapshot()
            .map_err(|e| error(Cause::Control(e)))?;
        if snapshot.status != ControllerStatus::Ready
            || snapshot.current.is_some()
            || !snapshot.actions.is_empty()
            || snapshot.retained_failed_generation.is_some()
            || snapshot.enabled != [false]
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
        });
        let client = IntervalClient {
            binding: Arc::clone(&binding),
        };
        Ok((
            IntervalController {
                binding,
                epochs: self.epochs,
                _exclusive: PhantomData,
            },
            client,
        ))
    }
}
/// One non-Clone controller, Send but not Sync. No Session or EpochHandle escapes.
pub struct IntervalController {
    binding: Arc<Binding>,
    epochs: Vec<EpochHandle>,
    _exclusive: PhantomData<Cell<()>>,
}
impl IntervalController {
    fn owner(&self, epoch: &IntervalEpoch) -> Result<&EpochHandle, BridgeError> {
        self.binding.process()?;
        let owner = self.epochs.get(epoch.index).ok_or(error(Cause::Epoch))?;
        if !Arc::ptr_eq(&epoch.key, &self.binding.key) || owner.generation() != epoch.generation {
            return Err(error(Cause::Epoch));
        }
        Ok(owner)
    }
    /// Stage without recycling a lifetime slot or dropping an old owner.
    pub fn stage(&mut self, config: Config) -> Result<IntervalEpoch, BridgeError> {
        self.binding.process()?;
        staged(
            &self.binding.session,
            &self.binding.key,
            &mut self.epochs,
            self.binding.limits,
            config,
        )
    }
    /// Exact existing metadata publication; physical bookkeeping stays enabled.
    pub fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        let owner = self.owner(epoch)?;
        self.binding
            .session
            .publish(owner, FailurePoint::None)
            .map_err(|e| error(Cause::Control(e)))
    }
    /// Remove only the specified current epoch, preserving its old reservations.
    pub fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        let generation = self.owner(epoch)?.generation();
        self.binding
            .session
            .remove_with_controls(Some(generation), |_| {})
            .map_err(|e| error(Cause::Control(e)))
    }
    /// Final metadata report, without equating report availability with native drain.
    pub fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        Ok(self.owner(epoch)?.try_report())
    }
    /// Bounded immutable copy of the complete existing action history.
    pub fn history(&self) -> Result<ControllerSnapshot, BridgeError> {
        self.binding.process()?;
        self.binding
            .session
            .snapshot()
            .map_err(|e| error(Cause::Control(e)))
    }
}
impl Drop for IntervalController {
    fn drop(&mut self) {
        // Closing is not a fabricated Removed row or a native/code drain.
        // A forked active copy owns private metadata but has no rebinding API.
        for epoch in &self.epochs {
            epoch.close();
        }
    }
}
/// Cloneable attachment authority only; it has no controller methods.
#[derive(Clone)]
pub struct IntervalClient {
    binding: Arc<Binding>,
}

/// Explicit caller-owned readable stack extent, not mapping discovery.
pub struct ReadableStack {
    start: u64,
    end: u64,
}
impl ReadableStack {
    /// # Safety
    /// Every byte remains mapped and readable through the last admitted RET;
    /// no signal/nonlocal exit, foreign unwind or concurrent unmap may violate it.
    pub unsafe fn new(start: u64, end: u64) -> Result<Self, BridgeError> {
        if start == 0 || start.checked_add(8).is_none_or(|n| n > end) {
            return Err(error(Cause::Identity));
        }
        Ok(Self { start, end })
    }
}
#[repr(C, align(4096))]
struct Page([u64; 512]);
/// Unique full 4096-byte journal, allocated before callbacks and retained for
/// process lifetime. The only public address is for the caller's owned tracer.
pub struct IntervalJournal {
    page: &'static mut Page,
    _local: PhantomData<Rc<()>>,
}
impl IntervalJournal {
    /// Allocate a separately aligned zero page. No callback allocation occurs.
    pub fn allocate() -> Self {
        Self {
            page: Box::leak(Box::new(Page([0; 512]))),
            _local: PhantomData,
        }
    }
    /// Read-only diagnostic coordinate; no writable reference is exposed.
    pub fn address(&self) -> u64 {
        std::ptr::from_ref(&*self.page) as usize as u64
    }
    fn used(&self) -> usize {
        // SAFETY: unique retained page; only its attached thread writes.
        unsafe { self.page.0.as_ptr().read_volatile() as usize }
    }
    fn word(&mut self, index: usize, value: u64) {
        // SAFETY: callers use fixed header offsets; no user index reaches this seam.
        unsafe { self.page.0.as_mut_ptr().add(index).write_volatile(value) };
    }
    fn header(&mut self, tid: u64, depth: usize) {
        self.word(2, tid);
        self.word(3, depth as u64);
    }
    fn row(&mut self, row: [u64; 7]) {
        let n = self.used();
        // SAFETY: complete fixed row capacity was preflighted before the model mutation.
        unsafe {
            self.page
                .0
                .as_mut_ptr()
                .add(4 + n * 7)
                .cast::<[u64; 7]>()
                .write_volatile(row)
        };
        self.word(0, (n + 1) as u64);
    }
    fn poison(&mut self) {
        self.word(1, 1);
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Counts of committed pairs and actual original-owner finishes.
pub struct PairTotals {
    /// Committed admitted plus unsampled entries.
    pub entries: u64,
    /// Exact matching RET completions, never cancellations.
    pub returns: u64,
    /// Admitted model completions.
    pub completed: u64,
    /// Exact initial/removed/closed-function unsampled pair completions.
    pub unsampled: u64,
}
struct Pair {
    key: Arc<()>,
    install: u64,
    function: FunctionId,
    registration: u64,
    ordinal: u64,
    rsp: u64,
    return_word: u64,
    slot: ModelReturnSlot,
    receipt: IntervalEntry,
    summary: Option<IntervalEntrySummary>,
}
struct State {
    binding: Arc<Binding>,
    actual_thread: ThreadId,
    tid: u64,
    registration: u64,
    stack: ReadableStack,
    model: ThreadModel,
    pairs: [Option<Pair>; PAIRS],
    depth: usize,
    next: u64,
    totals: PairTotals,
    journal: IntervalJournal,
    failure: Option<BridgeError>,
}
thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static POISONED: Cell<bool> = const { Cell::new(false) };
}
/// Non-Clone actual-thread token; failure retains TLS ownership, not return credit.
pub struct IntervalThread {
    key: Arc<()>,
    pid: u32,
    thread: ThreadId,
    tid: u64,
    registration: u64,
    active: bool,
    _local: PhantomData<Rc<()>>,
}
fn tid() -> u64 {
    // SAFETY: kernel read-only identity query.
    unsafe { libc::syscall(libc::SYS_gettid) as u64 }
}
impl IntervalClient {
    /// Attach only after the complete site publication and caller stack admission.
    ///
    /// # Safety
    /// The installed fixed grammar, caller-certified single-thread/signal and
    /// readable-stack contract holds until an empty explicit detach. A real
    /// original invoke CALL must supply the sealed terminal return word.
    pub unsafe fn attach(
        &self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<IntervalThread, BridgeError> {
        self.binding.process()?;
        if registration == 0 || journal.used() != 0 || journal.page.0.iter().any(|&x| x != 0) {
            return Err(error(Cause::Attachment));
        }
        STATE
            .try_with(|cell| {
                if POISONED.get() {
                    return Err(error(Cause::Attachment));
                }
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                if storage.is_some() {
                    return Err(error(Cause::Attachment));
                }
                // All TLS/native checks precede this never-recycled registration.
                let model = self
                    .binding
                    .session
                    .register_thread(registration)
                    .map_err(|e| error(Cause::Setup(e)))?;
                let actual_thread = thread::current().id();
                let tid = tid();
                let mut state = State {
                    binding: Arc::clone(&self.binding),
                    actual_thread,
                    tid,
                    registration,
                    stack,
                    model,
                    pairs: std::array::from_fn(|_| None),
                    depth: 0,
                    next: 1,
                    totals: PairTotals::default(),
                    journal,
                    failure: None,
                };
                state.journal.header(tid, 0);
                *storage = Some(state);
                Ok(IntervalThread {
                    key: Arc::clone(&self.binding.key),
                    pid: self.binding.pid,
                    thread: actual_thread,
                    tid,
                    registration,
                    active: true,
                    _local: PhantomData,
                })
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
impl IntervalThread {
    fn matches(&self, state: &State) -> bool {
        self.active
            && self.pid == std::process::id()
            && self.thread == thread::current().id()
            && self.tid == tid()
            && self.registration == state.registration
            && Arc::ptr_eq(&self.key, &state.binding.key)
            && state.tid == self.tid
            && state.actual_thread == self.thread
    }
    /// Return exact totals only for an empty unpoisoned pair/model state.
    pub fn totals(&self) -> Result<PairTotals, BridgeError> {
        STATE
            .try_with(|cell| {
                let storage = cell.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let state = storage.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) {
                    return Err(error(Cause::Attachment));
                }
                if POISONED.get()
                    || state.failure.is_some()
                    || state.depth != 0
                    || state.model.depth() != 0
                {
                    return Err(error(Cause::Outstanding));
                }
                Ok(state.totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    /// Failure leaves this handle and all TLS owners intact; only empty success removes them.
    pub fn detach(&mut self) -> Result<PairTotals, BridgeError> {
        let totals = self.totals()?;
        STATE
            .try_with(|cell| {
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                if !storage.as_ref().is_some_and(|s| self.matches(s)) {
                    return Err(error(Cause::Attachment));
                }
                storage.take();
                self.active = false;
                Ok(totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
impl Drop for IntervalThread {
    fn drop(&mut self) {
        if self.active && self.detach().is_err() {
            let _ = POISONED.try_with(|p| p.set(true));
            let _ = STATE.try_with(|cell| {
                if let Ok(mut storage) = cell.try_borrow_mut() {
                    if let Some(s) = storage.as_mut() {
                        s.fail(error(Cause::Outstanding));
                    }
                }
            });
        }
    }
}
fn packed(
    summary: IntervalEntrySummary,
    function: FunctionId,
) -> Result<(u64, u64, u64), BridgeError> {
    let (kind, generation, inv1, prefix, reason, binding) = match summary {
        IntervalEntrySummary::Admitted {
            generation,
            invocation,
            history_len,
            binding,
        } => (
            1,
            generation.get(),
            invocation.checked_add(1).ok_or(error(Cause::Capacity))?,
            history_len,
            0,
            binding,
        ),
        IntervalEntrySummary::Unsampled {
            reason,
            history_len,
            binding,
        } => {
            let (generation, code) = match reason {
                UnsampledSummary::InitialDisarmed => (0, 1),
                UnsampledSummary::Removed { generation } => (generation.get(), 2),
                UnsampledSummary::FunctionClosed {
                    generation,
                    function: actual,
                } if actual == function => (generation.get(), 3),
                _ => return Err(error(Cause::Invariant)),
            };
            (3, generation, 0, history_len, code, binding)
        }
    };
    if prefix > 256 || inv1 > 4096 || (kind == 1 && inv1 == 0) {
        return Err(error(Cause::Capacity));
    }
    let binding_matches = match binding {
        BindingChange::Initial => generation == 0 && reason == 1,
        BindingChange::Published {
            action_index,
            generation: owner,
        } => action_index < prefix && owner.get() == generation && (reason == 0 || reason == 3),
        BindingChange::Removed {
            action_index,
            generation: owner,
        } => action_index < prefix && owner.get() == generation && reason == 2,
    };
    if !binding_matches {
        return Err(error(Cause::Invariant));
    }
    let value = (inv1 as u64) | ((prefix as u64) << 13) | (reason << 22);
    Ok((kind, generation, value))
}
impl State {
    fn fail(&mut self, failure: BridgeError) {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
        self.journal.poison();
    }
    fn identity(
        &self,
        context: &HookContext,
        control: ControlIdentity<'_>,
        entry: bool,
    ) -> Result<u64, BridgeError> {
        self.binding.process()?;
        if self.actual_thread != thread::current().id()
            || self.tid != tid()
            || context.stack_pointer < self.stack.start
            || context
                .stack_pointer
                .checked_add(8)
                .is_none_or(|n| n > self.stack.end)
            || !self
                .binding
                .site
                .matches(context.instruction_pointer, control, entry)
        {
            return Err(error(Cause::Identity));
        }
        // SAFETY: exact readable extent supplied by unsafe attach; no return repair.
        let word = unsafe { (context.stack_pointer as usize as *const u64).read_unaligned() };
        if word != self.binding.site.terminal {
            return Err(error(Cause::Return));
        }
        Ok(word)
    }
    fn enter(&mut self, pc: u64, rsp: u64, return_word: u64) -> Result<(), BridgeError> {
        if self.failure.is_some() {
            return Err(error(Cause::Attachment));
        }
        let depth = self.depth;
        if depth >= PAIRS.min(self.model.interval_depth_limit())
            || self.pairs[depth].is_some()
            || self
                .journal
                .used()
                .checked_add(depth)
                .and_then(|n| n.checked_add(2))
                .is_none_or(|n| n > EVENTS)
        {
            return Err(error(Cause::Capacity));
        }
        let next = self.next.checked_add(1).ok_or(error(Cause::Capacity))?;
        let entries = self
            .totals
            .entries
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        let mut slot = ModelReturnSlot {
            identity: self.next,
            word: TOKEN,
        };
        let receipt = self
            .model
            .enter_interval(
                self.binding.install,
                self.binding.function,
                self.next,
                &mut slot,
            )
            .map_err(|e| error(Cause::Entry(e)))?;
        // Retain before any postcondition; even impossible failure cannot lose an admission.
        self.pairs[depth] = Some(Pair {
            key: Arc::clone(&self.binding.key),
            install: self.binding.install,
            function: self.binding.function,
            registration: self.registration,
            ordinal: self.next,
            rsp,
            return_word,
            slot,
            receipt,
            summary: None,
        });
        self.depth += 1;
        let pair = self.pairs[depth].as_mut().ok_or(error(Cause::Invariant))?;
        let summary = pair.receipt.summary().ok_or(error(Cause::Invariant))?;
        pair.summary = Some(summary);
        let (kind, generation, bits) = packed(summary, self.binding.function)?;
        self.journal
            .row([kind, pair.ordinal, pc, rsp, return_word, generation, bits]);
        self.next = next;
        self.totals.entries = entries;
        self.journal.header(self.tid, self.depth);
        Ok(())
    }
    fn finish(&mut self, pc: u64, rsp: u64, return_word: u64) -> Result<(), BridgeError> {
        if self.failure.is_some() {
            return Err(error(Cause::Attachment));
        }
        let index = self.depth.checked_sub(1).ok_or(error(Cause::Return))?;
        let pair = self.pairs[index].as_mut().ok_or(error(Cause::Return))?;
        if pair.rsp != rsp
            || pair.return_word != return_word
            || !Arc::ptr_eq(&pair.key, &self.binding.key)
            || pair.install != self.binding.install
            || pair.function != self.binding.function
            || pair.registration != self.registration
            || pair.slot.identity != pair.ordinal
        {
            return Err(error(Cause::Return));
        }
        let summary = pair.summary.ok_or(error(Cause::Invariant))?;
        let (kind, generation, bits) = packed(summary, self.binding.function)?;
        if self.journal.used() >= EVENTS {
            return Err(error(Cause::Capacity));
        }
        let returns = self
            .totals
            .returns
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        let completed = self
            .totals
            .completed
            .checked_add(u64::from(kind == 1))
            .ok_or(error(Cause::Capacity))?;
        let unsampled = self
            .totals
            .unsampled
            .checked_add(u64::from(kind == 3))
            .ok_or(error(Cause::Capacity))?;
        let result = self
            .model
            .finish_interval(
                &mut pair.receipt,
                &mut pair.slot,
                Observation::Value(pair.ordinal),
            )
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
        self.journal.row([
            kind + 1,
            pair.ordinal,
            pc,
            rsp,
            return_word,
            generation,
            bits,
        ]);
        self.pairs[index] = None;
        self.depth = index;
        self.totals.returns = returns;
        self.totals.completed = completed;
        self.totals.unsampled = unsampled;
        self.journal.header(self.tid, self.depth);
        Ok(())
    }
}
fn callback(
    context: &HookContext,
    control: ControlIdentity<'_>,
    entry: bool,
) -> Result<(), BridgeError> {
    STATE
        .try_with(|cell| {
            if POISONED.get() {
                return Err(error(Cause::Attachment));
            }
            let mut storage = cell
                .try_borrow_mut()
                .map_err(|_| error(Cause::Attachment))?;
            let state = storage.as_mut().ok_or(error(Cause::Attachment))?;
            let result = state.identity(context, control, entry).and_then(|word| {
                if entry {
                    state.enter(context.instruction_pointer, context.stack_pointer, word)
                } else {
                    state.finish(context.instruction_pointer, context.stack_pointer, word)
                }
            });
            if let Err(e) = result {
                state.fail(e);
            }
            result
        })
        .unwrap_or(Err(error(Cause::Attachment)))
}
fn fatal() -> ! {
    let _ = POISONED.try_with(|p| p.set(true));
    // SAFETY: isolated native contract violation; never unwind through C or claim completion.
    unsafe { libc::_exit(123) }
}
unsafe extern "C" fn entry_callback(context: *mut HookContext, control: ControlIdentity<'_>) {
    if context.is_null() {
        fatal();
    }
    // SAFETY: invoked only by the sealed managed dispatch with its live saved frame.
    if callback(unsafe { &*context }, control, true).is_err() {
        fatal();
    }
}
unsafe extern "C" fn exit_callback(context: *mut HookContext, control: ControlIdentity<'_>) {
    if context.is_null() {
        fatal();
    }
    // SAFETY: same sealed dispatcher, at one original RET.
    if callback(unsafe { &*context }, control, false).is_err() {
        fatal();
    }
}

#[cfg(test)]
mod tests;
