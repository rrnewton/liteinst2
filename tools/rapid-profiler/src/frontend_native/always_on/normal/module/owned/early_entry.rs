//! Separate optional entry admission, with mandatory authenticated pre-RETs.
//! Sparse intervals never stand in for the four physical application calls.
use super::*;
use crate::frontend_native::always_on::site::ordinary::InstalledEarlyEntryModuleSite;
use liteinst2::controls::ControlWriter;
use std::sync::atomic::AtomicBool;
mod controller;
#[cfg(any(test, feature = "frontend-native-qualification"))]
pub mod qualification;
use controller::EarlyOutput;
pub use controller::{
    EarlyEntryModuleSessionController, PreparedEarlyEntryModuleSessionController,
};

struct Shared {
    binding: Arc<Binding>,
    failed: AtomicBool,
}
impl Shared {
    fn check(&self) -> Result<(), BridgeError> {
        self.binding.process()?;
        if self.failed.load(Ordering::Acquire) || !early_binding(&self.binding) {
            return Err(error(Cause::Identity));
        }
        Ok(())
    }
}
pub(in crate::frontend_native::always_on) fn profile_matches(
    profile: &BindingProfile,
    limits: Limits,
    config: Config,
) -> bool {
    matches!(profile, BindingProfile::Module { site, functions } if site.is_early_entry() && functions[0] != functions[1])
        && super::super::session::fixed(config.retained_per_function) == Some((limits, config))
}
pub(in crate::frontend_native::always_on) fn early_binding(binding: &Binding) -> bool {
    let k = match binding.limits.records_per_epoch {
        20 => 10,
        2000 => 1000,
        _ => return false,
    };
    let Some((_, config)) = super::super::session::fixed(k) else {
        return false;
    };
    profile_matches(&binding.profile, binding.limits, config)
        && matches!(binding.entry_mode, EntryMode::Concurrent)
        && binding.session.history_mode() == HistoryMode::Absolute
}

/// Sole owned-attachment capability; no conversion to any old normal client.
pub struct EarlyEntryModuleClient {
    shared: Arc<Shared>,
}
/// One physical caller position, including bypasses with no interval ordinal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyEntryModulePhysicalRow {
    pub batch: u64,
    pub position: usize,
    pub function: FunctionId,
    pub observed_ordinal: Option<u64>,
    pub return_pc: u64,
    pub entry_rsp: u64,
    pub return_word: u64,
}
/// Sparse observed-only transfer. It cannot be converted to an old four-entry
/// owned result; ordinals count callbacks, not physical caller positions.
#[derive(Debug)]
pub struct EarlyEntryModuleObservations(NormalModuleBatch);
impl EarlyEntryModuleObservations {
    pub fn records(&self) -> &[NormalModuleRecord] {
        self.0.records()
    }
    pub fn totals(&self) -> (NormalTotals, NormalTotals) {
        self.0.totals()
    }
    pub fn journal(&self) -> &[u64] {
        self.0.journal()
    }
    pub fn history_stream(&self) -> Option<&NormalModuleHistoryStream> {
        self.0.history_stream()
    }
    pub fn history_high_water(&self) -> Option<u64> {
        self.0.history_high_water()
    }
    pub fn next_ordinal(&self) -> u64 {
        self.0.next_ordinal()
    }
}
#[derive(Debug)]
pub struct OwnedEarlyEntryModuleResult {
    pub batch: u64,
    pub completed_calls: u64,
    pub sum: u64,
    pub values: [u64; 4],
    pub physical: [EarlyEntryModulePhysicalRow; 4],
    pub observations: Option<EarlyEntryModuleObservations>,
}
/// Same-thread exclusive caller owner. Drop never acknowledges return or drain.
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::OwnedEarlyEntryModuleThread;
/// fn send<T: Send>() {} send::<OwnedEarlyEntryModuleThread>();
/// ```
pub struct OwnedEarlyEntryModuleThread {
    inner: OwnedNormalModuleThread,
    shared: Arc<Shared>,
}

struct PhysicalBatch {
    number: u64,
    before: Baseline,
    position: usize,
    rsp: Option<u64>,
    seen: [Option<u64>; 4],
    rows: [Option<EarlyEntryModulePhysicalRow>; 4],
    pending_position: Option<usize>,
}
struct Visit {
    selected: SelectedFunction,
    pc: u64,
    rsp: u64,
    word: u64,
    stamp: RawTimestamp,
    entry: bool,
}
struct PhysicalState {
    shared: Arc<Shared>,
    order: [SelectedFunction; 2],
    words: [u64; 4],
    batches: u64,
    calls: u64,
    active: Option<PhysicalBatch>,
}
thread_local! { static PHYSICAL: RefCell<Option<PhysicalState>> = const { RefCell::new(None) }; }

impl PhysicalState {
    fn matches(&self, state: &NormalState) -> Result<(), BridgeError> {
        self.shared.check()?;
        if !Arc::ptr_eq(&self.shared.binding, &state.binding)
            || state.call_pair.is_some()
            || state.accuracy.is_some()
        {
            return Err(error(Cause::Identity));
        }
        Ok(())
    }
    fn begin(&mut self, state: &NormalState) -> Result<(), BridgeError> {
        self.matches(state)?;
        if self.active.is_some()
            || self.calls != self.batches.checked_mul(4).ok_or(error(Cause::Capacity))?
        {
            return Err(error(Cause::Outstanding));
        }
        let before = before_batch(state)?;
        let number = self.batches.checked_add(1).ok_or(error(Cause::Capacity))?;
        self.calls.checked_add(4).ok_or(error(Cause::Capacity))?;
        self.active = Some(PhysicalBatch {
            number,
            before,
            position: 0,
            rsp: None,
            seen: [None; 4],
            rows: [None; 4],
            pending_position: None,
        });
        Ok(())
    }
    fn shape(&self, state: &NormalState) -> Result<(), BridgeError> {
        self.matches(state)?;
        state.shape()?;
        let b = self.active.as_ref().ok_or(error(Cause::Outstanding))?;
        if b.number != self.batches.checked_add(1).ok_or(error(Cause::Capacity))?
            || b.position > 4
            || state.cursor != b.before.cursor
            || b.rows[..b.position].iter().any(Option::is_none)
            || b.rows[b.position..].iter().any(Option::is_some)
            || b.seen[b.position.saturating_add(1).min(4)..]
                .iter()
                .any(Option::is_some)
            || state
                .totals
                .entered
                .checked_sub(b.before.cursor.totals.entered)
                != Some(b.seen.iter().flatten().count() as u64)
            || state
                .totals
                .ret_observed
                .checked_sub(b.before.cursor.totals.ret_observed)
                != Some(
                    b.rows
                        .iter()
                        .flatten()
                        .filter(|r| r.observed_ordinal.is_some())
                        .count() as u64,
                )
        {
            return Err(error(Cause::Invariant));
        }
        let mut ordinal = b.before.next;
        let mut confirmed = 0;
        for index in 0..4 {
            if let Some(n) = b.seen[index] {
                if n != ordinal {
                    return Err(error(Cause::Invariant));
                }
                ordinal = ordinal.checked_add(1).ok_or(error(Cause::Capacity))?;
            }
            if let Some(row) = b.rows[index] {
                if row.batch != b.number
                    || row.position != index
                    || row.function != self.order[index % 2].function
                    || row.observed_ordinal != b.seen[index]
                    || row.return_word != self.words[index]
                    || Some(row.entry_rsp) != b.rsp
                {
                    return Err(error(Cause::Invariant));
                }
                let BindingProfile::Module { site, .. } = &state.binding.profile else {
                    return Err(error(Cause::Identity));
                };
                state.selected_geometry(
                    self.order[index % 2],
                    site.functions()[self.order[index % 2].index].entry(),
                    Some(row.return_pc),
                )?;
                if row.observed_ordinal.is_some() && b.pending_position != Some(index) {
                    let r = state
                        .records
                        .get(confirmed)
                        .and_then(|r| *r)
                        .ok_or(error(Cause::Invariant))?;
                    if state.functions[confirmed] != Some(self.order[index % 2])
                        || Some(r.raw.ordinal) != row.observed_ordinal
                        || r.raw.return_pc != row.return_pc
                        || r.entry_rsp != row.entry_rsp
                        || r.return_word != row.return_word
                    {
                        return Err(error(Cause::Invariant));
                    }
                    confirmed += 1;
                }
            }
        }
        if state.next != ordinal || state.len != confirmed {
            return Err(error(Cause::Invariant));
        }
        match (b.pending_position, &state.pending) {
            (None, None) if b.position == 4 || b.seen[b.position].is_none() => {}
            (Some(index), Some(p)) if index < 4 => {
                if b.seen[index] != Some(p.ordinal)
                    || p.selected != self.order[index % 2]
                    || p.word != self.words[index]
                    || Some(p.rsp) != b.rsp
                    || (p.returned.is_some() && (index >= b.position || b.rows[index].is_none()))
                    || (p.returned.is_none() && (index != b.position || b.rows[index].is_some()))
                    || (b.position < 4 && index != b.position && b.seen[b.position].is_some())
                {
                    return Err(error(Cause::Return));
                }
            }
            _ => return Err(error(Cause::Return)),
        }
        Ok(())
    }
    fn visit(&mut self, state: &mut NormalState, visit: Visit) -> Result<(), BridgeError> {
        let Visit {
            selected,
            pc,
            rsp,
            word,
            stamp,
            entry,
        } = visit;
        self.shape(state)?;
        let b = self.active.as_mut().ok_or(error(Cause::Outstanding))?;
        let index = b.position;
        if index >= 4
            || selected != self.order[index % 2]
            || word != self.words[index]
            || b.rsp.is_some_and(|prior| prior != rsp)
        {
            return Err(error(Cause::Return));
        }
        if entry {
            if b.seen[index].is_some()
                || state.pending.as_ref().is_some_and(|p| p.returned.is_none())
            {
                return Err(error(Cause::Return));
            }
            let ordinal = state.next;
            state.enter_function(selected, pc, rsp, word, stamp)?;
            b.rsp = Some(rsp);
            b.seen[index] = Some(ordinal);
            b.pending_position = Some(index);
        } else {
            let BindingProfile::Module { site, .. } = &state.binding.profile else {
                return Err(error(Cause::Identity));
            };
            state.selected_geometry(
                selected,
                site.functions()[selected.index].entry(),
                Some(pc),
            )?;
            if let Some(ordinal) = b.seen[index] {
                if b.pending_position != Some(index)
                    || state
                        .pending
                        .as_ref()
                        .is_none_or(|p| p.ordinal != ordinal || p.returned.is_some())
                {
                    return Err(error(Cause::Return));
                }
                state.observe_function(selected, pc, rsp, word, stamp)?;
            } else if state.pending.as_ref().is_some_and(|p| p.returned.is_none()) {
                return Err(error(Cause::Return));
            }
            b.rsp = Some(rsp);
            b.rows[index] = Some(EarlyEntryModulePhysicalRow {
                batch: b.number,
                position: index,
                function: selected.function,
                observed_ordinal: b.seen[index],
                return_pc: pc,
                entry_rsp: rsp,
                return_word: word,
            });
            b.position += 1;
        }
        self.shape(state)
    }
    fn returned(
        &self,
        state: &NormalState,
    ) -> Result<[EarlyEntryModulePhysicalRow; 4], BridgeError> {
        self.shape(state)?;
        let b = self.active.as_ref().ok_or(error(Cause::Outstanding))?;
        if b.position != 4
            || state.pending.as_ref().is_some_and(|p| p.returned.is_none())
            || state.transfer_check()?.1 != b.seen.iter().flatten().count()
        {
            return Err(error(Cause::Return));
        }
        Ok(b.rows.map(|row| row.expect("checked four physical rows")))
    }
    fn complete(
        &mut self,
        state: &NormalState,
        rows: [EarlyEntryModulePhysicalRow; 4],
        observations: Option<&NormalModuleBatch>,
    ) -> Result<(u64, u64), BridgeError> {
        self.matches(state)?;
        drained(state)?;
        let b = self.active.as_ref().ok_or(error(Cause::Outstanding))?;
        let count = b.seen.iter().flatten().count();
        if b.position != 4
            || b.rows != rows.map(Some)
            || observations.is_some() != (count != 0)
            || observations.map_or(0, |o| o.records.len()) != count
            || state
                .totals
                .entered
                .checked_sub(b.before.cursor.totals.entered)
                != Some(count as u64)
            || state
                .totals
                .confirmed
                .checked_sub(b.before.cursor.totals.confirmed)
                != Some(count as u64)
            || (count == 0 && state.cursor != b.before.cursor)
        {
            return Err(error(Cause::Return));
        }
        if let Some(batch) = observations {
            if batch.before != b.before.cursor
                || batch.after != state.cursor
                || batch.next != state.next
            {
                return Err(error(Cause::Invariant));
            }
            for (index, (record, row)) in batch
                .records
                .iter()
                .zip(rows.iter().filter(|r| r.observed_ordinal.is_some()))
                .enumerate()
            {
                let ordinal = row.observed_ordinal.ok_or(error(Cause::Invariant))?;
                let ack = if index + 1 == count {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: ordinal.checked_add(1).ok_or(error(Cause::Capacity))?,
                    }
                };
                if record.function != row.function
                    || record.record.raw.ordinal != ordinal
                    || record.record.raw.return_pc != row.return_pc
                    || record.record.entry_rsp != row.entry_rsp
                    || record.record.return_word != row.return_word
                    || record.record.acknowledgement != ack
                {
                    return Err(error(Cause::Return));
                }
            }
        }
        let calls = self.calls.checked_add(4).ok_or(error(Cause::Capacity))?;
        self.batches = b.number;
        self.calls = calls;
        self.active = None;
        Ok((self.batches, self.calls))
    }
}

fn identity(
    state: &NormalState,
    context: &HookContext,
    control: ControlIdentity<'_>,
    entry: bool,
) -> Result<(u64, SelectedFunction), BridgeError> {
    state.binding.process()?;
    if !early_binding(&state.binding)
        || state.actual_thread != thread::current().id()
        || state.tid != tid()
        || context.stack_pointer < state.stack.start
        || context.stack_pointer & 15 != 8
        || context
            .stack_pointer
            .checked_add(8)
            .is_none_or(|end| end > state.stack.end)
    {
        return Err(error(Cause::Identity));
    }
    let BindingProfile::Module { site, .. } = &state.binding.profile else {
        return Err(error(Cause::Identity));
    };
    let index = site
        .resolve_early_entry(context.instruction_pointer, control, entry)
        .ok_or(error(Cause::Identity))?;
    let selected = state.selection(index)?;
    // SAFETY: same exact owned-stack attachment contract as mandatory callbacks.
    let word = unsafe { (context.stack_pointer as usize as *const u64).read_unaligned() };
    if !stack_word_ok(&state.stack, context.stack_pointer, word) {
        return Err(error(Cause::Return));
    }
    Ok((word, selected))
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
            let result = PHYSICAL
                .try_with(|cell| {
                    let mut physical = cell
                        .try_borrow_mut()
                        .map_err(|_| error(Cause::Attachment))?;
                    let physical = physical.as_mut().ok_or(error(Cause::Attachment))?;
                    let (word, selected) = identity(state, context, control, entry)?;
                    physical.visit(
                        state,
                        Visit {
                            selected,
                            pc: context.instruction_pointer,
                            rsp: context.stack_pointer,
                            word,
                            stamp,
                            entry,
                        },
                    )
                })
                .unwrap_or(Err(error(Cause::Attachment)));
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
pub(in crate::frontend_native::always_on) unsafe extern "C" fn entry_callback(
    context: *mut HookContext,
    control: ControlIdentity<'_>,
) {
    // SAFETY: this sealed profile retains the original supported RDTSCP contract.
    let stamp = unsafe { timing::read() };
    if context.is_null() || callback(unsafe { &*context }, control, true, stamp).is_err() {
        fatal();
    }
    #[cfg(any(test, feature = "frontend-native-qualification"))]
    qualification::after_published(qualification::PauseKind::AfterEntryPublished);
}
pub(in crate::frontend_native::always_on) unsafe extern "C" fn exit_callback(
    context: *mut HookContext,
    control: ControlIdentity<'_>,
) {
    // SAFETY: identical instruction-support contract to entry.
    let stamp = unsafe { timing::read() };
    if context.is_null() || callback(unsafe { &*context }, control, false, stamp).is_err() {
        fatal();
    }
    #[cfg(any(test, feature = "frontend-native-qualification"))]
    qualification::after_published(qualification::PauseKind::AfterPreRetPublished);
}
impl EarlyEntryModuleClient {
    /// # Safety
    /// The complete `NormalModuleClient::attach_owned` sealed publication, sole
    /// attachment/entry, universal 0..=64-byte readonly input, scalar SysV ABI,
    /// stack/XSAVE/RDTSCP, ordinary-return, no-fork/signal/unwind/cancellation/CET
    /// and immutable process-lived source/control/mapping contracts hold.
    /// No caller pointer escapes. Only entry admission may disappear; every RET
    /// remains mandatory, and any actual entry retains its original model owner
    /// until a later real entry or checked outer return. Disarm never cancels it.
    pub unsafe fn attach_owned(
        self,
        caller: LoadedNormalModuleCaller,
        order: [usize; 2],
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<OwnedEarlyEntryModuleThread, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.shared.check()?;
        let binding = &self.shared.binding;
        if !caller.process_matches()
            || registration == 0
            || journal.page.0.iter().any(|&word| word != 0)
            || !matches!(order, [0, 1] | [1, 0])
            || !timing::supported()
        {
            return Err(error(Cause::Attachment));
        }
        let BindingProfile::Module { site, functions } = &binding.profile else {
            return Err(error(Cause::Identity));
        };
        if !site.has_sealed_source() {
            return Err(error(Cause::Identity));
        }
        let selected = order.map(|index| SelectedFunction {
            index,
            function: functions[index],
        });
        let entries = order.map(|index| site.functions()[index].entry());
        let state = PhysicalState {
            shared: Arc::clone(&self.shared),
            order: selected,
            words: caller.continuations(),
            batches: 0,
            calls: 0,
            active: None,
        };
        PHYSICAL
            .try_with(|cell| {
                let mut physical = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                if physical.is_some() {
                    return Err(error(Cause::Attachment));
                }
                let thread = attach_ready(binding, registration, stack, journal)?;
                *physical = Some(state);
                Ok(OwnedEarlyEntryModuleThread {
                    inner: OwnedNormalModuleThread {
                        thread,
                        caller,
                        binding: Arc::clone(binding),
                        order: selected,
                        entries,
                        admission: Arc::new(Admission::new()),
                    },
                    shared: self.shared,
                })
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
impl OwnedEarlyEntryModuleThread {
    pub fn close_handle(&self) -> NormalModuleClose {
        self.inner.close_handle()
    }
    fn physical<T>(
        &self,
        f: impl FnOnce(&mut PhysicalState, &NormalState) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        self.shared.check()?;
        NORMAL
            .try_with(|normal| {
                let storage = normal.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let state = storage.0.as_ref().ok_or(error(Cause::Attachment))?;
                if !self
                    .inner
                    .thread
                    .matches_profile(state, TransferProfile::EarlyModule)
                    || !Arc::ptr_eq(&self.shared.binding, &state.binding)
                    || !self.inner.caller.process_matches()
                {
                    return Err(error(Cause::Attachment));
                }
                state.health()?;
                PHYSICAL
                    .try_with(|cell| {
                        let mut p = cell
                            .try_borrow_mut()
                            .map_err(|_| error(Cause::Attachment))?;
                        let p = p.as_mut().ok_or(error(Cause::Attachment))?;
                        p.matches(state)?;
                        f(p, state)
                    })
                    .unwrap_or(Err(error(Cause::Attachment)))
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    /// One real four-call C application batch, even when all interval entries
    /// bypass. Every error after admission poisons the unchanged enclosing guard.
    pub fn run_batch(
        &mut self,
        inputs: NormalModuleInputs<'_>,
    ) -> Result<OwnedEarlyEntryModuleResult, BridgeError> {
        self.execute_body(|caller, entries| {
            let mut values = [0; 4];
            // SAFETY: exact retained caller/target/input contracts established once.
            let sum = unsafe { caller.invoke(entries, inputs.inputs, &mut values) };
            (sum, values)
        })
    }
    fn execute_body(
        &mut self,
        body: impl FnOnce(&mut LoadedNormalModuleCaller, [u64; 2]) -> (u64, [u64; 4]),
    ) -> Result<OwnedEarlyEntryModuleResult, BridgeError> {
        let active = ActiveBatch::acquire(&self.inner.admission)?;
        self.physical(|p, s| p.begin(s))?;
        let (sum, values) = body(&mut self.inner.caller, self.inner.entries);
        if sum != values.into_iter().fold(0, u64::wrapping_add) {
            return Err(error(Cause::Return));
        }
        let rows = self.physical(|p, s| p.returned(s))?;
        let observations = self.inner.thread.checkpoint_with::<EarlyOutput>()?;
        let (batch, calls) = self.physical(|p, s| p.complete(s, rows, observations.as_ref()))?;
        active.complete()?;
        Ok(OwnedEarlyEntryModuleResult {
            batch,
            completed_calls: calls,
            sum,
            values,
            physical: rows,
            observations: observations.map(EarlyEntryModuleObservations),
        })
    }
    pub fn finish(&mut self) -> Result<NormalTotals, BridgeError> {
        self.physical(|p, s| {
            if p.active.is_some() {
                return Err(error(Cause::Outstanding));
            }
            drained(s).map(|_| ())
        })?;
        if self.inner.admission.close() != NormalModuleCloseState::Closing {
            return Err(error(Cause::Outstanding));
        }
        let totals = match self
            .inner
            .thread
            .detach_profile(TransferProfile::EarlyModule)
        {
            Ok(totals) => totals,
            Err(e) => {
                self.inner.admission.poison();
                return Err(e);
            }
        };
        if !self.inner.admission.change(
            NormalModuleCloseState::Closing,
            NormalModuleCloseState::Closed,
        ) {
            self.inner.admission.poison();
            return Err(error(Cause::Outstanding));
        }
        PHYSICAL.with(|cell| {
            cell.borrow_mut().take();
        });
        Ok(totals)
    }
}

#[cfg(test)]
mod native;
