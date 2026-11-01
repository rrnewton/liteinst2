//! An owned ordinary-C batch, with one outer-return checkpoint. The original
//! unsafe attachment/checkpoint and their full-postflight contracts are intact.
use super::*;
use crate::frontend_native::LoadedNormalModuleCaller;
use std::sync::atomic::{AtomicU8, Ordering};
pub(in crate::frontend_native::always_on) mod early_entry;
pub use early_entry::{
    EarlyEntryModuleClient, EarlyEntryModuleObservations, EarlyEntryModulePhysicalRow,
    EarlyEntryModuleSessionController, OwnedEarlyEntryModuleResult, OwnedEarlyEntryModuleThread,
    PreparedEarlyEntryModuleSessionController,
};

/// Two immutable byte strings, each 0..=64 bytes. Every byte value, including
/// zero, and every length in this domain must be covered by `attach_owned`.
#[derive(Clone, Copy)]
pub struct NormalModuleInputs<'a> {
    inputs: [&'a [u8]; 2],
}
impl<'a> NormalModuleInputs<'a> {
    pub fn new(first: &'a [u8], second: &'a [u8]) -> Result<Self, BridgeError> {
        if first.len() > 64 || second.len() > 64 {
            return Err(error(Cause::Capacity));
        }
        Ok(Self {
            inputs: [first, second],
        })
    }
}

/// Closing is a request; only Closed acknowledges same-thread checked detach.
/// Poisoned retains owners and never acknowledges return or executable teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NormalModuleCloseState {
    Ready,
    Active,
    Closing,
    ActiveClosing,
    Closed,
    Poisoned,
}
struct Admission(AtomicU8);
impl Admission {
    fn new() -> Self {
        Self(AtomicU8::new(NormalModuleCloseState::Ready as u8))
    }
    fn state(&self) -> NormalModuleCloseState {
        use NormalModuleCloseState::*;
        match self.0.load(Ordering::Acquire) {
            0 => Ready,
            1 => Active,
            2 => Closing,
            3 => ActiveClosing,
            4 => Closed,
            _ => Poisoned,
        }
    }
    fn change(&self, from: NormalModuleCloseState, to: NormalModuleCloseState) -> bool {
        self.0
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    fn close(&self) -> NormalModuleCloseState {
        use NormalModuleCloseState::*;
        loop {
            let old = self.state();
            let new = match old {
                Ready => Closing,
                Active => ActiveClosing,
                _ => return old,
            };
            if self.change(old, new) {
                return new;
            }
        }
    }
    fn poison(&self) {
        self.0
            .store(NormalModuleCloseState::Poisoned as u8, Ordering::Release);
    }
}
/// Sendable close request/status only. It carries no target pointer, native-call
/// authority, checkpoint or timeout that could acknowledge a blocked invocation.
#[derive(Clone)]
pub struct NormalModuleClose(Arc<Admission>);
impl NormalModuleClose {
    pub fn request(&self) -> NormalModuleCloseState {
        self.0.close()
    }
    pub fn state(&self) -> NormalModuleCloseState {
        self.0.state()
    }
}
struct ActiveBatch {
    admission: Arc<Admission>,
    armed: bool,
}
impl ActiveBatch {
    fn acquire(admission: &Arc<Admission>) -> Result<Self, BridgeError> {
        if !admission.change(
            NormalModuleCloseState::Ready,
            NormalModuleCloseState::Active,
        ) {
            return Err(error(Cause::Outstanding));
        }
        Ok(Self {
            admission: Arc::clone(admission),
            armed: true,
        })
    }
    fn complete(mut self) -> Result<(), BridgeError> {
        use NormalModuleCloseState::*;
        loop {
            let old = self.admission.state();
            let new = match old {
                Active => Ready,
                ActiveClosing => Closing,
                _ => return Err(error(Cause::Outstanding)),
            };
            if self.admission.change(old, new) {
                self.armed = false;
                return Ok(());
            }
        }
    }
}
impl Drop for ActiveBatch {
    fn drop(&mut self) {
        if self.armed {
            self.admission.poison();
        }
    }
}

/// Attached actual-thread owner. It is !Send/!Sync through `NormalThread` and
/// the retained caller. Native/source/generated owners remain process-lived,
/// including refusal and abandonment. Drop never performs an acknowledgement.
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::OwnedNormalModuleThread;
/// fn send<T: Send>() {}
/// send::<OwnedNormalModuleThread>();
/// ```
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::OwnedNormalModuleThread;
/// fn sync<T: Sync>() {}
/// sync::<OwnedNormalModuleThread>();
/// ```
pub struct OwnedNormalModuleThread {
    thread: NormalThread,
    caller: LoadedNormalModuleCaller,
    binding: Arc<Binding>,
    order: [SelectedFunction; 2],
    entries: [u64; 2],
    admission: Arc<Admission>,
}
/// Four scalar results plus the existing complete sampled/unsampled transfer.
/// No scalar-result correctness or clock/performance qualification is inferred.
#[derive(Debug)]
pub struct OwnedNormalModuleResult {
    pub sum: u64,
    pub values: [u64; 4],
    pub observations: NormalModuleBatch,
}

impl NormalModuleClient {
    /// Admit once on the actual calling thread, retaining a sealed module and
    /// sealed compiled application caller. `order` maps semantic target/request
    /// positions to the module's canonical increasing-ELF indices (0 and 1).
    /// Further safe batches make one ordinary C call and one outer checkpoint;
    /// they do not perform repeated source/file/mapping snapshot scans.
    ///
    /// # Safety
    /// The real sealed publication/activation contracts hold continuously. This
    /// is the sole attachment and sole execution route for this module/caller;
    /// no cloned client, saved pointer or foreign entry executes either target.
    /// For EVERY pair of byte slices accepted by `NormalModuleInputs` (all byte
    /// values, lengths 0..=64, including empty and overlapping immutable slices),
    /// both targets have the exact SysV `(*const u8, usize) -> u64` ABI, read only
    /// within their slice and retain no pointers. They preserve the caller ABI,
    /// do not write input/request/target/result memory, call each other, nest or
    /// reenter. Caller and targets return only by ordinary matching RET; there
    /// is no unwind/nonlocal exit, signal/cancellation/fork or active CET.
    /// No foreign code changes loaded/generated/control mappings or permissions.
    /// The stack remains owned, readable and sufficiently writable for this C
    /// caller, all callback state saves/XSAVE and ordinary returns; RDTSCP stays
    /// supported. The caller loader's complete unsafe contract also continues.
    ///
    /// This separate owner profile supplies lifetime/entry/return rendezvous;
    /// it does not call or narrow the old public full-postflight attachment.
    /// The sealed backing and real installed owners cannot unload through this
    /// API. Arbitrary hostile in-process unsafe code is outside the contract.
    /// A blocked call holds Active indefinitely; no close timeout fabricates RET.
    pub unsafe fn attach_owned(
        self,
        caller: LoadedNormalModuleCaller,
        order: [usize; 2],
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<OwnedNormalModuleThread, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        if matches!(&self.binding.profile, BindingProfile::Module { site, .. } if site.is_early_entry())
            || !module_runtime_matches(&self.binding)
            || !caller.process_matches()
            || registration == 0
            || journal.page.0.iter().any(|&word| word != 0)
            || !matches!(order, [0, 1] | [1, 0])
        {
            return Err(error(Cause::Attachment));
        }
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        let BindingProfile::Module { site, functions } = &self.binding.profile else {
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
        let admission = Arc::new(Admission::new());
        // Separate owner-authorized admission above; same complete checked TLS
        // attachment transaction. Do not call the old public unsafe attach.
        let thread = attach_ready(&self.binding, registration, stack, journal)?;
        Ok(OwnedNormalModuleThread {
            thread,
            caller,
            binding: self.binding,
            order: selected,
            entries,
            admission,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct Baseline {
    cursor: Cursor,
    next: u64,
}
pub(super) fn drained(state: &NormalState) -> Result<Baseline, BridgeError> {
    state.health()?;
    state.shape()?;
    if state.pending.is_some()
        || state.len != 0
        || state.journal.used() != 0
        || !balanced(state.totals)
        || state.totals != state.cursor.totals
        || state.transfer_check()?.1 != 0
    {
        return Err(error(Cause::Outstanding));
    }
    Ok(Baseline {
        cursor: state.cursor,
        next: state.next,
    })
}
fn before_batch(state: &NormalState) -> Result<Baseline, BridgeError> {
    let before = drained(state)?;
    if CALLS < 4
        || before.next.checked_add(4).is_none()
        || before.cursor.number.checked_add(1).is_none()
        || before.cursor.totals.entered.checked_add(4).is_none()
    {
        return Err(error(Cause::Capacity));
    }
    Ok(before)
}
pub(super) fn returned(
    state: &NormalState,
    before: Baseline,
    order: [SelectedFunction; 2],
    words: [u64; 4],
) -> Result<(), BridgeError> {
    state.health()?;
    state.shape()?;
    let expected = [order[0], order[1], order[0], order[1]];
    let pending = state.pending.as_ref().ok_or(error(Cause::Return))?;
    if state.cursor != before.cursor
        || state.next != before.next.checked_add(4).ok_or(error(Cause::Capacity))?
        || state
            .totals
            .entered
            .checked_sub(before.cursor.totals.entered)
            != Some(4)
        || state
            .totals
            .ret_observed
            .checked_sub(before.cursor.totals.ret_observed)
            != Some(4)
        || state
            .totals
            .confirmed
            .checked_sub(before.cursor.totals.confirmed)
            != Some(3)
        || state.len != 3
        || pending.selected != expected[3]
        || pending.returned.is_none()
        || pending.word != words[3]
    {
        return Err(error(Cause::Return));
    }
    for i in 0..3 {
        let record = state.records[i].ok_or(error(Cause::Invariant))?;
        if state.functions[i] != Some(expected[i])
            || record.return_word != words[i]
            || record.entry_rsp != pending.rsp
        {
            return Err(error(Cause::Return));
        }
    }
    if state.transfer_check()?.1 != 4 {
        return Err(error(Cause::Invariant));
    }
    Ok(())
}

impl OwnedNormalModuleThread {
    pub fn close_handle(&self) -> NormalModuleClose {
        NormalModuleClose(Arc::clone(&self.admission))
    }
    fn state<T>(
        &self,
        f: impl FnOnce(&NormalState) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        self.binding.process()?;
        NORMAL
            .try_with(|cell| {
                let storage = cell.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let state = storage.0.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.thread.matches_for(state, true)
                    || !Arc::ptr_eq(&self.binding, &state.binding)
                    || !self.caller.process_matches()
                {
                    return Err(error(Cause::Attachment));
                }
                f(state)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    /// Execute the complete bounded application body once. Its four indirect
    /// calls go straight to selected entries; callbacks remain the existing SDK
    /// hooks. The static body bound is checked before entry, not inferred from
    /// the returned census. All post-entry errors and unwinding poison admission.
    pub fn run_batch(
        &mut self,
        inputs: NormalModuleInputs<'_>,
    ) -> Result<OwnedNormalModuleResult, BridgeError> {
        let active = ActiveBatch::acquire(&self.admission)?;
        let before = self.state(before_batch)?;
        let mut values = [0; 4];
        // SAFETY: one-time universal input/ABI/ownership admission, retained
        // immutable borrows and private arrays, exactly four ordinary target CALLs.
        let sum = unsafe { self.caller.invoke(self.entries, inputs.inputs, &mut values) };
        // Reaching here is the real outer C return, not a counter/report inference.
        if sum != values.into_iter().fold(0, u64::wrapping_add) {
            return Err(error(Cause::Return));
        }
        let words = self.caller.continuations();
        self.state(|s| returned(s, before, self.order, words))?;
        // Separate owner-authorized checkpoint: the preceding native call really
        // returned under the admitted contract. Preserve all existing transfer
        // allocation, identity, journal, health and sampled/unsampled checks.
        let observations = self
            .thread
            .checkpoint_with::<ModuleOutput>()?
            .ok_or(error(Cause::Return))?;
        let expected = [self.order[0], self.order[1], self.order[0], self.order[1]];
        if observations.before != before.cursor
            || observations.records.len() != 4
            || observations
                .after
                .totals
                .entered
                .checked_sub(before.cursor.totals.entered)
                != Some(4)
            || observations
                .after
                .totals
                .ret_observed
                .checked_sub(before.cursor.totals.ret_observed)
                != Some(4)
            || observations
                .after
                .totals
                .confirmed
                .checked_sub(before.cursor.totals.confirmed)
                != Some(4)
            || observations.records.iter().zip(expected).zip(words).any(
                |((record, selected), word)| {
                    record.function != selected.function || record.record.return_word != word
                },
            )
            || observations.records[3].record.acknowledgement
                != NormalAcknowledgement::CallerCheckpoint
        {
            return Err(error(Cause::Return));
        }
        self.state(drained)?;
        active.complete()?;
        Ok(OwnedNormalModuleResult {
            sum,
            values,
            observations,
        })
    }
    /// Close against future admission, then acknowledge only after same-thread
    /// empty-state verification and the original checked detach. This does not
    /// reclaim executable memory or acknowledge from a foreign waiting thread.
    pub fn finish(&mut self) -> Result<NormalTotals, BridgeError> {
        if self.admission.close() != NormalModuleCloseState::Closing {
            return Err(error(Cause::Outstanding));
        }
        let outcome = (|| {
            self.state(drained)?;
            self.thread.detach_for(true)
        })();
        match outcome {
            Ok(totals) => {
                if !self.admission.change(
                    NormalModuleCloseState::Closing,
                    NormalModuleCloseState::Closed,
                ) {
                    self.admission.poison();
                    return Err(error(Cause::Outstanding));
                }
                Ok(totals)
            }
            Err(e) => {
                self.admission.poison();
                Err(e)
            }
        }
    }
}
impl Drop for OwnedNormalModuleThread {
    fn drop(&mut self) {
        if self.admission.state() != NormalModuleCloseState::Closed {
            self.admission.poison();
        }
        // NormalThread's existing Drop poisons/retains any attached TLS state.
        // Source loader, installed image and publication owners are process-lived.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_batch_inputs_enforce_complete_domain_before_any_entry() {
        assert!(NormalModuleInputs::new(&[], &[255; 64]).is_ok());
        let bytes = [0; 64];
        assert!(NormalModuleInputs::new(&bytes, &bytes[1..]).is_ok());
        assert!(NormalModuleInputs::new(&[0; 65], &[]).is_err());
        assert!(NormalModuleInputs::new(&[], &[0; 65]).is_err());
    }
    #[test]
    fn owned_transfer_allocation_refusal_retains_pending_receipt_and_poisons_lease() {
        let mut fixture = super::super::session::tests::Fixture::new(10);
        let before = drained(&fixture.state).unwrap();
        let selected = [
            fixture.state.selection(0).unwrap(),
            fixture.state.selection(1).unwrap(),
        ];
        for index in [0, 1, 0, 1] {
            fixture.call(index);
        }
        returned(
            &fixture.state,
            before,
            selected,
            [0x9008, 0x9010, 0x9018, 0x9020],
        )
        .unwrap();
        let totals = fixture.state.totals;
        let journal = fixture.state.journal.page.0;
        let pending = fixture.state.pending.as_ref().unwrap().ordinal;
        let admission = Arc::new(Admission::new());
        let active = ActiveBatch::acquire(&admission).unwrap();
        FAIL_RESERVE.set(Some(0));
        let refusal = ModuleOutput::allocate().err();
        FAIL_RESERVE.set(None);
        assert_eq!(refusal, Some(error(Cause::Capacity)));
        drop(active); // The same armed guard covers every checkpoint `?`.
        assert_eq!(admission.state(), NormalModuleCloseState::Poisoned);
        assert!(ActiveBatch::acquire(&admission).is_err());
        assert_eq!(fixture.state.totals, totals);
        assert_eq!(fixture.state.journal.page.0, journal);
        assert_eq!(fixture.state.pending.as_ref().unwrap().ordinal, pending);
        assert!(fixture.state.pending.as_ref().unwrap().returned.is_some());
        assert_eq!(fixture.state.len, 3);
        assert_eq!(totals.confirmed, 3);
        assert!(drained(&fixture.state).is_err());
    }
    #[test]
    fn owned_close_linearizes_against_active_batch_and_never_acks_from_drop() {
        let gate = Arc::new(Admission::new());
        let active = ActiveBatch::acquire(&gate).unwrap();
        let close = NormalModuleClose(Arc::clone(&gate));
        let other = std::thread::spawn(move || {
            assert_eq!(close.request(), NormalModuleCloseState::ActiveClosing);
            close
        });
        let close = other.join().unwrap();
        assert!(ActiveBatch::acquire(&gate).is_err());
        assert_eq!(close.state(), NormalModuleCloseState::ActiveClosing);
        active.complete().unwrap();
        assert_eq!(close.state(), NormalModuleCloseState::Closing);
        assert!(ActiveBatch::acquire(&gate).is_err());
        assert_ne!(close.state(), NormalModuleCloseState::Closed);
        let gate = Arc::new(Admission::new());
        drop(ActiveBatch::acquire(&gate).unwrap());
        assert_eq!(gate.state(), NormalModuleCloseState::Poisoned);
        assert!(ActiveBatch::acquire(&gate).is_err());
        assert_eq!(gate.close(), NormalModuleCloseState::Poisoned);
        let gate = Arc::new(Admission::new());
        assert_eq!(gate.close(), NormalModuleCloseState::Closing);
        assert!(ActiveBatch::acquire(&gate).is_err());
    }
}

#[cfg(test)]
mod native;
