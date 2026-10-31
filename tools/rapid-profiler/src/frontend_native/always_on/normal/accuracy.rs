//! Opt-in NORMAL counter sidecars; unchanged records, journal and acknowledgments.
//! Counter/TSC windows differ and include instrumentation. No correction, scaling,
//! body-only interpretation, PMU availability requirement or accuracy pass exists.
use super::*;
use crate::counter_reading::CounterRecord;
mod counter;
use counter::Counter;
pub use counter::{
    NormalCounterAcquisition, NormalCounterClose, NormalCounterEndpoint, NormalCounterIdentity,
    NormalCounterOperation, NormalCounterRead, NormalCounterSyscall,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Endpoints {
    selected: SelectedFunction,
    ordinal: u64,
    start: NormalCounterEndpoint,
    end: Option<NormalCounterEndpoint>,
}
pub(super) struct State {
    counter: Counter,
    slots: [Option<Endpoints>; CALLS],
}
impl State {
    fn new(counter: Counter) -> Self {
        Self {
            counter,
            slots: [None; CALLS],
        }
    }
    pub(super) fn open() -> Self {
        Self::new(Counter::open())
    }
    pub(super) fn begin(
        &mut self,
        i: usize,
        selected: SelectedFunction,
        ordinal: u64,
    ) -> Result<(), BridgeError> {
        let slot = self.slots.get_mut(i).ok_or(error(Cause::Capacity))?;
        if slot.is_some() {
            return Err(error(Cause::Invariant));
        }
        *slot = Some(Endpoints {
            selected,
            ordinal,
            start: self.counter.endpoint(),
            end: None,
        });
        Ok(())
    }
    pub(super) fn end(
        &mut self,
        i: usize,
        selected: SelectedFunction,
        ordinal: u64,
    ) -> Result<(), BridgeError> {
        let row = self
            .slots
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(error(Cause::Invariant))?;
        if row.selected != selected || row.ordinal != ordinal || row.end.is_some() {
            return Err(error(Cause::Invariant));
        }
        row.end = Some(self.counter.endpoint());
        Ok(())
    }
    pub(super) fn shape(&self, s: &NormalState) -> Result<(), BridgeError> {
        if self.counter.acquisition().owner
            != (NormalCounterIdentity {
                pid: s.binding.pid,
                tid: s.tid,
            })
        {
            return Err(error(Cause::Identity));
        }
        for (i, slot) in self.slots.iter().enumerate() {
            let expected = if i < s.len {
                Some((
                    s.functions[i].ok_or(error(Cause::Invariant))?,
                    s.records[i].ok_or(error(Cause::Invariant))?.raw.ordinal,
                    true,
                ))
            } else if i == s.len {
                s.pending
                    .as_ref()
                    .map(|p| (p.selected, p.ordinal, p.returned.is_some()))
            } else {
                None
            };
            match (slot, expected) {
                (None, None) => (),
                (Some(row), Some((selected, ordinal, ended)))
                    if row.selected == selected
                        && row.ordinal == ordinal
                        && row.end.is_some() == ended => {}
                _ => return Err(error(Cause::Invariant)),
            }
        }
        Ok(())
    }
    fn row(
        &self,
        i: usize,
        selected: SelectedFunction,
        normal: NormalRecord,
    ) -> Result<NormalAccuracyRecord, BridgeError> {
        let p = self
            .slots
            .get(i)
            .copied()
            .flatten()
            .ok_or(error(Cause::Invariant))?;
        if p.selected != selected || p.ordinal != normal.raw.ordinal {
            return Err(error(Cause::Identity));
        }
        let end = p.end.ok_or(error(Cause::Invariant))?;
        Ok(NormalAccuracyRecord {
            function: selected.function,
            normal,
            start: p.start,
            end,
            counters: CounterRecord::new(
                p.start.read.and_then(NormalCounterRead::reading),
                end.read.and_then(NormalCounterRead::reading),
            ),
        })
    }
    pub(super) fn transferred(&mut self) {
        self.slots = [None; CALLS];
    }
}
/// Exactly one immutable sidecar per acknowledged NORMAL record, including
/// unsampled calls. Arithmetic retains raw words even when event identity fails;
/// consumers must inspect acquisition, endpoint IDs, read sizes and timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalAccuracyRecord {
    function: FunctionId,
    normal: NormalRecord,
    start: NormalCounterEndpoint,
    end: NormalCounterEndpoint,
    counters: CounterRecord,
}
impl NormalAccuracyRecord {
    pub fn function(&self) -> FunctionId {
        self.function
    }
    pub fn ordinal(&self) -> u64 {
        self.normal.raw.ordinal
    }
    pub fn normal(&self) -> NormalRecord {
        self.normal
    }
    pub fn start(&self) -> NormalCounterEndpoint {
        self.start
    }
    pub fn end(&self) -> NormalCounterEndpoint {
        self.end
    }
    pub fn counters(&self) -> CounterRecord {
        self.counters
    }
}
#[derive(Debug, Eq, PartialEq)]
pub struct NormalLeafSetAccuracyBatch {
    normal: NormalLeafSetBatch,
    counters: Vec<NormalAccuracyRecord>,
    acquisition: NormalCounterAcquisition,
}
impl NormalLeafSetAccuracyBatch {
    pub fn normal(&self) -> &NormalLeafSetBatch {
        &self.normal
    }
    pub fn counters(&self) -> &[NormalAccuracyRecord] {
        &self.counters
    }
    pub fn acquisition(&self) -> NormalCounterAcquisition {
        self.acquisition
    }
    /// Transfer all three parts together for a consumer that owns the NORMAL
    /// batch. The caller must retain/join every sidecar, including failed reads.
    pub fn into_parts(
        self,
    ) -> (
        NormalLeafSetBatch,
        Vec<NormalAccuracyRecord>,
        NormalCounterAcquisition,
    ) {
        (self.normal, self.counters, self.acquisition)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalAccuracyDetached {
    pub totals: NormalTotals,
    pub counter: NormalCounterClose,
}
/// Actual-thread-only handle. Explicit empty detach returns disable/close
/// evidence. Losing/forgetting this handle poisons or retains NORMAL, as before;
/// that retained counter fd also remains process-lived, not falsely closed.
pub struct NormalLeafSetAccuracyThread(NormalThread);
impl NormalLeafSetAccuracyThread {
    pub fn acquisition(&self) -> Result<NormalCounterAcquisition, BridgeError> {
        NORMAL
            .try_with(|cell| {
                let storage = cell.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let s = storage.0.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.0.matches_profile(s, TransferProfile::LeafSet) {
                    return Err(error(Cause::Attachment));
                }
                s.health()?;
                s.shape()?;
                Ok(s.accuracy
                    .as_ref()
                    .ok_or(error(Cause::Attachment))?
                    .counter
                    .acquisition())
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    pub fn totals(&self) -> Result<NormalTotals, BridgeError> {
        self.0.totals_profile(TransferProfile::LeafSet)
    }
    /// # Safety
    /// Identical complete-return/source/input/stack/signal obligations to
    /// NormalLeafSetThread::checkpoint_after_returns. No counter read grants
    /// physical-return or executable-reclamation authority.
    pub unsafe fn checkpoint_after_returns(
        &mut self,
    ) -> Result<Option<NormalLeafSetAccuracyBatch>, BridgeError> {
        self.0.checkpoint_with::<Output>()
    }
    pub fn detach(&mut self) -> Result<NormalAccuracyDetached, BridgeError> {
        let _scope = ControllerScope::enter()?;
        NORMAL
            .try_with(|cell| {
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let s = storage.0.as_mut().ok_or(error(Cause::Attachment))?;
                if !self.0.matches_profile(s, TransferProfile::LeafSet) {
                    return Err(error(Cause::Attachment));
                }
                s.health()?;
                s.shape()?;
                if s.pending.is_some() || s.len != 0 || s.journal.used() != 0 {
                    return Err(error(Cause::Outstanding));
                }
                let accuracy = s.accuracy.as_mut().ok_or(error(Cause::Attachment))?;
                let result = NormalAccuracyDetached {
                    totals: s.totals,
                    counter: accuracy.counter.close(),
                };
                drop(storage.0.take());
                self.0.active = false;
                Ok(result)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
pub(super) fn attach(
    binding: &Arc<Binding>,
    registration: u64,
    stack: ReadableStack,
    journal: IntervalJournal,
) -> Result<NormalLeafSetAccuracyThread, BridgeError> {
    // All profile/clock checks precede this helper. Opening is outside callbacks;
    // every ordinary PMU refusal remains in the resulting acquisition/rows.
    attach_profile_accuracy(binding, registration, stack, journal, None, true)
        .map(NormalLeafSetAccuracyThread)
}
struct Output {
    normal: leaf_set::LeafSetOutput,
    counters: Vec<NormalAccuracyRecord>,
}
impl TransferOutput for Output {
    type Batch = NormalLeafSetAccuracyBatch;
    type Identity = (leaf_set::LeafSetIdentity, NormalCounterAcquisition);
    const PROFILE: TransferProfile = TransferProfile::LeafSet;
    fn allocate() -> Result<(Self, Vec<u64>), BridgeError> {
        let (normal, journal) = leaf_set::LeafSetOutput::allocate()?;
        let mut counters = Vec::new();
        counters
            .try_reserve_exact(CALLS)
            .map_err(|_| error(Cause::Capacity))?;
        Ok((Self { normal, counters }, journal))
    }
    fn capacity(&self) -> bool {
        self.normal.capacity() && self.counters.is_empty() && self.counters.capacity() >= CALLS
    }
    fn identity(&self, s: &NormalState) -> Result<Self::Identity, BridgeError> {
        Ok((
            self.normal.identity(s)?,
            s.accuracy
                .as_ref()
                .ok_or(error(Cause::Attachment))?
                .counter
                .acquisition(),
        ))
    }
    fn capture_accuracy(&mut self, s: &NormalState) -> Result<(), BridgeError> {
        let a = s.accuracy.as_ref().ok_or(error(Cause::Attachment))?;
        a.shape(s)?;
        for i in 0..s.len {
            self.counters.push(a.row(
                i,
                s.functions[i].ok_or(error(Cause::Invariant))?,
                s.records[i].ok_or(error(Cause::Invariant))?,
            )?);
        }
        if let Some(p) = &s.pending {
            let (normal, _) = s.confirmation(NormalAcknowledgement::CallerCheckpoint)?;
            self.counters.push(a.row(s.len, p.selected, normal)?);
        }
        Ok(())
    }
    fn push(&mut self, normal: NormalRecord, selected: SelectedFunction) {
        self.normal.push(normal, selected);
    }
    fn finish(
        self,
        (id, acquisition): Self::Identity,
        h: TransferHeader,
        journal: Vec<u64>,
    ) -> Self::Batch {
        NormalLeafSetAccuracyBatch {
            normal: self.normal.finish(id, h, journal),
            counters: self.counters,
            acquisition,
        }
    }
}
#[cfg(test)]
mod tests;
