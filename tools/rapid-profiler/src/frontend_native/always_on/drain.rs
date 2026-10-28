//! Explicit same-thread transfer of bounded buffers; not epoch or code retirement.
use super::*;
use std::ops::Range;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Cursor {
    number: u64,
    totals: PairTotals,
    sequence: u64,
}

/// Immutable completed-buffer copy. Contains no ticket, epoch, gate or source owner.
/// Journal indices are local; ranges and ordinals are absolute lifetime values.
/// Timestamps retain their original raw/possibly unavailable meaning.
#[derive(Debug, Eq, PartialEq)]
pub struct IntervalBatch {
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
    gate_sequence: u64,
    raw_range: Range<u64>,
    event_range: Range<u64>,
    rows: Vec<RawInterval>,
    journal: Vec<u64>,
}
impl IntervalBatch {
    /// None is the unchanged legacy format. Absolute batches retain opaque
    /// stream identity only, not a Session/epoch owner or export acknowledgement.
    pub fn history_stream(&self) -> Option<&HistoryStream> {
        self.stream.as_ref()
    }
    /// Absolute mode only: checked committed prefix bound captured at transfer.
    pub fn history_high_water(&self) -> Option<u64> {
        self.history_end
    }
    /// Decode one local event prefix against that bound. This does not replay
    /// generation association; join HistoryBatch::binding_at for that proof.
    pub fn history_prefix(&self, event: usize) -> Option<u64> {
        self.stream.as_ref()?;
        if event as u64 >= *self.journal.first()? {
            return None;
        }
        let at = event.checked_mul(7)?.checked_add(10)?;
        history::decode_absolute(*self.journal.get(at)?, self.history_end?)
            .map(|(_, prefix, _)| prefix)
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
    pub fn totals(&self) -> (PairTotals, PairTotals) {
        (self.before.totals, self.after.totals)
    }
    pub fn completed_sequences(&self) -> (u64, u64) {
        (self.before.sequence, self.after.sequence)
    }
    pub fn next_ordinal(&self) -> u64 {
        self.next
    }
    pub fn gate_sequence(&self) -> u64 {
        self.gate_sequence
    }
    pub fn raw_range(&self) -> Range<u64> {
        self.raw_range.clone()
    }
    pub fn event_range(&self) -> Range<u64> {
        self.event_range.clone()
    }
    pub fn rows(&self) -> &[RawInterval] {
        &self.rows
    }
    /// All 512 original words: local header, complete event rows and zero tail.
    pub fn journal(&self) -> &[u64] {
        &self.journal
    }
}

// A failed/unwound post-preflight invocation leaves None sticky. No later
// successful call can fabricate the missing prior completion checkpoint.
pub(super) fn completed_checkpoint(
    previous: Option<PairTotals>,
    before: PairTotals,
    after: PairTotals,
) -> Option<PairTotals> {
    (previous == Some(before)).then_some(after)
}

#[cfg(test)]
thread_local! { static FAIL_RESERVE: Cell<Option<usize>> = const { Cell::new(None) }; }

fn reserve<T>(output: &mut Vec<T>, count: usize, _slot: usize) -> Result<(), BridgeError> {
    #[cfg(test)]
    if FAIL_RESERVE.get() == Some(_slot) {
        return Err(error(Cause::Capacity));
    }
    output
        .try_reserve_exact(count)
        .map_err(|_| error(Cause::Capacity))
}

fn balanced(totals: PairTotals) -> bool {
    totals.entries == totals.returns
        && totals.completed.checked_add(totals.unsampled) == Some(totals.returns)
}

fn pair_matches(
    row: &RawInterval,
    entry: &[u64],
    exit: &[u64],
    state: &State,
    gate: &CallGate,
) -> bool {
    if state.binding.session.history_mode() == HistoryMode::Absolute {
        history::pair_matches_absolute(row, entry, exit, state, gate)
    } else {
        pair_matches_legacy(row, entry, exit, state, gate)
    }
}

fn pair_matches_legacy(
    row: &RawInterval,
    entry: &[u64],
    exit: &[u64],
    state: &State,
    gate: &CallGate,
) -> bool {
    let bits = entry[6];
    let invocation = bits & 0x1fff;
    let prefix = (bits >> 13) & 0x1ff;
    let reason = (bits >> 22) & 3;
    let (kind, generation, owner_matches) = match row.owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation: n,
        } => (
            1,
            generation,
            generation != 0
                && reason == 0
                && n.checked_add(1).and_then(|n| u64::try_from(n).ok()) == Some(invocation)
                && invocation != 0
                && prefix != 0,
        ),
        RawIntervalOwner::InitialDisarmed => (3, 0, reason == 1 && invocation == 0),
        RawIntervalOwner::Removed { generation } => (
            3,
            generation,
            generation != 0 && reason == 2 && invocation == 0 && prefix != 0,
        ),
        RawIntervalOwner::FunctionClosed { generation } => (
            3,
            generation,
            generation != 0 && reason == 3 && invocation == 0 && prefix != 0,
        ),
    };
    owner_matches
        && invocation <= 4096
        && prefix <= 256
        && prefix <= state.binding.limits.actions as u64
        && bits == (invocation | (prefix << 13) | (reason << 22))
        && row.entry_pc == gate.target()
        && gate.declared_returns().contains(&row.return_pc)
        && entry
            == [
                kind,
                row.ordinal,
                row.entry_pc,
                entry[3],
                gate.continuation(),
                generation,
                bits,
            ]
        && exit
            == [
                kind + 1,
                row.ordinal,
                row.return_pc,
                entry[3],
                entry[4],
                generation,
                bits,
            ]
        && entry[3] >= state.stack.start
        && entry[3] & 15 == 8
        && entry[3]
            .checked_add(8)
            .is_some_and(|end| end <= state.stack.end)
}

impl IntervalThread {
    /// Transfer BOTH local buffers after the last successful ordinary invocation.
    ///
    /// This exclusive, same-thread operation neither closes an epoch nor releases
    /// an owner. Lifetime ordinals, counters, registration and history never reset.
    /// The 32-call/64-event bound still applies between explicit drains. A failed
    /// invocation cannot be retried into drain authority. Fixed profiles refuse.
    ///
    /// A tracer must stop this thread before inspecting its journal; resetting
    /// the same page does not promise a coherent concurrent external read.
    pub fn drain_completed(&mut self) -> Result<Option<IntervalBatch>, BridgeError> {
        // All allocation precedes the TLS transaction, including the failure seam.
        let mut rows = Vec::new();
        let mut journal = Vec::new();
        reserve(&mut rows, EVENTS / 2, 0)?;
        reserve(&mut journal, 512, 1)?;
        STATE
            .try_with(|cell| {
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let state = storage.as_mut().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) {
                    return Err(error(Cause::Attachment));
                }
                state.binding.process()?;
                if POISONED.get()
                    || state.failure.is_some()
                    || state.depth != 0
                    || state.model.depth() != 0
                    || state.pairs.iter().any(Option::is_some)
                    || self.finished.get() != Some(state.totals)
                {
                    return Err(error(Cause::Outstanding));
                }
                let gate = state
                    .binding
                    .site
                    .gate
                    .as_ref()
                    .ok_or(error(Cause::ClockProfile))?;
                let gate_sequence = gate.idle_checkpoint().map_err(|e| error(Cause::Gate(e)))?;
                state
                    .timing
                    .as_ref()
                    .ok_or(error(Cause::ClockProfile))?
                    .copy_committed(&mut rows)?;
                // Read every word, including unused tail; no capture/journal exemption.
                journal.extend(state.journal.page.0.iter().map(|word| {
                    // SAFETY: this exclusive TLS borrow owns the entire live page.
                    unsafe { std::ptr::read_volatile(word) }
                }));
                let before = self.drain_cursor;
                let totals = state.totals;
                let sequence = state.model.completed_sequence();
                if !balanced(before.totals)
                    || !balanced(totals)
                    || before.sequence != before.totals.completed
                    || sequence != totals.completed
                    || state.model.identity() != self.registration
                    || totals.entries.checked_add(1) != Some(state.next)
                {
                    return Err(error(Cause::Invariant));
                }
                let count = totals
                    .returns
                    .checked_sub(before.totals.returns)
                    .ok_or(error(Cause::Invariant))?;
                let sampled = totals
                    .completed
                    .checked_sub(before.totals.completed)
                    .ok_or(error(Cause::Invariant))?;
                let unsampled = totals
                    .unsampled
                    .checked_sub(before.totals.unsampled)
                    .ok_or(error(Cause::Invariant))?;
                let first_event = before
                    .totals
                    .returns
                    .checked_mul(2)
                    .ok_or(error(Cause::Capacity))?;
                let last_event = totals
                    .returns
                    .checked_mul(2)
                    .ok_or(error(Cause::Capacity))?;
                if count > (EVENTS / 2) as u64
                    || count != rows.len() as u64
                    || sampled.checked_add(unsampled) != Some(count)
                    || journal[..4] != [count * 2, 0, self.tid, 0]
                    || journal[4 + rows.len() * 14..].iter().any(|&word| word != 0)
                {
                    return Err(error(Cause::Invariant));
                }
                let mut observed_sampled = 0u64;
                for (index, row) in rows.iter().enumerate() {
                    let ordinal = before
                        .totals
                        .returns
                        .checked_add(index as u64)
                        .and_then(|n| n.checked_add(1))
                        .ok_or(error(Cause::Capacity))?;
                    let at = 4 + index * 14;
                    if row.ordinal != ordinal
                        || !pair_matches(
                            row,
                            &journal[at..at + 7],
                            &journal[at + 7..at + 14],
                            state,
                            gate,
                        )
                    {
                        return Err(error(Cause::Invariant));
                    }
                    observed_sampled +=
                        u64::from(matches!(row.owner, RawIntervalOwner::Sampled { .. }));
                }
                if observed_sampled != sampled {
                    return Err(error(Cause::Invariant));
                }
                if count == 0 {
                    return Ok(None);
                }
                let after = Cursor {
                    number: before.number.checked_add(1).ok_or(error(Cause::Capacity))?,
                    totals,
                    sequence,
                };
                let batch = IntervalBatch {
                    stream: history::stream_for(&state.binding),
                    history_end: (state.binding.session.history_mode() == HistoryMode::Absolute)
                        .then(|| state.binding.session.history_committed_end()),
                    pid: self.pid,
                    tid: self.tid,
                    registration: self.registration,
                    install: state.binding.install,
                    function: state.binding.function,
                    before,
                    after,
                    next: state.next,
                    gate_sequence,
                    raw_range: before.totals.returns..totals.returns,
                    event_range: first_event..last_event,
                    rows,
                    journal,
                };
                // Commit: no allocation, callback, model call, fallible operation or
                // destruction of an epoch/receipt owner follows the first write.
                state.timing = Some(timing::Rows::new());
                for index in 0..512 {
                    state.journal.word(index, 0);
                }
                state.journal.header(self.tid, 0);
                self.drain_cursor = after;
                Ok(Some(batch))
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}

#[cfg(test)]
mod tests;

/// Deliberately invalid transport sentinel, not a drain/native receipt. No test
/// may admit this value through the driver cursor or count it as worker success.
#[cfg(test)]
pub(super) fn backoff_transport_sentinel(stream: HistoryStream, marker: u64) -> IntervalBatch {
    IntervalBatch {
        stream: Some(stream),
        history_end: Some(0),
        pid: 0,
        tid: 0,
        registration: 0,
        install: 0,
        function: FunctionId(0),
        before: Cursor::default(),
        after: Cursor {
            number: marker,
            ..Cursor::default()
        },
        next: 0,
        gate_sequence: 0,
        raw_range: 0..0,
        event_range: 0..0,
        rows: Vec::new(),
        journal: vec![marker; 512],
    }
}
