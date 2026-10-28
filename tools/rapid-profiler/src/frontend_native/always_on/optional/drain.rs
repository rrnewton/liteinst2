//! Complete Slow buffers plus distinct physical-call ranges; no bypass samples.
use super::*;
use std::ops::Range;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Cursor {
    number: u64,
    totals: OptionalTotals,
    completed: u64,
}
#[derive(Debug, Eq, PartialEq)]
pub struct OptionalIntervalBatch {
    pid: u32,
    tid: u64,
    registration: u64,
    install: u64,
    function: FunctionId,
    before: Cursor,
    after: Cursor,
    gate_base: u64,
    gate_sequence: u64,
    next: u64,
    rows: Vec<RawInterval>,
    joins: Vec<u64>,
    journal: Vec<u64>,
    stream: Option<HistoryStream>,
    history_end: Option<u64>,
}
impl OptionalIntervalBatch {
    /// None selects the unchanged finite legacy format; this opaque key owns no epoch.
    pub fn history_stream(&self) -> Option<&HistoryStream> {
        self.stream.as_ref()
    }
    /// Committed absolute prefix bound at transfer, not a historical-owner proof.
    pub fn history_high_water(&self) -> Option<u64> {
        self.history_end
    }
    /// A Slow event only. Fast returns have no prefix; replay HistoryBatch to join ownership.
    pub fn history_prefix(&self, event: usize) -> Option<u64> {
        self.stream.as_ref()?;
        if event as u64 >= *self.journal.first()? {
            return None;
        }
        let at = event.checked_mul(7)?.checked_add(10)?;
        history::decode(*self.journal.get(at)?, self.history_end?).map(|(_, prefix, _)| prefix)
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
    pub fn totals(&self) -> (OptionalTotals, OptionalTotals) {
        (self.before.totals, self.after.totals)
    }
    pub fn completed_sequences(&self) -> (u64, u64) {
        (self.before.completed, self.after.completed)
    }
    pub fn physical_range(&self) -> Range<u64> {
        self.before.totals.physical..self.after.totals.physical
    }
    pub fn raw_range(&self) -> Range<u64> {
        self.before.totals.observed.returns..self.after.totals.observed.returns
    }
    pub fn event_range(&self) -> Range<u64> {
        self.before.totals.observed.returns * 2..self.after.totals.observed.returns * 2
    }
    pub fn gate_base(&self) -> u64 {
        self.gate_base
    }
    pub fn gate_sequence(&self) -> u64 {
        self.gate_sequence
    }
    pub fn next_ordinal(&self) -> u64 {
        self.next
    }
    pub fn rows(&self) -> &[RawInterval] {
        &self.rows
    }
    /// Absolute optional gate sequence for each Slow row, including original-call base.
    pub fn observed_gate_sequences(&self) -> &[u64] {
        &self.joins
    }
    /// Complete 512-word page, including the unused zero tail.
    pub fn journal(&self) -> &[u64] {
        &self.journal
    }
}
pub(super) fn pair_matches(row: &RawInterval, entry: &[u64], exit: &[u64], s: &State) -> bool {
    if s.binding.session.history_mode() == HistoryMode::Absolute {
        return history::pair_matches_absolute(row, entry, exit, s);
    }
    let bits = entry[6];
    let invocation = bits & 0x1fff;
    let prefix = (bits >> 13) & 0x1ff;
    let reason = (bits >> 22) & 3;
    let (kind, generation, owner) = match row.owner {
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
    let gate = &s.binding.site.gate;
    owner
        && invocation <= 4096
        && prefix <= 256
        && prefix <= s.binding.limits.actions as u64
        && bits == (invocation | (prefix << 13) | (reason << 22))
        && row.entry_pc == gate.target()
        && gate.returns().contains(&row.return_pc)
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
        && entry[3] >= s.stack.start
        && entry[3] & 15 == 8
        && entry[3]
            .checked_add(8)
            .is_some_and(|end| end <= s.stack.end)
}
impl OptionalThread {
    /// All-or-nothing same-thread transfer after actual physical completion. No
    /// epoch closes and no lifetime sequence/history/registration resets. Fast-only
    /// batches carry counters and a zero-event page, never fabricated raw rows.
    pub fn drain_completed(&mut self) -> Result<Option<OptionalIntervalBatch>, BridgeError> {
        let mut rows = Vec::new();
        let mut joins = Vec::new();
        let mut journal = Vec::new();
        rows.try_reserve_exact(EVENTS / 2)
            .map_err(|_| error(Cause::Capacity))?;
        joins
            .try_reserve_exact(EVENTS / 2)
            .map_err(|_| error(Cause::Capacity))?;
        journal
            .try_reserve_exact(512)
            .map_err(|_| error(Cause::Capacity))?;
        STATE
            .try_with(|cell| {
                let mut b = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let s = b.as_mut().ok_or(error(Cause::Attachment))?;
                if !self.matches(s) || self.finished.get() != Some(s.totals) {
                    return Err(error(Cause::Outstanding));
                }
                s.empty()?;
                let gate_sequence = s
                    .binding
                    .site
                    .gate
                    .idle_checkpoint()
                    .map_err(|e| error(Cause::Gate(e)))?;
                if s.gate_base.checked_add(s.totals.physical) != Some(gate_sequence) {
                    return Err(error(Cause::Invariant));
                }
                s.rows.copy_committed(&mut rows)?;
                journal.extend(
                    s.journal
                        .page
                        .0
                        .iter()
                        .map(|word| unsafe { std::ptr::read_volatile(word) }),
                );
                let before = self.cursor;
                let totals = s.totals;
                let completed = s.model.completed_sequence();
                if !balanced(before.totals)
                    || !balanced(totals)
                    || before.completed != before.totals.observed.completed
                    || completed != totals.observed.completed
                    || s.model.identity() != self.registration
                    || totals.observed.entries.checked_add(1) != Some(s.next)
                {
                    return Err(error(Cause::Invariant));
                }
                let count = totals
                    .observed
                    .returns
                    .checked_sub(before.totals.observed.returns)
                    .ok_or(error(Cause::Invariant))?;
                let sampled = totals
                    .observed
                    .completed
                    .checked_sub(before.totals.observed.completed)
                    .ok_or(error(Cause::Invariant))?;
                let unsampled = totals
                    .observed
                    .unsampled
                    .checked_sub(before.totals.observed.unsampled)
                    .ok_or(error(Cause::Invariant))?;
                let physical = totals
                    .physical
                    .checked_sub(before.totals.physical)
                    .ok_or(error(Cause::Invariant))?;
                let bypassed = totals
                    .bypassed
                    .checked_sub(before.totals.bypassed)
                    .ok_or(error(Cause::Invariant))?;
                // Prove public event_range multiplication cannot overflow before commit.
                before
                    .totals
                    .observed
                    .returns
                    .checked_mul(2)
                    .ok_or(error(Cause::Capacity))?;
                totals
                    .observed
                    .returns
                    .checked_mul(2)
                    .ok_or(error(Cause::Capacity))?;
                if count > 32
                    || count != rows.len() as u64
                    || sampled.checked_add(unsampled) != Some(count)
                    || count.checked_add(bypassed) != Some(physical)
                    || journal[..4] != [count * 2, 0, self.tid, 0]
                    || journal[4 + rows.len() * 14..].iter().any(|&v| v != 0)
                    || s.joins[rows.len()..].iter().any(|&v| v != 0)
                {
                    return Err(error(Cause::Invariant));
                }
                let mut previous = s
                    .gate_base
                    .checked_add(before.totals.physical)
                    .ok_or(error(Cause::Capacity))?;
                let mut observed_sampled = 0;
                for (index, row) in rows.iter().enumerate() {
                    let ordinal = before
                        .totals
                        .observed
                        .returns
                        .checked_add(index as u64)
                        .and_then(|n| n.checked_add(1))
                        .ok_or(error(Cause::Capacity))?;
                    let at = 4 + index * 14;
                    let sequence = s.joins[index];
                    if row.ordinal != ordinal
                        || !pair_matches(row, &journal[at..at + 7], &journal[at + 7..at + 14], s)
                        || sequence <= previous
                        || sequence > gate_sequence
                    {
                        return Err(error(Cause::Invariant));
                    }
                    joins.push(sequence);
                    previous = sequence;
                    observed_sampled +=
                        u64::from(matches!(row.owner, RawIntervalOwner::Sampled { .. }));
                }
                if observed_sampled != sampled {
                    return Err(error(Cause::Invariant));
                }
                if physical == 0 {
                    return Ok(None);
                }
                let after = Cursor {
                    number: before.number.checked_add(1).ok_or(error(Cause::Capacity))?,
                    totals,
                    completed,
                };
                let (stream, history_end) = history::batch_identity(&s.binding)?;
                let batch = OptionalIntervalBatch {
                    stream,
                    history_end,
                    pid: self.pid,
                    tid: self.tid,
                    registration: self.registration,
                    install: s.binding.install,
                    function: s.binding.function,
                    before,
                    after,
                    gate_base: s.gate_base,
                    gate_sequence,
                    next: s.next,
                    rows,
                    joins,
                    journal,
                };
                // Nonfallible storage-only commit. No callback, allocation or owner destruction.
                s.rows = timing::Rows::new();
                s.joins.fill(0);
                for i in 0..512 {
                    s.journal.word(i, 0);
                }
                s.journal.header(self.tid, 0);
                self.cursor = after;
                Ok(Some(batch))
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
