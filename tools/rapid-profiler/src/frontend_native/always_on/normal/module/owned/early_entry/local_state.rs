//! Sealed local physical relationships; current normal/shared state is never cached.
#![forbid(unsafe_code)]
use super::*;
use std::cell::Cell;
use std::ops::Deref;

pub(super) struct RawPhysicalState {
    pub(super) order: [SelectedFunction; 2],
    pub(super) words: [u64; 4],
    pub(super) batches: u64,
    pub(super) calls: u64,
    pub(super) active: Option<PhysicalBatch>,
}
#[derive(Clone, Copy)]
enum Stage {
    Invalid,
    Validated(u64),
    Pending(u64),
}

pub(super) struct LocalState {
    raw: RawPhysicalState,
    stage: Cell<Stage>,
}
impl Deref for LocalState {
    type Target = RawPhysicalState;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}
impl LocalState {
    pub(super) fn new(order: [SelectedFunction; 2], words: [u64; 4]) -> Self {
        Self {
            raw: RawPhysicalState {
                order,
                words,
                batches: 0,
                calls: 0,
                active: None,
            },
            stage: Cell::new(Stage::Invalid),
        }
    }
    // Every generic write invalidates before a mutable reference can escape.
    pub(super) fn raw_mut(&mut self) -> &mut RawPhysicalState {
        self.stage.set(Stage::Invalid);
        &mut self.raw
    }
    pub(super) fn begin(&mut self, before: Baseline, number: u64, owner: Arc<Binding>) {
        let valid = self.raw.batches.checked_add(1) == Some(number);
        let next = before.next;
        self.raw_mut().active = Some(PhysicalBatch {
            number,
            before,
            position: 0,
            rsp: None,
            seen: SeenSlots::empty(),
            rows: RowSlots::with_owner(owner),
            pending_position: None,
        });
        if valid {
            self.stage.set(Stage::Validated(next));
        }
    }
    pub(super) fn complete(&mut self, batches: u64, calls: u64) {
        let raw = self.raw_mut();
        raw.batches = batches;
        raw.calls = calls;
        raw.active = None;
    }
    pub(super) fn visit(&mut self) -> LocalVisit<'_> {
        let prior = match self.stage.replace(Stage::Invalid) {
            Stage::Validated(next) => Some(next),
            Stage::Invalid | Stage::Pending(_) => None,
        };
        LocalVisit {
            raw: &mut self.raw,
            stage: &self.stage,
            prior,
        }
    }
    // Pending is minted only by the exact narrow local updates below. This
    // cannot certify an arbitrary mutable view; raw_mut clears Pending too.
    pub(super) fn accept(&self) {
        if let Stage::Pending(next) = self.stage.get() {
            self.stage.set(Stage::Validated(next));
        }
    }
    #[cfg(test)]
    pub(super) fn is_certified(&self) -> bool {
        matches!(self.stage.get(), Stage::Validated(_))
    }
    pub(super) fn shape(&self, state: &NormalState) -> Result<(), BridgeError> {
        let cached = match self.stage.get() {
            Stage::Validated(next) => Some(next),
            Stage::Invalid | Stage::Pending(_) => None,
        };
        let b = self.active.as_ref().ok_or(error(Cause::Outstanding))?;
        if (cached.is_none()
            && b.number != self.batches.checked_add(1).ok_or(error(Cause::Capacity))?)
            || (cached.is_none() && b.position > 4)
            || state.cursor != b.before.cursor
            || (cached.is_none() && !b.rows.is_prefix(b.position))
            || (cached.is_none() && !b.seen.tail_is_empty(b.position.saturating_add(1).min(4)))
            || state
                .totals
                .entered
                .checked_sub(b.before.cursor.totals.entered)
                != Some(b.seen.count() as u64)
            || state
                .totals
                .ret_observed
                .checked_sub(b.before.cursor.totals.ret_observed)
                != Some(b.rows.observed_count() as u64)
        {
            return Err(error(Cause::Invariant));
        }
        let mut ordinal = b.before.next;
        let mut confirmed = 0;
        for index in 0..4 {
            if let (None, Some(n)) = (cached, b.seen[index]) {
                if n != ordinal {
                    return Err(error(Cause::Invariant));
                }
                ordinal = ordinal.checked_add(1).ok_or(error(Cause::Capacity))?;
            }
            if let Some(row) = b.rows[index] {
                if cached.is_none()
                    && (row.batch != b.number
                        || row.position != index
                        || row.function != self.order[index % 2].function
                        || row.observed_ordinal != b.seen[index]
                        || row.return_word != self.words[index]
                        || Some(row.entry_rsp) != b.rsp)
                {
                    return Err(error(Cause::Invariant));
                }
                let BindingProfile::Module { site, .. } = &state.binding.profile else {
                    return Err(error(Cause::Identity));
                };
                // Preserve canonical-entry indexing (including its original
                // panic) before consulting the exact immutable geometry fact.
                let selected = self.order[index % 2];
                let entry = site.functions()[selected.index].entry();
                if !b
                    .rows
                    .geometry_matches(index, state, selected, entry, row.return_pc)
                {
                    state.selected_geometry(selected, entry, Some(row.return_pc))?;
                }
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
        if state.next != cached.unwrap_or(ordinal) || state.len != confirmed {
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
        if cached.is_none() {
            self.stage.set(Stage::Validated(ordinal));
        }
        Ok(())
    }
}

// This capability exposes only immutable local data. Dropping it after a
// refusal leaves the capsule invalid, including partially changed normal state.
pub(super) struct LocalVisit<'a> {
    raw: &'a mut RawPhysicalState,
    stage: &'a Cell<Stage>,
    prior: Option<u64>,
}
impl Deref for LocalVisit<'_> {
    type Target = RawPhysicalState;
    fn deref(&self) -> &Self::Target {
        self.raw
    }
}
impl<'a> LocalVisit<'a> {
    pub(super) fn entry(self, index: usize, ordinal: u64, rsp: u64) {
        let b = self.raw.active.as_mut().unwrap();
        let prior_seen = b.seen[index]; // bounds before every write
        let next = self
            .prior
            .filter(|next| *next == ordinal)
            .and_then(|next| next.checked_add(1))
            .filter(|_| {
                index == b.position
                    && prior_seen.is_none()
                    && b.rsp.is_none_or(|prior| prior == rsp)
            });
        b.rsp = Some(rsp);
        b.seen.set(index, Some(ordinal));
        b.pending_position = Some(index);
        self.stage.set(next.map_or(Stage::Invalid, Stage::Pending));
    }
    pub(super) fn checked_return(
        self,
        state: &NormalState,
        selected: SelectedFunction,
        pc: u64,
    ) -> Result<CheckedRow<'a>, BridgeError> {
        let b = self.raw.active.as_mut().ok_or(error(Cause::Outstanding))?;
        let index = b.position;
        let expected_function = self.raw.order[index % 2].function;
        let expected_word = self.raw.words[index];
        let seen = b.seen[index];
        let prior_rsp = b.rsp;
        let row = b.rows.checked_return(state, selected, pc)?;
        Ok(CheckedRow {
            row,
            rsp: &mut b.rsp,
            position: &mut b.position,
            stage: self.stage,
            prior: self.prior,
            batch: b.number,
            index,
            expected_function,
            expected_word,
            seen,
            prior_rsp,
        })
    }
}
// The existing full-geometry capability still owns the actual row setter.
// Only this wrapper can update RSP/position with that row and propose local facts.
pub(super) struct CheckedRow<'a> {
    row: physical_slots::CheckedRow<'a>,
    rsp: &'a mut Option<u64>,
    position: &'a mut usize,
    stage: &'a Cell<Stage>,
    prior: Option<u64>,
    batch: u64,
    index: usize,
    expected_function: FunctionId,
    expected_word: u64,
    seen: Option<u64>,
    prior_rsp: Option<u64>,
}
impl CheckedRow<'_> {
    pub(super) fn canonical_entry(&self) -> u64 {
        self.row.canonical_entry()
    }
    pub(super) fn set(self, row: EarlyEntryModulePhysicalRow) {
        let index = self.index;
        let next = self.prior.filter(|_| {
            row.batch == self.batch
                && row.position == index
                && row.function == self.expected_function
                && row.observed_ordinal == self.seen
                && row.return_word == self.expected_word
                && self.prior_rsp.is_none_or(|rsp| rsp == row.entry_rsp)
        });
        *self.rsp = Some(row.entry_rsp);
        self.row.set(index, row);
        *self.position += 1;
        self.stage.set(next.map_or(Stage::Invalid, Stage::Pending));
    }
}
