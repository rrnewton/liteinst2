//! One callback-local reuse of already checked normal metadata.
//! The exclusive borrow never escapes; the volatile journal count is reread.
use super::*;

// Only this module can construct or consume a checked state. In particular it
// exposes neither NormalState nor the interior-mutable Session through a view.
struct CheckedVisit<'a> {
    state: &'a mut NormalState,
}
impl<'a> CheckedVisit<'a> {
    fn new(physical: &PhysicalState, state: &'a mut NormalState) -> Result<Self, BridgeError> {
        // Includes matches(), the full normal shape and the full physical shape.
        // matches() also excludes accuracy/call-pair state from this proof.
        physical.shape(state)?;
        Ok(Self { state })
    }
    fn has_unreturned_pending(&self) -> bool {
        self.state
            .pending
            .as_ref()
            .is_some_and(|p| p.returned.is_none())
    }
    fn next_ordinal(&self) -> u64 {
        self.state.next
    }
    fn pending_return_mismatch(&self, ordinal: u64) -> bool {
        self.state
            .pending
            .as_ref()
            .is_none_or(|p| p.ordinal != ordinal || p.returned.is_some())
    }
    #[inline(always)]
    fn return_geometry<'r>(
        &self,
        rows: &'r mut RowSlots,
        selected: SelectedFunction,
        pc: u64,
    ) -> Result<physical_slots::CheckedRow<'r>, BridgeError> {
        rows.checked_return(self.state, selected, pc)
    }
    fn journal_shape(&self) -> Result<(), BridgeError> {
        // All other normal-shape predicates are local immutable metadata since
        // new(); used() is volatile and remains fresh at its old inner position.
        // Bypasses never need this inner check. The exclusive proof still owns
        // the same unmodified metadata when an observed transition reaches it.
        let journal_used = self.state.len * 2
            + usize::from(self.state.pending.is_some())
            + usize::from(
                self.state
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.returned.is_some()),
            );
        if self.state.journal.used() != journal_used {
            return Err(error(Cause::Invariant));
        }
        Ok(())
    }
    fn enter(
        self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        start: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.state.selected_geometry(selected, pc, None)?;
        self.journal_shape()?;
        self.state.enter_transition(selected, pc, rsp, word, start)
    }
    fn observe(
        self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        end: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.journal_shape()?;
        self.state.observe_transition(selected, pc, rsp, word, end)
    }
    fn bypass(self) {}
}

// A RET certificate owns both exclusive borrows until its postcondition is
// consumed. No mutable view, Session operation, callback or proof clone escapes.
struct CheckedRet<'a> {
    physical: &'a mut PhysicalState,
    state: &'a mut NormalState,
}
struct CommittedRet<'a> {
    checked: CheckedRet<'a>,
    row: EarlyEntryModulePhysicalRow,
}
impl<'a> CheckedRet<'a> {
    fn new(
        physical: &'a mut PhysicalState,
        state: &'a mut NormalState,
    ) -> Result<Self, BridgeError> {
        physical.shape(state)?;
        Ok(Self { physical, state })
    }
    #[inline(always)]
    fn commit(
        self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        stamp: RawTimestamp,
    ) -> Result<CommittedRet<'a>, BridgeError> {
        // This reborrow uses the same full precheck; it cannot outlive commit.
        let checked = CheckedVisit {
            state: &mut *self.state,
        };
        let b = self
            .physical
            .active
            .as_mut()
            .ok_or(error(Cause::Outstanding))?;
        let index = b.position;
        if index >= 4
            || selected != self.physical.order[index % 2]
            || word != self.physical.words[index]
            || b.rsp.is_some_and(|prior| prior != rsp)
        {
            return Err(error(Cause::Return));
        }
        let geometry = checked.return_geometry(&mut b.rows, selected, pc)?;
        if let Some(ordinal) = b.seen[index] {
            if b.pending_position != Some(index) || checked.pending_return_mismatch(ordinal) {
                return Err(error(Cause::Return));
            }
            // With accuracy excluded by the precheck, this changes only the
            // journal, pending.returned and ret_observed. No confirmation or
            // receipt/owner/record/prefix mutation occurs on this transition.
            checked.observe(selected, pc, rsp, word, stamp)?;
        } else {
            if checked.has_unreturned_pending() {
                return Err(error(Cause::Return));
            }
            checked.bypass();
        }
        let row = EarlyEntryModulePhysicalRow {
            batch: b.number,
            position: index,
            function: selected.function,
            observed_ordinal: b.seen[index],
            return_pc: pc,
            entry_rsp: rsp,
            return_word: word,
        };
        b.rsp = Some(rsp);
        geometry.set(index, row);
        b.position += 1;
        Ok(CommittedRet { checked: self, row })
    }
}
impl CommittedRet<'_> {
    #[inline(always)]
    fn finish(self) -> Result<(), BridgeError> {
        let Self { checked, row } = self;
        let CheckedRet { physical, state } = checked;
        // The original full precheck excludes accuracy and owns both states
        // exclusively through this finish. RET changes only pending.returned,
        // ret_observed and the journal; bypass changes no normal metadata.
        // Model/receipt, other totals, next/cursor/len and prefixes stay fixed.
        // Keep fresh process/failed Acquire first, then the changed normal
        // relation and the volatile journal read at their old postcheck positions.
        physical.matches(state)?;
        let outstanding = u64::from(state.pending.is_some());
        let returned = u64::from(state.pending.as_ref().is_some_and(|p| p.returned.is_some()));
        if state.totals.confirmed.checked_add(returned) != Some(state.totals.ret_observed)
            || state.journal.used() != state.len * 2 + outstanding as usize + returned as usize
        {
            return Err(error(Cause::Invariant));
        }
        let b = physical.active.as_ref().ok_or(error(Cause::Outstanding))?;
        // The private constructor establishes every old-prefix predicate. Its
        // only physical writes are the exact new row/RSP/position below, whose
        // complete delta is checked here. Both borrows stay exclusive throughout.
        // seen/order/words/cursors/old rows/records and pending_position never
        // change. Thus old ordinal/confirmed joins remain true, including an
        // earlier Returned owner carried across bypasses. An observed new row is
        // the still-unconfirmed pending row; a bypass contributes no ordinal.
        if b.position != row.position + 1
            || b.rsp != Some(row.entry_rsp)
            || b.rows[row.position] != Some(row)
            || b.seen[row.position] != row.observed_ordinal
        {
            return Err(error(Cause::Invariant));
        }
        Ok(())
    }
}

// Entry may confirm one earlier Returned owner before admitting the new call.
// The proof owns both states across those unchanged transitions; no old physical
// row or existing record can change, and no Session/state view escapes.
struct CheckedEntry<'a> {
    physical: &'a mut PhysicalState,
    state: &'a mut NormalState,
}
struct CommittedEntry<'a> {
    checked: CheckedEntry<'a>,
    index: usize,
    ordinal: u64,
    prior_pending: Option<usize>,
    records_before: usize,
}
impl<'a> CheckedEntry<'a> {
    fn new(
        physical: &'a mut PhysicalState,
        state: &'a mut NormalState,
    ) -> Result<Self, BridgeError> {
        let checked = CheckedVisit::new(physical, state)?;
        Ok(Self {
            physical,
            state: checked.state,
        })
    }
    #[inline(always)]
    fn commit(
        self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        stamp: RawTimestamp,
    ) -> Result<CommittedEntry<'a>, BridgeError> {
        let checked = CheckedVisit {
            state: &mut *self.state,
        };
        let b = self
            .physical
            .active
            .as_mut()
            .ok_or(error(Cause::Outstanding))?;
        let index = b.position;
        if index >= 4
            || selected != self.physical.order[index % 2]
            || word != self.physical.words[index]
            || b.rsp.is_some_and(|prior| prior != rsp)
        {
            return Err(error(Cause::Return));
        }
        if b.seen[index].is_some() || checked.has_unreturned_pending() {
            return Err(error(Cause::Return));
        }
        let ordinal = checked.next_ordinal();
        let prior_pending = b.pending_position;
        let records_before = checked.state.len;
        // Geometry, fresh used(), confirmation, model entry and all error exits
        // remain in their original order. An error here gets no new postcheck:
        // a consumed receipt or partially installed Pending is never retried.
        checked.enter(selected, pc, rsp, word, stamp)?;
        b.rsp = Some(rsp);
        b.seen.set(index, Some(ordinal));
        b.pending_position = Some(index);
        Ok(CommittedEntry {
            checked: self,
            index,
            ordinal,
            prior_pending,
            records_before,
        })
    }
}
impl CommittedEntry<'_> {
    #[inline(always)]
    fn finish(self) -> Result<(), BridgeError> {
        let Self {
            checked,
            index,
            ordinal,
            prior_pending,
            records_before,
        } = self;
        let CheckedEntry { physical, state } = checked;
        physical.matches(state)?;
        // Full pre-shape and this successful exclusive transition establish the
        // unchanged normal facts. Optional confirmation checks balanced totals
        // and actual completed_sequence, then appends both exact prefixes; entry
        // preserves those facts and identity/cursor. reserve_entry proved len.
        // Keep changed counts and actual admitted depth before the fresh used()
        // read, in their old order. Partial confirmation/entry never reaches here.
        let outstanding = u64::from(state.pending.is_some());
        let returned = u64::from(state.pending.as_ref().is_some_and(|p| p.returned.is_some()));
        let sampled = state
            .pending
            .as_ref()
            .and_then(|p| p.summary)
            .is_some_and(|s| matches!(s, IntervalEntrySummary::Admitted { .. }));
        if state.totals.confirmed.checked_add(outstanding) != Some(state.totals.entered)
            || state.totals.confirmed.checked_add(returned) != Some(state.totals.ret_observed)
            || state.totals.entered.checked_add(1) != Some(state.next)
            || state.model.depth() != usize::from(sampled)
            || state.journal.used() != state.len * 2 + outstanding as usize + returned as usize
        {
            return Err(error(Cause::Invariant));
        }
        let b = physical.active.as_ref().ok_or(error(Cause::Outstanding))?;
        // Pre-shape established the complete old prefix and counts. Entry does
        // not change position/rows/cursor or ret_observed; entered and seen grow
        // once. Existing row RSPs stay equal because commit kept the RSP guard.
        if b.position != index || b.seen[index].is_none() || state.totals.entered != ordinal {
            return Err(error(Cause::Invariant));
        }
        if let Some(previous) = prior_pending {
            // Pre-shape deliberately skipped this row's record join while it
            // was pending. Confirmation makes it a newly checked record now.
            // The owner may span bypasses: previous is not necessarily index-1.
            // All earlier record joins and every old row geometry are unchanged.
            let row = b.rows[previous].ok_or(error(Cause::Invariant))?;
            let r = state
                .records
                .get(records_before)
                .and_then(|r| *r)
                .ok_or(error(Cause::Invariant))?;
            if state.functions[records_before] != Some(physical.order[previous % 2])
                || Some(r.raw.ordinal) != row.observed_ordinal
                || r.raw.return_pc != row.return_pc
                || r.entry_rsp != row.entry_rsp
                || r.return_word != row.return_word
            {
                return Err(error(Cause::Invariant));
            }
        }
        // This is the current seen slot's original ordinal/overflow position,
        // after the earlier newly confirmed row, then the final next/len check.
        if b.seen[index] != Some(ordinal) {
            return Err(error(Cause::Invariant));
        }
        let next = ordinal.checked_add(1).ok_or(error(Cause::Capacity))?;
        if state.next != next || state.len != records_before + usize::from(prior_pending.is_some())
        {
            return Err(error(Cause::Invariant));
        }
        // Keep the original final Pending predicates and Return classification.
        match (b.pending_position, &state.pending) {
            (None, None) if b.position == 4 || b.seen[b.position].is_none() => {}
            (Some(index), Some(p)) if index < 4 => {
                if b.seen[index] != Some(p.ordinal)
                    || p.selected != physical.order[index % 2]
                    || p.word != physical.words[index]
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
}

impl PhysicalState {
    pub(super) fn visit(
        &mut self,
        state: &mut NormalState,
        visit: Visit,
    ) -> Result<(), BridgeError> {
        if visit.entry {
            CheckedEntry::new(self, state)?
                .commit(visit.selected, visit.pc, visit.rsp, visit.word, visit.stamp)?
                .finish()
        } else {
            CheckedRet::new(self, state)?
                .commit(visit.selected, visit.pc, visit.rsp, visit.word, visit.stamp)?
                .finish()
        }
    }
}

// Keep the existing full-check methods available throughout normal, exactly as
// before. Only the transition tails are private to this child module, so a
// sibling cannot use a plain &mut NormalState to bypass their shape checks.
impl NormalState {
    pub(in crate::frontend_native::always_on::normal) fn enter_function(
        &mut self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        start: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.selected_geometry(selected, pc, None)?;
        self.shape()?;
        self.enter_transition(selected, pc, rsp, word, start)
    }
    fn enter_transition(
        &mut self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        start: RawTimestamp,
    ) -> Result<(), BridgeError> {
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
        if let Some(accuracy) = &mut self.accuracy {
            accuracy.begin(self.len, selected, self.next)?;
        }
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
    pub(in crate::frontend_native::always_on::normal) fn observe_function(
        &mut self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        end: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.shape()?;
        self.observe_transition(selected, pc, rsp, word, end)
    }
    fn observe_transition(
        &mut self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        end: RawTimestamp,
    ) -> Result<(), BridgeError> {
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
        if let Some(accuracy) = &mut self.accuracy {
            accuracy.end(self.len, selected, p.ordinal)?;
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
}

#[cfg(test)]
mod tests;
