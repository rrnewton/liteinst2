//! One callback-local reuse of already checked normal metadata.
//! The exclusive borrow never escapes; the volatile journal count is reread.
use super::*;

// Only this module can construct or consume a checked state. In particular it
// exposes neither NormalState nor the interior-mutable Session through a view.
struct CheckedVisit<'a> {
    state: &'a mut NormalState,
    journal_used: usize,
}
impl<'a> CheckedVisit<'a> {
    fn new(physical: &PhysicalState, state: &'a mut NormalState) -> Result<Self, BridgeError> {
        // Includes matches(), the full normal shape and the full physical shape.
        // matches() also excludes accuracy/call-pair state from this proof.
        physical.shape(state)?;
        let journal_used = state.len * 2
            + usize::from(state.pending.is_some())
            + usize::from(state.pending.as_ref().is_some_and(|p| p.returned.is_some()));
        Ok(Self {
            state,
            journal_used,
        })
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
    fn return_geometry(&self, selected: SelectedFunction, pc: u64) -> Result<(), BridgeError> {
        let BindingProfile::Module { site, .. } = &self.state.binding.profile else {
            return Err(error(Cause::Identity));
        };
        self.state
            .selected_geometry(selected, site.functions()[selected.index].entry(), Some(pc))
    }
    fn journal_shape(&self) -> Result<(), BridgeError> {
        // All other normal-shape predicates are local immutable metadata since
        // new(); used() is volatile and remains fresh at its old inner position.
        if self.state.journal.used() != self.journal_used {
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

impl PhysicalState {
    pub(super) fn visit(
        &mut self,
        state: &mut NormalState,
        visit: Visit,
    ) -> Result<(), BridgeError> {
        let Visit {
            selected,
            pc,
            rsp,
            word,
            stamp,
            entry,
        } = visit;
        let checked = CheckedVisit::new(self, state)?;
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
            if b.seen[index].is_some() || checked.has_unreturned_pending() {
                return Err(error(Cause::Return));
            }
            let ordinal = checked.next_ordinal();
            checked.enter(selected, pc, rsp, word, stamp)?;
            b.rsp = Some(rsp);
            b.seen[index] = Some(ordinal);
            b.pending_position = Some(index);
        } else {
            checked.return_geometry(selected, pc)?;
            if let Some(ordinal) = b.seen[index] {
                if b.pending_position != Some(index) || checked.pending_return_mismatch(ordinal) {
                    return Err(error(Cause::Return));
                }
                checked.observe(selected, pc, rsp, word, stamp)?;
            } else {
                if checked.has_unreturned_pending() {
                    return Err(error(Cause::Return));
                }
                checked.bypass();
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
