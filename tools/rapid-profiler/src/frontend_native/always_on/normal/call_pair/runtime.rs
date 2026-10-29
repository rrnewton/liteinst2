//! Two real frame receipts. No gate, scheduler, Report prerequisite or stack-slot rewrite.
use super::super::super::frame::{Frame, Identity};
use super::*;
use crate::generation::DeactivationRequest;
use std::thread::ThreadId;

#[derive(Clone, Copy)]
pub(super) struct View<'a> {
    binding: &'a Binding,
    stack: &'a ReadableStack,
    model: &'a ThreadModel,
    journal: &'a IntervalJournal,
    registration: u64,
    tid: u64,
    thread: ThreadId,
}
impl<'a> View<'a> {
    pub(super) fn of(s: &'a NormalState) -> Self {
        Self {
            binding: &s.binding,
            stack: &s.stack,
            model: &s.model,
            journal: &s.journal,
            registration: s.registration,
            tid: s.tid,
            thread: s.actual_thread,
        }
    }
}
pub(super) struct Context<'a> {
    binding: &'a Binding,
    stack: &'a ReadableStack,
    model: &'a mut ThreadModel,
    journal: &'a mut IntervalJournal,
    registration: u64,
    tid: u64,
    thread: ThreadId,
}
impl Context<'_> {
    fn view(&self) -> View<'_> {
        View {
            binding: self.binding,
            stack: self.stack,
            model: self.model,
            journal: self.journal,
            registration: self.registration,
            tid: self.tid,
            thread: self.thread,
        }
    }
}
pub(in crate::frontend_native::always_on::normal) struct State {
    pub(super) frames: [Option<Frame<()>>; 2],
    pub(super) slots: [Option<ModelReturnSlot>; 2],
    pub(super) rows: [Option<NormalCallPairRecord>; 2],
    pub(super) sequence: [u64; 2],
    pub(super) arguments: [u64; 2],
    pub(super) totals: NormalCallPairTotals,
    pub(super) before: NormalCallPairTotals,
    pub(super) number: u64,
    pub(super) next: u64,
}
impl State {
    pub(super) fn new() -> Self {
        Self {
            frames: [None, None],
            slots: [None; 2],
            rows: [None; 2],
            sequence: [0; 2],
            arguments: [0; 2],
            totals: NormalCallPairTotals::default(),
            before: NormalCallPairTotals::default(),
            number: 0,
            next: 1,
        }
    }
    pub(super) fn empty(&self) -> bool {
        self.frames.iter().all(Option::is_none) && self.rows.iter().all(Option::is_none)
    }
    pub(super) fn depth(&self) -> usize {
        self.frames.iter().filter(|p| p.is_some()).count()
    }
    fn words(
        v: View<'_>,
        function: FunctionId,
        summary: IntervalEntrySummary,
        ordinal: u64,
        [entry, rsp, word]: [u64; 3],
        returned: Option<u64>,
    ) -> Result<[u64; 7], BridgeError> {
        let (kind, generation, bits) =
            history::packed_for_function(&v.binding.session, function, summary)?;
        if prefix(summary) > v.binding.session.history_committed_end() {
            return Err(error(Cause::Invariant));
        }
        Ok([
            kind + u64::from(returned.is_some()),
            ordinal,
            returned.unwrap_or(entry),
            rsp,
            word,
            generation,
            bits,
        ])
    }
    // Regenerate every word from live receipt summaries / completed immutable
    // rows, not just a used prefix. This preflight never consumes a receipt.
    fn expected_page(&self, v: View<'_>) -> Result<[u64; 512], BridgeError> {
        let mut page = [0u64; 512];
        page[2] = v.tid;
        page[3] = self.depth() as u64;
        let mut events = [None; 4];
        for node in 0..2 {
            if let Some(p) = &self.frames[node] {
                let summary = p.summary.ok_or(error(Cause::Invariant))?;
                events[node] = Some(Self::words(
                    v,
                    p.function,
                    summary,
                    p.ordinal,
                    [p.entry_pc, p.rsp, p.word],
                    None,
                )?);
                if let Some(r) = p.returned {
                    events[3 - node] = Some(Self::words(
                        v,
                        p.function,
                        summary,
                        p.ordinal,
                        [p.entry_pc, p.rsp, p.word],
                        Some(r.pc),
                    )?);
                }
            } else if let Some(r) = self.rows[node] {
                events[node] = Some(Self::words(
                    v,
                    r.function,
                    r.summary,
                    r.raw.ordinal,
                    [r.raw.entry_pc, r.entry_rsp, r.return_word],
                    None,
                )?);
                events[3 - node] = Some(Self::words(
                    v,
                    r.function,
                    r.summary,
                    r.raw.ordinal,
                    [r.raw.entry_pc, r.entry_rsp, r.return_word],
                    Some(r.raw.return_pc),
                )?);
            }
        }
        let used = events.iter().take_while(|e| e.is_some()).count();
        if events[used..].iter().any(Option::is_some) {
            return Err(error(Cause::Invariant));
        }
        page[0] = used as u64;
        for (i, event) in events.into_iter().take(used).enumerate() {
            page[4 + i * 7..11 + i * 7].copy_from_slice(&event.ok_or(error(Cause::Invariant))?);
        }
        Ok(page)
    }
    pub(super) fn validate(&self, v: View<'_>) -> Result<(), BridgeError> {
        v.binding.process()?;
        let (site, functions) = table(v.binding)?;
        let sampled = self
            .frames
            .iter()
            .flatten()
            .filter(|p| matches!(p.summary, Some(IntervalEntrySummary::Admitted { .. })))
            .count();
        if v.registration == 0
            || v.thread != thread::current().id()
            || v.tid != tid()
            || v.model.interval_depth_limit() != 2
            || v.model.depth() != sampled
            || v.model.completed_sequence() != self.totals.pairs.completed
            || self.next
                != self
                    .totals
                    .pairs
                    .entered
                    .checked_add(1)
                    .ok_or(error(Cause::Capacity))?
            || !balanced(self.before.pairs)
            || self.before.roots != self.number
            || self.before.roots.checked_mul(2) != Some(self.before.pairs.entered)
            || self.before.child_acks != self.before.roots
            || self.rows[0].is_some()
        {
            return Err(error(Cause::Invariant));
        }
        let entries = self.frames.iter().filter(|p| p.is_some()).count()
            + self.rows.iter().filter(|p| p.is_some()).count();
        let observed = self
            .frames
            .iter()
            .flatten()
            .filter(|p| p.returned.is_some())
            .count()
            + self.rows.iter().filter(|p| p.is_some()).count();
        let confirmed = self.rows.iter().filter(|p| p.is_some()).count();
        if self.totals.roots != self.before.roots
            || self.before.pairs.entered.checked_add(entries as u64)
                != Some(self.totals.pairs.entered)
            || self.before.pairs.ret_observed.checked_add(observed as u64)
                != Some(self.totals.pairs.ret_observed)
            || self.before.pairs.confirmed.checked_add(confirmed as u64)
                != Some(self.totals.pairs.confirmed)
            || self
                .before
                .child_acks
                .checked_add(u64::from(self.rows[1].is_some()))
                != Some(self.totals.child_acks)
            || self.before.pairs.completed.checked_add(
                self.rows
                    .iter()
                    .flatten()
                    .filter(|r| r.completion.is_some())
                    .count() as u64,
            ) != Some(self.totals.pairs.completed)
            || self.before.pairs.unsampled.checked_add(
                self.rows
                    .iter()
                    .flatten()
                    .filter(|r| r.completion.is_none())
                    .count() as u64,
            ) != Some(self.totals.pairs.unsampled)
            || self
                .totals
                .pairs
                .completed
                .checked_add(self.totals.pairs.unsampled)
                != Some(self.totals.pairs.confirmed)
            || (self.frames[0].is_none() && !self.empty())
            || (self.frames[1].is_some() && self.rows[1].is_some())
        {
            return Err(error(Cause::Invariant));
        }
        let root_ordinal = self
            .before
            .pairs
            .entered
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        for (node, &function) in functions.iter().enumerate() {
            if let Some(p) = &self.frames[node] {
                let summary = p.summary.ok_or(error(Cause::Invariant))?;
                if !Arc::ptr_eq(&p.key, &v.binding.key)
                    || p.function != function
                    || p.registration != v.registration
                    || p.ordinal != root_ordinal + node as u64
                    || p.slot.identity != p.ordinal
                    || Some(p.slot) != self.slots[node]
                    || p.receipt.summary() != Some(summary)
                    || p.entry_pc != site.functions()[node].entry()
                    || !stack_word_ok(v.stack, p.rsp, p.word)
                    || p.start_sequence
                        != matches!(summary, IntervalEntrySummary::Admitted { .. })
                            .then_some(self.sequence[node])
                    || self.sequence[node] != self.before.pairs.completed
                {
                    return Err(error(Cause::Invariant));
                }
                if let Some(r) = p.returned {
                    if r.rsp != p.rsp
                        || r.word != p.word
                        || !site.functions()[node].returns().contains(&r.pc)
                    {
                        return Err(error(Cause::Return));
                    }
                }
                Self::words(
                    v,
                    p.function,
                    summary,
                    p.ordinal,
                    [p.entry_pc, p.rsp, p.word],
                    None,
                )?;
            } else if self.slots[node].is_some() {
                return Err(error(Cause::Invariant));
            }
        }
        if let Some(parent) = &self.frames[0] {
            if let Some(child) = &self.frames[1] {
                if parent.rsp.checked_sub(site.child_stack_delta()) != Some(child.rsp)
                    || child.word != site.edge().continuation()
                    || parent.returned.is_some()
                {
                    return Err(error(Cause::Return));
                }
            }
            if let Some(child) = self.rows[1] {
                if child.node != 1
                    || child.function != functions[1]
                    || child.parent_ordinal != parent.ordinal
                    || child.raw.ordinal != parent.ordinal + 1
                    || child.raw.entry_pc != site.functions()[1].entry()
                    || !site.functions()[1].returns().contains(&child.raw.return_pc)
                    || parent.rsp.checked_sub(site.child_stack_delta()) != Some(child.entry_rsp)
                    || child.return_word != site.edge().continuation()
                    || child.resume_pc != child.return_word
                    || child.entry_rsp.checked_add(8) != Some(child.resume_rsp)
                    || child.ack != NormalCallPairAcknowledgement::ChildContinuation
                    || child.sequence_before != self.sequence[1]
                    || child.sampled_children != child.completion.map(|_| 0)
                    || child.raw.owner != timing::owner(child.summary)
                    || !record_outcome_ok(&child, v.registration)
                {
                    return Err(error(Cause::Invariant));
                }
                if parent
                    .returned
                    .is_some_and(|r| r.value != (self.arguments[1].wrapping_shl(32) | child.value))
                {
                    return Err(error(Cause::Return));
                }
            } else if parent.returned.is_some() {
                return Err(error(Cause::Return));
            }
        }
        if self.expected_page(v)? != journal_copy(v.journal) {
            return Err(error(Cause::Invariant));
        }
        Ok(())
    }
    pub(super) fn entry(
        &mut self,
        x: &mut Context<'_>,
        node: usize,
        c: &HookContext,
        word: u64,
        start: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.validate(x.view())?;
        let (site, functions) = table(x.binding)?;
        if node > 1
            || self.depth() != node
            || self.frames[node].is_some()
            || self.rows[node].is_some()
            || c.instruction_pointer != site.functions()[node].entry()
            || !stack_word_ok(x.stack, c.stack_pointer, word)
        {
            return Err(error(Cause::Return));
        }
        if node == 0 {
            if !self.empty()
                || x.journal.used() != 0
                || self.next.checked_add(2).is_none()
                || self.number.checked_add(1).is_none()
                || self.totals.roots.checked_add(1).is_none()
                || self.totals.child_acks.checked_add(1).is_none()
                || self.totals.pairs.entered.checked_add(2).is_none()
                || self.totals.pairs.ret_observed.checked_add(2).is_none()
                || self.totals.pairs.confirmed.checked_add(2).is_none()
                || self.totals.pairs.completed.checked_add(2).is_none()
                || self.totals.pairs.unsampled.checked_add(2).is_none()
            {
                return Err(error(Cause::Capacity));
            }
        } else {
            let parent = self.frames[0].as_ref().ok_or(error(Cause::Return))?;
            if parent.returned.is_some()
                || parent.rsp.checked_sub(site.child_stack_delta()) != Some(c.stack_pointer)
                || word != site.edge().continuation()
                || [c.rdi, c.rsi] != self.arguments
                || x.journal.used() != 1
            {
                return Err(error(Cause::Return));
            }
        }
        let ordinal = self.next;
        let mut slot = ModelReturnSlot {
            identity: ordinal,
            word: TOKEN,
        };
        let sequence = x.model.completed_sequence();
        let receipt = x
            .model
            .enter_interval_waiting(x.binding.install, functions[node], start.ticks, &mut slot)
            .map_err(|e| error(Cause::Entry(e)))?;
        // Retain the real receipt immediately, before every fallible post-acquire check.
        self.frames[node] = Some(Frame {
            key: Arc::clone(&x.binding.key),
            function: functions[node],
            registration: x.registration,
            ordinal,
            rsp: c.stack_pointer,
            word,
            slot,
            receipt,
            summary: None,
            gate: (),
            start,
            start_sequence: None,
            entry_pc: c.instruction_pointer,
            returned: None,
        });
        self.slots[node] = Some(slot);
        self.sequence[node] = sequence;
        let p = self.frames[node].as_mut().ok_or(error(Cause::Invariant))?;
        let summary = p.receipt.summary().ok_or(error(Cause::Invariant))?;
        p.summary = Some(summary);
        p.start_sequence =
            matches!(summary, IntervalEntrySummary::Admitted { .. }).then_some(sequence);
        let words = Self::words(
            x.view(),
            p.function,
            summary,
            ordinal,
            [p.entry_pc, p.rsp, p.word],
            None,
        )?;
        if node == 0 {
            self.arguments = [c.rdi, c.rsi];
        }
        x.journal.row(words);
        self.next += 1;
        self.totals.pairs.entered += 1;
        x.journal.header(x.tid, self.depth());
        Ok(())
    }
    pub(super) fn observe(
        &mut self,
        x: &mut Context<'_>,
        node: usize,
        c: &HookContext,
        word: u64,
        end: RawTimestamp,
    ) -> Result<(), BridgeError> {
        self.validate(x.view())?;
        let (site, functions) = table(x.binding)?;
        if node > 1
            || self.depth() != node + 1
            || x.journal.used() != if node == 1 { 2 } else { 3 }
            || !site.functions()[node]
                .returns()
                .contains(&c.instruction_pointer)
        {
            return Err(error(Cause::Return));
        }
        if node == 0 {
            let child = self.rows[1].ok_or(error(Cause::Return))?;
            if self.frames[1].is_some()
                || c.rax != (self.arguments[1].wrapping_shl(32) | child.value)
            {
                return Err(error(Cause::Return));
            }
        }
        let p = self.frames[node].as_mut().ok_or(error(Cause::Return))?;
        p.observe(
            c,
            word,
            end,
            c.instruction_pointer,
            Identity {
                key: &x.binding.key,
                function: functions[node],
                registration: x.registration,
            },
        )?;
        let words = Self::words(
            x.view(),
            p.function,
            p.summary.ok_or(error(Cause::Invariant))?,
            p.ordinal,
            [p.entry_pc, p.rsp, p.word],
            Some(c.instruction_pointer),
        )?;
        x.journal.row(words);
        self.totals.pairs.ret_observed += 1;
        Ok(())
    }
    pub(super) fn prepare_completion(
        &self,
        x: &Context<'_>,
        node: usize,
        resume_pc: u64,
        resume_rsp: u64,
    ) -> Result<NormalCallPairRecord, BridgeError> {
        self.validate(x.view())?;
        let (_, functions) = table(x.binding)?;
        let p = self.frames[node].as_ref().ok_or(error(Cause::Return))?;
        let returned = p.returned.ok_or(error(Cause::Return))?;
        let summary = p.summary.ok_or(error(Cause::Invariant))?;
        if self.depth() != node + 1
            || p.function != functions[node]
            || p.rsp.checked_add(8) != Some(resume_rsp)
            || p.word != resume_pc
        {
            return Err(error(Cause::Return));
        }
        let children = p
            .start_sequence
            .map(|start| {
                x.model
                    .completed_sequence()
                    .checked_sub(start)
                    .ok_or(error(Cause::Invariant))
            })
            .transpose()?;
        let child_sampled =
            u64::from(node == 0 && self.rows[1].is_some_and(|r| r.completion.is_some()));
        if children.is_some_and(|n| n != child_sampled) {
            return Err(error(Cause::Invariant));
        }
        Ok(NormalCallPairRecord {
            function: p.function,
            node,
            parent_ordinal: self.before.pairs.entered + 1,
            raw: RawInterval {
                ordinal: p.ordinal,
                entry_pc: p.entry_pc,
                return_pc: returned.pc,
                owner: timing::owner(summary),
                start: p.start,
                end: returned.end,
            },
            entry_rsp: p.rsp,
            return_word: p.word,
            resume_pc,
            resume_rsp,
            value: returned.value,
            ack: if node == 1 {
                NormalCallPairAcknowledgement::ChildContinuation
            } else {
                NormalCallPairAcknowledgement::CallerCheckpoint
            },
            summary,
            sequence_before: self.sequence[node],
            sampled_children: children,
            completion: None,
            payload: None,
            k: x.binding.limits.records_per_epoch / 2,
        })
    }
    fn consume(
        &mut self,
        x: &mut Context<'_>,
        mut row: NormalCallPairRecord,
    ) -> Result<NormalCallPairRecord, BridgeError> {
        let node = row.node;
        let peers = self.frames.iter().enumerate().filter(|(i, p)| *i != node && p.as_ref().is_some_and(|p| {
            matches!((p.summary, row.summary), (Some(IntervalEntrySummary::Admitted { generation: a, .. }), IntervalEntrySummary::Admitted { generation: b, .. }) if a == b)
        })).count();
        // prepare_completion/ack/transfer performed all observable checks. This
        // private method consumes once; any postcondition failure is irreversible.
        let p = self.frames[node].as_mut().ok_or(error(Cause::Invariant))?;
        let result =
            super::super::super::frame::finish(p, x.model, row.raw.observation(), row.summary)?;
        if !finished_function_matches(result, row.function) {
            return Err(error(Cause::Invariant));
        }
        match result {
            IntervalExit::Completed {
                completion,
                payload,
                ..
            } => {
                row.completion = Some(completion);
                row.payload = Some(payload);
            }
            IntervalExit::Unsampled { .. } => {}
        }
        if !record_outcome_ok(&row, x.registration)
            || row
                .completion
                .is_some_and(|c| c.other_reservations_after_close.is_some_and(|n| n != peers))
            || x.model.completed_sequence()
                != self.totals.pairs.completed + u64::from(row.completion.is_some())
        {
            return Err(error(Cause::Invariant));
        }
        self.frames[node] = None;
        self.slots[node] = None;
        self.totals.pairs.confirmed += 1;
        self.totals.pairs.completed += u64::from(row.completion.is_some());
        self.totals.pairs.unsampled += u64::from(row.completion.is_none());
        x.journal.header(x.tid, self.depth());
        Ok(row)
    }
    pub(super) fn ack(
        &mut self,
        x: &mut Context<'_>,
        pc: u64,
        rsp: u64,
        word: u64,
        value: u64,
    ) -> Result<(), BridgeError> {
        self.validate(x.view())?;
        let (site, _) = table(x.binding)?;
        let parent = self.frames[0].as_ref().ok_or(error(Cause::Return))?;
        let child = self.frames[1].as_ref().ok_or(error(Cause::Return))?;
        let returned = child.returned.ok_or(error(Cause::Return))?;
        if self.depth() != 2
            || parent.returned.is_some()
            || self.rows[1].is_some()
            || x.journal.used() != 3
            || pc != site.edge().continuation()
            || parent
                .rsp
                .checked_add_signed(i64::from(site.call_rsp_offset()))
                != Some(rsp)
            || child.rsp.checked_add(8) != Some(rsp)
            || child.word != pc
            || word != pc
            || returned.word != pc
            || returned.value != value
        {
            return Err(error(Cause::Return));
        }
        let row = self.prepare_completion(x, 1, pc, rsp)?;
        let row = self.consume(x, row)?;
        self.rows[1] = Some(row);
        self.totals.child_acks += 1;
        Ok(())
    }
    pub(super) fn transfer(
        &mut self,
        x: &mut Context<'_>,
    ) -> Result<Option<NormalCallPairBatch>, BridgeError> {
        self.validate(x.view())?;
        if self.empty() {
            return Ok(None);
        }
        let root = self.frames[0].as_ref().ok_or(error(Cause::Return))?;
        let root_row = self.prepare_completion(
            x,
            0,
            root.word,
            root.rsp.checked_add(8).ok_or(error(Cause::Return))?,
        )?;
        let child = self.rows[1].ok_or(error(Cause::Return))?;
        if self.frames[1].is_some() || x.journal.used() != 4 {
            return Err(error(Cause::Return));
        }
        let number = self.number.checked_add(1).ok_or(error(Cause::Capacity))?;
        let stream = stream::stream_for(x.binding).ok_or(error(Cause::Identity))?;
        let history_end = x.binding.session.history_committed_end();
        // All output storage is fixed and materialized before final consumption.
        let mut batch = NormalCallPairBatch {
            pid: x.binding.pid,
            tid: x.tid,
            registration: x.registration,
            install: x.binding.install,
            stream,
            number,
            before: self.before,
            after: self.totals,
            history_end,
            records: [root_row, child],
            journal: journal_copy(x.journal),
        };
        let root_row = self.consume(x, root_row)?;
        self.totals.roots += 1;
        batch.records[0] = root_row;
        batch.after = self.totals;
        batch.journal[3] = 0;
        self.rows = [None; 2];
        self.sequence = [0; 2];
        self.arguments = [0; 2];
        self.number = number;
        self.before = self.totals;
        for i in 0..512 {
            x.journal.word(i, 0);
        }
        x.journal.header(x.tid, 0);
        Ok(Some(batch))
    }
}
pub(super) fn record_outcome_ok(row: &NormalCallPairRecord, registration: u64) -> bool {
    match row.summary {
        IntervalEntrySummary::Admitted {
            generation,
            invocation,
            ..
        } => {
            let (Some(c), Some(p), Some(children)) =
                (row.completion, row.payload, row.sampled_children)
            else {
                return false;
            };
            let admission = Admission {
                generation,
                invocation,
                function: row.function,
                entry_value: row.raw.start.ticks,
            };
            let Disposition::Retained { rank } = c.disposition else {
                return false;
            };
            c.admission == admission
                && rank < row.k
                && invocation < row.k * 2
                && p == (Payload {
                    admission,
                    thread: registration,
                    start_sequence: row.sequence_before,
                    outcome: PayloadOutcome::Completed {
                        end: row.raw.observation(),
                        completed_children: children,
                    },
                })
                && children <= u64::from(row.node == 0)
                && if rank + 1 == row.k {
                    c.deactivate
                        == Some(DeactivationRequest {
                            generation,
                            function: row.function,
                        })
                        && c.other_reservations_after_close.is_some_and(|n| n <= 1)
                } else {
                    c.deactivate.is_none() && c.other_reservations_after_close.is_none()
                }
        }
        IntervalEntrySummary::Unsampled { reason, .. } => {
            row.completion.is_none()
                && row.payload.is_none()
                && row.sampled_children.is_none()
                && match reason {
                    UnsampledSummary::FunctionClosed { function, .. } => function == row.function,
                    _ => true,
                }
        }
    }
}
fn journal_copy(journal: &IntervalJournal) -> [u64; 512] {
    // SAFETY: only this attached thread owns/writes the complete retained page.
    std::array::from_fn(|i| unsafe { journal.page.0.as_ptr().add(i).read_volatile() })
}
// Pure exact envelope arithmetic, shared by actual callbacks and hostile controls.
// Writability/full callback-stack headroom remain the explicit unsafe attach proof.
pub(super) fn envelope(
    stack: &ReadableStack,
    rsp: u64,
    context: u64,
    prefix: u64,
    layout: SavedExtendedStateLayout,
    [image, len, mask, format]: [u64; 4],
) -> bool {
    let Some(align) = layout.format().required_alignment() else {
        return false;
    };
    let expected = (context & !(align - 1)).checked_sub(layout.len());
    stack.start != 0
        && !layout.is_empty()
        && rsp.checked_sub(prefix) == Some(context)
        && context >= stack.start
        && context
            .checked_add(176)
            .is_some_and(|end| end <= rsp && end <= stack.end)
        && rsp.checked_add(8).is_some_and(|end| end <= stack.end)
        && len == layout.len()
        && mask == layout.mask()
        && format == layout.format().raw()
        && expected == Some(image)
        && image >= stack.start
        && image < context
        && image.checked_add(len).is_some_and(|end| end <= context)
}
fn read_word(stack: &ReadableStack, address: u64) -> Result<u64, BridgeError> {
    if address < stack.start || address.checked_add(8).is_none_or(|end| end > stack.end) {
        return Err(error(Cause::Return));
    }
    // SAFETY: actual live stack under the continuously readable+writable attachment.
    Ok(unsafe { (address as usize as *const u64).read_unaligned() })
}
pub(super) fn callback(
    state: &mut NormalState,
    c: &HookContext,
    control: ControlIdentity<'_>,
    role: Role,
    stamp: Option<RawTimestamp>,
) -> Result<(), BridgeError> {
    state.binding.process()?;
    let (site, _) = table(&state.binding)?;
    let descriptor = c.saved_extended_state();
    if state.actual_thread != thread::current().id()
        || state.tid != tid()
        || !site.resolve(c.instruction_pointer, control, role)
        || !envelope(
            &state.stack,
            c.stack_pointer,
            c as *const HookContext as usize as u64,
            site.stack_profile().context_stack_prefix_bytes() as u64,
            site.layout(),
            [
                descriptor.address(),
                descriptor.len(),
                descriptor.mask(),
                descriptor.format().raw(),
            ],
        )
    {
        return Err(error(Cause::Identity));
    }
    let word = read_word(
        &state.stack,
        if role == Role::ChildAck {
            c.stack_pointer.checked_sub(8).ok_or(error(Cause::Return))?
        } else {
            c.stack_pointer
        },
    )?;
    with_context(state, |pair, x| {
        if role == Role::ChildAck {
            if stamp.is_some() {
                return Err(error(Cause::Invariant));
            }
            return pair.ack(x, c.instruction_pointer, c.stack_pointer, word, c.rax);
        }
        let stamp = stamp.ok_or(error(Cause::ClockProfile))?;
        match role {
            Role::ParentEntry => pair.entry(x, 0, c, word, stamp),
            Role::ChildEntry => pair.entry(x, 1, c, word, stamp),
            Role::ChildRet => pair.observe(x, 1, c, word, stamp),
            Role::ParentRet => pair.observe(x, 0, c, word, stamp),
            Role::ChildAck => Err(error(Cause::Invariant)),
        }
    })
}
pub(super) fn with_context<T>(
    s: &mut NormalState,
    operation: impl FnOnce(&mut State, &mut Context<'_>) -> Result<T, BridgeError>,
) -> Result<T, BridgeError> {
    let NormalState {
        binding,
        stack,
        model,
        journal,
        registration,
        tid,
        actual_thread,
        call_pair,
        ..
    } = s;
    let pair = call_pair.as_mut().ok_or(error(Cause::Attachment))?;
    let mut x = Context {
        binding,
        stack,
        model,
        journal,
        registration: *registration,
        tid: *tid,
        thread: *actual_thread,
    };
    operation(pair, &mut x)
}
pub(super) fn transfer(s: &mut NormalState) -> Result<Option<NormalCallPairBatch>, BridgeError> {
    with_context(s, |pair, x| pair.transfer(x))
}

pub(super) fn transfer_checked(
    state: &mut NormalState,
) -> Result<Option<NormalCallPairBatch>, BridgeError> {
    state.health()?;
    state.busy = true;
    match transfer(state) {
        Ok(batch) => {
            state.busy = false;
            Ok(batch)
        }
        Err(e) => Err(state.fail(e)),
    }
}
