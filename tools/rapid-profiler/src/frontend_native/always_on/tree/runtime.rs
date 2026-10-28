use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Returned {
    pc: u64,
    rsp: u64,
    word: u64,
    value: u64,
    end: RawTimestamp,
}
struct Pair {
    key: Arc<()>,
    function: FunctionId,
    registration: u64,
    ordinal: u64,
    rsp: u64,
    word: u64,
    slot: ModelReturnSlot,
    receipt: IntervalEntry,
    summary: Option<IntervalEntrySummary>,
    gate: Option<gate::GateEntry>,
    start: RawTimestamp,
    start_sequence: Option<u64>,
    entry_pc: u64,
    returned: Option<Returned>,
}
#[derive(Clone, Copy)]
struct Invocation {
    external: u64,
    sequence: u64,
    row: usize,
    event: usize,
}
pub(super) struct State {
    pub binding: Arc<Binding>,
    pub thread: ThreadId,
    pub tid: u64,
    pub registration: u64,
    pub stack: ReadableStack,
    pub model: ThreadModel,
    pub journal: IntervalJournal,
    pub totals: TreeTotals,
    pub next: u64,
    pub gate_base: u64,
    pub rows: [Option<TreeRecord>; EVENTS / 2],
    pub len: usize,
    pairs: [Option<Pair>; 2],
    depth: usize,
    active: Option<Invocation>,
    last_external: u64,
    failure: Option<BridgeError>,
}
impl State {
    pub(super) fn new(
        binding: Arc<Binding>,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
        model: ThreadModel,
        gate_base: u64,
    ) -> Self {
        Self {
            binding,
            thread: thread::current().id(),
            tid: tid(),
            registration,
            stack,
            model,
            journal,
            totals: TreeTotals::default(),
            next: 1,
            gate_base,
            rows: [None; EVENTS / 2],
            len: 0,
            pairs: [None, None],
            depth: 0,
            active: None,
            last_external: 0,
            failure: None,
        }
    }
    pub(super) fn fail(&mut self, e: BridgeError) {
        self.failure.get_or_insert(e);
        self.journal.poison();
    }
    pub(super) fn empty(&self) -> Result<(), BridgeError> {
        self.binding.process()?;
        if TREE_POISON.get()
            || self.failure.is_some()
            || self.depth != 0
            || self.model.depth() != 0
            || self.pairs.iter().any(Option::is_some)
            || self.active.is_some()
        {
            return Err(error(Cause::Outstanding));
        }
        Ok(())
    }
    // Non-reserving admission for exactly eight roots. The ordinary begin still
    // repeats every dynamic reservation check immediately before each real CALL.
    pub(super) fn check_source_batch(&self, ids: &[u64; 8]) -> Result<(), BridgeError> {
        self.empty()?;
        let mut prior = self.last_external;
        for &id in ids {
            if id == 0 || id <= prior {
                return Err(error(Cause::Capacity));
            }
            prior = id;
        }
        if self.len.checked_add(16).is_none_or(|n| n > self.rows.len())
            || self
                .journal
                .used()
                .checked_add(32)
                .is_none_or(|n| n > EVENTS)
            || self.rows[self.len..].iter().any(Option::is_some)
            || self
                .gate_base
                .checked_add(self.totals.roots)
                .and_then(|n| n.checked_add(8))
                .is_none()
            || self.next.checked_add(16).is_none()
            || self.totals.roots.checked_add(8).is_none()
            || self.totals.pairs.entries.checked_add(16).is_none()
            || self.totals.pairs.returns.checked_add(16).is_none()
            || self.totals.pairs.completed.checked_add(16).is_none()
            || self.totals.pairs.unsampled.checked_add(16).is_none()
        {
            return Err(error(Cause::Capacity));
        }
        Ok(())
    }
    pub(super) fn begin(&mut self, external: u64, sequence: u64) -> Result<(), BridgeError> {
        self.empty()?;
        if external == 0
            || external <= self.last_external
            || self.len.checked_add(2).is_none_or(|n| n > self.rows.len())
            || self
                .journal
                .used()
                .checked_add(4)
                .is_none_or(|n| n > EVENTS)
            || self.rows[self.len..].iter().any(Option::is_some)
            || self
                .gate_base
                .checked_add(self.totals.roots)
                .and_then(|n| n.checked_add(1))
                != Some(sequence)
            || self.next.checked_add(2).is_none()
            || self.totals.roots.checked_add(1).is_none()
            || self.totals.pairs.entries.checked_add(2).is_none()
            || self.totals.pairs.returns.checked_add(2).is_none()
            || self.totals.pairs.completed.checked_add(2).is_none()
            || self.totals.pairs.unsampled.checked_add(2).is_none()
        {
            return Err(error(Cause::Capacity));
        }
        self.active = Some(Invocation {
            external,
            sequence,
            row: self.len,
            event: self.journal.used(),
        });
        self.last_external = external;
        Ok(())
    }
    fn read_word(&self, address: u64) -> Result<u64, BridgeError> {
        if address < self.stack.start || address.checked_add(8).is_none_or(|n| n > self.stack.end) {
            return Err(error(Cause::Return));
        }
        // SAFETY: caller-owned actual stack remains readable under unsafe attach.
        Ok(unsafe { (address as usize as *const u64).read_unaligned() })
    }
    pub(super) fn callback(
        &mut self,
        c: &HookContext,
        control: ControlIdentity<'_>,
        role: RoleKind,
        stamp: Option<RawTimestamp>,
    ) -> Result<(), BridgeError> {
        self.binding.process()?;
        if self.failure.is_some()
            || TREE_POISON.get()
            || CONTROLLER_ACTIVE.get()
            || self.thread != thread::current().id()
            || self.tid != tid()
            || !self
                .binding
                .site
                .matches(role, c.instruction_pointer, control)
        {
            return Err(error(Cause::Identity));
        }
        self.active.ok_or(error(Cause::Outstanding))?;
        if role == RoleKind::ChildAck {
            if stamp.is_some() {
                return Err(error(Cause::Invariant));
            }
            let word =
                self.read_word(c.stack_pointer.checked_sub(8).ok_or(error(Cause::Return))?)?;
            return self.ack(c.instruction_pointer, c.stack_pointer, word, c.rax);
        }
        let word = self.read_word(c.stack_pointer)?;
        let stamp = stamp.ok_or(error(Cause::ClockProfile))?;
        match role {
            RoleKind::RootEntry => {
                if self.depth != 0 || self.pairs.iter().any(Option::is_some) {
                    return Err(error(Cause::Return));
                }
                let entered = self
                    .binding
                    .site
                    .gate
                    .enter(c)
                    .map_err(|e| error(Cause::Gate(e)))?;
                self.enter(0, c, word, stamp, Some(entered))
            }
            RoleKind::ChildEntry => self.enter(1, c, word, stamp, None),
            RoleKind::ChildRet => self.observe(1, c, word, stamp),
            RoleKind::RootRet => {
                self.observe(0, c, word, stamp)?;
                let pair = self.pairs[0].as_ref().ok_or(error(Cause::Return))?;
                self.binding
                    .site
                    .gate
                    .observe_return(pair.gate.as_ref().ok_or(error(Cause::Return))?, c)
                    .map_err(|e| error(Cause::Gate(e)))?;
                #[cfg(test)]
                if let Some(pauses) = self.binding.native_pauses.get() {
                    pauses[2].wait(pair.ordinal)?;
                }
                Ok(())
            }
            RoleKind::ChildAck => Err(error(Cause::Invariant)),
        }
    }
    fn enter(
        &mut self,
        node: usize,
        c: &HookContext,
        word: u64,
        start: RawTimestamp,
        gate: Option<gate::GateEntry>,
    ) -> Result<(), BridgeError> {
        let active = self.active.ok_or(error(Cause::Outstanding))?;
        if self.depth != node
            || self.pairs[node].is_some()
            || self.journal.used() != active.event + node
            || self.model.interval_depth_limit() != 2
            || (node == 0) != gate.is_some()
        {
            return Err(error(Cause::Return));
        }
        let expected_pc = if node == 0 {
            self.binding.site.root
        } else {
            self.binding.site.child
        };
        if c.instruction_pointer != expected_pc || c.stack_pointer & 15 != 8 {
            return Err(error(Cause::Return));
        }
        if node == 0 {
            if word != self.binding.site.gate.continuation() {
                return Err(error(Cause::Return));
            }
        } else {
            let parent = self.pairs[0].as_ref().ok_or(error(Cause::Return))?;
            if parent.returned.is_some()
                || parent.rsp.checked_sub(16) != Some(c.stack_pointer)
                || word != self.binding.site.root + 14
                || self.rows[active.row + 1].is_some()
            {
                return Err(error(Cause::Return));
            }
        }
        let ordinal = self.next;
        let next = ordinal.checked_add(1).ok_or(error(Cause::Capacity))?;
        let entries = self
            .totals
            .pairs
            .entries
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        let mut slot = ModelReturnSlot {
            identity: ordinal,
            word: TOKEN,
        };
        let sequence = self.model.completed_sequence();
        let function = self.binding.functions[node];
        let receipt = self
            .model
            .enter_interval_waiting(self.binding.install, function, start.ticks, &mut slot)
            .map_err(|e| error(Cause::Entry(e)))?;
        self.pairs[node] = Some(Pair {
            key: Arc::clone(&self.binding.key),
            function,
            registration: self.registration,
            ordinal,
            rsp: c.stack_pointer,
            word,
            slot,
            receipt,
            summary: None,
            gate,
            start,
            start_sequence: None,
            entry_pc: c.instruction_pointer,
            returned: None,
        });
        self.depth += 1;
        let pair = self.pairs[node].as_mut().ok_or(error(Cause::Invariant))?;
        let summary = pair.receipt.summary().ok_or(error(Cause::Invariant))?;
        pair.summary = Some(summary);
        pair.start_sequence =
            matches!(summary, IntervalEntrySummary::Admitted { .. }).then_some(sequence);
        let (kind, generation, bits) = packed(summary, function)?;
        self.journal.row([
            kind,
            ordinal,
            c.instruction_pointer,
            c.stack_pointer,
            word,
            generation,
            bits,
        ]);
        self.next = next;
        self.totals.pairs.entries = entries;
        self.journal.header(self.tid, self.depth);
        #[cfg(test)]
        if node == 0 {
            if let Some(pauses) = self.binding.native_pauses.get() {
                pauses[0].wait(ordinal)?;
            }
        }
        Ok(())
    }
    fn observe(
        &mut self,
        node: usize,
        c: &HookContext,
        word: u64,
        end: RawTimestamp,
    ) -> Result<(), BridgeError> {
        let active = self.active.ok_or(error(Cause::Outstanding))?;
        let expected_events = active.event + if node == 1 { 2 } else { 3 };
        if self.depth != node + 1 || self.journal.used() != expected_events {
            return Err(error(Cause::Return));
        }
        if node == 0 {
            let child = self.rows[active.row + 1].ok_or(error(Cause::Return))?;
            if self.pairs[1].is_some()
                || child.node != 1
                || child.external_id != active.external
                || c.rax != child.value.wrapping_add(1)
            {
                return Err(error(Cause::Return));
            }
        }
        let pair = self.pairs[node].as_mut().ok_or(error(Cause::Return))?;
        let pc = if node == 0 {
            self.binding.site.root + 22
        } else {
            self.binding.site.child + 38
        };
        if pair.returned.is_some()
            || pair.rsp != c.stack_pointer
            || pair.word != word
            || c.instruction_pointer != pc
            || !Arc::ptr_eq(&pair.key, &self.binding.key)
            || pair.function != self.binding.functions[node]
            || pair.registration != self.registration
            || pair.slot.identity != pair.ordinal
        {
            return Err(error(Cause::Return));
        }
        pair.returned = Some(Returned {
            pc,
            rsp: c.stack_pointer,
            word,
            value: c.rax,
            end,
        });
        #[cfg(test)]
        if node == 1 {
            if let Some(pauses) = self.binding.native_pauses.get() {
                pauses[1].wait(pair.ordinal)?;
            }
        }
        Ok(())
    }
    fn ack(&mut self, pc: u64, rsp: u64, word: u64, value: u64) -> Result<(), BridgeError> {
        let active = self.active.ok_or(error(Cause::Outstanding))?;
        let parent = self.pairs[0].as_ref().ok_or(error(Cause::Return))?;
        let child = self.pairs[1].as_ref().ok_or(error(Cause::Return))?;
        let returned = child.returned.ok_or(error(Cause::Return))?;
        if self.depth != 2
            || parent.returned.is_some()
            || self.journal.used() != active.event + 2
            || pc != self.binding.site.root + 14
            || parent.rsp.checked_sub(8) != Some(rsp)
            || child.rsp.checked_add(8) != Some(rsp)
            || child.word != pc
            || word != pc
            || returned.word != pc
            || returned.value != value
            || self.rows[active.row + 1].is_some()
        {
            return Err(error(Cause::Return));
        }
        let row = self.complete(1, pc, rsp)?;
        self.rows[active.row + 1] = Some(row);
        Ok(())
    }
    fn complete(
        &mut self,
        node: usize,
        resume_pc: u64,
        resume_rsp: u64,
    ) -> Result<TreeRecord, BridgeError> {
        let active = self.active.ok_or(error(Cause::Outstanding))?;
        let pair = self.pairs[node].as_mut().ok_or(error(Cause::Return))?;
        let observed = pair.returned.ok_or(error(Cause::Return))?;
        let summary = pair.summary.ok_or(error(Cause::Invariant))?;
        if self.depth != node + 1
            || !Arc::ptr_eq(&pair.key, &self.binding.key)
            || pair.function != self.binding.functions[node]
            || pair.registration != self.registration
            || pair.slot.identity != pair.ordinal
            || observed.rsp != pair.rsp
            || observed.word != pair.word
        {
            return Err(error(Cause::Return));
        }
        let (kind, generation, bits) = packed(summary, pair.function)?;
        let mut totals = self.totals.pairs;
        totals.returns = totals
            .returns
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        totals.completed = totals
            .completed
            .checked_add(u64::from(kind == 1))
            .ok_or(error(Cause::Capacity))?;
        totals.unsampled = totals
            .unsampled
            .checked_add(u64::from(kind == 3))
            .ok_or(error(Cause::Capacity))?;
        let children = pair
            .start_sequence
            .map(|start| {
                self.model
                    .completed_sequence()
                    .checked_sub(start)
                    .ok_or(error(Cause::Invariant))
            })
            .transpose()?;
        let row = TreeRecord {
            external_id: active.external,
            node: node as u8,
            function: pair.function,
            registration: pair.registration,
            gate_sequence: active.sequence,
            callsite: (node == 1).then_some(self.binding.site.root + 9),
            raw: RawInterval {
                ordinal: pair.ordinal,
                entry_pc: pair.entry_pc,
                return_pc: observed.pc,
                owner: timing::owner(summary),
                start: pair.start,
                end: observed.end,
            },
            entry_rsp: pair.rsp,
            word: pair.word,
            resume_pc,
            resume_rsp,
            value: observed.value,
            summary,
            start_sequence: pair.start_sequence,
            children,
        };
        if self.journal.used() >= EVENTS {
            return Err(error(Cause::Capacity));
        }
        let exit = self
            .model
            .finish_interval(&mut pair.receipt, &mut pair.slot, row.raw.observation())
            .map_err(|e| error(Cause::Exit(e)))?;
        if exit.summary() != summary
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
            observed.pc,
            observed.rsp,
            observed.word,
            generation,
            bits,
        ]);
        self.pairs[node] = None;
        self.depth = node;
        self.totals.pairs = totals;
        self.journal.header(self.tid, self.depth);
        Ok(row)
    }
    pub(super) fn finish_root(
        &mut self,
        call: TreeCallResult,
        before: TreeTotals,
    ) -> Result<TreeTotals, BridgeError> {
        let active = self.active.ok_or(error(Cause::Outstanding))?;
        let root = self.pairs[0].as_ref().ok_or(error(Cause::Return))?;
        let observed = root.returned.ok_or(error(Cause::Return))?;
        let child = self.rows[active.row + 1].ok_or(error(Cause::Return))?;
        let roots = before.roots.checked_add(1).ok_or(error(Cause::Capacity))?;
        if self.failure.is_some()
            || TREE_POISON.get()
            || self.depth != 1
            || self.pairs[1].is_some()
            || self.len != active.row
            || self.rows[active.row].is_some()
            || self.journal.used() != active.event + 3
            || call.external_id != active.external
            || call.gate_sequence != active.sequence
            || call.value != observed.value
            || call.value != child.value.wrapping_add(1)
            || call.return_pc != observed.pc
            || call.entry_rsp != root.rsp
            || root.rsp.checked_add(8) != Some(call.pre_call_rsp)
            || call.resumed_rsp != call.pre_call_rsp
            || before.roots != self.totals.roots
            || before.pairs.entries.checked_add(2) != Some(self.totals.pairs.entries)
            || before.pairs.returns.checked_add(1) != Some(self.totals.pairs.returns)
        {
            return Err(error(Cause::Invariant));
        }
        let row = self.complete(0, self.binding.site.gate.continuation(), call.resumed_rsp)?;
        // Both rows and four events were reserved before CALL; no fallible step
        // follows this whole-tree publication. Gate Ready commits immediately next.
        self.rows[active.row] = Some(row);
        self.len = active.row + 2;
        self.active = None;
        self.totals.roots = roots;
        Ok(self.totals)
    }
}

#[cfg(test)]
mod tests;
