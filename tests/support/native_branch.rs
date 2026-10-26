//! Fixed two-exit grammar, using the existing borrowed owner and comparator.
//! Every original instruction is checked against an independent ISA effect.
//! The old CALL, snapshot, cleanup, step/deadline and history helpers stay exact.
use super::*;

const HEADS: [u64; 11] = [0, 5, 12, 15, 19, 21, 24, 27, 28, 32, 35];
const REWRITTEN: [u64; 7] = [0, 21, 24, 27, 28, 32, 35];

pub struct TwoExitCohortTrace {
    inner: CohortTrace,
}

pub struct BorrowedTwoExitOracle {
    borrowed: BorrowedLeafOracle,
    bias_object: u64,
}

impl BorrowedTwoExitOracle {
    /// # Safety
    /// The complete page and immutable ranges are live, readable ld.so owners
    /// retained for process lifetime. Publication is quiescent and exclusive.
    pub unsafe fn new(
        page: u64,
        entry: u64,
        invoke: u64,
        terminal: u64,
        bias_pointer: u64,
        bias_object: u64,
        immutable: &[(u64, usize)],
    ) -> Self {
        let page_end = page.checked_add(PAGE as u64).unwrap();
        let body_end = entry.checked_add(36).unwrap();
        assert!(entry >= page && body_end <= page_end);
        assert!(invoke >= body_end && invoke.checked_add(5) == Some(terminal));
        assert!(terminal < page_end);
        for &(address, len) in immutable {
            assert!(len > 0 && len <= 65536);
            assert!(address.checked_add(len as u64).is_some());
        }
        let borrowed = unsafe { BorrowedLeafOracle::new(page, entry, invoke, terminal, immutable) };
        let offset = usize::try_from(entry - page).unwrap();
        let body = &borrowed.inner.original_code[offset..offset + 36];
        assert_eq!(
            &body[..8],
            &[0x48, 0x8d, 0x44, 0x7f, 0x07, 0x4c, 0x8b, 0x15]
        );
        let displacement = i32::from_le_bytes(body[8..12].try_into().unwrap());
        assert_eq!(
            i128::from(entry) + 12 + i128::from(displacement),
            i128::from(bias_pointer),
            "fixed MOV reaches the declared relocated pointer"
        );
        assert_eq!(
            &body[12..],
            &[
                0x49, 0x03, 0x02, 0x48, 0x83, 0xff, 0x00, 0x75, 0x07, 0x48, 0x8d, 0x00, 0x48, 0x89,
                0x06, 0xc3, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x89, 0x06, 0xc3,
            ]
        );
        assert_eq!(immutable_word(&borrowed, bias_pointer), bias_object);
        assert_eq!(immutable_word(&borrowed, bias_object), 11);
        Self {
            borrowed,
            bias_object,
        }
    }

    pub fn stack_range(&self) -> (u64, u64) {
        self.borrowed.stack_range()
    }

    pub fn rsp(&self) -> u64 {
        self.borrowed.rsp()
    }

    pub fn terminal(&self) -> u64 {
        self.borrowed.terminal()
    }

    pub fn exit_for(&self, argument: u64) -> u64 {
        assert!(
            argument <= 1,
            "only the fixed zero/nonzero domain is admitted"
        );
        self.borrowed.entry + if argument == 0 { 27 } else { 35 }
    }

    pub fn heads_for(&self, argument: u64) -> [u64; 9] {
        assert!(
            argument <= 1,
            "only the fixed zero/nonzero domain is admitted"
        );
        let path = if argument == 0 {
            [0, 5, 12, 15, 19, 21, 24, 27]
        } else {
            [0, 5, 12, 15, 19, 28, 32, 35]
        };
        let mut heads = [self.terminal(); 9];
        for (head, offset) in heads.iter_mut().zip(path) {
            *head = self.borrowed.entry + offset;
        }
        heads
    }

    pub fn assert_publication(&self, edits: &[(u64, Vec<u8>)]) {
        if !edits.is_empty() {
            assert_eq!(edits.len(), 3);
            for (offset, len) in [(0, 5), (21, 7), (28, 8)] {
                let matches: Vec<_> = edits
                    .iter()
                    .filter(|(address, _)| *address == self.borrowed.entry + offset)
                    .collect();
                assert_eq!(matches.len(), 1, "one publication per frozen block window");
                assert_eq!(matches[0].1.len(), len);
            }
        }
        self.borrowed.assert_publication(edits);
    }

    pub fn original<F, G>(
        &self,
        invocations: &[Invocation],
        journal: u64,
        setup: F,
        captures: &Path,
    ) -> TwoExitCohortTrace
    where
        F: FnOnce() -> G,
        G: FnOnce(),
    {
        self.assert_publication(&[]);
        assert_cohort(invocations);
        let prepared = Prepared::fork(setup, 1);
        let child = &prepared.child;
        let mut trace = CohortTrace {
            states: Vec::new(),
            calls: Vec::new(),
            initial: Vec::new(),
            xstate: Vec::new(),
            invocations: invocations.to_vec(),
        };
        let mut steps = 0;
        let mut history = StepHistory::new(child, captures, self.stack_range());
        for (index, invocation) in invocations.iter().enumerate() {
            let mut initial = prepared.resume;
            let mut state = invocation.state_seed;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            initial.rax = next();
            initial.rbx = next();
            initial.rcx = next();
            initial.rdx = next();
            initial.rbp = next();
            initial.rsi = self.borrowed.inner.data.address() + 512;
            initial.rdi = invocation.argument;
            initial.r8 = next();
            initial.r9 = next();
            initial.r10 = next();
            initial.r11 = next();
            initial.r12 = next();
            initial.r13 = next();
            initial.r14 = next();
            initial.r15 = next();
            initial.rsp = self.rsp() + 8;
            initial.rip = self.borrowed.invoke;
            initial.orig_rax = u64::MAX;
            initial.eflags = 0xad7 | ((invocation.state_seed & 1) << 10);
            let xstate = seeded_xstate(prepared.xstate.clone(), invocation.state_seed);
            child.set_registers(&initial);
            child.set_xstate(&xstate);
            trace.initial.push(initial);
            trace.xstate.push(child.xstate());
            let call = self
                .borrowed
                .call(child, &mut steps, captures, index, &mut history);
            assert_journal(child, journal, &[]);
            let heads = self.heads_for(invocation.argument);
            let mut states = Vec::new();
            for (position, &head) in heads.iter().enumerate() {
                assert_eq!(
                    child.registers().rip,
                    head,
                    "independent original path order"
                );
                let snapshot =
                    self.borrowed
                        .snapshot(child, head, self.borrowed.inner.code.bytes());
                if let Some(previous) = states.last() {
                    self.assert_instruction(previous, &snapshot, *invocation);
                } else {
                    assert_state(&call.1, &snapshot);
                }
                assert_journal(child, journal, &[]);
                if position == 8 {
                    self.assert_return(&snapshot, *invocation);
                }
                save_snapshot(captures, index, position, &snapshot);
                history.progress(2, index, head, steps);
                states.push(snapshot);
                if position != 8 {
                    bounded_step(child, &mut steps, &mut history);
                }
            }
            // The complete actual RET is checked before any next initialization.
            trace.calls.push(call);
            trace.states.push(states);
        }
        std::fs::write(captures.join("journal.bin"), child.memory(journal, PAGE)).unwrap();
        prepared.finish(captures, steps);
        TwoExitCohortTrace { inner: trace }
    }

    pub fn compare<F, G>(
        &self,
        trace: &TwoExitCohortTrace,
        map: &TraceMap,
        expectation: PhaseExpectation<'_>,
        setup: F,
        captures: &Path,
    ) where
        F: FnOnce() -> G,
        G: FnOnce(),
    {
        let trace = &trace.inner;
        let PhaseExpectation {
            journal,
            events: expected_events,
            owned_threads,
        } = expectation;
        assert_cohort(&trace.invocations);
        assert_eq!(trace.initial.len(), 2);
        assert_eq!(trace.states.len(), 2);
        assert_eq!(trace.calls.len(), 2);
        assert_eq!(trace.xstate.len(), 2);
        self.assert_map(map, !expected_events.is_empty());
        if !expected_events.is_empty() {
            assert_eq!(expected_events.len(), 4);
            for (index, invocation) in trace.invocations.iter().enumerate() {
                let entry = expected_events[index * 2];
                let exit = expected_events[index * 2 + 1];
                assert!(entry[0] == 1 || entry[0] == 3);
                assert_eq!(exit[0], entry[0] + 1);
                assert_eq!(entry[2], self.borrowed.entry);
                assert_eq!(exit[2], self.exit_for(invocation.argument));
                assert_eq!(&entry[3..5], &[self.rsp(), self.terminal()]);
                assert_eq!(&exit[3..5], &[self.rsp(), self.terminal()]);
                for field in [1, 5, 6] {
                    assert_eq!(entry[field], exit[field]);
                }
            }
        }
        let code = self.borrowed.inner.code.bytes().to_vec();
        let prepared = Prepared::fork(setup, owned_threads);
        let child = &prepared.child;
        let mut steps = 0;
        let mut history = StepHistory::new(child, captures, self.stack_range());
        let mut seen_events = 0;
        for (index, expected) in trace.states.iter().enumerate() {
            assert_eq!(expected.len(), 9);
            // No register/XSAVE write follows this initialization until RET has
            // completed and its full state has been compared.
            child.set_registers(&trace.initial[index]);
            child.set_xstate(&trace.xstate[index]);
            assert_journal(child, journal, &expected_events[..seen_events]);
            let (before_call, after_call) =
                self.borrowed
                    .call(child, &mut steps, captures, index, &mut history);
            assert_state(&trace.calls[index].0, &before_call);
            assert_state(&trace.calls[index].1, &after_call);
            assert_journal(child, journal, &expected_events[..seen_events]);
            let mut next = 0;
            loop {
                assert!(
                    Instant::now() < child.deadline,
                    "whole persistent cohort deadline"
                );
                let pc = child.registers().rip;
                if let Some(&(logical, _)) =
                    map.boundaries.iter().find(|&&(_, physical)| physical == pc)
                {
                    let before = expected
                        .get(next)
                        .expect("unexpected extra restored boundary");
                    assert_eq!(
                        logical, before.logical_pc,
                        "ordered original/installed path visit"
                    );
                    let actual = self.borrowed.snapshot(child, logical, &code);
                    assert_state(before, &actual);
                    save_snapshot(captures, index, next, &actual);
                    history.progress(2, index, logical, steps);
                    if (logical == self.borrowed.entry
                        || logical == self.exit_for(trace.invocations[index].argument))
                        && !expected_events.is_empty()
                    {
                        seen_events += 1;
                    }
                    assert_journal(child, journal, &expected_events[..seen_events]);
                    next += 1;
                    if logical == self.terminal() {
                        assert_eq!(next, 9, "omitted source visit");
                        self.assert_return(&actual, trace.invocations[index]);
                        break;
                    }
                } else if (self.borrowed.inner.code.address()
                    ..self.borrowed.inner.code.address() + PAGE as u64)
                    .contains(&pc)
                {
                    assert!(map.gateways.contains(&pc), "undeclared source PC");
                }
                bounded_step(child, &mut steps, &mut history);
            }
        }
        assert_eq!(seen_events, expected_events.len());
        std::fs::write(captures.join("journal.bin"), child.memory(journal, PAGE)).unwrap();
        prepared.finish(captures, steps);
    }

    fn assert_map(&self, map: &TraceMap, installed: bool) {
        let mut heads: Vec<_> = HEADS
            .iter()
            .map(|offset| self.borrowed.entry + offset)
            .collect();
        heads.push(self.terminal());
        assert_eq!(map.boundaries.len(), heads.len());
        for head in heads {
            let entries: Vec<_> = map
                .boundaries
                .iter()
                .filter(|&&(logical, _)| logical == head)
                .collect();
            assert_eq!(
                entries.len(),
                1,
                "complete logical union, including the unused path"
            );
            let physical = entries[0].1;
            assert_eq!(
                map.boundaries
                    .iter()
                    .filter(|&&(_, pc)| pc == physical)
                    .count(),
                1
            );
            let rewritten = REWRITTEN
                .iter()
                .any(|offset| self.borrowed.entry + offset == head);
            if installed && rewritten {
                assert_ne!(physical, head);
                assert_eq!(
                    map.generated_ranges
                        .iter()
                        .filter(|range| range.contains(&physical))
                        .count(),
                    1
                );
            } else {
                assert_eq!(physical, head);
            }
        }
        if installed {
            assert_eq!(map.gateways.len(), 3);
            for offset in [0, 21, 28] {
                assert_eq!(
                    map.gateways
                        .iter()
                        .filter(|&&pc| pc == self.borrowed.entry + offset)
                        .count(),
                    1
                );
            }
            assert_eq!(map.generated_ranges.len(), 3);
            for (index, range) in map.generated_ranges.iter().enumerate() {
                assert!(range.start < range.end);
                let source = self.borrowed.inner.code.address();
                assert!(range.end <= source || range.start >= source + PAGE as u64);
                assert!(map.boundaries.iter().any(|&(_, pc)| range.contains(&pc)));
                for other in &map.generated_ranges[..index] {
                    assert!(range.end <= other.start || range.start >= other.end);
                }
            }
        } else {
            assert!(map.gateways.is_empty());
            assert!(map.generated_ranges.is_empty());
        }
    }

    fn assert_instruction(&self, before: &Snapshot, actual: &Snapshot, invocation: Invocation) {
        let mut expected = Snapshot {
            logical_pc: actual.logical_pc,
            registers: before.registers,
            xstate: before.xstate.clone(),
            data: before.data.clone(),
            application_stack: before.application_stack.clone(),
        };
        let entry = self.borrowed.entry;
        let offset = before.logical_pc.checked_sub(entry).unwrap();
        let next = match offset {
            0 => {
                expected.registers.rax = invocation.argument * 3 + 7;
                entry + 5
            }
            5 => {
                expected.registers.r10 = self.bias_object;
                entry + 12
            }
            12 => {
                let lhs = expected.registers.rax;
                expected.registers.rax = lhs.wrapping_add(11);
                expected.registers.eflags =
                    arithmetic_flags(expected.registers.eflags, lhs, 11, false);
                entry + 15
            }
            15 => {
                expected.registers.eflags =
                    arithmetic_flags(expected.registers.eflags, invocation.argument, 0, true);
                entry + 19
            }
            19 => {
                let zero = expected.registers.eflags & (1 << 6) != 0;
                assert_eq!(zero, invocation.argument == 0);
                entry + if zero { 21 } else { 28 }
            }
            21 => entry + 24,
            24 | 32 => {
                expected.data[512..520].copy_from_slice(&expected.registers.rax.to_le_bytes());
                entry + offset + 3
            }
            27 | 35 => {
                assert_eq!(before.logical_pc, self.exit_for(invocation.argument));
                assert_eq!(expected.registers.rsp, self.rsp());
                assert_eq!(
                    &expected.application_stack[128..136],
                    &self.terminal().to_le_bytes()
                );
                expected.registers.rsp += 8;
                self.terminal()
            }
            28 => {
                let lhs = expected.registers.rax;
                expected.registers.rax = lhs.wrapping_add(1);
                expected.registers.eflags =
                    arithmetic_flags(expected.registers.eflags, lhs, 1, false);
                entry + 32
            }
            _ => panic!("undeclared original instruction"),
        };
        expected.logical_pc = next;
        expected.registers.rip = next;
        assert_eq!(
            actual.registers.rip, next,
            "independent original ISA successor"
        );
        assert_state(&expected, actual);
    }

    fn assert_return(&self, point: &Snapshot, invocation: Invocation) {
        assert_eq!(
            point.registers.rsp,
            self.rsp() + 8,
            "real original RET stack consumption"
        );
        assert_eq!(
            point.registers.rip,
            self.terminal(),
            "real original return target"
        );
        let result = 3 * invocation.argument + 18 + invocation.argument;
        assert_eq!(point.registers.rax, result);
        assert_eq!(
            u64::from_le_bytes(point.data[512..520].try_into().unwrap()),
            result
        );
        assert_eq!(
            &point.application_stack[128..136],
            &self.terminal().to_le_bytes(),
            "application return word was changed"
        );
    }
}

fn assert_cohort(invocations: &[Invocation]) {
    assert_eq!(invocations.len(), 2);
    assert!(
        invocations
            .iter()
            .all(|invocation| invocation.argument <= 1)
    );
    assert_ne!(invocations[0].argument, invocations[1].argument);
}

fn immutable_word(borrowed: &BorrowedLeafOracle, address: u64) -> u64 {
    let end = address.checked_add(8).unwrap();
    let owners: Vec<_> = borrowed
        .immutable
        .iter()
        .filter(|(start, bytes)| {
            *start <= address && end <= start.checked_add(bytes.len() as u64).unwrap()
        })
        .collect();
    assert_eq!(owners.len(), 1, "word has one declared immutable owner");
    let (start, bytes) = owners[0];
    let offset = usize::try_from(address - start).unwrap();
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn arithmetic_flags(old: u64, lhs: u64, rhs: u64, subtract: bool) -> u64 {
    // This is the ISA write set, not a comparator mask. assert_state still
    // compares every original flag except its existing debugger-owned TF/RF.
    let (result, carry, overflow) = if subtract {
        let result = lhs.wrapping_sub(rhs);
        (result, lhs < rhs, ((lhs ^ rhs) & (lhs ^ result)) >> 63 != 0)
    } else {
        let (result, carry) = lhs.overflowing_add(rhs);
        (result, carry, (!(lhs ^ rhs) & (lhs ^ result)) >> 63 != 0)
    };
    let arithmetic = 0x8d5; // CF, PF, AF, ZF, SF, OF, and no other flag.
    (old & !arithmetic)
        | u64::from(carry)
        | (u64::from((result as u8).count_ones() & 1 == 0) << 2)
        | ((lhs ^ rhs ^ result) & (1 << 4))
        | (u64::from(result == 0) << 6)
        | ((result >> 63) << 7)
        | (u64::from(overflow) << 11)
}
