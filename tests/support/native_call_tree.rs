//! Fixed loaded CALL tree: real transfer witnesses and original operand checks.
//! No callback readiness, model token or relocated PC replaces a physical RET.
use super::{OriginalObservation, OriginalStep, Ready, Tracee};
use std::collections::BTreeSet;

#[path = "../../tools/rapid-profiler/tree-work/model.rs"]
pub mod model;
register_native_fixture!(tree_truth);

pub struct Stats {
    pub counts: truth::Counts,
    pub model: model::Summary,
}

fn bytes_at(bytes: &[u8], base: u64, address: u64, count: usize) -> &[u8] {
    let start = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    &bytes[start..start.checked_add(count).unwrap()]
}
fn word(bytes: &[u8], base: u64, address: u64) -> u64 {
    u64::from_le_bytes(bytes_at(bytes, base, address, 8).try_into().unwrap())
}
fn heads(root: u64) -> Vec<u64> {
    truth::ROOT_HEADS
        .iter()
        .map(|&p| root + u64::from(p))
        .chain(
            truth::CHILD_HEADS
                .iter()
                .map(|&p| root + truth::CHILD_OFFSET + u64::from(p)),
        )
        .collect()
}
fn check_source(ready: &Ready) {
    assert_eq!(ready.profile, super::Profile::Legacy);
    check_tree_source(ready);
}
fn check_tree_source(ready: &Ready) {
    let (base, _) = &ready.immutable[0];
    assert_eq!(
        bytes_at(&ready.original_source, *base, ready.entry, 23),
        truth::ROOT_BYTES
    );
    assert_eq!(
        bytes_at(&ready.original_source, *base, ready.entry + 23, 9),
        truth::GAP_BYTES
    );
    assert_eq!(
        bytes_at(&ready.original_source, *base, ready.entry + 32, 39),
        truth::CHILD_BYTES
    );
    assert_eq!(ready.heads, heads(ready.entry));
    assert_eq!(ready.returns, [ready.entry + 22, ready.entry + 70]);
    assert_eq!(
        ready.boundaries.iter().find(|(p, _)| *p == ready.entry + 9),
        Some(&(ready.entry + 9, ready.entry + 9)),
        "the application E8 stays at its original physical source PC"
    );
}

#[derive(Clone, Copy)]
pub(super) struct Transfer {
    index: usize,
    before: libc::user_regs_struct,
    word: u64,
}
pub(super) struct Witness {
    root: u64,
    continuation: u64,
    root_rsp: u64,
    physical: [u64; 3],
    next: usize,
}
impl Witness {
    pub(super) fn new(ready: &Ready, gate_rsp: u64) -> Self {
        check_source(ready);
        Self::new_checked(ready, gate_rsp)
    }
    pub(super) fn new_native(ready: &Ready, gate_rsp: u64) -> Self {
        assert_eq!(ready.profile, super::Profile::NativeCall);
        check_tree_source(ready);
        Self::new_checked(ready, gate_rsp)
    }
    fn new_checked(ready: &Ready, gate_rsp: u64) -> Self {
        let physical = |pc| ready.boundaries.iter().find(|(p, _)| *p == pc).unwrap().1;
        Self {
            root: ready.entry,
            continuation: ready.continuation,
            root_rsp: gate_rsp.checked_sub(16).unwrap(),
            physical: [
                ready.entry + 9,
                physical(ready.entry + 70),
                physical(ready.entry + 22),
            ],
            next: 0,
        }
    }
    fn slot(&self, index: usize) -> u64 {
        match index {
            0 | 1 => self.root_rsp.checked_sub(16).unwrap(),
            2 => self.root_rsp,
            _ => panic!("extra tree transfer"),
        }
    }
    fn check_before(&self, index: usize, before: &libc::user_regs_struct, bytes: &[u8], word: u64) {
        assert_eq!(index, self.next, "one CALL then child RET then root RET");
        assert_eq!(before.rip, self.physical[index]);
        let expected_rsp = match index {
            0 => self.root_rsp - 8,
            1 => self.root_rsp - 16,
            2 => self.root_rsp,
            _ => unreachable!(),
        };
        assert_eq!(before.rsp, expected_rsp);
        if index == 0 {
            assert_eq!(before.rip, self.root + 9);
            assert_eq!(bytes, [0xe8, 0x12, 0, 0, 0]);
        } else {
            assert_eq!(bytes, [0xc3]);
            assert_eq!(
                word,
                if index == 1 {
                    self.root + 14
                } else {
                    self.continuation
                }
            );
        }
    }
    pub(super) fn before(&self, child: &Tracee, pc: u64) -> Option<Transfer> {
        let index = self.physical.iter().position(|p| *p == pc)?;
        let before = child.registers();
        let bytes = child.memory(pc, if index == 0 { 5 } else { 1 });
        let word = word(
            &child.memory(self.slot(index), 8),
            self.slot(index),
            self.slot(index),
        );
        self.check_before(index, &before, &bytes, word);
        Some(Transfer {
            index,
            before,
            word,
        })
    }
    fn check_after(&mut self, transfer: Transfer, after: &libc::user_regs_struct, popped: u64) {
        let index = transfer.index;
        assert_eq!(
            index, self.next,
            "no omitted or duplicated transfer witness"
        );
        assert_eq!(transfer.before.rip, self.physical[index]);
        let (pc, rsp, saved) = match index {
            0 => (self.root + 32, self.root_rsp - 16, self.root + 14),
            1 => (self.root + 14, self.root_rsp - 8, transfer.word),
            2 => (self.continuation, self.root_rsp + 8, transfer.word),
            _ => panic!("extra tree transfer"),
        };
        assert_eq!(
            (after.rip, after.rsp),
            (pc, rsp),
            "immediate physical successor before its redirect/callback"
        );
        assert_eq!(
            after.rax, transfer.before.rax,
            "CALL/RET preserves returned RAX"
        );
        assert_eq!(popped, saved, "real original saved word, unchanged by RET");
        self.next += 1;
    }
    pub(super) fn after(&mut self, child: &Tracee, transfer: Transfer) {
        let address = self.slot(transfer.index);
        self.check_after(
            transfer,
            &child.registers(),
            word(&child.memory(address, 8), address, address),
        );
    }
    pub(super) fn finish(&self) -> usize {
        assert_eq!(self.next, 3);
        self.next
    }
}

// The source-defined tree gate deliberately retains its root owner here.
// A leaf COMPLETED phase is not an acceptable substitute for actual return.
fn pending_frame(armed: &[u64], ready: &Ready, gate_rsp: u64) -> Vec<u8> {
    assert_eq!(armed.len(), 14);
    let mut expected = armed.to_vec();
    expected[0] = 5; // TREE_RETURN_OBSERVED; NOT canonical IDLE/leaf COMPLETED.
    expected[6] = ready.entry;
    expected[7] = gate_rsp - 8;
    expected[8] = gate_rsp - 8;
    expected[11] = gate_rsp - 16;
    expected[12] = ready.continuation;
    expected[13] = ready.entry + 22;
    expected.iter().flat_map(|n| n.to_le_bytes()).collect()
}
pub(super) fn frame_after(
    child: &Tracee,
    actual: &libc::user_regs_struct,
    ready: &Ready,
    armed: &[u64],
    gate_rsp: u64,
) {
    check_frame(&child.memory(actual.rdi, 112), ready, armed, gate_rsp);
}
fn check_frame(actual: &[u8], ready: &Ready, armed: &[u64], gate_rsp: u64) {
    assert_eq!(
        actual,
        pending_frame(armed, ready, gate_rsp),
        "complete pending tree Frame before harness restoration"
    );
}

fn check_shape(actual: &[OriginalStep<'_>], expected: &[truth::Step], root: u64) {
    assert_eq!(actual.len(), 332);
    assert_eq!(actual.len(), expected.len());
    assert_eq!(
        actual.iter().map(|s| s.before.rip).collect::<BTreeSet<_>>(),
        heads(root).into_iter().collect()
    );
    for (actual, predicted) in actual.iter().zip(expected) {
        assert_eq!(
            (actual.before.rip, actual.after.rip),
            (predicted.pc, predicted.next_pc),
            "complete ordered original tree heads"
        );
        assert_eq!(
            predicted.node,
            if actual.before.rip < root + 32 {
                truth::ROOT_NODE
            } else {
                truth::CHILD_NODE
            }
        );
    }
}
fn call_store(before: &[u8], after: &[u8], base: u64, address: u64, value: u64) {
    assert_eq!(before.len(), after.len());
    let offset = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    let end = offset.checked_add(8).unwrap();
    assert_eq!(&after[offset..end], &value.to_le_bytes());
    assert_eq!(
        &before[..offset],
        &after[..offset],
        "CALL changes no lower protected byte"
    );
    assert_eq!(
        &before[end..],
        &after[end..],
        "CALL changes no other protected byte"
    );
}

fn check_step(
    actual: &OriginalStep<'_>,
    after_stack: &[u8],
    predicted: &truth::Step,
    root: u64,
    data: u64,
    root_rsp: u64,
) -> Option<truth::Event> {
    use truth::{CHILD_NODE, Event, EventKind, ROOT_NODE};
    let before = &actual.before;
    let after = &actual.after;
    assert_eq!((before.rip, after.rip), (predicted.pc, predicted.next_pc));
    assert_eq!((before.rdi, before.rsi), (data, truth::INPUT_BYTES as u64));
    let event = |node, kind, address, value| Event {
        node,
        kind,
        address,
        width: 8,
        value,
    };
    let input_read = |kind, address: u64| {
        assert!(
            data <= address
                && address.checked_add(8).unwrap()
                    <= data.checked_add(truth::INPUT_BYTES as u64).unwrap()
        );
        assert_eq!(address % 8, 0);
        event(
            CHILD_NODE,
            kind,
            address,
            word(actual.data, actual.data_address, address),
        )
    };
    let ret = |node, kind| {
        assert_eq!(before.rsp % 8, 0);
        let e = event(
            node,
            kind,
            before.rsp,
            word(actual.stack, actual.stack_address, before.rsp),
        );
        assert_eq!(
            (after.rip, after.rsp, after.rax),
            (e.value, before.rsp.checked_add(8).unwrap(), before.rax)
        );
        assert_eq!(word(after_stack, actual.stack_address, before.rsp), e.value);
        e
    };
    let offset = before.rip.checked_sub(root).unwrap();
    let got = if offset < 32 {
        assert_eq!(predicted.node, ROOT_NODE);
        assert_eq!(predicted.branch_taken, None);
        match offset {
            0 => {
                assert_eq!((before.rsp, after.rsp), (root_rsp, root_rsp - 8));
                None
            }
            4 => {
                assert_eq!(
                    (before.rsp, after.rsp, after.rax),
                    (root_rsp - 8, root_rsp - 8, 0)
                );
                None
            }
            9 => {
                assert_eq!(
                    (before.rsp, after.rsp, after.rip),
                    (root_rsp - 8, root_rsp - 16, root + 32)
                );
                assert_eq!(after.rax, before.rax);
                call_store(
                    actual.stack,
                    after_stack,
                    actual.stack_address,
                    root_rsp - 16,
                    root + 14,
                );
                Some(event(
                    ROOT_NODE,
                    EventKind::CallStore,
                    root_rsp - 16,
                    word(after_stack, actual.stack_address, root_rsp - 16),
                ))
            }
            14 => {
                assert_eq!(
                    (before.rsp, after.rsp, after.rax),
                    (root_rsp - 8, root_rsp - 8, before.rax.wrapping_add(1))
                );
                None
            }
            18 => {
                assert_eq!((before.rsp, after.rsp), (root_rsp - 8, root_rsp));
                None
            }
            22 => {
                assert_eq!(before.rsp, root_rsp);
                Some(ret(ROOT_NODE, EventKind::RootReturn))
            }
            _ => panic!("nonliteral root instruction"),
        }
    } else {
        assert_eq!(predicted.node, CHILD_NODE);
        assert_eq!(before.rsp, root_rsp - 16);
        if offset != 70 {
            assert_eq!(after.rsp, before.rsp);
        }
        if offset != 55 {
            assert_eq!(predicted.branch_taken, None);
        }
        match offset - 32 {
            0 => {
                let e = input_read(EventKind::Count, before.rdi.checked_add(16).unwrap());
                assert_eq!(after.rcx, e.value);
                Some(e)
            }
            4 => {
                assert_eq!(after.rax, 0);
                None
            }
            6 => {
                assert_eq!(after.rdx, 0);
                None
            }
            8 => {
                assert_eq!(before.rdx % 64, 0);
                assert!(before.rdx <= 960);
                let e = input_read(
                    EventKind::Payload,
                    before
                        .rdi
                        .checked_add(before.rdx)
                        .unwrap()
                        .checked_add(8)
                        .unwrap(),
                );
                assert_eq!(after.r8, e.value);
                Some(e)
            }
            13 => {
                assert_eq!(after.rax, before.rax.wrapping_add(before.r8));
                None
            }
            16 => {
                assert_eq!(before.rdx % 64, 0);
                assert!(before.rdx <= 960);
                let e = input_read(EventKind::Link, before.rdi.checked_add(before.rdx).unwrap());
                assert_eq!(after.rdx, e.value);
                Some(e)
            }
            20 => {
                assert!((1..=64).contains(&before.rcx));
                assert_eq!(after.rcx, before.rcx - 1);
                assert_eq!(
                    after.eflags & (1 << 6) != 0,
                    after.rcx == 0,
                    "DEC actual ZF"
                );
                None
            }
            23 => {
                assert!(before.rcx < 64);
                let taken = before.eflags & (1 << 6) == 0;
                assert_eq!(taken, before.rcx != 0);
                assert_eq!(predicted.branch_taken, Some(taken));
                None
            }
            25 => {
                assert_eq!(after.rdx, 0x9e37_79b9_7f4a_7c15);
                None
            }
            35 => {
                assert_eq!(after.rax, before.rax ^ before.rdx);
                None
            }
            38 => {
                assert_eq!(after.rip, root + 14);
                Some(ret(CHILD_NODE, EventKind::ChildReturn))
            }
            _ => panic!("nonliteral child instruction"),
        }
    };
    if offset != 9 {
        assert_eq!(
            actual.stack, after_stack,
            "only the actual CALL stores application stack bytes"
        );
    }
    assert_eq!(
        got, predicted.event,
        "full actual event node/kind/address/width/value"
    );
    got
}

/// Complete saved original snapshots, borrowed only after both normal reaps.
pub fn inspect(case: truth::Case, seed: u64, observed: OriginalObservation<'_>) -> Stats {
    let root = observed.entry;
    let root_bytes = bytes_at(observed.source, observed.source_address, root, 23);
    let child_bytes = bytes_at(observed.source, observed.source_address, root + 32, 39);
    truth::check_bytes(root_bytes, child_bytes).unwrap();
    assert_eq!(
        bytes_at(observed.source, observed.source_address, root + 23, 9),
        truth::GAP_BYTES
    );
    let input = truth::input(case, seed);
    assert_eq!(observed.input, &input);
    let steps: Vec<_> = observed.steps().collect();
    let starts: Vec<_> = steps
        .iter()
        .enumerate()
        .filter_map(|(i, s)| (s.before.rip == root).then_some(i))
        .collect();
    assert_eq!(
        starts,
        [8],
        "one real root entry after the eight Legacy gate instructions"
    );
    let first = &steps[8];
    let root_rsp = first.before.rsp;
    assert_eq!(
        observed.stack_address,
        root_rsp - 144,
        "entire unmasked child red zone"
    );
    assert_eq!(
        word(first.stack, observed.stack_address, root_rsp),
        observed.continuation
    );
    let expected = truth::interpret(
        root_bytes,
        child_bytes,
        &input,
        root,
        observed.input_address,
        root_rsp,
        observed.continuation,
    )
    .unwrap();
    assert_eq!(expected.steps.len(), 332);
    assert_eq!(steps.len(), 342);
    let body = &steps[8..340];
    check_shape(body, &expected.steps, root);
    let mut events = Vec::new();
    let (mut conditional, mut taken, mut root_instructions) = (0, 0, 0);
    for (i, (actual, predicted)) in body.iter().zip(&expected.steps).enumerate() {
        assert_eq!(
            bytes_at(
                actual.data,
                actual.data_address,
                observed.input_address,
                input.len()
            ),
            &input
        );
        let after = &observed.points[8 + i + 1];
        assert_eq!(
            bytes_at(
                &after.data,
                observed.data_address,
                observed.input_address,
                input.len()
            ),
            &input
        );
        if let Some(event) = check_step(
            actual,
            &after.application_stack,
            predicted,
            root,
            observed.input_address,
            root_rsp,
        ) {
            events.push(event);
        }
        root_instructions += usize::from(predicted.node == truth::ROOT_NODE);
        if let Some(branch) = predicted.branch_taken {
            conditional += 1;
            taken += usize::from(branch);
        }
    }
    let last = body.last().unwrap();
    assert_eq!(
        (last.after.rip, last.after.rsp, last.after.rax),
        (observed.continuation, expected.resumed_rsp, expected.value)
    );
    assert_eq!(last.after.rax, truth::scalar(case, seed));
    assert_eq!(steps[340].before.rip, observed.continuation);
    assert_eq!(
        events,
        truth::expected_events(
            case,
            seed,
            root,
            observed.input_address,
            root_rsp,
            observed.continuation
        )
        .unwrap()
    );
    let counts = truth::Counts {
        instructions: body.len(),
        root_instructions,
        child_instructions: body.len() - root_instructions,
        conditional,
        taken,
        input_reads: events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    truth::EventKind::Count | truth::EventKind::Payload | truth::EventKind::Link
                )
            })
            .count(),
        return_reads: events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    truth::EventKind::ChildReturn | truth::EventKind::RootReturn
                )
            })
            .count(),
        call_stores: events
            .iter()
            .filter(|e| e.kind == truth::EventKind::CallStore)
            .count(),
    };
    assert_eq!(counts, truth::counts(case));
    let model = model::check(case, observed.input_address, root_rsp, &events).unwrap();
    assert_eq!(model.accesses, 132);
    Stats { counts, model }
}

// Separate closed offsets; the Legacy inspector above remains literal.
pub fn inspect_native(case: truth::Case, seed: u64, observed: OriginalObservation<'_>) -> Stats {
    let root = observed.entry;
    let root_bytes = bytes_at(observed.source, observed.source_address, root, 23);
    let child_bytes = bytes_at(observed.source, observed.source_address, root + 32, 39);
    truth::check_bytes(root_bytes, child_bytes).unwrap();
    assert_eq!(
        bytes_at(observed.source, observed.source_address, root + 23, 9),
        truth::GAP_BYTES
    );
    let input = truth::input(case, seed);
    assert_eq!(observed.input, &input);
    let steps: Vec<_> = observed.steps().collect();
    let starts: Vec<_> = steps
        .iter()
        .enumerate()
        .filter_map(|(i, s)| (s.before.rip == root).then_some(i))
        .collect();
    assert_eq!(
        starts,
        [5],
        "one real root entry after the five NativeCall stencil instructions"
    );
    let first = &steps[5];
    let root_rsp = first.before.rsp;
    assert_eq!(
        observed.stack_address,
        root_rsp - 144,
        "entire unmasked child red zone"
    );
    assert_eq!(
        word(first.stack, observed.stack_address, root_rsp),
        observed.continuation
    );
    let expected = truth::interpret(
        root_bytes,
        child_bytes,
        &input,
        root,
        observed.input_address,
        root_rsp,
        observed.continuation,
    )
    .unwrap();
    assert_eq!(expected.steps.len(), 332);
    assert_eq!(steps.len(), 338);
    let body = &steps[5..337];
    check_shape(body, &expected.steps, root);
    let mut events = Vec::new();
    let (mut conditional, mut taken, mut root_instructions) = (0, 0, 0);
    for (i, (actual, predicted)) in body.iter().zip(&expected.steps).enumerate() {
        assert_eq!(
            bytes_at(
                actual.data,
                actual.data_address,
                observed.input_address,
                input.len()
            ),
            &input
        );
        let after = &observed.points[5 + i + 1];
        assert_eq!(
            bytes_at(
                &after.data,
                observed.data_address,
                observed.input_address,
                input.len()
            ),
            &input
        );
        if let Some(event) = check_step(
            actual,
            &after.application_stack,
            predicted,
            root,
            observed.input_address,
            root_rsp,
        ) {
            events.push(event);
        }
        root_instructions += usize::from(predicted.node == truth::ROOT_NODE);
        if let Some(branch) = predicted.branch_taken {
            conditional += 1;
            taken += usize::from(branch);
        }
    }
    let last = body.last().unwrap();
    assert_eq!(
        (last.after.rip, last.after.rsp, last.after.rax),
        (observed.continuation, expected.resumed_rsp, expected.value)
    );
    assert_eq!(last.after.rax, truth::scalar(case, seed));
    assert_eq!(steps[337].before.rip, observed.continuation);
    assert_eq!(
        events,
        truth::expected_events(
            case,
            seed,
            root,
            observed.input_address,
            root_rsp,
            observed.continuation
        )
        .unwrap()
    );
    let counts = truth::Counts {
        instructions: body.len(),
        root_instructions,
        child_instructions: body.len() - root_instructions,
        conditional,
        taken,
        input_reads: events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    truth::EventKind::Count | truth::EventKind::Payload | truth::EventKind::Link
                )
            })
            .count(),
        return_reads: events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    truth::EventKind::ChildReturn | truth::EventKind::RootReturn
                )
            })
            .count(),
        call_stores: events
            .iter()
            .filter(|e| e.kind == truth::EventKind::CallStore)
            .count(),
    };
    assert_eq!(counts, truth::counts(case));
    let model = model::check(case, observed.input_address, root_rsp, &events).unwrap();
    assert_eq!(model.accesses, 132);
    Stats { counts, model }
}

#[cfg(test)]
#[path = "native_call_tree/tests.rs"]
mod tests;

// Separate expected refusal; never added to the four positive pair counts.
#[path = "native_call_tree/refusal.rs"]
pub mod refusal;
