use super::*;

const ROOT: u64 = 0x1000;
const DATA: u64 = 0x2080;
const RSP: u64 = 0x3fe8;
const CONT: u64 = 0x5019;

fn registers(pc: u64, rsp: u64) -> libc::user_regs_struct {
    let mut r: libc::user_regs_struct = unsafe { core::mem::zeroed() };
    r.rip = pc;
    r.rsp = rsp;
    r.rdi = DATA;
    r.rsi = 1024;
    r.rax = 17;
    r
}
fn witness() -> Witness {
    Witness {
        root: ROOT,
        continuation: CONT,
        root_rsp: RSP,
        physical: [ROOT + 9, 0x6070, 0x6022],
        next: 0,
    }
}
fn transfer(w: &Witness, index: usize) -> (Transfer, libc::user_regs_struct, u64) {
    let (before_rsp, after_pc, after_rsp, saved) = match index {
        0 => (RSP - 8, ROOT + 32, RSP - 16, ROOT + 14),
        1 => (RSP - 16, ROOT + 14, RSP - 8, ROOT + 14),
        2 => (RSP, CONT, RSP + 8, CONT),
        _ => unreachable!(),
    };
    let before = registers(w.physical[index], before_rsp);
    (
        Transfer {
            index,
            before,
            word: if index == 0 { 0x5a5a } else { saved },
        },
        registers(after_pc, after_rsp),
        saved,
    )
}
fn refused(f: impl FnOnce()) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
}

#[test]
fn tree_native_actual_transfer_bytes_pc_rsp_and_saved_word() {
    let mut w = witness();
    for index in 0..3 {
        let (t, after, saved) = transfer(&w, index);
        let bytes: &[u8] = if index == 0 {
            &[0xe8, 0x12, 0, 0, 0]
        } else {
            &[0xc3]
        };
        w.check_before(index, &t.before, bytes, t.word);
        for at in 0..bytes.len() {
            let mut bad = bytes.to_vec();
            bad[at] ^= 1;
            refused(|| w.check_before(index, &t.before, &bad, t.word));
        }
        for field in 0..2 {
            let mut bad = t.before;
            if field == 0 {
                bad.rip += 1;
            } else {
                bad.rsp += 8;
            }
            refused(|| w.check_before(index, &bad, bytes, t.word));
        }
        if index != 0 {
            refused(|| w.check_before(index, &t.before, bytes, t.word + 1));
        }
        for field in 0..4 {
            let mut bad = after;
            let mut bad_saved = saved;
            match field {
                0 => bad.rip += 1,
                1 => bad.rsp += 8,
                2 => bad.rax ^= 1,
                _ => bad_saved ^= 1,
            }
            refused(|| w.check_after(t, &bad, bad_saved));
            assert_eq!(w.next, index);
        }
        w.check_after(t, &after, saved);
    }
    assert_eq!(w.finish(), 3);
}

#[test]
fn tree_native_transfer_population_order_and_original_call_pc() {
    let mut w = witness();
    refused(|| {
        w.finish();
    });
    let (child, after, saved) = transfer(&w, 1);
    refused(|| w.check_after(child, &after, saved));
    let (call, after, saved) = transfer(&w, 0);
    w.check_after(call, &after, saved);
    refused(|| w.check_after(call, &after, saved));
    refused(|| {
        w.finish();
    });
    let mut w = witness();
    w.physical[0] += 0x1000; // A consistent map must not authorize a moved E8.
    let (call, _, _) = transfer(&w, 0);
    refused(|| w.check_before(0, &call.before, &[0xe8, 0x12, 0, 0, 0], call.word));
}

fn ready() -> Ready {
    Ready {
        profile: super::super::Profile::Legacy,
        entry: ROOT,
        gate: 0x5000,
        continuation: CONT,
        heads: heads(ROOT),
        returns: vec![ROOT + 22, ROOT + 70],
        boundaries: heads(ROOT).into_iter().map(|p| (p, p)).collect(),
        immutable: vec![(ROOT, vec![0; 4096])],
        original_source: vec![0; 4096],
    }
}
#[test]
fn tree_native_closed_source_gap_heads_returns_and_call_map() {
    let mut r = ready();
    r.original_source[..23].copy_from_slice(&truth::ROOT_BYTES);
    r.original_source[23..32].copy_from_slice(&truth::GAP_BYTES);
    r.original_source[32..71].copy_from_slice(&truth::CHILD_BYTES);
    check_source(&r);
    for at in 0..71 {
        r.original_source[at] ^= 1;
        refused(|| check_source(&r));
        r.original_source[at] ^= 1;
    }
    r.heads.remove(0);
    refused(|| check_source(&r));
    r.heads = heads(ROOT);
    r.returns.pop();
    refused(|| check_source(&r));
    r.returns.push(ROOT + 70);
    r.boundaries[2].1 += 0x1000;
    refused(|| check_source(&r));
}
#[test]
fn tree_native_pending_frame_rejects_idle_leaf_phase_and_each_word() {
    let r = ready();
    let armed = [1, 1, 7, 31, 31, ROOT, 0, 0, 0, 0x3000, 0x4000, 0, 0, 0];
    let literal = [
        5_u64,
        1,
        7,
        31,
        31,
        ROOT,
        ROOT,
        RSP + 8,
        RSP + 8,
        0x3000,
        0x4000,
        RSP,
        CONT,
        ROOT + 22,
    ];
    let bytes: Vec<_> = literal.into_iter().flat_map(u64::to_le_bytes).collect();
    check_frame(&bytes, &r, &armed, RSP + 16);
    for at in (0..112).step_by(8) {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        refused(|| check_frame(&bad, &r, &armed, RSP + 16));
    }
    for phase in [0_u64, 1, 3] {
        let mut bad = bytes.clone();
        bad[..8].copy_from_slice(&phase.to_le_bytes());
        refused(|| check_frame(&bad, &r, &armed, RSP + 16));
    }
}

#[test]
fn tree_native_call_store_preserves_every_other_protected_byte() {
    let before = vec![0x5a; 168];
    let mut after = before.clone();
    after[128..136].copy_from_slice(&(ROOT + 14).to_le_bytes());
    call_store(&before, &after, RSP - 144, RSP - 16, ROOT + 14);
    for at in 0..168 {
        let mut bad = after.clone();
        bad[at] ^= 1;
        refused(|| call_store(&before, &bad, RSP - 144, RSP - 16, ROOT + 14));
    }
    refused(|| call_store(&before, &after, RSP - 144, RSP - 8, ROOT + 14));
    refused(|| call_store(&before, &after, RSP - 144, RSP - 16, ROOT + 15));
}

#[test]
fn tree_native_complete_shape_refuses_missing_extra_reordered_and_node() {
    let input = truth::input(truth::Case::Fit2, 17);
    let expected = truth::interpret(
        &truth::ROOT_BYTES,
        &truth::CHILD_BYTES,
        &input,
        ROOT,
        DATA,
        RSP,
        CONT,
    )
    .unwrap();
    let make = || {
        expected
            .steps
            .iter()
            .map(|s| OriginalStep {
                before: registers(s.pc, RSP),
                after: registers(s.next_pc, RSP),
                data_address: DATA,
                data: &input,
                stack_address: 0,
                stack: &[],
            })
            .collect::<Vec<_>>()
    };
    check_shape(&make(), &expected.steps, ROOT);
    let mut actual = make();
    actual.remove(3);
    refused(|| check_shape(&actual, &expected.steps, ROOT));
    let mut actual = make();
    actual.extend(make().into_iter().take(1));
    refused(|| check_shape(&actual, &expected.steps, ROOT));
    let mut actual = make();
    actual.swap(3, 4);
    refused(|| check_shape(&actual, &expected.steps, ROOT));
    let mut bad = expected.steps.clone();
    bad[3].node = truth::ROOT_NODE;
    refused(|| check_shape(&make(), &bad, ROOT));
}

#[test]
fn tree_native_actual_payload_link_and_dec_flags_are_authenticated() {
    use truth::{Event, EventKind, Step};
    let input = truth::input(truth::Case::Fit2, 17);
    let stack = [0x5a; 168];
    for (pc, next, kind, address, value) in [
        (
            ROOT + 40,
            ROOT + 45,
            EventKind::Payload,
            DATA + 8,
            word(&input, DATA, DATA + 8),
        ),
        (ROOT + 48, ROOT + 52, EventKind::Link, DATA, 256),
    ] {
        let mut before = registers(pc, RSP - 16);
        before.rdx = 0;
        let mut after = before;
        after.rip = next;
        if kind == EventKind::Payload {
            after.r8 = value;
        } else {
            after.rdx = value;
        }
        let actual = OriginalStep {
            before,
            after,
            data_address: DATA,
            data: &input,
            stack_address: RSP - 144,
            stack: &stack,
        };
        let expected = Step {
            node: truth::CHILD_NODE,
            pc,
            next_pc: next,
            branch_taken: None,
            event: Some(Event {
                node: truth::CHILD_NODE,
                kind,
                address,
                width: 8,
                value,
            }),
        };
        check_step(&actual, &stack, &expected, ROOT, DATA, RSP);
        for field in 0..5 {
            let mut bad = expected;
            let e = bad.event.as_mut().unwrap();
            match field {
                0 => e.node = 0,
                1 => e.address += 8,
                2 => e.width = 4,
                3 => e.value ^= 1,
                _ => e.kind = EventKind::Count,
            }
            refused(|| {
                check_step(&actual, &stack, &bad, ROOT, DATA, RSP);
            });
        }
    }
    let mut before = registers(ROOT + 52, RSP - 16);
    before.rcx = 1;
    let mut after = before;
    after.rip = ROOT + 55;
    after.rcx = 0;
    after.eflags = 1 << 6;
    let expected = Step {
        node: truth::CHILD_NODE,
        pc: before.rip,
        next_pc: after.rip,
        branch_taken: None,
        event: None,
    };
    let mut actual = OriginalStep {
        before,
        after,
        data_address: DATA,
        data: &input,
        stack_address: RSP - 144,
        stack: &stack,
    };
    check_step(&actual, &stack, &expected, ROOT, DATA, RSP);
    actual.after.eflags = 0;
    refused(|| {
        check_step(&actual, &stack, &expected, ROOT, DATA, RSP);
    });
}
