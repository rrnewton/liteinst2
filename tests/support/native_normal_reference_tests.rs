//! Fabricated direct-validator controls only: no hardware, process or native credit.
use super::*;
fn refused(f: impl FnOnce()) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
}
fn ready() -> NormalReady {
    NormalReady {
        caller: 0x1000,
        caller_immutable: vec![(0x1000, bytes::BYTES.to_vec())],
        entry: 0x2000,
        heads: vec![0x2000],
        returns: vec![0x2024],
        boundaries: vec![(0x2000, 0x2000)],
        immutable: vec![(0x2000, vec![0xc3])],
        original_source: vec![0xc3],
        journal: None,
    }
}
fn witness() -> Witness {
    let mut page = vec![0x6d; PAGE];
    page[CELLS_AT..CELLS_AT + bytes::CELLS_BYTES]
        .copy_from_slice(cell_bytes(&bytes::fresh_cells(1, [1, 2]).unwrap()));
    Witness {
        page,
        page_address: 0x3000,
        cells: 0x3080,
        caller: 0x1000,
        target: 0x2000,
        data: 0x4000,
        stack: 0x8008 - 176,
        rsp: 0x8008,
        value: 91,
        heads: 0,
        readers: 0,
        stores: 0,
        interiors: 0,
        outputs: [None; 4],
        reader_start: None,
        outer_return: false,
    }
}
fn point(offset: u64) -> Snapshot {
    let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    registers.rip = 0x1000 + offset;
    registers.rax = 0x1234_5678_9abc_def0;
    registers.rcx = 0x3333_2222_1111_0000;
    registers.rdx = 0xfedc_ba98_7654_3210;
    registers.r13 = 0x2000;
    registers.r14 = 0x3080;
    registers.rsp = 0x8008 - 40;
    registers.orig_rax = u64::MAX;
    registers.eflags = 0x202;
    Snapshot {
        logical_pc: registers.rip,
        registers,
        xstate: vec![0xa5; 64],
        data: vec![0x73; PAGE],
        application_stack: vec![0x5a; 184],
    }
}
fn next(before: &Snapshot, offset: u64) -> Snapshot {
    let mut after = copy_snapshot(before);
    after.logical_pc = 0x1000 + offset;
    after.registers.rip = after.logical_pc;
    after
}
fn corruptions() -> [fn(&mut Snapshot); 7] {
    [
        |p| p.registers.rbx ^= 1,
        |p| p.registers.rcx ^= 1,
        |p| p.registers.eflags ^= 1,
        |p| p.registers.fs_base ^= 1,
        |p| p.xstate[31] ^= 1,
        |p| p.data[19] ^= 1,
        |p| p.application_stack[0] ^= 1,
    ]
}
#[test]
fn ready_envelope_requires_owned_cells_and_exact_tail() {
    let r = ReferenceReady {
        normal: ready(),
        cells: 0x3080,
    };
    let wire = r.encode();
    let decoded = ReferenceReady::decode(&wire, 0x3080);
    assert_eq!(decoded.encode(), r.normal.encode());
    refused(|| {
        ReferenceReady::decode(&wire, 0x3088);
    });
    refused(|| {
        ReferenceReady::decode(&r.normal.encode(), 0x3080);
    });
    for end in 0..wire.len() {
        refused(|| {
            ReferenceReady::decode(&wire[..end], 0x3080);
        });
    }
    for at in [0, 8, 16] {
        let mut bad = wire.clone();
        bad[at] ^= 1;
        refused(|| {
            ReferenceReady::decode(&bad, 0x3080);
        });
    }
    let mut extra = wire;
    extra.push(0);
    refused(|| {
        ReferenceReady::decode(&extra, 0x3080);
    });
}
#[test]
fn helper_effects_preserve_complete_state() {
    // Independent LFENCE transition: successor changes, all application state stays.
    let before = point(44);
    let good = next(&before, 47);
    witness().effect(&before, &good);
    for corrupt in corruptions() {
        let mut bad = copy_snapshot(&good);
        corrupt(&mut bad);
        refused(|| witness().effect(&before, &bad));
    }
    let mut wrong = copy_snapshot(&good);
    wrong.registers.rip += 1;
    refused(|| witness().effect(&before, &wrong));
    let mut wrong = copy_snapshot(&good);
    wrong.logical_pc += 1;
    refused(|| witness().effect(&before, &wrong));
    // Actual five-register stack save geometry; complete protected stack remains compared.
    let before = point(15);
    let mut after = next(&before, 17);
    after.registers.rsp -= 8;
    put_word(
        &mut after.application_stack,
        witness().stack,
        after.registers.rsp,
        before.registers.r14,
    );
    witness().effect(&before, &after);
    for at in 0..after.application_stack.len() {
        let mut bad = copy_snapshot(&after);
        bad.application_stack[at] ^= 1;
        refused(|| witness().effect(&before, &bad));
    }
}
#[test]
fn rdtscp_outputs_require_actual_width_and_store_identity() {
    let before = point(47);
    let mut after = next(&before, 50);
    after.registers.rax = 0x89ab_cdef;
    after.registers.rdx = 7;
    after.registers.rcx = 13;
    let mut w = witness();
    w.effect(&before, &after);
    assert_eq!(w.outputs[0], Some([0x89ab_cdef, 7, 13]));
    for register in 0..3 {
        let mut bad = copy_snapshot(&after);
        match register {
            0 => bad.registers.rax |= 1 << 32,
            1 => bad.registers.rdx |= 1 << 32,
            _ => bad.registers.rcx |= 1 << 32,
        }
        refused(|| witness().effect(&before, &bad));
    }
    let mut duplicate = witness();
    duplicate.outputs[0] = Some([0, 0, 0]);
    refused(|| duplicate.effect(&before, &after));
    for (index, pc) in [53, 57, 61].into_iter().enumerate() {
        let mut before = point(pc);
        before.registers.rax = 0x89ab_cdef;
        before.registers.rdx = 7;
        before.registers.rcx = 13;
        let after = next(&before, pc + 4);
        let mut w = witness();
        w.outputs[0] = Some([0x89ab_cdef, 7, 13]);
        let old = w.page.clone();
        w.effect(&before, &after);
        let at = CELLS_AT + [40, 48, 56][index];
        let mut expected = old;
        expected[at..at + 4].copy_from_slice(&[0x89ab_cdef_u32, 7, 13][index].to_le_bytes());
        assert_eq!(w.page, expected);
        assert_eq!(w.stores, 1);
        refused(|| witness().effect(&before, &after));
        let mut wrong = witness();
        wrong.outputs[0] = Some([0x89ab_cdef, 7, 13]);
        wrong.outputs[0].as_mut().unwrap()[index] ^= 1;
        refused(|| wrong.effect(&before, &after));
        let mut wrong_page = expected.clone();
        wrong_page[at + 4] = 1;
        refused(|| w.check_page(&wrong_page));
    }
}
#[test]
fn reader_restoration_and_head_order_are_exact() {
    let before = point(32);
    let after = next(&before, 77);
    let mut w = witness();
    w.heads = 12;
    w.observe_head(&before);
    for &offset in &bytes::HEADS[13..24] {
        w.observe_head(&next(&before, offset));
    }
    w.observe_head(&after);
    assert_eq!((w.readers, w.interiors, w.heads), (1, 11, 25));
    assert!(w.reader_start.is_none());
    for corrupt in corruptions() {
        let mut w = witness();
        w.heads = 24;
        w.reader_start = Some(copy_snapshot(&before));
        let mut bad = copy_snapshot(&after);
        corrupt(&mut bad);
        refused(|| w.observe_head(&bad));
    }
    for offset in [2, 36, 295] {
        refused(|| witness().observe_head(&point(offset)));
    }
    let mut w = witness();
    w.observe_head(&point(0));
    refused(|| w.observe_head(&point(0)));
    let mut w = witness();
    w.heads = 24;
    refused(|| w.observe_head(&after));
}
#[test]
fn calls_returns_keep_actual_words_and_full_stack() {
    for (index, offset) in bytes::CALLS.into_iter().enumerate() {
        let mut r = ready();
        r.boundaries = vec![(0x2024, 0x5024)];
        let mut before = point(offset);
        before.registers.rdi = 0x4080;
        before.registers.rsi = 64;
        call_before(&before.registers, &r, index, 0x8008, 0x4000, 64);
        let mut after = copy_snapshot(&before);
        after.logical_pc = r.entry;
        after.registers.rip = r.entry;
        after.registers.rsp -= 8;
        let return_pc = r.caller + bytes::CONTINUATIONS[index];
        put_word(
            &mut after.application_stack,
            witness().stack,
            after.registers.rsp,
            return_pc,
        );
        witness().effect(&before, &after);
        call_after(&after.registers, &r, index, 0x8008, return_pc);
        for badword in [
            return_pc - 1,
            return_pc + 1,
            r.caller + CONTINUATIONS[index],
        ] {
            refused(|| call_after(&after.registers, &r, index, 0x8008, badword));
        }
        let mut ret = after.registers;
        ret.rip = 0x5024;
        ret.rax = 91;
        ret_before(&ret, &r, index, 0x8008, 91, return_pc);
        ret.rip = return_pc;
        ret.rsp += 8;
        ret_after(&ret, &r, index, 0x8008, 91, return_pc);
        refused(|| ret_after(&ret, &r, index, 0x8008, 91, return_pc + 1));
        let mut changed = copy_snapshot(&after);
        changed.application_stack[0] ^= 1;
        refused(|| witness().effect(&before, &changed));
    }
}
fn completed() -> Witness {
    let mut w = witness();
    w.heads = 80;
    w.readers = 4;
    w.stores = 12;
    w.interiors = 46;
    w.outputs = [Some([1, 0, 3]); 4];
    w.outer_return = true;
    for index in 0..2 {
        let base = w.cells + index as u64 * 144;
        for (field, value) in [
            (0, 2),
            (24, w.rsp - 40),
            (32, w.rsp - 40),
            (40, 10 + 20 * index as u64),
            (48, 0),
            (56, 3),
            (64, 20 + 20 * index as u64),
            (72, 0),
            (80, 3),
            (112, w.value),
        ] {
            put_word(&mut w.page, w.page_address, base + field, value);
        }
    }
    w
}
#[test]
fn postflight_requires_outer_return_and_complete_cells() {
    let good = completed().page[CELLS_AT..CELLS_AT + bytes::CELLS_BYTES].to_vec();
    let endpoints = completed().finish(&good);
    assert_eq!((endpoints[0].start.ticks, endpoints[1].end.ticks), (10, 40));
    for at in 0..good.len() {
        let mut bad = good.clone();
        bad[at] ^= 1;
        refused(|| {
            completed().finish(&bad);
        });
    }
    for end in [0, 1, 143, 144, 287] {
        refused(|| {
            completed().finish(&good[..end]);
        });
    }
    let mut extra = good.clone();
    extra.push(0);
    refused(|| {
        completed().finish(&extra);
    });
    let mut w = completed();
    w.outer_return = false;
    refused(|| {
        w.finish(&good);
    });
    let mut w = completed();
    w.reader_start = Some(point(220));
    refused(|| {
        w.finish(&good);
    });
    for field in 0..5 {
        let mut w = completed();
        match field {
            0 => w.heads -= 1,
            1 => w.readers -= 1,
            2 => w.stores -= 1,
            3 => w.interiors -= 1,
            _ => w.outputs[3] = None,
        }
        refused(|| {
            w.finish(&good);
        });
    }
    // Even a matching entire exported cell page cannot excuse invalid identities/AUX/order.
    for (field, value) in [
        (8, 9),
        (16, 9),
        (24, 0),
        (32, 0),
        (56, 1 << 32),
        (80, 4),
        (40, 21),
        (136, 0),
    ] {
        let mut w = completed();
        put_word(&mut w.page, w.page_address, w.cells + field, value);
        let bad = w.page[CELLS_AT..CELLS_AT + bytes::CELLS_BYTES].to_vec();
        refused(|| {
            w.finish(&bad);
        });
    }
}
#[test]
fn cell_page_requires_full_guards_and_disjoint_ranges() {
    check_cell_ranges(0x3080, &[(0x1000, 0x3000), (0x4000, 0x8008)]);
    for range in [
        (0x2fff, 0x3001),
        (0x3070, 0x3080),
        (0x31a0, 0x31a1),
        (0x3fff, 0x4001),
    ] {
        refused(|| check_cell_ranges(0x3080, &[range]));
    }
    for address in [0, 0x3081, 0x3088, u64::MAX] {
        refused(|| check_cell_ranges(address, &[(0x1000, 0x2000)]));
    }
    let w = witness();
    w.check_page(&w.page);
    for at in 0..PAGE {
        let mut bad = w.page.clone();
        bad[at] ^= 1;
        refused(|| w.check_page(&bad));
    }
}
fn result(case: ExactCase) -> NormalPairResult {
    let comparisons = 34 + 2 * case.counts().0;
    NormalPairResult {
        comparisons,
        original_steps: comparisons + 46,
        candidate_steps: comparisons + 46,
        visits: [case.counts().0; 2],
        returns: [0x2024; 2],
        declared_returns: BTreeSet::from([0x2024]),
        values: [case.scalar(); 2],
        outer_value: case.scalar().wrapping_mul(2),
        target_calls: 4,
        target_returns: 4,
        outer_returns: 2,
        normal_reaps: 2,
    }
}
fn stats() -> Stats {
    let e = bytes::Enclosure {
        start: bytes::Timestamp { ticks: 1, aux: 3 },
        end: bytes::Timestamp { ticks: 2, aux: 3 },
    };
    Stats {
        reader_checks: 8,
        output_stores: 24,
        helper_heads: 160,
        interior_heads: 92,
        returned_cells: 4,
        endpoints: [[e; 2]; 2],
    }
}
#[test]
fn pair_counts_require_all_heads_readers_stores_and_reaps() {
    let mut comparisons = 0;
    for seed in SEEDS {
        for length in [1, 64] {
            let case = ExactCase::new(seed, length);
            let pair = result(case);
            validate_pair(case, &pair, &[case.counts(); 2], &stats());
            comparisons += pair.comparisons;
        }
    }
    assert_eq!(comparisons, 1736);
    let case = ExactCase::new(SEEDS[0], 64);
    for field in 0..15 {
        let mut p = result(case);
        match field {
            0 => p.comparisons -= 1,
            1 => p.original_steps -= 1,
            2 => p.candidate_steps = MAX_STEPS + 1,
            3 => p.visits[0] -= 1,
            4 => p.returns[1] += 1,
            5 => p.declared_returns.clear(),
            6 => p.values[1] ^= 1,
            7 => p.outer_value ^= 1,
            8 => p.target_calls -= 1,
            9 => p.target_returns -= 1,
            10 => p.outer_returns -= 1,
            11 => p.normal_reaps -= 1,
            12 => p.original_steps = MAX_STEPS + 1,
            13 => p.candidate_steps -= 1,
            _ => p.visits[1] -= 1,
        }
        refused(|| validate_pair(case, &p, &[case.counts(); 2], &stats()));
    }
    for field in 0..5 {
        let mut s = stats();
        match field {
            0 => s.reader_checks -= 1,
            1 => s.output_stores -= 1,
            2 => s.helper_heads -= 1,
            3 => s.interior_heads -= 1,
            _ => s.returned_cells -= 1,
        }
        refused(|| validate_pair(case, &result(case), &[case.counts(); 2], &s));
    }
    let mut counts = [case.counts(); 2];
    counts[1].3 -= 1;
    refused(|| validate_pair(case, &result(case), &counts, &stats()));
}
