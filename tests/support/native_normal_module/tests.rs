//! Fabricated inputs exercise real validators only; no CALL/reap/native credit.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn ready(k: usize, candidate: bool) -> Ready {
    let code = [0xb8, 1, 0, 0, 0, 0xc3];
    let mut source = vec![0; PAGE];
    source[..6].copy_from_slice(&code);
    source[64..70].copy_from_slice(&code);
    let mut helper = vec![0; PAGE];
    helper[..bytes::BYTES.len()].copy_from_slice(bytes::BYTES);
    let functions = [0x3000, 0x3040].map(|entry| Function {
        entry,
        heads: vec![entry, entry + 5],
        returns: vec![entry + 5],
        boundaries: vec![(entry, entry), (entry + 5, entry + 5)],
    });
    Ready {
        caller: 0x1000,
        caller_immutable: vec![(0x1000, helper)],
        functions,
        immutable: vec![(0x3000, source.clone())],
        original_source: source,
        journal: candidate.then_some(JournalReady {
            address: 0x7000,
            a_generation: 11,
            b_generation: None,
            helper_tid: None,
        }),
        case: Case::new(0, k, 6, 6, 0),
    }
}
fn clone_point(p: &Snapshot) -> Snapshot {
    Snapshot {
        logical_pc: p.logical_pc,
        registers: p.registers,
        xstate: p.xstate.clone(),
        data: p.data.clone(),
        application_stack: p.application_stack.clone(),
    }
}
fn point(pc: u64) -> Snapshot {
    let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    registers.rip = pc;
    registers.rsp = 0x9100;
    registers.eflags = 2;
    Snapshot {
        logical_pc: pc,
        registers,
        xstate: vec![0; 1024],
        data: vec![0; PAGE],
        application_stack: vec![0; 256],
    }
}
#[test]
fn module_case_domain_preserves_all_inputs_and_mixed_extents() {
    for k in [1, 16] {
        for index in 0..16 {
            for order in 0..2 {
                let c = Case::new(index, k, 256, 80, order);
                assert_eq!(c.csv, csv::Case::new(index));
                assert_eq!(c.length, CASES[index % 8]);
                assert_eq!(
                    c.values(),
                    [
                        c.csv.expected(),
                        strnlen::cases::scalar(c.length),
                        c.csv.expected(),
                        strnlen::cases::scalar(c.length)
                    ]
                );
                assert_eq!(c.order, [order, 1 - order]);
                assert_eq!(c.admitted(), if k == 1 { 2 } else { 4 });
            }
        }
    }
    assert_eq!(
        Arguments::parse("1", "4096", "256", "4352", "80")
            .case(0)
            .order,
        [0, 1]
    );
    assert_eq!(
        Arguments::parse("16", "4352", "256", "4096", "80")
            .case(0)
            .order,
        [1, 0]
    );
    for (k, a, b) in [
        ("01", "256", "80"),
        ("2", "256", "80"),
        ("1", "257", "80"),
        ("16", "256", "81"),
        ("1", "4", "80"),
    ] {
        refuses(|| {
            Arguments::parse(k, "4096", a, "8192", b);
        });
    }
    refuses(|| {
        Arguments::parse("1", "4096", "6", "4097", "6");
    });
    refuses(|| {
        Case::new(16, 1, 6, 6, 0);
    });
    refuses(|| {
        Case::new(0, 1, 6, 6, 2);
    });
}
#[test]
fn module_ready_requires_complete_shared_union_and_unique_maps() {
    for candidate in [false, true] {
        for order in [0, 1] {
            let mut r = ready(1, candidate);
            r.case = Case::new(0, 1, 6, 6, order);
            assert_eq!(r.validate(candidate, r.case).len(), 4);
            assert_eq!(r.target(0).entry, r.functions[order].entry);
        }
    }
    for mutation in 0..8 {
        let mut r = ready(1, true);
        match mutation {
            0 => r.original_source[64] = 0xc3,
            1 => r.functions[1].heads.pop().map(|_| ()).unwrap(),
            2 => r.functions[1].boundaries[0].1 = r.functions[0].entry,
            3 => r.functions[1].returns[0] = r.functions[0].returns[0],
            4 => r.immutable[0].1[32] = 1,
            5 => r.immutable[0].1.push(0),
            6 => r.journal.as_mut().unwrap().address = 0x3000,
            _ => r.caller_immutable[0].1[31] ^= 1,
        }
        refuses(|| {
            r.validate(true, r.case);
        });
    }
    let a = ready(1, false);
    let mut b = ready(1, true);
    b.case.order = [1, 0];
    refuses(|| a.same_source(&b));
}
#[test]
fn module_wire_refuses_extra_missing_and_oversized_fields() {
    let r = ready(16, true);
    let wire = r.encode();
    let decoded = Ready::decode(&wire);
    r.same_source(&decoded);
    decoded.validate(true, r.case);
    let mut extra = wire.clone();
    extra.push(0);
    refuses(|| {
        Ready::decode(&extra);
    });
    refuses(|| {
        Ready::decode(&wire[..wire.len() - 1]);
    });
    let mut huge = wire.clone();
    huge[56..64].copy_from_slice(&257u64.to_le_bytes());
    refuses(|| {
        Ready::decode(&huge);
    });
    let mut wrong = wire;
    wrong[16..24].copy_from_slice(&2u64.to_le_bytes());
    refuses(|| {
        Ready::decode(&wrong);
    });
}
#[test]
fn module_four_transfers_require_order_target_rsp_and_real_words() {
    let r = ready(1, true);
    let data = 0x20000;
    let rsp = 0x9008;
    for call in 0..4 {
        call_order(call, call, call);
        ret_order(call + 1, call);
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.rip = r.caller + bytes::CALLS[call];
        regs.r13 = data + TARGETS as u64;
        regs.rbp = data + REQUESTS as u64;
        regs.r12 = data + RESULTS as u64;
        regs.rdi = data + (if call % 2 == 0 { INPUT } else { LENGTH_INPUT }) as u64;
        regs.rsi = r.case.bound(call) as u64;
        regs.rsp = rsp - 56;
        call_before(&regs, &r, call, rsp, data, r.case.bound(call));
        let mut wrong = regs;
        wrong.rdi += 64;
        refuses(|| call_before(&wrong, &r, call, rsp, data, r.case.bound(call)));
        regs.rip = r.target(call).entry;
        regs.rsp = rsp - 64;
        let word = r.caller + bytes::CONTINUATIONS[call];
        call_after(&regs, &r, call, rsp, word);
        refuses(|| call_after(&regs, &r, call, rsp, word + 1));
        regs.rip = r.target(call).returns[0];
        regs.rax = r.case.value(call);
        ret_before(&regs, &r, call, rsp, regs.rax, word);
        wrong = regs;
        wrong.rip = r.target((call + 1) % 4).returns[0];
        refuses(|| ret_before(&wrong, &r, call, rsp, regs.rax, word));
        regs.rip = word;
        regs.rsp += 8;
        ret_after(&regs, &r, call, rsp, regs.rax, word);
    }
    refuses(|| call_order(1, 0, 1));
    refuses(|| call_order(4, 4, 4));
    refuses(|| ret_order(4, 4));
}
#[test]
fn module_helper_effects_keep_full_state_and_four_store_slots() {
    let r = ready(16, false);
    let data = 0x20000;
    let stack = 0x9000;
    let mut before = point(r.caller + 6);
    before.registers.rdi = 0x1234;
    before.registers.r13 = 7;
    let mut after = clone_point(&before);
    after.logical_pc = r.caller + 9;
    after.registers.rip = after.logical_pc;
    after.registers.r13 = 0x1234;
    witness::step(&before, &after, &r, data, stack);
    for mutation in 0..4 {
        let mut bad = clone_point(&after);
        match mutation {
            0 => bad.registers.rcx ^= 1,
            1 => bad.xstate[200] ^= 1,
            2 => bad.application_stack[0] ^= 1,
            _ => bad.data[17] ^= 1,
        };
        refuses(|| witness::step(&before, &bad, &r, data, stack));
    }
    for (i, &offset) in bytes::RESULT_STORES.iter().enumerate() {
        let mut before = point(r.caller + offset);
        before.registers.r12 = data + RESULTS as u64;
        before.registers.rax = 11 + i as u64;
        let mut after = clone_point(&before);
        let next = bytes::HEADS.iter().position(|&n| n == offset).unwrap() + 1;
        after.logical_pc = r.caller + bytes::HEADS[next];
        after.registers.rip = after.logical_pc;
        after.data[RESULTS + i * 8..RESULTS + i * 8 + 8]
            .copy_from_slice(&(11 + i as u64).to_le_bytes());
        witness::step(&before, &after, &r, data, stack);
        after.data[RESULTS + (3 - i) * 8] ^= 1;
        refuses(|| witness::step(&before, &after, &r, data, stack));
    }
}
#[test]
fn module_data_and_journal_cover_both_inputs_targets_and_closed_owners() {
    for k in [1, 16] {
        let r = ready(k, true);
        let initial = vec![0xa7; PAGE];
        let mut actual = initial.clone();
        for i in 0..2 {
            put_word(
                &mut actual,
                0,
                (TARGETS + i * 8) as u64,
                r.functions[i].entry,
            );
        }
        for i in 0..4 {
            put_word(&mut actual, 0, (RESULTS + i * 8) as u64, r.case.value(i));
        }
        check_data(&initial, &actual, &r, true);
        for at in [INPUT, LENGTH_INPUT, REQUESTS, TARGETS, RESULTS + 24, 4095] {
            let mut bad = actual.clone();
            bad[at] ^= 1;
            refuses(|| check_data(&initial, &bad, &r, true));
        }
        let returns = [0x3005, 0x3045, 0x3005, 0x3045];
        let words = journal_words(&r, 17, 0x9008, &returns, true);
        assert_eq!(&words[..4], &[8, 0, 17, 1]);
        assert!(words[60..].iter().all(|&x| x == 0));
        assert_eq!(words[32], if k == 1 { 3 } else { 1 });
        assert_eq!(words[39], if k == 1 { 4 } else { 2 });
        assert_eq!(
            words[38],
            if k == 1 {
                (1 << 13) | (3 << 22)
            } else {
                3 | (1 << 13)
            }
        );
        assert_eq!(journal_words(&r, 17, 0x9008, &returns, false)[3], 0);
        let mut bad = returns;
        bad.swap(0, 1);
        refuses(|| {
            journal_words(&r, 17, 0x9008, &bad, true);
        });
    }
}
fn fixture(case: Case) -> (NormalPairResult<4>, Trace) {
    let code = vec![0xb8, 1, 0, 0, 0, 0xc3];
    let graph = csv::graph(&code);
    let csv = csv::BodyTrace {
        entry: 0x3000,
        visits: 2,
        ret_offset: 5,
        heads: graph.heads.clone(),
        edges: graph.edges.clone(),
        code: code.clone(),
        declared: graph,
    };
    let coverage = BodyCoverage {
        heads: BTreeSet::from([0, 5]),
        edges: BTreeSet::from([(0, 5)]),
        returns: BTreeSet::from([5]),
    };
    let length = BodyTrace {
        entry: 0x3040,
        code,
        declared: coverage.clone(),
        observed: coverage,
        visits: 2,
        input_reads: usize::from(case.length.bound != 0),
        input_bytes: usize::from(case.length.bound != 0),
        ret_offset: 5,
    };
    (
        NormalPairResult {
            comparisons: 48,
            original_steps: 48,
            candidate_steps: 48,
            visits: [2; 4],
            returns: [0x3005, 0x3045, 0x3005, 0x3045],
            declared_returns: BTreeSet::from([0x3005, 0x3045]),
            values: case.values(),
            outer_value: case.sum(),
            target_calls: 8,
            target_returns: 8,
            outer_returns: 2,
            normal_reaps: 2,
        },
        Trace {
            csv: [csv.clone(), csv],
            length: [length.clone(), length],
        },
    )
}
#[test]
fn module_population_requires_all_cases_seeds_returns_and_reaps() {
    for k in [1, 16] {
        let mut p = Population::default();
        for seed in SEEDS {
            for i in 0..16 {
                let case = Case::new(i, k, 6, 6, 0);
                let (pair, trace) = fixture(case);
                assert_eq!(p.record(seed, case, &pair, &trace).is_some(), i == 15);
            }
        }
        assert_eq!(p.finish(), 32 * 48);
    }
    refuses(|| {
        Population::default().finish();
    });
    let case = Case::new(0, 1, 6, 6, 0);
    let (mut pair, trace) = fixture(case);
    pair.normal_reaps = 1;
    refuses(|| trace::validate_pair(case, &pair, &trace));
    let (pair, mut trace) = fixture(case);
    trace.length[1].input_bytes = 1;
    refuses(|| trace::validate_pair(case, &pair, &trace));
    let (pair, trace) = fixture(case);
    refuses(|| {
        Population::default().record(SEEDS[1], case, &pair, &trace);
    });
}
#[test]
fn module_geometry_has_all_40_heads_and_four_exact_calls() {
    assert_eq!(
        (bytes::BYTES.len(), bytes::HEADS.len(), bytes::OUTER_RET),
        (123, 40, 122)
    );
    assert_eq!(
        (
            bytes::SUBJECT_RSP_DELTA,
            bytes::PROTECTED_STACK_BELOW_CALLER
        ),
        (64, 192)
    );
    let mut decoder = Decoder::with_ip(64, bytes::BYTES, 0, DecoderOptions::NONE);
    let mut heads = Vec::new();
    let mut calls = Vec::new();
    let mut returns = Vec::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        assert!(!i.is_invalid());
        heads.push(i.ip());
        if i.flow_control() == FlowControl::IndirectCall {
            calls.push((i.ip(), i.next_ip()));
        }
        if i.flow_control() == FlowControl::Return {
            returns.push(i.ip());
        }
    }
    assert_eq!(heads, bytes::HEADS);
    assert_eq!(
        calls,
        bytes::CALLS
            .into_iter()
            .zip(bytes::CONTINUATIONS)
            .collect::<Vec<_>>()
    );
    assert_eq!(returns, [122]);
    for i in 0..4 {
        assert_eq!(
            &bytes::BYTES[bytes::CALLS[i] as usize..bytes::CONTINUATIONS[i] as usize],
            call_bytes(i)
        );
    }
    assert_eq!(std::mem::size_of::<bytes::Request>(), 16);
}
