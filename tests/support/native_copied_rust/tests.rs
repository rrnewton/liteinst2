//! Fabricated inert bytes/copies only; no mappings, receipt or native execution.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
const BYTES: &[u8] = &[
    0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0, 0x48,
    0x89, 0x03, 0x5b, 0xc3,
];
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn plan() -> Plan {
    rust_invoke::admit(BYTES).unwrap()
}
fn fixture(function: usize, index: usize) -> Ready {
    let plan = plan();
    let mut caller = vec![0xcc; PAGE];
    caller[128..128 + BYTES.len()].copy_from_slice(BYTES);
    let mut source = vec![0x90; PAGE];
    source[5] = 0xc3;
    source[69] = 0xc3;
    Ready {
        caller: 0x1080,
        caller_immutable: vec![(0x1000, caller)],
        functions: [0x3000, 0x3040].map(|entry| module::Function {
            entry,
            heads: (0..6).map(|n| entry + n).collect(),
            returns: vec![entry + 5],
            boundaries: (0..6).map(|n| (entry + n, entry + n)).collect(),
        }),
        immutable: vec![(0x3000, source.clone())],
        original_source: source,
        journal: None,
        case: Case::new(function, index, 6, 6, 0),
        plan,
    }
}
#[test]
fn closed_cases_and_profile_refuse_crossovers() {
    let values = [
        (0..16)
            .map(|index| csv::Case::new(index).expected())
            .collect::<Vec<_>>(),
        CASES
            .into_iter()
            .map(strnlen::cases::scalar)
            .collect::<Vec<_>>(),
    ];
    assert_eq!(values.each_ref().map(Vec::len), [16, 8]);
    for (function, values) in values.iter().enumerate() {
        for (index, &value) in values.iter().enumerate() {
            for order in 0..2 {
                let c = Case::new(function, index, 256, 80, order);
                assert_eq!(c.selected(), if function == 0 { order } else { 1 - order });
                assert_eq!(c.value(), value);
            }
        }
    }
    for (f, i, a, b, o) in [
        (2, 0, 6, 6, 0),
        (0, 16, 6, 6, 0),
        (1, 8, 6, 6, 0),
        (0, 0, 4, 6, 0),
        (0, 0, 257, 6, 0),
        (0, 0, 6, 4, 0),
        (0, 0, 6, 81, 0),
        (0, 0, 6, 6, 2),
    ] {
        refuses(|| {
            Case::new(f, i, a, b, o);
        });
    }
    let p = plan();
    let profile = CallerProfile::CopiedRust(&p);
    assert_eq!(profile.calls(), [13]);
    assert_eq!(profile.continuations(), [15]);
    assert_eq!(profile.outer_ret(), 19);
    assert!(profile.heads().iter().all(|&n| profile.compare(n)));
    assert_ne!(profile, CallerProfile::Legacy);
    assert_ne!(profile, CallerProfile::Module);
    assert_ne!(profile, CallerProfile::Reference);
    let r = fixture(0, 0);
    let w = r.encode();
    refuses(|| {
        NormalReady::decode(&w);
    });
    refuses(|| {
        module::Ready::decode(&w);
    });
    refuses(|| {
        module::Ready::decode_session(&w);
    });
}
#[test]
fn ready_wire_requires_exact_parent_plan_and_geometry() {
    let r = fixture(0, 0);
    let p = Profile::new(
        r.case,
        r.plan.clone(),
        r.caller,
        r.caller_immutable[0].clone(),
    );
    let w = r.encode();
    let decoded = Ready::decode(&w, r.case, &r.plan);
    decoded.same_source(&r);
    assert_eq!(decoded.validate(false, &p).len(), 12);
    for n in [0, VERSION.len(), w.len() - 1] {
        let mut bad = w.clone();
        bad[n] ^= 1;
        refuses(|| {
            Ready::decode(&bad, r.case, &r.plan).validate(false, &p);
        });
    }
    refuses(|| {
        Ready::decode(&w[..w.len() - 1], r.case, &r.plan);
    });
    let mut extra = w.clone();
    extra.push(0);
    refuses(|| {
        Ready::decode(&extra, r.case, &r.plan);
    });
    refuses(|| {
        Ready::decode(&w, Case::new(1, 0, 6, 6, 0), &r.plan);
    });
    let other = rust_invoke::admit(&[
        0x55, 0x48, 0x89, 0xcd, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0,
        0x48, 0x89, 0x45, 0x00, 0x5d, 0xc3,
    ])
    .unwrap();
    refuses(|| {
        Ready::decode(&w, r.case, &other);
    });
    for which in 0..7 {
        let mut bad = r.clone();
        match which {
            0 => bad.caller_immutable[0].1[127] ^= 1, // Same bytes can decode, but source join must retain full padding.
            1 => bad.functions[0].heads.pop().map(|_| ()).unwrap(),
            2 => bad.functions[1].returns[0] -= 1,
            3 => bad.functions[1].boundaries[0].1 = bad.functions[0].entry,
            4 => bad.immutable[0].1[100] ^= 1,
            5 => bad.original_source[5] = 0x90,
            _ => bad.caller += 1,
        };
        refuses(|| {
            bad.validate(false, &p);
        });
    }
}
#[test]
fn single_call_order_and_full_journal_are_exact() {
    call_order(0, 0, 0);
    ret_order(1, 0);
    for t in [(1, 0, 0), (0, 1, 0), (0, 0, 1)] {
        refuses(|| call_order(t.0, t.1, t.2));
    }
    refuses(|| ret_order(0, 0));
    refuses(|| ret_order(1, 1));
    let mut r = fixture(1, 2);
    r.journal = Some(JournalReady {
        address: 0x7000,
        a_generation: 17,
        b_generation: None,
        helper_tid: None,
    });
    let words = journal_words(&r, 23, 0x9008, &[0x3045], true);
    let mut expected = [0; 512];
    expected[..4].copy_from_slice(&[2, 0, 23, 1]);
    expected[4..18].copy_from_slice(&[
        1, 1, 0x3040, 0x8ff8, 0x108f, 17, 8193, 2, 1, 0x3045, 0x8ff8, 0x108f, 17, 8193,
    ]);
    assert_eq!(words, expected);
    let bytes = words
        .iter()
        .flat_map(|n| n.to_le_bytes())
        .collect::<Vec<_>>();
    check_journal(&bytes, &expected);
    for i in 0..512 {
        let mut bad = bytes.clone();
        bad[i * 8] ^= 1;
        refuses(|| check_journal(&bad, &expected));
    }
    let clear = journal_words(&r, 23, 0x9008, &[0x3045], false);
    expected[3] = 0;
    assert_eq!(clear, expected);
    refuses(|| {
        journal_words(&r, 23, 0x9008, &[], true);
    });
    refuses(|| {
        journal_words(&r, 23, 0x9008, &[0x3005], true);
    });
    let initial = vec![0x5a; PAGE];
    let mut data = initial.clone();
    data[RESULTS..RESULTS + 8].copy_from_slice(&1_u64.to_le_bytes());
    check_data(&initial, &data, 1, true);
    data[RESULTS + 8] ^= 1;
    refuses(|| check_data(&initial, &data, 1, true));
}
fn snapshot(pc: u64) -> Snapshot {
    // Fully initialized inert register copy; it is never a ptrace/native receipt.
    let mut r: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    r.rip = pc;
    r.rsp = 0x9008;
    r.eflags = 0x202;
    Snapshot {
        logical_pc: pc,
        registers: r,
        xstate: vec![0; 512],
        data: vec![0; PAGE],
        application_stack: vec![0x5a; 152],
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
#[test]
fn caller_effects_cover_every_operation_and_outer_return() {
    let r = fixture(0, 0);
    let stack = 0x9008 - 144;
    let data = 0x5000;
    let mut p = snapshot(r.caller);
    p.registers.rbx = 0x7777;
    p.registers.rcx = data + 320;
    p.registers.rdi = 0x3000;
    p.registers.rsi = data + 128;
    p.registers.rdx = 0;
    put_word(&mut p.application_stack, stack, 0x9008, 0x2222);
    let mut points = vec![p];
    for pc in [
        0x1081, 0x1084, 0x1087, 0x108a, 0x108d, 0x3000, 0x3005, 0x108f, 0x1092, 0x1093, 0x2222,
    ] {
        let mut p = clone_point(points.last().unwrap());
        p.logical_pc = pc;
        p.registers.rip = pc;
        match pc {
            0x1081 => {
                p.registers.rsp = 0x9000;
                put_word(&mut p.application_stack, stack, 0x9000, 0x7777);
            }
            0x1084 => p.registers.rbx = data + 320,
            0x1087 => p.registers.rax = 0x3000,
            0x108a => p.registers.rdi = data + 128,
            0x108d => p.registers.rsi = 0,
            0x3000 => {
                p.registers.rsp = 0x8ff8;
                put_word(&mut p.application_stack, stack, 0x8ff8, 0x108f);
            }
            0x3005 => p.registers.rax = 1,
            0x108f => p.registers.rsp = 0x9000,
            0x1092 => put_word(&mut p.data, data, data + 320, 1),
            0x1093 => {
                p.registers.rbx = 0x7777;
                p.registers.rsp = 0x9008;
            }
            0x2222 => p.registers.rsp = 0x9010,
            _ => unreachable!(),
        }
        points.push(p);
    }
    effects::caller_effects(&points, &r, data, stack);
    for which in 0..6 {
        let mut bad = clone_point(points.last().unwrap());
        match which {
            0 => bad.registers.rax ^= 1,
            1 => bad.registers.rsp += 8,
            2 => bad.registers.rip += 1,
            3 => bad.registers.eflags ^= 0x40,
            4 => bad.application_stack[144] ^= 1,
            _ => bad.xstate[511] ^= 1,
        };
        refuses(|| effects::outer_effect(&points[points.len() - 2], &bad, stack));
    }
    let rich = rust_invoke::admit(&[
        0x53, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0x0c, 0x24, 0x48, 0x8d, 0x1c, 0x24, 0x48, 0x8b,
        0x1b, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0, 0x48, 0x89, 0x03,
        0x48, 0x83, 0xc4, 0x10, 0x5b, 0xc3,
    ])
    .unwrap();
    let mut rich_ready = r.clone();
    rich_ready.plan = rich;
    // Independent concrete SUB, stack store, LEA, load, ADD vectors.
    for (offset, next) in [(1, 5), (5, 9), (9, 13), (13, 16), (30, 34)] {
        let mut a = snapshot(r.caller + offset);
        a.registers.rsp = 0x9000;
        a.registers.rcx = data + 320;
        a.registers.rbx = 0x9000;
        a.application_stack = vec![0; 176];
        let base = 0x8f60;
        put_word(&mut a.application_stack, base, 0x9000, data + 320);
        if offset == 5 {
            put_word(&mut a.application_stack, base, 0x9000, 0);
        }
        if offset == 9 {
            a.registers.rbx = 0x7777;
        }
        let mut b = clone_point(&a);
        b.logical_pc = r.caller + next;
        b.registers.rip = b.logical_pc;
        match offset {
            1 => {
                b.registers.rsp = 0x8ff0;
                b.registers.eflags = 0x206;
            }
            5 => put_word(&mut b.application_stack, base, 0x9000, data + 320),
            9 => b.registers.rbx = 0x9000,
            13 => b.registers.rbx = data + 320,
            30 => {
                b.registers.rsp = 0x9010;
                b.registers.eflags = 0x202;
            }
            _ => unreachable!(),
        }
        effects::step(&a, &b, &rich_ready, data, base);
        b.registers.r12 ^= 1;
        refuses(|| effects::step(&a, &b, &rich_ready, data, base));
    }
}
fn metadata(case: Case) -> (NormalPairResult<1>, Trace) {
    let declared = BodyCoverage {
        heads: BTreeSet::from([0, 1]),
        edges: BTreeSet::from([(0, 1)]),
        returns: BTreeSet::from([1]),
    };
    let trace = if case.function == 0 {
        Trace::Csv(csv::BodyTrace {
            entry: 0x3000,
            visits: 2,
            ret_offset: 1,
            heads: declared.heads.clone(),
            edges: declared.edges.clone(),
            code: vec![0x90, 0xc3],
            declared: csv::Graph {
                heads: declared.heads.clone(),
                edges: declared.edges.clone(),
                returns: declared.returns.clone(),
            },
        })
    } else {
        Trace::Length(BodyTrace {
            entry: 0x3040,
            code: vec![0x90, 0xc3],
            declared: declared.clone(),
            observed: declared,
            visits: 2,
            input_reads: usize::from(case.bound() != 0),
            input_bytes: usize::from(case.bound() != 0),
            ret_offset: 1,
        })
    };
    let comparisons = plan().heads().len() + 3;
    (
        NormalPairResult {
            comparisons,
            original_steps: comparisons + 1,
            candidate_steps: comparisons + 7,
            visits: [2],
            returns: [if case.function == 0 { 0x3001 } else { 0x3041 }],
            declared_returns: BTreeSet::from([if case.function == 0 { 0x3001 } else { 0x3041 }]),
            values: [case.value()],
            outer_value: 0xdead,
            target_calls: 2,
            target_returns: 2,
            outer_returns: 2,
            normal_reaps: 2,
        },
        trace,
    )
}
#[test]
fn fixed_population_requires_complete_corpus_and_declared_returns() {
    let mut p = Population::default();
    let plan = plan();
    let mut groups = 0;
    for seed in SEEDS {
        for f in 0..2 {
            for i in 0..if f == 0 { 16 } else { 8 } {
                let c = Case::new(f, i, 6, 6, 0);
                let (pair, t) = metadata(c);
                if p.record(seed, c, &plan, &pair, &t).is_some() {
                    groups += 1;
                }
            }
        }
    }
    assert_eq!(groups, 4);
    assert_eq!(p.finish(), 48 * (plan.heads().len() + 3));
    let c = Case::new(0, 0, 6, 6, 0);
    let (pair, t) = metadata(c);
    refuses(|| {
        p.record(SEEDS[0], c, &plan, &pair, &t);
    });
    refuses(|| {
        Population::default().finish();
    });
    for which in 0..8 {
        let (mut pair, mut t) = metadata(c);
        let mut seed = SEEDS[0];
        let mut c = c;
        match which {
            0 => seed = SEEDS[1],
            1 => c = Case::new(0, 1, 6, 6, 0),
            2 => pair.normal_reaps = 1,
            3 => pair.target_calls = 4,
            4 => pair.comparisons -= 1,
            5 => pair.candidate_steps = MAX_STEPS + 1,
            6 => pair.values[0] += 1,
            _ => {
                let Trace::Csv(t) = &mut t else {
                    unreachable!()
                };
                t.declared.returns.insert(2);
                pair.declared_returns.insert(0x3002);
            }
        };
        refuses(|| {
            let mut p = Population::default();
            p.record(seed, c, &plan, &pair, &t);
            if which == 7 {
                for i in 1..16 {
                    let c = Case::new(0, i, 6, 6, 0);
                    let (mut pair, mut t) = metadata(c);
                    let Trace::Csv(t) = &mut t else {
                        unreachable!()
                    };
                    t.declared.returns.insert(2);
                    pair.declared_returns.insert(0x3002);
                    let t = Trace::Csv(t.clone());
                    p.record(SEEDS[0], c, &plan, &pair, &t);
                }
            }
        });
    }
}
