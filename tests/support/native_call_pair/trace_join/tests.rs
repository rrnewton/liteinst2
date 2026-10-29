//! Fabricated data exercise actual codecs/joins, not ptrace, owners or reaps.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn fixture(scenario: Scenario, k: usize) -> (Ready, Ready, Vec<Snapshot>, Trace, Witness) {
    let plan = rust_invoke::admit(&[
        0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0,
        0x48, 0x89, 0x03, 0x5b, 0xc3,
    ])
    .unwrap();
    let mut parent = vec![
        0x48, 0x83, 0xec, 24, 0x48, 0x89, 0x74, 0x24, 8, 0xe8, 0, 0, 0, 0, 0x48, 0x8b, 0x54, 0x24,
        8, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0x48, 0x83, 0xc4, 24, 0xc3,
    ];
    parent[10..14].copy_from_slice(&(0x3200i32 - 0x310e).to_le_bytes());
    let mut page = vec![0x90; PAGE];
    page[0x100..0x11f].copy_from_slice(&parent);
    page[0x205] = 0xc3;
    let pheads = vec![
        0x3100, 0x3104, 0x3109, 0x310e, 0x3113, 0x3117, 0x311a, 0x311e,
    ];
    let original = Ready {
        caller: 0x1080,
        caller_immutable: Vec::new(),
        functions: [
            module::Function {
                entry: 0x3100,
                heads: pheads.clone(),
                returns: vec![0x311e],
                boundaries: Vec::new(),
            },
            module::Function {
                entry: 0x3200,
                heads: (0..6).map(|n| 0x3200 + n).collect(),
                returns: vec![0x3205],
                boundaries: Vec::new(),
            },
        ],
        immutable: vec![(0x3000, page.clone())],
        original_sources: vec![(0x3000, page)],
        journal: None,
        case: Case::new(k, 0, scenario, [0x3100, 0x3200], [31, 6]),
        plan,
        layout: [240, 416, 144, 400],
    };
    let mut candidate = original.clone();
    candidate.journal = Some(JournalReady {
        address: 0x8000,
        a_generation: 11,
        b_generation: (scenario == Scenario::RearmB).then_some(12),
        helper_tid: scenario.helper().then_some(99),
    });
    let graph = csv::graph(&[0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]);
    let parent_plan = original.parent_plan();
    let trace = Trace {
        parent_entry: 0x3100,
        child_entry: 0x3200,
        parent_visits: 8,
        parent_ret_offset: 30,
        parent_heads: parent_plan.heads().into_iter().collect(),
        parent_edges: parent_plan.edges(),
        child: csv::BodyTrace {
            entry: 0x3200,
            visits: 6,
            ret_offset: 5,
            heads: graph.heads.clone(),
            edges: graph.edges.clone(),
            code: vec![0x90, 0x90, 0x90, 0x90, 0x90, 0xc3],
            declared: graph,
        },
        child_delta: 32,
        stack_bytes: original.plan.subject_rsp_delta() + 168,
        parent_generation: 11,
        child_generation: match scenario {
            Scenario::StableA => 11,
            Scenario::RearmB => 12,
            Scenario::RemovedChild => 0,
        },
    };
    let prsp = 0x9008 - original.plan.subject_rsp_delta();
    let crsp = prsp - 32;
    let stack = 0x9008 - (trace.stack_bytes - 8);
    let continuation = original.caller + original.plan.continuations()[0];
    let pcs: Vec<_> = [0x1080, 0x3100, 0x3104, 0x3109]
        .into_iter()
        .chain(0x3200..=0x3205)
        .chain([0x310e, 0x3113, 0x3117, 0x311a, 0x311e, continuation])
        .collect();
    let points = pcs
        .into_iter()
        .map(|pc| {
            let mut point = Snapshot {
                logical_pc: pc,
                registers: unsafe { std::mem::zeroed() },
                xstate: vec![0; 24],
                data: vec![0; PAGE],
                application_stack: vec![0; trace.stack_bytes as usize],
            };
            point.registers.rip = pc;
            point.registers.rax = 1;
            point.registers.rsp = if (0x3200..=0x3205).contains(&pc) {
                crsp
            } else if pc == continuation {
                prsp + 8
            } else if pc == 0x3100 || pc == 0x311e {
                prsp
            } else {
                prsp - 24
            };
            put_word(&mut point.application_stack, stack, prsp, continuation);
            put_word(&mut point.application_stack, stack, crsp, 0x310e);
            point
        })
        .collect::<Vec<_>>();
    let fs = frames(&original, &points, &trace);
    let mut w = Witness {
        header: [
            MAGIC,
            1,
            384,
            if k == 10 {
                scenario.id() - 1
            } else {
                96 + scenario.id() - 1
            },
            SEEDS[0],
            k as u64,
            0,
            scenario.id(),
            77,
            0x3100,
            31,
            0x3200,
            6,
            0x1080,
            20,
            0,
        ],
        batch: [0; 20],
        stream: [
            77,
            INSTALL,
            0xc5c5_c5c5_c5c5_c5c5,
            0xc5c5_c5c5_c5c5_c5c5,
            0xc5c5_c5c5_c5c5_c5c5,
            0xc5c5_c5c5_c5c5_c5c5,
            0x3100,
            1,
            501,
            502,
            0x3100,
            0x3200,
            0x3109,
            0x3200,
            0x310e,
            1,
        ],
        rows: [[0; 48]; 2],
        report_count: if scenario == Scenario::RearmB { 2 } else { 1 },
        reports: [[0; 46]; 2],
        history: [0; 50],
    };
    let sampled = u64::from(scenario.sampled_child());
    w.batch[..6].copy_from_slice(&[
        77,
        77,
        1,
        INSTALL,
        1,
        match scenario {
            Scenario::StableA => 1,
            Scenario::RearmB => 3,
            Scenario::RemovedChild => 2,
        },
    ]);
    w.batch[13..20].copy_from_slice(&[1, 1, 2, 2, 2, 1 + sampled, 1 - sampled]);
    for (n, (r, f)) in w.rows.iter_mut().zip(fs).enumerate() {
        let s = n == 0 || scenario.sampled_child();
        let generation = if n == 1 && scenario == Scenario::RearmB {
            12
        } else {
            11
        };
        let slot = u64::from(n == 1 && scenario == Scenario::StableA);
        let children = u64::from(n == 0) * sampled;
        r[..24].copy_from_slice(&[
            501 + n as u64,
            n as u64,
            1,
            n as u64 + 1,
            f.entry,
            f.ret,
            if s { 1 } else { 3 },
            generation,
            slot,
            10,
            3,
            20,
            3,
            f.rsp,
            f.word,
            f.resume,
            f.resume_rsp,
            1,
            if n == 0 { 2 } else { 1 },
            if n == 0 || scenario == Scenario::StableA {
                1
            } else {
                2
            },
            0,
            u64::from(n == 0),
            u64::from(s),
            children,
        ]);
        if s {
            r[24..36].copy_from_slice(&[
                1,
                generation,
                slot,
                501 + n as u64,
                10,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
            ]);
            r[36..48].copy_from_slice(&[
                1,
                generation,
                slot,
                501 + n as u64,
                10,
                1,
                0,
                1,
                1,
                20,
                children,
                0,
            ]);
        }
    }
    for (i, report) in w
        .reports
        .iter_mut()
        .take(w.report_count as usize)
        .enumerate()
    {
        report[0] = 11 + i as u64;
        let rows: Vec<_> = w
            .rows
            .iter()
            .filter(|r| r[6] == 1 && r[7] == report[0])
            .collect();
        report[1] = rows.len() as u64;
        for (r, obs) in rows.into_iter().zip(report[2..].chunks_exact_mut(22)) {
            obs[..10].copy_from_slice(&[r[7], r[8], r[0], 10, 1, 1, r[8], 1, 0, 0]);
            obs[10..].copy_from_slice(&r[36..48]);
        }
    }
    let (count, last) = if scenario == Scenario::RearmB {
        (3, 12)
    } else {
        (2, 11)
    };
    w.history[..16].copy_from_slice(&w.stream);
    w.history[16..26].copy_from_slice(&[1, 0, count, 0, 0, 0, 2, count - 1, last, count]);
    w.history[26..34].copy_from_slice(&[1, 11, 0, 0, 1, 11, 0, 0]);
    if scenario == Scenario::RearmB {
        w.history[34..42].copy_from_slice(&[1, 12, 0, 0, 1, 12, 0, 0]);
        w.history[42..50].copy_from_slice(&[2, 12, 0, 0, 0, 0, 0, 0]);
    } else {
        w.history[34..42].copy_from_slice(&[2, 11, 0, 0, 0, 0, 0, 0]);
    }
    (original, candidate, points, trace, w)
}
fn check(
    original: &Ready,
    candidate: &Ready,
    points: &[Snapshot],
    trace: &Trace,
    w: &Witness,
) -> [WorkRow; 2] {
    join(
        SEEDS[0],
        original,
        candidate,
        points,
        trace,
        (77, &witness::encode(w)),
    )
}
#[test]
fn postflight_codec_roundtrip_and_canonical_bounds_refuse() {
    let (_, _, _, _, w) = fixture(Scenario::StableA, 10);
    let b = witness::encode(&w);
    assert_eq!(b.len(), 3072);
    assert_eq!(witness::decode(&b), w);
    for len in 0..b.len() {
        refuses(|| {
            witness::decode(&b[..len]);
        });
    }
    let mut extra = b.to_vec();
    extra.push(0);
    refuses(|| {
        witness::decode(&extra);
    });
    for word in 291..384 {
        let mut bad = b;
        bad[word * 8] = 1;
        refuses(|| {
            witness::decode(&bad);
        });
    }
    for (word, value) in [
        (1, 2),
        (2, 385),
        (15, 1),
        (52 + 6, 99),
        (52 + 22, 2),
        (52 + 24, 2),
    ] {
        let mut bad = b;
        bad[word * 8..word * 8 + 8].copy_from_slice(&u64::to_le_bytes(value));
        refuses(|| {
            witness::decode(&bad);
        });
    }
}
#[test]
fn trace_join_stable_rearm_removed_preserves_instruction_membership() {
    for k in [10, 1000] {
        for scenario in [Scenario::StableA, Scenario::RearmB, Scenario::RemovedChild] {
            let (o, c, p, t, w) = fixture(scenario, k);
            let rows = check(&o, &c, &p, &t, &w).map(|r| r.values());
            assert_eq!(&rows[0][30..], &[8, 14, 13]);
            assert_eq!(&rows[1][30..], &[6, 6, 5]);
            assert_eq!(rows[0][32] - rows[1][32], 8);
            assert_eq!(rows[0][30] - 1, 7); // Seven parent instructions plus the child C3.
            assert_eq!(rows[0][26], 1);
            assert_eq!(rows[1][20], if scenario.sampled_child() { 1 } else { 3 });
            assert_eq!(
                rows[1][21],
                if scenario == Scenario::RearmB { 12 } else { 11 }
            );
            assert_eq!(
                rows[1][22],
                match scenario {
                    Scenario::StableA => 2,
                    Scenario::RearmB => 1,
                    Scenario::RemovedChild => 0,
                }
            );
            assert_eq!(rows[1][23], u64::from(scenario.sampled_child()));
            assert_eq!(rows[0][27], 1 + u64::from(scenario.sampled_child()));
        }
    }
}
#[test]
fn trace_join_rejects_changed_record_report_history_identity() {
    for scenario in [Scenario::StableA, Scenario::RearmB, Scenario::RemovedChild] {
        let (o, c, p, t, w) = fixture(scenario, 10);
        check(&o, &c, &p, &t, &w);
        for n in 0..2 {
            for i in (0..48).filter(|i| !(9..=12).contains(i)) {
                let mut bad = w.clone();
                bad.rows[n][i] ^= 1;
                refuses(|| {
                    check(&o, &c, &p, &t, &bad);
                });
            }
            for i in 0..46 {
                let mut bad = w.clone();
                bad.reports[n][i] ^= 1;
                refuses(|| {
                    check(&o, &c, &p, &t, &bad);
                });
            }
        }
        for i in 0..50 {
            let mut bad = w.clone();
            bad.history[i] ^= 1;
            refuses(|| {
                check(&o, &c, &p, &t, &bad);
            });
        }
        for i in 0..16 {
            let mut bad = w.clone();
            bad.header[i] ^= 1;
            refuses(|| {
                check(&o, &c, &p, &t, &bad);
            });
            let mut bad = w.clone();
            bad.stream[i] ^= 1;
            refuses(|| {
                check(&o, &c, &p, &t, &bad);
            });
        }
        for i in 0..20 {
            let mut bad = w.clone();
            bad.batch[i] ^= 1;
            refuses(|| {
                check(&o, &c, &p, &t, &bad);
            });
        }
        let mut duplicate = w.clone();
        duplicate.rows[1] = duplicate.rows[0];
        refuses(|| {
            check(&o, &c, &p, &t, &duplicate);
        });
        let mut reordered = w.clone();
        reordered.rows.swap(0, 1);
        refuses(|| {
            check(&o, &c, &p, &t, &reordered);
        });
        if scenario == Scenario::RearmB {
            let mut missing = w.clone();
            missing.report_count = 1;
            missing.reports[1] = [0; 46];
            refuses(|| {
                check(&o, &c, &p, &t, &missing);
            });
            let mut shifted = w.clone();
            shifted.rows[1][7] = 13;
            shifted.rows[1][25] = 13;
            shifted.rows[1][37] = 13;
            shifted.reports[1][0] = 13;
            shifted.reports[1][2] = 13;
            shifted.reports[1][13] = 13;
            refuses(|| {
                check(&o, &c, &p, &t, &shifted);
            });
        }
        refuses(|| {
            join(SEEDS[0], &o, &c, &p, &t, (78, &witness::encode(&w)));
        });
    }
}
#[test]
fn trace_join_rejects_shifted_and_duplicated_reference_boundaries() {
    let (o, c, mut p, mut t, w) = fixture(Scenario::StableA, 10);
    check(&o, &c, &p, &t, &w);
    let at = p.iter().position(|p| p.logical_pc == 0x3205).unwrap();
    p[at].logical_pc = 0x3204;
    refuses(|| {
        check(&o, &c, &p, &t, &w);
    });
    p[at].logical_pc = 0x3205;
    p[at - 1].logical_pc = 0x3200;
    refuses(|| {
        check(&o, &c, &p, &t, &w);
    });
    p[at - 1].logical_pc = 0x3204;
    p[at + 1].registers.rsp += 8;
    refuses(|| {
        check(&o, &c, &p, &t, &w);
    });
    p[at + 1].registers.rsp -= 8;
    t.child.visits -= 1;
    refuses(|| {
        check(&o, &c, &p, &t, &w);
    });
    t.child.visits += 1;
    t.parent_visits += 1;
    refuses(|| {
        check(&o, &c, &p, &t, &w);
    });
}
#[test]
fn trace_join_timestamp_consistency_preserves_observations() {
    let (o, c, p, t, mut w) = fixture(Scenario::StableA, 10);
    let expected = check(&o, &c, &p, &t, &w);
    w.rows[0][9] = 9;
    w.rows[0][28] = 9;
    w.rows[0][40] = 9;
    w.reports[0][5] = 9;
    w.reports[0][16] = 9;
    assert_eq!(check(&o, &c, &p, &t, &w), expected);
    w.rows[0][11] = 21;
    refuses(|| {
        check(&o, &c, &p, &t, &w);
    });
    w.rows[0][45] = 21;
    w.reports[0][21] = 21;
    assert_eq!(check(&o, &c, &p, &t, &w), expected);
    w.rows[0][10] = 4;
    w.rows[0][11] = 1;
    w.rows[0][44] = 2;
    w.rows[0][45] = 1;
    w.reports[0][20] = 2;
    w.reports[0][21] = 1;
    assert_eq!(check(&o, &c, &p, &t, &w), expected); // AUX mismatch precedes reversal.
    w.rows[0][10] = 3;
    w.rows[0][45] = 2;
    w.reports[0][21] = 2;
    assert_eq!(check(&o, &c, &p, &t, &w), expected);
    let (o, c, p, t, mut w) = fixture(Scenario::RemovedChild, 10);
    let expected = check(&o, &c, &p, &t, &w);
    w.rows[1][9..13].copy_from_slice(&[u64::MAX, 5, 0, 7]);
    assert_eq!(check(&o, &c, &p, &t, &w), expected);
}
