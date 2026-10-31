//! Pure fixtures exercise refusals; none grants execution or geometry authority.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn ready(candidate: bool, seed: u64, length: usize) -> (Ready, Profile) {
    // A non-page-aligned symbol verifies that the complete source page is joined.
    let case = Case::new(seed, length, 0x4020, 37);
    let plan = rust_invoke::admit(&[
        0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0,
        0x48, 0x89, 0x03, 0x5b, 0xc3,
    ])
    .unwrap();
    let mut caller = vec![0xcc; PAGE];
    caller[128..148].copy_from_slice(plan.bytes());
    let mut page = vec![0; PAGE];
    page[32..69].copy_from_slice(&BODY);
    let profile = Profile::new(
        case,
        plan.clone(),
        0x1080,
        (0x1000, caller.clone()),
        page.clone(),
    );
    let entry = 0x104020;
    let heads: Vec<_> = HEADS.map(|pc| entry + pc).to_vec();
    let boundaries = heads
        .iter()
        .enumerate()
        .map(|(i, &pc)| {
            (
                pc,
                if candidate {
                    0x200000 + i as u64 * 4
                } else {
                    pc
                },
            )
        })
        .collect();
    let original_sources = vec![(0x104000, page)];
    let mut immutable = original_sources.clone();
    if candidate {
        immutable[0].1[32..69].fill(0xcc);
        immutable.push((0x200000, vec![0x90; 128]));
    }
    (
        Ready {
            caller: 0x1080,
            caller_immutable: vec![(0x1000, caller)],
            functions: vec![module::Function {
                entry,
                heads,
                returns: vec![entry + 36],
                boundaries,
            }],
            immutable,
            original_sources,
            journal: candidate.then_some(JournalReady {
                address: 0x300000,
                a_generation: 1,
                b_generation: None,
                helper_tid: None,
            }),
            case,
            plan,
        },
        profile,
    )
}
#[test]
fn exact_accuracy_keys_cover_all_lengths_and_reject_noncanonical_or_foreign_cases() {
    let keys = keys();
    assert_eq!(keys.len(), 128);
    assert_eq!(keys.iter().collect::<BTreeSet<_>>().len(), 128);
    let mut comparisons = 0;
    for (seed, length) in keys {
        let c = Case::new(seed, length, 0x4020, 37);
        assert_eq!(
            Case::parse(&[&seed.to_string(), &length.to_string(), "16416", "37"]),
            c
        );
        assert_eq!((c.k(), c.function_id(), c.n()), (10, 41, 1));
        assert_eq!(c.itinerary().len(), 6 * length + 5);
        assert_eq!(
            c.itinerary().iter().copied().collect::<BTreeSet<_>>(),
            HEADS.into_iter().collect()
        );
        comparisons += c.counts().0 + 10;
        if !matches!(length, 1 | 64) {
            refuses(|| {
                ExactCase::new(seed, length);
            });
        }
    }
    assert_eq!(comparisons, 26_880);
    let seed = SEEDS[0].to_string();
    let args = [seed.as_str(), "1", "16416", "37"];
    for (field, value) in [
        (0, "0"),
        (0, "+1"),
        (1, "0"),
        (1, "65"),
        (1, "01"),
        (2, "0"),
        (2, "4090"),
        (2, "18446744073709551615"),
        (3, "36"),
        (3, "38"),
    ] {
        let mut bad = args;
        bad[field] = value;
        refuses(|| {
            Case::parse(&bad);
        });
    }
    refuses(|| {
        Case::parse(&args[..3]);
    });
}
#[test]
fn exact_accuracy_wire_binds_version_key_function_policy_and_complete_payload() {
    for candidate in [false, true] {
        let (r, p) = ready(candidate, SEEDS[0], 17);
        let wire = r.encode();
        Ready::decode(&wire, r.case, &r.plan).validate(candidate, &p);
        refuses(|| {
            NormalReady::decode(&wire);
        });
        refuses(|| {
            module::Ready::decode(&wire);
        });
        for field in 0..8 {
            let mut bad = wire.clone();
            bad[VERSION.len() + field * 8] ^= 1;
            refuses(|| {
                Ready::decode(&bad, r.case, &r.plan).validate(candidate, &p);
            });
        }
        for length in [0, VERSION.len(), wire.len() - 1] {
            refuses(|| {
                Ready::decode(&wire[..length], r.case, &r.plan);
            });
        }
        let mut bad = wire.clone();
        bad[0] ^= 1;
        refuses(|| {
            Ready::decode(&bad, r.case, &r.plan);
        });
        let mut bad = wire;
        bad.push(0);
        refuses(|| {
            Ready::decode(&bad, r.case, &r.plan);
        });
        let mut bad_case = r.case;
        bad_case.seed = SEEDS[1];
        refuses(|| {
            Ready::decode(&r.encode(), bad_case, &r.plan);
        });
        let tagged = WalkReady::ExactAccuracy(r);
        refuses(|| {
            tagged.selected_leaf_set();
        });
        refuses(|| {
            tagged.copied_rust();
        });
    }
}
#[test]
fn exact_accuracy_ready_refuses_incomplete_or_aliasing_source_and_boundary_owners() {
    for candidate in [false, true] {
        let (r, p) = ready(candidate, SEEDS[0], 1);
        r.validate(candidate, &p);
        for field in 0..14 {
            let mut bad = r.clone();
            match field {
                0 => bad.functions[0].entry += 1,
                1 => {
                    bad.functions[0].heads.pop();
                    bad.functions[0].boundaries.pop();
                }
                2 => bad.functions[0].heads.swap(0, 1),
                3 => bad.functions[0].returns[0] -= 1,
                4 => bad.functions[0].boundaries[1] = bad.functions[0].boundaries[0],
                5 => bad.original_sources[0].1[32] ^= 1,
                6 => bad.original_sources[0].1[4095] ^= 1,
                7 => bad.immutable[0].1[4095] ^= 1,
                8 => bad.caller_immutable[0].1[4095] ^= 1,
                9 => bad.caller += 1,
                10 => bad.original_sources.push(bad.original_sources[0].clone()),
                11 => bad.immutable[0].0 = bad.caller_immutable[0].0,
                12 => bad.functions[0].boundaries[0].1 = 0x700000,
                _ => bad.functions.push(bad.functions[0].clone()),
            }
            refuses(|| {
                bad.validate(candidate, &p);
            });
        }
    }
    let (r, p) = ready(true, SEEDS[1], 64);
    for head in 0..HEADS.len() {
        let mut bad = r.clone();
        let pc = bad.functions[0].heads[head];
        bad.functions[0].boundaries[head] = (pc, pc);
        refuses(|| {
            bad.validate(true, &p);
        });
    }
    for field in 0..6 {
        let mut bad = r.clone();
        match field {
            0 => bad.journal = None,
            1 => bad.journal.as_mut().unwrap().a_generation = 0,
            2 => bad.journal.as_mut().unwrap().b_generation = Some(2),
            3 => bad.journal.as_mut().unwrap().helper_tid = Some(7),
            4 => bad.journal.as_mut().unwrap().address = bad.immutable[0].0,
            _ => bad.immutable[1].1.resize(8193, 0),
        }
        refuses(|| {
            bad.validate(true, &p);
        });
    }
}
// Deliberately synthetic states test this adapter, not the independent instruction
// interpreter or the real full-state comparator. Real execution calls exact_body::check.
fn points(r: &Ready) -> Vec<Snapshot> {
    let pcs: Vec<_> = r.plan.heads()[..6]
        .iter()
        .map(|&x| r.caller + x)
        .chain(r.case.itinerary().iter().map(|&x| r.target().entry + x))
        .chain(r.plan.heads()[6..].iter().map(|&x| r.caller + x))
        .chain([0x123000])
        .collect();
    let mut data = vec![0; PAGE];
    data[INPUT..INPUT + 64].copy_from_slice(&r.case.input());
    let end = 6 + r.case.counts().0;
    pcs.into_iter()
        .enumerate()
        .map(|(i, pc)| {
            // SAFETY: this integer-only C register structure admits all-zero fields.
            let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            registers.rip = pc;
            registers.rsp = 0x8000 + u64::from(i >= end) * 8;
            registers.rdi = 0x400080;
            registers.rsi = r.case.bound() as u64;
            registers.rax = if i >= end - 1 { r.case.value() } else { 0 };
            Snapshot {
                logical_pc: pc,
                registers,
                xstate: vec![7; 64],
                data: data.clone(),
                application_stack: vec![0; 152],
            }
        })
        .collect()
}
fn trace(r: &Ready, p: &[Snapshot]) -> Trace {
    trace::check(r, p, 0x400000, 0x7f78, |body| {
        assert_eq!(
            (body.entry, body.continuation),
            (r.target().entry, r.caller + 15)
        );
        assert_eq!(
            (body.code, body.input),
            (&BODY[..], &r.case.input()[..r.case.bound()])
        );
        assert_eq!(body.input_address, 0x400080);
        assert_eq!(body.steps.len(), r.case.counts().0);
        for step in body.steps {
            assert_eq!((step.data_address, step.stack_address), (0x400000, 0x7f78));
            assert_eq!((step.data.len(), step.stack.len()), (PAGE, 152));
        }
        r.case.counts()
    })
}
#[test]
fn exact_accuracy_trace_covers_every_loop_visit_and_all_128_keys() {
    let mut comparisons = 0;
    for (seed, length) in keys() {
        let (r, p) = ready(false, seed, length);
        r.validate(false, &p);
        let points = points(&r);
        let t = trace(&r, &points);
        assert_eq!(t.visits, 6 * length + 5);
        assert_eq!(t.return_pc, r.target().entry + 36);
        comparisons += points.len();
    }
    assert_eq!(comparisons, 26_880);
}
#[test]
fn exact_accuracy_trace_refuses_wrong_itinerary_input_scalar_stack_xstate_and_counts() {
    let (r, _) = ready(false, SEEDS[0], 17);
    for field in 0..12 {
        let mut p = points(&r);
        let end = 6 + r.case.counts().0;
        match field {
            0 => {
                p.remove(7);
            }
            1 => p[7].logical_pc += 1,
            2 => p[end].logical_pc += 1,
            3 => p[6].registers.rdi += 1,
            4 => p[6].registers.rsi += 1,
            5 => p[6].data[INPUT] ^= 1,
            6 => p[end - 1].registers.rax ^= 1,
            7 => p[end].registers.rax ^= 1,
            8 => p[end].registers.rsp += 8,
            9 => p[7].data[PAGE - 1] ^= 1,
            10 => p[7].application_stack[0] ^= 1,
            _ => p[7].xstate[63] ^= 1,
        }
        refuses(|| {
            trace(&r, &p);
        });
    }
    refuses(|| {
        trace::check(&r, &points(&r), 0x400000, 0x7f78, |_| (0, 0, 0, 0));
    });
}
fn pair(r: &Ready) -> NormalPairResult<1> {
    let visits = r.case.counts().0;
    NormalPairResult {
        comparisons: visits + 10,
        original_steps: visits + 10,
        candidate_steps: visits + 10,
        visits: [visits],
        returns: [r.target().entry + 36],
        declared_returns: [r.target().entry + 36].into_iter().collect(),
        values: [r.case.value()],
        outer_value: r.case.value(),
        target_calls: 2,
        target_returns: 2,
        outer_returns: 2,
        normal_reaps: 2,
    }
}
#[test]
fn exact_accuracy_row_requires_exact_completion_reaps_counts_and_return_identity() {
    let (r, _) = ready(false, SEEDS[1], 64);
    let t = trace(&r, &points(&r));
    let row = pair_row(r.case, &r.plan, &pair(&r), &t);
    assert_eq!(HEADER.trim_end().split(',').count(), 32);
    assert_eq!(row.trim_end().split(',').count(), 32);
    assert!(row.len() <= 768);
    assert!(terminal(r.case, 399).contains("children=2:comparisons=399"));
    for field in 0..12 {
        let mut p = pair(&r);
        match field {
            0 => p.comparisons -= 1,
            1 => p.visits[0] -= 1,
            2 => p.values[0] ^= 1,
            3 => p.outer_value ^= 1,
            4 => p.target_calls = 1,
            5 => p.target_returns = 1,
            6 => p.outer_returns = 1,
            7 => p.normal_reaps = 1,
            8 => p.original_steps = MAX_STEPS + 1,
            9 => p.candidate_steps = p.comparisons - 1,
            10 => p.declared_returns.clear(),
            _ => {
                p.returns[0] -= 1;
                p.declared_returns = p.returns.into_iter().collect();
            }
        }
        refuses(|| {
            pair_row(r.case, &r.plan, &p, &t);
        });
    }
    refuses(|| {
        terminal(r.case, 398);
    });
}
