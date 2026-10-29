//! Fabricated data for actual new validators; no native calls or reaps supplied.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn rejects(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn ready(code: &[u8], candidate: bool) -> NormalReady {
    let g = graph(code);
    let mut caller = vec![0; PAGE];
    caller[..BYTES.len()].copy_from_slice(BYTES);
    let mut source = vec![0; PAGE];
    source[..code.len()].copy_from_slice(code);
    let heads: Vec<_> = g.heads.iter().map(|p| 0x3000 + p).collect();
    NormalReady {
        caller: 0x1000,
        caller_immutable: vec![(0x1000, caller)],
        entry: 0x3000,
        returns: g.returns.iter().map(|p| 0x3000 + p).collect(),
        boundaries: heads.iter().map(|p| (*p, *p)).collect(),
        heads,
        immutable: vec![(0x3000, source.clone())],
        original_source: source,
        journal: candidate.then_some(JournalReady {
            address: 0x7000,
            a_generation: 11,
            b_generation: None,
            helper_tid: None,
        }),
    }
}
fn code() -> Vec<u8> {
    vec![0xb8, 1, 0, 0, 0, 0xc3]
}
fn steps(value: u64) -> Vec<OriginalStep<'static>> {
    let mut a: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    a.rip = 0x3000;
    a.rsp = 0x9000;
    a.rdi = 0x20080;
    let mut b = a;
    b.rip = 0x3005;
    b.rax = value;
    let mut c = b;
    c.rip = 0x101e;
    c.rsp += 8;
    vec![
        OriginalStep {
            before: a,
            after: b,
            data_address: 0x20000,
            data: &[],
            stack_address: 0x8f80,
            stack: &[],
        },
        OriginalStep {
            before: b,
            after: c,
            data_address: 0x20000,
            data: &[],
            stack_address: 0x8f80,
            stack: &[],
        },
    ]
}
fn inspect_fixture(case: Case, r: &NormalReady, s: &[OriginalStep<'_>], input: &[u8]) -> BodyTrace {
    inspect(
        case,
        r,
        OriginalBody {
            entry: 0x3000,
            continuation: 0x101e,
            code: &r.original_source[..6],
            input_address: 0x20080,
            input,
            steps: s,
        },
    )
}
fn fixture(case: Case) -> (NormalPairResult, Trace) {
    let r = ready(&code(), false);
    let input = case.input();
    let s = steps(case.expected());
    let a = inspect_fixture(case, &r, &s, &input[..case.length()]);
    let comparisons = 24 + 2 * a.visits;
    (
        NormalPairResult {
            comparisons,
            original_steps: comparisons,
            candidate_steps: comparisons,
            visits: [a.visits; 2],
            returns: [0x3005; 2],
            declared_returns: BTreeSet::from([0x3005]),
            values: [case.expected(); 2],
            outer_value: case.expected() * 2,
            target_calls: 4,
            target_returns: 4,
            outer_returns: 2,
            normal_reaps: 2,
        },
        Trace {
            bodies: [a.clone(), a],
        },
    )
}
#[test]
fn csv_cases_arguments_and_profile_keep_all_sixteen_and_legacy_limits() {
    let counts = [1, 1, 3, 2, 3, 2, 2, 1, 1, 2, 3, 2, 1, 2, 4, 3];
    assert_eq!(counts.iter().sum::<u64>(), 33);
    for (i, &count) in counts.iter().enumerate() {
        let c = Case::new(i);
        assert_eq!((c.id(), c.expected()), (i + 1, count));
        assert_eq!(&c.input()[..c.length()], RECORDS[i].0);
        assert!(c.input()[c.length()..].iter().all(|&b| b == 0xa7));
        for seed in SEEDS {
            profile(seed, c, 5);
            profile(seed, c, 256);
        }
    }
    assert_eq!(Case::new(0).length(), 0);
    assert_eq!(
        Arguments::parse("4096", "256"),
        Arguments {
            elf_va: 4096,
            length: 256
        }
    );
    for bad in [
        "",
        "00",
        "01",
        "+1",
        "-1",
        " 1",
        "1\n",
        "18446744073709551616",
    ] {
        rejects(|| {
            Arguments::parse(bad, "6");
        });
    }
    for n in ["0", "257"] {
        rejects(|| {
            Arguments::parse("4096", n);
        });
    }
    rejects(|| {
        Arguments::parse("18446744073709551615", "6");
    });
    rejects(|| {
        Case::new(16);
    });
    rejects(|| profile(0, Case::new(0), 6));
    for n in [0, 4, 257] {
        rejects(|| profile(SEEDS[0], Case::new(0), n));
    }
    rejects(|| mode_case(SEEDS[0], CASES[0], 81, Mode::Stable));
}
#[test]
fn csv_ready_keeps_complete_heads_returns_maps_and_distinct_extent_authority() {
    let mut long = vec![0x90; 89];
    long.push(0xc3);
    for candidate in [false, true] {
        let r = ready(&long, candidate);
        assert_eq!(validate_ready(&r, candidate, 90).len(), 90);
        rejects(|| {
            r.validate(candidate, 90, Mode::Stable);
        });
        for field in 0..7 {
            let mut bad = r.clone();
            match field {
                0 => {
                    bad.heads.remove(1);
                }
                1 => {
                    bad.heads[1] = bad.heads[0];
                }
                2 => bad.returns[0] -= 1,
                3 => {
                    let _ = bad.boundaries.pop();
                }
                4 => bad.boundaries[1].1 = bad.boundaries[0].1,
                5 => bad.boundaries[1].0 = bad.boundaries[0].0,
                _ => bad.caller_immutable[0].1[0] ^= 1,
            }
            rejects(|| {
                validate_ready(&bad, candidate, 90);
            });
        }
    }
    let mut r = ready(&[0x85, 0xc0, 0x74, 1, 0xc3, 0xc3], false);
    assert_eq!(validate_ready(&r, false, 6).len(), 4);
    let _ = r.returns.pop();
    rejects(|| {
        validate_ready(&r, false, 6);
    }); // A declared C3 cannot disappear.
}
#[test]
fn csv_body_inspection_refuses_wrong_input_path_value_and_return() {
    let c = Case::new(2);
    let r = ready(&code(), false);
    let input = c.input();
    let s = steps(c.expected());
    assert_eq!(inspect_fixture(c, &r, &s, &input[..c.length()]).visits, 2);
    let mut wrong = input;
    wrong[0] ^= 1;
    rejects(|| {
        inspect_fixture(c, &r, &s, &wrong[..c.length()]);
    });
    for field in 0..6 {
        let mut bad = steps(c.expected());
        match field {
            0 => bad[0].before.rip += 1,
            1 => bad[0].after.rip += 1,
            2 => bad[1].before.rip += 1,
            3 => bad[1].after.rip += 1,
            4 => bad[1].before.rax += 1,
            _ => bad[1].after.rax += 1,
        }
        rejects(|| {
            inspect_fixture(c, &r, &bad, &input[..c.length()]);
        });
    }
    rejects(|| {
        inspect_fixture(c, &r, &s[..1], &input[..c.length()]);
    });
    rejects(|| {
        graph(&[0xe8, 0, 0, 0, 0, 0xc3]);
    });
    rejects(|| {
        graph(&[0x90, 0x90, 0x90, 0x90, 0xeb, 0xfa]);
    }); // Edge to entry.
}
#[test]
fn csv_pair_requires_both_calls_returns_reaps_and_complete_comparison_counts() {
    for i in 0..16 {
        let c = Case::new(i);
        let (p, t) = fixture(c);
        validate_pair(c, &p, &t);
        for field in 0..13 {
            let (mut bad, t) = fixture(c);
            match field {
                0 => bad.comparisons -= 1,
                1 => bad.original_steps = bad.comparisons - 1,
                2 => bad.candidate_steps = MAX_STEPS + 1,
                3 => bad.visits[1] += 1,
                4 => bad.values[0] += 1,
                5 => bad.outer_value += 1,
                6 => bad.returns[1] += 1,
                7 => {
                    bad.declared_returns.insert(0x3004);
                }
                8 => bad.target_calls -= 1,
                9 => bad.target_returns -= 1,
                10 => bad.outer_returns -= 1,
                11 => bad.normal_reaps -= 1,
                _ => bad.original_steps = MAX_STEPS + 1,
            }
            rejects(|| validate_pair(c, &bad, &t));
        }
    }
}
#[test]
fn csv_population_requires_every_ordered_pair_and_each_seeds_return_union() {
    let mut population = Population::default();
    for seed in SEEDS {
        for i in 0..16 {
            let c = Case::new(i);
            let (p, t) = fixture(c);
            assert_eq!(population.record(seed, c, &p, &t).is_some(), i == 15);
        }
    }
    assert_eq!(population.finish(), 32 * 28);
    rejects(|| {
        Population::default().finish();
    });
    for (seed, c) in [(SEEDS[1], Case::new(0)), (SEEDS[0], Case::new(1))] {
        let (p, t) = fixture(c);
        rejects(|| {
            let _ = Population::default().record(seed, c, &p, &t);
        });
    }
    // A coherent two-RET source/summary with every case taking the first RET.
    // Complete pair accounting cannot substitute for the per-seed union gate.
    let two_returns = |c| {
        let (mut p, mut t) = fixture(c);
        let bytes = vec![0x85, 0xc0, 0x74, 1, 0xc3, 0xc3];
        for b in &mut t.bodies {
            b.code = bytes.clone();
            b.declared = graph(&bytes);
            b.visits = 3;
            b.ret_offset = 4;
            b.heads = BTreeSet::from([0, 2, 4]);
            b.edges = BTreeSet::from([(0, 2), (2, 4)]);
        }
        p.visits = [3; 2];
        p.comparisons = 30;
        p.original_steps = 30;
        p.candidate_steps = 30;
        p.returns = [0x3004; 2];
        p.declared_returns = BTreeSet::from([0x3004, 0x3005]);
        (p, t)
    };
    let mut missing = Population::default();
    for i in 0..15 {
        let c = Case::new(i);
        let (p, t) = two_returns(c);
        let _ = missing.record(SEEDS[0], c, &p, &t);
    }
    let c = Case::new(15);
    let (p, t) = two_returns(c);
    rejects(|| {
        let _ = missing.record(SEEDS[0], c, &p, &t);
    });
}
#[test]
fn csv_trace_summary_keeps_source_and_observed_coverage_separate() {
    let c = Case::new(0);
    // A real decoded alignment NOP lies behind an unconditional jump. Its head
    // and edge are declared, but this original trace never executes them.
    let r = ready(&[0xb8, 1, 0, 0, 0, 0xeb, 1, 0x90, 0xc3], false);
    let mut s = steps(c.expected());
    let before = s[1].before;
    let mut ret = before;
    ret.rip = 0x3008;
    let after = s[1].after;
    s[1].after = ret;
    s.push(OriginalStep {
        before: ret,
        after,
        data_address: 0x20000,
        data: &[],
        stack_address: 0x8f80,
        stack: &[],
    });
    let a = inspect(
        c,
        &r,
        OriginalBody {
            entry: r.entry,
            continuation: 0x101e,
            code: &r.original_source[..9],
            input_address: 0x20080,
            input: &[],
            steps: &s,
        },
    );
    let (mut p, _) = fixture(c);
    p.comparisons = 30;
    p.original_steps = 30;
    p.candidate_steps = 30;
    p.visits = [3; 2];
    p.returns = [0x3008; 2];
    p.declared_returns = BTreeSet::from([0x3008]);
    let t = Trace {
        bodies: [a.clone(), a],
    };
    validate_pair(c, &p, &t);
    assert_ne!(t.bodies[0].heads, t.bodies[0].declared.heads);
    for field in 0..4 {
        let mut bad = t.clone();
        match field {
            0 => {
                bad.bodies[1].code[0] ^= 1;
            }
            1 => {
                bad.bodies[1].heads.insert(4);
            }
            2 => {
                bad.bodies[1].edges.insert((0, 4));
            }
            _ => bad.bodies[1].ret_offset = 4,
        }
        rejects(|| validate_pair(c, &p, &bad));
    }
}
