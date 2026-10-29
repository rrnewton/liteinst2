//! Inert byte/state/control metadata exercise actual validators; no native claim.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
#[test]
fn call_pair_postflight_fits_without_reader_and_closes_after_one_send() {
    let deadline = Deadline::start();
    let [read, write] = postflight_pipe();
    for fd in [&read, &write] {
        let descriptor_flags = unsafe { libc::fcntl(fd.0, libc::F_GETFD) };
        let status_flags = unsafe { libc::fcntl(fd.0, libc::F_GETFL) };
        assert!(descriptor_flags >= 0 && status_flags >= 0);
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
        assert_ne!(status_flags & libc::O_NONBLOCK, 0);
    }
    let bytes: Vec<_> = (0..POSTFLIGHT_LIMIT).map(|i| (i % 251) as u8).collect();
    PostflightOutput {
        fd: write,
        deadline,
    }
    .finish(&bytes);
    assert_eq!(read_closed(read.0, deadline, POSTFLIGHT_LIMIT), bytes);
}
#[test]
fn call_pair_postflight_rejects_empty_and_oversized_before_writing() {
    for length in [0, POSTFLIGHT_LIMIT + 1] {
        let deadline = Deadline::start();
        let [read, write] = postflight_pipe();
        refuses(|| {
            PostflightOutput {
                fd: write,
                deadline,
            }
            .finish(&vec![1; length])
        });
        assert!(read_closed(read.0, deadline, POSTFLIGHT_LIMIT).is_empty());
    }
}
#[test]
fn call_pair_postflight_drop_without_finish_emits_no_packet() {
    let deadline = Deadline::start();
    let [read, write] = postflight_pipe();
    drop(PostflightOutput {
        fd: write,
        deadline,
    });
    assert!(read_closed(read.0, deadline, POSTFLIGHT_LIMIT).is_empty());
}
fn caller_plan() -> Plan {
    rust_invoke::admit(&[
        0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0,
        0x48, 0x89, 0x03, 0x5b, 0xc3,
    ])
    .unwrap()
}
fn code() -> Vec<u8> {
    let mut b = vec![
        0x48, 0x83, 0xec, 24, 0x48, 0x89, 0x74, 0x24, 8, 0xe8, 0, 0, 0, 0, 0x48, 0x8b, 0x54, 0x24,
        8, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0x48, 0x83, 0xc4, 24, 0xc3,
    ];
    b[10..14].copy_from_slice(&(0x3200i32 - 0x310e).to_le_bytes());
    b
}
fn fixture(scenario: Scenario) -> (Profile, Ready) {
    let plan = caller_plan();
    let parent = code();
    let child = vec![0x90, 0x90, 0x90, 0x90, 0x90, 0xc3];
    let case = Case::new(
        10,
        0,
        scenario,
        [0x3100, 0x3200],
        [parent.len(), child.len()],
    );
    let mut page = vec![0x90; PAGE];
    page[0x100..0x100 + parent.len()].copy_from_slice(&parent);
    page[0x200..0x206].copy_from_slice(&child);
    let mut cp = vec![0x90; PAGE];
    cp[0x80..0x80 + plan.bytes().len()].copy_from_slice(plan.bytes());
    let pages = vec![(0x1000, cp)];
    let p = Profile::new(case, plan.clone(), 0x1080, pages.clone(), [parent, child]);
    let heads = p.parent.heads();
    let ready = Ready {
        caller: 0x1080,
        caller_immutable: pages,
        functions: [
            module::Function {
                entry: 0x3100,
                heads: heads.iter().map(|h| 0x3100 + h).collect(),
                returns: vec![0x311e],
                boundaries: heads.iter().map(|h| (0x3100 + h, 0x3100 + h)).collect(),
            },
            module::Function {
                entry: 0x3200,
                heads: (0..6).map(|i| 0x3200 + i).collect(),
                returns: vec![0x3205],
                boundaries: (0..6).map(|i| (0x3200 + i, 0x3200 + i)).collect(),
            },
        ],
        immutable: vec![(0x3000, page.clone())],
        original_sources: vec![(0x3000, page)],
        journal: None,
        case,
        plan,
        layout: [240, 416, 144, 400],
    };
    (p, ready)
}
fn candidate(mut r: Ready) -> Ready {
    let call = r.parent().entry + r.parent_plan().call;
    let mut next = 0x6000;
    for f in &mut r.functions {
        for (a, b) in &mut f.boundaries {
            if *a != call {
                *b = next;
                next += 16;
            }
        }
    }
    r.immutable.push((0x6000, vec![0x90; 512]));
    r.journal = Some(JournalReady {
        address: 0x8000,
        a_generation: 11,
        b_generation: (r.case.scenario == Scenario::RearmB).then_some(12),
        helper_tid: r.case.scenario.helper().then_some(99),
    });
    r
}
fn snapshot(pc: u64) -> Snapshot {
    Snapshot {
        logical_pc: pc,
        registers: unsafe { std::mem::zeroed() },
        xstate: vec![0; 24],
        data: vec![0; PAGE],
        application_stack: vec![0; 456],
    }
}
#[test]
fn call_pair_case_matrix_and_profile_refuse_old_discriminators() {
    let all = keys();
    assert_eq!(all.len(), 192);
    assert_eq!(all.iter().copied().collect::<BTreeSet<_>>().len(), 192);
    let (p, r) = fixture(Scenario::StableA);
    assert_ne!(
        CallerProfile::OriginalRust(&p.plan),
        CallerProfile::CopiedRust(&p.plan)
    );
    assert_ne!(CallerProfile::OriginalRust(&p.plan), CallerProfile::Module);
    for (k, i, a, b) in [
        (1, 0, 31, 6),
        (10, 16, 31, 6),
        (1000, 0, 81, 6),
        (10, 0, 31, 257),
    ] {
        refuses(|| {
            Case::new(k, i, r.case.scenario, r.case.selections, [a, b]);
        });
    }
    refuses(|| {
        Case::new(10, 0, r.case.scenario, [0x3100, 0x3110], [31, 6]);
    });
}
#[test]
fn call_pair_ready_joins_original_caller_pages_functions_and_layout() {
    let (p, r) = fixture(Scenario::RearmB);
    r.validate(false, &p);
    let c = candidate(r.clone());
    c.validate(true, &p);
    let round = Ready::decode(&c.encode(), &p);
    round.validate(true, &p);
    for n in 0..8 {
        let mut b = c.clone();
        match n {
            0 => b.caller += 1,
            1 => b.caller_immutable[0].1[0] ^= 1,
            2 => b.original_sources[0].1[0x100] ^= 1,
            3 => b.layout[1] -= 16,
            4 => b.functions[1].entry += 1,
            5 => b.functions[0].boundaries.pop().map(|_| ()).unwrap(),
            6 => b.immutable[1].0 = b.caller_immutable[0].0,
            _ => b.journal.as_mut().unwrap().b_generation = Some(11),
        }
        refuses(|| {
            b.validate(true, &p);
        });
    }
    let mut bad = r.encode();
    bad.extend([0]);
    refuses(|| {
        Ready::decode(&bad, &p);
    });
}
#[test]
fn call_pair_nested_order_requires_physical_child_landing_before_ack() {
    use phase::{Event::*, advance};
    let mut state = 0;
    for (e, land) in [
        (ParentCall, false),
        (ChildCall, false),
        (ChildReturn, true),
        (None, true),
        (ParentReturn, false),
    ] {
        state = advance(state, e, land);
    }
    assert_eq!(state, 5);
    for (s, e, land) in [
        (0, ChildCall, false),
        (2, None, true),
        (2, ChildReturn, false),
        (3, ParentReturn, false),
        (4, None, true),
        (5, ParentCall, false),
    ] {
        refuses(|| {
            advance(s, e, land);
        });
    }
}
#[test]
fn call_pair_e8_target_stack_words_and_roles_are_exact() {
    let (_, r) = fixture(Scenario::StableA);
    let p = r.parent_plan();
    assert_eq!((p.call, p.continuation, p.delta), (9, 14, 32));
    let mut wrong = code();
    wrong[10] ^= 1;
    refuses(|| {
        parent::Parent::decode(&wrong, 0x3100, 0x3200);
    });
    let rsp = 0x9008;
    let crsp = rsp - r.plan.subject_rsp_delta() - p.delta;
    phase::landing(
        &r,
        p.delta,
        phase::Event::ChildCall,
        [0x3200, crsp, 0, 0x310e],
        rsp,
    );
    phase::landing(
        &r,
        p.delta,
        phase::Event::ChildReturn,
        [0x310e, crsp + 8, 1, 0x310e],
        rsp,
    );
    for (x, y, z, w) in [
        (0x310f, crsp + 8, 1, 0x310e),
        (0x310e, crsp + 16, 1, 0x310e),
        (0x310e, crsp + 8, 2, 0x310e),
        (0x310e, crsp + 8, 1, 0x310f),
    ] {
        refuses(|| phase::landing(&r, p.delta, phase::Event::ChildReturn, [x, y, z, w], rsp));
    }
}
#[test]
fn call_pair_control_ack_preserves_own_generations_and_removed_child() {
    for scenario in [Scenario::RearmB, Scenario::RemovedChild] {
        let (_, r) = fixture(scenario);
        let r = candidate(r);
        for stage in 1..=2 {
            let rearm = scenario == Scenario::RearmB;
            let words = [
                ACK_MAGIC,
                stage as u64,
                7,
                99,
                11,
                if rearm { 12 } else { 0 },
                0,
                u64::from(rearm && stage == 2),
                if rearm && stage == 2 { 3 } else { 2 },
                if rearm && stage == 1 { 12 } else { 0 },
            ];
            check_ack(&words, stage, 7, &r);
            for n in 0..words.len() {
                let mut bad = words;
                bad[n] ^= 1;
                refuses(|| check_ack(&bad, stage, 7, &r));
            }
        }
    }
}
#[test]
fn call_pair_complete_stack_capture_bounds_and_deep_tail_refuse() {
    let (_, r) = fixture(Scenario::StableA);
    let p = Profile::new(
        r.case,
        r.plan.clone(),
        r.caller,
        r.caller_immutable.clone(),
        [code(), vec![0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]],
    );
    assert_eq!(p.stack_below(), r.plan.subject_rsp_delta() + 160);
    copied_capture::nested_bounds(&[(0x1000, 456)]);
    refuses(|| copied_capture::nested_bounds(&[(u64::MAX - 8, 456)]));
    refuses(|| copied_capture::nested_bounds(&[(0x1000, 100), (0x1020, 456)]));
    refuses(|| copied_capture::nested_bounds(&[(0x1000, 102857)]));
    let a = snapshot(0x3100);
    let mut b = snapshot(0x3100);
    assert_state(&a, &b);
    b.application_stack[0] ^= 1;
    refuses(|| assert_state(&a, &b));
}
#[test]
fn call_pair_parent_effects_preserve_defined_flags_and_scalar() {
    let p = parent::Parent::decode(&code(), 0x3100, 0x3200);
    for (s, value) in [(19, 7u64), (23, 3u64)] {
        let mut before = snapshot(0x3100 + s);
        before.registers.rdx = 7;
        before.registers.rax = 3;
        before.registers.eflags = 0x202;
        let mut after = copied_rust::effects::copy(&before);
        after.logical_pc = 0x3100 + if s == 19 { 23 } else { 26 };
        if s == 19 {
            after.registers.rdx = value << 32;
        } else {
            after.registers.rax = 7 | value;
        }
        let result = if s == 19 { value << 32 } else { 7 | value };
        after.registers.eflags = (0x202
            & !((1 << 11) | (1 << 7) | (1 << 6) | (1 << 4) | (1 << 2) | 1))
            | if result == 0 { 1 << 6 } else { 0 }
            | if (result as u8).count_ones() % 2 == 0 {
                1 << 2
            } else {
                0
            };
        parent::effect(&p, 0x3100, 0x3200, &before, &after, 0x8e40);
        after.registers.r12 = 1;
        refuses(|| parent::effect(&p, 0x3100, 0x3200, &before, &after, 0x8e40));
    }
}
#[test]
fn call_pair_pair_population_and_full_cfg_coverage_refuse() {
    let mut p = Population::default();
    refuses(|| {
        Population::default().finish();
    });
    let (c, r) = fixture(Scenario::StableA);
    let graph = csv::graph(&[0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]);
    let t = Trace {
        parent_entry: 0x3100,
        child_entry: 0x3200,
        parent_visits: 8,
        parent_ret_offset: 30,
        parent_heads: c.parent.heads().into_iter().collect(),
        parent_edges: c.parent.edges(),
        child: csv::BodyTrace {
            entry: 0x3200,
            code: vec![0x90, 0x90, 0x90, 0x90, 0x90, 0xc3],
            visits: 6,
            ret_offset: 5,
            heads: graph.heads.clone(),
            edges: graph.edges.clone(),
            declared: graph,
        },
        child_delta: 32,
        stack_bytes: c.stack_below() + 8,
        parent_generation: 11,
        child_generation: 11,
    };
    let pair = NormalPairResult {
        comparisons: r.plan.heads().len() + 15,
        original_steps: 100,
        candidate_steps: 200,
        visits: [8, 6],
        returns: [0x3205, 0x311e],
        declared_returns: BTreeSet::from([0x3205, 0x311e]),
        values: [r.case.value(), r.case.fields()],
        outer_value: r.case.value(),
        target_calls: 4,
        target_returns: 4,
        outer_returns: 2,
        normal_reaps: 2,
    };
    trace::validate_pair(r.case, &r.plan, &pair, &t);
    p.record(SEEDS[0], r.case, &r.plan, &pair, &t);
    refuses(|| p.record(SEEDS[0], r.case, &r.plan, &pair, &t));
    let mut full = Population::default();
    for (k, seed, index, scenario) in keys() {
        let case = Case::new(k, index, scenario, r.case.selections, r.case.extents);
        let mut trace = t.clone();
        trace.child_generation = match scenario {
            Scenario::StableA => 11,
            Scenario::RearmB => 12,
            Scenario::RemovedChild => 0,
        };
        let item = NormalPairResult {
            comparisons: pair.comparisons,
            original_steps: 100,
            candidate_steps: 200,
            visits: pair.visits,
            returns: pair.returns,
            declared_returns: pair.declared_returns.clone(),
            values: [case.value(), case.fields()],
            outer_value: case.value(),
            target_calls: 4,
            target_returns: 4,
            outer_returns: 2,
            normal_reaps: 2,
        };
        full.record(seed, case, &r.plan, &item, &trace);
    }
    assert_eq!(full.finish().len(), 12);
    let mut bad = pair;
    bad.normal_reaps = 1;
    refuses(|| trace::validate_pair(r.case, &r.plan, &bad, &t));
}
#[test]
fn call_pair_all_journal_words_and_phase_counts_refuse() {
    for scenario in [Scenario::StableA, Scenario::RearmB, Scenario::RemovedChild] {
        let (_, r) = fixture(scenario);
        let r = candidate(r);
        for (used, depth) in [(1, 1), (2, 2), (3, 2), (3, 1), (4, 1), (4, 0)] {
            let words = journal(&r, 7, 0x9008, Some(0x3205), Some(0x311e), used, depth);
            let raw: Vec<_> = words.into_iter().flat_map(u64::to_le_bytes).collect();
            check_journal(&raw, &words);
            for n in 0..512 {
                let mut bad = raw.clone();
                bad[n * 8] ^= 1;
                refuses(|| check_journal(&bad, &words));
            }
        }
        refuses(|| {
            journal(&r, 7, 0x9008, Some(0x3205), Some(0x311e), 3, 0);
        });
    }
    // Additional inert diagnostics controls; every original journal assertion above remains.
    {
        use phase::{StepAttribution, StepPoint};
        let (mut profile, _) = fixture(Scenario::RearmB);
        profile.set_diagnostic_origin((0x80, 0x1000));
        assert_eq!(profile.diagnostic_origin, Some((0x80, 0x1000)));
        let (mut wrong, _) = fixture(Scenario::StableA);
        refuses(|| wrong.set_diagnostic_origin((0x80, 0x1001)));
        assert_eq!(wrong.diagnostic_origin, None);
        refuses(|| wrong.set_diagnostic_origin((0x1081, 0)));
        assert_eq!(wrong.diagnostic_origin, None);

        let mut counts = StepAttribution::new(true);
        let original = StepAttribution::new(false);
        for bucket in 0..8 {
            counts.completed(bucket);
        }
        for _ in 8..MAX_STEPS {
            counts.completed(4); // Existing stage 3: physical child RET to acknowledged continuation.
        }
        assert_eq!(counts.counts, [1, 1, 1, 1, MAX_STEPS - 7, 1, 1, 1]);
        assert_eq!(counts.counts.iter().sum::<usize>(), MAX_STEPS);
        assert_eq!(original.counts, [0; 8]);
        let point = |steps| StepPoint {
            bucket: 4,
            steps,
            rip: 0x1234,
            pid: 7,
        };
        let mut output = b"preserved\n".to_vec();
        counts
            .write_exhaustion(&mut output, &profile, SEEDS[0], point(MAX_STEPS - 1))
            .unwrap();
        assert_eq!(output, b"preserved\n");
        counts
            .write_exhaustion(&mut output, &profile, SEEDS[0], point(MAX_STEPS))
            .unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        assert!(text.starts_with("preserved\ncall-pair step attribution: candidate=1 k=10 "));
        assert!(text.contains("steps=20000 bucket=4 rip=0x1234 caller=0x1080 origin_joined=1 caller_elf_va=0x80 executable_load_bias=0x1000"));
        assert!(text.ends_with("completed=[1, 1, 1, 1, 19993, 1, 1, 1]\n"));
        assert_eq!(text.bytes().filter(|&b| b == b'\n').count(), 2);
        assert!(output.len() < 1024);
        assert_eq!(counts.counts.iter().sum::<usize>(), MAX_STEPS);
        struct FailedWrite;
        impl std::io::Write for FailedWrite {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("fabricated closed diagnostic sink"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(
            counts
                .write_exhaustion(&mut FailedWrite, &profile, SEEDS[0], point(MAX_STEPS))
                .is_err()
        );
        assert_eq!(counts.counts.iter().sum::<usize>(), MAX_STEPS);
    }
}
