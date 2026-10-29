//! Inert byte/metadata controls for actual helpers; no loaded/native authority.
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
fn selections() -> [Selection; 4] {
    [0x4000, 0x4040, 0x9000, 0x9040].map(|elf_va| Selection { elf_va, extent: 6 })
}
fn fixture(subset: u8, operation: usize) -> Ready {
    let case = Case::new(subset, 10, operation, 0, selections());
    let mut caller = vec![0xcc; PAGE];
    caller[128..128 + BYTES.len()].copy_from_slice(BYTES);
    let table = case.table();
    let pages: BTreeSet<_> = table
        .iter()
        .map(|(_, s)| (s.elf_va + 0x100000) & !4095)
        .collect();
    let original_sources: Vec<_> = pages
        .into_iter()
        .map(|a| {
            let mut bytes = vec![0x90; PAGE];
            for (_, s) in &table {
                let entry = s.elf_va + 0x100000;
                if a <= entry && entry < a + 4096 {
                    bytes[(entry - a) as usize + 5] = 0xc3;
                }
            }
            (a, bytes)
        })
        .collect();
    let functions = table
        .iter()
        .map(|(_, s)| {
            let entry = s.elf_va + 0x100000;
            module::Function {
                entry,
                heads: (0..6).map(|n| entry + n).collect(),
                returns: vec![entry + 5],
                boundaries: (0..6).map(|n| (entry + n, entry + n)).collect(),
            }
        })
        .collect();
    Ready {
        caller: 0x1080,
        caller_immutable: vec![(0x1000, caller)],
        functions,
        immutable: original_sources.clone(),
        original_sources,
        journal: None,
        case,
        plan: plan(),
    }
}
fn profile(r: &Ready) -> Profile {
    Profile::new(
        r.case,
        r.plan.clone(),
        r.caller,
        r.caller_immutable[0].clone(),
    )
}
#[test]
fn leaf_set_profile_refuses_invalid_tables_and_preserves_old_discriminators() {
    for subset in 1..=15 {
        for (operation, &function_id) in FUNCTION_IDS.iter().enumerate() {
            if subset & (1 << operation) != 0 {
                let c = Case::new(subset, 1000, operation, 0, selections());
                assert_eq!(c.n(), subset.count_ones() as usize);
                assert_eq!(c.table()[c.selected()].0, operation);
                assert_eq!(c.function_id(), function_id);
            }
        }
    }
    for (subset, k, op, index) in [
        (0, 10, 0, 0),
        (16, 10, 0, 0),
        (1, 16, 0, 0),
        (1, 10, 1, 0),
        (1, 10, 0, 16),
        (2, 10, 1, 8),
    ] {
        refuses(|| {
            Case::new(subset, k, op, index, selections());
        });
    }
    for which in 0..6 {
        let mut s = selections();
        match which {
            0 => s[0].elf_va = 0,
            1 => s[1].elf_va = s[0].elf_va,
            2 => s[1].elf_va = s[0].elf_va + 5,
            3 => s[1].extent = 81,
            4 => s[0].extent = 257,
            _ => s[3].elf_va = 0xf000,
        };
        refuses(|| {
            Case::new(15, 10, 0, 0, s);
        });
    }
    for (va, extent, op) in [
        ("01", "6", 0),
        ("1", "06", 0),
        ("+1", "6", 0),
        ("18446744073709551615", "6", 0),
        ("1", "6", 4),
    ] {
        refuses(|| {
            Selection::parse(va, extent, op);
        });
    }
    let r = fixture(15, 0);
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
    let tagged = WalkReady::LeafSetCopied(r.clone());
    refuses(|| {
        tagged.single();
    });
    refuses(|| {
        tagged.module();
    });
    refuses(|| {
        tagged.copied_rust();
    });
    let old = copied_rust::Case::new(0, 0, 6, 6, 0);
    refuses(|| {
        copied_rust::Ready::decode(&w, old, &r.plan);
    });
}
#[test]
fn leaf_set_geometry_retains_noncontiguous_pages_and_complete_union() {
    let r = fixture(15, 0);
    let p = profile(&r);
    assert_eq!(
        r.original_sources
            .iter()
            .map(|(a, _)| *a)
            .collect::<Vec<_>>(),
        [0x104000, 0x109000]
    );
    assert_eq!(r.validate(false, &p).len(), 24);
    let mut candidate = r.clone();
    candidate.immutable.push((0x200000, vec![0x90; 96]));
    for (i, f) in candidate.functions.iter_mut().enumerate() {
        for (n, (_, physical)) in f.boundaries.iter_mut().enumerate() {
            *physical = 0x200000 + (i * 16 + n) as u64;
        }
    }
    candidate.journal = Some(JournalReady {
        address: 0x300000,
        a_generation: 17,
        b_generation: None,
        helper_tid: None,
    });
    candidate.same_source(&r);
    assert_eq!(candidate.validate(true, &p).len(), 24);
    for field in 0..5 {
        let mut bad = candidate.clone();
        match field {
            0 => bad.journal = None,
            1 => bad.journal.as_mut().unwrap().address = 0x200000,
            2 => bad.journal.as_mut().unwrap().a_generation = 0,
            3 => bad.functions[0].boundaries[0].1 = 0x201000,
            _ => bad.immutable[2].1.resize(8193, 0),
        }
        refuses(|| {
            bad.validate(true, &p);
        });
    }
    assert_eq!(
        source_bytes(&r.original_sources, 0x109040, 6),
        [0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]
    );
    refuses(|| {
        source_bytes(&r.original_sources, 0x105000, 1);
    });
    for which in 0..9 {
        let mut bad = r.clone();
        match which {
            0 => bad.original_sources[1].0 = 0x105000,
            1 => {
                bad.original_sources.pop();
            }
            2 => bad.original_sources[0].1.pop().map(|_| ()).unwrap(),
            3 => bad.functions[3].boundaries[0].1 = bad.functions[0].entry,
            4 => bad.functions[3].heads.pop().map(|_| ()).unwrap(),
            5 => bad.functions[2].returns[0] -= 1,
            6 => bad.immutable[1].1[100] ^= 1,
            7 => bad.functions[1].entry += 1,
            _ => bad.immutable.push((0x200000, vec![0; 8193])),
        }
        refuses(|| {
            bad.validate(false, &p);
        });
    }
    // Crossing an adjacent page is copied literally; a missing page cannot be zero-filled.
    let pages = vec![(0x3000, vec![1; 4096]), (0x4000, vec![2; 4096])];
    assert_eq!(source_bytes(&pages, 0x3ffe, 4), [1, 1, 2, 2]);
    let duplicate = vec![pages[0].clone(), pages[0].clone()];
    refuses(|| {
        source_bytes(&duplicate, 0x3000, 1);
    });
}
#[test]
fn leaf_set_ready_joins_parent_plan_caller_table_and_selection() {
    for subset in 1..=15 {
        let operation = (0..4).find(|i| subset & (1 << i) != 0).unwrap();
        let r = fixture(subset, operation);
        let p = profile(&r);
        let w = r.encode();
        let decoded = Ready::decode(&w, r.case, &r.plan);
        decoded.same_source(&r);
        assert_eq!(decoded.validate(false, &p).len(), 6 * r.case.n());
        refuses(|| {
            Ready::decode(&w[..w.len() - 1], r.case, &r.plan);
        });
        let mut extra = w.clone();
        extra.push(0);
        refuses(|| {
            Ready::decode(&extra, r.case, &r.plan);
        });
        let other = Case::new(subset, 1000, operation, 0, selections());
        refuses(|| {
            Ready::decode(&w, other, &r.plan);
        });
        let mut bad = r.clone();
        bad.caller_immutable[0].1[127] ^= 1;
        refuses(|| {
            bad.validate(false, &p);
        });
        let mut bad = r.clone();
        bad.caller += 1;
        refuses(|| {
            bad.validate(false, &p);
        });
        let mut bad = r.clone();
        bad.case.selections[0].elf_va += 1;
        refuses(|| {
            bad.validate(false, &p);
        });
        let mut bad = r.clone();
        bad.plan = rust_invoke::admit(&[
            0x55, 0x48, 0x89, 0xcd, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff,
            0xd0, 0x48, 0x89, 0x45, 0, 0x5d, 0xc3,
        ])
        .unwrap();
        refuses(|| {
            bad.validate(false, &p);
        });
    }
}
fn metadata(case: Case) -> (NormalPairResult<1>, Trace) {
    assert!(case.operation < 2);
    let entry = case.selections[case.operation].elf_va + 0x100000;
    let declared = BodyCoverage {
        heads: BTreeSet::from([0, 1]),
        edges: BTreeSet::from([(0, 1)]),
        returns: BTreeSet::from([1]),
    };
    let t = if case.operation == 0 {
        Trace::Csv(csv::BodyTrace {
            entry,
            visits: 2,
            ret_offset: 1,
            heads: declared.heads.clone(),
            edges: declared.edges.clone(),
            code: vec![0x90, 0xc3],
            declared: csv::Graph {
                heads: declared.heads,
                edges: declared.edges,
                returns: declared.returns,
            },
        })
    } else {
        Trace::Length(BodyTrace {
            entry,
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
            returns: [entry + 1],
            declared_returns: BTreeSet::from([entry + 1]),
            values: [case.value()],
            outer_value: 0xdead,
            target_calls: 2,
            target_returns: 2,
            outer_returns: 2,
            normal_reaps: 2,
        },
        t,
    )
}
#[test]
fn leaf_set_pair_requires_target_and_real_copied_outer_returns() {
    for operation in 0..2 {
        let c = Case::new(3, 10, operation, 0, selections());
        let (pair, t) = metadata(c);
        trace::validate_pair(c, &plan(), &pair, &t);
        for field in 0..11 {
            let (mut bad, t) = metadata(c);
            match field {
                0 => bad.target_calls = 1,
                1 => bad.target_returns = 1,
                2 => bad.outer_returns = 1,
                3 => bad.normal_reaps = 1,
                4 => bad.values[0] ^= 1,
                5 => bad.visits[0] += 1,
                6 => bad.comparisons -= 1,
                7 => bad.original_steps = MAX_STEPS + 1,
                8 => bad.candidate_steps = MAX_STEPS + 1,
                9 => bad.returns[0] += 1,
                _ => {
                    bad.declared_returns.insert(0xdead);
                }
            }
            refuses(|| trace::validate_pair(c, &plan(), &bad, &t));
        }
    }
    let ready = fixture(15, 2);
    let rsp = 0x9008;
    let word = ready.caller + ready.plan.continuations()[0];
    let mut call: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    call.rax = ready.target().entry;
    call.rdi = 0x5000 + INPUT as u64;
    call.rsi = ready.case.bound() as u64;
    call.rsp = rsp - 8;
    copied_rust::call_before_view(&call, ready.view(), 0, rsp, 0x5000, ready.case.bound());
    for field in 0..4 {
        let mut bad = call;
        match field {
            0 => bad.rax += 1,
            1 => bad.rdi += 1,
            2 => bad.rsi += 1,
            _ => bad.rsp += 8,
        };
        refuses(|| {
            copied_rust::call_before_view(&bad, ready.view(), 0, rsp, 0x5000, ready.case.bound())
        });
    }
    call.rip = ready.target().entry;
    call.rsp = rsp - ready.plan.subject_rsp_delta();
    copied_rust::call_after_view(&call, ready.view(), 0, rsp, word);
    refuses(|| copied_rust::call_after_view(&call, ready.view(), 0, rsp, word + 1));
    call.rip = ready.target().returns[0];
    call.rax = ready.case.value();
    copied_rust::ret_before_view(&call, ready.view(), 0, rsp, ready.case.value(), word);
    refuses(|| copied_rust::ret_before_view(&call, ready.view(), 1, rsp, ready.case.value(), word));
    call.rip = word;
    call.rsp += 8;
    copied_rust::ret_after_view(&call, ready.view(), 0, rsp, ready.case.value(), word);
    for field in 0..3 {
        let mut bad = call;
        match field {
            0 => bad.rip += 1,
            1 => bad.rsp += 8,
            _ => bad.rax ^= 1,
        };
        refuses(|| {
            copied_rust::ret_after_view(&bad, ready.view(), 0, rsp, ready.case.value(), word)
        });
    }
    // The shared real-outer-C3 effect checks full architectural data, not merely RIP.
    let r = fixture(1, 0);
    let stack = 0x8000;
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    regs.rip = r.caller + r.plan.outer_ret();
    regs.rsp = stack + 128;
    regs.eflags = 0x202;
    let before = Snapshot {
        logical_pc: regs.rip,
        registers: regs,
        xstate: vec![0; 512],
        data: vec![0; PAGE],
        application_stack: vec![0; 144],
    };
    let mut before = before;
    put_word(&mut before.application_stack, stack, regs.rsp, 0x2222);
    for field in 0..7 {
        let mut after = Snapshot {
            logical_pc: 0x2222,
            registers: before.registers,
            xstate: before.xstate.clone(),
            data: before.data.clone(),
            application_stack: before.application_stack.clone(),
        };
        after.registers.rip = 0x2222;
        after.registers.rsp += 8;
        if field == 0 {
            copied_rust::outer_effect(&before, &after, stack);
            continue;
        }
        match field {
            1 => after.registers.rax ^= 1,
            2 => after.registers.eflags ^= 0x40,
            3 => after.xstate[511] ^= 1,
            4 => after.data[4095] ^= 1,
            5 => after.application_stack[143] ^= 1,
            _ => after.registers.rsp += 8,
        };
        refuses(|| copied_rust::outer_effect(&before, &after, stack));
    }
}
fn observation() -> trace::Observation<'static> {
    let declared = BodyCoverage {
        heads: BTreeSet::from([0, 1]),
        edges: BTreeSet::from([(0, 1)]),
        returns: BTreeSet::from([1]),
    };
    trace::Observation {
        comparisons: 12,
        code: &[0x90, 0xc3],
        observed: declared.clone(),
        declared,
    }
}
#[test]
fn leaf_set_population_retains_all_subsets_k_seeds_cases_and_counts() {
    let keys = keys();
    let mut counts = [0; 4];
    let mut groups = 0;
    let mut p = Population::default();
    let plan = plan();
    for &(subset, k, seed, operation, index) in &keys {
        counts[operation] += 1;
        let c = Case::new(subset, k, operation, index, selections());
        if let Some(g) = p.record_observation(seed, c, &plan, observation()) {
            assert_eq!(g.comparisons, 12 * CASE_COUNTS[operation]);
            groups += 1;
        }
    }
    assert_eq!(counts, [512, 256, 256, 256]);
    assert_eq!(groups, 128);
    assert_eq!(p.finish(), 1280 * 12);
    let c = Case::new(1, 10, 0, 0, selections());
    for field in 0..6 {
        refuses(|| {
            let mut p = Population::default();
            let mut c = c;
            let mut seed = SEEDS[0];
            let mut o = observation();
            match field {
                0 => seed = SEEDS[1],
                1 => c = Case::new(1, 1000, 0, 0, selections()),
                2 => c = Case::new(1, 10, 0, 1, selections()),
                3 => c = Case::new(3, 10, 0, 0, selections()),
                4 => o.comparisons = 0,
                _ => o.observed.returns.clear(),
            };
            p.record_observation(seed, c, &plan, o);
        });
    }
    let mut p = Population::default();
    p.record_observation(SEEDS[0], c, &plan, observation());
    refuses(|| {
        p.record_observation(SEEDS[0], c, &plan, observation());
    });
    let mut p = Population::default();
    p.record_observation(SEEDS[0], c, &plan, observation());
    refuses(|| {
        let mut o = observation();
        o.code = &[0xc3];
        p.record_observation(SEEDS[0], Case::new(1, 10, 0, 1, selections()), &plan, o);
    });
}
#[test]
fn leaf_set_coverage_preserves_csv_subset_and_full_other_cfg_rules() {
    let full = BodyCoverage {
        heads: BTreeSet::from([0, 1, 2]),
        edges: BTreeSet::from([(0, 1), (0, 2), (1, 2)]),
        returns: BTreeSet::from([2]),
    };
    let subset = BodyCoverage {
        heads: BTreeSet::from([0, 2]),
        edges: BTreeSet::from([(0, 2)]),
        returns: BTreeSet::from([2]),
    };
    trace::coverage_complete(0, &subset, &full);
    for operation in 1..4 {
        trace::coverage_complete(operation, &full, &full);
        refuses(|| trace::coverage_complete(operation, &subset, &full));
    }
    let mut missing = subset.clone();
    missing.returns.clear();
    for operation in 0..4 {
        refuses(|| trace::coverage_complete(operation, &missing, &full));
    }
    let mut extra = full.clone();
    extra.heads.insert(3);
    refuses(|| trace::coverage_complete(0, &extra, &full));
}
#[test]
fn leaf_set_output_caps_and_partial_rows_never_qualify() {
    let c = Case::new(1, 10, 0, 0, selections());
    let (pair, t) = metadata(c);
    let fields = pair_fields(SEEDS[0], c, &plan(), &pair, &t);
    assert_eq!(fields.len(), 36);
    assert!(fields[18].is_empty() && fields[19].is_empty());
    let mut text = HEADER.to_owned();
    append_row(&mut text, &fields, 36, 768, 1024 * 1024);
    assert_eq!(text.lines().count(), 2);
    for field in 0..4 {
        let mut bad = fields.clone();
        match field {
            0 => {
                bad.pop();
            }
            1 => bad[0].push(','),
            2 => bad[0].push('\n'),
            _ => bad[0] = "x".repeat(769),
        };
        let old = text.clone();
        refuses(|| append_row(&mut text, &bad, 36, 768, 1024 * 1024));
        assert_eq!(text, old);
    }
    let old = text.clone();
    refuses(|| append_row(&mut text, &fields, 36, 768, old.len()));
    assert_eq!(text, old);
    let maximum = vec![u64::MAX.to_string(); 36];
    let mut maximum_table = String::new();
    append_row(&mut maximum_table, &maximum, 36, 768, 1024 * 1024);
    assert_eq!(maximum_table.len(), 756);
    let mut raw = pair;
    raw.outer_value = u64::MAX;
    let raw_fields = pair_fields(SEEDS[0], c, &plan(), &raw, &t);
    assert_eq!(raw_fields[17], u64::MAX.to_string());
    let covered = Coverage {
        heads: 2,
        declared_heads: 2,
        edges: 1,
        declared_edges: 1,
        returns: 1,
        declared_returns: 1,
        comparisons: usize::MAX,
    };
    let cf = coverage_fields(SEEDS[0], c, &covered);
    assert_eq!(cf.len(), 16);
    append_row(&mut maximum_table, &cf, 16, 384, 1024 * 1024);
    assert!(terminal(usize::MAX).len() <= 1024);
    assert!(terminal(15360).contains(":pairs=1280:children=2560:"));
    refuses(|| {
        terminal(0);
    });
    refuses(|| {
        Population::default().finish();
    });
    let mut p = Population::default();
    p.record_observation(SEEDS[0], c, &plan(), observation());
    refuses(|| {
        p.finish();
    });
}

#[test]
fn leaf_set_whole_policy_extent_and_complete_table_are_fixed() {
    assert_eq!(
        (0..4).map(policy).collect::<Vec<_>>(),
        vec![
            PlanningPolicy::CertifiedBlocks,
            PlanningPolicy::WholeFunction,
            PlanningPolicy::WholeFunction,
            PlanningPolicy::WholeFunction,
        ]
    );
    for operation in 0..4 {
        let maximum = if operation == 0 { 256 } else { 80 };
        assert_eq!(maximum_extent(operation), maximum);
        for extent in [5, maximum] {
            assert_eq!(
                Selection::parse("16384", &extent.to_string(), operation),
                Selection {
                    elf_va: 16384,
                    extent
                }
            );
        }
        for extent in [4, maximum + 1, 257] {
            refuses(|| {
                Selection::parse("16384", &extent.to_string(), operation);
            });
        }
        if operation != 0 {
            for extent in [4, 81, 256] {
                let mut all =
                    [0x4000, 0x4100, 0x4200, 0x4300].map(|elf_va| Selection { elf_va, extent: 6 });
                all[operation].extent = extent;
                // Even an unselected descriptor is checked before any child.
                refuses(|| {
                    Case::new(1, 10, 0, 0, all);
                });
            }
        }
    }
    refuses(|| {
        policy(4);
    });
    refuses(|| {
        maximum_extent(usize::MAX);
    });
    let mut all = [0x4300, 0x4100, 0x4200, 0x4000].map(|elf_va| Selection { elf_va, extent: 80 });
    all[0].extent = 256;
    let case = Case::new(15, 10, 0, 0, all);
    assert_eq!(
        case.table().iter().map(|(op, _)| *op).collect::<Vec<_>>(),
        [3, 1, 2, 0]
    );
    assert_eq!(
        case.table()
            .iter()
            .map(|(op, _)| policy(*op))
            .collect::<Vec<_>>(),
        [
            PlanningPolicy::WholeFunction,
            PlanningPolicy::WholeFunction,
            PlanningPolicy::WholeFunction,
            PlanningPolicy::CertifiedBlocks,
        ]
    );
    assert_eq!(case.selected(), 3);
}

#[test]
fn leaf_set_whole_ready_version_and_coherent_oversize_refuse() {
    assert_eq!(PROFILE, "leaf-set-whole-rust-v1");
    assert_eq!(VERSION, b"LEAF-SET-WHOLE-RUST-V1\0");
    let ready = fixture(1, 0);
    let wire = ready.encode();
    assert_eq!(Ready::decode(&wire, ready.case, &ready.plan).encode(), wire);
    for prefix in [
        b"LEAF-SET-COPIED-RUST-V1\0".as_slice(),
        b"LEAF-SET-WHOLE-RUST-V2\0",
    ] {
        let mut old = prefix.to_vec();
        old.extend_from_slice(&wire[VERSION.len()..]);
        refuses(|| {
            Ready::decode(&old, ready.case, &ready.plan);
        });
    }
    for operation in 1..4 {
        for extent in [4, 81, 256] {
            let mut coherent = ready.case;
            coherent.selections[operation].extent = extent;
            let mut changed = wire.clone();
            let at = VERSION.len() + 5 * 8 + operation * 16 + 8;
            changed[at..at + 8].copy_from_slice(&(extent as u64).to_le_bytes());
            // Parent expectation agrees with the corruption: only full-table
            // profile admission, not an incidental unequal Case, must refuse.
            refuses(|| {
                Ready::decode(&changed, coherent, &ready.plan);
            });
        }
    }
    assert!(terminal(15360).starts_with("native-leaf-set-rust:profile=leaf-set-whole-rust-v1:"));
    assert!(!terminal(15360).contains("leaf-set-copied-rust-v1"));
}
