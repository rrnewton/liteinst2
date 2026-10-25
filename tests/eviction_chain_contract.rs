#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/eviction_chain_cases.rs"]
mod cases;
use cases::{CASES, Fixture};
use liteinst2::contracts::*;
use liteinst2::eviction_chain::{MAX_SHORT_SUCCESSORS, plan_successor_chain_detailed};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{TacticPolicy, plan_install};
use liteinst2::search::SearchStop;
use liteinst2::trampoline::HookContext;

const BASE: u64 = 0x3000_0000_0000;
unsafe extern "C" fn observe(_: *mut HookContext) {}
fn plan(
    f: &Fixture<'_>,
) -> Result<liteinst2::eviction_chain::PlannedChain, liteinst2::eviction_chain::ChainFailure> {
    plan_successor_chain_detailed(
        &f.request(observe),
        &f.policies[1..],
        f.search(),
        f.budget(),
    )
}

#[test]
fn exact_depth_two_and_three_genuine_reverse_compositions() {
    for case in &CASES {
        let f = Fixture::new(case, BASE);
        assert_eq!(
            plan_install(&f.request(observe)).unwrap_err(),
            Refusal::AllocationUnavailable
        );
        assert_eq!(
            liteinst2::eviction::plan_successor(&f.request(observe), &f.policies[1], f.budget())
                .unwrap_err(),
            Refusal::NoPatchWindow
        );
        let p = plan(&f).expect("every frozen chain must plan");
        f.assert_plan(&p);
        assert!(
            p.metrics()
                .runs
                .iter()
                .all(|r| r.stop == SearchStop::Accepted)
        );
        assert_eq!(p.metrics().discovery.stop, SearchStop::DomainComplete);
    }
}

#[test]
fn one_less_depth_is_a_witnessed_cutoff_not_a_no_window_claim() {
    for case in &CASES {
        let f = Fixture::new(case, BASE);
        let mut search = f.search();
        search.max_short_successors -= 1;
        let e = plan_successor_chain_detailed(
            &f.request(observe),
            &f.policies[1..],
            search,
            f.budget(),
        )
        .unwrap_err();
        assert_eq!(e.reason, Refusal::AllocationUnavailable);
        assert_eq!(e.metrics.candidate_trials, 0);
        assert_eq!(
            e.metrics.discovery.short_successors.len(),
            search.max_short_successors + 1
        );
        assert_eq!(
            e.metrics.discovery.stop,
            SearchStop::BudgetLimited {
                remaining_at_least: 1
            }
        );
        assert_eq!(e.metrics.discovery.anchor, None);
        assert!(!e.metrics.global_cutoff);
    }
}

#[test]
fn zero_and_one_less_global_budget_keep_exact_work_inventory() {
    for case in &CASES {
        let f = Fixture::new(case, BASE);
        for limit in [0, case.lengths.len() - 1] {
            let mut search = f.search();
            search.max_candidate_trials = limit;
            let e = plan_successor_chain_detailed(
                &f.request(observe),
                &f.policies[1..],
                search,
                f.budget(),
            )
            .unwrap_err();
            assert_eq!(e.reason, Refusal::AllocationUnavailable);
            assert_eq!(e.metrics.candidate_trials, limit);
            assert_eq!(e.metrics.attempts.len(), limit);
            assert!(e.metrics.global_cutoff);
            assert_eq!(
                e.metrics.runs.last().unwrap().stop,
                SearchStop::BudgetLimited {
                    remaining_at_least: 1
                }
            );
            assert!(e.metrics.attempts.iter().all(|a| !a.complete_chain));
        }
        let accepted = plan(&f).unwrap();
        assert_eq!(
            accepted.metrics().candidate_trials,
            accepted.metrics().global_limit
        );
        assert!(
            !accepted.metrics().global_cutoff,
            "equality with the cap does not prove exhaustion"
        );
    }
}

#[test]
fn every_node_zero_candidate_budget_remains_local() {
    for node in 0..CASES[0].lengths.len() {
        let mut f = Fixture::new(&CASES[0], BASE);
        f.policies[node].max_candidates = 0;
        let e = plan(&f).unwrap_err();
        assert_eq!(e.reason, Refusal::AllocationUnavailable);
        assert!(!e.metrics.global_cutoff);
        assert_eq!(
            e.metrics.candidate_trials,
            CASES[0].lengths.len() - 1 - node
        );
        assert_eq!(
            e.metrics.runs.last().unwrap().original,
            BASE + CASES[0].heads[node] as u64
        );
        assert_eq!(e.metrics.runs.last().unwrap().examined, 0);
        assert!(matches!(
            e.metrics.runs.last().unwrap().stop,
            SearchStop::BudgetLimited { .. }
        ));
    }
}

#[test]
fn per_node_and_aggregate_capacity_limits_refuse_without_relabelling() {
    for node in 0..CASES[0].lengths.len() {
        for mapping_limit in [true, false] {
            let mut f = Fixture::new(&CASES[0], BASE);
            if mapping_limit {
                f.policies[node].max_mappings = 0;
            } else {
                f.policies[node].max_mapped_bytes = 4095;
            }
            let e = plan(&f).unwrap_err();
            assert_eq!(e.reason, Refusal::AllocationUnavailable);
            assert!(!e.metrics.global_cutoff);
            assert!(e.metrics.attempts.iter().all(|a| !a.complete_chain));
        }
    }
    let f = Fixture::new(&CASES[0], BASE);
    for dimension in 0..5 {
        let mut b = f.budget();
        match dimension {
            0 => b.max_steps = 3,
            1 => b.max_mappings = 3,
            2 => b.max_virtual_bytes = 3 * 4096,
            3 => b.max_backing_bytes = 3 * 4096,
            4 => b.max_virtual_span = 4096,
            _ => unreachable!(),
        }
        let e = plan_successor_chain_detailed(&f.request(observe), &f.policies[1..], f.search(), b)
            .unwrap_err();
        assert_eq!(e.reason, Refusal::AllocationUnavailable);
        assert!(!e.metrics.global_cutoff);
        assert!(e.metrics.attempts.iter().all(|a| !a.complete_chain));
    }
}

#[test]
fn forced_dependency_cycles_skips_and_extra_heads_never_substitute() {
    let f = Fixture::new(&CASES[0], BASE);
    for forced in [
        vec![],
        vec![BASE + 2, BASE + 2, BASE + 6],
        vec![BASE + 3, BASE + 2, BASE + 6],
        vec![BASE + 3, BASE + 6],
        vec![BASE + 2],
        vec![BASE + 2, BASE + 3, BASE + 6, BASE + 11],
    ] {
        let mut search = f.search();
        search.forced_successors = Some(&forced);
        let e = plan_successor_chain_detailed(
            &f.request(observe),
            &f.policies[1..],
            search,
            f.budget(),
        )
        .unwrap_err();
        assert_eq!(e.reason, Refusal::InvalidPlan);
        assert_eq!(e.metrics.candidate_trials, 0);
    }
    let e = plan_successor_chain_detailed(
        &f.request(observe),
        &f.policies[1..2],
        f.search(),
        f.budget(),
    )
    .unwrap_err();
    assert_eq!(e.reason, Refusal::InvalidPlan);
}

#[test]
fn midpoint_entries_and_saved_resume_pcs_are_rejected() {
    for midpoint in [1, 4, 7] {
        for resume in [false, true] {
            let mut f = Fixture::new(&CASES[0], BASE);
            if resume {
                f.entries.resumes = ResumeObligation::Enumerated(vec![BASE + midpoint]);
            } else {
                f.entries.entries.push(LegalEntry {
                    address: BASE + midpoint,
                    requires_endbr: false,
                });
            }
            let e = plan(&f).unwrap_err();
            assert_eq!(e.reason, Refusal::NotInstructionHead);
            assert_eq!(e.metrics.candidate_trials, 0);
        }
    }
}

#[test]
fn complete_entry_scope_and_cet_obligations_remain_mandatory() {
    for case in 0..4 {
        let mut f = Fixture::new(&CASES[0], BASE);
        match case {
            0 => f.entries.completeness = EntryCompleteness::Incomplete,
            1 => f.entries.resumes = ResumeObligation::Unresolved,
            2 => {
                f.entries.scope = AddressRange::new(BASE, 2).unwrap();
                f.entries.entries.truncate(1);
            }
            3 => f.entries.entries[1].requires_endbr = true,
            _ => unreachable!(),
        }
        let e = plan(&f).unwrap_err();
        if case == 3 {
            assert!(matches!(e.reason, Refusal::UnsupportedSemantics(_)));
        } else {
            assert_eq!(e.reason, Refusal::UnresolvedEntry);
        }
        assert_eq!(e.metrics.candidate_trials, 0);
    }
}

#[test]
fn semantic_qualification_and_existing_replacement_rule_are_preserved() {
    for case in 0..3 {
        let mut f = Fixture::new(&CASES[0], BASE);
        match case {
            0 => f.code[2] = 0x9d,
            1 => f.code[6..11].copy_from_slice(&[0xe8, 0, 0, 0, 0]),
            2 => f.code[..2].copy_from_slice(&[0xd9, 0xe8]),
            _ => unreachable!(),
        }
        let e = plan(&f).unwrap_err();
        assert!(matches!(e.reason, Refusal::UnsupportedSemantics(_)));
        assert_eq!(e.metrics.candidate_trials, 0);
        if case == 2 {
            let mut request = f.request(observe);
            request.semantics = HookSemantics::ReplaceFirst;
            let p =
                plan_successor_chain_detailed(&request, &f.policies[1..], f.search(), f.budget())
                    .unwrap();
            assert_eq!(p.nodes().len(), 4);
            assert_eq!(
                p.bundle().plan().final_bytes()[0].bytes,
                CASES[0].final_bytes
            );
            assert_eq!(p.nodes().iter().filter(|n| n.has_selected_hook).count(), 1);
        }
    }
}

#[test]
fn direct_original_branch_to_a_victim_midpoint_is_positive_counterevidence() {
    let mut f = Fixture::new(&CASES[0], BASE);
    let from = f.code.len();
    f.code.push(0xe9);
    f.code
        .extend_from_slice(&(4_i32 - from as i32 - 5).to_le_bytes());
    f.entries.scope = AddressRange::new(BASE, f.code.len()).unwrap();
    f.entries.entries.push(LegalEntry {
        address: BASE + from as u64,
        requires_endbr: false,
    });
    let e = plan(&f).unwrap_err();
    assert_eq!(e.reason, Refusal::NotInstructionHead);
    assert_eq!(e.metrics.candidate_trials, 0);
}

#[test]
fn depth_hard_limit_and_exact_search_mode_do_not_silently_fallback() {
    let f = Fixture::new(&CASES[0], BASE);
    let mut s = f.search();
    s.max_short_successors = MAX_SHORT_SUCCESSORS + 1;
    assert!(matches!(
        plan_successor_chain_detailed(&f.request(observe), &f.policies[1..], s, f.budget())
            .unwrap_err()
            .reason,
        Refusal::UnsupportedSemantics(_)
    ));
    for selected in [true, false] {
        let mut r = f.request(observe);
        let mut s = f.search();
        if selected {
            r.search.tactics = TacticPolicy::RelocationOnly;
        } else {
            s.auxiliary_puns = TacticPolicy::RelocationOnly;
        }
        assert!(matches!(
            plan_successor_chain_detailed(&r, &f.policies[1..], s, f.budget())
                .unwrap_err()
                .reason,
            Refusal::UnsupportedSemantics(_)
        ));
    }
    let mut r = f.request(observe);
    r.search.max_displaced_bytes = 4;
    assert_eq!(
        plan_successor_chain_detailed(&r, &f.policies[1..], f.search(), f.budget())
            .unwrap_err()
            .reason,
        Refusal::NoPatchWindow
    );
    let mut s = f.search();
    s.forced_successors = None;
    let p = plan_successor_chain_detailed(&f.request(observe), &f.policies[1..], s, f.budget())
        .unwrap();
    f.assert_plan(&p);
}

#[test]
fn suffix_backtracking_is_charged_and_retains_the_first_failed_path() {
    let mut f = Fixture::new(&CASES[1], BASE);
    let anchor = f.targets.len() - 1;
    let bad = f.targets[anchor] - 65536;
    f.policies[anchor].preferred_address = Some(bad);
    f.policies[anchor]
        .ranges
        .insert(0, AddressRange::new(bad & !4095, 8192).unwrap());
    f.policies[anchor].max_candidates = 2;
    let mut s = f.search();
    s.max_candidate_trials = 6;
    let p = plan_successor_chain_detailed(&f.request(observe), &f.policies[1..], s, f.budget())
        .unwrap();
    assert_eq!(p.metrics().candidate_trials, 6);
    assert!(!p.metrics().global_cutoff);
    assert_eq!(p.metrics().attempts[0].target, Some(bad));
    assert!(!p.metrics().attempts[0].complete_chain);
    assert_eq!(p.metrics().runs[1].original, BASE + 9);
    assert_eq!(p.metrics().runs[1].examined, 0);
    assert_eq!(p.metrics().runs[1].stop, SearchStop::DomainComplete);
    assert_eq!(
        p.bundle().plan().final_bytes()[0].bytes,
        CASES[1].final_bytes
    );
    assert_eq!(
        p.nodes().iter().map(|n| n.target).collect::<Vec<_>>(),
        f.targets
    );
    s.max_candidate_trials = 5;
    let e = plan_successor_chain_detailed(&f.request(observe), &f.policies[1..], s, f.budget())
        .unwrap_err();
    assert_eq!(e.reason, Refusal::AllocationUnavailable);
    assert_eq!(e.metrics.candidate_trials, 5);
    assert!(e.metrics.global_cutoff);
}

#[test]
fn a_missing_anchor_or_direct_long_successor_is_not_a_recursive_chain() {
    for code in [
        vec![0x89, 0xc0, 0x90, 0x90, 0x90, 0xc3],
        vec![0x89, 0xc0, 0xb8, 0x11, 0x22, 0x33, 0x44, 0xc3],
    ] {
        let mut f = Fixture::new(&CASES[0], BASE);
        f.code = code;
        f.entries.scope = AddressRange::new(BASE, f.code.len()).unwrap();
        f.entries.entries.clear();
        let mut s = f.search();
        s.forced_successors = None;
        s.max_short_successors = 8;
        let e = plan_successor_chain_detailed(&f.request(observe), &f.policies[1..], s, f.budget())
            .unwrap_err();
        assert_eq!(e.reason, Refusal::NoPatchWindow);
        assert_eq!(e.metrics.candidate_trials, 0);
        assert!(!e.metrics.global_cutoff);
    }
}
