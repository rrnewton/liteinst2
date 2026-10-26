//! Grouped successor chains retain exact plans while charging actual backing.

#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/eviction_chain_cases.rs"]
mod cases;
use cases::{CASES, Fixture};
use liteinst2::bundle::{BundleBudget, BundleMemory};
use liteinst2::contracts::{AddressRange, Refusal};
use liteinst2::eviction_chain::{
    PlannedChain, plan_successor_chain, plan_successor_chain_detailed,
    plan_successor_chain_grouped, plan_successor_chain_grouped_detailed,
};
use liteinst2::grouping::{BackingKind, GroupingBudget, GroupingMemory};
use liteinst2::search::SearchStop;
use liteinst2::trampoline::HookContext;

const BASE: u64 = 0x3000_0000_0000;
const SPAN: u64 = 0x6d69_9000;
unsafe extern "C" fn observe(_: *mut HookContext) {}

fn exact_bundle() -> BundleBudget {
    BundleBudget {
        max_steps: 4,
        max_mappings: 4,
        max_virtual_bytes: 16384,
        max_backing_bytes: 4096,
        max_virtual_span: SPAN,
    }
}

fn exact_grouping() -> GroupingBudget {
    GroupingBudget {
        max_mappings: 4,
        max_virtual_pages: 4,
        max_virtual_bytes: 16384,
        max_backing_bytes: 4096,
        max_virtual_span: SPAN,
    }
}

fn assert_same_transaction(ordinary: &PlannedChain, grouped: &PlannedChain) {
    assert_eq!(grouped.nodes(), ordinary.nodes());
    assert_eq!(grouped.metrics(), ordinary.metrics());
    let a = ordinary.bundle().plan();
    let b = grouped.bundle().plan();
    assert_eq!(b.identity(), a.identity());
    assert_eq!(b.originals(), a.originals());
    assert_eq!(b.final_bytes(), a.final_bytes());
    assert_eq!(b.steps(), a.steps());
    assert_eq!(b.locks(), a.locks());
    // Whole image equality includes bytes, layouts, routes, PC maps,
    // instruction boundaries and retained controls, not just image lengths.
    assert_eq!(grouped.bundle().images(), ordinary.bundle().images());
    assert_eq!(b.memory().mappings, a.memory().mappings);
    assert_eq!(b.memory().virtual_pages, a.memory().virtual_pages);
    assert_eq!(b.memory().virtual_bytes, a.memory().virtual_bytes);
    assert_eq!(b.memory().virtual_span, a.memory().virtual_span);
}

#[test]
fn exact_four_virtual_pages_share_one_backing_page_without_plan_changes() {
    let f = Fixture::new(&CASES[0], BASE);
    let ordinary = plan_successor_chain_detailed(
        &f.request(observe),
        &f.policies[1..],
        f.search(),
        f.budget(),
    )
    .unwrap();
    f.assert_plan(&ordinary);
    assert!(ordinary.bundle().grouping().is_none());
    let grouped = plan_successor_chain_grouped_detailed(
        &f.request(observe),
        &f.policies[1..],
        f.search(),
        exact_bundle(),
        exact_grouping(),
    )
    .unwrap();
    assert_same_transaction(&ordinary, &grouped);
    let simple = plan_successor_chain_grouped(
        &f.request(observe),
        &f.policies[1..],
        f.search(),
        exact_bundle(),
        exact_grouping(),
    )
    .unwrap();
    assert_same_transaction(&grouped, &simple);
    assert_eq!(
        simple.bundle().plan().memory(),
        grouped.bundle().plan().memory()
    );
    assert_eq!(
        simple.bundle().grouping().unwrap().groups(),
        grouped.bundle().grouping().unwrap().groups()
    );
    assert_eq!(
        ordinary.bundle().plan().memory(),
        BundleMemory {
            mappings: 4,
            virtual_pages: 4,
            backing_pages: 4,
            virtual_bytes: 16384,
            backing_bytes: 16384,
            virtual_span: SPAN,
        }
    );
    assert_eq!(
        grouped.bundle().plan().memory(),
        BundleMemory {
            mappings: 4,
            virtual_pages: 4,
            backing_pages: 1,
            virtual_bytes: 16384,
            backing_bytes: 4096,
            virtual_span: SPAN,
        }
    );
    let grouping = grouped.bundle().grouping().unwrap();
    assert_eq!(grouping.images(), ordinary.bundle().images());
    assert_eq!(
        grouping.memory(),
        GroupingMemory {
            mappings: 4,
            virtual_pages: 4,
            backing_pages: 1,
            virtual_bytes: 16384,
            backing_bytes: 4096,
            virtual_span: SPAN,
        }
    );
    assert_eq!(grouping.groups().len(), 1);
    let group = &grouping.groups()[0];
    assert_eq!(group.kind(), BackingKind::SharedPage);
    assert_eq!(group.backing_len(), 4096);
    assert_eq!(group.image_indices(), &[0, 1, 2, 3]);
    // Publication order is anchor, LEA auxiliary, NOP auxiliary, selected.
    let images = grouped.bundle().images();
    let offsets: Vec<_> = images.iter().map(|image| image.address() & 4095).collect();
    assert_eq!(offsets, [0x461, 0x008, 0x0f0, 0x985]);
    assert_eq!(images[0].bytes().len(), 10);
    assert_eq!(images[1].bytes().len(), 8);
    assert_eq!(images[2].bytes().len(), 6);
    assert!(!images[3].bytes().is_empty());
    assert!(images[3].bytes().len() <= 0x67b);
    let aliases: Vec<_> = f
        .targets
        .iter()
        .rev()
        .map(|&target| AddressRange::new(target & !4095, 4096).unwrap())
        .collect();
    assert_eq!(group.aliases(), aliases);
    for (index, image) in images.iter().enumerate() {
        let start = offsets[index];
        let end = start + image.bytes().len() as u64;
        assert!(end <= 4096);
        let allocations = &grouped.bundle().plan().steps()[index].parts().allocations;
        assert_eq!(allocations.len(), 1);
        assert_eq!(allocations[0].range, aliases[index]);
        for (other, other_image) in images.iter().take(index).enumerate() {
            let other_end = offsets[other] + other_image.bytes().len() as u64;
            assert!(end <= offsets[other] || other_end <= start);
            assert!(!aliases[index].overlaps(aliases[other]));
        }
    }
    assert_eq!(f.code, CASES[0].code);
}

#[test]
fn ordinary_chain_still_refuses_one_page_of_backing_before_search() {
    let f = Fixture::new(&CASES[0], BASE);
    let failure = plan_successor_chain_detailed(
        &f.request(observe),
        &f.policies[1..],
        f.search(),
        exact_bundle(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.metrics.candidate_trials, 0);
    assert!(failure.metrics.runs.is_empty());
    assert!(failure.metrics.attempts.is_empty());
    assert!(!failure.metrics.global_cutoff);
    assert!(!failure.metrics.classification_complete);
    assert_eq!(
        plan_successor_chain(
            &f.request(observe),
            &f.policies[1..],
            f.search(),
            exact_bundle()
        )
        .unwrap_err(),
        failure.reason
    );
    assert_eq!(f.code, CASES[0].code);
}

#[test]
fn every_bundle_limit_remains_binding_with_grouped_backing() {
    let f = Fixture::new(&CASES[0], BASE);
    let exact = exact_bundle();
    for budget in [
        BundleBudget {
            max_steps: 3,
            ..exact
        },
        BundleBudget {
            max_mappings: 3,
            ..exact
        },
        BundleBudget {
            max_virtual_bytes: 16383,
            ..exact
        },
        BundleBudget {
            max_backing_bytes: 4095,
            ..exact
        },
        BundleBudget {
            max_virtual_span: SPAN - 1,
            ..exact
        },
    ] {
        let failure = plan_successor_chain_grouped_detailed(
            &f.request(observe),
            &f.policies[1..],
            f.search(),
            budget,
            exact_grouping(),
        )
        .unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert!(!failure.metrics.global_cutoff);
        assert!(!failure.metrics.classification_complete);
        assert!(failure.metrics.attempts.iter().all(|a| !a.complete_chain));
        if budget.max_backing_bytes == 4095 {
            assert_eq!(failure.metrics.candidate_trials, 0);
            assert!(failure.metrics.attempts.is_empty());
        }
        assert_eq!(f.code, CASES[0].code);
    }
}

#[test]
fn every_grouping_limit_remains_binding_at_each_composed_suffix() {
    let f = Fixture::new(&CASES[0], BASE);
    let exact = exact_grouping();
    for budget in [
        GroupingBudget {
            max_mappings: 3,
            ..exact
        },
        GroupingBudget {
            max_virtual_pages: 3,
            ..exact
        },
        GroupingBudget {
            max_virtual_bytes: 16383,
            ..exact
        },
        GroupingBudget {
            max_backing_bytes: 4095,
            ..exact
        },
        GroupingBudget {
            max_virtual_span: SPAN - 1,
            ..exact
        },
    ] {
        let failure = plan_successor_chain_grouped_detailed(
            &f.request(observe),
            &f.policies[1..],
            f.search(),
            exact_bundle(),
            budget,
        )
        .unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert!(!failure.metrics.global_cutoff);
        assert!(!failure.metrics.classification_complete);
        assert!(failure.metrics.attempts.iter().all(|a| !a.complete_chain));
        if budget.max_backing_bytes == 4095 {
            // The first real anchor trial pays work and fails composition.
            // This must not become a free or successful placement attempt.
            assert_eq!(failure.metrics.candidate_trials, 1);
            assert_eq!(failure.metrics.attempts.len(), 1);
            assert_eq!(failure.metrics.attempts[0].original, BASE + 6);
            assert_eq!(failure.metrics.attempts[0].target, Some(f.targets[3]));
            assert_eq!(
                failure.metrics.attempts[0].refusal,
                Some(Refusal::AllocationUnavailable)
            );
        }
        assert_eq!(f.code, CASES[0].code);
    }
}

#[test]
fn grouped_suffix_backtracking_preserves_trials_failures_and_global_cutoff() {
    let mut f = Fixture::new(&CASES[1], BASE);
    let anchor = f.targets.len() - 1;
    let bad = f.targets[anchor] - 65536;
    f.policies[anchor].preferred_address = Some(bad);
    f.policies[anchor]
        .ranges
        .insert(0, AddressRange::new(bad & !4095, 8192).unwrap());
    f.policies[anchor].max_candidates = 2;
    let mut search = f.search();
    search.max_candidate_trials = 6;
    let ordinary =
        plan_successor_chain_detailed(&f.request(observe), &f.policies[1..], search, f.budget())
            .unwrap();
    let grouped = plan_successor_chain_grouped_detailed(
        &f.request(observe),
        &f.policies[1..],
        search,
        f.budget(),
        GroupingBudget::default(),
    )
    .unwrap();
    assert_same_transaction(&ordinary, &grouped);
    assert_eq!(grouped.metrics().candidate_trials, 6);
    assert!(!grouped.metrics().global_cutoff);
    assert_eq!(grouped.metrics().attempts[0].target, Some(bad));
    assert!(!grouped.metrics().attempts[0].complete_chain);
    assert_eq!(grouped.metrics().runs[1].original, BASE + 9);
    assert_eq!(grouped.metrics().runs[1].examined, 0);
    assert_eq!(grouped.metrics().runs[1].stop, SearchStop::DomainComplete);
    assert_eq!(
        grouped.bundle().plan().final_bytes()[0].bytes,
        CASES[1].final_bytes
    );
    assert_eq!(
        grouped.nodes().iter().map(|n| n.target).collect::<Vec<_>>(),
        f.targets
    );
    // Rebuilding after the failed suffix cannot retain its rejected image.
    assert!(
        grouped
            .bundle()
            .grouping()
            .unwrap()
            .images()
            .iter()
            .all(|i| i.address() != bad)
    );
    search.max_candidate_trials = 5;
    let ordinary_failure =
        plan_successor_chain_detailed(&f.request(observe), &f.policies[1..], search, f.budget())
            .unwrap_err();
    let grouped_failure = plan_successor_chain_grouped_detailed(
        &f.request(observe),
        &f.policies[1..],
        search,
        f.budget(),
        GroupingBudget::default(),
    )
    .unwrap_err();
    assert_eq!(grouped_failure, ordinary_failure);
    assert_eq!(grouped_failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(grouped_failure.metrics.candidate_trials, 5);
    assert!(grouped_failure.metrics.global_cutoff);
    assert!(!grouped_failure.metrics.classification_complete);
    assert!(
        grouped_failure
            .metrics
            .attempts
            .iter()
            .all(|a| !a.complete_chain)
    );
    assert_eq!(f.code, CASES[1].code);
}
