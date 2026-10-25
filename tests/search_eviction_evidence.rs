#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Four additive pure-planner puzzles using the existing T2/T3 contract geometry.
//! No executable mappings or native/publication coverage are created here.
use liteinst2::bundle::BundleBudget;
use liteinst2::contracts::*;
use liteinst2::eviction::plan_successor_detailed;
use liteinst2::neighbor::{NeighborAttemptStage, NeighborSearch, plan_neighbor_detailed};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy};
use liteinst2::search::{
    CandidateProof, RefusalClass, SearchDomain, SearchEvidence, SearchRun, SearchStop,
};

const PAGE: usize = 4096;
const PAD: usize = 16;
const BASE: u64 = 0x3800_0000_0000;
const VICTIM_DISPLACEMENT: i32 = 0x0012_3456;
const VICTIM_VALUE: u64 = 0x1937_5a82_4b6c_d0e1;
unsafe extern "C" fn noop(_: *mut liteinst2::trampoline::HookContext) {}

fn identity(case: u64) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([case as u8; 32]),
        mapping: case + 1,
        generation: 1,
    }
}
fn run(evidence: &SearchEvidence, domain: SearchDomain) -> &SearchRun {
    let mut matches = evidence.runs.iter().filter(|item| item.domain == domain);
    let first = matches.next().unwrap();
    assert!(
        matches.next().is_none(),
        "this fixture requires exactly one run of this domain"
    );
    first
}
fn allocated(target: u64, max_candidates: usize) -> AllocationPolicy {
    let mut policy = AllocationPolicy::near(target).unwrap();
    policy.preferred_address = Some(target);
    policy.ranges = vec![AddressRange::new(target & !4095, 8192).unwrap()];
    policy.max_candidates = max_candidates;
    policy
}

struct SuccessorFixture {
    selected: u64,
    source: u64,
    original: Vec<u8>,
    entries: LegalEntrySet,
    selected_allocation: AllocationPolicy,
    victim_allocation: AllocationPolicy,
}
impl SuccessorFixture {
    fn new(case: u64, offset: usize) -> Self {
        // Exactly failure_inventory's Fixture::new(case, offset, 2, 1, 8).
        let selected = BASE + case * 0x2_0000_0000 + offset as u64;
        let source = selected - PAD as u64;
        let mut original = vec![0x90; PAD];
        original.extend_from_slice(&[0x66, 0x90]);
        original.extend_from_slice(&[0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]);
        original.push(0xb8);
        original.extend_from_slice(&0x1937_5a82_u32.to_le_bytes());
        original.push(0xc3);
        let entries = LegalEntrySet {
            identity: identity(case),
            scope: AddressRange::new(selected, 2 + 8 + 6).unwrap(),
            provenance: EntryProvenance::Declared("whole successor NOP fixture".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: vec![],
            resumes: ResumeObligation::NoneExist,
        };
        let victim_target = selected + 2 + 5 + VICTIM_DISPLACEMENT as u64;
        let mut patch = vec![0xe9];
        patch.extend_from_slice(&VICTIM_DISPLACEMENT.to_le_bytes());
        let fixed = i32::from_le_bytes(patch[..4].try_into().unwrap());
        let selected_target = u64::try_from(i128::from(selected + 6) + i128::from(fixed)).unwrap();
        Self {
            selected,
            source,
            original,
            entries,
            selected_allocation: allocated(selected_target, 256),
            victim_allocation: allocated(victim_target, 256),
        }
    }
    fn request(&self) -> InstallRequest<'_> {
        InstallRequest {
            identity: self.entries.identity,
            code: &self.original,
            base_address: self.source,
            function: self.entries.scope,
            block: AddressRange::new(self.selected, 2).unwrap(),
            logical_pc: self.selected,
            entries: &self.entries,
            hook: noop,
            semantics: HookSemantics::Observe,
            allocation: &self.selected_allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::PrefixPunOnly,
                max_sites: 1,
                max_upstream_bytes: 0,
                max_displaced_bytes: 8,
            },
        }
    }
}

#[test]
fn successor_selected_no_window_still_dominates_later_victim_unavailability() {
    let fixture = SuccessorFixture::new(0, 128);
    let original = fixture.original.clone();
    let positive = plan_successor_detailed(
        &fixture.request(),
        &fixture.victim_allocation,
        BundleBudget::default(),
    )
    .unwrap();
    assert_eq!(positive.metrics().attempts.len(), 1);
    assert_eq!(positive.metrics().attempts[0].prefix_count, Some(1));
    assert_eq!(positive.metrics().attempts[0].refusal, None);
    assert!(positive.metrics().search.accepted);
    assert!(!positive.metrics().search.classification_complete);
    let first_target = fixture.victim_allocation.preferred_address.unwrap();
    let unavailable = AllocationPolicy {
        max_candidates: 1,
        ranges: vec![AddressRange::new((first_target & !4095) + 0x2_0000, 8192).unwrap()],
        ..fixture.victim_allocation.clone()
    };
    let first = plan_successor_detailed(&fixture.request(), &unavailable, BundleBudget::default())
        .unwrap_err();
    assert_eq!(first.reason, Refusal::AllocationUnavailable);
    assert_eq!(first.attempts.len(), 1);
    assert_eq!(first.attempts[0].prefix_count, None);
    assert_eq!(first.attempts[0].victim, fixture.selected + 2);
    assert_eq!(first.attempts[0].victim_target, first_target);
    assert_eq!(
        first.attempts[0].refusal,
        Some(Refusal::AllocationUnavailable)
    );
    assert_eq!(fixture.original, original);

    let crossing = SuccessorFixture::new(1, 128 + 63);
    let original = crossing.original.clone();
    let victim_target = crossing.victim_allocation.preferred_address.unwrap();
    let victim = AllocationPolicy {
        max_candidates: 2,
        ..crossing.victim_allocation.clone()
    };
    let failed =
        plan_successor_detailed(&crossing.request(), &victim, BundleBudget::default()).unwrap_err();
    assert_eq!(failed.reason, Refusal::NoPatchWindow);
    assert_eq!(failed.attempts.len(), 2);
    assert_eq!(failed.attempts[0].prefix_count, Some(1));
    assert_eq!(failed.attempts[0].refusal, Some(Refusal::NoPatchWindow));
    assert_eq!(failed.attempts[0].victim_target, victim_target);
    assert_eq!(failed.attempts[1].prefix_count, None);
    assert_eq!(
        failed.attempts[1].refusal,
        Some(Refusal::AllocationUnavailable)
    );
    assert_eq!(failed.attempts[1].victim_target, victim_target + 0x1_0000);
    assert_eq!(failed.attempts[0].victim, crossing.selected + 2);
    assert_eq!(failed.attempts[1].victim, crossing.selected + 2);
    let local = failed
        .search
        .refusals
        .iter()
        .find(|item| item.reason == Refusal::NoPatchWindow)
        .unwrap();
    assert_eq!(local.class, RefusalClass::Prerequisite);
    assert_eq!(local.scope.physical_pc, Some(crossing.selected));
    assert_eq!(local.scope.victim_target, Some(victim_target));
    assert_eq!(local.scope.prefix_count, Some(1));
    let images = run(&failed.search, SearchDomain::VictimImages);
    assert_eq!(images.examined, 2);
    assert_eq!(images.limit, 2);
    assert_eq!(
        images.stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    let Some(CandidateProof::Indexed {
        omitted: Some(witness),
        ..
    }) = &images.candidates
    else {
        panic!("exact remaining victim slot required");
    };
    assert_eq!(witness.slot, 2);
    assert_eq!(witness.target, victim_target + 0x2_0000);
    assert!(!failed.search.accepted);
    assert!(!failed.search.classification_complete);
    assert_eq!(crossing.original, original);
}

struct NeighborFixture {
    source: u64,
    selected: u64,
    lower: u64,
    upper: u64,
    first_target: u64,
    second_target: u64,
    original: Vec<u8>,
    entries: LegalEntrySet,
    selected_allocation: AllocationPolicy,
    victim_allocation: AllocationPolicy,
}
impl NeighborFixture {
    fn new() -> Self {
        // Exactly automatic_budget's case0, S=PAGE-128, lower=S-131,
        // upper=S+124, L3/M10, PAD16 and the original MOVABS immediate.
        let selected = BASE + (PAGE - 128) as u64;
        let lower = selected - 131;
        let upper = selected + 124;
        let source = lower - PAD as u64;
        let mut original = vec![0x90; (upper + 11 - source) as usize];
        let at = (selected - source) as usize;
        original[at..at + 3].copy_from_slice(&[0x48, 0xff, 0xc0]);
        original[at + 3] = 0xc3;
        let mut victim_bytes = vec![0x48, 0xb8];
        victim_bytes.extend_from_slice(&VICTIM_VALUE.to_le_bytes());
        for victim in [lower, upper] {
            let at = (victim - source) as usize;
            original[at..at + 10].copy_from_slice(&victim_bytes);
            original[at + 10] = 0xc3;
        }
        let entries = LegalEntrySet {
            identity: identity(0),
            scope: AddressRange::new(lower, (upper + 11 - lower) as usize).unwrap(),
            provenance: EntryProvenance::Declared(
                "two independent INC/MOVABS/RET streams with NOP filler".into(),
            ),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: [selected, lower, selected + 3, lower + 10, upper, upper + 10]
                .into_iter()
                .map(|address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let first_target = upper + 5 + 0x1_0000;
        let second_target = lower + 5 + 0x1_0000;
        assert_ne!(first_target & !4095, second_target & !4095);
        let selected_allocation = AllocationPolicy {
            preferred_address: Some(first_target),
            ranges: vec![AddressRange::new(first_target & !4095, PAGE).unwrap()],
            max_candidates: 1,
            ..AllocationPolicy::near(lower + 5).unwrap()
        };
        let victim_allocation = AllocationPolicy {
            preferred_address: None,
            ranges: vec![AddressRange::new(second_target & !4095, 2 * PAGE).unwrap()],
            max_candidates: 1,
            ..AllocationPolicy::near(lower).unwrap()
        };
        Self {
            source,
            selected,
            lower,
            upper,
            first_target,
            second_target,
            original,
            entries,
            selected_allocation,
            victim_allocation,
        }
    }
    fn request(&self) -> InstallRequest<'_> {
        InstallRequest {
            identity: self.entries.identity,
            code: &self.original,
            base_address: self.source,
            function: self.entries.scope,
            block: AddressRange::new(self.selected, 3).unwrap(),
            logical_pc: self.selected,
            entries: &self.entries,
            hook: noop,
            semantics: HookSemantics::Observe,
            allocation: &self.selected_allocation,
            search: SearchPolicy {
                max_sites: 1,
                max_upstream_bytes: 0,
                max_displaced_bytes: 10,
                ..Default::default()
            },
        }
    }
    fn search(&self) -> NeighborSearch {
        NeighborSearch {
            forced_victim: None,
            max_victims: 2,
            max_pairs: 2,
        }
    }
    fn assert_first(&self, attempt: &liteinst2::neighbor::NeighborAttempt) {
        assert_eq!(attempt.stage, NeighborAttemptStage::SelectedPlacement);
        assert_eq!(attempt.victim, self.upper);
        assert_eq!(attempt.victim_target, Some(self.first_target));
        assert_eq!(attempt.selected_target, Some(self.first_target));
        assert_eq!(attempt.refusal, Some(Refusal::AllocationUnavailable));
    }
    fn assert_winner(&self, plan: &liteinst2::neighbor::PlannedNeighbor) {
        assert_eq!(plan.metrics().victims_examined, 2);
        assert_eq!(plan.metrics().pairs_examined, 2);
        assert_eq!(plan.metrics().attempts.len(), 2);
        self.assert_first(&plan.metrics().attempts[0]);
        let success = &plan.metrics().attempts[1];
        assert_eq!(success.stage, NeighborAttemptStage::Composition);
        assert_eq!(success.victim, self.lower);
        assert_eq!(success.refusal, None);
        assert_eq!(success.victim_target, Some(self.second_target));
        assert_eq!(success.selected_target, Some(self.first_target));
        assert_eq!(plan.geometry().selected, self.selected);
        assert_eq!(plan.geometry().victim, self.lower);
        assert_eq!(plan.geometry().relay, self.lower + 5);
        assert_eq!(plan.geometry().rel8, -128);
        assert_eq!(plan.geometry().victim_target, self.second_target);
        assert_eq!(plan.geometry().selected_target, self.first_target);
        let steps = plan.bundle().plan().steps();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].parts().physical_pc, self.selected);
        assert_eq!(steps[1].parts().physical_pc, self.lower);
        assert!(plan.metrics().search.accepted);
        assert!(!plan.metrics().search.classification_complete);
    }
}

#[test]
fn neighbor_entered_pair_cutoff_then_second_pair_wins_unchanged() {
    let fixture = NeighborFixture::new();
    let original = fixture.original.clone();
    let failed = plan_neighbor_detailed(
        &fixture.request(),
        &fixture.victim_allocation,
        NeighborSearch {
            max_pairs: 1,
            ..fixture.search()
        },
        BundleBudget::default(),
    )
    .unwrap_err();
    assert_eq!(failed.reason, Refusal::AllocationUnavailable);
    assert_eq!(failed.attempts.len(), 1);
    fixture.assert_first(&failed.attempts[0]);
    let pairs = run(&failed.search, SearchDomain::JointPairs);
    assert_eq!(pairs.limit, 1);
    assert_eq!(pairs.examined, 1);
    assert_eq!(
        pairs.stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    // The lower victim's current selected slot was entered but not charged.
    let lower = failed
        .search
        .runs
        .iter()
        .find(|item| {
            item.domain == SearchDomain::SelectedImages
                && item.scope.victim_target == Some(fixture.second_target)
        })
        .unwrap();
    assert_eq!(lower.examined, 0);
    assert_eq!(lower.stop, SearchStop::Interrupted);
    assert!(!failed.search.classification_complete);
    let planned = plan_neighbor_detailed(
        &fixture.request(),
        &fixture.victim_allocation,
        fixture.search(),
        BundleBudget::default(),
    )
    .unwrap();
    fixture.assert_winner(&planned);
    assert_eq!(planned.metrics().attempts[0], failed.attempts[0]);
    assert_eq!(
        run(&planned.metrics().search, SearchDomain::JointPairs).stop,
        SearchStop::Accepted
    );
    assert_eq!(fixture.original, original);
}

#[test]
fn neighbor_automatic_victim_limit_has_its_own_one_two_evidence() {
    let fixture = NeighborFixture::new();
    let original = fixture.original.clone();
    let failed = plan_neighbor_detailed(
        &fixture.request(),
        &fixture.victim_allocation,
        NeighborSearch {
            max_victims: 1,
            ..fixture.search()
        },
        BundleBudget::default(),
    )
    .unwrap_err();
    assert_eq!(failed.reason, Refusal::AllocationUnavailable);
    assert_eq!(failed.attempts.len(), 1);
    fixture.assert_first(&failed.attempts[0]);
    let victims = run(&failed.search, SearchDomain::Victims);
    assert_eq!(victims.finite_total, Some(2));
    assert_eq!(victims.limit, 1);
    assert_eq!(victims.examined, 1);
    assert_eq!(
        victims.stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    let pairs = run(&failed.search, SearchDomain::JointPairs);
    assert_eq!(pairs.limit, 2);
    assert_eq!(pairs.examined, 1);
    assert_eq!(pairs.stop, SearchStop::UnclassifiedBoundedStop);
    let planned = plan_neighbor_detailed(
        &fixture.request(),
        &fixture.victim_allocation,
        fixture.search(),
        BundleBudget::default(),
    )
    .unwrap();
    fixture.assert_winner(&planned);
    assert_eq!(planned.metrics().attempts[0], failed.attempts[0]);
    assert_eq!(
        run(&planned.metrics().search, SearchDomain::Victims).stop,
        SearchStop::Accepted
    );
    assert!(!failed.search.classification_complete);
    assert_eq!(fixture.original, original);
}

#[test]
fn neighbor_forced_singleton_completes_victims_without_global_impossibility() {
    let fixture = NeighborFixture::new();
    let original = fixture.original.clone();
    let failed = plan_neighbor_detailed(
        &fixture.request(),
        &fixture.victim_allocation,
        NeighborSearch {
            forced_victim: Some(fixture.upper),
            max_victims: 1,
            max_pairs: 1,
        },
        BundleBudget::default(),
    )
    .unwrap_err();
    assert_eq!(failed.reason, Refusal::AllocationUnavailable);
    assert_eq!(failed.attempts.len(), 1);
    fixture.assert_first(&failed.attempts[0]);
    let victims = run(&failed.search, SearchDomain::Victims);
    assert_eq!(victims.finite_total, Some(1));
    assert_eq!(victims.limit, 1);
    assert_eq!(victims.examined, 1);
    assert_eq!(victims.stop, SearchStop::DomainComplete);
    let pairs = run(&failed.search, SearchDomain::JointPairs);
    assert_eq!(pairs.limit, 1);
    assert_eq!(pairs.examined, 1);
    assert_eq!(pairs.stop, SearchStop::UnclassifiedBoundedStop);
    assert!(failed.search.runs.iter().any(|item| matches!(
        item.domain,
        SearchDomain::SelectedImages | SearchDomain::VictimImages
    ) && item.stop
        == SearchStop::BudgetLimited {
            remaining_at_least: 1
        }));
    assert!(!failed.search.accepted);
    assert!(!failed.search.classification_complete);
    assert_eq!(fixture.original, original);
}
