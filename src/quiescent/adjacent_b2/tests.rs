//! Source-only controls for the CLOSED adjacent B2 contract. Execution is separate.
//! The first ten contract groups remain ten additive tests; no live publisher is used.

use super::*;
use crate::bundle::{BundleBudget, BundleMemory};
use crate::composition::Composition;
use crate::contracts::*;
use crate::emission::{
    ArtifactEmission, ArtifactMetrics, ArtifactPlan, ArtifactRequest, ArtifactRequirement,
    PlanningSite, SymbolicHook, TargetProfile,
};
use crate::engine::{self, EnginePolicy, Tactic};
use crate::planner::HookSemantics;
use crate::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
use crate::search::{CandidateProof, PageWalkEvidence, RefusalClass, SearchDomain, SearchStop};
use crate::trampoline::SavedExtendedStateLayout;

const B: u64 = 0x1000_06f9;
const H128: u64 = 0x11c0_7080;
const H0: u64 = 0x11c0_7000;
const LOW: u64 = 0x7900_f000;
const PRIMARY: &[u8] = &[0x75, 0x02, 0x75, 0x00, 0x69, 0xc0, 0x01, 0, 0, 0, 0xc3];

fn range(address: u64, len: usize) -> AddressRange {
    AddressRange::new(address, len).expect("declared fixture range")
}

fn identity() -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([0xa3; 32]),
        mapping: 1,
        generation: 1,
    }
}

fn entries(base: u64, len: usize, heads: &[usize]) -> LegalEntrySet {
    LegalEntrySet {
        identity: identity(),
        scope: range(base, len),
        provenance: EntryProvenance::Declared("authored-adjacent-b2-v1".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: heads
            .iter()
            .map(|offset| LegalEntry {
                address: base + *offset as u64,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    }
}

fn allocation(target: u64, page: u64, candidates: usize) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(page, 4096)],
        preferred_address: Some(target),
        max_candidates: candidates,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    }
}

fn emission(hook: u64, occupied: Vec<AddressRange>) -> ArtifactEmission {
    ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            SavedExtendedStateLayout::describe_target_fxsave64(),
            7,
        )
        .expect("declared FXSAVE target shape"),
        SymbolicHook {
            identity: 11,
            address: Some(hook),
        },
        occupied,
    )
}

fn search() -> SearchPolicy {
    SearchPolicy {
        tactics: TacticPolicy::GeneralizedPunOnly,
        max_upstream_bytes: 0,
        max_displaced_bytes: 2,
        max_sites: 1,
    }
}

fn budget(joint: usize) -> AdjacentB2Budget {
    AdjacentB2Budget {
        max_continuations: joint,
        bundle: BundleBudget {
            max_steps: 2,
            max_mappings: 2,
            max_virtual_bytes: 8192,
            max_backing_bytes: 8192,
            max_virtual_span: 1 << 31,
        },
    }
}

#[derive(Clone)]
struct Fixture {
    base: u64,
    code: Vec<u8>,
    entries: LegalEntrySet,
    lower: AllocationPolicy,
    upper: AllocationPolicy,
    emission: ArtifactEmission,
}

impl Fixture {
    fn with_source(base: u64, code: &[u8], heads: &[usize]) -> Self {
        Self {
            base,
            code: code.to_vec(),
            entries: entries(base, code.len(), heads),
            lower: allocation(LOW, LOW, 1),
            upper: allocation(H128, H0, 2),
            emission: emission(
                base + 4096,
                vec![
                    range(base & !4095, 4096),
                    range((base & !4095) + 4096, 4096),
                ],
            ),
        }
    }

    fn primary() -> Self {
        Self::with_source(B, PRIMARY, &[0, 2, 4, 10])
    }

    fn scope(&self) -> AddressRange {
        range(self.base, self.code.len())
    }

    fn site(&self, upper: bool) -> PlanningSite<'_> {
        let logical_pc = self.base + if upper { 2 } else { 0 };
        PlanningSite {
            identity: identity(),
            code: &self.code,
            base_address: self.base,
            function: self.scope(),
            block: range(logical_pc, 2),
            logical_pc,
            entries: &self.entries,
            semantics: HookSemantics::Observe,
            allocation: if upper { &self.upper } else { &self.lower },
            search: search(),
        }
    }

    fn sites(&self) -> [PlanningSite<'_>; 2] {
        [self.site(false), self.site(true)]
    }

    fn snapshot(&self) -> ExpectedBytes {
        ExpectedBytes {
            address: self.base,
            bytes: self.code.clone(),
        }
    }

    fn empty(&self) -> Composition {
        Composition::new(identity(), vec![self.snapshot()]).expect("real original composition")
    }
}

fn checked_pair(
    sites: [PlanningSite<'_>; 2],
    emission: &ArtifactEmission,
    predecessor: &Composition,
    pending: &[AddressRange],
    budget: AdjacentB2Budget,
) -> Result<AdjacentB2ArtifactPlan, AdjacentB2Failure> {
    let before = predecessor.clone();
    let result =
        plan_adjacent_b2_with_emission_after(sites, emission, predecessor, pending, budget);
    assert_eq!(
        predecessor, &before,
        "success and every failure preserve the complete predecessor"
    );
    result
}

fn run(
    f: &Fixture,
    predecessor: &Composition,
    pending: &[AddressRange],
    joint: usize,
) -> Result<AdjacentB2ArtifactPlan, AdjacentB2Failure> {
    checked_pair(f.sites(), &f.emission, predecessor, pending, budget(joint))
}

fn failure(result: Result<AdjacentB2ArtifactPlan, AdjacentB2Failure>) -> AdjacentB2Failure {
    match result {
        Err(failure) => failure,
        Ok(_) => panic!("the specified rejection must not return a partial or complete pair"),
    }
}

fn counts(upper: usize, lower: usize, joint: usize) -> PairCounts {
    PairCounts {
        upper,
        lower,
        joint,
    }
}

fn assert_evidence(evidence: &PairEvidence, base: u64, expected: PairCounts, accepted: bool) {
    assert_eq!(evidence.lower_pc, base);
    assert_eq!(evidence.upper_pc, base + 2);
    assert_eq!(evidence.counts, expected);
    assert_eq!(evidence.accepted, accepted);
    assert!(!evidence.classification_complete);
    let mut previous = counts(0, 0, 0);
    for event in &evidence.events {
        assert_eq!(
            event.counters_before, previous,
            "chronological counter continuity"
        );
        let mut next = previous;
        match event.stage {
            PairStage::UpperLeaf if event.search.is_some() => next.upper += 1,
            PairStage::LowerSchedule => next.joint += 1,
            PairStage::LowerLeaf => next.lower += 1,
            _ => {}
        }
        assert_eq!(
            event.counters_after, next,
            "each exact call/scope spends its own debit"
        );
        if event.stage == PairStage::UpperLeaf && event.search.is_none() {
            assert_eq!(
                event.outcome,
                PairOutcome::Refused(Refusal::AllocationUnavailable)
            );
            assert_eq!(
                event.counters_before, event.counters_after,
                "upper-window derivation refusal precedes every kernel debit"
            );
        } else if matches!(event.stage, PairStage::UpperLeaf | PairStage::LowerLeaf) {
            let leaf = event
                .search
                .as_ref()
                .expect("complete exact-target kernel evidence");
            assert!(!leaf.classification_complete);
            for run in leaf
                .runs
                .iter()
                .filter(|run| run.domain == SearchDomain::SelectedImages)
            {
                assert_eq!(
                    run.examined, 1,
                    "one exact-target call, not a nested address search"
                );
            }
        } else {
            assert!(event.search.is_none());
        }
        previous = next;
    }
    assert_eq!(previous, expected);
}

fn at(evidence: &PairEvidence, stage: PairStage) -> Vec<&PairEvent> {
    evidence
        .events
        .iter()
        .filter(|event| event.stage == stage)
        .collect()
}

fn assert_local_refusal(
    evidence: &PairEvidence,
    stage: PairStage,
    reason: Refusal,
    after: PairCounts,
) {
    let event = evidence
        .events
        .iter()
        .find(|event| {
            event.stage == stage
                && event.counters_after == after
                && event.outcome == PairOutcome::Refused(reason.clone())
        })
        .expect("exact reached refusal and cumulative debit must survive");
    assert_eq!(event.outcome, PairOutcome::Refused(reason));
}

fn assert_preflight(
    result: Result<AdjacentB2ArtifactPlan, AdjacentB2Failure>,
    eligibility: PairEligibility,
    reason: Refusal,
) {
    let failure = failure(result);
    assert_eq!(failure.stop, PairStop::Eligibility(eligibility));
    assert_eq!(failure.reason, reason);
    assert_eq!(failure.stage, PairStage::Preflight);
    assert_eq!(failure.evidence.counts, counts(0, 0, 0));
    assert!(!failure.evidence.accepted);
    assert!(!failure.evidence.classification_complete);
    assert!(failure.evidence.upper_schedule.is_none());
    assert!(failure.evidence.lower_schedules.is_empty());
    assert!(failure.evidence.events.iter().all(|event| {
        event.stage == PairStage::Preflight
            && event.search.is_none()
            && event.counters_before == counts(0, 0, 0)
            && event.counters_after == counts(0, 0, 0)
    }));
    assert_eq!(failure.unvisited_target, None);
}

fn public_singleton(
    site: PlanningSite<'_>,
    emission: &ArtifactEmission,
    predecessor: &Composition,
    target: u64,
) -> ArtifactPlan {
    // The named target is an independent singleton control, with the frozen
    // complete permit and unchanged image cap. There is no target retry loop.
    let mut allocation = site.allocation.clone();
    allocation.preferred_address = Some(target);
    let selected = PlanningSite {
        allocation: &allocation,
        ..site
    };
    let before = predecessor.clone();
    let plan = engine::plan_with_emission_after(
        &ArtifactRequest {
            site: selected,
            emission,
        },
        predecessor,
        &allocation,
        EnginePolicy {
            forced: Some(Tactic::GeneralizedPun),
            ..EnginePolicy::default()
        },
    )
    .expect("mandatory real public singleton control; a failed positive blocks acceptance");
    assert_eq!(predecessor, &before);
    assert_eq!(plan.images().count(), 1);
    assert_eq!(plan.images().next().unwrap().address(), target);
    assert_eq!(plan.source_steps().len(), 1);
    plan
}

fn append(predecessor: &Composition, artifact: &ArtifactPlan) -> Composition {
    let mut current = predecessor.clone();
    for step in artifact.source_steps() {
        current.append(step).expect("real checked singleton append");
    }
    current
}

fn artifact_equal(actual: &ArtifactPlan, expected: &ArtifactPlan) {
    assert_eq!(
        actual.source_steps(),
        expected.source_steps(),
        "all checked plan fields"
    );
    let left: Vec<_> = actual.images().collect();
    let right: Vec<_> = expected.images().collect();
    assert_eq!(left.len(), right.len());
    for (a, b) in left.iter().zip(&right) {
        assert_eq!(a.address(), b.address());
        assert_eq!(a.bytes(), b.bytes());
        assert_eq!(a.entry_routes(), b.entry_routes());
        assert_eq!(a.instruction_boundaries(), b.instruction_boundaries());
        assert_eq!(a.program_counter_mappings(), b.program_counter_mappings());
        assert_eq!(
            a.metadata(),
            b.metadata(),
            "complete operand ledger and outstanding requirements"
        );
        assert!(!a.metadata().qualification_complete());
    }
    assert!(!actual.qualification_complete());
}

fn assert_pair_matches(
    f: &Fixture,
    predecessor: &Composition,
    pair: &AdjacentB2ArtifactPlan,
    upper_target: u64,
    lower_target: u64,
) -> Composition {
    let upper = public_singleton(f.site(true), &f.emission, predecessor, upper_target);
    let after_upper = append(predecessor, &upper);
    let lower = public_singleton(f.site(false), &f.emission, &after_upper, lower_target);
    artifact_equal(&pair.members()[0], &upper);
    artifact_equal(&pair.members()[1], &lower);
    assert_eq!(pair.logical_pcs(), [f.base + 2, f.base]);
    assert!(!pair.qualification_complete());
    for (member, pc) in pair.members().iter().zip([f.base + 2, f.base]) {
        assert_eq!(member.source_steps().len(), 1);
        assert_eq!(member.images().count(), 1);
        let parts = member.source_steps()[0].parts();
        assert_eq!(parts.logical_pc, pc);
        assert_eq!(parts.physical_pc, pc);
        assert_eq!(parts.identity, identity());
        assert_eq!(parts.entries, f.entries);
        assert_eq!(parts.dependencies, [f.scope()]);
        assert_eq!(parts.displaced, range(pc, 2));
        assert_eq!(parts.writes.len(), 1);
        assert_eq!(parts.writes[0].bytes.len(), 2);
        let PlanKind::GeneralizedPun(pun) = &parts.kind else {
            panic!("forced B2")
        };
        assert_eq!(pun.instruction_len, 2);
        assert_eq!(pun.consumed, range(pc, 5));
        assert_eq!(pun.store, parts.writes[0]);
        assert_eq!(parts.allocations.len(), 1);
        assert_eq!(parts.allocations[0].range.len(), 4096);
        assert_eq!(parts.allocations[0].alignment, 4096);
        let ArtifactMetrics::Single(metrics) = member.metrics() else {
            panic!("pair metrics must not masquerade as Engine")
        };
        assert_eq!(metrics.allocation_attempts, 1);
        assert_eq!(metrics.displaced_bytes, 2);
        assert_eq!(metrics.upstream_bytes, 0);
        assert_eq!(metrics.prefix_instructions, 0);
    }
    assert_eq!(
        pair.members()[0].source_steps()[0].parts().reads[0].bytes,
        predecessor
            .planning_overlay(identity(), f.base, &f.code)
            .unwrap()
    );
    assert_eq!(
        pair.members()[1].source_steps()[0].parts().reads[0].bytes,
        after_upper
            .planning_overlay(identity(), f.base, &f.code)
            .unwrap()
    );
    assert_ne!(
        pair.members()[1].source_steps()[0].parts().reads[0].bytes,
        f.code
    );
    let final_state = append(&after_upper, &lower);
    let mut replay = predecessor.clone();
    for member in pair.members() {
        for step in member.source_steps() {
            replay.append(step).unwrap();
        }
    }
    assert_eq!(replay, final_state);
    final_state
}

fn page_proof(returned: usize, omitted: Option<u64>, walks: &[(u64, usize)]) -> CandidateProof {
    CandidateProof::PageBoundary {
        returned,
        omitted,
        walks: walks
            .iter()
            .enumerate()
            .map(
                |(range_index, &(finite_slots, examined))| PageWalkEvidence {
                    range_index,
                    finite_slots,
                    examined,
                },
            )
            .collect(),
    }
}

fn assert_primary_schedules(evidence: &PairEvidence) {
    let upper = evidence.upper_schedule.as_ref().unwrap();
    assert_eq!(upper.window, range(H0, 256));
    assert_eq!(upper.targets, [H128, H0]);
    assert_eq!(upper.upper_ordinal, None);
    assert_eq!(upper.upper_target, None);
    assert_eq!(upper.proof, page_proof(2, None, &[(1, 1)]));
    assert_eq!(evidence.lower_schedules.len(), 2);
    let first = &evidence.lower_schedules[0];
    assert_eq!(first.window, range(0x7980_effe, 256));
    assert!(first.targets.is_empty());
    assert_eq!(first.upper_ordinal, Some(0));
    assert_eq!(first.upper_target, Some(H128));
    assert_eq!(first.proof, page_proof(0, None, &[(0, 0)]));
    let second = &evidence.lower_schedules[1];
    assert_eq!(second.window, range(0x7900_effe, 256));
    assert_eq!(second.targets, [LOW]);
    assert_eq!(second.upper_ordinal, Some(1));
    assert_eq!(second.upper_target, Some(H0));
    assert_eq!(second.proof, page_proof(1, None, &[(1, 1)]));
}

fn primary_memory() -> BundleMemory {
    BundleMemory {
        mappings: 2,
        virtual_pages: 2,
        backing_pages: 2,
        virtual_bytes: 8192,
        backing_bytes: 8192,
        virtual_span: 0x6740_9000,
    }
}

fn upper_fit_fixture() -> Fixture {
    let mut f = Fixture::with_source(0x1000_0679, PRIMARY, &[0, 2, 4, 10]);
    f.upper = allocation(0x11c0_6f80, H0, 2);
    f.lower = allocation(0x7980_f000, 0x7980_f000, 1);
    f
}

fn same_page_fixture() -> Fixture {
    let mut f = Fixture::with_source(
        0x3000_0000,
        &[0x75, 0x02, 0x75, 0x00, 0xe9, 0x00, 0xe9, 0x00, 0x00, 0xc3],
        &[0, 2, 4, 9],
    );
    f.upper = allocation(0x1900_e907, 0x1900_e000, 1);
    f.lower = allocation(0x1900_e907, 0x1900_e000, 1);
    f
}

fn same_page_positive_setup(f: &Fixture, predecessor: &Composition) {
    let upper = public_singleton(f.site(true), &f.emission, predecessor, 0x1900_e907);
    let after_upper = append(predecessor, &upper);
    let lower = public_singleton(f.site(false), &f.emission, &after_upper, 0x1900_e907);
    assert_eq!(
        upper.source_steps()[0].parts().allocations,
        lower.source_steps()[0].parts().allocations
    );
    assert_eq!(
        lower.source_steps()[0].parts().reads[0].bytes,
        after_upper.final_bytes()[0].bytes
    );
}

fn remote_predecessor(
    mut f: Fixture,
    lower_conflict: bool,
) -> (Fixture, Composition, ArtifactPlan) {
    let prior_base = if lower_conflict {
        0xe871_5ffb
    } else {
        0x812f_dffb
    };
    let prior_target = if lower_conflict { 0x7901_f000 } else { H0 };
    let prior_code = [0x75, 0x00, 0x90, 0x90, 0x90, 0xc3];
    let prior_entries = entries(prior_base, prior_code.len(), &[0, 2, 3, 4, 5]);
    let prior_allocation = allocation(prior_target, prior_target, 1);
    let mut occupied = f.emission.occupied().to_vec();
    occupied.push(range(prior_base & !4095, 8192));
    f.emission = emission(B + 4096, occupied.clone());
    let original = Composition::new(
        identity(),
        vec![
            f.snapshot(),
            ExpectedBytes {
                address: prior_base,
                bytes: prior_code.to_vec(),
            },
        ],
    )
    .unwrap();
    let prior_site = PlanningSite {
        identity: identity(),
        code: &prior_code,
        base_address: prior_base,
        function: range(prior_base, prior_code.len()),
        block: range(prior_base, 2),
        logical_pc: prior_base,
        entries: &prior_entries,
        semantics: HookSemantics::Observe,
        allocation: &prior_allocation,
        search: search(),
    };
    let prior = public_singleton(prior_site, &f.emission, &original, prior_target);
    let predecessor = append(&original, &prior);
    if lower_conflict {
        occupied.push(range(prior_target, 4096));
        f.emission = emission(B + 4096, occupied);
        f.upper.preferred_address = Some(0x11c0_7001);
        f.lower.preferred_address = Some(0x7901_f000);
        f.lower.ranges = vec![range(0x7901_f000, 4096), range(LOW, 4096)];
    }
    // UpperAppend's hostile variant deliberately omits the known generated page
    // only. All original and hook occupancy remains declared.
    (f, predecessor, prior)
}

fn positive_predecessor() -> (Fixture, Composition, ArtifactPlan) {
    let mut f = Fixture::with_source(
        B,
        &[
            0x75, 0x02, 0x75, 0x00, 0x69, 0xc0, 0x01, 0, 0, 0, 0xc3, 0x75, 0x00, 0x69, 0xc0, 0x02,
            0, 0, 0, 0xc3,
        ],
        &[0, 2, 4, 10, 11, 13, 19],
    );
    let allocation = allocation(0x12c0_7009, 0x12c0_7000, 1);
    let selected = PlanningSite {
        logical_pc: 0x1000_0704,
        block: range(0x1000_0704, 2),
        allocation: &allocation,
        ..f.site(false)
    };
    let prior = public_singleton(selected, &f.emission, &f.empty(), 0x12c0_7009);
    let predecessor = append(&f.empty(), &prior);
    let mut occupied = f.emission.occupied().to_vec();
    occupied.push(range(0x12c0_7000, 4096));
    f.emission = emission(B + 4096, occupied);
    (f, predecessor, prior)
}

#[test]
fn adjacent_b2_actual_images_and_pair() {
    let f = Fixture::primary();
    let predecessor = f.empty();
    let h128 = public_singleton(f.site(true), &f.emission, &predecessor, H128);
    let h0 = public_singleton(f.site(true), &f.emission, &predecessor, H0);
    assert_eq!(
        h128.source_steps()[0].parts().allocations[0].range,
        range(H0, 4096)
    );
    assert_eq!(
        h0.source_steps()[0].parts().allocations[0].range,
        range(H0, 4096)
    );
    let pair = run(&f, &predecessor, &[], 2).expect("frozen primary pair must succeed");
    let final_state = assert_pair_matches(&f, &predecessor, &pair, H0, LOW);
    assert_eq!(
        final_state.final_bytes(),
        &[ExpectedBytes {
            address: B,
            bytes: vec![0xe9, 0x02, 0xe9, 0x00, 0x69, 0xc0, 0x01, 0, 0, 0, 0xc3]
        }]
    );
    assert_eq!(final_state.locks(), &[range(B, 7)]);
    assert_eq!(final_state.originals(), &[f.snapshot()]);
    assert_eq!(pair.memory(), primary_memory());
    assert_evidence(pair.evidence(), B, counts(2, 1, 2), true);
    assert_primary_schedules(pair.evidence());
    let schedules = at(pair.evidence(), PairStage::LowerSchedule);
    assert_eq!(schedules.len(), 2);
    assert_eq!(schedules[0].outcome, PairOutcome::EmptySchedule);
    assert_eq!(schedules[0].counters_after, counts(1, 0, 1));
    assert_eq!(schedules[1].outcome, PairOutcome::LocalAccepted);
    assert_eq!(schedules[1].counters_after, counts(2, 0, 2));
    assert_eq!(at(pair.evidence(), PairStage::Aggregate).len(), 1);
    assert_eq!(
        at(pair.evidence(), PairStage::Aggregate)[0].outcome,
        PairOutcome::LocalAccepted
    );
    for member in pair.members() {
        let image = member.images().next().unwrap();
        for required in [
            ArtifactRequirement::ArtifactIdentityAndAddressBinding,
            ArtifactRequirement::TargetCpuAndStateAtEntry,
            ArtifactRequirement::OriginalDynamicRelocationOwnership,
            ArtifactRequirement::OriginalImmediatePointerProvenance,
            ArtifactRequirement::HookAbiAndReadiness(11),
            ArtifactRequirement::GeneratedUnwindInformation,
            ArtifactRequirement::OriginalCodeAsDataContract,
        ] {
            assert!(image.metadata().requirements().contains(&required));
        }
        assert!(!image.metadata().fields().is_empty());
        assert!(
            image
                .metadata()
                .fields()
                .iter()
                .all(|field| field.bias_domain == 7)
        );
    }
}

#[test]
fn adjacent_b2_cap_boundaries() {
    // The complete frozen zero/one/two table, with preflight still first.
    for (upper, lower, joint, stop) in [
        (0, 1, 0, PairStop::UpperImagesBudget),
        (2, 0, 2, PairStop::LowerImagesBudget),
        (2, 1, 0, PairStop::JointContinuationsBudget),
        (1, 1, 2, PairStop::InvalidBudgetRelation),
    ] {
        let mut f = Fixture::primary();
        f.upper.max_candidates = upper;
        f.lower.max_candidates = lower;
        let error = failure(run(&f, &f.empty(), &[], joint));
        assert_eq!(error.stop, stop);
        assert_eq!(
            error.reason,
            if joint > upper {
                Refusal::InvalidRange
            } else {
                Refusal::AllocationUnavailable
            }
        );
        assert_eq!(error.stage, PairStage::Preflight);
        assert_evidence(&error.evidence, B, counts(0, 0, 0), false);
        assert!(error.evidence.upper_schedule.is_none());
        assert!(error.evidence.lower_schedules.is_empty());
    }
    let mut f = Fixture::primary();
    f.upper.max_candidates = 1;
    let error = failure(run(&f, &f.empty(), &[], 1));
    assert_eq!(error.stop, PairStop::UpperScheduleBudget);
    assert_eq!(error.reason, Refusal::AllocationUnavailable);
    assert_eq!(error.unvisited_target, Some(H0));
    assert_evidence(&error.evidence, B, counts(1, 0, 1), false);
    assert_eq!(
        error.evidence.upper_schedule.as_ref().unwrap().targets,
        [H128]
    );
    assert_eq!(
        error.evidence.upper_schedule.as_ref().unwrap().proof,
        page_proof(1, Some(H0), &[(1, 1)])
    );
    assert_eq!(
        at(&error.evidence, PairStage::LowerSchedule)[0].outcome,
        PairOutcome::EmptySchedule
    );
    let f = Fixture::primary();
    let error = failure(run(&f, &f.empty(), &[], 1));
    assert_eq!(error.stop, PairStop::JointContinuationsBudget);
    assert_eq!(error.unvisited_target, Some(H0));
    assert_evidence(&error.evidence, B, counts(1, 0, 1), false);
    assert_eq!(at(&error.evidence, PairStage::UpperLeaf).len(), 1);
    let pair = run(&f, &f.empty(), &[], 2).expect("primary-positive row");
    assert_evidence(pair.evidence(), B, counts(2, 1, 2), true);

    let fit = upper_fit_fixture();
    let pair =
        run(&fit, &fit.empty(), &[], 1).expect("first-upper-fit-refuses then mandatory success");
    assert_evidence(pair.evidence(), fit.base, counts(2, 1, 1), true);
    assert_local_refusal(
        pair.evidence(),
        PairStage::UpperLeaf,
        Refusal::AllocationUnavailable,
        counts(1, 0, 0),
    );

    let (f, predecessor, _) = remote_predecessor(Fixture::primary(), true);
    let error = failure(run(&f, &predecessor, &[], 2));
    assert_eq!(error.stop, PairStop::LowerImagesBudget);
    assert_eq!(error.unvisited_target, Some(H0));
    assert_evidence(&error.evidence, B, counts(1, 1, 1), false);
    assert_local_refusal(
        &error.evidence,
        PairStage::LowerLeaf,
        Refusal::AllocationUnavailable,
        counts(1, 1, 1),
    );

    let (f, predecessor, _) = remote_predecessor(Fixture::primary(), false);
    let error = failure(run(&f, &predecessor, &[], 2));
    assert_eq!(error.stop, PairStop::Exhausted);
    assert_eq!(error.reason, Refusal::OwnershipConflict);
    assert_eq!(error.stage, PairStage::UpperAppend);
    assert_evidence(&error.evidence, B, counts(2, 0, 0), false);
    assert_eq!(at(&error.evidence, PairStage::UpperAppend).len(), 2);

    let f = Fixture::primary();
    let error = failure(run(&f, &f.empty(), &[range(B + 4, 6)], 2));
    assert_eq!(error.stop, PairStop::Exhausted);
    assert_eq!(error.reason, Refusal::OwnershipConflict);
    assert_eq!(error.stage, PairStage::UpperPending);
    assert_evidence(&error.evidence, B, counts(2, 0, 0), false);

    let f = same_page_fixture();
    let predecessor = f.empty();
    same_page_positive_setup(&f, &predecessor);
    let error = failure(run(&f, &predecessor, &[], 1));
    assert_eq!(error.stop, PairStop::LowerImagesBudget);
    assert_eq!(error.stage, PairStage::LowerSchedule);
    assert_eq!(error.reason, Refusal::AllocationUnavailable);
    assert_eq!(error.unvisited_target, Some(0x1900_e905));
    assert_evidence(&error.evidence, f.base, counts(1, 1, 1), false);
    assert_local_refusal(
        &error.evidence,
        PairStage::LowerAppend,
        Refusal::OwnershipConflict,
        counts(1, 1, 1),
    );
    assert_eq!(
        error.evidence.upper_schedule.as_ref().unwrap().proof,
        page_proof(1, None, &[(1, 1)])
    );
    let lower = &error.evidence.lower_schedules[0];
    assert_eq!(lower.window, range(0x1900_e905, 256));
    assert_eq!(lower.targets, [0x1900_e907]);
    assert_eq!(lower.proof, page_proof(1, Some(0x1900_e905), &[(1, 1)]));

    let mut f = Fixture::primary();
    f.upper.max_candidates = usize::MAX;
    f.lower.max_candidates = usize::MAX;
    let error = failure(run(&f, &f.empty(), &[], usize::MAX));
    assert_eq!(
        error.stop,
        PairStop::Eligibility(PairEligibility::BudgetShape)
    );
    assert_eq!(error.reason, Refusal::InvalidRange);
    assert_eq!(error.stage, PairStage::Preflight);
    assert_eq!(error.evidence.counts, counts(0, 0, 0));
    assert!(error.evidence.upper_schedule.is_none());
    assert!(error.evidence.lower_schedules.is_empty());
}

#[test]
fn adjacent_b2_no_cumulative_reset() {
    let fit = upper_fit_fixture();
    let predecessor = fit.empty();
    let upper = public_singleton(fit.site(true), &fit.emission, &predecessor, H0);
    let after_upper = append(&predecessor, &upper);
    public_singleton(fit.site(false), &fit.emission, &after_upper, 0x7980_f000);
    let pair = run(&fit, &predecessor, &[], 1).expect("frozen upper-fit positive");
    let final_state = assert_pair_matches(&fit, &predecessor, &pair, H0, 0x7980_f000);
    assert_eq!(
        final_state.final_bytes()[0].bytes,
        [0xe9, 0x82, 0xe9, 0x80, 0x69, 0xc0, 0x01, 0, 0, 0, 0xc3]
    );
    assert_evidence(pair.evidence(), fit.base, counts(2, 1, 1), true);
    assert_local_refusal(
        pair.evidence(),
        PairStage::UpperLeaf,
        Refusal::AllocationUnavailable,
        counts(1, 0, 0),
    );
    assert_eq!(
        at(pair.evidence(), PairStage::UpperLeaf)[0].upper_target,
        Some(0x11c0_6f80)
    );
    let public_search = crate::quiescent::plan_install_with_emission(&ArtifactRequest {
        site: fit.site(true),
        emission: &fit.emission,
    })
    .expect("unchanged public singleton must retain its first fit refusal before h0");
    let ArtifactMetrics::Single(public_metrics) = public_search.metrics() else {
        panic!("singleton metrics")
    };
    assert_eq!(public_search.images().next().unwrap().address(), H0);
    assert_eq!(
        at(pair.evidence(), PairStage::UpperLeaf)[0]
            .search
            .as_ref()
            .unwrap()
            .refusals,
        public_metrics.search.refusals,
        "retain the actual typed kernel refusal without guessing its resource/address subcase"
    );

    let (mut f, predecessor, prior) = remote_predecessor(Fixture::primary(), true);
    assert_eq!(
        prior.source_steps()[0].parts().allocations[0].range,
        range(0x7901_f000, 4096)
    );
    let error = failure(run(&f, &predecessor, &[], 2));
    assert_eq!(error.stop, PairStop::LowerImagesBudget);
    assert_evidence(&error.evidence, B, counts(1, 1, 1), false);
    assert_eq!(at(&error.evidence, PairStage::UpperLeaf).len(), 1);
    assert_local_refusal(
        &error.evidence,
        PairStage::LowerLeaf,
        Refusal::AllocationUnavailable,
        counts(1, 1, 1),
    );
    f.lower.max_candidates = 2; // Exact second frozen row, not a retry selected by outcome.
    let pair = run(&f, &predecessor, &[], 2).expect("frozen cumulative lower cap2 positive");
    assert_pair_matches(&f, &predecessor, &pair, H0, LOW);
    assert_evidence(pair.evidence(), B, counts(2, 2, 2), true);
    let lower_calls = at(pair.evidence(), PairStage::LowerLeaf);
    assert_eq!(lower_calls.len(), 2);
    assert_eq!(lower_calls[0].lower_target, Some(0x7901_f000));
    assert_eq!(lower_calls[0].upper_target, Some(0x11c0_7001));
    assert_eq!(
        lower_calls[0].outcome,
        PairOutcome::Refused(Refusal::AllocationUnavailable)
    );
    assert_eq!(lower_calls[1].lower_target, Some(LOW));
    assert_eq!(lower_calls[1].upper_target, Some(H0));
    assert_eq!(lower_calls[1].outcome, PairOutcome::LocalAccepted);
    assert_eq!(lower_calls[1].counters_before, counts(2, 1, 2));
    assert_eq!(
        pair.evidence().lower_schedules[0].proof,
        page_proof(1, None, &[(1, 1), (0, 0)])
    );
    assert_eq!(
        pair.evidence().lower_schedules[1].proof,
        page_proof(1, None, &[(0, 0), (1, 1)])
    );

    let mut duplicate = Fixture::primary();
    duplicate.upper.ranges.push(duplicate.upper.ranges[0]);
    duplicate.lower.ranges.push(duplicate.lower.ranges[0]);
    let pair = run(&duplicate, &duplicate.empty(), &[], 2)
        .expect("duplicate walks preserve primary positive");
    assert_evidence(pair.evidence(), B, counts(2, 1, 2), true);
    assert_eq!(
        pair.evidence().upper_schedule.as_ref().unwrap().proof,
        page_proof(2, None, &[(1, 1), (1, 1)])
    );
    assert_eq!(
        pair.evidence().lower_schedules[0].proof,
        page_proof(0, None, &[(0, 0), (0, 0)])
    );
    assert_eq!(
        pair.evidence().lower_schedules[1].proof,
        page_proof(1, None, &[(1, 1), (1, 1)])
    );

    // In this exact domain, distinct upper targets change byte 2 of the lower
    // rel32. The resulting 256-address windows differ by 65536 or more. A
    // repeated lower address across these overlays is therefore unreachable;
    // no fabricated owner/overlay is used to claim that case was exercised.
    for first in 0_u64..256 {
        for second in first + 1..256 {
            let left = range(0x7900_effe + (first << 16), 256);
            let right = range(0x7900_effe + (second << 16), 256);
            assert!(!left.overlaps(right));
        }
    }
}

#[test]
fn adjacent_b2_original_current_identity() {
    let (f, predecessor, prior) = positive_predecessor();
    let before = predecessor.clone();
    let pair = run(&f, &predecessor, &[], 2).expect("frozen real predecessor positive");
    let current = assert_pair_matches(&f, &predecessor, &pair, H0, LOW);
    assert_eq!(predecessor, before);
    assert_eq!(pair.memory(), primary_memory());
    assert_eq!(pair.members().len(), 2);
    assert_eq!(
        &current.final_bytes()[0].bytes[11..],
        &predecessor.final_bytes()[0].bytes[11..]
    );
    assert_ne!(&current.final_bytes()[0].bytes[11..13], &f.code[11..13]);
    assert_eq!(
        prior.source_steps()[0].parts().allocations[0].range,
        range(0x12c0_7000, 4096)
    );
    assert_eq!(current.originals(), &[f.snapshot()]);
    assert_evidence(pair.evidence(), B, counts(2, 1, 2), true);

    for changed in [
        CodeIdentity {
            generation: 2,
            ..identity()
        },
        CodeIdentity {
            mapping: 2,
            ..identity()
        },
        CodeIdentity {
            source: SourceIdentity([0xa4; 32]),
            ..identity()
        },
    ] {
        let mut sites = f.sites();
        sites[0].identity = changed;
        assert_preflight(
            checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
            PairEligibility::OriginalAuthentication,
            Refusal::StaleGeneration,
        );
        let mut sites = f.sites();
        sites[1].identity = changed;
        assert_preflight(
            checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
            PairEligibility::CommonIdentity,
            Refusal::StaleGeneration,
        );
    }
    let current_bytes = predecessor.final_bytes()[0].bytes.clone();
    let mut sites = f.sites();
    sites[0].code = &current_bytes;
    sites[1].code = &current_bytes;
    assert_preflight(
        checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
        PairEligibility::OriginalAuthentication,
        Refusal::ExpectedBytesChanged,
    );
    let mut changed_code = f.code.clone();
    changed_code[7] ^= 1;
    let mut sites = f.sites();
    sites[0].code = &changed_code;
    sites[1].code = &changed_code;
    assert_preflight(
        checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
        PairEligibility::OriginalAuthentication,
        Refusal::ExpectedBytesChanged,
    );
    let mut changed_entries = f.entries.clone();
    changed_entries.provenance = EntryProvenance::Declared("different declaration".into());
    for field in 0..5 {
        let mut sites = f.sites();
        match field {
            0 => sites[1].base_address += 1,
            1 => sites[1].code = &changed_code,
            2 => sites[1].function = range(B, f.code.len() - 1),
            3 => sites[1].entries = &changed_entries,
            4 => sites[1].code = &f.code[..f.code.len() - 1],
            _ => unreachable!(),
        }
        assert_preflight(
            checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
            PairEligibility::IncompatibleView,
            Refusal::InvalidPlan,
        );
    }
    // The lower read must come from the accepted h0 overlay, not the discarded
    // h128 trial, while retaining every byte of the real prior edit.
    let failed_trial = public_singleton(f.site(true), &f.emission, &predecessor, H128);
    let failed_overlay = append(&predecessor, &failed_trial);
    assert_ne!(
        pair.members()[1].source_steps()[0].parts().reads[0].bytes,
        failed_overlay.final_bytes()[0].bytes
    );
}

#[test]
fn adjacent_b2_entry_and_domain_boundaries() {
    // Each role independently covers every admitted ordinary condition code.
    for role in 0..2 {
        for opcode in 0x70..=0x7f {
            let mut f = Fixture::primary();
            f.code[role * 2] = opcode;
            let predecessor = f.empty();
            let pair = run(&f, &predecessor, &[], 2)
                .expect("all sixteen forward Jcc conditions are mandatory positives");
            assert_pair_matches(&f, &predecessor, &pair, H0, LOW);
            assert_evidence(pair.evidence(), B, counts(2, 1, 2), true);
        }
    }
    let f = Fixture::primary();
    let predecessor = f.empty();
    for upper_pc in [B, B + 1, B + 4] {
        let mut sites = f.sites();
        sites[1].logical_pc = upper_pc;
        sites[1].block = range(upper_pc, 2);
        assert_preflight(
            checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
            PairEligibility::PairGeometry,
            Refusal::InvalidRange,
        );
    }
    assert_preflight(
        checked_pair(
            [f.site(true), f.site(false)],
            &f.emission,
            &predecessor,
            &[],
            budget(2),
        ),
        PairEligibility::PairGeometry,
        Refusal::InvalidRange,
    );
    let mut sites = f.sites();
    sites[0].block = range(B, 4);
    assert_preflight(
        checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
        PairEligibility::PairGeometry,
        Refusal::InvalidRange,
    );
    let mut sites = f.sites();
    sites[0].function = range(B, PRIMARY.len() - 1);
    sites[1].function = sites[0].function;
    assert_preflight(
        checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
        PairEligibility::PairGeometry,
        Refusal::InvalidRange,
    );
    let mut wider_entries = f.entries.clone();
    wider_entries.scope = range(B, PRIMARY.len() + 1);
    let mut sites = f.sites();
    sites[0].entries = &wider_entries;
    sites[1].entries = &wider_entries;
    assert_preflight(
        checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
        PairEligibility::PairGeometry,
        Refusal::InvalidRange,
    );
    let mut sites = f.sites();
    sites[0].logical_pc = u64::MAX;
    sites[1].logical_pc = 1;
    assert_preflight(
        checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
        PairEligibility::PairGeometry,
        Refusal::InvalidRange,
    );
    let mut sites = f.sites();
    sites[0].base_address = u64::MAX;
    assert_preflight(
        checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
        PairEligibility::OriginalAuthentication,
        Refusal::InvalidRange,
    );
    assert_eq!(AddressRange::new(u64::MAX, 2), Err(Refusal::InvalidRange));

    for opcode in [0xeb, 0xe0, 0xe1, 0xe2, 0xe3] {
        for role in 0..2 {
            let mut f = Fixture::primary();
            f.code[role * 2] = opcode;
            assert_preflight(
                run(&f, &f.empty(), &[], 2),
                PairEligibility::BranchDomain,
                Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
            );
        }
    }
    for (replacement, heads, eligibility, reason) in [
        (
            &[0x90, 0x90][..],
            &[0, 1, 2, 4, 10][..],
            PairEligibility::BranchDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
        ),
        (
            &[0xc3, 0x90][..],
            &[0, 1, 2, 4, 10][..],
            PairEligibility::BranchDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
        ),
        (
            &[0x66, 0x75, 0x01, 0x90][..],
            &[0, 3, 4, 10][..],
            PairEligibility::OriginalQualification,
            Refusal::NotInstructionHead,
        ),
        (
            &[0x66, 0x66, 0x75, 0x00][..],
            &[0, 4, 10][..],
            PairEligibility::OriginalQualification,
            Refusal::NotInstructionHead,
        ),
    ] {
        let mut code = PRIMARY.to_vec();
        code[..replacement.len()].copy_from_slice(replacement);
        let f = Fixture::with_source(B, &code, heads);
        assert_preflight(run(&f, &f.empty(), &[], 2), eligibility, reason);
    }
    let call = Fixture::with_source(
        B,
        &[0xe8, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0xc3],
        &[0, 5, 6, 7, 8],
    );
    assert_preflight(
        run(&call, &call.empty(), &[], 2),
        PairEligibility::OriginalQualification,
        Refusal::NotInstructionHead,
    );
    for (role, displacement, eligibility, reason) in [
        (
            0,
            0xfe,
            PairEligibility::BranchDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
        ),
        (
            0,
            0xfc,
            PairEligibility::BranchDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
        ),
        (
            0,
            0x00,
            PairEligibility::BranchDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
        ),
        (
            1,
            0xfe,
            PairEligibility::BranchDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
        ),
        (
            1,
            0xfc,
            PairEligibility::BranchDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
        ),
        (
            0,
            0x7f,
            PairEligibility::BranchDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
        ),
        (
            1,
            0x7f,
            PairEligibility::BranchDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires forward two-byte Jcc".into()),
        ),
        (
            0,
            0x03,
            PairEligibility::BranchHead,
            Refusal::NotInstructionHead,
        ),
        (
            1,
            0x01,
            PairEligibility::BranchHead,
            Refusal::NotInstructionHead,
        ),
    ] {
        let mut f = Fixture::primary();
        f.code[role * 2 + 1] = displacement;
        assert_preflight(run(&f, &f.empty(), &[], 2), eligibility, reason);
    }
    let f = Fixture::primary();
    for role in 0..2 {
        let mut sites = f.sites();
        sites[role].semantics = HookSemantics::ReplaceFirst;
        assert_preflight(
            checked_pair(sites, &f.emission, &f.empty(), &[], budget(2)),
            PairEligibility::ObservingDomain,
            Refusal::UnsupportedSemantics("adjacent B2 requires observing hooks".into()),
        );
        for field in 0..7 {
            let mut sites = f.sites();
            match field {
                0 => sites[role].search.max_sites = 0,
                1 => sites[role].search.max_sites = 2,
                2 => sites[role].search.max_upstream_bytes = 1,
                3 => sites[role].search.max_displaced_bytes = 3,
                4 => sites[role].search.tactics = TacticPolicy::RelocationOnly,
                5 => sites[role].search.tactics = TacticPolicy::PrefixPunOnly,
                6 => sites[role].search.tactics = TacticPolicy::PreferGeneralizedPun,
                _ => unreachable!(),
            }
            assert_preflight(
                checked_pair(sites, &f.emission, &f.empty(), &[], budget(2)),
                PairEligibility::SearchDomain,
                Refusal::UnsupportedSemantics("adjacent B2 exact search contract".into()),
            );
        }
    }
    for mutation in 0..11 {
        let mut f = Fixture::primary();
        let (eligibility, reason) = match mutation {
            0 => {
                f.entries.completeness = EntryCompleteness::Complete;
                (
                    PairEligibility::AllHeadDomain,
                    Refusal::UnsupportedSemantics(
                        "adjacent B2 requires all-head entry contract".into(),
                    ),
                )
            }
            1 => {
                f.entries.entries.remove(2);
                (PairEligibility::AllHeadPopulation, Refusal::UnresolvedEntry)
            }
            2 => {
                f.entries.entries.insert(1, f.entries.entries[0]);
                (PairEligibility::AllHeadPopulation, Refusal::UnresolvedEntry)
            }
            3 => {
                f.entries.entries.swap(0, 1);
                (PairEligibility::AllHeadPopulation, Refusal::UnresolvedEntry)
            }
            4 => {
                f.entries.resumes = ResumeObligation::Enumerated(vec![B, B]);
                (PairEligibility::ResumeShape, Refusal::InvalidRange)
            }
            5 => {
                f.entries.resumes = ResumeObligation::Enumerated(vec![B + 2, B]);
                (PairEligibility::ResumeShape, Refusal::InvalidRange)
            }
            6 => {
                f.entries.resumes = ResumeObligation::Unresolved;
                (
                    PairEligibility::OriginalQualification,
                    Refusal::UnresolvedEntry,
                )
            }
            7 => {
                f.entries.resumes = ResumeObligation::Enumerated(vec![B + 1]);
                (
                    PairEligibility::OriginalQualification,
                    Refusal::NotInstructionHead,
                )
            }
            8 => {
                f.entries.completeness = EntryCompleteness::Incomplete;
                (
                    PairEligibility::OriginalQualification,
                    Refusal::UnresolvedEntry,
                )
            }
            9 => {
                f.entries.entries[3].requires_endbr = true;
                (
                    PairEligibility::CetDomain,
                    Refusal::UnsupportedSemantics(
                        "adjacent B2 excludes CET entry requirements".into(),
                    ),
                )
            }
            10 => {
                f.entries.identity.generation += 1;
                (
                    PairEligibility::OriginalQualification,
                    Refusal::StaleGeneration,
                )
            }
            _ => unreachable!(),
        };
        assert_preflight(run(&f, &f.empty(), &[], 2), eligibility, reason);
    }
    let mut resumed = Fixture::primary();
    resumed.entries.resumes = ResumeObligation::Enumerated(vec![B, B + 2, B + 4, B + 10]);
    let pair =
        run(&resumed, &resumed.empty(), &[], 2).expect("canonical enumerated all-head resumes");
    assert_pair_matches(&resumed, &resumed.empty(), &pair, H0, LOW);
    let short = Fixture::with_source(B, &[0x75, 0x02, 0x75, 0x00, 0xc3], &[0, 2, 4]);
    assert_preflight(
        run(&short, &short.empty(), &[], 2),
        PairEligibility::FetchStoreDomain,
        Refusal::NoPatchWindow,
    );
    for base in [0x1000_06fd, 0x1000_06ff] {
        let f = Fixture::with_source(base, PRIMARY, &[0, 2, 4, 10]);
        assert_preflight(
            run(&f, &f.empty(), &[], 2),
            PairEligibility::FetchStoreDomain,
            Refusal::NoPatchWindow,
        );
    }
    // Fixed byte-derived windows, declared before any result is inspected.
    for (base, upper_target, lower_target) in [
        (0x1000_06fc, 0x11c0_7003, 0x7900_f001),
        (0x1000_06fe, 0x11c0_7005, 0x7900_f003),
    ] {
        let mut f = Fixture::with_source(base, PRIMARY, &[0, 2, 4, 10]);
        f.upper.preferred_address = Some(upper_target);
        f.lower.preferred_address = Some(lower_target);
        let predecessor = f.empty();
        public_singleton(f.site(true), &f.emission, &predecessor, upper_target);
        let pair = run(&f, &predecessor, &[], 2)
            .expect("offset60/62 stores remain legal across fetch-line crossings");
        let final_state = assert_pair_matches(&f, &predecessor, &pair, upper_target, lower_target);
        assert_eq!(
            final_state.final_bytes()[0].bytes,
            [0xe9, 0, 0xe9, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3]
        );
        assert_evidence(pair.evidence(), base, counts(1, 1, 1), true);
    }
}

#[test]
fn adjacent_b2_pending_full_ranges() {
    let f = Fixture::primary();
    let predecessor = f.empty();
    for pending in [
        vec![],
        vec![range(B + 7, 4)],
        vec![range(B + 7, 3), range(B + 10, 1)],
    ] {
        let pair = run(&f, &predecessor, &pending, 2)
            .expect("empty and adjacent unclaimed pending positives");
        let final_state = assert_pair_matches(&f, &predecessor, &pair, H0, LOW);
        assert_eq!(final_state.require_unclaimed_ranges(&pending), Ok(()));
        assert_eq!(at(pair.evidence(), PairStage::LowerPending).len(), 1);
        assert_eq!(
            at(pair.evidence(), PairStage::LowerPending)[0].outcome,
            PairOutcome::LocalAccepted
        );
    }
    for pending in [
        vec![range(B, 2)],
        vec![range(B + 1, 1)],
        vec![range(B + 2, 2)],
        vec![range(B + 3, 2)],
        vec![range(B - 1, 2)],
        vec![range(B + 10, 1), range(B + 7, 2)],
        vec![range(B + 7, 3), range(B + 9, 2)],
    ] {
        assert_preflight(
            run(&f, &predecessor, &pending, 2),
            PairEligibility::PendingShape,
            Refusal::InvalidRange,
        );
    }
    for pending in [vec![range(B + 10, 2)], vec![range(B + 100, 1)]] {
        assert_preflight(
            run(&f, &predecessor, &pending, 2),
            PairEligibility::PendingInitial,
            Refusal::DependencyNotHeld,
        );
    }
    let with_gap = Composition::new(
        identity(),
        vec![
            f.snapshot(),
            ExpectedBytes {
                address: B + 100,
                bytes: vec![0x90, 0x90],
            },
            ExpectedBytes {
                address: B + 104,
                bytes: vec![0x90, 0x90],
            },
        ],
    )
    .unwrap();
    assert_preflight(
        run(&f, &with_gap, &[range(B + 101, 4)], 2),
        PairEligibility::PendingInitial,
        Refusal::DependencyNotHeld,
    );

    let upper = public_singleton(f.site(true), &f.emission, &predecessor, H128);
    let owned = append(&predecessor, &upper);
    assert_preflight(
        run(&f, &owned, &[], 2),
        PairEligibility::PendingInitial,
        Refusal::OwnershipConflict,
    );
    let error = failure(run(&f, &predecessor, &[range(B + 4, 6)], 2));
    assert_eq!(error.stop, PairStop::Exhausted);
    assert_eq!(error.stage, PairStage::UpperPending);
    assert_eq!(error.reason, Refusal::OwnershipConflict);
    assert_evidence(&error.evidence, B, counts(2, 0, 0), false);
    for upper_ordinal in 0..2 {
        let event = at(&error.evidence, PairStage::UpperPending)[upper_ordinal];
        assert_eq!(event.upper_ordinal, Some(upper_ordinal));
        assert_eq!(
            event.outcome,
            PairOutcome::Refused(Refusal::OwnershipConflict)
        );
    }
    assert_eq!(
        &owned.final_bytes()[0].bytes[4..10],
        &f.code[4..10],
        "unchanged IMUL bytes still carry ownership"
    );
    assert!(error.evidence.lower_schedules.is_empty());

    // Every newly locked lower byte is already in the lower selected range or
    // in the upper five-byte lock. Initial exclusion plus UpperPending success
    // therefore precludes a new LowerPending lock conflict in this domain.
    let lower_selected = range(B, 2);
    let upper_lock = range(B + 2, 5);
    for address in B..B + 5 {
        assert!(lower_selected.contains(address) || upper_lock.contains(address));
    }
    for start in B - 2..B + 13 {
        for end in start + 1..B + 14 {
            let external = range(start, (end - start) as usize);
            if !external.overlaps(range(B, 4)) && !external.overlaps(upper_lock) {
                assert!(!external.overlaps(range(B, 5)));
            }
        }
    }
    // Omission of an external selection is a caller completeness obligation;
    // these controls do not pretend the empty slice certifies that obligation.
}

#[test]
fn adjacent_b2_allocation_and_hook_boundaries() {
    let f = Fixture::primary();
    let predecessor = f.empty();
    let positive = run(&f, &predecessor, &[], 2).expect("common target/hook/full-permit positive");
    assert_pair_matches(&f, &predecessor, &positive, H0, LOW);
    let unresolved = ArtifactEmission::new(
        f.emission.profile().clone(),
        SymbolicHook {
            identity: 11,
            address: None,
        },
        f.emission.occupied().to_vec(),
    );
    assert_preflight(
        checked_pair(f.sites(), &unresolved, &predecessor, &[], budget(2)),
        PairEligibility::HookBinding,
        Refusal::UnsupportedSemantics("adjacent B2 requires resolved symbolic hook".into()),
    );
    assert_eq!(
        TargetProfile::linux_x86_64_legacy_evex(SavedExtendedStateLayout::UNAVAILABLE, 7)
            .unwrap_err(),
        Refusal::UnsupportedSemantics("artifact target state is unavailable".into())
    );
    for role in 0..2 {
        for mappings in [true, false] {
            let mut f = Fixture::primary();
            let policy = if role == 0 {
                &mut f.lower
            } else {
                &mut f.upper
            };
            if mappings {
                policy.max_mappings = 0;
            } else {
                policy.max_mapped_bytes = 4095;
            }
            assert_preflight(
                run(&f, &f.empty(), &[], 2),
                PairEligibility::SiteResource,
                Refusal::AllocationUnavailable,
            );
        }
        for missing_first in [true, false] {
            let mut f = Fixture::primary();
            let policy = if role == 0 {
                &mut f.lower
            } else {
                &mut f.upper
            };
            let start = policy.ranges[0].start();
            policy.ranges[0] = range(start + u64::from(missing_first), 4095);
            let error = failure(run(&f, &f.empty(), &[], 2));
            assert_eq!(error.reason, Refusal::AllocationUnavailable);
            assert_eq!(error.stop, PairStop::Exhausted);
            let expected = if role == 0 {
                counts(2, 1, 2)
            } else if missing_first {
                counts(1, 0, 0)
            } else {
                counts(2, 0, 0)
            };
            assert_evidence(&error.evidence, B, expected, false);
            let stage = if role == 0 {
                PairStage::LowerLeaf
            } else {
                PairStage::UpperLeaf
            };
            assert_eq!(error.stage, stage);
            assert!(at(&error.evidence, stage).iter().any(|event| {
                event
                    .search
                    .as_ref()
                    .unwrap()
                    .refusals
                    .iter()
                    .any(|refusal| {
                        refusal.class == RefusalClass::AddressPolicy
                            && refusal.reason == Refusal::AllocationUnavailable
                    })
            }));
        }
    }
    // Declared occupancy is enforced before append, for complete source/hook
    // mappings as well as an actual predecessor's generated mapping.
    let mut occupied = f.emission.occupied().to_vec();
    occupied.push(range(H0, 4096));
    let source_owner = Composition::new(
        identity(),
        vec![
            f.snapshot(),
            ExpectedBytes {
                address: H0,
                bytes: vec![0x90; 4096],
            },
        ],
    )
    .unwrap();
    for (occupied_emission, owner) in [
        (emission(B + 4096, occupied.clone()), source_owner),
        (emission(H0 + 128, occupied), predecessor.clone()),
    ] {
        let error = failure(checked_pair(
            f.sites(),
            &occupied_emission,
            &owner,
            &[],
            budget(2),
        ));
        assert_eq!(error.stop, PairStop::Exhausted);
        assert_eq!(error.stage, PairStage::UpperLeaf);
        assert_evidence(&error.evidence, B, counts(2, 0, 0), false);
    }
    let (f, predecessor, prior) = remote_predecessor(Fixture::primary(), false);
    public_singleton(f.site(true), &f.emission, &predecessor, H128);
    public_singleton(f.site(true), &f.emission, &predecessor, H0);
    let omitted = failure(run(&f, &predecessor, &[], 2));
    assert_eq!(omitted.stop, PairStop::Exhausted);
    assert_eq!(omitted.stage, PairStage::UpperAppend);
    assert_eq!(omitted.reason, Refusal::OwnershipConflict);
    assert_evidence(&omitted.evidence, B, counts(2, 0, 0), false);
    for debit in 1..=2 {
        assert_local_refusal(
            &omitted.evidence,
            PairStage::UpperAppend,
            Refusal::OwnershipConflict,
            counts(debit, 0, 0),
        );
    }
    let mut occupied = f.emission.occupied().to_vec();
    occupied.push(prior.source_steps()[0].parts().allocations[0].range);
    let complete_emission = emission(B + 4096, occupied);
    let declared = failure(checked_pair(
        f.sites(),
        &complete_emission,
        &predecessor,
        &[],
        budget(2),
    ));
    assert_eq!(declared.stage, PairStage::UpperLeaf);
    assert_evidence(&declared.evidence, B, counts(2, 0, 0), false);

    let same = same_page_fixture();
    let predecessor = same.empty();
    same_page_positive_setup(&same, &predecessor);
    let error = failure(run(&same, &predecessor, &[], 1));
    assert_eq!(error.stop, PairStop::LowerImagesBudget);
    assert_eq!(error.unvisited_target, Some(0x1900_e905));
    assert_local_refusal(
        &error.evidence,
        PairStage::LowerAppend,
        Refusal::OwnershipConflict,
        counts(1, 1, 1),
    );
    let f = Fixture::primary();
    let upper = public_singleton(f.site(true), &f.emission, &f.empty(), H0);
    let duplicate = append(&f.empty(), &upper);
    assert_preflight(
        run(&f, &duplicate, &[], 2),
        PairEligibility::PendingInitial,
        Refusal::OwnershipConflict,
    );
    // A duplicate physical site already owns its consumed interval. It cannot
    // first appear as a new append-stage duplicate inside this two-site API.
}

#[test]
fn adjacent_b2_aggregate_and_rollback() {
    let (f, predecessor, _) = positive_predecessor();
    let before = predecessor.clone();
    let mut exact = budget(2);
    exact.bundle.max_virtual_span = 0x6740_9000;
    let pair = checked_pair(f.sites(), &f.emission, &predecessor, &[], exact)
        .expect("exact two-new-member aggregate limits must succeed with a real predecessor");
    assert_eq!(pair.memory(), primary_memory());
    assert_pair_matches(&f, &predecessor, &pair, H0, LOW);
    for field in 0..5 {
        let mut limited = budget(2);
        match field {
            0 => limited.bundle.max_steps = 1,
            1 => limited.bundle.max_mappings = 1,
            2 => limited.bundle.max_virtual_bytes = 8191,
            3 => limited.bundle.max_backing_bytes = 8191,
            4 => limited.bundle.max_virtual_span = 0x6740_8fff,
            _ => unreachable!(),
        }
        let error = failure(checked_pair(
            f.sites(),
            &f.emission,
            &predecessor,
            &[],
            limited,
        ));
        assert_eq!(error.reason, Refusal::AllocationUnavailable);
        assert_eq!(error.stop, PairStop::Exhausted);
        assert_eq!(error.stage, PairStage::Aggregate);
        assert_eq!(error.unvisited_target, None);
        assert_evidence(&error.evidence, B, counts(2, 1, 2), false);
        assert_local_refusal(
            &error.evidence,
            PairStage::Aggregate,
            Refusal::AllocationUnavailable,
            counts(2, 1, 2),
        );
        assert_eq!(
            at(&error.evidence, PairStage::LowerSchedule)[0].outcome,
            PairOutcome::EmptySchedule
        );
        for stage in [
            PairStage::UpperAppend,
            PairStage::UpperPending,
            PairStage::LowerAppend,
            PairStage::LowerPending,
        ] {
            assert!(
                at(&error.evidence, stage)
                    .iter()
                    .all(|event| event.outcome == PairOutcome::LocalAccepted)
            );
        }
        assert_eq!(predecessor, before);
    }
    // Eventual success after a real earlier refusal still spends the original
    // cumulative budgets; no accepted upper escapes through a failure value.
    let fit = upper_fit_fixture();
    let pair = run(&fit, &fit.empty(), &[], 1).expect("later valid candidate within U2/L1/J1");
    assert_evidence(pair.evidence(), fit.base, counts(2, 1, 1), true);
    assert_local_refusal(
        pair.evidence(),
        PairStage::UpperLeaf,
        Refusal::AllocationUnavailable,
        counts(1, 0, 0),
    );
    assert_eq!(
        at(pair.evidence(), PairStage::Aggregate)
            .last()
            .unwrap()
            .outcome,
        PairOutcome::LocalAccepted
    );

    // ADJ-C1: both declared upper/lower pairs are real singleton successes.
    // The first complete pair exceeds only the fixed aggregate span limit;
    // the second fits that same limit without resetting either image budget.
    let mut recovery = Fixture::primary();
    recovery.upper.preferred_address = Some(H0 + 1);
    recovery.lower = allocation(LOW + 0x1_0000, LOW + 0x1_0000, 2);
    recovery.lower.ranges.push(range(LOW, 4096));
    let predecessor = recovery.empty();
    let original = predecessor.clone();
    let mut singleton_pairs = Vec::new();
    for (upper_target, lower_target, span) in [
        (H0 + 1, LOW + 0x1_0000, 0x6741_9000),
        (H0, LOW, 0x6740_9000),
    ] {
        let upper = public_singleton(
            recovery.site(true),
            &recovery.emission,
            &predecessor,
            upper_target,
        );
        let after_upper = append(&predecessor, &upper);
        let lower = public_singleton(
            recovery.site(false),
            &recovery.emission,
            &after_upper,
            lower_target,
        );
        let complete = append(&after_upper, &lower);
        let upper_mapping = upper.source_steps()[0].parts().allocations[0].range;
        let lower_mapping = lower.source_steps()[0].parts().allocations[0].range;
        assert_eq!(upper_mapping, range(H0, 4096));
        assert_eq!(lower_mapping, range(lower_target, 4096));
        assert_eq!(
            upper_mapping.end().max(lower_mapping.end())
                - upper_mapping.start().min(lower_mapping.start()),
            span
        );
        singleton_pairs.push(([upper, lower], complete));
    }
    let mut aggregate_limit = budget(2);
    aggregate_limit.bundle.max_virtual_span = 0x6740_9000;
    let pair = checked_pair(
        recovery.sites(),
        &recovery.emission,
        &predecessor,
        &[],
        aggregate_limit,
    )
    .expect("real Aggregate refusal must retain evidence and recover within U2/L2/J2");
    assert_evidence(pair.evidence(), B, counts(2, 2, 2), true);
    assert_eq!(pair.memory(), primary_memory());
    assert_eq!(
        pair.evidence().upper_schedule.as_ref().unwrap().targets,
        [H0 + 1, H0]
    );
    assert_eq!(pair.evidence().lower_schedules.len(), 2);
    assert_eq!(pair.evidence().lower_schedules[0].targets, [LOW + 0x1_0000]);
    assert_eq!(pair.evidence().lower_schedules[1].targets, [LOW]);
    let aggregate = at(pair.evidence(), PairStage::Aggregate);
    assert_eq!(aggregate.len(), 2);
    assert_eq!(
        aggregate[0].outcome,
        PairOutcome::Refused(Refusal::AllocationUnavailable)
    );
    assert_eq!(aggregate[0].counters_before, counts(1, 1, 1));
    assert_eq!(aggregate[0].counters_after, counts(1, 1, 1));
    assert_eq!(aggregate[0].upper_ordinal, Some(0));
    assert_eq!(aggregate[0].lower_ordinal, Some(0));
    assert_eq!(aggregate[0].upper_target, Some(H0 + 1));
    assert_eq!(aggregate[0].lower_target, Some(LOW + 0x1_0000));
    assert_eq!(aggregate[1].outcome, PairOutcome::LocalAccepted);
    assert_eq!(aggregate[1].counters_before, counts(2, 2, 2));
    assert_eq!(aggregate[1].counters_after, counts(2, 2, 2));
    assert_eq!(aggregate[1].upper_ordinal, Some(1));
    assert_eq!(aggregate[1].lower_ordinal, Some(0));
    assert_eq!(aggregate[1].upper_target, Some(H0));
    assert_eq!(aggregate[1].lower_target, Some(LOW));
    for stage in [
        PairStage::UpperLeaf,
        PairStage::UpperAppend,
        PairStage::UpperPending,
        PairStage::LowerLeaf,
        PairStage::LowerAppend,
        PairStage::LowerPending,
    ] {
        let events = at(pair.evidence(), stage);
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event.outcome == PairOutcome::LocalAccepted)
        );
    }
    artifact_equal(&pair.members()[0], &singleton_pairs[1].0[0]);
    artifact_equal(&pair.members()[1], &singleton_pairs[1].0[1]);
    let final_state = assert_pair_matches(&recovery, &predecessor, &pair, H0, LOW);
    assert_eq!(final_state, singleton_pairs[1].1);
    assert_ne!(final_state, singleton_pairs[0].1);
    assert_eq!(predecessor, original);
}

#[test]
fn adjacent_b2_failure_precedence() {
    let f = Fixture::primary();
    let predecessor = f.empty();
    run(&f, &predecessor, &[], 2).expect("positive established before dual-fault mutations");
    let mut wrong_code = f.code.clone();
    wrong_code[7] ^= 1;
    for stale_lower in [false, true] {
        let mut sites = f.sites();
        sites[0].code = &wrong_code;
        sites[1].identity.generation += 1;
        if stale_lower {
            sites[0].identity.generation += 1;
        }
        assert_preflight(
            checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
            PairEligibility::OriginalAuthentication,
            if stale_lower {
                Refusal::StaleGeneration
            } else {
                Refusal::ExpectedBytesChanged
            },
        );
    }
    let mut sites = f.sites();
    sites[1].identity.mapping += 1;
    sites[1].base_address += 1;
    assert_preflight(
        checked_pair(sites, &f.emission, &predecessor, &[], budget(2)),
        PairEligibility::CommonIdentity,
        Refusal::StaleGeneration,
    );
    let unresolved = ArtifactEmission::new(
        f.emission.profile().clone(),
        SymbolicHook {
            identity: 11,
            address: None,
        },
        f.emission.occupied().to_vec(),
    );
    let mut sites = f.sites();
    sites[0].search.max_sites = 0;
    sites[1].semantics = HookSemantics::ReplaceFirst;
    assert_preflight(
        checked_pair(sites, &unresolved, &predecessor, &[], budget(2)),
        PairEligibility::SearchDomain,
        Refusal::UnsupportedSemantics("adjacent B2 exact search contract".into()),
    );
    let mut no_capacity = Fixture::primary();
    no_capacity.lower.max_mappings = 0;
    assert_preflight(
        checked_pair(
            no_capacity.sites(),
            &unresolved,
            &predecessor,
            &[range(B, 2)],
            budget(2),
        ),
        PairEligibility::HookBinding,
        Refusal::UnsupportedSemantics("adjacent B2 requires resolved symbolic hook".into()),
    );
    assert_preflight(
        run(&no_capacity, &predecessor, &[range(B, 2)], 2),
        PairEligibility::SiteResource,
        Refusal::AllocationUnavailable,
    );
    let mut invalid_caps = Fixture::primary();
    invalid_caps.upper.max_candidates = 1;
    assert_preflight(
        run(
            &invalid_caps,
            &predecessor,
            &[range(B, 2), range(B + 100, 1)],
            2,
        ),
        PairEligibility::PendingShape,
        Refusal::InvalidRange,
    );
    assert_preflight(
        run(&invalid_caps, &predecessor, &[range(B + 100, 1)], 2),
        PairEligibility::PendingInitial,
        Refusal::DependencyNotHeld,
    );
    let upper = public_singleton(f.site(true), &f.emission, &predecessor, H0);
    let locked = append(&predecessor, &upper);
    assert_preflight(
        run(&f, &locked, &[range(B + 100, 1)], 2),
        PairEligibility::PendingInitial,
        Refusal::DependencyNotHeld,
    );
    assert_preflight(
        run(&f, &locked, &[], 2),
        PairEligibility::PendingInitial,
        Refusal::OwnershipConflict,
    );
    let mut all_zero = Fixture::primary();
    all_zero.upper.max_candidates = 0;
    all_zero.lower.max_candidates = 0;
    let error = failure(run(&all_zero, &all_zero.empty(), &[], 0));
    assert_eq!(error.stop, PairStop::UpperImagesBudget);
    let error = failure(run(&all_zero, &all_zero.empty(), &[], 1));
    assert_eq!(error.stop, PairStop::InvalidBudgetRelation);
    assert_eq!(error.reason, Refusal::InvalidRange);
    all_zero.upper.max_candidates = 2;
    let error = failure(run(&all_zero, &all_zero.empty(), &[], 0));
    assert_eq!(error.stop, PairStop::LowerImagesBudget);

    // The same-page bytes retain valid original Jccs, heads and fetch/store
    // geometry at this declared base, but their upper signed rel32 window is
    // negative. Deriving that window is not an exact-target image attempt.
    let same_source = same_page_fixture();
    let mut negative_window = Fixture::with_source(0x1000_0000, &same_source.code, &[0, 2, 4, 9]);
    negative_window.upper = same_source.upper;
    negative_window.lower = same_source.lower;
    assert!(
        i128::from(negative_window.base)
            + 7
            + i128::from(i32::from_le_bytes([0x00, 0xe9, 0x00, 0xe9]))
            < 0
    );
    let error = failure(run(&negative_window, &negative_window.empty(), &[], 1));
    assert_eq!(error.stop, PairStop::Exhausted);
    assert_eq!(error.reason, Refusal::AllocationUnavailable);
    assert_eq!(error.stage, PairStage::UpperLeaf);
    assert_eq!(error.unvisited_target, None);
    assert_evidence(
        &error.evidence,
        negative_window.base,
        counts(0, 0, 0),
        false,
    );
    assert!(error.evidence.upper_schedule.is_none());
    assert!(error.evidence.lower_schedules.is_empty());
    let refused_window = at(&error.evidence, PairStage::UpperLeaf);
    assert_eq!(refused_window.len(), 1);
    assert_eq!(
        refused_window[0].outcome,
        PairOutcome::Refused(Refusal::AllocationUnavailable)
    );
    assert!(refused_window[0].search.is_none());
    assert_eq!(refused_window[0].counters_before, counts(0, 0, 0));
    assert_eq!(refused_window[0].counters_after, counts(0, 0, 0));

    let mut empty = Fixture::primary();
    empty.upper.preferred_address = None;
    empty.upper.ranges.clear();
    let error = failure(run(&empty, &empty.empty(), &[], 2));
    assert_eq!(error.stop, PairStop::Exhausted);
    assert_eq!(error.reason, Refusal::AllocationUnavailable);
    assert_evidence(&error.evidence, B, counts(0, 0, 0), false);
    assert!(at(&error.evidence, PairStage::UpperLeaf).is_empty());
    assert_eq!(
        error.evidence.upper_schedule.as_ref().unwrap().proof,
        page_proof(0, None, &[])
    );
    let error = failure(run(&f, &predecessor, &[], 1));
    assert_eq!(error.stop, PairStop::JointContinuationsBudget);
    assert_eq!(
        at(&error.evidence, PairStage::LowerSchedule)[0].outcome,
        PairOutcome::EmptySchedule
    );
    assert!(at(&error.evidence, PairStage::LowerLeaf).is_empty());
    assert!(!error.evidence.accepted);

    let same = same_page_fixture();
    same_page_positive_setup(&same, &same.empty());
    let error = failure(run(&same, &same.empty(), &[], 1));
    assert_local_refusal(
        &error.evidence,
        PairStage::LowerAppend,
        Refusal::OwnershipConflict,
        counts(1, 1, 1),
    );
    assert_eq!(error.stop, PairStop::LowerImagesBudget);
    assert_eq!(error.reason, Refusal::AllocationUnavailable);
    assert_eq!(error.unvisited_target, Some(0x1900_e905));
    let (f, predecessor, _) = remote_predecessor(Fixture::primary(), false);
    let error = failure(run(&f, &predecessor, &[], 2));
    assert_eq!(error.stop, PairStop::Exhausted);
    assert_eq!(error.reason, Refusal::OwnershipConflict);
    assert_eq!(error.stage, PairStage::UpperAppend);
    assert_eq!(
        error.evidence.events.last().unwrap().outcome,
        PairOutcome::Refused(Refusal::OwnershipConflict)
    );
    assert_eq!(
        error.evidence.upper_schedule.as_ref().unwrap().proof,
        page_proof(2, None, &[(1, 1)])
    );
    assert!(!error.evidence.classification_complete);
    // Malformed AddressRange values and arbitrary unchecked PatchPlans cannot
    // enter through this API. Do not invent an impossible structural owner to
    // manufacture TerminalInvariant, LowerPending, or duplicate-append evidence.
}

#[test]
fn adjacent_b2_legacy_projection() {
    let f = Fixture::primary();
    let predecessor = f.empty();
    let request = ArtifactRequest {
        site: f.site(true),
        emission: &f.emission,
    };
    let legacy = crate::quiescent::plan_install_with_emission(&request)
        .expect("old forced B2 still selects its first local upper success");
    assert_eq!(legacy.images().next().unwrap().address(), H128);
    let expected = public_singleton(f.site(true), &f.emission, &predecessor, H128);
    artifact_equal(&legacy, &expected);
    let ArtifactMetrics::Single(metrics) = legacy.metrics() else {
        panic!("unchanged singleton metric kind")
    };
    assert_eq!(metrics.allocation_attempts, 1);
    assert_eq!(metrics.attempts.len(), 1);
    let after_upper = append(&predecessor, &legacy);
    let error = engine::plan_with_emission_after(
        &ArtifactRequest {
            site: f.site(false),
            emission: &f.emission,
        },
        &after_upper,
        &f.lower,
        EnginePolicy {
            forced: Some(Tactic::GeneralizedPun),
            ..EnginePolicy::default()
        },
    )
    .expect_err("old lower continuation retains its unchanged unavailable permit");
    assert_eq!(error.reason, Refusal::AllocationUnavailable);
    assert_eq!(error.attempts.len(), 1);
    assert_eq!(error.attempts[0].tactic, Tactic::GeneralizedPun);
    assert_eq!(
        error.attempts[0].refusal,
        Some(Refusal::AllocationUnavailable)
    );
    let images: Vec<_> = error.attempts[0]
        .search
        .runs
        .iter()
        .filter(|run| run.domain == SearchDomain::SelectedImages)
        .collect();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].examined, 0);
    assert_eq!(images[0].stop, SearchStop::DomainComplete);
    assert_eq!(images[0].candidates, Some(page_proof(0, None, &[(0, 0)])));
    let defaults = SearchPolicy::default();
    assert_eq!(defaults.tactics, TacticPolicy::PreferGeneralizedPun);
    assert_eq!(defaults.max_upstream_bytes, 64);
    assert_eq!(defaults.max_displaced_bytes, 80);
    assert_eq!(defaults.max_sites, 65);
    let engine = EnginePolicy::default();
    assert_eq!(engine.forced, None);
    assert_eq!(engine.successor_puns, TacticPolicy::PreferGeneralizedPun);
    assert_eq!(engine.bundle, BundleBudget::default());
    assert_eq!(f.upper.max_candidates, 2);
    assert_eq!(f.lower.max_candidates, 1);
    let mut cap_one = f.clone();
    cap_one.upper.max_candidates = 1;
    let old_one = crate::quiescent::plan_install_with_emission(&ArtifactRequest {
        site: cap_one.site(true),
        emission: &cap_one.emission,
    })
    .expect("legacy upper cap1 positive remains first local target");
    assert_eq!(old_one.images().next().unwrap().address(), H128);
    let error = failure(run(&cap_one, &cap_one.empty(), &[], 1));
    assert_eq!(error.stop, PairStop::UpperScheduleBudget);
    assert_evidence(&error.evidence, B, counts(1, 0, 1), false);
    // Existing source bodies, profiles and controls are separately required to
    // remain literal; this additive module introduces no old-path call site.
}
