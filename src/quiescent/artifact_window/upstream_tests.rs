//! Authored outcomes over the real shared artifact planner; no native execution.
use super::*;
use crate::emission::{
    ArtifactEmission, ArtifactMetrics, PlanningSite, SymbolicHook, TargetProfile,
};
use crate::search::SearchStop;
use crate::trampoline::SavedExtendedStateLayout;

const BASE: u64 = 0x0040_0000;
// LEA RAX,[RAX]; POP RBX; POP RBP. Only the two POPs are observations.
const SHORT: [u8; 6] = [0x48, 0x8d, 0x40, 0, 0x5b, 0x5d];

struct Fixture {
    base: u64,
    code: Vec<u8>,
    entries: LegalEntrySet,
    allocation: AllocationPolicy,
    emission: ArtifactEmission,
    search: SearchPolicy,
}
impl Fixture {
    fn new(base: u64, bytes: &[u8]) -> Self {
        let identity = CodeIdentity {
            source: SourceIdentity([29; 32]),
            mapping: 7,
            generation: 1,
        };
        Self {
            base,
            code: bytes.to_vec(),
            entries: LegalEntrySet {
                identity,
                scope: AddressRange::new(base, bytes.len()).unwrap(),
                provenance: EntryProvenance::Declared("bounded upstream control".into()),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: vec![LegalEntry {
                    address: base,
                    requires_endbr: false,
                }],
                resumes: ResumeObligation::NoneExist,
            },
            allocation: AllocationPolicy {
                ranges: vec![AddressRange::new(0x0100_0000, 0x1f00_0000).unwrap()],
                preferred_address: None,
                max_candidates: 1,
                max_mappings: 1,
                max_mapped_bytes: 4096,
            },
            emission: Self::emission(Some(base + 4096), vec![]),
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 64,
                max_displaced_bytes: 256,
                max_sites: 64,
            },
        }
    }
    fn emission(address: Option<u64>, occupied: Vec<AddressRange>) -> ArtifactEmission {
        ArtifactEmission::new(
            TargetProfile::linux_x86_64_legacy_evex(
                SavedExtendedStateLayout::describe_target_fxsave64(),
                7,
            )
            .unwrap(),
            SymbolicHook {
                identity: 19,
                address,
            },
            occupied,
        )
    }
    fn predecessor(&self) -> Composition {
        Composition::new(
            self.entries.identity,
            vec![ExpectedBytes {
                address: self.base,
                bytes: self.code.clone(),
            }],
        )
        .unwrap()
    }
    fn request<'a>(&'a self, pcs: &'a [u64], end: u64) -> ArtifactObservationSearchRequest<'a> {
        let source = AddressRange::new(self.base, self.code.len()).unwrap();
        ArtifactObservationSearchRequest {
            artifact: ArtifactRequest {
                site: PlanningSite {
                    identity: self.entries.identity,
                    code: &self.code,
                    base_address: self.base,
                    function: source,
                    block: source,
                    logical_pc: pcs.first().copied().unwrap_or(self.base),
                    entries: &self.entries,
                    semantics: HookSemantics::Observe,
                    allocation: &self.allocation,
                    search: self.search,
                },
                emission: &self.emission,
            },
            end,
            observation_pcs: pcs,
        }
    }
    fn plan(&self, pcs: &[u64], end: u64) -> Result<ArtifactObservationPlan, PlanningFailure> {
        plan_artifact_observation_window_upstream_after(
            &self.request(pcs, end),
            &self.predecessor(),
            &[],
        )
    }
    fn exact(&self, pcs: &[u64], end: u64) -> Result<ArtifactObservationPlan, PlanningFailure> {
        let input = self.request(pcs, end);
        plan_artifact_observation_window_after(
            &ArtifactObservationRequest {
                artifact: input.artifact,
                physical_pc: input.artifact.site.logical_pc,
                end,
                observation_pcs: pcs,
            },
            &self.predecessor(),
            &[],
        )
    }
}
fn metrics(plan: &ArtifactObservationPlan) -> &PlanMetrics {
    let ArtifactMetrics::Single(metrics) = plan.artifact().metrics() else {
        panic!("one B1 window")
    };
    metrics
}

#[test]
fn short_span_uses_one_legal_prefix_and_preserves_every_head_and_observer() {
    let f = Fixture::new(BASE, &SHORT);
    let pcs = [BASE + 4, BASE + 5];
    let exact = f.exact(&pcs, BASE + 6).unwrap_err();
    assert_eq!(exact.reason, Refusal::NoPatchWindow);
    assert_eq!(exact.attempts.len(), 1);
    let before = f.predecessor();
    let group =
        plan_artifact_observation_window_upstream_after(&f.request(&pcs, BASE + 6), &before, &[])
            .unwrap();
    assert_eq!(before, f.predecessor());
    assert_eq!(group.observation_pcs(), pcs);
    assert_eq!(group.artifact().source_steps().len(), 1);
    assert_eq!(group.artifact().images().count(), 1);
    let parts = group.artifact().source_steps()[0].parts();
    assert_eq!(parts.physical_pc, BASE);
    assert_eq!(parts.logical_pc, BASE + 4);
    assert_eq!(parts.displaced, AddressRange::new(BASE, 6).unwrap());
    assert_eq!(
        parts.reads,
        [ExpectedBytes {
            address: BASE,
            bytes: SHORT.to_vec()
        }]
    );
    assert_eq!(parts.allocations.len(), 1);
    assert_eq!(parts.allocations[0].range.len(), 4096);
    let image = group.artifact().images().next().unwrap();
    assert_eq!(
        image.entry_routes().iter().map(|r| r.0).collect::<Vec<_>>(),
        [BASE, BASE + 4, BASE + 5]
    );
    assert_eq!(
        image
            .instruction_boundaries()
            .iter()
            .map(|r| r.0)
            .collect::<Vec<_>>(),
        [BASE, BASE + 4, BASE + 5]
    );
    for (entry, body) in image
        .entry_routes()
        .iter()
        .zip(image.instruction_boundaries())
    {
        assert_eq!(entry.0, body.0);
        if entry.0 == BASE {
            assert_eq!(entry.1, body.1);
        } else {
            assert!(entry.1 < body.1);
        }
    }
    assert_eq!(
        image
            .metadata()
            .fields()
            .iter()
            .filter(|f| f.role == "LogicalPc")
            .map(|f| f.target)
            .collect::<Vec<_>>(),
        pcs.map(i128::from)
    );
    assert_eq!(
        image
            .metadata()
            .fields()
            .iter()
            .filter(|f| f.role == "HookCall")
            .map(|f| f.target)
            .collect::<Vec<_>>(),
        [i128::from(BASE + 4096); 2]
    );
    let m = metrics(&group);
    assert_eq!(
        (
            m.upstream_bytes,
            m.displaced_bytes,
            m.prefix_instructions,
            m.allocation_attempts
        ),
        (4, 6, 1, 1)
    );
    assert_eq!(
        m.attempts
            .iter()
            .map(|a| (a.physical_pc, a.refusal.clone()))
            .collect::<Vec<_>>(),
        [(BASE + 4, Some(Refusal::NoPatchWindow)), (BASE, None)]
    );
    assert_eq!(&m.search, group.search());
    assert_eq!(
        group
            .search()
            .runs
            .iter()
            .map(|r| (r.domain, r.examined, r.stop))
            .collect::<Vec<_>>(),
        [
            (SearchDomain::PhysicalSites, 2, SearchStop::Accepted),
            (SearchDomain::SelectedImages, 1, SearchStop::Accepted)
        ]
    );
    assert_eq!(group.search().runs[0].finite_total, Some(2));
    assert!(group.search().accepted);
    assert!(!group.search().classification_complete);
    assert!(!group.artifact().qualification_complete());
}

#[test]
fn constrained_offset_refuses_before_prefix_fits_in_the_same_arena() {
    // At logical0x4068fb, the +2/+4 heads fix rel32 bytes1/3 to06.
    // This ordinal-zero mask domain has offsets0xf00..0xfff: at most256B.
    // At the four-byte LEA prefix only byte3 is fixed. The fitter retains
    // its available certified default seed BEFORE minimizing page offset.
    let logical = 0x0040_68fb;
    let f = Fixture::new(
        logical - 4,
        &[0x48, 0x8d, 0x40, 0, 0x41, 0x54, 0x41, 0x55, 0x5b],
    );
    let pcs = [logical, logical + 2, logical + 4];
    let scan = InstructionScanner::default().scan(&f.code, f.base).unwrap();
    let window =
        crate::trampoline::ArtifactObservationWindow::checked(&scan, logical, logical + 5, &pcs)
            .unwrap();
    let prepared =
        crate::trampoline::PreparedArtifact::for_observation_window(&window, &f.emission).unwrap();
    assert!(prepared.size_bound() > 256 && prepared.size_bound() <= 4096);
    let exact = f.exact(&pcs, logical + 5).unwrap_err();
    assert_eq!(exact.reason, Refusal::AllocationUnavailable);
    assert_eq!(exact.search.runs.len(), 1);
    assert_eq!(
        exact.search.refusals.last().unwrap().class,
        RefusalClass::AddressPolicy
    );
    assert_eq!(
        candidate_target(logical, [false, true, false, true], None, 0),
        Some(0x0641_6f00)
    );
    let prefix_window = crate::trampoline::ArtifactObservationWindow::checked(
        &scan,
        logical - 4,
        logical + 5,
        &pcs,
    )
    .unwrap();
    let prefix_prepared =
        crate::trampoline::PreparedArtifact::for_observation_window(&prefix_window, &f.emission)
            .unwrap();
    // The same three observers plus one ordinary LEA: fitting.rs charges15B
    // for that additional original instruction, not an extra observer.
    assert_eq!(prefix_prepared.size_bound(), prepared.size_bound() + 15);
    assert!(prefix_prepared.size_bound() <= 4096 - 0x8fc);
    let group = f.plan(&pcs, logical + 5).unwrap();
    assert_eq!(
        group.artifact().source_steps()[0].parts().physical_pc,
        logical - 4
    );
    assert_eq!(
        group.artifact().source_steps()[0].parts().displaced.end(),
        logical + 5
    );
    let image = group.artifact().images().next().unwrap();
    let next = (logical - 4) + 5;
    // Default displacement0x10000 has bytes[00,00,01,00]; constraining only
    // byte3 to06 gives[00,00,01,06], independently of the observed result.
    let expected_target = next + 0x0601_0000;
    assert_eq!(expected_target, 0x0641_68fc);
    assert_eq!(
        candidate_target(logical - 4, [false, false, false, true], None, 0),
        Some(expected_target)
    );
    assert_eq!(image.address(), expected_target);
    assert_eq!(image.address() % 4096, 0x8fc);
    assert!(image.bytes().len() <= prefix_prepared.size_bound());
    assert!(image.address() % 4096 + prefix_prepared.size_bound() as u64 <= 4096);
    assert_eq!(group.artifact().images().count(), 1);
    let parts = group.artifact().source_steps()[0].parts();
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(&parts.writes[0].bytes[..5], &[0xe9, 0, 0, 1, 0x06]);
    assert_eq!(parts.allocations.len(), 1);
    assert_eq!(
        parts.allocations[0].range,
        AddressRange::new(expected_target & !4095, 4096).unwrap()
    );
    assert!(
        parts.allocations[0]
            .range
            .covers(AddressRange::new(image.address(), image.bytes().len()).unwrap())
    );
    assert_eq!(
        metrics(&group)
            .attempts
            .iter()
            .map(|a| a.refusal.clone())
            .collect::<Vec<_>>(),
        [Some(Refusal::AllocationUnavailable), None]
    );
    assert_eq!(metrics(&group).allocation_attempts, 1);
    assert_eq!(
        f.allocation.ranges,
        [AddressRange::new(0x0100_0000, 0x1f00_0000).unwrap()]
    );
}

#[test]
fn sixty_five_heads_share_one_sixty_four_site_domain_and_retain_omission() {
    let mut bytes = vec![0x90; 64];
    bytes.extend_from_slice(&[0x5b, 0x5d]);
    let mut f = Fixture::new(BASE, &bytes);
    f.emission = Fixture::emission(Some(BASE + 4096), f.allocation.ranges.clone());
    let pcs = [BASE + 64, BASE + 65];
    let failure = f.plan(&pcs, BASE + 66).unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 64);
    assert_eq!(failure.search.runs.len(), 1);
    let run = &failure.search.runs[0];
    assert_eq!(
        (run.domain, run.limit, run.finite_total, run.examined),
        (SearchDomain::PhysicalSites, 64, Some(65), 64)
    );
    assert_eq!(
        run.stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    // Same-site first, then nearest heads not crossing the eight-byte-store
    // cache-line boundary, then the deferred crossing heads. Head+57 is omitted.
    assert_eq!(failure.attempts[0].physical_pc, BASE + 64);
    assert_eq!(failure.attempts[1].physical_pc, BASE + 56);
    assert_eq!(failure.attempts[57].physical_pc, BASE);
    assert_eq!(failure.attempts[58].physical_pc, BASE + 63);
    assert_eq!(failure.attempts[63].physical_pc, BASE + 58);
    for segment in [&failure.attempts[1..58], &failure.attempts[58..]] {
        assert!(
            segment
                .windows(2)
                .all(|p| p[0].physical_pc == p[1].physical_pc + 1)
        );
    }
    assert!(!failure.attempts.iter().any(|a| a.physical_pc == BASE + 57));
    assert!(
        failure
            .attempts
            .iter()
            .all(|a| a.refusal.is_some() && BASE + 64 - a.physical_pc <= 64)
    );
    assert!(!failure.search.accepted);
    assert!(!failure.search.classification_complete);
    f.search.max_sites = 0;
    let zero = f.plan(&pcs, BASE + 66).unwrap_err();
    assert_eq!(zero.reason, Refusal::NoPatchWindow);
    assert!(zero.attempts.is_empty());
    assert_eq!(zero.search.runs[0].finite_total, Some(65));
    assert_eq!(
        zero.search.runs[0].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 65
        }
    );
}

#[test]
fn block_distance_displacement_call_and_nonfinal_transfer_remain_hard_boundaries() {
    let pcs = [BASE + 4, BASE + 5];
    let mut f = Fixture::new(BASE, &SHORT);
    let mut request = f.request(&pcs, BASE + 6);
    request.artifact.site.block = AddressRange::new(BASE + 4, 2).unwrap();
    let failure = plan_artifact_observation_window_upstream_after(&request, &f.predecessor(), &[])
        .unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert_eq!(failure.attempts.len(), 1);
    f.search.max_upstream_bytes = 3;
    assert_eq!(f.plan(&pcs, BASE + 6).unwrap_err().attempts.len(), 1);
    f.search.max_upstream_bytes = 64;
    f.search.max_sites = 1;
    let failure = f.plan(&pcs, BASE + 6).unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert_eq!(
        failure.search.runs[0].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    f.search.max_sites = 64;
    f.search.max_displaced_bytes = 5;
    let failure = f.plan(&pcs, BASE + 6).unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert_eq!(failure.attempts.len(), 2);
    assert_eq!(failure.search.runs[0].stop, SearchStop::DomainComplete);
    let split_end = Fixture::new(BASE, &[0x48, 0x8d, 0x40, 0, 0x41, 0x5c, 0x5d]);
    let failure = split_end.plan(&[BASE + 4], BASE + 5).unwrap_err();
    assert_eq!(failure.reason, Refusal::NotInstructionHead);
    assert_eq!(failure.attempts.len(), 2);
    let call = Fixture::new(BASE, &[0xe8, 0, 0, 0, 0, 0x5b, 0x5d]);
    let failure = call.plan(&[BASE + 5, BASE + 6], BASE + 7).unwrap_err();
    assert_eq!(
        failure.reason,
        Refusal::UnsupportedSemantics("Call has no qualified A1 relocation contract".into())
    );
    assert_eq!(failure.attempts.len(), 2);
    let branch = Fixture::new(BASE, &[0xeb, 0, 0x90, 0x90, 0x5b, 0x5d]);
    let failure = branch.plan(&pcs, BASE + 6).unwrap_err();
    assert_eq!(
        failure.reason,
        Refusal::UnsupportedSemantics("control transfer before displaced end".into())
    );
    assert_eq!(failure.attempts.len(), 4);
}

#[test]
fn identity_pending_overlay_and_cet_checks_keep_predecessor_unchanged() {
    let pcs = [BASE + 4, BASE + 5];
    let mut f = Fixture::new(BASE, &SHORT);
    let before = f.predecessor();
    let mut wrong_identity = f.request(&pcs, BASE + 6);
    wrong_identity.artifact.site.identity.generation += 1;
    let failure =
        plan_artifact_observation_window_upstream_after(&wrong_identity, &before, &[]).unwrap_err();
    assert_eq!(failure.reason, Refusal::StaleGeneration);
    assert!(failure.attempts.is_empty() && failure.search.runs.is_empty());
    let prefix = AddressRange::new(BASE, 4).unwrap();
    let failure = plan_artifact_observation_window_upstream_after(
        &f.request(&pcs, BASE + 6),
        &before,
        &[prefix],
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::OwnershipConflict);
    assert_eq!(failure.attempts.len(), 2);
    assert_eq!(failure.search.runs[0].stop, SearchStop::DomainComplete);
    assert_eq!(failure.search.runs[1].stop, SearchStop::Accepted);
    assert!(!failure.search.accepted);
    assert_eq!(before, f.predecessor());
    let uncovered = AddressRange::new(BASE + 6, 1).unwrap();
    let failure = plan_artifact_observation_window_upstream_after(
        &f.request(&pcs, BASE + 6),
        &before,
        &[uncovered],
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::DependencyNotHeld);
    assert!(failure.attempts.is_empty() && failure.search.runs.is_empty());
    let first = f.plan(&pcs, BASE + 6).unwrap();
    let mut changed = before.clone();
    changed.append(&first.artifact().source_steps()[0]).unwrap();
    let snapshot = changed.clone();
    f.emission = Fixture::emission(None, vec![]);
    let failure =
        plan_artifact_observation_window_upstream_after(&f.request(&pcs, BASE + 6), &changed, &[])
            .unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert_eq!(failure.attempts.len(), 2);
    assert_eq!(
        failure.search.refusals.last().unwrap().reason,
        Refusal::ExpectedBytesChanged
    );
    f.entries.entries.push(LegalEntry {
        address: BASE + 4,
        requires_endbr: true,
    });
    let failure =
        plan_artifact_observation_window_upstream_after(&f.request(&pcs, BASE + 6), &changed, &[])
            .unwrap_err();
    assert_eq!(
        failure.reason,
        Refusal::UnsupportedSemantics("CET IBT landing pad in displaced range".into())
    );
    assert_eq!(changed, snapshot);
}

#[test]
fn oversized_certificate_is_not_rescued_by_an_earlier_head_or_unresolved_hook() {
    let mut code = SHORT[..4].to_vec();
    code.extend_from_slice(&[0x58; 32]);
    let mut f = Fixture::new(BASE, &code);
    f.emission = Fixture::emission(None, vec![]);
    let pcs: Vec<_> = (4..36).map(|i| BASE + i).collect();
    let scan = InstructionScanner::default().scan(&f.code, BASE).unwrap();
    let window =
        crate::trampoline::ArtifactObservationWindow::checked(&scan, BASE + 4, BASE + 36, &pcs)
            .unwrap();
    let prepared =
        crate::trampoline::PreparedArtifact::for_observation_window(&window, &f.emission).unwrap();
    assert!(prepared.size_bound() > 4096);
    let failure = f.plan(&pcs, BASE + 36).unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 2);
    assert!(
        failure
            .attempts
            .iter()
            .all(|a| a.refusal == Some(Refusal::AllocationUnavailable))
    );
    assert_eq!(failure.search.runs.len(), 1);
    assert_eq!(failure.search.runs[0].stop, SearchStop::DomainComplete);
    assert_eq!(failure.search.refusals.len(), 2);
    assert!(
        failure
            .search
            .refusals
            .iter()
            .all(|r| r.class == RefusalClass::AddressPolicy)
    );
    assert!(!failure.search.accepted);
}

#[test]
fn population_allocation_and_per_head_symbol_failures_are_never_bypassed() {
    let pcs = [BASE + 4, BASE + 5];
    let mut f = Fixture::new(BASE, &SHORT);
    for (selected, end, reason) in [
        (vec![], BASE + 6, Refusal::InvalidPlan),
        (vec![BASE + 4, BASE + 4], BASE + 6, Refusal::InvalidPlan),
        (vec![BASE + 4, BASE + 3], BASE + 6, Refusal::InvalidPlan),
        (vec![BASE + 4, BASE + 6], BASE + 6, Refusal::InvalidRange),
        (
            vec![BASE + 1, BASE + 4],
            BASE + 6,
            Refusal::NotInstructionHead,
        ),
    ] {
        let failure = f.plan(&selected, end).unwrap_err();
        assert_eq!(failure.reason, reason);
        assert!(failure.attempts.is_empty() && failure.search.runs.is_empty());
    }
    f.entries.completeness = EntryCompleteness::Complete;
    assert_eq!(
        f.plan(&pcs, BASE + 6).unwrap_err().reason,
        Refusal::UnresolvedEntry
    );
    f.entries.completeness = EntryCompleteness::AllInstructionHeads;
    f.search.tactics = TacticPolicy::PreferGeneralizedPun;
    assert_eq!(
        f.plan(&pcs, BASE + 6).unwrap_err().reason,
        Refusal::UnsupportedSemantics(
            "artifact observation window requires explicit relocation-only policy".into()
        )
    );
    f.search.tactics = TacticPolicy::RelocationOnly;
    let mut replaced = f.request(&pcs, BASE + 6);
    replaced.artifact.site.semantics = HookSemantics::ReplaceFirst;
    assert_eq!(
        plan_artifact_observation_window_upstream_after(&replaced, &f.predecessor(), &[])
            .unwrap_err()
            .reason,
        Refusal::UnsupportedSemantics(
            "artifact observation window requires observing hooks".into()
        )
    );
    f.allocation.max_candidates = 2;
    assert_eq!(
        f.plan(&pcs, BASE + 6).unwrap_err().reason,
        Refusal::InvalidRange
    );
    f.allocation.max_candidates = 1;
    f.allocation.max_mapped_bytes = 8192;
    assert_eq!(
        f.plan(&pcs, BASE + 6).unwrap_err().reason,
        Refusal::InvalidRange
    );
    let mut two_prefixes = SHORT[..4].to_vec();
    two_prefixes.extend_from_slice(&SHORT);
    let mut f = Fixture::new(BASE, &two_prefixes);
    f.emission = Fixture::emission(None, vec![]);
    let failure = f.plan(&[BASE + 8, BASE + 9], BASE + 10).unwrap_err();
    assert_eq!(
        failure.reason,
        Refusal::Backend("artifact TargetBinding: UnresolvedSymbol(19)".into())
    );
    assert_eq!(failure.attempts.len(), 3);
    assert_eq!(failure.search.runs[0].finite_total, Some(3));
    assert_eq!(failure.search.runs[0].stop, SearchStop::DomainComplete);
    assert_eq!(
        failure
            .search
            .runs
            .iter()
            .skip(1)
            .map(|r| (r.scope.physical_pc, r.examined))
            .collect::<Vec<_>>(),
        [(Some(BASE + 4), 1), (Some(BASE), 1)]
    );
    assert!(!failure.search.accepted);
}
