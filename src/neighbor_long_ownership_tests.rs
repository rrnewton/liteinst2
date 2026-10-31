//! Pure long-victim artifact/ownership controls; no mapped code or execution.
use super::*;
use crate::emission::{ArtifactEmission, PlanningSite, SymbolicHook, TargetProfile};
use crate::engine::{
    self, CandidateEvidence, EngineFailure, EnginePolicy, SelectedMetrics, Tactic,
};
use crate::quiescent::{SearchPolicy, TacticPolicy};
use crate::search::{SearchDomain, SearchStop};
use crate::trampoline::SavedExtendedStateLayout;

fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}

fn allocation(target: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(target & !4095, 8192)],
        preferred_address: Some(target),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 8192,
    }
}

struct Fixture {
    base: u64,
    selected: usize,
    code: Vec<u8>,
    entries: LegalEntrySet,
    selected_allocation: AllocationPolicy,
    victim_allocation: AllocationPolicy,
    emission: ArtifactEmission,
}

impl Fixture {
    fn new(selected: usize) -> Self {
        assert!(matches!(selected, 0 | 2));
        let base = 0x4200_0000_0000;
        let mut code = vec![0x90; 48];
        code[..2].copy_from_slice(&[0xff, 0xc0]);
        code[selected..selected + 3].copy_from_slice(&[0xff, 0xc0, 0xc3]);
        for (at, first) in [(16, 0x37), (32, 0x27)] {
            code[at - 2..at].copy_from_slice(&[0xff, 0xc0]);
            code[at..at + 10]
                .copy_from_slice(&[0x48, 0xb8, first, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97]);
        }
        code[42] = 0xc3;
        let identity = CodeIdentity {
            source: SourceIdentity([91; 32]),
            mapping: 23,
            generation: 9,
        };
        let spans = [
            (0, 2),
            (selected, selected + 2),
            (14, 16),
            (16, 26),
            (30, 32),
            (32, 42),
        ];
        let entries = LegalEntrySet {
            identity,
            scope: range(base, code.len()),
            provenance: EntryProvenance::Declared("literal two long victims".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: (0..code.len())
                .filter(|&i| !spans.iter().any(|&(a, b)| a < i && i < b))
                .map(|i| LegalEntry {
                    address: base + i as u64,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        Self {
            base,
            selected,
            code,
            entries,
            selected_allocation: allocation(base + 0x0100_0080),
            victim_allocation: allocation(base + 0x0600_0080),
            emission: ArtifactEmission::new(
                TargetProfile::linux_x86_64_legacy_evex(
                    SavedExtendedStateLayout::describe_target_fxsave64(),
                    7,
                )
                .unwrap(),
                SymbolicHook {
                    identity: 11,
                    address: Some(base + 0x1000),
                },
                vec![range(base, 4096)],
            ),
        }
    }

    fn request(&self) -> ArtifactRequest<'_> {
        ArtifactRequest {
            site: PlanningSite {
                identity: self.entries.identity,
                code: &self.code,
                base_address: self.base,
                function: self.entries.scope,
                block: range(self.base + self.selected as u64, 2),
                logical_pc: self.base + self.selected as u64,
                entries: &self.entries,
                semantics: HookSemantics::Observe,
                allocation: &self.selected_allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 15,
                    max_sites: 1,
                },
            },
            emission: &self.emission,
        }
    }

    fn empty(&self) -> Composition {
        Composition::new(
            self.entries.identity,
            vec![ExpectedBytes {
                address: self.base,
                bytes: self.code.clone(),
            }],
        )
        .unwrap()
    }

    fn policy(&self) -> EnginePolicy {
        EnginePolicy {
            forced: Some(Tactic::NeighborEviction),
            neighbor: NeighborSearch {
                forced_victim: None,
                max_victims: 2,
                max_pairs: 2,
            },
            bundle: BundleBudget {
                max_steps: 2,
                max_mappings: 2,
                max_virtual_bytes: 16384,
                max_backing_bytes: 16384,
                max_virtual_span: 1 << 32,
            },
            ..Default::default()
        }
    }

    fn prior(&self, prior: &Composition, at: usize) -> Composition {
        // Independent E9 displacement: only the low byte is replaced; the
        // three original successor bytes are consumed unchanged by this B2.
        let disp = i32::from_le_bytes([0, self.code[at + 2], self.code[at + 3], self.code[at + 4]]);
        let target =
            u64::try_from(i128::from(self.base + at as u64 + 5) + i128::from(disp)).unwrap();
        let allocation = allocation(target);
        let mut request = self.request();
        request.site.logical_pc = self.base + at as u64;
        request.site.block = range(request.site.logical_pc, 2);
        request.site.allocation = &allocation;
        let plan = engine::plan_with_emission_after(
            &request,
            prior,
            &self.victim_allocation,
            EnginePolicy {
                forced: Some(Tactic::GeneralizedPun),
                ..self.policy()
            },
        )
        .unwrap();
        assert!(matches!(
            plan.source_steps()[0].parts().kind,
            PlanKind::GeneralizedPun(_)
        ));
        append(prior, &plan)
    }

    fn plan(
        &self,
        prior: &Composition,
        policy: EnginePolicy,
    ) -> Result<ArtifactPlan, EngineFailure> {
        engine::plan_with_emission_after_and_long_t3_ownership(
            &self.request(),
            prior,
            &self.victim_allocation,
            policy,
        )
    }
}

fn append(prior: &Composition, plan: &ArtifactPlan) -> Composition {
    let mut next = prior.clone();
    for step in plan.source_steps() {
        next.append(step).unwrap();
    }
    next
}

fn details(plan: &ArtifactPlan) -> (&NeighborGeometry, &NeighborMetrics) {
    let ArtifactMetrics::Engine(Tactic::NeighborEviction, SelectedMetrics::Neighbor(g, m), a) =
        plan.metrics()
    else {
        panic!("long T3 metrics")
    };
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].refusal, None);
    assert_eq!(a[0].search, m.search);
    let CandidateEvidence::Neighbor(rows) = &a[0].candidates else {
        panic!("neighbor evidence")
    };
    assert_eq!(rows, &m.attempts);
    assert!(m.search.accepted && !m.search.classification_complete);
    assert!(!plan.qualification_complete());
    (g, m)
}

fn refused(error: &EngineFailure, pairs: usize) {
    assert_eq!(error.reason, Refusal::OwnershipConflict);
    assert_eq!(error.attempts.len(), 1);
    let a = &error.attempts[0];
    assert_eq!(a.tactic, Tactic::NeighborEviction);
    assert_eq!(a.refusal, Some(Refusal::OwnershipConflict));
    assert!(!a.search.accepted && !a.search.classification_complete);
    let CandidateEvidence::Neighbor(rows) = &a.candidates else {
        panic!("neighbor attempts")
    };
    assert_eq!(rows.len(), pairs);
    assert!(
        rows.iter()
            .all(|r| r.stage == NeighborAttemptStage::Composition
                && r.refusal == Some(Refusal::OwnershipConflict))
    );
    assert_eq!(
        a.search
            .runs
            .iter()
            .find(|r| r.domain == SearchDomain::JointPairs)
            .unwrap()
            .examined,
        pairs
    );
}

#[test]
fn long_t3_ownership_continues_past_consumed_suffix_and_keeps_exact_pair() {
    let f = Fixture::new(0);
    let prior = f.prior(&f.empty(), 30);
    let saved = prior.clone();
    assert_eq!(&prior.final_bytes()[0].bytes[32..42], &f.code[32..42]);
    assert!(
        prior
            .locks()
            .iter()
            .any(|r| r.covers(range(f.base + 32, 3)))
    );
    let old =
        engine::plan_with_emission_after(&f.request(), &prior, &f.victim_allocation, f.policy())
            .unwrap();
    assert_eq!(details(&old).0.victim, f.base + 32);
    assert_eq!(
        prior.clone().append(&old.source_steps()[0]),
        Err(Refusal::OwnershipConflict)
    );
    let plan = f.plan(&prior, f.policy()).unwrap();
    let (g, m) = details(&plan);
    assert_eq!(
        (g.selected, g.victim, g.victim_len),
        (f.base, f.base + 16, 10)
    );
    assert_eq!((m.victims_examined, m.pairs_examined), (2, 2));
    assert_eq!(m.attempts.len(), 2);
    assert_eq!(
        (m.attempts[0].victim, &m.attempts[0].refusal),
        (f.base + 32, &Some(Refusal::OwnershipConflict))
    );
    assert_eq!(
        (m.attempts[1].victim, &m.attempts[1].refusal),
        (f.base + 16, &None)
    );
    assert_eq!(
        m.search.runs.iter().map(|r| r.examined).collect::<Vec<_>>(),
        [2, 2, 1, 1, 1, 1]
    );
    let complete = append(&prior, &plan);
    assert_eq!(complete.originals(), prior.originals());
    assert_eq!(&complete.final_bytes()[0].bytes[32..42], &f.code[32..42]);
    assert_eq!(
        plan.source_steps()
            .iter()
            .map(|s| s.parts().physical_pc)
            .collect::<Vec<_>>(),
        [f.base + 16, f.base]
    );
    assert_eq!(&complete.final_bytes()[0].bytes[..2], &[0xeb, 19]);
    assert!(
        complete
            .locks()
            .iter()
            .any(|r| r.covers(range(f.base + 16, 10)))
    );
    assert!(complete.locks().iter().any(|r| r.covers(range(f.base, 2))));
    let mut forced = f.policy();
    forced.neighbor.forced_victim = Some(f.base + 16);
    let reference = f.plan(&prior, forced).unwrap();
    assert_eq!(plan.source_steps(), reference.source_steps());
    assert_eq!(complete, append(&prior, &reference));
    assert_eq!(prior, saved);
}

#[test]
fn long_t3_ownership_conflicting_victims_and_existing_caps_still_refuse() {
    let f = Fixture::new(0);
    let prior = f.prior(&f.empty(), 30);
    let both = f.prior(&prior, 14);
    let saved = both.clone();
    let error = f.plan(&both, f.policy()).unwrap_err();
    refused(&error, 2);
    assert_eq!(
        error.attempts[0].search.runs[0].stop,
        SearchStop::DomainComplete
    );
    assert_eq!(both, saved);
    for victim_cap in [true, false] {
        let mut p = f.policy();
        if victim_cap {
            p.neighbor.max_victims = 1;
        } else {
            p.neighbor.max_pairs = 1;
        }
        let error = f.plan(&prior, p).unwrap_err();
        refused(&error, 1);
        assert_eq!(prior, f.prior(&f.empty(), 30));
    }
}

#[test]
fn long_t3_ownership_checks_selected_member_and_original_authority() {
    let f = Fixture::new(2);
    let prior = f.prior(&f.empty(), 0);
    let saved = prior.clone();
    assert_eq!(&prior.final_bytes()[0].bytes[2..4], &f.code[2..4]);
    let old =
        engine::plan_with_emission_after(&f.request(), &prior, &f.victim_allocation, f.policy())
            .unwrap();
    let mut partial = prior.clone();
    assert_eq!(old.source_steps()[0].parts().physical_pc, f.base + 32);
    partial.append(&old.source_steps()[0]).unwrap();
    let victim_only = partial.clone();
    assert_eq!(
        partial.append(&old.source_steps()[1]),
        Err(Refusal::OwnershipConflict)
    );
    assert_eq!(partial, victim_only);
    refused(&f.plan(&prior, f.policy()).unwrap_err(), 2);
    assert_eq!(prior, saved);
    let mut changed = f.code.clone();
    changed[47] ^= 1;
    let mut request = f.request();
    request.site.code = &changed;
    let failure = engine::plan_with_emission_after_and_long_t3_ownership(
        &request,
        &prior,
        &f.victim_allocation,
        f.policy(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert!(failure.attempts.is_empty());
    request = f.request();
    request.site.identity.generation += 1;
    let failure = engine::plan_with_emission_after_and_long_t3_ownership(
        &request,
        &prior,
        &f.victim_allocation,
        f.policy(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::StaleGeneration);
    assert!(failure.attempts.is_empty());
    assert_eq!(prior, saved);
}
