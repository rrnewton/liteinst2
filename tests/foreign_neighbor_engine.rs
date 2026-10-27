//! Pure source-planning controls; no executable mappings or CPU observations.
use liteinst2::bundle::BundleBudget;
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::emission::*;
use liteinst2::engine::{
    self, CandidateEvidence, EngineAttempt, EnginePolicy, SelectedMetrics, Tactic,
};
use liteinst2::neighbor::NeighborSearch;
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, SearchPolicy};
use liteinst2::search::SearchDomain;
use liteinst2::trampoline::SavedExtendedStateLayout;

const S: u64 = 0x40186c;
const V: u64 = 0x4018e6;
const SB: u64 = 0x401850;
const VB: u64 = 0x4018d0;
const NOP10: [u8; 10] = [0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0];

fn range(pc: u64, len: usize) -> AddressRange {
    AddressRange::new(pc, len).unwrap()
}
fn identity() -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([57; 32]),
        mapping: 15,
        generation: 1,
    }
}
fn allocation(pc: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(pc, 65536)],
        preferred_address: Some(pc),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 65536,
    }
}
fn entries(base: u64, bytes: &[u8], heads: Vec<u64>) -> LegalEntrySet {
    LegalEntrySet {
        identity: identity(),
        scope: range(base, bytes.len()),
        provenance: EntryProvenance::Declared("complete source fixture".into()),
        completeness: EntryCompleteness::Complete,
        entries: heads
            .into_iter()
            .map(|address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    }
}
fn original(name: &str, base: u64) -> (Vec<u8>, LegalEntrySet) {
    let mut bytes = Vec::new();
    let mut heads = Vec::new();
    // Complete committed original table, never a visited/selected subset.
    for line in include_str!("support/e9_common_seed.instructions.tsv")
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = line.split('\t').collect();
        if fields[4] != name {
            continue;
        }
        let pc = u64::from_str_radix(&fields[1][2..], 16).unwrap();
        assert_eq!(pc, base + bytes.len() as u64);
        heads.push(pc);
        for offset in (0..fields[5].len()).step_by(2) {
            bytes.push(u8::from_str_radix(&fields[5][offset..offset + 2], 16).unwrap());
        }
    }
    let e = entries(base, &bytes, heads);
    (bytes, e)
}
struct Fixture {
    selected: Vec<u8>,
    victim: Vec<u8>,
    selected_entries: LegalEntrySet,
    victim_entries: LegalEntrySet,
    selected_allocation: AllocationPolicy,
    victim_allocation: AllocationPolicy,
    emission: ArtifactEmission,
}
impl Fixture {
    fn new() -> Self {
        let (selected, selected_entries) = original("li2_sift_down", SB);
        let (victim, victim_entries) = original("li2_heap_sort", VB);
        assert_eq!((selected.len(), selected_entries.entries.len()), (127, 45));
        assert_eq!((victim.len(), victim_entries.entries.len()), (129, 40));
        Self {
            selected,
            victim,
            selected_entries,
            victim_entries,
            selected_allocation: allocation(0x10000),
            victim_allocation: allocation(0x30000),
            emission: ArtifactEmission::new(
                TargetProfile::linux_x86_64_legacy_evex(
                    SavedExtendedStateLayout::describe_target_fxsave64(),
                    1,
                )
                .unwrap(),
                SymbolicHook {
                    identity: 15,
                    address: Some(0x401960),
                },
                vec![range(0x400000, 0x25000)],
            ),
        }
    }
    fn request(&self) -> ArtifactRequest<'_> {
        ArtifactRequest {
            site: PlanningSite {
                identity: identity(),
                code: &self.selected,
                base_address: self.selected_entries.scope.start(),
                function: self.selected_entries.scope,
                block: range(S, 2),
                logical_pc: S,
                entries: &self.selected_entries,
                semantics: HookSemantics::Observe,
                allocation: &self.selected_allocation,
                search: SearchPolicy {
                    max_sites: 64,
                    max_displaced_bytes: 256,
                    ..SearchPolicy::default()
                },
            },
            emission: &self.emission,
        }
    }
    fn foreign(&self) -> PlanningSite<'_> {
        PlanningSite {
            identity: identity(),
            code: &self.victim,
            base_address: VB,
            function: self.victim_entries.scope,
            block: range(0x4018d6, 26),
            logical_pc: V,
            entries: &self.victim_entries,
            semantics: HookSemantics::Observe,
            allocation: &self.victim_allocation,
            search: self.request().site.search,
        }
    }
    fn predecessor(&self) -> Composition {
        Composition::new(
            identity(),
            vec![
                ExpectedBytes {
                    address: self.selected_entries.scope.start(),
                    bytes: self.selected.clone(),
                },
                ExpectedBytes {
                    address: VB,
                    bytes: self.victim.clone(),
                },
            ],
        )
        .unwrap()
    }
}
fn policy() -> EnginePolicy {
    EnginePolicy {
        neighbor: NeighborSearch {
            forced_victim: None,
            max_victims: 256,
            max_pairs: 4096,
        },
        bundle: BundleBudget {
            max_virtual_span: 1_073_741_824,
            ..BundleBudget::default()
        },
        ..EnginePolicy::default()
    }
}
fn attempts(plan: &ArtifactPlan) -> &[EngineAttempt] {
    let ArtifactMetrics::Engine(_, _, attempts) = plan.metrics() else {
        panic!("engine metrics")
    };
    attempts
}
fn work(attempts: &[EngineAttempt]) -> (usize, usize) {
    let mut counts = (0, 0);
    for run in attempts
        .iter()
        .filter(|a| a.tactic == Tactic::NeighborEviction)
        .flat_map(|a| &a.search.runs)
    {
        if run.domain == SearchDomain::Victims {
            counts.0 += run.examined;
        }
        if run.domain == SearchDomain::JointPairs {
            counts.1 += run.examined;
        }
    }
    counts
}
fn continue_plan(
    f: &Fixture,
    c: &Composition,
    p: EnginePolicy,
    owners: &[PlanningSite<'_>],
) -> Result<ArtifactPlan, engine::EngineFailure> {
    engine::plan_with_emission_after_with_foreign(&f.request(), c, &f.victim_allocation, p, owners)
}
fn local(
    f: &Fixture,
    c: &Composition,
    p: EnginePolicy,
) -> Result<ArtifactPlan, engine::EngineFailure> {
    engine::plan_with_emission_after(&f.request(), c, &f.victim_allocation, p)
}

#[test]
fn empty_foreign_failure_and_local_success_are_unchanged() {
    let mut f = Fixture::new();
    assert_eq!(
        format!("{:?}", local(&f, &f.predecessor(), policy())),
        format!("{:?}", continue_plan(&f, &f.predecessor(), policy(), &[]))
    );
    // Independent small local B1 positive: return it before examining even a
    // malformed duplicate foreign list. This does not substitute for ID15.
    f.selected = vec![0xb8, 42, 0, 0, 0, 0xc3];
    f.selected_entries = entries(S, &f.selected, vec![S, S + 5]);
    let mut r = f.request();
    r.site.block = f.selected_entries.scope;
    let p = EnginePolicy {
        forced: Some(Tactic::Relocation),
        ..policy()
    };
    let old =
        engine::plan_with_emission_after(&r, &f.predecessor(), &f.victim_allocation, p).unwrap();
    let new = engine::plan_with_emission_after_with_foreign(
        &r,
        &f.predecessor(),
        &f.victim_allocation,
        p,
        &[f.foreign(), f.foreign()],
    )
    .unwrap();
    assert_eq!(format!("{old:?}"), format!("{new:?}"));
}

#[test]
fn id15_continuation_retains_all_five_local_refusals_and_exact_foreign_geometry() {
    let f = Fixture::new();
    let c = f.predecessor();
    let old = local(&f, &c, policy()).unwrap_err();
    assert_eq!(old.attempts.len(), 5);
    assert!(old.attempts.iter().all(|a| a.refusal.is_some()));
    let p = continue_plan(&f, &c, policy(), &[f.foreign()]).unwrap();
    assert!(!p.qualification_complete());
    let ArtifactMetrics::Engine(tactic, SelectedMetrics::Neighbor(g, m), all) = p.metrics() else {
        panic!("T3 engine result")
    };
    assert_eq!(*tactic, Tactic::NeighborEviction);
    assert_eq!(all.len(), 6);
    assert_eq!(format!("{:?}", &all[..5]), format!("{:?}", old.attempts));
    assert_eq!(work(all), (1, 1));
    assert_eq!((m.victims_examined, m.pairs_examined), (1, 1));
    assert_eq!((g.selected, g.victim, g.relay, g.rel8), (S, V, V + 5, 125));
    assert_eq!((g.selected_target, g.victim_target), (0x10000, 0x30000));
    assert_eq!(
        p.source_steps()[0].parts().writes[0].bytes,
        vec![0xe9, 0x15, 0xe7, 0xc2, 0xff, 0xe9, 0x10, 0xe7, 0xc0, 0xff]
    );
    assert_eq!(
        p.source_steps()[1].parts().writes[0].bytes,
        vec![0xeb, 0x7d]
    );
    assert_eq!(p.source_steps()[0].parts().entries, f.victim_entries);
    let mut appended = c.clone();
    for step in p.source_steps() {
        appended.append(step).unwrap();
    }
    assert_eq!(c, f.predecessor());
    assert_eq!(appended.locks(), &[range(S, 2), range(V, 10)]);
}

#[test]
fn forced_tactic_and_exact_forced_victim_are_never_substituted() {
    let f = Fixture::new();
    for p in [
        EnginePolicy {
            forced: Some(Tactic::Relocation),
            ..policy()
        },
        EnginePolicy {
            forced: Some(Tactic::NeighborEviction),
            neighbor: NeighborSearch {
                forced_victim: Some(V + 1),
                ..policy().neighbor
            },
            ..policy()
        },
    ] {
        assert_eq!(
            format!("{:?}", local(&f, &f.predecessor(), p)),
            format!(
                "{:?}",
                continue_plan(&f, &f.predecessor(), p, &[f.foreign()])
            )
        );
    }
    let p = EnginePolicy {
        forced: Some(Tactic::NeighborEviction),
        neighbor: NeighborSearch {
            forced_victim: Some(V),
            ..policy().neighbor
        },
        ..policy()
    };
    let result = continue_plan(&f, &f.predecessor(), p, &[f.foreign()]).unwrap();
    assert_eq!(attempts(&result).len(), 2);
    assert_eq!(
        attempts(&result)[0].refusal,
        Some(Refusal::NotInstructionHead)
    );
}

#[test]
fn failed_foreign_qualification_is_retained_and_consumes_the_shared_victim_budget() {
    let f = Fixture::new();
    let mut bad = f.foreign();
    bad.logical_pc = VB;
    bad.block = range(VB, 6);
    let p = EnginePolicy {
        neighbor: NeighborSearch {
            max_victims: 2,
            ..policy().neighbor
        },
        ..policy()
    };
    let result = continue_plan(&f, &f.predecessor(), p, &[bad, f.foreign()]).unwrap();
    assert_eq!(attempts(&result).len(), 7);
    assert_eq!(attempts(&result)[5].refusal, Some(Refusal::NoPatchWindow));
    assert_eq!(work(attempts(&result)), (2, 1));
    let limited = EnginePolicy {
        neighbor: NeighborSearch {
            max_victims: 1,
            ..p.neighbor
        },
        ..p
    };
    let fail = continue_plan(&f, &f.predecessor(), limited, &[bad, f.foreign()]).unwrap_err();
    assert_eq!(fail.attempts.len(), 6);
    assert_eq!(fail.reason, Refusal::NoPatchWindow);
    assert_eq!(work(&fail.attempts), (1, 0));
}

#[test]
fn preflight_refusal_cannot_evade_victim_budget_or_widen_allocations() {
    let f = Fixture::new();
    let mut bad = f.foreign();
    bad.logical_pc = VB;
    bad.block = range(VB, 6);
    bad.identity.generation += 1;
    let p = EnginePolicy {
        neighbor: NeighborSearch {
            max_victims: 1,
            ..policy().neighbor
        },
        ..policy()
    };
    let failed = continue_plan(&f, &f.predecessor(), p, &[bad, f.foreign()]).unwrap_err();
    assert_eq!(failed.reason, Refusal::StaleGeneration);
    assert_eq!(work(&failed.attempts), (1, 0));
    assert_eq!(failed.attempts.len(), 6);
    let expanded = AllocationPolicy {
        max_candidates: 2,
        ..f.victim_allocation.clone()
    };
    bad = f.foreign();
    bad.allocation = &expanded;
    let failed = continue_plan(&f, &f.predecessor(), policy(), &[bad]).unwrap_err();
    assert_eq!(failed.reason, Refusal::InvalidRange);
    assert_eq!(work(&failed.attempts), (1, 0));
}

#[test]
fn exhausted_original_victim_or_pair_budget_never_restarts_at_foreign_owner() {
    for exhaust_pairs in [false, true] {
        let mut f = Fixture::new();
        f.selected = [vec![0xeb, 0], NOP10.to_vec(), vec![0xc3]].concat();
        f.selected_entries = entries(S, &f.selected, vec![S, S + 2, S + 12]);
        if exhaust_pairs {
            f.selected_allocation = f.victim_allocation.clone();
        } else {
            f.selected_entries.entries[1].requires_endbr = true;
        }
        let p = EnginePolicy {
            forced: Some(Tactic::NeighborEviction),
            neighbor: NeighborSearch {
                max_victims: if exhaust_pairs { 2 } else { 1 },
                max_pairs: 1,
                forced_victim: None,
            },
            ..policy()
        };
        let old = local(&f, &f.predecessor(), p).unwrap_err();
        assert_eq!(work(&old.attempts), (1, usize::from(exhaust_pairs)));
        let new = continue_plan(&f, &f.predecessor(), p, &[f.foreign()]).unwrap_err();
        assert_eq!(format!("{old:?}"), format!("{new:?}"));
    }
}

// Structurally admitted prior edits isolate inherited lock/allocation checks;
// they are not an independent semantic or native proof of that predecessor.
fn prior(site: PlanningSite<'_>, allocation: Option<AddressRange>) -> PatchPlan {
    let pc = site.logical_pc;
    PatchPlan::checked(PlanParts {
        identity: site.identity,
        profile: ApplicationProfile::InstallOnce,
        kind: PlanKind::Relocation,
        logical_pc: pc,
        physical_pc: pc,
        displaced: range(pc, 1),
        reads: vec![ExpectedBytes {
            address: site.base_address,
            bytes: site.code.to_vec(),
        }],
        writes: vec![ByteEdit {
            address: pc,
            bytes: vec![site.code[(pc - site.base_address) as usize]],
        }],
        dependencies: vec![range(site.base_address, site.code.len())],
        entries: site.entries.clone(),
        obligations: vec![EntryObligation::Preserved(pc)],
        generated: vec![],
        allocations: allocation
            .into_iter()
            .map(|range| AllocationRequest {
                range,
                alignment: 4096,
            })
            .collect(),
        requirements: PublicationRequirements {
            quiescent: true,
            sync_core: true,
            sigill_router: false,
        },
    })
    .unwrap()
}

#[test]
fn failed_foreign_pair_is_not_reset_and_survives_later_success() {
    let f = Fixture::new();
    let base = 0x401830;
    let bytes = [NOP10.to_vec(), vec![0xc3]].concat();
    let e = entries(base, &bytes, vec![base, base + 10]);
    let bad = PlanningSite {
        code: &bytes,
        base_address: base,
        function: e.scope,
        block: e.scope,
        logical_pc: base,
        entries: &e,
        ..f.foreign()
    };
    let mut originals = f.predecessor().originals().to_vec();
    originals.push(ExpectedBytes {
        address: base,
        bytes: bytes.clone(),
    });
    let mut c = Composition::new(identity(), originals).unwrap();
    c.append(&prior(bad, None)).unwrap();
    let p = EnginePolicy {
        neighbor: NeighborSearch {
            max_victims: 2,
            max_pairs: 1,
            forced_victim: None,
        },
        ..policy()
    };
    let fail = continue_plan(&f, &c, p, &[bad, f.foreign()]).unwrap_err();
    assert_eq!(work(&fail.attempts), (1, 1));
    assert_eq!(fail.reason, Refusal::OwnershipConflict);
    assert_eq!(fail.attempts.len(), 6);
    let p = EnginePolicy {
        neighbor: NeighborSearch {
            max_pairs: 2,
            ..p.neighbor
        },
        ..p
    };
    let result = continue_plan(&f, &c, p, &[bad, f.foreign()]).unwrap();
    assert_eq!(work(attempts(&result)), (2, 2));
    assert_eq!(
        attempts(&result)[5].refusal,
        Some(Refusal::OwnershipConflict)
    );
    assert_eq!(attempts(&result)[6].refusal, None);
    let CandidateEvidence::Neighbor(candidates) = &attempts(&result)[5].candidates else {
        panic!("foreign candidate history")
    };
    assert_eq!(candidates[0].victim, base);
    assert_eq!(candidates[0].refusal, Some(Refusal::OwnershipConflict));
}

#[test]
fn duplicate_eligible_heads_refuse_before_foreign_emission() {
    let f = Fixture::new();
    let old = local(&f, &f.predecessor(), policy()).unwrap_err();
    let fail =
        continue_plan(&f, &f.predecessor(), policy(), &[f.foreign(), f.foreign()]).unwrap_err();
    assert_eq!(fail.reason, Refusal::OwnershipConflict);
    assert_eq!(
        format!("{:?}", &fail.attempts[..5]),
        format!("{:?}", old.attempts)
    );
    assert_eq!(work(&fail.attempts), (0, 0));
    assert_eq!(fail.attempts.len(), 6);
}

#[test]
fn foreign_success_cannot_lose_inherited_site_or_allocation_ownership() {
    let f = Fixture::new();
    for allocated in [false, true] {
        let mut c = f.predecessor();
        let mut held = f.foreign();
        if allocated {
            held.logical_pc = 0x40194c;
        }
        c.append(&prior(held, allocated.then(|| range(0x10000, 4096))))
            .unwrap();
        let before = c.clone();
        let fail = continue_plan(&f, &c, policy(), &[f.foreign()]).unwrap_err();
        assert_eq!(fail.reason, Refusal::OwnershipConflict);
        assert_eq!(work(&fail.attempts), (1, 1));
        assert_eq!(c, before);
    }
}
