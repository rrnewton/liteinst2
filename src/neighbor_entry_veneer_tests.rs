//! Pure artifact integration controls. No executable mapping or host-state query.
use super::*;
use crate::emission::{
    ArtifactEmission, ArtifactRequirement, PlanningSite, SymbolicHook, TargetProfile,
};
use crate::engine::{self, CandidateEvidence, EnginePolicy, SelectedMetrics, Tactic};
use crate::quiescent::{SearchPolicy, TacticPolicy};
use crate::scanner::InstructionScanner;
use crate::trampoline::SavedExtendedStateLayout;
use iced_x86::{Code, Decoder, DecoderOptions};

fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}
fn policy(target: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(target & !4095, 4096)],
        preferred_address: Some(target),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    }
}
struct Fixture {
    base: u64,
    selected: usize,
    victim: usize,
    victim_len: usize,
    code: Vec<u8>,
    entries: LegalEntrySet,
    selected_policy: AllocationPolicy,
    victim_policy: AllocationPolicy,
    emission: ArtifactEmission,
}
impl Fixture {
    fn new(victim_offset: u64, before: bool, long: bool) -> Self {
        let victim = 32;
        let selected = if before { 16 } else { 42 };
        let victim_len = if long { 10 } else { 6 };
        let base = 0x400000 + victim_offset - victim as u64;
        let mut code = vec![0x90; 80];
        let mut operation = vec![0x2e; victim_len - 5];
        operation.extend_from_slice(&[0xb8, 0x37, 0x31, 0x42, 0x53]);
        code[victim..victim + victim_len].copy_from_slice(&operation);
        if !long {
            code[victim + 6..victim + 10].copy_from_slice(&[0x44, 0x8d, 0x48, 0x03]);
        }
        code[selected..selected + 3].copy_from_slice(&[0x75, 0, 0xc3]);
        let entry = if long {
            base + 0x0300_0100
        } else {
            base + victim as u64 + 10 + 0x0348_8d44
        };
        let identity = CodeIdentity {
            source: SourceIdentity([0x69; 32]),
            mapping: 19,
            generation: 7,
        };
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let entries = LegalEntrySet {
            identity,
            scope: range(base, code.len()),
            provenance: EntryProvenance::Declared("entry veneer whole-instruction puzzle".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: scan
                .instructions()
                .iter()
                .map(|i| LegalEntry {
                    address: i.address(),
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let emission = ArtifactEmission::new(
            TargetProfile::linux_x86_64_legacy_evex(
                SavedExtendedStateLayout::describe_target_fxsave64(),
                7,
            )
            .unwrap(),
            SymbolicHook {
                identity: 11,
                address: Some(base + 0x20000),
            },
            vec![range(base & !4095, 8192)],
        );
        Self {
            base,
            selected,
            victim,
            victim_len,
            code,
            entries,
            selected_policy: policy(entry),
            victim_policy: policy(base + victim as u64 + 0x0600_0080),
            emission,
        }
    }
    fn source(&self) -> AddressRange {
        range(self.base, self.code.len())
    }
    fn s(&self) -> u64 {
        self.base + self.selected as u64
    }
    fn v(&self) -> u64 {
        self.base + self.victim as u64
    }
    fn request(&self) -> ArtifactRequest<'_> {
        ArtifactRequest {
            site: PlanningSite {
                identity: self.entries.identity,
                code: &self.code,
                base_address: self.base,
                function: self.source(),
                block: range(self.s(), 2),
                logical_pc: self.s(),
                entries: &self.entries,
                semantics: HookSemantics::Observe,
                allocation: &self.selected_policy,
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
    fn prior(&self) -> Composition {
        Composition::new(
            self.entries.identity,
            vec![ExpectedBytes {
                address: self.base,
                bytes: self.code.clone(),
            }],
        )
        .unwrap()
    }
    fn engine(&self) -> EnginePolicy {
        EnginePolicy {
            forced: Some(Tactic::NeighborEviction),
            successor_puns: TacticPolicy::PreferGeneralizedPun,
            neighbor: NeighborSearch {
                forced_victim: Some(self.v()),
                max_victims: 1,
                max_pairs: 1,
            },
            bundle: BundleBudget {
                max_steps: 2,
                max_mappings: 2,
                max_virtual_bytes: 8192,
                max_backing_bytes: 8192,
                max_virtual_span: 1 << 32,
            },
        }
    }
    fn new_plan(
        &self,
        prior: &Composition,
        pending: &[AddressRange],
        p: EnginePolicy,
    ) -> Result<ArtifactPlan, engine::EngineFailure> {
        engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
            &self.request(),
            prior,
            pending,
            &self.victim_policy,
            p,
        )
    }
    fn old_plan(
        &self,
        prior: &Composition,
        pending: &[AddressRange],
        p: EnginePolicy,
    ) -> Result<ArtifactPlan, engine::EngineFailure> {
        engine::plan_with_emission_after_and_fitting_mixed_t3_pending(
            &self.request(),
            prior,
            pending,
            &self.victim_policy,
            p,
        )
    }
}
fn details(plan: &ArtifactPlan) -> (&NeighborGeometry, &NeighborMetrics) {
    let ArtifactMetrics::Engine(
        Tactic::NeighborEviction,
        SelectedMetrics::Neighbor(g, m),
        attempts,
    ) = plan.metrics()
    else {
        panic!("one T3 engine result")
    };
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].refusal, None);
    assert_eq!(attempts[0].outer_refusal, None);
    assert_eq!(attempts[0].search, m.search);
    let CandidateEvidence::Neighbor(rows) = &attempts[0].candidates else {
        panic!("T3 rows")
    };
    assert_eq!(rows, &m.attempts);
    (g, m)
}
fn append(prior: &Composition, plan: &ArtifactPlan) -> Composition {
    let mut result = prior.clone();
    for step in plan.source_steps() {
        result.append(step).unwrap();
    }
    result
}
fn same_plan(old: &ArtifactPlan, new: &ArtifactPlan) {
    assert_eq!(
        format!("{:?}", old.metrics()),
        format!("{:?}", new.metrics())
    );
    same_output(old, new);
}
fn same_output(old: &ArtifactPlan, new: &ArtifactPlan) {
    assert_eq!(old.source_steps(), new.source_steps());
    let a: Vec<_> = old.images().collect();
    let b: Vec<_> = new.images().collect();
    assert_eq!(a.len(), b.len());
    for (a, b) in a.iter().zip(&b) {
        assert_eq!(a.address(), b.address());
        assert_eq!(a.bytes(), b.bytes());
        assert_eq!(a.entry_address(), b.entry_address());
        assert_eq!(a.entry_veneer(), b.entry_veneer());
        assert_eq!(a.entry_routes(), b.entry_routes());
        assert_eq!(a.instruction_boundaries(), b.instruction_boundaries());
        assert_eq!(a.program_counter_mappings(), b.program_counter_mappings());
        assert_eq!(a.metadata(), b.metadata());
    }
}
fn branch(bytes: &[u8], pc: u64, code: Code, target: u64) {
    let instruction = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE).decode();
    assert_eq!(instruction.code(), code);
    assert_eq!(instruction.near_branch_target(), target);
}

#[test]
fn entry_veneer_pairs_keep_both_source_orders_full_envelope_and_one_slot() {
    let mut cases = 0;
    for offset in [0x11f7, 0x1227] {
        for before in [false, true] {
            let f = Fixture::new(offset, before, false);
            let prior = f.prior();
            let old = f.old_plan(&prior, &[], f.engine()).unwrap_err();
            assert_eq!(old.reason, Refusal::AllocationUnavailable);
            assert_eq!(old.attempts.len(), 1);
            let plan = f.new_plan(&prior, &[], f.engine()).unwrap();
            let (g, m) = details(&plan);
            assert_eq!(
                (g.selected, g.selected_len, g.victim, g.victim_len),
                (f.s(), 2, f.v(), 6)
            );
            assert_eq!((m.victims_examined, m.pairs_examined), (1, 1));
            assert_eq!(
                (
                    m.selected_fallthrough_redirects,
                    m.victim_fallthrough_redirects
                ),
                (4, 2)
            );
            assert_eq!(m.attempts.len(), 2);
            assert_eq!(
                m.attempts[0].stage,
                NeighborAttemptStage::EntryVeneerCertificate
            );
            assert_eq!(m.attempts[0].refusal, Some(Refusal::AllocationUnavailable));
            assert_eq!(m.attempts[0].selected_target, None);
            assert_eq!(m.attempts[1].stage, NeighborAttemptStage::Composition);
            assert_eq!(m.attempts[1].refusal, None);
            for domain in [
                SearchDomain::Victims,
                SearchDomain::JointPairs,
                SearchDomain::VictimImages,
                SearchDomain::SelectedImages,
            ] {
                let rows: Vec<_> = m
                    .search
                    .runs
                    .iter()
                    .filter(|r| r.domain == domain)
                    .collect();
                assert_eq!(rows.len(), 1);
                assert_eq!((rows[0].limit, rows[0].examined), (1, 1));
                assert_eq!(rows[0].stop, crate::search::SearchStop::Accepted);
            }
            assert!(!m.search.classification_complete);
            assert!(!plan.qualification_complete());
            let images: Vec<_> = plan.images().collect();
            assert_eq!(images.len(), 2);
            let wrapped: Vec<_> = images
                .iter()
                .filter(|i| i.entry_veneer().is_some())
                .collect();
            assert_eq!(wrapped.len(), 1);
            let image = wrapped[0];
            let layout = image.entry_veneer().unwrap();
            let entry = f.v() + 10 + 0x0348_8d44;
            assert_eq!(entry & 4095, if offset == 0x11f7 { 3909 } else { 3957 });
            assert_eq!(layout.entry_address(), entry);
            assert_eq!(image.entry_address(), entry);
            assert_eq!(g.selected_target, entry);
            assert_eq!(image.address(), entry & !4095);
            assert_eq!(layout.storage_address(), image.address());
            assert!(layout.body_len() <= layout.size_bound());
            assert!(layout.size_bound() <= (entry - image.address()) as usize);
            assert_eq!(image.bytes().len(), (entry - image.address()) as usize + 5);
            let (lo, hi) = layout.padding_range();
            assert_eq!(
                (lo, hi),
                (image.address() + layout.body_len() as u64, entry)
            );
            assert!(
                image.bytes()[layout.body_len()..(entry - image.address()) as usize]
                    .iter()
                    .all(|&b| b == 0xcc)
            );
            assert_eq!(layout.veneer_range(), (entry, entry + 5));
            branch(
                &image.bytes()[(entry - image.address()) as usize..],
                entry,
                Code::Jmp_rel32_64,
                image.address(),
            );
            let field = image.metadata().fields().last().unwrap();
            assert_eq!(field.offset, entry - image.address() + 1);
            assert_eq!(field.origin, entry - image.address() + 5);
            assert_eq!(field.target, i128::from(image.address()));
            assert!(field.role.starts_with("EntryVeneer"));
            assert_eq!(
                image
                    .metadata()
                    .fields()
                    .iter()
                    .filter(|f| f.role.starts_with("EntryVeneer"))
                    .count(),
                1
            );
            assert!(image.entry_routes().contains(&(f.s(), image.address())));
            assert!(
                image
                    .instruction_boundaries()
                    .iter()
                    .any(|(pc, _)| *pc == f.s())
            );
            assert!(
                image
                    .instruction_boundaries()
                    .iter()
                    .all(|(_, pc)| *pc != entry)
            );
            assert!(
                image
                    .program_counter_mappings()
                    .iter()
                    .any(|p| p.generated_start() == entry
                        && p.generated_end() == entry + 5
                        && p.logical_address() == f.s())
            );
            assert!(
                image
                    .program_counter_mappings()
                    .iter()
                    .all(|p| p.generated_end() <= lo || p.generated_start() >= hi)
            );
            assert!(
                image
                    .metadata()
                    .requirements()
                    .contains(&ArtifactRequirement::HookAbiAndReadiness(11))
            );
            let after = append(&prior, &plan);
            let bytes = &after.final_bytes()[0].bytes;
            branch(&bytes[f.selected..], f.s(), Code::Jmp_rel8_64, f.v() + 5);
            branch(
                &bytes[f.victim..],
                f.v(),
                Code::Jmp_rel32_64,
                g.victim_target,
            );
            branch(&bytes[f.victim + 5..], f.v() + 5, Code::Jmp_rel32_64, entry);
            assert_eq!(
                &bytes[f.victim + 6..f.victim + 10],
                &f.code[f.victim + 6..f.victim + 10]
            );
            for i in 0..bytes.len() {
                if !(f.selected..f.selected + 2).contains(&i)
                    && !(f.victim..f.victim + 10).contains(&i)
                {
                    assert_eq!(bytes[i], f.code[i]);
                }
            }
            let allocations: Vec<_> = plan
                .source_steps()
                .iter()
                .flat_map(|s| &s.parts().allocations)
                .collect();
            assert_eq!(allocations.len(), 2);
            assert_eq!(allocations.iter().map(|a| a.range.len()).sum::<u64>(), 8192);
            assert!(
                allocations
                    .iter()
                    .all(|a| a.range.len() == 4096 && a.alignment == 4096)
            );
            assert!(!allocations[0].range.overlaps(allocations[1].range));
            assert!(
                allocations
                    .iter()
                    .any(|a| a.range == f.selected_policy.ranges[0])
            );
            if offset == 0x11f7 && !before {
                let preferred = f
                    .new_plan(
                        &prior,
                        &[],
                        EnginePolicy {
                            forced: None,
                            ..f.engine()
                        },
                    )
                    .unwrap();
                same_output(&plan, &preferred);
                let ArtifactMetrics::Engine(
                    Tactic::NeighborEviction,
                    SelectedMetrics::Neighbor(pg, pm),
                    history,
                ) = preferred.metrics()
                else {
                    panic!("complete engine frontier into T3")
                };
                assert_eq!(pg, g);
                assert_eq!(pm, m);
                assert_eq!(
                    history.iter().map(|a| a.tactic).collect::<Vec<_>>(),
                    [
                        Tactic::GeneralizedPun,
                        Tactic::Relocation,
                        Tactic::PrefixedPun,
                        Tactic::SuccessorEviction,
                        Tactic::NeighborEviction
                    ]
                );
                assert!(history[..4].iter().all(|a| a.refusal.is_some()));
                let ArtifactMetrics::Engine(_, _, forced_history) = plan.metrics() else {
                    panic!("forced T3 history")
                };
                assert_eq!(
                    format!("{:?}", history[4]),
                    format!("{:?}", forced_history[0])
                );
            }
            assert_eq!(prior, f.prior());
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

#[test]
fn entry_veneer_direct_short_and_long_pairs_keep_exact_old_output() {
    for long in [false, true] {
        for before in [false, true] {
            let f = Fixture::new(0x1400, before, long);
            let prior = f.prior();
            let old = f.old_plan(&prior, &[], f.engine()).unwrap();
            let new = f.new_plan(&prior, &[], f.engine()).unwrap();
            same_plan(&old, &new);
            assert!(
                new.images()
                    .all(|i| i.entry_veneer().is_none() && i.entry_address() == i.address())
            );
            let (g, m) = details(&new);
            assert_eq!(g.victim_len, f.victim_len);
            assert_eq!(
                (m.victims_examined, m.pairs_examined, m.attempts.len()),
                (1, 1, 1)
            );
            assert_eq!(m.selected_fallthrough_redirects, 3);
            assert_eq!(append(&prior, &old), append(&prior, &new));
        }
    }
}

#[test]
fn entry_veneer_pending_suffix_and_inherited_page_ownership_still_refuse() {
    let f = Fixture::new(0x11f7, false, false);
    let prior = f.prior();
    for pending in [range(f.v(), 6), range(f.v() + 6, 4), range(f.s(), 2)] {
        let failure = f.new_plan(&prior, &[pending], f.engine()).unwrap_err();
        assert_eq!(failure.reason, Refusal::OwnershipConflict);
        assert_eq!(failure.attempts.len(), 1);
        let CandidateEvidence::Neighbor(rows) = &failure.attempts[0].candidates else {
            panic!("T3")
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].stage, NeighborAttemptStage::EntryVeneerCertificate);
        assert_eq!(rows[1].stage, NeighborAttemptStage::Composition);
        assert_eq!(rows[1].refusal, Some(Refusal::OwnershipConflict));
        let pairs: Vec<_> = failure.attempts[0]
            .search
            .runs
            .iter()
            .filter(|r| r.domain == SearchDomain::JointPairs)
            .collect();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].examined, 1);
        assert!(!failure.attempts[0].search.accepted);
    }
    let plan = f.new_plan(&prior, &[], f.engine()).unwrap();
    let after = append(&prior, &plan);
    let failure = f
        .new_plan(&after, &[range(f.v() + 6, 4)], f.engine())
        .unwrap_err();
    assert_eq!(failure.reason, Refusal::OwnershipConflict);
    assert!(failure.attempts.is_empty());
    // An independently supplied occupied byte blocks the whole veneer page.
    let occupied = ArtifactEmission::new(
        f.emission.profile().clone(),
        f.emission.hook(),
        vec![range(f.selected_policy.ranges[0].start() + 123, 1)],
    );
    let mut request = f.request();
    request.emission = &occupied;
    let failure = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
        &request,
        &prior,
        &[],
        &f.victim_policy,
        f.engine(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    let CandidateEvidence::Neighbor(rows) = &failure.attempts[0].candidates else {
        panic!("T3")
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].stage, NeighborAttemptStage::SelectedPlacement);
    assert_eq!(rows[0].selected_target, None);
    assert_eq!(prior, f.prior());
}

#[test]
fn entry_veneer_shared_pair_caps_preflight_and_full_byte_budget_are_not_restarted() {
    let f = Fixture::new(0x1227, true, false);
    let prior = f.prior();
    for mutation in 0..7 {
        let mut p = f.engine();
        match mutation {
            0 => p.neighbor.max_pairs = 0,
            1 => p.neighbor.max_victims = 0,
            2 => p.bundle.max_steps = 1,
            3 => p.bundle.max_mappings = 1,
            4 => p.bundle.max_virtual_bytes = 8191,
            5 => p.bundle.max_backing_bytes = 8191,
            6 => p.bundle.max_virtual_span = 4096,
            _ => unreachable!(),
        }
        let failure = f.new_plan(&prior, &[], p).unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert_eq!(failure.attempts.len(), 1);
        assert!(!failure.attempts[0].search.accepted);
        let CandidateEvidence::Neighbor(rows) = &failure.attempts[0].candidates else {
            panic!("T3")
        };
        if mutation == 6 {
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[1].stage, NeighborAttemptStage::Composition);
            assert_eq!(rows[1].refusal, Some(Refusal::AllocationUnavailable));
        } else {
            assert!(rows.is_empty());
        }
    }
    let mut invalid = f.selected_policy.clone();
    invalid.max_candidates = 2;
    let mut request = f.request();
    request.site.allocation = &invalid;
    let outside = [range(f.source().end(), 1)];
    let failure = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
        &request,
        &prior,
        &outside,
        &f.victim_policy,
        f.engine(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::DependencyNotHeld);
    assert!(failure.attempts.is_empty());
    let failure = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
        &request,
        &prior,
        &[],
        &f.victim_policy,
        f.engine(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::InvalidRange);
    assert!(failure.attempts.is_empty());
    let mut changed = f.code.clone();
    changed[0] ^= 1;
    request.site.code = &changed;
    let failure = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
        &request,
        &prior,
        &outside,
        &f.victim_policy,
        f.engine(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert!(failure.attempts.is_empty());
    assert_eq!(prior, f.prior());
}

#[test]
fn entry_veneer_missing_hook_and_emit_errors_do_not_trigger_another_candidate() {
    let f = Fixture::new(0x11f7, false, false);
    let prior = f.prior();
    let missing = ArtifactEmission::new(
        f.emission.profile().clone(),
        SymbolicHook {
            identity: 11,
            address: None,
        },
        vec![],
    );
    let mut request = f.request();
    request.emission = &missing;
    let failure = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
        &request,
        &prior,
        &[],
        &f.victim_policy,
        f.engine(),
    )
    .unwrap_err();
    assert!(matches!(failure.reason, Refusal::Backend(_)));
    assert_eq!(failure.attempts.len(), 1);
    let CandidateEvidence::Neighbor(rows) = &failure.attempts[0].candidates else {
        panic!("T3")
    };
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].stage, NeighborAttemptStage::EntryVeneerCertificate);
    assert_eq!(rows[1].stage, NeighborAttemptStage::SelectedPlacement);
    assert!(matches!(rows[1].refusal, Some(Refusal::Backend(_))));
    for domain in [
        SearchDomain::JointPairs,
        SearchDomain::SelectedImages,
        SearchDomain::VictimImages,
    ] {
        let runs: Vec<_> = failure.attempts[0]
            .search
            .runs
            .iter()
            .filter(|r| r.domain == domain)
            .collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].examined, 1);
    }
    assert_eq!(prior, f.prior());
}

#[test]
fn entry_veneer_first_four_preserve_forced_and_outer_refusal_history() {
    let mut f = Fixture::new(0x1400, false, false);
    f.base = 0x4014f8;
    f.selected = 3;
    f.victim = 5;
    f.victim_len = 2;
    f.code = vec![0x83, 0xf8, 0, 0x75, 0, 0xeb, 0, 0x0f, 0x1f, 0x40, 0, 0xc3];
    f.entries.scope = f.source();
    f.entries.entries = [0, 3, 5, 7, 11]
        .map(|o| LegalEntry {
            address: f.base + o,
            requires_endbr: false,
        })
        .to_vec();
    f.selected_policy = policy(0x0f41_0000);
    f.selected_policy.ranges = vec![range(0x0100_0000, 0x1f00_0000)];
    f.victim_policy = f.selected_policy.clone();
    f.emission = ArtifactEmission::new(
        f.emission.profile().clone(),
        SymbolicHook {
            identity: 11,
            address: Some(0x402000),
        },
        vec![range(0x401000, 4096)],
    );
    let prior = f.prior();
    let pending = [range(f.base + 5, 2)];
    let mut request = f.request();
    request.site.block = range(f.base, 5);
    request.site.search.max_upstream_bytes = 3;
    request.site.search.max_sites = 2;
    let p = EnginePolicy {
        forced: None,
        ..f.engine()
    };
    let old = engine::plan_with_emission_after_and_fitting_mixed_t3_pending(
        &request,
        &prior,
        &pending,
        &f.victim_policy,
        p,
    )
    .unwrap();
    let new = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
        &request,
        &prior,
        &pending,
        &f.victim_policy,
        p,
    )
    .unwrap();
    same_plan(&old, &new);
    let ArtifactMetrics::Engine(Tactic::Relocation, SelectedMetrics::Single(m), attempts) =
        new.metrics()
    else {
        panic!("B2 outer refusal then B1")
    };
    assert_eq!(
        attempts.iter().map(|a| a.tactic).collect::<Vec<_>>(),
        [Tactic::GeneralizedPun, Tactic::Relocation]
    );
    assert_eq!(
        (m.upstream_bytes, m.displaced_bytes, m.allocation_attempts),
        (3, 5, 1)
    );
    assert!(attempts[0].search.accepted);
    assert_eq!(attempts[0].refusal, Some(Refusal::OwnershipConflict));
    assert_eq!(
        attempts[0].outer_refusal.as_ref().unwrap().class,
        RefusalClass::Prerequisite
    );
    assert_eq!(
        append(&prior, &new).require_unclaimed_ranges(&pending),
        Ok(())
    );
    for tactic in [
        Tactic::GeneralizedPun,
        Tactic::Relocation,
        Tactic::PrefixedPun,
        Tactic::SuccessorEviction,
    ] {
        let p = EnginePolicy {
            forced: Some(tactic),
            ..p
        };
        let old = engine::plan_with_emission_after_and_fitting_mixed_t3_pending(
            &request,
            &prior,
            &pending,
            &f.victim_policy,
            p,
        );
        let new = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
            &request,
            &prior,
            &pending,
            &f.victim_policy,
            p,
        );
        match (old, new) {
            (Ok(a), Ok(b)) => same_plan(&a, &b),
            (Err(a), Err(b)) => {
                assert_eq!(a.reason, b.reason);
                assert_eq!(format!("{:?}", a.attempts), format!("{:?}", b.attempts));
                assert_eq!(b.attempts.len(), 1);
            }
            _ => panic!("forced first-four result changed"),
        }
    }
    assert_eq!(prior, f.prior());
}

#[test]
fn entry_veneer_successor_pair_keeps_direct_images_and_complete_admission() {
    let mut f = Fixture::new(0x1400, false, false);
    f.base = 0x4200_0000_0080;
    f.selected = 0;
    f.victim = 3;
    f.victim_len = 8;
    f.code = vec![
        0x0f, 0x1f, 0, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3,
    ];
    f.entries.scope = f.source();
    f.entries.entries = [0, 3, 11, 16]
        .map(|o| LegalEntry {
            address: f.base + o,
            requires_endbr: false,
        })
        .to_vec();
    f.selected_policy = policy(f.base + 5 + 0x56e9_0000 + 0x8000);
    f.victim_policy = policy(f.base + 8 + 0x0012_3456);
    f.emission = ArtifactEmission::new(
        f.emission.profile().clone(),
        SymbolicHook {
            identity: 11,
            address: Some(f.base + 0x1000),
        },
        vec![range(f.base & !4095, 4096)],
    );
    let prior = f.prior();
    let mut request = f.request();
    request.site.block = f.source();
    let p = EnginePolicy {
        forced: Some(Tactic::SuccessorEviction),
        ..f.engine()
    };
    let old = engine::plan_with_emission_after_and_fitting_mixed_t3_pending(
        &request,
        &prior,
        &[],
        &f.victim_policy,
        p,
    )
    .unwrap();
    let new = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
        &request,
        &prior,
        &[],
        &f.victim_policy,
        p,
    )
    .unwrap();
    same_plan(&old, &new);
    assert_eq!(new.images().count(), 2);
    assert!(new.images().all(|i| i.entry_veneer().is_none()));
    let pending = [range(f.v(), 8)];
    let old = engine::plan_with_emission_after_and_fitting_mixed_t3_pending(
        &request,
        &prior,
        &pending,
        &f.victim_policy,
        p,
    )
    .unwrap_err();
    let new = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
        &request,
        &prior,
        &pending,
        &f.victim_policy,
        p,
    )
    .unwrap_err();
    assert_eq!(new.reason, Refusal::OwnershipConflict);
    assert_eq!(new.reason, old.reason);
    assert_eq!(format!("{:?}", new.attempts), format!("{:?}", old.attempts));
    assert_eq!(new.attempts.len(), 1);
    assert!(new.attempts[0].search.accepted);
    assert_eq!(
        new.attempts[0].outer_refusal.as_ref().unwrap().reason,
        Refusal::OwnershipConflict
    );
}

#[test]
fn entry_veneer_checked_member_binds_original_head_full_bytes_and_page() {
    let f = Fixture::new(0x11f7, false, false);
    let request = PlanningRequest::artifact(&f.request());
    let scan = InstructionScanner::default().scan(&f.code, f.base).unwrap();
    let plan = TrampolinePlan::from_symbolic_short_instruction(&scan, f.s(), false).unwrap();
    let prepared = PreparedArtifact::new(&plan, &f.emission).unwrap();
    let entry = f.selected_policy.preferred_address.unwrap();
    let placement =
        crate::trampoline::EntryVeneerPlacement::new(entry & !4095, entry, prepared.size_bound())
            .unwrap();
    let envelope =
        crate::trampoline::ArtifactTrampolineAllocation::emit(prepared, placement).unwrap();
    let image = crate::emission::ArtifactStoredImage::EntryVeneer(envelope.clone());
    let patch = short_redirect(f.s(), f.v()).unwrap().2.to_vec();
    let member = crate::eviction::artifact_instruction_member_core(
        &request,
        f.source(),
        range(f.s(), 2),
        image.clone(),
        placement.mapping(),
        patch.clone(),
    )
    .unwrap();
    member.validate().unwrap();
    assert_eq!(member.plan.parts().generated[0].bytes, envelope.bytes());
    assert_eq!(
        member.plan.parts().generated[0].bytes.len(),
        envelope.placement().storage_len()
    );
    // A structurally valid allocation cannot omit or widen the exact image page.
    let enlarged = crate::eviction::artifact_instruction_member_core(
        &request,
        f.source(),
        range(f.s(), 2),
        image.clone(),
        range(placement.storage_address(), 8192),
        patch.clone(),
    );
    assert!(matches!(enlarged, Err(Refusal::InvalidPlan)));
    // An independently valid original head is not this body's source identity.
    let wrong_head = crate::eviction::artifact_instruction_member_core(
        &request,
        f.source(),
        range(f.v(), 6),
        image,
        placement.mapping(),
        vec![0xeb, 0],
    );
    assert!(matches!(wrong_head, Err(Refusal::InvalidPlan)));
    let mut parts = member.plan.parts().clone();
    parts.generated[0].bytes[envelope.body_len()] ^= 1;
    let altered = crate::emission::ArtifactMember::checked(
        PatchPlan::checked(parts).unwrap(),
        member.image.clone(),
    );
    assert!(matches!(altered, Err(Refusal::InvalidPlan)));
    let mut parts = member.plan.parts().clone();
    parts.generated[0].program_counters.pop();
    let altered = crate::emission::ArtifactMember::checked(
        PatchPlan::checked(parts).unwrap(),
        member.image.clone(),
    );
    assert!(matches!(altered, Err(Refusal::InvalidPlan)));
    // No frame-trace conversion is available for the extended storage layout.
    let pair = f.new_plan(&f.prior(), &[], f.engine()).unwrap();
    assert!(matches!(
        pair.frame_trace_nop5(&f.emission, crate::frame_trace::FrameTraceLimits::default()),
        Err(crate::emission::ArtifactFrameTraceRefusal::UnsupportedPlan)
    ));
}
