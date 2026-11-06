//! Source/contract puzzles; execution is qualified separately by the native oracle.
use super::*;
use crate::emission::{ArtifactEmission, PlanningSite, SymbolicHook, TargetProfile};
use crate::engine::{self, EnginePolicy, SelectedMetrics, Tactic};
use crate::quiescent::{SearchPolicy, TacticPolicy};
use crate::scanner::InstructionScanner;
use crate::search::{SearchDomain, SearchStop};
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
    selected_len: usize,
    victim: usize,
    victim_len: usize,
    code: Vec<u8>,
    entries: LegalEntrySet,
    selected_policy: AllocationPolicy,
    victim_policy: AllocationPolicy,
    emission: ArtifactEmission,
}
impl Fixture {
    fn new(selected_len: usize, victim_len: usize, before: bool) -> Self {
        let base = 0x400000;
        let victim = 32;
        let selected = if before { 16 } else { 48 };
        let mut code = vec![0x90; 80];
        let selected_bytes: &[u8] = match selected_len {
            2 => &[0xff, 0xc0],
            3 => &[0x48, 0xff, 0xc0],
            4 => &[0x48, 0x83, 0xc0, 1],
            _ => panic!("selected grammar"),
        };
        code[selected..selected + selected_len].copy_from_slice(selected_bytes);
        let mut operation = vec![0x2e; victim_len - 5];
        operation.extend_from_slice(&[0xb8, 0x37, 0x31, 0x42, 0x53]);
        code[victim..victim + victim_len].copy_from_slice(&operation);
        let identity = CodeIdentity {
            source: SourceIdentity([0x61; 32]),
            mapping: 19,
            generation: 7,
        };
        // Independent literal head grammar, subsequently checked against decoder.
        let entries = LegalEntrySet {
            identity,
            scope: range(base, code.len()),
            provenance: EntryProvenance::Declared("overlapping relay literal grammar".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: (0..code.len())
                .filter(|&i| {
                    !(selected < i && i < selected + selected_len
                        || victim < i && i < victim + victim_len)
                })
                .map(|i| LegalEntry {
                    address: base + i as u64,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        // Literal byte relation, independent of the production joint solver.
        let selected_target = base + 0x100008;
        let displacement = i32::try_from(selected_target - (base + victim as u64 + 6))
            .unwrap()
            .to_le_bytes();
        let victim_displacement =
            i32::from_le_bytes([0xe9, displacement[0], displacement[1], displacement[2]]);
        let victim_target =
            u64::try_from(i128::from(base + victim as u64 + 5) + i128::from(victim_displacement))
                .unwrap();
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
            vec![range(base, 4096)],
        );
        Self {
            base,
            selected,
            selected_len,
            victim,
            victim_len,
            code,
            entries,
            selected_policy: policy(selected_target),
            victim_policy: policy(victim_target),
            emission,
        }
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
                function: self.entries.scope,
                block: range(self.s(), self.selected_len),
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
    fn policy(&self) -> EnginePolicy {
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
                max_virtual_span: 1 << 29,
            },
        }
    }
    fn plan(
        &self,
        prior: &Composition,
        pending: &[AddressRange],
        policy: EnginePolicy,
    ) -> Result<ArtifactPlan, engine::EngineFailure> {
        engine::plan_with_emission_after_and_overlapping_t3_pending(
            &self.request(),
            prior,
            pending,
            &self.victim_policy,
            policy,
        )
    }
}

fn branch(bytes: &[u8], pc: u64, code: Code, target: u64) {
    let instruction = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE).decode();
    assert_eq!(instruction.code(), code);
    assert_eq!(instruction.near_branch_target(), target);
}

#[test]
fn six_bytes_keep_both_targets_and_all_original_heads_for_sixty_layouts() {
    let mut count = 0;
    for selected_len in 2..=4 {
        for victim_len in 6..=15 {
            for before in [false, true] {
                let f = Fixture::new(selected_len, victim_len, before);
                let prior = f.prior();
                let original = prior.final_bytes().to_vec();
                let scan = InstructionScanner::default().scan(&f.code, f.base).unwrap();
                assert_eq!(
                    scan.instructions()
                        .iter()
                        .map(|i| i.address())
                        .collect::<Vec<_>>(),
                    f.entries
                        .entries
                        .iter()
                        .map(|i| i.address)
                        .collect::<Vec<_>>()
                );
                let plan = f.plan(&prior, &[], f.policy()).unwrap();
                let ArtifactMetrics::Engine(
                    Tactic::NeighborEviction,
                    SelectedMetrics::Neighbor(g, m),
                    attempts,
                ) = plan.metrics()
                else {
                    panic!("forced overlapping T3 result");
                };
                assert_eq!((g.selected, g.victim, g.relay), (f.s(), f.v(), f.v() + 1));
                assert_eq!((g.selected_len, g.victim_len), (selected_len, victim_len));
                assert_eq!(Some(g.selected_target), f.selected_policy.preferred_address);
                assert_eq!(Some(g.victim_target), f.victim_policy.preferred_address);
                assert_eq!((m.victims_examined, m.pairs_examined), (1, 1));
                assert_eq!(
                    (
                        m.selected_fallthrough_redirects,
                        m.victim_fallthrough_redirects
                    ),
                    (3, 2)
                );
                assert_eq!(attempts.len(), 1);
                assert_eq!(m.attempts.len(), 1);
                assert_eq!(m.attempts[0].refusal, None);
                assert_eq!(m.attempts[0].stage, NeighborAttemptStage::Composition);
                for domain in [
                    SearchDomain::Victims,
                    SearchDomain::JointPairs,
                    SearchDomain::SelectedImages,
                    SearchDomain::VictimImages,
                ] {
                    let runs: Vec<_> = m
                        .search
                        .runs
                        .iter()
                        .filter(|r| r.domain == domain)
                        .collect();
                    assert_eq!(runs.len(), 1);
                    assert_eq!((runs[0].examined, runs[0].limit), (1, 1));
                    assert_eq!(runs[0].stop, SearchStop::Accepted);
                }
                assert!(!plan.qualification_complete());
                assert_eq!(plan.source_steps().len(), 2);
                let mut composed = prior.clone();
                for step in plan.source_steps() {
                    let p = step.parts();
                    assert_eq!(p.identity, f.entries.identity);
                    assert_eq!(p.entries, f.entries);
                    assert_eq!(p.dependencies, [f.entries.scope]);
                    assert_eq!(p.allocations.len(), 1);
                    assert_eq!(p.allocations[0].range.len(), 4096);
                    assert_eq!(p.generated.len(), 1);
                    assert!(
                        p.allocations[0]
                            .range
                            .covers(range(p.generated[0].address, p.generated[0].bytes.len()))
                    );
                    assert_eq!(p.writes.len(), 1);
                    assert!(p.requirements.quiescent && p.requirements.sync_core);
                    assert!(!p.requirements.sigill_router);
                    step.check_entry_obligations().unwrap();
                    let edit = &p.writes[0];
                    if p.physical_pc == f.s() {
                        assert_eq!(edit.bytes.len(), 2);
                        branch(&edit.bytes, f.s(), Code::Jmp_rel8_64, f.v() + 1);
                    } else {
                        assert_eq!(p.physical_pc, f.v());
                        assert_eq!(edit.bytes.len(), 6);
                        assert_eq!(&edit.bytes[..2], &[0xe9, 0xe9]);
                        branch(&edit.bytes[..5], f.v(), Code::Jmp_rel32_64, g.victim_target);
                        branch(
                            &edit.bytes[1..],
                            f.v() + 1,
                            Code::Jmp_rel32_64,
                            g.selected_target,
                        );
                    }
                    composed.append(step).unwrap();
                }
                let final_bytes = &composed.final_bytes()[0].bytes;
                for (offset, original_byte) in f.code.iter().enumerate() {
                    if !(f.selected..f.selected + 2).contains(&offset)
                        && !(f.victim..f.victim + 6).contains(&offset)
                    {
                        assert_eq!(final_bytes[offset], *original_byte);
                    }
                }
                assert_eq!(prior.final_bytes(), original);
                let images: Vec<_> = plan.images().collect();
                assert_eq!(images.len(), 2);
                for image in images {
                    assert_eq!(image.address(), image.entry_address());
                    assert!(image.entry_veneer().is_none());
                    let logical = if image.address() == g.selected_target {
                        f.s()
                    } else {
                        f.v()
                    };
                    assert_eq!(image.entry_routes(), [(logical, image.address())]);
                    assert_eq!(image.instruction_boundaries().len(), 1);
                    assert_eq!(image.instruction_boundaries()[0].0, logical);
                }
                count += 1;
            }
        }
    }
    assert_eq!(count, 60);
}

#[test]
fn new_family_needs_no_successor_fetch_and_keeps_old_refusal() {
    let mut f = Fixture::new(2, 6, true);
    f.code.truncate(f.victim + f.victim_len);
    f.entries.scope = range(f.base, f.code.len());
    f.entries
        .entries
        .retain(|entry| f.entries.scope.contains(entry.address));
    let prior = f.prior();
    let old = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
        &f.request(),
        &prior,
        &[],
        &f.victim_policy,
        f.policy(),
    )
    .unwrap_err();
    assert_eq!(old.reason, Refusal::NoPatchWindow);
    let plan = f.plan(&prior, &[], f.policy()).unwrap();
    assert_eq!(plan.source_steps().len(), 2);
    for step in plan.source_steps() {
        for edit in &step.parts().writes {
            assert!(
                f.entries
                    .scope
                    .covers(range(edit.address, edit.bytes.len()))
            );
        }
    }
}

#[test]
fn pending_victim_and_prior_edits_refuse_without_mutating_predecessor() {
    let f = Fixture::new(2, 6, true);
    let prior = f.prior();
    let original = prior.final_bytes().to_vec();
    let failure = f.plan(&prior, &[range(f.v(), 6)], f.policy()).unwrap_err();
    assert_eq!(failure.reason, Refusal::OwnershipConflict);
    assert_eq!(prior.final_bytes(), original);
    // A pending instruction after the whole victim remains completely untouched.
    let plan = f.plan(&prior, &[range(f.v() + 6, 1)], f.policy()).unwrap();
    let mut composed = prior.clone();
    for step in plan.source_steps() {
        composed.append(step).unwrap();
    }
    let before = composed.final_bytes().to_vec();
    let failure = f.plan(&composed, &[], f.policy()).unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert_eq!(composed.final_bytes(), before);
}

#[test]
fn relay_interior_cannot_be_declared_an_original_entry() {
    let mut f = Fixture::new(2, 6, true);
    f.entries.entries.push(LegalEntry {
        address: f.v() + 1,
        requires_endbr: false,
    });
    f.entries.entries.sort_by_key(|entry| entry.address);
    let failure = f.plan(&f.prior(), &[], f.policy()).unwrap_err();
    assert_eq!(failure.reason, Refusal::NotInstructionHead);
}

#[test]
fn original_limits_and_zero_work_bounds_remain_strict() {
    let f = Fixture::new(2, 6, true);
    let p = f.policy();
    for altered in [
        EnginePolicy {
            neighbor: NeighborSearch {
                max_pairs: 0,
                ..p.neighbor
            },
            ..p
        },
        EnginePolicy {
            neighbor: NeighborSearch {
                max_victims: 0,
                ..p.neighbor
            },
            ..p
        },
        EnginePolicy {
            bundle: BundleBudget {
                max_steps: 1,
                ..p.bundle
            },
            ..p
        },
        EnginePolicy {
            bundle: BundleBudget {
                max_mappings: 1,
                ..p.bundle
            },
            ..p
        },
        EnginePolicy {
            bundle: BundleBudget {
                max_virtual_bytes: 8191,
                ..p.bundle
            },
            ..p
        },
        EnginePolicy {
            bundle: BundleBudget {
                max_backing_bytes: 8191,
                ..p.bundle
            },
            ..p
        },
        EnginePolicy {
            bundle: BundleBudget {
                max_virtual_span: 4096,
                ..p.bundle
            },
            ..p
        },
    ] {
        assert_eq!(
            f.plan(&f.prior(), &[], altered).unwrap_err().reason,
            Refusal::AllocationUnavailable
        );
    }
}

#[test]
fn overlapping_rel8_endpoints_are_exact() {
    assert_eq!(redirect(200, 73), Ok((74, -128, [0xeb, 0x80])));
    assert_eq!(redirect(200, 328), Ok((329, 127, [0xeb, 0x7f])));
    assert_eq!(redirect(200, 72), Err(Refusal::NoPatchWindow));
    assert_eq!(redirect(200, 329), Err(Refusal::NoPatchWindow));
    assert_eq!(redirect(u64::MAX, 0), Err(Refusal::InvalidRange));
    assert_eq!(redirect(0, u64::MAX), Err(Refusal::InvalidRange));
}
