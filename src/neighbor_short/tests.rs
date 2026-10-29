//! Artifact/contract puzzles only. No mapped code, callback or native witness.
use super::*;
use crate::composition::Composition;
use crate::emission::{ArtifactEmission, PlanningSite, SymbolicHook, TargetProfile};
use crate::quiescent::{SearchPolicy, TacticPolicy};
use crate::search::{CandidateProof, SearchStop};
use crate::trampoline::SavedExtendedStateLayout;

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

fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}

fn policy(target: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(target & !4095, 8192)],
        preferred_address: Some(target),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 8192,
    }
}

impl Fixture {
    fn new(selected_len: usize, victim_len: usize, delta: i64) -> Self {
        let base = 0x4200_0000_0000;
        let selected = 256;
        let victim = usize::try_from(selected as i64 + delta).unwrap();
        let mut code = vec![0x90; 512];
        let selected_bytes: &[u8] = match selected_len {
            2 => &[0xff, 0xc0],
            3 => &[0x48, 0xff, 0xc0],
            4 => &[0x48, 0x83, 0xc0, 1],
            _ => panic!("fixture selected length"),
        };
        code[selected..selected + selected_len].copy_from_slice(selected_bytes);
        code[selected + selected_len] = 0xc3;
        // One complete original instruction, not an artificially split victim.
        let mut operation = vec![0x2e; victim_len - 5];
        operation.extend_from_slice(&[0xb8, 0x27, 0x31, 0x42, 0x53]);
        code[victim..victim + victim_len].copy_from_slice(&operation);
        code[victim + victim_len + 4] = 0xc3;
        let identity = CodeIdentity {
            source: SourceIdentity([31; 32]),
            mapping: 19,
            generation: 7,
        };
        let entries = LegalEntrySet {
            identity,
            scope: range(base, code.len()),
            provenance: EntryProvenance::Declared("literal short-victim fixture".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: (0..code.len())
                .filter(|&i| {
                    !(selected < i && i < selected + selected_len)
                        && !(victim < i && i < victim + victim_len)
                })
                .map(|i| LegalEntry {
                    address: base + i as u64,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        // Independent literal E9 arithmetic; does not call Relay or decoder.
        let mut final_view = code.clone();
        final_view[selected] = 0xeb;
        final_view[selected + 1] = i8::try_from(delta + 3).unwrap() as u8;
        let free = victim_len - 6;
        let mut displacement = [0_u8; 4];
        displacement[free..].copy_from_slice(&final_view[victim + victim_len..victim + 10]);
        let target = u64::try_from(
            i128::from(base + victim as u64 + 10) + i128::from(i32::from_le_bytes(displacement)),
        )
        .unwrap();
        let emission = ArtifactEmission::new(
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
        );
        Self {
            base,
            selected,
            selected_len,
            victim,
            victim_len,
            code,
            entries,
            selected_policy: policy(target),
            victim_policy: policy(base + victim as u64 + 0x0600_0043),
            emission,
        }
    }

    fn source(&self) -> AddressRange {
        range(self.base, self.code.len())
    }
    fn v(&self) -> u64 {
        self.base + self.victim as u64
    }
    fn s(&self) -> u64 {
        self.base + self.selected as u64
    }
    fn request(&self) -> ArtifactRequest<'_> {
        ArtifactRequest {
            site: PlanningSite {
                identity: self.entries.identity,
                code: &self.code,
                base_address: self.base,
                function: self.source(),
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
    fn search(&self) -> NeighborSearch {
        NeighborSearch {
            forced_victim: Some(self.v()),
            max_victims: 1,
            max_pairs: 1,
        }
    }
    fn plan(&self) -> ArtifactPlan {
        plan_neighbor_short_with_emission(
            &self.request(),
            &self.victim_policy,
            self.search(),
            BundleBudget::default(),
        )
        .unwrap()
    }
    fn relay(&self) -> Relay {
        Relay::new(
            &PlanningRequest::artifact(&self.request()),
            self.source(),
            range(self.v(), self.victim_len),
            short_redirect(self.s(), self.v()).unwrap().2,
        )
        .unwrap()
    }
    fn composition(&self, plan: &ArtifactPlan) -> Composition {
        let mut result = Composition::new(
            self.entries.identity,
            vec![ExpectedBytes {
                address: self.base,
                bytes: self.code.clone(),
            }],
        )
        .unwrap();
        for step in plan.source_steps() {
            result.append(step).unwrap();
        }
        result
    }
}

#[test]
fn short_endpoints_preserve_whole_victims_and_all_successor_bytes() {
    let mut cases = 0;
    for selected_len in 2..=4 {
        for victim_len in 6..=9 {
            for delta in [-131, 124] {
                let f = Fixture::new(selected_len, victim_len, delta);
                let plan = f.plan();
                assert!(!plan.qualification_complete());
                assert_eq!(plan.images().count(), 2);
                let ArtifactMetrics::Neighbor(g, m) = plan.metrics() else {
                    panic!("metrics")
                };
                assert_eq!(
                    (g.selected, g.selected_len, g.victim, g.victim_len),
                    (f.s(), selected_len, f.v(), victim_len)
                );
                assert_eq!(
                    (g.relay, g.rel8),
                    (f.v() + 5, if delta < 0 { -128 } else { 127 })
                );
                assert_eq!(
                    (m.victims_examined, m.pairs_examined, m.attempts.len()),
                    (1, 1, 1)
                );
                assert_eq!(
                    (
                        m.selected_fallthrough_redirects,
                        m.victim_fallthrough_redirects
                    ),
                    (3, 2)
                );
                assert!(m.search.accepted);
                let step = plan
                    .source_steps()
                    .iter()
                    .find(|p| p.parts().physical_pc == f.v())
                    .unwrap();
                assert_eq!(step.parts().displaced, range(f.v(), victim_len));
                assert_eq!(step.parts().writes[0].bytes.len(), 10);
                let bytes = &step.parts().writes[0].bytes;
                assert_eq!((bytes[0], bytes[5]), (0xe9, 0xe9));
                let first = i32::from_le_bytes(bytes[1..5].try_into().unwrap());
                let second = i32::from_le_bytes(bytes[6..10].try_into().unwrap());
                assert_eq!(
                    i128::from(f.v() + 5) + i128::from(first),
                    i128::from(g.victim_target)
                );
                assert_eq!(
                    i128::from(f.v() + 10) + i128::from(second),
                    i128::from(g.selected_target)
                );
                assert!(!f.entries.entries.iter().any(|e| e.address == g.relay));
                assert!(
                    f.entries
                        .entries
                        .iter()
                        .any(|e| e.address == f.v() + victim_len as u64)
                );
                assert!(matches!(step.parts().kind, PlanKind::Relocation));
                assert_eq!(
                    &step.parts().writes[0].bytes[victim_len..],
                    &f.code[f.victim + victim_len..f.victim + 10]
                );
                let c = f.composition(&plan);
                assert!(c.locks().iter().any(|r| r.covers(range(f.v(), 10))));
                let final_bytes = &c.final_bytes()[0].bytes;
                for i in 0..f.code.len() {
                    if !(f.victim..f.victim + victim_len).contains(&i)
                        && !(f.selected..f.selected + 2).contains(&i)
                    {
                        assert_eq!(final_bytes[i], f.code[i], "preserved byte {i}");
                    }
                }
                assert_eq!(
                    plan_neighbor_with_emission(
                        &f.request(),
                        &f.victim_policy,
                        f.search(),
                        BundleBudget::default()
                    )
                    .unwrap_err()
                    .reason,
                    Refusal::NoPatchWindow
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 24);
}

#[test]
fn short_window_sign_endpoints_and_reencoding_are_exact() {
    for len in 6..=9 {
        for high in [0_u8, 0x7f, 0x80, 0xff] {
            let mut f = Fixture::new(2, len, 124);
            f.code[f.victim + len..f.victim + 10].fill(0);
            f.code[f.victim + 9] = high;
            let r = f.relay();
            let low = u64::try_from(
                i128::from(f.v() + 10) + i128::from(i32::from_le_bytes([0, 0, 0, high])),
            )
            .unwrap();
            assert_eq!(r.window(), range(low, 1_usize << (8 * (len - 6))));
            for target in [r.window().start(), r.window().end() - 1] {
                let mut patch =
                    near_redirect(f.v(), f.victim_policy.preferred_address.unwrap()).unwrap();
                patch.extend_from_slice(&near_redirect(f.v() + 5, target).unwrap());
                assert_eq!(r.check_patch(&patch, target), Ok(()));
                for index in 5..10 {
                    let mut changed = patch.clone();
                    changed[index] ^= 1;
                    assert!(r.check_patch(&changed, target).is_err());
                }
                assert!(r.check_patch(&patch[..9], target).is_err());
                assert_eq!(
                    r.check_patch(&patch, low - 1),
                    Err(Refusal::AllocationUnavailable)
                );
                assert_eq!(
                    r.check_patch(&patch, r.window().end()),
                    Err(Refusal::AllocationUnavailable)
                );
            }
        }
    }
    let f = Fixture::new(2, 6, 124);
    let original = f.request();
    // Helper-only range arithmetic controls, not decodable-source claims.
    for v in [u64::MAX - 9, u64::MAX - 6] {
        assert!(
            Relay::new(
                &PlanningRequest::artifact(&original),
                f.source(),
                range(v, 6),
                [0xeb, 0]
            )
            .is_err()
        );
    }
    let mut low = original;
    low.site.base_address = 0;
    low.site.function = range(0, f.code.len());
    low.site.logical_pc = f.selected as u64;
    let mut low_entries = f.entries.clone();
    low_entries.scope = low.site.function;
    low.site.entries = &low_entries;
    assert!(matches!(
        Relay::new(
            &PlanningRequest::artifact(&low),
            low.site.function,
            range(f.victim as u64, 6),
            short_redirect(low.site.logical_pc, f.victim as u64)
                .unwrap()
                .2
        ),
        Err(Refusal::AllocationUnavailable)
    ));
    let mut positive = f.code.clone();
    positive[f.victim + 9] = 0x7f;
    let base = u64::MAX - 1024;
    let mut high = original;
    high.site.code = &positive;
    high.site.base_address = base;
    high.site.function = range(base, positive.len());
    high.site.logical_pc = base + f.selected as u64;
    let mut entries = f.entries.clone();
    entries.scope = high.site.function;
    high.site.entries = &entries;
    assert!(
        Relay::new(
            &PlanningRequest::artifact(&high),
            high.site.function,
            range(base + f.victim as u64, 6),
            short_redirect(high.site.logical_pc, base + f.victim as u64)
                .unwrap()
                .2
        )
        .is_err()
    );
    // Start is representable but the complete free-byte window end is not.
    let f = Fixture::new(2, 9, 124);
    let mut bytes = f.code.clone();
    bytes[f.victim + 9] = 0x7f;
    let base = u64::MAX - 128 - 0x7f00_0000 - f.victim as u64 - 10;
    let mut request = f.request();
    request.site.base_address = base;
    request.site.code = &bytes;
    request.site.function = range(base, bytes.len());
    request.site.logical_pc = base + f.selected as u64;
    let mut entries = f.entries.clone();
    entries.scope = request.site.function;
    request.site.entries = &entries;
    assert!(matches!(
        Relay::new(
            &PlanningRequest::artifact(&request),
            request.site.function,
            range(base + f.victim as u64, 9),
            short_redirect(request.site.logical_pc, base + f.victim as u64)
                .unwrap()
                .2
        ),
        Err(Refusal::InvalidRange)
    ));
}

#[test]
fn selected_inside_suffix_uses_exact_prospective_overlay() {
    for selected_len in 2..=4 {
        for len in 6..=9 {
            let f = Fixture::new(selected_len, len, -(len as i64));
            let plan = f.plan();
            assert_eq!(plan.source_steps()[0].parts().physical_pc, f.s());
            assert_eq!(plan.source_steps()[1].parts().physical_pc, f.v());
            let r = f.relay();
            let patch = &plan.source_steps()[1].parts().writes[0].bytes;
            let first_view = &plan.source_steps()[1].parts().reads[0].bytes;
            assert_eq!(
                &first_view[f.selected..f.selected + 2],
                &[0xeb, (-((len as i8) - 3)) as u8]
            );
            let initial = PlanningRequest::artifact(&f.request());
            assert_eq!(
                r.check_current(&initial, f.source(), patch),
                Err(Refusal::ExpectedBytesChanged)
            );
            assert_eq!(
                r.check_current(&initial.with_code(first_view), f.source(), patch),
                Ok(())
            );
            let c = f.composition(&plan);
            assert_eq!(
                &c.final_bytes()[0].bytes[f.victim + len..f.victim + 10],
                &first_view[f.victim + len..f.victim + 10]
            );
            let mut stale = f.selected_policy.clone();
            let mut disp = [0; 4];
            disp[len - 6..].copy_from_slice(&f.code[f.victim + len..f.victim + 10]);
            let stale_target =
                u64::try_from(i128::from(f.v() + 10) + i128::from(i32::from_le_bytes(disp)))
                    .unwrap();
            stale = AllocationPolicy {
                preferred_address: Some(stale_target),
                ..stale
            };
            stale.ranges = vec![range(stale_target & !4095, 8192)];
            let mut request = f.request();
            request.site.allocation = &stale;
            assert!(
                plan_neighbor_short_with_emission(
                    &request,
                    &f.victim_policy,
                    f.search(),
                    BundleBudget::default()
                )
                .is_err()
            );
            let mut forged = short_redirect(f.s(), f.v()).unwrap().2;
            forged[1] ^= 1;
            assert!(Relay::new(&initial, f.source(), range(f.v(), len), forged).is_err());
        }
    }
    // Private-helper current-view arithmetic control: this manual view is not
    // an authenticated Composition::planning_overlay predecessor. The original
    // selected/victim bytes still qualify; the relay must bind the supplied view.
    let f = Fixture::new(2, 8, 124);
    let mut current = f.code.clone();
    current[f.victim + 9] = 0x91;
    let target =
        u64::try_from(i128::from(f.v() + 10) + i128::from(i32::from_le_bytes([0, 0, 0x90, 0x91])))
            .unwrap();
    let allocation = policy(target);
    let mut request = f.request();
    request.site.allocation = &allocation;
    let original = PlanningRequest::artifact(&request);
    let plan = plan_neighbor_mode(
        &original.with_code(&current),
        &f.victim_policy,
        f.search(),
        BundleBudget::default(),
        true,
    )
    .unwrap();
    assert_eq!(plan.geometry().selected_target, target);
    assert_eq!(plan.bundle().plan().originals()[0].bytes, current);
    assert_eq!(
        plan.bundle().plan().final_bytes()[0].bytes[f.victim + 9],
        0x91
    );
}

#[test]
fn full_fetch_scope_original_identity_and_boundaries_fail_closed() {
    for len in 6..=9 {
        let f = Fixture::new(2, len, 124);
        let original = f.request();
        for bytes in len..10 {
            let mut request = original;
            request.site.code = &f.code[..f.victim + bytes];
            request.site.function = range(f.base, f.victim + bytes);
            let mut entries = f.entries.clone();
            entries.scope = request.site.function;
            let scope = entries.scope;
            entries.entries.retain(|e| scope.contains(e.address));
            request.site.entries = &entries;
            assert!(
                plan_neighbor_short_with_emission(
                    &request,
                    &f.victim_policy,
                    f.search(),
                    BundleBudget::default()
                )
                .is_err()
            );
        }
        // Keep source and entry authority complete; omit only function-owned
        // suffix bytes while retaining both whole original instructions.
        for bytes in len..10 {
            let mut request = original;
            request.site.function = range(f.base, f.victim + bytes);
            assert_eq!(
                plan_neighbor_short_with_emission(
                    &request,
                    &f.victim_policy,
                    f.search(),
                    BundleBudget::default()
                )
                .unwrap_err()
                .reason,
                Refusal::NoPatchWindow
            );
        }
        let mut request = original;
        request.site.function = range(f.base, f.victim + 10);
        let complete = plan_neighbor_short_with_emission(
            &request,
            &f.victim_policy,
            f.search(),
            BundleBudget::default(),
        )
        .unwrap();
        let ArtifactMetrics::Neighbor(geometry, _) = complete.metrics() else {
            panic!("metrics")
        };
        assert_eq!(geometry.victim_len, len);
        let mut entries = f.entries.clone();
        entries.scope = range(f.base, f.victim + len);
        let scope = entries.scope;
        entries.entries.retain(|e| scope.contains(e.address));
        let mut request = original;
        request.site.entries = &entries;
        assert_eq!(
            plan_neighbor_short_with_emission(
                &request,
                &f.victim_policy,
                f.search(),
                BundleBudget::default()
            )
            .unwrap_err()
            .reason,
            Refusal::UnresolvedEntry
        );
        for mutation in 0..4 {
            let mut entries = f.entries.clone();
            match mutation {
                0 => entries.entries.push(LegalEntry {
                    address: f.v() + 5,
                    requires_endbr: false,
                }),
                1 => {
                    entries
                        .entries
                        .iter_mut()
                        .find(|e| e.address == f.v())
                        .unwrap()
                        .requires_endbr = true
                }
                2 => entries.completeness = EntryCompleteness::Incomplete,
                3 => entries.resumes = ResumeObligation::Unresolved,
                _ => unreachable!(),
            }
            let mut request = original;
            request.site.entries = &entries;
            assert!(
                plan_neighbor_short_with_emission(
                    &request,
                    &f.victim_policy,
                    f.search(),
                    BundleBudget::default()
                )
                .is_err()
            );
        }
        let initial = PlanningRequest::artifact(&original);
        for offset in [f.selected, f.victim, f.victim + len - 1] {
            let mut changed = f.code.clone();
            changed[offset] ^= 1;
            assert_eq!(
                plan_neighbor_mode(
                    &initial.with_code(&changed),
                    &f.victim_policy,
                    f.search(),
                    BundleBudget::default(),
                    true
                )
                .unwrap_err()
                .reason,
                Refusal::ExpectedBytesChanged
            );
        }
    }
    for victim_delta in [-132, 125] {
        let f = Fixture::new(2, 6, if victim_delta < 0 { -131 } else { 124 });
        assert_eq!(
            short_redirect(f.s(), (f.s() as i64 + victim_delta) as u64),
            Err(Refusal::NoPatchWindow)
        );
    }
    // The full relay fetch crosses both a cache line and a page; this is a
    // quiescent bundle, not the standalone atomic-pun store contract.
    let mut f = Fixture::new(2, 8, -131);
    let shift = 4092 - f.victim as u64;
    f.base += shift;
    f.entries.scope = f.source();
    for e in &mut f.entries.entries {
        e.address += shift;
    }
    f.selected_policy = policy(f.selected_policy.preferred_address.unwrap() + shift);
    f.victim_policy = policy(f.victim_policy.preferred_address.unwrap() + shift);
    f.emission = ArtifactEmission::new(
        f.emission.profile().clone(),
        f.emission.hook(),
        vec![f.source()],
    );
    assert_eq!(f.v() & 4095, 4092);
    assert_eq!(f.plan().source_steps().len(), 2);
}

#[test]
fn suffix_locks_and_leases_keep_all_ten_bytes_protected() {
    for len in 6..=9 {
        let f = Fixture::new(2, len, 124);
        let plan = f.plan();
        let c = f.composition(&plan);
        let victim = plan
            .source_steps()
            .iter()
            .find(|p| p.parts().physical_pc == f.v())
            .unwrap();
        for offset in len..10 {
            let mut parts = victim.parts().clone();
            parts.logical_pc = f.base + 16;
            parts.physical_pc = f.base + 16;
            parts.displaced = range(f.base + 16, 1);
            parts.reads = c.final_bytes().to_vec();
            parts.obligations = vec![EntryObligation::Preserved(f.base + 16)];
            parts.generated.clear();
            parts.allocations.clear();
            parts.writes = vec![ByteEdit {
                address: f.v() + offset as u64,
                bytes: vec![c.final_bytes()[0].bytes[f.victim + offset]],
            }];
            let same = PatchPlan::checked(parts.clone()).unwrap();
            let mut next = c.clone();
            next.append(&same).unwrap();
            assert_eq!(next.final_bytes(), c.final_bytes());
            parts.writes[0].bytes[0] ^= 1;
            let changed = PatchPlan::checked(parts).unwrap();
            let mut next = c.clone();
            assert_eq!(next.append(&changed), Err(Refusal::OwnershipConflict));
            assert_eq!(next, c);
            let mut mutated = f.code.clone();
            mutated[f.victim + offset] ^= 1;
            let mut stale = Composition::new(
                f.entries.identity,
                vec![ExpectedBytes {
                    address: f.base,
                    bytes: mutated,
                }],
            )
            .unwrap();
            assert_eq!(
                stale.append(&plan.source_steps()[0]),
                Err(Refusal::ExpectedBytesChanged)
            );
        }
        let mut guard = ();
        // SAFETY: mock metadata only, as in contracts::tests. No live source,
        // publisher, callback or generated executable authority exists here.
        let lease = unsafe {
            QuiescenceLease::new(
                &mut guard,
                f.entries.identity,
                vec![range(f.base, f.victim + 9)],
            )
        };
        assert_eq!(lease.check(victim), Err(Refusal::DependencyNotHeld));
        drop(lease);
        // SAFETY: same metadata-only mock as above, never passed to a publisher.
        let lease =
            unsafe { QuiescenceLease::new(&mut guard, f.entries.identity, vec![f.source()]) };
        assert_eq!(lease.check(victim), Ok(()));
        drop(lease);
        let mut identity = f.entries.identity;
        identity.generation += 1;
        // SAFETY: same metadata-only mock; the stale identity is expected to refuse.
        let lease = unsafe { QuiescenceLease::new(&mut guard, identity, vec![f.source()]) };
        assert_eq!(lease.check(victim), Err(Refusal::StaleGeneration));
        drop(lease);

        // This separate source ends at the relay-fetch boundary. The shorter
        // lease therefore omits exactly one borrowed suffix byte and nothing else.
        let mut tight = Fixture::new(2, len, 124);
        tight.code.truncate(tight.victim + 10);
        tight.entries.scope = tight.source();
        let scope = tight.entries.scope;
        tight
            .entries
            .entries
            .retain(|entry| scope.contains(entry.address));
        let plan = tight.plan();
        let victim = plan
            .source_steps()
            .iter()
            .find(|step| step.parts().physical_pc == tight.v())
            .unwrap();
        assert_eq!(tight.source().end(), tight.v() + 10);
        assert!(victim.parts().dependencies.contains(&tight.source()));
        assert!(
            tight
                .composition(&plan)
                .locks()
                .iter()
                .any(|lock| lock.covers(range(tight.v(), 10)))
        );
        // SAFETY: metadata-only mock, never passed to a publisher.
        let lease = unsafe {
            QuiescenceLease::new(&mut guard, tight.entries.identity, vec![tight.source()])
        };
        assert_eq!(lease.check(victim), Ok(()));
        drop(lease);
        // SAFETY: same metadata-only mock; only the last source byte is unheld.
        let lease = unsafe {
            QuiescenceLease::new(
                &mut guard,
                tight.entries.identity,
                vec![range(tight.base, tight.code.len() - 1)],
            )
        };
        assert_eq!(lease.check(victim), Err(Refusal::DependencyNotHeld));
    }
}

#[test]
fn short_search_charges_real_pairs_and_keeps_full_mapping_limits() {
    let mut f = Fixture::new(2, 9, 124);
    let target = f.selected_policy.preferred_address.unwrap();
    f.selected_policy.max_candidates = 2;
    f.selected_policy.preferred_address = Some(target + (1 << 24) - 1);
    // Preferred target is in the window but its full image has no permit.
    let failure = plan_neighbor_short_with_emission(
        &f.request(),
        &f.victim_policy,
        f.search(),
        BundleBudget::default(),
    )
    .unwrap_err();
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(
        failure.attempts[0].stage,
        NeighborAttemptStage::SelectedPlacement
    );
    assert!(
        failure
            .search
            .runs
            .iter()
            .any(|r| r.domain == SearchDomain::JointPairs
                && r.examined == 1
                && matches!(r.stop, SearchStop::BudgetLimited { .. }))
    );
    let mut search = f.search();
    search.max_pairs = 2;
    let plan = plan_neighbor_short_with_emission(
        &f.request(),
        &f.victim_policy,
        search,
        BundleBudget::default(),
    )
    .unwrap();
    let ArtifactMetrics::Neighbor(_, metrics) = plan.metrics() else {
        panic!("metrics")
    };
    assert_eq!((metrics.pairs_examined, metrics.attempts.len()), (2, 2));
    assert!(metrics.attempts[0].refusal.is_some());
    assert!(metrics.attempts[1].refusal.is_none());
    f.selected_policy = policy(target);
    f.selected_policy.ranges.clear();
    f.selected_policy.preferred_address = None;
    let empty = plan_neighbor_short_with_emission(
        &f.request(),
        &f.victim_policy,
        f.search(),
        BundleBudget::default(),
    )
    .unwrap_err();
    assert_eq!(empty.reason, Refusal::AllocationUnavailable);
    assert!(
        empty
            .search
            .runs
            .iter()
            .any(|r| r.domain == SearchDomain::SelectedImages
                && r.examined == 0
                && matches!(
                    r.candidates,
                    Some(CandidateProof::PageBoundary {
                        returned: 0,
                        omitted: None,
                        ..
                    })
                ))
    );
    for mutation in 0..8 {
        let mut f = Fixture::new(2, 8, 124);
        let mut budget = BundleBudget::default();
        let mut search = f.search();
        match mutation {
            0 => f.selected_policy.max_candidates = 0,
            1 => f.victim_policy.max_mapped_bytes = 4095,
            2 => budget.max_steps = 1,
            3 => budget.max_mappings = 1,
            4 => budget.max_virtual_bytes = 8191,
            5 => budget.max_backing_bytes = 8191,
            6 => search.max_victims = 0,
            7 => search.max_pairs = 0,
            _ => unreachable!(),
        }
        assert!(
            plan_neighbor_short_with_emission(&f.request(), &f.victim_policy, search, budget)
                .is_err()
        );
    }
    let mut f = Fixture::new(2, 8, 124);
    f.emission = ArtifactEmission::new(
        f.emission.profile().clone(),
        f.emission.hook(),
        vec![f.source(), f.selected_policy.ranges[0]],
    );
    assert!(
        plan_neighbor_short_with_emission(
            &f.request(),
            &f.victim_policy,
            f.search(),
            BundleBudget::default()
        )
        .is_err()
    );
}

#[test]
fn short_entrypoints_do_not_admit_long_victims_or_change_long_search() {
    for len in 10..=15 {
        let mut f = Fixture::new(2, 9, -131);
        let mut bytes = vec![0x2e; len - 10];
        bytes.extend_from_slice(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8]);
        f.code[f.victim..f.victim + len].copy_from_slice(&bytes);
        let victim = f.v();
        f.entries
            .entries
            .retain(|e| !(victim < e.address && e.address < victim + len as u64));
        let long = plan_neighbor_with_emission(
            &f.request(),
            &f.victim_policy,
            f.search(),
            BundleBudget::default(),
        )
        .unwrap();
        let ArtifactMetrics::Neighbor(g, metrics) = long.metrics() else {
            panic!("metrics")
        };
        assert_eq!(g.victim_len, len);
        assert_eq!(metrics.pairs_examined, 1);
        assert_eq!(
            g.selected_target,
            f.selected_policy.preferred_address.unwrap()
        );
        assert_eq!(g.victim_target, f.victim_policy.preferred_address.unwrap());
        assert_eq!(
            plan_neighbor_short_with_emission(
                &f.request(),
                &f.victim_policy,
                f.search(),
                BundleBudget::default()
            )
            .unwrap_err()
            .reason,
            Refusal::NoPatchWindow
        );
        let mut search = f.search();
        search.forced_victim = None;
        assert!(
            plan_neighbor_short_with_emission(
                &f.request(),
                &f.victim_policy,
                search,
                BundleBudget::default()
            )
            .is_err()
        );
    }
    let mut f = Fixture::new(2, 6, 124);
    f.code[f.victim..f.victim + 6].copy_from_slice(&[0xb8, 1, 2, 3, 4, 0x90]);
    assert_eq!(
        plan_neighbor_short_with_emission(
            &f.request(),
            &f.victim_policy,
            f.search(),
            BundleBudget::default()
        )
        .unwrap_err()
        .reason,
        Refusal::NoPatchWindow
    );
}
