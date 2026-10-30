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
                for (i, &original) in f.code.iter().enumerate() {
                    if !(f.victim..f.victim + victim_len).contains(&i)
                        && !(f.selected..f.selected + 2).contains(&i)
                    {
                        assert_eq!(final_bytes[i], original, "preserved byte {i}");
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

// Engine adapter controls: artifacts only, no new callback/native authority.
fn engine_policy(
    f: &Fixture,
    forced: Option<crate::engine::Tactic>,
) -> crate::engine::EnginePolicy {
    crate::engine::EnginePolicy {
        forced,
        neighbor: f.search(),
        ..Default::default()
    }
}

fn artifact_equal(f: &Fixture, actual: &ArtifactPlan, expected: &ArtifactPlan) {
    assert_eq!(actual.source_steps(), expected.source_steps());
    assert_eq!(f.composition(actual), f.composition(expected));
    let actual_images: Vec<_> = actual.images().collect();
    let expected_images: Vec<_> = expected.images().collect();
    assert_eq!(actual_images.len(), expected_images.len());
    for (a, e) in actual_images.iter().zip(&expected_images) {
        assert_eq!(a.address(), e.address());
        assert_eq!(a.bytes(), e.bytes());
        assert_eq!(a.entry_routes(), e.entry_routes());
        assert_eq!(a.instruction_boundaries(), e.instruction_boundaries());
        assert_eq!(a.program_counter_mappings(), e.program_counter_mappings());
        assert_eq!(a.metadata().fields(), e.metadata().fields());
        assert_eq!(a.metadata().requirements(), e.metadata().requirements());
        assert!(!a.metadata().qualification_complete());
    }
    assert!(!actual.qualification_complete() && !expected.qualification_complete());
}

fn assert_neighbor_adapter(f: &Fixture, actual: &ArtifactPlan, leaf: &ArtifactPlan) {
    use crate::engine::{SelectedMetrics, Tactic};
    artifact_equal(f, actual, leaf);
    let ArtifactMetrics::Engine(Tactic::NeighborEviction, SelectedMetrics::Neighbor(g, m), a) =
        actual.metrics()
    else {
        panic!("engine metric kind")
    };
    let ArtifactMetrics::Neighbor(expected_g, expected_m) = leaf.metrics() else {
        panic!("leaf metric kind")
    };
    assert_eq!(g, expected_g);
    assert_eq!(m, expected_m);
    assert_eq!(a.last().unwrap().refusal, None);
    assert_eq!(a.last().unwrap().search, m.search);
    let crate::engine::CandidateEvidence::Neighbor(rows) = &a.last().unwrap().candidates else {
        panic!("neighbor evidence")
    };
    assert_eq!(rows, &m.attempts);
}

#[test]
fn short_engine_forced_matches_direct_at_all_endpoints() {
    use crate::engine::{self, Tactic};
    let mut count = 0;
    for selected in 2..=4 {
        for victim in 6..=9 {
            for delta in [-131, 124] {
                let f = Fixture::new(selected, victim, delta);
                let leaf = f.plan();
                let actual = engine::plan_with_emission_and_short_neighbors(
                    &f.request(),
                    &f.victim_policy,
                    engine_policy(&f, Some(Tactic::NeighborEviction)),
                )
                .unwrap();
                assert_neighbor_adapter(&f, &actual, &leaf);
                let ArtifactMetrics::Engine(_, _, attempts) = actual.metrics() else {
                    unreachable!()
                };
                assert_eq!(attempts.len(), 1);
                count += 1;
            }
        }
    }
    assert_eq!(count, 24);
}

#[test]
fn short_engine_preferred_keeps_five_stage_order() {
    use crate::engine::{self, Tactic};
    let mut f = Fixture::new(2, 6, 124);
    // Natural two-byte Jcc, then one-byte NOP/RET: no B1 block or T2 victim.
    f.code[f.selected..f.selected + 4].copy_from_slice(&[0x75, 1, 0x90, 0xc3]);
    // Both B2 and T1 target windows are independently excluded by the frozen
    // selected permits; true source refusals precede the required T3 winner.
    for (next, fixed, width) in [
        (f.s() + 5, 0x90c3_9000_u32, 256),
        (f.s() + 6, 0x9090_c390, 1),
    ] {
        let low = u64::try_from(i128::from(next) + i128::from(fixed as i32)).unwrap();
        assert!(
            f.selected_policy
                .ranges
                .iter()
                .all(|p| !p.overlaps(range(low, width)))
        );
    }
    let leaf = f.plan();
    let actual = engine::plan_with_emission_and_short_neighbors(
        &f.request(),
        &f.victim_policy,
        engine_policy(&f, None),
    )
    .unwrap();
    assert_neighbor_adapter(&f, &actual, &leaf);
    let ArtifactMetrics::Engine(_, _, attempts) = actual.metrics() else {
        unreachable!()
    };
    assert_eq!(
        attempts.iter().map(|a| a.tactic).collect::<Vec<_>>(),
        [
            Tactic::GeneralizedPun,
            Tactic::Relocation,
            Tactic::PrefixedPun,
            Tactic::SuccessorEviction,
            Tactic::NeighborEviction
        ]
    );
    for (a, reason) in attempts[..4].iter().zip([
        Refusal::AllocationUnavailable,
        Refusal::NoPatchWindow,
        Refusal::AllocationUnavailable,
        Refusal::NoPatchWindow,
    ]) {
        assert_eq!(a.refusal.as_ref(), Some(&reason));
    }
    // Two independently permitted destinations: the earlier GP must win even
    // though a forced short-neighbor transaction is also feasible.
    let mut f = Fixture::new(2, 6, 124);
    let gp = u64::try_from(
        i128::from(f.s() + 5) + i128::from(i32::from_le_bytes([0, 0xc3, 0x90, 0x90])),
    )
    .unwrap();
    f.selected_policy.ranges.push(range(gp & !4095, 8192));
    f.selected_policy.preferred_address = Some(gp);
    let short = engine::plan_with_emission_and_short_neighbors(
        &f.request(),
        &f.victim_policy,
        engine_policy(&f, Some(Tactic::NeighborEviction)),
    )
    .unwrap();
    let ArtifactMetrics::Engine(Tactic::NeighborEviction, _, _) = short.metrics() else {
        panic!("short positive")
    };
    let preferred = engine::plan_with_emission_and_short_neighbors(
        &f.request(),
        &f.victim_policy,
        engine_policy(&f, None),
    )
    .unwrap();
    let old = engine::plan_with_emission(&f.request(), &f.victim_policy, engine_policy(&f, None))
        .unwrap();
    artifact_equal(&f, &preferred, &old);
    let ArtifactMetrics::Engine(Tactic::GeneralizedPun, _, attempts) = preferred.metrics() else {
        panic!("GP ranking")
    };
    assert_eq!(attempts.len(), 1);
}

#[test]
fn short_engine_never_spends_a_second_neighbor_budget() {
    use crate::engine::{self, CandidateEvidence, Tactic};
    for mutation in 0..10 {
        let mut f = Fixture::new(2, 9, 124);
        let mut p = engine_policy(&f, Some(Tactic::NeighborEviction));
        match mutation {
            0 => p.neighbor.max_victims = 0,
            1 => p.neighbor.max_pairs = 0,
            2 => f.selected_policy.max_candidates = 0,
            3 => f.victim_policy.max_candidates = 0,
            4 => f.selected_policy.max_mapped_bytes = 4095,
            5 => p.bundle.max_steps = 1,
            6 => p.bundle.max_mappings = 1,
            7 => p.bundle.max_virtual_bytes = 8191,
            8 => p.bundle.max_backing_bytes = 8191,
            9 => {
                f.selected_policy.max_candidates = 2;
                f.selected_policy.preferred_address =
                    Some(f.selected_policy.preferred_address.unwrap() + (1 << 24) - 1);
            }
            _ => unreachable!(),
        }
        let leaf =
            plan_neighbor_short_with_emission(&f.request(), &f.victim_policy, p.neighbor, p.bundle)
                .unwrap_err();
        let actual =
            engine::plan_with_emission_and_short_neighbors(&f.request(), &f.victim_policy, p)
                .unwrap_err();
        assert_eq!(actual.reason, leaf.reason);
        assert_eq!(actual.attempts.len(), 1);
        let a = &actual.attempts[0];
        assert_eq!(a.tactic, Tactic::NeighborEviction);
        assert_eq!(a.refusal.as_ref(), Some(&leaf.reason));
        assert_eq!(a.search, leaf.search);
        assert!(a.outer_refusal.is_none());
        let CandidateEvidence::Neighbor(rows) = &a.candidates else {
            panic!("lost evidence")
        };
        assert_eq!(rows, &leaf.attempts);
        if mutation == 9 {
            let mut twice = p;
            twice.neighbor.max_pairs = 2;
            let positive = engine::plan_with_emission_and_short_neighbors(
                &f.request(),
                &f.victim_policy,
                twice,
            )
            .unwrap();
            let ArtifactMetrics::Engine(_, crate::engine::SelectedMetrics::Neighbor(_, m), _) =
                positive.metrics()
            else {
                panic!("metrics")
            };
            assert_eq!((m.pairs_examined, m.attempts.len()), (2, 2));
            let preferred = engine::plan_with_emission_and_short_neighbors(
                &f.request(),
                &f.victim_policy,
                crate::engine::EnginePolicy { forced: None, ..p },
            )
            .unwrap_err();
            assert_eq!(preferred.attempts.len(), 5);
            assert_eq!(preferred.attempts.last().unwrap().search, leaf.search);
        }
    }
}

#[test]
fn short_engine_after_binds_original_and_current_suffix() {
    use crate::engine::{self, Tactic};
    let mut f = Fixture::new(2, 6, -6); // selected EB overlaps the fixed fetch suffix
    f.code[16..21].copy_from_slice(&[0xb8, 1, 2, 3, 4]);
    f.entries
        .entries
        .retain(|e| !(f.base + 16 < e.address && e.address < f.base + 21));
    let empty = Composition::new(
        f.entries.identity,
        vec![ExpectedBytes {
            address: f.base,
            bytes: f.code.clone(),
        }],
    )
    .unwrap();
    let policy = engine_policy(&f, Some(Tactic::NeighborEviction));
    let plain = f.plan();
    let after = engine::plan_with_emission_after_and_short_neighbors(
        &f.request(),
        &empty,
        &f.victim_policy,
        policy,
    )
    .unwrap();
    assert_neighbor_adapter(&f, &after, &plain);
    let prior_allocation = self::policy(f.base + 0x2000_0080);
    let mut request = f.request();
    request.site.logical_pc = f.base + 16;
    request.site.block = range(f.base + 16, 5);
    request.site.allocation = &prior_allocation;
    let prior = engine::plan_with_emission(
        &request,
        &f.victim_policy,
        engine_policy(&f, Some(Tactic::Relocation)),
    )
    .unwrap();
    let mut predecessor = empty.clone();
    for step in prior.source_steps() {
        predecessor.append(step).unwrap();
    }
    let saved = predecessor.clone();
    let next = engine::plan_with_emission_after_and_short_neighbors(
        &f.request(),
        &predecessor,
        &f.victim_policy,
        policy,
    )
    .unwrap();
    assert_eq!(predecessor, saved);
    assert_eq!(
        next.source_steps()[0].parts().reads,
        predecessor.final_bytes()
    );
    let mut complete = predecessor.clone();
    for step in next.source_steps() {
        complete.append(step).unwrap();
    }
    assert_eq!(complete.originals(), empty.originals());
    assert_eq!(
        &complete.final_bytes()[0].bytes[16..21],
        &predecessor.final_bytes()[0].bytes[16..21]
    );
    assert_eq!(
        &complete.final_bytes()[0].bytes[f.selected..f.selected + 2],
        &[0xeb, (-3_i8) as u8]
    );
    for mutation in 0..2 {
        let mut wrong = f.request();
        let mut bytes = f.code.clone();
        if mutation == 0 {
            wrong.site.identity.generation += 1;
        } else {
            bytes[0] ^= 1;
            wrong.site.code = &bytes;
        }
        let error = engine::plan_with_emission_after_and_short_neighbors(
            &wrong,
            &predecessor,
            &f.victim_policy,
            policy,
        )
        .unwrap_err();
        assert_eq!(
            error.reason,
            if mutation == 0 {
                Refusal::StaleGeneration
            } else {
                Refusal::ExpectedBytesChanged
            }
        );
        assert!(error.attempts.is_empty());
    }
    // A real selected edit and a real victim relocation each invalidate the
    // original-instruction requirement, independently of metadata lock tests.
    let mut selected_changed = empty.clone();
    selected_changed.append(&plain.source_steps()[0]).unwrap();
    assert!(
        engine::plan_with_emission_after_and_short_neighbors(
            &f.request(),
            &selected_changed,
            &f.victim_policy,
            policy
        )
        .is_err()
    );
    let mut request = f.request();
    request.site.logical_pc = f.v();
    request.site.block = range(f.v(), f.victim_len);
    request.site.allocation = &prior_allocation;
    let victim_plan = engine::plan_with_emission(
        &request,
        &f.victim_policy,
        engine_policy(&f, Some(Tactic::Relocation)),
    )
    .unwrap();
    let mut victim_changed = empty.clone();
    for step in victim_plan.source_steps() {
        victim_changed.append(step).unwrap();
    }
    assert!(
        engine::plan_with_emission_after_and_short_neighbors(
            &f.request(),
            &victim_changed,
            &f.victim_policy,
            policy
        )
        .is_err()
    );
    // The after API does not waive the caller's transactional append checks.
    // Each hostile metadata plan is structurally valid before the exact
    // composition check. None claims instruction or executable authority.
    for mutation in 0..3 {
        let mut parts = next.source_steps()[0].parts().clone();
        parts.reads = complete.final_bytes().to_vec();
        if mutation != 1 {
            parts.physical_pc = f.base + 32;
            parts.logical_pc = f.base + 32;
            parts.displaced = range(f.base + 32, 1);
            parts.obligations = vec![EntryObligation::Preserved(f.base + 32)];
        }
        match mutation {
            0 => {
                // locked selected byte, distinct physical site and no allocation
                parts.writes[0].bytes[1] ^= 1;
                parts.generated.clear();
                parts.allocations.clear();
            }
            1 => {
                parts.generated.clear();
                parts.allocations.clear();
            } // duplicate physical site
            2 => parts.writes.clear(), // distinct site, identical exclusive allocation
            _ => unreachable!(),
        }
        let hostile = PatchPlan::checked(parts).unwrap();
        let mut candidate = complete.clone();
        assert_eq!(candidate.append(&hostile), Err(Refusal::OwnershipConflict));
        assert_eq!(candidate, complete);
    }
    // Exact borrowed suffix lock: use a valid metadata edit to one byte that
    // remains an original successor entry, never a synthetic positive code run.
    let at = f.v() + 9;
    let mut parts = next.source_steps()[1].parts().clone();
    parts.logical_pc = f.base + 32;
    parts.physical_pc = f.base + 32;
    parts.displaced = range(f.base + 32, 1);
    parts.reads = complete.final_bytes().to_vec();
    parts.generated.clear();
    parts.allocations.clear();
    parts.obligations = vec![EntryObligation::Preserved(f.base + 32)];
    parts.writes = vec![ByteEdit {
        address: at,
        bytes: vec![complete.final_bytes()[0].bytes[(at - f.base) as usize] ^ 1],
    }];
    let hostile = PatchPlan::checked(parts).unwrap();
    let mut candidate = complete.clone();
    assert_eq!(candidate.append(&hostile), Err(Refusal::OwnershipConflict));
    assert_eq!(candidate, complete);
}

#[test]
fn short_engine_defaults_and_long_schedule_are_unchanged() {
    use crate::engine::{self, CandidateEvidence, Tactic};
    for len in 10..=15 {
        let mut f = Fixture::new(2, 9, -131);
        let mut bytes = vec![0x2e; len - 10];
        bytes.extend_from_slice(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8]);
        f.code[f.victim..f.victim + len].copy_from_slice(&bytes);
        let v = f.v();
        f.entries
            .entries
            .retain(|e| !(v < e.address && e.address < v + len as u64));
        let p = engine_policy(&f, Some(Tactic::NeighborEviction));
        let old = engine::plan_with_emission(&f.request(), &f.victim_policy, p).unwrap();
        let leaf =
            plan_neighbor_with_emission(&f.request(), &f.victim_policy, p.neighbor, p.bundle)
                .unwrap();
        assert_neighbor_adapter(&f, &old, &leaf);
        let failure =
            engine::plan_with_emission_and_short_neighbors(&f.request(), &f.victim_policy, p)
                .unwrap_err();
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(failure.reason, Refusal::NoPatchWindow);
    }
    let f = Fixture::new(2, 6, 124);
    for tactic in [
        Tactic::GeneralizedPun,
        Tactic::Relocation,
        Tactic::PrefixedPun,
        Tactic::SuccessorEviction,
    ] {
        let p = engine_policy(&f, Some(tactic));
        let old = engine::plan_with_emission(&f.request(), &f.victim_policy, p);
        let new = engine::plan_with_emission_and_short_neighbors(&f.request(), &f.victim_policy, p);
        match (old, new) {
            (Ok(a), Ok(b)) => {
                artifact_equal(&f, &a, &b);
                assert_eq!(format!("{:?}", a.metrics()), format!("{:?}", b.metrics()));
            }
            (Err(a), Err(b)) => {
                assert_eq!(a.reason, b.reason);
                assert_eq!(format!("{:?}", a.attempts), format!("{:?}", b.attempts));
                assert_eq!(a.attempts.len(), 1);
                assert!(!matches!(
                    &a.attempts[0].candidates,
                    CandidateEvidence::Neighbor(_)
                ));
            }
            _ => panic!("forced non-neighbor dispatch differs"),
        }
    }
    let d = crate::engine::EnginePolicy::default();
    assert_eq!(d.forced, None);
    assert_eq!(d.successor_puns, TacticPolicy::PreferGeneralizedPun);
    assert_eq!(
        format!("{:?}", d.neighbor),
        format!("{:?}", NeighborSearch::default())
    );
    assert_eq!(
        format!("{:?}", d.bundle),
        format!("{:?}", BundleBudget::default())
    );
}

// Inherited ShortOnly T3 controls. Artifact planning and contract checks only;
// the live wrapper below is exercised only at pre-emission authentication refusal.
fn ownership_empty(f: &Fixture) -> Composition {
    Composition::new(
        f.entries.identity,
        vec![ExpectedBytes {
            address: f.base,
            bytes: f.code.clone(),
        }],
    )
    .unwrap()
}

fn ownership_policy(f: &Fixture) -> crate::engine::EnginePolicy {
    crate::engine::EnginePolicy {
        forced: Some(crate::engine::Tactic::NeighborEviction),
        neighbor: NeighborSearch {
            max_pairs: 2,
            ..f.search()
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

fn ownership_gp_fixture() -> Fixture {
    let mut f = Fixture::new(2, 6, 124);
    f.selected = 0;
    f.victim = 32;
    f.code = vec![
        0xff, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xff,
        0xc0, 0x2e, 0xb8, 0x37, 0x31, 0x42, 0x53, 0xb8, 1, 1, 1, 1, 0xc3, 0x90, 0x90, 0xff, 0xc0,
        0x2e, 0xb8, 0x27, 0x31, 0x42, 0x53, 0xb8, 1, 1, 1, 1, 0xc3, 0x90, 0x90, 0x90, 0x90,
    ];
    assert_eq!(f.code.len(), 48);
    f.entries.scope = f.source();
    f.entries.entries = [
        0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 22, 27, 28, 29, 30, 32, 38, 43, 44, 45,
        46, 47,
    ]
    .into_iter()
    .map(|offset| LegalEntry {
        address: f.base + offset,
        requires_endbr: false,
    })
    .collect();
    f.selected_policy = policy(f.base + 0x0101_01e2);
    f.victim_policy = policy(f.base + 0x0600_0080);
    f
}

fn ownership_allocation_fixture() -> Fixture {
    let mut f = Fixture::new(2, 9, 124);
    for offset in [16, 32] {
        f.code[offset..offset + 5].copy_from_slice(&[0xb8, 1, 2, 3, 4]);
        f.entries.entries.retain(|e| {
            !(f.base + (offset as u64) < e.address && e.address < f.base + (offset as u64) + 5)
        });
    }
    let target = f.base - 0x7000_0000 + 0x3000;
    f.selected_policy = AllocationPolicy {
        ranges: vec![range(target, 8192)],
        preferred_address: Some(target),
        max_candidates: 2,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let victim = f.base + 0x0600_0000;
    f.victim_policy = AllocationPolicy {
        ranges: vec![range(victim, 4096)],
        preferred_address: Some(victim),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    // Literal fixed-suffix arithmetic, independent of the planner's Relay.
    let low = f.v() + 10 - 0x7000_0000;
    assert_eq!(low, 0x41ff_9000_0186);
    assert!(low <= target && target + 4096 < low + (1 << 24));
    f
}

fn ownership_append(prior: &Composition, plan: &ArtifactPlan) -> Composition {
    let mut next = prior.clone();
    for step in plan.source_steps() {
        next.append(step).unwrap();
    }
    next
}

fn ownership_prior(
    f: &Fixture,
    prior: &Composition,
    offset: usize,
    len: usize,
    target: u64,
    tactic: crate::engine::Tactic,
) -> (Composition, ArtifactPlan) {
    let allocation = policy(target);
    let mut request = f.request();
    request.site.logical_pc = f.base + offset as u64;
    request.site.block = range(request.site.logical_pc, len);
    request.site.allocation = &allocation;
    let plan = crate::engine::plan_with_emission_after(
        &request,
        prior,
        &f.victim_policy,
        crate::engine::EnginePolicy {
            forced: Some(tactic),
            ..ownership_policy(f)
        },
    )
    .unwrap();
    let next = ownership_append(prior, &plan);
    (next, plan)
}

fn ownership_next(
    f: &Fixture,
    prior: &Composition,
    policy: crate::engine::EnginePolicy,
) -> Result<ArtifactPlan, crate::engine::EngineFailure> {
    crate::engine::plan_with_emission_after_and_short_t3_ownership(
        &f.request(),
        prior,
        &f.victim_policy,
        policy,
    )
}

fn ownership_details(plan: &ArtifactPlan) -> (&NeighborGeometry, &NeighborMetrics) {
    let ArtifactMetrics::Engine(
        crate::engine::Tactic::NeighborEviction,
        crate::engine::SelectedMetrics::Neighbor(g, m),
        attempts,
    ) = plan.metrics()
    else {
        panic!("expected actual T3 result")
    };
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].refusal, None);
    assert!(attempts[0].outer_refusal.is_none());
    assert_eq!(attempts[0].search, m.search);
    let crate::engine::CandidateEvidence::Neighbor(rows) = &attempts[0].candidates else {
        panic!("expected neighbor evidence")
    };
    assert_eq!(rows, &m.attempts);
    assert!(m.search.accepted);
    assert!(!m.search.classification_complete);
    assert!(!plan.qualification_complete());
    (g, m)
}

fn ownership_failure(
    error: &crate::engine::EngineFailure,
    reason: Refusal,
) -> (&[NeighborAttempt], &SearchEvidence) {
    assert_eq!(error.reason, reason);
    assert_eq!(error.attempts.len(), 1);
    let a = &error.attempts[0];
    assert_eq!(a.tactic, crate::engine::Tactic::NeighborEviction);
    assert_eq!(a.refusal.as_ref(), Some(&reason));
    assert!(a.outer_refusal.is_none());
    assert!(!a.search.accepted && !a.search.classification_complete);
    let crate::engine::CandidateEvidence::Neighbor(rows) = &a.candidates else {
        panic!("expected neighbor failure evidence")
    };
    (rows, &a.search)
}

fn ownership_row(
    victim: u64,
    victim_target: u64,
    selected: u64,
    refusal: Option<Refusal>,
) -> NeighborAttempt {
    NeighborAttempt {
        victim,
        stage: NeighborAttemptStage::Composition,
        victim_target: Some(victim_target),
        selected_target: Some(selected),
        refusal,
    }
}

fn ownership_artifact_equal(prior: &Composition, a: &ArtifactPlan, b: &ArtifactPlan) {
    assert_eq!(a.source_steps(), b.source_steps());
    assert_eq!(ownership_append(prior, a), ownership_append(prior, b));
    ownership_images_equal(a, b);
}

fn ownership_images_equal(a: &ArtifactPlan, b: &ArtifactPlan) {
    let aa: Vec<_> = a.images().collect();
    let bb: Vec<_> = b.images().collect();
    assert_eq!(aa.len(), bb.len());
    for (a, b) in aa.iter().zip(&bb) {
        assert_eq!(a.address(), b.address());
        assert_eq!(a.bytes(), b.bytes());
        assert_eq!(a.entry_routes(), b.entry_routes());
        assert_eq!(a.instruction_boundaries(), b.instruction_boundaries());
        assert_eq!(a.program_counter_mappings(), b.program_counter_mappings());
        assert_eq!(a.metadata().fields(), b.metadata().fields());
        assert_eq!(a.metadata().requirements(), b.metadata().requirements());
        assert!(!a.metadata().qualification_complete() && !b.metadata().qualification_complete());
    }
    assert!(!a.qualification_complete() && !b.qualification_complete());
}

#[test]
fn short_t3_ownership_real_gp_continues_to_second_victim() {
    use crate::engine::{self, Tactic};
    let f = ownership_gp_fixture();
    let empty = ownership_empty(&f);
    let (prior, gp) = ownership_prior(
        &f,
        &empty,
        30,
        2,
        f.base + 0x27b8_2e23,
        Tactic::GeneralizedPun,
    );
    assert!(matches!(
        gp.source_steps()[0].parts().kind,
        PlanKind::GeneralizedPun(_)
    ));
    assert_eq!(&prior.final_bytes()[0].bytes[32..38], &f.code[32..38]);
    assert!(prior.locks().iter().any(|r| r.covers(range(f.v(), 3))));
    let saved = prior.clone();
    let p = crate::engine::EnginePolicy {
        neighbor: NeighborSearch {
            forced_victim: None,
            max_victims: 2,
            max_pairs: 2,
        },
        ..ownership_policy(&f)
    };
    let old = engine::plan_with_emission_after_and_short_neighbors(
        &f.request(),
        &prior,
        &f.victim_policy,
        p,
    )
    .unwrap();
    assert_eq!(ownership_details(&old).0.victim, f.v());
    let mut refused = prior.clone();
    assert_eq!(
        refused.append(&old.source_steps()[0]),
        Err(Refusal::OwnershipConflict)
    );
    assert_eq!(refused, saved);
    let next = ownership_next(&f, &prior, p).unwrap();
    let (g, m) = ownership_details(&next);
    assert_eq!(
        (g.victim, g.selected_target, g.victim_target),
        (f.base + 16, f.base + 0x0101_01d2, f.base + 0x0600_0080)
    );
    assert_eq!((m.victims_examined, m.pairs_examined), (2, 2));
    assert_eq!(
        m.attempts,
        [
            ownership_row(
                f.v(),
                g.victim_target,
                f.base + 0x0101_01e2,
                Some(Refusal::OwnershipConflict)
            ),
            ownership_row(f.base + 16, g.victim_target, g.selected_target, None),
        ]
    );
    assert_eq!(
        m.search.runs.iter().map(|r| r.examined).collect::<Vec<_>>(),
        [2, 2, 1, 1, 1, 1]
    );
    assert_eq!(
        ownership_append(&prior, &next).originals(),
        empty.originals()
    );
    assert_eq!(prior, saved);
    let mut forced = p;
    forced.neighbor.forced_victim = Some(f.v());
    ownership_failure(
        &ownership_next(&f, &prior, forced).unwrap_err(),
        Refusal::OwnershipConflict,
    );
    forced.neighbor.forced_victim = Some(f.base + 16);
    let direct = ownership_next(&f, &prior, forced).unwrap();
    ownership_artifact_equal(&prior, &next, &direct);
    assert_eq!(prior, saved);
    let (both, _) = ownership_prior(
        &f,
        &prior,
        14,
        2,
        f.base + 0x37b8_2e13,
        Tactic::GeneralizedPun,
    );
    let both_saved = both.clone();
    let error = ownership_next(&f, &both, p).unwrap_err();
    let (rows, search) = ownership_failure(&error, Refusal::OwnershipConflict);
    assert_eq!(
        rows,
        [
            ownership_row(
                f.v(),
                g.victim_target,
                f.base + 0x0101_01e2,
                Some(Refusal::OwnershipConflict)
            ),
            ownership_row(
                f.base + 16,
                g.victim_target,
                f.base + 0x0101_01d2,
                Some(Refusal::OwnershipConflict)
            ),
        ]
    );
    assert_eq!(search.runs[0].stop, SearchStop::DomainComplete);
    assert_eq!(search.runs[1].stop, SearchStop::UnclassifiedBoundedStop);
    assert_eq!(search.runs[1].examined, 2);
    assert_eq!(both, both_saved);
}

#[test]
fn short_t3_ownership_real_allocations_continue_after_partial_append() {
    use crate::engine::{self, Tactic};
    let mut f = ownership_allocation_fixture();
    let t0 = f.selected_policy.preferred_address.unwrap();
    let t1 = t0 + 4096;
    let empty = ownership_empty(&f);
    let (prior, first) = ownership_prior(&f, &empty, 16, 5, t0, Tactic::Relocation);
    assert_eq!(
        first.source_steps()[0].parts().allocations[0].range,
        range(t0, 4096)
    );
    let saved = prior.clone();
    let p = ownership_policy(&f);
    let old = engine::plan_with_emission_after_and_short_neighbors(
        &f.request(),
        &prior,
        &f.victim_policy,
        p,
    )
    .unwrap();
    assert_eq!(ownership_details(&old).0.selected_target, t0);
    assert_eq!(old.source_steps().len(), 2);
    assert_eq!(old.source_steps()[0].parts().physical_pc, f.v());
    assert_eq!(old.source_steps()[1].parts().physical_pc, f.s());
    let mut partial = prior.clone();
    partial.append(&old.source_steps()[0]).unwrap();
    let first_appended = partial.clone();
    assert_ne!(partial, prior);
    assert_eq!(
        partial.append(&old.source_steps()[1]),
        Err(Refusal::OwnershipConflict)
    );
    assert_eq!(partial, first_appended);
    assert_eq!(prior, saved);
    let next = ownership_next(&f, &prior, p).unwrap();
    let (g, m) = ownership_details(&next);
    assert_eq!(g.selected_target, t1);
    assert_eq!((m.victims_examined, m.pairs_examined), (1, 2));
    assert_eq!(
        m.attempts,
        [
            ownership_row(f.v(), g.victim_target, t0, Some(Refusal::OwnershipConflict)),
            ownership_row(f.v(), g.victim_target, t1, None),
        ]
    );
    assert_eq!(
        m.search.runs.iter().map(|r| r.examined).collect::<Vec<_>>(),
        [1, 2, 1, 2]
    );
    assert!(m.search.runs.iter().all(|r| r.stop == SearchStop::Accepted));
    let committed = ownership_append(&prior, &next);
    assert_eq!(committed.originals(), empty.originals());
    assert_eq!(
        &committed.final_bytes()[0].bytes[16..21],
        &prior.final_bytes()[0].bytes[16..21]
    );
    assert_eq!(prior, saved);
    // Reference at the admitted address uses the unchanged short wrapper.
    f.selected_policy.ranges = vec![range(t1, 4096)];
    f.selected_policy.preferred_address = Some(t1);
    f.selected_policy.max_candidates = 1;
    let reference = engine::plan_with_emission_after_and_short_neighbors(
        &f.request(),
        &prior,
        &f.victim_policy,
        p,
    )
    .unwrap();
    ownership_artifact_equal(&prior, &next, &reference);
    f.selected_policy.ranges = vec![range(t0, 8192)];
    f.selected_policy.preferred_address = Some(t0);
    f.selected_policy.max_candidates = 2;
    let (both, second) = ownership_prior(&f, &prior, 32, 5, t1, Tactic::Relocation);
    assert_eq!(
        second.source_steps()[0].parts().allocations[0].range,
        range(t1, 4096)
    );
    let saved = both.clone();
    let error = ownership_next(&f, &both, p).unwrap_err();
    let (rows, search) = ownership_failure(&error, Refusal::OwnershipConflict);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter().map(|r| r.selected_target).collect::<Vec<_>>(),
        [Some(t0), Some(t1)]
    );
    assert!(
        rows.iter()
            .all(|r| r.stage == NeighborAttemptStage::Composition
                && r.refusal == Some(Refusal::OwnershipConflict))
    );
    assert_eq!(search.runs[0].stop, SearchStop::DomainComplete);
    assert_eq!(search.runs[1].stop, SearchStop::UnclassifiedBoundedStop);
    assert_eq!(search.runs[3].stop, SearchStop::DomainComplete);
    assert_eq!(both, saved);
}

#[test]
fn short_t3_ownership_caps_and_evidence_are_not_restarted() {
    use crate::engine::{self, Tactic};
    let f = ownership_gp_fixture();
    let (prior, _) = ownership_prior(
        &f,
        &ownership_empty(&f),
        30,
        2,
        f.base + 0x27b8_2e23,
        Tactic::GeneralizedPun,
    );
    let p = crate::engine::EnginePolicy {
        neighbor: NeighborSearch {
            forced_victim: None,
            max_victims: 2,
            max_pairs: 1,
        },
        ..ownership_policy(&f)
    };
    let error = ownership_next(&f, &prior, p).unwrap_err();
    let (rows, s) = ownership_failure(&error, Refusal::OwnershipConflict);
    assert_eq!(
        rows,
        [ownership_row(
            f.v(),
            f.base + 0x0600_0080,
            f.base + 0x0101_01e2,
            Some(Refusal::OwnershipConflict)
        )]
    );
    assert_eq!(
        s.runs
            .iter()
            .map(|r| (r.domain, r.examined))
            .collect::<Vec<_>>(),
        [
            (SearchDomain::Victims, 2),
            (SearchDomain::JointPairs, 1),
            (SearchDomain::VictimImages, 1),
            (SearchDomain::SelectedImages, 1),
            (SearchDomain::VictimImages, 1),
            (SearchDomain::SelectedImages, 0),
        ]
    );
    assert_eq!(
        s.runs.iter().map(|r| r.stop).collect::<Vec<_>>(),
        [
            SearchStop::Interrupted,
            SearchStop::BudgetLimited {
                remaining_at_least: 1
            },
            SearchStop::BudgetLimited {
                remaining_at_least: 1
            },
            SearchStop::DomainComplete,
            SearchStop::Interrupted,
            SearchStop::Interrupted,
        ]
    );
    assert_eq!(s.runs[4].scope.physical_pc, Some(f.base + 16));
    assert!(s.runs[5].candidates.is_none());
    let mut capped = p;
    capped.neighbor.max_pairs = 2;
    capped.neighbor.max_victims = 1;
    let error = ownership_next(&f, &prior, capped).unwrap_err();
    let (rows, s) = ownership_failure(&error, Refusal::OwnershipConflict);
    assert_eq!(rows.len(), 1);
    assert_eq!(s.runs[0].examined, 1);
    assert_eq!(
        s.runs[0].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    let mut positive = p;
    positive.neighbor.max_pairs = 2;
    assert_eq!(
        ownership_details(&ownership_next(&f, &prior, positive).unwrap())
            .0
            .victim,
        f.base + 16
    );

    let mut f = ownership_allocation_fixture();
    let t0 = f.selected_policy.preferred_address.unwrap();
    let (prior, _) = ownership_prior(&f, &ownership_empty(&f), 16, 5, t0, Tactic::Relocation);
    let saved = prior.clone();
    let mut capped = ownership_policy(&f);
    capped.neighbor.max_pairs = 1;
    let error = ownership_next(&f, &prior, capped).unwrap_err();
    let (rows, s) = ownership_failure(&error, Refusal::OwnershipConflict);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        s.runs.iter().map(|r| r.examined).collect::<Vec<_>>(),
        [1, 1, 1, 1]
    );
    assert_eq!(
        s.runs[1].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    f.selected_policy.max_candidates = 1;
    let error = ownership_next(&f, &prior, ownership_policy(&f)).unwrap_err();
    let (rows, s) = ownership_failure(&error, Refusal::OwnershipConflict);
    assert_eq!(rows.len(), 1);
    assert!(
        matches!(&s.runs[3].candidates, Some(CandidateProof::PageBoundary {
        returned: 1, omitted: Some(t), ..
    }) if *t == t0 + 4096)
    );
    assert_eq!(
        s.runs[3].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    // A later unavailable victim placement must not erase the earlier joint error.
    f.victim_policy.max_candidates = 2;
    let error = ownership_next(&f, &prior, ownership_policy(&f)).unwrap_err();
    let (rows, _) = ownership_failure(&error, Refusal::OwnershipConflict);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].stage, NeighborAttemptStage::Composition);
    assert_eq!(rows[0].refusal, Some(Refusal::OwnershipConflict));
    assert_eq!(rows[1].stage, NeighborAttemptStage::VictimPlacement);
    assert_eq!(rows[1].refusal, Some(Refusal::AllocationUnavailable));
    assert_eq!(prior, saved);
    // These are local refusals before inherited admission: their complete old
    // evidence must survive, rather than become an ownership fallback/retry.
    for mutation in 0..13 {
        let mut f = ownership_allocation_fixture();
        let mut p = ownership_policy(&f);
        match mutation {
            0 => p.neighbor.max_victims = 0,
            1 => p.neighbor.max_pairs = 0,
            2 => f.selected_policy.max_candidates = 0,
            3 => f.victim_policy.max_candidates = 0,
            4 => f.selected_policy.max_mapped_bytes = 4095,
            5 => p.bundle.max_steps = 1,
            6 => p.bundle.max_mappings = 1,
            7 => p.bundle.max_virtual_bytes = 8191,
            8 => p.bundle.max_backing_bytes = 8191,
            9 => p.bundle.max_virtual_span = 4096,
            10 => f.victim_policy.max_mapped_bytes = 4095,
            11 => f.selected_policy.max_mappings = 0,
            12 => f.victim_policy.max_mappings = 0,
            _ => unreachable!(),
        }
        let old = engine::plan_with_emission_after_and_short_neighbors(
            &f.request(),
            &prior,
            &f.victim_policy,
            p,
        )
        .unwrap_err();
        let new = ownership_next(&f, &prior, p).unwrap_err();
        assert_eq!(old.reason, Refusal::AllocationUnavailable);
        assert_eq!(new.reason, old.reason);
        assert_eq!(format!("{:?}", new.attempts), format!("{:?}", old.attempts));
        assert_eq!(new.attempts.len(), 1);
        assert_eq!(prior, saved);
    }
}

#[test]
fn short_t3_ownership_original_and_overlay_identity_are_independent() {
    use crate::engine::Tactic;
    let mut f = Fixture::new(2, 6, -6);
    f.code[16..21].copy_from_slice(&[0xb8, 1, 2, 3, 4]);
    f.entries
        .entries
        .retain(|e| !(f.base + 16 < e.address && e.address < f.base + 21));
    let empty = ownership_empty(&f);
    let (prior, _) = ownership_prior(&f, &empty, 16, 5, f.base + 0x2000_0080, Tactic::Relocation);
    let saved = prior.clone();
    let p = ownership_policy(&f);
    let next = ownership_next(&f, &prior, p).unwrap();
    assert_eq!(next.source_steps()[0].parts().reads, prior.final_bytes());
    assert_ne!(prior.final_bytes(), prior.originals());
    let complete = ownership_append(&prior, &next);
    assert_eq!(
        &complete.final_bytes()[0].bytes[16..21],
        &prior.final_bytes()[0].bytes[16..21]
    );
    assert_eq!(
        &complete.final_bytes()[0].bytes[f.selected..f.selected + 2],
        &[0xeb, 0xfd]
    );
    assert_eq!(prior, saved);
    for mutation in 0..3 {
        let mut request = f.request();
        let mut bytes = f.code.clone();
        match mutation {
            0 => request.site.identity.generation += 1,
            1 => {
                bytes[0] ^= 1;
                request.site.code = &bytes;
            }
            2 => request.site.code = &prior.final_bytes()[0].bytes,
            _ => unreachable!(),
        }
        let error = crate::engine::plan_with_emission_after_and_short_t3_ownership(
            &request,
            &prior,
            &f.victim_policy,
            p,
        )
        .unwrap_err();
        assert_eq!(
            error.reason,
            if mutation == 0 {
                Refusal::StaleGeneration
            } else {
                Refusal::ExpectedBytesChanged
            }
        );
        assert!(error.attempts.is_empty());
        assert_eq!(prior, saved);
    }
    let gap = Composition::new(
        f.entries.identity,
        vec![
            ExpectedBytes {
                address: f.base,
                bytes: f.code[..64].to_vec(),
            },
            ExpectedBytes {
                address: f.base + 65,
                bytes: f.code[65..].to_vec(),
            },
        ],
    )
    .unwrap();
    let error = ownership_next(&f, &gap, p).unwrap_err();
    assert_eq!(error.reason, Refusal::DependencyNotHeld);
    assert!(error.attempts.is_empty());
    // The selected operation is the first member in this overlap fixture.
    let plain = f.plan();
    assert_eq!(plain.source_steps()[0].parts().physical_pc, f.s());
    let mut changed_selected = empty.clone();
    changed_selected.append(&plain.source_steps()[0]).unwrap();
    let (changed_victim, _) = ownership_prior(
        &f,
        &empty,
        f.victim,
        f.victim_len,
        f.base + 0x2200_0080,
        Tactic::Relocation,
    );
    for changed in [&changed_selected, &changed_victim] {
        let saved = (*changed).clone();
        for semantics in [HookSemantics::Observe, HookSemantics::ReplaceFirst] {
            let mut request = f.request();
            request.site.semantics = semantics;
            let error = crate::engine::plan_with_emission_after_and_short_t3_ownership(
                &request,
                changed,
                &f.victim_policy,
                p,
            )
            .unwrap_err();
            ownership_failure(&error, Refusal::ExpectedBytesChanged);
            assert_eq!(*changed, saved);
        }
    }
}

// A structurally checked metadata reservation isolates actual Composition site
// and byte-lock rules. It is never an emitted/publication/native witness.
fn ownership_reservation(
    f: &Fixture,
    prior: &Composition,
    template: &PatchPlan,
    site: u64,
    byte: Option<u64>,
) -> Composition {
    let mut parts = template.parts().clone();
    parts.kind = PlanKind::Relocation;
    parts.logical_pc = site;
    parts.physical_pc = site;
    parts.displaced = range(site, 1);
    parts.obligations = vec![EntryObligation::Preserved(site)];
    parts.reads = prior.final_bytes().to_vec();
    parts.generated.clear();
    parts.allocations.clear();
    parts.writes = byte
        .into_iter()
        .map(|at| ByteEdit {
            address: at,
            bytes: vec![prior.final_bytes()[0].bytes[(at - f.base) as usize]],
        })
        .collect();
    let reservation = PatchPlan::checked(parts).unwrap();
    let mut next = prior.clone();
    next.append(&reservation).unwrap();
    assert_eq!(next.final_bytes(), prior.final_bytes());
    next
}

#[test]
fn short_t3_ownership_exact_current_suffix_and_identical_locks() {
    use crate::engine::Tactic;
    let mut f = ownership_allocation_fixture();
    // Original successor is one MOV, independently relocated by a real plan.
    let at = f.victim + f.victim_len;
    f.code[at..at + 5].copy_from_slice(&[0xb8, 1, 2, 3, 4]);
    f.code[at + 5] = 0xc3;
    f.entries
        .entries
        .retain(|e| !(f.base + (at as u64) < e.address && e.address < f.base + (at as u64) + 5));
    let empty = ownership_empty(&f);
    let (prior, _) = ownership_prior(&f, &empty, at, 5, f.base + 0x2400_0080, Tactic::Relocation);
    assert_eq!(prior.final_bytes()[0].bytes[at], 0xe9);
    assert_eq!(f.code[at], 0xb8);
    // L9 contributes three free low bytes. Only the ACTUAL current E9 byte is
    // fixed, so the new signed window is [V+10-0x17000000, +2^24).
    let low = f.v() + 10 - 0x1700_0000;
    let target = (low + 4095) & !4095;
    f.selected_policy = AllocationPolicy {
        ranges: vec![range(target, 4096)],
        preferred_address: Some(target),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let saved = prior.clone();
    let next = ownership_next(&f, &prior, ownership_policy(&f)).unwrap();
    assert_eq!(ownership_details(&next).0.selected_target, target);
    let joined = ownership_append(&prior, &next);
    assert_eq!(
        &joined.final_bytes()[0].bytes[at..at + 5],
        &prior.final_bytes()[0].bytes[at..at + 5]
    );
    assert_eq!(prior, saved);
    // Permits for the original B8 suffix must not authorize the current E9.
    let old_target = ((f.v() + 10 - 0x4800_0000) + 4095) & !4095;
    f.selected_policy.ranges = vec![range(old_target, 4096)];
    f.selected_policy.preferred_address = Some(old_target);
    ownership_failure(
        &ownership_next(&f, &prior, ownership_policy(&f)).unwrap_err(),
        Refusal::AllocationUnavailable,
    );

    let f = ownership_allocation_fixture();
    let empty = ownership_empty(&f);
    let plain = ownership_next(&f, &empty, ownership_policy(&f)).unwrap();
    let locked = ownership_reservation(
        &f,
        &empty,
        &plain.source_steps()[0],
        f.base + 64,
        Some(f.v() + 9),
    );
    assert!(locked.locks().iter().any(|r| r.contains(f.v() + 9)));
    let saved = locked.clone();
    let next = ownership_next(&f, &locked, ownership_policy(&f)).unwrap();
    // An overlapping inherited lock holding exactly the preserved suffix value
    // is admissible; rejecting all overlaps would change Composition semantics.
    ownership_artifact_equal(&locked, &next, &plain);
    assert_eq!(
        ownership_append(&locked, &next).final_bytes()[0].bytes[f.victim + 9],
        0x90
    );
    assert_eq!(locked, saved);
}

#[test]
fn short_t3_ownership_duplicate_sites_and_byte_locks_refuse() {
    let f = ownership_allocation_fixture();
    let empty = ownership_empty(&f);
    let plain = ownership_next(&f, &empty, ownership_policy(&f)).unwrap();
    for (site, byte) in [
        (f.s(), None),
        (f.v(), None),
        (f.base + 64, Some(f.s())),
        (f.base + 64, Some(f.v())),
    ] {
        let prior = ownership_reservation(&f, &empty, &plain.source_steps()[0], site, byte);
        let saved = prior.clone();
        let old = crate::engine::plan_with_emission_after_and_short_neighbors(
            &f.request(),
            &prior,
            &f.victim_policy,
            ownership_policy(&f),
        )
        .unwrap();
        let mut scratch = prior.clone();
        let failed_step = if site == f.s() || byte == Some(f.s()) {
            scratch.append(&old.source_steps()[0]).unwrap();
            1
        } else {
            0
        };
        let before_failed_step = scratch.clone();
        assert_eq!(
            scratch.append(&old.source_steps()[failed_step]),
            Err(Refusal::OwnershipConflict)
        );
        assert_eq!(scratch, before_failed_step);
        let error = ownership_next(&f, &prior, ownership_policy(&f)).unwrap_err();
        let (rows, search) = ownership_failure(&error, Refusal::OwnershipConflict);
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|r| r.stage == NeighborAttemptStage::Composition
                    && r.refusal == Some(Refusal::OwnershipConflict))
        );
        assert_eq!(search.runs[1].examined, 2);
        assert_eq!(prior, saved);
    }
}

#[test]
fn short_t3_ownership_first_four_and_legacy_paths_are_unchanged() {
    use crate::engine::{self, Tactic};
    let mut f = Fixture::new(2, 6, 124);
    f.code[f.selected..f.selected + 4].copy_from_slice(&[0x75, 1, 0x90, 0xc3]);
    let empty = ownership_empty(&f);
    for (tactic, reason) in [
        (Tactic::GeneralizedPun, Refusal::AllocationUnavailable),
        (Tactic::Relocation, Refusal::NoPatchWindow),
        (Tactic::PrefixedPun, Refusal::AllocationUnavailable),
        (Tactic::SuccessorEviction, Refusal::NoPatchWindow),
    ] {
        let p = crate::engine::EnginePolicy {
            forced: Some(tactic),
            ..ownership_policy(&f)
        };
        let old = engine::plan_with_emission_after_and_short_neighbors(
            &f.request(),
            &empty,
            &f.victim_policy,
            p,
        )
        .unwrap_err();
        let new = ownership_next(&f, &empty, p).unwrap_err();
        assert_eq!(old.reason, reason);
        assert_eq!(new.reason, reason);
        assert_eq!(format!("{:?}", old.attempts), format!("{:?}", new.attempts));
        assert_eq!(new.attempts.len(), 1);
    }
    let p = crate::engine::EnginePolicy {
        forced: None,
        ..ownership_policy(&f)
    };
    let old = engine::plan_with_emission_after_and_short_neighbors(
        &f.request(),
        &empty,
        &f.victim_policy,
        p,
    )
    .unwrap();
    let new = ownership_next(&f, &empty, p).unwrap();
    ownership_artifact_equal(&empty, &new, &old);
    assert_eq!(
        format!("{:?}", new.metrics()),
        format!("{:?}", old.metrics())
    );
    let ArtifactMetrics::Engine(Tactic::NeighborEviction, _, attempts) = new.metrics() else {
        panic!("required fifth-arm success")
    };
    assert_eq!(
        attempts.iter().map(|a| a.tactic).collect::<Vec<_>>(),
        [
            Tactic::GeneralizedPun,
            Tactic::Relocation,
            Tactic::PrefixedPun,
            Tactic::SuccessorEviction,
            Tactic::NeighborEviction,
        ]
    );
    // A real inherited allocation conflict in preferred GP remains the caller's
    // responsibility: the new T3-only option must not restart after GP succeeds.
    let mut f = Fixture::new(2, 6, 124);
    f.code[16..21].copy_from_slice(&[0xb8, 1, 2, 3, 4]);
    f.entries
        .entries
        .retain(|e| !(f.base + 16 < e.address && e.address < f.base + 21));
    let gp = u64::try_from(
        i128::from(f.s() + 5) + i128::from(i32::from_le_bytes([0, 0xc3, 0x90, 0x90])),
    )
    .unwrap();
    f.selected_policy.ranges.push(range(gp & !4095, 8192));
    f.selected_policy.preferred_address = Some(gp);
    let (prior, _) = ownership_prior(&f, &ownership_empty(&f), 16, 5, gp, Tactic::Relocation);
    let saved = prior.clone();
    let p = crate::engine::EnginePolicy {
        forced: None,
        ..ownership_policy(&f)
    };
    let old = engine::plan_with_emission_after_and_short_neighbors(
        &f.request(),
        &prior,
        &f.victim_policy,
        p,
    )
    .unwrap();
    let new = ownership_next(&f, &prior, p).unwrap();
    assert_eq!(new.source_steps(), old.source_steps());
    ownership_images_equal(&new, &old);
    assert_eq!(
        format!("{:?}", new.metrics()),
        format!("{:?}", old.metrics())
    );
    let ArtifactMetrics::Engine(Tactic::GeneralizedPun, _, attempts) = new.metrics() else {
        panic!("required GP success")
    };
    assert_eq!(attempts.len(), 1);
    let mut scratch = prior.clone();
    assert_eq!(
        scratch.append(&new.source_steps()[0]),
        Err(Refusal::OwnershipConflict)
    );
    assert_eq!(scratch, saved);
    assert_eq!(prior, saved);
    for len in 10..=15 {
        let mut f = Fixture::new(2, 9, -131);
        let mut bytes = vec![0x2e; len - 10];
        bytes.extend_from_slice(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8]);
        f.code[f.victim..f.victim + len].copy_from_slice(&bytes);
        let v = f.v();
        f.entries
            .entries
            .retain(|e| !(v < e.address && e.address < v + len as u64));
        let empty = ownership_empty(&f);
        let p = ownership_policy(&f);
        let old =
            engine::plan_with_emission_after(&f.request(), &empty, &f.victim_policy, p).unwrap();
        assert_eq!(ownership_details(&old).0.victim_len, len);
        ownership_failure(
            &ownership_next(&f, &empty, p).unwrap_err(),
            Refusal::NoPatchWindow,
        );
    }
}

#[test]
fn short_t3_ownership_live_and_artifact_preflight_refuse_before_emission() {
    unsafe extern "C" fn never_called(_: *mut crate::trampoline::HookContext) {
        unreachable!("authentication refusals must precede emission/callback use");
    }
    let f = ownership_allocation_fixture();
    let empty = ownership_empty(&f);
    let gap = Composition::new(
        f.entries.identity,
        vec![ExpectedBytes {
            address: f.base,
            bytes: f.code[..64].to_vec(),
        }],
    )
    .unwrap();
    for mutation in 0..3 {
        let prior = if mutation == 2 { &gap } else { &empty };
        let saved = (*prior).clone();
        let mut bytes = f.code.clone();
        if mutation == 1 {
            bytes[0] ^= 1;
        }
        let mut a = f.request();
        a.site.code = &bytes;
        if mutation == 0 {
            a.site.identity.generation += 1;
        }
        let live = crate::quiescent::InstallRequest {
            identity: a.site.identity,
            code: a.site.code,
            base_address: a.site.base_address,
            function: a.site.function,
            block: a.site.block,
            logical_pc: a.site.logical_pc,
            entries: a.site.entries,
            hook: never_called,
            semantics: a.site.semantics,
            allocation: a.site.allocation,
            search: a.site.search,
        };
        let a = crate::engine::plan_with_emission_after_and_short_t3_ownership(
            &a,
            prior,
            &f.victim_policy,
            ownership_policy(&f),
        )
        .unwrap_err();
        let l = crate::engine::plan_after_and_short_t3_ownership(
            &live,
            prior,
            &f.victim_policy,
            ownership_policy(&f),
        )
        .unwrap_err();
        let reason = match mutation {
            0 => Refusal::StaleGeneration,
            1 => Refusal::ExpectedBytesChanged,
            2 => Refusal::DependencyNotHeld,
            _ => unreachable!(),
        };
        assert_eq!(a.reason, reason);
        assert_eq!(l.reason, reason);
        assert!(a.attempts.is_empty() && l.attempts.is_empty());
        assert_eq!(*prior, saved);
    }
}
