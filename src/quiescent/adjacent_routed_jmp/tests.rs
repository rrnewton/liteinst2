use super::*;
use crate::emission::{ArtifactRequest, ArtifactRequirement, SymbolicHook, TargetProfile};
use crate::trampoline::SavedExtendedStateLayout;

const BASE: u64 = 0x401000;
const L: u64 = 0x401bfe;
const U: u64 = 0x401c00;
const F: u64 = 0x401c02;
const E: u64 = 0x401c05;
const B: u64 = 0x401bbe;
const T: u64 = 0x401c45;
const FIRST: u64 = 0x073c0600;
fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}
fn limits() -> RoutedJmpBudget {
    RoutedJmpBudget {
        max_continuations: 2,
        bundle: BundleBudget {
            max_steps: 2,
            max_mappings: 2,
            max_virtual_bytes: 8192,
            max_backing_bytes: 8192,
            max_virtual_span: 1 << 31,
        },
    }
}
struct Fixture {
    code: Vec<u8>,
    identity: CodeIdentity,
    entries: LegalEntrySet,
    lower: AllocationPolicy,
    upper: AllocationPolicy,
    input: ArtifactEmission,
}
impl Fixture {
    fn new() -> Self {
        let hex = include_str!("fixture.hex").trim();
        let code = (0..hex.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&hex[n..n + 2], 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(code.len(), 4096);
        assert_eq!(
            &code[(L - BASE) as usize..(E - BASE) as usize],
            &[0x76, 0xbe, 0xeb, 0x43, 0x4c, 0x89, 0xe7]
        );
        let identity = CodeIdentity {
            source: SourceIdentity([0x72; 32]),
            mapping: 1,
            generation: 0,
        };
        let scan = InstructionScanner::default().scan(&code, BASE).unwrap();
        assert_eq!(scan.instructions().len(), 4082);
        // Independent literal-head roster: only these authored operand bytes
        // are not heads. Do not let the decoder choose the expected roster.
        let interiors = [
            (BASE + 0x101, BASE + 0x105),
            (L - 6, L),
            (L + 1, U),
            (U + 1, F),
            (F + 1, E),
        ];
        let expected = (BASE..BASE + 4096)
            .filter(|pc| !interiors.iter().any(|&(a, b)| a <= *pc && *pc < b))
            .collect::<Vec<_>>();
        assert_eq!(
            scan.instructions()
                .iter()
                .map(|i| i.address())
                .collect::<Vec<_>>(),
            expected
        );
        let entries = LegalEntrySet {
            identity,
            scope: range(BASE, 4096),
            provenance: EntryProvenance::Declared("frozen routed JMP source v1".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            resumes: ResumeObligation::NoneExist,
            entries: scan
                .instructions()
                .iter()
                .map(|i| LegalEntry {
                    address: i.address(),
                    requires_endbr: false,
                })
                .collect(),
        };
        let policy = |preferred_address, ranges, max_candidates| AllocationPolicy {
            preferred_address: Some(preferred_address),
            ranges,
            max_candidates,
            max_mappings: 1,
            max_mapped_bytes: 4096,
        };
        let input = ArtifactEmission::new(
            TargetProfile::linux_x86_64_legacy_evex(
                SavedExtendedStateLayout::describe_target_fxsave64(),
                1,
            )
            .unwrap(),
            SymbolicHook {
                identity: 1,
                address: Some(BASE + 0xf00),
            },
            vec![range(0x400000, 0x56000), range(0x480000, 8192)],
        );
        Self {
            code,
            identity,
            entries,
            input,
            lower: policy(FIRST, vec![range(0x073c0000, 4096)], 1),
            upper: policy(0x600000, vec![range(0x5f2000, 4096)], 2),
        }
    }
    fn sites(&self) -> [PlanningSite<'_>; 2] {
        let lower = PlanningSite {
            identity: self.identity,
            code: &self.code,
            base_address: BASE,
            function: range(BASE, 4096),
            block: range(L, 2),
            logical_pc: L,
            entries: &self.entries,
            semantics: HookSemantics::Observe,
            allocation: &self.lower,
            search: SearchPolicy {
                tactics: TacticPolicy::GeneralizedPunOnly,
                max_upstream_bytes: 0,
                max_displaced_bytes: 2,
                max_sites: 1,
            },
        };
        [
            lower,
            PlanningSite {
                block: range(U, 2),
                logical_pc: U,
                allocation: &self.upper,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 5,
                    max_sites: 1,
                },
                ..lower
            },
        ]
    }
    fn original(&self) -> Composition {
        Composition::new(
            self.identity,
            vec![ExpectedBytes {
                address: BASE,
                bytes: self.code.clone(),
            }],
        )
        .unwrap()
    }
    fn run(
        &self,
        p: &Composition,
        pending: &[AddressRange],
        budget: RoutedJmpBudget,
    ) -> Result<RoutedJmpArtifactPlan, RoutedJmpFailure> {
        plan_adjacent_routed_jmp_with_emission_after(self.sites(), &self.input, p, pending, budget)
    }
    fn upper_member(&self) -> (VerifiedRoutedJmpSuffix, PlannedInstall) {
        let sites = self.sites();
        let requests = sites.map(|site| PlanningRequest {
            original_code: site.code,
            site,
            emission: EmissionContext::Artifact(&self.input),
        });
        let p = preflight(&requests, &self.input, &self.original(), &[], limits())
            .unwrap_or_else(|_| panic!("fixture preflight"));
        let request = requests[1].with_code(&p.current);
        let instructions = p
            .scan
            .instructions()
            .iter()
            .filter(|i| U <= i.address() && i.address() < E)
            .collect();
        let member = emit_relocation_window(
            &request,
            &p.scan,
            p.source,
            self.input.occupied(),
            (None, None),
            RelocationWindow {
                physical: U,
                end: E,
                displaced: range(U, 5),
                instructions,
                authority: RelocationAuthority::RoutedJmp {
                    proof: &p.proof,
                    ordinal: 0,
                    target: 0x5f2300,
                },
            },
            &mut SearchEvidence::default(),
        )
        .unwrap();
        (p.proof, member)
    }
    fn refresh_heads(&mut self) {
        let scan = InstructionScanner::default()
            .scan(&self.code, BASE)
            .unwrap();
        self.entries.entries = scan
            .instructions()
            .iter()
            .map(|i| LegalEntry {
                address: i.address(),
                requires_endbr: false,
            })
            .collect();
    }
}

#[test]
fn frozen_low_address_pair_is_real_and_exact() {
    let f = Fixture::new();
    let predecessor = f.original();
    let before = predecessor.final_bytes().to_vec();
    let result = f.run(&predecessor, &[], limits()).unwrap();
    assert_eq!(result.logical_pcs(), [U, L]);
    assert!(!result.qualification_complete());
    assert!(result.evidence().accepted);
    assert!(!result.evidence().classification_complete);
    assert_eq!(
        result.evidence().counts,
        PairCounts {
            upper: 1,
            lower: 1,
            joint: 1
        }
    );
    assert_eq!(result.evidence().upper_slots, [(0, Some(0x5f2300))]);
    let schedule = &result.evidence().lower_schedules[0];
    assert_eq!(schedule.window, range(0x073c0503, 256));
    assert_eq!(schedule.targets, [FIRST]);
    assert_eq!(result.memory().mappings, 2);
    assert_eq!(result.memory().virtual_bytes, 8192);
    let upper = &result.members()[0];
    let lower = &result.members()[1];
    assert_eq!(upper.source_steps().len(), 1);
    assert_eq!(lower.source_steps().len(), 1);
    assert_eq!(upper.source_steps()[0].parts().kind, PlanKind::Relocation);
    assert!(matches!(
        lower.source_steps()[0].parts().kind,
        PlanKind::GeneralizedPun(_)
    ));
    assert_eq!(
        upper.source_steps()[0].parts().writes[0].bytes,
        [0xe9, 0xfb, 0x06, 0x1f, 0]
    );
    assert_eq!(
        lower.source_steps()[0].parts().writes[0].bytes,
        [0xe9, 0xfd]
    );
    assert_eq!(upper.images().next().unwrap().address(), 0x5f2300);
    assert_eq!(lower.images().next().unwrap().address(), FIRST);
    assert!(
        lower
            .images()
            .next()
            .unwrap()
            .metadata()
            .fields()
            .iter()
            .any(
                |f| f.role == format!("OriginalBranch {{ original_pc: {L} }}")
                    && f.target == i128::from(B)
            )
    );
    let image = upper.images().next().unwrap();
    assert_eq!(image.entry_routes()[1].0, F);
    assert_eq!(image.entry_routes()[1], image.instruction_boundaries()[1]);
    assert!(
        image
            .metadata()
            .requirements()
            .contains(&ArtifactRequirement::EntryRouterBootstrap)
    );
    assert!(
        lower.source_steps()[0]
            .parts()
            .obligations
            .contains(&EntryObligation::Preserved(F))
    );
    let mut actual = predecessor.clone();
    for member in result.members() {
        for step in member.source_steps() {
            actual.append(step).unwrap();
        }
    }
    assert_eq!(
        &actual.final_bytes()[0].bytes[(L - BASE) as usize..(E - BASE) as usize],
        &[0xe9, 0xfd, 0xe9, 0xfb, 0x06, 0x1f, 0]
    );
    assert_eq!(predecessor.final_bytes(), before);
    assert!(predecessor.locks().is_empty());
}

#[test]
fn actual_predecessor_is_preserved_and_never_bypassed() {
    let mut f = Fixture::new();
    let allocation = AllocationPolicy {
        preferred_address: Some(0x500000),
        ranges: vec![range(0x500000, 4096)],
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let site = PlanningSite {
        logical_pc: BASE + 0x100,
        block: range(BASE + 0x100, 5),
        allocation: &allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0,
            max_displaced_bytes: 5,
            max_sites: 1,
        },
        ..f.sites()[0]
    };
    let prior = plan_install_with_emission(&ArtifactRequest {
        site,
        emission: &f.input,
    })
    .unwrap();
    let mut predecessor = f.original();
    for step in prior.source_steps() {
        predecessor.append(step).unwrap();
    }
    let original_prior = predecessor.final_bytes().to_vec();
    let locks = predecessor.locks().to_vec();
    let mut occupied = f.input.occupied().to_vec();
    occupied.push(range(0x500000, 4096));
    f.input = ArtifactEmission::new(f.input.profile().clone(), f.input.hook(), occupied);
    let pair = f.run(&predecessor, &[], limits()).unwrap();
    let mut complete = predecessor.clone();
    for member in pair.members() {
        for step in member.source_steps() {
            complete.append(step).unwrap();
        }
    }
    assert_eq!(
        &complete.final_bytes()[0].bytes[0x100..0x105],
        &original_prior[0].bytes[0x100..0x105]
    );
    assert_eq!(predecessor.final_bytes(), original_prior);
    assert_eq!(predecessor.locks(), locks);
    assert_eq!(
        pair.memory().mappings,
        2,
        "pair-only accounting is not the three-mapping whole set"
    );
}

#[test]
fn old_adjacent_domain_and_mid_transfer_guards_stay_closed() {
    let f = Fixture::new();
    let mut sites = f.sites();
    sites[1].search = sites[0].search;
    assert!(
        plan_adjacent_b2_with_emission_after(
            sites,
            &f.input,
            &f.original(),
            &[],
            AdjacentB2Budget {
                max_continuations: 2,
                bundle: limits().bundle
            }
        )
        .is_err()
    );
    let mut site = f.sites()[1];
    let short = plan_install_with_emission(&ArtifactRequest {
        site,
        emission: &f.input,
    })
    .unwrap_err();
    assert_eq!(short.reason, Refusal::NoPatchWindow);
    site.block = range(U, 5);
    let wide = plan_install_with_emission(&ArtifactRequest {
        site,
        emission: &f.input,
    })
    .unwrap_err();
    assert!(
        matches!(wide.reason,Refusal::UnsupportedSemantics(ref s) if s=="control transfer before displaced end")
    );
    site = f.sites()[1];
    site.search = SearchPolicy {
        tactics: TacticPolicy::GeneralizedPunOnly,
        max_displaced_bytes: 2,
        max_upstream_bytes: 0,
        max_sites: 1,
    };
    assert_eq!(
        plan_install_with_emission(&ArtifactRequest {
            site,
            emission: &f.input
        })
        .unwrap_err()
        .reason,
        Refusal::AllocationUnavailable,
        "fixed 4c89e7 suffix remains below zero"
    );
}

#[test]
fn original_targets_suffix_and_forced_search_refuse_before_images() {
    for (at, bytes) in [
        (L, vec![0x74, 0xbe]),
        (L, vec![0x76, 0]),
        (L, vec![0x76, 0xff]),
        (U, vec![0x75, 0x43]),
        (U, vec![0xeb, 0xfe]),
        (U, vec![0xeb, 1]),
        (F, vec![0x4c, 0x89, 0xe6]),
        (F, vec![0x4c, 0x8b, 0x27]),
    ] {
        let mut f = Fixture::new();
        let off = (at - BASE) as usize;
        f.code[off..off + bytes.len()].copy_from_slice(&bytes);
        f.refresh_heads();
        let error = f.run(&f.original(), &[], limits()).unwrap_err();
        assert_eq!(error.stage, RoutedJmpStage::Preflight);
        assert_eq!(error.evidence.counts, PairCounts::default());
    }
    let f = Fixture::new();
    let mut sites = f.sites();
    sites[1].search.tactics = TacticPolicy::GeneralizedPunOnly;
    let e =
        plan_adjacent_routed_jmp_with_emission_after(sites, &f.input, &f.original(), &[], limits())
            .unwrap_err();
    assert_eq!(e.stop, RoutedJmpStop::Eligibility("exact-search-observe"));
    let mut sites = f.sites();
    sites[0].semantics = HookSemantics::ReplaceFirst;
    let e =
        plan_adjacent_routed_jmp_with_emission_after(sites, &f.input, &f.original(), &[], limits())
            .unwrap_err();
    assert_eq!(e.stop, RoutedJmpStop::Eligibility("exact-search-observe"));
    let mut f = Fixture::new();
    f.input = ArtifactEmission::new(
        f.input.profile().clone(),
        SymbolicHook {
            identity: 1,
            address: None,
        },
        f.input.occupied().to_vec(),
    );
    let e = f.run(&f.original(), &[], limits()).unwrap_err();
    assert_eq!(e.stop, RoutedJmpStop::Eligibility("resolved-hook"));
    assert_eq!(e.evidence.counts, PairCounts::default());
}

#[test]
fn all_head_resume_identity_and_original_mutants_refuse() {
    for kind in 0..9 {
        let mut f = Fixture::new();
        let predecessor = f.original();
        match kind {
            0 => f.entries.entries.retain(|e| e.address != F),
            1 => f.entries.entries[0].requires_endbr = true,
            2 => f.entries.resumes = ResumeObligation::Enumerated(vec![F, F]),
            3 => f.identity.generation += 1,
            4 => f.code[(L - BASE) as usize + 1] ^= 1,
            5 => f.entries.completeness = EntryCompleteness::Incomplete,
            6 => f.entries.entries.swap(0, 1),
            7 => f.entries.entries[1] = f.entries.entries[0],
            _ => f.entries.resumes = ResumeObligation::Unresolved,
        }
        let before = predecessor.final_bytes().to_vec();
        let e = f.run(&predecessor, &[], limits()).unwrap_err();
        assert_eq!(e.stage, RoutedJmpStage::Preflight);
        assert_eq!(e.evidence.counts, PairCounts::default());
        assert_eq!(predecessor.final_bytes(), before);
    }
}

#[test]
fn selected_suffix_and_pending_shape_are_not_exempted() {
    let f = Fixture::new();
    for pending in [
        vec![range(F, 3)],
        vec![range(L, 2)],
        vec![range(U, 2)],
        vec![range(E + 4, 2), range(E + 2, 2)],
        vec![range(E, 4), range(E + 2, 4)],
    ] {
        let e = f.run(&f.original(), &pending, limits()).unwrap_err();
        assert_eq!(
            e.stop,
            RoutedJmpStop::Eligibility("pending-shape-or-selected-suffix")
        );
        assert_eq!(e.evidence.counts, PairCounts::default());
    }
    let p = f.run(&f.original(), &[range(E, 1)], limits()).unwrap();
    assert_eq!(
        p.evidence().counts,
        PairCounts {
            upper: 1,
            lower: 1,
            joint: 1
        }
    );
}

#[test]
fn upper_and_lower_ownership_fail_without_mutating_predecessor() {
    let f = Fixture::new();
    let pair = f.run(&f.original(), &[], limits()).unwrap();
    let lower_policy = AllocationPolicy {
        preferred_address: Some(0x4c840703),
        ranges: vec![range(0x4c840000, 4096)],
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let lower_site = PlanningSite {
        allocation: &lower_policy,
        ..f.sites()[0]
    };
    let lower = plan_install_with_emission(&ArtifactRequest {
        site: lower_site,
        emission: &f.input,
    })
    .unwrap();
    for step in [
        &pair.members()[0].source_steps()[0],
        &lower.source_steps()[0],
    ] {
        let mut predecessor = f.original();
        predecessor.append(step).unwrap();
        let before = predecessor.final_bytes().to_vec();
        let e = f.run(&predecessor, &[], limits()).unwrap_err();
        assert_eq!(e.stop, RoutedJmpStop::Eligibility("initial-pending"));
        assert_eq!(e.reason, Refusal::OwnershipConflict);
        assert_eq!(predecessor.final_bytes(), before);
    }
}

#[test]
fn budgets_zero_relation_and_overflow_are_explicit() {
    for (u, l, j, expected) in [
        (0, 1, 0, RoutedJmpStop::UpperBudget),
        (2, 0, 2, RoutedJmpStop::LowerBudget),
        (2, 1, 0, RoutedJmpStop::JointBudget),
        (1, 1, 2, RoutedJmpStop::InvalidBudget),
        (usize::MAX, 1, 1, RoutedJmpStop::InvalidBudget),
    ] {
        let mut f = Fixture::new();
        f.upper.max_candidates = u;
        f.lower.max_candidates = l;
        let mut bound = limits();
        bound.max_continuations = j;
        let e = f.run(&f.original(), &[], bound).unwrap_err();
        assert_eq!(e.stop, expected);
        assert_eq!(e.evidence.counts, PairCounts::default());
    }
}

#[test]
fn empty_lower_scope_charges_j_and_keeps_original_second_upper_slot() {
    let mut f = Fixture::new();
    f.lower.ranges = vec![range(0x083c0000, 4096)];
    // No preferred candidate in either window; original declared policy is
    // reused, not changed after the first upper outcome.
    f.lower.preferred_address = None;
    let p = f.run(&f.original(), &[], limits()).unwrap();
    assert_eq!(
        p.evidence().counts,
        PairCounts {
            upper: 2,
            lower: 1,
            joint: 2
        }
    );
    assert_eq!(
        p.evidence().upper_slots,
        [(0, Some(0x5f2300)), (1, Some(0x5f2400))]
    );
    assert!(p.evidence().lower_schedules[0].targets.is_empty());
    assert_eq!(p.evidence().lower_schedules[1].targets, [0x083c0503]);
    let mut cap = limits();
    cap.max_continuations = 1;
    let e = f.run(&f.original(), &[], cap).unwrap_err();
    assert_eq!(e.stop, RoutedJmpStop::JointBudget);
    assert_eq!(
        e.evidence.counts,
        PairCounts {
            upper: 1,
            lower: 0,
            joint: 1
        }
    );
    f.upper.max_candidates = 1;
    let e = f.run(&f.original(), &[], cap).unwrap_err();
    assert_eq!(e.stop, RoutedJmpStop::UpperBudget);
    assert_eq!(
        e.evidence.counts,
        PairCounts {
            upper: 1,
            lower: 0,
            joint: 1
        }
    );
    assert_eq!(e.unvisited_target, Some(0x5f2400));
}

#[test]
fn lower_image_budget_is_cumulative_and_does_not_retry() {
    let mut f = Fixture::new();
    f.lower.max_mapped_bytes = 4096;
    f.lower.preferred_address = Some(0x073c0600);
    let mut occupied = f.input.occupied().to_vec();
    occupied.push(range(0x073c0000, 4096));
    f.input = ArtifactEmission::new(f.input.profile().clone(), f.input.hook(), occupied);
    let p = f.original();
    let before = p.final_bytes().to_vec();
    let e = f.run(&p, &[], limits()).unwrap_err();
    assert_eq!(e.stop, RoutedJmpStop::LowerBudget);
    assert_eq!(
        e.evidence.counts,
        PairCounts {
            upper: 1,
            lower: 1,
            joint: 1
        }
    );
    assert_eq!(e.evidence.upper_slots.len(), 1);
    assert_eq!(p.final_bytes(), before);
}

#[test]
fn actual_pair_resource_refusals_retain_both_local_successes() {
    for which in 0..5 {
        let f = Fixture::new();
        let mut cap = limits();
        match which {
            0 => cap.bundle.max_steps = 1,
            1 => cap.bundle.max_mappings = 1,
            2 => cap.bundle.max_virtual_bytes = 8191,
            3 => cap.bundle.max_backing_bytes = 8191,
            _ => cap.bundle.max_virtual_span = 0x0100_0000,
        }
        let p = f.original();
        let before = p.final_bytes().to_vec();
        let e = f.run(&p, &[], cap).unwrap_err();
        assert_eq!(
            e.evidence.counts,
            PairCounts {
                upper: 1,
                lower: 1,
                joint: 1
            }
        );
        assert!(
            e.evidence
                .events
                .iter()
                .any(|r| r.stage == RoutedJmpStage::Aggregate
                    && r.refusal == Some(Refusal::AllocationUnavailable))
        );
        assert!(!e.evidence.accepted);
        assert_eq!(p.final_bytes(), before);
    }
}

#[test]
fn exact_upper_kernel_rejects_favorable_forged_target() {
    let f = Fixture::new();
    let sites = f.sites();
    let requests = sites.map(|site| PlanningRequest {
        original_code: site.code,
        site,
        emission: EmissionContext::Artifact(&f.input),
    });
    let p = preflight(&requests, &f.input, &f.original(), &[], limits())
        .unwrap_or_else(|_| panic!("fixture preflight"));
    let request = requests[1].with_code(&p.current);
    let result = emit_relocation_window(
        &request,
        &p.scan,
        p.source,
        f.input.occupied(),
        (None, None),
        RelocationWindow {
            physical: U,
            end: E,
            displaced: range(U, 5),
            instructions: p
                .scan
                .instructions()
                .iter()
                .filter(|i| U <= i.address() && i.address() < E)
                .collect(),
            authority: RelocationAuthority::RoutedJmp {
                proof: &p.proof,
                ordinal: 0,
                target: 0x5f2400,
            },
        },
        &mut SearchEvidence::default(),
    );
    assert!(matches!(result, Err(Refusal::InvalidPlan)));
}

#[test]
fn real_upper_image_route_and_byte_mutants_are_rejected() {
    let f = Fixture::new();
    let (proof, member) = f.upper_member();
    proof.verify_member(&member, &f.input, true).unwrap();
    let image = member.image();
    let mut entries = image.entry_routes().to_vec();
    entries[1].1 = entries[0].1;
    let mut v = ImageView::from(image);
    v.entries = &entries;
    assert_eq!(
        verify_view(v, &f.input, U, T, E, Some((F, &proof.original[4..]))),
        Err(Refusal::InvalidPlan)
    );
    let mut bodies = image.instruction_boundaries().to_vec();
    bodies[1].1 += 1;
    let mut v = ImageView::from(image);
    v.bodies = &bodies;
    assert_eq!(
        verify_view(v, &f.input, U, T, E, Some((F, &proof.original[4..]))),
        Err(Refusal::InvalidPlan)
    );
    let branch = (image.instruction_boundaries()[0].1 - image.address()) as usize;
    let suffix = (image.entry_routes()[1].1 - image.address()) as usize;
    let hook = image
        .artifact_metadata()
        .unwrap()
        .fields()
        .iter()
        .find(|f| f.role == "HookCall")
        .unwrap()
        .offset as usize;
    for at in [branch + 1, suffix + 2, image.bytes().len() - 1, hook] {
        let mut bytes = image.bytes().to_vec();
        bytes[at] ^= 1;
        let mut v = ImageView::from(image);
        v.bytes = &bytes;
        assert_eq!(
            verify_view(v, &f.input, U, T, E, Some((F, &proof.original[4..]))),
            Err(Refusal::InvalidPlan)
        );
    }
    let mut v = ImageView::from(image);
    v.layout.return_len = 4;
    assert_eq!(
        verify_view(v, &f.input, U, T, E, Some((F, &proof.original[4..]))),
        Err(Refusal::InvalidPlan)
    );
    let mut maps = image.program_counter_mappings().to_vec();
    maps.swap(0, 1);
    let mut v = ImageView::from(image);
    v.maps = &maps;
    assert_eq!(
        verify_view(v, &f.input, U, T, E, Some((F, &proof.original[4..]))),
        Err(Refusal::InvalidPlan)
    );
    let mut bytes = image.bytes().to_vec();
    bytes[0] = 0xe9;
    let mut v = ImageView::from(image);
    v.bytes = &bytes;
    assert_eq!(
        verify_view(v, &f.input, U, T, E, Some((F, &proof.original[4..]))),
        Err(Refusal::InvalidPlan),
        "helper control transfer cannot bypass the hook"
    );
}

#[test]
fn expected_metadata_targets_are_independent_of_candidate_fields() {
    let f = Fixture::new();
    let (proof, member) = f.upper_member();
    let image = member.image();
    for index in 0..4 {
        let mut metadata = image.artifact_metadata().unwrap().clone();
        metadata.fields[index].target += 1;
        let mut v = ImageView::from(image);
        v.metadata = Some(&metadata);
        assert_eq!(
            verify_view(v, &f.input, U, T, E, Some((F, &proof.original[4..]))),
            Err(Refusal::InvalidPlan)
        );
    }
    let mut metadata = image.artifact_metadata().unwrap().clone();
    metadata.fields.push(metadata.fields[0].clone());
    let mut v = ImageView::from(image);
    v.metadata = Some(&metadata);
    assert_eq!(
        verify_view(v, &f.input, U, T, E, Some((F, &proof.original[4..]))),
        Err(Refusal::InvalidPlan)
    );
}

#[test]
fn suffix_canonical_alternative_is_semantic_not_register_mnemonic_guess() {
    let mut f = Fixture::new();
    f.code[(F - BASE) as usize..(E - BASE) as usize].copy_from_slice(&[0x49, 0x8b, 0xfc]);
    f.refresh_heads();
    let p = f.run(&f.original(), &[], limits()).unwrap();
    assert_eq!(
        p.evidence().counts,
        PairCounts {
            upper: 1,
            lower: 1,
            joint: 1
        }
    );
    assert_eq!(
        p.members()[0].images().next().unwrap().entry_routes()[1].0,
        F
    );
}

#[test]
fn one_page_and_fetch_store_boundaries_do_not_relax() {
    let mut f = Fixture::new();
    f.upper.max_mapped_bytes = 4095;
    let e = f.run(&f.original(), &[], limits()).unwrap_err();
    assert_eq!(e.stop, RoutedJmpStop::Eligibility("site-resource"));
    let f = Fixture::new();
    let mut sites = f.sites();
    sites[0].search.max_displaced_bytes = 1;
    assert_eq!(
        plan_adjacent_routed_jmp_with_emission_after(sites, &f.input, &f.original(), &[], limits())
            .unwrap_err()
            .stop,
        RoutedJmpStop::Eligibility("exact-search-observe")
    );
    let mut sites = f.sites();
    sites[0].block = range(L, 3);
    assert_eq!(
        plan_adjacent_routed_jmp_with_emission_after(sites, &f.input, &f.original(), &[], limits())
            .unwrap_err()
            .stage,
        RoutedJmpStage::Preflight
    );
    let mut f = Fixture::new();
    let offset = (L - BASE) as usize;
    f.code[offset - 7..offset + 8].fill(0x90);
    f.code[offset + 1..offset + 8].copy_from_slice(&[0x76, 0xbe, 0xeb, 0x43, 0x4c, 0x89, 0xe7]);
    f.refresh_heads();
    let mut sites = f.sites();
    sites[0].logical_pc = L + 1;
    sites[0].block = range(L + 1, 2);
    sites[1].logical_pc = U + 1;
    sites[1].block = range(U + 1, 2);
    let e =
        plan_adjacent_routed_jmp_with_emission_after(sites, &f.input, &f.original(), &[], limits())
            .unwrap_err();
    assert_eq!(e.stop, RoutedJmpStop::Eligibility("geometry"));
    assert_eq!(
        e.evidence.counts,
        PairCounts::default(),
        "two-byte store crosses a cache line"
    );
}

// R1 controls use the original two upper slots and unchanged U2/L1/J2 caps.
// An image/append refusal must not admit a lower scope or return half a pair.
fn assert_upper_only_failure(
    error: &RoutedJmpFailure,
    predecessor: &Composition,
    before: &Composition,
) {
    assert_eq!(error.stop, RoutedJmpStop::UpperBudget);
    assert_eq!(error.stage, RoutedJmpStage::UpperImage);
    assert_eq!(error.reason, Refusal::AllocationUnavailable);
    assert_eq!(error.unvisited_target, Some(0x5f2b00));
    assert_eq!(error.evidence.selected, [L, U]);
    assert_eq!(error.evidence.suffix, Some(F));
    assert_eq!(
        error.evidence.counts,
        PairCounts {
            upper: 2,
            lower: 0,
            joint: 0
        }
    );
    assert_eq!(
        error.evidence.upper_slots,
        [(0, Some(0x5f2300)), (1, Some(0x5f2400))]
    );
    assert!(error.evidence.lower_schedules.is_empty());
    assert!(!error.evidence.accepted);
    assert!(!error.evidence.classification_complete);
    let preflight = &error.evidence.events[0];
    assert_eq!(preflight.stage, RoutedJmpStage::Preflight);
    assert_eq!(preflight.refusal, None);
    assert_eq!(preflight.before, PairCounts::default());
    assert_eq!(preflight.after, PairCounts::default());
    assert_eq!(preflight.upper, None);
    assert_eq!(preflight.lower, None);
    assert!(preflight.search.is_none());
    assert_eq!(predecessor.final_bytes(), before.final_bytes());
    assert_eq!(predecessor.locks(), before.locks());
    assert_eq!(
        predecessor, before,
        "all predecessor ownership survives refusal"
    );
}

#[test]
fn denied_upper_page_debits_each_original_image_slot_without_lower_work() {
    let mut f = Fixture::new();
    let mut occupied = f.input.occupied().to_vec();
    occupied.push(range(0x5f2000, 4096));
    f.input = ArtifactEmission::new(f.input.profile().clone(), f.input.hook(), occupied);
    let predecessor = f.original();
    let before = predecessor.clone();
    let error = f.run(&predecessor, &[], limits()).unwrap_err();
    assert_upper_only_failure(&error, &predecessor, &before);
    assert_eq!(error.evidence.events.len(), 3);
    for (ordinal, target) in [0x5f2300, 0x5f2400].into_iter().enumerate() {
        let event = &error.evidence.events[ordinal + 1];
        assert_eq!(event.stage, RoutedJmpStage::UpperImage);
        assert_eq!(event.refusal, Some(Refusal::AllocationUnavailable));
        assert_eq!(event.upper, Some((ordinal, target)));
        assert_eq!(event.lower, None);
        assert_eq!(
            event.before,
            PairCounts {
                upper: ordinal,
                lower: 0,
                joint: 0
            }
        );
        assert_eq!(
            event.after,
            PairCounts {
                upper: ordinal + 1,
                lower: 0,
                joint: 0
            }
        );
        assert!(!event.search.as_ref().unwrap().accepted);
    }
}

#[test]
fn resolved_out_of_range_hook_debits_upper_images_without_lower_work() {
    let mut f = Fixture::new();
    // Resolved and canonical, but outside signed rel32 reach of either fixed
    // upper page. This is not the existing unresolved-hook preflight control.
    const FAR_HOOK: u64 = 0x1_0000_0000;
    assert!(FAR_HOOK - 0x5f3000 > i32::MAX as u64);
    f.input = ArtifactEmission::new(
        f.input.profile().clone(),
        SymbolicHook {
            identity: 1,
            address: Some(FAR_HOOK),
        },
        f.input.occupied().to_vec(),
    );
    let predecessor = f.original();
    let before = predecessor.clone();
    let error = f.run(&predecessor, &[], limits()).unwrap_err();
    assert_upper_only_failure(&error, &predecessor, &before);
    assert_eq!(error.evidence.events.len(), 3);
    for (ordinal, target) in [0x5f2300, 0x5f2400].into_iter().enumerate() {
        let event = &error.evidence.events[ordinal + 1];
        assert_eq!(event.stage, RoutedJmpStage::UpperImage);
        let Some(Refusal::Backend(raw)) = &event.refusal else {
            panic!("resolved out-of-range hook must retain its raw image refusal");
        };
        assert!(
            raw.starts_with("artifact OutOfRange: DisplacementOutOfRange {"),
            "{raw}"
        );
        assert_eq!(event.upper, Some((ordinal, target)));
        assert_eq!(event.lower, None);
        assert_eq!(
            event.before,
            PairCounts {
                upper: ordinal,
                lower: 0,
                joint: 0
            }
        );
        assert_eq!(
            event.after,
            PairCounts {
                upper: ordinal + 1,
                lower: 0,
                joint: 0
            }
        );
        assert!(!event.search.as_ref().unwrap().accepted);
    }
}

#[test]
fn real_predecessor_allocation_collision_follows_upper_acceptance_and_rolls_back() {
    let f = Fixture::new();
    // The real predecessor edits only the separate MOV EAX,7, but owns the
    // exact page containing BOTH original upper candidates. Deliberately omit
    // its allocation from input.occupied(): this forged/incomplete occupancy
    // negative must reach Composition's overlap guard after local acceptance.
    let allocation = AllocationPolicy {
        preferred_address: Some(0x5f2000),
        ranges: vec![range(0x5f2000, 4096)],
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let site = PlanningSite {
        logical_pc: BASE + 0x100,
        block: range(BASE + 0x100, 5),
        allocation: &allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0,
            max_displaced_bytes: 5,
            max_sites: 1,
        },
        ..f.sites()[0]
    };
    let prior = plan_install_with_emission(&ArtifactRequest {
        site,
        emission: &f.input,
    })
    .unwrap();
    assert_eq!(prior.source_steps().len(), 1);
    let parts = prior.source_steps()[0].parts();
    assert_eq!(parts.kind, PlanKind::Relocation);
    assert_eq!(parts.displaced, range(BASE + 0x100, 5));
    assert!(!parts.displaced.overlaps(range(L, (E - L) as usize)));
    assert_eq!(parts.allocations.len(), 1);
    assert_eq!(parts.allocations[0].range, range(0x5f2000, 4096));
    assert_eq!(prior.images().next().unwrap().address(), 0x5f2000);
    assert!(
        f.input
            .occupied()
            .iter()
            .all(|r| !r.overlaps(range(0x5f2000, 4096)))
    );
    let mut predecessor = f.original();
    predecessor.append(&prior.source_steps()[0]).unwrap();
    assert_eq!(predecessor.locks(), &[range(BASE + 0x100, 5)]);
    assert_ne!(predecessor.final_bytes(), f.original().final_bytes());
    predecessor
        .require_unclaimed_ranges(&[range(L, 2), range(U, 5)])
        .unwrap();
    let before = predecessor.clone();
    let error = f.run(&predecessor, &[], limits()).unwrap_err();
    assert_upper_only_failure(&error, &predecessor, &before);
    assert_eq!(error.evidence.events.len(), 7);
    for (ordinal, target) in [0x5f2300, 0x5f2400].into_iter().enumerate() {
        let events = &error.evidence.events[1 + 3 * ordinal..4 + 3 * ordinal];
        for event in events {
            assert_eq!(event.upper, Some((ordinal, target)));
            assert_eq!(event.lower, None);
            assert_eq!(
                event.after,
                PairCounts {
                    upper: ordinal + 1,
                    lower: 0,
                    joint: 0
                }
            );
        }
        assert_eq!(events[0].stage, RoutedJmpStage::UpperImage);
        assert_eq!(
            events[0].refusal, None,
            "real upper image must accept before collision"
        );
        assert_eq!(
            events[0].before,
            PairCounts {
                upper: ordinal,
                lower: 0,
                joint: 0
            }
        );
        assert!(events[0].search.as_ref().unwrap().accepted);
        assert_eq!(events[1].stage, RoutedJmpStage::UpperProof);
        assert_eq!(
            events[1].refusal, None,
            "real upper proof must accept before collision"
        );
        assert_eq!(events[1].before, events[1].after);
        assert!(events[1].search.is_none());
        assert_eq!(events[2].stage, RoutedJmpStage::UpperAppend);
        assert_eq!(events[2].refusal, Some(Refusal::OwnershipConflict));
        assert_eq!(events[2].before, events[2].after);
        assert!(events[2].search.is_none());
    }
}

#[test]
fn real_upper_image_missing_and_extra_suffix_entries_are_rejected() {
    let f = Fixture::new();
    let (proof, member) = f.upper_member();
    proof.verify_member(&member, &f.input, true).unwrap();
    assert_eq!(
        (
            proof.lower,
            proof.upper,
            proof.suffix,
            proof.end,
            proof.backward,
            proof.forward
        ),
        (L, U, F, E, B, T)
    );
    assert_eq!(proof.original, [0x76, 0xbe, 0xeb, 0x43, 0x4c, 0x89, 0xe7]);
    let image = member.image();
    assert_eq!(image.address(), 0x5f2300);
    assert_eq!(
        image
            .entry_routes()
            .iter()
            .map(|&(pc, _)| pc)
            .collect::<Vec<_>>(),
        [U, F]
    );
    assert_eq!(image.entry_routes()[1], image.instruction_boundaries()[1]);
    let check = |v| verify_view(v, &f.input, U, T, E, Some((F, &[0x4c, 0x89, 0xe7])));
    check(ImageView::from(image)).unwrap();
    let mut missing = image.entry_routes().to_vec();
    missing.remove(1);
    let mut view = ImageView::from(image);
    view.entries = &missing;
    assert_eq!(check(view), Err(Refusal::InvalidPlan), "missing F entry");
    let mut extra = image.entry_routes().to_vec();
    extra.push(image.entry_routes()[1]);
    let mut view = ImageView::from(image);
    view.entries = &extra;
    assert_eq!(check(view), Err(Refusal::InvalidPlan), "extra F entry");
}

#[test]
fn real_upper_missing_wrong_routes_and_source_illegal_marker_are_rejected() {
    let f = Fixture::new();
    let (proof, member) = f.upper_member();
    proof.verify_member(&member, &f.input, true).unwrap();
    assert_eq!(
        (proof.upper, proof.suffix, proof.end, proof.forward),
        (U, F, E, T)
    );
    let parts = member.plan().parts();
    let route = member.image().entry_routes()[1];
    assert_eq!(route.0, F);
    assert_ne!(route.1, 0x5f2300, "F bypasses U's observing entry");
    assert_eq!(
        parts.obligations,
        [
            EntryObligation::Preserved(U),
            EntryObligation::Routed(crate::contracts::EntryRoute {
                original: F,
                generated: route.1
            })
        ]
    );
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(parts.writes[0].address, U);
    assert_eq!(parts.writes[0].bytes, [0xe9, 0xfb, 0x06, 0x1f, 0]);
    assert_eq!(parts.writes[0].address + 2, F);
    let artifact = crate::emission::ArtifactPlan::single(member.clone());
    assert!(
        artifact
            .images()
            .next()
            .unwrap()
            .metadata()
            .requirements()
            .contains(&ArtifactRequirement::EntryRouterBootstrap)
    );
    for kind in 0..4 {
        let mut changed = parts.clone();
        match kind {
            0 => {
                changed.obligations.remove(1);
            }
            1 => {
                changed.obligations[1] = EntryObligation::Routed(crate::contracts::EntryRoute {
                    original: F + 1,
                    generated: route.1,
                })
            }
            2 => {
                changed.obligations[1] = EntryObligation::Routed(crate::contracts::EntryRoute {
                    original: F,
                    generated: 0x5f2300,
                })
            }
            _ => changed.writes[0].bytes[2] = 0x90,
        }
        // These edits remain structurally valid relocation plans. The sealed
        // semantic verifier, not unchecked construction, must refuse them.
        let mut mutant = member.clone();
        mutant.plan = crate::contracts::PatchPlan::checked(changed).unwrap();
        assert_eq!(
            proof.verify_member(&mutant, &f.input, true),
            Err(Refusal::InvalidPlan),
            "missing route, wrong route source/destination, or corrupt source marker: {kind}"
        );
    }
}
