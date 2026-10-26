//! Pure artifact-emission contract tests; no generated code is executed.

use crate::contracts::*;
use crate::emission::*;
use crate::engine::{self, EnginePolicy, Tactic};
use crate::neighbor::NeighborSearch;
use crate::planner::HookSemantics;
use crate::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
use crate::scanner::InstructionScanner;
use crate::trampoline::{SavedExtendedStateLayout, TrampolineError, TrampolinePlan};

fn target(hook: Option<u64>, occupied: Vec<AddressRange>) -> ArtifactEmission {
    ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            SavedExtendedStateLayout::describe_target_fxsave64(),
            7,
        )
        .unwrap(),
        SymbolicHook {
            identity: 11,
            address: hook,
        },
        occupied,
    )
}

#[test]
fn declared_target_state_checks_shape_but_never_claims_runtime_readiness() {
    let avx = SavedExtendedStateLayout::describe_target_xsave64(7, &[(4, 576, 256)]).unwrap();
    assert_eq!(avx.mask(), 7);
    assert_eq!(avx.image_len(), 832);
    assert_eq!(avx.len(), 832);
    assert_eq!(avx.components()[0].xfeature(), 4);
    for (mask, components) in [
        (7, vec![]),
        (7, vec![(4, 575, 256)]),
        (7, vec![(4, u64::MAX, 2)]),
        (0x27, vec![(4, 576, 256), (32, 832, 64)]),
        (0x207, vec![(4, 576, 256), (512, 800, 8)]),
        (0x203, vec![(512, 576, 4)]),
        (0x403, vec![(1024, 576, 8)]),
    ] {
        assert!(matches!(
            SavedExtendedStateLayout::describe_target_xsave64(mask, &components),
            Err(TrampolineError::InvalidExtendedStateLayout { .. })
        ));
    }
    assert!(
        TargetProfile::linux_x86_64_legacy_evex(SavedExtendedStateLayout::UNAVAILABLE, 1).is_err()
    );
}

#[test]
fn five_forced_tactics_keep_symbolic_binding_and_checked_source_geometry() {
    // Exactly the existing engine contract's five source shapes and dictated
    // displacement geometries, using virtual coordinates only; no mapped code.
    for tactic in [
        Tactic::Relocation,
        Tactic::GeneralizedPun,
        Tactic::PrefixedPun,
        Tactic::SuccessorEviction,
        Tactic::NeighborEviction,
    ] {
        let s = 0x4200_0000_0080_u64;
        let (mut body, block_len, heads) = match tactic {
            Tactic::Relocation => (vec![0xb8, 42, 0, 0, 0, 0xc3], 6, vec![0, 5]),
            Tactic::GeneralizedPun => (
                vec![0x0f, 0x1f, 0, 0xb8, 42, 0, 0, 0, 0xc3],
                9,
                vec![0, 3, 8],
            ),
            Tactic::PrefixedPun => (vec![0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3], 8, vec![0, 2, 7]),
            Tactic::SuccessorEviction => (
                vec![
                    0x0f, 0x1f, 0, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3,
                ],
                17,
                vec![0, 3, 11, 16, 64, 74],
            ),
            Tactic::NeighborEviction => (vec![0x75, 1, 0x90, 0xc3], 2, vec![0, 2, 3, 64, 74]),
        };
        if matches!(tactic, Tactic::SuccessorEviction | Tactic::NeighborEviction) {
            body.resize(64, 0x90);
            body.extend_from_slice(&[0x48, 0xb8]);
            body.extend_from_slice(&42_u64.to_le_bytes());
            body.push(0xc3);
        }
        let function = AddressRange::new(s, body.len()).unwrap();
        let mut code = vec![0x90; 16];
        code.extend_from_slice(&body);
        let identity = CodeIdentity {
            source: SourceIdentity([7; 32]),
            mapping: 1,
            generation: 3,
        };
        let entries = LegalEntrySet {
            identity,
            scope: function,
            provenance: EntryProvenance::Declared(
                "existing engine fixture geometry; explicit entries only".into(),
            ),
            completeness: EntryCompleteness::Complete,
            entries: heads
                .into_iter()
                .map(|offset| LegalEntry {
                    address: s + offset,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let selected = match tactic {
            Tactic::Relocation | Tactic::NeighborEviction => s + 0x400_0000,
            Tactic::GeneralizedPun => s + 5 + 0x2ab8_0000 + 0x8000,
            Tactic::PrefixedPun => s + 6 + 0x2ab8,
            Tactic::SuccessorEviction => s + 5 + 0x56e9_0000 + 0x8000,
        };
        let victim = if tactic == Tactic::SuccessorEviction {
            s + 8 + 0x0012_3456
        } else {
            s + 0x600_0000
        };
        let policy = |address| AllocationPolicy {
            ranges: vec![AddressRange::new(address & !4095, 8192).unwrap()],
            preferred_address: Some(address),
            max_candidates: 256,
            max_mappings: 1,
            max_mapped_bytes: 8192,
        };
        let allocation = policy(selected);
        let victim_allocation = policy(victim);
        let emission = target(
            Some(s + 0x1000),
            vec![AddressRange::new(s & !4095, 8192).unwrap()],
        );
        let request = ArtifactRequest {
            site: PlanningSite {
                identity,
                code: &code,
                base_address: s - 16,
                function,
                block: AddressRange::new(s, block_len).unwrap(),
                logical_pc: s,
                entries: &entries,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_sites: 1,
                    ..SearchPolicy::default()
                },
            },
            emission: &emission,
        };
        let plan = engine::plan_with_emission(
            &request,
            &victim_allocation,
            EnginePolicy {
                forced: Some(tactic),
                neighbor: NeighborSearch {
                    forced_victim: Some(s + 64),
                    ..NeighborSearch::default()
                },
                ..EnginePolicy::default()
            },
        )
        .unwrap();
        let ArtifactMetrics::Engine(winner, _, attempts) = plan.metrics() else {
            panic!("engine metrics missing")
        };
        assert_eq!(*winner, tactic);
        assert_eq!(attempts.len(), 1);
        assert!(!plan.qualification_complete());
        let expected_images =
            if matches!(tactic, Tactic::SuccessorEviction | Tactic::NeighborEviction) {
                2
            } else {
                1
            };
        assert_eq!(plan.images().count(), expected_images);
        let mut hooks = 0;
        for image in plan.images() {
            assert!(!image.metadata().qualification_complete());
            assert!(
                image
                    .metadata()
                    .requirements()
                    .contains(&ArtifactRequirement::TargetCpuAndStateAtEntry)
            );
            assert!(
                image
                    .metadata()
                    .requirements()
                    .contains(&ArtifactRequirement::OriginalImmediatePointerProvenance)
            );
            for field in image.metadata().fields() {
                assert!(field.offset + field.width as u64 <= image.bytes().len() as u64);
                if field.role == "HookCall" {
                    assert_eq!(field.target, i128::from(s + 0x1000));
                    hooks += 1;
                }
            }
        }
        assert_eq!(hooks, 1);
        for step in plan.source_steps() {
            assert_eq!(step.parts().identity, identity);
            step.check_entry_obligations().unwrap();
        }
    }
}

#[test]
fn callback_free_self_branch_targets_its_own_generated_entry() {
    let pc = 0x400000;
    let scan = InstructionScanner::default()
        .scan(&[0x75, 0xfe], pc)
        .unwrap();
    let plan = TrampolinePlan::from_instruction(&scan, pc).unwrap();
    let image = plan
        .emit_artifact_at(0x500000, &target(None, vec![]))
        .unwrap();
    let metadata = image.artifact_metadata().unwrap();
    let branch = metadata
        .fields()
        .iter()
        .find(|field| field.role.starts_with("OriginalBranch"))
        .unwrap();
    assert_eq!(branch.target, 0x500000);
    assert_eq!(branch.width, 1);
    assert_eq!(image.entry_routes(), &[(pc, 0x500000)]);
    assert_eq!(image.instruction_boundaries(), &[(pc, 0x500000)]);
    assert_eq!(metadata.fields().last().unwrap().target, i128::from(pc + 2));
    assert!(
        !metadata
            .requirements()
            .iter()
            .any(|item| matches!(item, ArtifactRequirement::HookAbiAndReadiness(_)))
    );
}

#[test]
fn rip_displacement_uses_next_instruction_after_trailing_immediate() {
    let pc = 0x400000;
    let scan = InstructionScanner::default()
        .scan(&[0x83, 0x3d, 0, 1, 0, 0, 7], pc)
        .unwrap();
    let image = TrampolinePlan::from_instruction(&scan, pc)
        .unwrap()
        .emit_artifact_at(0x500000, &target(None, vec![]))
        .unwrap();
    let field = image
        .artifact_metadata()
        .unwrap()
        .fields()
        .iter()
        .find(|field| field.role.starts_with("OriginalRipOperand"))
        .unwrap();
    assert_eq!(
        (field.offset, field.width, field.origin, field.target),
        (2, 4, 7, 0x400107)
    );
    assert_eq!(
        i32::from_le_bytes(image.bytes()[2..6].try_into().unwrap()),
        -0x0fff00
    );
    assert_eq!(image.bytes()[6], 7);
}

#[test]
fn symbolic_replace_has_hook_entry_without_original_execution_boundary() {
    let pc = 0x400000;
    let scan = InstructionScanner::default()
        .scan(&[0xff, 0xc0], pc)
        .unwrap();
    let plan = TrampolinePlan::from_symbolic_short_instruction(&scan, pc, true).unwrap();
    let image = plan
        .emit_artifact_at(0x500000, &target(Some(pc + 4096), vec![]))
        .unwrap();
    assert_eq!(image.entry_routes(), &[(pc, 0x500000)]);
    assert!(image.instruction_boundaries().is_empty());
    let fields = image.artifact_metadata().unwrap().fields();
    assert_eq!(
        fields
            .iter()
            .map(|field| field.role.as_str())
            .collect::<Vec<_>>(),
        vec!["LogicalPc", "HookCall", "Return"]
    );
    assert_eq!(fields.last().unwrap().target, i128::from(pc + 2));
}

#[test]
fn unresolved_far_and_absolute_operands_fail_without_fabricating_binding() {
    let pc = 0x400000;
    let scan = InstructionScanner::default()
        .scan(&[0xff, 0xc0], pc)
        .unwrap();
    let plan = TrampolinePlan::from_symbolic_short_instruction(&scan, pc, false).unwrap();
    for (binding, reason) in [
        (None, ArtifactRefusalKind::TargetBinding),
        (Some(u64::MAX), ArtifactRefusalKind::OutOfRange),
    ] {
        assert!(
            matches!(plan.emit_artifact_at(0x500000,&target(binding,vec![])),Err(TrampolineError::Artifact {reason:actual,..}) if actual==reason)
        );
    }
    let scan = InstructionScanner::default()
        .scan(&[0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0], pc)
        .unwrap();
    let plan = TrampolinePlan::from_instruction(&scan, pc).unwrap();
    assert!(matches!(
        plan.emit_artifact_at(0x500000, &target(None, vec![])),
        Err(TrampolineError::Artifact {
            reason: ArtifactRefusalKind::RuntimeAbsoluteFixup,
            ..
        })
    ));
}

#[test]
fn baseless_indexed_absolute_memory_requires_a_runtime_fixup() {
    let pc = 0x400000;
    let code = [0x48, 0x8b, 0x04, 0xc5, 0x00, 0x10, 0x40, 0x00, 0xc3];
    let scan = InstructionScanner::default().scan(&code, pc).unwrap();
    let plan = TrampolinePlan::from_instruction(&scan, pc).unwrap();
    let outcome = plan.emit_artifact_at(0x500000, &target(Some(0x410000), vec![]));
    assert!(
        matches!(
            outcome,
            Err(TrampolineError::Artifact {
                reason: ArtifactRefusalKind::RuntimeAbsoluteFixup,
                ..
            })
        ),
        "base-less indexed absolute displacement must not disappear from provenance"
    );
}

#[test]
fn indexed_and_truncated_address_shapes_keep_exact_refusals_and_positive_control() {
    for (bytes, reason) in [
        (
            vec![0x67, 0x48, 0x8b, 0x04, 0xc5, 0, 0x10, 0x40, 0],
            ArtifactRefusalKind::RuntimeAbsoluteFixup,
        ),
        (
            vec![0x48, 0x8d, 0x04, 0xc5, 0, 0x10, 0x40, 0],
            ArtifactRefusalKind::RuntimeAbsoluteFixup,
        ),
        (
            vec![0x67, 0x48, 0x8b, 0x05, 0, 0, 0, 0],
            ArtifactRefusalKind::UnmodelledEncoding,
        ),
    ] {
        let scan = InstructionScanner::default()
            .scan(&bytes, 0x400000)
            .unwrap();
        let plan = TrampolinePlan::from_instruction(&scan, 0x400000).unwrap();
        let result = plan.emit_artifact_at(0x500000, &target(Some(0x410000), vec![]));
        assert!(
            matches!(result, Err(TrampolineError::Artifact { reason: actual, .. }) if actual == reason)
        );
    }
    // A register base with an index and a constant byte offset remains supported.
    let scan = InstructionScanner::default()
        .scan(&[0x48, 0x8b, 0x44, 0xc3, 0x10], 0x400000)
        .unwrap();
    let image = TrampolinePlan::from_instruction(&scan, 0x400000)
        .unwrap()
        .emit_artifact_at(0x500000, &target(Some(0x410000), vec![]))
        .unwrap();
    assert!(!image.artifact_metadata().unwrap().qualification_complete());
    assert_eq!(&image.bytes()[..5], &[0x48, 0x8b, 0x44, 0xc3, 0x10]);
}
