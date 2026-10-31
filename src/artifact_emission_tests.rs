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

// This decoder-driven finite model checks branch meaning and register/flags
// metadata. It is not native execution or target-CPU state evidence.
fn jrcxz_bridge_exit(bytes: &[u8], address: u64, rcx: u64) -> u64 {
    use iced_x86::{Code, Decoder, DecoderOptions, InstructionInfoFactory, OpAccess, Register};
    let mut info = InstructionInfoFactory::new();
    let mut pc = address;
    for _ in 0..3 {
        if pc < address || pc >= address + bytes.len() as u64 {
            return pc;
        }
        let i = Decoder::with_ip(
            64,
            &bytes[(pc - address) as usize..],
            pc,
            DecoderOptions::NONE,
        )
        .decode();
        assert_eq!(i.rflags_read(), 0);
        assert_eq!(i.rflags_modified(), 0);
        let usage = info.info(&i);
        assert!(usage.used_memory().is_empty());
        let registers: Vec<_> = usage
            .used_registers()
            .iter()
            .map(|r| (r.register(), r.access()))
            .collect();
        pc = match i.code() {
            Code::Jrcxz_rel8_64 => {
                assert_eq!(i.len(), 2);
                assert_eq!(registers, [(Register::RCX, OpAccess::Read)]);
                if rcx == 0 {
                    i.near_branch_target()
                } else {
                    i.next_ip()
                }
            }
            Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => {
                assert!(registers.is_empty());
                i.near_branch_target()
            }
            other => panic!("unexpected bridge instruction {other:?}"),
        };
    }
    assert!(pc < address || pc >= address + bytes.len() as u64);
    pc
}

#[test]
fn jrcxz_artifact_bridge_has_complete_fields_paths_and_pc_ownership() {
    let pc = 0xa954;
    let scan = InstructionScanner::default().scan(&[0xe3, 4], pc).unwrap();
    let image = TrampolinePlan::from_instruction(&scan, pc)
        .unwrap()
        .emit_artifact_at(0x6f9259, &target(None, vec![]))
        .unwrap();
    assert_eq!(image.bytes().len(), 14);
    assert_eq!(&image.bytes()[..5], &[0xe3, 2, 0xeb, 5, 0xe9]);
    assert_eq!(image.entry_routes(), &[(pc, image.address())]);
    assert_eq!(image.instruction_boundaries(), &[(pc, image.address())]);
    for offset in 0..14 {
        let owners: Vec<_> = image
            .program_counter_mappings()
            .iter()
            .filter_map(|m| m.translate(image.address() + offset))
            .collect();
        assert_eq!(owners, [if offset < 9 { pc } else { pc + 2 }]);
    }
    let metadata = image.artifact_metadata().unwrap();
    assert!(!metadata.qualification_complete());
    let fields = metadata.fields();
    assert_eq!(
        fields
            .iter()
            .map(|f| (f.offset, f.width, f.origin, f.target))
            .collect::<Vec<_>>(),
        [
            (1, 1, 2, i128::from(image.address() + 4)),
            (3, 1, 4, i128::from(image.address() + 9)),
            (5, 4, 9, i128::from(pc + 6)),
            (10, 4, 14, i128::from(pc + 2))
        ]
    );
    assert_eq!(
        fields[0].role,
        format!("OriginalBranchBridge {{ original_pc: {pc} }}")
    );
    assert_eq!(fields[1].role, fields[0].role);
    assert_eq!(
        fields[2].role,
        format!("OriginalBranch {{ original_pc: {pc} }}")
    );
    assert_eq!(fields[3].role, "Return");
    for bias in [0, 0x7000_0000_0000] {
        for rcx in [0, 1, 1 << 32, u64::MAX] {
            assert_eq!(
                jrcxz_bridge_exit(image.bytes(), image.address() + bias, rcx),
                pc + bias + if rcx == 0 { 6 } else { 2 }
            );
        }
    }
    assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
    assert!(
        metadata
            .requirements()
            .contains(&ArtifactRequirement::GeneratedUnwindInformation)
    );
}

#[test]
fn jrcxz_artifact_bridge_routes_internal_entries_and_keeps_finite_refusals() {
    use iced_x86::{Code, Decoder, DecoderOptions};
    let pc = 0x400000;
    // Target is a separately enterable original head inside this displaced window.
    let scan = InstructionScanner::default()
        .scan(&[0xe3, 1, 0x90, 0x90, 0x90], pc)
        .unwrap();
    let image = TrampolinePlan::from_symbolic_window(&scan, pc, pc, pc + 5, false)
        .unwrap()
        .emit_artifact_at(0x500000, &target(Some(pc + 0x1000), vec![]))
        .unwrap();
    let routes = image.entry_routes();
    assert_eq!(
        routes.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
        [pc, pc + 2, pc + 3, pc + 4]
    );
    let body = image.instruction_boundaries()[0].1;
    let at = (body - image.address()) as usize;
    let jump =
        Decoder::with_ip(64, &image.bytes()[at + 4..], body + 4, DecoderOptions::NONE).decode();
    assert_eq!(jump.code(), Code::Jmp_rel32_64);
    assert_eq!(jump.near_branch_target(), routes[2].1);
    let field = image
        .artifact_metadata()
        .unwrap()
        .fields()
        .iter()
        .find(|f| f.role == format!("OriginalBranch {{ original_pc: {pc} }}"))
        .unwrap();
    assert_eq!(field.target, i128::from(routes[2].1));
    assert_eq!(body + 9, routes[1].1);
    for offset in 0..9 {
        assert_eq!(
            image
                .program_counter_mappings()
                .iter()
                .find_map(|m| m.translate(body + offset)),
            Some(pc)
        );
    }
    assert!(
        !routes
            .iter()
            .any(|(_, generated)| [body + 2, body + 4].contains(generated))
    );
    // A self target goes to the observing entry, not the restored bridge body.
    let self_scan = InstructionScanner::default()
        .scan(&[0xe3, 0xfe], pc)
        .unwrap();
    let self_image = TrampolinePlan::from_symbolic_short_instruction(&self_scan, pc, false)
        .unwrap()
        .emit_artifact_at(0x500000, &target(Some(pc + 0x1000), vec![]))
        .unwrap();
    let original = self_image
        .artifact_metadata()
        .unwrap()
        .fields()
        .iter()
        .find(|f| f.role == format!("OriginalBranch {{ original_pc: {pc} }}"))
        .unwrap();
    assert_eq!(original.target, i128::from(self_image.entry_routes()[0].1));
    assert_ne!(
        original.target,
        i128::from(self_image.instruction_boundaries()[0].1)
    );
    // No unsupported expansion is accepted by the new finite route.
    for bytes in [
        &[0x67, 0xe3, 4][..],
        &[0x2e, 0xe3, 4],
        &[0xe2, 4],
        &[0xe1, 4],
        &[0xe0, 4],
    ] {
        let scan = InstructionScanner::default().scan(bytes, pc).unwrap();
        let result = TrampolinePlan::from_instruction(&scan, pc)
            .unwrap()
            .emit_artifact_at(0x500000, &target(None, vec![]));
        assert!(matches!(
            result,
            Err(TrampolineError::Artifact {
                reason: ArtifactRefusalKind::UnmodelledEncoding,
                ..
            })
        ));
    }
    // Exact signed-rel32 endpoints for the taken E9; next-byte misses still refuse.
    let destination = 0x1_0000_0000_u64;
    // rel8=-5 makes both the taken and fallthrough rel32 displacements equal,
    // so the mandatory return field does not mask the bridge's endpoints.
    let pc = destination + 3;
    let scan = InstructionScanner::default()
        .scan(&[0xe3, 0xfb], pc)
        .unwrap();
    let plan = TrampolinePlan::from_instruction(&scan, pc).unwrap();
    for address in [
        destination - 9 - i32::MAX as u64,
        destination - 9 + (1_u64 << 31),
    ] {
        assert!(
            plan.emit_artifact_at(address, &target(None, vec![]))
                .is_ok()
        );
    }
    for address in [
        destination - 10 - i32::MAX as u64,
        destination - 8 + (1_u64 << 31),
    ] {
        assert!(matches!(
            plan.emit_artifact_at(address, &target(None, vec![])),
            Err(TrampolineError::Artifact {
                reason: ArtifactRefusalKind::OutOfRange,
                ..
            })
        ));
    }
}

#[test]
fn jrcxz_artifact_engine_keeps_source_pair_and_allocation_authority() {
    let pc = 0xa954;
    let mut code = vec![0xe3, 4, 0x90, 0x90, 0x90, 0x90, 0xc3];
    code.resize(64, 0x90);
    code.extend_from_slice(&[0x48, 0xb8, 42, 0, 0, 0, 0, 0, 0, 0, 0xc3]);
    let function = AddressRange::new(pc, code.len()).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0x14; 32]),
        mapping: 1,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: function,
        completeness: EntryCompleteness::Complete,
        provenance: EntryProvenance::Declared("finite JRCXZ/long-victim pure fixture".into()),
        entries: [0, 2, 3, 4, 5, 6, 64, 74]
            .into_iter()
            .map(|offset| LegalEntry {
                address: pc + offset,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    };
    let policy = |preferred| AllocationPolicy {
        ranges: vec![AddressRange::new(preferred, 4096).unwrap()],
        preferred_address: Some(preferred),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let selected = policy(0x700000);
    let victim = policy(0x720000);
    let emission = target(
        Some(0x2000),
        vec![AddressRange::new(pc & !4095, 4096).unwrap()],
    );
    let request = ArtifactRequest {
        site: PlanningSite {
            identity,
            code: &code,
            base_address: pc,
            function,
            block: AddressRange::new(pc, 2).unwrap(),
            logical_pc: pc,
            entries: &entries,
            semantics: HookSemantics::Observe,
            allocation: &selected,
            search: SearchPolicy {
                max_sites: 1,
                max_upstream_bytes: 0,
                ..SearchPolicy::default()
            },
        },
        emission: &emission,
    };
    let search = EnginePolicy {
        forced: Some(Tactic::NeighborEviction),
        neighbor: NeighborSearch {
            max_victims: 1,
            max_pairs: 1,
            forced_victim: Some(pc + 64),
        },
        ..EnginePolicy::default()
    };
    let planned = engine::plan_with_emission(&request, &victim, search).unwrap();
    assert_eq!(planned.images().count(), 2);
    assert_eq!(planned.source_steps().len(), 2);
    assert!(!planned.qualification_complete());
    for step in planned.source_steps() {
        assert_eq!(step.parts().identity, identity);
        step.check_entry_obligations().unwrap();
        assert_eq!(step.parts().allocations.len(), 1);
        assert_eq!(step.parts().allocations[0].range.len(), 4096);
    }
    let selected_image = planned.images().find(|i| i.address() == 0x700000).unwrap();
    let body = selected_image.instruction_boundaries()[0].1;
    assert_eq!(
        selected_image
            .metadata()
            .fields()
            .iter()
            .find(|f| f.role == format!("OriginalBranch {{ original_pc: {pc} }}"))
            .unwrap()
            .target,
        i128::from(pc + 6)
    );
    assert_eq!(
        selected_image
            .program_counter_mappings()
            .iter()
            .find_map(|m| m.translate(body + 4)),
        Some(pc)
    );
    let occupied = target(
        Some(0x2000),
        vec![AddressRange::new(0x700000, 4096).unwrap()],
    );
    assert!(
        engine::plan_with_emission(
            &ArtifactRequest {
                emission: &occupied,
                ..request
            },
            &victim,
            search
        )
        .is_err()
    );
    let short_policy = AllocationPolicy {
        max_mapped_bytes: 4095,
        ..selected.clone()
    };
    assert!(
        engine::plan_with_emission(
            &ArtifactRequest {
                site: PlanningSite {
                    allocation: &short_policy,
                    ..request.site
                },
                ..request
            },
            &victim,
            search
        )
        .is_err()
    );
}
