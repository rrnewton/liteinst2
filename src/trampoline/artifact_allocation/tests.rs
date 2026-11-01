use super::*;
use crate::emission::{ArtifactRefusalKind, SymbolicHook, TargetProfile};
use crate::scanner::InstructionScanner;

fn input(hook: Option<u64>) -> ArtifactEmission {
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
        vec![],
    )
}

fn make_plan(pc: u64, bytes: &[u8], observe: bool) -> TrampolinePlan {
    let scan = InstructionScanner::default().scan(bytes, pc).unwrap();
    assert_eq!(scan.instructions().len(), 1);
    if observe {
        TrampolinePlan::from_symbolic_short_instruction(&scan, pc, false).unwrap()
    } else {
        TrampolinePlan::from_instruction(&scan, pc).unwrap()
    }
}

fn allocation() -> ArtifactTrampolineAllocation {
    let plan = make_plan(0x400000, &[0xe3, 0xfe], true);
    let prepared = PreparedArtifact::new(&plan, &input(Some(0x401000))).unwrap();
    let placement = EntryVeneerPlacement::new(0x500000, 0x500f45, prepared.size_bound()).unwrap();
    ArtifactTrampolineAllocation::emit(prepared, placement).unwrap()
}

fn invalid_is(result: Result<(), TrampolineError>, expected: &str) {
    assert!(matches!(result,
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::InvalidFieldLedger, message })
            if message == expected
    ));
}

#[test]
fn entry_veneer_preserves_exact_short_body_fields_maps_and_requirements() {
    let cases: &[&[u8]] = &[&[0xff, 0xc0], &[0x75, 0xfe], &[0x0f, 0x1f, 0], &[0xe3, 4]];
    for &bytes in cases {
        for observe in [false, true] {
            let plan = make_plan(0x400000, bytes, observe);
            let input = input(observe.then_some(0x401000));
            let ordinary = plan.emit_artifact_at(0x500000, &input).unwrap();
            let prepared = PreparedArtifact::new(&plan, &input).unwrap();
            let bound = prepared.size_bound();
            let placement = EntryVeneerPlacement::new(0x500000, 0x500f45, bound).unwrap();
            let mut actual = ArtifactTrampolineAllocation::emit(prepared, placement).unwrap();
            assert_eq!(actual.body, ordinary);
            assert_eq!(&actual.bytes()[..ordinary.bytes().len()], ordinary.bytes());
            assert_eq!(actual.body_layout(), ordinary.layout());
            assert_eq!(actual.body_layout().total_len(), Some(actual.body_len()));
            assert!(actual.body_len() <= bound);
            assert_eq!(actual.bytes().len(), placement.storage_len());
            assert!(actual.bytes().len() > actual.body_len());
            assert_eq!(actual.entry_routes(), ordinary.entry_routes());
            assert_eq!(
                actual.instruction_boundaries(),
                ordinary.instruction_boundaries()
            );
            let old = ordinary.artifact_metadata().unwrap();
            assert_eq!(
                &actual.artifact_metadata().fields()[..old.fields().len()],
                old.fields()
            );
            assert_eq!(
                actual.artifact_metadata().requirements(),
                old.requirements()
            );
            assert!(!actual.artifact_metadata().qualification_complete());
            assert_eq!(actual.entry_transfer(), (0x500f45, 0x500000));
            assert_eq!(
                &actual.program_counter_mappings()[..ordinary.program_counter_mappings().len()],
                ordinary.program_counter_mappings()
            );
            let veneer_pc = actual.program_counter_mappings().last().unwrap();
            assert_eq!(veneer_pc.generated_start(), actual.entry_address());
            assert_eq!(veneer_pc.generated_end(), actual.entry_address() + 5);
            assert_eq!(veneer_pc.logical_address(), 0x400000);
            for pc in actual.storage_address() + actual.body_len() as u64..actual.entry_address() {
                assert!(
                    actual
                        .program_counter_mappings()
                        .iter()
                        .all(|map| map.translate(pc).is_none())
                );
            }
            assert!(
                actual
                    .instruction_boundaries()
                    .iter()
                    .all(|(_, pc)| *pc != actual.entry_address())
            );
            assert!(
                actual
                    .entry_routes()
                    .iter()
                    .all(|(_, pc)| *pc != actual.entry_address())
            );
            actual.require_artifact_router();
            actual.require_artifact_router();
            assert_eq!(
                actual
                    .artifact_metadata()
                    .requirements()
                    .iter()
                    .filter(|r| **r == ArtifactRequirement::EntryRouterBootstrap)
                    .count(),
                1
            );
            for old_requirement in old.requirements() {
                assert!(
                    actual
                        .artifact_metadata()
                        .requirements()
                        .contains(old_requirement)
                );
            }
            actual.validate().unwrap();
        }
    }
}

#[test]
fn entry_veneer_fixed_suffix_puzzle_uses_one_complete_owned_envelope() {
    let selected_pc = 57_842;
    let base = 55_140_352;
    for (victim, entry) in [(57_847, 55_144_261), (57_895, 55_144_309)] {
        let plan = make_plan(selected_pc, &[0x7e, 0x5c], true);
        let input = input(Some(0x401000));
        let prepared = PreparedArtifact::new(&plan, &input).unwrap();
        let bound = prepared.size_bound();
        let policy = crate::quiescent::AllocationPolicy {
            ranges: vec![AddressRange::new(base, 4096).unwrap()],
            preferred_address: Some(entry),
            max_candidates: 1,
            max_mappings: 1,
            max_mapped_bytes: 4096,
        };
        let source = AddressRange::new(57_000, 2000).unwrap();
        let window = AddressRange::new(entry, 1).unwrap();
        let victim_mapping = AddressRange::new(1_302_528, 4096).unwrap();
        assert!(matches!(
            crate::emission::placement::fitting_for_pun(
                &policy,
                window,
                &[victim_mapping],
                source,
                bound
            ),
            Err(Refusal::AllocationUnavailable)
        ));
        let placement = crate::emission::placement::entry_veneer_for_pun(
            &policy,
            window,
            &[victim_mapping],
            source,
            bound,
        )
        .unwrap();
        assert_eq!(placement.storage_address(), base);
        let actual = ArtifactTrampolineAllocation::emit(prepared, placement).unwrap();
        assert_eq!(actual.placement().mapping(), policy.ranges[0]);
        assert!(actual.body_len() <= bound && bound <= placement.entry_offset());
        assert_eq!(actual.bytes().len(), placement.entry_offset() + 5);
        assert!(
            actual.bytes()[actual.body_len()..placement.entry_offset()]
                .iter()
                .all(|&byte| byte == 0xcc)
        );
        // Exact fixed-suffix source E9 algebra, without fabricating a pair plan
        // or claiming that source ownership/pending admission has passed.
        let displacement = i32::try_from(i128::from(entry) - i128::from(victim + 10)).unwrap();
        assert_eq!(displacement.to_le_bytes(), [0x44, 0x8d, 0x48, 0x03]);
        let mut source_relay = vec![0xe9];
        source_relay.extend_from_slice(&displacement.to_le_bytes());
        let relay = Decoder::with_ip(64, &source_relay, victim + 5, DecoderOptions::NONE).decode();
        assert_eq!(relay.code(), Code::Jmp_rel32_64);
        assert_eq!(relay.near_branch_target(), actual.entry_address());
        let veneer = Decoder::with_ip(
            64,
            &actual.bytes()[placement.entry_offset()..],
            entry,
            DecoderOptions::NONE,
        )
        .decode();
        assert_eq!(veneer.code(), Code::Jmp_rel32_64);
        assert_eq!(veneer.len(), 5);
        assert_eq!(veneer.near_branch_target(), base);
        // The single existing allocation owns padding too, not just RX code.
        let owned = AddressRange::new(actual.storage_address(), actual.bytes().len()).unwrap();
        assert!(placement.mapping().covers(owned));
        assert!(!placement.mapping().overlaps(victim_mapping));
        assert!(!placement.mapping().overlaps(source));
        let body_return = actual
            .artifact_metadata()
            .fields()
            .iter()
            .find(|field| field.role == "Return")
            .unwrap();
        assert_eq!(body_return.target, i128::from(selected_pc + 2));
        actual.validate().unwrap();
    }
}

#[test]
fn entry_veneer_rejects_partition_field_pc_and_requirement_mutations() {
    let original = allocation();
    for index in [0, original.body_len(), original.placement().entry_offset()] {
        let mut changed = original.clone();
        changed.bytes[index] ^= 1;
        invalid_is(
            changed.validate(),
            "veneer body/gap/instruction partition changed",
        );
    }
    let mut changed = original.clone();
    let last = changed.bytes.len() - 1;
    changed.bytes[last] ^= 1;
    invalid_is(
        changed.validate(),
        "artifact field bytes do not encode their exact target",
    );
    for mutation in 0..7 {
        let mut changed = original.clone();
        let field = changed.metadata.fields.last_mut().unwrap();
        match mutation {
            0 => field.offset -= 1,
            1 => field.origin -= 1,
            2 => field.target += 1,
            3 => field.bias_domain += 1,
            4 => field.width = 1,
            5 => field.role = "Return".into(),
            _ => field.encoding = ArtifactFieldEncoding::Delta,
        }
        invalid_is(
            changed.validate(),
            "veneer field inventory or outstanding requirements changed",
        );
    }
    let mut changed = original.clone();
    changed.metadata.requirements.pop();
    invalid_is(
        changed.validate(),
        "veneer field inventory or outstanding requirements changed",
    );
    let mut changed = original.clone();
    changed
        .metadata
        .fields
        .push(changed.metadata.fields[0].clone());
    invalid_is(
        changed.validate(),
        "veneer field inventory or outstanding requirements changed",
    );
    for mutation in 0..3 {
        let mut changed = original.clone();
        let pc = changed.program_counters.last_mut().unwrap();
        match mutation {
            0 => pc.generated_start -= 1,
            1 => pc.generated_end += 1,
            _ => pc.logical_address += 1,
        }
        invalid_is(
            changed.validate(),
            "veneer PC inventory changed or grants padding authority",
        );
    }
    let mut changed = original.clone();
    changed.body.entry_routes[0].1 = changed.entry_address();
    invalid_is(
        changed.validate(),
        "veneer body route or restored boundary is not original",
    );
    // Preserve numeric byte arithmetic while redirecting a body branch into the
    // formerly absent gap: this reaches the new local-target exclusion itself.
    for destination in [
        original.storage_address() + original.body_len() as u64,
        original.entry_address(),
        original.entry_address() + 1,
    ] {
        let mut changed_body = original.body.clone();
        let field = changed_body
            .artifact
            .as_mut()
            .unwrap()
            .fields
            .iter_mut()
            .find(|field| field.role.starts_with("OriginalBranch {"))
            .unwrap();
        assert_eq!(
            (field.encoding, field.width),
            (ArtifactFieldEncoding::Relative, 4)
        );
        field.target = i128::from(destination);
        let delta =
            i32::try_from(field.target - i128::from(changed_body.address + field.origin)).unwrap();
        let offset = field.offset as usize;
        changed_body.bytes[offset..offset + 4].copy_from_slice(&delta.to_le_bytes());
        invalid_is(
            ArtifactTrampolineAllocation::from_body(changed_body, original.placement).map(|_| ()),
            "body field points into the new padding or veneer",
        );
    }
}

#[test]
fn entry_veneer_retains_exact_body_and_binding_refusals() {
    let plan = make_plan(0x400000, &[0xff, 0xc0], true);
    let prepared = PreparedArtifact::new(&plan, &input(Some(0x401000))).unwrap();
    let mismatched =
        EntryVeneerPlacement::new(0x500000, 0x500f45, prepared.size_bound() - 1).unwrap();
    invalid_is(
        ArtifactTrampolineAllocation::emit(prepared, mismatched).map(|_| ()),
        "veneer certificate does not bind the prepared body",
    );
    let prepared = PreparedArtifact::new(&plan, &input(None)).unwrap();
    let placement = EntryVeneerPlacement::new(0x500000, 0x500f45, prepared.size_bound()).unwrap();
    assert!(
        matches!(ArtifactTrampolineAllocation::emit(prepared, placement),
            Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::TargetBinding, message }) if message == "UnresolvedSymbol(11)"
        )
    );
    let far = input(Some(0x1_0000_0000));
    let prepared = PreparedArtifact::new(&plan, &far).unwrap();
    let placement = EntryVeneerPlacement::new(0x500000, 0x500f45, prepared.size_bound()).unwrap();
    assert!(matches!(
        ArtifactTrampolineAllocation::emit(prepared, placement),
        Err(TrampolineError::Artifact {
            reason: ArtifactRefusalKind::OutOfRange,
            ..
        })
    ));
    let long = make_plan(0x400000, &[0xb8, 42, 0, 0, 0], false);
    let prepared = PreparedArtifact::new(&long, &input(None)).unwrap();
    let placement = EntryVeneerPlacement::new(0x500000, 0x500f45, prepared.size_bound()).unwrap();
    invalid_is(
        ArtifactTrampolineAllocation::emit(prepared, placement).map(|_| ()),
        "veneer is restricted to one original 2..=4-byte selected instruction",
    );
    let original = allocation();
    let too_small =
        EntryVeneerPlacement::new(original.storage_address(), original.entry_address(), 1).unwrap();
    invalid_is(
        ArtifactTrampolineAllocation::from_body(original.body.clone(), too_small).map(|_| ()),
        "veneer body/certificate/owner geometry mismatch",
    );
    let mut extra_head = original.body.clone();
    extra_head.entry_routes.push((0x400002, 0x500001));
    invalid_is(
        ArtifactTrampolineAllocation::from_body(extra_head, original.placement).map(|_| ()),
        "veneer requires exactly one selected original head",
    );
    let mut extra_boundary = original.body.clone();
    extra_boundary
        .instruction_boundaries
        .push((0x400002, 0x500001));
    invalid_is(
        ArtifactTrampolineAllocation::from_body(extra_boundary, original.placement).map(|_| ()),
        "veneer requires exactly one unchanged restored boundary",
    );
    let mut wrong_domain = original.body.clone();
    wrong_domain.artifact.as_mut().unwrap().fields[0].bias_domain += 1;
    invalid_is(
        ArtifactTrampolineAllocation::from_body(wrong_domain, original.placement).map(|_| ()),
        "artifact field domain/extent/origin/overlap mismatch",
    );
}

#[test]
fn entry_veneer_new_field_keeps_linker_identity_bias_template_and_overlap_guards() {
    let placement = EntryVeneerPlacement::new(0x500000, 0x500f45, 100).unwrap();
    let mut template = vec![0xcc; placement.storage_len()];
    template[placement.entry_offset()..].copy_from_slice(&[0xe9, 0, 0, 0, 0]);
    let current = ImagePlacement {
        image: ImageId(placement.storage_address()),
        address: RelativeAddress {
            domain: BiasDomain(7),
            offset: i128::from(placement.storage_address()),
        },
        len: template.len() as u64,
    };
    let field = veneer_fixup(placement, 0x400000);
    let linked = fixups::link_bias_invariant(
        current.image,
        &template,
        std::slice::from_ref(&field),
        &[current],
    )
    .unwrap();
    let field_bytes = &linked[placement.entry_offset() + 1..];
    assert_eq!(
        field_bytes,
        &(-(placement.storage_len() as i32)).to_le_bytes()
    );
    let mut bad = field.clone();
    bad.target = Target::Image {
        image: ImageId(0x600000),
        offset: 0,
    };
    assert!(matches!(
        fixups::link_bias_invariant(current.image, &template, &[bad], &[current]),
        Err(fixups::Error::UnknownImage(ImageId(0x600000)))
    ));
    let mut bad = field.clone();
    bad.target = Target::Address(RelativeAddress {
        domain: BiasDomain(8),
        offset: i128::from(placement.storage_address()),
    });
    assert!(matches!(
        fixups::link_bias_invariant(current.image, &template, &[bad], &[current]),
        Err(fixups::Error::CrossBiasDomain { .. })
    ));
    let mut bad = field.clone();
    bad.expected[0] = 1;
    assert!(matches!(
        fixups::link_bias_invariant(current.image, &template, &[bad], &[current]),
        Err(fixups::Error::TemplateMismatch { .. })
    ));
    assert!(matches!(
        fixups::link_bias_invariant(
            current.image,
            &template,
            &[field.clone(), field],
            &[current]
        ),
        Err(fixups::Error::OverlappingFields { .. })
    ));
    // A different common bias cancels exactly; it is not runtime qualification.
    for bias in [0_i128, 0x1234_5000, -0x10000] {
        let biased = ImagePlacement {
            address: RelativeAddress {
                offset: current.address.offset + bias,
                ..current.address
            },
            ..current
        };
        let bytes = fixups::link_bias_invariant(
            current.image,
            &template,
            &[veneer_fixup(placement, 0x400000)],
            &[biased],
        )
        .unwrap();
        assert_eq!(bytes, linked);
    }
}

#[test]
fn entry_veneer_accepts_exact_body_boundary_and_full_page_end() {
    let plan = make_plan(0x400000, &[0xe3, 4], false);
    for offset in [14, 4091] {
        let prepared = PreparedArtifact::new(&plan, &input(None)).unwrap();
        assert_eq!(prepared.size_bound(), 14);
        let placement =
            EntryVeneerPlacement::new(0x500000, 0x500000 + offset, prepared.size_bound()).unwrap();
        let actual = ArtifactTrampolineAllocation::emit(prepared, placement).unwrap();
        assert_eq!(actual.body_len(), 14);
        assert_eq!(actual.bytes().len(), offset as usize + 5);
        assert_eq!(actual.body_layout().total_len(), Some(14));
        assert!(
            actual.bytes()[14..offset as usize]
                .iter()
                .all(|&byte| byte == 0xcc)
        );
        let field = actual.artifact_metadata().fields().last().unwrap();
        assert_eq!(field.offset, offset + 1);
        assert_eq!(field.origin, offset + 5);
        assert_eq!(field.target, 0x500000);
        actual.validate().unwrap();
    }
}
