use super::*;
use crate::emission::{ArtifactRefusalKind, SymbolicHook, TargetProfile};
use crate::scanner::InstructionScanner;

fn target(hook: Option<u64>) -> ArtifactEmission {
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

fn make_plan(bytes: &[u8], observe: bool) -> TrampolinePlan {
    let scan = InstructionScanner::default().scan(bytes, 0x400000).unwrap();
    assert_eq!(scan.instructions().len(), 1);
    if observe && bytes.len() <= 4 {
        TrampolinePlan::from_symbolic_short_instruction(&scan, 0x400000, false).unwrap()
    } else if observe {
        // The short constructor must still reject these unchanged 5/7-byte cases.
        assert!(matches!(
            TrampolinePlan::from_symbolic_short_instruction(&scan, 0x400000, false),
            Err(TrampolineError::Encoding { message })
                if message == "short instruction trampoline requires exactly one 1..=4-byte instruction"
        ));
        TrampolinePlan::from_symbolic_window(
            &scan,
            0x400000,
            0x400000,
            0x400000 + bytes.len() as u64,
            false,
        )
        .unwrap()
    } else {
        TrampolinePlan::from_instruction(&scan, 0x400000).unwrap()
    }
}

#[test]
fn prepared_bound_matches_ordinary_nop_jrcxz_and_hook_artifact_images() {
    let cases: &[(&[u8], usize)] = &[
        (&[0xb8, 42, 0, 0, 0], 20),
        (&[0x75, 0xfe], 20),
        (&[0x83, 0x3d, 0, 1, 0, 0, 7], 20),
        (&[0x0f, 0x1f, 0x44, 0, 0], 10),
        (&[0xe3, 4], 14),
    ];
    for &(bytes, expected_bound) in cases {
        for observe in [false, true] {
            let plan = make_plan(bytes, observe);
            let input = target(observe.then_some(0x401000));
            let prepared = PreparedArtifact::new(&plan, &input).unwrap();
            let bound = prepared.size_bound();
            if !observe {
                assert_eq!(bound, expected_bound);
            }
            let legacy = plan.emit_artifact_at(0x500000, &input).unwrap();
            let actual = prepared.emit_at(0x500000).unwrap();
            assert!(actual.bytes().len() <= bound);
            assert_eq!(actual.bytes(), legacy.bytes());
            assert_eq!(actual.entry_routes(), legacy.entry_routes());
            assert_eq!(
                actual.instruction_boundaries(),
                legacy.instruction_boundaries()
            );
            assert_eq!(actual.artifact_metadata(), legacy.artifact_metadata());
            assert!(!actual.artifact_metadata().unwrap().qualification_complete());
        }
    }
}

#[test]
fn prepared_emission_keeps_field_reach_and_fixed_fragment_refusals() {
    let plan = make_plan(&[0xff, 0xc0], true);
    // Preparation retains an unresolved field; only final binding can refuse it.
    // Neither the prepared nor the ordinary emitter may invent a hook address.
    let unbound_input = target(None);
    let unbound = PreparedArtifact::new(&plan, &unbound_input).unwrap();
    let hook_fields: Vec<_> = unbound
        .preparation
        .fragments
        .iter()
        .flat_map(|(_, fragment)| fragment.fields.iter().map(move |field| (fragment, field)))
        .filter(|(_, field)| field.role == Role::HookCall)
        .collect();
    assert_eq!(hook_fields.len(), 1);
    let (fragment, field) = hook_fields[0];
    assert_eq!(field.target, Target::UnresolvedSymbol(11));
    assert_eq!(
        field.encoding,
        Encoding::PcRelative32 {
            next: field.offset + 4
        }
    );
    assert_eq!(field.expected.as_slice(), &[0; 4]);
    let offset = usize::try_from(field.offset).unwrap();
    assert_eq!(fragment.bytes[offset - 1], 0xe8);
    assert_eq!(&fragment.bytes[offset..offset + 4], &[0; 4]);
    assert!(matches!(
        unbound.emit_at(0x500000),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::TargetBinding, message })
            if message == "UnresolvedSymbol(11)"
    ));
    assert!(matches!(
        plan.emit_artifact_at(0x500000, &unbound_input),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::TargetBinding, message })
            if message == "UnresolvedSymbol(11)"
    ));
    // A real tracer-owned constructor is outside the artifact profile at prepare.
    // This function pointer is retained by the plan; the control never calls it.
    unsafe extern "C" fn uncalled_hook(_: *mut HookContext) {}
    let scan = InstructionScanner::default()
        .scan(&[0xb8, 42, 0, 0, 0], 0x400000)
        .unwrap();
    let unsupported =
        TrampolinePlan::from_scan_replacing_first_with_ptrace_stops(&scan, 0x400000, uncalled_hook)
            .unwrap();
    assert!(matches!(
        PreparedArtifact::new(&unsupported, &target(Some(0x401000))),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact profile does not implement ptrace, controlled or multi-action binding"
    ));
    assert!(matches!(
        unsupported.emit_artifact_at(0x500000, &target(Some(0x401000))),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact profile does not implement ptrace, controlled or multi-action binding"
    ));
    let prepared = PreparedArtifact::new(&plan, &target(Some(0x401000))).unwrap();
    assert!(prepared.emit_at(u64::MAX - 100).is_err());
    let mut prepared = PreparedArtifact::new(&plan, &target(Some(0x401000))).unwrap();
    let field = &mut prepared.preparation.fragments[0].1.fields[0];
    field.expected[0] ^= 1;
    assert!(prepared.emit_at(0x500000).is_err());
    let jrcxz = make_plan(&[0xe3, 4], false);
    let mut prepared = PreparedArtifact::new(&jrcxz, &target(None)).unwrap();
    let index = prepared.preparation.jrcxz_bridges[0].0;
    prepared.preparation.encoded_instructions[index].set_declare_byte_value(0, 0x90);
    assert!(prepared.emit_at(0x500000).is_err());
}

#[test]
fn fitting_encoder_accounting_rejects_hidden_bytes_offsets_and_undersized_bound() {
    let plan = make_plan(&[0x0f, 0x1f, 0x44, 0, 0], false);
    let prepared = PreparedArtifact::new(&plan, &target(None)).unwrap();
    let ir = &prepared.preparation.encoded_instructions;
    let make = || encode_relocated_block_with_metadata(ir, 0x500000, None, true).unwrap();
    let block = make();
    verify_block(ir, &block, 0x500000, prepared.size_bound()).unwrap();
    assert!(verify_block(ir, &block, 0x500000, prepared.size_bound() - 1).is_err());
    let mut padding = make();
    padding.encoded.code_buffer.push(0x90);
    assert!(verify_block(ir, &padding, 0x500000, 4096).is_err());
    let mut lost = make();
    lost.encoded.new_instruction_offsets[0] = u32::MAX;
    assert!(verify_block(ir, &lost, 0x500000, 4096).is_err());
    let mut changed = make();
    changed.encoded.code_buffer[0] ^= 1;
    assert!(verify_block(ir, &changed, 0x500000, 4096).is_err());
    let mut unknown = PreparedArtifact::new(&plan, &target(None)).unwrap();
    unknown
        .preparation
        .encoded_instructions
        .push(Instruction::with(Code::Nopd));
    assert!(prepared_bound(&unknown.preparation).is_err());
}
