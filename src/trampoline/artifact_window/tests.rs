use super::*;
use crate::contracts::{CodeIdentity, SourceIdentity};
use crate::emission::{ArtifactRefusalKind, FixedImageBinding, SymbolicHook, TargetProfile};

const SOURCE: u64 = 0x400000;
const IMAGE: u64 = 0x500000;
const HOOK: u64 = 0x401000;

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

fn scan(bytes: &[u8]) -> ScanResult {
    InstructionScanner::default().scan(bytes, SOURCE).unwrap()
}

fn window(bytes: &[u8], pcs: &[u64]) -> ArtifactObservationWindow {
    ArtifactObservationWindow::checked(&scan(bytes), SOURCE, SOURCE + bytes.len() as u64, pcs)
        .unwrap()
}

#[test]
fn single_observation_keeps_ordinary_symbolic_bytes_maps_and_requirements() {
    let bytes = [0x90, 0x48, 0x83, 0xc0, 1, 0x90];
    let scan = scan(&bytes);
    for pc in [SOURCE, SOURCE + 1, SOURCE + 5] {
        let old = TrampolinePlan::from_symbolic_window(
            &scan,
            SOURCE,
            pc,
            SOURCE + bytes.len() as u64,
            false,
        )
        .unwrap()
        .emit_artifact_at(IMAGE, &target(Some(HOOK)))
        .unwrap();
        let new =
            ArtifactObservationWindow::checked(&scan, SOURCE, SOURCE + bytes.len() as u64, &[pc])
                .unwrap()
                .emit_at(IMAGE, &target(Some(HOOK)))
                .unwrap();
        assert_eq!(new.observation_pcs(), &[pc]);
        // Whole image equality includes bytes, first-helper layout, mappings,
        // bindings and unresolved requirements; the public result stays opaque.
        assert_eq!(new.image, old);
        assert!(!new.image().metadata().qualification_complete());
    }
}

#[test]
fn stack_window_preserves_every_head_and_exact_callback_pc_fields() {
    // PUSH RSP; NOP; POP RSP; XOR EAX,EAX; PUSH R8; POP R8.
    // This is an emission control, not proof of scratch after a runtime RSP pivot.
    let bytes = [0x54, 0x90, 0x5c, 0x31, 0xc0, 0x41, 0x50, 0x41, 0x58];
    let pcs = [SOURCE, SOURCE + 2, SOURCE + 5, SOURCE + 7];
    let window = window(&bytes, &pcs);
    let input = target(Some(HOOK));
    let prepared = fitting::PreparedArtifact::for_observation_window(&window, &input).unwrap();
    let bound = prepared.size_bound();
    let prepared_image = prepared.emit_at(IMAGE).unwrap();
    let output = window.emit_at(IMAGE, &input).unwrap();
    assert_eq!(output.image, prepared_image);
    assert!(output.image().bytes().len() <= bound);
    assert_eq!(output.observation_pcs(), &pcs);
    let view = output.image();
    let heads = [
        SOURCE,
        SOURCE + 1,
        SOURCE + 2,
        SOURCE + 3,
        SOURCE + 5,
        SOURCE + 7,
    ];
    assert_eq!(
        view.entry_routes().iter().map(|r| r.0).collect::<Vec<_>>(),
        heads
    );
    assert_eq!(
        view.instruction_boundaries()
            .iter()
            .map(|r| r.0)
            .collect::<Vec<_>>(),
        heads
    );
    let originals = scan(&bytes);
    for ((&(pc, entry), &(body_pc, body)), original) in view
        .entry_routes()
        .iter()
        .zip(view.instruction_boundaries())
        .zip(originals.instructions())
    {
        assert_eq!(pc, body_pc);
        if pcs.contains(&pc) {
            assert!(entry < body);
        } else {
            assert_eq!(entry, body);
        }
        let decoded = Decoder::with_ip(
            64,
            &view.bytes()[(body - IMAGE) as usize..],
            body,
            DecoderOptions::NONE,
        )
        .decode();
        assert_eq!(decoded.code(), original.instruction().code());
        assert_eq!(
            decoded.op0_register(),
            original.instruction().op0_register()
        );
    }
    let fields = view.metadata().fields();
    let logical: Vec<_> = fields.iter().filter(|f| f.role == "LogicalPc").collect();
    let calls: Vec<_> = fields.iter().filter(|f| f.role == "HookCall").collect();
    assert_eq!(
        logical.iter().map(|f| f.target).collect::<Vec<_>>(),
        pcs.map(i128::from)
    );
    assert_eq!(calls.len(), pcs.len());
    for ((pc, logical), call) in pcs.iter().zip(logical).zip(calls) {
        let entry = view.entry_routes().iter().find(|r| r.0 == *pc).unwrap().1;
        let body = view
            .instruction_boundaries()
            .iter()
            .find(|r| r.0 == *pc)
            .unwrap()
            .1;
        assert_eq!(logical.bias_domain, 7);
        assert_eq!(call.target, i128::from(HOOK));
        assert!(entry <= IMAGE + logical.offset && logical.offset < call.offset);
        assert!(IMAGE + call.offset + call.width as u64 <= body);
    }
    assert_eq!(
        view.metadata()
            .requirements()
            .iter()
            .filter(|r| **r == ArtifactRequirement::HookAbiAndReadiness(11))
            .count(),
        1
    );
}

#[test]
fn internal_branch_targets_selected_entry_not_restored_body() {
    // JNE to PUSH at +3, skipping one unselected NOP; two selected stack heads.
    let bytes = [0x75, 1, 0x90, 0x50, 0x58, 0x90];
    let output = window(&bytes, &[SOURCE + 3, SOURCE + 4])
        .emit_at(IMAGE, &target(Some(HOOK)))
        .unwrap();
    let view = output.image();
    let entry = view
        .entry_routes()
        .iter()
        .find(|r| r.0 == SOURCE + 3)
        .unwrap()
        .1;
    let body = view
        .instruction_boundaries()
        .iter()
        .find(|r| r.0 == SOURCE + 3)
        .unwrap()
        .1;
    let branch_pc = view.instruction_boundaries()[0].1;
    let branch = Decoder::with_ip(
        64,
        &view.bytes()[(branch_pc - IMAGE) as usize..],
        branch_pc,
        DecoderOptions::NONE,
    )
    .decode();
    assert_eq!(branch.mnemonic(), Mnemonic::Jne);
    assert_eq!(branch.near_branch_target(), entry);
    assert!(entry < body);
    assert_eq!(view.entry_routes()[0].1, branch_pc);
    assert_eq!(
        view.metadata()
            .fields()
            .iter()
            .filter(|f| f.role == "LogicalPc")
            .map(|f| f.target)
            .collect::<Vec<_>>(),
        [i128::from(SOURCE + 3), i128::from(SOURCE + 4)]
    );
}

#[test]
fn population_validation_preserves_existing_window_error_precedence() {
    let scan = scan(&[0x50, 0x48, 0x89, 0xd8, 0x58, 0x90]);
    assert!(
        matches!(ArtifactObservationWindow::checked(&scan, SOURCE, SOURCE + 6, &[]),
        Err(TrampolineError::Artifact { message, .. }) if message == "artifact observation window has no actions")
    );
    for pcs in [&[SOURCE, SOURCE][..], &[SOURCE + 4, SOURCE][..]] {
        assert!(
            matches!(ArtifactObservationWindow::checked(&scan, SOURCE, SOURCE + 6, pcs),
            Err(TrampolineError::Artifact { message, .. }) if message == "artifact observation heads must be ordered and distinct")
        );
    }
    for invalid in [SOURCE + 2, SOURCE + 6, SOURCE + 7] {
        assert!(
            matches!(ArtifactObservationWindow::checked(&scan, SOURCE, SOURCE + 6, &[SOURCE, invalid]),
            Err(TrampolineError::SiteNotFound { address }) if address == invalid)
        );
    }
    // End inside MOV wins over the duplicate population, exactly as the old
    // window constructor's boundary check precedes the new population stage.
    assert!(
        matches!(ArtifactObservationWindow::checked(&scan, SOURCE, SOURCE + 3, &[SOURCE, SOURCE]),
        Err(TrampolineError::Encoding { message }) if message == "displaced window ends inside an instruction")
    );
    assert!(
        matches!(ArtifactObservationWindow::checked(&scan, SOURCE + 2, SOURCE + 6, &[SOURCE + 4]),
        Err(TrampolineError::SiteNotFound { address }) if address == SOURCE + 2)
    );
    assert!(matches!(
        ArtifactObservationWindow::checked(&scan, SOURCE, SOURCE + 4, &[SOURCE]),
        Err(TrampolineError::InstructionTooShort {
            instruction_len: 4,
            ..
        })
    ));
}

#[test]
fn complete_action_accounting_rejects_missing_duplicated_and_wrong_fields() {
    let window = window(&[0x50, 0x90, 0x58, 0x90, 0x90], &[SOURCE, SOURCE + 2]);
    let input = target(None);
    let mut preparation = window.prepare(&input).unwrap();
    window.verify_preparation(&input, 2, &preparation).unwrap();
    assert!(matches!(window.verify_preparation(&input, 1, &preparation),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact window lost an observation"));
    let removed = preparation.fragments.pop().unwrap();
    assert!(matches!(window.verify_preparation(&input, 2, &preparation),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact window lost an observation"));
    preparation.fragments.push(removed);
    let fields = &mut preparation.fragments[1].1.fields;
    let original = fields.clone();
    fields.push(fields[0].clone());
    assert!(matches!(window.verify_preparation(&input, 2, &preparation),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact window observation fields differ"));
    preparation.fragments[1].1.fields = original;
    let field = preparation.fragments[1]
        .1
        .fields
        .iter_mut()
        .find(|f| f.role == Role::LogicalPc)
        .unwrap();
    field.target = artifact_target(&input, SOURCE);
    assert!(matches!(window.verify_preparation(&input, 2, &preparation),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact window observation fields differ"));
}

#[test]
fn artifact_linking_keeps_original_field_error_before_missing_hook_and_fixed_obligation() {
    // JMP [RAX*8 + 0x400000] is intentionally not common-bias PIC.
    let bytes = [0xff, 0x24, 0xc5, 0, 0, 0x40, 0];
    let window = window(&bytes, &[SOURCE]);
    let unresolved = target(None);
    assert!(matches!(
        window.emit_at(IMAGE, &unresolved),
        Err(TrampolineError::Artifact {
            reason: ArtifactRefusalKind::RuntimeAbsoluteFixup,
            ..
        })
    ));
    let identity = CodeIdentity {
        source: SourceIdentity([0x24; 32]),
        mapping: 7,
        generation: 1,
    };
    let binding = FixedImageBinding::zero_bias(identity, 7).unwrap();
    let input = target(Some(HOOK)).with_fixed_image(binding).unwrap();
    let output = window.emit_at(IMAGE, &input).unwrap();
    let view = output.image();
    assert_eq!(view.metadata().fixed_image(), Some(binding));
    assert!(!view.metadata().qualification_complete());
    let field = view
        .metadata()
        .fields()
        .iter()
        .find(|f| f.fixed_source.is_some())
        .unwrap();
    let source = field.fixed_source.as_ref().unwrap();
    assert_eq!(source.instruction.start(), SOURCE);
    assert_eq!(source.instruction.len(), 7);
    assert_eq!(source.displacement.start(), SOURCE + 3);
    assert_eq!(source.displacement.len(), 4);
    view.metadata()
        .validate_fixed_image(identity, 7, 0, IMAGE, view.bytes())
        .unwrap();
    assert!(
        view.metadata()
            .validate_fixed_image(identity, 7, 1, IMAGE, view.bytes())
            .is_err()
    );
    let mut other = identity;
    other.generation += 1;
    assert!(
        view.metadata()
            .validate_fixed_image(other, 7, 0, IMAGE, view.bytes())
            .is_err()
    );
    // Even after field provenance is admitted, no hook address is fabricated.
    assert!(
        matches!(window.emit_at(IMAGE, &unresolved.with_fixed_image(binding).unwrap()),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::TargetBinding, message }) if message == "UnresolvedSymbol(11)")
    );
}

#[test]
fn final_link_and_size_refusals_leave_old_live_actions_unsupported() {
    let bytes = [0x50, 0x90, 0x58, 0x90, 0x90];
    let scan = scan(&bytes);
    let window = window(&bytes, &[SOURCE, SOURCE + 2]);
    assert!(matches!(
        window.emit_at(IMAGE, &target(None)),
        Err(TrampolineError::Artifact {
            reason: ArtifactRefusalKind::TargetBinding,
            ..
        })
    ));
    assert!(matches!(
        window.emit_at(IMAGE, &target(Some(u64::MAX))),
        Err(TrampolineError::Artifact {
            reason: ArtifactRefusalKind::OutOfRange,
            ..
        })
    ));
    let input = target(Some(HOOK));
    let prepared = window.prepare(&input).unwrap();
    assert!(
        matches!(window.base.emit_prepared_ordered_at(IMAGE, Some(&input), None, prepared, Some(1)),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "fitting artifact encoded bytes exceed certificate")
    );
    // Existing genuine live action construction is still outside artifact
    // emission; a function pointer never becomes a symbolic target implicitly.
    unsafe extern "C" fn unused_hook(_: *mut HookContext) {}
    let live = TrampolinePlan::from_actions(
        &scan,
        SOURCE,
        SOURCE + 5,
        &[
            (SOURCE, unused_hook as HookCallback, false),
            (SOURCE + 2, unused_hook, false),
        ],
    )
    .unwrap();
    assert!(matches!(live.emit_artifact_at(IMAGE, &input),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact profile does not implement ptrace, controlled or multi-action binding"));
    assert!(matches!(fitting::PreparedArtifact::new(&live, &input),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact profile does not implement ptrace, controlled or multi-action binding"));
    assert!(
        matches!(live.prepare_ordered_input(Some(&input), false, false, Some(&window)),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact window requires its sealed symbolic plan")
    );
    assert!(
        matches!(window.base.prepare_ordered_input(Some(&input), true, false, Some(&window)),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact window requires its sealed symbolic plan")
    );
    assert!(
        matches!(window.base.prepare_ordered_input(None, false, false, Some(&window)),
        Err(TrampolineError::Artifact { reason: ArtifactRefusalKind::UnmodelledEncoding, message })
            if message == "artifact window requires its sealed symbolic plan")
    );
}
