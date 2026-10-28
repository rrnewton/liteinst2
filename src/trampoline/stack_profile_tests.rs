use super::*;

unsafe extern "C" fn observer(_: *mut HookContext) {}

fn controlled(profile: ObservationStackProfile) -> TrampolinePlan {
    let scan = InstructionScanner::default()
        .scan(&[0x90; 5], 0x4000_0000)
        .unwrap();
    TrampolinePlan::from_controlled_actions_with_stack_profile(
        &scan,
        0x4000_0000,
        0x4000_0005,
        &[ControlledAction {
            logical_pc: 0x4000_0000,
            control: ProbeControl::new(observer, true),
        }],
        profile,
    )
    .unwrap()
}

#[test]
fn explicit_legacy_matches_old_constructor_bytes_layout_maps_and_owners() {
    let scan = InstructionScanner::default()
        .scan(&[0x90; 5], 0x4000_0000)
        .unwrap();
    let actions = [ControlledAction {
        logical_pc: 0x4000_0000,
        control: ProbeControl::new(observer, true),
    }];
    let old =
        TrampolinePlan::from_controlled_actions(&scan, 0x4000_0000, 0x4000_0005, &actions).unwrap();
    let explicit = TrampolinePlan::from_controlled_actions_with_stack_profile(
        &scan,
        0x4000_0000,
        0x4000_0005,
        &actions,
        ObservationStackProfile::Legacy128,
    )
    .unwrap();
    assert_eq!(
        old.observation_stack_profile(),
        ObservationStackProfile::Legacy128
    );
    assert_eq!(
        old.emit_at(0x4100_0000).unwrap(),
        explicit.emit_at(0x4100_0000).unwrap()
    );
    assert_eq!(HOOK_CONTEXT_STACK_PREFIX_BYTES, 304);
    assert_eq!(ObservationStackProfile::Legacy128.reserved_bytes(), 128);
    assert_eq!(
        ObservationStackProfile::Legacy128.context_stack_prefix_bytes(),
        304
    );
    assert_eq!(ObservationStackProfile::Tree144.reserved_bytes(), 144);
    assert_eq!(
        ObservationStackProfile::Tree144.context_stack_prefix_bytes(),
        320
    );
    assert_eq!(core::mem::size_of::<HookContext>(), 176);
}

#[test]
fn nonlegacy_profile_refuses_mixed_modes_before_emission() {
    let plan = controlled(ObservationStackProfile::Tree144);
    assert!(plan.validate_stack_profile(false).is_ok());
    assert!(plan.validate_stack_profile(true).is_err()); // Artifact is not admitted.
    for case in 0..5 {
        let mut bad = plan.clone();
        match case {
            0 => bad.ptrace_stops = true,
            1 => bad.actions[0].2 = true,
            2 => bad.controls.clear(),
            3 => bad.kind = TrampolineKind::PatchWindow,
            4 => bad.actions.push(bad.actions[0]),
            _ => unreachable!(),
        }
        assert!(bad.emit_at(0x4100_0000).is_err());
    }
    // Controls cannot be replaced by an optional role or erased to plain actions.
    let mut bad = plan.clone();
    let (selector, _) = crate::precontext::PreContextSelector::new(false);
    unsafe extern "C" fn preserving(_: *mut HookContext, _: crate::controls::ControlIdentity<'_>) {}
    bad.precontext_actions = vec![crate::precontext::PreContextAction::new(
        0x4000_0000,
        crate::precontext::PreContextRole::Entry,
        &selector,
        preserving,
    )]
    .into_boxed_slice();
    assert!(bad.emit_at(0x4100_0000).is_err());
}

#[test]
fn profile_is_part_of_image_identity_not_a_byte_length_guess() {
    let image = controlled(ObservationStackProfile::Tree144)
        .emit_at(0x4100_0000)
        .unwrap();
    let mut wrong = image.clone();
    wrong.layout.observation_stack_profile = ObservationStackProfile::Legacy128;
    assert_eq!(image.bytes(), wrong.bytes());
    assert_ne!(image, wrong);
    assert_eq!(
        image.layout().observation_stack_profile,
        ObservationStackProfile::Tree144
    );
}
