//! Final-byte and ownership controls. No emitted code or callback executes.
use super::*;
use crate::controls::PointObservationAction::{AfterCapture, EarlyIfEnabled};

const SOURCE: u64 = 0x0100_0000;
const IMAGE: u64 = 0x0200_0000;
unsafe extern "C" fn observe(_: *mut HookContext) {}

struct Program {
    action: ControlledAction,
    ir: Vec<Instruction>,
    spec: GateSpec,
    encoded: BlockEncoderResult,
    boundaries: (usize, usize, usize),
}
impl Program {
    fn verify(&self) -> Result<crate::controls::EarlyControlGateLayout, TrampolineError> {
        verify(
            &self.spec,
            &self.ir,
            IMAGE,
            &self.encoded,
            &self.action,
            self.boundaries,
        )
    }
    fn offset(&self, ordinal: usize) -> usize {
        self.encoded.new_instruction_offsets[self.spec.indices[ordinal]] as usize
    }
}
fn marker(label: u64) -> Instruction {
    let mut instruction = Instruction::with(Code::Zero_bytes);
    instruction.set_ip(label);
    instruction
}
fn program(padding: usize) -> Program {
    let action = ControlledAction {
        logical_pc: SOURCE,
        control: ProbeControl::new(observe, false),
    };
    let mut next = 10_u64;
    let mut identity = || {
        next += 1;
        Ok(next)
    };
    let mut ir = vec![marker(1)];
    let spec = append(&mut ir, &action.control, 2, 3, &mut identity).unwrap();
    let observer = ir.len();
    ir.push(marker(2));
    for _ in 0..=padding {
        let mut instruction = Instruction::with(Code::Nopd);
        instruction.set_ip(identity().unwrap());
        ir.push(instruction);
    }
    let body = ir.len();
    ir.push(marker(3));
    let mut instruction = Instruction::with(Code::Retnq);
    instruction.set_ip(identity().unwrap());
    ir.push(instruction);
    let encoded = BlockEncoder::encode(
        64,
        InstructionBlock::new(&ir, IMAGE),
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
            | BlockEncoderOptions::RETURN_RELOC_INFOS,
    )
    .unwrap();
    let result = Program {
        action,
        ir,
        spec,
        encoded,
        boundaries: (0, observer, body),
    };
    result.verify().unwrap();
    assert!(result.encoded.reloc_infos.is_empty());
    result
}

#[test]
fn encoded_paths_restore_rcx_rsp_and_leave_the_red_zone_untouched() {
    const RSP: u64 = 0x0500_0000;
    for padding in [0, 512] {
        let program = program(padding);
        let layout = program.verify().unwrap();
        for original_rcx in [0_u64, 0xfeed_7654_dead_ffff] {
            for enabled in [0_u8, 1] {
                let mut stack = [0xa5_u8; 256];
                let mut simulated_rcx = original_rcx;
                let mut simulated_rsp = RSP;
                let mut pc = layout.entry;
                let mut finished = false;
                // Independent semantics of the final decoded eleven-instruction
                // stencil; this is not a native or extended-state oracle.
                for _ in 0..GATE_INSTRUCTIONS {
                    if pc == layout.observing_entry || pc == layout.original_body {
                        assert_eq!(
                            pc,
                            if enabled == 0 {
                                layout.original_body
                            } else {
                                layout.observing_entry
                            }
                        );
                        finished = true;
                        break;
                    }
                    let instruction = Decoder::with_ip(
                        64,
                        &program.encoded.code_buffer[(pc - IMAGE) as usize..],
                        pc,
                        DecoderOptions::NONE,
                    )
                    .decode();
                    assert_eq!(instruction.rflags_modified(), 0);
                    let mut next = instruction.next_ip();
                    match instruction.code() {
                        Code::Lea_r64_m => {
                            assert_eq!(instruction.op0_register(), Register::RSP);
                            assert_eq!(instruction.memory_base(), Register::RSP);
                            simulated_rsp =
                                simulated_rsp.wrapping_add(instruction.memory_displacement64());
                        }
                        Code::Push_r64 => {
                            assert_eq!(instruction.op0_register(), Register::RCX);
                            simulated_rsp -= 8;
                            assert_eq!(simulated_rsp, RSP - 136);
                            stack[120..128].copy_from_slice(&simulated_rcx.to_le_bytes());
                        }
                        Code::Pop_r64 => {
                            assert_eq!(instruction.op0_register(), Register::RCX);
                            assert_eq!(simulated_rsp, RSP - 136);
                            simulated_rcx = u64::from_le_bytes(stack[120..128].try_into().unwrap());
                            simulated_rsp += 8;
                        }
                        Code::Mov_r64_imm64 => simulated_rcx = instruction.immediate64(),
                        Code::Movzx_r32_rm8 => {
                            assert_eq!(instruction.op0_register(), Register::ECX);
                            assert_eq!(instruction.memory_base(), Register::RCX);
                            assert_eq!(
                                simulated_rcx,
                                program.action.control.enabled_load().address()
                            );
                            simulated_rcx = u64::from(enabled);
                        }
                        Code::Jrcxz_rel8_64 if simulated_rcx == 0 => {
                            next = instruction.near_branch_target()
                        }
                        Code::Jrcxz_rel8_64 => {}
                        Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => {
                            next = instruction.near_branch_target()
                        }
                        _ => panic!("unexpected final gate instruction {instruction:?}"),
                    }
                    pc = next;
                }
                assert!(finished);
                assert_eq!((simulated_rsp, simulated_rcx), (RSP, original_rcx));
                assert!(stack[..120].iter().all(|byte| *byte == 0xa5));
                assert!(stack[128..].iter().all(|byte| *byte == 0xa5));
            }
        }
    }
}

#[test]
fn final_byte_changes_to_load_restore_and_both_branches_refuse() {
    // One changed byte per independently valid starting image.
    for (ordinal, byte) in [
        (0, 4),
        (2, 2),
        (3, 1),
        (4, 1),
        (5, 0),
        (6, 4),
        (7, 1),
        (8, 0),
        (10, 1),
    ] {
        let mut program = program(512);
        let offset = program.offset(ordinal) + byte;
        program.encoded.code_buffer[offset] ^= 1;
        assert!(
            program.verify().is_err(),
            "accepted corrupt instruction {ordinal}, byte {byte}"
        );
    }
}

#[test]
fn owner_label_and_instruction_offset_corruption_refuse() {
    let mut wrong_owner = program(512);
    wrong_owner.action.control = ProbeControl::new(observe, false);
    assert!(wrong_owner.verify().is_err());
    let mut missing = program(512);
    missing.encoded.new_instruction_offsets[missing.spec.indices[4]] = u32::MAX;
    assert!(missing.verify().is_err());
    let mut repeated = program(512);
    repeated.spec.indices[8] = repeated.spec.indices[5];
    assert!(repeated.verify().is_err());
    let mut wrong_body = program(512);
    wrong_body.boundaries.2 = wrong_body.boundaries.1;
    assert!(wrong_body.verify().is_err());
    let mut missing_label = program(512);
    missing_label.ir[missing_label.boundaries.1] = marker(99);
    assert!(missing_label.verify().is_err());
}

fn actions() -> Vec<ControlledAction> {
    [0, 3, 6]
        .into_iter()
        .map(|offset| ControlledAction {
            logical_pc: SOURCE + offset,
            control: ProbeControl::new(observe, false),
        })
        .collect()
}
fn scan() -> ScanResult {
    InstructionScanner::default()
        .scan(&[0x48, 0x89, 0xc8, 0x48, 0x01, 0xd8, 0xc3], SOURCE)
        .unwrap()
}
fn point_plan() -> TrampolinePlan {
    let actions = actions()
        .into_iter()
        .map(EarlyIfEnabled)
        .collect::<Vec<_>>();
    TrampolinePlan::from_point_observation_actions(&scan(), SOURCE, SOURCE + 7, &actions).unwrap()
}

#[test]
fn mixed_actions_preserve_old_output_controls_maps_and_owner_lifetime() {
    let controls = actions();
    let weak = controls
        .iter()
        .map(|action| action.control.downgrade())
        .collect::<Vec<_>>();
    let after = controls
        .iter()
        .cloned()
        .map(AfterCapture)
        .collect::<Vec<_>>();
    let old =
        TrampolinePlan::from_controlled_actions(&scan(), SOURCE, SOURCE + 7, &controls).unwrap();
    let same = TrampolinePlan::from_point_observation_actions(&scan(), SOURCE, SOURCE + 7, &after)
        .unwrap();
    assert_eq!(old.emit_at(IMAGE).unwrap(), same.emit_at(IMAGE).unwrap());
    let mixed = vec![
        EarlyIfEnabled(controls[0].clone()),
        AfterCapture(controls[1].clone()),
        EarlyIfEnabled(controls[2].clone()),
    ];
    let plan = TrampolinePlan::from_point_observation_actions(&scan(), SOURCE, SOURCE + 7, &mixed)
        .unwrap();
    let image = plan.emit_at(IMAGE).unwrap();
    assert_eq!(
        image
            .early_control_gates()
            .iter()
            .map(|gate| gate.logical_pc)
            .collect::<Vec<_>>(),
        [SOURCE, SOURCE + 6]
    );
    for gate in image.early_control_gates() {
        assert!(
            image
                .entry_routes()
                .contains(&(gate.logical_pc, gate.entry))
        );
        assert!(
            image
                .instruction_boundaries()
                .contains(&(gate.logical_pc, gate.original_body))
        );
        assert_eq!(
            Decoder::with_ip(
                64,
                &image.bytes()[(gate.post_load - IMAGE) as usize..],
                gate.post_load,
                DecoderOptions::NONE
            )
            .decode()
            .code(),
            Code::Jrcxz_rel8_64
        );
        assert!(
            image
                .program_counter_mappings()
                .iter()
                .any(|map| map.translate(gate.post_load) == Some(gate.logical_pc))
        );
    }
    let scan = scan();
    for (original, &(pc, body)) in scan
        .instructions()
        .iter()
        .zip(image.instruction_boundaries())
    {
        assert_eq!(pc, original.address());
        assert_eq!(
            &image.bytes()[(body - IMAGE) as usize..][..original.len()],
            &scan.snapshot()[original.offset()..original.offset() + original.len()]
        );
    }
    for mask in 0..8 {
        for (index, action) in controls.iter().enumerate() {
            action.control.set_enabled(mask & (1 << index) != 0);
        }
        assert_eq!(plan.emit_at(IMAGE).unwrap(), image);
    }
    drop(old);
    drop(same);
    drop(after);
    drop(mixed);
    drop(controls);
    drop(plan);
    assert!(weak.iter().all(|control| control.strong_count() == 1));
    drop(image);
    assert!(weak.iter().all(|control| control.upgrade().is_none()));
}

#[test]
fn internal_branch_reaches_gate_but_rip_data_keeps_original_address() {
    let bytes = [
        0x48, 0x8b, 0x05, 0xf9, 0xff, 0xff, 0xff, 0xeb, 0xf7, 0x90, 0xc3,
    ];
    let scan = InstructionScanner::default().scan(&bytes, SOURCE).unwrap();
    let actions = [EarlyIfEnabled(ControlledAction {
        logical_pc: SOURCE,
        control: ProbeControl::new(observe, false),
    })];
    let plan = TrampolinePlan::from_point_observation_actions(
        &scan,
        SOURCE,
        SOURCE + bytes.len() as u64,
        &actions,
    )
    .unwrap();
    let image = plan.emit_at(IMAGE).unwrap();
    let body = |pc| {
        image
            .instruction_boundaries()
            .iter()
            .find(|(original, _)| *original == pc)
            .unwrap()
            .1
    };
    let read = Decoder::with_ip(
        64,
        &image.bytes()[(body(SOURCE) - IMAGE) as usize..],
        body(SOURCE),
        DecoderOptions::NONE,
    )
    .decode();
    assert_eq!(read.ip_rel_memory_address(), SOURCE);
    let branch = Decoder::with_ip(
        64,
        &image.bytes()[(body(SOURCE + 7) - IMAGE) as usize..],
        body(SOURCE + 7),
        DecoderOptions::NONE,
    )
    .decode();
    assert_eq!(
        branch.near_branch_target(),
        image.early_control_gates()[0].entry
    );
    assert_ne!(
        branch.near_branch_target(),
        image.early_control_gates()[0].original_body
    );
}

#[test]
fn invalid_associations_and_unsupported_emission_profiles_refuse() {
    let controls = actions();
    for invalid in [
        vec![],
        vec![
            EarlyIfEnabled(controls[1].clone()),
            AfterCapture(controls[0].clone()),
        ],
        vec![
            EarlyIfEnabled(controls[0].clone()),
            AfterCapture(controls[0].clone()),
        ],
        vec![EarlyIfEnabled(ControlledAction {
            logical_pc: SOURCE + 1,
            control: controls[0].control.clone(),
        })],
        vec![
            EarlyIfEnabled(controls[0].clone()),
            AfterCapture(ControlledAction {
                logical_pc: SOURCE + 3,
                control: controls[0].control.clone(),
            }),
        ],
    ] {
        assert!(
            TrampolinePlan::from_point_observation_actions(&scan(), SOURCE, SOURCE + 7, &invalid)
                .is_err()
        );
    }
    let plan = point_plan();
    assert!(plan.emit_with_frame_trace_at(IMAGE).is_err());
    assert!(plan.prepare_ordered(None, true, false).is_err());
    let artifact = ArtifactEmission::new(
        crate::emission::TargetProfile::linux_x86_64_legacy_evex(
            SavedExtendedStateLayout::describe_target_fxsave64(),
            7,
        )
        .unwrap(),
        crate::emission::SymbolicHook {
            identity: 11,
            address: Some(SOURCE + 100),
        },
        vec![],
    );
    assert!(plan.emit_artifact_at(IMAGE, &artifact).is_err());
    assert!(
        plan.emit_artifact_with_frame_trace_at(IMAGE, &artifact, FrameTraceLimits::default())
            .is_err()
    );
    assert!(plan.prepare_ordered(Some(&artifact), false, false).is_err());
    assert!(fitting::PreparedArtifact::new(&plan, &artifact).is_err());
    for profile in [
        ObservationStackProfile::Tree144,
        ObservationStackProfile::CallPair240,
    ] {
        let mut changed = plan.clone();
        changed.observation_stack_profile = profile;
        assert!(changed.emit_at(IMAGE).is_err());
    }
    let mut ptrace = plan.clone();
    ptrace.ptrace_stops = true;
    assert!(ptrace.emit_at(IMAGE).is_err());
    let mut replacement = plan.clone();
    replacement.actions[0].2 = true;
    assert!(replacement.emit_at(IMAGE).is_err());
    unsafe extern "C" fn managed(_: *mut HookContext, _: crate::controls::ControlIdentity<'_>) {}
    let (selector, _) = crate::precontext::PreContextSelector::new(false);
    let mut precontext = plan.clone();
    precontext.precontext_actions = vec![crate::precontext::PreContextAction::new(
        SOURCE,
        crate::precontext::PreContextRole::Entry,
        &selector,
        managed,
    )]
    .into_boxed_slice();
    assert!(precontext.emit_at(IMAGE).is_err());
    let mut missing = plan;
    missing.early_controls.as_mut().unwrap().modes = vec![true].into_boxed_slice();
    assert!(missing.emit_at(IMAGE).is_err());
}

#[test]
fn prepared_gate_population_and_body_associations_are_required() {
    let plan = point_plan();
    for corruption in 0..4 {
        let mut prepared = plan.prepare_ordered(None, false, false).unwrap();
        match corruption {
            0 => {
                prepared.early_control_specs.pop();
            }
            1 => {
                prepared.early_control_specs.swap(0, 1);
            }
            2 => {
                prepared.early_control_specs[0].0 = 1;
            }
            3 => {
                prepared.heads[0].2 = prepared.heads[1].2;
            }
            _ => unreachable!(),
        }
        assert!(
            plan.emit_prepared_ordered_at(IMAGE, None, None, prepared, None)
                .is_err()
        );
    }
}

#[test]
fn rounded_two_page_bound_is_exact_and_does_not_restrict_old_profile() {
    for (offset, len) in [(0, 8192), (1, 8191), (4095, 4097)] {
        validate_image_extent(IMAGE + offset, len).unwrap();
        assert!(validate_image_extent(IMAGE + offset, len + 1).is_err());
    }
    assert!(validate_image_extent(IMAGE, 0).is_err());
    assert!(validate_image_extent(u64::MAX - 4, 5).is_err());
    let source = vec![0x90; 8192];
    let scan = InstructionScanner::default().scan(&source, SOURCE).unwrap();
    let action = ControlledAction {
        logical_pc: SOURCE,
        control: ProbeControl::new(observe, false),
    };
    let old = TrampolinePlan::from_controlled_actions(
        &scan,
        SOURCE,
        SOURCE + source.len() as u64,
        core::slice::from_ref(&action),
    )
    .unwrap();
    assert!(old.emit_at(IMAGE).unwrap().bytes().len() > 8192);
    for action in [AfterCapture(action.clone()), EarlyIfEnabled(action)] {
        let new = TrampolinePlan::from_point_observation_actions(
            &scan,
            SOURCE,
            SOURCE + source.len() as u64,
            &[action],
        )
        .unwrap();
        assert!(matches!(
            new.emit_at(IMAGE),
            Err(TrampolineError::CodeTooLarge { .. })
        ));
    }
}
