use super::*;
use crate::trampoline::ObservationStackProfile;
use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};

fn tree() -> TrampolinePlan {
    let code = [0x90; 5];
    TrampolinePlan::from_controlled_actions_with_stack_profile(
        &scan(&code),
        BASE,
        BASE + 5,
        &[ControlledAction {
            logical_pc: BASE,
            control: ProbeControl::new(observer, true),
        }],
        ObservationStackProfile::Tree144,
    )
    .unwrap()
}

#[test]
fn every_tree_role_preserves_full_protected_range_and_original_registers() {
    let plan = tree();
    let emitted = plan.emit_with_frame_trace_at(NEAR).unwrap();
    assert_eq!(emitted.image(), &plan.emit_at(NEAR).unwrap());
    let trace = emitted.trace().unwrap();
    assert_eq!(
        trace.observation_stack_profile(),
        ObservationStackProfile::Tree144
    );
    // Root entry, child entry, child RET, original root+14, root RET.
    // This is an encoded-helper storage model, not execution of a call tree.
    let outer_rsp = 0x20_0008_u64;
    let protected = outer_rsp - 160;
    for delta in [16, 32, 32, 24, 16] {
        for seed in [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567] {
            let mut machine = Machine::new(seed);
            machine.original[7] = outer_rsp - delta;
            machine.registers[7] = machine.original[7];
            let mut saves = 0;
            let mut restores = 0;
            let mut returned = false;
            for row in trace.instructions() {
                let FrameInstructionKind::Helper(helper) = row.kind() else {
                    continue;
                };
                let start = (row.start() - NEAR) as usize;
                let end = (row.end() - NEAR) as usize;
                let mut decoder = Decoder::with_ip(
                    64,
                    &emitted.image().bytes()[start..end],
                    row.start(),
                    DecoderOptions::NONE,
                );
                let i = decoder.decode();
                assert!(!i.is_invalid() && !decoder.can_decode());
                assert_eq!(i.next_ip(), row.end());
                assert_eq!(i.code(), helper.instruction().code());
                assert_eq!(
                    helper.before().observation_stack_profile(),
                    ObservationStackProfile::Tree144
                );
                machine.check(helper.before());
                match i.mnemonic() {
                    Mnemonic::Fxsave64 | Mnemonic::Xsave64 => {
                        let image_end = machine
                            .read(Register::RSP)
                            .checked_add(emitted.image().layout().saved_extended_state.image_len())
                            .unwrap();
                        assert!(image_end <= machine.original[7] - 320);
                        assert!(image_end <= protected);
                        saves += 1;
                    }
                    Mnemonic::Fxrstor64 | Mnemonic::Xrstor64 => restores += 1,
                    Mnemonic::Call => {
                        assert!(machine.read(Register::RSP) <= protected); // Real CALL's 8-byte return word is lower.
                        assert_eq!(helper.before().original_rsp_rule(), (Register::R12, 320));
                    }
                    _ => {}
                }
                machine.step(&i, emitted.image());
                // Every modeled push, descriptor/header/PKRU store stays below
                // the entire [S-160,end) range; no red-zone bytes are masked.
                assert!(machine.memory.keys().all(|address| *address < protected));
                machine.check(helper.after());
                if helper.stage() == FrameStage::Restore
                    && helper.after()
                        == &FrameState::entry_for_profile(ObservationStackProfile::Tree144)
                {
                    assert!(!returned);
                    returned = true;
                }
            }
            assert!(returned);
            assert_eq!((saves, restores, machine.calls), (1, 1, 1));
            assert_eq!(machine.registers, machine.original);
            assert_eq!(machine.flags, machine.original_flags);
        }
    }
}

// Recover the producer annotations from an actual emitted helper's state
// transitions. Mutations below keep these annotations while changing the actual
// encoded instructions, exercising resolve() rather than a copied predicate.
fn helper(stage: FrameStage) -> (HelperFrames, Vec<Instruction>) {
    let emission = tree().emit_with_frame_trace_at(NEAR).unwrap();
    let mut frames = HelperFrames::with_profile(stage, ObservationStackProfile::Tree144);
    let mut source = Vec::new();
    for row in emission.trace().unwrap().instructions() {
        let FrameInstructionKind::Helper(h) = row.kind() else {
            continue;
        };
        if h.stage() != stage {
            continue;
        }
        let i = *h.instruction();
        source.push(i);
        if i.mnemonic() == Mnemonic::Call {
            frames.call(source.len(), FrameCallKind::ControlDispatcher);
        }
        if h.before() == h.after() {
            continue;
        }
        let effect = match i.mnemonic() {
            Mnemonic::Lea => {
                let difference = h.after().original_rsp_offset - h.before().original_rsp_offset;
                if difference > 0 {
                    FrameEffect::Reserve(difference)
                } else {
                    FrameEffect::Release(-difference)
                }
            }
            Mnemonic::Pushfq => FrameEffect::SaveFlags,
            Mnemonic::Popfq => FrameEffect::RestoreFlags,
            Mnemonic::Push => {
                let r = i.op0_register();
                if h.before().original_register(r) == Some(OriginalRegisterLocation::Live(r)) {
                    FrameEffect::SaveRegister(r)
                } else {
                    FrameEffect::MetadataWord
                }
            }
            Mnemonic::Pop => FrameEffect::RestoreRegister(i.op0_register()),
            Mnemonic::Add => FrameEffect::SkipMetadata,
            Mnemonic::Mov if stage == FrameStage::SaveAndCall => FrameEffect::AnchorContext,
            Mnemonic::Mov => FrameEffect::RestoreStack,
            _ => panic!("unexpected frame transition"),
        };
        frames.after(source.len(), effect);
    }
    (frames, source)
}

fn resolve(
    frames: &HelperFrames,
    source: &[Instruction],
) -> Result<HelperImage, FrameTraceRefusal> {
    let encoded = BlockEncoder::encode(
        64,
        InstructionBlock::new(source, NEAR),
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
    )
    .unwrap();
    frames.resolve(source, &encoded)
}

#[test]
fn actual_wrong_reserve_recovery_restore_and_descriptor_refuse() {
    for stage in [FrameStage::SaveAndCall, FrameStage::Restore] {
        let (frames, source) = helper(stage);
        assert!(resolve(&frames, &source).is_ok());
        let mut mutations = 0;
        for (index, instruction) in source.iter().enumerate() {
            if instruction.mnemonic() == Mnemonic::Lea {
                let mut changed = source.clone();
                let delta = if instruction.op0_register() == Register::RAX {
                    8
                } else {
                    16
                };
                changed[index].set_memory_displacement64(
                    instruction.memory_displacement64().wrapping_add(delta),
                );
                assert!(matches!(
                    resolve(&frames, &changed),
                    Err(FrameTraceRefusal::InvalidProducerAnnotation)
                ));
                mutations += 1;
            }
        }
        assert_eq!(
            mutations,
            if stage == FrameStage::SaveAndCall {
                3
            } else {
                2
            }
        );
    }
}

#[test]
fn profile_annotations_cannot_mix_or_attach_to_another_image() {
    let legacy = FrameState::saved();
    let tree_state = FrameState::saved_for_profile(ObservationStackProfile::Tree144);
    assert_eq!(legacy.original_rsp_rule(), (Register::R12, 304));
    assert_eq!(tree_state.original_rsp_rule(), (Register::R12, 320));
    assert_ne!(legacy, tree_state);
    let mut wrong = legacy.clone();
    wrong.profile = ObservationStackProfile::Tree144;
    assert_eq!(
        wrong.apply(FrameEffect::RestoreStack),
        Err(FrameTraceRefusal::InvalidProducerAnnotation)
    );
    let mut wrong = tree_state;
    wrong.profile = ObservationStackProfile::Legacy128;
    assert_eq!(
        wrong.apply(FrameEffect::RestoreStack),
        Err(FrameTraceRefusal::InvalidProducerAnnotation)
    );
    let (mut frames, source) = helper(FrameStage::SaveAndCall);
    let encoded = BlockEncoder::encode(
        64,
        InstructionBlock::new(&source, NEAR),
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
    )
    .unwrap();
    frames.finish(&source, &encoded);
    let mut recorder = FrameRecorder::new(
        FrameEntryOrigin::ApplicationStack,
        FrameTraceLimits::default(),
    );
    recorder.helper(BASE, NEAR, &encoded.code_buffer, frames);
    assert_eq!(
        recorder.refusal,
        Some(FrameTraceRefusal::InvalidProducerAnnotation)
    );
    let image = tree().emit_at(NEAR).unwrap();
    assert!(matches!(
        FrameRecorder::new(
            FrameEntryOrigin::ApplicationStack,
            FrameTraceLimits::default()
        )
        .finish(&image),
        Err(FrameTraceRefusal::InvalidProducerAnnotation)
    ));
    let (mut bad, source) = helper(FrameStage::SaveAndCall);
    bad.effects[0].1 = FrameEffect::Reserve(128);
    assert!(matches!(
        resolve(&bad, &source),
        Err(FrameTraceRefusal::InvalidProducerAnnotation)
    ));
}

#[test]
fn coalesced_tree_actions_keep_each_fresh_profile_anchor() {
    let code = [0xb8, 1, 0, 0, 0, 0xb9, 2, 0, 0, 0];
    let actions = [BASE, BASE + 5].map(|logical_pc| ControlledAction {
        logical_pc,
        control: ProbeControl::new(observer, true),
    });
    let plan = TrampolinePlan::from_controlled_actions_with_stack_profile(
        &scan(&code),
        BASE,
        BASE + 10,
        &actions,
        ObservationStackProfile::Tree144,
    )
    .unwrap();
    let emission = plan.emit_with_frame_trace_at(NEAR).unwrap();
    assert_eq!(emission.image(), &plan.emit_at(NEAR).unwrap());
    let trace = emission.trace().unwrap();
    assert_eq!(
        trace
            .calls()
            .iter()
            .map(|call| call.original_pc())
            .collect::<Vec<_>>(),
        [BASE, BASE + 5]
    );
    for pc in [BASE, BASE + 5] {
        let helpers: Vec<_> = trace
            .instructions()
            .iter()
            .filter(|row| row.original_pc() == pc)
            .filter_map(|row| match row.kind() {
                FrameInstructionKind::Helper(helper) => Some(helper),
                _ => None,
            })
            .collect();
        assert_eq!(
            helpers.first().unwrap().before(),
            &FrameState::entry_for_profile(ObservationStackProfile::Tree144)
        );
        assert_eq!(
            helpers.last().unwrap().after(),
            &FrameState::entry_for_profile(ObservationStackProfile::Tree144)
        );
        assert!(
            helpers
                .iter()
                .all(|h| h.before().observation_stack_profile()
                    == ObservationStackProfile::Tree144
                    && h.after().observation_stack_profile() == ObservationStackProfile::Tree144)
        );
        assert_eq!(
            helpers
                .iter()
                .filter(|h| h.instruction().mnemonic() == Mnemonic::Call
                    && h.before().original_rsp_rule() == (Register::R12, 320))
                .count(),
            1
        );
    }
}
