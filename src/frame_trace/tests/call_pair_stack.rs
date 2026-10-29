//! Encoded-helper geometry only: no application execution or callback headroom proof.
use super::*;
use crate::trampoline::ObservationStackProfile;
use iced_x86::{BlockEncoder, BlockEncoderOptions, InstructionBlock};

fn plan(profile: ObservationStackProfile) -> TrampolinePlan {
    TrampolinePlan::from_controlled_actions_with_stack_profile(
        &scan(&[0x90; 5]),
        BASE,
        BASE + 5,
        &[ControlledAction {
            logical_pc: BASE,
            control: ProbeControl::new(observer, true),
        }],
        profile,
    )
    .unwrap()
}

// Decode immutable encoded bytes once per emission. The borrowed image and
// helper rows stay paired; no Machine, memory, seed or walk result is retained.
struct DecodedHelpers<'a> {
    image: &'a TrampolineImage,
    rows: Vec<(&'a HelperFrame, Instruction)>,
}

fn decoded_helpers(emission: &FrameEmission) -> DecodedHelpers<'_> {
    let image = emission.image();
    let mut rows = Vec::new();
    for row in emission.trace().unwrap().instructions() {
        let FrameInstructionKind::Helper(helper) = row.kind() else {
            continue;
        };
        let start = usize::try_from(row.start() - NEAR).unwrap();
        let end = usize::try_from(row.end() - NEAR).unwrap();
        let mut decoder = Decoder::with_ip(
            64,
            &image.bytes()[start..end],
            row.start(),
            DecoderOptions::NONE,
        );
        let i = decoder.decode();
        assert!(!i.is_invalid() && !decoder.can_decode());
        assert_eq!(i.next_ip(), row.end());
        assert_eq!(i.code(), helper.instruction().code());
        rows.push((helper.as_ref(), i));
    }
    DecodedHelpers { image, rows }
}

// Drive the existing independent Machine from each actual encoded instruction.
// Check the full enclosing window, including bytes above this role's RSP. The
// saved-state model checks byte extents and matching save/restore addresses, not
// architectural XSAVE contents or an arbitrary callback's stack consumption.
fn preservation(
    decoded: &DecodedHelpers<'_>,
    role_rsp: u64,
    low: u64,
    high: u64,
    seed: u64,
) -> (bool, bool) {
    let image = decoded.image;
    let profile = image.layout().observation_stack_profile;
    let prefix = profile.context_stack_prefix_bytes() as u64;
    let layout = image.layout().saved_extended_state;
    let mut machine = Machine::new(seed);
    machine.original[7] = role_rsp;
    machine.registers[7] = role_rsp;
    let expected: Vec<_> = (low..high).map(|at| (at, (at ^ seed) as u8)).collect();
    machine.memory.extend(expected.iter().copied());
    let mut untouched = true;
    let mut save = None;
    let mut restores = 0;
    let mut returned = 0;
    let mut stores = 0;
    for &(helper, i) in &decoded.rows {
        assert_eq!(helper.before().observation_stack_profile(), profile);
        assert_eq!(helper.after().observation_stack_profile(), profile);
        machine.check(helper.before());
        let write = match i.mnemonic() {
            Mnemonic::Push | Mnemonic::Pushfq => {
                Some((machine.read(Register::RSP).checked_sub(8).unwrap(), 8))
            }
            Mnemonic::Mov if i.op0_kind() == OpKind::Memory => {
                Some((machine.memory_address(&i), i.memory_size().size() as u64))
            }
            Mnemonic::Fxsave64 | Mnemonic::Xsave64 => {
                let at = machine.read(Register::RSP);
                assert!(save.replace(at).is_none());
                assert_eq!(at % layout.format().required_alignment().unwrap(), 0);
                assert!(
                    at.checked_add(layout.image_len()).unwrap()
                        <= role_rsp.checked_sub(prefix).unwrap()
                );
                Some((at, layout.image_len()))
            }
            Mnemonic::Fxrstor64 | Mnemonic::Xrstor64 => {
                assert_eq!(Some(machine.read(Register::RSP)), save);
                restores += 1;
                None
            }
            Mnemonic::Call => {
                assert_eq!(
                    helper.before().original_rsp_rule(),
                    (Register::R12, prefix as i32)
                );
                let context = machine.read(Register::R12);
                assert_eq!(context, role_rsp.checked_sub(prefix).unwrap());
                assert_eq!(machine.load(context), BASE);
                assert_eq!(machine.load(context + 8), role_rsp);
                assert_eq!(Some(machine.load(context + 144)), save);
                assert_eq!(machine.load(context + 152), layout.len());
                assert_eq!(machine.load(context + 160), layout.mask());
                assert_eq!(machine.load(context + 168), layout.format().raw());
                // The helper CALL's physical return word, separately from the
                // Machine's arbitrary caller-saved register/FLAGS clobbers.
                Some((machine.read(Register::RSP).checked_sub(8).unwrap(), 8))
            }
            _ => None,
        };
        if let Some((at, len)) = write {
            assert!(len > 0);
            let end = at.checked_add(len).unwrap();
            untouched &= end <= low; // Every byte, not only the first address.
            stores += 1;
        }
        machine.step(&i, image);
        machine.check(helper.after());
        if helper.stage() == FrameStage::Restore
            && helper.after() == &FrameState::entry_for_profile(profile)
        {
            returned += 1;
        }
    }
    assert_eq!((restores, returned, machine.calls), (1, 1, 1));
    assert!(save.is_some() && stores >= 24); // 16 pushes + 2 metadata + 4 descriptors + save + CALL.
    assert_eq!(machine.registers, machine.original); // Includes return-value RAX and RSP.
    assert_eq!(machine.flags, machine.original_flags);
    (
        untouched,
        expected
            .iter()
            .all(|&(at, byte)| machine.memory.get(&at) == Some(&byte)),
    )
}

#[test]
fn call_pair240_all_bounded_roles_preserve_enclosing_window() {
    let p = plan(ObservationStackProfile::CallPair240);
    let emission = p.emit_with_frame_trace_at(NEAR).unwrap();
    assert_eq!(emission.image(), &p.emit_at(NEAR).unwrap());
    assert_eq!(
        emission.trace().unwrap().observation_stack_profile(),
        ObservationStackProfile::CallPair240
    );
    let decoded = decoded_helpers(&emission);
    let outer = 0x20_0008_u64;
    let mut geometries = 0;
    let mut widest = 0;
    // Every aligned enclosing excursion L, every aligned CALL delta D admitted
    // by the unchanged 256-byte caller, and each admitted child delta d.
    for deepest in (0_u64..=256).step_by(8) {
        for parent_delta in (16_u64..=256).step_by(16) {
            if deepest < parent_delta - 8 {
                continue;
            } // CALL's own live RSP was visited.
            for child_delta in [16_u64, 32, 48, 64] {
                let bound = deepest.max(parent_delta + child_delta + 128);
                assert!(bound <= 448);
                widest = widest.max(bound);
                // ParentEntry, ChildEntry, ChildRet, ChildAck, ParentRet.
                for delta in [
                    parent_delta,
                    parent_delta + child_delta,
                    parent_delta + child_delta,
                    parent_delta + child_delta - 8,
                    parent_delta,
                ] {
                    for seed in [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567] {
                        assert_eq!(
                            preservation(&decoded, outer - delta, outer - bound, outer + 8, seed),
                            (true, true)
                        );
                    }
                }
                geometries += 1;
            }
        }
    }
    assert_eq!(geometries, 1088);
    assert_eq!(widest, 448);
}

#[test]
fn call_pair240_old144_overlaps_child_and_earlier_caller_excursions() {
    let old = plan(ObservationStackProfile::Tree144)
        .emit_with_frame_trace_at(NEAR)
        .unwrap();
    let new = plan(ObservationStackProfile::CallPair240)
        .emit_with_frame_trace_at(NEAR)
        .unwrap();
    let old_decoded = decoded_helpers(&old);
    let new_decoded = decoded_helpers(&new);
    let outer = 0x20_0008_u64;
    // First: maximum child red zone. Second: earlier deep enclosing excursion,
    // restored to sp=-8 before CALL. Neither may be masked from the snapshot.
    for (deepest, parent_delta, child_delta) in [(8_u64, 16_u64, 64_u64), (256, 16, 16)] {
        let bound = deepest.max(parent_delta + child_delta + 128);
        assert_eq!(
            preservation(
                &old_decoded,
                outer - parent_delta,
                outer - bound,
                outer + 8,
                0x1234
            ),
            (false, false)
        );
        assert_eq!(
            preservation(
                &new_decoded,
                outer - parent_delta,
                outer - bound,
                outer + 8,
                0x1234
            ),
            (true, true)
        );
    }
}

fn helper(stage: FrameStage) -> (HelperFrames, Vec<Instruction>) {
    let emission = plan(ObservationStackProfile::CallPair240)
        .emit_with_frame_trace_at(NEAR)
        .unwrap();
    let mut frames = HelperFrames::with_profile(stage, ObservationStackProfile::CallPair240);
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

#[test]
fn call_pair240_actual_reserve_recovery_restore_and_profile_mutations_refuse() {
    for stage in [FrameStage::SaveAndCall, FrameStage::Restore] {
        let (mut frames, source) = helper(stage);
        let resolve = |frames: &HelperFrames, source: &[Instruction]| {
            let encoded = BlockEncoder::encode(
                64,
                InstructionBlock::new(source, NEAR),
                BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
            )
            .unwrap();
            frames.resolve(source, &encoded)
        };
        assert!(resolve(&frames, &source).is_ok());
        let mut mutations = 0;
        for (index, i) in source.iter().enumerate() {
            if i.mnemonic() == Mnemonic::Lea {
                let mut changed = source.clone();
                changed[index].set_memory_displacement64(i.memory_displacement64().wrapping_add(8));
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
        frames.profile = ObservationStackProfile::Tree144;
        assert!(matches!(
            resolve(&frames, &source),
            Err(FrameTraceRefusal::InvalidProducerAnnotation)
        ));
    }
    let mut wrong = FrameState::saved_for_profile(ObservationStackProfile::CallPair240);
    assert_eq!(wrong.original_rsp_rule(), (Register::R12, 416));
    wrong.profile = ObservationStackProfile::Tree144;
    assert_eq!(
        wrong.apply(FrameEffect::RestoreStack),
        Err(FrameTraceRefusal::InvalidProducerAnnotation)
    );
}
