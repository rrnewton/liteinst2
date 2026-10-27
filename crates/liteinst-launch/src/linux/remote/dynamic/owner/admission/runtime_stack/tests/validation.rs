use super::*;

#[test]
fn stack_bootstrap_data_uses_actual_first_user_pkru_and_exact_restore_chain() {
    let boot = model_bootstrap();
    let e = &boot.evidence;
    assert_ne!(e.exec_exit.xstate, e.restored_entry.xstate);
    validate_bootstrap_data(
        &e.exec_event,
        &e.exec_exit,
        &e.entry_trap,
        &e.restored_entry,
    )
    .unwrap();
    for change in 0..8 {
        let mut exec = e.exec_event.clone();
        let mut exit = e.exec_exit.clone();
        let mut entry = e.entry_trap.clone();
        let mut restored = e.restored_entry.clone();
        match change {
            0 => exec.registers.rsp += 8,
            1 => exit.registers.rax = 1,
            2 => exit.xstate[0] ^= 1,
            3 => entry.registers.rip += 1,
            4 => entry.registers.rsp += 8,
            5 => entry.mask ^= 1,
            6 => restored.xstate[0] ^= 1,
            7 => restored.registers.orig_rax = libc::SYS_execve as u64,
            _ => unreachable!(),
        }
        assert!(validate_bootstrap_data(&exec, &exit, &entry, &restored).is_err());
    }
}
#[test]
fn stack_profile_description_requires_complete_original_stack_and_post_read_state() {
    let boot = model_bootstrap();
    let mut p = profile(&boot);
    let original_records = p.layout_evidence.records;
    let description = p.validate(input(&boot)).unwrap();
    assert_eq!(description.initial_rsp, 0x802010);
    assert_eq!(description.restored, boot.stop);
    assert_eq!(description.stack.range(), 0x800000..0x804000);
    assert_eq!(p.layout_evidence.records, original_records);
    assert_eq!(
        p.allocated_bytes().unwrap(),
        PreparedStackProfile::reservation_bytes().unwrap()
    );
    assert!(matches!(p.validate(input(&boot)), Err(StackError::Reused)));
    for change in 0..8 {
        let mut boot = model_bootstrap();
        let mut p = profile(&boot);
        match change {
            0 => boot.stop.identity.generation = 1,
            1 => boot.stop.token.task = None,
            2 => boot.stop.phase = AdmissionPhase::NativeCompleted,
            3 => boot.island.page_size = 8192,
            4 => p.observation.state.state.mask ^= 1,
            5 => p.observation.state.state.registers.eflags ^= 1,
            6 => p.observation.maps[1] ^= 1,
            7 => p.observation.smaps_capture.complete = false,
            _ => unreachable!(),
        }
        assert!(p.validate(input(&boot)).is_err());
        assert!(p.description().is_none());
        let first = p.first_failure();
        assert!(first.is_some());
        assert!(matches!(p.validate(input(&boot)), Err(StackError::Reused)));
        assert_eq!(p.first_failure(), first);
    }
}
#[test]
fn stack_unstarted_failed_and_aborted_storage_never_yields_descriptions() {
    let boot = model_bootstrap();
    let mut empty = PreparedStackProfile::empty();
    assert!(matches!(
        empty.validate(input(&boot)),
        Err(StackError::Incomplete)
    ));
    assert!(empty.description().is_none());
    let mut aborted = PreparedStackProfile::empty();
    aborted.allocate_payloads().unwrap();
    aborted.mark_aborted();
    assert!(matches!(
        aborted.validate(input(&boot)),
        Err(StackError::Reused)
    ));
    assert_eq!(aborted.first_failure(), Some(StackError::Aborted));
    let mut partial = PreparedStackOperand::empty();
    partial.observation.set_fault(AllocationFault {
        fail_before: Some(1),
        panic_after: None,
    });
    assert_eq!(partial.allocate_payloads(), Err(StackError::Allocation));
    partial.mark_aborted();
    assert_eq!(partial.first_failure(), Some(StackError::Allocation));
    assert!(partial.description().is_none());
}
#[test]
fn stack_encoding_and_address_profile_are_closed_with_untouched_return_page_geometry() {
    let stack = 0x800000..0x804000;
    let island = 0x600000..0x601000;
    // E8 ends exactly at the page boundary. Encoding fetch is the preceding
    // page; this is a pure geometry control, not evidence that NX was applied.
    let exact =
        OperandGeometry::derive(0x400ffb, &[0xe8, 0, 0, 0, 0], 0x802010, &stack, &island).unwrap();
    assert_eq!(exact.next_pc, 0x401000);
    assert_eq!(exact.call_target, Some(0x401000));
    assert_eq!(exact.slot, 0x802008..0x802010);
    let crossing =
        OperandGeometry::derive(0x400ffd, &[0xe8, 0, 0, 0, 0], 0x802010, &stack, &island).unwrap();
    assert_eq!(crossing.next_pc, 0x401002);
    for bytes in [
        &[0x66, 0xe8, 0, 0, 0, 0][..],
        &[0x48, 0xc3],
        &[0xc2, 8, 0],
        &[0xff, 0xd0],
        &[0x50],
        &[0x58],
        &[0xe8, 0, 0, 0],
        &[0x90],
    ] {
        assert_eq!(
            OperandGeometry::derive(0x401000, bytes, 0x802010, &stack, &island),
            Err(StackError::Encoding)
        );
    }
    assert_eq!(
        OperandGeometry::derive(USER_END - 1, &[0xc3], 0x802010, &stack, &island),
        Err(StackError::Geometry)
    );
    assert_eq!(
        OperandGeometry::derive(0x600000, &[0xc3], 0x802010, &stack, &island),
        Err(StackError::Geometry)
    );
    let displacement = (0x600000_i64 - 0x401005) as i32;
    let mut call = [0xe8, 0, 0, 0, 0];
    call[1..].copy_from_slice(&displacement.to_le_bytes());
    assert_eq!(
        OperandGeometry::derive(0x401000, &call, 0x802010, &stack, &island),
        Err(StackError::Geometry)
    );
}
#[test]
fn stack_frozen_word_geometry_preserves_cross_page_envelope_and_rejects_growth() {
    let stack = 0x800000..0x804000;
    let island = 0x600000..0x601000;
    let call =
        OperandGeometry::derive(0x401000, &[0xe8, 0, 0, 0, 0], 0x802003, &stack, &island).unwrap();
    assert_eq!(call.slot, 0x801ffb..0x802003);
    assert_eq!(call.envelope, 0x801ff8..0x802008);
    let ret = OperandGeometry::derive(0x401000, &[0xc3], 0x801ffb, &stack, &island).unwrap();
    assert_eq!(ret.slot, call.slot);
    assert_eq!(ret.envelope, call.envelope);
    assert_eq!(
        OperandGeometry::derive(0x401000, &[0xe8, 0, 0, 0, 0], 0x800000, &stack, &island),
        Err(StackError::Geometry)
    );
    assert_eq!(
        OperandGeometry::derive(0x401000, &[0xc3], 0x803ffc, &stack, &island),
        Err(StackError::Geometry)
    );
}
#[test]
fn stack_word_requires_exact_real_request_shape_without_rejecting_all_ones_data() {
    let geometry = OperandGeometry::derive(
        0x401000,
        &[0xc3],
        0x802010,
        &(0x800000..0x804000),
        &(0x600000..0x601000),
    )
    .unwrap();
    let all_ones = word(&geometry, u64::MAX);
    assert_eq!(all_ones.peek[0].unwrap().request.result, -1);
    assert_eq!(all_ones.validate(&geometry), Ok(u64::MAX));
    for change in 0..7 {
        let mut bad = all_ones;
        match change {
            0 => bad.complete = false,
            1 => bad.copied = 7,
            2 => bad.peek[0] = None,
            3 => bad.peek[0].as_mut().unwrap().request.errno = Some(libc::EFAULT),
            4 => bad.peek[0].as_mut().unwrap().address += 8,
            5 => bad.bytes[0] ^= 1,
            6 => bad.peek[1] = bad.peek[0],
            _ => unreachable!(),
        }
        assert!(bad.validate(&geometry).is_err());
    }
}
fn operand(
    profile: &ProfileDescription,
    state: &TaskStateSnapshot,
    bytes: &[u8],
    value: u64,
) -> PreparedStackOperand {
    let mut p = PreparedStackOperand::empty();
    p.allocate_payloads().unwrap();
    observation(&mut p.observation, state);
    p.layout_evidence = layout();
    let geometry = OperandGeometry::derive(
        state.registers.rip,
        bytes,
        state.registers.rsp,
        &profile.stack.range(),
        &(0x600000..0x601000),
    )
    .unwrap();
    p.word = word(&geometry, value);
    p
}
#[test]
fn stack_operand_description_binds_current_full_state_metadata_word_and_layout() {
    let boot = model_bootstrap();
    let mut p = profile(&boot);
    let facts = p.validate(input(&boot)).unwrap();
    let current = state();
    let until = std::time::Instant::now();
    let island = 0x600000..0x601000;
    let bytes = [0xc3];
    for change in 0..16 {
        let mut current_stop = boot.stop.clone();
        let mut supplied_island = island.clone();
        let mut o = operand(facts, &current, &bytes, 0x401005);
        match change {
            0 => {}
            1 => o.observation.state.state.mask ^= 1,
            2 => o.observation.state.state.xstate[0] ^= 1,
            3 => o.layout_evidence.records[4].as_mut().unwrap().registers[1] = 840,
            4 => o.observation.maps[1] ^= 1,
            5 => o.word.peek[0].as_mut().unwrap().address += 8,
            6 => o.observation.smaps_capture.complete = false,
            7 => {
                o.word = word(
                    &OperandGeometry::derive(
                        current.registers.rip,
                        &bytes,
                        current.registers.rsp,
                        &facts.stack.range(),
                        &island,
                    )
                    .unwrap(),
                    island.start,
                )
            }
            8 => o.observation.state.state.registers.eflags |= 1 << 18,
            9 => current_stop.token.tid += 1,
            10 => current_stop.token.session += 1,
            11 => current_stop.token.task = None,
            12 => current_stop.identity.generation += 1,
            13 => current_stop.token.sequence -= 1,
            14 => current_stop.phase = AdmissionPhase::NativeCompleted,
            15 => supplied_island = 0x700000..0x701000,
            _ => unreachable!(),
        }
        let result = o.validate(OperandInput {
            profile: facts,
            original_maps: ORIGINAL,
            expected_maps: BASELINE,
            current: &current,
            current_stop: &current_stop,
            until,
            pc: current.registers.rip,
            encoding: &bytes,
            island: &supplied_island,
        });
        if change == 0 {
            let description = result.unwrap();
            assert_eq!(description.target, 0x401005);
            assert_eq!(description.stop, current_stop);
            assert_eq!(description.until, until);
            assert!(o.description().is_some());
        } else {
            assert!(result.is_err());
            assert!(o.description().is_none());
            assert!(o.first_failure().is_some());
        }
        assert!(matches!(
            o.validate(OperandInput {
                profile: facts,
                original_maps: ORIGINAL,
                expected_maps: BASELINE,
                current: &current,
                current_stop: &current_stop,
                until,
                pc: current.registers.rip,
                encoding: &bytes,
                island: &supplied_island
            }),
            Err(StackError::Reused)
        ));
    }
}
fn change_register(registers: &mut RegisterSnapshot, index: usize) {
    let target = match index {
        0 => &mut registers.r15,
        1 => &mut registers.r14,
        2 => &mut registers.r13,
        3 => &mut registers.r12,
        4 => &mut registers.rbp,
        5 => &mut registers.rbx,
        6 => &mut registers.r11,
        7 => &mut registers.r10,
        8 => &mut registers.r9,
        9 => &mut registers.r8,
        10 => &mut registers.rax,
        11 => &mut registers.rcx,
        12 => &mut registers.rdx,
        13 => &mut registers.rsi,
        14 => &mut registers.rdi,
        15 => &mut registers.orig_rax,
        16 => &mut registers.rip,
        17 => &mut registers.cs,
        18 => &mut registers.eflags,
        19 => &mut registers.rsp,
        20 => &mut registers.ss,
        21 => &mut registers.fs_base,
        22 => &mut registers.gs_base,
        23 => &mut registers.ds,
        24 => &mut registers.es,
        25 => &mut registers.fs,
        26 => &mut registers.gs,
        _ => unreachable!(),
    };
    *target ^= 1;
}
#[test]
fn stack_call_effect_preserves_every_register_flag_xstate_mask_and_neighbor() {
    let mut initial = state();
    initial.registers.rsp = 0x802003;
    initial.registers.orig_rax = libc::SYS_getpid as u64;
    let geometry = OperandGeometry::derive(
        initial.registers.rip,
        &[0xe8, 0, 0, 0, 0],
        initial.registers.rsp,
        &(0x800000..0x804000),
        &(0x600000..0x601000),
    )
    .unwrap();
    let before = word(&geometry, 0x1122334455667788).bytes;
    let facts = OperandDescription {
        target: geometry.call_target.unwrap(),
        geometry,
        value: 0x1122334455667788,
        pkru: 0,
        stop: model_bootstrap().stop,
        until: std::time::Instant::now(),
    };
    let mut after_bytes = before;
    let offset = (facts.geometry.slot.start - facts.geometry.envelope.start) as usize;
    after_bytes[offset..offset + 8].copy_from_slice(&facts.geometry.next_pc.to_le_bytes());
    let mut actual = initial.clone();
    actual.registers.rip = facts.target;
    actual.registers.rsp -= 8;
    actual.registers.orig_rax = u64::MAX;
    validate_effect(&initial, &actual, &facts, &before, &after_bytes).unwrap();
    for index in 0..27 {
        let mut changed = actual.clone();
        change_register(&mut changed.registers, index);
        assert_eq!(
            validate_effect(&initial, &changed, &facts, &before, &after_bytes),
            Err(StackError::State)
        );
    }
    for index in 0..actual.xstate.len() {
        let mut changed = actual.clone();
        changed.xstate[index] ^= 1;
        assert_eq!(
            validate_effect(&initial, &changed, &facts, &before, &after_bytes),
            Err(StackError::State)
        );
    }
    for bit in 0..64 {
        let mut changed = actual.clone();
        changed.mask ^= 1 << bit;
        assert_eq!(
            validate_effect(&initial, &changed, &facts, &before, &after_bytes),
            Err(StackError::State)
        );
    }
    for index in 0..16 {
        let mut changed = after_bytes;
        changed[index] ^= 1;
        assert_eq!(
            validate_effect(&initial, &actual, &facts, &before, &changed),
            Err(StackError::Word)
        );
    }
}
#[test]
fn stack_ret_effect_requires_captured_target_and_unchanged_entire_envelope() {
    let mut initial = state();
    initial.registers.rsp = 0x801ffb;
    let geometry = OperandGeometry::derive(
        initial.registers.rip,
        &[0xc3],
        initial.registers.rsp,
        &(0x800000..0x804000),
        &(0x600000..0x601000),
    )
    .unwrap();
    let before = word(&geometry, 0x401005).bytes;
    let facts = OperandDescription {
        geometry,
        value: 0x401005,
        target: 0x401005,
        pkru: 0,
        stop: model_bootstrap().stop,
        until: std::time::Instant::now(),
    };
    let mut actual = initial.clone();
    actual.registers.rip = facts.target;
    actual.registers.rsp += 8;
    validate_effect(&initial, &actual, &facts, &before, &before).unwrap();
    for index in 0..16 {
        let mut changed = before;
        changed[index] ^= 1;
        assert!(validate_effect(&initial, &actual, &facts, &before, &changed).is_err());
    }
    let mut bad_target = facts.clone();
    bad_target.value = u64::MAX;
    bad_target.target = u64::MAX;
    let mut bad_word = before;
    let offset = (facts.geometry.slot.start - facts.geometry.envelope.start) as usize;
    bad_word[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut bad_state = actual.clone();
    bad_state.registers.rip = u64::MAX;
    assert_eq!(
        validate_effect(&initial, &bad_state, &bad_target, &bad_word, &bad_word),
        Err(StackError::Geometry)
    );
    let mut changed = facts.clone();
    changed.target += 1;
    actual.registers.rip += 1;
    assert_eq!(
        validate_effect(&initial, &actual, &changed, &before, &before),
        Err(StackError::Word)
    );
}
