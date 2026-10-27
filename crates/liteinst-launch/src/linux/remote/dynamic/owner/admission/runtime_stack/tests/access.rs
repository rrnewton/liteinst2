use super::*;

#[test]
fn stack_cpuid_requires_each_actual_record_and_closed_component_layout() {
    let original = layout();
    let accepted = original.validate().unwrap();
    for missing in 0..5 {
        let mut bad = original;
        bad.records[missing] = None;
        assert_eq!(bad.validate(), Err(StackError::Incomplete));
    }
    for wrong in 0..5 {
        let mut bad = original;
        bad.records[wrong].as_mut().unwrap().subleaf ^= 1;
        assert_eq!(bad.validate(), Err(StackError::Layout));
    }
    for (record, register, bit) in [(1, 2, 26), (1, 2, 27), (2, 2, 3), (2, 2, 4), (3, 0, 9)] {
        let mut bad = original;
        bad.records[record].as_mut().unwrap().registers[register] &= !(1 << bit);
        assert_eq!(bad.validate(), Err(StackError::Layout));
    }
    for (record, register, value) in [
        (0, 0, 12),
        (4, 0, 4),
        (4, 0, 16),
        (4, 1, 575),
        (4, 1, 65528),
        (4, 2, 1),
    ] {
        let mut bad = original;
        bad.records[record].as_mut().unwrap().registers[register] = value;
        assert_eq!(bad.validate(), Err(StackError::Layout));
    }
    let mut moved = original;
    moved.records[1].as_mut().unwrap().registers[1] ^= 0xff00_0000;
    assert_eq!(moved.validate(), Ok(accepted));
    assert_ne!(moved.records, original.records);
    assert_eq!(original.records[1].unwrap().registers[1], 0x2000_0000);
    let mut changed = original;
    changed.records[4].as_mut().unwrap().registers[1] = 840;
    assert_ne!(changed.validate().unwrap(), accepted);
}
#[test]
fn stack_xstate_requires_independent_success_and_exact_iovec_extent() {
    for change in 0..12 {
        let mut storage = StackObservationStorage::empty();
        storage.allocate_payloads().unwrap();
        slot(&mut storage.state, &state());
        let layout = layout().validate().unwrap();
        assert_eq!(validate_state(&storage.state, layout), Ok(0));
        match change {
            0 => storage.state.complete = false,
            1 => storage.state.registers_request = None,
            2 => storage.state.xstate_request = None,
            3 => storage.state.mask_request = None,
            4 => {
                storage.state.registers_request = Some(Request {
                    result: -1,
                    errno: Some(libc::EFAULT),
                })
            }
            5 => {
                storage.state.xstate_request = Some(Request {
                    result: 1,
                    errno: None,
                })
            }
            6 => {
                storage.state.mask_request = Some(Request {
                    result: 0,
                    errno: Some(libc::EIO),
                })
            }
            7 => storage.state.requested_pointer ^= 8,
            8 => storage.state.returned_pointer ^= 8,
            9 => storage.state.returned_length = 575,
            10 => storage.state.returned_length = BYTES,
            11 => storage.state.returned_length = 839,
            _ => unreachable!(),
        }
        assert_eq!(
            validate_state(&storage.state, layout),
            Err(StackError::Request)
        );
    }
}
#[test]
fn stack_pkru_requires_export_presence_uncompacted_header_and_key_zero_rights() {
    for (offset, value) in [
        (464, 0),
        (512, 0),
        (520, 1_u64 << 63),
        (528, 1),
        (568, 1),
        (832, 1),
        (832, 2),
        (832, 1_u64 << 32),
    ] {
        let mut storage = StackObservationStorage::empty();
        storage.allocate_payloads().unwrap();
        slot(&mut storage.state, &state());
        storage.state.state.xstate[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert_eq!(
            validate_state(&storage.state, layout().validate().unwrap()),
            Err(StackError::Xstate)
        );
    }
    let mut storage = StackObservationStorage::empty();
    storage.allocate_payloads().unwrap();
    slot(&mut storage.state, &state());
    storage.state.state.xstate[832..840].copy_from_slice(&0xffff_fffc_u64.to_le_bytes());
    assert_eq!(
        validate_state(&storage.state, layout().validate().unwrap()),
        Ok(0xffff_fffc)
    );
    let mut truncated = state();
    truncated.xstate.truncate(832);
    slot(&mut storage.state, &truncated);
    assert_eq!(
        validate_state(&storage.state, layout().validate().unwrap()),
        Err(StackError::Xstate)
    );
}
#[test]
fn stack_native64_access_refuses_ac_tf_rf_vm_and_changed_segments() {
    for change in 0..6 {
        let mut storage = StackObservationStorage::empty();
        storage.allocate_payloads().unwrap();
        slot(&mut storage.state, &state());
        match change {
            0 => storage.state.state.registers.eflags |= 1 << 18,
            1 => storage.state.state.registers.eflags |= 1 << 8,
            2 => storage.state.state.registers.eflags |= 1 << 16,
            3 => storage.state.state.registers.eflags |= 1 << 17,
            4 => storage.state.state.registers.cs = 0x23,
            5 => storage.state.state.registers.ss = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            validate_state(&storage.state, layout().validate().unwrap()),
            Err(StackError::Mode)
        );
    }
}
#[test]
fn stack_pagemap_requires_both_resident_exclusive_pages_and_exact_request() {
    let envelope = 0x801ff8..0x802008;
    let good = pagemap(&envelope);
    assert_eq!(good.requested, 16);
    assert_eq!(good.validate(&envelope), Ok(()));
    for page in 0..2 {
        for bit in [56, 63] {
            let mut bad = good;
            bad.bytes[page * 8 + bit / 8] ^= 1 << (bit % 8);
            assert_eq!(bad.validate(&envelope), Err(StackError::Pagemap));
        }
        for bit in 57..63 {
            let mut bad = good;
            bad.bytes[page * 8 + bit / 8] |= 1 << (bit % 8);
            assert_eq!(bad.validate(&envelope), Err(StackError::Pagemap));
        }
    }
    let mut descriptive = good;
    descriptive.bytes[0] = 0xa5;
    descriptive.bytes[6] |= 0x80;
    assert_eq!(descriptive.validate(&envelope), Ok(()));
    assert_ne!(descriptive.bytes, good.bytes);
    for change in 0..6 {
        let mut bad = good;
        match change {
            0 => bad.offset += 8,
            1 => bad.requested = 8,
            2 => bad.copied = 8,
            3 => {
                bad.request = Some(Request {
                    result: 8,
                    errno: None,
                })
            }
            4 => {
                bad.request = Some(Request {
                    result: -1,
                    errno: Some(libc::EACCES),
                })
            }
            5 => bad.fd = -1,
            _ => unreachable!(),
        }
        assert_eq!(bad.validate(&envelope), Err(StackError::Request));
    }
}
