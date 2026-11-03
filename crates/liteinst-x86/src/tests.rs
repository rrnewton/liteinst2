use super::*;

#[test]
fn selected_register_facts_preserve_every_width_and_rsp() {
    for (class, extension) in [(SelectedClass::Rdrand, 0xf0), (SelectedClass::Rdseed, 0xf8)] {
        for width in [Width::Bits16, Width::Bits32, Width::Bits64] {
            for index in 0..16_u8 {
                let mut bytes = [0; 5];
                let mut len = 0;
                if width == Width::Bits16 {
                    bytes[len] = 0x66;
                    len += 1;
                }
                if width == Width::Bits64 || index >= 8 {
                    bytes[len] = 0x40 | if width == Width::Bits64 { 8 } else { 0 } | (index >> 3);
                    len += 1;
                }
                bytes[len..len + 3].copy_from_slice(&[0x0f, 0xc7, extension + (index & 7)]);
                len += 3;
                let decoded = decode64(0x1000, &bytes[..len]);
                assert_eq!(decoded.error, DecoderError::None);
                assert_eq!(decoded.instruction.len(), len);
                assert_eq!(selected_code(&decoded.instruction), Some(class));
                assert_eq!(selected_mnemonic(&decoded.instruction), Some(class));
                let operand = gpr(decoded.instruction.op0_register()).unwrap();
                assert_eq!((operand.register as u8, operand.width), (index, width));
            }
        }
    }
    for register in [
        Register::AL,
        Register::AH,
        Register::SS,
        Register::XMM0,
        Register::None,
    ] {
        assert_eq!(gpr(register), None);
    }
    let before = decode64(1, &[0x48, 0x66, 0x0f, 0xc7, 0xf0]);
    let after = decode64(1, &[0x66, 0x48, 0x0f, 0xc7, 0xf0]);
    assert_eq!(
        gpr(before.instruction.op0_register()).unwrap().width,
        Width::Bits16
    );
    assert_eq!(
        gpr(after.instruction.op0_register()).unwrap().width,
        Width::Bits64
    );
}

#[test]
fn decode_preserves_status_and_leaves_adapter_policy_unapplied() {
    for (bytes, error) in [
        (&[][..], DecoderError::NoMoreBytes),
        (&[0x0f][..], DecoderError::NoMoreBytes),
        (&[0xf0, 0x90][..], DecoderError::InvalidInstruction),
    ] {
        let decoded = decode64(0x1000, bytes);
        assert_eq!(decoded.error, error);
        assert!(decoded.instruction.is_invalid());
    }
    let empty = decode64(0x1000, &[]);
    assert_eq!(empty.instruction.len(), 0);
    assert_eq!(empty.instruction.next_ip(), 0x1000);
    let wrap = decode64(u64::MAX, &[0x90]);
    assert_eq!(wrap.error, DecoderError::None);
    assert_eq!(wrap.instruction.next_ip(), 0);
    let prefixed = decode64(0x1000, &[0x66, 0x0f, 0xa2, 0x90]);
    assert_eq!(prefixed.error, DecoderError::None);
    assert_eq!(prefixed.instruction.len(), 3);
    assert_eq!(
        selected_code(&prefixed.instruction),
        Some(SelectedClass::Cpuid)
    );
    // All-start policy must still inspect the selected bytes inside a MOV.
    let bytes = [0xb8, 0x0f, 0xa2, 0, 0, 0xc3];
    assert_eq!(selected_code(&decode64(0x1000, &bytes).instruction), None);
    assert_eq!(
        selected_code(&decode64(0x1001, &bytes[1..]).instruction),
        Some(SelectedClass::Cpuid)
    );
}

#[test]
fn exact_form_and_mnemonic_views_remain_distinct() {
    for (bytes, class) in [
        (&[0x0f, 0xa2][..], SelectedClass::Cpuid),
        (&[0x0f, 0x31][..], SelectedClass::Rdtsc),
        (&[0x0f, 0x01, 0xf9][..], SelectedClass::Rdtscp),
        (&[0x0f, 0x05][..], SelectedClass::Syscall),
        (&[0x0f, 0x34][..], SelectedClass::Sysenter),
        (&[0xcd, 0x80][..], SelectedClass::Int80),
        (&[0xf3, 0x0f, 0xc7, 0xf8][..], SelectedClass::Rdpid),
    ] {
        let decoded = decode64(0x1000, bytes);
        assert_eq!(decoded.error, DecoderError::None);
        assert_eq!(selected_code(&decoded.instruction), Some(class));
        assert_eq!(selected_mnemonic(&decoded.instruction), Some(class));
    }
    let other_int = decode64(0x1000, &[0xcd, 0x81]);
    assert_eq!(selected_code(&other_int.instruction), None);
    assert_eq!(selected_mnemonic(&other_int.instruction), None);
    // The admission view deliberately still recognizes a non-64-bit Code.
    let narrow =
        Decoder::with_ip(32, &[0xf3, 0x0f, 0xc7, 0xf8], 0x1000, DecoderOptions::NONE).decode();
    assert_eq!(narrow.code(), Code::Rdpid_r32);
    assert_eq!(selected_code(&narrow), None);
    assert_eq!(selected_mnemonic(&narrow), Some(SelectedClass::Rdpid));
    let wide = decode64(0x1000, &[0xf3, 0x0f, 0xc7, 0xf8]);
    assert_eq!(
        gpr(wide.instruction.op0_register()).unwrap().width,
        Width::Bits64
    );
}

#[test]
fn jump_fact_matches_the_complete_legacy_mnemonic_population() {
    extern crate std;
    let mut count = 0;
    for mnemonic in Mnemonic::values() {
        let expected = std::format!("{mnemonic:?}")
            .to_ascii_lowercase()
            .starts_with('j');
        assert_eq!(is_jump_mnemonic(mnemonic), expected, "{mnemonic:?}");
        count += usize::from(expected);
    }
    assert_eq!(count, 23);
}

#[test]
fn register_stack_union_keeps_all_registers_and_exact_code_boundaries() {
    for (opcode, code, class) in [
        (0x50, Code::Push_r64, JumpStackClass::PushRegister64),
        (0x58, Code::Pop_r64, JumpStackClass::PopRegister64),
    ] {
        for index in 0..16_u8 {
            let bytes = [0x41, opcode + (index & 7)];
            let bytes = if index < 8 { &bytes[1..] } else { &bytes[..] };
            let decoded = decode64(0x1000, bytes);
            assert_eq!(decoded.error, DecoderError::None);
            assert_eq!(decoded.instruction.code(), code);
            assert_eq!(jump_or_register_stack(&decoded.instruction), Some(class));
            let operand = gpr(decoded.instruction.op0_register()).unwrap();
            assert_eq!(
                (operand.register as u8, operand.width),
                (index, Width::Bits64)
            );
        }
    }
    for bytes in [
        &[0x66, 0x50][..],
        &[0x66, 0x58],
        &[0xff, 0xf0],
        &[0x8f, 0xc0],
        &[0xff, 0x30],
        &[0x8f, 0],
        &[0x6a, 0],
        &[0x68, 0, 0, 0, 0],
        &[0x9c],
        &[0x9d],
        &[0x0f, 0xa0],
        &[0x0f, 0xa1],
        &[0xc3],
        &[0xe8, 0, 0, 0, 0],
        &[0xe2, 0],
        &[0xc7, 0xf8, 0, 0, 0, 0],
    ] {
        let decoded = decode64(0x1000, bytes);
        assert_eq!(decoded.error, DecoderError::None, "{bytes:x?}");
        assert_eq!(
            jump_or_register_stack(&decoded.instruction),
            None,
            "{bytes:x?}"
        );
    }
    // Selection retains these Code forms; existing consumers decide whether
    // a prefix is qualified. This is deliberately not a runtime admission test.
    for (bytes, class) in [
        (&[0x48, 0x54][..], JumpStackClass::PushRegister64),
        (&[0xf3, 0x5c][..], JumpStackClass::PopRegister64),
        (&[0x75, 0][..], JumpStackClass::Jump),
        (&[0xff, 0xe0][..], JumpStackClass::Jump),
    ] {
        let decoded = decode64(0x1000, bytes);
        assert_eq!(decoded.error, DecoderError::None);
        assert_eq!(jump_or_register_stack(&decoded.instruction), Some(class));
    }
}
