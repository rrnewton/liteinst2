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
