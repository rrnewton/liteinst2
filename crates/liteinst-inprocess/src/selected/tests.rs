//! Supplied-value controls only; these never execute a selected instruction.
use super::{
    SelectedDestination, SelectedKind, SelectedWidth, callbacks, decode_selected, metrics::Counters,
};
use liteinst2::trampoline::HookContext;

fn fields(c: &HookContext) -> [u64; 18] {
    [
        c.rax,
        c.rcx,
        c.rdx,
        c.rbx,
        c.stack_pointer,
        c.rbp,
        c.rsi,
        c.rdi,
        c.r8,
        c.r9,
        c.r10,
        c.r11,
        c.r12,
        c.r13,
        c.r14,
        c.r15,
        c.rflags,
        c.instruction_pointer,
    ]
}
fn seeded() -> HookContext {
    let mut c = HookContext::default();
    c.rax = 0x123456789abc0000;
    c.rcx = 0x123456789abc0001;
    c.rdx = 0x123456789abc0002;
    c.rbx = 0x123456789abc0003;
    c.stack_pointer = 0x123456789abc0004;
    c.rbp = 0x123456789abc0005;
    c.rsi = 0x123456789abc0006;
    c.rdi = 0x123456789abc0007;
    c.r8 = 0x123456789abc0008;
    c.r9 = 0x123456789abc0009;
    c.r10 = 0x123456789abc000a;
    c.r11 = 0x123456789abc000b;
    c.r12 = 0x123456789abc000c;
    c.r13 = 0x123456789abc000d;
    c.r14 = 0x123456789abc000e;
    c.r15 = 0x123456789abc000f;
    c.rflags = 0xed7;
    c.instruction_pointer = 0x1000;
    c
}
fn encoding(kind: SelectedKind, width: u8, destination: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    if kind == SelectedKind::Rdpid {
        bytes.push(0xf3);
    }
    if width == 16 {
        bytes.push(0x66);
    }
    let rex = 0x40 | if width == 64 { 8 } else { 0 } | if destination >= 8 { 1 } else { 0 };
    if rex != 0x40 {
        bytes.push(rex);
    }
    bytes.extend([
        0x0f,
        0xc7,
        if kind == SelectedKind::Rdrand {
            0xf0
        } else {
            0xf8
        } | (destination & 7),
    ]);
    bytes
}

#[test]
fn selected_all_decode_width_destination_and_rsp_refusal() {
    for kind in [SelectedKind::Rdrand, SelectedKind::Rdseed] {
        for (bits, width) in [
            (16, SelectedWidth::Bits16),
            (32, SelectedWidth::Bits32),
            (64, SelectedWidth::Bits64),
        ] {
            for destination in 0..16 {
                let bytes = encoding(kind, bits, destination);
                let result = decode_selected(kind, 0x1000, &bytes);
                if destination == 4 {
                    assert!(result.is_err());
                    continue;
                }
                let decoded = result.unwrap();
                assert_eq!(decoded.destination().unwrap() as u8, destination);
                assert_eq!(decoded.width(), Some(width));
                assert_eq!(decoded.bytes(), bytes);
                assert_eq!(decoded.logical_pc(), 0x1000);
                assert_eq!(decoded.next_pc(), 0x1000 + bytes.len() as u64);
                assert!(callbacks::for_instruction(&decoded).is_ok());
            }
        }
    }
    for destination in 0..16 {
        // RDPID without REX.W still has a full zero-extended long-mode result.
        let bytes = encoding(SelectedKind::Rdpid, 32, destination);
        let result = decode_selected(SelectedKind::Rdpid, 0x2000, &bytes);
        if destination == 4 {
            assert!(result.is_err());
            continue;
        }
        let decoded = result.unwrap();
        assert_eq!(decoded.destination().unwrap() as u8, destination);
        assert_eq!(decoded.width(), Some(SelectedWidth::Bits64));
        assert_eq!(decoded.bytes(), bytes);
        assert!(callbacks::for_instruction(&decoded).is_ok());
    }
    assert_eq!(
        decode_selected(SelectedKind::Rdtscp, 0x3000, &[0x0f, 0x01, 0xf9])
            .unwrap()
            .next_pc(),
        0x3003
    );
    assert_eq!(SelectedDestination::Rsp as u8, 4);
}

#[test]
fn selected_all_prefix_legality_and_exact_old_profile() {
    let before_operand = [0x48, 0x66, 0x0f, 0xc7, 0xf0];
    let after_operand = [0x66, 0x48, 0x0f, 0xc7, 0xf0];
    assert_eq!(
        decode_selected(SelectedKind::Rdrand, 1, &before_operand)
            .unwrap()
            .width(),
        Some(SelectedWidth::Bits16)
    );
    assert_eq!(
        decode_selected(SelectedKind::Rdrand, 1, &after_operand)
            .unwrap()
            .width(),
        Some(SelectedWidth::Bits64)
    );
    for bytes in [
        &[0xf0, 0x0f, 0xc7, 0xf0][..],
        &[0x0f, 0xc7, 0x30],
        &[0x0f, 0xc7],
        &[0xf3, 0x0f, 0xc7, 0xf8],
    ] {
        assert!(decode_selected(SelectedKind::Rdrand, 0x1000, bytes).is_err());
    }
    let mut overlong = vec![0x66; 13];
    overlong.extend([0x0f, 0xc7, 0xf0]);
    assert!(decode_selected(SelectedKind::Rdrand, 0x1000, &overlong).is_err());
    assert!(decode_selected(SelectedKind::Rdrand, u64::MAX - 1, &[0x0f, 0xc7, 0xf0]).is_err());
    for kind in [
        SelectedKind::Cpuid,
        SelectedKind::Rdtsc,
        SelectedKind::Syscall,
    ] {
        let bytes = kind.encoding().unwrap();
        assert_eq!(decode_selected(kind, 0x1000, bytes).unwrap().bytes(), bytes);
        let mut prefixed = vec![0x66];
        prefixed.extend(bytes);
        assert!(decode_selected(kind, 0x1000, &prefixed).is_err());
    }
}

#[test]
fn selected_all_supplied_outcomes_preserve_unaffected_state() {
    for destination in 0..16 {
        for (width, value) in [
            (SelectedWidth::Bits16, 0xbeef),
            (SelectedWidth::Bits32, 0xabcdef01),
            (SelectedWidth::Bits64, 0x87654321abcdef01),
        ] {
            for carry in [false, true] {
                let mut c = seeded();
                let before = fields(&c);
                let descriptor = c.saved_extended_state();
                let value = if carry { value } else { 0 };
                let applied = callbacks::apply_random(&mut c, destination, width, value, carry);
                if destination == 4 {
                    assert!(!applied);
                    assert_eq!(fields(&c), before);
                    continue;
                }
                assert!(applied);
                let mut expected = before;
                expected[destination as usize] = if width == SelectedWidth::Bits16 {
                    (before[destination as usize] & !0xffff) | value
                } else {
                    value
                };
                expected[16] = (before[16] & !0x8d5) | u64::from(carry);
                assert_eq!(fields(&c), expected);
                assert_eq!(c.saved_extended_state(), descriptor);
            }
        }
        let mut c = seeded();
        let before = fields(&c);
        let descriptor = c.saved_extended_state();
        let applied = callbacks::apply_rdpid(&mut c, destination, 0xfedcba98);
        let mut expected = before;
        if destination == 4 {
            assert!(!applied);
        } else {
            assert!(applied);
            expected[destination as usize] = 0xfedcba98;
        }
        assert_eq!(fields(&c), expected);
        assert_eq!(c.saved_extended_state(), descriptor);
    }
    for (width, value, carry) in [
        (SelectedWidth::Bits16, 0x10000, true),
        (SelectedWidth::Bits32, 0x100000000, true),
        (SelectedWidth::Bits64, 1, false),
    ] {
        let mut c = seeded();
        let before = fields(&c);
        assert!(!callbacks::apply_random(&mut c, 0, width, value, carry));
        assert_eq!(fields(&c), before);
    }
    let mut c = seeded();
    let mut expected = fields(&c);
    let descriptor = c.saved_extended_state();
    callbacks::apply_rdtscp(&mut c, 0x12345678, 0x87654321, 0xfedcba98);
    expected[0] = 0x12345678;
    expected[2] = 0x87654321;
    expected[1] = 0xfedcba98;
    assert_eq!(fields(&c), expected);
    assert_eq!(c.saved_extended_state(), descriptor);
}

#[test]
fn selected_all_counter_prefix_is_actual_and_never_reset() {
    let counters = Counters::new();
    assert_eq!(counters.snapshot().entered, 0);
    assert_eq!(counters.snapshot().first_logical_pc, None);
    assert!(!counters.complete(false));
    assert!(counters.enter(0));
    assert_eq!(counters.snapshot().first_logical_pc, Some(0));
    assert!(counters.complete(true));
    assert!(!counters.complete(false));
    assert!(counters.enter(0x1234));
    let interrupted = counters.snapshot();
    assert_eq!(interrupted.entered, 2);
    assert_eq!(interrupted.completed, 1);
    assert_eq!(interrupted.carry_clear, 1);
    assert_eq!(interrupted.first_logical_pc, Some(0));
    assert_eq!(interrupted.last_logical_pc, Some(0x1234));
    assert!(counters.complete(false));
    assert_eq!(counters.snapshot().completed, 2);
}
