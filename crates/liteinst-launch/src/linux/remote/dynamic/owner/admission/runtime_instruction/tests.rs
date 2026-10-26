//! Literal decoder/model controls only. No task is launched or stepped, and
//! Absent debug state below is synthetic, never a native certificate.
use super::*;
use crate::selected::{Gpr, OperandWidth, Operation, SyscallAbi, SysenterConvention};
use iced_x86::{OpKind, Register};
use liteinst_admission::scan::{Boundary, SiteClass};
use liteinst_admission::{Generation, MappingId};

const BASE: u64 = 0x401000;

fn snapshot(base: u64, bytes: &[u8]) -> Snapshot {
    Snapshot::new(
        MappingId(17),
        Generation(9),
        base,
        bytes.to_vec(),
        Boundary::Unknown,
        Boundary::Unknown,
        WriteControl::Owned,
    )
    .unwrap()
}
fn registers(pc: u64) -> RegisterSnapshot {
    RegisterSnapshot {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        rbp: 0x801000,
        rbx: 0x802000,
        r11: 11,
        r10: 10,
        r9: 9,
        r8: 8,
        rax: 0x1122334455667788,
        rcx: 3,
        rdx: 2,
        rsi: 0x803000,
        rdi: 0x804000,
        orig_rax: u64::MAX,
        rip: pc,
        cs: 0x33,
        eflags: 0x202,
        rsp: 0x805000,
        ss: 0x2b,
        fs_base: 0x806000,
        gs_base: 0x807000,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}
fn ordinary(bytes: &[u8], code: Code, family: OrdinaryFamily) -> OrdinaryInstruction {
    let source = snapshot(BASE, bytes);
    let state = registers(BASE);
    let candidate = classify(
        &source,
        &state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    assert!(std::ptr::eq(candidate.snapshot(), &source));
    assert!(std::ptr::eq(candidate.registers(), &state));
    assert_eq!(candidate.debug(), DebugDisposition::Absent);
    assert_eq!(candidate.bytes(), bytes);
    assert_eq!(
        candidate.range(),
        AddressRange::from_len(BASE, bytes.len()).unwrap()
    );
    assert_eq!(candidate.next_pc(), BASE + bytes.len() as u64);
    let CandidateKind::Ordinary(value) = candidate.kind() else {
        panic!("ordinary case dispatched selected");
    };
    assert_eq!(value.decoded().code(), code);
    assert_eq!(value.family(), family);
    *value
}
fn refuses(bytes: &[u8], expected: InstructionRefusal) {
    let source = snapshot(BASE, bytes);
    assert_eq!(
        classify(
            &source,
            &registers(BASE),
            DebugDisposition::Absent,
            &SyscallAliases::new()
        )
        .unwrap_err(),
        expected
    );
}
fn unsupported(bytes: &[u8], code: Code) {
    refuses(bytes, InstructionRefusal::Unsupported(code));
}

#[test]
fn runtime_instruction_selected_classes_keep_existing_exact_dispatch() {
    let rows: &[(&[u8], SiteClass)] = &[
        (&[0x0f, 0xa2], SiteClass::Cpuid),
        (&[0x66, 0x0f, 0xc7, 0xf0], SiteClass::Rdrand),
        (&[0x48, 0x0f, 0xc7, 0xf8], SiteClass::Rdseed),
        (&[0xf3, 0x0f, 0xc7, 0xf8], SiteClass::Rdpid),
        (&[0x0f, 0x31], SiteClass::Rdtsc),
        (&[0x0f, 0x01, 0xf9], SiteClass::Rdtscp),
        (&[0x0f, 0x05], SiteClass::Syscall),
        (&[0x66, 0x0f, 0xa2], SiteClass::Cpuid),
    ];
    for (bytes, class) in rows {
        let source = snapshot(BASE, bytes);
        let state = registers(BASE);
        let aliases = SyscallAliases::new();
        let expected = selected::decode(BASE, bytes, &aliases).unwrap();
        let candidate = classify(&source, &state, DebugDisposition::Absent, &aliases).unwrap();
        assert_eq!(candidate.bytes(), *bytes);
        assert_eq!(candidate.next_pc(), BASE + bytes.len() as u64);
        assert_eq!(candidate.kind(), &CandidateKind::Selected(expected));
        let CandidateKind::Selected(value) = candidate.kind() else {
            unreachable!()
        };
        assert_eq!(value.operation().class(), *class);
    }
}

#[test]
fn runtime_instruction_alias_errors_never_fall_through_to_ordinary() {
    let sysenter = SyscallAbi::DeclaredSysenter(
        SysenterConvention::new(
            31,
            Gpr::Rax,
            [Gpr::Rbx, Gpr::Rcx, Gpr::Rdx, Gpr::Rsi, Gpr::Rdi, Gpr::Rbp],
            OperandWidth::Bits32,
        )
        .unwrap(),
    );
    for (bytes, abi, wrong) in [
        (&[0xcd, 0x80][..], SyscallAbi::LinuxI386Int80, sysenter),
        (&[0x0f, 0x34][..], sysenter, SyscallAbi::LinuxI386Int80),
    ] {
        let source = snapshot(BASE, bytes);
        let state = registers(BASE);
        let mut aliases = SyscallAliases::new();
        assert_eq!(
            classify(&source, &state, DebugDisposition::Absent, &aliases).unwrap_err(),
            InstructionRefusal::Selected(SemanticsError::UndeclaredAlias)
        );
        aliases.declare(BASE + 1, abi).unwrap();
        assert_eq!(
            classify(&source, &state, DebugDisposition::Absent, &aliases).unwrap_err(),
            InstructionRefusal::Selected(SemanticsError::UndeclaredAlias)
        );
        aliases.declare(BASE, abi).unwrap();
        let candidate = classify(&source, &state, DebugDisposition::Absent, &aliases).unwrap();
        let CandidateKind::Selected(value) = candidate.kind() else {
            panic!("alias became ordinary");
        };
        assert_eq!(value.operation(), Operation::Syscall { abi });
        let mut bad = SyscallAliases::new();
        bad.declare(BASE, wrong).unwrap();
        assert_eq!(
            classify(&source, &state, DebugDisposition::Absent, &bad).unwrap_err(),
            InstructionRefusal::Selected(SemanticsError::AliasClassMismatch)
        );
    }
    for bytes in [
        &[0x90][..],
        &[0x48, 0x89, 0xc0],
        &[0x0f, 0xa2],
        &[0x0f, 0x05],
    ] {
        let source = snapshot(BASE, bytes);
        let mut aliases = SyscallAliases::new();
        aliases.declare(BASE, SyscallAbi::LinuxI386Int80).unwrap();
        assert_eq!(
            classify(
                &source,
                &registers(BASE),
                DebugDisposition::Absent,
                &aliases
            )
            .unwrap_err(),
            InstructionRefusal::Selected(SemanticsError::AliasClassMismatch)
        );
    }
}

#[test]
fn runtime_instruction_selected_classification_is_not_state_release_permission() {
    let source = snapshot(BASE, &[0x0f, 0xa2]);
    for debug in [
        DebugDisposition::Unknown,
        DebugDisposition::Present,
        DebugDisposition::Absent,
    ] {
        for flags in [0x202 | TF, 0x202 | RF, 0x202 | TF | RF, 0, u64::MAX] {
            let state = RegisterSnapshot {
                eflags: flags,
                ..registers(BASE)
            };
            let candidate = classify(&source, &state, debug, &SyscallAliases::new()).unwrap();
            assert!(
                matches!(candidate.kind(), CandidateKind::Selected(value) if value.operation() == Operation::Cpuid)
            );
            assert_eq!(candidate.registers().eflags, flags);
            assert_eq!(candidate.debug(), debug);
        }
    }
    let wrong_mode = RegisterSnapshot {
        cs: 0x23,
        ..registers(BASE)
    };
    assert_eq!(
        classify(
            &source,
            &wrong_mode,
            DebugDisposition::Absent,
            &SyscallAliases::new()
        )
        .unwrap_err(),
        InstructionRefusal::UnsupportedMode
    );
}

#[test]
fn runtime_instruction_mov_width_and_high8_rex_boundary_remain_exact() {
    let rows: &[(&[u8], Code, Register, Register)] = &[
        (&[0x88, 0xe0], Code::Mov_rm8_r8, Register::AL, Register::AH),
        (
            &[0x40, 0x88, 0xe0],
            Code::Mov_rm8_r8,
            Register::AL,
            Register::SPL,
        ),
        (
            &[0x44, 0x88, 0xe0],
            Code::Mov_rm8_r8,
            Register::AL,
            Register::R12L,
        ),
        (
            &[0x66, 0x89, 0xe0],
            Code::Mov_rm16_r16,
            Register::AX,
            Register::SP,
        ),
        (
            &[0x89, 0xe0],
            Code::Mov_rm32_r32,
            Register::EAX,
            Register::ESP,
        ),
        (
            &[0x48, 0x89, 0xe0],
            Code::Mov_rm64_r64,
            Register::RAX,
            Register::RSP,
        ),
        (
            &[0x66, 0x48, 0x89, 0xe0],
            Code::Mov_rm64_r64,
            Register::RAX,
            Register::RSP,
        ),
        (
            &[0x48, 0x66, 0x89, 0xe0],
            Code::Mov_rm16_r16,
            Register::AX,
            Register::SP,
        ),
    ];
    for (bytes, code, destination, source) in rows {
        let value = ordinary(bytes, *code, OrdinaryFamily::Move);
        assert_eq!(value.decoded().op0_register(), *destination);
        assert_eq!(value.decoded().op1_register(), *source);
    }
    for (bytes, code, destination) in [
        (&[0xb4, 0x0f][..], Code::Mov_r8_imm8, Register::AH),
        (&[0x40, 0xb4, 0x0f][..], Code::Mov_r8_imm8, Register::SPL),
        (&[0x41, 0xb4, 0x0f][..], Code::Mov_r8_imm8, Register::R12L),
        (
            &[0x66, 0xb8, 0x34, 0x12][..],
            Code::Mov_r16_imm16,
            Register::AX,
        ),
        (&[0xb8, 1, 2, 3, 4][..], Code::Mov_r32_imm32, Register::EAX),
        (
            &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8][..],
            Code::Mov_r64_imm64,
            Register::RAX,
        ),
    ] {
        assert_eq!(
            ordinary(bytes, code, OrdinaryFamily::Move)
                .decoded()
                .op0_register(),
            destination
        );
    }
}

#[test]
fn runtime_instruction_memory_and_lea_keep_original_address_operands() {
    for (bytes, code, family) in [
        (
            &[0x48, 0x8b, 0x44, 0x8b, 0x10][..],
            Code::Mov_r64_rm64,
            OrdinaryFamily::Move,
        ),
        (
            &[0x48, 0x89, 0x44, 0x8b, 0x10][..],
            Code::Mov_rm64_r64,
            OrdinaryFamily::Move,
        ),
        (
            &[0x48, 0x8d, 0x44, 0x8b, 0x10][..],
            Code::Lea_r64_m,
            OrdinaryFamily::Address,
        ),
        (
            &[0x8d, 0x44, 0x8b, 0x10][..],
            Code::Lea_r32_m,
            OrdinaryFamily::Address,
        ),
        (
            &[0x66, 0x8d, 0x44, 0x8b, 0x10][..],
            Code::Lea_r16_m,
            OrdinaryFamily::Address,
        ),
    ] {
        let value = ordinary(bytes, code, family);
        assert_eq!(value.decoded().memory_base(), Register::RBX);
        assert_eq!(value.decoded().memory_index(), Register::RCX);
        assert_eq!(value.decoded().memory_index_scale(), 4);
        assert_eq!(value.decoded().memory_displacement64(), 16);
    }
    let addr32 = ordinary(
        &[0x67, 0x48, 0x8b, 0x03],
        Code::Mov_r64_rm64,
        OrdinaryFamily::Move,
    );
    assert_eq!(addr32.decoded().memory_base(), Register::EBX);
    let relative = ordinary(
        &[0x48, 0x8b, 0x05, 0x10, 0, 0, 0],
        Code::Mov_r64_rm64,
        OrdinaryFamily::Move,
    );
    assert_eq!(relative.decoded().memory_base(), Register::RIP);
    assert_eq!(relative.decoded().memory_displacement64(), BASE + 7 + 16);
    let absolute = ordinary(
        &[0x48, 0xa1, 0, 0x30, 0x80, 0, 0, 0, 0, 0],
        Code::Mov_RAX_moffs64,
        OrdinaryFamily::Move,
    );
    assert_eq!(absolute.decoded().memory_base(), Register::None);
    assert_eq!(absolute.decoded().memory_displacement64(), 0x803000);
    ordinary(
        &[0xc6, 0x03, 0x7f],
        Code::Mov_rm8_imm8,
        OrdinaryFamily::Move,
    );
    ordinary(
        &[0x66, 0xc7, 0x03, 0x34, 0x12],
        Code::Mov_rm16_imm16,
        OrdinaryFamily::Move,
    );
    ordinary(
        &[0xc7, 0x03, 1, 2, 3, 4],
        Code::Mov_rm32_imm32,
        OrdinaryFamily::Move,
    );
    ordinary(
        &[0x48, 0xc7, 0x03, 0xff, 0xff, 0xff, 0xff],
        Code::Mov_rm64_imm32,
        OrdinaryFamily::Move,
    );
}

#[test]
fn runtime_instruction_integer_and_compare_families_retain_flags_input() {
    let rows: &[(&[u8], Code, OrdinaryFamily)] = &[
        (
            &[0x48, 0x01, 0xd8],
            Code::Add_rm64_r64,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x48, 0x11, 0xd8],
            Code::Adc_rm64_r64,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x48, 0x29, 0xd8],
            Code::Sub_rm64_r64,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x48, 0x19, 0xd8],
            Code::Sbb_rm64_r64,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x48, 0x21, 0xd8],
            Code::And_rm64_r64,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x48, 0x09, 0xd8],
            Code::Or_rm64_r64,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x48, 0x31, 0xd8],
            Code::Xor_rm64_r64,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x48, 0x39, 0xd8],
            Code::Cmp_rm64_r64,
            OrdinaryFamily::Compare,
        ),
        (
            &[0x48, 0x85, 0xd8],
            Code::Test_rm64_r64,
            OrdinaryFamily::Compare,
        ),
        (&[0x04, 0x7f], Code::Add_AL_imm8, OrdinaryFamily::Arithmetic),
        (
            &[0x66, 0x05, 0x34, 0x12],
            Code::Add_AX_imm16,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x05, 1, 2, 3, 4],
            Code::Add_EAX_imm32,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x48, 0x05, 1, 2, 3, 4],
            Code::Add_RAX_imm32,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x48, 0x83, 0x03, 0xff],
            Code::Add_rm64_imm8,
            OrdinaryFamily::Arithmetic,
        ),
        (
            &[0x80, 0x3b, 0x7f],
            Code::Cmp_rm8_imm8,
            OrdinaryFamily::Compare,
        ),
        (
            &[0x48, 0xf7, 0x03, 1, 2, 3, 4],
            Code::Test_rm64_imm32,
            OrdinaryFamily::Compare,
        ),
    ];
    for (bytes, code, family) in rows {
        ordinary(bytes, *code, *family);
    }
    let source = snapshot(BASE, &[0x48, 0x11, 0xd8]);
    for flags in [0x202, 0x203, ORDINARY_FLAGS] {
        let state = RegisterSnapshot {
            eflags: flags,
            ..registers(BASE)
        };
        let before = state;
        let candidate = classify(
            &source,
            &state,
            DebugDisposition::Absent,
            &SyscallAliases::new(),
        )
        .unwrap();
        assert_eq!(*candidate.registers(), before);
        assert_eq!(state, before);
        // This is input retention, not a prediction of output flags or memory.
    }
}

#[test]
fn runtime_instruction_stack_nop_and_near_control_families_are_closed() {
    for (bytes, code, family, reg) in [
        (
            &[0x50][..],
            Code::Push_r64,
            OrdinaryFamily::Push,
            Register::RAX,
        ),
        (
            &[0x54][..],
            Code::Push_r64,
            OrdinaryFamily::Push,
            Register::RSP,
        ),
        (
            &[0x41, 0x50][..],
            Code::Push_r64,
            OrdinaryFamily::Push,
            Register::R8,
        ),
        (
            &[0x58][..],
            Code::Pop_r64,
            OrdinaryFamily::Pop,
            Register::RAX,
        ),
        (
            &[0x5c][..],
            Code::Pop_r64,
            OrdinaryFamily::Pop,
            Register::RSP,
        ),
        (
            &[0x41, 0x58][..],
            Code::Pop_r64,
            OrdinaryFamily::Pop,
            Register::R8,
        ),
    ] {
        assert_eq!(ordinary(bytes, code, family).decoded().op0_register(), reg);
    }
    for (bytes, code) in [
        (&[0x90][..], Code::Nopd),
        (&[0x66, 0x90][..], Code::Nopw),
        (&[0x48, 0x90][..], Code::Nopq),
        (&[0x0f, 0x1f, 0][..], Code::Nop_rm32),
        (&[0x66, 0x0f, 0x1f, 0][..], Code::Nop_rm16),
        (&[0x48, 0x0f, 0x1f, 0][..], Code::Nop_rm64),
    ] {
        ordinary(bytes, code, OrdinaryFamily::Nop);
    }
    assert_eq!(
        ordinary(&[0xeb, 0xfe], Code::Jmp_rel8_64, OrdinaryFamily::Jump).direct_target(),
        Some(BASE)
    );
    assert_eq!(
        ordinary(
            &[0xe9, 0xfb, 0xff, 0xff, 0xff],
            Code::Jmp_rel32_64,
            OrdinaryFamily::Jump
        )
        .direct_target(),
        Some(BASE)
    );
    assert_eq!(
        ordinary(
            &[0xe8, 0x10, 0, 0, 0],
            Code::Call_rel32_64,
            OrdinaryFamily::Call
        )
        .direct_target(),
        Some(BASE + 21)
    );
    assert_eq!(
        ordinary(&[0xc3], Code::Retnq, OrdinaryFamily::Return).direct_target(),
        None
    );
}

#[test]
fn runtime_instruction_every_near_condition_keeps_literal_relative_target() {
    let short = [
        Code::Jo_rel8_64,
        Code::Jno_rel8_64,
        Code::Jb_rel8_64,
        Code::Jae_rel8_64,
        Code::Je_rel8_64,
        Code::Jne_rel8_64,
        Code::Jbe_rel8_64,
        Code::Ja_rel8_64,
        Code::Js_rel8_64,
        Code::Jns_rel8_64,
        Code::Jp_rel8_64,
        Code::Jnp_rel8_64,
        Code::Jl_rel8_64,
        Code::Jge_rel8_64,
        Code::Jle_rel8_64,
        Code::Jg_rel8_64,
    ];
    let near = [
        Code::Jo_rel32_64,
        Code::Jno_rel32_64,
        Code::Jb_rel32_64,
        Code::Jae_rel32_64,
        Code::Je_rel32_64,
        Code::Jne_rel32_64,
        Code::Jbe_rel32_64,
        Code::Ja_rel32_64,
        Code::Js_rel32_64,
        Code::Jns_rel32_64,
        Code::Jp_rel32_64,
        Code::Jnp_rel32_64,
        Code::Jl_rel32_64,
        Code::Jge_rel32_64,
        Code::Jle_rel32_64,
        Code::Jg_rel32_64,
    ];
    for (condition, code) in short.into_iter().enumerate() {
        assert_eq!(
            ordinary(
                &[0x70 + condition as u8, 0x05],
                code,
                OrdinaryFamily::ConditionalBranch
            )
            .direct_target(),
            Some(BASE + 7)
        );
    }
    for (condition, code) in near.into_iter().enumerate() {
        assert_eq!(
            ordinary(
                &[0x0f, 0x80 + condition as u8, 0xfa, 0xff, 0xff, 0xff],
                code,
                OrdinaryFamily::ConditionalBranch
            )
            .direct_target(),
            Some(BASE)
        );
    }
}

#[test]
fn runtime_instruction_indirect_transfers_do_not_invent_destinations() {
    for (bytes, code, family, memory) in [
        (
            &[0xff, 0xd0][..],
            Code::Call_rm64,
            OrdinaryFamily::Call,
            false,
        ),
        (
            &[0xff, 0x13][..],
            Code::Call_rm64,
            OrdinaryFamily::Call,
            true,
        ),
        (
            &[0xff, 0xe0][..],
            Code::Jmp_rm64,
            OrdinaryFamily::Jump,
            false,
        ),
        (
            &[0xff, 0x23][..],
            Code::Jmp_rm64,
            OrdinaryFamily::Jump,
            true,
        ),
    ] {
        let value = ordinary(bytes, code, family);
        assert_eq!(value.direct_target(), None);
        assert_eq!(
            value.decoded().op0_kind(),
            if memory {
                OpKind::Memory
            } else {
                OpKind::Register
            }
        );
    }
    let source = snapshot(BASE, &[0xff, 0x13]);
    let state = registers(BASE);
    let candidate = classify(
        &source,
        &state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    assert_eq!(candidate.next_pc(), BASE + 2);
    assert_eq!(candidate.registers().rsp, 0x805000);
    assert_eq!(candidate.registers().rbx, 0x802000);
    // CALL word, actual target and return-boundary history remain native inputs.
}

#[test]
fn runtime_instruction_embedded_selected_and_alternate_pc_use_original_bytes() {
    let source = snapshot(BASE, &[0xb8, 0x0f, 0xa2, 0x90, 0x90, 0xc3]);
    let state = registers(BASE);
    let outer = classify(
        &source,
        &state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    assert!(
        matches!(outer.kind(), CandidateKind::Ordinary(value) if value.decoded().code() == Code::Mov_r32_imm32)
    );
    assert_eq!(outer.bytes(), &[0xb8, 0x0f, 0xa2, 0x90, 0x90]);
    let embedded_state = RegisterSnapshot {
        rip: BASE + 1,
        ..state
    };
    let embedded = classify(
        &source,
        &embedded_state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    assert!(
        matches!(embedded.kind(), CandidateKind::Selected(value) if value.operation() == Operation::Cpuid)
    );
    assert!(std::ptr::eq(outer.snapshot(), embedded.snapshot()));
    assert_eq!(embedded.bytes(), &[0x0f, 0xa2]);
    assert_eq!(embedded.next_pc(), BASE + 3);
    let prefixed = snapshot(BASE, &[0x66, 0x89, 0xe0]);
    let at_prefix = classify(
        &prefixed,
        &state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    let after_prefix = classify(
        &prefixed,
        &embedded_state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    assert!(
        matches!(at_prefix.kind(), CandidateKind::Ordinary(value) if value.decoded().code() == Code::Mov_rm16_r16)
    );
    assert!(
        matches!(after_prefix.kind(), CandidateKind::Ordinary(value) if value.decoded().code() == Code::Mov_rm32_r32)
    );
}

#[test]
fn runtime_instruction_candidate_keeps_full_snapshot_and_all_register_fields() {
    let source = snapshot(BASE - 2, &[0x0f, 0x05, 0x90, 0x0f, 0x31, 0xcc]);
    let before_source = source.clone();
    let state = registers(BASE);
    let before_state = state;
    let candidate = classify(
        &source,
        &state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    assert_eq!(candidate.snapshot(), &before_source);
    assert_eq!(candidate.registers(), &before_state);
    assert_eq!(
        candidate.snapshot().bytes(),
        &[0x0f, 0x05, 0x90, 0x0f, 0x31, 0xcc]
    );
    assert_eq!(
        candidate.snapshot().range(),
        AddressRange::new(BASE - 2, BASE + 4).unwrap()
    );
    assert_eq!(candidate.snapshot().mapping, MappingId(17));
    assert_eq!(candidate.snapshot().generation, Generation(9));
    assert_eq!(candidate.snapshot().before, Boundary::Unknown);
    assert_eq!(candidate.snapshot().after, Boundary::Unknown);
    assert_eq!(candidate.bytes(), &[0x90]);
    assert_eq!(source, before_source);
    assert_eq!(state, before_state);
    let mut other = source.clone();
    other.mapping = MappingId(18);
    let changed = classify(
        &other,
        &state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    assert_ne!(candidate, changed);
    // New owned descriptions can decode, but cannot silently equal old binding.
}

#[test]
fn runtime_instruction_complete_snapshot_closure_is_required_at_window_edges() {
    for bytes in [
        &[0x0f][..],
        &[0x48, 0xb8, 1, 2, 3],
        &[0xe8, 0, 0],
        &[0x66],
        &[0xf3, 0x0f, 0xc7],
    ] {
        refuses(
            bytes,
            InstructionRefusal::Selected(SemanticsError::InvalidEncoding),
        );
    }
    let left = snapshot(0x4fff, &[0x0f]);
    let right = snapshot(0x5000, &[0xa2]);
    assert_eq!(left.range().end(), right.range().start());
    assert_eq!(
        classify(
            &left,
            &registers(0x4fff),
            DebugDisposition::Absent,
            &SyscallAliases::new()
        )
        .unwrap_err(),
        InstructionRefusal::Selected(SemanticsError::InvalidEncoding)
    );
    let whole = snapshot(0x4fff, &[0x0f, 0xa2]);
    let state = registers(0x4fff);
    let candidate = classify(
        &whole,
        &state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    assert_eq!(candidate.next_pc(), 0x5001);
    assert!(
        matches!(candidate.kind(), CandidateKind::Selected(value) if value.operation() == Operation::Cpuid)
    );
    let mut maximum = vec![0x66; 14];
    maximum.push(0x90);
    ordinary(&maximum, Code::Nopw, OrdinaryFamily::Nop);
    let mut excessive = vec![0x66; 15];
    excessive.push(0x90);
    refuses(
        &excessive,
        InstructionRefusal::Selected(SemanticsError::InvalidEncoding),
    );
}

#[test]
fn runtime_instruction_source_and_relative_address_overflow_refuse() {
    let source = snapshot(BASE, &[0x90]);
    for pc in [BASE - 1, BASE + 1, u64::MAX] {
        assert_eq!(
            classify(
                &source,
                &registers(pc),
                DebugDisposition::Absent,
                &SyscallAliases::new()
            )
            .unwrap_err(),
            InstructionRefusal::ProgramCounterOutsideSnapshot
        );
    }
    assert!(
        Snapshot::new(
            MappingId(1),
            Generation(0),
            u64::MAX,
            vec![0x90],
            Boundary::Unknown,
            Boundary::Unknown,
            WriteControl::Owned
        )
        .is_none()
    );
    for (base, bytes) in [
        (0, &[0xeb, 0xfd][..]),
        (u64::MAX - 5, &[0xe9, 1, 0, 0, 0][..]),
        (u64::MAX - 5, &[0xe8, 1, 0, 0, 0][..]),
    ] {
        let source = snapshot(base, bytes);
        assert_eq!(
            classify(
                &source,
                &registers(base),
                DebugDisposition::Absent,
                &SyscallAliases::new()
            )
            .unwrap_err(),
            InstructionRefusal::AddressOverflow
        );
    }
    let source = snapshot(u64::MAX - 2, &[0xeb, 0xfe]);
    let state = registers(u64::MAX - 2);
    let result = classify(
        &source,
        &state,
        DebugDisposition::Absent,
        &SyscallAliases::new(),
    )
    .unwrap();
    let CandidateKind::Ordinary(value) = result.kind() else {
        unreachable!()
    };
    assert_eq!(value.direct_target(), Some(u64::MAX - 2));
}

#[test]
fn runtime_instruction_ordinary_state_and_writer_profile_is_exact() {
    let source = snapshot(BASE, &[0x90]);
    let aliases = SyscallAliases::new();
    for (flags, expected) in [
        (0x202 | TF, InstructionRefusal::TrapFlag),
        (0x202 | RF, InstructionRefusal::ResumeFlag),
        (0, InstructionRefusal::UnsupportedFlags),
    ] {
        assert_eq!(
            classify(
                &source,
                &RegisterSnapshot {
                    eflags: flags,
                    ..registers(BASE)
                },
                DebugDisposition::Absent,
                &aliases
            )
            .unwrap_err(),
            expected
        );
    }
    for bit in 0..64 {
        let mask = 1_u64 << bit;
        if mask & (ORDINARY_FLAGS | TF | RF) == 0 {
            assert_eq!(
                classify(
                    &source,
                    &RegisterSnapshot {
                        eflags: 0x202 | mask,
                        ..registers(BASE)
                    },
                    DebugDisposition::Absent,
                    &aliases
                )
                .unwrap_err(),
                InstructionRefusal::UnsupportedFlags
            );
        }
    }
    for debug in [DebugDisposition::Unknown, DebugDisposition::Present] {
        assert_eq!(
            classify(&source, &registers(BASE), debug, &aliases).unwrap_err(),
            InstructionRefusal::DebugStateUnproven
        );
    }
    for cs in [0, 0x23, 0x10, 0x1_0033] {
        assert_eq!(
            classify(
                &source,
                &RegisterSnapshot {
                    cs,
                    ..registers(BASE)
                },
                DebugDisposition::Absent,
                &aliases
            )
            .unwrap_err(),
            InstructionRefusal::UnsupportedMode
        );
    }
    for writes in [WriteControl::UnownedAlias, WriteControl::ExternalWriter] {
        let mut changed = source.clone();
        changed.writes = writes;
        assert_eq!(
            classify(
                &changed,
                &registers(BASE),
                DebugDisposition::Absent,
                &aliases
            )
            .unwrap_err(),
            InstructionRefusal::UncontrolledWrites
        );
    }
}

#[test]
fn runtime_instruction_hidden_prefix_and_notrack_hazards_refuse() {
    for bytes in [
        &[0xf0, 0x48, 0x01, 0x03][..],
        &[0xf2, 0xf0, 0x48, 0x01, 0x03][..],
        &[0xf3, 0xf0, 0x48, 0x01, 0x03][..],
        &[0xf3, 0x48, 0x89, 0x03][..],
        &[0x66, 0xf3, 0x48, 0x89, 0x03][..],
        &[0x3e, 0xff, 0xe0][..],
        &[0x66, 0x3e, 0xff, 0xd0][..],
        &[0x64, 0x48, 0x8b, 0x03][..],
        &[0x65, 0x48, 0x8b, 0x03][..],
        &[0x2e, 0x90][..],
        &[0x36, 0x90][..],
        &[0x26, 0x90][..],
        &[0xf3, 0x90][..],
        &[0xf3, 0x0f, 0x1e, 0xfa][..],
    ] {
        refuses(bytes, InstructionRefusal::UnsupportedPrefix);
    }
}

#[test]
fn runtime_instruction_flags_inhibition_and_exception_codes_never_become_ordinary() {
    for (bytes, code) in [
        (&[0x9c][..], Code::Pushfq),
        (&[0x66, 0x9c][..], Code::Pushfw),
        (&[0x9d][..], Code::Popfq),
        (&[0x66, 0x9d][..], Code::Popfw),
        (&[0x9e][..], Code::Sahf),
        (&[0x9f][..], Code::Lahf),
        (&[0x48, 0xcf][..], Code::Iretq),
        (&[0xfa][..], Code::Cli),
        (&[0xfb][..], Code::Sti),
        (&[0x48, 0x8e, 0xd0][..], Code::Mov_Sreg_r64m16),
        (&[0x48, 0x0f, 0xb2, 0x03][..], Code::Lss_r64_m1664),
        (&[0x0f, 0x21, 0xc0][..], Code::Mov_r64_dr),
        (&[0x0f, 0x23, 0xc0][..], Code::Mov_dr_r64),
        (&[0x0f, 0x20, 0xc0][..], Code::Mov_r64_cr),
        (&[0x0f, 0x22, 0xc0][..], Code::Mov_cr_r64),
        (&[0xcc][..], Code::Int3),
        (&[0xf1][..], Code::Int1),
        (&[0xcd, 0x81][..], Code::Int_imm8),
        (&[0x0f, 0x0b][..], Code::Ud2),
        (&[0xf4][..], Code::Hlt),
        (&[0x48, 0x0f, 0x07][..], Code::Sysretq),
        (&[0x48, 0x0f, 0x35][..], Code::Sysexitq),
    ] {
        unsupported(bytes, code);
    }
    for bytes in [&[0x17][..], &[0x66, 0x17], &[0x06], &[0x60], &[0x61]] {
        refuses(
            bytes,
            InstructionRefusal::Selected(SemanticsError::InvalidEncoding),
        );
    }
}

#[test]
fn runtime_instruction_strings_transactions_and_architectural_system_state_refuse() {
    for (bytes, code) in [
        (&[0xa4][..], Code::Movsb_m8_m8),
        (&[0x48, 0xa5][..], Code::Movsq_m64_m64),
        (&[0xa6][..], Code::Cmpsb_m8_m8),
        (&[0xaa][..], Code::Stosb_m8_AL),
        (&[0xac][..], Code::Lodsb_AL_m8),
        (&[0xae][..], Code::Scasb_AL_m8),
        (&[0x6c][..], Code::Insb_m8_DX),
        (&[0x6e][..], Code::Outsb_DX_m8),
        (&[0xc7, 0xf8, 0, 0, 0, 0][..], Code::Xbegin_rel32),
        (&[0xc6, 0xf8, 1][..], Code::Xabort_imm8),
        (&[0x0f, 0x01, 0xd5][..], Code::Xend),
        (&[0x0f, 0x01, 0xd6][..], Code::Xtest),
        (&[0x0f, 0x01, 0xee][..], Code::Rdpkru),
        (&[0x0f, 0x01, 0xef][..], Code::Wrpkru),
        (&[0x0f, 0xae, 0x2b][..], Code::Xrstor_mem),
        (&[0x0f, 0xae, 0x0b][..], Code::Fxrstor_m512byte),
        (&[0x0f, 0x30][..], Code::Wrmsr),
        (&[0x0f, 0x32][..], Code::Rdmsr),
        (&[0x0f, 0x01, 0xf8][..], Code::Swapgs),
        (&[0x0f, 0x01, 0xc1][..], Code::Vmcall),
    ] {
        unsupported(bytes, code);
    }
    for bytes in [
        &[0xf3, 0xa4][..],
        &[0xf2, 0xa6],
        &[0x67, 0xf3, 0x48, 0xa5],
        &[0xf3, 0x48, 0x0f, 0xae, 0xd0],
    ] {
        refuses(bytes, InstructionRefusal::UnsupportedPrefix);
    }
}

#[test]
fn runtime_instruction_unlisted_alternate_ordinary_forms_stay_unsupported() {
    for (bytes, code) in [
        (&[0x48, 0x87, 0x03][..], Code::Xchg_rm64_r64),
        (&[0x48, 0x87, 0xc3][..], Code::Xchg_rm64_r64),
        (&[0x66, 0x50][..], Code::Push_r16),
        (&[0xff, 0x33][..], Code::Push_rm64),
        (&[0x8f, 0xc0][..], Code::Pop_rm64),
        (&[0xc2, 8, 0][..], Code::Retnq_imm16),
        (&[0x48, 0xcb][..], Code::Retfq),
        (&[0x48, 0xff, 0x2b][..], Code::Jmp_m1664),
        (&[0x48, 0xff, 0x1b][..], Code::Call_m1664),
        (&[0x48, 0xd1, 0xe0][..], Code::Shl_rm64_1),
        (&[0x48, 0x0f, 0x44, 0xc3][..], Code::Cmove_r64_rm64),
        (&[0x48, 0x0f, 0xbe, 0xc3][..], Code::Movsx_r64_rm8),
        (&[0x66, 0x0f, 0xef, 0xc0][..], Code::Pxor_xmm_xmmm128),
        (&[0xc8, 0, 0, 0][..], Code::Enterq_imm16_imm8),
        (&[0xc9][..], Code::Leaveq),
    ] {
        unsupported(bytes, code);
    }
}
