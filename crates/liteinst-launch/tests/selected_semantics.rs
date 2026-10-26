#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use liteinst_launch::RegisterSnapshot;
use liteinst_launch::selected::{
    Gpr, InstructionFault, InstructionProvider, NativeProvider, OperandWidth, Operation,
    ProviderDecision, ScriptEntry, ScriptedProvider, SelectedArguments, SelectedInput,
    SelectedResult, SemanticsError, SyscallAbi, SyscallAliases, SyscallResult, SysenterConvention,
    decode,
};

const PC: u64 = 0x400100;
const RF: u64 = 0x10000;
const STATUS: u64 = 0x8d5; // OF|SF|ZF|AF|PF|CF.
const GPRS: [Gpr; 16] = [
    Gpr::Rax,
    Gpr::Rcx,
    Gpr::Rdx,
    Gpr::Rbx,
    Gpr::Rsp,
    Gpr::Rbp,
    Gpr::Rsi,
    Gpr::Rdi,
    Gpr::R8,
    Gpr::R9,
    Gpr::R10,
    Gpr::R11,
    Gpr::R12,
    Gpr::R13,
    Gpr::R14,
    Gpr::R15,
];

fn registers() -> RegisterSnapshot {
    RegisterSnapshot {
        rax: 0x1111_2222_3333_4444,
        rcx: 0x2222_3333_4444_5555,
        rdx: 0x3333_4444_5555_6666,
        rbx: 0x4444_5555_6666_7777,
        rsp: 0x5555_6666_7777_8888,
        rbp: 0x6666_7777_8888_9999,
        rsi: 0x7777_8888_9999_aaaa,
        rdi: 0x8888_9999_aaaa_bbbb,
        r8: 0x9999_aaaa_bbbb_cccc,
        r9: 0xaaaa_bbbb_cccc_dddd,
        r10: 0xbbbb_cccc_dddd_eeee,
        r11: 0xcccc_dddd_eeee_ffff,
        r12: 0xdddd_eeee_ffff_1111,
        r13: 0xeeee_ffff_1111_2222,
        r14: 0xffff_1111_2222_3333,
        r15: 0x1234_5678_9abc_def0,
        rip: PC,
        eflags: RF | STATUS | 0x400 | 0x202,
        cs: 0x33,
        ss: 0x2b,
        ds: 0x2b,
        es: 0x2b,
        fs: 0,
        gs: 0,
        fs_base: 0x60001000,
        gs_base: 0x60002000,
        orig_rax: u64::MAX,
    }
}

fn int80_input(bytes: &[u8], number: u64) -> SelectedInput {
    let mut aliases = SyscallAliases::new();
    aliases.declare(PC, SyscallAbi::LinuxI386Int80).unwrap();
    let mut before = registers();
    before.rax = number;
    before.eflags &= !RF;
    SelectedInput::new(decode(PC, bytes, &aliases).unwrap(), before).unwrap()
}

fn input(bytes: &[u8]) -> SelectedInput {
    SelectedInput::new(
        decode(PC, bytes, &SyscallAliases::new()).unwrap(),
        registers(),
    )
    .unwrap()
}

#[test]
fn int80_getid_script_preserves_every_other_register_flag_and_kernel_field() {
    for bytes in [&[0xcd, 0x80][..], &[0x66, 0xcd, 0x80], &[0x48, 0xcd, 0x80]] {
        for number in [20, 224] {
            let input = int80_input(bytes, 0xa1b2_c3d4_0000_0000 | number);
            for value in [1, 17, i32::MAX as u32] {
                let result = SelectedResult::Syscall(SyscallResult::LinuxI386Int80GetId { value });
                let completed = input.complete(result).unwrap();
                let mut expected = *input.registers();
                expected.rax = u64::from(value);
                expected.rip += bytes.len() as u64;
                assert_eq!(completed.before, *input.registers());
                assert_eq!(completed.after, expected);
                assert_eq!(input.native_result(&expected).unwrap(), result);
                assert_eq!(
                    input.validate_native_completion(&expected).unwrap(),
                    completed
                );
                let mut actual_kernel_metadata = expected;
                actual_kernel_metadata.orig_rax = number;
                assert_eq!(
                    input.validate_native_completion(&actual_kernel_metadata),
                    Err(SemanticsError::NativeStateMismatch)
                );
            }
        }
    }
}

#[test]
fn int80_getid_script_rejects_unqualified_numbers_flags_values_and_other_abis() {
    let result = SelectedResult::Syscall(SyscallResult::LinuxI386Int80GetId { value: 12 });
    for number in [0, 1, 2, 4, 11, 39, 186, u32::MAX as u64] {
        assert_eq!(
            int80_input(&[0xcd, 0x80], 0xa1b2_c3d4_0000_0000 | number).complete(result),
            Err(SemanticsError::UnsupportedScriptedSyscall)
        );
    }
    let good = int80_input(&[0xcd, 0x80], 20);
    for flags in [RF, 0x100, 0x40000, 0x4000, 0x3000] {
        let mut before = *good.registers();
        before.eflags |= flags;
        let changed = SelectedInput::new(good.instruction().clone(), before).unwrap();
        assert_eq!(
            changed.complete(result),
            Err(SemanticsError::UnqualifiedSyscallFlags)
        );
    }
    for value in [0, 1_u32 << 31, u32::MAX] {
        assert_eq!(
            good.complete(SelectedResult::Syscall(
                SyscallResult::LinuxI386Int80GetId { value }
            )),
            Err(SemanticsError::InvalidProcessIdentifier)
        );
    }
    assert_eq!(
        input(&[0x0f, 0x05]).complete(result),
        Err(SemanticsError::UnqualifiedSyscallCompletion)
    );
    let mut aliases = SyscallAliases::new();
    aliases
        .declare(
            PC,
            SyscallAbi::DeclaredSysenter(
                SysenterConvention::new(
                    1,
                    Gpr::Rax,
                    [Gpr::Rbx, Gpr::Rcx, Gpr::Rdx, Gpr::Rsi, Gpr::Rdi, Gpr::Rbp],
                    OperandWidth::Bits32,
                )
                .unwrap(),
            ),
        )
        .unwrap();
    let sysenter =
        SelectedInput::new(decode(PC, &[0x0f, 0x34], &aliases).unwrap(), registers()).unwrap();
    assert_eq!(
        sysenter.complete(result),
        Err(SemanticsError::UnqualifiedSyscallCompletion)
    );
    assert_eq!(
        good.complete(SelectedResult::Syscall(SyscallResult::LinuxX64GetId {
            value: 12
        })),
        Err(SemanticsError::UnqualifiedSyscallCompletion)
    );
}

#[test]
fn invalid_int80_completion_does_not_consume_a_matching_script_row() {
    let input = int80_input(&[0xcd, 0x80], 20);
    for result in [
        SyscallResult::LinuxI386Int80GetId { value: 0 },
        SyscallResult::LinuxX64GetId { value: 17 },
    ] {
        let mut provider = ScriptedProvider::new([ScriptEntry {
            input: input.clone(),
            decision: ProviderDecision::Complete(SelectedResult::Syscall(result)),
        }]);
        for _ in 0..2 {
            assert!(provider.decide(&input).is_err());
            assert_eq!(provider.consumed(), 0);
            assert_eq!(provider.remaining(), 1);
        }
    }
}

// Architectural encoding order, written independently of production Gpr helpers.
fn slot(registers: &mut RegisterSnapshot, index: usize) -> &mut u64 {
    match index {
        0 => &mut registers.rax,
        1 => &mut registers.rcx,
        2 => &mut registers.rdx,
        3 => &mut registers.rbx,
        4 => &mut registers.rsp,
        5 => &mut registers.rbp,
        6 => &mut registers.rsi,
        7 => &mut registers.rdi,
        8 => &mut registers.r8,
        9 => &mut registers.r9,
        10 => &mut registers.r10,
        11 => &mut registers.r11,
        12 => &mut registers.r12,
        13 => &mut registers.r13,
        14 => &mut registers.r14,
        15 => &mut registers.r15,
        _ => panic!("invalid test register index"),
    }
}

fn random_encoding(seed: bool, width: usize, index: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    if width == 16 {
        bytes.push(0x66);
    }
    let rex = 0x40 | if width == 64 { 8 } else { 0 } | if index >= 8 { 1 } else { 0 };
    if rex != 0x40 {
        bytes.push(rex);
    }
    bytes.extend_from_slice(&[
        0x0f,
        0xc7,
        (if seed { 0xf8 } else { 0xf0 }) + (index % 8) as u8,
    ]);
    bytes
}

#[test]
fn exact_decode_keeps_prefix_length_and_refuses_invalid_encodings() {
    for (bytes, operation) in [
        (&[0x0f, 0xa2][..], Operation::Cpuid),
        (&[0x0f, 0x31][..], Operation::Rdtsc),
        (&[0x0f, 0x01, 0xf9][..], Operation::Rdtscp),
        (
            &[0x0f, 0x05][..],
            Operation::Syscall {
                abi: SyscallAbi::LinuxX64,
            },
        ),
        (&[0x66, 0x0f, 0xa2][..], Operation::Cpuid),
    ] {
        let mut with_tail = bytes.to_vec();
        with_tail.push(0x90);
        let decoded = decode(PC, &with_tail, &SyscallAliases::new()).unwrap();
        assert_eq!(decoded.operation(), operation);
        assert_eq!(decoded.bytes(), bytes);
        assert_eq!(decoded.logical_pc(), PC);
        assert_eq!(decoded.next_pc(), PC + bytes.len() as u64);
    }
    for bytes in [
        &[][..],
        &[0x0f][..],
        &[0x0f, 0xc7][..],
        &[0xf0, 0x0f, 0xc7, 0xf0][..],
        &[0x66; 16][..],
    ] {
        assert_eq!(
            decode(PC, bytes, &SyscallAliases::new()),
            Err(SemanticsError::InvalidEncoding)
        );
    }
    for bytes in [&[0x90][..], &[0x0f, 0xc7, 0x30][..], &[0xcd, 0x81][..]] {
        assert!(matches!(
            decode(PC, bytes, &SyscallAliases::new()),
            Err(SemanticsError::NotSelected | SemanticsError::InvalidEncoding)
        ));
    }
    assert_eq!(
        decode(u64::MAX, &[0x0f, 0xa2], &SyscallAliases::new()),
        Err(SemanticsError::AddressOverflow)
    );
    let decoded = decode(PC, &[0x0f, 0xa2], &SyscallAliases::new()).unwrap();
    let mut changed = registers();
    changed.rip += 1;
    assert_eq!(
        SelectedInput::new(decoded.clone(), changed),
        Err(SemanticsError::ProgramCounterMismatch)
    );
    changed = registers();
    changed.cs = 0x23;
    assert_eq!(
        SelectedInput::new(decoded, changed),
        Err(SemanticsError::UnsupportedExecutionMode)
    );
}

#[test]
fn cpuid_input_width_and_all_four_outputs_are_exact() {
    let input = input(&[0x0f, 0xa2]);
    assert_eq!(
        input.arguments(),
        SelectedArguments::Cpuid {
            leaf: 0x3333_4444,
            subleaf: 0x4444_5555
        }
    );
    let completed = input
        .complete(SelectedResult::Cpuid {
            eax: 0x80000001,
            ebx: 0x12345678,
            ecx: 0,
            edx: u32::MAX,
        })
        .unwrap();
    let mut expected = registers();
    expected.rip = PC + 2;
    expected.eflags &= !RF;
    expected.rax = 0x80000001;
    expected.rbx = 0x12345678;
    expected.rcx = 0;
    expected.rdx = 0xffff_ffff;
    assert_eq!(completed.before, registers());
    assert_eq!(completed.after, expected);
    assert_eq!(
        input.validate_native_completion(&expected).unwrap(),
        completed
    );
}

#[test]
fn random_success_and_failure_cover_every_gpr_width_including_rsp() {
    for seed in [false, true] {
        for (bits, width, value) in [
            (16, OperandWidth::Bits16, 0xbccdu64),
            (32, OperandWidth::Bits32, 0xaabb_ccdd),
            (64, OperandWidth::Bits64, 0x0123_4567_89ab_cdef),
        ] {
            for (index, destination) in GPRS.into_iter().enumerate() {
                let bytes = random_encoding(seed, bits, index);
                let input = input(&bytes);
                assert_eq!(
                    input.instruction().operation(),
                    if seed {
                        Operation::Rdseed { destination, width }
                    } else {
                        Operation::Rdrand { destination, width }
                    }
                );
                assert_eq!(input.arguments(), SelectedArguments::None);
                for carry in [false, true] {
                    let value = if carry { value } else { 0 };
                    let result = if seed {
                        SelectedResult::Rdseed { value, carry }
                    } else {
                        SelectedResult::Rdrand { value, carry }
                    };
                    let completed = input.complete(result).unwrap();
                    let mut expected = registers();
                    expected.rip = PC + bytes.len() as u64;
                    expected.eflags = (expected.eflags & !(RF | STATUS)) | u64::from(carry);
                    let target = slot(&mut expected, index);
                    *target = if bits == 16 {
                        (*target & !0xffff) | value
                    } else {
                        value
                    };
                    assert_eq!(
                        completed.after, expected,
                        "seed={seed} bits={bits} reg={index} carry={carry}"
                    );
                    assert_eq!(
                        input.validate_native_completion(&expected).unwrap().after,
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn random_zero_success_is_distinct_from_failure_and_bad_values_refuse() {
    for seed in [false, true] {
        for bits in [16, 32, 64] {
            let input = input(&random_encoding(seed, bits, 4));
            let result = |value, carry| {
                if seed {
                    SelectedResult::Rdseed { value, carry }
                } else {
                    SelectedResult::Rdrand { value, carry }
                }
            };
            let success = input.complete(result(0, true)).unwrap();
            let failure = input.complete(result(0, false)).unwrap();
            assert_eq!(success.after.eflags, failure.after.eflags | 1);
            assert_eq!(success.after.rsp, failure.after.rsp);
            assert_eq!(
                input.complete(result(1, false)),
                Err(SemanticsError::NonzeroFailedRandom)
            );
            if bits < 64 {
                assert_eq!(
                    input.complete(result(1 << bits, true)),
                    Err(SemanticsError::ResultOutOfRange)
                );
            }
        }
    }
}

#[test]
fn long_mode_rdpid_zero_extends_aux_in_every_destination_without_rex_w() {
    for (index, destination) in GPRS.into_iter().enumerate() {
        let mut bytes = vec![0xf3];
        if index >= 8 {
            bytes.push(0x41);
        }
        bytes.extend_from_slice(&[0x0f, 0xc7, 0xf8 + (index % 8) as u8]);
        let input = input(&bytes);
        assert_eq!(
            input.instruction().operation(),
            Operation::Rdpid { destination }
        );
        let completed = input
            .complete(SelectedResult::Rdpid {
                auxiliary: 0xfedc_ba98,
            })
            .unwrap();
        let mut expected = registers();
        expected.rip += bytes.len() as u64;
        expected.eflags &= !RF;
        *slot(&mut expected, index) = 0xfedc_ba98;
        assert_eq!(completed.after, expected);
    }
}

#[test]
fn timestamp_halves_and_rdtscp_aux_are_independent_zero_extended_outputs() {
    for counter in [0, 1, 0x89ab_cdef_0123_4567, u64::MAX] {
        let rdtsc = input(&[0x0f, 0x31])
            .complete(SelectedResult::Rdtsc { counter })
            .unwrap();
        let mut expected = registers();
        expected.rip += 2;
        expected.eflags &= !RF;
        expected.rax = counter & 0xffff_ffff;
        expected.rdx = counter >> 32;
        assert_eq!(rdtsc.after, expected);
        let rdtscp = input(&[0x0f, 0x01, 0xf9])
            .complete(SelectedResult::Rdtscp {
                counter,
                auxiliary: 0xf123_4567,
            })
            .unwrap();
        expected.rip += 1;
        expected.rcx = 0xf123_4567;
        assert_eq!(rdtscp.after, expected);
    }
}

fn syscall_input(number: u64, flags: u64) -> SelectedInput {
    let mut registers = registers();
    registers.rax = number;
    registers.eflags = flags;
    SelectedInput::new(
        decode(PC, &[0x0f, 0x05], &SyscallAliases::new()).unwrap(),
        registers,
    )
    .unwrap()
}

#[test]
fn x64_getid_completion_preserves_full_state_and_defines_rcx_r11() {
    for number in [libc::SYS_getpid, libc::SYS_gettid] {
        let input = syscall_input(number as u64, 0x202 | STATUS | 0x400);
        let before = *input.registers();
        assert_eq!(
            input.arguments(),
            SelectedArguments::Syscall {
                abi: SyscallAbi::LinuxX64,
                number: number as u64,
                arguments: [
                    before.rdi, before.rsi, before.rdx, before.r10, before.r8, before.r9
                ]
            }
        );
        let completed = input
            .complete(SelectedResult::Syscall(SyscallResult::LinuxX64GetId {
                value: 12345,
            }))
            .unwrap();
        let mut expected = before;
        expected.rip += 2;
        expected.rax = 12345;
        expected.rcx = PC + 2;
        expected.r11 = before.eflags;
        assert_eq!(completed.after, expected);
        // Kernel bookkeeping is not silently discarded by exact validation.
        let mut exit_stop = expected;
        exit_stop.orig_rax = number as u64;
        assert_eq!(
            input.validate_native_completion(&exit_stop),
            Err(SemanticsError::NativeStateMismatch)
        );
        assert_eq!(
            input.validate_native_completion(&expected).unwrap(),
            completed
        );
    }
}

#[test]
fn scripted_syscalls_refuse_unmodeled_effects_flags_and_invalid_returns() {
    let result = SelectedResult::Syscall(SyscallResult::LinuxX64GetId { value: 12 });
    for number in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_mmap,
        libc::SYS_clone,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        assert_eq!(
            syscall_input(number as u64, 0x202).complete(result),
            Err(SemanticsError::UnsupportedScriptedSyscall)
        );
    }
    for flags in [
        0,
        2,
        0x200,
        0x302,
        0x202 | RF,
        0x202 | 0x40000,
        0x202 | 0x200000,
        0x202 | (1 << 63),
    ] {
        assert_eq!(
            syscall_input(libc::SYS_getpid as u64, flags).complete(result),
            Err(SemanticsError::UnqualifiedSyscallFlags)
        );
    }
    for value in [0, i32::MAX as u32 + 1, u32::MAX] {
        assert_eq!(
            syscall_input(libc::SYS_getpid as u64, 0x202).complete(SelectedResult::Syscall(
                SyscallResult::LinuxX64GetId { value }
            )),
            Err(SemanticsError::InvalidProcessIdentifier)
        );
    }
}

#[test]
fn alias_inputs_require_exact_declarations_and_never_borrow_x64_completion() {
    let mut aliases = SyscallAliases::new();
    assert_eq!(
        decode(PC, &[0xcd, 0x80], &aliases),
        Err(SemanticsError::UndeclaredAlias)
    );
    assert_eq!(
        decode(PC, &[0x0f, 0x34], &aliases),
        Err(SemanticsError::UndeclaredAlias)
    );
    aliases.declare(PC, SyscallAbi::LinuxI386Int80).unwrap();
    assert_eq!(
        aliases.declare(PC, SyscallAbi::LinuxI386Int80),
        Err(SemanticsError::DuplicateAlias)
    );
    for bytes in [&[0x0f, 0x34][..], &[0x0f, 0xa2][..], &[0x90][..]] {
        assert_eq!(
            decode(PC, bytes, &aliases),
            Err(SemanticsError::AliasClassMismatch)
        );
    }
    let input =
        SelectedInput::new(decode(PC, &[0xcd, 0x80], &aliases).unwrap(), registers()).unwrap();
    assert_eq!(
        input.arguments(),
        SelectedArguments::Syscall {
            abi: SyscallAbi::LinuxI386Int80,
            number: 0x3333_4444,
            arguments: [
                0x6666_7777,
                0x4444_5555,
                0x5555_6666,
                0x9999_aaaa,
                0xaaaa_bbbb,
                0x8888_9999
            ]
        }
    );
    assert_eq!(
        input.complete(SelectedResult::Syscall(SyscallResult::LinuxX64GetId {
            value: 3
        })),
        Err(SemanticsError::UnqualifiedSyscallCompletion)
    );
    let fault = input.fault(InstructionFault::InvalidOpcode);
    assert_eq!(fault.input, input);

    assert_eq!(
        SysenterConvention::new(0, Gpr::Rax, [Gpr::Rax; 6], OperandWidth::Bits32),
        Err(SemanticsError::InvalidAliasDeclaration)
    );
    let convention = SysenterConvention::new(
        9,
        Gpr::R10,
        [Gpr::R15, Gpr::R14, Gpr::R13, Gpr::R12, Gpr::Rsp, Gpr::Rax],
        OperandWidth::Bits32,
    )
    .unwrap();
    let mut aliases = SyscallAliases::new();
    aliases
        .declare(PC, SyscallAbi::DeclaredSysenter(convention))
        .unwrap();
    let input =
        SelectedInput::new(decode(PC, &[0x0f, 0x34], &aliases).unwrap(), registers()).unwrap();
    assert_eq!(
        input.arguments(),
        SelectedArguments::Syscall {
            abi: SyscallAbi::DeclaredSysenter(convention),
            number: 0xdddd_eeee,
            arguments: [
                0x9abc_def0,
                0x2222_3333,
                0x1111_2222,
                0xffff_1111,
                0x7777_8888,
                0x3333_4444
            ]
        }
    );
    assert_eq!(
        input.complete(SelectedResult::Syscall(SyscallResult::LinuxX64GetId {
            value: 3
        })),
        Err(SemanticsError::UnqualifiedSyscallCompletion)
    );
    assert_eq!(
        input
            .fault(InstructionFault::GeneralProtection { error_code: 0 })
            .input
            .registers(),
        &registers()
    );
}

#[test]
fn every_cross_class_result_mismatch_refuses_without_changing_inputs() {
    let inputs = [
        input(&[0x0f, 0xa2]),
        input(&[0x0f, 0xc7, 0xf0]),
        input(&[0x0f, 0xc7, 0xf8]),
        input(&[0xf3, 0x0f, 0xc7, 0xf8]),
        input(&[0x0f, 0x31]),
        input(&[0x0f, 0x01, 0xf9]),
        syscall_input(libc::SYS_getpid as u64, 0x202),
    ];
    let results = [
        SelectedResult::Cpuid {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
        SelectedResult::Rdrand {
            value: 1,
            carry: true,
        },
        SelectedResult::Rdseed {
            value: 1,
            carry: true,
        },
        SelectedResult::Rdpid { auxiliary: 1 },
        SelectedResult::Rdtsc { counter: 1 },
        SelectedResult::Rdtscp {
            counter: 1,
            auxiliary: 1,
        },
        SelectedResult::Syscall(SyscallResult::LinuxX64GetId { value: 1 }),
    ];
    for (class, input) in inputs.iter().enumerate() {
        let before = input.clone();
        for (result_class, result) in results.iter().enumerate() {
            if class == result_class {
                assert!(input.complete(*result).is_ok());
            } else {
                assert_eq!(
                    input.complete(*result),
                    Err(SemanticsError::ResultClassMismatch)
                );
            }
            assert_eq!(*input, before);
        }
    }
}

#[test]
fn native_validation_checks_upper_halves_flags_and_unaffected_registers() {
    let input = input(&[0x0f, 0xa2]);
    let completed = input
        .complete(SelectedResult::Cpuid {
            eax: 1,
            ebx: 2,
            ecx: 3,
            edx: 4,
        })
        .unwrap();
    for altered in 0..7 {
        let mut after = completed.after;
        match altered {
            0 => after.rax |= 1 << 32,
            1 => after.r10 ^= 1,
            2 => after.eflags ^= 1,
            3 => after.rsp += 16,
            4 => after.rip += 1,
            5 => after.fs_base ^= 1,
            _ => after.orig_rax ^= 1,
        }
        assert_eq!(
            input.validate_native_completion(&after),
            Err(SemanticsError::NativeStateMismatch)
        );
    }
    let input = input_for_random_validation();
    let completed = input
        .complete(SelectedResult::Rdrand {
            value: 7,
            carry: true,
        })
        .unwrap();
    for extra in [0x800, RF, 0x400] {
        let mut after = completed.after;
        after.eflags ^= extra;
        assert_eq!(
            input.validate_native_completion(&after),
            Err(SemanticsError::NativeStateMismatch)
        );
    }
}

fn input_for_random_validation() -> SelectedInput {
    input(&[0x0f, 0xc7, 0xf0])
}

#[test]
fn faults_do_not_complete_or_normalize_rf_outputs_pc_or_metadata() {
    for bytes in [
        &[0x0f, 0xa2][..],
        &[0x0f, 0xc7, 0xf8][..],
        &[0x0f, 0x05][..],
    ] {
        let input = input(bytes);
        for fault in [
            InstructionFault::InvalidOpcode,
            InstructionFault::GeneralProtection { error_code: 0 },
            InstructionFault::PageFault {
                address: 0xdeadbeef,
                error_code: 0x14,
            },
        ] {
            let faulted = input.fault(fault);
            assert_eq!(faulted.input.registers(), &registers());
            assert_eq!(faulted.input.instruction().logical_pc(), PC);
            assert_eq!(faulted.fault, fault);
        }
    }
}

#[test]
fn native_provider_only_requests_execution_and_script_consumption_is_exact() {
    let input = input(&[0x0f, 0xa2]);
    assert_eq!(
        NativeProvider.decide(&input).unwrap(),
        ProviderDecision::Native
    );
    let decision = ProviderDecision::Complete(SelectedResult::Cpuid {
        eax: 7,
        ebx: 0,
        ecx: 0,
        edx: 0,
    });
    let mut provider = ScriptedProvider::new([ScriptEntry {
        input: input.clone(),
        decision,
    }]);
    assert_eq!(provider.finish(), Err(SemanticsError::ScriptRemaining));
    let mut changed = *input.registers();
    changed.r10 ^= 1;
    let wrong_register = SelectedInput::new(input.instruction().clone(), changed).unwrap();
    assert_eq!(
        provider.decide(&wrong_register),
        Err(SemanticsError::ScriptMismatch)
    );
    let decoded = decode(PC + 1, &[0x0f, 0xa2], &SyscallAliases::new()).unwrap();
    changed = *input.registers();
    changed.rip += 1;
    let wrong_site = SelectedInput::new(decoded, changed).unwrap();
    assert_eq!(
        provider.decide(&wrong_site),
        Err(SemanticsError::ScriptMismatch)
    );
    assert_eq!((provider.consumed(), provider.remaining()), (0, 1));
    assert_eq!(provider.decide(&input).unwrap(), decision);
    assert_eq!((provider.consumed(), provider.remaining()), (1, 0));
    assert_eq!(
        provider.decide(&input),
        Err(SemanticsError::ScriptExhausted)
    );
    assert_eq!(provider.finish(), Ok(()));
}

#[test]
fn invalid_scripted_completions_refuse_without_consuming_or_skipping_a_row() {
    let get_id = SelectedResult::Syscall(SyscallResult::LinuxX64GetId { value: 17 });
    let mut aliases = SyscallAliases::new();
    aliases.declare(PC, SyscallAbi::LinuxI386Int80).unwrap();
    let alias_input =
        SelectedInput::new(decode(PC, &[0xcd, 0x80], &aliases).unwrap(), registers()).unwrap();
    for (input, result, refusal) in [
        (
            input(&[0x0f, 0xa2]),
            SelectedResult::Rdtsc { counter: 1 },
            SemanticsError::ResultClassMismatch,
        ),
        (
            input(&[0x66, 0x0f, 0xc7, 0xf4]),
            SelectedResult::Rdrand {
                value: 0x1_0000,
                carry: true,
            },
            SemanticsError::ResultOutOfRange,
        ),
        (
            input(&[0x0f, 0xc7, 0xfc]),
            SelectedResult::Rdseed {
                value: 1,
                carry: false,
            },
            SemanticsError::NonzeroFailedRandom,
        ),
        (
            syscall_input(libc::SYS_getpid as u64, 0x202 | RF),
            get_id,
            SemanticsError::UnqualifiedSyscallFlags,
        ),
        (
            syscall_input(libc::SYS_write as u64, 0x202),
            get_id,
            SemanticsError::UnsupportedScriptedSyscall,
        ),
        (
            syscall_input(libc::SYS_gettid as u64, 0x202),
            SelectedResult::Syscall(SyscallResult::LinuxX64GetId { value: 0 }),
            SemanticsError::InvalidProcessIdentifier,
        ),
        (
            alias_input,
            get_id,
            SemanticsError::UnqualifiedSyscallCompletion,
        ),
    ] {
        let unchanged = input.clone();
        let mut provider = ScriptedProvider::new([
            ScriptEntry {
                input: input.clone(),
                decision: ProviderDecision::Complete(result),
            },
            ScriptEntry {
                input: input.clone(),
                decision: ProviderDecision::Native,
            },
        ]);
        for _ in 0..2 {
            assert_eq!(provider.decide(&input), Err(refusal));
            assert_eq!((provider.consumed(), provider.remaining()), (0, 2));
            assert_eq!(provider.finish(), Err(SemanticsError::ScriptRemaining));
            assert_eq!(input, unchanged);
        }
    }
    // Requests and uncompleted faults have no successful-result transition to
    // validate; each still consumes its exact matching row once.
    let input = input(&[0x0f, 0xc7, 0xf0]);
    for decision in [
        ProviderDecision::Native,
        ProviderDecision::Fault(InstructionFault::InvalidOpcode),
    ] {
        let mut provider = ScriptedProvider::new([ScriptEntry {
            input: input.clone(),
            decision,
        }]);
        assert_eq!(provider.decide(&input), Ok(decision));
        assert_eq!((provider.consumed(), provider.remaining()), (1, 0));
        assert_eq!(
            provider.decide(&input),
            Err(SemanticsError::ScriptExhausted)
        );
        assert_eq!(provider.finish(), Ok(()));
    }
}
