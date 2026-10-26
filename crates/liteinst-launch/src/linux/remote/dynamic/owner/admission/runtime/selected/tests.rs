//! Synthetic adapter controls only, with no ptrace/native qualification.
use super::*;
fn registers(pc: u64) -> RegisterSnapshot {
    RegisterSnapshot {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        rbp: 11,
        rbx: 10,
        r11: 9,
        r10: 8,
        r9: 7,
        r8: 6,
        rax: 0xfeed_beef_0000_0005,
        rcx: 4,
        rdx: 3,
        rsi: 2,
        rdi: 1,
        orig_rax: u64::MAX,
        rip: pc,
        cs: 0x33,
        eflags: 0xad7,
        rsp: 0x700000,
        ss: 0x2b,
        fs_base: 0x900000,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

fn input(bytes: &[u8]) -> SelectedInput {
    SelectedInput::new(
        selected::decode(0x401000, bytes, &SyscallAliases::new()).unwrap(),
        registers(0x401000),
    )
    .unwrap()
}
#[test]
fn six_cpu_results_preserve_full_unrelated_state_and_exact_width() {
    let cases = [
        (
            &[0x0f, 0xa2][..],
            SelectedResult::Cpuid {
                eax: 1,
                ebx: 2,
                ecx: 3,
                edx: 4,
            },
            0,
        ),
        (
            &[0x0f, 0x31][..],
            SelectedResult::Rdtsc {
                counter: 0x1234_5678_9abc_def0,
            },
            1,
        ),
        (
            &[0x0f, 0x01, 0xf9][..],
            SelectedResult::Rdtscp {
                counter: 0x1234_5678_9abc_def0,
                auxiliary: 0xcafe,
            },
            2,
        ),
        (
            &[0x66, 0x0f, 0xc7, 0xf0][..],
            SelectedResult::Rdrand {
                value: 0x9876,
                carry: true,
            },
            3,
        ),
        (
            &[0x41, 0x0f, 0xc7, 0xf9][..],
            SelectedResult::Rdseed {
                value: 0x1234,
                carry: true,
            },
            4,
        ),
        (
            &[0xf3, 0x41, 0x0f, 0xc7, 0xfa][..],
            SelectedResult::Rdpid { auxiliary: 0x8765 },
            5,
        ),
    ];
    for (encoding, result, kind) in cases {
        let input = input(encoding);
        let before = *input.registers();
        let completed = model(&input, result).unwrap();
        let mut expected = before;
        expected.rip += encoding.len() as u64;
        match kind {
            0 => {
                expected.rax = 1;
                expected.rbx = 2;
                expected.rcx = 3;
                expected.rdx = 4;
            }
            1 => {
                expected.rax = 0x9abc_def0;
                expected.rdx = 0x1234_5678;
            }
            2 => {
                expected.rax = 0x9abc_def0;
                expected.rdx = 0x1234_5678;
                expected.rcx = 0xcafe;
            }
            3 => {
                expected.rax = 0xfeed_beef_0000_9876;
                expected.eflags = 0x203;
            }
            4 => {
                expected.r9 = 0x1234;
                expected.eflags = 0x203;
            }
            5 => {
                expected.r10 = 0x8765;
            }
            _ => unreachable!(),
        }
        assert_eq!(completed.before, before);
        assert_eq!(completed.after, expected);
        assert_eq!(completed.instruction.bytes(), encoding);
    }
}
#[test]
fn selected_semantic_failures_are_not_relabelled() {
    assert!(matches!(
        model(&input(&[0x0f, 0xa2]), SelectedResult::Rdtsc { counter: 1 }),
        Err(GateError::Selected(SemanticsError::ResultClassMismatch))
    ));
    assert!(matches!(
        model(
            &input(&[0x0f, 0xc7, 0xf0]),
            SelectedResult::Rdrand {
                value: 1,
                carry: false
            }
        ),
        Err(GateError::Selected(SemanticsError::NonzeroFailedRandom))
    ));
    assert!(matches!(
        model(
            &input(&[0x66, 0x0f, 0xc7, 0xf0]),
            SelectedResult::Rdrand {
                value: 0x1_0000,
                carry: true
            }
        ),
        Err(GateError::Selected(SemanticsError::ResultOutOfRange))
    ));
}
#[test]
fn valid_getpid_semantics_cannot_enter_cpu_only_transport() {
    let mut registers = registers(0x401000);
    registers.rax = libc::SYS_getpid as u64;
    let input = SelectedInput::new(
        selected::decode(registers.rip, &[0x0f, 0x05], &SyscallAliases::new()).unwrap(),
        registers,
    )
    .unwrap();
    let result =
        SelectedResult::Syscall(crate::selected::SyscallResult::LinuxX64GetId { value: 123 });
    assert!(input.complete(result).is_ok());
    assert!(matches!(
        model(&input, result),
        Err(GateError::Refused(
            "runtime selected syscall transport is not qualified"
        ))
    ));
}
#[test]
fn selected_control_flags_are_checked_without_masking() {
    for (flags, orig_rax) in [
        (0x302, u64::MAX),
        (0x10202, u64::MAX),
        (0x3202, u64::MAX),
        (0x200, u64::MAX),
        (0x202, 0),
    ] {
        let mut registers = registers(0x401000);
        registers.eflags = flags;
        registers.orig_rax = orig_rax;
        let input = SelectedInput::new(
            selected::decode(registers.rip, &[0x0f, 0xa2], &SyscallAliases::new()).unwrap(),
            registers,
        )
        .unwrap();
        assert!(matches!(
            model(
                &input,
                SelectedResult::Cpuid {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0
                }
            ),
            Err(GateError::Refused(
                "runtime selected native64 control flags differ"
            ))
        ));
        assert_eq!(*input.registers(), registers);
    }
}
#[test]
fn selected_reservation_retains_all_six_dimensions_and_bounded_shape() {
    let charge = budget(65536, 1).unwrap();
    assert_eq!(
        (
            charge.epochs,
            charge.reports,
            charge.origins,
            charge.witnesses,
            charge.plan_history
        ),
        (0, 0, 1, 1, 0)
    );
    assert!(charge.source_fact_bytes >= 12 * MAX_XSTATE + 3 * 65536);
    assert!(charge.source_fact_bytes < 64 * 1024 * 1024);
    for (window, growth) in [(0, 0), (65537, 0), (4096, 2), (usize::MAX, usize::MAX)] {
        assert!(matches!(
            budget(window, growth),
            Err(GateError::Refused(
                "runtime selected reservation geometry differs"
            ))
        ));
    }
}
