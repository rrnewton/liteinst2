//! Comparator-only synthetic control records. No native permission/completion
//! is constructed or exercised by these fixtures.
use super::*;
fn stop() -> AdmissionStop {
    let registry = crate::lifecycle::LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 1,
            processes: 1,
            address_spaces: 1,
            obligations: 1,
        },
        42,
        0x401000,
    )
    .unwrap();
    let task = registry.root_task();
    let row = registry.task(task).unwrap();
    AdmissionStop {
        token: DynamicStop {
            session: 7,
            tid: 42,
            task: Some(task),
            sequence: 17,
        },
        identity: DynamicTask {
            task,
            process: row.process,
            address_space: row.address_space,
            generation: 0,
        },
        phase: AdmissionPhase::Restored,
        signal: None,
    }
}
fn model_profile(dr6: u64) -> ControlProfile {
    let mut value = ControlProfile {
        complete: true,
        tid: Some(42),
        rseq_request: Some(Request {
            result: 24,
            errno: None,
        }),
        ..ControlProfile::default()
    };
    value.cet.complete = true; // synthetic certificate predicate, never a query claim
    value.debug.values = [0, 0, 0, 0, dr6, 0];
    value.debug.requests = std::array::from_fn(|index| {
        Some(Request {
            result: value.debug.values[index] as i64,
            errno: None,
        })
    });
    value
}
fn invalid<T>(value: Result<T, LaunchError>, reason: &'static str) {
    assert!(matches!(value, Err(LaunchError::Invalid(actual)) if actual == reason));
}
#[test]
fn owned_native_lineage_never_accepts_an_unrelated_or_refreshed_checkpoint() {
    let stop = stop();
    let lineage = ControlLineage {
        checkpoint: stop.clone(),
        dr6: DR_BASE,
        kernel: None,
    };
    lineage
        .authenticate(&stop, &model_profile(DR_BASE))
        .unwrap();
    for field in 0..6 {
        let mut changed = stop.clone();
        match field {
            0 => changed.token.sequence += 1,
            1 => changed.token.tid += 1,
            2 => changed.token.session += 1,
            3 => changed.token.task = None,
            4 => changed.identity.generation += 1,
            _ => changed.phase = AdmissionPhase::NativeCompleted,
        }
        invalid(
            lineage.authenticate(&changed, &model_profile(DR_BASE)),
            "owned instruction control lineage is stale",
        );
    }
    invalid(
        lineage.authenticate(&stop, &model_profile(DR_TRACE)),
        "owned instruction debug profile differs",
    );
    let mut foreign = model_profile(DR_BASE);
    foreign.tid = Some(43);
    invalid(
        lineage.authenticate(&stop, &foreign),
        "owned instruction control lineage is stale",
    );
    let prior_step = ControlLineage {
        checkpoint: stop.clone(),
        dr6: DR_TRACE,
        kernel: None,
    };
    prior_step
        .authenticate(&stop, &model_profile(DR_TRACE))
        .unwrap();
    invalid(
        prior_step.authenticate(&stop, &model_profile(DR_BASE)),
        "owned instruction debug profile differs",
    );
}
#[test]
fn owned_native_profile_requires_all_rseq_bytes_exact_count_and_cet_completion() {
    for index in 0..24 {
        let mut changed = model_profile(DR_BASE);
        changed.rseq[index] = 1;
        invalid(
            changed.require(DR_BASE),
            "owned instruction control profile incomplete",
        );
    }
    for result in [0, 1, 23, 25, -1] {
        let mut changed = model_profile(DR_BASE);
        changed.rseq_request = Some(Request {
            result,
            errno: None,
        });
        invalid(
            changed.require(DR_BASE),
            "owned instruction control profile incomplete",
        );
    }
    let mut changed = model_profile(DR_BASE);
    changed.rseq_request = Some(Request {
        result: -1,
        errno: Some(libc::EINVAL),
    });
    invalid(
        changed.require(DR_BASE),
        "owned instruction control profile incomplete",
    );
    let mut changed = model_profile(DR_BASE);
    changed.cet.complete = false;
    invalid(
        changed.require(DR_BASE),
        "owned instruction control profile incomplete",
    );
    let mut changed = model_profile(DR_BASE);
    changed.complete = false;
    invalid(
        changed.require(DR_BASE),
        "owned instruction control profile incomplete",
    );
}

// New predicate-only fixtures. No native return/ordinary/selected seal exists
// here; private structural rows exercise refusals, not a source of authority.
fn kernel_lineage(number: u64) -> ControlLineage {
    let checkpoint = stop();
    ControlLineage {
        checkpoint: checkpoint.clone(),
        dr6: DR_BASE,
        kernel: Some(KernelControlOrigin {
            attempt: KernelAttemptId {
                session: checkpoint.token.session,
                invocation: 9,
            },
            returned: checkpoint,
            number,
        }),
    }
}
fn control_state(number: u64) -> TaskStateSnapshot {
    let mut registers: RegisterSnapshot =
        unsafe { std::mem::zeroed::<libc::user_regs_struct>() }.into();
    registers.rip = 0x401000;
    registers.rsp = 0x800000;
    registers.cs = 0x33;
    registers.ss = 0x2b;
    registers.eflags = 0x202;
    registers.orig_rax = number;
    TaskStateSnapshot {
        registers,
        xstate: vec![0x5a; 832],
        mask: 0x200,
    }
}
fn synthetic_signal(
    stop: &AdmissionStop,
) -> crate::linux::remote::dynamic::owner::trusted::OwnedSignal {
    crate::linux::remote::dynamic::owner::trusted::OwnedSignal {
        raw: [0; 128],
        view: crate::SignalStop {
            signal: libc::SIGUSR1,
            code: libc::SI_USER,
            address: None,
            instruction_pointer: 0x401000,
            pid: stop.token.tid,
            sequence: stop.token.sequence,
        },
    }
}
#[test]
fn kernel_control_requires_exact_current_checkpoint_and_original_return_identity() {
    let number = libc::SYS_getpid as u64;
    let lineage = kernel_lineage(number);
    lineage
        .require_orig_rax(&lineage.checkpoint, number)
        .unwrap();
    for field in 0..7 {
        let mut changed = lineage.checkpoint.clone();
        match field {
            0 => changed.token.sequence += 1,
            1 => changed.token.session += 1,
            2 => changed.token.tid += 1,
            3 => changed.token.task = None,
            4 => changed.identity.generation += 1,
            5 => changed.phase = AdmissionPhase::EntryReady,
            _ => changed.signal = Some(synthetic_signal(&changed)),
        }
        invalid(
            lineage.require_orig_rax(&changed, number),
            "owned instruction control lineage is stale",
        );
    }
    for field in 0..10 {
        let mut changed = kernel_lineage(number);
        let origin = changed.kernel.as_mut().unwrap();
        match field {
            0 => origin.attempt.session += 1,
            1 => origin.attempt.invocation = 0,
            2 => origin.returned.token.sequence += 1,
            3 => origin.returned.token.tid += 1,
            4 => origin.returned.token.session += 1,
            5 => origin.returned.token.task = None,
            6 => origin.returned.identity.generation += 1,
            7 => origin.returned.phase = AdmissionPhase::NativeCompleted,
            8 => origin.returned.signal = Some(synthetic_signal(&origin.returned)),
            _ => origin.number = libc::SYS_exit as u64,
        }
        invalid(
            changed.require_orig_rax(&changed.checkpoint, number),
            "owned instruction kernel control provenance differs",
        );
    }
}
#[test]
fn kernel_control_does_not_allow_a_bare_number_or_normalized_max() {
    for number in [libc::SYS_getpid as u64, libc::SYS_gettid as u64] {
        let lineage = kernel_lineage(number);
        for other in [u64::MAX, 0, libc::SYS_exit_group as u64, number ^ 1] {
            invalid(
                lineage.require_orig_rax(&lineage.checkpoint, other),
                "owned instruction inherited orig_rax differs",
            );
        }
        let absent = ControlLineage {
            checkpoint: lineage.checkpoint.clone(),
            dr6: DR_BASE,
            kernel: None,
        };
        invalid(
            absent.require_orig_rax(&absent.checkpoint, number),
            "owned instruction inherited orig_rax differs",
        );
        absent
            .require_orig_rax(&absent.checkpoint, u64::MAX)
            .unwrap();
        invalid(
            runner::require_state(&control_state(number)),
            "owned instruction native state profile differs",
        );
        runner::require_lineage_state(&lineage, &lineage.checkpoint, &control_state(number))
            .unwrap();
    }
}
#[test]
fn kernel_control_keeps_every_original_native_state_gate() {
    let number = libc::SYS_gettid as u64;
    let lineage = kernel_lineage(number);
    for field in 0..8 {
        let mut changed = control_state(number);
        match field {
            0 => changed.registers.cs = 0x23,
            1 => changed.registers.eflags |= 0x100,
            2 => changed.registers.eflags |= 0x10000,
            3 => changed.registers.eflags &= !2,
            4 => changed.xstate.clear(),
            5 => changed.xstate.truncate(511),
            6 => changed.xstate.resize(MAX_XSTATE, 0),
            _ => changed.xstate.resize(MAX_XSTATE + 1, 0),
        }
        invalid(
            runner::require_lineage_state(&lineage, &lineage.checkpoint, &changed),
            "owned instruction native state profile differs",
        );
    }
}
#[test]
fn kernel_control_ordinary_trace_requires_max_and_preserves_other_controls() {
    let number = libc::SYS_getpid as u64;
    let lineage = kernel_lineage(number);
    let before = control_state(number);
    let mut after = before.clone();
    after.registers.orig_rax = u64::MAX;
    after.registers.rax = 0x1234;
    after.registers.rip += 3;
    after.registers.eflags ^= 1 | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    runner::control_after_step(&lineage, &lineage.checkpoint, &before, &after).unwrap();
    invalid(
        runner::control_unchanged(&before, &after),
        "owned ordinary changed non-arithmetic control state",
    );
    for value in [number, libc::SYS_gettid as u64, 0] {
        let mut changed = after.clone();
        changed.registers.orig_rax = value;
        invalid(
            runner::control_after_step(&lineage, &lineage.checkpoint, &before, &changed),
            "owned instruction native state profile differs",
        );
    }
    for field in 0..10 {
        let mut changed = after.clone();
        match field {
            0 => changed.registers.ss ^= 1,
            1 => changed.registers.ds ^= 1,
            2 => changed.registers.es ^= 1,
            3 => changed.registers.fs ^= 1,
            4 => changed.registers.gs ^= 1,
            5 => changed.registers.fs_base ^= 1,
            6 => changed.registers.gs_base ^= 1,
            7 => changed.registers.eflags ^= 0x400,
            8 => changed.mask ^= 1,
            _ => changed.xstate[17] ^= 1,
        }
        invalid(
            runner::control_after_step(&lineage, &lineage.checkpoint, &before, &changed),
            "owned ordinary changed non-arithmetic control state",
        );
    }
}
#[test]
fn kernel_control_selected_checks_both_actual_orig_values() {
    for number in [libc::SYS_getpid as u64, libc::SYS_gettid as u64] {
        let lineage = kernel_lineage(number);
        lineage
            .selected_orig_rax(&lineage.checkpoint, number, number)
            .unwrap();
        for other in [0, u64::MAX, number ^ 1] {
            invalid(
                lineage.selected_orig_rax(&lineage.checkpoint, other, other),
                "owned instruction inherited orig_rax differs",
            );
            invalid(
                lineage.selected_orig_rax(&lineage.checkpoint, number, other),
                "selected native orig_rax was not preserved",
            );
        }
        let mut later = lineage.checkpoint.clone();
        later.token.sequence += 1;
        invalid(
            lineage.selected_orig_rax(&later, number, number),
            "owned instruction control lineage is stale",
        );
    }
}
#[test]
fn kernel_control_selected_six_cpu_models_preserve_full_inherited_state() {
    use super::super::super::runtime::selected::model_with_lineage;
    use crate::selected::{SelectedInput, SelectedResult, SyscallAliases};
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
    for number in [libc::SYS_getpid as u64, libc::SYS_gettid as u64] {
        let lineage = kernel_lineage(number);
        for (encoding, result, family) in cases {
            let mut registers = control_state(number).registers;
            registers.rax = 0xfeed_beef_0000_0005;
            let input = SelectedInput::new(
                crate::selected::decode(registers.rip, encoding, &SyscallAliases::new()).unwrap(),
                registers,
            )
            .unwrap();
            let mut expected = registers;
            expected.rip += encoding.len() as u64;
            match family {
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
                5 => expected.r10 = 0x8765,
                _ => unreachable!(),
            }
            let actual = model_with_lineage(&input, result, &lineage, &lineage.checkpoint).unwrap();
            assert_eq!(actual.before, registers);
            assert_eq!(actual.after, expected);
            assert_eq!(actual.instruction.bytes(), encoding);
        }
    }
}
#[test]
fn kernel_control_selected_rejects_flags_aliases_and_semantic_mismatch() {
    use super::super::super::runtime::selected::model_with_lineage;
    use crate::selected::{SelectedInput, SelectedResult, SemanticsError, SyscallAliases};
    let number = libc::SYS_getpid as u64;
    let lineage = kernel_lineage(number);
    let result = SelectedResult::Cpuid {
        eax: 1,
        ebx: 2,
        ecx: 3,
        edx: 4,
    };
    for field in 0..5 {
        let mut registers = control_state(number).registers;
        match field {
            0 => registers.cs = 0x23,
            1 => registers.eflags |= 0x100,
            2 => registers.eflags |= 0x10000,
            3 => registers.eflags &= !2,
            _ => registers.eflags |= 0x3000,
        }
        let input = SelectedInput::new(
            crate::selected::decode(registers.rip, &[0x0f, 0xa2], &SyscallAliases::new()).unwrap(),
            registers,
        );
        if field == 0 {
            assert_eq!(input, Err(SemanticsError::UnsupportedExecutionMode));
            continue;
        }
        let input = input.unwrap();
        assert!(matches!(
            model_with_lineage(&input, result, &lineage, &lineage.checkpoint),
            Err(GateError::Refused(
                "runtime selected native64 control flags differ"
            ))
        ));
    }
    let registers = control_state(number).registers;
    let input = SelectedInput::new(
        crate::selected::decode(registers.rip, &[0x0f, 0xa2], &SyscallAliases::new()).unwrap(),
        registers,
    )
    .unwrap();
    assert!(matches!(
        model_with_lineage(
            &input,
            SelectedResult::Rdtsc { counter: 1 },
            &lineage,
            &lineage.checkpoint
        ),
        Err(GateError::Selected(SemanticsError::ResultClassMismatch))
    ));
    let mut registers = registers;
    registers.rax = number;
    let syscall = SelectedInput::new(
        crate::selected::decode(registers.rip, &[0x0f, 0x05], &SyscallAliases::new()).unwrap(),
        registers,
    )
    .unwrap();
    assert!(matches!(
        model_with_lineage(
            &syscall,
            SelectedResult::Syscall(crate::selected::SyscallResult::LinuxX64GetId { value: 42 }),
            &lineage,
            &lineage.checkpoint
        ),
        Err(GateError::Refused(
            "runtime selected syscall transport is not qualified"
        ))
    ));
}
#[test]
fn kernel_control_temporary_reservation_keeps_retained_profile_separate() {
    let actual = ControlProfile::temporary_bytes().unwrap();
    assert!(
        actual
            >= 3 * size_of::<RegisterSnapshot>()
                + size_of::<libc::user_regs_struct>()
                + size_of::<libc::iovec>()
                + size_of::<libc::statfs>()
    );
    // Two retained 16 KiB+1 proc-status arrays are already inside each profile;
    // this temporary envelope does not allocate or recopy those buffers.
    assert!(actual < size_of::<ControlProfile>());
    let mut profile = model_profile(DR_BASE);
    let before = profile.cet.status[0].bytes;
    assert_eq!(ControlProfile::temporary_bytes().unwrap(), actual);
    assert_eq!(profile.cet.status[0].bytes, before);
    profile.rseq_request = None;
    invalid(
        profile.require(DR_BASE),
        "owned instruction control profile incomplete",
    );
}
