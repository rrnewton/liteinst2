//! Synthetic read outcomes exercise the production capture transaction. These
//! cases establish no actual ptrace, signal delivery, state or cleanup evidence.
use super::*;
use std::cell::Cell;

fn writer() -> SignalJournalWriter {
    let request =
        launch::anchor::AnchorRequest::new(launch::anchor::ANCHOR_EVIDENCE_BOUND).unwrap();
    let anchor = launch::anchor::AnchorArchive::new(request, 71).unwrap();
    SignalJournalWriter::new(71, anchor.reader()).unwrap()
}

fn initialized(op: u8) -> [u8; 88] {
    let mut raw = [0xa5_u8; 88];
    raw[0] = op;
    raw[4..8].copy_from_slice(&AUDIT_ARCH_X86_64.to_ne_bytes());
    raw[8..16].copy_from_slice(&0x40_1234_u64.to_ne_bytes());
    raw[16..24].copy_from_slice(&0x70_5678_u64.to_ne_bytes());
    if op == libc::PTRACE_SYSCALL_INFO_EXIT {
        raw[24..32].copy_from_slice(&(-22_i64).to_ne_bytes());
        raw[32] = 1;
    }
    raw
}

fn info(
    fact: &mut Option<SignalJournalFact>,
    tid: i32,
    result: i64,
    errno: Option<i32>,
    raw: [u8; 88],
) -> Result<(libc::ptrace_syscall_info, [u8; 88], usize), LaunchError> {
    *fact = Some(SignalJournalFact::SyscallInfo {
        tid,
        result,
        errno,
        initialized: raw,
    });
    SignalJournalWriter::interpret_syscall(result, errno, raw)
}

fn complete(state: &mut StateBuffer, _: i32) -> Result<TaskStateSnapshot, LaunchError> {
    let registers = RegisterSnapshot::from(unsafe { std::mem::zeroed::<libc::user_regs_struct>() });
    assert!(SignalJournalWriter::retain_registers(state, 0, None, registers).is_none());
    state.xstate[..512].fill(0x5a);
    state.length = 512;
    state.xstate_read = Some(SignalXstateRead {
        result: 0,
        errno: None,
        reported_bytes: 512,
        pointer_unchanged: true,
    });
    state.mask = Some(0x80);
    state.mask_read = Some(SignalMaskRead {
        result: 0,
        errno: None,
        initialized: 0x80,
    });
    state.complete = true;
    let mut returned = state.returned.take().unwrap();
    returned[..512].copy_from_slice(&state.xstate[..512]);
    returned.truncate(512);
    Ok(TaskStateSnapshot {
        registers,
        xstate: returned,
        mask: 0x80,
    })
}

#[test]
fn failed_syscall_observation_still_retains_the_independent_complete_state() {
    for (op, count, errno) in [
        (libc::PTRACE_SYSCALL_INFO_EXIT, -1, Some(libc::EIO)),
        (libc::PTRACE_SYSCALL_INFO_EXIT, 32, None),
        (libc::PTRACE_SYSCALL_INFO_EXIT, 89, None),
        (99, 88, None),
    ] {
        let journal = writer();
        let raw = initialized(op);
        let state_calls = Cell::new(0);
        let result = journal.capture_pair_with(
            19,
            0x857f,
            |fact, tid| info(fact, tid, count, errno, raw),
            |slot, tid| {
                state_calls.set(state_calls.get() + 1);
                complete(slot, tid)
            },
        );
        assert!(result.is_err());
        assert_eq!(state_calls.get(), 1);
        let snapshot = journal.reader().snapshot();
        assert_eq!(
            snapshot.facts,
            vec![
                SignalJournalFact::RawWait {
                    tid: 19,
                    status: 0x857f
                },
                SignalJournalFact::SyscallInfo {
                    tid: 19,
                    result: count,
                    errno,
                    initialized: raw
                },
                SignalJournalFact::State {
                    slot: 0,
                    tid: 19,
                    stop: None
                },
            ]
        );
        assert_eq!(snapshot.states.len(), 1);
        assert!(snapshot.states[0].complete);
        assert_eq!(snapshot.states[0].xstate, vec![0x5a; 512]);
        assert_eq!(snapshot.states[0].signal_mask, Some(0x80));
        assert!(snapshot.first_failure.is_some());
        assert!(
            journal
                .append(SignalJournalFact::Validated {
                    phase: SignalJournalPhase::ReturnObserved
                })
                .is_err()
        );
        assert_eq!(journal.reader().snapshot(), snapshot);
    }
}

#[test]
fn failed_state_observation_preserves_syscall_bytes_and_partial_state() {
    for registers_result in [-1, 1, 0] {
        let journal = writer();
        let raw = initialized(libc::PTRACE_SYSCALL_INFO_EXIT);
        let mut registers =
            RegisterSnapshot::from(unsafe { std::mem::zeroed::<libc::user_regs_struct>() });
        registers.r15 = 0x1234;
        registers.rip = 0x401234;
        let registers_errno = (registers_result == -1).then_some(libc::EIO);
        let result = journal.capture_pair_with(
            23,
            0x857f,
            |fact, tid| info(fact, tid, 33, None, raw),
            |slot, _| {
                let registers_error = SignalJournalWriter::retain_registers(
                    slot,
                    registers_result,
                    registers_errno,
                    registers,
                );
                slot.xstate[..64].fill(0x36);
                slot.length = 64;
                slot.xstate_read = Some(SignalXstateRead {
                    result: -1,
                    errno: Some(libc::EIO),
                    reported_bytes: MAX_XSTATE,
                    pointer_unchanged: true,
                });
                slot.mask_read = Some(SignalMaskRead {
                    result: 0,
                    errno: None,
                    initialized: 0x20,
                });
                slot.mask = Some(0x20);
                Err(registers_error.unwrap_or_else(|| {
                    io_error(
                        "synthetic state read",
                        io::Error::from_raw_os_error(libc::EIO),
                    )
                }))
            },
        );
        if registers_result == 1 {
            assert!(matches!(
                result,
                Err(LaunchError::Invalid("signal register read result differs"))
            ));
        } else {
            assert!(
                matches!(result, Err(LaunchError::System { source, .. }) if source.raw_os_error() == Some(libc::EIO))
            );
        }
        let snapshot = journal.reader().snapshot();
        assert_eq!(
            snapshot.facts[1],
            SignalJournalFact::SyscallInfo {
                tid: 23,
                result: 33,
                errno: None,
                initialized: raw
            }
        );
        assert_eq!(snapshot.states.len(), 1);
        assert!(!snapshot.states[0].complete);
        assert_eq!(
            snapshot.states[0].registers,
            (registers_result == 0).then_some(registers)
        );
        assert_eq!(
            snapshot.states[0].register_read,
            Some(SignalRegisterRead {
                result: registers_result,
                errno: registers_errno,
                initialized: registers
            })
        );
        assert_eq!(snapshot.states[0].xstate, vec![0x36; 64]);
        assert_eq!(snapshot.states[0].signal_mask, Some(0x20));
        let expected = if registers_result == 1 {
            SignalJournalFailure::InvalidState
        } else {
            SignalJournalFailure::NativeIo(Some(libc::EIO))
        };
        assert_eq!(
            snapshot.first_failure,
            Some((SignalJournalPhase::Prepared, expected))
        );
    }
}

#[test]
fn paired_signal_reads_preserve_first_error_and_cleanup_without_validation() {
    for component_errors in [false, true] {
        let journal = writer();
        let state_calls = Cell::new(0);
        let result: Result<([u8; 128], TaskStateSnapshot), _> = journal.capture_pair_with(
            29,
            0x857f,
            |fact, tid| {
                *fact = Some(SignalJournalFact::Siginfo {
                    tid,
                    result: -1,
                    errno: Some(libc::EPERM),
                    raw: [0x49; 128],
                });
                Err(io_error(
                    "synthetic siginfo",
                    io::Error::from_raw_os_error(libc::EPERM),
                ))
            },
            |slot, _| {
                state_calls.set(state_calls.get() + 1);
                slot.length = 7;
                slot.xstate[..7].fill(0x62);
                if !component_errors {
                    return Err(LaunchError::Timeout("synthetic independent state"));
                }
                let mut initialized =
                    RegisterSnapshot::from(unsafe { std::mem::zeroed::<libc::user_regs_struct>() });
                initialized.r11 = 0x7788;
                let error =
                    SignalJournalWriter::retain_registers(slot, -1, Some(libc::EIO), initialized)
                        .unwrap();
                slot.xstate_read = Some(SignalXstateRead {
                    result: -1,
                    errno: Some(libc::ENOSPC),
                    reported_bytes: MAX_XSTATE,
                    pointer_unchanged: true,
                });
                slot.mask_read = Some(SignalMaskRead {
                    result: -1,
                    errno: Some(libc::ESRCH),
                    initialized: 0,
                });
                Err(error)
            },
        );
        assert!(
            matches!(result, Err(LaunchError::System { source, .. }) if source.raw_os_error() == Some(libc::EPERM))
        );
        assert_eq!(state_calls.get(), 1);
        let before = journal.reader().snapshot();
        assert_eq!(
            before.first_failure,
            Some((
                SignalJournalPhase::Prepared,
                SignalJournalFailure::NativeIo(Some(libc::EPERM))
            ))
        );
        assert_eq!(before.states[0].xstate, vec![0x62; 7]);
        assert!(before.states[0].registers.is_none());
        if component_errors {
            let registers = before.states[0].register_read.unwrap();
            assert_eq!(
                (registers.result, registers.errno, registers.initialized.r11),
                (-1, Some(libc::EIO), 0x7788)
            );
            assert_eq!(
                before.states[0].xstate_read.unwrap().errno,
                Some(libc::ENOSPC)
            );
            assert_eq!(
                before.states[0].signal_mask_read.unwrap().errno,
                Some(libc::ESRCH)
            );
        } else {
            assert!(before.states[0].register_read.is_none());
            assert!(before.states[0].xstate_read.is_none());
            assert!(before.states[0].signal_mask_read.is_none());
        }
        assert!(!before.states[0].complete);
        journal.fail(SignalJournalFailure::Timeout);
        journal.close(Some(true));
        let after = journal.reader().snapshot();
        assert_eq!(after.facts, before.facts);
        assert_eq!(after.states, before.states);
        assert_eq!(after.first_failure, before.first_failure);
        assert!(after.closing);
        assert_eq!(after.cleanup_complete, Some(true));
        assert!(
            !after
                .facts
                .iter()
                .any(|fact| matches!(fact, SignalJournalFact::Validated { .. }))
        );
    }
}

#[test]
fn paired_capture_reserves_raw_stop_and_state_before_any_read() {
    for scenario in 0..4 {
        let journal = writer();
        {
            let mut archive = journal.lock();
            match scenario {
                0 => {
                    archive.fact_count = FACT_SLOTS;
                }
                1 => {
                    archive.state_count = STATE_SLOTS;
                }
                2 => {
                    archive.failure = Some((
                        SignalJournalPhase::Prepared,
                        SignalJournalFailure::Cancelled,
                    ));
                }
                3 => {
                    archive.closing = true;
                }
                _ => unreachable!(),
            }
        }
        let before = journal.reader().snapshot();
        let (facts, states) = {
            let a = journal.lock();
            (a.fact_count, a.state_count)
        };
        let reads = Cell::new(0);
        let result: Result<((), TaskStateSnapshot), _> = journal.capture_pair_with(
            31,
            0x857f,
            |_, _| {
                reads.set(reads.get() + 1);
                Ok(())
            },
            |slot, tid| {
                reads.set(reads.get() + 1);
                complete(slot, tid)
            },
        );
        assert!(result.is_err());
        assert_eq!(reads.get(), 0);
        let a = journal.lock();
        assert_eq!(
            (a.fact_count, a.state_count),
            (facts + usize::from(scenario == 1), states)
        );
        drop(a);
        let after = journal.reader().snapshot();
        let mut expected_facts = before.facts.clone();
        if scenario == 1 {
            expected_facts.push(SignalJournalFact::RawWait {
                tid: 31,
                status: 0x857f,
            });
        }
        assert_eq!(after.facts, expected_facts);
        assert_eq!(after.states, before.states);
        assert_eq!(after.frames, before.frames);
        assert_eq!(after.closing, before.closing);
        assert!(after.first_failure.is_some());
        if before.first_failure.is_some() {
            assert_eq!(after.first_failure, before.first_failure);
        }
    }
}

#[test]
fn complete_pair_consumes_exact_preallocated_slots_without_capacity_renewal() {
    let journal = writer();
    let raw = initialized(libc::PTRACE_SYSCALL_INFO_EXIT);
    for index in 0..STATE_SLOTS {
        let ((info, captured, count), state) = journal
            .capture_pair_with(
                37,
                0x857f,
                |fact, tid| info(fact, tid, 33, None, raw),
                complete,
            )
            .unwrap();
        assert_eq!(info.op, libc::PTRACE_SYSCALL_INFO_EXIT);
        assert_eq!((captured, count), (raw, 33));
        assert_eq!(state.xstate, vec![0x5a; 512]);
        assert_eq!(state.mask, 0x80);
        let a = journal.lock();
        assert_eq!(a.fact_count, index + 1);
        assert_eq!(a.state_count, index + 1);
        assert_eq!(a.states.len(), STATE_SLOTS);
        assert!(a.failure.is_none());
        assert!(a.states[index].returned.is_none());
    }
    let reads = Cell::new(0);
    let result: Result<((), TaskStateSnapshot), _> = journal.capture_pair_with(
        37,
        0x857f,
        |_, _| {
            reads.set(reads.get() + 1);
            Ok(())
        },
        |slot, tid| {
            reads.set(reads.get() + 1);
            complete(slot, tid)
        },
    );
    assert!(result.is_err());
    assert_eq!(reads.get(), 0);
    let a = journal.lock();
    assert_eq!(a.fact_count, STATE_SLOTS + 1);
    assert_eq!(a.state_count, STATE_SLOTS);
    assert_eq!(
        a.failure,
        Some((SignalJournalPhase::Prepared, SignalJournalFailure::Capacity))
    );
}

#[test]
fn syscall_information_validator_preserves_raw_exit_error_bit_and_exact_sizes() {
    for (op, minimum) in [
        (libc::PTRACE_SYSCALL_INFO_ENTRY, 80_i64),
        (libc::PTRACE_SYSCALL_INFO_EXIT, 33),
    ] {
        let raw = initialized(op);
        for count in [minimum, 88] {
            let (info, retained, length) =
                SignalJournalWriter::interpret_syscall(count, None, raw).unwrap();
            assert_eq!(info.op, op);
            assert_eq!(info.arch, AUDIT_ARCH_X86_64);
            assert_eq!(info.instruction_pointer, 0x40_1234);
            assert_eq!(info.stack_pointer, 0x70_5678);
            assert_eq!((retained, length), (raw, count as usize));
            if op == libc::PTRACE_SYSCALL_INFO_EXIT {
                let exit = unsafe { info.u.exit };
                assert_eq!(exit.sval, -22);
                assert_eq!(exit.is_error, 1);
            }
        }
        for count in [-1, 0, minimum - 1, 89] {
            assert!(SignalJournalWriter::interpret_syscall(count, Some(libc::EIO), raw).is_err());
        }
    }
    for op in [
        libc::PTRACE_SYSCALL_INFO_NONE,
        libc::PTRACE_SYSCALL_INFO_SECCOMP,
        99,
    ] {
        assert!(SignalJournalWriter::interpret_syscall(88, None, initialized(op)).is_err());
    }
}

#[test]
fn complete_signal_trajectories_preserve_68_and_71_logical_facts_in_fixed_storage() {
    for (with_extent, logical, stored, states) in [(false, 68, 56, 6), (true, 71, 57, 7)] {
        let journal = writer();
        let mut expected = Vec::new();
        let mut state_index = 0;
        let mut frame_index = 0;
        let token = KernelStopIdentity {
            session: 71,
            sequence: 2,
            tid: 41,
            task: None,
        };
        // This is the finite ordinary/edited trajectory's diagnostic schedule,
        // not a fabricated native execution. All query outcomes are synthetic.
        fn one(
            journal: &SignalJournalWriter,
            expected: &mut Vec<SignalJournalFact>,
            fact: SignalJournalFact,
        ) {
            journal.append(fact.clone()).unwrap();
            expected.push(fact);
        }
        fn phase(
            journal: &SignalJournalWriter,
            expected: &mut Vec<SignalJournalFact>,
            phase: SignalJournalPhase,
        ) {
            journal.phase(phase).unwrap();
            expected.push(SignalJournalFact::Phase(phase));
        }
        fn frames(
            journal: &SignalJournalWriter,
            expected: &mut Vec<SignalJournalFact>,
            index: &mut usize,
            count: usize,
        ) {
            for _ in 0..count {
                one(
                    journal,
                    expected,
                    SignalJournalFact::Frame {
                        slot: *index,
                        address: 0x70_8008,
                    },
                );
                *index += 1;
            }
        }
        fn stop(
            journal: &SignalJournalWriter,
            expected: &mut Vec<SignalJournalFact>,
            index: &mut usize,
            syscall: bool,
        ) {
            let raw = initialized(libc::PTRACE_SYSCALL_INFO_EXIT);
            let fact = if syscall {
                SignalJournalFact::SyscallInfo {
                    tid: 41,
                    result: 33,
                    errno: None,
                    initialized: raw,
                }
            } else {
                SignalJournalFact::Siginfo {
                    tid: 41,
                    result: 0,
                    errno: None,
                    raw: [0x42; 128],
                }
            };
            journal
                .capture_pair_with(
                    41,
                    0x857f,
                    |slot, _| {
                        *slot = Some(fact.clone());
                        Ok(())
                    },
                    complete,
                )
                .unwrap();
            expected.extend([
                SignalJournalFact::RawWait {
                    tid: 41,
                    status: 0x857f,
                },
                fact,
                SignalJournalFact::State {
                    slot: *index,
                    tid: 41,
                    stop: None,
                },
            ]);
            *index += 1;
        }
        if with_extent {
            stop(&journal, &mut expected, &mut state_index, false);
        } // actual bootstrap extent acquisition
        stop(&journal, &mut expected, &mut state_index, false); // original queued signal
        phase(&journal, &mut expected, SignalJournalPhase::DeliveryPending);
        one(
            &journal,
            &mut expected,
            SignalJournalFact::Validated {
                phase: SignalJournalPhase::DeliveryPending,
            },
        );
        phase(&journal, &mut expected, SignalJournalPhase::DeliveryRelease);
        one(
            &journal,
            &mut expected,
            SignalJournalFact::ReleaseAttempt { token },
        );
        one(
            &journal,
            &mut expected,
            SignalJournalFact::Released { token },
        );
        phase(&journal, &mut expected, SignalJournalPhase::HandlerFetch);
        stop(&journal, &mut expected, &mut state_index, false);
        phase(&journal, &mut expected, SignalJournalPhase::FrameCapture);
        frames(&journal, &mut expected, &mut frame_index, 3); // header, FP prefix, full frame
        phase(&journal, &mut expected, SignalJournalPhase::Projection);
        frames(&journal, &mut expected, &mut frame_index, 5); // projection, settle, rebind x2, publish
        phase(&journal, &mut expected, SignalJournalPhase::HandlerGuard);
        stop(&journal, &mut expected, &mut state_index, false);
        frames(&journal, &mut expected, &mut frame_index, 2); // reconcile + normalize
        phase(&journal, &mut expected, SignalJournalPhase::HandlerReady);
        one(
            &journal,
            &mut expected,
            SignalJournalFact::Validated {
                phase: SignalJournalPhase::HandlerReady,
            },
        );
        frames(&journal, &mut expected, &mut frame_index, 5); // handler CPUID completion
        frames(&journal, &mut expected, &mut frame_index, 5); // handler to restorer-head NX fetch
        frames(&journal, &mut expected, &mut frame_index, 5); // restorer MOV to selected syscall guard
        frames(&journal, &mut expected, &mut frame_index, 2); // final frame rereads
        phase(&journal, &mut expected, SignalJournalPhase::ReturnEntry);
        one(
            &journal,
            &mut expected,
            SignalJournalFact::ReleaseAttempt { token },
        );
        one(
            &journal,
            &mut expected,
            SignalJournalFact::Released { token },
        );
        stop(&journal, &mut expected, &mut state_index, true);
        one(
            &journal,
            &mut expected,
            SignalJournalFact::Validated {
                phase: SignalJournalPhase::ReturnEntry,
            },
        );
        phase(&journal, &mut expected, SignalJournalPhase::ReturnRelease);
        one(
            &journal,
            &mut expected,
            SignalJournalFact::ReleaseAttempt { token },
        );
        one(
            &journal,
            &mut expected,
            SignalJournalFact::Released { token },
        );
        phase(&journal, &mut expected, SignalJournalPhase::ReturnObserved);
        stop(&journal, &mut expected, &mut state_index, true);
        one(
            &journal,
            &mut expected,
            SignalJournalFact::Validated {
                phase: SignalJournalPhase::ReturnObserved,
            },
        );
        phase(&journal, &mut expected, SignalJournalPhase::ReturnBridge);
        stop(&journal, &mut expected, &mut state_index, false);
        phase(&journal, &mut expected, SignalJournalPhase::ReturnRearmed);
        one(
            &journal,
            &mut expected,
            SignalJournalFact::Validated {
                phase: SignalJournalPhase::ReturnRearmed,
            },
        );
        assert_eq!(
            (expected.len(), state_index, frame_index),
            (logical, states, 27)
        );
        let archive = journal.lock();
        assert_eq!(archive.fact_count, stored);
        assert_eq!(archive.states.len(), 16);
        assert_eq!(archive.frames.len(), 32);
        assert!(archive.failure.is_none());
        drop(archive);
        assert_eq!(journal.reader().snapshot().facts, expected);
        // Fill exactly the remaining fixed physical slots, then refuse without
        // changing any already expanded evidence or pretending a query ran.
        for _ in stored..64 {
            one(
                &journal,
                &mut expected,
                SignalJournalFact::Validated {
                    phase: SignalJournalPhase::ReturnRearmed,
                },
            );
        }
        let reads = Cell::new(0);
        let result: Result<((), TaskStateSnapshot), _> = journal.capture_pair_with(
            41,
            0x857f,
            |_, _| {
                reads.set(reads.get() + 1);
                Ok(())
            },
            |slot, tid| {
                reads.set(reads.get() + 1);
                complete(slot, tid)
            },
        );
        assert!(result.is_err());
        assert_eq!(reads.get(), 0);
        assert_eq!(journal.reader().snapshot().facts, expected);
        let archive = journal.lock();
        assert_eq!(archive.fact_count, 64);
        assert_eq!(archive.state_count, states);
    }
}
