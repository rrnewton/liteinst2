//! Six finite real-kernel controls. Scripted CPU values are not native CPU evidence.
use super::*;
use crate::lifecycle::ExitStatus;
use crate::linux::remote::dynamic::owner::admission::census::ObservedStop;
use crate::linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::assert_no_selected_effects;
use crate::linux::remote::dynamic::owner::admission::runtime::{RuntimeStage, isolation};
use crate::linux::remote::dynamic::owner::bootstrap::Request;
use crate::linux::remote::dynamic::owner::tests::reaped;
use crate::selected::{InstructionFault, SelectedResult, SyscallResult};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
mod archive;
mod public;
mod support;
use support::*;

fn check_pending(
    owner: &Owner,
    input: &RuntimeProviderInput,
    before: &Current,
    until: Instant,
    kernel: bool,
) {
    assert_eq!(input.input.registers(), &before.state.registers);
    assert_eq!(
        input.input.instruction().logical_pc(),
        before.state.registers.rip
    );
    assert_eq!(input.token.stop, before.stop.token);
    assert_eq!(input.token.task, before.observed.task);
    assert_eq!(input.token.generation.0, 0);
    assert_eq!(input.token.pc, before.state.registers.rip);
    let runtime = owner.runtime.as_ref().unwrap();
    assert!(runtime.pages.iter().all(|p| !p.executable));
    if kernel {
        assert!(runtime.selected_pending.is_none());
        let index = runtime.kernel_pending.unwrap();
        let a = &runtime.kernel_attempts[index];
        assert_eq!(a.token, input.token);
        assert_eq!(a.until, until);
        assert_eq!(a.stage, KernelStage::Pending);
        assert!(a.prepared.is_some() && a.first_failure.is_none() && a.decision.is_none());
        assert_eq!(a.input.as_ref(), Some(&input.input));
        assert_eq!(a.before, before.observed);
        assert!(a.native.test_effects().is_empty());
        assert!((0..9).all(|i| a.native.raw_view(i).is_none()));
        assert_eq!(input.input.instruction().bytes(), [0x0f, 0x05]);
        let identity = a.identity.as_ref().unwrap();
        assert_eq!(identity.until(), until);
        assert_eq!(identity.pending(), &input.token);
    } else {
        assert!(runtime.kernel_pending.is_none());
        assert!(runtime.selected_pending.is_some());
    }
}
fn pending_setup(
    owner: &mut Owner,
    app: &std::os::fd::OwnedFd,
    memory: &Memory,
    until: Instant,
    number: u8,
) -> (Box<RuntimeProviderInput>, Current) {
    let initial = current(owner, app, memory, until);
    let input = pending(owner, until);
    let before = current(owner, app, memory, until);
    let mut expected = initial.state.clone();
    expected.registers.rax = number as u64;
    expected.registers.rip += 2;
    assert_eq!(before.state, expected);
    advance_count(&initial, &before, 1, 7);
    assert_ne!(before.origin, initial.origin);
    assert!(before.stop.token.sequence > initial.stop.token.sequence);
    (input, before)
}
fn terminal(
    owner: &mut Owner,
    input: &RuntimeProviderInput,
    before: &Current,
    until: Instant,
    two: bool,
    memory: &Memory,
) {
    let reply = complete(owner, input, ProviderDecision::Native, until).unwrap();
    let AdmissionReply::Event(DynamicAdmissionEvent::TaskTerminal {
        task,
        status,
        all_terminal,
    }) = reply
    else {
        panic!("terminal operation invented a return")
    };
    assert_eq!(task, before.observed.task);
    assert_eq!(status, ExitStatus::Code(7));
    assert!(all_terminal);
    let runtime = owner.runtime.as_ref().unwrap();
    assert_eq!(runtime.stage, RuntimeStage::Terminal);
    assert!(
        runtime.initial_origin.is_none()
            && runtime.control_lineage.is_none()
            && runtime.kernel_pending.is_none()
    );
    assert!(
        runtime.pages.iter().any(|p| p.executable),
        "terminal preserves last open inventory; no synthetic NX observation"
    );
    let census = runtime.census.as_ref().unwrap();
    assert_eq!(census.active().count(), 0);
    assert_eq!(census.rows().count(), before.rows.len());
    assert_eq!(census.rows().cloned().collect::<Vec<_>>(), before.rows);
    assert_eq!(
        &census.history()[..before.history.len()],
        before.history.as_slice()
    );
    assert_eq!(census.history().len(), before.history.len() + 4);
    assert_eq!(census.used().origins, before.used.origins);
    assert_eq!(census.used().witnesses, before.used.witnesses + 4);
    assert_eq!(
        (
            census.used().epochs,
            census.used().reports,
            census.used().plan_history
        ),
        (
            before.used.epochs,
            before.used.reports,
            before.used.plan_history
        )
    );
    assert!(census.used().source_fact_bytes >= before.used.source_fact_bytes);
    assert!(
        census.charged().source_fact_bytes <= DynamicAdmissionLimits::default().source_fact_bytes
    );
    let index = runtime.kernel_attempts.len() - 1;
    assert_eq!(runtime.kernel_attempts[index].stage, KernelStage::Terminal);
    archive::native(owner, index, &before.state, None, &memory.maps, two);
    let journal = owner.kernel_journal.reader().snapshot();
    assert!(!journal.archive_poisoned);
    assert!(journal.attempts.is_empty());
    archive::journal(
        journal.runtime_attempts.last().unwrap(),
        &before.state,
        None,
        owner.pid,
    );
    census.test_runtime_kernel_chain(
        &before.observed,
        before.history.len(),
        runtime.kernel_attempts[index].identity.as_ref().unwrap(),
        journal.runtime_attempts.last().unwrap(),
        None,
    );
    // No read of task state, stack, source or maps is made after this real death.
}
fn returning(entry: usize, number: u8, terminate: u8, cpu: bool) {
    let program = code(number, terminate, cpu);
    with_owner(entry, &program, options(), |owner, app, memory, until| {
        let (input, before) = pending_setup(owner, app, memory, until, number);
        check_pending(owner, &input, &before, until, true);
        assert_ne!(before.state.registers.r12, MARK);
        assert_ne!(before.state.registers.r13, !MARK);
        let expected = syscall_after(&before.state, owner.pid);
        completed(
            complete(owner, &input, ProviderDecision::Native, until).unwrap(),
            &before,
            &input,
            &expected,
            SelectedExecution::Native,
        );
        let mut after = current(owner, app, memory, until);
        assert_eq!(after.state, expected);
        advance_count(&before, &after, 1, 8);
        assert_ne!(after.origin, before.origin);
        assert!(after.stop.token.sequence > before.stop.token.sequence);
        archive::native(
            owner,
            0,
            &before.state,
            Some(&expected),
            &memory.maps,
            entry == 4093,
        );
        let journal = owner.kernel_journal.reader().snapshot();
        assert_eq!(journal.runtime_attempts.len(), 1);
        assert!(journal.attempts.is_empty());
        archive::journal(
            &journal.runtime_attempts[0],
            &before.state,
            Some(&expected),
            owner.pid,
        );
        let runtime = owner.runtime.as_ref().unwrap();
        runtime.census.as_ref().unwrap().test_runtime_kernel_chain(
            &before.observed,
            before.history.len(),
            runtime.kernel_attempts[0].identity.as_ref().unwrap(),
            &journal.runtime_attempts[0],
            Some(after.origin),
        );
        if cpu {
            let input = pending(owner, until);
            check_pending(owner, &input, &after, until, false);
            let unchanged = current(owner, app, memory, until);
            same_current(&after, &unchanged);
            assert_eq!(input.input.instruction().bytes(), [0x0f, 0xa2]);
            assert_eq!(input.input.registers().orig_rax, number as u64);
            let expected = cpu_after(&after.state);
            completed(
                complete(owner, &input, ProviderDecision::Complete(SCRIPT), until).unwrap(),
                &after,
                &input,
                &expected,
                SelectedExecution::Scripted,
            );
            let next = current(owner, app, memory, until);
            assert_eq!(next.state, expected);
            advance_count(&after, &next, 1, 1);
            after = next;
        }
        let input = pending(owner, until);
        let end = current(owner, app, memory, until);
        let mut expected = after.state.clone();
        if cpu {
            expected.registers.r12 = MARK;
            expected.registers.rip += 10;
        }
        expected.registers.rax = terminate as u64;
        expected.registers.rdi = 7;
        expected.registers.rip += 10;
        expected.registers.orig_rax = u64::MAX;
        assert_eq!(end.state, expected);
        advance_count(
            &after,
            &end,
            if cpu { 3 } else { 2 },
            if cpu { 21 } else { 14 },
        );
        assert_eq!(
            end.state.registers.r13, before.state.registers.r13,
            "instruction after terminal syscall remains unexecuted"
        );
        check_pending(owner, &input, &end, until, true);
        terminal(owner, &input, &end, until, false, memory);
        reaped(app);
    });
}

#[test]
fn runtime_kernel_public_getpid_selected_ordinary_exit_preserves_lineage() {
    isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_public_getpid_selected_ordinary_exit_preserves_lineage",
        || {
            returning(4096, 39, 60, true);
            public::consumer(39, 60, true);
        },
    );
}
#[test]
fn runtime_kernel_gettid_exit_group_retains_real_terminal() {
    isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_gettid_exit_group_retains_real_terminal",
        || {
            returning(4096, 186, 231, true);
            public::consumer(186, 231, true);
        },
    );
}
#[test]
fn runtime_kernel_cross_page_syscall_preserves_exact_fetch() {
    isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_cross_page_syscall_preserves_exact_fetch",
        || {
            for (number, end) in [(39, 60), (186, 231)] {
                returning(4093, number, end, false);
            }
            // Terminal originals also cross the boundary. The existing constructor
            // permits only 4093/4095. An original branch skips the syscall to
            // genuine register setup, followed by an original direct
            // backward branch to the cross-page SYSCALL, with no synthetic state.
            for number in [60u8, 231] {
                let mut program = vec![
                    0xeb, 0x02, 0x0f, 0x05, 0xbf, 7, 0, 0, 0, 0xb8, number, 0, 0, 0, 0xeb, 0xf2,
                ];
                program.extend_from_slice(&[0x49, 0xbd]);
                program.extend_from_slice(&(!MARK).to_le_bytes());
                with_owner(4093, &program, options(), |owner, app, memory, until| {
                    let initial = current(owner, app, memory, until);
                    let input = pending(owner, until);
                    let before = current(owner, app, memory, until);
                    let mut expected = initial.state.clone();
                    expected.registers.rdi = 7;
                    expected.registers.rax = number as u64;
                    expected.registers.rip = BASE + 4095;
                    assert_eq!(before.state, expected);
                    advance_count(&initial, &before, 4, 28);
                    check_pending(owner, &input, &before, until, true);
                    terminal(owner, &input, &before, until, true, memory);
                    reaped(app);
                });
            }
        },
    );
}
fn refusal_counters(before: &Current, after: &Current) {
    same_current(before, after);
    assert_eq!(
        (
            after.used.epochs,
            after.used.origins,
            after.used.witnesses,
            after.used.reports,
            after.used.plan_history
        ),
        (
            before.used.epochs,
            before.used.origins,
            before.used.witnesses,
            before.used.reports,
            before.used.plan_history
        )
    );
    assert_eq!(after.charged, before.charged);
    assert!(after.used.source_fact_bytes >= before.used.source_fact_bytes);
    assert!(after.used.source_fact_bytes <= after.charged.source_fact_bytes);
}
fn old_refusal(program: &[u8], options: DynamicRuntimeOptions, syscall: bool) {
    with_owner(4096, program, options, |owner, app, memory, until| {
        let input = pending(owner, until);
        let before = current(owner, app, memory, until);
        check_pending(owner, &input, &before, until, false);
        assert_eq!(
            input.input.instruction().bytes(),
            if syscall {
                &[0x0f, 0x05]
            } else {
                &[0x0f, 0xa2]
            }
        );
        assert!(matches!(
            complete(owner, &input, ProviderDecision::Native, until),
            Err(GateError::Refused(
                "runtime selected Native transport is not qualified"
            ))
        ));
        let after = current(owner, app, memory, until);
        refusal_counters(&before, &after);
        assert_eq!(before.used, after.used);
        let runtime = owner.runtime.as_ref().unwrap();
        assert_no_selected_effects(runtime.selected_attempts.last().unwrap());
        archive::no_effects(owner, 0);
        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
        assert_eq!(after.state.registers.r12, before.state.registers.r12);
    });
}
#[test]
fn runtime_kernel_default_native_and_cpu_refusals_keep_current_state() {
    isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_default_native_and_cpu_refusals_keep_current_state",
        || {
            old_refusal(&code(39, 60, true), DynamicRuntimeOptions::default(), true);
            for options in [DynamicRuntimeOptions::default(), options()] {
                let mut code = vec![0x0f, 0xa2, 0x49, 0xbc];
                code.extend_from_slice(&MARK.to_le_bytes());
                code.extend_from_slice(&[0xeb, 0xfe]);
                old_refusal(&code, options, false);
            }
        },
    );
}
#[test]
fn runtime_kernel_fault_and_unsupported_syscalls_never_release() {
    isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_fault_and_unsupported_syscalls_never_release",
        || {
            for decision in [
                ProviderDecision::Fault(InstructionFault::GeneralProtection { error_code: 0 }),
                ProviderDecision::Complete(SelectedResult::Syscall(SyscallResult::LinuxX64GetId {
                    value: 123,
                })),
            ] {
                with_owner(
                    4096,
                    &code(39, 60, true),
                    options(),
                    |owner, app, memory, until| {
                        let (input, before) = pending_setup(owner, app, memory, until, 39);
                        check_pending(owner, &input, &before, until, true);
                        let reply = complete(owner, &input, decision, until);
                        match decision {
                            ProviderDecision::Fault(fault) => {
                                let AdmissionReply::Event(DynamicAdmissionEvent::Fault {
                                    task,
                                    fault: actual,
                                }) = reply.unwrap()
                                else {
                                    panic!("fault became native completion")
                                };
                                assert_eq!(task, before.observed.task);
                                assert_eq!(actual.input, input.input);
                                assert_eq!(actual.fault, fault);
                            }
                            _ => assert!(matches!(
                                reply,
                                Err(GateError::Refused(
                                    "runtime kernel profile requires native execution or a provider fault"
                                ))
                            )),
                        }
                        let after = current(owner, app, memory, until);
                        refusal_counters(&before, &after);
                        archive::no_effects(owner, 1);
                        let a = &owner.runtime.as_ref().unwrap().kernel_attempts[0];
                        assert_eq!(a.decision, Some(decision));
                        assert!(a.checks.progress[0].complete && a.checks.progress[1].complete);
                        assert!(a.checks.progress[2..].iter().all(|p| !p.started));
                        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                        let journal = owner.kernel_journal.reader().snapshot();
                        let failed = journal.runtime_attempts.last().unwrap().failure.unwrap();
                        if matches!(decision, ProviderDecision::Fault(_)) {
                            assert_eq!(a.stage, KernelStage::Fault);
                            assert_eq!(a.first_failure, None);
                            assert_eq!(
                                (failed.stage, failed.kind),
                                (
                                    RuntimeKernelJournalStage::Prepared,
                                    KernelFailureKind::Cancelled
                                )
                            );
                        } else {
                            assert_eq!(
                                a.first_failure,
                                Some((
                                    KernelStage::SourceAfterProvider,
                                    super::super::selected::SelectedFailure::Refused(
                                        "runtime kernel profile requires native execution or a provider fault"
                                    )
                                ))
                            );
                            assert_eq!(
                                (failed.stage, failed.kind),
                                (
                                    RuntimeKernelJournalStage::Original,
                                    KernelFailureKind::AdmissionRejected
                                )
                            );
                        }
                    },
                );
            }
            for number in [1u32, 39 | (1 << 30)] {
                let mut code = vec![0xb8];
                code.extend_from_slice(&number.to_le_bytes());
                code.extend_from_slice(&[0x0f, 0x05, 0x49, 0xbc]);
                code.extend_from_slice(&MARK.to_le_bytes());
                old_refusal(&code, options(), true);
            }
            for encoding in [&[0xcd, 0x80][..], &[0x0f, 0x34][..]] {
                let mut code = encoding.to_vec();
                code.extend_from_slice(&[0x49, 0xbc]);
                code.extend_from_slice(&MARK.to_le_bytes());
                with_owner(4096, &code, options(), |owner, app, memory, until| {
                    let before = current(owner, app, memory, until);
                    assert!(matches!(
                        invoke(owner, AdmissionRequest::Advance, until),
                        Err(GateError::Refused(
                            "runtime actual instruction is unqualified"
                        ))
                    ));
                    let after = current(owner, app, memory, until);
                    same_current(&before, &after);
                    assert_eq!(before.charged, after.charged);
                    assert_eq!(before.used, after.used);
                    let r = owner.runtime.as_ref().unwrap();
                    assert!(r.ordinary_attempts.is_empty() && r.selected_attempts.is_empty());
                    archive::no_effects(owner, 0);
                });
            }
        },
    );
}
#[test]
fn runtime_kernel_stale_reply_keeps_physical_custody() {
    isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_stale_reply_keeps_physical_custody",
        || {
            with_owner(
                4096,
                &code(39, 60, true),
                options(),
                |owner, app, memory, until| {
                    let (input, before) = pending_setup(owner, app, memory, until, 39);
                    check_pending(owner, &input, &before, until, true);
                    let mut stale = input.token.clone();
                    stale.invocation = stale.invocation.checked_add(1).unwrap();
                    assert!(matches!(
                        invoke(
                            owner,
                            AdmissionRequest::CompleteRuntime {
                                token: stale,
                                decision: ProviderDecision::Native
                            },
                            until
                        ),
                        Err(GateError::Refused(
                            "runtime kernel pending identity or original deadline differs"
                        ))
                    ));
                    let after = current(owner, app, memory, until);
                    refusal_counters(&before, &after);
                    assert_eq!(before.used, after.used);
                    archive::no_effects(owner, 1);
                    let a = &owner.runtime.as_ref().unwrap().kernel_attempts[0];
                    assert_eq!(a.token, input.token);
                    assert_eq!(a.until, until);
                    assert!(a.decision.is_none());
                    assert!(a.checks.progress[0].complete);
                    assert!(a.checks.progress[1..].iter().all(|p| !p.started));
                    assert_eq!(
                        a.first_failure,
                        Some((
                            KernelStage::Pending,
                            super::super::selected::SelectedFailure::Refused(
                                "runtime kernel pending identity or original deadline differs"
                            )
                        ))
                    );
                    let journal = owner.kernel_journal.reader().snapshot();
                    let failed = journal.runtime_attempts.last().unwrap().failure.unwrap();
                    assert_eq!(
                        (failed.stage, failed.kind),
                        (
                            RuntimeKernelJournalStage::Original,
                            KernelFailureKind::AdmissionRejected
                        )
                    );
                    assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                },
            );
        },
    );
}
