use super::*;
use crate::selected::SelectedResult;

fn pending(owner: &mut Owner, until: Instant) -> Box<RuntimeProviderInput> {
    match support::invoke(owner, AdmissionRequest::Advance, until).unwrap() {
        AdmissionReply::RuntimeProvider(input) => input,
        _ => panic!("expected actual selected boundary"),
    }
}
fn complete(
    owner: &mut Owner,
    input: &RuntimeProviderInput,
    decision: ProviderDecision,
    expected: &TaskStateSnapshot,
    until: Instant,
) {
    let reply = support::invoke(
        owner,
        AdmissionRequest::CompleteRuntime {
            token: input.token.clone(),
            decision,
        },
        until,
    )
    .unwrap();
    let AdmissionReply::Event(DynamicAdmissionEvent::Completed(done)) = reply else {
        panic!("completion differs")
    };
    assert_eq!(done.selected.input, input.input);
    assert_eq!(done.selected.after, expected.registers);
    assert_eq!(done.selected.xstate, expected.xstate);
    assert_eq!(done.signal_mask, expected.mask);
    assert_eq!(support::observe_state(owner, until), *expected);
}
pub(super) fn mixed() {
    // Native getpid -> CALL/RET (inherited syscall orig_rax) -> scripted CPUID
    // -> ordinary NOP -> second scripted CPUID. The CPU values are literals.
    let call_pc = BASE + 4100;
    let next = call_pc + 5;
    let mut code = vec![0xb0, 39, 0x0f, 0x05, 0xe8];
    code.extend_from_slice(
        &i32::try_from(CALLEE as i64 - next as i64)
            .unwrap()
            .to_le_bytes(),
    );
    code.extend_from_slice(&[0x0f, 0xa2, 0x90, 0x0f, 0xa2]);
    code.extend_from_slice(&fixture::MARKER);
    let program = Program {
        fixture: Fixture::stack_code(
            4096,
            &[(4096, &code), (0x1100, &[0xc3]), (0x1101, &fixture::MARKER)],
        ),
        entry: BASE + 4096,
        call_pc,
        target: CALLEE,
        next,
        setup: 0,
        encoding: code[4..9].try_into().unwrap(),
    };
    let _ = support::with_owner(
        &program,
        true,
        |owner, initial, until, original| {
            let options = DynamicRuntimeOptions {
                kernel: RuntimeKernelProfile::IdentityAndTermination,
                ..support::options()
            };
            let initial_state = support::begin(owner, initial, until, original, options);
            ledger::install(owner);
            let input = pending(owner, until);
            let syscall_before = support::observe_state(owner, until);
            let mut expected = initial_state.clone();
            expected.registers.rax = 39;
            expected.registers.rip += 2;
            assert_eq!(syscall_before, expected);
            assert_eq!(input.input.registers(), &syscall_before.registers);
            expected.registers.rip += 2;
            expected.registers.rcx = expected.registers.rip;
            expected.registers.r11 = syscall_before.registers.eflags & !0x10000;
            expected.registers.eflags &= !0x10000;
            expected.registers.orig_rax = 39;
            expected.registers.rax = owner.pid as u64;
            complete(owner, &input, ProviderDecision::Native, &expected, until);
            let kernel_history = owner
                .runtime
                .as_ref()
                .unwrap()
                .census
                .as_ref()
                .unwrap()
                .history()
                .to_vec();
            let stack_before = original.read_stack(owner, until);
            let call_start = kernel_history.len();
            let call = compare::successor(&expected, CALLEE, true);
            support::one(owner, until).unwrap();
            compare::completed(
                owner,
                original,
                compare::CompletionExpected {
                    before: &expected,
                    after: &call,
                    stack_before: &stack_before,
                    ordinal: 0,
                    call: true,
                    next,
                },
                until,
            );
            ledger::chain(owner, 0, call_start);
            ledger::check(owner, 1);
            let pushed = original.read_stack(owner, until);
            let ret_start = owner
                .runtime
                .as_ref()
                .unwrap()
                .census
                .as_ref()
                .unwrap()
                .history()
                .len();
            let returned = compare::successor(&call, next, false);
            support::one(owner, until).unwrap();
            compare::completed(
                owner,
                original,
                compare::CompletionExpected {
                    before: &call,
                    after: &returned,
                    stack_before: &pushed,
                    ordinal: 1,
                    call: false,
                    next: CALLEE + 1,
                },
                until,
            );
            ledger::chain(owner, 1, ret_start);
            let input = pending(owner, until);
            assert_eq!(input.input.registers(), &returned.registers);
            let result = SelectedResult::Cpuid {
                eax: 0x76543210,
                ebx: 0xfedcba98,
                ecx: 0x13572468,
                edx: 0xabcd1234,
            };
            let mut cpu = returned.clone();
            cpu.registers.rip += 2;
            cpu.registers.rax = 0x76543210;
            cpu.registers.rbx = 0xfedcba98;
            cpu.registers.rcx = 0x13572468;
            cpu.registers.rdx = 0xabcd1234;
            complete(
                owner,
                &input,
                ProviderDecision::Complete(result),
                &cpu,
                until,
            );
            let second = pending(owner, until);
            let mut after_nop = cpu.clone();
            after_nop.registers.rip += 1;
            after_nop.registers.orig_rax = u64::MAX;
            assert_eq!(support::observe_state(owner, until), after_nop);
            assert_eq!(second.input.registers(), &after_nop.registers);
            let runtime = owner.runtime.as_ref().unwrap();
            assert_eq!(
                &runtime.census.as_ref().unwrap().history()[..kernel_history.len()],
                kernel_history
            );
            assert_eq!(runtime.stack.as_ref().unwrap().count, 2);
            ledger::check(owner, 1);
            assert_eq!(original.read_stack(owner, until), pushed);
            original.require_source(owner, until);
            assert_eq!(after_nop.registers.r12, initial_state.registers.r12);
            retention::retained(owner)
        },
        |owner, retained| {
            retained(owner);
            ledger::check(owner, 1);
        },
    );
}

fn no_effects(owner: &Owner) {
    let runtime = owner.runtime.as_ref().unwrap();
    if let Some(stack) = &runtime.stack {
        for attempt in stack.attempts.iter().flatten() {
            let p = attempt.native.progress();
            assert_eq!(p.waits, [None; 7]);
            assert!(p.effects().is_empty());
            assert!(!p.instruction_completed && !p.nx_closed);
            assert!(!attempt.native.diagnostics().claimed);
        }
    }
}
pub(super) fn refusals() {
    // Each excluded encoding is an actual captured instruction. No accepted
    // alternative or provider result is substituted for a refusal.
    let cases: &[(&[u8], bool, &str)] = &[
        (
            &[0xe8, 0xfb, 0, 0, 0],
            false,
            "runtime ordinary stack footprint is unqualified",
        ),
        (
            &[0xff, 0xd0],
            true,
            "runtime ordinary stack footprint is unqualified",
        ),
        (
            &[0xff, 0x10],
            true,
            "runtime ordinary stack footprint is unqualified",
        ),
        (
            &[0xf3, 0xe8, 0, 0, 0, 0],
            true,
            "runtime actual instruction is unqualified",
        ),
        (
            &[0xc2, 8, 0],
            true,
            "runtime actual instruction is unqualified",
        ),
        (&[0xcb], true, "runtime actual instruction is unqualified"),
    ];
    for &(code, opt_in, reason) in cases {
        let program = Program::literal(4096, code);
        let _ = support::with_owner(
            &program,
            true,
            |owner, initial, until, original| {
                let options = if opt_in {
                    support::options()
                } else {
                    DynamicRuntimeOptions::default()
                };
                let before = support::begin(owner, initial, until, original, options);
                let history = owner
                    .runtime
                    .as_ref()
                    .unwrap()
                    .census
                    .as_ref()
                    .unwrap()
                    .history()
                    .to_vec();
                let result = support::invoke(owner, AdmissionRequest::Advance, until);
                assert!(matches!(result,Err(GateError::Refused(actual)) if actual==reason));
                assert_eq!(support::observe_state(owner, until), before);
                assert_eq!(
                    original.read_stack(owner, until),
                    *original.stack.as_ref().unwrap()
                );
                assert_eq!(
                    owner
                        .runtime
                        .as_ref()
                        .unwrap()
                        .census
                        .as_ref()
                        .unwrap()
                        .history(),
                    history
                );
                no_effects(owner);
                if !owner.runtime.as_ref().unwrap().ordinary_attempts.is_empty() {
                    crate::linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::assert_unreleased(owner.runtime.as_ref().unwrap(), &[false]);
                }
                assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                retention::retained(owner)
            },
            |owner, retained| retained(owner),
        );
    }
    // Literal direct CALL to zero, real RET of the initial argc word, and an
    // actual ordinary MOV placing RSP below the original stack.
    for mode in 0..3 {
        let mut code = Vec::new();
        if mode == 2 {
            code.extend_from_slice(&[0x48, 0xbc, 0x00, 0x10, 0, 0, 0, 0, 0, 0]);
        }
        if mode == 1 {
            code.push(0xc3);
        } else {
            let next = BASE + 4096 + code.len() as u64 + 5;
            let target = if mode == 0 { 0 } else { CALLEE };
            code.push(0xe8);
            code.extend_from_slice(
                &i32::try_from(target as i64 - next as i64)
                    .unwrap()
                    .to_le_bytes(),
            );
        }
        let program = Program::literal(4096, &code);
        let _ = support::with_owner(
            &program,
            true,
            |owner, initial, until, original| {
                let mut before =
                    support::begin(owner, initial, until, original, support::options());
                if mode == 1 {
                    let bytes = memory(owner.pid, before.registers.rsp, 8);
                    assert_eq!(u64::from_le_bytes(bytes.try_into().unwrap()), 1);
                }
                if mode == 2 {
                    support::ordinary(owner, until);
                    before.registers.rsp = 4096;
                    before.registers.rip += 10;
                    assert_eq!(support::observe_state(owner, until), before);
                }
                let history = owner
                    .runtime
                    .as_ref()
                    .unwrap()
                    .census
                    .as_ref()
                    .unwrap()
                    .history()
                    .to_vec();
                let result = support::invoke(owner, AdmissionRequest::Advance, until);
                if mode == 0 {
                    assert!(matches!(
                        result,
                        Err(GateError::Refused(
                            "runtime stack continuation is outside the original profile"
                        ))
                    ));
                } else {
                    assert!(matches!(
                        result,
                        Err(GateError::Control(LaunchError::Invalid(
                            "owned stack captured evidence is outside the qualified profile"
                        )))
                    ));
                }
                assert_eq!(support::observe_state(owner, until), before);
                assert_eq!(
                    owner
                        .runtime
                        .as_ref()
                        .unwrap()
                        .census
                        .as_ref()
                        .unwrap()
                        .history(),
                    history
                );
                no_effects(owner);
                assert_eq!(
                    original.read_stack(owner, until),
                    *original.stack.as_ref().unwrap()
                );
                retention::retained(owner)
            },
            |owner, retained| retained(owner),
        );
    }
    let program = Program::call(4096, false);
    let _ = support::with_owner(
        &program,
        true,
        |owner, initial, until, original| {
            let before = support::begin(owner, initial, until, original, support::options());
            let retained = retention::retained(owner);
            assert!(matches!(
                owner.execute(
                    DynamicRequest::Resume(initial.clone(), DynamicResume::Continue),
                    until
                ),
                Err(LaunchError::Invalid(
                    "raw dynamic requests cannot bypass admission ownership"
                ))
            ));
            assert_eq!(support::observe_state(owner, until), before);
            retained(owner);
            retained
        },
        |owner, retained| retained(owner),
    );
}

pub(super) fn late() {
    for hook in [
        RootIntervention::AfterCallRecordPanic,
        RootIntervention::RefuseClosedObserver,
    ] {
        let program = Program::call(4096, false);
        let _ = support::with_owner(
            &program,
            true,
            |owner, initial, until, original| {
                let before = support::begin(owner, initial, until, original, support::options());
                ledger::install(owner);
                let runtime = owner.runtime.as_mut().unwrap();
                let origin = runtime.initial_origin;
                let history = runtime.census.as_ref().unwrap().history().to_vec();
                runtime.stack.as_mut().unwrap().intervention = Some(hook);
                let result = catch_unwind(AssertUnwindSafe(|| match hook {
                    RootIntervention::AfterCallRecordPanic => {
                        support::invoke_unwind(owner, original, AdmissionRequest::Advance, until)
                    }
                    RootIntervention::RefuseClosedObserver => {
                        support::invoke(owner, AdmissionRequest::Advance, until)
                    }
                }));
                match hook {
                    RootIntervention::AfterCallRecordPanic => {
                        assert_eq!(
                            support::panic_payload(result).downcast_ref::<u32>(),
                            Some(&0x43414c4c)
                        )
                    }
                    RootIntervention::RefuseClosedObserver => assert!(matches!(
                        result.unwrap(),
                        Err(GateError::Control(LaunchError::Invalid(
                            "injected stack closed-source observer refusal"
                        )))
                    )),
                }
                let runtime = owner.runtime.as_ref().unwrap();
                let stack = runtime.stack.as_ref().unwrap();
                let attempt = stack.attempts[0].as_ref().unwrap();
                let native = attempt.native.diagnostics();
                let p = attempt.native.progress();
                assert_eq!(runtime.initial_origin, origin);
                assert_eq!(runtime.census.as_ref().unwrap().history(), history);
                assert!(!native.claimed);
                assert!(attempt.failure.is_some());
                ledger::check(owner, 1);
                match hook {
                    RootIntervention::AfterCallRecordPanic => {
                        assert_eq!(attempt.failure, Some(Failure::Unwound));
                        assert_eq!(p.waits, [None; 7]);
                        assert!(p.effects().is_empty());
                        assert_eq!(support::observe_state(owner, until), before);
                        assert_eq!(
                            original.read_stack(owner, until),
                            *original.stack.as_ref().unwrap()
                        );
                    }
                    RootIntervention::RefuseClosedObserver => {
                        assert!(p.waits.iter().all(Option::is_some));
                        assert_eq!(p.queries_started, [true; 7]);
                        assert!(p.instruction_completed && !p.nx_closed);
                        assert_eq!(native.words[2].association, None);
                        assert!(!native.words[2].complete);
                        assert!(attempt.source.progress[2].complete);
                        assert_eq!(attempt.source.bytes[2], original.source);
                        let expected = compare::successor(&before, CALLEE, true);
                        assert_eq!(support::observe_state(owner, until), expected);
                        assert_eq!(
                            original.read_stack(owner, until),
                            compare::stack_effect(
                                original.stack.as_ref().unwrap(),
                                original.stack_range.start,
                                before.registers.rsp,
                                program.next,
                                true
                            )
                        );
                    }
                }
                assert_eq!(
                    support::observe_maps(owner, until),
                    runtime.sources.runtime_baseline_maps().unwrap()
                );
                original.require_source(owner, until);
                match hook {
                    RootIntervention::AfterCallRecordPanic => {
                        assert!(!owner.closing && owner.cancel.load(Ordering::Acquire));
                    }
                    RootIntervention::RefuseClosedObserver => {
                        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                    }
                }
                retention::retained(owner)
            },
            |owner, retained| {
                // The original conjunction is checked at actual cleanup for
                // early unwinds, and still before cleanup for returned errors.
                assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                retained(owner);
                ledger::check(owner, 1);
            },
        );
    }
}

pub(super) fn budgets() {
    let program = Program::call(4096, false);
    let (startup, charge) = support::with_owner(
        &program,
        true,
        |owner, initial, until, original| {
            support::begin(owner, initial, until, original, support::options());
            let runtime = owner.runtime.as_ref().unwrap();
            (
                runtime.census.as_ref().unwrap().charged(),
                storage::attempt_charge(
                    runtime.sources.window(0).unwrap().snapshot.bytes().len(),
                    true,
                )
                .unwrap(),
            )
        },
        |_, _| {},
    );
    assert_eq!(
        (
            charge.origins,
            charge.witnesses,
            charge.epochs,
            charge.reports,
            charge.plan_history
        ),
        (1, 7, 0, 0, 0)
    );
    for axis in 0..3 {
        let mut options = support::options();
        match axis {
            0 => {
                options.limits.source_fact_bytes =
                    startup.source_fact_bytes + charge.source_fact_bytes - 1
            }
            1 => options.limits.origins = startup.origins + charge.origins - 1,
            _ => options.limits.witnesses = startup.witnesses + charge.witnesses - 1,
        }
        let _ = support::with_owner(
            &program,
            true,
            |owner, initial, until, original| {
                let before = support::begin(owner, initial, until, original, options);
                let runtime = owner.runtime.as_ref().unwrap();
                let census = runtime.census.as_ref().unwrap();
                let actual = census.charged();
                let fresh = storage::attempt_charge(
                    runtime.sources.window(0).unwrap().snapshot.bytes().len(),
                    true,
                )
                .unwrap();
                match axis {
                    0 => assert_eq!(
                        options.limits.source_fact_bytes,
                        actual.source_fact_bytes + fresh.source_fact_bytes - 1
                    ),
                    1 => assert_eq!(options.limits.origins, actual.origins + fresh.origins - 1),
                    _ => assert_eq!(
                        options.limits.witnesses,
                        actual.witnesses + fresh.witnesses - 1
                    ),
                }
                let used = census.used();
                let saved = retention::retained(owner);
                assert!(matches!(
                    support::invoke(owner, AdmissionRequest::Advance, until),
                    Err(GateError::Refused(
                        "dynamic continuation lifetime capacity exhausted"
                    ))
                ));
                assert_eq!(support::observe_state(owner, until), before);
                no_effects(owner);
                saved(owner);
                assert_eq!(
                    owner
                        .runtime
                        .as_ref()
                        .unwrap()
                        .census
                        .as_ref()
                        .unwrap()
                        .used(),
                    used
                );
                saved
            },
            |owner, saved| saved(owner),
        );
    }
    for mode in 0..3 {
        let _ = support::with_owner(
            &program,
            true,
            |owner, initial, until, original| {
                let before = support::begin(owner, initial, until, original, support::options());
                let history = owner
                    .runtime
                    .as_ref()
                    .unwrap()
                    .census
                    .as_ref()
                    .unwrap()
                    .history()
                    .to_vec();
                if mode == 0 {
                    std::thread::sleep(until.saturating_duration_since(Instant::now()));
                }
                if mode == 1 {
                    let mut changed = before.registers;
                    changed.r12 ^= 1;
                    let regs: libc::user_regs_struct = changed.into();
                    raw::checked(
                        libc::PTRACE_SETREGS,
                        owner.pid,
                        0,
                        (&raw const regs) as usize,
                    );
                    assert_eq!(support::observe_state(owner, until).registers, changed);
                }
                if mode == 2 {
                    let address = BASE + 0x1800;
                    let old = memory(owner.pid, address, 8);
                    let mut changed: u64 = u64::from_le_bytes(old.try_into().unwrap());
                    changed ^= 1;
                    raw::checked(
                        libc::PTRACE_POKEDATA,
                        owner.pid,
                        address as usize,
                        changed as usize,
                    );
                    assert_eq!(memory(owner.pid, address, 8), changed.to_le_bytes());
                }
                let result = support::invoke(owner, AdmissionRequest::Advance, until);
                match mode {
                    0 => assert!(matches!(
                        result,
                        Err(GateError::Control(LaunchError::Timeout("dynamic command")))
                    )),
                    1 => assert!(matches!(
                        result,
                        Err(GateError::Refused(
                            "runtime source complete current state differs"
                        ))
                    )),
                    _ => assert!(matches!(
                        result,
                        Err(GateError::Refused(
                            "runtime complete original source window changed"
                        ))
                    )),
                }
                no_effects(owner);
                assert_eq!(
                    owner
                        .runtime
                        .as_ref()
                        .unwrap()
                        .census
                        .as_ref()
                        .unwrap()
                        .history(),
                    history
                );
                // No renewed observation deadline after expiry. Other subcases
                // independently observe their real changed state under the old one.
                if mode != 0 {
                    support::require_diagnostic_held(owner, until);
                    assert_eq!(
                        support::observe_maps(owner, until),
                        owner
                            .runtime
                            .as_ref()
                            .unwrap()
                            .sources
                            .runtime_baseline_maps()
                            .unwrap()
                    );
                }
                retention::retained(owner)
            },
            |owner, retained| retained(owner),
        );
    }
}
