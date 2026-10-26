//! Channel-only exec dispatch tests. Synthetic journal/state observations grant
//! no native EXEC, source publication, lifetime handoff or physical cleanup.
use super::super::super::source::exec_tests as model;
use super::*;

fn exec_fixture<S: DynamicSourceResolver>(
    sources: S,
    state: DynamicAdmissionState,
) -> (
    DynamicSourceSession<crate::selected::NativeProvider, S>,
    Receiver<Command>,
    Arc<AtomicBool>,
) {
    let (mut session, commands, cancel) = fixture(crate::selected::NativeProvider, sources, state);
    session.profile = SourceProfile::Exec {
        profile: model::profile(),
        progress: owner::exec_journal::ExecJournalWriter::new(SESSION).reader(),
    };
    (session, commands, cancel)
}

fn ready(before: &DynamicAdmissionState, next: DynamicTask) -> DynamicAdmissionState {
    let mut state = before.clone();
    state.task = next;
    state.registers.rip = SOURCE;
    state.registers.rax = 0;
    state.registers.orig_rax = u64::MAX;
    state.xstate.fill(0xa6);
    state
}

fn replacement(before: &DynamicAdmissionState, next: DynamicTask) -> DynamicAdmissionEvent {
    DynamicAdmissionEvent::ImageReplaced(Box::new(DynamicImageReplacement {
        before: before.clone(),
        ready: ready(before, next),
        input: pending(before).input,
        attempt: KernelAttemptId {
            session: SESSION,
            invocation: 13,
        },
    }))
}

fn begin_exec(
    commands: &Receiver<Command>,
    before: &DynamicAdmissionState,
    next: DynamicTask,
) -> (Instant, Command, DynamicSourceRequest) {
    let (until, complete, _) = begin(commands, before);
    (
        until,
        complete,
        model::request(&pending(before).token, next, until),
    )
}

#[test]
fn exec_callbacks_share_caller_thread_and_original_deadline_and_return_distinct_event() {
    let (previous, next) = model::identities();
    let before = model::state(previous);
    let client = std::thread::current().id();
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let source_calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&provider_calls);
    let expected = pending(&before).input;
    let provider = Provider(move |input: &SelectedInput| {
        assert_eq!(std::thread::current().id(), client);
        assert_eq!(input, &expected);
        assert_eq!(counted.fetch_add(1, Ordering::AcqRel), 0);
        Ok(ProviderDecision::Native)
    });
    let counted = Arc::clone(&source_calls);
    let resolver = Resolver(move |capture: &DynamicSourceRequest| {
        assert_eq!(std::thread::current().id(), client);
        assert_eq!(counted.fetch_add(1, Ordering::AcqRel), 0);
        assert_eq!(capture.transition(), DynamicSourceTransition::Exec);
        assert_eq!(capture.previous_task(), previous);
        assert_eq!(capture.task(), next);
        assert_eq!(
            (capture.previous_epoch(), capture.candidate_epoch()),
            (7, 0)
        );
        assert_eq!(capture.images()[0].bytes(), vec![0x90; 4096]);
        Ok(facts(capture))
    });
    let (mut session, commands, cancel) = fixture(provider, resolver, before.clone());
    assert!(session.exec_progress().is_none());
    session.profile = SourceProfile::Exec {
        profile: model::profile(),
        progress: owner::exec_journal::ExecJournalWriter::new(SESSION).reader(),
    };
    assert!(session.exec_progress().is_some());
    let for_owner = before.clone();
    let script = owner(commands, move |commands| {
        let (until, complete, capture) = begin_exec(commands, &for_owner, next);
        let token = capture.token.clone();
        let expected_facts = facts(&capture);
        respond(complete, AdmissionReply::AcquireSources(Box::new(capture)));
        let resolved = receive(commands);
        assert_eq!(resolved.until, until);
        match &resolved.request {
            Request::Admission(value) => match &**value {
                AdmissionRequest::ResolveSources {
                    token: actual,
                    facts,
                } => {
                    assert_eq!(actual, &token);
                    assert_eq!(actual.until, until);
                    assert_eq!(facts, &expected_facts);
                }
                _ => panic!("exec source resolution changed phase"),
            },
            _ => panic!("exec wrapper exposed raw authority"),
        }
        respond(
            resolved,
            AdmissionReply::Event(replacement(&for_owner, next)),
        );
    });
    let DynamicAdmissionEvent::ImageReplaced(actual) = session.next_event().unwrap() else {
        panic!("exec did not return distinct image replacement")
    };
    assert_eq!(actual.before, before);
    assert_eq!(actual.ready, ready(&before, next));
    assert_eq!(actual.input, pending(&before).input);
    assert_eq!(
        actual.attempt,
        KernelAttemptId {
            session: SESSION,
            invocation: 13
        }
    );
    assert_eq!(provider_calls.load(Ordering::Acquire), 1);
    assert_eq!(source_calls.load(Ordering::Acquire), 1);
    assert!(!session.is_closed() && !cancel.load(Ordering::Acquire));
    no_followup(&owner_finished(script));
}

#[test]
fn stale_cross_kind_or_foreign_exec_capture_cannot_reach_resolver() {
    for row in 0..10 {
        let (previous, next) = model::identities();
        let mut before = model::state(previous);
        before.registers.rax = match row {
            6 => libc::SYS_getpid as u64,
            7 => (libc::SYS_execve as u64) | (1 << 30),
            8 => libc::SYS_execveat as u64,
            9 => (libc::SYS_execve as u64) | (1 << 32),
            _ => libc::SYS_execve as u64,
        };
        let resolver = Resolver(
            |_: &DynamicSourceRequest| -> Result<DynamicSourceFacts, GateError> {
                panic!("invalid exec capture reached resolver")
            },
        );
        let (mut session, commands, cancel) = exec_fixture(resolver, before.clone());
        let script = owner(commands, move |commands| {
            let (until, complete, mut capture) = begin_exec(commands, &before, next);
            match row {
                0 => capture.token.original.invocation += 1,
                1 => capture.token.until += Duration::from_nanos(1),
                2 => capture.token.candidate_epoch = 1,
                3 => capture.token.task = previous,
                4 => capture.token.transition = SourceTransitionBinding::Mapping,
                5 => capture.token.capture_stop.sequence += 1,
                6..=9 => {}
                _ => unreachable!(),
            }
            assert_eq!(
                capture.expires_at(),
                if row == 1 {
                    until + Duration::from_nanos(1)
                } else {
                    until
                }
            );
            respond(complete, AdmissionReply::AcquireSources(Box::new(capture)));
        });
        let reason = if row < 6 {
            "dynamic exec source request binding differs"
        } else {
            "source acquisition lacks an original native exec request"
        };
        assert!(
            matches!(session.next_event(), Err(GateError::Refused(actual)) if actual == reason)
        );
        closed(&mut session, &cancel);
        no_followup(&owner_finished(script));
    }
}

#[test]
fn exec_replacement_requires_source_roundtrip_and_exact_final_invocation_identity() {
    for row in 0..8 {
        let (previous, next) = model::identities();
        let before = model::state(previous);
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let resolver = Resolver(move |capture: &DynamicSourceRequest| {
            counted.fetch_add(1, Ordering::AcqRel);
            Ok(facts(capture))
        });
        let (mut session, commands, cancel) = exec_fixture(resolver, before.clone());
        let script = owner(commands, move |commands| {
            if row == 0 {
                let advance = receive(commands);
                respond(advance, AdmissionReply::Event(replacement(&before, next)));
                return;
            }
            let (_, complete, capture) = begin_exec(commands, &before, next);
            if row == 1 {
                respond(complete, AdmissionReply::Event(replacement(&before, next)));
                return;
            }
            respond(complete, AdmissionReply::AcquireSources(Box::new(capture)));
            let resolved = receive(commands);
            if row == 2 {
                respond(resolved, AdmissionReply::Event(event(&before)));
                return;
            }
            let mut changed = replacement(&before, next);
            let DynamicAdmissionEvent::ImageReplaced(value) = &mut changed else {
                unreachable!()
            };
            match row {
                3 => value.before.task = next,
                4 => value.before.registers.rbx ^= 1,
                5 => value.ready.task.generation = 1,
                6 => value.attempt.invocation += 1,
                7 => value.input = pending(&state()).input,
                _ => unreachable!(),
            }
            respond(resolved, AdmissionReply::Event(changed));
        });
        let reason = match row {
            0 => "image replacement lacks its pending exec acquisition",
            1 => "exec completion lacks source acquisition",
            2 => "exec source reply lacks image replacement",
            _ => "image replacement binding differs",
        };
        assert!(
            matches!(session.next_event(), Err(GateError::Refused(actual)) if actual == reason)
        );
        assert_eq!(calls.load(Ordering::Acquire), usize::from(row >= 2));
        closed(&mut session, &cancel);
        no_followup(&owner_finished(script));
    }
}

#[test]
fn exec_source_error_panic_and_cancellation_keep_original_failure_and_no_commit() {
    for row in 0..3 {
        let (previous, next) = model::identities();
        let before = model::state(previous);
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let trigger = Arc::new(std::sync::Mutex::new(None::<Arc<AtomicBool>>));
        let callback_trigger = Arc::clone(&trigger);
        let resolver = Resolver(move |capture: &DynamicSourceRequest| {
            counted.fetch_add(1, Ordering::AcqRel);
            match row {
                0 => Err(GateError::Refused("intentional exec source refusal")),
                1 => std::panic::panic_any("intentional exec source panic"),
                2 => {
                    callback_trigger
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .store(true, Ordering::Release);
                    Ok(facts(capture))
                }
                _ => unreachable!(),
            }
        });
        let (mut session, commands, cancel) = exec_fixture(resolver, before.clone());
        *trigger.lock().unwrap() = Some(Arc::clone(&cancel));
        let script = owner(commands, move |commands| {
            let (_, complete, capture) = begin_exec(commands, &before, next);
            respond(complete, AdmissionReply::AcquireSources(Box::new(capture)));
        });
        let outcome = catch_unwind(AssertUnwindSafe(|| session.next_event()));
        match row {
            0 => assert!(matches!(
                outcome,
                Ok(Err(GateError::Refused("intentional exec source refusal")))
            )),
            1 => assert_eq!(
                outcome.unwrap_err().downcast_ref::<&str>(),
                Some(&"intentional exec source panic")
            ),
            2 => assert!(matches!(
                outcome,
                Ok(Err(GateError::Control(LaunchError::Timeout(
                    "dynamic source acquisition"
                ))))
            )),
            _ => unreachable!(),
        }
        assert_eq!(calls.load(Ordering::Acquire), 1);
        closed(&mut session, &cancel);
        no_followup(&owner_finished(script));
    }
}

#[test]
fn exec_malformed_heads_or_second_acquisition_never_become_image_completion() {
    for row in 0..2 {
        let (previous, next) = model::identities();
        let before = model::state(previous);
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let resolver = Resolver(move |capture: &DynamicSourceRequest| {
            counted.fetch_add(1, Ordering::AcqRel);
            let mut result = facts(capture);
            if row == 0 {
                result.images[0].capture.request.serial += 1;
            }
            Ok(result)
        });
        let (mut session, commands, cancel) = exec_fixture(resolver, before.clone());
        let script = owner(commands, move |commands| {
            let (until, complete, capture) = begin_exec(commands, &before, next);
            respond(complete, AdmissionReply::AcquireSources(Box::new(capture)));
            if row == 1 {
                let resolved = receive(commands);
                assert_eq!(resolved.until, until);
                respond(
                    resolved,
                    AdmissionReply::AcquireSources(Box::new(model::request(
                        &pending(&before).token,
                        next,
                        until,
                    ))),
                );
            }
        });
        let reason = if row == 0 {
            "dynamic source reply image set differs"
        } else {
            "source reply did not finish its pending acquisition"
        };
        assert!(
            matches!(session.next_event(), Err(GateError::Refused(actual)) if actual == reason)
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        closed(&mut session, &cancel);
        no_followup(&owner_finished(script));
    }
}

#[test]
fn exec_expired_or_cancelled_provider_boundary_has_no_callback_effect() {
    let (previous, _) = model::identities();
    let before = model::state(previous);
    for cancelled in [false, true] {
        let resolver = Resolver(
            |_: &DynamicSourceRequest| -> Result<DynamicSourceFacts, GateError> {
                panic!("resolver called past exec deadline")
            },
        );
        let provider = Provider(
            |_: &SelectedInput| -> Result<ProviderDecision, SemanticsError> {
                panic!("provider called past exec deadline")
            },
        );
        let (mut session, commands, cancel) = fixture(provider, resolver, before.clone());
        session.profile = SourceProfile::Exec {
            profile: model::profile(),
            progress: owner::exec_journal::ExecJournalWriter::new(SESSION).reader(),
        };
        cancel.store(cancelled, Ordering::Release);
        let until = if cancelled {
            Instant::now() + TIMEOUT
        } else {
            Instant::now()
        };
        assert!(matches!(
            session.finish_advance(
                AdmissionReply::Provider(Box::new(pending(&before))),
                until,
                until,
            ),
            Err(GateError::Control(LaunchError::Timeout(
                "dynamic admission provider"
            )))
        ));
        no_followup(&commands);
    }
}
