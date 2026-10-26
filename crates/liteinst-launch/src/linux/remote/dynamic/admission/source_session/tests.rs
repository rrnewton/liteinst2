//! Channel-only controls. Synthetic observations below are never native mapping,
//! syscall, publication, head-completeness or physical-cleanup evidence.
use super::super::source::tests::{SESSION, SOURCE, facts, pending, profile, request, state};
use super::*;
use crate::selected::SemanticsError;
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::TryRecvError;

const TIMEOUT: Duration = Duration::from_secs(3);

struct Provider<F>(F);
impl<F: FnMut(&SelectedInput) -> Result<ProviderDecision, SemanticsError>> InstructionProvider
    for Provider<F>
{
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        (self.0)(input)
    }
}
struct Resolver<F>(F);
impl<F: FnMut(&DynamicSourceRequest) -> Result<DynamicSourceFacts, GateError>> DynamicSourceResolver
    for Resolver<F>
{
    fn resolve(&mut self, request: &DynamicSourceRequest) -> Result<DynamicSourceFacts, GateError> {
        (self.0)(request)
    }
}

fn fixture<P: InstructionProvider, S: DynamicSourceResolver>(
    provider: P,
    sources: S,
    state: DynamicAdmissionState,
) -> (
    DynamicSourceSession<P, S>,
    Receiver<Command>,
    Arc<AtomicBool>,
) {
    let (commands, receiver) = channel();
    let (_finished, done) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let session = DynamicSession {
        pid: 101,
        initial: DynamicEvent {
            tid: 101,
            task: Some(state.task),
            kind: DynamicEventKind::Interrupted,
            stop: Some(pending(&state).token.stop),
        },
        commands,
        cancel: Arc::clone(&cancel),
        done,
        operation_timeout: TIMEOUT,
    };
    (
        DynamicSourceSession {
            inner: DynamicAdmissionSession {
                session,
                provider,
                initial: state,
                kernel_progress: owner::kernel_journal::KernelJournalWriter::new(SESSION).reader(),
                timeout: TIMEOUT,
                closed: false,
            },
            sources,
            profile: SourceProfile::Mapping(profile()),
        },
        receiver,
        cancel,
    )
}

fn event(state: &DynamicAdmissionState) -> DynamicAdmissionEvent {
    DynamicAdmissionEvent::Lifecycle(DynamicEvent {
        tid: 101,
        task: Some(state.task),
        kind: DynamicEventKind::Interrupted,
        stop: None,
    })
}

type OwnerOutcome = Result<Receiver<Command>, Box<dyn Any + Send>>;
struct MockOwner {
    done: Receiver<OwnerOutcome>,
    thread: std::thread::JoinHandle<()>,
}
fn owner(
    commands: Receiver<Command>,
    action: impl FnOnce(&Receiver<Command>) + Send + 'static,
) -> MockOwner {
    let (finished, done) = channel();
    let thread = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| action(&commands))).map(|()| commands);
        let _ = finished.send(result);
    });
    MockOwner { done, thread }
}
fn owner_finished(owner: MockOwner) -> Receiver<Command> {
    let result = owner
        .done
        .recv_timeout(TIMEOUT)
        .expect("bounded channel-only owner completion");
    owner.thread.join().expect("mock owner panic escaped catch");
    match result {
        Ok(commands) => commands,
        Err(payload) => resume_unwind(payload),
    }
}
fn receive(commands: &Receiver<Command>) -> Command {
    commands
        .recv_timeout(TIMEOUT)
        .expect("bounded mock owner request")
}
fn respond(command: Command, reply: AdmissionReply) {
    assert!(
        command
            .reply
            .send(Ok(Response::Admission(Box::new(Ok(reply)))))
            .is_ok()
    );
}
fn begin(
    commands: &Receiver<Command>,
    state: &DynamicAdmissionState,
) -> (Instant, Command, DynamicSourceRequest) {
    let advance = receive(commands);
    assert!(
        matches!(&advance.request, Request::Admission(request) if matches!(&**request, AdmissionRequest::Advance))
    );
    let until = advance.until;
    let expected = pending(state);
    respond(
        advance,
        AdmissionReply::Provider(Box::new(expected.clone())),
    );
    let complete = receive(commands);
    assert_eq!(complete.until, until);
    match &complete.request {
        Request::Admission(value) => match &**value {
            AdmissionRequest::Complete { token, decision } => {
                assert_eq!(token, &expected.token);
                assert_eq!(*decision, ProviderDecision::Native);
            }
            _ => panic!("original Complete phase missing"),
        },
        _ => panic!("raw control escaped source wrapper"),
    }
    (until, complete, request(&expected.token, until))
}
fn no_followup(commands: &Receiver<Command>) {
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}
fn closed<P: InstructionProvider, S: DynamicSourceResolver>(
    session: &mut DynamicSourceSession<P, S>,
    cancel: &AtomicBool,
) {
    assert!(session.is_closed());
    assert!(cancel.load(Ordering::Acquire));
    assert!(matches!(
        session.next_event(),
        Err(GateError::Refused("dynamic admission session is closed"))
    ));
}

#[test]
fn source_callback_and_instruction_provider_share_client_thread_and_original_deadline() {
    let model = state();
    let client = std::thread::current().id();
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let source_calls = Arc::new(AtomicUsize::new(0));
    let pc = Arc::clone(&provider_calls);
    let sc = Arc::clone(&source_calls);
    let expected_input = pending(&model).input;
    let provider = Provider(move |input: &SelectedInput| {
        assert_eq!(std::thread::current().id(), client);
        assert_eq!(input, &expected_input);
        assert_eq!(pc.fetch_add(1, Ordering::AcqRel), 0);
        Ok(ProviderDecision::Native)
    });
    let resolver = Resolver(move |capture: &DynamicSourceRequest| {
        assert_eq!(std::thread::current().id(), client);
        assert_eq!(sc.fetch_add(1, Ordering::AcqRel), 0);
        assert_eq!(
            (capture.previous_epoch(), capture.candidate_epoch()),
            (0, 1)
        );
        assert_eq!(capture.images()[0].range(), SOURCE..SOURCE + 4096);
        assert_eq!(capture.images()[0].bytes(), vec![0x90; 4096]);
        assert_eq!(capture.images()[0].original_mapping().permissions, "r-xp");
        assert_eq!(
            capture.images()[0].quarantined_mapping().permissions,
            "r--p"
        );
        assert_eq!(
            capture.kernel_attempt(),
            KernelAttemptId {
                session: SESSION,
                invocation: 13
            }
        );
        Ok(facts(capture))
    });
    let (mut session, commands, cancel) = fixture(provider, resolver, model.clone());
    let for_owner = model.clone();
    let script = owner(commands, move |commands| {
        let (until, complete, capture) = begin(commands, &for_owner);
        let expected_token = capture.token.clone();
        let expected_facts = facts(&capture);
        respond(complete, AdmissionReply::AcquireSources(Box::new(capture)));
        let resolved = receive(commands);
        assert_eq!(resolved.until, until);
        match &resolved.request {
            Request::Admission(value) => match &**value {
                AdmissionRequest::ResolveSources { token, facts } => {
                    assert_eq!(token, &expected_token);
                    assert_eq!(facts, &expected_facts);
                    assert_eq!(token.until, until);
                }
                _ => panic!("source answer replaced by another operation"),
            },
            _ => panic!("raw source authority escaped"),
        }
        respond(resolved, AdmissionReply::Event(event(&for_owner)));
    });
    let DynamicAdmissionEvent::Lifecycle(result) = session.next_event().unwrap() else {
        panic!("model event missing")
    };
    assert_eq!(result.task, Some(model.task));
    assert_eq!(result.tid, 101);
    assert!(result.stop_token().is_none());
    assert_eq!(provider_calls.load(Ordering::Acquire), 1);
    assert_eq!(source_calls.load(Ordering::Acquire), 1);
    assert!(!session.is_closed() && !cancel.load(Ordering::Acquire));
    no_followup(&owner_finished(script));
}

#[test]
fn ordinary_events_and_direct_completions_never_invoke_source_resolution() {
    let model = state();
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&provider_calls);
    let provider = Provider(move |_: &SelectedInput| {
        counted.fetch_add(1, Ordering::AcqRel);
        Ok(ProviderDecision::Native)
    });
    let resolver = Resolver(
        |_: &DynamicSourceRequest| -> Result<DynamicSourceFacts, GateError> {
            panic!("unexpected source callback")
        },
    );
    let (mut session, commands, cancel) = fixture(provider, resolver, model.clone());
    let script = owner(commands, move |commands| {
        let advance = receive(commands);
        assert!(
            matches!(&advance.request, Request::Admission(value) if matches!(&**value, AdmissionRequest::Advance))
        );
        respond(advance, AdmissionReply::Event(event(&model)));
        let (_, complete, _) = begin(commands, &model);
        respond(complete, AdmissionReply::Event(event(&model)));
    });
    assert!(matches!(
        session.next_event(),
        Ok(DynamicAdmissionEvent::Lifecycle(_))
    ));
    assert!(matches!(
        session.next_event(),
        Ok(DynamicAdmissionEvent::Lifecycle(_))
    ));
    assert_eq!(provider_calls.load(Ordering::Acquire), 1);
    assert!(!cancel.load(Ordering::Acquire));
    no_followup(&owner_finished(script));
}

#[test]
fn contradictory_or_stale_acquisitions_refuse_before_resolver_or_resolve_command() {
    for row in 0..6 {
        let mut model = state();
        if row == 4 {
            model.registers.rax = libc::SYS_getpid as u64;
        }
        if row == 5 {
            model.registers.rdx = (libc::PROT_READ | libc::PROT_WRITE) as u64;
        }
        let provider = Provider(|_: &SelectedInput| Ok(ProviderDecision::Native));
        let resolver = Resolver(
            |_: &DynamicSourceRequest| -> Result<DynamicSourceFacts, GateError> {
                panic!("invalid request reached resolver")
            },
        );
        let (mut session, commands, cancel) = fixture(provider, resolver, model.clone());
        let script = owner(commands, move |commands| {
            let (_, complete, mut capture) = begin(commands, &model);
            match row {
                0 => capture.token.original.invocation += 1,
                1 => capture.token.until += Duration::from_nanos(1),
                2 => capture.token.capture_stop.sequence = capture.token.original.stop.sequence,
                3 => {
                    let image = &mut Arc::get_mut(&mut capture.images).unwrap()[0];
                    image.original.start += 4096;
                    image.original.end += 4096;
                    image.quarantined.start += 4096;
                    image.quarantined.end += 4096;
                }
                4 | 5 => {}
                _ => unreachable!(),
            }
            respond(complete, AdmissionReply::AcquireSources(Box::new(capture)));
        });
        let expected = match row {
            3 => "source capture differs from original mapping range",
            4 | 5 => "source acquisition lacks an original native RX mapping request",
            _ => "dynamic source request binding differs",
        };
        assert!(
            matches!(session.next_event(), Err(GateError::Refused(actual)) if actual == expected)
        );
        closed(&mut session, &cancel);
        no_followup(&owner_finished(script));
    }
}

#[test]
fn source_error_panic_and_post_callback_cancellation_preserve_failure_and_close() {
    for row in 0..3 {
        let model = state();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let trigger = Arc::new(std::sync::Mutex::new(None::<Arc<AtomicBool>>));
        let callback_trigger = Arc::clone(&trigger);
        let resolver = Resolver(move |capture: &DynamicSourceRequest| {
            counted.fetch_add(1, Ordering::AcqRel);
            match row {
                0 => Err(GateError::Refused("intentional source refusal")),
                1 => std::panic::panic_any("intentional source panic"),
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
        let (mut session, commands, cancel) = fixture(
            Provider(|_: &SelectedInput| Ok(ProviderDecision::Native)),
            resolver,
            model.clone(),
        );
        *trigger.lock().unwrap() = Some(Arc::clone(&cancel));
        let script = owner(commands, move |commands| {
            let (_, complete, capture) = begin(commands, &model);
            respond(complete, AdmissionReply::AcquireSources(Box::new(capture)));
        });
        let outcome = catch_unwind(AssertUnwindSafe(|| session.next_event()));
        match row {
            0 => assert!(matches!(
                outcome,
                Ok(Err(GateError::Refused("intentional source refusal")))
            )),
            1 => assert_eq!(
                outcome.unwrap_err().downcast_ref::<&str>(),
                Some(&"intentional source panic")
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
fn malformed_head_reply_never_reaches_owner_commit_and_second_acquisition_is_not_retried() {
    for row in 0..2 {
        let model = state();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let resolver = Resolver(move |capture: &DynamicSourceRequest| {
            counted.fetch_add(1, Ordering::AcqRel);
            let mut result = facts(capture);
            if row == 0 {
                result.images[0].heads.insert(SOURCE + 4096);
            }
            Ok(result)
        });
        let (mut session, commands, cancel) = fixture(
            Provider(|_: &SelectedInput| Ok(ProviderDecision::Native)),
            resolver,
            model.clone(),
        );
        let script = owner(commands, move |commands| {
            let (until, complete, capture) = begin(commands, &model);
            respond(complete, AdmissionReply::AcquireSources(Box::new(capture)));
            if row == 1 {
                let resolve = receive(commands);
                assert_eq!(resolve.until, until);
                assert!(
                    matches!(&resolve.request, Request::Admission(value) if matches!(&**value, AdmissionRequest::ResolveSources { .. }))
                );
                respond(
                    resolve,
                    AdmissionReply::AcquireSources(Box::new(request(
                        &pending(&model).token,
                        until,
                    ))),
                );
            }
        });
        let expected = if row == 0 {
            "dynamic source reply head lies outside capture"
        } else {
            "source reply did not finish its pending acquisition"
        };
        assert!(
            matches!(session.next_event(), Err(GateError::Refused(actual)) if actual == expected)
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        closed(&mut session, &cancel);
        no_followup(&owner_finished(script));
    }
}

#[test]
fn expired_or_cancelled_callback_boundary_has_no_provider_effect_or_followup() {
    let model = state();
    for cancelled in [false, true] {
        let provider = Provider(
            |_: &SelectedInput| -> Result<ProviderDecision, SemanticsError> {
                panic!("provider ran after expiry")
            },
        );
        let resolver = Resolver(
            |_: &DynamicSourceRequest| -> Result<DynamicSourceFacts, GateError> {
                panic!("resolver ran after expiry")
            },
        );
        let (mut session, commands, cancel) = fixture(provider, resolver, model.clone());
        cancel.store(cancelled, Ordering::Release);
        let until = if cancelled {
            Instant::now() + TIMEOUT
        } else {
            Instant::now()
        };
        assert!(matches!(
            session.finish_advance(
                AdmissionReply::Provider(Box::new(pending(&model))),
                until,
                until
            ),
            Err(GateError::Control(LaunchError::Timeout(
                "dynamic admission provider"
            )))
        ));
        no_followup(&commands);
    }
}

mod exec;
