//! Channel-only transport tests. Registry-created identities and initialized
//! register data below are synthetic inputs, never native stop, exclusion,
//! instruction, cleanup or publication evidence. No process is launched.

use super::*;
use crate::gate::SelectedExecution;
use crate::lifecycle::{LifecycleRegistry, Limits};
use crate::selected::{InstructionFault, SelectedResult, SemanticsError, SyscallAliases, decode};
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind, panic_any, resume_unwind};
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};

const TIMEOUT: Duration = Duration::from_secs(3);
const PC: u64 = 0x401000;
const SESSION: u64 = 41;
const PANIC: &str = "intentional admission provider panic";
const RESULT: SelectedResult = SelectedResult::Cpuid {
    eax: 7,
    ebx: 11,
    ecx: 13,
    edx: 17,
};

struct Provider<F>(F);
impl<F> InstructionProvider for Provider<F>
where
    F: FnMut(&SelectedInput) -> Result<ProviderDecision, SemanticsError>,
{
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        (self.0)(input)
    }
}

fn state() -> DynamicAdmissionState {
    let registry = LifecycleRegistry::new(
        Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 1,
            obligations: 8,
        },
        101,
        PC,
    )
    .unwrap();
    let task = registry.root_task();
    let record = registry.task(task).unwrap();
    // All fields of user_regs_struct are integers; zero initializes every one.
    // This is channel payload data, not an observation of a native process.
    let mut raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    raw.rip = PC;
    raw.cs = 0x33;
    raw.eflags = 0x202;
    raw.rsp = 0x600000;
    raw.orig_rax = u64::MAX;
    DynamicAdmissionState {
        task: DynamicTask {
            task,
            process: record.process,
            address_space: record.address_space,
            generation: 0,
        },
        registers: raw.into(),
        xstate: vec![0x5a; 832],
        signal_mask: 0x200,
    }
}

fn stop(state: &DynamicAdmissionState) -> DynamicStop {
    DynamicStop {
        session: SESSION,
        sequence: 3,
        tid: 101,
        task: Some(state.task.task),
    }
}

fn pending(state: &DynamicAdmissionState) -> ProviderInput {
    ProviderInput {
        token: PendingToken {
            stop: stop(state),
            task: state.task,
            epoch: 7,
            plan: 11,
            invocation: 13,
        },
        input: SelectedInput::new(
            decode(PC, &[0x0f, 0xa2], &SyscallAliases::default()).unwrap(),
            state.registers,
        )
        .unwrap(),
    }
}

fn completed(state: &DynamicAdmissionState) -> DynamicAdmissionEvent {
    let input = pending(state).input;
    let after = input.complete(RESULT).unwrap().after;
    DynamicAdmissionEvent::Completed(Box::new(DynamicAdmissionCompletion {
        before_task: state.task,
        after_task: state.task,
        selected: SelectedCompletion {
            input,
            after,
            before_xstate: state.xstate.clone(),
            xstate: state.xstate.clone(),
            execution: SelectedExecution::Scripted,
        },
        before_signal_mask: state.signal_mask,
        signal_mask: state.signal_mask,
    }))
}

fn fixture<P: InstructionProvider>(
    provider: P,
    state: DynamicAdmissionState,
) -> (
    DynamicAdmissionSession<P>,
    Receiver<Command>,
    Arc<AtomicBool>,
) {
    let (commands, receiver) = channel();
    let (_done_sender, done) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let initial = DynamicEvent {
        tid: 101,
        task: Some(state.task),
        kind: DynamicEventKind::Interrupted,
        stop: Some(stop(&state)),
    };
    let session = DynamicSession {
        pid: 101,
        initial,
        commands,
        cancel: Arc::clone(&cancel),
        done,
        operation_timeout: TIMEOUT,
    };
    (
        DynamicAdmissionSession {
            session,
            provider,
            initial: state,
            kernel_progress: owner::kernel_journal::KernelJournalWriter::new(SESSION).reader(),
            timeout: TIMEOUT,
            closed: false,
        },
        receiver,
        cancel,
    )
}

type OwnerResult = Result<Receiver<Command>, Box<dyn Any + Send>>;

// Each script has only bounded receives. It returns its command receiver to the
// test, allowing an exact check that no forbidden followup was queued. No join
// or native cleanup is involved; panic payloads are forwarded without relabeling.
fn owner(
    commands: Receiver<Command>,
    script: impl FnOnce(&Receiver<Command>) + Send + 'static,
) -> Receiver<OwnerResult> {
    let (finished, result) = channel();
    let _thread = std::thread::spawn(move || {
        let outcome = catch_unwind(AssertUnwindSafe(|| script(&commands)));
        let _ = finished.send(outcome.map(|()| commands));
    });
    result
}

fn owner_finished(result: Receiver<OwnerResult>) -> Receiver<Command> {
    match result
        .recv_timeout(TIMEOUT)
        .expect("bounded mock-owner completion")
    {
        Ok(commands) => commands,
        Err(payload) => resume_unwind(payload),
    }
}

fn receive(commands: &Receiver<Command>) -> Command {
    commands
        .recv_timeout(TIMEOUT)
        .expect("bounded mock-owner request")
}

fn respond(command: Command, reply: AdmissionReply) {
    assert!(
        command
            .reply
            .send(Ok(Response::Admission(Box::new(Ok(reply)))))
            .is_ok()
    );
}

fn expect_advance(command: &Command) {
    assert!(
        matches!(&command.request, Request::Admission(request) if matches!(&**request, AdmissionRequest::Advance))
    );
}

fn expect_no_followup(commands: &Receiver<Command>) {
    assert!(matches!(commands.try_recv(), Err(TryRecvError::Empty)));
}

fn assert_closed<P: InstructionProvider>(
    session: &mut DynamicAdmissionSession<P>,
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
fn completion_preserves_one_absolute_deadline_and_runs_provider_on_client_thread() {
    let state = state();
    let expected = pending(&state);
    let calls = Arc::new(AtomicUsize::new(0));
    let client = std::thread::current().id();
    let counted = Arc::clone(&calls);
    let expected_input = expected.input.clone();
    let provider = Provider(move |input: &SelectedInput| {
        assert_eq!(std::thread::current().id(), client);
        assert_eq!(input, &expected_input);
        assert_eq!(counted.fetch_add(1, Ordering::AcqRel), 0);
        Ok(ProviderDecision::Complete(RESULT))
    });
    let (mut session, commands, cancel) = fixture(provider, state.clone());
    let reply_state = state.clone();
    let script = owner(commands, move |commands| {
        let advance = receive(commands);
        expect_advance(&advance);
        let until = advance.until;
        assert!(until > Instant::now());
        respond(
            advance,
            AdmissionReply::Provider(Box::new(expected.clone())),
        );
        let complete = receive(commands);
        assert_eq!(complete.until, until);
        match &complete.request {
            Request::Admission(request) => match &**request {
                AdmissionRequest::Complete { token, decision } => {
                    assert_eq!(token, &expected.token);
                    assert_eq!(*decision, ProviderDecision::Complete(RESULT));
                }
                _ => panic!("complete phase was replaced"),
            },
            _ => panic!("raw control request escaped admission"),
        }
        respond(complete, AdmissionReply::Event(completed(&reply_state)));
        let inspection = receive(commands);
        assert!(
            matches!(&inspection.request, Request::Admission(request) if matches!(&**request, AdmissionRequest::State(task) if *task == reply_state.task.task))
        );
        respond(inspection, AdmissionReply::State(reply_state));
    });
    let DynamicAdmissionEvent::Completed(completion) = session.next_event().unwrap() else {
        panic!("missing completion")
    };
    assert_eq!(completion.before_task, state.task);
    assert_eq!(completion.after_task, state.task);
    assert_eq!(completion.selected.input, pending(&state).input);
    assert_eq!(
        completion.selected.after,
        pending(&state).input.complete(RESULT).unwrap().after
    );
    assert_eq!(completion.selected.before_xstate, state.xstate);
    assert_eq!(completion.selected.xstate, state.xstate);
    assert_eq!(completion.before_signal_mask, state.signal_mask);
    assert_eq!(completion.signal_mask, state.signal_mask);
    assert_eq!(completion.selected.execution, SelectedExecution::Scripted);
    assert_eq!(session.state(state.task.task).unwrap(), state);
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert!(!session.is_closed());
    assert!(!cancel.load(Ordering::Acquire));
    let commands = owner_finished(script);
    expect_no_followup(&commands);
    drop(session);
    assert!(cancel.load(Ordering::Acquire));
    assert!(matches!(
        commands.try_recv(),
        Err(TryRecvError::Disconnected)
    ));
}

#[test]
fn provider_panic_keeps_exact_payload_and_cancels_without_complete() {
    let state = state();
    let pending = pending(&state);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let provider = Provider(
        move |_: &SelectedInput| -> Result<ProviderDecision, SemanticsError> {
            counted.fetch_add(1, Ordering::AcqRel);
            panic_any(PANIC);
        },
    );
    let (mut session, commands, cancel) = fixture(provider, state);
    let script = owner(commands, move |commands| {
        let advance = receive(commands);
        expect_advance(&advance);
        respond(advance, AdmissionReply::Provider(Box::new(pending)));
    });
    let panic = catch_unwind(AssertUnwindSafe(|| session.next_event())).unwrap_err();
    assert_eq!(panic.downcast_ref::<&str>(), Some(&PANIC));
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_closed(&mut session, &cancel);
    expect_no_followup(&owner_finished(script));
}

#[test]
fn provider_error_preserves_typed_refusal_and_cancels_without_complete() {
    let state = state();
    let pending = pending(&state);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let provider = Provider(move |_: &SelectedInput| {
        counted.fetch_add(1, Ordering::AcqRel);
        Err(SemanticsError::ScriptMismatch)
    });
    let (mut session, commands, cancel) = fixture(provider, state);
    let script = owner(commands, move |commands| {
        let advance = receive(commands);
        expect_advance(&advance);
        respond(advance, AdmissionReply::Provider(Box::new(pending)));
    });
    assert!(matches!(
        session.next_event(),
        Err(GateError::Selected(SemanticsError::ScriptMismatch))
    ));
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_closed(&mut session, &cancel);
    expect_no_followup(&owner_finished(script));
}

#[test]
fn cancellation_before_provider_reply_prevents_client_callback() {
    let state = state();
    let pending = pending(&state);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let provider = Provider(move |_: &SelectedInput| {
        counted.fetch_add(1, Ordering::AcqRel);
        Ok(ProviderDecision::Complete(RESULT))
    });
    let (mut session, commands, cancel) = fixture(provider, state);
    let owner_cancel = Arc::clone(&cancel);
    let script = owner(commands, move |commands| {
        let advance = receive(commands);
        expect_advance(&advance);
        owner_cancel.store(true, Ordering::Release);
        respond(advance, AdmissionReply::Provider(Box::new(pending)));
    });
    assert!(matches!(
        session.next_event(),
        Err(GateError::Control(LaunchError::Timeout(
            "dynamic admission provider"
        )))
    ));
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert_closed(&mut session, &cancel);
    expect_no_followup(&owner_finished(script));
}

#[test]
fn cancellation_during_provider_prevents_complete_command() {
    let state = state();
    let pending = pending(&state);
    let (send_cancel, callback_cancel) = channel::<Arc<AtomicBool>>();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let provider = Provider(move |_: &SelectedInput| {
        counted.fetch_add(1, Ordering::AcqRel);
        callback_cancel
            .recv_timeout(TIMEOUT)
            .unwrap()
            .store(true, Ordering::Release);
        Ok(ProviderDecision::Complete(RESULT))
    });
    let (mut session, commands, cancel) = fixture(provider, state);
    send_cancel.send(Arc::clone(&cancel)).unwrap();
    let script = owner(commands, move |commands| {
        let advance = receive(commands);
        expect_advance(&advance);
        respond(advance, AdmissionReply::Provider(Box::new(pending)));
    });
    assert!(matches!(
        session.next_event(),
        Err(GateError::Control(LaunchError::Invalid(
            "dynamic session is closing"
        )))
    ));
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_closed(&mut session, &cancel);
    expect_no_followup(&owner_finished(script));
}

#[test]
fn already_queued_provider_reply_after_absolute_expiry_does_not_call_provider() {
    let state = state();
    let pending = pending(&state);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let provider = Provider(move |_: &SelectedInput| {
        counted.fetch_add(1, Ordering::AcqRel);
        Ok(ProviderDecision::Complete(RESULT))
    });
    let (mut session, commands, cancel) = fixture(provider, state);
    let (sender, receiver) = channel();
    // The reply is queued before the receive, and its original deadline is
    // already past. This tests the actual boundary helper, not an OS scheduler.
    let until = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap();
    assert!(
        sender
            .send(AdmissionReply::Provider(Box::new(pending)))
            .is_ok()
    );
    let reply = receiver.recv_timeout(Duration::ZERO).unwrap();
    assert!(Instant::now() >= until);
    assert!(matches!(
        session.finish_advance(reply, until, until),
        Err(GateError::Control(LaunchError::Timeout(
            "dynamic admission provider"
        )))
    ));
    assert_eq!(calls.load(Ordering::Acquire), 0);
    expect_no_followup(&commands);
    // Direct helper use deliberately does not pretend to exercise next_event's
    // outer cancellation guard; the real public panic/error cases do that.
    assert!(!cancel.load(Ordering::Acquire));
}

#[test]
fn provider_return_after_absolute_expiry_cannot_enqueue_completion() {
    let state = state();
    let pending = pending(&state);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let (deadline_sender, deadline_receiver) = channel::<Instant>();
    let provider = Provider(move |_: &SelectedInput| {
        counted.fetch_add(1, Ordering::AcqRel);
        let until = deadline_receiver.recv_timeout(TIMEOUT).unwrap();
        let (_held_sender, no_response) = channel::<()>();
        assert!(matches!(
            no_response.recv_timeout(until.saturating_duration_since(Instant::now())),
            Err(RecvTimeoutError::Timeout)
        ));
        assert!(Instant::now() >= until);
        Ok(ProviderDecision::Complete(RESULT))
    });
    let (mut session, commands, cancel) = fixture(provider, state);
    let until = Instant::now().checked_add(TIMEOUT).unwrap();
    deadline_sender.send(until).unwrap();
    assert!(matches!(
        session.finish_advance(AdmissionReply::Provider(Box::new(pending)), until, until),
        Err(GateError::Control(LaunchError::Timeout(
            "dynamic admission provider"
        )))
    ));
    assert_eq!(calls.load(Ordering::Acquire), 1);
    expect_no_followup(&commands);
    // As above, this helper-only deadline witness makes no outer-guard claim.
    assert!(!cancel.load(Ordering::Acquire));
}

#[test]
fn malformed_inspection_reply_closes_every_public_inspection() {
    for kind in 0..3 {
        let state = state();
        let task = state.task.task;
        let provider = Provider(|_: &SelectedInput| Ok(ProviderDecision::Native));
        let (mut session, commands, cancel) = fixture(provider, state.clone());
        let script = owner(commands, move |commands| {
            let inspection = receive(commands);
            match (&inspection.request, kind) {
                (Request::Admission(request), 0) => assert!(
                    matches!(&**request, AdmissionRequest::State(actual) if *actual == task)
                ),
                (Request::Admission(request), 1) => assert!(
                    matches!(&**request, AdmissionRequest::Memory { task: actual, address: PC, len: 4 } if *actual == task)
                ),
                (Request::Admission(request), 2) => {
                    assert!(matches!(&**request, AdmissionRequest::Metrics))
                }
                _ => panic!("wrong inspection request"),
            }
            respond(
                inspection,
                AdmissionReply::Ready(
                    state,
                    owner::kernel_journal::KernelJournalWriter::new(SESSION).reader(),
                ),
            );
        });
        match kind {
            0 => assert!(matches!(
                session.state(task),
                Err(GateError::Refused("dynamic admission state reply differs"))
            )),
            1 => assert!(matches!(
                session.read_memory(task, PC, 4),
                Err(GateError::Refused("dynamic admission memory reply differs"))
            )),
            2 => assert!(matches!(
                session.metrics(),
                Err(GateError::Refused(
                    "dynamic admission metrics reply differs"
                ))
            )),
            _ => unreachable!(),
        }
        assert_closed(&mut session, &cancel);
        expect_no_followup(&owner_finished(script));
    }
}

#[test]
fn wrong_complete_phases_do_not_reopen_or_invoke_provider_twice() {
    for kind in 0..3 {
        let state = state();
        let pending = pending(&state);
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let provider = Provider(move |_: &SelectedInput| {
            counted.fetch_add(1, Ordering::AcqRel);
            Ok(ProviderDecision::Complete(RESULT))
        });
        let (mut session, commands, cancel) = fixture(provider, state.clone());
        let script = owner(commands, move |commands| {
            let advance = receive(commands);
            expect_advance(&advance);
            respond(advance, AdmissionReply::Provider(Box::new(pending.clone())));
            let complete = receive(commands);
            assert!(
                matches!(&complete.request, Request::Admission(request) if matches!(&**request, AdmissionRequest::Complete { .. }))
            );
            respond(
                complete,
                match kind {
                    0 => AdmissionReply::Ready(
                        state,
                        owner::kernel_journal::KernelJournalWriter::new(SESSION).reader(),
                    ),
                    1 => AdmissionReply::Provider(Box::new(pending)),
                    2 => AdmissionReply::Bytes(vec![1, 2, 3]),
                    _ => unreachable!(),
                },
            );
        });
        assert!(matches!(
            session.next_event(),
            Err(GateError::Refused(
                "provider reply did not finish its pending invocation"
            ))
        ));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_closed(&mut session, &cancel);
        expect_no_followup(&owner_finished(script));
    }
}

#[test]
fn wrong_advance_and_outer_response_types_close_without_provider() {
    for outer in [false, true] {
        let state = state();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let provider = Provider(move |_: &SelectedInput| {
            counted.fetch_add(1, Ordering::AcqRel);
            Ok(ProviderDecision::Native)
        });
        let (mut session, commands, cancel) = fixture(provider, state.clone());
        let script = owner(commands, move |commands| {
            let advance = receive(commands);
            expect_advance(&advance);
            if outer {
                assert!(advance.reply.send(Ok(Response::Unit)).is_ok());
            } else {
                respond(advance, AdmissionReply::State(state));
            }
        });
        let error = session.next_event().unwrap_err();
        if outer {
            assert!(matches!(
                error,
                GateError::Refused("dynamic admission response type differs")
            ));
        } else {
            assert!(matches!(
                error,
                GateError::Refused("dynamic admission advance returned the wrong phase")
            ));
        }
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert_closed(&mut session, &cancel);
        expect_no_followup(&owner_finished(script));
    }
}

#[test]
fn typed_owner_gate_and_control_errors_remain_distinct() {
    for kind in 0..4 {
        let state = state();
        let provider = Provider(|_: &SelectedInput| Ok(ProviderDecision::Native));
        let (mut session, commands, cancel) = fixture(provider, state);
        let script = owner(commands, move |commands| {
            let advance = receive(commands);
            expect_advance(&advance);
            let reply = match kind {
                0 => Ok(Response::Admission(Box::new(Err(GateError::Refused(
                    "specific admission proof missing",
                ))))),
                1 => Ok(Response::Admission(Box::new(Err(GateError::Selected(
                    SemanticsError::NativeStateMismatch,
                ))))),
                2 => Ok(Response::Admission(Box::new(Err(GateError::Control(
                    LaunchError::Timeout("pending owner deadline"),
                ))))),
                3 => Err(LaunchError::Invalid("specific owner control failure")),
                _ => unreachable!(),
            };
            assert!(advance.reply.send(reply).is_ok());
        });
        let error = session.next_event().unwrap_err();
        match kind {
            0 => assert!(matches!(
                error,
                GateError::Refused("specific admission proof missing")
            )),
            1 => assert!(matches!(
                error,
                GateError::Selected(SemanticsError::NativeStateMismatch)
            )),
            2 => assert!(matches!(
                error,
                GateError::Control(LaunchError::Timeout("pending owner deadline"))
            )),
            3 => assert!(matches!(
                error,
                GateError::Control(LaunchError::Invalid("specific owner control failure"))
            )),
            _ => unreachable!(),
        }
        assert_closed(&mut session, &cancel);
        expect_no_followup(&owner_finished(script));
    }
}

#[test]
fn fault_signal_and_final_terminal_diagnostics_close_without_cleanup_claim() {
    for kind in 0..3 {
        let state = state();
        let input = pending(&state).input;
        let provider = Provider(|_: &SelectedInput| Ok(ProviderDecision::Native));
        let (mut session, commands, cancel) = fixture(provider, state.clone());
        let script = owner(commands, move |commands| {
            let advance = receive(commands);
            expect_advance(&advance);
            let event = match kind {
                0 => DynamicAdmissionEvent::Fault {
                    task: state.task,
                    fault: Box::new(FaultedInstruction {
                        input,
                        fault: InstructionFault::InvalidOpcode,
                    }),
                },
                1 => {
                    let mut raw = [0_u8; 128];
                    raw[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
                    DynamicAdmissionEvent::ApplicationSignal {
                        state: Box::new(state),
                        signal: DynamicSignalInfo { raw },
                        input: Some(Box::new(input)),
                    }
                }
                2 => DynamicAdmissionEvent::TaskTerminal {
                    task: state.task,
                    status: ExitStatus::Code(7),
                    all_terminal: true,
                },
                _ => unreachable!(),
            };
            respond(advance, AdmissionReply::Event(event));
        });
        match (kind, session.next_event().unwrap()) {
            (0, DynamicAdmissionEvent::Fault { task, fault }) => {
                assert_eq!(task, session.initial.task);
                assert_eq!(fault.fault, InstructionFault::InvalidOpcode);
                assert_eq!(fault.input, pending(&session.initial).input);
            }
            (
                1,
                DynamicAdmissionEvent::ApplicationSignal {
                    state,
                    signal,
                    input,
                },
            ) => {
                assert_eq!(*state, session.initial);
                assert_eq!(signal.signal(), libc::SIGUSR1);
                assert_eq!(*input.unwrap(), pending(&session.initial).input);
            }
            (
                2,
                DynamicAdmissionEvent::TaskTerminal {
                    task,
                    status,
                    all_terminal,
                },
            ) => {
                assert_eq!(task, session.initial.task);
                assert_eq!(status, ExitStatus::Code(7));
                assert!(all_terminal);
            }
            _ => panic!("diagnostic event was relabelled"),
        }
        assert_closed(&mut session, &cancel);
        expect_no_followup(&owner_finished(script));
        // No DynamicCleanup value is created or expected by this mock owner.
    }
}

#[test]
fn nonterminal_lifecycle_notifications_keep_transport_open() {
    for kind in 0..2 {
        let state = state();
        let provider = Provider(|_: &SelectedInput| Ok(ProviderDecision::Native));
        let (mut session, commands, cancel) = fixture(provider, state.clone());
        let script = owner(commands, move |commands| {
            let advance = receive(commands);
            expect_advance(&advance);
            let event = if kind == 0 {
                DynamicAdmissionEvent::Lifecycle(DynamicEvent {
                    tid: 101,
                    task: Some(state.task),
                    kind: DynamicEventKind::TaskExiting {
                        status: ExitStatus::Code(7),
                    },
                    stop: None,
                })
            } else {
                DynamicAdmissionEvent::TaskTerminal {
                    task: state.task,
                    status: ExitStatus::Code(7),
                    all_terminal: false,
                }
            };
            respond(advance, AdmissionReply::Event(event));
        });
        match (kind, session.next_event().unwrap()) {
            (0, DynamicAdmissionEvent::Lifecycle(event)) => assert!(matches!(
                event.kind,
                DynamicEventKind::TaskExiting {
                    status: ExitStatus::Code(7)
                }
            )),
            (
                1,
                DynamicAdmissionEvent::TaskTerminal {
                    all_terminal: false,
                    ..
                },
            ) => {}
            _ => panic!("nonterminal event changed"),
        }
        assert!(!session.is_closed());
        assert!(!cancel.load(Ordering::Acquire));
        expect_no_followup(&owner_finished(script));
        drop(session);
        assert!(cancel.load(Ordering::Acquire));
    }
}

#[test]
fn drop_cancels_session_before_provider_destructor_runs() {
    struct DropProvider {
        cancel: Receiver<Arc<AtomicBool>>,
        observed: Sender<bool>,
    }
    impl InstructionProvider for DropProvider {
        fn decide(&mut self, _: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
            panic!("provider must not run")
        }
    }
    impl Drop for DropProvider {
        fn drop(&mut self) {
            let cancel = self.cancel.recv_timeout(TIMEOUT).unwrap();
            assert!(self.observed.send(cancel.load(Ordering::Acquire)).is_ok());
        }
    }
    let (send_cancel, callback_cancel) = channel();
    let (observed, observation) = channel();
    let (session, commands, cancel) = fixture(
        DropProvider {
            cancel: callback_cancel,
            observed,
        },
        state(),
    );
    send_cancel.send(Arc::clone(&cancel)).unwrap();
    drop(session);
    assert!(observation.recv_timeout(TIMEOUT).unwrap());
    assert!(cancel.load(Ordering::Acquire));
    assert!(matches!(
        commands.try_recv(),
        Err(TryRecvError::Disconnected)
    ));
}

#[test]
fn expired_command_is_refused_before_queue_without_renewing_deadline() {
    let provider = Provider(|_: &SelectedInput| Ok(ProviderDecision::Native));
    let (mut session, commands, cancel) = fixture(provider, state());
    let expired = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap();
    assert!(matches!(
        session
            .session
            .admission_call(AdmissionRequest::Advance, expired, expired),
        Err(GateError::Control(LaunchError::Timeout(
            "dynamic admission command"
        )))
    ));
    assert!(cancel.load(Ordering::Acquire));
    expect_no_followup(&commands);
    assert_closed(&mut session, &cancel);
}

#[test]
fn valid_inspections_preserve_complete_payload_and_keep_session_open() {
    let state = state();
    let expected = state.clone();
    let provider = Provider(|_: &SelectedInput| Ok(ProviderDecision::Native));
    let (mut session, commands, cancel) = fixture(provider, state);
    let actual = expected.clone();
    let script = owner(commands, move |commands| {
        let state_request = receive(commands);
        assert!(
            matches!(&state_request.request, Request::Admission(request) if matches!(&**request, AdmissionRequest::State(task) if *task == actual.task.task))
        );
        respond(state_request, AdmissionReply::State(actual.clone()));
        let memory_request = receive(commands);
        assert!(
            matches!(&memory_request.request, Request::Admission(request) if matches!(&**request, AdmissionRequest::Memory { task, address: PC, len: 4 } if *task == actual.task.task))
        );
        respond(memory_request, AdmissionReply::Bytes(vec![0, 1, 0xff, 2]));
        let metric_request = receive(commands);
        assert!(
            matches!(&metric_request.request, Request::Admission(request) if matches!(&**request, AdmissionRequest::Metrics))
        );
        let metrics = DynamicAdmissionMetrics {
            generation_changes: 17,
            ..DynamicAdmissionMetrics::default()
        };
        respond(metric_request, AdmissionReply::Metrics(metrics));
    });
    assert_eq!(session.state(expected.task.task).unwrap(), expected);
    assert_eq!(
        session.read_memory(expected.task.task, PC, 4).unwrap(),
        [0, 1, 0xff, 2]
    );
    assert_eq!(session.metrics().unwrap().generation_changes, 17);
    assert!(!session.is_closed());
    assert!(!cancel.load(Ordering::Acquire));
    expect_no_followup(&owner_finished(script));
}
