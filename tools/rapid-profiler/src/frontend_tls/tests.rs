use super::*;
use crate::frontend::{
    FailurePoint, FunctionSpec, GroupSpec, Limits, PayloadOutcome, RecordObservation,
};
use crate::generation::{
    CancelReason, Config, DeactivationRequest, Disposition, GenerationId, Record, Terminal,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, mpsc};
use std::time::Duration;

const A: FunctionId = FunctionId(11);
const B: FunctionId = FunctionId(29);
const INSTALL: u64 = 71;
const WAIT: Duration = Duration::from_secs(2);

fn limits() -> Limits {
    Limits {
        epochs: 3,
        threads: 4,
        depth: 4,
        records_per_epoch: 32,
        actions: 64,
    }
}

fn setup(limits: Limits, k: usize, m: usize) -> (Arc<Session>, crate::frontend::EpochHandle) {
    let session = Arc::new(
        Session::new(
            INSTALL,
            &[
                FunctionSpec {
                    function: A,
                    group: 0,
                },
                FunctionSpec {
                    function: B,
                    group: 1,
                },
            ],
            &[
                GroupSpec { mandatory: false },
                GroupSpec { mandatory: false },
            ],
            limits,
        )
        .unwrap(),
    );
    let epoch = session
        .stage(Config {
            retained_per_function: k,
            max_inflight: m,
            max_invocations: 32,
        })
        .unwrap();
    session.publish(&epoch, FailurePoint::None).unwrap();
    (session, epoch)
}

fn receive<T>(rx: &mpsc::Receiver<T>) -> T {
    rx.recv_timeout(WAIT).expect("fixed bounded TLS handshake")
}

fn fresh(f: impl FnOnce() + Send + 'static) {
    // Every wait inside these fixed workers has a deadline. The root also owns
    // the unchanged 20 CPU / 30 wall outer process bound for each cohort.
    thread::spawn(f).join().expect("required TLS worker")
}

fn complete(outcome: IntervalOutcome) -> (Completion, Payload) {
    match outcome {
        IntervalOutcome::Completed {
            completion,
            payload,
        } => (completion, payload),
        other => panic!("required completion, got {other:?}"),
    }
}

fn depth(registration: &ThreadRegistration) -> usize {
    registration.access(|a| Ok(a.model().depth())).unwrap()
}

enum Expected {
    Completed {
        end: u64,
        children: u64,
        rank: Option<usize>,
    },
    Dropped,
}

// Literal reference records, independent of production terminal/retention code.
fn row(
    generation: GenerationId,
    invocation: usize,
    function: FunctionId,
    entry: u64,
    thread_and_sequence: (u64, u64),
    outcome: Expected,
) -> RecordObservation {
    let admission = Admission {
        generation,
        invocation,
        function,
        entry_value: entry,
    };
    let (terminal, payload) = match outcome {
        Expected::Completed {
            end,
            children,
            rank,
        } => (
            Terminal::Completed {
                value: invocation as u64,
                disposition: rank.map_or(Disposition::DroppedAfterBudget, |rank| {
                    Disposition::Retained { rank }
                }),
            },
            PayloadOutcome::Completed {
                end: Observation::Value(end),
                completed_children: children,
            },
        ),
        Expected::Dropped => (
            Terminal::Cancelled(CancelReason::DroppedTicket),
            PayloadOutcome::Cancelled(CancelReason::DroppedTicket),
        ),
    };
    RecordObservation {
        record: Record {
            admission,
            terminal: Some(terminal),
        },
        payload: Some(Payload {
            admission,
            thread: thread_and_sequence.0,
            start_sequence: thread_and_sequence.1,
            outcome: payload,
        }),
    }
}

fn retained(end: u64, children: u64, rank: usize) -> Expected {
    Expected::Completed {
        end,
        children,
        rank: Some(rank),
    }
}

fn exact_completion(actual: (Completion, Payload), expected: &RecordObservation) {
    assert_eq!(actual.0.admission, expected.record.admission);
    assert_eq!(Some(actual.1), expected.payload);
    let Some(Terminal::Completed { disposition, .. }) = expected.record.terminal else {
        panic!("reference completion required")
    };
    assert_eq!(actual.0.disposition, disposition);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Start,
    New,
    Finish,
    Exit,
}

#[derive(Debug)]
enum Event {
    Ready(u64, ThreadId),
    Entered,
    Old(Completion, Payload),
    New(Completion, Payload),
    Done(Completion, Payload),
    Cancelled,
}

struct Worker {
    go: mpsc::Sender<Step>,
    events: mpsc::Receiver<Event>,
    join: thread::JoinHandle<()>,
}

fn rotation_worker(session: Arc<Session>, number: u64) -> Worker {
    let (go, steps) = mpsc::channel();
    let (send, events) = mpsc::channel();
    let join = thread::spawn(move || {
        let registration = attach_current_thread(&session).unwrap();
        assert_eq!(registration.thread_id(), thread::current().id());
        send.send(Event::Ready(
            registration.identity(),
            registration.thread_id(),
        ))
        .unwrap();
        assert_eq!(receive(&steps), Step::Start);
        let old_start = 100 + 10 * number;
        let new_start = 200 + 10 * number;
        let (value, outcome) = registration.observe(INSTALL, A, old_start, || {
            let (value, inner) = registration.observe(INSTALL, B, old_start + 1, || {
                (1_000 + number, Observation::Value(old_start + 2))
            });
            assert_eq!(value, 1_000 + number);
            let (c, p) = complete(inner);
            send.send(Event::Old(c, p)).unwrap();
            assert_eq!(receive(&steps), Step::New);
            let (value, inner) = registration.observe(INSTALL, B, new_start, || {
                (2_000 + number, Observation::Value(new_start + 1))
            });
            assert_eq!(value, 2_000 + number);
            let (c, p) = complete(inner);
            send.send(Event::New(c, p)).unwrap();
            assert_eq!(receive(&steps), Step::Finish);
            (3_000 + number, Observation::Value(old_start + 3))
        });
        assert_eq!(value, 3_000 + number);
        assert_eq!(depth(&registration), 0);
        let (c, p) = complete(outcome);
        send.send(Event::Done(c, p)).unwrap();
        assert_eq!(receive(&steps), Step::Exit);
    });
    Worker { go, events, join }
}

#[test]
fn tls_p1_two_actual_threads_rotate_and_finish_exact_old_frames() {
    let (session, old) = setup(limits(), 4, 4);
    let workers = [
        rotation_worker(Arc::clone(&session), 0),
        rotation_worker(Arc::clone(&session), 1),
    ];
    let mut identities = Vec::new();
    let mut actual_threads = Vec::new();
    for worker in &workers {
        let Event::Ready(identity, actual) = receive(&worker.events) else {
            panic!("ready")
        };
        identities.push(identity);
        actual_threads.push(actual);
        assert_ne!(actual, thread::current().id());
    }
    assert_ne!(identities[0], identities[1]);
    assert_ne!(actual_threads[0], actual_threads[1]);
    for (i, worker) in workers.iter().enumerate() {
        worker.go.send(Step::Start).unwrap();
        let Event::Old(c, p) = receive(&worker.events) else {
            panic!("old inner")
        };
        exact_completion(
            (c, p),
            &row(
                old.generation(),
                2 * i + 1,
                B,
                101 + 10 * i as u64,
                (identities[i], 0),
                retained(102 + 10 * i as u64, 0, i),
            ),
        );
        assert_eq!(c.deactivate, None);
        assert_eq!(c.other_reservations_after_close, None);
    }
    assert_eq!(old.reservations(), 2);
    let new = session
        .stage(Config {
            retained_per_function: 4,
            max_inflight: 4,
            max_invocations: 32,
        })
        .unwrap();
    session.publish(&new, FailurePoint::None).unwrap();
    assert!(old.try_report().is_none());
    assert_eq!(session.retained_epochs(), 2);
    for (i, worker) in workers.iter().enumerate() {
        worker.go.send(Step::New).unwrap();
        let Event::New(c, p) = receive(&worker.events) else {
            panic!("new inner")
        };
        exact_completion(
            (c, p),
            &row(
                new.generation(),
                i,
                B,
                200 + 10 * i as u64,
                (identities[i], 1),
                retained(201 + 10 * i as u64, 0, i),
            ),
        );
        assert_eq!(c.deactivate, None);
    }
    session.remove_current().unwrap();
    assert!(new.try_report().is_some());
    for (i, worker) in workers.iter().enumerate() {
        assert!(old.try_report().is_none());
        worker.go.send(Step::Finish).unwrap();
        let Event::Done(c, p) = receive(&worker.events) else {
            panic!("old outer")
        };
        exact_completion(
            (c, p),
            &row(
                old.generation(),
                2 * i,
                A,
                100 + 10 * i as u64,
                (identities[i], 0),
                retained(103 + 10 * i as u64, 2, i),
            ),
        );
        assert_eq!(c.deactivate, None);
        assert_eq!(old.reservations(), 1 - i);
    }
    assert_eq!(
        old.try_report().unwrap().records().collect::<Vec<_>>(),
        vec![
            row(
                old.generation(),
                0,
                A,
                100,
                (identities[0], 0),
                retained(103, 2, 0)
            ),
            row(
                old.generation(),
                1,
                B,
                101,
                (identities[0], 0),
                retained(102, 0, 0)
            ),
            row(
                old.generation(),
                2,
                A,
                110,
                (identities[1], 0),
                retained(113, 2, 1)
            ),
            row(
                old.generation(),
                3,
                B,
                111,
                (identities[1], 0),
                retained(112, 0, 1)
            ),
        ]
    );
    assert_eq!(
        new.try_report().unwrap().records().collect::<Vec<_>>(),
        vec![
            row(
                new.generation(),
                0,
                B,
                200,
                (identities[0], 1),
                retained(201, 0, 0)
            ),
            row(
                new.generation(),
                1,
                B,
                210,
                (identities[1], 1),
                retained(211, 0, 1)
            ),
        ]
    );
    for worker in workers {
        worker.go.send(Step::Exit).unwrap();
        worker.join.join().unwrap();
    }
}

#[test]
fn tls_p2_two_reservations_keep_one_k_winner_and_one_dropped_completion() {
    let (session, epoch) = setup(limits(), 1, 2);
    let workers: Vec<_> = (0..2)
        .map(|number| {
            let session = Arc::clone(&session);
            let (go, steps) = mpsc::channel();
            let (send, events) = mpsc::channel();
            let join = thread::spawn(move || {
                let registration = attach_current_thread(&session).unwrap();
                send.send(Event::Ready(
                    registration.identity(),
                    registration.thread_id(),
                ))
                .unwrap();
                assert_eq!(receive(&steps), Step::Start);
                let (value, outcome) = registration.observe(INSTALL, A, 10 + number, || {
                    send.send(Event::Entered).unwrap();
                    assert_eq!(receive(&steps), Step::Finish);
                    (100 + number, Observation::Value(20 + number))
                });
                assert_eq!(value, 100 + number);
                let (c, p) = complete(outcome);
                send.send(Event::Done(c, p)).unwrap();
                assert_eq!(receive(&steps), Step::Exit);
            });
            Worker { go, events, join }
        })
        .collect();
    let mut ids = Vec::new();
    let mut actual_threads = Vec::new();
    for worker in &workers {
        let Event::Ready(id, actual) = receive(&worker.events) else {
            panic!("ready")
        };
        assert_ne!(actual, thread::current().id());
        actual_threads.push(actual);
        ids.push(id);
        worker.go.send(Step::Start).unwrap();
        assert!(matches!(receive(&worker.events), Event::Entered));
    }
    assert_ne!(ids[0], ids[1]);
    assert_ne!(actual_threads[0], actual_threads[1]);
    assert_eq!(epoch.close(), 2);
    assert!(epoch.try_report().is_none());
    for (i, worker) in workers.iter().enumerate() {
        worker.go.send(Step::Finish).unwrap();
        let Event::Done(c, p) = receive(&worker.events) else {
            panic!("done")
        };
        exact_completion(
            (c, p),
            &row(
                epoch.generation(),
                i,
                A,
                10 + i as u64,
                (ids[i], 0),
                Expected::Completed {
                    end: 20 + i as u64,
                    children: 0,
                    rank: if i == 0 { Some(0) } else { None },
                },
            ),
        );
        assert_eq!(
            c.deactivate,
            if i == 0 {
                Some(DeactivationRequest {
                    generation: epoch.generation(),
                    function: A,
                })
            } else {
                None
            }
        );
        assert_eq!(
            c.other_reservations_after_close,
            if i == 0 { Some(1) } else { None }
        );
    }
    assert_eq!(
        epoch.try_report().unwrap().records().collect::<Vec<_>>(),
        vec![
            row(
                epoch.generation(),
                0,
                A,
                10,
                (ids[0], 0),
                retained(20, 0, 0)
            ),
            row(
                epoch.generation(),
                1,
                A,
                11,
                (ids[1], 0),
                Expected::Completed {
                    end: 21,
                    children: 0,
                    rank: None
                }
            ),
        ]
    );
    for worker in workers {
        worker.go.send(Step::Exit).unwrap();
        worker.join.join().unwrap();
    }
}

#[test]
fn tls_p3_nested_panic_cancels_exact_frames_then_same_registration_recovers() {
    let (session, epoch) = setup(limits(), 4, 4);
    let (go, steps) = mpsc::channel();
    let (send, events) = mpsc::channel();
    let join = thread::spawn(move || {
        let registration = attach_current_thread(&session).unwrap();
        send.send(Event::Ready(
            registration.identity(),
            registration.thread_id(),
        ))
        .unwrap();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            registration.observe(INSTALL, A, 10, || {
                registration.observe(INSTALL, B, 11, || -> ((), Observation) {
                    panic!("required TLS ordinary-unwind fixture")
                });
                ((), Observation::Value(99))
            })
        }));
        assert!(panic.is_err());
        let panic = panic.expect_err("required body panic");
        assert_eq!(
            panic.downcast_ref::<&str>().copied(),
            Some("required TLS ordinary-unwind fixture")
        );
        assert_eq!(depth(&registration), 0);
        send.send(Event::Cancelled).unwrap();
        assert_eq!(receive(&steps), Step::Start);
        let (value, outcome) = registration.observe(INSTALL, A, 20, || (7, Observation::Value(21)));
        assert_eq!(value, 7);
        let (c, p) = complete(outcome);
        send.send(Event::Done(c, p)).unwrap();
        assert_eq!(receive(&steps), Step::Exit);
    });
    let Event::Ready(id, actual) = receive(&events) else {
        panic!("ready")
    };
    assert_ne!(actual, thread::current().id());
    assert!(matches!(receive(&events), Event::Cancelled));
    assert_eq!(epoch.reservations(), 0);
    assert_eq!(
        epoch.records().collect::<Vec<_>>(),
        vec![
            row(epoch.generation(), 0, A, 10, (id, 0), Expected::Dropped),
            row(epoch.generation(), 1, B, 11, (id, 0), Expected::Dropped),
        ]
    );
    go.send(Step::Start).unwrap();
    let Event::Done(c, p) = receive(&events) else {
        panic!("recovered")
    };
    exact_completion(
        (c, p),
        &row(epoch.generation(), 2, A, 20, (id, 0), retained(21, 0, 0)),
    );
    assert_eq!(c.deactivate, None);
    assert_eq!(epoch.close(), 0);
    assert_eq!(
        epoch.try_report().unwrap().records().collect::<Vec<_>>(),
        vec![
            row(epoch.generation(), 0, A, 10, (id, 0), Expected::Dropped),
            row(epoch.generation(), 1, B, 11, (id, 0), Expected::Dropped),
            row(epoch.generation(), 2, A, 20, (id, 0), retained(21, 0, 0)),
        ]
    );
    go.send(Step::Exit).unwrap();
    join.join().unwrap();
}

#[test]
fn tls_p4_detach_and_forgotten_registration_follow_actual_thread_teardown() {
    let (session, epoch) = setup(
        Limits {
            threads: 2,
            ..limits()
        },
        4,
        2,
    );
    let drops = Arc::new(AtomicUsize::new(0));
    let observed_drops = Arc::clone(&drops);
    let (send, events) = mpsc::channel();
    let (go, steps) = mpsc::channel();
    let join = thread::spawn(move || {
        let first = attach_current_thread(&session).unwrap();
        first
            .access(|a| {
                a.drop_witness = Some(Arc::clone(&observed_drops));
                Ok(())
            })
            .unwrap();
        let first_id = first.identity();
        let actual = first.thread_id();
        let (value, outcome) = first.observe(INSTALL, A, 10, || (101, Observation::Value(11)));
        assert_eq!(value, 101);
        let first_result = complete(outcome);
        first.detach().unwrap();
        assert_eq!(observed_drops.load(Ordering::Acquire), 1);
        let second = attach_current_thread(&session).unwrap();
        second
            .access(|a| {
                a.drop_witness = Some(Arc::clone(&observed_drops));
                Ok(())
            })
            .unwrap();
        assert_eq!(second.thread_id(), actual);
        let second_id = second.identity();
        assert_ne!(first_id, second_id);
        let (value, outcome) = second.observe(INSTALL, A, 20, || (202, Observation::Value(21)));
        assert_eq!(value, 202);
        let second_result = complete(outcome);
        std::mem::forget(second);
        send.send((first_id, second_id, actual, first_result, second_result))
            .unwrap();
        assert_eq!(receive(&steps), Step::Exit);
    });
    let (first, second, actual, c1, c2) = receive(&events);
    assert_ne!(actual, thread::current().id());
    assert_eq!(drops.load(Ordering::Acquire), 1);
    let rows = vec![
        row(epoch.generation(), 0, A, 10, (first, 0), retained(11, 0, 0)),
        row(
            epoch.generation(),
            1,
            A,
            20,
            (second, 0),
            retained(21, 0, 1),
        ),
    ];
    exact_completion(c1, &rows[0]);
    exact_completion(c2, &rows[1]);
    epoch.close();
    assert_eq!(
        epoch.try_report().unwrap().records().collect::<Vec<_>>(),
        rows
    );
    go.send(Step::Exit).unwrap();
    join.join().unwrap();
    assert_eq!(drops.load(Ordering::Acquire), 2);
}

#[test]
fn tls_r1_duplicate_attachment_preserves_original_and_t_budget() {
    fresh(|| {
        let (session, epoch) = setup(
            Limits {
                threads: 2,
                ..limits()
            },
            4,
            2,
        );
        let first = attach_current_thread(&session).unwrap();
        assert_eq!(
            attach_current_thread(&session).err(),
            Some(AttachError::AlreadyAttached)
        );
        assert_eq!(depth(&first), 0);
        assert_eq!(epoch.records().count(), 0);
        let id = first.identity();
        first.detach().unwrap();
        let second = attach_current_thread(&session).unwrap();
        assert_ne!(second.identity(), id);
        second.detach().unwrap();
    });
}

#[test]
fn tls_r2_wrong_install_runs_body_once_without_admission() {
    fresh(|| {
        let (session, epoch) = setup(limits(), 4, 2);
        let registration = attach_current_thread(&session).unwrap();
        let calls = Cell::new(0);
        let (value, outcome) = registration.observe(INSTALL + 1, A, 10, || {
            calls.set(calls.get() + 1);
            (123, Observation::Value(11))
        });
        assert_eq!((value, calls.get()), (123, 1));
        assert_eq!(
            outcome,
            IntervalOutcome::Refused(BridgeError::Entry(EntryError::WrongInstall))
        );
        assert_eq!(depth(&registration), 0);
        assert_eq!(epoch.reservations(), 0);
        assert_eq!(epoch.records().count(), 0);
    });
}

#[test]
fn tls_r3_removed_current_runs_body_once_without_admission() {
    fresh(|| {
        let (session, epoch) = setup(limits(), 4, 2);
        let registration = attach_current_thread(&session).unwrap();
        session.remove_current().unwrap();
        let calls = Cell::new(0);
        let (value, outcome) = registration.observe(INSTALL, A, 10, || {
            calls.set(calls.get() + 1);
            (321, Observation::Value(11))
        });
        assert_eq!((value, calls.get()), (321, 1));
        assert_eq!(
            outcome,
            IntervalOutcome::Refused(BridgeError::Entry(EntryError::NoCurrent))
        );
        assert_eq!(depth(&registration), 0);
        assert_eq!(epoch.try_report().unwrap().records().count(), 0);
    });
}

#[test]
fn tls_r4_depth_refusal_keeps_exact_existing_outer_frame() {
    fresh(|| {
        let (session, epoch) = setup(
            Limits {
                depth: 1,
                ..limits()
            },
            4,
            2,
        );
        let registration = attach_current_thread(&session).unwrap();
        let id = registration.identity();
        let (value, outcome) = registration.observe(INSTALL, A, 10, || {
            let before = epoch.records().collect::<Vec<_>>();
            let calls = Cell::new(0);
            let (value, inner) = registration.observe(INSTALL, B, 20, || {
                calls.set(calls.get() + 1);
                (87, Observation::Value(21))
            });
            assert_eq!((value, calls.get()), (87, 1));
            assert_eq!(
                inner,
                IntervalOutcome::Refused(BridgeError::Entry(EntryError::Depth))
            );
            assert_eq!(depth(&registration), 1);
            assert_eq!(epoch.reservations(), 1);
            assert_eq!(epoch.records().collect::<Vec<_>>(), before);
            (91, Observation::Value(11))
        });
        assert_eq!(value, 91);
        let expected = row(epoch.generation(), 0, A, 10, (id, 0), retained(11, 0, 0));
        exact_completion(complete(outcome), &expected);
        epoch.close();
        assert_eq!(
            epoch.try_report().unwrap().records().collect::<Vec<_>>(),
            vec![expected]
        );
    });
}

#[test]
fn tls_r5_bookkeeping_borrow_busy_runs_body_once_without_panic() {
    fresh(|| {
        let (session, epoch) = setup(limits(), 4, 2);
        let registration = attach_current_thread(&session).unwrap();
        let calls = Cell::new(0);
        LOCAL.with(|local| {
            let storage = local.attached.borrow_mut();
            let (value, outcome) = registration.observe(INSTALL, A, 10, || {
                calls.set(calls.get() + 1);
                (45, Observation::Value(11))
            });
            assert_eq!((value, calls.get()), (45, 1));
            assert_eq!(outcome, IntervalOutcome::Refused(BridgeError::Busy));
            assert_eq!(storage.as_ref().unwrap().model.as_ref().unwrap().depth(), 0);
            assert!(!local.poisoned.get());
        });
        assert_eq!(epoch.records().count(), 0);
        assert_eq!(epoch.reservations(), 0);
    });
}

#[test]
fn tls_r6_lifetime_thread_limit_does_not_recycle_after_os_thread_exit() {
    let (session, epoch) = setup(
        Limits {
            threads: 1,
            ..limits()
        },
        4,
        2,
    );
    let first = Arc::clone(&session);
    fresh(move || {
        let _registration = attach_current_thread(&first).unwrap();
    });
    let second = Arc::clone(&session);
    fresh(move || {
        assert_eq!(
            attach_current_thread(&second).err(),
            Some(AttachError::Setup(SetupError::ThreadLimit))
        );
        LOCAL.with(|local| assert!(local.attached.borrow().is_none()));
    });
    assert_eq!(epoch.records().count(), 0);
    assert_eq!(epoch.reservations(), 0);
}

#[test]
fn tls_r7_registration_identity_overflow_refuses_before_t_consumption() {
    fresh(|| {
        let (session, epoch) = setup(
            Limits {
                threads: 1,
                ..limits()
            },
            4,
            2,
        );
        let counter = AtomicU64::new(u64::MAX);
        assert_eq!(
            attach_with_counter(&session, &counter).err(),
            Some(AttachError::IdentityExhausted)
        );
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);
        LOCAL.with(|local| assert!(local.attached.borrow().is_none()));
        let registration = attach_current_thread(&session).unwrap();
        assert_eq!(depth(&registration), 0);
        assert_eq!(epoch.records().count(), 0);
    });
}

#[test]
fn tls_r8_slot_identity_overflow_preserves_records_and_runs_body_once() {
    fresh(|| {
        let (session, epoch) = setup(limits(), 4, 2);
        let registration = attach_current_thread(&session).unwrap();
        registration
            .access(|a| {
                a.next_slot = u64::MAX;
                Ok(())
            })
            .unwrap();
        let calls = Cell::new(0);
        let (value, outcome) = registration.observe(INSTALL, A, 10, || {
            calls.set(calls.get() + 1);
            (63, Observation::Value(11))
        });
        assert_eq!((value, calls.get()), (63, 1));
        assert_eq!(
            outcome,
            IntervalOutcome::Refused(BridgeError::SlotIdentityExhausted)
        );
        assert_eq!(registration.access(|a| Ok(a.next_slot)).unwrap(), u64::MAX);
        assert_eq!(depth(&registration), 0);
        assert_eq!(epoch.reservations(), 0);
        assert_eq!(epoch.records().count(), 0);
    });
}

#[test]
fn unwind_seam_rejects_two_mismatches_and_drops_only_matching_inner_frame() {
    let (session, epoch) = setup(limits(), 4, 2);
    let mut model = session.register_thread(42).unwrap();
    let original_outer = ModelReturnSlot {
        identity: 1,
        word: 101,
    };
    let original_inner = ModelReturnSlot {
        identity: 2,
        word: 202,
    };
    let mut outer = original_outer;
    let mut inner = original_inner;
    model.enter(INSTALL, A, 10, &mut outer).unwrap();
    model.enter(INSTALL, B, 20, &mut inner).unwrap();
    let before = epoch.records().collect::<Vec<_>>();
    for mut wrong in [
        ModelReturnSlot {
            identity: 3,
            ..inner
        },
        ModelReturnSlot {
            word: inner.word ^ 1,
            ..inner
        },
    ] {
        let unchanged = wrong;
        assert_eq!(
            model.cancel_on_unwind(&mut wrong),
            Err(ExitError::SlotMismatch)
        );
        assert_eq!(wrong, unchanged);
        assert_eq!(model.depth(), 2);
        assert_eq!(epoch.reservations(), 2);
        assert_eq!(epoch.records().collect::<Vec<_>>(), before);
    }
    model.cancel_on_unwind(&mut inner).unwrap();
    assert_eq!(inner, original_inner);
    assert_eq!(model.depth(), 1);
    assert_eq!(epoch.reservations(), 1);
    assert_eq!(epoch.records().next().unwrap(), before[0]);
    assert_eq!(
        epoch.records().nth(1).unwrap(),
        row(epoch.generation(), 1, B, 20, (42, 0), Expected::Dropped)
    );
    let actual = model.finish(&mut outer, Observation::Value(11)).unwrap();
    assert_eq!(outer, original_outer);
    exact_completion(
        actual,
        &row(epoch.generation(), 0, A, 10, (42, 0), retained(11, 0, 0)),
    );
    epoch.close();
    assert_eq!(
        epoch.try_report().unwrap().records().collect::<Vec<_>>(),
        vec![
            row(epoch.generation(), 0, A, 10, (42, 0), retained(11, 0, 0)),
            row(epoch.generation(), 1, B, 20, (42, 0), Expected::Dropped),
        ]
    );
}

#[test]
fn tls_invariant_failure_retains_frame_and_poison_until_actual_thread_teardown() {
    let (session, epoch) = setup(limits(), 4, 2);
    let drops = Arc::new(AtomicUsize::new(0));
    let observed_drops = Arc::clone(&drops);
    let (send, events) = mpsc::channel();
    let (go, steps) = mpsc::channel();
    let join = thread::spawn(move || {
        let registration = attach_current_thread(&session).unwrap();
        let id = registration.identity();
        let actual = registration.thread_id();
        registration
            .access(|a| {
                a.drop_witness = Some(Arc::clone(&observed_drops));
                Ok(())
            })
            .unwrap();
        let mut guard = registration.begin(INSTALL, A, 10).unwrap();
        guard.slot.identity += 1;
        assert_eq!(
            guard.finish(Observation::Value(11)),
            IntervalOutcome::InvariantFailure(BridgeError::Exit(ExitError::SlotMismatch))
        );
        LOCAL.with(|local| {
            assert!(local.poisoned.get());
            let storage = local.attached.borrow();
            let attached = storage.as_ref().unwrap();
            assert_eq!(attached.identity, id);
            assert_eq!(attached.model.as_ref().unwrap().depth(), 1);
        });
        let calls = Cell::new(0);
        let (value, outcome) = registration.observe(INSTALL, B, 20, || {
            calls.set(calls.get() + 1);
            (39, Observation::Value(21))
        });
        assert_eq!((value, calls.get()), (39, 1));
        assert_eq!(outcome, IntervalOutcome::Refused(BridgeError::Poisoned));
        assert_eq!(registration.detach(), Err(BridgeError::Poisoned));
        assert_eq!(
            attach_current_thread(&session).err(),
            Some(AttachError::Poisoned)
        );
        assert_eq!(observed_drops.load(Ordering::Acquire), 0);
        send.send((id, actual)).unwrap();
        assert_eq!(receive(&steps), Step::Exit);
    });
    let (id, actual) = receive(&events);
    assert_ne!(actual, thread::current().id());
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert_eq!(epoch.close(), 1);
    assert!(epoch.try_report().is_none());
    assert_eq!(
        epoch.records().collect::<Vec<_>>(),
        vec![RecordObservation {
            record: Record {
                admission: Admission {
                    generation: epoch.generation(),
                    invocation: 0,
                    function: A,
                    entry_value: 10
                },
                terminal: None
            },
            payload: None,
        }]
    );
    go.send(Step::Exit).unwrap();
    join.join().unwrap();
    assert_eq!(drops.load(Ordering::Acquire), 1);
    assert_eq!(epoch.reservations(), 0);
    assert_eq!(
        epoch.try_report().unwrap().records().collect::<Vec<_>>(),
        vec![row(
            epoch.generation(),
            0,
            A,
            10,
            (id, 0),
            Expected::Dropped
        )]
    );
}
