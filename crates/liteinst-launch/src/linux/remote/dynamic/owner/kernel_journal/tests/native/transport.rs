//! Actual client response expiry with a controlled reply-delivery gate. The
//! original owner has already retained an independently witnessed EXIT and
//! returns its exact injected error. Neither that error nor the public timeout
//! is renamed to make the other path pass.
use super::*;

#[test]
fn caller_response_expiry_keeps_actual_exit_prefix_after_owner_error_and_cleanup() {
    let fixture = Fixture::new(libc::SYS_getpid);
    let oracle = raw::original(Arc::clone(&fixture));
    let (commands, command_rx) = std::sync::mpsc::channel::<Command>();
    let (setup_tx, setup_rx) = sync_channel(1);
    let (witness_tx, witness_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let (deliver_tx, deliver_rx) = sync_channel(1);
    let (finished_tx, finished_rx) = sync_channel(1);
    let cancel = Arc::new(AtomicBool::new(false));
    let thread_cancel = Arc::clone(&cancel);
    let child_fixture = Arc::clone(&fixture);
    let worker = spawn_masked(move || {
        let blocked = launch::BlockedSignals::new().unwrap();
        let mut owner = Owner::new(NEXT.fetch_add(1, Ordering::Relaxed), thread_cancel);
        let reader = owner.kernel_journal.reader();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (initial, _) = launch_owner(
                &mut owner,
                &child_fixture,
                DynamicAdmissionOptions::default(),
                APP_MASK,
            );
            let until = Instant::now() + TIMEOUT;
            let AdmissionReply::Provider(pending) = owner
                .execute_admission(AdmissionRequest::Advance, until)
                .unwrap()
            else {
                panic!("actual original provider input")
            };
            let setup = Setup {
                reader: reader.clone(),
                input: pending.input.clone(),
                token: pending.token.clone(),
                parent: owner.pid,
                until,
            };
            setup_tx.send((setup, initial, pending.token)).unwrap();
            owner.journal_fault = Some(JournalFault {
                point: JournalFaultPoint::AfterValidatedExit,
                memory: vec![
                    BASE..BASE + SOURCE_BYTES as u64,
                    DATA..DATA + DATA_BYTES as u64,
                ],
                action: JournalFaultAction::AwaitRelease {
                    ready: witness_tx,
                    release: release_rx,
                },
            });
            let command = command_rx.recv_timeout(TIMEOUT).unwrap();
            assert_eq!(command.until, until);
            assert!(matches!(command.request, Request::Admission(_)));
            // The production command dispatcher and exact absolute deadline are
            // used. Only delivery of its resulting reply is held back below.
            let response = owner.execute(command.request, command.until);
            assert!(matches!(&response,
                Ok(Response::Admission(reply)) if matches!(reply.as_ref(),
                    Err(GateError::Control(LaunchError::Invalid("injected kernel journal failure"))))));
            let held = owner
                .stopped
                .iter()
                .map(|(&tid, &status)| Held {
                    tid,
                    status,
                    frame: raw::frame(tid),
                })
                .collect();
            let pins = owner
                .handles
                .iter()
                .map(|(&tid, pin)| (tid, duplicate(pin)))
                .collect();
            (command.reply, response, held, pins)
        }));
        let before_cleanup = reader.snapshot();
        let admission_retained = owner.admission.is_some();
        let cleanup = owner.cleanup();
        let mask_result = blocked.restore();
        match result {
            Err(panic) => {
                let _ = finished_tx.send(Err(panic_text(panic)));
            }
            Ok((reply, response, held, pins)) => {
                if let Err(error) = mask_result {
                    let _ = finished_tx.send(Err(format!("mask restoration: {error:?}")));
                    return;
                }
                // Cleanup is complete before the reply gate; its deadline does
                // not extend any native operation or retain an application.
                if deliver_rx.recv_timeout(2 * TIMEOUT).is_err() {
                    let _ = finished_tx.send(Err("bounded reply gate was abandoned".into()));
                    return;
                }
                let outcome = match reply.send(response) {
                    Err(std::sync::mpsc::SendError(Ok(Response::Admission(result)))) => {
                        match *result {
                            Err(error) => Outcome::Error(error),
                            _ => {
                                let _ = finished_tx
                                    .send(Err("unexpected successful owner reply".into()));
                                return;
                            }
                        }
                    }
                    _ => {
                        let _ = finished_tx
                            .send(Err("reply was delivered before actual client expiry".into()));
                        return;
                    }
                };
                let _ = finished_tx.send(Ok(Finished {
                    outcome,
                    reader,
                    before_cleanup,
                    held,
                    admission_retained,
                    panic_custody_verified: false,
                    pins,
                    cleanup,
                }));
            }
        }
    });
    let setup_result = setup_rx.recv_timeout(2 * TIMEOUT);
    let (setup, initial, token) = match setup_result {
        Ok(value) => value,
        Err(error) => {
            drop(release_tx);
            drop(deliver_tx);
            let _ = finished_rx.recv_timeout(3 * TIMEOUT);
            panic!("native transport setup failed: {error:?}");
        }
    };
    let witness_reader = setup.reader.clone();
    let witness_worker = std::thread::spawn(move || {
        let result = witness_rx.recv_timeout(TIMEOUT);
        let snapshot = witness_reader.snapshot();
        let _ = release_tx.send(JournalFaultRelease::Error);
        (result, snapshot)
    });
    let (_unused_done, done) = std::sync::mpsc::channel();
    let mut session = DynamicSession {
        pid: setup.parent,
        initial,
        commands,
        cancel,
        done,
        operation_timeout: TIMEOUT,
    };
    let result = session.admission_call_for_journal_test(
        AdmissionRequest::Complete {
            token,
            decision: crate::selected::ProviderDecision::Native,
        },
        setup.until,
        setup.until,
    );
    let caller_cancelled = session.cancel.load(Ordering::Acquire);
    let _ = deliver_tx.send(());
    let final_result = finished_rx.recv_timeout(3 * TIMEOUT);
    let witness_result = witness_worker.join().unwrap();
    drop(session);
    let finished = final_result
        .expect("bounded native transport cleanup")
        .unwrap();
    worker.join().unwrap();
    let witness = witness_result
        .0
        .expect("actual EXIT witness, before reply withholding");
    let trial = Trial {
        setup,
        witness: Some(witness),
        during: Some(witness_result.1),
        finished,
    };
    // All assertions below run after the real owner has physically cleaned up.
    assert!(matches!(
        result,
        Err(GateError::Control(LaunchError::Timeout(
            "dynamic tracer response"
        )))
    ));
    assert!(caller_cancelled);
    assert!(matches!(
        &trial.finished.outcome,
        Outcome::Error(GateError::Control(LaunchError::Invalid(
            "injected kernel journal failure"
        )))
    ));
    let receipt = trial.finished.cleanup.as_ref().unwrap();
    assert_eq!(receipt.reaped, [trial.setup.parent]);
    for (_, pin) in &trial.finished.pins {
        assert!(physically_gone(pin));
        assert_echild(pin);
    }
    for (_, pin) in &trial.witness.as_ref().unwrap().owned {
        assert!(physically_gone(pin));
        assert_echild(pin);
    }
    compare_prefix(&trial, &oracle, &fixture);
    let snapshot = trial.finished.reader.snapshot();
    let a = attempt(&snapshot);
    assert_eq!(snapshot.writer, KernelWriterStatus::Cleaned);
    assert_eq!(a.failure.unwrap().kind, KernelFailureKind::Injected);
    assert!(stored(a, KernelStateSlot::Exit).is_some());
    assert_eq!(
        count(a, |fact| matches!(
            fact,
            KernelJournalFact::AdmissionComplete { .. }
                | KernelJournalFact::TransportComplete { .. }
        )),
        0
    );
}
