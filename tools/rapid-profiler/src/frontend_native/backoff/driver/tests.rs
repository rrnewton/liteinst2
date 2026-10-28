//! Metadata controls for the real driver methods. No native calls, clock loop,
//! fabricated worker-finished receipt, or durable-export success is involved.
use super::*;
use crate::frontend::{Action, ActionKind, ControlError, ControllerStatus};
use crate::frontend_native::always_on as model;

fn prepared() -> Prepared {
    // SAFETY: existing metadata-only fixture; no executable installation, calls,
    // attachment, source writer, fork, or controller reentry exists in this test.
    unsafe {
        prepare(
            model::backoff_test_site(),
            71,
            FunctionId(11),
            Policy::ten_ms(10, 4, 4).unwrap(),
        )
    }
    .unwrap()
}
fn no_completion(d: &Driver) {
    assert_eq!(d.cursor.number, 0);
    assert_eq!(d.cursor.totals, PairTotals::default());
    assert_eq!(d.cursor.gate, None);
    assert!(d.shared.finished.get().is_none());
    assert_eq!(finished_ok(None), Err(Error::Worker));
}
fn published(d: &Driver) -> &HistoryBatch {
    let Some(Export::History(batch)) = &d.pending else {
        panic!("missing owned, unsent history")
    };
    batch
}
fn failed_export(disconnected: bool) {
    let Prepared {
        mut driver,
        client,
        stop,
        export,
    } = prepared();
    let expected = if disconnected {
        Error::Disconnected
    } else {
        Error::Full
    };
    let output = if disconnected {
        drop(export);
        None
    } else {
        // Inert transport fillers, not driver-produced reports or export credit.
        for i in 0..EXPORT_QUEUE {
            driver
                .output
                .try_send(Export::Report(FinalReport {
                    generation: 800 + i as u64,
                    records: Vec::new(),
                }))
                .unwrap();
        }
        Some(export)
    };
    let mut addresses = [std::ptr::null(); WORK_QUEUE];
    for (i, address) in addresses.iter_mut().enumerate() {
        let native = model::backoff_test_transport(driver.stream.clone(), 700 + i as u64);
        *address = native.journal().as_ptr();
        client
            .tx
            .try_send(CompletedBatch {
                native,
                calls: [None; ROWS],
            })
            .unwrap();
    }
    // No producer remains; unread values must stay owned by the actual receiver.
    // These deliberately invalid sentinels are never admitted by receive_one().
    drop(client);
    assert_eq!(driver.arm(), Err(expected));
    let generation = driver.slots[0].as_ref().unwrap().generation();
    let first = published(&driver);
    let address = first.actions().as_ptr();
    let expected_action = Action {
        kind: ActionKind::Published,
        generation,
        function: None,
        current: Some(generation),
        group: None,
    };
    assert_eq!(first.actions(), &[expected_action]);
    assert_eq!((first.number(), first.range()), (1, 0..1));
    assert_eq!(first.before(), HistoryBinding::Initial);
    assert_eq!(first.stream(), &driver.stream);
    assert_eq!(driver.history_window().unwrap().range(), 1..1);

    // These are the same real removal and retention methods used after run()
    // refuses. Do not run the clock, synthesize a receipt, or retry the export.
    stop.request();
    driver.close().unwrap();
    assert!(stop.requested());
    assert_eq!(driver.current, None);
    assert_eq!(driver.close_error(), None);
    assert!(driver.close_attempted);
    assert_eq!(published(&driver).actions().as_ptr(), address);
    assert_eq!(published(&driver).actions(), &[expected_action]);
    let window = driver.history_window().unwrap();
    assert_eq!(window.range(), 1..2);
    assert_eq!(window.last_batch_number(), 1);
    assert_eq!(window.before(), published(&driver).after());
    assert_eq!(window.status(), ControllerStatus::Ready);
    assert_eq!(window.current(), None);
    assert_eq!(window.retained_failed_generation(), None);
    assert_eq!(
        window.actions(),
        &[Action {
            kind: ActionKind::Removed,
            generation,
            function: None,
            current: None,
            group: None,
        }]
    );
    assert_eq!(
        window.after(),
        HistoryBinding::Removed {
            action_index: 1,
            generation,
        }
    );
    assert_eq!((driver.arms, driver.reports, driver.exported), (1, 0, 0));
    assert_eq!((driver.history_number, driver.history_end), (1, 1));
    no_completion(&driver);

    let Some(Export::History(first)) = driver.take_pending() else {
        panic!("lost transferred history")
    };
    assert_eq!(first.actions().as_ptr(), address);
    assert_eq!(first.actions(), &[expected_action]);
    let last = driver.recover_history().unwrap().unwrap();
    assert!(last.follows(&first));
    assert_eq!((last.number(), last.range()), (2, 1..2));
    assert_eq!(last.actions(), window.actions());
    assert_eq!(last.after(), window.after());
    assert!(driver.recover_history().unwrap().is_none());
    assert!(driver.take_pending().is_none());
    for (i, address) in addresses.into_iter().enumerate() {
        let packet = driver.recover_worker_packet().unwrap();
        assert_eq!(packet.native.journal().as_ptr(), address);
        assert_eq!(packet.native.journal(), &[700 + i as u64; 512]);
        assert_eq!(packet.native.history_stream(), Some(&driver.stream));
        assert_eq!(packet.native.number(), 700 + i as u64);
        assert!(packet.calls.iter().all(Option::is_none));
    }
    assert!(driver.recover_worker_packet().is_none());
    assert_eq!(driver.receive_one(), Err(Error::Worker));
    if let Some(output) = output {
        for i in 0..EXPORT_QUEUE {
            let Export::Report(report) = output.try_recv().unwrap() else {
                panic!("transport filler changed")
            };
            assert_eq!(report.generation, 800 + i as u64);
            assert!(report.records.is_empty());
        }
        assert!(matches!(output.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }
    let report = driver.recover_report().unwrap().unwrap();
    assert_eq!(report.generation, generation.get());
    assert!(report.records.is_empty()); // No calls were made.
    assert!(driver.recover_report().unwrap().is_none());
    assert_eq!(model::backoff_test_retained(&driver.controller), 0);
    assert_eq!(driver.exported, 0); // Recovery is not successful sink delivery.
    no_completion(&driver);
}

#[test]
fn full_after_real_arm_retains_pending_history_removed_suffix_and_unread_packets() {
    failed_export(false);
}
#[test]
fn disconnect_after_real_arm_retains_pending_history_removed_suffix_and_unread_packets() {
    failed_export(true);
}

#[test]
fn terminal_history_is_a_qualified_failure_window_not_a_normal_batch() {
    let Prepared { mut driver, .. } = prepared();
    let epoch = driver.controller.stage(driver.policy.config()).unwrap();
    let generation = epoch.generation();
    let injected = model::backoff_test_after_mutation(&driver.controller, &epoch);
    assert_eq!(
        injected,
        Err(model::backoff_test_control_error(
            ControlError::InjectedAfter
        ))
    );
    driver.slots[0] = Some(epoch);
    let before = driver.history_window().unwrap();
    assert_eq!(before.range(), 0..1);
    assert_eq!(before.status(), ControllerStatus::TerminalFailure);
    assert_eq!(before.current(), Some(generation));
    assert_eq!(before.retained_failed_generation(), Some(generation));
    assert_eq!(before.before(), HistoryBinding::Initial);
    assert_eq!(before.after(), HistoryBinding::Initial);
    assert_eq!(
        before.actions(),
        &[Action {
            kind: ActionKind::FailedAfter,
            generation,
            function: None,
            current: Some(generation),
            group: None,
        }]
    );
    let expected = Error::Bridge(model::backoff_test_control_error(
        ControlError::TerminalFailure,
    ));
    assert_eq!(driver.history(), Err(expected));
    assert_eq!(driver.recover_history(), Err(expected));
    assert!(matches!(driver.recover_report(), Err(actual) if actual == expected));
    assert_eq!(driver.history_window().unwrap(), before);
    assert!(driver.slots[0].is_some());
    assert_eq!(model::backoff_test_retained(&driver.controller), 1);
    assert!(driver.take_pending().is_none());
    assert_eq!((driver.history_number, driver.history_end), (0, 0));
    assert_eq!((driver.arms, driver.reports, driver.exported), (0, 0, 0));
    no_completion(&driver);
}

#[test]
fn real_retirement_copies_reports_but_external_report_owners_still_bound_reuse() {
    let Prepared {
        mut driver,
        client: _client,
        export,
        ..
    } = prepared();
    for _ in 0..SLOTS {
        driver.arm().unwrap();
        assert!(matches!(export.try_recv().unwrap(), Export::History(_)));
    }
    driver.close().unwrap();
    driver.history().unwrap();
    assert!(matches!(export.try_recv().unwrap(), Export::History(_)));
    let mut held = driver
        .slots
        .iter()
        .map(|e| {
            driver
                .controller
                .report(e.as_ref().unwrap())
                .unwrap()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let generations = held.iter().map(|r| r.generation()).collect::<Vec<_>>();
    assert!(generations.windows(2).all(|pair| pair[0] != pair[1]));
    assert_eq!(model::backoff_test_retained(&driver.controller), SLOTS);
    driver.retire().unwrap();
    assert!(driver.slots.iter().all(Option::is_none));
    assert_eq!(model::backoff_test_retained(&driver.controller), SLOTS);
    for generation in &generations {
        let Export::Report(report) = export.try_recv().unwrap() else {
            panic!("missing real retired report")
        };
        assert_eq!(report.generation, generation.get());
        assert!(report.records.is_empty());
    }
    let before = driver.history_window().unwrap();
    let counts = (driver.arms, driver.reports, driver.exported);
    assert_eq!(
        driver.arm(),
        Err(Error::Bridge(model::backoff_test_epoch_limit()))
    );
    assert_eq!(driver.history_window().unwrap(), before);
    assert_eq!((driver.arms, driver.reports, driver.exported), counts);
    assert!(driver.slots.iter().all(Option::is_none));
    assert_eq!(driver.current, None);
    drop(held.pop().unwrap());
    assert_eq!(model::backoff_test_retained(&driver.controller), SLOTS - 1);
    driver.arm().unwrap();
    let fresh = driver.slots[0].as_ref().unwrap().generation();
    assert!(!generations.contains(&fresh));
    assert!(matches!(export.try_recv().unwrap(), Export::History(_)));
    assert_eq!(model::backoff_test_retained(&driver.controller), SLOTS);
    driver.close().unwrap();
    driver.history().unwrap();
    assert!(matches!(export.try_recv().unwrap(), Export::History(_)));
    driver.retire().unwrap();
    let Export::Report(report) = export.try_recv().unwrap() else {
        panic!("missing fresh retired report")
    };
    assert_eq!(report.generation, fresh.get());
    assert!(report.records.is_empty());
    assert_eq!(model::backoff_test_retained(&driver.controller), SLOTS - 1);
    drop(held);
    assert_eq!(model::backoff_test_retained(&driver.controller), 0);
    assert_eq!((driver.arms, driver.reports), (4, 4));
    assert_eq!((driver.history_number, driver.history_end), (6, 6));
    assert_eq!(driver.exported, 10);
    assert!(driver.pending.is_none());
    no_completion(&driver);
}

#[test]
fn poll_deadline_diagnostic_distinguishes_inclusive_arm_and_exclusive_end_limits() {
    let start = Instant::now();
    let policy = Policy::ten_ms(10, 3, 100).unwrap();
    let mut clock = Clock::new(start, policy).unwrap();
    let ns = Duration::from_nanos(1);
    let slack = Duration::from_millis(2);
    assert_eq!(
        clock.poll(start + slack, false, 0),
        Ok(Decision::Arm(start))
    );
    let now = start + slack + ns;
    assert_eq!(clock.poll(now, false, 0), Err(Error::Deadline));
    assert_eq!(
        clock.poll_failure(now, false, 0),
        DeadlineFailure {
            phase: DeadlinePhase::ClockPoll,
            scheduled: Some(Duration::ZERO),
            limit: Some(slack),
            observed: Some(slack + ns),
            arm_started: None,
            at_limit_is_late: false,
        }
    );
    let end = Duration::from_millis(30);
    assert_eq!(clock.poll(start + end, false, 1), Err(Error::Deadline));
    let missed = clock.poll_failure(start + end, false, 1);
    assert_eq!(
        (missed.scheduled, missed.limit, missed.at_limit_is_late),
        (Some(end), Some(end), true)
    );
    // Earlier acknowledged stop wins over the original absolute endpoint.
    assert_eq!(clock.poll(start + ns, true, 1), Ok(Decision::Stop));
    let stopped = Duration::from_secs(2) + ns;
    assert_eq!(
        clock.poll(start + stopped - ns, false, 1),
        Ok(Decision::Wait)
    );
    assert_eq!(clock.poll(start + stopped, false, 1), Err(Error::Deadline));
    let failure = clock.poll_failure(start + stopped, false, 1);
    assert_eq!(
        (
            failure.scheduled,
            failure.limit,
            failure.observed,
            failure.at_limit_is_late
        ),
        (Some(stopped), Some(stopped), Some(stopped), true)
    );
    assert_eq!(clock.stopping, Some(start + stopped)); // Never renew the deadline.
}

#[test]
fn actual_deadline_errors_retain_first_phase_and_do_not_replace_other_errors() {
    let Prepared { mut driver, .. } = prepared();
    let start = Instant::now();
    let policy = Policy::ten_ms(10, 3, 100).unwrap();
    let ns = Duration::from_nanos(1);
    let slack = Duration::from_millis(2);
    let began = start + Duration::from_millis(1);
    let observed = start + slack + ns;
    assert_eq!(arm_due(start + slack, start, slack), Ok(true));
    let arm_error = arm_due(observed, start, slack).unwrap_err();
    let arm = DeadlineFailure::at(
        DeadlinePhase::ArmOperation,
        start,
        Some(start),
        Some(start + slack),
        observed,
        Some(began),
        false,
    );
    assert_eq!(
        arm,
        DeadlineFailure {
            phase: DeadlinePhase::ArmOperation,
            scheduled: Some(Duration::ZERO),
            limit: Some(slack),
            observed: Some(slack + ns),
            arm_started: Some(Duration::from_millis(1)),
            at_limit_is_late: false,
        }
    );
    assert_eq!(driver.remember_deadline(Error::Full, arm), Error::Full);
    assert_eq!(driver.deadline_failure(), None);
    assert_eq!(driver.remember_deadline(arm_error, arm), Error::Deadline);
    assert_eq!(driver.deadline_failure(), Some(arm));
    let mut clock = Clock::new(start, policy).unwrap();
    let end = start + Duration::from_millis(30);
    assert_eq!(clock.poll(end, false, 3), Ok(Decision::Stop));
    let deadline = start + Duration::from_millis(2030);
    assert_eq!(clock.check_deadline(deadline - ns), Ok(()));
    let final_error = clock.check_deadline(deadline).unwrap_err();
    let final_failure = DeadlineFailure::at(
        DeadlinePhase::FinalCompletion,
        start,
        Some(clock.diagnostic_shutdown_deadline()),
        Some(clock.diagnostic_shutdown_deadline()),
        deadline,
        None,
        true,
    );
    assert_eq!(final_failure.phase, DeadlinePhase::FinalCompletion);
    assert_eq!(
        (
            final_failure.scheduled,
            final_failure.limit,
            final_failure.observed
        ),
        (
            Some(Duration::from_millis(2030)),
            Some(Duration::from_millis(2030)),
            Some(Duration::from_millis(2030))
        )
    );
    assert!(final_failure.at_limit_is_late);
    assert_eq!(
        driver.remember_deadline(final_error, final_failure),
        Error::Deadline
    );
    assert_eq!(driver.deadline_failure(), Some(arm)); // First failure survives recovery.
    no_completion(&driver);
}
