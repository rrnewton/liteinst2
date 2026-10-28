//! Actual controller methods/channels; no native completion or durability credit.
use super::*;
use crate::frontend::ActionKind;
use crate::frontend_native::always_on as model;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

fn prepared() -> Prepared {
    // SAFETY: existing inert metadata site; no executable publication/calls.
    unsafe {
        prepare(
            model::backoff_test_site(),
            81,
            FunctionId(12),
            Policy::ten_ms(10, 4, 100).unwrap(),
        )
    }
    .unwrap()
}
fn script(times: impl IntoIterator<Item = Instant>) -> sink::TestClock {
    let mut times = times.into_iter().collect::<std::collections::VecDeque<_>>();
    sink::TestClock::new(
        move || times.pop_front().expect("exact clock script"),
        |_| panic!("unexpected wait"),
    )
}
fn no_native(d: &Driver) {
    assert_eq!(d.cursor.number, 0);
    assert_eq!(d.cursor.totals, PairTotals::default());
    assert!(d.shared.finished.get().is_none());
    assert_eq!(finished_ok(None), Err(Error::Worker));
}
#[test]
fn missing_budget_preserves_real_published_and_removed_without_fallback() {
    let Prepared {
        mut driver,
        client,
        export,
        ..
    } = prepared();
    driver.policy = driver.policy.with_sink_backpressure();
    assert_eq!(driver.arm(), Err(Error::Sequence));
    assert_eq!(driver.accepted_exports(), 0);
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    let Some(Export::History(first)) = driver.pending.as_ref() else {
        panic!("Published retained")
    };
    let address = first.actions().as_ptr();
    let action = first.actions()[0];
    assert_eq!(action.kind, ActionKind::Published);
    driver.close().unwrap();
    let window = driver.history_window().unwrap();
    assert_eq!(window.range(), 1..2);
    assert_eq!(window.actions()[0].kind, ActionKind::Removed);
    let Some(Export::History(first)) = driver.take_pending() else {
        panic!("original packet")
    };
    assert_eq!(first.actions().as_ptr(), address);
    assert_eq!(first.actions(), &[action]);
    let last = driver.recover_history().unwrap().unwrap();
    assert!(last.follows(&first));
    assert_eq!(last.actions(), window.actions());
    drop(client);
    assert_eq!(driver.receive_one(Duration::ZERO), Err(Error::Worker));
    no_native(&driver);
}
#[test]
fn accepted_late_calls_are_received_once_and_never_returned_as_pending() {
    let Prepared {
        mut driver, export, ..
    } = prepared();
    driver.policy = driver.policy.with_sink_backpressure();
    let start = Instant::now();
    let clock = Clock::new(start, driver.policy).unwrap();
    driver.sink.budget = Some(clock.export_budget(Some(start), Some(start)).unwrap());
    // Opaque transport sentinel: never admitted by receive_one/cursor.
    let native = model::backoff_test_transport(driver.stream.clone(), 77);
    let address = native.journal().as_ptr();
    let calls = Export::Calls(Box::new(CompletedBatch {
        native,
        calls: [None; ROWS],
    }));
    let late = start + driver.policy.lateness() + Duration::from_nanos(1);
    sink::with_clock(script([start, late]), || {
        assert_eq!(driver.emit(calls), Err(Error::Deadline))
    });
    assert_eq!(driver.accepted_exports(), 1);
    assert!(driver.pending.is_none());
    let Export::Calls(packet) = export.try_recv().unwrap() else {
        panic!("actual Calls send")
    };
    assert_eq!(packet.native.journal().as_ptr(), address);
    assert_eq!(packet.native.journal(), &[77; 512]);
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    let failure = driver.deadline_failure().unwrap();
    assert_eq!(failure.phase, DeadlinePhase::SinkExportAccepted);
    assert!(!failure.at_limit_is_late);
    assert_eq!(
        failure.observed,
        Some(driver.policy.lateness() + Duration::from_nanos(1))
    );
    no_native(&driver);
}
#[test]
fn real_retired_report_burst_shares_one_hard_budget_and_counts_late_acceptance() {
    let Prepared {
        mut driver, export, ..
    } = prepared();
    for _ in 0..SLOTS {
        driver.arm().unwrap();
        assert!(matches!(export.try_recv().unwrap(), Export::History(_)));
    }
    driver.close().unwrap();
    driver.history().unwrap();
    assert!(matches!(export.try_recv().unwrap(), Export::History(_)));
    let generations = driver
        .slots
        .iter()
        .map(|e| e.as_ref().unwrap().generation().get())
        .collect::<Vec<_>>();
    driver.policy = driver.policy.with_sink_backpressure();
    let start = Instant::now();
    let clock = Clock::new(start, driver.policy).unwrap();
    let budget = clock.export_budget(Some(start), None).unwrap();
    driver.sink.budget = Some(budget);
    let us = Duration::from_micros(250);
    sink::with_clock(
        script([
            start,
            start + us,
            start + us * 2,
            start + us * 3,
            start + us * 4,
            start + Duration::from_millis(2) + Duration::from_nanos(1),
        ]),
        || {
            assert_eq!(driver.retire(), Err(Error::Deadline));
        },
    );
    assert_eq!(driver.sink.budget, Some(budget));
    assert_eq!((driver.reports, driver.accepted_exports()), (3, 7));
    assert!(driver.pending.is_none());
    assert!(driver.slots.iter().all(Option::is_none));
    assert_eq!(model::backoff_test_retained(&driver.controller), 0);
    for generation in generations {
        let Export::Report(report) = export.try_recv().unwrap() else {
            panic!("real retired Report")
        };
        assert_eq!(report.generation, generation);
        assert!(report.records.is_empty()); // No invocation was fabricated.
    }
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert_eq!(
        driver.deadline_failure().unwrap().phase,
        DeadlinePhase::SinkExportAccepted
    );
    no_native(&driver);
}
#[test]
fn original_next_arm_all_issued_and_early_stop_budgets_do_not_renew() {
    let start = Instant::now();
    let policy = Policy::ten_ms(10, 520, 100000)
        .unwrap()
        .with_sink_backpressure();
    let mut clock = Clock::new(start, policy).unwrap();
    let next = clock.body_export_budget(17).unwrap();
    assert_eq!(
        next,
        clock
            .export_budget(Some(start + policy.period() * 17), None)
            .unwrap()
    );
    let all = clock.body_export_budget(520).unwrap();
    assert_eq!(all, clock.export_budget(None, None).unwrap());
    let observed = start + Duration::from_millis(171);
    assert_eq!(clock.poll(observed, true, 17), Ok(Decision::Stop));
    let stopped = clock.body_export_budget(17).unwrap();
    assert_eq!(stopped, clock.body_export_budget(520).unwrap());
    assert_ne!(stopped, all);
    let deadline = observed + policy.shutdown();
    assert_eq!(
        clock.check_deadline(deadline - Duration::from_nanos(1)),
        Ok(())
    );
    assert_eq!(clock.check_deadline(deadline), Err(Error::Deadline));
    assert_eq!(
        clock.poll(deadline - Duration::from_nanos(1), false, 17),
        Ok(Decision::Wait)
    );
    assert_eq!(clock.body_export_budget(17).unwrap(), stopped);
    let (tx, rx) = mpsc::sync_channel(EXPORT_QUEUE);
    let mut context = sink::Context {
        budget: Some(stopped),
    };
    let mut pending = None;
    let mut accepted = 0;
    let mut failure = None;
    sink::with_clock(script([deadline]), || {
        assert_eq!(
            context.emit(&tx, 9, &mut pending, &mut accepted, &mut failure),
            Err(Error::Deadline)
        )
    });
    assert_eq!((pending, accepted), (Some(9), 0));
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert!(failure.unwrap().at_limit_is_late);
    assert_eq!(failure.unwrap().limit, Some(Duration::from_millis(2171)));
}
#[test]
fn request_during_real_arm_wait_is_acknowledged_by_actual_stop_branch() {
    let Prepared {
        mut driver,
        client,
        stop,
        export,
    } = prepared();
    driver.policy = driver.policy.with_sink_backpressure();
    let start = Instant::now();
    for generation in 800..804 {
        driver
            .output
            .try_send(Export::Report(FinalReport {
                generation,
                records: Vec::new(),
            }))
            .unwrap();
    }
    let rx = Rc::new(RefCell::new(export));
    let wait_rx = rx.clone();
    let time = Rc::new(Cell::new(start));
    let now = time.clone();
    let scheduler_time = time.clone();
    let waits = Rc::new(Cell::new(0_u32));
    let wait_count = waits.clone();
    let requested = stop.clone();
    let mut client = Some(client);
    let hook = sink::TestClock::new(
        move || now.get(),
        move |duration| {
            assert_eq!(duration, Duration::from_micros(250));
            let n = wait_count.get() + 1;
            wait_count.set(n);
            assert!(n <= 2);
            assert!(matches!(
                wait_rx.borrow().try_recv().unwrap(),
                Export::Report(_)
            ));
            requested.request();
            if n == 2 {
                drop(client.take());
            }
            time.set(start + Duration::from_millis(10) * (n - 1) + duration);
        },
    );
    let later = start + Duration::from_millis(10);
    let mut observations = [
        start,
        start,
        start + Duration::from_micros(250),
        later,
        later,
        later,
        later,
        later + Duration::from_micros(250),
    ]
    .into_iter();
    let result = sink::with_clock(hook, || {
        run_loop_with(DriverRef::Mandatory(&mut driver), start, || {
            let at = observations.next().expect("exact scheduler observations");
            scheduler_time.set(at);
            at
        })
    });
    assert!(matches!(result, Err(Error::Worker))); // No fake finished receipt.
    assert_eq!(waits.get(), 2);
    assert!(stop.requested());
    assert_eq!(driver.arms, 1);
    assert!(driver.close_attempted);
    assert_eq!(driver.current, None);
    assert_eq!(driver.history_window().unwrap().current(), None);
    assert_eq!(driver.history_end, 2);
    let mut expected_clock = Clock::new(start, driver.policy).unwrap();
    assert_eq!(expected_clock.poll(later, true, 1), Ok(Decision::Stop));
    assert_eq!(
        driver.sink.budget,
        Some(expected_clock.body_export_budget(1).unwrap())
    );
    assert_eq!(driver.accepted_exports(), 2);
    assert!(driver.pending.is_none());
    let mut kinds = Vec::new();
    while let Ok(packet) = rx.borrow().try_recv() {
        if let Export::History(h) = packet {
            kinds.push(h.actions()[0].kind);
        }
    }
    assert_eq!(kinds, [ActionKind::Published, ActionKind::Removed]);
    no_native(&driver);
}

#[test]
fn mixed_history_calls_and_report_do_not_replace_the_context_budget() {
    let Prepared {
        mut driver, export, ..
    } = prepared();
    driver.policy = driver.policy.with_sink_backpressure();
    let start = Instant::now();
    let clock = Clock::new(start, driver.policy).unwrap();
    let budget = clock.export_budget(Some(start), Some(start)).unwrap();
    driver.sink.budget = Some(budget);
    let us = Duration::from_micros(250);
    let hook = script([
        start,
        start + us,
        start + us * 2,
        start + us * 3,
        start + us * 4,
        start + us * 5,
        start + us * 6,
        start + Duration::from_millis(2) + Duration::from_nanos(1),
    ]);
    sink::with_clock(hook, || {
        driver.arm().unwrap();
        let native = model::backoff_test_transport(driver.stream.clone(), 91);
        // Transport-only sentinel, not cursor/native admission.
        driver
            .emit(Export::Calls(Box::new(CompletedBatch {
                native,
                calls: [None; ROWS],
            })))
            .unwrap();
        driver.close().unwrap();
        driver.history().unwrap();
        assert_eq!(driver.retire(), Err(Error::Deadline));
    });
    assert_eq!(driver.sink.budget, Some(budget));
    assert_eq!(driver.accepted_exports(), 4);
    assert!(driver.pending.is_none());
    assert!(matches!(export.try_recv().unwrap(), Export::History(_)));
    assert!(matches!(export.try_recv().unwrap(), Export::Calls(_)));
    assert!(matches!(export.try_recv().unwrap(), Export::History(_)));
    assert!(matches!(export.try_recv().unwrap(), Export::Report(_)));
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    no_native(&driver);
}
#[test]
fn opt_in_run_refusals_clear_budget_and_keep_failure_before_cleanup() {
    for mode in 0..3 {
        let Prepared {
            mut driver,
            client,
            stop,
            export: _export,
        } = prepared();
        driver.policy = driver.policy.with_sink_backpressure();
        let start = Instant::now() + Duration::from_secs(1);
        driver.sink.budget = Some(
            Clock::new(start, driver.policy)
                .unwrap()
                .body_export_budget(0)
                .unwrap(),
        );
        if mode == 0 {
            driver.started = true;
        }
        if mode == 1 {
            driver.shared.start.set(start).unwrap();
        }
        if mode == 2 {
            stop.request();
        }
        drop(client);
        let expected = if mode == 2 {
            Error::Worker
        } else {
            Error::AlreadyStarted
        };
        assert_eq!(driver.run(start), Err(expected));
        assert!(driver.shared.controller_failed.load(Ordering::Acquire));
        assert!(driver.sink.budget.is_none());
        assert_eq!(driver.close_attempted, mode == 2);
        assert_eq!(driver.current, None);
        assert_eq!(driver.accepted_exports(), 0);
        assert!(driver.pending.is_none());
        no_native(&driver);
    }
}
