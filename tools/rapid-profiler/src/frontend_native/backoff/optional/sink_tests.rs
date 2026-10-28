//! Real optional metadata operations; no native Fast/Slow or finish credit.
use super::*;
use crate::frontend::{ActionKind, ControllerStatus};
use std::cell::Cell;
use std::rc::Rc;

fn prepared() -> OptionalPrepared {
    // SAFETY: existing metadata-only site, no executable publication/attachment.
    unsafe {
        prepare_optional(
            crate::frontend_native::always_on::optional::metadata_site(),
            82,
            FunctionId(13),
            Policy::ten_ms(10, 4, 100).unwrap(),
        )
    }
    .unwrap()
}
fn no_native(d: &OptionalDriver) {
    assert_eq!(d.cursor.number, 0);
    assert_eq!(d.cursor.totals, OptionalTotals::default());
    assert!(d.shared.finished.get().is_none());
    assert_eq!(optional_finished_ok(None), Err(Error::Worker));
}
#[test]
fn missing_budget_keeps_optional_history_and_never_falls_back() {
    let OptionalPrepared {
        mut driver, export, ..
    } = prepared();
    driver.policy = driver.policy.with_sink_backpressure();
    assert_eq!(driver.arm(), Err(Error::Sequence));
    assert_eq!(driver.accepted_exports(), 0);
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    let Some(OptionalExport::History(h)) = driver.pending.as_ref() else {
        panic!("retained Published")
    };
    assert_eq!(h.range(), 0..1);
    assert_eq!(h.actions()[0].kind, ActionKind::Published);
    assert!(driver.deadline_failure().is_none());
    driver.close().unwrap();
    assert_eq!(
        driver.history_window().unwrap().actions()[0].kind,
        ActionKind::Removed
    );
    no_native(&driver);
}
#[test]
fn optional_full_and_disconnect_keep_history_removed_and_unread_sink_items() {
    for disconnected in [false, true] {
        let OptionalPrepared {
            mut driver,
            client,
            export,
            ..
        } = prepared();
        driver.policy = driver.policy.with_sink_backpressure();
        let rx = if disconnected {
            drop(export);
            None
        } else {
            for generation in 800..804 {
                driver
                    .output
                    .try_send(OptionalExport::Report(FinalReport {
                        generation,
                        records: Vec::new(),
                    }))
                    .unwrap();
            }
            Some(export)
        };
        let start = Instant::now();
        let budget = sink::Budget::new(
            start,
            Some(start),
            driver.policy.lateness(),
            start + Duration::from_secs(1),
            Some(start),
        )
        .unwrap();
        driver.sink.budget = Some(budget);
        let clock = Rc::new(Cell::new(start));
        let now = clock.clone();
        let waits = Rc::new(Cell::new(0));
        let waited = waits.clone();
        let hook = sink::TestClock::new(
            move || now.get(),
            move |duration| {
                assert!(!disconnected);
                assert_eq!(duration, Duration::from_micros(250));
                waited.set(waited.get() + 1);
                clock.set(clock.get() + duration);
            },
        );
        let expected = if disconnected {
            Error::Disconnected
        } else {
            Error::Full
        };
        sink::with_clock(hook, || assert_eq!(driver.arm(), Err(expected)));
        assert_eq!(waits.get(), if disconnected { 0 } else { 4 });
        assert_eq!(driver.sink.budget, Some(budget));
        let Some(OptionalExport::History(first)) = driver.pending.as_ref() else {
            panic!("actual Published")
        };
        let address = first.actions().as_ptr();
        let action = first.actions()[0];
        driver.close().unwrap();
        let window = driver.history_window().unwrap();
        assert_eq!(window.status(), ControllerStatus::Ready);
        assert_eq!(window.range(), 1..2);
        assert_eq!(window.current(), None);
        assert_eq!(window.actions()[0].kind, ActionKind::Removed);
        let Some(OptionalExport::History(first)) = driver.take_pending() else {
            panic!("same packet")
        };
        assert_eq!(first.actions().as_ptr(), address);
        assert_eq!(first.actions(), &[action]);
        let last = driver.recover_history().unwrap().unwrap();
        assert!(last.follows(&first));
        assert_eq!(last.actions(), window.actions());
        let report = driver.recover_report().unwrap().unwrap();
        assert_eq!(report.generation, action.generation.get());
        assert!(report.records.is_empty());
        assert_eq!(driver.accepted_exports(), 0); // Recovery is not delivery.
        assert!(driver.deadline_failure().is_none());
        if let Some(rx) = rx {
            for generation in 800..804 {
                let OptionalExport::Report(r) = rx.try_recv().unwrap() else {
                    panic!("transport filler")
                };
                assert_eq!(r.generation, generation);
            }
            assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        }
        drop(client);
        assert_eq!(driver.receive_one(Duration::ZERO), Err(Error::Worker));
        no_native(&driver);
    }
}
#[test]
fn genuine_optional_report_copy_is_delivered_before_late_failure_without_pending() {
    let OptionalPrepared {
        mut driver, export, ..
    } = prepared();
    let mut model = driver.controller.metadata_model().unwrap();
    driver.arm().unwrap();
    assert!(matches!(
        export.try_recv().unwrap(),
        OptionalExport::History(_)
    ));
    driver
        .controller
        .metadata_complete(&mut model, driver.slots[0].as_ref().unwrap(), 10)
        .unwrap();
    driver.scan().unwrap();
    assert!(matches!(
        export.try_recv().unwrap(),
        OptionalExport::History(_)
    ));
    driver.arm().unwrap();
    assert!(matches!(
        export.try_recv().unwrap(),
        OptionalExport::History(_)
    ));
    let report = driver
        .controller
        .report(driver.slots[0].as_ref().unwrap())
        .unwrap()
        .unwrap();
    let generation = report.generation().get();
    let records = report.records().collect::<Vec<_>>();
    drop(report);
    assert_eq!(records.len(), 10);
    driver.policy = driver.policy.with_sink_backpressure();
    let start = Instant::now();
    let budget = sink::Budget::new(
        start,
        Some(start),
        driver.policy.lateness(),
        start + Duration::from_secs(1),
        None,
    )
    .unwrap();
    driver.sink.budget = Some(budget);
    let mut times = [
        start,
        start + driver.policy.lateness() + Duration::from_nanos(1),
    ]
    .into_iter();
    let hook = sink::TestClock::new(move || times.next().unwrap(), |_| panic!("unblocked send"));
    sink::with_clock(hook, || assert_eq!(driver.retire(), Err(Error::Deadline)));
    assert_eq!(driver.sink.budget, Some(budget));
    assert_eq!((driver.reports, driver.accepted_exports()), (1, 4));
    assert!(driver.pending.is_none());
    assert!(driver.slots[0].is_none());
    assert!(driver.slots[1].is_some());
    let OptionalExport::Report(actual) = export.try_recv().unwrap() else {
        panic!("actual Report accepted")
    };
    assert_eq!(actual.generation, generation);
    assert_eq!(actual.records, records);
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert_eq!(
        driver.deadline_failure().unwrap().phase,
        DeadlinePhase::SinkExportAccepted
    );
    no_native(&driver);
}

#[test]
fn optional_opt_in_run_refusals_clear_budget_without_fabricating_finish() {
    for mode in 0..3 {
        let OptionalPrepared {
            mut driver,
            client,
            stop,
            export: _export,
        } = prepared();
        driver.policy = driver.policy.with_sink_backpressure();
        let start = Instant::now() + Duration::from_secs(1);
        driver.sink.budget = Some(
            sink::Budget::new(
                start,
                Some(start),
                driver.policy.lateness(),
                start + Duration::from_secs(3),
                None,
            )
            .unwrap(),
        );
        if mode == 0 {
            driver.started = true;
        }
        if mode == 1 {
            driver.shared.common.start.set(start).unwrap();
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
        assert!(
            driver
                .shared
                .common
                .controller_failed
                .load(Ordering::Acquire)
        );
        assert!(driver.sink.budget.is_none());
        assert_eq!(driver.close_attempted, mode == 2);
        assert_eq!(driver.current, None);
        assert_eq!(driver.accepted_exports(), 0);
        assert!(driver.pending.is_none());
        no_native(&driver);
    }
}
