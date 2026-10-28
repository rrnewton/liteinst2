//! Pure metadata/transport controls only. No native return or publication credit.
use super::*;

#[test]
fn optional_finish_requires_real_profile_balance_detach_and_no_loss() {
    let totals = OptionalTotals {
        physical: 5,
        bypassed: 3,
        observed: PairTotals {
            entries: 2,
            returns: 2,
            completed: 1,
            unsampled: 1,
        },
    };
    let good = OptionalWorkerStatus {
        totals: Some(totals),
        detached: true,
        error: None,
        unexported: false,
    };
    assert_eq!(optional_finished_ok(Some(good)), Ok(()));
    assert_eq!(optional_finished_ok(None), Err(Error::Worker));
    for bad in [
        OptionalWorkerStatus {
            detached: false,
            ..good
        },
        OptionalWorkerStatus {
            error: Some(Error::Full),
            ..good
        },
        OptionalWorkerStatus {
            unexported: true,
            ..good
        },
        OptionalWorkerStatus {
            totals: None,
            ..good
        },
        OptionalWorkerStatus {
            totals: Some(OptionalTotals {
                bypassed: 2,
                ..totals
            }),
            ..good
        },
        OptionalWorkerStatus {
            totals: Some(OptionalTotals {
                observed: PairTotals {
                    completed: 2,
                    unsampled: 1,
                    ..totals.observed
                },
                ..totals
            }),
            ..good
        },
    ] {
        assert_eq!(optional_finished_ok(Some(bad)), Err(Error::Worker));
    }
}
#[test]
fn typed_optional_endpoints_move_but_no_unsafe_send_is_needed() {
    fn send<T: Send>() {}
    send::<OptionalDriver>();
    send::<OptionalClient>();
    send::<OptionalExport>();
    send::<OptionalWorkerFinish>();
    assert_eq!(
        (ROWS, SLOTS, HISTORY, WORK_QUEUE, EXPORT_QUEUE),
        (4, 3, 8, 2, 4)
    );
    let p = Policy::ten_ms(10, 520, 100000).unwrap();
    assert_eq!(
        (p.period(), p.lateness(), p.shutdown()),
        (
            Duration::from_millis(10),
            Duration::from_millis(2),
            Duration::from_secs(2)
        )
    );
    assert_eq!((p.epoch_limit(), p.call_limit()), (520, 100000));
}
#[test]
fn optional_full_and_disconnection_retain_exact_report_copy() {
    // Deliberately inert copied report data; never claimed to come from retire().
    let (tx, rx) = mpsc::sync_channel(1);
    send(
        &tx,
        OptionalExport::Report(FinalReport {
            generation: 10,
            records: Vec::new(),
        }),
    )
    .unwrap();
    let (e, p) = send(
        &tx,
        OptionalExport::Report(FinalReport {
            generation: 11,
            records: Vec::new(),
        }),
    )
    .unwrap_err();
    assert_eq!(e, Error::Full);
    let OptionalExport::Report(r) = &p else {
        panic!("retained variant")
    };
    assert_eq!(r.generation, 11);
    drop(rx);
    let (e, p) = send(&tx, p).unwrap_err();
    assert_eq!(e, Error::Disconnected);
    let OptionalExport::Report(r) = p else {
        panic!("retained variant")
    };
    assert_eq!(r.generation, 11);
}

fn prepared() -> OptionalPrepared {
    // SAFETY: cfg(test) metadata site only; no executable image, attachment,
    // invocation, source writer, signal, fork or controller reentry exists.
    unsafe {
        prepare_optional(
            crate::frontend_native::always_on::optional::metadata_site(),
            71,
            FunctionId(11),
            Policy::ten_ms(10, 4, 100).unwrap(),
        )
    }
    .unwrap()
}
fn history(
    export: &mpsc::Receiver<OptionalExport>,
    kind: crate::frontend::ActionKind,
) -> HistoryBatch {
    let OptionalExport::History(b) = export.try_recv().unwrap() else {
        panic!("actual history expected")
    };
    assert_eq!(b.actions().len(), 1);
    assert_eq!(b.actions()[0].kind, kind);
    b
}
fn no_native_credit(d: &OptionalDriver) {
    assert_eq!(d.cursor.number, 0);
    assert_eq!(d.cursor.totals, OptionalTotals::default());
    assert!(d.shared.finished.get().is_none());
    assert_eq!(optional_finished_ok(None), Err(Error::Worker));
}
#[test]
fn real_scans_latch_each_generation_once_and_rearm_without_fabricating_fast_calls() {
    use crate::frontend::ActionKind;
    let OptionalPrepared {
        mut driver,
        client: _client,
        export,
        ..
    } = prepared();
    let mut model = driver.controller.metadata_model().unwrap();
    driver.arm().unwrap();
    let a = history(&export, ActionKind::Published);
    let first = driver.slots[0].as_ref().unwrap().generation();
    driver.scan().unwrap();
    assert_eq!((driver.disabled, driver.history_end), (0, 1));
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    driver
        .controller
        .metadata_complete(&mut model, driver.slots[0].as_ref().unwrap(), 10)
        .unwrap();
    driver.scan().unwrap();
    let disabled = history(&export, ActionKind::Disabled);
    assert!(disabled.follows(&a));
    assert_eq!(disabled.actions()[0].generation, first);
    assert_eq!(driver.disabled_generation, Some(first.get()));
    driver.scan().unwrap();
    assert_eq!((driver.disabled, driver.history_end), (1, 2));
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    driver.arm().unwrap();
    let b = history(&export, ActionKind::Published);
    assert!(b.follows(&disabled));
    assert_eq!(driver.disabled_generation, None);
    let second = driver.slots[1].as_ref().unwrap().generation();
    assert_ne!(first, second);
    driver.retire().unwrap();
    let OptionalExport::Report(old) = export.try_recv().unwrap() else {
        panic!("real report")
    };
    assert_eq!(old.generation, first.get());
    assert_eq!(old.records.len(), 10);
    driver.scan().unwrap();
    assert_eq!((driver.disabled, driver.history_end), (1, 3));
    driver
        .controller
        .metadata_complete(&mut model, driver.slots[1].as_ref().unwrap(), 10)
        .unwrap();
    driver.scan().unwrap();
    let disabled = history(&export, ActionKind::Disabled);
    assert!(disabled.follows(&b));
    driver.close().unwrap();
    driver.history().unwrap();
    let removed = history(&export, ActionKind::Removed);
    assert!(removed.follows(&disabled));
    driver.scan().unwrap();
    driver.retire().unwrap();
    let OptionalExport::Report(new) = export.try_recv().unwrap() else {
        panic!("real report")
    };
    assert_eq!(new.generation, second.get());
    assert_eq!(new.records.len(), 10);
    assert_eq!(
        (
            driver.arms,
            driver.reports,
            driver.disabled,
            driver.history_end
        ),
        (2, 2, 2, 5)
    );
    assert!(driver.slots.iter().all(Option::is_none));
    assert_eq!(driver.current, None);
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    // Real model admission/finish and selector maintenance above are not native
    // CALL/RET or OB-ACCEPTANCE-1 evidence. No Fast result was manufactured.
    no_native_credit(&driver);
}
#[test]
fn optional_pending_history_survives_full_or_disconnect_and_final_removed_stays_resident() {
    use crate::frontend::{ActionKind, ControllerStatus};
    for disconnected in [false, true] {
        let OptionalPrepared {
            mut driver,
            client,
            stop,
            export,
        } = prepared();
        let output = if disconnected {
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
        drop(client);
        let expected = if disconnected {
            Error::Disconnected
        } else {
            Error::Full
        };
        assert_eq!(driver.arm(), Err(expected));
        let Some(OptionalExport::History(first)) = driver.pending.as_ref() else {
            panic!("retained Published")
        };
        let address = first.actions().as_ptr();
        let action = first.actions()[0];
        assert_eq!(action.kind, ActionKind::Published);
        assert_eq!(first.range(), 0..1);
        stop.request();
        driver.close().unwrap();
        let window = driver.history_window().unwrap();
        assert_eq!(window.range(), 1..2);
        assert_eq!(window.status(), ControllerStatus::Ready);
        assert_eq!(window.current(), None);
        assert_eq!(window.actions()[0].kind, ActionKind::Removed);
        let Some(OptionalExport::History(first)) = driver.take_pending() else {
            panic!("lost Published")
        };
        assert_eq!(first.actions().as_ptr(), address);
        assert_eq!(first.actions(), &[action]);
        let last = driver.recover_history().unwrap().unwrap();
        assert!(last.follows(&first));
        assert_eq!(last.actions(), window.actions());
        assert!(driver.recover_history().unwrap().is_none());
        let report = driver.recover_report().unwrap().unwrap();
        assert_eq!(report.generation, action.generation.get());
        assert!(report.records.is_empty());
        assert!(driver.recover_report().unwrap().is_none());
        assert_eq!((driver.arms, driver.reports, driver.exported), (1, 1, 0));
        assert_eq!(driver.receive_one(Duration::ZERO), Err(Error::Worker));
        no_native_credit(&driver);
        if let Some(rx) = output {
            for generation in 800..804 {
                let OptionalExport::Report(r) = rx.try_recv().unwrap() else {
                    panic!("inert filler")
                };
                assert_eq!(r.generation, generation);
            }
        }
    }
}
#[test]
fn optional_shared_scheduler_refuses_unstarted_duplicate_and_disconnected_workers() {
    for mode in 0..3 {
        let OptionalPrepared {
            mut driver,
            client,
            stop,
            export: _export,
        } = prepared();
        let start = Instant::now() + Duration::from_secs(1);
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
        assert_eq!(driver.close_attempted, mode == 2);
        assert_eq!(driver.current, None);
        assert_eq!(
            (
                driver.arms,
                driver.reports,
                driver.disabled,
                driver.exported
            ),
            (0, 0, 0, 0)
        );
        assert!(driver.pending.is_none());
        no_native_credit(&driver);
        assert_eq!(driver.run(start), Err(Error::AlreadyStarted));
        assert_eq!(driver.close_attempted, mode == 2);
    }
}

mod native;
