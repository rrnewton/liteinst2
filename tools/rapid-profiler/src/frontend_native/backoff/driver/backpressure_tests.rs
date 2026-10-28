//! Real run() error exits, with no native calls or fabricated completion.
use super::*;
use crate::frontend_native::always_on as model;

fn prepared() -> Prepared {
    // SAFETY: metadata-only synthetic site, no installation/execution or reentry.
    unsafe {
        prepare(
            model::backoff_test_site(),
            71,
            FunctionId(11),
            Policy::ten_ms(10, 4, 4).unwrap().with_worker_backpressure(),
        )
    }
    .unwrap()
}
#[test]
fn every_run_error_exit_publishes_sticky_failure_without_early_close() {
    for mode in 0..3 {
        let Prepared {
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
            driver.shared.start.set(start).unwrap();
        }
        // Requested stop before start + a disconnected worker makes run_inner
        // refuse Worker immediately, independent of the 2ms arm schedule.
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
        assert_eq!(driver.close_attempted, mode == 2);
        assert_eq!(driver.current, None);
        assert_eq!((driver.arms, driver.reports, driver.exported), (0, 0, 0));
        assert_eq!(driver.cursor.totals, PairTotals::default());
        assert!(driver.shared.finished.get().is_none());
        assert!(driver.pending.is_none());
        assert_eq!(driver.run(start), Err(Error::AlreadyStarted));
        assert!(driver.shared.controller_failed.load(Ordering::Acquire));
        assert_eq!(driver.close_attempted, mode == 2);
    }
}
