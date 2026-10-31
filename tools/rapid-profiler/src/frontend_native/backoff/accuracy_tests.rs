//! Constructor controls only; no timing or native success is inferred.
use super::*;

#[test]
fn accuracy_matrix_is_explicit_and_keeps_finite_and_deadline_bounds() {
    for k in [1, 10, 100, 1000] {
        for ms in [1, 10, 100] {
            for (epochs, calls) in [(1, 1), (4096, 1_000_000)] {
                let p = Policy::accuracy(k, ms, epochs, calls).unwrap();
                assert!(p.is_accuracy());
                assert_eq!(p.retained(), k);
                assert_eq!(p.epoch_limit(), epochs);
                assert_eq!(p.call_limit(), calls);
                assert_eq!(p.period(), Duration::from_millis(u64::from(ms)));
                assert_eq!(p.lateness(), Duration::from_millis(2));
                assert_eq!(p.shutdown(), Duration::from_secs(2));
                assert!(!p.worker_backpressure() && !p.sink_backpressure());
                assert_eq!(
                    p.config(),
                    Config {
                        retained_per_function: k,
                        max_inflight: 1,
                        max_invocations: k,
                    }
                );
            }
        }
    }
    for (k, ms, epochs, calls) in [
        (0, 1, 1, 1),
        (2, 1, 1, 1),
        (1001, 1, 1, 1),
        (usize::MAX, 1, 1, 1),
        (1, 0, 1, 1),
        (1, 2, 1, 1),
        (1, 1000, 1, 1),
        (1, u32::MAX, 1, 1),
        (1, 1, 0, 1),
        (1, 1, 4097, 1),
        (1, 1, 1, 0),
        (1, 1, 1, 1_000_001),
    ] {
        assert_eq!(Policy::accuracy(k, ms, epochs, calls), Err(Error::Policy));
    }
}

#[test]
fn legacy_constructor_is_not_an_accuracy_policy_even_at_identical_numbers() {
    for k in [10, 1000] {
        let old = Policy::ten_ms(k, 520, 4096).unwrap();
        let accuracy = Policy::accuracy(k, 10, 520, 4096).unwrap();
        assert!(!old.is_accuracy());
        assert_ne!(old, accuracy);
        assert_eq!(old.period(), Duration::from_millis(10));
        assert_eq!(old.lateness(), accuracy.lateness());
        assert_eq!(old.shutdown(), accuracy.shutdown());
        assert_eq!(old.config(), accuracy.config());
        assert!(!old.worker_backpressure() && !old.sink_backpressure());
    }
    for k in [1, 100] {
        assert_eq!(Policy::ten_ms(k, 520, 4096), Err(Error::Policy));
    }
}

#[test]
fn old_driver_boundary_refuses_accuracy_before_any_activation() {
    for k in [1, 10, 100, 1000] {
        for ms in [1, 10, 100] {
            let p = Policy::accuracy(k, ms, 520, 4096).unwrap();
            for candidate in [p, p.with_worker_backpressure(), p.with_sink_backpressure()] {
                assert_eq!(candidate.require_legacy_driver(), Err(Error::Policy));
            }
        }
    }
    for k in [10, 1000] {
        let p = Policy::ten_ms(k, 520, 4096).unwrap();
        for candidate in [p, p.with_worker_backpressure(), p.with_sink_backpressure()] {
            assert_eq!(candidate.require_legacy_driver(), Ok(()));
        }
    }
}
