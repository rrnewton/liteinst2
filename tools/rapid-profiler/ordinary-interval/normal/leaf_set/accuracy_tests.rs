//! Consumer binding and literal READY prefix controls; no native execution.
use super::*;

#[test]
fn accuracy_ready_binds_actual_period_and_old_headers_remain_literal() {
    for k in [1, 10, 100, 1000] {
        for ms in [1, 10, 100] {
            let p = Policy::accuracy(k, ms, 520, 4096).unwrap();
            assert_eq!(schedule_policy(k, 520, Some(p)).unwrap(), p);
            assert_eq!(
                ready_header("selected-session-v1", k, 520, Some(p)),
                format!("READY,selected-accuracy-session-v1,{k},520,{ms},2,64,")
            );
        }
    }
    assert_eq!(
        ready_header("selected-session-v1", 10, 520, None),
        "READY,selected-session-v1,10,520,10,2,64,"
    );
    assert_eq!(
        ready_header("selected-session-v1", 1000, 1, None),
        "READY,selected-session-v1,1000,1,10,2,64,"
    );
    assert_eq!(
        ready_header("leaf-set-session-v1", 10, 520, None),
        "READY,leaf-set-session-v1,10,520,10,2,64,"
    );
    for k in [10, 1000] {
        assert_eq!(
            schedule_policy(k, 520, None).unwrap(),
            Policy::ten_ms(k, 520, 4096).unwrap()
        );
    }
}

#[test]
fn consumer_refuses_legacy_substitution_wrong_k_epochs_calls_or_transport_options() {
    let p = Policy::accuracy(1, 1, 520, 4096).unwrap();
    for (k, e, policy) in [
        (10, 520, Policy::ten_ms(10, 520, 4096).unwrap()),
        (100, 520, p),
        (1, 519, p),
        (1, 520, Policy::accuracy(1, 1, 520, 4095).unwrap()),
        (1, 520, p.with_worker_backpressure()),
        (1, 520, p.with_sink_backpressure()),
    ] {
        assert_eq!(
            schedule_policy(k, e, Some(policy)).err().as_deref(),
            Some("selected accuracy policy binding mismatch")
        );
    }
    assert!(schedule_policy(1, 520, None).is_err());
    assert!(schedule_policy(100, 520, None).is_err());
}

#[test]
fn arm_wire_keeps_actual_observations_and_late_completed_arms() {
    let a = shared::ArmObservation {
        number: 2,
        generation: 7,
        due: Duration::from_millis(1),
        started: Duration::from_millis(2),
        completed: Duration::from_micros(3001),
        accepted: false,
    };
    assert_eq!(arm_line(a), "ARM,2,7,1000000,2000000,3001000,0\n");
    assert_eq!(
        arm_line(shared::ArmObservation {
            accepted: true,
            ..a
        }),
        "ARM,2,7,1000000,2000000,3001000,1\n"
    );
    let extreme = shared::ArmObservation {
        number: u32::MAX,
        generation: u64::MAX,
        due: Duration::MAX,
        started: Duration::MAX,
        completed: Duration::MAX,
        accepted: false,
    };
    validate_line(&arm_line(extreme));
}
