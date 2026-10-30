//! Explicit observations drive the real Schedule; these are not OS timing evidence.
use super::*;

fn start() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
fn grant(s: &mut Schedule, observed: Instant, due: Instant) {
    assert_eq!(s.poll(observed, false), Ok(ScheduleDecision::Arm { due }));
}

#[test]
fn matrix_has_exact_original_dues_520_acknowledged_arms_and_exclusive_shutdown() {
    for k in [1, 10, 100, 1000] {
        for ms in [1, 10, 100] {
            let start = start();
            let p = Policy::accuracy(k, ms, 520, 4096).unwrap();
            let mut s = Schedule::new(start, p).unwrap();
            for n in 0..520 {
                let due = start + p.period() * n;
                assert_eq!(
                    s.poll(due - Duration::from_nanos(1), false),
                    Ok(ScheduleDecision::Wait)
                );
                assert_eq!(
                    s.wait_bound(due - Duration::from_nanos(1)),
                    Ok(Duration::from_nanos(1))
                );
                grant(&mut s, due, due);
                assert_eq!(s.armed(), n);
                assert_eq!(s.pending_arm(), Some(due));
                s.arm_completed(due).unwrap();
                assert_eq!(s.armed(), n + 1);
            }
            let end = start + p.period() * 520;
            assert_eq!(
                s.poll(end - Duration::from_nanos(1), false),
                Ok(ScheduleDecision::Wait)
            );
            assert_eq!(s.poll(end, false), Ok(ScheduleDecision::Stop));
            assert_eq!(
                s.check_completion(end + p.shutdown() - Duration::from_nanos(1)),
                Ok(StopReason::EpochLimit)
            );
            assert_eq!(s.armed(), 520);
            assert_eq!(s.poll(end, false), Err(Error::Sequence));
        }
    }
}

#[test]
fn overlapping_one_ms_windows_keep_original_dues_without_renewing_lateness() {
    let start = start();
    let p = Policy::accuracy(1, 1, 4, 4096).unwrap();
    let observed = start + Duration::from_millis(2);
    let mut s = Schedule::new(start, p).unwrap();
    for n in 0..3 {
        // All three grants remain distinct original dues, although observed at
        // one time. Equality at the first due+2ms is accepted, not shifted.
        let due = start + p.period() * n;
        grant(&mut s, observed, due);
        s.arm_completed(observed).unwrap();
        assert_eq!(s.armed(), n + 1);
    }
    assert_eq!(s.wait_bound(observed), Ok(Duration::from_millis(1)));
    let due = start + p.period() * 3;
    grant(&mut s, due, due);
    s.arm_completed(due).unwrap();
    assert_eq!(
        s.poll(start + p.period() * 4, false),
        Ok(ScheduleDecision::Stop)
    );
    assert_eq!(s.armed(), 4);
}

#[test]
fn every_period_keeps_two_ms_edges_sticky_failure_and_actual_completed_count() {
    for ms in [1, 10, 100] {
        let start = start();
        let p = Policy::accuracy(100, ms, 4, 4096).unwrap();
        let edge = start + Duration::from_millis(2);
        let late = edge + Duration::from_nanos(1);
        let mut s = Schedule::new(start, p).unwrap();
        grant(&mut s, edge, start);
        s.arm_completed(edge).unwrap();
        assert_eq!(s.armed(), 1);
        let mut s = Schedule::new(start, p).unwrap();
        assert_eq!(s.poll(late, false), Err(Error::Deadline));
        assert_eq!(s.poll(start, false), Err(Error::Deadline));
        assert_eq!(s.armed(), 0);
        let mut s = Schedule::new(start, p).unwrap();
        grant(&mut s, start, start);
        assert_eq!(s.arm_completed(late), Err(Error::Deadline));
        assert_eq!(s.armed(), 1); // real completed operation survives refusal
        assert_eq!(s.pending_arm(), None);
        assert_eq!(s.poll(start, true), Err(Error::Deadline));
        assert_eq!(s.arm_completed(start), Err(Error::Deadline));
    }
}

#[test]
fn one_ms_end_and_requested_stop_do_not_get_a_fresh_arm_or_shutdown_budget() {
    let start = start();
    let p = Policy::accuracy(1, 1, 1, 4096).unwrap();
    let end = start + p.period();
    let mut missed = Schedule::new(start, p).unwrap();
    // The finite end still refuses a missing arm, even inside due+2ms.
    assert_eq!(missed.poll(end, false), Err(Error::Deadline));
    assert_eq!(missed.armed(), 0);
    let mut s = Schedule::new(start, p).unwrap();
    grant(&mut s, start, start);
    s.arm_completed(start).unwrap();
    assert_eq!(s.poll(end, false), Ok(ScheduleDecision::Stop));
    assert_eq!(s.check_completion(end + p.shutdown()), Err(Error::Deadline));
    let mut s = Schedule::new(start, p).unwrap();
    let requested = start + Duration::from_micros(500);
    assert_eq!(s.poll(requested, true), Ok(ScheduleDecision::Stop));
    assert_eq!(
        s.poll(requested + Duration::from_millis(1), true),
        Ok(ScheduleDecision::Wait)
    );
    assert_eq!(
        s.check_completion(requested + p.shutdown()),
        Err(Error::Deadline)
    );
    assert_eq!(s.armed(), 0);
    let mut pending = Schedule::new(start, p).unwrap();
    grant(&mut pending, start, start);
    assert_eq!(pending.poll(start, false), Err(Error::Sequence));
    assert_eq!(pending.arm_completed(start), Err(Error::Sequence));
}
