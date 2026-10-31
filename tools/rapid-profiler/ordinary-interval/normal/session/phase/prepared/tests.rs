use super::*;
fn setup(ms: u32, epochs: u32, delay: u64) -> (Arc<Shared>, super::super::Worker, Instant) {
    let p = Policy::accuracy(10, ms, epochs, 4096).unwrap();
    let request = Request::new(super::super::Request::new("random", delay, p).unwrap(), 1).unwrap();
    let phase = super::super::Shared::new(request.phase());
    let gate = Shared::new(request, Arc::clone(&phase));
    let worker = super::super::Worker::new(phase);
    (gate, worker, Instant::now())
}
fn arm(g: &Shared, generation: u64) -> ArmObservation {
    let due = g.request.phase.policy.period();
    ArmObservation {
        number: 2,
        generation,
        due,
        started: due,
        completed: due,
        accepted: true,
    }
}
fn start(g: &Shared, t: Instant) {
    g.prepared(t).unwrap();
    g.start(t, g.request.phase.policy).unwrap();
    g.phase.first_arm(Duration::ZERO).unwrap();
}
#[test]
fn prepared_request_is_fixed_j_no_extra_epoch_and_original_profiles_unchanged() {
    for ms in [1, 10, 100] {
        for k in [1, 10, 100, 1000] {
            let p = Policy::accuracy(k, ms, 2, 4096).unwrap();
            let phase =
                super::super::Request::new("random", u64::from(ms) * 1_000_000 - 1, p).unwrap();
            let r = Request::new(phase, 1).unwrap();
            assert_eq!(r.phase().policy(), p);
            assert_eq!(r.target, u64::from(ms) * 2_000_000 - 1);
            assert_eq!(r.end, u64::from(ms) * 2_000_000);
            assert_eq!(
                phase.header(),
                format!("PHASE,random,{}\n", u64::from(ms) * 1_000_000 - 1)
            );
            assert!(Request::new(phase, 0).is_err());
            assert!(Request::new(phase, 2).is_err());
        }
    }
    let p = Policy::accuracy(10, 1, 1, 4096).unwrap();
    let old = super::super::Request::new("locked", 0, p).unwrap();
    assert!(Request::new(old, 1).is_err());
    assert_eq!(
        old.ready(),
        "READY,selected-accuracy-phase-session-v1,10,1,1,2,64,"
    );
}
#[test]
fn prepared_barrier_precedes_one_origin_and_records_actual_ready_lead() {
    let (g, mut w, t) = setup(10, 3, 0);
    assert!(g.start(t, g.request.phase.policy).is_err());
    g.prepared(t).unwrap();
    assert!(!g.poll_with(&mut w, || t).unwrap()); // no fabricated origin/ARM
    assert!(
        g.start(t - Duration::from_nanos(1), g.request.phase.policy)
            .is_err()
    );
    g.start(t + Duration::from_nanos(7), g.request.phase.policy)
        .unwrap();
    assert_eq!(g.barrier_line().unwrap(), "PREPARED,1,41,7\n");
    assert!(g.prepared(t).is_err());
    assert!(g.start(t, g.request.phase.policy).is_err());
    assert!(g.hold_input());
}
#[test]
fn prepared_requires_actual_accepted_arm2_and_keeps_generation_not_epoch_arithmetic() {
    let (g, mut w, t) = setup(10, 3, 0);
    start(&g, t);
    assert!(
        !g.poll_with(&mut w, || t + Duration::from_millis(10))
            .unwrap()
    );
    for bad in [
        ArmObservation {
            number: 1,
            ..arm(&g, 73)
        },
        ArmObservation {
            number: 3,
            ..arm(&g, 73)
        },
        ArmObservation {
            accepted: false,
            ..arm(&g, 73)
        },
        ArmObservation {
            generation: 0,
            ..arm(&g, 73)
        },
        ArmObservation {
            due: Duration::ZERO,
            ..arm(&g, 73)
        },
        ArmObservation {
            started: Duration::from_millis(9),
            ..arm(&g, 73)
        },
        ArmObservation {
            started: Duration::from_millis(11),
            ..arm(&g, 73)
        },
        ArmObservation {
            completed: Duration::from_millis(12) + Duration::from_nanos(1),
            ..arm(&g, 73)
        },
    ] {
        assert!(g.target_arm(bad).is_err());
    }
    assert_eq!(
        g.target_arm(arm(&g, 73)).unwrap(),
        "TARGET_ARM,2,73,10000000,10000000,10000000\n"
    );
    assert!(g.target_arm(arm(&g, 73)).is_err());
    assert!(
        g.poll_with(&mut w, || t + Duration::from_millis(10))
            .unwrap()
    );
    assert!(
        g.begin_with(&mut w, || t + Duration::from_millis(10))
            .unwrap()
    );
    assert_eq!(g.arm.get().unwrap().generation, 73);
    let (g, mut w, t) = setup(10, 3, 0);
    start(&g, t);
    g.target_arm(ArmObservation {
        completed: Duration::from_millis(12),
        ..arm(&g, 74)
    })
    .unwrap();
    assert!(
        !g.poll_with(&mut w, || t + Duration::from_millis(10))
            .unwrap()
    );
    assert!(
        g.poll_with(&mut w, || t + Duration::from_millis(12))
            .unwrap()
    );
    assert!(
        g.begin_with(&mut w, || t + Duration::from_millis(12))
            .unwrap()
    );
    assert_eq!(g.gate.get().unwrap().opened - g.request.target, 2_000_000);
    // Exact 2 ms remains accepted ARM lateness, never a claimed phase tolerance.
}
#[test]
fn prepared_gate_checks_target_edges_whole_period_misses_end_and_clock_regression() {
    for offset in [0, 10_000_000] {
        let (g, mut w, t) = setup(10, 4, 581_334);
        start(&g, t);
        assert!(
            !g.poll_with(&mut w, || t + Duration::from_nanos(10_581_333))
                .unwrap()
        );
        g.target_arm(arm(&g, 9)).unwrap();
        assert!(
            !g.poll_with(&mut w, || t + Duration::from_nanos(10_581_333))
                .unwrap()
        );
        assert!(
            g.poll_with(&mut w, || t + Duration::from_nanos(10_581_334 + offset))
                .unwrap()
        );
        assert!(
            g.begin_with(&mut w, || t + Duration::from_nanos(10_581_334 + offset))
                .unwrap()
        );
        assert_eq!(g.gate.get().unwrap().opened - g.request.target, offset);
        assert!(g.complete().is_err());
        g.returned().unwrap();
        assert!(!g.hold_input());
        assert!(
            g.poll_with(&mut w, || t + Duration::from_millis(30))
                .is_err()
        );
        assert!(g.cancel().is_err());
    }
    let (g, mut w, t) = setup(1, 2, 0);
    start(&g, t);
    g.target_arm(arm(&g, 8)).unwrap();
    assert!(
        !g.poll_with(&mut w, || t + Duration::from_millis(2))
            .unwrap()
    );
    assert!(g.hold_input()); // setup can exhaust epochs; never add another
    assert!(
        g.poll_with(&mut w, || t + Duration::from_millis(1))
            .is_err()
    );
    let (g, mut w, t) = setup(1, 2, 0);
    start(&g, t);
    assert!(
        g.poll_with(&mut w, || t + Duration::from_nanos(g.request.phase.fence))
            .is_err()
    );
}
#[test]
fn prepared_cancel_never_fabricates_release_return_or_full_population() {
    let (g, mut w, t) = setup(10, 3, 0);
    start(&g, t);
    assert!(!g.poll_with(&mut w, || t + Duration::from_nanos(1)).unwrap());
    g.cancel().unwrap();
    assert_eq!(
        g.cancellation_line().unwrap(),
        "CANCELLED,1,41,never_invoked,10000000,1,0\n"
    );
    assert!(g.cancel().is_err());
    assert!(g.returned().is_err());
    assert!(
        g.poll_with(&mut w, || t + Duration::from_millis(10))
            .is_err()
    );
    assert!(g.phase.release().is_err());
    assert!(g.phase.complete(0).is_err());
    assert!(g.complete().is_err());
    assert!(g.hold_input()); // EOF cannot claim a completion for this failure
}
#[test]
fn prepared_real_phase_clock_requires_all2048_and_keeps_shared_monotonicity() {
    let (g, mut w, t) = setup(10, 3, 0);
    start(&g, t);
    g.target_arm(arm(&g, 91)).unwrap();
    assert!(
        g.poll_with(&mut w, || t + Duration::from_millis(10))
            .unwrap()
    );
    for id in 1..=CALLS as u64 {
        let before = t + Duration::from_nanos(10_000_000 + id * 2);
        if id == 1 {
            assert!(g.begin_with(&mut w, || before).unwrap());
        } else {
            w.before_with(id, 0, || before).unwrap();
        }
        // Pure timestamps only; this does not manufacture a native Call/receipt.
        w.returned(before + Duration::from_nanos(1)).unwrap();
        assert!(g.phase.row(id, id, FUNCTION).is_ok());
        if id < CALLS as u64 {
            assert!(g.phase.complete(id as usize).is_err());
        }
    }
    g.returned().unwrap();
    g.complete().unwrap();
    g.phase.complete(CALLS).unwrap();
    assert!(
        w.before_with(2049, 0, || t + Duration::from_millis(11))
            .is_err()
    );
    let (g, mut w, t) = setup(10, 3, 0);
    start(&g, t);
    g.target_arm(arm(&g, 91)).unwrap();
    assert!(
        g.poll_with(&mut w, || t + Duration::from_millis(10))
            .unwrap()
    );
    assert!(
        g.begin_with(&mut w, || t + Duration::from_millis(9))
            .is_err()
    );
}

#[test]
fn prepared_final_admission_refuses_end_after_custody_without_fabricated_timing() {
    for crossing in [false, true] {
        let (g, mut w, t) = setup(10, 2, 0);
        start(&g, t);
        g.target_arm(arm(&g, 99)).unwrap();
        assert!(
            g.poll_with(&mut w, || t + Duration::from_millis(10))
                .unwrap()
        );
        let mut reads = 0;
        assert!(
            !g.begin_with(&mut w, || {
                reads += 1;
                if crossing && reads == 1 {
                    t + Duration::from_nanos(19_999_999)
                } else {
                    t + Duration::from_millis(20)
                }
            })
            .unwrap()
        );
        assert!(w.pending.is_none());
        assert!(g.phase.release.get().is_none());
        assert!(g.gate.get().is_none());
        assert!(g.hold_input());
        g.cancel().unwrap();
        assert!(g.cancellation_line().is_ok());
    }
}

#[test]
fn prepared_poll_acquires_origin_before_sampling_and_keeps_real_regressions() {
    let (g, mut w, t) = setup(10, 3, 0);
    g.prepared(t).unwrap();
    let sampled = std::cell::Cell::new(0);
    // In the former race, this could sample t before start publishes t+1.
    // The actual production seam now never calls the reader without origin.
    assert!(
        !g.poll_with(&mut w, || {
            sampled.set(sampled.get() + 1);
            panic!("clock must not be sampled before acquiring published origin")
        })
        .unwrap()
    );
    assert_eq!(sampled.get(), 0);
    assert!(!w.failed);
    let origin = t + Duration::from_nanos(1);
    g.start(origin, g.request.phase.policy).unwrap();
    assert!(
        !g.poll_with(&mut w, || {
            assert_eq!(g.phase.origin.get(), Some(&origin));
            sampled.set(sampled.get() + 1);
            origin
        })
        .unwrap()
    );
    assert_eq!(sampled.get(), 1);
    assert!(!w.failed);
    assert_eq!(w.last, 0);
    // A genuinely regressing clock after acquisition is still fatal/sticky.
    assert!(g.poll_with(&mut w, || t).is_err());
    assert!(w.failed);
    assert!(
        g.poll_with(&mut w, || origin + Duration::from_millis(1))
            .is_err()
    );
}
