use super::*;
fn totals(n: u64) -> NormalTotals {
    NormalTotals {
        entered: n,
        ret_observed: n,
        confirmed: n,
        completed: 0,
        unsampled: n,
    }
}
#[test]
fn partial_broadcast_full_acknowledgements_and_stop_keep_exact_custody() {
    let (a, ar) = mpsc::sync_channel(1);
    let (b, br) = mpsc::sync_channel(1);
    b.send(Command::Call {
        id: 8,
        bound: 0,
        bytes: vec![],
    })
    .unwrap();
    let tx = [a, b];
    let mut d = Dispatch {
        pending: Some(Pending::Flush(Barrier::new(Some(u64::MAX), [3, 2]))),
        stop: None,
    };
    assert!(d.advance(&tx, true, [3, 2]).unwrap());
    let Some(Pending::Flush(barrier)) = d.pending.as_ref() else {
        panic!()
    };
    assert_eq!(barrier.sent, [true, false]);
    assert!(d.stop.is_none());
    assert!(d.flushed(1, u64::MAX, totals(2)).is_err(), "not sent");
    assert!(d.flushed(0, 9, totals(3)).is_err(), "wrong ID");
    assert!(d.flushed(0, u64::MAX, totals(2)).is_err(), "wrong prefix");
    assert!(d.flushed(2, u64::MAX, totals(3)).is_err(), "foreign worker");
    assert_eq!(ar.try_recv().unwrap(), Command::Flush { id: u64::MAX });
    assert!(!d.flushed(0, u64::MAX, totals(3)).unwrap());
    assert!(d.flushed(0, u64::MAX, totals(3)).is_err(), "duplicate");
    assert!(!d.advance(&tx, true, [3, 2]).unwrap());
    assert!(ar.try_recv().is_err(), "no resend of successful half");
    assert_eq!(
        br.try_recv().unwrap(),
        Command::Call {
            id: 8,
            bound: 0,
            bytes: vec![]
        }
    );
    assert!(d.advance(&tx, true, [3, 2]).unwrap());
    assert_eq!(br.try_recv().unwrap(), Command::Flush { id: u64::MAX });
    assert!(d.stop.is_none());
    assert!(d.flushed(1, u64::MAX, totals(2)).unwrap());
    assert!(d.pending.is_none());
    assert!(d.advance(&tx, true, [3, 2]).unwrap());
    assert_eq!(ar.try_recv().unwrap(), Command::Stop);
    assert_eq!(br.try_recv().unwrap(), Command::Stop);
    assert!(!d.advance(&tx, true, [3, 2]).unwrap());
    assert!(!d.complete());
    d.finished(0, totals(3)).unwrap();
    assert!(!d.complete());
    assert!(d.finished(0, totals(3)).is_err());
    assert!(d.finished(1, totals(1)).is_err());
    d.finished(1, totals(2)).unwrap();
    assert!(d.complete());
}
#[test]
fn full_call_and_partial_disconnected_broadcast_never_reroute_or_disappear() {
    let (a, ar) = mpsc::sync_channel(1);
    let (b, br) = mpsc::sync_channel(1);
    a.send(Command::Flush { id: 1 }).unwrap();
    let tx = [a, b];
    let mut d = Dispatch {
        pending: Some(Pending::Call {
            worker: 0,
            command: Command::Call {
                id: u64::MAX,
                bound: 1,
                bytes: vec![0],
            },
        }),
        stop: None,
    };
    assert!(!d.advance(&tx, true, [1, 0]).unwrap());
    assert!(matches!(
        &d.pending,
        Some(Pending::Call {
            worker: 0,
            command: Command::Call { id: u64::MAX, .. }
        })
    ));
    assert!(br.try_recv().is_err());
    drop(ar);
    assert!(d.advance(&tx, true, [1, 0]).is_err());
    assert!(d.pending.is_some() && d.stop.is_none());
    let (a, ar) = mpsc::sync_channel(1);
    let (b, br) = mpsc::sync_channel(1);
    drop(br);
    let mut d = Dispatch {
        pending: Some(Pending::Flush(Barrier::new(Some(7), [0, 0]))),
        stop: None,
    };
    assert!(d.advance(&[a, b], true, [0, 0]).is_err());
    let Some(Pending::Flush(barrier)) = d.pending else {
        panic!()
    };
    assert_eq!(barrier.id, Some(7));
    assert_eq!(barrier.sent, [true, false]);
    assert_eq!(barrier.ack, [false, false]);
    assert!(d.stop.is_none());
    assert_eq!(ar.try_recv().unwrap(), Command::Flush { id: 7 });
}
#[test]
fn complete_output_envelope_retains_maximum_ids_and_population() {
    assert_eq!(output_bound(4096, 0, 4096), 1_749_369);
    assert!(output_bound(0, 4096, 4096) < 1_749_369);
    assert!(output_bound(4095, 1, 4096) < 1_749_369);
    for (calls, flushes, arms) in [
        (4096, 1, 4096),
        (0, 4097, 1),
        (0, 0, 4097),
        (usize::MAX, 1, 1),
    ] {
        assert!(std::panic::catch_unwind(|| output_bound(calls, flushes, arms)).is_err());
    }
    // These are the actual shared input validator and ID set, not a new grammar.
    let command = protocol::parse(b"CALL 18446744073709551615 0 -").unwrap();
    let mut ids = protocol::Ids::default();
    ids.accept(&command).unwrap();
    assert!(ids.accept(&Command::Flush { id: u64::MAX }).is_err());
}
