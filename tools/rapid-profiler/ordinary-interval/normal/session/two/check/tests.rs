use super::*;
use rapid_profiler::frontend::Payload;
use rapid_profiler::frontend_native::RawTimestamp;
use rapid_profiler::generation::{Admission, Epoch, Record};
fn refused(f: impl FnOnce()) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
}
fn epoch() -> Epoch {
    Epoch::new(
        &[FUNCTION],
        Config {
            retained_per_function: 1,
            max_inflight: 2,
            max_invocations: 4,
        },
    )
    .unwrap()
}
fn row(epoch: &Epoch, slot: usize, disposition: Disposition, thread: u64) -> RecordObservation {
    let admission = Admission {
        generation: epoch.id(),
        invocation: slot,
        function: FUNCTION,
        entry_value: 100,
    };
    RecordObservation {
        record: Record {
            admission,
            terminal: Some(Terminal::Completed {
                value: slot as u64,
                disposition,
            }),
        },
        payload: Some(Payload {
            admission,
            thread,
            start_sequence: 4,
            outcome: PayloadOutcome::Completed {
                end: Observation::Value(110),
                completed_children: 0,
            },
        }),
    }
}
fn raw(row: &RecordObservation) -> RawInterval {
    RawInterval {
        ordinal: 3,
        entry_pc: 0x1000,
        return_pc: 0x1022,
        owner: RawIntervalOwner::Sampled {
            generation: row.record.admission.generation.get(),
            invocation: row.record.admission.invocation,
        },
        start: RawTimestamp { ticks: 100, aux: 3 },
        end: RawTimestamp { ticks: 110, aux: 3 },
    }
}
#[test]
fn global_slots_and_retained_ranks_accept_out_of_order_but_refuse_corruption() {
    let epoch = epoch();
    // Worker2's slot1 completes first; slot0 is dropped. Receive/rank order is
    // intentionally not slot order. Every admission still owns its payload.
    let rows = [
        row(&epoch, 1, Disposition::Retained { rank: 0 }, 2),
        row(&epoch, 0, Disposition::DroppedAfterBudget, 1),
    ];
    assert_eq!(
        report(epoch.id().get(), &rows, 1),
        Counts {
            admitted: 2,
            retained: 1,
            dropped: 1
        }
    );
    assert_eq!(
        sample(&rows[0], raw(&rows[0]), 2, 4),
        ("retained", 1, Observation::Value(110))
    );
    assert_eq!(
        sample(&rows[1], raw(&rows[1]), 1, 4),
        ("dropped", 0, Observation::Value(110))
    );
    for mutation in 0..8 {
        let mut bad = rows;
        match mutation {
            0 => {
                bad[0].record.admission.invocation = 2;
                bad[0].payload.as_mut().unwrap().admission.invocation = 2;
                bad[0].record.terminal = Some(Terminal::Completed {
                    value: 2,
                    disposition: Disposition::Retained { rank: 0 },
                });
            }
            1 => bad[1] = bad[0],
            2 => {
                bad[0].record.terminal = Some(Terminal::Completed {
                    value: 1,
                    disposition: Disposition::Retained { rank: 1 },
                })
            }
            3 => {
                bad[0].record.terminal = Some(Terminal::Completed {
                    value: 1,
                    disposition: Disposition::DroppedAfterBudget,
                })
            }
            4 => {
                bad[1].record.terminal = Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::Retained { rank: 0 },
                })
            }
            5 => bad[0].record.terminal = None,
            6 => bad[0].payload = None,
            7 => {
                bad[1].record.terminal = Some(Terminal::Completed {
                    value: 1,
                    disposition: Disposition::DroppedAfterBudget,
                })
            }
            _ => unreachable!(),
        }
        refused(|| {
            report(epoch.id().get(), &bad, 1);
        });
    }
    refused(|| {
        report(epoch.id().get(), &rows[..1], 1);
    });
    let generation = epoch.id().get();
    let mut final_counts = BTreeMap::new();
    refused(|| closed_budget(generation, &final_counts, 1));
    final_counts.insert(
        generation,
        Counts {
            admitted: 0,
            retained: 0,
            dropped: 0,
        },
    );
    refused(|| closed_budget(generation, &final_counts, 1));
    final_counts.insert(generation, report(generation, &rows, 1));
    closed_budget(generation, &final_counts, 1);
}
#[test]
fn both_dispositions_join_actual_registration_sequence_and_raw_endpoints() {
    let epoch = epoch();
    for disposition in [
        Disposition::Retained { rank: 0 },
        Disposition::DroppedAfterBudget,
    ] {
        let row = row(&epoch, 1, disposition, 2);
        let interval = raw(&row);
        sample(&row, interval, 2, 4);
        for mutation in 0..9 {
            let mut bad = row;
            match mutation {
                0 => bad.record.admission.entry_value += 1,
                1 => bad.record.admission.function = FunctionId(2),
                2 => bad.record.terminal = None,
                3 => bad.payload.as_mut().unwrap().thread = 1,
                4 => bad.payload.as_mut().unwrap().start_sequence += 1,
                5 => bad.payload.as_mut().unwrap().admission.invocation = 0,
                6 => {
                    bad.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                        end: Observation::Value(109),
                        completed_children: 0,
                    }
                }
                7 => {
                    bad.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                        end: Observation::Value(110),
                        completed_children: 1,
                    }
                }
                8 => bad.payload = None,
                _ => unreachable!(),
            }
            refused(|| {
                sample(&bad, interval, 2, 4);
            });
        }
        let mut interval = interval;
        interval.end.ticks = 99;
        interval.end.aux = 4;
        let mut unavailable = row;
        unavailable.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
            end: Observation::Unavailable(1),
            completed_children: 0,
        };
        assert_eq!(
            sample(&unavailable, interval, 2, 4).2,
            Observation::Unavailable(1)
        );
        interval.end.aux = 3;
        refused(|| {
            sample(&unavailable, interval, 2, 4);
        });
        unavailable.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
            end: Observation::Unavailable(2),
            completed_children: 0,
        };
        assert_eq!(
            sample(&unavailable, interval, 2, 4).2,
            Observation::Unavailable(2)
        );
    }
}
#[test]
fn local_identity_acknowledgement_and_whole_page_cannot_cross_workers() {
    let epoch = epoch();
    let row = row(&epoch, 0, Disposition::Retained { rank: 0 }, 1);
    let mut interval = raw(&row);
    interval.ordinal = 1;
    let record = NormalRecord {
        raw: interval,
        entry_rsp: 0x8008,
        return_word: 0x2005,
        history_prefix: 513,
        acknowledgement: NormalAcknowledgement::CallerCheckpoint,
    };
    let generation = epoch.id().get();
    let mut page = [0; 512];
    page[..18].copy_from_slice(&[
        2, 0, 9, 0, 1, 1, 0x1000, 0x8008, 0x2005, generation, 0x1002001, 2, 1, 0x1022, 0x8008,
        0x2005, generation, 0x1002001,
    ]);
    journal(&[record], &page, 9);
    for at in [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 511,
    ] {
        let mut wrong = page;
        wrong[at] ^= 1;
        refused(|| journal(&[record], &wrong, 9));
    }
    refused(|| journal(&[record], &page, 10));
    refused(|| journal(&[record], &page[..511], 9));
    acknowledgement(record, true);
    refused(|| acknowledgement(record, false));
    let mut next = record;
    next.acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 2 };
    acknowledgement(next, false);
    next.acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 3 };
    refused(|| acknowledgement(next, false));
    let expected = [u64::from(std::process::id()), 9, 1, INSTALL, FUNCTION.0];
    identity(0, [9, 10], expected);
    for i in 0..5 {
        let mut wrong = expected;
        wrong[i] += 1;
        refused(|| identity(0, [9, 10], wrong));
    }
    refused(|| identity(1, [9, 10], expected));
    assert_eq!(
        owner(
            interval.owner,
            HistoryBinding::Published {
                action_index: 512,
                generation: epoch.id()
            },
            513
        )
        .0,
        "sampled"
    );
    refused(|| {
        owner(
            interval.owner,
            HistoryBinding::Published {
                action_index: 512,
                generation: epoch.id(),
            },
            512,
        );
    });
    refused(|| {
        owner(interval.owner, HistoryBinding::Initial, 513);
    });
}
