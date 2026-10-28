use super::*;
use rapid_profiler::frontend::{
    FailurePoint, FunctionSpec, GroupSpec, Limits, ModelReturnSlot, Session,
};
use rapid_profiler::frontend_native::RawTimestamp;
use rapid_profiler::generation::Config;

struct Fixture {
    expected: Expected,
    transitions: Vec<Transition>,
    calls: Vec<Call>,
    records: [Vec<RecordObservation>; 3],
    totals: PairTotals,
    end: u64,
}
fn fixture(old_return_after_remove: bool) -> Fixture {
    let session = Session::new(
        7,
        &[FunctionSpec {
            function: FunctionId(1),
            group: 0,
        }],
        &[GroupSpec { mandatory: true }],
        Limits {
            epochs: 3,
            threads: 1,
            depth: 1,
            records_per_epoch: 32,
            actions: 6,
        },
    )
    .unwrap();
    let epochs = std::array::from_fn::<_, 3, _>(|_| {
        session
            .stage(Config {
                retained_per_function: 32,
                max_inflight: 1,
                max_invocations: 32,
            })
            .unwrap()
    });
    let generations = epochs.each_ref().map(|e| e.generation().get());
    let values = std::array::from_fn(|i| {
        let n = if i % 2 == 0 { 1 } else { 64 };
        (0..n)
            .map(|j| u64::from(((j * 37 + 11) as u8) ^ 0x5a))
            .sum::<u64>()
            ^ 0x9e37_79b9_7f4a_7c15
    });
    let expected = Expected {
        generations,
        values,
        entry: 0x1000,
        ret: 0x1024,
    };
    let base = 1_000_000;
    let transitions = (0..6)
        .map(|i| {
            let requested = if i == 0 {
                0
            } else {
                base + [0, 30, 40, 70, 80, 110][i] * 1_000_000
            };
            Transition {
                index: i,
                generation: generations[i / 2],
                requested,
                before: if i == 0 { 500_000 } else { requested },
                after: if i == 0 { base } else { requested + 100 },
            }
        })
        .collect();
    let mut model = session.register_thread(1).unwrap();
    let mut calls = Vec::new();
    for (epoch, handle) in epochs.iter().enumerate() {
        session.publish(handle, FailurePoint::None).unwrap();
        for j in 0..8 {
            let i = epoch * 8 + j;
            if j == 6 && !(old_return_after_remove && epoch == 0) {
                session.remove_current().unwrap();
            }
            let start = 100 + 10 * i as u64;
            let owner = if j < 6 {
                let mut slot = ModelReturnSlot {
                    identity: i as u64 + 1,
                    word: 0x4000,
                };
                let admission = model.enter(7, FunctionId(1), start, &mut slot).unwrap();
                if old_return_after_remove && i == 5 {
                    session.remove_current().unwrap();
                }
                model
                    .finish(&mut slot, Observation::Value(start + 3))
                    .unwrap();
                assert_eq!(slot.word, 0x4000);
                RawIntervalOwner::Sampled {
                    generation: admission.generation.get(),
                    invocation: admission.invocation,
                }
            } else {
                RawIntervalOwner::Removed {
                    generation: generations[epoch],
                }
            };
            let before = base + (epoch as u64 * 40 + [2, 7, 12, 17, 22, 27, 32, 37][j]) * 1_000_000;
            calls.push(Call {
                external_id: i as u64 + 1000,
                length: if i % 2 == 0 { 1 } else { 64 },
                raw: RawInterval {
                    ordinal: i as u64 + 1,
                    entry_pc: expected.entry,
                    return_pc: expected.ret,
                    owner,
                    start: RawTimestamp {
                        ticks: start,
                        aux: 1,
                    },
                    end: RawTimestamp {
                        ticks: start + 3,
                        aux: 1,
                    },
                },
                call: CallResult {
                    value: values[i],
                    pre_call_rsp: 0x3000,
                    entry_rsp: 0x2ff8,
                    resumed_rsp: 0x3000,
                    return_pc: expected.ret,
                },
                before,
                after: if old_return_after_remove && i == 5 {
                    base + 31_000_000
                } else {
                    before + 1000
                },
            });
        }
    }
    assert_eq!(session.snapshot().unwrap().actions.len(), 6);
    let records = epochs
        .each_ref()
        .map(|e| e.try_report().unwrap().records().collect());
    Fixture {
        expected,
        transitions,
        calls,
        records,
        totals: PairTotals {
            entries: 24,
            returns: 24,
            completed: 18,
            unsampled: 6,
        },
        end: base + 120_000_000,
    }
}
fn validate(f: &Fixture) -> Result<(usize, usize), Error> {
    let counts = calls(&f.transitions, &f.calls, f.totals, f.end, &f.expected)?;
    reports(&f.calls, &f.records, &f.expected)?;
    Ok(counts)
}

#[test]
fn three_epochs_and_actual_old_owner_completion_after_remove_join_exactly() {
    for boundary in [false, true] {
        let f = fixture(boundary);
        assert_eq!(validate(&f), Ok((18, 6)));
        assert_eq!(
            f.records.iter().map(Vec::len).collect::<Vec<_>>(),
            [6, 6, 6]
        );
        assert_eq!(f.records[1][0].payload.unwrap().start_sequence, 6);
        assert_eq!(f.records[2][0].payload.unwrap().start_sequence, 12);
    }
}

#[test]
fn wrong_identity_boundary_result_stack_clock_and_owner_refuse() {
    for mutant in 0..11 {
        let mut f = fixture(false);
        match mutant {
            0 => f.calls[1].external_id = 1000,
            1 => f.calls[1].raw.ordinal = 1,
            2 => f.calls[0].raw.entry_pc += 1,
            3 => f.calls[0].call.return_pc += 1,
            4 => f.calls[0].call.value ^= 1,
            5 => f.calls[0].call.resumed_rsp += 8,
            6 => f.calls[0].raw.end.aux ^= 1,
            7 => f.calls[0].raw.end.ticks = f.calls[0].raw.start.ticks - 1,
            8 => {
                f.calls[0].raw.owner = RawIntervalOwner::Removed {
                    generation: f.expected.generations[0],
                }
            }
            9 => {
                f.calls[0].raw.owner = RawIntervalOwner::Sampled {
                    generation: 0,
                    invocation: 0,
                }
            }
            10 => {
                f.calls[0].raw.owner = RawIntervalOwner::FunctionClosed {
                    generation: f.expected.generations[0],
                }
            }
            _ => unreachable!(),
        }
        assert!(validate(&f).is_err(), "mutant {mutant}");
    }
    let mut f = fixture(false);
    f.calls[8].raw.owner = RawIntervalOwner::Removed {
        generation: f.expected.generations[0],
    };
    assert_eq!(validate(&f), Err(Error::Owner));
}

#[test]
fn report_payload_terminal_and_cross_epoch_sequence_are_not_replaceable() {
    for mutant in 0..6 {
        let mut f = fixture(false);
        match mutant {
            0 => f.records[1][0].payload.as_mut().unwrap().start_sequence = 0,
            1 => f.records[1][0].payload.as_mut().unwrap().thread = 2,
            2 => {
                f.records[1][0].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(f.calls[8].raw.end.ticks),
                    completed_children: 1,
                }
            }
            3 => {
                f.records[1][0].record.terminal = Some(Terminal::Completed {
                    value: 1,
                    disposition: Disposition::Retained { rank: 0 },
                })
            }
            4 => {
                f.records[1].pop();
            }
            5 => {
                let extra = f.records[1][0];
                f.records[1].push(extra);
            }
            _ => unreachable!(),
        }
        assert_eq!(validate(&f), Err(Error::Report), "mutant {mutant}");
    }
}

#[test]
fn missed_off_window_is_failure_without_dropping_or_rescheduling_calls() {
    let mut f = fixture(false);
    for i in 22..24 {
        f.calls[i].before = f.end + (i as u64 - 21) * 1_000_000;
        f.calls[i].after = f.calls[i].before + 1000;
    }
    assert_eq!(reports(&f.calls, &f.records, &f.expected), Ok(()));
    assert_eq!(validate(&f), Err(Error::Coverage));
    assert_eq!(f.calls.len(), 24);
    f.calls.pop();
    assert_eq!(validate(&f), Err(Error::Schedule));
}

#[test]
fn changed_deadlines_or_invented_totals_refuse() {
    let mut f = fixture(false);
    f.transitions[1].requested += 1;
    assert_eq!(validate(&f), Err(Error::Schedule));
    let mut f = fixture(false);
    f.totals.completed += 1;
    assert_eq!(validate(&f), Err(Error::Totals));
}
