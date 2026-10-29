//! Fabricated observations test the actual pure predicates. Native authority
//! comes only from the separately executed command, never these fixture values.
use super::*;
use rapid_profiler::frontend::Payload;
use rapid_profiler::frontend_native::RawTimestamp;
use rapid_profiler::generation::{Admission, Epoch, Record};
struct Fixture {
    k: usize,
    a: u64,
    b: u64,
    rows: Vec<NormalRecord>,
    returned: Vec<Returned>,
    payloads: Vec<RecordObservation>,
    reports: Vec<ReportSpan>,
    actions: Vec<check::HistoryRow>,
    phases: Vec<Phase>,
}
impl Fixture {
    fn new(k: usize) -> Self {
        let cfg = Config {
            retained_per_function: k,
            max_inflight: 1,
            max_invocations: k,
        };
        let ids = [
            Epoch::new(&[FUNCTION], cfg).unwrap().id(),
            Epoch::new(&[FUNCTION], cfg).unwrap().id(),
        ];
        let (a, b) = (ids[0].get(), ids[1].get());
        let t = hold_ordinal(k) as usize;
        let mut rows = Vec::new();
        let mut returned = Vec::new();
        let mut payloads = Vec::new();
        for g in 0..CALLS {
            let (at, local) = if g < t { (0, g) } else { (1, g - t) };
            let sampled = local < k;
            let row = NormalRecord {
                raw: RawInterval {
                    ordinal: g as u64 + 1,
                    entry_pc: 0x1000,
                    return_pc: 0x1024,
                    owner: if sampled {
                        RawIntervalOwner::Sampled {
                            generation: ids[at].get(),
                            invocation: local,
                        }
                    } else {
                        RawIntervalOwner::FunctionClosed {
                            generation: ids[at].get(),
                        }
                    },
                    start: RawTimestamp {
                        ticks: g as u64 * 2,
                        aux: 7,
                    },
                    end: RawTimestamp {
                        ticks: g as u64 * 2 + 1,
                        aux: 7,
                    },
                },
                entry_rsp: 0x8008,
                return_word: 0x2000 + if g % 2 == 0 { 30 } else { 48 },
                history_prefix: at as u64 + 1,
                acknowledgement: if g % 24 == 23 {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: g as u64 + 2,
                    }
                },
            };
            if sampled {
                let admission = Admission {
                    generation: ids[at],
                    function: FUNCTION,
                    invocation: local,
                    entry_value: row.raw.start.ticks,
                };
                payloads.push(RecordObservation {
                    record: Record {
                        admission,
                        terminal: Some(Terminal::Completed {
                            value: local as u64,
                            disposition: Disposition::Retained { rank: local },
                        }),
                    },
                    payload: Some(Payload {
                        admission,
                        thread: 1,
                        start_sequence: payloads.len() as u64,
                        outcome: PayloadOutcome::Completed {
                            end: Observation::Value(row.raw.end.ticks),
                            completed_children: 0,
                        },
                    }),
                });
            }
            rows.push(row);
            returned.push(Returned {
                id: g as u64 + 1,
                value: case(g).value,
            });
        }
        let history: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| HistoryCopy {
                number: i as u64 + 1,
                range: i as u64..i as u64 + 1,
                before: if i == 0 {
                    HistoryBinding::Initial
                } else {
                    HistoryBinding::Published {
                        action_index: 0,
                        generation: ids[0],
                    }
                },
                after: HistoryBinding::Published {
                    action_index: i as u64,
                    generation: id,
                },
                actions: vec![Action {
                    kind: ActionKind::Published,
                    generation: id,
                    function: None,
                    current: Some(id),
                    group: None,
                }],
            })
            .collect();
        let snapshot = Snapshot {
            slots: [Some((a, Some(0))), Some((b, None)), None],
            current: Some(1),
            banks: 1,
            reports: vec![ReportSpan {
                generation: a,
                start: 0,
                end: k,
            }],
            payloads: payloads[..k].to_vec(),
            history,
            stream: (17, INSTALL, FUNCTION),
            committed: 2,
        };
        let mut after = snapshot.clone();
        after.slots[0] = None;
        after.banks = 2;
        let phases = [snapshot.clone(), snapshot, after]
            .into_iter()
            .enumerate()
            .map(|(i, snapshot)| Phase {
                number: i + 1,
                totals: phase_totals(k, i + 1),
                completed_batches: (t - 22) / 24,
                snapshot,
            })
            .collect();
        Self {
            k,
            a,
            b,
            rows,
            returned,
            payloads,
            reports: vec![
                ReportSpan {
                    generation: a,
                    start: 0,
                    end: k,
                },
                ReportSpan {
                    generation: b,
                    start: k,
                    end: 2 * k,
                },
            ],
            actions: vec![
                check::HistoryRow {
                    prefix: 1,
                    generation: a,
                    removed: false,
                },
                check::HistoryRow {
                    prefix: 2,
                    generation: b,
                    removed: false,
                },
                check::HistoryRow {
                    prefix: 3,
                    generation: b,
                    removed: true,
                },
            ],
            phases,
        }
    }
}
#[test]
fn phase_requires_exact_held_and_released_totals() {
    for k in [10, 1000] {
        let f = Fixture::new(k);
        assert!(phases_valid(&f.phases, f.a, f.b, k));
        for i in 0..3 {
            for field in 0..5 {
                let mut bad = f.phases.clone();
                let t = &mut bad[i].totals;
                match field {
                    0 => t.entered += 1,
                    1 => t.ret_observed += 1,
                    2 => t.confirmed += 1,
                    3 => t.completed += 1,
                    _ => t.unsampled += 1,
                };
                assert!(!phases_valid(&bad, f.a, f.b, k));
            }
        }
        let mut bad = f.phases.clone();
        bad[2].completed_batches += 1;
        assert!(!phases_valid(&bad, f.a, f.b, k));
    }
}
#[test]
fn copied_snapshot_requires_same_slot_payload_history_and_bank_count() {
    let f = Fixture::new(10);
    for mutation in 0..6 {
        let mut bad = f.phases.clone();
        let s = &mut bad[1].snapshot;
        match mutation {
            0 => s.banks += 1,
            1 => s.slots[0] = Some((f.a, Some(1))),
            2 => s.reports.push(s.reports[0]),
            3 => s.payloads[0].payload = None,
            4 => s.history[0].actions[0].kind = ActionKind::Removed,
            _ => s.stream.1 += 1,
        };
        assert!(!phases_valid(&bad, f.a, f.b, 10));
    }
}
#[test]
fn reclaim_requires_old_slot_absence_and_unchanged_copy() {
    let f = Fixture::new(10);
    let first = &f.phases[0].snapshot;
    let after = &f.phases[2].snapshot;
    assert!(released(first, after, f.a, f.b, 10));
    assert!(!released(first, first, f.a, f.b, 10));
    for mutation in 0..5 {
        let mut bad = after.clone();
        match mutation {
            0 => bad.banks = 3,
            1 => bad.reports.clear(),
            2 => {
                bad.payloads.pop().unwrap();
            }
            3 => bad.current = None,
            _ => bad.slots[1] = None,
        };
        assert!(!released(first, &bad, f.a, f.b, 10));
    }
}
#[test]
fn boundary_rows_require_actual_next_entry_before_checkpoint() {
    for k in [10, 1000] {
        let f = Fixture::new(k);
        let t = hold_ordinal(k) as usize;
        assert!(boundaries(&f.rows, f.a, f.b, k));
        for mutation in 0..5 {
            let mut bad = f.rows.clone();
            match mutation {
                0 => bad[t - 1].acknowledgement = NormalAcknowledgement::CallerCheckpoint,
                1 => {
                    bad[t + 1].acknowledgement = NormalAcknowledgement::NextEntry {
                        ordinal: t as u64 + 3,
                    }
                }
                2 => bad[t].raw.owner = RawIntervalOwner::FunctionClosed { generation: f.b },
                3 => bad[t].history_prefix = 1,
                _ => {
                    bad.pop();
                }
            };
            assert!(!boundaries(&bad, f.a, f.b, k));
        }
    }
}
#[test]
fn command_phase_refuses_skip_repeat_and_identity_substitution() {
    let id = Identity { tid: 18, a: 41 };
    for phase in 1..=3 {
        let good = Command {
            phase,
            tid: 18,
            a: 41,
            b: if phase == 1 { 0 } else { 49 },
        };
        assert!(command_valid(good, phase, id, 49));
        for mutation in 0..4 {
            let mut bad = good;
            match mutation {
                0 => bad.phase = phase % 3 + 1,
                1 => bad.tid = 17,
                2 => bad.a = 49,
                _ => bad.b += 1,
            };
            assert!(!command_valid(bad, phase, id, 49));
        }
    }
}
#[test]
fn control_wire_requires_complete_counts_and_three_phase_rows() {
    for k in [10, 1000] {
        let f = Fixture::new(k);
        let facts = check::Facts {
            pid: 17,
            entry: 0x1000,
            caller: 0x2000,
            stack: (0x7000, 0x9000),
            k: f.k,
        };
        let counts = check::finish(facts, &f.rows, &f.actions, &f.reports, &f.payloads, 2).unwrap();
        let text = output_control(
            Export {
                f: facts,
                controller: 18,
                app_cpu: 2,
                controller_cpu: 3,
                rows: &f.rows,
                returned: &f.returned,
                actions: &f.actions,
                reports: &f.reports,
                counts,
                arms: 2,
            },
            Identity { tid: 18, a: f.a },
            f.b,
            &f.phases,
        );
        assert_eq!(text.lines().count(), 3083);
        assert_eq!(text.lines().filter(|l| l.starts_with("PHASE,")).count(), 3);
        assert!(
            text.ends_with("deadline_scope=original-15s-functional schedule=not-run timing=none\n")
        );
        assert!(!text.contains("policy=10ms-2ms"));
        assert!(!text.contains("stop_reason=Requested"));
        let mut missing = f.phases.clone();
        missing.pop();
        assert!(!phases_valid(&missing, f.a, f.b, k));
        let mut reordered = f.phases.clone();
        reordered.swap(0, 1);
        assert!(!phases_valid(&reordered, f.a, f.b, k));
    }
}
