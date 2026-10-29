//! Fabricated data and owned-channel controls; no native-return/join evidence.
use super::*;
use rapid_profiler::frontend::Payload;
use rapid_profiler::frontend_native::RawTimestamp;
use rapid_profiler::generation::{Admission, Epoch, Record};

struct Fixture {
    f: check::Facts,
    rows: Vec<NormalRecord>,
    actions: Vec<check::HistoryRow>,
    reports: Vec<ReportSpan>,
    payloads: Vec<RecordObservation>,
}
impl Fixture {
    fn new(k: usize) -> Self {
        let config = Config {
            retained_per_function: k,
            max_inflight: 1,
            max_invocations: k,
        };
        let ids = std::array::from_fn::<_, 3, _>(|_| Epoch::new(&[FUNCTION], config).unwrap().id());
        let f = check::Facts {
            pid: 17,
            entry: 0x1000,
            caller: 0x2000,
            stack: (0x7000, 0x9000),
            k,
        };
        let mut rows = Vec::new();
        let mut payloads = Vec::new();
        for g in 0..CALLS {
            let epoch = g / 1536;
            let invocation = g % 1536;
            let sampled = invocation < k;
            let r = NormalRecord {
                raw: RawInterval {
                    ordinal: g as u64 + 1,
                    entry_pc: f.entry,
                    return_pc: f.entry + 36,
                    owner: if sampled {
                        RawIntervalOwner::Sampled {
                            generation: ids[epoch].get(),
                            invocation,
                        }
                    } else {
                        RawIntervalOwner::FunctionClosed {
                            generation: ids[epoch].get(),
                        }
                    },
                    start: RawTimestamp {
                        ticks: g as u64 * 100,
                        aux: 3,
                    },
                    end: RawTimestamp {
                        ticks: g as u64 * 100 + 90,
                        aux: 3,
                    },
                },
                entry_rsp: 0x7ff8,
                return_word: f.caller + [30, 48][g % 2],
                history_prefix: epoch as u64 + 1,
                acknowledgement: if g % BLOCK == BLOCK - 1 {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: g as u64 + 2,
                    }
                },
            };
            if sampled {
                let admission = Admission {
                    generation: ids[epoch],
                    function: FUNCTION,
                    invocation,
                    entry_value: r.raw.start.ticks,
                };
                payloads.push(RecordObservation {
                    record: Record {
                        admission,
                        terminal: Some(Terminal::Completed {
                            value: invocation as u64,
                            disposition: Disposition::Retained { rank: invocation },
                        }),
                    },
                    payload: Some(Payload {
                        admission,
                        thread: 1,
                        start_sequence: payloads.len() as u64,
                        outcome: PayloadOutcome::Completed {
                            end: Observation::Value(r.raw.end.ticks),
                            completed_children: 0,
                        },
                    }),
                });
            }
            rows.push(r);
        }
        let mut actions: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| check::HistoryRow {
                prefix: i as u64 + 1,
                generation: id.get(),
                removed: false,
            })
            .collect();
        actions.push(check::HistoryRow {
            prefix: 4,
            generation: ids[2].get(),
            removed: true,
        });
        let reports = vec![
            ReportSpan {
                generation: ids[0].get(),
                start: 0,
                end: k,
            },
            ReportSpan {
                generation: ids[1].get(),
                start: k,
                end: 2 * k,
            },
            ReportSpan {
                generation: ids[2].get(),
                start: 2 * k,
                end: 2 * k,
            },
        ];
        Self {
            f,
            rows,
            actions,
            reports,
            payloads,
        }
    }
    fn totals(&self, n: usize) -> NormalTotals {
        let sampled = self.rows[..n]
            .iter()
            .filter(|r| matches!(r.raw.owner, RawIntervalOwner::Sampled { .. }))
            .count() as u64;
        NormalTotals {
            entered: n as u64,
            ret_observed: n as u64,
            confirmed: n as u64,
            completed: sampled,
            unsampled: n as u64 - sampled,
        }
    }
    fn meta(&self, b: usize) -> check::Meta {
        let before = self.totals(b * BLOCK);
        let after = self.totals((b + 1) * BLOCK);
        check::Meta {
            stream: true,
            high: Some(3),
            pid: 17,
            tid: 17,
            registration: 1,
            install: INSTALL,
            function: FUNCTION,
            number: b as u64 + 1,
            totals: (before, after),
            sequences: (before.completed, after.completed),
            next: after.confirmed + 1,
        }
    }
    fn words(&self, b: usize) -> [u64; 512] {
        let mut words = [0; 512];
        words[..4].copy_from_slice(&[48, 0, 17, 0]);
        for (i, r) in self.rows[b * BLOCK..(b + 1) * BLOCK].iter().enumerate() {
            let (kind, generation, inv, reason) = match r.raw.owner {
                RawIntervalOwner::Sampled {
                    generation,
                    invocation,
                } => (1, generation, invocation as u64 + 1, 0),
                RawIntervalOwner::FunctionClosed { generation } => (3, generation, 0, 3),
                _ => unreachable!(),
            };
            let p = r.history_prefix;
            let bits = inv | ((p & 511) << 13) | (reason << 22) | ((p >> 9) << 24);
            let at = 4 + i * 14;
            words[at..at + 7].copy_from_slice(&[
                kind,
                r.raw.ordinal,
                r.raw.entry_pc,
                r.entry_rsp,
                r.return_word,
                generation,
                bits,
            ]);
            words[at + 7..at + 14].copy_from_slice(&[
                kind + 1,
                r.raw.ordinal,
                r.raw.return_pc,
                r.entry_rsp,
                r.return_word,
                generation,
                bits,
            ]);
        }
        words
    }
    fn batch(&self, b: usize) -> check::Checked<NormalTotals> {
        check::batch(
            self.f,
            b,
            self.meta(b),
            &self.rows[b * BLOCK..(b + 1) * BLOCK],
            &self.words(b),
            self.totals(b * BLOCK),
        )
    }
    fn finish(&self) -> check::Checked<check::Counts> {
        check::finish(
            self.f,
            &self.rows,
            &self.actions,
            &self.reports,
            &self.payloads,
            3,
        )
    }
}
#[test]
fn arguments_cpu_roles_and_complete_task_identity_are_exact() {
    assert_eq!(roles("10", "1", "3"), Some((10, 1, 3)));
    assert_eq!(roles("1000", "1023", "0"), Some((1000, 1023, 0)));
    for (k, a, c) in [
        ("1", "1", "3"),
        ("010", "1", "3"),
        ("10", "+1", "3"),
        ("10", "1", "1"),
        ("10", "1024", "3"),
        ("10", "1", "03"),
    ] {
        assert!(roles(k, a, c).is_none());
    }
    let names = |xs: &[&str]| {
        xs.iter()
            .map(|s| std::ffi::OsString::from(*s))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        task_ids(names(&["23", "17"]), 17, 23),
        Some(BTreeSet::from([17, 23]))
    );
    for xs in [
        &["17"][..],
        &["17", "23", "24"],
        &["17", "23", "23"],
        &["17", "023"],
        &["17", "0"],
        &["17", "2147483648"],
    ] {
        assert!(task_ids(names(xs), 17, 23).is_none());
    }
    assert!(task_ids(names(&["17"]), 17, 17).is_none());
}
#[test]
fn fixed_work_and_guarded_pairs_never_accept_aggregate_only_results() {
    let rows: Vec<_> = (0..CALLS)
        .map(|g| Returned {
            id: g as u64 + 1,
            value: case(g).value,
        })
        .collect();
    assert!(population(&rows));
    let mut bad = rows.clone();
    bad[0].value = bad[0].value.wrapping_add(1);
    bad[1].value = bad[1].value.wrapping_sub(1);
    assert!(!population(&bad));
    assert!(!population(&rows[..CALLS - 1]));
    let mut bad = rows;
    bad.swap(0, 1);
    assert!(!population(&bad));
    let mut data = Data::new();
    data.check(0, false);
    data.requests[0][1].bound = 64;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.check(0, false))).is_err()
    );
    let mut data = Data::new();
    data.results[0].before[0] ^= 1;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.check(0, false))).is_err()
    );
    assert_eq!(
        (0..CALLS).map(|g| work(case(g).length)[0]).sum::<usize>(),
        614400
    );
}
#[test]
fn mixed_batches_keep_absolute_ordinals_sample_sequences_and_stack_clock() {
    for k in [10, 1000] {
        let f = Fixture::new(k);
        for b in 0..BLOCKS {
            assert_eq!(f.batch(b), Ok(f.totals((b + 1) * BLOCK)));
        }
    }
    let f = Fixture::new(10);
    let b = 1;
    let base = f.meta(b);
    let mut bad = base;
    bad.sequences = (24, 48);
    assert_eq!(
        check::batch(f.f, b, bad, &f.rows[24..48], &f.words(b), f.totals(24)),
        Err(check::Fault::Identity)
    );
    let mut bad = base;
    bad.stream = false;
    assert!(check::batch(f.f, b, bad, &f.rows[24..48], &f.words(b), f.totals(24)).is_err());
    for field in 0..8 {
        let mut f = Fixture::new(10);
        match field {
            0 => f.rows[0].raw.ordinal = 2,
            1 => f.rows[0].raw.return_pc += 1,
            2 => f.rows[0].history_prefix = 0,
            3 => f.rows[0].acknowledgement = NormalAcknowledgement::CallerCheckpoint,
            4 => f.rows[0].entry_rsp = 120,
            5 => f.rows[1].return_word -= 1,
            6 => f.rows[0].raw.end.ticks = 0,
            7 => f.rows[0].raw.end.aux = 4,
            _ => unreachable!(),
        }
        // For reversed ticks choose the second row (row zero legitimately starts zero).
        if field == 6 {
            f.rows[1].raw.end.ticks = 0;
        }
        assert!(f.batch(0).is_err());
    }
    let mut f = Fixture::new(10);
    for r in &mut f.rows[..BLOCK] {
        r.raw.start.ticks = 0;
        r.raw.end.ticks = u64::MAX;
        r.raw.start.aux = u32::MAX;
        r.raw.end.aux = u32::MAX;
    }
    assert!(f.batch(0).is_ok());
}
#[test]
fn every_journal_word_and_absolute_prefix_high_bits_are_authenticated() {
    assert_eq!(check::high_water(512, Some(513), 520), Ok(513));
    for (previous, current, arms) in [
        (513, Some(512), 520),
        (0, None, 520),
        (0, Some(0), 520),
        (0, Some(521), 520),
        (0, Some(3), 2),
    ] {
        assert!(check::high_water(previous, current, arms).is_err());
    }
    let mut f = Fixture::new(10);
    for r in &mut f.rows[..BLOCK] {
        r.history_prefix = 513;
    }
    let mut m = f.meta(0);
    m.high = Some(513);
    let words = f.words(0);
    assert!(check::batch(f.f, 0, m, &f.rows[..BLOCK], &words, NormalTotals::default()).is_ok());
    for i in 0..512 {
        let mut bad = words;
        bad[i] ^= 1;
        assert_eq!(
            check::batch(f.f, 0, m, &f.rows[..BLOCK], &bad, NormalTotals::default()),
            Err(check::Fault::Journal)
        );
    }
    m.high = Some(512);
    assert_eq!(
        check::batch(f.f, 0, m, &f.rows[..BLOCK], &words, NormalTotals::default()),
        Err(check::Fault::Record)
    );
}
#[test]
fn complete_owner_population_refuses_reopen_reorder_missing_or_wrong_history() {
    for k in [10, 1000] {
        let f = Fixture::new(k);
        assert_eq!(
            f.finish(),
            Ok(check::Counts {
                sampled: (2 * k) as u64,
                closed: (CALLS - 2 * k) as u64,
                generations: 2,
                after_closed: true
            })
        );
    }
    for field in 0..8 {
        let mut f = Fixture::new(10);
        match field {
            0 => {
                f.rows.pop();
            }
            1 => {
                f.actions.pop();
            }
            2 => f.actions[0].removed = true,
            3 => f.actions[1].generation = f.actions[0].generation,
            4 => f.rows[0].history_prefix = 0,
            5 => f.rows[24].history_prefix = 2,
            6 => {
                f.rows[10].raw.owner = RawIntervalOwner::Sampled {
                    generation: f.actions[0].generation,
                    invocation: 0,
                }
            }
            7 => {
                f.rows[0].raw.owner = RawIntervalOwner::FunctionClosed {
                    generation: f.actions[0].generation,
                }
            }
            _ => unreachable!(),
        }
        assert!(f.finish().is_err());
    }
    let mut f = Fixture::new(10);
    f.rows.swap(0, 1);
    f.rows[0].raw.ordinal = 1;
    f.rows[1].raw.ordinal = 2;
    assert!(f.finish().is_err());
}
#[test]
fn all_report_payloads_ranges_empty_generations_and_terminal_dispositions_join() {
    let mut f = Fixture::new(10);
    f.reports.swap(0, 1);
    assert!(f.finish().is_ok());
    for field in 0..10 {
        let mut f = Fixture::new(10);
        match field {
            0 => {
                f.reports.pop();
            }
            1 => f.reports[1] = f.reports[0],
            2 => f.reports[1].start = 0,
            3 => {
                f.payloads.pop();
            }
            4 => f.payloads[0].record.terminal = None,
            5 => {
                f.payloads[0].record.terminal = Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::DroppedAfterBudget,
                })
            }
            6 => f.payloads[0].payload.as_mut().unwrap().thread = 2,
            7 => f.payloads[10].payload.as_mut().unwrap().start_sequence = 1536,
            8 => {
                f.payloads[0].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(91),
                    completed_children: 0,
                }
            }
            9 => f.payloads[0].record.admission.entry_value += 1,
            _ => unreachable!(),
        }
        assert!(f.finish().is_err());
    }
}
#[test]
fn owned_schedule_handoff_keeps_original_requested_deadline_and_pending_transfer() {
    let start = Instant::now();
    let policy = Policy::ten_ms(10, EPOCHS, CALLS as u64).unwrap();
    let stopped = start + Duration::from_millis(1);
    let deadline = shutdown(start, stopped, policy).unwrap();
    assert_eq!(deadline, stopped + Duration::from_secs(2));
    assert!(before(deadline - Duration::from_nanos(1), deadline));
    assert!(!before(deadline, deadline));
    assert_eq!(
        shutdown(start, start + policy.period() * EPOCHS, policy),
        Some(start + policy.period() * EPOCHS + policy.shutdown())
    );
    let mut schedule = Schedule::new(start, policy).unwrap();
    assert_eq!(
        schedule.poll(start, false),
        Ok(ScheduleDecision::Arm { due: start })
    );
    schedule.arm_completed(start).unwrap();
    let ready = Ready {
        tid: 23,
        start,
        absolute_end: start + policy.period() * EPOCHS + policy.shutdown(),
    };
    assert!(!handoff_ready(ready, ready, deadline, &schedule, 1));
    assert_eq!(schedule.poll(stopped, true), Ok(ScheduleDecision::Stop));
    assert!(handoff_ready(ready, ready, deadline, &schedule, 1));
    let mut wrong = ready;
    wrong.tid = 24;
    assert!(!handoff_ready(ready, wrong, deadline, &schedule, 1));
    let mut wrong = ready;
    wrong.start += Duration::from_nanos(1);
    assert!(!handoff_ready(ready, wrong, deadline, &schedule, 1));
    assert!(!handoff_ready(
        ready,
        ready,
        ready.absolute_end + Duration::from_nanos(1),
        &schedule,
        1
    ));
    assert!(!handoff_ready(ready, ready, deadline, &schedule, 0));
    let (tx, rx) = mpsc::sync_channel(1);
    let owned = Box::new(19_u64);
    let address = &*owned as *const u64;
    tx.try_send((schedule, owned))
        .unwrap_or_else(|_| panic!("one owned transfer"));
    let (mut schedule, owned) = rx.try_recv().unwrap();
    assert_eq!(&*owned as *const u64, address);
    assert_eq!(*owned, 19);
    assert!(
        schedule
            .wait_bound(deadline - Duration::from_nanos(1))
            .is_ok()
    );
    assert_eq!(
        schedule.check_completion(deadline),
        Err(rapid_profiler::frontend_native::backoff::Error::Deadline)
    );
    // A refused transfer still owns its exact item, with no retry or drop inferred.
    let (tx, rx) = mpsc::sync_channel(1);
    tx.try_send(Box::new(1)).unwrap();
    let item = Box::new(2);
    let address = &*item as *const i32;
    let mpsc::TrySendError::Full(item) = tx.try_send(item).unwrap_err() else {
        panic!("full")
    };
    assert_eq!(&*item as *const i32, address);
    assert_eq!(*rx.try_recv().unwrap(), 1);
    let (tx, rx) = mpsc::sync_channel(1);
    drop(rx);
    let item = Box::new(3);
    let address = &*item as *const i32;
    let mpsc::TrySendError::Disconnected(item) = tx.try_send(item).unwrap_err() else {
        panic!("disconnected")
    };
    assert_eq!(&*item as *const i32, address);
}
#[test]
fn bounded_wire_retains_all_rows_empty_reports_zero_and_full_width_ticks() {
    let mut f = Fixture::new(10);
    for r in &mut f.rows {
        r.raw.start.ticks = u64::MAX;
        r.raw.end.ticks = u64::MAX;
        r.raw.start.aux = u32::MAX;
        r.raw.end.aux = u32::MAX;
    }
    let counts = check::Counts {
        sampled: 20,
        closed: 3052,
        generations: 2,
        after_closed: true,
    };
    let returned: Vec<_> = (0..CALLS)
        .map(|g| Returned {
            id: g as u64 + 1,
            value: case(g).value,
        })
        .collect();
    let text = output(Export {
        f: f.f,
        controller: 23,
        app_cpu: 1,
        controller_cpu: 3,
        rows: &f.rows,
        returned: &returned,
        actions: &f.actions,
        reports: &f.reports,
        counts,
        arms: 3,
    });
    assert!(text.is_ascii() && text.len() <= OUTPUT_CAP);
    assert_eq!(text.lines().count(), 3082);
    assert_eq!(text.lines().nth(1), Some(HEADER));
    assert!(
        text.lines()
            .skip(2)
            .take(CALLS)
            .all(|line| line.split(',').count() == 27)
    );
    assert!(text.contains(&format!("REPORT,3,{},0\n", f.actions[2].generation)));
    assert!(text.contains("observed_generations=2 rearmed=true sampled_after_closed=true"));
    let zero = row(0, returned[0], &f.rows[0], Some(0), 10);
    assert_eq!(zero.split(',').nth(23), Some("0"));
    f.rows[0].raw.start.ticks = 0;
    let full = row(0, returned[0], &f.rows[0], Some(0), 10);
    assert_eq!(full.split(',').nth(23), Some("18446744073709551615"));
}
