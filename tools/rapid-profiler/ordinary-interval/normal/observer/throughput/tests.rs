//! Fabricated data controls call the real validators; no native-return evidence.
use super::*;
use rapid_profiler::frontend::{Action, Payload};
use rapid_profiler::frontend_native::RawTimestamp;
use rapid_profiler::generation::{Admission, Epoch, Record};

struct Fixture {
    e: Expected,
    rows: Vec<NormalRecord>,
    reports: Vec<RecordObservation>,
    history: ControllerSnapshot,
}
impl Fixture {
    fn new() -> Self {
        // Opaque generation identity only; no fabricated native Batch,
        // attachment, executable owner or actual-return evidence.
        let generation = Epoch::new(&[FUNCTION], CONFIG).unwrap().id();
        let e = Expected {
            pid: 17,
            tid: 17,
            entry: 0x1000,
            caller: 0x2000,
            generation: generation.get(),
            stack: (0x7000, 0x9000),
        };
        let mut rows = Vec::new();
        let mut reports = Vec::new();
        for g in 0..CALLS {
            let r = NormalRecord {
                raw: RawInterval {
                    ordinal: g as u64 + 1,
                    entry_pc: e.entry,
                    return_pc: e.entry + 36,
                    owner: RawIntervalOwner::Sampled {
                        generation: e.generation,
                        invocation: g,
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
                return_word: e.caller + [30, 48][g % 2],
                history_prefix: 1,
                acknowledgement: if g % BLOCK == BLOCK - 1 {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: g as u64 + 2,
                    }
                },
            };
            let admission = Admission {
                generation,
                function: FUNCTION,
                invocation: g,
                entry_value: r.raw.start.ticks,
            };
            reports.push(RecordObservation {
                record: Record {
                    admission,
                    terminal: Some(Terminal::Completed {
                        value: g as u64,
                        disposition: Disposition::Retained { rank: g },
                    }),
                },
                payload: Some(Payload {
                    admission,
                    thread: 1,
                    start_sequence: g as u64,
                    outcome: PayloadOutcome::Completed {
                        end: Observation::Value(r.raw.end.ticks),
                        completed_children: 0,
                    },
                }),
            });
            rows.push(r);
        }
        Self {
            e,
            rows,
            reports,
            history: ControllerSnapshot {
                status: ControllerStatus::Ready,
                current: None,
                enabled: vec![true],
                retained_failed_generation: None,
                actions: vec![
                    Action {
                        kind: ActionKind::Published,
                        generation,
                        function: None,
                        current: Some(generation),
                        group: None,
                    },
                    Action {
                        kind: ActionKind::Removed,
                        generation,
                        function: None,
                        current: None,
                        group: None,
                    },
                ],
            },
        }
    }
    fn words(&self, b: usize) -> [u64; 512] {
        let mut words = [0; 512];
        words[..4].copy_from_slice(&[48, 0, 17, 0]);
        for (i, r) in self.rows[b * BLOCK..(b + 1) * BLOCK].iter().enumerate() {
            let ordinal = (b * BLOCK + i + 1) as u64;
            for event in 0..2 {
                let at = 4 + 14 * i + 7 * event;
                words[at..at + 7].copy_from_slice(&[
                    event as u64 + 1,
                    ordinal,
                    self.e.entry + if event == 0 { 0 } else { 36 },
                    r.entry_rsp,
                    r.return_word,
                    self.e.generation,
                    ordinal | (1 << 13),
                ]);
            }
        }
        words
    }
    fn batch(&self, b: usize) -> Check {
        batch(
            self.e,
            b,
            metadata(self.e, b),
            &self.rows[b * BLOCK..(b + 1) * BLOCK],
            &self.words(b),
        )
    }
    fn report(&self) -> Check {
        report(
            self.e,
            &self.rows,
            self.e.generation,
            &self.reports,
            &self.history,
        )
    }
}

fn spans() -> (Span, Vec<Span>, Span) {
    let setup = Span { start: 1, end: 5 };
    let bodies: Vec<_> = (0..BLOCKS)
        .map(|i| {
            let start = 10 + i as u64 * 20;
            Span {
                start,
                end: start + 10,
            }
        })
        .collect();
    let service = Span {
        start: 10,
        end: 2597,
    };
    (setup, bodies, service)
}
fn returns() -> (Vec<Returned>, Vec<u64>) {
    let rows = (0..CALLS)
        .map(|g| Returned {
            id: g as u64 + 1,
            value: case(g).value,
        })
        .collect();
    let sums = (0..PAIRS)
        .map(|p| {
            let value = case(2 * p).value;
            value.wrapping_add(value)
        })
        .collect();
    (rows, sums)
}

#[test]
fn raw_clock_timespec_domains_and_u64_overflow() {
    assert_eq!(nanoseconds(0, 0), Ok(0));
    assert_eq!(nanoseconds(1, 7), Ok(1_000_000_007));
    for (sec, ns) in [(-1, 0), (0, -1), (0, 1_000_000_000), (0, i64::MAX)] {
        assert_eq!(nanoseconds(sec, ns), Err(TimingError::Domain));
    }
    let sec = i64::try_from(u64::MAX / 1_000_000_000).unwrap();
    let ns = i64::try_from(u64::MAX % 1_000_000_000).unwrap();
    assert_eq!(nanoseconds(sec, ns), Ok(u64::MAX));
    assert_eq!(nanoseconds(sec, ns + 1), Err(TimingError::Overflow));
    assert_eq!(nanoseconds(sec + 1, 0), Err(TimingError::Overflow));
    assert_eq!(nanoseconds(i64::MAX, 0), Err(TimingError::Overflow));
}
#[test]
fn timing_requires_all128_ordered_blocks_and_final_service_tail() {
    let (setup, bodies, service) = spans();
    // 128*10 body ns, 127*10 inter-block ns, 37 final validation/drain ns.
    assert_eq!(
        validate_timing(setup, &bodies, service),
        Ok(Timing {
            setup: 4,
            body: 1280,
            service: 2587
        })
    );
    for at in 0..BLOCKS {
        let mut bad = bodies.clone();
        bad.remove(at);
        assert_eq!(
            validate_timing(setup, &bad, service),
            Err(TimingError::Population)
        );
        let mut bad = bodies.clone();
        bad[at].end = bad[at].start - 1;
        assert_eq!(
            validate_timing(setup, &bad, service),
            Err(TimingError::Order)
        );
        if at > 0 {
            let mut bad = bodies.clone();
            bad[at] = bad[at - 1];
            assert_eq!(
                validate_timing(setup, &bad, service),
                Err(TimingError::Order)
            );
            let mut bad = bodies.clone();
            bad.swap(at - 1, at);
            // Keep the service-start join valid so this mutation isolates body
            // order, including the swap that changes the first body start.
            let reordered_service = Span {
                start: bad[0].start,
                ..service
            };
            assert_eq!(
                validate_timing(setup, &bad, reordered_service),
                Err(TimingError::Order)
            );
            let mut bad = bodies.clone();
            bad[at].start = bad[at - 1].end - 1;
            assert_eq!(
                validate_timing(setup, &bad, service),
                Err(TimingError::Order)
            );
        }
    }
    let mut extra = bodies.clone();
    extra.push(service);
    assert_eq!(
        validate_timing(setup, &extra, service),
        Err(TimingError::Population)
    );
    assert_eq!(
        validate_timing(Span { start: 6, end: 5 }, &bodies, service),
        Err(TimingError::Order)
    );
    assert_eq!(
        validate_timing(Span { end: 11, ..setup }, &bodies, service),
        Err(TimingError::Service)
    );
    assert_eq!(
        validate_timing(
            setup,
            &bodies,
            Span {
                start: 11,
                ..service
            }
        ),
        Err(TimingError::Service)
    );
    assert_eq!(
        validate_timing(
            setup,
            &bodies,
            Span {
                end: 2559,
                ..service
            }
        ),
        Err(TimingError::Service)
    );
    // An actual later endpoint must include the complete final tail, not body sum.
    let later = validate_timing(
        setup,
        &bodies,
        Span {
            end: 2697,
            ..service
        },
    )
    .unwrap();
    assert_eq!((later.body, later.service), (1280, 2687));
}
#[test]
fn timing_preserves_zero_and_maximum_endpoints() {
    for at in [0, u64::MAX] {
        let zero = Span { start: at, end: at };
        assert_eq!(
            validate_timing(zero, &[zero; BLOCKS], zero),
            Ok(Timing {
                setup: 0,
                body: 0,
                service: 0
            })
        );
    }
    let zero = Span { start: 0, end: 0 };
    let whole = Span {
        start: 0,
        end: u64::MAX,
    };
    let mut bodies = [Span {
        start: u64::MAX,
        end: u64::MAX,
    }; BLOCKS];
    bodies[0] = whole;
    assert_eq!(
        validate_timing(zero, &bodies, whole),
        Ok(Timing {
            setup: 0,
            body: u64::MAX,
            service: u64::MAX
        })
    );
    bodies[1] = whole; // An overflowing apparent sum is already non-monotone.
    assert_eq!(
        validate_timing(zero, &bodies, whole),
        Err(TimingError::Order)
    );
}
#[test]
fn returns_require_each_ordered_value_and_helper_sum() {
    let (mut rows, mut sums) = returns();
    assert_eq!(returned_population(&rows, &sums), Ok(()));
    assert_eq!(
        returned_population(&rows[..CALLS - 1], &sums),
        Err(Error::Population)
    );
    assert_eq!(
        returned_population(&rows, &sums[..PAIRS - 1]),
        Err(Error::Population)
    );
    rows.swap(0, 1);
    assert_eq!(returned_population(&rows, &sums), Err(Error::Population));
    rows.swap(0, 1);
    let saved = rows[CALLS - 1];
    rows[CALLS - 1] = rows[0];
    assert_eq!(returned_population(&rows, &sums), Err(Error::Population));
    rows[CALLS - 1] = saved;
    let sum = rows[0].value.wrapping_add(rows[1].value);
    rows[0].value += 1;
    rows[1].value -= 1;
    assert_eq!(rows[0].value.wrapping_add(rows[1].value), sum);
    assert_eq!(returned_population(&rows, &sums), Err(Error::Population));
    rows[0].value -= 1;
    rows[1].value += 1;
    sums[PAIRS - 1] ^= 1;
    assert_eq!(returned_population(&rows, &sums), Err(Error::Population));
}
#[test]
fn guard_and_request_mutations_refuse_before_checkpoint() {
    // Calls Data::check directly; no target, attachment or checkpoint is fabricated.
    for field in 0..7 {
        let mut data = Data::new();
        data.check(0, false);
        data.results[0].values = [case(0).value; 2];
        data.check(0, true);
        match field {
            0 => data.inputs[0][0] ^= 1,
            1 => data.inputs[0][16] ^= 1,
            2 => data.requests[0][0].data = std::ptr::null(),
            3 => data.requests[0][1].bound += 1,
            4 => data.results[0].before[0] ^= 1,
            5 => data.results[0].after[1] ^= 1,
            _ => data.results[0].values[1] ^= 1,
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.check(0, true))).is_err()
        );
    }
}
#[test]
fn reused_batch_join_requires_full_identity_and_journal() {
    let mut f = Fixture::new();
    for b in 0..BLOCKS {
        assert_eq!(f.batch(b), Ok(()));
    }
    for g in [0, 23, 24, CALLS - 1] {
        let saved = f.rows[g];
        for field in 0..5 {
            match field {
                0 => {
                    f.rows[g].raw.owner = RawIntervalOwner::FunctionClosed {
                        generation: f.e.generation,
                    }
                }
                1 => f.rows[g].return_word += 1,
                2 => f.rows[g].entry_rsp = 0x7008,
                3 => f.rows[g].raw.end.aux ^= 1,
                _ => f.rows[g].acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 1 },
            }
            assert!(f.batch(g / BLOCK).is_err());
            f.rows[g] = saved;
        }
    }
    let b = BLOCKS - 1;
    let rows = &f.rows[b * BLOCK..];
    let mut words = f.words(b);
    for at in 0..512 {
        words[at] ^= 1;
        assert_eq!(
            batch(f.e, b, metadata(f.e, b), rows, &words),
            Err(Error::Journal)
        );
        words[at] ^= 1;
    }
    let mut m = metadata(f.e, b);
    m.totals.1.confirmed -= 1;
    assert_eq!(batch(f.e, b, m, rows, &words), Err(Error::Identity));
}
#[test]
fn reused_report_join_requires_complete_population_and_history() {
    let mut f = Fixture::new();
    assert_eq!(f.report(), Ok(()));
    let last = f.reports.pop().unwrap();
    assert_eq!(f.report(), Err(Error::Population));
    f.reports.push(last);
    let saved = f.reports[CALLS - 1];
    f.reports[CALLS - 1]
        .payload
        .as_mut()
        .unwrap()
        .start_sequence -= 1;
    assert_eq!(f.report(), Err(Error::Report));
    f.reports[CALLS - 1] = saved;
    f.reports[CALLS - 1].record.terminal = None;
    assert_eq!(f.report(), Err(Error::Report));
    f.reports[CALLS - 1] = saved;
    f.history.actions.swap(0, 1);
    assert_eq!(f.report(), Err(Error::History));
    f.history.actions.swap(0, 1);
    f.history.current = Some(f.history.actions[0].generation);
    assert_eq!(f.report(), Err(Error::History));
}
#[test]
fn timing_appendix_has_exact_population_and_raw_sums() {
    let (setup, bodies, service) = spans();
    let timing = validate_timing(setup, &bodies, service).unwrap();
    for mode in [Mode::Native, Mode::AlwaysOn] {
        let mut out = String::from("untouched functional prefix\n");
        append_timing(&mut out, mode, 1023, setup, &bodies, service, timing);
        let lines: Vec<_> = out.lines().collect();
        assert_eq!(lines.len(), 134);
        assert_eq!(lines[0], "untouched functional prefix");
        assert_eq!(lines[1], TIMING_SCOPE);
        assert_eq!(lines[2], TIMING_HEADER);
        assert_eq!(lines[3], "setup,0,1,5");
        assert_eq!(lines[4], "body,1,10,20");
        assert_eq!(lines[131], "body,128,2550,2560");
        assert_eq!(lines[132], "service,0,10,2597");
        assert_eq!(
            lines[133],
            format!(
                "normal-observer-throughput TIMING_COMPLETE mode={} cpu=1023 clock=CLOCK_MONOTONIC_RAW units=ns timing_rows=130 setup_ns=4 body_ns=1280 service_ns=2587",
                mode.name()
            )
        );
        assert!(out.is_ascii() && out.ends_with('\n') && out.len() < 16 * 1024);
    }
    let zero = Span {
        start: u64::MAX,
        end: u64::MAX,
    };
    let timing = validate_timing(zero, &[zero; BLOCKS], zero).unwrap();
    let mut out = String::new();
    append_timing(
        &mut out,
        Mode::Native,
        0,
        zero,
        &[zero; BLOCKS],
        zero,
        timing,
    );
    assert!(out.ends_with("setup_ns=0 body_ns=0 service_ns=0\n"));
    assert!(out.contains("body,128,18446744073709551615,18446744073709551615\n"));
}
