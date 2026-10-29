//! Fabricated endpoint/record controls; no physical call or clock evidence.
use super::*;
use rapid_profiler::frontend_native::RawTimestamp;

fn captured(value: Option<u64>) -> Capture {
    let mut c = Capture::new();
    c.mark(Point::SetupStart, || value.unwrap_or(1));
    c.mark(Point::SetupEnd, || value.unwrap_or(5));
    for b in 0..BLOCKS {
        let first = b * BLOCK / 2;
        let last = first + BLOCK / 2;
        c.mark(Point::BodyStart { first, last }, || {
            value.unwrap_or(10 + b as u64 * 20)
        });
        c.mark(Point::BodyEnd { first, last }, || {
            value.unwrap_or(20 + b as u64 * 20)
        });
    }
    c.mark(Point::ServiceEnd, || value.unwrap_or(2597));
    c
}

struct Fixture {
    facts: check::Facts,
    rows: Vec<NormalRecord>,
    returned: Vec<Returned>,
    actions: [check::HistoryRow; 2],
    reports: [ReportSpan; 1],
}
impl Fixture {
    fn new(k: usize) -> Self {
        let facts = check::Facts {
            pid: 17,
            entry: 0x1000,
            caller: 0x2000,
            stack: (0x7000, 0x9000),
            k,
        };
        let rows = (0..CALLS)
            .map(|g| NormalRecord {
                raw: RawInterval {
                    ordinal: g as u64 + 1,
                    entry_pc: facts.entry,
                    return_pc: facts.entry + 36,
                    owner: if g < k {
                        RawIntervalOwner::Sampled {
                            generation: 41,
                            invocation: g,
                        }
                    } else {
                        RawIntervalOwner::FunctionClosed { generation: 41 }
                    },
                    start: RawTimestamp {
                        ticks: u64::MAX,
                        aux: u32::MAX,
                    },
                    end: RawTimestamp {
                        ticks: u64::MAX,
                        aux: u32::MAX,
                    },
                },
                entry_rsp: 0x7ff8,
                return_word: facts.caller + [30, 48][g % 2],
                history_prefix: 1,
                acknowledgement: if g % BLOCK == BLOCK - 1 {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: g as u64 + 2,
                    }
                },
            })
            .collect();
        Self {
            facts,
            rows,
            returned: (0..CALLS)
                .map(|g| Returned {
                    id: g as u64 + 1,
                    value: case(g).value,
                })
                .collect(),
            actions: [
                check::HistoryRow {
                    prefix: 1,
                    generation: 41,
                    removed: false,
                },
                check::HistoryRow {
                    prefix: 2,
                    generation: 41,
                    removed: true,
                },
            ],
            reports: [ReportSpan {
                generation: 41,
                start: 0,
                end: k,
            }],
        }
    }
    fn export(&self) -> Export<'_> {
        Export {
            f: self.facts,
            controller: 23,
            app_cpu: 1,
            controller_cpu: 3,
            rows: &self.rows,
            returned: &self.returned,
            actions: &self.actions,
            reports: &self.reports,
            counts: check::Counts {
                sampled: self.facts.k as u64,
                closed: (CALLS - self.facts.k) as u64,
                generations: 1,
                after_closed: false,
            },
            arms: 1,
        }
    }
}

#[test]
fn no_timing_hooks_never_read_clock_or_keep_storage() {
    assert_eq!(std::mem::size_of::<NoTiming>(), 0);
    let mut quiet = NoTiming;
    for point in [Point::SetupStart, Point::SetupEnd, Point::ServiceEnd] {
        quiet.mark(point, || panic!("NoTiming read a clock"));
    }
    // The existing pending-owner route has eleven-pair and one-pair ranges.
    // NoTiming imposes no new timing shape, count or phase requirement on them.
    for (first, last) in [(0, 11), (11, 12), (492, 503), (503, 504)] {
        quiet.mark(Point::BodyStart { first, last }, || {
            panic!("unexpected start clock")
        });
        quiet.mark(Point::BodyEnd { first, last }, || {
            panic!("unexpected end clock")
        });
    }
    let f = Fixture::new(10);
    assert_eq!(quiet.output(f.export()), super::super::output(f.export()));
}

#[test]
fn capture_hooks_require_full_order_and_twelve_pair_ranges() {
    let mut c = Capture::new();
    let refusal = |c: &mut Capture, point| {
        assert_eq!(
            c.record(point, || panic!("invalid hook read a clock")),
            Err(Error::Phase)
        );
    };
    refusal(&mut c, Point::SetupEnd);
    refusal(&mut c, Point::BodyStart { first: 0, last: 12 });
    c.mark(Point::SetupStart, || 0);
    refusal(&mut c, Point::SetupStart);
    c.mark(Point::SetupEnd, || 0);
    for b in 0..BLOCKS {
        let first = b * BLOCK / 2;
        let last = first + BLOCK / 2;
        refusal(&mut c, Point::BodyEnd { first, last });
        refusal(
            &mut c,
            Point::BodyStart {
                first,
                last: last - 1,
            },
        );
        refusal(
            &mut c,
            Point::BodyStart {
                first: first + 1,
                last,
            },
        );
        refusal(
            &mut c,
            Point::BodyStart {
                first: first + 12,
                last: last + 12,
            },
        );
        c.mark(Point::BodyStart { first, last }, || b as u64);
        refusal(&mut c, Point::BodyStart { first, last });
        refusal(
            &mut c,
            Point::BodyEnd {
                first,
                last: last + 1,
            },
        );
        c.mark(Point::BodyEnd { first, last }, || b as u64);
    }
    refusal(
        &mut c,
        Point::BodyStart {
            first: PAIRS,
            last: PAIRS + 12,
        },
    );
    c.mark(Point::ServiceEnd, || BLOCKS as u64);
    refusal(&mut c, Point::ServiceEnd);
    assert!(c.timing().is_ok());
}

#[test]
fn capture_requires_all_blocks_and_original_service_tail() {
    let c = captured(None);
    assert_eq!(
        c.timing(),
        Ok(Timing {
            setup: 4,
            body: 1280,
            service: 2587
        })
    );
    for missing in 0..BLOCKS {
        let mut partial = Capture::new();
        partial.mark(Point::SetupStart, || 0);
        partial.mark(Point::SetupEnd, || 0);
        for b in 0..missing {
            let (first, last) = (b * 12, (b + 1) * 12);
            partial.mark(Point::BodyStart { first, last }, || 0);
            partial.mark(Point::BodyEnd { first, last }, || 0);
        }
        assert_eq!(partial.timing(), Err(Error::Phase));
        assert_eq!(
            partial.record(Point::ServiceEnd, || panic!("unfinished clock")),
            Err(Error::Phase)
        );
        let mut bad = captured(None);
        bad.bodies[missing].end = bad.bodies[missing].start - 1;
        assert_eq!(bad.timing(), Err(Error::Timing(TimingError::Order)));
        if missing > 0 {
            let mut bad = captured(None);
            bad.bodies[missing].start = bad.bodies[missing - 1].end - 1;
            assert_eq!(bad.timing(), Err(Error::Timing(TimingError::Order)));
        }
    }
    let mut bad = captured(None);
    bad.setup.end = bad.bodies[0].start + 1;
    assert_eq!(bad.timing(), Err(Error::Timing(TimingError::Service)));
    let mut bad = captured(None);
    bad.service.start += 1;
    assert_eq!(bad.timing(), Err(Error::Timing(TimingError::Service)));
    let mut bad = captured(None);
    bad.service.end = bad.bodies[BLOCKS - 1].end - 1;
    assert_eq!(bad.timing(), Err(Error::Timing(TimingError::Service)));
    let mut longer = captured(None);
    longer.service.end += 100;
    assert_eq!(
        longer.timing(),
        Ok(Timing {
            setup: 4,
            body: 1280,
            service: 2687
        })
    );
}

#[test]
fn shared_clock_arithmetic_keeps_domain_zero_and_maximum() {
    for (sec, ns) in [(-1, 0), (0, -1), (0, 1_000_000_000)] {
        assert_eq!(clock::nanoseconds(sec, ns), Err(TimingError::Domain));
    }
    let sec = (u64::MAX / 1_000_000_000) as i64;
    let ns = (u64::MAX % 1_000_000_000) as i64;
    assert_eq!(clock::nanoseconds(sec, ns), Ok(u64::MAX));
    assert_eq!(clock::nanoseconds(sec, ns + 1), Err(TimingError::Overflow));
    assert_eq!(clock::nanoseconds(sec + 1, 0), Err(TimingError::Overflow));
    for at in [0, u64::MAX] {
        let c = captured(Some(at));
        assert_eq!(
            c.timing(),
            Ok(Timing {
                setup: 0,
                body: 0,
                service: 0
            })
        );
        let mut text = String::new();
        c.append(&mut text, 10, 0, 1023).unwrap();
        assert!(text.contains(&format!("setup,0,{at},{at}\n")));
        assert!(text.ends_with("setup_ns=0 body_ns=0 service_ns=0\n"));
    }
    let mut c = captured(Some(u64::MAX));
    c.setup = Span { start: 0, end: 0 };
    c.bodies[0].start = 0;
    c.service.start = 0;
    assert_eq!(
        c.timing(),
        Ok(Timing {
            setup: 0,
            body: u64::MAX,
            service: u64::MAX
        })
    );
}

#[test]
fn elapsed_output_preserves_functional_rows_and_fixed_timing_suffix() {
    for k in [10, 1000] {
        let f = Fixture::new(k);
        let old = NoTiming.output(f.export());
        let measured = captured(None).output(f.export());
        let a: Vec<_> = old.lines().collect();
        let b: Vec<_> = measured.lines().collect();
        assert_eq!(a.len(), 3078);
        assert_eq!(b.len(), 3211);
        assert_eq!(a[0], SCOPE);
        assert_eq!(b[0], FUNCTIONAL_SCOPE);
        assert_eq!(&a[1..a.len() - 1], &b[1..a.len() - 1]);
        assert!(
            a.last()
                .unwrap()
                .starts_with("normal-observer-backoff FUNCTIONAL_PASS ")
        );
        assert!(a.last().unwrap().ends_with("timing=none"));
        assert_eq!(
            b[a.len() - 1],
            a.last()
                .unwrap()
                .replacen(
                    "normal-observer-backoff ",
                    "normal-observer-backoff-elapsed ",
                    1
                )
                .replace("timing=none", "timing=raw-appendix")
        );
        let tail = &b[a.len()..];
        assert_eq!((tail[0], tail[1]), (TIMING_SCOPE, TIMING_HEADER));
        assert_eq!(tail[2], "setup,0,1,5");
        for i in 0..BLOCKS {
            assert_eq!(
                tail[i + 3],
                format!("body,{},{},{}", i + 1, 10 + i * 20, 20 + i * 20)
            );
        }
        assert_eq!(tail[131], "service,0,10,2597");
        assert_eq!(
            tail[132],
            format!(
                "normal-observer-backoff-elapsed TIMING_COMPLETE k={k} app_cpu=1 controller_cpu=3 clock=CLOCK_MONOTONIC_RAW units=ns timing_rows=130 setup_ns=4 body_ns=1280 service_ns=2587"
            )
        );
        assert!(measured.is_ascii() && measured.len() <= TOTAL_OUTPUT_CAP);
    }
}

#[test]
fn elapsed_output_rejects_unfinished_capture_and_wrong_roles() {
    let mut output = String::from("retained");
    assert_eq!(
        Capture::new().append(&mut output, 10, 1, 3),
        Err(Error::Phase)
    );
    assert_eq!(output, "retained");
    for (k, app, control) in [
        (0, 1, 3),
        (11, 1, 3),
        (10, 1024, 3),
        (1000, 1, 1024),
        (10, 7, 7),
    ] {
        assert_eq!(
            captured(None).append(&mut output, k, app, control),
            Err(Error::Roles)
        );
        assert_eq!(output, "retained");
    }
    let mut bad = captured(None);
    bad.service.end = 0;
    assert_eq!(
        bad.append(&mut output, 10, 1, 3),
        Err(Error::Timing(TimingError::Order))
    );
    assert_eq!(output, "retained");
}

#[test]
fn printed_timing_does_not_override_original_completion_deadline() {
    let start = Instant::now();
    let policy = Policy::ten_ms(10, EPOCHS, CALLS as u64).unwrap();
    let mut schedule = Schedule::new(start, policy).unwrap();
    assert_eq!(
        schedule.poll(start, false),
        Ok(ScheduleDecision::Arm { due: start })
    );
    schedule.arm_completed(start).unwrap();
    let stopped = start + Duration::from_millis(1);
    assert_eq!(schedule.poll(stopped, true), Ok(ScheduleDecision::Stop));
    let deadline = shutdown(start, stopped, policy).unwrap();
    assert!(
        schedule
            .wait_bound(deadline - Duration::from_nanos(1))
            .is_ok()
    );
    let printed = captured(None).output(Fixture::new(10).export());
    assert!(printed.contains(" TIMING_COMPLETE "));
    assert_eq!(
        schedule.check_completion(deadline),
        Err(rapid_profiler::frontend_native::backoff::Error::Deadline)
    );
}
