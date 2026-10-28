//! Synthetic observations through actual wrapper/legacy joins; no native credit.
use super::*;
use rapid_profiler::frontend_native::{RawIntervalOwner, RawTimestamp};
use rapid_profiler::generation::{Config, Epoch};

fn expected() -> Expected {
    Expected {
        gate: 0x8000,
        pid: 7,
        tid: 7,
        target: 0x1000,
        continuation: 0x5000,
        return_pc: 0x1024,
    }
}
fn ids() -> [u64; CALLS] {
    std::array::from_fn(|i| 2200 + i as u64)
}
fn values() -> [u64; CALLS] {
    std::array::from_fn(|i| 100 + i as u64)
}
fn originals() -> Originals {
    Originals::new(expected(), ids(), values()).unwrap()
}
fn enclosure(i: usize, installed: bool) -> Enclosure {
    let at = i + if installed { CALLS } else { 0 };
    let start = 1000 + at as u64 * 100;
    let rsp = if installed { 0x9000 } else { 0x8000 };
    Enclosure {
        leg: if installed {
            ReferenceLeg::Installed
        } else {
            ReferenceLeg::Original
        },
        external_id: ids()[i],
        gate: expected().gate,
        sequence: 1001 + at as u64,
        pid: 7,
        tid: 7,
        target: expected().target,
        continuation: expected().continuation,
        pre_call_rsp: rsp,
        resumed_rsp: rsp,
        start: ReferenceTimestamp {
            ticks: start,
            aux: 3,
        },
        end: ReferenceTimestamp {
            ticks: start + 80,
            aux: 3,
        },
    }
}
fn original(i: usize) -> OriginalCallResult {
    OriginalCallResult {
        value: values()[i],
        pre_call_rsp: 0x8000,
        resumed_rsp: 0x8000,
    }
}
fn call(i: usize) -> CallResult {
    CallResult {
        value: values()[i],
        pre_call_rsp: 0x9000,
        entry_rsp: 0x8ff8,
        resumed_rsp: 0x9000,
        return_pc: expected().return_pc,
    }
}
fn completed_originals() -> Originals {
    let mut o = originals();
    for (i, l) in o.labels().into_iter().enumerate() {
        o.record(l, original(i), enclosure(i, false)).unwrap();
    }
    o
}
struct Fixture {
    trial: Installed,
    rows: Vec<RawInterval>,
}
impl Fixture {
    fn new() -> Self {
        let epoch = Epoch::new(
            &[FunctionId(1)],
            Config {
                retained_per_function: CALLS,
                max_inflight: 1,
                max_invocations: CALLS,
            },
        )
        .unwrap();
        let generation = epoch.id();
        let trial = completed_originals()
            .installed(generation, FunctionId(1), 1)
            .unwrap();
        let rows = (0..CALLS)
            .map(|i| {
                let r = enclosure(i, true);
                RawInterval {
                    ordinal: i as u64 + 1,
                    entry_pc: expected().target,
                    return_pc: expected().return_pc,
                    owner: RawIntervalOwner::Sampled {
                        generation: generation.get(),
                        invocation: i,
                    },
                    start: RawTimestamp {
                        ticks: r.start.ticks + 10,
                        aux: 3,
                    },
                    end: RawTimestamp {
                        ticks: r.end.ticks - 20,
                        aux: 3,
                    },
                }
            })
            .collect();
        Self { trial, rows }
    }
    fn step(&mut self, i: usize) -> Result<(), Error> {
        let label = self.trial.labels()[i];
        self.trial.begin(label, &self.rows[..i])?.finish(
            &self.rows[..=i],
            call(i),
            enclosure(i, true),
        )
    }
}

#[test]
fn complete_population_keeps_real_sequence_independent_of_raw_ordinal() {
    let mut f = Fixture::new();
    for i in 0..CALLS {
        f.step(i).unwrap();
    }
    f.trial.complete().unwrap();
    assert_eq!(f.trial.originals().count(), 24);
    assert_eq!(f.trial.joined().count(), 24);
    assert_eq!(
        f.trial
            .originals()
            .map(|o| o.work.instructions)
            .sum::<u64>(),
        4800
    );
    for (i, (old, r)) in f.trial.joined().enumerate() {
        assert_eq!(old.label.external_id, ids()[i]);
        assert_eq!(old.raw.ordinal, i as u64 + 1);
        assert_eq!(r.reference.sequence, 1025 + i as u64);
        assert_eq!(
            r.gaps,
            Gaps {
                enclosure: 80,
                raw: 50,
                entry: 10,
                exit: 20
            }
        );
        assert_eq!(old.label.length, if i % 2 == 0 { 1 } else { 64 });
    }
    assert_eq!(f.trial.state.last_sequence, Some(1048));
}

#[test]
fn all_reference_identity_fields_and_stack_must_join_the_actual_result() {
    for installed in [false, true] {
        for field in 0..11 {
            let mut r = enclosure(0, installed);
            let expected_error = match field {
                0 => {
                    r.gate += 1;
                    Error::Identity
                }
                1 => {
                    r.pid += 1;
                    Error::Identity
                }
                2 => {
                    r.tid += 1;
                    Error::Identity
                }
                3 => {
                    r.target += 1;
                    Error::Identity
                }
                4 => {
                    r.continuation += 1;
                    Error::Identity
                }
                5 => {
                    r.leg = if installed {
                        ReferenceLeg::Original
                    } else {
                        ReferenceLeg::Installed
                    };
                    Error::Identity
                }
                6 => {
                    r.external_id += 1;
                    Error::Label
                }
                7 => {
                    r.sequence = 0;
                    Error::Sequence
                }
                8 => {
                    r.pre_call_rsp += 16;
                    Error::Stack
                }
                9 => {
                    r.resumed_rsp += 16;
                    Error::Stack
                }
                _ => {
                    r.pre_call_rsp = 0;
                    r.resumed_rsp = 0;
                    Error::Stack
                }
            };
            if installed {
                let mut f = Fixture::new();
                let l = f.trial.labels()[0];
                assert_eq!(
                    f.trial
                        .begin(l, &[])
                        .unwrap()
                        .finish(&f.rows[..1], call(0), r),
                    Err(expected_error)
                );
                assert_eq!(f.trial.complete(), Err(Error::Poisoned));
            } else {
                let mut o = originals();
                let l = o.labels()[0];
                assert_eq!(o.record(l, original(0), r), Err(expected_error));
                assert_eq!(
                    o.record(l, original(0), enclosure(0, false)),
                    Err(Error::Poisoned)
                );
            }
        }
    }
}

#[test]
fn reference_and_raw_endpoint_mutations_refuse_without_outlier_filtering() {
    for field in 0..9 {
        let mut f = Fixture::new();
        let l = f.trial.labels()[0];
        let mut r = enclosure(0, true);
        match field {
            0 => r.start.ticks = f.rows[0].start.ticks + 1,
            1 => r.end.ticks = f.rows[0].end.ticks - 1,
            2 => f.rows[0].start.ticks = r.start.ticks - 1,
            3 => f.rows[0].end.ticks = r.end.ticks + 1,
            4 => r.end.ticks = r.start.ticks - 1,
            5 => r.end.aux += 1,
            6 => f.rows[0].start.aux += 1,
            7 => f.rows[0].end.aux += 1,
            _ => {
                r.start.aux = 4;
                r.end.aux = 4;
                f.rows[0].start.aux = 4;
                f.rows[0].end.aux = 4;
            }
        }
        assert_eq!(
            f.trial
                .begin(l, &[])
                .unwrap()
                .finish(&f.rows[..1], call(0), r),
            Err(Error::Clock)
        );
        assert_eq!(f.trial.complete(), Err(Error::Poisoned));
    }
    // Exact equal endpoints remain valid; neither arithmetic nor a threshold
    // fabricates nonzero work duration. The unchanged old join also permits zero.
    let mut f = Fixture::new();
    let l = f.trial.labels()[0];
    let mut r = enclosure(0, true);
    r.end.ticks = r.start.ticks;
    f.rows[0].start.ticks = r.start.ticks;
    f.rows[0].end.ticks = r.end.ticks;
    f.trial
        .begin(l, &[])
        .unwrap()
        .finish(&f.rows[..1], call(0), r)
        .unwrap();
    assert_eq!(
        f.trial.joined().next().unwrap().1.gaps,
        Gaps {
            enclosure: 0,
            raw: 0,
            entry: 0,
            exit: 0
        }
    );
}

#[test]
fn missing_extra_prior_owner_value_and_ret_rows_use_the_unchanged_join() {
    for field in 0..6 {
        let mut f = Fixture::new();
        let l = f.trial.labels()[0];
        let mut c = call(0);
        let mut rows = f.rows[..1].to_vec();
        let old_error = match field {
            0 => {
                rows.clear();
                work::JoinError::RowCount
            }
            1 => {
                rows.push(rows[0]);
                work::JoinError::RowCount
            }
            2 => {
                rows[0].owner = RawIntervalOwner::InitialDisarmed;
                work::JoinError::Owner
            }
            3 => {
                rows[0].return_pc += 1;
                work::JoinError::Boundary
            }
            4 => {
                c.value += 1;
                work::JoinError::Value
            }
            _ => {
                rows[0].ordinal += 1;
                work::JoinError::Ordinal
            }
        };
        assert_eq!(
            f.trial
                .begin(l, &[])
                .unwrap()
                .finish(&rows, c, enclosure(0, true)),
            Err(Error::Work(old_error))
        );
        assert_eq!(f.trial.complete(), Err(Error::Poisoned));
    }
    let mut f = Fixture::new();
    f.step(0).unwrap();
    f.rows[0].start.ticks += 1;
    let l = f.trial.labels()[1];
    assert_eq!(
        f.trial.begin(l, &f.rows[..1]).err(),
        Some(Error::Work(work::JoinError::PriorRow))
    );
    assert_eq!(f.trial.begin(l, &f.rows[..1]).err(), Some(Error::Poisoned));
}

#[test]
fn exact_ids_populations_and_dropped_pending_are_not_recoverable_success() {
    let mut dup = ids();
    dup[1] = dup[0];
    assert!(matches!(
        Originals::new(expected(), dup, values()),
        Err(Error::Config)
    ));
    let mut o = originals();
    let wrong = o.labels()[1];
    assert_eq!(
        o.record(wrong, original(0), enclosure(0, false)),
        Err(Error::Label)
    );
    let mut f = Fixture::new();
    assert_eq!(f.trial.complete(), Err(Error::Incomplete));
    {
        let _pending = f.trial.begin(f.trial.labels()[0], &[]).unwrap();
    }
    assert_eq!(f.trial.complete(), Err(Error::Poisoned));
    let mut f = Fixture::new();
    for i in 0..CALLS {
        f.step(i).unwrap();
    }
    assert_eq!(
        f.trial.begin(f.trial.labels()[0], &f.rows).err(),
        Some(Error::Extra)
    );
    assert_eq!(f.trial.complete(), Err(Error::Poisoned));
}

#[test]
fn sequence_reset_gap_wrap_and_cross_leg_clock_change_are_refused() {
    for field in 0..4 {
        let mut f = Fixture::new();
        let l = f.trial.labels()[0];
        let mut r = enclosure(0, true);
        let error = match field {
            0 => {
                r.sequence = 1;
                Error::Sequence
            }
            1 => {
                r.sequence += 1;
                Error::Sequence
            }
            2 => {
                r.start.ticks = 1;
                r.end.ticks = 2;
                Error::Clock
            }
            _ => {
                r.start.aux = 4;
                r.end.aux = 4;
                Error::Clock
            }
        };
        assert_eq!(
            f.trial
                .begin(l, &[])
                .unwrap()
                .finish(&f.rows[..1], call(0), r),
            Err(error)
        );
    }
    let mut o = originals();
    let labels = o.labels();
    let mut first = enclosure(0, false);
    first.sequence = u64::MAX;
    o.record(labels[0], original(0), first).unwrap();
    assert_eq!(
        o.record(labels[1], original(1), enclosure(1, false)),
        Err(Error::Sequence)
    );
}
