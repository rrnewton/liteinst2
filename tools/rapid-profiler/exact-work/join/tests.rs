use super::*;
use rapid_profiler::frontend::Payload;
use rapid_profiler::frontend_native::RawTimestamp;
use rapid_profiler::generation::{Admission, Config, Epoch, Record};

type RowMutation = fn(&mut RawInterval, &mut CallResult);
type RecordMutation = fn(&mut RecordObservation);

struct Fixture {
    trial: Trial,
    rows: Vec<RawInterval>,
    calls: Vec<CallResult>,
    records: Vec<RecordObservation>,
}
impl Fixture {
    fn new(schedule: Schedule, k: usize) -> Self {
        let function = FunctionId(7);
        let epoch = Epoch::new(
            &[function],
            Config {
                retained_per_function: k,
                max_inflight: 1,
                max_invocations: CALLS,
            },
        )
        .unwrap();
        let generation = epoch.id();
        let trial = Trial::new(TrialConfig {
            schedule,
            retained: k,
            external_ids: std::array::from_fn(|i| 1000 + i as u64),
            expected_values: std::array::from_fn(|i| 100 + i as u64),
            generation,
            function,
            thread: 1,
            entry_pc: 4096,
            return_pc: 4140,
        })
        .unwrap();
        let rows: Vec<_> = (0..CALLS)
            .map(|i| RawInterval {
                ordinal: i as u64 + 1,
                entry_pc: 4096,
                return_pc: 4140,
                owner: if i < k {
                    RawIntervalOwner::Sampled {
                        generation: generation.get(),
                        invocation: i,
                    }
                } else {
                    RawIntervalOwner::FunctionClosed {
                        generation: generation.get(),
                    }
                },
                start: RawTimestamp {
                    ticks: 1000 + i as u64 * 10,
                    aux: 3,
                },
                end: RawTimestamp {
                    ticks: 1001 + i as u64 * 10,
                    aux: 3,
                },
            })
            .collect();
        let calls = (0..CALLS)
            .map(|i| CallResult {
                value: 100 + i as u64,
                pre_call_rsp: 8192,
                entry_rsp: 8184,
                resumed_rsp: 8192,
                return_pc: 4140,
            })
            .collect();
        let records = rows
            .iter()
            .take(k)
            .enumerate()
            .map(|(rank, row)| {
                let admission = Admission {
                    generation,
                    function,
                    invocation: rank,
                    entry_value: row.start.ticks,
                };
                RecordObservation {
                    record: Record {
                        admission,
                        terminal: Some(Terminal::Completed {
                            value: rank as u64,
                            disposition: Disposition::Retained { rank },
                        }),
                    },
                    payload: Some(Payload {
                        admission,
                        thread: 1,
                        start_sequence: rank as u64,
                        outcome: PayloadOutcome::Completed {
                            end: Observation::Value(row.end.ticks),
                            completed_children: 0,
                        },
                    }),
                }
            })
            .collect();
        Self {
            trial,
            rows,
            calls,
            records,
        }
    }
    fn complete(&mut self) {
        let labels = self.trial.labels();
        for (i, label) in labels.into_iter().enumerate() {
            self.trial
                .begin(label, &self.rows[..i])
                .unwrap()
                .finish(&self.rows[..=i], self.calls[i])
                .unwrap();
        }
    }
    fn totals(&self) -> PairTotals {
        PairTotals {
            entries: 24,
            returns: 24,
            completed: self.trial.config.retained as u64,
            unsampled: (CALLS - self.trial.config.retained) as u64,
        }
    }
    fn validate(&self) -> Result<Summary, JoinError> {
        self.trial.validate_records(
            &self.rows,
            self.totals(),
            self.trial.config.generation,
            &self.records,
        )
    }
}

#[test]
fn all_twelve_complete_trials_keep_population_and_selection_distinct() {
    for schedule in [
        Schedule::AllShort,
        Schedule::AllLong,
        Schedule::Alternating,
        Schedule::TenShortThenLong,
    ] {
        for k in [24, 1, 10] {
            let mut f = Fixture::new(schedule, k);
            f.complete();
            let summary = f.validate().unwrap();
            let input_reads = match schedule {
                Schedule::AllShort => 24,
                Schedule::AllLong => 1536,
                Schedule::Alternating => 780,
                Schedule::TenShortThenLong => 906,
            };
            assert_eq!(
                summary.population,
                Work {
                    instructions: 6 * input_reads + 120,
                    branches: input_reads,
                    taken_branches: input_reads - 24,
                    input_byte_reads: input_reads,
                    return_read_bytes: 192
                }
            );
            assert_eq!((summary.population_calls, summary.retained_calls), (24, k));
            assert_eq!(
                f.trial
                    .joined()
                    .map(|c| c.label.external_id)
                    .collect::<Vec<_>>(),
                (1000..1024).collect::<Vec<_>>()
            );
            if k == 24 {
                assert_eq!(summary.selection_error_numerator, 0);
            }
            if schedule == Schedule::TenShortThenLong && k == 10 {
                assert_eq!(summary.retained.instructions, 110);
                assert_eq!(summary.population.instructions, 5556);
                assert_eq!(
                    (
                        summary.selection_error_numerator,
                        summary.selection_error_denominator
                    ),
                    (-52920, 240)
                );
            }
        }
    }
}

#[test]
fn duplicate_plan_ids_and_swapped_or_unknown_call_labels_refuse() {
    let mut f = Fixture::new(Schedule::AllShort, 10);
    f.trial.config.external_ids[1] = f.trial.config.external_ids[0];
    assert!(matches!(
        Trial::new(f.trial.config),
        Err(JoinError::DuplicateId)
    ));
    for mode in 0..3 {
        let mut f = Fixture::new(Schedule::AllShort, 10);
        let mut label = f.trial.labels()[0];
        match mode {
            0 => label = f.trial.labels()[1],
            1 => label.external_id = 999,
            _ => label.length = 64,
        }
        assert_eq!(f.trial.begin(label, &[]).err(), Some(JoinError::Label));
        assert_eq!(
            f.trial.begin(f.trial.labels()[0], &[]).err(),
            Some(JoinError::Poisoned)
        );
    }
}

#[test]
fn only_the_fixed_k_set_and_valid_boundary_descriptors_are_admitted() {
    for k in [0, 2, 25] {
        let mut config = Fixture::new(Schedule::AllShort, 1).trial.config;
        config.retained = k;
        assert!(matches!(Trial::new(config), Err(JoinError::Config)));
    }
    for mode in 0..3 {
        let mut config = Fixture::new(Schedule::AllShort, 1).trial.config;
        match mode {
            0 => config.thread = 0,
            1 => config.entry_pc = 0,
            _ => config.return_pc = config.entry_pc,
        }
        assert!(matches!(Trial::new(config), Err(JoinError::Config)));
    }
}

#[test]
fn raw_length_missing_extra_and_prior_row_mutation_refuse() {
    for count in [0, 2] {
        let mut f = Fixture::new(Schedule::AllLong, 1);
        let label = f.trial.labels()[0];
        assert_eq!(
            f.trial
                .begin(label, &[])
                .unwrap()
                .finish(&f.rows[..count], f.calls[0]),
            Err(JoinError::RowCount)
        );
    }
    let mut f = Fixture::new(Schedule::AllShort, 1);
    let labels = f.trial.labels();
    f.trial
        .begin(labels[0], &[])
        .unwrap()
        .finish(&f.rows[..1], f.calls[0])
        .unwrap();
    assert_eq!(
        f.trial.begin(labels[0], &f.rows[..1]).err(),
        Some(JoinError::Label)
    );
    let mut f = Fixture::new(Schedule::AllShort, 1);
    f.trial
        .begin(labels[0], &[])
        .unwrap()
        .finish(&f.rows[..1], f.calls[0])
        .unwrap();
    f.rows[0].end.ticks += 1;
    assert_eq!(
        f.trial.begin(labels[1], &f.rows[..1]).err(),
        Some(JoinError::PriorRow)
    );
}

#[test]
fn missing_completion_dropped_token_and_extra_invocation_cannot_validate() {
    let mut f = Fixture::new(Schedule::AllShort, 24);
    assert_eq!(f.validate(), Err(JoinError::Incomplete));
    {
        let _pending = f.trial.begin(f.trial.labels()[0], &[]).unwrap();
    }
    assert_eq!(f.validate(), Err(JoinError::Poisoned));
    let mut f = Fixture::new(Schedule::AllShort, 24);
    f.complete();
    assert_eq!(
        f.trial.begin(f.trial.labels()[0], &f.rows).err(),
        Some(JoinError::ExtraCall)
    );
    assert_eq!(f.validate(), Err(JoinError::Poisoned));
}

#[test]
fn each_new_row_boundary_owner_stack_value_and_clock_guard_refuses_specifically() {
    let changes: &[(RowMutation, JoinError)] = &[
        (|r, _| r.ordinal += 1, JoinError::Ordinal),
        (|r, _| r.entry_pc += 1, JoinError::Boundary),
        (|r, _| r.return_pc += 1, JoinError::Boundary),
        (|_, c| c.return_pc += 1, JoinError::Boundary),
        (
            |r, _| r.owner = RawIntervalOwner::InitialDisarmed,
            JoinError::Owner,
        ),
        (
            |r, _| r.owner = RawIntervalOwner::FunctionClosed { generation: 0 },
            JoinError::Owner,
        ),
        (|_, c| c.value += 1, JoinError::Value),
        (|_, c| c.resumed_rsp += 8, JoinError::Stack),
        (|_, c| c.entry_rsp += 8, JoinError::Stack),
        (|r, _| r.end.aux += 1, JoinError::Clock),
        (|r, _| r.end.ticks = r.start.ticks - 1, JoinError::Clock),
    ];
    for &(change, error) in changes {
        let mut f = Fixture::new(Schedule::AllShort, 1);
        change(&mut f.rows[0], &mut f.calls[0]);
        assert_eq!(
            f.trial
                .begin(f.trial.labels()[0], &[])
                .unwrap()
                .finish(&f.rows[..1], f.calls[0]),
            Err(error)
        );
        assert_eq!(f.validate(), Err(JoinError::Poisoned));
    }
}

#[test]
fn generation_invocation_and_closed_owner_cannot_be_substituted() {
    for mode in 0..4 {
        let mut f = Fixture::new(Schedule::AllShort, 1);
        let generation = f.trial.config.generation.get();
        let labels = f.trial.labels();
        if mode < 2 {
            f.rows[0].owner = RawIntervalOwner::Sampled {
                generation: generation + u64::from(mode == 0),
                invocation: usize::from(mode == 1),
            };
            assert_eq!(
                f.trial
                    .begin(labels[0], &[])
                    .unwrap()
                    .finish(&f.rows[..1], f.calls[0]),
                Err(JoinError::Owner)
            );
        } else {
            f.trial
                .begin(labels[0], &[])
                .unwrap()
                .finish(&f.rows[..1], f.calls[0])
                .unwrap();
            f.rows[1].owner = if mode == 2 {
                RawIntervalOwner::Removed { generation }
            } else {
                RawIntervalOwner::FunctionClosed {
                    generation: generation + 1,
                }
            };
            assert_eq!(
                f.trial
                    .begin(labels[1], &f.rows[..1])
                    .unwrap()
                    .finish(&f.rows[..2], f.calls[1]),
                Err(JoinError::Owner)
            );
        }
    }
}

#[test]
fn final_population_rows_totals_and_report_population_are_exact() {
    let mut f = Fixture::new(Schedule::Alternating, 10);
    f.complete();
    let generation = f.trial.config.generation;
    assert_eq!(
        f.trial
            .validate_records(&f.rows[..23], f.totals(), generation, &f.records),
        Err(JoinError::RowCount)
    );
    let mut extra = f.rows.clone();
    extra.push(f.rows[0]);
    assert_eq!(
        f.trial
            .validate_records(&extra, f.totals(), generation, &f.records),
        Err(JoinError::RowCount)
    );
    let mut swapped = f.rows.clone();
    swapped.swap(0, 1);
    assert_eq!(
        f.trial
            .validate_records(&swapped, f.totals(), generation, &f.records),
        Err(JoinError::PriorRow)
    );
    let mut totals = f.totals();
    totals.unsampled -= 1;
    assert_eq!(
        f.trial
            .validate_records(&f.rows, totals, generation, &f.records),
        Err(JoinError::Totals)
    );
    let other = Fixture::new(Schedule::AllShort, 1).trial.config.generation;
    assert_eq!(
        f.trial
            .validate_records(&f.rows, f.totals(), other, &f.records),
        Err(JoinError::ReportGeneration)
    );
    assert_eq!(
        f.trial
            .validate_records(&f.rows, f.totals(), generation, &f.records[..9]),
        Err(JoinError::RecordCount)
    );
    let mut records = f.records.clone();
    records.push(records[0]);
    assert_eq!(
        f.trial
            .validate_records(&f.rows, f.totals(), generation, &records),
        Err(JoinError::RecordCount)
    );
}

#[test]
fn report_identity_terminal_and_payload_mutations_do_not_pass_via_another_guard() {
    let changes: &[(RecordMutation, JoinError)] = &[
        (
            |r| r.record.admission.function = FunctionId(99),
            JoinError::Admission,
        ),
        (|r| r.record.admission.invocation += 1, JoinError::Admission),
        (
            |r| r.record.admission.entry_value += 1,
            JoinError::Admission,
        ),
        (|r| r.record.terminal = None, JoinError::Terminal),
        (
            |r| {
                r.record.terminal = Some(Terminal::Completed {
                    value: 1001,
                    disposition: Disposition::Retained { rank: 0 },
                })
            },
            JoinError::Terminal,
        ),
        (
            |r| {
                r.record.terminal = Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::Retained { rank: 1 },
                })
            },
            JoinError::Terminal,
        ),
        (
            |r| {
                r.record.terminal = Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::DroppedAfterBudget,
                })
            },
            JoinError::Terminal,
        ),
        (|r| r.payload = None, JoinError::Payload),
        (
            |r| r.payload.as_mut().unwrap().admission.entry_value += 1,
            JoinError::Payload,
        ),
        (
            |r| r.payload.as_mut().unwrap().thread += 1,
            JoinError::Payload,
        ),
        (
            |r| r.payload.as_mut().unwrap().start_sequence += 1,
            JoinError::Payload,
        ),
        (
            |r| {
                r.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(1002),
                    completed_children: 0,
                }
            },
            JoinError::Payload,
        ),
        (
            |r| {
                r.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(1001),
                    completed_children: 1,
                }
            },
            JoinError::Payload,
        ),
    ];
    for &(change, error) in changes {
        let mut f = Fixture::new(Schedule::AllShort, 10);
        f.complete();
        assert!(f.validate().is_ok());
        change(&mut f.records[0]);
        assert_eq!(f.validate(), Err(error));
    }
    let mut f = Fixture::new(Schedule::AllShort, 10);
    f.complete();
    f.records.swap(0, 1);
    assert_eq!(f.validate(), Err(JoinError::Admission));
    f.records.swap(0, 1);
    f.records[1] = f.records[0];
    assert_eq!(f.validate(), Err(JoinError::Admission));
    let mut f = Fixture::new(Schedule::AllShort, 10);
    f.complete();
    let other = Fixture::new(Schedule::AllShort, 1).trial.config.generation;
    f.records[0].record.admission.generation = other;
    f.records[0].payload.as_mut().unwrap().admission.generation = other;
    assert_eq!(f.validate(), Err(JoinError::Admission));
}
