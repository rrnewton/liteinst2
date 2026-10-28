use super::tests::{Fixture, fixture};
use super::*;

fn leg_fixture() -> Fixture {
    let mut f = fixture();
    for row in &mut f.installed {
        row.reference.sequence -= 24;
    }
    f
}
fn check(f: &Fixture) -> Result<[Gaps; 24]> {
    all_installed_leg(
        f.e,
        &f.installed,
        Parts {
            meta: f.meta,
            rows: &f.rows,
            journal: &f.journal,
            report_generation: f.e.generation,
            reports: &f.reports,
            history: &f.history,
        },
    )
}

#[test]
fn leg_valid_local_population_and_zero_endpoints() {
    let f = leg_fixture();
    assert_eq!(validate_original_leg(&f.originals), Ok(()));
    assert_eq!(
        check(&f),
        Ok([Gaps {
            enclosure: 90,
            raw: 60,
            entry: 10,
            exit: 20
        }; 24])
    );
    for tick in [0, u64::MAX] {
        let mut f = leg_fixture();
        for row in f.originals.iter_mut().chain(f.installed.iter_mut()) {
            row.reference.enclosure.start.ticks = tick;
            row.reference.enclosure.end.ticks = tick;
        }
        for (row, report) in f.rows.iter_mut().zip(f.reports.iter_mut()) {
            row.raw.start.ticks = tick;
            row.raw.end.ticks = tick;
            report.record.admission.entry_value = tick;
            let payload = report.payload.as_mut().unwrap();
            payload.admission.entry_value = tick;
            payload.outcome = PayloadOutcome::Completed {
                end: Observation::Value(tick),
                completed_children: 0,
            };
        }
        assert_eq!(validate_original_leg(&f.originals), Ok(()));
        assert_eq!(check(&f), Ok([Gaps::default(); 24]));
    }
    let mut f = leg_fixture();
    for (pair, rows) in f.originals.chunks_exact_mut(2).enumerate() {
        for row in rows {
            row.reference.observed_pre_call_rsp += pair as u64 * 16;
        }
    }
    assert_eq!(validate_original_leg(&f.originals), Ok(()));
}

#[test]
fn leg_identity_and_48_row_boundary_are_distinct() {
    for i in 0..24 {
        let mut f = leg_fixture();
        f.originals[i].reference.sequence += 24;
        assert_eq!(validate_original_leg(&f.originals), Err(Error::Identity));
        let mut f = leg_fixture();
        f.installed[i].reference.sequence += 24;
        assert_eq!(check(&f), Err(Error::Identity));
    }
    let legacy = fixture();
    assert!(legacy.check().is_ok());
    assert_eq!(
        validate_original_leg(&legacy.installed),
        Err(Error::Identity)
    );
    assert_eq!(leg_fixture().check(), Err(Error::Identity));
    let mut legacy = fixture();
    for (original, installed) in legacy.originals.iter().zip(legacy.installed.iter_mut()) {
        installed.reference.enclosure = original.reference.enclosure;
    }
    assert_eq!(legacy.check(), Err(Error::Clock));
    let mut legacy = fixture();
    for row in &mut legacy.installed {
        row.reference.enclosure.start.aux += 1;
        row.reference.enclosure.end.aux += 1;
    }
    assert_eq!(legacy.check(), Err(Error::Clock));
}

#[test]
fn leg_population_scalar_case_and_order_are_exact() {
    for installed in [false, true] {
        for mutation in 0..9 {
            let mut f = leg_fixture();
            let rows = if installed {
                &mut f.installed
            } else {
                &mut f.originals
            };
            match mutation {
                0 => {
                    rows.pop();
                }
                1 => rows.push(rows[0]),
                2 => rows.swap(0, 2),
                3 => rows[0].value ^= 1,
                4 => rows[0].seed_index = 1,
                5 => rows[0].length = 0,
                6 => rows[0].reference.external_id = 0,
                7 => rows[23].reference.external_id = u64::MAX,
                _ => rows[23].reference.sequence = u64::MAX,
            }
            if installed {
                assert!(check(&f).is_err(), "installed mutation{mutation}");
            } else {
                assert!(
                    validate_original_leg(&f.originals).is_err(),
                    "original mutation{mutation}"
                );
            }
        }
    }
}

#[test]
fn leg_clock_aux_stack_and_pair_rsp_are_exact() {
    for installed in [false, true] {
        for mutation in 0..10 {
            let mut f = leg_fixture();
            let rows = if installed {
                &mut f.installed
            } else {
                &mut f.originals
            };
            let row = &mut rows[1];
            let r = &mut row.reference.enclosure;
            match mutation {
                0 => r.end.ticks = r.start.ticks - 1,
                1 => r.start.aux += 1,
                2 => r.end.aux += 1,
                3 => {
                    r.start.aux += 1;
                    r.end.aux += 1;
                }
                4 => r.start.ticks = 0,
                5 => row.reference.observed_pre_call_rsp = 0,
                6 => row.reference.observed_pre_call_rsp += 1,
                7 => row.reference.observed_pre_call_rsp = 128,
                8 => row.reference.observed_pre_call_rsp = u64::MAX - 15,
                _ => row.reference.observed_pre_call_rsp += 16,
            }
            let expected = if mutation < 5 {
                Error::Clock
            } else {
                Error::Stack
            };
            if installed {
                assert_eq!(check(&f), Err(expected), "installed mutation{mutation}");
            } else {
                assert_eq!(
                    validate_original_leg(&f.originals),
                    Err(expected),
                    "original mutation{mutation}"
                );
            }
        }
    }
}

#[test]
fn installed_leg_keeps_metadata_record_and_full_journal_joins() {
    for word in 0..512 {
        let mut f = leg_fixture();
        f.journal[word] ^= 1;
        assert_eq!(check(&f), Err(Error::Journal), "word{word}");
    }
    for mutation in 0..14 {
        let mut f = leg_fixture();
        let expected = match mutation {
            0 => {
                f.e.pid = 0;
                Error::Identity
            }
            1 => {
                f.e.entry = u64::MAX;
                Error::Identity
            }
            2 => {
                f.meta.legacy = false;
                Error::Identity
            }
            3 => {
                f.meta.totals.1.confirmed -= 1;
                Error::Identity
            }
            4 => {
                f.meta.sequences.1 -= 1;
                Error::Identity
            }
            5 => {
                f.rows.pop();
                Error::Population
            }
            6 => {
                f.rows[0].raw.ordinal += 1;
                Error::Record
            }
            7 => {
                f.rows[0].raw.owner = RawIntervalOwner::FunctionClosed {
                    generation: f.e.generation,
                };
                Error::Record
            }
            8 => {
                f.rows[23].acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 25 };
                Error::Record
            }
            9 => {
                f.rows[0].entry_rsp += 16;
                Error::Stack
            }
            10 => {
                f.rows[0].return_word += 1;
                Error::Stack
            }
            11 => {
                f.rows[0].raw.end.aux += 1;
                Error::Clock
            }
            12 => {
                f.rows[0].raw.end.ticks = f.installed[0].reference.enclosure.end.ticks + 1;
                Error::Clock
            }
            _ => {
                f.rows[0].raw.return_pc += 1;
                Error::Record
            }
        };
        assert_eq!(check(&f), Err(expected), "mutation{mutation}");
    }
    let mut f = leg_fixture();
    for row in &mut f.rows {
        row.history_prefix = 2;
    }
    for event in 0..48 {
        f.journal[4 + event * 7 + 6] += 1 << 13;
    }
    assert_eq!(check(&f), Err(Error::Record));
}

#[test]
fn installed_leg_keeps_report_and_history_joins() {
    for mutation in 0..14 {
        let mut f = leg_fixture();
        let expected = match mutation {
            0 => {
                f.reports.pop();
                Error::Population
            }
            1 => {
                f.reports[0].record.admission.entry_value ^= 1;
                Error::Report
            }
            2 => {
                f.reports[0].record.admission.invocation = 1;
                Error::Report
            }
            3 => {
                f.reports[0].record.terminal = Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::Retained { rank: 1 },
                });
                Error::Report
            }
            4 => {
                f.reports[0].record.terminal = Some(Terminal::Completed {
                    value: 1,
                    disposition: Disposition::Retained { rank: 0 },
                });
                Error::Report
            }
            5 => {
                f.reports[0].payload = None;
                Error::Report
            }
            6 => {
                f.reports[0].payload.as_mut().unwrap().start_sequence = 1;
                Error::Report
            }
            7 => {
                f.reports[0].payload.as_mut().unwrap().thread = 2;
                Error::Report
            }
            8 => {
                f.reports[0].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(0),
                    completed_children: 0,
                };
                Error::Report
            }
            9 => {
                f.history.status = ControllerStatus::TerminalFailure;
                Error::History
            }
            10 => {
                f.history.current = Some(f.history.actions[0].generation);
                Error::History
            }
            11 => {
                f.history.actions.pop();
                Error::History
            }
            12 => {
                f.history.enabled[0] = false;
                Error::History
            }
            _ => {
                f.history.actions.swap(0, 1);
                Error::History
            }
        };
        assert_eq!(check(&f), Err(expected), "mutation{mutation}");
    }
}
