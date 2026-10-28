use super::*;
use rapid_profiler::frontend::{FailurePoint, FunctionSpec, GroupSpec, ModelReturnSlot, Session};
use rapid_profiler::frontend_native::RawTimestamp;

struct Fixture {
    e: Expected,
    g: [u64; EPOCHS],
    t: Vec<Transition>,
    calls: Vec<Call>,
    raw: Vec<RawInterval>,
    retired: Vec<Retired>,
    records: Vec<RecordObservation>,
    end: u64,
}
fn fixture() -> Fixture {
    fixture_mode(false)
}
fn fixture_mode(crossing: bool) -> Fixture {
    let session = Session::new(
        INSTALL,
        &[FunctionSpec {
            function: FUNCTION,
            group: 0,
        }],
        &[GroupSpec { mandatory: true }],
        Limits {
            epochs: 3,
            threads: 1,
            depth: 1,
            records_per_epoch: CALLS,
            actions: 40,
        },
    )
    .unwrap();
    let mut model = session.register_thread(1).unwrap();
    let e = Expected {
        values: std::array::from_fn(|i| if i % 2 == 0 { 81 } else { 8352 }),
        entry: 0x1000,
        ret: 0x1024,
        continuation: 0x4000,
        pid: 11,
        tid: 12,
    };
    let (mut g, mut t, mut calls, mut retired, mut records) =
        ([0; EPOCHS], Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let base = 1_000_000;
    for (epoch, generation) in g.iter_mut().enumerate() {
        let owner = session.stage(CONFIG).unwrap();
        *generation = owner.generation().get();
        session.publish(&owner, FailurePoint::None).unwrap();
        for index in 2 * epoch..2 * epoch + 2 {
            let requested = if index == 0 {
                0
            } else {
                base + action_ms(index) * 1_000_000
            };
            t.push(Transition {
                index,
                generation: *generation,
                requested,
                before: if index == 0 { 500_000 } else { requested },
                after: if index == 0 { base } else { requested + 100 },
            });
        }
        for j in 0..8 {
            let i = 8 * epoch + j;
            let start = 100 + i as u64 * 10;
            if j == 6 && !(crossing && epoch == 0) {
                session.remove_current().unwrap();
            }
            let raw_owner = if j < 6 {
                let mut slot = ModelReturnSlot {
                    identity: i as u64 + 1,
                    word: e.continuation,
                };
                let a = model.enter(INSTALL, FUNCTION, start, &mut slot).unwrap();
                if crossing && i == 5 {
                    session.remove_current().unwrap();
                }
                model
                    .finish(&mut slot, Observation::Value(start + 3))
                    .unwrap();
                assert_eq!(slot.word, e.continuation);
                RawIntervalOwner::Sampled {
                    generation: a.generation.get(),
                    invocation: a.invocation,
                }
            } else {
                RawIntervalOwner::Removed {
                    generation: *generation,
                }
            };
            let before = base + call_ms(i) * 1_000_000 + 1000;
            calls.push(Call {
                id: 1000 + i as u64,
                length: if i % 2 == 0 { 1 } else { 64 },
                raw: RawInterval {
                    ordinal: i as u64 + 1,
                    entry_pc: e.entry,
                    return_pc: e.ret,
                    owner: raw_owner,
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
                    value: e.values[i],
                    pre_call_rsp: 0x3000,
                    entry_rsp: 0x2ff8,
                    resumed_rsp: 0x3000,
                    return_pc: e.ret,
                },
                before,
                after: if crossing && i == 5 {
                    base + 31_000_000
                } else {
                    before + 1000
                },
            });
        }
        let observed = owner.try_report().unwrap();
        let record_start = records.len();
        records.extend(observed.records());
        drop(observed);
        drop(owner); // Real model permits; no mocked successful predicates.
        let before = calls.last().unwrap().after + 100;
        retired.push(Retired {
            epoch,
            generation: *generation,
            checkpoint: 8 * epoch as u64 + 7,
            before,
            after: before + 100,
            staged_after: (epoch + 3 < EPOCHS).then_some(before + 200),
            record_start,
            record_end: records.len(),
        });
    }
    assert_eq!(session.snapshot().unwrap().actions.len(), 40);
    let raw = calls.iter().map(|c| c.raw).collect();
    Fixture {
        e,
        g,
        t,
        calls,
        raw,
        retired,
        records,
        end: base + 800_000_000,
    }
}
fn valid(f: &Fixture) -> Result<[usize; 40], Error> {
    finish(
        &f.t,
        &f.calls,
        &f.g,
        &f.e,
        (&f.retired, &f.records),
        f.end,
        totals(&f.calls),
    )
}
fn page(f: &Fixture, end: usize) -> [u64; 512] {
    let mut p = [0; 512];
    p[0] = 8;
    p[2] = f.e.tid;
    for (local, c) in f.calls[end - 4..end].iter().enumerate() {
        let epoch = (end - 4 + local) / 8;
        let (kind, inv, reason, prefix) = match c.raw.owner {
            RawIntervalOwner::Sampled { invocation, .. } => {
                (1, invocation as u64 + 1, 0, 2 * epoch as u64 + 1)
            }
            RawIntervalOwner::Removed { .. } => (3, 0, 2, 2 * epoch as u64 + 2),
            _ => unreachable!(),
        };
        for side in 0..2 {
            let at = 4 + (2 * local + side) * 7;
            p[at..at + 7].copy_from_slice(&[
                kind + side as u64,
                c.raw.ordinal,
                if side == 0 { f.e.entry } else { f.e.ret },
                c.call.entry_rsp,
                f.e.continuation,
                f.g[epoch],
                inv | (prefix << 13) | (reason << 22),
            ]);
        }
    }
    p
}
fn view<'a>(f: &'a Fixture, p: &'a [u64], end: usize) -> Batch<'a> {
    let before = totals(&f.calls[..end - 4]);
    let after = totals(&f.calls[..end]);
    Batch {
        identity: (11, 12, 1, INSTALL, FUNCTION),
        number: (end / 4) as u64,
        totals: (before, after),
        sequences: (before.completed, after.completed),
        next: end as u64 + 1,
        gate: 200 + end as u64,
        raw: end as u64 - 4..end as u64,
        events: 2 * end as u64 - 8..2 * end as u64,
        rows: &f.raw[end - 4..end],
        journal: p,
    }
}

#[test]
fn twenty_real_model_reports_and_forty_complete_batch_views_join() {
    let f = fixture();
    assert_eq!(
        valid(&f),
        Ok(std::array::from_fn(|i| if i % 2 == 0 { 6 } else { 2 }))
    );
    assert_eq!(
        totals(&f.calls),
        PairTotals {
            entries: 160,
            returns: 160,
            completed: 120,
            unsampled: 40
        }
    );
    for end in (4..=CALLS).step_by(4) {
        let p = page(&f, end);
        assert_eq!(
            batch(&view(&f, &p, end), &f.calls[..end], &f.g, &f.e, 200),
            Ok(())
        );
    }
    let crossing = fixture_mode(true);
    let mut coverage = std::array::from_fn(|i| if i % 2 == 0 { 6 } else { 2 });
    coverage[0] = 5;
    assert_eq!(valid(&crossing), Ok(coverage)); // Original owner survives a real disarm bracket.
}
#[test]
fn ids_owners_call_returns_clock_and_action_brackets_refuse() {
    for m in 0..10 {
        let mut f = fixture();
        match m {
            0 => f.calls[1].id = 1000,
            1 => f.calls[1].raw.ordinal = 1,
            2 => f.calls[0].call.resumed_rsp += 8,
            3 => f.calls[0].raw.end.aux ^= 1,
            4 => f.calls[0].call.value ^= 1,
            5 => f.calls[0].raw.entry_pc += 1,
            6 => f.calls[0].raw.owner = RawIntervalOwner::FunctionClosed { generation: f.g[0] },
            7 => f.calls[0].raw.owner = RawIntervalOwner::Removed { generation: f.g[0] },
            8 => f.t[1].requested += 1,
            9 => f.g[3] = f.g[0],
            _ => unreachable!(),
        }
        assert!(valid(&f).is_err(), "mutation {m}");
    }
}
#[test]
fn missing_stable_windows_and_fixed_replacement_cutoffs_refuse() {
    let mut f = fixture();
    f.calls.pop();
    assert_eq!(valid(&f), Err(Error::Schedule));
    let mut f = fixture();
    f.calls.push(f.calls[159]);
    assert_eq!(valid(&f), Err(Error::Schedule));
    let mut f = fixture();
    f.t[39].after = f.end - 1; // Ordered in-window calls overlap final disarm; no complete off window.
    assert_eq!(valid(&f), Err(Error::Coverage));
    for m in 0..5 {
        let mut f = fixture();
        match m {
            0 => f.retired[0].staged_after = Some(cutoff(f.t[0].after, 3).unwrap()),
            1 => f.retired[0].checkpoint = 6, // A call before actual disarm is not a native return proof.
            2 => f.retired[0].before = f.calls[6].after - 1,
            3 => f.retired.swap(0, 1),
            4 => {
                f.retired.pop();
            }
            _ => unreachable!(),
        }
        assert!(valid(&f).is_err(), "reuse mutation {m}");
    }
}
#[test]
fn missing_duplicate_stale_counters_prefixes_and_full_page_tail_refuse() {
    let f = fixture();
    let p = page(&f, 8);
    for m in 0..10 {
        let mut b = view(&f, &p, 8);
        match m {
            0 => b.number = 1,
            1 => b.next = 8,
            2 => b.gate += 1,
            3 => b.sequences.0 = 0,
            4 => b.totals.1.completed += 1,
            5 => b.identity.2 = 2,
            6 => b.events.start = 0,
            7 => b.rows = &f.raw[..4],
            8 => b.rows = &f.raw[4..7],
            9 => b.number = 3,
            _ => unreachable!(),
        }
        assert_eq!(batch(&b, &f.calls[..8], &f.g, &f.e, 200), Err(Error::Batch));
    }
    for at in [0, 1, 2, 3, 10, 17, 60, 511] {
        let mut p = page(&f, 8);
        p[at] ^= 1;
        assert_eq!(
            batch(&view(&f, &p, 8), &f.calls[..8], &f.g, &f.e, 200),
            Err(Error::Batch)
        );
    }
}
#[test]
fn report_payload_ownership_global_sequence_and_population_refuse() {
    for m in 0..7 {
        let mut f = fixture();
        match m {
            0 => f.records[6].payload.as_mut().unwrap().start_sequence = 0,
            1 => f.records[6].payload.as_mut().unwrap().thread = 2,
            2 => {
                f.records[6].record.terminal = Some(Terminal::Completed {
                    value: 1,
                    disposition: Disposition::Retained { rank: 0 },
                })
            }
            3 => {
                f.records.pop();
            }
            4 => f.retired[1].record_start = 0,
            5 => {
                f.records[6].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(0),
                    completed_children: 1,
                }
            }
            6 => f.records.push(f.records[0]),
            _ => unreachable!(),
        }
        assert!(valid(&f).is_err(), "report mutation {m}");
    }
}
#[test]
fn bounded_export_returns_the_exact_unsent_owner_on_full_and_disconnect() {
    let (tx, rx) = mpsc::sync_channel(2);
    let owner = Arc::new([7_u8; 512]);
    super::super::export(&tx, Arc::clone(&owner)).unwrap();
    super::super::export(&tx, Arc::clone(&owner)).unwrap();
    let (error, unsent) = super::super::export(&tx, Arc::clone(&owner)).unwrap_err();
    assert_eq!(error, Error::Full);
    assert!(Arc::ptr_eq(&owner, &unsent));
    assert_eq!(*unsent, [7; 512]);
    assert_eq!(Arc::strong_count(&owner), 4);
    assert!(Arc::ptr_eq(&owner, &rx.recv().unwrap()));
    assert!(Arc::ptr_eq(&owner, &rx.recv().unwrap()));
    drop(rx);
    let (error, again) = super::super::export(&tx, unsent).unwrap_err();
    assert_eq!(error, Error::Disconnected);
    assert!(Arc::ptr_eq(&owner, &again));
    assert_eq!(Arc::strong_count(&owner), 2);
}

#[test]
fn single_completed_call_after_window_end_refuses_with_coverage_intact() {
    let mut f = fixture();
    assert_eq!(
        valid(&f),
        Ok(std::array::from_fn(|i| if i % 2 == 0 { 6 } else { 2 }))
    );
    let before = totals(&f.calls);
    // Only the last call moves; call 158 still covers the final off window.
    f.calls[159].before = f.end + 1000;
    f.calls[159].after = f.end + 2000;
    assert_eq!(
        f.calls[158].raw.owner,
        RawIntervalOwner::Removed {
            generation: f.g[19]
        }
    );
    assert!(f.calls[158].before > f.t[39].after && f.calls[158].after < f.end);
    assert_eq!(
        f.calls
            .iter()
            .filter(|c| c.before > f.t[39].after && c.after < f.end)
            .count(),
        1
    );
    assert_eq!(totals(&f.calls), before);
    assert!(prefix(&f.t, &f.calls, &f.g, &f.e).is_ok());
    // All former final joins remain valid: the new refusal is chronology, not lost coverage.
    for r in &f.retired {
        assert_eq!(reuse(r, &f.t, &f.calls, &f.g), Ok(()));
        assert_eq!(
            report(
                &f.calls,
                r.generation,
                &f.records[r.record_start..r.record_end]
            ),
            Ok(())
        );
    }
    assert_eq!(valid(&f), Err(Error::Schedule));
}

#[test]
fn final_retirement_after_window_end_refuses_with_all_old_joins_intact() {
    let mut f = fixture();
    assert_eq!(
        valid(&f),
        Ok(std::array::from_fn(|i| if i % 2 == 0 { 6 } else { 2 }))
    );
    // Only the last retirement moves; it has no replacement-stage cutoff.
    f.retired[19].before = f.end + 1000;
    f.retired[19].after = f.end + 2000;
    assert!(f.calls.iter().all(|c| c.after <= f.end));
    assert!(f.retired[19].after < f.t[0].after + 2_000_000_000);
    assert!(prefix(&f.t, &f.calls, &f.g, &f.e).is_ok());
    assert_eq!(reuse(&f.retired[19], &f.t, &f.calls, &f.g), Ok(()));
    let r = &f.retired[19];
    assert_eq!(
        report(
            &f.calls,
            r.generation,
            &f.records[r.record_start..r.record_end]
        ),
        Ok(())
    );
    assert_eq!(valid(&f), Err(Error::Schedule));
}
