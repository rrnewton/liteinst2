use super::*;
use rapid_profiler::frontend::{FailurePoint, FunctionSpec, GroupSpec, ModelReturnSlot, Session};
use rapid_profiler::frontend_native::RawTimestamp;

struct Fixture {
    e: Expected,
    calls: Vec<CallResult>,
    rows: Vec<RawInterval>,
    page: [u64; 512],
    records: [Vec<RecordObservation>; 2],
    history: ControllerSnapshot,
}
fn fixture() -> Fixture {
    // Actual metadata engine supplies generations, payloads and Reports. These
    // controls never claim that the fabricated call/frame fields executed.
    let session = Session::new(
        INSTALL,
        &[FunctionSpec {
            function: FUNCTION,
            group: 0,
        }],
        &[GroupSpec { mandatory: true }],
        Limits {
            epochs: 2,
            threads: 1,
            depth: 1,
            records_per_epoch: 8,
            actions: 4,
        },
    )
    .unwrap();
    let mut thread = session.register_thread(1).unwrap();
    let a = session.stage(CONFIG).unwrap();
    let b = session.stage(CONFIG).unwrap();
    let g = [a.generation().get(), b.generation().get()];
    let e = Expected {
        originals: [11, 12, 13, 14, 15, 16, 17, 18],
        entry: 0x1000,
        returns: BTreeSet::from([0x1020, 0x1030]),
        continuation: 0x4000,
        pid: 11,
        tid: 12,
        generations: g,
    };
    let owners = [
        RawIntervalOwner::Sampled {
            generation: g[0],
            invocation: 0,
        },
        RawIntervalOwner::Sampled {
            generation: g[0],
            invocation: 1,
        },
        RawIntervalOwner::FunctionClosed { generation: g[0] },
        RawIntervalOwner::FunctionClosed { generation: g[0] },
        RawIntervalOwner::Removed { generation: g[0] },
        RawIntervalOwner::Sampled {
            generation: g[1],
            invocation: 0,
        },
        RawIntervalOwner::Sampled {
            generation: g[1],
            invocation: 1,
        },
        RawIntervalOwner::FunctionClosed { generation: g[1] },
    ];
    let (mut calls, mut rows) = (Vec::new(), Vec::new());
    session.publish(&a, FailurePoint::None).unwrap();
    for (i, owner) in owners.into_iter().enumerate() {
        if i == 4 {
            session.remove_current().unwrap();
        }
        if i == 5 {
            session.publish(&b, FailurePoint::None).unwrap();
        }
        let start = 100 + 10 * i as u64;
        if let RawIntervalOwner::Sampled {
            generation,
            invocation,
        } = owner
        {
            let mut slot = ModelReturnSlot {
                identity: i as u64 + 1,
                word: e.continuation,
            };
            let admitted = thread.enter(INSTALL, FUNCTION, start, &mut slot).unwrap();
            assert_eq!(
                (admitted.generation.get(), admitted.invocation),
                (generation, invocation)
            );
            thread
                .finish(&mut slot, Observation::Value(start + 3))
                .unwrap();
            assert_eq!(slot.word, e.continuation);
        }
        let ret = if i == 0 { 0x1020 } else { 0x1030 };
        calls.push(CallResult {
            value: e.originals[i],
            pre_call_rsp: 0x3000,
            entry_rsp: 0x2ff8,
            resumed_rsp: 0x3000,
            return_pc: ret,
        });
        rows.push(RawInterval {
            ordinal: i as u64 + 1,
            entry_pc: e.entry,
            return_pc: ret,
            owner,
            start: RawTimestamp {
                ticks: start,
                aux: 7,
            },
            end: RawTimestamp {
                ticks: start + 3,
                aux: 7,
            },
        });
    }
    session.remove_current().unwrap();
    let records = [
        a.try_report().unwrap().records().collect(),
        b.try_report().unwrap().records().collect(),
    ];
    let history = session.snapshot().unwrap();
    // Literal wire expectations: no call to the production prefix/packing code.
    let packed = [
        0x2001, 0x2002, 0xc02000, 0xc02000, 0x804000, 0x6001, 0x6002, 0xc06000,
    ];
    let entry_kinds = [1, 1, 3, 3, 3, 1, 1, 3];
    let mut page = [0; 512];
    page[..4].copy_from_slice(&[16, 0, 12, 0]);
    for (i, packed) in packed.into_iter().enumerate() {
        let generation = g[usize::from(i >= 5)];
        let at = 4 + i * 14;
        page[at..at + 14].copy_from_slice(&[
            entry_kinds[i],
            i as u64 + 1,
            0x1000,
            0x2ff8,
            0x4000,
            generation,
            packed,
            entry_kinds[i] + 1,
            i as u64 + 1,
            rows[i].return_pc,
            0x2ff8,
            0x4000,
            generation,
            packed,
        ]);
    }
    Fixture {
        e,
        calls,
        rows,
        page,
        records,
        history,
    }
}
impl Fixture {
    fn batch(&self) -> Batch<'_> {
        Batch {
            identity: (11, 12, 1, INSTALL, FUNCTION),
            number: 1,
            totals: (
                PairTotals::default(),
                PairTotals {
                    entries: 8,
                    returns: 8,
                    completed: 4,
                    unsampled: 4,
                },
            ),
            sequences: (0, 4),
            next: 9,
            gate: 8,
            raw: 0..8,
            events: 0..16,
            legacy: true,
            rows: &self.rows,
            journal: &self.page,
        }
    }
    fn valid(&self) -> Result<(), Error> {
        population(&self.calls, &self.rows, &self.batch(), &self.e)
    }
}

#[test]
fn selected_canonical_cli_numbers() {
    for (text, value) in [("0", 0), ("1", 1), ("18446744073709551615", u64::MAX)] {
        assert_eq!(number(text), value);
    }
    for bad in [
        "",
        "+1",
        "-1",
        "01",
        "00",
        " 1",
        "1 ",
        "0x10",
        "18446744073709551616",
    ] {
        assert!(std::panic::catch_unwind(|| number(bad)).is_err(), "{bad}");
    }
}

#[test]
fn selected_exact_population_and_real_reports() {
    let f = fixture();
    assert_eq!(f.valid(), Ok(()));
    assert_eq!(history(&f.history, f.e.generations), Ok(()));
    for (i, observed) in f.records.iter().enumerate() {
        assert_eq!(
            records(&f.rows, f.e.generations[i], 2 * i as u64, observed),
            Ok(())
        );
    }
    for (n, completed) in [0, 1, 2, 2, 2, 2, 3, 4, 4].into_iter().enumerate() {
        assert_eq!(
            totals(n).unwrap(),
            PairTotals {
                entries: n as u64,
                returns: n as u64,
                completed,
                unsampled: n as u64 - completed
            }
        );
    }
    assert_eq!(totals(9), Err(Error::Call));
    assert_eq!(
        std::array::from_fn::<_, 8, _>(prefix),
        [1, 1, 1, 1, 2, 3, 3, 3]
    );
}

#[test]
fn selected_call_owner_and_return_refusals() {
    let f = fixture();
    assert_eq!(f.valid(), Ok(()));
    assert!(population(&f.calls[..7], &f.rows, &f.batch(), &f.e).is_err());
    let mut extra = f.calls.clone();
    extra.push(f.calls[0]);
    assert!(population(&extra, &f.rows, &f.batch(), &f.e).is_err());
    let mut swapped = f.calls.clone();
    swapped.swap(0, 1);
    assert!(population(&swapped, &f.rows, &f.batch(), &f.e).is_err());
    for field in 0..5 {
        let mut c = f.calls[0];
        match field {
            0 => c.value ^= 1,
            1 => c.return_pc += 1,
            2 => c.entry_rsp += 8,
            3 => c.pre_call_rsp += 1,
            _ => c.resumed_rsp += 16,
        }
        assert_eq!(
            returned(0, &c, 11, &f.e.returns, totals(1).unwrap()),
            Err(Error::Call)
        );
    }
    for field in 0..4 {
        let mut t = totals(1).unwrap();
        match field {
            0 => t.entries += 1,
            1 => t.returns += 1,
            2 => t.completed += 1,
            _ => t.unsampled += 1,
        }
        assert_eq!(
            returned(0, &f.calls[0], 11, &f.e.returns, t),
            Err(Error::Call)
        );
    }
    for field in 0..8 {
        let mut bad = fixture();
        match field {
            0 => bad.rows[0].ordinal = 2,
            1 => bad.rows[0].entry_pc += 1,
            2 => bad.rows[0].return_pc += 1,
            3 => bad.rows[0].end.aux += 1,
            4 => bad.rows[0].end.ticks = bad.rows[0].start.ticks - 1,
            5 => {
                bad.rows[0].owner = RawIntervalOwner::Sampled {
                    generation: bad.e.generations[1],
                    invocation: 0,
                }
            }
            6 => {
                bad.rows[0].owner = RawIntervalOwner::Sampled {
                    generation: bad.e.generations[0],
                    invocation: 1,
                }
            }
            _ => {
                bad.rows[4].owner = RawIntervalOwner::FunctionClosed {
                    generation: bad.e.generations[0],
                }
            }
        }
        assert!(bad.valid().is_err());
    }
    let mut bad = fixture();
    bad.e.returns.insert(0x1040);
    assert_eq!(bad.valid(), Err(Error::Call));
}

#[test]
fn selected_whole_journal_prefix_and_tail_refusals() {
    let f = fixture();
    assert_eq!(f.valid(), Ok(()));
    for word in 0..512 {
        let mut page = f.page;
        page[word] ^= 1;
        let mut b = f.batch();
        b.journal = &page;
        assert_eq!(
            population(&f.calls, &f.rows, &b, &f.e),
            Err(Error::Batch),
            "word {word}"
        );
    }
    // Change both endpoints consistently to a plausible older prefix: the
    // decoder's entry/exit equality alone would not detect this association.
    let mut page = f.page;
    page[4 + 5 * 14 + 6] = 0x2001;
    page[4 + 5 * 14 + 13] = 0x2001;
    let mut b = f.batch();
    b.journal = &page;
    assert_eq!(population(&f.calls, &f.rows, &b, &f.e), Err(Error::Batch));
}

#[test]
fn selected_batch_identity_ranges_and_counts_refusals() {
    let f = fixture();
    assert_eq!(f.valid(), Ok(()));
    for field in 0..17 {
        let mut b = f.batch();
        match field {
            0 => b.identity.0 += 1,
            1 => b.identity.1 += 1,
            2 => b.identity.2 += 1,
            3 => b.identity.3 += 1,
            4 => b.identity.4 = FunctionId(2),
            5 => b.number += 1,
            6 => b.totals.0.entries = 1,
            7 => b.totals.1.unsampled = 3,
            8 => b.sequences.0 = 1,
            9 => b.sequences.1 = 8,
            10 => b.next = 8,
            11 => b.gate = 16,
            12 => b.raw = 1..9,
            13 => b.events = 0..15,
            14 => b.legacy = false,
            15 => b.rows = &f.rows[..7],
            _ => b.journal = &f.page[..511],
        }
        assert_eq!(
            population(&f.calls, &f.rows, &b, &f.e),
            Err(Error::Batch),
            "field {field}"
        );
    }
}

#[test]
fn selected_report_full_identity_sequence_and_payload_refusals() {
    let f = fixture();
    for (epoch, good) in f.records.iter().enumerate() {
        let g = f.e.generations[epoch];
        let sequence = 2 * epoch as u64;
        assert_eq!(records(&f.rows, g, sequence, good), Ok(()));
        assert_eq!(
            records(&f.rows, g, sequence, &good[..1]),
            Err(Error::Report)
        );
        let mut extra = good.clone();
        extra.push(good[0]);
        assert_eq!(records(&f.rows, g, sequence, &extra), Err(Error::Report));
        let mut reverse = good.clone();
        reverse.swap(0, 1);
        assert_eq!(records(&f.rows, g, sequence, &reverse), Err(Error::Report));
        assert_eq!(records(&f.rows, g, sequence + 1, good), Err(Error::Report));
        assert_eq!(records(&f.rows, g, u64::MAX, good), Err(Error::Report));
        for field in 0..12 {
            let mut bad = good.clone();
            match field {
                0 => {
                    bad[0].record.admission.generation =
                        f.records[1 - epoch][0].record.admission.generation
                }
                1 => bad[0].record.admission.function = FunctionId(2),
                2 => bad[0].record.admission.invocation = 1,
                3 => bad[0].record.admission.entry_value += 1,
                4 => {
                    bad[0].record.terminal = Some(Terminal::Completed {
                        value: 1,
                        disposition: Disposition::Retained { rank: 0 },
                    })
                }
                5 => {
                    bad[0].record.terminal = Some(Terminal::Completed {
                        value: 0,
                        disposition: Disposition::Retained { rank: 1 },
                    })
                }
                6 => bad[0].payload = None,
                7 => bad[0].payload.as_mut().unwrap().admission.invocation = 1,
                8 => bad[0].payload.as_mut().unwrap().thread = 2,
                9 => bad[0].payload.as_mut().unwrap().start_sequence += 1,
                10 => {
                    bad[0].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                        end: Observation::Value(999),
                        completed_children: 0,
                    }
                }
                _ => {
                    let p = bad[0].payload.as_mut().unwrap();
                    let PayloadOutcome::Completed { end, .. } = p.outcome else {
                        unreachable!()
                    };
                    p.outcome = PayloadOutcome::Completed {
                        end,
                        completed_children: 1,
                    };
                }
            }
            assert_eq!(
                records(&f.rows, g, sequence, &bad),
                Err(Error::Report),
                "field {field}"
            );
        }
    }
}

#[test]
fn selected_history_requires_all_four_actual_actions() {
    let f = fixture();
    assert_eq!(history(&f.history, f.e.generations), Ok(()));
    for field in 0..11 {
        let mut h = f.history.clone();
        match field {
            0 => h.status = ControllerStatus::TerminalFailure,
            1 => h.current = Some(h.actions[2].generation),
            2 => h.enabled[0] = false,
            3 => h.retained_failed_generation = Some(h.actions[0].generation),
            4 => {
                h.actions.pop();
            }
            5 => h.actions.push(h.actions[3]),
            6 => h.actions.swap(0, 2),
            7 => h.actions[3].kind = ActionKind::Deferred,
            8 => h.actions[3].current = Some(h.actions[3].generation),
            9 => h.actions[0].function = Some(FUNCTION),
            _ => h.actions[0].group = Some(0),
        }
        assert_eq!(history(&h, f.e.generations), Err(Error::History));
    }
}
