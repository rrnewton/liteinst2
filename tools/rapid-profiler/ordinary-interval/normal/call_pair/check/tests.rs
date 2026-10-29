use super::*;
use rapid_profiler::frontend_native::RawTimestamp;
use rapid_profiler::generation::{Admission, Epoch, GenerationId, Record};
fn refuse(f: impl FnOnce()) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
}
fn generation(k: usize) -> GenerationId {
    Epoch::new(
        &[FunctionId(101), FunctionId(202)],
        Config {
            retained_per_function: k,
            max_inflight: 2,
            max_invocations: 2 * k,
        },
    )
    .unwrap()
    .id()
}
fn accounting(k: usize) -> Accounting {
    let mut p = Accounting::new(
        Geometry {
            functions: [FunctionId(101), FunctionId(202)],
            entries: [0x1000, 0x1100],
            ends: [0x1050, 0x1180],
            returns: [vec![0x1040], vec![0x1150, 0x1160]],
            call_pc: 0x1020,
            continuation: 0x1025,
            child_delta: 32,
        },
        k,
        520,
    );
    p.ready(pair_worker::Identity {
        pid: 11,
        tid: 12,
        cpu: 1,
        stack: (0x8000, 0xa000),
        caller: (0x2000, 0x3000),
    });
    p
}
fn published(g: GenerationId, index: u64) -> HistoryBinding {
    HistoryBinding::Published {
        action_index: index,
        generation: g,
    }
}
fn sampled(g: GenerationId, invocation: usize) -> RawIntervalOwner {
    RawIntervalOwner::Sampled {
        generation: g.get(),
        invocation,
    }
}
// Fabricated metadata only; never constructs an opaque site/stream/Batch or an
// actual Call receipt. It feeds the exact production Accounting::join validator.
fn fixture(
    p: &mut Accounting,
    owners: [RawIntervalOwner; 2],
    bindings: [HistoryBinding; 2],
    prefixes: [u64; 2],
) -> (Meta, [Row; 2], [u64; 512], [HistoryBinding; 2]) {
    let root = p.number + 1;
    p.accept(&Arc::new(input::Record::new(root, b"a,b").unwrap()));
    let mut rows = std::array::from_fn(|node| Row {
        function: p.geometry.functions[node],
        node,
        parent: 2 * root - 1,
        raw: RawInterval {
            ordinal: 2 * root - 1 + node as u64,
            entry_pc: p.geometry.entries[node],
            return_pc: p.geometry.returns[node][0],
            owner: owners[node],
            start: RawTimestamp {
                ticks: 10 + node as u64 * 10,
                aux: 3,
            },
            end: RawTimestamp {
                ticks: 50 - node as u64 * 10,
                aux: 3,
            },
        },
        rsp: 0x9008 - node as u64 * 32,
        word: if node == 0 { 0x2005 } else { 0x1025 },
        resume_pc: if node == 0 { 0x2005 } else { 0x1025 },
        resume_rsp: 0x9010 - node as u64 * 32,
        value: if node == 0 { (3_u64 << 32) | 2 } else { 2 },
        ack: if node == 0 {
            NormalCallPairAcknowledgement::CallerCheckpoint
        } else {
            NormalCallPairAcknowledgement::ChildContinuation
        },
        prefix: prefixes[node],
        sequence: p.totals.pairs.completed,
        children: u64::from(node == 0),
        sampled_children: None,
        completion: None,
        payload: None,
    });
    for node in 0..2 {
        if let RawIntervalOwner::Sampled {
            generation,
            invocation,
        } = owners[node]
        {
            let g = match bindings[node] {
                HistoryBinding::Published { generation: g, .. } => g,
                _ => panic!(),
            };
            assert_eq!(g.get(), generation);
            let rank = p
                .generations
                .iter()
                .find(|g| g.id == generation)
                .map_or(0, |g| g.counts[node]);
            let admission = Admission {
                generation: g,
                invocation,
                function: rows[node].function,
                entry_value: rows[node].raw.start.ticks,
            };
            let children =
                u64::from(node == 0 && matches!(owners[1], RawIntervalOwner::Sampled { .. }));
            rows[node].sampled_children = Some(children);
            rows[node].completion=Some(Completion {admission,disposition:Disposition::Retained {rank},
                deactivate:(rank+1==p.k).then_some(DeactivationRequest {generation:g,function:rows[node].function}),
                other_reservations_after_close:(rank+1==p.k).then_some(usize::from(node==1 && matches!(owners[0],RawIntervalOwner::Sampled {generation:g,..} if g==generation))) });
            rows[node].payload = Some(Payload {
                admission,
                thread: 1,
                start_sequence: p.totals.pairs.completed,
                outcome: PayloadOutcome::Completed {
                    end: observation(rows[node].raw),
                    completed_children: children,
                },
            });
        }
    }
    let n = owners
        .iter()
        .filter(|o| matches!(o, RawIntervalOwner::Sampled { .. }))
        .count() as u64;
    let after = NormalCallPairTotals {
        roots: root,
        child_acks: root,
        pairs: NormalTotals {
            entered: root * 2,
            ret_observed: root * 2,
            confirmed: root * 2,
            completed: p.totals.pairs.completed + n,
            unsampled: p.totals.pairs.unsampled + 2 - n,
        },
    };
    (
        Meta {
            pid: 11,
            tid: 12,
            registration: 1,
            install: INSTALL,
            number: root,
            before: p.totals,
            after,
            high: *prefixes.iter().max().unwrap(),
        },
        rows,
        journal(&rows, 12),
        bindings,
    )
}
fn first() -> (Accounting, Meta, [Row; 2], [u64; 512], [HistoryBinding; 2]) {
    let mut p = accounting(10);
    let g = generation(10);
    let (m, r, j, b) = fixture(
        &mut p,
        [sampled(g, 0), sampled(g, 1)],
        [published(g, 512); 2],
        [513; 2],
    );
    (p, m, r, j, b)
}
fn observed(s: Seen) -> RecordObservation {
    let c = s.row.completion.unwrap();
    RecordObservation {
        record: Record {
            admission: c.admission,
            terminal: Some(Terminal::Completed {
                value: c.admission.invocation as u64,
                disposition: c.disposition,
            }),
        },
        payload: s.row.payload,
    }
}
#[test]
fn nested_rows_join_real_shape_lifo_payloads_and_independent_generations() {
    let (mut p, m, r, j, b) = first();
    p.join(m, r, &j, b);
    assert_eq!(p.totals, m.after);
    assert_eq!(
        p.rows.iter().map(|s| s.rank).collect::<Vec<_>>(),
        vec![Some(0), Some(0)]
    );
    assert_eq!(
        p.rows.iter().map(|s| s.row.sequence).collect::<Vec<_>>(),
        vec![0, 0]
    );
    assert_eq!(p.rows[0].row.sampled_children, Some(1));
    assert_eq!(p.rows[1].row.sampled_children, Some(0));
    let copy = p.rows.iter().map(|&s| observed(s)).collect::<Vec<_>>();
    report_shape(
        copy[0].record.admission.generation.get(),
        &copy,
        20,
        &p.geometry.functions,
    );
    for (s, r) in p.rows.iter().zip(&copy) {
        assert_eq!(sample(*s, r), observation(s.row.raw));
    }
    let mut p = accounting(10);
    let a = generation(10);
    let b = generation(10);
    let (m, r, j, h) = fixture(
        &mut p,
        [sampled(a, 0), sampled(b, 0)],
        [published(a, 512), published(b, 513)],
        [513, 514],
    );
    p.join(m, r, &j, h);
    assert_eq!(p.generations.len(), 2);
    assert_eq!(p.generations[0].counts, [1, 0]);
    assert_eq!(p.generations[1].counts, [0, 1]);
    assert_eq!(p.rows[0].row.sampled_children, Some(1)); // Sampled child across generations still counts.
}
#[test]
fn full_512_word_journal_event_order_and_both_identity_rows_refuse_corruption() {
    for word in 0..512 {
        let (mut p, m, r, mut j, b) = first();
        j[word] ^= 1;
        refuse(|| p.join(m, r, &j, b));
    }
    let (mut p, m, r, mut j, b) = first();
    for i in 0..7 {
        j.swap(4 + 2 * 7 + i, 4 + 3 * 7 + i);
    }
    refuse(|| p.join(m, r, &j, b));
    for node in 0..2 {
        for mutation in 0..16 {
            let (mut p, m, mut r, _, b) = first();
            let s = &mut r[node];
            match mutation {
                0 => s.node ^= 1,
                1 => s.function = FunctionId(999),
                2 => s.parent += 1,
                3 => s.raw.ordinal += 1,
                4 => s.raw.entry_pc += 1,
                5 => s.raw.return_pc += 1,
                6 => s.rsp += 16,
                7 => s.word += 1,
                8 => s.resume_pc += 1,
                9 => s.resume_rsp += 1,
                10 => s.value ^= 1,
                11 => {
                    s.ack = if node == 0 {
                        NormalCallPairAcknowledgement::ChildContinuation
                    } else {
                        NormalCallPairAcknowledgement::CallerCheckpoint
                    }
                }
                12 => s.sequence += 1,
                13 => s.children ^= 1,
                14 => s.sampled_children = None,
                _ => s.prefix = 0,
            }
            let j = journal(&r, 12);
            refuse(|| p.join(m, r, &j, b));
        }
    }
    for mutation in 0..9 {
        let (mut p, mut m, r, j, b) = first();
        match mutation {
            0 => m.pid += 1,
            1 => m.tid += 1,
            2 => m.registration += 1,
            3 => m.install += 1,
            4 => m.number += 1,
            5 => m.before.pairs.completed += 1,
            6 => m.after.roots += 1,
            7 => m.after.child_acks += 1,
            _ => m.high = 512,
        }
        refuse(|| p.join(m, r, &j, b));
    }
}
#[test]
fn independent_function_budgets_closed_removed_initial_and_stop_between_entries() {
    for k in [10, 1000] {
        let mut p = accounting(k);
        let g = generation(k);
        for pair in 0..k {
            let (m, r, j, h) = fixture(
                &mut p,
                [sampled(g, 2 * pair), sampled(g, 2 * pair + 1)],
                [published(g, 0); 2],
                [1; 2],
            );
            p.join(m, r, &j, h);
        }
        let last = &p.rows[p.rows.len() - 2..];
        assert_eq!(
            last[0]
                .row
                .completion
                .unwrap()
                .other_reservations_after_close,
            Some(0)
        );
        assert_eq!(
            last[1]
                .row
                .completion
                .unwrap()
                .other_reservations_after_close,
            Some(1)
        );
        let (m, r, j, h) = fixture(
            &mut p,
            [RawIntervalOwner::FunctionClosed {
                generation: g.get(),
            }; 2],
            [published(g, 0); 2],
            [1; 2],
        );
        p.join(m, r, &j, h);
        assert_eq!(
            (p.totals.pairs.completed, p.totals.pairs.unsampled),
            (2 * k as u64, 2)
        );
        assert!(
            p.rows[p.rows.len() - 2..]
                .iter()
                .all(|s| s.rank.is_none() && s.row.payload.is_none())
        );
    }
    // Controller removal between parent and child entries preserves both real rows.
    let mut p = accounting(10);
    let g = generation(10);
    let (m, r, j, h) = fixture(
        &mut p,
        [
            sampled(g, 0),
            RawIntervalOwner::Removed {
                generation: g.get(),
            },
        ],
        [
            published(g, 0),
            HistoryBinding::Removed {
                action_index: 1,
                generation: g,
            },
        ],
        [1, 2],
    );
    p.join(m, r, &j, h);
    assert_eq!(p.rows[0].row.sampled_children, Some(0));
    assert_eq!((p.totals.pairs.completed, p.totals.pairs.unsampled), (1, 1));
    let mut p = accounting(10);
    let g = generation(10);
    let (m, r, j, h) = fixture(
        &mut p,
        [RawIntervalOwner::InitialDisarmed, sampled(g, 0)],
        [HistoryBinding::Initial, published(g, 0)],
        [0, 1],
    );
    p.join(m, r, &j, h);
    assert_eq!(p.rows[0].row.sampled_children, None);
    assert_eq!(p.rows[1].row.sampled_children, Some(0));
    let mut p = accounting(1000);
    let g = generation(1000);
    for _ in 0..2048 {
        let (m, r, j, h) = fixture(
            &mut p,
            [RawIntervalOwner::Removed {
                generation: g.get(),
            }; 2],
            [HistoryBinding::Removed {
                action_index: 1,
                generation: g,
            }; 2],
            [2; 2],
        );
        p.join(m, r, &j, h);
    }
    assert_eq!(
        (p.accepted.len(), p.rows.len(), p.number),
        (2048, 4096, 2048)
    );
    assert_eq!(
        (
            p.totals.roots,
            p.totals.child_acks,
            p.totals.pairs.unsampled
        ),
        (2048, 2048, 4096)
    );
    p.reports(&[(g.get(), vec![])], &[g.get()]);
    refuse(|| p.accept(&Arc::new(input::Record::new(2048, b"a,b").unwrap())));
    for which in 0..4 {
        let (mut p, m, mut r, _, mut b) = first();
        match which {
            0 => {
                r[0].raw.owner = RawIntervalOwner::FunctionClosed {
                    generation: coordinates(r[0].raw.owner).1,
                }
            }
            1 => {
                r[0].raw.owner = RawIntervalOwner::Removed {
                    generation: coordinates(r[0].raw.owner).1,
                }
            }
            2 => b[0] = HistoryBinding::Initial,
            _ => r[1].prefix = 512,
        }
        let j = journal(&r, 12);
        refuse(|| p.join(m, r, &j, b));
    }
}
// Actual core metadata production through the same Frame::complete path used by
// finish_interval. ModelReturnSlot is data only, not a native return/site receipt.
fn core_report_slots_and_payload_children_are_independent() {
    use rapid_profiler::frontend::{
        FailurePoint, FunctionSpec, GroupSpec, Limits, ModelReturnSlot, Session,
    };
    for k in [10, 1000] {
        let session = Session::new(
            INSTALL,
            &[
                FunctionSpec {
                    function: FunctionId(101),
                    group: 0,
                },
                FunctionSpec {
                    function: FunctionId(202),
                    group: 0,
                },
            ],
            &[GroupSpec { mandatory: true }],
            Limits {
                epochs: 3,
                threads: 1,
                depth: 2,
                records_per_epoch: 2 * k,
                actions: 8,
            },
        )
        .unwrap();
        let epoch = session
            .stage(Config {
                retained_per_function: k,
                max_inflight: 2,
                max_invocations: 2 * k,
            })
            .unwrap();
        let g = epoch.generation();
        let mut thread = session.register_thread(1).unwrap();
        session.publish(&epoch, FailurePoint::None).unwrap();
        let mut p = accounting(k);
        for root in 0..2 {
            let (m, r, j, h) = fixture(
                &mut p,
                [sampled(g, 2 * root), sampled(g, 2 * root + 1)],
                [published(g, 0); 2],
                [1; 2],
            );
            let mut slots = std::array::from_fn::<_, 2, _>(|node| ModelReturnSlot {
                identity: node as u64 + 1,
                word: r[node].word,
            });
            for node in 0..2 {
                let admission = thread
                    .enter(
                        INSTALL,
                        r[node].function,
                        r[node].raw.start.ticks,
                        &mut slots[node],
                    )
                    .unwrap();
                assert_eq!(admission, r[node].completion.unwrap().admission);
            }
            assert_eq!(thread.depth(), 2);
            for node in [1, 0] {
                let (completion, payload) = thread
                    .finish(&mut slots[node], observation(r[node].raw))
                    .unwrap();
                assert_eq!(Some(completion), r[node].completion);
                assert_eq!(Some(payload), r[node].payload);
                assert_eq!(slots[node].word, r[node].word);
            }
            assert_eq!(thread.depth(), 0);
            assert_eq!(thread.completed_sequence(), 2 * (root as u64 + 1));
            p.join(m, r, &j, h);
        }
        session.remove_current().unwrap();
        assert_eq!(epoch.reservations(), 0);
        let report = epoch.try_report().unwrap();
        let records = report.records().collect::<Vec<_>>();
        assert_eq!(records.len(), 4);
        let reports = vec![(g.get(), records.clone())];
        p.reports(&reports, &[g.get()]);
        for (slot, (&seen, row)) in p.rows.iter().zip(&records).enumerate() {
            let children = seen.row.sampled_children.unwrap();
            assert_ne!(slot as u64, children);
            assert_eq!(
                row.record.terminal,
                Some(Terminal::Completed {
                    value: slot as u64,
                    disposition: Disposition::Retained { rank: slot / 2 },
                })
            );
            assert_eq!(
                row.payload.unwrap().outcome,
                PayloadOutcome::Completed {
                    end: observation(seen.row.raw),
                    completed_children: children,
                }
            );
            assert_eq!(sample(seen, row), observation(seen.row.raw));
            // Old child-count-as-terminal model must fail both production joins.
            let mut wrong_slot = records.clone();
            wrong_slot[slot].record.terminal = Some(Terminal::Completed {
                value: children,
                disposition: Disposition::Retained { rank: slot / 2 },
            });
            refuse(|| report_shape(g.get(), &wrong_slot, 2 * k, &p.geometry.functions));
            refuse(|| {
                sample(seen, &wrong_slot[slot]);
            });
            refuse(|| p.reports(&[(g.get(), wrong_slot.clone())], &[g.get()]));
            // Correct terminal slots cannot hide changed child counts in either copy.
            let mut wrong_payload = *row;
            wrong_payload.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                end: observation(seen.row.raw),
                completed_children: children ^ 1,
            };
            refuse(|| {
                sample(seen, &wrong_payload);
            });
            let mut wrong_count = seen;
            wrong_count.row.sampled_children = Some(children ^ 1);
            refuse(|| {
                sample(wrong_count, row);
            });
        }
    }
}
#[test]
fn returned_completion_payload_and_report_bijection_predicates_refuse_coherent_changes() {
    core_report_slots_and_payload_children_are_independent();
    for node in 0..2 {
        for mutation in 0..8 {
            let (mut p, m, mut r, j, b) = first();
            match mutation {
                0 => r[node].completion = None,
                1 => r[node].payload = None,
                2 => r[node].completion.as_mut().unwrap().admission.function = FunctionId(999),
                3 => {
                    r[node].completion.as_mut().unwrap().disposition =
                        Disposition::Retained { rank: 1 }
                }
                4 => r[node].payload.as_mut().unwrap().thread = 2,
                5 => r[node].payload.as_mut().unwrap().start_sequence = 1,
                6 => {
                    r[node].sampled_children = Some(1 - u64::from(node == 0));
                    r[node].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                        end: observation(r[node].raw),
                        completed_children: r[node].sampled_children.unwrap(),
                    };
                }
                _ => {
                    r[node]
                        .completion
                        .as_mut()
                        .unwrap()
                        .other_reservations_after_close = Some(0)
                }
            }
            refuse(|| p.join(m, r, &j, b));
        }
    }
    let (mut p, m, r, j, b) = first();
    p.join(m, r, &j, b);
    for node in 0..2 {
        for mutation in 0..7 {
            let seen = p.rows[node];
            let mut row = observed(seen);
            match mutation {
                0 => row.record.admission.function = FunctionId(999),
                1 => row.record.admission.invocation += 1,
                2 => {
                    row.record.terminal = Some(Terminal::Completed {
                        value: 9,
                        disposition: Disposition::Retained { rank: 0 },
                    })
                }
                3 => row.payload = None,
                4 => row.payload.as_mut().unwrap().thread = 2,
                5 => row.payload.as_mut().unwrap().start_sequence += 1,
                _ => {
                    row.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                        end: Observation::Unavailable(9),
                        completed_children: 0,
                    }
                }
            }
            refuse(|| {
                sample(seen, &row);
            });
        }
    }
}
#[test]
fn raw_endpoints_keep_zero_maximum_migration_and_regression_without_timing_claim() {
    for (start, end, a0, a1, want) in [
        (0, 0, 0, 0, Observation::Value(0)),
        (
            u64::MAX,
            u64::MAX,
            u32::MAX,
            u32::MAX,
            Observation::Value(u64::MAX),
        ),
        (u64::MAX, 0, 0, 0, Observation::Unavailable(2)),
        (u64::MAX, 0, 0, 1, Observation::Unavailable(1)),
    ] {
        let (mut p, m, mut r, _, b) = first();
        for row in &mut r {
            row.raw.start = RawTimestamp {
                ticks: start,
                aux: a0,
            };
            row.raw.end = RawTimestamp {
                ticks: end,
                aux: a1,
            };
            row.completion.as_mut().unwrap().admission.entry_value = start;
            row.payload.as_mut().unwrap().admission.entry_value = start;
            row.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                end: want,
                completed_children: row.sampled_children.unwrap(),
            };
        }
        let j = journal(&r, 12);
        p.join(m, r, &j, b);
        for &s in &p.rows {
            assert_eq!(sample(s, &observed(s)), want);
            let raw = raw_line(s);
            assert!(raw.contains(&start.to_string()));
            assert!(raw.contains(&end.to_string()));
        }
    }
}
#[test]
fn every_report_generation_and_sample_has_one_complete_join_including_empty_epochs() {
    let (mut p, m, r, j, b) = first();
    p.join(m, r, &j, b);
    let g = p.rows[0].row.completion.unwrap().admission.generation.get();
    let empty = generation(10).get();
    let records = p.rows.iter().map(|&s| observed(s)).collect::<Vec<_>>();
    let reports = vec![(g, records), (empty, vec![])];
    let publications = [g, empty];
    p.reports(&reports, &publications);
    for mutation in 0..7 {
        let mut changed = reports.clone();
        match mutation {
            0 => {
                changed.pop();
            }
            1 => {
                let duplicate = changed[0].1.clone();
                changed.push((g, duplicate));
            }
            2 => changed[0].1.pop().map(|_| ()).unwrap(),
            3 => {
                let extra = changed[0].1[0];
                changed[0].1.push(extra);
            }
            4 => changed[0].0 = empty,
            5 => changed[0].1.swap(0, 1),
            _ => {
                let extra = changed[0].1[0];
                changed[1].1.push(extra);
            }
        }
        refuse(|| p.reports(&changed, &publications));
    }
    let mut wrong = publications;
    wrong[1] = g;
    refuse(|| p.reports(&reports, &wrong));
}
#[test]
fn numeric_rows_have_exact_fields_complete_raw_values_and_bounded_ascii_framing() {
    let (mut p, m, r, j, b) = first();
    p.join(m, r, &j, b);
    for &s in &p.rows {
        for (line, fields) in [
            (call_line(s), 16),
            (raw_line(s), 14),
            (sample_line(s, sample(s, &observed(s))), 13),
        ] {
            validate_line(&line);
            assert_eq!(line.trim_end_matches('\n').split(',').count(), fields);
        }
        let mut extreme = s;
        extreme.row.raw.start.ticks = u64::MAX;
        extreme.row.raw.end.ticks = u64::MAX;
        extreme.row.raw.start.aux = u32::MAX;
        extreme.row.raw.end.aux = u32::MAX;
        extreme.row.rsp = u64::MAX;
        extreme.row.word = u64::MAX;
        extreme.row.resume_pc = u64::MAX;
        extreme.row.resume_rsp = u64::MAX;
        let line = raw_line(extreme);
        validate_line(&line);
        assert!(line.len() <= 222);
        let columns = line.trim_end_matches('\n').split(',').collect::<Vec<_>>();
        for at in [5, 6, 7, 8, 10, 11] {
            assert_eq!(columns[at], u64::MAX.to_string());
        }
        for at in [12, 13] {
            assert_eq!(columns[at], u32::MAX.to_string());
        }
    }
    let full = input::Record::new(2048, &[b','; 64]).unwrap();
    let result = result_line(&full, packed(&full));
    validate_line(&result);
    assert_eq!(result.trim_end_matches('\n').split(',').count(), 8);
    assert!(result.len() <= 62);
    validate_line(&format!("{}\n", "a".repeat(349)));
    for bad in [
        "x".into(),
        "x\r\n".into(),
        "x\ny\n".into(),
        "x\0\n".into(),
        "x\t\n".into(),
        "é\n".into(),
        format!("{}\n", "a".repeat(350)),
    ] {
        refuse(|| validate_line(&bad));
    }
    let geometry = p.geometry.clone();
    for mutation in 0..6 {
        let mut bad = geometry.clone();
        match mutation {
            0 => bad.functions[1] = bad.functions[0],
            1 => bad.ends[0] = bad.entries[0] + 81,
            2 => bad.entries[1] = bad.entries[0],
            3 => bad.continuation += 1,
            4 => bad.child_delta = 8,
            _ => {
                let pc = bad.returns[1][0];
                bad.returns[1].push(pc);
            }
        }
        refuse(|| bad.check());
    }
}
#[test]
fn complete_role_census_preserves_original_call_continuation_and_every_child_ret() {
    use NormalCallPairRoleKind::*;
    let geometry = accounting(10).geometry;
    let rows = [
        (ParentEntry, 0x1000),
        (ChildEntry, 0x1100),
        (ChildRet, 0x1150),
        (ChildRet, 0x1160),
        (ChildAck, 0x1025),
        (ParentRet, 0x1040),
    ]
    .map(|(kind, pc)| NormalCallPairRole { kind, pc });
    geometry.check_roles(&rows);
    for i in 0..rows.len() {
        let mut missing = rows.to_vec();
        missing.remove(i);
        refuse(|| geometry.check_roles(&missing));
        let mut wrong = rows;
        wrong[i].pc += 1;
        refuse(|| geometry.check_roles(&wrong));
        let mut duplicate = rows.to_vec();
        duplicate.push(rows[i]);
        refuse(|| geometry.check_roles(&duplicate));
    }
    let mut moved = rows;
    moved.swap(0, 1);
    refuse(|| geometry.check_roles(&moved));
    let mut changed = rows;
    changed[4].pc = geometry.call_pc;
    refuse(|| geometry.check_roles(&changed));
}
