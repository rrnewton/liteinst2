//! Fabricated copied data exercises the real consumer, not native execution.
use super::*;
use rapid_profiler::frontend_native::RawTimestamp;

fn fixture(k: usize) -> (Spec, Vec<TreeCallResult>, Vec<Batch>, Vec<ReportRow>) {
    let s = Spec {
        root: 0x1000,
        continuation: 0x9000,
        generation: 7,
        k,
        pid: 77,
        tid: 77,
        gate_base: 24,
    };
    let mut calls = Vec::new();
    let mut nodes = Vec::new();
    let mut reports = Vec::new();
    for i in 0..24 {
        let value = truth::scalar(label(i).0, label(i).1);
        let rsp = 0x200f8 + 16 * (i % 3) as u64;
        calls.push(TreeCallResult {
            external_id: i as u64 + 1,
            gate_sequence: 25 + i as u64,
            value,
            entry_rsp: rsp,
            pre_call_rsp: rsp + 8,
            resumed_rsp: rsp + 8,
            return_pc: 0x1016,
        });
        for n in 0..2 {
            let start = RawTimestamp {
                ticks: 100 * i as u64 + if n == 0 { 1 } else { 3 },
                aux: 5,
            };
            let end = RawTimestamp {
                ticks: 100 * i as u64 + if n == 0 { 8 } else { 6 },
                aux: 5,
            };
            let slot = 2 * i + n;
            let word = if n == 0 { 0x9000 } else { 0x100e };
            let sampled = i < k;
            nodes.push(Node {
                id: i as u64 + 1,
                node: n as u8,
                parent: (n == 1).then_some((i as u64 + 1, 0)),
                function: FunctionId(n as u64 + 1),
                depth: n,
                callsite: (n == 1).then_some(0x1009),
                registration: 1,
                gate: 25 + i as u64,
                raw: RawInterval {
                    ordinal: slot as u64 + 1,
                    entry_pc: if n == 0 { 0x1000 } else { 0x1020 },
                    return_pc: if n == 0 { 0x1016 } else { 0x1046 },
                    owner: if sampled {
                        RawIntervalOwner::Sampled {
                            generation: 7,
                            invocation: slot,
                        }
                    } else {
                        RawIntervalOwner::FunctionClosed { generation: 7 }
                    },
                    start,
                    end,
                },
                rsp: rsp - 16 * n as u64,
                word,
                resume_pc: word,
                resume_rsp: rsp + 8 - 16 * n as u64,
                value: value.wrapping_sub(n as u64),
                prefix: 1,
                sequence: sampled.then_some(2 * i as u64),
                children: sampled.then_some(u64::from(n == 0)),
            });
            if sampled {
                let admission = AdmissionRow {
                    generation: 7,
                    function: FunctionId(n as u64 + 1),
                    invocation: slot,
                    entry: start.ticks,
                };
                reports.push(ReportRow {
                    admission,
                    terminal: Some(Terminal::Completed {
                        value: slot as u64,
                        disposition: Disposition::Retained { rank: i },
                    }),
                    payload: Some(PayloadRow {
                        admission,
                        thread: 1,
                        sequence: 2 * i as u64,
                        outcome: PayloadOutcome::Completed {
                            end: Observation::Value(end.ticks),
                            completed_children: u64::from(n == 0),
                        },
                    }),
                });
            }
        }
    }
    let mut batches = Vec::new();
    for b in 0..3 {
        let mut journal = vec![0_u64; 512];
        journal[..4].copy_from_slice(&[32, 0, 77, 0]);
        for j in 0..8 {
            let i = 8 * b + j;
            let sampled = i < k;
            let kind = if sampled { 1 } else { 3 };
            for (e, (n, exit)) in [(0, false), (1, false), (1, true), (0, true)]
                .into_iter()
                .enumerate()
            {
                let r = nodes[2 * i + n];
                let packed = if sampled {
                    (2 * i + n + 1) as u64 | 0x2000
                } else {
                    0xc0_2000
                };
                let words = [
                    kind + u64::from(exit),
                    r.raw.ordinal,
                    if exit {
                        r.raw.return_pc
                    } else {
                        r.raw.entry_pc
                    },
                    r.rsp,
                    r.word,
                    7,
                    packed,
                ];
                let at = 4 + j * 28 + e * 7;
                journal[at..at + 7].copy_from_slice(&words);
            }
        }
        batches.push(Batch {
            pid: 77,
            tid: 77,
            install: INSTALL,
            registration: 1,
            functions: FUNCTIONS,
            number: b as u64 + 1,
            gate_base: 24,
            gate_sequence: 32 + 8 * b as u64,
            totals: (totals(8 * b, k), totals(8 * b + 8, k)),
            completed: ((2 * (8 * b).min(k)) as u64, (2 * (8 * b + 8).min(k)) as u64),
            nodes: nodes[16 * b..16 * b + 16].to_vec(),
            journal,
        });
    }
    (s, calls, batches, reports)
}
#[test]
fn tree_population_all_three_policies_and_nonzero_gate_baseline() {
    for k in [1, 10, 24] {
        let (s, c, b, r) = fixture(k);
        assert!(population(&s, &c, &b, &r));
        assert_eq!(r.len(), 2 * k);
        assert_eq!(b[2].nodes[15].raw.ordinal, 48);
        assert_eq!(b[2].gate_sequence, 48);
    }
}
#[test]
fn tree_population_missing_duplicate_or_reordered_calls_and_batches_refuse() {
    let (s, c, b, r) = fixture(10);
    assert!(!population(&s, &c[..23], &b, &r));
    assert!(!population(&s, &c, &b[..2], &r));
    let mut bad = c.clone();
    bad[10] = c[9];
    assert!(!population(&s, &bad, &b, &r));
    let mut bad = b.clone();
    bad.swap(0, 1);
    assert!(!population(&s, &c, &bad, &r));
    let mut bad = b.clone();
    bad[2] = b[1].clone();
    assert!(!population(&s, &c, &bad, &r));
    let mut bad = b.clone();
    bad[1].nodes.pop();
    assert!(!population(&s, &c, &bad, &r));
    assert!(!population(&s, &c, &b, &r[..19]));
}
#[test]
fn tree_population_identity_stack_and_case_substitution_refuse() {
    let (s, c, b, r) = fixture(10);
    for change in 0..12 {
        let mut bad = b.clone();
        let n = &mut bad[0].nodes[1];
        match change {
            0 => n.id += 1,
            1 => n.node = 0,
            2 => n.parent = None,
            3 => n.function = FunctionId(1),
            4 => n.depth = 0,
            5 => n.callsite = Some(0x1014),
            6 => n.registration += 1,
            7 => n.gate += 1,
            8 => n.raw.ordinal += 1,
            9 => {
                n.rsp += 16;
                n.resume_rsp += 16;
            }
            10 => {
                n.word += 1;
                n.resume_pc += 1;
            }
            11 => n.prefix += 1,
            _ => unreachable!(),
        }
        if change == 9 {
            for at in [14, 21] {
                bad[0].journal[at] += 16;
            }
        }
        if change == 10 {
            for at in [15, 22] {
                bad[0].journal[at] += 1;
            }
        }
        assert!(!population(&s, &c, &bad, &r));
    }
    // Change the call and both matching node values to the other valid case;
    // the preassigned population label still rejects the substitution.
    let mut bad_calls = c.clone();
    let mut bad_batches = b.clone();
    let other = truth::scalar(truth::Case::Conflict3, SEEDS[0]);
    assert_ne!(other, c[0].value);
    bad_calls[0].value = other;
    bad_batches[0].nodes[0].value = other;
    bad_batches[0].nodes[1].value = other.wrapping_sub(1);
    assert!(!population(&s, &bad_calls, &bad_batches, &r));
}
#[test]
fn tree_population_every_full_journal_word_and_prior_batch_metadata_refuse() {
    let (s, c, b, r) = fixture(10);
    for batch_index in 0..3 {
        for word in 0..512 {
            let mut bad = b.clone();
            bad[batch_index].journal[word] ^= 1;
            assert!(!population(&s, &c, &bad, &r));
        }
    }
    let mut bad = b.clone();
    bad[0].totals.1.roots += 1;
    assert!(!population(&s, &c, &bad, &r));
    let mut bad = b.clone();
    bad[0].completed.1 += 1;
    assert!(!population(&s, &c, &bad, &r));
    let mut bad = b.clone();
    bad[0].gate_base = 0;
    assert!(!population(&s, &c, &bad, &r));
    // Mutually consistent installed counters cannot replace the independently
    // counted24 successful original returns on the fresh actual main thread.
    let mut shifted = s;
    shifted.gate_base += 1;
    let mut shifted_calls = c.clone();
    for call in &mut shifted_calls {
        call.gate_sequence += 1;
    }
    let mut shifted_batches = b.clone();
    for batch in &mut shifted_batches {
        batch.gate_base += 1;
        batch.gate_sequence += 1;
        for node in &mut batch.nodes {
            node.gate += 1;
        }
    }
    assert!(!population(&shifted, &shifted_calls, &shifted_batches, &r));
}
#[test]
fn tree_population_report_owner_rank_and_complete_payload_refuse() {
    let (s, c, b, r) = fixture(10);
    for change in 0..13 {
        let mut bad = r.clone();
        let row = &mut bad[0];
        match change {
            0 => row.admission.generation += 1,
            1 => row.admission.function = FunctionId(2),
            2 => row.admission.invocation += 1,
            3 => row.admission.entry += 1,
            4 => {
                row.terminal = Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::Retained { rank: 1 },
                })
            }
            5 => row.payload = None,
            6 => row.payload.as_mut().unwrap().admission.invocation += 1,
            7 => row.payload.as_mut().unwrap().thread += 1,
            8 => row.payload.as_mut().unwrap().sequence += 1,
            9 => {
                row.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(8),
                    completed_children: 0,
                }
            }
            10 => row.terminal = None,
            11 => {
                row.terminal = Some(Terminal::Completed {
                    value: 1,
                    disposition: Disposition::Retained { rank: 0 },
                })
            }
            12 => {
                row.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Unavailable(1),
                    completed_children: 1,
                }
            }
            _ => unreachable!(),
        }
        assert!(!population(&s, &c, &b, &bad));
    }
    let mut bad = r.clone();
    bad[1] = r[0];
    assert!(!population(&s, &c, &b, &bad));
}
#[test]
fn tree_population_closed_owners_and_clock_chronology_refuse() {
    let (s, c, b, r) = fixture(1);
    for change in 0..6 {
        let mut bad = b.clone();
        let n = &mut bad[0].nodes[2];
        match change {
            0 => n.raw.owner = RawIntervalOwner::FunctionClosed { generation: 8 },
            1 => {
                n.raw.owner = RawIntervalOwner::Sampled {
                    generation: 7,
                    invocation: 2,
                }
            }
            2 => n.sequence = Some(2),
            3 => n.children = Some(1),
            4 => n.raw.end.ticks = n.raw.start.ticks - 1,
            5 => n.raw.end.aux += 1,
            _ => unreachable!(),
        }
        assert!(!population(&s, &c, &bad, &r));
    }
    let mut bad = b.clone();
    for n in &mut bad[2].nodes {
        n.raw.start.aux += 1;
        n.raw.end.aux += 1;
    }
    assert!(!population(&s, &c, &bad, &r));
    let mut bad = b.clone();
    for n in &mut bad[2].nodes {
        n.raw.start.ticks -= 1600;
        n.raw.end.ticks -= 1600;
    }
    assert!(!population(&s, &c, &bad, &r));
}
