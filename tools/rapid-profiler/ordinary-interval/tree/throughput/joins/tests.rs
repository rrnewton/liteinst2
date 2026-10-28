//! Synthetic copies test the actual consumer; no fabricated native receipts.
use super::*;
use rapid_profiler::frontend_native::RawTimestamp;
fn fixture(block: usize, k: usize) -> (Spec, Vec<TreeCallResult>, Vec<Batch>, Vec<Reported>) {
    // Deliberately nonconsecutive generations: no block+1 assumption.
    let s = Spec {
        root: 0x1000,
        continuation: 0x9000,
        pid: 77,
        tid: 77,
        block,
        k,
        generation: 17 + 3 * block as u64,
    };
    let mut calls = Vec::new();
    let mut nodes = Vec::new();
    let mut reports = Vec::new();
    for i in 0..24 {
        let id = (24 * block + i + 1) as u64;
        let rsp = 0x200f8;
        calls.push(TreeCallResult {
            external_id: id,
            gate_sequence: id,
            value: VALUES[label(i).2],
            pre_call_rsp: rsp + 8,
            entry_rsp: rsp,
            resumed_rsp: rsp + 8,
            return_pc: 0x1016,
        });
        for (n, &function) in FUNCTIONS.iter().enumerate() {
            let start = RawTimestamp {
                ticks: 100 * id + 1 + 2 * n as u64,
                aux: 5,
            };
            let end = RawTimestamp {
                ticks: 100 * id + 8 - 2 * n as u64,
                aux: 5,
            };
            let slot = 2 * i + n;
            let sampled = i < k;
            let word = if n == 0 { 0x9000 } else { 0x100e };
            nodes.push(Node {
                id,
                node: n as u8,
                parent: (n == 1).then_some((id, 0)),
                function,
                depth: n,
                callsite: (n == 1).then_some(0x1009),
                registration: 1,
                gate: id,
                raw: RawInterval {
                    ordinal: (48 * block + slot + 1) as u64,
                    entry_pc: if n == 0 { 0x1000 } else { 0x1020 },
                    return_pc: if n == 0 { 0x1016 } else { 0x1046 },
                    start,
                    end,
                    owner: if sampled {
                        RawIntervalOwner::Sampled {
                            generation: s.generation,
                            invocation: slot,
                        }
                    } else {
                        RawIntervalOwner::FunctionClosed {
                            generation: s.generation,
                        }
                    },
                },
                rsp: rsp - 16 * n as u64,
                word,
                resume_pc: word,
                resume_rsp: rsp + 8 - 16 * n as u64,
                value: calls[i].value.wrapping_sub(n as u64),
                prefix: 2 * block + 1,
                sequence: sampled.then_some((2 * k * block + 2 * i) as u64),
                children: sampled.then_some(u64::from(n == 0)),
            });
            if sampled {
                let a = AdmissionData {
                    generation: s.generation,
                    function,
                    slot,
                    entry: start.ticks,
                };
                reports.push(Reported {
                    admission: a,
                    terminal: Some(Terminal::Completed {
                        value: slot as u64,
                        disposition: Disposition::Retained { rank: i },
                    }),
                    payload: Some(PayloadData {
                        admission: a,
                        thread: 1,
                        sequence: (2 * k * block + 2 * i) as u64,
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
        let mut page = vec![0_u64; 512];
        page[..4].copy_from_slice(&[32, 0, 77, 0]);
        for j in 0..8 {
            let i = 8 * b + j;
            for (e, (n, exit)) in [(0, false), (1, false), (1, true), (0, true)]
                .into_iter()
                .enumerate()
            {
                let row = nodes[2 * i + n];
                let sampled = i < k;
                let packed = (((2 * block + 1) as u64) << 13)
                    | if sampled {
                        (2 * i + n + 1) as u64
                    } else {
                        0xc0_0000
                    };
                let words = [
                    (if sampled { 1 } else { 3 }) + u64::from(exit),
                    row.raw.ordinal,
                    if exit {
                        row.raw.return_pc
                    } else {
                        row.raw.entry_pc
                    },
                    row.rsp,
                    row.word,
                    s.generation,
                    packed,
                ];
                let at = 4 + j * 28 + e * 7;
                page[at..at + 7].copy_from_slice(&words);
            }
        }
        let counts = |roots: usize| {
            let all = 24 * block + roots;
            let admitted = 2 * k * block + 2 * roots.min(k);
            TreeTotals {
                roots: all as u64,
                pairs: PairTotals {
                    entries: 2 * all as u64,
                    returns: 2 * all as u64,
                    completed: admitted as u64,
                    unsampled: (2 * all - admitted) as u64,
                },
            }
        };
        let before = counts(8 * b);
        let after = counts(8 * b + 8);
        batches.push(Batch {
            pid: 77,
            tid: 77,
            install: INSTALL,
            registration: 1,
            functions: FUNCTIONS,
            number: (3 * block + b + 1) as u64,
            gate_base: 0,
            gate_sequence: (24 * block + 8 * b + 8) as u64,
            totals: (before, after),
            completed: (before.pairs.completed, after.pairs.completed),
            nodes: nodes[16 * b..16 * b + 16].to_vec(),
            journal: page,
        });
    }
    (s, calls, batches, reports)
}
fn nodes(b: &[Batch]) -> Vec<Node> {
    b.iter().flat_map(|p| p.nodes.iter().copied()).collect()
}
fn prefix(k: usize, blocks: usize) -> Cursor {
    let mut c = Cursor::default();
    for block in 0..blocks {
        let (s, call, b, r) = fixture(block, k);
        assert!(c.finish_block(&s, &call, &nodes(&b), &r));
    }
    c
}
#[test]
fn throughput_absolute_lifetimes_and_local_slots_all64_blocks() {
    for k in [1, 10, 24] {
        let mut cursor = Cursor::default();
        for block in 0..64 {
            let (s, c, b, r) = fixture(block, k);
            for (j, batch_view) in b.iter().enumerate() {
                assert!(batch(&s, j, &c, batch_view));
            }
            assert!(cursor.finish_block(&s, &c, &nodes(&b), &r));
            assert_eq!(r[0].admission.slot, 0);
            assert_eq!(r[0].payload.unwrap().sequence, (2 * k * block) as u64);
            assert_eq!(b[2].nodes[15].raw.ordinal, (48 * (block + 1)) as u64);
            assert_eq!(b[2].gate_sequence, (24 * (block + 1)) as u64);
        }
        assert_eq!(cursor.blocks(), 64);
        let t = totals_at(64, 0, k);
        assert_eq!(
            (t.roots, t.pairs.entries, t.pairs.returns),
            (1536, 3072, 3072)
        );
        assert_eq!(
            (t.pairs.completed, t.pairs.unsampled),
            ((128 * k) as u64, (3072 - 128 * k) as u64)
        );
    }
}
#[test]
fn throughput_reset_namespaces_and_stale_epoch_refuse() {
    let (s, c, b, r) = fixture(1, 10);
    for field in 0..10 {
        let mut bad = b[0].clone();
        match field {
            0 => bad.number = 1,
            1 => bad.gate_base = 24,
            2 => bad.gate_sequence -= 24,
            3 => bad.totals.0 = totals_at(0, 0, 10),
            4 => bad.completed.0 = 0,
            5 => {
                bad.nodes[0].raw.ordinal -= 48;
                bad.journal[5] -= 48;
                bad.journal[26] -= 48;
            }
            6 => {
                bad.nodes[0].prefix = 1;
                bad.journal[10] -= 2 << 13;
                bad.journal[31] -= 2 << 13;
            }
            7 => bad.nodes[0].sequence = Some(0),
            8 => {
                bad.nodes[0].raw.owner = RawIntervalOwner::Sampled {
                    generation: s.generation - 3,
                    invocation: 0,
                }
            }
            9 => {
                bad.nodes[0].raw.owner = RawIntervalOwner::Sampled {
                    generation: s.generation,
                    invocation: 20,
                }
            }
            _ => unreachable!(),
        }
        assert!(!batch(&s, 0, &c, &bad));
    }
    let mut reset = c.clone();
    for call in &mut reset {
        call.external_id -= 24;
        call.gate_sequence -= 24;
    }
    assert!(!batch(&s, 0, &reset, &b[0]));
    let mut cursor = prefix(10, 1);
    let before = cursor;
    let mut stale = s;
    stale.generation -= 3;
    assert!(!cursor.finish_block(&stale, &c, &nodes(&b), &r));
    assert_eq!(cursor, before);
    // A fully coherent copied batch/Report from a reused generation still
    // cannot advance the lifetime cursor: isolate the cross-block guard.
    let mut same = b.clone();
    let mut same_reports = r.clone();
    for page in &mut same {
        for row in &mut page.nodes {
            match &mut row.raw.owner {
                RawIntervalOwner::Sampled { generation, .. }
                | RawIntervalOwner::FunctionClosed { generation } => *generation = stale.generation,
                _ => unreachable!(),
            }
        }
        for event in page.journal[4..228].chunks_exact_mut(7) {
            event[5] = stale.generation;
        }
    }
    for row in &mut same_reports {
        row.admission.generation = stale.generation;
        row.payload.as_mut().unwrap().admission.generation = stale.generation;
    }
    for (j, page) in same.iter().enumerate() {
        assert!(batch(&stale, j, &c, page));
    }
    assert!(!cursor.finish_block(&stale, &c, &nodes(&same), &same_reports));
    assert_eq!(cursor, before);
}
#[test]
fn throughput_entire_pages_and_full_reports_are_required() {
    let (s, c, b, r) = fixture(2, 10);
    for (j, page) in b.iter().enumerate() {
        for word in 0..512 {
            let mut bad = page.clone();
            bad.journal[word] ^= 1;
            assert!(!batch(&s, j, &c, &bad));
        }
    }
    let cursor = prefix(10, 2);
    let n = nodes(&b);
    for field in 0..13 {
        let mut bad = r.clone();
        let row = &mut bad[0];
        match field {
            0 => row.admission.generation -= 1,
            1 => row.admission.function = FunctionId(2),
            2 => row.admission.slot = 20,
            3 => row.admission.entry += 1,
            4 => {
                row.terminal = Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::Retained { rank: 20 },
                })
            }
            5 => {
                row.terminal = Some(Terminal::Completed {
                    value: n[0].raw.end.ticks,
                    disposition: Disposition::Retained { rank: 0 },
                })
            }
            6 => row.payload = None,
            7 => row.payload.as_mut().unwrap().admission.entry += 1,
            8 => row.payload.as_mut().unwrap().thread = 2,
            9 => row.payload.as_mut().unwrap().sequence = 0,
            10 => {
                row.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Value(n[0].raw.end.ticks),
                    completed_children: 0,
                }
            }
            11 => {
                row.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                    end: Observation::Unavailable(1),
                    completed_children: 1,
                }
            }
            12 => row.terminal = None,
            _ => unreachable!(),
        }
        let mut probe = cursor;
        assert!(!probe.finish_block(&s, &c, &n, &bad));
        assert_eq!(probe, cursor);
    }
    let mut probe = cursor;
    assert!(!probe.finish_block(&s, &c, &n, &r[..19]));
    assert_eq!(probe, cursor);
}
#[test]
fn throughput_cross_block_clock_and_cursor_prefix_are_transactional() {
    let (s, c, b, r) = fixture(1, 1);
    let n = nodes(&b);
    let cursor = prefix(1, 1);
    let mut probe = cursor;
    let mut skipped = s;
    skipped.block = 2;
    assert!(!probe.finish_block(&skipped, &c, &n, &r));
    assert_eq!(probe, cursor);
    for field in 0..4 {
        let mut bad = n.clone();
        match field {
            0 => {
                for row in &mut bad {
                    row.raw.start.aux += 1;
                    row.raw.end.aux += 1;
                }
            }
            1 => bad[0].raw.start.ticks = 2399,
            2 => bad[1].raw.start.ticks = bad[0].raw.start.ticks - 1,
            3 => bad[1].raw.end.ticks = bad[0].raw.end.ticks + 1,
            _ => unreachable!(),
        }
        let mut probe = cursor;
        assert!(!probe.finish_block(&s, &c, &bad, &r));
        assert_eq!(probe, cursor);
    }
    let mut probe = cursor;
    assert!(probe.finish_block(&s, &c, &n, &r));
    assert_eq!(probe.blocks(), 2);
    assert!(!probe.finish_block(&s, &c, &n, &r));
    assert_eq!(probe.blocks(), 2);
}
#[test]
fn throughput_actual_call_anchors_scalar_stack_and_closed_rows() {
    let (s, c, b, r) = fixture(1, 1);
    let n = nodes(&b);
    let cursor = prefix(1, 1);
    let mut bad = c.clone();
    bad[0].value ^= 1;
    let mut probe = cursor;
    assert!(!probe.finish_block(&s, &bad, &n, &r));
    let mut bad = n.clone();
    bad[1].rsp += 16;
    bad[1].resume_rsp += 16;
    let mut probe = cursor;
    assert!(!probe.finish_block(&s, &c, &bad, &r));
    for field in 0..4 {
        let mut bad = n.clone();
        match field {
            0 => {
                bad[2].raw.owner = RawIntervalOwner::Sampled {
                    generation: s.generation,
                    invocation: 2,
                }
            }
            1 => bad[2].sequence = Some(4),
            2 => bad[2].children = Some(1),
            3 => bad[2].parent = Some((25, 0)),
            _ => unreachable!(),
        }
        let mut probe = cursor;
        assert!(!probe.finish_block(&s, &c, &bad, &r));
    }
}
