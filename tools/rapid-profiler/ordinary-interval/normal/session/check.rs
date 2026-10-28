//! Complete population/owner joins; a timestamp never selects an epoch.
use super::*;
use rapid_profiler::frontend_native::{HistoryBatch, HistoryBinding, HistoryStream, NormalRecord};
use std::collections::BTreeMap;

pub(super) struct Ledger {
    pub accepted: Vec<Command>,
    cursor: usize,
    pub totals: NormalTotals,
    pub batches: u64,
    pub flushes: usize,
    pub records: Vec<(u64, NormalRecord, u64)>,
    tid: u64,
    entry: u64,
    returns: BTreeSet<u64>,
    stream: HistoryStream,
    slots: BTreeMap<u64, usize>,
    k: usize,
}
impl Ledger {
    pub fn new(
        tid: u64,
        entry: u64,
        returns: BTreeSet<u64>,
        stream: HistoryStream,
        k: usize,
    ) -> Self {
        Self {
            accepted: Vec::with_capacity(protocol::COMMANDS),
            cursor: 0,
            totals: NormalTotals::default(),
            batches: 0,
            flushes: 0,
            records: Vec::with_capacity(protocol::COMMANDS),
            tid,
            entry,
            returns,
            stream,
            slots: BTreeMap::new(),
            k,
        }
    }
    pub fn batch(
        &mut self,
        calls: Vec<worker::Call>,
        batch: NormalBatch,
        history: &[HistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        assert_eq!(batch.history_stream(), Some(&self.stream));
        assert!(batch.history_high_water().unwrap() <= history.last().unwrap().range().end);
        assert_eq!(
            (
                batch.pid(),
                batch.tid(),
                batch.registration(),
                batch.install(),
                batch.function()
            ),
            (std::process::id(), self.tid, 1, INSTALL, FUNCTION)
        );
        assert_eq!(batch.number(), self.batches + 1);
        assert_eq!(batch.totals().0, self.totals);
        assert!(!calls.is_empty() && calls.len() <= 4);
        assert_eq!(batch.records().len(), calls.len());
        let count = calls.len();
        check_journal(batch.records(), batch.journal(), self.tid);
        let before = self.totals.completed;
        for (i, (call, record)) in calls.iter().zip(batch.records()).enumerate() {
            assert_eq!(
                self.accepted.get(self.cursor),
                Some(&Command::Call {
                    id: call.id,
                    bound: call.bound,
                    bytes: call.bytes.clone(),
                })
            );
            assert_eq!(call.value, worker::scalar(&call.bytes, call.bound));
            let raw = record.raw;
            owner_slot(raw.owner, &mut self.slots, self.k);
            assert_eq!(raw.ordinal, self.totals.confirmed + 1);
            assert_eq!(raw.entry_pc, self.entry);
            assert!(self.returns.contains(&raw.return_pc));
            assert_eq!(record.entry_rsp & 15, 8);
            assert_ne!(record.return_word, 0);
            assert_eq!(
                record.acknowledgement,
                if i + 1 == count {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: raw.ordinal + 1,
                    }
                }
            );
            let prefix = record.history_prefix;
            assert!(prefix <= batch.history_high_water().unwrap());
            let binding = history
                .iter()
                .rev()
                .find_map(|h| {
                    assert_eq!(h.stream(), &self.stream);
                    h.binding_at(prefix)
                })
                .expect("retained history contains every original entry stamp");
            let (kind, generation, invocation, _reason, label) = match raw.owner {
                RawIntervalOwner::Sampled {
                    generation,
                    invocation,
                } => {
                    assert_published(binding, prefix, generation);
                    (1, generation, invocation as u64 + 1, 0, "sampled")
                }
                RawIntervalOwner::FunctionClosed { generation } => {
                    assert_published(binding, prefix, generation);
                    (3, generation, 0, 3, "closed")
                }
                RawIntervalOwner::Removed { generation } => {
                    assert!(
                        matches!(binding, HistoryBinding::Removed { action_index, generation: g } if action_index < prefix && g.get() == generation)
                    );
                    (3, generation, 0, 2, "removed")
                }
                RawIntervalOwner::InitialDisarmed => {
                    assert_eq!(binding, HistoryBinding::Initial);
                    (3, 0, 0, 1, "initial")
                }
            };
            self.records.push((call.id, *record, self.totals.completed));
            self.totals.entered += 1;
            self.totals.ret_observed += 1;
            self.totals.confirmed += 1;
            self.totals.completed += u64::from(kind == 1);
            self.totals.unsampled += u64::from(kind != 1);
            self.cursor += 1;
            io.emit(format!(
                "RESULT,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                call.id,
                raw.ordinal,
                call.bound,
                call.bytes.len(),
                checksum(&call.bytes),
                call.value,
                label,
                generation,
                invocation,
                prefix,
                raw.return_pc - self.entry,
                if i + 1 == count { "checkpoint" } else { "next" },
                raw.start.ticks,
                raw.end.ticks,
                raw.start.aux,
                raw.end.aux,
                batch.number()
            ))?;
        }
        assert_eq!(batch.totals().1, self.totals);
        assert_eq!(batch.completed_sequences(), (before, self.totals.completed));
        assert_eq!(batch.next_ordinal(), self.totals.confirmed + 1);
        self.batches += 1;
        Ok(())
    }
    pub fn flushed(&mut self, id: u64, totals: NormalTotals, io: &mut Io) -> Result<(), String> {
        assert_eq!(self.accepted.get(self.cursor), Some(&Command::Flush { id }));
        assert_eq!(totals, self.totals);
        self.cursor += 1;
        self.flushes += 1;
        io.emit(format!(
            "FLUSHED,{id},{},{},{}\n",
            self.batches, totals.confirmed, totals.completed
        ))
    }
    pub fn finish(
        &self,
        totals: NormalTotals,
        reports: &[(u64, Vec<RecordObservation>)],
        io: &mut Io,
    ) -> Result<(), String> {
        assert_eq!(totals, self.totals);
        assert_eq!(self.cursor, self.accepted.len());
        assert_eq!(totals.confirmed as usize, self.records.len());
        assert_eq!(self.records.len() + self.flushes, self.accepted.len());
        let mut reported = BTreeSet::new();
        for (generation, rows) in reports {
            for row in rows {
                let admission = row.record.admission;
                assert_eq!(admission.generation.get(), *generation);
                assert!(
                    reported.insert((*generation, admission.invocation)),
                    "duplicate Report row"
                );
                let (id, raw, sequence) = self
                    .records
                    .iter()
                    .find_map(|(id, r, sequence)| {
                        (r.raw.owner
                            == RawIntervalOwner::Sampled {
                                generation: *generation,
                                invocation: admission.invocation,
                            })
                        .then_some((*id, r.raw, *sequence))
                    })
                    .expect("every Report row belongs to one actual request");
                let end = check_sample(row, raw, sequence);
                let (kind, value) = match end {
                    Observation::Value(n) => ("value", n),
                    Observation::Unavailable(n) => ("unavailable", n),
                };
                io.emit(format!(
                    "SAMPLE,{id},{generation},{},{},{sequence},{kind},{value}\n",
                    admission.invocation, admission.entry_value
                ))?;
            }
        }
        assert_eq!(reported.len() as u64, totals.completed);
        for (_, record, _) in &self.records {
            if let RawIntervalOwner::Sampled {
                generation,
                invocation,
            } = record.raw.owner
            {
                assert!(reported.contains(&(generation, invocation)));
            }
        }
        Ok(())
    }
}
fn assert_published(binding: HistoryBinding, prefix: u64, generation: u64) {
    assert!(
        matches!(binding, HistoryBinding::Published { action_index, generation: g } if action_index < prefix && g.get() == generation)
    );
}
// Diagnostic FNV-1a only; exact input equality above, not this checksum, owns the join.
fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn check_sample(row: &RecordObservation, raw: RawInterval, sequence: u64) -> Observation {
    let admission = row.record.admission;
    assert_eq!(
        raw.owner,
        RawIntervalOwner::Sampled {
            generation: admission.generation.get(),
            invocation: admission.invocation
        }
    );
    assert_eq!(admission.function, FUNCTION);
    assert_eq!(admission.entry_value, raw.start.ticks);
    assert_eq!(
        row.record.terminal,
        Some(Terminal::Completed {
            value: admission.invocation as u64,
            disposition: Disposition::Retained {
                rank: admission.invocation
            },
        })
    );
    let payload = row.payload.expect("complete returned sample");
    assert_eq!(payload.admission, admission);
    assert_eq!(payload.thread, 1);
    assert_eq!(payload.start_sequence, sequence);
    let end = if raw.start.aux != raw.end.aux {
        Observation::Unavailable(1)
    } else if raw.end.ticks < raw.start.ticks {
        Observation::Unavailable(2)
    } else {
        Observation::Value(raw.end.ticks)
    };
    assert_eq!(
        payload.outcome,
        PayloadOutcome::Completed {
            end,
            completed_children: 0
        }
    );
    end
}

fn owner_slot(owner: RawIntervalOwner, slots: &mut BTreeMap<u64, usize>, k: usize) {
    match owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => {
            let next = slots.entry(generation).or_default();
            assert_eq!(
                invocation, *next,
                "independent contiguous per-epoch admission"
            );
            assert!(invocation < k);
            *next += 1;
        }
        RawIntervalOwner::FunctionClosed { generation } => {
            assert_eq!(
                slots.get(&generation),
                Some(&k),
                "closed only after K prior samples"
            );
        }
        RawIntervalOwner::InitialDisarmed | RawIntervalOwner::Removed { .. } => (),
    }
}
fn check_journal(records: &[NormalRecord], page: &[u64], tid: u64) {
    assert!(!records.is_empty() && records.len() <= 4);
    assert_eq!(page.len(), 512);
    assert_eq!(&page[..4], &[records.len() as u64 * 2, 0, tid, 0]);
    assert!(page[4 + records.len() * 14..].iter().all(|&n| n == 0));
    for (i, record) in records.iter().enumerate() {
        let raw = record.raw;
        let (kind, generation, invocation, reason) = match raw.owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation,
            } => (1, generation, invocation as u64 + 1, 0),
            RawIntervalOwner::FunctionClosed { generation } => (3, generation, 0, 3),
            RawIntervalOwner::Removed { generation } => (3, generation, 0, 2),
            RawIntervalOwner::InitialDisarmed => (3, 0, 0, 1),
        };
        let prefix = record.history_prefix;
        let bits = invocation | ((prefix & 0x1ff) << 13) | (reason << 22) | ((prefix >> 9) << 24);
        let at = 4 + i * 14;
        assert_eq!(
            &page[at..at + 7],
            &[
                kind,
                raw.ordinal,
                raw.entry_pc,
                record.entry_rsp,
                record.return_word,
                generation,
                bits
            ]
        );
        assert_eq!(
            &page[at + 7..at + 14],
            &[
                kind + 1,
                raw.ordinal,
                raw.return_pc,
                record.entry_rsp,
                record.return_word,
                generation,
                bits
            ]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rapid_profiler::frontend::{Payload, PayloadOutcome};
    use rapid_profiler::frontend_native::RawTimestamp;
    use rapid_profiler::generation::{Admission, Epoch, Record};
    fn refused(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    fn raw() -> RawInterval {
        RawInterval {
            ordinal: 1,
            entry_pc: 0x1000,
            return_pc: 0x1020,
            owner: RawIntervalOwner::Sampled {
                generation: 7,
                invocation: 0,
            },
            start: RawTimestamp { ticks: 100, aux: 3 },
            end: RawTimestamp { ticks: 110, aux: 3 },
        }
    }
    #[test]
    fn coherent_shift_and_premature_closed_cannot_relabel_sample_population() {
        let mut slots = BTreeMap::new();
        refused(|| {
            owner_slot(
                RawIntervalOwner::Sampled {
                    generation: 7,
                    invocation: 1,
                },
                &mut slots,
                2,
            )
        });
        refused(|| {
            owner_slot(
                RawIntervalOwner::FunctionClosed { generation: 7 },
                &mut slots,
                2,
            )
        });
        owner_slot(
            RawIntervalOwner::Sampled {
                generation: 7,
                invocation: 0,
            },
            &mut slots,
            2,
        );
        refused(|| {
            owner_slot(
                RawIntervalOwner::FunctionClosed { generation: 7 },
                &mut slots,
                2,
            )
        });
        owner_slot(
            RawIntervalOwner::Sampled {
                generation: 7,
                invocation: 1,
            },
            &mut slots,
            2,
        );
        owner_slot(
            RawIntervalOwner::FunctionClosed { generation: 7 },
            &mut slots,
            2,
        );
        refused(|| {
            owner_slot(
                RawIntervalOwner::Sampled {
                    generation: 7,
                    invocation: 2,
                },
                &mut slots,
                2,
            )
        });
        assert_eq!(slots[&7], 2);
    }
    #[test]
    fn whole_journal_tail_prefix_and_return_word_corruptions_refuse() {
        let record = NormalRecord {
            raw: raw(),
            entry_rsp: 0x8008,
            return_word: 0x2005,
            history_prefix: 513,
            acknowledgement: NormalAcknowledgement::CallerCheckpoint,
        };
        let mut page = [0; 512];
        page[..18].copy_from_slice(&[
            2, 0, 9, 0, 1, 1, 0x1000, 0x8008, 0x2005, 7, 0x1002001, 2, 1, 0x1020, 0x8008, 0x2005,
            7, 0x1002001,
        ]);
        check_journal(&[record], &page, 9);
        for at in [0, 1, 2, 3, 4, 8, 10, 11, 15, 17, 18, 511] {
            let mut corrupted = page;
            corrupted[at] ^= 1;
            refused(|| check_journal(&[record], &corrupted, 9));
        }
        let mut changed = record;
        changed.history_prefix = 1;
        refused(|| check_journal(&[changed], &page, 9));
        refused(|| check_journal(&[record], &page[..511], 9));
    }
    #[test]
    fn report_payload_sequence_endpoint_and_terminal_are_independently_joined() {
        let epoch = Epoch::new(
            &[FUNCTION],
            Config {
                retained_per_function: 2,
                max_inflight: 1,
                max_invocations: 2,
            },
        )
        .unwrap();
        let generation = epoch.id();
        let admission = Admission {
            generation,
            invocation: 0,
            function: FUNCTION,
            entry_value: 100,
        };
        let row = RecordObservation {
            record: Record {
                admission,
                terminal: Some(Terminal::Completed {
                    value: 0,
                    disposition: Disposition::Retained { rank: 0 },
                }),
            },
            payload: Some(Payload {
                admission,
                thread: 1,
                start_sequence: 4,
                outcome: PayloadOutcome::Completed {
                    end: Observation::Value(110),
                    completed_children: 0,
                },
            }),
        };
        let mut interval = raw();
        interval.owner = RawIntervalOwner::Sampled {
            generation: generation.get(),
            invocation: 0,
        };
        assert_eq!(check_sample(&row, interval, 4), Observation::Value(110));
        for mutation in 0..6 {
            let mut wrong = row;
            match mutation {
                0 => wrong.record.admission.entry_value += 1,
                1 => wrong.record.terminal = None,
                2 => wrong.payload.as_mut().unwrap().start_sequence += 1,
                3 => wrong.payload.as_mut().unwrap().thread = 2,
                4 => {
                    wrong.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                        end: Observation::Value(109),
                        completed_children: 0,
                    }
                }
                5 => wrong.payload = None,
                _ => unreachable!(),
            }
            refused(|| {
                check_sample(&wrong, interval, 4);
            });
        }
        assert_published(
            HistoryBinding::Published {
                action_index: 512,
                generation,
            },
            513,
            generation.get(),
        );
        refused(|| {
            assert_published(
                HistoryBinding::Published {
                    action_index: 512,
                    generation,
                },
                512,
                generation.get(),
            )
        });
        refused(|| {
            assert_published(
                HistoryBinding::Published {
                    action_index: 0,
                    generation,
                },
                1,
                generation.get() + 1,
            )
        });
    }
}
