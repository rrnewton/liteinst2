//! Independent worker cursors and complete shared admission/retention joins.
use super::*;
use rapid_profiler::frontend_native::{HistoryStream, NormalRecord};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Cursor {
    pub totals: NormalTotals,
    pub batches: u64,
    accepted: Vec<usize>,
    seen: usize,
    prefix: u64,
}
struct Joined {
    id: u64,
    worker: usize,
    record: NormalRecord,
    sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Counts {
    pub admitted: usize,
    pub retained: usize,
    pub dropped: usize,
}
pub(super) struct Ledger {
    pub accepted: Vec<Command>,
    pub local: [Cursor; 2],
    pub flushes: usize,
    pub calls: usize,
    records: Vec<Joined>,
    slots: BTreeMap<(u64, usize), usize>,
    tids: [u64; 2],
    entry: u64,
    returns: BTreeSet<u64>,
    stream: HistoryStream,
    k: usize,
}
impl Ledger {
    pub fn new(
        tids: [u64; 2],
        entry: u64,
        returns: BTreeSet<u64>,
        stream: HistoryStream,
        k: usize,
    ) -> Self {
        assert!(tids[0] != 0 && tids[1] != 0 && tids[0] != tids[1]);
        assert_eq!(returns, [entry + 34, entry + 40].into());
        Self {
            accepted: Vec::with_capacity(protocol::COMMANDS),
            local: std::array::from_fn(|_| Cursor::default()),
            flushes: 0,
            calls: 0,
            records: Vec::with_capacity(protocol::COMMANDS),
            slots: BTreeMap::new(),
            tids,
            entry,
            returns,
            stream,
            k,
        }
    }
    pub fn prefixes(&self) -> [u64; 2] {
        self.local.each_ref().map(|c| c.accepted.len() as u64)
    }
    pub fn accept(&mut self, command: Command) -> Pending {
        assert!(self.accepted.len() < protocol::COMMANDS);
        let pending = match &command {
            Command::Call { id, bound, bytes } => {
                let worker = self.calls % 2;
                self.local[worker].accepted.push(self.accepted.len());
                self.calls += 1;
                Pending::Call {
                    worker,
                    command: Command::Call {
                        id: *id,
                        bound: *bound,
                        bytes: bytes.clone(),
                    },
                }
            }
            Command::Flush { id } => Pending::Flush(Barrier::new(Some(*id), self.prefixes())),
            Command::Stop => panic!("STOP is not an accepted request"),
        };
        self.accepted.push(command);
        pending
    }
    pub fn batch(
        &mut self,
        worker: usize,
        calls: Vec<worker::Call>,
        batch: NormalBatch,
        history: &[HistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        assert!(worker < 2);
        assert_eq!(batch.history_stream(), Some(&self.stream));
        let high = batch.history_high_water().expect("streaming batch");
        assert!(high <= history.last().expect("initial arm history").range().end);
        identity(
            worker,
            self.tids,
            [
                batch.pid() as u64,
                batch.tid(),
                batch.registration(),
                batch.install(),
                batch.function().0,
            ],
        );
        let local = &mut self.local[worker];
        assert_eq!(batch.number(), local.batches + 1);
        assert_eq!(batch.totals().0, local.totals);
        assert!(!calls.is_empty() && calls.len() <= 4);
        assert_eq!(batch.records().len(), calls.len());
        journal(batch.records(), batch.journal(), self.tids[worker]);
        let before = local.totals.completed;
        for (i, (call, record)) in calls.iter().zip(batch.records()).enumerate() {
            let index = *local.accepted.get(local.seen).expect("accepted local call");
            assert_eq!(
                self.accepted.get(index),
                Some(&Command::Call {
                    id: call.id,
                    bound: call.bound,
                    bytes: call.bytes.clone()
                })
            );
            assert_eq!(call.value, scalar(&call.bytes, call.bound));
            let raw = record.raw;
            assert_eq!(raw.ordinal, local.totals.confirmed + 1);
            assert_eq!(raw.entry_pc, self.entry);
            assert!(self.returns.contains(&raw.return_pc));
            assert_eq!(
                raw.return_pc - self.entry,
                if call.bound != 0 && call.value == call.bound as u64 {
                    40
                } else {
                    34
                }
            );
            assert_eq!(record.entry_rsp & 15, 8);
            assert_ne!(record.return_word, 0);
            acknowledgement(*record, i + 1 == calls.len());
            let prefix = record.history_prefix;
            assert!(prefix >= local.prefix && prefix <= high);
            local.prefix = prefix;
            let binding = history
                .iter()
                .rev()
                .find_map(|h| {
                    assert_eq!(h.stream(), &self.stream);
                    h.binding_at(prefix)
                })
                .expect("retained exact entry history");
            let (label, generation, invocation) = owner(raw.owner, binding, prefix);
            if let RawIntervalOwner::Sampled {
                generation,
                invocation,
            } = raw.owner
            {
                assert!(invocation < protocol::COMMANDS);
                assert!(
                    self.slots
                        .insert((generation, invocation), self.records.len())
                        .is_none(),
                    "unique global admission slot"
                );
            }
            self.records.push(Joined {
                id: call.id,
                worker,
                record: *record,
                sequence: local.totals.completed,
            });
            local.totals.entered += 1;
            local.totals.ret_observed += 1;
            local.totals.confirmed += 1;
            local.totals.completed += u64::from(label == "sampled");
            local.totals.unsampled += u64::from(label != "sampled");
            local.seen += 1;
            io.emit(format!(
                "RESULT,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                call.id,
                worker + 1,
                worker + 1,
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
                if i + 1 == calls.len() {
                    "checkpoint"
                } else {
                    "next"
                },
                raw.start.ticks,
                raw.end.ticks,
                raw.start.aux,
                raw.end.aux,
                batch.number()
            ))?;
        }
        assert_eq!(batch.totals().1, local.totals);
        assert_eq!(
            batch.completed_sequences(),
            (before, local.totals.completed)
        );
        assert_eq!(batch.next_ordinal(), local.totals.confirmed + 1);
        local.batches += 1;
        Ok(())
    }
    pub fn flushed(&mut self, id: u64, io: &mut Io) -> Result<(), String> {
        assert!(self.accepted.contains(&Command::Flush { id }));
        self.flushes += 1;
        io.emit(format!(
            "FLUSHED,{id},{},{},{},{},{},{}\n",
            self.local[0].totals.confirmed,
            self.local[1].totals.confirmed,
            self.local[0].batches,
            self.local[1].batches,
            self.local[0].totals.completed,
            self.local[1].totals.completed
        ))
    }
    pub fn totals(&self, worker: usize, totals: NormalTotals) {
        assert!(worker < 2);
        assert_eq!(totals, self.local[worker].totals);
        assert_eq!(totals.entered, totals.ret_observed);
        assert_eq!(totals.ret_observed, totals.confirmed);
        assert_eq!(totals.confirmed, totals.completed + totals.unsampled);
    }
    pub fn finish(
        &self,
        reports: &[(u64, Vec<RecordObservation>)],
        io: &mut Io,
    ) -> Result<Counts, String> {
        assert_eq!(self.records.len(), self.calls);
        assert_eq!(self.calls + self.flushes, self.accepted.len());
        for c in &self.local {
            assert_eq!(c.seen, c.accepted.len());
            assert_eq!(c.totals.confirmed as usize, c.seen);
        }
        let mut reported = BTreeSet::new();
        let mut generations = BTreeMap::new();
        let mut sum = Counts {
            admitted: 0,
            retained: 0,
            dropped: 0,
        };
        for (generation, rows) in reports {
            let counts = report(*generation, rows, self.k);
            assert!(generations.insert(*generation, counts).is_none());
            sum.admitted += counts.admitted;
            sum.retained += counts.retained;
            sum.dropped += counts.dropped;
            for row in rows {
                let a = row.record.admission;
                assert!(reported.insert((*generation, a.invocation)));
                let joined = &self.records[*self
                    .slots
                    .get(&(*generation, a.invocation))
                    .expect("Report has actual request")];
                let (disposition, rank, end) = sample(
                    row,
                    joined.record.raw,
                    joined.worker as u64 + 1,
                    joined.sequence,
                );
                let (kind, value) = match end {
                    Observation::Value(n) => ("value", n),
                    Observation::Unavailable(n) => ("unavailable", n),
                };
                io.emit(format!(
                    "SAMPLE,{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    joined.id,
                    joined.worker + 1,
                    joined.worker + 1,
                    generation,
                    a.invocation,
                    a.entry_value,
                    joined.sequence,
                    disposition,
                    rank,
                    a.invocation,
                    kind,
                    value
                ))?;
            }
        }
        assert_eq!(reported.len(), self.slots.len());
        assert_eq!(
            sum.admitted as u64,
            self.local.iter().map(|c| c.totals.completed).sum::<u64>()
        );
        for joined in &self.records {
            match joined.record.raw.owner {
                RawIntervalOwner::Sampled {
                    generation,
                    invocation,
                } => assert!(reported.contains(&(generation, invocation))),
                RawIntervalOwner::FunctionClosed { generation } => {
                    closed_budget(generation, &generations, self.k)
                }
                RawIntervalOwner::InitialDisarmed | RawIntervalOwner::Removed { .. } => (),
            }
        }
        assert_eq!(sum.admitted, sum.retained + sum.dropped);
        assert_eq!(
            self.calls as u64,
            sum.admitted as u64 + self.local.iter().map(|c| c.totals.unsampled).sum::<u64>()
        );
        Ok(sum)
    }
}
fn closed_budget(generation: u64, reports: &BTreeMap<u64, Counts>, k: usize) {
    assert_eq!(
        reports
            .get(&generation)
            .expect("closed owner Report")
            .retained,
        k
    );
}
fn identity(worker: usize, tids: [u64; 2], actual: [u64; 5]) {
    assert!(worker < 2);
    assert_eq!(
        actual,
        [
            u64::from(std::process::id()),
            tids[worker],
            worker as u64 + 1,
            INSTALL,
            FUNCTION.0
        ]
    );
}
fn acknowledgement(record: NormalRecord, last: bool) {
    assert_eq!(
        record.acknowledgement,
        if last {
            NormalAcknowledgement::CallerCheckpoint
        } else {
            NormalAcknowledgement::NextEntry {
                ordinal: record.raw.ordinal + 1,
            }
        }
    );
}
fn owner(
    owner: RawIntervalOwner,
    binding: HistoryBinding,
    prefix: u64,
) -> (&'static str, u64, u64) {
    match owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => {
            published(binding, prefix, generation);
            ("sampled", generation, invocation as u64 + 1)
        }
        RawIntervalOwner::FunctionClosed { generation } => {
            published(binding, prefix, generation);
            ("closed", generation, 0)
        }
        RawIntervalOwner::Removed { generation } => {
            assert!(
                matches!(binding, HistoryBinding::Removed { action_index, generation: g } if action_index < prefix && g.get() == generation)
            );
            ("removed", generation, 0)
        }
        RawIntervalOwner::InitialDisarmed => {
            assert_eq!(binding, HistoryBinding::Initial);
            ("initial", 0, 0)
        }
    }
}
fn published(binding: HistoryBinding, prefix: u64, generation: u64) {
    assert!(
        matches!(binding, HistoryBinding::Published { action_index, generation: g } if action_index < prefix && g.get() == generation)
    );
}
fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}
// All admissions appear in a final Report, including dropped payloads. Slot and
// retained-rank are independently contiguous sets, never receive-order counters.
pub(super) fn report(generation: u64, rows: &[RecordObservation], k: usize) -> Counts {
    assert_ne!(generation, 0);
    assert!(rows.len() <= protocol::COMMANDS);
    let mut slots = BTreeSet::new();
    let mut ranks = BTreeSet::new();
    let mut dropped = 0;
    for row in rows {
        let a = row.record.admission;
        assert_eq!(a.generation.get(), generation);
        assert_eq!(a.function, FUNCTION);
        assert!(slots.insert(a.invocation));
        let disposition = match row.record.terminal {
            Some(Terminal::Completed { value, disposition }) => {
                assert_eq!(value, a.invocation as u64);
                disposition
            }
            _ => panic!("cancelled/unfinished Report"),
        };
        assert!(row.payload.is_some());
        match disposition {
            Disposition::Retained { rank } => assert!(ranks.insert(rank)),
            Disposition::DroppedAfterBudget => dropped += 1,
        }
    }
    assert_eq!(slots, (0..rows.len()).collect());
    let retained = rows.len().min(k);
    assert_eq!(ranks, (0..retained).collect());
    assert_eq!(dropped, rows.len() - retained);
    Counts {
        admitted: rows.len(),
        retained,
        dropped,
    }
}
fn sample(
    row: &RecordObservation,
    raw: RawInterval,
    registration: u64,
    sequence: u64,
) -> (&'static str, u64, Observation) {
    let a = row.record.admission;
    assert_eq!(
        raw.owner,
        RawIntervalOwner::Sampled {
            generation: a.generation.get(),
            invocation: a.invocation
        }
    );
    assert_eq!(a.function, FUNCTION);
    assert_eq!(a.entry_value, raw.start.ticks);
    let (disposition, rank) = match row.record.terminal {
        Some(Terminal::Completed { value, disposition }) => {
            assert_eq!(value, a.invocation as u64);
            match disposition {
                Disposition::Retained { rank } => ("retained", rank as u64 + 1),
                Disposition::DroppedAfterBudget => ("dropped", 0),
            }
        }
        _ => panic!("complete Report required"),
    };
    let payload = row.payload.expect("complete returned admission");
    assert_eq!(payload.admission, a);
    assert_eq!(payload.thread, registration);
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
    (disposition, rank, end)
}
fn journal(records: &[NormalRecord], page: &[u64], tid: u64) {
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
mod tests;
