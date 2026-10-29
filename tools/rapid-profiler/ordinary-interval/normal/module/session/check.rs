//! Complete accepted population and function-aware absolute-history accounting.
use super::*;
use rapid_profiler::frontend_native::{
    HistoryBinding, NormalModuleHistoryBatch, NormalModuleHistoryStream, NormalModuleRecord,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::normal) struct Metadata<const N: usize = 2> {
    pub(in crate::normal) identity: CodeIdentity,
    pub(in crate::normal) functions: [FunctionId; N],
    pub(in crate::normal) entries: [u64; N],
    pub(in crate::normal) pid: u32,
    pub(in crate::normal) tid: u64,
    pub(in crate::normal) registration: u64,
    pub(in crate::normal) install: u64,
    pub(in crate::normal) number: u64,
    pub(in crate::normal) totals: (NormalTotals, NormalTotals),
    pub(in crate::normal) sequences: (u64, u64),
    pub(in crate::normal) next: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::normal) struct Generation<const N: usize = 2> {
    pub(in crate::normal) id: u64,
    pub(in crate::normal) slots: usize,
    pub(in crate::normal) counts: [usize; N],
}
#[derive(Clone, Copy)]
pub(in crate::normal) struct Seen {
    pub(in crate::normal) id: u64,
    pub(in crate::normal) row: NormalModuleRecord,
    pub(in crate::normal) sequence: u64,
    pub(in crate::normal) rank: Option<usize>,
}
pub(in crate::normal) struct Population<const N: usize = 2> {
    pub accepted: Vec<Arc<input::Record>>,
    pub rows: Vec<Seen>,
    pub totals: NormalTotals,
    pub batches: u64,
    pub(in crate::normal) generations: Vec<Generation<N>>,
    pub(in crate::normal) entries: [u64; N],
    pub(in crate::normal) ends: [u64; N],
    pub(in crate::normal) returns: [Vec<u64>; N],
    pub(in crate::normal) identity: Option<worker::Identity>,
    pub(in crate::normal) k: usize,
    pub(in crate::normal) epoch_limit: usize,
}
pub(super) struct Ledger {
    pub population: Population,
    stream: NormalModuleHistoryStream,
    calls: Vec<worker::Call>,
    journals: Vec<[u64; 512]>,
}
impl Ledger {
    pub(super) fn new(
        stream: NormalModuleHistoryStream,
        entries: [u64; 2],
        ends: [u64; 2],
        returns: [Vec<u64>; 2],
        k: usize,
        epochs: usize,
    ) -> Self {
        assert!(matches!(k, 10 | 1000) && (1..=520).contains(&epochs));
        assert_eq!(stream.functions(), &FUNCTIONS);
        assert_eq!(stream.entries(), &entries);
        assert_eq!(stream.identity(), identity(entries[0]));
        assert_eq!(stream.install(), INSTALL);
        assert_eq!(stream.pid(), std::process::id());
        Self {
            population: Population {
                accepted: Vec::with_capacity(input::RECORDS),
                rows: Vec::with_capacity(input::RECORDS * 2),
                totals: NormalTotals::default(),
                batches: 0,
                generations: Vec::with_capacity(epochs),
                entries,
                ends,
                returns,
                identity: None,
                k,
                epoch_limit: epochs,
            },
            stream,
            calls: Vec::with_capacity(input::RECORDS * 2),
            journals: Vec::with_capacity(input::RECORDS),
        }
    }
    pub(super) fn ready(&mut self, id: worker::Identity) {
        assert_eq!(id.pid, self.stream.pid());
        self.population.ready(id);
    }
    pub(super) fn accept(&mut self, record: &Arc<input::Record>) {
        self.population.accept(record);
    }

    pub(super) fn batch(
        &mut self,
        calls: Vec<worker::Call>,
        batch: NormalModuleBatch,
        history: &[NormalModuleHistoryBatch],
        io: &mut shared::io::Io,
    ) -> Result<(), String> {
        assert_eq!(batch.history_stream(), Some(&self.stream));
        let high = batch
            .history_high_water()
            .expect("absolute module history stamp");
        let meta = Metadata {
            identity: batch.identity(),
            functions: *batch.functions(),
            entries: *batch.entries(),
            pid: batch.pid(),
            tid: batch.tid(),
            registration: batch.registration(),
            install: batch.install(),
            number: batch.number(),
            totals: batch.totals(),
            sequences: batch.completed_sequences(),
            next: batch.next_ordinal(),
        };
        assert_eq!(calls.len(), batch.records().len());
        assert!(!calls.is_empty() && calls.len() <= 4 && calls.len() % 2 == 0);
        let bindings: Vec<_> = batch
            .records()
            .iter()
            .map(|r| {
                assert!(r.record.history_prefix <= high);
                assert!(high <= history.last().unwrap().range().end);
                history
                    .iter()
                    .rev()
                    .find_map(|h| {
                        assert_eq!(h.stream(), &self.stream);
                        h.binding_at(r.record.history_prefix)
                    })
                    .expect("retained complete history covers every original entry")
            })
            .collect();
        // Retain actual returned values/guard owners before any assertion/output.
        let call_start = self.calls.len();
        assert!(call_start + calls.len() <= input::RECORDS * 2);
        self.calls.extend(calls);
        self.journals
            .push(batch.journal().try_into().expect("full512word journal"));
        // Validate actual outputs against every retained accepted byte before raw joins.
        for (i, call) in self.calls[call_start..].iter().enumerate() {
            call.check();
            let ordinal = self.population.rows.len() + i;
            assert_eq!(call.function, ordinal % 2);
            let accepted = &self.population.accepted[ordinal / 2];
            assert_eq!(call.record.as_ref(), accepted.as_ref());
            assert!(Arc::ptr_eq(&call.record, accepted));
        }
        let start = self.population.rows.len();
        self.population
            .join(meta, batch.records(), batch.journal(), &bindings);
        for seen in &self.population.rows[start..] {
            let r = seen.row.record;
            let raw = r.raw;
            let f = index(seen.row.function);
            let (label, generation, invocation) = owner_wire(raw.owner);
            let (ack, ack_ordinal) = match r.acknowledgement {
                NormalAcknowledgement::CallerCheckpoint => ("checkpoint", 0),
                NormalAcknowledgement::NextEntry { ordinal } => ("next", ordinal),
            };
            io.emit(format!(
                "CALL,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                seen.id,
                seen.row.function.0,
                raw.ordinal,
                label,
                generation,
                invocation,
                r.history_prefix,
                raw.return_pc - self.population.entries[f],
                r.entry_rsp,
                r.return_word,
                raw.start.ticks,
                raw.end.ticks,
                raw.start.aux,
                raw.end.aux,
                ack,
                ack_ordinal,
                self.population.batches,
                seen.sequence
            ))?;
            if f == 1 {
                let a = &self.population.accepted[(seen.id - 1) as usize];
                io.emit(format!(
                    "RESULT,{},{},{},{},{},{},{}\n",
                    a.id,
                    a.length,
                    a.checksum(),
                    a.fields,
                    a.length,
                    raw.ordinal - 1,
                    raw.ordinal
                ))?;
            }
        }
        Ok(())
    }
    pub(super) fn finish(
        &self,
        totals: NormalTotals,
        reports: &[(u64, Vec<RecordObservation>)],
        io: &mut shared::io::Io,
    ) -> Result<(), String> {
        assert_eq!(totals, self.population.totals);
        assert_eq!(
            self.population.rows.len(),
            self.population.accepted.len() * 2
        );
        assert_eq!(totals.entered, totals.ret_observed);
        assert_eq!(totals.confirmed, totals.entered);
        assert_eq!(totals.confirmed, totals.completed + totals.unsampled);
        let mut reported = BTreeSet::new();
        let mut generations = BTreeSet::new();
        for (generation, records) in reports {
            assert!(generations.insert(*generation));
            report_shape(*generation, records, self.population.k * 2);
            for observed in records {
                let a = observed.record.admission;
                assert!(reported.insert((*generation, a.invocation)));
                let seen = self
                    .population
                    .rows
                    .iter()
                    .find(|s| {
                        s.row.record.raw.owner
                            == RawIntervalOwner::Sampled {
                                generation: *generation,
                                invocation: a.invocation,
                            }
                    })
                    .expect("Report row has exactly one actual call");
                let end = sample(observed, *seen);
                let (kind, value) = match end {
                    Observation::Value(n) => ("value", n),
                    Observation::Unavailable(n) => ("unavailable", n),
                };
                io.emit(format!(
                    "SAMPLE,{},{},{},{},{},{},{},{},{}\n",
                    seen.id,
                    a.function.0,
                    generation,
                    a.invocation,
                    seen.rank.unwrap(),
                    seen.sequence,
                    a.entry_value,
                    kind,
                    value
                ))?;
            }
        }
        assert_eq!(reported.len() as u64, totals.completed);
        for seen in &self.population.rows {
            if let RawIntervalOwner::Sampled {
                generation,
                invocation,
            } = seen.row.record.raw.owner
            {
                assert!(reported.contains(&(generation, invocation)));
            }
        }
        assert_eq!(self.calls.len(), self.population.rows.len());
        assert_eq!(self.journals.len() as u64, self.population.batches);
        for call in &self.calls {
            call.check();
        }
        for a in &self.population.accepted {
            a.check();
        }
        for (f, function) in FUNCTIONS.iter().enumerate() {
            let mut counts = [0u64; 4];
            let mut mask = 0u64;
            for s in self
                .population
                .rows
                .iter()
                .filter(|s| s.row.function == *function)
            {
                counts[match s.row.record.raw.owner {
                    RawIntervalOwner::Sampled { .. } => 0,
                    RawIntervalOwner::FunctionClosed { .. } => 1,
                    RawIntervalOwner::InitialDisarmed => 2,
                    RawIntervalOwner::Removed { .. } => 3,
                }] += 1;
                mask |= 1
                    << self.population.returns[f]
                        .iter()
                        .position(|&pc| pc == s.row.record.raw.return_pc)
                        .unwrap();
            }
            assert_eq!(
                counts.iter().sum::<u64>(),
                self.population.accepted.len() as u64
            );
            io.emit(format!(
                "COVERAGE,{},{},{},{},{},{},{},{}\n",
                function.0,
                self.population.accepted.len(),
                counts[0],
                counts[1],
                counts[2],
                counts[3],
                self.population.returns[f].len(),
                mask
            ))?;
        }
        Ok(())
    }
    pub(super) fn history_reports(
        &self,
        history: &[NormalModuleHistoryBatch],
        reports: &[(u64, Vec<RecordObservation>)],
    ) {
        let publications: Vec<_> = history
            .iter()
            .flat_map(|h| {
                assert_eq!(h.stream(), &self.stream);
                h.actions()
            })
            .filter(|a| a.kind == rapid_profiler::frontend::ActionKind::Published)
            .map(|a| a.generation.get())
            .collect();
        assert_eq!(publications.len(), reports.len());
        for generation in publications {
            assert_eq!(reports.iter().filter(|r| r.0 == generation).count(), 1);
        }
    }
}
impl<const N: usize> Population<N> {
    pub(in crate::normal) fn ready(&mut self, id: worker::Identity) {
        assert!(self.identity.replace(id).is_none());
        assert_ne!(id.pid, 0);
        assert_ne!(id.tid, u64::from(id.pid));
        assert!(id.stack.0 < id.stack.1 && id.caller.0 < id.caller.1);
        for f in 0..N {
            assert!(self.entries[f] < self.ends[f]);
            assert!((1..=4).contains(&self.returns[f].len()));
            assert!(self.returns[f].windows(2).all(|w| w[0] < w[1]));
            assert!(
                self.returns[f]
                    .iter()
                    .all(|&pc| self.entries[f] < pc && pc < self.ends[f])
            );
        }
    }
    pub(in crate::normal) fn accept(&mut self, record: &Arc<input::Record>) {
        assert!(self.accepted.len() < input::RECORDS);
        record.check();
        assert_eq!(record.id, self.accepted.len() as u64 + 1);
        self.accepted.push(Arc::clone(record));
    } // Accessor projection used by production above and fabricated corruption controls.
    pub(in crate::normal) fn accept_with_limit(
        &mut self,
        record: &Arc<input::Record>,
        limit: usize,
    ) {
        assert!((1..=input::RECORDS).contains(&limit) && self.accepted.len() < limit);
        self.accept(record);
    }
    pub(in crate::normal) fn join_for(
        &mut self,
        m: Metadata<N>,
        rows: &[NormalModuleRecord],
        journal: &[u64],
        bindings: &[HistoryBinding],
        functions: [FunctionId; N],
    ) {
        let id = self.identity.unwrap();
        assert_eq!(
            (m.identity, m.functions, m.entries),
            (identity(self.entries[0]), functions, self.entries)
        );
        assert_eq!(
            (m.pid, m.tid, m.registration, m.install),
            (id.pid, id.tid, 1, INSTALL)
        );
        assert_eq!(m.number, self.batches + 1);
        assert_eq!(m.totals.0, self.totals);
        assert!(!rows.is_empty() && rows.len() <= 4 && rows.len() % N == 0);
        assert_eq!(bindings.len(), rows.len());
        let copied: [rapid_profiler::frontend_native::NormalRecord; 4] =
            std::array::from_fn(|i| rows[i.min(rows.len() - 1)].record);
        shared::check::check_journal(&copied[..rows.len()], journal, id.tid);
        let before = self.totals.completed;
        for (i, row) in rows.iter().enumerate() {
            let ordinal = self.totals.confirmed + 1;
            let f = ((ordinal - 1) % N as u64) as usize;
            let r = row.record;
            let raw = r.raw;
            let accepted = self
                .accepted
                .get((ordinal as usize - 1) / N)
                .expect("no unaccepted physical call");
            assert_eq!(row.function, functions[f]);
            assert_eq!(raw.ordinal, ordinal);
            assert!(
                self.rows
                    .last()
                    .is_none_or(|last| last.row.record.history_prefix <= r.history_prefix)
            );
            assert_eq!(raw.entry_pc, self.entries[f]);
            assert!(self.returns[f].contains(&raw.return_pc));
            assert_eq!(r.entry_rsp % 16, 8);
            assert!(
                r.entry_rsp
                    .checked_sub(128)
                    .is_some_and(|a| a >= id.stack.0)
            );
            assert!(r.entry_rsp.checked_add(8).is_some_and(|b| b <= id.stack.1));
            assert!(id.caller.0 <= r.return_word && r.return_word < id.caller.1);
            assert_eq!(
                r.acknowledgement,
                if i + 1 == rows.len() {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: ordinal + 1,
                    }
                }
            );
            let rank = owner_for(
                raw.owner,
                f,
                r.history_prefix,
                bindings[i],
                &mut self.generations,
                self.k,
                self.epoch_limit,
            );
            self.rows.push(Seen {
                id: accepted.id,
                row: *row,
                sequence: self.totals.completed,
                rank,
            });
            self.totals.entered += 1;
            self.totals.ret_observed += 1;
            self.totals.confirmed += 1;
            self.totals.completed += u64::from(rank.is_some());
            self.totals.unsampled += u64::from(rank.is_none());
        }
        assert_eq!(m.totals.1, self.totals);
        assert_eq!(m.sequences, (before, self.totals.completed));
        assert_eq!(m.next, self.totals.confirmed + 1);
        self.batches += 1;
    }
}
impl Population {
    fn join(
        &mut self,
        m: Metadata,
        rows: &[NormalModuleRecord],
        journal: &[u64],
        bindings: &[HistoryBinding],
    ) {
        self.join_for(m, rows, journal, bindings, FUNCTIONS);
    }
}

fn index(function: FunctionId) -> usize {
    FUNCTIONS
        .iter()
        .position(|&f| f == function)
        .expect("authenticated function tag")
}
pub(in crate::normal) fn owner_wire(owner: RawIntervalOwner) -> (&'static str, u64, u64) {
    match owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => ("sampled", generation, invocation as u64 + 1),
        RawIntervalOwner::FunctionClosed { generation } => ("closed", generation, 0),
        RawIntervalOwner::Removed { generation } => ("removed", generation, 0),
        RawIntervalOwner::InitialDisarmed => ("initial", 0, 0),
    }
}
#[cfg(test)]
fn owner(
    owner: RawIntervalOwner,
    f: usize,
    prefix: u64,
    binding: HistoryBinding,
    generations: &mut Vec<Generation>,
    k: usize,
    limit: usize,
) -> Option<usize> {
    owner_for(owner, f, prefix, binding, generations, k, limit)
}
fn owner_for<const N: usize>(
    owner: RawIntervalOwner,
    f: usize,
    prefix: u64,
    binding: HistoryBinding,
    generations: &mut Vec<Generation<N>>,
    k: usize,
    limit: usize,
) -> Option<usize> {
    match owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => {
            assert!(
                matches!(binding,HistoryBinding::Published{action_index,generation:g}if action_index<prefix&&g.get()==generation)
            );
            let at = match generations.iter().position(|g| g.id == generation) {
                Some(i) => i,
                None => {
                    assert!(generations.len() < limit);
                    generations.push(Generation {
                        id: generation,
                        slots: 0,
                        counts: [0; N],
                    });
                    generations.len() - 1
                }
            };
            let g = &mut generations[at];
            assert_eq!(invocation, g.slots);
            assert!(g.slots < N * k && g.counts[f] < k);
            let rank = g.counts[f];
            g.slots += 1;
            g.counts[f] += 1;
            Some(rank)
        }
        RawIntervalOwner::FunctionClosed { generation } => {
            assert!(
                matches!(binding,HistoryBinding::Published{action_index,generation:g}if action_index<prefix&&g.get()==generation)
            );
            assert_eq!(
                generations
                    .iter()
                    .find(|g| g.id == generation)
                    .map(|g| g.counts[f]),
                Some(k)
            );
            None
        }
        RawIntervalOwner::Removed { generation } => {
            assert!(
                matches!(binding,HistoryBinding::Removed{action_index,generation:g}if action_index<prefix&&g.get()==generation)
            );
            None
        }
        RawIntervalOwner::InitialDisarmed => {
            assert_eq!(prefix, 0);
            assert_eq!(binding, HistoryBinding::Initial);
            None
        }
    }
}
pub(in crate::normal) fn report_shape(
    generation: u64,
    records: &[RecordObservation],
    capacity: usize,
) {
    assert!(generation != 0 && matches!(capacity, 20 | 2000) && records.len() <= capacity);
    report_shape_for(generation, records, capacity, &FUNCTIONS);
}
pub(in crate::normal) fn report_shape_for<const N: usize>(
    generation: u64,
    records: &[RecordObservation],
    capacity: usize,
    functions: &[FunctionId; N],
) {
    assert!((1..=4).contains(&N));
    assert!(
        generation != 0
            && (capacity == N * 10 || capacity == N * 1000)
            && records.len() <= capacity
    );
    let mut ranks = [0; N];
    for (i, row) in records.iter().enumerate() {
        let a = row.record.admission;
        let f = functions
            .iter()
            .position(|&f| f == a.function)
            .expect("authenticated function tag");
        assert_eq!(a.generation.get(), generation);
        assert_eq!(a.invocation, i);
        assert!(ranks[f] < capacity / N);
        assert_eq!(
            row.record.terminal,
            Some(Terminal::Completed {
                value: i as u64,
                disposition: Disposition::Retained { rank: ranks[f] }
            })
        );
        let p = row.payload.expect("complete returned payload");
        assert_eq!(p.admission, a);
        assert_eq!(p.thread, 1);
        assert!(matches!(
            p.outcome,
            PayloadOutcome::Completed {
                completed_children: 0,
                ..
            }
        ));
        ranks[f] += 1;
    }
}
pub(in crate::normal) fn sample(row: &RecordObservation, seen: Seen) -> Observation {
    let a = row.record.admission;
    let raw = seen.row.record.raw;
    assert_eq!(a.function, seen.row.function);
    assert_eq!(
        raw.owner,
        RawIntervalOwner::Sampled {
            generation: a.generation.get(),
            invocation: a.invocation
        }
    );
    assert_eq!(a.entry_value, raw.start.ticks);
    assert_eq!(
        row.record.terminal,
        Some(Terminal::Completed {
            value: a.invocation as u64,
            disposition: Disposition::Retained {
                rank: seen.rank.unwrap()
            }
        })
    );
    let p = row.payload.expect("complete actual returned payload");
    assert_eq!(p.admission, a);
    assert_eq!(p.thread, 1);
    assert_eq!(p.start_sequence, seen.sequence);
    let end = if raw.start.aux != raw.end.aux {
        Observation::Unavailable(1)
    } else if raw.end.ticks < raw.start.ticks {
        Observation::Unavailable(2)
    } else {
        Observation::Value(raw.end.ticks)
    };
    assert_eq!(
        p.outcome,
        PayloadOutcome::Completed {
            end,
            completed_children: 0
        }
    );
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use rapid_profiler::frontend::{Payload, PayloadOutcome};
    use rapid_profiler::frontend_native::{NormalRecord, RawTimestamp};
    use rapid_profiler::generation::{Admission, Epoch, Record};
    fn refuse(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    // Fabricated metadata only. This fixture never constructs a trusted history
    // stream/site or invokes the target/SDK normal attachment path.
    fn fixture() -> (
        Population,
        Metadata,
        [NormalModuleRecord; 2],
        [HistoryBinding; 2],
        rapid_profiler::generation::GenerationId,
    ) {
        let generation = Epoch::new(
            &FUNCTIONS,
            Config {
                retained_per_function: 10,
                max_inflight: 1,
                max_invocations: 20,
            },
        )
        .unwrap()
        .id();
        let mut p = Population {
            accepted: Vec::with_capacity(2048),
            rows: Vec::with_capacity(4096),
            totals: NormalTotals::default(),
            batches: 0,
            generations: Vec::with_capacity(520),
            entries: [0x1000, 0x1080],
            ends: [0x1050, 0x10c0],
            returns: [vec![0x1040], vec![0x10b0]],
            identity: None,
            k: 10,
            epoch_limit: 520,
        };
        p.ready(worker::Identity {
            pid: 11,
            tid: 12,
            cpu: 1,
            stack: (0x8000, 0xa000),
            caller: (0x2000, 0x3000),
        });
        p.accept(&Arc::new(input::Record::new(1, b"a,b").unwrap()));
        let rows = std::array::from_fn(|i| NormalModuleRecord {
            function: FUNCTIONS[i],
            record: NormalRecord {
                raw: RawInterval {
                    ordinal: i as u64 + 1,
                    entry_pc: p.entries[i],
                    return_pc: p.returns[i][0],
                    owner: RawIntervalOwner::Sampled {
                        generation: generation.get(),
                        invocation: i,
                    },
                    start: RawTimestamp { ticks: 0, aux: 3 },
                    end: RawTimestamp { ticks: 0, aux: 3 },
                },
                entry_rsp: 0x9008,
                return_word: 0x2005,
                history_prefix: 513,
                acknowledgement: if i == 0 {
                    NormalAcknowledgement::NextEntry { ordinal: 2 }
                } else {
                    NormalAcknowledgement::CallerCheckpoint
                },
            },
        });
        let meta = Metadata {
            identity: identity(p.entries[0]),
            functions: FUNCTIONS,
            entries: p.entries,
            pid: 11,
            tid: 12,
            registration: 1,
            install: INSTALL,
            number: 1,
            totals: (
                NormalTotals::default(),
                NormalTotals {
                    entered: 2,
                    ret_observed: 2,
                    confirmed: 2,
                    completed: 2,
                    unsampled: 0,
                },
            ),
            sequences: (0, 2),
            next: 3,
        };
        (
            p,
            meta,
            rows,
            [HistoryBinding::Published {
                action_index: 512,
                generation,
            }; 2],
            generation,
        )
    }
    fn journal(rows: &[NormalModuleRecord]) -> [u64; 512] {
        let mut p = [0; 512];
        p[..4].copy_from_slice(&[rows.len() as u64 * 2, 0, 12, 0]);
        for (i, row) in rows.iter().enumerate() {
            let r = row.record;
            let (raw, pre) = (r.raw, r.history_prefix);
            let (kind, g, slot, reason) = match raw.owner {
                RawIntervalOwner::Sampled {
                    generation,
                    invocation,
                } => (1, generation, invocation as u64 + 1, 0),
                RawIntervalOwner::FunctionClosed { generation } => (3, generation, 0, 3),
                RawIntervalOwner::Removed { generation } => (3, generation, 0, 2),
                RawIntervalOwner::InitialDisarmed => (3, 0, 0, 1),
            };
            let bits = slot | ((pre & 511) << 13) | (reason << 22) | ((pre >> 9) << 24);
            let at = 4 + 14 * i;
            p[at..at + 7].copy_from_slice(&[
                kind,
                raw.ordinal,
                raw.entry_pc,
                r.entry_rsp,
                r.return_word,
                g,
                bits,
            ]);
            p[at + 7..at + 14].copy_from_slice(&[
                kind + 1,
                raw.ordinal,
                raw.return_pc,
                r.entry_rsp,
                r.return_word,
                g,
                bits,
            ]);
        }
        p
    }
    fn observation(
        seen: Seen,
        generation: rapid_profiler::generation::GenerationId,
    ) -> RecordObservation {
        let RawIntervalOwner::Sampled { invocation, .. } = seen.row.record.raw.owner else {
            panic!()
        };
        let raw = seen.row.record.raw;
        let a = Admission {
            generation,
            invocation,
            function: seen.row.function,
            entry_value: raw.start.ticks,
        };
        let end = if raw.start.aux != raw.end.aux {
            Observation::Unavailable(1)
        } else if raw.end.ticks < raw.start.ticks {
            Observation::Unavailable(2)
        } else {
            Observation::Value(raw.end.ticks)
        };
        RecordObservation {
            record: Record {
                admission: a,
                terminal: Some(Terminal::Completed {
                    value: invocation as u64,
                    disposition: Disposition::Retained {
                        rank: seen.rank.unwrap(),
                    },
                }),
            },
            payload: Some(Payload {
                admission: a,
                thread: 1,
                start_sequence: seen.sequence,
                outcome: PayloadOutcome::Completed {
                    end,
                    completed_children: 0,
                },
            }),
        }
    }
    #[test]
    fn ordered_module_population_keeps_global_slots_and_function_ranks() {
        let (mut p, m, rows, bindings, g) = fixture();
        p.join(m, &rows, &journal(&rows), &bindings);
        assert_eq!((p.rows[0].rank, p.rows[1].rank), (Some(0), Some(0)));
        assert_eq!((p.rows[0].sequence, p.rows[1].sequence), (0, 1));
        let mut generations = Vec::with_capacity(2);
        let binding = HistoryBinding::Published {
            action_index: 512,
            generation: g,
        };
        for invocation in 0..10 {
            assert_eq!(
                owner(
                    RawIntervalOwner::Sampled {
                        generation: g.get(),
                        invocation
                    },
                    0,
                    513,
                    binding,
                    &mut generations,
                    10,
                    2
                ),
                Some(invocation)
            );
        }
        assert_eq!(
            owner(
                RawIntervalOwner::FunctionClosed {
                    generation: g.get()
                },
                0,
                513,
                binding,
                &mut generations,
                10,
                2
            ),
            None
        );
        assert_eq!(
            owner(
                RawIntervalOwner::Sampled {
                    generation: g.get(),
                    invocation: 10
                },
                1,
                513,
                binding,
                &mut generations,
                10,
                2
            ),
            Some(0)
        );
        assert_eq!(generations[0].counts, [10, 1]);
        assert_eq!(generations[0].slots, 11);
        // One logical record can have two different admitted generations.
        let (mut p, m, mut rows, mut bindings, _) = fixture();
        let other = Epoch::new(
            &FUNCTIONS,
            Config {
                retained_per_function: 10,
                max_inflight: 1,
                max_invocations: 20,
            },
        )
        .unwrap()
        .id();
        rows[1].record.raw.owner = RawIntervalOwner::Sampled {
            generation: other.get(),
            invocation: 0,
        };
        rows[1].record.history_prefix = 514;
        bindings[1] = HistoryBinding::Published {
            action_index: 513,
            generation: other,
        };
        p.join(m, &rows, &journal(&rows), &bindings);
        assert_eq!(p.generations.len(), 2);
    }
    #[test]
    fn complete_population_identity_ack_stack_and_all_journal_words_refuse() {
        for at in 0..512 {
            let (mut p, m, rows, b, _) = fixture();
            let mut words = journal(&rows);
            words[at] ^= 1;
            refuse(|| p.join(m, &rows, &words, &b));
        }
        for choice in 0..9 {
            let (mut p, m, mut rows, b, _) = fixture();
            match choice {
                0 => rows[0].function = FUNCTIONS[1],
                1 => rows[0].record.raw.ordinal = 2,
                2 => rows[0].record.raw.entry_pc += 1,
                3 => rows[0].record.raw.return_pc += 1,
                4 => rows[0].record.entry_rsp = 0x8008,
                5 => rows[0].record.return_word = 0x3000,
                6 => rows[0].record.acknowledgement = NormalAcknowledgement::CallerCheckpoint,
                7 => {
                    rows[1].record.acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 3 }
                }
                _ => {
                    p.accepted.clear();
                }
            }
            refuse(|| p.join(m, &rows, &journal(&rows), &b));
        }
        for choice in 0..8 {
            let (mut p, mut m, rows, b, _) = fixture();
            match choice {
                0 => m.tid += 1,
                1 => m.install += 1,
                2 => m.functions.swap(0, 1),
                3 => m.number += 1,
                4 => m.sequences.0 = 1,
                5 => m.next += 1,
                6 => m.totals.1.unsampled = 1,
                _ => m.identity.mapping += 1,
            }
            refuse(|| p.join(m, &rows, &journal(&rows), &b));
        }
    }
    #[test]
    fn absolute_history_owner_prefix_and_independent_closed_budget_refuse() {
        for choice in 0..5 {
            let (mut p, m, mut rows, mut b, g) = fixture();
            match choice {
                0 => b[0] = HistoryBinding::Initial,
                1 => rows[0].record.history_prefix = 512,
                2 => {
                    rows[0].record.raw.owner = RawIntervalOwner::FunctionClosed {
                        generation: g.get(),
                    }
                }
                3 => {
                    rows[0].record.raw.owner = RawIntervalOwner::Sampled {
                        generation: g.get(),
                        invocation: 1,
                    }
                }
                _ => {
                    rows[0].record.raw.owner = RawIntervalOwner::Removed {
                        generation: g.get(),
                    }
                }
            }
            refuse(|| p.join(m, &rows, &journal(&rows), &b));
        }
        let (mut p, m, mut rows, mut b, g) = fixture();
        rows[0].record.history_prefix = 514;
        b[0] = HistoryBinding::Published {
            action_index: 513,
            generation: g,
        };
        refuse(|| p.join(m, &rows, &journal(&rows), &b));
        let (mut p, mut m, mut rows, mut b, g) = fixture();
        rows[0].record.raw.owner = RawIntervalOwner::InitialDisarmed;
        rows[0].record.history_prefix = 0;
        b[0] = HistoryBinding::Initial;
        rows[1].record.raw.owner = RawIntervalOwner::Removed {
            generation: g.get(),
        };
        rows[1].record.history_prefix = 514;
        b[1] = HistoryBinding::Removed {
            action_index: 513,
            generation: g,
        };
        m.totals.1.completed = 0;
        m.totals.1.unsampled = 2;
        m.sequences = (0, 0);
        p.join(m, &rows, &journal(&rows), &b);
        assert!(p.rows.iter().all(|s| s.rank.is_none()));
    }
    #[test]
    fn report_payloads_keep_function_rank_sequence_and_raw_unavailability() {
        let (mut p, m, rows, b, g) = fixture();
        p.join(m, &rows, &journal(&rows), &b);
        let observations: Vec<_> = p.rows.iter().map(|s| observation(*s, g)).collect();
        report_shape(g.get(), &observations, 20);
        for (seen, observed) in p.rows.iter().zip(&observations) {
            assert_eq!(sample(observed, *seen), Observation::Value(0));
        }
        for choice in 0..6 {
            let mut changed = observations[1];
            match choice {
                0 => changed.record.admission.function = FUNCTIONS[0],
                1 => {
                    changed.record.terminal = Some(Terminal::Completed {
                        value: 1,
                        disposition: Disposition::Retained { rank: 1 },
                    })
                }
                2 => changed.payload.as_mut().unwrap().start_sequence = 0,
                3 => changed.payload.as_mut().unwrap().thread = 2,
                4 => {
                    changed.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                        end: Observation::Value(1),
                        completed_children: 0,
                    }
                }
                _ => changed.payload = None,
            }
            refuse(|| {
                sample(&changed, p.rows[1]);
            });
        }
        for (start, end, aux, outcome) in [
            (u64::MAX, u64::MAX, 3, Observation::Value(u64::MAX)),
            (u64::MAX, 0, 3, Observation::Unavailable(2)),
            (0, 0, u32::MAX, Observation::Unavailable(1)),
        ] {
            let mut seen = p.rows[0];
            seen.row.record.raw.start.ticks = start;
            seen.row.record.raw.end.ticks = end;
            seen.row.record.raw.end.aux = aux;
            assert_eq!(sample(&observation(seen, g), seen), outcome);
        }
        let mut changed = observations;
        changed[1].record.terminal = Some(Terminal::Completed {
            value: 1,
            disposition: Disposition::Retained { rank: 1 },
        });
        refuse(|| report_shape(g.get(), &changed, 20));
    }
}
