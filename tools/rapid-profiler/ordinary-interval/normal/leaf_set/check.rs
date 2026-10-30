//! Leaf-set table/stream/actual-call adapters around the shared population engine.
use super::*;
use population::{Metadata, Population, Seen};
use rapid_profiler::frontend_native::NormalLeafSetHistoryStream;
use std::fmt::Write as _;
pub(super) struct Ledger<const N: usize> {
    pub population: Population<N>,
    stream: NormalLeafSetHistoryStream,
    leaves: [Selection; N],
    pub(super) expectations: Expectations<N>,
    calls: Vec<worker::Call>,
    journals: Vec<[u64; 512]>,
}
impl<const N: usize> Ledger<N> {
    pub(super) fn new(
        stream: NormalLeafSetHistoryStream,
        selection: ([Selection; N], Expectations<N>),
        entries: [u64; N],
        ends: [u64; N],
        returns: [Vec<u64>; N],
        k: usize,
        epochs: usize,
    ) -> Self {
        assert!((1..=4).contains(&N) && matches!(k, 10 | 1000) && (1..=520).contains(&epochs));
        assert_eq!(stream.accuracy_policy(), None);
        Self::prepare(stream, selection, entries, ends, returns, k, epochs)
    }
    pub(super) fn new_accuracy(
        stream: NormalLeafSetHistoryStream,
        selection: ([Selection; N], Expectations<N>),
        entries: [u64; N],
        ends: [u64; N],
        returns: [Vec<u64>; N],
        policy: Policy,
    ) -> Self {
        assert!((1..=4).contains(&N) && (1..=520).contains(&policy.epoch_limit()));
        assert_eq!(
            schedule_policy(policy.retained(), policy.epoch_limit(), Some(policy)).unwrap(),
            policy
        );
        assert_eq!(stream.accuracy_policy(), Some(policy));
        Self::prepare(
            stream,
            selection,
            entries,
            ends,
            returns,
            policy.retained(),
            policy.epoch_limit() as usize,
        )
    }
    fn prepare(
        stream: NormalLeafSetHistoryStream,
        selection: ([Selection; N], Expectations<N>),
        entries: [u64; N],
        ends: [u64; N],
        returns: [Vec<u64>; N],
        k: usize,
        epochs: usize,
    ) -> Self {
        let (leaves, expectations) = selection;
        assert_eq!(stream.functions(), &leaves.map(|l| l.function));
        assert_eq!(stream.entries(), &entries);
        assert_eq!(stream.identity(), identity(entries[0]));
        assert_eq!(stream.install(), INSTALL);
        assert_eq!(stream.pid(), std::process::id());
        Self {
            population: Population {
                accepted: Vec::with_capacity(record_cap(N)),
                rows: Vec::with_capacity(record_cap(N) * N),
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
            leaves,
            expectations,
            calls: Vec::with_capacity(record_cap(N) * N),
            journals: Vec::with_capacity(record_cap(N)),
        }
    }
    pub(super) fn ready(&mut self, id: pair_worker::Identity) {
        assert_eq!(id.pid, self.stream.pid());
        self.population.ready(id);
    }
    pub(super) fn accept(&mut self, record: &Arc<input::Record>) -> Result<(), String> {
        // This runs in the controller before the accepted owner can be sent.
        self.expectations.record(record)?;
        self.population.accept_with_limit(record, record_cap(N));
        Ok(())
    }
    pub(super) fn batch(
        &mut self,
        calls: Vec<worker::Call>,
        batch: NormalLeafSetBatch,
        history: &[NormalLeafSetHistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        assert_eq!(batch.history_stream(), &self.stream);
        let high = batch.history_high_water();
        let meta = Metadata {
            identity: batch.identity(),
            functions: batch.functions().try_into().unwrap(),
            entries: batch.entries().try_into().unwrap(),
            pid: batch.pid(),
            tid: batch.tid(),
            registration: batch.registration(),
            install: batch.install(),
            number: batch.number(),
            totals: batch.totals(),
            sequences: batch.completed_sequences(),
            next: batch.next_ordinal(),
        };
        assert_eq!(calls.len(), N);
        assert_eq!(batch.records().len(), N);
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
        let call_start = self.calls.len();
        assert!(call_start + calls.len() <= record_cap(N) * N);
        self.calls.extend(calls);
        self.journals
            .push(batch.journal().try_into().expect("full512word journal"));
        for (i, call) in self.calls[call_start..].iter().enumerate() {
            call.check(N);
            let ordinal = self.population.rows.len() + i;
            assert_eq!(call.inner.function, ordinal % N);
            let accepted = &self.population.accepted[ordinal / N];
            assert_eq!(call.inner.record.as_ref(), accepted.as_ref());
            assert!(Arc::ptr_eq(&call.inner.record, accepted));
            assert_eq!(
                call.value(),
                self.expectations.record(accepted)?[ordinal % N].value(accepted, ordinal % N, N)
            );
        }
        let start = self.population.rows.len();
        self.population.join_for(
            meta,
            batch.records(),
            batch.journal(),
            &bindings,
            self.leaves.map(|l| l.function),
        );
        for seen in &self.population.rows[start..] {
            let f = self.index(seen.row.function);
            emit(
                io,
                call_line(
                    *seen,
                    f,
                    self.population.entries[f],
                    self.population.batches,
                ),
            )?;
        }
        let seen = self.population.rows.last().unwrap();
        let a = &self.population.accepted[(seen.id - 1) as usize];
        let values: [u64; N] = std::array::from_fn(|i| self.calls[call_start + i].value());
        emit(
            io,
            self.result_line(
                a,
                &values,
                seen.row.record.raw.ordinal + 1 - N as u64,
                seen.row.record.raw.ordinal,
            ),
        )
    }
    fn result_line(&self, a: &input::Record, values: &[u64; N], first: u64, last: u64) -> String {
        match &self.expectations {
            Expectations::Builtin(_) => result_line(a, values, first, last),
            Expectations::Frozen(_) => selected_result_line(a, values, first, last),
        }
    }
    fn index(&self, function: FunctionId) -> usize {
        self.leaves
            .iter()
            .position(|l| l.function == function)
            .expect("complete immutable function table")
    }
    pub(super) fn history_reports(
        &self,
        history: &[NormalLeafSetHistoryBatch],
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
    pub(super) fn finish(
        &self,
        totals: NormalTotals,
        reports: &[(u64, Vec<RecordObservation>)],
        io: &mut Io,
    ) -> Result<(), String> {
        assert_eq!(totals, self.population.totals);
        assert_eq!(
            self.population.rows.len(),
            self.population.accepted.len() * N
        );
        assert_eq!(totals.entered, totals.ret_observed);
        assert_eq!(totals.confirmed, totals.entered);
        assert_eq!(totals.confirmed, totals.completed + totals.unsampled);
        let mut reported = BTreeSet::new();
        let mut generations = BTreeSet::new();
        for (generation, records) in reports {
            assert!(generations.insert(*generation));
            population::report_shape_for(
                *generation,
                records,
                self.population.k * N,
                &self.leaves.map(|l| l.function),
            );
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
                emit(io, sample_line(observed, *seen, self.index(a.function)))?;
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
            call.check(N);
        }
        for record in &self.population.accepted {
            record.check();
        }
        for (f, leaf) in self.leaves.iter().enumerate() {
            let mut counts = [0_u64; 4];
            let mut mask = 0_u64;
            for s in self
                .population
                .rows
                .iter()
                .filter(|s| s.row.function == leaf.function)
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
            emit(
                io,
                format!(
                    "COVERAGE,{},{},{},{},{},{},{},{}\n",
                    f,
                    self.population.accepted.len(),
                    counts[0],
                    counts[1],
                    counts[2],
                    counts[3],
                    self.population.returns[f].len(),
                    mask
                ),
            )?;
        }
        Ok(())
    }
}
fn call_line(seen: Seen, f: usize, entry: u64, batch: u64) -> String {
    let r = seen.row.record;
    let raw = r.raw;
    let (label, generation, invocation) = population::owner_wire(raw.owner);
    let (ack, ack_ordinal) = match r.acknowledgement {
        NormalAcknowledgement::CallerCheckpoint => ("checkpoint", 0),
        NormalAcknowledgement::NextEntry { ordinal } => ("next", ordinal),
    };
    let line = format!(
        "CALL,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        seen.id,
        f,
        raw.ordinal,
        label,
        generation,
        invocation,
        r.history_prefix,
        raw.return_pc.checked_sub(entry).unwrap(),
        r.entry_rsp,
        r.return_word,
        raw.start.ticks,
        raw.end.ticks,
        raw.start.aux,
        raw.end.aux,
        ack,
        ack_ordinal,
        batch,
        seen.sequence
    );
    validate_line(&line);
    line
}
fn result_line<const N: usize>(
    a: &input::Record,
    values: &[u64; N],
    first: u64,
    last: u64,
) -> String {
    assert!((1..=4).contains(&N));
    assert_eq!(last.checked_sub(first).unwrap() + 1, N as u64);
    assert!(values.iter().all(|&v| v <= 65));
    selected_result_line(a, values, first, last)
}
fn selected_result_line<const N: usize>(
    a: &input::Record,
    values: &[u64; N],
    first: u64,
    last: u64,
) -> String {
    assert!((1..=4).contains(&N));
    assert_eq!(last.checked_sub(first).unwrap() + 1, N as u64);
    a.check();
    let mut line = format!("RESULT,{},{},{}", a.id, a.length, a.checksum());
    for value in values {
        write!(&mut line, ",{value}").unwrap();
    }
    writeln!(&mut line, ",{first},{last}").unwrap();
    validate_line(&line);
    line
}
fn sample_line(observed: &RecordObservation, seen: Seen, f: usize) -> String {
    let end = population::sample(observed, seen);
    let a = observed.record.admission;
    let (kind, value) = match end {
        Observation::Value(n) => ("value", n),
        Observation::Unavailable(n) => ("unavailable", n),
    };
    let line = format!(
        "SAMPLE,{},{},{},{},{},{},{},{},{}\n",
        seen.id,
        f,
        a.generation.get(),
        a.invocation,
        seen.rank.unwrap(),
        seen.sequence,
        a.entry_value,
        kind,
        value
    );
    validate_line(&line);
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use rapid_profiler::frontend::{HistoryBinding, Payload};
    use rapid_profiler::frontend_native::{NormalModuleRecord, NormalRecord, RawTimestamp};
    use rapid_profiler::generation::{Admission, Epoch, GenerationId, Record};
    fn refuse(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    // Real core IDs plus fabricated scalar observations; no native owner/receipt/stream.
    fn fixture<const N: usize>(k: usize) -> (Population<N>, [FunctionId; N], GenerationId) {
        let functions = std::array::from_fn(|i| FunctionId(i as u64 * 101));
        let g = Epoch::new(
            &functions,
            Config {
                retained_per_function: k,
                max_inflight: 1,
                max_invocations: N * k,
            },
        )
        .unwrap()
        .id();
        let mut p = Population {
            accepted: Vec::with_capacity(record_cap(N)),
            rows: Vec::with_capacity(record_cap(N) * N),
            totals: NormalTotals::default(),
            batches: 0,
            generations: Vec::with_capacity(520),
            entries: std::array::from_fn(|i| 0x1000 + i as u64 * 128),
            ends: std::array::from_fn(|i| 0x1050 + i as u64 * 128),
            returns: std::array::from_fn(|i| vec![0x1040 + i as u64 * 128]),
            identity: None,
            k,
            epoch_limit: 520,
        };
        p.ready(pair_worker::Identity {
            pid: 11,
            tid: 12,
            cpu: 1,
            stack: (0x8000, 0xa000),
            caller: (0x2000, 0x3000),
        });
        (p, functions, g)
    }
    fn next<const N: usize>(
        p: &mut Population<N>,
        functions: [FunctionId; N],
        g: GenerationId,
    ) -> (Metadata<N>, [NormalModuleRecord; N], [HistoryBinding; N]) {
        let id = p.accepted.len() as u64 + 1;
        p.accept_with_limit(
            &Arc::new(input::Record::new(id, b"a,b").unwrap()),
            record_cap(N),
        );
        let sampled = id <= p.k as u64;
        let before = p.totals;
        let base = before.confirmed;
        let rows = std::array::from_fn(|i| NormalModuleRecord {
            function: functions[i],
            record: NormalRecord {
                raw: RawInterval {
                    ordinal: base + i as u64 + 1,
                    entry_pc: p.entries[i],
                    return_pc: p.returns[i][0],
                    owner: if sampled {
                        RawIntervalOwner::Sampled {
                            generation: g.get(),
                            invocation: before.completed as usize + i,
                        }
                    } else {
                        RawIntervalOwner::FunctionClosed {
                            generation: g.get(),
                        }
                    },
                    start: RawTimestamp { ticks: 0, aux: 3 },
                    end: RawTimestamp { ticks: 0, aux: 3 },
                },
                entry_rsp: 0x9008,
                return_word: 0x2005,
                history_prefix: 513,
                acknowledgement: if i + 1 == N {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: base + i as u64 + 2,
                    }
                },
            },
        });
        let after = NormalTotals {
            entered: before.entered + N as u64,
            ret_observed: before.ret_observed + N as u64,
            confirmed: before.confirmed + N as u64,
            completed: before.completed + if sampled { N as u64 } else { 0 },
            unsampled: before.unsampled + if sampled { 0 } else { N as u64 },
        };
        let m = Metadata {
            identity: identity(p.entries[0]),
            functions,
            entries: p.entries,
            pid: 11,
            tid: 12,
            registration: 1,
            install: INSTALL,
            number: p.batches + 1,
            totals: (before, after),
            sequences: (before.completed, after.completed),
            next: after.confirmed + 1,
        };
        (
            m,
            rows,
            [HistoryBinding::Published {
                action_index: 512,
                generation: g,
            }; N],
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

    fn positive<const N: usize>() {
        let (mut p, f, g) = fixture::<N>(10);
        for round in 0..2 {
            let (m, rows, b) = next(&mut p, f, g);
            p.join_for(m, &rows, &journal(&rows), &b, f);
            for (i, s) in p.rows[round * N..].iter().enumerate() {
                assert_eq!(s.rank, Some(round));
                assert_eq!(s.sequence, (round * N + i) as u64);
                assert_eq!(s.row.function, f[i]);
            }
        }
        assert_eq!(p.batches, 2);
        assert_eq!(p.totals.confirmed, 2 * N as u64);
    }
    #[test]
    fn ordered_population_n1_through_n4_keeps_global_and_local_coordinates() {
        positive::<1>();
        positive::<2>();
        positive::<3>();
        positive::<4>();
    }
    #[test]
    fn population_refuses_full_table_identity_and_each_journal_word() {
        for at in 0..512 {
            let (mut p, f, g) = fixture::<3>(10);
            let (m, rows, b) = next(&mut p, f, g);
            let mut words = journal(&rows);
            words[at] ^= 1;
            refuse(|| p.join_for(m, &rows, &words, &b, f));
        }
        for choice in 0..14 {
            let (mut p, f, g) = fixture::<4>(10);
            let (mut m, mut rows, b) = next(&mut p, f, g);
            match choice {
                0 => m.functions.swap(2, 3),
                1 => m.entries[3] += 1,
                2 => m.tid += 1,
                3 => m.install += 1,
                4 => m.identity.generation += 1,
                5 => m.number += 1,
                6 => rows[3].function = f[2],
                7 => rows[2].record.raw.ordinal += 1,
                8 => rows[3].record.raw.return_pc += 1,
                9 => rows[1].record.entry_rsp = 120,
                10 => rows[0].record.return_word = 0x3000,
                11 => {
                    rows[3].record.acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 5 }
                }
                12 => m.sequences.1 -= 1,
                _ => {
                    p.accepted.clear();
                }
            }
            refuse(|| p.join_for(m, &rows, &journal(&rows), &b, f));
        }
        let (mut p, f, g) = fixture::<3>(10);
        let (m, rows, b) = next(&mut p, f, g);
        refuse(|| p.join_for(m, &rows[..2], &journal(&rows[..2]), &b[..2], f));
    }
    fn budget<const N: usize>(k: usize) {
        let (mut p, f, g) = fixture::<N>(k);
        for _ in 0..=k {
            let (m, rows, b) = next(&mut p, f, g);
            p.join_for(m, &rows, &journal(&rows), &b, f);
        }
        assert_eq!(p.totals.completed, (N * k) as u64);
        assert_eq!(p.totals.unsampled, N as u64);
        let last = p.rows[N * k - 1];
        let call = call_line(last, N - 1, p.entries[N - 1], k as u64);
        assert_eq!(
            call.trim_end().split(',').nth(6).unwrap(),
            (N * k).to_string()
        );
        let sample = sample_line(&observation(last, g), last, N - 1);
        assert_eq!(
            sample.trim_end().split(',').nth(4).unwrap(),
            (N * k - 1).to_string()
        );
        let closed = p.rows.last().unwrap();
        assert_eq!(
            call_line(*closed, N - 1, p.entries[N - 1], k as u64 + 1)
                .trim_end()
                .split(',')
                .nth(6),
            Some("0")
        );
        let observations: Vec<_> = p.rows[..N * k].iter().map(|&s| observation(s, g)).collect();
        population::report_shape_for(g.get(), &observations, N * k, &f);
        assert_eq!(observations.len(), N * k);
    }
    #[test]
    fn mixed_history_and_full_budget_keep_one_based_call_and_zero_based_sample() {
        for k in [10, 1000] {
            budget::<1>(k);
            budget::<2>(k);
            budget::<3>(k);
            budget::<4>(k);
        }
        let (mut p, f, g) = fixture::<3>(10);
        let (m, mut rows, mut b) = next(&mut p, f, g);
        let second = Epoch::new(
            &f,
            Config {
                retained_per_function: 10,
                max_inflight: 1,
                max_invocations: 30,
            },
        )
        .unwrap()
        .id();
        rows[2].record.raw.owner = RawIntervalOwner::Sampled {
            generation: second.get(),
            invocation: 0,
        };
        rows[2].record.history_prefix = 514;
        b[2] = HistoryBinding::Published {
            action_index: 513,
            generation: second,
        };
        p.join_for(m, &rows, &journal(&rows), &b, f);
        assert_eq!(p.generations.len(), 2);
        assert_eq!(p.rows[2].rank, Some(0));
        assert_eq!(p.rows[2].sequence, 2);
        // A record straddles A->B; B's third function reaches K first. The last
        // record must keep sampled B slots28/29 beside FunctionClosed B, not
        // treat the aggregate completed count as each function's retained rank.
        let (mut q, ids, a) = fixture::<3>(10);
        let bgen = Epoch::new(
            &ids,
            Config {
                retained_per_function: 10,
                max_inflight: 1,
                max_invocations: 30,
            },
        )
        .unwrap()
        .id();
        for record in 0..11 {
            let (mut meta, mut rows, mut bindings) = next(&mut q, ids, a);
            for i in 0..3 {
                if record == 0 && i < 2 {
                    continue;
                }
                rows[i].record.history_prefix = 514;
                bindings[i] = HistoryBinding::Published {
                    action_index: 513,
                    generation: bgen,
                };
                rows[i].record.raw.owner = if record == 10 && i == 2 {
                    RawIntervalOwner::FunctionClosed {
                        generation: bgen.get(),
                    }
                } else {
                    RawIntervalOwner::Sampled {
                        generation: bgen.get(),
                        invocation: if record == 0 {
                            0
                        } else {
                            1 + (record - 1) * 3 + i
                        },
                    }
                };
            }
            if record == 10 {
                meta.totals.1.completed = meta.totals.0.completed + 2;
                meta.totals.1.unsampled = 1;
                meta.sequences.1 = meta.totals.1.completed;
            }
            q.join_for(meta, &rows, &journal(&rows), &bindings, ids);
        }
        assert_eq!((q.totals.completed, q.totals.unsampled), (32, 1));
        assert_eq!(q.rows[30].rank, Some(9));
        assert_eq!(q.rows[31].rank, Some(9));
        assert_eq!(q.rows[32].rank, None);
        assert_eq!(q.generations[1].counts, [10, 10, 10]);
        assert_eq!(q.generations[1].slots, 30);
        for choice in 0..3 {
            let (mut p, f, g) = fixture::<3>(10);
            let (m, mut rows, mut b) = next(&mut p, f, g);
            match choice {
                0 => {
                    for row in &mut rows {
                        let RawIntervalOwner::Sampled { invocation, .. } =
                            &mut row.record.raw.owner
                        else {
                            panic!()
                        };
                        *invocation += 1;
                    }
                }
                1 => b[2] = HistoryBinding::Initial,
                _ => {
                    rows[2].record.raw.owner = RawIntervalOwner::FunctionClosed {
                        generation: g.get(),
                    }
                }
            }
            refuse(|| p.join_for(m, &rows, &journal(&rows), &b, f));
        }
    }
    #[test]
    fn report_payload_and_wire_refuse_shift_missing_duplicate_and_unavailable_corruption() {
        let (mut p, f, g) = fixture::<4>(10);
        let (m, rows, b) = next(&mut p, f, g);
        p.join_for(m, &rows, &journal(&rows), &b, f);
        let observations: Vec<_> = p.rows.iter().map(|&s| observation(s, g)).collect();
        population::report_shape_for(g.get(), &observations, 40, &f);
        for choice in 0..7 {
            let mut changed = observations.clone();
            match choice {
                0 => {
                    changed.remove(1);
                }
                1 => changed[3] = changed[2],
                2 => changed[3].record.admission.function = f[2],
                3 => {
                    for o in &mut changed {
                        o.record.admission.invocation += 1;
                    }
                }
                4 => changed[3].payload.as_mut().unwrap().start_sequence += 1,
                5 => changed[3].payload.as_mut().unwrap().admission.function = f[0],
                _ => changed[3].payload = None,
            }
            refuse(|| {
                population::report_shape_for(g.get(), &changed, 40, &f);
                for (o, s) in changed.iter().zip(&p.rows) {
                    sample_line(o, *s, 0);
                }
            });
        }
        for (start, end, aux, expected) in [
            (u64::MAX, u64::MAX, 3, Observation::Value(u64::MAX)),
            (u64::MAX, 0, 3, Observation::Unavailable(2)),
            (u64::MAX, 0, u32::MAX, Observation::Unavailable(1)),
        ] {
            let mut seen = p.rows[3];
            seen.row.record.raw.start.ticks = start;
            seen.row.record.raw.end.ticks = end;
            seen.row.record.raw.end.aux = aux;
            let o = observation(seen, g);
            assert_eq!(population::sample(&o, seen), expected);
            validate_line(&sample_line(&o, seen, 3));
            let mut wrong = o;
            wrong.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                end: Observation::Unavailable(0),
                completed_children: 0,
            };
            refuse(|| {
                sample_line(&wrong, seen, 3);
            });
        }
        let a = input::Record::new(1024, &[b','; 64]).unwrap();
        let result = result_line(&a, &[65, 64, 0, 0], 4093, 4096);
        assert_eq!(result.trim_end().split(',').count(), 10);
        validate_line(&result);
        let mut seen = p.rows[3];
        seen.id = 2048;
        seen.sequence = 4096;
        seen.row.record.raw.ordinal = 4096;
        seen.row.record.raw.owner = RawIntervalOwner::Sampled {
            generation: u64::MAX,
            invocation: 3999,
        };
        seen.row.record.history_prefix = u64::MAX;
        seen.row.record.raw.start.ticks = u64::MAX;
        seen.row.record.raw.end.ticks = u64::MAX;
        seen.row.record.raw.start.aux = u32::MAX;
        seen.row.record.raw.end.aux = u32::MAX;
        seen.row.record.entry_rsp = u64::MAX - 23;
        seen.row.record.return_word = u64::MAX;
        let line = call_line(seen, 3, p.entries[3], 2048);
        assert!(line.len() <= 217);
        assert_eq!(line.trim_end().split(',').count(), 19);
        refuse(|| {
            result_line(&a, &[65, 64, 0, 66], 4093, 4096);
        });
        refuse(|| {
            result_line(&a, &[65, 64, 0, 0], 4092, 4096);
        });
    }
}

#[cfg(test)]
pub(in crate::normal) mod selected_controls {
    use super::*;
    fn refuse(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    pub(in crate::normal) fn selected_full_u64_wire_keeps_old_bounds_and_old_refusal() {
        let record = input::Record::new(1024, &[b'A'; 64]).unwrap();
        let values = [u64::MAX; 4];
        let line = selected_result_line(&record, &values, 4093, 4096);
        assert_eq!(
            line,
            format!(
                "RESULT,1024,64,{},18446744073709551615,18446744073709551615,18446744073709551615,18446744073709551615,4093,4096\n",
                record.checksum()
            )
        );
        validate_line(&line);
        refuse(|| {
            result_line(&record, &values, 4093, 4096);
        });
        refuse(|| {
            selected_result_line(&record, &values, 4092, 4096);
        });
        refuse(|| {
            selected_result_line(&record, &[], 4093, 4096);
        });
        refuse(|| {
            selected_result_line(&record, &[0; 5], 4092, 4096);
        });
        assert_eq!(
            result_line(&record, &[65; 4], 4093, 4096),
            selected_result_line(&record, &[65; 4], 4093, 4096)
        );
        for n in 1..=4 {
            let records = record_cap(n);
            let lines = 2 * n * records + records + 2 * 520 + 6 * n + 4;
            assert!(lines * 350 < 4 * 1024 * 1024);
        }
    }
}
