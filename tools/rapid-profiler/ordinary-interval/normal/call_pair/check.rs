//! Nested accounting. No flat Population or final-Report checkpoint prerequisite.
use super::*;
use rapid_profiler::frontend::Payload;
use rapid_profiler::frontend_native::{
    HistoryBinding, NormalCallPairAcknowledgement, NormalCallPairRecord, NormalCallPairRole,
    NormalCallPairRoleKind,
};
use rapid_profiler::generation::{Completion, DeactivationRequest};
#[derive(Clone, Debug)]
pub(super) struct Geometry {
    pub functions: [FunctionId; 2],
    pub entries: [u64; 2],
    pub ends: [u64; 2],
    pub returns: [Vec<u64>; 2],
    pub call_pc: u64,
    pub continuation: u64,
    pub child_delta: u64,
}
impl Geometry {
    pub(super) fn check_roles(&self, roles: &[NormalCallPairRole]) {
        use NormalCallPairRoleKind::*;
        let expected: Vec<_> = std::iter::once((ParentEntry, self.entries[0]))
            .chain(std::iter::once((ChildEntry, self.entries[1])))
            .chain(self.returns[1].iter().map(|&pc| (ChildRet, pc)))
            .chain([
                (ChildAck, self.continuation),
                (ParentRet, self.returns[0][0]),
            ])
            .map(|(kind, pc)| NormalCallPairRole { kind, pc })
            .collect();
        assert_eq!(roles, expected);
    }
    pub(super) fn check(&self) {
        assert_ne!(self.functions[0], self.functions[1]);
        for i in 0..2 {
            assert!(self.entries[i] > 0 && self.ends[i] > self.entries[i]);
            assert!(
                (if i == 0 { 5..=80 } else { 1..=256 }).contains(&(self.ends[i] - self.entries[i]))
            );
            assert!((if i == 0 { 1..=1 } else { 1..=4 }).contains(&self.returns[i].len()));
            assert!(self.returns[i].windows(2).all(|w| w[0] < w[1]));
            assert!(
                self.returns[i]
                    .iter()
                    .all(|&pc| self.entries[i] <= pc && pc < self.ends[i])
            );
        }
        assert!(self.ends[0] <= self.entries[1] || self.ends[1] <= self.entries[0]);
        assert!(
            self.entries[0] <= self.call_pc
                && self.call_pc.checked_add(5) == Some(self.continuation)
        );
        assert!(self.continuation <= self.returns[0][0]);
        assert!(matches!(self.child_delta, 16 | 32 | 48 | 64));
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Row {
    function: FunctionId,
    node: usize,
    parent: u64,
    raw: RawInterval,
    rsp: u64,
    word: u64,
    resume_pc: u64,
    resume_rsp: u64,
    value: u64,
    ack: NormalCallPairAcknowledgement,
    prefix: u64,
    sequence: u64,
    children: u64,
    sampled_children: Option<u64>,
    completion: Option<Completion>,
    payload: Option<Payload>,
}
impl Row {
    fn read(r: &NormalCallPairRecord) -> Self {
        Self {
            function: r.function(),
            node: r.node(),
            parent: r.parent_ordinal(),
            raw: r.raw(),
            rsp: r.entry_rsp(),
            word: r.return_word(),
            resume_pc: r.resume_pc(),
            resume_rsp: r.resume_rsp(),
            value: r.value(),
            ack: r.acknowledgement(),
            prefix: r.history_prefix(),
            sequence: r.sequence_before(),
            children: r.actual_children(),
            sampled_children: r.sampled_children(),
            completion: r.completion(),
            payload: r.payload(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Meta {
    pid: u32,
    tid: u64,
    registration: u64,
    install: u64,
    number: u64,
    before: NormalCallPairTotals,
    after: NormalCallPairTotals,
    high: u64,
}
#[derive(Clone, Copy, Debug)]
struct Seen {
    row: Row,
    rank: Option<usize>,
}
#[derive(Clone, Debug)]
struct Generation {
    id: u64,
    slots: usize,
    counts: [usize; 2],
}
pub(super) struct Accounting {
    pub accepted: Vec<Arc<input::Record>>,
    pub totals: NormalCallPairTotals,
    rows: Vec<Seen>,
    generations: Vec<Generation>,
    number: u64,
    geometry: Geometry,
    identity: Option<pair_worker::Identity>,
    k: usize,
    epochs: usize,
}
impl Accounting {
    fn new(geometry: Geometry, k: usize, epochs: usize) -> Self {
        geometry.check();
        assert!(matches!(k, 10 | 1000) && (1..=520).contains(&epochs));
        Self {
            accepted: Vec::with_capacity(input::RECORDS),
            totals: NormalCallPairTotals::default(),
            rows: Vec::with_capacity(4096),
            generations: Vec::with_capacity(epochs),
            number: 0,
            geometry,
            identity: None,
            k,
            epochs,
        }
    }
    fn ready(&mut self, id: pair_worker::Identity) {
        assert!(self.identity.replace(id).is_none());
        assert!(id.pid != 0 && id.tid != u64::from(id.pid) && id.tid != 0 && id.cpu < 1024);
        assert!(id.stack.0 < id.stack.1 && id.caller.0 < id.caller.1);
    }
    fn accept(&mut self, record: &Arc<input::Record>) {
        record.check();
        assert!(self.accepted.len() < input::RECORDS);
        assert_eq!(record.id, self.accepted.len() as u64 + 1);
        self.accepted.push(Arc::clone(record));
    }
    fn owner(&mut self, row: Row, binding: HistoryBinding) -> Option<usize> {
        match row.raw.owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation,
            } => {
                assert!(
                    matches!(binding,HistoryBinding::Published { action_index,generation:g } if action_index<row.prefix && g.get()==generation)
                );
                let at = match self.generations.iter().position(|g| g.id == generation) {
                    Some(i) => i,
                    None => {
                        assert!(self.generations.len() < self.epochs);
                        self.generations.push(Generation {
                            id: generation,
                            slots: 0,
                            counts: [0; 2],
                        });
                        self.generations.len() - 1
                    }
                };
                let g = &mut self.generations[at];
                assert_eq!(invocation, g.slots);
                assert!(g.slots < 2 * self.k && g.counts[row.node] < self.k);
                let rank = g.counts[row.node];
                g.slots += 1;
                g.counts[row.node] += 1;
                Some(rank)
            }
            RawIntervalOwner::FunctionClosed { generation } => {
                assert!(
                    matches!(binding,HistoryBinding::Published { action_index,generation:g } if action_index<row.prefix && g.get()==generation)
                );
                assert_eq!(
                    self.generations
                        .iter()
                        .find(|g| g.id == generation)
                        .map(|g| g.counts[row.node]),
                    Some(self.k)
                );
                None
            }
            RawIntervalOwner::Removed { generation } => {
                assert!(
                    matches!(binding,HistoryBinding::Removed { action_index,generation:g } if action_index<row.prefix && g.get()==generation)
                );
                None
            }
            RawIntervalOwner::InitialDisarmed => {
                assert_eq!(row.prefix, 0);
                assert_eq!(binding, HistoryBinding::Initial);
                None
            }
        }
    }
}
fn observation(raw: RawInterval) -> Observation {
    if raw.start.aux != raw.end.aux {
        Observation::Unavailable(1)
    } else if raw.end.ticks < raw.start.ticks {
        Observation::Unavailable(2)
    } else {
        Observation::Value(raw.end.ticks)
    }
}
fn coordinates(owner: RawIntervalOwner) -> (&'static str, u64, u64, u64, u64) {
    match owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => ("sampled", generation, invocation as u64 + 1, 1, 0),
        RawIntervalOwner::FunctionClosed { generation } => ("closed", generation, 0, 3, 3),
        RawIntervalOwner::Removed { generation } => ("removed", generation, 0, 3, 2),
        RawIntervalOwner::InitialDisarmed => ("initial", 0, 0, 3, 1),
    }
}
fn journal(rows: &[Row; 2], tid: u64) -> [u64; 512] {
    let mut page = [0; 512];
    page[0] = 4;
    page[2] = tid;
    for (event, (node, ret)) in [(0, false), (1, false), (1, true), (0, true)]
        .into_iter()
        .enumerate()
    {
        let r = rows[node];
        let (_, g, slot, kind, reason) = coordinates(r.raw.owner);
        assert!(slot <= 2000 && r.prefix <= 1040);
        let bits = slot | ((r.prefix & 511) << 13) | (reason << 22) | ((r.prefix >> 9) << 24);
        let at = 4 + 7 * event;
        page[at..at + 7].copy_from_slice(&[
            kind + u64::from(ret),
            r.raw.ordinal,
            if ret { r.raw.return_pc } else { r.raw.entry_pc },
            r.rsp,
            r.word,
            g,
            bits,
        ]);
    }
    page
}
fn outcome(row: Row, rank: Option<usize>, child: Row, parent: Row, k: usize) {
    let RawIntervalOwner::Sampled {
        generation,
        invocation,
    } = row.raw.owner
    else {
        assert_eq!(rank, None);
        assert_eq!(row.completion, None);
        assert_eq!(row.payload, None);
        assert_eq!(row.sampled_children, None);
        return;
    };
    let c = row.completion.expect("sampled complete outcome");
    let rank = rank.unwrap();
    assert_eq!(c.admission.generation.get(), generation);
    assert_eq!(
        (
            c.admission.invocation,
            c.admission.function,
            c.admission.entry_value
        ),
        (invocation, row.function, row.raw.start.ticks)
    );
    assert_eq!(c.disposition, Disposition::Retained { rank });
    let children =
        u64::from(row.node == 0 && matches!(child.raw.owner, RawIntervalOwner::Sampled { .. }));
    assert_eq!(row.sampled_children, Some(children));
    assert_eq!(
        row.payload,
        Some(Payload {
            admission: c.admission,
            thread: 1,
            start_sequence: row.sequence,
            outcome: PayloadOutcome::Completed {
                end: observation(row.raw),
                completed_children: children
            }
        })
    );
    if rank + 1 == k {
        assert_eq!(
            c.deactivate,
            Some(DeactivationRequest {
                generation: c.admission.generation,
                function: row.function
            })
        );
        let peers = usize::from(
            row.node == 1
                && matches!(parent.raw.owner,RawIntervalOwner::Sampled { generation:g,.. } if g==generation),
        );
        assert_eq!(c.other_reservations_after_close, Some(peers));
    } else {
        assert_eq!(c.deactivate, None);
        assert_eq!(c.other_reservations_after_close, None);
    }
}
impl Accounting {
    fn join(
        &mut self,
        meta: Meta,
        rows: [Row; 2],
        words: &[u64; 512],
        bindings: [HistoryBinding; 2],
    ) {
        let id = self.identity.unwrap();
        let root = self.number;
        assert!(root < self.accepted.len() as u64 && self.rows.len() == root as usize * 2);
        assert_eq!(
            (meta.pid, meta.tid, meta.registration, meta.install),
            (id.pid, id.tid, 1, INSTALL)
        );
        assert_eq!(meta.number, root + 1);
        assert_eq!(meta.before, self.totals);
        assert!(meta.high <= 2 * self.epochs as u64);
        worker::complete(meta.after, root + 1);
        let record = &self.accepted[root as usize];
        record.check();
        assert_eq!(
            (rows[0].value, rows[1].value),
            (packed(record), record.fields)
        );
        assert_eq!(
            rows[0].rsp.checked_sub(self.geometry.child_delta),
            Some(rows[1].rsp)
        );
        assert_eq!(rows[1].word, self.geometry.continuation);
        assert!(rows[0].word >= id.caller.0 && rows[0].word < id.caller.1);
        assert!(rows[0].prefix <= rows[1].prefix);
        if let Some(previous) = self.rows.last() {
            assert!(previous.row.prefix <= rows[0].prefix);
        }
        for (node, &r) in rows.iter().enumerate() {
            assert_eq!((r.node, r.function), (node, self.geometry.functions[node]));
            assert_eq!(
                (r.parent, r.raw.ordinal),
                (root * 2 + 1, root * 2 + 1 + node as u64)
            );
            assert_eq!(r.raw.entry_pc, self.geometry.entries[node]);
            assert!(self.geometry.returns[node].contains(&r.raw.return_pc));
            assert_eq!(r.rsp % 16, 8);
            assert!(r.rsp.checked_sub(416).is_some_and(|v| v >= id.stack.0));
            assert!(r.rsp.checked_add(8).is_some_and(|v| v <= id.stack.1));
            assert_eq!(
                (r.resume_pc, r.resume_rsp),
                (r.word, r.rsp.checked_add(8).unwrap())
            );
            assert_eq!(
                r.ack,
                if node == 0 {
                    NormalCallPairAcknowledgement::CallerCheckpoint
                } else {
                    NormalCallPairAcknowledgement::ChildContinuation
                }
            );
            assert_eq!(r.children, u64::from(node == 0));
            assert_eq!(r.sequence, self.totals.pairs.completed);
            assert!(r.prefix <= meta.high);
        }
        assert_eq!(words, &journal(&rows, id.tid)); // Includes every zero tail word.
        let ranks: [Option<usize>; 2] = std::array::from_fn(|i| self.owner(rows[i], bindings[i]));
        for i in 0..2 {
            outcome(rows[i], ranks[i], rows[1], rows[0], self.k);
        }
        let sampled = ranks.iter().filter(|r| r.is_some()).count() as u64;
        assert_eq!(
            meta.after.pairs.completed,
            self.totals.pairs.completed.checked_add(sampled).unwrap()
        );
        assert_eq!(
            meta.after.pairs.unsampled,
            self.totals
                .pairs
                .unsampled
                .checked_add(2 - sampled)
                .unwrap()
        );
        self.rows.extend(std::array::from_fn::<_, 2, _>(|i| Seen {
            row: rows[i],
            rank: ranks[i],
        }));
        self.totals = meta.after;
        self.number = meta.number;
    }
}
// The core terminal retains the global admission slot. The Payload independently
// retains completed_children, which may be one for this nested parent.
pub(super) fn report_shape(
    generation: u64,
    rows: &[RecordObservation],
    capacity: usize,
    functions: &[FunctionId; 2],
) {
    assert!(generation != 0 && matches!(capacity, 20 | 2000) && rows.len() <= capacity);
    assert_ne!(functions[0], functions[1]);
    let mut ranks = [0; 2];
    for (slot, row) in rows.iter().enumerate() {
        let a = row.record.admission;
        let node = functions.iter().position(|&f| f == a.function).unwrap();
        assert_eq!((a.generation.get(), a.invocation), (generation, slot));
        assert!(ranks[node] < capacity / 2);
        let p = row.payload.expect("complete copied Report payload");
        assert_eq!(p.admission, a);
        assert_eq!(p.thread, 1);
        let PayloadOutcome::Completed {
            completed_children, ..
        } = p.outcome
        else {
            panic!("cancelled report")
        };
        assert!(completed_children <= u64::from(node == 0));
        assert_eq!(
            row.record.terminal,
            Some(Terminal::Completed {
                value: a.invocation as u64,
                disposition: Disposition::Retained { rank: ranks[node] }
            })
        );
        ranks[node] += 1;
    }
}
fn sample(seen: Seen, observed: &RecordObservation) -> Observation {
    let c = seen
        .row
        .completion
        .expect("Report has one retained sampled row");
    assert_eq!(observed.record.admission, c.admission);
    let PayloadOutcome::Completed {
        completed_children, ..
    } = seen.row.payload.expect("sampled complete payload").outcome
    else {
        panic!("cancelled sampled payload")
    };
    assert_eq!(Some(completed_children), seen.row.sampled_children);
    assert_eq!(
        observed.record.terminal,
        Some(Terminal::Completed {
            value: c.admission.invocation as u64,
            disposition: c.disposition
        })
    );
    assert_eq!(observed.payload, seen.row.payload);
    assert_eq!(
        c.disposition,
        Disposition::Retained {
            rank: seen.rank.unwrap()
        }
    );
    observation(seen.row.raw)
}
pub(super) struct Ledger {
    pub accounting: Accounting,
    stream: NormalCallPairHistoryStream,
    calls: Vec<worker::Call>,
    pub batches: Vec<NormalCallPairBatch>,
}
impl Ledger {
    pub(super) fn new(
        stream: NormalCallPairHistoryStream,
        geometry: Geometry,
        k: usize,
        epochs: usize,
    ) -> Self {
        assert_eq!(stream.functions(), &geometry.functions);
        assert_eq!(stream.entries(), &geometry.entries);
        assert_eq!(
            stream.edge(),
            [geometry.call_pc, geometry.entries[1], geometry.continuation]
        );
        assert_eq!(stream.identity(), identity(geometry.entries[0]));
        assert_eq!(
            stream.format(),
            rapid_profiler::frontend_native::HistoryFormat::AbsoluteV1
        );
        assert_eq!(stream.install(), INSTALL);
        assert_eq!(stream.pid(), std::process::id());
        Self {
            accounting: Accounting::new(geometry, k, epochs),
            stream,
            calls: Vec::with_capacity(input::RECORDS),
            batches: Vec::with_capacity(input::RECORDS),
        }
    }
    pub(super) fn ready(&mut self, id: pair_worker::Identity) {
        assert_eq!(id.pid, self.stream.pid());
        self.accounting.ready(id);
    }
    pub(super) fn accept(&mut self, record: &Arc<input::Record>) {
        self.accounting.accept(record);
    }
    pub(super) fn batch(
        &mut self,
        calls: Vec<worker::Call>,
        batch: NormalCallPairBatch,
        history: &[NormalCallPairHistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        // Both owners cross into outer-owned retained storage before assertions.
        let old = self.calls.len();
        self.calls.extend(calls);
        self.batches.push(batch);
        assert_eq!(self.calls.len(), old + 1);
        assert!(self.calls.len() <= input::RECORDS);
        assert_eq!(self.batches.len(), old + 1);
        let b = self.batches.last().unwrap();
        assert_eq!(b.stream(), &self.stream);
        let rows = b.records().map(|r| Row::read(&r));
        let high = b.history_end();
        assert!(high <= history.last().unwrap().range().end);
        let bindings = std::array::from_fn(|i| {
            history
                .iter()
                .rev()
                .find_map(|h| {
                    assert_eq!(h.stream(), &self.stream);
                    h.binding_at(rows[i].prefix)
                })
                .expect("retained complete history covers each entry")
        });
        let call = &self.calls[old];
        let accepted = &self.accounting.accepted[old];
        assert_eq!(call.function, 0);
        assert!(Arc::ptr_eq(&call.record, accepted));
        assert_eq!(call.record.as_ref(), accepted.as_ref());
        call.check_expected(1, packed(accepted));
        assert_eq!(call.value(), rows[0].value);
        let meta = Meta {
            pid: b.pid(),
            tid: b.tid(),
            registration: b.registration(),
            install: b.install(),
            number: b.number(),
            before: b.before(),
            after: b.after(),
            high,
        };
        self.accounting.join(meta, rows, b.journal(), bindings);
        for seen in &self.accounting.rows[old * 2..] {
            emit(io, call_line(*seen))?;
            emit(io, raw_line(*seen))?;
        }
        emit(
            io,
            result_line(&self.accounting.accepted[old], call.value()),
        )
    }
    pub(super) fn final_checks(&self) {
        let a = &self.accounting;
        let roots = a.accepted.len();
        assert_eq!(self.calls.len(), roots);
        assert_eq!(self.batches.len(), roots);
        assert_eq!(a.rows.len(), 2 * roots);
        worker::complete(a.totals, roots as u64);
        for (i, call) in self.calls.iter().enumerate() {
            let r = &a.accepted[i];
            r.check();
            assert_eq!(r.id, i as u64 + 1);
            assert!(Arc::ptr_eq(r, &call.record));
            assert_eq!(call.function, 0);
            call.check_expected(1, packed(r));
            let b = &self.batches[i];
            assert_eq!(b.stream(), &self.stream);
            let rows = b.records().map(|r| Row::read(&r));
            assert_eq!(rows, [a.rows[2 * i].row, a.rows[2 * i + 1].row]);
            assert_eq!(b.journal(), &journal(&rows, a.identity.unwrap().tid));
        }
    }
    pub(super) fn finish(
        &self,
        totals: NormalTotals,
        reports: &[(u64, Vec<RecordObservation>)],
        history: &[NormalCallPairHistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        self.final_checks();
        assert_eq!(totals, self.accounting.totals.pairs);
        let publications: Vec<_> = history
            .iter()
            .flat_map(|h| {
                assert_eq!(h.stream(), &self.stream);
                h.actions()
            })
            .filter(|a| a.kind == rapid_profiler::frontend::ActionKind::Published)
            .map(|a| a.generation.get())
            .collect();
        self.accounting.reports(reports, &publications);
        for (g, rows) in reports {
            for row in rows {
                let seen = *self
                    .accounting
                    .rows
                    .iter()
                    .find(|r| {
                        r.row.raw.owner
                            == RawIntervalOwner::Sampled {
                                generation: *g,
                                invocation: row.record.admission.invocation,
                            }
                    })
                    .unwrap();
                emit(io, sample_line(seen, observation(seen.row.raw)))?;
            }
        }
        for node in 0..2 {
            let mut counts = [0_u64; 4];
            let mut mask = 0_u64;
            for s in self.accounting.rows.iter().filter(|s| s.row.node == node) {
                counts[match s.row.raw.owner {
                    RawIntervalOwner::Sampled { .. } => 0,
                    RawIntervalOwner::FunctionClosed { .. } => 1,
                    RawIntervalOwner::Removed { .. } => 2,
                    RawIntervalOwner::InitialDisarmed => 3,
                }] += 1;
                mask |= 1
                    << self.accounting.geometry.returns[node]
                        .iter()
                        .position(|&pc| pc == s.row.raw.return_pc)
                        .unwrap();
            }
            assert_eq!(
                counts.iter().sum::<u64>(),
                self.accounting.accepted.len() as u64
            );
            emit(
                io,
                format!(
                    "COVERAGE,{node},{},{},{},{},{},{}\n",
                    counts[0],
                    counts[1],
                    counts[2],
                    counts[3],
                    mask,
                    (1_u64 << self.accounting.geometry.returns[node].len()) - 1
                ),
            )?;
        }
        Ok(())
    }
}
fn call_line(s: Seen) -> String {
    let r = s.row;
    let (kind, g, slot, _, _) = coordinates(r.raw.owner);
    format!(
        "CALL,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        r.parent.checked_add(1).unwrap() / 2,
        r.node,
        r.function.0,
        r.raw.ordinal,
        r.parent,
        kind,
        g,
        slot,
        r.prefix,
        r.sequence,
        r.children,
        u8::from(r.sampled_children.is_some()),
        r.sampled_children.unwrap_or(0),
        if r.node == 0 {
            "checkpoint"
        } else {
            "continuation"
        },
        s.rank.map_or(0, |rank| rank + 1)
    )
}
fn raw_line(s: Seen) -> String {
    let r = s.row;
    format!(
        "RAW,{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        r.parent.checked_add(1).unwrap() / 2,
        r.node,
        r.raw.entry_pc,
        r.raw.return_pc,
        r.rsp,
        r.word,
        r.resume_pc,
        r.resume_rsp,
        r.value,
        r.raw.start.ticks,
        r.raw.end.ticks,
        r.raw.start.aux,
        r.raw.end.aux
    )
}
fn result_line(r: &input::Record, value: u64) -> String {
    format!(
        "RESULT,{},{},{},{},{},{},{}\n",
        r.id,
        r.length,
        r.checksum(),
        value,
        r.fields,
        2 * r.id - 1,
        2 * r.id
    )
}
fn sample_line(s: Seen, end: Observation) -> String {
    let c = s.row.completion.unwrap();
    let p = s.row.payload.unwrap();
    let a = c.admission;
    let (kind, value) = match end {
        Observation::Value(n) => ("value", n),
        Observation::Unavailable(n) => ("unavailable", n),
    };
    format!(
        "SAMPLE,{},{},{},{},{},{},{},{},{},{},{},{}\n",
        s.row.parent.checked_add(1).unwrap() / 2,
        s.row.node,
        a.function.0,
        a.generation.get(),
        a.invocation,
        s.rank.unwrap(),
        p.start_sequence,
        a.entry_value,
        p.thread,
        s.row.sampled_children.unwrap(),
        kind,
        value
    )
}
#[cfg(test)]
mod tests;

impl Accounting {
    fn reports(&self, reports: &[(u64, Vec<RecordObservation>)], publications: &[u64]) {
        assert_eq!(publications.len(), reports.len());
        for &g in publications {
            assert_eq!(reports.iter().filter(|r| r.0 == g).count(), 1);
        }
        let mut observed = BTreeSet::new();
        for (g, rows) in reports {
            assert!(publications.contains(g));
            report_shape(*g, rows, 2 * self.k, &self.geometry.functions);
            for row in rows {
                let a = row.record.admission;
                assert!(observed.insert((*g, a.invocation)));
                let seen = *self
                    .rows
                    .iter()
                    .find(|r| {
                        r.row.raw.owner
                            == RawIntervalOwner::Sampled {
                                generation: *g,
                                invocation: a.invocation,
                            }
                    })
                    .unwrap();
                sample(seen, row);
            }
        }
        assert_eq!(observed.len() as u64, self.totals.pairs.completed);
        for s in &self.rows {
            match s.row.raw.owner {
                RawIntervalOwner::Sampled {
                    generation,
                    invocation,
                } => assert!(observed.contains(&(generation, invocation))),
                RawIntervalOwner::FunctionClosed { generation } => {
                    let rows = &reports.iter().find(|r| r.0 == generation).unwrap().1;
                    assert_eq!(
                        rows.iter()
                            .filter(|r| r.record.admission.function == s.row.function)
                            .count(),
                        self.k
                    );
                }
                RawIntervalOwner::Removed { generation } => {
                    assert!(reports.iter().any(|r| r.0 == generation))
                }
                RawIntervalOwner::InitialDisarmed => {}
            }
        }
    }
}
