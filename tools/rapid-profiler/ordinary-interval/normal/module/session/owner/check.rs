//! Exact owner-control facts; fabricated facts do not establish a native return.
use super::*;
use rapid_profiler::frontend::{Action, ActionKind};
use rapid_profiler::frontend_native::{
    HistoryBinding, NormalModuleHistoryStream, NormalModuleRecord,
};
use shared::epoch_storage::{OutputSnapshot, SlotSnapshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Metadata {
    pub identity: CodeIdentity,
    pub functions: [FunctionId; 2],
    pub entries: [u64; 2],
    pub pid: u32,
    pub tid: u64,
    pub registration: u64,
    pub install: u64,
    pub number: u64,
    pub totals: (NormalTotals, NormalTotals),
    pub sequences: (u64, u64),
    pub next: u64,
}
pub(super) struct Population {
    pub k: usize,
    pub hot: usize,
    pub generations: [u64; 2],
    pub entries: [u64; 2],
    pub ends: [u64; 2],
    pub returns: [Vec<u64>; 2],
    pub id: worker::Identity,
    pub rows: Vec<super::super::check::Seen>,
    pub totals: NormalTotals,
    pub batches: u64,
}
impl Population {
    pub fn join(
        &mut self,
        m: Metadata,
        rows: &[NormalModuleRecord],
        journal: &[u64],
        bindings: &[HistoryBinding],
        high: u64,
    ) {
        assert!(matches!(self.k, 10 | 1000) && self.hot < 2);
        assert_eq!(
            (m.identity, m.functions, m.entries),
            (identity(self.entries[0]), FUNCTIONS, self.entries)
        );
        assert_eq!(
            (m.pid, m.tid, m.registration, m.install),
            (self.id.pid, self.id.tid, 1, INSTALL)
        );
        assert_eq!(m.number, self.batches + 1);
        assert_eq!(m.totals.0, self.totals);
        let h = self.k.div_ceil(4) as u64;
        assert!(m.number <= h + 2);
        let count = if m.number <= h {
            (self.k - (m.number as usize - 1) * 4).min(4)
        } else if m.number == h + 1 {
            1
        } else {
            2
        };
        assert_eq!(rows.len(), count);
        assert_eq!(bindings.len(), count);
        assert_eq!(high, if m.number == h + 2 { 3 } else { 1 });
        let copied: Vec<_> = rows.iter().map(|r| r.record).collect();
        shared::check::check_journal(&copied, journal, self.id.tid);
        let before = self.totals.completed;
        for (i, row) in rows.iter().enumerate() {
            let ordinal = self.rows.len() as u64 + 1;
            let k = self.k as u64;
            assert!(ordinal <= k + 3);
            let f = if ordinal == k + 1 || ordinal == k + 3 {
                1 - self.hot
            } else {
                self.hot
            };
            let r = row.record;
            let raw = r.raw;
            let second = ordinal == k + 3;
            let generation = self.generations[usize::from(second)];
            assert_ne!(generation, 0);
            let prefix = if second { 2 } else { 1 };
            assert_eq!(row.function, FUNCTIONS[f]);
            assert_eq!(raw.ordinal, ordinal);
            assert_eq!(raw.entry_pc, self.entries[f]);
            assert!(self.returns[f].contains(&raw.return_pc));
            assert!(self.entries[f] < raw.return_pc && raw.return_pc < self.ends[f]);
            assert_eq!(r.entry_rsp % 16, 8);
            assert!(
                r.entry_rsp
                    .checked_sub(128)
                    .is_some_and(|a| a >= self.id.stack.0)
            );
            assert!(
                r.entry_rsp
                    .checked_add(8)
                    .is_some_and(|b| b <= self.id.stack.1)
            );
            assert!(self.id.caller.0 <= r.return_word && r.return_word < self.id.caller.1);
            assert_eq!(r.history_prefix, prefix);
            assert!(
                matches!(bindings[i], HistoryBinding::Published { action_index, generation: g }
                if action_index == prefix - 1 && g.get() == generation)
            );
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
            let closed = ordinal == k + 2;
            let rank = if closed {
                assert_eq!(raw.owner, RawIntervalOwner::FunctionClosed { generation });
                None
            } else {
                let invocation = if second { 0 } else { ordinal as usize - 1 };
                assert_eq!(
                    raw.owner,
                    RawIntervalOwner::Sampled {
                        generation,
                        invocation
                    }
                );
                Some(if ordinal <= k {
                    ordinal as usize - 1
                } else {
                    0
                })
            };
            self.rows.push(super::super::check::Seen {
                id: 1,
                row: *row,
                sequence: self.totals.completed,
                rank,
            });
            self.totals.entered += 1;
            self.totals.ret_observed += 1;
            self.totals.confirmed += 1;
            self.totals.completed += u64::from(!closed);
            self.totals.unsampled += u64::from(closed);
        }
        assert_eq!(m.totals.1, self.totals);
        assert_eq!(m.sequences, (before, self.totals.completed));
        assert_eq!(m.next, self.totals.confirmed + 1);
        self.batches += 1;
    }
}
pub(super) struct Ledger {
    pub population: Population,
    pub stream: NormalModuleHistoryStream,
    pub record: Arc<input::Record>,
    pub journals: Vec<[u64; 512]>,
}
impl Ledger {
    pub fn batch(
        &mut self,
        calls: &[worker::Call],
        b: &NormalModuleBatch,
        history: &[NormalModuleHistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        self.record.check();
        assert_eq!(b.history_stream(), Some(&self.stream));
        let high = b.history_high_water().expect("absolute owner history");
        assert_eq!(calls.len(), b.records().len());
        for call in calls {
            call.check();
            assert!(Arc::ptr_eq(&call.record, &self.record));
            assert_eq!(call.record.as_ref(), self.record.as_ref());
        }
        let bindings: Vec<_> = b
            .records()
            .iter()
            .map(|r| {
                assert!(r.record.history_prefix <= high);
                assert_eq!(high, history.last().unwrap().range().end);
                history
                    .iter()
                    .rev()
                    .find_map(|h| {
                        assert_eq!(h.stream(), &self.stream);
                        h.binding_at(r.record.history_prefix)
                    })
                    .expect("complete original history")
            })
            .collect();
        let meta = Metadata {
            identity: b.identity(),
            functions: *b.functions(),
            entries: *b.entries(),
            pid: b.pid(),
            tid: b.tid(),
            registration: b.registration(),
            install: b.install(),
            number: b.number(),
            totals: b.totals(),
            sequences: b.completed_sequences(),
            next: b.next_ordinal(),
        };
        let start = self.population.rows.len();
        self.population
            .join(meta, b.records(), b.journal(), &bindings, high);
        self.journals
            .push(b.journal().try_into().expect("all 512 journal words"));
        for (seen, call) in self.population.rows[start..].iter().zip(calls) {
            let r = seen.row.record;
            let raw = r.raw;
            let f = FUNCTIONS
                .iter()
                .position(|&f| f == seen.row.function)
                .unwrap();
            assert_eq!(call.function, f);
            let expected = if f == 0 { 3 } else { 5 };
            assert_eq!(call.value(), expected);
            let (owner, generation, invocation) = match raw.owner {
                RawIntervalOwner::Sampled {
                    generation,
                    invocation,
                } => ("sampled", generation, invocation as u64 + 1),
                RawIntervalOwner::FunctionClosed { generation } => ("closed", generation, 0),
                _ => panic!("owner control admits no other owner"),
            };
            io.emit(format!(
                "CALL,{},{f},{expected},{},{generation},{owner},{invocation},{},{}\n",
                raw.ordinal,
                call.value(),
                r.history_prefix,
                self.population.batches
            ))?;
            let (ack, next) = match r.acknowledgement {
                NormalAcknowledgement::CallerCheckpoint => ("checkpoint", 0),
                NormalAcknowledgement::NextEntry { ordinal } => ("next", ordinal),
            };
            io.emit(format!(
                "RAW,{},{},{},{},{},{},{},{},{ack},{next}\n",
                raw.ordinal,
                r.entry_rsp,
                r.return_word,
                raw.return_pc - self.population.entries[f],
                raw.start.ticks,
                raw.end.ticks,
                raw.start.aux,
                raw.end.aux
            ))?;
        }
        Ok(())
    }
    pub fn finish(&self, engine: &Engine, events: &[Message], io: &mut Io) -> Result<(), String> {
        let p = &self.population;
        assert_eq!(p.rows.len(), p.k + 3);
        assert_eq!(p.totals, expected_totals(p.k, 5));
        assert_eq!(p.batches, p.k.div_ceil(4) as u64 + 2);
        assert_eq!(self.journals.len() as u64, p.batches);
        check_history(&engine.history, &self.stream, p.generations);
        engine.final_check()?;
        assert_eq!(engine.committed_arms, 2);
        assert!(engine.current.is_none() && engine.epochs.iter().all(Option::is_none));
        assert_eq!(engine.banks.len(), 3);
        assert_eq!(engine.reports.len(), 2);
        let mut actual_calls = 0;
        for message in events {
            if let Message::Batch(shared::worker::Event::Batch { calls, native }) = message {
                assert_eq!(calls.len(), native.records().len());
                for c in calls {
                    c.check();
                    assert!(Arc::ptr_eq(&c.record, &self.record));
                }
                actual_calls += calls.len();
            }
        }
        assert_eq!(actual_calls, p.k + 3);
        self.record.check();
        for (at, (generation, rows)) in engine.reports.iter().enumerate() {
            assert_eq!(*generation, p.generations[at]);
            assert_eq!(rows.len(), if at == 0 { p.k + 1 } else { 1 });
            super::super::check::report_shape(*generation, rows, p.k * 2);
            for (invocation, row) in rows.iter().enumerate() {
                let ordinal = if at == 0 { invocation } else { p.k + 2 };
                let seen = p.rows[ordinal];
                let end = super::super::check::sample(row, seen);
                let f = FUNCTIONS
                    .iter()
                    .position(|&f| f == seen.row.function)
                    .unwrap();
                let (kind, value) = match end {
                    Observation::Value(n) => ("value", n),
                    Observation::Unavailable(n) => ("unavailable", n),
                };
                io.emit(format!(
                    "SAMPLE,{generation},{f},{invocation},{},{},{},{kind},{value}\n",
                    seen.rank.unwrap(),
                    seen.sequence,
                    row.record.admission.entry_value
                ))?;
            }
        }
        Ok(())
    }
}
fn check_history(
    history: &[NormalModuleHistoryBatch],
    stream: &NormalModuleHistoryStream,
    g: [u64; 2],
) {
    assert_eq!(history.len(), 3);
    assert!(g[0] > 0 && g[1] > g[0]);
    for (i, h) in history.iter().enumerate() {
        assert_eq!(h.stream(), stream);
        assert_eq!(h.number(), i as u64 + 1);
        assert_eq!(h.range(), i as u64..i as u64 + 1);
        if i == 0 {
            assert_eq!(h.before(), HistoryBinding::Initial);
        } else {
            assert!(h.follows(&history[i - 1]));
        }
        assert_eq!(h.actions().len(), 1);
        let action = h.actions()[0];
        assert_eq!(
            action.kind,
            if i == 2 {
                ActionKind::Removed
            } else {
                ActionKind::Published
            }
        );
        assert_eq!(action.generation.get(), g[usize::from(i != 0)]);
        assert_eq!(
            action.current.map(|v| v.get()),
            if i == 2 { None } else { Some(g[i]) }
        );
        assert_eq!((action.function, action.group), (None, None));
        assert_eq!(
            h.after(),
            if i == 2 {
                HistoryBinding::Removed {
                    action_index: 2,
                    generation: action.generation,
                }
            } else {
                HistoryBinding::Published {
                    action_index: i as u64,
                    generation: action.generation,
                }
            }
        );
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HistorySnapshot {
    pub number: u64,
    pub range: std::ops::Range<u64>,
    pub before: HistoryBinding,
    pub after: HistoryBinding,
    pub actions: Vec<Action>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Held {
    pub slot: SlotSnapshot,
    pub reports: Vec<(u64, Vec<RecordObservation>)>,
    pub history: Vec<HistorySnapshot>,
    pub banks: usize,
    pub current: Option<usize>,
    pub worker: WorkerState,
}
impl Held {
    pub fn capture(
        engine: &Engine,
        a: usize,
        worker: WorkerState,
        stream: &NormalModuleHistoryStream,
    ) -> Self {
        Self {
            slot: engine.epochs[a].as_ref().unwrap().snapshot(),
            reports: engine.reports.clone(),
            history: engine
                .history
                .iter()
                .map(|h| {
                    assert_eq!(h.stream(), stream); // Borrow opaque key; no extra retained epoch owner.
                    HistorySnapshot {
                        number: h.number(),
                        range: h.range(),
                        before: h.before(),
                        after: h.after(),
                        actions: h.actions().to_vec(),
                    }
                })
                .collect(),
            banks: engine.banks.len(),
            current: engine.current,
            worker,
        }
    }
    pub fn unchanged(&self, after: &Self) {
        assert_eq!(self, after);
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PhaseState {
    pub totals: NormalTotals,
    pub batches: u64,
    pub banks: u64,
    pub current: u64,
    pub history: u64,
    pub reports: u64,
    pub copies: u64,
    pub refusals: u64,
    pub a_slot: u64,
    pub b_slot: u64,
    pub a_index: u64,
    pub a_output: u64,
    pub checkpoints: u64,
    pub reclaimed: u64,
    pub b_report: u64,
    pub detach: u64,
    pub joins: u64,
}
pub(super) const PHASES: [&str; 6] = [
    "hot-exhaust",
    "cold-available",
    "held",
    "refused-twice",
    "released-before-checkpoint",
    "finish",
];
pub(super) fn expected_totals(k: usize, phase: usize) -> NormalTotals {
    assert!(matches!(k, 10 | 1000) && phase < 6);
    let k = k as u64;
    let (n, confirmed, completed, unsampled) = match phase {
        0 => (k, k, k, 0),
        1 => (k + 1, k + 1, k + 1, 0),
        2 | 3 => (k + 2, k + 1, k + 1, 0),
        4 => (k + 3, k + 2, k + 1, 1),
        5 => (k + 3, k + 3, k + 2, 1),
        _ => unreachable!(),
    };
    NormalTotals {
        entered: n,
        ret_observed: n,
        confirmed,
        completed,
        unsampled,
    }
}
impl PhaseState {
    pub fn expected(k: usize, phase: usize, g: [u64; 2]) -> Self {
        let h = k.div_ceil(4) as u64;
        assert!(g[0] > 0 && (phase < 3 || g[1] > g[0]));
        Self {
            totals: expected_totals(k, phase),
            batches: h + u64::from(phase > 0) + u64::from(phase == 5),
            banks: [2, 2, 2, 1, 2, 3][phase],
            current: if phase < 3 {
                g[0]
            } else if phase == 3 {
                g[1]
            } else {
                0
            },
            history: [1, 1, 1, 2, 3, 3][phase],
            reports: [0, 0, 0, 1, 1, 2][phase],
            copies: u64::from(phase >= 3),
            refusals: if phase >= 3 { 2 } else { 0 },
            a_slot: u64::from(phase < 4),
            b_slot: u64::from(matches!(phase, 3 | 4)),
            a_index: u64::from(phase == 3),
            a_output: u64::from(phase == 3),
            checkpoints: h + u64::from(phase > 0) + if phase == 5 { 2 } else { 0 },
            reclaimed: u64::from(phase >= 4),
            b_report: if phase < 4 {
                0
            } else if phase == 4 {
                1
            } else {
                2
            },
            detach: u64::from(phase == 5),
            joins: u64::from(phase == 5),
        }
    }
    pub fn check(&self, k: usize, phase: usize, g: [u64; 2]) {
        assert_eq!(*self, Self::expected(k, phase, g));
    }
    pub fn emit(&self, phase: usize, io: &mut Io) -> Result<(), String> {
        let t = self.totals;
        io.emit(format!(
            "PHASE,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            PHASES[phase],
            t.entered,
            t.ret_observed,
            t.confirmed,
            t.completed,
            t.unsampled,
            self.batches,
            self.banks,
            self.current,
            self.history,
            self.reports,
            self.copies,
            self.refusals,
            self.a_slot,
            self.b_slot,
            self.a_index,
            self.a_output,
            self.checkpoints,
            self.reclaimed,
            ["not-checked", "pending", "copied"][self.b_report as usize],
            self.detach,
            self.joins
        ))
    }
}
pub(super) fn copied_state(
    slot: Option<&shared::epoch_storage::Slot<rapid_profiler::frontend_native::IntervalEpoch>>,
) -> (u64, u64) {
    slot.and_then(|s| s.snapshot().copied)
        .map_or((0, 0), |(_, index, _, output)| {
            (
                index as u64 + 1,
                u64::from(output == OutputSnapshot::Emitted),
            )
        })
}
