//! One selected-function admission; complete copied data, no callback authority.
use crate::oracle::native_ordinary::normal_caller::leaf_set_copied::{self as copied, Ready};
use liteinst2::contracts::{CodeIdentity, SourceIdentity};
use rapid_profiler::frontend::{
    Action, ActionKind, ControllerStatus, HistoryBinding, Observation, PayloadOutcome,
    RecordObservation,
};
use rapid_profiler::frontend_native::{
    HistoryFormat, NormalAcknowledgement, NormalModuleRecord, NormalTotals, RawIntervalOwner,
};
use rapid_profiler::generation::{Disposition, FunctionId, GenerationId, Terminal};
pub(super) const INSTALL: u64 = 0x6c73_7201;
pub(super) fn functions(ready: &Ready) -> Vec<FunctionId> {
    ready
        .case
        .table()
        .iter()
        .map(|(operation, _)| FunctionId(copied::FUNCTION_IDS[*operation]))
        .collect()
}
pub(super) fn identity(entry: u64) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([0x6c; 32]),
        mapping: entry,
        generation: 1,
    }
}
pub(super) fn totals(confirmed: u64) -> NormalTotals {
    assert!(confirmed <= 1);
    NormalTotals {
        entered: 1,
        ret_observed: 1,
        confirmed,
        completed: confirmed,
        unsampled: 0,
    }
}
#[derive(Clone)]
pub(super) struct Metadata {
    pub identity: CodeIdentity,
    pub functions: Vec<FunctionId>,
    pub entries: Vec<u64>,
    pub pid: u32,
    pub tid: u64,
    pub registration: u64,
    pub install: u64,
    pub number: u64,
    pub next: u64,
    pub sequences: (u64, u64),
    pub totals: (NormalTotals, NormalTotals),
}
pub(super) fn metadata(ready: &Ready, pid: u32, m: Metadata) {
    assert_ne!(pid, 0);
    let entries = ready.functions.iter().map(|f| f.entry).collect::<Vec<_>>();
    assert_eq!(
        (m.identity, m.functions, m.entries),
        (identity(entries[0]), functions(ready), entries)
    );
    assert_eq!(
        (m.pid, m.tid, m.registration, m.install),
        (pid, u64::from(pid), 1, INSTALL)
    );
    assert_eq!((m.number, m.next, m.sequences), (1, 2, (0, 1)));
    assert_eq!(m.totals, (NormalTotals::default(), totals(1)));
}
pub(super) fn rows(ready: &Ready, rsp: u64, pid: u32, rows: &[NormalModuleRecord], words: &[u64]) {
    assert_eq!(rows.len(), 1);
    let tagged = &rows[0];
    let r = &tagged.record;
    let generation = ready.journal.as_ref().unwrap().a_generation;
    assert_eq!(tagged.function, FunctionId(ready.case.function_id()));
    assert_eq!(
        (r.raw.ordinal, r.raw.entry_pc, r.history_prefix),
        (1, ready.target().entry, 1)
    );
    assert!(ready.target().returns.contains(&r.raw.return_pc));
    assert_eq!(
        r.raw.owner,
        RawIntervalOwner::Sampled {
            generation,
            invocation: 0
        }
    );
    assert_eq!(
        (r.entry_rsp, r.return_word),
        (
            rsp.checked_sub(ready.plan.subject_rsp_delta()).unwrap(),
            ready.caller + ready.plan.continuations()[0]
        )
    );
    assert_eq!(r.acknowledgement, NormalAcknowledgement::CallerCheckpoint);
    assert_eq!(
        words,
        copied::journal_words(ready, u64::from(pid), rsp, &[r.raw.return_pc], false)
    );
}
pub(super) fn records(
    ready: &Ready,
    rows: &[NormalModuleRecord],
    generation: u64,
    records: &[RecordObservation],
) {
    assert_eq!(rows.len(), 1);
    assert_eq!(records.len(), 1);
    assert_eq!(generation, ready.journal.as_ref().unwrap().a_generation);
    let raw = &rows[0].record.raw;
    let r = &records[0];
    let a = r.record.admission;
    assert_eq!(
        (a.generation.get(), a.function, a.invocation, a.entry_value),
        (
            generation,
            FunctionId(ready.case.function_id()),
            0,
            raw.start.ticks
        )
    );
    assert_eq!(rows[0].function, a.function);
    assert_eq!(
        raw.owner,
        RawIntervalOwner::Sampled {
            generation,
            invocation: 0
        }
    );
    assert_eq!(
        r.record.terminal,
        Some(Terminal::Completed {
            value: 0,
            disposition: Disposition::Retained { rank: 0 }
        })
    );
    let p = r.payload.unwrap();
    assert_eq!(p.admission, a);
    assert_eq!((p.thread, p.start_sequence), (1, 0));
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
}
#[derive(Clone)]
pub(super) struct Stream {
    pub pid: u32,
    pub install: u64,
    pub identity: CodeIdentity,
    pub functions: Vec<FunctionId>,
    pub entries: Vec<u64>,
    pub format: HistoryFormat,
}
pub(super) fn stream(ready: &Ready, pid: u32, s: &Stream) {
    assert_ne!(pid, 0);
    let entries: Vec<_> = ready.functions.iter().map(|f| f.entry).collect();
    assert_eq!(
        (
            s.pid,
            s.install,
            s.identity,
            &s.functions,
            &s.entries,
            s.format
        ),
        (
            pid,
            INSTALL,
            identity(entries[0]),
            &functions(ready),
            &entries,
            HistoryFormat::AbsoluteV1
        )
    );
}
#[derive(Clone)]
pub(super) struct Chunk {
    pub number: u64,
    pub range: std::ops::Range<u64>,
    pub before: HistoryBinding,
    pub after: HistoryBinding,
    pub actions: Vec<Action>,
}
pub(super) fn chunk(generation: GenerationId, published: bool, c: &Chunk) {
    let bound = HistoryBinding::Published {
        action_index: 0,
        generation,
    };
    let removed = HistoryBinding::Removed {
        action_index: 1,
        generation,
    };
    let (number, range, before, after, kind, current) = if published {
        (
            1,
            0..1,
            HistoryBinding::Initial,
            bound,
            ActionKind::Published,
            Some(generation),
        )
    } else {
        (2, 1..2, bound, removed, ActionKind::Removed, None)
    };
    assert_eq!(
        (c.number, &c.range, c.before, c.after),
        (number, &range, before, after)
    );
    assert_eq!(
        c.actions,
        [Action {
            kind,
            generation,
            function: None,
            current,
            group: None
        }]
    );
}
#[derive(Clone)]
pub(super) struct Window {
    pub number: u64,
    pub range: std::ops::Range<u64>,
    pub before: HistoryBinding,
    pub after: HistoryBinding,
    pub actions: Vec<Action>,
    pub status: ControllerStatus,
    pub current: Option<GenerationId>,
    pub enabled: Vec<bool>,
    pub failed: Option<GenerationId>,
}
pub(super) fn closed(removed: HistoryBinding, w: &Window) {
    assert!(matches!(
        removed,
        HistoryBinding::Removed {
            action_index: 1,
            ..
        }
    ));
    assert_eq!(
        (w.number, &w.range, w.before, w.after),
        (2, &(2..2), removed, removed)
    );
    assert!(w.actions.is_empty());
    assert_eq!(
        (w.status, w.current, w.failed),
        (ControllerStatus::Ready, None, None)
    );
    assert_eq!(w.enabled, [true]);
}
pub(super) fn banks(count: usize, reclaimed: bool) {
    assert_eq!(count, if reclaimed { 3 } else { 2 });
}
pub(super) fn watermark(high_water: u64) {
    assert_eq!(high_water, 1);
}
#[cfg(test)]
#[path = "check/tests.rs"]
mod tests;
