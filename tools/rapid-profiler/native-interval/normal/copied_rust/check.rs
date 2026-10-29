//! One selected-function admission; complete copied data, no callback authority.
use crate::oracle::native_ordinary::normal_caller::copied_rust::{self as copied, Ready};
use liteinst2::contracts::{CodeIdentity, SourceIdentity};
use rapid_profiler::frontend::{
    ActionKind, ControllerSnapshot, ControllerStatus, Observation, PayloadOutcome,
    RecordObservation,
};
use rapid_profiler::frontend_native::{
    NormalAcknowledgement, NormalModuleRecord, NormalTotals, RawIntervalOwner,
};
use rapid_profiler::generation::{Disposition, FunctionId, Terminal};
pub(super) const INSTALL: u64 = 0x7275_7301;
pub(super) const FUNCTIONS: [FunctionId; 2] = [FunctionId(71), FunctionId(72)];
pub(super) fn identity(entry: u64) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([0x69; 32]),
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
#[derive(Clone, Copy)]
pub(super) struct Metadata {
    pub identity: CodeIdentity,
    pub functions: [FunctionId; 2],
    pub entries: [u64; 2],
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
    let entries = ready.functions.each_ref().map(|f| f.entry);
    assert_eq!(
        (m.identity, m.functions, m.entries),
        (identity(entries[0]), FUNCTIONS, entries)
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
    assert_eq!(tagged.function, FUNCTIONS[ready.case.selected()]);
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
            FUNCTIONS[ready.case.selected()],
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
pub(super) fn history(snapshot: &ControllerSnapshot, generation: u64) {
    assert_eq!(snapshot.status, ControllerStatus::Ready);
    assert_eq!(snapshot.retained_failed_generation, None);
    assert_eq!(snapshot.current, None);
    assert_eq!(snapshot.enabled, [true]);
    assert_eq!(snapshot.actions.len(), 2);
    for (a, (kind, current)) in snapshot.actions.iter().zip([
        (ActionKind::Published, Some(generation)),
        (ActionKind::Removed, None),
    ]) {
        assert_eq!(
            (
                a.kind,
                a.generation.get(),
                a.current.map(|g| g.get()),
                a.function,
                a.group
            ),
            (kind, generation, current, None, None)
        );
    }
}
#[cfg(test)]
#[path = "check/tests.rs"]
mod tests;
