//! Complete copied module accounting. Actual CALL/RET authority stays in the walk.
use crate::oracle::native_ordinary::normal_caller::module::{
    self as native_module, Case, Ready, bytes,
};
use liteinst2::contracts::{CodeIdentity, SourceIdentity};
use rapid_profiler::frontend::{Observation, PayloadOutcome};
use rapid_profiler::frontend_native::{NormalTotals, RawIntervalOwner};
use rapid_profiler::generation::{Disposition, FunctionId, Terminal};
pub(super) const INSTALL: u64 = 0x6d6f_6401;
pub(super) const FUNCTIONS: [FunctionId; 2] = [FunctionId(71), FunctionId(72)];
pub(super) fn identity(entry: u64) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([0x6d; 32]),
        mapping: entry,
        generation: 1,
    }
}
use rapid_profiler::frontend::RecordObservation;
use rapid_profiler::frontend_native::{NormalAcknowledgement, NormalModuleRecord};
pub(super) fn totals(case: Case, confirmed: u64) -> NormalTotals {
    assert!(confirmed <= 4);
    let completed = confirmed.min(case.admitted() as u64);
    NormalTotals {
        entered: 4,
        ret_observed: 4,
        confirmed,
        completed,
        unsampled: confirmed - completed,
    }
}
pub(super) fn rows(
    ready: &Ready,
    rsp: u64,
    pid: u32,
    records: &[NormalModuleRecord],
    words: &[u64],
) {
    assert_eq!(records.len(), 4);
    let generation = ready.journal.as_ref().unwrap().a_generation;
    let mut returns = Vec::new();
    for (i, tagged) in records.iter().enumerate() {
        let r = &tagged.record;
        let f = ready.target(i);
        let ordinal = i as u64 + 1;
        assert_eq!(tagged.function, FUNCTIONS[ready.case.function(i)]);
        assert_eq!(
            (r.raw.ordinal, r.raw.entry_pc, r.history_prefix),
            (ordinal, f.entry, 1)
        );
        assert!(f.returns.contains(&r.raw.return_pc));
        returns.push(r.raw.return_pc);
        let owner = if i < ready.case.admitted() {
            RawIntervalOwner::Sampled {
                generation,
                invocation: i,
            }
        } else {
            RawIntervalOwner::FunctionClosed { generation }
        };
        assert_eq!(r.raw.owner, owner);
        assert_eq!(
            (r.entry_rsp, r.return_word),
            (
                rsp - bytes::SUBJECT_RSP_DELTA,
                ready.caller + bytes::CONTINUATIONS[i]
            )
        );
        assert_eq!(
            r.acknowledgement,
            if i == 3 {
                NormalAcknowledgement::CallerCheckpoint
            } else {
                NormalAcknowledgement::NextEntry {
                    ordinal: ordinal + 1,
                }
            }
        );
    }
    assert_eq!(
        words,
        native_module::journal_words(ready, u64::from(pid), rsp, &returns, false)
    );
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
    let entries = ready.functions.each_ref().map(|f| f.entry);
    assert_ne!(pid, 0);
    assert_eq!(
        (m.identity, m.functions, m.entries),
        (identity(entries[0]), FUNCTIONS, entries)
    );
    assert_eq!(
        (m.pid, m.tid, m.registration, m.install),
        (pid, u64::from(pid), 1, INSTALL)
    );
    assert_eq!(
        (m.number, m.next, m.sequences),
        (1, 5, (0, ready.case.admitted() as u64))
    );
    assert_eq!(m.totals, (NormalTotals::default(), totals(ready.case, 4)));
}
pub(super) fn records(
    ready: &Ready,
    rows: &[NormalModuleRecord],
    generation: u64,
    records: &[RecordObservation],
) {
    assert_eq!(rows.len(), 4);
    assert_eq!(records.len(), ready.case.admitted());
    assert_eq!(generation, ready.journal.as_ref().unwrap().a_generation);
    for (i, r) in records.iter().enumerate() {
        let row = &rows[i];
        let raw = &row.record.raw;
        let a = r.record.admission;
        assert_eq!(
            (a.generation.get(), a.function, a.invocation, a.entry_value),
            (
                generation,
                FUNCTIONS[ready.case.function(i)],
                i,
                raw.start.ticks
            )
        );
        assert_eq!(row.function, a.function);
        assert_eq!(
            raw.owner,
            RawIntervalOwner::Sampled {
                generation,
                invocation: i
            }
        );
        assert_eq!(
            r.record.terminal,
            Some(Terminal::Completed {
                value: i as u64,
                disposition: Disposition::Retained { rank: i / 2 }
            })
        );
        let p = r.payload.unwrap();
        assert_eq!(p.admission, a);
        assert_eq!((p.thread, p.start_sequence), (1, i as u64));
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
}
#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;
