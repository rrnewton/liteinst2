//! Copy live checked SDK observations into the oracle's primitive wire only.
use super::*;
use native::witness::{MAGIC, WORDS, Witness};
use rapid_profiler::frontend::{
    Action, ActionKind, HistoryBinding, Observation, Payload, PayloadOutcome, RecordObservation,
};
use rapid_profiler::frontend_native::{
    HistoryFormat, NormalCallPairAcknowledgement, NormalCallPairBatch, NormalCallPairHistoryBatch,
    NormalCallPairHistoryStream, NormalCallPairRecord, NormalCallPairTotals,
};
use rapid_profiler::generation::{Admission, CancelReason, Completion, Disposition, Terminal};
fn admission(a: Admission) -> [u64; 4] {
    [
        a.generation.get(),
        u64::try_from(a.invocation).unwrap(),
        a.function.0,
        a.entry_value,
    ]
}
fn disposition(d: Disposition) -> [u64; 2] {
    match d {
        Disposition::Retained { rank } => [1, u64::try_from(rank).unwrap()],
        Disposition::DroppedAfterBudget => [2, 0],
    }
}
fn reason(r: CancelReason) -> u64 {
    match r {
        CancelReason::Explicit => 1,
        CancelReason::DroppedTicket => 2,
    }
}
fn payload(p: Option<Payload>) -> [u64; 12] {
    let mut out = [0; 12];
    if let Some(p) = p {
        out[0] = 1;
        out[1..5].copy_from_slice(&admission(p.admission));
        out[5] = p.thread;
        out[6] = p.start_sequence;
        match p.outcome {
            PayloadOutcome::Completed {
                end,
                completed_children,
            } => {
                out[7] = 1;
                let (tag, value) = match end {
                    Observation::Value(v) => (1, v),
                    Observation::Unavailable(r) => (2, r),
                };
                out[8] = tag;
                out[9] = value;
                out[10] = completed_children;
            }
            PayloadOutcome::Cancelled(r) => {
                out[7] = 2;
                out[11] = reason(r);
            }
        }
    }
    out
}
fn completion(c: Option<Completion>) -> [u64; 12] {
    let mut out = [0; 12];
    if let Some(c) = c {
        out[0] = 1;
        out[1..5].copy_from_slice(&admission(c.admission));
        out[5..7].copy_from_slice(&disposition(c.disposition));
        if let Some(d) = c.deactivate {
            out[7..10].copy_from_slice(&[1, d.generation.get(), d.function.0]);
        }
        if let Some(n) = c.other_reservations_after_close {
            out[10..12].copy_from_slice(&[1, u64::try_from(n).unwrap()]);
        }
    }
    out
}
fn record(r: &NormalCallPairRecord) -> [u64; 48] {
    let raw = r.raw();
    let owner = match raw.owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => [1, generation, u64::try_from(invocation).unwrap()],
        RawIntervalOwner::InitialDisarmed => [2, 0, 0],
        RawIntervalOwner::Removed { generation } => [3, generation, 0],
        RawIntervalOwner::FunctionClosed { generation } => [4, generation, 0],
    };
    let ack = match r.acknowledgement() {
        NormalCallPairAcknowledgement::ChildContinuation => 1,
        NormalCallPairAcknowledgement::CallerCheckpoint => 2,
    };
    let mut out = [0; 48];
    out[..24].copy_from_slice(&[
        r.function().0,
        u64::try_from(r.node()).unwrap(),
        r.parent_ordinal(),
        raw.ordinal,
        raw.entry_pc,
        raw.return_pc,
        owner[0],
        owner[1],
        owner[2],
        raw.start.ticks,
        u64::from(raw.start.aux),
        raw.end.ticks,
        u64::from(raw.end.aux),
        r.entry_rsp(),
        r.return_word(),
        r.resume_pc(),
        r.resume_rsp(),
        r.value(),
        ack,
        r.history_prefix(),
        r.sequence_before(),
        r.actual_children(),
        u64::from(r.sampled_children().is_some()),
        r.sampled_children().unwrap_or(0),
    ]);
    out[24..36].copy_from_slice(&completion(r.completion()));
    out[36..48].copy_from_slice(&payload(r.payload()));
    out
}
fn stream(s: &NormalCallPairHistoryStream) -> [u64; 16] {
    assert_eq!(s.format(), HistoryFormat::AbsoluteV1);
    let id = s.identity();
    let hash: [u64; 4] = std::array::from_fn(|i| {
        u64::from_le_bytes(id.source.0[i * 8..i * 8 + 8].try_into().unwrap())
    });
    let edge = s.edge();
    [
        u64::from(s.pid()),
        s.install(),
        hash[0],
        hash[1],
        hash[2],
        hash[3],
        id.mapping,
        id.generation,
        s.functions()[0].0,
        s.functions()[1].0,
        s.entries()[0],
        s.entries()[1],
        edge[0],
        edge[1],
        edge[2],
        1,
    ]
}
fn observation(r: &RecordObservation) -> [u64; 22] {
    let mut out = [0; 22];
    out[..4].copy_from_slice(&admission(r.record.admission));
    if let Some(t) = r.record.terminal {
        out[4] = 1;
        match t {
            Terminal::Completed {
                value,
                disposition: d,
            } => {
                out[5] = 1;
                out[6] = value;
                out[7..9].copy_from_slice(&disposition(d));
            }
            Terminal::Cancelled(r) => {
                out[5] = 2;
                out[9] = reason(r);
            }
        }
    }
    out[10..].copy_from_slice(&payload(r.payload));
    out
}
fn binding(b: HistoryBinding) -> [u64; 3] {
    match b {
        HistoryBinding::Initial => [0, 0, 0],
        HistoryBinding::Published {
            action_index,
            generation,
        } => [1, action_index, generation.get()],
        HistoryBinding::Removed {
            action_index,
            generation,
        } => [2, action_index, generation.get()],
    }
}
fn action(a: &Action) -> [u64; 8] {
    let kind = match a.kind {
        ActionKind::Published => 1,
        ActionKind::Removed => 2,
        ActionKind::Stale => 3,
        ActionKind::Deferred => 4,
        ActionKind::Disabled => 5,
        ActionKind::FailedBefore => 6,
        ActionKind::FailedAfter => 7,
    };
    [
        kind,
        a.generation.get(),
        u64::from(a.function.is_some()),
        a.function.map_or(0, |f| f.0),
        u64::from(a.current.is_some()),
        a.current.map_or(0, |g| g.get()),
        u64::from(a.group.is_some()),
        a.group.map_or(0, |g| u64::try_from(g).unwrap()),
    ]
}
pub(super) struct FinalFacts {
    count: u64,
    reports: [[u64; 46]; 2],
    history: [u64; 50],
}
/// Values copied while the actual Reports and history chunk still live. No
/// Report/stream/receipt is constructed from these data on either side.
pub(super) fn copy_final(
    reports: &[(u64, Vec<RecordObservation>)],
    history: &NormalCallPairHistoryBatch,
) -> FinalFacts {
    assert!((1..=2).contains(&reports.len()));
    assert!((1..=2).contains(&reports.iter().map(|(_, r)| r.len()).sum::<usize>()));
    let mut out = FinalFacts {
        count: reports.len() as u64,
        reports: [[0; 46]; 2],
        history: [0; 50],
    };
    for ((generation, rows), target) in reports.iter().zip(&mut out.reports) {
        assert!((1..=2).contains(&rows.len()));
        target[..2].copy_from_slice(&[*generation, rows.len() as u64]);
        for (row, slot) in rows.iter().zip(target[2..].chunks_exact_mut(22)) {
            slot.copy_from_slice(&observation(row));
        }
    }
    out.history[..16].copy_from_slice(&stream(history.stream()));
    out.history[16..19].copy_from_slice(&[
        history.number(),
        history.range().start,
        history.range().end,
    ]);
    out.history[19..22].copy_from_slice(&binding(history.before()));
    out.history[22..25].copy_from_slice(&binding(history.after()));
    assert!((2..=3).contains(&history.actions().len()));
    out.history[25] = history.actions().len() as u64;
    for (a, slot) in history
        .actions()
        .iter()
        .zip(out.history[26..].chunks_exact_mut(8))
    {
        slot.copy_from_slice(&action(a));
    }
    out
}
fn totals(t: NormalCallPairTotals) -> [u64; 7] {
    [
        t.roots,
        t.child_acks,
        t.pairs.entered,
        t.pairs.ret_observed,
        t.pairs.confirmed,
        t.pairs.completed,
        t.pairs.unsampled,
    ]
}
pub(super) fn capture(
    ready: &Ready,
    seed: u64,
    batch: &NormalCallPairBatch,
    facts: FinalFacts,
) -> Witness {
    let case = ready.case;
    let index = native::keys()
        .iter()
        .position(|key| *key == (case.k, seed, case.index, case.scenario))
        .unwrap();
    let mut meta = [0; 20];
    meta[..6].copy_from_slice(&[
        u64::from(batch.pid()),
        batch.tid(),
        batch.registration(),
        batch.install(),
        batch.number(),
        batch.history_end(),
    ]);
    meta[6..13].copy_from_slice(&totals(batch.before()));
    meta[13..20].copy_from_slice(&totals(batch.after()));
    Witness {
        header: [
            MAGIC,
            1,
            WORDS as u64,
            index as u64,
            seed,
            case.k as u64,
            case.index as u64,
            case.scenario.id(),
            u64::from(batch.pid()),
            case.selections[0],
            case.extents[0] as u64,
            case.selections[1],
            case.extents[1] as u64,
            ready.caller,
            ready.plan.bytes().len() as u64,
            0,
        ],
        batch: meta,
        stream: stream(batch.stream()),
        rows: batch.records().each_ref().map(record),
        report_count: facts.count,
        reports: facts.reports,
        history: facts.history,
    }
}
