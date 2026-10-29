//! Pure joins used by the actual child. Metadata controls do not mint owners.
use super::*;
use rapid_profiler::frontend::{
    Action, ActionKind, ControllerStatus, HistoryBinding, Observation, Payload, PayloadOutcome,
    RecordObservation,
};
use rapid_profiler::frontend_native::{
    HistoryFormat, NormalCallPairAcknowledgement as Ack, NormalCallPairBatch,
    NormalCallPairHistoryBatch, NormalCallPairRecord, NormalCallPairTotals, NormalTotals,
    RawInterval, RawIntervalOwner,
};
use rapid_profiler::generation::{Completion, Disposition, Terminal};
pub(super) fn identity(entry: u64) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([0xc5; 32]),
        mapping: entry,
        generation: 1,
    }
}
pub(super) fn totals(case: Case, finalized: bool) -> NormalCallPairTotals {
    let child = u64::from(case.scenario.sampled_child());
    let confirmed = 1 + u64::from(finalized);
    NormalCallPairTotals {
        roots: u64::from(finalized),
        child_acks: 1,
        pairs: NormalTotals {
            entered: 2,
            ret_observed: 2,
            confirmed,
            completed: child + u64::from(finalized),
            unsampled: 1 - child,
        },
    }
}
#[derive(Clone, Copy)]
pub(super) struct Row {
    pub function: FunctionId,
    pub node: usize,
    pub parent: u64,
    pub raw: RawInterval,
    pub rsp: u64,
    pub word: u64,
    pub resume: u64,
    pub resume_rsp: u64,
    pub value: u64,
    pub ack: Ack,
    pub prefix: u64,
    pub before: u64,
    pub actual: u64,
    pub sampled: Option<u64>,
    pub completion: Option<Completion>,
    pub payload: Option<Payload>,
}
impl Row {
    pub(super) fn from(r: &NormalCallPairRecord) -> Self {
        Self {
            function: r.function(),
            node: r.node(),
            parent: r.parent_ordinal(),
            raw: r.raw(),
            rsp: r.entry_rsp(),
            word: r.return_word(),
            resume: r.resume_pc(),
            resume_rsp: r.resume_rsp(),
            value: r.value(),
            ack: r.acknowledgement(),
            prefix: r.history_prefix(),
            before: r.sequence_before(),
            actual: r.actual_children(),
            sampled: r.sampled_children(),
            completion: r.completion(),
            payload: r.payload(),
        }
    }
}
fn end(raw: RawInterval) -> Observation {
    if raw.start.aux != raw.end.aux {
        Observation::Unavailable(1)
    } else if raw.end.ticks < raw.start.ticks {
        Observation::Unavailable(2)
    } else {
        Observation::Value(raw.end.ticks)
    }
}
pub(super) fn rows(ready: &Ready, rsp: u64, pid: u32, rows: &[Row; 2], journal: &[u64; 512]) {
    let j = ready.journal.as_ref().unwrap();
    let sampled = ready.case.scenario.sampled_child();
    let parent_delta = ready.plan.subject_rsp_delta();
    let child_delta = super::geometry(ready).2;
    for (n, r) in rows.iter().enumerate() {
        let f = &ready.functions[n];
        let expected_rsp = rsp
            .checked_sub(parent_delta + if n == 1 { child_delta } else { 0 })
            .unwrap();
        let word = if n == 0 {
            ready.caller + ready.plan.continuations()[0]
        } else {
            super::geometry(ready).1
        };
        assert_eq!(
            (r.function, r.node, r.parent, r.raw.ordinal, r.raw.entry_pc),
            (
                FunctionId(native::FUNCTIONS[n]),
                n,
                1,
                n as u64 + 1,
                f.entry
            )
        );
        assert!(f.returns.contains(&r.raw.return_pc));
        assert_eq!(
            (r.rsp, r.word, r.resume, r.resume_rsp),
            (expected_rsp, word, word, expected_rsp + 8)
        );
        assert_eq!(
            (r.value, r.ack, r.before, r.actual),
            (
                if n == 0 {
                    ready.case.value()
                } else {
                    ready.case.fields()
                },
                if n == 0 {
                    Ack::CallerCheckpoint
                } else {
                    Ack::ChildContinuation
                },
                0,
                if n == 0 { 1 } else { 0 }
            )
        );
        assert_eq!(
            r.prefix,
            if n == 0 || ready.case.scenario == Scenario::StableA {
                1
            } else {
                2
            }
        );
        if n == 0 || sampled {
            let generation = if n == 0 {
                j.a_generation
            } else {
                j.b_generation.unwrap_or(j.a_generation)
            };
            let invocation = if n == 1 && ready.case.scenario == Scenario::StableA {
                1
            } else {
                0
            };
            assert_eq!(
                r.raw.owner,
                RawIntervalOwner::Sampled {
                    generation,
                    invocation
                }
            );
            assert_eq!(r.sampled, Some(if n == 0 { u64::from(sampled) } else { 0 }));
            let c = r.completion.unwrap();
            assert_eq!(
                (
                    c.admission.generation.get(),
                    c.admission.function,
                    c.admission.invocation,
                    c.admission.entry_value
                ),
                (generation, r.function, invocation, r.raw.start.ticks)
            );
            assert_eq!(c.disposition, Disposition::Retained { rank: 0 });
            assert_eq!(
                (c.deactivate, c.other_reservations_after_close),
                (None, None)
            );
            let p = r.payload.unwrap();
            assert_eq!(p.admission, c.admission);
            assert_eq!((p.thread, p.start_sequence), (1, 0));
            assert_eq!(
                p.outcome,
                PayloadOutcome::Completed {
                    end: end(r.raw),
                    completed_children: r.sampled.unwrap()
                }
            );
        } else {
            assert_eq!(
                r.raw.owner,
                RawIntervalOwner::Removed {
                    generation: j.a_generation
                }
            );
            assert_eq!((r.sampled, r.completion, r.payload), (None, None, None));
        }
    }
    assert_eq!(
        *journal,
        native::journal(
            ready,
            u64::from(pid),
            rsp,
            Some(rows[1].raw.return_pc),
            Some(rows[0].raw.return_pc),
            4,
            0
        )
    );
}
pub(super) fn batch(ready: &Ready, rsp: u64, pid: u32, b: &NormalCallPairBatch) {
    assert_eq!(
        (b.pid(), b.tid(), b.registration(), b.install(), b.number()),
        (pid, u64::from(pid), 1, native::INSTALL, 1)
    );
    assert_eq!(b.before(), NormalCallPairTotals::default());
    assert_eq!(b.after(), totals(ready.case, true));
    assert_eq!(
        b.history_end(),
        match ready.case.scenario {
            Scenario::StableA => 1,
            Scenario::RearmB => 3,
            Scenario::RemovedChild => 2,
        }
    );
    let s = b.stream();
    assert_eq!(
        (
            s.pid(),
            s.install(),
            s.identity(),
            *s.functions(),
            *s.entries(),
            s.edge(),
            s.format()
        ),
        (
            pid,
            native::INSTALL,
            identity(ready.parent().entry),
            native::FUNCTIONS.map(FunctionId),
            ready.functions.each_ref().map(|f| f.entry),
            [geometry(ready).0, ready.child().entry, geometry(ready).1],
            HistoryFormat::AbsoluteV1
        )
    );
    rows(
        ready,
        rsp,
        pid,
        &b.records().each_ref().map(Row::from),
        b.journal(),
    );
}
pub(super) fn reports(ready: &Ready, rows: &[Row; 2], reports: &[(u64, Vec<RecordObservation>)]) {
    let j = ready.journal.as_ref().unwrap();
    assert_eq!(reports.len(), if j.b_generation.is_some() { 2 } else { 1 });
    let mut joined = 0;
    for (i, (generation, records)) in reports.iter().enumerate() {
        assert_eq!(
            *generation,
            if i == 0 {
                j.a_generation
            } else {
                j.b_generation.unwrap()
            }
        );
        let expected:Vec<_>=rows.iter().filter(|r|matches!(r.raw.owner,RawIntervalOwner::Sampled{generation:g,..} if g==*generation)).collect();
        assert_eq!(records.len(), expected.len());
        for (slot, (r, e)) in records.iter().zip(expected).enumerate() {
            let c = e.completion.unwrap();
            assert_eq!(c.admission.invocation, slot);
            assert_eq!(r.record.admission, c.admission);
            assert_eq!(
                r.record.terminal,
                Some(Terminal::Completed {
                    value: c.admission.invocation as u64,
                    disposition: c.disposition
                })
            );
            assert_eq!(r.payload, e.payload);
            joined += 1;
        }
    }
    assert_eq!(joined, 1 + usize::from(ready.case.scenario.sampled_child()));
}
pub(super) fn history(ready: &Ready, b: &NormalCallPairBatch, h: &NormalCallPairHistoryBatch) {
    assert_eq!(h.stream(), b.stream());
    assert_eq!(
        (h.number(), h.range(), h.before()),
        (
            1,
            0..if ready.case.scenario == Scenario::RearmB {
                3
            } else {
                2
            },
            HistoryBinding::Initial
        )
    );
    actions(ready, h.actions());
    for r in b.records() {
        match (r.raw().owner, h.binding_at(r.history_prefix())) {
            (
                RawIntervalOwner::Sampled { generation: g, .. },
                Some(HistoryBinding::Published {
                    generation,
                    action_index,
                }),
            )
            | (
                RawIntervalOwner::Removed { generation: g },
                Some(HistoryBinding::Removed {
                    generation,
                    action_index,
                }),
            ) => {
                assert_eq!(generation.get(), g);
                assert_eq!(action_index + 1, r.history_prefix());
            }
            _ => panic!("history owner join"),
        }
    }
}
pub(super) fn actions(ready: &Ready, actions: &[Action]) {
    let j = ready.journal.as_ref().unwrap();
    let expected = if let Some(b) = j.b_generation {
        vec![
            (ActionKind::Published, j.a_generation, Some(j.a_generation)),
            (ActionKind::Published, b, Some(b)),
            (ActionKind::Removed, b, None),
        ]
    } else {
        vec![
            (ActionKind::Published, j.a_generation, Some(j.a_generation)),
            (ActionKind::Removed, j.a_generation, None),
        ]
    };
    assert_eq!(actions.len(), expected.len());
    for (a, (kind, g, current)) in actions.iter().zip(expected) {
        assert_eq!(
            (
                a.kind,
                a.generation.get(),
                a.current.map(|g| g.get()),
                a.function,
                a.group
            ),
            (kind, g, current, None, None)
        );
    }
}
pub(super) fn final_history(
    controller: &NormalCallPairSessionController,
    ready: &Ready,
    batch: &NormalCallPairBatch,
    h: &NormalCallPairHistoryBatch,
) {
    history(ready, batch, h);
    let w = controller.history_window().unwrap();
    assert_eq!(w.stream(), h.stream());
    assert_eq!(
        (w.last_batch_number(), w.range(), w.before(), w.after()),
        (1, h.range().end..h.range().end, h.after(), h.after())
    );
    assert!(w.actions().is_empty());
    assert_eq!(w.status(), ControllerStatus::Ready);
    assert_eq!((w.current(), w.retained_failed_generation()), (None, None));
    assert_eq!(w.enabled(), [false]);
}
#[cfg(test)]
mod tests;
