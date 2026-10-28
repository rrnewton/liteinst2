//! Exact native-control observations. No production validator is called here.
use super::*;

pub(super) fn ready(state: &Snapshot, worker: usize) {
    assert_eq!(state.pid, std::process::id());
    assert!(state.tid != 0);
    assert_eq!(state.registration, worker as u64 + 1);
    assert_eq!(state.model, (state.registration, 0, 0));
    assert_eq!(state.totals, NormalTotals::default());
    assert_eq!(state.cursor, Cursor::default());
    assert_eq!(state.next, 1);
    assert_eq!(state.len, 0);
    assert!(state.pending.is_none());
    assert!(state.records.iter().all(Option::is_none));
    let mut page = [0; 512];
    page[2] = state.tid;
    assert_eq!(state.journal, page);
    assert_eq!(state.journal_address % 4096, 0);
    assert!(state.failure.is_none() && !state.busy);
}
fn words(raw: RawInterval, rsp: u64, word: u64, prefix: u64, depth: u64) -> [u64; 512] {
    let (kind, generation, inv1, reason) = match raw.owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => (1, generation, invocation as u64 + 1, 0),
        RawIntervalOwner::FunctionClosed { generation } => (3, generation, 0, 3),
        _ => panic!("exact native control owner population"),
    };
    assert!(inv1 <= 4096);
    assert!(prefix <= 12);
    let bits = inv1 | ((prefix & 511) << 13) | (reason << 22) | ((prefix >> 9) << 24);
    let mut page = [0; 512];
    page[0] = 2;
    page[3] = depth;
    page[4..11].copy_from_slice(&[kind, raw.ordinal, raw.entry_pc, rsp, word, generation, bits]);
    page[11..18].copy_from_slice(&[
        kind + 1,
        raw.ordinal,
        raw.return_pc,
        rsp,
        word,
        generation,
        bits,
    ]);
    page
}
pub(super) fn returned(
    state: &Snapshot,
    initial: &Snapshot,
    shared: &Shared,
    ordinal: u64,
    generation: u64,
    invocation: Option<usize>,
    prefix: u64,
) {
    assert_eq!(
        (
            state.pid,
            state.tid,
            state.registration,
            state.actual_thread,
            state.journal_address
        ),
        (
            initial.pid,
            initial.tid,
            initial.registration,
            initial.actual_thread,
            initial.journal_address
        )
    );
    assert_eq!(ordinal, if invocation.is_some() { 1 } else { 2 });
    let previous = ordinal - 1;
    let before = NormalTotals {
        entered: previous,
        ret_observed: previous,
        confirmed: previous,
        completed: previous,
        unsampled: 0,
    };
    assert_eq!(
        state.cursor,
        Cursor {
            number: previous,
            totals: before,
            sequence: previous
        }
    );
    assert_eq!(
        state.totals,
        NormalTotals {
            entered: ordinal,
            ret_observed: ordinal,
            ..before
        }
    );
    assert_eq!(
        state.model,
        (
            state.registration,
            usize::from(invocation.is_some()),
            previous
        )
    );
    assert_eq!(state.next, ordinal + 1);
    assert_eq!(state.len, 0);
    assert!(state.records.iter().all(Option::is_none));
    assert!(state.failure.is_none() && !state.busy);
    let pending = state.pending.as_ref().unwrap();
    let raw = pending.raw.unwrap();
    assert_eq!(pending.ordinal, ordinal);
    assert_eq!(pending.slot.identity, ordinal);
    assert_eq!(pending.entry, shared.entry);
    assert_eq!(pending.start, raw.start);
    assert_eq!(pending.summary, pending.receipt_summary);
    assert_eq!(raw.ordinal, ordinal);
    assert_eq!(raw.entry_pc, shared.entry);
    assert_eq!(
        raw.return_pc,
        shared.entry + if state.registration == 1 { 40 } else { 34 }
    );
    assert!(shared.returns.contains(&raw.return_pc));
    assert_eq!(pending.rsp % 16, 8);
    assert_ne!(pending.word, 0);
    assert!(
        raw.elapsed_ticks().is_some(),
        "endpoint consistency only, no calibrated accuracy"
    );
    let expected_owner = if let Some(invocation) = invocation {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        }
    } else {
        RawIntervalOwner::FunctionClosed { generation }
    };
    assert_eq!(raw.owner, expected_owner);
    match pending.summary.unwrap() {
        IntervalEntrySummary::Admitted {
            generation: actual,
            invocation: slot,
            history_len,
            binding,
        } if invocation == Some(slot) => {
            assert_eq!(actual.get(), generation);
            assert_eq!(history_len as u64, prefix);
            assert!(
                matches!(binding, BindingChange::Published { action_index, generation: g }
                    if action_index as u64 + 1 == prefix && g.get() == generation)
            );
        }
        IntervalEntrySummary::Unsampled {
            reason:
                UnsampledSummary::FunctionClosed {
                    generation: actual,
                    function,
                },
            history_len,
            binding,
        } if invocation.is_none() => {
            assert_eq!(actual.get(), generation);
            assert_eq!(function, FUNCTION);
            assert_eq!(history_len as u64, prefix);
            assert!(
                matches!(binding, BindingChange::Published { action_index, generation: g }
                    if action_index as u64 + 1 == prefix && g.get() == generation)
            );
            assert_eq!(pending.slot.word, TOKEN);
        }
        other => panic!("wrong native receipt summary: {other:?}"),
    }
    let mut page = words(raw, pending.rsp, pending.word, prefix, 1);
    page[2] = state.tid;
    assert_eq!(state.journal, page); // Includes complete zero tail before confirmation.
}
pub(super) fn batch(
    batch: &NormalBatch,
    before: &Snapshot,
    stream: &HistoryStream,
    history: &[HistoryBatch],
    shared: &Shared,
) {
    let pending = before.pending.as_ref().unwrap();
    let raw = pending.raw.unwrap();
    assert_eq!(batch.pid(), before.pid);
    assert_eq!(batch.tid(), before.tid);
    assert_eq!(batch.registration(), before.registration);
    assert_eq!(batch.install(), INSTALL);
    assert_eq!(batch.function(), FUNCTION);
    assert_eq!(batch.history_stream(), Some(stream));
    assert_eq!(batch.history_high_water(), Some(history.len() as u64));
    assert_eq!(batch.number(), before.cursor.number + 1);
    assert_eq!(batch.next_ordinal(), before.next);
    assert_eq!(batch.records().len(), 1);
    let sampled = u64::from(matches!(raw.owner, RawIntervalOwner::Sampled { .. }));
    let after = NormalTotals {
        entered: before.totals.entered,
        ret_observed: before.totals.ret_observed,
        confirmed: before.totals.confirmed + 1,
        completed: before.totals.completed + sampled,
        unsampled: before.totals.unsampled + 1 - sampled,
    };
    assert_eq!(batch.totals(), (before.cursor.totals, after));
    assert_eq!(
        batch.completed_sequences(),
        (before.cursor.sequence, after.completed)
    );
    let row = &batch.records()[0];
    assert_eq!(row.raw, raw);
    assert_eq!(row.entry_rsp, pending.rsp);
    assert_eq!(row.return_word, pending.word);
    assert_eq!(row.acknowledgement, NormalAcknowledgement::CallerCheckpoint);
    assert_eq!(row.raw.entry_pc, shared.entry);
    assert!(shared.returns.contains(&row.raw.return_pc));
    let prefix = match pending.summary.unwrap() {
        IntervalEntrySummary::Admitted { history_len, .. }
        | IntervalEntrySummary::Unsampled { history_len, .. } => history_len as u64,
    };
    assert_eq!(row.history_prefix, prefix);
    let generation = match raw.owner {
        RawIntervalOwner::Sampled { generation, .. }
        | RawIntervalOwner::FunctionClosed { generation } => generation,
        _ => panic!("native owner"),
    };
    let bindings: Vec<_> = history
        .iter()
        .filter_map(|chunk| chunk.binding_at(prefix))
        .collect();
    assert!(!bindings.is_empty());
    assert!(bindings.iter().all(
        |b| matches!(b, HistoryBinding::Published { generation: g, .. } if g.get() == generation)
    ));
    let mut page = words(raw, pending.rsp, pending.word, prefix, 0);
    page[2] = before.tid;
    assert_eq!(batch.journal(), page); // ALL512, independently rebuilt and complete zero tail.
}
pub(super) fn report(report: &Report, expected: &[(usize, Disposition)], batches: &[NormalBatch]) {
    let rows: Vec<_> = report.records().collect();
    assert_eq!(rows.len(), expected.len());
    let mut seen = BTreeSet::new();
    for &(index, disposition) in expected {
        let batch = &batches[index];
        let native = &batch.records()[0];
        let RawIntervalOwner::Sampled {
            generation,
            invocation,
        } = native.raw.owner
        else {
            panic!("report only admitted native rows");
        };
        assert!(seen.insert(invocation));
        assert_eq!(report.generation().get(), generation);
        let row = &rows[invocation];
        let admission = row.record.admission;
        assert_eq!(admission.generation.get(), generation);
        assert_eq!(admission.function, FUNCTION);
        assert_eq!(admission.invocation, invocation);
        assert_eq!(admission.entry_value, native.raw.start.ticks);
        assert_eq!(
            row.record.terminal,
            Some(Terminal::Completed {
                value: invocation as u64,
                disposition
            })
        );
        let payload = row.payload.unwrap();
        assert_eq!(payload.admission, admission);
        assert_eq!(payload.thread, batch.registration());
        assert_eq!(payload.start_sequence, batch.completed_sequences().0);
        assert_eq!(
            payload.outcome,
            PayloadOutcome::Completed {
                end: native.raw.observation(),
                completed_children: 0
            }
        );
        assert!(native.raw.elapsed_ticks().is_some());
    }
    assert_eq!(seen, (0..rows.len()).collect());
}
