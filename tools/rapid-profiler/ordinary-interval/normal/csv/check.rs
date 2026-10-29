//! Immutable CSV joins only; no native return or checkpoint authority.
use super::*;
use rapid_profiler::frontend::{ActionKind, ControllerSnapshot, ControllerStatus};
use rapid_profiler::frontend_native::NormalRecord;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Identity,
    Population,
    Input,
    Value,
    Record,
    Stack,
    Clock,
    Journal,
    Report,
    History,
    Coverage,
}
pub(super) type Check = Result<(), Error>;
pub(super) fn require(ok: bool, error: Error) -> Check {
    if ok { Ok(()) } else { Err(error) }
}
pub(super) fn pending(n: u64) -> NormalTotals {
    assert!((1..=CALLS as u64).contains(&n));
    NormalTotals {
        entered: n,
        ret_observed: n,
        confirmed: n - 1,
        completed: n - 1,
        unsampled: 0,
    }
}
pub(super) fn complete() -> NormalTotals {
    NormalTotals {
        entered: 16,
        ret_observed: 16,
        confirmed: 16,
        completed: 16,
        unsampled: 0,
    }
}
#[derive(Clone, Copy)]
pub(super) struct Expected<'a> {
    pub pid: u32,
    pub tid: u64,
    pub entry: u64,
    pub end: u64,
    pub returns: &'a [u64],
    pub generation: u64,
    pub stack: (u64, u64),
    pub caller: (u64, u64),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Metadata {
    pub legacy: bool,
    pub pid: u32,
    pub tid: u64,
    pub registration: u64,
    pub install: u64,
    pub function: FunctionId,
    pub number: u64,
    pub totals: (NormalTotals, NormalTotals),
    pub sequences: (u64, u64),
    pub next: u64,
}
pub(super) fn metadata(e: Expected<'_>) -> Metadata {
    Metadata {
        legacy: true,
        pid: e.pid,
        tid: e.tid,
        registration: 1,
        install: INSTALL,
        function: FUNCTION,
        number: 1,
        totals: (NormalTotals::default(), complete()),
        sequences: (0, 16),
        next: 17,
    }
}
pub(super) fn batch(
    e: Expected<'_>,
    meta: Metadata,
    rows: &[NormalRecord],
    words: &[u64],
) -> Check {
    require(
        e.pid != 0
            && e.tid == u64::from(e.pid)
            && e.generation != 0
            && e.entry != 0
            && e.end
                .checked_sub(e.entry)
                .is_some_and(|n| (1..=256).contains(&n))
            && (1..=4).contains(&e.returns.len())
            && e.returns.iter().all(|&pc| e.entry < pc && pc < e.end)
            && e.returns.windows(2).all(|w| w[0] < w[1])
            && e.stack.0 != 0
            && e.stack.0 < e.stack.1
            && e.caller.0 != 0
            && e.caller.0 < e.caller.1
            && meta == metadata(e),
        Error::Identity,
    )?;
    require(rows.len() == CALLS, Error::Population)?;
    let mut journal = [0; 512];
    journal[..4].copy_from_slice(&[32, 0, e.tid, 0]);
    let mut covered = BTreeSet::new();
    for (i, r) in rows.iter().enumerate() {
        let ordinal = i as u64 + 1;
        require(
            r.raw.ordinal == ordinal
                && r.raw.entry_pc == e.entry
                && e.returns.contains(&r.raw.return_pc)
                && r.raw.owner
                    == (RawIntervalOwner::Sampled {
                        generation: e.generation,
                        invocation: i,
                    })
                && r.history_prefix == 1
                && r.acknowledgement
                    == (if i + 1 == CALLS {
                        NormalAcknowledgement::CallerCheckpoint
                    } else {
                        NormalAcknowledgement::NextEntry {
                            ordinal: ordinal + 1,
                        }
                    }),
            Error::Record,
        )?;
        // The normal runtime already matched the copied entry and pre-RET stack
        // words. This range/domain join is not an independent CALL/RET witness,
        // and no caller stack word is reread after its lifetime has ended.
        require(
            r.entry_rsp % 16 == 8
                && r.entry_rsp.checked_sub(128).is_some_and(|a| a >= e.stack.0)
                && r.entry_rsp.checked_add(8).is_some_and(|b| b <= e.stack.1)
                && e.caller.0 <= r.return_word
                && r.return_word < e.caller.1,
            Error::Stack,
        )?;
        require(r.raw.elapsed_ticks().is_some(), Error::Clock)?;
        covered.insert(r.raw.return_pc);
        let bits = ordinal | (1 << 13);
        let at = 4 + 14 * i;
        journal[at..at + 7].copy_from_slice(&[
            1,
            ordinal,
            e.entry,
            r.entry_rsp,
            r.return_word,
            e.generation,
            bits,
        ]);
        journal[at + 7..at + 14].copy_from_slice(&[
            2,
            ordinal,
            r.raw.return_pc,
            r.entry_rsp,
            r.return_word,
            e.generation,
            bits,
        ]);
    }
    require(
        covered.iter().copied().eq(e.returns.iter().copied()),
        Error::Coverage,
    )?;
    // Includes all four header words, 224 event words and 284 zero tail words.
    require(words == journal, Error::Journal)
}
pub(super) fn report(
    e: Expected<'_>,
    rows: &[NormalRecord],
    generation: u64,
    records: &[RecordObservation],
    h: &ControllerSnapshot,
) -> Check {
    require(
        rows.len() == CALLS && records.len() == CALLS,
        Error::Population,
    )?;
    require(generation == e.generation, Error::Report)?;
    for (i, (row, observed)) in rows.iter().zip(records).enumerate() {
        let a = observed.record.admission;
        require(
            a.generation.get() == e.generation
                && a.function == FUNCTION
                && a.invocation == i
                && a.entry_value == row.raw.start.ticks
                && observed.record.terminal
                    == Some(Terminal::Completed {
                        value: i as u64,
                        disposition: Disposition::Retained { rank: i },
                    }),
            Error::Report,
        )?;
        let p = observed.payload.ok_or(Error::Report)?;
        require(
            p.admission == a
                && p.thread == 1
                && p.start_sequence == i as u64
                && p.outcome
                    == (PayloadOutcome::Completed {
                        end: Observation::Value(row.raw.end.ticks),
                        completed_children: 0,
                    }),
            Error::Report,
        )?;
    }
    require(
        h.status == ControllerStatus::Ready
            && h.current.is_none()
            && h.enabled == [true]
            && h.retained_failed_generation.is_none()
            && h.actions.len() == 2,
        Error::History,
    )?;
    for (i, a) in h.actions.iter().enumerate() {
        require(
            a.generation.get() == e.generation
                && a.function.is_none()
                && a.group.is_none()
                && a.kind
                    == (if i == 0 {
                        ActionKind::Published
                    } else {
                        ActionKind::Removed
                    })
                && a.current.map(|g| g.get()) == (if i == 0 { Some(e.generation) } else { None }),
            Error::History,
        )?;
    }
    Ok(())
}
pub(super) fn validate(
    e: Expected<'_>,
    observed: &NormalBatch,
    reported: &Report,
    history: &ControllerSnapshot,
) -> Check {
    batch(
        e,
        Metadata {
            legacy: observed.history_stream().is_none() && observed.history_high_water().is_none(),
            pid: observed.pid(),
            tid: observed.tid(),
            registration: observed.registration(),
            install: observed.install(),
            function: observed.function(),
            number: observed.number(),
            totals: observed.totals(),
            sequences: observed.completed_sequences(),
            next: observed.next_ordinal(),
        },
        observed.records(),
        observed.journal(),
    )?;
    report(
        e,
        observed.records(),
        reported.generation().get(),
        &reported.records().collect::<Vec<_>>(),
        history,
    )
}
