//! Immutable complete joins; these copies supply no return or executable authority.
use super::*;
use rapid_profiler::frontend::{ActionKind, ControllerSnapshot, ControllerStatus};
use rapid_profiler::frontend_native::NormalModuleRecord;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Identity,
    Population,
    Record,
    Stack,
    Clock,
    Journal,
    Coverage,
    Report,
    History,
}
pub(super) type Check = Result<(), Error>;
fn require(ok: bool, error: Error) -> Check {
    if ok { Ok(()) } else { Err(error) }
}
#[derive(Clone, Copy)]
pub(super) struct Expected<'a> {
    pub identity: CodeIdentity,
    pub pid: u32,
    pub entries: [u64; 2],
    pub ends: [u64; 2],
    pub returns: [&'a [u64]; 2],
    pub generation: u64,
    pub k: usize,
    pub stack: (u64, u64),
    pub caller: (u64, u64),
}
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
pub(super) fn metadata(e: Expected<'_>) -> Metadata {
    Metadata {
        identity: e.identity,
        functions: FUNCTIONS,
        entries: e.entries,
        pid: e.pid,
        tid: u64::from(e.pid),
        registration: 1,
        install: INSTALL,
        number: 1,
        totals: (NormalTotals::default(), totals(32, 32, e.k)),
        sequences: (0, (e.k * 2) as u64),
        next: 33,
    }
}
pub(super) fn batch(
    e: Expected<'_>,
    meta: Metadata,
    rows: &[NormalModuleRecord],
    words: &[u64],
) -> Check {
    require(
        matches!(e.k, 1 | 16)
            && e.pid != 0
            && e.generation != 0
            && e.identity == identity(e.entries[0])
            && e.entries[0] != 0
            && e.ends[0] <= e.entries[1]
            && e.stack.0 != 0
            && e.stack.0 < e.stack.1
            && e.caller.0 != 0
            && e.caller.0 < e.caller.1,
        Error::Identity,
    )?;
    for f in 0..2 {
        require(
            e.ends[f]
                .checked_sub(e.entries[f])
                .is_some_and(|n| (5..=if f == 0 { 256 } else { 80 }).contains(&n))
                && (e.entries[f] & !4095) == (e.entries[0] & !4095)
                && ((e.ends[f] - 1) & !4095) == (e.entries[0] & !4095)
                && (1..=4).contains(&e.returns[f].len())
                && e.returns[f]
                    .iter()
                    .all(|&pc| e.entries[f] < pc && pc < e.ends[f])
                && e.returns[f].windows(2).all(|w| w[0] < w[1]),
            Error::Identity,
        )?;
    }
    require(meta == metadata(e), Error::Identity)?;
    require(rows.len() == CALLS, Error::Population)?;
    let mut journal = [0; 512];
    journal[..4].copy_from_slice(&[64, 0, u64::from(e.pid), 0]);
    let mut covered: [BTreeSet<u64>; 2] = std::array::from_fn(|_| BTreeSet::new());
    for (i, row) in rows.iter().enumerate() {
        let f = i % 2;
        let r = &row.record;
        let ordinal = i as u64 + 1;
        let sampled = i < 2 * e.k;
        let owner = if sampled {
            RawIntervalOwner::Sampled {
                generation: e.generation,
                invocation: i,
            }
        } else {
            RawIntervalOwner::FunctionClosed {
                generation: e.generation,
            }
        };
        require(
            row.function == FUNCTIONS[f]
                && r.raw.ordinal == ordinal
                && r.raw.entry_pc == e.entries[f]
                && e.returns[f].contains(&r.raw.return_pc)
                && r.raw.owner == owner
                && r.history_prefix == 1
                && r.acknowledgement
                    == if i + 1 == CALLS {
                        NormalAcknowledgement::CallerCheckpoint
                    } else {
                        NormalAcknowledgement::NextEntry {
                            ordinal: ordinal + 1,
                        }
                    },
            Error::Record,
        )?;
        require(
            r.entry_rsp % 16 == 8
                && r.entry_rsp.checked_sub(128).is_some_and(|a| a >= e.stack.0)
                && r.entry_rsp.checked_add(8).is_some_and(|b| b <= e.stack.1)
                && e.caller.0 <= r.return_word
                && r.return_word < e.caller.1,
            Error::Stack,
        )?;
        require(r.raw.elapsed_ticks().is_some(), Error::Clock)?;
        covered[f].insert(r.raw.return_pc);
        let (kind, bits) = if sampled {
            (1, ordinal | (1 << 13))
        } else {
            (3, (1 << 13) | (3 << 22))
        };
        let at = 4 + 14 * i;
        journal[at..at + 7].copy_from_slice(&[
            kind,
            ordinal,
            e.entries[f],
            r.entry_rsp,
            r.return_word,
            e.generation,
            bits,
        ]);
        journal[at + 7..at + 14].copy_from_slice(&[
            kind + 1,
            ordinal,
            r.raw.return_pc,
            r.entry_rsp,
            r.return_word,
            e.generation,
            bits,
        ]);
    }
    for (f, found) in covered.iter().enumerate() {
        require(
            found.iter().copied().eq(e.returns[f].iter().copied()),
            Error::Coverage,
        )?;
    }
    // All four header words, 448 event words and 60 zero tail words are exact.
    require(words == journal, Error::Journal)
}
pub(super) fn report(
    e: Expected<'_>,
    rows: &[NormalModuleRecord],
    generation: u64,
    records: &[RecordObservation],
    h: &ControllerSnapshot,
) -> Check {
    require(
        rows.len() == CALLS && records.len() == 2 * e.k,
        Error::Population,
    )?;
    require(generation == e.generation, Error::Report)?;
    for (i, observed) in records.iter().enumerate() {
        let row = &rows[i];
        let a = observed.record.admission;
        require(
            row.function == FUNCTIONS[i % 2]
                && a.function == row.function
                && a.generation.get() == e.generation
                && a.invocation == i
                && a.entry_value == row.record.raw.start.ticks
                && observed.record.terminal
                    == Some(Terminal::Completed {
                        value: i as u64,
                        disposition: Disposition::Retained { rank: i / 2 },
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
                        end: Observation::Value(row.record.raw.end.ticks),
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
    observed: &NormalModuleBatch,
    reported: &Report,
    h: &ControllerSnapshot,
) -> Check {
    batch(
        e,
        Metadata {
            identity: observed.identity(),
            functions: *observed.functions(),
            entries: *observed.entries(),
            pid: observed.pid(),
            tid: observed.tid(),
            registration: observed.registration(),
            install: observed.install(),
            number: observed.number(),
            totals: observed.totals(),
            sequences: observed.completed_sequences(),
            next: observed.next_ordinal(),
        },
        observed.records(),
        observed.journal(),
    )?;
    let records: Vec<_> = reported.records().collect();
    report(
        e,
        observed.records(),
        reported.generation().get(),
        &records,
        h,
    )
}
