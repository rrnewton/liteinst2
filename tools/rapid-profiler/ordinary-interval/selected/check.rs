//! Fixed population joins used by the real consumer and pure corruption controls.
use super::*;
use rapid_profiler::frontend::{ActionKind, ControllerSnapshot, ControllerStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Call,
    Owner,
    Batch,
    Report,
    History,
}

pub(super) struct Expected {
    pub originals: [u64; 8],
    pub entry: u64,
    pub returns: BTreeSet<u64>,
    pub continuation: u64,
    pub pid: u32,
    pub tid: u64,
    pub generations: [u64; 2],
}

#[derive(Clone)]
pub(super) struct Batch<'a> {
    pub identity: (u32, u64, u64, u64, FunctionId),
    pub number: u64,
    pub totals: (PairTotals, PairTotals),
    pub sequences: (u64, u64),
    pub next: u64,
    pub gate: u64,
    pub raw: std::ops::Range<u64>,
    pub events: std::ops::Range<u64>,
    pub legacy: bool,
    pub rows: &'a [RawInterval],
    pub journal: &'a [u64],
}
impl<'a> From<&'a IntervalBatch> for Batch<'a> {
    fn from(b: &'a IntervalBatch) -> Self {
        Self {
            identity: (
                b.pid(),
                b.tid(),
                b.registration(),
                b.install(),
                b.function(),
            ),
            number: b.number(),
            totals: b.totals(),
            sequences: b.completed_sequences(),
            next: b.next_ordinal(),
            gate: b.gate_sequence(),
            raw: b.raw_range(),
            events: b.event_range(),
            legacy: b.history_stream().is_none() && b.history_high_water().is_none(),
            rows: b.rows(),
            journal: b.journal(),
        }
    }
}

pub(super) fn prefix(index: usize) -> u64 {
    match index {
        0..=3 => 1,
        4 => 2,
        5..=7 => 3,
        _ => unreachable!(),
    }
}
pub(super) fn totals(n: usize) -> Result<PairTotals, Error> {
    let completed = *[0, 1, 2, 2, 2, 2, 3, 4, 4].get(n).ok_or(Error::Call)?;
    Ok(PairTotals {
        entries: n as u64,
        returns: n as u64,
        completed,
        unsampled: n as u64 - completed,
    })
}
pub(super) fn returned(
    index: usize,
    c: &CallResult,
    value: u64,
    returns: &BTreeSet<u64>,
    actual: PairTotals,
) -> Result<(), Error> {
    if index >= 8
        || c.value != value
        || !returns.contains(&c.return_pc)
        || c.pre_call_rsp % 16 != 0
        || c.pre_call_rsp.checked_sub(8) != Some(c.entry_rsp)
        || c.pre_call_rsp != c.resumed_rsp
        || actual != totals(index + 1)?
    {
        return Err(Error::Call);
    }
    Ok(())
}

pub(super) fn population(
    calls: &[CallResult],
    rows: &[RawInterval],
    b: &Batch<'_>,
    e: &Expected,
) -> Result<(), Error> {
    if calls.len() != 8
        || rows.len() != 8
        || e.entry == 0
        || e.continuation == 0
        || e.pid == 0
        || e.tid == 0
        || e.tid == u64::from(e.pid)
        || e.returns.is_empty()
        || e.generations[0] == 0
        || e.generations[0] >= e.generations[1]
    {
        return Err(Error::Call);
    }
    if b.identity != (e.pid, e.tid, 1, INSTALL, FUNCTION)
        || b.number != 1
        || b.totals != (PairTotals::default(), totals(8)?)
        || b.sequences != (0, 4)
        || b.next != 9
        || b.gate != 8
        || b.raw != (0..8)
        || b.events != (0..16)
        || !b.legacy
        || b.rows != rows
        || b.journal.len() != 512
    {
        return Err(Error::Batch);
    }
    let mut page = [0_u64; 512];
    page[0] = 16;
    page[2] = e.tid;
    let mut seen = BTreeSet::new();
    for (i, (c, r)) in calls.iter().zip(rows).enumerate() {
        returned(i, c, e.originals[i], &e.returns, totals(i + 1)?)?;
        if r.ordinal != i as u64 + 1
            || r.entry_pc != e.entry
            || r.return_pc != c.return_pc
            || r.elapsed_ticks().is_none()
        {
            return Err(Error::Call);
        }
        seen.insert(r.return_pc);
        let (generation, invocation, kind, reason) = match i {
            0 | 1 => (e.generations[0], Some(i), 1, 0),
            2 | 3 => (e.generations[0], None, 3, 3),
            4 => (e.generations[0], None, 3, 2),
            5 | 6 => (e.generations[1], Some(i - 5), 1, 0),
            7 => (e.generations[1], None, 3, 3),
            _ => unreachable!(),
        };
        let owner = match invocation {
            Some(invocation) => RawIntervalOwner::Sampled {
                generation,
                invocation,
            },
            None if i == 4 => RawIntervalOwner::Removed { generation },
            None => RawIntervalOwner::FunctionClosed { generation },
        };
        if r.owner != owner {
            return Err(Error::Owner);
        }
        let packed = invocation.map_or(0, |n| n as u64 + 1) | (prefix(i) << 13) | (reason << 22);
        for side in 0..2 {
            let at = 4 + (2 * i + side) * 7;
            page[at..at + 7].copy_from_slice(&[
                kind + side as u64,
                r.ordinal,
                if side == 0 { e.entry } else { c.return_pc },
                c.entry_rsp,
                e.continuation,
                generation,
                packed,
            ]);
        }
    }
    if seen != e.returns {
        return Err(Error::Call);
    }
    if b.journal != page {
        return Err(Error::Batch);
    }
    Ok(())
}

pub(super) fn records(
    rows: &[RawInterval],
    generation: u64,
    first_sequence: u64,
    records: &[RecordObservation],
) -> Result<(), Error> {
    if rows.len() != 8 || generation == 0 || records.len() != 2 || !matches!(first_sequence, 0 | 2)
    {
        return Err(Error::Report);
    }
    let (mut rank, mut sequence) = (0, 0);
    for row in rows {
        if let RawIntervalOwner::Sampled {
            generation: g,
            invocation,
        } = row.owner
        {
            if g == generation {
                let r = records.get(rank).ok_or(Error::Report)?;
                let a = r.record.admission;
                let p = r.payload.ok_or(Error::Report)?;
                if invocation != rank
                    || a.generation.get() != generation
                    || a.function != FUNCTION
                    || a.invocation != rank
                    || a.entry_value != row.start.ticks
                    || p.admission != a
                    || p.thread != 1
                    || sequence != first_sequence + rank as u64
                    || p.start_sequence != sequence
                    || r.record.terminal
                        != Some(Terminal::Completed {
                            value: rank as u64,
                            disposition: Disposition::Retained { rank },
                        })
                    || p.outcome
                        != (PayloadOutcome::Completed {
                            end: Observation::Value(row.end.ticks),
                            completed_children: 0,
                        })
                {
                    return Err(Error::Report);
                }
                rank += 1;
            }
            sequence += 1;
        }
    }
    if rank != 2 || sequence != 4 {
        return Err(Error::Report);
    }
    Ok(())
}

pub(super) fn history(h: &ControllerSnapshot, g: [u64; 2]) -> Result<(), Error> {
    if g[0] == 0
        || g[0] >= g[1]
        || h.status != ControllerStatus::Ready
        || h.current.is_some()
        || h.enabled != [true]
        || h.retained_failed_generation.is_some()
        || h.actions.len() != 4
    {
        return Err(Error::History);
    }
    for (i, a) in h.actions.iter().enumerate() {
        if a.kind
            != if i % 2 == 0 {
                ActionKind::Published
            } else {
                ActionKind::Removed
            }
            || a.generation.get() != g[i / 2]
            || a.current.map(|n| n.get()) != if i % 2 == 0 { Some(g[i / 2]) } else { None }
            || a.function.is_some()
            || a.group.is_some()
        {
            return Err(Error::History);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
