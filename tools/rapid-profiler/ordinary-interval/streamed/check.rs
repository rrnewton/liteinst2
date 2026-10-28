//! Pure finite joins. Nominal 120/40 ownership is never substituted for observations.
use super::*;

pub(super) const CALLS: usize = 160;
pub(super) const EPOCHS: usize = 20;
pub(super) const BATCHES: usize = 40;
pub(super) const INSTALL: u64 = 0x7374_7201;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Schedule,
    Call,
    Owner,
    Coverage,
    Batch,
    Report,
    Reuse,
    Native,
    Full,
    Disconnected,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Call {
    pub id: u64,
    pub length: usize,
    pub raw: RawInterval,
    pub call: CallResult,
    pub before: u64,
    pub after: u64,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Transition {
    pub index: usize,
    pub generation: u64,
    pub requested: u64,
    pub before: u64,
    pub after: u64,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Retired {
    pub epoch: usize,
    pub generation: u64,
    pub checkpoint: u64,
    pub before: u64,
    pub after: u64,
    pub staged_after: Option<u64>,
    pub record_start: usize,
    pub record_end: usize,
}
#[derive(Clone)]
pub(super) struct Expected {
    pub values: [u64; CALLS],
    pub entry: u64,
    pub ret: u64,
    pub continuation: u64,
    pub pid: u32,
    pub tid: u64,
}
pub(super) struct Batch<'a> {
    pub identity: (u32, u64, u64, u64, FunctionId),
    pub number: u64,
    pub totals: (PairTotals, PairTotals),
    pub sequences: (u64, u64),
    pub next: u64,
    pub gate: u64,
    pub raw: std::ops::Range<u64>,
    pub events: std::ops::Range<u64>,
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
            rows: b.rows(),
            journal: b.journal(),
        }
    }
}
pub(super) fn action_ms(index: usize) -> u64 {
    40 * (index / 2) as u64 + if index % 2 == 0 { 0 } else { 30 }
}
pub(super) fn call_ms(index: usize) -> u64 {
    40 * (index / 8) as u64 + [2, 7, 12, 17, 22, 27, 32, 37][index % 8]
}
pub(super) fn cutoff(base: u64, replacement: usize) -> Result<u64, Error> {
    if !(3..EPOCHS).contains(&replacement) {
        return Err(Error::Schedule);
    }
    base.checked_add((40 * replacement as u64 - 10) * 1_000_000)
        .ok_or(Error::Schedule)
}
fn binding(owner: RawIntervalOwner, generations: &[u64; EPOCHS]) -> Result<usize, Error> {
    let (g, sampled) = match owner {
        RawIntervalOwner::Sampled { generation, .. } => (generation, true),
        RawIntervalOwner::Removed { generation } => (generation, false),
        _ => return Err(Error::Owner),
    };
    if g == 0 {
        return Err(Error::Owner);
    }
    let epoch = generations
        .iter()
        .position(|&n| n == g)
        .ok_or(Error::Owner)?;
    Ok(2 * epoch + usize::from(!sampled))
}
pub(super) fn totals(calls: &[Call]) -> PairTotals {
    let sampled = calls
        .iter()
        .filter(|c| matches!(c.raw.owner, RawIntervalOwner::Sampled { .. }))
        .count() as u64;
    PairTotals {
        entries: calls.len() as u64,
        returns: calls.len() as u64,
        completed: sampled,
        unsampled: calls.len() as u64 - sampled,
    }
}
pub(super) fn call_shape(i: usize, c: &Call, base: u64, e: &Expected) -> Result<(), Error> {
    let requested = base
        .checked_add(call_ms(i) * 1_000_000)
        .ok_or(Error::Schedule)?;
    let deadline = base.checked_add(2_000_000_000).ok_or(Error::Schedule)?;
    if i >= CALLS
        || c.id != 1000 + i as u64
        || c.raw.ordinal != i as u64 + 1
        || c.length != if i % 2 == 0 { 1 } else { 64 }
        || c.call.value != e.values[i]
        || c.raw.entry_pc != e.entry
        || c.raw.return_pc != e.ret
        || c.call.return_pc != e.ret
        || c.call.pre_call_rsp % 16 != 0
        || c.call.pre_call_rsp.checked_sub(8) != Some(c.call.entry_rsp)
        || c.call.pre_call_rsp != c.call.resumed_rsp
        || c.raw.elapsed_ticks().is_none()
        || c.before < requested
        || c.before > c.after
        || c.after >= deadline
    {
        return Err(Error::Call);
    }
    Ok(())
}
pub(super) fn prefix(
    t: &[Transition],
    calls: &[Call],
    g: &[u64; EPOCHS],
    e: &Expected,
) -> Result<[usize; 40], Error> {
    if t.is_empty() || t.len() > 40 || calls.len() > CALLS {
        return Err(Error::Schedule);
    }
    let base = t[0].after;
    let deadline = base.checked_add(2_000_000_000).ok_or(Error::Schedule)?;
    let mut last = 0;
    for &value in g.iter().filter(|&&n| n != 0) {
        if value <= last {
            return Err(Error::Owner);
        }
        last = value;
    }
    for (i, a) in t.iter().enumerate() {
        let requested = if i == 0 {
            0
        } else {
            base.checked_add(action_ms(i) * 1_000_000)
                .ok_or(Error::Schedule)?
        };
        if a.index != i
            || a.generation == 0
            || a.generation != g[i / 2]
            || a.requested != requested
            || a.before < requested
            || a.after < a.before
            || a.after >= deadline
            || (i > 0 && t[i - 1].after > a.before)
        {
            return Err(Error::Schedule);
        }
    }
    let mut ranks = [0; EPOCHS];
    let mut previous_binding = 0;
    let mut covered = [0; 40];
    for (i, c) in calls.iter().enumerate() {
        call_shape(i, c, base, e)?;
        if i > 0 && calls[i - 1].after > c.before {
            return Err(Error::Call);
        }
        let b = binding(c.raw.owner, g)?;
        if b < previous_binding || b >= t.len() {
            return Err(Error::Owner);
        }
        previous_binding = b;
        if let RawIntervalOwner::Sampled {
            generation,
            invocation,
        } = c.raw.owner
        {
            if invocation != ranks[b / 2] || generation != g[b / 2] {
                return Err(Error::Owner);
            }
            ranks[b / 2] += 1;
        }
        // Literal timed-profile conservative bracket; no fabricated linearization time.
        let latest = t.get(b + 1).map_or(u64::MAX, |next| next.after);
        if c.after < t[b].before || c.before > latest {
            return Err(Error::Owner);
        }
        for j in 0..t.len().saturating_sub(1) {
            if c.before > t[j].after && c.after < t[j + 1].before {
                if b != j {
                    return Err(Error::Owner);
                }
                covered[j] += 1;
            }
        }
    }
    Ok(covered)
}
pub(super) fn batch(
    b: &Batch<'_>,
    calls: &[Call],
    g: &[u64; EPOCHS],
    e: &Expected,
    g0: u64,
) -> Result<(), Error> {
    let end = calls.len();
    if end == 0 || end > CALLS || end % 4 != 0 {
        return Err(Error::Batch);
    }
    let start = end - 4;
    let before = totals(&calls[..start]);
    let after = totals(calls);
    if b.identity != (e.pid, e.tid, 1, INSTALL, FUNCTION)
        || b.number != (end / 4) as u64
        || b.totals != (before, after)
        || b.sequences != (before.completed, after.completed)
        || b.next != end as u64 + 1
        || b.gate != g0.checked_add(end as u64).ok_or(Error::Batch)?
        || b.raw != (start as u64..end as u64)
        || b.events != (2 * start as u64..2 * end as u64)
        || b.rows.len() != 4
        || b.journal.len() != 512
    {
        return Err(Error::Batch);
    }
    let mut page = [0_u64; 512];
    page[0] = 8;
    page[2] = e.tid;
    for (local, c) in calls[start..].iter().enumerate() {
        if b.rows[local] != c.raw {
            return Err(Error::Batch);
        }
        let binding = binding(c.raw.owner, g)?;
        let (kind, generation, inv, reason) = match c.raw.owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation,
            } => (1, generation, invocation as u64 + 1, 0),
            RawIntervalOwner::Removed { generation } => (3, generation, 0, 2),
            _ => return Err(Error::Owner),
        };
        let bits = inv | ((binding as u64 + 1) << 13) | (reason << 22);
        for side in 0..2 {
            let at = 4 + (local * 2 + side) * 7;
            page[at..at + 7].copy_from_slice(&[
                kind + side as u64,
                c.raw.ordinal,
                if side == 0 { e.entry } else { c.call.return_pc },
                c.call.entry_rsp,
                e.continuation,
                generation,
                bits,
            ]);
        }
    }
    if b.journal != page {
        return Err(Error::Batch);
    }
    Ok(())
}
pub(super) fn report(
    calls: &[Call],
    generation: u64,
    records: &[RecordObservation],
) -> Result<(), Error> {
    let mut rank = 0;
    let mut sequence = 0;
    for c in calls {
        if let RawIntervalOwner::Sampled {
            generation: g,
            invocation,
        } = c.raw.owner
        {
            if g == generation {
                let r = records.get(rank).ok_or(Error::Report)?;
                let a = r.record.admission;
                let p = r.payload.ok_or(Error::Report)?;
                if invocation != rank
                    || a.generation.get() != g
                    || a.function != FUNCTION
                    || a.invocation != rank
                    || a.entry_value != c.raw.start.ticks
                    || p.admission != a
                    || p.thread != 1
                    || p.start_sequence != sequence
                    || r.record.terminal
                        != Some(Terminal::Completed {
                            value: rank as u64,
                            disposition: Disposition::Retained { rank },
                        })
                    || p.outcome
                        != (PayloadOutcome::Completed {
                            end: Observation::Value(c.raw.end.ticks),
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
    if rank != records.len() {
        return Err(Error::Report);
    }
    Ok(())
}
pub(super) fn reuse(
    r: &Retired,
    t: &[Transition],
    calls: &[Call],
    g: &[u64; EPOCHS],
) -> Result<(), Error> {
    if r.epoch >= EPOCHS {
        return Err(Error::Reuse);
    }
    let disarm = t.get(2 * r.epoch + 1).ok_or(Error::Reuse)?;
    let checkpoint = calls
        .iter()
        .find(|c| c.raw.ordinal == r.checkpoint)
        .ok_or(Error::Reuse)?;
    if r.generation != g[r.epoch]
        || checkpoint.before <= disarm.after
        || checkpoint.after > r.before
        || r.before > r.after
        || r.record_start > r.record_end
        || r.after >= t[0].after + 2_000_000_000
    {
        return Err(Error::Reuse);
    }
    if r.epoch + 3 < EPOCHS {
        let staged = r.staged_after.ok_or(Error::Reuse)?;
        if staged < r.after
            || staged >= cutoff(t[0].after, r.epoch + 3)?
            || g[r.epoch + 3] <= r.generation
        {
            return Err(Error::Reuse);
        }
    } else if r.staged_after.is_some() {
        return Err(Error::Reuse);
    }
    Ok(())
}
pub(super) fn finish(
    t: &[Transition],
    calls: &[Call],
    g: &[u64; EPOCHS],
    e: &Expected,
    owners: (&[Retired], &[RecordObservation]),
    windowend: u64,
    actual: PairTotals,
) -> Result<[usize; 40], Error> {
    let (retired, records) = owners;
    if t.len() != 40 || calls.len() != CALLS || retired.len() != EPOCHS || g.contains(&0) {
        return Err(Error::Schedule);
    }
    let base = t[0].after;
    if !(base + 800_000_000..base + 2_000_000_000).contains(&windowend) || actual != totals(calls) {
        return Err(Error::Schedule);
    }
    let mut coverage = prefix(t, calls, g, e)?;
    for c in calls {
        if c.before > t[39].after && c.after < windowend {
            if binding(c.raw.owner, g)? != 39 {
                return Err(Error::Owner);
            }
            coverage[39] += 1;
        }
    }
    if coverage.contains(&0) {
        return Err(Error::Coverage);
    }
    if calls.iter().any(|c| c.after > windowend) {
        return Err(Error::Schedule);
    }
    if retired.iter().any(|r| r.after > windowend) {
        return Err(Error::Schedule);
    }
    let mut end = 0;
    for (i, r) in retired.iter().enumerate() {
        if r.epoch != i || r.record_start != end {
            return Err(Error::Reuse);
        }
        reuse(r, t, calls, g)?;
        report(
            calls,
            g[i],
            records
                .get(r.record_start..r.record_end)
                .ok_or(Error::Report)?,
        )?;
        end = r.record_end;
    }
    if end != records.len() || records.len() != actual.completed as usize {
        return Err(Error::Report);
    }
    Ok(coverage)
}

#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;
