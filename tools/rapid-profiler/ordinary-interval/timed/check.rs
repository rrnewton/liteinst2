//! Pure joins over observed calls/actions and genuine final epoch records.
use rapid_profiler::frontend::{Observation, PayloadOutcome, RecordObservation};
use rapid_profiler::frontend_native::{CallResult, PairTotals, RawInterval, RawIntervalOwner};
use rapid_profiler::generation::{Disposition, FunctionId, Terminal};

#[derive(Clone, Copy, Debug)]
pub(super) struct Transition {
    pub index: usize,
    pub generation: u64,
    pub requested: u64,
    pub before: u64,
    pub after: u64,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Call {
    pub external_id: u64,
    pub length: usize,
    pub raw: RawInterval,
    pub call: CallResult,
    pub before: u64,
    pub after: u64,
}
pub(super) struct Expected {
    pub generations: [u64; 3],
    pub values: [u64; 24],
    pub entry: u64,
    pub ret: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Schedule,
    Call,
    Owner,
    Totals,
    Coverage,
    Report,
}

pub(super) fn calls(
    t: &[Transition],
    calls: &[Call],
    totals: PairTotals,
    windowend: u64,
    e: &Expected,
) -> Result<(usize, usize), Error> {
    if t.len() != 6
        || calls.len() != 24
        || e.generations.contains(&0)
        || e.generations[0] >= e.generations[1]
        || e.generations[1] >= e.generations[2]
    {
        return Err(Error::Schedule);
    }
    let base = t[0].after;
    let end = base.checked_add(120_000_000).ok_or(Error::Schedule)?;
    let deadline = base.checked_add(2_000_000_000).ok_or(Error::Schedule)?;
    if !(end..deadline).contains(&windowend) {
        return Err(Error::Schedule);
    }
    for (i, a) in t.iter().enumerate() {
        let requested = if i == 0 {
            0
        } else {
            base.checked_add([0, 30, 40, 70, 80, 110][i] * 1_000_000)
                .ok_or(Error::Schedule)?
        };
        if a.index != i
            || a.generation != e.generations[i / 2]
            || a.requested != requested
            || a.before < requested
            || a.after < a.before
            || a.after >= deadline
            || (i > 0 && t[i - 1].after > a.before)
        {
            return Err(Error::Schedule);
        }
    }
    let (mut sampled, mut unsampled) = (0, 0);
    let mut ranks = [0; 3];
    let mut covered = [false; 6];
    let mut previous_binding = 0;
    for (i, c) in calls.iter().enumerate() {
        let r = c.raw;
        let requested = base
            .checked_add((40 * (i / 8) as u64 + [2, 7, 12, 17, 22, 27, 32, 37][i % 8]) * 1_000_000)
            .ok_or(Error::Schedule)?;
        if c.external_id != i as u64 + 1000
            || r.ordinal != i as u64 + 1
            || c.length != if i % 2 == 0 { 1 } else { 64 }
            || c.call.value != e.values[i]
            || r.entry_pc != e.entry
            || r.return_pc != e.ret
            || c.call.return_pc != e.ret
            || c.call.pre_call_rsp % 16 != 0
            || c.call.pre_call_rsp.checked_sub(8) != Some(c.call.entry_rsp)
            || c.call.pre_call_rsp != c.call.resumed_rsp
            || r.start.aux != r.end.aux
            || r.end.ticks < r.start.ticks
            || c.before < requested
            || c.before > c.after
            || c.after >= deadline
            || (i > 0 && calls[i - 1].after > c.before)
        {
            return Err(Error::Call);
        }
        let (generation, is_sampled) = match r.owner {
            RawIntervalOwner::Sampled { generation, .. } => (generation, true),
            RawIntervalOwner::Removed { generation } => (generation, false),
            _ => return Err(Error::Owner),
        };
        let epoch = e
            .generations
            .iter()
            .position(|&g| g == generation)
            .ok_or(Error::Owner)?;
        let binding = epoch * 2 + usize::from(!is_sampled);
        if binding < previous_binding {
            return Err(Error::Owner);
        }
        previous_binding = binding;
        if is_sampled {
            if r.owner
                != (RawIntervalOwner::Sampled {
                    generation,
                    invocation: ranks[epoch],
                })
            {
                return Err(Error::Owner);
            }
            ranks[epoch] += 1;
            sampled += 1;
        } else {
            unsampled += 1;
        }
        // Conservative possible binding lifetime, not a measured linearization time.
        let latest = t.get(binding + 1).map_or(u64::MAX, |next| next.after);
        if c.after < t[binding].before || c.before > latest {
            return Err(Error::Owner);
        }
        for j in 0..6 {
            let right = t.get(j + 1).map_or(windowend, |next| next.before);
            if c.before > t[j].after && c.after < right {
                if binding != j {
                    return Err(Error::Owner);
                }
                covered[j] = true;
            }
        }
    }
    if totals
        != (PairTotals {
            entries: 24,
            returns: 24,
            completed: sampled as u64,
            unsampled: unsampled as u64,
        })
    {
        return Err(Error::Totals);
    }
    if !covered.into_iter().all(|v| v) {
        return Err(Error::Coverage);
    }
    Ok((sampled, unsampled))
}

pub(super) fn reports(
    calls: &[Call],
    records: &[Vec<RecordObservation>; 3],
    e: &Expected,
) -> Result<(), Error> {
    let mut ranks = [0; 3];
    let mut sequence = 0;
    for c in calls {
        let RawIntervalOwner::Sampled {
            generation,
            invocation,
        } = c.raw.owner
        else {
            continue;
        };
        let epoch = e
            .generations
            .iter()
            .position(|&g| g == generation)
            .ok_or(Error::Report)?;
        let rank = ranks[epoch];
        let record = records[epoch].get(rank).ok_or(Error::Report)?;
        let a = record.record.admission;
        let payload = record.payload.ok_or(Error::Report)?;
        if invocation != rank
            || a.generation.get() != generation
            || a.function != FunctionId(1)
            || a.invocation != rank
            || a.entry_value != c.raw.start.ticks
            || record.record.terminal
                != Some(Terminal::Completed {
                    value: rank as u64,
                    disposition: Disposition::Retained { rank },
                })
            || payload.admission != a
            || payload.thread != 1
            || payload.start_sequence != sequence
            || payload.outcome
                != (PayloadOutcome::Completed {
                    end: Observation::Value(c.raw.end.ticks),
                    completed_children: 0,
                })
        {
            return Err(Error::Report);
        }
        ranks[epoch] += 1;
        sequence += 1;
    }
    if records.iter().zip(ranks).any(|(r, n)| r.len() != n) {
        return Err(Error::Report);
    }
    Ok(())
}

#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;
