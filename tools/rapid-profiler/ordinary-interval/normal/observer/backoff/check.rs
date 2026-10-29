//! Independent complete mixed-owner checks; no clock selects an epoch.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Fault {
    Identity,
    Population,
    Record,
    Stack,
    Clock,
    Journal,
    History,
    Report,
}
pub(super) type Checked<T = ()> = Result<T, Fault>;
fn need(ok: bool, fault: Fault) -> Checked {
    if ok { Ok(()) } else { Err(fault) }
}
#[derive(Clone, Copy)]
pub(super) struct Facts {
    pub pid: u32,
    pub entry: u64,
    pub caller: u64,
    pub stack: (u64, u64),
    pub k: usize,
}
#[derive(Clone, Copy)]
pub(super) struct Meta {
    pub stream: bool,
    pub high: Option<u64>,
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
impl Meta {
    pub fn actual(b: &NormalBatch, stream: &HistoryStream) -> Self {
        Self {
            stream: b.history_stream() == Some(stream),
            high: b.history_high_water(),
            pid: b.pid(),
            tid: b.tid(),
            registration: b.registration(),
            install: b.install(),
            function: b.function(),
            number: b.number(),
            totals: b.totals(),
            sequences: b.completed_sequences(),
            next: b.next_ordinal(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Counts {
    pub sampled: u64,
    pub closed: u64,
    pub generations: usize,
    pub after_closed: bool,
}
pub(super) fn high_water(previous: u64, current: Option<u64>, arms: u32) -> Checked<u64> {
    let current = current.ok_or(Fault::History)?;
    need(
        (1..=EPOCHS).contains(&arms)
            && current != 0
            && current >= previous
            && current <= u64::from(arms),
        Fault::History,
    )?;
    Ok(current)
}
pub(super) fn owner(raw: RawIntervalOwner, k: usize) -> Checked<(u64, Option<usize>)> {
    match raw {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } if generation != 0 && invocation < k => Ok((generation, Some(invocation))),
        RawIntervalOwner::FunctionClosed { generation } if generation != 0 => {
            Ok((generation, None))
        }
        _ => Err(Fault::Record),
    }
}
pub(super) fn batch(
    f: Facts,
    b: usize,
    m: Meta,
    rows: &[NormalRecord],
    words: &[u64],
    before: NormalTotals,
) -> Checked<NormalTotals> {
    need(b < BLOCKS && rows.len() == BLOCK, Fault::Population)?;
    need(
        matches!(f.k, 10 | 1000)
            && f.pid != 0
            && f.pid <= i32::MAX as u32
            && f.entry != 0
            && f.entry.checked_add(37).is_some()
            && f.caller != 0
            && f.caller.checked_add(67).is_some()
            && f.stack.0 != 0
            && f.stack.0 < f.stack.1
            && m.stream
            && m.high.is_some_and(|n| (1..=521).contains(&n))
            && (
                m.pid,
                m.tid,
                m.registration,
                m.install,
                m.function,
                m.number,
            ) == (f.pid, u64::from(f.pid), 1, INSTALL, FUNCTION, b as u64 + 1)
            && m.totals.0 == before
            && before.entered == (b * BLOCK) as u64
            && before.ret_observed == before.entered
            && before.confirmed == before.entered
            && before.completed.checked_add(before.unsampled) == Some(before.entered),
        Fault::Identity,
    )?;
    let mut totals = before;
    let mut journal = [0_u64; 512];
    journal[..4].copy_from_slice(&[48, 0, u64::from(f.pid), 0]);
    for (i, r) in rows.iter().enumerate() {
        let ordinal = (b * BLOCK + i + 1) as u64;
        let (generation, inv) = owner(r.raw.owner, f.k)?;
        need(
            r.raw.ordinal == ordinal
                && r.raw.entry_pc == f.entry
                && r.raw.return_pc == f.entry + 36
                && r.history_prefix != 0
                && r.history_prefix <= m.high.unwrap()
                && r.acknowledgement
                    == (if i + 1 == BLOCK {
                        NormalAcknowledgement::CallerCheckpoint
                    } else {
                        NormalAcknowledgement::NextEntry {
                            ordinal: ordinal + 1,
                        }
                    }),
            Fault::Record,
        )?;
        need(
            r.entry_rsp % 16 == 8
                && r.entry_rsp.checked_sub(128).is_some_and(|p| p >= f.stack.0)
                && r.entry_rsp.checked_add(8).is_some_and(|p| p <= f.stack.1)
                && r.return_word == f.caller + caller_bytes::CONTINUATIONS[i % 2]
                && (i % 2 == 0 || r.entry_rsp == rows[i - 1].entry_rsp),
            Fault::Stack,
        )?;
        need(r.raw.elapsed_ticks().is_some(), Fault::Clock)?;
        let (kind, inv1, reason) = inv.map_or((3, 0, 3), |n| (1, n as u64 + 1, 0));
        let prefix = r.history_prefix;
        let bits = inv1 | ((prefix & 0x1ff) << 13) | (reason << 22) | ((prefix >> 9) << 24);
        let at = 4 + i * 14;
        journal[at..at + 7].copy_from_slice(&[
            kind,
            ordinal,
            f.entry,
            r.entry_rsp,
            r.return_word,
            generation,
            bits,
        ]);
        journal[at + 7..at + 14].copy_from_slice(&[
            kind + 1,
            ordinal,
            f.entry + 36,
            r.entry_rsp,
            r.return_word,
            generation,
            bits,
        ]);
        totals.entered += 1;
        totals.ret_observed += 1;
        totals.confirmed += 1;
        totals.completed += u64::from(inv.is_some());
        totals.unsampled += u64::from(inv.is_none());
    }
    need(words == journal, Fault::Journal)?;
    need(
        m.totals.1 == totals
            && m.sequences == (before.completed, totals.completed)
            && m.next == totals.confirmed + 1,
        Fault::Identity,
    )?;
    Ok(totals)
}
// Metadata below comes from retained, authenticated HistoryBatch transfers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HistoryRow {
    pub prefix: u64,
    pub generation: u64,
    pub removed: bool,
}
pub(super) fn history_rows(
    chunks: &[HistoryBatch],
    stream: &HistoryStream,
    arms: u32,
) -> Checked<Vec<HistoryRow>> {
    need(
        (1..=EPOCHS).contains(&arms) && chunks.len() == arms as usize + 1,
        Fault::History,
    )?;
    let mut rows = Vec::with_capacity(chunks.len());
    for (i, h) in chunks.iter().enumerate() {
        need(
            h.stream() == stream
                && h.number() == i as u64 + 1
                && h.range() == (i as u64..i as u64 + 1)
                && h.actions().len() == 1
                && (if i == 0 {
                    h.before() == HistoryBinding::Initial
                } else {
                    h.follows(&chunks[i - 1])
                }),
            Fault::History,
        )?;
        let a = h.actions()[0];
        let generation = a.generation.get();
        let removed = i == arms as usize;
        need(
            a.function.is_none()
                && a.group.is_none()
                && a.kind
                    == (if removed {
                        ActionKind::Removed
                    } else {
                        ActionKind::Published
                    })
                && a.current.map(|g| g.get()) == (if removed { None } else { Some(generation) }),
            Fault::History,
        )?;
        need(
            h.after()
                == (if removed {
                    HistoryBinding::Removed {
                        action_index: i as u64,
                        generation: a.generation,
                    }
                } else {
                    HistoryBinding::Published {
                        action_index: i as u64,
                        generation: a.generation,
                    }
                }),
            Fault::History,
        )?;
        rows.push(HistoryRow {
            prefix: i as u64 + 1,
            generation,
            removed,
        });
    }
    history(&rows, arms)?;
    Ok(rows)
}
pub(super) fn history(rows: &[HistoryRow], arms: u32) -> Checked {
    need(
        (1..=EPOCHS).contains(&arms) && rows.len() == arms as usize + 1,
        Fault::History,
    )?;
    for (i, r) in rows.iter().enumerate() {
        let removed = i == arms as usize;
        need(
            r.prefix == i as u64 + 1
                && r.generation != 0
                && r.removed == removed
                && (i == 0
                    || if removed {
                        r.generation == rows[i - 1].generation
                    } else {
                        r.generation > rows[i - 1].generation
                    }),
            Fault::History,
        )?;
    }
    Ok(())
}
pub(super) fn finish(
    f: Facts,
    rows: &[NormalRecord],
    actions: &[HistoryRow],
    reports: &[ReportSpan],
    payloads: &[RecordObservation],
    arms: u32,
) -> Checked<Counts> {
    need(rows.len() == CALLS, Fault::Population)?;
    history(actions, arms)?;
    need(reports.len() == arms as usize, Fault::Report)?;
    let mut slots = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut closed = BTreeSet::new();
    let mut admitted = BTreeMap::new();
    let mut sequence = 0_u64;
    let mut previous = 0;
    let mut after_closed = false;
    for (g, r) in rows.iter().enumerate() {
        let (generation, inv) = owner(r.raw.owner, f.k)?;
        need(
            r.raw.ordinal == g as u64 + 1
                && r.history_prefix != 0
                && r.history_prefix >= previous
                && r.history_prefix <= u64::from(arms),
            Fault::Record,
        )?;
        previous = r.history_prefix;
        need(
            actions[(r.history_prefix - 1) as usize].generation == generation,
            Fault::History,
        )?;
        seen.insert(generation);
        match inv {
            Some(inv) => {
                let next = slots.entry(generation).or_insert(0);
                need(!closed.contains(&generation) && *next == inv, Fault::Record)?;
                *next += 1;
                after_closed |= closed.iter().any(|&old| old < generation);
                need(
                    admitted.insert((generation, inv), (r, sequence)).is_none(),
                    Fault::Record,
                )?;
                sequence += 1;
            }
            None => {
                need(slots.get(&generation) == Some(&f.k), Fault::Record)?;
                closed.insert(generation);
            }
        }
    }
    let mut covered = BTreeSet::new();
    let mut ranges = BTreeSet::new();
    for report in reports {
        need(
            ranges.insert(report.generation)
                && report.start <= report.end
                && report.end <= payloads.len()
                && actions[..arms as usize]
                    .iter()
                    .any(|a| a.generation == report.generation),
            Fault::Report,
        )?;
        let expected = *slots.get(&report.generation).unwrap_or(&0);
        need(report.end - report.start == expected, Fault::Report)?;
        for (rank, p) in payloads[report.start..report.end].iter().enumerate() {
            let a = p.record.admission;
            let (r, seq) = *admitted
                .get(&(report.generation, rank))
                .ok_or(Fault::Report)?;
            need(
                covered.insert((report.generation, rank))
                    && a.generation.get() == report.generation
                    && a.invocation == rank
                    && a.function == FUNCTION
                    && a.entry_value == r.raw.start.ticks
                    && p.record.terminal
                        == Some(Terminal::Completed {
                            value: rank as u64,
                            disposition: Disposition::Retained { rank },
                        }),
                Fault::Report,
            )?;
            let value = p.payload.ok_or(Fault::Report)?;
            need(
                value.admission == a
                    && value.thread == 1
                    && value.start_sequence == seq
                    && value.outcome
                        == (PayloadOutcome::Completed {
                            end: Observation::Value(r.raw.end.ticks),
                            completed_children: 0,
                        }),
                Fault::Report,
            )?;
        }
    }
    // Every copied payload occupies one distinct contiguous copied range, even
    // when publication order differs from report readiness order.
    let mut order: Vec<_> = reports.iter().collect();
    order.sort_by_key(|r| (r.start, r.end));
    let mut at = 0;
    for r in order {
        need(r.start == at, Fault::Report)?;
        at = r.end;
    }
    need(
        at == payloads.len()
            && covered.len() == admitted.len()
            && payloads.len() == sequence as usize,
        Fault::Report,
    )?;
    Ok(Counts {
        sampled: sequence,
        closed: CALLS as u64 - sequence,
        generations: seen.len(),
        after_closed,
    })
}
