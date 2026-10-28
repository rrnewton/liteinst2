//! Absolute lifetime joins; epoch-local slots are never substituted for IDs.
use super::super::check::Node;
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Spec {
    pub root: u64,
    pub continuation: u64,
    pub pid: u32,
    pub tid: u64,
    pub k: usize,
    pub block: usize,
    pub generation: u64,
}
impl Spec {
    fn valid(self) -> bool {
        self.block < BLOCKS
            && matches!(self.k, 1 | 10 | 24)
            && self.generation > 0
            && self.pid > 0
            && self.tid > 0
            && self.root.checked_add(71).is_some()
            && self.continuation > 0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AdmissionData {
    pub generation: u64,
    pub function: FunctionId,
    pub slot: usize,
    pub entry: u64,
}
impl From<rapid_profiler::generation::Admission> for AdmissionData {
    fn from(a: rapid_profiler::generation::Admission) -> Self {
        Self {
            generation: a.generation.get(),
            function: a.function,
            slot: a.invocation,
            entry: a.entry_value,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PayloadData {
    pub admission: AdmissionData,
    pub thread: u64,
    pub sequence: u64,
    pub outcome: PayloadOutcome,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Reported {
    pub admission: AdmissionData,
    pub terminal: Option<Terminal>,
    pub payload: Option<PayloadData>,
}
impl From<RecordObservation> for Reported {
    fn from(r: RecordObservation) -> Self {
        Self {
            admission: r.record.admission.into(),
            terminal: r.record.terminal,
            payload: r.payload.map(|p| PayloadData {
                admission: p.admission.into(),
                thread: p.thread,
                sequence: p.start_sequence,
                outcome: p.outcome,
            }),
        }
    }
}
pub(super) fn totals_at(block: usize, roots: usize, k: usize) -> TreeTotals {
    let total = block * CALLS + roots;
    let completed = 2 * (block * k + roots.min(k));
    TreeTotals {
        roots: total as u64,
        pairs: PairTotals {
            entries: 2 * total as u64,
            returns: 2 * total as u64,
            completed: completed as u64,
            unsampled: (2 * total - completed) as u64,
        },
    }
}
pub(super) fn call(s: &Spec, i: usize, c: TreeCallResult) -> bool {
    s.valid()
        && i < CALLS
        && c.external_id == (s.block * CALLS + i + 1) as u64
        && c.gate_sequence == c.external_id
        && c.entry_rsp & 15 == 8
        && c.entry_rsp >= 16
        && c.entry_rsp.checked_add(8) == Some(c.pre_call_rsp)
        && c.pre_call_rsp == c.resumed_rsp
        && c.return_pc == s.root + 22
        && c.value == VALUES[label(i).2]
}
fn node(s: &Spec, i: usize, n: usize, c: TreeCallResult, r: Node) -> bool {
    let Some(rsp) = c.entry_rsp.checked_sub(16 * n as u64) else {
        return false;
    };
    let Some(resume_rsp) = rsp.checked_add(8) else {
        return false;
    };
    let sampled = i < s.k;
    let owner = if sampled {
        RawIntervalOwner::Sampled {
            generation: s.generation,
            invocation: 2 * i + n,
        }
    } else {
        RawIntervalOwner::FunctionClosed {
            generation: s.generation,
        }
    };
    let word = if n == 0 { s.continuation } else { s.root + 14 };
    let expected = Node {
        id: c.external_id,
        node: n as u8,
        parent: (n == 1).then_some((c.external_id, 0)),
        function: FUNCTIONS[n],
        depth: n,
        callsite: (n == 1).then_some(s.root + 9),
        registration: 1,
        gate: c.gate_sequence,
        rsp,
        word,
        resume_pc: word,
        resume_rsp,
        value: c.value.wrapping_sub(n as u64),
        prefix: 2 * s.block + 1,
        sequence: sampled.then_some((2 * s.block * s.k + 2 * i) as u64),
        children: sampled.then_some(u64::from(n == 0)),
        raw: RawInterval {
            ordinal: (2 * (s.block * CALLS + i) + n + 1) as u64,
            entry_pc: s.root + if n == 0 { 0 } else { 32 },
            return_pc: s.root + if n == 0 { 22 } else { 70 },
            owner,
            start: r.raw.start,
            end: r.raw.end,
        },
    };
    r == expected && r.raw.elapsed_ticks().is_some()
}
fn event(r: Node, entry: bool) -> [u64; 7] {
    let prefix = (r.prefix as u64) << 13;
    let (kind, generation, packed) = match r.raw.owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => (1, generation, prefix | (invocation as u64 + 1)),
        RawIntervalOwner::FunctionClosed { generation } => (3, generation, prefix | (3 << 22)),
        _ => unreachable!("exact node checked first"),
    };
    [
        kind + u64::from(!entry),
        r.raw.ordinal,
        if entry {
            r.raw.entry_pc
        } else {
            r.raw.return_pc
        },
        r.rsp,
        r.word,
        generation,
        packed,
    ]
}
pub(super) fn batch(s: &Spec, index: usize, calls: &[TreeCallResult], b: &Batch) -> bool {
    if !s.valid()
        || index >= 3
        || calls.len() < (index + 1) * PER_BATCH
        || b.nodes.len() != 16
        || b.journal.len() != 512
        || b.pid != s.pid
        || b.tid != s.tid
        || b.install != INSTALL
        || b.registration != 1
        || b.functions != FUNCTIONS
        || b.number != (3 * s.block + index + 1) as u64
        || b.gate_base != 0
    {
        return false;
    }
    let first = index * PER_BATCH;
    let last = first + PER_BATCH;
    let before = totals_at(s.block, first, s.k);
    let after = totals_at(s.block, last, s.k);
    if b.totals != (before, after)
        || b.completed != (before.pairs.completed, after.pairs.completed)
        || b.gate_sequence != (s.block * CALLS + last) as u64
    {
        return false;
    }
    let mut page = [0_u64; 512];
    page[..4].copy_from_slice(&[32, 0, s.tid, 0]);
    for (j, pair) in b.nodes.chunks_exact(2).enumerate() {
        let i = first + j;
        if !call(s, i, calls[i])
            || !node(s, i, 0, calls[i], pair[0])
            || !node(s, i, 1, calls[i], pair[1])
        {
            return false;
        }
        for (e, words) in [
            event(pair[0], true),
            event(pair[1], true),
            event(pair[1], false),
            event(pair[0], false),
        ]
        .iter()
        .enumerate()
        {
            let at = 4 + j * 28 + e * 7;
            page[at..at + 7].copy_from_slice(words);
        }
    }
    b.journal == page
}
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Cursor {
    next: usize,
    generation: u64,
    last: Option<(u64, u32)>,
}
impl Cursor {
    pub(super) fn blocks(self) -> usize {
        self.next
    }
    pub(super) fn finish_block(
        &mut self,
        s: &Spec,
        calls: &[TreeCallResult],
        nodes: &[Node],
        reports: &[Reported],
    ) -> bool {
        if !s.valid()
            || s.block != self.next
            || s.generation <= self.generation
            || calls.len() != CALLS
            || nodes.len() != 2 * CALLS
            || reports.len() != 2 * s.k
        {
            return false;
        }
        let mut last = self.last;
        for (i, pair) in nodes.chunks_exact(2).enumerate() {
            if !call(s, i, calls[i])
                || !node(s, i, 0, calls[i], pair[0])
                || !node(s, i, 1, calls[i], pair[1])
            {
                return false;
            }
            let (root, child) = (pair[0].raw, pair[1].raw);
            if root.start.ticks > child.start.ticks
                || child.end.ticks > root.end.ticks
                || root.start.aux != child.start.aux
                || last.is_some_and(|(end, aux)| root.start.ticks < end || root.start.aux != aux)
            {
                return false;
            }
            last = Some((root.end.ticks, root.start.aux));
            if i >= s.k {
                continue;
            }
            for (n, row) in pair.iter().enumerate() {
                let slot = 2 * i + n;
                let admission = AdmissionData {
                    generation: s.generation,
                    function: FUNCTIONS[n],
                    slot,
                    entry: row.raw.start.ticks,
                };
                let expected = Reported {
                    admission,
                    terminal: Some(Terminal::Completed {
                        value: slot as u64,
                        disposition: Disposition::Retained { rank: i },
                    }),
                    payload: Some(PayloadData {
                        admission,
                        thread: 1,
                        sequence: (2 * s.block * s.k + 2 * i) as u64,
                        outcome: PayloadOutcome::Completed {
                            end: Observation::Value(row.raw.end.ticks),
                            completed_children: u64::from(n == 0),
                        },
                    }),
                };
                if reports[slot] != expected {
                    return false;
                }
            }
        }
        self.next += 1;
        self.generation = s.generation;
        self.last = last;
        true
    }
}
#[cfg(test)]
mod tests;
