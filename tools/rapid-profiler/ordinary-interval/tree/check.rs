//! Pure joins over complete copied records, never authority to invoke native code.
use super::*;
use rapid_profiler::frontend::{Payload, PayloadOutcome};
use rapid_profiler::generation::Admission;

#[derive(Clone, Copy, Debug)]
pub(super) struct Spec {
    pub root: u64,
    pub continuation: u64,
    pub generation: u64,
    pub k: usize,
    pub pid: u32,
    pub tid: u64,
    pub gate_base: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Node {
    pub id: u64,
    pub node: u8,
    pub parent: Option<(u64, u8)>,
    pub function: FunctionId,
    pub depth: usize,
    pub callsite: Option<u64>,
    pub registration: u64,
    pub gate: u64,
    pub raw: RawInterval,
    pub rsp: u64,
    pub word: u64,
    pub resume_pc: u64,
    pub resume_rsp: u64,
    pub value: u64,
    pub prefix: usize,
    pub sequence: Option<u64>,
    pub children: Option<u64>,
}
impl From<&TreeRecord> for Node {
    fn from(r: &TreeRecord) -> Self {
        Self {
            id: r.external_id(),
            node: r.node(),
            parent: r.parent(),
            function: r.function(),
            depth: r.depth(),
            callsite: r.callsite(),
            registration: r.registration(),
            gate: r.gate_sequence(),
            raw: *r.raw(),
            rsp: r.entry_rsp(),
            word: r.return_word(),
            resume_pc: r.resume_pc(),
            resume_rsp: r.resume_rsp(),
            value: r.value(),
            prefix: r.history_prefix(),
            sequence: r.model_start_sequence(),
            children: r.model_completed_children(),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Batch {
    pub pid: u32,
    pub tid: u64,
    pub install: u64,
    pub registration: u64,
    pub functions: [FunctionId; 2],
    pub number: u64,
    pub gate_base: u64,
    pub gate_sequence: u64,
    pub totals: (TreeTotals, TreeTotals),
    pub completed: (u64, u64),
    pub nodes: Vec<Node>,
    pub journal: Vec<u64>,
}
impl From<&TreeBatch> for Batch {
    fn from(b: &TreeBatch) -> Self {
        Self {
            pid: b.pid(),
            tid: b.tid(),
            install: b.install(),
            registration: b.registration(),
            functions: b.functions(),
            number: b.number(),
            gate_base: b.gate_base(),
            gate_sequence: b.gate_sequence(),
            totals: b.totals(),
            completed: b.completed_sequences(),
            nodes: b.rows().iter().map(Node::from).collect(),
            journal: b.journal().to_vec(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdmissionRow {
    generation: u64,
    function: FunctionId,
    invocation: usize,
    entry: u64,
}
impl From<Admission> for AdmissionRow {
    fn from(a: Admission) -> Self {
        Self {
            generation: a.generation.get(),
            function: a.function,
            invocation: a.invocation,
            entry: a.entry_value,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PayloadRow {
    admission: AdmissionRow,
    thread: u64,
    sequence: u64,
    outcome: PayloadOutcome,
}
impl From<Payload> for PayloadRow {
    fn from(p: Payload) -> Self {
        Self {
            admission: p.admission.into(),
            thread: p.thread,
            sequence: p.start_sequence,
            outcome: p.outcome,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReportRow {
    admission: AdmissionRow,
    terminal: Option<Terminal>,
    payload: Option<PayloadRow>,
}
impl From<RecordObservation> for ReportRow {
    fn from(r: RecordObservation) -> Self {
        Self {
            admission: r.record.admission.into(),
            terminal: r.record.terminal,
            payload: r.payload.map(PayloadRow::from),
        }
    }
}

pub(super) fn call(s: &Spec, i: usize, c: TreeCallResult) -> bool {
    i < CALLS
        && c.external_id == i as u64 + 1
        && s.gate_base.checked_add(i as u64 + 1) == Some(c.gate_sequence)
        && c.entry_rsp & 15 == 8
        && c.entry_rsp >= 16
        && c.entry_rsp.checked_add(8) == Some(c.pre_call_rsp)
        && c.pre_call_rsp == c.resumed_rsp
        && c.return_pc == s.root + 22
        && c.value == truth::scalar(label(i).0, label(i).1)
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
        id: i as u64 + 1,
        node: n as u8,
        parent: (n == 1).then_some((i as u64 + 1, 0)),
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
        prefix: 1,
        sequence: sampled.then_some(2 * i as u64),
        children: sampled.then_some(u64::from(n == 0)),
        raw: RawInterval {
            ordinal: (2 * i + n + 1) as u64,
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
    let (kind, generation, bits) = match r.raw.owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => (1, generation, (invocation as u64 + 1) | (1 << 13)),
        RawIntervalOwner::FunctionClosed { generation } => (3, generation, (1 << 13) | (3 << 22)),
        _ => unreachable!("node checked before journal construction"),
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
        bits,
    ]
}
pub(super) fn batch(s: &Spec, index: usize, calls: &[TreeCallResult], b: &Batch) -> bool {
    if index >= 3
        || calls.len() < (index + 1) * PER_BATCH
        || b.nodes.len() != 16
        || b.journal.len() != 512
        || b.pid != s.pid
        || b.tid != s.tid
        || b.install != INSTALL
        || b.registration != 1
        || b.functions != FUNCTIONS
        || b.number != index as u64 + 1
        || b.gate_base != s.gate_base
    {
        return false;
    }
    let first = index * PER_BATCH;
    let last = first + PER_BATCH;
    if b.totals != (totals(first, s.k), totals(last, s.k))
        || b.completed != ((2 * first.min(s.k)) as u64, (2 * last.min(s.k)) as u64)
        || s.gate_base.checked_add(last as u64) != Some(b.gate_sequence)
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
        let (r, c) = (pair[0].raw, pair[1].raw);
        if !(r.start.ticks <= c.start.ticks && c.end.ticks <= r.end.ticks)
            || r.start.aux != c.start.aux
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
pub(super) fn population(
    s: &Spec,
    calls: &[TreeCallResult],
    batches: &[Batch],
    reports: &[ReportRow],
) -> bool {
    if !matches!(s.k, 1 | 10 | 24)
        || s.generation == 0
        || s.pid == 0
        || s.tid == 0
        || s.gate_base != CALLS as u64
        || calls.len() != CALLS
        || batches.len() != 3
        || reports.len() != 2 * s.k
    {
        return false;
    }
    if !batches
        .iter()
        .enumerate()
        .all(|(i, b)| batch(s, i, calls, b))
    {
        return false;
    }
    let nodes: Vec<_> = batches.iter().flat_map(|b| &b.nodes).collect();
    let aux = nodes[0].raw.start.aux;
    let mut end = 0;
    for (i, pair) in nodes.chunks_exact(2).enumerate() {
        let (root, child) = (pair[0], pair[1]);
        if root.raw.start.ticks < end || root.raw.start.aux != aux || child.raw.start.aux != aux {
            return false;
        }
        end = root.raw.end.ticks;
        if i >= s.k {
            continue;
        }
        for (n, row) in [root, child].iter().enumerate() {
            let slot = 2 * i + n;
            let admission = AdmissionRow {
                generation: s.generation,
                function: FUNCTIONS[n],
                invocation: slot,
                entry: row.raw.start.ticks,
            };
            let expected = ReportRow {
                admission,
                terminal: Some(Terminal::Completed {
                    value: slot as u64,
                    disposition: Disposition::Retained { rank: i },
                }),
                payload: Some(PayloadRow {
                    admission,
                    thread: 1,
                    sequence: (2 * i) as u64,
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
    true
}
#[cfg(test)]
mod tests;
