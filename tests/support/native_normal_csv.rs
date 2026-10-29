//! Closed CSV body under the existing real 67-byte caller and full-state oracle.
//! No instruction-work estimate, timing claim or new caller authority.
use super::*;
pub const LABEL: &str = "normal-csv-fields-v1";
const RECORDS: [(&[u8], u64); 16] = [
    (b"", 1),
    (b"a", 1),
    (b"a,b,c", 3),
    (b",", 2),
    (b",,", 3),
    (b"a,", 2),
    (b",a", 2),
    (b"\"\"", 1),
    (b"\"a,b\"", 1),
    (b"\"a\",\"b\"", 2),
    (b"a,\"b,c\",d", 3),
    (b"\"a\"\"b\",c", 2),
    (b"\"\"\"\"", 1),
    (b"\"\",\"\"", 2),
    (b"plain,\"say \"\"hi\"\"\",,tail", 4),
    (b"\"comma,, and \"\"quote\"\"\",last,", 3),
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case(usize);
impl Case {
    pub fn new(index: usize) -> Self {
        assert!(index < RECORDS.len());
        Self(index)
    }
    pub fn id(self) -> usize {
        self.0 + 1
    }
    pub fn length(self) -> usize {
        RECORDS[self.0].0.len()
    }
    pub fn expected(self) -> u64 {
        RECORDS[self.0].1
    }
    pub fn input(self) -> [u8; 64] {
        let mut bytes = [0xa7; 64];
        bytes[..self.length()].copy_from_slice(RECORDS[self.0].0);
        bytes
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arguments {
    pub elf_va: u64,
    pub length: usize,
}
impl Arguments {
    pub fn parse(elf_va: &str, length: &str) -> Self {
        // The existing selected parser has canonical u64/overflow checks and a
        // 1..=256 extent. CSV admission separately requires a five-byte window.
        let a = super::super::selected::Arguments::parse(elf_va, length);
        Self {
            elf_va: a.elf_va,
            length: a.length,
        }
    }
}
pub(super) fn profile(seed: u64, case: Case, extent: usize) {
    assert!(SEEDS.contains(&seed));
    assert_eq!(Case::new(case.0), case);
    assert!((5..=256).contains(&extent), "CSV certified extent");
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Graph {
    pub(super) heads: BTreeSet<u64>,
    pub(super) edges: BTreeSet<(u64, u64)>,
    pub(super) returns: BTreeSet<u64>,
}
pub(super) fn graph(code: &[u8]) -> Graph {
    assert!((5..=256).contains(&code.len()));
    // Relative IPs make declared geometry stable across fresh child mappings.
    let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    let mut g = Graph {
        heads: BTreeSet::new(),
        edges: BTreeSet::new(),
        returns: BTreeSet::new(),
    };
    while decoder.can_decode() {
        let i = decoder.decode();
        assert!(!i.is_invalid() && i.next_ip() <= code.len() as u64);
        assert!(g.heads.insert(i.ip()));
        match i.flow_control() {
            FlowControl::Next => {
                g.edges.insert((i.ip(), i.next_ip()));
            }
            FlowControl::ConditionalBranch => {
                g.edges.insert((i.ip(), i.next_ip()));
                g.edges.insert((i.ip(), i.near_branch_target()));
            }
            FlowControl::UnconditionalBranch => {
                g.edges.insert((i.ip(), i.near_branch_target()));
            }
            FlowControl::Return => {
                assert_eq!(code[i.ip() as usize..i.next_ip() as usize], [0xc3]);
                g.returns.insert(i.ip());
            }
            _ => panic!("CSV closed scalar flow"),
        }
    }
    assert_eq!(decoder.position(), code.len());
    assert!((1..=4).contains(&g.returns.len()));
    assert!(
        g.edges
            .iter()
            .all(|(a, b)| g.heads.contains(a) && g.heads.contains(b) && *b != 0)
    );
    g
}
pub(super) fn validate_ready(
    ready: &NormalReady,
    candidate: bool,
    extent: usize,
) -> BTreeMap<u64, u64> {
    assert!((5..=256).contains(&extent));
    let maps = ready.validate_body(candidate, extent, Mode::Stable, CallerProfile::Legacy);
    let code = bytes_at(
        &ready.original_source,
        ready.immutable[0].0,
        ready.entry,
        extent,
    );
    let declared = graph(code);
    assert_eq!(
        ready
            .heads
            .iter()
            .map(|p| p.checked_sub(ready.entry).unwrap())
            .collect::<BTreeSet<_>>(),
        declared.heads
    );
    assert_eq!(
        ready
            .returns
            .iter()
            .map(|p| p.checked_sub(ready.entry).unwrap())
            .collect::<BTreeSet<_>>(),
        declared.returns
    );
    maps
}
pub(super) fn validate_geometry(entry: u64, heads: &[u64], returns: &[u64], code: &[u8]) {
    let declared = graph(code);
    assert_eq!(
        heads
            .iter()
            .map(|p| p.checked_sub(entry).unwrap())
            .collect::<BTreeSet<_>>(),
        declared.heads
    );
    assert_eq!(
        returns
            .iter()
            .map(|p| p.checked_sub(entry).unwrap())
            .collect::<BTreeSet<_>>(),
        declared.returns
    );
}
#[derive(Clone, Debug)]
pub struct BodyTrace {
    pub entry: u64,
    pub visits: usize,
    pub ret_offset: u64,
    pub heads: BTreeSet<u64>,
    pub edges: BTreeSet<(u64, u64)>,
    pub(super) code: Vec<u8>,
    pub(super) declared: Graph,
}
#[derive(Clone, Debug)]
pub struct Trace {
    pub bodies: [BodyTrace; 2],
}
pub(super) fn inspect(case: Case, ready: &NormalReady, body: OriginalBody<'_>) -> BodyTrace {
    inspect_geometry(case, ready.entry, &ready.heads, &ready.returns, body)
}
pub(super) fn inspect_geometry(
    case: Case,
    entry: u64,
    heads: &[u64],
    returns: &[u64],
    body: OriginalBody<'_>,
) -> BodyTrace {
    assert_eq!(body.entry, entry);
    assert_eq!(body.input, &case.input()[..case.length()]);
    assert!(!body.steps.is_empty() && body.steps.len() <= MAX_STEPS);
    let declared = graph(body.code);
    assert_eq!(
        heads
            .iter()
            .map(|p| p.checked_sub(body.entry).unwrap())
            .collect::<BTreeSet<_>>(),
        declared.heads
    );
    assert_eq!(
        returns
            .iter()
            .map(|p| p.checked_sub(body.entry).unwrap())
            .collect::<BTreeSet<_>>(),
        declared.returns
    );
    assert_eq!(body.steps[0].before.rip, body.entry);
    let mut heads = BTreeSet::new();
    let mut edges = BTreeSet::new();
    for (n, step) in body.steps.iter().enumerate() {
        let head = step.before.rip.checked_sub(body.entry).unwrap();
        assert!(declared.heads.contains(&head));
        heads.insert(head);
        if n + 1 == body.steps.len() {
            assert!(declared.returns.contains(&head));
            assert_eq!(step.after.rip, body.continuation);
            assert_eq!(
                (step.before.rax, step.after.rax),
                (case.expected(), case.expected())
            );
        } else {
            assert!(!declared.returns.contains(&head));
            assert_eq!(step.after.rip, body.steps[n + 1].before.rip);
            let next = step.after.rip.checked_sub(body.entry).unwrap();
            assert!(declared.edges.contains(&(head, next)));
            edges.insert((head, next));
        }
    }
    BodyTrace {
        entry: body.entry,
        visits: body.steps.len(),
        ret_offset: body
            .steps
            .last()
            .unwrap()
            .before
            .rip
            .checked_sub(body.entry)
            .unwrap(),
        heads,
        edges,
        code: body.code.to_vec(),
        declared,
    }
}
pub(super) fn validate_pair(case: Case, pair: &NormalPairResult, trace: &Trace) {
    assert_eq!(
        (
            pair.target_calls,
            pair.target_returns,
            pair.outer_returns,
            pair.normal_reaps
        ),
        (4, 4, 2, 2)
    );
    assert_eq!(pair.values, [case.expected(); 2]);
    assert_eq!(pair.outer_value, case.expected().wrapping_mul(2));
    assert_eq!(pair.visits, trace.bodies.each_ref().map(|b| b.visits));
    assert!(pair.visits.iter().all(|&n| n > 0));
    assert_eq!(
        pair.comparisons,
        HEADS.len() + pair.visits[0] + pair.visits[1]
    );
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
    let [a, b] = &trace.bodies;
    assert_eq!(
        (&a.code, &a.declared, &a.heads, &a.edges, a.ret_offset),
        (&b.code, &b.declared, &b.heads, &b.edges, b.ret_offset)
    );
    for (n, body) in trace.bodies.iter().enumerate() {
        assert_eq!(
            pair.returns[n],
            body.entry.checked_add(body.ret_offset).unwrap()
        );
        assert!(body.declared.returns.contains(&body.ret_offset));
        assert!(body.heads.contains(&0) && body.heads.contains(&body.ret_offset));
        assert!(
            body.heads.is_subset(&body.declared.heads)
                && body.edges.is_subset(&body.declared.edges)
        );
        assert_eq!(
            pair.declared_returns,
            body.declared
                .returns
                .iter()
                .map(|r| body.entry.checked_add(*r).unwrap())
                .collect()
        );
    }
}
#[derive(Default)]
pub struct Population {
    next: usize,
    declared: Option<(Vec<u8>, Graph)>,
    heads: BTreeSet<u64>,
    edges: BTreeSet<(u64, u64)>,
    returns: BTreeSet<u64>,
    comparisons: usize,
}
pub struct Coverage {
    pub heads: usize,
    pub edges: usize,
    pub declared_heads: usize,
    pub declared_edges: usize,
    pub returns: usize,
}
impl Population {
    pub fn record(
        &mut self,
        seed: u64,
        case: Case,
        pair: &NormalPairResult,
        trace: &Trace,
    ) -> Option<Coverage> {
        assert!(self.next < 32);
        assert_eq!(
            (seed, case),
            (SEEDS[self.next / 16], Case::new(self.next % 16))
        );
        validate_pair(case, pair, trace);
        for b in &trace.bodies {
            if let Some((code, g)) = &self.declared {
                assert_eq!((code, g), (&b.code, &b.declared));
            } else {
                self.declared = Some((b.code.clone(), b.declared.clone()));
            }
            self.heads.extend(&b.heads);
            self.edges.extend(&b.edges);
            self.returns.insert(b.ret_offset);
        }
        self.comparisons = self.comparisons.checked_add(pair.comparisons).unwrap();
        self.next += 1;
        if self.next % 16 != 0 {
            return None;
        }
        let g = &self.declared.as_ref().unwrap().1;
        assert_eq!(
            self.returns, g.returns,
            "every declared CSV RET for each seed"
        );
        let result = Coverage {
            heads: self.heads.len(),
            edges: self.edges.len(),
            declared_heads: g.heads.len(),
            declared_edges: g.edges.len(),
            returns: g.returns.len(),
        };
        self.heads.clear();
        self.edges.clear();
        self.returns.clear();
        Some(result)
    }
    pub fn finish(self) -> usize {
        assert_eq!(self.next, 32);
        assert!(self.declared.is_some());
        assert!(self.heads.is_empty() && self.edges.is_empty() && self.returns.is_empty());
        self.comparisons
    }
}

#[cfg(test)]
#[path = "native_normal_csv/tests.rs"]
mod tests;
