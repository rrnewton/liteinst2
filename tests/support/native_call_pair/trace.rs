//! Complete ordered original traces, interpreted only after both normal reaps.
use super::*;
#[derive(Clone, Debug)]
pub struct Trace {
    pub parent_entry: u64,
    pub child_entry: u64,
    pub parent_visits: usize,
    pub parent_ret_offset: u64,
    pub parent_heads: BTreeSet<u64>,
    pub parent_edges: BTreeSet<(u64, u64)>,
    pub child: csv::BodyTrace,
    pub child_delta: u64,
    pub stack_bytes: u64,
    pub parent_generation: u64,
    pub child_generation: u64,
}
impl Trace {
    pub fn child_declared_counts(&self) -> [usize; 3] {
        [
            self.child.declared.heads.len(),
            self.child.declared.edges.len(),
            self.child.declared.returns.len(),
        ]
    }
}
pub(super) fn inspect(
    oracle: &NormalOracle,
    ready: &Ready,
    candidate: &Ready,
    points: &[Snapshot],
) -> Trace {
    ready.same_source(candidate);
    assert!(ready.journal.is_none());
    let j = candidate.journal.as_ref().unwrap();
    let p = ready.parent_plan();
    let seen: Vec<_> = points
        .iter()
        .filter_map(|s| {
            s.logical_pc
                .checked_sub(ready.parent().entry)
                .filter(|at| p.heads().contains(at))
        })
        .collect();
    assert_eq!(seen, p.heads());
    for pair in points.windows(2) {
        if pair[0]
            .logical_pc
            .checked_sub(ready.parent().entry)
            .is_some_and(|at| p.heads().contains(&at))
        {
            parent::effect(
                &p,
                ready.parent().entry,
                ready.child().entry,
                &pair[0],
                &pair[1],
                oracle.stack_start(),
            );
        }
    }
    let positions = |pc| {
        points
            .iter()
            .enumerate()
            .filter_map(|(i, p)| (p.logical_pc == pc).then_some(i))
            .collect::<Vec<_>>()
    };
    let roots = positions(ready.parent().entry);
    let children = positions(ready.child().entry);
    assert_eq!(roots.len(), 1);
    assert_eq!(children.len(), 1);
    let start = children[0];
    let finish = (start..points.len())
        .find(|&i| ready.child().returns.contains(&points[i].logical_pc))
        .unwrap();
    let parent_ret = positions(ready.parent().returns[0]);
    assert_eq!(parent_ret.len(), 1);
    assert!(roots[0] < start && finish < parent_ret[0]);
    assert_eq!(points[start - 1].logical_pc, ready.parent().entry + p.call);
    assert_eq!(
        points[finish + 1].logical_pc,
        ready.parent().entry + p.continuation
    );
    callee_saves(
        &points[roots[0]].registers,
        &points[parent_ret[0]].registers,
    );
    assert_eq!(points[parent_ret[0]].registers.rax, ready.case.value());
    let steps: Vec<_> = points[start..=finish + 1]
        .windows(2)
        .map(|w| OriginalStep {
            before: w[0].registers,
            after: w[1].registers,
            data_address: oracle.data.address(),
            data: &w[0].data,
            stack_address: oracle.stack_start(),
            stack: &w[0].application_stack,
        })
        .collect();
    let code = leaf_set_copied::source_bytes(
        &ready.original_sources,
        ready.child().entry,
        ready.case.extents[1],
    );
    let child = csv::inspect_geometry(
        ready.case.csv(),
        ready.child().entry,
        &ready.child().heads,
        &ready.child().returns,
        OriginalBody {
            entry: ready.child().entry,
            continuation: ready.parent().entry + p.continuation,
            input_address: oracle.data.address() + INPUT as u64,
            input: &oracle.data.bytes()[INPUT..INPUT + ready.case.bound()],
            code: &code,
            steps: &steps,
        },
    );
    Trace {
        parent_entry: ready.parent().entry,
        child_entry: ready.child().entry,
        parent_visits: seen.len(),
        parent_ret_offset: p.ret(),
        parent_heads: seen.into_iter().collect(),
        parent_edges: p.edges(),
        child,
        child_delta: p.delta,
        stack_bytes: oracle.stack_below() + 8,
        parent_generation: j.a_generation,
        child_generation: if ready.case.scenario == Scenario::RemovedChild {
            0
        } else {
            j.b_generation.unwrap_or(j.a_generation)
        },
    }
}
pub(super) fn validate_pair(case: Case, plan: &Plan, pair: &NormalPairResult<2>, trace: &Trace) {
    case.assert_valid();
    assert_eq!(
        (
            pair.target_calls,
            pair.target_returns,
            pair.outer_returns,
            pair.normal_reaps
        ),
        (4, 4, 2, 2)
    );
    assert_eq!(pair.values, [case.value(), case.fields()]);
    assert_eq!(pair.visits, [trace.parent_visits, trace.child.visits]);
    assert!(pair.visits.iter().all(|&n| n > 0));
    assert_eq!(
        pair.comparisons,
        plan.heads().len() + trace.parent_visits + trace.child.visits + 1
    );
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
    assert_eq!(
        pair.returns,
        [
            trace.child_entry + trace.child.ret_offset,
            trace.parent_entry + trace.parent_ret_offset
        ]
    );
    let mut declared: BTreeSet<_> = trace
        .child
        .declared
        .returns
        .iter()
        .map(|r| trace.child_entry + r)
        .collect();
    declared.insert(trace.parent_entry + trace.parent_ret_offset);
    assert_eq!(pair.declared_returns, declared);
    assert_eq!(trace.parent_visits, trace.parent_heads.len());
    assert_eq!(trace.parent_edges.len() + 1, trace.parent_heads.len());
    assert!([16, 32, 48, 64].contains(&trace.child_delta));
    assert_eq!(
        trace.stack_bytes,
        plan.protected_stack_below()
            .max(plan.subject_rsp_delta() + trace.child_delta + 128)
            + 8
    );
    assert!(trace.stack_bytes <= 456);
    assert_ne!(trace.parent_generation, 0);
    match case.scenario {
        Scenario::StableA => assert_eq!(trace.child_generation, trace.parent_generation),
        Scenario::RearmB => assert!(
            trace.child_generation != 0 && trace.child_generation != trace.parent_generation
        ),
        Scenario::RemovedChild => assert_eq!(trace.child_generation, 0),
    }
}
#[derive(Clone, Debug)]
pub struct Coverage {
    pub k: usize,
    pub scenario: Scenario,
    pub seed: u64,
    pub cases: usize,
    pub parent_heads: usize,
    pub parent_edges: usize,
    pub parent_returns: usize,
    pub child_heads: usize,
    pub child_edges: usize,
    pub child_returns: usize,
    pub child_declared_heads: usize,
    pub child_declared_edges: usize,
    pub child_declared_returns: usize,
}
type ParentShape = (BTreeSet<u64>, BTreeSet<(u64, u64)>, u64);
#[derive(Default)]
struct Group {
    cases: BTreeSet<usize>,
    parent_heads: BTreeSet<u64>,
    parent_edges: BTreeSet<(u64, u64)>,
    parent_returns: BTreeSet<u64>,
    child_heads: BTreeSet<u64>,
    child_edges: BTreeSet<(u64, u64)>,
    child_returns: BTreeSet<u64>,
    declared: Option<csv::Graph>,
    parent_shape: Option<ParentShape>,
}
#[derive(Default)]
pub struct Population {
    next: usize,
    groups: BTreeMap<(usize, u64, u64), Group>,
}
impl Population {
    pub fn record(
        &mut self,
        seed: u64,
        case: Case,
        plan: &Plan,
        pair: &NormalPairResult<2>,
        trace: &Trace,
    ) {
        validate_pair(case, plan, pair, trace);
        assert_eq!(
            keys().get(self.next),
            Some(&(case.k, seed, case.index, case.scenario))
        );
        self.next += 1;
        let group = self
            .groups
            .entry((case.k, case.scenario.id(), seed))
            .or_default();
        assert!(group.cases.insert(case.index));
        let shape = (
            trace.parent_heads.clone(),
            trace.parent_edges.clone(),
            trace.parent_ret_offset,
        );
        if let Some(old) = &group.parent_shape {
            assert_eq!(old, &shape);
        } else {
            group.parent_shape = Some(shape);
        }
        if let Some(old) = &group.declared {
            assert_eq!(old, &trace.child.declared);
        } else {
            group.declared = Some(trace.child.declared.clone());
        }
        group.parent_heads.extend(&trace.parent_heads);
        group.parent_edges.extend(&trace.parent_edges);
        group.parent_returns.insert(trace.parent_ret_offset);
        group.child_heads.extend(&trace.child.heads);
        group.child_edges.extend(&trace.child.edges);
        group.child_returns.insert(trace.child.ret_offset);
    }
    pub fn finish(self) -> Vec<Coverage> {
        assert_eq!(self.next, 192);
        assert_eq!(self.groups.len(), 12);
        let mut out = Vec::with_capacity(12);
        for k in [10, 1000] {
            for scenario in [Scenario::StableA, Scenario::RearmB, Scenario::RemovedChild] {
                for seed in SEEDS {
                    let g = &self.groups[&(k, scenario.id(), seed)];
                    assert_eq!(g.cases, (0..16).collect());
                    let d = g.declared.as_ref().unwrap();
                    let p = g.parent_shape.as_ref().unwrap();
                    assert_eq!(g.parent_heads, p.0);
                    assert_eq!(g.parent_edges, p.1);
                    assert_eq!(g.parent_returns, BTreeSet::from([p.2]));
                    assert!(g.child_heads.is_subset(&d.heads) && g.child_edges.is_subset(&d.edges));
                    assert_eq!(g.child_returns, d.returns);
                    out.push(Coverage {
                        k,
                        scenario,
                        seed,
                        cases: 16,
                        parent_heads: g.parent_heads.len(),
                        parent_edges: g.parent_edges.len(),
                        parent_returns: g.parent_returns.len(),
                        child_heads: g.child_heads.len(),
                        child_edges: g.child_edges.len(),
                        child_returns: g.child_returns.len(),
                        child_declared_heads: d.heads.len(),
                        child_declared_edges: d.edges.len(),
                        child_declared_returns: d.returns.len(),
                    });
                }
            }
        }
        out
    }
}
