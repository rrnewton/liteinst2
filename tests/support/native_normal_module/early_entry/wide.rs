//! Proposed explicit 80,000-step optional-entry profile. Default oracles keep
//! the unchanged 20,000-step Walk and validator. No ambient budget override.
use super::*;

const STEP_LIMIT: usize = 80_000;

// The field is private to this module. Only OptionalEntry80kOracle constructs
// this token; NormalOracle has no public setter or accepting constructor.
pub(in super::super::super) struct StepBudget(());
impl StepBudget {
    fn allows(&self, steps: usize) -> bool {
        steps < STEP_LIMIT
    }
    pub(in super::super::super) fn step(&self, walk: &mut Walk<'_>, phase: &str) {
        assert!(
            self.allows(walk.steps),
            "optional-entry-80k child budget: phase={phase} steps={} rip={:#x} pid={} step_anchor={:#x}",
            walk.steps,
            walk.child.registers().rip,
            walk.child.pid,
            Self::step as *const () as usize
        );
        assert!(Instant::now() < walk.child.deadline);
        walk.steps += 1;
        walk.child.step(&[]);
    }
}

/// Named qualification-only admission. No Deref or inner-oracle extraction:
/// the admitted budget cannot be used with another public NormalOracle route.
pub struct OptionalEntry80kOracle {
    inner: NormalOracle,
}
impl OptionalEntry80kOracle {
    pub fn new(seed: u64, case: Case, scenario: Scenario, deadline: Deadline) -> Self {
        case.assert_session();
        let mut inner = NormalOracle::new_early_entry(seed, case, scenario, deadline);
        assert!(inner.early_entry_80k.is_none());
        inner.early_entry_80k = Some(StepBudget(()));
        Self { inner }
    }
    pub fn pair<F>(&self, setup: F) -> (NormalPairResult<4>, Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        let oracle = &self.inner;
        assert!(oracle.early_entry.is_some() && oracle.early_entry_80k.is_some());
        assert!(
            oracle.reference.is_none()
                && oracle.copied_rust.is_none()
                && oracle.leaf_set_copied.is_none()
                && oracle.selected_leaf_set.is_none()
                && oracle.exact_accuracy.is_none()
                && oracle.call_pair.is_none()
        );
        let case = oracle.module.expect("optional-entry-80k module profile");
        case.assert_session();
        let (pair, trace, reference) = oracle.pair_engine::<F, _, _, 4>(setup, |ready, points| {
            let trace = super::super::trace::inspect(oracle, ready.module(), points);
            let visits = trace.visits();
            (trace, visits)
        });
        assert!(reference.is_none());
        validate_pair(case, &pair, &trace);
        oracle.deadline.check();
        (pair, trace)
    }
}

// This separately named validator carries every old comparison literally.
// Only its admitted step ceiling differs; old trace::validate_pair is unchanged.
pub(in super::super) fn validate_pair(case: Case, pair: &NormalPairResult<4>, trace: &Trace) {
    case.assert_session();
    assert_eq!(
        (
            pair.target_calls,
            pair.target_returns,
            pair.outer_returns,
            pair.normal_reaps
        ),
        (8, 8, 2, 2)
    );
    assert_eq!(pair.values, case.values());
    assert_eq!(pair.outer_value, case.sum());
    assert_eq!(pair.visits, trace.visits());
    assert!(pair.visits.iter().all(|&n| n > 0));
    assert_eq!(
        pair.comparisons,
        bytes::HEADS.len() + pair.visits.iter().sum::<usize>()
    );
    assert!((pair.comparisons..=STEP_LIMIT).contains(&pair.original_steps));
    assert!((pair.comparisons..=STEP_LIMIT).contains(&pair.candidate_steps));
    let [a, b] = &trace.csv;
    assert_eq!(
        (
            a.entry,
            &a.code,
            &a.declared,
            &a.heads,
            &a.edges,
            a.ret_offset
        ),
        (
            b.entry,
            &b.code,
            &b.declared,
            &b.heads,
            &b.edges,
            b.ret_offset
        )
    );
    let [a, b] = &trace.length;
    assert_eq!(
        (
            a.entry,
            &a.code,
            &a.declared,
            &a.observed,
            a.ret_offset,
            a.input_reads,
            a.input_bytes
        ),
        (
            b.entry,
            &b.code,
            &b.declared,
            &b.observed,
            b.ret_offset,
            b.input_reads,
            b.input_bytes
        )
    );
    let mut declared = BTreeSet::new();
    for (i, b) in trace.csv.iter().enumerate() {
        assert_eq!(
            pair.returns[2 * i],
            b.entry.checked_add(b.ret_offset).unwrap()
        );
        assert!(b.declared.returns.contains(&b.ret_offset));
        assert!(b.heads.contains(&0) && b.heads.contains(&b.ret_offset));
        assert!(b.heads.is_subset(&b.declared.heads) && b.edges.is_subset(&b.declared.edges));
        declared.extend(
            b.declared
                .returns
                .iter()
                .map(|r| b.entry.checked_add(*r).unwrap()),
        );
    }
    for (i, b) in trace.length.iter().enumerate() {
        assert_eq!(
            pair.returns[2 * i + 1],
            b.entry.checked_add(b.ret_offset).unwrap()
        );
        assert_eq!(b.observed.returns, BTreeSet::from([b.ret_offset]));
        assert!(b.observed.subset(&b.declared));
        if case.length.bound == 0 {
            assert_eq!((b.input_reads, b.input_bytes), (0, 0));
        } else {
            assert!(b.input_reads > 0);
        }
        assert!(b.input_reads <= b.visits);
        assert!((b.input_reads..=b.input_reads.checked_mul(8).unwrap()).contains(&b.input_bytes));
        declared.extend(
            b.declared
                .returns
                .iter()
                .map(|r| b.entry.checked_add(*r).unwrap()),
        );
    }
    assert_eq!(pair.declared_returns, declared);
}
// Same complete population reducer, separately admitted for the named profile.
#[derive(Default)]
pub struct OptionalEntry80kPopulation {
    next: usize,
    k: Option<usize>,
    order: Option<[usize; 2]>,
    csv: Option<(Vec<u8>, csv::Graph)>,
    length: Option<(Vec<u8>, BodyCoverage)>,
    csv_heads: BTreeSet<u64>,
    csv_edges: BTreeSet<(u64, u64)>,
    csv_returns: BTreeSet<u64>,
    length_observed: BodyCoverage,
    comparisons: usize,
}
impl OptionalEntry80kPopulation {
    pub fn record(
        &mut self,
        seed: u64,
        case: Case,
        pair: &NormalPairResult<4>,
        trace: &Trace,
    ) -> Option<Coverage> {
        case.assert_session();
        self.record_common(seed, case, pair, trace)
    }
    fn record_common(
        &mut self,
        seed: u64,
        case: Case,
        pair: &NormalPairResult<4>,
        trace: &Trace,
    ) -> Option<Coverage> {
        assert!(self.next < 32);
        assert_eq!(
            (seed, case.csv.id()),
            (SEEDS[self.next / 16], self.next % 16 + 1)
        );
        assert_eq!(case.length, CASES[self.next % 8]);
        if let Some(k) = self.k {
            assert_eq!(k, case.k);
        } else {
            self.k = Some(case.k);
        }
        if let Some(order) = self.order {
            assert_eq!(order, case.order);
        } else {
            self.order = Some(case.order);
        }
        validate_pair(case, pair, trace);
        for b in &trace.csv {
            if let Some((code, g)) = &self.csv {
                assert_eq!((code, g), (&b.code, &b.declared));
            } else {
                self.csv = Some((b.code.clone(), b.declared.clone()));
            }
            self.csv_heads.extend(&b.heads);
            self.csv_edges.extend(&b.edges);
            self.csv_returns.insert(b.ret_offset);
        }
        for b in &trace.length {
            if let Some((code, g)) = &self.length {
                assert_eq!((code, g), (&b.code, &b.declared));
            } else {
                self.length = Some((b.code.clone(), b.declared.clone()));
            }
            self.length_observed.extend(&b.observed);
        }
        self.comparisons = self.comparisons.checked_add(pair.comparisons).unwrap();
        self.next += 1;
        if !self.next.is_multiple_of(16) {
            return None;
        }
        let csv = &self.csv.as_ref().unwrap().1;
        let length = &self.length.as_ref().unwrap().1;
        assert_eq!(self.csv_returns, csv.returns, "all CSV RETs per seed and K");
        assert_eq!(
            &self.length_observed, length,
            "unchanged full length CFG/read cohort per seed and K"
        );
        let coverage = Coverage {
            csv_heads: self.csv_heads.len(),
            csv_edges: self.csv_edges.len(),
            csv_declared_heads: csv.heads.len(),
            csv_declared_edges: csv.edges.len(),
            csv_returns: csv.returns.len(),
            length_heads: length.heads.len(),
            length_edges: length.edges.len(),
            length_returns: length.returns.len(),
        };
        self.csv_heads.clear();
        self.csv_edges.clear();
        self.csv_returns.clear();
        self.length_observed = BodyCoverage::default();
        Some(coverage)
    }
    pub fn finish(self) -> usize {
        assert_eq!(self.next, 32);
        assert!(
            self.k.is_some() && self.order.is_some() && self.csv.is_some() && self.length.is_some()
        );
        assert!(
            self.csv_heads.is_empty() && self.csv_edges.is_empty() && self.csv_returns.is_empty()
        );
        assert_eq!(self.length_observed, BodyCoverage::default());
        self.comparisons
    }
}

#[cfg(test)]
pub(in super::super) fn check_budget_boundaries() {
    let budget = StepBudget(());
    assert!(budget.allows(19_999));
    assert!(budget.allows(20_000));
    assert!(budget.allows(79_999));
    assert!(!budget.allows(80_000));
    assert!(!budget.allows(usize::MAX));
}
