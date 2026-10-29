//! Original-only body interpretation and the fixed all-subset LeafSet census.
use super::*;
#[derive(Clone)]
pub enum Trace {
    Csv(csv::BodyTrace),
    Length(BodyTrace),
    Scanner(scanner::Trace),
}
impl Trace {
    pub fn visits(&self) -> usize {
        match self {
            Self::Csv(t) => t.visits,
            Self::Length(t) => t.visits,
            Self::Scanner(t) => t.visits(),
        }
    }
    pub fn ret_offset(&self) -> u64 {
        match self {
            Self::Csv(t) => t.ret_offset,
            Self::Length(t) => t.ret_offset,
            Self::Scanner(t) => t.ret_offset(),
        }
    }
    pub fn input_reads(&self) -> Option<(usize, usize)> {
        match self {
            Self::Csv(_) => None,
            Self::Length(t) => Some((t.input_reads, t.input_bytes)),
            Self::Scanner(t) => Some((t.input_reads(), t.input_bytes())),
        }
    }
    pub fn counts(&self) -> (usize, usize, usize, usize, usize) {
        let (observed, declared) = self.coverage();
        (
            observed.heads.len(),
            declared.heads.len(),
            observed.edges.len(),
            declared.edges.len(),
            declared.returns.len(),
        )
    }
    fn entry(&self) -> u64 {
        match self {
            Self::Csv(t) => t.entry,
            Self::Length(t) => t.entry,
            Self::Scanner(t) => t.entry(),
        }
    }
    fn code(&self) -> &[u8] {
        match self {
            Self::Csv(t) => &t.code,
            Self::Length(t) => &t.code,
            Self::Scanner(t) => t.code(),
        }
    }
    fn coverage(&self) -> (BodyCoverage, BodyCoverage) {
        match self {
            Self::Csv(t) => (
                BodyCoverage {
                    heads: t.heads.clone(),
                    edges: t.edges.clone(),
                    returns: BTreeSet::from([t.ret_offset]),
                },
                BodyCoverage {
                    heads: t.declared.heads.clone(),
                    edges: t.declared.edges.clone(),
                    returns: t.declared.returns.clone(),
                },
            ),
            Self::Length(t) => (t.observed.clone(), t.declared.clone()),
            Self::Scanner(t) => {
                let convert = |c: &scanner::Coverage| BodyCoverage {
                    heads: c.heads.clone(),
                    edges: c.edges.clone(),
                    returns: c.returns.clone(),
                };
                assert_eq!(t.effects_checked(), t.visits());
                assert_eq!(t.effect_heads(), &t.observed().heads);
                (convert(t.observed()), convert(t.declared()))
            }
        }
    }
}
pub(super) fn inspect(oracle: &NormalOracle, ready: &Ready, points: &[Snapshot]) -> Trace {
    let p = oracle.leaf_set_copied.as_ref().unwrap();
    assert_eq!((&p.plan, p.case), (&ready.plan, ready.case));
    let steps: Vec<_> = points
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
    let starts: Vec<_> = steps
        .iter()
        .enumerate()
        .filter_map(|(n, s)| {
            ready
                .functions
                .iter()
                .any(|f| f.entry == s.before.rip)
                .then_some(n)
        })
        .collect();
    assert_eq!(starts.len(), 1);
    let start = starts[0];
    assert!(start > 0);
    let f = ready.target();
    assert_eq!(steps[start].before.rip, f.entry);
    assert_eq!(
        steps[start - 1].before.rip,
        ready.caller + ready.plan.calls()[0]
    );
    let finish = (start..steps.len())
        .find(|&n| f.returns.contains(&steps[n].before.rip))
        .unwrap();
    let continuation = ready.caller + ready.plan.continuations()[0];
    assert_eq!(steps[finish].after.rip, continuation);
    let code = source_bytes(
        &ready.original_sources,
        f.entry,
        ready.case.selections[ready.case.operation].extent,
    );
    if ready.case.operation == 0 {
        Trace::Csv(csv::inspect_geometry(
            csv::Case::new(ready.case.index),
            f.entry,
            &f.heads,
            &f.returns,
            OriginalBody {
                entry: f.entry,
                continuation,
                code: &code,
                input_address: oracle.data.address() + INPUT as u64,
                input: &oracle.data.bytes()[INPUT..INPUT + ready.case.bound()],
                steps: &steps[start..=finish],
            },
        ))
    } else if ready.case.operation == 1 {
        Trace::Length(strnlen::inspect_normal_body(
            CASES[ready.case.index],
            f.entry,
            continuation,
            oracle.data.address() + INPUT as u64,
            &code,
            &steps[start..=finish],
        ))
    } else {
        fn state(p: &Snapshot) -> scanner::State<'_> {
            scanner::State {
                registers: &p.registers,
                xstate: &p.xstate,
                data: &p.data,
                stack: &p.application_stack,
            }
        }
        let windows: Vec<_> = points[start..=finish + 1]
            .windows(2)
            .map(|p| scanner::Step {
                before: state(&p[0]),
                after: state(&p[1]),
            })
            .collect();
        let plan = scanner::Plan::decode(&code);
        Trace::Scanner(scanner::inspect(
            if ready.case.operation == 2 {
                scanner::Operation::Digits
            } else {
                scanner::Operation::Spaces
            },
            scanner::Case::new(ready.case.index),
            &plan,
            scanner::Observation {
                entry: f.entry,
                continuation,
                input_address: oracle.data.address() + INPUT as u64,
                data_address: oracle.data.address(),
                stack_address: oracle.stack_start(),
                code: &code,
                input: &oracle.data.bytes()[INPUT..INPUT + ready.case.bound()],
                steps: &windows,
            },
        ))
    }
}
pub(super) fn validate_pair(case: Case, plan: &Plan, pair: &NormalPairResult<1>, trace: &Trace) {
    case.assert_valid();
    assert!(matches!(
        (case.operation, trace),
        (0, Trace::Csv(_)) | (1, Trace::Length(_)) | (2 | 3, Trace::Scanner(_))
    ));
    assert_eq!(
        (
            pair.target_calls,
            pair.target_returns,
            pair.outer_returns,
            pair.normal_reaps
        ),
        (2, 2, 2, 2)
    );
    assert_eq!(pair.values, [case.value()]);
    assert_eq!(pair.visits, [trace.visits()]);
    assert!(trace.visits() > 0);
    assert_eq!(pair.comparisons, plan.heads().len() + trace.visits() + 1);
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
    assert_eq!(
        pair.returns,
        [trace.entry().checked_add(trace.ret_offset()).unwrap()]
    );
    let (observed, declared) = trace.coverage();
    assert!(observed.subset(&declared));
    assert_eq!(observed.returns, BTreeSet::from([trace.ret_offset()]));
    assert_eq!(
        pair.declared_returns,
        declared
            .returns
            .iter()
            .map(|n| trace.entry().checked_add(*n).unwrap())
            .collect()
    );
    if let Some((reads, bytes)) = trace.input_reads() {
        assert!(reads <= trace.visits());
        assert!((reads..=reads.checked_mul(8).unwrap()).contains(&bytes));
        if case.bound() == 0 {
            assert_eq!((reads, bytes), (0, 0));
        } else {
            assert!(reads > 0);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Coverage {
    pub heads: usize,
    pub declared_heads: usize,
    pub edges: usize,
    pub declared_edges: usize,
    pub returns: usize,
    pub declared_returns: usize,
    pub comparisons: usize,
}
pub struct Population {
    next: usize,
    keys: Vec<(u8, usize, u64, usize, usize)>,
    plan: Option<Plan>,
    selections: Option<[Selection; 4]>,
    codes: [Option<Vec<u8>>; 4],
    declared: [Option<BodyCoverage>; 4],
    observed: BodyCoverage,
    comparisons: usize,
    group_comparisons: usize,
    groups: usize,
}
impl Default for Population {
    fn default() -> Self {
        Self {
            next: 0,
            keys: keys(),
            plan: None,
            selections: None,
            codes: std::array::from_fn(|_| None),
            declared: std::array::from_fn(|_| None),
            observed: BodyCoverage::default(),
            comparisons: 0,
            group_comparisons: 0,
            groups: 0,
        }
    }
}
pub(super) fn coverage_complete(
    operation: usize,
    observed: &BodyCoverage,
    declared: &BodyCoverage,
) {
    assert!(observed.subset(declared));
    assert_eq!(observed.returns, declared.returns);
    if operation != 0 {
        assert_eq!(observed, declared);
    }
}
pub(super) struct Observation<'a> {
    pub comparisons: usize,
    pub code: &'a [u8],
    pub observed: BodyCoverage,
    pub declared: BodyCoverage,
}
impl Population {
    pub fn record(
        &mut self,
        seed: u64,
        case: Case,
        plan: &Plan,
        pair: &NormalPairResult<1>,
        trace: &Trace,
    ) -> Option<Coverage> {
        validate_pair(case, plan, pair, trace);
        let (observed, declared) = trace.coverage();
        self.record_observation(
            seed,
            case,
            plan,
            Observation {
                comparisons: pair.comparisons,
                code: trace.code(),
                observed,
                declared,
            },
        )
    }
    // Metadata-only extraction shared by real traces and explicitly fabricated
    // population controls. Only record() accepts a native pair and sealed Trace.
    pub(super) fn record_observation(
        &mut self,
        seed: u64,
        case: Case,
        plan: &Plan,
        o: Observation<'_>,
    ) -> Option<Coverage> {
        case.assert_valid();
        assert!(self.next < 1280);
        assert_eq!(
            self.keys[self.next],
            (case.subset, case.k, seed, case.operation, case.index)
        );
        assert!(o.comparisons > 0 && !o.code.is_empty());
        assert!(o.observed.subset(&o.declared));
        assert!(!o.observed.heads.is_empty() && o.observed.returns.len() == 1);
        if let Some(expected) = &self.plan {
            assert_eq!(expected, plan);
        } else {
            self.plan = Some(plan.clone());
        }
        if let Some(expected) = self.selections {
            assert_eq!(expected, case.selections);
        } else {
            self.selections = Some(case.selections);
        }
        let i = case.operation;
        if let Some(code) = &self.codes[i] {
            assert_eq!(code, o.code);
        } else {
            self.codes[i] = Some(o.code.to_vec());
        }
        if let Some(expected) = &self.declared[i] {
            assert_eq!(expected, &o.declared);
        } else {
            self.declared[i] = Some(o.declared.clone());
        }
        self.observed.heads.extend(o.observed.heads);
        self.observed.edges.extend(o.observed.edges);
        self.observed.returns.extend(o.observed.returns);
        self.comparisons = self.comparisons.checked_add(o.comparisons).unwrap();
        self.group_comparisons = self.group_comparisons.checked_add(o.comparisons).unwrap();
        self.next += 1;
        if case.index + 1 == CASE_COUNTS[i] {
            coverage_complete(i, &self.observed, &o.declared);
            let result = Coverage {
                heads: self.observed.heads.len(),
                declared_heads: o.declared.heads.len(),
                edges: self.observed.edges.len(),
                declared_edges: o.declared.edges.len(),
                returns: self.observed.returns.len(),
                declared_returns: o.declared.returns.len(),
                comparisons: self.group_comparisons,
            };
            self.observed = BodyCoverage::default();
            self.group_comparisons = 0;
            self.groups += 1;
            Some(result)
        } else {
            None
        }
    }
    pub fn finish(self) -> usize {
        assert_eq!(
            (self.next, self.groups, self.group_comparisons),
            (1280, 128, 0)
        );
        assert_eq!(self.observed, BodyCoverage::default());
        assert!(
            self.codes.iter().all(Option::is_some) && self.declared.iter().all(Option::is_some)
        );
        self.comparisons
    }
}
