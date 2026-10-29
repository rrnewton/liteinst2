//! Existing original-body interpreters, with an exact separate 48-pair census.
use super::*;
#[derive(Clone)]
pub enum Trace {
    Csv(csv::BodyTrace),
    Length(BodyTrace),
}
impl Trace {
    pub fn visits(&self) -> usize {
        match self {
            Self::Csv(t) => t.visits,
            Self::Length(t) => t.visits,
        }
    }
    pub fn ret_offset(&self) -> u64 {
        match self {
            Self::Csv(t) => t.ret_offset,
            Self::Length(t) => t.ret_offset,
        }
    }
    pub fn input_reads(&self) -> Option<(usize, usize)> {
        match self {
            Self::Csv(_) => None,
            Self::Length(t) => Some((t.input_reads, t.input_bytes)),
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
        }
    }
    fn code(&self) -> &[u8] {
        match self {
            Self::Csv(t) => &t.code,
            Self::Length(t) => &t.code,
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
        }
    }
}
pub(super) fn inspect(oracle: &NormalOracle, ready: &Ready, points: &[Snapshot]) -> Trace {
    let p = oracle.copied_rust.as_ref().unwrap();
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
    let code = bytes_at(
        &ready.original_source,
        ready.immutable[0].0,
        f.entry,
        ready.case.extents[ready.case.function],
    );
    if ready.case.function == 0 {
        Trace::Csv(csv::inspect_geometry(
            csv::Case::new(ready.case.index),
            f.entry,
            &f.heads,
            &f.returns,
            OriginalBody {
                entry: f.entry,
                continuation,
                code,
                input_address: oracle.data.address() + INPUT as u64,
                input: &oracle.data.bytes()[INPUT..INPUT + ready.case.bound()],
                steps: &steps[start..=finish],
            },
        ))
    } else {
        Trace::Length(strnlen::inspect_normal_body(
            CASES[ready.case.index],
            f.entry,
            continuation,
            oracle.data.address() + INPUT as u64,
            code,
            &steps[start..=finish],
        ))
    }
}
pub(super) fn validate_pair(case: Case, plan: &Plan, pair: &NormalPairResult<1>, trace: &Trace) {
    case.assert_valid();
    assert_eq!(
        case.function,
        usize::from(matches!(trace, Trace::Length(_)))
    );
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
#[derive(Default)]
pub struct Population {
    next: usize,
    plan: Option<Plan>,
    geometry: Option<([usize; 2], [usize; 2])>,
    codes: [Option<Vec<u8>>; 2],
    declared: [Option<BodyCoverage>; 2],
    observed: BodyCoverage,
    comparisons: usize,
    group_comparisons: usize,
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
        assert!(self.next < 48);
        assert_eq!(seed, SEEDS[self.next / 24]);
        let local = self.next % 24;
        assert_eq!(
            (case.function, case.index),
            if local < 16 {
                (0, local)
            } else {
                (1, local - 16)
            }
        );
        validate_pair(case, plan, pair, trace);
        if let Some(old) = &self.plan {
            assert_eq!(old, plan);
        } else {
            self.plan = Some(plan.clone());
        }
        let geometry = (case.extents, case.order);
        if let Some(old) = self.geometry {
            assert_eq!(old, geometry);
        } else {
            self.geometry = Some(geometry);
        }
        let (observed, declared) = trace.coverage();
        let f = case.function;
        if let Some(old) = &self.codes[f] {
            assert_eq!(old, trace.code());
            assert_eq!(self.declared[f].as_ref().unwrap(), &declared);
        } else {
            self.codes[f] = Some(trace.code().to_vec());
            self.declared[f] = Some(declared.clone());
        }
        self.observed.extend(&observed);
        self.comparisons = self.comparisons.checked_add(pair.comparisons).unwrap();
        self.group_comparisons = self
            .group_comparisons
            .checked_add(pair.comparisons)
            .unwrap();
        self.next += 1;
        if local == 15 || local == 23 {
            assert_eq!(
                self.observed.returns, declared.returns,
                "all declared function RETs per seed"
            );
            assert!(self.observed.subset(&declared));
            if f == 1 {
                assert_eq!(self.observed, declared, "complete reachable length CFG");
            }
            let c = Coverage {
                heads: self.observed.heads.len(),
                declared_heads: declared.heads.len(),
                edges: self.observed.edges.len(),
                declared_edges: declared.edges.len(),
                returns: self.observed.returns.len(),
                declared_returns: declared.returns.len(),
                comparisons: self.group_comparisons,
            };
            self.observed = BodyCoverage::default();
            self.group_comparisons = 0;
            Some(c)
        } else {
            None
        }
    }
    pub fn finish(&self) -> usize {
        assert_eq!(self.next, 48);
        assert!(self.plan.is_some() && self.geometry.is_some());
        assert!(
            self.codes.iter().all(Option::is_some) && self.declared.iter().all(Option::is_some)
        );
        assert_eq!(self.observed, BodyCoverage::default());
        assert_eq!(self.group_comparisons, 0);
        self.comparisons
    }
}
