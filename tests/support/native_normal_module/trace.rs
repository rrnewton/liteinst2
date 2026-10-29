use super::*;
pub struct Trace {
    pub csv: [csv::BodyTrace; 2],
    pub length: [BodyTrace; 2],
}
impl Trace {
    pub fn visits(&self) -> [usize; 4] {
        [
            self.csv[0].visits,
            self.length[0].visits,
            self.csv[1].visits,
            self.length[1].visits,
        ]
    }
    pub fn offsets(&self) -> [u64; 4] {
        [
            self.csv[0].ret_offset,
            self.length[0].ret_offset,
            self.csv[1].ret_offset,
            self.length[1].ret_offset,
        ]
    }
}
pub(super) fn inspect(oracle: &NormalOracle, ready: &Ready, points: &[Snapshot]) -> Trace {
    let case = oracle.module.unwrap();
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
    assert_eq!(starts.len(), 4);
    let mut csv = Vec::new();
    let mut length = Vec::new();
    for call in 0..4 {
        let f = ready.target(call);
        let start = starts[call];
        assert!(start > 0);
        assert_eq!(steps[start].before.rip, f.entry);
        assert_eq!(
            steps[start - 1].before.rip,
            ready.caller + bytes::CALLS[call]
        );
        let finish = (start..steps.len())
            .find(|&n| f.returns.contains(&steps[n].before.rip))
            .unwrap();
        assert!(call == 3 || finish < starts[call + 1]);
        let continuation = ready.caller + bytes::CONTINUATIONS[call];
        assert_eq!(steps[finish].after.rip, continuation);
        let input_offset = if call % 2 == 0 { INPUT } else { LENGTH_INPUT };
        let code = bytes_at(
            &ready.original_source,
            ready.immutable[0].0,
            f.entry,
            case.extents[call % 2],
        );
        if call % 2 == 0 {
            csv.push(csv::inspect_geometry(
                case.csv,
                f.entry,
                &f.heads,
                &f.returns,
                OriginalBody {
                    entry: f.entry,
                    continuation,
                    code,
                    input_address: oracle.data.address() + input_offset as u64,
                    input: &oracle.data.bytes()[input_offset..input_offset + case.bound(call)],
                    steps: &steps[start..=finish],
                },
            ));
        } else {
            // Reuse the exact existing original-byte/read/RET interpreter.
            length.push(strnlen::inspect_normal_body(
                case.length,
                f.entry,
                continuation,
                oracle.data.address() + input_offset as u64,
                code,
                &steps[start..=finish],
            ));
        }
    }
    Trace {
        csv: csv.try_into().ok().unwrap(),
        length: length.try_into().ok().unwrap(),
    }
}
pub(super) fn validate_pair(case: Case, pair: &NormalPairResult<4>, trace: &Trace) {
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
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
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
#[derive(Default)]
pub struct Population {
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
pub struct Coverage {
    pub csv_heads: usize,
    pub csv_edges: usize,
    pub csv_declared_heads: usize,
    pub csv_declared_edges: usize,
    pub csv_returns: usize,
    pub length_heads: usize,
    pub length_edges: usize,
    pub length_returns: usize,
}
impl Population {
    pub fn record(
        &mut self,
        seed: u64,
        case: Case,
        pair: &NormalPairResult<4>,
        trace: &Trace,
    ) -> Option<Coverage> {
        assert!(!case.is_session());
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
        if self.next % 16 != 0 {
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

/// Distinct admission wrapper over the same complete body/coverage reducer.
#[derive(Default)]
pub struct SessionPopulation(Population);
impl SessionPopulation {
    pub fn record(
        &mut self,
        seed: u64,
        case: Case,
        pair: &NormalPairResult<4>,
        trace: &Trace,
    ) -> Option<Coverage> {
        case.assert_session();
        self.0.record_common(seed, case, pair, trace)
    }
    pub fn finish(self) -> usize {
        self.0.finish()
    }
}
