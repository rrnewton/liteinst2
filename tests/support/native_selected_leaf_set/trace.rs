//! Independent complete compiler-body itineraries and scalar/read observations.
//! The actual original/installed full architectural comparator stays unchanged.
use super::*;
#[derive(Clone, Debug)]
pub struct Trace {
    visits: usize,
    ret: u64,
    reads: usize,
    heads: BTreeSet<u64>,
    edges: BTreeSet<(u64, u64)>,
    declared_heads: BTreeSet<u64>,
    declared_edges: BTreeSet<(u64, u64)>,
    returns: BTreeSet<u64>,
}
impl Trace {
    pub fn visits(&self) -> usize {
        self.visits
    }
}
fn declared(operation: usize) -> (BTreeSet<u64>, BTreeSet<(u64, u64)>) {
    let mut heads = BTreeSet::new();
    let mut edges = BTreeSet::new();
    for input in compiled::INPUTS {
        let e = compiled::expected(input, operation);
        heads.extend(e.visits.iter().map(|&x| x as u64));
        edges.extend(e.visits.windows(2).map(|p| (p[0] as u64, p[1] as u64)));
    }
    assert_eq!(heads.len(), [13, 17][operation]);
    (heads, edges)
}
fn body(
    case: Case,
    entry: u64,
    continuation: u64,
    input_address: u64,
    points: &[Snapshot],
) -> Trace {
    case.assert_valid();
    let input = compiled::INPUTS[case.index];
    let e = compiled::expected(input, case.operation);
    assert_eq!(case.value(), e.answer);
    assert_eq!(points.len(), e.visits.len() + 1);
    let observed: Vec<_> = points[..points.len() - 1]
        .iter()
        .map(|p| p.logical_pc)
        .collect();
    assert_eq!(
        observed,
        e.visits
            .iter()
            .map(|&at| entry + at as u64)
            .collect::<Vec<_>>()
    );
    assert_eq!(points.last().unwrap().logical_pc, continuation);
    let first = &points[0];
    let last = &points[points.len() - 2];
    let after = points.last().unwrap();
    assert_eq!(
        (first.registers.rdi, first.registers.rsi),
        (input_address, input.len() as u64)
    );
    assert_eq!(&first.data[INPUT..INPUT + 64], case.input());
    assert_eq!(last.logical_pc, entry + e.ret as u64);
    assert_eq!(
        (last.registers.rax, after.registers.rax),
        (e.answer, e.answer)
    );
    assert_eq!(
        after.registers.rsp,
        first.registers.rsp.checked_add(8).unwrap()
    );
    for point in points {
        assert_eq!(point.data, first.data, "complete read-only leaf data");
        assert_eq!(
            point.application_stack, first.application_stack,
            "complete leaf stack/red zone"
        );
        assert_eq!(
            point.xstate, first.xstate,
            "scalar leaf leaves all extended state unchanged"
        );
        if point.logical_pc != continuation {
            assert_eq!(point.registers.rsp, first.registers.rsp);
        }
    }
    let read_pc = entry + if case.operation == 0 { 25 } else { 16 };
    let reads: Vec<_> = points.iter().filter(|p| p.logical_pc == read_pc).collect();
    assert_eq!(reads.len(), e.reads.len());
    for (point, &index) in reads.iter().zip(&e.reads) {
        assert!(index < input.len());
        let address = if case.operation == 0 {
            point
                .registers
                .rdi
                .checked_add(point.registers.rdx)
                .unwrap()
        } else {
            point.registers.rdi
        };
        assert_eq!(address, input_address + index as u64);
        assert_eq!(point.data[INPUT + index], input[index]);
    }
    if case.operation == 1 {
        let before: Vec<_> = points
            .iter()
            .filter(|p| p.logical_pc == entry + 24)
            .collect();
        let after: Vec<_> = points
            .iter()
            .filter(|p| p.logical_pc == entry + 28)
            .collect();
        assert_eq!((before.len(), after.len()), (input.len(), input.len()));
        let mut count = 0;
        for ((a, b), &byte) in before.iter().zip(after).zip(input) {
            let carry = u64::from(byte.is_ascii_uppercase());
            assert_eq!((a.registers.eflags & 1, a.registers.r8), (carry, count));
            count += carry;
            assert_eq!(b.registers.r8, count);
        }
        assert_eq!(count, e.answer);
    }
    let (declared_heads, declared_edges) = declared(case.operation);
    Trace {
        visits: e.visits.len(),
        ret: e.ret as u64,
        reads: reads.len(),
        heads: e.visits.iter().map(|&p| p as u64).collect(),
        edges: e
            .visits
            .windows(2)
            .map(|p| (p[0] as u64, p[1] as u64))
            .collect(),
        declared_heads,
        declared_edges,
        returns: compiled::RETURNS[case.operation]
            .into_iter()
            .map(|x| x as u64)
            .collect(),
    }
}
pub(super) fn inspect(oracle: &NormalOracle, ready: &Ready, points: &[Snapshot]) -> Trace {
    let profile = oracle.selected_leaf_set.as_ref().unwrap();
    assert_eq!((&profile.plan, profile.case), (&ready.plan, ready.case));
    let f = ready.target();
    let case = ready.case;
    assert_eq!(
        source_bytes(
            &ready.original_sources,
            f.entry,
            case.selections[case.operation].extent
        ),
        compiled::BODIES[case.operation]
    );
    let call = ready.plan.calls()[0];
    let continuation = ready.plan.continuations()[0];
    let call_index = ready.plan.heads().iter().position(|&p| p == call).unwrap();
    let expected = compiled::expected(compiled::INPUTS[case.index], case.operation);
    let visits: Vec<_> = ready.plan.heads()[..=call_index]
        .iter()
        .map(|&p| ready.caller + p)
        .chain(expected.visits.iter().map(|&p| f.entry + p as u64))
        .chain(
            ready.plan.heads()[call_index + 1..]
                .iter()
                .map(|&p| ready.caller + p),
        )
        .collect();
    assert_eq!(points.len(), visits.len() + 1);
    assert_eq!(
        points[..points.len() - 1]
            .iter()
            .map(|p| p.logical_pc)
            .collect::<Vec<_>>(),
        visits
    );
    let start = call_index + 1;
    let end = start + expected.visits.len();
    assert_eq!(points[start - 1].logical_pc, ready.caller + call);
    assert_eq!(points[end].logical_pc, ready.caller + continuation);
    assert_eq!(
        points
            .iter()
            .filter(|p| ready.functions.iter().any(|f| f.entry == p.logical_pc))
            .count(),
        1
    );
    body(
        case,
        f.entry,
        ready.caller + continuation,
        oracle.data.address() + INPUT as u64,
        &points[start..=end],
    )
}
pub(super) fn validate_pair(case: Case, plan: &Plan, pair: &NormalPairResult<1>, trace: &Trace) {
    case.assert_valid();
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
    assert_eq!(pair.outer_value, case.value());
    assert_eq!(pair.visits, [trace.visits]);
    assert_eq!(pair.comparisons, plan.heads().len() + trace.visits + 1);
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
    assert_eq!(pair.returns.len(), 1);
    let entry = pair.returns[0].checked_sub(trace.ret).unwrap();
    assert_eq!(
        pair.declared_returns,
        trace.returns.iter().map(|p| entry + p).collect()
    );
    let expected = compiled::expected(compiled::INPUTS[case.index], case.operation);
    assert_eq!(
        (trace.visits, trace.ret, trace.reads),
        (
            expected.visits.len(),
            expected.ret as u64,
            expected.reads.len()
        )
    );
    assert_eq!(
        trace.heads,
        expected.visits.iter().map(|&p| p as u64).collect()
    );
    assert_eq!(
        trace.edges,
        expected
            .visits
            .windows(2)
            .map(|p| (p[0] as u64, p[1] as u64))
            .collect()
    );
    assert!(
        trace.heads.is_subset(&trace.declared_heads)
            && trace.edges.is_subset(&trace.declared_edges)
    );
    assert_eq!(
        trace.returns,
        compiled::RETURNS[case.operation]
            .into_iter()
            .map(|x| x as u64)
            .collect()
    );
}
pub(super) fn fields(trace: &Trace) -> Vec<String> {
    let mut fields = [
        trace.reads,
        trace.ret as usize,
        trace.heads.len(),
        trace.declared_heads.len(),
        trace.edges.len(),
        trace.declared_edges.len(),
        trace.returns.len(),
    ]
    .map(|n| n.to_string())
    .to_vec();
    let heads = |values: &BTreeSet<u64>| {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(";")
    };
    let edges = |values: &BTreeSet<(u64, u64)>| {
        values
            .iter()
            .map(|(a, b)| format!("{a}-{b}"))
            .collect::<Vec<_>>()
            .join(";")
    };
    fields.extend([
        heads(&trace.heads),
        edges(&trace.edges),
        heads(&trace.declared_heads),
        edges(&trace.declared_edges),
        heads(&trace.returns),
    ]);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    fn refuses(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    fn points(case: Case) -> Vec<Snapshot> {
        let e = compiled::expected(compiled::INPUTS[case.index], case.operation);
        let mut data = vec![0x5a; PAGE];
        data[INPUT..INPUT + 64].copy_from_slice(&case.input());
        let mut count = 0;
        let mut read = 0;
        e.visits
            .iter()
            .map(|&p| 0x4000 + p as u64)
            .chain([0x108f])
            .map(|pc| {
                // Inert complete copies only; this never constructs loaded authority.
                let mut r: libc::user_regs_struct = unsafe { std::mem::zeroed() };
                r.rip = pc;
                r.rsp = 0x9000;
                r.rdi = 0x600080;
                r.rsi = case.bound() as u64;
                r.rax = e.answer;
                r.eflags = 0x202;
                if case.operation == 0 && pc == 0x4019 {
                    r.rdx = e.reads[read] as u64;
                    read += 1;
                }
                if case.operation == 1 {
                    if pc == 0x4010 {
                        r.rdi += read as u64;
                        read += 1;
                    }
                    if pc == 0x4018 {
                        r.eflags |=
                            u64::from(compiled::INPUTS[case.index][read - 1].is_ascii_uppercase());
                        r.r8 = count;
                    }
                    if pc == 0x401c {
                        count +=
                            u64::from(compiled::INPUTS[case.index][read - 1].is_ascii_uppercase());
                        r.r8 = count;
                    }
                }
                if pc == 0x108f {
                    r.rsp += 8;
                }
                Snapshot {
                    logical_pc: pc,
                    registers: r,
                    xstate: vec![0; 512],
                    data: data.clone(),
                    application_stack: vec![0xa5; 152],
                }
            })
            .collect()
    }
    #[test]
    fn selected_original_semantic_calibrations_reject_trace_value_input_read_and_state_mutants() {
        for operation in 0..2 {
            for index in 0..12 {
                let case = super::super::tests::case(operation, index);
                let p = points(case);
                let t = body(case, 0x4000, 0x108f, 0x600080, &p);
                assert_eq!(
                    t.ret,
                    compiled::expected(compiled::INPUTS[index], operation).ret as u64
                );
            }
            let case = super::super::tests::case(operation, 4);
            for mutation in 0..10 {
                let mut p = points(case);
                let ret = p.len() - 2;
                match mutation {
                    0 => p[1].logical_pc = p[0].logical_pc,
                    1 => {
                        p.remove(2);
                    }
                    2 => {
                        p[ret].registers.rax ^= 1;
                        p[ret + 1].registers.rax = p[ret].registers.rax;
                    }
                    3 => {
                        for point in &mut p {
                            point.data[INPUT] ^= 1;
                        }
                    }
                    4 => {
                        p.iter_mut()
                            .find(|p| p.logical_pc == 0x4000 + if operation == 0 { 25 } else { 16 })
                            .unwrap()
                            .registers
                            .rdi += 1
                    }
                    5 => p[2].application_stack[0] ^= 1,
                    6 => p[2].data[PAGE - 1] ^= 1,
                    7 => p[2].xstate[511] ^= 1,
                    8 => p[2].registers.rsp += 8,
                    _ => p[ret + 1].logical_pc += 1,
                }
                refuses(|| {
                    body(case, 0x4000, 0x108f, 0x600080, &p);
                });
            }
        }
        let case = super::super::tests::case(1, 4);
        for pc in [0x4018, 0x401c] {
            let mut p = points(case);
            let at = p.iter_mut().find(|p| p.logical_pc == pc).unwrap();
            if pc == 0x4018 {
                at.registers.eflags ^= 1;
            } else {
                at.registers.r8 += 1;
            }
            refuses(|| {
                body(case, 0x4000, 0x108f, 0x600080, &p);
            });
        }
    }
    #[test]
    fn selected_pair_refuses_missing_call_return_reap_comparison_and_declared_return() {
        let case = super::super::tests::case(1, 4);
        let p = points(case);
        let trace = body(case, 0x4000, 0x108f, 0x600080, &p);
        let plan = rust_invoke::admit(&[
            0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff,
            0xd0, 0x48, 0x89, 0x03, 0x5b, 0xc3,
        ])
        .unwrap();
        let pair = || NormalPairResult {
            comparisons: plan.heads().len() + trace.visits + 1,
            original_steps: 1000,
            candidate_steps: 1200,
            visits: [trace.visits],
            returns: [0x4000 + trace.ret],
            declared_returns: trace.returns.iter().map(|r| 0x4000 + r).collect(),
            values: [case.value()],
            outer_value: case.value(),
            target_calls: 2,
            target_returns: 2,
            outer_returns: 2,
            normal_reaps: 2,
        };
        validate_pair(case, &plan, &pair(), &trace);
        for field in 0..9 {
            let mut p = pair();
            match field {
                0 => p.target_calls -= 1,
                1 => p.target_returns -= 1,
                2 => p.outer_returns -= 1,
                3 => p.normal_reaps -= 1,
                4 => p.comparisons -= 1,
                5 => p.values[0] ^= 1,
                6 => p.outer_value ^= 1,
                7 => p.declared_returns.clear(),
                _ => p.candidate_steps = MAX_STEPS + 1,
            }
            refuses(|| validate_pair(case, &plan, &p, &trace));
        }
    }
}
