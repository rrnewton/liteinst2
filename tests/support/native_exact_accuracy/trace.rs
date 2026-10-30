//! Complete ORIGINAL itinerary plus the existing independent Exact37 interpreter.
use super::*;
#[derive(Clone, Debug)]
pub struct Trace {
    pub(super) visits: usize,
    pub(super) return_pc: u64,
    pub(super) counts: (usize, usize, usize, usize),
}
pub(super) fn inspect<O>(
    oracle: &NormalOracle,
    ready: &Ready,
    points: &[Snapshot],
    inspect: O,
) -> Trace
where
    O: for<'a> FnOnce(OriginalBody<'a>) -> (usize, usize, usize, usize),
{
    let p = oracle.exact_accuracy.as_ref().unwrap();
    assert_eq!((p.case, &p.plan), (ready.case, &ready.plan));
    check(
        ready,
        points,
        oracle.data.address(),
        oracle.stack_start(),
        inspect,
    )
}
pub(super) fn check<O>(
    ready: &Ready,
    points: &[Snapshot],
    data: u64,
    stack: u64,
    inspect: O,
) -> Trace
where
    O: for<'a> FnOnce(OriginalBody<'a>) -> (usize, usize, usize, usize),
{
    let case = ready.case;
    case.assert_valid();
    caller_plan(&ready.plan);
    let f = ready.target();
    let code = source_bytes(&ready.original_sources, f.entry, BODY.len());
    assert_eq!(code, BODY);
    assert_eq!(f.heads, HEADS.map(|pc| f.entry + pc));
    assert_eq!(f.returns, [f.entry + 36]);
    let itinerary = case.itinerary();
    let call = ready.plan.calls()[0];
    let continuation = ready.caller + ready.plan.continuations()[0];
    let call_index = ready
        .plan
        .heads()
        .iter()
        .position(|&pc| pc == call)
        .unwrap();
    let visits: Vec<_> = ready.plan.heads()[..=call_index]
        .iter()
        .map(|&pc| ready.caller + pc)
        .chain(itinerary.iter().map(|&pc| f.entry + pc))
        .chain(
            ready.plan.heads()[call_index + 1..]
                .iter()
                .map(|&pc| ready.caller + pc),
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
    let end = start + itinerary.len();
    assert_eq!(points[start - 1].logical_pc, ready.caller + call);
    assert_eq!(points[end].logical_pc, continuation);
    assert_eq!(points.iter().filter(|p| p.logical_pc == f.entry).count(), 1);
    let first = &points[start];
    let last = &points[end - 1];
    let after = &points[end];
    assert_eq!(
        (first.registers.rdi, first.registers.rsi),
        (data + INPUT as u64, case.length as u64)
    );
    assert_eq!(&first.data[INPUT..INPUT + 64], case.input());
    assert_eq!(last.logical_pc, f.entry + 36);
    assert_eq!(
        (last.registers.rax, after.registers.rax),
        (case.value(), case.value())
    );
    assert_eq!(
        after.registers.rsp,
        first.registers.rsp.checked_add(8).unwrap()
    );
    for point in &points[start..=end] {
        assert_eq!(
            point.data, first.data,
            "all leaf data including guard bytes"
        );
        assert_eq!(
            point.application_stack, first.application_stack,
            "leaf stack and complete red zone"
        );
        assert_eq!(
            point.xstate, first.xstate,
            "scalar Exact37 preserves extended state"
        );
        if point.logical_pc != continuation {
            assert_eq!(point.registers.rsp, first.registers.rsp);
        }
    }
    let steps: Vec<_> = points
        .windows(2)
        .map(|w| OriginalStep {
            before: w[0].registers,
            after: w[1].registers,
            data_address: data,
            data: &w[0].data,
            stack_address: stack,
            stack: &w[0].application_stack,
        })
        .collect();
    let input = case.input();
    let counts = inspect(OriginalBody {
        entry: f.entry,
        continuation,
        code: &code,
        input_address: data + INPUT as u64,
        input: &input[..case.length],
        steps: &steps[start..end],
    });
    assert_eq!(counts, case.counts());
    Trace {
        visits: itinerary.len(),
        return_pc: f.entry + 36,
        counts,
    }
}
pub(super) fn validate_pair(case: Case, plan: &Plan, pair: &NormalPairResult<1>, trace: &Trace) {
    case.assert_valid();
    caller_plan(plan);
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
    assert_eq!(trace.counts, case.counts());
    assert_eq!(trace.visits, case.counts().0);
    assert_eq!(pair.visits, [trace.visits]);
    assert_eq!(pair.comparisons, plan.heads().len() + trace.visits + 1);
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
    assert_eq!(
        pair.declared_returns,
        pair.returns.iter().copied().collect()
    );
    assert_eq!(pair.returns, [trace.return_pc]);
}
