//! Nineteen original owner cases plus one accessor-first refusal, all fresh processes.
use super::*;
use crate::frontend::RecordObservation;
use crate::frontend_native::always_on::tree::native_checks;
use crate::frontend_native::{
    OriginalTreeCallResult, TreeBatch, TreeCallResult, TreeError, TreeSourceBatch,
    TreeSourceBatchError, TreeSourceBatchRequest, TreeThread,
};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::rc::Rc;

fn preparation() -> (TreeSitePreparation, usize) {
    let candidate = std::env::var_os("RAPID_TREE_CANDIDATE").expect("candidate ELF");
    let expected = std::env::var_os("RAPID_TREE_EXPECTED").expect("independent expected ELF");
    let candidate = Path::new(&candidate);
    let bytes = expected_file(candidate, Path::new(&expected));
    let cpu = pin(None);
    // SAFETY: same fixed, independently authenticated fixture and exclusive
    // caller/source/stack contract as the parent control. No helper exists yet.
    let owner = unsafe {
        LoadedCallTree::load(
            candidate,
            &bytes,
            c"call_tree_root",
            c"call_tree_child",
            TREE_CONTRACT,
        )
    }
    .unwrap();
    let root = owner.certificate().root().entry();
    let gate = TreeCallGate::new(owner.certificate().root()).unwrap();
    (
        TreeSitePreparation::new(owner, gate, identity(root)).unwrap(),
        cpu,
    )
}

fn requests(bytes: &[u8], first: u64) -> [TreeSourceBatchRequest<'_>; 8] {
    std::array::from_fn(|i| TreeSourceBatchRequest {
        bytes,
        external_id: first + i as u64,
    })
}
fn config_n(n: usize) -> Config {
    Config {
        retained_per_function: 1,
        max_inflight: 2,
        max_invocations: n,
    }
}
fn prepared(
    prep: TreeSitePreparation,
    epochs: usize,
    records: usize,
    actions: usize,
) -> PreparedTreeController {
    PreparedTreeController::new(
        publish_tree(prep),
        INSTALL,
        FUNCTIONS,
        Limits {
            epochs,
            threads: 1,
            depth: 2,
            records_per_epoch: records,
            actions,
        },
    )
    .unwrap()
}
fn original_result(call: OriginalTreeCallResult, input: &Input, before: &Input) {
    assert_eq!(call.value, VALUE);
    assert_eq!(call.pre_call_rsp, call.resumed_rsp);
    assert_eq!(input, before);
}
fn installed_result(call: TreeCallResult, id: u64, root: u64, input: &Input, before: &Input) {
    assert_eq!(call.external_id, id);
    assert_eq!(call.value, VALUE);
    assert_eq!(call.pre_call_rsp, call.resumed_rsp);
    assert_eq!(call.entry_rsp.checked_add(8), Some(call.pre_call_rsp));
    assert_eq!(call.return_pc, root + 22);
    assert_eq!(input, before);
}
fn same_error(first: &TreeSourceBatchError, next: TreeSourceBatchError) {
    match (first, next) {
        (TreeSourceBatchError::Abandoned, TreeSourceBatchError::Abandoned)
        | (TreeSourceBatchError::Unfinished, TreeSourceBatchError::Unfinished)
        | (TreeSourceBatchError::CallCount, TreeSourceBatchError::CallCount) => {}
        (TreeSourceBatchError::Call(a), TreeSourceBatchError::Call(b)) => {
            assert!(Rc::ptr_eq(a, &b));
            assert!(
                matches!(a.as_ref(), TreeError::Bridge(e) if *e == error(Cause::ControllerReentry))
            );
        }
        (a, b) => panic!("batch first cause changed: {a:?} -> {b:?}"),
    }
}
fn refused<T>(result: Result<T, TreeSourceBatchError>) -> TreeSourceBatchError {
    match result {
        Ok(_) => panic!("unexpected batch admission/success"),
        Err(e) => e,
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Drop(usize),
    Forget(usize),
    First,
    Unwind,
    Early,
    Extra,
}
impl Failure {
    fn calls(self) -> usize {
        match self {
            Self::Drop(n) | Self::Forget(n) => n,
            Self::Extra => 8,
            _ => 1,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Drop(_) | Self::Unwind => "Abandoned",
            Self::Forget(_) => "Unfinished",
            Self::First => "ControllerReentry",
            Self::Early | Self::Extra => "CallCount",
        }
    }
}
#[derive(Debug, Eq, PartialEq)]
struct CallerUnwind;

fn original_failure(name: &str, mode: Failure) {
    let (mut prep, _) = preparation();
    let gate = Arc::clone(prep.gate());
    let start = gate.idle_checkpoint().unwrap();
    let input = input();
    let before = input.clone();
    let readable = stack();
    let requests = [&input.0[64..1088]; 8];
    let payload = Box::new(CallerUnwind);
    let mut batch = unsafe { prep.begin_original_source_batch(&requests, &readable) }.unwrap();
    for _ in 0..mode.calls() {
        original_result(unsafe { batch.invoke_next() }.unwrap(), &input, &before);
    }
    let returned = gate.idle_checkpoint().unwrap();
    assert_eq!(returned, start + mode.calls() as u64);
    let first = match mode {
        Failure::Drop(_) => {
            drop(batch);
            TreeSourceBatchError::Abandoned
        }
        Failure::Forget(_) => {
            std::mem::forget(batch);
            TreeSourceBatchError::Unfinished
        }
        Failure::Unwind => {
            let result: Result<(), _> = catch_unwind(AssertUnwindSafe(|| {
                let _guard = batch;
                resume_unwind(payload);
            }));
            assert_eq!(
                result.unwrap_err().downcast_ref::<CallerUnwind>(),
                Some(&CallerUnwind)
            );
            TreeSourceBatchError::Abandoned
        }
        Failure::Early => {
            let e = batch.finish().unwrap_err();
            same_error(&TreeSourceBatchError::CallCount, e);
            TreeSourceBatchError::CallCount
        }
        Failure::Extra | Failure::First => {
            let e = if matches!(mode, Failure::First) {
                let scope = ControllerScope::enter().unwrap();
                let e = unsafe { batch.invoke_next() }.unwrap_err();
                drop(scope);
                assert!(
                    matches!(&e, TreeSourceBatchError::Call(c) if matches!(c.as_ref(), TreeError::Bridge(b) if *b == error(Cause::ControllerReentry)))
                );
                e
            } else {
                let e = unsafe { batch.invoke_next() }.unwrap_err();
                same_error(&TreeSourceBatchError::CallCount, e);
                TreeSourceBatchError::CallCount
            };
            same_error(&e, unsafe { batch.invoke_next() }.unwrap_err());
            same_error(&e, batch.finish().unwrap_err());
            e
        }
    };
    assert!(matches!(
        unsafe { prep.prepare_original_call() },
        Err(crate::frontend_native::SiteError::Correspondence)
    ));
    same_error(
        &first,
        refused(unsafe { prep.begin_original_source_batch(&requests, &readable) }),
    );
    assert_eq!(gate.idle_checkpoint().unwrap(), returned);
    assert_eq!(input, before);
    println!(
        "tree-batch-owner PASS case={name} originals={} installed=0 finishes=0 refusal={} joins=0 retained_poison=false",
        mode.calls(),
        mode.label()
    );
}

// Two real guard observations must leave the entire caller state unchanged.
// Expected counters come from each fixed case, not from the observed snapshot.
fn observed_totals(guard: &mut TreeSourceBatch<'_>, expected: TreeTotals) {
    let before = native_checks::state().unwrap();
    assert_eq!(guard.totals().unwrap(), expected);
    assert_eq!(native_checks::state().unwrap(), before);
    assert_eq!(guard.totals().unwrap(), expected);
    assert_eq!(native_checks::state().unwrap(), before);
}

fn installed_failure(name: &str, mode: Failure) {
    let (prep, _) = preparation();
    let root = prep.gate().target();
    let gate = Arc::clone(prep.gate());
    let start = gate.idle_checkpoint().unwrap();
    let input = input();
    let before = input.clone();
    let readable = stack();
    let requests = requests(&input.0[64..1088], 1);
    let (_controller, client) = unsafe { prepared(prep, 1, 2, 2).activate_concurrent() }.unwrap();
    let mut attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
    let payload = Box::new(CallerUnwind);
    let mut batch = unsafe { attached.begin_source_batch(&requests) }.unwrap();
    observed_totals(&mut batch, totals(0, 0));
    for i in 0..mode.calls() {
        installed_result(
            unsafe { batch.invoke_next() }.unwrap(),
            i as u64 + 1,
            root,
            &input,
            &before,
        );
        observed_totals(&mut batch, totals(i as u64 + 1, 0));
    }
    let returned = native_checks::state().unwrap();
    assert_eq!(
        returned.totals,
        TreeTotals {
            roots: mode.calls() as u64,
            pairs: PairTotals {
                entries: 2 * mode.calls() as u64,
                returns: 2 * mode.calls() as u64,
                completed: 0,
                unsampled: 2 * mode.calls() as u64,
            }
        }
    );
    assert_eq!(gate.idle_checkpoint().unwrap(), start + mode.calls() as u64);
    let first = match mode {
        Failure::Drop(_) => {
            drop(batch);
            TreeSourceBatchError::Abandoned
        }
        Failure::Forget(_) => {
            std::mem::forget(batch);
            TreeSourceBatchError::Unfinished
        }
        Failure::Unwind => {
            let result: Result<(), _> = catch_unwind(AssertUnwindSafe(|| {
                let _guard = batch;
                resume_unwind(payload);
            }));
            assert_eq!(
                result.unwrap_err().downcast_ref::<CallerUnwind>(),
                Some(&CallerUnwind)
            );
            TreeSourceBatchError::Abandoned
        }
        Failure::Early => {
            same_error(
                &TreeSourceBatchError::CallCount,
                batch.finish().unwrap_err(),
            );
            TreeSourceBatchError::CallCount
        }
        Failure::Extra | Failure::First => {
            let e = if matches!(mode, Failure::First) {
                let scope = ControllerScope::enter().unwrap();
                let e = unsafe { batch.invoke_next() }.unwrap_err();
                drop(scope);
                assert!(
                    matches!(&e, TreeSourceBatchError::Call(c) if matches!(c.as_ref(), TreeError::Bridge(b) if *b == error(Cause::ControllerReentry)))
                );
                e
            } else {
                same_error(
                    &TreeSourceBatchError::CallCount,
                    unsafe { batch.invoke_next() }.unwrap_err(),
                );
                TreeSourceBatchError::CallCount
            };
            same_error(&e, batch.totals().unwrap_err());
            same_error(&e, batch.totals().unwrap_err());
            same_error(&e, unsafe { batch.invoke_next() }.unwrap_err());
            same_error(&e, batch.totals().unwrap_err());
            same_error(&e, batch.finish().unwrap_err());
            e
        }
    };
    let checkpoint = native_checks::owner(&attached);
    assert_eq!(checkpoint.state, returned);
    assert!(
        matches!(unsafe { attached.prepare_tree_call(&input.0[64..1088], 9) }, Err(TreeError::Bridge(e)) if e == error(Cause::Outstanding))
    );
    same_error(
        &first,
        refused(unsafe { attached.begin_source_batch(&requests) }),
    );
    assert_eq!(attached.totals().unwrap_err(), error(Cause::Outstanding));
    assert_eq!(
        attached.drain_completed().unwrap_err(),
        error(Cause::Outstanding)
    );
    assert_eq!(attached.detach().unwrap_err(), error(Cause::Outstanding));
    assert_eq!(native_checks::owner(&attached), checkpoint);
    drop(attached);
    let mut poisoned = returned;
    assert_eq!(poisoned.failure, None);
    assert!(!poisoned.poisoned);
    assert_eq!(poisoned.journal[1], 0);
    poisoned.failure = Some(error(Cause::Outstanding));
    poisoned.poisoned = true;
    poisoned.journal[1] = 1;
    assert_eq!(native_checks::state(), Some(poisoned));
    assert_eq!(gate.idle_checkpoint().unwrap(), start + mode.calls() as u64);
    assert_eq!(input, before);
    println!(
        "tree-batch-owner PASS case={name} originals=0 installed={} finishes=0 refusal={} joins=0 retained_poison=true",
        mode.calls(),
        mode.label()
    );
}

macro_rules! failure_tests {
    ($runner:ident; $($name:ident => $mode:expr),+ $(,)?) => {$(
        #[test]
        #[ignore = "requires release tree batch fixture reproducer; one fresh process"]
        fn $name() { $runner(stringify!($name), $mode); }
    )+};
}
failure_tests!(original_failure;
    original_drop_0 => Failure::Drop(0), original_drop_1 => Failure::Drop(1),
    original_forget_0 => Failure::Forget(0), original_forget_1 => Failure::Forget(1),
    original_first_error => Failure::First, original_caller_unwind => Failure::Unwind,
    original_early_finish => Failure::Early, original_extra_call => Failure::Extra,
);
failure_tests!(installed_failure;
    installed_drop_0 => Failure::Drop(0), installed_drop_1 => Failure::Drop(1),
    installed_forget_0 => Failure::Forget(0), installed_forget_1 => Failure::Forget(1),
    installed_first_error => Failure::First, installed_caller_unwind => Failure::Unwind,
    installed_early_finish => Failure::Early, installed_extra_call => Failure::Extra,
);

#[derive(Clone, Copy)]
struct Geometry {
    root: u64,
    continuation: u64,
    gate_base: u64,
}
type Want = (RawIntervalOwner, usize);
fn totals(roots: u64, sampled: u64) -> TreeTotals {
    TreeTotals {
        roots,
        pairs: PairTotals {
            entries: 2 * roots,
            returns: 2 * roots,
            completed: sampled,
            unsampled: 2 * roots - sampled,
        },
    }
}
fn finished_calls(
    attached: &mut TreeThread,
    input: &Input,
    before: &Input,
    first: u64,
    root: u64,
    expected: (TreeTotals, bool),
) -> Vec<TreeCallResult> {
    let requests = requests(&input.0[64..1088], first);
    let mut guard = unsafe { attached.begin_source_batch(&requests) }.unwrap();
    observed_totals(&mut guard, expected.0);
    let mut calls = Vec::with_capacity(8);
    for id in first..first + 8 {
        let call = unsafe { guard.invoke_next() }.unwrap();
        installed_result(call, id, root, input, before);
        calls.push(call);
        observed_totals(
            &mut guard,
            totals(id, expected.0.pairs.completed + 2 * u64::from(expected.1)),
        );
    }
    assert_eq!(guard.finish().unwrap().calls(), 8);
    calls
}

// Independent expectations describe each actual owner/history position. Inspect
// all rows, every event and the complete 512-word page after the real drain.
fn checked_drain(
    attached: &mut TreeThread,
    geometry: Geometry,
    calls: &[TreeCallResult],
    want: &[Want],
    span: (TreeTotals, TreeTotals),
    number: u64,
) -> TreeBatch {
    assert_eq!(want.len(), calls.len() * 2);
    assert_eq!(attached.totals().unwrap(), span.1);
    let batch = attached
        .drain_completed()
        .unwrap()
        .expect("actual completed rows");
    assert_eq!(batch.functions(), FUNCTIONS);
    assert_eq!(
        (batch.install(), batch.registration(), batch.number()),
        (INSTALL, 1, number)
    );
    assert_eq!(batch.pid(), std::process::id());
    assert_eq!(batch.tid(), unsafe { libc::syscall(libc::SYS_gettid) }
        as u64);
    assert_eq!(batch.gate_base(), geometry.gate_base);
    assert_eq!(batch.gate_sequence(), calls.last().unwrap().gate_sequence);
    assert_eq!(batch.totals(), span);
    assert_eq!(
        batch.completed_sequences(),
        (span.0.pairs.completed, span.1.pairs.completed)
    );
    assert_eq!(batch.rows().len(), want.len());
    let journal = batch.journal();
    assert_eq!(journal.len(), 512);
    assert_eq!(&journal[..4], &[4 * calls.len() as u64, 0, batch.tid(), 0]);
    assert!(
        journal[4 + 28 * calls.len()..]
            .iter()
            .all(|&word| word == 0)
    );
    let mut completed = span.0.pairs.completed;
    for (i, call) in calls.iter().enumerate() {
        assert_eq!(
            call.gate_sequence,
            geometry.gate_base + span.0.roots + i as u64 + 1
        );
        let sampled = |n: usize| matches!(want[2 * i + n].0, RawIntervalOwner::Sampled { .. });
        for node in 0..2 {
            let row = &batch.rows()[2 * i + node];
            let (owner, history) = want[2 * i + node];
            assert_eq!(row.external_id(), call.external_id);
            assert_eq!(row.node(), node as u8);
            assert_eq!(row.function(), FUNCTIONS[node]);
            assert_eq!(row.depth(), node);
            assert_eq!(row.registration(), 1);
            assert_eq!(row.gate_sequence(), call.gate_sequence);
            assert_eq!(
                row.raw().ordinal,
                span.0.pairs.entries + 2 * i as u64 + node as u64 + 1
            );
            assert_eq!(row.history_prefix(), history);
            assert_eq!(row.raw().owner, owner);
            assert_eq!(row.parent(), (node == 1).then_some((call.external_id, 0)));
            assert_eq!(row.callsite(), (node == 1).then_some(geometry.root + 9));
            let (entry, ret, rsp, word, resumed, value) = if node == 0 {
                (
                    geometry.root,
                    geometry.root + 22,
                    call.entry_rsp,
                    geometry.continuation,
                    call.pre_call_rsp,
                    VALUE,
                )
            } else {
                (
                    geometry.root + 32,
                    geometry.root + 70,
                    call.entry_rsp - 16,
                    geometry.root + 14,
                    call.entry_rsp - 8,
                    VALUE - 1,
                )
            };
            assert_eq!((row.raw().entry_pc, row.raw().return_pc), (entry, ret));
            assert_eq!(
                (
                    row.entry_rsp(),
                    row.return_word(),
                    row.resume_pc(),
                    row.resume_rsp(),
                    row.value()
                ),
                (rsp, word, word, resumed, value)
            );
            assert!(row.raw().elapsed_ticks().is_some());
            assert_eq!(
                row.model_start_sequence(),
                sampled(node).then_some(completed)
            );
            assert_eq!(
                row.model_completed_children(),
                sampled(node).then_some(u64::from(node == 0 && sampled(1)))
            );
            let (entry_kind, generation, inv1, reason) = match owner {
                RawIntervalOwner::Sampled {
                    generation,
                    invocation,
                } => (1, generation, invocation as u64 + 1, 0),
                RawIntervalOwner::FunctionClosed { generation } => (3, generation, 0, 3),
                RawIntervalOwner::Removed { generation } => (3, generation, 0, 2),
                RawIntervalOwner::InitialDisarmed => (3, 0, 0, 1),
            };
            let bits = inv1 | ((history as u64) << 13) | (reason << 22);
            for (offset, kind, pc) in [(node, entry_kind, entry), (3 - node, entry_kind + 1, ret)] {
                let at = 4 + i * 28 + offset * 7;
                assert_eq!(
                    &journal[at..at + 7],
                    &[kind, row.raw().ordinal, pc, rsp, word, generation, bits]
                );
            }
        }
        completed += u64::from(sampled(0)) + u64::from(sampled(1));
    }
    assert_eq!(completed, span.1.pairs.completed);
    assert!(attached.drain_completed().unwrap().is_none());
    let after = native_checks::state().unwrap();
    assert_eq!(after.len, 0);
    assert!(after.rows.iter().all(Option::is_none));
    let mut empty = [0_u64; 512];
    empty[2] = batch.tid();
    assert_eq!(after.journal, empty);
    batch
}

fn observation(
    record: RecordObservation,
    row: &TreeRecord,
    generation: u64,
    invocation: usize,
    start: u64,
    children: u64,
) {
    let admission = record.record.admission;
    assert_eq!(admission.generation.get(), generation);
    assert_eq!(admission.function, row.function());
    assert_eq!(admission.invocation, invocation);
    assert_eq!(admission.entry_value, row.raw().start.ticks);
    assert_eq!(
        row.raw().owner,
        RawIntervalOwner::Sampled {
            generation,
            invocation
        }
    );
    assert_eq!(
        record.record.terminal,
        Some(Terminal::Completed {
            value: invocation as u64,
            disposition: Disposition::Retained { rank: 0 }
        })
    );
    let payload = record.payload.unwrap();
    assert_eq!(payload.admission, admission);
    assert_eq!(payload.thread, 1);
    assert_eq!(payload.start_sequence, start);
    assert_eq!(
        payload.outcome,
        PayloadOutcome::Completed {
            end: Observation::Value(row.raw().end.ticks),
            completed_children: children
        }
    );
    assert_eq!(row.model_start_sequence(), Some(start));
    assert_eq!(row.model_completed_children(), Some(children));
}
fn two_records(records: &[RecordObservation], rows: &[TreeRecord], generation: u64, start: u64) {
    assert_eq!(records.len(), 2);
    assert_eq!(rows.len(), 2);
    observation(records[0], &rows[0], generation, 0, start, 1);
    observation(records[1], &rows[1], generation, 1, start, 0);
}
fn history(controller: &TreeController, actions: &[Action]) {
    let h = controller.history().unwrap();
    assert_eq!(h.status, ControllerStatus::Ready);
    assert_eq!(h.current, None);
    assert_eq!(h.enabled, [true, true]);
    assert_eq!(h.retained_failed_generation, None);
    assert_eq!(h.actions, actions);
}
fn published(generation: crate::generation::GenerationId) -> Action {
    Action {
        kind: ActionKind::Published,
        generation,
        function: None,
        current: Some(generation),
        group: None,
    }
}
fn removed(generation: crate::generation::GenerationId) -> Action {
    Action {
        kind: ActionKind::Removed,
        generation,
        function: None,
        current: None,
        group: None,
    }
}

#[test]
#[ignore = "requires release tree batch fixture reproducer; one fresh process"]
fn finish_reuse_capacity() {
    let (mut prep, _) = preparation();
    let gate = Arc::clone(prep.gate());
    let root = gate.target();
    let start = gate.idle_checkpoint().unwrap();
    let input = input();
    let before = input.clone();
    let readable = stack();
    for bytes in [&input.0[64..1087], &input.0[65..1089]] {
        let bad = [bytes; 8];
        assert!(
            matches!(refused(unsafe { prep.begin_original_source_batch(&bad, &readable) }),
            TreeSourceBatchError::Call(e) if matches!(e.as_ref(), TreeError::Bridge(b) if *b == error(Cause::Identity)))
        );
        assert_eq!(gate.idle_checkpoint().unwrap(), start);
    }
    let inputs = [&input.0[64..1088]; 8];
    for _ in 0..2 {
        let mut batch = unsafe { prep.begin_original_source_batch(&inputs, &readable) }.unwrap();
        for _ in 0..8 {
            original_result(unsafe { batch.invoke_next() }.unwrap(), &input, &before);
        }
        assert_eq!(batch.finish().unwrap().calls(), 8);
    }
    assert_eq!(gate.idle_checkpoint().unwrap(), start + 16);
    let geometry = Geometry {
        root,
        continuation: gate.continuation(),
        gate_base: start + 16,
    };
    let mut prepared = prepared(prep, 1, 48, 4);
    let a = prepared.stage(config_n(48)).unwrap();
    let ga = a.generation();
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let mut attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
    controller.arm(&a).unwrap();
    let checkpoint = native_checks::owner(&attached);
    for bad_kind in 0..5 {
        let mut bad = requests(&input.0[64..1088], 1);
        match bad_kind {
            0 => bad[0].external_id = 0,
            1 => bad[3].external_id = bad[2].external_id,
            2 => bad.swap(2, 3),
            3 => bad[7].bytes = &input.0[64..1087],
            4 => bad[7].bytes = &input.0[65..1089],
            _ => unreachable!(),
        }
        let expected = error(if bad_kind < 3 {
            Cause::Capacity
        } else {
            Cause::Identity
        });
        assert!(
            matches!(refused(unsafe { attached.begin_source_batch(&bad) }),
            TreeSourceBatchError::Call(e) if matches!(e.as_ref(), TreeError::Bridge(b) if *b == expected))
        );
        assert_eq!(native_checks::owner(&attached), checkpoint);
    }
    let mut calls = finished_calls(
        &mut attached,
        &input,
        &before,
        1,
        root,
        (totals(0, 0), true),
    );
    calls.extend(finished_calls(
        &mut attached,
        &input,
        &before,
        9,
        root,
        (totals(8, 2), false),
    ));
    let full = native_checks::owner(&attached);
    assert_eq!(
        (
            full.state.len,
            full.state.journal[0],
            full.state.last_external
        ),
        (32, 64, 16)
    );
    let third = requests(&input.0[64..1088], 17);
    assert!(
        matches!(refused(unsafe { attached.begin_source_batch(&third) }),
        TreeSourceBatchError::Call(e) if matches!(e.as_ref(), TreeError::Bridge(b) if *b == error(Cause::Capacity)))
    );
    assert_eq!(native_checks::owner(&attached), full);
    let wants = |count: usize, sampled: bool, generation: u64, prefix: usize| -> Vec<Want> {
        (0..count)
            .map(|i| {
                (
                    if sampled && i < 2 {
                        RawIntervalOwner::Sampled {
                            generation,
                            invocation: i,
                        }
                    } else {
                        RawIntervalOwner::FunctionClosed { generation }
                    },
                    prefix,
                )
            })
            .collect()
    };
    let first = checked_drain(
        &mut attached,
        geometry,
        &calls,
        &wants(32, true, ga.get(), 1),
        (totals(0, 0), totals(16, 2)),
        1,
    );
    // Reuse the exact previously refused ID/input request array after the drain.
    let mut guard = unsafe { attached.begin_source_batch(&third) }.unwrap();
    observed_totals(&mut guard, totals(16, 2));
    let mut calls = Vec::with_capacity(8);
    for id in 17..25 {
        let call = unsafe { guard.invoke_next() }.unwrap();
        installed_result(call, id, root, &input, &before);
        calls.push(call);
        observed_totals(&mut guard, totals(id, 2));
    }
    assert_eq!(guard.finish().unwrap().calls(), 8);
    let second = checked_drain(
        &mut attached,
        geometry,
        &calls,
        &wants(16, false, ga.get(), 1),
        (totals(16, 2), totals(24, 2)),
        2,
    );
    assert!(first.same_stream(&second));
    controller.disarm(&a).unwrap();
    let report = controller.retire(&a).unwrap();
    assert_eq!(report.generation(), ga);
    two_records(
        &report.records().collect::<Vec<_>>(),
        &first.rows()[..2],
        ga.get(),
        0,
    );
    assert!(
        matches!(controller.stage(config_n(48)), Err(e) if e == error(Cause::Setup(SetupError::EpochLimit)))
    );
    drop(report);
    let b = controller.stage(config_n(48)).unwrap();
    let gb = b.generation();
    assert_ne!(ga, gb);
    controller.arm(&b).unwrap();
    let calls = finished_calls(
        &mut attached,
        &input,
        &before,
        25,
        root,
        (totals(24, 2), true),
    );
    let third = checked_drain(
        &mut attached,
        geometry,
        &calls,
        &wants(16, true, gb.get(), 3),
        (totals(24, 2), totals(32, 4)),
        3,
    );
    assert!(first.same_stream(&third));
    controller.disarm(&b).unwrap();
    let report = controller.retire(&b).unwrap();
    assert_eq!(report.generation(), gb);
    two_records(
        &report.records().collect::<Vec<_>>(),
        &third.rows()[..2],
        gb.get(),
        2,
    );
    drop(report);
    history(
        &controller,
        &[published(ga), removed(ga), published(gb), removed(gb)],
    );
    assert_eq!(attached.detach().unwrap(), totals(32, 4));
    assert_eq!(native_checks::state(), None);
    assert_eq!(input, before);
    println!(
        "tree-batch-owner PASS case=finish_reuse_capacity originals=16 installed=32 finishes=6 refusal=AdmissionCapacityPermit joins=0 retained_poison=false"
    );
}

fn concurrent_owners(closed: bool) {
    let (prep, cpu) = preparation();
    let geometry = Geometry {
        root: prep.gate().target(),
        continuation: prep.gate().continuation(),
        gate_base: prep.gate().idle_checkpoint().unwrap(),
    };
    let input = input();
    let before = input.clone();
    let readable = stack();
    let requests = requests(&input.0[64..1088], 1);
    let mut prepared = prepared(prep, 3, 2, if closed { 6 } else { 4 });
    let epochs = [
        prepared.stage(config_n(2)).unwrap(),
        prepared.stage(config_n(2)).unwrap(),
        prepared.stage(config_n(2)).unwrap(),
    ];
    let generations = epochs.each_ref().map(|e| e.generation());
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let base = if closed { 3 } else { 1 };
    let pauses = [
        Arc::new(EntryPause::new(base)),
        Arc::new(EntryPause::new(base + 1)),
        Arc::new(EntryPause::new(base)),
    ];
    controller
        .native_pauses(pauses.each_ref().map(Arc::clone))
        .unwrap();
    let mut attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (a_tx, a_rx) = mpsc::sync_channel(1);
    let helper_pauses = pauses.each_ref().map(Arc::clone);
    let handle = thread::spawn(move || {
        pin(Some(cpu));
        let resume = ResumeAll(helper_pauses);
        let [a, b, c] = epochs;
        controller.arm(&a).unwrap();
        ready_tx.send(()).unwrap();
        until(|| resume.0[0].entered.load(Ordering::Acquire));
        if !closed {
            assert!(controller.report(&a).unwrap().is_none());
        }
        controller.arm(&b).unwrap();
        if closed {
            // Copy records only. No A Report/receipt clone survives to mask the
            // permit owned by the actual FunctionClosed root invocation.
            let report = controller
                .report(&a)
                .unwrap()
                .expect("A's sampled calls already returned");
            assert_eq!(report.records().count(), 2);
            let records: Vec<_> = report.records().collect();
            let retired = controller.retire(&a).unwrap();
            assert_eq!(retired.records().collect::<Vec<_>>(), records);
            drop(retired);
            drop(report);
            a_tx.send(records).unwrap();
            assert!(
                matches!(controller.stage(config_n(2)), Err(e) if e == error(Cause::Setup(SetupError::EpochLimit)))
            );
        } else {
            assert!(controller.report(&a).unwrap().is_none());
        }
        resume.0[0].resume.store(true, Ordering::Release);
        until(|| resume.0[1].entered.load(Ordering::Acquire));
        controller.arm(&c).unwrap();
        assert!(controller.report(&b).unwrap().is_none());
        if closed {
            assert!(
                matches!(controller.stage(config_n(2)), Err(e) if e == error(Cause::Setup(SetupError::EpochLimit)))
            );
        } else {
            assert!(controller.report(&a).unwrap().is_none());
        }
        resume.0[1].resume.store(true, Ordering::Release);
        until(|| resume.0[2].entered.load(Ordering::Acquire));
        let child = controller
            .report(&b)
            .unwrap()
            .expect("actual child C3 and +14 ACK");
        assert_eq!(child.records().count(), 1);
        if closed {
            assert!(
                matches!(controller.stage(config_n(2)), Err(e) if e == error(Cause::Setup(SetupError::EpochLimit)))
            );
        } else {
            assert!(controller.report(&a).unwrap().is_none());
        }
        resume.0[2].resume.store(true, Ordering::Release);
        done_rx
            .recv_timeout(WAIT)
            .expect("actual outer return and successful invoke postflight");
        if closed {
            // A's receipt released its permit only after its actual outer return.
            let d = controller.stage(config_n(2)).unwrap();
            assert!(!generations.contains(&d.generation()));
            controller.disarm(&c).unwrap();
            let report_c = controller.report(&c).unwrap().expect("unused C closed");
            assert_eq!(report_c.records().count(), 0);
            controller.arm(&d).unwrap();
            controller.disarm(&d).unwrap();
            let report_d = controller.report(&d).unwrap().expect("unused D closed");
            assert_eq!(report_d.records().count(), 0);
            OwnerDone {
                controller,
                epochs: [b, c, d],
                reports: [child, report_c, report_d],
            }
        } else {
            let root = controller
                .report(&a)
                .unwrap()
                .expect("actual root outer return and postflight");
            assert_eq!(root.records().count(), 1);
            controller.disarm(&c).unwrap();
            let report_c = controller.report(&c).unwrap().expect("unused C closed");
            assert_eq!(report_c.records().count(), 0);
            OwnerDone {
                controller,
                epochs: [a, b, c],
                reports: [root, child, report_c],
            }
        }
    });
    // Drops before the attachment/input on unwind; releases all pauses and joins.
    let mut worker = OwnerWorker {
        handle: Some(handle),
        done: Some(done_tx),
        pauses,
    };
    ready_rx.recv_timeout(WAIT).unwrap();
    let mut batch = unsafe { attached.begin_source_batch(&requests) }.unwrap();
    observed_totals(&mut batch, totals(0, 0));
    let mut calls = Vec::with_capacity(8);
    let first_calls = if closed { 2 } else { 1 };
    for id in 1..=first_calls {
        let call = unsafe { batch.invoke_next() }.unwrap();
        installed_result(call, id, geometry.root, &input, &before);
        calls.push(call);
        observed_totals(
            &mut batch,
            totals(id, if closed && id == 2 { 3 } else { 2 }),
        );
    }
    // A metadata Report is genuine and available while the source batch has
    // not finished. Joining does not waive any remaining source-batch checks.
    let mut done = worker.joined();
    assert!(worker.handle.is_none());
    let a_records = if closed {
        a_rx.recv_timeout(WAIT).unwrap()
    } else {
        Vec::new()
    };
    for id in first_calls + 1..=8 {
        let call = unsafe { batch.invoke_next() }.unwrap();
        installed_result(call, id, geometry.root, &input, &before);
        calls.push(call);
        observed_totals(&mut batch, totals(id, if closed { 3 } else { 2 }));
    }
    assert_eq!(batch.finish().unwrap().calls(), 8);
    let ga = generations[0];
    let gb = generations[1];
    let gc = generations[2];
    let mut wants: Vec<Want> = if closed {
        vec![
            (
                RawIntervalOwner::Sampled {
                    generation: ga.get(),
                    invocation: 0,
                },
                1,
            ),
            (
                RawIntervalOwner::Sampled {
                    generation: ga.get(),
                    invocation: 1,
                },
                1,
            ),
            (
                RawIntervalOwner::FunctionClosed {
                    generation: ga.get(),
                },
                1,
            ),
            (
                RawIntervalOwner::Sampled {
                    generation: gb.get(),
                    invocation: 0,
                },
                2,
            ),
        ]
    } else {
        vec![
            (
                RawIntervalOwner::Sampled {
                    generation: ga.get(),
                    invocation: 0,
                },
                1,
            ),
            (
                RawIntervalOwner::Sampled {
                    generation: gb.get(),
                    invocation: 0,
                },
                2,
            ),
        ]
    };
    let removed_generation = done.epochs[2].generation();
    wants.resize(
        16,
        (
            RawIntervalOwner::Removed {
                generation: removed_generation.get(),
            },
            if closed { 6 } else { 4 },
        ),
    );
    let expected = totals(8, if closed { 3 } else { 2 });
    let drained = checked_drain(
        &mut attached,
        geometry,
        &calls,
        &wants,
        (totals(0, 0), expected),
        1,
    );
    if closed {
        two_records(&a_records, &drained.rows()[..2], ga.get(), 0);
        assert_eq!(done.reports[0].generation(), gb);
        let records: Vec<_> = done.reports[0].records().collect();
        assert_eq!(records.len(), 1);
        observation(records[0], &drained.rows()[3], gb.get(), 0, 2, 0);
        let gd = done.epochs[2].generation();
        history(
            &done.controller,
            &[
                published(ga),
                published(gb),
                published(gc),
                removed(gc),
                published(gd),
                removed(gd),
            ],
        );
    } else {
        report_row(&done.reports[0], &drained.rows()[0], ga.get(), 1);
        report_row(&done.reports[1], &drained.rows()[1], gb.get(), 0);
        history(
            &done.controller,
            &[published(ga), published(gb), published(gc), removed(gc)],
        );
    }
    for (epoch, report) in done.epochs.iter().zip(&done.reports) {
        let retired = done.controller.retire(epoch).unwrap();
        assert_eq!(retired.generation(), report.generation());
        assert_eq!(
            retired.records().collect::<Vec<_>>(),
            report.records().collect::<Vec<_>>()
        );
    }
    assert_eq!(attached.detach().unwrap(), expected);
    assert_eq!(native_checks::state(), None);
    assert_eq!(input, before);
    let name = if closed { "closed_abc" } else { "sampled_abc" };
    println!(
        "tree-batch-owner PASS case={name} originals=0 installed=8 finishes=1 refusal=None joins=1 retained_poison=false"
    );
}

#[test]
#[ignore = "requires release tree batch fixture reproducer; one fresh process"]
fn sampled_abc() {
    concurrent_owners(false);
}
#[test]
#[ignore = "requires release tree batch fixture reproducer; one fresh process"]
fn closed_abc() {
    concurrent_owners(true);
}

// A separate process preserves the old invoke-first case and makes the accessor
// itself encounter the real ControllerScope refusal after one actual return.
#[test]
#[ignore = "requires release tree batch fixture reproducer; one fresh process"]
fn installed_totals_first_error() {
    let (prep, _) = preparation();
    let root = prep.gate().target();
    let gate = Arc::clone(prep.gate());
    let start = gate.idle_checkpoint().unwrap();
    let input = input();
    let before = input.clone();
    let requests = requests(&input.0[64..1088], 1);
    let (_controller, client) = unsafe { prepared(prep, 1, 2, 2).activate_concurrent() }.unwrap();
    let mut attached = unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }.unwrap();
    let mut batch = unsafe { attached.begin_source_batch(&requests) }.unwrap();
    observed_totals(&mut batch, totals(0, 0));
    installed_result(
        unsafe { batch.invoke_next() }.unwrap(),
        1,
        root,
        &input,
        &before,
    );
    observed_totals(&mut batch, totals(1, 0));
    let returned = native_checks::state().unwrap();
    assert_eq!(returned.totals, totals(1, 0));
    assert_eq!(gate.idle_checkpoint().unwrap(), start + 1);
    let scope = ControllerScope::enter().unwrap();
    let first = batch.totals().unwrap_err();
    drop(scope);
    assert!(
        matches!(&first, TreeSourceBatchError::Call(c) if matches!(c.as_ref(), TreeError::Bridge(b) if *b == error(Cause::ControllerReentry)))
    );
    assert_eq!(native_checks::state(), Some(returned.clone()));
    assert_eq!(gate.idle_checkpoint().unwrap(), start + 1);
    same_error(&first, batch.totals().unwrap_err());
    same_error(&first, batch.totals().unwrap_err());
    same_error(&first, unsafe { batch.invoke_next() }.unwrap_err());
    assert_eq!(native_checks::state(), Some(returned.clone()));
    assert_eq!(gate.idle_checkpoint().unwrap(), start + 1);
    same_error(&first, batch.finish().unwrap_err());
    let checkpoint = native_checks::owner(&attached);
    assert_eq!(checkpoint.state, returned);
    assert!(
        matches!(unsafe { attached.prepare_tree_call(&input.0[64..1088], 9) }, Err(TreeError::Bridge(e)) if e == error(Cause::Outstanding))
    );
    same_error(
        &first,
        refused(unsafe { attached.begin_source_batch(&requests) }),
    );
    assert_eq!(attached.totals().unwrap_err(), error(Cause::Outstanding));
    assert_eq!(
        attached.drain_completed().unwrap_err(),
        error(Cause::Outstanding)
    );
    assert_eq!(attached.detach().unwrap_err(), error(Cause::Outstanding));
    assert_eq!(native_checks::owner(&attached), checkpoint);
    drop(attached);
    let mut poisoned = returned;
    assert_eq!(poisoned.failure, None);
    assert!(!poisoned.poisoned);
    assert_eq!(poisoned.journal[1], 0);
    poisoned.failure = Some(error(Cause::Outstanding));
    poisoned.poisoned = true;
    poisoned.journal[1] = 1;
    assert_eq!(native_checks::state(), Some(poisoned));
    assert_eq!(gate.idle_checkpoint().unwrap(), start + 1);
    assert_eq!(input, before);
    println!(
        "tree-batch-owner PASS case=installed_totals_first_error originals=0 installed=1 finishes=0 refusal=ControllerReentry joins=0 retained_poison=true"
    );
}
