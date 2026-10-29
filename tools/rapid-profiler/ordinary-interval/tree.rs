//! Complete finite root/child population; no cache-model or timing accuracy.
use super::counter::truth as leaf;
use super::*;
use rapid_profiler::frontend::{ActionKind, ControllerStatus};
use rapid_profiler::frontend_native::{
    InstalledTreeSite, LoadedCallTree, PreparedTreeController, TreeBatch, TreeCallGate,
    TreeCallResult, TreeContract, TreeRecord, TreeSitePreparation, TreeTotals,
};
mod check;
pub(super) mod throughput;
#[path = "../tree-work/truth.rs"]
pub mod truth;
use check::{Batch, ReportRow, Spec};

const CALLS: usize = 24;
const PER_BATCH: usize = 8;
const FUNCTIONS: [FunctionId; 2] = [FunctionId(1), FunctionId(2)];
const INSTALL: u64 = 0x7472_706f;
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const TREE_CONTRACT: TreeContract = TreeContract {
    root_only_external_entry: true,
    ordinary_ret_only: true,
    no_active_cet: true,
};
#[repr(C, align(64))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Input([u8; 1152]);
fn label(i: usize) -> (truth::Case, u64, usize) {
    assert!(i < CALLS);
    let case = if i < 10 {
        truth::Case::Fit2
    } else {
        truth::Case::Conflict3
    };
    (case, SEEDS[i % 2], usize::from(i >= 10) * 2 + i % 2)
}
fn inputs() -> [Input; 4] {
    std::array::from_fn(|i| {
        let mut out = Input([0xa5; 1152]);
        out.0[1088..].fill(0x5a);
        out.0[64..1088].copy_from_slice(&truth::input(truth::ALL[i / 2], SEEDS[i % 2]));
        out
    })
}
fn totals(roots: usize, k: usize) -> TreeTotals {
    TreeTotals {
        roots: roots as u64,
        pairs: PairTotals {
            entries: (2 * roots) as u64,
            returns: (2 * roots) as u64,
            completed: (2 * roots.min(k)) as u64,
            unsampled: (2 * roots.saturating_sub(k)) as u64,
        },
    }
}
fn publish_tree(prep: TreeSitePreparation) -> InstalledTreeSite {
    single_main();
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert_eq!(originals.len(), 1);
    let source = AddressRange::new(originals[0].address, originals[0].bytes.len()).unwrap();
    assert_eq!((source.start() % 4096, source.len()), (0, 4096));
    assert_eq!(planned.plan().steps().len(), 4);
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    // SAFETY: sole actual thread, exact whole-page alias and exclusive preparation;
    // no signal/foreign entry, saved resume, writer, source CALL, fork or unload.
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let result = {
        let mut lease =
            unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
        let result = unsafe {
            planned.publish_with(&[alias], &mut lease, || {
                protect(source, libc::PROT_READ | libc::PROT_EXEC)
            })
        };
        if result.is_ok() {
            assert!(!lease.is_poisoned());
        }
        result
    };
    let (installed, receipt) = match result {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("tree population publication FAILED: {e:?}");
            std::process::abort();
        }
    };
    // SAFETY: exact successful transaction/final RX; retain code and owners for
    // the process lifetime, including seal refusal. No unload or reclamation.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}
fn work(bytes: &[u8], i: usize, root: u64, rsp: u64, continuation: u64, value: u64) {
    let (case, seed, _) = label(i);
    let interpreted = truth::interpret(
        &truth::ROOT_BYTES,
        &truth::CHILD_BYTES,
        bytes,
        root,
        bytes.as_ptr() as usize as u64,
        rsp,
        continuation,
    )
    .unwrap();
    assert_eq!(interpreted.value, value);
    assert_eq!(value, truth::scalar(case, seed));
    let key = 0x9e37_79b9_7f4a_7c15_u64;
    let cycle = case.cycle();
    let sum = (0..64).fold(0_u64, |sum, i| {
        sum.wrapping_add(seed ^ key.wrapping_mul(cycle[i % cycle.len()] as u64 + 1))
    });
    assert_eq!(value, (sum ^ key).wrapping_add(1));
    assert_eq!(interpreted.resumed_rsp, rsp.checked_add(8).unwrap());
    let counts = truth::counts(case);
    assert_eq!(
        (
            counts.instructions,
            counts.root_instructions,
            counts.child_instructions
        ),
        (332, 6, 326)
    );
    assert_eq!(
        (
            counts.conditional,
            counts.taken,
            counts.input_reads,
            counts.return_reads,
            counts.call_stores
        ),
        (64, 63, 129, 2, 1)
    );
    assert_eq!(interpreted.steps.len(), counts.instructions);
    assert_eq!(
        interpreted
            .steps
            .iter()
            .filter_map(|s| s.event)
            .collect::<Vec<_>>(),
        truth::expected_events(
            case,
            seed,
            root,
            bytes.as_ptr() as usize as u64,
            rsp,
            continuation
        )
        .unwrap()
    );
    // Predictions for an independently qualified fixed source; no native trace
    // or model3/65 cache result is fabricated from this ordinary call stack.
}
fn history(
    controller: &rapid_profiler::frontend_native::TreeController,
    generation: u64,
    removed: bool,
) {
    let h = controller.history().unwrap();
    assert_eq!(h.status, ControllerStatus::Ready);
    assert_eq!(h.current.map(|g| g.get()), (!removed).then_some(generation));
    assert!(h.retained_failed_generation.is_none());
    assert_eq!(h.enabled, [true, true]); // Historical mandatory groups, not physical cheap-off.
    assert_eq!(h.actions.len(), if removed { 2 } else { 1 });
    for (i, a) in h.actions.iter().enumerate() {
        assert_eq!(
            a.kind,
            if i == 0 {
                ActionKind::Published
            } else {
                ActionKind::Removed
            }
        );
        assert_eq!(a.generation.get(), generation);
        assert_eq!(a.current.map(|g| g.get()), (i == 0).then_some(generation));
        assert_eq!((a.function, a.group), (None, None));
    }
}

pub(super) fn run(candidate: &Path, expected: &Path, k: usize) {
    assert!(matches!(k, 1 | 10 | 24));
    single_main();
    let cpu = pin(None);
    let tid = u64::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap();
    let bytes = expected_file(candidate, expected);
    // SAFETY: exact trusted, normally loaded closed tree; read-only1024-byte
    // inputs, ordinary returns, sole external root, no CET/signals/unwind/fork.
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
    truth::check_bytes(owner.root_code(), owner.callee_code()).unwrap();
    let root = owner.certificate().root().entry();
    assert_eq!(
        owner.certificate().callee().entry(),
        root + truth::CHILD_OFFSET
    );
    assert_eq!(
        owner.certificate().root().heads(),
        truth::ROOT_HEADS.map(|n| root + u64::from(n))
    );
    assert_eq!(
        owner.certificate().callee().heads(),
        truth::CHILD_HEADS.map(|n| root + 32 + u64::from(n))
    );
    let offset = usize::try_from(root - owner.source_range().0).unwrap();
    assert_eq!(
        &owner.original_source()[offset + 23..offset + 32],
        &truth::GAP_BYTES
    );
    let gate = TreeCallGate::new(owner.certificate().root()).unwrap();
    let continuation = gate.continuation();
    let mut prep = TreeSitePreparation::new(owner, gate, identity(root)).unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        [root, root + 32, root + 70, root + 14, root + 22]
    );
    let ids: [u64; CALLS] = std::array::from_fn(|i| i as u64 + 1);
    let labels: [(truth::Case, u64, usize); CALLS] = std::array::from_fn(label);
    let expected_inputs = inputs();
    let input = Box::new(expected_inputs.clone());
    let readable = stack();
    let mut originals = 0;
    for (i, row) in labels.iter().enumerate() {
        let slice = &input[row.2].0[64..1088];
        // SAFETY: unchanged complete source, immutable aligned input and owned
        // actual-thread stack; guard consumed once before any publication.
        let result = unsafe {
            prep.prepare_original_call()
                .unwrap()
                .invoke(slice, &readable)
        }
        .unwrap();
        assert_eq!(result.pre_call_rsp, result.resumed_rsp);
        work(
            slice,
            i,
            root,
            result.pre_call_rsp.checked_sub(8).unwrap(),
            continuation,
            result.value,
        );
        assert_eq!(*input, expected_inputs);
        originals += 1;
    }
    assert_eq!(originals, CALLS);
    single_main();
    let mut prepared = PreparedTreeController::new(
        publish_tree(prep),
        INSTALL,
        FUNCTIONS,
        Limits {
            epochs: 1,
            threads: 1,
            depth: 2,
            records_per_epoch: 48,
            actions: 2,
        },
    )
    .unwrap();
    let epoch = prepared
        .stage(Config {
            retained_per_function: k,
            max_inflight: 2,
            max_invocations: 48,
        })
        .unwrap();
    // SAFETY: complete five-role publication, same local caller; controller and
    // attachment never overlap a live application invocation or TLS borrow.
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    controller.arm(&epoch).unwrap();
    let mut attached = unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }.unwrap();
    let mut calls = Vec::with_capacity(CALLS);
    let mut held: Vec<TreeBatch> = Vec::with_capacity(3);
    let mut sealed: Vec<Vec<TreeRecord>> = Vec::with_capacity(3);
    let mut batches: Vec<Batch> = Vec::with_capacity(3);
    assert_eq!(attached.totals().unwrap(), totals(0, k));
    let spec = Spec {
        root,
        continuation,
        generation: epoch.generation().get(),
        k,
        pid: std::process::id(),
        tid,
        gate_base: u64::try_from(originals).unwrap(),
    };
    history(&controller, spec.generation, false);
    for (i, (id, row)) in ids.iter().zip(&labels).enumerate() {
        let slice = &input[row.2].0[64..1088];
        // SAFETY: one real synchronous CALL on the attached actual thread, with
        // immutable full input and no writer/foreign entry; normal returns only.
        let call = unsafe { attached.prepare_tree_call(slice, *id).unwrap().invoke() }.unwrap();
        assert!(check::call(&spec, i, call));
        work(slice, i, root, call.entry_rsp, continuation, call.value);
        assert_eq!(*input, expected_inputs);
        calls.push(call);
        assert_eq!(attached.totals().unwrap(), totals(i + 1, k));
        if (i + 1) % PER_BATCH == 0 {
            let batch = attached
                .drain_completed()
                .unwrap()
                .expect("complete eight-root batch");
            if let Some(first) = held.first() {
                assert!(batch.same_stream(first));
            }
            let view = Batch::from(&batch);
            assert!(check::batch(&spec, batches.len(), &calls, &view));
            for ((old, seal), previous) in held.iter().zip(&sealed).zip(&batches) {
                assert_eq!(old.rows(), seal.as_slice());
                assert_eq!(&Batch::from(old), previous);
            }
            sealed.push(batch.rows().to_vec());
            batches.push(view);
            held.push(batch);
        }
    }
    assert!(attached.drain_completed().unwrap().is_none());
    assert_eq!(attached.detach().unwrap(), totals(CALLS, k));
    controller.disarm(&epoch).unwrap();
    history(&controller, spec.generation, true);
    let report = controller
        .report(&epoch)
        .unwrap()
        .expect("final closed zero report");
    assert_eq!(report.generation().get(), spec.generation);
    let reports: Vec<_> = report.records().map(ReportRow::from).collect();
    assert!(check::population(&spec, &calls, &batches, &reports));
    let retired = controller.retire(&epoch).unwrap();
    assert_eq!(retired.generation().get(), spec.generation);
    assert_eq!(
        retired.records().map(ReportRow::from).collect::<Vec<_>>(),
        reports
    );
    drop(retired);
    drop(report);
    assert_eq!(*input, expected_inputs);
    for ((old, seal), previous) in held.iter().zip(&sealed).zip(&batches) {
        assert_eq!(old.rows(), seal.as_slice());
        assert_eq!(&Batch::from(old), previous);
    }
    pin(Some(cpu));
    single_main();
    emit(&spec, &batches);
}
fn emit(spec: &Spec, batches: &[Batch]) {
    println!(
        "k,external_id,seed,case,node,parent,function,ordinal,owner,generation,invocation,inclusive_instructions,exclusive_instructions,value,gate_sequence,start_ticks,end_ticks,start_aux,end_aux"
    );
    for node in batches.iter().flat_map(|b| &b.nodes) {
        let i = usize::try_from(node.id - 1).unwrap();
        let (case, seed, _) = label(i);
        let (owner, invocation) = match node.raw.owner {
            RawIntervalOwner::Sampled { invocation, .. } => ("sampled", invocation.to_string()),
            RawIntervalOwner::FunctionClosed { .. } => ("closed", String::new()),
            _ => unreachable!("complete population check"),
        };
        let parent = node
            .parent
            .map(|(id, _)| id.to_string())
            .unwrap_or_default();
        let (inclusive, exclusive) = if node.node == 0 { (332, 6) } else { (326, 326) };
        println!(
            "{},{},{seed},{},{},{parent},{},{},{owner},{},{invocation},{inclusive},{exclusive},{},{},{},{},{},{}",
            spec.k,
            node.id,
            case.name(),
            node.node,
            node.function.0,
            node.raw.ordinal,
            spec.generation,
            node.value,
            node.gate,
            node.raw.start.ticks,
            node.raw.end.ticks,
            node.raw.start.aux,
            node.raw.end.aux
        );
    }
    let selected_conflict = spec.k.saturating_sub(10);
    let error = 24 * selected_conflict as i64 - 14 * spec.k as i64;
    println!(
        "tree-population FUNCTIONAL_PASS k={} originals=24 roots=24 nodes=48 sampled={} closed={} batches=3 events=96 reports={} actions=2 conflict_population=14 conflict_retained={} selection_error_numerator={} selection_error_denominator={} root_inclusive_instructions=7968 root_exclusive_instructions=144 child_instructions=7824 input_unchanged=true records_joined=true uncalibrated=true",
        spec.k,
        2 * spec.k,
        48 - 2 * spec.k,
        2 * spec.k,
        selected_conflict,
        error,
        24 * spec.k
    );
}
