//! Matched guarded-consumer cost, not bare leaf or instrumentation latency.
use super::*;
use rapid_profiler::frontend_native::{TreeController, TreeThread};
use std::collections::VecDeque;
use std::io::Write;
mod clocks;
mod joins;

const BLOCKS: usize = 64;
const VALUES: [u64; 4] = [
    13455538007910626262,
    14448916110156114966,
    18114441086748040058,
    6122101979721109698,
];
const HEADER: &str = "mode,block,call_first,call_last,roots,node_rows,sampled,closed,batches,events,reports,generation,history_prefix,gate_first,gate_last,completed_before,completed_after,conflict_population,conflict_retained,selection_error_numerator,selection_error_denominator,root_inclusive_instructions,root_exclusive_instructions,child_instructions,checksum";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Mode {
    name: &'static str,
    k: Option<usize>,
}
impl Mode {
    fn parse(name: &str) -> Self {
        match name {
            "original-sdk" => Self {
                name: "original-sdk",
                k: None,
            },
            "k1" => Self {
                name: "k1",
                k: Some(1),
            },
            "k10" => Self {
                name: "k10",
                k: Some(10),
            },
            "k24" => Self {
                name: "k24",
                k: Some(24),
            },
            _ => panic!("tree-throughput mode must be original-sdk, k1, k10 or k24"),
        }
    }
}
#[derive(Clone, Copy)]
struct BlockRow {
    index: usize,
    checksum: u64,
    generation: Option<u64>,
}
fn prepare(candidate: &Path, expected: &Path) -> (TreeSitePreparation, u64, u64) {
    let bytes = expected_file(candidate, expected);
    // SAFETY: same closed source/ABI, sole actual caller, immutable inputs,
    // no external child entry, CET, signals, unwind, fork, writers or unload.
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
    let prep = TreeSitePreparation::new(owner, gate, identity(root)).unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        [root, root + 32, root + 70, root + 14, root + 22]
    );
    (prep, root, continuation)
}
fn values() {
    // One setup check per unique input. No interpreter/event replay per call.
    for (index, expected) in VALUES.iter().enumerate() {
        let (case, seed) = (truth::ALL[index / 2], SEEDS[index % 2]);
        let cycle: &[u64] = if index < 2 { &[0, 4] } else { &[0, 4, 8] };
        let key = 0x9e37_79b9_7f4a_7c15_u64;
        let sum = (0..64).fold(0_u64, |sum, i| {
            sum.wrapping_add(seed ^ key.wrapping_mul(cycle[i % cycle.len()] + 1))
        });
        assert_eq!(*expected, (sum ^ key).wrapping_add(1));
        assert_eq!(*expected, truth::scalar(case, seed));
    }
}
fn kept(held: &VecDeque<(TreeBatch, Vec<TreeRecord>, Batch)>) {
    for (batch, seal, view) in held {
        assert_eq!(batch.rows(), seal.as_slice());
        assert_eq!(&Batch::from(batch), view);
    }
}
fn final_history(controller: &TreeController, rows: &[BlockRow]) {
    assert_eq!(rows.len(), BLOCKS);
    let h = controller.history().unwrap();
    assert_eq!(h.status, ControllerStatus::Ready);
    assert!(h.current.is_none() && h.retained_failed_generation.is_none());
    assert_eq!(h.enabled, [true, true]);
    assert_eq!(h.actions.len(), 2 * BLOCKS);
    for (i, action) in h.actions.iter().enumerate() {
        let generation = rows[i / 2].generation.expect("actual staged generation");
        assert_eq!(
            action.kind,
            if i % 2 == 0 {
                ActionKind::Published
            } else {
                ActionKind::Removed
            }
        );
        assert_eq!(action.generation.get(), generation);
        assert_eq!(
            action.current.map(|g| g.get()),
            (i % 2 == 0).then_some(generation)
        );
        assert_eq!((action.function, action.group), (None, None));
    }
}
fn original(
    mut prep: TreeSitePreparation,
    input: &[Input; 4],
    expected: &[Input; 4],
) -> (clocks::Snapshot, clocks::Snapshot, Vec<BlockRow>) {
    let readable = stack();
    let mut rows = Vec::with_capacity(BLOCKS);
    let mut calls = 0;
    let s1 = clocks::read();
    for block in 0..BLOCKS {
        let mut checksum = 0_u64;
        for i in 0..CALLS {
            let index = label(i).2;
            // SAFETY: one-use original guard, actual local stack, same immutable
            // full input and complete source; no installation or other entry.
            let call = unsafe {
                prep.prepare_original_call()
                    .unwrap()
                    .invoke(&input[index].0[64..1088], &readable)
            }
            .unwrap();
            assert!(call.pre_call_rsp >= 8 && call.pre_call_rsp & 15 == 0);
            assert_eq!(call.pre_call_rsp, call.resumed_rsp);
            assert_eq!(call.value, VALUES[index]);
            assert_eq!(input, expected);
            checksum = checksum.wrapping_add(call.value);
            calls += 1;
        }
        rows.push(BlockRow {
            index: block,
            checksum,
            generation: None,
        });
    }
    let s2 = clocks::read();
    assert_eq!(calls, BLOCKS * CALLS);
    // Keep the original source/generated owners alive for the process lifetime.
    std::mem::forget(prep);
    (s1, s2, rows)
}
fn installed(
    prep: TreeSitePreparation,
    root: u64,
    continuation: u64,
    k: usize,
    input: &[Input; 4],
    expected: &[Input; 4],
) -> (clocks::Snapshot, clocks::Snapshot, Vec<BlockRow>) {
    let prepared = PreparedTreeController::new(
        publish_tree(prep),
        INSTALL,
        FUNCTIONS,
        Limits {
            epochs: 1,
            threads: 1,
            depth: 2,
            records_per_epoch: 48,
            actions: 128,
        },
    )
    .unwrap();
    // SAFETY: complete five-role publication and unchanged actual-thread ABI;
    // controller operations occur only after synchronous physical returns.
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let mut attached: TreeThread =
        unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }.unwrap();
    let pid = std::process::id();
    let tid = u64::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap();
    assert_eq!(attached.totals().unwrap(), joins::totals_at(0, 0, k));
    let mut held = VecDeque::with_capacity(3);
    let mut cursor = joins::Cursor::default();
    let mut summaries = Vec::with_capacity(BLOCKS);
    let s1 = clocks::read();
    for block in 0..BLOCKS {
        let epoch = controller
            .stage(Config {
                retained_per_function: k,
                max_inflight: 2,
                max_invocations: 48,
            })
            .unwrap();
        let generation = epoch.generation().get();
        assert!(generation > 0);
        controller.arm(&epoch).unwrap();
        let spec = joins::Spec {
            root,
            continuation,
            pid,
            tid,
            k,
            block,
            generation,
        };
        let mut calls = Vec::with_capacity(CALLS);
        let mut nodes = Vec::with_capacity(2 * CALLS);
        let mut checksum = 0_u64;
        for i in 0..CALLS {
            let index = label(i).2;
            let id = (block * CALLS + i + 1) as u64;
            // SAFETY: one actual synchronous CALL, immutable input throughout
            // exclusive prepared guard/return/postflight; no writer or reentry.
            let call = unsafe {
                attached
                    .prepare_tree_call(&input[index].0[64..1088], id)
                    .unwrap()
                    .invoke()
            }
            .unwrap();
            assert!(joins::call(&spec, i, call));
            assert_eq!(input, expected);
            checksum = checksum.wrapping_add(call.value);
            calls.push(call);
            assert_eq!(
                attached.totals().unwrap(),
                joins::totals_at(block, i + 1, k)
            );
            if (i + 1) % PER_BATCH == 0 {
                kept(&held);
                if held.len() == 3 {
                    held.pop_front();
                }
                let batch = attached
                    .drain_completed()
                    .unwrap()
                    .expect("complete eight-root batch");
                if let Some((old, _, _)) = held.front() {
                    assert!(batch.same_stream(old));
                }
                let view = Batch::from(&batch);
                assert!(joins::batch(&spec, i / PER_BATCH, &calls, &view));
                nodes.extend_from_slice(&view.nodes);
                kept(&held);
                let seal = batch.rows().to_vec();
                held.push_back((batch, seal, view));
            }
        }
        assert!(attached.drain_completed().unwrap().is_none());
        controller.disarm(&epoch).unwrap();
        let report = controller.retire(&epoch).unwrap();
        assert_eq!(report.generation().get(), generation);
        let reports: Vec<_> = report.records().map(joins::Reported::from).collect();
        assert!(cursor.finish_block(&spec, &calls, &nodes, &reports));
        kept(&held);
        drop(report); // Its final Arc releases E1 before the next stage.
        summaries.push(BlockRow {
            index: block,
            checksum,
            generation: Some(generation),
        });
    }
    let s2 = clocks::read();
    assert_eq!(cursor.blocks(), BLOCKS);
    assert!(attached.drain_completed().unwrap().is_none());
    assert_eq!(attached.detach().unwrap(), joins::totals_at(BLOCKS, 0, k));
    final_history(&controller, &summaries);
    kept(&held);
    drop(held);
    drop(controller);
    (s1, s2, summaries)
}
fn optional(value: Option<u64>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}
fn export(out: &mut impl Write, mode: Mode, rows: &[BlockRow]) {
    assert_eq!(rows.len(), BLOCKS);
    writeln!(out, "{HEADER}").unwrap();
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row.index, index);
        assert_eq!(
            row.checksum,
            VALUES[0]
                .wrapping_add(VALUES[1])
                .wrapping_mul(5)
                .wrapping_add(VALUES[2].wrapping_add(VALUES[3]).wrapping_mul(7))
        );
        let first = index as u64 * 24 + 1;
        let k = mode.k.unwrap_or(0);
        let present = mode.k.is_some();
        assert_eq!(row.generation.is_some(), present);
        let selected = mode.k.map(|k| k.saturating_sub(10));
        let error = selected.map(|n| (24 * n) as i64 - (14 * k) as i64);
        writeln!(
            out,
            "{},{},{},{},24,{},{},{},{},{},{},{},{},{},{},{},{},14,{},{},{},7968,144,7824,{}",
            mode.name,
            index,
            first,
            first + 23,
            if present { 48 } else { 0 },
            2 * k,
            if present { 48 - 2 * k } else { 0 },
            if present { 3 } else { 0 },
            if present { 96 } else { 0 },
            2 * k,
            optional(row.generation),
            optional(present.then_some(2 * index as u64 + 1)),
            optional(present.then_some(first)),
            optional(present.then_some(first + 23)),
            optional(present.then_some((2 * k * index) as u64)),
            optional(present.then_some((2 * k * (index + 1)) as u64)),
            optional(selected.map(|n| n as u64)),
            error.map(|n| n.to_string()).unwrap_or_default(),
            optional(mode.k.map(|k| (24 * k) as u64)),
            row.checksum
        )
        .unwrap();
    }
}
pub(crate) fn run(mode: &str, candidate: &Path, expected: &Path) {
    let mode = Mode::parse(mode);
    single_main();
    let cpu = pin(None);
    let resolution = clocks::resolution();
    let s0 = clocks::read(); // Whole region starts before source/load/input/setup.
    let (prep, root, continuation) = prepare(candidate, expected);
    values();
    let expected_inputs = inputs();
    let input = Box::new(expected_inputs.clone());
    let (s1, s2, rows) = match mode.k {
        None => original(prep, &input, &expected_inputs),
        Some(k) => installed(prep, root, continuation, k, &input, &expected_inputs),
    };
    assert_eq!(*input, expected_inputs);
    drop(input);
    pin(Some(cpu));
    single_main();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    export(&mut out, mode, &rows);
    out.flush().unwrap();
    let s3 = clocks::read(); // Flush belongs to whole, not the inner loop.
    let snapshots = [s0, s1, s2, s3];
    let m = clocks::metrics(&snapshots, resolution).expect("valid whole/loop clock brackets");
    let k = mode.k.unwrap_or(0);
    let present = mode.k.is_some();
    write!(out, "tree-throughput FUNCTIONAL_PASS mode={} blocks=64 roots=1536 calls=1536 originals={} installed_roots={} node_rows={} sampled={} closed={} batches={} events={} reports={} epochs={} actions={} root_inclusive_instructions=509952 root_exclusive_instructions=9216 child_instructions=500736 input_unchanged=true records_joined={} clock_scope=guarded-consumer",
        mode.name, if present { 0 } else { 1536 }, if present { 1536 } else { 0 },
        if present { 3072 } else { 0 }, 128*k, if present { 3072-128*k } else { 0 },
        if present { 192 } else { 0 }, if present { 6144 } else { 0 }, 128*k,
        if present { 64 } else { 0 }, if present { 128 } else { 0 }, present).unwrap();
    for (i, s) in snapshots.iter().enumerate() {
        write!(
            out,
            " s{i}_wall_before={} s{i}_cpu={} s{i}_wall_after={}",
            s.wall_before, s.cpu, s.wall_after
        )
        .unwrap();
    }
    writeln!(out, " wall_resolution_ns={} cpu_resolution_ns={} whole_wall_lower_ns={} whole_wall_ns={} whole_cpu_ns={} loop_wall_lower_ns={} loop_wall_ns={} loop_cpu_ns={}",
        resolution.wall, resolution.cpu, m.whole_wall_lower, m.whole_wall_upper, m.whole_cpu,
        m.loop_wall_lower, m.loop_wall_upper, m.loop_cpu).unwrap();
    out.flush().unwrap(); // Timing terminal itself is outside both regions.
}
