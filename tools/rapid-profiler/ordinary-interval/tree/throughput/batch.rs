//! Eight-call source-provenance policy for the same complete checked consumer.
//! No bare-native, hook-cost or equal invalid-client-detection claim.
use super::*;
use rapid_profiler::frontend_native::TreeSourceBatchRequest;

const CHUNKS: usize = 3;
const FINISHES: usize = BLOCKS * CHUNKS;
const PROVENANCE: &str = "source-batch8";

fn mode(name: &str) -> Mode {
    match name {
        "original-sdk-batch8" => Mode {
            name: "original-sdk-batch8",
            k: None,
        },
        "k1-batch8" => Mode {
            name: "k1-batch8",
            k: Some(1),
        },
        "k10-batch8" => Mode {
            name: "k10-batch8",
            k: Some(10),
        },
        "k24-batch8" => Mode {
            name: "k24-batch8",
            k: Some(24),
        },
        _ => panic!(
            "tree-comparison-batch mode must be original-sdk-batch8, k1-batch8, k10-batch8 or k24-batch8"
        ),
    }
}

fn requests(
    input: &[Input; 4],
    block: usize,
    chunk: usize,
) -> [TreeSourceBatchRequest<'_>; PER_BATCH] {
    assert_eq!((CALLS, PER_BATCH, CHUNKS), (24, 8, 3));
    assert!(block < BLOCKS && chunk < CHUNKS, "bounded request chunk");
    std::array::from_fn(|n| {
        let i = chunk * PER_BATCH + n;
        TreeSourceBatchRequest {
            bytes: &input[label(i).2].0[64..1088],
            external_id: (block * CALLS + i + 1) as u64,
        }
    })
}

fn record_finish(finishes: &mut usize, calls: usize) {
    assert_eq!(calls, PER_BATCH, "exact eight-call source finish");
    assert!(*finishes < FINISHES, "bounded successful finish count");
    *finishes += 1;
}

fn original(
    mut prep: TreeSitePreparation,
    input: &[Input; 4],
    expected: &[Input; 4],
    mut collected: Option<&mut collection::Results>,
) -> (clocks::Snapshot, clocks::Snapshot, Vec<BlockRow>, usize) {
    let readable = stack();
    let mut rows = Vec::with_capacity(BLOCKS);
    let mut calls = 0;
    let mut finishes = 0;
    let s1 = clocks::read();
    for block in 0..BLOCKS {
        let mut checksum = 0_u64;
        for chunk in 0..CHUNKS {
            // Only the bytes are passed to the original-only API. These local
            // scheduling IDs are not original-call observations or raw rows.
            let scheduled = requests(input, block, chunk);
            let requests = scheduled.map(|r| r.bytes);
            // SAFETY: actual local stack and retained original source/owners;
            // immutable file, mappings and all inputs continuously through finish,
            // including gaps. No publication, alias writer, foreign entry, signal,
            // fork, unload, reentry or nonlocal exit; eight normal real CALL/RETs.
            let mut guard =
                unsafe { prep.begin_original_source_batch(&requests, &readable) }.unwrap();
            for n in 0..PER_BATCH {
                let i = chunk * PER_BATCH + n;
                let index = label(i).2;
                // SAFETY: the complete begin contract still holds through this
                // synchronous call and subsequent explicit finish.
                let call = unsafe { guard.invoke_next() }.unwrap();
                assert!(call.pre_call_rsp >= 8 && call.pre_call_rsp & 15 == 0);
                assert_eq!(call.pre_call_rsp, call.resumed_rsp);
                assert_eq!(call.value, VALUES[index]);
                assert_eq!(input, expected);
                if let Some(results) = &mut collected {
                    results.record(block * CALLS + i, call.value);
                }
                checksum = checksum.wrapping_add(call.value);
                calls += 1;
            }
            record_finish(&mut finishes, guard.finish().unwrap().calls());
        }
        rows.push(BlockRow {
            index: block,
            checksum,
            generation: None,
        });
    }
    assert_eq!(finishes, FINISHES); // Every successful finish is inside S1..S2.
    let s2 = clocks::read();
    assert_eq!(calls, BLOCKS * CALLS);
    // Keep the original source/generated owners alive for the process lifetime.
    std::mem::forget(prep);
    (s1, s2, rows, finishes)
}
fn installed(
    prep: TreeSitePreparation,
    root: u64,
    continuation: u64,
    k: usize,
    input: &[Input; 4],
    expected: &[Input; 4],
    mut collected: Option<&mut collection::Results>,
) -> (clocks::Snapshot, clocks::Snapshot, Vec<BlockRow>, usize) {
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
    let mut finishes = 0;
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
        for chunk in 0..CHUNKS {
            let requests = requests(input, block, chunk);
            // SAFETY: one attached actual thread and retained sealed source/image
            // owners; immutable files, mappings and all inputs through finish,
            // including gaps. Same valid normal stack, no code retirement/writer,
            // foreign entry, signal, fork, unload, reentry or nonlocal exit.
            let mut guard = unsafe { attached.begin_source_batch(&requests) }.unwrap();
            for n in 0..PER_BATCH {
                let i = chunk * PER_BATCH + n;
                // SAFETY: the complete begin contract still holds; this invokes
                // exactly the next request and commits its own actual return.
                let call = unsafe { guard.invoke_next() }.unwrap();
                assert!(joins::call(&spec, i, call));
                assert_eq!(input, expected);
                if let Some(results) = &mut collected {
                    results.record(block * CALLS + i, call.value);
                }
                checksum = checksum.wrapping_add(call.value);
                calls.push(call);
                assert_eq!(guard.totals().unwrap(), joins::totals_at(block, i + 1, k));
            }
            // Consuming finish proves the complete source boundary before any
            // drain. Neither successful calls nor model readiness replace it.
            record_finish(&mut finishes, guard.finish().unwrap().calls());
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
            assert!(joins::batch(&spec, chunk, &calls, &view));
            nodes.extend_from_slice(&view.nodes);
            kept(&held);
            let seal = batch.rows().to_vec();
            held.push_back((batch, seal, view));
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
    assert_eq!(finishes, FINISHES); // Final finish and Report drop precede S2.
    let s2 = clocks::read();
    assert_eq!(cursor.blocks(), BLOCKS);
    assert!(attached.drain_completed().unwrap().is_none());
    assert_eq!(attached.detach().unwrap(), joins::totals_at(BLOCKS, 0, k));
    final_history(&controller, &summaries);
    kept(&held);
    drop(held);
    drop(controller);
    (s1, s2, summaries, finishes)
}
pub(crate) fn run(name: &str, candidate: &Path, expected: &Path) {
    let mode = mode(name);
    let collect = true;
    single_main();
    let cpu = pin(None);
    let resolution = clocks::resolution();
    let s0 = clocks::read(); // Whole region starts before source/load/input/setup.
    let (prep, root, continuation) = prepare(candidate, expected);
    values();
    let expected_inputs = inputs();
    let input = Box::new(expected_inputs.clone());
    let mut collected = collect.then(collection::Results::new);
    if collect {
        assert_eq!((BLOCKS, CALLS), (collection::BLOCKS, collection::CALLS));
        for call in 0..CALLS {
            assert_eq!(label(call).2, collection::input_index(call));
        }
    }
    let (s1, s2, rows, finishes) = match mode.k {
        None => original(prep, &input, &expected_inputs, collected.as_mut()),
        Some(k) => installed(
            prep,
            root,
            continuation,
            k,
            &input,
            &expected_inputs,
            collected.as_mut(),
        ),
    };
    if let Some(results) = &collected {
        results.complete(
            &VALUES,
            &rows.iter().map(|row| row.checksum).collect::<Vec<_>>(),
        );
    }
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
    let protocol = "tree-comparison-batch";
    let scope = "matched-consumer";
    write!(out, "{protocol} FUNCTIONAL_PASS mode={} blocks=64 roots=1536 calls=1536 originals={} installed_roots={} node_rows={} sampled={} closed={} batches={} events={} reports={} epochs={} actions={} root_inclusive_instructions=509952 root_exclusive_instructions=9216 child_instructions=500736 input_unchanged=true records_joined={} clock_scope={scope}",
        mode.name, if present { 0 } else { 1536 }, if present { 1536 } else { 0 },
        if present { 3072 } else { 0 }, 128*k, if present { 3072-128*k } else { 0 },
        if present { 192 } else { 0 }, if present { 6144 } else { 0 }, 128*k,
        if present { 64 } else { 0 }, if present { 128 } else { 0 }, present).unwrap();
    if collect {
        write!(out, " collected_results=1536").unwrap();
    }
    write!(
        out,
        " source_batch_calls=8 source_batch_finishes={finishes} provenance_policy={PROVENANCE}"
    )
    .unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_batch_modes_are_distinct_from_every_historical_route() {
        for (name, k) in [
            ("original-sdk-batch8", None),
            ("k1-batch8", Some(1)),
            ("k10-batch8", Some(10)),
            ("k24-batch8", Some(24)),
        ] {
            assert_eq!(mode(name), Mode { name, k });
        }
        for name in [
            "",
            "native",
            "original-sdk",
            "k1",
            "k10",
            "k24",
            "k2-batch8",
            "k10-batch8 ",
        ] {
            assert!(std::panic::catch_unwind(|| mode(name)).is_err());
        }
    }

    #[test]
    fn source_batch_requests_preserve_all_ids_and_mixed_chunk_inputs() {
        let input = inputs();
        // Literal independent input schedule: the middle chunk straddles both
        // Fit2/Conflict3 and K10, while the first/last chunk edges stay 8/16.
        let schedule = [
            0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
        ];
        let mut next_id = 1;
        let mut counts = [0; 4];
        for block in 0..64 {
            for chunk in 0..3 {
                let requests = requests(&input, block, chunk);
                let original = requests.map(|r| r.bytes);
                assert_eq!(requests.len(), 8);
                for (n, request) in requests.iter().enumerate() {
                    let index = schedule[chunk * 8 + n];
                    assert_eq!(request.external_id, next_id);
                    assert_eq!(request.bytes.len(), 1024);
                    assert_eq!(request.bytes.as_ptr(), input[index].0[64..1088].as_ptr());
                    assert_eq!(request.bytes, &input[index].0[64..1088]);
                    assert_eq!(original[n].as_ptr(), request.bytes.as_ptr());
                    assert_eq!(original[n].len(), 1024);
                    counts[index] += 1;
                    next_id += 1;
                }
            }
        }
        assert_eq!(next_id, 1537);
        assert_eq!(counts, [320, 320, 448, 448]);
        assert_eq!(&schedule[8..16], &[0, 1, 2, 3, 2, 3, 2, 3]);
    }

    #[test]
    fn source_batch_requests_refuse_out_of_population_before_indexing() {
        let input = inputs();
        for (block, chunk) in [(64, 0), (usize::MAX, 0), (0, 3), (0, usize::MAX), (64, 3)] {
            assert!(std::panic::catch_unwind(|| requests(&input, block, chunk)).is_err());
        }
        assert_eq!(requests(&input, 63, 2)[7].external_id, 1536);
    }

    #[test]
    fn source_batch_finish_accounting_requires_eight_and_bounds_every_increment() {
        // Scripted verification counts exercise only consumer bookkeeping;
        // they do not fabricate an SDK verification, call or native finish.
        for initial in [0, 191] {
            for calls in [0, 7, 9, usize::MAX] {
                let mut finishes = initial;
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        record_finish(&mut finishes, calls);
                    }))
                    .is_err()
                );
                assert_eq!(finishes, initial);
            }
        }
        let mut finishes = 0;
        for expected in 1..=192 {
            record_finish(&mut finishes, 8);
            assert_eq!(finishes, expected);
        }
        for initial in [finishes, usize::MAX] {
            let mut count = initial;
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    record_finish(&mut count, 8);
                }))
                .is_err()
            );
            assert_eq!(count, initial);
        }
    }
}
