//! Four fixed loaded CALL-tree pairs; no hardware-cache or timing claim.
use super::{Path, STATE_SEEDS, current_single_main, oracle};
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::*;
use oracle::native_ordinary::{
    ChildContext, GATE_BYTES, OrdinaryOracle, Profile, Ready, call_tree,
};
use rapid_profiler::frontend::{
    Action, ActionKind, ControllerStatus, Limits, Observation, PayloadOutcome,
};
use rapid_profiler::frontend_native::{
    IntervalJournal, LoadedCallTree, PairTotals, PreparedTreeController, RawIntervalOwner,
    ReadableStack, TreeCallGate, TreeContract, TreeSitePreparation, TreeTotals,
};
use rapid_profiler::generation::{Config, Disposition, FunctionId, Terminal};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

unsafe extern "C" {
    static __rapid_profiler_ordinary_call_v1: u8;
}
const FUNCTIONS: [FunctionId; 2] = [FunctionId(1), FunctionId(2)];
const INSTALL: u64 = 0x7472_6565;
const REGISTRATION: u64 = 1;
const EXTERNAL_ID: u64 = 1;
const CONTRACT: TreeContract = TreeContract {
    root_only_external_entry: true,
    ordinary_ret_only: true,
    no_active_cet: true,
};

// Same separately trusted complete-ELF contract as the old ordinary driver.
fn expected_bytes(subject: &Path, expected: &Path) -> Vec<u8> {
    let mut file = File::open(expected).unwrap();
    let before = file.metadata().unwrap();
    let other = std::fs::metadata(subject).unwrap();
    assert!(before.is_file() && other.is_file());
    assert_ne!(
        (before.dev(), before.ino()),
        (other.dev(), other.ino()),
        "independent expected ELF"
    );
    assert!((1..=1024 * 1024).contains(&before.len()));
    let mut bytes = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    let stamp = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    assert_eq!(stamp(&before), stamp(&file.metadata().unwrap()));
    assert_eq!(bytes.len() as u64, before.len());
    bytes
}

fn protect(range: AddressRange, flags: i32) -> Result<(), Refusal> {
    // SAFETY: this actual sole child owns the one complete common source page.
    if unsafe {
        libc::mprotect(
            range.start() as usize as *mut libc::c_void,
            range.len() as usize,
            flags,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}
fn publish(prep: TreeSitePreparation) -> rapid_profiler::frontend_native::InstalledTreeSite {
    current_single_main();
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert_eq!(originals.len(), 1);
    let source = AddressRange::new(originals[0].address, originals[0].bytes.len()).unwrap();
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|s| s.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    // SAFETY: exact whole-page alias, sole actual child, no application call or
    // signal/writer/resume; preparation is exclusively borrowed through publish.
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
        Err(failure) => {
            eprintln!("tree oracle publication FAILED: {failure:?}");
            // Keep partial publication/code/control ownership; never unwind it.
            std::process::abort();
        }
    };
    // SAFETY: exact published owners, final RX, process-lived child-local source.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

fn child(candidate: bool, context: ChildContext<'_>, subject: &Path, expected_elf: &[u8]) {
    current_single_main();
    let (case, seed) = context.tree_case().expect("closed tree child");
    let input = call_tree::truth::input(case, seed);
    assert_eq!(context.input(), &input);
    // SAFETY: fixed exact linked DSO, only the root has external entry, no CET,
    // constructor/signal/nonlocal entry, foreign caller, source writer or unload.
    let owner = unsafe {
        LoadedCallTree::load(
            subject,
            expected_elf,
            c"call_tree_root",
            c"call_tree_child",
            CONTRACT,
        )
    }
    .unwrap();
    call_tree::truth::check_bytes(owner.root_code(), owner.callee_code()).unwrap();
    let entry = owner.certificate().root().entry();
    let child_entry = owner.certificate().callee().entry();
    assert_eq!(child_entry, entry + 32);
    assert_eq!(owner.certificate().root().call().call_pc(), entry + 9);
    assert_eq!(owner.certificate().root().call().continuation(), entry + 14);
    let heads: Vec<_> = owner
        .certificate()
        .root()
        .heads()
        .iter()
        .chain(owner.certificate().callee().heads())
        .copied()
        .collect();
    let returns = vec![entry + 22, child_entry + 38];
    assert_eq!(owner.certificate().root().returns(), &returns[..1]);
    assert_eq!(owner.certificate().callee().returns(), &returns[1..]);
    let gate = TreeCallGate::new(owner.certificate().root()).unwrap();
    let gate_address = &raw const __rapid_profiler_ordinary_call_v1 as usize as u64;
    // SAFETY: bounded immutable production text; no direct raw invocation.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(gate_address as usize as *const u8, GATE_BYTES.len()) },
        GATE_BYTES
    );
    assert_eq!(gate.continuation(), gate_address + 25);
    let continuation = gate.continuation();
    let mut prep = TreeSitePreparation::new(
        owner,
        gate,
        CodeIdentity {
            source: SourceIdentity([0x74; 32]),
            mapping: entry,
            generation: 1,
        },
    )
    .unwrap();
    let originals = prep.plan().plan().originals();
    assert_eq!(originals.len(), 1);
    let original_source = originals[0].bytes.clone();
    let mut immutable = vec![(originals[0].address, original_source.clone())];
    let mut boundaries: Vec<_> = heads.iter().map(|p| (*p, *p)).collect();
    if candidate {
        let planned = prep.plan();
        assert_eq!(planned.plan().final_bytes().len(), 1);
        let final_source = &planned.plan().final_bytes()[0];
        immutable[0] = (final_source.address, final_source.bytes.clone());
        boundaries.clear();
        for image in planned.images() {
            boundaries.extend_from_slice(image.instruction_boundaries());
            immutable.push((image.address(), image.bytes().to_vec()));
        }
        // The shortest covering child-entry window can leave child+6 in source.
        // Every original head still has exactly one full-state observation.
        for &pc in &heads {
            if !boundaries.iter().any(|(head, _)| *head == pc) {
                boundaries.push((pc, pc));
            }
        }
        assert_eq!(
            immutable.len(),
            5,
            "one source page and four complete images"
        );
    }
    assert_eq!(
        boundaries.iter().find(|(pc, _)| *pc == entry + 9),
        Some(&(entry + 9, entry + 9))
    );
    let ready = Ready {
        profile: Profile::Legacy,
        entry,
        gate: gate_address,
        continuation,
        heads,
        returns,
        boundaries,
        immutable,
        original_source,
    };
    let data = context.input().as_ptr();
    let length = context.input().len();
    assert_eq!(length, 1024);
    let expected = call_tree::truth::scalar(case, seed);
    let gate_rsp = context.gate_rsp();
    let root_rsp = gate_rsp - 16;
    let (start, end) = context.stack_range();
    // SAFETY: inherited private guarded stack covers the actual armed CALL,
    // both application frames, and the complete child's red zone until return.
    let stack = unsafe { ReadableStack::new(start, end) }.unwrap();
    if candidate {
        let site = publish(prep);
        let mut prepared = PreparedTreeController::new(
            site,
            INSTALL,
            FUNCTIONS,
            Limits {
                epochs: 1,
                threads: 1,
                depth: 2,
                records_per_epoch: 2,
                actions: 2,
            },
        )
        .unwrap();
        let epoch = prepared
            .stage(Config {
                retained_per_function: 1,
                max_inflight: 2,
                max_invocations: 2,
            })
            .unwrap();
        let generation = epoch.generation().get();
        // SAFETY: the actual child remains single-main and owns published code.
        let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
        controller.arm(&epoch).unwrap();
        let mut attached =
            unsafe { client.attach(REGISTRATION, stack, IntervalJournal::allocate()) }.unwrap();
        let zero = TreeTotals {
            roots: 0,
            pairs: PairTotals {
                entries: 0,
                returns: 0,
                completed: 0,
                unsampled: 0,
            },
        };
        let totals = TreeTotals {
            roots: 1,
            pairs: PairTotals {
                entries: 2,
                returns: 2,
                completed: 2,
                unsampled: 0,
            },
        };
        assert_eq!(attached.totals().unwrap(), zero);
        context.ready(&ready);
        // SAFETY: full immutable1024B closed input, genuine attached tree gate;
        // tracer restores only this child's harness context after all comparisons.
        let result =
            unsafe { attached.invoke_tree(std::slice::from_raw_parts(data, length), EXTERNAL_ID) }
                .unwrap();
        assert_eq!(
            (
                result.value,
                result.pre_call_rsp,
                result.entry_rsp,
                result.resumed_rsp,
                result.return_pc,
                result.gate_sequence,
                result.external_id
            ),
            (
                expected,
                gate_rsp - 8,
                root_rsp,
                gate_rsp - 8,
                entry + 22,
                1,
                EXTERNAL_ID
            )
        );
        assert_eq!(unsafe { std::slice::from_raw_parts(data, length) }, &input);
        assert_eq!(attached.totals().unwrap(), totals);
        let batch = attached
            .drain_completed()
            .unwrap()
            .expect("two physically returned tree rows");
        let pid = std::process::id();
        assert_eq!(batch.pid(), pid);
        assert_eq!(batch.tid(), u64::from(pid));
        assert_eq!(batch.registration(), REGISTRATION);
        assert_eq!(batch.install(), INSTALL);
        assert_eq!(batch.functions(), FUNCTIONS);
        assert_eq!(batch.number(), 1);
        assert_eq!((batch.gate_base(), batch.gate_sequence()), (0, 1));
        assert_eq!(batch.completed_sequences(), (0, 2));
        assert_eq!(batch.totals(), (zero, totals));
        assert_eq!(batch.rows().len(), 2);
        for node in 0..2_u8 {
            let matches: Vec<_> = batch
                .rows()
                .iter()
                .filter(|row| row.node() == node)
                .collect();
            assert_eq!(matches.len(), 1);
            let row = matches[0];
            let n = usize::from(node);
            let raw = row.raw();
            assert_eq!(row.external_id(), EXTERNAL_ID);
            assert_eq!(row.parent(), (node == 1).then_some((EXTERNAL_ID, 0)));
            assert_eq!(row.function(), FUNCTIONS[n]);
            assert_eq!(row.depth(), n);
            assert_eq!(row.callsite(), (node == 1).then_some(entry + 9));
            assert_eq!(
                row.entry_rsp(),
                if node == 0 { root_rsp } else { root_rsp - 16 }
            );
            assert_eq!(
                row.return_word(),
                if node == 0 { continuation } else { entry + 14 }
            );
            assert_eq!(
                row.resume_pc(),
                if node == 0 { continuation } else { entry + 14 }
            );
            assert_eq!(
                row.resume_rsp(),
                if node == 0 {
                    gate_rsp - 8
                } else {
                    root_rsp - 8
                }
            );
            assert_eq!(
                row.value(),
                if node == 0 {
                    expected
                } else {
                    expected.wrapping_sub(1)
                }
            );
            assert_eq!(
                (
                    row.gate_sequence(),
                    row.registration(),
                    row.history_prefix()
                ),
                (1, REGISTRATION, 1)
            );
            assert_eq!(row.model_start_sequence(), Some(0));
            assert_eq!(row.model_completed_children(), Some(u64::from(node == 0)));
            assert_eq!(
                (raw.ordinal, raw.entry_pc, raw.return_pc),
                (
                    u64::from(node) + 1,
                    if node == 0 { entry } else { child_entry },
                    if node == 0 {
                        entry + 22
                    } else {
                        child_entry + 38
                    }
                )
            );
            assert_eq!(
                raw.owner,
                RawIntervalOwner::Sampled {
                    generation,
                    invocation: n
                }
            );
        }
        let mut journal = [0_u64; 512];
        journal[..4].copy_from_slice(&[4, 0, u64::from(pid), 0]);
        for (index, event) in [
            [
                1,
                1,
                entry,
                root_rsp,
                continuation,
                generation,
                1 | (1 << 13),
            ],
            [
                1,
                2,
                child_entry,
                root_rsp - 16,
                entry + 14,
                generation,
                2 | (1 << 13),
            ],
            [
                2,
                2,
                child_entry + 38,
                root_rsp - 16,
                entry + 14,
                generation,
                2 | (1 << 13),
            ],
            [
                2,
                1,
                entry + 22,
                root_rsp,
                continuation,
                generation,
                1 | (1 << 13),
            ],
        ]
        .into_iter()
        .enumerate()
        {
            journal[4 + 7 * index..11 + 7 * index].copy_from_slice(&event);
        }
        assert_eq!(batch.journal(), &journal);
        assert!(attached.drain_completed().unwrap().is_none());
        assert_eq!(attached.totals().unwrap(), totals);
        controller.disarm(&epoch).unwrap();
        let report = controller.report(&epoch).unwrap().unwrap();
        assert_eq!(report.generation().get(), generation);
        let records: Vec<_> = report.records().collect();
        assert_eq!(records.len(), 2);
        for row in batch.rows() {
            let n = usize::from(row.node());
            let raw = row.raw();
            let records: Vec<_> = records
                .iter()
                .filter(|r| r.record.admission.function == FUNCTIONS[n])
                .collect();
            assert_eq!(records.len(), 1);
            let record = records[0];
            let admission = record.record.admission;
            assert_eq!(admission.generation.get(), generation);
            assert_eq!(
                (
                    admission.function,
                    admission.invocation,
                    admission.entry_value
                ),
                (FUNCTIONS[n], n, raw.start.ticks)
            );
            assert_eq!(
                record.record.terminal,
                Some(Terminal::Completed {
                    value: n as u64,
                    disposition: Disposition::Retained { rank: 0 }
                })
            );
            let payload = record.payload.unwrap();
            assert_eq!(payload.admission, admission);
            assert_eq!((payload.thread, payload.start_sequence), (REGISTRATION, 0));
            let end = if raw.start.aux != raw.end.aux {
                Observation::Unavailable(1)
            } else if raw.end.ticks < raw.start.ticks {
                Observation::Unavailable(2)
            } else {
                Observation::Value(raw.end.ticks)
            };
            assert_eq!(
                payload.outcome,
                PayloadOutcome::Completed {
                    end,
                    completed_children: u64::from(row.node() == 0)
                }
            );
        }
        let history = controller.history().unwrap();
        assert_eq!(history.status, ControllerStatus::Ready);
        assert_eq!(history.current, None);
        assert_eq!(history.retained_failed_generation, None);
        assert_eq!(
            history.actions,
            [
                Action {
                    kind: ActionKind::Published,
                    generation: epoch.generation(),
                    function: None,
                    current: Some(epoch.generation()),
                    group: None
                },
                Action {
                    kind: ActionKind::Removed,
                    generation: epoch.generation(),
                    function: None,
                    current: None,
                    group: None
                },
            ]
        );
        assert_eq!(attached.detach().unwrap(), totals);
        // Both retained model owners were completed only after physical returns;
        // raw callback TSC values are joined, not compared across siblings.
    } else {
        // SAFETY: original whole-source before-check precedes the tracer stop.
        let original = unsafe { prep.prepare_original_call() }.unwrap();
        context.ready(&ready);
        // SAFETY: the controlled stop runs no handler/writer; consuming guard
        // performs the real original CALL and complete source after-check.
        let result =
            unsafe { original.invoke(std::slice::from_raw_parts(data, length), &stack) }.unwrap();
        assert_eq!(
            (result.value, result.pre_call_rsp, result.resumed_rsp),
            (expected, gate_rsp - 8, gate_rsp - 8)
        );
        assert_eq!(unsafe { std::slice::from_raw_parts(data, length) }, &input);
    }
    current_single_main();
}

pub fn run(subject: &Path, expected: &Path, output: &Path) {
    current_single_main();
    let expected_elf = expected_bytes(subject, expected);
    let mut csv = String::from(
        "seed,case,status,children,comparisons,original_visits,original_steps,candidate_steps,instructions,root_instructions,child_instructions,conditional_branches,taken_branches,input_reads,return_reads,call_stores,model_events,model_hits,model_misses,root_misses,child_misses,model_writebacks,model_hit_bits,value,transfers,real_outer_returns\n",
    );
    let mut totals = [0_usize; 14];
    let mut last_deadline = None;
    for seed in STATE_SEEDS {
        let mut observed_returns = BTreeSet::new();
        let mut declared_returns = None;
        for case in call_tree::truth::ALL {
            let oracle = OrdinaryOracle::new_tree(case, seed);
            let deadline = oracle.tree_deadline();
            let mut stats = None;
            let result = oracle.pair_tree(
                |candidate, context| child(candidate, context, subject, &expected_elf),
                |actual| {
                    stats = Some(call_tree::inspect(case, seed, actual));
                },
            );
            assert!(Instant::now() < deadline);
            let call_tree::Stats { counts, model } =
                stats.expect("complete actual original tree trace");
            assert_eq!(result.visits, 332);
            assert_eq!(result.comparisons, 343);
            assert!((1..=20_000).contains(&result.original_steps));
            assert!((1..=20_000).contains(&result.candidate_steps));
            assert_eq!(result.value, call_tree::truth::scalar(case, seed));
            assert_eq!(result.returns.len(), 2);
            assert_eq!(result.returns, result.declared_returns);
            if let Some(previous) = &declared_returns {
                assert_eq!(previous, &result.declared_returns);
            } else {
                declared_returns = Some(result.declared_returns.clone());
            }
            observed_returns.extend(result.returns);
            let bits: String = model
                .hit_by_event
                .iter()
                .map(|&hit| if hit { '1' } else { '0' })
                .collect();
            assert_eq!(bits.len(), 132);
            // pair_tree returned only after both Witness::finish()==3 and both
            // actual outer RET/normal reaps. These fixed counts are not readiness.
            let (transfers, outer_returns) = (6, 2);
            csv.push_str(&format!("{seed},{},PASS,2,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n", case.name(), result.comparisons, result.visits, result.original_steps, result.candidate_steps, counts.instructions, counts.root_instructions, counts.child_instructions, counts.conditional, counts.taken, counts.input_reads, counts.return_reads, counts.call_stores, model.accesses, model.hits, model.misses, model.root_misses, model.child_misses, model.writebacks, bits, result.value, transfers, outer_returns));
            let values = [
                1,
                result.comparisons,
                counts.instructions,
                counts.conditional,
                counts.taken,
                counts.input_reads,
                counts.return_reads,
                counts.call_stores,
                model.accesses,
                model.hits,
                model.misses,
                transfers,
                outer_returns,
                model.writebacks,
            ];
            for (total, value) in totals.iter_mut().zip(values) {
                *total = total.checked_add(value).unwrap();
            }
            std::fs::write(output.join("tree-pairs.csv"), &csv).unwrap();
            assert!(Instant::now() < deadline, "tree complete output deadline");
            last_deadline = Some(deadline);
        }
        assert_eq!(
            observed_returns,
            declared_returns.unwrap(),
            "complete actual two-RET union per seed"
        );
    }
    assert_eq!(
        totals,
        [4, 1372, 1328, 256, 252, 516, 8, 4, 528, 392, 136, 24, 8, 0]
    );
    current_single_main();
    assert!(
        Instant::now() < last_deadline.unwrap(),
        "tree final output deadline"
    );
    println!(
        "native-tree:required=4:pairs=4:children=8:comparisons=1372:instructions=1328:conditional=256:taken=252:input-reads=516:return-reads=8:call-stores=4:model-events=528:model-hits=392:model-misses=136:transfers=24:real-outer-ret=8:complete"
    );
    assert!(
        Instant::now() < last_deadline.unwrap(),
        "tree terminal output deadline"
    );
}

/// One intentionally malformed child return word, separate from state pairs.
pub fn run_refusal(subject: &Path, expected: &Path, output: &Path) {
    current_single_main();
    let expected_elf = expected_bytes(subject, expected);
    let oracle = OrdinaryOracle::new_tree(call_tree::truth::Case::Fit2, call_tree::refusal::SEED);
    let deadline = oracle.tree_deadline();
    let result =
        oracle.refuse_tree_child_return(|context| child(true, context, subject, &expected_elf));
    assert!((1..=20_000).contains(&result.steps));
    assert!(Instant::now() < deadline);
    current_single_main();
    std::fs::write(output.join("tree-refusal.csv"), format!(
        "status,children,steps,injected_bytes,physical_calls,exit_code,reaped,echild,runtime_cause\nEXPECTED_REFUSAL,1,{},8,1,123,1,1,undifferentiated\n", result.steps
    )).unwrap();
    assert!(
        Instant::now() < deadline,
        "refusal complete output deadline"
    );
    println!(
        "native-tree-refusal:required=1:children=1:injected-bytes=8:physical-call=1:exit=123:reaped=1:echild=1:runtime-cause=undifferentiated:expected-refusal"
    );
    assert!(
        Instant::now() < deadline,
        "refusal terminal output deadline"
    );
}
