//! Eight real SDK source-batch calls. Only indices 0 and 7 receive full-state
//! comparison; the middle six retain actual transfer and complete functional joins.
use super::*;
use rapid_profiler::frontend_native::{TreeCallResult, TreeSourceBatchRequest};

const CALLS: usize = 8;
const SELECTED: [usize; 2] = [0, 7];

// No ninth or post-finish checkpoint. This is a qualification-only, direct
// self-SIGSTOP after a real return and complete functional/input assertions.
// The unchanged Tracee owns the signal; no application signal handler runs.
fn checkpoint(index: usize) {
    assert!(index < CALLS - 1);
    // SAFETY: direct Linux syscalls with initialized integer arguments. The
    // child is still single-main, and its exact parent is the existing tracer.
    unsafe {
        let pid = libc::syscall(libc::SYS_getpid);
        let tid = libc::syscall(libc::SYS_gettid);
        assert!(pid > 0 && pid <= libc::c_long::from(i32::MAX));
        assert_eq!(tid, pid);
        assert_eq!(libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGSTOP), 0);
    }
}

fn totals() -> TreeTotals {
    TreeTotals {
        roots: CALLS as u64,
        pairs: PairTotals {
            entries: (2 * CALLS) as u64,
            returns: (2 * CALLS) as u64,
            completed: (2 * CALLS) as u64,
            unsampled: 0,
        },
    }
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
    // SAFETY: this is the same inherited oracle mapping exposed by context;
    // the parent keeps it alive across both children and all eight real calls.
    // No mutable slice/reference or TLS borrow crosses the native CALL.
    let bytes = unsafe { std::slice::from_raw_parts(data, length) };
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
                records_per_epoch: 16,
                actions: 2,
            },
        )
        .unwrap();
        let epoch = prepared
            .stage(Config {
                retained_per_function: CALLS,
                max_inflight: 2,
                max_invocations: 16,
            })
            .unwrap();
        let generation = epoch.generation().get();
        // SAFETY: one actual child, exact five-role publication and Tree144
        // stack contract. The parent supplies this guarded stack on every call.
        let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
        controller.arm(&epoch).unwrap();
        let mut attached =
            unsafe { client.attach(REGISTRATION, stack, IntervalJournal::allocate()) }.unwrap();
        let zero = TreeTotals::default();
        assert_eq!(attached.totals().unwrap(), zero);
        let requests: [TreeSourceBatchRequest<'_>; CALLS] =
            std::array::from_fn(|index| TreeSourceBatchRequest {
                bytes,
                external_id: EXTERNAL_ID + index as u64,
            });
        // SAFETY: caller-owned source/input/stack remain immutable and live
        // through finish, including each controlled stop. No foreign entry,
        // signal handler, file/mapping writer, reentry, fork or retirement occurs.
        let mut guard = unsafe { attached.begin_source_batch(&requests) }.unwrap();
        assert_eq!(guard.totals().unwrap(), zero);
        assert_eq!(guard.totals().unwrap(), zero);
        context.ready(&ready);
        let mut calls: Vec<TreeCallResult> = Vec::with_capacity(CALLS);
        for index in 0..CALLS {
            // SAFETY: consume the next fixed admitted request on the same child.
            // The parent authenticates this exact gate and its own real harness
            // return, and supplies the admitted stack for all eight rounds.
            let result = unsafe { guard.invoke_next() }.unwrap();
            assert_eq!(
                (
                    result.value,
                    result.pre_call_rsp,
                    result.entry_rsp,
                    result.resumed_rsp,
                    result.return_pc,
                    result.gate_sequence,
                    result.external_id,
                ),
                (
                    expected,
                    gate_rsp - 8,
                    root_rsp,
                    gate_rsp - 8,
                    entry + 22,
                    index as u64 + 1,
                    EXTERNAL_ID + index as u64,
                )
            );
            assert_eq!(bytes, &input);
            calls.push(result);
            let roots = index as u64 + 1;
            let expected_totals = TreeTotals {
                roots,
                pairs: PairTotals {
                    entries: 2 * roots,
                    returns: 2 * roots,
                    completed: 2 * roots,
                    unsampled: 0,
                },
            };
            assert_eq!(guard.totals().unwrap(), expected_totals);
            assert_eq!(guard.totals().unwrap(), expected_totals);
            if index + 1 < CALLS {
                checkpoint(index);
            }
        }
        assert_eq!(guard.finish().unwrap().calls(), CALLS);
        assert_eq!(calls.len(), CALLS);
        assert_eq!(attached.totals().unwrap(), totals());
        let batch = attached
            .drain_completed()
            .unwrap()
            .expect("all sixteen physically returned tree rows");
        let pid = std::process::id();
        assert_eq!(batch.pid(), pid);
        assert_eq!(batch.tid(), u64::from(pid));
        assert_eq!(batch.registration(), REGISTRATION);
        assert_eq!(batch.install(), INSTALL);
        assert_eq!(batch.functions(), FUNCTIONS);
        assert_eq!(batch.number(), 1);
        assert_eq!((batch.gate_base(), batch.gate_sequence()), (0, 8));
        assert_eq!(batch.completed_sequences(), (0, 16));
        assert_eq!(batch.totals(), (zero, totals()));
        assert_eq!(batch.rows().len(), 16);
        let mut journal = [0_u64; 512];
        journal[..4].copy_from_slice(&[32, 0, u64::from(pid), 0]);
        for (index, call) in calls.iter().enumerate() {
            for (node, &function) in FUNCTIONS.iter().enumerate() {
                let invocation = 2 * index + node;
                let ordinal = invocation as u64 + 1;
                let row = &batch.rows()[invocation];
                let raw = row.raw();
                let (pc, ret, rsp, word, resumed, value) = if node == 0 {
                    (
                        entry,
                        entry + 22,
                        root_rsp,
                        continuation,
                        gate_rsp - 8,
                        expected,
                    )
                } else {
                    (
                        child_entry,
                        child_entry + 38,
                        root_rsp - 16,
                        entry + 14,
                        root_rsp - 8,
                        expected.wrapping_sub(1),
                    )
                };
                assert_eq!(row.external_id(), call.external_id);
                assert_eq!(row.node(), node as u8);
                assert_eq!(row.parent(), (node == 1).then_some((call.external_id, 0)));
                assert_eq!(row.function(), function);
                assert_eq!(row.depth(), node);
                assert_eq!(row.callsite(), (node == 1).then_some(entry + 9));
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
                assert_eq!(
                    (
                        row.gate_sequence(),
                        row.registration(),
                        row.history_prefix()
                    ),
                    (call.gate_sequence, REGISTRATION, 1)
                );
                assert_eq!(row.model_start_sequence(), Some(2 * index as u64));
                assert_eq!(row.model_completed_children(), Some(u64::from(node == 0)));
                assert_eq!(
                    (raw.ordinal, raw.entry_pc, raw.return_pc),
                    (ordinal, pc, ret)
                );
                assert_eq!(
                    raw.owner,
                    RawIntervalOwner::Sampled {
                        generation,
                        invocation
                    }
                );
                let packed = ordinal | (1 << 13);
                for (offset, kind, event_pc) in [(node, 1, pc), (3 - node, 2, ret)] {
                    let at = 4 + index * 28 + offset * 7;
                    journal[at..at + 7]
                        .copy_from_slice(&[kind, ordinal, event_pc, rsp, word, generation, packed]);
                }
            }
        }
        // Full page equality includes header, all32 seven-word events and every
        // unused word; no selected-only export or journal-byte normalization.
        assert_eq!(batch.journal(), &journal);
        assert!(attached.drain_completed().unwrap().is_none());
        assert_eq!(attached.totals().unwrap(), totals());
        controller.disarm(&epoch).unwrap();
        let report = controller
            .report(&epoch)
            .unwrap()
            .expect("closed exact K8 epoch");
        assert_eq!(report.generation().get(), generation);
        let records: Vec<_> = report.records().collect();
        assert_eq!(records.len(), 16);
        for (invocation, (row, record)) in batch.rows().iter().zip(&records).enumerate() {
            let index = invocation / 2;
            let node = invocation % 2;
            let raw = row.raw();
            let admission = record.record.admission;
            assert_eq!(admission.generation.get(), generation);
            assert_eq!(
                (
                    admission.function,
                    admission.invocation,
                    admission.entry_value
                ),
                (FUNCTIONS[node], invocation, raw.start.ticks)
            );
            // The unchanged model completes with its epoch-local invocation
            // slot; raw end timestamps belong in payload.end, not terminal.value.
            assert_eq!(
                record.record.terminal,
                Some(Terminal::Completed {
                    value: invocation as u64,
                    disposition: Disposition::Retained { rank: index },
                })
            );
            let payload = record.payload.unwrap();
            assert_eq!(payload.admission, admission);
            assert_eq!(
                (payload.thread, payload.start_sequence),
                (REGISTRATION, 2 * index as u64)
            );
            // Same raw-to-model availability contract as the old tree route;
            // this is not an elapsed-time or cross-child TSC comparison.
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
                    completed_children: u64::from(node == 0),
                }
            );
        }
        let history = controller.history().unwrap();
        assert_eq!(history.status, ControllerStatus::Ready);
        assert_eq!(history.current, None);
        assert_eq!(history.enabled, [true, true]);
        assert_eq!(history.retained_failed_generation, None);
        assert_eq!(
            history.actions,
            [
                Action {
                    kind: ActionKind::Published,
                    generation: epoch.generation(),
                    function: None,
                    current: Some(epoch.generation()),
                    group: None,
                },
                Action {
                    kind: ActionKind::Removed,
                    generation: epoch.generation(),
                    function: None,
                    current: None,
                    group: None,
                },
            ]
        );
        let retired = controller.retire(&epoch).unwrap();
        assert_eq!(retired.generation(), report.generation());
        assert_eq!(retired.records().collect::<Vec<_>>(), records);
        drop(retired);
        drop(report);
        assert_eq!(attached.detach().unwrap(), totals());
        assert_eq!(bytes, &input);
        // Normal child exit can occur only after actual finish, full joins,
        // retirement and detach. It is not a separately exported finish token.
    } else {
        let requests = [bytes; CALLS];
        // SAFETY: original source provenance is admitted before initial ready;
        // the same immutable source/input/stack contract holds through finish.
        let mut guard = unsafe { prep.begin_original_source_batch(&requests, &stack) }.unwrap();
        context.ready(&ready);
        for index in 0..CALLS {
            // SAFETY: parent supplies the actual admitted stack and restores
            // this call's own harness only after its real outer C3.
            let result = unsafe { guard.invoke_next() }.unwrap();
            assert_eq!(
                (result.value, result.pre_call_rsp, result.resumed_rsp),
                (expected, gate_rsp - 8, gate_rsp - 8)
            );
            assert_eq!(bytes, &input);
            if index + 1 < CALLS {
                checkpoint(index);
            }
        }
        assert_eq!(guard.finish().unwrap().calls(), CALLS);
        assert_eq!(bytes, &input);
    }
    current_single_main();
}

/// Fixed new-route population. Normal reaps bind the child assertions above;
/// selected traces independently bind full state and original operand semantics.
pub fn run(subject: &Path, expected: &Path, output: &Path) {
    current_single_main();
    let expected_elf = expected_bytes(subject, expected);
    let mut csv = String::from(
        "seed,case,status,children,calls_per_child,full_indices,comparisons,original_visits,original_steps,candidate_steps,selected0_original_steps,selected0_candidate_steps,selected7_original_steps,selected7_candidate_steps,hardware_stops_original,hardware_stops_candidate,tree_transfers,outer_calls,outer_returns,normal_reaps,source_attested_finishes,candidate_rows,candidate_events,candidate_report_records,value\n",
    );
    let mut totals = [0_usize; 12];
    let mut last_deadline = None;
    for seed in STATE_SEEDS {
        let mut observed_returns = BTreeSet::new();
        let mut declared_returns = None;
        for case in call_tree::truth::ALL {
            let oracle = OrdinaryOracle::new_tree(case, seed);
            let deadline = oracle.tree_deadline();
            let mut inspections = Vec::with_capacity(2);
            let result = oracle.pair_tree_batch(
                |candidate, context| child(candidate, context, subject, &expected_elf),
                |index, actual| {
                    assert_eq!(index, SELECTED[inspections.len()]);
                    inspections.push((index, call_tree::inspect(case, seed, actual)));
                },
            );
            assert!(Instant::now() < deadline);
            assert_eq!(inspections.len(), 2);
            assert_eq!(
                result.selected.each_ref().map(|(index, _)| *index),
                SELECTED
            );
            assert_eq!(result.calls, [8, 8]);
            assert_eq!(result.tree_transfers, [24, 24]);
            assert_eq!(result.outer_calls, [8, 8]);
            assert_eq!(result.outer_returns, [8, 8]);
            assert_eq!(result.hardware_stops, [38, 38]);
            assert_eq!(result.normal_reaps, 2);
            assert!((1..=20_000).contains(&result.original_steps));
            assert!((1..=20_000).contains(&result.candidate_steps));
            let mut selected_steps = [0_usize; 2];
            for ((index, selected), (observed_index, stats)) in
                result.selected.iter().zip(&inspections)
            {
                assert_eq!(index, observed_index);
                assert_eq!(selected.visits, 332);
                assert_eq!(selected.comparisons, 343);
                assert!((1..=20_000).contains(&selected.original_steps));
                assert!((1..=20_000).contains(&selected.candidate_steps));
                selected_steps[0] = selected_steps[0]
                    .checked_add(selected.original_steps)
                    .unwrap();
                selected_steps[1] = selected_steps[1]
                    .checked_add(selected.candidate_steps)
                    .unwrap();
                assert_eq!(selected.value, call_tree::truth::scalar(case, seed));
                assert_eq!(selected.returns.len(), 2);
                assert_eq!(selected.returns, selected.declared_returns);
                if let Some(previous) = &declared_returns {
                    assert_eq!(previous, &selected.declared_returns);
                } else {
                    declared_returns = Some(selected.declared_returns.clone());
                }
                observed_returns.extend(selected.returns.iter().copied());
                assert_eq!(stats.counts, call_tree::truth::counts(case));
                assert_eq!(stats.model.accesses, 132);
                assert_eq!(stats.model.hit_by_event.len(), 132);
                assert_eq!(stats.model.hits + stats.model.misses, 132);
                assert_eq!(stats.model.writebacks, 0);
            }
            // Six middle rounds each charge outer CALL, three application
            // transfers and outer RET. CONT instructions are not step counts.
            assert_eq!(
                selected_steps[0].checked_add(30),
                Some(result.original_steps)
            );
            assert_eq!(
                selected_steps[1].checked_add(30),
                Some(result.candidate_steps)
            );
            let comparisons: usize = result.selected.iter().map(|(_, r)| r.comparisons).sum();
            let visits: usize = result.selected.iter().map(|(_, r)| r.visits).sum();
            assert_eq!((comparisons, visits), (686, 664));
            let roots: usize = result.calls.iter().sum();
            let transfers: usize = result.tree_transfers.iter().sum();
            let outer_calls: usize = result.outer_calls.iter().sum();
            let outer_returns: usize = result.outer_returns.iter().sum();
            let stops: usize = result.hardware_stops.iter().sum();
            // These fixed child-join counts are source-attested by both normal
            // exits after finish; the parent has no forged batch-verification API.
            let (finishes, rows, events, records) = (2, 16, 32, 16);
            let a = &result.selected[0].1;
            let z = &result.selected[1].1;
            csv.push_str(&format!(
                "{seed},{},PASS,2,8,0+7,{comparisons},{visits},{},{},{},{},{},{},{},{},{transfers},{outer_calls},{outer_returns},{},{finishes},{rows},{events},{records},{}\n",
                case.name(), result.original_steps, result.candidate_steps,
                a.original_steps, a.candidate_steps, z.original_steps, z.candidate_steps,
                result.hardware_stops[0], result.hardware_stops[1], result.normal_reaps, a.value,
            ));
            let values = [
                1,
                roots,
                2,
                comparisons,
                transfers,
                outer_calls,
                outer_returns,
                stops,
                finishes,
                rows,
                events,
                records,
            ];
            for (total, value) in totals.iter_mut().zip(values) {
                *total = total.checked_add(value).unwrap();
            }
            std::fs::write(output.join("tree-batch-pairs.csv"), &csv).unwrap();
            assert!(Instant::now() < deadline, "batch complete output deadline");
            last_deadline = Some(deadline);
        }
        assert_eq!(
            observed_returns,
            declared_returns.unwrap(),
            "both actual RETs per seed"
        );
    }
    assert_eq!(totals, [4, 64, 8, 2744, 192, 64, 64, 304, 8, 64, 128, 64]);
    current_single_main();
    assert!(
        Instant::now() < last_deadline.unwrap(),
        "batch final output deadline"
    );
    println!(
        "native-tree-batch:required=4:pairs=4:children=8:roots=64:selected-call-pairs=8:comparisons=2744:tree-transfers=192:outer-calls=64:outer-returns=64:hardware-stops=304:source-attested-finishes=8:candidate-rows=64:candidate-events=128:candidate-report-records=64:selected=0+7:middle=functional-only:complete"
    );
    assert!(
        Instant::now() < last_deadline.unwrap(),
        "batch terminal output deadline"
    );
}
