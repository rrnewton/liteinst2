//! Genuine loaded optional frontend, independently traced through its real TLS gate.
use super::{Path, STATE_SEEDS, current_single_main, oracle};
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::*;
use oracle::native_ordinary::optional_frontend::{
    self as native, ChildContext, GATE, Helper, Ready,
};
use rapid_profiler::frontend::{ActionKind, Limits, Observation, PayloadOutcome};
use rapid_profiler::frontend_native::{
    IntegerLeafContract, IntervalJournal, LoadedIntegerLeaf, OptionalIntervalBatch, OptionalPath,
    OptionalSitePreparation, OptionalTotals, PairTotals, PreparedOptionalController,
    RawIntervalOwner, ReadableStack, SiteError,
};
use rapid_profiler::generation::{Config, Disposition, FunctionId, Terminal};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

unsafe extern "C" {
    static __rapid_profiler_optional_call_v1: u8;
}
const CONTRACT: IntegerLeafContract = IntegerLeafContract {
    single_external_entry: true,
    ordinary_ret_only: true,
    no_active_cet: true,
};
const FUNCTION: FunctionId = FunctionId(1);
const INSTALL: u64 = 0x6f70_7401;
fn identity(entry: u64) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([0x6f; 32]),
        mapping: entry,
        generation: 1,
    }
}
fn protect(range: AddressRange, flags: i32) -> Result<(), Refusal> {
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
fn publish(
    prep: OptionalSitePreparation,
) -> rapid_profiler::frontend_native::InstalledOptionalSite {
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
    // SAFETY: the actual child is single-main with exclusive fresh DSO ownership;
    // no signal/foreign entry, saved resume, writer or application pointer escaped.
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
        Ok(v) => v,
        Err(failure) => {
            eprintln!("optional publication FAILED: {failure:?}");
            std::process::abort();
        }
    };
    // SAFETY: full successful transaction and final RX; seal retains every owner.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}
fn report(
    controller: &mut rapid_profiler::frontend_native::OptionalController,
    epoch: &rapid_profiler::frontend_native::IntervalEpoch,
    batch: &OptionalIntervalBatch,
    slow: bool,
) {
    let generation = epoch.generation().get();
    let report = controller.retire(epoch).unwrap();
    assert_eq!(report.generation().get(), generation);
    let records: Vec<_> = report.records().collect();
    assert_eq!(records.len(), usize::from(slow));
    if !slow {
        return;
    }
    let row = batch.rows()[0];
    let admission = records[0].record.admission;
    assert_eq!(admission.generation.get(), generation);
    assert_eq!(admission.function, FUNCTION);
    assert_eq!(admission.invocation, 0);
    assert_eq!(admission.entry_value, row.start.ticks);
    assert_eq!(
        records[0].record.terminal,
        Some(Terminal::Completed {
            value: 0,
            disposition: Disposition::Retained { rank: 0 }
        })
    );
    let payload = records[0].payload.unwrap();
    assert_eq!(payload.admission, admission);
    assert_eq!(payload.thread, 1);
    assert_eq!(payload.start_sequence, 0);
    let end = if row.start.aux != row.end.aux {
        Observation::Unavailable(1)
    } else if row.end.ticks < row.start.ticks {
        Observation::Unavailable(2)
    } else {
        Observation::Value(row.end.ticks)
    };
    assert_eq!(
        payload.outcome,
        PayloadOutcome::Completed {
            end,
            completed_children: 0
        }
    );
}
fn child(
    candidate: bool,
    mut context: ChildContext<'_>,
    subject: &Path,
    expected_elf: &[u8],
    slow: bool,
) {
    current_single_main();
    // SAFETY: independently trusted exact fixed compiler DSO, no constructors,
    // foreign entry/CET/signals/unload/writers. This child's loader precedes calls.
    let owner = unsafe {
        LoadedIntegerLeaf::load(
            subject,
            expected_elf,
            c"ordinary_checksum_nonempty",
            CONTRACT,
        )
    }
    .unwrap();
    let entry = owner.entry();
    let heads = owner.certificate().heads().to_vec();
    let returns = owner.certificate().returns().to_vec();
    let mut prep = OptionalSitePreparation::new(owner, identity(entry)).unwrap();
    let selector = prep.plan().images()[0]
        .precontext_selector()
        .unwrap()
        .clone();
    assert!(
        prep.plan()
            .images()
            .iter()
            .all(|image| image.precontext_selector() == Some(&selector))
    );
    assert!(!selector.is_enabled());
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        std::iter::once(entry)
            .chain(returns.iter().copied())
            .collect::<Vec<_>>()
    );
    let gate = &raw const __rapid_profiler_optional_call_v1 as usize as u64;
    assert_eq!(
        unsafe { std::slice::from_raw_parts(gate as usize as *const u8, GATE.len()) },
        GATE
    );
    assert_eq!(prep.gate().continuation(), gate + 28);
    let original = &prep.plan().plan().originals()[0];
    let original_source = original.bytes.clone();
    let mut immutable = vec![(original.address, original.bytes.clone())];
    let mut boundaries: Vec<_> = heads.iter().map(|p| (*p, *p)).collect();
    let mut observers = Vec::new();
    if candidate {
        let planned = prep.plan();
        assert_eq!(planned.plan().originals().len(), 1);
        assert_eq!(planned.plan().final_bytes().len(), 1);
        let final_source = &planned.plan().final_bytes()[0];
        immutable[0] = (final_source.address, final_source.bytes.clone());
        boundaries.clear();
        for image in planned.images() {
            boundaries.extend_from_slice(image.instruction_boundaries());
            immutable.push((image.address(), image.bytes().to_vec()));
            observers.extend(
                image
                    .precontext_gates()
                    .iter()
                    .map(|g| (g.logical_pc, g.observing_entry)),
            );
        }
        for &pc in &heads {
            if !boundaries.iter().any(|(head, _)| *head == pc) {
                boundaries.push((pc, pc));
            }
        }
        observers.sort_unstable();
    }
    let ready = Ready {
        base: oracle::native_ordinary::Ready {
            profile: oracle::native_ordinary::Profile::Legacy,
            entry,
            gate,
            continuation: prep.gate().continuation(),
            heads,
            returns,
            boundaries,
            immutable,
            original_source,
        },
        observers,
    };
    let data = context.input().as_ptr();
    let length = context.input().len();
    let expected = context
        .input()
        .iter()
        .map(|b| u64::from(b ^ 0x5a))
        .sum::<u64>()
        ^ 0x9e37_79b9_7f4a_7c15;
    let gate_rsp = context.gate_rsp();
    let (start, end) = context.stack_range();
    // SAFETY: inherited mapped guard-bounded stack; ptrace seeds only the actual
    // privately armed invocation and restores its own harness after comparison.
    let stack = unsafe { ReadableStack::new(start, end) }.unwrap();
    if candidate {
        let site = publish(prep);
        let mut prepared = PreparedOptionalController::new(
            site,
            INSTALL,
            FUNCTION,
            Limits {
                epochs: 1,
                threads: 1,
                depth: 1,
                records_per_epoch: 1,
                actions: 2,
            },
        )
        .unwrap();
        let epoch = prepared
            .stage(Config {
                retained_per_function: 1,
                max_inflight: 1,
                max_invocations: 1,
            })
            .unwrap();
        let generation = epoch.generation().get();
        let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
        if slow {
            controller.arm(&epoch).unwrap();
        }
        let initial = controller.history().unwrap();
        assert_eq!(initial.enabled, [slow]);
        assert_eq!(selector.is_enabled(), slow);
        assert_eq!(
            initial.current.map(|g| g.get()),
            if slow { Some(generation) } else { None }
        );
        let mut attached = unsafe { client.attach(1, stack, IntervalJournal::allocate()) }.unwrap();
        let helper = context.controller(move |io: Helper<OptionalIntervalBatch>| {
            let batch = io.transition(slow, || {
                if slow {
                    controller.disarm(&epoch).unwrap();
                    assert!(controller.report(&epoch).unwrap().is_none());
                    let error = match controller.retire(&epoch) {
                        Err(error) => error,
                        Ok(_) => panic!("in-flight epoch retired"),
                    };
                    assert_eq!(format!("{error:?}"), "BridgeError { cause: NotDrained }");
                } else {
                    controller.arm(&epoch).unwrap();
                }
                let snapshot = controller.history().unwrap();
                // Removed closes admission without changing historical group state.
                // Authenticate the actual retained selector separately from history.
                assert_eq!(snapshot.enabled, [true]);
                assert_eq!(
                    snapshot.current.map(|g| g.get()),
                    if slow { None } else { Some(generation) }
                );
                let enabled = selector.is_enabled();
                assert_eq!(enabled, !slow);
                enabled
            });
            // This message exists only after actual invoke/drain/detach. Keeping
            // the controller alive until then prevents premature binding poison.
            if !slow {
                controller.disarm(&epoch).unwrap();
            }
            assert!(!selector.is_enabled());
            report(&mut controller, &epoch, &batch, slow);
            let history = controller.history().unwrap();
            assert_eq!(history.actions.len(), 2);
            assert!(history.current.is_none());
            assert_eq!(
                history.actions.iter().map(|a| a.kind).collect::<Vec<_>>(),
                [ActionKind::Published, ActionKind::Removed]
            );
            assert!(
                history
                    .actions
                    .iter()
                    .all(|a| a.generation.get() == generation)
            );
        });
        context.ready(&ready);
        let result =
            unsafe { attached.invoke_integer_leaf(std::slice::from_raw_parts(data, length)) }
                .unwrap();
        assert_eq!(result.value, expected);
        assert_eq!((result.physical, result.gate_sequence), (1, 1));
        assert_eq!(
            (result.pre_call_rsp, result.entry_rsp, result.resumed_rsp),
            (gate_rsp - 8, gate_rsp - 16, gate_rsp - 8)
        );
        assert!(ready.returns.contains(&result.return_pc));
        assert_eq!(
            result.path,
            if slow {
                OptionalPath::Slow { ordinal: 1 }
            } else {
                OptionalPath::FastBypass
            }
        );
        let totals = OptionalTotals {
            physical: 1,
            bypassed: u64::from(!slow),
            observed: PairTotals {
                entries: u64::from(slow),
                returns: u64::from(slow),
                completed: u64::from(slow),
                unsampled: 0,
            },
        };
        assert_eq!(attached.totals().unwrap(), totals);
        let batch = attached.drain_completed().unwrap().unwrap();
        assert_eq!(
            (
                batch.pid(),
                batch.tid(),
                batch.registration(),
                batch.install(),
                batch.function()
            ),
            (
                std::process::id(),
                u64::from(std::process::id()),
                1,
                INSTALL,
                FUNCTION
            )
        );
        assert_eq!(
            (
                batch.number(),
                batch.gate_base(),
                batch.gate_sequence(),
                batch.next_ordinal()
            ),
            (1, 0, 1, 1 + u64::from(slow))
        );
        assert_eq!(batch.totals(), (OptionalTotals::default(), totals));
        assert_eq!(batch.physical_range(), 0..1);
        assert_eq!(batch.raw_range(), 0..u64::from(slow));
        assert_eq!(batch.event_range(), 0..2 * u64::from(slow));
        assert_eq!(batch.completed_sequences(), (0, u64::from(slow)));
        assert_eq!(batch.rows().len(), usize::from(slow));
        assert_eq!(
            batch.observed_gate_sequences(),
            if slow { &[1][..] } else { &[] }
        );
        let mut page = [0_u64; 512];
        page[..4].copy_from_slice(&[2 * u64::from(slow), 0, u64::from(std::process::id()), 0]);
        if slow {
            let row = batch.rows()[0];
            assert_eq!(row.ordinal, 1);
            assert_eq!(row.entry_pc, entry);
            assert_eq!(row.return_pc, result.return_pc);
            assert_eq!(
                row.owner,
                RawIntervalOwner::Sampled {
                    generation,
                    invocation: 0
                }
            );
            page[4..11].copy_from_slice(&[
                1,
                1,
                entry,
                result.entry_rsp,
                ready.continuation,
                generation,
                0x2001,
            ]);
            page[11..18].copy_from_slice(&[
                2,
                1,
                result.return_pc,
                result.entry_rsp,
                ready.continuation,
                generation,
                0x2001,
            ]);
        }
        assert_eq!(batch.journal(), page);
        assert!(attached.drain_completed().unwrap().is_none());
        assert_eq!(attached.detach().unwrap(), totals);
        helper.finish(batch);
    } else {
        let call = unsafe { prep.prepare_original_call() }.unwrap();
        context.ready(&ready);
        let result = unsafe { call.invoke(data, length, &stack) }.unwrap();
        assert_eq!(result.value, expected);
        assert_eq!(
            (result.pre_call_rsp, result.resumed_rsp),
            (gate_rsp - 8, gate_rsp - 8)
        );
    }
    // Real group exit/reap, not an instantaneous task-census inference after join.
}

pub fn run(subject: &Path, expected: &Path, output: &Path, slow: bool) {
    current_single_main();
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
    let mut expected_elf = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut expected_elf)
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
    assert_eq!(expected_elf.len() as u64, before.len());
    drop(file);
    let mut csv = String::from(
        "seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value,observer_entries,helper_joins\n",
    );
    let mut comparisons = 0;
    for seed in STATE_SEEDS {
        let mut observed = BTreeSet::new();
        let mut declared = None;
        for length in [1, 64] {
            let result = native::pair(seed, length, slow, |candidate, context| {
                child(candidate, context, subject, &expected_elf, slow)
            });
            if let Some(previous) = &declared {
                assert_eq!(previous, &result.declared_returns);
            } else {
                declared = Some(result.declared_returns.clone());
            }
            observed.extend(result.returns);
            comparisons += result.comparisons;
            csv.push_str(&format!(
                "{seed},{length},PASS,2,{},{},{},{},{},{},1\n",
                result.comparisons,
                result.visits,
                result.original_steps,
                result.candidate_steps,
                result.value,
                if slow { 2 } else { 0 }
            ));
            std::fs::write(output.join("optional-pairs.csv"), &csv).unwrap();
        }
        assert_eq!(
            observed,
            declared.unwrap(),
            "actual RET union for each seed/mode"
        );
    }
    let negative =
        unsafe { LoadedIntegerLeaf::load(subject, &expected_elf, c"ordinary_checksum", CONTRACT) }
            .unwrap();
    assert!(
        negative
            .certificate()
            .returns()
            .iter()
            .any(|&ret| negative.certificate().blocks().contains(&(ret, ret + 1)))
    );
    let entry = negative.entry();
    assert!(matches!(
        OptionalSitePreparation::new(negative, identity(entry)),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));
    std::fs::write(
        output.join("optional-refusals.csv"),
        "case,status,reason\nempty_capable_symbol,PASS,NoPatchWindow\n",
    )
    .unwrap();
    current_single_main();
    let mode = if slow { "slow" } else { "fast" };
    let observers = if slow { 8 } else { 0 };
    println!(
        "native-optional-{mode}:required=4:pairs=4:children=8:comparisons={comparisons}:observer-entries={observers}:controller-transitions=4:helper-joins=4:short-ret-refusals=1:real-outer-ret=8:complete"
    );
}
