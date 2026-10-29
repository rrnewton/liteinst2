//! Ordinary compiled C callers, with no per-call SDK invoke or CALL-gate frame.
use super::{Path, current_single_main, oracle};
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::*;
use native::caller_bytes;
use oracle::native_ordinary::normal_caller::{
    self as native, ControlStatus, JournalReady, Mode, NormalContext, NormalOracle, NormalReady,
    Population,
};
// Preserve the native target's existing test-only fixture registrations.
// Its production reference route keeps the canonical oracle geometry alias.
macro_rules! register_reference_fixture {
    () => {
        #[cfg(test)]
        #[path = "reference_owner.rs"]
        pub mod reference;
        #[cfg(test)]
        #[path = "reference_bytes.rs"]
        pub mod reference_bytes;
    };
}
#[path = "../normal-work/caller.rs"]
mod caller;
use caller::CallerOwner;
use caller_bytes::Request;
mod check;
pub(super) mod csv;
pub(super) mod exact;
pub(super) mod reference;
use check::{Facts, rows_match};
use oracle::native_ordinary::strnlen::{Arguments, CASES, Deadline, LABEL, SEEDS, cases};
use rapid_profiler::frontend::{
    ActionKind, ControllerSnapshot, ControllerStatus, Limits, Observation, PayloadOutcome, Report,
};
use rapid_profiler::frontend_native::{
    InstalledNormalSite, IntervalJournal, LoadedNormalLeaf, NormalBatch, NormalLeafContract,
    NormalRecord, NormalSitePreparation, NormalTotals, PreparedNormalController, RawIntervalOwner,
    ReadableStack, TrustedFunctionSelection,
};
use rapid_profiler::generation::{Config, Disposition, FunctionId, Terminal};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

const INSTALL: u64 = 0x6e6f_7201;
const FUNCTION: FunctionId = FunctionId(1);
const CONTRACT: NormalLeafContract = NormalLeafContract {
    single_external_entry: true,
    ordinary_call_ret_only: true,
    no_active_cet: true,
};
const HEADER: &str = "mode,seed,case,bound,status,children,comparisons,visits0,visits1,original_steps,candidate_steps,value0,value1,outer_value,input_reads0,input_reads1,input_bytes0,input_bytes1,ret_offset0,ret_offset1,target_calls,target_returns,outer_returns,normal_reaps,helper_joins\n";

fn protect(range: AddressRange, flags: i32) -> Result<(), Refusal> {
    // SAFETY: fresh child-private complete source mapping, no active caller.
    if unsafe {
        libc::mprotect(
            range.start() as usize as *mut _,
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
fn publish(prep: NormalSitePreparation) -> InstalledNormalSite {
    current_single_main();
    let planned = prep.plan();
    assert_eq!(planned.plan().originals().len(), 1);
    let original = &planned.plan().originals()[0];
    let source = AddressRange::new(original.address, original.bytes.len()).unwrap();
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
    // SAFETY: complete exclusive preparation, no subject entry/saved resume,
    // signal, source writer or unload. This real lease covers every allocation.
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
            eprintln!("normal caller publication FAILED: {failure:?}");
            std::process::abort(); // Never unwind partially published owners.
        }
    };
    // SAFETY: exact successful transaction and final RX; all owners stay retained.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

fn totals(confirmed: u64) -> NormalTotals {
    NormalTotals {
        entered: 2,
        ret_observed: 2,
        confirmed,
        completed: confirmed,
        unsampled: 0,
    }
}
fn history(snapshot: &ControllerSnapshot, generations: &[u64], removed: bool) {
    assert_eq!(snapshot.status, ControllerStatus::Ready);
    assert_eq!(snapshot.retained_failed_generation, None);
    assert_eq!(snapshot.enabled, [true]); // Historical mandatory group metadata.
    let mut expected = vec![(ActionKind::Published, generations[0], Some(generations[0]))];
    if generations.len() == 2 {
        expected.push((ActionKind::Removed, generations[0], None));
        expected.push((ActionKind::Published, generations[1], Some(generations[1])));
    }
    if removed {
        expected.push((ActionKind::Removed, *generations.last().unwrap(), None));
    }
    assert_eq!(
        snapshot.current.map(|g| g.get()),
        if removed {
            None
        } else {
            generations.last().copied()
        }
    );
    assert_eq!(snapshot.actions.len(), expected.len());
    for (action, (kind, generation, current)) in snapshot.actions.iter().zip(expected) {
        assert_eq!(
            (
                action.kind,
                action.generation.get(),
                action.current.map(|g| g.get()),
                action.function,
                action.group
            ),
            (kind, generation, current, None, None)
        );
    }
}
fn batch(batch: &NormalBatch, facts: &Facts<'_>) {
    assert_eq!(
        (
            batch.pid(),
            batch.tid(),
            batch.registration(),
            batch.install(),
            batch.function()
        ),
        (std::process::id(), facts.tid, 1, INSTALL, FUNCTION)
    );
    assert_eq!(
        (
            batch.number(),
            batch.next_ordinal(),
            batch.completed_sequences()
        ),
        (1, 3, (0, 2))
    );
    assert_eq!(batch.totals(), (NormalTotals::default(), totals(2)));
    assert!(rows_match(batch.records(), batch.journal(), facts));
}
fn report(report: &Report, rows: &[NormalRecord], indices: &[usize], crossed: bool) {
    let records: Vec<_> = report.records().collect();
    assert_eq!(records.len(), indices.len());
    for (record, &index) in records.iter().zip(indices) {
        let row = rows[index].raw;
        let invocation = if crossed { 0 } else { index };
        let generation = match row.owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation: actual,
            } => {
                assert_eq!(actual, invocation);
                generation
            }
            _ => panic!("both normal-state invocations must be sampled"),
        };
        assert_eq!(report.generation().get(), generation);
        let admission = record.record.admission;
        assert_eq!(
            (
                admission.generation.get(),
                admission.function,
                admission.invocation,
                admission.entry_value
            ),
            (generation, FUNCTION, invocation, row.start.ticks)
        );
        assert_eq!(
            record.record.terminal,
            Some(Terminal::Completed {
                value: invocation as u64,
                disposition: Disposition::Retained { rank: invocation }
            })
        );
        let payload = record.payload.unwrap();
        assert_eq!(payload.admission, admission);
        assert_eq!((payload.thread, payload.start_sequence), (1, index as u64));
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
}
fn check_live(immutable: &[(u64, Vec<u8>)]) {
    for (address, bytes) in immutable {
        // SAFETY: retained process-lived readable source/images under continuous
        // no-writer/no-unmap custody; this consumer scan precedes checkpoint.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(*address as usize as *const u8, bytes.len()) },
            bytes
        );
    }
}

fn child(
    candidate: bool,
    context: NormalContext<'_>,
    subject: &Path,
    selection: &TrustedFunctionSelection<'_>,
    caller_path: &Path,
    caller_elf: &[u8],
    mode: Mode,
) -> i32 {
    child_with(
        candidate,
        context,
        subject,
        selection,
        caller_path,
        caller_elf,
        reference::Profile::Legacy(mode),
    )
}
fn child_with(
    candidate: bool,
    mut context: NormalContext<'_>,
    subject: &Path,
    selection: &TrustedFunctionSelection<'_>,
    caller_path: &Path,
    caller_elf: &[u8],
    profile: reference::Profile,
) -> i32 {
    let mode = profile.mode();
    current_single_main();
    context.deadline().check();
    let crossed = mode == Mode::CrossedOwner;
    let csv_case = context.csv_case();
    let exact_case = context.exact_case();
    let (bound, expected) = if let Some(case) = csv_case {
        assert_eq!(mode, Mode::Stable);
        assert_eq!(context.input(), case.input());
        assert_eq!(selection.label(), native::csv::LABEL);
        (case.length(), case.expected())
    } else if let Some(case) = exact_case {
        assert_eq!(mode, Mode::Stable);
        assert_eq!(context.input(), case.input());
        assert_eq!(selection.label(), profile.exact_label());
        (case.length(), case.scalar())
    } else {
        let case = context.case();
        let input = cases::input(case);
        assert_eq!(context.input(), input);
        assert_eq!(selection.label(), LABEL);
        (case.bound, cases::scalar(case))
    };
    // SAFETY: independently pinned complete final admitted scalar ELF and compiler
    // helper; no constructors, foreign caller, active CET, signals, alias writer,
    // unload or nonlocal exit. Both real C calls obey the separate normal ABI.
    let owner = unsafe { LoadedNormalLeaf::load_selected(subject, selection, CONTRACT) }.unwrap();
    let mut caller =
        unsafe { reference::Helper::load(profile, &mut context, caller_path, caller_elf) };
    let entry = owner.entry();
    let heads = owner.certificate().heads().to_vec();
    let returns = owner.certificate().returns().to_vec();
    if exact_case.is_some() {
        super::ordinary::exact_body::source(owner.code(), entry, &heads, &returns);
    }
    let source = (owner.source_range().0, owner.original_source().to_vec());
    let original_source = source.1.clone();
    let caller_source = caller.source();
    let caller_immutable = vec![(caller_source.0, caller_source.1.to_vec())];
    let mut ready = NormalReady {
        caller: caller.entry(),
        caller_immutable,
        entry,
        heads: heads.clone(),
        returns: returns.clone(),
        boundaries: heads.iter().map(|p| (*p, *p)).collect(),
        immutable: vec![source],
        original_source,
        journal: None,
    };
    let data_address = context.data_address();
    assert_eq!(context.data_len(), 4096);
    assert_eq!(context.input().as_ptr() as usize as u64, data_address + 128);
    assert_eq!(context.requests_address(), data_address + 256);
    assert_eq!(context.results_address(), data_address + 320);
    // SAFETY: inherited page has exactly these disjoint initialized Request and
    // output slots, held through both actual returns; only C writes outputs.
    let requests = unsafe { &*(context.requests_address() as usize as *const [Request; 2]) };
    for request in requests {
        assert_eq!(
            (request.data as usize as u64, request.bound),
            (data_address + 128, bound as u64)
        );
    }
    let results_address = context.results_address();
    assert_eq!(
        unsafe { (results_address as usize as *const [u64; 2]).read() },
        [0, 0]
    );
    let mut expected_data =
        unsafe { std::slice::from_raw_parts(data_address as usize as *const u8, 4096) }.to_vec();
    expected_data[320..328].copy_from_slice(&expected.to_le_bytes());
    expected_data[328..336].copy_from_slice(&expected.to_le_bytes());
    let caller_rsp = context.caller_rsp();
    let deadline = context.deadline();
    if candidate {
        let prep = if csv_case.is_some() {
            NormalSitePreparation::new_certified_blocks(
                owner,
                CodeIdentity {
                    source: SourceIdentity([0x6f; 32]),
                    mapping: entry,
                    generation: 1,
                },
            )
        } else {
            NormalSitePreparation::new_whole_function(
                owner,
                CodeIdentity {
                    source: SourceIdentity([0x6f; 32]),
                    mapping: entry,
                    generation: 1,
                },
            )
        }
        .unwrap();
        assert_eq!(
            prep.role_pcs().collect::<Vec<_>>(),
            std::iter::once(entry)
                .chain(returns.iter().copied())
                .collect::<Vec<_>>()
        );
        let planned = prep.plan();
        assert_eq!(planned.plan().originals().len(), 1);
        assert_eq!(planned.plan().final_bytes().len(), 1);
        let final_source = &planned.plan().final_bytes()[0];
        assert_eq!(final_source.address, ready.immutable[0].0);
        ready.immutable[0] = (final_source.address, final_source.bytes.clone());
        ready.boundaries.clear();
        for image in planned.images() {
            ready
                .boundaries
                .extend_from_slice(image.instruction_boundaries());
            ready
                .immutable
                .push((image.address(), image.bytes().to_vec()));
        }
        for &pc in &heads {
            if !ready.boundaries.iter().any(|(head, _)| *head == pc) {
                ready.boundaries.push((pc, pc));
            }
        }
        let site = publish(prep);
        let mut prepared = PreparedNormalController::new(
            site,
            INSTALL,
            FUNCTION,
            Limits {
                epochs: if crossed { 2 } else { 1 },
                threads: 1,
                depth: 1,
                records_per_epoch: 2,
                actions: if crossed { 4 } else { 2 },
            },
        )
        .unwrap();
        let config = Config {
            retained_per_function: if crossed { 1 } else { 2 },
            max_inflight: 1,
            max_invocations: if crossed { 1 } else { 2 },
        };
        let a = prepared.stage(config).unwrap();
        let b = crossed.then(|| prepared.stage(config).unwrap());
        let generations = [
            a.generation().get(),
            b.as_ref()
                .map_or(a.generation().get(), |b| b.generation().get()),
        ];
        // SAFETY: same actual child after real publication. Crossed mode has one
        // independent controller thread, no callback-dependent lock or reentry.
        let (mut controller, client) = unsafe {
            if crossed {
                prepared.activate_concurrent()
            } else {
                prepared.activate()
            }
        }
        .unwrap();
        controller.arm(&a).unwrap();
        let (start, end) = context.stack_range();
        let stack = unsafe { ReadableStack::new(start, end) }.unwrap();
        let journal = IntervalJournal::allocate();
        let address = journal.address();
        // Register before starting any controller helper. No registry/admission race.
        let mut attached = unsafe { client.attach(1, stack, journal) }.unwrap();
        assert_eq!(attached.totals().unwrap(), NormalTotals::default());
        let mut local = Some((controller, a, b, None));
        let mut helper = None;
        let mut helper_tid = None;
        if crossed {
            let mut io = context
                .take_control()
                .expect("crossed candidate control pipes");
            let (mut controller, a, b, _) = local.take().unwrap();
            let b = b.unwrap();
            let (sent, received) = std::sync::mpsc::sync_channel(1);
            helper = Some(std::thread::spawn(move || {
                let actual_tid = unsafe { libc::syscall(libc::SYS_gettid) };
                assert!(actual_tid > 0 && actual_tid <= libc::c_long::from(i32::MAX));
                let tid = actual_tid as u64;
                assert_ne!(tid, u64::from(std::process::id()));
                sent.send(tid).unwrap();
                assert_eq!(io.receive(), 1);
                controller.disarm(&a).unwrap();
                assert!(controller.report(&a).unwrap().is_none());
                controller.arm(&b).unwrap();
                assert!(controller.report(&b).unwrap().is_none());
                let snapshot = controller.history().unwrap();
                history(&snapshot, &generations, false);
                io.acknowledge(
                    1,
                    ControlStatus {
                        helper_tid: tid,
                        a_generation: generations[0],
                        b_generation: generations[1],
                        a_ready: false,
                        b_ready: false,
                        history_len: 3,
                        current: generations[1],
                    },
                );
                assert_eq!(io.receive(), 2);
                let a_report = controller
                    .report(&a)
                    .unwrap()
                    .expect("A completed only at second real entry");
                assert!(controller.report(&b).unwrap().is_none());
                let snapshot = controller.history().unwrap();
                history(&snapshot, &generations, false);
                io.acknowledge(
                    2,
                    ControlStatus {
                        helper_tid: tid,
                        a_generation: generations[0],
                        b_generation: generations[1],
                        a_ready: true,
                        b_ready: false,
                        history_len: 3,
                        current: generations[1],
                    },
                );
                (controller, a, Some(b), Some(a_report))
            }));
            helper_tid = Some(received.recv_timeout(Duration::from_secs(2)).unwrap());
            deadline.check();
        } else {
            assert!(context.take_control().is_none());
        }
        ready.journal = Some(JournalReady {
            address,
            a_generation: generations[0],
            b_generation: crossed.then_some(generations[1]),
            helper_tid,
        });
        caller.verify().unwrap();
        check_live(&ready.immutable);
        deadline.check();
        caller.ready(context, &ready);
        // SAFETY: real application C CALLs, no SDK invocation/RBX scratch. The
        // tracer seeds only the actual helper entry and restores its real harness
        // after complete comparisons and the independently checked callee saves.
        let (sum, values) = {
            let results = unsafe { &mut *(results_address as usize as *mut [u64; 2]) };
            let sum = unsafe { caller.invoke(entry, requests, results) };
            (sum, *results)
        }; // End the output's unique borrow before reading the complete data page.
        assert_eq!(
            (sum, values),
            (expected.wrapping_add(expected), [expected, expected])
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(data_address as usize as *const u8, 4096) },
            expected_data
        );
        caller.verify().unwrap();
        check_live(&ready.immutable);
        caller.postflight(caller_rsp, expected);
        deadline.check();
        if let Some(join) = helper {
            local = Some(join.join().expect("actual controller helper join"));
        }
        current_single_main();
        deadline.check();
        let (mut controller, a, b, a_report) = local.unwrap();
        assert_eq!(attached.totals().unwrap(), totals(1));
        assert!(
            controller
                .report(b.as_ref().unwrap_or(&a))
                .unwrap()
                .is_none()
        );
        // SAFETY: both physical target returns and the actual outer caller return
        // preceded all complete consumer checks above; no callback/reentry active.
        let completed = unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .unwrap();
        let facts = Facts {
            entry,
            returns: &returns,
            caller: ready.caller,
            caller_rsp,
            generations,
            crossed,
            tid: u64::from(std::process::id()),
        };
        if csv_case.is_some() {
            assert!(completed.history_stream().is_none());
            assert!(completed.history_high_water().is_none());
        }
        caller.batch(&completed, &facts);
        assert_eq!(attached.totals().unwrap(), totals(2));
        assert!(
            unsafe { attached.checkpoint_after_returns() }
                .unwrap()
                .is_none()
        );
        if let Some(b) = b {
            report(a_report.as_ref().unwrap(), completed.records(), &[0], true);
            controller.disarm(&b).unwrap();
            let retired_a = controller.retire(&a).unwrap();
            let retired_b = controller.retire(&b).unwrap();
            report(&retired_a, completed.records(), &[0], true);
            report(&retired_b, completed.records(), &[1], true);
            history(&controller.history().unwrap(), &generations, true);
            drop((a_report, retired_a, retired_b));
        } else {
            assert!(a_report.is_none());
            controller.disarm(&a).unwrap();
            let retired = controller.retire(&a).unwrap();
            report(&retired, completed.records(), &[0, 1], false);
            history(&controller.history().unwrap(), &generations[..1], true);
            drop(retired);
        }
        assert_eq!(attached.detach().unwrap(), totals(2));
    } else {
        assert!(context.take_control().is_none());
        owner.verify_original().unwrap();
        caller.verify().unwrap();
        deadline.check();
        caller.ready(context, &ready);
        // SAFETY: same true original C caller/target ABI and inherited live data.
        let (sum, values) = {
            let results = unsafe { &mut *(results_address as usize as *mut [u64; 2]) };
            let sum = unsafe { caller.invoke(entry, requests, results) };
            (sum, *results)
        };
        assert_eq!(
            (sum, values),
            (expected.wrapping_add(expected), [expected, expected])
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(data_address as usize as *const u8, 4096) },
            expected_data
        );
        owner.verify_original().unwrap();
        caller.verify().unwrap();
        check_live(&ready.immutable);
        caller.postflight(caller_rsp, expected);
    }
    caller.finish();
    current_single_main();
    deadline.check();
    0
}

fn trusted(candidate: &Path, expected: &Path) -> Vec<u8> {
    let mut file = File::open(expected).unwrap();
    let before = file.metadata().unwrap();
    let other = std::fs::metadata(candidate).unwrap();
    assert!(before.is_file() && other.is_file());
    assert_ne!(
        (before.dev(), before.ino()),
        (other.dev(), other.ino()),
        "independent whole trusted ELF"
    );
    assert!((1..=1024 * 1024).contains(&before.len()));
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
    let mut bytes = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(stamp(&before), stamp(&file.metadata().unwrap()));
    assert_eq!(bytes.len() as u64, before.len());
    bytes
}
pub fn run(
    subject: &Path,
    expected: &Path,
    arguments: Arguments,
    caller_path: &Path,
    caller_expected: &Path,
    output: &Path,
    mut deadline: Deadline,
) {
    deadline.check();
    current_single_main();
    let elf = trusted(subject, expected);
    let caller_elf = trusted(caller_path, caller_expected);
    let selection =
        TrustedFunctionSelection::new(&elf, arguments.elf_va, arguments.length, LABEL).unwrap();
    let mut population = Population::default();
    let mut csv = String::from(HEADER);
    let mut count = 0;
    let (mut comparisons, mut input_reads, mut input_bytes) = (0, 0, 0);
    let mut crossed_totals = None;
    for (mode, seed, case) in SEEDS
        .into_iter()
        .flat_map(|seed| {
            CASES
                .into_iter()
                .map(move |case| (Mode::Stable, seed, case))
        })
        .chain(std::iter::once((Mode::CrossedOwner, SEEDS[0], CASES[7])))
    {
        if count != 0 {
            deadline = Deadline::start();
        }
        let oracle = NormalOracle::new(seed, case, arguments.length, deadline, mode);
        let (pair, trace) = oracle.pair(|candidate, context| {
            child(
                candidate,
                context,
                subject,
                &selection,
                caller_path,
                &caller_elf,
                mode,
            )
        });
        assert_eq!(
            (
                pair.target_calls,
                pair.target_returns,
                pair.outer_returns,
                pair.normal_reaps
            ),
            (4, 4, 2, 2)
        );
        assert_eq!(pair.values, [case.expected, case.expected]);
        assert_eq!(pair.outer_value, case.expected.wrapping_add(case.expected));
        if mode == Mode::Stable {
            population.record(seed, case, &pair, &trace);
        } else {
            assert_eq!((seed, case), (SEEDS[0], CASES[7]));
        }
        let a = &trace.bodies[0];
        let b = &trace.bodies[1];
        comparisons += pair.comparisons;
        input_reads += a.input_reads + b.input_reads;
        input_bytes += a.input_bytes + b.input_bytes;
        if mode == Mode::CrossedOwner {
            assert!(
                crossed_totals
                    .replace((
                        pair.comparisons,
                        a.input_reads + b.input_reads,
                        a.input_bytes + b.input_bytes
                    ))
                    .is_none()
            );
        }
        let mode_name = if mode == Mode::Stable {
            "stable"
        } else {
            "crossed-owner"
        };
        csv.push_str(&format!("{mode_name},{seed},{},{},PASS,2,{},{},{},{},{},{},{},{},{},{},{},{},{},{},4,4,2,2,{}\n",
            case.name,case.bound,pair.comparisons,pair.visits[0],pair.visits[1],pair.original_steps,pair.candidate_steps,
            pair.values[0],pair.values[1],pair.outer_value,a.input_reads,b.input_reads,a.input_bytes,b.input_bytes,
            a.ret_offset,b.ret_offset,usize::from(mode==Mode::CrossedOwner)));
        std::fs::write(output.join("normal-pairs.csv"), &csv).unwrap();
        drop(oracle);
        deadline.check();
        count += 1;
    }
    assert_eq!(count, 17);
    let stable = population.finish();
    let crossed = crossed_totals.unwrap();
    assert_eq!(
        (comparisons, input_reads, input_bytes),
        (
            stable.comparisons + crossed.0,
            stable.input_reads + crossed.1,
            stable.input_bytes + crossed.2
        )
    );
    current_single_main();
    deadline.check();
    let mut out = std::io::stdout().lock();
    writeln!(out,"native-normal:selection={LABEL}:stable-required=16:stable-pairs=16:crossed-owner-pairs=1:pairs=17:children=34:comparisons={comparisons}:input-reads={input_reads}:input-bytes={input_bytes}:coverage-seeds=2:target-calls=68:target-returns=68:real-outer-ret=34:helper-joins=1:complete").unwrap();
    out.flush().unwrap();
    deadline.check();
}
