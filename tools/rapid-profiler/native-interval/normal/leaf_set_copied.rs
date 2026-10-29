//! Exact copied application caller with the actual opt-in LeafSet E3 SDK route.
use super::rust_invoke_artifact::Artifact;
use super::*;
use native::leaf_set_copied::{self as leaf, Case, Population, Ready, Selection};
use native::module::Function;
use rapid_profiler::frontend_native::{
    InstalledNormalLeafSetSite, LoadedNormalLeafSet, NormalLeafSetHistoryBatch,
    NormalLeafSetHistoryStream, NormalLeafSetSessionController, NormalLeafSetSitePreparation,
    NormalModuleContract, NormalModulePreparationPolicy, NormalModuleRoleKind,
    PreparedNormalLeafSetSessionController,
};
mod check;
use check::{INSTALL, identity};
const CONTRACT: NormalModuleContract = NormalModuleContract {
    single_external_entry_per_function: true,
    sequential_call_ret_only: true,
    no_active_cet: true,
};
#[inline(never)]
unsafe fn machine_call(entry: u64, target: u64, input: *const u8, bound: usize, output: *mut u64) {
    // SAFETY: the independently admitted four-origin machine ABI and exact RX
    // artifact copy remain live. This is not a Rust-ABI or whole-process claim.
    let call: unsafe extern "C" fn(u64, *const u8, usize, *mut u64) =
        unsafe { std::mem::transmute(entry as usize) };
    unsafe { call(target, input, bound, output) };
    std::hint::black_box(unsafe { output.read_volatile() });
}
fn publish(prep: NormalLeafSetSitePreparation) -> InstalledNormalLeafSetSite {
    current_single_main();
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert!((1..=2).contains(&originals.len()));
    let sources: Vec<_> = originals
        .iter()
        .map(|s| {
            let range = AddressRange::new(s.address, s.bytes.len()).unwrap();
            assert_eq!(range.start() % 4096, 0);
            assert_eq!(range.len(), 4096);
            range
        })
        .collect();
    assert!(
        sources
            .windows(2)
            .all(|w| w[0].start() + 4096 <= w[1].start())
    );
    let mut ranges = sources.clone();
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = &prep;
    let aliases: Vec<_> = sources
        .iter()
        .map(|&source| {
            protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: exact complete child-private page, one thread, no saved resume.
            unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap()
        })
        .collect();
    let result = {
        let mut lease =
            unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
        let result = unsafe {
            planned.publish_with(&aliases, &mut lease, || {
                for &source in &sources {
                    protect(source, libc::PROT_READ | libc::PROT_EXEC)?;
                }
                Ok(())
            })
        };
        if result.is_ok() {
            assert!(!lease.is_poisoned());
        }
        result
    };
    let (installed, receipt) = match result {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("native LeafSet publication FAILED: {error:?}");
            std::process::abort();
        }
    };
    // SAFETY: full union transaction, all source pages RX and every owner retained.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}
fn stream(s: &NormalLeafSetHistoryStream) -> check::Stream {
    check::Stream {
        pid: s.pid(),
        install: s.install(),
        identity: s.identity(),
        functions: s.functions().to_vec(),
        entries: s.entries().to_vec(),
        format: s.format(),
    }
}
fn chunk(c: &NormalLeafSetHistoryBatch) -> check::Chunk {
    check::Chunk {
        number: c.number(),
        range: c.range(),
        before: c.before(),
        after: c.after(),
        actions: c.actions().to_vec(),
    }
}
fn closed_history(
    controller: &NormalLeafSetSessionController,
    ready: &Ready,
    removed: &NormalLeafSetHistoryBatch,
) {
    let w = controller.history_window().unwrap();
    assert_eq!(w.stream(), removed.stream());
    check::stream(ready, std::process::id(), &stream(w.stream()));
    check::closed(
        removed.after(),
        &check::Window {
            number: w.last_batch_number(),
            range: w.range(),
            before: w.before(),
            after: w.after(),
            actions: w.actions().to_vec(),
            status: w.status(),
            current: w.current(),
            enabled: w.enabled().to_vec(),
            failed: w.retained_failed_generation(),
        },
    );
}
fn child(
    candidate: bool,
    context: NormalContext<'_>,
    subject: &Path,
    selections: &[&TrustedFunctionSelection<'_>],
    artifact: &Artifact,
) -> i32 {
    current_single_main();
    let deadline = context.deadline();
    deadline.check();
    artifact.verify().unwrap();
    let case = context.leaf_set_copied_case();
    assert_eq!(context.input(), case.input());
    // SAFETY: exact independently trusted complete selections, one retained DSO,
    // sequential scalar leaves, no signals/CET/unwind/reentry or source writers.
    let loaded =
        unsafe { LoadedNormalLeafSet::load_selected(subject, selections, CONTRACT) }.unwrap();
    assert_eq!(loaded.functions().len(), case.n());
    assert!((1..=2).contains(&loaded.source_pages().len()));
    for page in loaded.source_pages() {
        assert_eq!((page.address % 4096, page.bytes.len()), (0, 4096));
    }
    for ((operation, selection), f) in case.table().iter().zip(loaded.functions()) {
        assert_eq!(f.label(), leaf::LABELS[*operation]);
        assert_eq!(f.code().len(), selection.extent);
    }
    let sources: Vec<_> = loaded
        .source_pages()
        .iter()
        .map(|s| (s.address, s.bytes.clone()))
        .collect();
    let copied = artifact.source();
    let mut ready = Ready {
        caller: artifact.entry(),
        caller_immutable: vec![(copied.0, copied.1.to_vec())],
        functions: loaded
            .functions()
            .iter()
            .map(|f| Function {
                entry: f.entry(),
                heads: f.certificate().heads().to_vec(),
                returns: f.certificate().returns().to_vec(),
                boundaries: f.certificate().heads().iter().map(|&p| (p, p)).collect(),
            })
            .collect(),
        immutable: sources.clone(),
        original_sources: sources,
        journal: None,
        case,
        plan: artifact.plan().clone(),
    };
    let data = context.data_address();
    let results = context.results_address();
    let rsp = context.caller_rsp();
    assert_eq!(context.data_len(), 4096);
    assert_eq!(context.input().as_ptr() as usize as u64, data + 128);
    assert_eq!(results, data + 320);
    let mut expected_data =
        unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) }.to_vec();
    assert_eq!(&expected_data[320..328], &[0; 8]);
    expected_data[320..328].copy_from_slice(&case.value().to_le_bytes());
    let mut original = Some(loaded);
    let mut installed = None;
    if candidate {
        let policies: Vec<_> = case
            .table()
            .iter()
            .map(|(operation, _)| match leaf::policy(*operation) {
                leaf::PlanningPolicy::CertifiedBlocks => {
                    NormalModulePreparationPolicy::CertifiedBlocks
                }
                leaf::PlanningPolicy::WholeFunction => NormalModulePreparationPolicy::WholeFunction,
            })
            .collect();
        let prep = NormalLeafSetSitePreparation::new_with_policies(
            original.take().unwrap(),
            identity(ready.functions[0].entry),
            &policies,
        )
        .unwrap();
        let roles: Vec<_> = ready
            .functions
            .iter()
            .enumerate()
            .flat_map(|(i, f)| {
                std::iter::once((i, NormalModuleRoleKind::Entry, f.entry)).chain(
                    f.returns
                        .iter()
                        .map(move |&pc| (i, NormalModuleRoleKind::Return, pc)),
                )
            })
            .collect();
        assert_eq!(
            prep.roles()
                .map(|r| (r.function_index, r.kind, r.pc))
                .collect::<Vec<_>>(),
            roles
        );
        let planned = prep.plan();
        assert_eq!(
            planned.plan().originals().len(),
            ready.original_sources.len()
        );
        assert_eq!(
            planned.plan().final_bytes().len(),
            ready.original_sources.len()
        );
        ready.immutable.clear();
        for (source, expected) in planned
            .plan()
            .originals()
            .iter()
            .zip(&ready.original_sources)
        {
            assert_eq!((source.address, &source.bytes), (expected.0, &expected.1));
        }
        for (source, expected) in planned
            .plan()
            .final_bytes()
            .iter()
            .zip(&ready.original_sources)
        {
            assert_eq!((source.address, source.bytes.len()), (expected.0, 4096));
            ready.immutable.push((source.address, source.bytes.clone()));
        }
        for f in &mut ready.functions {
            f.boundaries.clear();
        }
        for image in planned.images() {
            for &(logical, physical) in image.instruction_boundaries() {
                let owners: Vec<_> = ready
                    .functions
                    .iter()
                    .enumerate()
                    .filter_map(|(i, f)| f.heads.contains(&logical).then_some(i))
                    .collect();
                assert_eq!(owners.len(), 1);
                ready.functions[owners[0]]
                    .boundaries
                    .push((logical, physical));
            }
            ready
                .immutable
                .push((image.address(), image.bytes().to_vec()));
        }
        for f in &mut ready.functions {
            for &head in &f.heads {
                if !f.boundaries.iter().any(|(a, _)| *a == head) {
                    f.boundaries.push((head, head));
                }
            }
        }
        let site = publish(prep);
        let mut prepared = PreparedNormalLeafSetSessionController::new(
            site,
            INSTALL,
            &check::functions(&ready),
            case.k(),
        )
        .unwrap();
        let mut banks = prepared.prepare_epoch_storage().unwrap();
        check::banks(banks.len(), true);
        // SAFETY: dedicated pristine child; immutable table and all callable owners
        // remain live through the one actual returned call and final postflight.
        let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
        let epoch = match controller.stage_prepared(banks.pop().unwrap()) {
            Ok(epoch) => epoch,
            Err((error, bank)) => {
                banks.push(bank);
                panic!("LeafSet stage: {error:?}")
            }
        };
        check::banks(banks.len(), false);
        controller.arm(&epoch).unwrap();
        let published = controller
            .drain_history()
            .unwrap()
            .expect("LeafSet Published transfer");
        check::stream(&ready, std::process::id(), &stream(published.stream()));
        check::chunk(epoch.generation(), true, &chunk(&published));
        assert_eq!(
            published.binding_at(0),
            Some(rapid_profiler::frontend::HistoryBinding::Initial)
        );
        assert_eq!(published.binding_at(1), Some(published.after()));
        assert!(controller.drain_history().unwrap().is_none());
        let (low, high) = context.stack_range();
        let stack = unsafe { ReadableStack::new(low, high) }.unwrap();
        let journal = IntervalJournal::allocate();
        let address = journal.address();
        let attached = unsafe { client.attach(1, stack, journal) }.unwrap();
        assert_eq!(attached.totals().unwrap(), NormalTotals::default());
        ready.journal = Some(JournalReady {
            address,
            a_generation: epoch.generation().get(),
            b_generation: None,
            helper_tid: None,
        });
        installed = Some((controller, client, epoch, attached, banks, published));
    } else {
        original.as_mut().unwrap().verify_original().unwrap();
    }
    artifact.verify().unwrap();
    check_live(&ready.immutable);
    deadline.check();
    context.ready_leaf_set_copied(&ready);
    // Same bridge callsite in both children, with the actual copied body's CALL,
    // continuation, store and outer C3 compared before restoring harness state.
    unsafe {
        machine_call(
            artifact.entry(),
            ready.target().entry,
            (data + 128) as usize as *const u8,
            case.bound(),
            results as usize as *mut u64,
        )
    };
    assert_eq!(
        unsafe { (results as usize as *const u64).read() },
        case.value()
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) },
        expected_data
    );
    artifact.verify().unwrap();
    check_live(&ready.immutable);
    if let Some(original) = &mut original {
        original.verify_original().unwrap();
    }
    current_single_main();
    deadline.check();
    if let Some((mut controller, client, epoch, mut attached, mut banks, published)) = installed {
        assert_eq!(attached.totals().unwrap(), check::totals(0));
        // SAFETY: actual target/outer returns and complete source/input/result/
        // immutable/stack custody postflight precede this caller checkpoint.
        let batch = unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .unwrap();
        check::metadata(
            &ready,
            std::process::id(),
            check::Metadata {
                identity: batch.identity(),
                functions: batch.functions().to_vec(),
                entries: batch.entries().to_vec(),
                pid: batch.pid(),
                tid: batch.tid(),
                registration: batch.registration(),
                install: batch.install(),
                number: batch.number(),
                next: batch.next_ordinal(),
                sequences: batch.completed_sequences(),
                totals: batch.totals(),
            },
        );
        assert_eq!(batch.history_stream(), published.stream());
        check::stream(&ready, std::process::id(), &stream(batch.history_stream()));
        check::watermark(batch.history_high_water());
        check::rows(
            &ready,
            rsp,
            std::process::id(),
            batch.records(),
            batch.journal(),
        );
        assert_eq!(attached.totals().unwrap(), check::totals(1));
        assert!(
            unsafe { attached.checkpoint_after_returns() }
                .unwrap()
                .is_none()
        );
        assert_eq!(attached.detach().unwrap(), check::totals(1));
        controller.disarm(&epoch).unwrap();
        let removed = controller
            .drain_history()
            .unwrap()
            .expect("LeafSet Removed transfer");
        assert!(removed.follows(&published));
        check::stream(&ready, std::process::id(), &stream(removed.stream()));
        check::chunk(epoch.generation(), false, &chunk(&removed));
        assert_eq!(removed.binding_at(1), Some(removed.before()));
        assert_eq!(removed.binding_at(2), Some(removed.after()));
        assert!(controller.drain_history().unwrap().is_none());
        let report = controller
            .report(&epoch)
            .unwrap()
            .expect("one-call closed LeafSet Report");
        check::records(
            &ready,
            batch.records(),
            report.generation().get(),
            &report.records().collect::<Vec<_>>(),
        );
        closed_history(&controller, &ready, &removed);
        artifact.verify().unwrap();
        check_live(&ready.immutable);
        deadline.check();
        drop(report);
        check::banks(banks.len(), false);
        let bank = match controller.reclaim_storage(epoch) {
            Ok(bank) => bank,
            Err((error, token)) => {
                let _retained = token;
                panic!("LeafSet reclaim: {error:?}")
            }
        };
        banks.push(bank);
        check::banks(banks.len(), true);
        closed_history(&controller, &ready, &removed);
        drop((
            batch, attached, client, controller, banks, published, removed,
        ));
    }
    current_single_main();
    deadline.check();
    0
}
pub(crate) fn run(
    subject: &Path,
    expected: &Path,
    app: &Path,
    app_expected: &Path,
    output: &Path,
    selections: [Selection; 4],
    mut deadline: Deadline,
) {
    deadline.check();
    current_single_main();
    // The fixed campaign includes the full set; reject its complete selection
    // geometry before any child or installed owner, rather than late in mask15.
    let _ = Case::new(15, 10, 0, 0, selections);
    let elf = trusted(subject, expected);
    let app_bytes = trusted_bounded(app, app_expected, 512 * 1024 * 1024);
    // SAFETY: private complete admitted copy before all forks, retained beyond all
    // normal reaps; no CET/nonlocal transfer or original application state claim.
    let artifact = unsafe { Artifact::open(app, &app_bytes) }.unwrap();
    assert_eq!(artifact.selection().extent, artifact.plan().bytes().len());
    let descriptors: Vec<_> = selections
        .iter()
        .enumerate()
        .map(|(i, s)| {
            TrustedFunctionSelection::new(&elf, s.elf_va, s.extent, leaf::LABELS[i]).unwrap()
        })
        .collect();
    let mut population = Population::default();
    let mut rows = leaf::HEADER.to_owned();
    let mut coverage = leaf::COVERAGE_HEADER.to_owned();
    let mut count = 0;
    let mut groups = 0;
    for (subset, k, seed, operation, index) in leaf::keys() {
        if count != 0 {
            deadline = Deadline::start();
        }
        artifact.verify().unwrap();
        deadline.check();
        let case = Case::new(subset, k, operation, index, selections);
        let selected: Vec<_> = case.table().iter().map(|(i, _)| &descriptors[*i]).collect();
        let oracle = NormalOracle::new_leaf_set_copied(
            seed,
            case,
            artifact.plan().clone(),
            artifact.entry(),
            (artifact.source().0, artifact.source().1.to_vec()),
            deadline,
        );
        let (pair, trace) = oracle.pair_leaf_set_copied(|candidate, context| {
            // Installed owners must never unwind after partial publication/call.
            std::panic::set_hook(Box::new(|info| {
                eprintln!("LeafSet copied Rust child FAILED: {info}");
                std::process::abort();
            }));
            child(candidate, context, subject, &selected, &artifact)
        });
        artifact.verify().unwrap();
        deadline.check();
        if let Some(c) = population.record(seed, case, artifact.plan(), &pair, &trace) {
            leaf::append_row(
                &mut coverage,
                &leaf::coverage_fields(seed, case, &c),
                16,
                384,
                65536,
            );
            groups += 1;
        }
        leaf::append_row(
            &mut rows,
            &leaf::pair_fields(seed, case, artifact.plan(), &pair, &trace),
            36,
            768,
            1024 * 1024,
        );
        std::fs::write(output.join("leaf-set-rust-pairs.csv"), &rows).unwrap();
        std::fs::write(output.join("leaf-set-rust-coverage.csv"), &coverage).unwrap();
        drop(oracle);
        deadline.check();
        count += 1;
    }
    assert_eq!((count, groups), (1280, 128));
    let comparisons = population.finish();
    assert_eq!(trusted(subject, expected), elf);
    artifact.verify().unwrap();
    current_single_main();
    deadline.check();
    let terminal = leaf::terminal(comparisons);
    let mut out = std::io::stdout().lock();
    out.write_all(terminal.as_bytes()).unwrap();
    out.flush().unwrap();
    deadline.check();
}
