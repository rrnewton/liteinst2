//! One exact nonempty checksum leaf through the actual accuracy LeafSet lifecycle.
use super::*;
use crate::{exact_truth as truth, ordinary::exact_body};
use native::exact_accuracy::{self as exact, Case, Ready};
#[path = "exact_check.rs"]
mod check;
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
    let case = context.exact_accuracy_case();
    assert_eq!(context.input(), case.input());
    // SAFETY: exact independently trusted complete selections, one retained DSO,
    // sequential scalar leaves, no signals/CET/unwind/reentry or source writers.
    let loaded =
        unsafe { LoadedNormalLeafSet::load_selected(subject, selections, CONTRACT) }.unwrap();
    assert_eq!(loaded.functions().len(), case.n());
    assert_eq!(loaded.source_pages().len(), 1);
    for page in loaded.source_pages() {
        assert_eq!((page.address % 4096, page.bytes.len()), (0, 4096));
    }
    for ((_, selection), f) in case.table().iter().zip(loaded.functions()) {
        assert_eq!(f.label(), exact::LABEL);
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
        let policies = [NormalModulePreparationPolicy::WholeFunction; 1];
        let prep = NormalLeafSetSitePreparation::new_with_policies(
            original.take().unwrap(),
            check::identity(ready.functions[0].entry),
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
        assert_eq!(planned.images().len(), 1);
        assert_eq!(roles.len(), 2);
        for f in &ready.functions {
            assert_eq!(f.boundaries.len(), f.heads.len());
            for &head in &f.heads {
                assert_eq!(
                    f.boundaries
                        .iter()
                        .filter(|&&(a, b)| a == head && b != head)
                        .count(),
                    1
                );
            }
        }
        let site = publish(prep);
        let policy =
            rapid_profiler::frontend_native::backoff::Policy::accuracy(10, 10, 1, 4096).unwrap();
        let mut prepared = PreparedNormalLeafSetSessionController::new_accuracy(
            site,
            check::INSTALL,
            &check::functions(&ready),
            policy,
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
        assert_eq!(published.stream().accuracy_policy(), Some(policy));
        assert_eq!(client.accuracy_policy(), Some(policy));
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
        let attached = unsafe { accuracy::Attachment::attach(&client, stack, journal, true) };
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
    context.ready_exact_accuracy(&ready);
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
        let retained = unsafe { attached.checkpoint_after_returns() }.unwrap();
        retained.check(true);
        let batch = retained.normal();
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
        assert!(unsafe { attached.checkpoint_after_returns() }.is_none());
        let (totals, counter_close) = attached.detach();
        assert_eq!(totals, check::totals(1));
        assert!(counter_close.is_some());
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
            retained,
            counter_close,
            attached,
            client,
            controller,
            banks,
            published,
            removed,
        ));
    }
    current_single_main();
    deadline.check();
    0
}

// Extract the complete actual source page; LoadedNormalLeafSet still owns ELF admission.
fn source_page(elf: &[u8], case: Case) -> Vec<u8> {
    use object::{Object, ObjectSegment, SegmentFlags};
    let file = object::File::parse(elf).unwrap();
    let va = case.selections()[0].elf_va;
    let segments: Vec<_> = file
        .segments()
        .filter(|s| {
            s.address() <= va
                && va.checked_add(37).unwrap() <= s.address().checked_add(s.size()).unwrap()
        })
        .collect();
    assert_eq!(segments.len(), 1);
    let segment = &segments[0];
    assert_eq!(segment.flags(), SegmentFlags::Elf { p_flags: 5 });
    let (offset, files) = segment.file_range();
    assert_eq!(files, segment.size());
    assert_eq!(offset % 4096, segment.address() % 4096);
    let page_va = va & !4095;
    let file_page = (offset & !4095)
        .checked_add(page_va.checked_sub(segment.address() & !4095).unwrap())
        .unwrap();
    let start = usize::try_from(file_page).unwrap();
    let end = start.checked_add(4096).unwrap();
    assert!(end <= elf.len());
    elf[start..end].to_vec()
}
pub(crate) fn run(
    subject: &Path,
    expected: &Path,
    app: &Path,
    app_expected: &Path,
    output: &Path,
    case: Case,
    deadline: Deadline,
) {
    deadline.check();
    current_single_main();
    assert_eq!(exact::BODY, truth::BYTES);
    assert_eq!(exact::HEADS, truth::HEADS.map(u64::from));
    assert_eq!(case.k(), 10);
    let input = case.input();
    assert_eq!(
        case.value(),
        truth::checksum(&input[..case.bound()]).unwrap()
    );
    assert_eq!(case.counts(), truth::counts(case.bound()).unwrap());
    let elf = trusted(subject, expected);
    let page = source_page(&elf, case);
    let app_bytes = trusted_bounded(app, app_expected, 512 * 1024 * 1024);
    // SAFETY: independent complete copied-machine ABI/geometry and owner lifetime
    // acceptance. This grants no original-address or Rust-ABI qualification.
    let artifact = unsafe { Artifact::open(app, &app_bytes) }.unwrap();
    assert_eq!(artifact.selection().extent, artifact.plan().bytes().len());
    let selection = case.selections()[0];
    let descriptor =
        TrustedFunctionSelection::new(&elf, selection.elf_va, selection.extent, exact::LABEL)
            .unwrap();
    let oracle = NormalOracle::new_exact_accuracy(
        case,
        artifact.plan().clone(),
        artifact.entry(),
        (artifact.source().0, artifact.source().1.to_vec()),
        page,
        deadline,
    );
    let (pair, trace) = oracle.pair_exact_accuracy(
        |candidate, context| {
            std::panic::set_hook(Box::new(|info| {
                eprintln!("Exact37 accuracy child FAILED: {info}");
                std::process::abort();
            }));
            child(candidate, context, subject, &[&descriptor], &artifact)
        },
        |body| {
            exact_body::check(
                body.code,
                body.input,
                body.entry,
                body.input_address,
                body.continuation,
                body.steps,
            )
        },
    );
    artifact.verify().unwrap();
    assert_eq!(trusted(subject, expected), elf);
    assert_eq!(
        trusted_bounded(app, app_expected, 512 * 1024 * 1024),
        app_bytes
    );
    deadline.check();
    current_single_main();
    let row = exact::pair_row(case, artifact.plan(), &pair, &trace);
    std::fs::write(
        output.join("exact37-accuracy-pair.csv"),
        exact::HEADER.to_owned() + &row,
    )
    .unwrap();
    let mut out = std::io::stdout().lock();
    out.write_all(exact::terminal(case, pair.comparisons).as_bytes())
        .unwrap();
    out.flush().unwrap();
    deadline.check();
}
