//! Explicit fresh-process integration control with independently built C DSOs.
//! It is not part of the parallel pure suite or a performance/state oracle.
use super::*;
use crate::frontend_native::always_on::tests::concurrent_native::{
    expected_file, identity, pin, protect, stack,
};
use crate::frontend_native::{
    InstalledNormalModuleSite, LoadedNormalModule, NormalModuleContract,
    NormalModulePreparationPolicy, NormalModuleSitePreparation, TrustedFunctionSelection,
};
use liteinst::bundle::WritableAlias;
use liteinst::contracts::{AddressRange, QuiescenceLease};
use std::path::Path;
use std::time::{Duration, Instant};

fn number(name: &str) -> u64 {
    let value = std::env::var(name).expect("independently authenticated ELF coordinate");
    assert!(!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()));
    assert!(value == "0" || !value.starts_with('0'));
    value.parse().unwrap()
}
fn fixture(candidate: &str, expected: &str) -> Vec<u8> {
    let candidate = std::env::var_os(candidate).expect("fixed compiled fixture");
    let expected = std::env::var_os(expected).expect("independent complete expected ELF");
    expected_file(Path::new(&candidate), Path::new(&expected))
}
fn publish(prep: NormalModuleSitePreparation) -> InstalledNormalModuleSite {
    // Routed interior entries require the reserved synchronous SIGILL router.
    // Do not silently unblock an inherited mask or replace its disposition.
    let mut actual_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut actual_mask) },
        0
    );
    assert_eq!(unsafe { libc::sigismember(&actual_mask, libc::SIGILL) }, 0);
    let planned = prep.plan();
    assert_eq!(planned.plan().originals().len(), 1);
    let original = &planned.plan().originals()[0];
    assert_eq!(original.bytes.len(), 4096);
    let source = AddressRange::new(original.address, original.bytes.len()).unwrap();
    let mut ranges = vec![source];
    ranges.extend(planned.plan().steps().iter().flat_map(|step| {
        step.parts()
            .allocations
            .iter()
            .map(|allocation| allocation.range)
    }));
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    // SAFETY: exact fresh-process private loaded page, no calling capability or
    // saved entry exists yet. All source/generated ranges belong to this lease.
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let mut lease =
        unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
    let result = unsafe {
        planned.publish_with(&[alias], &mut lease, || {
            protect(source, libc::PROT_READ | libc::PROT_EXEC)
        })
    };
    if let Err(failure) = &result {
        use std::io::Write;
        // Best-effort diagnostics only; no unwind or recovery from publication.
        let _ = writeln!(
            std::io::stderr().lock(),
            "owned module publication FAILED: {failure:?}"
        );
        std::process::abort();
    }
    assert!(!lease.is_poisoned());
    drop(lease);
    let (installed, receipt) = result.unwrap();
    // SAFETY: exact successful publication and final RX; all owners retained.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

#[test]
#[ignore = "requires one exact fresh release process and independently admitted module/caller C fixtures"]
fn owned_module_native_four_call_batches_epochs_and_close() {
    // External owner must select ONLY this test, bind the two complete final
    // ELF/source/coordinate sets, inactive CET, dependencies and continuous
    // no-foreign-entry/writer/unload premises. Missing inputs are failures.
    let deadline = Instant::now().checked_add(Duration::from_secs(15)).unwrap();
    pin(None);
    let mut signals: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigfillset(&mut signals) }, 0);
    // Keep asynchronous signals blocked while preserving the core's owned
    // synchronous entry-routing signal; foreign delivery/reentry stays excluded.
    assert_eq!(unsafe { libc::sigdelset(&mut signals, libc::SIGILL) }, 0);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) },
        0
    );
    let subject = fixture(
        "RAPID_OWNED_MODULE_CANDIDATE",
        "RAPID_OWNED_MODULE_EXPECTED",
    );
    let caller_elf = fixture(
        "RAPID_OWNED_CALLER_CANDIDATE",
        "RAPID_OWNED_CALLER_EXPECTED",
    );
    let csv = TrustedFunctionSelection::new(
        &subject,
        number("RAPID_OWNED_CSV_VA"),
        usize::try_from(number("RAPID_OWNED_CSV_LENGTH")).unwrap(),
        "normal-csv-fields-v1",
    )
    .unwrap();
    let length = TrustedFunctionSelection::new(
        &subject,
        number("RAPID_OWNED_LENGTH_VA"),
        usize::try_from(number("RAPID_OWNED_LENGTH_LENGTH")).unwrap(),
        "freebsd-strnlen-14.1-v1",
    )
    .unwrap();
    let selections = if csv.elf_range().0 < length.elf_range().0 {
        [&csv, &length]
    } else {
        [&length, &csv]
    };
    let order = if csv.elf_range().0 < length.elf_range().0 {
        [0, 1]
    } else {
        [1, 0]
    };
    // SAFETY: exact fixed csv_fields.c and strnlen.c source, final compiler ELF,
    // complete selections and fresh private sealed owner. Both functions are
    // read-only/in-bounds for every 0..=64-byte slice, including arbitrary bytes.
    let loaded = unsafe {
        LoadedNormalModule::load_sealed_selected_pair(
            selections,
            NormalModuleContract {
                single_external_entry_per_function: true,
                sequential_call_ret_only: true,
                no_active_cet: true,
            },
        )
    }
    .unwrap();
    let entries = loaded.functions().each_ref().map(|f| f.entry());
    let caller_selection = TrustedFunctionSelection::new(
        &caller_elf,
        number("RAPID_OWNED_CALLER_VA"),
        123,
        "normal_module_caller",
    )
    .unwrap();
    // SAFETY: fixed independently compiled module_caller.c, complete final ELF,
    // no dependencies/constructors/foreign entry, inactive CET and retained RX.
    let caller = unsafe { LoadedNormalModuleCaller::load_sealed(&caller_selection) }.unwrap();
    let words = caller.continuations();
    let mut policies = [NormalModulePreparationPolicy::WholeFunction; 2];
    policies[order[0]] = NormalModulePreparationPolicy::CertifiedBlocks;
    let site = publish(
        NormalModuleSitePreparation::new_with_policies(loaded, identity(entries[0]), policies)
            .unwrap(),
    );
    let ids = [FunctionId(11), FunctionId(29)];
    let mut prepared =
        PreparedNormalModuleSessionController::new(site, 0x6f77_6e01, ids, 10).unwrap();
    let mut banks = prepared.prepare_epoch_storage().unwrap();
    assert_eq!(banks.len(), 3);
    // SAFETY: pristine fresh process, private installed mapping union, no native
    // entry yet; one actual attached caller and no callback-dependent locks.
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    // SAFETY: the complete two C source semantics cover EVERY safe input above;
    // private arrays and slices do not escape, only this actual thread calls,
    // current real stack owns callback save space and ordinary returns.
    let mut worker =
        unsafe { client.attach_owned(caller, order, 1, stack(), IntervalJournal::allocate()) }
            .unwrap();
    let close = worker.close_handle();
    let epoch_a = controller.stage_prepared(banks.pop().unwrap()).unwrap();
    let generation_a = epoch_a.generation().get();
    controller.arm(&epoch_a).unwrap();
    let first = worker
        .run_batch(NormalModuleInputs::new(&[], &[]).unwrap())
        .unwrap();
    assert_eq!((first.sum, first.values), (2, [1, 0, 1, 0]));
    controller.disarm(&epoch_a).unwrap();
    let report_a = controller.report(&epoch_a).unwrap().unwrap();
    assert_eq!(report_a.records().count(), 4);
    drop(report_a);
    let reclaimed = controller
        .reclaim_storage(epoch_a)
        .map_err(|(e, _)| e)
        .unwrap();
    let epoch_b = controller.stage_prepared(reclaimed).unwrap();
    let generation_b = epoch_b.generation().get();
    controller.arm(&epoch_b).unwrap();
    let csv_input = *b"a,\"b,c\"";
    let length_input = *b"x\0z";
    let second = worker
        .run_batch(NormalModuleInputs::new(&csv_input, &length_input).unwrap())
        .unwrap();
    assert_eq!((second.sum, second.values), (6, [2, 1, 2, 1]));
    assert_eq!(csv_input, *b"a,\"b,c\"");
    assert_eq!(length_input, *b"x\0z");
    controller.disarm(&epoch_b).unwrap();
    let all_bytes = [255; 64];
    let removed = worker
        .run_batch(NormalModuleInputs::new(&all_bytes, &all_bytes).unwrap())
        .unwrap();
    assert_eq!((removed.sum, removed.values), (130, [1, 64, 1, 64]));
    assert_eq!(all_bytes, [255; 64]);
    for (index, batch) in [
        &first.observations,
        &second.observations,
        &removed.observations,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(batch.records().len(), 4);
        assert_eq!(batch.journal().len(), 512);
        assert_eq!(batch.number(), index as u64 + 1);
        assert_eq!(batch.entries(), &entries);
        assert_eq!(batch.functions(), &ids);
        let (before, after) = batch.totals();
        assert_eq!(after.entered - before.entered, 4);
        assert_eq!(after.ret_observed - before.ret_observed, 4);
        assert_eq!(after.confirmed - before.confirmed, 4);
        assert_eq!(
            after.completed - before.completed,
            if index == 2 { 0 } else { 4 }
        );
        assert_eq!(
            after.unsampled - before.unsampled,
            if index == 2 { 4 } else { 0 }
        );
        for (i, row) in batch.records().iter().enumerate() {
            if index < 2 {
                let expected_generation = [generation_a, generation_b][index];
                assert!(matches!(
                    row.record.raw.owner,
                    RawIntervalOwner::Sampled { generation, .. }
                        if generation == expected_generation
                ));
            } else {
                assert_eq!(
                    row.record.raw.owner,
                    RawIntervalOwner::Removed {
                        generation: generation_b
                    }
                );
            }
            assert_eq!(row.function, ids[order[i % 2]]);
            assert_eq!(row.record.return_word, words[i]);
            assert_eq!(row.record.raw.entry_pc, entries[order[i % 2]]);
            assert_eq!(
                row.record.acknowledgement,
                if i == 3 {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: row.record.raw.ordinal + 1,
                    }
                }
            );
        }
    }
    let report_b = controller.report(&epoch_b).unwrap().unwrap();
    assert_eq!(report_b.records().count(), 4);
    drop(report_b);
    let _reclaimed = controller
        .reclaim_storage(epoch_b)
        .map_err(|(e, _)| e)
        .unwrap();
    let history = controller.drain_history().unwrap().unwrap();
    assert_eq!(history.actions().len(), 4);
    assert!(controller.history_window().unwrap().current().is_none());
    assert_eq!(close.request(), NormalModuleCloseState::Closing);
    assert!(
        worker
            .run_batch(NormalModuleInputs::new(&[], &[]).unwrap())
            .is_err()
    );
    assert_eq!(close.state(), NormalModuleCloseState::Closing);
    let totals = worker.finish().unwrap();
    assert_eq!(
        totals,
        NormalTotals {
            entered: 12,
            ret_observed: 12,
            confirmed: 12,
            completed: 8,
            unsampled: 4
        }
    );
    assert_eq!(close.state(), NormalModuleCloseState::Closed);
    assert!(
        worker
            .run_batch(NormalModuleInputs::new(&[], &[]).unwrap())
            .is_err()
    );
    assert!(worker.finish().is_err());
    assert_eq!(close.state(), NormalModuleCloseState::Closed);
    assert!(NORMAL.with(|cell| cell.borrow().0.is_none()));
    drop(worker);
    assert_eq!(close.state(), NormalModuleCloseState::Closed);
    assert!(Instant::now() < deadline);
}

#[path = "performance.rs"]
mod performance;
