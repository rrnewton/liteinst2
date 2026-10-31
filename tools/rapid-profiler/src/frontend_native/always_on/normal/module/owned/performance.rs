//! Fixed-work wall-time comparison; all semantic/ownership checks precede any
//! completed-result claim. This is not the strict qualification consumer.
use super::*;
use crate::frontend::{ActionKind, HistoryBinding, Observation, PayloadOutcome};
use crate::generation::{Disposition, Terminal};
use std::io::Write;

const PAIRS: usize = 5;
const WARMUP: usize = 64;
const MEASURED: usize = 256;
const BATCHES: usize = WARMUP + MEASURED;
const CALLS_PER_ARM: usize = 4 * BATCHES;
const INSTALL: u64 = 0x6f77_6e02;
const REGISTRATION: u64 = 1;
const _: () = assert!(CALLS_PER_ARM == 1280 && CALLS_PER_ARM <= 2000 && CALLS_PER_ARM / 2 <= 1000);

type Case = (Vec<u8>, Vec<u8>, [u64; 4]);
fn cases() -> [Case; 4] {
    let mut length = vec![255; 64];
    length[32] = 0;
    [
        (vec![], vec![], [1, 0, 1, 0]),
        (b"a,\"b,c\"".to_vec(), b"x\0z".to_vec(), [2, 1, 2, 1]),
        (vec![255; 64], vec![255; 64], [1, 64, 1, 64]),
        (b"a,b,".repeat(16), length, [33, 32, 33, 32]),
    ]
}
fn totals(n: u64) -> NormalTotals {
    NormalTotals {
        entered: n,
        ret_observed: n,
        confirmed: n,
        completed: n,
        unsampled: 0,
    }
}
fn values(sum: u64, actual: [u64; 4], expected: [u64; 4]) {
    assert_eq!(actual, expected);
    assert_eq!(sum, expected.into_iter().fold(0u64, u64::wrapping_add));
}
fn timing(output: &mut std::fs::File, pair: usize, arm: &str, started: Instant, ended: Instant) {
    let ns = ended
        .checked_duration_since(started)
        .expect("monotonic wall clock")
        .as_nanos();
    assert!(ns > 0);
    // Raw numbers are retained even if a later assertion fails. Only the final
    // summary plus the successful process/owner closure validates all rows.
    writeln!(output, "{{\"kind\":\"timing\",\"pair\":{pair},\"arm\":\"{arm}\",\"warmup_batches\":{WARMUP},\"measured_batches\":{MEASURED},\"target_calls\":{},\"wall_ns\":{ns}}}", 4 * MEASURED).unwrap();
}

struct Expected {
    entries: [u64; 2],
    ids: [FunctionId; 2],
    order: [usize; 2],
    words: [u64; 4],
    returns: [Vec<u64>; 2],
    pid: u32,
    tid: u64,
}
impl Expected {
    fn batch(&self, result: &OwnedNormalModuleResult, index: usize, pair: usize, generation: u64) {
        let batch = &result.observations;
        let first = (pair * CALLS_PER_ARM + 4 * index) as u64;
        assert_eq!(batch.records().len(), 4);
        assert_eq!(batch.journal().len(), 512);
        assert_eq!(batch.number(), (pair * BATCHES + index + 1) as u64);
        assert_eq!(batch.entries(), &self.entries);
        assert_eq!(batch.functions(), &self.ids);
        assert_eq!(batch.identity(), identity(self.entries[0]));
        assert_eq!(
            (
                batch.pid(),
                batch.tid(),
                batch.registration(),
                batch.install()
            ),
            (self.pid, self.tid, REGISTRATION, INSTALL)
        );
        assert_eq!(batch.totals(), (totals(first), totals(first + 4)));
        assert_eq!(batch.completed_sequences(), (first, first + 4));
        assert_eq!(batch.next_ordinal(), first + 5);
        assert_eq!(batch.history_high_water(), Some((2 * pair + 1) as u64));
        let mut journal = [0u64; 512];
        journal[..4].copy_from_slice(&[8, 0, self.tid, 0]);
        for (i, row) in batch.records().iter().enumerate() {
            let selected = self.order[i % 2];
            assert_eq!(row.function, self.ids[selected]);
            assert_eq!(row.record.return_word, self.words[i]);
            assert_eq!(row.record.raw.ordinal, first + i as u64 + 1);
            assert_eq!(row.record.raw.entry_pc, self.entries[selected]);
            assert!(self.returns[selected].contains(&row.record.raw.return_pc));
            assert_eq!(
                row.record.raw.owner,
                RawIntervalOwner::Sampled {
                    generation,
                    invocation: 4 * index + i
                }
            );
            assert_eq!(row.record.history_prefix, (2 * pair + 1) as u64);
            assert_eq!(row.record.entry_rsp % 16, 8);
            assert_eq!(row.record.entry_rsp, batch.records()[0].record.entry_rsp);
            let bits = (4 * index + i + 1) as u64 | (((2 * pair + 1) as u64) << 13);
            journal[4 + i * 14..11 + i * 14].copy_from_slice(&[
                1,
                row.record.raw.ordinal,
                row.record.raw.entry_pc,
                row.record.entry_rsp,
                self.words[i],
                generation,
                bits,
            ]);
            journal[11 + i * 14..18 + i * 14].copy_from_slice(&[
                2,
                row.record.raw.ordinal,
                row.record.raw.return_pc,
                row.record.entry_rsp,
                self.words[i],
                generation,
                bits,
            ]);
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
        assert_eq!(batch.journal(), journal);
    }
}

#[test]
#[ignore = "requires one exact fresh release process, reserved CPU and independently admitted module/caller C fixtures"]
fn owned_module_native_fixed_work_batch_cost() {
    // Exactly one fixed experiment; no adaptive repetitions, larger capacity or
    // qualification threshold. The external owner retains every outcome.
    let deadline = Instant::now().checked_add(Duration::from_secs(15)).unwrap();
    pin(None);
    let mut signals: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigfillset(&mut signals) }, 0);
    assert_eq!(unsafe { libc::sigdelset(&mut signals, libc::SIGILL) }, 0);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) },
        0
    );
    let path =
        std::env::var_os("RAPID_OWNED_BATCH_COST_OUTPUT").expect("exclusive raw output path");
    assert!(Path::new(&path).is_absolute());
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
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
    let order = if csv.elf_range().0 < length.elf_range().0 {
        [0, 1]
    } else {
        [1, 0]
    };
    let selections = if order == [0, 1] {
        [&csv, &length]
    } else {
        [&length, &csv]
    };
    let contract = NormalModuleContract {
        single_external_entry_per_function: true,
        sequential_call_ret_only: true,
        no_active_cet: true,
    };
    // SAFETY: same independently built complete C ELF and universal read-only
    // 0..=64-byte input semantics as the integration control. Each constructor
    // makes its own sealed backing and retains its complete loader/provenance.
    // No foreign entry, alias writer, unload, CET, signal reentry or escape.
    let baseline =
        unsafe { LoadedNormalModule::load_sealed_selected_pair(selections, contract) }.unwrap();
    let loaded =
        unsafe { LoadedNormalModule::load_sealed_selected_pair(selections, contract) }.unwrap();
    let baseline_entries = baseline.functions().each_ref().map(|f| f.entry());
    let entries = loaded.functions().each_ref().map(|f| f.entry());
    for original in baseline.source_pages() {
        for installed in loaded.source_pages() {
            assert!(
                original.address + original.bytes.len() as u64 <= installed.address
                    || installed.address + installed.bytes.len() as u64 <= original.address
            );
        }
    }
    for (original, installed) in baseline.functions().iter().zip(loaded.functions()) {
        assert_eq!(original.elf_range(), installed.elf_range());
        assert_eq!(original.code(), installed.code());
        assert_ne!(original.entry(), installed.entry());
    }
    let returns = loaded
        .functions()
        .each_ref()
        .map(|f| f.certificate().returns().to_vec());
    let caller_selection = TrustedFunctionSelection::new(
        &caller_elf,
        number("RAPID_OWNED_CALLER_VA"),
        123,
        "normal_module_caller",
    )
    .unwrap();
    // SAFETY: two independent sealed instances of the same admitted full ELF /
    // exact 123-byte, four CALL/store, outer-RET body. Sole actual caller thread.
    let mut baseline_caller =
        unsafe { LoadedNormalModuleCaller::load_sealed(&caller_selection) }.unwrap();
    let caller = unsafe { LoadedNormalModuleCaller::load_sealed(&caller_selection) }.unwrap();
    let words = caller.continuations();
    assert!(
        baseline_caller
            .continuations()
            .iter()
            .all(|pc| !words.contains(pc))
    );
    let mut policies = [NormalModulePreparationPolicy::WholeFunction; 2];
    policies[order[0]] = NormalModulePreparationPolicy::CertifiedBlocks;
    let site = publish(
        NormalModuleSitePreparation::new_with_policies(loaded, identity(entries[0]), policies)
            .unwrap(),
    );
    let ids = [FunctionId(11), FunctionId(29)];
    let mut prepared =
        PreparedNormalModuleSessionController::new(site, INSTALL, ids, 1000).unwrap();
    let mut banks = prepared.prepare_epoch_storage().unwrap();
    assert_eq!(banks.len(), 3);
    // SAFETY: real initial union-wide quiescence; all owners remain retained.
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    // SAFETY: same universal ABI/input, stack and sole-thread admission as the
    // integration control. The baseline targets are independent and unpatched.
    let mut worker = unsafe {
        client.attach_owned(
            caller,
            order,
            REGISTRATION,
            stack(),
            IntervalJournal::allocate(),
        )
    }
    .unwrap();
    let close = worker.close_handle();
    let expected = Expected {
        entries,
        ids,
        order,
        words,
        returns,
        pid: std::process::id(),
        tid: unsafe { libc::syscall(libc::SYS_gettid) } as u64,
    };
    let inputs = cases();
    let unchanged = inputs.clone();
    let admitted = inputs
        .each_ref()
        .map(|(a, b, _)| NormalModuleInputs::new(a, b).unwrap());
    let mut bank = Some(banks.pop().unwrap());
    let mut previous_history = None;
    let mut previous_generation = None;
    for pair in 0..PAIRS {
        let arms = if pair % 2 == 0 {
            ["baseline", "owned"]
        } else {
            ["owned", "baseline"]
        };
        for arm in arms {
            assert!(Instant::now() < deadline);
            if arm == "baseline" {
                baseline.verify_original().unwrap();
                let mut results = Vec::with_capacity(BATCHES);
                let mut invoke = |index: usize| {
                    let (a, b, _) = &inputs[index % inputs.len()];
                    let mut values = [0; 4];
                    // SAFETY: exclusive mutable caller borrow is the baseline
                    // batch's entry lease: no close/entry handle is exposed, all
                    // unpatched module/input/result owners remain live through
                    // actual outer RET, and no installed hook is reached.
                    let sum = unsafe {
                        baseline_caller.invoke(
                            order.map(|i| baseline_entries[i]),
                            [a, b],
                            &mut values,
                        )
                    };
                    results.push((sum, values));
                };
                for index in 0..WARMUP {
                    invoke(index);
                }
                let started = Instant::now();
                for index in WARMUP..BATCHES {
                    invoke(index);
                }
                let ended = Instant::now();
                timing(&mut output, pair, arm, started, ended);
                assert_eq!(results.len(), BATCHES);
                for (index, (sum, actual)) in results.into_iter().enumerate() {
                    values(sum, actual, inputs[index % inputs.len()].2);
                }
                baseline.verify_original().unwrap();
            } else {
                let epoch = controller.stage_prepared(bank.take().unwrap()).unwrap();
                let generation = epoch.generation();
                assert!(previous_generation.is_none_or(|old| generation.get() > old));
                previous_generation = Some(generation.get());
                controller.arm(&epoch).unwrap();
                let mut results = Vec::with_capacity(BATCHES);
                for index in 0..WARMUP {
                    results.push(worker.run_batch(admitted[index % admitted.len()]).unwrap());
                }
                let started = Instant::now();
                for index in WARMUP..BATCHES {
                    results.push(worker.run_batch(admitted[index % admitted.len()]).unwrap());
                }
                let ended = Instant::now();
                timing(&mut output, pair, arm, started, ended);
                assert_eq!(results.len(), BATCHES);
                for (index, result) in results.iter().enumerate() {
                    values(result.sum, result.values, inputs[index % inputs.len()].2);
                    expected.batch(result, index, pair, generation.get());
                }
                controller.disarm(&epoch).unwrap();
                let report = controller.report(&epoch).unwrap().unwrap();
                assert_eq!(report.generation(), generation);
                assert_eq!(report.records().count(), CALLS_PER_ARM);
                for (invocation, observation) in report.records().enumerate() {
                    let raw = &results[invocation / 4].observations.records()[invocation % 4]
                        .record
                        .raw;
                    let admission = observation.record.admission;
                    assert_eq!(admission.generation, generation);
                    assert_eq!(admission.invocation, invocation);
                    assert_eq!(admission.function, ids[order[invocation % 2]]);
                    assert_eq!(admission.entry_value, raw.start.ticks);
                    let end = if raw.start.aux != raw.end.aux {
                        Observation::Unavailable(1)
                    } else if raw.end.ticks < raw.start.ticks {
                        Observation::Unavailable(2)
                    } else {
                        Observation::Value(raw.end.ticks)
                    };
                    let payload = observation.payload.unwrap();
                    assert_eq!(payload.admission, admission);
                    assert_eq!(payload.thread, REGISTRATION);
                    assert_eq!(
                        payload.start_sequence,
                        (pair * CALLS_PER_ARM + invocation) as u64
                    );
                    assert_eq!(
                        payload.outcome,
                        PayloadOutcome::Completed {
                            end,
                            completed_children: 0
                        }
                    );
                    // Unavailable timestamps remain explicit completion values;
                    // no timing-validity threshold is imposed on raw endpoints.
                    assert_eq!(
                        observation.record.terminal,
                        Some(Terminal::Completed {
                            value: invocation as u64,
                            disposition: Disposition::Retained {
                                rank: invocation / 2
                            }
                        })
                    );
                }
                let history = controller.drain_history().unwrap().unwrap();
                assert_eq!(history.number(), pair as u64 + 1);
                assert_eq!(history.range(), (2 * pair) as u64..(2 * pair + 2) as u64);
                assert_eq!(history.actions().len(), 2);
                if let Some(previous) = &previous_history {
                    assert!(history.follows(previous));
                } else {
                    assert_eq!(history.before(), HistoryBinding::Initial);
                }
                for (action, kind) in history
                    .actions()
                    .iter()
                    .zip([ActionKind::Published, ActionKind::Removed])
                {
                    assert_eq!(action.kind, kind);
                    assert_eq!(action.generation, generation);
                    assert_eq!(action.function, None);
                }
                for result in &results {
                    let batch = &result.observations;
                    assert_eq!(batch.history_stream(), Some(history.stream()));
                    for row in batch.records() {
                        assert_eq!(
                            history.binding_at(row.record.history_prefix),
                            Some(HistoryBinding::Published {
                                action_index: (2 * pair) as u64,
                                generation
                            })
                        );
                    }
                }
                previous_history = Some(history);
                assert!(controller.history_window().unwrap().current().is_none());
                drop(report);
                drop(results);
                // Actual reclamation, never an inferred drain or a retry/split.
                bank = Some(
                    controller
                        .reclaim_storage(epoch)
                        .map_err(|(e, _)| e)
                        .unwrap(),
                );
            }
            assert_eq!(inputs, unchanged);
            assert_eq!(close.state(), NormalModuleCloseState::Ready);
        }
    }
    assert_eq!(previous_history.unwrap().range().end, 10);
    assert!(controller.drain_history().unwrap().is_none());
    assert!(bank.is_some());
    assert_eq!(banks.len(), 2);
    assert_eq!(close.request(), NormalModuleCloseState::Closing);
    let final_totals = worker.finish().unwrap();
    assert_eq!(final_totals, totals((PAIRS * CALLS_PER_ARM) as u64));
    assert_eq!(close.state(), NormalModuleCloseState::Closed);
    assert!(NORMAL.with(|cell| cell.borrow().0.is_none()));
    drop(worker);
    assert_eq!(close.state(), NormalModuleCloseState::Closed);
    baseline.verify_original().unwrap();
    assert_eq!(inputs, unchanged);
    assert!(Instant::now() < deadline);
    writeln!(output, "{{\"kind\":\"validated\",\"pairs\":{PAIRS},\"timing_rows\":{},\"warmup_batches_per_arm\":{},\"measured_batches_per_arm\":{},\"entered\":{},\"ret_observed\":{},\"confirmed\":{},\"completed\":{},\"unsampled\":0,\"history_actions\":10,\"closed\":true}}", PAIRS * 2, PAIRS * WARMUP, PAIRS * MEASURED, final_totals.entered, final_totals.ret_observed, final_totals.confirmed, final_totals.completed).unwrap();
    output.flush().unwrap();
}
