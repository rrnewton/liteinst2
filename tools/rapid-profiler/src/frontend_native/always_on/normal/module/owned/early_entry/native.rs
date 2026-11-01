//! Fixed fresh-process optional-entry integration; no timing/full-state claim.
//! Existing mandatory native controls remain separate and unchanged.
use super::*;
use crate::frontend_native::always_on::tests::concurrent_native::{
    expected_file, identity, pin, protect, stack,
};
use crate::frontend_native::{
    EarlyEntryModuleSitePreparation, InstalledEarlyEntryModuleSite, LoadedNormalModule,
    NormalModuleContract, NormalModulePreparationPolicy, TrustedFunctionSelection,
};
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::{AddressRange, QuiescenceLease};
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
fn publish(prep: EarlyEntryModuleSitePreparation) -> InstalledEarlyEntryModuleSite {
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

use crate::frontend::{ActionKind, HistoryBinding, PayloadOutcome, RecordObservation};
use qualification::{PauseKind, PendingSnapshot, QualificationSnapshot};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, SyncSender};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    ArmA,
    DisarmA,
    ArmB,
    ScanB,
    Finish,
}
#[derive(Debug)]
struct Request {
    command: Command,
    witness: Option<QualificationSnapshot>,
}
#[derive(Debug)]
struct Ack {
    command: Command,
    pid: u32,
    controller_tid: u64,
    generation: u64,
}
struct Channel {
    request: SyncSender<Request>,
    ack: RefCell<Receiver<Ack>>,
    worker_tid: u64,
    deadline: Instant,
}
impl Channel {
    fn send(&self, command: Command, witness: Option<QualificationSnapshot>) -> u64 {
        assert!(Instant::now() < self.deadline);
        self.request.try_send(Request { command, witness }).unwrap();
        let ack = self
            .ack
            .borrow_mut()
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!((ack.command, ack.pid), (command, std::process::id()));
        assert_ne!(ack.controller_tid, self.worker_tid);
        assert!(ack.controller_tid > 0 && Instant::now() < self.deadline);
        ack.generation
    }
}
fn report_rows(
    controller: &EarlyEntryModuleSessionController,
    epoch: &IntervalEpoch,
    expected: usize,
) -> Vec<RecordObservation> {
    let report = controller.report(epoch).unwrap().unwrap();
    assert_eq!(report.generation(), epoch.generation());
    let rows: Vec<_> = report.records().collect();
    assert_eq!(rows.len(), expected);
    rows
}
fn controller_body(
    mut controller: EarlyEntryModuleSessionController,
    mut banks: Vec<IntervalEpochStorage>,
    rx: Receiver<Request>,
    tx: SyncSender<Ack>,
    worker_tid: u64,
    k: usize,
    deadline: Instant,
) -> (
    EarlyEntryModuleSessionController,
    NormalModuleHistoryBatch,
    Vec<RecordObservation>,
) {
    let epoch_a = controller.stage_prepared(banks.pop().unwrap()).unwrap();
    let mut epoch_b = None;
    let mut records = Vec::new();
    for command in [
        Command::ArmA,
        Command::DisarmA,
        Command::ArmB,
        Command::ScanB,
        Command::Finish,
    ] {
        let request = rx
            .recv_timeout(
                deadline
                    .checked_duration_since(Instant::now())
                    .expect("15s deadline"),
            )
            .unwrap();
        assert_eq!(request.command, command);
        if let Some(s) = request.witness.as_ref() {
            assert_eq!(
                (s.pid, s.tid, s.position),
                (std::process::id(), worker_tid, Some(1))
            );
            assert_ne!(s.tid, tid());
            assert_eq!(s.model_depth, usize::from(command == Command::DisarmA));
            match command {
                Command::ArmA => {
                    assert_eq!(
                        (s.active_batch, s.completed_batches, s.completed_calls),
                        (Some(3), 2, 8)
                    );
                    assert_eq!(s.entry_seen, [None; 4]);
                    assert!(s.pending.is_none());
                }
                Command::DisarmA => {
                    assert_eq!(
                        (s.active_batch, s.completed_batches, s.completed_calls),
                        (Some(4), 3, 12)
                    );
                    assert_eq!(s.entry_seen, [Some(4), None, None, None]);
                    let p = s.pending.as_ref().unwrap();
                    assert_eq!(
                        (p.physical_batch, p.physical_position, p.ordinal),
                        (4, 0, 4)
                    );
                    assert!(p.returned.is_some());
                    assert_eq!(p.summary, p.actual_summary);
                    assert!(
                        matches!(p.summary.unwrap().owner, RawIntervalOwner::Sampled { generation, .. } if generation == epoch_a.generation().get())
                    );
                    assert!(controller.report(&epoch_a).unwrap().is_none());
                }
                _ => panic!("unexpected callback request"),
            }
        } else {
            assert!(!matches!(command, Command::ArmA | Command::DisarmA));
        }
        let generation = match command {
            Command::ArmA => {
                controller.arm(&epoch_a).unwrap();
                epoch_a.generation().get()
            }
            Command::DisarmA => {
                controller.disarm(&epoch_a).unwrap();
                assert!(controller.report(&epoch_a).unwrap().is_none());
                epoch_a.generation().get()
            }
            Command::ArmB => {
                records.extend(report_rows(&controller, &epoch_a, 4));
                let next = controller.stage_prepared(banks.pop().unwrap()).unwrap();
                assert!(next.generation().get() > epoch_a.generation().get());
                controller.arm(&next).unwrap();
                let generation = next.generation().get();
                epoch_b = Some(next);
                generation
            }
            Command::ScanB => {
                assert_eq!(controller.scan_closed().unwrap(), 2);
                epoch_b.as_ref().unwrap().generation().get()
            }
            Command::Finish => {
                let b = epoch_b.as_ref().unwrap();
                controller.disarm(b).unwrap();
                records.extend(report_rows(&controller, b, 2 * k));
                b.generation().get()
            }
        };
        tx.try_send(Ack {
            command,
            pid: std::process::id(),
            controller_tid: tid(),
            generation,
        })
        .unwrap();
        assert!(Instant::now() < deadline);
    }
    assert_eq!(banks.len(), 1);
    let history = controller.drain_history().unwrap().unwrap();
    assert_eq!(history.range(), 0..6);
    assert_eq!(
        history.actions().iter().map(|a| a.kind).collect::<Vec<_>>(),
        [
            ActionKind::Published,
            ActionKind::Removed,
            ActionKind::Published,
            ActionKind::Deferred,
            ActionKind::Deferred,
            ActionKind::Removed
        ]
    );
    let a = epoch_a.generation();
    let b = epoch_b.as_ref().unwrap().generation();
    assert_eq!(
        history
            .actions()
            .iter()
            .map(|r| r.generation)
            .collect::<Vec<_>>(),
        [a, a, b, b, b, b]
    );
    assert_eq!(history.actions()[3].function, Some(FunctionId(11)));
    assert_eq!(history.actions()[4].function, Some(FunctionId(29)));
    assert_eq!(history.before(), HistoryBinding::Initial);
    assert!(controller.history_window().unwrap().current().is_none());
    (controller, history, records)
}

fn run(k: usize, order: [usize; 2]) {
    let deadline = Instant::now().checked_add(Duration::from_secs(15)).unwrap();
    pin(None);
    let mut signals: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigfillset(&mut signals) }, 0);
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
    let csv_index = usize::from(csv.elf_range().0 > length.elf_range().0);
    let selections = if csv_index == 0 {
        [&csv, &length]
    } else {
        [&length, &csv]
    };
    // SAFETY: exact independently authenticated C sources/final ELFs; sealed
    // private loader, complete scalar 0..=64 input semantics and inactive CET.
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
    // SAFETY: same exact admitted 123-byte C caller, retained sealed mappings.
    let caller = unsafe { LoadedNormalModuleCaller::load_sealed(&caller_selection) }.unwrap();
    let words = caller.continuations();
    let mut policies = [NormalModulePreparationPolicy::WholeFunction; 2];
    policies[csv_index] = NormalModulePreparationPolicy::CertifiedBlocks;
    let site = publish(
        EarlyEntryModuleSitePreparation::new_with_policies(loaded, identity(entries[0]), policies)
            .unwrap(),
    );
    assert_eq!(
        site.gates()
            .iter()
            .map(|g| g.logical_pc)
            .collect::<Vec<_>>(),
        entries
    );
    let ids = [FunctionId(11), FunctionId(29)];
    let mut prepared =
        PreparedEarlyEntryModuleSessionController::new(site, 0x6f77_6e02, ids, k).unwrap();
    let banks = prepared.prepare_epoch_storage().unwrap();
    assert_eq!(banks.len(), 3);
    // SAFETY: pristine process, one owned caller, no foreign entry/unload/writer;
    // controller thread mutates only metadata, never holds a callback dependency.
    let (controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    // SAFETY: both full C contracts cover every safe-accepted input; real worker
    // owns its whole stack and retained caller, no signal/reentry/nonlocal exit.
    let mut worker =
        unsafe { client.attach_owned(caller, order, 1, stack(), IntervalJournal::allocate()) }
            .unwrap();
    let close = worker.close_handle();
    let worker_tid = tid();
    let (request_tx, request_rx) = mpsc::sync_channel(1);
    let (ack_tx, ack_rx) = mpsc::sync_channel(1);
    let controller_thread = std::thread::spawn(move || {
        controller_body(
            controller, banks, request_rx, ack_tx, worker_tid, k, deadline,
        )
    });
    let channel = Rc::new(Channel {
        request: request_tx,
        ack: RefCell::new(ack_rx),
        worker_tid,
        deadline,
    });
    let hook_channel = Rc::clone(&channel);
    let old_returned = Rc::new(RefCell::new(None::<(PendingSnapshot, [u64; 512])>));
    let hook_old = Rc::clone(&old_returned);
    // SAFETY: callback observer runs only after both actual borrows/model locks
    // release. It sends copied witnesses to a real distinct controller and waits
    // at most two seconds; it does not mutate model/native state on the worker.
    unsafe {
        qualification::install_observer(move |kind, s| {
            assert_eq!((s.pid, s.tid), (std::process::id(), worker_tid));
            if kind != PauseKind::AfterPreRetPublished {
                return;
            }
            match (s.active_batch, s.position) {
                (Some(3), Some(1)) => {
                    hook_channel.send(Command::ArmA, Some(s.clone()));
                }
                (Some(4), Some(1)) => {
                    *hook_old.borrow_mut() = Some((s.pending.unwrap(), s.journal));
                    hook_channel.send(Command::DisarmA, Some(s.clone()));
                }
                (Some(4), Some(2..=4)) => {
                    let saved = hook_old.borrow();
                    let (pending, journal) = saved.as_ref().unwrap();
                    assert_eq!(s.pending.as_ref(), Some(pending));
                    assert_eq!(&s.journal, journal);
                    assert_eq!(s.entry_seen, [Some(4), None, None, None]);
                }
                _ => {}
            }
        })
    }
    .unwrap();
    let csv_input = *b"a,\"b,c\"";
    let length_input = *b"x\0z";
    let inputs = order.map(|i| {
        if i == csv_index {
            csv_input.as_slice()
        } else {
            length_input.as_slice()
        }
    });
    let values = order.map(|i| if i == csv_index { 2 } else { 1 });
    let expected_values = [values[0], values[1], values[0], values[1]];
    let batches = k / 2 + 6;
    let mut records = Vec::new();
    let mut ordinal = 1;
    let mut generation_a = None;
    let mut generation_b = None;
    for batch in 1..=batches {
        if batch == 5 {
            generation_b = Some(channel.send(Command::ArmB, None));
        }
        if batch == batches {
            channel.send(Command::ScanB, None);
        }
        let observed = match batch {
            1 | 2 => [false; 4],
            3 => [false, true, true, true],
            4 => [true, false, false, false],
            n if n == batches => [false; 4],
            _ => [true; 4],
        };
        let result = worker
            .run_batch(NormalModuleInputs::new(inputs[0], inputs[1]).unwrap())
            .unwrap();
        assert_eq!(
            (
                result.batch,
                result.completed_calls,
                result.sum,
                result.values
            ),
            (batch as u64, batch as u64 * 4, 6, expected_values)
        );
        assert_eq!(csv_input, *b"a,\"b,c\"");
        assert_eq!(length_input, *b"x\0z");
        let sparse = result
            .observations
            .as_ref()
            .map(|o| o.records())
            .unwrap_or(&[]);
        assert_eq!(sparse.len(), observed.into_iter().filter(|v| *v).count());
        let mut sparse_index = 0;
        for (position, row) in result.physical.iter().enumerate() {
            assert_eq!(
                (row.batch, row.position, row.function, row.return_word),
                (
                    batch as u64,
                    position,
                    ids[order[position % 2]],
                    words[position]
                )
            );
            assert_eq!(row.entry_rsp, result.physical[0].entry_rsp);
            if observed[position] {
                assert_eq!(row.observed_ordinal, Some(ordinal));
                let r = sparse[sparse_index];
                sparse_index += 1;
                assert_eq!(
                    (
                        r.function,
                        r.record.raw.ordinal,
                        r.record.raw.entry_pc,
                        r.record.raw.return_pc,
                        r.record.entry_rsp,
                        r.record.return_word
                    ),
                    (
                        row.function,
                        ordinal,
                        entries[order[position % 2]],
                        row.return_pc,
                        row.entry_rsp,
                        row.return_word
                    )
                );
                let expected_generation = if batch <= 4 {
                    let RawIntervalOwner::Sampled { generation, .. } = r.record.raw.owner else {
                        panic!("epoch A")
                    };
                    if let Some(a) = generation_a {
                        assert_eq!(a, generation);
                    } else {
                        generation_a = Some(generation);
                    }
                    generation
                } else {
                    generation_b.unwrap()
                };
                if batch == batches - 1 {
                    assert_eq!(
                        r.record.raw.owner,
                        RawIntervalOwner::FunctionClosed {
                            generation: expected_generation
                        }
                    );
                } else {
                    assert!(
                        matches!(r.record.raw.owner, RawIntervalOwner::Sampled { generation, .. } if generation == expected_generation)
                    );
                }
                let ack = if sparse_index == sparse.len() {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: ordinal + 1,
                    }
                };
                assert_eq!(r.record.acknowledgement, ack);
                records.push(r);
                ordinal += 1;
            } else {
                assert_eq!(row.observed_ordinal, None);
            }
        }
        assert!(Instant::now() < deadline);
    }
    assert!(old_returned.borrow().is_some());
    channel.send(Command::Finish, None);
    while !controller_thread.is_finished() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let (controller, history, reports) = controller_thread.join().unwrap();
    assert_eq!(records.len(), 2 * k + 8);
    assert_eq!(reports.len(), 2 * k + 4);
    for r in &records {
        let generation = match r.record.raw.owner {
            RawIntervalOwner::Sampled { generation, .. }
            | RawIntervalOwner::FunctionClosed { generation } => generation,
            _ => panic!("unexpected owner"),
        };
        assert!(
            matches!(history.binding_at(r.record.history_prefix), Some(HistoryBinding::Published { generation: g, .. }) if g.get() == generation)
        );
    }
    let mut keys = std::collections::BTreeSet::new();
    let mut ranks = std::collections::BTreeMap::new();
    for (sequence, r) in records
        .iter()
        .filter(|r| matches!(r.record.raw.owner, RawIntervalOwner::Sampled { .. }))
        .enumerate()
    {
        let RawIntervalOwner::Sampled {
            generation,
            invocation,
        } = r.record.raw.owner
        else {
            unreachable!()
        };
        assert!(keys.insert((generation, invocation, r.function.0)));
        let rank = ranks.entry((generation, r.function.0)).or_insert(0_usize);
        let matching: Vec<_> = reports
            .iter()
            .filter(|row| {
                row.record.admission.generation.get() == generation
                    && row.record.admission.invocation == invocation
            })
            .collect();
        assert_eq!(matching.len(), 1);
        let model = matching[0];
        let payload = model.payload.unwrap();
        assert_eq!(
            (
                model.record.admission.function,
                model.record.admission.entry_value
            ),
            (r.function, r.record.raw.start.ticks)
        );
        assert_eq!(payload.admission, model.record.admission);
        assert_eq!(
            (payload.thread, payload.start_sequence),
            (1, sequence as u64)
        );
        assert_eq!(
            payload.outcome,
            PayloadOutcome::Completed {
                end: r.record.raw.observation(),
                completed_children: 0
            }
        );
        assert_eq!(
            model.record.terminal,
            Some(crate::generation::Terminal::Completed {
                value: invocation as u64,
                disposition: crate::generation::Disposition::Retained { rank: *rank }
            })
        );
        *rank += 1;
    }
    assert_eq!(
        keys,
        reports
            .iter()
            .map(|r| (
                r.record.admission.generation.get(),
                r.record.admission.invocation,
                r.record.admission.function.0
            ))
            .collect()
    );
    for function in ids {
        assert_eq!(ranks.get(&(generation_a.unwrap(), function.0)), Some(&2));
        assert_eq!(ranks.get(&(generation_b.unwrap(), function.0)), Some(&k));
    }
    assert_eq!(close.request(), NormalModuleCloseState::Closing);
    assert!(
        worker
            .run_batch(NormalModuleInputs::new(&[], &[]).unwrap())
            .is_err()
    );
    let totals = worker.finish().unwrap();
    assert_eq!(
        totals,
        NormalTotals {
            entered: (2 * k + 8) as u64,
            ret_observed: (2 * k + 8) as u64,
            confirmed: (2 * k + 8) as u64,
            completed: (2 * k + 4) as u64,
            unsampled: 4
        }
    );
    assert_eq!(close.state(), NormalModuleCloseState::Closed);
    assert!(worker.finish().is_err());
    assert!(NORMAL.with(|c| c.borrow().0.is_none()));
    assert!(PHYSICAL.with(|c| c.borrow().is_none()));
    drop(worker);
    drop(controller);
    assert_eq!(close.state(), NormalModuleCloseState::Closed);
    assert!(Instant::now() < deadline);
    eprintln!(
        "early-entry-owned: k={k} order={}{} batches={batches} calls={} observed={} sampled={} unsampled=4 bypass=16 epochs=2 reports={} history=6 post_k=4 returned_bypass=3 closed=true",
        order[0],
        order[1],
        batches * 4,
        2 * k + 8,
        2 * k + 4,
        2 * k + 4
    );
}
#[test]
#[ignore = "fixed fresh release process, exact admitted C fixtures and 15s deadline"]
fn early_entry_owned_module_k10_order01() {
    run(10, [0, 1]);
}
#[test]
#[ignore = "fixed fresh release process, exact admitted C fixtures and 15s deadline"]
fn early_entry_owned_module_k10_order10() {
    run(10, [1, 0]);
}
#[test]
#[ignore = "fixed fresh release process, exact admitted C fixtures and 15s deadline"]
fn early_entry_owned_module_k1000_order01() {
    run(1000, [0, 1]);
}
#[test]
#[ignore = "fixed fresh release process, exact admitted C fixtures and 15s deadline"]
fn early_entry_owned_module_k1000_order10() {
    run(1000, [1, 0]);
}
