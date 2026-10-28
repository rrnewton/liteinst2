//! Required explicit fresh-process tree ownership control, not a state oracle.
use super::*;
use crate::frontend_native::{
    InstalledTreeSite, LoadedCallTree, PreparedTreeController, TreeCallGate, TreeContract,
    TreeController, TreeRecord, TreeSitePreparation, TreeTotals,
};

const FUNCTIONS: [FunctionId; 2] = [FunctionId(1), FunctionId(2)];
const INSTALL: u64 = 0x7472_6565;
const EXTERNAL: u64 = 0x7472_0001;
const VALUE: u64 = 0x37ac_32a6_0897_73d6;
const TREE_CONTRACT: TreeContract = TreeContract {
    root_only_external_entry: true,
    ordinary_ret_only: true,
    no_active_cet: true,
};
#[repr(C, align(64))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Input([u8; 1152]);
fn input() -> Input {
    let mut input = Input([0xa5; 1152]);
    input.0[1088..].fill(0x5a);
    let bytes = &mut input.0[64..1088];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (37 * i + 11) as u8;
    }
    for node in 0..16 {
        let next = match node {
            0 => 4,
            4 => 0,
            _ => node,
        };
        bytes[node * 64..node * 64 + 8].copy_from_slice(&((next * 64) as u64).to_le_bytes());
        bytes[node * 64 + 8..node * 64 + 16].copy_from_slice(
            &0x9e37_79b9_7f4a_7c15_u64
                .wrapping_mul(node as u64 + 1)
                .to_le_bytes(),
        );
    }
    bytes[16..24].copy_from_slice(&64_u64.to_le_bytes());
    input
}
fn publish_tree(prep: TreeSitePreparation) -> InstalledTreeSite {
    // The fresh exact-test process has one exclusive fresh DSO owner. The passive
    // libtest harness has no gate/subject capability, and no helper exists yet.
    // No signal/foreign entry, saved resume, source writer or callable escape.
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert_eq!(originals.len(), 1);
    let source = AddressRange::new(originals[0].address, originals[0].bytes.len()).unwrap();
    assert_eq!(source.start() % 4096, 0);
    assert_eq!(source.len(), 4096);
    assert_eq!(planned.plan().steps().len(), 4);
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    // SAFETY: exclusive complete source page and no live native call.
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let result = {
        // SAFETY: the borrowed preparation excludes every source entry capability.
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
            eprintln!("tree publication FAILED: {failure:?}");
            std::process::abort();
        }
    };
    // SAFETY: exact successful publication, final RX and exclusive new-source proof.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

struct ResumeAll([Arc<EntryPause>; 3]);
impl Drop for ResumeAll {
    fn drop(&mut self) {
        for pause in &self.0 {
            pause.resume.store(true, Ordering::Release);
        }
    }
}
struct OwnerDone {
    controller: TreeController,
    epochs: [IntervalEpoch; 3],
    reports: [Report; 3],
}
struct OwnerWorker {
    handle: Option<JoinHandle<OwnerDone>>,
    done: Option<mpsc::SyncSender<()>>,
    pauses: [Arc<EntryPause>; 3],
}
impl OwnerWorker {
    fn wait(&self) {
        let until = Instant::now() + WAIT;
        while !self.handle.as_ref().unwrap().is_finished() {
            if Instant::now() >= until {
                std::process::abort();
            }
            thread::yield_now();
        }
    }
    fn joined(&mut self) -> OwnerDone {
        self.done.take().unwrap().send(()).unwrap();
        self.wait();
        self.handle
            .take()
            .unwrap()
            .join()
            .expect("tree controller helper failed")
    }
}
impl Drop for OwnerWorker {
    fn drop(&mut self) {
        for pause in &self.pauses {
            pause.resume.store(true, Ordering::Release);
        }
        self.done.take();
        if self.handle.is_some() {
            self.wait();
            let _ = self.handle.take().unwrap().join();
        }
    }
}
fn report_row(report: &Report, row: &TreeRecord, generation: u64, children: u64) {
    assert_eq!(report.generation().get(), generation);
    let records: Vec<_> = report.records().collect();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    let admission = record.record.admission;
    assert_eq!(admission.generation.get(), generation);
    assert_eq!(admission.function, row.function());
    assert_eq!(admission.invocation, 0); // distinct original owners, each first admission
    assert_eq!(admission.entry_value, row.raw().start.ticks);
    assert_eq!(
        row.raw().owner,
        RawIntervalOwner::Sampled {
            generation,
            invocation: 0
        }
    );
    assert_eq!(
        record.record.terminal,
        Some(Terminal::Completed {
            value: 0,
            disposition: Disposition::Retained { rank: 0 }
        })
    );
    let payload = record.payload.unwrap();
    assert_eq!(payload.admission, admission);
    assert_eq!(payload.thread, 1);
    assert_eq!(payload.start_sequence, 0);
    assert!(row.raw().elapsed_ticks().is_some());
    assert_eq!(
        payload.outcome,
        PayloadOutcome::Completed {
            end: Observation::Value(row.raw().end.ticks),
            completed_children: children
        }
    );
    assert_eq!(row.model_start_sequence(), Some(0));
    assert_eq!(row.model_completed_children(), Some(children));
}

#[test]
#[ignore = "requires release tree fixture reproducer"]
fn tree_native_root_child_keep_distinct_owners_until_actual_returns() {
    let candidate = std::env::var_os("RAPID_TREE_CANDIDATE").expect("candidate ELF");
    let expected = std::env::var_os("RAPID_TREE_EXPECTED").expect("independent expected ELF");
    let candidate = Path::new(&candidate);
    let bytes = expected_file(candidate, Path::new(&expected));
    let cpu = pin(None);
    // SAFETY: fixed trusted constructor/dependency-free DSO, one local calling
    // worker, exact immutable offset-linked input, no CET/signals/foreign entry,
    // source writer/fork/unwind/unload; full writable callback stack is mapped.
    let owner = unsafe {
        LoadedCallTree::load(
            candidate,
            &bytes,
            c"call_tree_root",
            c"call_tree_child",
            TREE_CONTRACT,
        )
    }
    .unwrap();
    let root = owner.certificate().root().entry();
    let gate = TreeCallGate::new(owner.certificate().root()).unwrap();
    let continuation = gate.continuation();
    let mut prep = TreeSitePreparation::new(owner, gate, identity(root)).unwrap();
    let mut roles: Vec<_> = prep.role_pcs().collect();
    roles.sort();
    assert_eq!(roles, [root, root + 14, root + 22, root + 32, root + 70]);
    let input = input();
    let before = input.clone();
    let readable = stack();
    let original = unsafe { prep.prepare_original_call() }.unwrap();
    let original = unsafe { original.invoke(&input.0[64..1088], &readable) }.unwrap();
    assert_eq!(original.value, VALUE);
    assert_eq!(original.pre_call_rsp, original.resumed_rsp);
    assert_eq!(input, before);
    let mut prepared = PreparedTreeController::new(
        publish_tree(prep),
        INSTALL,
        FUNCTIONS,
        Limits {
            epochs: 3,
            threads: 1,
            depth: 2,
            records_per_epoch: 2,
            actions: 8,
        },
    )
    .unwrap();
    let config = Config {
        retained_per_function: 1,
        max_inflight: 2,
        max_invocations: 2,
    };
    let epochs = [
        prepared.stage(config).unwrap(),
        prepared.stage(config).unwrap(),
        prepared.stage(config).unwrap(),
    ];
    let generations = epochs.each_ref().map(|e| e.generation());
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let pauses = [
        Arc::new(EntryPause::new(1)),
        Arc::new(EntryPause::new(2)),
        Arc::new(EntryPause::new(1)),
    ];
    controller
        .native_pauses(pauses.each_ref().map(Arc::clone))
        .unwrap();
    // Invocation authority and its mutable loader verifier never leave this thread.
    let mut attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let helper_pauses = pauses.each_ref().map(Arc::clone);
    let handle = thread::spawn(move || {
        pin(Some(cpu));
        let resume = ResumeAll(helper_pauses);
        controller.arm(&epochs[0]).unwrap();
        ready_tx.send(()).unwrap();
        until(|| resume.0[0].entered.load(Ordering::Acquire));
        assert!(controller.report(&epochs[0]).unwrap().is_none());
        controller.arm(&epochs[1]).unwrap();
        assert!(controller.report(&epochs[0]).unwrap().is_none());
        resume.0[0].resume.store(true, Ordering::Release);
        until(|| resume.0[1].entered.load(Ordering::Acquire));
        controller.arm(&epochs[2]).unwrap();
        // Both original owners are still live before the actual child C3.
        assert!(controller.report(&epochs[0]).unwrap().is_none());
        assert!(controller.report(&epochs[1]).unwrap().is_none());
        resume.0[1].resume.store(true, Ordering::Release);
        until(|| resume.0[2].entered.load(Ordering::Acquire));
        // The child returned to real root+14; root C3 has not executed yet.
        let child = controller
            .report(&epochs[1])
            .unwrap()
            .expect("B completes only after child continuation ACK");
        assert_eq!(child.records().count(), 1);
        assert!(controller.report(&epochs[0]).unwrap().is_none());
        resume.0[2].resume.store(true, Ordering::Release);
        // The calling thread sends only after real outer return and postflight.
        done_rx
            .recv_timeout(WAIT)
            .expect("actual successful tree invoke");
        let root = controller
            .report(&epochs[0])
            .unwrap()
            .expect("A completes after actual outer return and postflight");
        controller.disarm(&epochs[2]).unwrap();
        let current = controller
            .report(&epochs[2])
            .unwrap()
            .expect("unused C closed");
        assert_eq!(current.records().count(), 0);
        OwnerDone {
            controller,
            epochs,
            reports: [root, child, current],
        }
    });
    let mut worker = OwnerWorker {
        handle: Some(handle),
        done: Some(done_tx),
        pauses,
    };
    ready_rx.recv_timeout(WAIT).unwrap();
    let call = unsafe { attached.invoke_tree(&input.0[64..1088], EXTERNAL) }.unwrap();
    assert_eq!(call.external_id, EXTERNAL);
    assert_eq!(call.value, VALUE);
    assert_eq!(call.pre_call_rsp, call.resumed_rsp);
    assert_eq!(call.entry_rsp.checked_add(8), Some(call.pre_call_rsp));
    assert_eq!(call.return_pc, root + 22);
    assert_eq!(input, before);
    let mut done = worker.joined();
    assert!(worker.handle.is_none());
    let totals = attached.totals().unwrap();
    assert_eq!(
        totals,
        TreeTotals {
            roots: 1,
            pairs: PairTotals {
                entries: 2,
                returns: 2,
                completed: 2,
                unsampled: 0
            }
        }
    );
    let batch = attached
        .drain_completed()
        .unwrap()
        .expect("one complete tree");
    assert_eq!(batch.functions(), FUNCTIONS);
    assert_eq!(
        (batch.install(), batch.registration(), batch.number()),
        (INSTALL, 1, 1)
    );
    assert_eq!(batch.pid(), std::process::id());
    assert_eq!(batch.tid(), unsafe { libc::syscall(libc::SYS_gettid) }
        as u64);
    assert_eq!(batch.gate_base().checked_add(1), Some(call.gate_sequence));
    assert_eq!(batch.gate_sequence(), call.gate_sequence);
    assert_eq!(batch.completed_sequences(), (0, 2));
    assert_eq!(
        batch.totals(),
        (
            TreeTotals {
                roots: 0,
                pairs: PairTotals::default()
            },
            totals
        )
    );
    let rows = batch.rows();
    assert_eq!(rows.len(), 2);
    let root_row = &rows[0];
    let child_row = &rows[1];
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.external_id(), EXTERNAL);
        assert_eq!(row.node(), i as u8);
        assert_eq!(row.function(), FUNCTIONS[i]);
        assert_eq!(row.depth(), i); // public record depth is zero-based, unlike active frame count
        assert_eq!(row.registration(), 1);
        assert_eq!(row.gate_sequence(), call.gate_sequence);
        assert_eq!(row.raw().ordinal, i as u64 + 1);
        assert_eq!(row.history_prefix(), i + 1);
    }
    assert_eq!(root_row.parent(), None);
    assert_eq!(root_row.callsite(), None);
    assert_eq!(child_row.parent(), Some((EXTERNAL, 0)));
    assert_eq!(child_row.callsite(), Some(root + 9));
    assert_eq!(
        (root_row.raw().entry_pc, root_row.raw().return_pc),
        (root, root + 22)
    );
    assert_eq!(
        (child_row.raw().entry_pc, child_row.raw().return_pc),
        (root + 32, root + 70)
    );
    assert_eq!(
        (
            root_row.entry_rsp(),
            root_row.return_word(),
            root_row.resume_pc(),
            root_row.resume_rsp(),
            root_row.value()
        ),
        (
            call.entry_rsp,
            continuation,
            continuation,
            call.pre_call_rsp,
            VALUE
        )
    );
    assert_eq!(
        (
            child_row.entry_rsp(),
            child_row.return_word(),
            child_row.resume_pc(),
            child_row.resume_rsp(),
            child_row.value()
        ),
        (
            call.entry_rsp - 16,
            root + 14,
            root + 14,
            call.entry_rsp - 8,
            VALUE - 1
        )
    );
    report_row(&done.reports[0], root_row, generations[0].get(), 1);
    report_row(&done.reports[1], child_row, generations[1].get(), 0);
    let journal = batch.journal();
    assert_eq!(journal.len(), 512);
    assert_eq!(&journal[..4], &[4, 0, batch.tid(), 0]);
    assert!(journal[32..].iter().all(|&x| x == 0));
    for (event, (row, kind, bits, generation)) in [
        (root_row, 1, 8193, generations[0]),
        (child_row, 1, 16385, generations[1]),
        (child_row, 2, 16385, generations[1]),
        (root_row, 2, 8193, generations[0]),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            &journal[4 + event * 7..11 + event * 7],
            &[
                kind,
                row.raw().ordinal,
                if kind == 1 {
                    row.raw().entry_pc
                } else {
                    row.raw().return_pc
                },
                row.entry_rsp(),
                row.return_word(),
                generation.get(),
                bits
            ]
        );
    }
    assert!(attached.drain_completed().unwrap().is_none());
    assert_eq!(attached.detach().unwrap(), totals);
    let history = done.controller.history().unwrap();
    assert_eq!(history.status, ControllerStatus::Ready);
    assert_eq!(history.current, None);
    assert_eq!(history.enabled, [true, true]);
    assert_eq!(history.retained_failed_generation, None);
    assert_eq!(
        history.actions,
        vec![
            Action {
                kind: ActionKind::Published,
                generation: generations[0],
                function: None,
                current: Some(generations[0]),
                group: None
            },
            Action {
                kind: ActionKind::Published,
                generation: generations[1],
                function: None,
                current: Some(generations[1]),
                group: None
            },
            Action {
                kind: ActionKind::Published,
                generation: generations[2],
                function: None,
                current: Some(generations[2]),
                group: None
            },
            Action {
                kind: ActionKind::Removed,
                generation: generations[2],
                function: None,
                current: None,
                group: None
            },
        ]
    );
    for (epoch, report) in done.epochs.iter().zip(&done.reports) {
        let retired = done.controller.retire(epoch).unwrap();
        assert_eq!(retired.generation(), report.generation());
        assert_eq!(
            retired.records().collect::<Vec<_>>(),
            report.records().collect::<Vec<_>>()
        );
    }
    assert_eq!(input, before);
    println!(
        "tree-owner-native PASS originals=1 roots=1 entries=2 returns=2 sampled=2 rows=2 events=4 reports=1+1+0 root_owner=A child_owner=B rearmed_owner=C child_pending_before_ret=true root_pending_before_ret=true actual_outer_return=true input_unchanged=true joined=true"
    );
}

mod batch_owner_native;
