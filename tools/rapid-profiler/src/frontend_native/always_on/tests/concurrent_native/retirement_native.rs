//! Separate exact-test processes; real calls, not register-state qualification.
use super::*;

const MANY: [usize; 16] = [1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64, 1, 64];
const CLOSED: [usize; 2] = [1, 64];
const ONE: Config = Config {
    retained_per_function: 1,
    max_inflight: 1,
    max_invocations: 6,
};

struct Fixture {
    // Fields drop in declaration order: resume/join the worker before closing
    // controller epochs or releasing the remaining harness data on any panic.
    worker: Worker,
    controller: IntervalController,
    ack: mpsc::Receiver<(u64, RawInterval)>,
    input: Arc<[u8; 96]>,
    before: [u8; 96],
    originals: Vec<u64>,
    entry: u64,
    continuation: u64,
    returns: BTreeSet<u64>,
}
impl Fixture {
    fn new(lengths: &'static [usize], pause_ordinal: u64) -> Self {
        assert!(matches!(lengths.len(), 2 | 16));
        let candidate = std::env::var_os("RAPID_CONCURRENT_CANDIDATE").expect("candidate ELF");
        let expected =
            std::env::var_os("RAPID_CONCURRENT_EXPECTED").expect("independent expected ELF");
        let candidate = Path::new(&candidate);
        let bytes = expected_file(candidate, Path::new(&expected));
        let cpu = pin(None);
        // SAFETY: one exact test in a fresh process, trusted constructor/dependency-
        // free local DSO, no foreign subject capability, CET, signals, unwind,
        // alias writer or unload. The full loader and factory checks are unchanged.
        let owner = unsafe {
            LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum_nonempty", CONTRACT)
        }
        .unwrap();
        let entry = owner.entry();
        let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
        let gate = CallGate::new(owner.certificate()).unwrap();
        let continuation = gate.continuation();
        let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
        assert_eq!(
            prep.role_pcs().collect::<Vec<_>>(),
            std::iter::once(entry)
                .chain(returns.iter().copied())
                .collect::<Vec<_>>()
        );
        let before = guarded();
        let input = Arc::new(before);
        let original_stack = stack();
        let mut originals = Vec::with_capacity(lengths.len());
        for &length in lengths {
            let slice = &input[16..16 + length];
            // SAFETY: the uninstalled owner is exclusive; fixed valid nonempty
            // immutable input and the actual mapped stack remain live through RET.
            let original =
                unsafe { prep.invoke_original(slice.as_ptr(), slice.len(), &original_stack) }
                    .unwrap();
            assert_eq!(original.value, model(slice));
            assert_eq!(original.pre_call_rsp, original.resumed_rsp);
            assert_eq!(*input, before);
            originals.push(original.value);
        }
        let prepared = PreparedIntervalController::new(
            publish(prep),
            0x7265_7401,
            FUNCTION,
            Limits {
                epochs: 1,
                threads: 1,
                depth: 1,
                records_per_epoch: 6,
                actions: 32,
            },
        )
        .unwrap();
        // SAFETY: no fork/TLS/outstanding call; only the joined worker below
        // receives invocation authority after exclusive publication and sealing.
        let (controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
        let pause = Arc::new(EntryPause::new(pause_ordinal));
        if pause_ordinal != 0 {
            assert!(
                controller
                    .binding
                    .native_entry_pause
                    .set(Arc::clone(&pause))
                    .is_ok()
            );
        }
        let (command_tx, command_rx) = mpsc::sync_channel(1);
        let (ack_tx, ack) = mpsc::sync_channel(1);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker_input = Arc::clone(&input);
        let handle = thread::spawn(move || {
            pin(Some(cpu));
            let readable = stack();
            // SAFETY: sole invocation worker, no reentry/signal/nonlocal exit;
            // sealed source/generated owners and immutable input outlive every RET.
            let mut attached =
                unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
            let mut calls = Vec::with_capacity(lengths.len());
            ready_tx.send(()).unwrap();
            for (index, &length) in lengths.iter().enumerate() {
                let id = 1000 + index as u64;
                assert_eq!(command_rx.recv_timeout(WAIT).unwrap(), (id, length));
                assert_eq!(attached.raw_intervals().unwrap().len(), index);
                let slice = &worker_input[16..16 + length];
                // SAFETY: exact library CALL gate and admitted input/ABI contract.
                let result = unsafe { attached.invoke_integer_leaf(slice) }.unwrap();
                assert_eq!(result.value, model(slice));
                assert_eq!(result.pre_call_rsp, result.resumed_rsp);
                assert_eq!(result.entry_rsp.checked_add(8), Some(result.pre_call_rsp));
                assert_eq!(*worker_input, before);
                let rows = attached.raw_intervals().unwrap();
                assert_eq!(rows.len(), index + 1);
                assert_eq!(rows[index].ordinal, index as u64 + 1);
                calls.push(result);
                ack_tx.send((id, rows[index])).unwrap();
            }
            let totals = attached.totals().unwrap();
            let rows = attached.raw_intervals().unwrap();
            // Only the attached worker reads this non-atomic journal/TLS state.
            let (journal, tid) = STATE.with(|cell| {
                let storage = cell.borrow();
                let state = storage.as_ref().unwrap();
                assert_eq!(
                    (state.registration, state.depth, state.model.depth()),
                    (1, 0, 0)
                );
                assert_eq!(state.next, lengths.len() as u64 + 1);
                assert_eq!(state.model.completed_sequence(), totals.completed);
                assert!(state.pairs.iter().all(Option::is_none));
                assert!(state.failure.is_none());
                (state.journal.page.0, state.tid)
            });
            assert_eq!(attached.detach().unwrap(), totals);
            Done {
                calls,
                rows,
                totals,
                journal,
                tid,
            }
        });
        let worker = Worker {
            commands: Some(command_tx),
            pause,
            handle: Some(handle),
        };
        // The existing worker guard is already installed before any fallible wait.
        ready_rx
            .recv_timeout(WAIT)
            .expect("one attached worker ready");
        Self {
            worker,
            controller,
            ack,
            input,
            before,
            originals,
            entry,
            continuation,
            returns,
        }
    }

    fn send(&self, index: usize, length: usize) {
        self.worker
            .commands
            .as_ref()
            .unwrap()
            .send((1000 + index as u64, length))
            .unwrap();
    }

    fn receive(&self, index: usize) -> RawInterval {
        let (id, row) = self.ack.recv_timeout(WAIT).unwrap();
        assert_eq!((id, row.ordinal), (1000 + index as u64, index as u64 + 1));
        row
    }

    fn joined(
        &mut self,
        owners: &[RawIntervalOwner],
        bits: &[u64],
        acknowledged: &[RawInterval],
    ) -> Done {
        let done = self.worker.join();
        assert_eq!(*self.input, self.before);
        assert_eq!(Arc::strong_count(&self.input), 1);
        assert_eq!(done.rows.as_slice(), acknowledged);
        assert_eq!(
            (done.calls.len(), done.rows.len(), bits.len()),
            (self.originals.len(), owners.len(), owners.len())
        );
        assert_eq!(
            done.rows
                .iter()
                .map(|r| r.return_pc)
                .collect::<BTreeSet<_>>(),
            self.returns
        );
        assert_eq!(
            &done.journal[..4],
            &[2 * owners.len() as u64, 0, done.tid, 0]
        );
        assert!(
            done.journal[4 + owners.len() * 14..]
                .iter()
                .all(|&v| v == 0)
        );
        for (index, row) in done.rows.iter().enumerate() {
            let call = &done.calls[index];
            assert_eq!(
                (row.ordinal, row.entry_pc, row.return_pc),
                (index as u64 + 1, self.entry, call.return_pc)
            );
            assert_eq!(row.owner, owners[index]);
            assert_eq!(call.value, self.originals[index]);
            assert_eq!(call.pre_call_rsp, call.resumed_rsp);
            assert_eq!(call.entry_rsp.checked_add(8), Some(call.pre_call_rsp));
            assert!(
                row.elapsed_ticks().is_some(),
                "clock failure is not timing success"
            );
            let (kind, generation) = match owners[index] {
                RawIntervalOwner::Sampled { generation, .. } => (1, generation),
                RawIntervalOwner::FunctionClosed { generation } => (3, generation),
                other => panic!("unexpected retirement owner {other:?}"),
            };
            for side in 0..2 {
                let offset = 4 + (index * 2 + side) * 7;
                assert_eq!(
                    &done.journal[offset..offset + 7],
                    &[
                        kind + side as u64,
                        index as u64 + 1,
                        if side == 0 { self.entry } else { row.return_pc },
                        call.entry_rsp,
                        self.continuation,
                        generation,
                        bits[index],
                    ]
                );
            }
        }
        done
    }
}

fn expect_permit_retained(controller: &mut IntervalController) {
    let before = controller.history().unwrap();
    assert_eq!(controller.binding.session.retained_epochs(), 1);
    assert!(matches!(
        controller.stage(ONE),
        Err(BridgeError {
            cause: Cause::Setup(SetupError::EpochLimit)
        })
    ));
    assert_eq!(controller.history().unwrap(), before);
    assert_eq!(controller.epochs.len(), 1);
    assert!(controller.epochs[0].is_none());
    assert_eq!(controller.binding.session.retained_epochs(), 1);
}

fn action(kind: ActionKind, generation: GenerationId, current: Option<GenerationId>) -> Action {
    Action {
        kind,
        generation,
        function: None,
        current,
        group: None,
    }
}

#[test]
#[ignore = "requires release fixture reproducer"]
fn ordinary_native_retirement_sixteen_epochs() {
    let mut fixture = Fixture::new(&MANY, 0);
    let mut generations = BTreeSet::new();
    let mut owners = Vec::new();
    let mut bits = Vec::new();
    let mut rows = Vec::new();
    let mut actions = Vec::new();
    for (index, &length) in MANY.iter().enumerate() {
        let epoch = fixture.controller.stage(ONE).unwrap();
        assert_eq!(epoch.index, 0);
        assert!(generations.insert(epoch.generation()));
        fixture.controller.arm(&epoch).unwrap();
        fixture.send(index, length);
        let row = fixture.receive(index); // actual invoke/normal-return checks finished
        fixture.controller.disarm(&epoch).unwrap();
        let before = fixture.controller.history().unwrap();
        let report = fixture.controller.retire(&epoch).unwrap();
        assert_eq!(fixture.controller.history().unwrap(), before);
        check_report(&report, &[row], epoch.generation().get(), index as u64);
        expect_permit_retained(&mut fixture.controller);
        drop(report);
        assert_eq!(fixture.controller.binding.session.retained_epochs(), 0);
        owners.push(RawIntervalOwner::Sampled {
            generation: epoch.generation().get(),
            invocation: 0,
        });
        bits.push(1 | (((index * 2 + 1) as u64) << 13));
        rows.push(row);
        actions.push(action(
            ActionKind::Published,
            epoch.generation(),
            Some(epoch.generation()),
        ));
        actions.push(action(ActionKind::Removed, epoch.generation(), None));
        assert_eq!(fixture.controller.history().unwrap().actions, actions);
        assert!(matches!(
            fixture.controller.report(&epoch),
            Err(BridgeError {
                cause: Cause::Epoch
            })
        ));
    }
    let done = fixture.joined(&owners, &bits, &rows);
    assert_eq!(
        done.totals,
        PairTotals {
            entries: 16,
            returns: 16,
            completed: 16,
            unsampled: 0
        }
    );
    let history = fixture.controller.history().unwrap();
    assert_eq!(history.status, ControllerStatus::Ready);
    assert_eq!(history.current, None);
    assert_eq!(history.enabled, [true]);
    assert_eq!(history.retained_failed_generation, None);
    assert_eq!(history.actions, actions);
    assert_eq!((generations.len(), history.actions.len()), (16, 32));
    println!(
        "retirement-native PASS case=sixteen-epochs epochs=16 originals=16 calls=16 sampled=16 rows=16 events=32 actions=32 registrations=1 report_permit_refusals=16 joined=true"
    );
}

#[test]
#[ignore = "requires release fixture reproducer"]
fn ordinary_native_retirement_function_closed_receipt() {
    let mut fixture = Fixture::new(&CLOSED, 2);
    let epoch = fixture.controller.stage(ONE).unwrap();
    let generation = epoch.generation();
    fixture.controller.arm(&epoch).unwrap();
    fixture.send(0, CLOSED[0]);
    let first = fixture.receive(0);
    fixture.send(1, CLOSED[1]);
    until(|| fixture.worker.pause.entered.load(Ordering::Acquire));
    assert!(matches!(
        fixture.ack.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(!fixture.worker.handle.as_ref().unwrap().is_finished());
    // This real K-closed entry has committed its receipt; it has no reservation.
    assert_eq!(fixture.controller.owner(&epoch).unwrap().reservations(), 0);
    fixture.controller.disarm(&epoch).unwrap();
    let observed = fixture.controller.report(&epoch).unwrap().unwrap();
    let records: Vec<_> = observed.records().collect();
    let before = fixture.controller.history().unwrap();
    let retired = fixture.controller.retire(&epoch).unwrap();
    assert_eq!(fixture.controller.history().unwrap(), before);
    check_report(&retired, &[first], generation.get(), 0);
    assert_eq!(retired.records().collect::<Vec<_>>(), records);
    drop(observed);
    drop(retired);
    expect_permit_retained(&mut fixture.controller); // only the FunctionClosed receipt remains
    fixture.worker.pause.resume.store(true, Ordering::Release);
    let second = fixture.receive(1); // only after the actual normal-return validation
    let done = fixture.joined(
        &[
            RawIntervalOwner::Sampled {
                generation: generation.get(),
                invocation: 0,
            },
            RawIntervalOwner::FunctionClosed {
                generation: generation.get(),
            },
        ],
        &[8193, (1 << 13) | (3 << 22)],
        &[first, second],
    );
    assert_eq!(
        done.totals,
        PairTotals {
            entries: 2,
            returns: 2,
            completed: 1,
            unsampled: 1
        }
    );
    assert_eq!(records.len(), 1);
    assert_eq!(fixture.controller.binding.session.retained_epochs(), 0);
    // ER-RET-1: consumption releases the receipt inside the exit callback.
    // We assert success after verified return, not impossibility before that RET.
    let next = fixture.controller.stage(ONE).unwrap();
    assert_eq!(next.index, epoch.index);
    assert_ne!(next.generation(), generation);
    let history = fixture.controller.history().unwrap();
    assert_eq!(history.status, ControllerStatus::Ready);
    assert_eq!(history.current, None);
    assert_eq!(history.enabled, [true]);
    assert_eq!(history.retained_failed_generation, None);
    assert_eq!(
        history.actions,
        vec![
            action(ActionKind::Published, generation, Some(generation)),
            action(ActionKind::Removed, generation, None)
        ]
    );
    println!(
        "retirement-native PASS case=function-closed originals=2 calls=2 sampled=1 closed=1 rows=2 events=4 actions=2 report_ready_before_return=true receipt_permit_refusal=1 post_return_stage=true joined=true"
    );
}
