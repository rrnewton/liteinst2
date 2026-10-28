//! One exact release subprocess. Real driver operations, not a Clock-loop trial.
use super::super::*;
use crate::frontend::{Action, ActionKind, ControllerStatus, Observation, PayloadOutcome};
use crate::frontend_native::always_on::optional::{
    BackoffEntryPause, backoff_gate_checkpoint, backoff_native_publish,
};
use crate::frontend_native::always_on::{
    backoff_native_contract as CONTRACT, backoff_native_expected_file as expected_file,
    backoff_native_function as FUNCTION, backoff_native_guarded as guarded,
    backoff_native_identity as identity, backoff_native_model as model, backoff_native_pin as pin,
    backoff_native_stack as stack,
};
use crate::frontend_native::{
    LoadedIntegerLeaf, OptionalCallGate, OptionalSitePreparation, RawInterval,
};
use crate::generation::{Disposition, GenerationId, Terminal};
use liteinst2::contracts::Refusal;
use std::collections::BTreeSet;
use std::path::Path;
use std::thread::{self, JoinHandle};

const COUNT: usize = 13;
const INSTALL: u64 = 0x6f62_6e61_7469_0001;
const WAIT: Duration = Duration::from_secs(2);
const TERMINAL: &str = "optional-backoff-native PASS originals=13 calls=13 fast=1 slow=12 sampled=12 unsampled=0 batches=13 events=24 history_batches=5 actions=5 epochs=3 retired=3 report_records=12 registrations=1 post_disable_fast=1 post_rearm_sampled=2 inflight_old_owner=1 worker_joins=1 short_ret_refusals=1 detached=true input_unchanged=true";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Request {
    id: u64,
    length: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Reply {
    request: Request,
    call: OptionalCallResult,
}
enum Ack {
    Ready { tid: u64, base: u64 },
    Returned(Reply),
}
struct Done {
    tid: u64,
    base: u64,
    calls: Vec<Reply>,
    finish: OptionalWorkerFinish,
}
fn live(deadline: Instant) {
    assert!(Instant::now() < deadline, "original child deadline");
}
fn wait_time(deadline: Instant) -> Duration {
    live(deadline);
    WAIT.min(deadline.saturating_duration_since(Instant::now()))
}
fn run_worker(
    client: OptionalClient,
    gate: Arc<OptionalCallGate>,
    input: Arc<[u8; 96]>,
    commands: mpsc::Receiver<Request>,
    ack: mpsc::SyncSender<Ack>,
    schedule: (usize, Instant),
) -> Done {
    let (cpu, deadline) = schedule;
    pin(Some(cpu));
    let readable = stack();
    let base = backoff_gate_checkpoint(&gate);
    // SAFETY: observe this actual Linux thread, not a caller-provided identity.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
    assert!(tid != 0 && tid <= i32::MAX as u64);
    let mut calls = Vec::with_capacity(COUNT);
    // SAFETY: sole attached worker; immutable valid input, live mapped stack,
    // exact admitted ABI, normal return and no foreign/signal/nonlocal entry.
    let mut attached = unsafe { client.attach(readable, IntervalJournal::allocate()) }.unwrap();
    if ack.send(Ack::Ready { tid, base }).is_ok() {
        loop {
            let request = match commands.recv_timeout(wait_time(deadline)) {
                Ok(r) => r,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(e) => panic!("bounded command wait: {e:?}"),
            };
            assert!(calls.len() < COUNT);
            assert!((1..=64).contains(&request.length));
            let bytes = &input[16..16 + request.length];
            // SAFETY: same actual-thread gate/stack and immutable valid leaf input.
            let outcome = unsafe { attached.invoke(bytes) }.unwrap();
            let OptionalCallOutcome::Returned {
                call,
                export_error: None,
            } = outcome
            else {
                panic!("every commanded call must really return and export: {outcome:?}");
            };
            assert_eq!(call.value, model(bytes));
            assert_eq!(call.pre_call_rsp, call.resumed_rsp);
            assert_eq!(call.entry_rsp.checked_add(8), Some(call.pre_call_rsp));
            assert_eq!(*input, guarded());
            // The idle flush may already have transferred this one call. An
            // explicit flush then returns empty; it never creates another packet.
            attached.flush().unwrap();
            let reply = Reply { request, call };
            calls.push(reply); // Retain the real returned evidence before ACK.
            live(deadline);
            if ack.send(Ack::Returned(reply)).is_err() {
                break;
            }
        }
    }
    let finish = attached.finish();
    assert_eq!(*input, guarded());
    live(deadline);
    Done {
        tid,
        base,
        calls,
        finish,
    }
}

// Declared after driver/input: every unwind releases the real pause and joins
// before borrowed invocation authority or input can disappear.
struct Worker {
    commands: Option<mpsc::SyncSender<Request>>,
    ack: Option<mpsc::Receiver<Ack>>,
    pause: Arc<BackoffEntryPause>,
    handle: Option<JoinHandle<Done>>,
    deadline: Instant,
}
impl Worker {
    fn command(&self, request: Request) {
        live(self.deadline);
        self.commands.as_ref().unwrap().try_send(request).unwrap();
    }
    fn ack(&self) -> Ack {
        self.ack
            .as_ref()
            .unwrap()
            .recv_timeout(wait_time(self.deadline))
            .unwrap()
    }
    fn returned(&self, request: Request) -> Reply {
        let Ack::Returned(reply) = self.ack() else {
            panic!("real return required")
        };
        assert_eq!(reply.request, request);
        reply
    }
    fn wait(&self) {
        let end = self.deadline.min(Instant::now() + WAIT);
        while !self.handle.as_ref().unwrap().is_finished() {
            if Instant::now() >= end {
                std::process::abort();
            }
            thread::yield_now();
        }
    }
    fn join(&mut self) -> Done {
        self.commands.take();
        self.wait();
        let result = self
            .handle
            .take()
            .unwrap()
            .join()
            .expect("actual native worker failed");
        live(self.deadline);
        result
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.pause.cancel();
        self.commands.take();
        self.ack.take(); // No blocked ACK can outlive its receiver on failure.
        if self.handle.is_some() {
            self.wait();
            let _ = self.handle.take().unwrap().join();
        }
    }
}

fn capture(rx: &mpsc::Receiver<OptionalExport>, saved: &mut Vec<OptionalExport>) {
    assert!(saved.len() < 21);
    saved.push(rx.try_recv().expect("one actual export"));
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}
fn current(driver: &OptionalDriver) -> GenerationId {
    driver.slots[driver.current.unwrap()]
        .as_ref()
        .unwrap()
        .generation()
}
fn totals(physical: u64) -> OptionalTotals {
    let fast = u64::from(physical >= 11);
    let slow = physical - fast;
    OptionalTotals {
        physical,
        bypassed: fast,
        observed: PairTotals {
            entries: slow,
            returns: slow,
            completed: slow,
            unsampled: 0,
        },
    }
}
#[derive(Eq, PartialEq)]
struct SavedPacket {
    rows: Vec<RawInterval>,
    page: Vec<u64>,
    calls: [Option<(usize, OptionalCallResult, Duration, Duration)>; ROWS],
}
fn saved_packet(p: &OptionalCompletedBatch) -> SavedPacket {
    SavedPacket {
        rows: p.native.rows().to_vec(),
        page: p.native.journal().to_vec(),
        calls: p
            .calls
            .map(|x| x.map(|c| (c.length, c.result, c.before, c.after))),
    }
}
struct Expected {
    entry: u64,
    continuation: u64,
    returns: BTreeSet<u64>,
    tid: u64,
    base: u64,
    generations: [GenerationId; 3],
    stream: HistoryStream,
}
impl Expected {
    fn packet(&self, p: &OptionalCompletedBatch, reply: Reply) {
        let b = &p.native;
        let call = reply.call;
        let n = call.physical;
        assert!((1..=13).contains(&n));
        assert_eq!(
            (
                b.pid(),
                b.tid(),
                b.registration(),
                b.install(),
                b.function()
            ),
            (std::process::id(), self.tid, 1, INSTALL, FUNCTION)
        );
        assert_eq!(b.history_stream(), Some(&self.stream));
        assert_eq!(b.number(), n);
        assert_eq!(b.physical_range(), n - 1..n);
        assert_eq!(b.totals(), (totals(n - 1), totals(n)));
        let begin = totals(n - 1).observed.returns;
        let end = totals(n).observed.returns;
        assert_eq!(b.raw_range(), begin..end);
        assert_eq!(b.event_range(), 2 * begin..2 * end);
        assert_eq!(b.completed_sequences(), (begin, end));
        assert_eq!(b.next_ordinal(), end + 1);
        assert_eq!(
            (b.gate_base(), b.gate_sequence()),
            (self.base, self.base + n)
        );
        assert_eq!(call.gate_sequence, self.base + n);
        assert_eq!(call.pre_call_rsp, call.resumed_rsp);
        assert_eq!(call.entry_rsp.checked_add(8), Some(call.pre_call_rsp));
        assert_eq!(call.entry_rsp & 15, 8);
        assert!(self.returns.contains(&call.return_pc));
        let item = p.calls[0].expect("actual returned call");
        assert_eq!((item.length, item.result), (reply.request.length, call));
        assert!(item.before <= item.after && item.after < Duration::from_secs(15));
        assert!(p.calls[1..].iter().all(Option::is_none));
        let mut page = [0; 512];
        page[2] = self.tid;
        if n == 11 {
            assert_eq!(call.path, OptionalPath::FastBypass);
            assert!(b.rows().is_empty());
            assert!(b.observed_gate_sequences().is_empty());
            assert_eq!(b.history_high_water(), Some(2));
            assert_eq!(b.history_prefix(0), None);
        } else {
            let (owner, invocation, prefix, high_water) = if n <= 10 {
                (self.generations[0], n - 1, 1, 1)
            } else if n == 12 {
                (self.generations[1], 0, 3, 4)
            } else {
                (self.generations[2], 0, 4, 4)
            };
            assert_eq!(call.path, OptionalPath::Slow { ordinal: end });
            assert_eq!(b.rows().len(), 1);
            assert_eq!(b.observed_gate_sequences(), &[self.base + n]);
            assert_eq!(b.history_high_water(), Some(high_water));
            assert_eq!(
                (b.history_prefix(0), b.history_prefix(1)),
                (Some(prefix), Some(prefix))
            );
            assert_eq!(b.history_prefix(2), None);
            let row = b.rows()[0];
            assert_eq!(
                (row.ordinal, row.entry_pc, row.return_pc),
                (end, self.entry, call.return_pc)
            );
            assert_eq!(
                row.owner,
                RawIntervalOwner::Sampled {
                    generation: owner.get(),
                    invocation: invocation as usize,
                }
            );
            assert!(
                row.elapsed_ticks().is_some(),
                "raw clock refusal stays a failure"
            );
            page[0] = 2;
            for side in 0..2 {
                let at = 4 + side * 7;
                page[at..at + 7].copy_from_slice(&[
                    1 + side as u64,
                    end,
                    if side == 0 {
                        self.entry
                    } else {
                        call.return_pc
                    },
                    call.entry_rsp,
                    self.continuation,
                    owner.get(),
                    (invocation + 1) | (prefix << 13),
                ]);
            }
        }
        assert_eq!(b.journal(), page); // Both sealed RSPs and every zero-tail word.
    }
    fn history(&self, exports: &[OptionalExport]) {
        let [a, b, c] = self.generations;
        let kinds = [
            ActionKind::Published,
            ActionKind::Disabled,
            ActionKind::Published,
            ActionKind::Published,
            ActionKind::Removed,
        ];
        let owners = [a, a, b, c, c];
        let bindings = [
            HistoryBinding::Initial,
            HistoryBinding::Published {
                action_index: 0,
                generation: a,
            },
            HistoryBinding::Published {
                action_index: 0,
                generation: a,
            },
            HistoryBinding::Published {
                action_index: 2,
                generation: b,
            },
            HistoryBinding::Published {
                action_index: 3,
                generation: c,
            },
            HistoryBinding::Removed {
                action_index: 4,
                generation: c,
            },
        ];
        let chunks: Vec<_> = exports
            .iter()
            .filter_map(|e| match e {
                OptionalExport::History(h) => Some(h),
                _ => None,
            })
            .collect();
        assert_eq!(chunks.len(), 5);
        for (i, h) in chunks.iter().enumerate() {
            assert_eq!(h.stream(), &self.stream);
            assert_eq!(h.number(), i as u64 + 1);
            assert_eq!(h.range(), i as u64..i as u64 + 1);
            assert_eq!((h.before(), h.after()), (bindings[i], bindings[i + 1]));
            assert_eq!(
                h.actions(),
                &[Action {
                    kind: kinds[i],
                    generation: owners[i],
                    function: (i == 1).then_some(FUNCTION),
                    current: (i != 4).then_some(owners[i]),
                    group: (i == 1).then_some(0),
                }]
            );
            assert_eq!(h.binding_at(i as u64), Some(bindings[i]));
            assert_eq!(h.binding_at(i as u64 + 1), Some(bindings[i + 1]));
            if i != 0 {
                assert!(h.follows(chunks[i - 1]));
            }
        }
        for p in exports.iter().filter_map(|e| match e {
            OptionalExport::Calls(p) => Some(p),
            _ => None,
        }) {
            if p.native.rows().is_empty() {
                assert!(chunks.iter().all(|h| !optional_matches_history(p, 0, h)));
            } else {
                let prefix = p.native.history_prefix(0).unwrap();
                let row = p.native.rows()[0];
                let owner = match row.owner {
                    RawIntervalOwner::Sampled { generation, .. } => generation,
                    _ => panic!("all Slow calls sampled"),
                };
                let binding = bindings[prefix as usize];
                let HistoryBinding::Published { generation, .. } = binding else {
                    panic!("published owner")
                };
                assert_eq!(generation.get(), owner);
                assert!(optional_matches_history(p, 0, chunks[prefix as usize - 1]));
            }
        }
    }
}
fn report(r: &FinalReport, rows: &[RawInterval], generation: u64, sequence: u64) {
    assert_eq!(r.generation, generation);
    assert_eq!(r.records.len(), rows.len());
    for (rank, (record, row)) in r.records.iter().zip(rows).enumerate() {
        let a = record.record.admission;
        assert_eq!(
            row.owner,
            RawIntervalOwner::Sampled {
                generation,
                invocation: rank
            }
        );
        assert_eq!(
            (a.generation.get(), a.function, a.invocation, a.entry_value),
            (generation, FUNCTION, rank, row.start.ticks)
        );
        assert_eq!(
            record.record.terminal,
            Some(Terminal::Completed {
                value: a.invocation as u64,
                disposition: Disposition::Retained { rank },
            })
        );
        let payload = record.payload.unwrap();
        assert_eq!(payload.admission, a);
        assert_eq!(
            (payload.thread, payload.start_sequence),
            (1, sequence + rank as u64)
        );
        assert_eq!(
            payload.outcome,
            PayloadOutcome::Completed {
                end: Observation::Value(row.end.ticks),
                completed_children: 0,
            }
        );
    }
}

#[test]
#[ignore = "requires release fixture reproducer"]
fn optional_backoff_native_disable_rearm_and_old_owner() {
    let deadline = Instant::now() + Duration::from_secs(15);
    let candidate = std::env::var_os("RAPID_CONCURRENT_CANDIDATE").expect("candidate ELF");
    let expected = std::env::var_os("RAPID_CONCURRENT_EXPECTED").expect("independent expected ELF");
    let candidate = Path::new(&candidate);
    let bytes = expected_file(candidate, Path::new(&expected));
    let cpu = pin(None);
    // SAFETY: sole selected subprocess owns the trusted RTLD_LOCAL fixture;
    // no constructors/dependencies, foreign entry, CET, signals, unwind or unload.
    let negative =
        unsafe { LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum", CONTRACT) }
            .unwrap();
    assert!(
        negative
            .certificate()
            .returns()
            .iter()
            .any(|&ret| negative.certificate().blocks().contains(&(ret, ret + 1)))
    );
    let id = identity(negative.entry());
    assert!(matches!(
        OptionalSitePreparation::new(negative, id),
        Err(crate::frontend_native::SiteError::Core(
            Refusal::NoPatchWindow
        ))
    ));
    // SAFETY: same trusted ELF, this separate symbol requires length 1..64.
    let owner = unsafe {
        LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum_nonempty", CONTRACT)
    }
    .unwrap();
    let entry = owner.entry();
    let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
    let mut prep = OptionalSitePreparation::new(owner, identity(entry)).unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        std::iter::once(entry)
            .chain(returns.iter().copied())
            .collect::<Vec<_>>()
    );
    let gate = Arc::clone(prep.gate());
    let selector = prep
        .plan()
        .images()
        .first()
        .unwrap()
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
    let input = Arc::new(guarded());
    let requests: [Request; COUNT] = std::array::from_fn(|i| Request {
        id: 40_000 + i as u64,
        length: if i % 2 == 0 { 1 } else { 64 },
    });
    let readable = stack();
    let original_base = backoff_gate_checkpoint(&gate);
    let mut originals = Vec::with_capacity(COUNT);
    for request in requests {
        live(deadline);
        let data = &input[16..16 + request.length];
        // SAFETY: exclusively borrowed uninstalled original and actual mapped stack.
        let call = unsafe { prep.prepare_original_call() }.unwrap();
        let result = unsafe { call.invoke(data.as_ptr(), data.len(), &readable) }.unwrap();
        assert_eq!(result.value, model(data));
        assert_eq!(result.pre_call_rsp, result.resumed_rsp);
        assert_eq!(*input, guarded());
        originals.push((request, result.value));
    }
    assert_eq!(backoff_gate_checkpoint(&gate), original_base + COUNT as u64);
    live(deadline);
    let site = backoff_native_publish(prep);
    // SAFETY: actual sealed whole-source publication; one forthcoming attached
    // worker, immutable input and no controller/callback lock cycle or reentry.
    let OptionalPrepared {
        mut driver,
        client,
        stop: _stop,
        export,
    } = unsafe { prepare_optional(site, INSTALL, FUNCTION, Policy::ten_ms(10, 3, 100).unwrap()) }
        .unwrap();
    let pause = Arc::new(BackoffEntryPause::new(11));
    driver.controller.backoff_install_pause(Arc::clone(&pause));
    // Actual deterministic driver-operation control, deliberately not run()/Clock.
    let start = Instant::now();
    driver.shared.common.start.set(start).unwrap();
    let mut exports = Vec::with_capacity(21);
    let mut replies = Vec::with_capacity(COUNT);
    let mut snapshots = Vec::with_capacity(COUNT);
    let (commands, rx) = mpsc::sync_channel(1);
    let (tx, ack) = mpsc::sync_channel(1);
    let worker_input = Arc::clone(&input);
    let worker_gate = Arc::clone(&gate);
    let handle = thread::spawn(move || {
        run_worker(client, worker_gate, worker_input, rx, tx, (cpu, deadline))
    });
    let mut worker = Worker {
        commands: Some(commands),
        ack: Some(ack),
        pause: Arc::clone(&pause),
        handle: Some(handle),
        deadline,
    };
    let Ack::Ready { tid, base } = worker.ack() else {
        panic!("actual attachment required")
    };
    assert!(driver.shared.common.attached.load(Ordering::Acquire));
    assert!(driver.shared.finished.get().is_none());

    driver.arm().unwrap();
    let a = current(&driver);
    capture(&export, &mut exports);
    for (i, request) in requests[..10].iter().copied().enumerate() {
        assert!(selector.is_enabled());
        worker.command(request);
        let reply = worker.returned(request);
        assert_eq!((request, reply.call.value), originals[i]);
        replies.push(reply);
        driver.receive_one(Duration::ZERO).unwrap();
        capture(&export, &mut exports);
        let OptionalExport::Calls(p) = exports.last().unwrap() else {
            panic!("call packet")
        };
        snapshots.push(saved_packet(p));
        if i == 0 {
            let before = driver.history_window().unwrap();
            driver.scan().unwrap();
            assert_eq!(driver.history_window().unwrap(), before);
            assert_eq!((driver.disabled, driver.history_end), (0, 1));
            assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
        }
    }
    assert!(
        selector.is_enabled(),
        "K completion alone did not store selector"
    );
    driver.scan().unwrap();
    assert!(!selector.is_enabled());
    assert_eq!((driver.disabled, driver.history_end), (1, 2));
    capture(&export, &mut exports);
    let before = driver.history_window().unwrap();
    driver.scan().unwrap();
    assert_eq!(driver.history_window().unwrap(), before);
    assert_eq!((driver.disabled, driver.history_end), (1, 2));
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    // The unique controller cannot mutate while this exact call enters/returns.
    // Physical selector observations bracket the real Fast result and flush ACK.
    assert!(!selector.is_enabled());
    worker.command(requests[10]);
    let fast = worker.returned(requests[10]);
    assert_eq!(fast.call.path, OptionalPath::FastBypass);
    assert!(!selector.is_enabled());
    assert_eq!(driver.history_window().unwrap(), before);
    assert_eq!((fast.request, fast.call.value), originals[10]);
    replies.push(fast);
    driver.receive_one(Duration::ZERO).unwrap();
    capture(&export, &mut exports);
    let OptionalExport::Calls(p) = exports.last().unwrap() else {
        panic!("Fast packet")
    };
    snapshots.push(saved_packet(p));
    assert!(p.native.rows().is_empty());
    assert_eq!(p.native.journal()[0], 0);

    driver.arm().unwrap();
    let b = current(&driver);
    assert!(selector.is_enabled());
    capture(&export, &mut exports);
    driver.retire().unwrap();
    capture(&export, &mut exports);
    assert_eq!(driver.reports, 1);
    worker.command(requests[11]);
    let pause_deadline = deadline.min(Instant::now() + WAIT);
    while !pause.entered() {
        live(pause_deadline);
        thread::yield_now();
    }
    assert!(matches!(
        worker.ack.as_ref().unwrap().try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let b_slot = driver.current.unwrap();
    assert!(
        driver
            .controller
            .report(driver.slots[b_slot].as_ref().unwrap())
            .unwrap()
            .is_none()
    );
    driver.arm().unwrap();
    let c = current(&driver);
    capture(&export, &mut exports);
    assert!(
        driver
            .controller
            .report(driver.slots[b_slot].as_ref().unwrap())
            .unwrap()
            .is_none()
    );
    driver.retire().unwrap();
    assert_eq!(driver.reports, 1);
    assert_eq!(driver.slots[b_slot].as_ref().unwrap().generation(), b);
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));
    pause.release();
    let old = worker.returned(requests[11]);
    assert_eq!(old.call.path, OptionalPath::Slow { ordinal: 11 });
    assert_eq!((old.request, old.call.value), originals[11]);
    replies.push(old);
    driver.receive_one(Duration::ZERO).unwrap();
    capture(&export, &mut exports);
    let OptionalExport::Calls(p) = exports.last().unwrap() else {
        panic!("old owner packet")
    };
    snapshots.push(saved_packet(p));
    assert_eq!(
        p.native.rows()[0].owner,
        RawIntervalOwner::Sampled {
            generation: b.get(),
            invocation: 0
        }
    );
    driver.retire().unwrap();
    capture(&export, &mut exports);
    assert_eq!(driver.reports, 2);
    assert!(driver.slots[b_slot].is_none());

    assert!(selector.is_enabled());
    worker.command(requests[12]);
    let last = worker.returned(requests[12]);
    assert_eq!(last.call.path, OptionalPath::Slow { ordinal: 12 });
    assert_eq!((last.request, last.call.value), originals[12]);
    replies.push(last);
    driver.receive_one(Duration::ZERO).unwrap();
    capture(&export, &mut exports);
    let OptionalExport::Calls(p) = exports.last().unwrap() else {
        panic!("current owner packet")
    };
    snapshots.push(saved_packet(p));
    driver.close().unwrap();
    assert!(!selector.is_enabled());
    driver.history().unwrap();
    capture(&export, &mut exports);
    driver.retire().unwrap();
    capture(&export, &mut exports);
    assert!(!driver.finished_ready().unwrap()); // No detached or joined fiction.
    let done = worker.join(); // Real finish/detach then actual OS thread join.
    assert_eq!((done.tid, done.base), (tid, base));
    assert_eq!(done.calls, replies);
    assert_eq!(done.calls.len(), COUNT);
    assert_eq!(done.finish.status.totals, Some(totals(13)));
    assert!(done.finish.status.detached);
    assert_eq!(done.finish.status.error, None);
    assert!(!done.finish.status.unexported);
    assert!(done.finish.unexported.is_none());
    assert!(done.finish.partial_calls.iter().all(Option::is_none));
    assert_eq!(driver.shared.finished.get(), Some(&done.finish.status));
    assert!(driver.shared.common.finished.get().is_none());
    assert!(driver.finished_ready().unwrap());
    driver.receive_one(Duration::ZERO).unwrap(); // Disconnected only after real finish.
    assert!(driver.recover_worker_packet().is_none());
    assert!(driver.pending.is_none());
    assert_eq!(driver.close_error(), None);
    assert_eq!(driver.deadline_failure(), None);
    assert!(
        !driver.started,
        "this test does not claim run()/Clock-loop coverage"
    );
    assert_eq!(
        (
            driver.arms,
            driver.disabled,
            driver.reports,
            driver.exported
        ),
        (3, 1, 3, 21)
    );
    assert_eq!(
        (
            driver.history_end,
            driver.history_number,
            driver.cursor.number
        ),
        (5, 5, 13)
    );
    assert_eq!(driver.cursor.totals, totals(13));
    assert!(driver.slots.iter().all(Option::is_none));
    assert_eq!(driver.current, None);
    let window = driver.history_window().unwrap();
    assert_eq!(window.status(), ControllerStatus::Ready);
    assert_eq!(window.current(), None);
    assert_eq!(window.range(), 5..5);
    assert!(window.actions().is_empty());
    assert!(matches!(export.try_recv(), Err(mpsc::TryRecvError::Empty)));

    let expected = Expected {
        entry,
        continuation: gate.continuation(),
        returns,
        tid,
        base,
        generations: [a, b, c],
        stream: driver.stream.clone(),
    };
    expected.history(&exports);
    let packets: Vec<_> = exports
        .iter()
        .filter_map(|e| match e {
            OptionalExport::Calls(p) => Some(p),
            _ => None,
        })
        .collect();
    assert_eq!(packets.len(), COUNT);
    let mut rows = Vec::with_capacity(12);
    for (index, ((p, reply), snapshot)) in packets.iter().zip(&replies).zip(&snapshots).enumerate()
    {
        assert_eq!(reply.request, requests[index]);
        assert_eq!(reply.call.physical, index as u64 + 1);
        expected.packet(p, *reply);
        assert!(
            saved_packet(p) == *snapshot,
            "held packet changed during retirement"
        );
        rows.extend_from_slice(p.native.rows());
    }
    assert_eq!(rows.len(), 12);
    assert_eq!(
        replies
            .iter()
            .map(|r| r.request.id)
            .collect::<BTreeSet<_>>()
            .len(),
        13
    );
    assert_eq!(
        replies
            .iter()
            .map(|r| r.call.return_pc)
            .collect::<BTreeSet<_>>(),
        expected.returns
    );
    assert_eq!(
        rows.iter().map(|r| r.return_pc).collect::<BTreeSet<_>>(),
        expected.returns
    );
    let reports: Vec<_> = exports
        .iter()
        .filter_map(|e| match e {
            OptionalExport::Report(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(reports.len(), 3);
    report(reports[0], &rows[..10], a.get(), 0);
    report(reports[1], &rows[10..11], b.get(), 10);
    report(reports[2], &rows[11..], c.get(), 11);
    assert_eq!(reports.iter().map(|r| r.records.len()).sum::<usize>(), 12);
    assert_eq!(*input, guarded());
    assert_eq!(Arc::strong_count(&input), 1); // Joined worker released its actual owner.
    live(deadline);
    println!("{TERMINAL}");
}
