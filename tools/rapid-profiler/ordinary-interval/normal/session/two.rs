//! Two ordinary callers with bounded local queues and one shared metadata controller.
use super::worker::scalar;
use super::*;
use rapid_profiler::frontend_native::{
    InstalledTwoCallerNormalSite, LoadedTwoCallerNormalLeaf, PreparedTwoCallerNormalController,
    TwoCallerNormalLeafContract, TwoCallerNormalSitePreparation,
};
mod check;
mod exact;
mod worker;
use check::Ledger;
use exact::Subject;

struct Engine {
    controller: IntervalController,
    epochs: [Option<IntervalEpoch>; 4],
    current: Option<usize>,
    history: Vec<HistoryBatch>,
    reports: Vec<(u64, Vec<RecordObservation>)>,
    k: usize,
    committed_arms: u32,
}
impl Engine {
    fn history(&mut self, io: &mut Io) -> Result<(), String> {
        if let Some(chunk) = self.controller.drain_history().map_err(failure)? {
            if let Some(previous) = self.history.last() {
                assert!(chunk.follows(previous));
            } else {
                assert_eq!(chunk.number(), 1);
                assert_eq!(chunk.range().start, 0);
                assert_eq!(chunk.before(), HistoryBinding::Initial);
            }
            assert_eq!(
                chunk.range().end - chunk.range().start,
                chunk.actions().len() as u64
            );
            // Retain the actual transfer before any output operation may refuse.
            self.history.push(chunk);
            let h = self.history.last().unwrap();
            for (i, action) in h.actions().iter().enumerate() {
                assert_eq!(action.function, None);
                assert_eq!(action.group, None);
                let kind = match action.kind {
                    rapid_profiler::frontend::ActionKind::Published => {
                        assert_eq!(action.current, Some(action.generation));
                        "published"
                    }
                    rapid_profiler::frontend::ActionKind::Removed => {
                        assert_eq!(action.current, None);
                        "removed"
                    }
                    _ => panic!("unexpected mandatory session action"),
                };
                io.emit(format!(
                    "HISTORY,{},{},{kind},{}\n",
                    h.number(),
                    h.range().start + i as u64 + 1,
                    action.generation.get()
                ))?;
            }
        }
        Ok(())
    }
    fn retire(&mut self, io: &mut Io) -> Result<(), String> {
        for i in 0..4 {
            if self.current == Some(i) {
                continue;
            }
            let Some(epoch) = &self.epochs[i] else {
                continue;
            };
            if self.controller.report(epoch).map_err(failure)?.is_none() {
                continue;
            }
            let report = self.controller.retire(epoch).map_err(failure)?;
            let generation = report.generation().get();
            let records: Vec<_> = report.records().collect();
            let counts = check::report(generation, &records, self.k);
            self.reports.push((generation, records));
            drop(report);
            self.epochs[i] = None;
            io.emit(format!(
                "REPORT,{generation},{},{},{},0,0\n",
                counts.admitted, counts.retained, counts.dropped
            ))?;
        }
        Ok(())
    }
    fn arm(&mut self, io: &mut Io) -> Result<(), String> {
        self.retire(io)?;
        let i = self
            .epochs
            .iter()
            .position(Option::is_none)
            .ok_or("retained epoch capacity")?;
        let epoch = self
            .controller
            .stage(Config {
                retained_per_function: self.k,
                max_inflight: 2,
                max_invocations: protocol::COMMANDS,
            })
            .map_err(failure)?;
        self.controller.arm(&epoch).map_err(failure)?;
        self.committed_arms += 1; // Publication remains real if history later fails.
        self.epochs[i] = Some(epoch);
        self.current = Some(i);
        self.history(io)
    }
    fn stop(&mut self, io: &mut Io) -> Result<(), String> {
        if let Some(i) = self.current {
            self.controller
                .disarm(self.epochs[i].as_ref().unwrap())
                .map_err(failure)?;
            self.current = None;
        }
        self.history(io)
    }
}

fn publish(prep: TwoCallerNormalSitePreparation) -> InstalledTwoCallerNormalSite {
    single_main();
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert_eq!(originals.len(), 1);
    let source = AddressRange::new(originals[0].address, originals[0].bytes.len()).unwrap();
    assert_eq!(source.start() % 4096, 0);
    assert!(matches!(source.len(), 4096 | 8192));
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    // This process has one actual thread and no subject caller, saved resume,
    // signal handler, writer or live invocation. No subject CALL was dispatched.
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
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
        Err(error) => {
            eprintln!("normal two-caller publication FAILED: {error:?}");
            std::process::abort();
        }
    };
    // SAFETY: actual complete transaction and RX source under sole-thread
    // exclusion. Seal retains every code/control/source owner for process life.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

// A single logical broadcast survives partial sends until both exact local ACKs.
#[derive(Debug)]
struct Barrier {
    id: Option<u64>,
    prefix: [u64; 2],
    sent: [bool; 2],
    ack: [bool; 2],
}
impl Barrier {
    fn new(id: Option<u64>, prefix: [u64; 2]) -> Self {
        Self {
            id,
            prefix,
            sent: [false; 2],
            ack: [false; 2],
        }
    }
    fn send(&mut self, tx: &[mpsc::SyncSender<Command>; 2]) -> Result<bool, String> {
        let mut progress = false;
        for (i, destination) in tx.iter().enumerate() {
            if self.sent[i] {
                continue;
            }
            let command = match self.id {
                Some(id) => Command::Flush { id },
                None => Command::Stop,
            };
            match destination.try_send(command) {
                Ok(()) => {
                    self.sent[i] = true;
                    progress = true;
                }
                Err(TrySendError::Full(_)) => (),
                Err(TrySendError::Disconnected(_)) => {
                    return Err("broadcast queue disconnected".into());
                }
            }
        }
        Ok(progress)
    }
    fn acknowledge(
        &mut self,
        worker: usize,
        id: Option<u64>,
        confirmed: u64,
    ) -> Result<bool, String> {
        if worker >= 2
            || self.id != id
            || !self.sent[worker]
            || self.ack[worker]
            || self.prefix[worker] != confirmed
        {
            return Err("foreign/early/duplicate broadcast acknowledgement".into());
        }
        self.ack[worker] = true;
        Ok(self.ack == [true; 2])
    }
}
#[derive(Debug)]
enum Pending {
    Call { worker: usize, command: Command },
    Flush(Barrier),
}
#[derive(Default)]
struct Dispatch {
    pending: Option<Pending>,
    stop: Option<Barrier>,
}
impl Dispatch {
    fn advance(
        &mut self,
        tx: &[mpsc::SyncSender<Command>; 2],
        stopping: bool,
        prefix: [u64; 2],
    ) -> Result<bool, String> {
        let mut progress = false;
        if let Some(pending) = self.pending.take() {
            match pending {
                Pending::Call { worker, command } => match tx[worker].try_send(command) {
                    Ok(()) => progress = true,
                    Err(TrySendError::Full(command)) => {
                        self.pending = Some(Pending::Call { worker, command })
                    }
                    Err(TrySendError::Disconnected(command)) => {
                        self.pending = Some(Pending::Call { worker, command });
                        return Err("work queue disconnected".into());
                    }
                },
                Pending::Flush(mut barrier) => {
                    // Retain bits and the logical request even if the second send fails.
                    let result = barrier.send(tx);
                    self.pending = Some(Pending::Flush(barrier));
                    progress |= result?;
                }
            }
        }
        if stopping && self.pending.is_none() {
            let barrier = self.stop.get_or_insert_with(|| Barrier::new(None, prefix));
            progress |= barrier.send(tx)?;
        }
        Ok(progress)
    }
    fn flushed(&mut self, worker: usize, id: u64, totals: NormalTotals) -> Result<bool, String> {
        let Some(Pending::Flush(barrier)) = self.pending.as_mut() else {
            return Err("unexpected FLUSH acknowledgement".into());
        };
        let complete = barrier.acknowledge(worker, Some(id), totals.confirmed)?;
        if complete {
            self.pending = None;
        }
        Ok(complete)
    }
    fn finished(&mut self, worker: usize, totals: NormalTotals) -> Result<(), String> {
        self.stop
            .as_mut()
            .ok_or("unexpected worker completion")?
            .acknowledge(worker, None, totals.confirmed)?;
        Ok(())
    }
    fn complete(&self) -> bool {
        self.pending.is_none()
            && self
                .stop
                .as_ref()
                .is_some_and(|s| s.sent == [true; 2] && s.ack == [true; 2])
    }
}
fn output_bound(calls: usize, flushes: usize, arms: u32) -> usize {
    assert!(
        calls
            .checked_add(flushes)
            .is_some_and(|n| n <= protocol::COMMANDS)
    );
    assert!(arms <= 4096);
    331 * calls + 59 * flushes + 49 * (arms as usize + 1) + 47 * arms as usize + 328
}
fn cpus() -> [usize; 3] {
    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) },
        0
    );
    let mut ids =
        (0..libc::CPU_SETSIZE as usize).filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) });
    std::array::from_fn(|_| ids.next().expect("three distinct permitted session CPUs"))
}

pub(crate) fn run(
    candidate: &Path,
    trusted: &Path,
    elf_va: u64,
    length: u64,
    k: usize,
    epochs: u32,
) {
    if let Err(error) = run_checked(candidate, trusted, elf_va, length, k, epochs) {
        eprintln!("normal-session-two FAILED: {error}");
        // Fail-stop keeps callback/receipt and process-lived executable custody;
        // it is not a successful partial population, cancellation or worker join.
        std::process::exit(1);
    }
}
pub(crate) fn run_exact(
    candidate: &Path,
    trusted: &Path,
    elf_va: u64,
    length: u64,
    k: usize,
    epochs: u32,
) {
    if let Err(error) = run_subject(
        Subject::Exact37,
        candidate,
        trusted,
        elf_va,
        length,
        k,
        epochs,
    ) {
        eprintln!("normal-session-two-exact FAILED: {error}");
        // Identical fail-stop ownership: no partial population or join credit.
        std::process::exit(1);
    }
}
fn run_checked(
    candidate: &Path,
    trusted: &Path,
    elf_va: u64,
    length: u64,
    k: usize,
    epochs: u32,
) -> Result<(), String> {
    run_subject(
        Subject::Strnlen41,
        candidate,
        trusted,
        elf_va,
        length,
        k,
        epochs,
    )
}
fn run_subject(
    subject: Subject,
    candidate: &Path,
    trusted: &Path,
    elf_va: u64,
    length: u64,
    k: usize,
    epochs: u32,
) -> Result<(), String> {
    single_main();
    let cpus = cpus();
    let policy = Policy::ten_ms(k, epochs, protocol::COMMANDS as u64).map_err(failure)?;
    match subject {
        Subject::Strnlen41 => {
            assert_eq!(
                length, 41,
                "qualified strnlen extent, not arbitrary discovery"
            );
        }
        Subject::Exact37 => exact::extent(length),
    }
    let bytes = expected_file(candidate, trusted);
    let selection = TrustedFunctionSelection::new(
        &bytes,
        elf_va,
        usize::try_from(length).map_err(failure)?,
        subject.label(),
    )
    .map_err(failure)?;
    // SAFETY: independently authenticated closed-subject ELF/extent, exact ABI,
    // read-only input and sole entry. Publication is globally quiescent; both
    // actual workers attach before dispatch. No signal/reentry/unwind/CET/writer,
    // unload/fork or code reclamation; all installed owners are process-lived.
    let owner = unsafe {
        LoadedTwoCallerNormalLeaf::load_selected(
            candidate,
            &selection,
            TwoCallerNormalLeafContract {
                single_external_entry: true,
                ordinary_call_ret_only: true,
                no_active_cet: true,
            },
        )
    }
    .map_err(failure)?;
    let entry = owner.entry();
    let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
    match subject {
        Subject::Strnlen41 => assert_eq!(returns, [entry + 34, entry + 40].into()),
        Subject::Exact37 => exact::geometry(
            entry,
            owner.certificate().range(),
            owner.code(),
            owner.certificate().heads(),
            &returns,
        ),
    }
    owner.verify_original().map_err(failure)?;
    let prep = TwoCallerNormalSitePreparation::new_whole_function(owner, identity(entry))
        .map_err(failure)?;
    let mut spans: Vec<_> = prep
        .plan()
        .plan()
        .final_bytes()
        .iter()
        .map(|s| (s.address, s.bytes.clone()))
        .collect();
    spans.extend(
        prep.plan()
            .images()
            .iter()
            .map(|i| (i.address(), i.bytes().to_vec())),
    );
    let spans = Arc::new(spans);
    let site = publish(prep);
    unsafe { immutable(&spans) };
    let prepared = PreparedTwoCallerNormalController::new_streaming_history(
        site,
        INSTALL,
        FUNCTION,
        Limits {
            epochs: 4,
            threads: 2,
            depth: 1,
            records_per_epoch: protocol::COMMANDS,
            actions: 8,
        },
    )
    .map_err(failure)?;
    // SAFETY: pristine activation, process-private real publication, no callback-
    // dependent controller locks; exactly two D1 callers use the explicit barrier.
    let (controller, client) = unsafe { prepared.activate_concurrent() }.map_err(failure)?;
    let stream = controller
        .history_window()
        .map_err(failure)?
        .stream()
        .clone();
    let mut engine = Engine {
        controller,
        epochs: [None, None, None, None],
        current: None,
        history: Vec::with_capacity(epochs as usize + 1),
        reports: Vec::with_capacity(epochs as usize),
        k,
        committed_arms: 0,
    };
    let mut io = Io::new()?;
    // One original setup deadline spans BOTH creations and Ready observations.
    let setup_limit = Instant::now().checked_add(WAIT).ok_or("setup deadline")?;
    let [first, second] = std::array::from_fn(|i| {
        let (tx, rx) = mpsc::sync_channel(2);
        let (events, replies) = mpsc::sync_channel(1);
        let client = client.clone();
        let spans = Arc::clone(&spans);
        let handle = thread::spawn(move || {
            worker::run(
                (entry, subject),
                client,
                spans,
                rx,
                events,
                cpus[i + 1],
                i as u64 + 1,
            )
        });
        (tx, replies, Some(handle))
    });
    let tx = [first.0, second.0];
    let replies = [first.1, second.1];
    let mut handles = [first.2, second.2];
    // This borrowing boundary leaves engine, I/O, channels and join handles
    // alive when a recoverable controller error selects process fail-stop.
    // Returning Err from their owner scope would disconnect attached workers
    // and close epochs before the outer wrapper could choose exit(1).
    let mut loop_trace = loop_trace::Trace::default();
    let outcome = (|| -> Result<(), String> {
        pin(Some(cpus[0]));
        let mut tids = [0; 2];
        for (i, replies) in replies.iter().enumerate() {
            let now = Instant::now();
            if now >= setup_limit {
                return Err("worker setup deadline".into());
            }
            let worker::Event::Ready { tid } = replies
                .recv_timeout(setup_limit.duration_since(now))
                .map_err(failure)?
            else {
                return Err("worker attachment handshake".into());
            };
            if Instant::now() >= setup_limit {
                return Err("worker setup completion deadline".into());
            }
            tids[i] = tid;
        }
        let mut ledger = match subject {
            Subject::Strnlen41 => Ledger::new(tids, entry, returns, stream, k),
            Subject::Exact37 => Ledger::new_exact(tids, entry, returns, stream, k),
        };
        let mut ids = protocol::Ids::default();
        let mut dispatch = Dispatch::default();
        let mut requested = false;
        let mut finished = [None; 2];
        let mut prefer = 0;
        let mut final_output = false;
        match subject {
            Subject::Strnlen41 => io.emit(format!(
                "READY,normal-two-session-v1,{k},{epochs},10,2,4096,4096,2,1,2,1,4,2,4096\n"
            ))?,
            Subject::Exact37 => io.emit(format!(
                "READY,normal-two-exact-v1,{k},{epochs},10,2,4096,4096,2,1,2,1,4,2,4096\n"
            ))?,
        }
        for (i, tid) in tids.into_iter().enumerate() {
            io.emit(format!("WORKER,{},{},{tid}\n", i + 1, i + 1))?;
        }
        let started = Instant::now();
        let mut schedule = Schedule::new(started, policy).map_err(failure)?;
        let mut previous_poll = started;
        let mut last_wait: Option<(Duration, Duration)> = None;
        loop {
            let mut progress = false;
            let observed = Instant::now();
            let waited = last_wait.take();
            let decision = schedule.poll(observed, requested).map_err(|e| {
                loop_trace.refused_poll(
                    observed,
                    loop_trace::State {
                        pending: match dispatch.pending.as_ref() {
                            None => 0,
                            Some(Pending::Call { .. }) => 1,
                            Some(Pending::Flush(_)) => 2,
                        },
                        requested,
                        stopping: schedule.is_stopping(),
                        accepted: ledger.accepted.len(),
                        history: engine.history.last().map_or(0, |h| h.range().end),
                        reports: engine.reports.len(),
                        finished: u8::from(finished[0].is_some())
                            | (u8::from(finished[1].is_some()) << 1),
                        write_blocked: io.write_blocked(),
                        output_drained: io.drained(),
                    },
                );
                format!(
                    "{} elapsed_ns={} poll_gap_ns={} last_wait_ns={:?}",
                    clock_failure(e, "poll", engine.committed_arms, &schedule),
                    observed.duration_since(started).as_nanos(),
                    observed.duration_since(previous_poll).as_nanos(),
                    waited.map(|(requested, elapsed)| (requested.as_nanos(), elapsed.as_nanos()))
                )
            })?;
            loop_trace.begin(
                observed,
                loop_trace::State {
                    pending: match dispatch.pending.as_ref() {
                        None => 0,
                        Some(Pending::Call { .. }) => 1,
                        Some(Pending::Flush(_)) => 2,
                    },
                    requested,
                    stopping: schedule.is_stopping(),
                    accepted: ledger.accepted.len(),
                    history: engine.history.last().map_or(0, |h| h.range().end),
                    reports: engine.reports.len(),
                    finished: u8::from(finished[0].is_some())
                        | (u8::from(finished[1].is_some()) << 1),
                    write_blocked: io.write_blocked(),
                    output_drained: io.drained(),
                },
            );
            match decision {
                ScheduleDecision::Arm { .. } => {
                    loop_trace.decision("arm");
                    if let Err(error) = engine.arm(&mut io) {
                        return Err(format!(
                            "arm/history failed: committed={} completed={} {error}",
                            engine.committed_arms,
                            schedule.armed()
                        ));
                    }
                    schedule.arm_completed(Instant::now()).map_err(|e| {
                        clock_failure(e, "arm-completed", engine.committed_arms, &schedule)
                    })?;
                    progress = true;
                }
                ScheduleDecision::Stop => {
                    loop_trace.decision("stop");
                    engine.stop(&mut io)?;
                    progress = true;
                }
                ScheduleDecision::Wait => loop_trace.decision("wait"),
            }
            previous_poll = observed;
            loop_trace.mark(loop_trace::Phase::PollArm);
            // At most one reply, rotating preference. Metadata/timer never wait on a queue.
            let mut event = None;
            for offset in 0..2 {
                let i = (prefer + offset) % 2;
                match replies[i].try_recv() {
                    Ok(value) => {
                        event = Some((i, value));
                        prefer = (i + 1) % 2;
                        break;
                    }
                    Err(TryRecvError::Disconnected) if finished[i].is_none() => {
                        return Err("worker disconnected before completion".into());
                    }
                    Err(TryRecvError::Disconnected | TryRecvError::Empty) => (),
                }
            }
            if let Some((i, event)) = event {
                match event {
                    worker::Event::Batch { calls, native } => {
                        loop_trace.reply("batch", i + 1, calls.len());
                        assert!(finished[i].is_none());
                        engine.history(&mut io)?;
                        ledger.batch(i, calls, *native, &engine.history, &mut io)?;
                    }
                    worker::Event::Flushed { id, totals } => {
                        loop_trace.reply("flushed", i + 1, 0);
                        ledger.totals(i, totals);
                        if dispatch.flushed(i, id, totals)? {
                            ledger.flushed(id, &mut io)?;
                        }
                    }
                    worker::Event::Finished(totals) => {
                        loop_trace.reply("finished", i + 1, 0);
                        ledger.totals(i, totals);
                        dispatch.finished(i, totals)?;
                        assert!(finished[i].replace(totals).is_none());
                    }
                    worker::Event::Ready { .. } => return Err("duplicate worker handshake".into()),
                }
                progress = true;
            }
            loop_trace.progress(progress);
            loop_trace.mark(loop_trace::Phase::ReplyHistory);
            engine.retire(&mut io)?;
            loop_trace.mark(loop_trace::Phase::Retire);
            if !schedule.is_stopping() && !requested && dispatch.pending.is_none() {
                if let Some(command) = io.command()? {
                    loop_trace.command(match &command {
                        Command::Call { .. } => "call",
                        Command::Flush { .. } => "flush",
                        Command::Stop => "stop",
                    });
                    if command == Command::Stop {
                        requested = true;
                    } else {
                        subject.accept(&mut ids, &command)?;
                        dispatch.pending = Some(ledger.accept(command));
                    }
                    progress = true;
                } else if io.eof() {
                    return Err("EOF before STOP or scheduled shutdown".into());
                }
            }
            loop_trace.progress(progress);
            loop_trace.mark(loop_trace::Phase::Input);
            progress |= dispatch.advance(&tx, schedule.is_stopping(), ledger.prefixes())?;
            loop_trace.progress(progress);
            loop_trace.mark(loop_trace::Phase::Dispatch);
            if !final_output
                && finished.iter().all(Option::is_some)
                && handles
                    .iter()
                    .all(|h| h.as_ref().is_some_and(|h| h.is_finished()))
            {
                assert!(schedule.is_stopping() && dispatch.complete());
                for handle in &mut handles {
                    handle.take().unwrap().join().map_err(|_| "worker panic")?;
                }
                engine.retire(&mut io)?;
                engine.history(&mut io)?;
                assert!(engine.epochs.iter().all(Option::is_none));
                assert_eq!(engine.reports.len(), schedule.armed() as usize);
                assert_eq!(engine.committed_arms, schedule.armed());
                assert_eq!(
                    engine.history.last().unwrap().range().end,
                    u64::from(schedule.armed()) + 1
                );
                let counts = ledger.finish(&engine.reports, &mut io)?;
                assert!(
                    subject.output_bound(ledger.calls, ledger.flushes, schedule.armed())
                        < 4 * 1024 * 1024
                );
                assert_eq!(ids.len(), ledger.accepted.len());
                single_main();
                unsafe { immutable(&spans) };
                for (i, totals) in finished.iter().enumerate() {
                    let t = totals.unwrap();
                    ledger.totals(i, t);
                    io.emit(format!(
                        "WORKER_DONE,{},{},{},{},{},{},{},1,1\n",
                        i + 1,
                        ledger.local[i].batches,
                        t.entered,
                        t.ret_observed,
                        t.confirmed,
                        t.completed,
                        t.unsampled
                    ))?;
                }
                io.emit(format!("IO,{}\n", io.write_blocked()))?;
                io.emit(format!(
                    "DONE,{:?},{},{},{},{},{},{},{},{},{},{},0,0,2,2\n",
                    schedule.stop_reason().unwrap(),
                    schedule.armed(),
                    engine.history.last().unwrap().range().end,
                    ledger.accepted.len(),
                    ledger.calls,
                    counts.admitted,
                    counts.retained,
                    counts.dropped,
                    ledger.local.iter().map(|c| c.totals.unsampled).sum::<u64>(),
                    ledger.local.iter().map(|c| c.batches).sum::<u64>(),
                    ledger.flushes
                ))?;
                final_output = true;
            }
            loop_trace.mark(loop_trace::Phase::Finalize);
            io.write()?;
            loop_trace.mark(loop_trace::Phase::Write);
            if final_output && io.drained() {
                schedule.check_completion(Instant::now()).map_err(|e| {
                    clock_failure(e, "final-output", engine.committed_arms, &schedule)
                })?;
                return Ok(());
            }
            let observed = Instant::now();
            let bound = schedule
                .wait_bound(observed)
                .map_err(|e| clock_failure(e, "wait", engine.committed_arms, &schedule))?;
            loop_trace.mark(loop_trace::Phase::WaitBound);
            if !progress {
                let wait = guarded_wait(started, observed, policy, &schedule, bound);
                if wait.is_zero() {
                    std::hint::spin_loop();
                } else {
                    let before = Instant::now();
                    if schedule.is_stopping() {
                        thread::sleep(wait);
                    } else {
                        let until = observed.checked_add(wait).ok_or("idle wait extent")?;
                        while Instant::now() < until {
                            std::hint::spin_loop();
                        }
                    }
                    last_wait = Some((wait, before.elapsed()));
                }
            }
            loop_trace.mark(loop_trace::Phase::Wait);
            loop_trace.complete(loop_trace::State {
                pending: match dispatch.pending.as_ref() {
                    None => 0,
                    Some(Pending::Call { .. }) => 1,
                    Some(Pending::Flush(_)) => 2,
                },
                requested,
                stopping: schedule.is_stopping(),
                accepted: ledger.accepted.len(),
                history: engine.history.last().map_or(0, |h| h.range().end),
                reports: engine.reports.len(),
                finished: u8::from(finished[0].is_some()) | (u8::from(finished[1].is_some()) << 1),
                write_blocked: io.write_blocked(),
                output_drained: io.drained(),
            });
        }
    })();
    if let Err(error) = outcome {
        let details = loop_trace.failure();
        match subject {
            Subject::Strnlen41 => eprintln!("normal-session-two FAILED: {error}{details}"),
            Subject::Exact37 => eprintln!("normal-session-two-exact FAILED: {error}{details}"),
        }
        // No cancellation, checkpoint, detach or join is fabricated on failure.
        // Independent worker/callback failures keep their original fail-stop.
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
