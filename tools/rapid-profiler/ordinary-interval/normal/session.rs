//! Finite external-input application session; no per-call profiler invocation.
use super::*;
use rapid_profiler::frontend_native::backoff::{Policy, Schedule, ScheduleDecision};
use rapid_profiler::frontend_native::{
    HistoryBatch, HistoryBinding, IntervalController, IntervalEpoch, IntervalEpochStorage,
};
use std::sync::mpsc::{TryRecvError, TrySendError};
mod check;
mod epoch_storage;
mod io;
mod loop_trace;
mod protocol;
pub(crate) mod two;
mod worker;
use check::Ledger;
use epoch_storage::Slot;
use io::Io;
use protocol::Command;

struct Engine {
    controller: IntervalController,
    epochs: [Option<Slot<IntervalEpoch>>; 3],
    banks: Vec<IntervalEpochStorage>,
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
        for i in 0..3 {
            if self.current == Some(i) {
                continue;
            }
            let Some(slot) = self.epochs[i].as_mut() else {
                continue;
            };
            if slot.report_index().is_none() {
                let Some(report) = self.controller.report(slot.epoch()).map_err(failure)? else {
                    continue;
                };
                let generation = report.generation().get();
                let records: Vec<_> = report.records().collect();
                assert!(records.len() <= self.k);
                let n = records.len();
                let index = self.reports.len();
                self.reports.push((generation, records));
                slot.copied(generation, index, format!("REPORT,{generation},{n}\n"));
                drop(report);
            }
            let index = slot.report_index().unwrap();
            assert_eq!(self.reports[index].0, slot.epoch().generation().get());
            slot.emit(|line| io.emit(line))?;
            if let Some(bank) = slot
                .reclaim(|epoch| self.controller.reclaim_storage(epoch))
                .map_err(failure)?
            {
                self.banks.push(bank); // At most the original E prepared banks.
                self.epochs[i] = None;
            }
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
        let mut bank = Some(self.banks.pop().ok_or("retained epoch capacity")?);
        #[allow(clippy::result_large_err)]
        // Keep the returned bank inline until custody is restored.
        let epoch =
            match epoch_storage::transfer(&mut bank, |bank| self.controller.stage_prepared(bank)) {
                Ok(epoch) => epoch,
                Err(error) => {
                    self.banks.push(bank.take().unwrap());
                    return Err(failure(error));
                }
            };
        // Retain the staged token before the fallible publication, including
        // its failure path. Only a successful arm changes current/counts.
        self.epochs[i] = Some(Slot::new(epoch));
        self.controller
            .arm(self.epochs[i].as_ref().unwrap().epoch())
            .map_err(failure)?;
        self.committed_arms += 1; // Publication remains real if history later fails.
        self.current = Some(i);
        self.history(io)
    }
    fn stop(&mut self, io: &mut Io) -> Result<(), String> {
        if let Some(i) = self.current {
            self.controller
                .disarm(self.epochs[i].as_ref().unwrap().epoch())
                .map_err(failure)?;
            self.current = None;
        }
        self.history(io)
    }
}
fn failure(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
fn clock_failure(
    e: impl std::fmt::Debug,
    phase: &str,
    committed: u32,
    schedule: &Schedule,
) -> String {
    format!(
        "clock {phase}: {e:?} committed={committed} completed={} pending={:?}",
        schedule.armed(),
        schedule.pending_arm()
    )
}

fn dispatch(
    tx: &mpsc::SyncSender<Command>,
    pending: &mut Option<Command>,
    stopping: bool,
    stop_sent: &mut bool,
) -> Result<bool, String> {
    let mut progress = false;
    if let Some(command) = pending.take() {
        match tx.try_send(command) {
            Ok(()) => progress = true,
            Err(TrySendError::Full(command)) => *pending = Some(command),
            Err(TrySendError::Disconnected(command)) => {
                *pending = Some(command);
                return Err("work queue disconnected".into());
            }
        }
    }
    if stopping && pending.is_none() && !*stop_sent {
        match tx.try_send(Command::Stop) {
            Ok(()) => {
                *stop_sent = true;
                progress = true;
            }
            Err(TrySendError::Full(_)) => (),
            Err(TrySendError::Disconnected(_)) => return Err("stop queue disconnected".into()),
        }
    }
    Ok(progress)
}

// Shorten only the caller's idle slice; Schedule retains every deadline.
// The original next arm becomes the original end after the last acknowledgement.
fn guarded_wait(
    started: Instant,
    observed: Instant,
    policy: Policy,
    schedule: &Schedule,
    bound: Duration,
) -> Duration {
    if schedule.is_stopping() {
        return bound;
    }
    // Schedule::new checked the whole end and armed() cannot exceed epoch_limit.
    let due = started
        .checked_add(policy.period() * schedule.armed())
        .expect("validated original schedule extent");
    bound.min(
        due.saturating_duration_since(observed)
            .saturating_sub(policy.lateness()),
    )
}

fn cpus() -> [usize; 2] {
    // Read before narrowing main's mask; the worker inherits this complete mask.
    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) },
        0
    );
    let mut ids =
        (0..libc::CPU_SETSIZE as usize).filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) });
    std::array::from_fn(|_| ids.next().expect("two distinct permitted session CPUs"))
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
        eprintln!("normal-session FAILED: {error}");
        // Failure is process fail-stop, never cancellation, a successful worker
        // join, or release authority for an unfinished callback/receipt.
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
    single_main();
    let cpus = cpus();
    let policy = Policy::ten_ms(k, epochs, protocol::COMMANDS as u64).map_err(failure)?;
    let bytes = expected_file(candidate, trusted);
    let selection = TrustedFunctionSelection::new(
        &bytes,
        elf_va,
        usize::try_from(length).map_err(failure)?,
        LABEL,
    )
    .map_err(failure)?;
    // SAFETY: closed read-only strnlen application, independent full ELF extent,
    // exact C ABI and sole entry; no signals/reentry/nonlocal exit/CET or writers.
    // One attached worker supplies bounded immutable input for every actual call.
    let owner = unsafe { LoadedNormalLeaf::load_selected(candidate, &selection, NORMAL_CONTRACT) }
        .map_err(failure)?;
    let entry = owner.entry();
    let returns = owner.certificate().returns().iter().copied().collect();
    owner.verify_original().map_err(failure)?;
    let prep =
        NormalSitePreparation::new_whole_function(owner, identity(entry)).map_err(failure)?;
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
    let mut prepared = PreparedNormalController::new_streaming_history(
        site,
        INSTALL,
        FUNCTION,
        Limits {
            epochs: 3,
            threads: 1,
            depth: 1,
            records_per_epoch: k,
            actions: 8,
        },
    )
    .map_err(failure)?;
    // Allocate/touch exactly E fixed banks before activation, Ready or start.
    let banks = prepared
        .prepare_epoch_storage(Config {
            retained_per_function: k,
            max_inflight: 1,
            max_invocations: k,
        })
        .map_err(failure)?;
    assert_eq!(banks.len(), 3);
    // SAFETY: pristine metadata, completed real quiescent publication, exactly
    // one controlled calling worker. Main does no blocking I/O under metadata.
    let (controller, client) = unsafe { prepared.activate_concurrent() }.map_err(failure)?;
    let stream = controller
        .history_window()
        .map_err(failure)?
        .stream()
        .clone();
    let mut engine = Engine {
        controller,
        epochs: [None, None, None],
        banks,
        current: None,
        history: Vec::with_capacity(epochs as usize + 1),
        reports: Vec::with_capacity(epochs as usize),
        k,
        committed_arms: 0,
    };
    let mut io = Io::new()?;
    let (tx, rx) = mpsc::sync_channel(4);
    let (events, replies) = mpsc::sync_channel(1);
    let worker_spans = Arc::clone(&spans);
    let mut handle = Some(joined_task::spawn(move || {
        worker::run(entry, client, worker_spans, rx, events, cpus[1])
    }));
    let mut joined = None; // Kept outside the fail-stop borrowing boundary.
    // This borrowing boundary leaves engine, I/O, channels and join handles
    // alive when a recoverable controller error selects process fail-stop.
    // Returning Err from their owner scope would disconnect attached workers
    // and close epochs before the outer wrapper could choose exit(1).
    let mut loop_trace = loop_trace::Trace::default();
    let outcome = (|| -> Result<(), String> {
        pin(Some(cpus[0]));
        let worker::Event::Ready { tid } = replies.recv_timeout(WAIT).map_err(failure)? else {
            return Err("worker attachment handshake".into());
        };
        let mut ledger = Ledger::new(tid, entry, returns, stream, k);
        let mut ids = protocol::Ids::default();
        let mut pending = None;
        let mut requested = false;
        let mut stop_sent = false;
        let mut finished = None;
        let mut final_output = false;
        io.emit(format!(
            "READY,normal-session-v1,{k},{epochs},10,2,4096,4096,4,1\n"
        ))?;
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
                        pending: match pending.as_ref() {
                            None => 0,
                            Some(Command::Call { .. }) => 1,
                            Some(Command::Flush { .. }) => 2,
                            Some(Command::Stop) => 3,
                        },
                        requested,
                        stopping: schedule.is_stopping(),
                        accepted: ledger.accepted.len(),
                        history: engine.history.last().map_or(0, |h| h.range().end),
                        reports: engine.reports.len(),
                        finished: u8::from(finished.is_some()),
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
                    pending: match pending.as_ref() {
                        None => 0,
                        Some(Command::Call { .. }) => 1,
                        Some(Command::Flush { .. }) => 2,
                        Some(Command::Stop) => 3,
                    },
                    requested,
                    stopping: schedule.is_stopping(),
                    accepted: ledger.accepted.len(),
                    history: engine.history.last().map_or(0, |h| h.range().end),
                    reports: engine.reports.len(),
                    finished: u8::from(finished.is_some()),
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
            // At most one reply per iteration. A full reply slot blocks only the
            // worker after its metadata operation, never the controller or timer.
            match replies.try_recv() {
                Ok(worker::Event::Batch { calls, native }) => {
                    loop_trace.reply("batch", 1, calls.len());
                    engine.history(&mut io)?;
                    ledger.batch(calls, *native, &engine.history, &mut io)?;
                    progress = true;
                }
                Ok(worker::Event::Flushed { id, totals }) => {
                    loop_trace.reply("flushed", 1, 0);
                    ledger.flushed(id, totals, &mut io)?;
                    progress = true;
                }
                Ok(worker::Event::Finished(totals)) => {
                    loop_trace.reply("finished", 1, 0);
                    assert!(finished.replace(totals).is_none());
                    progress = true;
                }
                Ok(worker::Event::Ready { .. }) => return Err("duplicate worker handshake".into()),
                Err(TryRecvError::Disconnected) if finished.is_none() => {
                    return Err("worker disconnected before completion".into());
                }
                Err(TryRecvError::Disconnected | TryRecvError::Empty) => (),
            }
            loop_trace.progress(progress);
            loop_trace.mark(loop_trace::Phase::ReplyHistory);
            engine.retire(&mut io)?;
            loop_trace.mark(loop_trace::Phase::Retire);
            if !schedule.is_stopping() && !requested && pending.is_none() {
                if let Some(command) = io.command()? {
                    loop_trace.command(match &command {
                        Command::Call { .. } => "call",
                        Command::Flush { .. } => "flush",
                        Command::Stop => "stop",
                    });
                    if command == Command::Stop {
                        requested = true;
                    } else {
                        ids.accept(&command).map_err(str::to_string)?;
                        // Acceptance reserves both ledger space and this owned
                        // pending cell. Queue Full never loses an accepted request.
                        ledger.accepted.push(match &command {
                            Command::Call { id, bound, bytes } => Command::Call {
                                id: *id,
                                bound: *bound,
                                bytes: bytes.clone(),
                            },
                            Command::Flush { id } => Command::Flush { id: *id },
                            Command::Stop => unreachable!(),
                        });
                        pending = Some(command);
                    }
                    progress = true;
                } else if io.eof() {
                    return Err("EOF before STOP or scheduled shutdown".into());
                }
            }
            loop_trace.progress(progress);
            loop_trace.mark(loop_trace::Phase::Input);
            progress |= dispatch(&tx, &mut pending, schedule.is_stopping(), &mut stop_sent)?;
            loop_trace.progress(progress);
            loop_trace.mark(loop_trace::Phase::Dispatch);
            if !final_output && let Some(totals) = finished {
                if joined.is_none() && handle.as_ref().is_some_and(|h| h.is_finished()) {
                    assert!(schedule.is_stopping() && stop_sent && pending.is_none());
                    joined = Some(handle.take().unwrap().join());
                    let captured = joined.as_ref().unwrap().tid();
                    if u64::from(captured) != tid {
                        return Err(format!(
                            "joined task identity captured_tids=[{captured}] Ready={tid} observed_tasks=None"
                        ));
                    }
                }
                // One complete observation per loop. The original Schedule
                // still bounds shutdown; unrelated tasks refuse immediately.
                let retired = match joined.as_mut() {
                    Some(task) => joined_task::poll_exclusive(&mut [task], || {
                        schedule
                            .wait_bound(Instant::now())
                            .map(|_| ())
                            .map_err(|error| {
                                joined_task::Error::Clock(clock_failure(
                                    error,
                                    "task-retirement",
                                    engine.committed_arms,
                                    &schedule,
                                ))
                            })
                    })
                    .map_err(|error| error.to_string())?,
                    None => false,
                };
                if retired {
                    joined
                        .as_ref()
                        .unwrap()
                        .result()
                        .as_ref()
                        .map_err(|_| "worker panic")?;
                    engine.retire(&mut io)?;
                    engine.history(&mut io)?;
                    assert!(engine.epochs.iter().all(Option::is_none));
                    assert_eq!(engine.banks.len(), 3);
                    assert_eq!(engine.reports.len(), schedule.armed() as usize);
                    assert_eq!(engine.committed_arms, schedule.armed());
                    assert_eq!(
                        engine.history.last().unwrap().range().end,
                        u64::from(schedule.armed()) + 1
                    );
                    ledger.finish(totals, &engine.reports, &mut io)?;
                    assert_eq!(ids.len(), ledger.accepted.len());
                    single_main();
                    unsafe { immutable(&spans) };
                    io.emit(format!("IO,{}\n", io.write_blocked()))?;
                    io.emit(format!(
                        "DONE,{:?},{},{},{},{},{},{},{},{},1,1\n",
                        schedule.stop_reason().unwrap(),
                        schedule.armed(),
                        engine.history.last().unwrap().range().end,
                        ledger.accepted.len(),
                        totals.confirmed,
                        totals.completed,
                        totals.unsampled,
                        ledger.batches,
                        ledger.flushes
                    ))?;
                    final_output = true;
                }
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
                    // Service the complete nonblocking loop again; do not wait past
                    // the guard or claim that spinning prevents preemption.
                    std::hint::spin_loop();
                } else {
                    let before = Instant::now();
                    if schedule.is_stopping() {
                        thread::sleep(wait);
                    } else {
                        // A normal scheduler cannot bound wakeup after sleep. Spend
                        // a controller CPU during this finite timed portion instead.
                        // One immutable target, at most the existing 1ms cap; after
                        // preemption the next real poll still refuses lateness.
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
                pending: match pending.as_ref() {
                    None => 0,
                    Some(Command::Call { .. }) => 1,
                    Some(Command::Flush { .. }) => 2,
                    Some(Command::Stop) => 3,
                },
                requested,
                stopping: schedule.is_stopping(),
                accepted: ledger.accepted.len(),
                history: engine.history.last().map_or(0, |h| h.range().end),
                reports: engine.reports.len(),
                finished: u8::from(finished.is_some()),
                write_blocked: io.write_blocked(),
                output_drained: io.drained(),
            });
        }
    })();
    if let Err(error) = outcome {
        let details = loop_trace.failure();
        let retirement = joined
            .as_ref()
            .map_or_else(String::new, |task| format!("; {}", task.diagnostic()));
        eprintln!("normal-session FAILED: {error}{details}{retirement}");
        // No cancellation, checkpoint, detach or join is fabricated on failure.
        // Independent worker/callback failures keep their original fail-stop.
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guarded_wait_preserves_original_due_end_and_shutdown_boundaries() {
        use rapid_profiler::frontend_native::backoff::Error;
        let started = Instant::now();
        let tick = Duration::from_nanos(1);
        let poll = Duration::from_millis(1);
        for k in [10, 1000] {
            let policy = Policy::ten_ms(k, 2, 1).unwrap();
            let mut schedule = Schedule::new(started, policy).unwrap();
            assert_eq!(
                schedule.poll(started, false),
                Ok(ScheduleDecision::Arm { due: started })
            );
            schedule.arm_completed(started).unwrap();
            let due = started + policy.period();
            let guard = due - policy.lateness();
            for (at, expected) in [
                (guard - poll * 2, poll),
                (guard - poll, poll),
                (guard - tick, tick),
                (guard, Duration::ZERO),
                (guard + tick, Duration::ZERO),
                (due, Duration::ZERO),
            ] {
                let bound = schedule.wait_bound(at).unwrap();
                assert_eq!(
                    guarded_wait(started, at, policy, &schedule, bound),
                    expected
                );
                assert_eq!(schedule.armed(), 1);
                assert_eq!(schedule.pending_arm(), None);
            }
            assert_eq!(schedule.poll(due, false), Ok(ScheduleDecision::Arm { due }));
            schedule.arm_completed(due).unwrap();
            let end = started + policy.period() * policy.epoch_limit();
            for (at, expected) in [
                (end - policy.lateness() - tick, tick),
                (end - policy.lateness(), Duration::ZERO),
                (end - tick, Duration::ZERO),
                (end, Duration::ZERO),
            ] {
                let bound = schedule.wait_bound(at).unwrap();
                assert_eq!(
                    guarded_wait(started, at, policy, &schedule, bound),
                    expected
                );
                assert_eq!(schedule.armed(), 2);
            }
            assert_eq!(schedule.poll(end, false), Ok(ScheduleDecision::Stop));
            let limit = end + policy.shutdown();
            for at in [end, limit - tick] {
                let bound = schedule.wait_bound(at).unwrap();
                assert_eq!(guarded_wait(started, at, policy, &schedule, bound), bound);
            }
            assert_eq!(schedule.wait_bound(limit), Err(Error::Deadline));

            let mut late = Schedule::new(started, policy).unwrap();
            assert_eq!(
                late.poll(started, false),
                Ok(ScheduleDecision::Arm { due: started })
            );
            late.arm_completed(started).unwrap();
            let at = due + policy.lateness() + tick;
            let bound = late.wait_bound(at).unwrap();
            assert_eq!(
                guarded_wait(started, at, policy, &late, bound),
                Duration::ZERO
            );
            assert_eq!(late.poll(at, false), Err(Error::Deadline));
            assert_eq!(late.armed(), 1);
            assert_eq!(late.poll(due, false), Err(Error::Deadline));
        }
    }

    #[test]
    fn accepted_full_queue_retains_pending_before_stop_and_disconnect() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(Command::Flush { id: 1 }).unwrap();
        let mut pending = Some(Command::Flush { id: 2 });
        let mut stopped = false;
        assert!(!dispatch(&tx, &mut pending, true, &mut stopped).unwrap());
        assert_eq!(pending, Some(Command::Flush { id: 2 }));
        assert!(!stopped);
        assert_eq!(rx.try_recv().unwrap(), Command::Flush { id: 1 });
        assert!(dispatch(&tx, &mut pending, true, &mut stopped).unwrap());
        assert!(pending.is_none() && !stopped);
        assert_eq!(rx.try_recv().unwrap(), Command::Flush { id: 2 });
        assert!(dispatch(&tx, &mut pending, true, &mut stopped).unwrap());
        assert!(stopped);
        assert_eq!(rx.try_recv().unwrap(), Command::Stop);
        assert!(!dispatch(&tx, &mut pending, true, &mut stopped).unwrap());
        pending = Some(Command::Flush { id: 3 });
        drop(rx);
        assert!(dispatch(&tx, &mut pending, false, &mut stopped).is_err());
        assert_eq!(pending, Some(Command::Flush { id: 3 }));
    }
}
