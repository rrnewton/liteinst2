//! Separate actual-return control after restaging the exact reclaimed bank.
//! No Schedule, warmup, allocation-count or architectural-state claim.
use super::check as owner_check;
use super::*;
mod check;
#[cfg(test)]
mod tests;

fn run_worker(
    start: WorkStart,
    rx: mpsc::Receiver<Command>,
    tx: mpsc::SyncSender<Message>,
    deadline: Deadline,
) -> WorkerState {
    let WorkStart {
        entries,
        client,
        custody,
        record,
        cpu,
        k,
        hot,
    } = start;
    let worker = worker::Worker::attach(entries, client, custody, cpu);
    send_message(&tx, Message::Ready(worker.identity()), deadline);
    // This is immutable accepted input ownership, not an epoch/receipt clone.
    let reused_input = Arc::clone(&record);
    let (mut worker, checkpoints) = worker_prefix(worker, record, k, hot, &rx, &tx, deadline);
    command(&rx, Command::Recycle, deadline);
    for function in [hot, 1 - hot] {
        deadline.check().unwrap();
        worker.call_one(Arc::clone(&reused_input), function);
        deadline.check().unwrap();
    }
    barrier(&worker, &tx, 6, checkpoints, deadline);
    worker_finish(worker, checkpoints, &rx, &tx, deadline, 7)
}
struct Receive<'a> {
    replies: &'a mpsc::Receiver<Message>,
    retained: &'a mut Vec<Message>,
    ledger: &'a mut check::Ledger,
    engine: &'a Engine,
    io: &'a mut Io,
}
impl Receive<'_> {
    fn state(&mut self, phase: usize, deadline: Deadline) -> Result<WorkerState, String> {
        loop {
            next_message(self.replies, self.retained, deadline)?;
            match self.retained.last().unwrap() {
                Message::Batch(shared::worker::Event::Batch { calls, native }) => self
                    .ledger
                    .batch(calls, native, &self.engine.history, self.io)?,
                Message::State {
                    phase: actual,
                    state,
                } => {
                    assert_eq!(*actual, phase);
                    return Ok(*state);
                }
                _ => return Err("unexpected reuse message".into()),
            }
        }
    }
}
fn slots(engine: &Engine) -> [Option<u64>; 3] {
    std::array::from_fn(|i| {
        engine.epochs[i]
            .as_ref()
            .map(|s| s.epoch().generation().get())
    })
}
struct Progress {
    generations: [u64; 3],
    copies: u64,
    refusals: u64,
    reclaimed: bool,
    restaged: bool,
    b_report: u64,
    c_report: u64,
    detach: bool,
    joins: u64,
}
impl Progress {
    fn phase(
        &self,
        phase: usize,
        state: WorkerState,
        ledger: &check::Ledger,
        engine: &Engine,
        old: Option<&check::OldCopy>,
        io: &mut Io,
    ) -> Result<(), String> {
        let live = slots(engine);
        let present = |g| u64::from(g != 0 && live.contains(&Some(g)));
        let (a_index, a_output, stable) = if let Some(old) = old {
            old.check(&engine.reports);
            let (_, index, _, output) = old.slot.copied.as_ref().unwrap();
            (
                *index as u64 + 1,
                u64::from(*output == shared::epoch_storage::OutputSnapshot::Emitted),
                1,
            )
        } else {
            (0, 0, 0)
        };
        let observed = check::PhaseState {
            totals: state.totals,
            batches: ledger.population.batches,
            banks: engine.banks.len() as u64,
            current: engine.current.map_or(0, |i| live[i].unwrap()),
            history: engine.history.last().unwrap().range().end,
            reports: engine.reports.len() as u64,
            copies: self.copies,
            refusals: self.refusals,
            a_slot: present(self.generations[0]),
            b_slot: present(self.generations[1]),
            c_slot: present(self.generations[2]),
            a_index,
            a_output,
            checkpoints: state.checkpoints,
            reclaimed: u64::from(self.reclaimed),
            restaged: u64::from(self.restaged),
            b_report: self.b_report,
            c_report: self.c_report,
            stable,
            detach: u64::from(self.detach),
            joins: self.joins,
        };
        observed.check(ledger.population.k, phase, self.generations);
        observed.emit(phase, io)
    }
}
pub(crate) fn run(args: &[std::ffi::OsString]) {
    let deadline = Deadline::new(Instant::now());
    if let Err(error) = run_checked(args, deadline) {
        eprintln!("normal-module-session-reuse FAILED: {error}");
        std::process::exit(1);
    }
}
fn run_checked(args: &[std::ffi::OsString], deadline: Deadline) -> Result<(), String> {
    deadline.check()?;
    let Setup {
        entries,
        ends,
        returns,
        cpus,
        k,
        hot,
        direction,
        custody,
        mut engine,
        stream,
        client,
        record,
        mut fail_stop,
    } = prepare(args)?;
    // Only these new fixed populations reserve another history/report slot.
    engine.history.reserve_exact(4);
    engine.reports.reserve_exact(3);
    let mut io = Io::new()?;
    let (tx, rx) = mpsc::sync_channel(1);
    let (events, replies) = mpsc::sync_channel(1);
    let worker_custody = Arc::clone(&custody);
    let worker_record = Arc::clone(&record);
    let mut retained = Vec::with_capacity(k.div_ceil(4) + 12);
    let mut ledger = None;
    let mut held = None;
    let mut copied_a = None;
    let mut progress = None;
    let mut handle = Some(joined_task::spawn(move || {
        run_worker(
            WorkStart {
                entries,
                client,
                custody: worker_custody,
                record: worker_record,
                cpu: cpus[1],
                k,
                hot,
            },
            rx,
            events,
            deadline,
        )
    }));
    let mut joined = None;
    let mut active_fail_stop = csv::FailStop(true);
    // Actual call/batch/token/report/joined owners outlive this entire closure.
    let outcome = (|| -> Result<(), String> {
        pin(Some(cpus[0]));
        next_message(&replies, &mut retained, deadline)?;
        let Message::Ready(id) = &retained[0] else {
            return Err("reuse attachment handshake".into());
        };
        let id = *id;
        metadata_for(
            id,
            cpus,
            k,
            direction,
            Geometry {
                entries,
                ends,
                returns: &returns,
            },
            &mut io,
            "module-session-reuse-v1",
        )?;
        assert_eq!(stream.identity(), identity(entries[0]));
        assert_eq!(stream.functions(), &FUNCTIONS);
        assert_eq!(stream.entries(), &entries);
        assert_eq!((stream.pid(), stream.install()), (id.pid, INSTALL));
        assert_eq!(
            stream.format(),
            rapid_profiler::frontend_native::HistoryFormat::AbsoluteV1
        );
        deadline.check()?;
        engine.arm(&mut io)?;
        deadline.check()?;
        let a = engine.current.unwrap();
        let generation_a = engine.epochs[a]
            .as_ref()
            .unwrap()
            .epoch()
            .generation()
            .get();
        ledger = Some(check::Ledger {
            population: check::Population {
                k,
                hot,
                generations: [generation_a, 0, 0],
                entries,
                ends,
                returns,
                id,
                rows: Vec::with_capacity(k + 5),
                totals: NormalTotals::default(),
                batches: 0,
            },
            stream,
            record: Arc::clone(&record),
            journals: Vec::with_capacity(k.div_ceil(4) + 2),
        });
        progress = Some(Progress {
            generations: [generation_a, 0, 0],
            copies: 0,
            refusals: 0,
            reclaimed: false,
            restaged: false,
            b_report: 0,
            c_report: 0,
            detach: false,
            joins: 0,
        });
        let ledger = ledger.as_mut().unwrap();
        let progress = progress.as_mut().unwrap();
        let mut state = WorkerState {
            totals: NormalTotals::default(),
            checkpoints: 0,
        };
        for (phase, cmd) in [(0, Command::Hot), (1, Command::Cold), (2, Command::Hold)] {
            send_owned(&tx, cmd, deadline).map_err(|(e, _)| e)?;
            state = Receive {
                replies: &replies,
                retained: &mut retained,
                ledger,
                engine: &engine,
                io: &mut io,
            }
            .state(phase, deadline)?;
            progress.phase(phase, state, ledger, &engine, None, &mut io)?;
        }
        deadline.check()?;
        engine.arm(&mut io)?;
        deadline.check()?;
        let b = engine.current.unwrap();
        assert_ne!(a, b);
        let generation_b = engine.epochs[b]
            .as_ref()
            .unwrap()
            .epoch()
            .generation()
            .get();
        assert!(generation_b > generation_a);
        progress.generations[1] = generation_b;
        ledger.population.generations[1] = generation_b;
        assert!(engine.reports.is_empty());
        deadline.check()?;
        assert!(engine.copy_report_at(a, &mut io)?);
        deadline.check()?;
        assert_eq!(engine.reports.len(), 1);
        assert_eq!(engine.reports[0].0, generation_a);
        assert_eq!(engine.reports[0].1.len(), k + 1);
        progress.copies += 1;
        held = Some(owner_check::Held::capture(
            &engine,
            a,
            state,
            &ledger.stream,
        ));
        copied_a = Some(check::OldCopy::capture(&engine, a));
        for _ in 0..2 {
            deadline.check()?;
            assert!(!engine.reclaim_at(a)?);
            progress.refusals += 1;
            held.as_ref()
                .unwrap()
                .unchanged(&owner_check::Held::capture(
                    &engine,
                    a,
                    state,
                    &ledger.stream,
                ));
            deadline.check()?;
        }
        progress.phase(3, state, ledger, &engine, copied_a.as_ref(), &mut io)?;
        send_owned(&tx, Command::Release, deadline).map_err(|(e, _)| e)?;
        state = Receive {
            replies: &replies,
            retained: &mut retained,
            ledger,
            engine: &engine,
            io: &mut io,
        }
        .state(4, deadline)?;
        deadline.check()?;
        assert!(engine.reclaim_at(a)?);
        progress.reclaimed = true;
        copied_a.as_ref().unwrap().check(&engine.reports);
        progress.phase(4, state, ledger, &engine, copied_a.as_ref(), &mut io)?;
        // reclaim_at just pushed A. Vacant A/spare plus current B make retire
        // inert. Nothing between this check and arm can push another bank.
        check::before_restage(
            slots(&engine),
            engine.current,
            engine.banks.len(),
            a,
            b,
            [generation_a, generation_b],
        );
        deadline.check()?;
        engine.arm(&mut io)?;
        deadline.check()?;
        let c = engine.current.unwrap();
        assert_eq!(c, a);
        let generation_c = engine.epochs[c]
            .as_ref()
            .unwrap()
            .epoch()
            .generation()
            .get();
        progress.generations[2] = generation_c;
        ledger.population.generations[2] = generation_c;
        check::after_restage(
            slots(&engine),
            engine.current,
            engine.banks.len(),
            a,
            b,
            progress.generations,
            &engine.epochs[c].as_ref().unwrap().snapshot(),
        );
        assert_eq!(engine.committed_arms, 3);
        progress.restaged = true;
        copied_a.as_ref().unwrap().check(&engine.reports);
        assert!(
            engine
                .controller
                .report(engine.epochs[b].as_ref().unwrap().epoch())
                .map_err(failure)?
                .is_none()
        );
        progress.b_report = 1;
        io.emit(format!(
            "META,epochs,{generation_a},{generation_b},{generation_c}\n"
        ))?;
        progress.phase(5, state, ledger, &engine, copied_a.as_ref(), &mut io)?;
        send_owned(&tx, Command::Recycle, deadline).map_err(|(e, _)| e)?;
        state = Receive {
            replies: &replies,
            retained: &mut retained,
            ledger,
            engine: &engine,
            io: &mut io,
        }
        .state(6, deadline)?;
        deadline.check()?;
        copied_a.as_ref().unwrap().check(&engine.reports);
        assert!(engine.copy_report_at(b, &mut io)?);
        assert_eq!(engine.reports.len(), 2);
        assert_eq!(
            (engine.reports[1].0, engine.reports[1].1.len()),
            (generation_b, 1)
        );
        progress.b_report = 2;
        assert!(engine.reclaim_at(b)?);
        engine.stop(&mut io)?;
        deadline.check()?;
        assert!(
            engine
                .controller
                .report(engine.epochs[c].as_ref().unwrap().epoch())
                .map_err(failure)?
                .is_none()
        );
        progress.c_report = 1;
        progress.phase(6, state, ledger, &engine, copied_a.as_ref(), &mut io)?;
        send_owned(&tx, Command::Finish, deadline).map_err(|(e, _)| e)?;
        state = Receive {
            replies: &replies,
            retained: &mut retained,
            ledger,
            engine: &engine,
            io: &mut io,
        }
        .state(7, deadline)?;
        finish_join(
            &mut handle,
            &mut joined,
            &replies,
            &mut retained,
            id,
            state,
            deadline,
        )?;
        progress.joins = 1;
        progress.detach = true;
        single_main();
        deadline.check()?;
        assert!(engine.copy_report_at(c, &mut io)?);
        progress.c_report = 2;
        assert!(engine.reclaim_at(c)?);
        copied_a.as_ref().unwrap().check(&engine.reports);
        worker::cpu_is(cpus[0]);
        custody.files_and_code();
        ledger.finish(&engine, &retained, &mut io)?;
        assert_eq!(state.totals, ledger.population.totals);
        progress.phase(7, state, ledger, &engine, copied_a.as_ref(), &mut io)?;
        let calls = k + 5;
        let sampled = k + 4;
        let batches = k.div_ceil(4) + 2;
        io.emit(format!("module-session-reuse:profile=session-absolute-v1:schedule=not-run:k={k}:direction={direction}:calls={calls}:confirmed={calls}:sampled={sampled}:unsampled=1:batches={batches}:reports=3:actions=4:banks=3:shared-owner-refusals=2:held-report-copies=1:reclaimed-before-checkpoint=1:restaged=1:worker-joins=1:complete\n"))?;
        assert!(io.output_len() <= 631092 && io.output_len() <= 1024 * 1024);
        while !io.drained() {
            deadline.check()?;
            io.write()?;
            deadline.check()?;
            if !io.drained() {
                std::thread::yield_now();
            }
        }
        custody.files_and_code();
        record.check();
        copied_a.as_ref().unwrap().check(&engine.reports);
        worker::cpu_is(cpus[0]);
        single_main();
        deadline.check()
    })();
    if let Err(error) = outcome {
        let retirement = joined
            .as_ref()
            .map_or_else(String::new, |task| format!("; {}", task.diagnostic()));
        eprintln!("normal-module-session-reuse FAILED: {error}{retirement}");
        std::process::exit(1);
    }
    active_fail_stop.0 = false;
    fail_stop.0 = false;
    Ok(())
}
