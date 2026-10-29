//! Deterministic actual-worker custody control. Schedule is deliberately not run.
use super::*;
use shared::worker::Runtime;
use std::time::{Duration, Instant};
mod check;
#[cfg(test)]
mod tests;
type Engine = shared::engine::Engine<NormalModuleSessionController>;
type BatchEvent = shared::worker::Event<worker::Call, NormalModuleBatch>;

#[derive(Clone, Copy)]
struct Deadline {
    start: Instant,
    end: Instant,
}
impl Deadline {
    fn new(start: Instant) -> Self {
        Self {
            start,
            end: start.checked_add(Duration::from_secs(15)).unwrap(),
        }
    }
    fn check_at(self, now: Instant) -> Result<(), String> {
        if self.end != self.start.checked_add(Duration::from_secs(15)).unwrap()
            || now < self.start
            || now >= self.end
        {
            Err("original owner deadline".into())
        } else {
            Ok(())
        }
    }
    fn check(self) -> Result<(), String> {
        self.check_at(Instant::now())
    }
    fn remaining(self) -> Result<Duration, String> {
        let now = Instant::now();
        self.check_at(now)?;
        Ok(self.end.duration_since(now))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerState {
    totals: NormalTotals,
    checkpoints: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Hot,
    Cold,
    Hold,
    Release,
    Finish,
}
enum Message {
    Ready(worker::Identity),
    Batch(BatchEvent),
    State { phase: usize, state: WorkerState },
}

// A full queue retains precisely this value. A timeout/disconnect returns it;
// callers select fail-stop before dropping any returned Call/Batch ownership.
fn send_owned<T>(
    tx: &mpsc::SyncSender<T>,
    mut value: T,
    deadline: Deadline,
) -> Result<(), (String, T)> {
    loop {
        if let Err(error) = deadline.check() {
            return Err((error, value));
        }
        match tx.try_send(value) {
            Ok(()) => return Ok(()),
            Err(mpsc::TrySendError::Full(returned)) => value = returned,
            Err(mpsc::TrySendError::Disconnected(returned)) => {
                return Err(("owner channel disconnected".into(), returned));
            }
        }
        std::thread::yield_now();
    }
}
fn send_message(tx: &mpsc::SyncSender<Message>, value: Message, deadline: Deadline) {
    if let Err(retained) = send_owned(tx, value, deadline) {
        let _live_until_abort = retained;
        std::process::abort();
    }
}
fn command(rx: &mpsc::Receiver<Command>, expected: Command, deadline: Deadline) {
    assert_eq!(
        rx.recv_timeout(deadline.remaining().unwrap()).unwrap(),
        expected
    );
    deadline.check().unwrap();
}
fn flush(
    worker: &mut worker::Worker,
    tx: &mpsc::SyncSender<Message>,
    checkpoints: &mut u64,
    deadline: Deadline,
) {
    deadline.check().unwrap();
    let event = worker.take_batch().expect("nonempty actual owner calls");
    *checkpoints += 1;
    send_message(tx, Message::Batch(event), deadline);
}
fn barrier(
    worker: &worker::Worker,
    tx: &mpsc::SyncSender<Message>,
    phase: usize,
    checkpoints: u64,
    deadline: Deadline,
) {
    worker.postflight();
    send_message(
        tx,
        Message::State {
            phase,
            state: WorkerState {
                totals: worker.totals(),
                checkpoints,
            },
        },
        deadline,
    );
}
struct WorkStart {
    entries: [u64; 2],
    client: rapid_profiler::frontend_native::NormalModuleClient,
    custody: Arc<worker::Custody>,
    record: Arc<input::Record>,
    cpu: usize,
    k: usize,
    hot: usize,
}
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
    let mut worker = worker::Worker::attach(entries, client, custody, cpu);
    send_message(&tx, Message::Ready(worker.identity()), deadline);
    let mut checkpoints = 0;
    command(&rx, Command::Hot, deadline);
    for i in 0..k {
        deadline.check().unwrap();
        worker.call_one(Arc::clone(&record), hot);
        deadline.check().unwrap();
        if (i + 1) % 4 == 0 || i + 1 == k {
            flush(&mut worker, &tx, &mut checkpoints, deadline);
        }
    }
    barrier(&worker, &tx, 0, checkpoints, deadline);
    command(&rx, Command::Cold, deadline);
    worker.call_one(Arc::clone(&record), 1 - hot);
    flush(&mut worker, &tx, &mut checkpoints, deadline);
    barrier(&worker, &tx, 1, checkpoints, deadline);
    command(&rx, Command::Hold, deadline);
    worker.call_one(Arc::clone(&record), hot);
    barrier(&worker, &tx, 2, checkpoints, deadline); // No idle flush on this separate route.
    command(&rx, Command::Release, deadline);
    worker.call_one(record, 1 - hot);
    barrier(&worker, &tx, 4, checkpoints, deadline); // B remains pending here.
    command(&rx, Command::Finish, deadline);
    flush(&mut worker, &tx, &mut checkpoints, deadline);
    let totals = worker.finish(); // Same postflight, empty checkpoint, detach and postflight.
    checkpoints += 1;
    let state = WorkerState {
        totals,
        checkpoints,
    };
    send_message(&tx, Message::State { phase: 5, state }, deadline);
    deadline.check().unwrap();
    state
}
fn next_message(
    replies: &mpsc::Receiver<Message>,
    retained: &mut Vec<Message>,
    deadline: Deadline,
) -> Result<(), String> {
    let message = replies
        .recv_timeout(deadline.remaining()?)
        .map_err(failure)?;
    retained.push(message); // Retain before checking time, shape or accounting.
    deadline.check()
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
                _ => return Err("unexpected owner message".into()),
            }
        }
    }
}

struct Progress {
    generations: [u64; 2],
    a: usize,
    b: Option<usize>,
    copies: u64,
    refusals: u64,
    reclaimed: bool,
    b_report: u64,
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
        io: &mut Io,
    ) -> Result<(), String> {
        let a = engine.epochs[self.a].as_ref();
        let b = self.b.and_then(|i| engine.epochs[i].as_ref());
        let (a_index, a_output) = check::copied_state(a);
        let observed = check::PhaseState {
            totals: state.totals,
            batches: ledger.population.batches,
            banks: engine.banks.len() as u64,
            current: engine.current.map_or(0, |i| {
                engine.epochs[i]
                    .as_ref()
                    .unwrap()
                    .epoch()
                    .generation()
                    .get()
            }),
            history: engine.history.last().unwrap().range().end,
            reports: engine.reports.len() as u64,
            copies: self.copies,
            refusals: self.refusals,
            a_slot: u64::from(a.is_some()),
            b_slot: u64::from(b.is_some()),
            a_index,
            a_output,
            checkpoints: state.checkpoints,
            reclaimed: u64::from(self.reclaimed),
            b_report: self.b_report,
            detach: u64::from(self.detach),
            joins: self.joins,
        };
        observed.check(ledger.population.k, phase, self.generations);
        observed.emit(phase, io)
    }
}
struct Geometry<'a> {
    entries: [u64; 2],
    ends: [u64; 2],
    returns: &'a [Vec<u64>; 2],
}
fn metadata(
    id: worker::Identity,
    cpus: [usize; 2],
    k: usize,
    direction: &str,
    geometry: Geometry<'_>,
    io: &mut Io,
) -> Result<(), String> {
    let Geometry {
        entries,
        ends,
        returns,
    } = geometry;
    assert!(
        entries[0] > 0 && entries[0] < ends[0] && ends[0] <= entries[1] && entries[1] < ends[1]
    );
    assert!(
        (5..=256).contains(&(ends[0] - entries[0])) && (5..=80).contains(&(ends[1] - entries[1]))
    );
    assert_eq!(entries[0] & !4095, (ends[1] - 1) & !4095);
    assert_eq!(id.pid, std::process::id());
    assert!((1..=i32::MAX as u32).contains(&id.pid) && id.tid <= i32::MAX as u64);
    assert!(id.tid != 0 && id.tid != u64::from(id.pid));
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        i64::from(id.pid)
    );
    assert_eq!(id.cpu, cpus[1]);
    assert!(cpus[0] != cpus[1] && cpus.iter().all(|&cpu| cpu < 1024));
    worker::cpu_is(cpus[0]);
    let caller = csv::invoke as *const () as usize as u64;
    assert!(id.caller.0 <= caller && caller < id.caller.1 && id.stack.0 < id.stack.1);
    io.emit(format!("META,run,module-session-owner-v1,session-absolute-v1,not-run,{k},{direction},{INSTALL},{},{},{},{},{},1\n",
        id.pid, id.pid, id.tid, cpus[0], cpus[1]))?;
    io.emit(format!(
        "META,code,{},{},1,101,202,{},{},{},{},{caller}\n",
        "6f".repeat(32),
        entries[0],
        entries[0],
        ends[0],
        entries[1],
        ends[1]
    ))?;
    io.emit(format!(
        "META,memory,{},{},{},{}\n",
        id.stack.0, id.stack.1, id.caller.0, id.caller.1
    ))?;
    io.emit("META,input,612c622c63,5,3,5\n".into())?;
    for f in 0..2 {
        assert!((1..=4).contains(&returns[f].len()) && returns[f].windows(2).all(|w| w[0] < w[1]));
        for &pc in &returns[f] {
            assert!(entries[f] < pc && pc < ends[f]);
            io.emit(format!("META,ret,{f},{}\n", pc - entries[f]))?;
        }
    }
    Ok(())
}
pub(crate) fn run(args: &[std::ffi::OsString]) {
    let deadline = Deadline::new(Instant::now());
    if let Err(error) = run_checked(args, deadline) {
        eprintln!("normal-module-session-owner FAILED: {error}");
        std::process::exit(1);
    }
}
fn run_checked(args: &[std::ffi::OsString], deadline: Deadline) -> Result<(), String> {
    deadline.check()?;
    if args.len() != 8 {
        return Err("normal-module-session-owner CANDIDATE TRUSTED_FINAL CSV_VA CSV_LENGTH LENGTH_VA LENGTH_LENGTH K DIRECTION".into());
    }
    let n = args[2..7]
        .iter()
        .map(|s| number(s))
        .collect::<Result<Vec<_>, _>>()?;
    let vas = [n[0], n[2]];
    let lengths = [
        usize::try_from(n[1]).map_err(failure)?,
        usize::try_from(n[3]).map_err(failure)?,
    ];
    let k = usize::try_from(n[4]).map_err(failure)?;
    let direction = args[7].to_str().ok_or("owner direction ASCII")?;
    let hot = match direction {
        "csv-length" => 0,
        "length-csv" => 1,
        _ => return Err("owner direction".into()),
    };
    if !matches!(k, 10 | 1000)
        || vas[0] >= vas[1]
        || !(5..=256).contains(&lengths[0])
        || !(5..=80).contains(&lengths[1])
    {
        return Err("closed module owner profile".into());
    }
    single_main();
    let cpus = shared::cpus();
    let candidate = Path::new(&args[0]);
    let trusted = Path::new(&args[1]);
    let bytes = expected_file(candidate, trusted);
    let selections = [
        TrustedFunctionSelection::new(&bytes, vas[0], lengths[0], LABELS[0]).map_err(failure)?,
        TrustedFunctionSelection::new(&bytes, vas[1], lengths[1], LABELS[1]).map_err(failure)?,
    ];
    // SAFETY: two independently selected read-only scalar leaves, sole entry per
    // function, sequential union/no recursion or reentry, ordinary CALL/RET only;
    // no active CET, signals, cancellation, nonlocal exits, writers or unload.
    // stdin bytes never select code or alter the exact function/table contract.
    let owner = unsafe {
        LoadedNormalModule::load_selected_pair(
            candidate,
            [&selections[0], &selections[1]],
            NormalModuleContract {
                single_external_entry_per_function: true,
                sequential_call_ret_only: true,
                no_active_cet: true,
            },
        )
    }
    .map_err(failure)?;
    owner.verify_original().map_err(failure)?;
    let entries = owner.functions().each_ref().map(|f| f.entry());
    let ends = std::array::from_fn(|i| entries[i].checked_add(lengths[i] as u64).unwrap());
    let returns = owner
        .functions()
        .each_ref()
        .map(|f| f.certificate().returns().to_vec());
    assert_eq!(owner.source_pages().len(), 1);
    assert_eq!(owner.source_pages()[0].bytes.len(), 4096);
    assert_eq!(entries[0] & !4095, entries[1] & !4095);
    for f in 0..2 {
        assert_eq!(
            owner.functions()[f].certificate().range(),
            (entries[f], ends[f])
        );
    }
    let mut custody = worker::Custody::new(candidate, trusted, bytes.clone());
    // From publication onward, an unwind must not release executable/attached owners.
    let mut fail_stop = csv::FailStop(true);
    let prep = NormalModuleSitePreparation::new_with_policies(
        owner,
        identity(entries[0]),
        [
            NormalModulePreparationPolicy::CertifiedBlocks,
            NormalModulePreparationPolicy::WholeFunction,
        ],
    )
    .map_err(failure)?;
    for f in 0..2 {
        assert_eq!(prep.functions()[f].range(), (entries[f], ends[f]));
        assert_eq!(prep.functions()[f].returns(), returns[f]);
    }
    custody.source = prep
        .plan()
        .plan()
        .final_bytes()
        .iter()
        .map(|s| (s.address, s.bytes.clone()))
        .collect();
    custody.generated = prep
        .plan()
        .images()
        .iter()
        .map(|i| (i.address(), i.bytes().to_vec()))
        .collect();
    let site = publish(prep);
    custody.files_and_code();
    let custody = Arc::new(custody);
    let mut prepared =
        PreparedNormalModuleSessionController::new(site, INSTALL, FUNCTIONS, k).map_err(failure)?;
    let banks = prepared.prepare_epoch_storage().map_err(failure)?;
    assert_eq!(banks.len(), 3);
    // SAFETY: pristine exact E3 module session with already touched banks and one
    // future controlled calling worker; main performs no target calls or gated API.
    let (controller, client) = unsafe { prepared.activate_concurrent() }.map_err(failure)?;
    let stream = controller
        .history_window()
        .map_err(failure)?
        .stream()
        .clone();
    let mut engine = shared::engine::Engine {
        controller,
        epochs: [None, None, None],
        banks,
        current: None,
        history: Vec::with_capacity(3),
        reports: Vec::with_capacity(2),
        k: 2 * k,
        committed_arms: 0,
    };
    let record = Arc::new(input::Record::new(1, b"a,b,c").unwrap());
    assert_eq!((record.fields, record.length), (3, 5));
    let mut io = Io::new()?;
    let (tx, rx) = mpsc::sync_channel(1);
    let (events, replies) = mpsc::sync_channel(1);
    let worker_custody = Arc::clone(&custody);
    let worker_record = Arc::clone(&record);
    let mut retained = Vec::with_capacity(k.div_ceil(4) + 8);
    let mut ledger = None;
    let mut held = None;
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
    // All physical-call events, code/epoch owners, Report copies and snapshots
    // outlive this error-selecting closure. A hard error exits before their drops.
    let outcome = (|| -> Result<(), String> {
        pin(Some(cpus[0]));
        next_message(&replies, &mut retained, deadline)?;
        let Message::Ready(id) = &retained[0] else {
            return Err("owner attachment handshake".into());
        };
        let id = *id;
        metadata(
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
                generations: [generation_a, 0],
                entries,
                ends,
                returns,
                id,
                rows: Vec::with_capacity(k + 3),
                totals: NormalTotals::default(),
                batches: 0,
            },
            stream,
            record: Arc::clone(&record),
            journals: Vec::with_capacity(k.div_ceil(4) + 2),
        });
        progress = Some(Progress {
            generations: [generation_a, 0],
            a,
            b: None,
            copies: 0,
            refusals: 0,
            reclaimed: false,
            b_report: 0,
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
            progress.phase(phase, state, ledger, &engine, &mut io)?;
        }
        // Engine::arm first skips current A in retire; this does not attempt A
        // reclamation or create an extra Report before the declared two attempts.
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
        progress.b = Some(b);
        progress.generations[1] = generation_b;
        ledger.population.generations[1] = generation_b;
        io.emit(format!("META,epochs,{generation_a},{generation_b}\n"))?;
        assert!(engine.reports.is_empty());
        deadline.check()?;
        assert!(engine.copy_report_at(a, &mut io)?);
        deadline.check()?;
        assert_eq!(engine.reports.len(), 1);
        assert_eq!(engine.reports[0].0, generation_a);
        assert_eq!(engine.reports[0].1.len(), k + 1);
        progress.copies += 1;
        held = Some(check::Held::capture(&engine, a, state, &ledger.stream));
        for _ in 0..2 {
            deadline.check()?;
            assert!(!engine.reclaim_at(a)?); // Actual SharedOwner, same returned token.
            progress.refusals += 1;
            held.as_ref().unwrap().unchanged(&check::Held::capture(
                &engine,
                a,
                state,
                &ledger.stream,
            ));
            deadline.check()?;
        }
        progress.phase(3, state, ledger, &engine, &mut io)?;
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
        assert!(engine.reclaim_at(a)?); // B is still pending; no checkpoint permission yet.
        progress.reclaimed = true;
        engine.stop(&mut io)?;
        deadline.check()?;
        assert!(
            engine
                .controller
                .report(engine.epochs[b].as_ref().unwrap().epoch())
                .map_err(failure)?
                .is_none()
        );
        progress.b_report = 1;
        progress.phase(4, state, ledger, &engine, &mut io)?;
        send_owned(&tx, Command::Finish, deadline).map_err(|(e, _)| e)?;
        state = Receive {
            replies: &replies,
            retained: &mut retained,
            ledger,
            engine: &engine,
            io: &mut io,
        }
        .state(5, deadline)?;
        while !handle.as_ref().unwrap().is_finished() {
            deadline.check()?;
            std::thread::yield_now();
        }
        deadline.check()?;
        joined = Some(handle.take().unwrap().join());
        let task = joined.as_mut().unwrap();
        assert_eq!(u64::from(task.tid()), id.tid);
        while !joined_task::poll_exclusive(&mut [&mut *task], || {
            deadline.check().map_err(joined_task::Error::Clock)
        })
        .map_err(failure)?
        {
            deadline.check()?;
            std::thread::yield_now();
        }
        assert_eq!(
            task.result().as_ref().map_err(|_| "owner worker panic")?,
            &state
        );
        match replies.try_recv() {
            Err(mpsc::TryRecvError::Disconnected) => {}
            Err(mpsc::TryRecvError::Empty) => {
                return Err("owner sender survived native join".into());
            }
            Ok(extra) => {
                retained.push(extra);
                return Err("extra owner event after completion".into());
            }
        }
        progress.joins = 1;
        progress.detach = true;
        single_main();
        deadline.check()?;
        assert!(engine.copy_report_at(b, &mut io)?);
        progress.b_report = 2;
        assert!(engine.reclaim_at(b)?);
        worker::cpu_is(cpus[0]);
        custody.files_and_code();
        ledger.finish(&engine, &retained, &mut io)?;
        assert_eq!(state.totals, ledger.population.totals);
        progress.phase(5, state, ledger, &engine, &mut io)?;
        let calls = k + 3;
        let sampled = k + 2;
        let batches = k.div_ceil(4) + 2;
        io.emit(format!("module-session-owner:profile=session-absolute-v1:schedule=not-run:k={k}:direction={direction}:calls={calls}:confirmed={calls}:sampled={sampled}:unsampled=1:batches={batches}:reports=2:actions=3:banks=3:shared-owner-refusals=2:held-report-copies=1:reclaimed-before-checkpoint=1:worker-joins=1:complete\n"))?;
        assert!(io.output_len() <= 629852 && io.output_len() <= 1024 * 1024);
        while !io.drained() {
            deadline.check()?;
            io.write()?;
            deadline.check()?;
            if !io.drained() {
                std::thread::yield_now();
            }
        }
        // The printed terminal is tentative until these checks and outer closure.
        custody.files_and_code();
        record.check();
        worker::cpu_is(cpus[0]);
        single_main();
        deadline.check()
    })();
    if let Err(error) = outcome {
        let retirement = joined
            .as_ref()
            .map_or_else(String::new, |task| format!("; {}", task.diagnostic()));
        eprintln!("normal-module-session-owner FAILED: {error}{retirement}");
        std::process::exit(1);
    }
    active_fail_stop.0 = false;
    fail_stop.0 = false;
    Ok(())
}
