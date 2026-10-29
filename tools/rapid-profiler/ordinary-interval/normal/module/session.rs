//! Input-driven two-function session using the existing controller and worker loops.
//! Functional application only; output is tentative until post-write Schedule acceptance.
use super::*;
use crate::normal::session as shared;
use rapid_profiler::frontend_native::backoff::{Policy, Schedule};
use rapid_profiler::frontend_native::{
    NormalModuleHistoryBatch, NormalModuleSessionController, PreparedNormalModuleSessionController,
};
use shared::io::Io;
use shared::{Application as ApplicationTrait, failure};
use std::sync::OnceLock;
pub(in crate::normal) mod check;
pub(in crate::normal) mod input;
pub(crate) mod owner;
pub(in crate::normal) mod worker;

pub(in crate::normal) struct Application {
    ledger: check::Ledger,
    input: input::Input,
    custody: Arc<worker::Custody>,
    entries: [u64; 2],
    ends: [u64; 2],
    returns: [Vec<u64>; 2],
    ready: Arc<OnceLock<worker::Identity>>,
    cpus: [usize; 2],
    k: usize,
    epochs: u32,
}
impl Application {
    fn ready(&mut self, tid: u64, io: &mut Io) -> Result<(), String> {
        let id = *self.ready.get().expect("owned actual worker handshake");
        assert_eq!(id.tid, tid);
        assert_eq!(id.cpu, self.cpus[1]);
        assert_eq!(id.pid, std::process::id());
        assert_ne!(id.tid, u64::from(id.pid));
        worker::cpu_is(self.cpus[0]);
        self.ledger.ready(id);
        io.emit(format!(
            "READY,module-session-v1,{},{},10,2,64,2048,4,1,{},{},{},{},{},{},{},{},{},{},{}\n",
            self.k,
            self.epochs,
            INSTALL,
            id.pid,
            id.pid,
            id.tid,
            self.cpus[0],
            self.cpus[1],
            self.entries[0],
            self.entries[1],
            self.ends[0],
            self.ends[1],
            csv::invoke as *const () as usize as u64
        ))?;
        for (f, function) in FUNCTIONS.iter().enumerate() {
            for &pc in &self.returns[f] {
                io.emit(format!("RET,{},{}\n", function.0, pc - self.entries[f]))?;
            }
        }
        Ok(())
    }
}
impl ApplicationTrait for Application {
    type Controller = NormalModuleSessionController;
    type Command = input::Command;
    type Call = worker::Call;
    type Batch = NormalModuleBatch;
    type Completion = Result<(), input::InputCompletion>;
    fn accepted_len(&self) -> usize {
        self.ledger.population.accepted.len()
    }
    fn input(&mut self, io: &mut Io) -> Result<Option<input::Command>, String> {
        self.input.poll(io, self.ledger.population.accepted.len())
    }
    fn accept(&mut self, command: &input::Command) -> Result<(), String> {
        let input::Command::Record(record) = command else {
            unreachable!()
        };
        self.ledger.accept(record);
        Ok(())
    }
    fn batch(
        &mut self,
        calls: Vec<worker::Call>,
        batch: NormalModuleBatch,
        history: &[NormalModuleHistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        self.ledger.batch(calls, batch, history, io)
    }
    fn flushed(&mut self, _id: u64, _totals: NormalTotals, _io: &mut Io) -> Result<(), String> {
        Err("CSV input has no Flush command".into())
    }
    fn finish(
        &mut self,
        totals: NormalTotals,
        reports: &[(u64, Vec<RecordObservation>)],
        history: &[NormalModuleHistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        self.ledger.history_reports(history, reports);
        self.ledger.finish(totals, reports, io)
    }
    fn final_checks(&self) -> Result<(), String> {
        assert_eq!(
            self.ledger.population.rows.len(),
            self.ledger.population.accepted.len() * 2
        );
        Ok(())
    }
    fn final_custody(&self) -> Result<(), String> {
        worker::cpu_is(self.cpus[0]);
        self.custody.files_and_code();
        Ok(())
    }
    fn terminal(
        &self,
        schedule: &Schedule,
        history_end: u64,
        totals: NormalTotals,
        io: &mut Io,
    ) -> Result<(), String> {
        let fields: u64 = self
            .ledger
            .population
            .accepted
            .iter()
            .map(|r| r.fields)
            .sum();
        let bytes: usize = self
            .ledger
            .population
            .accepted
            .iter()
            .map(|r| r.length)
            .sum();
        io.emit(format!(
            "DONE,{},{:?},{},{},{},{},{},{},{},{},{},{},{},{},{},{},1,1\n",
            self.input.status(),
            schedule.stop_reason().unwrap(),
            schedule.armed(),
            history_end,
            self.ledger.population.accepted.len(),
            totals.entered,
            totals.ret_observed,
            totals.confirmed,
            totals.completed,
            totals.unsampled,
            self.ledger.population.batches,
            fields,
            bytes,
            u8::from(self.input.eof),
            self.input.error.map_or("none", input::Refusal::label),
            u8::from(self.input.eof && self.input.error.is_none())
        ))
    }
    fn completion(&self) -> Self::Completion {
        self.input.completion()
    }
}
fn number(value: &std::ffi::OsStr) -> Result<u64, String> {
    let s = value.to_str().ok_or("non-ASCII numeric argument")?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err("canonical unsigned decimal required".into());
    }
    s.parse().map_err(failure)
}
pub(crate) fn run(args: &[std::ffi::OsString]) {
    if let Err(error) = run_checked(args) {
        eprintln!("normal-module-session FAILED: {error}");
        std::process::exit(1);
    }
}
fn run_checked(args: &[std::ffi::OsString]) -> Result<(), String> {
    if args.len() != 8 {
        return Err("normal-module-session CANDIDATE TRUSTED_FINAL CSV_VA CSV_LENGTH LENGTH_VA LENGTH_LENGTH K EPOCHS".into());
    }
    let numbers = args[2..]
        .iter()
        .map(|s| number(s))
        .collect::<Result<Vec<_>, _>>()?;
    let vas = [numbers[0], numbers[2]];
    let lengths = [
        usize::try_from(numbers[1]).map_err(failure)?,
        usize::try_from(numbers[3]).map_err(failure)?,
    ];
    let k = usize::try_from(numbers[4]).map_err(failure)?;
    let epochs = u32::try_from(numbers[5]).map_err(failure)?;
    if !matches!(k, 10 | 1000)
        || !(1..=520).contains(&epochs)
        || vas[0] >= vas[1]
        || !(5..=256).contains(&lengths[0])
        || !(5..=80).contains(&lengths[1])
    {
        return Err("closed module-session profile".into());
    }
    single_main();
    let cpus = shared::cpus();
    let policy = Policy::ten_ms(k, epochs, 4096).map_err(failure)?;
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
    let spans: Vec<_> = custody
        .source
        .iter()
        .chain(&custody.generated)
        .cloned()
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
        history: Vec::with_capacity(epochs as usize + 1),
        reports: Vec::with_capacity(epochs as usize),
        k: 2 * k,
        committed_arms: 0,
    };
    let ready = Arc::new(OnceLock::new());
    // All bounded ledger outer capacities and transport storage precede Ready/start.
    let mut application = Application {
        ledger: check::Ledger::new(stream, entries, ends, returns.clone(), k, epochs as usize),
        input: input::Input::default(),
        custody: Arc::clone(&custody),
        entries,
        ends,
        returns,
        ready: Arc::clone(&ready),
        cpus,
        k,
        epochs,
    };
    let mut io = Io::new()?;
    let (tx, rx) = mpsc::sync_channel(4);
    let (events, replies) = mpsc::sync_channel(1);
    let worker_custody = Arc::clone(&custody);
    let mut handle = Some(joined_task::spawn(move || {
        worker::run(entries, client, worker_custody, ready, rx, events, cpus[1])
    }));
    let mut joined = None;
    let mut state = shared::LoopState::default();
    let mut trace = shared::loop_trace::Trace::default();
    // Every accepted input/pending cell and owner is outside this borrowing scope.
    // A hard refusal selects exit before dropping channels, epochs or the worker.
    let mut active_fail_stop = csv::FailStop(true);
    let outcome = (|| -> Result<Result<(), input::InputCompletion>, String> {
        pin(Some(cpus[0]));
        let shared::worker::Event::Ready { tid } = replies.recv_timeout(WAIT).map_err(failure)?
        else {
            return Err("module worker attachment handshake".into());
        };
        application.ready(tid, &mut io)?;
        shared::drive(shared::Loop {
            app: &mut application,
            engine: &mut engine,
            io: &mut io,
            tx: &tx,
            replies: &replies,
            handle: &mut handle,
            joined: &mut joined,
            state: &mut state,
            loop_trace: &mut trace,
            tid,
            policy,
            spans: &spans,
        })
    })();
    match outcome {
        Err(error) => {
            let details = trace.failure();
            let retirement = joined
                .as_ref()
                .map_or_else(String::new, |task| format!("; {}", task.diagnostic()));
            eprintln!("normal-module-session FAILED: {error}{details}{retirement}");
            std::process::exit(1);
        }
        Ok(Err(completion)) => {
            // Finalized typed input outcome; all owners stay in this scope until exit.
            eprint!("{}", completion.stderr());
            std::process::exit(1);
        }
        Ok(Ok(())) => {}
    }
    active_fail_stop.0 = false;
    fail_stop.0 = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_numeric_cli_never_normalizes_signs_spaces_or_overflow() {
        for (value, n) in [("0", 0), ("10", 10), ("18446744073709551615", u64::MAX)] {
            assert_eq!(number(std::ffi::OsStr::new(value)).unwrap(), n);
        }
        for value in [
            "",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1\n",
            "18446744073709551616",
        ] {
            assert!(number(std::ffi::OsStr::new(value)).is_err());
        }
    }
    #[test]
    fn accepted_module_pending_owner_survives_full_queue_and_disconnect_before_stop() {
        let (tx, rx) = mpsc::sync_channel(1);
        let a = Arc::new(input::Record::new(1, b"a,b").unwrap());
        let b = Arc::new(input::Record::new(2, b"").unwrap());
        tx.send(input::Command::Record(Arc::clone(&a))).unwrap();
        let mut pending = Some(input::Command::Record(Arc::clone(&b)));
        let mut stopped = false;
        assert!(!shared::dispatch(&tx, &mut pending, true, &mut stopped).unwrap());
        assert!(matches!(pending.as_ref(),Some(input::Command::Record(r))if Arc::ptr_eq(r,&b)));
        assert!(!stopped);
        let input::Command::Record(first) = rx.try_recv().unwrap() else {
            panic!()
        };
        assert!(Arc::ptr_eq(&first, &a));
        assert!(shared::dispatch(&tx, &mut pending, true, &mut stopped).unwrap());
        assert!(pending.is_none() && !stopped);
        let input::Command::Record(second) = rx.try_recv().unwrap() else {
            panic!()
        };
        assert!(Arc::ptr_eq(&second, &b));
        assert!(shared::dispatch(&tx, &mut pending, true, &mut stopped).unwrap());
        assert!(stopped);
        assert!(matches!(rx.try_recv().unwrap(), input::Command::Stop));
        pending = Some(input::Command::Record(Arc::clone(&b)));
        drop(rx);
        assert!(shared::dispatch(&tx, &mut pending, false, &mut stopped).is_err());
        assert!(matches!(pending.as_ref(),Some(input::Command::Record(r))if Arc::ptr_eq(r,&b)));
        assert_eq!((a.bytes(), b.bytes()), (b"a,b".as_slice(), b"".as_slice()));
    }
}
