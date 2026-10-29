//! One actual normal parent CALL per accepted CSV record; its original E8 calls the child.
//! Functional observations only; output remains tentative through final Schedule acceptance.
use super::module::session::{input, worker as pair_worker};
use super::session as shared;
use super::*;
use rapid_profiler::frontend_native::backoff::{Policy, Schedule};
use rapid_profiler::frontend_native::{
    BridgeError, EpochStorageReclaimError, InstalledNormalCallPairSite, IntervalEpoch,
    IntervalEpochStorage, LoadedNormalCallPair, NormalCallPairBatch, NormalCallPairContract,
    NormalCallPairHistoryBatch, NormalCallPairHistoryStream, NormalCallPairSessionController,
    NormalCallPairSitePreparation, NormalCallPairTotals, PreparedNormalCallPairSessionController,
};
use shared::io::Io;
use shared::{Application as ApplicationTrait, failure};
use std::sync::OnceLock;
mod check;
#[cfg(test)]
mod tests;
mod worker;
const INSTALL: u64 = 0x6370_0001;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Selection {
    function: FunctionId,
    va: u64,
    extent: usize,
}
fn number(value: &std::ffi::OsStr) -> Result<u64, String> {
    let s = value.to_str().ok_or("non-ASCII numeric argument")?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err("canonical unsigned decimal required".into());
    }
    s.parse().map_err(failure)
}
fn arguments(args: &[std::ffi::OsString]) -> Result<(usize, u32, [Selection; 2]), String> {
    if args.len() != 10 {
        return Err("normal-call-pair-session CANDIDATE TRUSTED_FINAL K EPOCHS PARENT_ID PARENT_VA PARENT_EXTENT CHILD_ID CHILD_VA CHILD_EXTENT".into());
    }
    let k = usize::try_from(number(&args[2])?).map_err(failure)?;
    let epochs = u32::try_from(number(&args[3])?).map_err(failure)?;
    if !matches!(k, 10 | 1000) || !(1..=520).contains(&epochs) {
        return Err("closed CallPair session profile".into());
    }
    let one = |at: usize| -> Result<Selection, String> {
        Ok(Selection {
            function: FunctionId(number(&args[at])?),
            va: number(&args[at + 1])?,
            extent: usize::try_from(number(&args[at + 2])?).map_err(failure)?,
        })
    };
    let selected = [one(4)?, one(7)?];
    let ends = selected.map(|s| s.va.checked_add(s.extent as u64));
    if selected[0].function == selected[1].function
        || selected.iter().any(|s| s.va == 0)
        || !(5..=80).contains(&selected[0].extent)
        || !(1..=256).contains(&selected[1].extent)
        || ends.iter().any(Option::is_none)
        || (selected[0].va < ends[1].unwrap() && selected[1].va < ends[0].unwrap())
    {
        return Err("independent disjoint parent/child selections required".into());
    }
    Ok((k, epochs, selected))
}
fn packed(record: &input::Record) -> u64 {
    record.check();
    assert!(record.length <= 64 && record.fields <= 65);
    ((record.length as u64) << 32) | record.fields
}
fn completion_stderr(c: input::InputCompletion) -> String {
    match c {
        input::InputCompletion::Refused(why) => {
            format!("normal-call-pair-session INPUT_REFUSED: {}\n", why.label())
        }
        input::InputCompletion::Incomplete => "normal-call-pair-session INPUT_INCOMPLETE\n".into(),
    }
}
fn validate_line(line: &str) {
    assert!(
        line.bytes()
            .all(|b| b == b'\n' || (0x20..=0x7e).contains(&b))
            && line.len() <= 350
            && line.ends_with('\n')
    );
    assert_eq!(line.bytes().filter(|&b| b == b'\n').count(), 1);
    assert!(!line.contains('\r'));
}
fn emit(io: &mut Io, line: String) -> Result<(), String> {
    validate_line(&line);
    io.emit(line)
}
pub(in crate::normal) struct Controller {
    inner: NormalCallPairSessionController,
    functions: [FunctionId; 2],
}
impl shared::engine::Controller for Controller {
    type History = NormalCallPairHistoryBatch;
    fn drain_history(&mut self) -> Result<Option<Self::History>, BridgeError> {
        self.inner.drain_history()
    }
    fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        self.inner.report(epoch)
    }
    fn reclaim_storage(
        &mut self,
        epoch: IntervalEpoch,
    ) -> Result<IntervalEpochStorage, (EpochStorageReclaimError, IntervalEpoch)> {
        self.inner.reclaim_storage(epoch)
    }
    #[allow(clippy::result_large_err)]
    // Exact bank stays inline until custody is restored, without a boxed error.
    fn stage_prepared(
        &mut self,
        bank: IntervalEpochStorage,
    ) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)> {
        self.inner.stage_prepared(bank)
    }
    fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        self.inner.arm(epoch)
    }
    fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        self.inner.disarm(epoch)
    }
    fn check_report(&self, generation: u64, rows: &[RecordObservation], capacity: usize) {
        check::report_shape(generation, rows, capacity, &self.functions);
    }
    fn final_check(&self, history: &[Self::History]) -> Result<(), String> {
        let w = self.inner.history_window().map_err(failure)?;
        assert_eq!(w.stream().functions(), &self.functions);
        let last = history.last().expect("complete arm/remove history");
        assert_eq!(w.stream(), last.stream());
        assert_eq!(
            w.status(),
            rapid_profiler::frontend::ControllerStatus::Ready
        );
        assert_eq!(w.current(), None);
        assert_eq!(w.enabled(), &[true]);
        assert_eq!(w.retained_failed_generation(), None);
        assert_eq!(w.last_batch_number(), last.number());
        assert_eq!(w.range().end, last.range().end);
        assert_eq!(w.after(), last.after());
        assert_eq!(
            w.before(),
            history
                .iter()
                .rev()
                .find_map(|h| h.binding_at(w.range().start))
                .unwrap()
        );
        assert_eq!(w.range().end - w.range().start, w.actions().len() as u64);
        for (i, action) in w.actions().iter().enumerate() {
            let index = w.range().start + i as u64;
            let expected = history
                .iter()
                .find_map(|h| {
                    h.range()
                        .contains(&index)
                        .then(|| &h.actions()[(index - h.range().start) as usize])
                })
                .unwrap();
            assert_eq!(action, expected);
        }
        Ok(())
    }
}

fn publish(prep: NormalCallPairSitePreparation) -> InstalledNormalCallPairSite {
    single_main();
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert!((1..=2).contains(&originals.len()));
    let sources: Vec<_> = originals
        .iter()
        .map(|s| {
            let range = AddressRange::new(s.address, s.bytes.len()).unwrap();
            assert_eq!(range.start() % 4096, 0);
            assert_eq!(range.len(), 4096);
            range
        })
        .collect();
    assert!(
        sources
            .windows(2)
            .all(|w| w[0].start() + 4096 <= w[1].start())
    );
    let mut ranges = sources.clone();
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = &prep;
    let aliases: Vec<_> = sources
        .iter()
        .map(|&source| {
            protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: exact complete source page, sole thread and no saved resumes.
            unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap()
        })
        .collect();
    let result = {
        let mut lease =
            unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
        let result = unsafe {
            planned.publish_with(&aliases, &mut lease, || {
                for &source in &sources {
                    protect(source, libc::PROT_READ | libc::PROT_EXEC)?;
                }
                Ok(())
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
            eprintln!("call-pair publication FAILED: {error:?}");
            std::process::abort();
        }
    };
    // SAFETY: complete union transaction, all source pages RX, retained owners.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

pub(in crate::normal) struct Application {
    ledger: check::Ledger,
    input: input::Input,
    custody: Arc<pair_worker::Custody>,
    selected: [Selection; 2],
    geometry: check::Geometry,
    ready: Arc<OnceLock<pair_worker::Identity>>,
    cpus: [usize; 2],
    k: usize,
    epochs: u32,
}
impl Application {
    fn ready(&mut self, tid: u64, io: &mut Io) -> Result<(), String> {
        let id = *self.ready.get().expect("owned actual worker handshake");
        assert_eq!(
            (id.tid, id.cpu, id.pid),
            (tid, self.cpus[1], std::process::id())
        );
        assert_ne!(id.tid, u64::from(id.pid));
        pair_worker::cpu_is(self.cpus[0]);
        self.ledger.ready(id);
        emit(
            io,
            format!(
                "READY,normal-call-pair-session-v1,{},{},10,2,64,2048,4,1,{},{},{},{},{},{},{}\n",
                self.k,
                self.epochs,
                INSTALL,
                id.pid,
                id.pid,
                id.tid,
                self.cpus[0],
                self.cpus[1],
                csv::invoke as *const () as usize as u64
            ),
        )?;
        for (node, selected) in self.selected.iter().enumerate() {
            emit(
                io,
                format!(
                    "FUNCTION,{node},{},{},{},{},{},{}\n",
                    selected.function.0,
                    selected.va,
                    selected.extent,
                    self.geometry.entries[node],
                    self.geometry.ends[node],
                    self.geometry.returns[node].len()
                ),
            )?;
            for &pc in &self.geometry.returns[node] {
                emit(
                    io,
                    format!("RET,{node},{}\n", pc - self.geometry.entries[node]),
                )?;
            }
        }
        emit(
            io,
            format!(
                "EDGE,{},{},{},{}\n",
                self.geometry.call_pc,
                self.geometry.entries[1],
                self.geometry.continuation,
                self.geometry.child_delta
            ),
        )
    }
}
impl ApplicationTrait for Application {
    type Controller = Controller;
    type Command = input::Command;
    type Call = worker::Call;
    type Batch = NormalCallPairBatch;
    type Completion = Result<(), input::InputCompletion>;
    fn accepted_len(&self) -> usize {
        self.ledger.accounting.accepted.len()
    }
    fn input(&mut self, io: &mut Io) -> Result<Option<input::Command>, String> {
        self.input
            .poll_with_limit(io, self.ledger.accounting.accepted.len(), input::RECORDS)
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
        batch: NormalCallPairBatch,
        history: &[NormalCallPairHistoryBatch],
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
        history: &[NormalCallPairHistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        self.ledger.finish(totals, reports, history, io)
    }
    fn final_checks(&self) -> Result<(), String> {
        self.ledger.final_checks();
        Ok(())
    }
    fn final_custody(&self) -> Result<(), String> {
        pair_worker::cpu_is(self.cpus[0]);
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
            .accounting
            .accepted
            .iter()
            .map(|r| r.fields)
            .sum();
        let bytes: usize = self
            .ledger
            .accounting
            .accepted
            .iter()
            .map(|r| r.length)
            .sum();
        emit(
            io,
            format!(
                "DONE,{},{:?},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                self.input.status(),
                schedule.stop_reason().unwrap(),
                schedule.armed(),
                history_end,
                self.ledger.accounting.accepted.len(),
                totals.entered,
                totals.ret_observed,
                totals.confirmed,
                totals.completed,
                totals.unsampled,
                self.ledger.accounting.totals.roots,
                self.ledger.accounting.totals.child_acks,
                self.ledger.batches.len(),
                fields,
                bytes,
                u8::from(self.input.eof),
                self.input.error.map_or("none", input::Refusal::label),
                u8::from(self.input.eof && self.input.error.is_none())
            ),
        )
    }
    fn completion(&self) -> Self::Completion {
        self.input.completion()
    }
}
pub(crate) fn run(args: &[std::ffi::OsString]) {
    if let Err(error) = run_checked(args) {
        eprintln!("normal-call-pair-session FAILED: {error}");
        std::process::exit(1);
    }
}
fn run_checked(args: &[std::ffi::OsString]) -> Result<(), String> {
    let (k, epochs, selected) = arguments(args)?;
    single_main();
    let cpus = shared::cpus();
    assert!(cpus.iter().all(|&cpu| cpu < 1024));
    let policy = Policy::ten_ms(k, epochs, 4096).map_err(failure)?;
    let candidate = Path::new(&args[0]);
    let trusted = Path::new(&args[1]);
    let bytes = expected_file(candidate, trusted);
    let parent =
        TrustedFunctionSelection::new(&bytes, selected[0].va, selected[0].extent, "parent")
            .map_err(failure)?;
    let child = TrustedFunctionSelection::new(&bytes, selected[1].va, selected[1].extent, "child")
        .map_err(failure)?;
    // SAFETY: complete independently selected functions in this retained ELF.
    // Only the parent has external entries; its one original E8 enters the child.
    // Ordinary SysV return only, immutable code/input, no signals/CET/unwind/fork,
    // reentry, cancellation, alias writers or unload; input never selects code.
    // This contract and mapped-stack checks do not grant native-state or callback
    // worst-case stack qualification; that remains an independent prerequisite.
    let owner = unsafe {
        LoadedNormalCallPair::load_selected(
            candidate,
            &parent,
            &child,
            NormalCallPairContract {
                parent_only_external_entry: true,
                ordinary_ret_only: true,
                no_active_cet: true,
            },
        )
    }
    .map_err(failure)?;
    owner.verify_original().map_err(failure)?;
    let entries = [owner.parent().entry(), owner.child().entry()];
    let ends = std::array::from_fn(|i| entries[i].checked_add(selected[i].extent as u64).unwrap());
    let returns = [
        owner.parent().certificate().returns().to_vec(),
        owner.child().certificate().returns().to_vec(),
    ];
    assert_eq!(owner.parent().certificate().range(), (entries[0], ends[0]));
    assert_eq!(owner.child().certificate().range(), (entries[1], ends[1]));
    let edge = owner.edge();
    let geometry = check::Geometry {
        functions: selected.map(|s| s.function),
        entries,
        ends,
        returns,
        call_pc: edge.call_pc(),
        continuation: edge.continuation(),
        child_delta: owner.parent().certificate().child_stack_delta(),
    };
    geometry.check();
    assert_eq!(edge.callee_entry(), entries[1]);
    let source_pages: Vec<_> = owner
        .source_pages()
        .iter()
        .map(|s| (s.address, s.bytes.clone()))
        .collect();
    assert!((1..=2).contains(&source_pages.len()));
    for (address, bytes) in &source_pages {
        assert_eq!(address % 4096, 0);
        assert_eq!(bytes.len(), 4096);
    }
    let mut custody = pair_worker::Custody::new(candidate, trusted, bytes.clone());
    let mut fail_stop = csv::FailStop(true);
    let prep = NormalCallPairSitePreparation::new(owner, identity(entries[0])).map_err(failure)?;
    assert_eq!(prep.edge(), edge);
    geometry.check_roles(&prep.roles().collect::<Vec<_>>());
    for i in 0..2 {
        assert_eq!(prep.functions()[i].range(), (entries[i], ends[i]));
        assert_eq!(prep.functions()[i].returns(), geometry.returns[i]);
    }
    assert_eq!(
        prep.plan()
            .plan()
            .originals()
            .iter()
            .map(|s| (s.address, s.bytes.clone()))
            .collect::<Vec<_>>(),
        source_pages
    );
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
    let functions = geometry.functions;
    let mut prepared =
        PreparedNormalCallPairSessionController::new(site, INSTALL, functions[0], functions[1], k)
            .map_err(failure)?;
    let banks = prepared.prepare_epoch_storage().map_err(failure)?;
    assert_eq!(banks.len(), 3);
    // SAFETY: pristine exact prepared E3 set, one future worker, no main calls.
    let (inner, client) = unsafe { prepared.activate_concurrent() }.map_err(failure)?;
    let stream = inner.history_window().map_err(failure)?.stream().clone();
    let mut engine = shared::engine::Engine {
        controller: Controller { inner, functions },
        epochs: [None, None, None],
        banks,
        current: None,
        history: Vec::with_capacity(epochs as usize + 1),
        reports: Vec::with_capacity(epochs as usize),
        k: 2 * k,
        committed_arms: 0,
    };
    let ready = Arc::new(OnceLock::new());
    let mut application = Application {
        ledger: check::Ledger::new(stream, geometry.clone(), k, epochs as usize),
        input: input::Input::default(),
        custody: Arc::clone(&custody),
        selected,
        geometry,
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
        worker::run(
            entries[0],
            client,
            worker_custody,
            ready,
            rx,
            events,
            cpus[1],
        )
    }));
    let mut joined = None;
    let mut state = shared::LoopState::default();
    let mut trace = shared::loop_trace::Trace::default();
    // All accepted/pending/returned/output owners remain outside this borrowing scope.
    let mut active_fail_stop = csv::FailStop(true);
    let outcome = (|| -> Result<Result<(), input::InputCompletion>, String> {
        pin(Some(cpus[0]));
        let shared::worker::Event::Ready { tid } = replies.recv_timeout(WAIT).map_err(failure)?
        else {
            return Err("call-pair worker attachment handshake".into());
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
            eprintln!("normal-call-pair-session FAILED: {error}{details}{retirement}");
            std::process::exit(1);
        }
        Ok(Err(completion)) => {
            eprint!("{}", completion_stderr(completion));
            std::process::exit(1);
        }
        Ok(Ok(())) => {}
    }
    active_fail_stop.0 = false;
    fail_stop.0 = false;
    Ok(())
}
