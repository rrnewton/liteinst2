//! Bounded input-driven one-to-four certified scalar leaves; functional observations only.
use super::module::session::{check as population, input, worker as pair_worker};
use super::session as shared;
use super::*;
use rapid_profiler::frontend_native::backoff::{Policy, Schedule};
use rapid_profiler::frontend_native::{
    BridgeError, EpochStorageReclaimError, InstalledNormalLeafSetSite, IntervalEpoch,
    IntervalEpochStorage, LoadedNormalLeafSet, NormalLeafSetBatch, NormalLeafSetHistoryBatch,
    NormalLeafSetSessionController, NormalLeafSetSitePreparation, NormalModuleContract,
    NormalModulePreparationPolicy, PreparedNormalLeafSetSessionController,
};
use shared::io::Io;
use shared::{Application as ApplicationTrait, failure};
use std::sync::OnceLock;
mod check;
mod worker;
const INSTALL: u64 = 0x6d6f_6401;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Csv,
    Length,
    Digits,
    Spaces,
}
impl Operation {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "csv_fields" => Ok(Self::Csv),
            "length" => Ok(Self::Length),
            "ascii_digits" => Ok(Self::Digits),
            "ascii_spaces" => Ok(Self::Spaces),
            _ => Err("unknown leaf operation".into()),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Csv => "csv_fields",
            Self::Length => "length",
            Self::Digits => "ascii_digits",
            Self::Spaces => "ascii_spaces",
        }
    }
    fn value(self, record: &input::Record) -> u64 {
        record.check();
        match self {
            Self::Csv => record.fields,
            Self::Length => record.length as u64,
            Self::Digits => record.bytes().iter().filter(|b| b.is_ascii_digit()).count() as u64,
            Self::Spaces => record.bytes().iter().filter(|&&b| b == b' ').count() as u64,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Preparation {
    Certified,
    Whole,
}
impl Preparation {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "certified" => Ok(Self::Certified),
            "whole" => Ok(Self::Whole),
            _ => Err("explicit leaf policy required".into()),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Certified => "certified",
            Self::Whole => "whole",
        }
    }
    fn sdk(self) -> NormalModulePreparationPolicy {
        match self {
            Self::Certified => NormalModulePreparationPolicy::CertifiedBlocks,
            Self::Whole => NormalModulePreparationPolicy::WholeFunction,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Leaf {
    function: FunctionId,
    operation: Operation,
    va: u64,
    extent: usize,
    policy: Preparation,
}
fn record_cap(n: usize) -> usize {
    assert!((1..=4).contains(&n));
    input::RECORDS.min(4096 / n)
}
fn number(value: &std::ffi::OsStr) -> Result<u64, String> {
    let s = value.to_str().ok_or("non-ASCII numeric argument")?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err("canonical unsigned decimal required".into());
    }
    s.parse().map_err(failure)
}
fn arguments(args: &[std::ffi::OsString]) -> Result<(usize, u32, Vec<Leaf>), String> {
    if args.len() < 5 {
        return Err("normal-leaf-set-session CANDIDATE TRUSTED_FINAL K EPOCHS N (ID OP ELF_VA EXTENT POLICY){N}".into());
    }
    let k = usize::try_from(number(&args[2])?).map_err(failure)?;
    let epochs = u32::try_from(number(&args[3])?).map_err(failure)?;
    let n = usize::try_from(number(&args[4])?).map_err(failure)?;
    if !matches!(k, 10 | 1000)
        || !(1..=520).contains(&epochs)
        || !(1..=4).contains(&n)
        || args.len() != 5 + 5 * n
    {
        return Err("closed leaf-set session profile".into());
    }
    let mut leaves: Vec<Leaf> = Vec::with_capacity(n);
    for row in args[5..].chunks_exact(5) {
        let leaf = Leaf {
            function: FunctionId(number(&row[0])?),
            operation: Operation::parse(row[1].to_str().ok_or("ASCII operation required")?)?,
            va: number(&row[2])?,
            extent: usize::try_from(number(&row[3])?).map_err(failure)?,
            policy: Preparation::parse(row[4].to_str().ok_or("ASCII policy required")?)?,
        };
        let range = match leaf.policy {
            Preparation::Certified => 1..=256,
            Preparation::Whole => 5..=80,
        };
        if leaf.va == 0
            || !range.contains(&leaf.extent)
            || leaf.va.checked_add(leaf.extent as u64).is_none()
            || leaves
                .iter()
                .any(|p| p.function == leaf.function || p.operation == leaf.operation)
            || leaves.last().is_some_and(|p| {
                p.va >= leaf.va || p.va.checked_add(p.extent as u64).unwrap() > leaf.va
            })
        {
            return Err("complete canonical leaf table required".into());
        }
        leaves.push(leaf);
    }
    Ok((k, epochs, leaves))
}
fn completion_stderr(c: input::InputCompletion) -> String {
    match c {
        input::InputCompletion::Refused(why) => {
            format!("normal-leaf-set-session INPUT_REFUSED: {}\n", why.label())
        }
        input::InputCompletion::Incomplete => "normal-leaf-set-session INPUT_INCOMPLETE\n".into(),
    }
}
fn emit(io: &mut Io, line: String) -> Result<(), String> {
    validate_line(&line);
    io.emit(line)
}
fn validate_line(line: &str) {
    assert!(line.is_ascii() && line.len() <= 350 && line.ends_with('\n'));
    assert_eq!(line.bytes().filter(|&b| b == b'\n').count(), 1);
    assert!(!line.contains('\r'));
}

// Private adapter, not a public SDK/worker generic. Exact immutable IDs remain
// available for report validation without deriving identity from output rows.
pub(in crate::normal) struct Controller<const N: usize> {
    inner: NormalLeafSetSessionController,
    functions: [FunctionId; N],
}
impl<const N: usize> shared::engine::Controller for Controller<N> {
    type History = NormalLeafSetHistoryBatch;
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
        population::report_shape_for(generation, rows, capacity, &self.functions);
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

pub(in crate::normal) struct Application<const N: usize> {
    ledger: check::Ledger<N>,
    input: input::Input,
    custody: Arc<pair_worker::Custody>,
    leaves: [Leaf; N],
    entries: [u64; N],
    ends: [u64; N],
    returns: [Vec<u64>; N],
    ready: Arc<OnceLock<pair_worker::Identity>>,
    cpus: [usize; 2],
    k: usize,
    epochs: u32,
}
impl<const N: usize> Application<N> {
    fn ready(&mut self, tid: u64, io: &mut Io) -> Result<(), String> {
        let id = *self.ready.get().expect("owned actual worker handshake");
        assert_eq!(id.tid, tid);
        assert_eq!(id.cpu, self.cpus[1]);
        assert_eq!(id.pid, std::process::id());
        assert_ne!(id.tid, u64::from(id.pid));
        pair_worker::cpu_is(self.cpus[0]);
        self.ledger.ready(id);
        emit(
            io,
            format!(
                "READY,leaf-set-session-v1,{},{},10,2,64,{},{},1,{},{},{},{},{},{},{},{},{}\n",
                self.k,
                self.epochs,
                record_cap(N),
                N,
                INSTALL,
                id.pid,
                id.pid,
                id.tid,
                self.cpus[0],
                self.cpus[1],
                csv::invoke as *const () as usize as u64,
                N,
                identity(self.entries[0]).generation
            ),
        )?;
        for (i, leaf) in self.leaves.iter().enumerate() {
            emit(
                io,
                format!(
                    "LEAF,{},{},{},{},{},{},{},{},{}\n",
                    i,
                    leaf.function.0,
                    leaf.operation.label(),
                    leaf.policy.label(),
                    leaf.va,
                    leaf.extent,
                    self.entries[i],
                    self.ends[i],
                    self.returns[i].len()
                ),
            )?;
            for &pc in &self.returns[i] {
                emit(io, format!("RET,{i},{}\n", pc - self.entries[i]))?;
            }
        }
        Ok(())
    }
}
impl<const N: usize> ApplicationTrait for Application<N> {
    type Controller = Controller<N>;
    type Command = input::Command;
    type Call = worker::Call;
    type Batch = NormalLeafSetBatch;
    type Completion = Result<(), input::InputCompletion>;
    fn accepted_len(&self) -> usize {
        self.ledger.population.accepted.len()
    }
    fn input(&mut self, io: &mut Io) -> Result<Option<input::Command>, String> {
        self.input
            .poll_with_limit(io, self.ledger.population.accepted.len(), record_cap(N))
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
        batch: NormalLeafSetBatch,
        history: &[NormalLeafSetHistoryBatch],
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
        history: &[NormalLeafSetHistoryBatch],
        io: &mut Io,
    ) -> Result<(), String> {
        self.ledger.history_reports(history, reports);
        self.ledger.finish(totals, reports, io)
    }
    fn final_checks(&self) -> Result<(), String> {
        assert_eq!(
            self.ledger.population.rows.len(),
            self.ledger.population.accepted.len() * N
        );
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
        emit(
            io,
            format!(
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
            ),
        )
    }
    fn completion(&self) -> Self::Completion {
        self.input.completion()
    }
}

fn publish(prep: NormalLeafSetSitePreparation) -> InstalledNormalLeafSetSite {
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
            eprintln!("leaf-set publication FAILED: {error:?}");
            std::process::abort();
        }
    };
    // SAFETY: complete union transaction, all source pages RX, retained owners.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}
pub(crate) fn run(args: &[std::ffi::OsString]) {
    if let Err(error) = run_checked(args) {
        eprintln!("normal-leaf-set-session FAILED: {error}");
        std::process::exit(1);
    }
}
fn run_checked(args: &[std::ffi::OsString]) -> Result<(), String> {
    let (k, epochs, leaves) = arguments(args)?;
    match leaves.len() {
        1 => run_selected::<1>(args, k, epochs, leaves.try_into().unwrap()),
        2 => run_selected::<2>(args, k, epochs, leaves.try_into().unwrap()),
        3 => run_selected::<3>(args, k, epochs, leaves.try_into().unwrap()),
        4 => run_selected::<4>(args, k, epochs, leaves.try_into().unwrap()),
        _ => unreachable!(),
    }
}
fn run_selected<const N: usize>(
    args: &[std::ffi::OsString],
    k: usize,
    epochs: u32,
    leaves: [Leaf; N],
) -> Result<(), String> {
    single_main();
    let cpus = shared::cpus();
    assert!(cpus.iter().all(|&cpu| cpu < 1024));
    let policy = Policy::ten_ms(k, epochs, 4096).map_err(failure)?;
    let candidate = Path::new(&args[0]);
    let trusted = Path::new(&args[1]);
    let bytes = expected_file(candidate, trusted);
    let selections: Vec<_> = leaves
        .iter()
        .map(|leaf| {
            TrustedFunctionSelection::new(&bytes, leaf.va, leaf.extent, leaf.operation.label())
                .map_err(failure)
        })
        .collect::<Result<_, _>>()?;
    let refs: Vec<_> = selections.iter().collect();
    // SAFETY: independently selected scalar read-only leaves in one retained DSO,
    // sequential union/no recursion, exact ordinary CALL/RET ABI, no CET/signals,
    // cancellation/nonlocal exit, writer or unload; input never chooses code.
    let owner = unsafe {
        LoadedNormalLeafSet::load_selected(
            candidate,
            &refs,
            NormalModuleContract {
                single_external_entry_per_function: true,
                sequential_call_ret_only: true,
                no_active_cet: true,
            },
        )
    }
    .map_err(failure)?;
    owner.verify_original().map_err(failure)?;
    assert_eq!(owner.functions().len(), N);
    let entries = std::array::from_fn(|i| owner.functions()[i].entry());
    let ends = std::array::from_fn(|i| entries[i].checked_add(leaves[i].extent as u64).unwrap());
    let returns: [Vec<u64>; N] =
        std::array::from_fn(|i| owner.functions()[i].certificate().returns().to_vec());
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
    for i in 0..N {
        assert_eq!(
            owner.functions()[i].certificate().range(),
            (entries[i], ends[i])
        );
    }
    let mut custody = pair_worker::Custody::new(candidate, trusted, bytes.clone());
    let mut fail_stop = csv::FailStop(true);
    let policies: Vec<_> = leaves.iter().map(|leaf| leaf.policy.sdk()).collect();
    let prep =
        NormalLeafSetSitePreparation::new_with_policies(owner, identity(entries[0]), &policies)
            .map_err(failure)?;
    assert_eq!(prep.functions().len(), N);
    for i in 0..N {
        assert_eq!(prep.functions()[i].range(), (entries[i], ends[i]));
        assert_eq!(prep.functions()[i].returns(), returns[i]);
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
    let functions = leaves.map(|leaf| leaf.function);
    let mut prepared = PreparedNormalLeafSetSessionController::new(site, INSTALL, &functions, k)
        .map_err(failure)?;
    let banks = prepared.prepare_epoch_storage().map_err(failure)?;
    assert_eq!(banks.len(), 3);
    // SAFETY: pristine exact prepared E3 set, one future controlled worker, no main calls.
    let (inner, client) = unsafe { prepared.activate_concurrent() }.map_err(failure)?;
    let stream = inner.history_window().map_err(failure)?.stream().clone();
    let mut engine = shared::engine::Engine {
        controller: Controller { inner, functions },
        epochs: [None, None, None],
        banks,
        current: None,
        history: Vec::with_capacity(epochs as usize + 1),
        reports: Vec::with_capacity(epochs as usize),
        k: N * k,
        committed_arms: 0,
    };
    let ready = Arc::new(OnceLock::new());
    let mut application = Application {
        ledger: check::Ledger::new(
            stream,
            leaves,
            entries,
            ends,
            returns.clone(),
            k,
            epochs as usize,
        ),
        input: input::Input::default(),
        custody: Arc::clone(&custody),
        leaves,
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
        worker::run::<N>(
            std::array::from_fn(|i| (entries[i], leaves[i].operation)),
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
            return Err("leaf-set worker attachment handshake".into());
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
            eprintln!("normal-leaf-set-session FAILED: {error}{details}{retirement}");
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

#[cfg(test)]
mod tests {
    use super::*;
    fn refuse(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    fn args(n: usize) -> Vec<std::ffi::OsString> {
        let mut a: Vec<_> = ["candidate", "trusted", "10", "520"]
            .into_iter()
            .map(Into::into)
            .collect();
        a.push(n.to_string().into());
        for (i, op) in ["csv_fields", "length", "ascii_digits", "ascii_spaces"]
            .iter()
            .take(n)
            .enumerate()
        {
            a.extend(
                [
                    i.to_string(),
                    op.to_string(),
                    (4096 + i * 128).to_string(),
                    "64".into(),
                    "certified".into(),
                ]
                .map(Into::into),
            );
        }
        a
    }
    #[test]
    fn canonical_table_cli_keeps_all_functions_and_refuses_invalid_last() {
        for n in 1..=4 {
            let original = args(n);
            let (k, e, leaves) = arguments(&original).unwrap();
            assert_eq!((k, e, leaves.len()), (10, 520, n));
            for (i, l) in leaves.iter().enumerate() {
                assert_eq!(l.function, FunctionId(i as u64));
                assert_eq!(l.va, 4096 + i as u64 * 128);
            }
            for choice in 0..9 {
                let mut changed = original.clone();
                let last = 5 + (n - 1) * 5;
                match choice {
                    0 => changed[2] = "1".into(),
                    1 => changed[3] = "521".into(),
                    2 => changed[4] = "0".into(),
                    3 => changed[last + 2] = u64::MAX.to_string().into(),
                    4 => changed[last + 3] = "257".into(),
                    5 => changed[last + 4] = "fallback".into(),
                    6 => changed[last + 1] = "unknown".into(),
                    7 => {
                        changed[last + 3] = "81".into();
                        changed[last + 4] = "whole".into();
                    }
                    _ => {
                        changed.pop();
                    }
                }
                assert!(arguments(&changed).is_err());
            }
            if n > 1 {
                for col in [0, 1, 2] {
                    let mut changed = original.clone();
                    changed[5 + (n - 1) * 5 + col] = changed[5 + col].clone();
                    assert!(arguments(&changed).is_err());
                }
            }
        }
        for value in ["", "00", "+1", "-1", "1 ", " 1", "18446744073709551616"] {
            assert!(number(std::ffi::OsStr::new(value)).is_err());
        }
        assert_eq!(
            number(std::ffi::OsStr::new("18446744073709551615")).unwrap(),
            u64::MAX
        );
    }
    #[test]
    fn operations_match_accepted_encoded_bytes_without_calling_targets() {
        for (bytes, values) in [
            (b"".as_slice(), [1, 0, 0, 0]),
            (b"\"1 2\", 3", [2, 8, 3, 2]),
            (b"\"\",42,  ", [3, 8, 2, 2]),
        ] {
            let record = input::Record::new(1, bytes).unwrap();
            assert_eq!(
                [
                    Operation::Csv,
                    Operation::Length,
                    Operation::Digits,
                    Operation::Spaces
                ]
                .map(|op| op.value(&record)),
                values
            );
        }
        for (bytes, values) in [
            ([b' '; 64], [1, 64, 0, 64]),
            ([b','; 64], [65, 64, 0, 0]),
            ([b'9'; 64], [1, 64, 64, 0]),
        ] {
            let record = input::Record::new(1, &bytes).unwrap();
            assert_eq!(
                [
                    Operation::Csv,
                    Operation::Length,
                    Operation::Digits,
                    Operation::Spaces
                ]
                .map(|op| op.value(&record)),
                values
            );
        }
        for (bytes, fields) in csv::CASES {
            assert_eq!(
                Operation::Csv.value(&input::Record::new(1, bytes).unwrap()),
                fields
            );
        }
    }
    #[test]
    fn typed_completion_and_wire_bounds_keep_all_outcomes() {
        assert_eq!(
            completion_stderr(input::InputCompletion::Incomplete),
            "normal-leaf-set-session INPUT_INCOMPLETE\n"
        );
        for (why, label) in [
            (input::Refusal::Syntax, "syntax"),
            (input::Refusal::Overlong, "overlong"),
            (input::Refusal::Unterminated, "unterminated"),
            (input::Refusal::RecordLimit, "record_limit"),
        ] {
            assert_eq!(
                completion_stderr(input::InputCompletion::Refused(why)),
                format!("normal-leaf-set-session INPUT_REFUSED: {label}\n")
            );
        }
        for (n, records, rows) in [
            (1, 2048, 7194),
            (2, 2048, 11296),
            (3, 1365, 10617),
            (4, 1024, 10284),
        ] {
            assert_eq!(record_cap(n), records);
            assert_eq!(2 * n * records + records + 2 * 520 + 6 * n + 4, rows);
            assert!(rows * 350 < 4 * 1024 * 1024);
        }
        validate_line(&("x".repeat(349) + "\n"));
        for line in [
            "x".repeat(350) + "\n",
            "x\r\n".into(),
            "x\ny\n".into(),
            "x".into(),
            "é\n".into(),
        ] {
            refuse(|| validate_line(&line));
        }
    }
    #[test]
    fn accepted_pending_leaf_record_survives_full_queue_and_disconnect() {
        let (tx, rx) = mpsc::sync_channel(1);
        let a = Arc::new(input::Record::new(1, b"1, 2").unwrap());
        let b = Arc::new(input::Record::new(2, b"").unwrap());
        tx.send(input::Command::Record(Arc::clone(&a))).unwrap();
        let mut pending = Some(input::Command::Record(Arc::clone(&b)));
        let mut stop = false;
        assert!(!shared::dispatch(&tx, &mut pending, true, &mut stop).unwrap());
        assert!(!stop);
        assert!(matches!(pending.as_ref(),Some(input::Command::Record(r))if Arc::ptr_eq(r,&b)));
        let input::Command::Record(first) = rx.try_recv().unwrap() else {
            panic!()
        };
        assert!(Arc::ptr_eq(&first, &a));
        assert!(shared::dispatch(&tx, &mut pending, true, &mut stop).unwrap());
        assert!(pending.is_none() && !stop);
        let input::Command::Record(second) = rx.try_recv().unwrap() else {
            panic!()
        };
        assert!(Arc::ptr_eq(&second, &b));
        pending = Some(input::Command::Record(Arc::clone(&b)));
        drop(rx);
        assert!(shared::dispatch(&tx, &mut pending, true, &mut stop).is_err());
        assert!(!stop);
        assert!(matches!(pending.as_ref(),Some(input::Command::Record(r))if Arc::ptr_eq(r,&b)));
        a.check();
        b.check();
    }
}
