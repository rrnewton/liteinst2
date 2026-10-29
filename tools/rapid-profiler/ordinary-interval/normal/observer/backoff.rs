//! Fixed ordinary calls under independently scheduled metadata admission.
//! No elapsed estimator, cheap-off path, or full 520-arm qualification.
use super::*;
use rapid_profiler::frontend_native::backoff::{Policy, Schedule, ScheduleDecision, StopReason};
use rapid_profiler::frontend_native::{
    EpochStorageReclaimError, HistoryBatch, HistoryBinding, HistoryStream, IntervalController,
    IntervalEpoch, IntervalEpochStorage,
};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};
mod check;
pub(crate) mod elapsed;
pub(crate) mod pending_owner;
#[cfg(test)]
mod tests;

const INSTALL: u64 = 0x6e62_6b31;
const EPOCHS: u32 = 520;
const ROW_CAP: usize = 272;
const OUTPUT_CAP: usize = CALLS * ROW_CAP + (521 + 520) * 64 + 4096;
const _: () = assert!(OUTPUT_CAP == 906_304 && OUTPUT_CAP < 1024 * 1024);
const SCOPE: &str = "# normal observer backoff; complete fixed work and raw callback ticks; no timing, accuracy, cheap-off or 520-arm qualification";
const HEADER: &str = "id,repetition,case,seed_index,length,input_fnv1a64,value,instructions,conditional,taken,input_bytes,ret_bytes,batch,owner,generation,invocation,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,ack,ack_ordinal,completed_sequence";

fn number(s: &str) -> Option<usize> {
    let n = s.parse::<usize>().ok()?;
    (n.to_string() == s).then_some(n)
}
fn roles(k: &str, main: &str, control: &str) -> Option<(usize, usize, usize)> {
    let (k, main, control) = (number(k)?, number(main)?, number(control)?);
    (matches!(k, 10 | 1000) && main < 1024 && control < 1024 && main != control)
        .then_some((k, main, control))
}
fn affinity() -> BTreeSet<usize> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) },
        0
    );
    (0..libc::CPU_SETSIZE as usize)
        .filter(|&n| unsafe { libc::CPU_ISSET(n, &set) })
        .collect()
}
fn singleton(cpu: usize) {
    assert_eq!(affinity(), BTreeSet::from([cpu]));
    assert_eq!(unsafe { libc::sched_getcpu() }, i32::try_from(cpu).unwrap());
}
fn task_ids(
    names: impl IntoIterator<Item = std::ffi::OsString>,
    pid: u32,
    controller: u64,
) -> Option<BTreeSet<u64>> {
    if pid == 0
        || pid > i32::MAX as u32
        || controller == 0
        || controller > i32::MAX as u64
        || controller == u64::from(pid)
    {
        return None;
    }
    let mut ids = BTreeSet::new();
    for name in names {
        let s = name.to_str()?;
        let n = s.parse::<u64>().ok()?;
        if n.to_string() != s || n == 0 || n > i32::MAX as u64 || !ids.insert(n) {
            return None;
        }
    }
    (ids == BTreeSet::from([u64::from(pid), controller])).then_some(ids)
}
fn live_tasks(controller: u64) {
    let pid = std::process::id();
    assert_eq!(unsafe { libc::syscall(libc::SYS_gettid) }, i64::from(pid));
    let names = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|r| r.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert!(task_ids(names, pid, controller).is_some());
}
fn custody(c: &Custody<'_>, calling: &mut CallerOwner, controller: Option<u64>) {
    // Same complete old custody checks, with a separately authenticated exact
    // two-task profile only while the metadata controller is live.
    calling.verify().unwrap();
    for (candidate, trusted, expected) in [
        (c.candidate, c.trusted, c.subject),
        (c.caller_candidate, c.caller_trusted, c.helper),
    ] {
        assert_eq!(expected_file(candidate, trusted), expected);
        let mut actual = Vec::new();
        File::open(candidate)
            .unwrap()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, expected);
    }
    unsafe { immutable(&c.spans) };
    assert_eq!(stack_bounds(), c.stack);
    singleton(c.cpu);
    if let Some(tid) = controller {
        live_tasks(tid)
    } else {
        single_main()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReportSpan {
    generation: u64,
    start: usize,
    end: usize,
}
struct Slot {
    epoch: Option<IntervalEpoch>,
    copied: Option<usize>,
}
struct Engine {
    controller: IntervalController,
    banks: Vec<IntervalEpochStorage>,
    slots: [Option<Slot>; 3],
    current: Option<usize>,
    history: Vec<HistoryBatch>,
    reports: Vec<ReportSpan>,
    payloads: Vec<RecordObservation>,
    stream: HistoryStream,
    k: usize,
    committed: u32,
}
impl Engine {
    fn history(&mut self) {
        let h = self
            .controller
            .drain_history()
            .unwrap()
            .expect("one committed binding action");
        assert!(self.history.len() < EPOCHS as usize + 1);
        assert_eq!(h.stream(), &self.stream);
        assert_eq!(h.actions().len(), 1);
        assert_eq!(h.number(), self.history.len() as u64 + 1);
        assert_eq!(
            h.range(),
            self.history.len() as u64..self.history.len() as u64 + 1
        );
        if let Some(last) = self.history.last() {
            assert!(h.follows(last));
        } else {
            assert_eq!(h.before(), HistoryBinding::Initial);
        }
        self.history.push(h);
    }
    fn retire(&mut self) {
        for i in 0..3 {
            if self.current == Some(i) {
                continue;
            }
            let Some(slot) = self.slots[i].as_mut() else {
                continue;
            };
            if slot.copied.is_none() {
                let Some(report) = self
                    .controller
                    .report(slot.epoch.as_ref().unwrap())
                    .unwrap()
                else {
                    continue;
                };
                let generation = report.generation().get();
                let n = report.records().count();
                assert!(n <= self.k && self.reports.len() < EPOCHS as usize);
                assert!(
                    self.payloads
                        .len()
                        .checked_add(n)
                        .is_some_and(|n| n <= CALLS)
                );
                let start = self.payloads.len();
                self.payloads.extend(report.records());
                let index = self.reports.len();
                self.reports.push(ReportSpan {
                    generation,
                    start,
                    end: self.payloads.len(),
                });
                slot.copied = Some(index);
                drop(report);
            }
            let report = self.reports[slot.copied.unwrap()];
            assert_eq!(
                slot.epoch.as_ref().unwrap().generation().get(),
                report.generation
            );
            match self.controller.reclaim_storage(slot.epoch.take().unwrap()) {
                Ok(bank) => {
                    self.banks.push(bank);
                    self.slots[i] = None;
                }
                Err((error, epoch)) => {
                    slot.epoch = Some(epoch); // Restore before diagnosing any refusal.
                    assert_eq!(error, EpochStorageReclaimError::SharedOwner);
                }
            }
        }
    }
    fn arm(&mut self) {
        self.retire();
        let i = self
            .slots
            .iter()
            .position(Option::is_none)
            .expect("bounded E3 capacity");
        let bank = self.banks.pop().expect("original prepared bank");
        let epoch = match self.controller.stage_prepared(bank) {
            Ok(epoch) => epoch,
            Err((error, bank)) => {
                self.banks.push(bank);
                panic!("stage: {error:?}")
            }
        };
        self.slots[i] = Some(Slot {
            epoch: Some(epoch),
            copied: None,
        });
        self.controller
            .arm(self.slots[i].as_ref().unwrap().epoch.as_ref().unwrap())
            .unwrap();
        self.committed += 1;
        self.current = Some(i);
        self.history();
    }
    fn stop(&mut self) {
        let i = self.current.expect("initial actual arm");
        self.controller
            .disarm(self.slots[i].as_ref().unwrap().epoch.as_ref().unwrap())
            .unwrap();
        self.current = None;
        self.history();
    }
}
#[derive(Default)]
struct Signals {
    stop: AtomicBool,
    deadline: OnceLock<Instant>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ready {
    tid: u64,
    start: Instant,
    absolute_end: Instant,
}
struct Handoff {
    engine: Engine,
    schedule: Schedule,
    ready: Ready,
    deadline: Instant,
}
fn before(now: Instant, deadline: Instant) -> bool {
    now < deadline
}
fn shutdown(start: Instant, stopped: Instant, policy: Policy) -> Option<Instant> {
    Some(
        stopped.checked_add(policy.shutdown())?.min(
            start
                .checked_add(policy.period() * policy.epoch_limit())?
                .checked_add(policy.shutdown())?,
        ),
    )
}
fn checked_wait(schedule: &mut Schedule) {
    schedule
        .wait_bound(Instant::now())
        .expect("original schedule bound");
}
fn handoff_ready(
    r: Ready,
    actual: Ready,
    deadline: Instant,
    schedule: &Schedule,
    committed: u32,
) -> bool {
    r == actual
        && deadline <= r.absolute_end
        && schedule.stop_reason() == Some(StopReason::Requested)
        && schedule.pending_arm().is_none()
        && committed == schedule.armed()
}
fn control(
    mut engine: Engine,
    k: usize,
    cpu: usize,
    signals: Arc<Signals>,
    ready: mpsc::SyncSender<Ready>,
    handoff: mpsc::SyncSender<Handoff>,
) {
    // Abort on panic before any owned engine/token can unwind out of this scope.
    let mut guard = FailStop(true);
    pin(Some(cpu));
    singleton(cpu);
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
    assert!(tid > 0 && tid <= i32::MAX as u64 && tid != u64::from(std::process::id()));
    let policy = Policy::ten_ms(k, EPOCHS, CALLS as u64).unwrap();
    let start = Instant::now();
    let mut schedule = Schedule::new(start, policy).unwrap();
    let identity = Ready {
        tid,
        start,
        absolute_end: start
            .checked_add(policy.period() * EPOCHS)
            .unwrap()
            .checked_add(policy.shutdown())
            .unwrap(),
    };
    let mut announced = false;
    loop {
        let observed = Instant::now();
        let decision = schedule
            .poll(observed, signals.stop.load(Ordering::Acquire))
            .expect("fixed clock poll");
        match decision {
            ScheduleDecision::Arm { .. } => {
                engine.arm();
                schedule
                    .arm_completed(Instant::now())
                    .expect("post arm/history deadline");
                if !announced {
                    ready.try_send(identity).unwrap();
                    announced = true;
                }
            }
            ScheduleDecision::Stop => {
                assert!(announced && signals.stop.load(Ordering::Acquire));
                assert_eq!(schedule.stop_reason(), Some(StopReason::Requested));
                let deadline = shutdown(start, observed, policy).unwrap();
                signals.deadline.set(deadline).unwrap();
                engine.stop();
                engine.retire();
                checked_wait(&mut schedule);
                assert!(engine.slots.iter().all(Option::is_none));
                assert_eq!(engine.banks.len(), 3);
                assert_eq!(engine.reports.len(), schedule.armed() as usize);
                assert_eq!(engine.committed, schedule.armed());
                singleton(cpu);
                // Schedule and all owners leave through the channel BEFORE native
                // thread return. Joined result contains only (), never the clock.
                if let Err(retained) = handoff.try_send(Handoff {
                    engine,
                    schedule,
                    ready: identity,
                    deadline,
                }) {
                    let _retained = retained; // No unwind/drop of the transferred owner.
                    std::process::abort();
                }
                guard.0 = false;
                return;
            }
            ScheduleDecision::Wait => (),
        }
        engine.retire();
        singleton(cpu);
        let observed = Instant::now();
        let bound = schedule.wait_bound(observed).expect("fixed wait bound");
        let due = start
            .checked_add(policy.period() * schedule.armed())
            .unwrap();
        let wait = bound.min(
            due.saturating_duration_since(observed)
                .saturating_sub(policy.lateness()),
        );
        let until = observed.checked_add(wait).unwrap();
        while Instant::now() < until {
            std::hint::spin_loop();
        }
        if wait.is_zero() {
            std::hint::spin_loop();
        }
    }
}
fn row(g: usize, r: Returned, record: &NormalRecord, sequence: Option<u64>, k: usize) -> String {
    // Reuse the unchanged fixed-work/native prefix, replacing its fourteen absent
    // SDK columns with this separately validated mixed-owner observation.
    let native = super::row(g, r, None);
    let prefix = native.split(',').take(12).collect::<Vec<_>>().join(",");
    let (generation, inv) = check::owner(record.raw.owner, k).unwrap();
    assert_eq!(sequence.is_some(), inv.is_some());
    let (ack, ordinal) = match record.acknowledgement {
        NormalAcknowledgement::CallerCheckpoint => ("C", String::new()),
        NormalAcknowledgement::NextEntry { ordinal } => ("N", ordinal.to_string()),
    };
    let line = format!(
        "{prefix},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        g / BLOCK + 1,
        if inv.is_some() { "sampled" } else { "closed" },
        generation,
        inv.map_or_else(String::new, |n| n.to_string()),
        record.history_prefix,
        record.entry_rsp,
        record.return_word,
        record.raw.start.ticks,
        record.raw.end.ticks,
        record.raw.start.aux,
        record.raw.end.aux,
        record.raw.elapsed_ticks().unwrap(),
        ack,
        ordinal,
        sequence.map_or_else(String::new, |n| n.to_string())
    );
    assert_eq!(line.split(',').count(), 27);
    assert!(line.len() < ROW_CAP);
    line
}
struct Export<'a> {
    f: check::Facts,
    controller: u64,
    app_cpu: usize,
    controller_cpu: usize,
    rows: &'a [NormalRecord],
    returned: &'a [Returned],
    actions: &'a [check::HistoryRow],
    reports: &'a [ReportSpan],
    counts: check::Counts,
    arms: u32,
}
fn output(export: Export<'_>) -> String {
    output_with(export, elapsed::Wire::Functional)
}
fn output_with(export: Export<'_>, wire: elapsed::Wire) -> String {
    let (scope, command, timing) = wire.labels();
    let Export {
        f,
        controller,
        app_cpu,
        controller_cpu,
        rows,
        returned,
        actions,
        reports,
        counts,
        arms,
    } = export;
    assert!(population(returned));
    let mut text = String::with_capacity(OUTPUT_CAP);
    writeln!(text, "{scope}\n{HEADER}").unwrap();
    let mut sequence = 0;
    for (g, (r, record)) in returned.iter().zip(rows).enumerate() {
        let sampled = matches!(record.raw.owner, RawIntervalOwner::Sampled { .. });
        writeln!(
            text,
            "{}",
            row(g, *r, record, sampled.then_some(sequence), f.k)
        )
        .unwrap();
        sequence += u64::from(sampled);
    }
    assert_eq!(sequence, counts.sampled);
    for a in actions {
        let line = format!(
            "HISTORY,{},{},{}\n",
            a.prefix,
            if a.removed { "removed" } else { "published" },
            a.generation
        );
        assert!(line.len() <= 64);
        text.push_str(&line);
    }
    for (i, a) in actions[..arms as usize].iter().enumerate() {
        let report = reports
            .iter()
            .find(|r| r.generation == a.generation)
            .unwrap();
        let line = format!(
            "REPORT,{},{},{}\n",
            i + 1,
            a.generation,
            report.end - report.start
        );
        assert!(line.len() <= 64);
        text.push_str(&line);
    }
    writeln!(text,"{command} FUNCTIONAL_PASS k={} policy=10ms-2ms epoch_limit=520 stop_reason=Requested arms={arms} committed_arms={arms} completed_arms={arms} pending_arm=none repetitions=128 calls=3072 helper_calls=1536 instructions=614400 conditional=99840 taken=96768 input_bytes=99840 ret_bytes=24576 pid={} tid={} controller_tid={controller} app_cpu={app_cpu} controller_cpu={controller_cpu} entry={} caller={} install={INSTALL} function=1 batches=128 events=6144 rows=3072 sampled={} unsampled={} reports={arms} records={} actions={} journal_words=65536 next_entry_acknowledgements=2944 checkpoint_acknowledgements=128 banks=3 observed_generations={} rearmed={} sampled_after_closed={} input_unchanged=true detached=true joined=1 deadline_scope=issued-arms-and-requested-shutdown all_elapsed_due_arms=unqualified cheap_off=false timing={timing}",
        f.k,f.pid,f.pid,f.entry,f.caller,counts.sampled,counts.closed,counts.sampled,arms+1,counts.generations,arms>1,counts.after_closed).unwrap();
    assert!(text.is_ascii() && text.len() <= OUTPUT_CAP);
    text
}

struct Setup<'a> {
    k: usize,
    app_cpu: usize,
    controller_cpu: usize,
    candidate: &'a Path,
    trusted: &'a Path,
    caller_candidate: &'a Path,
    caller_trusted: &'a Path,
    subject: Vec<u8>,
    helper: Vec<u8>,
    calling: CallerOwner,
    entry: u64,
    caller: u64,
    readable: ReadableStack,
    stack: (u64, u64),
    spans: Vec<(u64, Vec<u8>)>,
    stream: HistoryStream,
    engine: Engine,
    client: rapid_profiler::frontend_native::NormalClient,
}
fn prepare(args: &[std::ffi::OsString]) -> Setup<'_> {
    prepare_measured(args, &mut elapsed::NoTiming)
}
fn prepare_measured<'a, M: elapsed::Measurement>(
    args: &'a [std::ffi::OsString],
    measurement: &mut M,
) -> Setup<'a> {
    let (k, app_cpu, controller_cpu) = roles(
        args[0].to_str().unwrap(),
        args[1].to_str().unwrap(),
        args[2].to_str().unwrap(),
    )
    .unwrap();
    single_main();
    assert_eq!(affinity(), BTreeSet::from([app_cpu, controller_cpu]));
    let candidate = Path::new(&args[3]);
    let trusted = Path::new(&args[4]);
    let elf_va = strnlen::number(args[5].to_str().unwrap());
    assert_eq!(strnlen::number(args[6].to_str().unwrap()), 37);
    let caller_candidate = Path::new(&args[7]);
    let caller_trusted = Path::new(&args[8]);
    measurement.mark(elapsed::Point::SetupStart, super::throughput::now);
    let subject = expected_file(candidate, trusted);
    let helper = expected_file(caller_candidate, caller_trusted);
    // SAFETY: same independently trusted complete Exact37 and 67-byte fixture;
    // sole ordinary main caller, immutable inputs/code and no reentry, CET,
    // signals, fork, nonlocal exit, alias writer or unload through process exit.
    let calling = unsafe { CallerOwner::load(caller_candidate, &helper) }.unwrap();
    let selection = TrustedFunctionSelection::new(&subject, elf_va, 37, LABEL).unwrap();
    let owner =
        unsafe { LoadedNormalLeaf::load_selected(candidate, &selection, NORMAL_CONTRACT) }.unwrap();
    truth::check_bytes(owner.code()).unwrap();
    let entry = owner.entry();
    assert_eq!(
        owner.certificate().heads(),
        truth::HEADS.map(|o| entry + u64::from(o))
    );
    assert_eq!(
        owner.certificate().returns(),
        [entry.checked_add(36).unwrap()]
    );
    assert_eq!(
        owner.certificate().range(),
        (entry, entry.checked_add(37).unwrap())
    );
    owner.verify_original().unwrap();
    let caller = calling.entry();
    let readable = stack();
    let stack = stack_bounds();
    let prep = NormalSitePreparation::new_whole_function(owner, identity(entry)).unwrap();
    assert_eq!(prep.role_pcs().collect::<Vec<_>>(), [entry, entry + 36]);
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
    spans.push((calling.source().0, calling.source().1.to_vec()));
    let site = publish(prep);
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
    .unwrap();
    let banks = prepared
        .prepare_epoch_storage(Config {
            retained_per_function: k,
            max_inflight: 1,
            max_invocations: k,
        })
        .unwrap();
    assert_eq!(banks.len(), 3);
    // SAFETY: quiescent publication; only metadata controller runs concurrently,
    // and no callback-dependent locks, reentry or signal paths are introduced.
    let (controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let stream = controller.history_window().unwrap().stream().clone();
    assert_eq!(
        (stream.pid(), stream.install(), stream.function()),
        (std::process::id(), INSTALL, FUNCTION)
    );
    let engine = Engine {
        controller,
        banks,
        slots: [None, None, None],
        current: None,
        history: Vec::with_capacity(EPOCHS as usize + 1),
        reports: Vec::with_capacity(EPOCHS as usize),
        payloads: Vec::with_capacity(CALLS),
        stream: stream.clone(),
        k,
        committed: 0,
    };
    Setup {
        k,
        app_cpu,
        controller_cpu,
        candidate,
        trusted,
        caller_candidate,
        caller_trusted,
        subject,
        helper,
        calling,
        entry,
        caller,
        readable,
        stack,
        spans,
        stream,
        engine,
        client,
    }
}

fn call_range(
    data: &mut Data,
    sums: &mut [u64],
    returned: &mut Vec<Returned>,
    calling: &mut CallerOwner,
    c: &Custody<'_>,
    entry: u64,
    range: std::ops::Range<usize>,
) {
    call_range_measured(
        data,
        sums,
        returned,
        calling,
        c,
        entry,
        (range, &mut elapsed::NoTiming),
    );
}
fn call_range_measured<M: elapsed::Measurement>(
    data: &mut Data,
    sums: &mut [u64],
    returned: &mut Vec<Returned>,
    calling: &mut CallerOwner,
    c: &Custody<'_>,
    entry: u64,
    measured_range: (std::ops::Range<usize>, &mut M),
) {
    let (range, measurement) = measured_range;
    let first = range.start;
    let last = range.end;
    for p in first..last {
        data.check(p, false);
    }
    unsafe { immutable(&c.spans) };
    measurement.mark(
        elapsed::Point::BodyStart { first, last },
        super::throughput::now,
    );
    for (p, sum) in sums.iter_mut().enumerate().take(last).skip(first) {
        // SAFETY: retained complete immutable sources and disjoint requests,
        // results and input; sole attached main, actual ordinary CALL/RET.
        *sum = unsafe { calling.invoke(entry, &data.requests[p], &mut data.results[p].values) };
    }
    measurement.mark(
        elapsed::Point::BodyEnd { first, last },
        super::throughput::now,
    );
    for (p, &sum) in sums.iter().enumerate().take(last).skip(first) {
        data.check(p, true);
        let expected = case(2 * p).value;
        assert_eq!(sum, expected.wrapping_add(expected));
        for (j, &value) in data.results[p].values.iter().enumerate() {
            returned.push(Returned {
                id: (2 * p + j + 1) as u64,
                value,
            });
        }
    }
}

struct Final {
    f: check::Facts,
    totals: NormalTotals,
    high: u64,
    arms: u32,
}
fn finish(
    engine: &Engine,
    stream: &HistoryStream,
    batches: &[NormalBatch],
    expected: Final,
) -> (Vec<NormalRecord>, Vec<check::HistoryRow>, check::Counts) {
    let Final {
        f,
        totals,
        high,
        arms,
    } = expected;
    let window = engine.controller.history_window().unwrap();
    assert_eq!(window.stream(), stream);
    assert_eq!(window.last_batch_number(), u64::from(arms) + 1);
    assert_eq!(window.before(), engine.history.last().unwrap().after());
    assert_eq!(window.after(), window.before());
    assert_eq!(window.status(), ControllerStatus::Ready);
    assert!(window.current().is_none());
    assert_eq!(window.enabled(), [true]);
    assert!(window.retained_failed_generation().is_none());
    assert!(window.actions().is_empty());
    assert_eq!(window.range(), u64::from(arms) + 1..u64::from(arms) + 1);
    let actions = check::history_rows(&engine.history, stream, arms).unwrap();
    let mut rows = Vec::with_capacity(CALLS);
    let mut again = NormalTotals::default();
    let mut final_high = 0;
    for (b, batch) in batches.iter().enumerate() {
        final_high = check::high_water(final_high, batch.history_high_water(), arms).unwrap();
        again = check::batch(
            f,
            b,
            check::Meta::actual(batch, stream),
            batch.records(),
            batch.journal(),
            again,
        )
        .unwrap();
        rows.extend_from_slice(batch.records());
    }
    assert_eq!(final_high, high);
    assert_eq!(again, totals);
    let counts =
        check::finish(f, &rows, &actions, &engine.reports, &engine.payloads, arms).unwrap();
    assert_eq!(
        (counts.sampled, counts.closed),
        (totals.completed, totals.unsampled)
    );
    (rows, actions, counts)
}

pub(crate) fn run(args: &[std::ffi::OsString]) {
    assert_eq!(
        args.len(),
        9,
        "normal-observer-backoff K APP_CPU CONTROLLER_CPU CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL"
    );
    run_measured(args, elapsed::NoTiming);
}
fn run_measured<M: elapsed::Measurement>(args: &[std::ffi::OsString], mut measurement: M) {
    let Setup {
        k,
        app_cpu,
        controller_cpu,
        candidate,
        trusted,
        caller_candidate,
        caller_trusted,
        subject,
        helper,
        mut calling,
        entry,
        caller,
        readable,
        stack,
        spans,
        stream,
        engine,
        client,
    } = prepare_measured(args, &mut measurement);
    let mut data = Data::new();
    let mut sums = vec![0_u64; PAIRS];
    let mut returned = Vec::with_capacity(CALLS);
    let mut batches = Vec::with_capacity(BLOCKS);
    let mut attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
    assert_eq!(attached.totals().unwrap(), NormalTotals::default());
    let signals = Arc::new(Signals::default());
    let control_signals = Arc::clone(&signals);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (handoff_tx, handoff_rx) = mpsc::sync_channel(1);
    let handle = joined_task::spawn(move || {
        control(
            engine,
            k,
            controller_cpu,
            control_signals,
            ready_tx,
            handoff_tx,
        )
    });
    // Guard follows every active owner/handle; failure aborts before teardown.
    let mut fail_stop = FailStop(true);
    pin(Some(app_cpu));
    let ready = ready_rx
        .recv_timeout(WAIT)
        .expect("initial actual arm/history handshake");
    assert!(before(Instant::now(), ready.absolute_end));
    let c = Custody {
        candidate,
        trusted,
        subject: &subject,
        caller_candidate,
        caller_trusted,
        helper: &helper,
        cpu: app_cpu,
        stack,
        spans,
    };
    custody(&c, &mut calling, Some(ready.tid));
    let f = check::Facts {
        pid: std::process::id(),
        entry,
        caller,
        stack,
        k,
    };
    let mut totals = NormalTotals::default();
    let mut high = 0;
    measurement.mark(elapsed::Point::SetupEnd, super::throughput::now);
    for b in 0..BLOCKS {
        let first = b * BLOCK / 2;
        let last = first + BLOCK / 2;
        call_range_measured(
            &mut data,
            &mut sums,
            &mut returned,
            &mut calling,
            &c,
            entry,
            (first..last, &mut measurement),
        );
        custody(&c, &mut calling, Some(ready.tid));
        assert_eq!(*data.inputs, [input(0), input(1)]);
        assert!(before(Instant::now(), ready.absolute_end));
        // SAFETY: all 24 actual helper target calls returned on this thread;
        // complete input/source/generated/helper/stack/CPU postflight precedes
        // acknowledgement. No physical C3 or executable reclamation is inferred.
        let batch = unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .expect("24 returned calls");
        high = check::high_water(high, batch.history_high_water(), EPOCHS).unwrap();
        totals = check::batch(
            f,
            b,
            check::Meta::actual(&batch, &stream),
            batch.records(),
            batch.journal(),
            totals,
        )
        .unwrap();
        assert_eq!(attached.totals().unwrap(), totals);
        batches.push(batch);
    }
    assert!(population(&returned));
    assert_eq!(sums.len(), PAIRS);
    for (p, &sum) in sums.iter().enumerate() {
        data.check(p, true);
        let value = case(2 * p).value;
        assert_eq!(sum, value.wrapping_add(value));
    }
    custody(&c, &mut calling, Some(ready.tid));
    assert!(
        unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .is_none()
    );
    assert_eq!(attached.detach().unwrap(), totals);
    assert_eq!(
        (totals.entered, totals.ret_observed, totals.confirmed),
        (3072, 3072, 3072)
    );
    assert_eq!(totals.completed + totals.unsampled, 3072);
    signals.stop.store(true, Ordering::Release);
    let mut h = loop {
        assert!(before(
            Instant::now(),
            signals
                .deadline
                .get()
                .copied()
                .unwrap_or(ready.absolute_end)
        ));
        match handoff_rx.try_recv() {
            Ok(h) => break h,
            Err(mpsc::TryRecvError::Empty) => thread::yield_now(),
            Err(mpsc::TryRecvError::Disconnected) => panic!("owned handoff disconnected"),
        }
    };
    let mut handoff_guard = FailStop(true); // Declared after the newly received owners.
    assert!(handoff_ready(
        ready,
        h.ready,
        h.deadline,
        &h.schedule,
        h.engine.committed
    ));
    assert_eq!(signals.deadline.get(), Some(&h.deadline));
    checked_wait(&mut h.schedule);
    while !handle.is_finished() {
        checked_wait(&mut h.schedule);
        thread::yield_now();
    }
    checked_wait(&mut h.schedule);
    let mut joined = handle.join();
    checked_wait(&mut h.schedule);
    assert_eq!(u64::from(joined.tid()), ready.tid);
    while !joined_task::poll_exclusive(&mut [&mut joined], || {
        h.schedule
            .wait_bound(Instant::now())
            .map(|_| ())
            .map_err(|e| joined_task::Error::Clock(format!("{e:?}")))
    })
    .unwrap()
    {
        thread::yield_now();
    }
    joined.result().as_ref().expect("actual controller join");
    checked_wait(&mut h.schedule);
    custody(&c, &mut calling, None);
    let arms = h.schedule.armed();
    let (rows, actions, counts) = finish(
        &h.engine,
        &stream,
        &batches,
        Final {
            f,
            totals,
            high,
            arms,
        },
    );
    custody(&c, &mut calling, None);
    checked_wait(&mut h.schedule);
    measurement.mark(elapsed::Point::ServiceEnd, super::throughput::now);
    let text = measurement.output(Export {
        f,
        controller: ready.tid,
        app_cpu,
        controller_cpu,
        rows: &rows,
        returned: &returned,
        actions: &actions,
        reports: &h.engine.reports,
        counts,
        arms,
    });
    checked_wait(&mut h.schedule);
    std::io::stdout().lock().write_all(text.as_bytes()).unwrap();
    assert_eq!(
        h.schedule.check_completion(Instant::now()).unwrap(),
        StopReason::Requested
    );
    handoff_guard.0 = false;
    fail_stop.0 = false;
}
