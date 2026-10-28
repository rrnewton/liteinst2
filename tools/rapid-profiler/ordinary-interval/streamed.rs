//! Finite streamed profiling through the public drain and retirement APIs.
use super::exact::truth;
use super::*;
use rapid_profiler::frontend::{ActionKind, ControllerStatus};
use rapid_profiler::frontend_native::{
    IntervalBatch, IntervalClient, IntervalController, IntervalEpoch, IntervalThread,
};
use std::sync::OnceLock;
#[path = "streamed/check.rs"]
mod check;
use check::{BATCHES, Batch, CALLS, Call, EPOCHS, Error, Expected, INSTALL, Retired, Transition};

fn two_cpus() -> [usize; 2] {
    const WORDS: usize = std::mem::size_of::<libc::cpu_set_t>() / std::mem::size_of::<usize>();
    let mut words = [0_usize; WORDS];
    // SAFETY: the exact libc-sized output buffer is valid for this read.
    assert_eq!(
        unsafe {
            libc::sched_getaffinity(0, std::mem::size_of_val(&words), words.as_mut_ptr().cast())
        },
        0
    );
    let selected: Vec<_> = (0..WORDS * usize::BITS as usize)
        .filter(|&n| words[n / usize::BITS as usize] & (1 << (n % usize::BITS as usize)) != 0)
        .take(2)
        .collect();
    assert_eq!(selected.len(), 2, "two allowed CPUs required");
    [selected[0], selected[1]]
}
fn ns(origin: Instant, now: Instant) -> u64 {
    now.duration_since(origin).as_nanos().try_into().unwrap()
}
fn until(target: Instant, deadline: Instant) -> Result<(), Error> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::Schedule);
        }
        if now >= target {
            return Ok(());
        }
        thread::sleep(target.duration_since(now));
    }
}

struct Packet {
    batch: IntervalBatch,
    calls: [Call; 4],
}
struct Outcome {
    status: Result<(), Error>,
    unsent: Option<Packet>,
    partial: Vec<Call>,
    totals: Option<PairTotals>,
    detached: bool,
}
fn export<T>(tx: &mpsc::SyncSender<T>, value: T) -> Result<(), (Error, T)> {
    tx.try_send(value).map_err(|e| match e {
        mpsc::TrySendError::Full(v) => (Error::Full, v),
        mpsc::TrySendError::Disconnected(v) => (Error::Disconnected, v),
    })
}
// On ANY controller failure disconnect export before the existing bounded join.
// Input/controller declarations precede this guard and therefore outlive it.
struct Stream {
    rx: Option<mpsc::Receiver<Packet>>,
    worker: Worker<Outcome>,
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.rx.take();
    }
}
struct Work {
    client: IntervalClient,
    expected: Expected,
    input: Arc<[u8; 96]>,
    input_before: [u8; 96],
    labels: [(u64, usize); CALLS],
    cpu: usize,
    clock: Arc<OnceLock<(Instant, Instant)>>,
    ready: mpsc::SyncSender<u64>,
    start: mpsc::Receiver<()>,
    export: mpsc::SyncSender<Packet>,
}
fn invoke(
    work: &Work,
    attached: &mut IntervalThread,
    out: &mut Outcome,
    origin: Instant,
    base: Instant,
) -> Result<(), Error> {
    let deadline = base + WAIT;
    let mut export_failure = None;
    for (i, &(id, length)) in work.labels.iter().enumerate() {
        until(base + Duration::from_millis(check::call_ms(i)), deadline)?;
        let prefix = attached.raw_intervals().map_err(|_| Error::Native)?;
        if prefix.len() != out.partial.len()
            || prefix.iter().zip(&out.partial).any(|(r, c)| r != &c.raw)
        {
            return Err(Error::Batch);
        }
        let before = Instant::now();
        // SAFETY: trusted fixed bytes, live immutable nonempty input, pinned
        // worker, exact installed gate/stack, no signal/nonlocal exit or reentry.
        let result = unsafe { attached.invoke_integer_leaf(&work.input[16..16 + length]) }
            .map_err(|_| Error::Native)?;
        let after = Instant::now();
        let rows = attached.raw_intervals().map_err(|_| Error::Native)?;
        if rows.len() != prefix.len() + 1
            || rows[..prefix.len()] != prefix
            || *work.input != work.input_before
        {
            return Err(Error::Call);
        }
        let call = Call {
            id,
            length,
            raw: *rows.last().ok_or(Error::Call)?,
            call: result,
            before: ns(origin, before),
            after: ns(origin, after),
        };
        if out.partial.len() == 4 {
            return Err(Error::Batch);
        }
        out.partial.push(call); // Retain the observed prefix before validation/refusal.
        check::call_shape(i, &call, ns(origin, base), &work.expected)?;
        if out.partial.len() == 4 {
            let batch = attached
                .drain_completed()
                .map_err(|_| Error::Native)?
                .ok_or(Error::Batch)?;
            if !attached
                .raw_intervals()
                .map_err(|_| Error::Native)?
                .is_empty()
            {
                return Err(Error::Batch);
            }
            let calls = std::array::from_fn(|n| out.partial[n]);
            out.partial.clear();
            if let Err((error, packet)) = export(&work.export, Packet { batch, calls }) {
                out.unsent = Some(packet);
                export_failure = Some(error);
                break;
            }
        }
    }
    out.totals = Some(attached.totals().map_err(|_| Error::Native)?);
    if !out.partial.is_empty()
        || !attached
            .raw_intervals()
            .map_err(|_| Error::Native)?
            .is_empty()
        || attached
            .drain_completed()
            .map_err(|_| Error::Native)?
            .is_some()
    {
        return Err(Error::Batch);
    }
    if attached.detach().map_err(|_| Error::Native)? != out.totals.unwrap() {
        return Err(Error::Native);
    }
    out.detached = true;
    export_failure.map_or(Ok(()), Err)
}
fn work(work: Work) -> Outcome {
    let mut out = Outcome {
        status: Ok(()),
        unsent: None,
        partial: Vec::with_capacity(4),
        totals: None,
        detached: false,
    };
    out.status = (|| {
        pin(Some(work.cpu));
        // SAFETY: only this worker invokes; publication finished before spawn.
        let mut attached = unsafe { work.client.attach(1, stack(), IntervalJournal::allocate()) }
            .map_err(|_| Error::Native)?;
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
        work.ready.send(tid).map_err(|_| Error::Disconnected)?;
        work.start
            .recv_timeout(WAIT)
            .map_err(|_| Error::Disconnected)?;
        let (origin, base) = *work.clock.get().ok_or(Error::Schedule)?;
        invoke(&work, &mut attached, &mut out, origin, base)
    })();
    out
}
struct Collected {
    calls: Vec<Call>,
    batches: Vec<IntervalBatch>,
    transitions: Vec<Transition>,
    retired: Vec<Retired>,
    records: Vec<RecordObservation>,
    g0: Option<u64>,
}
impl Collected {
    fn new() -> Self {
        Self {
            calls: Vec::with_capacity(CALLS),
            batches: Vec::with_capacity(BATCHES),
            transitions: Vec::with_capacity(40),
            retired: Vec::with_capacity(EPOCHS),
            records: Vec::with_capacity(CALLS),
            g0: None,
        }
    }
    fn receive(&mut self, packet: Packet, g: &[u64; EPOCHS], e: &Expected) -> Result<(), Error> {
        if self.batches.len() == BATCHES || self.calls.len() + 4 > CALLS {
            return Err(Error::Batch);
        }
        self.calls.extend(packet.calls);
        self.batches.push(packet.batch);
        let b = Batch::from(self.batches.last().ok_or(Error::Batch)?);
        let g0 = match self.g0 {
            Some(n) => n,
            None => b.gate.checked_sub(4).ok_or(Error::Batch)?,
        };
        check::batch(&b, &self.calls, g, e, g0)?;
        check::prefix(&self.transitions, &self.calls, g, e)?;
        self.g0 = Some(g0);
        Ok(())
    }
}
fn history(controller: &IntervalController, t: &[Transition]) -> Result<(), Error> {
    let h = controller.history().map_err(|_| Error::Native)?;
    let last = t.last().ok_or(Error::Schedule)?;
    let current = if last.index % 2 == 0 {
        Some(last.generation)
    } else {
        None
    };
    if h.status != ControllerStatus::Ready
        || h.current.map(|g| g.get()) != current
        || h.enabled != [true]
        || h.retained_failed_generation.is_some()
        || h.actions.len() != t.len()
    {
        return Err(Error::Reuse);
    }
    for (i, (a, t)) in h.actions.iter().zip(t).enumerate() {
        if a.kind
            != if i % 2 == 0 {
                ActionKind::Published
            } else {
                ActionKind::Removed
            }
            || a.generation.get() != t.generation
            || a.current.map(|g| g.get()) != if i % 2 == 0 { Some(t.generation) } else { None }
            || a.function.is_some()
            || a.group.is_some()
        {
            return Err(Error::Reuse);
        }
    }
    Ok(())
}
const CONFIG: Config = Config {
    retained_per_function: CALLS,
    max_inflight: 1,
    max_invocations: CALLS,
};
fn control(
    controller: &mut IntervalController,
    slots: &mut [Option<(usize, IntervalEpoch)>; 3],
    g: &mut [u64; EPOCHS],
    e: &Expected,
    stream: &Stream,
    clock: (Instant, Instant),
    data: &mut Collected,
) -> Result<u64, Error> {
    let (origin, base) = clock;
    let deadline = base + WAIT;
    let base_ns = ns(origin, base);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::Schedule);
        }
        let action = data.transitions.len();
        // Due arm/disarm operations take priority over packet validation/retirement.
        if action < 40 && now >= base + Duration::from_millis(check::action_ms(action)) {
            let epoch = action / 2;
            let (index, token) = slots[epoch % 3].as_ref().ok_or(Error::Reuse)?;
            if *index != epoch {
                return Err(Error::Reuse);
            }
            let before = Instant::now();
            if action % 2 == 0 {
                controller.arm(token)
            } else {
                controller.disarm(token)
            }
            .map_err(|_| Error::Native)?;
            let after = Instant::now();
            data.transitions.push(Transition {
                index: action,
                generation: g[epoch],
                requested: base_ns + check::action_ms(action) * 1_000_000,
                before: ns(origin, before),
                after: ns(origin, after),
            });
            if after >= deadline {
                return Err(Error::Schedule);
            }
            history(controller, &data.transitions)?;
            continue;
        }
        for (index, &generation) in g.iter().enumerate().skip(3) {
            if generation == 0 && ns(origin, now) >= check::cutoff(base_ns, index)? {
                return Err(Error::Reuse);
            }
        }
        let old = data.retired.len();
        if old < EPOCHS && data.transitions.len() > 2 * old + 1 {
            let disarm = data.transitions[2 * old + 1];
            if let Some(c) = data.calls.iter().find(|c| c.before > disarm.after) {
                // All data.calls are from accepted complete packets. This call's
                // real invoke and successful idle drain preceded the one-way send.
                let checkpoint = c.raw.ordinal;
                let (index, token) = slots[old % 3].as_ref().ok_or(Error::Reuse)?;
                if *index != old {
                    return Err(Error::Reuse);
                }
                let before = ns(origin, Instant::now());
                let report = controller.retire(token).map_err(|_| Error::Native)?;
                let after = ns(origin, Instant::now());
                slots[old % 3].take();
                let record_start = data.records.len();
                data.retired.push(Retired {
                    epoch: old,
                    generation: report.generation().get(),
                    checkpoint,
                    before,
                    after,
                    staged_after: None,
                    record_start,
                    record_end: record_start,
                });
                for record in report.records() {
                    if data.records.len() == CALLS {
                        return Err(Error::Report);
                    }
                    data.records.push(record);
                    data.retired[old].record_end = data.records.len();
                }
                if report.generation().get() != g[old] {
                    return Err(Error::Report);
                }
                check::report(&data.calls, g[old], &data.records[record_start..])?;
                drop(report); // Last acquired Report permit is gone BEFORE staging.
                if old + 3 < EPOCHS {
                    if g[old + 3] != 0
                        || ns(origin, Instant::now()) >= check::cutoff(base_ns, old + 3)?
                    {
                        return Err(Error::Reuse);
                    }
                    let next = controller.stage(CONFIG).map_err(|_| Error::Native)?;
                    let staged = ns(origin, Instant::now());
                    g[old + 3] = next.generation().get();
                    slots[old % 3] = Some((old + 3, next));
                    data.retired[old].staged_after = Some(staged);
                    if staged >= check::cutoff(base_ns, old + 3)? || g[old + 3] <= g[old + 2] {
                        return Err(Error::Reuse);
                    }
                }
                check::reuse(&data.retired[old], &data.transitions, &data.calls, g)?;
                history(controller, &data.transitions)?;
                let expected_live = 3usize.saturating_sub(data.retired.len().saturating_sub(17));
                if slots.iter().flatten().count() != expected_live {
                    return Err(Error::Reuse);
                }
                continue;
            }
        }
        if action == 40
            && data.calls.len() == CALLS
            && data.retired.len() == EPOCHS
            && now >= base + Duration::from_millis(800)
        {
            return Ok(ns(origin, now));
        }
        let mut wake = if action < 40 {
            base + Duration::from_millis(check::action_ms(action))
        } else {
            base + Duration::from_millis(800)
        };
        for (i, &generation) in g.iter().enumerate().skip(3) {
            if generation == 0 {
                wake = wake.min(origin + Duration::from_nanos(check::cutoff(base_ns, i)?));
            }
        }
        if wake <= now {
            wake = deadline;
        }
        match stream
            .rx
            .as_ref()
            .ok_or(Error::Disconnected)?
            .recv_timeout(wake.duration_since(now))
        {
            Ok(packet) => data.receive(packet, g, e)?,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if data.calls.len() != CALLS {
                    return Err(Error::Disconnected);
                }
                // Worker is finished; only the fixed final window boundary remains.
                until(base + Duration::from_millis(800), deadline)?;
            }
        }
    }
}

fn emit_call(c: &Call) {
    let (owner, g, inv) = match c.raw.owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation,
        } => ("sampled", generation, invocation.to_string()),
        RawIntervalOwner::Removed { generation } => ("removed", generation, String::new()),
        RawIntervalOwner::InitialDisarmed => ("initial", 0, String::new()),
        RawIntervalOwner::FunctionClosed { generation } => ("closed", generation, String::new()),
    };
    println!(
        "{},{},{},{owner},{g},{inv},{},{},{},{},{},{},{},{},{},{},{},{}",
        c.id,
        c.raw.ordinal,
        c.length,
        c.before,
        c.after,
        c.call.value,
        c.call.pre_call_rsp,
        c.call.entry_rsp,
        c.call.resumed_rsp,
        c.raw.start.ticks,
        c.raw.end.ticks,
        c.raw.start.aux,
        c.raw.end.aux,
        c.raw.entry_pc,
        c.raw.return_pc
    );
}
fn emit(data: &Collected, out: &Outcome) {
    // All formatting occurs after join. Partial/failure observations are kept;
    // only run's final complete checks can emit the distinct PASS terminal.
    println!("# transitions\naction,index,generation,requested_ns,before_ns,after_ns");
    for t in &data.transitions {
        println!(
            "{},{},{},{},{},{}",
            if t.index % 2 == 0 { "arm" } else { "disarm" },
            t.index,
            t.generation,
            t.requested,
            t.before,
            t.after
        );
    }
    println!(
        "# calls\nexternal_id,ordinal,length,owner,generation,invocation,before_ns,after_ns,value,pre_rsp,entry_rsp,resumed_rsp,start_ticks,end_ticks,start_aux,end_aux,entry_pc,return_pc"
    );
    for c in &data.calls {
        emit_call(c);
    }
    println!(
        "# batches\nnumber,raw_start,raw_end,event_start,event_end,sequence_start,sequence_end,next_ordinal,gate_sequence,entries,returns,sampled,removed"
    );
    for b in &data.batches {
        let (_, n) = b.totals();
        let (a, z) = b.completed_sequences();
        println!(
            "{},{},{},{},{},{a},{z},{},{},{},{},{},{}",
            b.number(),
            b.raw_range().start,
            b.raw_range().end,
            b.event_range().start,
            b.event_range().end,
            b.next_ordinal(),
            b.gate_sequence(),
            n.entries,
            n.returns,
            n.completed,
            n.unsampled
        );
    }
    println!(
        "# retirement\nepoch,generation,checkpoint_ordinal,retire_before_ns,retire_after_ns,stage_complete_ns,record_start,record_end"
    );
    for r in &data.retired {
        println!(
            "{},{},{},{},{},{},{},{}",
            r.epoch,
            r.generation,
            r.checkpoint,
            r.before,
            r.after,
            r.staged_after.map(|n| n.to_string()).unwrap_or_default(),
            r.record_start,
            r.record_end
        );
    }
    println!(
        "# reports\ngeneration,invocation,thread,start_sequence,entry_ticks,end_ticks,rank,children"
    );
    for r in &data.records {
        if let (
            Some(p),
            Some(Terminal::Completed {
                disposition: Disposition::Retained { rank },
                ..
            }),
        ) = (r.payload, r.record.terminal)
        {
            if let PayloadOutcome::Completed {
                end: Observation::Value(end),
                completed_children,
            } = p.outcome
            {
                println!(
                    "{},{},{},{},{},{end},{rank},{completed_children}",
                    r.record.admission.generation.get(),
                    r.record.admission.invocation,
                    p.thread,
                    p.start_sequence,
                    r.record.admission.entry_value
                );
            } else {
                println!("# failed report observation {r:?}");
            }
        } else {
            println!("# incomplete report {r:?}");
        }
    }
    if let Some(packet) = &out.unsent {
        println!(
            "# FAILED unsent owned batch number={} rows={} events={}",
            packet.batch.number(),
            packet.batch.rows().len(),
            packet.batch.journal()[0]
        );
        for c in &packet.calls {
            emit_call(c);
        }
    }
    if !out.partial.is_empty() {
        println!("# FAILED partial worker calls");
        for c in &out.partial {
            emit_call(c);
        }
    }
    if let Err(error) = out.status {
        println!("# FAILED worker {error:?} detached={}", out.detached);
    }
}

pub(super) fn run(candidate: &Path, expected: &Path) {
    single_main();
    let [worker_cpu, controller_cpu] = two_cpus();
    let bytes = expected_file(candidate, expected);
    // SAFETY: sole source owner, exact trusted DSO, readonly nonempty scalar ABI,
    // no external entry, constructors, CET, signal/unwind, fork, unload or writer.
    let owner =
        unsafe { LoadedIntegerLeaf::load(candidate, &bytes, c"exact_work_nonempty", CONTRACT) }
            .unwrap();
    truth::check_bytes(owner.code()).unwrap();
    let entry = owner.entry();
    let ret = entry.checked_add(36).unwrap();
    assert_eq!(
        owner.certificate().range(),
        (entry, entry + truth::BYTES.len() as u64)
    );
    assert_eq!(owner.certificate().returns(), [ret]);
    assert_eq!(
        owner.certificate().heads(),
        truth::HEADS.map(|n| entry + u64::from(n))
    );
    let gate = CallGate::new(owner.certificate()).unwrap();
    let continuation = gate.continuation();
    let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
    assert_eq!(prep.role_pcs().collect::<Vec<_>>(), [entry, ret]);
    let input_before = guarded();
    let input = Arc::new(input_before);
    let labels =
        std::array::from_fn::<_, CALLS, _>(|i| (1000 + i as u64, if i % 2 == 0 { 1 } else { 64 }));
    let values = labels.map(|(_, n)| truth::checksum(&input[16..16 + n]).unwrap());
    let readable = stack();
    for (i, (_, length)) in labels.iter().copied().enumerate() {
        let slice = &input[16..16 + length];
        // SAFETY: exclusive uninstalled owner, valid retained input and actual stack.
        let c = unsafe { prep.invoke_original(slice.as_ptr(), length, &readable) }.unwrap();
        assert_eq!(c.value, values[i]);
        assert_eq!(c.pre_call_rsp, c.resumed_rsp);
        assert_eq!(*input, input_before);
        let truth = truth::interpret(
            &truth::BYTES,
            slice,
            entry,
            slice.as_ptr() as usize as u64,
            c.pre_call_rsp - 8,
            continuation,
        )
        .unwrap();
        assert_eq!(truth.value, c.value);
        assert_eq!(truth.resumed_rsp, c.resumed_rsp);
        assert_eq!(truth.steps.len(), truth::counts(length).unwrap().0);
    }
    let mut prepared = PreparedIntervalController::new(
        publish(prep),
        INSTALL,
        FUNCTION,
        Limits {
            epochs: 3,
            threads: 1,
            depth: 1,
            records_per_epoch: CALLS,
            actions: 40,
        },
    )
    .unwrap();
    let mut slots = std::array::from_fn::<_, 3, _>(|i| Some((i, prepared.stage(CONFIG).unwrap())));
    let mut generations = [0; EPOCHS];
    for (i, slot) in slots.iter().enumerate() {
        generations[i] = slot.as_ref().unwrap().1.generation().get();
    }
    // SAFETY: pristine concurrent activation; controller never waits while holding
    // metadata locks and no application mutex/acknowledgement surrounds calls.
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let mut e = Expected {
        values,
        entry,
        ret,
        continuation,
        pid: std::process::id(),
        tid: 0,
    };
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (start_tx, start_rx) = mpsc::sync_channel(1);
    let (tx, rx) = mpsc::sync_channel(2);
    let clock = Arc::new(OnceLock::new());
    let work_input = Work {
        client,
        expected: e.clone(),
        input: Arc::clone(&input),
        input_before,
        labels,
        cpu: worker_cpu,
        clock: Arc::clone(&clock),
        ready: ready_tx,
        start: start_rx,
        export: tx,
    };
    let handle = thread::spawn(move || work(work_input));
    let mut stream = Stream {
        rx: Some(rx),
        worker: Worker {
            resume: Some(start_tx),
            handle: Some(handle),
        },
    };
    pin(Some(controller_cpu));
    e.tid = ready_rx.recv_timeout(WAIT).unwrap();
    assert_ne!(e.tid, u64::from(e.pid));
    let mut data = Collected::new();
    let origin = Instant::now();
    let before = Instant::now();
    controller.arm(&slots[0].as_ref().unwrap().1).unwrap();
    let base = Instant::now();
    data.transitions.push(Transition {
        index: 0,
        generation: generations[0],
        requested: 0,
        before: ns(origin, before),
        after: ns(origin, base),
    });
    clock.set((origin, base)).unwrap();
    stream.worker.resume.take().unwrap().send(()).unwrap();
    let result = control(
        &mut controller,
        &mut slots,
        &mut generations,
        &e,
        &stream,
        (origin, base),
        &mut data,
    );
    stream.rx.take(); // Disconnect first on failure, then bounded join before input/controller drop.
    let outcome = stream.worker.join();
    emit(&data, &outcome);
    let windowend = result.expect("streamed controller/schedule failure");
    outcome.status.expect("streamed worker/export failure");
    assert!(outcome.unsent.is_none() && outcome.partial.is_empty() && outcome.detached);
    assert_eq!(data.batches.len(), BATCHES);
    assert!(slots.iter().all(Option::is_none));
    assert_eq!(*input, input_before);
    assert_eq!(Arc::strong_count(&input), 1);
    single_main();
    history(&controller, &data.transitions).unwrap();
    let totals = outcome.totals.unwrap();
    let coverage = check::finish(
        &data.transitions,
        &data.calls,
        &generations,
        &e,
        (&data.retired, &data.records),
        windowend,
        totals,
    )
    .unwrap();
    println!(
        "# actual whole-call coverage {coverage:?}; full journal pages checked in process, not exported; uncalibrated finite trial"
    );
    println!(
        "streamed-work PASS originals=160 calls=160 entries=160 returns=160 sampled={} unsampled={} epochs=20 slots=3 retired=20 replacements=17 batches=40 raw_rows=160 events=320 actions=40 reports={} active_coverage=20 off_coverage=20 windowend_ns={windowend} worker_cpu={worker_cpu} controller_cpu={controller_cpu} input_unchanged=true detached=true joined=true",
        totals.completed,
        totals.unsampled,
        data.records.len()
    );
}
