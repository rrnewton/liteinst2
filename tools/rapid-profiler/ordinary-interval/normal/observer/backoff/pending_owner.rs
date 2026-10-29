//! Command-driven native ownership control. No Schedule or measured policy.
use super::*;
use rapid_profiler::frontend::Action;
#[cfg(test)]
mod tests;
const SCOPE: &str = "# normal backoff pending owner; deterministic native functional control; schedule not run; no timing or performance claim";
#[derive(Clone, Copy)]
struct Deadline(Instant);
impl Deadline {
    fn new() -> Self {
        Self(Instant::now().checked_add(Duration::from_secs(15)).unwrap())
    }
    fn live(self) -> bool {
        Instant::now() < self.0
    }
    fn check(self) {
        assert!(self.live(), "original 15-second functional deadline");
    }
    fn recv<T>(self, rx: &mpsc::Receiver<T>) -> T {
        self.check();
        let value = rx
            .recv_timeout(self.0.saturating_duration_since(Instant::now()))
            .expect("owned phase receiver");
        // T may own Engine: do not unwind/drop it on a late receive.
        if !self.live() {
            std::process::abort();
        }
        value
    }
    fn send<T>(self, tx: &mpsc::SyncSender<T>, mut value: T) {
        loop {
            if !self.live() {
                std::process::abort();
            }
            match tx.try_send(value) {
                Ok(()) => return,
                Err(mpsc::TrySendError::Full(retained)) => {
                    value = retained;
                    thread::yield_now();
                }
                Err(mpsc::TrySendError::Disconnected(retained)) => {
                    let _retained = retained;
                    std::process::abort();
                }
            }
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct HistoryCopy {
    number: u64,
    range: std::ops::Range<u64>,
    before: HistoryBinding,
    after: HistoryBinding,
    actions: Vec<Action>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    slots: [Option<(u64, Option<usize>)>; 3],
    current: Option<usize>,
    banks: usize,
    reports: Vec<ReportSpan>,
    payloads: Vec<RecordObservation>,
    history: Vec<HistoryCopy>,
    stream: (u32, u64, FunctionId),
    committed: u32,
}
impl Snapshot {
    fn actual(e: &Engine) -> Self {
        Self {
            slots: std::array::from_fn(|i| {
                e.slots[i]
                    .as_ref()
                    .map(|s| (s.epoch.as_ref().unwrap().generation().get(), s.copied))
            }),
            current: e.current,
            banks: e.banks.len(),
            reports: e.reports.clone(),
            payloads: e.payloads.clone(),
            history: e
                .history
                .iter()
                .map(|h| {
                    assert_eq!(h.stream(), &e.stream);
                    HistoryCopy {
                        number: h.number(),
                        range: h.range(),
                        before: h.before(),
                        after: h.after(),
                        actions: h.actions().to_vec(),
                    }
                })
                .collect(),
            stream: (e.stream.pid(), e.stream.install(), e.stream.function()),
            committed: e.committed,
        }
    }
    fn current_generation(&self) -> Option<u64> {
        self.current
            .and_then(|i| self.slots.get(i).copied().flatten().map(|s| s.0))
    }
}
fn held(s: &Snapshot, a: u64, b: u64, k: usize) -> bool {
    a != 0
        && a < b
        && s.stream.0 != 0
        && s.stream.1 == INSTALL
        && s.stream.2 == FUNCTION
        && s.committed == 2
        && s.banks == 1
        && s.history.len() == 2
        && s.slots.iter().filter(|s| s.is_some()).count() == 2
        && s.slots.contains(&Some((a, Some(0))))
        && s.current_generation() == Some(b)
        && s.current.is_some_and(|i| s.slots[i] == Some((b, None)))
        && s.reports
            == [ReportSpan {
                generation: a,
                start: 0,
                end: k,
            }]
        && s.payloads.len() == k
}
fn released(before: &Snapshot, after: &Snapshot, a: u64, b: u64, k: usize) -> bool {
    if !held(before, a, b, k) {
        return false;
    }
    let mut expected = before.clone();
    let Some(i) = expected.slots.iter().position(|s| *s == Some((a, Some(0)))) else {
        return false;
    };
    expected.slots[i] = None;
    expected.banks = 2;
    &expected == after
}
fn hold_ordinal(k: usize) -> u64 {
    match k {
        10 => 22,
        1000 => 1006,
        _ => panic!("fixed K"),
    }
}
fn phase_totals(k: usize, number: usize) -> NormalTotals {
    let t = hold_ordinal(k);
    assert!((1..=3).contains(&number));
    if number < 3 {
        NormalTotals {
            entered: t,
            ret_observed: t,
            confirmed: t - 1,
            completed: k as u64,
            unsampled: t - 1 - k as u64,
        }
    } else {
        NormalTotals {
            entered: t + 2,
            ret_observed: t + 2,
            confirmed: t + 1,
            completed: k as u64 + 1,
            unsampled: t - k as u64,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    tid: u64,
    a: u64,
}
#[derive(Clone, Copy)]
struct Command {
    phase: usize,
    tid: u64,
    a: u64,
    b: u64,
}
fn command_valid(c: Command, phase: usize, id: Identity, b: u64) -> bool {
    (1..=3).contains(&phase)
        && c.phase == phase
        && c.tid == id.tid
        && c.a == id.a
        && c.b == if phase == 1 { 0 } else { b }
}
enum Ack {
    Held(Box<[Snapshot; 2]>),
    Released(Box<Snapshot>),
}
struct Ports {
    ready: mpsc::SyncSender<Identity>,
    ack: mpsc::SyncSender<Ack>,
    handoff: mpsc::SyncSender<Engine>,
}
fn controller(mut engine: Engine, cpu: usize, d: Deadline, rx: mpsc::Receiver<Command>, tx: Ports) {
    let mut guard = FailStop(true);
    pin(Some(cpu));
    singleton(cpu);
    d.check();
    engine.arm();
    d.check();
    let id = Identity {
        tid: unsafe { libc::syscall(libc::SYS_gettid) } as u64,
        a: engine.slots[engine.current.unwrap()]
            .as_ref()
            .unwrap()
            .epoch
            .as_ref()
            .unwrap()
            .generation()
            .get(),
    };
    assert!(id.tid > 0 && id.tid <= i32::MAX as u64 && id.tid != u64::from(std::process::id()));
    d.send(&tx.ready, id);
    assert!(command_valid(d.recv(&rx), 1, id, 0));
    singleton(cpu);
    engine.arm();
    d.check();
    let b = engine.slots[engine.current.unwrap()]
        .as_ref()
        .unwrap()
        .epoch
        .as_ref()
        .unwrap()
        .generation()
        .get();
    engine.retire();
    d.check();
    let first = Snapshot::actual(&engine);
    assert!(held(&first, id.a, b, engine.k));
    engine.retire();
    d.check();
    let second = Snapshot::actual(&engine);
    assert_eq!(first, second);
    d.send(&tx.ack, Ack::Held(Box::new([first.clone(), second])));
    assert!(command_valid(d.recv(&rx), 2, id, b));
    singleton(cpu);
    engine.retire();
    d.check();
    let after = Snapshot::actual(&engine);
    assert!(released(&first, &after, id.a, b, engine.k));
    d.send(&tx.ack, Ack::Released(Box::new(after)));
    assert!(command_valid(d.recv(&rx), 3, id, b));
    singleton(cpu);
    engine.stop();
    engine.retire();
    d.check();
    assert!(engine.slots.iter().all(Option::is_none));
    assert_eq!(engine.banks.len(), 3);
    assert_eq!(engine.committed, 2);
    assert_eq!(engine.reports.len(), 2);
    d.send(&tx.handoff, engine);
    guard.0 = false;
}
#[derive(Clone)]
struct Phase {
    number: usize,
    totals: NormalTotals,
    completed_batches: usize,
    snapshot: Snapshot,
}
fn phases_valid(phases: &[Phase], a: u64, b: u64, k: usize) -> bool {
    phases.len() == 3
        && phases.iter().enumerate().all(|(i, p)| {
            p.number == i + 1
                && p.totals == phase_totals(k, i + 1)
                && p.completed_batches == (hold_ordinal(k) as usize - 22) / 24
        })
        && held(&phases[0].snapshot, a, b, k)
        && phases[0].snapshot == phases[1].snapshot
        && released(&phases[0].snapshot, &phases[2].snapshot, a, b, k)
}
fn boundaries(rows: &[NormalRecord], a: u64, b: u64, k: usize) -> bool {
    let t = hold_ordinal(k) as usize;
    rows.len() == CALLS
        && rows.iter().enumerate().all(|(g, r)| {
            let (generation, prefix, local) = if g < t { (a, 1, g) } else { (b, 2, g - t) };
            r.history_prefix == prefix
                && r.raw.owner
                    == if local < k {
                        RawIntervalOwner::Sampled {
                            generation,
                            invocation: local,
                        }
                    } else {
                        RawIntervalOwner::FunctionClosed { generation }
                    }
        })
        && rows[t - 1].acknowledgement
            == (NormalAcknowledgement::NextEntry {
                ordinal: t as u64 + 1,
            })
        && rows[t + 1].acknowledgement == NormalAcknowledgement::CallerCheckpoint
}
fn phase_line(p: &Phase, a: u64, b: u64, k: usize) -> String {
    let s = &p.snapshot;
    let t = p.totals;
    let line = format!(
        "PHASE,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        p.number,
        if p.number < 3 {
            "shared-owner"
        } else {
            "reclaimed"
        },
        hold_ordinal(k),
        a,
        b,
        t.entered,
        t.ret_observed,
        t.confirmed,
        t.completed,
        t.unsampled,
        p.number < 3,
        s.reports
            .iter()
            .position(|report| report.generation == a)
            .unwrap(),
        s.reports.len(),
        s.payloads.len(),
        s.banks,
        s.current_generation().unwrap(),
        s.history.len(),
        p.number,
        p.completed_batches
    );
    assert!(line.len() <= ROW_CAP);
    line
}
fn output_control(e: Export<'_>, id: Identity, b: u64, phases: &[Phase]) -> String {
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
    } = e;
    assert_eq!(controller, id.tid);
    assert_eq!(arms, 2);
    assert!(phases_valid(phases, id.a, b, f.k));
    assert!(boundaries(rows, id.a, b, f.k));
    assert!(population(returned));
    assert_eq!(
        (
            counts.sampled,
            counts.closed,
            counts.generations,
            counts.after_closed
        ),
        (2 * f.k as u64, CALLS as u64 - 2 * f.k as u64, 2, true)
    );
    let mut text = String::with_capacity(OUTPUT_CAP);
    writeln!(text, "{SCOPE}\n{HEADER}").unwrap();
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
    for (i, a) in actions[..2].iter().enumerate() {
        let r = reports
            .iter()
            .find(|r| r.generation == a.generation)
            .unwrap();
        let line = format!("REPORT,{},{},{}\n", i + 1, a.generation, r.end - r.start);
        assert!(line.len() <= 64);
        text.push_str(&line);
    }
    for p in phases {
        text.push_str(&phase_line(p, id.a, b, f.k));
    }
    writeln!(text,"normal-observer-backoff-pending-owner FUNCTIONAL_PASS k={} hold_ordinal={} generation_a={} generation_b={b} arms=2 repetitions=128 calls=3072 helper_calls=1536 instructions=614400 conditional=99840 taken=96768 input_bytes=99840 ret_bytes=24576 pid={} tid={} controller_tid={} app_cpu={app_cpu} controller_cpu={controller_cpu} entry={} caller={} install={INSTALL} function=1 batches=128 events=6144 rows=3072 sampled={} unsampled={} reports=2 records={} actions=3 journal_words=65536 next_entry_acknowledgements=2944 checkpoint_acknowledgements=128 banks=3 observed_generations=2 rearmed=true sampled_after_closed=true input_unchanged=true detached=true joined=1 old_report_copies=1 shared_owner_refusals=2 reclaim_before_checkpoint=true phase_rows=3 deadline_scope=original-15s-functional schedule=not-run timing=none",f.k,hold_ordinal(f.k),id.a,f.pid,f.pid,id.tid,f.entry,f.caller,counts.sampled,counts.closed,counts.sampled).unwrap();
    assert!(text.is_ascii() && text.len() <= OUTPUT_CAP);
    assert_eq!(text.lines().count(), 3083);
    text
}
pub(crate) fn run(args: &[std::ffi::OsString]) {
    let d = Deadline::new();
    assert_eq!(
        args.len(),
        9,
        "normal-observer-backoff-pending-owner K APP_CPU CONTROLLER_CPU CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL"
    );
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
    } = prepare(args);
    let mut setup_guard = FailStop(true);
    d.check();
    let mut data = Data::new();
    let mut sums = vec![0_u64; PAIRS];
    let mut returned = Vec::with_capacity(CALLS);
    let mut batches = Vec::with_capacity(BLOCKS);
    let mut attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
    let mut attached_guard = FailStop(true);
    assert_eq!(attached.totals().unwrap(), NormalTotals::default());
    let (command_tx, command_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (ack_tx, ack_rx) = mpsc::sync_channel(1);
    let (handoff_tx, handoff_rx) = mpsc::sync_channel(1);
    let handle = joined_task::spawn(move || {
        controller(
            engine,
            controller_cpu,
            d,
            command_rx,
            Ports {
                ready: ready_tx,
                ack: ack_tx,
                handoff: handoff_tx,
            },
        )
    });
    let mut handle_guard = FailStop(true);
    pin(Some(app_cpu));
    let id = d.recv(&ready_rx);
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
    custody(&c, &mut calling, Some(id.tid));
    d.check();
    let f = check::Facts {
        pid: std::process::id(),
        entry,
        caller,
        stack,
        k,
    };
    let t = hold_ordinal(k) as usize;
    let hold_block = (t - 22) / 24;
    let mut b_generation = 0;
    let mut phases = Vec::with_capacity(3);
    let mut totals = NormalTotals::default();
    let mut high = 0;
    for block in 0..BLOCKS {
        let first = block * BLOCK / 2;
        let last = first + BLOCK / 2;
        let cut = if block == hold_block { last - 1 } else { last };
        d.check();
        call_range(
            &mut data,
            &mut sums,
            &mut returned,
            &mut calling,
            &c,
            entry,
            first..cut,
        );
        custody(&c, &mut calling, Some(id.tid));
        assert_eq!(*data.inputs, [input(0), input(1)]);
        d.check();
        if block == hold_block {
            let before = attached.totals().unwrap();
            assert_eq!(before, phase_totals(k, 1));
            assert_eq!(returned.len(), t);
            d.send(
                &command_tx,
                Command {
                    phase: 1,
                    tid: id.tid,
                    a: id.a,
                    b: 0,
                },
            );
            let Ack::Held(snapshots) = d.recv(&ack_rx) else {
                panic!("first owned acknowledgement");
            };
            assert_eq!(attached.totals().unwrap(), before);
            b_generation = snapshots[0].current_generation().unwrap();
            for (i, snapshot) in (*snapshots).into_iter().enumerate() {
                phases.push(Phase {
                    number: i + 1,
                    totals: before,
                    completed_batches: batches.len(),
                    snapshot,
                });
            }
            d.check();
            call_range(
                &mut data,
                &mut sums,
                &mut returned,
                &mut calling,
                &c,
                entry,
                cut..last,
            );
            custody(&c, &mut calling, Some(id.tid));
            assert_eq!(*data.inputs, [input(0), input(1)]);
            d.check();
            let after = attached.totals().unwrap();
            assert_eq!(after, phase_totals(k, 3));
            d.send(
                &command_tx,
                Command {
                    phase: 2,
                    tid: id.tid,
                    a: id.a,
                    b: b_generation,
                },
            );
            let Ack::Released(snapshot) = d.recv(&ack_rx) else {
                panic!("second owned acknowledgement");
            };
            assert_eq!(attached.totals().unwrap(), after);
            phases.push(Phase {
                number: 3,
                totals: after,
                completed_batches: batches.len(),
                snapshot: *snapshot,
            });
            assert!(phases_valid(&phases, id.a, b_generation, k));
        }
        // Complete actual return/source/input postflight precedes the only block checkpoint.
        d.check();
        let batch = unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .expect("24 actual returned calls");
        high = check::high_water(high, batch.history_high_water(), 2).unwrap();
        totals = check::batch(
            f,
            block,
            check::Meta::actual(&batch, &stream),
            batch.records(),
            batch.journal(),
            totals,
        )
        .unwrap();
        assert_eq!(attached.totals().unwrap(), totals);
        batches.push(batch);
        d.check();
    }
    assert!(population(&returned));
    assert_eq!(sums.len(), PAIRS);
    for (p, &sum) in sums.iter().enumerate() {
        data.check(p, true);
        let value = case(2 * p).value;
        assert_eq!(sum, value.wrapping_add(value));
    }
    custody(&c, &mut calling, Some(id.tid));
    d.check();
    assert!(
        unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .is_none()
    );
    assert_eq!(attached.detach().unwrap(), totals);
    assert_eq!(
        totals,
        NormalTotals {
            entered: 3072,
            ret_observed: 3072,
            confirmed: 3072,
            completed: 2 * k as u64,
            unsampled: 3072 - 2 * k as u64
        }
    );
    d.send(
        &command_tx,
        Command {
            phase: 3,
            tid: id.tid,
            a: id.a,
            b: b_generation,
        },
    );
    let engine = d.recv(&handoff_rx);
    let mut handoff_guard = FailStop(true);
    while !handle.is_finished() {
        d.check();
        thread::yield_now();
    }
    d.check();
    let mut joined = handle.join();
    d.check();
    assert_eq!(u64::from(joined.tid()), id.tid);
    while !joined_task::poll_exclusive(&mut [&mut joined], || {
        if d.live() {
            Ok(())
        } else {
            Err(joined_task::Error::Deadline)
        }
    })
    .unwrap()
    {
        thread::yield_now();
    }
    joined.result().as_ref().expect("actual controller join");
    d.check();
    custody(&c, &mut calling, None);
    d.check();
    let (rows, actions, counts) = finish(
        &engine,
        &stream,
        &batches,
        Final {
            f,
            totals,
            high,
            arms: 2,
        },
    );
    assert_eq!(actions[0].generation, id.a);
    assert_eq!(actions[1].generation, b_generation);
    assert!(boundaries(&rows, id.a, b_generation, k));
    custody(&c, &mut calling, None);
    d.check();
    let text = output_control(
        Export {
            f,
            controller: id.tid,
            app_cpu,
            controller_cpu,
            rows: &rows,
            returned: &returned,
            actions: &actions,
            reports: &engine.reports,
            counts,
            arms: 2,
        },
        id,
        b_generation,
        &phases,
    );
    d.check();
    std::io::stdout().lock().write_all(text.as_bytes()).unwrap();
    d.check();
    handoff_guard.0 = false;
    handle_guard.0 = false;
    attached_guard.0 = false;
    setup_guard.0 = false;
}
