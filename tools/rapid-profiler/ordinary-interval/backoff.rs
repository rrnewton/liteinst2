//! Small SDK demonstration. Native result checks are functional, not full-state
//! qualification or calibrated timing. The old timed/streamed trials are separate.
use super::*;
use rapid_profiler::frontend_native::backoff::{self as api, CallOutcome, Export};
use std::io::{BufWriter, Write};

const OUTPUT_CAP: usize = 64 * 1024 * 1024;
struct Output {
    file: File,
    written: usize,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .written
            .checked_add(bytes.len())
            .is_none_or(|n| n > OUTPUT_CAP)
        {
            return Err(std::io::Error::other("bounded export capacity"));
        }
        let n = self.file.write(bytes)?;
        self.written += n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
struct Sink {
    status: Result<(), String>,
    exports: u64,
    calls: u64,
    records: u64,
    reports: u32,
    history_end: u64,
    history_batches: u64,
    owners: [u64; 4],
    max_entry_prefix: u64,
    last_closed: Option<u64>,
    sampled_after_closed: bool,
    written: usize,
    unwritten: Vec<u8>,
    failed: Option<Export>,
    queued: mpsc::Receiver<Export>,
}
fn sink(output: Output, rx: mpsc::Receiver<Export>, stop: api::StopHandle) -> Sink {
    // Debug emits many tiny fragments. Bound buffering independently of the
    // existing channel and file caps; the underlying Output counts real writes.
    let mut output = BufWriter::with_capacity(8192, output);
    let mut result = Sink {
        status: Ok(()),
        exports: 0,
        calls: 0,
        records: 0,
        reports: 0,
        history_end: 0,
        history_batches: 0,
        owners: [0; 4],
        max_entry_prefix: 0,
        last_closed: None,
        sampled_after_closed: false,
        written: 0,
        unwritten: Vec::new(),
        failed: None,
        queued: rx,
    };
    let mut previous = None;
    while let Ok(packet) = result.queued.recv() {
        let shape = match &packet {
            Export::History(h) => previous.as_ref().map_or_else(
                || {
                    h.number() == 1
                        && h.range().start == 0
                        && h.before() == rapid_profiler::frontend_native::HistoryBinding::Initial
                },
                |p| h.follows(p),
            ),
            Export::Calls(c) => {
                !c.native.rows().is_empty()
                    && c.native.rows().len() <= 4
                    && (0..c.native.rows().len()).all(|i| {
                        c.native.history_prefix(2 * i).is_some()
                            && c.native.history_prefix(2 * i) == c.native.history_prefix(2 * i + 1)
                    })
            }
            Export::Report(_) => true,
        };
        if !shape {
            result.status = Err("history/batch export order".into());
            result.failed = Some(packet);
            stop.request();
            break;
        }
        // Keep every derived Debug field/array element without indentation;
        // whitespace must not consume the fixed export budget or sink CPU.
        if let Err(e) = writeln!(output, "{packet:?}") {
            result.status = Err(e.to_string());
            result.failed = Some(packet);
            stop.request();
            break;
        }
        result.exports += 1;
        match packet {
            Export::History(h) => {
                result.history_end = h.range().end;
                result.history_batches = h.number();
                previous = Some(h);
            }
            Export::Calls(c) => {
                result.calls += c.native.rows().len() as u64;
                for (i, row) in c.native.rows().iter().enumerate() {
                    let owner = match row.owner {
                        RawIntervalOwner::Sampled { generation, .. } => {
                            result.sampled_after_closed |=
                                result.last_closed.is_some_and(|closed| generation > closed);
                            0
                        }
                        RawIntervalOwner::InitialDisarmed => 1,
                        RawIntervalOwner::FunctionClosed { generation } => {
                            result.last_closed = Some(generation);
                            2
                        }
                        RawIntervalOwner::Removed { .. } => 3,
                    };
                    result.owners[owner] += 1;
                    // Actual entry event prefix, not the batch's high-water.
                    result.max_entry_prefix = result
                        .max_entry_prefix
                        .max(c.native.history_prefix(2 * i).unwrap());
                }
            }
            Export::Report(r) => {
                result.records += r.records.len() as u64;
                result.reports += 1;
            }
        }
    }
    if result.status.is_ok() {
        result.status = output
            .flush()
            .and_then(|()| output.get_ref().file.sync_all())
            .map_err(|e| e.to_string());
        if result.status.is_err() {
            stop.request();
        }
    }
    // No implicit Drop flush after reporting failure: return the bounded unsent
    // bytes with the failed packet/queue. A successful flush leaves none.
    let (output, unwritten) = output.into_parts();
    result.written = output.written;
    result.unwritten = unwritten.expect("sink writer did not unwind");
    result
}
fn cpus() -> [usize; 4] {
    const WORDS: usize = std::mem::size_of::<libc::cpu_set_t>() / std::mem::size_of::<usize>();
    let mut allowed = [0_usize; WORDS];
    assert_eq!(
        unsafe {
            libc::sched_getaffinity(
                0,
                std::mem::size_of_val(&allowed),
                allowed.as_mut_ptr().cast(),
            )
        },
        0
    );
    let mut ids = (0..WORDS * usize::BITS as usize)
        .filter(|&i| allowed[i / usize::BITS as usize] & (1 << (i % usize::BITS as usize)) != 0);
    std::array::from_fn(|_| ids.next().expect("four distinct application CPUs"))
}

pub(super) fn run(
    candidate: &Path,
    trusted: &Path,
    k: usize,
    epochs: u32,
    calls: u64,
    path: &Path,
) {
    run_mode(candidate, trusted, k, epochs, calls, path, false);
}

pub(super) fn run_wait(
    candidate: &Path,
    trusted: &Path,
    k: usize,
    epochs: u32,
    calls: u64,
    path: &Path,
) {
    run_mode(candidate, trusted, k, epochs, calls, path, true);
}

fn run_mode(
    candidate: &Path,
    trusted: &Path,
    k: usize,
    epochs: u32,
    calls: u64,
    path: &Path,
    worker_backpressure: bool,
) {
    let policy = api::Policy::ten_ms(k, epochs, calls).expect("finite backoff policy");
    let policy = if worker_backpressure {
        policy.with_worker_backpressure()
    } else {
        policy
    };
    single_main();
    let [worker_cpu, controller_cpu, sink_cpu, main_cpu] = cpus();
    let bytes = expected_file(candidate, trusted);
    // SAFETY: same explicit trusted compiler/ordinary readonly-leaf contract as
    // the existing demo. Only this worker may call the admitted nonempty symbol.
    let owner = unsafe {
        LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum_nonempty", CONTRACT)
    }
    .unwrap();
    let gate = CallGate::new(owner.certificate()).unwrap();
    let entry = owner.entry();
    let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
    let data = Arc::new(guarded());
    let expected = *data;
    let readable = stack();
    for length in LENGTHS {
        let slice = &data[16..16 + length];
        // SAFETY: original owned leaf, before publication, sole caller, valid input.
        let value =
            unsafe { prep.invoke_original(slice.as_ptr(), slice.len(), &readable) }.unwrap();
        assert_eq!(value.value, model(slice));
        assert_eq!(value.pre_call_rsp, value.resumed_rsp);
        assert_eq!(*data, expected);
    }
    let site = publish(prep);
    // SAFETY: publication is complete and process-lived, one immutable worker,
    // no foreign entry/signals/CET/nonlocal exits; actual joins below own teardown.
    let api::Prepared {
        mut driver,
        client,
        stop,
        export,
    } = unsafe { api::prepare(site, 0x0bac_c0ff, FUNCTION, policy) }.unwrap();
    let output = Output {
        file: std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
        written: 0,
    };
    let sink_stop = stop.clone();
    let mut sink_thread = Worker {
        resume: None,
        handle: Some(joined_task::spawn(move || {
            pin(Some(sink_cpu));
            sink(output, export, sink_stop)
        })),
    };
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (start_tx, start_rx) = mpsc::sync_channel(1);
    let worker_data = Arc::clone(&data);
    let worker_stop = stop.clone();
    // Declared after data/controller setup. Existing Worker Drop always joins or
    // aborts; neither failure unwinding nor sink delay releases live input.
    let mut worker = Worker {
        resume: None,
        handle: Some(joined_task::spawn(move || {
            pin(Some(worker_cpu));
            // SAFETY: actual pinned worker and live observed stack; no native work yet.
            let mut attached =
                unsafe { client.attach(stack(), IntervalJournal::allocate()) }.unwrap();
            ready_tx.send(()).unwrap();
            let start: Instant = start_rx.recv_timeout(WAIT).unwrap();
            thread::sleep(start.saturating_duration_since(Instant::now()));
            let mut count = 0_u64;
            let mut error = None;
            // Independent application cadence. No per-call controller handshake:
            // finite bursts with idle gaps, not calls indexed by epoch boundaries.
            while !worker_stop.requested() {
                let length = LENGTHS[count as usize % LENGTHS.len()];
                let slice = &worker_data[16..16 + length];
                // SAFETY: immutable guarded input, trusted 1..64 ABI and real return.
                match unsafe { attached.invoke(slice) } {
                    Ok(CallOutcome::StoppedBeforeCall) => break,
                    Ok(CallOutcome::Returned { call, export_error }) => {
                        count += 1;
                        if call.value != model(slice)
                            || call.pre_call_rsp != call.resumed_rsp
                            || *worker_data != expected
                        {
                            error = Some("functional result/input/stack".to_string());
                            worker_stop.request();
                            break;
                        }
                        if let Some(e) = export_error {
                            error = Some(format!("export: {e:?}"));
                            break;
                        }
                    }
                    Err(e) => {
                        error = Some(format!("invoke: {e:?}"));
                        worker_stop.request();
                        break;
                    }
                }
                thread::sleep(if count % 23 == 0 {
                    Duration::from_millis(3)
                } else {
                    Duration::from_micros(250)
                });
            }
            let finish = attached.finish();
            (count, error, finish)
        })),
    };
    ready_rx.recv_timeout(WAIT).expect("one initial ready");
    let start = Instant::now() + Duration::from_millis(20);
    let mut control = Worker {
        resume: None,
        handle: Some(joined_task::spawn(move || {
            pin(Some(controller_cpu));
            let result = driver.run(start);
            (driver, result)
        })),
    };
    // All children inherited the original four-CPU mask before main narrows it.
    // Keep Debug export and join polling off the controller's application CPU.
    pin(Some(main_cpu));
    start_tx.send(start).expect("one initial start");
    drop(start_tx);
    let end = start + policy.period() * policy.epoch_limit() + policy.shutdown();
    while !control.handle.as_ref().unwrap().is_finished() {
        if Instant::now() >= end {
            // No source/data reclamation or fabricated join on a stuck callback,
            // allocator or controller. The process is the final bounded owner.
            std::process::abort();
        }
        thread::sleep(Duration::from_millis(1));
    }
    let (mut driver, result) = control.join(); // Actual controller OS-thread join.
    stop.request();
    let (calls, call_error, finish) = worker.join(); // Actual worker OS-thread join.
    assert_eq!(*data, expected);
    if result.is_err() || call_error.is_some() || finish.status.error.is_some() {
        // These bounded recovery values are unexported failure prefixes, not a
        // complete successful stream. Keep the receiver until actual worker join.
        eprintln!("backoff FAILED result={result:?} call={call_error:?} worker={finish:?}");
        eprintln!("deadline diagnostic {:?}", driver.deadline_failure());
        if let Some(p) = driver.take_pending() {
            eprintln!("unexported {p:?}");
        }
        while let Some(p) = driver.recover_worker_packet() {
            eprintln!("unexported {p:?}");
        }
        eprintln!(
            "secondary removal {:?}; final history window {:?}",
            driver.close_error(),
            driver.history_window()
        );
        loop {
            match driver.recover_report() {
                Ok(Some(r)) => eprintln!("unexported report {r:?}"),
                Ok(None) => break,
                Err(e) => {
                    eprintln!("report recovery refused {e:?}");
                    break;
                }
            }
        }
    }
    drop(driver); // Closes the sole sink sender only after all real worker calls.
    let sink = sink_thread.join(); // Actual sink join, including flush/sync success.
    if sink.status.is_err() {
        eprintln!(
            "sink FAILED {:?}; retained packet {:?}; buffered bytes {:?}",
            sink.status, sink.failed, sink.unwritten
        );
        while let Ok(p) = sink.queued.try_recv() {
            eprintln!("unwritten {p:?}");
        }
    }
    let summary = result.expect("controller failure; saved prefix is not full credit");
    assert!(call_error.is_none());
    assert!(finish.status.error.is_none() && finish.status.detached && !finish.status.unexported);
    assert_eq!(finish.status.totals, Some(summary.totals));
    assert_eq!(summary.totals.entries, calls);
    assert_eq!(summary.totals.returns, calls);
    assert_eq!(sink.calls, calls);
    assert_eq!(sink.owners.iter().sum::<u64>(), calls);
    assert_eq!(sink.owners[0], summary.totals.completed);
    assert_eq!(
        sink.owners[1..].iter().sum::<u64>(),
        summary.totals.unsampled
    );
    assert_eq!(sink.records, summary.totals.completed);
    assert_eq!(sink.reports, summary.reports);
    assert_eq!(sink.history_end, summary.actions);
    assert_eq!(sink.history_batches, summary.history_batches);
    assert_eq!(sink.exports, summary.accepted_exports);
    assert!(sink.status.is_ok());
    assert!(sink.unwritten.is_empty());
    assert!(finish.unexported.is_none() && finish.partial_calls.iter().all(Option::is_none));
    let stop_reason = match summary.stop_reason {
        api::StopReason::Requested => "requested",
        api::StopReason::EpochLimit => "epoch-limit",
    };
    let ns = |time: Option<Duration>| {
        time.map_or_else(|| "none".to_string(), |d| d.as_nanos().to_string())
    };
    let policy_suffix = if policy.worker_backpressure() {
        " worker_backpressure=bounded-wait"
    } else {
        ""
    };
    println!(
        "backoff-work COMPLETE originals={} k={k} calls={calls} arms={} reports={} actions={} sampled={} unsampled={} initial={} closed={} removed={} max_entry_prefix={} sampled_after_closed={} epoch_limit={epochs} call_limit={} stop_reason={stop_reason} max_arm_late_ns={} stop_ack_ns={} removed_ns={} controller_done_ns={} call_batches={} history_batches={} accepted_exports={} written_exports={} written_bytes={} worker_detached=true actual_threads_joined=3 export_synced=true result_input_rsp_checked=true scope=finite-functional-raw-uncalibrated mandatory_hooks=on{policy_suffix}",
        LENGTHS.len(),
        summary.arms,
        summary.reports,
        summary.actions,
        summary.totals.completed,
        summary.totals.unsampled,
        sink.owners[1],
        sink.owners[2],
        sink.owners[3],
        sink.max_entry_prefix,
        sink.sampled_after_closed,
        policy.call_limit(),
        summary.max_arm_lateness.as_nanos(),
        ns(summary.stop_acknowledged),
        ns(summary.removal_completed),
        ns(summary.controller_completed),
        summary.call_batches,
        summary.history_batches,
        summary.accepted_exports,
        sink.exports,
        sink.written,
    );
}

mod optional;
pub(super) fn run_optional(
    candidate: &Path,
    trusted: &Path,
    k: usize,
    epochs: u32,
    calls: u64,
    path: &Path,
    wait: bool,
) {
    optional::run(candidate, trusted, k, epochs, calls, path, wait);
}

// The two sink-wait routes are explicit; the existing routes above stay literal.
pub(super) fn run_optional_sink_wait(
    candidate: &Path,
    trusted: &Path,
    k: usize,
    epochs: u32,
    calls: u64,
    path: &Path,
    worker_wait: bool,
) {
    optional::run_sink_wait(candidate, trusted, k, epochs, calls, path, worker_wait);
}
