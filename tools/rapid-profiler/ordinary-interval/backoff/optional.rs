//! Explicit optional demo; sparse observation is not a changed mandatory result.
use super::*;
use api::{OptionalCallOutcome, OptionalExport};
use rapid_profiler::frontend::ActionKind;
use rapid_profiler::frontend_native::{InstalledOptionalSite, OptionalSitePreparation};

struct Sink {
    status: Result<(), String>,
    exports: u64,
    physical: u64,
    fast: u64,
    slow: u64,
    records: u64,
    reports: u32,
    actions: u64,
    histories: u64,
    disabled: u32,
    owners: [u64; 4],
    max_entry_prefix: u64,
    written: usize,
    unwritten: Vec<u8>,
    failed: Option<OptionalExport>,
    queued: mpsc::Receiver<OptionalExport>,
}
fn sink(output: Output, rx: mpsc::Receiver<OptionalExport>, stop: api::StopHandle) -> Sink {
    let mut output = BufWriter::with_capacity(8192, output);
    let mut s = Sink {
        status: Ok(()),
        exports: 0,
        physical: 0,
        fast: 0,
        slow: 0,
        records: 0,
        reports: 0,
        actions: 0,
        histories: 0,
        disabled: 0,
        owners: [0; 4],
        max_entry_prefix: 0,
        written: 0,
        unwritten: Vec::new(),
        failed: None,
        queued: rx,
    };
    let mut previous = None;
    while let Ok(packet) = s.queued.recv() {
        let shape = match &packet {
            OptionalExport::History(h) => previous.as_ref().map_or_else(
                || {
                    h.number() == 1
                        && h.range().start == 0
                        && h.before() == rapid_profiler::frontend_native::HistoryBinding::Initial
                },
                |p| h.follows(p),
            ),
            OptionalExport::Calls(c) => {
                let range = c.native.physical_range();
                let count = range.end.checked_sub(range.start);
                count.is_some_and(|n| (1..=4).contains(&n))
                    && range.start == s.physical
                    && c.native.rows().len() <= count.unwrap() as usize
                    && (0..c.native.rows().len()).all(|i| {
                        c.native.history_prefix(i * 2).is_some()
                            && c.native.history_prefix(i * 2) == c.native.history_prefix(i * 2 + 1)
                    })
            }
            OptionalExport::Report(_) => true,
        };
        if !shape {
            s.status = Err("optional history/physical batch order".into());
            s.failed = Some(packet);
            stop.request();
            break;
        }
        if let Err(e) = writeln!(output, "{packet:?}") {
            s.status = Err(e.to_string());
            s.failed = Some(packet);
            stop.request();
            break;
        }
        s.exports += 1;
        match packet {
            OptionalExport::History(h) => {
                s.actions = h.range().end;
                s.histories = h.number();
                s.disabled += h
                    .actions()
                    .iter()
                    .filter(|a| a.kind == ActionKind::Disabled)
                    .count() as u32;
                previous = Some(h);
            }
            OptionalExport::Calls(c) => {
                let (before, after) = c.native.totals();
                s.physical = after.physical;
                s.fast += after.bypassed - before.bypassed;
                s.slow += c.native.rows().len() as u64;
                for (i, row) in c.native.rows().iter().enumerate() {
                    let owner = match row.owner {
                        RawIntervalOwner::Sampled { .. } => 0,
                        RawIntervalOwner::InitialDisarmed => 1,
                        RawIntervalOwner::FunctionClosed { .. } => 2,
                        RawIntervalOwner::Removed { .. } => 3,
                    };
                    s.owners[owner] += 1;
                    s.max_entry_prefix = s
                        .max_entry_prefix
                        .max(c.native.history_prefix(i * 2).unwrap());
                }
            }
            OptionalExport::Report(r) => {
                s.records += r.records.len() as u64;
                s.reports += 1;
            }
        }
    }
    if s.status.is_ok() {
        s.status = output
            .flush()
            .and_then(|()| output.get_ref().file.sync_all())
            .map_err(|e| e.to_string());
        if s.status.is_err() {
            stop.request();
        }
    }
    let (output, unwritten) = output.into_parts();
    s.written = output.written;
    s.unwritten = unwritten.expect("no sink unwind");
    s
}
fn publish(prep: OptionalSitePreparation) -> InstalledOptionalSite {
    single_main();
    let planned = prep.plan();
    let original = planned.plan().originals();
    assert_eq!(original.len(), 1);
    let source = AddressRange::new(original[0].address, original[0].bytes.len()).unwrap();
    assert_eq!(source.start() % 4096, 0);
    assert!(matches!(source.len(), 4096 | 8192));
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    // SAFETY: whole owned source, actual single-thread exclusion, no foreign
    // entry/signal/resume/unload/alias writer; only prep owns the original gate.
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let result = {
        let mut lease =
            unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
        let result = unsafe {
            planned.publish_with(&[alias], &mut lease, || {
                protect(source, libc::PROT_READ | libc::PROT_EXEC)
            })
        };
        if result.is_ok() {
            assert!(!lease.is_poisoned());
        }
        result
    };
    let (installed, receipt) = match result {
        Ok(p) => p,
        Err(e) => {
            eprintln!("optional publication FAILED: {e:?}");
            std::process::abort();
        }
    };
    // SAFETY: actual complete publication; seal retains all source/image/receipt
    // and selector owners process-lived even on correspondence refusal.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}
pub(super) fn run(
    candidate: &Path,
    trusted: &Path,
    k: usize,
    epochs: u32,
    limit: u64,
    path: &Path,
    wait: bool,
) {
    let policy = api::Policy::ten_ms(k, epochs, limit).unwrap();
    let policy = if wait {
        policy.with_worker_backpressure()
    } else {
        policy
    };
    single_main();
    let [worker_cpu, controller_cpu, sink_cpu, main_cpu] = cpus();
    let bytes = expected_file(candidate, trusted);
    // SAFETY: same separately trusted bounded integer compiler fixture/unsafe
    // ABI as the mandatory demo, plus the optional profile's reserved RBX proof.
    let owner = unsafe {
        LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum_nonempty", CONTRACT)
    }
    .unwrap();
    let entry = owner.entry();
    let mut prep = OptionalSitePreparation::new(owner, identity(entry)).unwrap();
    let data = Arc::new(guarded());
    let expected = *data;
    let readable = stack();
    for length in LENGTHS {
        let input = &data[16..16 + length];
        // SAFETY: one-shot exclusive original call before any publication.
        let value = unsafe {
            prep.prepare_original_call()
                .unwrap()
                .invoke(input.as_ptr(), input.len(), &readable)
        }
        .unwrap();
        assert_eq!(value.value, model(input));
        assert_eq!(value.pre_call_rsp, value.resumed_rsp);
        assert_eq!(*data, expected);
    }
    let site = publish(prep);
    // SAFETY: complete process-lived optional publication; only one actual worker
    // invokes with immutable owned input. Actual joins below precede reclamation.
    let api::OptionalPrepared {
        mut driver,
        client,
        stop,
        export,
    } = unsafe { api::prepare_optional(site, 0x0bac_c0ff, FUNCTION, policy) }.unwrap();
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
        handle: Some(thread::spawn(move || {
            pin(Some(sink_cpu));
            sink(output, export, sink_stop)
        })),
    };
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (start_tx, start_rx) = mpsc::sync_channel(1);
    let worker_data = data.clone();
    let worker_stop = stop.clone();
    let mut worker = Worker {
        resume: None,
        handle: Some(thread::spawn(move || {
            pin(Some(worker_cpu));
            // SAFETY: actual pinned worker owns its stack and new journal.
            let mut attached =
                unsafe { client.attach(stack(), IntervalJournal::allocate()) }.unwrap();
            ready_tx.send(()).unwrap();
            let start: Instant = start_rx.recv_timeout(WAIT).unwrap();
            thread::sleep(start.saturating_duration_since(Instant::now()));
            let mut count = 0u64;
            let mut error = None;
            while !worker_stop.requested() {
                let length = LENGTHS[count as usize % LENGTHS.len()];
                let input = &worker_data[16..16 + length];
                // SAFETY: same valid immutable input/stack/normal-return obligations.
                match unsafe { attached.invoke(input) } {
                    Ok(OptionalCallOutcome::StoppedBeforeCall) => break,
                    Ok(OptionalCallOutcome::Returned { call, export_error }) => {
                        count += 1;
                        if call.value != model(input)
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
                // Same independent cadence: no per-call controller rendezvous.
                thread::sleep(if count % 23 == 0 {
                    Duration::from_millis(3)
                } else {
                    Duration::from_micros(250)
                });
            }
            (count, error, attached.finish())
        })),
    };
    ready_rx.recv_timeout(WAIT).expect("one initial ready");
    let start = Instant::now() + Duration::from_millis(20);
    let mut control = Worker {
        resume: None,
        handle: Some(thread::spawn(move || {
            pin(Some(controller_cpu));
            let result = driver.run(start);
            (driver, result)
        })),
    };
    pin(Some(main_cpu));
    start_tx.send(start).expect("one initial start");
    drop(start_tx);
    let end = start + policy.period() * policy.epoch_limit() + policy.shutdown();
    while !control.handle.as_ref().unwrap().is_finished() {
        if Instant::now() >= end {
            std::process::abort();
        }
        thread::sleep(Duration::from_millis(1));
    }
    let (mut driver, result) = control.join();
    stop.request();
    let (calls, call_error, finish) = worker.join();
    assert_eq!(*data, expected);
    if result.is_err() || call_error.is_some() || finish.status.error.is_some() {
        eprintln!(
            "optional backoff FAILED result={result:?} call={call_error:?} worker={finish:?}"
        );
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
    drop(driver);
    let sink = sink_thread.join();
    if sink.status.is_err() {
        eprintln!(
            "sink FAILED {:?}; packet {:?}; buffered {:?}",
            sink.status, sink.failed, sink.unwritten
        );
        while let Ok(p) = sink.queued.try_recv() {
            eprintln!("unwritten {p:?}");
        }
    }
    let summary = result.expect("failed prefix is not COMPLETE");
    assert!(
        call_error.is_none()
            && finish.status.error.is_none()
            && finish.status.detached
            && !finish.status.unexported
    );
    assert_eq!(finish.status.totals, Some(summary.totals));
    assert_eq!(summary.totals.physical, calls);
    assert_eq!(sink.physical, calls);
    assert_eq!(sink.fast, summary.totals.bypassed);
    assert_eq!(sink.slow, summary.totals.observed.returns);
    assert_eq!(sink.owners.iter().sum::<u64>(), sink.slow);
    assert_eq!(sink.fast + sink.slow, calls);
    assert_eq!(sink.owners[0], summary.totals.observed.completed);
    assert_eq!(
        sink.owners[1..].iter().sum::<u64>(),
        summary.totals.observed.unsampled
    );
    assert_eq!(sink.records, summary.totals.observed.completed);
    assert_eq!(sink.reports, summary.reports);
    assert_eq!(sink.actions, summary.actions);
    assert_eq!(sink.histories, summary.history_batches);
    assert_eq!(sink.disabled, summary.disabled);
    assert_eq!(sink.exports, summary.accepted_exports);
    assert!(sink.status.is_ok() && sink.unwritten.is_empty());
    assert!(finish.unexported.is_none() && finish.partial_calls.iter().all(Option::is_none));
    let stop_reason = match summary.stop_reason {
        api::StopReason::Requested => "requested",
        api::StopReason::EpochLimit => "epoch-limit",
    };
    let ns =
        |t: Option<Duration>| t.map_or_else(|| "none".to_string(), |d| d.as_nanos().to_string());
    let transport = if wait { "bounded-wait" } else { "immediate" };
    println!(
        "optional-backoff-work COMPLETE originals={} k={k} calls={calls} fast={} slow={} sampled={} unsampled={} arms={} reports={} disabled={} actions={} history_batches={} call_batches={} max_entry_prefix={} epoch_limit={epochs} call_limit={limit} stop_reason={stop_reason} max_arm_late_ns={} stop_ack_ns={} removed_ns={} controller_done_ns={} accepted_exports={} written_exports={} written_bytes={} worker_detached=true actual_threads_joined=3 export_synced=true result_input_rsp_checked=true worker_backpressure={transport} scope=finite-functional-raw-uncalibrated post_disable_rearm_coverage=not-qualified",
        LENGTHS.len(),
        sink.fast,
        sink.slow,
        summary.totals.observed.completed,
        summary.totals.observed.unsampled,
        summary.arms,
        summary.reports,
        summary.disabled,
        summary.actions,
        summary.history_batches,
        summary.call_batches,
        sink.max_entry_prefix,
        summary.max_arm_lateness.as_nanos(),
        ns(summary.stop_acknowledged),
        ns(summary.removal_completed),
        ns(summary.controller_completed),
        summary.accepted_exports,
        sink.exports,
        sink.written
    );
}
