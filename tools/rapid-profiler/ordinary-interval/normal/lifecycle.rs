//! Actual public attachment abandonment, including the calling thread's TLS exit.
use super::*;
use rapid_profiler::frontend_native::{BridgeError, IntervalController, IntervalEpoch};
use std::path::PathBuf;

pub(super) struct Inputs {
    pub cpu: usize,
    pub entry: u64,
    pub caller_entry: u64,
    pub caller_path: PathBuf,
    pub caller_bytes: Vec<u8>,
    pub input: Arc<[[u8; 96]; 8]>,
    pub expected_input: [[u8; 96]; 8],
    pub spans: Arc<Vec<(u64, Vec<u8>)>>,
    pub originals: [u64; 8],
}

fn pending() -> NormalTotals {
    NormalTotals {
        entered: 2,
        ret_observed: 2,
        confirmed: 1,
        completed: 1,
        unsampled: 0,
    }
}
fn epoch_limit(controller: &mut IntervalController, config: Config) {
    let error = controller
        .stage(config)
        .err()
        .expect("pending owner retained");
    // BridgeError intentionally keeps model causes opaque to API consumers.
    // Match the complete diagnostic; an unrelated error cannot pass this check.
    assert_eq!(
        format!("{error:?}"),
        "BridgeError { cause: Setup(EpochLimit) }"
    );
}
fn attachment_refused(error: BridgeError) {
    assert_eq!(format!("{error:?}"), "BridgeError { cause: Attachment }");
}
fn sampled_pending(controller: &IntervalController, epoch: &IntervalEpoch) {
    assert!(
        controller.report(epoch).unwrap().is_none(),
        "pending sampled frame must not be completed or cancelled by Drop/TLS exit"
    );
}
fn completed_report(report: &Report, generation: u64) {
    assert_eq!(report.generation().get(), generation);
    let records: Vec<_> = report.records().collect();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    let admission = record.record.admission;
    assert_eq!(admission.generation.get(), generation);
    assert_eq!(admission.function, FUNCTION);
    assert_eq!(admission.invocation, 0);
    assert_eq!(
        record.record.terminal,
        Some(Terminal::Completed {
            value: 0,
            disposition: Disposition::Retained { rank: 0 },
        })
    );
    let payload = record.payload.unwrap();
    assert_eq!(payload.admission, admission);
    assert_eq!(payload.thread, 1);
    assert_eq!(payload.start_sequence, 0);
    match payload.outcome {
        PayloadOutcome::Completed {
            end: Observation::Value(end),
            completed_children: 0,
        } => {
            assert!(end >= admission.entry_value);
        }
        outcome => panic!("wrong actual completed payload: {outcome:?}"),
    }
}

pub(super) fn run(
    mut prepared: PreparedNormalController,
    mode: Mode,
    calling: &mut CallerOwner,
    inputs: Inputs,
) {
    assert!(mode != Mode::Work);
    let config = Config {
        retained_per_function: if mode == Mode::DropClosed { 1 } else { 2 },
        max_inflight: 1,
        max_invocations: 8,
    };
    let epoch = prepared.stage(config).unwrap();
    let generation = epoch.generation().get();
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    controller.arm(&epoch).unwrap();
    let (park_tx, park_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let worker_input = Arc::clone(&inputs.input);
    let worker_spans = Arc::clone(&inputs.spans);
    let handle = joined_task::spawn(move || {
        pin(Some(inputs.cpu));
        let mut caller =
            unsafe { CallerOwner::load(&inputs.caller_path, &inputs.caller_bytes) }.unwrap();
        assert_eq!(caller.entry(), inputs.caller_entry);
        let attached = unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }.unwrap();
        let requests = requests(&worker_input, 3);
        let mut results = [u64::MAX; 2];
        let sum = unsafe { caller.invoke(inputs.entry, &requests, &mut results) };
        assert_eq!(results, [inputs.originals[6], inputs.originals[7]]);
        assert_eq!(sum, results[0] + results[1]);
        assert_eq!(*worker_input, inputs.expected_input);
        caller.verify().unwrap();
        unsafe { immutable(&worker_spans) };
        assert_eq!(attached.totals().unwrap(), pending());
        park_tx.send(pending()).unwrap();
        resume_rx
            .recv_timeout(WAIT)
            .expect("abandonment controller handshake");
        // Both actual calls returned, but there is deliberately no checkpoint.
        // This public safe Drop must retain the last receipt, not cancel it.
        drop(attached);
        let error = unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }
            .err()
            .expect("lost handle must poison this TLS attachment");
        attachment_refused(error);
        assert_eq!(*worker_input, inputs.expected_input);
        caller.verify().unwrap();
        unsafe { immutable(&worker_spans) };
        results
    });
    let mut worker = Worker {
        resume: Some(resume_tx),
        handle: Some(handle),
    };
    assert_eq!(park_rx.recv_timeout(WAIT).unwrap(), pending());
    controller.disarm(&epoch).unwrap();
    if mode == Mode::DropClosed {
        // K=1 completed at the second entry. The second, FunctionClosed receipt
        // still retains its epoch even after controller/report ownership ends.
        let report = controller.retire(&epoch).unwrap();
        completed_report(&report, generation);
        drop(report);
        epoch_limit(&mut controller, config);
    } else {
        sampled_pending(&controller, &epoch);
    }
    worker.resume.as_ref().unwrap().send(()).unwrap();
    assert_eq!(worker.join(), [inputs.originals[6], inputs.originals[7]]);
    assert_eq!(
        Arc::strong_count(&inputs.input),
        1,
        "actual TLS worker joined"
    );
    assert_eq!(Arc::strong_count(&inputs.spans), 1);
    assert_eq!(*inputs.input, inputs.expected_input);
    calling.verify().unwrap();
    unsafe { immutable(&inputs.spans) };
    if mode == Mode::DropClosed {
        epoch_limit(&mut controller, config);
    } else {
        sampled_pending(&controller, &epoch);
    }
    let history = controller.history().unwrap();
    assert_eq!(history.current, None);
    assert_eq!(history.enabled, [true]);
    assert_eq!(history.actions.len(), 2);
    for (i, action) in history.actions.iter().enumerate() {
        assert_eq!(action.generation.get(), generation);
        assert_eq!(
            action.current.map(|g| g.get()),
            (i == 0).then_some(generation)
        );
        assert_eq!(
            action.kind,
            if i == 0 {
                rapid_profiler::frontend::ActionKind::Published
            } else {
                rapid_profiler::frontend::ActionKind::Removed
            }
        );
        assert_eq!(action.function, None);
        assert_eq!(action.group, None);
    }
    single_main();
    println!(
        "normal-drop complete owner={} original_calls=8 installed_calls=2 entered=2 ret_observed=2 confirmed=1 completed=1 unsampled=0 checkpoints=0 reattach_refusals=1 pending_after_tls_exit=1 worker_joins=1",
        if mode == Mode::DropClosed {
            "function-closed"
        } else {
            "sampled"
        }
    );
}
