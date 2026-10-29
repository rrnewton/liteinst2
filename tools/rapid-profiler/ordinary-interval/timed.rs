//! Three bounded autonomous windows; raw endpoints are not calibrated time.
use super::*;
use rapid_profiler::frontend::{ActionKind, ControllerStatus};
use std::sync::OnceLock;
#[path = "timed/check.rs"]
mod check;
use super::exact::truth;
use check::{Call, Expected, Transition};

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
fn until(target: Instant, deadline: Instant) {
    loop {
        let now = Instant::now();
        assert!(
            now < deadline,
            "timed schedule exceeded its 2-second deadline"
        );
        if now >= target {
            return;
        }
        thread::sleep(target.duration_since(now));
    }
}

pub(super) fn run(candidate: &Path, expected: &Path) {
    single_main();
    let [worker_cpu, controller_cpu] = two_cpus();
    let bytes = expected_file(candidate, expected);
    // SAFETY: trusted exact DSO; sole source owner, readonly scalar ABI, no CET,
    // external entry, constructors, signal/nonlocal exit, fork, unload or writer.
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
    let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
    assert_eq!(prep.role_pcs().collect::<Vec<_>>(), [entry, ret]);
    let expected_input = guarded();
    let input = Arc::new(expected_input);
    let labels =
        std::array::from_fn::<_, 24, _>(|i| (i as u64 + 1000, if i % 2 == 0 { 1 } else { 64 }));
    let values = labels.map(|(_, n)| truth::checksum(&input[16..16 + n]).unwrap());
    let original_stack = stack();
    for (i, (_, n)) in labels.iter().copied().enumerate() {
        let slice = &input[16..16 + n];
        // SAFETY: full prepublication owner checks and the bounded nonempty ABI.
        let call = unsafe { prep.invoke_original(slice.as_ptr(), n, &original_stack) }.unwrap();
        assert_eq!(call.value, values[i]);
        assert_eq!(call.pre_call_rsp, call.resumed_rsp);
        assert_eq!(*input, expected_input);
        let walked = truth::interpret(
            &truth::BYTES,
            slice,
            entry,
            slice.as_ptr() as usize as u64,
            call.pre_call_rsp - 8,
            prep.gate().continuation(),
        )
        .unwrap();
        assert_eq!(walked.value, call.value);
        assert_eq!(walked.steps.len(), truth::counts(n).unwrap().0);
        assert_eq!(walked.resumed_rsp, call.resumed_rsp);
    }
    let site = publish(prep);
    let mut prepared = PreparedIntervalController::new(
        site,
        0x7469_6d01,
        FUNCTION,
        Limits {
            epochs: 3,
            threads: 1,
            depth: 1,
            records_per_epoch: 32,
            actions: 6,
        },
    )
    .unwrap();
    let epochs = std::array::from_fn::<_, 3, _>(|_| {
        prepared
            .stage(Config {
                retained_per_function: 32,
                max_inflight: 1,
                max_invocations: 32,
            })
            .unwrap()
    });
    let generations = epochs.each_ref().map(|e| e.generation().get());
    assert_eq!(
        generations,
        [1, 2, 3],
        "fresh process generation population"
    );
    let expected = Expected {
        generations,
        values,
        entry,
        ret,
    };
    // SAFETY: pristine activation after sole-thread publication. Controller
    // operations never depend on callbacks; no application mutex surrounds calls.
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (start_tx, start_rx) = mpsc::sync_channel(1);
    let clock = Arc::new(OnceLock::<(Instant, Instant)>::new());
    let worker_clock = Arc::clone(&clock);
    let worker_input = Arc::clone(&input);
    let handle = joined_task::spawn(move || {
        // Parent has not narrowed affinity yet; this child inherited the full set.
        pin(Some(worker_cpu));
        // SAFETY: installed immutable site; this one worker alone invokes it.
        let mut attached =
            unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }.unwrap();
        ready_tx.send(()).unwrap();
        start_rx.recv_timeout(WAIT).unwrap();
        let (origin, base) = *worker_clock.get().unwrap();
        let deadline = base + WAIT;
        let offsets = [2, 7, 12, 17, 22, 27, 32, 37];
        let mut calls: Vec<Call> = Vec::with_capacity(24);
        for (i, (external_id, length)) in labels.into_iter().enumerate() {
            until(
                base + Duration::from_millis(40 * (i / 8) as u64 + offsets[i % 8]),
                deadline,
            );
            let before_rows = attached.raw_intervals().unwrap();
            assert_eq!(before_rows, calls.iter().map(|c| c.raw).collect::<Vec<_>>());
            let before = Instant::now();
            // SAFETY: live immutable guarded input and the exact installed ABI;
            // no callback allocation hooks/controller reentry or external caller.
            let call =
                unsafe { attached.invoke_integer_leaf(&worker_input[16..16 + length]) }.unwrap();
            let after = Instant::now();
            assert!(after < deadline, "call exceeded timed trial deadline");
            let rows = attached.raw_intervals().unwrap();
            assert_eq!(rows.len(), i + 1);
            assert_eq!(&rows[..i], before_rows.as_slice());
            assert_eq!(call.value, values[i]);
            assert_eq!(*worker_input, expected_input);
            calls.push(Call {
                external_id,
                length,
                raw: rows[i],
                call,
                before: ns(origin, before),
                after: ns(origin, after),
            });
        }
        let totals = attached.totals().unwrap();
        assert_eq!(
            attached.raw_intervals().unwrap(),
            calls.iter().map(|c| c.raw).collect::<Vec<_>>()
        );
        assert_eq!(attached.detach().unwrap(), totals);
        (calls, totals)
    });
    let mut worker = Worker {
        resume: Some(start_tx),
        handle: Some(handle),
    };
    pin(Some(controller_cpu));
    ready_rx.recv_timeout(WAIT).unwrap();
    let origin = Instant::now();
    let before = Instant::now();
    controller.arm(&epochs[0]).unwrap();
    let base = Instant::now();
    let mut transitions = Vec::with_capacity(6);
    transitions.push(Transition {
        index: 0,
        generation: generations[0],
        requested: 0,
        before: ns(origin, before),
        after: ns(origin, base),
    });
    clock.set((origin, base)).unwrap();
    worker.resume.take().unwrap().send(()).unwrap();
    for (index, milliseconds) in [(1, 30), (2, 40), (3, 70), (4, 80), (5, 110)] {
        let target = base + Duration::from_millis(milliseconds);
        until(target, base + WAIT);
        let before = Instant::now();
        if index % 2 == 0 {
            controller.arm(&epochs[index / 2]).unwrap();
        } else {
            controller.disarm(&epochs[index / 2]).unwrap();
        }
        let after = Instant::now();
        assert!(after < base + WAIT);
        transitions.push(Transition {
            index,
            generation: generations[index / 2],
            requested: ns(origin, target),
            before: ns(origin, before),
            after: ns(origin, after),
        });
    }
    until(base + Duration::from_millis(120), base + WAIT);
    let windowend = ns(origin, Instant::now());
    let (calls, totals) = worker.join();
    assert_eq!(*input, expected_input);
    assert_eq!(Arc::strong_count(&input), 1);
    single_main();
    let history = controller.history().unwrap();
    assert_eq!(history.status, ControllerStatus::Ready);
    assert_eq!(history.current, None);
    assert_eq!(history.retained_failed_generation, None);
    assert_eq!(history.enabled, [true]); // Mandatory native entry/RET controls stay active.
    assert_eq!(history.actions.len(), 6);
    for (index, action) in history.actions.iter().enumerate() {
        let generation = epochs[index / 2].generation();
        assert_eq!(
            action.kind,
            if index % 2 == 0 {
                ActionKind::Published
            } else {
                ActionKind::Removed
            }
        );
        assert_eq!(action.generation, generation);
        assert_eq!(
            action.current,
            if index % 2 == 0 {
                Some(generation)
            } else {
                None
            }
        );
        assert_eq!((action.function, action.group), (None, None));
    }
    let reports = epochs
        .each_ref()
        .map(|e| controller.report(e).unwrap().expect("closed drained epoch"));
    let records = reports.each_ref().map(|r| r.records().collect::<Vec<_>>());
    for (report, generation) in reports.iter().zip(generations) {
        assert_eq!(report.generation().get(), generation);
    }
    // Emit actual complete observations before coverage checks. A failed
    // schedule retains these tables, but never receives the PASS terminal.
    println!("# transitions");
    println!("action,index,generation,requested_ns,before_ns,after_ns");
    for t in &transitions {
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
    println!("# calls");
    println!(
        "external_id,ordinal,length,owner,generation,invocation,before_ns,after_ns,value,pre_rsp,entry_rsp,resumed_rsp,start_ticks,end_ticks,start_aux,end_aux,entry_pc,return_pc"
    );
    for c in &calls {
        let (owner, generation, invocation) = match c.raw.owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation,
            } => ("sampled", generation, invocation.to_string()),
            RawIntervalOwner::Removed { generation } => ("removed", generation, String::new()),
            _ => panic!("unexpected timed owner"),
        };
        println!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            c.external_id,
            c.raw.ordinal,
            c.length,
            owner,
            generation,
            invocation,
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
    println!("# reports");
    println!("generation,invocation,thread,start_sequence,entry_ticks,end_ticks,rank,children");
    for rows in &records {
        for r in rows {
            let payload = r.payload.expect("drained payload");
            let Some(Terminal::Completed {
                disposition: Disposition::Retained { rank },
                ..
            }) = r.record.terminal
            else {
                panic!("timed report terminal");
            };
            let PayloadOutcome::Completed {
                end: Observation::Value(end),
                completed_children,
            } = payload.outcome
            else {
                panic!("timed report observation");
            };
            println!(
                "{},{},{},{},{},{},{},{}",
                r.record.admission.generation.get(),
                r.record.admission.invocation,
                payload.thread,
                payload.start_sequence,
                r.record.admission.entry_value,
                end,
                rank,
                completed_children
            );
        }
    }
    let (sampled, unsampled) =
        check::calls(&transitions, &calls, totals, windowend, &expected).unwrap();
    check::reports(&calls, &records, &expected).unwrap();
    println!(
        "timed-work PASS originals=24 calls=24 entries=24 returns=24 sampled={sampled} unsampled={unsampled} epochs=3 actions=6 raw_rows=24 reports={sampled} active_coverage=3 off_coverage=3 windowend_ns={windowend} worker_cpu={worker_cpu} controller_cpu={controller_cpu} input_unchanged=true joined=true"
    );
}
