//! One fresh serial population; timing endpoints are observations, not truth.
use super::*;
#[path = "../exact-work/join.rs"]
mod join;
#[path = "../exact-work/truth.rs"]
mod truth;

pub(super) fn run(candidate: &Path, expected: &Path, name: &str, retained: usize) {
    let (schedule, schedule_id) = match name {
        "short" => (join::Schedule::AllShort, 0),
        "long" => (join::Schedule::AllLong, 1),
        "alternating" => (join::Schedule::Alternating, 2),
        "late-long" => (join::Schedule::TenShortThenLong, 3),
        _ => panic!("unknown exact-work schedule"),
    };
    assert!(matches!(retained, 24 | 1 | 10));
    single_main();
    let cpu = pin(None);
    let bytes = expected_file(candidate, expected);
    // SAFETY: exact trusted fixture DSO, immutable readonly scalar nonempty ABI;
    // no constructors, external entries, CET, signal/unwind, fork or unload.
    let owner =
        unsafe { LoadedIntegerLeaf::load(candidate, &bytes, c"exact_work_nonempty", CONTRACT) }
            .unwrap();
    truth::check_bytes(owner.code()).unwrap();
    let entry = owner.entry();
    let return_pc = entry.checked_add(36).unwrap();
    assert_eq!(
        owner.certificate().range(),
        (entry, entry + truth::BYTES.len() as u64)
    );
    assert_eq!(owner.certificate().returns(), [return_pc]);
    assert_eq!(
        owner.certificate().heads(),
        truth::HEADS.map(|o| entry + u64::from(o))
    );
    let gate = CallGate::new(owner.certificate()).unwrap();
    let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
    assert_eq!(prep.role_pcs().collect::<Vec<_>>(), [entry, return_pc]);
    let expected_input = guarded();
    let input = Arc::new(expected_input);
    let lengths = schedule.lengths();
    let values = lengths.map(|n| truth::checksum(&expected_input[16..16 + n]).unwrap());
    // IDs and input/work truth exist before original or instrumented invocation.
    let ids = std::array::from_fn(|i| (schedule_id * 10000 + retained * 100 + i) as u64);
    let original_stack = stack();
    for (index, length) in lengths.into_iter().enumerate() {
        let slice = &input[16..16 + length];
        let result =
            unsafe { prep.invoke_original(slice.as_ptr(), slice.len(), &original_stack) }.unwrap();
        assert_eq!(result.value, values[index]);
        assert_eq!(result.pre_call_rsp, result.resumed_rsp);
        assert_eq!(*input, expected_input);
        // This work model supplies no time. Its native ordered trace is a
        // separate mandatory stage of the reproducer, not this direct call.
        let model = truth::interpret(
            &truth::BYTES,
            slice,
            entry,
            slice.as_ptr() as usize as u64,
            result.pre_call_rsp - 8,
            prep.gate().continuation(),
        )
        .unwrap();
        assert_eq!(model.value, result.value);
        assert_eq!(model.steps.len(), truth::counts(length).unwrap().0);
        assert_eq!(model.resumed_rsp, result.resumed_rsp);
    }
    let site = publish(prep);
    let mut prepared = PreparedIntervalController::new(
        site,
        0x6578_6101,
        FUNCTION,
        Limits {
            epochs: 1,
            threads: 1,
            depth: 1,
            records_per_epoch: join::CALLS,
            actions: 2,
        },
    )
    .unwrap();
    let epoch = prepared
        .stage(Config {
            retained_per_function: retained,
            max_inflight: 1,
            max_invocations: join::CALLS,
        })
        .unwrap();
    let mut trial = join::Trial::new(join::TrialConfig {
        schedule,
        retained,
        external_ids: ids,
        expected_values: values,
        generation: epoch.generation(),
        function: FUNCTION,
        thread: 1,
        entry_pc: entry,
        return_pc,
    })
    .unwrap();
    // SAFETY: completed single-thread publication; no TLS clients yet.
    let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
    controller.arm(&epoch).unwrap();
    let worker_input = Arc::clone(&input);
    let handle = thread::spawn(move || {
        pin(Some(cpu));
        let mut attached =
            unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }.unwrap();
        for label in trial.labels() {
            let before = attached.raw_intervals().unwrap();
            let pending = trial.begin(label, &before).unwrap();
            let slice = &worker_input[16..16 + label.length];
            // Exactly one synchronous call between the preassigned label and
            // its new raw row. Input stays live until this worker is joined.
            let call = unsafe { attached.invoke_integer_leaf(slice) }.unwrap();
            let after = attached.raw_intervals().unwrap();
            pending.finish(&after, call).unwrap();
            assert_eq!(*worker_input, expected_input);
        }
        let totals = attached.totals().unwrap();
        let rows = attached.raw_intervals().unwrap();
        assert_eq!(attached.detach().unwrap(), totals);
        (trial, rows, totals)
    });
    let mut worker = Worker {
        resume: None,
        handle: Some(handle),
    };
    let (trial, rows, totals) = worker.join();
    assert_eq!(*input, expected_input);
    assert_eq!(Arc::strong_count(&input), 1);
    controller.disarm(&epoch).unwrap();
    let report = controller
        .report(&epoch)
        .unwrap()
        .expect("drained exact-work owner");
    let summary = trial.validate(&rows, totals, &report).unwrap();
    pin(Some(cpu));
    single_main();
    println!(
        "# exact original work from authenticated fixed assembly; uncalibrated raw RDTSCP endpoints, no timing accuracy or savings-from-K claim"
    );
    println!(
        "schedule,k,external_id,ordinal,length,owner,generation,invocation,instructions,branches,taken_branches,input_byte_reads,return_read_bytes,value,start_ticks,end_ticks,start_aux,end_aux"
    );
    for call in trial.joined() {
        let (owner, generation, invocation) = match call.raw.owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation,
            } => ("sampled", generation, invocation.to_string()),
            RawIntervalOwner::FunctionClosed { generation } => {
                ("closed", generation, String::new())
            }
            _ => unreachable!("complete trial validation"),
        };
        println!(
            "{name},{retained},{},{},{},{owner},{generation},{invocation},{},{},{},{},{},{},{},{},{},{}",
            call.label.external_id,
            call.raw.ordinal,
            call.label.length,
            call.work.instructions,
            call.work.branches,
            call.work.taken_branches,
            call.work.input_byte_reads,
            call.work.return_read_bytes,
            call.call.value,
            call.raw.start.ticks,
            call.raw.end.ticks,
            call.raw.start.aux,
            call.raw.end.aux
        );
    }
    println!(
        "exact-work PASS calls={} retained={} population_instructions={} retained_instructions={} selection_error_numerator={} selection_error_denominator={} originals=24 raw_rows=24 input_unchanged=true joined=true",
        summary.population_calls,
        summary.retained_calls,
        summary.population.instructions,
        summary.retained.instructions,
        summary.selection_error_numerator,
        summary.selection_error_denominator
    );
}
