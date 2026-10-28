//! Same-thread original/installed CALL enclosures; no accuracy/calibration policy.
use super::super::*;
use super::truth;
use rapid_profiler::frontend_native::{GateProfile, ReferenceLeg};
mod join;

pub(crate) fn run(candidate: &Path, expected: &Path) {
    single_main();
    let cpu = pin(None);
    let tid = u64::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap();
    let bytes = expected_file(candidate, expected);
    // SAFETY: independently pinned trusted exact-work DSO, readonly nonempty
    // ABI, no constructors, external entry/CET/signal/nonlocal exit/fork/unload.
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
    let gate = CallGate::new_reference(owner.certificate()).unwrap();
    assert_eq!(gate.profile(), GateProfile::ReferenceAmdV1);
    let expected_gate = join::Expected {
        gate: Arc::as_ptr(&gate) as usize as u64,
        pid: u64::from(std::process::id()),
        tid,
        target: entry,
        continuation: gate.continuation(),
        return_pc,
    };
    let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
    assert_eq!(prep.role_pcs().collect::<Vec<_>>(), [entry, return_pc]);
    let expected_input = guarded();
    let input = Box::new(expected_input);
    let lengths = super::join::Schedule::Alternating.lengths();
    let values = lengths.map(|n| truth::checksum(&expected_input[16..16 + n]).unwrap());
    // All IDs, lengths, values and descriptor/thread identity precede observation.
    // Both legs share an ID; the explicit leg is part of the external join key.
    let ids = std::array::from_fn(|i| 0x7265_6600 + i as u64);
    let mut originals = join::Originals::new(expected_gate, ids, values).unwrap();
    let readable = stack();
    for label in originals.labels() {
        let slice = &input[16..16 + label.length];
        // SAFETY: single pinned actual thread; original source before publication,
        // complete current stack VMA, stable admitted clock/OS and immutable data.
        let result = unsafe {
            prep.invoke_original_reference(
                slice.as_ptr(),
                slice.len(),
                &readable,
                label.external_id,
            )
        }
        .unwrap();
        let model = truth::interpret(
            &truth::BYTES,
            slice,
            entry,
            slice.as_ptr() as usize as u64,
            result.call.pre_call_rsp.checked_sub(8).unwrap(),
            expected_gate.continuation,
        )
        .unwrap();
        assert_eq!(model.value, result.call.value);
        assert_eq!(model.resumed_rsp, result.call.resumed_rsp);
        assert_eq!(model.steps.len(), truth::counts(label.length).unwrap().0);
        assert_eq!(*input, expected_input);
        originals
            .record(label, result.call, result.reference.into())
            .unwrap();
    }
    pin(Some(cpu));
    single_main();
    // Same actual thread: the unchanged publisher proves full source/allocation
    // exclusion and final RX before attachment. All original calls have returned.
    let site = publish(prep);
    let mut prepared = PreparedIntervalController::new(
        site,
        0x7265_6601,
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
            retained_per_function: join::CALLS,
            max_inflight: 1,
            max_invocations: join::CALLS,
        })
        .unwrap();
    let mut trial = originals
        .installed(epoch.generation(), FUNCTION, 1)
        .unwrap();
    // SAFETY: successful sole-thread publication, no client exists yet.
    let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
    controller.arm(&epoch).unwrap();
    // No worker is spawned: this is the same actual original-calling thread/CPU.
    let mut attached = unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }.unwrap();
    for label in trial.labels() {
        let before = attached.raw_intervals().unwrap();
        let pending = trial.begin(label, &before).unwrap();
        let slice = &input[16..16 + label.length];
        // Exactly one real synchronous call between old join::Pending's prefix
        // and finish. SDK postflight authenticates the physical CALL/RET enclosure.
        let result =
            unsafe { attached.invoke_integer_leaf_reference(slice, label.external_id) }.unwrap();
        let after = attached.raw_intervals().unwrap();
        let model = truth::interpret(
            &truth::BYTES,
            slice,
            entry,
            slice.as_ptr() as usize as u64,
            result.call.entry_rsp,
            expected_gate.continuation,
        )
        .unwrap();
        assert_eq!(model.value, result.call.value);
        assert_eq!(model.resumed_rsp, result.call.resumed_rsp);
        assert_eq!(model.steps.len(), truth::counts(label.length).unwrap().0);
        assert_eq!(*input, expected_input);
        pending
            .finish(&after, result.call, result.reference.into())
            .unwrap();
    }
    let totals = attached.totals().unwrap();
    let rows = attached.raw_intervals().unwrap();
    assert_eq!(attached.detach().unwrap(), totals);
    controller.disarm(&epoch).unwrap();
    let report = controller
        .report(&epoch)
        .unwrap()
        .expect("closed reference owner");
    let summary = trial.validate(&rows, totals, &report).unwrap();
    assert_eq!(summary.population_calls, 24);
    assert_eq!(summary.retained_calls, 24);
    assert_eq!(
        summary.population,
        super::join::Work {
            instructions: 4800,
            branches: 780,
            taken_branches: 756,
            input_byte_reads: 780,
            return_read_bytes: 192,
        }
    );
    assert_eq!(summary.retained, summary.population);
    assert_eq!(summary.selection_error_numerator, 0);
    assert_eq!(trial.originals().count(), 24);
    assert_eq!(trial.joined().count(), 24);
    assert_eq!(*input, expected_input);
    pin(Some(cpu));
    single_main();
    assert_eq!(
        u64::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap(),
        tid
    );
    // Every call returned and attachment is detached before ordinary reclamation.
    drop(input);
    println!(
        "# uncalibrated real-CALL enclosures and hook endpoints; fixed-assembly work model, no timing-accuracy, frequency-conversion or performance claim"
    );
    println!(
        "leg,external_id,gate_sequence,ordinal,length,owner,generation,invocation,instructions,branches,taken_branches,input_byte_reads,return_read_bytes,value,reference_start_ticks,reference_end_ticks,reference_start_aux,reference_end_aux,raw_start_ticks,raw_end_ticks,raw_start_aux,raw_end_aux,enclosure_ticks,raw_ticks,entry_gap_ticks,return_gap_ticks"
    );
    for o in trial.originals() {
        print_row(o.label, o.call.value, o.work, o.reference, None);
    }
    for (call, r) in trial.joined() {
        print_row(
            call.label,
            call.call.value,
            call.work,
            r.reference,
            Some((call.raw, r.gaps)),
        );
    }
    println!(
        "exact-reference FUNCTIONAL_PASS originals=24 installed=24 raw_rows=24 sampled=24 unsampled=0 report_records=24 original_instructions=4800 installed_instructions=4800 same_thread=true detached=true input_unchanged=true uncalibrated=true"
    );
}

fn print_row(
    label: super::join::Label,
    value: u64,
    work: super::join::Work,
    reference: join::Enclosure,
    raw: Option<(RawInterval, join::Gaps)>,
) {
    let mut fields = [const { String::new() }; 26];
    fields[0] = match reference.leg {
        ReferenceLeg::Original => "original",
        ReferenceLeg::Installed => "installed",
    }
    .into();
    fields[1] = label.external_id.to_string();
    fields[2] = reference.sequence.to_string();
    fields[4] = label.length.to_string();
    fields[5] = "original".into();
    for (at, value) in [
        (8, work.instructions),
        (9, work.branches),
        (10, work.taken_branches),
        (11, work.input_byte_reads),
        (12, work.return_read_bytes),
        (13, value),
        (14, reference.start.ticks),
        (15, reference.end.ticks),
        (16, u64::from(reference.start.aux)),
        (17, u64::from(reference.end.aux)),
        (
            22,
            reference
                .end
                .ticks
                .checked_sub(reference.start.ticks)
                .unwrap(),
        ),
    ] {
        fields[at] = value.to_string();
    }
    if let Some((row, gaps)) = raw {
        let RawIntervalOwner::Sampled {
            generation,
            invocation,
        } = row.owner
        else {
            unreachable!("unchanged exact-work K24 join already validated")
        };
        fields[3] = row.ordinal.to_string();
        fields[5] = "sampled".into();
        fields[6] = generation.to_string();
        fields[7] = invocation.to_string();
        for (at, value) in [
            (18, row.start.ticks),
            (19, row.end.ticks),
            (20, u64::from(row.start.aux)),
            (21, u64::from(row.end.aux)),
            (22, gaps.enclosure),
            (23, gaps.raw),
            (24, gaps.entry),
            (25, gaps.exit),
        ] {
            fields[at] = value.to_string();
        }
    }
    println!("{}", fields.join(","));
}
