//! Segmented ordinary-call timing with complete independent functional evidence.
//! Setup and encoding are separate; service includes all postflight/checkpoints.
//! No back-off, controller thread, subtraction, rate or accuracy qualification.
use super::*;

const TOTAL_OUTPUT_BYTES: usize = OUTPUT_BYTES + 16 * 1024;
const _: () = assert!(TOTAL_OUTPUT_BYTES == 806_912 && TOTAL_OUTPUT_BYTES < 1024 * 1024);
const TIMING_SCOPE: &str = "# normal throughput v1; segmented call-path and validated service elapsed wall nanoseconds; no subtraction, accuracy, or continuous-throughput claim";
const TIMING_HEADER: &str = "kind,index,start_ns,end_ns";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Span {
    pub(super) start: u64,
    pub(super) end: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TimingError {
    Domain,
    Overflow,
    Population,
    Order,
    Service,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Timing {
    pub(super) setup: u64,
    pub(super) body: u64,
    pub(super) service: u64,
}
pub(super) fn nanoseconds(seconds: i64, nanos: i64) -> Result<u64, TimingError> {
    let seconds = u64::try_from(seconds).map_err(|_| TimingError::Domain)?;
    let nanos = u64::try_from(nanos).map_err(|_| TimingError::Domain)?;
    if nanos >= 1_000_000_000 {
        return Err(TimingError::Domain);
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|whole| whole.checked_add(nanos))
        .ok_or(TimingError::Overflow)
}
pub(super) fn now() -> u64 {
    let mut stamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: one writable timespec; this reads no subject or SDK state.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut stamp) },
        0
    );
    nanoseconds(stamp.tv_sec, stamp.tv_nsec).expect("CLOCK_MONOTONIC_RAW nanoseconds")
}
fn elapsed(span: Span) -> Result<u64, TimingError> {
    span.end.checked_sub(span.start).ok_or(TimingError::Order)
}
pub(super) fn validate_timing(
    setup: Span,
    bodies: &[Span],
    service: Span,
) -> Result<Timing, TimingError> {
    if bodies.len() != BLOCKS {
        return Err(TimingError::Population);
    }
    let setup_ns = elapsed(setup)?;
    let service_ns = elapsed(service)?;
    if setup.end > bodies[0].start || service.start != bodies[0].start {
        return Err(TimingError::Service);
    }
    let mut previous = setup.end;
    let mut sum = 0_u64;
    for &body in bodies {
        if body.start < previous {
            return Err(TimingError::Order);
        }
        sum = sum
            .checked_add(elapsed(body)?)
            .ok_or(TimingError::Overflow)?;
        previous = body.end;
    }
    if previous > service.end || sum > service_ns {
        return Err(TimingError::Service);
    }
    Ok(Timing {
        setup: setup_ns,
        body: sum,
        service: service_ns,
    })
}
fn returned_population(rows: &[Returned], sums: &[u64]) -> Check {
    require(population(rows) && sums.len() == PAIRS, Error::Population)?;
    require(
        sums.iter().enumerate().all(|(p, &sum)| {
            let expected = case(2 * p).value;
            sum == expected.wrapping_add(expected)
        }),
        Error::Population,
    )
}
fn append_timing(
    output: &mut String,
    mode: Mode,
    cpu: usize,
    setup: Span,
    bodies: &[Span],
    service: Span,
    timing: Timing,
) {
    assert_eq!(validate_timing(setup, bodies, service), Ok(timing));
    assert!(cpu < libc::CPU_SETSIZE as usize);
    writeln!(output, "{TIMING_SCOPE}\n{TIMING_HEADER}").unwrap();
    writeln!(output, "setup,0,{},{}", setup.start, setup.end).unwrap();
    for (index, body) in bodies.iter().enumerate() {
        writeln!(output, "body,{},{},{}", index + 1, body.start, body.end).unwrap();
    }
    writeln!(output, "service,0,{},{}", service.start, service.end).unwrap();
    writeln!(output, "normal-observer-throughput TIMING_COMPLETE mode={} cpu={cpu} clock=CLOCK_MONOTONIC_RAW units=ns timing_rows=130 setup_ns={} body_ns={} service_ns={}",
             mode.name(), timing.setup, timing.body, timing.service).unwrap();
}

pub(crate) fn run(args: &[std::ffi::OsString]) {
    assert_eq!(
        args.len(),
        7,
        "normal-observer-throughput MODE CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL"
    );
    let mode = Mode::parse(args[0].to_str().unwrap()).expect("native or always-on");
    let candidate = Path::new(&args[1]);
    let trusted = Path::new(&args[2]);
    let elf_va = strnlen::number(args[3].to_str().unwrap());
    assert_eq!(strnlen::number(args[4].to_str().unwrap()), 37);
    let caller_candidate = Path::new(&args[5]);
    let caller_trusted = Path::new(&args[6]);
    single_main();
    let cpu = pin(None);
    let setup_start = now();
    let subject = expected_file(candidate, trusted);
    let helper = expected_file(caller_candidate, caller_trusted);
    // SAFETY: independently authenticated complete trusted ELFs and immutable
    // sources; sole actual main caller, no signals, writer, CET, fork, unload,
    // nonlocal exit or reentry. Requests retain all readable input for all calls.
    let mut calling = unsafe { CallerOwner::load(caller_candidate, &helper) }.unwrap();
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
    let caller = calling.entry();
    let mut original = Some(owner);
    let readable = stack();
    let stack = stack_bounds();
    let mut custody = Custody {
        candidate,
        trusted,
        subject: &subject,
        caller_candidate,
        caller_trusted,
        helper: &helper,
        cpu,
        stack,
        spans: vec![
            (
                original.as_ref().unwrap().source_range().0,
                original.as_ref().unwrap().original_source().to_vec(),
            ),
            (calling.source().0, calling.source().1.to_vec()),
        ],
    };
    let mut data = Data::new();
    let mut sums = vec![0_u64; PAIRS].into_boxed_slice();
    let mut bodies = [Span::default(); BLOCKS];
    let mut returned = Vec::with_capacity(CALLS);
    let mut batches = Vec::with_capacity(if mode == Mode::AlwaysOn { BLOCKS } else { 0 });
    let mut state = if mode == Mode::AlwaysOn {
        original.as_mut().unwrap().verify_original().unwrap();
        let prep =
            NormalSitePreparation::new_whole_function(original.take().unwrap(), identity(entry))
                .unwrap();
        assert_eq!(prep.role_pcs().collect::<Vec<_>>(), [entry, entry + 36]);
        custody.spans = prep
            .plan()
            .plan()
            .final_bytes()
            .iter()
            .map(|s| (s.address, s.bytes.clone()))
            .collect();
        custody.spans.extend(
            prep.plan()
                .images()
                .iter()
                .map(|i| (i.address(), i.bytes().to_vec())),
        );
        custody
            .spans
            .push((calling.source().0, calling.source().1.to_vec()));
        let site = publish(prep);
        let mut prepared = PreparedNormalController::new(
            site,
            INSTALL,
            FUNCTION,
            Limits {
                epochs: 1,
                threads: 1,
                depth: 1,
                records_per_epoch: CALLS,
                actions: 2,
            },
        )
        .unwrap();
        let epoch = prepared.stage(CONFIG).unwrap();
        let generation = epoch.generation().get();
        let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
        controller.arm(&epoch).unwrap();
        let attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
        assert_eq!(attached.totals().unwrap(), NormalTotals::default());
        Some((controller, client, epoch, attached, generation))
    } else {
        None
    };
    // All live controller/attachment/input/code owners precede this guard.
    // Failed checks abort before their teardown; no failure manufactures a
    // checkpoint or successful detach. Setup failures above precede all calls.
    let mut fail_stop = FailStop(true);
    custody.check(&mut calling);
    if let Some(owner) = original.as_mut() {
        owner.verify_original().unwrap();
    }
    let e = Expected {
        pid: std::process::id(),
        tid: u64::from(std::process::id()),
        entry,
        caller,
        generation: state.as_ref().map_or(0, |s| s.4),
        stack,
    };
    let setup_end = now();
    for (b, body) in bodies.iter_mut().enumerate() {
        let first = b * BLOCK / 2;
        let last = first + BLOCK / 2;
        for p in first..last {
            data.check(p, false);
        }
        unsafe { immutable(&custody.spans) };
        body.start = now();
        for (p, sum) in sums.iter_mut().enumerate().take(last).skip(first) {
            // SAFETY: exact retained subject/helper and disjoint complete inputs,
            // requests/results, real main stack and normal returns. invoke keeps
            // its PID/target/sum checks; those checks are included in body time.
            *sum = unsafe { calling.invoke(entry, &data.requests[p], &mut data.results[p].values) };
        }
        body.end = now();
        // All independent validation is outside the body subtotal, but remains
        // in the unsubtracted service envelope and before unsafe checkpoint.
        for (p, &sum) in sums.iter().enumerate().take(last).skip(first) {
            data.check(p, true);
            let c = case(2 * p);
            assert_eq!(sum, c.value.wrapping_add(c.value));
            for (j, &value) in data.results[p].values.iter().enumerate() {
                returned.push(Returned {
                    id: (2 * p + j + 1) as u64,
                    value,
                });
            }
        }
        let n = ((b + 1) * BLOCK) as u64;
        if let Some((_, _, _, attached, _)) = state.as_ref() {
            assert_eq!(attached.totals().unwrap(), pending(n));
        }
        custody.check(&mut calling);
        assert_eq!(*data.inputs, [input(0), input(1)]);
        if let Some(owner) = original.as_mut() {
            owner.verify_original().unwrap();
        }
        if let Some((_, _, _, attached, _)) = state.as_mut() {
            // SAFETY: every actual helper call returned on this same attached
            // thread. Full guarded-input/source/image/stack/CPU postflight above
            // precedes confirmation of the last pending pre-RET receipt.
            let observed = unsafe { attached.checkpoint_after_returns() }
                .unwrap()
                .expect("24 returned calls");
            assert_eq!(attached.totals().unwrap(), complete(n));
            batch(
                e,
                batches.len(),
                Metadata::from_batch(&observed),
                observed.records(),
                observed.journal(),
            )
            .unwrap();
            batches.push(observed);
        }
    }
    returned_population(&returned, &sums).unwrap();
    for p in 0..PAIRS {
        data.check(p, true);
    }
    custody.check(&mut calling);
    if let Some(owner) = original.as_mut() {
        owner.verify_original().unwrap();
    }
    if let Some((controller, _, epoch, attached, _)) = state.as_mut() {
        assert_eq!(batches.len(), BLOCKS);
        assert_eq!(attached.totals().unwrap(), complete(CALLS as u64));
        assert!(
            unsafe { attached.checkpoint_after_returns() }
                .unwrap()
                .is_none()
        );
        assert_eq!(attached.detach().unwrap(), complete(CALLS as u64));
        controller.disarm(epoch).unwrap();
        let observed = controller
            .report(epoch)
            .unwrap()
            .expect("all3072 retained calls");
        let history = controller.history().unwrap();
        let mut rows = Vec::with_capacity(CALLS);
        for (b, observed) in batches.iter().enumerate() {
            batch(
                e,
                b,
                Metadata::from_batch(observed),
                observed.records(),
                observed.journal(),
            )
            .unwrap();
            rows.extend_from_slice(observed.records());
        }
        report(
            e,
            &rows,
            observed.generation().get(),
            &observed.records().collect::<Vec<_>>(),
            &history,
        )
        .unwrap();
    } else {
        assert!(batches.is_empty());
    }
    custody.check(&mut calling);
    // Only after final population/results/custody and installed empty checkpoint,
    // detach/disarm/complete Report/history validation. Encoding is not timed.
    let service_end = now();
    let setup = Span {
        start: setup_start,
        end: setup_end,
    };
    let service = Span {
        start: bodies[0].start,
        end: service_end,
    };
    let timing = validate_timing(setup, &bodies, service).unwrap();
    let mut output = String::with_capacity(TOTAL_OUTPUT_BYTES);
    writeln!(output, "{SCOPE}\n{HEADER}").unwrap();
    for (g, r) in returned.iter().enumerate() {
        let record = (mode == Mode::AlwaysOn).then(|| &batches[g / BLOCK].records()[g % BLOCK]);
        let line = row(g, *r, record);
        assert!(line.len() < ROW_BYTES);
        writeln!(output, "{line}").unwrap();
    }
    writeln!(output, "{}", terminal(mode, e)).unwrap();
    assert!(output.is_ascii() && output.len() <= OUTPUT_BYTES && OUTPUT_BYTES < 1024 * 1024);
    // Exact old 3,075-line functional prefix above; a separate timing appendix.
    append_timing(&mut output, mode, cpu, setup, &bodies, service, timing);
    assert!(output.is_ascii() && output.len() <= TOTAL_OUTPUT_BYTES);
    std::io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .unwrap();
    fail_stop.0 = false;
}

#[cfg(test)]
mod tests;
