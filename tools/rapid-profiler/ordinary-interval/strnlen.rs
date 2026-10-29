//! Unchanged FreeBSD strnlen, all eight fixed cases and the complete owner schedule.
use super::*;
use rapid_profiler::frontend_native::{IntervalBatch, TrustedFunctionSelection};

#[path = "../strnlen-work/cases.rs"]
pub mod cases;
mod check {
    crate::consumer_checks::consumer_check!();
}
use cases::{CASES, LABEL};

const INSTALL: u64 = 0x7374_6e01;
const CONFIG: Config = Config {
    retained_per_function: 2,
    max_inflight: 1,
    max_invocations: 8,
};

pub(super) fn number(word: &str) -> u64 {
    let value = word.parse::<u64>().expect("canonical unsigned decimal");
    assert_eq!(value.to_string(), word, "canonical unsigned decimal");
    value
}

pub(super) fn refusals(prestrip: &Path, trusted: &Path, mutated: &Path, elf_va: u64, length: u64) {
    use rapid_profiler::frontend_native::SetupRefusal;
    single_main();
    let bytes = expected_file(prestrip, trusted);
    assert_eq!(expected_file(mutated, trusted), bytes);
    let selection =
        TrustedFunctionSelection::new(&bytes, elf_va, usize::try_from(length).unwrap(), LABEL)
            .unwrap();
    // SAFETY: the wrapper authenticates the independently built final ELF and
    // its complete selected extent. The named parser must reject the localized,
    // stripped name before retaining/loading; both selected candidates differ
    // from the complete trusted final bytes and must fail before dlopen. No
    // candidate code is called, and no live-owner mutation is attempted.
    let named = unsafe { LoadedIntegerLeaf::load(trusted, &bytes, c"strnlen", CONTRACT) };
    assert!(matches!(named, Err(SetupRefusal::SymbolOwner)));
    let wrong_file = unsafe { LoadedIntegerLeaf::load_selected(prestrip, &selection, CONTRACT) };
    assert!(matches!(wrong_file, Err(SetupRefusal::SourceBytes)));
    let changed = unsafe { LoadedIntegerLeaf::load_selected(mutated, &selection, CONTRACT) };
    assert!(matches!(changed, Err(SetupRefusal::SourceBytes)));
    assert_eq!(expected_file(prestrip, trusted), bytes);
    assert_eq!(expected_file(mutated, trusted), bytes);
    single_main();
    println!("case,status,refusal");
    println!("named-final,expected-refusal,SymbolOwner");
    println!("wrong-whole-file,expected-refusal,SourceBytes");
    println!("changed-selected-byte,expected-refusal,SourceBytes");
    println!("strnlen-refusals complete cases=3 expected_refusals=3 subject_calls=0");
}

struct Completed {
    calls: Vec<CallResult>,
    rows: Vec<RawInterval>,
    totals: PairTotals,
    batch: IntervalBatch,
    tid: u64,
}

pub(super) fn run(candidate: &Path, trusted: &Path, elf_va: u64, length: u64) {
    single_main();
    let cpu = pin(None);
    let bytes = expected_file(candidate, trusted);
    let selection =
        TrustedFunctionSelection::new(&bytes, elf_va, usize::try_from(length).unwrap(), LABEL)
            .unwrap();
    // SAFETY: this route accepts only the independently pinned final linked C
    // fixture. Trusted pre-strip metadata supplies the complete selected extent;
    // the wrapper proves unchanged final code/LOAD geometry before copying the
    // candidate. These CLI numbers are ELF VAs, never candidate-derived authority.
    // No constructors, dependencies, foreign callers, signals, CET, unwind/fork,
    // alias writes, unload or mapping changes. Every bound 0..64 has a valid
    // nonnull 64-byte backing object; zero bound still performs the real CALL/RET.
    let owner =
        unsafe { LoadedIntegerLeaf::load_selected(candidate, &selection, CONTRACT) }.unwrap();
    let entry = owner.entry();
    let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
    assert!(!returns.is_empty());
    let gate = CallGate::new(owner.certificate()).unwrap();
    let continuation = gate.continuation();
    let mut prep =
        OrdinarySitePreparation::new_whole_function(owner, gate, identity(entry)).unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        std::iter::once(entry)
            .chain(returns.iter().copied())
            .collect::<Vec<_>>()
    );
    let expected_input = guarded_inputs();
    let input = Arc::new(expected_input);
    let readable = stack();
    let mut originals = [0_u64; 8];
    for (index, case) in CASES.into_iter().enumerate() {
        let slice = &input[index][16..16 + case.bound];
        // SAFETY: retained unpatched complete owner, one current thread/stack,
        // immutable guarded input and no publication until all eight returns.
        let call = unsafe { prep.invoke_original(slice.as_ptr(), slice.len(), &readable) }.unwrap();
        assert_eq!(call.value, cases::scalar(case));
        assert_eq!(call.pre_call_rsp, call.resumed_rsp);
        assert_eq!(call.pre_call_rsp % 16, 0);
        assert_eq!(*input, expected_input);
        originals[index] = call.value;
    }
    let site = publish(prep);
    let mut prepared = PreparedIntervalController::new(
        site,
        INSTALL,
        FUNCTION,
        Limits {
            epochs: 2,
            threads: 1,
            depth: 1,
            records_per_epoch: 8,
            actions: 4,
        },
    )
    .unwrap();
    let first = prepared.stage(CONFIG).unwrap();
    let second = prepared.stage(CONFIG).unwrap();
    let generations = [first.generation().get(), second.generation().get()];
    assert!(generations[0] > 0 && generations[1] > generations[0]);
    // SAFETY: final source publication is complete, no TLS client exists yet;
    // this process never forks/unloads or reclaims the retained source/images.
    let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
    controller.arm(&first).unwrap();
    let (park_tx, park_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let worker_input = Arc::clone(&input);
    let worker_returns = returns.clone();
    let handle = joined_task::spawn(move || {
        pin(Some(cpu));
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        assert!(tid > 0 && tid as u64 != u64::from(std::process::id()));
        let readable = stack();
        // SAFETY: this sole actual worker owns its admitted live stack/TLS and
        // only calls the matching gate. Code/input owners outlive every return.
        let mut attached =
            unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
        let mut calls = Vec::new();
        for (index, case) in CASES.into_iter().enumerate() {
            let slice = &worker_input[index][16..16 + case.bound];
            // SAFETY: the same qualified 0..64 read-only ABI/input and retained
            // site, no foreign entry, signal, reentry, nonlocal exit or mutation.
            let call = unsafe { attached.invoke_integer_leaf(slice) }.unwrap();
            assert_eq!(call.value, cases::scalar(case));
            let totals = attached.totals().unwrap();
            check::returned(index, &call, originals[index], &worker_returns, totals).unwrap();
            assert_eq!(*worker_input, expected_input);
            calls.push(call);
            if matches!(index, 3 | 4) {
                // The actual call and input/RSP/totals checks precede parking.
                park_tx.send((index + 1, totals)).unwrap();
                resume_rx
                    .recv_timeout(WAIT)
                    .expect("strnlen controller handshake");
            }
        }
        let totals = attached.totals().unwrap();
        let rows = attached.raw_intervals().unwrap();
        let batch = attached
            .drain_completed()
            .unwrap()
            .expect("eight completed calls");
        assert_eq!(batch.rows(), rows);
        let journal = batch.journal().to_vec();
        assert!(attached.drain_completed().unwrap().is_none());
        assert_eq!(attached.detach().unwrap(), totals);
        assert_eq!(batch.rows(), rows);
        assert_eq!(batch.journal(), journal);
        assert_eq!(*worker_input, expected_input);
        Completed {
            calls,
            rows,
            totals,
            batch,
            tid: tid as u64,
        }
    });
    // On any failure disconnect a parked worker, then join before input drops.
    let mut worker = Worker {
        resume: Some(resume_tx),
        handle: Some(handle),
    };
    assert_eq!(
        park_rx.recv_timeout(WAIT).expect("four returned calls"),
        (4, check::totals(4).unwrap())
    );
    controller.disarm(&first).unwrap();
    let first_report = controller.report(&first).unwrap().expect("A drained");
    let first_records: Vec<_> = first_report.records().collect();
    assert_eq!(first_records.len(), 2);
    worker.resume.as_ref().unwrap().send(()).unwrap();
    assert_eq!(
        park_rx.recv_timeout(WAIT).expect("removed call returned"),
        (5, check::totals(5).unwrap())
    );
    controller.arm(&second).unwrap();
    worker.resume.as_ref().unwrap().send(()).unwrap();
    let done = worker.join();
    assert_eq!(*input, expected_input);
    assert_eq!(Arc::strong_count(&input), 1, "actual worker owner joined");
    assert_eq!(done.totals, check::totals(8).unwrap());
    // The fourth action follows drain, detach and actual worker join. It is not
    // retroactively an entry prefix or a substitute for an actual return.
    controller.disarm(&second).unwrap();
    let second_report = controller.report(&second).unwrap().expect("B drained");
    assert_eq!(first_report.generation().get(), generations[0]);
    assert_eq!(first_report.records().collect::<Vec<_>>(), first_records);
    let queried = controller.report(&first).unwrap().unwrap();
    assert_eq!(queried.generation(), first_report.generation());
    assert_eq!(queried.records().collect::<Vec<_>>(), first_records);
    check_report(&first_report, &done.rows[..2], generations[0], 0);
    check_report(&second_report, &done.rows[5..7], generations[1], 2);
    let expected = check::Expected {
        originals,
        entry,
        returns,
        continuation,
        pid: std::process::id(),
        tid: done.tid,
        generations,
    };
    check::population(
        &done.calls,
        &done.rows,
        &check::Batch::from(&done.batch),
        &expected,
    )
    .unwrap();
    check::records(&done.rows, generations[0], 0, &first_records).unwrap();
    check::records(
        &done.rows,
        generations[1],
        2,
        &second_report.records().collect::<Vec<_>>(),
    )
    .unwrap();
    check::history(&controller.history().unwrap(), generations).unwrap();
    pin(Some(cpu));
    single_main();
    println!(
        "# unchanged FreeBSD strnlen calls; raw callback ticks are uncalibrated; no accuracy or performance claim"
    );
    println!(
        "ordinal,case,bound,owner,generation,invocation,history_prefix,ret_offset,native_value,value,start_ticks,end_ticks,start_aux,end_aux,elapsed_ticks"
    );
    for (index, row) in done.rows.iter().enumerate() {
        let (owner, generation, invocation) = match row.owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation,
            } => ("sampled", generation, invocation.to_string()),
            RawIntervalOwner::FunctionClosed { generation } => {
                ("closed", generation, String::new())
            }
            RawIntervalOwner::Removed { generation } => ("removed", generation, String::new()),
            _ => unreachable!("complete fixed schedule checked"),
        };
        println!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            row.ordinal,
            CASES[index].name,
            CASES[index].bound,
            owner,
            generation,
            invocation,
            check::prefix(index),
            row.return_pc - entry,
            originals[index],
            done.calls[index].value,
            row.start.ticks,
            row.end.ticks,
            row.start.aux,
            row.end.aux,
            row.elapsed_ticks().unwrap()
        );
    }
    println!(
        "strnlen-work PASS originals=8 calls=8 sampled=4 closed=3 removed=1 reports=2+2 batches=1 events=16 actions=4 entries=8 returns=8 completed=4 unsampled=4 raw_rows=8 input_unchanged=true joined=true"
    );
}

fn guarded_inputs() -> [[u8; 96]; 8] {
    std::array::from_fn(|index| {
        let mut storage = [0xa5; 96];
        storage[16..80].copy_from_slice(&cases::input(CASES[index]));
        storage
    })
}
