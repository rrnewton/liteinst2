//! Two real functions in one DSO, one attachment and one complete transfer.
//! Functional accounting only; native state and performance require other runs.
use super::*;
use rapid_profiler::frontend_native::{
    InstalledNormalModuleSite, LoadedNormalModule, NormalModuleBatch, NormalModuleContract,
    NormalModulePreparationPolicy, NormalModuleSitePreparation, PreparedNormalModuleController,
};
use std::fmt::Write as _;
use std::io::Write as _;
mod check;
pub(crate) mod session;
#[cfg(test)]
mod tests;
const CALLS: usize = 32;
const INSTALL: u64 = 0x6d6f_6401;
const FUNCTIONS: [FunctionId; 2] = [FunctionId(101), FunctionId(202)];
const LABELS: [&str; 2] = ["normal-csv-fields-v1", cases::LABEL];

fn case(i: usize) -> (usize, usize, u64) {
    assert!(i < CALLS);
    if i % 2 == 0 {
        let c = csv::CASES[i / 2];
        (0, c.0.len(), c.1)
    } else {
        let c = cases::CASES[(i / 2) % 8];
        (1, c.bound, c.expected)
    }
}
fn inputs() -> [[u8; 96]; CALLS] {
    let csv = csv::inputs();
    let length = super::input();
    std::array::from_fn(|i| {
        if i % 2 == 0 {
            csv[i / 2]
        } else {
            length[(i / 2) % 8]
        }
    })
}
#[repr(C)]
struct Results {
    before: [u64; 2],
    values: [u64; CALLS],
    after: [u64; 2],
}
impl Results {
    fn new() -> Self {
        Self {
            before: [0xa7a7; 2],
            values: [u64::MAX; CALLS],
            after: [0x5a5a; 2],
        }
    }
}
struct Data {
    input: Box<[[u8; 96]; CALLS]>,
    results: Box<[Results; 2]>,
}
impl Data {
    fn new() -> Self {
        Self {
            input: Box::new(inputs()),
            results: Box::new([Results::new(), Results::new()]),
        }
    }
    fn check(&self, original: usize, installed: usize) {
        assert!(original <= CALLS && installed <= CALLS);
        assert_eq!(*self.input, inputs());
        for (leg, done) in [original, installed].into_iter().enumerate() {
            let r = &self.results[leg];
            assert_eq!(r.before, [0xa7a7; 2]);
            assert_eq!(r.after, [0x5a5a; 2]);
            for (i, &value) in r.values.iter().enumerate() {
                assert_eq!(value, if i < done { case(i).2 } else { u64::MAX });
                if leg == 1 && i < done {
                    assert_eq!(value, self.results[0].values[i]);
                }
            }
        }
    }
}
fn totals(n: u64, confirmed: u64, k: usize) -> NormalTotals {
    assert!(matches!(k, 1 | 16) && confirmed <= n && n <= CALLS as u64);
    let completed = confirmed.min((2 * k) as u64);
    NormalTotals {
        entered: n,
        ret_observed: n,
        confirmed,
        completed,
        unsampled: confirmed - completed,
    }
}
fn publish(prep: NormalModuleSitePreparation) -> InstalledNormalModuleSite {
    single_main();
    let planned = prep.plan();
    // This example intentionally exercises two complete functions sharing one page.
    let originals = planned.plan().originals();
    assert_eq!(originals.len(), 1);
    let source = AddressRange::new(originals[0].address, originals[0].bytes.len()).unwrap();
    assert_eq!(source.start() % 4096, 0);
    assert_eq!(source.len(), 4096);
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
    // SAFETY: sole-thread quiescence, complete owned source page, no saved resumes.
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
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("module publication FAILED: {error:?}");
            std::process::abort();
        }
    };
    // SAFETY: exact complete transaction, RX source and continuous exclusive custody.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

pub(crate) fn run(args: &[std::ffi::OsString]) {
    let deadline = Instant::now().checked_add(Duration::from_secs(15)).unwrap();
    assert_eq!(
        args.len(),
        7,
        "normal-module-work CANDIDATE TRUSTED_FINAL CSV_VA CSV_LENGTH LENGTH_VA LENGTH_LENGTH K"
    );
    let number = |i: usize| strnlen::number(args[i].to_str().unwrap());
    let (candidate, trusted) = (Path::new(&args[0]), Path::new(&args[1]));
    let vas = [number(2), number(4)];
    let lengths = [
        usize::try_from(number(3)).unwrap(),
        usize::try_from(number(5)).unwrap(),
    ];
    let k = usize::try_from(number(6)).unwrap();
    assert!(matches!(k, 1 | 16) && vas[0] < vas[1]);
    assert!((5..=256).contains(&lengths[0]) && (5..=80).contains(&lengths[1]));
    single_main();
    let cpu = pin(None);
    let pid = std::process::id();
    let bytes = expected_file(candidate, trusted);
    let selections = [
        TrustedFunctionSelection::new(&bytes, vas[0], lengths[0], LABELS[0]).unwrap(),
        TrustedFunctionSelection::new(&bytes, vas[1], lengths[1], LABELS[1]).unwrap(),
    ];
    // SAFETY: complete independently trusted final ELF/selections; two exact scalar
    // ABIs, sole ordinary main caller, valid input, no active CET/signals/unwind,
    // nonlocal exit/fork/reentry/alias writer/unload. Both leaves contain no CALL.
    let owner = unsafe {
        LoadedNormalModule::load_selected_pair(
            candidate,
            [&selections[0], &selections[1]],
            NormalModuleContract {
                single_external_entry_per_function: true,
                sequential_call_ret_only: true,
                no_active_cet: true,
            },
        )
    }
    .unwrap();
    let entries = owner.functions().each_ref().map(|f| f.entry());
    let ends = std::array::from_fn(|i| entries[i].checked_add(lengths[i] as u64).unwrap());
    let returns = owner
        .functions()
        .each_ref()
        .map(|f| f.certificate().returns().to_vec());
    for i in 0..2 {
        assert_eq!(
            owner.functions()[i].certificate().range(),
            (entries[i], ends[i])
        );
    }
    assert_eq!(owner.source_pages().len(), 1);
    assert_eq!(owner.source_pages()[0].bytes.len(), 4096);
    assert_eq!(entries[0] & !4095, entries[1] & !4095);
    let targets: [csv::Csv; 2] =
        entries.map(|e| unsafe { std::mem::transmute(usize::try_from(e).unwrap()) });
    let readable = stack();
    let mut custody = csv::Custody {
        candidate,
        trusted,
        bytes: &bytes,
        cpu,
        pid,
        stack: csv::stack_bounds(),
        caller: csv::mapping(csv::invoke as *const () as usize as u64, "r-xp"),
        source: owner
            .source_pages()
            .iter()
            .map(|s| (s.address, s.bytes.clone()))
            .collect(),
        generated: Vec::new(),
        deadline,
    };
    let mut data = Data::new();
    let mut original = Some(owner);
    let mut state = None;
    let mut batch = None;
    let mut report = None;
    let mut fail_stop = csv::FailStop(true);
    for i in 0..CALLS {
        data.check(i, 0);
        custody.check();
        original.as_mut().unwrap().verify_original().unwrap();
        let (function, bound, _) = case(i);
        // SAFETY: selected scalar ABI, guarded input, original owner, actual call/store.
        unsafe {
            csv::invoke(
                targets[function],
                &data.input[i][16..16 + bound],
                &mut data.results[0].values[i],
            )
        };
        data.check(i + 1, 0);
        original.as_mut().unwrap().verify_original().unwrap();
        custody.check();
    }
    let code_identity = identity(entries[0]);
    let prep = NormalModuleSitePreparation::new_with_policies(
        original.take().unwrap(),
        code_identity,
        [
            NormalModulePreparationPolicy::CertifiedBlocks,
            NormalModulePreparationPolicy::WholeFunction,
        ],
    )
    .unwrap();
    for i in 0..2 {
        assert_eq!(prep.functions()[i].range(), (entries[i], ends[i]));
        assert_eq!(prep.functions()[i].returns(), returns[i]);
    }
    custody.source = prep
        .plan()
        .plan()
        .final_bytes()
        .iter()
        .map(|s| (s.address, s.bytes.clone()))
        .collect();
    custody.generated = prep
        .plan()
        .images()
        .iter()
        .map(|i| (i.address(), i.bytes().to_vec()))
        .collect();
    let site = publish(prep);
    let mut prepared = PreparedNormalModuleController::new(
        site,
        INSTALL,
        FUNCTIONS,
        Limits {
            epochs: 1,
            threads: 1,
            depth: 1,
            records_per_epoch: CALLS,
            actions: 2,
        },
    )
    .unwrap();
    let epoch = prepared
        .stage(Config {
            retained_per_function: k,
            max_inflight: 1,
            max_invocations: CALLS,
        })
        .unwrap();
    let generation = epoch.generation().get();
    // SAFETY: sole actual caller/controller, pristine process, no active subject.
    let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
    controller.arm(&epoch).unwrap();
    let attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
    assert!(
        state
            .replace((controller, client, epoch, attached))
            .is_none()
    );
    assert_eq!(
        state.as_ref().unwrap().3.totals().unwrap(),
        NormalTotals::default()
    );
    for i in 0..CALLS {
        data.check(CALLS, i);
        custody.check();
        let (function, bound, _) = case(i);
        // SAFETY: same real ordinary caller, one attached thread and continuous custody.
        unsafe {
            csv::invoke(
                targets[function],
                &data.input[i][16..16 + bound],
                &mut data.results[1].values[i],
            )
        };
        data.check(CALLS, i + 1);
        custody.check();
        assert_eq!(
            state.as_ref().unwrap().3.totals().unwrap(),
            totals(i as u64 + 1, i as u64, k)
        );
    }
    let (controller, _, epoch, attached) = state.as_mut().unwrap();
    // Full postflight succeeds before actual-return attestation and receipt consumption.
    custody.check();
    data.check(CALLS, CALLS);
    assert!(
        batch
            .replace(
                unsafe { attached.checkpoint_after_returns() }
                    .unwrap()
                    .expect("32 actual returns")
            )
            .is_none()
    );
    assert_eq!(attached.totals().unwrap(), totals(32, 32, k));
    custody.check();
    data.check(CALLS, CALLS);
    assert!(
        unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .is_none()
    );
    assert_eq!(attached.detach().unwrap(), totals(32, 32, k));
    controller.disarm(epoch).unwrap();
    assert!(
        report
            .replace(
                controller
                    .report(epoch)
                    .unwrap()
                    .expect("all sampled records completed")
            )
            .is_none()
    );
    let history = controller.history().unwrap();
    let expected = check::Expected {
        identity: code_identity,
        pid,
        entries,
        ends,
        returns: [&returns[0], &returns[1]],
        generation,
        k,
        stack: custody.stack,
        caller: custody.caller,
    };
    check::validate(
        expected,
        batch.as_ref().unwrap(),
        report.as_ref().unwrap(),
        &history,
    )
    .unwrap();
    custody.check();
    data.check(CALLS, CALLS);
    let text = output(&data, batch.as_ref().unwrap(), expected, cpu);
    std::io::stdout().lock().write_all(text.as_bytes()).unwrap();
    assert!(Instant::now() < deadline, "module final deadline");
    fail_stop.0 = false;
}
fn output(data: &Data, batch: &NormalModuleBatch, e: check::Expected<'_>, cpu: usize) -> String {
    let mut text = String::with_capacity(16384);
    writeln!(text, "ordinal,function,case,length,expected,original,installed,return_offset,owner,invocation_plus_one,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,ack,ack_ordinal").unwrap();
    for (i, row) in batch.records().iter().enumerate() {
        let (function, bound, value) = case(i);
        let r = &row.record;
        let (kind, slot) = match r.raw.owner {
            RawIntervalOwner::Sampled { invocation, .. } => (1, invocation + 1),
            RawIntervalOwner::FunctionClosed { .. } => (3, 0),
            _ => panic!("closed two-cohort module profile"),
        };
        let (ack, next) = match r.acknowledgement {
            NormalAcknowledgement::NextEntry { ordinal } => (1, ordinal),
            NormalAcknowledgement::CallerCheckpoint => (2, 0),
        };
        writeln!(
            text,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            r.raw.ordinal,
            row.function.0,
            if function == 0 {
                i / 2 + 1
            } else {
                (i / 2) % 8 + 1
            },
            bound,
            value,
            data.results[0].values[i],
            data.results[1].values[i],
            r.raw.return_pc - e.entries[function],
            kind,
            slot,
            r.history_prefix,
            r.entry_rsp,
            r.return_word,
            r.raw.start.ticks,
            r.raw.end.ticks,
            r.raw.start.aux,
            r.raw.end.aux,
            ack,
            next
        )
        .unwrap();
    }
    writeln!(text, "normal-module-work MODULE_FUNCTIONAL_PASS k={} originals=32 installed=32 functions=2 shared_source_pages=1 records=32 actions=2 journal_words=512 completed={} unsampled={} next_entry=31 checkpoints=1 pid={} tid={} cpu={} generation={} entry0={} entry1={} length0={} length1={} caller_entry={} returns0={} returns1={} install={INSTALL} function0=101 function1=202 registration=1", e.k, 2 * e.k, 32 - 2 * e.k, e.pid, e.pid, cpu, e.generation, e.entries[0], e.entries[1], e.ends[0] - e.entries[0], e.ends[1] - e.entries[1], csv::invoke as *const () as usize as u64, e.returns[0].len(), e.returns[1].len()).unwrap();
    assert!(text.is_ascii() && text.len() <= 16384);
    text
}
