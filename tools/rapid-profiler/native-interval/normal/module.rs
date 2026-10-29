//! Four real CSV/length transitions through one shared-page normal module.
use super::*;
use native::module::{
    self as native_module, Arguments, Function, Population as ModulePopulation, Ready, bytes,
};
use rapid_profiler::frontend_native::{
    InstalledNormalModuleSite, LoadedNormalModule, NormalModuleContract,
    NormalModulePreparationPolicy, NormalModuleRoleKind, NormalModuleSitePreparation,
    PreparedNormalModuleController,
};
mod check;
mod owner;
pub(crate) mod session;
use check::{FUNCTIONS, INSTALL, identity};
const CONTRACT: NormalModuleContract = NormalModuleContract {
    single_external_entry_per_function: true,
    sequential_call_ret_only: true,
    no_active_cet: true,
};
const HEADER: &str = "k,seed,case,length_case,csv_length,length_bound,csv_index,length_index,status,children,comparisons,visits0,visits1,visits2,visits3,original_steps,candidate_steps,value0,value1,value2,value3,outer_value,ret_offset0,ret_offset1,ret_offset2,ret_offset3,csv_heads,csv_edges,length_heads,length_edges,length_reads0,length_reads1,length_bytes0,length_bytes1,declared_returns,target_calls,target_returns,outer_returns,normal_reaps\n";
const COVERAGE: &str = "k,seed,csv_cases,length_cases,csv_observed_heads,csv_declared_heads,csv_observed_edges,csv_declared_edges,csv_returns,length_heads,length_edges,length_returns\n";
fn publish(prep: NormalModuleSitePreparation) -> InstalledNormalModuleSite {
    current_single_main();
    let planned = prep.plan();
    assert_eq!(planned.plan().originals().len(), 1);
    let original = &planned.plan().originals()[0];
    assert_eq!(original.bytes.len(), 4096);
    let source = AddressRange::new(original.address, original.bytes.len()).unwrap();
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|s| s.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    // SAFETY: one actual complete module page and all generated allocations,
    // no source entry/saved resume, aliases, signals, unload or foreign caller.
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
        Err(f) => {
            eprintln!("module publication FAILED: {f:?}");
            std::process::abort()
        }
    };
    // SAFETY: exact actual successful transaction, complete final RX and owners.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}
fn child(
    candidate: bool,
    context: NormalContext<'_>,
    subject: &Path,
    selections: [&TrustedFunctionSelection<'_>; 2],
    caller_path: &Path,
    caller_elf: &[u8],
    session_profile: bool,
) -> i32 {
    current_single_main();
    context.deadline().check();
    let case = if session_profile {
        context.module_session_case()
    } else {
        context.module_case()
    };
    assert_eq!(context.input(), case.csv.input());
    assert_eq!(context.length_input(), cases::input(case.length));
    // SAFETY: independently trusted complete same-ELF selections; one actual
    // sequential calling thread, no CALL/reentry/tail/nonlocal edge in either
    // leaf, no active CET/signals/fork/alias mutation/unload through last use.
    let loaded =
        unsafe { LoadedNormalModule::load_selected_pair(subject, selections, CONTRACT) }.unwrap();
    assert_eq!(loaded.source_pages().len(), 1);
    assert_eq!(loaded.source_pages()[0].bytes.len(), 4096);
    for (semantic, &index) in case.order.iter().enumerate() {
        let f = &loaded.functions()[index];
        assert_eq!(
            f.label(),
            if semantic == 0 {
                native_module::CSV_LABEL
            } else {
                native_module::LENGTH_LABEL
            }
        );
        assert_eq!(f.code().len(), case.extents[semantic]);
    }
    let mut caller = unsafe { owner::Caller::load(caller_path, caller_elf) };
    let source = &loaded.source_pages()[0];
    let helper = caller.source();
    let mut ready = Ready {
        caller: caller.entry(),
        caller_immutable: vec![(helper.0, helper.1.to_vec())],
        functions: loaded.functions().each_ref().map(|f| Function {
            entry: f.entry(),
            heads: f.certificate().heads().to_vec(),
            returns: f.certificate().returns().to_vec(),
            boundaries: f.certificate().heads().iter().map(|&p| (p, p)).collect(),
        }),
        immutable: vec![(source.address, source.bytes.clone())],
        original_source: source.bytes.clone(),
        journal: None,
        case,
    };
    let data = context.data_address();
    assert_eq!(context.data_len(), 4096);
    assert_eq!(context.input().as_ptr() as usize as u64, data + 128);
    assert_eq!(
        context.length_input().as_ptr() as usize as u64,
        data + native_module::LENGTH_INPUT as u64
    );
    assert_eq!(
        (
            context.requests_address(),
            context.targets_address(),
            context.results_address()
        ),
        (data + 256, data + 288, data + 320)
    );
    let entries = ready.functions.each_ref().map(|f| f.entry);
    let targets_address = context.targets_address();
    // SAFETY: disjoint inherited table is initialized only before tracing/calls;
    // its complete bytes are independently checked by the parent at every head.
    unsafe {
        (targets_address as usize as *mut [u64; 2])
            .write([entries[case.order[0]], entries[case.order[1]]]);
    }
    let targets = unsafe { &*(targets_address as usize as *const [bytes::Target; 2]) };
    let requests = unsafe { &*(context.requests_address() as usize as *const [bytes::Request; 2]) };
    for (i, r) in requests.iter().enumerate() {
        assert_eq!(
            (r.data as usize as u64, r.bound),
            (
                data + if i == 0 {
                    128
                } else {
                    native_module::LENGTH_INPUT as u64
                },
                case.bound(i) as u64
            )
        );
    }
    let results_address = context.results_address();
    assert_eq!(
        unsafe { (results_address as usize as *const [u64; 4]).read() },
        [0; 4]
    );
    let mut expected_data =
        unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) }.to_vec();
    for i in 0..4 {
        expected_data[320 + i * 8..328 + i * 8].copy_from_slice(&case.value(i).to_le_bytes());
    }
    let rsp = context.caller_rsp();
    let deadline = context.deadline();
    if candidate {
        let id = identity(entries[0]);
        let mut policies = [NormalModulePreparationPolicy::WholeFunction; 2];
        policies[case.order[0]] = NormalModulePreparationPolicy::CertifiedBlocks;
        let prep = NormalModuleSitePreparation::new_with_policies(loaded, id, policies).unwrap();
        let expected_roles: Vec<_> = ready
            .functions
            .iter()
            .enumerate()
            .flat_map(|(i, f)| {
                std::iter::once((i, NormalModuleRoleKind::Entry, f.entry)).chain(
                    f.returns
                        .iter()
                        .map(move |&pc| (i, NormalModuleRoleKind::Return, pc)),
                )
            })
            .collect();
        assert_eq!(
            prep.roles()
                .map(|r| (r.function_index, r.kind, r.pc))
                .collect::<Vec<_>>(),
            expected_roles
        );
        let planned = prep.plan();
        assert_eq!(planned.plan().originals().len(), 1);
        assert_eq!(planned.plan().final_bytes().len(), 1);
        let final_source = &planned.plan().final_bytes()[0];
        assert_eq!(final_source.address, ready.immutable[0].0);
        ready.immutable[0] = (final_source.address, final_source.bytes.clone());
        for f in &mut ready.functions {
            f.boundaries.clear();
        }
        for image in planned.images() {
            for &(original, physical) in image.instruction_boundaries() {
                let owners: Vec<_> = ready
                    .functions
                    .iter()
                    .enumerate()
                    .filter_map(|(i, f)| f.heads.contains(&original).then_some(i))
                    .collect();
                assert_eq!(owners.len(), 1);
                ready.functions[owners[0]]
                    .boundaries
                    .push((original, physical));
            }
            ready
                .immutable
                .push((image.address(), image.bytes().to_vec()));
        }
        for f in &mut ready.functions {
            for &head in &f.heads {
                if !f.boundaries.iter().any(|(a, _)| *a == head) {
                    f.boundaries.push((head, head));
                }
            }
        }
        let site = publish(prep);
        let (mut controller, client, epoch) = session::Candidate::prepare(site, case);
        let generation = epoch.generation().get();
        controller.arm(&epoch, &ready);
        let (low, high) = context.stack_range();
        let stack = unsafe { ReadableStack::new(low, high) }.unwrap();
        let journal = IntervalJournal::allocate();
        let address = journal.address();
        let mut attached = unsafe { client.attach(1, stack, journal) }.unwrap();
        assert_eq!(attached.totals().unwrap(), NormalTotals::default());
        ready.journal = Some(JournalReady {
            address,
            a_generation: generation,
            b_generation: None,
            helper_tid: None,
        });
        caller.verify();
        check_live(&ready.immutable);
        deadline.check();
        session::ready(context, &ready);
        // SAFETY: actual four-call C helper, live disjoint arrays/inputs. The one
        // parent walk checks each physical CALL/C3 and outer RET before resuming.
        let (sum, values) = {
            let results = unsafe { &mut *(results_address as usize as *mut [u64; 4]) };
            let sum = unsafe { caller.invoke(targets, requests, results) };
            (sum, *results)
        };
        assert_eq!((sum, values), (case.sum(), case.values()));
        assert_eq!(
            unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) },
            expected_data
        );
        caller.verify();
        check_live(&ready.immutable);
        current_single_main();
        deadline.check();
        assert_eq!(attached.totals().unwrap(), check::totals(case, 3));
        // SAFETY: all four real target returns, real outer RET, complete helper,
        // module/images/input/target/request/result postflight already succeeded.
        let batch = unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .unwrap();
        assert_eq!(id, identity(entries[0]));
        check::metadata(
            &ready,
            std::process::id(),
            check::Metadata {
                identity: batch.identity(),
                functions: *batch.functions(),
                entries: *batch.entries(),
                pid: batch.pid(),
                tid: batch.tid(),
                registration: batch.registration(),
                install: batch.install(),
                number: batch.number(),
                next: batch.next_ordinal(),
                sequences: batch.completed_sequences(),
                totals: batch.totals(),
            },
        );
        check::rows(
            &ready,
            rsp,
            std::process::id(),
            batch.records(),
            batch.journal(),
        );
        controller.batch(&ready, &batch);
        assert_eq!(attached.totals().unwrap(), check::totals(case, 4));
        assert!(
            unsafe { attached.checkpoint_after_returns() }
                .unwrap()
                .is_none()
        );
        assert_eq!(attached.detach().unwrap(), check::totals(case, 4));
        controller.disarm(&epoch, &ready);
        let report = controller.report(&epoch);
        check::records(
            &ready,
            batch.records(),
            report.generation().get(),
            &report.records().collect::<Vec<_>>(),
        );
        controller.history(&ready);
        caller.verify();
        check_live(&ready.immutable);
        drop(report);
        controller.reclaim(epoch, &ready);
        drop((batch, client, controller));
    } else {
        loaded.verify_original().unwrap();
        caller.verify();
        deadline.check();
        session::ready(context, &ready);
        let (sum, values) = {
            let results = unsafe { &mut *(results_address as usize as *mut [u64; 4]) };
            let sum = unsafe { caller.invoke(targets, requests, results) };
            (sum, *results)
        };
        assert_eq!((sum, values), (case.sum(), case.values()));
        assert_eq!(
            unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) },
            expected_data
        );
        loaded.verify_original().unwrap();
        caller.verify();
        check_live(&ready.immutable);
    }
    current_single_main();
    deadline.check();
    0
}
pub(crate) fn run(
    subject: &Path,
    expected: &Path,
    arguments: Arguments,
    caller_path: &Path,
    caller_expected: &Path,
    output: &Path,
    deadline: Deadline,
) {
    run_profile(
        subject,
        expected,
        session::Run::Finite(arguments),
        caller_path,
        caller_expected,
        output,
        deadline,
    )
}
fn run_profile(
    subject: &Path,
    expected: &Path,
    arguments: session::Run,
    caller_path: &Path,
    caller_expected: &Path,
    output: &Path,
    mut deadline: Deadline,
) {
    deadline.check();
    current_single_main();
    let (k, csv_args, length_args) = arguments.fields();
    let elf = trusted(subject, expected);
    let caller_elf = trusted(caller_path, caller_expected);
    let csv_selection = TrustedFunctionSelection::new(
        &elf,
        csv_args.elf_va,
        csv_args.length,
        native_module::CSV_LABEL,
    )
    .unwrap();
    let length_selection = TrustedFunctionSelection::new(
        &elf,
        length_args.elf_va,
        length_args.length,
        native_module::LENGTH_LABEL,
    )
    .unwrap();
    let selections = if csv_args.elf_va < length_args.elf_va {
        [&csv_selection, &length_selection]
    } else {
        [&length_selection, &csv_selection]
    };
    let mut population = arguments.population();
    let prefix = if arguments.is_session() {
        "profile,"
    } else {
        ""
    };
    let mut rows = format!("{prefix}{HEADER}");
    let mut coverage = format!("{prefix}{COVERAGE}");
    let mut count = 0;
    let mut covered = 0;
    for seed in SEEDS {
        for index in 0..16 {
            if count != 0 {
                deadline = Deadline::start();
            }
            let case = arguments.case(index);
            let oracle = arguments.oracle(seed, case, deadline);
            let (pair, trace) = arguments.pair(&oracle, |candidate, context| {
                // Dedicated child only. Fail-stop precedes every child-local owner.
                std::panic::set_hook(Box::new(|info| {
                    eprintln!("native module child FAILED: {info}");
                    std::process::abort();
                }));
                child(
                    candidate,
                    context,
                    subject,
                    selections,
                    caller_path,
                    &caller_elf,
                    arguments.is_session(),
                )
            });
            if let Some(c) = population.record(seed, case, &pair, &trace) {
                assert_eq!(index, 15);
                covered += 1;
                if arguments.is_session() {
                    coverage.push_str("session-absolute-v1,");
                }
                coverage.push_str(&format!(
                    "{},{seed},16,8,{},{},{},{},{},{},{},{}\n",
                    k,
                    c.csv_heads,
                    c.csv_declared_heads,
                    c.csv_edges,
                    c.csv_declared_edges,
                    c.csv_returns,
                    c.length_heads,
                    c.length_edges,
                    c.length_returns
                ));
            }
            let offsets = trace.offsets();
            let mut fields = vec![
                k.to_string(),
                seed.to_string(),
                case.csv.id().to_string(),
                (index % 8 + 1).to_string(),
                case.csv.length().to_string(),
                case.length.bound.to_string(),
                case.order[0].to_string(),
                case.order[1].to_string(),
                "PASS".to_owned(),
                "2".to_owned(),
            ];
            fields.extend(
                [
                    pair.comparisons as u64,
                    pair.visits[0] as u64,
                    pair.visits[1] as u64,
                    pair.visits[2] as u64,
                    pair.visits[3] as u64,
                    pair.original_steps as u64,
                    pair.candidate_steps as u64,
                    pair.values[0],
                    pair.values[1],
                    pair.values[2],
                    pair.values[3],
                    pair.outer_value,
                    offsets[0],
                    offsets[1],
                    offsets[2],
                    offsets[3],
                    trace.csv[0].heads.len() as u64,
                    trace.csv[0].edges.len() as u64,
                    trace.length[0].observed_heads() as u64,
                    trace.length[0].observed_edges() as u64,
                    trace.length[0].input_reads as u64,
                    trace.length[1].input_reads as u64,
                    trace.length[0].input_bytes as u64,
                    trace.length[1].input_bytes as u64,
                    pair.declared_returns.len() as u64,
                    8,
                    8,
                    2,
                    2,
                ]
                .map(|n| n.to_string()),
            );
            assert_eq!(fields.len(), 39);
            if arguments.is_session() {
                fields.insert(0, "session-absolute-v1".to_owned());
            }
            rows.push_str(&fields.join(","));
            rows.push('\n');
            // Only complete paired records, after both normal reaps and all truth checks.
            let (pairs_name, coverage_name) = arguments.files();
            if arguments.is_session() {
                assert!(rows.len() <= 65_536 && coverage.len() <= 65_536);
            }
            std::fs::write(output.join(pairs_name), &rows).unwrap();
            std::fs::write(output.join(coverage_name), &coverage).unwrap();
            drop(oracle);
            deadline.check();
            count += 1;
        }
    }
    assert_eq!((count, covered), (32, 2));
    let comparisons = population.finish();
    current_single_main();
    deadline.check();
    let mut out = std::io::stdout().lock();
    if arguments.is_session() {
        let terminal = format!(
            "native-normal-module-session:profile=session-absolute-v1:k={k}:e=3:t=1:d=1:m=1:a={}:resident-actions=8:required=32:pairs=32:children=64:comparisons={comparisons}:coverage-seeds=2:csv-cases-per-seed=16:length-cases-per-seed=8:target-calls=256:target-returns=256:real-outer-ret=64:normal-reaps=64:complete",
            k.checked_mul(2).unwrap()
        );
        assert!(terminal.len() < 65_536);
        writeln!(out, "{terminal}").unwrap();
    } else {
        writeln!(out,"native-normal-module:k={}:required=32:pairs=32:children=64:comparisons={comparisons}:coverage-seeds=2:csv-cases-per-seed=16:length-cases-per-seed=8:target-calls=256:target-returns=256:real-outer-ret=64:normal-reaps=64:complete",k).unwrap();
    }
    out.flush().unwrap();
    deadline.check();
}
