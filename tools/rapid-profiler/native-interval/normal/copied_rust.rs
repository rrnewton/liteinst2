//! Copied complete application FUNC, one actual nested target CALL per child.
use super::rust_invoke_artifact::Artifact;
use super::*;
use native::copied_rust::{Case, Population, Ready};
use native::module::{CSV_LABEL, Function, LENGTH_LABEL};
use rapid_profiler::frontend_native::{
    LoadedNormalModule, NormalModuleContract, NormalModulePreparationPolicy, NormalModuleRoleKind,
    NormalModuleSitePreparation, PreparedNormalModuleController,
};
mod check;
use check::{FUNCTIONS, INSTALL, identity};
const CONTRACT: NormalModuleContract = NormalModuleContract {
    single_external_entry_per_function: true,
    sequential_call_ret_only: true,
    no_active_cet: true,
};
const HEADER: &str = "profile,seed,function,case,bound,status,children,comparisons,visits,original_steps,candidate_steps,result,outer_rax,input_reads,input_bytes,ret_offset,observed_heads,declared_heads,observed_edges,declared_edges,declared_returns,caller_bytes,caller_heads,call_offset,continuation_offset,outer_ret_offset,subject_rsp_delta,target_calls,target_returns,outer_returns,normal_reaps\n";
const COVERAGE: &str = "profile,seed,function,cases,observed_heads,declared_heads,observed_edges,declared_edges,observed_returns,declared_returns,comparisons\n";
const PROFILE: &str = "copied-rust-invoke-v1";
#[inline(never)]
unsafe fn machine_call(entry: u64, target: u64, input: *const u8, bound: usize, output: *mut u64) {
    // SAFETY: this is the separately admitted four-origin machine ABI, not an
    // assertion about Rust ABI. The complete copied bytes and owners are live.
    let call: unsafe extern "C" fn(u64, *const u8, usize, *mut u64) =
        unsafe { std::mem::transmute(entry as usize) };
    unsafe { call(target, input, bound, output) };
    // An observable actual post-call access forbids replacing the CALL by a tail jump.
    std::hint::black_box(unsafe { output.read_volatile() });
}
fn child(
    candidate: bool,
    context: NormalContext<'_>,
    subject: &Path,
    selections: [&TrustedFunctionSelection<'_>; 2],
    artifact: &Artifact,
) -> i32 {
    current_single_main();
    let deadline = context.deadline();
    deadline.check();
    artifact.verify().unwrap();
    let case = context.copied_rust_case();
    assert_eq!(context.input(), case.input());
    // SAFETY: one retained module/page, both complete independently trusted scalar
    // leaf selections; one actual calling thread, no signals/CET/unwind/reentry.
    let loaded =
        unsafe { LoadedNormalModule::load_selected_pair(subject, selections, CONTRACT) }.unwrap();
    assert_eq!(loaded.source_pages().len(), 1);
    assert_eq!(loaded.source_pages()[0].bytes.len(), 4096);
    for (semantic, &index) in case.order().iter().enumerate() {
        assert_eq!(
            loaded.functions()[index].label(),
            if semantic == 0 {
                CSV_LABEL
            } else {
                LENGTH_LABEL
            }
        );
        assert_eq!(
            loaded.functions()[index].code().len(),
            case.extents()[semantic]
        );
    }
    let source = &loaded.source_pages()[0];
    let copied = artifact.source();
    let mut ready = Ready {
        caller: artifact.entry(),
        caller_immutable: vec![(copied.0, copied.1.to_vec())],
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
        plan: artifact.plan().clone(),
    };
    let data = context.data_address();
    let results = context.results_address();
    let rsp = context.caller_rsp();
    assert_eq!(context.data_len(), 4096);
    assert_eq!(context.input().as_ptr() as usize as u64, data + 128);
    assert_eq!(results, data + 320);
    let mut expected_data =
        unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) }.to_vec();
    assert_eq!(&expected_data[320..328], &[0; 8]);
    expected_data[320..328].copy_from_slice(&case.value().to_le_bytes());
    let entries = ready.functions.each_ref().map(|f| f.entry);
    let mut original = Some(loaded);
    let mut installed = None;
    if candidate {
        let mut policies = [NormalModulePreparationPolicy::WholeFunction; 2];
        policies[case.order()[0]] = NormalModulePreparationPolicy::CertifiedBlocks;
        let prep = NormalModuleSitePreparation::new_with_policies(
            original.take().unwrap(),
            identity(entries[0]),
            policies,
        )
        .unwrap();
        let roles: Vec<_> = ready
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
            roles
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
            for &(logical, physical) in image.instruction_boundaries() {
                let owners: Vec<_> = ready
                    .functions
                    .iter()
                    .enumerate()
                    .filter_map(|(i, f)| f.heads.contains(&logical).then_some(i))
                    .collect();
                assert_eq!(owners.len(), 1);
                ready.functions[owners[0]]
                    .boundaries
                    .push((logical, physical));
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
        let site = module::publish(prep);
        let mut prepared = PreparedNormalModuleController::new(
            site,
            INSTALL,
            FUNCTIONS,
            Limits {
                epochs: 1,
                threads: 1,
                depth: 1,
                records_per_epoch: 32,
                actions: 2,
            },
        )
        .unwrap();
        let epoch = prepared
            .stage(Config {
                retained_per_function: 16,
                max_inflight: 1,
                max_invocations: 32,
            })
            .unwrap();
        // SAFETY: actual dedicated child, continuous union-wide sequential custody.
        let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
        controller.arm(&epoch).unwrap();
        let (low, high) = context.stack_range();
        let stack = unsafe { ReadableStack::new(low, high) }.unwrap();
        let journal = IntervalJournal::allocate();
        let address = journal.address();
        let attached = unsafe { client.attach(1, stack, journal) }.unwrap();
        assert_eq!(attached.totals().unwrap(), NormalTotals::default());
        ready.journal = Some(JournalReady {
            address,
            a_generation: epoch.generation().get(),
            b_generation: None,
            helper_tid: None,
        });
        installed = Some((controller, client, epoch, attached));
    } else {
        original.as_mut().unwrap().verify_original().unwrap();
    }
    artifact.verify().unwrap();
    check_live(&ready.immutable);
    deadline.check();
    context.ready_copied_rust(&ready);
    // One shared bridge callsite in both children. The parent checks its actual
    // pushed continuation, the complete copied body and the outer C3 before resume.
    unsafe {
        machine_call(
            artifact.entry(),
            ready.target().entry,
            (data + 128) as usize as *const u8,
            case.bound(),
            results as usize as *mut u64,
        )
    };
    assert_eq!(
        unsafe { (results as usize as *const u64).read() },
        case.value()
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) },
        expected_data
    );
    artifact.verify().unwrap();
    check_live(&ready.immutable);
    if let Some(original) = &mut original {
        original.verify_original().unwrap();
    }
    current_single_main();
    deadline.check();
    if let Some((mut controller, client, epoch, mut attached)) = installed {
        assert_eq!(attached.totals().unwrap(), check::totals(0));
        // SAFETY: real target and copied outer returns plus complete independent
        // artifact/source/image/input/output postflight succeeded before this call.
        let batch = unsafe { attached.checkpoint_after_returns() }
            .unwrap()
            .unwrap();
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
        assert_eq!(batch.history_stream(), None);
        assert_eq!(batch.history_high_water(), None);
        check::rows(
            &ready,
            rsp,
            std::process::id(),
            batch.records(),
            batch.journal(),
        );
        assert_eq!(attached.totals().unwrap(), check::totals(1));
        assert!(
            unsafe { attached.checkpoint_after_returns() }
                .unwrap()
                .is_none()
        );
        assert_eq!(attached.detach().unwrap(), check::totals(1));
        controller.disarm(&epoch).unwrap();
        let report = controller
            .report(&epoch)
            .unwrap()
            .expect("one-call closed Report");
        check::records(
            &ready,
            batch.records(),
            report.generation().get(),
            &report.records().collect::<Vec<_>>(),
        );
        check::history(&controller.history().unwrap(), epoch.generation().get());
        artifact.verify().unwrap();
        check_live(&ready.immutable);
        deadline.check();
        drop(report);
        drop((batch, attached, epoch, client, controller));
    }
    current_single_main();
    deadline.check();
    0
}
pub(crate) fn run(
    subject: &Path,
    expected: &Path,
    arguments: native::module::Arguments,
    app: &Path,
    app_expected: &Path,
    output: &Path,
    mut deadline: Deadline,
) {
    assert_eq!(arguments.k, 16);
    deadline.check();
    current_single_main();
    let elf = trusted(subject, expected);
    let app_bytes = trusted_bounded(app, app_expected, 512 * 1024 * 1024);
    // SAFETY: parent-only private copy before forks, retained unchanged beyond all
    // normal reaps; source qualification supplies no active CET/nonlocal transfer.
    let artifact = unsafe { Artifact::open(app, &app_bytes) }.unwrap();
    assert_eq!(artifact.selection().extent, artifact.plan().bytes().len());
    let csv =
        TrustedFunctionSelection::new(&elf, arguments.csv.elf_va, arguments.csv.length, CSV_LABEL)
            .unwrap();
    let length = TrustedFunctionSelection::new(
        &elf,
        arguments.length.elf_va,
        arguments.length.length,
        LENGTH_LABEL,
    )
    .unwrap();
    let order = usize::from(arguments.csv.elf_va > arguments.length.elf_va);
    let selections = if order == 0 {
        [&csv, &length]
    } else {
        [&length, &csv]
    };
    let mut population = Population::default();
    let mut rows = HEADER.to_owned();
    let mut coverage = COVERAGE.to_owned();
    let mut count = 0;
    let mut covered = 0;
    for seed in SEEDS {
        for function in 0..2 {
            for index in 0..if function == 0 { 16 } else { 8 } {
                if count != 0 {
                    deadline = Deadline::start();
                }
                artifact.verify().unwrap();
                deadline.check();
                let case = Case::new(
                    function,
                    index,
                    arguments.csv.length,
                    arguments.length.length,
                    order,
                );
                let oracle = NormalOracle::new_copied_rust(
                    seed,
                    case,
                    artifact.plan().clone(),
                    artifact.entry(),
                    (artifact.source().0, artifact.source().1.to_vec()),
                    deadline,
                );
                let (pair, trace) = oracle.pair_copied_rust(|candidate, context| {
                    // Dedicated oracle child only; no unwinding of callable owners on failure.
                    std::panic::set_hook(Box::new(|info| {
                        eprintln!("copied Rust child FAILED: {info}");
                        std::process::abort();
                    }));
                    child(candidate, context, subject, selections, &artifact)
                });
                artifact.verify().unwrap();
                deadline.check();
                let name = if function == 0 { "csv" } else { "length" };
                if let Some(c) = population.record(seed, case, artifact.plan(), &pair, &trace) {
                    covered += 1;
                    coverage.push_str(&format!(
                        "{PROFILE},{seed},{name},{},{},{},{},{},{},{},{}\n",
                        if function == 0 { 16 } else { 8 },
                        c.heads,
                        c.declared_heads,
                        c.edges,
                        c.declared_edges,
                        c.returns,
                        c.declared_returns,
                        c.comparisons
                    ));
                }
                let (heads, declared_heads, edges, declared_edges, returns) = trace.counts();
                let p = artifact.plan();
                let mut fields = vec![
                    PROFILE.to_owned(),
                    seed.to_string(),
                    name.to_owned(),
                    (index + 1).to_string(),
                    case.bound().to_string(),
                    "PASS".to_owned(),
                    "2".to_owned(),
                ];
                fields.extend(
                    [
                        pair.comparisons as u64,
                        pair.visits[0] as u64,
                        pair.original_steps as u64,
                        pair.candidate_steps as u64,
                        pair.values[0],
                        pair.outer_value,
                    ]
                    .map(|n| n.to_string()),
                );
                let reads = trace.input_reads();
                fields.push(reads.map_or_else(String::new, |x| x.0.to_string()));
                fields.push(reads.map_or_else(String::new, |x| x.1.to_string()));
                fields.extend(
                    [
                        trace.ret_offset(),
                        heads as u64,
                        declared_heads as u64,
                        edges as u64,
                        declared_edges as u64,
                        returns as u64,
                        p.bytes().len() as u64,
                        p.heads().len() as u64,
                        p.calls()[0],
                        p.continuations()[0],
                        p.outer_ret(),
                        p.subject_rsp_delta(),
                        2,
                        2,
                        2,
                        2,
                    ]
                    .map(|n| n.to_string()),
                );
                assert_eq!(fields.len(), 31);
                rows.push_str(&fields.join(","));
                rows.push('\n');
                assert!(rows.len() <= 65536 && coverage.len() <= 65536);
                std::fs::write(output.join("copied-rust-pairs.csv"), &rows).unwrap();
                std::fs::write(output.join("copied-rust-coverage.csv"), &coverage).unwrap();
                drop(oracle);
                deadline.check();
                count += 1;
            }
        }
    }
    assert_eq!((count, covered), (48, 4));
    let comparisons = population.finish();
    artifact.verify().unwrap();
    current_single_main();
    deadline.check();
    let terminal = format!(
        "native-rust-invoke:profile={PROFILE}:required=48:pairs=48:children=96:comparisons={comparisons}:coverage-seeds=2:csv-cases-per-seed=16:length-cases-per-seed=8:target-calls=96:target-returns=96:real-outer-ret=96:normal-reaps=96:scope=copied-body-only:complete\n"
    );
    assert!(terminal.len() <= 1024);
    let mut out = std::io::stdout().lock();
    out.write_all(terminal.as_bytes()).unwrap();
    out.flush().unwrap();
    deadline.check();
}
