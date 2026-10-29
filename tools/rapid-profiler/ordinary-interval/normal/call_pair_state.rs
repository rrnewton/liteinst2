//! Original-address Rust caller plus admitted original-E8 parent/CSV child.
//! This route owns no campaign runner and never invokes the input-session engine.
use crate::oracle::native_ordinary::normal_caller::{
    self as caller_oracle, JournalReady, NormalContext, NormalOracle, call_pair as native,
};
use crate::oracle::native_ordinary::strnlen::Deadline;
use crate::*;
use native::{Case, Ready, Scenario};
use rapid_profiler::frontend_native::{
    InstalledNormalCallPairSite, LoadedNormalCallPair, NormalCallPairContract,
    NormalCallPairSessionController, NormalCallPairSitePreparation,
    PreparedNormalCallPairSessionController, RawIntervalOwner, TrustedFunctionSelection,
};
#[allow(dead_code)]
#[path = "../../native-interval/normal/rust_invoke_artifact.rs"]
mod artifact;
mod caller;
mod check;
mod held;
mod lifecycle;
use caller::RunningCaller;
const CONTRACT: NormalCallPairContract = NormalCallPairContract {
    parent_only_external_entry: true,
    ordinary_ret_only: true,
    no_active_cet: true,
};
fn geometry(r: &Ready) -> (u64, u64, u64) {
    let parent = r.parent();
    let code = source_bytes(&r.original_sources, parent.entry, r.case.extents[0]);
    let mut decoder =
        iced_x86::Decoder::with_ip(64, &code, parent.entry, iced_x86::DecoderOptions::NONE);
    let mut call = None;
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.code() == iced_x86::Code::Call_rel32_64 {
            assert!(call.is_none());
            assert_eq!(i.near_branch_target(), r.child().entry);
            call = Some((i.ip(), i.next_ip()));
        }
    }
    let (call, cont) = call.unwrap();
    let delta = native::parent_delta(&code, parent.entry, r.child().entry);
    (call, cont, delta)
}
fn source_bytes(pages: &[(u64, Vec<u8>)], entry: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let at = entry.checked_add(i as u64).unwrap();
            let rows: Vec<_> = pages
                .iter()
                .filter(|(a, b)| *a <= at && at < a.checked_add(b.len() as u64).unwrap())
                .collect();
            assert_eq!(rows.len(), 1);
            rows[0].1[(at - rows[0].0) as usize]
        })
        .collect()
}
fn live(spans: &[(u64, Vec<u8>)], source_count: usize) {
    for (i, (a, b)) in spans.iter().enumerate() {
        let (actual_low, actual_high) =
            super::csv::mapping(*a, if i < source_count { "r-xp" } else { "r-xs" });
        assert!(actual_low <= *a && a.checked_add(b.len() as u64).unwrap() <= actual_high);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(*a as usize as *const u8, b.len()) },
            b
        );
    }
}
fn published(prep: NormalCallPairSitePreparation) -> InstalledNormalCallPairSite {
    crate::single_main();
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert!((1..=2).contains(&originals.len()));
    let sources: Vec<_> = originals
        .iter()
        .map(|s| {
            assert_eq!(s.bytes.len(), 4096);
            AddressRange::new(s.address, 4096).unwrap()
        })
        .collect();
    let mut ranges = sources.clone();
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|s| s.parts().allocations.iter().map(|a| a.range)),
    );
    let mut aliases = Vec::new();
    for &range in &sources {
        protect(range, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        aliases
            .push(unsafe { WritableAlias::new(range, range.start() as usize as *mut u8) }.unwrap());
    }
    let mut exclusive = &prep;
    let result = {
        let mut lease =
            unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
        let r = unsafe {
            planned.publish_with(&aliases, &mut lease, || {
                for &range in &sources {
                    protect(range, libc::PROT_READ | libc::PROT_EXEC)?;
                }
                Ok(())
            })
        };
        if r.is_ok() {
            assert!(!lease.is_poisoned());
        }
        r
    };
    let (installed, receipt) = match result {
        Ok(r) => r,
        Err(_) => std::process::abort(),
    };
    unsafe { prep.seal(installed, receipt) }.unwrap()
}
fn child(
    candidate: bool,
    mut context: NormalContext<'_>,
    subject: &Path,
    selections: [&TrustedFunctionSelection<'_>; 2],
    sources: &held::Sources,
    caller: &RunningCaller,
) -> i32 {
    crate::single_main();
    let deadline = context.deadline();
    deadline.check();
    sources.verify().unwrap();
    unsafe { caller.verify() }.unwrap();
    let case = context.call_pair_case();
    // SAFETY: independent complete trusted selections; original parent E8 and
    // actual child ordinary return, one main caller, no alias writers/unload/CET.
    let loaded = unsafe {
        LoadedNormalCallPair::load_selected(subject, selections[0], selections[1], CONTRACT)
    }
    .unwrap();
    let mut ready = Ready {
        caller: caller.entry(),
        caller_immutable: caller.pages(),
        functions: [
            caller_oracle::module::Function {
                entry: loaded.parent().entry(),
                heads: loaded.parent().certificate().heads().to_vec(),
                returns: loaded.parent().certificate().returns().to_vec(),
                boundaries: loaded
                    .parent()
                    .certificate()
                    .heads()
                    .iter()
                    .map(|&p| (p, p))
                    .collect(),
            },
            caller_oracle::module::Function {
                entry: loaded.child().entry(),
                heads: loaded.child().certificate().heads().to_vec(),
                returns: loaded.child().certificate().returns().to_vec(),
                boundaries: loaded
                    .child()
                    .certificate()
                    .heads()
                    .iter()
                    .map(|&p| (p, p))
                    .collect(),
            },
        ],
        immutable: loaded
            .source_pages()
            .iter()
            .map(|p| (p.address, p.bytes.clone()))
            .collect(),
        original_sources: loaded
            .source_pages()
            .iter()
            .map(|p| (p.address, p.bytes.clone()))
            .collect(),
        journal: None,
        case,
        plan: caller.plan().clone(),
        layout: [240, 416, 144, 400],
    };
    let data = context.data_address();
    let rsp = context.caller_rsp();
    let range = context.stack_range();
    let control = context.take_control();
    let output_address = context.results_address();
    let mut expected_data =
        unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) }.to_vec();
    expected_data[320..328].copy_from_slice(&case.value().to_le_bytes());
    let entry = ready.parent().entry;
    let mut original = None;
    let mut attached = None;
    let mut control_owner = None;
    if candidate {
        let prep = NormalCallPairSitePreparation::new(loaded, check::identity(entry)).unwrap();
        let plan = prep.plan();
        assert_eq!(plan.plan().originals().len(), ready.original_sources.len());
        ready.immutable = plan
            .plan()
            .final_bytes()
            .iter()
            .map(|p| (p.address, p.bytes.clone()))
            .collect();
        for f in &mut ready.functions {
            f.boundaries.clear();
        }
        for image in plan.images() {
            assert_eq!(
                image.layout().observation_stack_profile,
                liteinst2::trampoline::ObservationStackProfile::CallPair240
            );
            for &(a, b) in image.instruction_boundaries() {
                let matches: Vec<_> = ready
                    .functions
                    .iter()
                    .enumerate()
                    .filter_map(|(i, f)| f.heads.contains(&a).then_some(i))
                    .collect();
                assert_eq!(matches.len(), 1);
                ready.functions[matches[0]].boundaries.push((a, b));
            }
            ready
                .immutable
                .push((image.address(), image.bytes().to_vec()));
        }
        for f in &mut ready.functions {
            for &a in &f.heads {
                if !f.boundaries.iter().any(|(p, _)| *p == a) {
                    f.boundaries.push((a, a));
                }
            }
        }
        let site = published(prep);
        let (owner, client) = lifecycle::Owner::prepare(site, case);
        let (a, b) = owner.generations();
        let (low, high) = super::csv::mapping(range.0, "rw-p");
        assert!(low <= range.0 && range.1 <= high);
        assert!(range.0 < rsp.checked_sub(448).unwrap() && rsp + 8 <= range.1);
        let stack = unsafe { ReadableStack::new(range.0, range.1) }.unwrap();
        let journal = IntervalJournal::allocate();
        let address = journal.address();
        // SAFETY: the oracle owns, initializes and retains the entire guarded RW
        // stack. The evaluation's unsafe contract includes sufficient actual
        // callback call-stack headroom beyond the sealed XSAVE allocation; the
        // map/range checks alone do not prove a compiled callback stack bound.
        let thread = unsafe { client.attach(1, stack, journal) }.unwrap();
        assert_eq!(
            thread.totals().unwrap(),
            rapid_profiler::frontend_native::NormalCallPairTotals::default()
        );
        let (owner, tid) = lifecycle::Controller::start(owner, control, case, deadline);
        ready.journal = Some(JournalReady {
            address,
            a_generation: a,
            b_generation: b,
            helper_tid: tid,
        });
        attached = Some(thread);
        control_owner = Some(owner);
    } else {
        assert!(control.is_none());
        loaded.verify_original().unwrap();
        original = Some(loaded);
    }
    // Complete setup/source/map/byte checks happen before the ptrace-ready stop.
    // No filesystem scan is inserted between that stop and the original caller.
    sources.verify().unwrap();
    unsafe { caller.verify() }.unwrap();
    live(&ready.immutable, ready.original_sources.len());
    deadline.check();
    let mut fail = super::csv::FailStop(true);
    context.ready_call_pair(&ready);
    let input =
        unsafe { std::slice::from_raw_parts((data + 128) as usize as *const u8, case.bound()) };
    let result = unsafe { &mut *(output_address as usize as *mut u64) };
    let target: super::csv::Csv = unsafe { std::mem::transmute(entry as usize) };
    unsafe { super::csv::invoke(target, input, result) };
    assert_eq!(*result, case.value());
    assert_eq!(
        unsafe { std::slice::from_raw_parts(data as usize as *const u8, 4096) },
        expected_data
    );
    sources.verify().unwrap();
    unsafe { caller.verify() }.unwrap();
    live(&ready.immutable, ready.original_sources.len());
    deadline.check();
    if let Some(mut thread) = attached {
        assert_eq!(thread.totals().unwrap(), check::totals(case, false));
        let batch = unsafe { thread.checkpoint_after_returns() }
            .unwrap()
            .unwrap();
        check::batch(&ready, rsp, std::process::id(), &batch);
        let owner = control_owner.take().unwrap().join(deadline);
        owner.finish(&ready, &batch, &mut thread, deadline);
        let page = unsafe {
            std::slice::from_raw_parts(
                ready.journal.as_ref().unwrap().address as usize as *const u64,
                512,
            )
        };
        let mut expected = [0; 512];
        expected[2] = u64::from(std::process::id());
        assert_eq!(page, expected);
    } else {
        original.as_mut().unwrap().verify_original().unwrap();
    }
    crate::single_main();
    sources.verify().unwrap();
    unsafe { caller.verify() }.unwrap();
    live(&ready.immutable, ready.original_sources.len());
    deadline.check();
    fail.0 = false;
    0
}
pub(crate) struct Request<'a> {
    pub subject: &'a Path,
    pub expected: &'a Path,
    pub selections: [u64; 2],
    pub extents: [usize; 2],
    pub executable: &'a Path,
    pub trusted: &'a Path,
    pub output: &'a Path,
    pub cpu: usize,
}
pub(crate) fn run(
    Request {
        subject,
        expected,
        selections,
        extents,
        executable,
        trusted,
        output,
        cpu,
    }: Request<'_>,
) {
    crate::single_main();
    assert_eq!(pin(Some(cpu)), cpu);
    assert!(output.is_absolute() && !output.exists());
    std::fs::create_dir(output).unwrap();
    assert_eq!(output.canonicalize().unwrap(), output);
    let sources = held::Sources::open(subject, expected).unwrap();
    let caller = unsafe {
        RunningCaller::open(
            executable,
            trusted,
            super::csv::invoke as *const () as usize as u64,
        )
    }
    .unwrap();
    let parent =
        TrustedFunctionSelection::new(sources.bytes(), selections[0], extents[0], "csv_summary")
            .unwrap();
    let child_selection =
        TrustedFunctionSelection::new(sources.bytes(), selections[1], extents[1], "csv_fields")
            .unwrap();
    let code = [
        sources.selected(selections[0], extents[0]).unwrap(),
        sources.selected(selections[1], extents[1]).unwrap(),
    ];
    let mut population = native::Population::default();
    let mut rows = String::from(HEADER);
    let mut comparisons = 0usize;
    let mut last_deadline = None;
    for (k, seed, index, scenario) in native::keys() {
        let deadline = Deadline::start();
        last_deadline = Some(deadline);
        let case = Case::new(k, index, scenario, selections, extents);
        sources.verify().unwrap();
        unsafe { caller.verify() }.unwrap();
        let oracle = NormalOracle::new_call_pair(
            seed,
            case,
            caller.plan().clone(),
            caller.entry(),
            caller.pages(),
            code.clone(),
            deadline,
        )
        .with_call_pair_diagnostic_origin(caller.diagnostic_origin());
        let (pair, trace) = oracle.pair_call_pair(|candidate, context| {
            child(
                candidate,
                context,
                subject,
                [&parent, &child_selection],
                &sources,
                &caller,
            )
        });
        population.record(seed, case, caller.plan(), &pair, &trace);
        comparisons = comparisons.checked_add(pair.comparisons).unwrap();
        let plan = caller.plan();
        let values = [
            k as u64,
            seed,
            index as u64 + 1,
            scenario.id(),
            case.bound() as u64,
            case.fields(),
            case.value(),
            plan.bytes().len() as u64,
            plan.heads().len() as u64,
            plan.calls()[0],
            plan.continuations()[0],
            plan.outer_ret(),
            plan.subject_rsp_delta(),
            trace.stack_bytes,
            extents[0] as u64,
            trace.parent_heads.len() as u64,
            trace.parent_edges.len() as u64,
            1,
            trace.parent_visits as u64,
            trace.parent_ret_offset,
            trace.child_delta,
            extents[1] as u64,
            trace.child.heads.len() as u64,
            trace.child.edges.len() as u64,
            trace.child_declared_counts()[0] as u64,
            trace.child_declared_counts()[1] as u64,
            trace.child_declared_counts()[2] as u64,
            trace.child.visits as u64,
            trace.child.ret_offset,
            pair.comparisons as u64,
            pair.original_steps as u64,
            pair.candidate_steps as u64,
            trace.parent_generation,
            trace.child_generation,
            u64::from(scenario.sampled_child()),
            1,
            u64::from(scenario.sampled_child()),
            u64::from(scenario.sampled_child()),
            1 + u64::from(scenario.sampled_child()),
            if scenario == Scenario::RearmB { 3 } else { 2 },
            4,
            4,
            4,
            2,
            2,
        ];
        assert_eq!(values.len(), 45);
        rows.push_str(&values.map(|v| v.to_string()).join(","));
        rows.push('\n');
        assert!(rows.len() <= 524288);
        std::fs::write(output.join("call-pair-state-pairs.csv"), &rows).unwrap();
        sources.verify().unwrap();
        unsafe { caller.verify() }.unwrap();
        deadline.check();
    }
    let deadline = last_deadline.unwrap();
    deadline.check();
    let mut coverage = String::from(COVERAGE);
    for c in population.finish() {
        let row = [
            c.k as u64,
            c.scenario.id(),
            c.seed,
            c.cases as u64,
            c.parent_heads as u64,
            c.parent_edges as u64,
            c.parent_returns as u64,
            c.child_heads as u64,
            c.child_edges as u64,
            c.child_returns as u64,
            c.child_declared_heads as u64,
            c.child_declared_edges as u64,
            c.child_declared_returns as u64,
        ];
        coverage.push_str(&row.map(|v| v.to_string()).join(","));
        coverage.push('\n');
    }
    assert!(coverage.len() <= 16384);
    std::fs::write(output.join("call-pair-state-coverage.csv"), coverage).unwrap();
    sources.verify().unwrap();
    unsafe { caller.verify() }.unwrap();
    crate::single_main();
    let terminal = format!(
        "native-call-pair-state:profile=normal-call-pair-original-rust-v1:required=192:pairs=192:children=384:comparisons={comparisons}:coverage-groups=12:k-values=2:seeds=2:scenarios=3:target-calls=768:target-returns=768:real-outer-ret=384:normal-reaps=384:scope=original-caller-nested-body:complete\n"
    );
    assert!(terminal.len() <= 1024);
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    out.write_all(terminal.as_bytes()).unwrap();
    out.flush().unwrap();
    deadline.check();
}
const HEADER: &str = "k,seed,case,scenario,input_len,fields,packed,caller_extent,caller_heads,caller_call,caller_continuation,caller_ret,caller_delta,stack_bytes,parent_extent,parent_heads,parent_edges,parent_returns,parent_visits,parent_ret_offset,child_delta,child_extent,child_heads,child_edges,child_declared_heads,child_declared_edges,child_declared_returns,child_visits,child_ret_offset,comparisons,original_steps,candidate_steps,parent_generation,child_generation,child_sampled,parent_actual_children,parent_sampled_children,child_end_sequence,parent_end_sequence,history_actions,journal_events,target_calls,target_returns,outer_returns,normal_reaps\n";
const COVERAGE: &str = "k,scenario,seed,cases,parent_heads,parent_edges,parent_returns,child_heads,child_edges,child_returns,child_declared_heads,child_declared_edges,child_declared_returns\n";
