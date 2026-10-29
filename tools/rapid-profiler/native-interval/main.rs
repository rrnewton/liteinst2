//! Fixed normally loaded native interval witness; root runs one bounded mode.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

mod branch;
mod cache;
#[path = "../exact-work/truth.rs"]
mod exact_truth;
mod native_tree;
mod normal;
mod optional;
#[allow(dead_code)]
#[path = "../../../tests/support/native_interval_oracle.rs"]
mod oracle;
mod ordinary;
mod reference;
mod tree;

use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_coalesced_detailed,
};
use oracle::TraceMap;
use oracle::native_interval::{BorrowedLeafOracle, Invocation, PhaseExpectation};
use rapid_profiler::frontend::{
    FailurePoint, FunctionSpec, GroupSpec, Limits, PayloadOutcome, Session,
};
use rapid_profiler::frontend_native::{
    Attach, Journal, LoadedLeaf, NativeThread, NativeTotals, SetupRefusal, SubjectContract,
    entry_callback, exit_callback,
};
use rapid_profiler::generation::{Config, Disposition, FunctionId, Terminal};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::{Duration, Instant};

const INSTALL: u64 = 0x1ea5_0001;
const FUNCTION: FunctionId = FunctionId(1);
const STATE_SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const SUBJECT: &[u8] = include_bytes!(env!("NATIVE_INTERVAL_DSO"));
const MODE_NAMES: [&str; 4] = ["straight", "budget", "generation", "refusals"];

struct Gate {
    entered: AtomicBool,
    released: AtomicBool,
    controller_done: AtomicBool,
}
static ACTIVE_GATE: AtomicPtr<Gate> = AtomicPtr::new(std::ptr::null_mut());
fn traced_monotonic() -> Duration {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the kernel writes one initialized, live timespec. This explicit
    // syscall avoids the vDSO route while this gate is being single-stepped.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clock_gettime,
            libc::CLOCK_MONOTONIC,
            &mut time as *mut libc::timespec,
        )
    };
    if result != 0 || time.tv_sec < 0 || time.tv_nsec < 0 || time.tv_nsec >= 1_000_000_000 {
        unsafe { libc::_exit(126) };
    }
    Duration::new(time.tv_sec as u64, time.tv_nsec as u32)
}
unsafe extern "C" fn entry_gate(ordinal: u64) {
    if ordinal != 1 {
        return;
    }
    let pointer = ACTIVE_GATE.load(Ordering::Acquire);
    if pointer.is_null() {
        unsafe { libc::_exit(124) };
    }
    // SAFETY: the setup Arc and controller own the gate until child cleanup.
    let gate = unsafe { &*pointer };
    gate.entered.store(true, Ordering::Release);
    let deadline = match traced_monotonic().checked_add(Duration::from_secs(2)) {
        Some(deadline) => deadline,
        None => unsafe { libc::_exit(126) },
    };
    while !gate.released.load(Ordering::Acquire) {
        if traced_monotonic() >= deadline {
            unsafe { libc::_exit(125) };
        }
        std::thread::yield_now();
    }
}

fn current_single_main() {
    let pid = std::process::id();
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        libc::c_long::from(pid)
    );
    let tasks: Vec<_> = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(tasks, vec![std::ffi::OsString::from(pid.to_string())]);
}
fn directory(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    std::fs::create_dir(&path).unwrap();
    path
}
fn protection(page: u64, flags: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(page as usize as *mut libc::c_void, 4096, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}
fn assert_rx(page: u64) {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let row = maps
        .lines()
        .find(|line| {
            let (a, b) = line
                .split_whitespace()
                .next()
                .unwrap()
                .split_once('-')
                .unwrap();
            u64::from_str_radix(a, 16).unwrap() <= page
                && page + 4096 <= u64::from_str_radix(b, 16).unwrap()
        })
        .unwrap();
    assert_eq!(row.split_whitespace().nth(1), Some("r-xp"));
}

fn cohorts(mode: &str) -> Vec<Vec<u64>> {
    match mode {
        "straight" => vec![vec![0, 1]],
        "budget" => vec![vec![0, 1, 2], vec![1, 2, 3]],
        "generation" => vec![vec![0, 0], vec![1, 1]],
        _ => unreachable!(),
    }
}

fn run(mode: &str, subject: &Path, output: &Path) {
    current_single_main();
    // SAFETY: fixed private DSO, no foreign calls or saved contexts; exact input
    // bytes are independently embedded by the preceding authenticated compiler.
    let leaf = unsafe { LoadedLeaf::load(subject, SUBJECT, SubjectContract::LEAF) }.unwrap();
    leaf.admit(leaf.entry(), leaf.bias_object(), SubjectContract::LEAF)
        .unwrap();
    std::fs::write(
        output.join("loader-before.maps"),
        std::fs::read("/proc/self/maps").unwrap(),
    )
    .unwrap();
    std::fs::write(output.join("source-page.bin"), leaf.original_page()).unwrap();
    std::fs::write(output.join("loader.json"), leaf.identity_record()).unwrap();
    if mode == "refusals" {
        refusals(leaf, subject, output);
        permission_refusals(leaf, output);
        return;
    }
    let mut calls = 0;
    for (case, arguments) in cohorts(mode).iter().enumerate() {
        let case_dir = directory(output, &format!("case-{case}"));
        let oracle = unsafe {
            BorrowedLeafOracle::new(
                leaf.page(),
                leaf.entry(),
                leaf.invoke(),
                leaf.terminal(),
                &leaf.immutable_extents(),
            )
        };
        let journal = Journal::allocate().unwrap();
        let install = INSTALL.checked_add(case as u64).unwrap();
        let code_generation = case as u64 + 1;
        let session = Arc::new(
            Session::new(
                install,
                &[FunctionSpec {
                    function: FUNCTION,
                    group: 0,
                }],
                &[GroupSpec { mandatory: true }],
                Limits {
                    epochs: 2,
                    threads: 1,
                    depth: 4,
                    records_per_epoch: 16,
                    actions: 16,
                },
            )
            .unwrap(),
        );
        let config = Config {
            retained_per_function: if mode == "budget" { 1 } else { 16 },
            max_inflight: 4,
            max_invocations: 16,
        };
        let g1 = session.stage(config).unwrap();
        let g2 = session.stage(config).unwrap();
        session.publish(&g1, FailurePoint::None).unwrap();
        let (stack_start, stack_end) = oracle.stack_range();
        let attach = Attach {
            install,
            function: FUNCTION,
            entry: leaf.entry(),
            ret: leaf.entry() + 18,
            stack_start,
            stack_end,
            registration: 1,
            after_entry: None,
        };
        let invocations: Vec<_> = arguments
            .iter()
            .enumerate()
            .map(|(i, &argument)| Invocation {
                argument,
                state_seed: STATE_SEEDS[i % 2],
            })
            .collect();
        let count = arguments.len() as u64;
        let child_setup = |installed: bool| {
            let session = Arc::clone(&session);
            let g1 = g1.clone();
            let g2 = g2.clone();
            let crossing = installed && mode == "generation";
            move || {
                let gate = Arc::new(Gate {
                    entered: AtomicBool::new(false),
                    released: AtomicBool::new(false),
                    controller_done: AtomicBool::new(false),
                });
                ACTIVE_GATE.store(Arc::as_ptr(&gate).cast_mut(), Ordering::Release);
                let controller = if crossing {
                    let session = Arc::clone(&session);
                    let gate = Arc::clone(&gate);
                    let old = g1.clone();
                    let new = g2.clone();
                    Some(std::thread::spawn(move || {
                        let deadline = Instant::now() + Duration::from_secs(2);
                        while !gate.entered.load(Ordering::Acquire) {
                            assert!(Instant::now() < deadline, "controller entry handshake");
                            std::thread::sleep(Duration::from_micros(100));
                        }
                        assert_eq!(old.reservations(), 1);
                        old.close();
                        assert!(old.try_report().is_none(), "pre-RET owner cannot drain");
                        session.publish(&new, FailurePoint::None).unwrap();
                        assert_eq!(old.reservations(), 1);
                        gate.controller_done.store(true, Ordering::Release);
                        gate.released.store(true, Ordering::Release);
                    }))
                } else {
                    None
                };
                let mut attach = attach;
                if crossing {
                    attach.after_entry = Some(entry_gate);
                }
                let registration =
                    unsafe { NativeThread::attach(&session, attach, journal) }.unwrap();
                move || {
                    if let Some(controller) = controller {
                        let deadline = Instant::now() + Duration::from_secs(2);
                        while !controller.is_finished() {
                            assert!(Instant::now() < deadline, "controller join deadline");
                            std::thread::sleep(Duration::from_micros(100));
                        }
                        controller.join().unwrap();
                        assert!(gate.controller_done.load(Ordering::Acquire));
                    }
                    let expected = if !installed {
                        NativeTotals::default()
                    } else if mode == "budget" {
                        NativeTotals {
                            entries: count,
                            returns: count,
                            completed: 1,
                            refused: count - 1,
                        }
                    } else {
                        NativeTotals {
                            entries: count,
                            returns: count,
                            completed: count,
                            refused: 0,
                        }
                    };
                    assert_eq!(registration.detach().unwrap(), expected);
                    g1.close();
                    g2.close();
                    let r1 = g1.try_report().expect("closed original owner drained");
                    let r2 = g2.try_report().expect("closed replacement owner drained");
                    let rows1: Vec<_> = r1.records().collect();
                    let rows2: Vec<_> = r2.records().collect();
                    assert_eq!(
                        rows1.len(),
                        if !installed {
                            0
                        } else if crossing || mode == "budget" {
                            1
                        } else {
                            count as usize
                        }
                    );
                    assert_eq!(rows2.len(), usize::from(crossing));
                    for (rows, generation, ordinal_base) in
                        [(&rows1, g1.generation(), 1), (&rows2, g2.generation(), 2)]
                    {
                        for (i, row) in rows.iter().enumerate() {
                            assert_eq!(row.record.admission.generation, generation);
                            assert_eq!(row.record.admission.function, FUNCTION);
                            assert_eq!(row.record.admission.invocation, i);
                            assert_eq!(row.record.admission.entry_value, ordinal_base + i as u64);
                            // Terminal values use the zero-based invocation within this generation.
                            // Entry and payload values retain the native pair ordinal.
                            assert!(
                                matches!(row.record.terminal, Some(Terminal::Completed { value, disposition: Disposition::Retained { rank } }) if value == i as u64 && rank == i)
                            );
                            let payload = row.payload.unwrap();
                            assert_eq!(payload.admission, row.record.admission);
                            assert_eq!(payload.thread, 1);
                            assert_eq!(payload.start_sequence, ordinal_base + i as u64 - 1);
                            assert!(
                                matches!(payload.outcome, PayloadOutcome::Completed { completed_children: 0, end: rapid_profiler::frontend::Observation::Value(value) } if value == ordinal_base + i as u64)
                            );
                        }
                    }
                    ACTIVE_GATE.store(std::ptr::null_mut(), Ordering::Release);
                }
            }
        };
        let original_dir = directory(&case_dir, "original");
        let trace = oracle.original(
            &invocations,
            journal.address(),
            child_setup(false),
            &original_dir,
        );
        leaf.verify(false).unwrap();

        let scope = AddressRange::new(leaf.entry(), 19).unwrap();
        // Identity is process-local and nonreused; whole file/body/map identity is
        // separately authenticated by LoadedLeaf, never inferred from this tag.
        let identity = CodeIdentity {
            source: SourceIdentity([0x1e; 32]),
            mapping: leaf.entry(),
            generation: code_generation,
        };
        let entries = LegalEntrySet {
            identity,
            scope,
            provenance: EntryProvenance::Declared(
                "fixed complete normally loaded 19-byte leaf".into(),
            ),
            completeness: EntryCompleteness::Complete,
            entries: vec![LegalEntry {
                address: leaf.entry(),
                requires_endbr: false,
            }],
            resumes: ResumeObligation::NoneExist,
        };
        let controls = [
            ProbeControl::new(entry_callback, true),
            ProbeControl::new(exit_callback, true),
        ];
        let actions = [
            ControlledAction {
                logical_pc: leaf.entry(),
                control: controls[0].clone(),
            },
            ControlledAction {
                logical_pc: leaf.entry() + 18,
                control: controls[1].clone(),
            },
        ];
        let allocation = AllocationPolicy::near(leaf.entry()).unwrap();
        assert_eq!(
            (
                allocation.max_candidates,
                allocation.max_mappings,
                allocation.max_mapped_bytes
            ),
            (256, 1, 8192)
        );
        let planned = plan_coalesced_detailed(
            &InstallRequest {
                identity,
                code: leaf.code(),
                base_address: leaf.entry(),
                function: scope,
                block: scope,
                logical_pc: leaf.entry(),
                entries: &entries,
                hook: entry_callback,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 80,
                    max_sites: 1,
                },
            },
            &actions,
        )
        .expect("required fixed coalesced leaf, no refusal substitution");
        assert_eq!(planned.metrics().displaced_bytes, 19);
        assert_eq!(planned.image().instruction_boundaries().len(), 5);
        assert_eq!(
            planned
                .image()
                .instruction_boundaries()
                .iter()
                .map(|&(pc, _)| pc - leaf.entry())
                .collect::<Vec<_>>(),
            [0, 5, 12, 15, 18]
        );
        let edits: Vec<_> = planned
            .plan()
            .parts()
            .writes
            .iter()
            .map(|e| (e.address, e.bytes.clone()))
            .collect();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].0, leaf.entry());
        assert_eq!(edits[0].1.len(), 19, "complete authenticated source span");
        let ranges: Vec<_> = planned
            .plan()
            .parts()
            .dependencies
            .iter()
            .copied()
            .chain(planned.plan().parts().allocations.iter().map(|a| a.range))
            .collect();
        current_single_main();
        // No child remains; no subject pointer is made callable outside this
        // closed fixture. The exclusive module borrow represents that lease.
        let page = leaf.page();
        let pointer = leaf.entry() as usize as *mut u8;
        protection(page, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        let (mut installed, _) = {
            let mut lease = unsafe { QuiescenceLease::new(leaf, identity, ranges.clone()) };
            let result = unsafe {
                planned.publish_with(pointer, &mut lease, || {
                    protection(page, libc::PROT_READ | libc::PROT_EXEC)
                })
            };
            match result {
                Ok(value) => {
                    assert!(!lease.is_poisoned());
                    value
                }
                Err(failure) => {
                    if failure.stage == FailureStage::BeforeWrite {
                        protection(page, libc::PROT_READ | libc::PROT_EXEC).unwrap();
                    }
                    panic!("publication failure remains failed and gated: {failure:?}");
                }
            }
        };
        assert_rx(page);
        leaf.verify(true).unwrap();
        oracle.assert_publication(&edits);
        let generated_range = planned.image().address()
            ..planned.image().address() + planned.image().bytes().len() as u64;
        let mut map = TraceMap {
            boundaries: planned.image().instruction_boundaries().to_vec(),
            gateways: vec![leaf.entry()],
            generated_ranges: vec![generated_range],
        };
        map.boundaries.push((leaf.terminal(), leaf.terminal()));
        let image = planned.image();
        let mut physical = std::collections::BTreeSet::new();
        for &(_, generated) in image.instruction_boundaries() {
            assert!(
                (image.address()..image.address() + image.bytes().len() as u64)
                    .contains(&generated)
            );
            assert!(physical.insert(generated));
        }
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    image.address() as usize as *const u8,
                    image.bytes().len(),
                )
            },
            image.bytes()
        );
        std::fs::write(case_dir.join("generated.bin"), image.bytes()).unwrap();
        std::fs::write(case_dir.join("source-edit.bin"), &edits[0].1).unwrap();
        std::fs::write(case_dir.join("plan.json"), format!("{{\"source\":{},\"identity_generation\":{},\"displaced_bytes\":19,\"image\":{},\"image_bytes\":{},\"allocation_attempts\":{},\"boundaries\":{:?}}}\n",
            leaf.entry(), code_generation, image.address(), image.bytes().len(), planned.metrics().allocation_attempts,
            image.instruction_boundaries().iter().map(|&(a,b)| [a,b]).collect::<Vec<_>>())).unwrap();
        let mut events = Vec::new();
        for i in 0..arguments.len() {
            let ordinal = i as u64 + 1;
            let refused = mode == "budget" && i > 0;
            let generation = if refused {
                0
            } else if mode == "generation" && i == 1 {
                g2.generation().get()
            } else {
                g1.generation().get()
            };
            let invocation = if refused || mode == "generation" {
                1
            } else {
                ordinal
            };
            events.push([
                if refused { 3 } else { 1 },
                ordinal,
                leaf.entry(),
                oracle.rsp(),
                oracle.terminal(),
                generation,
                invocation,
            ]);
            events.push([
                if refused { 4 } else { 2 },
                ordinal,
                leaf.entry() + 18,
                oracle.rsp(),
                oracle.terminal(),
                generation,
                invocation,
            ]);
        }
        std::fs::write(
            case_dir.join("expected-events.json"),
            format!("{events:?}\n"),
        )
        .unwrap();
        let installed_dir = directory(&case_dir, "installed");
        oracle.compare(
            &trace,
            &map,
            PhaseExpectation {
                journal: journal.address(),
                events: &events,
                owned_threads: if mode == "generation" { 2 } else { 1 },
            },
            child_setup(true),
            &installed_dir,
        );
        leaf.verify(true).unwrap();
        oracle.assert_publication(&edits);

        current_single_main();
        protection(page, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        {
            let mut lease = unsafe { QuiescenceLease::new(leaf, identity, ranges) };
            let result = unsafe {
                installed.retire_with(&mut lease, || {
                    protection(page, libc::PROT_READ | libc::PROT_EXEC)
                })
            };
            if let Err(failure) = result {
                if failure.stage == FailureStage::BeforeWrite {
                    protection(page, libc::PROT_READ | libc::PROT_EXEC).unwrap();
                }
                panic!("retirement failure remains failed and gated: {failure:?}");
            }
            assert!(!lease.is_poisoned());
        }
        assert!(installed.is_retired());
        assert_rx(page);
        leaf.verify(false).unwrap();
        oracle.assert_publication(&[]);
        let identity_map = TraceMap {
            boundaries: [0, 5, 12, 15, 18]
                .map(|offset| (leaf.entry() + offset, leaf.entry() + offset))
                .into_iter()
                .chain([(leaf.terminal(), leaf.terminal())])
                .collect(),
            gateways: vec![],
            generated_ranges: vec![],
        };
        let retired_dir = directory(&case_dir, "retired");
        oracle.compare(
            &trace,
            &identity_map,
            PhaseExpectation {
                journal: journal.address(),
                events: &[],
                owned_threads: 1,
            },
            child_setup(false),
            &retired_dir,
        );
        // Even after source retirement and model drain, retain every generated
        // owner/control. Pre-RET completion never authorizes code reclamation.
        std::mem::forget(installed);
        std::mem::forget(controls);
        calls += arguments.len();
        std::fs::write(case_dir.join("truth.json"), format!("{{\"arguments\":{arguments:?},\"state_seeds\":{STATE_SEEDS:?},\"install\":{install},\"identity_generation\":{code_generation},\"g1\":{},\"g2\":{},\"calls_per_phase\":{},\"heads\":[0,5,12,15,18],\"instructions_per_call\":5,\"phases\":[\"original\",\"installed\",\"retired\"]}}\n", g1.generation().get(), g2.generation().get(), arguments.len())).unwrap();
    }
    current_single_main();
    leaf.verify(false).unwrap();
    std::fs::write(
        output.join("loader-after.maps"),
        std::fs::read("/proc/self/maps").unwrap(),
    )
    .unwrap();
    let (completed, refused) = match mode {
        "straight" => (2, 0),
        "budget" => (2, 4),
        "generation" => (4, 0),
        _ => unreachable!(),
    };
    println!(
        "native-leaf:{mode}:calls_per_phase={calls}:phases=3:visits_per_phase={}:events={}:completed={completed}:refused={refused}",
        calls * 5,
        calls * 2
    );
}

fn refusals(leaf: &mut LoadedLeaf, subject: &Path, output: &Path) {
    let before = leaf.original_page().to_vec();
    let mut wrong_bytes = SUBJECT.to_vec();
    wrong_bytes[0] ^= 1;
    let mismatch = unsafe { LoadedLeaf::load(subject, &wrong_bytes, SubjectContract::LEAF) };
    assert!(matches!(mismatch, Err(SetupRefusal::SourceBytes)));
    unchanged_refusal(leaf, &before);
    let mut cases = vec!["source-byte-mismatch"];
    assert_eq!(
        leaf.admit(leaf.entry() + 1, leaf.bias_object(), SubjectContract::LEAF),
        Err(SetupRefusal::SymbolOwner)
    );
    unchanged_refusal(leaf, &before);
    cases.push("foreign-selected-symbol");
    assert_eq!(
        leaf.admit(leaf.entry(), leaf.bias_object() + 8, SubjectContract::LEAF),
        Err(SetupRefusal::Relocation)
    );
    unchanged_refusal(leaf, &before);
    cases.push("wrong-relocated-pointer");
    let mut contract = SubjectContract::LEAF;
    contract.exit = 17;
    assert_eq!(
        leaf.admit(leaf.entry(), leaf.bias_object(), contract),
        Err(SetupRefusal::EntryExit)
    );
    unchanged_refusal(leaf, &before);
    cases.push("incomplete-entry-exit-set");
    contract = SubjectContract::LEAF;
    contract.no_active_ibt = false;
    assert_eq!(
        leaf.admit(leaf.entry(), leaf.bias_object(), contract),
        Err(SetupRefusal::Cet)
    );
    unchanged_refusal(leaf, &before);
    cases.push("unsupported-cet-policy");
    contract = SubjectContract::LEAF;
    contract.ordinary_ret_only = false;
    assert_eq!(
        leaf.admit(leaf.entry(), leaf.bias_object(), contract),
        Err(SetupRefusal::ExitSemantics)
    );
    unchanged_refusal(leaf, &before);
    cases.push("unsupported-exit-semantics");
    leaf.verify(false).unwrap();
    assert_rx(leaf.page());
    assert_eq!(
        unsafe { std::slice::from_raw_parts(leaf.page() as usize as *const u8, 4096) },
        before
    );
    std::fs::write(output.join("refusals.txt"), cases.join("\n") + "\n").unwrap();
    std::fs::write(
        output.join("loader-after.maps"),
        std::fs::read("/proc/self/maps").unwrap(),
    )
    .unwrap();
    println!("native-leaf:refusals:required=6:beforewrite=6:source-page-unchanged");
}
fn unchanged_refusal(leaf: &mut LoadedLeaf, original: &[u8]) {
    leaf.verify(false).unwrap();
    assert_rx(leaf.page());
    assert_eq!(
        unsafe { std::slice::from_raw_parts(leaf.page() as usize as *const u8, 4096) },
        original
    );
}

struct HeaderReadOnly(u64);
impl Drop for HeaderReadOnly {
    fn drop(&mut self) {
        // Restore on both the ordinary path and an assertion unwind. A failed
        // restoration is fatal, never permission to continue another control.
        if protection(self.0, libc::PROT_READ).is_err() {
            unsafe { libc::_exit(126) };
        }
    }
}
fn mapping_page(fields: &[String], page: u64) -> Vec<String> {
    assert!(fields.len() >= 6);
    assert_eq!(page & 4095, 0);
    let page_end = page.checked_add(4096).unwrap();
    let (low, high) = fields[0].split_once('-').unwrap();
    let low = u64::from_str_radix(low, 16).unwrap();
    let high = u64::from_str_radix(high, 16).unwrap();
    assert!(low <= page && page_end <= high);
    let offset = u64::from_str_radix(&fields[2], 16)
        .unwrap()
        .checked_add(page.checked_sub(low).unwrap())
        .unwrap();
    let mut projected = fields.to_vec();
    projected[0] = format!("{page:x}-{page_end:x}");
    projected[2] = format!("{offset:x}");
    projected
}
fn header_mapping(maps: &str, page: u64) -> Vec<String> {
    assert!(maps.len() <= 1024 * 1024);
    let rows: Vec<_> = maps
        .lines()
        .filter(|line| {
            let (low, high) = line
                .split_whitespace()
                .next()
                .unwrap()
                .split_once('-')
                .unwrap();
            u64::from_str_radix(low, 16).unwrap() <= page
                && page < u64::from_str_radix(high, 16).unwrap()
        })
        .collect();
    assert_eq!(rows.len(), 1);
    let fields: Vec<_> = rows[0].split_whitespace().map(str::to_string).collect();
    mapping_page(&fields, page)
}
fn module_mapping_pages(
    maps: &str,
    header: &[String],
) -> std::collections::BTreeMap<u64, Vec<String>> {
    assert!(maps.len() <= 1024 * 1024);
    assert!(header.len() >= 6);
    let mut pages = std::collections::BTreeMap::new();
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().map(str::to_string).collect();
        assert!(fields.len() >= 5);
        let same_file = fields[3..5] == header[3..5];
        let same_path = fields.len() >= 6 && fields[5..] == header[5..];
        if !same_file && !same_path {
            continue;
        }
        let (low, high) = fields[0].split_once('-').unwrap();
        let low = u64::from_str_radix(low, 16).unwrap();
        let high = u64::from_str_radix(high, 16).unwrap();
        assert!(low < high);
        assert_eq!(low & 4095, 0);
        assert_eq!(high & 4095, 0);
        // Four admitted <=64-KiB loads need at most 17 pages each. An
        // unexpected extra alias or oversized extent fails this fixed fixture.
        let count = usize::try_from((high - low) / 4096).unwrap();
        assert!(pages.len().checked_add(count).unwrap() <= 4 * 17);
        for address in (low..high).step_by(4096) {
            assert!(
                pages
                    .insert(address, mapping_page(&fields, address))
                    .is_none()
            );
        }
    }
    assert!(!pages.is_empty());
    pages
}
fn permission_refusals(leaf: &mut LoadedLeaf, output: &Path) {
    current_single_main();
    leaf.verify(false).unwrap();
    let page = leaf.header_page();
    assert_ne!(page, leaf.page());
    let original_source = leaf.original_page().to_vec();
    let original_header =
        unsafe { std::slice::from_raw_parts(page as usize as *const u8, 4096) }.to_vec();
    let before_maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let before_row = header_mapping(&before_maps, page);
    assert_eq!(before_row[1], "r--p");
    assert_eq!(u64::from_str_radix(&before_row[2], 16).unwrap(), 0);
    let before_module = module_mapping_pages(&before_maps, &before_row);
    assert_eq!(before_module.get(&page), Some(&before_row));
    std::fs::write(output.join("permission-header-before.maps"), before_maps).unwrap();
    std::fs::write(
        output.join("permission-header-before.bin"),
        &original_header,
    )
    .unwrap();
    let mut cases = Vec::new();
    for (name, flags, permissions) in [
        ("writable", libc::PROT_READ | libc::PROT_WRITE, "rw-p"),
        ("executable", libc::PROT_READ | libc::PROT_EXEC, "r-xp"),
    ] {
        let restore = HeaderReadOnly(page);
        protection(page, flags).unwrap();
        let mutated_maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let mut expected_row = before_row.clone();
        expected_row[1] = permissions.to_string();
        assert_eq!(header_mapping(&mutated_maps, page), expected_row);
        let mut expected_module = before_module.clone();
        expected_module.get_mut(&page).unwrap()[1] = permissions.to_string();
        assert_eq!(
            module_mapping_pages(&mutated_maps, &before_row),
            expected_module
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(page as usize as *const u8, 4096) },
            original_header
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(leaf.page() as usize as *const u8, 4096) },
            original_source
        );
        assert_rx(leaf.page());
        // Every exact page range, affine file offset, owner, pathname and byte
        // remains checked. Only the header permission changes; VMA splitting
        // or merging cannot hide any module-page semantic change. Raw maps
        // below remain complete and unmodified.
        assert_eq!(leaf.verify(false), Err(SetupRefusal::SymbolOwner));
        std::fs::write(
            output.join(format!("permission-header-{name}.maps")),
            mutated_maps,
        )
        .unwrap();
        drop(restore);
        unchanged_refusal(leaf, &original_source);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(page as usize as *const u8, 4096) },
            original_header
        );
        let restored_maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        assert_eq!(header_mapping(&restored_maps, page), before_row);
        assert_eq!(
            module_mapping_pages(&restored_maps, &before_row),
            before_module
        );
        std::fs::write(
            output.join(format!("permission-header-{name}-restored.maps")),
            restored_maps,
        )
        .unwrap();
        cases.push(format!("header-load-{name}"));
    }
    std::fs::write(output.join("permission-header-after.bin"), unsafe {
        std::slice::from_raw_parts(page as usize as *const u8, 4096)
    })
    .unwrap();
    std::fs::write(
        output.join("permission-refusals.txt"),
        cases.join("\n") + "\n",
    )
    .unwrap();
    current_single_main();
    println!("native-leaf:permissions:required=2:beforewrite=2:header-page-restored");
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).and_then(|s| s.to_str()) == Some("tree-batch-state") {
        assert_eq!(
            args.len(),
            5,
            "tree-batch-state CANDIDATE_ELF TRUSTED_EXPECTED_ELF NEW_OUTPUT_DIRECTORY"
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[4]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        tree::batch::run(&subject, &expected, &output);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("tree-return-word-refusal") {
        assert_eq!(
            args.len(),
            5,
            "tree-return-word-refusal CANDIDATE_ELF TRUSTED_EXPECTED_ELF NEW_OUTPUT_DIRECTORY"
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[4]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        tree::run_refusal(&subject, &expected, &output);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("native-tree-state") {
        assert_eq!(
            args.len(),
            5,
            "native-tree-state CANDIDATE TRUSTED NEW_OUTPUT_DIRECTORY"
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[4]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        native_tree::run(&subject, &expected, &output);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("tree-state") {
        assert_eq!(
            args.len(),
            5,
            "tree-state CANDIDATE_ELF TRUSTED_EXPECTED_ELF NEW_OUTPUT_DIRECTORY"
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[4]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        tree::run(&subject, &expected, &output);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("cache-state") {
        assert_eq!(
            args.len(),
            5,
            "cache-state CANDIDATE_ELF TRUSTED_EXPECTED_ELF NEW_OUTPUT_DIRECTORY"
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[4]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        cache::run(&subject, &expected, &output);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("exact-reference-state") {
        assert_eq!(
            args.len(),
            5,
            "exact-reference-state CANDIDATE_ELF TRUSTED_EXPECTED_ELF NEW_OUTPUT_DIRECTORY"
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[4]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        reference::run(&subject, &expected, &output);
        return;
    }
    if matches!(
        args.get(1).and_then(|s| s.to_str()),
        Some("optional-fast-state" | "optional-slow-state")
    ) {
        assert_eq!(
            args.len(),
            5,
            "optional-state CANDIDATE_ELF TRUSTED_EXPECTED_ELF NEW_OUTPUT_DIRECTORY"
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[4]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        optional::run(
            &subject,
            &expected,
            &output,
            args[1] == "optional-slow-state",
        );
        return;
    }
    if matches!(
        args.get(1).and_then(|s| s.to_str()),
        Some("exact-state" | "exact-concurrent-state")
    ) {
        assert_eq!(
            args.len(),
            5,
            "exact-state CANDIDATE_ELF TRUSTED_EXPECTED_ELF NEW_OUTPUT_DIRECTORY"
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[4]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        if args[1] == "exact-concurrent-state" {
            ordinary::run_exact_concurrent(&subject, &expected, &output);
        } else {
            ordinary::run_exact(&subject, &expected, &output);
        }
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-rust-invoke-state") {
        let deadline = oracle::native_ordinary::strnlen::Deadline::start();
        assert_eq!(
            args.len(),
            11,
            "normal-rust-invoke-state CANDIDATE FINAL CSV_VA CSV_LENGTH LENGTH_VA LENGTH_LENGTH APP APP_FINAL OUTPUT"
        );
        let arguments = oracle::native_ordinary::normal_caller::module::Arguments::parse(
            "16",
            args[4].to_str().unwrap(),
            args[5].to_str().unwrap(),
            args[6].to_str().unwrap(),
            args[7].to_str().unwrap(),
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let app = PathBuf::from(&args[8]).canonicalize().unwrap();
        let app_expected = PathBuf::from(&args[9]).canonicalize().unwrap();
        let output = PathBuf::from(&args[10]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        deadline.check();
        normal::copied_rust::run(
            &subject,
            &expected,
            arguments,
            &app,
            &app_expected,
            &output,
            deadline,
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-module-state") {
        let deadline = oracle::native_ordinary::strnlen::Deadline::start();
        assert_eq!(
            args.len(),
            12,
            "normal-module-state K CANDIDATE FINAL CSV_VA CSV_LENGTH LENGTH_VA LENGTH_LENGTH CALLER_CANDIDATE CALLER_FINAL OUTPUT"
        );
        let arguments = oracle::native_ordinary::normal_caller::module::Arguments::parse(
            args[2].to_str().unwrap(),
            args[5].to_str().unwrap(),
            args[6].to_str().unwrap(),
            args[7].to_str().unwrap(),
            args[8].to_str().unwrap(),
        );
        let subject = PathBuf::from(&args[3]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[4]).canonicalize().unwrap();
        let caller = PathBuf::from(&args[9]).canonicalize().unwrap();
        let caller_expected = PathBuf::from(&args[10]).canonicalize().unwrap();
        let output = PathBuf::from(&args[11]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        deadline.check();
        normal::module::run(
            &subject,
            &expected,
            arguments,
            &caller,
            &caller_expected,
            &output,
            deadline,
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-module-session-state") {
        let deadline = oracle::native_ordinary::strnlen::Deadline::start();
        assert_eq!(
            args.len(),
            12,
            "normal-module-session-state K CANDIDATE FINAL CSV_VA CSV_LENGTH LENGTH_VA LENGTH_LENGTH CALLER_CANDIDATE CALLER_FINAL OUTPUT"
        );
        let arguments = oracle::native_ordinary::normal_caller::module::SessionArguments::parse(
            args[2].to_str().unwrap(),
            args[5].to_str().unwrap(),
            args[6].to_str().unwrap(),
            args[7].to_str().unwrap(),
            args[8].to_str().unwrap(),
        );
        let subject = PathBuf::from(&args[3]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[4]).canonicalize().unwrap();
        let caller = PathBuf::from(&args[9]).canonicalize().unwrap();
        let caller_expected = PathBuf::from(&args[10]).canonicalize().unwrap();
        let output = PathBuf::from(&args[11]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        deadline.check();
        normal::module::session::run(
            &subject,
            &expected,
            arguments,
            &caller,
            &caller_expected,
            &output,
            deadline,
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-csv-state") {
        let deadline = oracle::native_ordinary::strnlen::Deadline::start();
        assert_eq!(
            args.len(),
            9,
            "normal-csv-state CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL OUTPUT"
        );
        let arguments = oracle::native_ordinary::normal_caller::csv::Arguments::parse(
            args[4].to_str().unwrap(),
            args[5].to_str().unwrap(),
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let caller = PathBuf::from(&args[6]).canonicalize().unwrap();
        let caller_expected = PathBuf::from(&args[7]).canonicalize().unwrap();
        let output = PathBuf::from(&args[8]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        deadline.check();
        normal::csv::run(
            &subject,
            &expected,
            arguments,
            &caller,
            &caller_expected,
            &output,
            deadline,
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-reference-state") {
        let deadline = oracle::native_ordinary::strnlen::Deadline::start();
        assert_eq!(
            args.len(),
            9,
            "normal-reference-state CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL OUTPUT"
        );
        let arguments = oracle::native_ordinary::strnlen::Arguments::parse(
            args[4].to_str().unwrap(),
            args[5].to_str().unwrap(),
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let caller = PathBuf::from(&args[6]).canonicalize().unwrap();
        let caller_expected = PathBuf::from(&args[7]).canonicalize().unwrap();
        let output = PathBuf::from(&args[8]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        deadline.check();
        normal::reference::run(
            &subject,
            &expected,
            arguments,
            &caller,
            &caller_expected,
            &output,
            deadline,
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-exact-state") {
        let deadline = oracle::native_ordinary::strnlen::Deadline::start();
        assert_eq!(
            args.len(),
            9,
            "normal-exact-state CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL OUTPUT"
        );
        let arguments = oracle::native_ordinary::strnlen::Arguments::parse(
            args[4].to_str().unwrap(),
            args[5].to_str().unwrap(),
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let caller = PathBuf::from(&args[6]).canonicalize().unwrap();
        let caller_expected = PathBuf::from(&args[7]).canonicalize().unwrap();
        let output = PathBuf::from(&args[8]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        deadline.check();
        normal::exact::run(
            &subject,
            &expected,
            arguments,
            &caller,
            &caller_expected,
            &output,
            deadline,
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-state") {
        let deadline = oracle::native_ordinary::strnlen::Deadline::start();
        assert_eq!(
            args.len(),
            9,
            "normal-state CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL OUTPUT"
        );
        let arguments = oracle::native_ordinary::strnlen::Arguments::parse(
            args[4].to_str().unwrap(),
            args[5].to_str().unwrap(),
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let caller = PathBuf::from(&args[6]).canonicalize().unwrap();
        let caller_expected = PathBuf::from(&args[7]).canonicalize().unwrap();
        let output = PathBuf::from(&args[8]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        deadline.check();
        normal::run(
            &subject,
            &expected,
            arguments,
            &caller,
            &caller_expected,
            &output,
            deadline,
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("strnlen-state") {
        let deadline = oracle::native_ordinary::strnlen::Deadline::start();
        assert_eq!(
            args.len(),
            7,
            "strnlen-state CANDIDATE FINAL ELF_VA LENGTH OUTPUT"
        );
        let arguments = oracle::native_ordinary::strnlen::Arguments::parse(
            args[4].to_str().unwrap(),
            args[5].to_str().unwrap(),
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[6]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        deadline.check();
        ordinary::strnlen::run(&subject, &expected, arguments, &output, deadline);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("selected-state") {
        assert_eq!(
            args.len(),
            7,
            "selected-state CANDIDATE FINAL ELF_VA LENGTH OUTPUT"
        );
        let arguments = oracle::native_ordinary::selected::Arguments::parse(
            args[4].to_str().unwrap(),
            args[5].to_str().unwrap(),
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[6]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        ordinary::selected::run(&subject, &expected, arguments, &output);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("ordinary-state") {
        assert_eq!(
            args.len(),
            5,
            "ordinary-state CANDIDATE_ELF TRUSTED_EXPECTED_ELF NEW_OUTPUT_DIRECTORY"
        );
        let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
        let expected = PathBuf::from(&args[3]).canonicalize().unwrap();
        let output = PathBuf::from(&args[4]);
        assert!(output.is_absolute() && !output.exists());
        std::fs::create_dir(&output).unwrap();
        assert_eq!(output.canonicalize().unwrap(), output);
        ordinary::run(&subject, &expected, &output);
        return;
    }
    assert_eq!(args.len(), 4);
    let mode = args[1].to_str().unwrap();
    assert!(
        MODE_NAMES.contains(&mode)
            || [
                "two-returns-paths",
                "two-returns-budget",
                "two-returns-generation",
                "two-returns-refusals"
            ]
            .contains(&mode)
    );
    let subject = PathBuf::from(&args[2]).canonicalize().unwrap();
    let output = PathBuf::from(&args[3]);
    assert!(output.is_absolute() && !output.exists());
    std::fs::create_dir(&output).unwrap();
    assert_eq!(output.canonicalize().unwrap(), output);
    if let Some(branch_mode) = mode.strip_prefix("two-returns-") {
        branch::run(branch_mode, &subject, &output);
    } else {
        run(mode, &subject, &output);
    }
}
