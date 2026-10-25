#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Runtime controls on unchanged emitted and published code.
//! Three bounded subprocess modes preserve the predeclared cohort. Grouped
//! masks use two fixed snapshot workers after one publication; no worker emits
//! or republishes code. Existing state comparators and trace limits are reused.

#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::bundle::{BundleBudget, PlannedBundle, WritableAlias};
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, ExpectedBytes,
    LegalEntry, LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation,
    SourceIdentity,
};
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::grouping::{BackingKind, GroupingBudget};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, InstallRequest, SearchPolicy, plan_coalesced};
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::{HookCallback, HookContext, TrampolinePlan};
use oracle::{
    HookEvent, HookEventLog, HookExpectation, Mapping, NativeOracle, NativeTrace, TraceMap,
};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const TEST: &str = "runtime_control_oracle_modes";
const ENV: &str = "LITEINST_RUNTIME_CONTROL_ORACLE_MODE";
// Leave ten seconds for outer-command startup and cleanup within 180 seconds.
// This is a newly predeclared wrapper bound, not a change to native trace limits.
const WRAPPER_BUDGET: Duration = Duration::from_secs(170);
const WORKER_BUDGET: Duration = Duration::from_secs(150);

#[test]
fn runtime_control_oracle_modes() {
    if let Ok(mode) = std::env::var(ENV) {
        match mode.as_str() {
            "emitter" => emitter_controls(),
            "single" => published_controls(false),
            "grouped" => published_controls(true),
            _ => panic!("unknown required controls mode"),
        }
        return;
    }
    // Serial modes keep CPU concurrency bounded. The isolated group mode runs
    // only this one test, then creates two ptrace controllers and at most their
    // two stopped/running trace children; the parent only waits.
    let deadline = Instant::now() + WRAPPER_BUDGET;
    for mode in ["emitter", "single", "grouped"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(ENV, mode)
            .process_group(0)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                // SAFETY: this exact owned mode and every snapshot/trace worker
                // inherit its private process group; unrelated tests do not.
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                child.wait().unwrap();
                panic!("required controls mode {mode} exhausted wrapper budget");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if !status.success() {
            // SAFETY: failure cleanup also kills any surviving owned descendants.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
        }
        assert!(
            status.success(),
            "required controls mode {mode} failed: {status}"
        );
    }
}

unsafe fn record(context: *mut HookContext, id: u64) {
    // SAFETY: the emitter supplies a live saved frame; each child has an active
    // bounded private event log. Callbacks may clobber C scratch state.
    unsafe {
        oracle::record_hook_event(id, (*context).instruction_pointer);
        core::arch::asm!("add rax, 1", "pxor xmm0, xmm0", "fninit", out("rax") _, out("xmm0") _, options(nostack));
    }
}
macro_rules! hook {
    ($name:ident, $id:expr) => {
        unsafe extern "C" fn $name(context: *mut HookContext) {
            // SAFETY: same live frame/private log contract as record.
            unsafe {
                record(context, $id);
            }
        }
    };
}
hook!(hook_a, 10);
hook!(hook_b, 20);
hook!(hook_c, 30);
hook!(hook_d, 40);
hook!(hook_e, 50);
hook!(hook_f, 60);
const CALLBACKS: [HookCallback; 6] = [hook_a, hook_b, hook_c, hook_d, hook_e, hook_f];

fn actions(pcs: &[u64]) -> Vec<ControlledAction> {
    pcs.iter()
        .zip(CALLBACKS)
        .map(|(&logical_pc, callback)| ControlledAction {
            logical_pc,
            control: ProbeControl::new(callback, false),
        })
        .collect()
}
fn events(pcs: &[u64], mask: usize) -> Vec<HookEvent> {
    pcs.iter()
        .enumerate()
        .filter(|(index, _)| mask & (1 << index) != 0)
        .map(|(index, &logical_pc)| HookEvent {
            probe_id: (index as u64 + 1) * 10,
            logical_pc,
        })
        .collect()
}
fn set_mask(controls: &[ProbeControl], mask: usize, snapshots: &[(u64, Vec<u8>)]) {
    for (index, control) in controls.iter().enumerate() {
        let before: Vec<_> = controls.iter().map(ProbeControl::is_enabled).collect();
        let clone = control.clone();
        assert_pages(snapshots);
        clone.set_enabled(mask & (1 << index) != 0);
        assert_pages(snapshots);
        assert_eq!(clone, *control);
        for (other, actual) in controls.iter().enumerate() {
            assert_eq!(
                actual.is_enabled(),
                if other == index {
                    mask & (1 << index) != 0
                } else {
                    before[other]
                },
                "toggling one control changed another"
            );
        }
    }
    for (index, control) in controls.iter().enumerate() {
        assert_eq!(control.is_enabled(), mask & (1 << index) != 0);
    }
}
fn page(address: u64) -> Vec<u8> {
    assert_eq!(address % 4096, 0);
    // SAFETY: callers supply their retained readable source/generated pages.
    unsafe { std::slice::from_raw_parts(address as usize as *const u8, 4096) }.to_vec()
}
fn assert_pages(snapshots: &[(u64, Vec<u8>)]) {
    for (address, expected) in snapshots {
        assert_eq!(
            page(*address),
            *expected,
            "runtime control changed immutable code bytes"
        );
    }
}
fn identity_map(heads: &[u64], terminal: u64) -> TraceMap {
    TraceMap {
        boundaries: heads
            .iter()
            .copied()
            .chain([terminal])
            .map(|pc| (pc, pc))
            .collect(),
        ..TraceMap::default()
    }
}
fn permissions(pointer: *mut u8, protection: i32) -> Result<(), Refusal> {
    // SAFETY: this fixture owns the complete private source page under its lease.
    if unsafe { libc::mprotect(pointer.cast(), 4096, protection) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

fn emitter_controls() {
    let code = [
        0xeb, 3, 0x48, 0x8d, 7, 0x80, 7, 1, 0x80, 0x3f, 14, 0x75, 0xf5, 0xc3,
    ];
    let oracle = NativeOracle::new(&code);
    let base = oracle.code.address();
    let offsets = [0, 2, 5, 8, 11, 13];
    let heads = offsets.map(|offset| base + offset);
    let visits: [&[u64]; 6] = [
        &[0, 5, 8, 11, 2, 5, 8, 11, 2, 5, 8, 11, 13],
        &[2, 5, 8, 11, 2, 5, 8, 11, 2, 5, 8, 11, 13],
        &[5, 8, 11, 2, 5, 8, 11, 2, 5, 8, 11, 13],
        &[8, 11, 2, 5, 8, 11, 2, 5, 8, 11, 2, 5, 8, 11, 13],
        &[11, 13],
        &[13],
    ];
    let mut originals = Vec::new();
    for seed in SEEDS {
        for (index, &entry) in heads.iter().enumerate() {
            let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
            assert_eq!(
                trace.visits(),
                visits[index]
                    .iter()
                    .map(|offset| base + offset)
                    .chain([oracle.return_pc()])
                    .collect::<Vec<_>>()
            );
            originals.push((entry, trace));
        }
    }
    let pcs = [base + 2, base + 5, base + 8];
    let actions = actions(&pcs);
    let controls: Vec<_> = actions
        .iter()
        .map(|action| action.control.clone())
        .collect();
    let scan = InstructionScanner::default().scan(&code, base).unwrap();
    // The CFG is supplied only to the lower-level emitter, not to the public
    // planner's certified-basic-block interface.
    let plan = TrampolinePlan::from_controlled_actions(&scan, base, base + 13, &actions).unwrap();
    let mapping = Mapping::new(4096);
    let image = plan.emit_at(mapping.address()).unwrap();
    assert!(image.bytes().len() <= 4096);
    assert_eq!(image.entry_routes().len(), 5);
    assert_eq!(image.instruction_boundaries().len(), 5);
    // SAFETY: this newly owned writable page contains the complete image.
    unsafe {
        core::ptr::copy_nonoverlapping(
            image.bytes().as_ptr(),
            mapping.writable(),
            image.bytes().len(),
        );
    }
    mapping.protect(libc::PROT_READ | libc::PROT_EXEC);
    let mut boundaries = image.instruction_boundaries().to_vec();
    boundaries.extend([
        (base + 13, base + 13),
        (oracle.return_pc(), oracle.return_pc()),
    ]);
    let map = TraceMap {
        boundaries,
        generated_ranges: std::iter::once(
            image.address()..image.address() + image.bytes().len() as u64,
        )
        .collect(),
        ..TraceMap::default()
    };
    let snapshots = vec![
        (base, page(base)),
        (mapping.address(), page(mapping.address())),
    ];
    let log = HookEventLog::new();
    let mut comparisons = 0;
    let mut event_count = 0;
    let mut masks = 0_u16;
    let mut previous = 0_usize;
    for index in 0_usize..8 {
        let mask = index ^ (index >> 1);
        if index != 0 {
            assert_eq!((previous ^ mask).count_ones(), 1);
        }
        previous = mask;
        assert_eq!(masks & (1 << mask), 0);
        masks |= 1 << mask;
        assert_pages(&snapshots);
        set_mask(&controls, mask, &snapshots);
        assert_pages(&snapshots);
        let enabled = events(&pcs, mask);
        for (entry, trace) in &originals {
            let generated = if *entry == base + 13 {
                *entry
            } else {
                image
                    .entry_routes()
                    .iter()
                    .find(|(logical, _)| logical == entry)
                    .expect("every displaced original head needs its entry route")
                    .1
            };
            oracle.assert_trace(
                trace,
                generated,
                &map,
                &[],
                Some(HookExpectation {
                    log: &log,
                    enabled: &enabled,
                }),
            );
            comparisons += 1;
            event_count += trace
                .visits()
                .iter()
                .filter(|pc| enabled.iter().any(|event| event.logical_pc == **pc))
                .count();
            assert_pages(&snapshots);
        }
        oracle.assert_publication(&[]);
    }
    assert_eq!(masks, 255);
    assert_eq!(comparisons, 96);
    assert_eq!(event_count, 280);
    eprintln!(
        "runtime controlled CFG: same image, eight masks, all six heads, two seeds, 96 state comparisons and 280 exact ordered events"
    );
}

fn block(index: usize) -> Vec<u8> {
    let mut code = Vec::new();
    for (register, value) in [
        (0xb8, 0x1234_5678_u32),
        (0xb9, 0x8765_4321),
        (0xba, 0x5a5a_6969),
    ] {
        code.push(register);
        code.extend_from_slice(&(value ^ index as u32).to_le_bytes());
    }
    code.push(0xc3);
    assert_eq!(code.len(), 16);
    code
}

struct MaskInputs<'a> {
    oracle: &'a NativeOracle,
    originals: &'a [(u64, NativeTrace)],
    controls: &'a [ProbeControl],
    pcs: &'a [u64],
    map: &'a TraceMap,
    routed: &'a [u64],
    snapshots: &'a [(u64, Vec<u8>)],
    edits: &'a [(u64, Vec<u8>)],
}

fn run_masks(input: &MaskInputs<'_>, indices: std::ops::Range<usize>) -> [u64; 3] {
    let log = HookEventLog::new();
    let mut comparisons = 0_u64;
    let mut event_count = 0_u64;
    let mut coverage = 0_u64;
    let mut previous: Option<usize> = None;
    for index in indices {
        let mask = index ^ (index >> 1);
        if let Some(previous) = previous {
            assert_eq!((previous ^ mask).count_ones(), 1);
        }
        previous = Some(mask);
        assert_eq!(coverage & (1 << mask), 0);
        coverage |= 1 << mask;
        assert_pages(input.snapshots);
        set_mask(input.controls, mask, input.snapshots);
        assert_pages(input.snapshots);
        let enabled = events(input.pcs, mask);
        for (entry, trace) in input.originals {
            input.oracle.assert_trace(
                trace,
                *entry,
                input.map,
                input.routed,
                Some(HookExpectation {
                    log: &log,
                    enabled: &enabled,
                }),
            );
            comparisons += 1;
            event_count += trace
                .visits()
                .iter()
                .filter(|pc| enabled.iter().any(|event| event.logical_pc == **pc))
                .count() as u64;
            assert_pages(input.snapshots);
        }
        input.oracle.assert_publication(input.edits);
    }
    [comparisons, event_count, coverage]
}

fn snapshot_workers(input: &MaskInputs<'_>) {
    assert_eq!(input.controls.len(), 6);
    assert!(input.controls.iter().all(|control| !control.is_enabled()));
    assert_eq!(input.originals.len(), 16);
    let deadline = Instant::now() + WORKER_BUDGET;
    let mut workers = Vec::new();
    for shard in 0..2 {
        let mut pipe = [0; 2];
        // SAFETY: valid two-fd output, closed in their respective owners below.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: this is an isolated one-test subprocess after publication and
        // all original children have been reaped. The parent performs no library
        // mutation until both fixed workers exit. No other test owns a registry
        // lock in this subprocess. Each worker inherits identical immutable code
        // and its own private copy-on-write controls, baseline state and log.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: child owns only the writing end of this fixed receipt pipe.
            unsafe {
                libc::close(pipe[0]);
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let receipt = run_masks(input, shard * 32..(shard + 1) * 32);
                assert_eq!(
                    receipt,
                    if shard == 0 {
                        [512, 288, 0xffff_ffff]
                    } else {
                        [512, 480, 0xffff_ffff_0000_0000]
                    }
                );
                // SAFETY: one fixed 24-byte receipt fits PIPE_BUF and the parent
                // retains the corresponding read end until this worker exits.
                let count = unsafe {
                    libc::write(
                        pipe[1],
                        receipt.as_ptr().cast(),
                        core::mem::size_of_val(&receipt),
                    )
                };
                assert_eq!(count, core::mem::size_of_val(&receipt) as isize);
            }));
            // SAFETY: never return to the inherited test harness or run parent
            // ownership destructors. The outer wrapper kills the whole private
            // process group after a failed status, including surviving tracees.
            unsafe {
                libc::close(pipe[1]);
                libc::_exit(if result.is_ok() { 0 } else { 1 });
            }
        }
        // SAFETY: parent owns the read end and exact child PID.
        unsafe {
            libc::close(pipe[1]);
        }
        workers.push((pid, pipe[0], shard));
    }
    let mut receipts = Vec::new();
    while !workers.is_empty() {
        assert!(
            Instant::now() < deadline,
            "grouped snapshot workers exhausted fixed budget"
        );
        let mut index = 0;
        while index < workers.len() {
            let (pid, read, shard) = workers[index];
            let mut status = 0;
            // SAFETY: exact owned child and initialized status output.
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            assert!(waited == 0 || waited == pid);
            if waited == 0 {
                index += 1;
                continue;
            }
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "required grouped worker {shard} failed: {status}"
            );
            let mut receipt = [0_u64; 3];
            // SAFETY: worker has exited; its one fixed receipt must be present.
            let count = unsafe {
                libc::read(
                    read,
                    receipt.as_mut_ptr().cast(),
                    core::mem::size_of_val(&receipt),
                )
            };
            assert_eq!(count, core::mem::size_of_val(&receipt) as isize);
            let mut extra = 0_u8;
            // SAFETY: after the exact receipt, no additional payload is allowed.
            assert_eq!(unsafe { libc::read(read, (&raw mut extra).cast(), 1) }, 0);
            unsafe {
                libc::close(read);
            }
            assert_eq!(
                receipt,
                if shard == 0 {
                    [512, 288, 0xffff_ffff]
                } else {
                    [512, 480, 0xffff_ffff_0000_0000]
                }
            );
            receipts.push(receipt);
            workers.swap_remove(index);
        }
        if !workers.is_empty() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts.iter().map(|r| r[0]).sum::<u64>(), 1024);
    assert_eq!(receipts.iter().map(|r| r[1]).sum::<u64>(), 768);
    assert_eq!(receipts[0][2] & receipts[1][2], 0);
    assert_eq!(receipts[0][2] | receipts[1][2], u64::MAX);
    assert!(
        input.controls.iter().all(|control| !control.is_enabled()),
        "worker controls must be private snapshots"
    );
    assert_pages(input.snapshots);
    input.oracle.assert_publication(input.edits);
}

fn published_controls(grouped: bool) {
    let functions = if grouped { 2 } else { 1 };
    let code: Vec<_> = (0..functions).flat_map(block).collect();
    let mut oracle = NativeOracle::new(&code);
    let base = oracle.code.address();
    let offsets: Vec<_> = (0..functions)
        .flat_map(|index| [0, 5, 10, 15].map(|pc| index * 16 + pc))
        .collect();
    let heads: Vec<_> = offsets.iter().map(|&offset| base + offset as u64).collect();
    let pcs: Vec<_> = heads
        .iter()
        .enumerate()
        .filter(|(index, _)| index % 4 != 3)
        .map(|(_, &pc)| pc)
        .collect();
    let actions = actions(&pcs);
    let controls: Vec<_> = actions
        .iter()
        .map(|action| action.control.clone())
        .collect();
    let mut originals = Vec::new();
    for seed in SEEDS {
        for (index, &entry) in heads.iter().enumerate() {
            let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
            let end = index / 4 * 4 + 4;
            assert_eq!(
                trace.visits(),
                heads[index..end]
                    .iter()
                    .copied()
                    .chain([oracle.return_pc()])
                    .collect::<Vec<_>>()
            );
            originals.push((entry, trace));
        }
    }
    let identity = CodeIdentity {
        source: SourceIdentity([if grouped { 0xc3 } else { 0xc2 }; 32]),
        mapping: base,
        generation: 1,
    };
    let snapshots: Vec<_> = code
        .chunks_exact(16)
        .enumerate()
        .map(|(index, bytes)| ExpectedBytes {
            address: base + index as u64 * 16,
            bytes: bytes.to_vec(),
        })
        .collect();
    let mut members = Vec::new();
    for (index, snapshot) in snapshots.iter().enumerate() {
        let scope = AddressRange::new(snapshot.address, snapshot.bytes.len()).unwrap();
        let entries = LegalEntrySet {
            identity,
            scope,
            provenance: EntryProvenance::Declared(
                "controlled straight-line block, all four heads".into(),
            ),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: heads[index * 4..index * 4 + 4]
                .iter()
                .map(|&address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let target = base
            + if !grouped {
                0x0800_0000
            } else if index == 0 {
                0x1000_0000
            } else {
                0x1800_0800
            };
        let mut allocation = AllocationPolicy::near(snapshot.address).unwrap();
        allocation.ranges = vec![AddressRange::new(target & !4095, 4096).unwrap()];
        allocation.preferred_address = Some(target);
        let member = plan_coalesced(
            &InstallRequest {
                identity,
                code: &snapshot.bytes,
                base_address: snapshot.address,
                function: scope,
                block: scope,
                logical_pc: snapshot.address,
                entries: &entries,
                hook: CALLBACKS[index * 3],
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    max_upstream_bytes: 0,
                    max_sites: 1,
                    ..SearchPolicy::default()
                },
            },
            &actions[index * 3..index * 3 + 3],
        )
        .expect("required controlled block refused");
        assert!(matches!(member.plan().parts().kind, PlanKind::Relocation));
        assert_eq!(member.plan().parts().physical_pc, snapshot.address);
        assert_eq!(
            member.plan().parts().displaced,
            AddressRange::new(snapshot.address, 15).unwrap()
        );
        assert_eq!(member.image().address(), target);
        assert_eq!(member.image().entry_routes().len(), 3);
        assert_eq!(member.image().instruction_boundaries().len(), 3);
        let routes: Vec<_> = member
            .plan()
            .parts()
            .obligations
            .iter()
            .filter_map(|obligation| match obligation {
                EntryObligation::Routed(route) => Some(*route),
                EntryObligation::Preserved(pc) => {
                    assert_eq!(*pc, snapshot.address);
                    None
                }
                EntryObligation::Unresolved { .. } => panic!("unresolved controlled entry"),
            })
            .collect();
        assert_eq!(
            routes
                .iter()
                .map(|route| route.original)
                .collect::<Vec<_>>(),
            [snapshot.address + 5, snapshot.address + 10],
            "both alternate controlled heads require owned SIGILL routes"
        );
        for route in routes {
            assert!(
                member
                    .image()
                    .entry_routes()
                    .contains(&(route.original, route.generated)),
                "published alternate route must enter its exact controlled image head"
            );
        }
        assert!(member.plan().parts().requirements.sigill_router);
        assert!(member.image().bytes().len() <= 2048);
        members.push(member);
    }
    let bundle = if grouped {
        PlannedBundle::compose_grouped(
            snapshots,
            members,
            BundleBudget::default(),
            GroupingBudget {
                max_mappings: 2,
                max_virtual_pages: 2,
                max_virtual_bytes: 8192,
                max_backing_bytes: 4096,
                ..GroupingBudget::default()
            },
        )
    } else {
        PlannedBundle::compose(snapshots, members, BundleBudget::default())
    }
    .expect("required controlled bundle refused");
    assert_eq!(bundle.plan().steps().len(), functions);
    assert_eq!(bundle.images().len(), functions);
    if grouped {
        let grouping = bundle
            .grouping()
            .expect("required physical grouping missing");
        assert_eq!(grouping.groups().len(), 1);
        assert_eq!(grouping.groups()[0].kind(), BackingKind::SharedPage);
        assert_eq!(grouping.groups()[0].image_indices(), &[0, 1]);
        assert_eq!(grouping.memory().virtual_pages, 2);
        assert_eq!(grouping.memory().backing_pages, 1);
        assert_eq!(grouping.memory().virtual_bytes, 8192);
        assert_eq!(grouping.memory().backing_bytes, 4096);
        assert_eq!(bundle.plan().memory().virtual_bytes, 8192);
        assert_eq!(bundle.plan().memory().backing_bytes, 4096);
        assert_eq!(bundle.images()[0].address() % 4096, 0);
        assert_eq!(bundle.images()[1].address() % 4096, 0x800);
        assert_ne!(
            bundle.images()[0].address() / 4096,
            bundle.images()[1].address() / 4096
        );
    } else {
        assert!(bundle.grouping().is_none());
    }
    let mut map = TraceMap {
        boundaries: heads
            .iter()
            .enumerate()
            .filter(|(index, _)| index % 4 == 3)
            .map(|(_, &pc)| (pc, pc))
            .chain([(oracle.return_pc(), oracle.return_pc())])
            .collect(),
        gateways: pcs.clone(),
        ..TraceMap::default()
    };
    for image in bundle.images() {
        map.boundaries
            .extend_from_slice(image.instruction_boundaries());
        map.generated_ranges
            .push(image.address()..image.address() + image.bytes().len() as u64);
    }
    let edits: Vec<_> = bundle
        .plan()
        .steps()
        .iter()
        .flat_map(|step| &step.parts().writes)
        .map(|edit| (edit.address, edit.bytes.clone()))
        .collect();
    let routed: Vec<_> = pcs
        .iter()
        .enumerate()
        .filter(|(index, _)| index % 3 != 0)
        .map(|(_, &pc)| pc)
        .collect();
    let source = AddressRange::new(base, code.len()).unwrap();
    let mut drain = vec![source];
    drain.extend(bundle.plan().steps().iter().flat_map(|step| {
        step.parts()
            .allocations
            .iter()
            .map(|allocation| allocation.range)
    }));
    let writable = oracle.code.writable();
    // SAFETY: exact private source alias remains owned through retirement.
    let aliases = [unsafe { WritableAlias::new(source, writable) }.unwrap()];
    let mut installed = {
        // SAFETY: all original traces completed and no continuation is live.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![source]) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: source exclusion covers stores, final RX and synchronization.
        let (installed, receipt) = unsafe {
            bundle.publish_with(&aliases, &mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required control publication failed");
        assert_eq!(receipt.plan().steps(), bundle.plan().steps());
        assert!(!lease.is_poisoned());
        installed
    };
    // This accessor counts handled signals, not configured routes. No child
    // has executed yet, and later ptrace children update private fork snapshots.
    // Exact configured routes were checked against both image heads above.
    assert_eq!(installed.routed_entries(), 0);
    oracle.assert_publication(&edits);
    let mut immutable = vec![(base, page(base))];
    for image in bundle.images() {
        let page_address = image.address() & !4095;
        immutable.push((page_address, page(page_address)));
        // SAFETY: successful publication retains the readable immutable image.
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    image.address() as usize as *const u8,
                    image.bytes().len(),
                )
            },
            image.bytes()
        );
    }
    if grouped {
        assert_eq!(
            immutable[1].1, immutable[2].1,
            "aliases must expose the same physical payload"
        );
        assert_sealed_aliases(&[immutable[1].0, immutable[2].0]);
    }
    let input = MaskInputs {
        oracle: &oracle,
        originals: &originals,
        controls: &controls,
        pcs: &pcs,
        map: &map,
        routed: &routed,
        snapshots: &immutable,
        edits: &edits,
    };
    if grouped {
        snapshot_workers(&input);
    } else {
        assert_eq!(run_masks(&input, 0..8), [64, 48, 255]);
    }
    let all = (1 << pcs.len()) - 1;
    set_mask(&controls, all, &immutable);
    assert_pages(&immutable);
    // Lifetime evidence must not retain hidden image/control clones. The maps,
    // edits, drain ranges and snapshots above contain only integers and bytes.
    drop(controls);
    drop(actions);
    drop(bundle);
    let log = HookEventLog::new();
    let enabled = events(&pcs, all);
    let mut retained = 0;
    let mut retained_events = 0;
    for (entry, trace) in &originals {
        oracle.assert_trace(
            trace,
            *entry,
            &map,
            &routed,
            Some(HookExpectation {
                log: &log,
                enabled: &enabled,
            }),
        );
        retained += 1;
        retained_events += trace
            .visits()
            .iter()
            .filter(|pc| enabled.iter().any(|event| event.logical_pc == **pc))
            .count();
        assert_pages(&immutable);
    }
    assert_eq!(retained, functions * 8);
    assert_eq!(retained_events, functions * 12);
    {
        // SAFETY: all snapshot workers and their trace children are reaped;
        // source, generated mappings and continuations are completely drained.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, drain) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: full lease remains held through original-byte/RX restoration.
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required control retirement failed");
        assert!(!lease.is_poisoned());
    }
    assert!(installed.is_retired());
    oracle.assert_publication(&[]);
    for (entry, trace) in &originals {
        oracle.assert_trace(
            trace,
            *entry,
            &identity_map(&heads, oracle.return_pc()),
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &[],
            }),
        );
    }
    let _pinned = Box::leak(Box::new(oracle));
    eprintln!(
        "runtime controls grouped={grouped}: {} installed + {} retired comparisons on one publication; exact events and source/generated byte invariance",
        if grouped { 1040 } else { 72 },
        functions * 8
    );
}

fn assert_sealed_aliases(pages: &[u64; 2]) {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut prior = None;
    for &page in pages {
        let fields = maps
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .find(|fields| {
                let (low, high) = fields[0].split_once('-').unwrap();
                u64::from_str_radix(low, 16).unwrap() == page
                    && u64::from_str_radix(high, 16).unwrap() == page + 4096
            })
            .expect("required grouped alias missing");
        assert_eq!(fields[1], "r-xs");
        assert_eq!(u64::from_str_radix(fields[2], 16).unwrap(), 0);
        let inode = fields[4].parse::<u64>().unwrap();
        assert_ne!(inode, 0);
        let identity = (fields[3].to_owned(), inode);
        if let Some(prior) = &prior {
            assert_eq!(prior, &identity);
        } else {
            prior = Some(identity);
        }
        // SAFETY: isolated source/generated execution is drained. A sealed
        // shared mapping must reject this without changing permissions.
        assert_eq!(
            unsafe {
                libc::mprotect(
                    page as usize as *mut _,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EACCES)
        );
    }
}
