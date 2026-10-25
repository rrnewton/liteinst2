//! Native comparisons for extended successor eviction chains.

#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[allow(dead_code)]
#[path = "support/eviction_chain_cases.rs"]
mod cases;
#[path = "support/eviction_chain_extension_isolation.rs"]
mod isolation;
#[allow(dead_code)]
#[path = "support/quiescent_oracle.rs"]
mod oracle;

use cases::{Case, Fixture};
use liteinst2::bundle::{InstalledBundle, WritableAlias};
use liteinst2::contracts::*;
use liteinst2::eviction_chain::{PlannedChain, plan_successor_chain_detailed};
use liteinst2::trampoline::HookContext;
use oracle::{HookEvent, HookEventLog, HookExpectation, Mapping, NativeOracle, TraceMap};
use std::sync::atomic::{AtomicBool, Ordering};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const ID: u64 = 0xc702;
// Explicit instrumentation-only callback mode. Parent stores occur only after
// every preceding trace child has exited/reaped. Emitted code never changes.
static RECORD_EVENTS: AtomicBool = AtomicBool::new(true);
unsafe extern "C" fn observe(context: *mut HookContext) {
    if RECORD_EVENTS.load(Ordering::Relaxed) {
        unsafe { oracle::record_hook_event(ID, (*context).instruction_pointer) };
    }
    unsafe {
        core::arch::asm!("add rax, 1","pxor xmm0, xmm0","fninit",out("rax") _,out("xmm0") _,options(nostack));
    }
}

const BRANCH: Case = Case {
    name: "chain-depth2-short-JNZ-backedge",
    // SHR ECX,1; JNZ selected; LEA RCX,[RDI]; MOV EAX,imm32;
    // MOV [RDI],RAX; RET. LEA overwrites ECX only after the loop ends.
    code: &[
        0xd1, 0xe9, 0x75, 0xfc, 0x48, 0x8d, 0x0f, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0x07,
        0xc3,
    ],
    heads: &[0, 2, 4, 7, 12, 15],
    lengths: &[2, 2, 3, 5],
    prefixes: &[0, 0, 0],
    target_deltas: &[-0x167f167b, -0x7fff1679, 0x56e98009, 0x04523462],
    final_bytes: &[
        0xe9, 0x80, 0xe9, 0x80, 0xe9, 0x00, 0x80, 0xe9, 0x56, 0x34, 0x52, 0x04, 0x48, 0x89, 0x07,
        0xc3,
    ],
};

fn permissions(pointer: *mut u8, flags: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(pointer.cast(), 4096, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}
fn images(planned: &PlannedChain) {
    for image in planned.bundle().images() {
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
}
fn allocations(planned: &PlannedChain) -> Vec<AddressRange> {
    planned
        .bundle()
        .plan()
        .steps()
        .iter()
        .flat_map(|s| s.parts().allocations.iter().map(|a| a.range))
        .collect()
}
fn planned(f: &Fixture<'_>) -> PlannedChain {
    // Original windows are derived solely from the handwritten original bytes.
    // Every short node must require a descendant edit to fit its own permit.
    for i in 0..f.case.lengths.len() - 1 {
        let h = f.case.heads[i];
        let len = f.case.lengths[i];
        let free = len - 1;
        let mut d = [0_u8; 4];
        d[free..].copy_from_slice(&f.code[h + len..h + 5]);
        let low =
            u64::try_from(i128::from(f.base + h as u64 + 5) + i128::from(i32::from_le_bytes(d)))
                .unwrap();
        let original_window = AddressRange::new(low, 1_usize << (8 * free)).unwrap();
        assert!(
            f.policies[i]
                .ranges
                .iter()
                .all(|r| !r.overlaps(original_window))
        );
    }
    let plan = plan_successor_chain_detailed(
        &f.request(observe),
        &f.policies[1..],
        f.search(),
        f.budget(),
    )
    .expect("required branch/fault chain must succeed without substitution");
    f.assert_plan(&plan);
    assert_eq!(plan.nodes().len(), 4);
    plan
}
fn edits(planned: &PlannedChain) -> Vec<(u64, Vec<u8>)> {
    planned
        .bundle()
        .plan()
        .steps()
        .iter()
        .flat_map(|s| {
            s.parts()
                .writes
                .iter()
                .map(|e| (e.address, e.bytes.clone()))
        })
        .collect()
}
fn publish(native: &mut NativeOracle, f: &Fixture<'_>, plan: &PlannedChain) -> InstalledBundle {
    let pointer = native.code.writable();
    let aliases = [unsafe { WritableAlias::new(f.entries.scope, pointer) }.unwrap()];
    let (installed, receipt) = {
        let mut lease =
            unsafe { QuiescenceLease::new(native, f.entries.identity, vec![f.entries.scope]) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        let result = unsafe {
            plan.bundle().publish_with(&aliases, &mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required extension publication failed");
        assert!(!lease.is_poisoned());
        result
    };
    assert_eq!(receipt.plan().steps(), plan.bundle().plan().steps());
    native.assert_publication(&edits(plan));
    images(plan);
    installed
}
fn retire(
    native: &mut NativeOracle,
    f: &Fixture<'_>,
    plan: &PlannedChain,
    installed: &mut InstalledBundle,
) {
    let pointer = native.code.writable();
    let mut ranges = vec![f.entries.scope];
    ranges.extend(allocations(plan));
    {
        let mut lease = unsafe { QuiescenceLease::new(native, f.entries.identity, ranges) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required extension retirement failed");
        assert!(!lease.is_poisoned());
    }
    assert!(installed.is_retired());
    native.assert_publication(&[]);
    images(plan);
}
fn maps(native: &NativeOracle, f: &Fixture<'_>, plan: &PlannedChain) -> (TraceMap, TraceMap) {
    let heads: Vec<_> = f.case.heads.iter().map(|&h| f.base + h as u64).collect();
    let mut installed = TraceMap {
        boundaries: heads[4..]
            .iter()
            .copied()
            .chain([native.return_pc()])
            .map(|pc| (pc, pc))
            .collect(),
        gateways: heads[..4].to_vec(),
        ..TraceMap::default()
    };
    for image in plan.bundle().images() {
        installed
            .boundaries
            .extend_from_slice(image.instruction_boundaries());
        installed
            .generated_ranges
            .push(image.address()..image.address() + image.bytes().len() as u64);
    }
    let original = TraceMap {
        boundaries: heads
            .iter()
            .copied()
            .chain([native.return_pc()])
            .map(|pc| (pc, pc))
            .collect(),
        ..TraceMap::default()
    };
    (installed, original)
}
fn seeded_ecx(seed: u64) -> u32 {
    let mut state = seed;
    for _ in 0..3 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
    }
    state as u32
}

#[test]
fn native_chain_short_conditional_backedge() {
    isolation::run_parent("native_chain_short_conditional_backedge");
}
/// Compare native state through the short conditional chain backedge.
pub fn run_native_chain_short_conditional_backedge() {
    RECORD_EVENTS.store(true, Ordering::Relaxed);
    assert_eq!(SEEDS.map(seeded_ecx), [0xfa97ac78, 0x6f659161]);
    assert_eq!(4_i64 + i64::from(BRANCH.code[3] as i8), 0);
    let mut native = NativeOracle::new(BRANCH.code);
    let f = Fixture::new(&BRANCH, native.code.address());
    let plan = planned(&f);
    let heads: Vec<_> = BRANCH.heads.iter().map(|&h| f.base + h as u64).collect();
    let mut originals = Vec::new();
    let mut events = 0;
    for (seed_index, seed) in SEEDS.into_iter().enumerate() {
        for (i, &entry) in heads.iter().enumerate() {
            let expected: Vec<_> = if i == 0 {
                (0..[32, 31][seed_index])
                    .flat_map(|_| [heads[0], heads[1]])
                    .chain(heads[2..].iter().copied())
                    .chain([native.return_pc()])
                    .collect()
            } else {
                heads[i..]
                    .iter()
                    .copied()
                    .chain([native.return_pc()])
                    .collect()
            };
            let trace = native.trace_original(entry, &heads, &[native.return_pc()], seed);
            assert_eq!(trace.visits(), expected);
            let visits = expected.iter().filter(|&&pc| pc == f.base).count();
            assert_eq!(visits, if i == 0 { [32, 31][seed_index] } else { 0 });
            events += visits;
            originals.push((i, entry, trace));
        }
    }
    assert_eq!(originals.len(), 12);
    assert_eq!(events, 63);
    let (installed_map, original_map) = maps(&native, &f, &plan);
    let mut installed = publish(&mut native, &f, &plan);
    let log = HookEventLog::new();
    let selected = [HookEvent {
        probe_id: ID,
        logical_pc: f.base,
    }];
    let mut installed_count = 0;
    let mut auxiliary = 0;
    for (i, entry, trace) in &originals {
        // The log predicate produces one event for every repeated selected
        // native visit. Direct auxiliary entry has no selected visit here.
        native.assert_trace(
            trace,
            *entry,
            &installed_map,
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &selected,
            }),
        );
        installed_count += 1;
        auxiliary += usize::from(*i > 0 && *i < 4);
        native.assert_publication(&edits(&plan));
        images(&plan);
    }
    assert_eq!(installed.routed_entries(), 0);
    retire(&mut native, &f, &plan, &mut installed);
    let mut retired_count = 0;
    for (_, entry, trace) in &originals {
        native.assert_trace(
            trace,
            *entry,
            &original_map,
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &[],
            }),
        );
        retired_count += 1;
        native.assert_publication(&[]);
        images(&plan);
    }
    assert_eq!((installed_count, retired_count, auxiliary), (12, 12, 6));
    eprintln!(
        "chain extension branch: cycles=1 heads=6 original=12 installed=12 retired=12 selected_events=63 auxiliary_entries_without_selected_hook=6 generated_images=4 all_bytes_exact=true"
    );
    // SHR by1 leaves AF architecturally undefined. The native comparator keeps
    // the exact pre-existing full flags comparison including AF; no mask added.
}

fn operand_bytes(page: &Mapping, expected: &[u8]) {
    assert_eq!(
        unsafe { std::slice::from_raw_parts(page.writable(), 4096) },
        expected
    );
}
fn fault_case(operand: u64) -> Case {
    let mut code = vec![0x89, 0xc0, 0x90, 0x48, 0x8d, 0x0f, 0x48, 0xa1];
    code.extend_from_slice(&operand.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0x07, 0xc3]);
    assert_eq!(code.len(), 20);
    assert_eq!(u64::from_le_bytes(code[8..16].try_into().unwrap()), operand);
    let mut final_bytes = code.clone();
    final_bytes[..11].copy_from_slice(&[
        0xe9, 0x80, 0xe9, 0xe9, 0x00, 0x80, 0xe9, 0x56, 0x34, 0x62, 0x04,
    ]);
    assert_eq!(&final_bytes[11..16], &code[11..16]);
    // These two twenty-byte fixture arrays live until the fresh child process
    // exits. No production decoding/planning computes either byte stream.
    Case {
        name: "chain-depth2-MOFFS64-readable-and-protected",
        code: Box::leak(code.into_boxed_slice()),
        heads: &[0, 2, 3, 6, 16, 19],
        lengths: &[2, 1, 3, 10],
        prefixes: &[0, 0, 0],
        target_deltas: &[0x00e9e985, -0x167fff10, 0x56e98008, 0x04623461],
        final_bytes: Box::leak(final_bytes.into_boxed_slice()),
    }
}

#[test]
fn native_chain_anchor_readable_and_fault() {
    isolation::run_parent("native_chain_anchor_readable_and_fault");
}
/// Compare readable and faulting loads in the eviction-chain fixture.
pub fn run_native_chain_anchor_readable_and_fault() {
    RECORD_EVENTS.store(true, Ordering::Relaxed);
    let operand = Mapping::new(4096);
    let expected_page: Vec<u8> = (0..4096).map(|i| (i * 17 + 29) as u8).collect();
    unsafe { std::ptr::copy_nonoverlapping(expected_page.as_ptr(), operand.writable(), 4096) };
    operand.protect(libc::PROT_READ);
    operand_bytes(&operand, &expected_page);
    let case = fault_case(operand.address());
    let mut native = NativeOracle::new(case.code);
    let f = Fixture::new(&case, native.code.address());
    let plan = planned(&f);
    let heads: Vec<_> = case.heads.iter().map(|&h| f.base + h as u64).collect();
    let mut originals = Vec::new();
    for seed in SEEDS {
        for (i, &entry) in heads.iter().enumerate() {
            let trace = native.trace_original(entry, &heads, &[native.return_pc()], seed);
            assert_eq!(
                trace.visits(),
                heads[i..]
                    .iter()
                    .copied()
                    .chain([native.return_pc()])
                    .collect::<Vec<_>>()
            );
            originals.push((i, entry, trace));
        }
    }
    assert_eq!(originals.len(), 12);
    operand.protect(libc::PROT_NONE);
    let mut faults = Vec::new();
    for seed in SEEDS {
        for (i, &entry) in heads[..4].iter().enumerate() {
            let trace =
                native.original_fault(&heads[i..4], seed, (libc::SIGSEGV, 2, operand.address()));
            faults.push((entry, trace));
        }
    }
    assert_eq!(faults.len(), 8);
    // All eight faults end at the anchor; the later store/RET are not claimed
    // to execute in those paths. The readable partner entered all six heads.
    operand.protect(libc::PROT_READ);
    operand_bytes(&operand, &expected_page);
    let (installed_map, original_map) = maps(&native, &f, &plan);
    let mut installed = publish(&mut native, &f, &plan);
    let log = HookEventLog::new();
    let selected = [HookEvent {
        probe_id: ID,
        logical_pc: f.base,
    }];
    let mut normal_installed = 0;
    let mut events = 0;
    let mut auxiliary = 0;
    for (i, entry, trace) in &originals {
        native.assert_trace(
            trace,
            *entry,
            &installed_map,
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &selected,
            }),
        );
        normal_installed += 1;
        events += usize::from(*i == 0);
        auxiliary += usize::from(*i > 0 && *i < 4);
        operand_bytes(&operand, &expected_page);
        native.assert_publication(&edits(&plan));
        images(&plan);
    }
    // The unchanged synchronous-fault helper has no event-log activation.
    // Disable only the callback's instrumentation log; preserve the exact same
    // code, callback pointer and deliberate state clobbers. Fault event counts
    // are explicitly unmeasured, not reported as zero or inferred from normal.
    RECORD_EVENTS.store(false, Ordering::Relaxed);
    operand.protect(libc::PROT_NONE);
    let mut fault_installed = 0;
    for (entry, trace) in &faults {
        native.assert_patched(trace, *entry, &installed_map.boundaries, &[]);
        fault_installed += 1;
        native.assert_publication(&edits(&plan));
        images(&plan);
    }
    assert_eq!(installed.routed_entries(), 0);
    operand.protect(libc::PROT_READ);
    operand_bytes(&operand, &expected_page);
    retire(&mut native, &f, &plan, &mut installed);
    RECORD_EVENTS.store(true, Ordering::Relaxed);
    let mut normal_retired = 0;
    for (_, entry, trace) in &originals {
        native.assert_trace(
            trace,
            *entry,
            &original_map,
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &[],
            }),
        );
        normal_retired += 1;
        operand_bytes(&operand, &expected_page);
        native.assert_publication(&[]);
        images(&plan);
    }
    RECORD_EVENTS.store(false, Ordering::Relaxed);
    operand.protect(libc::PROT_NONE);
    let mut fault_retired = 0;
    for (entry, trace) in &faults {
        native.assert_patched(trace, *entry, &original_map.boundaries, &[]);
        fault_retired += 1;
        native.assert_publication(&[]);
        images(&plan);
    }
    operand.protect(libc::PROT_READ);
    operand_bytes(&operand, &expected_page);
    assert_eq!(
        (
            normal_installed,
            normal_retired,
            fault_installed,
            fault_retired,
            events,
            auxiliary
        ),
        (12, 12, 8, 8, 2, 6)
    );
    eprintln!(
        "chain extension load: cycles=1 heads=6 normal_original=12 normal_installed=12 normal_retired=12 fault_original=8 fault_installed=8 fault_retired=8 normal_selected_events=2 fault_events=unmeasured auxiliary_normal_entries_without_selected_hook=6 generated_images=4 same_operand_and_source=true exact_SEGV_ACCERR_address_and_original_PC=true all_bytes_exact=true"
    );
}

/// Dispatch the selected fixture on the fresh process main thread.
pub fn isolated_main() {
    isolation::main_thread_driver();
}
