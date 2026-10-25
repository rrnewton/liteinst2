//! Native state comparisons for successor eviction chains.

#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/eviction_chain_cases.rs"]
mod cases;
#[path = "support/eviction_chain_isolation.rs"]
mod isolation;
#[allow(dead_code)]
#[path = "support/quiescent_oracle.rs"]
mod oracle;

use cases::{CASES, Fixture};
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::*;
use liteinst2::eviction_chain::{PlannedChain, plan_successor_chain_detailed};
use liteinst2::trampoline::HookContext;
use oracle::{HookEvent, HookEventLog, HookExpectation, NativeOracle, TraceMap};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const ID: u64 = 0xc701;
unsafe extern "C" fn observe(context: *mut HookContext) {
    unsafe {
        oracle::record_hook_event(ID, (*context).instruction_pointer);
        core::arch::asm!("add rax, 1","pxor xmm0, xmm0","fninit",out("rax") _,out("xmm0") _,options(nostack));
    }
}
fn permissions(pointer: *mut u8, flags: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(pointer.cast(), 4096, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}
fn planned(f: &Fixture<'_>) -> PlannedChain {
    plan_successor_chain_detailed(
        &f.request(observe),
        &f.policies[1..],
        f.search(),
        f.budget(),
    )
    .expect("required recursive chain cannot become refusal coverage")
}
fn image_bytes(planned: &PlannedChain) {
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
fn is_mapped(range: AddressRange) -> bool {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .any(|line| {
            let (lo, hi) = line
                .split_whitespace()
                .next()
                .unwrap()
                .split_once('-')
                .unwrap();
            let lo = u64::from_str_radix(lo, 16).unwrap();
            let hi = u64::from_str_radix(hi, 16).unwrap();
            lo < range.end() && range.start() < hi
        })
}

struct Occupied {
    address: *mut u8,
    len: usize,
}
impl Occupied {
    fn new(range: AddressRange) -> Self {
        let address = unsafe {
            libc::mmap(
                range.start() as usize as *mut libc::c_void,
                range.len() as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_ne!(
            address,
            libc::MAP_FAILED,
            "dictated collision owner must be reserved, never skipped"
        );
        assert_eq!(address as usize as u64, range.start());
        unsafe { std::ptr::write_bytes(address.cast::<u8>(), 0xa5, range.len() as usize) };
        Self {
            address: address.cast(),
            len: range.len() as usize,
        }
    }
    fn check(&self) {
        assert!(
            unsafe { std::slice::from_raw_parts(self.address, self.len) }
                .iter()
                .all(|&b| b == 0xa5)
        );
    }
}
impl Drop for Occupied {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::munmap(self.address.cast(), self.len) }, 0);
    }
}

fn preflight_refusals(
    native: &mut NativeOracle,
    f: &Fixture<'_>,
    planned: &PlannedChain,
    aliases: &[WritableAlias],
) {
    let bundle = planned.bundle();
    let source = f.entries.scope;
    let pointer = native.code.writable();
    let mut before_write = 0;
    for missing in [false, true] {
        let identity = if missing {
            f.entries.identity
        } else {
            CodeIdentity {
                generation: 2,
                ..f.entries.identity
            }
        };
        let ranges = if missing {
            vec![AddressRange::new(f.base, 1).unwrap()]
        } else {
            vec![source]
        };
        let mut lease = unsafe { QuiescenceLease::new(native, identity, ranges) };
        let failure = match unsafe {
            bundle.publish_with(aliases, &mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        } {
            Err(e) => e,
            Ok(_) => panic!("stale or incomplete lease published"),
        };
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert_eq!(
            failure.reason,
            if missing {
                Refusal::DependencyNotHeld
            } else {
                Refusal::StaleGeneration
            }
        );
        assert!(!lease.is_poisoned());
        before_write += 1;
    }
    native.assert_publication(&[]);
    let mut stale_page = unsafe { std::slice::from_raw_parts(pointer, 4096) }.to_vec();
    stale_page[0] = 0x90;
    {
        let mut lease = unsafe { QuiescenceLease::new(native, f.entries.identity, vec![source]) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe { std::ptr::write_volatile(pointer, 0x90) };
        let failure = match unsafe {
            bundle.publish_with(aliases, &mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        } {
            Err(e) => e,
            Ok(_) => panic!("stale original snapshot published"),
        };
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
        assert!(!lease.is_poisoned());
        assert_eq!(
            unsafe { std::slice::from_raw_parts(pointer, 4096) },
            stale_page
        );
        unsafe { std::ptr::write_volatile(pointer, f.code[0]) };
    }
    before_write += 1;
    native.assert_publication(&[]);
    let ranges = allocations(planned);
    assert!(ranges.iter().all(|&r| !is_mapped(r)));
    let held = Occupied::new(*ranges.last().unwrap());
    // The same late selected-image page is a separately counted planning
    // refusal; all earlier pure members remain unpublished.
    let failure = plan_successor_chain_detailed(
        &f.request(observe),
        &f.policies[1..],
        f.search(),
        f.budget(),
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.metrics.candidate_trials, f.case.lengths.len());
    assert!(!failure.metrics.global_cutoff);
    assert_eq!(failure.metrics.attempts.last().unwrap().original, f.base);
    assert_eq!(
        failure.metrics.attempts.last().unwrap().refusal,
        Some(Refusal::AllocationUnavailable)
    );
    held.check();
    native.assert_publication(&[]);
    {
        let mut lease = unsafe { QuiescenceLease::new(native, f.entries.identity, vec![source]) };
        let failure = match unsafe {
            bundle.publish_with(aliases, &mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        } {
            Err(e) => e,
            Ok(_) => panic!("occupied final image unexpectedly published"),
        };
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert!(matches!(failure.reason, Refusal::Backend(_)));
        assert!(!lease.is_poisoned());
        before_write += 1;
    }
    native.assert_publication(&[]);
    held.check();
    assert!(
        ranges[..ranges.len() - 1].iter().all(|&r| !is_mapped(r)),
        "every earlier staged image must unmap on the final collision"
    );
    drop(held);
    assert!(ranges.iter().all(|&r| !is_mapped(r)));
    assert_eq!(before_write, 4);
    eprintln!(
        "chain preflight: planning_occupied=1 before_write=4 all_source_and_owner_bytes_unchanged=true staged_cleanup=true"
    );
}

#[test]
fn native_eviction_chains_all_original_entries() {
    isolation::run_parent("native_eviction_chains_all_original_entries");
}

/// Compare native eviction-chain execution from every declared original entry.
pub fn run_native_eviction_chains_all_original_entries() {
    let mut retained = Vec::new();
    let mut original_count = 0;
    let mut installed_count = 0;
    let mut retired_count = 0;
    let mut hooks = 0;
    let mut auxiliary_entries = 0;
    for (case_index, case) in CASES.iter().enumerate() {
        let mut native = NativeOracle::new(case.code);
        let base = native.code.address();
        let f = Fixture::new(case, base);
        let planned = planned(&f);
        f.assert_plan(&planned);
        let bundle = planned.bundle();
        let source = f.entries.scope;
        let pointer = native.code.writable();
        let aliases = [unsafe { WritableAlias::new(source, pointer) }.unwrap()];
        if case_index == 0 {
            preflight_refusals(&mut native, &f, &planned, &aliases);
        }
        let heads: Vec<_> = case.heads.iter().map(|&h| base + h as u64).collect();
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
                original_count += 1;
            }
        }
        let (mut installed, receipt) = {
            let mut lease =
                unsafe { QuiescenceLease::new(&mut native, f.entries.identity, vec![source]) };
            permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            let result = unsafe {
                bundle.publish_with(&aliases, &mut lease, || {
                    permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .expect("required chain publication");
            assert!(!lease.is_poisoned());
            result
        };
        assert_eq!(receipt.plan().steps(), bundle.plan().steps());
        let edits: Vec<_> = bundle
            .plan()
            .steps()
            .iter()
            .flat_map(|s| {
                s.parts()
                    .writes
                    .iter()
                    .map(|e| (e.address, e.bytes.clone()))
            })
            .collect();
        native.assert_publication(&edits);
        image_bytes(&planned);
        let n = case.lengths.len();
        let mut map = TraceMap {
            boundaries: heads[n..]
                .iter()
                .copied()
                .chain([native.return_pc()])
                .map(|pc| (pc, pc))
                .collect(),
            gateways: heads[..n].to_vec(),
            ..TraceMap::default()
        };
        for image in bundle.images() {
            map.boundaries
                .extend_from_slice(image.instruction_boundaries());
            map.generated_ranges
                .push(image.address()..image.address() + image.bytes().len() as u64);
        }
        let log = HookEventLog::new();
        let selected = [HookEvent {
            probe_id: ID,
            logical_pc: base,
        }];
        for (i, entry, trace) in &originals {
            let enabled: &[HookEvent] = if *i == 0 { &selected } else { &[] };
            native.assert_trace(
                trace,
                *entry,
                &map,
                &[],
                Some(HookExpectation { log: &log, enabled }),
            );
            installed_count += 1;
            hooks += usize::from(*i == 0);
            auxiliary_entries += usize::from(*i > 0 && *i < n);
            image_bytes(&planned);
        }
        assert_eq!(installed.routed_entries(), 0);
        {
            let mut ranges = vec![source];
            ranges.extend(allocations(&planned));
            let mut lease =
                unsafe { QuiescenceLease::new(&mut native, f.entries.identity, ranges) };
            permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            unsafe {
                installed.retire_with(&mut lease, || {
                    permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .expect("required complete chain retirement");
            assert!(!lease.is_poisoned());
        }
        assert!(installed.is_retired());
        native.assert_publication(&[]);
        image_bytes(&planned);
        let original_map = TraceMap {
            boundaries: heads
                .iter()
                .copied()
                .chain([native.return_pc()])
                .map(|pc| (pc, pc))
                .collect(),
            ..TraceMap::default()
        };
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
        }
        native.assert_publication(&[]);
        image_bytes(&planned);
        retained.push(native);
    }
    assert_eq!(
        (original_count, installed_count, retired_count),
        (38, 38, 38)
    );
    assert_eq!(hooks, 6);
    assert_eq!(auxiliary_entries, 20);
    assert_eq!(retained.len(), 3);
    eprintln!(
        "chain native: cycles=3 heads=19 original=38 installed=38 retired=38 selected_hooks=6 auxiliary_entries_without_selected_hook=20 all_images_exact=true"
    );
}

#[test]
fn native_eviction_chain_postwrite_failure_keeps_every_image() {
    isolation::run_parent("native_eviction_chain_postwrite_failure_keeps_every_image");
}

/// Check that postwrite failure retains every eviction-chain image.
pub fn run_native_eviction_chain_postwrite_failure_keeps_every_image() {
    let mut native = NativeOracle::new(CASES[1].code);
    let f = Fixture::new(&CASES[1], native.code.address());
    let planned = planned(&f);
    f.assert_plan(&planned);
    let bundle = planned.bundle();
    let pointer = native.code.writable();
    let aliases = [unsafe { WritableAlias::new(f.entries.scope, pointer) }.unwrap()];
    {
        let mut lease =
            unsafe { QuiescenceLease::new(&mut native, f.entries.identity, vec![f.entries.scope]) };
        let failure = match unsafe {
            bundle.publish_with(&aliases, &mut lease, || {
                Err(Refusal::Backend("forced chain finalizer".into()))
            })
        } {
            Err(e) => e,
            Ok(_) => panic!("forced finalizer unexpectedly completed"),
        };
        assert_eq!(failure.stage, FailureStage::KeepGated);
        assert_eq!(
            failure.reason,
            Refusal::Backend("forced chain finalizer".into())
        );
        assert!(lease.is_poisoned());
    }
    let edits: Vec<_> = bundle
        .plan()
        .steps()
        .iter()
        .flat_map(|s| {
            s.parts()
                .writes
                .iter()
                .map(|e| (e.address, e.bytes.clone()))
        })
        .collect();
    native.assert_publication(&edits);
    image_bytes(&planned);
    assert!(allocations(&planned).iter().all(|&r| is_mapped(r)));
    // No source entry is executed after the failed transaction. This isolated
    // child exits with all code/source storage retained behind the poisoned gate.
    std::mem::forget(native);
    eprintln!(
        "chain postwrite: KeepGated=1 poisoned=true retained_images=5 native_entry_after_failure=0"
    );
}

/// Dispatch the selected fixture on the fresh process main thread.
pub fn isolated_main() {
    isolation::main_thread_driver();
}
