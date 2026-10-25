#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/boundary_signal_isolation.rs"]
mod isolation;
#[allow(dead_code)]
#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::contracts::*;
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::{HookContext, translate_program_counter};
use oracle::{
    HookEvent, HookEventLog, HookExpectation, NativeOracle, NativeTrace, SignalResume, TraceMap,
};

use oracle::boundary_signal::{BoundarySignalVisit, assert_boundary_signal_inventory};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const ID: u64 = 0xb051;
struct Puzzle {
    name: &'static str,
    bytes: &'static [u8],
    heads: &'static [u64],
    logical: u64,
    displaced: usize,
    points_per_phase: usize,
}
const PUZZLES: [Puzzle; 2] = [
    Puzzle {
        name: "same-site-nop5",
        bytes: &[0x0f, 0x1f, 0x44, 0, 0, 0xc3],
        heads: &[0, 5],
        logical: 0,
        displaced: 5,
        points_per_phase: 10,
    },
    Puzzle {
        name: "upstream-rip-lea",
        bytes: &[0x48, 0x8d, 0x05, 0xf9, 0xff, 0xff, 0xff, 0x89, 0xc0, 0xc3],
        heads: &[0, 7, 9],
        logical: 7,
        displaced: 9,
        points_per_phase: 18,
    },
];
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
fn check_trace(
    native: &NativeOracle,
    trace: &NativeTrace,
    map: &TraceMap,
    routed: &[u64],
    hooks: HookExpectation<'_>,
    signal: &SignalResume,
) -> usize {
    let expected: Vec<_> = trace
        .visits()
        .iter()
        .map(|&logical| {
            let candidates: Vec<_> = map
                .boundaries
                .iter()
                .filter(|&&(pc, _)| pc == logical)
                .collect();
            assert_eq!(
                candidates.len(),
                1,
                "fixed fixture needs one physical implementation per head"
            );
            (logical, candidates[0].1)
        })
        .collect();
    let entry = trace.visits()[0];
    let before = signal.completed_roundtrips();
    let actual: Vec<BoundarySignalVisit> =
        native.assert_trace_at_signal_boundaries(trace, entry, map, routed, Some(hooks), signal);
    assert_boundary_signal_inventory(&actual, &expected);
    assert_eq!(signal.completed_roundtrips() - before, trace.visits().len());
    let mut generated = 0;
    for visit in actual {
        if visit.physical_pc != visit.logical_pc {
            generated += 1;
            assert_eq!(
                translate_program_counter(visit.physical_pc),
                Some(visit.logical_pc)
            );
        } else {
            assert_eq!(translate_program_counter(visit.physical_pc), None);
        }
    }
    generated
}
fn check_image(image: &liteinst2::trampoline::TrampolineImage) {
    assert_eq!(
        unsafe {
            std::slice::from_raw_parts(image.address() as usize as *const u8, image.bytes().len())
        },
        image.bytes()
    );
}
pub fn run_boundary_signals_every_restored_visit() {
    assert_eq!(PUZZLES.iter().map(|p| p.heads.len()).sum::<usize>(), 5);
    assert_eq!(
        PUZZLES.iter().map(|p| p.points_per_phase).sum::<usize>(),
        28
    );
    let mut retained = Vec::new();
    let mut traces_by_phase = [0; 3];
    let mut rounds_by_phase = [0; 3];
    let mut generated_rounds = 0;
    let mut selected_events = 0;
    let mut originals = 0;
    for (index, puzzle) in PUZZLES.iter().enumerate() {
        let mut native = NativeOracle::new(puzzle.bytes);
        let base = native.code.address();
        let identity = CodeIdentity {
            source: SourceIdentity([0xb0 + index as u8; 32]),
            mapping: index as u64 + 1,
            generation: 1,
        };
        let function = AddressRange::new(base, puzzle.bytes.len()).unwrap();
        let source = AddressRange::new(base, 4096).unwrap();
        let heads: Vec<_> = puzzle.heads.iter().map(|off| base + off).collect();
        let entries = LegalEntrySet {
            identity,
            scope: function,
            provenance: EntryProvenance::Declared("literal boundary-signal source heads".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: heads
                .iter()
                .map(|&address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let target = base + 64 * 1024 * 1024 + index as u64 * 2 * 1024 * 1024;
        let allocation = AllocationPolicy {
            ranges: vec![AddressRange::new(target, 4096).unwrap()],
            preferred_address: Some(target),
            max_candidates: 1,
            max_mappings: 1,
            max_mapped_bytes: 4096,
        };
        let plan = plan_install(&InstallRequest {
            identity,
            code: puzzle.bytes,
            base_address: base,
            function,
            block: function,
            logical_pc: base + puzzle.logical,
            entries: &entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: puzzle.logical as usize,
                max_displaced_bytes: puzzle.displaced,
                max_sites: if index == 0 { 1 } else { 2 },
            },
        })
        .expect("required boundary-signal relocation positive refused");
        assert_eq!(plan.plan().parts().kind, PlanKind::Relocation);
        assert_eq!(plan.plan().parts().physical_pc, base);
        assert_eq!(plan.plan().parts().logical_pc, base + puzzle.logical);
        assert_eq!(
            plan.plan().parts().displaced,
            AddressRange::new(base, puzzle.displaced).unwrap()
        );
        assert_eq!(plan.image().address(), target);
        let mut expected_jump = vec![0xe9];
        expected_jump.extend_from_slice(&i32::try_from(target - base - 5).unwrap().to_le_bytes());
        if index == 1 {
            // The one relocation edit covers LEA7 + MOV2. Offsets 5/6
            // retain the LEA displacement; offset 7 is the owned PUSHA
            // marker, and offset 8 retains MOV's original ModR/M byte.
            // The ten-byte snapshot cannot certify a 15-byte EVEX fetch.
            assert_eq!(&puzzle.bytes[5..9], &[0xff, 0xff, 0x89, 0xc0]);
            expected_jump.extend_from_slice(&[0xff, 0xff, 0x60, 0xc0]);
        }
        assert_eq!(expected_jump.len(), puzzle.displaced);
        assert_eq!(plan.plan().parts().writes.len(), 1);
        assert_eq!(plan.plan().parts().writes[0].address, base);
        assert_eq!(plan.plan().parts().writes[0].bytes, expected_jump);
        assert_eq!(
            plan.image()
                .instruction_boundaries()
                .iter()
                .map(|&(pc, _)| pc)
                .collect::<Vec<_>>(),
            heads
                .iter()
                .copied()
                .filter(|&pc| pc < base + puzzle.displaced as u64)
                .collect::<Vec<_>>()
        );
        let routed: Vec<_> = plan
            .plan()
            .parts()
            .obligations
            .iter()
            .filter_map(|o| match o {
                EntryObligation::Routed(r) => Some(r.original),
                _ => None,
            })
            .collect();
        assert_eq!(routed, if index == 0 { vec![] } else { vec![base + 7] });
        if index == 1 {
            // This marker belongs to the single authenticated full-span edit,
            // not a second ByteEdit. The route obligation above stays exact.
            assert_eq!(plan.plan().parts().writes[0].address + 7, base + 7);
            assert_eq!(&plan.plan().parts().writes[0].bytes[7..8], &[0x60]);
        }
        let all: Vec<_> = heads.iter().copied().chain([native.return_pc()]).collect();
        let direct = TraceMap {
            boundaries: all.iter().map(|&pc| (pc, pc)).collect(),
            gateways: vec![],
            generated_ranges: vec![],
        };
        let mut installed_map = TraceMap {
            boundaries: vec![],
            gateways: vec![],
            generated_ranges: std::iter::once(target..target + plan.image().bytes().len() as u64)
                .collect(),
        };
        for &pc in &all {
            if plan.plan().parts().displaced.contains(pc) {
                let matches: Vec<_> = plan
                    .image()
                    .instruction_boundaries()
                    .iter()
                    .filter(|&&(original, _)| original == pc)
                    .collect();
                assert_eq!(matches.len(), 1);
                installed_map.boundaries.push(*matches[0]);
                installed_map.gateways.push(pc);
            } else {
                installed_map.boundaries.push((pc, pc));
            }
        }
        let mut traces = Vec::new();
        for seed in SEEDS {
            for (start, &entry) in heads.iter().enumerate() {
                let trace = native.trace_original(entry, &heads, &[native.return_pc()], seed);
                assert_eq!(
                    trace.visits(),
                    heads[start..]
                        .iter()
                        .copied()
                        .chain([native.return_pc()])
                        .collect::<Vec<_>>()
                );
                originals += 1;
                traces.push((entry, trace));
            }
        }
        assert_eq!(
            traces
                .iter()
                .map(|(_, trace)| trace.visits().len())
                .sum::<usize>(),
            puzzle.points_per_phase
        );
        let signal = unsafe { SignalResume::new() };
        let log = HookEventLog::new();
        let enabled = [HookEvent {
            probe_id: ID,
            logical_pc: base + puzzle.logical,
        }];
        for (_, trace) in &traces {
            assert_eq!(
                check_trace(
                    &native,
                    trace,
                    &direct,
                    &[],
                    HookExpectation {
                        log: &log,
                        enabled: &[]
                    },
                    &signal
                ),
                0
            );
            traces_by_phase[0] += 1;
            rounds_by_phase[0] += trace.visits().len();
        }
        let pointer = native.code.writable();
        let (mut installed, receipt) = {
            let mut lease = unsafe { QuiescenceLease::new(&mut native, identity, vec![source]) };
            permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            unsafe {
                plan.publish_with(pointer, &mut lease, || {
                    permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap()
        };
        assert_eq!(receipt.plan().parts().identity, identity);
        let edits: Vec<_> = plan
            .plan()
            .parts()
            .writes
            .iter()
            .map(|e| (e.address, e.bytes.clone()))
            .collect();
        native.assert_publication(&edits);
        check_image(plan.image());
        for (_, trace) in &traces {
            generated_rounds += check_trace(
                &native,
                trace,
                &installed_map,
                &routed,
                HookExpectation {
                    log: &log,
                    enabled: &enabled,
                },
                &signal,
            );
            selected_events += trace
                .visits()
                .iter()
                .filter(|&&pc| pc == base + puzzle.logical)
                .count();
            traces_by_phase[1] += 1;
            rounds_by_phase[1] += trace.visits().len();
            native.assert_publication(&edits);
            check_image(plan.image());
        }
        {
            let mut ranges = vec![source];
            ranges.extend(plan.plan().parts().allocations.iter().map(|a| a.range));
            let mut lease = unsafe { QuiescenceLease::new(&mut native, identity, ranges) };
            permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            unsafe {
                installed.retire_with(&mut lease, || {
                    permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap();
        }
        native.assert_publication(&[]);
        check_image(plan.image());
        for (_, trace) in &traces {
            assert_eq!(
                check_trace(
                    &native,
                    trace,
                    &direct,
                    &[],
                    HookExpectation {
                        log: &log,
                        enabled: &[]
                    },
                    &signal
                ),
                0
            );
            traces_by_phase[2] += 1;
            rounds_by_phase[2] += trace.visits().len();
        }
        assert_eq!(signal.completed_roundtrips(), 3 * puzzle.points_per_phase);
        eprintln!(
            "boundary-signal layout={} entries={} baseline={} signals_per_phase={} physical_kernel_RIP_preserved=true unwind_qualified=false",
            puzzle.name,
            heads.len(),
            traces.len(),
            puzzle.points_per_phase
        );
        drop(signal);
        retained.push(native);
    }
    assert_eq!(originals, 10);
    assert_eq!(traces_by_phase, [10, 10, 10]);
    assert_eq!(rounds_by_phase, [28, 28, 28]);
    assert_eq!(generated_rounds, 8);
    assert_eq!(selected_events, 6);
    assert_eq!(retained.len(), 2);
    eprintln!(
        "boundary-signal complete: layouts=2 heads=5 seeds=2 baseline=10 traces=30 original=10 installed=10 retired=10 signal_roundtrips=84 generated_boundaries=8 source_boundaries=76 selected_events=6 unwind_qualified=false"
    );
}
pub fn isolated_main() {
    isolation::main_thread_driver();
}
#[test]
fn boundary_signals_every_restored_visit() {
    isolation::run_parent("boundary_signals_every_restored_visit");
}
