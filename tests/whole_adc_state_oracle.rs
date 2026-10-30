#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Fixed ADC encoding-family evidence through the actual whole-function emitter.
//! Setup remains outside the complete read-only leaf; entry and RET are observed.
//! This is not a complete selected-session SDK/ABI or concurrency qualification.
//! All bytes, heads, carries and expected answers are independent of iced-x86.

#[path = "support/adc_fixtures.rs"]
mod adc;
#[path = "support/isolated_native_test.rs"]
mod isolated_native_test;
#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, LegalEntry,
    LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::quiescent::{
    AllocationPolicy, WholeFunctionRequest, plan_whole_function_controlled_detailed,
};
use liteinst2::trampoline::HookContext;
use oracle::{HookEvent, HookEventLog, HookExpectation, NativeOracle, TraceMap};

const PROBE_ID: u64 = 0xadc;

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: assert_trace activates this child's bounded private event log.
    // The callback observes without editing HookContext/application memory.
    unsafe {
        oracle::record_hook_event(PROBE_ID, (*context).instruction_pointer);
        // Deterministically clear CF and clobber caller-saved state. CF=1
        // fixtures therefore require the real trampoline's flag restoration.
        core::arch::asm!(
            "xor eax, eax",
            "pxor xmm0, xmm0",
            "fninit",
            out("rax") _,
            out("xmm0") _,
            options(nostack),
        );
    }
}

unsafe extern "C" fn observe_return(context: *mut HookContext) {
    // SAFETY: assert_trace activates this child's bounded private event log.
    // The callback observes without editing HookContext/application memory.
    unsafe {
        oracle::record_hook_event(PROBE_ID + 1, (*context).instruction_pointer);
        // Deterministically clear CF and clobber caller-saved state. CF=1
        // fixtures therefore require the real trampoline's flag restoration.
        core::arch::asm!(
            "xor eax, eax",
            "pxor xmm0, xmm0",
            "fninit",
            out("rax") _,
            out("xmm0") _,
            options(nostack),
        );
    }
}

fn permissions(pointer: *mut u8, protection: i32) -> Result<(), Refusal> {
    // SAFETY: every call retains this exact private source page under a lease.
    if unsafe { libc::mprotect(pointer.cast(), 4096, protection) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

fn run_width(width: u32, expected_families: usize) {
    let forms = adc::forms(width);
    assert_eq!(forms.len(), expected_families);
    let mut comparisons = 0;
    let mut retained_fixtures = Vec::new();
    for form in forms {
        for (case_index, (left, right)) in adc::operands(width, form).into_iter().enumerate() {
            let fixture = adc::fixture(width, form, left, right);
            // Both carries execute exactly these same bytes and seed-independent
            // MOV setup. Nothing writes flags between the hook and the ADC.
            let mut native = NativeOracle::with_seeded_memory_and_flags(&fixture.bytes, 0xadc);
            let base = native.code.address();
            let source = AddressRange::new(base, fixture.bytes.len()).unwrap();
            let selected = base + fixture.adc as u64;
            let leaf = &fixture.bytes[fixture.adc..];
            let leaf_scope = AddressRange::new(selected, leaf.len()).unwrap();
            let ret = base + fixture.bytes.len() as u64 - 1;
            assert!((5..=80).contains(&leaf.len()));
            assert_eq!(leaf.last(), Some(&0xc3));
            let heads: Vec<_> = fixture.heads.iter().map(|&at| base + at as u64).collect();
            let identity = CodeIdentity {
                source: SourceIdentity([width as u8; 32]),
                mapping: comparisons as u64 + 1,
                generation: 1,
            };
            let entries = LegalEntrySet {
                identity,
                scope: leaf_scope,
                provenance: EntryProvenance::Declared(format!("adc-{width}-{form:?}-{case_index}")),
                completeness: EntryCompleteness::Complete,
                // The complete straight-line leaf has exactly one leader.
                // Setup is outside the selected source range, never admitted
                // as a write-capable whole-function operation.
                entries: vec![LegalEntry {
                    address: selected,
                    requires_endbr: false,
                }],
                resumes: ResumeObligation::NoneExist,
            };
            let mut allocation = AllocationPolicy::near(selected).unwrap();
            // Fresh-exec isolation removes parallel arena competitors; this
            // bounded preferred target keeps successive owned fixtures apart.
            allocation.preferred_address =
                Some(base + 64 * 1024 * 1024 + retained_fixtures.len() as u64 * 1024 * 1024);
            let actions = [
                ControlledAction {
                    logical_pc: selected,
                    control: ProbeControl::new(observe, true),
                },
                ControlledAction {
                    logical_pc: ret,
                    control: ProbeControl::new(observe_return, true),
                },
            ];
            // SAFETY: handwritten complete scalar leaf, exact sole external
            // entry/RET, no active executions or saved resumes. Setup executes
            // outside the leaf and falls through its one declared entry.
            let prepared = unsafe {
                plan_whole_function_controlled_detailed(
                    &WholeFunctionRequest {
                        identity,
                        code: leaf,
                        base_address: selected,
                        entries: &entries,
                        allocation: &allocation,
                    },
                    &actions,
                )
            }
            .unwrap_or_else(|error| {
                panic!("required whole ADC {width}/{form:?}/{case_index}: {error:?}")
            });
            assert_eq!(prepared.plan().parts().displaced, leaf_scope);
            assert_eq!(prepared.plan().parts().reads.len(), 1);
            assert_eq!(prepared.plan().parts().reads[0].address, selected);
            assert_eq!(prepared.plan().parts().reads[0].bytes, leaf);
            assert_eq!(prepared.image().controls().len(), 2);
            assert_eq!(
                prepared.image().controls(),
                actions
                    .iter()
                    .map(|a| a.control.clone())
                    .collect::<Vec<_>>()
            );
            assert!(matches!(
                &prepared.plan().parts().kind,
                PlanKind::Relocation
            ));
            assert_eq!(prepared.plan().parts().logical_pc, selected);
            assert_eq!(prepared.plan().parts().physical_pc, selected);
            let owned_sigill: Vec<_> = prepared
                .plan()
                .parts()
                .obligations
                .iter()
                .filter_map(|item| {
                    if let EntryObligation::Routed(route) = item {
                        Some(route.original)
                    } else {
                        None
                    }
                })
                .collect();
            let parts = prepared.plan().parts();
            let mut boundaries = prepared.image().instruction_boundaries().to_vec();
            for pc in heads.iter().copied().chain([native.return_pc()]) {
                if parts.displaced.contains(pc) {
                    assert!(boundaries.iter().any(|&(original, _)| original == pc));
                } else {
                    let end = heads
                        .iter()
                        .copied()
                        .find(|&head| head > pc)
                        .unwrap_or(pc + 1);
                    assert!(
                        parts.writes.iter().all(|write| {
                            write.address >= end || write.address + write.bytes.len() as u64 <= pc
                        }),
                        "identity boundary must retain its entire original instruction"
                    );
                    assert!(!boundaries.iter().any(|&(original, _)| original == pc));
                    boundaries.push((pc, pc));
                }
            }
            let map = TraceMap {
                boundaries,
                gateways: vec![selected],
                generated_ranges: std::iter::once(
                    prepared.image().address()
                        ..prepared.image().address() + prepared.image().bytes().len() as u64,
                )
                .collect(),
            };
            let edits: Vec<_> = prepared
                .plan()
                .parts()
                .writes
                .iter()
                .map(|edit| (edit.address, edit.bytes.clone()))
                .collect();
            let mut originals = Vec::new();
            for carry in [false, true] {
                let seed = 0x1234_5678_8765_0000
                    | (if case_index % 2 == 0 { 0x400 } else { 0x8d4 })
                    | u64::from(carry);
                let trace = native.trace_original(base, &heads, &[native.return_pc()], seed);
                let mut expected_visits = heads.clone();
                expected_visits.push(native.return_pc());
                assert_eq!(trace.visits(), expected_visits);
                let (destination, flags) = adc::answer(width, form, left, right, carry);
                trace.assert_adc_boundary_state(
                    selected,
                    base + fixture.after_adc as u64,
                    adc::extended(form),
                    carry,
                    destination,
                    flags,
                );
                originals.push(trace);
            }
            let writable = native.code.writable();
            // SAFETY: fixture.adc is an authenticated in-page instruction head;
            // the whole request snapshot begins there, not at the setup prefix.
            let leaf_writable = unsafe { writable.add(fixture.adc) };
            let (mut installed, receipt) = {
                // SAFETY: every original child is reaped; this exclusive owner
                // excludes executors, escaped pointers and saved continuations.
                let mut lease =
                    unsafe { QuiescenceLease::new(&mut native, identity, vec![source]) };
                permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
                // SAFETY: exact source bytes and full private page are owned;
                // the finalizer restores RX before sync-core and publication.
                unsafe {
                    prepared.publish_with(leaf_writable, &mut lease, || {
                        permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                    })
                }
                .unwrap()
            };
            assert_eq!(receipt.plan().parts().identity, identity);
            native.assert_publication(&edits);
            let log = HookEventLog::with_capacity(2);
            let enabled = [
                HookEvent {
                    probe_id: PROBE_ID,
                    logical_pc: selected,
                },
                HookEvent {
                    probe_id: PROBE_ID + 1,
                    logical_pc: ret,
                },
            ];
            for trace in &originals {
                // The unchanged ordered oracle checks ALL GPR/RFLAGS, exposed
                // xstate, data and application stack/red-zone bytes at EVERY
                // restored head, plus the exact two-event entry/RET callback log.
                native.assert_trace(
                    trace,
                    base,
                    &map,
                    &owned_sigill,
                    Some(HookExpectation {
                        log: &log,
                        enabled: &enabled,
                    }),
                );
                comparisons += 1;
            }
            {
                let mut ranges = vec![source];
                ranges.extend(
                    prepared
                        .plan()
                        .parts()
                        .allocations
                        .iter()
                        .map(|item| item.range),
                );
                // SAFETY: all patched children are reaped; the exclusive owner
                // drains source/generated execution and every saved resume.
                let mut lease = unsafe { QuiescenceLease::new(&mut native, identity, ranges) };
                permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
                // SAFETY: the retained source page stays owned through final RX.
                unsafe {
                    installed.retire_with(&mut lease, || {
                        permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                    })
                }
                .unwrap();
            }
            native.assert_publication(&[]);
            retained_fixtures.push(native);
        }
    }
    assert_eq!(comparisons, expected_families * 6 * 2);
    assert_eq!(retained_fixtures.len(), expected_families * 6);
    eprintln!(
        "WHOLE ADC{width}: {expected_families} encoding families, {comparisons} required native state comparisons, zero mismatches"
    );
}

#[test]
fn native_whole_adc_8_bit_state_and_carry_survive_the_hook() {
    isolated_native_test::run(
        "native_whole_adc_8_bit_state_and_carry_survive_the_hook",
        "LITEINST2_WHOLE_ADC_ORACLE_8",
        || run_width(8, 9),
    );
}

#[test]
fn native_whole_adc_16_bit_state_and_carry_survive_the_hook() {
    isolated_native_test::run(
        "native_whole_adc_16_bit_state_and_carry_survive_the_hook",
        "LITEINST2_WHOLE_ADC_ORACLE_16",
        || run_width(16, 7),
    );
}

#[test]
fn native_whole_adc_32_bit_state_and_carry_survive_the_hook() {
    isolated_native_test::run(
        "native_whole_adc_32_bit_state_and_carry_survive_the_hook",
        "LITEINST2_WHOLE_ADC_ORACLE_32",
        || run_width(32, 7),
    );
}

#[test]
fn native_whole_adc_64_bit_state_and_carry_survive_the_hook() {
    isolated_native_test::run(
        "native_whole_adc_64_bit_state_and_carry_survive_the_hook",
        "LITEINST2_WHOLE_ADC_ORACLE_64",
        || run_width(64, 8),
    );
}
