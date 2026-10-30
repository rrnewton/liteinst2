#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Fixed ADC encoding-family evidence through the actual generic trampoline.
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
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
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

#[test]
fn adc_arithmetic_answers_have_independent_literal_calibration() {
    use adc::Form::RegisterFromRm;
    // Flags are literal OF/SF/ZF/AF/PF/CF answers, not a second copy of the
    // arithmetic formula. Cases distinguish carry, overflow, parity and AF.
    for (left, right, carry, low, flags) in [
        (0, 0, false, 0, 0x44),
        (0, 0, true, 1, 0),
        (0xff, 0, true, 0, 0x55),
        (0x7f, 0, true, 0x80, 0x890),
        (0x0f, 1, false, 0x10, 0x10),
        (0x80, 0xff, false, 0x7f, 0x801),
        (0xff, 1, true, 1, 0x11),
        (0x55, 0, true, 0x56, 0x04),
    ] {
        assert_eq!(
            adc::answer(8, RegisterFromRm, left, right, carry),
            (0xa5f0_1234_0000_0000 | low, flags)
        );
    }
    for width in [16, 32, 64] {
        let maximum = adc::mask(width);
        let sign = 1_u64 << (width - 1);
        let preserved = if width == 16 {
            0xa5f0_1234_0000_0000
        } else {
            0
        };
        assert_eq!(
            adc::answer(width, RegisterFromRm, maximum, 0, true),
            (preserved, 0x55)
        );
        assert_eq!(
            adc::answer(width, RegisterFromRm, sign - 1, 0, true),
            (preserved | sign, 0x894)
        );
        assert_eq!(
            adc::answer(width, RegisterFromRm, sign, maximum, false),
            (preserved | (sign - 1), 0x805)
        );
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
            let heads: Vec<_> = fixture.heads.iter().map(|&at| base + at as u64).collect();
            let identity = CodeIdentity {
                source: SourceIdentity([width as u8; 32]),
                mapping: comparisons as u64 + 1,
                generation: 1,
            };
            let entries = LegalEntrySet {
                identity,
                scope: source,
                provenance: EntryProvenance::Declared(format!("adc-{width}-{form:?}-{case_index}")),
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
            let mut allocation = AllocationPolicy::near(selected).unwrap();
            // Fresh-exec isolation removes parallel arena competitors; this
            // bounded preferred target keeps successive owned fixtures apart.
            allocation.preferred_address =
                Some(base + 64 * 1024 * 1024 + retained_fixtures.len() as u64 * 1024 * 1024);
            let prepared = plan_install(&InstallRequest {
                identity,
                code: &fixture.bytes,
                base_address: base,
                function: source,
                block: source,
                logical_pc: selected,
                entries: &entries,
                hook: observe,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    ..SearchPolicy::default()
                },
            })
            .unwrap_or_else(|error| {
                panic!("required ADC {width}/{form:?}/{case_index}: {error:?}")
            });
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
            let (mut installed, receipt) = {
                // SAFETY: every original child is reaped; this exclusive owner
                // excludes executors, escaped pointers and saved continuations.
                let mut lease =
                    unsafe { QuiescenceLease::new(&mut native, identity, vec![source]) };
                permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
                // SAFETY: exact source bytes and full private page are owned;
                // the finalizer restores RX before sync-core and publication.
                unsafe {
                    prepared.publish_with(writable, &mut lease, || {
                        permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                    })
                }
                .unwrap()
            };
            assert_eq!(receipt.plan().parts().identity, identity);
            native.assert_publication(&edits);
            let log = HookEventLog::with_capacity(1);
            let enabled = [HookEvent {
                probe_id: PROBE_ID,
                logical_pc: selected,
            }];
            for trace in &originals {
                // The unchanged ordered oracle checks ALL GPR/RFLAGS, exposed
                // xstate, data and application stack/red-zone bytes at EVERY
                // restored head, plus the exact one-event callback log.
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
        "ADC{width}: {expected_families} encoding families, {comparisons} required native state comparisons, zero mismatches"
    );
}

#[test]
fn native_adc_8_bit_state_and_carry_survive_the_hook() {
    isolated_native_test::run(
        "native_adc_8_bit_state_and_carry_survive_the_hook",
        "LITEINST2_ADC_ORACLE_8",
        || run_width(8, 9),
    );
}

#[test]
fn native_adc_16_bit_state_and_carry_survive_the_hook() {
    isolated_native_test::run(
        "native_adc_16_bit_state_and_carry_survive_the_hook",
        "LITEINST2_ADC_ORACLE_16",
        || run_width(16, 7),
    );
}

#[test]
fn native_adc_32_bit_state_and_carry_survive_the_hook() {
    isolated_native_test::run(
        "native_adc_32_bit_state_and_carry_survive_the_hook",
        "LITEINST2_ADC_ORACLE_32",
        || run_width(32, 7),
    );
}

#[test]
fn native_adc_64_bit_state_and_carry_survive_the_hook() {
    isolated_native_test::run(
        "native_adc_64_bit_state_and_carry_survive_the_hook",
        "LITEINST2_ADC_ORACLE_64",
        || run_width(64, 8),
    );
}
