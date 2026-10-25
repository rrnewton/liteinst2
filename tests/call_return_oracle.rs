#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet,
    PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use oracle::{HookEvent, HookEventLog, HookExpectation, NativeOracle, TraceMap};

const ID: u64 = 0xe401;
const SOURCE_OFFSET: usize = 0x100;
const BODY_HEADS: [usize; 8] = [0, 7, 8, 9, 11, 12, 17, 64];

unsafe extern "C" fn observe(context: *mut HookContext) {
    unsafe {
        oracle::record_hook_event(ID, (*context).instruction_pointer);
        core::arch::asm!("add rax, 1", "pxor xmm0, xmm0", "fninit",
            out("rax") _, out("xmm0") _, options(nostack));
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

fn fixture(register: u8) -> Vec<u8> {
    assert!(matches!(register, 0 | 7));
    let mut bytes = vec![0xcc; 0x200];
    // LEA RAX/RDI,[RIP+helper]; selected NOP; NOP; CALL RAX/RDI;
    // return NOP; MOV EAX,42; RET. The CALL stays at its original address.
    bytes[..3].copy_from_slice(&[0x48, 0x8d, 0x05 | register << 3]);
    bytes[3..7].copy_from_slice(&57_i32.to_le_bytes());
    bytes[7..18].copy_from_slice(&[
        0x90,
        0x90,
        0xff,
        0xd0 | register,
        0x90,
        0xb8,
        42,
        0,
        0,
        0,
        0xc3,
    ]);
    bytes[64] = 0xc3;
    // Literal dispatchers seed the callee address before entering every body
    // head, so entry at CALL has a valid original context in both images.
    for (index, target) in BODY_HEADS.into_iter().enumerate() {
        let at = 0x100 + index * 12;
        bytes[at..at + 3].copy_from_slice(&[0x48, 0x8d, 0x05 | register << 3]);
        bytes[at + 3..at + 7].copy_from_slice(&(64_i32 - (at + 7) as i32).to_le_bytes());
        bytes[at + 7] = 0xe9;
        bytes[at + 8..at + 12].copy_from_slice(&(target as i32 - (at + 12) as i32).to_le_bytes());
    }
    let mut page_prefix = vec![0xcc; SOURCE_OFFSET];
    page_prefix.extend(bytes);
    page_prefix
}

#[test]
fn original_call_returns_inside_unchanged_pun_displacement() {
    let mut retained = Vec::new();
    let mut counts = [0_usize; 4];
    for register in [0_u8, 7] {
        let bytes = fixture(register);
        let mut native = NativeOracle::new(&bytes);
        let base = native.code.address() + SOURCE_OFFSET as u64;
        let selected = base + 7;
        let source = AddressRange::new(base, 18).unwrap();
        let mut all_heads = BODY_HEADS.map(|offset| base + offset as u64).to_vec();
        for index in 0..BODY_HEADS.len() {
            let dispatcher = base + 0x100 + index as u64 * 12;
            all_heads.extend([dispatcher, dispatcher + 7]);
        }
        let terminal = native.return_pc();
        let mut traces = Vec::new();
        for seed in [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567] {
            for (index, target) in BODY_HEADS.into_iter().enumerate() {
                let entry = base + 0x100 + index as u64 * 12;
                let mut expected = vec![entry, entry + 7];
                let body: &[usize] = match target {
                    0 => &[0, 7, 8, 9, 64, 11, 12, 17],
                    7 => &[7, 8, 9, 64, 11, 12, 17],
                    8 => &[8, 9, 64, 11, 12, 17],
                    9 => &[9, 64, 11, 12, 17],
                    11 => &[11, 12, 17],
                    12 => &[12, 17],
                    17 => &[17],
                    64 => &[64],
                    _ => unreachable!(),
                };
                expected.extend(body.iter().map(|&offset| base + offset as u64));
                expected.push(terminal);
                let trace = native.trace_original(entry, &all_heads, &[terminal], seed);
                assert_eq!(trace.visits(), expected);
                traces.push((entry, trace));
                counts[0] += 1;
            }
        }
        let identity = CodeIdentity {
            source: SourceIdentity([register + 0x61; 32]),
            mapping: base,
            generation: 1,
        };
        let entries = LegalEntrySet {
            identity,
            scope: source,
            provenance: EntryProvenance::Declared(
                "literal original CALL return at selected+4 in unchanged pun displacement".into(),
            ),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: BODY_HEADS[..7]
                .iter()
                .map(|&offset| LegalEntry {
                    address: base + offset as u64,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let displacement = i32::from_le_bytes(
            bytes[SOURCE_OFFSET + 8..SOURCE_OFFSET + 12]
                .try_into()
                .unwrap(),
        );
        let target = u64::try_from(i128::from(selected + 5) + i128::from(displacement)).unwrap();
        let allocation = AllocationPolicy {
            ranges: vec![AddressRange::new(target & !4095, 4096).unwrap()],
            preferred_address: Some(target),
            max_candidates: 1,
            max_mappings: 1,
            max_mapped_bytes: 4096,
        };
        let mut request = InstallRequest {
            identity,
            code: &bytes[SOURCE_OFFSET..SOURCE_OFFSET + 18],
            base_address: base,
            function: source,
            block: AddressRange::new(selected, 11).unwrap(),
            logical_pc: selected,
            entries: &entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::GeneralizedPunOnly,
                max_upstream_bytes: 0,
                max_displaced_bytes: 1,
                max_sites: 1,
            },
        };
        let plan = plan_install(&request).unwrap();
        let parts = plan.plan().parts();
        let PlanKind::GeneralizedPun(pun) = &parts.kind else {
            panic!("required generalized pun was substituted");
        };
        assert_eq!(pun.instruction_len, 1);
        assert_eq!(pun.consumed, AddressRange::new(selected, 5).unwrap());
        assert_eq!(pun.target_window, AddressRange::new(target, 1).unwrap());
        assert!(pun.consumed.contains(base + 11));
        assert_eq!(pun.store.address, selected);
        assert_eq!(pun.store.bytes, [0xe9]);
        assert_eq!(parts.displaced, AddressRange::new(selected, 1).unwrap());
        assert_eq!(parts.writes.len(), 1);
        assert_eq!(parts.writes[0].address, selected);
        assert_eq!(parts.writes[0].bytes, [0xe9]);
        assert_eq!(plan.image().address(), target);
        assert!(!parts.requirements.sigill_router);
        let original_map = TraceMap {
            boundaries: all_heads
                .iter()
                .copied()
                .chain([terminal])
                .map(|pc| (pc, pc))
                .collect(),
            gateways: vec![],
            generated_ranges: vec![],
        };
        // The same window cannot relocate its CALL. This required refusal is
        // separate from the successful pun preserving the original CALL/RET.
        request.search.tactics = TacticPolicy::RelocationOnly;
        request.search.max_displaced_bytes = 5;
        assert_eq!(
            plan_install(&request).unwrap_err(),
            Refusal::UnsupportedSemantics("Call has no qualified A1 relocation contract".into())
        );
        native.assert_publication(&[]);
        for (entry, trace) in &traces {
            native.assert_trace(trace, *entry, &original_map, &[], None);
            counts[1] += 1;
        }
        let mut installed_map = TraceMap {
            boundaries: original_map
                .boundaries
                .iter()
                .copied()
                .filter(|&(pc, _)| pc != selected)
                .collect(),
            gateways: vec![selected],
            generated_ranges: std::iter::once(target..target + plan.image().bytes().len() as u64)
                .collect(),
        };
        installed_map
            .boundaries
            .extend(plan.image().instruction_boundaries());
        let pointer = native.code.writable();
        // SAFETY: the complete source snapshot lies inside this owned page.
        let writable_source = unsafe { pointer.add(SOURCE_OFFSET) };
        let (mut installed, receipt) = {
            let mut lease = unsafe { QuiescenceLease::new(&mut native, identity, vec![source]) };
            permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            unsafe {
                plan.publish_with(writable_source, &mut lease, || {
                    permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap()
        };
        assert_eq!(receipt.plan().parts().identity, identity);
        native.assert_publication(&[(selected, vec![0xe9])]);
        let log = HookEventLog::new();
        let enabled = [HookEvent {
            probe_id: ID,
            logical_pc: selected,
        }];
        for (entry, trace) in &traces {
            native.assert_trace(
                trace,
                *entry,
                &installed_map,
                &[],
                Some(HookExpectation {
                    log: &log,
                    enabled: &enabled,
                }),
            );
            assert_eq!(
                unsafe {
                    core::slice::from_raw_parts(target as *const u8, plan.image().bytes().len())
                },
                plan.image().bytes()
            );
            counts[2] += 1;
        }
        {
            let mut ranges = vec![source];
            ranges.extend(parts.allocations.iter().map(|a| a.range));
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
        for (entry, trace) in &traces {
            native.assert_trace(trace, *entry, &original_map, &[], None);
            counts[3] += 1;
        }
        retained.push(native);
    }
    assert_eq!(counts, [32, 32, 32, 32]);
    println!(
        "call_return original=32 refused_preserved=32 installed=32 retired=32 authenticated_hooks=8 actual_call_return_paths_per_phase=16 relocation_refusals=2 relocated_CALL_support=false"
    );
}
