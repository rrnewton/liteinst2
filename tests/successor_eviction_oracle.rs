#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Required native T2 cases. The successor redirect's displacement bytes are
//! chosen independently; they make an originally unavailable selected pun fit.
//! Normal cases enter every original head with both seeds, including the
//! unhooked victim. The fault case enters its zeroing prefix and stops at the
//! declared victim fault; it does not claim execution of its unreachable RET.

#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::bundle::{BundleBudget, WritableAlias};
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, LegalEntry,
    LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::eviction::{EvictionKind, plan_successor};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use oracle::{HookEvent, HookEventLog, HookExpectation, NativeOracle, TraceMap};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const PROBE_ID: u64 = 0x702;

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the emitter supplies its live frame, and assert_trace activates
    // the isolated child's bounded private log. All clobbers are caller-saved.
    unsafe {
        oracle::record_hook_event(PROBE_ID, (*context).instruction_pointer);
        destroy_scratch_state();
    }
}

unsafe extern "C" fn fault_observe(_: *mut HookContext) {
    // SAFETY: the fault oracle uses the same no-op state contract without an
    // event log. The normal cases separately require exact callback events.
    unsafe { destroy_scratch_state() };
}

unsafe fn destroy_scratch_state() {
    // SAFETY: these user-mode instructions clobber only caller-saved scratch
    // state. The trampoline must restore the complete application state.
    unsafe {
        core::arch::asm!(
            "add rax, 1",
            "pxor xmm0, xmm0",
            "fninit",
            out("rax") _,
            out("xmm0") _,
            options(nostack),
        );
    }
}

fn permissions(pointer: *mut u8, protection: i32) -> Result<(), Refusal> {
    // SAFETY: callers retain the complete private source page under their lease.
    if unsafe { libc::mprotect(pointer.cast(), 4096, protection) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

struct Puzzle {
    name: &'static str,
    code: &'static [u8],
    heads: [usize; 4],
    selected_len: usize,
    prefixes: usize,
    victim_displacement: i32,
    selected_frozen: u32,
    original_frozen: u32,
}

#[test]
fn native_state_covers_successor_eviction_into_b2_and_t1_puns() {
    isolation::run_parent("native_state_covers_successor_eviction_into_b2_and_t1_puns");
}

pub fn run_native_state_covers_successor_eviction_into_b2_and_t1_puns() {
    let puzzles = [
        Puzzle {
            name: "T2-B2-LEA-MOV-store",
            // LEA RCX,[RDI]; MOV EAX,0x44332211; MOV [RDI],RAX; RET.
            code: &[
                0x48, 0x8d, 0x0f, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0x07, 0xc3,
            ],
            heads: [0, 3, 8, 11],
            selected_len: 3,
            prefixes: 0,
            victim_displacement: 0x0020_0010,
            selected_frozen: 0x10e9_0000,
            original_frozen: 0x11b8_0000,
        },
        Puzzle {
            name: "T2-T1-MOV-MOV-store",
            // MOV EAX,EAX; MOV ECX,0x44332211; MOV [RDI],RCX; RET.
            code: &[
                0x89, 0xc0, 0xb9, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0x0f, 0xc3,
            ],
            heads: [0, 2, 7, 10],
            selected_len: 2,
            prefixes: 1,
            victim_displacement: 0x0012_3456,
            selected_frozen: 0x1234_56e9,
            original_frozen: 0x3322_11b9,
        },
    ];
    let mut installed_comparisons = 0;
    let mut retired_comparisons = 0;
    let mut victim_entries = 0;
    let mut retained = Vec::new();
    for (index, puzzle) in puzzles.iter().enumerate() {
        let mut oracle = NativeOracle::new(puzzle.code);
        let base = oracle.code.address();
        let victim = base + puzzle.selected_len as u64;
        let heads = puzzle.heads.map(|offset| base + offset as u64);
        let source = AddressRange::new(base, puzzle.code.len()).unwrap();
        let block = AddressRange::new(base, puzzle.selected_len).unwrap();
        assert_eq!(
            block.end(),
            victim,
            "victim must be outside the selected block"
        );
        let identity = CodeIdentity {
            source: SourceIdentity([0xd0 + index as u8; 32]),
            mapping: base,
            generation: 1,
        };
        let entries = LegalEntrySet {
            identity,
            scope: source,
            provenance: EntryProvenance::Declared(puzzle.name.into()),
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
        let free = puzzle.selected_len - puzzle.prefixes - 1;
        let width = 1_usize << (8 * free);
        let selected_next = base + (5 + puzzle.prefixes) as u64;
        let selected_low =
            u64::try_from(i128::from(selected_next) + i128::from(puzzle.selected_frozen as i32))
                .unwrap();
        let expected_window = AddressRange::new(selected_low, width).unwrap();
        let selected_target = selected_low + width as u64 / 2;
        let selected_pages = AddressRange::new(selected_target & !4095, 8192).unwrap();
        let original_low =
            u64::try_from(i128::from(selected_next) + i128::from(puzzle.original_frozen as i32))
                .unwrap();
        assert!(!selected_pages.overlaps(AddressRange::new(original_low, width).unwrap()));
        assert_eq!(
            &puzzle.original_frozen.to_le_bytes()[free..],
            &puzzle.code[puzzle.selected_len..5 + puzzle.prefixes],
            "original bytes must force the handwritten unavailable window"
        );
        let victim_target =
            u64::try_from(i128::from(victim + 5) + i128::from(puzzle.victim_displacement)).unwrap();
        let mut selected_allocation = AllocationPolicy::near(base).unwrap();
        selected_allocation.ranges = vec![selected_pages];
        selected_allocation.preferred_address = Some(selected_target);
        let mut victim_allocation = AllocationPolicy::near(victim).unwrap();
        victim_allocation.ranges = vec![AddressRange::new(victim_target & !4095, 8192).unwrap()];
        victim_allocation.preferred_address = Some(victim_target);
        let request = InstallRequest {
            identity,
            code: puzzle.code,
            base_address: base,
            function: source,
            block,
            logical_pc: base,
            entries: &entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation: &selected_allocation,
            search: SearchPolicy {
                tactics: if puzzle.prefixes == 0 {
                    TacticPolicy::GeneralizedPunOnly
                } else {
                    TacticPolicy::PrefixPunOnly
                },
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        };
        assert_eq!(
            plan_install(&request).unwrap_err(),
            Refusal::AllocationUnavailable
        );
        let planned = plan_successor(&request, &victim_allocation, BundleBudget::default())
            .unwrap_or_else(|error| panic!("required {} refused: {error:?}", puzzle.name));
        assert_eq!(planned.kind(), EvictionKind::Successor { victim });
        let bundle = planned.bundle();
        let steps = bundle.plan().steps();
        assert_eq!(steps.len(), 2);
        assert_eq!(bundle.images().len(), 2);
        assert_eq!(steps[0].parts().physical_pc, victim);
        assert_eq!(steps[0].parts().logical_pc, victim);
        assert_eq!(
            steps[0].parts().displaced,
            AddressRange::new(victim, 5).unwrap()
        );
        assert!(matches!(steps[0].parts().kind, PlanKind::Relocation));
        assert_eq!(steps[0].parts().writes.len(), 1);
        let victim_edit = &steps[0].parts().writes[0];
        let mut expected_redirect = vec![0xe9];
        expected_redirect.extend_from_slice(&puzzle.victim_displacement.to_le_bytes());
        assert_eq!(victim_edit.address, victim);
        assert_eq!(victim_edit.bytes, expected_redirect);
        assert_eq!(bundle.images()[0].address(), victim_target);
        assert_eq!(bundle.images()[0].instruction_boundaries().len(), 1);
        assert_eq!(bundle.images()[0].instruction_boundaries()[0].0, victim);
        let selected = steps[1].parts();
        assert_eq!(selected.physical_pc, base);
        assert_eq!(selected.logical_pc, base);
        assert_eq!(
            selected.displaced,
            AddressRange::new(base, puzzle.selected_len).unwrap()
        );
        let (consumed, actual_window, store) = match &selected.kind {
            PlanKind::GeneralizedPun(pun) => {
                assert_eq!(puzzle.prefixes, 0);
                assert_eq!(pun.instruction_len as usize, puzzle.selected_len);
                (pun.consumed, pun.target_window, &pun.store)
            }
            PlanKind::PrefixedPun(pun) => {
                assert_eq!(puzzle.prefixes, 1);
                assert_eq!(pun.prefix_count as usize, puzzle.prefixes);
                assert_eq!(pun.instruction_len as usize, puzzle.selected_len);
                (pun.consumed, pun.target_window, &pun.store)
            }
            other => panic!("required selected pun became {other:?}"),
        };
        assert_eq!(
            consumed,
            AddressRange::new(base, 5 + puzzle.prefixes).unwrap()
        );
        assert_eq!(actual_window, expected_window);
        assert_eq!(bundle.images()[1].address(), selected_target);
        assert_eq!(bundle.images()[1].instruction_boundaries().len(), 1);
        assert_eq!(bundle.images()[1].instruction_boundaries()[0].0, base);
        assert_eq!(selected.writes.len(), 1);
        let selected_edit = &selected.writes[0];
        assert_eq!(selected_edit.address, base);
        assert_eq!(selected_edit.bytes.len(), puzzle.selected_len);
        assert_eq!(
            &selected_edit.bytes[..puzzle.prefixes],
            vec![0x2e; puzzle.prefixes]
        );
        assert_eq!(selected_edit.bytes[puzzle.prefixes], 0xe9);
        let mut overlay = puzzle.code.to_vec();
        overlay[puzzle.selected_len..puzzle.selected_len + 5].copy_from_slice(&expected_redirect);
        assert_eq!(
            &puzzle.selected_frozen.to_le_bytes()[free..],
            &overlay[puzzle.selected_len..5 + puzzle.prefixes]
        );
        assert_eq!(store.address, base);
        assert_eq!(store.bytes.len(), puzzle.selected_len.next_power_of_two());
        let mut expected_store = overlay[..store.bytes.len()].to_vec();
        expected_store[..puzzle.selected_len].copy_from_slice(&selected_edit.bytes);
        assert_eq!(
            store.bytes, expected_store,
            "selected store must preserve the victim E9 padding byte"
        );
        overlay[..puzzle.selected_len].copy_from_slice(&selected_edit.bytes);
        let encoded_displacement = i32::from_le_bytes(
            overlay[puzzle.prefixes + 1..5 + puzzle.prefixes]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            i128::from(selected_next) + i128::from(encoded_displacement),
            i128::from(selected_target)
        );
        for step in steps {
            assert!(!step.parts().requirements.sigill_router);
            assert!(
                step.parts()
                    .obligations
                    .iter()
                    .all(|obligation| matches!(obligation, EntryObligation::Preserved(_)))
            );
        }
        let mut map = TraceMap {
            boundaries: heads[2..]
                .iter()
                .copied()
                .chain([oracle.return_pc()])
                .map(|pc| (pc, pc))
                .collect(),
            gateways: vec![base, victim],
            ..TraceMap::default()
        };
        for image in bundle.images() {
            map.boundaries
                .extend_from_slice(image.instruction_boundaries());
            map.generated_ranges
                .push(image.address()..image.address() + image.bytes().len() as u64);
        }
        let mut originals = Vec::new();
        for seed in SEEDS {
            for (entry_index, &entry) in heads.iter().enumerate() {
                let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
                assert_eq!(
                    trace.visits(),
                    heads[entry_index..]
                        .iter()
                        .copied()
                        .chain([oracle.return_pc()])
                        .collect::<Vec<_>>()
                );
                originals.push((entry, trace));
            }
        }
        let writable = oracle.code.writable();
        // SAFETY: this exact private source alias remains valid throughout the
        // complete bundle lifetime; all trace children are reaped before writes.
        let aliases = [unsafe { WritableAlias::new(source, writable) }.unwrap()];
        let (mut installed, receipt) = {
            // SAFETY: exclusive ownership excludes all executors, aliases and
            // saved continuations. Every original child has been reaped.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![source]) };
            permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: complete original source and both stores are held. Final
            // RX permissions precede sync-core and the successful receipt.
            let result = unsafe {
                bundle.publish_with(&aliases, &mut lease, || {
                    permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .expect("required successor-eviction bundle publication failed");
            assert!(!lease.is_poisoned());
            result
        };
        assert_eq!(receipt.plan().steps(), steps);
        let edits = vec![
            (victim, victim_edit.bytes.clone()),
            (base, selected_edit.bytes.clone()),
        ];
        oracle.assert_publication(&edits);
        let log = HookEventLog::new();
        let enabled = [HookEvent {
            probe_id: PROBE_ID,
            logical_pc: base,
        }];
        for (entry, trace) in &originals {
            oracle.assert_trace(
                trace,
                *entry,
                &map,
                &[],
                Some(HookExpectation {
                    log: &log,
                    enabled: &enabled,
                }),
            );
            installed_comparisons += 1;
            victim_entries += usize::from(*entry == victim);
        }
        assert_eq!(installed.routed_entries(), 0);
        {
            let mut ranges = vec![source];
            ranges.extend(steps.iter().flat_map(|step| {
                step.parts()
                    .allocations
                    .iter()
                    .map(|allocation| allocation.range)
            }));
            // SAFETY: all installed children have been reaped; both generated
            // images, source and saved continuations are fully drained.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
            permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: the complete lifetime drain and exact source alias remain
            // held while original bytes and final permissions are restored.
            unsafe {
                installed.retire_with(&mut lease, || {
                    permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .expect("required successor-eviction bundle retirement failed");
            assert!(!lease.is_poisoned());
        }
        assert!(installed.is_retired());
        oracle.assert_publication(&[]);
        let original_map = TraceMap {
            boundaries: heads
                .iter()
                .copied()
                .chain([oracle.return_pc()])
                .map(|pc| (pc, pc))
                .collect(),
            ..TraceMap::default()
        };
        for (entry, trace) in &originals {
            oracle.assert_trace(
                trace,
                *entry,
                &original_map,
                &[],
                Some(HookExpectation {
                    log: &log,
                    enabled: &[],
                }),
            );
            retired_comparisons += 1;
        }
        retained.push(oracle);
    }
    assert_eq!(installed_comparisons, 16);
    assert_eq!(retired_comparisons, 16);
    assert_eq!(
        victim_entries, 4,
        "each callback-free victim entry must execute with both seeds"
    );
    eprintln!(
        "native T2 oracle: B2 and T1 after forced successor eviction; eight original heads; 16 installed and 16 retired full-state/event comparisons; four callback-free victim entries; zero mismatches"
    );
}

#[test]
fn native_successor_eviction_preserves_seven_byte_victim_fault() {
    isolation::run_parent("native_successor_eviction_preserves_seven_byte_victim_fault");
}

pub fn run_native_successor_eviction_preserves_seven_byte_victim_fault() {
    // Independently checked with GNU objdump: MOV EAX,0 at0 (5 bytes),
    // MOV EAX,EAX at5 (2), MOV RCX,[RAX+disp32=0] at7 (7), RET at14.
    // The victim is REX.W + 8B + ModRM88 (mod10, regRCX, baseRAX) + disp32:
    // 1+1+1+4=7 bytes. A five-byte E9 leaves exactly TWO displacement bytes.
    let code = [
        0xb8, 0, 0, 0, 0, 0x89, 0xc0, 0x48, 0x8b, 0x88, 0, 0, 0, 0, 0xc3,
    ];
    assert_eq!(&code[7..10], &[0x48, 0x8b, 0x88]);
    assert_eq!(i32::from_le_bytes(code[10..14].try_into().unwrap()), 0);
    assert_eq!(&code[12..14], &[0, 0]);
    let mut oracle = NativeOracle::new(&code);
    let base = oracle.code.address();
    let selected = base + 5;
    let victim = base + 7;
    let source = AddressRange::new(base, code.len()).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0xdf; 32]),
        mapping: base,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared("T2 null-load fault; original entry0".into()),
        completeness: EntryCompleteness::Complete,
        entries: vec![LegalEntry {
            address: base,
            requires_endbr: false,
        }],
        resumes: ResumeObligation::NoneExist,
    };
    // Distinct windows from both normal cases prevent retained generated
    // mappings from colliding if a source page address is later reused.
    let victim_displacement = 0x0032_3476_i32;
    let victim_target = victim + 5 + victim_displacement as u64;
    let selected_frozen = 0x3476_e900_u32; // overlay E9 76 34 fixes high bytes
    let selected_low = selected + 5 + u64::from(selected_frozen);
    let selected_target = selected_low + 128;
    let selected_pages = AddressRange::new(selected_target & !4095, 8192).unwrap();
    let original_low =
        u64::try_from(i128::from(selected + 5) + i128::from(0x888b_4800_u32 as i32)).unwrap();
    assert!(!selected_pages.overlaps(AddressRange::new(original_low, 256).unwrap()));
    let mut selected_allocation = AllocationPolicy::near(selected).unwrap();
    selected_allocation.ranges = vec![selected_pages];
    selected_allocation.preferred_address = Some(selected_target);
    let mut victim_allocation = AllocationPolicy::near(victim).unwrap();
    victim_allocation.ranges = vec![AddressRange::new(victim_target & !4095, 8192).unwrap()];
    victim_allocation.preferred_address = Some(victim_target);
    let request = InstallRequest {
        identity,
        code: &code,
        base_address: base,
        function: source,
        block: AddressRange::new(selected, 2).unwrap(),
        logical_pc: selected,
        entries: &entries,
        hook: fault_observe,
        semantics: HookSemantics::Observe,
        allocation: &selected_allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::GeneralizedPunOnly,
            max_upstream_bytes: 0,
            max_sites: 1,
            ..SearchPolicy::default()
        },
    };
    assert_eq!(
        plan_install(&request).unwrap_err(),
        Refusal::AllocationUnavailable
    );
    let planned = plan_successor(&request, &victim_allocation, BundleBudget::default())
        .expect("required seven-byte faulting victim eviction refused");
    assert_eq!(planned.kind(), EvictionKind::Successor { victim });
    let bundle = planned.bundle();
    let steps = bundle.plan().steps();
    assert_eq!(steps.len(), 2);
    assert_eq!(
        steps[0].parts().displaced,
        AddressRange::new(victim, 7).unwrap()
    );
    assert_eq!(steps[0].parts().writes.len(), 1);
    let victim_edit = &steps[0].parts().writes[0];
    let mut expected_redirect = vec![0xe9];
    expected_redirect.extend_from_slice(&victim_displacement.to_le_bytes());
    assert_eq!(victim_edit.address, victim);
    assert_eq!(victim_edit.bytes, expected_redirect);
    assert_eq!(bundle.images()[0].address(), victim_target);
    assert_eq!(bundle.images()[0].instruction_boundaries().len(), 1);
    assert_eq!(bundle.images()[0].instruction_boundaries()[0].0, victim);
    let selected_parts = steps[1].parts();
    let PlanKind::GeneralizedPun(pun) = &selected_parts.kind else {
        panic!("fault fixture requires B2 after victim eviction");
    };
    assert_eq!(pun.instruction_len, 2);
    assert_eq!(
        pun.target_window,
        AddressRange::new(selected_low, 256).unwrap()
    );
    assert_eq!(selected_parts.writes.len(), 1);
    assert_eq!(selected_parts.writes[0].address, selected);
    assert_eq!(selected_parts.writes[0].bytes.len(), 2);
    assert_eq!(bundle.images()[1].address(), selected_target);
    let edits: Vec<_> = steps
        .iter()
        .flat_map(|step| &step.parts().writes)
        .map(|edit| (edit.address, edit.bytes.clone()))
        .collect();
    let mut expected = code.to_vec();
    for (address, bytes) in &edits {
        let offset = (address - base) as usize;
        expected[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    assert_eq!(
        &expected[..5],
        &code[..5],
        "zeroing prefix must remain original"
    );
    assert_eq!(
        &expected[12..15],
        &code[12..15],
        "both victim tail bytes and RET must remain original"
    );
    let boundaries: Vec<_> = bundle
        .images()
        .iter()
        .flat_map(|image| image.instruction_boundaries().iter().copied())
        .collect();
    let originals: Vec<_> = SEEDS
        .into_iter()
        .map(|seed| {
            // Linux SEGV_MAPERR=1. The original MOV EAX,0 fixes RAX before the
            // victim load; SIGSEGV and address0 are native fixture obligations.
            oracle.original_fault(&[base, selected, victim], seed, (libc::SIGSEGV, 1, 0))
        })
        .collect();
    let writable = oracle.code.writable();
    // SAFETY: this fixture exclusively owns the exact alias through retirement.
    let aliases = [unsafe { WritableAlias::new(source, writable) }.unwrap()];
    let mut installed = {
        // SAFETY: all original faulting children were killed/reaped at their
        // ptrace fault stops; exclusive ownership drains every source reference.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![source]) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: source, consumed suffix and both writes remain held; final
        // source RX permissions precede synchronization and the receipt.
        let (installed, receipt) = unsafe {
            bundle.publish_with(&aliases, &mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required faulting-victim publication failed");
        assert_eq!(receipt.plan().steps(), steps);
        assert!(!lease.is_poisoned());
        installed
    };
    oracle.assert_publication(&edits);
    for original in &originals {
        oracle.assert_patched(original, base, &boundaries, &[]);
    }
    assert_eq!(installed.routed_entries(), 0);
    {
        let mut ranges = vec![source];
        ranges.extend(steps.iter().flat_map(|step| {
            step.parts()
                .allocations
                .iter()
                .map(|allocation| allocation.range)
        }));
        // SAFETY: patched children have also been killed/reaped at fault stops;
        // the lease drains source and both retained generated images.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: full source/generated drain remains held through restoration.
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required faulting-victim retirement failed");
        assert!(!lease.is_poisoned());
    }
    assert!(installed.is_retired());
    oracle.assert_publication(&[]);
    for original in &originals {
        oracle.assert_patched(original, base, &[], &[]);
    }
    assert_eq!(originals.len(), 2);
    eprintln!(
        "native T2 victim fault: seven-byte MOV with two unchanged tail bytes; two installed and two retired SIGSEGV/SEGV_MAPERR/address0 comparisons at the original victim PC; zero state mismatches"
    );
}

struct AdditionalPuzzle {
    name: &'static str,
    code: Vec<u8>,
    function_len: usize,
    heads: Vec<usize>,
    victim_len: usize,
    victim_displacement: i32,
    selected_frozen: u32,
    original_frozen: u32,
    branch_back: bool,
    identity_byte: u8,
}

#[test]
fn native_successor_eviction_preserves_bounded_victim_backedge() {
    isolation::run_parent("native_successor_eviction_preserves_bounded_victim_backedge");
}

pub fn run_native_successor_eviction_preserves_bounded_victim_backedge() {
    // SHR ECX,1; JNZ selected; RET. The six-byte victim's rel32 is -8.
    // ECX reaches zero within32 selected visits from every initial value.
    // SHR by1 leaves AF architecturally undefined: this fixture deliberately
    // retains the stricter existing full native-flags comparison, including AF.
    // It does not claim that every flag written by SHR is ISA-defined.
    run_additional_puzzle(AdditionalPuzzle {
        name: "T2-B2-SHR-JNZ-backedge",
        code: vec![0xd1, 0xe9, 0x0f, 0x85, 0xf8, 0xff, 0xff, 0xff, 0xc3],
        function_len: 9,
        heads: vec![0, 2, 8],
        victim_len: 6,
        victim_displacement: 0x0044_3486,
        selected_frozen: 0x3486_e900,
        original_frozen: 0xf885_0f00,
        branch_back: true,
        identity_byte: 0xe1,
    });
}

#[test]
fn native_successor_eviction_preserves_victim_rip_relative_data() {
    isolation::run_parent("native_successor_eviction_preserves_victim_rip_relative_data");
}

pub fn run_native_successor_eviction_preserves_victim_rip_relative_data() {
    // MOV EAX,EAX; MOV RCX,[RIP+55]; MOV [RDI],RCX; RET.
    // The load's original nextPC is9 and its controlled data target is64.
    // Only bytes0..13 are scanner input/function code. The constant at64 is
    // outside that snapshot/function but inside the oracle's exact code-page
    // comparison; none of its bytes is declared as an instruction head.
    let mut code = vec![0x90; 72];
    code[..13].copy_from_slice(&[
        0x89, 0xc0, 0x48, 0x8b, 0x0d, 55, 0, 0, 0, 0x48, 0x89, 0x0f, 0xc3,
    ]);
    let input = 0x1122_3344_5566_7788_u64;
    code[64..72].copy_from_slice(&input.to_le_bytes());
    assert_eq!(
        9_i64 + i64::from(i32::from_le_bytes(code[5..9].try_into().unwrap())),
        64
    );
    assert_eq!(u64::from_le_bytes(code[64..72].try_into().unwrap()), input);
    run_additional_puzzle(AdditionalPuzzle {
        name: "T2-B2-MOV-RIP-load-store",
        code,
        function_len: 13,
        heads: vec![0, 2, 9, 12],
        victim_len: 7,
        victim_displacement: 0x0056_348a,
        selected_frozen: 0x348a_e900,
        original_frozen: 0x0d8b_4800,
        branch_back: false,
        identity_byte: 0xe2,
    });
}

fn run_additional_puzzle(puzzle: AdditionalPuzzle) {
    let mut oracle = NativeOracle::new(&puzzle.code);
    let base = oracle.code.address();
    let victim = base + 2;
    let source_code = &puzzle.code[..puzzle.function_len];
    let source = AddressRange::new(base, source_code.len()).unwrap();
    let heads: Vec<_> = puzzle
        .heads
        .iter()
        .map(|offset| base + *offset as u64)
        .collect();
    let identity = CodeIdentity {
        source: SourceIdentity([puzzle.identity_byte; 32]),
        mapping: base,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared(puzzle.name.into()),
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
    assert_eq!(puzzle.heads[1], 2);
    assert_eq!(puzzle.heads[2], 2 + puzzle.victim_len);
    assert_eq!(source_code[puzzle.function_len - 1], 0xc3);
    if puzzle.branch_back {
        assert_eq!(&source_code[2..4], &[0x0f, 0x85]);
        assert_eq!(
            8_i64 + i64::from(i32::from_le_bytes(source_code[4..8].try_into().unwrap())),
            0,
            "the original victim must branch back to the selected original PC"
        );
    }
    assert_eq!(
        &puzzle.original_frozen.to_le_bytes()[1..],
        &source_code[2..5]
    );
    let victim_target = victim + 5 + u64::try_from(puzzle.victim_displacement).unwrap();
    let selected_low = base + 5 + u64::from(puzzle.selected_frozen);
    let selected_target = selected_low + 128;
    let selected_window = AddressRange::new(selected_low, 256).unwrap();
    let selected_pages = AddressRange::new(selected_target & !4095, 8192).unwrap();
    let original_low =
        u64::try_from(i128::from(base + 5) + i128::from(puzzle.original_frozen as i32)).unwrap();
    assert!(!selected_pages.overlaps(AddressRange::new(original_low, 256).unwrap()));
    let mut selected_allocation = AllocationPolicy::near(base).unwrap();
    selected_allocation.ranges = vec![selected_pages];
    selected_allocation.preferred_address = Some(selected_target);
    let mut victim_allocation = AllocationPolicy::near(victim).unwrap();
    victim_allocation.ranges = vec![AddressRange::new(victim_target & !4095, 8192).unwrap()];
    victim_allocation.preferred_address = Some(victim_target);
    let request = InstallRequest {
        identity,
        code: source_code,
        base_address: base,
        function: source,
        block: AddressRange::new(base, 2).unwrap(),
        logical_pc: base,
        entries: &entries,
        hook: observe,
        semantics: HookSemantics::Observe,
        allocation: &selected_allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::GeneralizedPunOnly,
            max_upstream_bytes: 0,
            max_sites: 1,
            ..SearchPolicy::default()
        },
    };
    assert_eq!(
        plan_install(&request).unwrap_err(),
        Refusal::AllocationUnavailable
    );
    let planned = plan_successor(&request, &victim_allocation, BundleBudget::default())
        .unwrap_or_else(|error| panic!("required {} refused: {error:?}", puzzle.name));
    assert_eq!(planned.kind(), EvictionKind::Successor { victim });
    let bundle = planned.bundle();
    let steps = bundle.plan().steps();
    assert_eq!(steps.len(), 2);
    assert_eq!(bundle.images().len(), 2);
    assert!(matches!(steps[0].parts().kind, PlanKind::Relocation));
    assert_eq!(steps[0].parts().logical_pc, victim);
    assert_eq!(steps[0].parts().physical_pc, victim);
    assert_eq!(
        steps[0].parts().displaced,
        AddressRange::new(victim, puzzle.victim_len).unwrap()
    );
    assert_eq!(steps[0].parts().writes.len(), 1);
    let victim_edit = &steps[0].parts().writes[0];
    let mut expected_redirect = vec![0xe9];
    expected_redirect.extend_from_slice(&puzzle.victim_displacement.to_le_bytes());
    assert_eq!(victim_edit.address, victim);
    assert_eq!(victim_edit.bytes, expected_redirect);
    assert_eq!(bundle.images()[0].address(), victim_target);
    assert_eq!(bundle.images()[0].instruction_boundaries().len(), 1);
    assert_eq!(bundle.images()[0].instruction_boundaries()[0].0, victim);
    let selected = steps[1].parts();
    let PlanKind::GeneralizedPun(pun) = &selected.kind else {
        panic!(
            "{} requires generalized pun after successor eviction",
            puzzle.name
        );
    };
    assert_eq!(selected.logical_pc, base);
    assert_eq!(selected.physical_pc, base);
    assert_eq!(pun.instruction_len, 2);
    assert_eq!(pun.consumed, AddressRange::new(base, 5).unwrap());
    assert_eq!(pun.target_window, selected_window);
    assert_eq!(selected.writes.len(), 1);
    assert_eq!(selected.writes[0].address, base);
    assert_eq!(selected.writes[0].bytes.len(), 2);
    assert_eq!(selected.writes[0].bytes[0], 0xe9);
    assert_eq!(pun.store, selected.writes[0]);
    assert_eq!(bundle.images()[1].address(), selected_target);
    assert_eq!(bundle.images()[1].instruction_boundaries().len(), 1);
    assert_eq!(bundle.images()[1].instruction_boundaries()[0].0, base);
    let edits: Vec<_> = steps
        .iter()
        .flat_map(|step| &step.parts().writes)
        .map(|edit| (edit.address, edit.bytes.clone()))
        .collect();
    let mut overlay = source_code.to_vec();
    for (address, bytes) in &edits {
        let offset = usize::try_from(address - base).unwrap();
        overlay[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    assert_eq!(&puzzle.selected_frozen.to_le_bytes()[1..], &overlay[2..5]);
    assert_eq!(
        i128::from(base + 5) + i128::from(i32::from_le_bytes(overlay[1..5].try_into().unwrap())),
        i128::from(selected_target)
    );
    assert_eq!(
        &overlay[7..],
        &source_code[7..],
        "every unreachable victim-tail byte and following original instruction must survive"
    );
    for step in steps {
        assert!(!step.parts().requirements.sigill_router);
        assert!(
            step.parts()
                .obligations
                .iter()
                .all(|obligation| matches!(obligation, EntryObligation::Preserved(_)))
        );
    }
    let mut map = TraceMap {
        boundaries: heads[2..]
            .iter()
            .copied()
            .chain([oracle.return_pc()])
            .map(|pc| (pc, pc))
            .collect(),
        gateways: vec![base, victim],
        ..TraceMap::default()
    };
    for image in bundle.images() {
        map.boundaries
            .extend_from_slice(image.instruction_boundaries());
        map.generated_ranges
            .push(image.address()..image.address() + image.bytes().len() as u64);
    }
    let mut originals = Vec::new();
    let mut expected_hook_visits = 0;
    for (seed_index, seed) in SEEDS.into_iter().enumerate() {
        for (entry_index, &entry) in heads.iter().enumerate() {
            let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
            let expected: Vec<_> = if puzzle.branch_back && entry_index == 0 {
                // Handwritten counts for the fixed seeded ECX values:
                // 0xfa97ac78 takes32 shifts; 0x6f659161 takes31 shifts.
                let turns = [32, 31][seed_index];
                (0..turns)
                    .flat_map(|_| [base, victim])
                    .chain([heads[2], oracle.return_pc()])
                    .collect()
            } else {
                heads[entry_index..]
                    .iter()
                    .copied()
                    .chain([oracle.return_pc()])
                    .collect()
            };
            assert_eq!(
                trace.visits(),
                expected,
                "native original visits must match independently bounded fixture semantics"
            );
            let hooks = expected.iter().filter(|&&pc| pc == base).count();
            assert!(
                hooks <= 32,
                "fixture exceeded its predeclared selected-visit bound"
            );
            if entry == victim {
                assert_eq!(
                    hooks, 0,
                    "direct victim entry must not invoke the selected hook"
                );
            }
            expected_hook_visits += hooks;
            originals.push((entry, trace));
        }
    }
    assert_eq!(
        expected_hook_visits,
        if puzzle.branch_back { 63 } else { 2 }
    );
    let writable = oracle.code.writable();
    // SAFETY: this fixture owns the complete source alias through retirement.
    let aliases = [unsafe { WritableAlias::new(source, writable) }.unwrap()];
    let mut installed = {
        // SAFETY: every original child was reaped; this owner excludes all
        // source execution and saved continuations throughout publication.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![source]) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: final RX precedes synchronization and the successful receipt.
        let (installed, receipt) = unsafe {
            bundle.publish_with(&aliases, &mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap_or_else(|error| panic!("required {} publication failed: {error:?}", puzzle.name));
        assert_eq!(receipt.plan().steps(), steps);
        assert!(!lease.is_poisoned());
        installed
    };
    oracle.assert_publication(&edits);
    let log = HookEventLog::new();
    let enabled = [HookEvent {
        probe_id: PROBE_ID,
        logical_pc: base,
    }];
    for (entry, trace) in &originals {
        oracle.assert_trace(
            trace,
            *entry,
            &map,
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &enabled,
            }),
        );
    }
    assert_eq!(installed.routed_entries(), 0);
    {
        let mut ranges = vec![source];
        ranges.extend(steps.iter().flat_map(|step| {
            step.parts()
                .allocations
                .iter()
                .map(|allocation| allocation.range)
        }));
        // SAFETY: all installed children are reaped and both generated images
        // join the source/saved-continuation lifetime drain.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: the complete lease stays held through original-byte/RX restore.
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required additive successor-eviction retirement failed");
        assert!(!lease.is_poisoned());
    }
    assert!(installed.is_retired());
    oracle.assert_publication(&[]);
    let original_map = TraceMap {
        boundaries: heads
            .iter()
            .copied()
            .chain([oracle.return_pc()])
            .map(|pc| (pc, pc))
            .collect(),
        ..TraceMap::default()
    };
    for (entry, trace) in &originals {
        oracle.assert_trace(
            trace,
            *entry,
            &original_map,
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &[],
            }),
        );
    }
    assert_eq!(originals.len(), puzzle.heads.len() * SEEDS.len());
    eprintln!(
        "native {}: {} original heads; {} installed and {} retired full-state/event comparisons; {} exact selected-hook visits installed; two direct victim entries without selected hook; zero mismatches",
        puzzle.name,
        puzzle.heads.len(),
        originals.len(),
        originals.len(),
        expected_hook_visits
    );
}

#[path = "support/successor_eviction_isolation.rs"]
mod isolation;

/// Standalone fixture-binary entry; never starts Rust's test harness.
pub fn isolated_main() {
    isolation::main_thread_driver();
}

#[test]
fn occupied_successor_page_refuses_without_mutation() {
    isolation::run_parent("occupied_successor_page_refuses_without_mutation");
}
