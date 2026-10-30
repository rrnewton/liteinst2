#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Required native state comparisons for all six T1 prefix geometries.
//! Handwritten streams and frozen rel32 words determine placement independently
//! of the decoder and planner. Every original head executes with both seeds.

#[path = "support/quiescent_oracle.rs"]
mod oracle;

#[path = "support/isolated_native_test.rs"]
mod isolated_native_test;

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

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const PROBE_ID: u64 = 0x701;

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the emitter supplies a live frame and assert_trace activates the
    // child's bounded private log. Only caller-saved scratch state is destroyed.
    unsafe {
        oracle::record_hook_event(PROBE_ID, (*context).instruction_pointer);
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
    length: usize,
    prefixes: usize,
    code: &'static [u8],
    heads: [usize; 3],
    frozen: u32,
}

fn window(base: u64, length: usize, prefixes: usize, code: &[u8]) -> AddressRange {
    let free = length - prefixes - 1;
    let mut displacement = [0_u8; 4];
    displacement[free..].copy_from_slice(&code[length..5 + prefixes]);
    let start = u64::try_from(
        i128::from(base) + (5 + prefixes) as i128 + i128::from(i32::from_le_bytes(displacement)),
    )
    .unwrap();
    AddressRange::new(start, 1_usize << (8 * free)).unwrap()
}

#[test]
fn native_state_covers_every_prefixed_pun_and_original_successor() {
    isolated_native_test::run(
        "native_state_covers_every_prefixed_pun_and_original_successor",
        "LITEINST2_PREFIXED_PUN_CHILD",
        native_state_covers_every_prefixed_pun_and_original_successor_body,
    );
}

fn native_state_covers_every_prefixed_pun_and_original_successor_body() {
    // L2 MOV EAX,EAX; LEA RCX,[RDI+8]; RET.
    const L2: &[u8] = &[0x89, 0xc0, 0x48, 0x8d, 0x4f, 0x08, 0xc3];
    // L3 LEA RAX,[RDI]; MOV [RDI],RAX; RET.
    const L3: &[u8] = &[0x48, 0x8d, 0x07, 0x48, 0x89, 0x07, 0xc3];
    // L4 LEA RCX,[RDI+8]; MOV [RDI],RCX; RET.
    const L4: &[u8] = &[0x48, 0x8d, 0x4f, 0x08, 0x48, 0x89, 0x0f, 0xc3];
    let puzzles = [
        Puzzle {
            length: 2,
            prefixes: 1,
            code: L2,
            heads: [0, 2, 6],
            frozen: 0x084f_8d48,
        },
        Puzzle {
            length: 3,
            prefixes: 1,
            code: L3,
            heads: [0, 3, 6],
            frozen: 0x0789_4800,
        },
        Puzzle {
            length: 3,
            prefixes: 2,
            code: L3,
            heads: [0, 3, 6],
            frozen: 0xc307_8948,
        },
        Puzzle {
            length: 4,
            prefixes: 1,
            code: L4,
            heads: [0, 4, 7],
            frozen: 0x8948_0000,
        },
        Puzzle {
            length: 4,
            prefixes: 2,
            code: L4,
            heads: [0, 4, 7],
            frozen: 0x0f89_4800,
        },
        Puzzle {
            length: 4,
            prefixes: 3,
            code: L4,
            heads: [0, 4, 7],
            frozen: 0xc30f_8948,
        },
    ];
    let mut installed_comparisons = 0;
    let mut retired_comparisons = 0;
    let mut negative_displacements = 0;
    let mut retained = Vec::new();
    for (index, puzzle) in puzzles.iter().enumerate() {
        let mut oracle = NativeOracle::new(puzzle.code);
        let base = oracle.code.address();
        let heads = puzzle.heads.map(|offset| base + offset as u64);
        let source = AddressRange::new(base, puzzle.code.len()).unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity([0xc0 + index as u8; 32]),
            mapping: base,
            generation: 1,
        };
        let entries = LegalEntrySet {
            identity,
            scope: source,
            provenance: EntryProvenance::Declared(format!(
                "native T1 L{} P{} all three original heads",
                puzzle.length, puzzle.prefixes
            )),
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
        let free = puzzle.length - puzzle.prefixes - 1;
        let width = 1_usize << (8 * free);
        assert_eq!(
            &puzzle.frozen.to_le_bytes()[free..],
            &puzzle.code[puzzle.length..5 + puzzle.prefixes],
            "handwritten bytes must supply the declared fixed displacement"
        );
        assert!(
            puzzle.frozen.to_le_bytes()[..free]
                .iter()
                .all(|&byte| byte == 0)
        );
        let next = base + (5 + puzzle.prefixes) as u64;
        let low = u64::try_from(i128::from(next) + i128::from(puzzle.frozen as i32)).unwrap();
        let expected_window = AddressRange::new(low, width).unwrap();
        assert_eq!(
            expected_window,
            window(base, puzzle.length, puzzle.prefixes, puzzle.code)
        );
        let target = low + width as u64 / 2;
        let permitted = AddressRange::new(target & !4095, 8192).unwrap();
        for other_prefixes in 0..puzzle.length {
            if other_prefixes != puzzle.prefixes {
                assert!(
                    !permitted.overlaps(window(base, puzzle.length, other_prefixes, puzzle.code)),
                    "allocation must exclude B2 and every other prefix count"
                );
            }
        }
        let mut allocation = AllocationPolicy::near(base).unwrap();
        allocation.ranges = vec![permitted];
        allocation.preferred_address = Some(target);
        let mut request = InstallRequest {
            identity,
            code: puzzle.code,
            base_address: base,
            function: source,
            block: source,
            logical_pc: base,
            entries: &entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
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
        request.search.tactics = TacticPolicy::PrefixPunOnly;
        let prepared = plan_install(&request).unwrap_or_else(|error| {
            panic!(
                "required T1 L{} P{} refused: {error:?}",
                puzzle.length, puzzle.prefixes
            )
        });
        if puzzle.length == 2 {
            // This permitted page fixes displacement byte 1 to 0x7f..=0x9f,
            // none of which is an approved illegal opcode for successor head 2.
            // Ordinary relocation therefore cannot preserve that required entry.
            request.search.tactics = TacticPolicy::RelocationOnly;
            assert_eq!(
                plan_install(&request).unwrap_err(),
                Refusal::AllocationUnavailable
            );
            request.search.tactics = TacticPolicy::PreferGeneralizedPun;
            let default = plan_install(&request).expect("default must admit the T1 fallback");
            assert_eq!(
                default.plan(),
                prepared.plan(),
                "required T1 fallback changed geometry"
            );
        } else if puzzle.length == 3 && puzzle.prefixes == 2 {
            // This separate page permits the original relocation tactic: the
            // byte at successor head 3 is the approved illegal opcode 0x07.
            // Default ordering must retain that feasible tactic ahead of T1.
            request.search.tactics = TacticPolicy::RelocationOnly;
            let relocation =
                plan_install(&request).expect("required relocation alternative refused");
            assert!(matches!(
                relocation.plan().parts().kind,
                PlanKind::Relocation
            ));
            request.search.tactics = TacticPolicy::PreferGeneralizedPun;
            let default = plan_install(&request).expect("default must admit feasible relocation");
            assert_eq!(default.plan(), relocation.plan());
        }
        let parts = prepared.plan().parts();
        let PlanKind::PrefixedPun(pun) = &parts.kind else {
            panic!("required T1 became another tactic: {:?}", parts.kind);
        };
        assert_eq!(pun.instruction_len as usize, puzzle.length);
        assert_eq!(pun.prefix_count as usize, puzzle.prefixes);
        assert_eq!(parts.physical_pc, base);
        assert_eq!(parts.logical_pc, base);
        assert_eq!(
            parts.displaced,
            AddressRange::new(base, puzzle.length).unwrap()
        );
        assert_eq!(
            pun.consumed,
            AddressRange::new(base, 5 + puzzle.prefixes).unwrap()
        );
        assert_eq!(pun.target_window, expected_window);
        assert_eq!(pun.target_window.len(), width as u64);
        assert_eq!(
            prepared.image().address(),
            target,
            "preferred exact target must be used"
        );
        assert_eq!(parts.writes.len(), 1);
        let edit = &parts.writes[0];
        assert_eq!(edit.address, base);
        assert_eq!(edit.bytes.len(), puzzle.length);
        assert_eq!(&edit.bytes[..puzzle.prefixes], vec![0x2e; puzzle.prefixes]);
        assert_eq!(edit.bytes[puzzle.prefixes], 0xe9);
        assert_eq!(pun.store.address, base);
        assert_eq!(pun.store.bytes.len(), puzzle.length.next_power_of_two());
        assert_eq!(&pun.store.bytes[..puzzle.length], edit.bytes);
        assert_eq!(
            &pun.store.bytes[puzzle.length..],
            &puzzle.code[puzzle.length..pun.store.bytes.len()],
            "the wider three-byte store must preserve its successor pad"
        );
        let mut consumed = puzzle.code[..5 + puzzle.prefixes].to_vec();
        consumed[..puzzle.length].copy_from_slice(&edit.bytes);
        assert_eq!(
            &consumed[puzzle.length..],
            &puzzle.code[puzzle.length..5 + puzzle.prefixes]
        );
        let displacement = i32::from_le_bytes(consumed[puzzle.prefixes + 1..].try_into().unwrap());
        assert_eq!(
            i128::from(next) + i128::from(displacement),
            i128::from(target)
        );
        negative_displacements += usize::from(displacement < 0);
        assert!(
            parts
                .obligations
                .iter()
                .all(|entry| matches!(entry, EntryObligation::Preserved(_)))
        );
        assert!(!parts.requirements.sigill_router);
        assert_eq!(prepared.image().instruction_boundaries().len(), 1);
        assert_eq!(prepared.image().instruction_boundaries()[0].0, base);
        let mut boundaries = prepared.image().instruction_boundaries().to_vec();
        boundaries.extend(heads[1..].iter().map(|&pc| (pc, pc)));
        boundaries.push((oracle.return_pc(), oracle.return_pc()));
        let map = TraceMap {
            boundaries,
            gateways: vec![base],
            generated_ranges: std::iter::once(
                target..target + prepared.image().bytes().len() as u64,
            )
            .collect(),
        };
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
        let (mut installed, receipt) = {
            // SAFETY: this exclusive fixture owner has reaped every original
            // child and excludes all executors, aliases and saved continuations.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![source]) };
            permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: the exact source/store padding/fetch bytes are held; RX
            // is established before sync-core and successful receipt issuance.
            let result = unsafe {
                prepared.publish_with(writable, &mut lease, || {
                    permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .expect("required T1 publication failed");
            assert!(!lease.is_poisoned());
            result
        };
        assert_eq!(receipt.plan(), prepared.plan());
        oracle.assert_publication(&[(base, edit.bytes.clone())]);
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
        }
        assert_eq!(installed.routed_entries(), 0);
        {
            let mut ranges = vec![source];
            ranges.extend(parts.allocations.iter().map(|allocation| allocation.range));
            // SAFETY: all installed children have been reaped, draining source,
            // generated code and saved continuations before restoration.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
            permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: the complete source/generated lease and exact alias remain
            // held; finalization changes permissions only and cannot unwind.
            unsafe {
                installed.retire_with(&mut lease, || {
                    permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .expect("required T1 retirement failed");
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
    assert_eq!(installed_comparisons, 36);
    assert_eq!(retired_comparisons, 36);
    assert_eq!(negative_displacements, 3);
    eprintln!(
        "native T1 oracle: six required prefix geometries; 18 original heads; 36 installed and 36 retired comparisons; three negative rel32 cases; no successor changes or state mismatches"
    );
}
