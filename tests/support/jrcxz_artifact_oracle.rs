//! Finite artifact-only JRCXZ state evidence, through the real linked T3 plan.
//! Uses unchanged full-state capture/comparison and bounded process ownership.

use super::isolated_native_test;

use super::oracle::{
    HookEvent, HookEventLog, HookExpectation, Mapping, NativeOracle, SourceRelay, TraceMap,
};
use super::{SEEDS, exact_e9};
use liteinst::composition::Composition;
use liteinst::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, ExpectedBytes, LegalEntry,
    LegalEntrySet, ResumeObligation, SourceIdentity,
};
use liteinst::emission::{
    ArtifactEmission, ArtifactMetrics, ArtifactRequest, ArtifactRequirement, PlanningSite,
    SymbolicHook, TargetProfile,
};
use liteinst::engine::{self, EnginePolicy, SelectedMetrics, Tactic};
use liteinst::neighbor::NeighborSearch;
use liteinst::planner::HookSemantics;
use liteinst::quiescent::{AllocationPolicy, SearchPolicy};
use liteinst::scanner::InstructionScanner;
use liteinst::search::SearchDomain;
use liteinst::trampoline::{HookContext, SavedExtendedStateLayout};

const PAGE: usize = 4096;
const IMAGE_SLOT: usize = 2 * PAGE;
const GENERATED_BYTES: usize = 2 * IMAGE_SLOT + PAGE;
const SELECTED: usize = 10;
const VICTIM: usize = 122;
const PROBE: u64 = 0xe304;
const RCX: [u64; 4] = [0, 1, 1_u64 << 32, u64::MAX];

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the existing ptrace oracle has activated its bounded private log;
    // the admitted emitted callback frame supplies this live HookContext.
    unsafe {
        super::oracle::record_hook_event(PROBE, (*context).instruction_pointer);
        // Force both GPR/flags and xstate restoration, notably RCX==0 and the
        // nonzero high-half-only input. Do not edit the saved context or data.
        core::arch::asm!(
            "xor eax, eax", "mov rcx, -1", "pxor xmm0, xmm0", "fninit",
            out("rax") _, out("rcx") _, out("xmm0") _, options(nostack),
        );
    }
}

fn range(address: u64, bytes: usize) -> AddressRange {
    AddressRange::new(address, bytes).unwrap()
}

fn entries(identity: CodeIdentity, base: u64, bytes: &[u8], offsets: &[u64]) -> LegalEntrySet {
    let heads: Vec<_> = offsets.iter().map(|offset| base + offset).collect();
    // Decoder authenticates the independent literal inventory; it does not
    // supply RCX values, branch answers, visits, or expected machine state.
    let scan = InstructionScanner::default().scan(bytes, base).unwrap();
    assert_eq!(
        scan.instructions()
            .iter()
            .map(|i| i.address())
            .collect::<Vec<_>>(),
        heads
    );
    LegalEntrySet {
        identity,
        scope: range(base, bytes.len()),
        provenance: EntryProvenance::Declared("private finite JRCXZ native fixture".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: heads
            .into_iter()
            .map(|address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    }
}

fn allocation(address: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(address, IMAGE_SLOT)],
        preferred_address: Some(address),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: IMAGE_SLOT,
    }
}

fn copy_owned(mapping: &Mapping, len: usize, address: u64, bytes: &[u8]) {
    assert!(range(mapping.address(), len).covers(range(address, bytes.len())));
    let offset = usize::try_from(address - mapping.address()).unwrap();
    // SAFETY: this entire private RW mapping is retained, checked and quiescent.
    // Every oracle child was reaped before any mutation or permission change.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.writable().add(offset), bytes.len())
    };
}

fn assert_owned(mapping: &Mapping, bytes: &[u8]) {
    // SAFETY: the owner retains this original length through every child wait.
    assert_eq!(
        unsafe { core::slice::from_raw_parts(mapping.writable(), bytes.len()) },
        bytes
    );
}

#[test]
fn native_jrcxz_artifact_preserves_integer_flags_and_stack() {
    isolated_native_test::run(
        "jrcxz_artifact_native::native_jrcxz_artifact_preserves_integer_flags_and_stack",
        "LITEINST2_JRCXZ_ARTIFACT_ORACLE_CHILD",
        run,
    );
}

fn run() {
    let mut census = [0_usize; 4]; // original, linked, restored, linked hooks
    let mut branches = [0_usize; 2]; // original taken, fallthrough
    for rcx in RCX {
        let mut selected_bytes = vec![0x48, 0xb9]; // MOV RCX,imm64 leaves flags intact.
        selected_bytes.extend_from_slice(&rcx.to_le_bytes());
        selected_bytes.extend_from_slice(&[0xe3, 4, 0x90, 0x90, 0x90, 0x90, 0xc3]);
        assert_eq!(selected_bytes.len(), 17);
        let mut victim_bytes = vec![0x48, 0xb8]; // independent native MOVABS relay witness
        victim_bytes.extend_from_slice(&0x1739_5b7d_9ebc_daf0_u64.to_le_bytes());
        victim_bytes.push(0xc3);
        let mut code = vec![0xcc; VICTIM + victim_bytes.len()];
        code[..selected_bytes.len()].copy_from_slice(&selected_bytes);
        code[VICTIM..].copy_from_slice(&victim_bytes);
        let (oracle, mut adjacent) =
            NativeOracle::with_seeded_memory_and_flags_adjacent(&code, 0xe3_04, &[GENERATED_BYTES]);
        let generated = adjacent.pop().unwrap();
        assert!(adjacent.is_empty());
        let base = oracle.code.address();
        assert_eq!(generated.address(), base + PAGE as u64);
        let selected = base + SELECTED as u64;
        let victim = base + VICTIM as u64;
        let relay = victim + 5;
        let terminal = oracle.return_pc();
        let heads = [
            base,
            selected,
            base + 12,
            base + 13,
            base + 14,
            base + 15,
            base + 16,
            victim,
            victim + 10,
        ];
        let identity = CodeIdentity {
            source: SourceIdentity([0xe3; 32]),
            mapping: base,
            generation: 1,
        };
        let selected_entries = entries(
            identity,
            base,
            &selected_bytes,
            &[0, 10, 12, 13, 14, 15, 16],
        );
        let victim_entries = entries(identity, victim, &victim_bytes, &[0, 10]);
        let predecessor = Composition::new(
            identity,
            vec![
                ExpectedBytes {
                    address: base,
                    bytes: selected_bytes.clone(),
                },
                ExpectedBytes {
                    address: victim,
                    bytes: victim_bytes.clone(),
                },
            ],
        )
        .unwrap();
        let selected_target = generated.address();
        let victim_target = selected_target + IMAGE_SLOT as u64;
        let hook_target = victim_target + IMAGE_SLOT as u64;
        let selected_allocation = allocation(selected_target);
        let victim_allocation = allocation(victim_target);
        let state = SavedExtendedStateLayout::detect().unwrap();
        let emission = ArtifactEmission::new(
            TargetProfile::linux_x86_64_legacy_evex(state, 1).unwrap(),
            SymbolicHook {
                identity: PROBE,
                address: Some(hook_target),
            },
            vec![range(base, PAGE), range(hook_target, PAGE)],
        );
        let search = SearchPolicy {
            max_upstream_bytes: 0,
            max_sites: 1,
            ..SearchPolicy::default()
        };
        let request = ArtifactRequest {
            site: PlanningSite {
                identity,
                code: &selected_bytes,
                base_address: base,
                function: selected_entries.scope,
                block: range(selected, 2),
                logical_pc: selected,
                entries: &selected_entries,
                semantics: HookSemantics::Observe,
                allocation: &selected_allocation,
                search,
            },
            emission: &emission,
        };
        let foreign = PlanningSite {
            identity,
            code: &victim_bytes,
            base_address: victim,
            function: victim_entries.scope,
            block: victim_entries.scope,
            logical_pc: victim,
            entries: &victim_entries,
            semantics: HookSemantics::Observe,
            allocation: &victim_allocation,
            search,
        };
        let plan = engine::plan_with_emission_after_with_foreign(
            &request,
            &predecessor,
            &victim_allocation,
            EnginePolicy {
                forced: Some(Tactic::NeighborEviction),
                neighbor: NeighborSearch {
                    forced_victim: Some(victim),
                    max_victims: 1,
                    max_pairs: 1,
                },
                ..EnginePolicy::default()
            },
            &[foreign],
        )
        .expect("required finite artifact T3 must succeed; no skip/fallback");
        let ArtifactMetrics::Engine(tactic, SelectedMetrics::Neighbor(geometry, metrics), attempts) =
            plan.metrics()
        else {
            panic!("expected artifact T3 engine result");
        };
        assert_eq!(*tactic, Tactic::NeighborEviction);
        assert_eq!(
            (
                geometry.selected,
                geometry.selected_len,
                geometry.victim,
                geometry.victim_len
            ),
            (selected, 2, victim, 10)
        );
        assert_eq!(
            (
                geometry.relay,
                geometry.rel8,
                geometry.selected_target,
                geometry.victim_target
            ),
            (relay, 115, selected_target, victim_target)
        );
        assert_eq!((metrics.victims_examined, metrics.pairs_examined), (1, 1));
        for domain in [SearchDomain::Victims, SearchDomain::JointPairs] {
            assert_eq!(
                attempts
                    .iter()
                    .flat_map(|a| &a.search.runs)
                    .filter(|r| r.domain == domain)
                    .map(|r| r.examined)
                    .sum::<usize>(),
                1
            );
        }
        assert!(!plan.qualification_complete());
        let mut victim_edit = exact_e9(victim, victim_target).to_vec();
        victim_edit.extend_from_slice(&exact_e9(relay, selected_target));
        let edits = [(selected, vec![0xeb, 115]), (victim, victim_edit)];
        assert_eq!(plan.source_steps().len(), 2);
        let mut appended = predecessor.clone();
        for step in plan.source_steps() {
            let p = step.parts();
            assert_eq!(p.identity, identity);
            step.check_entry_obligations().unwrap();
            let (owner, edit) = if p.physical_pc == selected {
                (&selected_entries, &edits[0])
            } else {
                assert_eq!(p.physical_pc, victim);
                (&victim_entries, &edits[1])
            };
            assert_eq!(p.entries, *owner);
            assert_eq!(p.dependencies, [owner.scope]);
            assert_eq!(p.writes.len(), 1);
            assert_eq!((p.writes[0].address, &p.writes[0].bytes), (edit.0, &edit.1));
            assert!(p.requirements.quiescent && p.requirements.sync_core);
            assert!(!p.requirements.sigill_router);
            appended.append(step).unwrap();
        }
        assert_eq!(predecessor.originals(), predecessor.final_bytes());
        let mut map = TraceMap {
            boundaries: heads
                .into_iter()
                .filter(|pc| *pc != selected && *pc != victim)
                .chain([terminal])
                .map(|pc| (pc, pc))
                .collect(),
            gateways: vec![selected, victim],
            ..TraceMap::default()
        };
        let images: Vec<_> = plan.images().collect();
        assert_eq!(images.len(), 2);
        let mut expected_generated = vec![0xcc; GENERATED_BYTES];
        for image in &images {
            let logical = if image.address() == selected_target {
                selected
            } else {
                assert_eq!(image.address(), victim_target);
                victim
            };
            assert!(
                range(image.address(), IMAGE_SLOT)
                    .covers(range(image.address(), image.bytes().len()))
            );
            assert_eq!(image.entry_routes(), [(logical, image.address())]);
            assert_eq!(image.instruction_boundaries().len(), 1);
            assert_eq!(image.instruction_boundaries()[0].0, logical);
            assert!(!image.metadata().qualification_complete());
            assert_eq!(
                image
                    .metadata()
                    .requirements()
                    .contains(&ArtifactRequirement::HookAbiAndReadiness(PROBE)),
                logical == selected
            );
            let hooks: Vec<_> = image
                .metadata()
                .fields()
                .iter()
                .filter(|f| f.role == "HookCall")
                .collect();
            assert_eq!(hooks.len(), usize::from(logical == selected));
            if logical == selected {
                assert_eq!(hooks[0].target, i128::from(hook_target));
                let body = image.instruction_boundaries()[0].1;
                let at = usize::try_from(body - image.address()).unwrap();
                assert_eq!(&image.bytes()[at..at + 5], &[0xe3, 2, 0xeb, 5, 0xe9]);
                let fields: Vec<_> = image
                    .metadata()
                    .fields()
                    .iter()
                    .filter(|f| f.role.starts_with("OriginalBranch"))
                    .collect();
                assert_eq!(fields.len(), 3);
                assert_eq!(
                    fields
                        .iter()
                        .map(|f| (f.offset, f.width, f.target))
                        .collect::<Vec<_>>(),
                    [
                        (at as u64 + 1, 1, i128::from(body + 4)),
                        (at as u64 + 3, 1, i128::from(body + 9)),
                        (at as u64 + 5, 4, i128::from(selected + 6)),
                    ]
                );
                for offset in 0..9 {
                    assert_eq!(
                        image
                            .program_counter_mappings()
                            .iter()
                            .find_map(|p| p.translate(body + offset)),
                        Some(selected)
                    );
                }
            }
            map.boundaries
                .extend_from_slice(image.instruction_boundaries());
            map.generated_ranges
                .push(image.address()..image.address() + image.bytes().len() as u64);
            let at = usize::try_from(image.address() - generated.address()).unwrap();
            expected_generated[at..at + image.bytes().len()].copy_from_slice(image.bytes());
        }
        // This test-owned rel32 destination reaches the actual observing callback.
        // RAX scratch is inside the saved frame; the callback/frame restore it.
        let mut hook_bridge = vec![0x48, 0xb8];
        hook_bridge.extend_from_slice(&(observe as *const () as usize as u64).to_le_bytes());
        hook_bridge.extend_from_slice(&[0xff, 0xe0]);
        expected_generated[2 * IMAGE_SLOT..2 * IMAGE_SLOT + hook_bridge.len()]
            .copy_from_slice(&hook_bridge);
        copy_owned(
            &generated,
            GENERATED_BYTES,
            generated.address(),
            &expected_generated,
        );
        generated.protect(libc::PROT_READ | libc::PROT_EXEC);
        assert_owned(&generated, &expected_generated);
        assert_eq!(SavedExtendedStateLayout::detect().unwrap(), state);
        let mut originals = Vec::new();
        for seed in SEEDS {
            let trace = oracle.trace_original(base, &heads, &[terminal], seed);
            let offsets: &[u64] = if rcx == 0 {
                &[0, 10, 16]
            } else {
                &[0, 10, 12, 13, 14, 15, 16]
            };
            assert_eq!(
                trace.visits(),
                offsets
                    .iter()
                    .map(|at| base + at)
                    .chain([terminal])
                    .collect::<Vec<_>>()
            );
            trace.assert_jrcxz_boundary_state(selected, rcx);
            branches[usize::from(rcx != 0)] += 1;
            originals.push((base, trace));
            let witness = oracle.trace_original(victim, &heads, &[terminal], seed);
            assert_eq!(witness.visits(), [victim, victim + 10, terminal]);
            originals.push((victim, witness));
        }
        assert_eq!(originals.len(), 4);
        census[0] += originals.len();
        let witness = &originals[1].1;
        let relays = [SourceRelay {
            logical_pc: selected,
            relay_pc: relay,
            target: selected_target,
            victim_trace: witness,
        }];
        let log = HookEventLog::new();
        let enabled = [HookEvent {
            probe_id: PROBE,
            logical_pc: selected,
        }];
        oracle.assert_publication(&[]);
        oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        for snapshot in appended.final_bytes() {
            copy_owned(&oracle.code, PAGE, snapshot.address, &snapshot.bytes);
        }
        oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        oracle.assert_publication(&edits);
        for (entry, trace) in &originals {
            oracle.assert_trace_with_relays(
                trace,
                *entry,
                &map,
                &relays,
                &[],
                Some(HookExpectation {
                    log: &log,
                    enabled: &enabled,
                }),
            );
            census[1] += 1;
            census[3] += usize::from(*entry == base);
            assert_owned(&generated, &expected_generated);
        }
        // Restore only after all exact oracle children were reaped. Unwinding
        // also drops each Tracee before returning to these mapping owners.
        oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        for snapshot in predecessor.originals() {
            copy_owned(&oracle.code, PAGE, snapshot.address, &snapshot.bytes);
        }
        oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        oracle.assert_publication(&[]);
        let restored = TraceMap {
            boundaries: heads
                .into_iter()
                .chain([terminal])
                .map(|pc| (pc, pc))
                .collect(),
            ..TraceMap::default()
        };
        for (entry, trace) in &originals {
            oracle.assert_trace_with_relays(
                trace,
                *entry,
                &restored,
                &[],
                &[],
                Some(HookExpectation {
                    log: &log,
                    enabled: &[],
                }),
            );
            census[2] += 1;
            assert_owned(&generated, &expected_generated);
        }
        assert_eq!(SavedExtendedStateLayout::detect().unwrap(), state);
        assert!(!plan.qualification_complete());
    }
    assert_eq!(branches, [2, 6]);
    assert_eq!(census, [16, 16, 16, 8]);
    eprintln!(
        "artifact JRCXZ: 4 RCX values x 2 seeds, 16 original/16 linked/16 restored traces, 8 observing callbacks; no qualification claim"
    );
}
