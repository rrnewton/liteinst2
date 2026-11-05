//! Finite artifact-only V/V+1 overlap, authorized by independent native state.
//! Every mapping, authored head, seed and layout is required; no skip or retry.
use super::isolated_native_test;
use super::oracle::{
    HookEvent, HookEventLog, HookExpectation, Mapping, NativeOracle, OverlappingPages,
    OverlappingSourceRelay, TraceMap,
};
use super::{SEEDS, exact_e9};
use liteinst::bundle::BundleBudget;
use liteinst::composition::Composition;
use liteinst::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, ExpectedBytes, LegalEntry,
    LegalEntrySet, ResumeObligation, SourceIdentity,
};
use liteinst::emission::{
    ArtifactEmission, ArtifactFieldEncoding, ArtifactMetrics, ArtifactRequest, ArtifactRequirement,
    PlanningSite, SymbolicHook, TargetProfile,
};
use liteinst::engine::{self, EnginePolicy, SelectedMetrics, Tactic};
use liteinst::neighbor::{NeighborAttemptStage, NeighborSearch};
use liteinst::planner::HookSemantics;
use liteinst::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
use liteinst::scanner::InstructionScanner;
use liteinst::search::{SearchDomain, SearchStop};
use liteinst::trampoline::{HookContext, SavedExtendedStateLayout};

const PAGE: usize = 4096;
const PROBE: u64 = 0x61_0001;

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: an isolated child owns this callback frame and active event page.
    // Deliberate caller-saved clobbers test the unchanged full-state comparator.
    unsafe {
        super::oracle::record_hook_event(PROBE, (*context).instruction_pointer);
        core::arch::asm!("xor eax, eax", "mov rcx, -1", "pxor xmm0, xmm0", "fninit",
            out("rax") _, out("rcx") _, out("xmm0") _, options(nostack));
    }
}

fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}
fn policy(target: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(target & !4095, PAGE)],
        preferred_address: Some(target),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: PAGE,
    }
}
fn copy(mapping: &Mapping, bytes: &[u8]) {
    assert_eq!(bytes.len(), PAGE);
    // SAFETY: the sole retained page is RW and no child is active.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.writable(), PAGE) };
}
fn assert_page(mapping: &Mapping, bytes: &[u8]) {
    assert_eq!(bytes.len(), PAGE);
    // SAFETY: the immutable readable page owner remains alive.
    assert_eq!(
        unsafe { core::slice::from_raw_parts(mapping.writable(), PAGE) },
        bytes
    );
}

struct Puzzle {
    code: Vec<u8>,
    selected: usize,
    selected_len: usize,
    victim: usize,
    victim_len: usize,
    heads: [usize; 4],
}
impl Puzzle {
    fn new(selected_len: usize, victim_len: usize, before: bool) -> Self {
        assert!([2, 3, 4].contains(&selected_len));
        assert!([6, 9, 10, 15].contains(&victim_len));
        let selected = if before { 16 } else { 16 + victim_len + 1 };
        let victim = if before { 16 + selected_len + 1 } else { 16 };
        let mut code = vec![0xcc; 16 + selected_len + victim_len + 2];
        let instruction: &[u8] = match selected_len {
            2 => &[0xff, 0xc0],
            3 => &[0x48, 0xff, 0xc0],
            4 => &[0x48, 0x83, 0xc0, 1],
            _ => unreachable!(),
        };
        code[selected..selected + selected_len].copy_from_slice(instruction);
        code[selected + selected_len] = 0xc3;
        let mut mov = vec![0x2e; victim_len - 5];
        mov.extend_from_slice(&[0xb8, 0xf0, 0xda, 0xbc, 0x9e]);
        code[victim..victim + victim_len].copy_from_slice(&mov);
        code[victim + victim_len] = 0xc3;
        let mut heads = [
            selected,
            selected + selected_len,
            victim,
            victim + victim_len,
        ];
        heads.sort_unstable();
        Self {
            code,
            selected,
            selected_len,
            victim,
            victim_len,
            heads,
        }
    }
    fn visits(&self, offset: usize, base: u64, terminal: u64) -> Vec<u64> {
        assert!(self.heads.contains(&offset));
        let mut result = vec![base + offset as u64];
        if offset == self.selected {
            result.push(base + (offset + self.selected_len) as u64);
        } else if offset == self.victim {
            result.push(base + (offset + self.victim_len) as u64);
        } else {
            assert_eq!(self.code[offset], 0xc3);
        }
        result.push(terminal);
        result
    }
}

#[test]
fn native_overlapping_artifact_selected_before_preserves_full_state() {
    isolated_native_test::run(
        "overlapping_artifact_native::native_overlapping_artifact_selected_before_preserves_full_state",
        "LITEINST2_OVERLAP_BEFORE_CHILD",
        run_before,
    );
}
#[test]
fn native_overlapping_artifact_selected_after_preserves_full_state() {
    isolated_native_test::run(
        "overlapping_artifact_native::native_overlapping_artifact_selected_after_preserves_full_state",
        "LITEINST2_OVERLAP_AFTER_CHILD",
        run_after,
    );
}
fn run_before() {
    run(true);
}
fn run_after() {
    run(false);
}

fn run(before: bool) {
    let mut census = [0_usize; 6]; // layouts, original, linked, restored, relay visits, callbacks
    for selected_len in [2, 3, 4] {
        for victim_len in [6, 9, 10, 15] {
            let puzzle = Puzzle::new(selected_len, victim_len, before);
            let (oracle, mut adjacent, mut arena) =
                NativeOracle::with_seeded_memory_and_flags_neighbor_fixture(
                    &puzzle.code,
                    PROBE,
                    &[PAGE],
                );
            let hook_page = adjacent.pop().unwrap();
            assert!(adjacent.is_empty());
            let base = oracle.code.address();
            let selected = base + puzzle.selected as u64;
            let victim = base + puzzle.victim as u64;
            let relay_pc = victim + 1;
            let rel8 = i8::try_from(i128::from(relay_pc) - i128::from(selected + 2)).unwrap();
            assert_eq!(
                rel8,
                if before {
                    selected_len as i8
                } else {
                    -(victim_len as i8) - 2
                }
            );
            // Independent literal relation, never a call to the production solver.
            let selected_target = base + 0x100008;
            let d = i32::try_from(i128::from(selected_target) - i128::from(victim + 6))
                .unwrap()
                .to_le_bytes();
            let victim_displacement = i32::from_le_bytes([0xe9, d[0], d[1], d[2]]);
            let victim_target =
                u64::try_from(i128::from(victim + 5) + i128::from(victim_displacement)).unwrap();
            let selected_base = selected_target & !4095;
            let victim_base = victim_target & !4095;
            assert_ne!(selected_base, victim_base);
            assert_eq!(selected_target - selected_base, 8);
            assert_ne!(victim_target - victim_base, 0);
            let selected_page = arena.take_writable(selected_base, PAGE);
            let victim_page = arena.take_writable(victim_base, PAGE);
            assert_eq!(hook_page.address(), base + PAGE as u64);
            let function = range(base + 16, puzzle.code.len() - 16);
            let bytes = &puzzle.code[16..];
            let heads: Vec<_> = puzzle
                .heads
                .iter()
                .map(|offset| base + *offset as u64)
                .collect();
            assert_eq!(
                InstructionScanner::default()
                    .scan(bytes, function.start())
                    .unwrap()
                    .instructions()
                    .iter()
                    .map(|instruction| instruction.address())
                    .collect::<Vec<_>>(),
                heads
            );
            let identity = CodeIdentity {
                source: SourceIdentity([0x61; 32]),
                mapping: base,
                generation: 1,
            };
            let entries = LegalEntrySet {
                identity,
                scope: function,
                provenance: EntryProvenance::Declared(
                    "complete overlap INC/ADD/MOV/RET grammar".into(),
                ),
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
            let predecessor = Composition::new(
                identity,
                vec![ExpectedBytes {
                    address: function.start(),
                    bytes: bytes.to_vec(),
                }],
            )
            .unwrap();
            let selected_allocation = policy(selected_target);
            let victim_allocation = policy(victim_target);
            let state = SavedExtendedStateLayout::detect().unwrap();
            let emission = ArtifactEmission::new(
                TargetProfile::linux_x86_64_legacy_evex(state, 1).unwrap(),
                SymbolicHook {
                    identity: PROBE,
                    address: Some(hook_page.address()),
                },
                vec![range(base, PAGE), range(hook_page.address(), PAGE)],
            );
            let request = ArtifactRequest {
                site: PlanningSite {
                    identity,
                    code: bytes,
                    base_address: function.start(),
                    function,
                    block: range(selected, selected_len),
                    logical_pc: selected,
                    entries: &entries,
                    semantics: HookSemantics::Observe,
                    allocation: &selected_allocation,
                    search: SearchPolicy {
                        tactics: TacticPolicy::RelocationOnly,
                        max_upstream_bytes: 0,
                        max_displaced_bytes: 15,
                        max_sites: 1,
                    },
                },
                emission: &emission,
            };
            let plan = engine::plan_with_emission_after_and_overlapping_t3_pending(
                &request,
                &predecessor,
                &[],
                &victim_allocation,
                EnginePolicy {
                    forced: Some(Tactic::NeighborEviction),
                    neighbor: NeighborSearch {
                        forced_victim: Some(victim),
                        max_victims: 1,
                        max_pairs: 1,
                    },
                    bundle: BundleBudget {
                        max_steps: 2,
                        max_mappings: 2,
                        max_virtual_bytes: 8192,
                        max_backing_bytes: 8192,
                        max_virtual_span: 1 << 29,
                    },
                    ..EnginePolicy::default()
                },
            )
            .expect("required native overlapping pair refused; no skip/retry");
            let ArtifactMetrics::Engine(
                tactic,
                SelectedMetrics::Neighbor(geometry, metrics),
                attempts,
            ) = plan.metrics()
            else {
                panic!("overlapping T3 metrics absent")
            };
            assert_eq!(*tactic, Tactic::NeighborEviction);
            assert_eq!(
                (
                    geometry.selected,
                    geometry.selected_len,
                    geometry.victim,
                    geometry.victim_len
                ),
                (selected, selected_len, victim, victim_len)
            );
            assert_eq!(
                (
                    geometry.relay,
                    geometry.rel8,
                    geometry.selected_target,
                    geometry.victim_target
                ),
                (relay_pc, rel8, selected_target, victim_target)
            );
            assert_eq!(
                (
                    metrics.victims_examined,
                    metrics.pairs_examined,
                    metrics.selected_fallthrough_redirects,
                    metrics.victim_fallthrough_redirects
                ),
                (1, 1, 3, 2)
            );
            assert_eq!(metrics.attempts.len(), 1);
            assert_eq!(
                (metrics.attempts[0].stage, &metrics.attempts[0].refusal),
                (NeighborAttemptStage::Composition, &None)
            );
            assert_eq!(attempts.len(), 1);
            for domain in [
                SearchDomain::Victims,
                SearchDomain::JointPairs,
                SearchDomain::VictimImages,
                SearchDomain::SelectedImages,
            ] {
                let runs: Vec<_> = metrics
                    .search
                    .runs
                    .iter()
                    .filter(|run| run.domain == domain)
                    .collect();
                assert_eq!(runs.len(), 1);
                assert_eq!(
                    (runs[0].examined, runs[0].limit, runs[0].stop),
                    (1, 1, SearchStop::Accepted)
                );
            }
            assert!(!plan.qualification_complete());
            let a = exact_e9(victim, victim_target);
            let b = exact_e9(relay_pc, selected_target);
            assert_eq!(&a[1..], &b[..4]);
            let mut victim_edit = a.to_vec();
            victim_edit.push(b[4]);
            assert_eq!(&victim_edit[..2], &[0xe9, 0xe9]);
            assert_eq!(victim_edit.len(), 6);
            let edits = [(selected, vec![0xeb, rel8 as u8]), (victim, victim_edit)];
            let mut appended = predecessor.clone();
            assert_eq!(plan.source_steps().len(), 2);
            let physical_order: Vec<_> = plan
                .source_steps()
                .iter()
                .map(|step| step.parts().physical_pc)
                .collect();
            assert_eq!(physical_order, [selected.max(victim), selected.min(victim)]);
            for step in plan.source_steps() {
                let parts = step.parts();
                assert_eq!(parts.identity, identity);
                assert_eq!(parts.entries, entries);
                assert_eq!(parts.dependencies, [function]);
                step.check_entry_obligations().unwrap();
                let edit = edits
                    .iter()
                    .find(|edit| edit.0 == parts.physical_pc)
                    .unwrap();
                assert_eq!(parts.writes.len(), 1);
                assert_eq!(
                    (parts.writes[0].address, &parts.writes[0].bytes),
                    (edit.0, &edit.1)
                );
                assert_eq!(parts.allocations.len(), 1);
                assert_eq!(
                    parts.allocations[0].range,
                    range(
                        if parts.physical_pc == selected {
                            selected_base
                        } else {
                            victim_base
                        },
                        PAGE
                    )
                );
                assert_eq!(parts.generated.len(), 1);
                assert!(parts.allocations[0].range.covers(range(
                    parts.generated[0].address,
                    parts.generated[0].bytes.len()
                )));
                assert!(parts.requirements.quiescent && parts.requirements.sync_core);
                assert!(!parts.requirements.sigill_router);
                appended.append(step).unwrap();
            }
            appended.require_unclaimed_ranges(&[]).unwrap();
            assert_eq!(predecessor.originals(), predecessor.final_bytes());
            let terminal = oracle.return_pc();
            let mut map = TraceMap {
                boundaries: heads
                    .iter()
                    .copied()
                    .filter(|pc| *pc != selected && *pc != victim)
                    .chain([terminal])
                    .map(|pc| (pc, pc))
                    .collect(),
                gateways: vec![selected, victim],
                ..TraceMap::default()
            };
            let images: Vec<_> = plan.images().collect();
            assert_eq!(images.len(), 2);
            let mut selected_bytes = vec![0xcc; PAGE];
            let mut victim_bytes = vec![0xcc; PAGE];
            for image in &images {
                let logical = if image.address() == selected_target {
                    selected
                } else {
                    assert_eq!(image.address(), victim_target);
                    victim
                };
                let page = if logical == selected {
                    selected_base
                } else {
                    victim_base
                };
                assert!(range(page, PAGE).covers(range(image.address(), image.bytes().len())));
                assert_eq!(image.entry_address(), image.address());
                assert!(image.entry_veneer().is_none());
                assert_eq!(image.entry_routes(), [(logical, image.address())]);
                assert_eq!(image.instruction_boundaries().len(), 1);
                assert_eq!(image.instruction_boundaries()[0].0, logical);
                assert!(!image.metadata().qualification_complete());
                let mut fields = std::collections::BTreeSet::new();
                for field in image.metadata().fields() {
                    assert_eq!(field.bias_domain, 1);
                    assert!(field.origin <= image.bytes().len() as u64);
                    let offset = usize::try_from(field.offset).unwrap();
                    let end = offset.checked_add(field.width).unwrap();
                    let data = image.bytes().get(offset..end).unwrap();
                    for byte in offset..end {
                        assert!(fields.insert(byte), "overlapping image operand fields");
                    }
                    let value = match (field.encoding, field.width) {
                        (ArtifactFieldEncoding::Relative, 1) => i128::from(data[0] as i8),
                        (ArtifactFieldEncoding::Relative, 4) => {
                            i128::from(i32::from_le_bytes(data.try_into().unwrap()))
                        }
                        (ArtifactFieldEncoding::Delta, 8) => {
                            i128::from(i64::from_le_bytes(data.try_into().unwrap()))
                        }
                        _ => panic!("unexpected artifact operand encoding"),
                    };
                    assert_eq!(
                        value,
                        field.target - (i128::from(image.address()) + i128::from(field.origin))
                    );
                }
                let logical_fields: Vec<_> = image
                    .metadata()
                    .fields()
                    .iter()
                    .filter(|field| field.role == "LogicalPc")
                    .collect();
                assert_eq!(logical_fields.len(), usize::from(logical == selected));
                if logical == selected {
                    assert_eq!(logical_fields[0].target, i128::from(selected));
                }
                let hooks: Vec<_> = image
                    .metadata()
                    .fields()
                    .iter()
                    .filter(|field| field.role == "HookCall")
                    .collect();
                assert_eq!(hooks.len(), usize::from(logical == selected));
                if logical == selected {
                    assert_eq!(hooks[0].target, i128::from(hook_page.address()));
                }
                assert_eq!(
                    image
                        .metadata()
                        .requirements()
                        .contains(&ArtifactRequirement::HookAbiAndReadiness(PROBE)),
                    logical == selected
                );
                let returns: Vec<_> = image
                    .metadata()
                    .fields()
                    .iter()
                    .filter(|field| field.role == "Return")
                    .collect();
                assert_eq!(returns.len(), 1);
                let original_len = if logical == selected {
                    selected_len
                } else {
                    victim_len
                };
                assert_eq!(returns[0].target, i128::from(logical + original_len as u64));
                let restored = image.instruction_boundaries()[0].1;
                assert!(
                    map.generated_ranges
                        .iter()
                        .all(|old| !old.contains(&restored))
                );
                assert_eq!(
                    image
                        .program_counter_mappings()
                        .iter()
                        .find_map(|mapping| mapping.translate(restored)),
                    Some(logical)
                );
                let offset = usize::try_from(image.address() - page).unwrap();
                let page_bytes = if logical == selected {
                    &mut selected_bytes
                } else {
                    &mut victim_bytes
                };
                page_bytes[offset..offset + image.bytes().len()].copy_from_slice(image.bytes());
                map.boundaries
                    .extend_from_slice(image.instruction_boundaries());
                map.generated_ranges
                    .push(image.address()..image.address() + image.bytes().len() as u64);
            }
            let mut hook_bytes = vec![0xcc; PAGE];
            hook_bytes[..2].copy_from_slice(&[0x48, 0xb8]);
            hook_bytes[2..10]
                .copy_from_slice(&(observe as *const () as usize as u64).to_le_bytes());
            hook_bytes[10..12].copy_from_slice(&[0xff, 0xe0]);
            for (mapping, bytes) in [
                (&selected_page, &selected_bytes),
                (&victim_page, &victim_bytes),
                (&hook_page, &hook_bytes),
            ] {
                copy(mapping, bytes);
                mapping.protect(libc::PROT_READ | libc::PROT_EXEC);
                assert_page(mapping, bytes);
            }
            let pages = OverlappingPages::new([
                (&selected_page, &selected_bytes),
                (&victim_page, &victim_bytes),
                (&hook_page, &hook_bytes),
            ]);
            let mut originals = Vec::new();
            for seed in SEEDS {
                for (&head, &offset) in heads.iter().zip(&puzzle.heads) {
                    let trace = oracle.trace_original(head, &heads, &[terminal], seed);
                    assert_eq!(trace.visits(), puzzle.visits(offset, base, terminal));
                    census[4] += trace
                        .visits()
                        .iter()
                        .filter(|&&pc| pc == selected || pc == victim)
                        .count();
                    census[5] += trace.visits().iter().filter(|&&pc| pc == selected).count();
                    originals.push((head, trace));
                }
            }
            assert_eq!(originals.len(), 8);
            census[1] += originals.len();
            let victim_trace = &originals
                .iter()
                .find(|(head, _)| *head == victim)
                .unwrap()
                .1;
            assert_eq!(
                victim_trace.visits(),
                [victim, victim + victim_len as u64, terminal]
            );
            let relay = OverlappingSourceRelay {
                logical_pc: selected,
                relay_pc,
                target: selected_target,
                victim_target,
                victim_trace,
            };
            // Every original child is closed before publishing any source byte.
            oracle.assert_publication(&[]);
            oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
            for snapshot in appended.final_bytes() {
                let at = usize::try_from(snapshot.address - base).unwrap();
                assert!(at + snapshot.bytes.len() <= PAGE);
                // SAFETY: exact retained source ownership; all original children closed.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        snapshot.bytes.as_ptr(),
                        oracle.code.writable().add(at),
                        snapshot.bytes.len(),
                    )
                };
            }
            oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
            oracle.assert_publication(&edits);
            let selected_trace = &originals
                .iter()
                .find(|(head, _)| *head == selected)
                .unwrap()
                .1;
            oracle.assert_overlapping_preflight(selected_trace, &map, &relay, &pages);
            oracle.assert_overlapping_witness_negatives(selected_trace, &map, &relay, &pages);
            let log = HookEventLog::new();
            let enabled = [HookEvent {
                probe_id: PROBE,
                logical_pc: selected,
            }];
            for (head, trace) in &originals {
                oracle.assert_trace_with_overlapping_relay(
                    trace,
                    *head,
                    &map,
                    &relay,
                    &pages,
                    Some(HookExpectation {
                        log: &log,
                        enabled: &enabled,
                    }),
                );
                census[2] += 1;
            }
            oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
            for snapshot in predecessor.originals() {
                let at = usize::try_from(snapshot.address - base).unwrap();
                assert!(at + snapshot.bytes.len() <= PAGE);
                // SAFETY: all linked children are closed before exact restoration.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        snapshot.bytes.as_ptr(),
                        oracle.code.writable().add(at),
                        snapshot.bytes.len(),
                    )
                };
            }
            oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
            oracle.assert_publication(&[]);
            let restored = TraceMap {
                boundaries: heads
                    .iter()
                    .copied()
                    .chain([terminal])
                    .map(|pc| (pc, pc))
                    .collect(),
                ..TraceMap::default()
            };
            for (head, trace) in &originals {
                oracle.assert_trace_with_short_relays(
                    trace,
                    *head,
                    &restored,
                    &[],
                    &[],
                    Some(HookExpectation {
                        log: &log,
                        enabled: &[],
                    }),
                );
                census[3] += 1;
            }
            for (mapping, bytes) in [
                (&selected_page, &selected_bytes),
                (&victim_page, &victim_bytes),
                (&hook_page, &hook_bytes),
            ] {
                assert_page(mapping, bytes);
            }
            assert_eq!(SavedExtendedStateLayout::detect().unwrap(), state);
            assert!(!plan.qualification_complete());
            census[0] += 1;
        }
    }
    assert_eq!(census, [12, 96, 96, 96, 48, 24]);
    eprintln!(
        "overlapping artifact: selected_before={before}, 3 selected lengths x 4 victim lengths x 2 seeds, 48 heads, 96 original/96 linked/96 restored traces, 48 exact source-relay transitions and 24 callbacks; no qualification claim"
    );
}
