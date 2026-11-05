//! Finite short-T3 artifact entry veneer, with independent original witnesses.
//! All mappings and every authored entry are required; no skip, retry or fallback.

use super::isolated_native_test;

use super::oracle::{
    EntryVeneerSpec, EntryVeneerWitness, HookEvent, HookEventLog, HookExpectation, Mapping,
    NativeOracle, ShortSourceRelay, TraceMap,
};
use super::{SEEDS, exact_e9};
use liteinst::composition::Composition;
use liteinst::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, ExpectedBytes, LegalEntry,
    LegalEntrySet, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst::emission::{
    ArtifactEmission, ArtifactFieldEncoding, ArtifactMetrics, ArtifactRequest, ArtifactRequirement,
    PlanningSite, SymbolicHook, TargetProfile,
};
use liteinst::engine::{self, EnginePolicy, SelectedMetrics, Tactic};
use liteinst::neighbor::{NeighborAttemptStage, NeighborSearch};
use liteinst::planner::HookSemantics;
use liteinst::quiescent::{AllocationPolicy, SearchPolicy};
use liteinst::scanner::InstructionScanner;
use liteinst::search::SearchDomain;
use liteinst::trampoline::{HookContext, SavedExtendedStateLayout};

const PAGE: usize = 4096;
const VICTIM: usize = 551;
const PROBE: u64 = 0xe9_1888;

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: an isolated oracle child owns the active bounded event page and
    // this actual callback frame. Saved context and application memory stay intact.
    unsafe {
        super::oracle::record_hook_event(PROBE, (*context).instruction_pointer);
        core::arch::asm!(
            "xor eax, eax", "mov rcx, -1", "pxor xmm0, xmm0", "fninit",
            out("rax") _, out("rcx") _, out("xmm0") _, options(nostack),
        );
    }
}

fn range(address: u64, len: usize) -> AddressRange {
    AddressRange::new(address, len).unwrap()
}

fn policy(page: u64, entry: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(page, PAGE)],
        preferred_address: Some(entry),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: PAGE,
    }
}

fn copy(mapping: &Mapping, bytes: &[u8]) {
    assert_eq!(bytes.len(), PAGE);
    // SAFETY: the complete retained page is RW, no child is active, and exactly
    // PAGE bytes are copied. No page is released or replaced by MAP_FIXED.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.writable(), PAGE) };
}

fn assert_page(mapping: &Mapping, bytes: &[u8]) {
    assert_eq!(bytes.len(), PAGE);
    // SAFETY: the immutable readable mapping owner remains alive.
    assert_eq!(
        unsafe { core::slice::from_raw_parts(mapping.writable(), PAGE) },
        bytes
    );
}

struct Puzzle {
    code: Vec<u8>,
    start: usize,
    end: usize,
    selected: usize,
    heads: Vec<usize>,
}

impl Puzzle {
    fn new(selected: usize) -> Self {
        assert!([535, 567].contains(&selected));
        let start = selected.min(VICTIM);
        let end = (selected + 4).max(VICTIM + 11);
        let mut code = vec![0xcc; end];
        code[start..end].fill(0x90);
        code[selected..selected + 4].copy_from_slice(&[0x75, 1, 0xc3, 0xc3]);
        code[VICTIM..VICTIM + 11].copy_from_slice(&[
            0x2e, 0xb8, 0xf0, 0xda, 0xbc, 0x9e, // MOV EAX,0x9ebcdaf0
            0x44, 0x8d, 0x48, 3, // LEA R9D,[RAX+3], flags intact
            0xc3,
        ]);
        // Independent literal grammar: one selected two-byte JNZ, one six-byte
        // MOV, one four-byte LEA; every other byte in the function is NOP1/RET.
        let heads = (start..end)
            .filter(|&at| {
                at != selected + 1
                    && !(VICTIM < at && at < VICTIM + 6)
                    && !(VICTIM + 6 < at && at < VICTIM + 10)
            })
            .collect::<Vec<_>>();
        assert_eq!(heads.len(), if selected == 535 { 18 } else { 11 });
        Self {
            code,
            start,
            end,
            selected,
            heads,
        }
    }

    fn visits(&self, mut at: usize, base: u64, terminal: u64, zero: bool) -> Vec<u64> {
        let mut result = Vec::new();
        for _ in 0..=self.heads.len() {
            assert!(self.heads.contains(&at));
            result.push(base + at as u64);
            if self.code[at] == 0xc3 {
                result.push(terminal);
                return result;
            }
            at = if at == self.selected {
                at + if zero { 2 } else { 3 }
            } else if at == VICTIM {
                at + 6
            } else if at == VICTIM + 6 {
                at + 4
            } else {
                assert_eq!(self.code[at], 0x90);
                at + 1
            };
        }
        panic!("authored entry veneer path did not terminate");
    }
}

#[test]
fn native_entry_veneer_artifact_both_source_orders_preserve_full_state() {
    isolated_native_test::run(
        "entry_veneer_artifact_native::native_entry_veneer_artifact_both_source_orders_preserve_full_state",
        "LITEINST2_ENTRY_VENEER_ARTIFACT_ORACLE_CHILD",
        run,
    );
}

fn run() {
    witness_controls();
    let mut census = [0_usize; 4]; // original, linked, restored, veneer/hook visits
    let mut branches = [0_usize; 2];
    for selected_offset in [535, 567] {
        let puzzle = Puzzle::new(selected_offset);
        let (oracle, mut adjacent, mut arena) =
            NativeOracle::with_seeded_memory_and_flags_neighbor_fixture(
                &puzzle.code,
                0xe9_1888,
                &[PAGE],
            );
        let hook_page = adjacent.pop().unwrap();
        assert!(adjacent.is_empty());
        let base = oracle.code.address();
        let selected = base + selected_offset as u64;
        let victim = base + VICTIM as u64;
        let relay = victim + 5;
        let rel8 = i8::try_from(i128::from(relay) - i128::from(selected + 2)).unwrap();
        assert_eq!(rel8, if selected_offset == 535 { 19 } else { -13 });
        let entry = victim + 10 + 0x0348_8d44;
        let storage = entry & !4095;
        assert_eq!(entry - storage, 3957);
        let victim_target = base + 0x1800_0000;
        let selected_page = arena.take_writable(storage, PAGE);
        let victim_page = arena.take_writable(victim_target, PAGE);
        assert_eq!(hook_page.address(), base + PAGE as u64);
        let function = range(base + puzzle.start as u64, puzzle.end - puzzle.start);
        let bytes = &puzzle.code[puzzle.start..puzzle.end];
        let heads: Vec<_> = puzzle
            .heads
            .iter()
            .map(|offset| base + *offset as u64)
            .collect();
        let scan = InstructionScanner::default()
            .scan(bytes, function.start())
            .unwrap();
        assert_eq!(
            scan.instructions()
                .iter()
                .map(|instruction| instruction.address())
                .collect::<Vec<_>>(),
            heads
        );
        let identity = CodeIdentity {
            source: SourceIdentity([0xe9; 32]),
            mapping: base,
            generation: 1,
        };
        let entries = LegalEntrySet {
            identity,
            scope: function,
            provenance: EntryProvenance::Declared(
                "complete finite entry-veneer literal grammar".into(),
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
        let selected_allocation = policy(storage, entry);
        let victim_allocation = policy(victim_target, victim_target);
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
                block: range(selected, 2),
                logical_pc: selected,
                entries: &entries,
                semantics: HookSemantics::Observe,
                allocation: &selected_allocation,
                search: SearchPolicy {
                    max_upstream_bytes: 0,
                    max_sites: 1,
                    ..SearchPolicy::default()
                },
            },
            emission: &emission,
        };
        let engine_policy = EnginePolicy {
            forced: Some(Tactic::NeighborEviction),
            neighbor: NeighborSearch {
                forced_victim: Some(victim),
                max_victims: 1,
                max_pairs: 1,
            },
            ..EnginePolicy::default()
        };
        let old = engine::plan_with_emission_after_and_fitting_mixed_t3_pending(
            &request,
            &predecessor,
            &[],
            &victim_allocation,
            engine_policy,
        )
        .expect_err("old high-offset fitting profile must retain its refusal");
        assert_eq!(old.reason, Refusal::AllocationUnavailable);
        assert_eq!(old.attempts.len(), 1);
        assert_eq!(old.attempts[0].tactic, Tactic::NeighborEviction);
        let plan = engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
            &request,
            &predecessor,
            &[],
            &victim_allocation,
            engine_policy,
        )
        .expect("finite required short-T3 entry veneer refused; no skip/retry");
        let ArtifactMetrics::Engine(tactic, SelectedMetrics::Neighbor(geometry, metrics), attempts) =
            plan.metrics()
        else {
            panic!("entry veneer did not preserve T3 metrics");
        };
        assert_eq!(*tactic, Tactic::NeighborEviction);
        assert_eq!(
            (
                geometry.selected,
                geometry.selected_len,
                geometry.victim,
                geometry.victim_len
            ),
            (selected, 2, victim, 6)
        );
        assert_eq!(
            (
                geometry.relay,
                geometry.rel8,
                geometry.selected_target,
                geometry.victim_target
            ),
            (relay, rel8, entry, victim_target)
        );
        assert_eq!(
            (
                metrics.victims_examined,
                metrics.pairs_examined,
                metrics.selected_fallthrough_redirects,
                metrics.victim_fallthrough_redirects
            ),
            (1, 1, 4, 2)
        );
        assert_eq!(metrics.attempts.len(), 2);
        let certificate = &metrics.attempts[0];
        assert_eq!(
            (
                certificate.victim,
                certificate.stage,
                certificate.victim_target,
                certificate.selected_target,
                &certificate.refusal
            ),
            (
                victim,
                NeighborAttemptStage::EntryVeneerCertificate,
                Some(victim_target),
                None,
                &Some(Refusal::AllocationUnavailable)
            )
        );
        let composed = &metrics.attempts[1];
        assert_eq!(
            (
                composed.victim,
                composed.stage,
                composed.victim_target,
                composed.selected_target,
                &composed.refusal
            ),
            (
                victim,
                NeighborAttemptStage::Composition,
                Some(victim_target),
                Some(entry),
                &None
            )
        );
        assert_eq!(attempts.len(), 1);
        for domain in [
            SearchDomain::Victims,
            SearchDomain::JointPairs,
            SearchDomain::VictimImages,
            SearchDomain::SelectedImages,
        ] {
            let runs: Vec<_> = attempts[0]
                .search
                .runs
                .iter()
                .filter(|run| run.domain == domain)
                .collect();
            assert_eq!(runs.len(), 1);
            assert_eq!((runs[0].examined, runs[0].limit), (1, 1));
        }
        assert!(!plan.qualification_complete());
        let mut victim_edit = exact_e9(victim, victim_target).to_vec();
        victim_edit.extend_from_slice(&exact_e9(relay, entry));
        assert_eq!(&victim_edit[6..], &[0x44, 0x8d, 0x48, 3]);
        let edits = [(selected, vec![0xeb, rel8 as u8]), (victim, victim_edit)];
        assert_eq!(plan.source_steps().len(), 2);
        let mut appended = predecessor.clone();
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
            let allocation = parts.allocations[0].range;
            assert_eq!(
                allocation,
                range(
                    if parts.physical_pc == selected {
                        storage
                    } else {
                        victim_target
                    },
                    PAGE
                )
            );
            assert_eq!(parts.generated.len(), 1);
            assert!(allocation.covers(range(
                parts.generated[0].address,
                parts.generated[0].bytes.len()
            )));
            assert!(parts.requirements.quiescent && parts.requirements.sync_core);
            assert!(!parts.requirements.sigill_router);
            appended.append(step).unwrap();
        }
        assert_eq!(predecessor.originals(), predecessor.final_bytes());
        appended.require_unclaimed_ranges(&[]).unwrap();
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
        let selected_image = images
            .iter()
            .find(|image| image.address() == storage)
            .unwrap();
        let layout = selected_image
            .entry_veneer()
            .expect("selected storage lacks explicit veneer layout");
        assert_eq!(
            (layout.storage_address(), layout.entry_address()),
            (storage, entry)
        );
        assert_eq!(selected_image.entry_address(), entry);
        assert!(layout.body_len() <= layout.size_bound());
        assert!(layout.size_bound() <= 3957 && layout.size_bound() > PAGE - 3957);
        assert_eq!(
            layout.padding_range(),
            (storage + layout.body_len() as u64, entry)
        );
        assert_eq!(layout.veneer_range(), (entry, entry + 5));
        assert_eq!(selected_image.bytes().len(), 3962);
        let spec = EntryVeneerSpec {
            logical_pc: selected,
            storage,
            entry,
            body_len: layout.body_len(),
            size_bound: layout.size_bound(),
        };
        let mut selected_bytes = vec![0xcc; PAGE];
        let mut victim_bytes = vec![0xcc; PAGE];
        for image in &images {
            let logical = if image.address() == storage {
                selected
            } else {
                assert_eq!(image.address(), victim_target);
                assert_eq!(image.entry_address(), image.address());
                assert!(image.entry_veneer().is_none());
                victim
            };
            assert!(
                range(image.address(), PAGE).covers(range(image.address(), image.bytes().len()))
            );
            assert_eq!(image.entry_routes(), [(logical, image.address())]);
            assert_eq!(image.instruction_boundaries().len(), 1);
            assert_eq!(image.instruction_boundaries()[0].0, logical);
            assert!(!image.metadata().qualification_complete());
            let hooks: Vec<_> = image
                .metadata()
                .fields()
                .iter()
                .filter(|field| field.role == "HookCall")
                .collect();
            assert_eq!(hooks.len(), usize::from(logical == selected));
            assert_eq!(
                image
                    .metadata()
                    .requirements()
                    .contains(&ArtifactRequirement::HookAbiAndReadiness(PROBE)),
                logical == selected
            );
            if logical == selected {
                assert_eq!(hooks[0].target, i128::from(hook_page.address()));
                let fields: Vec<_> = image
                    .metadata()
                    .fields()
                    .iter()
                    .filter(|field| field.role.starts_with("EntryVeneer {"))
                    .collect();
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].encoding, ArtifactFieldEncoding::Relative);
                assert_eq!(
                    (
                        fields[0].offset,
                        fields[0].width,
                        fields[0].origin,
                        fields[0].target,
                        fields[0].bias_domain
                    ),
                    (3958, 4, 3962, i128::from(storage), 1)
                );
                assert_eq!(
                    fields[0].role,
                    format!("EntryVeneer {{ original_pc: {selected} }}")
                );
                assert_eq!(&image.bytes()[3957..], &exact_e9(entry, storage));
                for pc in storage + layout.body_len() as u64..entry {
                    assert!(
                        image
                            .program_counter_mappings()
                            .iter()
                            .all(|mapping| mapping.translate(pc).is_none())
                    );
                }
                for pc in entry..entry + 5 {
                    assert_eq!(
                        image
                            .program_counter_mappings()
                            .iter()
                            .find_map(|mapping| mapping.translate(pc)),
                        Some(selected)
                    );
                }
                assert!(
                    image
                        .instruction_boundaries()
                        .iter()
                        .all(|(_, pc)| *pc != entry)
                );
                selected_bytes[..image.bytes().len()].copy_from_slice(image.bytes());
            } else {
                victim_bytes[..image.bytes().len()].copy_from_slice(image.bytes());
            }
            map.boundaries
                .extend_from_slice(image.instruction_boundaries());
            map.generated_ranges
                .push(image.address()..image.address() + image.bytes().len() as u64);
        }
        spec.validate_image(selected_image.bytes(), &map).unwrap();
        let mut hook_bytes = vec![0xcc; PAGE];
        hook_bytes[..2].copy_from_slice(&[0x48, 0xb8]);
        hook_bytes[2..10].copy_from_slice(&(observe as *const () as usize as u64).to_le_bytes());
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
        let witness = EntryVeneerWitness::new(
            spec,
            selected_image.bytes(),
            [
                (&selected_page, &selected_bytes),
                (&victim_page, &victim_bytes),
                (&hook_page, &hook_bytes),
            ],
        );
        assert_eq!(SavedExtendedStateLayout::detect().unwrap(), state);
        let mut originals = Vec::new();
        for seed in SEEDS {
            let zero = seed & (1 << 6) != 0;
            for (&head, &offset) in heads.iter().zip(&puzzle.heads) {
                let trace = oracle.trace_original(head, &heads, &[terminal], seed);
                assert_eq!(trace.visits(), puzzle.visits(offset, base, terminal, zero));
                let visits = trace.assert_entry_veneer_jnz(selected, zero);
                branches[usize::from(zero)] += visits;
                census[3] += visits;
                originals.push((head, trace));
            }
        }
        assert_eq!(originals.len(), puzzle.heads.len() * 2);
        census[0] += originals.len();
        let victim_trace = &originals
            .iter()
            .find(|(head, _)| *head == victim)
            .unwrap()
            .1;
        assert_eq!(
            victim_trace.visits(),
            [victim, victim + 6, victim + 10, terminal]
        );
        let relays = [ShortSourceRelay {
            logical_pc: selected,
            relay_pc: relay,
            target: entry,
            victim_trace,
        }];
        // Every baseline child has returned before the first source write.
        oracle.assert_publication(&[]);
        oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        for snapshot in appended.final_bytes() {
            let at = usize::try_from(snapshot.address - base).unwrap();
            assert!(at + snapshot.bytes.len() <= PAGE);
            // SAFETY: exact retained source page, exclusive after all baselines.
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
        oracle.assert_entry_veneer_preflight(selected_trace, &map, &relays, &witness);
        // Actual authenticated native victim/source inputs, but no patched
        // execution: a wrong logical owner or entry cannot gain authority.
        for bad_spec in [
            EntryVeneerSpec {
                logical_pc: selected + 1,
                ..spec
            },
            EntryVeneerSpec {
                entry: entry - 1,
                ..spec
            },
        ] {
            let bad = EntryVeneerWitness::new(
                bad_spec,
                selected_image.bytes(),
                [
                    (&selected_page, &selected_bytes),
                    (&victim_page, &victim_bytes),
                    (&hook_page, &hook_bytes),
                ],
            );
            let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                oracle.assert_entry_veneer_preflight(selected_trace, &map, &relays, &bad);
            }))
            .expect_err("corrupt veneer witness accepted before execution");
            let message = refused
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| refused.downcast_ref::<&str>().copied())
                .expect("nontext veneer refusal");
            assert!(
                message.contains("invalid entry veneer witness"),
                "unexpected preflight refusal: {message}"
            );
        }
        let log = HookEventLog::new();
        let enabled = [HookEvent {
            probe_id: PROBE,
            logical_pc: selected,
        }];
        for (head, trace) in &originals {
            oracle.assert_trace_with_entry_veneer(
                trace,
                *head,
                &map,
                &relays,
                &witness,
                Some(HookExpectation {
                    log: &log,
                    enabled: &enabled,
                }),
            );
            census[1] += 1;
        }
        oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        for snapshot in predecessor.originals() {
            let at = usize::try_from(snapshot.address - base).unwrap();
            assert!(at + snapshot.bytes.len() <= PAGE);
            // SAFETY: all patched children are reaped before exact restoration.
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
            census[2] += 1;
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
    }
    assert_eq!(branches, [7, 7]);
    assert_eq!(census, [58, 58, 58, 14]);
    eprintln!(
        "artifact entry veneer: 2 source orders x 2 seeds, 29 heads, 58 original/58 linked/58 restored traces, 14 exact veneer transitions and callbacks; no qualification claim"
    );
}

#[test]
fn entry_veneer_witness_refuses_geometry_bytes_and_restored_authority() {
    witness_controls();
}

fn witness_controls() {
    let spec = EntryVeneerSpec {
        logical_pc: 0x400000,
        storage: 0x500000,
        entry: 0x500f75,
        body_len: 100,
        size_bound: 500,
    };
    let mut bytes = vec![0xcc; 3962];
    bytes[3957..].copy_from_slice(&exact_e9(spec.entry, spec.storage));
    let map = || TraceMap {
        boundaries: vec![(spec.logical_pc, spec.storage + 20)],
        generated_ranges: std::iter::once(spec.storage..spec.entry + 5).collect(),
        ..TraceMap::default()
    };
    spec.validate_image(&bytes, &map()).unwrap();
    for change in 0..8 {
        let mut bad = spec;
        match change {
            0 => bad.storage += 1,
            1 => bad.body_len = 0,
            2 => bad.body_len = bad.size_bound + 1,
            3 => bad.size_bound = 0,
            4 => bad.size_bound = 3958,
            5 => bad.entry = bad.storage + 4092,
            6 => bad.entry = bad.storage - 1,
            _ => bad.storage = u64::MAX - 4095,
        }
        assert!(bad.validate_image(&bytes, &map()).is_err());
    }
    for index in [100, 3956, 3957, 3958, 3961] {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        assert!(spec.validate_image(&bad, &map()).is_err());
    }
    for change in 0..7 {
        let mut bad = map();
        match change {
            0 => bad.generated_ranges[0].start = spec.entry,
            1 => bad.generated_ranges[0].end -= 1,
            2 => bad.generated_ranges.push(spec.storage..spec.entry),
            3 => bad.boundaries[0].1 = spec.entry,
            4 => bad.boundaries[0].1 = spec.storage + 100,
            5 => bad.boundaries[0].0 += 1,
            _ => bad.gateways.push(spec.entry),
        }
        assert!(spec.validate_image(&bytes, &bad).is_err());
    }
    let mut short = bytes.clone();
    short.pop();
    assert!(spec.validate_image(&short, &map()).is_err());
    bytes.push(0xcc);
    assert!(spec.validate_image(&bytes, &map()).is_err());
}
