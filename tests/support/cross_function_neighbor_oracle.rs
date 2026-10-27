//! Synthetic two-function T3 execution, not the common-app instruction corpus.
//! Reuses the parent's unchanged callback, seeds, full-state oracle and limits.

use super::oracle::{
    HookEvent, HookEventLog, HookExpectation, Mapping, NativeOracle, SourceRelay, TraceMap,
};
use super::{PROBE_ID, SEEDS, exact_e9, observe};
use liteinst2::composition::Composition;
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, ExpectedBytes,
    LegalEntry, LegalEntrySet, ResumeObligation, SourceIdentity,
};
use liteinst2::emission::{
    ArtifactEmission, ArtifactMetrics, ArtifactRequest, ArtifactRequirement, PlanningSite,
    SymbolicHook, TargetProfile,
};
use liteinst2::engine::{self, EnginePolicy, SelectedMetrics, Tactic};
use liteinst2::neighbor::NeighborSearch;
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, SearchPolicy};
use liteinst2::scanner::InstructionScanner;
use liteinst2::search::SearchDomain;
use liteinst2::trampoline::SavedExtendedStateLayout;

const PAGE: usize = 4096;
const IMAGE_SLOT: usize = 2 * PAGE;
const GENERATED_BYTES: usize = 2 * IMAGE_SLOT + PAGE;
const VICTIM: usize = 122; // (V + 5) - (S + 2) == 125, as for ID15 -> ID57.
const SELECTED_BYTES: [u8; 4] = [0x75, 1, 0x90, 0xc3]; // JNZ RET; NOP; RET.

fn range(address: u64, bytes: usize) -> AddressRange {
    AddressRange::new(address, bytes).unwrap()
}

fn entries(identity: CodeIdentity, base: u64, bytes: &[u8], offsets: &[u64]) -> LegalEntrySet {
    let heads: Vec<_> = offsets.iter().map(|offset| base + offset).collect();
    // Decoder only authenticates the declared complete original inventory;
    // expected execution paths below are independent literal branch semantics.
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
        provenance: EntryProvenance::Declared(
            "private complete two-function native fixture".into(),
        ),
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

fn copy_owned(mapping: &Mapping, owned_len: usize, address: u64, bytes: &[u8]) {
    assert!(range(mapping.address(), owned_len).covers(range(address, bytes.len())));
    let offset = usize::try_from(address - mapping.address()).unwrap();
    // SAFETY: the caller owns this whole RW (not executable) mapping, checked
    // the destination, and has no live child during any fixture write.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.writable().add(offset), bytes.len())
    };
}

fn assert_owned(mapping: &Mapping, expected: &[u8]) {
    // SAFETY: this fixture retains the whole readable mapping through every
    // child wait; expected.len() is its original, fixed allocation length.
    let actual = unsafe { core::slice::from_raw_parts(mapping.writable(), expected.len()) };
    assert_eq!(actual, expected);
}

fn visits(entry: u64, base: u64, terminal: u64, seed: u64) -> Vec<u64> {
    let offsets: &[u64] = match entry - base {
        0 if seed & 0x40 == 0 => &[0, 3], // JNZ taken when the seeded ZF is clear.
        0 => &[0, 2, 3],
        2 => &[2, 3],
        3 => &[3],
        122 => &[122, 132],
        132 => &[132],
        _ => panic!("undeclared fixture entry"),
    };
    offsets
        .iter()
        .map(|offset| base + offset)
        .chain([terminal])
        .collect()
}

#[test]
fn native_foreign_neighbor_two_owners_all_heads_both_seeds() {
    let mut victim_bytes = vec![0x48, 0xb8]; // MOVABS RAX, integer; RET.
    victim_bytes.extend_from_slice(&0x1739_5b7d_9ebc_daf0_u64.to_le_bytes());
    victim_bytes.push(0xc3);
    let mut code = vec![0xcc; VICTIM + victim_bytes.len()];
    code[..SELECTED_BYTES.len()].copy_from_slice(&SELECTED_BYTES);
    code[VICTIM..].copy_from_slice(&victim_bytes);
    let oracle = NativeOracle::with_seeded_memory_and_flags(&code, 0x15_57);
    let base = oracle.code.address();
    let victim = base + VICTIM as u64;
    let relay = victim + 5;
    let heads = [base, base + 2, base + 3, victim, victim + 10];
    let terminal = oracle.return_pc();
    assert_eq!(SEEDS.map(|seed| seed & 0x40 != 0), [false, true]);
    let identity = CodeIdentity {
        source: SourceIdentity([0x57; 32]),
        mapping: base,
        generation: 1,
    };
    let selected_entries = entries(identity, base, &SELECTED_BYTES, &[0, 2, 3]);
    let victim_entries = entries(identity, victim, &victim_bytes, &[0, 10]);
    assert!(!selected_entries.scope.overlaps(victim_entries.scope));
    let predecessor = Composition::new(
        identity,
        vec![
            ExpectedBytes {
                address: base,
                bytes: SELECTED_BYTES.to_vec(),
            },
            ExpectedBytes {
                address: victim,
                bytes: victim_bytes.clone(),
            },
        ],
    )
    .unwrap();

    // Reserve once without MAP_FIXED or a clobbering retry. The two image slots
    // and callback bridge are private, disjoint subranges of this single owner.
    // Planning/placement failure unwinds this owner before any source redirect.
    let generated = Mapping::new(GENERATED_BYTES);
    let selected_target = generated.address();
    let victim_target = selected_target + IMAGE_SLOT as u64;
    let hook_target = victim_target + IMAGE_SLOT as u64;
    assert!(!range(base, PAGE).overlaps(range(generated.address(), GENERATED_BYTES)));
    for target in [
        selected_target,
        victim_target,
        hook_target + PAGE as u64 - 1,
    ] {
        assert!(i32::try_from(i128::from(target) - i128::from(base) - 5).is_ok());
    }
    let selected_allocation = allocation(selected_target);
    let victim_allocation = allocation(victim_target);
    let state = SavedExtendedStateLayout::detect().unwrap();
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(state, 1).unwrap(),
        SymbolicHook {
            identity: PROBE_ID,
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
            code: &SELECTED_BYTES,
            base_address: base,
            function: selected_entries.scope,
            block: range(base, 2),
            logical_pc: base,
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
    let policy = EnginePolicy {
        neighbor: NeighborSearch {
            forced_victim: Some(victim),
            max_victims: 1,
            max_pairs: 1,
        },
        ..EnginePolicy::default()
    };
    let local =
        engine::plan_with_emission_after(&request, &predecessor, &victim_allocation, policy)
            .unwrap_err();
    assert_eq!(
        local.attempts.iter().map(|a| a.tactic).collect::<Vec<_>>(),
        [
            Tactic::GeneralizedPun,
            Tactic::Relocation,
            Tactic::PrefixedPun,
            Tactic::SuccessorEviction,
            Tactic::NeighborEviction,
        ]
    );
    assert!(local.attempts.iter().all(|a| a.refusal.is_some()));
    let plan = engine::plan_with_emission_after_with_foreign(
        &request,
        &predecessor,
        &victim_allocation,
        policy,
        &[foreign],
    )
    .expect("required owned foreign T3 must succeed; no skip/fallback");
    let ArtifactMetrics::Engine(tactic, SelectedMetrics::Neighbor(geometry, metrics), attempts) =
        plan.metrics()
    else {
        panic!("expected foreign T3 engine plan");
    };
    assert_eq!(*tactic, Tactic::NeighborEviction);
    assert_eq!(attempts.len(), 6);
    assert_eq!(
        format!("{:?}", &attempts[..5]),
        format!("{:?}", local.attempts)
    );
    assert!(attempts[5].refusal.is_none());
    for domain in [SearchDomain::Victims, SearchDomain::JointPairs] {
        assert_eq!(
            attempts
                .iter()
                .filter(|a| a.tactic == Tactic::NeighborEviction)
                .flat_map(|a| &a.search.runs)
                .filter(|r| r.domain == domain)
                .map(|r| r.examined)
                .sum::<usize>(),
            1
        );
    }
    assert_eq!((metrics.victims_examined, metrics.pairs_examined), (1, 1));
    assert_eq!(
        (
            geometry.selected,
            geometry.selected_len,
            geometry.victim,
            geometry.victim_len
        ),
        (base, 2, victim, 10)
    );
    assert_eq!(
        (
            geometry.relay,
            geometry.rel8,
            geometry.selected_target,
            geometry.victim_target
        ),
        (relay, 125, selected_target, victim_target)
    );
    assert!(!plan.qualification_complete());

    let mut expected_victim = exact_e9(victim, victim_target).to_vec();
    expected_victim.extend_from_slice(&exact_e9(relay, selected_target));
    let edits = [(base, vec![0xeb, 125]), (victim, expected_victim)];
    let mut appended = predecessor.clone();
    assert_eq!(plan.source_steps().len(), 2);
    for (step, owner, original, edit) in [
        (
            &plan.source_steps()[0],
            &victim_entries,
            &victim_bytes[..],
            &edits[1],
        ),
        (
            &plan.source_steps()[1],
            &selected_entries,
            &SELECTED_BYTES[..],
            &edits[0],
        ),
    ] {
        let parts = step.parts();
        assert_eq!(parts.identity, identity);
        assert_eq!(parts.entries, *owner);
        assert_eq!(
            parts.reads,
            [ExpectedBytes {
                address: owner.scope.start(),
                bytes: original.to_vec()
            }]
        );
        assert_eq!(parts.dependencies, [owner.scope]);
        assert_eq!((parts.logical_pc, parts.physical_pc), (edit.0, edit.0));
        assert_eq!(parts.displaced, range(edit.0, edit.1.len()));
        assert_eq!(parts.writes.len(), 1);
        assert_eq!(
            (parts.writes[0].address, &parts.writes[0].bytes),
            (edit.0, &edit.1)
        );
        assert!(parts.requirements.quiescent && parts.requirements.sync_core);
        assert!(!parts.requirements.sigill_router);
        assert_eq!(parts.obligations, [EntryObligation::Preserved(edit.0)]);
        let target = if edit.0 == base {
            selected_target
        } else {
            victim_target
        };
        assert_eq!(parts.allocations.len(), 1);
        assert_eq!(parts.allocations[0].alignment, PAGE);
        assert!(range(target, IMAGE_SLOT).covers(parts.allocations[0].range));
        assert_eq!(parts.generated.len(), 1);
        assert_eq!(parts.generated[0].address, target);
        appended.append(step).unwrap();
    }
    assert_eq!(predecessor.originals(), predecessor.final_bytes());

    let mut map = TraceMap {
        boundaries: heads
            .into_iter()
            .filter(|pc| *pc != base && *pc != victim)
            .chain([terminal])
            .map(|pc| (pc, pc))
            .collect(),
        gateways: vec![base, victim],
        ..TraceMap::default()
    };
    let mut expected_generated = vec![0xcc; GENERATED_BYTES];
    let images: Vec<_> = plan.images().collect();
    assert_eq!(images.len(), 2);
    for image in &images {
        let (logical, target) = if image.address() == selected_target {
            (base, selected_target)
        } else {
            assert_eq!(image.address(), victim_target);
            (victim, victim_target)
        };
        assert!(range(target, IMAGE_SLOT).covers(range(image.address(), image.bytes().len())));
        assert_eq!(image.entry_routes(), [(logical, target)]);
        assert_eq!(image.instruction_boundaries().len(), 1);
        assert_eq!(image.instruction_boundaries()[0].0, logical);
        assert!(!image.metadata().qualification_complete());
        assert_eq!(
            image
                .metadata()
                .requirements()
                .contains(&ArtifactRequirement::HookAbiAndReadiness(PROBE_ID)),
            logical == base
        );
        let member = plan
            .source_steps()
            .iter()
            .find(|step| step.parts().physical_pc == logical)
            .unwrap();
        assert_eq!(member.parts().generated[0].bytes, image.bytes());
        let hooks: Vec<_> = image
            .metadata()
            .fields()
            .iter()
            .filter(|f| f.role == "HookCall")
            .collect();
        assert_eq!(hooks.len(), usize::from(logical == base));
        if logical == base {
            assert_eq!(hooks[0].target, i128::from(hook_target));
        }
        assert_eq!(
            image
                .metadata()
                .fields()
                .iter()
                .filter(|f| f.role == "LogicalPc")
                .count(),
            usize::from(logical == base)
        );
        map.boundaries
            .extend_from_slice(image.instruction_boundaries());
        map.generated_ranges
            .push(image.address()..image.address() + image.bytes().len() as u64);
        let offset = usize::try_from(image.address() - generated.address()).unwrap();
        expected_generated[offset..offset + image.bytes().len()].copy_from_slice(image.bytes());
    }
    // Symbolic HookCall is rel32. This test-owned, nearby MOVABS/JMP bridge
    // reaches the real callback only after emitted full-state save/RDI setup.
    let mut hook_bridge = vec![0x48, 0xb8];
    hook_bridge.extend_from_slice(&(observe as *const () as usize as u64).to_le_bytes());
    hook_bridge.extend_from_slice(&[0xff, 0xe0]);
    let bridge_offset = 2 * IMAGE_SLOT;
    expected_generated[bridge_offset..bridge_offset + hook_bridge.len()]
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
        for entry in heads {
            let trace = oracle.trace_original(entry, &heads, &[terminal], seed);
            assert_eq!(trace.visits(), visits(entry, base, terminal, seed));
            originals.push((entry, trace));
        }
    }
    assert_eq!(originals.len(), 10);
    assert_eq!(
        originals
            .iter()
            .map(|(_, trace)| trace.visits().len())
            .sum::<usize>(),
        27
    );
    let witness = &originals
        .iter()
        .find(|(entry, _)| *entry == victim)
        .unwrap()
        .1;
    assert_eq!(witness.visits(), [victim, victim + 10, terminal]);
    let relays = [SourceRelay {
        logical_pc: base,
        relay_pc: relay,
        target: selected_target,
        victim_trace: witness,
    }];
    let log = HookEventLog::new();
    let enabled = [HookEvent {
        probe_id: PROBE_ID,
        logical_pc: base,
    }];

    // All generated bytes and the complete transaction are checked first. This
    // is private fixture publication between reaped children, not a conversion
    // to a live plan or a claim about concurrent publication/sync-core APIs.
    oracle.assert_publication(&[]);
    oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
    for snapshot in appended.final_bytes() {
        copy_owned(&oracle.code, PAGE, snapshot.address, &snapshot.bytes);
    }
    oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
    oracle.assert_publication(&edits);
    let mut no_hook_entries = 0;
    for (entry, trace) in &originals {
        if *entry != base {
            assert!(!trace.visits().contains(&base));
            no_hook_entries += 1;
        }
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
        assert_owned(&generated, &expected_generated);
    }
    assert_eq!(no_hook_entries, 8);

    // Restore only after every patched child was waited/reaped by the existing
    // oracle. No generated owner can drop while a trace is alive, including
    // panic unwinding (Tracee drops inside the unchanged oracle first).
    oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
    for original in predecessor.originals() {
        copy_owned(&oracle.code, PAGE, original.address, &original.bytes);
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
        assert_owned(&generated, &expected_generated);
    }
    assert!(!plan.qualification_complete());
}
