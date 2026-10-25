#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Required T3 endpoint cohort: six layouts, 737 original heads including every
//! NOP1 gap head, two fixed seeds, 1474 installed and 1474 retired comparisons.
//! Native victim span witnesses use exact MOVABS RAX,imm64 with 0/2/5 CS prefixes.
//! Additional branch, RIP-relative, MOFFS-fault and LOOP families use separate
//! independent literal grammars and native fallthrough witnesses.

#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::bundle::{BundleBudget, WritableAlias};
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, LegalEntry,
    LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::neighbor::{NeighborSearch, plan_neighbor};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, InstallRequest, SearchPolicy};
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::{HookContext, TrampolinePlan};
use oracle::{
    HookEvent, HookEventLog, HookExpectation, Mapping, NativeOracle, NativeTrace, SourceRelay,
    TraceMap,
};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const PROBE_ID: u64 = 0x703;

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: this isolated child has an active bounded private log and the
    // emitter supplies the live callback frame. Scratch clobbers are intentional.
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
    // SAFETY: this fixture owns the complete private source page under its lease.
    if unsafe { libc::mprotect(pointer.cast(), 4096, protection) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

struct Puzzle {
    code: Vec<u8>,
    heads: Vec<usize>,
    selected: usize,
    selected_len: usize,
    victim: usize,
    victim_len: usize,
    rel8: i8,
}

impl Puzzle {
    fn endpoint(selected_len: usize, victim_len: usize, backward: bool) -> Self {
        let (selected, victim, rel8) = if backward {
            (131, 0, -128)
        } else {
            (0, 124, 127)
        };
        let selected_bytes: &[u8] = match selected_len {
            2 => &[0xff, 0xc0],
            3 => &[0x48, 0xff, 0xc0],
            4 => &[0x48, 0x83, 0xc0, 1],
            _ => panic!("unexpected selected grammar"),
        };
        assert!([10, 12, 15].contains(&victim_len));
        let mut code = vec![0x90; (selected + selected_len).max(victim + victim_len) + 1];
        code[selected..selected + selected_len].copy_from_slice(selected_bytes);
        code[selected + selected_len] = 0xc3;
        let prefixes = victim_len - 10;
        code[victim..victim + prefixes].fill(0x2e);
        code[victim + prefixes..victim + prefixes + 2].copy_from_slice(&[0x48, 0xb8]);
        let immediate = 0x1739_5b7d_9ebc_daf0_u64 + selected_len as u64;
        code[victim + prefixes + 2..victim + victim_len].copy_from_slice(&immediate.to_le_bytes());
        code[victim + victim_len] = 0xc3;
        let heads = (0..code.len())
            .filter(|&pc| {
                !(selected < pc && pc < selected + selected_len)
                    && !(victim < pc && pc < victim + victim_len)
            })
            .collect();
        Self {
            code,
            heads,
            selected,
            selected_len,
            victim,
            victim_len,
            rel8,
        }
    }

    fn expected_visits(&self, entry: usize, base: u64, terminal: u64) -> Vec<u64> {
        let mut visits = Vec::new();
        let mut pc = entry;
        loop {
            assert!(self.heads.contains(&pc));
            visits.push(base + pc as u64);
            if pc == self.selected {
                pc += self.selected_len;
            } else if pc == self.victim {
                pc += self.victim_len;
            } else if pc == self.selected + self.selected_len || pc == self.victim + self.victim_len
            {
                assert_eq!(self.code[pc], 0xc3);
                visits.push(terminal);
                return visits;
            } else {
                assert_eq!(
                    self.code[pc], 0x90,
                    "every gap head is a real original NOP1"
                );
                pc += 1;
            }
        }
    }
}

const ENDPOINT_LAYOUTS: [(usize, usize, bool, usize); 6] = [
    (2, 10, true, 124),
    (3, 12, true, 122),
    (4, 15, true, 119),
    (2, 10, false, 125),
    (3, 12, false, 124),
    (4, 15, false, 123),
];

// The six named tests preserve the original frozen cohort. Exact per-layout
// checks work in fixed command shards; the last layout in a full process also
// checks the original aggregate execution counts. Six source owners stay pinned
// until process exit so parallel tests cannot reuse their retained image offsets.
static ENDPOINT_STARTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static ENDPOINT_COMPLETED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static ENDPOINT_HEADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static ENDPOINT_INSTALLED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static ENDPOINT_RETIRED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static ENDPOINT_DIRECT_VICTIMS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[test]
fn native_neighbor_endpoint_inventory_is_the_complete_frozen_cohort() {
    assert_eq!(ENDPOINT_LAYOUTS.len(), 6);
    assert_eq!(
        ENDPOINT_LAYOUTS.map(|layout| layout.3),
        [124, 122, 119, 125, 124, 123]
    );
    let mut heads = 0;
    for (selected_len, victim_len, backward, expected_heads) in ENDPOINT_LAYOUTS {
        let puzzle = Puzzle::endpoint(selected_len, victim_len, backward);
        assert_eq!(puzzle.heads.len(), expected_heads);
        heads += puzzle.heads.len();
    }
    assert_eq!(heads, 737);
    assert_eq!(heads * SEEDS.len(), 1474);
    assert_eq!(ENDPOINT_LAYOUTS.len() * SEEDS.len(), 12);
}

#[test]
fn native_neighbor_endpoint_backward_l2_m10_all_124_heads() {
    run_endpoint(0);
}
#[test]
fn native_neighbor_endpoint_backward_l3_m12_all_122_heads() {
    run_endpoint(1);
}
#[test]
fn native_neighbor_endpoint_backward_l4_m15_all_119_heads() {
    run_endpoint(2);
}
#[test]
fn native_neighbor_endpoint_forward_l2_m10_all_125_heads() {
    run_endpoint(3);
}
#[test]
fn native_neighbor_endpoint_forward_l3_m12_all_124_heads() {
    run_endpoint(4);
}
#[test]
fn native_neighbor_endpoint_forward_l4_m15_all_123_heads() {
    run_endpoint(5);
}

fn run_endpoint(layout_index: usize) {
    use std::sync::atomic::Ordering::SeqCst;
    let bit = 1 << layout_index;
    assert_eq!(
        ENDPOINT_STARTED.fetch_or(bit, SeqCst) & bit,
        0,
        "endpoint layout ran twice"
    );
    let (selected_len, victim_len, backward, expected_heads) = ENDPOINT_LAYOUTS[layout_index];
    let mut head_count = 0;
    let mut installed_count = 0;
    let mut retired_count = 0;
    let mut direct_victim_count = 0;
    let puzzle = Puzzle::endpoint(selected_len, victim_len, backward);
    assert_eq!(puzzle.heads.len(), expected_heads);
    head_count += puzzle.heads.len();
    let mut oracle = NativeOracle::new(&puzzle.code);
    let base = oracle.code.address();
    let selected = base + puzzle.selected as u64;
    let victim = base + puzzle.victim as u64;
    let relay = victim + 5;
    assert_eq!(
        i128::from(relay) - i128::from(selected) - 2,
        i128::from(puzzle.rel8)
    );
    let heads: Vec<_> = puzzle.heads.iter().map(|&pc| base + pc as u64).collect();
    let source = AddressRange::new(base, puzzle.code.len()).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0xf0 + layout_index as u8; 32]),
        mapping: base,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared("T3 all original NOP1-gap endpoint heads".into()),
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
    let selected_target = base + 0x1000_0180;
    let victim_target = base + 0x1800_0280;
    let mut selected_allocation = AllocationPolicy::near(selected).unwrap();
    selected_allocation.ranges = vec![AddressRange::new(selected_target & !4095, 8192).unwrap()];
    selected_allocation.preferred_address = Some(selected_target);
    let mut victim_allocation = AllocationPolicy::near(victim).unwrap();
    victim_allocation.ranges = vec![AddressRange::new(victim_target & !4095, 8192).unwrap()];
    victim_allocation.preferred_address = Some(victim_target);
    let request = InstallRequest {
        identity,
        code: &puzzle.code,
        base_address: base,
        function: source,
        block: AddressRange::new(selected, selected_len).unwrap(),
        logical_pc: selected,
        entries: &entries,
        hook: observe,
        semantics: HookSemantics::Observe,
        allocation: &selected_allocation,
        search: SearchPolicy {
            max_upstream_bytes: 0,
            max_sites: 1,
            ..SearchPolicy::default()
        },
    };
    let planned = plan_neighbor(&request, &victim_allocation, NeighborSearch {
        forced_victim:Some(victim), max_victims:1, max_pairs:1,
    }, BundleBudget::default()).unwrap_or_else(|error|
        panic!("required T3 endpoint L{selected_len}/M{victim_len}/backward={backward} refused: {error:?}"));
    let geometry = planned.geometry();
    assert_eq!(geometry.selected, selected);
    assert_eq!(geometry.selected_len, selected_len);
    assert_eq!(geometry.victim, victim);
    assert_eq!(geometry.victim_len, victim_len);
    assert_eq!(geometry.relay, relay);
    assert_eq!(geometry.rel8, puzzle.rel8);
    assert_eq!(geometry.selected_target, selected_target);
    assert_eq!(geometry.victim_target, victim_target);
    assert_eq!(planned.metrics().victims_examined, 1);
    assert_eq!(planned.metrics().pairs_examined, 1);
    assert_eq!(planned.metrics().selected_fallthrough_redirects, 3);
    assert_eq!(planned.metrics().victim_fallthrough_redirects, 2);
    let bundle = planned.bundle();
    assert_eq!(bundle.plan().steps().len(), 2);
    assert_eq!(bundle.images().len(), 2);
    assert!(
        bundle.plan().steps()[0].parts().physical_pc > bundle.plan().steps()[1].parts().physical_pc,
        "T3 members must compose in descending source order"
    );
    let selected_step = bundle
        .plan()
        .steps()
        .iter()
        .find(|step| step.parts().physical_pc == selected)
        .unwrap();
    let victim_step = bundle
        .plan()
        .steps()
        .iter()
        .find(|step| step.parts().physical_pc == victim)
        .unwrap();
    assert_eq!(
        selected_step.parts().displaced,
        AddressRange::new(selected, selected_len).unwrap()
    );
    assert_eq!(
        victim_step.parts().displaced,
        AddressRange::new(victim, victim_len).unwrap()
    );
    assert_eq!(selected_step.parts().writes.len(), 1);
    assert_eq!(selected_step.parts().writes[0].address, selected);
    assert_eq!(
        selected_step.parts().writes[0].bytes,
        [0xeb, puzzle.rel8 as u8]
    );
    let mut victim_bytes = exact_e9(victim, victim_target).to_vec();
    victim_bytes.extend_from_slice(&exact_e9(relay, selected_target));
    assert_eq!(victim_step.parts().writes.len(), 1);
    assert_eq!(victim_step.parts().writes[0].address, victim);
    assert_eq!(victim_step.parts().writes[0].bytes, victim_bytes);
    let edits = vec![
        (selected, vec![0xeb, puzzle.rel8 as u8]),
        (victim, victim_bytes),
    ];
    let mut map = TraceMap {
        boundaries: heads
            .iter()
            .copied()
            .filter(|&pc| pc != selected && pc != victim)
            .chain([oracle.return_pc()])
            .map(|pc| (pc, pc))
            .collect(),
        gateways: vec![selected, victim],
        ..TraceMap::default()
    };
    for image in bundle.images() {
        assert_eq!(image.instruction_boundaries().len(), 1);
        let expected = if image.address() == selected_target {
            selected
        } else {
            assert_eq!(image.address(), victim_target);
            victim
        };
        assert_eq!(image.instruction_boundaries()[0].0, expected);
        map.boundaries
            .extend_from_slice(image.instruction_boundaries());
        map.generated_ranges
            .push(image.address()..image.address() + image.bytes().len() as u64);
    }
    for step in bundle.plan().steps() {
        assert!(
            matches!(step.parts().kind, PlanKind::Relocation),
            "the dedicated PlannedNeighbor geometry owns the multi-member T3 identity"
        );
        assert!(!step.parts().requirements.sigill_router);
        assert!(
            step.parts()
                .obligations
                .iter()
                .all(|entry| matches!(entry, EntryObligation::Preserved(_)))
        );
    }
    let mut originals = Vec::new();
    for seed in SEEDS {
        for (&entry, &offset) in heads.iter().zip(&puzzle.heads) {
            let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
            assert_eq!(
                trace.visits(),
                puzzle.expected_visits(offset, base, oracle.return_pc())
            );
            originals.push((entry, trace));
        }
    }
    let witness = &originals
        .iter()
        .find(|(entry, _)| *entry == victim)
        .unwrap()
        .1;
    assert_eq!(
        witness.visits(),
        [victim, victim + victim_len as u64, oracle.return_pc()]
    );
    let relay_records = [SourceRelay {
        logical_pc: selected,
        relay_pc: relay,
        target: selected_target,
        victim_trace: witness,
    }];
    let writable = oracle.code.writable();
    // SAFETY: the complete private source alias remains alive through the
    // bundle's retirement, and every original child has been reaped.
    let aliases = [unsafe { WritableAlias::new(source, writable) }.unwrap()];
    let mut installed = {
        // SAFETY: exclusive source ownership excludes execution/continuations.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![source]) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: source exclusion remains held until executable permissions,
        // synchronization and the complete bundle receipt are established.
        let (installed, receipt) = unsafe {
            bundle.publish_with(&aliases, &mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required T3 endpoint publication failed");
        assert_eq!(receipt.plan().steps(), bundle.plan().steps());
        assert!(!lease.is_poisoned());
        installed
    };
    oracle.assert_publication(&edits);
    let log = HookEventLog::new();
    let enabled = [HookEvent {
        probe_id: PROBE_ID,
        logical_pc: selected,
    }];
    for (entry, trace) in &originals {
        if *entry == victim {
            assert!(!trace.visits().contains(&selected));
            direct_victim_count += 1;
        }
        oracle.assert_trace_with_relays(
            trace,
            *entry,
            &map,
            &relay_records,
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &enabled,
            }),
        );
        installed_count += 1;
    }
    assert_eq!(installed.routed_entries(), 0);
    {
        let mut ranges = vec![source];
        ranges.extend(bundle.plan().steps().iter().flat_map(|step| {
            step.parts()
                .allocations
                .iter()
                .map(|allocation| allocation.range)
        }));
        // SAFETY: every patched child is reaped; source and both generated
        // images join the complete continuation/execution lifetime drain.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: original bytes and final RX are restored while held.
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required T3 endpoint retirement failed");
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
        retired_count += 1;
    }
    assert_eq!(head_count, expected_heads);
    assert_eq!(installed_count, expected_heads * SEEDS.len());
    assert_eq!(retired_count, expected_heads * SEEDS.len());
    assert_eq!(direct_victim_count, SEEDS.len());
    // This bounded set of six private fixture owners deliberately lives until
    // process exit. It includes the source/data/stack mappings already owned by
    // each original layout; it does not create an unbounded mapping cache.
    let _pinned_source = Box::leak(Box::new(oracle));
    ENDPOINT_HEADS.fetch_add(head_count, SeqCst);
    ENDPOINT_INSTALLED.fetch_add(installed_count, SeqCst);
    ENDPOINT_RETIRED.fetch_add(retired_count, SeqCst);
    ENDPOINT_DIRECT_VICTIMS.fetch_add(direct_victim_count, SeqCst);
    let completed = ENDPOINT_COMPLETED.fetch_or(bit, SeqCst) | bit;
    eprintln!(
        "native T3 endpoint L{selected_len}/M{victim_len}/backward={backward}: {head_count} original heads, {installed_count} installed and {retired_count} retired full-state/event comparisons; zero mismatches"
    );
    if completed == ((1 << ENDPOINT_LAYOUTS.len()) - 1) {
        assert_eq!(ENDPOINT_HEADS.load(SeqCst), 737);
        assert_eq!(ENDPOINT_INSTALLED.load(SeqCst), 1474);
        assert_eq!(ENDPOINT_RETIRED.load(SeqCst), 1474);
        assert_eq!(ENDPOINT_DIRECT_VICTIMS.load(SeqCst), 12);
        eprintln!(
            "native T3 endpoint oracle: six layouts, 737 original heads including all NOP1 gap heads, two seeds, 1474 installed + 1474 retired full-state/event comparisons, 12 independent victim entries without selected hook; zero mismatches"
        );
    }
}

fn exact_e9(source: u64, target: u64) -> [u8; 5] {
    let displacement = i32::try_from(i128::from(target) - i128::from(source) - 5).unwrap();
    let mut bytes = [0; 5];
    bytes[0] = 0xe9;
    bytes[1..].copy_from_slice(&displacement.to_le_bytes());
    bytes
}

// Independent manually encoded relay scaffold. This validates the oracle
// itself, without asking the production T3 planner to construct the mutation.
struct RelayCalibration {
    oracle: NativeOracle,
    trace: NativeTrace,
    witness: NativeTrace,
    map: TraceMap,
    selected: u64,
    victim: u64,
    target: u64,
    _images: Vec<Mapping>,
}

impl RelayCalibration {
    fn new(seed: u64, extra_original_head: bool) -> Self {
        let mut code = vec![0x90; 35];
        code[..2].copy_from_slice(&[0x48, 0xb8]);
        code[2..10].copy_from_slice(&0x1357_9bdf_2468_ace0_u64.to_le_bytes());
        code[10] = 0xc3;
        code[32..35].copy_from_slice(&[0x66, 0x90, 0xc3]);
        let oracle = NativeOracle::new(&code);
        let victim = oracle.code.address();
        let selected = victim + 32;
        let mut heads: Vec<_> = (0..35)
            .filter(|&pc| !(1..10).contains(&pc) && pc != 33)
            .map(|pc| victim + pc)
            .collect();
        if extra_original_head {
            heads.push(victim + 5);
        }
        let trace = oracle.trace_original(selected, &heads, &[oracle.return_pc()], seed);
        let witness = oracle.trace_original(victim, &heads, &[oracle.return_pc()], seed);
        assert_eq!(trace.visits(), [selected, selected + 2, oracle.return_pc()]);
        assert_eq!(witness.visits(), [victim, victim + 10, oracle.return_pc()]);
        let victim_image = Mapping::new(4096);
        let selected_image = Mapping::new(4096);
        let target = selected_image.address();
        let mut victim_code = code[..10].to_vec();
        victim_code.extend_from_slice(&exact_e9(victim_image.address() + 10, victim + 10));
        write_mapping(&victim_image, 0, &victim_code);
        let mut selected_code = vec![0x66, 0x90];
        selected_code.extend_from_slice(&exact_e9(target + 2, selected + 2));
        write_mapping(&selected_image, 0, &selected_code);
        let mut victim_redirect = exact_e9(victim, victim_image.address()).to_vec();
        victim_redirect.extend_from_slice(&exact_e9(victim + 5, target));
        write_mapping(&oracle.code, 0, &victim_redirect);
        let rel8 = i8::try_from(i128::from(victim + 5) - i128::from(selected) - 2).unwrap();
        write_mapping(&oracle.code, 32, &[0xeb, rel8 as u8]);
        oracle.assert_publication(&[
            (victim, victim_redirect),
            (selected, vec![0xeb, rel8 as u8]),
        ]);
        let mut boundaries: Vec<_> = heads
            .iter()
            .copied()
            .filter(|&pc| pc != victim && pc != selected)
            .chain([oracle.return_pc()])
            .map(|pc| (pc, pc))
            .collect();
        boundaries.push((victim, victim_image.address()));
        boundaries.push((selected, target));
        let map = TraceMap {
            boundaries,
            gateways: vec![victim, selected],
            generated_ranges: vec![
                victim_image.address()..victim_image.address() + victim_code.len() as u64,
                target..target + selected_code.len() as u64,
            ],
        };
        Self {
            oracle,
            trace,
            witness,
            map,
            selected,
            victim,
            target,
            _images: vec![victim_image, selected_image],
        }
    }

    fn relay(&self) -> SourceRelay<'_> {
        SourceRelay {
            logical_pc: self.selected,
            relay_pc: self.victim + 5,
            target: self.target,
            victim_trace: &self.witness,
        }
    }

    fn assert_entry(&self, entry: u64) {
        self.oracle.assert_trace_with_relays(
            &self.trace,
            entry,
            &self.map,
            &[self.relay()],
            &[],
            None,
        );
    }

    fn source_write(&self, pc: u64, bytes: &[u8]) {
        write_mapping(
            &self.oracle.code,
            usize::try_from(pc - self.victim).unwrap(),
            bytes,
        );
    }

    fn prefix(&self, bytes: &[u8]) -> Mapping {
        let mapping = Mapping::new(4096);
        let mut code = bytes.to_vec();
        code.extend_from_slice(&exact_e9(
            mapping.address() + code.len() as u64,
            self.selected,
        ));
        write_mapping(&mapping, 0, &code);
        mapping
    }
}

fn write_mapping(mapping: &Mapping, offset: usize, bytes: &[u8]) {
    assert!(offset + bytes.len() <= 4096);
    mapping.protect(libc::PROT_READ | libc::PROT_WRITE);
    // SAFETY: calibration owns this complete private page and all prior children
    // are reaped. This bounded write is intentionally visible to the comparator.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.writable().add(offset), bytes.len())
    };
    mapping.protect(libc::PROT_READ | libc::PROT_EXEC);
}

#[test]
fn independent_native_relay_self_calibration() {
    for seed in SEEDS {
        let fixture = RelayCalibration::new(seed, false);
        fixture.assert_entry(fixture.selected);
    }
}

#[test]
#[should_panic(expected = "unclassified source head")]
fn rejects_unrecorded_internal_source_relay() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    fixture
        .oracle
        .assert_trace(&fixture.trace, fixture.selected, &fixture.map, &[], None);
}

#[test]
#[should_panic(expected = "overlapping relay victim spans")]
fn rejects_duplicate_source_relay_record() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    fixture.oracle.assert_trace_with_relays(
        &fixture.trace,
        fixture.selected,
        &fixture.map,
        &[fixture.relay(), fixture.relay()],
        &[],
        None,
    );
}

#[test]
#[should_panic(expected = "original head overlaps relay victim interior")]
fn rejects_original_head_inside_source_relay() {
    let fixture = RelayCalibration::new(SEEDS[0], true);
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "restored boundary overlaps relay victim span")]
fn rejects_restored_boundary_inside_source_relay() {
    let mut fixture = RelayCalibration::new(SEEDS[0], false);
    fixture
        .map
        .boundaries
        .push((fixture.selected, fixture.victim + 5));
    fixture
        .map
        .generated_ranges
        .push(fixture.victim + 5..fixture.victim + 6);
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "undeclared source gateway")]
fn existing_gateway_rule_still_rejects_internal_source_relay() {
    let mut fixture = RelayCalibration::new(SEEDS[0], false);
    fixture.map.gateways.push(fixture.victim + 5);
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "relay is not the second five-byte victim jump")]
fn rejects_wrong_source_relay_offset() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    let mut relay = fixture.relay();
    relay.relay_pc += 1;
    fixture.oracle.assert_trace_with_relays(
        &fixture.trace,
        fixture.selected,
        &fixture.map,
        &[relay],
        &[],
        None,
    );
}

#[test]
#[should_panic(expected = "foreign relay victim witness")]
fn rejects_foreign_native_victim_witness() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    let foreign = RelayCalibration::new(SEEDS[0], false);
    let mut relay = fixture.relay();
    relay.victim_trace = &foreign.witness;
    fixture.oracle.assert_trace_with_relays(
        &fixture.trace,
        fixture.selected,
        &fixture.map,
        &[relay],
        &[],
        None,
    );
}

#[test]
#[should_panic(expected = "relay victim is not an independently qualified MOVABS")]
fn rejects_nonqualified_native_victim_witness() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    let mut relay = fixture.relay();
    relay.victim_trace = &fixture.trace;
    fixture.oracle.assert_trace_with_relays(
        &fixture.trace,
        fixture.selected,
        &fixture.map,
        &[relay],
        &[],
        None,
    );
}

#[test]
#[should_panic(expected = "selected relay gateway is not exact EB rel8")]
fn rejects_wrong_selected_relay_opcode() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    fixture.source_write(fixture.selected, &[0x90]);
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "selected EB does not reach source relay")]
fn rejects_wrong_selected_relay_target() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    fixture.source_write(fixture.selected + 1, &[0]);
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "source relay E9 target mismatch")]
fn rejects_wrong_relay_e9_target() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    fixture.source_write(
        fixture.victim + 5,
        &exact_e9(fixture.victim + 5, fixture.target + 1),
    );
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "relay target is not one exact image entry")]
fn rejects_relay_target_inside_image_instead_of_entry() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    let mut relay = fixture.relay();
    relay.target += 1;
    fixture.source_write(relay.relay_pc, &exact_e9(relay.relay_pc, relay.target));
    fixture.oracle.assert_trace_with_relays(
        &fixture.trace,
        fixture.selected,
        &fixture.map,
        &[relay],
        &[],
        None,
    );
}

#[test]
#[should_panic(expected = "relay image owns a different logical instruction")]
fn rejects_relay_image_owning_wrong_original_instruction() {
    let mut fixture = RelayCalibration::new(SEEDS[0], false);
    for (_, generated) in &mut fixture.map.boundaries {
        if *generated == fixture.target {
            *generated = fixture._images[0].address() + 1;
        }
    }
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "rax mismatch")]
fn rejects_changed_gpr_at_source_relay() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    let prefix = fixture.prefix(&[0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0]); // MOVABS RAX,0
    fixture.assert_entry(prefix.address());
}

#[test]
#[should_panic(expected = "application data mismatch")]
fn rejects_application_side_effect_at_source_relay() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    let prefix = fixture.prefix(&[0x48, 0x89, 0x07]); // MOV [RDI],RAX
    fixture.assert_entry(prefix.address());
}

#[test]
#[should_panic(expected = "application stack/redzone mismatch")]
fn rejects_redzone_side_effect_at_source_relay() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    let prefix = fixture.prefix(&[0x48, 0x89, 0x44, 0x24, 0x80]); // MOV [RSP-128],RAX
    fixture.assert_entry(prefix.address());
}

#[test]
#[should_panic(expected = "hook event trace mismatch")]
fn rejects_extra_hook_event_before_source_relay() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    // This additional generated prefix runs a callback and a no-op, restores
    // application state, and then enters the valid original EB gateway. Its
    // extra event must be rejected at the relay before the selected callback.
    let prefix_source = Mapping::new(4096);
    let prefix_image = Mapping::new(4096);
    let nop = [0x0f, 0x1f, 0x44, 0, 0];
    let scan = InstructionScanner::default()
        .scan(&nop, prefix_source.address())
        .unwrap();
    let plan = TrampolinePlan::from_actions(
        &scan,
        prefix_source.address(),
        prefix_source.address() + 5,
        &[(prefix_source.address(), observe, false)],
    )
    .unwrap();
    let image = plan.emit_at(prefix_image.address()).unwrap();
    write_mapping(&prefix_image, 0, image.bytes());
    let mut prefix_code = nop.to_vec();
    prefix_code.extend_from_slice(&exact_e9(prefix_source.address() + 5, fixture.selected));
    write_mapping(&prefix_source, 0, &prefix_code);
    let log = HookEventLog::new();
    fixture.oracle.assert_trace_with_relays(
        &fixture.trace,
        prefix_image.address(),
        &fixture.map,
        &[fixture.relay()],
        &[],
        Some(HookExpectation {
            log: &log,
            enabled: &[],
        }),
    );
}

#[test]
#[should_panic(expected = "unexpected source relay")]
fn rejects_unexpected_source_relay_visit() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    fixture.oracle.assert_trace_with_relays(
        &fixture.witness,
        fixture.selected,
        &fixture.map,
        &[fixture.relay()],
        &[],
        None,
    );
}

#[test]
#[should_panic(expected = "missing or duplicate source relay visits")]
fn rejects_missing_required_source_relay_visit() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    fixture.assert_entry(fixture.target);
}

#[test]
#[should_panic(expected = "restored boundary outside declared generated images")]
fn rejects_malformed_relay_image_range() {
    let mut fixture = RelayCalibration::new(SEEDS[0], false);
    fixture.map.generated_ranges[1].end = fixture.target;
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "source relay E9 target mismatch")]
fn rejects_wrong_relay_e9_opcode() {
    let fixture = RelayCalibration::new(SEEDS[0], false);
    fixture.source_write(fixture.victim + 5, &[0x90]);
    fixture.assert_entry(fixture.selected);
}

#[test]
fn refuses_neighbor_relay_just_outside_both_signed_endpoints() {
    let mut refusals = 0;
    for (selected_len, victim_len) in [(2, 10), (3, 12), (4, 15)] {
        for backward in [true, false] {
            let mut puzzle = Puzzle::endpoint(selected_len, victim_len, backward);
            let inserted = if backward {
                puzzle.selected
            } else {
                puzzle.victim
            };
            puzzle.code.insert(inserted, 0x90);
            if backward {
                puzzle.selected += 1;
            } else {
                puzzle.victim += 1;
            }
            puzzle.heads = (0..puzzle.code.len())
                .filter(|&pc| {
                    !(puzzle.selected < pc && pc < puzzle.selected + selected_len)
                        && !(puzzle.victim < pc && pc < puzzle.victim + victim_len)
                })
                .collect();
            let oracle = NativeOracle::new(&puzzle.code);
            let base = oracle.code.address();
            let selected = base + puzzle.selected as u64;
            let victim = base + puzzle.victim as u64;
            let displacement = i128::from(victim) + 5 - i128::from(selected) - 2;
            assert_eq!(displacement, if backward { -129 } else { 128 });
            let source = AddressRange::new(base, puzzle.code.len()).unwrap();
            let identity = CodeIdentity {
                source: SourceIdentity([0xef; 32]),
                mapping: base,
                generation: 1,
            };
            let entries = LegalEntrySet {
                identity,
                scope: source,
                provenance: EntryProvenance::Declared(
                    "T3 one byte outside signed short relay reach".into(),
                ),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: puzzle
                    .heads
                    .iter()
                    .map(|&pc| LegalEntry {
                        address: base + pc as u64,
                        requires_endbr: false,
                    })
                    .collect(),
                resumes: ResumeObligation::NoneExist,
            };
            let selected_allocation = AllocationPolicy::near(selected).unwrap();
            let victim_allocation = AllocationPolicy::near(victim).unwrap();
            let request = InstallRequest {
                identity,
                code: &puzzle.code,
                base_address: base,
                function: source,
                block: AddressRange::new(selected, selected_len).unwrap(),
                logical_pc: selected,
                entries: &entries,
                hook: observe,
                semantics: HookSemantics::Observe,
                allocation: &selected_allocation,
                search: SearchPolicy::default(),
            };
            assert_eq!(
                plan_neighbor(
                    &request,
                    &victim_allocation,
                    NeighborSearch {
                        forced_victim: Some(victim),
                        max_victims: 1,
                        max_pairs: 1,
                    },
                    BundleBudget::default()
                )
                .unwrap_err(),
                Refusal::NoPatchWindow
            );
            oracle.assert_publication(&[]);
            refusals += 1;
        }
    }
    assert_eq!(refusals, 6);
}

// Additional families do not replace any endpoint or its two original seeds.
// Inverting x ^= x<<13; x ^= x>>7; x ^= x<<17 three times gives seeds whose
// third generated GPR (RCX) is 1 or 3. The executable derivation below fixes these
// constants without adding a register override or modifying the oracle seed path.
const LOOP_SEEDS: [u64; 2] = [0x7a53_8844_bea0_3e89, 0xb25a_1f07_667f_a8cf];

fn seeded_rcx(mut seed: u64) -> u64 {
    for _ in 0..3 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
    }
    seed
}

#[test]
fn native_neighbor_loop_seed_derivation_is_reproducible() {
    fn undo(value: u64, distance: u32, left: bool) -> u64 {
        let mut result = value;
        for shift in (distance..64).step_by(distance as usize) {
            result ^= if left { value << shift } else { value >> shift };
        }
        result
    }
    for (count, expected) in [1_u64, 3].into_iter().zip(LOOP_SEEDS) {
        let mut seed = count;
        for _ in 0..3 {
            seed = undo(undo(undo(seed, 17, true), 7, false), 13, true);
        }
        assert_eq!(seed, expected);
        assert_eq!(seeded_rcx(seed), count);
    }
    assert_eq!(
        SEEDS.map(seeded_rcx).map(|value| value as u32),
        [0xfa97_ac78, 0x6f65_9161]
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Family {
    SelectedLoop,
    VictimLoop,
    Jnz,
    RipLoad,
    MoffsFault,
}

struct FamilyPuzzle {
    kind: Family,
    code: Vec<u8>,
    function_len: usize,
    heads: Vec<usize>,
    selected: usize,
    victim: usize,
    victim_len: usize,
    expected_heads: usize,
    expected_events: usize,
    case_index: usize,
}

impl FamilyPuzzle {
    fn new(kind: Family, victim_len: usize, case_index: usize, moffs: u64) -> Self {
        let (selected, victim) = if kind == Family::VictimLoop {
            (32, 0)
        } else {
            (0, 32)
        };
        let function_len =
            (selected + 3).max(victim + victim_len + if kind == Family::RipLoad { 4 } else { 1 });
        let mut code = vec![
            0x90;
            if kind == Family::RipLoad {
                136
            } else {
                function_len
            }
        ];
        code[selected..selected + 2].copy_from_slice(match kind {
            Family::SelectedLoop => &[0xe2, 0xfe],
            Family::Jnz => &[0xd1, 0xe9], // SHR ECX,1
            Family::VictimLoop | Family::RipLoad => &[0x89, 0xc0],
            Family::MoffsFault => &[0xff, 0xc0],
        });
        code[selected + 2] = 0xc3;
        let prefixes = victim_len
            - match kind {
                Family::SelectedLoop | Family::MoffsFault => 10,
                Family::VictimLoop => 2,
                Family::Jnz => 6,
                Family::RipLoad => 7,
            };
        code[victim..victim + prefixes].fill(0x2e);
        let opcode = victim + prefixes;
        match kind {
            Family::SelectedLoop => {
                code[opcode..opcode + 2].copy_from_slice(&[0x48, 0xb8]);
                code[opcode + 2..victim + victim_len]
                    .copy_from_slice(&0x1739_5b7d_9ebc_daf0_u64.to_le_bytes());
            }
            Family::VictimLoop => {
                code[opcode..victim + victim_len]
                    .copy_from_slice(&[0xe2, (-(victim_len as i8)) as u8]);
                assert_eq!(
                    victim as i64 + victim_len as i64 + i64::from(code[opcode + 1] as i8),
                    victim as i64
                );
            }
            Family::Jnz => {
                // Original EB at 2 reaches V; the victim branches back to S
                // until SHR has zeroed ECX. AF is undefined for SHR: retain the
                // existing stricter native full-flags comparison without a mask.
                code[2..4].copy_from_slice(&[0xeb, 28]);
                code[opcode..opcode + 2].copy_from_slice(&[0x0f, 0x85]);
                let displacement = selected as i32 - (victim + victim_len) as i32;
                code[opcode + 2..victim + victim_len].copy_from_slice(&displacement.to_le_bytes());
                assert_eq!(
                    (victim + victim_len) as i64 + i64::from(displacement),
                    selected as i64
                );
                assert_eq!(2 + 2 + usize::from(code[3]), victim);
            }
            Family::RipLoad => {
                code[opcode..opcode + 3].copy_from_slice(&[0x48, 0x8b, 0x0d]);
                let displacement = 128_i32 - (victim + victim_len) as i32;
                code[opcode + 3..victim + victim_len].copy_from_slice(&displacement.to_le_bytes());
                assert_eq!((victim + victim_len) as i64 + i64::from(displacement), 128);
                code[victim + victim_len..victim + victim_len + 3]
                    .copy_from_slice(&[0x48, 0x89, 0x0f]);
                code[128..136].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
                assert!(
                    function_len < 128,
                    "read-only data stays outside scanner input/function"
                );
            }
            Family::MoffsFault => {
                code[opcode..opcode + 2].copy_from_slice(&[0x48, 0xa1]);
                code[opcode + 2..victim + victim_len].copy_from_slice(&moffs.to_le_bytes());
                assert_eq!(
                    u64::from_le_bytes(code[opcode + 2..victim + victim_len].try_into().unwrap()),
                    moffs
                );
            }
        }
        let victim_ret = victim + victim_len + if kind == Family::RipLoad { 3 } else { 0 };
        code[victim_ret] = 0xc3;
        let heads: Vec<_> = (0..function_len)
            .filter(|&pc| {
                !(selected < pc && pc < selected + 2)
                    && !(victim < pc && pc < victim + victim_len)
                    && !(kind == Family::Jnz && pc == 3)
                    && !(kind == Family::RipLoad && victim + victim_len < pc && pc < victim_ret)
            })
            .collect();
        let (expected_heads, expected_events) = match kind {
            Family::SelectedLoop => (33, 4),
            Family::VictimLoop => {
                if victim_len == 10 {
                    (25, 44)
                } else {
                    (20, 34)
                }
            }
            Family::Jnz => (32, 63),
            Family::RipLoad => (34, 2),
            Family::MoffsFault => (33, 2),
        };
        assert_eq!(heads.len(), expected_heads);
        Self {
            kind,
            code,
            function_len,
            heads,
            selected,
            victim,
            victim_len,
            expected_heads,
            expected_events,
            case_index,
        }
    }

    fn seeds(&self) -> [u64; 2] {
        if matches!(self.kind, Family::SelectedLoop | Family::VictimLoop) {
            LOOP_SEEDS
        } else {
            SEEDS
        }
    }

    /// Handwritten ISA transitions. These visit obligations are independent of
    /// both production decoding and the patched execution's path.
    fn visits(&self, entry: usize, seed: u64, fault: bool) -> Vec<usize> {
        let mut visits = Vec::new();
        let mut pc = entry;
        let mut rcx = seeded_rcx(seed);
        let mut zero = true; // unchanged seed flags 0xad7 set ZF
        loop {
            assert!(
                visits.len() < 256,
                "fixture visit derivation did not terminate"
            );
            assert!(self.heads.contains(&pc));
            visits.push(pc);
            if pc == self.selected {
                if self.kind == Family::SelectedLoop {
                    rcx -= 1;
                    if rcx == 0 {
                        pc += 2;
                    }
                } else {
                    if self.kind == Family::Jnz {
                        rcx = u64::from((rcx as u32) >> 1);
                        zero = rcx == 0;
                    }
                    pc += 2;
                }
            } else if pc == self.victim {
                match self.kind {
                    Family::VictimLoop => {
                        rcx -= 1;
                        if rcx == 0 {
                            pc += self.victim_len;
                        }
                    }
                    Family::Jnz if !zero => pc = self.selected,
                    Family::MoffsFault if fault => return visits,
                    _ => pc += self.victim_len,
                }
            } else if self.kind == Family::Jnz && pc == 2 {
                pc = self.victim;
            } else if self.kind == Family::RipLoad && pc == self.victim + self.victim_len {
                pc += 3;
            } else if self.code[pc] == 0xc3 {
                return visits;
            } else {
                assert_eq!(self.code[pc], 0x90);
                pc += 1;
            }
        }
    }
}

#[test]
fn native_neighbor_selected_loop_all_33_heads() {
    run_family(Family::SelectedLoop, 10, 0);
}
#[test]
fn native_neighbor_victim_loop_m10_all_25_heads() {
    run_family(Family::VictimLoop, 10, 1);
}
#[test]
fn native_neighbor_victim_loop_m15_all_20_heads() {
    run_family(Family::VictimLoop, 15, 2);
}
#[test]
fn native_neighbor_jnz_m10_all_32_heads() {
    run_family(Family::Jnz, 10, 3);
}
#[test]
fn native_neighbor_jnz_m15_all_32_heads() {
    run_family(Family::Jnz, 15, 4);
}
#[test]
fn native_neighbor_rip_load_m10_all_34_heads() {
    run_family(Family::RipLoad, 10, 5);
}
#[test]
fn native_neighbor_rip_load_m15_all_34_heads() {
    run_family(Family::RipLoad, 15, 6);
}
#[test]
fn native_neighbor_moffs_fault_m10_all_33_heads() {
    run_family(Family::MoffsFault, 10, 7);
}
#[test]
fn native_neighbor_moffs_fault_m15_all_33_heads() {
    run_family(Family::MoffsFault, 15, 8);
}

fn run_family(kind: Family, victim_len: usize, case_index: usize) {
    let fault_page = Mapping::new(4096);
    let puzzle = FamilyPuzzle::new(kind, victim_len, case_index, fault_page.address());
    let mut oracle = NativeOracle::new(&puzzle.code);
    let base = oracle.code.address();
    let selected = base + puzzle.selected as u64;
    let victim = base + puzzle.victim as u64;
    let relay = victim + 5;
    let rel8 = i8::try_from(i128::from(relay) - i128::from(selected) - 2).unwrap();
    let heads: Vec<_> = puzzle.heads.iter().map(|&pc| base + pc as u64).collect();
    let source = AddressRange::new(base, puzzle.function_len).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0xa0 + puzzle.case_index as u8; 32]),
        mapping: base,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared(format!(
            "T3 {kind:?} M{victim_len} all original heads"
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
    // Each additional case has distinct remote ranges. Source owners are also
    // pinned after retirement, preventing address reuse with retained images.
    let selected_target = base + 0x2000_0180 + case_index as u64 * 0x0100_0000;
    let victim_target = base + 0x4000_0280 + case_index as u64 * 0x0100_0000;
    let mut selected_allocation = AllocationPolicy::near(selected).unwrap();
    selected_allocation.ranges = vec![AddressRange::new(selected_target & !4095, 8192).unwrap()];
    selected_allocation.preferred_address = Some(selected_target);
    let mut victim_allocation = AllocationPolicy::near(victim).unwrap();
    victim_allocation.ranges = vec![AddressRange::new(victim_target & !4095, 8192).unwrap()];
    victim_allocation.preferred_address = Some(victim_target);
    let request = InstallRequest {
        identity,
        code: &puzzle.code[..puzzle.function_len],
        base_address: base,
        function: source,
        block: AddressRange::new(selected, 2).unwrap(),
        logical_pc: selected,
        entries: &entries,
        hook: observe,
        semantics: HookSemantics::Observe,
        allocation: &selected_allocation,
        search: SearchPolicy {
            max_upstream_bytes: 0,
            max_sites: 1,
            ..SearchPolicy::default()
        },
    };
    let planned = plan_neighbor(
        &request,
        &victim_allocation,
        NeighborSearch {
            forced_victim: Some(victim),
            max_victims: 1,
            max_pairs: 1,
        },
        BundleBudget::default(),
    )
    .unwrap_or_else(|error| panic!("required T3 {kind:?}/M{victim_len} refused: {error:?}"));
    let geometry = planned.geometry();
    assert_eq!((geometry.selected, geometry.selected_len), (selected, 2));
    assert_eq!((geometry.victim, geometry.victim_len), (victim, victim_len));
    assert_eq!((geometry.relay, geometry.rel8), (relay, rel8));
    assert_eq!(
        (geometry.selected_target, geometry.victim_target),
        (selected_target, victim_target)
    );
    assert_eq!(
        (
            planned.metrics().victims_examined,
            planned.metrics().pairs_examined
        ),
        (1, 1)
    );
    assert_eq!(
        (
            planned.metrics().selected_fallthrough_redirects,
            planned.metrics().victim_fallthrough_redirects
        ),
        (3, 2)
    );
    let bundle = planned.bundle();
    let steps = bundle.plan().steps();
    assert_eq!(steps.len(), 2);
    assert_eq!(bundle.images().len(), 2);
    assert!(steps[0].parts().physical_pc > steps[1].parts().physical_pc);
    let mut victim_bytes = exact_e9(victim, victim_target).to_vec();
    victim_bytes.extend_from_slice(&exact_e9(relay, selected_target));
    let edits = vec![(selected, vec![0xeb, rel8 as u8]), (victim, victim_bytes)];
    for (pc, len) in [(selected, 2), (victim, victim_len)] {
        let step = steps
            .iter()
            .find(|step| step.parts().physical_pc == pc)
            .unwrap()
            .parts();
        assert!(matches!(step.kind, PlanKind::Relocation));
        assert_eq!(step.displaced, AddressRange::new(pc, len).unwrap());
        assert_eq!(step.writes.len(), 1);
        assert_eq!(step.writes[0].address, pc);
        assert_eq!(
            step.writes[0].bytes,
            edits.iter().find(|(address, _)| *address == pc).unwrap().1
        );
        assert!(!step.requirements.sigill_router);
        assert!(
            step.obligations
                .iter()
                .all(|entry| matches!(entry, EntryObligation::Preserved(_)))
        );
    }
    let mut map = TraceMap {
        boundaries: heads
            .iter()
            .copied()
            .filter(|&pc| pc != selected && pc != victim)
            .chain([oracle.return_pc()])
            .map(|pc| (pc, pc))
            .collect(),
        gateways: vec![selected, victim],
        ..TraceMap::default()
    };
    for image in bundle.images() {
        let logical = if image.address() == selected_target {
            selected
        } else {
            assert_eq!(image.address(), victim_target);
            victim
        };
        assert_eq!(image.instruction_boundaries().len(), 1);
        assert_eq!(image.instruction_boundaries()[0].0, logical);
        map.boundaries
            .extend_from_slice(image.instruction_boundaries());
        map.generated_ranges
            .push(image.address()..image.address() + image.bytes().len() as u64);
    }
    // For MOFFS, this native single-step witness reads the very same mapped
    // address later made PROT_NONE. The operand/source snapshot never changes.
    let witness = oracle.trace_original(victim, &heads, &[oracle.return_pc()], puzzle.seeds()[0]);
    let expected_witness: Vec<_> = puzzle
        .visits(puzzle.victim, puzzle.seeds()[0], false)
        .into_iter()
        .map(|pc| base + pc as u64)
        .chain([oracle.return_pc()])
        .collect();
    assert_eq!(witness.visits(), expected_witness);
    assert_eq!(witness.visits()[1], victim + victim_len as u64);
    if kind == Family::MoffsFault {
        fault_page.protect(libc::PROT_NONE);
    }
    let mut originals = Vec::new();
    let mut faults = Vec::new();
    let mut event_count = 0;
    let mut direct_victims = 0;
    for seed in puzzle.seeds() {
        for (&entry, &offset) in heads.iter().zip(&puzzle.heads) {
            let visits: Vec<_> = puzzle
                .visits(offset, seed, true)
                .into_iter()
                .map(|pc| base + pc as u64)
                .collect();
            if kind == Family::MoffsFault && visits.last() == Some(&victim) {
                assert!(!visits.contains(&selected));
                // Linux SEGV_ACCERR = 2: the controlled target remains mapped.
                let baseline =
                    oracle.original_fault(&visits, seed, (libc::SIGSEGV, 2, fault_page.address()));
                faults.push((entry, baseline));
            } else {
                let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
                let expected: Vec<_> = visits.into_iter().chain([oracle.return_pc()]).collect();
                assert_eq!(trace.visits(), expected);
                let hooks = trace.visits().iter().filter(|&&pc| pc == selected).count();
                event_count += hooks;
                if entry == victim {
                    assert_eq!(
                        hooks, 0,
                        "independent victim entry must not execute selected hook"
                    );
                    if kind == Family::VictimLoop {
                        assert_eq!(
                            trace.visits().iter().filter(|&&pc| pc == victim).count(),
                            seeded_rcx(seed) as usize
                        );
                    }
                }
                if entry == selected && kind == Family::SelectedLoop {
                    assert_eq!(hooks, seeded_rcx(seed) as usize);
                }
                originals.push((entry, trace));
            }
            if entry == victim {
                direct_victims += 1;
            }
        }
    }
    assert_eq!(direct_victims, 2);
    assert_eq!(event_count, puzzle.expected_events);
    assert_eq!(originals.len() + faults.len(), puzzle.expected_heads * 2);
    assert_eq!(
        faults.len(),
        if kind == Family::MoffsFault { 60 } else { 0 }
    );
    let writable = oracle.code.writable();
    // SAFETY: this private source stays alive through complete retirement.
    let aliases = [unsafe { WritableAlias::new(source, writable) }.unwrap()];
    let mut installed = {
        // SAFETY: all original/witness children have been reaped.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![source]) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: source exclusion spans stores, RX restoration and sync.
        let (installed, receipt) = unsafe {
            bundle.publish_with(&aliases, &mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required family publication failed");
        assert_eq!(receipt.plan().steps(), steps);
        assert!(!lease.is_poisoned());
        installed
    };
    oracle.assert_publication(&edits);
    let relays = [SourceRelay {
        logical_pc: selected,
        relay_pc: relay,
        target: selected_target,
        victim_trace: &witness,
    }];
    let log = HookEventLog::new();
    let enabled = [HookEvent {
        probe_id: PROBE_ID,
        logical_pc: selected,
    }];
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
    }
    let boundaries: Vec<_> = bundle
        .images()
        .iter()
        .flat_map(|image| image.instruction_boundaries().iter().copied())
        .collect();
    for (entry, original) in &faults {
        // No selected hook is expected on these paths. Without an active private
        // event log, any unexpected callback exits the child and fails the oracle.
        oracle.assert_patched(original, *entry, &boundaries, &[]);
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
        // SAFETY: every patched child is reaped; both generated lifetimes drain.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
        permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: held exclusion includes source/generated continuations.
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required family retirement failed");
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
    for (entry, original) in &faults {
        oracle.assert_patched(original, *entry, &[], &[]);
    }
    let _pinned_source = Box::leak(Box::new(oracle));
    eprintln!(
        "native T3 {kind:?} M{victim_len}: {} original heads, {} installed + {} retired full-state/event comparisons ({} faults per phase), {event_count} exact installed hook events; zero mismatches",
        puzzle.expected_heads,
        originals.len() + faults.len(),
        originals.len() + faults.len(),
        faults.len()
    );
}

// A second independently encoded scaffold qualifies the new literal grammars.
// Its source and images are manual bytes, without invoking any library planner.
fn literal_victim_calibration(victim_bytes: &[u8; 10], seed: u64) -> RelayCalibration {
    let mut code = vec![0x90; 35];
    code[..10].copy_from_slice(victim_bytes);
    code[10] = 0xc3;
    code[32..35].copy_from_slice(&[0x66, 0x90, 0xc3]);
    let oracle = NativeOracle::new(&code);
    let victim = oracle.code.address();
    let selected = victim + 32;
    let heads: Vec<_> = (0..35)
        .filter(|&pc| !(1..10).contains(&pc) && pc != 33)
        .map(|pc| victim + pc)
        .collect();
    let trace = oracle.trace_original(selected, &heads, &[oracle.return_pc()], seed);
    let witness = oracle.trace_original(victim, &heads, &[oracle.return_pc()], seed);
    assert_eq!(trace.visits(), [selected, selected + 2, oracle.return_pc()]);
    let victim_image = Mapping::new(4096);
    let selected_image = Mapping::new(4096);
    let target = selected_image.address();
    let mut victim_code = victim_bytes.to_vec();
    victim_code.extend_from_slice(&exact_e9(victim_image.address() + 10, victim + 10));
    write_mapping(&victim_image, 0, &victim_code);
    let mut selected_code = vec![0x66, 0x90];
    selected_code.extend_from_slice(&exact_e9(target + 2, selected + 2));
    write_mapping(&selected_image, 0, &selected_code);
    let mut redirect = exact_e9(victim, victim_image.address()).to_vec();
    redirect.extend_from_slice(&exact_e9(victim + 5, target));
    write_mapping(&oracle.code, 0, &redirect);
    write_mapping(&oracle.code, 32, &[0xeb, (-29_i8) as u8]);
    oracle.assert_publication(&[(victim, redirect), (selected, vec![0xeb, (-29_i8) as u8])]);
    let mut boundaries: Vec<_> = heads
        .iter()
        .copied()
        .filter(|&pc| pc != victim && pc != selected)
        .chain([oracle.return_pc()])
        .map(|pc| (pc, pc))
        .collect();
    boundaries.push((victim, victim_image.address()));
    boundaries.push((selected, target));
    let map = TraceMap {
        boundaries,
        gateways: vec![victim, selected],
        generated_ranges: vec![
            victim_image.address()..victim_image.address() + victim_code.len() as u64,
            target..target + selected_code.len() as u64,
        ],
    };
    RelayCalibration {
        oracle,
        trace,
        witness,
        map,
        selected,
        victim,
        target,
        _images: vec![victim_image, selected_image],
    }
}

#[test]
fn independent_native_self_loop_relay_calibration() {
    let fixture = literal_victim_calibration(
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0xe2, 0xf6],
        LOOP_SEEDS[0],
    );
    assert_eq!(
        fixture.witness.visits(),
        [
            fixture.victim,
            fixture.victim + 10,
            fixture.oracle.return_pc()
        ]
    );
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "LOOP relay witness must start with RCX one")]
fn rejects_loop_witness_with_three_native_visits() {
    let fixture = literal_victim_calibration(
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0xe2, 0xf6],
        LOOP_SEEDS[1],
    );
    assert_eq!(
        fixture.witness.visits(),
        [
            fixture.victim,
            fixture.victim,
            fixture.victim,
            fixture.victim + 10,
            fixture.oracle.return_pc()
        ]
    );
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "LOOP relay witness must target its own original head")]
fn rejects_loop_lookalike_whose_target_coincides_with_native_fallthrough() {
    let fixture = literal_victim_calibration(
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0xe2, 0],
        LOOP_SEEDS[0],
    );
    assert_eq!(
        fixture.witness.visits(),
        [
            fixture.victim,
            fixture.victim + 10,
            fixture.oracle.return_pc()
        ]
    );
    fixture.assert_entry(fixture.selected);
}

#[test]
#[should_panic(expected = "relay victim is not an independently qualified MOVABS")]
fn rejects_jz_lookalike_whose_target_coincides_with_native_fallthrough() {
    let fixture =
        literal_victim_calibration(&[0x2e, 0x2e, 0x2e, 0x2e, 0x0f, 0x84, 0, 0, 0, 0], SEEDS[0]);
    assert_eq!(
        fixture.witness.visits(),
        [
            fixture.victim,
            fixture.victim + 10,
            fixture.oracle.return_pc()
        ]
    );
    fixture.assert_entry(fixture.selected);
}
