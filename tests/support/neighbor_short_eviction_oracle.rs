//! Separate same-function short-victim cohort. All mappings are required;
//! allocation refusal is a failure, never a skip or a retried layout.
use super::*;
use liteinst2::neighbor::plan_neighbor_short;
use oracle::ShortSourceRelay;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Mutex, MutexGuard};

// The suffix-derived exact image pages can overlap between these fixtures even
// when their anonymous source pages differ. Hold this cohort-local lock from
// before source allocation until all children and generated mappings are gone.
// Other tests in this crate and other workspace crates remain parallel.
static EXACT_ADDRESS_WINDOW: Mutex<()> = Mutex::new(());

fn exact_address_window() -> MutexGuard<'static, ()> {
    EXACT_ADDRESS_WINDOW
        .lock()
        .expect("short-neighbor exact-address window poisoned")
}

const ENDPOINTS: [(usize, usize, bool, usize); 8] = [
    (2, 6, true, 128),
    (2, 6, false, 129),
    (3, 7, true, 127),
    (3, 7, false, 128),
    (4, 8, true, 126),
    (4, 8, false, 127),
    (2, 9, true, 125),
    (2, 9, false, 129),
];
static STARTED: AtomicUsize = AtomicUsize::new(0);
static COMPLETED: AtomicUsize = AtomicUsize::new(0);
static HEADS: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: AtomicUsize = AtomicUsize::new(0);
static RETIRED: AtomicUsize = AtomicUsize::new(0);

struct ShortPuzzle {
    code: Vec<u8>,
    function_len: usize,
    heads: Vec<usize>,
    selected: usize,
    selected_len: usize,
    victim: usize,
    victim_len: usize,
    conditional: bool,
}
impl ShortPuzzle {
    fn endpoint(index: usize) -> Self {
        let (selected_len, victim_len, backward, count) = ENDPOINTS[index];
        let (selected, victim) = if backward { (131, 0) } else { (0, 124) };
        let selected_bytes: &[u8] = match selected_len {
            2 => &[0xff, 0xc0],
            3 => &[0x48, 0xff, 0xc0],
            4 => &[0x48, 0x83, 0xc0, 1],
            _ => unreachable!(),
        };
        let mut code = vec![0x90; (selected + selected_len + 1).max(victim + victim_len + 5)];
        code[selected..selected + selected_len].copy_from_slice(selected_bytes);
        code[selected + selected_len] = 0xc3;
        code[victim..victim + victim_len - 5].fill(0x2e);
        code[victim + victim_len - 5] = 0xb8;
        code[victim + victim_len - 4..victim + victim_len]
            .copy_from_slice(&0x9ebc_daf0_u32.to_le_bytes());
        code[victim + victim_len + 4] = 0xc3;
        let result = Self::new(
            code,
            selected,
            selected_len,
            victim,
            victim_len,
            false,
            None,
        );
        assert_eq!(result.heads.len(), count);
        result
    }
    fn new(
        code: Vec<u8>,
        selected: usize,
        selected_len: usize,
        victim: usize,
        victim_len: usize,
        conditional: bool,
        function_len: Option<usize>,
    ) -> Self {
        let function_len = function_len.unwrap_or(code.len());
        let heads = (0..function_len)
            .filter(|&pc| {
                !(selected < pc && pc < selected + selected_len)
                    && !(victim < pc && pc < victim + victim_len)
                    && !(conditional && pc == 4)
            })
            .collect();
        Self {
            code,
            function_len,
            heads,
            selected,
            selected_len,
            victim,
            victim_len,
            conditional,
        }
    }
    fn overlap() -> Self {
        let code = vec![
            0x2e, 0xb8, 0xf0, 0xda, 0xbc, 0x9e, 0xff, 0xc0, 0xc3, 0x90, 0xc3,
        ];
        Self::new(code, 6, 2, 0, 6, false, None)
    }
    fn rip() -> Self {
        let mut code = vec![0x90; 136];
        code[..3].copy_from_slice(&[0x89, 0xc0, 0xc3]);
        code[32..35].copy_from_slice(&[0x48, 0x8b, 0x0d]);
        code[35..39].copy_from_slice(&89_i32.to_le_bytes()); // next39 +89 =128
        code[43] = 0xc3;
        code[128..136].copy_from_slice(&0xf1e2_d3c4_b5a6_9788_u64.to_le_bytes());
        Self::new(code, 0, 2, 32, 7, false, Some(44))
    }
    fn conditional() -> Self {
        let mut code = vec![0x90; 49];
        code[..5].copy_from_slice(&[0x83, 0xf8, 0, 0xeb, 0x1b]);
        code[32..38].copy_from_slice(&[0x0f, 0x85, 10, 0, 0, 0]);
        code[42] = 0xc3;
        code[48] = 0xc3;
        Self::new(code, 0, 3, 32, 6, true, None)
    }
    fn visits(&self, mut pc: usize, base: u64, terminal: u64) -> Vec<u64> {
        let mut zero = true; // The unchanged ordinary oracle starts with ZF set.
        let mut visits = Vec::new();
        for _ in 0..=self.heads.len() {
            assert!(self.heads.contains(&pc));
            visits.push(base + pc as u64);
            if self.code[pc] == 0xc3 {
                visits.push(terminal);
                return visits;
            }
            pc = if self.conditional && pc == 0 {
                zero = false;
                3
            } else if self.conditional && pc == 3 {
                32
            } else if self.conditional && pc == 32 {
                if zero { 38 } else { 48 }
            } else if pc == self.selected {
                pc + self.selected_len
            } else if pc == self.victim {
                pc + self.victim_len
            } else {
                pc + 1
            };
        }
        panic!("authored short trace did not terminate");
    }
}

// This independently derives the exact zero-low-byte target from source bytes
// after the selected EB. No planner witness or decoded instruction is accepted.
fn suffix_target(code: &[u8], base: u64, selected: usize, victim: usize, len: usize) -> u64 {
    assert!((6..=9).contains(&len));
    let relay = base
        .checked_add(victim as u64)
        .unwrap()
        .checked_add(5)
        .unwrap();
    let next = base
        .checked_add(selected as u64)
        .unwrap()
        .checked_add(2)
        .unwrap();
    let rel8 = i8::try_from(i128::from(relay) - i128::from(next)).unwrap();
    let mut overlay = code.to_vec();
    overlay[selected..selected + 2].copy_from_slice(&[0xeb, rel8 as u8]);
    let mut displacement = [0_u8; 4];
    displacement[len - 6..].copy_from_slice(&overlay[victim + len..victim + 10]);
    u64::try_from(
        i128::from(base) + victim as i128 + 10 + i128::from(i32::from_le_bytes(displacement)),
    )
    .unwrap()
}

#[test]
fn short_endpoint_census() {
    assert_eq!(ENDPOINTS.len(), 8);
    assert_eq!(ENDPOINTS.iter().map(|row| row.3).sum::<usize>(), 1019);
    for index in 0..8 {
        let p = ShortPuzzle::endpoint(index);
        let rel8 = p.victim as isize + 5 - p.selected as isize - 2;
        assert_eq!(rel8, if ENDPOINTS[index].2 { -128 } else { 127 });
        assert_eq!(
            p.code.len(),
            [134, 135, 135, 136, 136, 137, 134, 138][index]
        );
    }
    assert_eq!(ShortPuzzle::overlap().heads, [0, 6, 8, 9, 10]);
    assert_eq!(ShortPuzzle::rip().heads.len(), 37);
    assert_eq!(ShortPuzzle::conditional().heads.len(), 41);
    assert_eq!(1019 + 5 + 37 + 41, 1102);
    assert_eq!(1102 * SEEDS.len(), 2204);
}
#[test]
fn short_endpoint_back_l6() {
    run(0, ShortPuzzle::endpoint(0), 128);
}
#[test]
fn short_endpoint_forward_l6() {
    run(1, ShortPuzzle::endpoint(1), 129);
}
#[test]
fn short_endpoint_back_l7() {
    run(2, ShortPuzzle::endpoint(2), 127);
}
#[test]
fn short_endpoint_forward_l7() {
    run(3, ShortPuzzle::endpoint(3), 128);
}
#[test]
fn short_endpoint_back_l8() {
    run(4, ShortPuzzle::endpoint(4), 126);
}
#[test]
fn short_endpoint_forward_l8() {
    run(5, ShortPuzzle::endpoint(5), 127);
}
#[test]
fn short_endpoint_back_l9() {
    run(6, ShortPuzzle::endpoint(6), 125);
}
#[test]
fn short_endpoint_forward_l9() {
    run(7, ShortPuzzle::endpoint(7), 129);
}
#[test]
fn short_selected_suffix_overlap() {
    run(8, ShortPuzzle::overlap(), 5);
}
#[test]
fn short_rip_read_effect() {
    run(9, ShortPuzzle::rip(), 37);
}
#[test]
fn short_conditional_fallthrough_and_taken() {
    run(10, ShortPuzzle::conditional(), 41);
}

fn run(layout_index: usize, puzzle: ShortPuzzle, expected_heads: usize) {
    let _address_window = exact_address_window();
    let bit = 1 << layout_index;
    assert_eq!(
        STARTED.fetch_or(bit, SeqCst) & bit,
        0,
        "endpoint layout ran twice"
    );
    let selected_len = puzzle.selected_len;
    let victim_len = puzzle.victim_len;
    let mut head_count = 0;
    let mut installed_count = 0;
    let mut retired_count = 0;
    let mut direct_victim_count = 0;
    assert_eq!(puzzle.heads.len(), expected_heads);
    head_count += puzzle.heads.len();
    let mut oracle = NativeOracle::new(&puzzle.code);
    let base = oracle.code.address();
    let selected = base + puzzle.selected as u64;
    let victim = base + puzzle.victim as u64;
    let relay = victim + 5;
    let rel8 = i8::try_from(i128::from(relay) - i128::from(selected) - 2).unwrap();
    let heads: Vec<_> = puzzle.heads.iter().map(|&pc| base + pc as u64).collect();
    let source = AddressRange::new(base, puzzle.function_len).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0xc0 + layout_index as u8; 32]),
        mapping: base,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared("short T3 all original authored heads".into()),
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
    let selected_target = suffix_target(
        &puzzle.code,
        base,
        puzzle.selected,
        puzzle.victim,
        victim_len,
    );
    let victim_target = base + 0x1800_0280;
    let mut selected_allocation = AllocationPolicy::near(selected).unwrap();
    selected_allocation.ranges = vec![AddressRange::new(selected_target & !4095, 8192).unwrap()];
    selected_allocation.preferred_address = Some(selected_target);
    selected_allocation.max_candidates = 1;
    let mut victim_allocation = AllocationPolicy::near(victim).unwrap();
    victim_allocation.ranges = vec![AddressRange::new(victim_target & !4095, 8192).unwrap()];
    victim_allocation.preferred_address = Some(victim_target);
    victim_allocation.max_candidates = 1;
    let request = InstallRequest {
        identity,
        code: &puzzle.code[..puzzle.function_len],
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
    let planned = plan_neighbor_short(
        &request,
        &victim_allocation,
        NeighborSearch {
            forced_victim: Some(victim),
            max_victims: 1,
            max_pairs: 1,
        },
        BundleBudget::default(),
    )
    .unwrap_or_else(|error| {
        panic!(
            "required short layout{layout_index} L{selected_len}/M{victim_len} refused: {error:?}"
        )
    });
    let geometry = planned.geometry();
    assert_eq!(geometry.selected, selected);
    assert_eq!(geometry.selected_len, selected_len);
    assert_eq!(geometry.victim, victim);
    assert_eq!(geometry.victim_len, victim_len);
    assert_eq!(geometry.relay, relay);
    assert_eq!(geometry.rel8, rel8);
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
    assert_eq!(selected_step.parts().writes[0].bytes, [0xeb, rel8 as u8]);
    let mut victim_bytes = exact_e9(victim, victim_target).to_vec();
    victim_bytes.extend_from_slice(&exact_e9(relay, selected_target));
    if layout_index == 8 {
        assert_eq!(&puzzle.code[6..10], &[0xff, 0xc0, 0xc3, 0x90]);
        assert_eq!(&victim_bytes[6..10], &[0xeb, 0xfd, 0xc3, 0x90]);
    }
    assert_eq!(victim_step.parts().writes.len(), 1);
    assert_eq!(victim_step.parts().writes[0].address, victim);
    assert_eq!(victim_step.parts().writes[0].bytes, victim_bytes);
    let edits = vec![(selected, vec![0xeb, rel8 as u8]), (victim, victim_bytes)];
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
                puzzle.visits(offset, base, oracle.return_pc())
            );
            originals.push((entry, trace));
        }
    }
    let witness = &originals
        .iter()
        .find(|(entry, _)| *entry == victim)
        .unwrap()
        .1;
    assert_eq!(witness.visits()[1], victim + victim_len as u64);
    if puzzle.conditional {
        for (_, trace) in originals.iter().filter(|(entry, _)| *entry == selected) {
            assert!(trace.visits().contains(&(base + 48)));
            assert!(!trace.visits().contains(&(base + 38)));
        }
    }
    let relay_records = [ShortSourceRelay {
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
            assert_eq!(trace.visits().contains(&selected), layout_index == 8);
            direct_victim_count += 1;
        }
        oracle.assert_trace_with_short_relays(
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
    // Exactly eleven source owners remain pinned through process exit, as in
    // the legacy cohort; there is no outcome-dependent mapping cache or retry.
    let _pinned_source = Box::leak(Box::new(oracle));
    HEADS.fetch_add(head_count, SeqCst);
    INSTALLED.fetch_add(installed_count, SeqCst);
    RETIRED.fetch_add(retired_count, SeqCst);
    let completed = COMPLETED.fetch_or(bit, SeqCst) | bit;
    if completed == (1 << 11) - 1 {
        assert_eq!(HEADS.load(SeqCst), 1102);
        assert_eq!(INSTALLED.load(SeqCst), 2204);
        assert_eq!(RETIRED.load(SeqCst), 2204);
    }
}

// This scaffold is hand-emitted independently of the short planner/decoder.
// The fixed suffix dictates one exact target and one exact mapping attempt.
struct Calibration {
    oracle: NativeOracle,
    trace: NativeTrace,
    witness: NativeTrace,
    map: TraceMap,
    selected: u64,
    victim: u64,
    target: u64,
    images: Vec<Mapping>,
    selected_page: Mapping,
}
impl Calibration {
    fn new(seed: u64) -> Self {
        Self::with(
            seed,
            &[0x2e, 0xb8, 0xf0, 0xda, 0xbc, 0x9e],
            false,
            false,
            false,
        )
    }
    fn rip(seed: u64) -> Self {
        Self::with(seed, &[0x48, 0x8b, 0x0d, 121, 0, 0, 0], false, false, false)
    }
    fn with(
        seed: u64,
        victim_code: &[u8],
        overlap: bool,
        extra_head: bool,
        seeded_flags: bool,
    ) -> Self {
        let len = victim_code.len();
        assert!((6..=9).contains(&len));
        assert!(!overlap || len == 6);
        let rip = victim_code.starts_with(&[0x48, 0x8b, 0x0d]);
        let selected = if overlap { 6 } else { 32 };
        let mut code = vec![0x90; selected + 3];
        code[..len].copy_from_slice(victim_code);
        code[10.min(selected + 2)] = 0xc3;
        code[selected..selected + 3].copy_from_slice(&[0x66, 0x90, 0xc3]);
        // The overlap case has a legal NOP and terminal after the selected RET.
        if overlap {
            code.extend_from_slice(&[0x90, 0xc3]);
        }
        let function_len = code.len();
        if rip {
            code.resize(136, 0x90);
            code[128..136].copy_from_slice(&0xf1e2_d3c4_b5a6_9788_u64.to_le_bytes());
        }
        let (oracle, images) = if seeded_flags {
            NativeOracle::with_seeded_memory_and_flags_adjacent(&code, seed, &[4096; 4])
        } else {
            NativeOracle::with_adjacent_code_mappings(&code, &[4096; 4])
        };
        let victim = oracle.code.address();
        let selected_pc = victim + selected as u64;
        let target = suffix_target(&code, victim, selected, 0, len);
        let selected_page = Mapping::exact_page(target & !4095);
        let mut heads: Vec<_> = (0..function_len)
            .filter(|&pc| !(1..len).contains(&pc) && pc != selected + 1)
            .map(|pc| victim + pc as u64)
            .collect();
        if extra_head {
            heads.push(victim + 5);
        }
        let trace = oracle.trace_original(selected_pc, &heads, &[oracle.return_pc()], seed);
        let witness = oracle.trace_original(victim, &heads, &[oracle.return_pc()], seed);
        assert_eq!(
            trace.visits(),
            [selected_pc, selected_pc + 2, oracle.return_pc()]
        );
        assert_eq!(witness.visits()[0], victim);
        let victim_image = images[0].address();
        let mut relocated = victim_code.to_vec();
        if rip {
            let displacement =
                i32::try_from(i128::from(victim + 128) - i128::from(victim_image + 7)).unwrap();
            relocated[3..7].copy_from_slice(&displacement.to_le_bytes());
        }
        relocated.extend_from_slice(&exact_e9(victim_image + len as u64, victim + len as u64));
        write_mapping(&images[0], 0, &relocated);
        let mut selected_code = vec![0x66, 0x90];
        selected_code.extend_from_slice(&exact_e9(target + 2, selected_pc + 2));
        write_mapping(
            &selected_page,
            usize::try_from(target - selected_page.address()).unwrap(),
            &selected_code,
        );
        let mut redirect = exact_e9(victim, victim_image).to_vec();
        redirect.extend_from_slice(&exact_e9(victim + 5, target));
        let rel8 = i8::try_from(i128::from(victim + 5) - i128::from(selected_pc) - 2).unwrap();
        // Overlay first, then the complete ten-byte patch, including equal bytes.
        write_mapping(&oracle.code, selected, &[0xeb, rel8 as u8]);
        write_mapping(&oracle.code, 0, &redirect);
        oracle.assert_publication(&[(selected_pc, vec![0xeb, rel8 as u8]), (victim, redirect)]);
        let mut boundaries: Vec<_> = heads
            .iter()
            .copied()
            .filter(|&pc| pc != victim && pc != selected_pc)
            .chain([oracle.return_pc()])
            .map(|pc| (pc, pc))
            .collect();
        boundaries.push((victim, victim_image));
        boundaries.push((selected_pc, target));
        let map = TraceMap {
            boundaries,
            gateways: vec![victim, selected_pc],
            generated_ranges: vec![
                victim_image..victim_image + relocated.len() as u64,
                target..target + selected_code.len() as u64,
            ],
        };
        Self {
            oracle,
            trace,
            witness,
            map,
            selected: selected_pc,
            victim,
            target,
            images,
            selected_page,
        }
    }
    fn relay(&self) -> ShortSourceRelay<'_> {
        ShortSourceRelay {
            logical_pc: self.selected,
            relay_pc: self.victim + 5,
            target: self.target,
            victim_trace: &self.witness,
        }
    }
    fn assert_entry(&self, entry: u64) {
        self.oracle.assert_trace_with_short_relays(
            &self.trace,
            entry,
            &self.map,
            &[self.relay()],
            &[],
            None,
        );
    }
    fn assert_victim(&self) {
        self.oracle.assert_trace_with_short_relays(
            &self.witness,
            self.victim,
            &self.map,
            &[self.relay()],
            &[],
            None,
        );
    }
    fn positive(&self) {
        assert!(
            self.selected_page.address() <= self.target
                && self.target < self.selected_page.address() + 4096
        );
        self.assert_entry(self.selected);
        self.assert_victim();
    }
    fn source_write(&self, offset: usize, bytes: &[u8]) {
        write_mapping(&self.oracle.code, offset, bytes);
    }
    fn prefix(&self, bytes: &[u8]) -> u64 {
        let image = &self.images[1];
        let mut code = bytes.to_vec();
        code.extend_from_slice(&exact_e9(
            image.address() + code.len() as u64,
            self.selected,
        ));
        write_mapping(image, 0, &code);
        image.address()
    }
    fn assert_target(&self, target: u64) {
        let mut relay = self.relay();
        relay.target = target;
        self.oracle.assert_trace_with_short_relays(
            &self.trace,
            self.selected,
            &self.map,
            &[relay],
            &[],
            None,
        );
    }
}

// Setup/capture/exact-address acquisition and every positive prerequisite occur
// before this catcher. A panic at some unrelated stage is not a passed refusal.
fn refused(reason: &str, action: impl FnOnce()) {
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action))
        .expect_err("hostile short relay accepted");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("nontext refusal");
    assert!(
        message.contains(reason),
        "expected {reason:?}, observed {message:?}"
    );
}

#[test]
fn short_independent_native_calibration() {
    let _address_window = exact_address_window();
    for seed in SEEDS {
        let f = Calibration::new(seed);
        f.positive();
        let f = Calibration::rip(seed);
        f.positive();
    }
    let f = Calibration::with(
        SEEDS[0],
        &[0x2e, 0xb8, 0xf0, 0xda, 0xbc, 0x9e],
        true,
        false,
        false,
    );
    f.positive();
}

#[test]
fn short_reject_foreign_or_wrong_grammar() {
    let _address_window = exact_address_window();
    let f = Calibration::new(SEEDS[0]);
    f.positive();
    let foreign = Calibration::new(SEEDS[0]);
    foreign.positive();
    let mut relay = f.relay();
    relay.victim_trace = &foreign.witness;
    refused("foreign short victim witness", || {
        f.oracle
            .assert_trace_with_short_relays(&f.trace, f.selected, &f.map, &[relay], &[], None)
    });
    let mut relay = f.relay();
    relay.victim_trace = &f.trace;
    refused("independent MOV/RIP/JNZ grammar", || {
        f.oracle
            .assert_trace_with_short_relays(&f.trace, f.selected, &f.map, &[relay], &[], None)
    });
    // Both unsupported six-byte instructions actually execute before rejection.
    for bytes in [
        [0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x90],
        [0x0f, 0x84, 0, 0, 0, 0],
    ] {
        let bad = Calibration::with(SEEDS[0], &bytes, false, false, false);
        assert_eq!(bad.witness.visits()[1], bad.victim + 6);
        refused("independent MOV/RIP/JNZ grammar", || {
            bad.assert_entry(bad.selected)
        });
    }
    // A genuine native taken JNZ is not a fallthrough/length witness.
    let taken = Calibration::with(SEEDS[0], &[0x0f, 0x85, 3, 0, 0, 0], false, false, true);
    assert_eq!(taken.witness.visits()[1], taken.victim + 9);
    refused("ZF-set fallthrough witness", || {
        taken.assert_entry(taken.selected)
    });
    for mutation in [
        oracle::ShortWitnessMutation::NoFirstStep,
        oracle::ShortWitnessMutation::InteriorFirstStep,
        oracle::ShortWitnessMutation::RemoveFirstSnapshot,
        oracle::ShortWitnessMutation::RemoveSecondSnapshot,
        oracle::ShortWitnessMutation::ChangeObservedRax,
        oracle::ShortWitnessMutation::ChangeObservedRcx,
    ] {
        let f = Calibration::new(SEEDS[0]);
        f.positive();
        f.oracle.assert_short_witness_rejected(
            &f.trace,
            f.witness,
            &f.map,
            [f.selected, f.victim + 5, f.target],
            mutation,
        );
    }
    let read = Calibration::rip(SEEDS[0]);
    read.positive();
    read.oracle.assert_short_witness_rejected(
        &read.trace,
        read.witness,
        &read.map,
        [read.selected, read.victim + 5, read.target],
        oracle::ShortWitnessMutation::ChangeObservedRcx,
    );
    let read = Calibration::rip(SEEDS[0]);
    read.positive();
    let wrong =
        i32::try_from(i128::from(read.victim + 129) - i128::from(read.images[0].address() + 7))
            .unwrap();
    write_mapping(&read.images[0], 3, &wrong.to_le_bytes());
    refused("rcx mismatch", || read.assert_victim());
    // A changed relocated effect cannot acquire authority from the correct witness.
    for (bytes, reason) in [
        (vec![0x2e, 0xb8, 0, 0, 0, 0], "rax mismatch"),
        (
            vec![0x48, 0xb8, 0xf0, 0xda, 0xbc, 0x9e, 1, 0, 0, 0],
            "rax mismatch",
        ),
        (vec![0x48, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0], "rax mismatch"),
    ] {
        let mut bad = Calibration::new(SEEDS[0]);
        bad.positive();
        let start = bad.images[0].address();
        let mut code = bytes;
        code.extend_from_slice(&exact_e9(start + code.len() as u64, bad.victim + 6));
        write_mapping(&bad.images[0], 0, &code);
        bad.map.generated_ranges[0] = start..start + code.len() as u64;
        refused(reason, || bad.assert_victim());
    }
}

#[test]
fn short_reject_suffix_overlay_corruption() {
    let _address_window = exact_address_window();
    for offset in 6..10 {
        let f = Calibration::new(SEEDS[0]);
        f.positive();
        f.source_write(offset, &[0x91]);
        refused("short E9 target mismatch", || f.assert_entry(f.selected));
    }
    let f = Calibration::new(SEEDS[0]);
    f.positive();
    f.source_write(100, &[0x90]);
    refused("unauthorized short source publication", || {
        f.assert_entry(f.selected)
    });
    // Fixed suffix must use the selected EB overlay, not the original NOP2.
    let f = Calibration::with(
        SEEDS[0],
        &[0x2e, 0xb8, 0xf0, 0xda, 0xbc, 0x9e],
        true,
        false,
        false,
    );
    f.positive();
    f.source_write(6, &[0x66, 0x90]);
    refused("short selected EB mismatch", || f.assert_entry(f.selected));
}

#[test]
fn short_reject_head_gateway_image_mismatch() {
    let _address_window = exact_address_window();
    let mut f = Calibration::new(SEEDS[0]);
    f.positive();
    f.map.boundaries.retain(|&(pc, _)| pc != f.victim + 6);
    refused("missing restored boundary", || f.assert_entry(f.selected));
    let f = Calibration::new(SEEDS[0]);
    f.positive();
    refused("overlapping relay victim spans", || {
        f.oracle.assert_trace_with_short_relays(
            &f.trace,
            f.selected,
            &f.map,
            &[f.relay(), f.relay()],
            &[],
            None,
        )
    });
    let f = Calibration::with(
        SEEDS[0],
        &[0x2e, 0xb8, 0xf0, 0xda, 0xbc, 0x9e],
        false,
        true,
        false,
    );
    refused("original head overlaps relay victim interior", || {
        f.assert_entry(f.selected)
    });
    let mut f = Calibration::new(SEEDS[0]);
    f.positive();
    f.map.gateways.push(f.victim + 5);
    refused("undeclared source gateway", || f.assert_entry(f.selected));
    let mut f = Calibration::new(SEEDS[0]);
    f.positive();
    f.map.boundaries.push((f.selected, f.victim + 5));
    f.map.generated_ranges.push(f.victim + 5..f.victim + 6);
    refused("restored boundary overlaps relay victim span", || {
        f.assert_entry(f.selected)
    });
    let mut f = Calibration::new(SEEDS[0]);
    f.positive();
    f.map.boundaries.push((f.victim + 6, f.target + 1));
    refused("relay image owns a different logical instruction", || {
        f.assert_entry(f.selected)
    });
    let f = Calibration::new(SEEDS[0]);
    f.positive();
    f.source_write(5, &exact_e9(f.victim + 5, f.target + 1));
    refused("relay target is not one exact image entry", || {
        f.assert_target(f.target + 1)
    });
    let mut f = Calibration::new(SEEDS[0]);
    f.positive();
    f.map
        .generated_ranges
        .push(f.map.generated_ranges[1].clone());
    refused("relay target is not one exact image entry", || {
        f.assert_entry(f.selected)
    });
    let mut f = Calibration::new(SEEDS[0]);
    f.positive();
    f.map.generated_ranges[1].end = f.images[0].address() + 20;
    refused("relay image ranges overlap", || f.assert_entry(f.selected));
    let mut f = Calibration::new(SEEDS[0]);
    f.positive();
    let target = f.victim + 100;
    f.map.generated_ranges[1] = target..target + 7;
    for (pc, generated) in &mut f.map.boundaries {
        if *pc == f.selected {
            *generated = target;
        }
    }
    f.source_write(5, &exact_e9(f.victim + 5, target));
    refused("relay image overlaps original source", || {
        f.assert_target(target)
    });
}

#[test]
fn short_reject_displacement_or_visit_corruption() {
    let _address_window = exact_address_window();
    for (offset, value, reason) in [
        (32, 0x90, "short selected EB mismatch"),
        (33, 0, "short selected EB mismatch"),
        (0, 0x90, "short victim entry is not E9"),
        (5, 0x90, "short E9 target mismatch"),
    ] {
        let f = Calibration::new(SEEDS[0]);
        f.positive();
        f.source_write(offset, &[value]);
        refused(reason, || f.assert_entry(f.selected));
    }
    let f = Calibration::new(SEEDS[0]);
    f.positive();
    refused("unclassified source head", || {
        f.oracle
            .assert_trace(&f.trace, f.selected, &f.map, &[], None)
    });
    refused("missing or duplicate source relay visits", || {
        f.assert_entry(f.target)
    });
    refused("unexpected source relay", || {
        f.oracle.assert_trace_with_short_relays(
            &f.witness,
            f.selected,
            &f.map,
            &[f.relay()],
            &[],
            None,
        )
    });
    // A generated detour re-enters the relay after the selected visit consumed.
    let f = Calibration::new(SEEDS[0]);
    f.positive();
    let code = exact_e9(f.target, f.victim + 5);
    write_mapping(
        &f.selected_page,
        usize::try_from(f.target - f.selected_page.address()).unwrap(),
        &code,
    );
    refused("unexpected source relay", || f.assert_entry(f.selected));
}

#[test]
fn short_reject_full_state_or_hook_corruption() {
    let _address_window = exact_address_window();
    for (code, reason) in [
        (&[0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0][..], "rax mismatch"),
        (&[0xf8][..], "defined RFLAGS mismatch"),
        (&[0x0f, 0x57, 0xc0][..], "extended state mismatch"),
        (&[0x48, 0x89, 0x07][..], "application data mismatch"),
        (
            &[0x48, 0x89, 0x44, 0x24, 0x80][..],
            "application stack/redzone mismatch",
        ),
    ] {
        let f = Calibration::new(SEEDS[0]);
        f.positive();
        let entry = f.prefix(code);
        refused(reason, || f.assert_entry(entry));
    }
    let f = Calibration::new(SEEDS[0]);
    f.positive();
    let log = HookEventLog::new();
    let enabled = [HookEvent {
        probe_id: PROBE_ID,
        logical_pc: f.selected,
    }];
    refused("hook event trace mismatch", || {
        f.oracle.assert_trace_with_short_relays(
            &f.trace,
            f.selected,
            &f.map,
            &[f.relay()],
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &enabled,
            }),
        )
    });
    // Only this hostile callback prefix uses the existing emitter. The valid
    // source, relay, original witnesses and manual image are independent of it.
    let prefix_source = &f.images[2];
    let prefix_image = &f.images[3];
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
    write_mapping(prefix_image, 0, image.bytes());
    let mut prefix = nop.to_vec();
    prefix.extend_from_slice(&exact_e9(prefix_source.address() + 5, f.selected));
    write_mapping(prefix_source, 0, &prefix);
    refused("hook event trace mismatch", || {
        f.oracle.assert_trace_with_short_relays(
            &f.trace,
            prefix_image.address(),
            &f.map,
            &[f.relay()],
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &[],
            }),
        )
    });
}

#[test]
fn short_reject_fetch_or_bound_violation() {
    let _address_window = exact_address_window();
    let f = Calibration::new(SEEDS[0]);
    f.positive();
    for (logical, relay, reason) in [
        (u64::MAX, f.victim + 5, "short EB overflow"),
        (f.victim + 4095, f.victim + 5, "short EB outside source"),
        (
            f.selected,
            f.selected + 130,
            "short EB outside signed reach",
        ),
        (
            f.selected,
            f.selected.checked_sub(127).unwrap(),
            "short EB outside signed reach",
        ),
    ] {
        let r = ShortSourceRelay {
            logical_pc: logical,
            relay_pc: relay,
            target: f.target,
            victim_trace: &f.witness,
        };
        refused(reason, || {
            f.oracle
                .assert_trace_with_short_relays(&f.trace, f.selected, &f.map, &[r], &[], None)
        });
    }
    for mutation in [
        oracle::ShortWitnessMutation::PartialFetch,
        oracle::ShortWitnessMutation::RemoveOriginalByte,
    ] {
        let bad = Calibration::new(SEEDS[0]);
        bad.positive();
        bad.oracle.assert_short_witness_rejected(
            &bad.trace,
            bad.witness,
            &bad.map,
            [bad.selected, bad.victim + 5, bad.target],
            mutation,
        );
    }
    // A source write missing from the retained original page always refuses.
    f.source_write(4095, &[0x90]);
    refused("unauthorized short source publication", || {
        f.assert_entry(f.selected)
    });
}

// Engine dispatch bridge; the direct planner and NativeOracle remain unchanged.
#[test]
fn short_engine_overlap_bundle_matches_direct_and_native() {
    let _address_window = exact_address_window();
    use liteinst2::engine::{self, CandidateEvidence, EnginePolicy, SelectedMetrics, Tactic};
    // Independent five-head bridge; do not enroll in the old 1102-head census.
    let puzzle = ShortPuzzle::overlap();
    let expected_heads = 5;
    assert_eq!(puzzle.heads, [0, 6, 8, 9, 10]);
    let selected_len = puzzle.selected_len;
    let victim_len = puzzle.victim_len;
    let mut head_count = 0;
    let mut installed_count = 0;
    let mut retired_count = 0;
    let mut direct_victim_count = 0;
    assert_eq!(puzzle.heads.len(), expected_heads);
    head_count += puzzle.heads.len();
    let mut oracle = NativeOracle::new(&puzzle.code);
    let base = oracle.code.address();
    let selected = base + puzzle.selected as u64;
    let victim = base + puzzle.victim as u64;
    let relay = victim + 5;
    let rel8 = i8::try_from(i128::from(relay) - i128::from(selected) - 2).unwrap();
    let heads: Vec<_> = puzzle.heads.iter().map(|&pc| base + pc as u64).collect();
    let source = AddressRange::new(base, puzzle.function_len).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0xe7; 32]),
        mapping: base,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared("short T3 all original authored heads".into()),
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
    let selected_target = suffix_target(
        &puzzle.code,
        base,
        puzzle.selected,
        puzzle.victim,
        victim_len,
    );
    let victim_target = base + 0x1800_0280;
    let mut selected_allocation = AllocationPolicy::near(selected).unwrap();
    selected_allocation.ranges = vec![AddressRange::new(selected_target & !4095, 8192).unwrap()];
    selected_allocation.preferred_address = Some(selected_target);
    selected_allocation.max_candidates = 1;
    let mut victim_allocation = AllocationPolicy::near(victim).unwrap();
    victim_allocation.ranges = vec![AddressRange::new(victim_target & !4095, 8192).unwrap()];
    victim_allocation.preferred_address = Some(victim_target);
    victim_allocation.max_candidates = 1;
    let request = InstallRequest {
        identity,
        code: &puzzle.code[..puzzle.function_len],
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
    let direct = plan_neighbor_short(
        &request,
        &victim_allocation,
        NeighborSearch {
            forced_victim: Some(victim),
            max_victims: 1,
            max_pairs: 1,
        },
        BundleBudget::default(),
    )
    .expect("required direct short bridge refused");
    let planned = engine::plan_with_short_neighbors(
        &request,
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
    )
    .expect("required engine short bridge refused");
    assert_eq!(planned.tactic(), Tactic::NeighborEviction);
    assert_eq!(planned.attempts().len(), 1);
    assert_eq!(planned.attempts()[0].refusal, None);
    let SelectedMetrics::Neighbor(geometry, metrics) = planned.metrics() else {
        panic!("engine metrics")
    };
    assert_eq!(geometry, direct.geometry());
    assert_eq!(metrics, direct.metrics());
    assert_eq!(planned.attempts()[0].search, metrics.search);
    let CandidateEvidence::Neighbor(rows) = &planned.attempts()[0].candidates else {
        panic!("leaf evidence")
    };
    assert_eq!(rows, &metrics.attempts);
    let a = planned.bundle();
    let b = direct.bundle();
    assert_eq!(a.plan().identity(), b.plan().identity());
    assert_eq!(a.plan().originals(), b.plan().originals());
    assert_eq!(a.plan().final_bytes(), b.plan().final_bytes());
    assert_eq!(a.plan().steps(), b.plan().steps());
    assert_eq!(a.plan().locks(), b.plan().locks());
    assert_eq!(a.plan().memory(), b.plan().memory());
    assert_eq!(a.images().len(), b.images().len());
    for (actual, expected) in a.images().iter().zip(b.images()) {
        assert_eq!(actual.address(), expected.address());
        assert_eq!(actual.bytes(), expected.bytes());
        assert_eq!(actual.entry_routes(), expected.entry_routes());
        assert_eq!(
            actual.instruction_boundaries(),
            expected.instruction_boundaries()
        );
        assert_eq!(
            actual.program_counter_mappings(),
            expected.program_counter_mappings()
        );
    }
    assert_eq!(geometry.selected, selected);
    assert_eq!(geometry.selected_len, selected_len);
    assert_eq!(geometry.victim, victim);
    assert_eq!(geometry.victim_len, victim_len);
    assert_eq!(geometry.relay, relay);
    assert_eq!(geometry.rel8, rel8);
    assert_eq!(geometry.selected_target, selected_target);
    assert_eq!(geometry.victim_target, victim_target);
    assert_eq!(metrics.victims_examined, 1);
    assert_eq!(metrics.pairs_examined, 1);
    assert_eq!(metrics.selected_fallthrough_redirects, 3);
    assert_eq!(metrics.victim_fallthrough_redirects, 2);
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
    assert_eq!(selected_step.parts().writes[0].bytes, [0xeb, rel8 as u8]);
    let mut victim_bytes = exact_e9(victim, victim_target).to_vec();
    victim_bytes.extend_from_slice(&exact_e9(relay, selected_target));
    assert_eq!(&puzzle.code[6..10], &[0xff, 0xc0, 0xc3, 0x90]);
    assert_eq!(&victim_bytes[6..10], &[0xeb, 0xfd, 0xc3, 0x90]);
    assert_eq!(victim_step.parts().writes.len(), 1);
    assert_eq!(victim_step.parts().writes[0].address, victim);
    assert_eq!(victim_step.parts().writes[0].bytes, victim_bytes);
    let edits = vec![(selected, vec![0xeb, rel8 as u8]), (victim, victim_bytes)];
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
                puzzle.visits(offset, base, oracle.return_pc())
            );
            originals.push((entry, trace));
        }
    }
    let witness = &originals
        .iter()
        .find(|(entry, _)| *entry == victim)
        .unwrap()
        .1;
    assert_eq!(witness.visits()[1], victim + victim_len as u64);
    let relay_records = [ShortSourceRelay {
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
            assert!(trace.visits().contains(&selected));
            direct_victim_count += 1;
        }
        oracle.assert_trace_with_short_relays(
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
    assert_eq!(originals.len(), 10);
    assert_eq!(originals.len() + installed_count + retired_count, 30);
    // Own this one additional mapping through process exit, independently of
    // the legacy endpoint census; neither a successful retry nor shared cache.
    let _pinned_source = Box::leak(Box::new(oracle));
}
