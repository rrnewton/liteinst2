//! One unchanged eviction chain, now published with sealed shared backing.
//! This child module reuses the existing oracle, callback and isolation driver.

use super::cases::{CASES, Fixture};
use super::oracle::{HookEvent, HookEventLog, HookExpectation, NativeOracle, TraceMap};
use super::{ID, Occupied, SEEDS, allocations, image_bytes, is_mapped, observe, permissions};
use liteinst2::bundle::{BundleMemory, WritableAlias};
use liteinst2::contracts::*;
use liteinst2::eviction_chain::plan_successor_chain_grouped_detailed;
use liteinst2::grouping::{BackingKind, GroupingBudget};
use liteinst2::trampoline::translate_program_counter;
use std::path::Path;

const PAGE: usize = 4096;
const SPAN: u64 = 0x6d699000;

#[derive(Clone, Debug, Eq, PartialEq)]
struct AliasOwner {
    device: String,
    inode: u64,
}

fn alias_owner(range: AddressRange) -> AliasOwner {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let matches: Vec<_> = maps
        .lines()
        .filter(|line| {
            let (low, high) = line
                .split_whitespace()
                .next()
                .unwrap()
                .split_once('-')
                .unwrap();
            let low = u64::from_str_radix(low, 16).unwrap();
            let high = u64::from_str_radix(high, 16).unwrap();
            low < range.end() && range.start() < high
        })
        .collect();
    assert_eq!(matches.len(), 1, "one exact dictated alias extent");
    let fields: Vec<_> = matches[0].split_whitespace().collect();
    assert_eq!(fields.len(), 7);
    let (low, high) = fields[0].split_once('-').unwrap();
    assert_eq!(u64::from_str_radix(low, 16).unwrap(), range.start());
    assert_eq!(u64::from_str_radix(high, 16).unwrap(), range.end());
    assert_eq!(fields[1], "r-xs");
    assert_eq!(u64::from_str_radix(fields[2], 16).unwrap(), 0);
    let (major, minor) = fields[3].split_once(':').unwrap();
    let device = (
        u64::from_str_radix(major, 16).unwrap(),
        u64::from_str_radix(minor, 16).unwrap(),
    );
    assert_ne!(device, (0, 0));
    let inode = fields[4].parse().unwrap();
    assert_ne!(inode, 0);
    assert_eq!(fields[5], "/memfd:liteinst2-immutable-group");
    assert_eq!(fields[6], "(deleted)");
    AliasOwner {
        device: fields[3].to_owned(),
        inode,
    }
}

fn assert_alias_pages(ranges: &[AddressRange], expected: &[u8], owner: &AliasOwner) {
    assert_eq!(expected.len(), PAGE);
    for &range in ranges {
        assert_eq!(range.len(), PAGE as u64);
        assert_eq!(&alias_owner(range), owner);
        // SAFETY: the exact complete readable alias was checked above. The
        // isolated main thread owns this transaction and all tracees are gone.
        let bytes =
            unsafe { std::slice::from_raw_parts(range.start() as usize as *const u8, PAGE) };
        assert_eq!(bytes, expected, "whole immutable backing page");
    }
}

fn assert_no_group_fds() {
    for (index, entry) in std::fs::read_dir("/proc/self/fd").unwrap().enumerate() {
        assert!(index < 4096, "bounded descriptor inventory");
        let target = std::fs::read_link(entry.unwrap().path()).unwrap();
        assert!(
            !target
                .to_string_lossy()
                .contains("liteinst2-immutable-group"),
            "staging must close every backing descriptor"
        );
    }
}

pub(super) fn run(capture: &Path) {
    let mut native = NativeOracle::new(CASES[0].code);
    let base = native.code.address();
    assert_eq!(base % PAGE as u64, 0);
    let fixture = Fixture::new(&CASES[0], base);
    let ordinary = super::planned(&fixture);
    fixture.assert_plan(&ordinary);
    let mut budget = fixture.budget();
    budget.max_backing_bytes = PAGE as u64;
    let grouping_budget = GroupingBudget {
        max_mappings: 4,
        max_virtual_pages: 4,
        max_virtual_bytes: 4 * PAGE as u64,
        max_backing_bytes: PAGE as u64,
        max_virtual_span: SPAN,
    };
    let grouped = plan_successor_chain_grouped_detailed(
        &fixture.request(observe),
        &fixture.policies[1..],
        fixture.search(),
        budget,
        grouping_budget,
    )
    .expect("required frozen chain must share one backing page");
    let bundle = grouped.bundle();
    let plan = bundle.plan();
    let old = ordinary.bundle().plan();
    assert_eq!(grouped.nodes(), ordinary.nodes());
    assert_eq!(grouped.metrics(), ordinary.metrics());
    assert_eq!(plan.identity(), old.identity());
    assert_eq!(plan.originals(), old.originals());
    assert_eq!(plan.final_bytes(), old.final_bytes());
    assert_eq!(plan.steps(), old.steps());
    assert_eq!(plan.locks(), old.locks());
    assert_eq!(bundle.images(), ordinary.bundle().images());
    let memory = plan.memory();
    assert_eq!(
        memory,
        BundleMemory {
            mappings: 4,
            virtual_pages: 4,
            backing_pages: 1,
            virtual_bytes: 4 * PAGE as u64,
            backing_bytes: PAGE as u64,
            virtual_span: SPAN,
        }
    );
    assert_eq!(
        old.memory(),
        BundleMemory {
            backing_pages: 4,
            backing_bytes: 4 * PAGE as u64,
            ..memory
        }
    );
    let grouping = bundle.grouping().expect("grouped transaction required");
    let grouped_memory = grouping.memory();
    assert_eq!(grouped_memory.mappings, memory.mappings);
    assert_eq!(grouped_memory.virtual_pages, memory.virtual_pages);
    assert_eq!(grouped_memory.backing_pages, memory.backing_pages);
    assert_eq!(grouped_memory.virtual_bytes, memory.virtual_bytes);
    assert_eq!(grouped_memory.backing_bytes, memory.backing_bytes);
    assert_eq!(grouped_memory.virtual_span, memory.virtual_span);
    assert_eq!(grouping.groups().len(), 1);
    let group = &grouping.groups()[0];
    assert_eq!(group.kind(), BackingKind::SharedPage);
    assert_eq!(group.backing_len(), PAGE);
    assert_eq!(group.image_indices(), &[0, 1, 2, 3]);
    let ranges = allocations(&grouped);
    assert_eq!(group.aliases(), ranges);
    assert_eq!(ranges.len(), 4);
    assert!(ranges.iter().all(|range| range.len() == PAGE as u64));
    assert!(ranges.iter().all(|&range| !is_mapped(range)));
    let images = bundle.images();
    let offsets: Vec<_> = images
        .iter()
        .map(|image| (image.address() % PAGE as u64) as usize)
        .collect();
    assert_eq!(offsets, [0x461, 0x008, 0x0f0, 0x985]);
    assert_eq!(images[0].bytes().len(), 10);
    assert_eq!(images[1].bytes().len(), 8);
    assert_eq!(images[2].bytes().len(), 6);
    assert!(!images[3].bytes().is_empty());
    assert!(images[3].bytes().len() <= 0x67b);
    let selected_image_bytes = images[3].bytes().len();
    let mut expected_page = vec![0xcc; PAGE];
    let mut occupied = [false; PAGE];
    for (image, &offset) in images.iter().zip(&offsets) {
        let end = offset.checked_add(image.bytes().len()).unwrap();
        assert!(end <= PAGE);
        assert!(occupied[offset..end].iter().all(|used| !used));
        occupied[offset..end].fill(true);
        expected_page[offset..end].copy_from_slice(image.bytes());
        for pc in image.address()..image.address() + image.bytes().len() as u64 {
            assert_eq!(translate_program_counter(pc), None);
        }
    }
    assert_no_group_fds();
    let pointer = native.code.writable();
    let source = fixture.entries.scope;
    let aliases = [unsafe { WritableAlias::new(source, pointer) }.unwrap()];
    // Anchor, LEA and NOP aliases precede this selected alias in staging order.
    let blocker = Occupied::new(ranges[3]);
    let mut finalize_calls = 0;
    {
        let mut lease =
            unsafe { QuiescenceLease::new(&mut native, fixture.entries.identity, vec![source]) };
        let failure = match unsafe {
            bundle.publish_with(&aliases, &mut lease, || {
                finalize_calls += 1;
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        } {
            Err(failure) => failure,
            Ok(_) => panic!("occupied final alias unexpectedly published"),
        };
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert!(!lease.is_poisoned());
    }
    assert_eq!(finalize_calls, 0);
    native.assert_publication(&[]);
    blocker.check();
    assert!(ranges[..3].iter().all(|&range| !is_mapped(range)));
    assert_no_group_fds();
    for image in images {
        for pc in image.address()..image.address() + image.bytes().len() as u64 {
            assert_eq!(translate_program_counter(pc), None);
        }
    }
    drop(blocker);
    assert!(ranges.iter().all(|&range| !is_mapped(range)));
    let collision_refusals = 1;

    let heads: Vec<_> = fixture
        .case
        .heads
        .iter()
        .map(|&offset| base + offset as u64)
        .collect();
    assert_eq!(heads.len(), 6);
    let mut originals = Vec::new();
    let mut original_states = 0;
    for seed in SEEDS {
        for (index, &entry) in heads.iter().enumerate() {
            let trace = native.trace_original(entry, &heads, &[native.return_pc()], seed);
            let visits = trace.visits();
            assert_eq!(
                visits,
                heads[index..]
                    .iter()
                    .copied()
                    .chain([native.return_pc()])
                    .collect::<Vec<_>>()
            );
            original_states += visits.len();
            originals.push((index, entry, trace));
        }
    }
    let (mut installed, receipt) = {
        let mut lease =
            unsafe { QuiescenceLease::new(&mut native, fixture.entries.identity, vec![source]) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        let result = unsafe {
            bundle.publish_with(&aliases, &mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required grouped chain publication");
        assert!(!lease.is_poisoned());
        result
    };
    assert_eq!(receipt.plan().steps(), plan.steps());
    assert_eq!(receipt.plan().memory(), memory);
    let edits: Vec<_> = plan
        .steps()
        .iter()
        .flat_map(|step| {
            step.parts()
                .writes
                .iter()
                .map(|edit| (edit.address, edit.bytes.clone()))
        })
        .collect();
    native.assert_publication(&edits);
    image_bytes(&grouped);
    let owner = alias_owner(ranges[0]);
    assert_alias_pages(&ranges, &expected_page, &owner);
    assert_no_group_fds();
    let mut seal_refusals = 0;
    for range in &ranges {
        // SAFETY: this attempts a permission upgrade on one exact owned alias.
        assert_eq!(
            unsafe {
                libc::mprotect(
                    range.start() as usize as *mut libc::c_void,
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            -1,
            "sealed code must not become writable"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EACCES)
        );
        seal_refusals += 1;
        assert_alias_pages(&ranges, &expected_page, &owner);
    }
    assert_eq!(installed.trampolines().len(), 4);
    let mut foreign_bytes_without_authority = 0;
    for (alias_index, (range, handle)) in ranges.iter().zip(installed.trampolines()).enumerate() {
        let own = &images[alias_index];
        assert_eq!(handle.address(), own.address());
        assert_eq!(handle.code_len(), own.bytes().len());
        assert_eq!(handle.allocation_len(), PAGE);
        assert_eq!(
            handle.program_counter_mappings(),
            own.program_counter_mappings()
        );
        for mapping in own.program_counter_mappings() {
            for pc in mapping.generated_start()..mapping.generated_end() {
                assert_eq!(
                    translate_program_counter(pc),
                    Some(mapping.logical_address())
                );
            }
        }
        for (foreign_index, foreign) in images.iter().enumerate() {
            if foreign_index == alias_index {
                continue;
            }
            let start = range.start() + offsets[foreign_index] as u64;
            for pc in start..start + foreign.bytes().len() as u64 {
                assert_eq!(handle.translate_program_counter(pc), None);
                assert_eq!(translate_program_counter(pc), None);
                foreign_bytes_without_authority += 1;
            }
        }
    }

    let mut map = TraceMap {
        boundaries: heads[4..]
            .iter()
            .copied()
            .chain([native.return_pc()])
            .map(|pc| (pc, pc))
            .collect(),
        gateways: heads[..4].to_vec(),
        ..TraceMap::default()
    };
    for image in images {
        map.boundaries
            .extend_from_slice(image.instruction_boundaries());
        map.generated_ranges
            .push(image.address()..image.address() + image.bytes().len() as u64);
    }
    let log = HookEventLog::new();
    let selected = [HookEvent {
        probe_id: ID,
        logical_pc: base,
    }];
    let mut installed_count = 0;
    let mut installed_comparisons = 0;
    let mut selected_hooks = 0;
    let mut auxiliary_entries = 0;
    let mut tail_entries = 0;
    for (index, entry, trace) in &originals {
        let enabled: &[HookEvent] = if *index == 0 { &selected } else { &[] };
        native.assert_trace(
            trace,
            *entry,
            &map,
            &[],
            Some(HookExpectation { log: &log, enabled }),
        );
        installed_count += 1;
        installed_comparisons += trace.visits().len();
        selected_hooks += usize::from(*index == 0);
        auxiliary_entries += usize::from(*index > 0 && *index < 4);
        tail_entries += usize::from(*index >= 4);
        assert_alias_pages(&ranges, &expected_page, &owner);
    }
    assert_eq!(installed.routed_entries(), 0);
    {
        let mut held = vec![source];
        held.extend_from_slice(&ranges);
        let mut lease =
            unsafe { QuiescenceLease::new(&mut native, fixture.entries.identity, held) };
        permissions(pointer, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(pointer, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("required complete grouped-chain retirement");
        assert!(!lease.is_poisoned());
    }
    assert!(installed.is_retired());
    native.assert_publication(&[]);
    image_bytes(&grouped);
    let original_map = TraceMap {
        boundaries: heads
            .iter()
            .copied()
            .chain([native.return_pc()])
            .map(|pc| (pc, pc))
            .collect(),
        ..TraceMap::default()
    };
    let mut retired_count = 0;
    let mut retired_comparisons = 0;
    for (_, entry, trace) in &originals {
        native.assert_trace(
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
        retired_comparisons += trace.visits().len();
        assert_alias_pages(&ranges, &expected_page, &owner);
    }
    assert_eq!(
        (originals.len(), installed_count, retired_count),
        (12, 12, 12)
    );
    assert_eq!(
        (original_states, installed_comparisons, retired_comparisons),
        (54, 54, 54)
    );
    assert_eq!((selected_hooks, auxiliary_entries, tail_entries), (2, 6, 4));
    assert_eq!((collision_refusals, seal_refusals), (1, 4));
    assert_eq!(
        foreign_bytes_without_authority,
        3 * images
            .iter()
            .map(|image| image.bytes().len())
            .sum::<usize>()
    );
    drop(installed);
    native.assert_publication(&[]);
    assert_alias_pages(&ranges, &expected_page, &owner);
    assert_no_group_fds();
    let comparisons = installed_comparisons + retired_comparisons;
    // These counts describe successfully returned NativeOracle assertions.
    // Full register/XSAVE/data/stack snapshots are not serialized here.
    let summary = format!(
        "{{\n  \"case\": \"chain-depth2-B2-1-and-3-byte-victims\",\n  \"status\": \"passed\",\n  \"mappings\": {},\n  \"virtual_pages\": {},\n  \"backing_pages\": {},\n  \"virtual_bytes\": {},\n  \"backing_bytes\": {},\n  \"virtual_span\": {},\n  \"selected_image_bytes\": {},\n  \"original_traces\": {},\n  \"installed_traces\": {},\n  \"retired_traces\": {},\n  \"original_boundary_states\": {},\n  \"full_state_comparisons\": {},\n  \"asserted_selected_hook_events\": {},\n  \"auxiliary_entries_without_hook\": {},\n  \"tail_entries_without_hook\": {},\n  \"late_collision_before_write\": {},\n  \"sealed_write_upgrade_refusals\": {},\n  \"foreign_bytes_without_pc_authority\": {},\n  \"alias_device\": \"{}\",\n  \"alias_inode\": {},\n  \"whole_alias_page_bytes_checked\": {},\n  \"state_evidence\": \"executed unchanged NativeOracle assertions; snapshots not serialized\"\n}}\n",
        memory.mappings,
        memory.virtual_pages,
        memory.backing_pages,
        memory.virtual_bytes,
        memory.backing_bytes,
        memory.virtual_span,
        selected_image_bytes,
        originals.len(),
        installed_count,
        retired_count,
        original_states,
        comparisons,
        selected_hooks,
        auxiliary_entries,
        tail_entries,
        collision_refusals,
        seal_refusals,
        foreign_bytes_without_authority,
        owner.device,
        owner.inode,
        ranges.len() * PAGE,
    );
    let summary_path = capture.join("summary.json");
    assert!(!summary_path.exists());
    std::fs::write(summary_path, summary).unwrap();
    eprintln!(
        "grouped chain: original=12 installed=12 retired=12 comparisons=108 selected_hooks=2 mappings=4 backing_pages=1 collision_before_write=1 sealed_write_refusals=4"
    );
}
