//! One fresh process executes exactly one input from a frozen campaign.
//! Compile with the reviewed standalone driver and explicit private table path.
//! Architectural comparisons use the shared, independently calibrated oracle.

#[allow(dead_code)]
#[path = "../../tests/support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::bundle::{BundleBudget, InstalledBundle, PlannedBundle, WritableAlias};
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, ExpectedBytes,
    FailureStage, LegalEntry, LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation,
    SourceIdentity,
};
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::engine::{self, EnginePolicy, Tactic};
use liteinst2::grouping::{BackingKind, GroupingBudget};
use liteinst2::neighbor::{NeighborGeometry, NeighborSearch};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_coalesced_detailed,
    plan_install_detailed,
};
use liteinst2::trampoline::{
    HookCallback, HookContext, TrampolineError, translate_program_counter,
};
use oracle::{
    HookEvent, HookEventLog, HookExpectation, NativeOracle, NativeTrace, SourceRelay, TraceMap,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

struct Case {
    id: usize,
    family: &'static str,
    input_sha256: &'static str,
    code: &'static [u8],
    heads: &'static [usize],
    paths: &'static [&'static [usize]],
    states: [u64; 2],
    memory_seed: u64,
    alignment: usize,
    selected: usize,
    physical: usize,
    length: usize,
    prefixes: usize,
    victim: Option<usize>,
    victim_len: usize,
    block: (usize, usize),
    functions: &'static [(usize, usize, usize)],
    actions: &'static [usize],
    target_kind: &'static str,
    selected_delta: u64,
    victim_delta: u64,
    expected: &'static str,
    forced: Tactic,
    masks: usize,
    expected_installed: usize,
    expected_retired: usize,
    expected_events: usize,
}
include!(concat!(env!("LITEINST_A2_CAMPAIGN_INPUT_DIR"), "/cases.rs"));
include!(concat!(
    env!("LITEINST_A2_CAMPAIGN_INPUT_DIR"),
    "/sample-cases.rs"
));

struct Recorder(PathBuf);
impl Recorder {
    fn line(&self, text: impl AsRef<str>) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.0.join("events.txt"))
            .unwrap();
        writeln!(file, "{}", text.as_ref()).unwrap();
        file.sync_data().unwrap();
    }
    fn bytes(&self, name: &str, bytes: &[u8]) {
        fs::write(self.0.join(name), bytes).unwrap();
    }
}

unsafe fn record(context: *mut HookContext, probe_id: u64) {
    // SAFETY: the controlled/native emitter supplies its live application frame;
    // the strict oracle activates a bounded private child event log.
    unsafe {
        oracle::record_hook_event(probe_id, (*context).instruction_pointer);
        core::arch::asm!("add rax, 1", "pxor xmm0, xmm0", "fninit",
            out("rax") _, out("xmm0") _, options(nostack));
    }
}
macro_rules! hook {
    ($name:ident, $id:literal) => {
        unsafe extern "C" fn $name(context: *mut HookContext) {
            unsafe { record(context, $id) }
        }
    };
}
hook!(hook_a, 1);
hook!(hook_b, 2);
hook!(hook_c, 3);
hook!(hook_d, 4);
const CALLBACKS: [HookCallback; 4] = [hook_a, hook_b, hook_c, hook_d];

fn range(start: u64, length: usize) -> AddressRange {
    AddressRange::new(start, length).unwrap()
}
fn add_signed(address: u64, displacement: i32) -> u64 {
    u64::try_from(i128::from(address) + i128::from(displacement)).unwrap()
}
fn bytes(address: u64, length: usize) -> Vec<u8> {
    // SAFETY: callers provide their retained source or published image ranges.
    unsafe { std::slice::from_raw_parts(address as usize as *const u8, length) }.to_vec()
}
fn check_bytes(snapshots: &[(u64, Vec<u8>)]) {
    for (address, expected) in snapshots {
        assert_eq!(
            bytes(*address, expected.len()),
            *expected,
            "immutable bytes changed"
        );
    }
}

fn private_backing_resources() -> Vec<String> {
    let mut resources: Vec<_> = fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .filter(|line| line.contains("memfd:liteinst2-trampoline"))
        .map(|line| format!("map:{line}"))
        .collect();
    for entry in fs::read_dir("/proc/self/fd").unwrap() {
        let entry = entry.unwrap();
        if let Ok(target) = fs::read_link(entry.path()) {
            if target
                .to_string_lossy()
                .contains("memfd:liteinst2-trampoline")
            {
                resources.push(format!(
                    "fd:{}:{}",
                    entry.file_name().to_string_lossy(),
                    target.display()
                ));
            }
        }
    }
    resources.sort();
    resources
}

fn mapping_fields(header: &str, grouped: bool) -> Vec<&str> {
    let fields: Vec<_> = header.split_whitespace().collect();
    let expected_name = if grouped {
        "/memfd:liteinst2-immutable-group"
    } else {
        "/memfd:liteinst2-trampoline"
    };
    assert_eq!(fields.len(), 7);
    assert_eq!(fields[1], "r-xs");
    assert_eq!(&fields[5..], &[expected_name, "(deleted)"]);
    fields
}

#[cfg(test)]
mod memory_name_calibration {
    use super::mapping_fields;

    #[test]
    fn exact_mapping_kind_is_required() {
        let private = "1000-2000 r-xs 00000000 00:01 9 /memfd:liteinst2-trampoline (deleted)";
        let grouped = "1000-2000 r-xs 00000000 00:01 9 /memfd:liteinst2-immutable-group (deleted)";
        assert_eq!(mapping_fields(private, false)[5], "/memfd:liteinst2-trampoline");
        assert_eq!(mapping_fields(grouped, true)[5], "/memfd:liteinst2-immutable-group");
        let negatives = [
            (private.to_string(), true),
            (grouped.to_string(), false),
            (private.replace("trampoline", "trampoline-spoof"), false),
            (grouped.replace("immutable-group", "immutable-group-spoof"), true),
            (private.replace("r-xs", "rwxs"), false),
            (private.replace("r-xs", "rwx s"), false),
            (grouped.replace("r-xs", "r-xp"), true),
            (private.replace(" (deleted)", ""), false),
            (format!("{grouped} extra"), true),
        ];
        for (header, kind) in negatives {
            assert!(std::panic::catch_unwind(|| mapping_fields(&header, kind)).is_err(), "accepted {header}");
        }
    }
}

// Parent-only accounting after reading the immutable image pages. These are
// observed whole-VMA values, separately reported from planner byte/page costs.
fn memory_observation(log: &Recorder, label: &str, bundle: &PlannedBundle) {
    let allocations: Vec<_> = bundle
        .plan()
        .steps()
        .iter()
        .flat_map(|step| step.parts().allocations.iter().map(|item| item.range))
        .collect();
    let maps = fs::read_to_string("/proc/self/maps").unwrap();
    log.bytes(&format!("{label}-maps.txt"), maps.as_bytes());
    let smaps = fs::read_to_string("/proc/self/smaps").unwrap();
    let mut records: Vec<(u64, u64, Vec<&str>)> = Vec::new();
    for line in smaps.lines() {
        let interval = line
            .split_whitespace()
            .next()
            .and_then(|word| word.split_once('-'))
            .and_then(|(a, b)| {
                Some((
                    u64::from_str_radix(a, 16).ok()?,
                    u64::from_str_radix(b, 16).ok()?,
                ))
            });
        if let Some((start, end)) = interval {
            records.push((start, end, vec![line]));
        } else if let Some((_, _, lines)) = records.last_mut() {
            lines.push(line);
        }
    }
    let mut selected = String::new();
    let mut coverage = vec![Vec::<(u64, u64)>::new(); allocations.len()];
    let mut count = 0;
    let mut totals = [0_u64; 3];
    let mut backing = std::collections::BTreeMap::new();
    for (start, end, lines) in records {
        let overlaps: Vec<_> = allocations
            .iter()
            .enumerate()
            .filter(|(_, range)| start < range.end() && range.start() < end)
            .map(|(i, _)| i)
            .collect();
        if overlaps.is_empty() {
            continue;
        }
        let fields = mapping_fields(lines[0], bundle.grouping().is_some());
        for index in overlaps {
            coverage[index].push((
                start.max(allocations[index].start()),
                end.min(allocations[index].end()),
            ));
        }
        count += 1;
        for (index, key) in ["Size:", "Rss:", "Pss:"].iter().enumerate() {
            let values: Vec<_> = lines
                .iter()
                .filter_map(|line| line.strip_prefix(key))
                .collect();
            assert_eq!(values.len(), 1);
            let parts: Vec<_> = values[0].split_whitespace().collect();
            assert_eq!(parts.len(), 2);
            assert_eq!(parts[1], "kB");
            totals[index] += parts[0].parse::<u64>().unwrap();
        }
        let key = (fields[3].to_string(), fields[4].parse::<u64>().unwrap());
        assert_ne!(key.1, 0);
        let measured = fs::metadata(format!("/proc/self/map_files/{start:x}-{end:x}"))
            .map(|metadata| metadata.len())
            .map_err(|error| error.raw_os_error());
        if let Some(previous) = backing.insert(key, measured) {
            assert_eq!(previous, measured);
        }
        selected.push_str(&lines.join("\n"));
        selected.push('\n');
    }
    for (allocation, mut ranges) in allocations.iter().zip(coverage) {
        ranges.sort_unstable();
        let mut cursor = allocation.start();
        for (start, end) in ranges {
            assert_eq!(start, cursor);
            cursor = end;
        }
        assert_eq!(
            cursor,
            allocation.end(),
            "an allocated image lacks complete observed VMA coverage"
        );
    }
    if bundle.grouping().is_some() {
        assert_eq!(backing.len(), 1);
    }
    log.bytes(
        &format!("{label}-trampoline-smaps.txt"),
        selected.as_bytes(),
    );
    log.line(format!("memory_observation phase={label} basis=parent-read-touched-whole-VMAs allocations={allocations:?} vmas={count} size_kib={} rss_kib={} pss_kib={} observed_backing={backing:?}",totals[0],totals[1],totals[2]));
}

fn permissions(page: u64, protection: i32) -> Result<(), Refusal> {
    // SAFETY: NativeOracle retains this complete private page throughout its lease.
    if unsafe { libc::mprotect(page as usize as *mut _, 4096, protection) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

struct Occupied {
    address: u64,
    length: usize,
}
impl Occupied {
    fn new(address: u64, length: usize) -> Self {
        assert_eq!(address % 4096, 0);
        // SAFETY: NOREPLACE can reserve only currently unmapped addresses. A
        // collision with unrelated host state is a run failure, never a retry.
        let actual = unsafe {
            libc::mmap(
                address as usize as *mut _,
                length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_ne!(
            actual,
            libc::MAP_FAILED,
            "required allocation hole/collision fixture unavailable: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(actual as usize as u64, address);
        Self { address, length }
    }
}
impl Drop for Occupied {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns this exact mapping.
        assert_eq!(
            unsafe { libc::munmap(self.address as usize as *mut _, self.length) },
            0
        );
    }
}

fn allocation(pc: u64, target: u64, pages: usize) -> AllocationPolicy {
    let mut result = AllocationPolicy::near(pc).unwrap();
    result.ranges = vec![range(target & !4095, pages * 4096)];
    result.preferred_address = Some(target);
    result.max_candidates = 256;
    result
}
fn pun_window(base: u64, c: &Case, overlay: &[u8]) -> AddressRange {
    let free = c.length - c.prefixes - 1;
    let mut word = [0_u8; 4];
    word[free..].copy_from_slice(&overlay[c.selected + c.length..c.selected + 5 + c.prefixes]);
    range(
        add_signed(
            base + c.selected as u64 + 5 + c.prefixes as u64,
            i32::from_le_bytes(word),
        ),
        1_usize << (8 * free),
    )
}
fn entries(identity: CodeIdentity, scope: AddressRange, heads: &[u64], cet: bool) -> LegalEntrySet {
    LegalEntrySet {
        identity,
        scope,
        provenance: EntryProvenance::Declared("frozen campaign literal original heads".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: heads
            .iter()
            .copied()
            .filter(|pc| scope.contains(*pc))
            .map(|address| LegalEntry {
                address,
                requires_endbr: cet && address == scope.start(),
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    }
}
fn e9(pc: u64, target: u64) -> Vec<u8> {
    let mut result = vec![0xe9];
    result.extend_from_slice(
        &i32::try_from(i128::from(target) - i128::from(pc + 5))
            .unwrap()
            .to_le_bytes(),
    );
    result
}

struct Prepared {
    bundle: PlannedBundle,
    controls: Vec<ProbeControl>,
    hook_pcs: Vec<u64>,
    neighbor: Option<NeighborGeometry>,
}

fn prepare(
    c: &Case,
    base: u64,
    identity: CodeIdentity,
    heads: &[u64],
    log: &Recorder,
) -> Result<Prepared, Refusal> {
    let start = Instant::now();
    let selected = base + c.selected as u64;
    let mut overlay = c.code.to_vec();
    let ordinary = (base & !4095) + c.selected_delta;
    let mut target = ordinary;
    let mut victim_target = (base & !4095) + c.victim_delta;
    if c.target_kind == "successor" {
        let victim = base + c.victim.unwrap() as u64;
        victim_target = add_signed(victim + 5, c.victim_delta as i32);
        overlay[c.victim.unwrap()..c.victim.unwrap() + 5]
            .copy_from_slice(&e9(victim, victim_target));
    }
    let window = if matches!(c.target_kind, "pun" | "successor") {
        let window = pun_window(base, c, &overlay);
        target = window.start() + window.len() / 2;
        Some(window)
    } else {
        None
    };
    let mut selected_allocation = allocation(selected, target, 2);
    if c.target_kind == "ordinary" && c.expected != "ownership_refusal_then_replan_positive" {
        selected_allocation.ranges = vec![range((target & !4095) - 4096, 3 * 4096)];
    }
    if c.expected == "allocation_refusal" {
        selected_allocation = allocation(selected, ordinary, 1);
        assert!(
            !selected_allocation.ranges[0].overlaps(window.unwrap()),
            "negative window must be independently disjoint"
        );
    }
    let victim_allocation = allocation(base + c.victim.unwrap_or(0) as u64, victim_target, 2);
    // Ownership's primary snapshot intentionally excludes its preceding B2
    // writer. Matching original bytes must reach the actual ownership check.
    let read_start = if c.family == "ownership" { 2 } else { 0 };
    let source = range(base + read_start as u64, c.code.len() - read_start);
    let entry_set = entries(identity, source, heads, c.expected == "cet_refusal");
    let request = InstallRequest {
        identity,
        code: &c.code[read_start..],
        base_address: source.start(),
        function: source,
        block: range(base + c.block.0 as u64, c.block.1 - c.block.0),
        logical_pc: selected,
        entries: &entry_set,
        hook: hook_a,
        semantics: HookSemantics::Observe,
        allocation: &selected_allocation,
        search: SearchPolicy {
            max_upstream_bytes: if c.physical < c.selected {
                c.selected - c.physical
            } else {
                0
            },
            max_displaced_bytes: 80,
            max_sites: if c.physical < c.selected { 2 } else { 1 },
            ..SearchPolicy::default()
        },
    };
    if c.target_kind == "successor" {
        let direct = plan_install_detailed(&InstallRequest {
            search: SearchPolicy {
                tactics: if c.prefixes == 0 {
                    TacticPolicy::GeneralizedPunOnly
                } else {
                    TacticPolicy::PrefixPunOnly
                },
                ..request.search
            },
            ..request
        })
        .unwrap_err();
        log.line(format!("required_direct_pun_refusal={direct:?}"));
        assert_eq!(direct.reason, Refusal::AllocationUnavailable);
        assert!(!selected_allocation.ranges[0].overlaps(pun_window(base, c, c.code)));
    }
    if c.target_kind == "controlled" {
        let controls: Vec<_> = c
            .actions
            .iter()
            .enumerate()
            .map(|(i, _)| ProbeControl::new(CALLBACKS[i], false))
            .collect();
        let mut originals = Vec::new();
        let mut members = Vec::new();
        let mut first_action = 0;
        for (index, &(first, end, last_action_end)) in c.functions.iter().enumerate() {
            let function = range(base + first as u64, end - first);
            let owned_entries = entries(identity, function, heads, false);
            let target = (base & !4095) + 0x10000000 + index as u64 * 0x08000800;
            let policy = allocation(function.start(), target, 1);
            let actions: Vec<_> = c
                .actions
                .iter()
                .enumerate()
                .filter(|(_, pc)| **pc >= first && **pc < end)
                .map(|(i, pc)| ControlledAction {
                    logical_pc: base + *pc as u64,
                    control: controls[i].clone(),
                })
                .collect();
            let member = plan_coalesced_detailed(
                &InstallRequest {
                    identity,
                    code: &c.code[first..end],
                    base_address: function.start(),
                    function,
                    block: function,
                    logical_pc: function.start(),
                    entries: &owned_entries,
                    hook: CALLBACKS[first_action],
                    semantics: HookSemantics::Observe,
                    allocation: &policy,
                    search: SearchPolicy {
                        max_upstream_bytes: 0,
                        max_sites: 1,
                        ..SearchPolicy::default()
                    },
                },
                &actions,
            )
            .map_err(|failure| {
                log.line(format!("coalesced_failure={failure:?}"));
                failure.reason
            })?;
            log.line(format!("coalesced_metrics={:?}", member.metrics()));
            assert_eq!(member.image().address(), target);
            assert!(member.image().bytes().len() <= 2048);
            assert_eq!(
                member.plan().parts().displaced,
                range(function.start(), last_action_end - first)
            );
            originals.push(ExpectedBytes {
                address: function.start(),
                bytes: c.code[first..end].to_vec(),
            });
            first_action += actions.len();
            members.push(member);
        }
        let grouped = c.family == "grouped";
        let bundle = if grouped {
            PlannedBundle::compose_grouped(
                originals,
                members,
                BundleBudget::default(),
                GroupingBudget {
                    max_mappings: 2,
                    max_virtual_pages: 2,
                    max_virtual_bytes: 8192,
                    max_backing_bytes: 4096,
                    ..GroupingBudget::default()
                },
            )
        } else {
            PlannedBundle::compose(originals, members, BundleBudget::default())
        }?;
        if grouped {
            let grouping = bundle.grouping().unwrap();
            assert_eq!(grouping.groups().len(), 1);
            assert_eq!(grouping.groups()[0].kind(), BackingKind::SharedPage);
            assert_eq!(
                (
                    grouping.memory().virtual_pages,
                    grouping.memory().backing_pages
                ),
                (2, 1)
            );
            assert_eq!(
                (
                    grouping.memory().virtual_bytes,
                    grouping.memory().backing_bytes
                ),
                (8192, 4096)
            );
        }
        log.line(format!(
            "planning_ns={}; memory={:?}; search_classification=unknown",
            start.elapsed().as_nanos(),
            bundle.plan().memory()
        ));
        log.line(format!("bundle_plan={:?}", bundle.plan()));
        return Ok(Prepared {
            bundle,
            controls,
            hook_pcs: c.actions.iter().map(|pc| base + *pc as u64).collect(),
            neighbor: None,
        });
    }
    let result = engine::plan(
        &request,
        &victim_allocation,
        EnginePolicy {
            forced: Some(c.forced),
            successor_puns: if c.prefixes == 0 {
                TacticPolicy::GeneralizedPunOnly
            } else {
                TacticPolicy::PrefixPunOnly
            },
            neighbor: NeighborSearch {
                forced_victim: c.victim.map(|pc| base + pc as u64),
                max_victims: 1,
                max_pairs: 1,
            },
            bundle: BundleBudget::default(),
        },
    );
    let plan = match result {
        Ok(plan) => plan,
        Err(failure) => {
            log.line(format!(
                "planning_ns={}; failure={failure:?}; search_classification=unknown",
                start.elapsed().as_nanos()
            ));
            return Err(failure.reason);
        }
    };
    log.line(format!(
        "planning_ns={}; attempts={:?}; metrics={:?}; memory={:?}; search_classification=unknown",
        start.elapsed().as_nanos(),
        plan.attempts(),
        plan.metrics(),
        plan.bundle().plan().memory()
    ));
    assert_eq!(
        plan.tactic(),
        c.forced,
        "a refusal/fallback never qualifies a forced positive"
    );
    let bundle = plan.bundle().clone();
    log.line(format!("bundle_plan={:?}", bundle.plan()));
    let neighbor = if let engine::SelectedMetrics::Neighbor(geometry, metrics) = plan.metrics() {
        assert_eq!(
            (geometry.selected_len, geometry.victim_len),
            (c.length, c.victim_len)
        );
        assert_eq!(geometry.selected, selected);
        assert_eq!(geometry.victim, base + c.victim.unwrap() as u64);
        assert_eq!(geometry.relay, geometry.victim + 5);
        assert_eq!(
            geometry.rel8,
            i8::try_from(i128::from(geometry.relay) - i128::from(selected + 2)).unwrap()
        );
        assert_eq!(geometry.selected_target, target);
        assert_eq!(geometry.victim_target, victim_target);
        assert_eq!(
            (
                metrics.selected_fallthrough_redirects,
                metrics.victim_fallthrough_redirects
            ),
            (3, 2)
        );
        assert!(
            bundle.plan().steps()[0].parts().physical_pc
                > bundle.plan().steps()[1].parts().physical_pc
        );
        Some(*geometry)
    } else {
        None
    };
    let step = bundle
        .plan()
        .steps()
        .iter()
        .find(|p| p.parts().logical_pc == selected)
        .unwrap()
        .parts();
    assert_eq!(step.physical_pc, base + c.physical as u64);
    match c.forced {
        Tactic::GeneralizedPun | Tactic::PrefixedPun | Tactic::SuccessorEviction => {
            let (length, prefixes, consumed, actual_window) = match &step.kind {
                PlanKind::GeneralizedPun(p) => {
                    (p.instruction_len as usize, 0, p.consumed, p.target_window)
                }
                PlanKind::PrefixedPun(p) => (
                    p.instruction_len as usize,
                    p.prefix_count as usize,
                    p.consumed,
                    p.target_window,
                ),
                other => panic!("pun changed kind: {other:?}"),
            };
            assert_eq!((length, prefixes), (c.length, c.prefixes));
            assert_eq!(consumed, range(selected, 5 + c.prefixes));
            assert_eq!(actual_window, window.unwrap());
            assert_eq!(step.writes.len(), 1);
            assert_eq!(step.writes[0].bytes.len(), c.length);
            assert_eq!(&step.writes[0].bytes[..c.prefixes], vec![0x2e; c.prefixes]);
            assert_eq!(step.writes[0].bytes[c.prefixes], 0xe9);
            overlay[c.selected..c.selected + c.length].copy_from_slice(&step.writes[0].bytes);
            assert_eq!(
                add_signed(
                    selected + 5 + c.prefixes as u64,
                    i32::from_le_bytes(
                        overlay[c.selected + c.prefixes + 1..c.selected + c.prefixes + 5]
                            .try_into()
                            .unwrap()
                    )
                ),
                target
            );
        }
        Tactic::Relocation => assert!(matches!(step.kind, PlanKind::Relocation)),
        Tactic::NeighborEviction => {
            let g = neighbor.unwrap();
            assert!(matches!(step.kind, PlanKind::Relocation));
            assert_eq!(step.writes[0].bytes, [0xeb, g.rel8 as u8]);
            let victim = bundle
                .plan()
                .steps()
                .iter()
                .find(|p| p.parts().physical_pc == g.victim)
                .unwrap();
            let mut exact = e9(g.victim, g.victim_target);
            exact.extend(e9(g.relay, g.selected_target));
            assert_eq!(victim.parts().writes[0].bytes, exact);
        }
    }
    if c.target_kind == "successor" {
        assert_eq!(bundle.plan().steps().len(), 2);
        let victim = &bundle.plan().steps()[0].parts();
        assert_eq!(victim.physical_pc, base + c.victim.unwrap() as u64);
        assert_eq!(victim.displaced.len(), c.victim_len as u64);
        assert_eq!(
            victim.writes[0].bytes,
            e9(victim.physical_pc, victim_target)
        );
    }
    Ok(Prepared {
        bundle,
        controls: vec![],
        hook_pcs: vec![selected],
        neighbor,
    })
}

fn trace_map(prepared: &Prepared, heads: &[u64], terminal: u64) -> (TraceMap, Vec<u64>) {
    let mut map = TraceMap::default();
    let moved: std::collections::BTreeSet<_> = prepared
        .bundle
        .images()
        .iter()
        .flat_map(|i| i.instruction_boundaries().iter().map(|p| p.0))
        .collect();
    map.boundaries.extend(
        heads
            .iter()
            .copied()
            .filter(|pc| !moved.contains(pc))
            .chain([terminal])
            .map(|pc| (pc, pc)),
    );
    for image in prepared.bundle.images() {
        map.boundaries
            .extend_from_slice(image.instruction_boundaries());
        map.generated_ranges
            .push(image.address()..image.address() + image.bytes().len() as u64);
    }
    let mut routed = Vec::new();
    for step in prepared.bundle.plan().steps() {
        map.gateways.push(step.parts().physical_pc);
        for obligation in &step.parts().obligations {
            match obligation {
                EntryObligation::Routed(route) => {
                    assert!(prepared.bundle.images().iter().any(|image| {
                        image
                            .entry_routes()
                            .contains(&(route.original, route.generated))
                    }));
                    map.gateways.push(route.original);
                    routed.push(route.original);
                }
                EntryObligation::Preserved(_) => {}
                EntryObligation::Unresolved { .. } => panic!("unresolved original entry"),
            }
        }
    }
    map.gateways.sort_unstable();
    map.gateways.dedup();
    routed.sort_unstable();
    routed.dedup();
    (map, routed)
}
fn set_mask(controls: &[ProbeControl], mask: usize, snapshots: &[(u64, Vec<u8>)]) {
    for (index, control) in controls.iter().enumerate() {
        let before: Vec<_> = controls.iter().map(ProbeControl::is_enabled).collect();
        check_bytes(snapshots);
        control.clone().set_enabled(mask & (1 << index) != 0);
        check_bytes(snapshots);
        for (other, actual) in controls.iter().enumerate() {
            assert_eq!(
                actual.is_enabled(),
                if other == index {
                    mask & (1 << index) != 0
                } else {
                    before[other]
                }
            );
        }
    }
}
fn publish(
    oracle: &mut NativeOracle,
    identity: CodeIdentity,
    source: AddressRange,
    bundle: &PlannedBundle,
) -> Result<InstalledBundle, liteinst2::contracts::PublicationFailure> {
    let page = oracle.code.address();
    let pointer = (source.start()) as usize as *mut u8;
    let alias = unsafe { WritableAlias::new(source, pointer) }.unwrap();
    let mut lease = unsafe { QuiescenceLease::new(oracle, identity, vec![source]) };
    permissions(page, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    let result = unsafe {
        bundle.publish_with(&[alias], &mut lease, || {
            permissions(page, libc::PROT_READ | libc::PROT_EXEC)
        })
    };
    if result.is_err() {
        assert!(!lease.is_poisoned());
        permissions(page, libc::PROT_READ | libc::PROT_EXEC).unwrap();
    }
    result.map(|(installed, receipt)| {
        assert_eq!(receipt.plan().steps(), bundle.plan().steps());
        installed
    })
}
fn retire(
    oracle: &mut NativeOracle,
    identity: CodeIdentity,
    source: AddressRange,
    bundle: &PlannedBundle,
    installed: &mut InstalledBundle,
) {
    let page = oracle.code.address();
    let mut drain = vec![source];
    drain.extend(
        bundle
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    let mut lease = unsafe { QuiescenceLease::new(oracle, identity, drain) };
    permissions(page, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    unsafe {
        installed.retire_with(&mut lease, || {
            permissions(page, libc::PROT_READ | libc::PROT_EXEC)
        })
    }
    .unwrap();
    assert!(!lease.is_poisoned());
}

fn cycle(
    c: &Case,
    oracle: &mut NativeOracle,
    base: u64,
    identity: CodeIdentity,
    heads: &[u64],
    originals: &[(u64, NativeTrace)],
    prepared: &Prepared,
    log: &Recorder,
    label: &str,
) -> (usize, usize, usize) {
    let source = range(base, c.code.len());
    let (map, routed) = trace_map(prepared, heads, oracle.return_pc());
    let relays: Vec<_> = prepared
        .neighbor
        .iter()
        .map(|g| SourceRelay {
            logical_pc: g.selected,
            relay_pc: g.relay,
            target: g.selected_target,
            victim_trace: &originals
                .iter()
                .find(|(entry, _)| *entry == g.victim)
                .unwrap()
                .1,
        })
        .collect();
    let mut installed =
        publish(oracle, identity, source, &prepared.bundle).expect("required publication failed");
    let edits: Vec<_> = prepared
        .bundle
        .plan()
        .steps()
        .iter()
        .flat_map(|p| {
            p.parts()
                .writes
                .iter()
                .map(|e| (e.address, e.bytes.clone()))
        })
        .collect();
    oracle.assert_publication(&edits);
    let mut immutable = vec![(oracle.code.address(), bytes(oracle.code.address(), 4096))];
    log.bytes(&format!("{label}-source-installed.bin"), &immutable[0].1);
    for (index, allocation) in prepared
        .bundle
        .plan()
        .steps()
        .iter()
        .flat_map(|p| &p.parts().allocations)
        .enumerate()
    {
        let snapshot = bytes(allocation.range.start(), allocation.range.len() as usize);
        log.bytes(&format!("{label}-image-{index}.bin"), &snapshot);
        immutable.push((allocation.range.start(), snapshot));
    }
    for image in prepared.bundle.images() {
        assert_eq!(bytes(image.address(), image.bytes().len()), image.bytes());
    }
    if prepared.bundle.grouping().is_some() {
        assert_eq!(immutable.len(), 3);
        assert_eq!(immutable[1].1, immutable[2].1);
        for image in &immutable[1..] {
            assert_eq!(
                unsafe {
                    libc::mprotect(
                        image.0 as usize as *mut _,
                        image.1.len(),
                        libc::PROT_READ | libc::PROT_WRITE,
                    )
                },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EACCES)
            );
        }
    }
    memory_observation(log, &format!("{label}-installed"), &prepared.bundle);
    let masks = if prepared.controls.is_empty() {
        1
    } else {
        1 << prepared.controls.len()
    };
    let hook_log = HookEventLog::new();
    let mut comparisons = 0;
    let mut verified_events = 0;
    let mut mask_inventory = 0_u64;
    for index in 0..masks {
        let mask = index ^ (index >> 1);
        assert_eq!(mask_inventory & (1 << mask), 0);
        mask_inventory |= 1 << mask;
        set_mask(&prepared.controls, mask, &immutable);
        let enabled: Vec<_> = prepared
            .hook_pcs
            .iter()
            .enumerate()
            .filter(|(i, _)| prepared.controls.is_empty() || mask & (1 << i) != 0)
            .map(|(i, pc)| HookEvent {
                probe_id: i as u64 + 1,
                logical_pc: *pc,
            })
            .collect();
        for (entry, trace) in originals {
            log.line(format!(
                "trace phase={label}-installed mask={mask} entry={:#x}",
                entry - base
            ));
            oracle.assert_trace_with_relays(
                trace,
                *entry,
                &map,
                &relays,
                &routed,
                Some(HookExpectation {
                    log: &hook_log,
                    enabled: &enabled,
                }),
            );
            comparisons += 1;
            verified_events += trace
                .visits()
                .iter()
                .filter(|pc| enabled.iter().any(|event| event.logical_pc == **pc))
                .count();
            check_bytes(&immutable);
        }
    }
    assert_eq!(
        mask_inventory,
        if masks == 64 {
            u64::MAX
        } else {
            (1_u64 << masks) - 1
        }
    );
    retire(oracle, identity, source, &prepared.bundle, &mut installed);
    oracle.assert_publication(&[]);
    check_bytes(&immutable[1..]);
    let original_map = TraceMap {
        boundaries: heads
            .iter()
            .copied()
            .chain([oracle.return_pc()])
            .map(|pc| (pc, pc))
            .collect(),
        ..TraceMap::default()
    };
    for (entry, trace) in originals {
        log.line(format!(
            "trace phase={label}-retired entry={:#x}",
            entry - base
        ));
        oracle.assert_trace(
            trace,
            *entry,
            &original_map,
            &[],
            Some(HookExpectation {
                log: &hook_log,
                enabled: &[],
            }),
        );
        oracle.assert_publication(&[]);
        check_bytes(&immutable[1..]);
    }
    memory_observation(log, &format!("{label}-retired"), &prepared.bundle);
    log.line(format!("cycle={label} installed={comparisons} retired={} verified_events={verified_events} mask_inventory={mask_inventory:#x}",originals.len()));
    (comparisons, originals.len(), verified_events)
}

fn owner(c: &Case, base: u64, identity: CodeIdentity, heads: &[u64]) -> Prepared {
    let source = range(base, 7);
    let entry_set = entries(identity, source, heads, false);
    let free = 1;
    let mut word = [0_u8; 4];
    word[free..].copy_from_slice(&c.code[2..5]);
    word[0] = 128;
    let target = add_signed(base + 5, i32::from_le_bytes(word));
    let policy = allocation(base, target, 2);
    let plan = plan_install_detailed(&InstallRequest {
        identity,
        code: &c.code[..7],
        base_address: base,
        function: source,
        block: range(base, 2),
        logical_pc: base,
        entries: &entry_set,
        hook: hook_a,
        semantics: HookSemantics::Observe,
        allocation: &policy,
        search: SearchPolicy {
            tactics: TacticPolicy::GeneralizedPunOnly,
            max_upstream_bytes: 0,
            max_displaced_bytes: 2,
            max_sites: 1,
        },
    })
    .expect("required preserved-byte B2 owner refused");
    assert!(matches!(
        plan.plan().parts().kind,
        PlanKind::GeneralizedPun(_)
    ));
    assert_eq!(plan.plan().parts().writes[0].bytes.len(), 2);
    let bundle = PlannedBundle::compose(
        vec![ExpectedBytes {
            address: base,
            bytes: c.code[..7].to_vec(),
        }],
        vec![plan],
        BundleBudget::default(),
    )
    .unwrap();
    Prepared {
        bundle,
        controls: vec![],
        hook_pcs: vec![base],
        neighbor: None,
    }
}

fn run(c: &Case, log: &Recorder) {
    let started = Instant::now();
    assert_eq!(c.heads.len(), c.paths.len());
    assert_eq!(
        c.masks,
        if c.actions.is_empty() {
            1
        } else {
            1 << c.actions.len()
        }
    );
    let mut code = vec![0xcc; c.alignment];
    code.extend_from_slice(c.code);
    let mut oracle = NativeOracle::with_seeded_memory_and_flags(&code, c.memory_seed);
    let base = oracle.code.address() + c.alignment as u64;
    let source = range(base, c.code.len());
    let heads: Vec<_> = c.heads.iter().map(|pc| base + *pc as u64).collect();
    let mut source_id = [0_u8; 32];
    source_id[..8].copy_from_slice(&(c.id as u64).to_le_bytes());
    source_id[8..16].copy_from_slice(&c.states[0].to_le_bytes());
    source_id[16..24].copy_from_slice(&c.states[1].to_le_bytes());
    source_id[24..].copy_from_slice(b"A2CAMP01");
    let identity = CodeIdentity {
        source: SourceIdentity(source_id),
        mapping: oracle.code.address(),
        generation: 1,
    };
    log.line(format!("started id={} family={} expected={} input_sha256={} states={:x?} original_base={base:#x} source_identity={identity:?}",c.id,c.family,c.expected,c.input_sha256,c.states));
    log.line(format!(
        "memory_seed={:#x} arithmetic_flags={:x?} memory_prng=splitmix64-le-chunks-v1",
        c.memory_seed,
        c.states.map(|seed| 0x202 | (seed & 0xcd5))
    ));
    log.bytes("source-original.bin", &bytes(oracle.code.address(), 4096));
    let mut originals = Vec::new();
    for seed in c.states {
        for ((&entry, &offset), expected) in heads.iter().zip(c.heads).zip(c.paths) {
            log.line(format!(
                "trace phase=original seed={seed:#x} entry={offset:#x}"
            ));
            let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
            assert_eq!(
                trace.visits(),
                expected
                    .iter()
                    .map(|pc| base + *pc as u64)
                    .chain([oracle.return_pc()])
                    .collect::<Vec<_>>()
            );
            originals.push((entry, trace));
        }
    }
    // Actual occupied holes are part of the frozen ordinary-placement grammar.
    // No allocation probing, reseeding, fixture removal or adaptive retry.
    let mut holes = Vec::new();
    if c.target_kind == "ordinary" && c.family != "ownership" {
        let target = (oracle.code.address() + c.selected_delta) & !4095;
        for page in [target - 4096, target + 4096] {
            holes.push(Occupied::new(page, 4096));
        }
    }
    let prepared = prepare(c, base, identity, &heads, log);
    if matches!(
        c.expected,
        "allocation_refusal" | "call_refusal" | "cet_refusal"
    ) {
        let reason = match prepared {
            Ok(_) => panic!("declared negative unexpectedly planned"),
            Err(reason) => reason,
        };
        if c.expected == "allocation_refusal" {
            assert_eq!(reason, Refusal::AllocationUnavailable)
        } else if c.expected == "call_refusal" {
            assert_eq!(
                reason,
                Refusal::UnsupportedSemantics(
                    "Call has no qualified A1 relocation contract".into()
                )
            );
        } else {
            assert_eq!(
                reason,
                Refusal::UnsupportedSemantics("CET IBT landing pad in displaced range".into())
            );
        }
        let map = TraceMap {
            boundaries: heads
                .iter()
                .copied()
                .chain([oracle.return_pc()])
                .map(|pc| (pc, pc))
                .collect(),
            ..TraceMap::default()
        };
        let hook_log = HookEventLog::new();
        for (entry, trace) in &originals {
            oracle.assert_trace(
                trace,
                *entry,
                &map,
                &[],
                Some(HookExpectation {
                    log: &hook_log,
                    enabled: &[],
                }),
            );
        }
        oracle.assert_publication(&[]);
        log.line(format!("complete outcome=expected_refusal reason={reason:?} primary_installed=0 primary_retired=0 original_preservation={} elapsed_ns={} search_classification=unknown",originals.len(),started.elapsed().as_nanos()));
        return;
    }
    let mut prepared =
        prepared.unwrap_or_else(|reason| panic!("required positive refused: {reason:?}"));
    if c.family == "collision" {
        let allocation = prepared.bundle.plan().steps()[0].parts().allocations[0].range;
        let collision = Occupied::new(allocation.start(), allocation.len() as usize);
        let before = bytes(oracle.code.address(), 4096);
        let backing_before = private_backing_resources();
        let error = publish(&mut oracle, identity, source, &prepared.bundle)
            .err()
            .expect("occupied alias was accepted");
        assert_eq!(
            (error.stage, error.reason),
            (
                FailureStage::BeforeWrite,
                Refusal::Backend(
                    TrampolineError::ExactAddressUnavailable {
                        address: prepared.bundle.images()[0].address(),
                    }
                    .to_string()
                )
            )
        );
        assert_eq!(bytes(oracle.code.address(), 4096), before);
        assert_eq!(
            private_backing_resources(),
            backing_before,
            "failed staging leaked private backing mappings or descriptors"
        );
        for image in prepared.bundle.images() {
            for mapping in image.program_counter_mappings() {
                assert_eq!(translate_program_counter(mapping.generated_start()), None);
            }
        }
        oracle.assert_publication(&[]);
        log.line("required_negative=allocation_collision stage=BeforeWrite source_unchanged=true same_plan_retry=true");
        drop(collision);
        let mut residency = vec![0; allocation.len() as usize / 4096];
        assert_eq!(
            unsafe {
                libc::mincore(
                    allocation.start() as usize as *mut _,
                    allocation.len() as usize,
                    residency.as_mut_ptr(),
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOMEM)
        );
    }
    let mut auxiliary = (0, 0, 0);
    if c.family == "ownership" {
        let prior = owner(c, base, identity, &heads);
        // Publish a real owner; its unchanged consumed suffix authenticates the
        // blocked planner's entire body snapshot. No stale-byte substitute.
        let mut installed = publish(&mut oracle, identity, source, &prior.bundle).unwrap();
        let owner_edits: Vec<_> = prior
            .bundle
            .plan()
            .steps()
            .iter()
            .flat_map(|step| {
                step.parts()
                    .writes
                    .iter()
                    .map(|edit| (edit.address, edit.bytes.clone()))
            })
            .collect();
        oracle.assert_publication(&owner_edits);
        let mut owner_immutable = vec![(oracle.code.address(), bytes(oracle.code.address(), 4096))];
        log.bytes("owner-source-installed.bin", &owner_immutable[0].1);
        for (index, allocation) in prior
            .bundle
            .plan()
            .steps()
            .iter()
            .flat_map(|step| &step.parts().allocations)
            .enumerate()
        {
            let snapshot = bytes(allocation.range.start(), allocation.range.len() as usize);
            log.bytes(&format!("owner-image-{index}.bin"), &snapshot);
            owner_immutable.push((allocation.range.start(), snapshot));
        }
        for image in prior.bundle.images() {
            assert_eq!(bytes(image.address(), image.bytes().len()), image.bytes());
        }
        memory_observation(log, "owner-installed", &prior.bundle);
        for snapshot in prepared.bundle.plan().originals() {
            assert_eq!(
                bytes(snapshot.address, snapshot.bytes.len()),
                snapshot.bytes
            );
        }
        let before = bytes(oracle.code.address(), 4096);
        let error = publish(&mut oracle, identity, source, &prepared.bundle)
            .err()
            .expect("owned read bytes were accepted");
        assert_eq!(
            (error.stage, error.reason),
            (FailureStage::BeforeWrite, Refusal::OwnershipConflict)
        );
        assert_eq!(bytes(oracle.code.address(), 4096), before);
        log.line("required_negative=preserved_pun_byte_ownership stage=BeforeWrite matching_snapshot=true source_unchanged=true");
        // Native owner traces must run while the actual negative-producing owner
        // is installed; then its retirement is checked against each original.
        let (map, routed) = trace_map(&prior, &heads, oracle.return_pc());
        let hooks = HookEventLog::new();
        for (entry, trace) in &originals {
            oracle.assert_trace(
                trace,
                *entry,
                &map,
                &routed,
                Some(HookExpectation {
                    log: &hooks,
                    enabled: &[HookEvent {
                        probe_id: 1,
                        logical_pc: base,
                    }],
                }),
            );
            auxiliary.0 += 1;
            auxiliary.2 += trace.visits().iter().filter(|pc| **pc == base).count();
            check_bytes(&owner_immutable);
        }
        retire(&mut oracle, identity, source, &prior.bundle, &mut installed);
        oracle.assert_publication(&[]);
        let map = TraceMap {
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
                &map,
                &[],
                Some(HookExpectation {
                    log: &hooks,
                    enabled: &[],
                }),
            );
            auxiliary.1 += 1;
            check_bytes(&owner_immutable[1..]);
            oracle.assert_publication(&[]);
        }
        memory_observation(log, "owner-retired", &prior.bundle);
        prepared = prepare(c, base, identity, &heads, log)
            .expect("required replan after owner retirement refused");
    }
    let primary = cycle(
        c,
        &mut oracle,
        base,
        identity,
        &heads,
        &originals,
        &prepared,
        log,
        "primary",
    );
    assert_eq!(
        (primary.0, primary.1),
        (c.expected_installed, c.expected_retired)
    );
    assert_eq!(primary.2, c.expected_events);
    assert_eq!(auxiliary.2, if c.family == "ownership" { 2 } else { 0 });
    assert_eq!(
        (auxiliary.0, auxiliary.1),
        if c.family == "ownership" {
            (originals.len(), originals.len())
        } else {
            (0, 0)
        }
    );
    log.line(format!("complete outcome={} primary_installed={} primary_retired={} auxiliary_installed={} auxiliary_retired={} verified_primary_events={} verified_auxiliary_events={} elapsed_ns={} search_classification=unknown",
                     c.expected,primary.0,primary.1,auxiliary.0,auxiliary.1,primary.2,auxiliary.2,started.elapsed().as_nanos()));
}

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(
        arguments.len(),
        3,
        "usage: campaign-frozen CASE_ID PRIVATE_RESULT_DIRECTORY"
    );
    assert_eq!(
        std::env::var("LITEINST_A2_CAMPAIGN_REVIEWED").as_deref(),
        Ok("frozen-v1"),
        "draft campaign must not execute before independent review and manifest freeze"
    );
    let id: usize = arguments[1].parse().unwrap();
    let c = CASES
        .iter()
        .chain(SAMPLES)
        .find(|case| case.id == id)
        .expect("ID absent from fixed 544-input denominator");
    assert_eq!((CASES.len(), SAMPLES.len()), (512, 32));
    let directory = Path::new(&arguments[2]);
    fs::create_dir(directory)
        .expect("result directory must be new; failure evidence cannot be overwritten");
    let log = Recorder(directory.to_path_buf());
    // The external frozen runner owns cgroup CPU/memory/PID/wall containment and
    // stderr/stdout receipts. This process never forks concurrent seed workers;
    // the unchanged oracle permits at most one tracing child at a time.
    run(c, &log);
}
