#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Finite exact compiled-function core-bundle oracle, not a loaded SDK state proof.
#[path = "support/compiled_selected_fixtures.rs"]
mod fixture;
#[path = "support/isolated_native_test.rs"]
mod isolated_native_test;
#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::bundle::{BundleBudget, PlannedBundle, WritableAlias};
use liteinst2::composition::Composition;
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, ExpectedBytes,
    LegalEntry, LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation,
    SourceIdentity,
};
use liteinst2::controls::{ControlIdentity, ControlledAction, ProbeControl};
use liteinst2::quiescent::{
    AllocationPolicy, WholeFunctionRequest, plan_whole_function_controlled_detailed_after,
};
use liteinst2::trampoline::{HookContext, translate_program_counter};
use oracle::{
    CompiledLeafExpectation, HookEvent, HookEventLog, HookExpectation, NativeOracle, TraceMap,
};
use std::cell::RefCell;

type Role = (ProbeControl, u64, u64); // Owner, exact logical PC, distinct event ID.
thread_local! { static OWNERS: RefCell<Vec<Role>> = const { RefCell::new(Vec::new()) }; }

fn roles_valid(roles: &[Role], pcs: &[u64]) -> bool {
    roles.len() == 6
        && pcs.len() == 6
        && roles.iter().enumerate().all(|(i, role)| {
            role.1 == pcs[i]
                && role.2 == 101 + i as u64
                && roles[..i]
                    .iter()
                    .all(|prior| prior.0 != role.0 && prior.1 != role.1 && prior.2 != role.2)
        })
}

unsafe extern "C" fn observe(context: *mut HookContext, token: ControlIdentity<'_>) {
    // Only immutable owners are retained in TLS; no token/writer escapes dispatch.
    let result = OWNERS.try_with(|owners| {
        let Ok(owners) = owners.try_borrow() else {
            return false;
        };
        let mut matched = owners.iter().filter(|role| role.0.has_identity(token));
        let Some(role) = matched.next() else {
            return false;
        };
        if matched.next().is_some() || context.is_null() {
            return false;
        }
        // SAFETY: generated bound dispatch owns the saved frame and log lifetime.
        unsafe {
            if (*context).instruction_pointer != role.1 {
                return false;
            }
            oracle::record_hook_event(role.2, role.1);
        }
        true
    });
    if !matches!(result, Ok(true)) {
        // SAFETY: terminal test-child refusal; never return an unverified callback.
        unsafe { libc::_exit(121) };
    }
    // SAFETY: deliberately clobber live scratch state, never the saved frame or
    // application memory. The unchanged comparator must observe full restoration.
    unsafe {
        core::arch::asm!(
            "xor eax, eax", "xor r10d, r10d", "xor r11d, r11d", "pxor xmm0, xmm0", "fninit",
            out("rax") _, out("r10") _, out("r11") _, out("xmm0") _, options(nostack),
        );
    }
}

fn permissions(pointer: *mut u8, protection: i32) -> Result<(), Refusal> {
    // SAFETY: exact owned source page, held through the finalizer.
    if unsafe { libc::mprotect(pointer.cast(), 4096, protection) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

fn exclude(policy: &mut AllocationPolicy, held: &[AddressRange]) {
    for &reserved in held {
        policy.ranges = policy
            .ranges
            .iter()
            .flat_map(|&candidate| {
                if !candidate.overlaps(reserved) {
                    return vec![candidate];
                }
                let mut pieces = Vec::new();
                if candidate.start() < reserved.start() {
                    pieces.push(
                        AddressRange::new(
                            candidate.start(),
                            (reserved.start() - candidate.start()) as usize,
                        )
                        .unwrap(),
                    );
                }
                if reserved.end() < candidate.end() {
                    pieces.push(
                        AddressRange::new(
                            reserved.end(),
                            (candidate.end() - reserved.end()) as usize,
                        )
                        .unwrap(),
                    );
                }
                pieces
            })
            .collect();
    }
    assert!(!policy.ranges.is_empty());
    assert!(
        policy
            .ranges
            .iter()
            .all(|r| held.iter().all(|h| !r.overlaps(*h)))
    );
    assert_eq!(
        (
            policy.max_candidates,
            policy.max_mappings,
            policy.max_mapped_bytes
        ),
        (256, 1, 8192)
    );
}

fn owned_bytes(range: AddressRange) -> Vec<u8> {
    // SAFETY: callers retain the complete readable source/generated mapping.
    unsafe {
        std::slice::from_raw_parts(range.start() as usize as *const u8, range.len() as usize)
            .to_vec()
    }
}

#[derive(Clone, Copy)]
enum MappingRole {
    SourcePrivate,
    GeneratedShared,
}

fn mapping_matches(
    owner: (AddressRange, MappingRole),
    actual: AddressRange,
    permissions: &str,
) -> bool {
    actual.covers(owner.0)
        && permissions
            == match owner.1 {
                MappingRole::SourcePrivate => "r-xp",
                MappingRole::GeneratedShared => "r-xs",
            }
}

fn owned_maps(ranges: &[(AddressRange, MappingRole)]) -> Vec<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let rows: Vec<_> = maps
        .lines()
        .filter_map(|line| {
            let (lo, rest) = line.split_once('-').unwrap();
            let hi = rest.split_once(' ').unwrap().0;
            let start = u64::from_str_radix(lo, 16).unwrap();
            let end = u64::from_str_radix(hi, 16).unwrap();
            let range = AddressRange::new(start, (end - start) as usize).unwrap();
            ranges
                .iter()
                .any(|(r, _)| r.overlaps(range))
                .then(|| (range, line.to_owned()))
        })
        .collect();
    for &owner in ranges {
        assert!(rows.iter().any(|(mapped, line)| mapping_matches(
            owner,
            *mapped,
            line.split_whitespace().nth(1).unwrap()
        )));
    }
    rows.into_iter().map(|(_, line)| line).collect()
}

fn run(selected: usize, mask: u8) {
    assert!(selected < 2 && mask < 8);
    let mut retained = Vec::new();
    let mut comparisons = 0;
    let mut boundary_comparisons = 0;
    for (case, input) in fixture::INPUTS.iter().enumerate() {
        let (bytes, setup) = fixture::fixture(input, selected);
        let mut native = NativeOracle::with_seeded_memory_and_flags(&bytes, 0xc011 + case as u64);
        let base = native.code.address();
        let source = AddressRange::new(base, 4096).unwrap();
        assert_eq!(base % 4096, 0);
        let identity = CodeIdentity {
            source: SourceIdentity([0xc1; 32]),
            mapping: case as u64 + 1,
            generation: 1,
        };
        let pcs: Vec<_> = (0..2)
            .flat_map(|f| {
                [0, fixture::RETURNS[f][0], fixture::RETURNS[f][1]]
                    .map(|offset| base + (fixture::OFFSETS[f] + offset) as u64)
            })
            .collect();
        let (controls, mut writers): (Vec<_>, Vec<_>) = (0..6)
            .map(|_| ProbeControl::new_managed_bound(observe, false))
            .unzip();
        let roles: Vec<_> = controls
            .iter()
            .enumerate()
            .map(|(i, c)| (c.clone(), pcs[i], 101 + i as u64))
            .collect();
        assert!(roles_valid(&roles, &pcs));
        OWNERS.with(|owners| {
            assert!(owners.borrow().is_empty());
            *owners.borrow_mut() = roles;
        });
        let originals = vec![ExpectedBytes {
            address: base,
            bytes: owned_bytes(source),
        }];
        let mut composition = Composition::new(identity, originals.clone()).unwrap();
        let mut held = vec![source];
        let mut members = Vec::new();
        for f in 0..2 {
            let entry = base + fixture::OFFSETS[f] as u64;
            let leaf = fixture::BODIES[f];
            let scope = AddressRange::new(entry, leaf.len()).unwrap();
            let entries = LegalEntrySet {
                identity,
                scope,
                provenance: EntryProvenance::Declared("exact d696 compiled scalar body".into()),
                completeness: EntryCompleteness::Complete,
                entries: fixture::LEADERS[f]
                    .iter()
                    .map(|&offset| LegalEntry {
                        address: entry + offset as u64,
                        requires_endbr: false,
                    })
                    .collect(),
                resumes: ResumeObligation::NoneExist,
            };
            let actions: Vec<_> = (f * 3..f * 3 + 3)
                .map(|i| ControlledAction {
                    logical_pc: pcs[i],
                    control: controls[i].clone(),
                })
                .collect();
            let mut allocation = AllocationPolicy::near(entry).unwrap();
            allocation.preferred_address =
                Some(base + 64 * 1024 * 1024 + (case * 2 + f) as u64 * 1024 * 1024);
            exclude(&mut allocation, &held);
            // SAFETY: complete reviewed read-only scalar CFG, all internal leaders
            // and literal RETs; sole external entry, no saved resumes/reentry/CET.
            // Private mappings, data and all callback owners outlive each child.
            let member = unsafe {
                plan_whole_function_controlled_detailed_after(
                    &WholeFunctionRequest {
                        identity,
                        code: leaf,
                        base_address: entry,
                        entries: &entries,
                        allocation: &allocation,
                    },
                    &actions,
                    &composition,
                )
            }
            .expect("required complete compiled function");
            let parts = member.plan().parts();
            assert_eq!(parts.displaced, scope);
            assert_eq!(
                parts.reads,
                [ExpectedBytes {
                    address: entry,
                    bytes: leaf.to_vec()
                }]
            );
            assert_eq!(parts.entries, entries);
            assert!(matches!(parts.kind, PlanKind::Relocation));
            assert_eq!((parts.logical_pc, parts.physical_pc), (entry, entry));
            assert_eq!(parts.writes.len(), 1);
            assert_eq!(
                (parts.writes[0].address, parts.writes[0].bytes.len()),
                (entry, leaf.len())
            );
            assert_eq!(parts.allocations.len(), 1);
            assert!(parts.allocations[0].range.len() <= 8192);
            assert!(held.iter().all(|r| !r.overlaps(parts.allocations[0].range)));
            assert_eq!(member.image().controls(), &controls[f * 3..f * 3 + 3]);
            let heads: Vec<_> = fixture::HEADS[f]
                .iter()
                .map(|&at| entry + at as u64)
                .collect();
            assert_eq!(
                member
                    .image()
                    .instruction_boundaries()
                    .iter()
                    .map(|p| p.0)
                    .collect::<Vec<_>>(),
                heads
            );
            assert_eq!(
                member
                    .image()
                    .entry_routes()
                    .iter()
                    .map(|p| p.0)
                    .collect::<Vec<_>>(),
                heads
            );
            composition.append(member.plan()).unwrap();
            held.extend(parts.allocations.iter().map(|a| a.range));
            members.push(member);
        }
        let bundle = PlannedBundle::compose(
            originals.clone(),
            members,
            BundleBudget {
                max_steps: 10,
                max_mappings: 10,
                max_virtual_bytes: 10 * 8192,
                max_backing_bytes: 10 * 8192,
                max_virtual_span: 1 << 32,
            },
        )
        .unwrap();
        assert_eq!(bundle.plan().steps().len(), 2);
        assert_eq!(bundle.images().len(), 2);
        assert_eq!(bundle.plan().originals(), originals);
        assert_eq!(bundle.plan().final_bytes(), composition.final_bytes());
        assert_eq!(bundle.plan().memory().mappings, 2);
        let edits: Vec<_> = bundle
            .plan()
            .steps()
            .iter()
            .flat_map(|p| &p.parts().writes)
            .map(|e| (e.address, e.bytes.clone()))
            .collect();
        let mut heads: Vec<_> = (0..2)
            .flat_map(|f| {
                fixture::HEADS[f]
                    .iter()
                    .map(move |&at| base + (fixture::OFFSETS[f] + at) as u64)
            })
            .collect();
        heads.extend(setup.iter().map(|&at| base + at as u64));
        heads.sort_unstable();
        assert_eq!(heads.len(), 51);
        let mut map = TraceMap {
            boundaries: bundle
                .images()
                .iter()
                .flat_map(|i| i.instruction_boundaries().iter().copied())
                .collect(),
            gateways: vec![pcs[0], pcs[3]],
            generated_ranges: bundle
                .images()
                .iter()
                .map(|i| i.address()..i.address() + i.bytes().len() as u64)
                .collect(),
        };
        assert_eq!(map.boundaries.len(), 33);
        for pc in heads.iter().copied().chain([native.return_pc()]) {
            if !map.boundaries.iter().any(|&(logical, _)| logical == pc) {
                map.boundaries.push((pc, pc));
            }
            if map
                .boundaries
                .iter()
                .any(|&(logical, physical)| logical == pc && physical == pc)
            {
                let end = heads.iter().copied().find(|&at| at > pc).unwrap_or(pc + 1);
                assert!(
                    edits
                        .iter()
                        .all(|(at, data)| *at >= end || *at + data.len() as u64 <= pc),
                    "entire identity instruction is unchanged"
                );
            }
        }
        let routed: Vec<_> = bundle
            .plan()
            .steps()
            .iter()
            .flat_map(|p| &p.parts().obligations)
            .filter_map(|o| match o {
                EntryObligation::Routed(route) => Some(route.original),
                EntryObligation::Preserved(_) => None,
                EntryObligation::Unresolved { .. } => panic!("unresolved entry"),
            })
            .collect();
        let e = fixture::expected(input, selected);
        let entry = pcs[selected * 3];
        let itinerary: Vec<_> = setup
            .iter()
            .map(|&at| base + at as u64)
            .chain(e.visits.iter().map(|&at| entry + at as u64))
            .chain([native.return_pc()])
            .collect();
        let start = base + fixture::SETUP as u64;
        let mut baselines = Vec::new();
        for seed in fixture::SEEDS {
            let trace = native.trace_original(start, &heads, &[native.return_pc()], seed);
            let expectation = CompiledLeafExpectation {
                entry,
                chosen_return: entry + e.ret as u64,
                seed,
                input,
                itinerary: &itinerary,
                read_indices: &e.reads,
                answer: e.answer,
                uppercase: selected == 1,
            };
            trace.assert_compiled_leaf_state(&expectation);
            if mask == 0 && case == 4 && seed == fixture::SEEDS[0] {
                calibrate(&trace, expectation);
            }
            baselines.push(trace);
        }
        let writable = native.code.writable();
        // SAFETY: complete private source page, no original child remains live.
        let aliases = [unsafe { WritableAlias::new(source, writable) }.unwrap()];
        let mut installed = {
            // SAFETY: exclusive source ownership and no escaped execution/resume.
            let mut lease = unsafe { QuiescenceLease::new(&mut native, identity, vec![source]) };
            permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: staged complete bundle stays excluded until restored RX.
            let (installed, receipt) = unsafe {
                bundle.publish_with(&aliases, &mut lease, || {
                    permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap();
            assert_eq!(receipt.plan().steps(), bundle.plan().steps());
            assert!(!lease.is_poisoned());
            installed
        };
        native.assert_publication(&edits);
        let immutable: Vec<_> = held.iter().map(|&r| (r, owned_bytes(r))).collect();
        assert_eq!(held.len(), 3);
        assert_eq!(held[0], source);
        let mapping_roles: Vec<_> = std::iter::once((source, MappingRole::SourcePrivate))
            .chain(
                held[1..]
                    .iter()
                    .map(|&range| (range, MappingRole::GeneratedShared)),
            )
            .collect();
        let mappings = owned_maps(&mapping_roles);
        let pc_maps: Vec<_> = bundle
            .images()
            .iter()
            .flat_map(|i| i.program_counter_mappings().iter())
            .flat_map(|m| {
                [
                    (m.generated_start(), m.logical_address()),
                    (m.generated_end() - 1, m.logical_address()),
                ]
            })
            .collect();
        let unchanged = || {
            for (range, bytes) in &immutable {
                assert_eq!(owned_bytes(*range), *bytes);
            }
            assert_eq!(owned_maps(&mapping_roles), mappings);
            for &(generated, logical) in &pc_maps {
                assert_eq!(translate_program_counter(generated), Some(logical));
            }
        };
        unchanged();
        let mut states = [false; 6];
        for i in 0..6 {
            let desired = (if i / 3 == selected { mask } else { 7 ^ mask }) & (1 << (i % 3)) != 0;
            writers[i].set_enabled(desired);
            states[i] = desired;
            assert_eq!(
                controls
                    .iter()
                    .map(ProbeControl::is_enabled)
                    .collect::<Vec<_>>(),
                states
            );
            unchanged();
        }
        let events: Vec<_> = [entry, entry + e.ret as u64]
            .into_iter()
            .filter_map(|pc| {
                let i = pcs.iter().position(|&at| at == pc).unwrap();
                states[i].then_some(HookEvent {
                    probe_id: 101 + i as u64,
                    logical_pc: pc,
                })
            })
            .collect();
        assert!(events.len() <= 2);
        let log = HookEventLog::with_capacity(2);
        for trace in &baselines {
            native.assert_trace(
                trace,
                start,
                &map,
                &routed,
                Some(HookExpectation {
                    log: &log,
                    enabled: &events,
                }),
            );
            unchanged();
            comparisons += 1;
            boundary_comparisons += trace.visits().len();
        }
        {
            // SAFETY: every forked trace child reaped; source and all generated
            // allocations/resumes are completely drained by this private owner.
            let mut lease = unsafe { QuiescenceLease::new(&mut native, identity, held.clone()) };
            permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: ownership extends through original bytes, RX and sync-core.
            unsafe {
                installed.retire_with(&mut lease, || {
                    permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap();
            assert!(!lease.is_poisoned());
        }
        assert!(installed.is_retired());
        native.assert_publication(&[]);
        OWNERS.with(|owners| owners.borrow_mut().clear());
        retained.push(native); // Prevent source-address reuse within this process.
    }
    assert_eq!(comparisons, 24);
    assert_eq!(retained.len(), 12);
    assert_eq!(boundary_comparisons, [2712, 4610][selected]);
    eprintln!(
        "COMPILED selected={selected} mask={mask}: 24 required native state comparisons, {boundary_comparisons} ordered boundary comparisons, zero mismatches"
    );
}

fn calibrate(trace: &oracle::NativeTrace, e: CompiledLeafExpectation<'_>) {
    let rejects = |e: &CompiledLeafExpectation<'_>| {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || trace.assert_compiled_leaf_state(e)
            ))
            .is_err()
        );
    };
    rejects(&CompiledLeafExpectation {
        answer: e.answer + 1,
        ..e
    });
    rejects(&CompiledLeafExpectation {
        itinerary: &e.itinerary[1..],
        ..e
    });
    let mut wrong_input = e.input.to_vec();
    wrong_input[0] ^= 1;
    rejects(&CompiledLeafExpectation {
        input: &wrong_input,
        ..e
    });
    rejects(&CompiledLeafExpectation {
        chosen_return: e.chosen_return + 1,
        ..e
    });
}

#[test]
fn distinct_managed_roles_reject_duplicate_owner_wrong_pc_and_event() {
    let pcs = [10, 20, 30, 40, 50, 60];
    let mut roles: Vec<_> = pcs
        .iter()
        .enumerate()
        .map(|(i, &pc)| {
            let (owner, _writer) = ProbeControl::new_managed_bound(observe, false);
            (owner, pc, 101 + i as u64)
        })
        .collect();
    assert!(roles_valid(&roles, &pcs));
    let original = roles[1].clone();
    roles[1].0 = roles[0].0.clone();
    assert!(!roles_valid(&roles, &pcs));
    roles[1] = original.clone();
    roles[1].1 += 1;
    assert!(!roles_valid(&roles, &pcs));
    roles[1] = original;
    roles[1].2 = roles[0].2;
    assert!(!roles_valid(&roles, &pcs));
}

#[test]
fn mapping_roles_reject_swapped_sharing_writes_and_missing_execute() {
    let source = AddressRange::new(0x10000, 4096).unwrap();
    let generated = AddressRange::new(0x20000, 8192).unwrap();
    let cases = [
        (source, MappingRole::SourcePrivate, "r-xp"),
        (generated, MappingRole::GeneratedShared, "r-xs"),
    ];
    for (range, role, correct) in cases {
        assert!(mapping_matches((range, role), range, correct));
        for wrong in [
            "r-xp", "r-xs", "rwxp", "rwxs", "r--p", "r--s", "---p", "---s",
        ] {
            if wrong != correct {
                assert!(!mapping_matches((range, role), range, wrong));
            }
        }
        let truncated = AddressRange::new(range.start(), range.len() as usize - 1).unwrap();
        assert!(!mapping_matches((range, role), truncated, correct));
        assert!(!mapping_matches(
            (range, role),
            AddressRange::new(0x30000, 8192).unwrap(),
            correct
        ));
    }
}

macro_rules! native_case {
    ($name:ident, $selected:expr, $mask:expr) => {
        #[test]
        fn $name() {
            isolated_native_test::run(
                stringify!($name),
                "LITEINST2_COMPILED_SELECTED_ORACLE",
                || run($selected, $mask),
            );
        }
    };
}
native_case!(first_equal_mask_0, 0, 0);
native_case!(first_equal_mask_1, 0, 1);
native_case!(first_equal_mask_2, 0, 2);
native_case!(first_equal_mask_3, 0, 3);
native_case!(first_equal_mask_4, 0, 4);
native_case!(first_equal_mask_5, 0, 5);
native_case!(first_equal_mask_6, 0, 6);
native_case!(first_equal_mask_7, 0, 7);
native_case!(uppercase_count_mask_0, 1, 0);
native_case!(uppercase_count_mask_1, 1, 1);
native_case!(uppercase_count_mask_2, 1, 2);
native_case!(uppercase_count_mask_3, 1, 3);
native_case!(uppercase_count_mask_4, 1, 4);
native_case!(uppercase_count_mask_5, 1, 5);
native_case!(uppercase_count_mask_6, 1, 6);
native_case!(uppercase_count_mask_7, 1, 7);
