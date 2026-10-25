#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Ordered-trace oracle foundation, independent of the future bundle planner.
//! Original heads and expected visits are handwritten. Native ptrace supplies
//! execution semantics; generated-image maps identify restored state only.

#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::{HookCallback, HookContext, TrampolinePlan};
use oracle::{HookEvent, HookEventLog, HookExpectation, Mapping, NativeOracle, TraceMap};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];

fn identity_map(heads: &[u64], terminal: u64) -> TraceMap {
    TraceMap {
        boundaries: heads
            .iter()
            .copied()
            .chain([terminal])
            .map(|pc| (pc, pc))
            .collect(),
        ..TraceMap::default()
    }
}

fn rewrite(oracle: &NativeOracle, offset: usize, bytes: &[u8]) {
    oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
    // SAFETY: this test owns the complete private source page and all children
    // have been reaped. Every rewrite is subsequently checked against its edit.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            oracle.code.writable().add(offset),
            bytes.len(),
        )
    };
    oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
}

#[test]
fn original_trace_steps_between_repeated_identical_pcs() {
    // MOV ECX,3; LOOP self; RET. LOOP preserves flags and decrements RCX even
    // when its target has exactly the same physical PC as the current stop.
    let oracle = NativeOracle::new(&[0xb9, 3, 0, 0, 0, 0xe2, 0xfe, 0xc3]);
    let base = oracle.code.address();
    let heads = [base, base + 5, base + 7];
    for seed in SEEDS {
        let trace = oracle.trace_original(base, &heads, &[oracle.return_pc()], seed);
        assert_eq!(
            trace.visits(),
            [
                base,
                base + 5,
                base + 5,
                base + 5,
                base + 7,
                oracle.return_pc()
            ]
        );
        oracle.assert_trace(
            &trace,
            base,
            &identity_map(&heads, oracle.return_pc()),
            &[],
            None,
        );
    }
}

unsafe extern "C" fn hook_a(context: *mut HookContext) {
    // SAFETY: the emitter supplies the live frame and assert_trace activates
    // this child's private event log before entering any callback.
    unsafe {
        oracle::record_hook_event(10, (*context).instruction_pointer);
        destroy_scratch_state();
    }
}

unsafe extern "C" fn hook_b(context: *mut HookContext) {
    // SAFETY: same emitter-frame and active child-log contract as hook_a.
    unsafe {
        oracle::record_hook_event(20, (*context).instruction_pointer);
        destroy_scratch_state();
    }
}

unsafe fn destroy_scratch_state() {
    // SAFETY: caller-saved integer, flags, XMM and x87 state may be clobbered by
    // a C callback. Restoring application state is the emitter's obligation.
    unsafe {
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

unsafe extern "C" fn missing_hook(_: *mut HookContext) {}

unsafe extern "C" fn duplicate_hook(context: *mut HookContext) {
    // SAFETY: this deliberate mutant records two valid events to the bounded
    // private log. The oracle must detect the extra logical callback.
    unsafe {
        hook_a(context);
        hook_a(context);
    }
}

unsafe extern "C" fn wrong_hook(context: *mut HookContext) {
    // SAFETY: the pointer is live; only the logged logical PC is corrupted.
    unsafe { oracle::record_hook_event(10, (*context).instruction_pointer + 1) };
}

fn multi_image_trace(first_hook: HookCallback) {
    multi_image_trace_with_capacity(first_hook, 128);
}

fn multi_image_trace_with_capacity(first_hook: HookCallback, capacity: usize) {
    // MOV ECX,3; DEC ECX; JNZ DEC; RET. Hook A runs once before MOV; B runs
    // before each of three DEC visits. All modified flags are ISA-defined.
    let code = [0xb9, 3, 0, 0, 0, 0xff, 0xc9, 0x75, 0xfc, 0xc3];
    let oracle = NativeOracle::new(&code);
    let base = oracle.code.address();
    let heads = [base, base + 5, base + 7, base + 9];
    let traces: Vec<_> = SEEDS
        .into_iter()
        .map(|seed| {
            let trace = oracle.trace_original(base, &heads, &[oracle.return_pc()], seed);
            assert_eq!(
                trace.visits(),
                [
                    base,
                    base + 5,
                    base + 7,
                    base + 5,
                    base + 7,
                    base + 5,
                    base + 7,
                    base + 9,
                    oracle.return_pc()
                ]
            );
            trace
        })
        .collect();
    let scan = InstructionScanner::default().scan(&code, base).unwrap();
    let mut maps = TraceMap {
        boundaries: vec![(oracle.return_pc(), oracle.return_pc())],
        gateways: vec![base, base + 5],
        ..TraceMap::default()
    };
    let mut allocations = Vec::new();
    let mut edits = Vec::new();
    for (site, hook) in [(base, first_hook), (base + 5, hook_b as HookCallback)] {
        let memory = Mapping::new(4096);
        let plan = TrampolinePlan::from_scan(&scan, site, hook).unwrap();
        let image = plan.emit_at(memory.address()).unwrap();
        assert!(image.bytes().len() <= 4096);
        // SAFETY: the complete generated image fits this owned writable page;
        // it is made RX before source publication and retained through tracing.
        unsafe {
            core::ptr::copy_nonoverlapping(
                image.bytes().as_ptr(),
                memory.writable(),
                image.bytes().len(),
            )
        };
        memory.protect(libc::PROT_READ | libc::PROT_EXEC);
        maps.boundaries
            .extend_from_slice(image.instruction_boundaries());
        maps.generated_ranges
            .push(memory.address()..memory.address() + image.bytes().len() as u64);
        let displacement =
            i32::try_from(i128::from(memory.address()) - i128::from(site + 5)).unwrap();
        let mut redirect = vec![0xe9];
        redirect.extend_from_slice(&displacement.to_le_bytes());
        rewrite(&oracle, (site - base) as usize, &redirect);
        edits.push((site, redirect));
        allocations.push(memory);
    }
    oracle.assert_publication(&edits);
    let log = HookEventLog::with_capacity(capacity);
    let enabled = [
        HookEvent {
            probe_id: 10,
            logical_pc: base,
        },
        HookEvent {
            probe_id: 20,
            logical_pc: base + 5,
        },
    ];
    for trace in &traces {
        oracle.assert_trace(
            trace,
            base,
            &maps,
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &enabled,
            }),
        );
    }
}

#[test]
fn ordered_trace_compares_two_images_and_multiple_logical_hooks() {
    multi_image_trace(hook_a);
}

#[test]
fn action_images_preserve_state_for_four_masks_and_three_entries() {
    // NOP; LEA RAX,[RDI] (A); ADD BYTE [RDI],1 (B); CMP BYTE [RDI],14;
    // JNE A; RET. The original application byte is 11, so all three entries
    // terminate after three ADDs, independently of the initial register seed.
    let code = [
        0x90, 0x48, 0x8d, 0x07, 0x80, 0x07, 0x01, 0x80, 0x3f, 0x0e, 0x75, 0xf5, 0xc3,
    ];
    let oracle = NativeOracle::new(&code);
    let base = oracle.code.address();
    let heads: Vec<_> = [0, 1, 4, 7, 10, 12].map(|offset| base + offset).into();
    let entry_offsets = [0, 4, 7]; // before A, at B, after B
    let expected_visits = [
        vec![0, 1, 4, 7, 10, 1, 4, 7, 10, 1, 4, 7, 10, 12],
        vec![4, 7, 10, 1, 4, 7, 10, 1, 4, 7, 10, 12],
        vec![7, 10, 1, 4, 7, 10, 1, 4, 7, 10, 1, 4, 7, 10, 12],
    ];
    let mut originals = Vec::new();
    for seed in SEEDS {
        for (index, offset) in entry_offsets.into_iter().enumerate() {
            let entry = base + offset;
            let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
            let mut expected: Vec<_> = expected_visits[index].iter().map(|pc| base + pc).collect();
            expected.push(oracle.return_pc());
            assert_eq!(trace.visits(), expected);
            originals.push((entry, trace));
        }
    }
    let scan = InstructionScanner::default().scan(&code, base).unwrap();
    let log = HookEventLog::new();
    let mut generated_comparisons = 0;
    let mut original_controls = 0;
    for mask in 0..4 {
        let mut actions = Vec::new();
        let mut enabled = Vec::new();
        for (bit, pc, id, callback) in [
            (1, base + 1, 10, hook_a as HookCallback),
            (2, base + 4, 20, hook_b as HookCallback),
        ] {
            if mask & bit != 0 {
                actions.push((pc, callback, false));
                enabled.push(HookEvent {
                    probe_id: id,
                    logical_pc: pc,
                });
            }
        }
        if mask == 0 {
            // This explicit control runs original bytes. The public emitter
            // requires a nonempty action set; no generated success is claimed.
            for (entry, trace) in &originals {
                oracle.assert_trace(
                    trace,
                    *entry,
                    &identity_map(&heads, oracle.return_pc()),
                    &[],
                    Some(HookExpectation {
                        log: &log,
                        enabled: &[],
                    }),
                );
                original_controls += 1;
            }
            continue;
        }
        let memory = Mapping::new(4096);
        let image = TrampolinePlan::from_actions(&scan, base, base + 12, &actions)
            .unwrap()
            .emit_at(memory.address())
            .unwrap();
        assert!(image.bytes().len() <= 4096);
        // SAFETY: this private generated page is writable and large enough.
        unsafe {
            core::ptr::copy_nonoverlapping(
                image.bytes().as_ptr(),
                memory.writable(),
                image.bytes().len(),
            )
        };
        memory.protect(libc::PROT_READ | libc::PROT_EXEC);
        let mut boundaries = image.instruction_boundaries().to_vec();
        boundaries.extend([
            (base + 12, base + 12),
            (oracle.return_pc(), oracle.return_pc()),
        ]);
        let map = TraceMap {
            boundaries,
            gateways: vec![],
            generated_ranges: std::iter::once(
                memory.address()..memory.address() + image.bytes().len() as u64,
            )
            .collect(),
        };
        for (entry, trace) in &originals {
            let generated_entry = image
                .entry_routes()
                .iter()
                .find(|&&(original, _)| original == *entry)
                .expect("every required alternate entry must have an emitted route")
                .1;
            oracle.assert_trace(
                trace,
                generated_entry,
                &map,
                &[],
                Some(HookExpectation {
                    log: &log,
                    enabled: &enabled,
                }),
            );
            generated_comparisons += 1;
        }
        oracle.assert_publication(&[]);
    }
    assert_eq!(generated_comparisons, 18);
    assert_eq!(original_controls, 6);
}

#[test]
fn mixed_bundle_publication_and_retirement_preserve_complete_state() {
    use liteinst2::bundle::{BundleBudget, PlannedBundle, WritableAlias};
    use liteinst2::contracts::{
        AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, ExpectedBytes, LegalEntry,
        LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
    };
    use liteinst2::planner::HookSemantics;
    use liteinst2::quiescent::{
        AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
    };

    // One original execution traverses both independent images: a five-byte
    // MOV relocated by B1, then an exact two-byte NOP punned by B2, MOV and RET.
    let code = [
        0xb8, 0x21, 0x43, 0x65, 0x07, 0x66, 0x90, 0xb8, 0x03, 0x02, 0x10, 0x00, 0xc3,
    ];
    let mut oracle = NativeOracle::new(&code);
    let base = oracle.code.address();
    let offsets = [0, 5, 7, 12];
    let heads: Vec<_> = offsets.map(|offset| base + offset).into();
    let mut originals = Vec::new();
    for seed in SEEDS {
        for (index, &entry) in heads.iter().enumerate() {
            let trace = oracle.trace_original(entry, &heads, &[oracle.return_pc()], seed);
            let expected: Vec<_> = heads[index..]
                .iter()
                .copied()
                .chain([oracle.return_pc()])
                .collect();
            assert_eq!(trace.visits(), expected);
            originals.push((entry, trace));
        }
    }
    let identity = CodeIdentity {
        source: SourceIdentity([0xa2; 32]),
        mapping: base,
        generation: 1,
    };
    let snapshots = vec![
        ExpectedBytes {
            address: base,
            bytes: code[..5].to_vec(),
        },
        ExpectedBytes {
            address: base + 5,
            bytes: code[5..].to_vec(),
        },
    ];
    let mut members = Vec::new();
    for (index, source) in snapshots.iter().enumerate() {
        let scope = AddressRange::new(source.address, source.bytes.len()).unwrap();
        let entries = LegalEntrySet {
            identity,
            scope,
            provenance: EntryProvenance::Declared("native mixed bundle all heads".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: heads
                .iter()
                .filter(|&&pc| scope.contains(pc))
                .map(|&address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let mut allocation = AllocationPolicy::near(source.address).unwrap();
        if index == 0 {
            allocation.preferred_address = Some(base + 64 * 1024 * 1024);
        }
        let member = plan_install(&InstallRequest {
            identity,
            code: &source.bytes,
            base_address: source.address,
            function: scope,
            block: scope,
            logical_pc: source.address,
            entries: &entries,
            hook: if index == 0 { hook_a } else { hook_b },
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: if index == 0 {
                    TacticPolicy::RelocationOnly
                } else {
                    TacticPolicy::GeneralizedPunOnly
                },
                ..SearchPolicy::default()
            },
        })
        .expect("mixed bundle member is a required positive");
        match &member.plan().parts().kind {
            PlanKind::PrefixedPun(_) => panic!("mixed B1/B2 fixture must not select T1"),
            PlanKind::Relocation => assert_eq!(index, 0),
            PlanKind::GeneralizedPun(pun) => {
                assert_eq!(index, 1);
                assert_eq!(pun.instruction_len, 2);
            }
        }
        members.push(member);
    }
    let bundle = PlannedBundle::compose(snapshots, members, BundleBudget::default())
        .expect("mixed bundle composition is a required positive");
    assert_eq!(bundle.plan().steps().len(), 2);
    assert_eq!(bundle.plan().memory().mappings, 2);
    let mut map = TraceMap {
        boundaries: vec![
            (base + 7, base + 7),
            (base + 12, base + 12),
            (oracle.return_pc(), oracle.return_pc()),
        ],
        gateways: vec![base, base + 5],
        ..TraceMap::default()
    };
    for image in bundle.images() {
        map.boundaries
            .extend_from_slice(image.instruction_boundaries());
        map.generated_ranges
            .push(image.address()..image.address() + image.bytes().len() as u64);
    }
    let edits: Vec<_> = bundle
        .plan()
        .steps()
        .iter()
        .flat_map(|plan| &plan.parts().writes)
        .map(|edit| (edit.address, edit.bytes.clone()))
        .collect();
    assert_eq!(edits.len(), 2);
    assert_eq!(edits[0].0, base);
    assert_eq!(edits[0].1.len(), 5);
    assert_eq!(edits[1].0, base + 5);
    assert_eq!(edits[1].1.len(), 2);
    let source_range = AddressRange::new(base, code.len()).unwrap();
    let writable = oracle.code.writable();
    // SAFETY: source and writable addresses name the same private page. Every
    // child is reaped before writes, and this fixture owns its whole lifetime.
    let aliases = [unsafe { WritableAlias::new(source_range, writable) }.unwrap()];
    let permissions = |protection| {
        // SAFETY: the full private source page is held under the caller's lease.
        if unsafe { libc::mprotect(writable.cast(), 4096, protection) } == 0 {
            Ok(())
        } else {
            Err(Refusal::Backend(
                std::io::Error::last_os_error().to_string(),
            ))
        }
    };
    let (mut installed, receipt) = {
        // SAFETY: exclusive ownership excludes every executor and continuation;
        // all original trace children have completed and been reaped.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![source_range]) };
        permissions(libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: aliases and complete source coverage satisfy the bundle's
        // contract; final source permissions are RX before sync and receipt.
        let result = unsafe {
            bundle.publish_with(&aliases, &mut lease, || {
                permissions(libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("mixed bundle publication is a required positive");
        assert!(!lease.is_poisoned());
        result
    };
    assert_eq!(receipt.plan().identity(), identity);
    assert_eq!(receipt.plan().steps(), bundle.plan().steps());
    oracle.assert_publication(&edits);
    let log = HookEventLog::new();
    let enabled = [
        HookEvent {
            probe_id: 10,
            logical_pc: base,
        },
        HookEvent {
            probe_id: 20,
            logical_pc: base + 5,
        },
    ];
    let mut installed_comparisons = 0;
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
    {
        let mut held = vec![source_range];
        held.extend(bundle.plan().steps().iter().flat_map(|plan| {
            plan.parts()
                .allocations
                .iter()
                .map(|allocation| allocation.range)
        }));
        // SAFETY: every patched child has been reaped; source plus all generated
        // ranges and their continuations are now exclusively drained.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, held) };
        permissions(libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: full retirement lease and exact source alias remain held.
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .expect("mixed bundle retirement is a required positive");
        assert!(!lease.is_poisoned());
    }
    assert!(installed.is_retired());
    oracle.assert_publication(&[]);
    let mut retired_comparisons = 0;
    for (entry, trace) in &originals {
        oracle.assert_trace(
            trace,
            *entry,
            &identity_map(&heads, oracle.return_pc()),
            &[],
            Some(HookExpectation {
                log: &log,
                enabled: &[],
            }),
        );
        retired_comparisons += 1;
    }
    assert_eq!(installed_comparisons, 8);
    assert_eq!(retired_comparisons, 8);
}

#[test]
#[should_panic(expected = "hook event trace mismatch")]
fn rejects_missing_hook_event() {
    multi_image_trace(missing_hook);
}

#[test]
#[should_panic(expected = "hook event trace mismatch")]
fn rejects_duplicate_hook_event() {
    multi_image_trace(duplicate_hook);
}

#[test]
#[should_panic(expected = "hook event trace mismatch")]
fn rejects_wrong_hook_logical_pc() {
    multi_image_trace(wrong_hook);
}

#[test]
#[should_panic(expected = "hook event log overflow")]
fn rejects_hook_event_log_overflow() {
    // A declared one-event log must reject its second write without needing
    // to exceed the unchanged ptrace instruction budget.
    multi_image_trace_with_capacity(duplicate_hook, 1);
}

#[test]
#[should_panic(expected = "missing restored boundary")]
fn rejects_missing_map_boundary() {
    let oracle = NativeOracle::new(&[0x90, 0xc3]);
    let base = oracle.code.address();
    let trace = oracle.trace_original(base, &[base, base + 1], &[oracle.return_pc()], SEEDS[0]);
    let map = identity_map(&[base], oracle.return_pc());
    oracle.assert_trace(&trace, base, &map, &[], None);
}

#[test]
#[should_panic(expected = "duplicate physical restored boundary")]
fn rejects_duplicate_physical_map_boundary() {
    let oracle = NativeOracle::new(&[0x90, 0xc3]);
    let base = oracle.code.address();
    let trace = oracle.trace_original(base, &[base, base + 1], &[oracle.return_pc()], SEEDS[0]);
    let mut map = identity_map(&[base, base + 1], oracle.return_pc());
    map.boundaries.push((base, base));
    oracle.assert_trace(&trace, base, &map, &[], None);
}

#[test]
#[should_panic(expected = "unexpected restored boundary")]
fn rejects_wrong_restored_boundary() {
    let oracle = NativeOracle::new(&[0x90, 0x90, 0xc3]);
    let base = oracle.code.address();
    let heads = [base, base + 1, base + 2];
    let trace = oracle.trace_original(base, &heads, &[oracle.return_pc()], SEEDS[0]);
    let mut map = identity_map(&heads, oracle.return_pc());
    map.boundaries[0].1 = base + 1;
    map.boundaries[1].1 = base;
    map.generated_ranges.push(base..base + 3);
    oracle.assert_trace(&trace, base, &map, &[], None);
}

#[test]
#[should_panic(expected = "unexpected restored boundary")]
fn rejects_missing_executed_boundary_without_skipping_to_the_rejoin() {
    let oracle = NativeOracle::new(&[0x90, 0x90, 0xc3]);
    let base = oracle.code.address();
    let heads = [base, base + 1, base + 2];
    let trace = oracle.trace_original(base, &heads, &[oracle.return_pc()], SEEDS[0]);
    rewrite(&oracle, 0, &[0xeb, 0]); // JMP directly to RET, skipping head1.
    oracle.assert_publication(&[(base, vec![0xeb, 0])]);
    oracle.assert_trace(
        &trace,
        base,
        &identity_map(&heads, oracle.return_pc()),
        &[],
        None,
    );
}

#[test]
#[should_panic(expected = "unexpected restored boundary")]
fn rejects_duplicate_executed_boundary() {
    let oracle = NativeOracle::new(&[0x90, 0x90, 0x90, 0xc3]);
    let base = oracle.code.address();
    let heads = [base, base + 1, base + 2, base + 3];
    let trace = oracle.trace_original(base, &heads, &[oracle.return_pc()], SEEDS[0]);
    rewrite(&oracle, 1, &[0xeb, 0xfd]); // JMP back to head0 instead of head2.
    oracle.assert_publication(&[(base + 1, vec![0xeb, 0xfd])]);
    oracle.assert_trace(
        &trace,
        base,
        &identity_map(&heads, oracle.return_pc()),
        &[],
        None,
    );
}
