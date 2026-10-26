//! Fixed two-return native subject. Old single-return cases are independent.
use super::*;
use liteinst2::bundle::{BundleBudget, PlannedBundle, WritableAlias};
use oracle::native_interval::native_branch::BorrowedTwoExitOracle;
use rapid_profiler::frontend_native::{BranchAttach, BranchSubjectContract, LoadedBranchLeaf};
const BRANCH_SUBJECT: &[u8] = include_bytes!(env!("NATIVE_BRANCH_DSO"));
const HEADS: [u64; 11] = [0, 5, 12, 15, 19, 21, 24, 27, 28, 32, 35];
fn branch_cohorts() -> [Vec<u64>; 2] {
    [vec![0, 1], vec![1, 0]]
}
fn controls_for_branch() -> [ProbeControl; 3] {
    [
        ProbeControl::new(entry_callback, true),
        ProbeControl::new(exit_callback, true),
        ProbeControl::new(exit_callback, true),
    ]
}

fn bundle(
    leaf: &LoadedBranchLeaf,
    generation: u64,
    controls: &[ProbeControl; 3],
) -> (PlannedBundle, TraceMap) {
    let entry = leaf.entry();
    let scope = AddressRange::new(entry, 36).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0x2e; 32]),
        mapping: entry,
        generation,
    };
    let entries = LegalEntrySet {
        identity,
        scope,
        provenance: EntryProvenance::Declared(
            "complete authored zero/nonzero leaf and both branch destinations".into(),
        ),
        completeness: EntryCompleteness::Complete,
        entries: [0, 21, 28]
            .map(|offset| LegalEntry {
                address: entry + offset,
                requires_endbr: false,
            })
            .to_vec(),
        resumes: ResumeObligation::NoneExist,
    };
    let mut overlay = leaf.code().to_vec();
    let mut members = Vec::new();
    let mut reserved: Vec<AddressRange> = Vec::new();
    // Every request authenticates the full function against the preceding
    // overlay. The nonzero redirect leaves a valid unreachable decode tail;
    // the zero block is last, so no later scan decodes its overwritten tail.
    for (index, (logical, start, len, displaced, control)) in
        [(0, 0, 21, 5, 0), (35, 28, 8, 8, 2), (27, 21, 7, 7, 1)]
            .into_iter()
            .enumerate()
    {
        let mut allocation = AllocationPolicy::near(entry).unwrap();
        assert_eq!(
            (
                allocation.max_candidates,
                allocation.max_mappings,
                allocation.max_mapped_bytes
            ),
            (256, 1, 8192)
        );
        allocation.preferred_address = Some((entry & !4095) + 0x10_0000 + index as u64 * 0x1_0000);
        // Pure planning reserves no mapping. Exclude every earlier member's
        // complete allocation, including its second page, before planning next.
        for prior in &reserved {
            allocation.ranges = allocation
                .ranges
                .iter()
                .flat_map(|range| {
                    let mut remaining = Vec::new();
                    if !range.overlaps(*prior) {
                        remaining.push(*range);
                    } else {
                        if range.start() < prior.start() {
                            remaining.push(
                                AddressRange::new(
                                    range.start(),
                                    (prior.start() - range.start()) as usize,
                                )
                                .unwrap(),
                            );
                        }
                        if prior.end() < range.end() {
                            remaining.push(
                                AddressRange::new(
                                    prior.end(),
                                    (range.end() - prior.end()) as usize,
                                )
                                .unwrap(),
                            );
                        }
                    }
                    remaining
                })
                .collect();
        }
        let member = plan_coalesced_detailed(
            &InstallRequest {
                identity,
                code: &overlay,
                base_address: entry,
                function: scope,
                block: AddressRange::new(entry + start, len).unwrap(),
                logical_pc: entry + logical,
                entries: &entries,
                hook: entry_callback,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: if index == 0 { 0 } else { 7 },
                    max_displaced_bytes: if index == 0 { 5 } else { 8 },
                    max_sites: if index == 0 { 1 } else { 3 },
                },
            },
            &[ControlledAction {
                logical_pc: entry + logical,
                control: controls[control].clone(),
            }],
        )
        .expect("required block-local positive plan refused");
        assert_eq!(member.plan().parts().kind, PlanKind::Relocation);
        assert_eq!(member.plan().parts().physical_pc, entry + start);
        assert_eq!(
            member.plan().parts().displaced,
            AddressRange::new(entry + start, displaced).unwrap()
        );
        assert_eq!(member.metrics().displaced_bytes, displaced);
        assert_eq!(member.plan().parts().writes.len(), 1);
        for request in &member.plan().parts().allocations {
            assert!(reserved.iter().all(|prior| !prior.overlaps(request.range)));
            reserved.push(request.range);
        }
        for edit in &member.plan().parts().writes {
            let offset = (edit.address - entry) as usize;
            overlay[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        members.push(member);
    }
    let bundle = PlannedBundle::compose(
        vec![ExpectedBytes {
            address: entry,
            bytes: leaf.code().to_vec(),
        }],
        members,
        BundleBudget {
            max_steps: 3,
            max_mappings: 3,
            max_virtual_bytes: 24576,
            max_backing_bytes: 24576,
            max_virtual_span: 1 << 32,
        },
    )
    .expect("required three-block bundle refused");
    assert_eq!(bundle.plan().final_bytes()[0].bytes, overlay);
    assert_eq!(bundle.images().len(), 3);
    let mut map = TraceMap {
        boundaries: Vec::new(),
        gateways: vec![entry, entry + 21, entry + 28],
        generated_ranges: Vec::new(),
    };
    for image in bundle.images() {
        let range = image.address()..image.address() + image.bytes().len() as u64;
        assert!(
            image
                .instruction_boundaries()
                .iter()
                .all(|&(_, pc)| range.contains(&pc))
        );
        map.boundaries
            .extend_from_slice(image.instruction_boundaries());
        map.generated_ranges.push(range);
    }
    for offset in HEADS {
        let logical = entry + offset;
        if !map.boundaries.iter().any(|&(pc, _)| pc == logical) {
            map.boundaries.push((logical, logical));
        }
    }
    map.boundaries.push((leaf.terminal(), leaf.terminal()));
    assert_eq!(map.boundaries.len(), 12);
    assert_eq!(
        map.boundaries
            .iter()
            .map(|&(pc, _)| pc)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        12
    );
    assert_eq!(
        map.boundaries
            .iter()
            .map(|&(_, pc)| pc)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        12
    );
    (bundle, map)
}

fn refusals(leaf: &mut LoadedBranchLeaf, output: &Path) {
    // The foreign RET is a real ordinary RET owned by the separately admitted
    // original fixture, not a guessed address or byte inside this function.
    let foreign = unsafe {
        LoadedLeaf::load(
            Path::new(env!("NATIVE_INTERVAL_DSO")),
            SUBJECT,
            SubjectContract::LEAF,
        )
    }
    .unwrap();
    let journal = Journal::allocate().unwrap();
    let before = leaf.original_page().to_vec();
    let a = leaf.entry();
    let mut rows = Vec::new();
    for (name, exits, expected) in [
        ("missing-ret", vec![a + 27], SetupRefusal::EntryExit),
        (
            "duplicate-ret",
            vec![a + 27, a + 27],
            SetupRefusal::EntryExit,
        ),
        (
            "non-ret-head",
            vec![a + 27, a + 32],
            SetupRefusal::EntryExit,
        ),
        (
            "foreign-ret",
            vec![a + 27, foreign.entry() + 18],
            SetupRefusal::SymbolOwner,
        ),
    ] {
        assert_eq!(
            leaf.admit(
                a,
                leaf.bias_object(),
                &exits,
                BranchSubjectContract::TWO_RETURNS
            ),
            Err(expected)
        );
        leaf.verify(false).unwrap();
        foreign.verify(false).unwrap();
        assert_rx(leaf.page());
        assert_eq!(
            unsafe { std::slice::from_raw_parts(leaf.page() as usize as *const u8, 4096) },
            before
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(journal.address() as usize as *const u8, 4096) },
            [0; 4096]
        );
        rows.push(format!("{{\"name\":\"{name}\",\"refusal\":\"{expected:?}\",\"source_unchanged\":true,\"journal_zero\":true,\"attachments_created\":0}}"));
    }
    std::fs::write(
        output.join("refusals.json"),
        format!("[{}]\n", rows.join(",")),
    )
    .unwrap();
    std::fs::write(
        output.join("loader-after.maps"),
        std::fs::read("/proc/self/maps").unwrap(),
    )
    .unwrap();
    println!("native-two-returns:refusals:required=4:beforewrite=4:source-page-unchanged");
}
pub(super) fn run(mode: &str, subject: &Path, output: &Path) {
    current_single_main();
    // SAFETY: fixed private DSO, no foreign calls or saved contexts; exact input
    // bytes are independently embedded by the preceding authenticated compiler.
    let leaf = unsafe {
        LoadedBranchLeaf::load(subject, BRANCH_SUBJECT, BranchSubjectContract::TWO_RETURNS)
    }
    .unwrap();
    leaf.admit(
        leaf.entry(),
        leaf.bias_object(),
        &[leaf.entry() + 27, leaf.entry() + 35],
        BranchSubjectContract::TWO_RETURNS,
    )
    .unwrap();
    std::fs::write(
        output.join("loader-before.maps"),
        std::fs::read("/proc/self/maps").unwrap(),
    )
    .unwrap();
    std::fs::write(output.join("source-page.bin"), leaf.original_page()).unwrap();
    std::fs::write(output.join("loader.json"), leaf.identity_record()).unwrap();
    if mode == "refusals" {
        refusals(leaf, output);
        return;
    }
    let mut calls = 0;
    for (case, arguments) in branch_cohorts().iter().enumerate() {
        let case_dir = directory(output, &format!("case-{case}"));
        let oracle = unsafe {
            BorrowedTwoExitOracle::new(
                leaf.page(),
                leaf.entry(),
                leaf.invoke(),
                leaf.terminal(),
                leaf.pointer(),
                leaf.bias_object(),
                &leaf.immutable_extents(),
            )
        };
        let journal = Journal::allocate().unwrap();
        let install = INSTALL.checked_add(case as u64).unwrap();
        let code_generation = case as u64 + 1;
        let session = Arc::new(
            Session::new(
                install,
                &[FunctionSpec {
                    function: FUNCTION,
                    group: 0,
                }],
                &[GroupSpec { mandatory: true }],
                Limits {
                    epochs: 2,
                    threads: 1,
                    depth: 4,
                    records_per_epoch: 16,
                    actions: 16,
                },
            )
            .unwrap(),
        );
        let config = Config {
            retained_per_function: if mode == "budget" { 1 } else { 16 },
            max_inflight: 4,
            max_invocations: 16,
        };
        let g1 = session.stage(config).unwrap();
        let g2 = session.stage(config).unwrap();
        session.publish(&g1, FailurePoint::None).unwrap();
        let (stack_start, stack_end) = oracle.stack_range();
        let attach = BranchAttach {
            install,
            function: FUNCTION,
            certificate: leaf.certificate(),
            stack_start,
            stack_end,
            registration: 1,
            after_entry: None,
        };
        let invocations: Vec<_> = arguments
            .iter()
            .enumerate()
            .map(|(i, &argument)| Invocation {
                argument,
                state_seed: STATE_SEEDS[i % 2],
            })
            .collect();
        let count = arguments.len() as u64;
        let child_setup = |installed: bool, phase: &str| {
            let report_path = case_dir.join(format!("{phase}-reports.json"));
            let session = Arc::clone(&session);
            let g1 = g1.clone();
            let g2 = g2.clone();
            let crossing = installed && mode == "generation";
            move || {
                let gate = Arc::new(Gate {
                    entered: AtomicBool::new(false),
                    released: AtomicBool::new(false),
                    controller_done: AtomicBool::new(false),
                });
                ACTIVE_GATE.store(Arc::as_ptr(&gate).cast_mut(), Ordering::Release);
                let controller = if crossing {
                    let session = Arc::clone(&session);
                    let gate = Arc::clone(&gate);
                    let old = g1.clone();
                    let new = g2.clone();
                    Some(std::thread::spawn(move || {
                        let deadline = Instant::now() + Duration::from_secs(2);
                        while !gate.entered.load(Ordering::Acquire) {
                            assert!(Instant::now() < deadline, "controller entry handshake");
                            std::thread::sleep(Duration::from_micros(100));
                        }
                        assert_eq!(old.reservations(), 1);
                        old.close();
                        assert!(old.try_report().is_none(), "pre-RET owner cannot drain");
                        session.publish(&new, FailurePoint::None).unwrap();
                        assert_eq!(old.reservations(), 1);
                        gate.controller_done.store(true, Ordering::Release);
                        gate.released.store(true, Ordering::Release);
                    }))
                } else {
                    None
                };
                let mut attach = attach;
                if crossing {
                    attach.after_entry = Some(entry_gate);
                }
                let registration =
                    unsafe { NativeThread::attach_branch(&session, attach, journal) }.unwrap();
                move || {
                    if let Some(controller) = controller {
                        let deadline = Instant::now() + Duration::from_secs(2);
                        while !controller.is_finished() {
                            assert!(Instant::now() < deadline, "controller join deadline");
                            std::thread::sleep(Duration::from_micros(100));
                        }
                        controller.join().unwrap();
                        assert!(gate.controller_done.load(Ordering::Acquire));
                    }
                    let expected = if !installed {
                        NativeTotals::default()
                    } else if mode == "budget" {
                        NativeTotals {
                            entries: count,
                            returns: count,
                            completed: 1,
                            refused: count - 1,
                        }
                    } else {
                        NativeTotals {
                            entries: count,
                            returns: count,
                            completed: count,
                            refused: 0,
                        }
                    };
                    let actual_totals = registration.detach().unwrap();
                    assert_eq!(actual_totals, expected);
                    g1.close();
                    g2.close();
                    let r1 = g1.try_report().expect("closed original owner drained");
                    let r2 = g2.try_report().expect("closed replacement owner drained");
                    let rows1: Vec<_> = r1.records().collect();
                    let rows2: Vec<_> = r2.records().collect();
                    assert_eq!(
                        rows1.len(),
                        if !installed {
                            0
                        } else if crossing || mode == "budget" {
                            1
                        } else {
                            count as usize
                        }
                    );
                    assert_eq!(rows2.len(), usize::from(crossing));
                    let mut report_rows = Vec::new();
                    for (rows, generation, ordinal_base) in
                        [(&rows1, g1.generation(), 1), (&rows2, g2.generation(), 2)]
                    {
                        for (i, row) in rows.iter().enumerate() {
                            assert_eq!(row.record.admission.generation, generation);
                            assert_eq!(row.record.admission.function, FUNCTION);
                            assert_eq!(row.record.admission.invocation, i);
                            assert_eq!(row.record.admission.entry_value, ordinal_base + i as u64);
                            // Terminal values use the zero-based invocation within this generation.
                            // Entry and payload values retain the native pair ordinal.
                            assert!(
                                matches!(row.record.terminal, Some(Terminal::Completed { value, disposition: Disposition::Retained { rank } }) if value == i as u64 && rank == i)
                            );
                            let payload = row.payload.unwrap();
                            assert_eq!(payload.admission, row.record.admission);
                            assert_eq!(payload.thread, 1);
                            assert_eq!(payload.start_sequence, ordinal_base + i as u64 - 1);
                            assert!(
                                matches!(payload.outcome, PayloadOutcome::Completed { completed_children: 0, end: rapid_profiler::frontend::Observation::Value(value) } if value == ordinal_base + i as u64)
                            );
                            let (terminal_value, rank) = match row.record.terminal.unwrap() {
                                Terminal::Completed {
                                    value,
                                    disposition: Disposition::Retained { rank },
                                } => (value, rank),
                                _ => unreachable!("completed retained terminal checked above"),
                            };
                            let end_value = match payload.outcome {
                                PayloadOutcome::Completed {
                                    end: rapid_profiler::frontend::Observation::Value(value),
                                    ..
                                } => value,
                                _ => unreachable!("completed value payload checked above"),
                            };
                            report_rows.push(format!(
                                "{{\"generation\":{},\"function\":1,\"invocation\":{},\"entry_value\":{},\"terminal_value\":{},\"rank\":{},\"payload_thread\":{},\"start_sequence\":{},\"end_value\":{}}}",
                                row.record.admission.generation.get(), row.record.admission.invocation,
                                row.record.admission.entry_value, terminal_value, rank,
                                payload.thread, payload.start_sequence, end_value,
                            ));
                        }
                    }
                    std::fs::write(report_path, format!(
                        "{{\"installed\":{installed},\"crossing\":{crossing},\"entries\":{},\"returns\":{},\"completed\":{},\"refused\":{},\"old_records\":{},\"new_records\":{},\"rows\":[{}]}}\n",
                        actual_totals.entries, actual_totals.returns, actual_totals.completed, actual_totals.refused,
                        rows1.len(), rows2.len(), report_rows.join(","),
                    )).unwrap();
                    ACTIVE_GATE.store(std::ptr::null_mut(), Ordering::Release);
                }
            }
        };
        let original_dir = directory(&case_dir, "original");
        let trace = oracle.original(
            &invocations,
            journal.address(),
            child_setup(false, "original"),
            &original_dir,
        );
        leaf.verify(false).unwrap();

        let controls = controls_for_branch();
        let (planned, map) = bundle(leaf, code_generation, &controls);
        let identity = planned.plan().identity();
        let edits: Vec<_> = planned
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
        let mut ranges = vec![AddressRange::new(leaf.page(), 4096).unwrap()];
        ranges.extend(planned.plan().steps().iter().flat_map(|step| {
            step.parts()
                .allocations
                .iter()
                .map(|allocation| allocation.range)
        }));
        current_single_main();
        let page = leaf.page();
        protection(page, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        let alias = unsafe {
            WritableAlias::new(
                AddressRange::new(page, 4096).unwrap(),
                page as usize as *mut u8,
            )
        }
        .unwrap();
        let (mut installed, _) = {
            let mut lease = unsafe { QuiescenceLease::new(leaf, identity, ranges.clone()) };
            let result = unsafe {
                planned.publish_with(&[alias], &mut lease, || {
                    protection(page, libc::PROT_READ | libc::PROT_EXEC)
                })
            };
            match result {
                Ok(value) => {
                    assert!(!lease.is_poisoned());
                    value
                }
                Err(failure) => {
                    if failure.stage == FailureStage::BeforeWrite {
                        protection(page, libc::PROT_READ | libc::PROT_EXEC).unwrap();
                    }
                    panic!("required three-member publication failed: {failure:?}");
                }
            }
        };
        assert_rx(page);
        leaf.verify(true).unwrap();
        oracle.assert_publication(&edits);
        for (index, image) in planned.images().iter().enumerate() {
            assert_eq!(
                unsafe {
                    std::slice::from_raw_parts(
                        image.address() as usize as *const u8,
                        image.bytes().len(),
                    )
                },
                image.bytes()
            );
            std::fs::write(
                case_dir.join(format!("generated-{index}.bin")),
                image.bytes(),
            )
            .unwrap();
        }
        for (index, (_, edit)) in edits.iter().enumerate() {
            std::fs::write(case_dir.join(format!("source-edit-{index}.bin")), edit).unwrap();
        }
        let rows: Vec<_> = planned.plan().steps().iter().zip(planned.images()).map(|(step, image)| {
            format!("{{\"physical\":{},\"logical\":{},\"displaced_bytes\":{},\"image\":{},\"image_bytes\":{},\"boundaries\":{:?}}}",
                step.parts().physical_pc, step.parts().logical_pc, step.parts().displaced.len(), image.address(), image.bytes().len(),
                image.instruction_boundaries().iter().map(|&(a,b)| [a,b]).collect::<Vec<_>>())
        }).collect();
        std::fs::write(
            case_dir.join("plan.json"),
            format!(
                "{{\"source\":{},\"identity_generation\":{},\"members\":[{}]}}\n",
                leaf.entry(),
                code_generation,
                rows.join(",")
            ),
        )
        .unwrap();
        let mut events = Vec::new();
        for (i, &argument) in arguments.iter().enumerate() {
            let ordinal = i as u64 + 1;
            let refused = mode == "budget" && i > 0;
            let generation = if refused {
                0
            } else if mode == "generation" && i == 1 {
                g2.generation().get()
            } else {
                g1.generation().get()
            };
            let invocation = if refused || mode == "generation" {
                1
            } else {
                ordinal
            };
            events.push([
                if refused { 3 } else { 1 },
                ordinal,
                leaf.entry(),
                oracle.rsp(),
                oracle.terminal(),
                generation,
                invocation,
            ]);
            events.push([
                if refused { 4 } else { 2 },
                ordinal,
                leaf.entry() + if argument == 0 { 27 } else { 35 },
                oracle.rsp(),
                oracle.terminal(),
                generation,
                invocation,
            ]);
        }
        std::fs::write(
            case_dir.join("expected-events.json"),
            format!("{events:?}\n"),
        )
        .unwrap();
        let installed_dir = directory(&case_dir, "installed");
        oracle.compare(
            &trace,
            &map,
            PhaseExpectation {
                journal: journal.address(),
                events: &events,
                owned_threads: if mode == "generation" { 2 } else { 1 },
            },
            child_setup(true, "installed"),
            &installed_dir,
        );
        leaf.verify(true).unwrap();
        oracle.assert_publication(&edits);

        current_single_main();
        protection(page, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        {
            let mut lease = unsafe { QuiescenceLease::new(leaf, identity, ranges) };
            let result = unsafe {
                installed.retire_with(&mut lease, || {
                    protection(page, libc::PROT_READ | libc::PROT_EXEC)
                })
            };
            if let Err(failure) = result {
                if failure.stage == FailureStage::BeforeWrite {
                    protection(page, libc::PROT_READ | libc::PROT_EXEC).unwrap();
                }
                panic!("retirement failure remains failed and gated: {failure:?}");
            }
            assert!(!lease.is_poisoned());
        }
        assert!(installed.is_retired());
        assert_rx(page);
        leaf.verify(false).unwrap();
        oracle.assert_publication(&[]);
        let identity_map = TraceMap {
            boundaries: HEADS
                .map(|offset| (leaf.entry() + offset, leaf.entry() + offset))
                .into_iter()
                .chain([(leaf.terminal(), leaf.terminal())])
                .collect(),
            gateways: vec![],
            generated_ranges: vec![],
        };
        let retired_dir = directory(&case_dir, "retired");
        oracle.compare(
            &trace,
            &identity_map,
            PhaseExpectation {
                journal: journal.address(),
                events: &[],
                owned_threads: 1,
            },
            child_setup(false, "retired"),
            &retired_dir,
        );
        // Even after source retirement and model drain, retain every generated
        // owner/control. Pre-RET completion never authorizes code reclamation.
        std::mem::forget(installed);
        std::mem::forget(controls);
        calls += arguments.len();
        std::fs::write(case_dir.join("truth.json"), format!("{{\"arguments\":{arguments:?},\"state_seeds\":{STATE_SEEDS:?},\"install\":{install},\"identity_generation\":{code_generation},\"g1\":{},\"g2\":{},\"calls_per_phase\":{},\"heads\":[0,5,12,15,19,21,24,27,28,32,35],\"instructions_per_call\":8,\"phases\":[\"original\",\"installed\",\"retired\"]}}\n", g1.generation().get(), g2.generation().get(), arguments.len())).unwrap();
    }
    current_single_main();
    leaf.verify(false).unwrap();
    std::fs::write(
        output.join("loader-after.maps"),
        std::fs::read("/proc/self/maps").unwrap(),
    )
    .unwrap();
    let (completed, refused) = match mode {
        "paths" => (4, 0),
        "budget" => (2, 2),
        "generation" => (4, 0),
        _ => unreachable!(),
    };
    println!(
        "native-two-returns:{mode}:calls_per_phase={calls}:phases=3:visits_per_phase={}:events={}:completed={completed}:refused={refused}",
        calls * 8,
        calls * 2
    );
}
