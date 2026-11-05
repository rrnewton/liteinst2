// Included only as a child of the unchanged ordered oracle. This fixed adapter
// reuses its exact Tracee, CHILD_BUDGET, MAX_STEPS, event log and assert_state;
// no ownership/cleanup implementation or architectural comparator is copied.
use super::*;
use liteinst::controls::EarlyControlGateLayout;

const _: () = assert!(PAGE.is_power_of_two());

struct Pending<'a> {
    gate: &'a EarlyControlGateLayout,
    enabled: bool,
    loaded: bool,
    observed: bool,
}

/// Compare the fixed straight-line fixture and additionally observe actual gate
/// PCs in that same trace. The return counters are [loads, helper, bypass].
/// This adapter has no alternate comparator, state mask or retry path.
pub fn assert_trace(
    oracle: &NativeOracle,
    trace: &NativeTrace,
    entry: u64,
    map: &TraceMap,
    hooks: HookExpectation<'_>,
    gates: &[EarlyControlGateLayout],
    pages: &[(u64, Vec<u8>)],
) -> [u64; 3] {
    let source = trace.source_base;
    assert_eq!(
        &trace.original_code[..12],
        &[
            0x48, 0x89, 0xc8, 0x48, 0x01, 0xd8, 0x48, 0x8b, 0x54, 0x24, 0xf8, 0xc3
        ]
    );
    assert_eq!(
        trace.heads,
        [source, source + 3, source + 6, source + 11]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        trace.terminals,
        [oracle.return_pc()].into_iter().collect::<BTreeSet<_>>()
    );
    assert_eq!(
        gates.iter().map(|gate| gate.logical_pc).collect::<Vec<_>>(),
        [source, source + 3]
    );
    assert!(map.gateways.is_empty());
    let physical = oracle.ordered_physical(trace, map);
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].0, source);
    assert!(
        pages
            .iter()
            .all(|(address, bytes)| *address & (PAGE as u64 - 1) == 0 && bytes.len() == PAGE)
    );
    assert_eq!(map.generated_ranges.len(), 1);
    let generated = &map.generated_ranges[0];
    assert_eq!(generated.start, pages[1].0);
    assert!(generated.end <= pages[1].0 + PAGE as u64);
    for gate in gates {
        assert!(generated.contains(&gate.entry));
        assert!(
            gate.entry < gate.post_load
                && gate.post_load < gate.observing_entry
                && gate.observing_entry < gate.original_body
        );
        assert!(generated.contains(&gate.original_body));
        assert_eq!(physical.get(&gate.original_body), Some(&gate.logical_pc));
        assert!(!physical.contains_key(&gate.entry));
        assert!(!physical.contains_key(&gate.post_load));
        assert!(!physical.contains_key(&gate.observing_entry));
    }
    let mut ids = BTreeSet::new();
    for event in hooks.enabled {
        assert!(ids.insert(event.probe_id));
        assert_eq!(
            event.logical_pc,
            match event.probe_id {
                10 => source,
                20 => source + 3,
                30 => source + 6,
                _ => panic!("foreign point event"),
            }
        );
    }
    assert!(hooks.enabled.contains(&HookEvent {
        probe_id: 30,
        logical_pc: source + 6
    }));
    let _active = hooks.log.activate();
    oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
    let child = Tracee::fork();
    let mut initial = trace.baseline.initial;
    initial.rip = entry;
    child.set_registers(&initial);
    child.set_xstate(&trace.baseline.xstate);
    let mut next = 0;
    let mut events = Vec::new();
    let mut pending: Option<Pending<'_>> = None;
    let mut after_branch = None;
    let mut counts = [0_u64; 3];
    let mut per_gate = [0_usize; 2];
    for step in 0..=MAX_STEPS {
        assert!(
            Instant::now() < child.deadline,
            "early static trace wall deadline exhausted"
        );
        let registers = child.registers();
        let pc = registers.rip;
        if let Some(expected) = after_branch.take() {
            assert_eq!(
                pc, expected,
                "real JRCXZ did not select the loaded-Boolean path"
            );
        }
        if let Some((index, gate)) = gates.iter().enumerate().find(|(_, gate)| gate.entry == pc) {
            assert!(pending.is_none(), "nested or duplicate early gate entry");
            let expected = trace.baseline.points.get(next).expect("extra early gate");
            assert_eq!(expected.logical_pc, gate.logical_pc);
            assert_state(
                expected,
                &oracle.snapshot(&child, gate.logical_pc, oracle.code.bytes()),
            );
            hooks.log.assert_events(&child, &events);
            per_gate[index] += 1;
            pending = Some(Pending {
                gate,
                enabled: hooks
                    .enabled
                    .iter()
                    .any(|event| event.logical_pc == gate.logical_pc),
                loaded: false,
                observed: false,
            });
        }
        if let Some(gate) = gates.iter().find(|gate| gate.post_load == pc) {
            let active = pending.as_mut().expect("post-load without gate entry");
            assert_eq!(active.gate, gate);
            assert!(!active.loaded, "repeated Boolean load boundary");
            assert_eq!(registers.rcx, u64::from(active.enabled));
            assert_eq!(
                child.memory(pc.checked_sub(3).unwrap(), 3),
                [0x0f, 0xb6, 0x09],
                "post-load label must follow the exact byte MOVZX ECX,[RCX]"
            );
            let branch = child.memory(pc, 2);
            assert_eq!(branch[0], 0xe3, "post-load PC must be the actual JRCXZ");
            let fallthrough = pc.checked_add(2).unwrap();
            let disabled = fallthrough
                .checked_add_signed(i64::from(branch[1] as i8))
                .unwrap();
            assert!(fallthrough < disabled && disabled < gate.observing_entry);
            after_branch = Some(if active.enabled {
                fallthrough
            } else {
                disabled
            });
            let expected = &trace.baseline.points[next];
            assert_eq!(
                registers.rsp,
                expected.registers.rsp.checked_sub(136).unwrap()
            );
            assert_eq!(
                child.memory(registers.rsp, 8),
                expected.registers.rcx.to_ne_bytes()
            );
            assert_eq!(
                registers.eflags & !DEBUGGER_FLAGS,
                expected.registers.eflags & !DEBUGGER_FLAGS
            );
            hooks.log.assert_events(&child, &events);
            active.loaded = true;
            counts[0] += 1;
        }
        if let Some(gate) = gates.iter().find(|gate| gate.observing_entry == pc) {
            let active = pending.as_mut().expect("helper without gate entry");
            assert_eq!(active.gate, gate);
            assert!(
                active.loaded && active.enabled && !active.observed,
                "false or repeated early helper entry"
            );
            let expected = &trace.baseline.points[next];
            assert_state(
                expected,
                &oracle.snapshot(&child, gate.logical_pc, oracle.code.bytes()),
            );
            hooks.log.assert_events(&child, &events);
            active.observed = true;
            counts[1] += 1;
        }
        if let Some(active) = pending
            .as_ref()
            .filter(|active| !active.enabled && pc != active.gate.original_body)
        {
            // A false path may use only its small local gate/restore code;
            // it may not enter any helper byte, dispatcher or callback.
            assert!(
                (active.gate.entry..active.gate.observing_entry).contains(&pc),
                "disabled path entered observer or foreign code"
            );
        }
        let relevant = physical.contains_key(&pc)
            || gates
                .iter()
                .any(|gate| [gate.entry, gate.post_load, gate.observing_entry].contains(&pc));
        if relevant {
            for (address, bytes) in pages {
                assert_eq!(
                    child.memory(*address, bytes.len()),
                    *bytes,
                    "early trace changed source/image page"
                );
            }
        }
        if let Some(&original) = physical.get(&pc) {
            let expected = trace
                .baseline
                .points
                .get(next)
                .expect("extra restored early boundary");
            assert_eq!(
                original, expected.logical_pc,
                "unexpected early restored visit"
            );
            if gates.iter().any(|gate| gate.logical_pc == original) {
                let active = pending.take().expect("body reached without early gate");
                assert_eq!(pc, active.gate.original_body);
                assert!(active.loaded, "body reached before real Boolean load");
                assert_eq!(
                    active.observed, active.enabled,
                    "helper/bypass path disagrees with loaded Boolean"
                );
                if !active.enabled {
                    counts[2] += 1;
                }
            } else {
                assert!(
                    pending.is_none(),
                    "early gate escaped to another original head"
                );
            }
            // This is the unchanged comparator and log-prefix rule used by
            // NativeOracle::assert_trace, with no GPR/TLS/data/stack exclusion.
            assert_state(
                expected,
                &oracle.snapshot(&child, original, oracle.code.bytes()),
            );
            events.extend(
                hooks
                    .enabled
                    .iter()
                    .filter(|event| event.logical_pc == original)
                    .copied(),
            );
            hooks.log.assert_events(&child, &events);
            next += 1;
            if trace.terminals.contains(&original) {
                assert_eq!(next, trace.baseline.points.len());
                assert!(pending.is_none());
                assert!(after_branch.is_none());
                for (index, gate) in gates.iter().enumerate() {
                    assert_eq!(
                        per_gate[index],
                        trace
                            .baseline
                            .points
                            .iter()
                            .filter(|point| point.logical_pc == gate.logical_pc)
                            .count()
                    );
                }
                assert_eq!(counts[0], counts[1] + counts[2]);
                assert_eq!(counts[0] as usize, per_gate.iter().sum::<usize>());
                return counts;
            }
        } else if (source..source + PAGE as u64).contains(&pc) {
            panic!("unclassified early source PC {pc:#x}");
        }
        assert!(
            step < MAX_STEPS,
            "early static instruction budget exhausted"
        );
        child.step(&[]);
    }
    unreachable!()
}
