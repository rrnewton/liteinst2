// Additive test-only support. The old SignalResume implementation is exact.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundarySignalVisit {
    pub logical_pc: u64,
    /// Actual kernel-saved and rt_sigreturn-restored PC; never rewritten.
    pub physical_pc: u64,
    pub roundtrips_before: usize,
    pub roundtrips_after: usize,
}

/// Complete ordered inventory; repeated logical/physical visits are retained.
pub fn assert_boundary_signal_inventory(actual: &[BoundarySignalVisit], expected: &[(u64, u64)]) {
    assert!(!expected.is_empty(), "empty boundary signal obligation");
    assert_eq!(
        actual.len(),
        expected.len(),
        "boundary signal inventory length"
    );
    let first = actual[0].roundtrips_before;
    for (index, (actual, &(logical, physical))) in actual.iter().zip(expected).enumerate() {
        assert_eq!(
            (actual.logical_pc, actual.physical_pc),
            (logical, physical),
            "boundary signal location mismatch"
        );
        assert_eq!(
            actual.roundtrips_before,
            first.checked_add(index).unwrap(),
            "boundary signal count sequence"
        );
        assert_eq!(
            actual.roundtrips_after,
            actual.roundtrips_before.checked_add(1).unwrap(),
            "missing actual signal roundtrip"
        );
    }
}

impl NativeOracle {
    /// Reuse the exact signal-frame/rt_sigreturn witness at every restored visit.
    /// Kernel physical RIP is preserved; logical lookup is a separate assertion.
    pub fn assert_trace_at_signal_boundaries(
        &self,
        trace: &NativeTrace,
        entry: u64,
        map: &TraceMap,
        owned_sigill_heads: &[u64],
        hooks: Option<HookExpectation<'_>>,
        signal: &SignalResume,
    ) -> Vec<BoundarySignalVisit> {
        let relays: &[SourceRelay<'_>] = &[];
        let logical: BTreeSet<_> = trace.heads.union(&trace.terminals).copied().collect();
        let mut physical = BTreeMap::new();
        for &(original, generated) in &map.boundaries {
            assert!(
                logical.contains(&original),
                "undeclared logical restored boundary"
            );
            assert!(
                physical.insert(generated, original).is_none(),
                "duplicate physical restored boundary"
            );
            assert!(
                generated == original
                    || map
                        .generated_ranges
                        .iter()
                        .any(|range| range.contains(&generated)),
                "restored boundary outside declared generated images"
            );
        }
        for original in logical {
            assert!(
                physical.values().any(|&pc| pc == original),
                "missing restored boundary for {original:#x}"
            );
        }
        for &gateway in &map.gateways {
            assert!(trace.heads.contains(&gateway), "undeclared source gateway");
            assert!(
                !physical.contains_key(&gateway),
                "gateway is a restored boundary"
            );
        }
        let relay_map = self.validate_relays(trace, map, &physical, relays);
        if let Some(hooks) = &hooks {
            let mut ids = BTreeSet::new();
            for event in hooks.enabled {
                assert!(
                    trace.heads.contains(&event.logical_pc),
                    "hook outside original heads"
                );
                assert!(
                    ids.insert(event.probe_id),
                    "duplicate enabled probe identity"
                );
            }
        }
        let _active_log = hooks.as_ref().map(|hooks| hooks.log.activate());
        self.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        let child = Tracee::fork();
        let mut initial = trace.baseline.initial;
        initial.rip = entry;
        child.set_registers(&initial);
        child.set_xstate(&trace.baseline.xstate);
        let mut witnessed = Vec::new();
        let mut signal_steps = 0_usize;
        let mut next = 0;
        let mut events = Vec::new();
        let mut relay_visits = BTreeMap::<u64, usize>::new();
        let mut relay_target = None;
        for step in 0..=MAX_STEPS {
            assert!(
                Instant::now() < child.deadline,
                "patched trace wall deadline exhausted"
            );
            let pc = child.registers().rip;
            if let Some(target) = relay_target.take() {
                assert_eq!(
                    pc, target,
                    "source relay did not reach its exact image entry"
                );
            }
            if let Some(&original) = physical.get(&pc) {
                let expected = trace
                    .baseline
                    .points
                    .get(next)
                    .expect("extra restored boundary after native trace");
                assert_eq!(
                    original, expected.logical_pc,
                    "unexpected restored boundary at visit {next}"
                );
                assert_state(
                    expected,
                    &self.snapshot(&child, original, self.code.bytes()),
                );
                if let Some(hooks) = &hooks {
                    events.extend(
                        hooks
                            .enabled
                            .iter()
                            .filter(|event| event.logical_pc == original)
                            .copied(),
                    );
                    hooks.log.assert_events(&child, &events);
                }
                // The existing state/event checks above must pass before
                // injection. Four fixed handler/restorer instructions are
                // charged to the same 20,000-instruction ceiling: INT3,
                // RET, MOV RAX,15 and SYSCALL. No budget is reset.
                signal_steps = signal_steps.checked_add(4).unwrap();
                assert!(
                    step.checked_add(signal_steps).unwrap() <= MAX_STEPS,
                    "signal trace instruction budget exhausted"
                );
                let before = signal.completed_roundtrips();
                signal.resume(self, &child);
                let after = signal.completed_roundtrips();
                assert_eq!(
                    after,
                    before.checked_add(1).unwrap(),
                    "missing actual signal roundtrip"
                );
                assert_eq!(
                    child.registers().rip,
                    pc,
                    "signal changed physical continuation"
                );
                assert!(
                    Instant::now() < child.deadline,
                    "signal trace wall deadline exhausted"
                );
                assert_state(
                    expected,
                    &self.snapshot(&child, original, self.code.bytes()),
                );
                if let Some(hooks) = &hooks {
                    hooks.log.assert_events(&child, &events);
                }
                witnessed.push(BoundarySignalVisit {
                    logical_pc: original,
                    physical_pc: pc,
                    roundtrips_before: before,
                    roundtrips_after: after,
                });
                next += 1;
                if trace.terminals.contains(&original) {
                    assert_eq!(
                        next,
                        trace.baseline.points.len(),
                        "missing native trace visits"
                    );
                    for relay in relays {
                        let required = trace
                            .baseline
                            .points
                            .iter()
                            .filter(|point| point.logical_pc == relay.logical_pc)
                            .count();
                        assert_eq!(
                            relay_visits.get(&relay.relay_pc).copied().unwrap_or(0),
                            required,
                            "missing or duplicate source relay visits"
                        );
                    }
                    return witnessed;
                }
            } else if let Some(&index) = relay_map.get(&pc) {
                let relay = &relays[index];
                let expected = trace
                    .baseline
                    .points
                    .get(next)
                    .expect("extra source relay after native trace");
                assert_eq!(
                    relay.logical_pc, expected.logical_pc,
                    "unexpected source relay at visit {next}"
                );
                assert_state(
                    expected,
                    &self.snapshot(&child, relay.logical_pc, self.code.bytes()),
                );
                if let Some(hooks) = &hooks {
                    hooks.log.assert_events(&child, &events);
                }
                *relay_visits.entry(pc).or_default() += 1;
                relay_target = Some(relay.target);
            } else if (self.code.address()..self.code.address() + PAGE as u64).contains(&pc) {
                assert!(
                    map.gateways.contains(&pc),
                    "unclassified source head {pc:#x}"
                );
            }
            assert!(
                step < MAX_STEPS,
                "patched trace instruction budget exhausted"
            );
            assert!(
                step.checked_add(signal_steps).unwrap() < MAX_STEPS,
                "signal trace instruction budget exhausted"
            );
            child.step(owned_sigill_heads);
        }
        unreachable!()
    }
}

#[cfg(test)]
mod calibration {
    use super::*;
    fn expected() -> [(u64, u64); 3] {
        [(10, 100), (10, 100), (20, 20)]
    }
    fn valid() -> Vec<BoundarySignalVisit> {
        expected()
            .iter()
            .enumerate()
            .map(|(i, &(logical_pc, physical_pc))| BoundarySignalVisit {
                logical_pc,
                physical_pc,
                roundtrips_before: 7 + i,
                roundtrips_after: 8 + i,
            })
            .collect()
    }
    #[test]
    fn repeated_boundaries_keep_order_and_physical_identity() {
        assert_boundary_signal_inventory(&valid(), &expected());
    }
    #[test]
    #[should_panic(expected = "boundary signal inventory length")]
    fn rejects_missing_terminal_roundtrip() {
        let mut v = valid();
        v.pop();
        assert_boundary_signal_inventory(&v, &expected());
    }
    #[test]
    #[should_panic(expected = "boundary signal inventory length")]
    fn rejects_duplicate_roundtrip() {
        let mut v = valid();
        v.push(v[2]);
        assert_boundary_signal_inventory(&v, &expected());
    }
    #[test]
    #[should_panic(expected = "boundary signal location mismatch")]
    fn rejects_wrong_logical_pc() {
        let mut v = valid();
        v[1].logical_pc = 11;
        assert_boundary_signal_inventory(&v, &expected());
    }
    #[test]
    #[should_panic(expected = "boundary signal location mismatch")]
    fn rejects_wrong_physical_pc() {
        let mut v = valid();
        v[1].physical_pc = 10;
        assert_boundary_signal_inventory(&v, &expected());
    }
    #[test]
    #[should_panic(expected = "missing actual signal roundtrip")]
    fn rejects_uncompleted_roundtrip() {
        let mut v = valid();
        v[1].roundtrips_after = v[1].roundtrips_before;
        assert_boundary_signal_inventory(&v, &expected());
    }
}
