// Exact previous parked trace body with a separate Word schedule seam.
impl NativeOracle {
    pub fn assert_trace_word_publication(
        &self,
        trace: &NativeTrace,
        entry: u64,
        map: &TraceMap,
        owned_sigill_heads: &[u64],
        hooks: Option<HookExpectation<'_>>,
        parked: &WordPublication,
    ) {
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
        let _parked_active = parked.activate();
        let child = parked.fork();
        let mut initial = trace.baseline.initial;
        initial.rip = entry;
        child.set_registers(&initial);
        child.set_xstate(&trace.baseline.xstate);
        let charged_steps = parked.publish_and_resume(
            self,
            &child,
            hooks
                .as_ref()
                .expect("parked publication requires an active hook log")
                .log,
        );
        let mut next = 0;
        let mut events = Vec::new();
        let mut relay_visits = BTreeMap::<u64, usize>::new();
        let mut relay_target = None;
        for step in charged_steps..=MAX_STEPS {
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
                    &self.snapshot(&child, original, parked.expected_source()),
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
                    return;
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
                    &self.snapshot(&child, relay.logical_pc, parked.expected_source()),
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
            child.step(owned_sigill_heads);
        }
        unreachable!()
    }
}
