// Included in ordered_trace. This authorization never reaches the old relay
// validators, and never obtains instruction length from planner metadata.
pub struct OverlappingSourceRelay<'a> {
    pub logical_pc: u64,
    pub relay_pc: u64,
    pub target: u64,
    pub victim_target: u64,
    pub victim_trace: &'a NativeTrace,
}

/// Both image pages and the hook bridge remain owned throughout every child.
pub struct OverlappingPages<'a> {
    pages: [(&'a Mapping, &'a [u8]); 3],
}

impl<'a> OverlappingPages<'a> {
    pub fn new(pages: [(&'a Mapping, &'a [u8]); 3]) -> Self {
        for (index, (mapping, expected)) in pages.iter().enumerate() {
            assert_eq!(mapping.len, PAGE, "overlap requires full page ownership");
            assert_eq!(expected.len(), PAGE, "overlap requires full page snapshot");
            assert_eq!(mapping.address() & (PAGE as u64 - 1), 0);
            assert!(
                pages[..index]
                    .iter()
                    .all(|(other, _)| other.address() != mapping.address()),
                "overlap page owners coincide"
            );
            assert_eq!(mapping.bytes(), *expected, "overlap parent page differs");
        }
        Self { pages }
    }

    fn validate(&self, oracle: &NativeOracle, map: &TraceMap) {
        assert_eq!(
            map.generated_ranges.len(),
            2,
            "overlap requires two full images"
        );
        let mut owners = BTreeSet::new();
        for image in &map.generated_ranges {
            assert!(image.start < image.end, "overlap image is empty");
            let owners_for_image: Vec<_> = self.pages[..2]
                .iter()
                .filter(|(mapping, _)| {
                    mapping.address() <= image.start && image.end <= mapping.address() + PAGE as u64
                })
                .collect();
            assert_eq!(
                owners_for_image.len(),
                1,
                "overlap image lacks its full page"
            );
            assert!(
                owners.insert(owners_for_image[0].0.address()),
                "overlap images share a page"
            );
        }
        for (mapping, _) in &self.pages {
            assert_ne!(
                mapping.address(),
                oracle.code.address(),
                "overlap page owns source"
            );
        }
        self.assert_parent_pages();
    }

    fn assert_pc(&self, pc: u64, map: &TraceMap) {
        for (mapping, _) in &self.pages[..2] {
            if (mapping.address()..mapping.address() + PAGE as u64).contains(&pc) {
                assert_eq!(
                    map.generated_ranges
                        .iter()
                        .filter(|image| image.contains(&pc))
                        .count(),
                    1,
                    "overlap executed image-page padding"
                );
            }
        }
    }

    fn assert_parent_pages(&self) {
        for (mapping, bytes) in &self.pages {
            assert_eq!(mapping.bytes(), *bytes, "overlap parent full page changed");
        }
    }

    fn assert_child_pages(&self, child: &Tracee) {
        for (mapping, bytes) in &self.pages {
            assert_eq!(
                child.memory(mapping.address(), PAGE),
                *bytes,
                "overlap child full page changed"
            );
        }
    }
}

impl NativeOracle {
    // One independent MOV EAX witness proves the complete original victim.
    // The two E9s authorize V and V+1 separately, with exact shared bytes.
    fn validate_overlapping_relay(
        &self,
        trace: &NativeTrace,
        map: &TraceMap,
        physical: &BTreeMap<u64, u64>,
        relay: &OverlappingSourceRelay<'_>,
    ) -> (BTreeMap<u64, usize>, Vec<RelayCoordinates>) {
        let source = self.code.address();
        let source_end = source.checked_add(PAGE as u64).unwrap();
        assert_eq!(self.original_code.len(), PAGE);
        assert_eq!(
            trace.source_base, source,
            "foreign overlap execution source"
        );
        assert_eq!(
            trace.original_code, self.original_code,
            "foreign overlap execution page"
        );
        let witness = relay.victim_trace;
        assert_eq!(
            witness.source_base, source,
            "foreign overlap witness source"
        );
        assert_eq!(
            witness.original_code, self.original_code,
            "foreign overlap witness page"
        );
        assert_eq!(witness.heads, trace.heads, "overlap witness heads differ");
        assert_eq!(
            witness.terminals, trace.terminals,
            "overlap witness terminals differ"
        );
        let (victim, native_next) = witness
            .first_step
            .expect("overlap witness lacks first step");
        assert_eq!(
            witness.baseline.initial.rip, victim,
            "overlap witness entry mismatch"
        );
        let before = witness
            .baseline
            .points
            .first()
            .expect("overlap witness lacks first snapshot");
        let after = witness
            .baseline
            .points
            .get(1)
            .expect("overlap witness lacks second snapshot");
        assert_eq!(
            (before.logical_pc, before.registers.rip),
            (victim, victim),
            "overlap first snapshot mismatch"
        );
        assert!(
            (source..source_end).contains(&victim),
            "overlap victim outside source"
        );
        let offset = usize::try_from(victim - source).unwrap();
        let original = &self.original_code[offset..];
        let prefixes = original
            .iter()
            .take(11)
            .take_while(|&&byte| byte == 0x2e)
            .count();
        assert!(
            (1..=10).contains(&prefixes),
            "overlap MOV prefix count outside1..10"
        );
        assert_eq!(
            original.get(prefixes),
            Some(&0xb8),
            "overlap requires native MOV EAX grammar"
        );
        let immediate = original
            .get(prefixes + 1..prefixes + 5)
            .expect("overlap MOV is truncated");
        let victim_len = prefixes + 5;
        let victim_end = victim.checked_add(victim_len as u64).unwrap();
        assert!(victim_end <= source_end);
        assert_eq!(
            native_next, victim_end,
            "overlap raw step does not prove victim length"
        );
        assert_eq!(
            (after.logical_pc, after.registers.rip),
            (victim_end, victim_end),
            "overlap second snapshot mismatch"
        );
        let mut registers = before.registers;
        registers.rax = u64::from(u32::from_le_bytes(immediate.try_into().unwrap()));
        registers.rip = victim_end;
        assert_state(
            &Snapshot {
                logical_pc: victim_end,
                registers,
                xstate: before.xstate.clone(),
                data: before.data.clone(),
                application_stack: before.application_stack.clone(),
            },
            after,
        );

        let selected = relay.logical_pc;
        assert!(
            (source..source_end).contains(&selected),
            "overlap selected outside source"
        );
        let selected_offset = usize::try_from(selected - source).unwrap();
        let selected_original = &self.original_code[selected_offset..];
        let selected_len = if selected_original.starts_with(&[0xff, 0xc0]) {
            2
        } else if selected_original.starts_with(&[0x48, 0xff, 0xc0]) {
            3
        } else if selected_original.starts_with(&[0x48, 0x83, 0xc0, 1]) {
            4
        } else {
            panic!("overlap selected lacks independent INC/ADD grammar")
        };
        let selected_end = selected.checked_add(selected_len).unwrap();
        assert!(
            selected_end <= victim || victim_end <= selected,
            "overlap original instructions intersect"
        );
        assert_eq!(relay.relay_pc, victim + 1, "overlap relay is not V+1");
        assert!(
            trace.heads.contains(&selected) && trace.heads.contains(&victim),
            "overlap lacks original heads"
        );
        assert_eq!(
            map.gateways.len(),
            2,
            "overlap requires exactly two gateways"
        );
        assert!(map.gateways.contains(&selected) && map.gateways.contains(&victim));
        for (start, end) in [(selected, selected_end), (victim, victim_end)] {
            assert!(
                trace
                    .heads
                    .iter()
                    .chain(&trace.terminals)
                    .all(|pc| *pc == start || !(start..end).contains(pc)),
                "overlap has interior original head"
            );
            assert!(
                physical.keys().all(|pc| !(start..end).contains(pc)),
                "overlap has source restored boundary"
            );
            assert!(
                map.gateways
                    .iter()
                    .all(|pc| *pc == start || !(start..end).contains(pc)),
                "overlap has interior gateway"
            );
        }
        assert_eq!(map.generated_ranges.len(), 2);
        assert_ne!(
            relay.target, relay.victim_target,
            "overlap image entries coincide"
        );
        for (target, logical) in [(relay.target, selected), (relay.victim_target, victim)] {
            let images: Vec<_> = map
                .generated_ranges
                .iter()
                .filter(|image| image.start == target)
                .collect();
            assert_eq!(images.len(), 1, "overlap target is not exact image entry");
            let image = images[0];
            assert!(image.start < image.end);
            assert!(
                image.end <= source || source_end <= image.start,
                "overlap image owns original source"
            );
            let boundaries: Vec<_> = map
                .boundaries
                .iter()
                .filter(|(_, pc)| image.contains(pc))
                .collect();
            assert_eq!(boundaries.len(), 1, "overlap image restored count differs");
            assert_eq!(
                boundaries[0].0, logical,
                "overlap image has foreign restored owner"
            );
        }
        let selected_jump = exact_e9(relay.relay_pc, relay.target);
        let victim_jump = exact_e9(victim, relay.victim_target);
        assert_eq!(
            &victim_jump[1..],
            &selected_jump[..4],
            "overlap E9 shared bytes disagree"
        );
        let mut source_patch = victim_jump.to_vec();
        source_patch.push(selected_jump[4]);
        assert_eq!(source_patch.len(), 6);
        let rel8 = i8::try_from(i128::from(relay.relay_pc) - i128::from(selected + 2))
            .expect("overlap EB outside signed reach");
        let mut expected_page = self.original_code.clone();
        expected_page[selected_offset..selected_offset + 2].copy_from_slice(&[0xeb, rel8 as u8]);
        expected_page[offset..offset + 6].copy_from_slice(&source_patch);
        assert_eq!(
            self.code.bytes(),
            expected_page,
            "unauthorized overlapping source publication"
        );
        let coordinates = vec![
            RelayCoordinates {
                logical_pc: selected,
                relay_pc: relay.relay_pc,
                target: relay.target,
            },
            RelayCoordinates {
                logical_pc: victim,
                relay_pc: victim,
                target: relay.victim_target,
            },
        ];
        (
            BTreeMap::from([(relay.relay_pc, 0), (victim, 1)]),
            coordinates,
        )
    }

    pub fn assert_overlapping_preflight(
        &self,
        trace: &NativeTrace,
        map: &TraceMap,
        relay: &OverlappingSourceRelay<'_>,
        pages: &OverlappingPages<'_>,
    ) {
        let physical = self.ordered_physical(trace, map);
        pages.validate(self, map);
        self.validate_overlapping_relay(trace, map, &physical, relay);
    }

    pub fn assert_trace_with_overlapping_relay(
        &self,
        trace: &NativeTrace,
        entry: u64,
        map: &TraceMap,
        relay: &OverlappingSourceRelay<'_>,
        pages: &OverlappingPages<'_>,
        hooks: Option<HookExpectation<'_>>,
    ) {
        let physical = self.ordered_physical(trace, map);
        pages.validate(self, map);
        let (relay_map, relays) = self.validate_overlapping_relay(trace, map, &physical, relay);
        self.assert_validated_trace_with_overlap(
            trace,
            entry,
            ValidatedTrace {
                map,
                physical,
                relay_map,
                relays,
                veneer: None,
            },
            &[],
            hooks,
            Some(pages),
        );
        pages.assert_parent_pages();
    }

    /// Corrupt copies of a real capture. Positive admission precedes every
    /// negative; no generated instruction or fabricated positive state runs.
    pub fn assert_overlapping_witness_negatives(
        &self,
        trace: &NativeTrace,
        map: &TraceMap,
        relay: &OverlappingSourceRelay<'_>,
        pages: &OverlappingPages<'_>,
    ) {
        self.assert_overlapping_preflight(trace, map, relay, pages);
        let original = relay.victim_trace;
        assert!(original.baseline.fault.is_none());
        for mutation in 0..10 {
            let mut witness = NativeTrace {
                baseline: Baseline {
                    initial: original.baseline.initial,
                    xstate: original.baseline.xstate.clone(),
                    points: original
                        .baseline
                        .points
                        .iter()
                        .map(|point| Snapshot {
                            logical_pc: point.logical_pc,
                            registers: point.registers,
                            xstate: point.xstate.clone(),
                            data: point.data.clone(),
                            application_stack: point.application_stack.clone(),
                        })
                        .collect(),
                    fault: None,
                },
                heads: original.heads.clone(),
                terminals: original.terminals.clone(),
                source_base: original.source_base,
                original_code: original.original_code.clone(),
                first_step: original.first_step,
            };
            let mut relay_pc = relay.relay_pc;
            let mut target = relay.target;
            let reason = match mutation {
                0 => {
                    witness.first_step = None;
                    "overlap witness lacks first step"
                }
                1 => {
                    witness.first_step.as_mut().unwrap().0 += 1;
                    "overlap witness entry mismatch"
                }
                2 => {
                    witness.baseline.points.truncate(1);
                    "overlap witness lacks second snapshot"
                }
                3 => {
                    witness.original_code.pop().unwrap();
                    "foreign overlap witness page"
                }
                4 => {
                    witness.baseline.points[0].logical_pc += 1;
                    "overlap first snapshot mismatch"
                }
                5 => {
                    witness.baseline.points[1].registers.rax ^= 1;
                    "rax mismatch"
                }
                6 => {
                    witness.baseline.points[1].registers.rcx ^= 1;
                    "rcx mismatch"
                }
                7 => {
                    witness.first_step.as_mut().unwrap().1 += 1;
                    "overlap raw step does not prove victim length"
                }
                8 => {
                    relay_pc += 1;
                    "overlap relay is not V+1"
                }
                _ => {
                    target += 1;
                    "overlap target is not exact image entry"
                }
            };
            let bad = OverlappingSourceRelay {
                logical_pc: relay.logical_pc,
                relay_pc,
                target,
                victim_target: relay.victim_target,
                victim_trace: &witness,
            };
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.assert_overlapping_preflight(trace, map, &bad, pages);
            }))
            .expect_err("malformed overlap witness accepted");
            let message = failure
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| failure.downcast_ref::<&str>().copied())
                .expect("nontext overlap refusal");
            assert!(
                message.contains(reason),
                "expected {reason:?}, observed {message:?}"
            );
        }
    }
}
