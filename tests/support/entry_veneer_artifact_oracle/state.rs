// Included inside ordered_trace; captures and the full comparator stay private.
// This is a separate opt-in witness, never an alternate range for the old oracle.
#[derive(Clone, Copy)]
pub struct EntryVeneerSpec {
    pub logical_pc: u64,
    pub storage: u64,
    pub entry: u64,
    pub body_len: usize,
    pub size_bound: usize,
}

impl EntryVeneerSpec {
    /// Pure geometry/bytes/map admission; no execution or fabricated state.
    pub fn validate_image(&self, bytes: &[u8], map: &TraceMap) -> Result<(), &'static str> {
        let page_end = self.storage.checked_add(PAGE as u64).ok_or("veneer page wraps")?;
        let offset = self.entry.checked_sub(self.storage).ok_or("veneer entry precedes storage")?;
        if !self.storage.is_multiple_of(PAGE as u64) || offset > (PAGE - 5) as u64
            || self.size_bound == 0 || self.size_bound > PAGE - 5
            || self.body_len == 0 || self.body_len > self.size_bound
            || self.size_bound as u64 > offset
        {
            return Err("veneer body/bound/page geometry mismatch");
        }
        let offset = usize::try_from(offset).map_err(|_| "veneer offset unrepresentable")?;
        if bytes.len() != offset + 5 || self.entry + 5 > page_end
            || bytes[self.body_len..offset].iter().any(|&byte| byte != 0xcc)
        {
            return Err("veneer full body/gap/envelope partition mismatch");
        }
        if bytes[offset..] != exact_e9(self.entry, self.storage) {
            return Err("veneer is not the exact entry-to-body E9");
        }
        let range = self.storage..self.entry + 5;
        if map.generated_ranges.iter().filter(|image| **image == range).count() != 1
            || map.generated_ranges.iter().filter(|image| image.start < page_end && self.storage < image.end).count() != 1
        {
            return Err("veneer lacks one exact disjoint full envelope");
        }
        let body_end = self.storage + self.body_len as u64;
        let boundaries: Vec<_> = map.boundaries.iter().filter(|(_, generated)| (self.storage..page_end).contains(generated)).collect();
        if boundaries.len() != 1 || boundaries[0].0 != self.logical_pc
            || !(self.storage..body_end).contains(&boundaries[0].1)
            || map.gateways.iter().any(|pc| (self.storage..page_end).contains(pc))
        {
            return Err("veneer has padding/entry or foreign restored authority");
        }
        Ok(())
    }
}

/// Immutable expected bytes borrow all three live page owners through every
/// child. The caller supplies full pages derived from the exact artifact/hook.
pub struct EntryVeneerWitness<'a> {
    spec: EntryVeneerSpec,
    envelope: Vec<u8>,
    pages: [(&'a Mapping, &'a [u8]); 3],
}

impl<'a> EntryVeneerWitness<'a> {
    pub fn new(
        spec: EntryVeneerSpec,
        envelope: &[u8],
        pages: [(&'a Mapping, &'a [u8]); 3],
    ) -> Self {
        for (index, (mapping, expected)) in pages.iter().enumerate() {
            assert_eq!(mapping.len, PAGE, "veneer requires complete page ownership");
            assert_eq!(expected.len(), PAGE, "veneer page snapshot incomplete");
            assert_eq!(mapping.address() % PAGE as u64, 0);
            assert_eq!(mapping.bytes(), *expected, "veneer parent page differs from exact artifact");
            assert!(pages[..index].iter().all(|(old, _)| old.address() != mapping.address()), "veneer page owners overlap");
        }
        let selected: Vec<_> = pages.iter().filter(|(mapping, _)| mapping.address() == spec.storage).collect();
        assert_eq!(selected.len(), 1, "veneer storage lacks exact page owner");
        assert_eq!(selected[0].1.get(..envelope.len()), Some(envelope), "veneer envelope differs from retained page");
        Self { spec, envelope: envelope.to_vec(), pages }
    }

    fn validate(&self, oracle: &NativeOracle, trace: &NativeTrace, map: &TraceMap, relays: &[ShortSourceRelay<'_>]) {
        self.spec.validate_image(&self.envelope, map).expect("invalid entry veneer witness");
        assert!(trace.heads.contains(&self.spec.logical_pc), "veneer logical PC is not original");
        assert_eq!(relays.len(), 1, "veneer profile requires exactly one short source relay");
        assert_eq!((relays[0].logical_pc, relays[0].target), (self.spec.logical_pc, self.spec.entry), "veneer/source-relay identity mismatch");
        assert_eq!(map.generated_ranges.len(), 2, "veneer profile requires both complete images");
        for image in &map.generated_ranges {
            assert!(image.start < image.end, "empty veneer-profile image");
            assert_eq!(self.pages.iter().filter(|(mapping, _)| {
                image.start == mapping.address() && image.end <= mapping.address() + PAGE as u64
            }).count(), 1, "generated image lacks its full retained page readback");
        }
        for (mapping, _) in &self.pages {
            assert_ne!(mapping.address(), oracle.code.address(), "veneer page overlaps original source");
        }
        self.assert_parent_pages();
    }

    fn image_base(&self, target: u64, logical: u64) -> u64 {
        if target == self.spec.entry {
            assert_eq!(logical, self.spec.logical_pc, "veneer target has foreign logical owner");
            self.spec.storage
        } else {
            assert_ne!(logical, self.spec.logical_pc, "selected relay bypasses veneer entry");
            target
        }
    }

    fn assert_parent_pages(&self) {
        for (mapping, bytes) in &self.pages {
            assert_eq!(mapping.bytes(), *bytes, "veneer parent full-page readback changed");
        }
    }

    fn assert_child_pages(&self, child: &Tracee) {
        for (mapping, bytes) in &self.pages {
            assert_eq!(child.memory(mapping.address(), PAGE), *bytes, "veneer child full-page readback changed");
        }
    }

    fn assert_pc(&self, pc: u64) {
        let body_end = self.spec.storage + self.spec.body_len as u64;
        if (body_end..self.spec.storage + PAGE as u64).contains(&pc) {
            assert_eq!(pc, self.spec.entry, "veneer traversed padding or instruction interior");
        }
    }
}

impl NativeOracle {
    /// Admission only: no child is forked and no generated instruction runs.
    pub fn assert_entry_veneer_preflight(
        &self,
        trace: &NativeTrace,
        map: &TraceMap,
        relays: &[ShortSourceRelay<'_>],
        veneer: &EntryVeneerWitness<'_>,
    ) {
        let physical = self.ordered_physical(trace, map);
        veneer.validate(self, trace, map, relays);
        self.validate_short_relays_inner(trace, map, &physical, relays, Some(veneer));
    }

    pub fn assert_trace_with_entry_veneer(
        &self,
        trace: &NativeTrace,
        entry: u64,
        map: &TraceMap,
        relays: &[ShortSourceRelay<'_>],
        veneer: &EntryVeneerWitness<'_>,
        hooks: Option<HookExpectation<'_>>,
    ) {
        let physical = self.ordered_physical(trace, map);
        veneer.validate(self, trace, map, relays);
        let relay_map = self.validate_short_relays_inner(trace, map, &physical, relays, Some(veneer));
        let coordinates = relays.iter().map(|relay| RelayCoordinates {
            logical_pc: relay.logical_pc, relay_pc: relay.relay_pc, target: relay.target,
        }).collect();
        self.assert_validated_trace(
            trace, entry,
            ValidatedTrace { map, physical, relay_map, relays: coordinates, veneer: Some(veneer) },
            &[], hooks,
        );
        veneer.assert_parent_pages();
    }
}

impl NativeTrace {
    /// Prove the original JNZ decision from its observed flags and raw next PC;
    /// the fixture's literal target/fallthrough are independent of the planner.
    pub fn assert_entry_veneer_jnz(&self, selected: u64, zero: bool) -> usize {
        let mut count = 0;
        for (index, before) in self.baseline.points.iter().enumerate() {
            if before.logical_pc != selected { continue; }
            assert_eq!(before.registers.rip, selected);
            assert_eq!(before.registers.eflags & (1 << 6) != 0, zero);
            let next = selected + if zero { 2 } else { 3 };
            let after = self.baseline.points.get(index + 1).expect("missing original JNZ successor");
            assert_eq!((after.logical_pc, after.registers.rip), (next, next));
            let expected = Snapshot {
                logical_pc: next, registers: before.registers,
                xstate: before.xstate.clone(), data: before.data.clone(),
                application_stack: before.application_stack.clone(),
            };
            assert_state(&expected, after);
            count += 1;
        }
        count
    }
}
