//! Source/contract/emission controls; no generated instruction is executed.

use super::*;
use crate::backedge_clock::{CLOCK_PAGE_BYTES, ClockMode};
use crate::composition::Composition;
use crate::controls::ControlIdentity;
use crate::trampoline::HookContext;

// MOV eax,0; MOV ecx,edi; JMP to first gate; DEC ecx; near JNZ to DEC;
// MOV edx,esi; DEC edx; near JG to second DEC; final RET.
// The forward JMP must target the first gate's entry, never its restored body.
const SOURCE: &[u8] = &[
    0xb8, 0, 0, 0, 0, 0x89, 0xf9, 0xeb, 2, 0xff, 0xc9, 0x0f, 0x85, 0xf8, 0xff, 0xff, 0xff, 0x89,
    0xf2, 0xff, 0xca, 0x0f, 0x8f, 0xf8, 0xff, 0xff, 0xff, 0xc3,
];

unsafe extern "C" fn callback(_: *mut HookContext, _: ControlIdentity<'_>) {}

fn clock() -> BackedgeClock {
    // Only the separate RW data page is allocated. No executable image or
    // source mapping is published by these emission controls.
    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            CLOCK_PAGE_BYTES,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    unsafe { BackedgeClock::from_owned_mapping(page as usize as u64, CLOCK_PAGE_BYTES) }.unwrap()
}

struct Fixture {
    region: BackedgeClockRegion,
    entries: LegalEntrySet,
    allocation: AllocationPolicy,
}

impl Fixture {
    fn new(mode: ClockMode) -> Self {
        let page = clock();
        let base = page.address() + 0x10000;
        let identity = CodeIdentity {
            source: SourceIdentity([119; 32]),
            mapping: base,
            generation: 1,
        };
        let managed = [11, 21].map(|offset| {
            let (control, writer) = ProbeControl::new_managed_bound(callback, true);
            (base + offset, control, writer)
        });
        let region = BackedgeClockRegion::new_owned_region(
            identity,
            base,
            SOURCE,
            managed,
            page.clone(),
            mode,
        )
        .unwrap();
        let entries = LegalEntrySet {
            identity,
            scope: AddressRange::new(base, SOURCE.len()).unwrap(),
            provenance: EntryProvenance::Declared("two-backedge closed scalar fixture".into()),
            completeness: EntryCompleteness::Complete,
            entries: [0, 9, 11, 17, 19, 27]
                .map(|offset| LegalEntry {
                    address: base + offset,
                    requires_endbr: false,
                })
                .to_vec(),
            resumes: ResumeObligation::NoneExist,
        };
        let target = page.address() + 0x20000;
        let allocation = AllocationPolicy {
            ranges: vec![AddressRange::new(target, 8192).unwrap()],
            preferred_address: Some(target),
            max_candidates: 1,
            max_mappings: 1,
            max_mapped_bytes: 8192,
        };
        Self {
            region,
            entries,
            allocation,
        }
    }

    fn base(&self) -> u64 {
        self.entries.scope.start()
    }

    fn scan(&self) -> ScanResult {
        InstructionScanner::default()
            .scan(SOURCE, self.base())
            .unwrap()
    }

    fn proof(&self) -> Result<Verified, Refusal> {
        Verified::new(&self.region, &self.entries, &self.allocation, &self.scan())
    }

    fn request(&self) -> PlanningRequest<'_> {
        PlanningRequest {
            site: PlanningSite {
                identity: self.entries.identity,
                code: SOURCE,
                base_address: self.base(),
                function: self.entries.scope,
                block: self.entries.scope,
                logical_pc: self.base() + 11,
                entries: &self.entries,
                semantics: HookSemantics::Observe,
                allocation: &self.allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 80,
                    max_sites: 1,
                },
            },
            original_code: SOURCE,
            emission: EmissionContext::Live(self.region.actions[0].control.callback()),
        }
    }

    fn emit(&self, occupied: &[AddressRange]) -> Result<PlannedInstall, Refusal> {
        let scan = self.scan();
        let proof = self.proof()?;
        // Exercise the actual shared whole-region transaction using a declared
        // synthetic address space. This is not a live-vacancy or publisher test.
        emit_relocation_window(
            &self.request(),
            &scan,
            self.entries.scope,
            occupied,
            (None, None),
            RelocationWindow {
                physical: self.base(),
                end: self.entries.scope.end(),
                displaced: self.entries.scope,
                instructions: scan.instructions().iter().collect(),
                authority: RelocationAuthority::OwnedClockRegion {
                    proof: &proof,
                    region: &self.region,
                },
            },
            &mut SearchEvidence::default(),
        )
    }

    fn plan(&self) -> PlannedInstall {
        self.emit(&[self.region.clock().range()]).unwrap()
    }
}

#[test]
fn owned_clock_region_one_transaction_preserves_all_heads_and_two_gates() {
    for mode in [ClockMode::Counter, ClockMode::Stop] {
        let fixture = Fixture::new(mode);
        let plan = fixture.plan();
        let parts = plan.plan().parts();
        assert_eq!(parts.displaced, fixture.entries.scope);
        assert_eq!(parts.physical_pc, fixture.base());
        assert_eq!(parts.logical_pc, fixture.base() + 11);
        assert_eq!(
            parts.reads,
            [ExpectedBytes {
                address: fixture.base(),
                bytes: SOURCE.to_vec()
            }]
        );
        assert_eq!(parts.dependencies, [fixture.entries.scope]);
        assert_eq!(parts.writes.len(), 1);
        assert_eq!(parts.writes[0].bytes.len(), SOURCE.len());
        assert_eq!(parts.writes[0].bytes[0], 0xe9);
        assert_eq!(parts.allocations.len(), 1);
        assert!(parts.allocations[0].range.len() <= 8192);
        assert!(
            !parts.allocations[0]
                .range
                .overlaps(fixture.region.clock().range())
        );
        assert_eq!(parts.generated.len(), 1);
        assert_eq!(parts.generated[0].bytes, plan.image().bytes());
        assert_eq!(parts.entries, fixture.entries);
        assert!(
            parts.requirements.quiescent
                && parts.requirements.sync_core
                && parts.requirements.sigill_router
        );
        assert_eq!(plan.metrics().allocation_attempts, 1);
        assert_eq!(plan.metrics().displaced_bytes, SOURCE.len());
        assert_eq!(plan.image().clock(), Some(fixture.region.clock()));
        assert!(plan.image().clock_gate().is_none());
        assert_eq!(plan.image().clock_region_gates().len(), 2);
        assert_eq!(
            plan.image().controls(),
            fixture
                .region
                .actions
                .each_ref()
                .map(|action| action.control.clone())
        );
        let heads: Vec<_> = fixture
            .scan()
            .instructions()
            .iter()
            .map(|item| item.address())
            .collect();
        assert_eq!(
            plan.image()
                .entry_routes()
                .iter()
                .map(|entry| entry.0)
                .collect::<Vec<_>>(),
            heads
        );
        assert_eq!(
            plan.image()
                .instruction_boundaries()
                .iter()
                .map(|entry| entry.0)
                .collect::<Vec<_>>(),
            heads
        );
        for (gate, pc) in plan.image().clock_region_gates().iter().zip([11, 21]) {
            assert_eq!(gate.logical_pc, fixture.base() + pc);
            assert!(gate.gate.entry < gate.gate.observing_entry);
            assert!(gate.gate.observing_entry < gate.gate.original_body);
        }
        // The forward JMP reaches a gated head: compare the generated target
        // against entry, and explicitly distinguish it from the restored body.
        let jump = plan
            .image()
            .instruction_boundaries()
            .iter()
            .find(|entry| entry.0 == fixture.base() + 7)
            .unwrap()
            .1;
        let offset = (jump - plan.image().address()) as usize;
        let decoded = Decoder::with_ip(
            64,
            &plan.image().bytes()[offset..],
            jump,
            DecoderOptions::NONE,
        )
        .decode();
        let first_gate = plan.image().clock_region_gates()[0].gate;
        assert_eq!(decoded.near_branch_target(), first_gate.entry);
        assert_ne!(decoded.near_branch_target(), first_gate.original_body);
        assert_eq!(parts.obligations.len(), fixture.entries.entries.len());
        assert_eq!(
            parts.obligations[0],
            EntryObligation::Preserved(fixture.base())
        );
        for entry in &fixture.entries.entries[1..] {
            let generated = plan
                .image()
                .entry_routes()
                .iter()
                .find(|route| route.0 == entry.address)
                .unwrap()
                .1;
            assert!(
                parts
                    .obligations
                    .contains(&EntryObligation::Routed(EntryRoute {
                        original: entry.address,
                        generated,
                    }))
            );
        }
        let mut composition = Composition::new(
            fixture.entries.identity,
            vec![ExpectedBytes {
                address: fixture.base(),
                bytes: SOURCE.to_vec(),
            }],
        )
        .unwrap();
        composition.append(plan.plan()).unwrap();
        assert_eq!(composition.final_bytes()[0].bytes, parts.writes[0].bytes);
    }
}

#[test]
fn owned_clock_region_complete_entries_and_generation_are_not_optional() {
    let fixture = Fixture::new(ClockMode::Stop);
    let mut cases = Vec::new();
    let mut entries = fixture.entries.clone();
    entries.identity.generation += 1;
    cases.push((entries, Refusal::StaleGeneration));
    let mut entries = fixture.entries.clone();
    entries.scope = AddressRange::new(fixture.base(), SOURCE.len() - 1).unwrap();
    cases.push((entries, Refusal::InvalidRange));
    let mut entries = fixture.entries.clone();
    entries.completeness = EntryCompleteness::AllInstructionHeads;
    cases.push((entries, Refusal::UnresolvedEntry));
    let mut entries = fixture.entries.clone();
    entries.resumes = ResumeObligation::Enumerated(vec![fixture.base()]);
    cases.push((entries, Refusal::UnresolvedEntry));
    let mut entries = fixture.entries.clone();
    entries.entries[0].requires_endbr = true;
    cases.push((entries, Refusal::UnresolvedEntry));
    let mut entries = fixture.entries.clone();
    entries.entries.remove(2); // A branch target is a required complete leader.
    cases.push((entries, Refusal::UnresolvedEntry));
    let mut entries = fixture.entries.clone();
    entries.entries.insert(
        1,
        LegalEntry {
            address: fixture.base() + 5,
            requires_endbr: false,
        },
    );
    cases.push((entries, Refusal::UnresolvedEntry));
    let mut entries = fixture.entries.clone();
    entries.entries.swap(1, 2);
    cases.push((entries, Refusal::UnresolvedEntry));
    for (entries, expected) in cases {
        // SAFETY: refused planning only; nothing is published or executed.
        let error = unsafe {
            plan_owned_clock_region_detailed(&fixture.region, &entries, &fixture.allocation)
        }
        .err()
        .unwrap();
        assert_eq!(error.reason, expected);
        assert!(error.attempts.is_empty());
        assert!(!error.search.accepted);
    }
}

#[test]
fn owned_clock_region_fixed_ceilings_smaller_caps_and_occupancy_are_enforced() {
    for (candidates, mappings, bytes) in [(257, 1, 8192), (1, 2, 8192), (1, 1, 8193)] {
        let mut fixture = Fixture::new(ClockMode::Stop);
        fixture.allocation.max_candidates = candidates;
        fixture.allocation.max_mappings = mappings;
        fixture.allocation.max_mapped_bytes = bytes;
        // SAFETY: qualification refuses before host admission or emission.
        let error = unsafe {
            plan_owned_clock_region_detailed(&fixture.region, &fixture.entries, &fixture.allocation)
        }
        .err()
        .unwrap();
        assert_eq!(error.reason, Refusal::AllocationUnavailable);
        assert!(error.attempts.is_empty());
    }
    for (candidates, mappings, bytes) in [(0, 1, 8192), (1, 0, 8192), (1, 1, 4095)] {
        let mut fixture = Fixture::new(ClockMode::Stop);
        fixture.allocation.max_candidates = candidates;
        fixture.allocation.max_mappings = mappings;
        fixture.allocation.max_mapped_bytes = bytes;
        assert_eq!(
            fixture.emit(&[]).err(),
            Some(Refusal::AllocationUnavailable)
        );
    }
    let mut fixture = Fixture::new(ClockMode::Stop);
    let clock_range = fixture.region.clock().range();
    fixture.allocation.preferred_address = Some(clock_range.start());
    fixture.allocation.ranges = vec![AddressRange::new(clock_range.start(), 8192).unwrap()];
    assert_eq!(
        fixture.emit(&[clock_range]).err(),
        Some(Refusal::AllocationUnavailable)
    );
    let fixture = Fixture::new(ClockMode::Stop);
    assert_eq!(
        fixture.emit(&fixture.allocation.ranges).err(),
        Some(Refusal::AllocationUnavailable)
    );
}

#[test]
fn owned_clock_region_image_verifier_rejects_changed_bodies_and_branch_destinations() {
    let fixture = Fixture::new(ClockMode::Stop);
    let scan = fixture.scan();
    let proof = fixture.proof().unwrap();
    let plan = fixture.plan();
    let image = plan.image();
    proof.verify_image(&scan, &fixture.region, image).unwrap();
    for source_offset in [0, 7, 11, 21, 27] {
        let mut bytes = image.bytes().to_vec();
        let body = image
            .instruction_boundaries()
            .iter()
            .find(|entry| entry.0 == fixture.base() + source_offset)
            .unwrap()
            .1;
        let at = (body - image.address()) as usize;
        let emitted = Decoder::with_ip(64, &bytes[at..], body, DecoderOptions::NONE).decode();
        if source_offset == 27 {
            bytes[at] = 0x90;
        } else if source_offset == 0 {
            bytes[at + 1] ^= 1; // Same MOV mnemonic, different scalar operand.
        } else {
            bytes[at + emitted.len() - 1] ^= 1;
        }
        assert_eq!(
            proof.verify_view(
                &scan,
                &fixture.region,
                ImageView {
                    bytes: &bytes,
                    ..ImageView::from(image)
                }
            ),
            Err(Refusal::InvalidPlan)
        );
    }
    let return_offset = image.bytes().len() - image.layout().return_len;
    for changed in [return_offset, return_offset + 4] {
        let mut bytes = image.bytes().to_vec();
        bytes[changed] ^= 1;
        assert_eq!(
            proof.verify_view(
                &scan,
                &fixture.region,
                ImageView {
                    bytes: &bytes,
                    ..ImageView::from(image)
                }
            ),
            Err(Refusal::InvalidPlan)
        );
    }
}

#[test]
fn owned_clock_region_image_verifier_rejects_missing_misbound_gates_heads_maps_and_clock() {
    let fixture = Fixture::new(ClockMode::Stop);
    let scan = fixture.scan();
    let proof = fixture.proof().unwrap();
    let plan = fixture.plan();
    let image = plan.image();
    let refused = |view| {
        assert_eq!(
            proof.verify_view(&scan, &fixture.region, view),
            Err(Refusal::InvalidPlan)
        );
    };
    refused(ImageView {
        gates: &image.clock_region_gates()[..1],
        ..ImageView::from(image)
    });
    for field in 0..4 {
        let mut gates = image.clock_region_gates().to_vec();
        match field {
            0 => gates[1].logical_pc = gates[0].logical_pc,
            1 => gates[1].gate.entry += 1,
            2 => gates[1].gate.observing_entry = gates[1].gate.original_body,
            _ => gates[1].gate.original_body -= 1,
        }
        refused(ImageView {
            gates: &gates,
            ..ImageView::from(image)
        });
    }
    refused(ImageView {
        entries: &image.entry_routes()[1..],
        ..ImageView::from(image)
    });
    let mut bodies = image.instruction_boundaries().to_vec();
    bodies[0].0 += 1;
    refused(ImageView {
        bodies: &bodies,
        ..ImageView::from(image)
    });
    let mut maps = image.program_counter_mappings().to_vec();
    maps.swap(0, 1);
    refused(ImageView {
        maps: &maps,
        ..ImageView::from(image)
    });
    refused(ImageView {
        maps: &image.program_counter_mappings()[..maps.len() - 1],
        ..ImageView::from(image)
    });
    let mut controls = image.controls().to_vec();
    controls.swap(0, 1);
    refused(ImageView {
        controls: &controls,
        ..ImageView::from(image)
    });
    refused(ImageView {
        clock: None,
        ..ImageView::from(image)
    });
    let other_clock = clock();
    refused(ImageView {
        clock: Some(&other_clock),
        ..ImageView::from(image)
    });
    let mut layout = image.layout();
    layout.return_len -= 1;
    layout.relocated_len += 1; // Preserve total length while moving the boundary.
    refused(ImageView {
        layout,
        ..ImageView::from(image)
    });
}
