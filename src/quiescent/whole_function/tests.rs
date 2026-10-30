//! Decode/emission/contract controls only; never publish or call generated code.
use super::*;
use crate::composition::Composition;

const PC: u64 = 0x2400_0080;
// XOR; TEST; JE +5; INC; RET; two unreachable original NOPs; RET.
const SHORT: &[u8] = &[
    0x31, 0xc0, 0x85, 0xf6, 0x74, 5, 0xff, 0xc0, 0xc3, 0x90, 0x90, 0xc3,
];
unsafe extern "C" fn noop(_: *mut crate::trampoline::HookContext) {}
fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}

struct Fixture {
    code: Vec<u8>,
    entries: LegalEntrySet,
    allocation: AllocationPolicy,
    actions: Vec<ControlledAction>,
}
impl Fixture {
    fn new(code: &[u8], leaders: &[u64], returns: &[u64]) -> Self {
        Self {
            code: code.to_vec(),
            entries: LegalEntrySet {
                identity: CodeIdentity {
                    source: SourceIdentity([107; 32]),
                    mapping: 107,
                    generation: 1,
                },
                scope: range(PC, code.len()),
                provenance: EntryProvenance::Declared(
                    "closed scalar fixture; sole external entry".into(),
                ),
                completeness: EntryCompleteness::Complete,
                entries: leaders
                    .iter()
                    .map(|&pc| LegalEntry {
                        address: PC + pc,
                        requires_endbr: false,
                    })
                    .collect(),
                resumes: ResumeObligation::NoneExist,
            },
            allocation: AllocationPolicy::near(PC).unwrap(),
            actions: std::iter::once(0)
                .chain(returns.iter().copied())
                .map(|pc| ControlledAction {
                    logical_pc: PC + pc,
                    control: ProbeControl::new(noop, true),
                })
                .collect(),
        }
    }
    fn short() -> Self {
        Self::new(SHORT, &[0, 6, 11], &[8, 11])
    }
    fn request(&self) -> WholeFunctionRequest<'_> {
        WholeFunctionRequest {
            identity: self.entries.identity,
            code: &self.code,
            base_address: PC,
            entries: &self.entries,
            allocation: &self.allocation,
        }
    }
    fn scan(&self) -> ScanResult {
        InstructionScanner::default().scan(&self.code, PC).unwrap()
    }
    fn proof(&self) -> Result<Verified, Refusal> {
        Verified::new(&self.request(), &self.scan(), &self.actions)
    }
    fn plan(&self) -> PlannedInstall {
        // SAFETY: finite source-only fixture; no image is published/executed.
        unsafe { plan_whole_function_controlled_detailed(&self.request(), &self.actions) }.unwrap()
    }
    fn original(&self) -> Composition {
        Composition::new(
            self.entries.identity,
            vec![ExpectedBytes {
                address: PC,
                bytes: self.code.clone(),
            }],
        )
        .unwrap()
    }
    fn old_request(&self, block: AddressRange, logical_pc: u64) -> InstallRequest<'_> {
        InstallRequest {
            identity: self.entries.identity,
            code: &self.code,
            base_address: PC,
            function: self.entries.scope,
            block,
            logical_pc,
            entries: &self.entries,
            hook: noop,
            semantics: HookSemantics::Observe,
            allocation: &self.allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_displaced_bytes: 80,
                max_sites: 1,
            },
        }
    }
}

#[test]
fn whole_two_short_returns_keep_nops_controls_and_composition() {
    let f = Fixture::short();
    let plan = f.plan();
    let p = plan.plan().parts();
    assert_eq!(p.displaced, f.entries.scope);
    assert_eq!((p.physical_pc, p.logical_pc), (PC, PC));
    assert_eq!(
        p.reads,
        [ExpectedBytes {
            address: PC,
            bytes: SHORT.to_vec()
        }]
    );
    assert_eq!(p.dependencies, [f.entries.scope]);
    assert_eq!(p.writes.len(), 1);
    assert_eq!(p.writes[0].bytes.len(), SHORT.len());
    assert_eq!(p.allocations.len(), 1);
    assert_eq!(p.generated.len(), 1);
    assert!(p.allocations[0].range.len() <= 8192);
    assert_eq!(p.entries, f.entries);
    assert!(p.requirements.quiescent && p.requirements.sync_core && p.requirements.sigill_router);
    assert_eq!(
        plan.image().controls(),
        f.actions
            .iter()
            .map(|a| a.control.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        plan.image().layout().observation_stack_profile,
        ObservationStackProfile::Legacy128
    );
    assert_eq!(plan.metrics().displaced_bytes, SHORT.len());
    assert_eq!(plan.metrics().upstream_bytes, 0);
    assert_eq!(plan.metrics().attempts.len(), 1);
    assert!(plan.metrics().search.accepted);
    let heads: Vec<_> = f
        .scan()
        .instructions()
        .iter()
        .map(|i| i.address())
        .collect();
    assert_eq!(
        plan.image()
            .entry_routes()
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>(),
        heads
    );
    assert_eq!(
        plan.image()
            .instruction_boundaries()
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>(),
        heads
    );
    for offset in [9, 10] {
        let body = plan
            .image()
            .instruction_boundaries()
            .iter()
            .find(|x| x.0 == PC + offset)
            .unwrap()
            .1;
        assert_eq!(
            plan.image().bytes()[(body - plan.image().address()) as usize],
            0x90
        );
    }
    assert_eq!(p.obligations[0], EntryObligation::Preserved(PC));
    for (obligation, original) in p.obligations[1..].iter().zip([PC + 6, PC + 11]) {
        let target = plan
            .image()
            .entry_routes()
            .iter()
            .find(|x| x.0 == original)
            .unwrap()
            .1;
        assert_eq!(
            *obligation,
            EntryObligation::Routed(EntryRoute {
                original,
                generated: target
            })
        );
    }
    assert_eq!(p.obligations.len(), 3);
    let mut composition = f.original();
    composition.append(plan.plan()).unwrap();
    assert_eq!(composition.final_bytes()[0].bytes, p.writes[0].bytes);
    assert!(
        composition
            .locks()
            .iter()
            .any(|lock| lock.covers(f.entries.scope))
    );
}

#[test]
fn whole_final_branch_after_last_action_forces_full_end() {
    // XOR; JMP to INC; RET; INC; JMP back to RET. The last action is +4,
    // but the final reachable branch at +7 is essential to executing it.
    let f = Fixture::new(
        &[0x31, 0xc0, 0xeb, 1, 0xc3, 0xff, 0xc0, 0xeb, 0xfb],
        &[0, 4, 5],
        &[4],
    );
    let plan = f.plan();
    assert_eq!(plan.plan().parts().displaced, range(PC, 9));
    assert_eq!(
        plan.image().instruction_boundaries().last().unwrap().0,
        PC + 7
    );
    let body = plan.image().instruction_boundaries().last().unwrap().1;
    let at = (body - plan.image().address()) as usize;
    let branch =
        Decoder::with_ip(64, &plan.image().bytes()[at..], body, DecoderOptions::NONE).decode();
    let ret_entry = plan
        .image()
        .entry_routes()
        .iter()
        .find(|x| x.0 == PC + 4)
        .unwrap()
        .1;
    let ret_body = plan
        .image()
        .instruction_boundaries()
        .iter()
        .find(|x| x.0 == PC + 4)
        .unwrap()
        .1;
    assert!(ret_entry < ret_body);
    assert_eq!(branch.near_branch_target(), ret_entry);
    let jumpback = plan.image().address()
        + (plan.image().bytes().len() - plan.image().layout().return_len) as u64;
    assert_eq!(branch.next_ip(), jumpback);
    assert_eq!(
        plan.image()
            .program_counter_mappings()
            .last()
            .unwrap()
            .logical_address(),
        PC + 9
    );
    // Existing block mode still rejects the interior transfer; no fallback.
    let error =
        plan_coalesced_detailed(&f.old_request(f.entries.scope, PC), &f.actions).unwrap_err();
    assert_eq!(
        error.reason,
        Refusal::UnsupportedSemantics("control transfer before displaced end".into())
    );
}

#[test]
fn whole_first_five_head_routes_and_legacy_short_ret_refusal() {
    let f = Fixture::new(
        &[0x85, 0xf6, 0x74, 1, 0xc3, 0x31, 0xc0, 0xc3],
        &[0, 4, 5],
        &[4, 7],
    );
    let plan = f.plan();
    let p = plan.plan().parts();
    assert_eq!(p.writes[0].bytes[0], 0xe9);
    assert!(ILLEGAL.contains(&p.writes[0].bytes[4]));
    let original = PC + 4;
    let generated = plan
        .image()
        .entry_routes()
        .iter()
        .find(|x| x.0 == original)
        .unwrap()
        .1;
    assert!(p.obligations.contains(&EntryObligation::Routed(EntryRoute {
        original,
        generated
    })));
    assert!(
        !p.obligations
            .contains(&EntryObligation::Preserved(original))
    );
    let ret = f.actions[1].clone();
    let error =
        plan_coalesced_detailed(&f.old_request(range(original, 1), original), &[ret]).unwrap_err();
    assert_eq!(error.reason, Refusal::NoPatchWindow);
}

#[test]
fn whole_cfg_refuses_escape_falloff_entry_reentry_and_non_scalar_shapes() {
    let good = Fixture::short();
    assert!(good.proof().is_ok());
    // Every negative is valid linear x86; it fails the actual closed-profile
    // validator rather than a copied test predicate or malformed decoder input.
    for bytes in [
        &[0x31, 0xc0, 0xeb, 0x7f, 0xc3][..], // escape
        &[0x31, 0xc0, 0x90, 0x90, 0x90][..], // falloff
        &[0x31, 0xc0, 0x75, 0xfc, 0xc3][..], // reenter entry
        &[0x31, 0xc0, 0xff, 0xe0, 0xc3][..], // indirect
        &[0xe8, 0, 0, 0, 0, 0xc3][..],       // CALL
        &[0x31, 0xc0, 0xc2, 8, 0][..],       // nonliteral RET
        &[0x48, 0x89, 0x07, 0x90, 0xc3][..], // store
        &[0x48, 0x89, 0xd8, 0x90, 0xc3][..], // callee-saved operand
        &[0xeb, 2, 0x31, 0xc0, 0xc3][..],    // unreachable non-NOP
        &[0x31, 0xc0, 0xeb, 0xff, 0xc3][..], // non-head destination
        &[0x31, 0xc0, 0xeb, 0xfe, 0xc3][..], // self-loop
        &[0x31, 0xc0, 0x90, 0xf3, 0xc3][..], // prefixed RET
        &[0x85, 0xf6, 0x74, 4, 0xff, 0xc0, 0xeb, 0xfc, 0xc3][..], // reachable no-exit SCC
    ] {
        let f = Fixture::new(bytes, &[0], &[(bytes.len() - 1) as u64]);
        assert!(matches!(f.proof(), Err(Refusal::UnsupportedSemantics(_))));
    }
}

#[test]
fn whole_entry_roles_and_finite_bounds_are_exact() {
    let f = Fixture::short();
    assert!(f.proof().is_ok());
    for change in 0..13 {
        let mut f = Fixture::short();
        match change {
            0 => {
                f.actions.pop();
            }
            1 => {
                f.actions.push(f.actions[2].clone());
            }
            2 => {
                f.actions[2].control = f.actions[1].control.clone();
            }
            3 => {
                f.actions.swap(1, 2);
            }
            4 => {
                f.actions[0].logical_pc += 2;
            }
            5 => {
                f.entries.entries.pop();
            }
            6 => {
                f.entries.entries.push(f.entries.entries[0]);
            }
            7 => {
                f.entries.resumes = ResumeObligation::Enumerated(vec![PC]);
            }
            8 => {
                f.entries.entries[0].requires_endbr = true;
            }
            9 => {
                f.entries.completeness = EntryCompleteness::Incomplete;
            }
            10 => {
                f.entries.completeness = EntryCompleteness::AllInstructionHeads;
            }
            11 => {
                f.entries.resumes = ResumeObligation::Unresolved;
            }
            12 => {
                f.entries.scope = range(PC, SHORT.len() - 1);
            }
            _ => unreachable!(),
        }
        assert!(f.proof().is_err(), "mutation {change}");
    }
    for field in 0..3 {
        let mut f = Fixture::short();
        match field {
            0 => f.allocation.max_candidates = 257,
            1 => f.allocation.max_mappings = 2,
            2 => f.allocation.max_mapped_bytes = 8193,
            _ => unreachable!(),
        }
        assert!(matches!(f.proof(), Err(Refusal::AllocationUnavailable)));
    }
    for len in [4, 80, 81] {
        let mut bytes = vec![0x90; len];
        bytes[len - 1] = 0xc3;
        let f = Fixture::new(&bytes, &[0], &[(len - 1) as u64]);
        assert_eq!(f.proof().is_ok(), len == 80);
    }
    let mut f = Fixture::short();
    f.allocation.max_candidates = 0;
    let failure =
        unsafe { plan_whole_function_controlled_detailed(&f.request(), &f.actions) }.unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert!(!failure.search.accepted);
}

#[test]
fn whole_overlay_authentication_precedes_image_search() {
    let f = Fixture::short();
    let mut composition = f.original();
    let first = unsafe {
        plan_whole_function_controlled_detailed_after(&f.request(), &f.actions, &composition)
    }
    .unwrap();
    assert_eq!(composition, f.original());
    composition.append(first.plan()).unwrap();
    let before = composition.clone();
    let error = unsafe {
        plan_whole_function_controlled_detailed_after(&f.request(), &f.actions, &composition)
    }
    .unwrap_err();
    assert_eq!(error.reason, Refusal::ExpectedBytesChanged);
    assert!(error.attempts.is_empty() && error.search.runs.is_empty() && !error.search.accepted);
    assert_eq!(composition, before);
    let mut request = f.request();
    request.identity.generation += 1;
    let error = unsafe {
        plan_whole_function_controlled_detailed_after(&request, &f.actions, &f.original())
    }
    .unwrap_err();
    assert_eq!(error.reason, Refusal::StaleGeneration);
    let mut changed = f.code.clone();
    changed[9] = 0x91;
    request = f.request();
    request.code = &changed;
    let error = unsafe {
        plan_whole_function_controlled_detailed_after(&request, &f.actions, &f.original())
    }
    .unwrap_err();
    assert_eq!(error.reason, Refusal::ExpectedBytesChanged);
    assert!(error.attempts.is_empty() && error.search.runs.is_empty());
}

#[test]
fn whole_actual_image_validator_refuses_branch_ret_maps_and_control_mutations() {
    let f = Fixture::short();
    let scan = f.scan();
    let proof = f.proof().unwrap();
    let plan = f.plan();
    let image = plan.image();
    assert!(proof.verify_image(&scan, &f.actions, image).is_ok());
    for pc in [PC + 4, PC + 8] {
        let mut bytes = image.bytes().to_vec();
        let body = image
            .instruction_boundaries()
            .iter()
            .find(|x| x.0 == pc)
            .unwrap()
            .1;
        let offset = (body - image.address()) as usize;
        let instruction =
            Decoder::with_ip(64, &bytes[offset..], body, DecoderOptions::NONE).decode();
        if pc == PC + 4 {
            bytes[offset + instruction.len() - 1] ^= 1;
        } else {
            bytes[offset] = 0x90;
        }
        assert_eq!(
            proof.verify_view(
                &scan,
                &f.actions,
                ImageView {
                    bytes: &bytes,
                    ..ImageView::from(image)
                }
            ),
            Err(Refusal::InvalidPlan)
        );
    }
    assert_eq!(
        proof.verify_view(
            &scan,
            &f.actions,
            ImageView {
                entries: &image.entry_routes()[1..],
                ..ImageView::from(image)
            }
        ),
        Err(Refusal::InvalidPlan)
    );
    let mut bodies = image.instruction_boundaries().to_vec();
    bodies[0].0 += 1;
    assert_eq!(
        proof.verify_view(
            &scan,
            &f.actions,
            ImageView {
                bodies: &bodies,
                ..ImageView::from(image)
            }
        ),
        Err(Refusal::InvalidPlan)
    );
    assert_eq!(
        proof.verify_view(
            &scan,
            &f.actions,
            ImageView {
                maps: &image.program_counter_mappings()[1..],
                ..ImageView::from(image)
            }
        ),
        Err(Refusal::InvalidPlan)
    );
    let mut controls = image.controls().to_vec();
    controls[1] = ProbeControl::new(noop, true);
    assert_eq!(
        proof.verify_view(
            &scan,
            &f.actions,
            ImageView {
                controls: &controls,
                ..ImageView::from(image)
            }
        ),
        Err(Refusal::InvalidPlan)
    );
}

#[path = "adc_tests.rs"]
mod adc_tests;
