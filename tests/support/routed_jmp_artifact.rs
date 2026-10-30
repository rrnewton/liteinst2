// Admission for this one frozen fixture, before any executable publication.
use super::*;
use liteinst2::bundle::BundleBudget;
use liteinst2::composition::Composition;
use liteinst2::emission::{ArtifactEmission, ArtifactField, ArtifactFieldEncoding, ArtifactPlan,
    ArtifactRequest, ArtifactRequirement, PlanningSite, SymbolicHook, TargetProfile};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{self, AllocationPolicy, PairCounts, RoutedJmpBudget, SearchPolicy, TacticPolicy};
use liteinst2::scanner::InstructionScanner;

#[derive(Clone)]
pub struct Image {
    pub pc: u64,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub entries: Vec<(u64, u64)>,
    pub bodies: Vec<(u64, u64)>,
    pub fields: Vec<ArtifactField>,
    pub requirements: Vec<ArtifactRequirement>,
    pub maps: Vec<(u64, u64, u64)>,
}
#[derive(Clone)]
pub struct Proof {
    pub steps: Vec<PlanParts>,
    pub images: Vec<Image>,
    pub source: Vec<u8>,
    pub routes: Vec<EntryRoute>,
    pub hook: u64,
}
fn policy(preferred: u64, page: u64, candidates: usize) -> AllocationPolicy {
    AllocationPolicy { preferred_address: Some(preferred), ranges: vec![range(page, PAGE)],
        max_candidates: candidates, max_mappings: 1, max_mapped_bytes: PAGE }
}
pub fn produce(hook: u64, state: SavedExtendedStateLayout) -> Proof {
    let scan = InstructionScanner::default().scan(FUNCTION, B).unwrap();
    assert_eq!(scan.instructions().iter().map(|i| i.address()).collect::<Vec<_>>(), HEADS);
    let entries = LegalEntrySet { identity: identity(), scope: range(B, FUNCTION.len()),
        provenance: EntryProvenance::Declared("frozen runnable mixed native v1".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        resumes: ResumeObligation::Enumerated(vec![F]),
        entries: HEADS.iter().map(|&address| LegalEntry { address, requires_endbr: false }).collect() };
    let lower = policy(LOWER_IMAGE, IMAGE_PAGES[2], 1);
    let upper = policy(0x600000, IMAGE_PAGES[1], 2);
    let prior_policy = policy(0x500000, IMAGE_PAGES[0], 1);
    let site = PlanningSite { identity: identity(), code: FUNCTION, base_address: B,
        function: range(B, FUNCTION.len()), block: range(L, 2), logical_pc: L, entries: &entries,
        semantics: HookSemantics::Observe, allocation: &lower,
        search: SearchPolicy { tactics: TacticPolicy::GeneralizedPunOnly,
            max_upstream_bytes: 0, max_displaced_bytes: 2, max_sites: 1 } };
    let sites = [site, PlanningSite { block: range(U, 2), logical_pc: U, allocation: &upper,
        search: SearchPolicy { tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0, max_displaced_bytes: 5, max_sites: 1 }, ..site }];
    let input = ArtifactEmission::new(TargetProfile::linux_x86_64_legacy_evex(state, 1).unwrap(),
        SymbolicHook { identity: hook, address: Some(hook) },
        vec![range(SOURCE, PAGE), range(NULL_HOOK, 3 * PAGE)]);
    let prior_site = PlanningSite { block: range(B, 6), logical_pc: B, allocation: &prior_policy,
        search: SearchPolicy { tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0, max_displaced_bytes: 6, max_sites: 1 }, ..site };
    let prior = quiescent::plan_install_with_emission(&ArtifactRequest { site: prior_site, emission: &input }).unwrap();
    let original = ExpectedBytes { address: B, bytes: FUNCTION.to_vec() };
    let mut composition = Composition::new(identity(), vec![original.clone()]).unwrap();
    for step in prior.source_steps() { composition.append(step).unwrap(); }
    let predecessor = composition.clone();
    let mut occupied = input.occupied().to_vec();
    occupied.push(range(IMAGE_PAGES[0], PAGE));
    let input = ArtifactEmission::new(input.profile().clone(), input.hook(), occupied);
    let pair = quiescent::plan_adjacent_routed_jmp_with_emission_after(sites, &input, &composition, &[],
        RoutedJmpBudget { max_continuations: 2, bundle: BundleBudget { max_steps: 2, max_mappings: 2,
            max_virtual_bytes: 8192, max_backing_bytes: 8192, max_virtual_span: 1 << 31 } }).unwrap();
    assert_eq!(composition, predecessor);
    assert!(!pair.qualification_complete());
    assert!(pair.evidence().accepted);
    assert!(!pair.evidence().classification_complete);
    assert_eq!(pair.logical_pcs(), [U, L]);
    assert_eq!(pair.evidence().counts, PairCounts { upper: 1, lower: 1, joint: 1 });
    assert_eq!(pair.evidence().upper_slots, [(0, Some(UPPER_IMAGE))]);
    assert_eq!(pair.evidence().lower_schedules.len(), 1);
    assert_eq!(pair.evidence().lower_schedules[0].window, range(0x073c0503, 256));
    assert_eq!(pair.evidence().lower_schedules[0].targets, [LOWER_IMAGE]);
    assert_eq!(pair.memory().mappings, 2);
    assert_eq!(pair.memory().virtual_bytes, 8192);
    let plans: [&ArtifactPlan; 3] = [&prior, &pair.members()[0], &pair.members()[1]];
    let mut proof = Proof { steps: Vec::new(), images: Vec::new(), source: FUNCTION.to_vec(), routes: Vec::new(), hook };
    for (index, plan) in plans.iter().enumerate() {
        assert_eq!(plan.source_steps().len(), 1);
        let part = plan.source_steps()[0].parts().clone();
        let mut views = plan.images();
        let view = views.next().unwrap(); assert!(views.next().is_none());
        assert!(!view.metadata().qualification_complete());
        proof.images.push(Image { pc: [B, U, L][index], address: view.address(), bytes: view.bytes().to_vec(),
            entries: view.entry_routes().to_vec(), bodies: view.instruction_boundaries().to_vec(),
            fields: view.metadata().fields().to_vec(), requirements: view.metadata().requirements().to_vec(),
            maps: view.program_counter_mappings().iter().map(|m| (m.generated_start(), m.generated_end(), m.logical_address())).collect() });
        proof.routes.extend(part.obligations.iter().filter_map(|o| match o { EntryObligation::Routed(r) => Some(*r), _ => None }));
        proof.steps.push(part);
        if index != 0 { composition.append(&plan.source_steps()[0]).unwrap(); }
    }
    assert_eq!(composition.originals(), [original]);
    assert_eq!(composition.locks(), [range(B, 6), range(L, 7)]);
    proof.source = composition.final_bytes()[0].bytes.clone();
    check(&proof);
    proof
}
fn at(image: &Image, address: u64, len: usize) -> &[u8] {
    let off = usize::try_from(address.checked_sub(image.address).unwrap()).unwrap();
    &image.bytes[off..off + len]
}
fn rel32(image: &Image, address: u64, opcode: &[u8], target: u64) {
    assert_eq!(at(image, address, opcode.len()), opcode);
    let bytes = at(image, address + opcode.len() as u64, 4);
    let actual = i128::from(address) + opcode.len() as i128 + 4 + i128::from(i32::from_le_bytes(bytes.try_into().unwrap()));
    assert_eq!(actual, i128::from(target));
}
pub fn body(image: &Image, logical: u64) -> u64 {
    let found: Vec<_> = image.bodies.iter().filter(|p| p.0 == logical).collect();
    assert_eq!(found.len(), 1); found[0].1
}
pub fn call(image: &Image, hook: u64) -> u64 {
    let fields: Vec<_> = image.fields.iter().filter(|f| f.role == "HookCall").collect();
    assert_eq!(fields.len(), 1);
    let f = fields[0]; assert_eq!(f.target, i128::from(hook)); assert_eq!(f.width, 4); assert_eq!(f.encoding, ArtifactFieldEncoding::Relative);
    assert_eq!(f.origin, f.offset + 4);
    let pc = image.address + f.offset.checked_sub(1).unwrap(); rel32(image, pc, &[0xe8], hook); pc
}
pub fn check(p: &Proof) {
    assert!([NULL_HOOK, RECORD_HOOK].contains(&p.hook));
    assert_eq!(p.steps.len(), 3); assert_eq!(p.images.len(), 3);
    let mut current = FUNCTION.to_vec();
    for (index, (step, image)) in p.steps.iter().zip(&p.images).enumerate() {
        let logical = [B, U, L][index];
        let address = [PRIOR_IMAGE, UPPER_IMAGE, LOWER_IMAGE][index];
        let heads: &[u64] = match index { 0 => &[B, B + 4], 1 => &[U, F], _ => &[L] };
        assert_eq!(step.identity, identity());
        assert_eq!(step.entries.identity, identity());
        assert_eq!(step.entries.scope, range(B, FUNCTION.len()));
        assert_eq!(step.entries.completeness, EntryCompleteness::AllInstructionHeads);
        assert_eq!(step.entries.resumes, ResumeObligation::Enumerated(vec![F]));
        assert_eq!(step.entries.entries.iter().map(|e| e.address).collect::<Vec<_>>(), HEADS);
        assert!(step.entries.entries.iter().all(|e| !e.requires_endbr));
        assert_eq!((step.logical_pc, step.physical_pc, image.pc, image.address), (logical, logical, logical, address));
        assert_eq!(step.displaced, range(logical, [6, 5, 2][index]));
        assert_eq!(step.profile, ApplicationProfile::InstallOnce);
        assert_eq!(step.requirements, PublicationRequirements { quiescent: true, sync_core: true, sigill_router: index != 2 });
        assert_eq!(step.allocations, [AllocationRequest { range: range(IMAGE_PAGES[index], PAGE), alignment: PAGE }]);
        assert_eq!(step.generated.len(), 1);
        assert_eq!(step.generated[0].address, image.address);
        assert_eq!(step.generated[0].bytes, image.bytes);
        assert_eq!(step.generated[0].program_counters.iter().map(|m| (m.generated_start(), m.generated_end(), m.logical_address())).collect::<Vec<_>>(), image.maps);
        assert!(range(IMAGE_PAGES[index], PAGE).covers(range(image.address, image.bytes.len())));
        assert_eq!(image.entries.iter().map(|p| p.0).collect::<Vec<_>>(), heads);
        assert_eq!(image.bodies.iter().map(|p| p.0).collect::<Vec<_>>(), heads);
        assert_eq!(image.entries[0], (logical, address));
        assert!(address < body(image, logical));
        if index != 2 { assert_eq!(image.entries[1], image.bodies[1]); }
        let return_start=image.address+image.bytes.len() as u64-5;
        let expected_maps:Vec<_>=image.entries.iter().enumerate().map(|(i,&(pc,start))|
            (start,image.entries.get(i+1).map_or(return_start,|p|p.1),pc))
            .chain(std::iter::once((return_start,image.address+image.bytes.len() as u64,[B+6,E,U][index]))).collect();
        assert_eq!(image.maps,expected_maps);
        assert!(image.maps.iter().all(|&(a,b,_)|a<b));
        for &(pc, generated) in &image.bodies {
            assert!(image.maps.iter().any(|&(a,b,l)| a <= generated && generated < b && l == pc));
        }
        assert_eq!(step.reads,[ExpectedBytes { address:B,bytes:current.clone() }]);
        assert_eq!(step.dependencies,[range(B,FUNCTION.len())]);
        if index<2 { assert_eq!(step.kind,PlanKind::Relocation); }
        else {
            let PlanKind::GeneralizedPun(pun)=&step.kind else { panic!("lower B2 required") };
            assert_eq!(pun.instruction_len,2);
            assert_eq!(pun.consumed,range(L,5));
            assert_eq!(pun.target_window,range(0x073c0503,256));
            assert_eq!(pun.store,ByteEdit { address:L,bytes:vec![0xe9,0xfd] });
        }
        let expected_write: &[u8] = match index { 0 => &[0xe9,0x3d,0xe4,0x0f,0x06,0x33], 1 => &[0xe9,0xfb,0x06,0x1f,0], _ => &[0xe9,0xfd] };
        assert_eq!(step.writes, [ByteEdit { address: logical, bytes: expected_write.to_vec() }]);
        let off = (logical - B) as usize; current[off..off+expected_write.len()].copy_from_slice(expected_write);
        let mut expected_requirements = vec![ArtifactRequirement::ArtifactIdentityAndAddressBinding,
            ArtifactRequirement::TargetCpuAndStateAtEntry, ArtifactRequirement::OriginalDynamicRelocationOwnership,
            ArtifactRequirement::OriginalImmediatePointerProvenance, ArtifactRequirement::GeneratedUnwindInformation,
            ArtifactRequirement::OriginalCodeAsDataContract, ArtifactRequirement::HookAbiAndReadiness(p.hook)];
        if index != 2 { expected_requirements.push(ArtifactRequirement::EntryRouterBootstrap); }
        assert_eq!(image.requirements, expected_requirements);
        let expected_fields = [
            ("LogicalPc".to_owned(), ArtifactFieldEncoding::Delta, 8, logical),
            ("HookCall".to_owned(), ArtifactFieldEncoding::Relative, 4, p.hook),
            (format!("OriginalBranch {{ original_pc: {} }}", [B+4,U,L][index]), ArtifactFieldEncoding::Relative, 4, [L-7,T,B][index]),
            ("Return".to_owned(), ArtifactFieldEncoding::Relative, 4, [B+6,E,U][index]),
        ];
        assert_eq!(image.fields.len(), expected_fields.len());
        for (role,encoding,width,target) in expected_fields {
            let found:Vec<_>=image.fields.iter().filter(|f|f.role==role).collect();
            assert_eq!(found.len(),1);
            assert_eq!((found[0].encoding,found[0].width,found[0].target),(encoding,width,i128::from(target)));
        }
        for f in &image.fields {
            assert_eq!(f.bias_domain, 1);
            let off = f.offset as usize; let data = &image.bytes[off..off + f.width];
            let value = match (f.encoding, f.width) {
                (ArtifactFieldEncoding::Relative, 1) => i128::from(data[0] as i8),
                (ArtifactFieldEncoding::Relative, 4) => i128::from(i32::from_le_bytes(data.try_into().unwrap())),
                (ArtifactFieldEncoding::Delta, 8) => i128::from(i64::from_le_bytes(data.try_into().unwrap())),
                _ => panic!("unexpected frozen-fixture field encoding"),
            };
            assert!(f.origin <= image.bytes.len() as u64);
            assert_eq!(i128::from(address) + i128::from(f.origin) + value, f.target);
            if f.role=="LogicalPc" {
                assert_eq!(f.origin+2,f.offset);
                assert_eq!(&image.bytes[off-9..off], &[0x48,0x8d,0x05,0,0,0,0,0x48,0xba]);
                assert_eq!(&image.bytes[off+8..off+12], &[0x48,0x01,0xd0,0x50]);
            } else if f.role=="Return" {
                assert_eq!(f.origin,f.offset+4);
                rel32(image,address+f.offset-1,&[0xe9],f.target.try_into().unwrap());
            }
        }
        let call_pc = call(image, p.hook); assert!(call_pc + 5 <= body(image, logical));
        match index {
            0 => { assert_eq!(at(image, body(image, B), 4), [0x49,0x83,0xc5,1]);
                assert_eq!(body(image,B+4), body(image,B)+4);
                rel32(image, body(image, B+4), &[0xe9], L-7);
                assert_eq!(body(image,B+4)+5,return_start); }
            1 => { rel32(image, body(image,U), &[0xe9], T);
                assert_eq!(body(image,F),body(image,U)+5);
                assert_eq!(at(image, body(image,F), 3), [0x4c,0x89,0xe7]);
                rel32(image, body(image,F)+3, &[0xe9], E);
                assert_eq!(body(image,F)+3,return_start); }
            _ => { rel32(image, body(image,L), &[0x0f,0x86], B);
                rel32(image, body(image,L)+6, &[0xe9], U);
                assert_eq!(body(image,L)+6,return_start); }
        }
    }
    assert_eq!(p.source, current);
    assert_eq!(&p.source[(L-B) as usize..(E-B) as usize], &[0xe9,0xfd,0xe9,0xfb,0x06,0x1f,0]);
    assert_eq!(p.source[4], 0x06); assert_eq!(p.source[(F-B) as usize], 0x06);
    let routes = vec![EntryRoute { original: B+4, generated: body(&p.images[0], B+4) },
        EntryRoute { original: F, generated: body(&p.images[1], F) }];
    assert_eq!(p.routes, routes);
    for (i, step) in p.steps.iter().enumerate() {
        let routed: Vec<_> = step.obligations.iter().filter_map(|o| match o { EntryObligation::Routed(r) => Some(*r), _ => None }).collect();
        assert_eq!(routed, if i < 2 { vec![routes[i]] } else { vec![] });
        assert_eq!(step.obligations,match i {
            0=>vec![EntryObligation::Preserved(B),EntryObligation::Routed(routes[0])],
            1=>vec![EntryObligation::Preserved(U),EntryObligation::Routed(routes[1])],
            _=>vec![EntryObligation::Preserved(L),EntryObligation::Preserved(U),EntryObligation::Preserved(F)],
        });
    }
    assert!(p.steps[2].obligations.contains(&EntryObligation::Preserved(F)));
}

pub fn controls(p: &Proof) {
    check(p); // The actual successful API result precedes every negative.
    for kind in 0..19 {
        let mut bad = p.clone();
        match kind {
            0 => bad.routes[1].generated = UPPER_IMAGE,
            1 => { bad.routes.pop(); }
            2 => bad.routes.push(bad.routes[1]),
            3 => bad.routes[1].original = F+1,
            4 => bad.source[(F-B) as usize] = 0x90,
            5 => { let n=(body(&bad.images[1],U)-UPPER_IMAGE+1) as usize; bad.images[1].bytes[n]^=1; bad.steps[1].generated[0].bytes=bad.images[1].bytes.clone(); }
            6 => { let n=(body(&bad.images[1],F)-UPPER_IMAGE+2) as usize; bad.images[1].bytes[n]^=1; bad.steps[1].generated[0].bytes=bad.images[1].bytes.clone(); }
            7 => { let n=(body(&bad.images[2],L)-LOWER_IMAGE+1) as usize; bad.images[2].bytes[n]=0x84; bad.steps[2].generated[0].bytes=bad.images[2].bytes.clone(); }
            8 => { let n=(body(&bad.images[1],F)-UPPER_IMAGE+4) as usize; bad.images[1].bytes[n]^=1; bad.steps[1].generated[0].bytes=bad.images[1].bytes.clone(); }
            9 => bad.images[1].requirements.retain(|r| *r != ArtifactRequirement::EntryRouterBootstrap),
            10 => bad.images.swap(0,1),
            11 => bad.steps.swap(1,2),
            12 => { bad.images[1].entries.pop(); }
            13 => bad.images[1].entries.push((F, UPPER_IMAGE)),
            14 => bad.steps[1].obligations.retain(|o| !matches!(o,EntryObligation::Routed(_))),
            15 => { for obligation in &mut bad.steps[1].obligations { if let EntryObligation::Routed(route)=obligation { route.generated=UPPER_IMAGE; } } }
            16 => { bad.steps.remove(0); }
            17 => { bad.images.remove(2); }
            _ => { bad.images.remove(1); }
        }
        refused(|| check(&bad));
    }
}
