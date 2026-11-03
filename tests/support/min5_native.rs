// Finite retained-memory carrier for the actual sealed min5 plan. Every original
// entry executes its real patched source bytes and the production SIGILL router.
// This does not qualify the offline ELF writer/bootstrap or complete CFG recovery.
use super::*;
use super::artifact_window_native::{event, events, observe};
use super::router_witness::{Router, Budget, assert_hook_context, counter, deliver, finish};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::emission::{ArtifactEmission, ArtifactFieldEncoding, ArtifactRequest, PlanningSite, SymbolicHook, TargetProfile};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, ArtifactObservationSearchRequest, ArtifactRelocationPlacement, SearchPolicy, TacticPolicy,
    plan_artifact_observation_window_upstream_after, plan_artifact_observation_window_upstream_after_with_placement,
    seal_artifact_observation_window_min5, seal_artifact_observation_windows_upstream_min5,
    plan_artifact_observation_windows_upstream_after_with_placement};
use liteinst2::search::{SearchDomain, SearchStop};
use liteinst2::sync_core::SyncCore;
use liteinst2::trampoline::{SavedExtendedStateLayout, HOOK_CONTEXT_STACK_PREFIX_BYTES};

const BODY: [u8; 5] = [0x5b, 0x5d, 0x41, 0x5c, 0xc3];
const HEADS: [usize; 4] = [0, 1, 2, 4];
const PHYSICAL_BODY: [u8; 5] = [0x66, 0x90, 0x5b, 0x5d, 0xc3];
const PHYSICAL_HEADS: [usize; 4] = [0, 2, 3, 4];
const PRELUDE: usize = 0x100;
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
fn range(address: u64, length: usize) -> AddressRange { AddressRange::new(address, length).unwrap() }
use super::routed_jmp_native::refused as rejected;

pub type SizeCertificate = fn(u64, &[u8], &[u64], &ArtifactEmission) -> usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault { None, Ret, Pop }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Window { SelectedMin5, PhysicalMin5 }
#[derive(Clone, Copy)]
enum PopRegister { Rbx, Rbp, R12 }
impl PopRegister {
    fn value(self, registers: &libc::user_regs_struct) -> u64 {
        match self { Self::Rbx => registers.rbx, Self::Rbp => registers.rbp, Self::R12 => registers.r12 }
    }
}
#[derive(Clone, Copy)]
enum Operation { Nop, Pop(PopRegister), Ret }
#[derive(Clone, Copy)]
struct Instruction { at: usize, next: usize, operation: Operation }
struct Description {
    body: &'static [u8; 5], heads: &'static [usize; 4], instructions: [Instruction; 4],
    selected: &'static [usize], ret_fault_entries: [usize; 2], provenance: &'static str,
}
const LEGACY: Description = Description {
    body: &BODY, heads: &HEADS,
    instructions: [
        Instruction { at: 0, next: 1, operation: Operation::Pop(PopRegister::Rbx) },
        Instruction { at: 1, next: 2, operation: Operation::Pop(PopRegister::Rbp) },
        Instruction { at: 2, next: 4, operation: Operation::Pop(PopRegister::R12) },
        Instruction { at: 4, next: 5, operation: Operation::Ret },
    ],
    selected: &[0, 1, 2], ret_fault_entries: [0, 1],
    provenance: "complete finite three-POP/RET literal grammar",
};
const PHYSICAL: Description = Description {
    body: &PHYSICAL_BODY, heads: &PHYSICAL_HEADS,
    instructions: [
        Instruction { at: 0, next: 2, operation: Operation::Nop },
        Instruction { at: 2, next: 3, operation: Operation::Pop(PopRegister::Rbx) },
        Instruction { at: 3, next: 4, operation: Operation::Pop(PopRegister::Rbp) },
        Instruction { at: 4, next: 5, operation: Operation::Ret },
    ],
    selected: &[2, 3], ret_fault_entries: [2, 3],
    provenance: "complete finite two-byte NOP/two-POP/RET literal grammar",
};
impl Description {
    fn validate(&self) {
        assert_eq!(self.instructions.map(|instruction| instruction.at), *self.heads);
        let mut pops = Vec::new();
        for instruction in self.instructions {
            let bytes: &[u8] = match instruction.operation {
                Operation::Nop => &[0x66, 0x90],
                Operation::Pop(PopRegister::Rbx) => &[0x5b],
                Operation::Pop(PopRegister::Rbp) => &[0x5d],
                Operation::Pop(PopRegister::R12) => &[0x41, 0x5c],
                Operation::Ret => &[0xc3],
            };
            assert_eq!(&self.body[instruction.at..instruction.next], bytes);
            if matches!(instruction.operation, Operation::Pop(_)) { pops.push(instruction.at); }
        }
        assert_eq!(pops.as_slice(), self.selected);
        assert!(matches!(self.instructions[3].operation, Operation::Ret));
        assert_eq!((self.instructions[3].at, self.instructions[3].next), (4, 5));
    }
    fn pop(&self, at: usize) -> (PopRegister, usize) {
        let instruction = self.instructions.iter().find(|instruction| instruction.at == at).unwrap();
        let Operation::Pop(register) = instruction.operation else { panic!("selected head must be an actual POP") };
        (register, instruction.next)
    }
    fn remaining_pops(&self, entry: usize) -> usize {
        self.instructions.iter().filter(|instruction| instruction.at >= entry && matches!(instruction.operation, Operation::Pop(_))).count()
    }
}
#[derive(Clone, Copy)]
struct Fixture { placement: ArtifactRelocationPlacement, fault: Fault, window: Window }
impl Fixture {
    fn description(self) -> &'static Description {
        match self.window { Window::SelectedMin5 => &LEGACY, Window::PhysicalMin5 => &PHYSICAL }
    }
    fn body_offset(self) -> usize {
        match self.placement {
            ArtifactRelocationPlacement::Fixed06 => 0,
            ArtifactRelocationPlacement::EntryAlphabetV1 => 0x8f5,
        }
    }
    fn fault_at(self) -> Option<usize> {
        match self.fault { Fault::None => None, Fault::Ret => Some(4), Fault::Pop => Some(2) }
    }
}

struct Owner {
    oracle: NativeOracle,
    image: Mapping,
    hook: Mapping,
    // Ownership is transferred from this retained reservation without holes.
    _arena: super::super::neighbor_fixture_arena::NeighborFixtureArena,
    _guard: Option<Mapping>,
    journal: HookEventLog,
    original: Vec<u8>,
    published: Vec<u8>,
    image_bytes: Vec<u8>,
    hook_bytes: Vec<u8>,
    identity: CodeIdentity,
    routes: Vec<EntryRoute>,
    bodies: Vec<(u64, u64)>,
    calls: Vec<(u64, u64)>,
    selected: Vec<u64>,
    state: SavedExtendedStateLayout,
    needed: u64,
    entry: usize,
    fault: bool,
    body: u64,
    fixture: Fixture,
}
impl Owner {
    fn new(entry: usize, fault: bool, certificate: SizeCertificate) -> Self {
        Self::with_fixture(entry, Fixture { placement: ArtifactRelocationPlacement::Fixed06,
            fault: if fault { Fault::Ret } else { Fault::None }, window: Window::SelectedMin5 }, certificate)
    }
    fn with_fixture(entry: usize, fixture: Fixture, certificate: SizeCertificate) -> Self {
        let description = fixture.description(); description.validate();
        assert!(description.heads.contains(&entry));
        if fixture.window == Window::PhysicalMin5 { assert_eq!(fixture.placement, ArtifactRelocationPlacement::EntryAlphabetV1); }
        let fault = fixture.fault != Fault::None;
        if fixture.fault == Fault::Ret { assert!(description.ret_fault_entries.contains(&entry)); }
        if fixture.fault == Fault::Pop {
            assert_eq!(entry, 2); assert_eq!(fixture.placement, ArtifactRelocationPlacement::EntryAlphabetV1);
        }
        let lower = match fixture.fault {
            Fault::None => 96,
            Fault::Ret => match fixture.window {
                Window::SelectedMin5 => if entry == 0 { 24 } else { 16 },
                Window::PhysicalMin5 => if entry == 2 { 16 } else { 8 },
            },
            Fault::Pop => 0,
        };
        let body_offset = fixture.body_offset();
        let mut code = vec![0xcc; PRELUDE + 10];
        if body_offset == 0 { code[..5].copy_from_slice(description.body); }
        code[PRELUDE..PRELUDE + 6].copy_from_slice(&[0x48, 0x8d, 0x64, 0x24, 0_u8.wrapping_sub(lower), 0xe9]);
        code[PRELUDE + 6..].copy_from_slice(&i32::try_from((body_offset + entry) as i64 - (PRELUDE + 10) as i64).unwrap().to_le_bytes());
        let (mut oracle, mut adjacent, mut arena) = NativeOracle::with_neighbor_fixture(&code, &[PAGE]);
        let hook = adjacent.pop().unwrap(); assert!(adjacent.is_empty());
        let base = oracle.code.address(); assert_eq!(base % PAGE as u64, 0);
        assert_eq!(hook.address(), base + PAGE as u64);
        let body = base + body_offset as u64;
        if body_offset != 0 {
            // The constructor's short-input/sentinel contract stays unchanged.
            // Derive the full expected page from its pristine snapshot, changing
            // only BODY, before any original trace or installed publication.
            assert!(code.len() < PAGE / 2 && body_offset > PAGE / 2 && body_offset + description.body.len() <= PAGE);
            assert_eq!(oracle.return_pc(), base + (PAGE / 2) as u64);
            let pristine = oracle.original_code.clone(); assert_eq!(oracle.code.bytes(), pristine);
            let mut expected = pristine.clone(); expected[body_offset..body_offset + description.body.len()].copy_from_slice(description.body);
            oracle.code.initialize(body_offset, description.body);
            assert_eq!(oracle.code.bytes(), expected);
            assert_eq!(&oracle.code.bytes()[PRELUDE..PRELUDE + 10], &pristine[PRELUDE..PRELUDE + 10]);
            assert_eq!(oracle.code.bytes()[PAGE / 2], pristine[PAGE / 2]);
            oracle.original_code = expected;
        }
        let guard = if fault {
            assert_eq!(oracle.stack.len, STACK_BYTES + PAGE);
            let guard = Mapping {
                // SAFETY: transfer the owned final page without any unmapped interval.
                address: unsafe { oracle.stack.address.add(STACK_BYTES) }, len: PAGE,
            };
            oracle.stack.len = STACK_BYTES; oracle.initial_rsp = guard.address();
            guard.protect(libc::PROT_NONE); Some(guard)
        } else { None };
        let suffix = description.remaining_pops(entry);
        let completed = if fixture.fault == Fault::Pop { 0 } else { suffix };
        let start_rsp = oracle.initial_rsp - u64::from(lower);
        // Only successful original operands are initialized. In the routed POP
        // fault case start_rsp is the guard itself and this loop is empty.
        for i in 0..completed {
            let value = 0x1020_3040_5060_7080_u64 + i as u64;
            oracle.stack.initialize((start_rsp - oracle.stack.address()) as usize + 8 * i, &value.to_le_bytes());
        }
        if fault { assert_eq!(start_rsp + 8 * completed as u64, oracle.initial_rsp); }
        else { oracle.stack.initialize((start_rsp - oracle.stack.address()) as usize + 8 * suffix, &oracle.return_pc().to_le_bytes()); }
        let identity = CodeIdentity { source: SourceIdentity([0x35; 32]), mapping: base, generation: 1 };
        let function = range(body, description.body.len());
        let heads = description.heads.map(|at| body + at as u64);
        let selected: Vec<_> = description.selected.iter().map(|&at| body + at as u64).collect();
        let entries = LegalEntrySet {
            identity, scope: function,
            provenance: EntryProvenance::Declared(description.provenance.into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: heads.map(|address| LegalEntry { address, requires_endbr: false }).to_vec(),
            resumes: ResumeObligation::NoneExist,
        };
        let (target, permit, patch) = if fixture.window == Window::PhysicalMin5 {
            let target = base + 0x0606_1000;
            assert_eq!(target - (body + 5), 0x0606_0706);
            let fixed_first = body + 5 + 0x0606_0600;
            let fixed_last = body + 5 + 0x0606_06ff;
            assert_eq!((fixed_first - base, fixed_last - base), (0x0606_0efa, 0x0606_0ff9));
            assert_eq!(fixed_first / PAGE as u64, fixed_last / PAGE as u64);
            assert_eq!(PAGE - (fixed_first % PAGE as u64) as usize, 262);
            (target, range(base + 0x0606_0000, 2 * PAGE), [0xe9, 6, 7, 6, 6])
        } else { match fixture.placement {
            ArtifactRelocationPlacement::Fixed06 => {
                let target = base + 5 + 0x0601_0606;
                assert_eq!(target % PAGE as u64, 0x60b);
                (target, range(target & !4095, PAGE), [0xe9, 6, 6, 1, 6])
            }
            ArtifactRelocationPlacement::EntryAlphabetV1 => {
                let target = base + 0x0600_1000;
                assert_eq!(target - (body + 5), 0x0600_0706);
                let fixed_minimum = body + 5 + 0x0600_0606;
                assert_eq!(fixed_minimum, base + 0x0600_0f00);
                assert_eq!(PAGE - (fixed_minimum % PAGE as u64) as usize, 256);
                (target, range(base + 0x0600_0000, 2 * PAGE), [0xe9, 6, 7, 0, 6])
            }
        } };
        let storage = target & !4095;
        let image = arena.take_writable(storage, PAGE);
        let allocation = AllocationPolicy { ranges: vec![permit], preferred_address: None,
            max_candidates: 1, max_mappings: 1, max_mapped_bytes: PAGE };
        let state = SavedExtendedStateLayout::detect().unwrap();
        let needed = state.len() + HOOK_CONTEXT_STACK_PREFIX_BYTES as u64 + PAGE as u64 + 64;
        let emission = ArtifactEmission::new(TargetProfile::linux_x86_64_legacy_evex(state, 7).unwrap(),
            SymbolicHook { identity: 11, address: Some(hook.address()) },
            vec![range(base, PAGE), range(hook.address(), PAGE)]);
        let request = ArtifactRequest { site: PlanningSite {
            identity, code: description.body, base_address: body, function, block: function, logical_pc: selected[0],
            entries: &entries, semantics: HookSemantics::Observe, allocation: &allocation,
            search: SearchPolicy { max_upstream_bytes: 64, max_sites: 64, max_displaced_bytes: 256,
                tactics: TacticPolicy::RelocationOnly },
        }, emission: &emission };
        let predecessor = Composition::new(identity, vec![ExpectedBytes { address: body, bytes: description.body.to_vec() }]).unwrap();
        let (planned, size_bound) = if fixture.window == Window::PhysicalMin5 {
            physical_plan(&request, &predecessor, &selected, certificate)
        } else {
            let old = plan_artifact_observation_window_upstream_after(&ArtifactObservationSearchRequest {
                artifact: request, end: body + 4, observation_pcs: &selected,
            }, &predecessor, &[]).expect_err("old four-byte profile must still refuse");
            assert_eq!(old.reason, Refusal::NoPatchWindow);
            let seal = seal_artifact_observation_window_min5(&request, &selected).unwrap();
            assert_eq!(seal.selected_span(), range(body, 4)); assert_eq!(seal.retained_span(), function);
            assert_eq!(seal.matches_request(&request, &selected), Ok(()));
            let size_bound = certificate(body, &BODY, &selected, &emission);
            assert!(size_bound <= PAGE - (target - storage) as usize);
            let input = ArtifactObservationSearchRequest {
                artifact: request, end: seal.retained_span().end(), observation_pcs: &selected,
            };
            let planned = match fixture.placement {
                ArtifactRelocationPlacement::Fixed06 => plan_artifact_observation_window_upstream_after(&input, &predecessor, &[]),
                ArtifactRelocationPlacement::EntryAlphabetV1 => {
                    assert!(size_bound > 256 && size_bound <= PAGE);
                    let fixed = plan_artifact_observation_window_upstream_after(&input, &predecessor, &[]).unwrap_err();
                    assert_eq!(fixed.reason, Refusal::AllocationUnavailable);
                    assert_eq!(fixed.attempts.len(), 1);
                    plan_artifact_observation_window_upstream_after_with_placement(&input, &predecessor, &[], fixture.placement)
                }
            }.expect("required exact retained plan; no retry/fallback");
            if fixture.placement == ArtifactRelocationPlacement::EntryAlphabetV1 {
                assert_eq!(planned.search().runs.iter().map(|r| (r.domain, r.limit, r.examined, r.stop)).collect::<Vec<_>>(), [
                    (SearchDomain::PhysicalSites, 64, 1, SearchStop::Accepted),
                    (SearchDomain::SelectedImages, 1, 1, SearchStop::Accepted),
                ]);
                assert_eq!(planned.search().runs[1].finite_total, None);
                assert_eq!(planned.search().runs[1].candidates, None);
                assert!(!planned.search().classification_complete);
            }
            (planned, size_bound)
        };
        assert_eq!(planned.observation_pcs(), selected);
        let artifact = planned.artifact(); assert!(!artifact.qualification_complete());
        assert_eq!(artifact.source_steps().len(), 1);
        let step = &artifact.source_steps()[0]; let parts = step.parts();
        assert_eq!(parts.identity, identity); assert_eq!(parts.entries, entries);
        assert_eq!(parts.displaced, function); assert_eq!(parts.reads, predecessor.originals());
        if fixture.window == Window::PhysicalMin5 { assert_eq!((parts.logical_pc, parts.physical_pc), (body + 2, body)); }
        assert_eq!(parts.writes, [ByteEdit { address: body, bytes: patch.to_vec() }]);
        assert_eq!(parts.allocations, [AllocationRequest { range: range(storage, PAGE), alignment: PAGE }]);
        assert_eq!(parts.requirements, PublicationRequirements { quiescent: true, sync_core: true, sigill_router: true });
        step.check_entry_obligations().unwrap();
        let views: Vec<_> = artifact.images().collect(); assert_eq!(views.len(), 1); let view = &views[0];
        assert_eq!(view.address(), target); assert!(view.bytes().len() <= size_bound); assert!(range(storage, PAGE).covers(range(target, view.bytes().len())));
        assert_eq!(view.entry_routes().iter().map(|r| r.0).collect::<Vec<_>>(), heads);
        let bodies = view.instruction_boundaries().to_vec(); assert_eq!(bodies.iter().map(|r| r.0).collect::<Vec<_>>(), heads);
        assert_eq!(view.entry_routes()[3], bodies[3]);
        if fixture.window == Window::PhysicalMin5 {
            assert_eq!(view.entry_routes()[0], bodies[0], "unselected NOP has no callback prefix");
            for index in [1, 2] { assert!(view.entry_routes()[index].1 < bodies[index].1); }
        }
        assert_eq!(view.bytes()[(bodies[3].1 - target) as usize], 0xc3);
        for &(pc, body) in &bodies { assert!(view.program_counter_mappings().iter().any(|m| m.translate(body) == Some(pc))); }
        let routes: Vec<_> = parts.obligations.iter().filter_map(|o| match o { EntryObligation::Routed(r) => Some(*r), _ => None }).collect();
        assert_eq!(routes, view.entry_routes()[1..].iter().map(|&(original, generated)| EntryRoute { original, generated }).collect::<Vec<_>>());
        let fields: Vec<_> = view.metadata().fields().iter().filter(|f| f.role == "HookCall").collect();
        match fixture.window { Window::SelectedMin5 => assert_eq!(fields.len(), 3), Window::PhysicalMin5 => assert_eq!(fields.len(), 2) }
        assert_eq!(view.metadata().fields().iter().filter(|f| f.role == "LogicalPc").map(|f| f.target).collect::<Vec<_>>(), selected.iter().map(|&pc| i128::from(pc)).collect::<Vec<_>>());
        let calls: Vec<_> = fields.iter().zip(&selected).map(|(f, &logical)| {
            assert_eq!(f.target, i128::from(hook.address())); assert_eq!(f.width, 4);
            assert_eq!(f.encoding, ArtifactFieldEncoding::Relative); assert_eq!(f.origin, f.offset + 4);
            let pc = target + f.offset - 1; let at = usize::try_from(pc - target).unwrap();
            assert_eq!(view.bytes()[at], 0xe8);
            assert_eq!(i128::from(pc + 5) + i128::from(i32::from_le_bytes(view.bytes()[at + 1..at + 5].try_into().unwrap())), i128::from(hook.address()));
            (pc, logical)
        }).collect();
        let mut composed = predecessor.clone(); composed.append(step).unwrap();
        assert_eq!(predecessor.originals(), predecessor.final_bytes()); composed.require_unclaimed_ranges(&[]).unwrap();
        let original = oracle.original_code.clone(); let mut published = original.clone();
        assert_eq!(composed.final_bytes().len(), 1); assert_eq!(composed.final_bytes()[0].address, body);
        published[body_offset..body_offset + description.body.len()].copy_from_slice(&composed.final_bytes()[0].bytes);
        let mut image_bytes = vec![0xcc; PAGE]; let offset = usize::try_from(target - storage).unwrap();
        image_bytes[offset..offset + view.bytes().len()].copy_from_slice(view.bytes());
        image.initialize(0, &image_bytes); image.protect(libc::PROT_READ | libc::PROT_EXEC);
        let mut hook_bytes = vec![0xcc; PAGE]; hook_bytes[..2].copy_from_slice(&[0x48, 0xb8]);
        hook_bytes[2..10].copy_from_slice(&(observe as *const () as usize as u64).to_le_bytes());
        hook_bytes[10..12].copy_from_slice(&[0xff, 0xe0]);
        hook.initialize(0, &hook_bytes); hook.protect(libc::PROT_READ | libc::PROT_EXEC);
        oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        Self { oracle, image, hook, _arena: arena, _guard: guard, journal: HookEventLog::new(),
            original, published, image_bytes, hook_bytes, identity, routes, bodies, calls,
            selected, state, needed, entry, fault, body, fixture }
    }
    fn lease(&self, source: &[u8], identity: CodeIdentity, routes: &[EntryRoute]) {
        assert_eq!(identity, self.identity); assert_eq!(source, self.oracle.code.bytes());
        assert_eq!(self.image.bytes(), self.image_bytes); assert_eq!(self.hook.bytes(), self.hook_bytes);
        assert_eq!(routes, self.routes);
    }
    fn immutable(&self, child: &Tracee, installed: bool) {
        assert_eq!(child.memory(self.oracle.code.address(), PAGE), *(if installed { &self.published } else { &self.original }));
        assert_eq!(child.memory(self.image.address(), PAGE), self.image_bytes);
        assert_eq!(child.memory(self.hook.address(), PAGE), self.hook_bytes);
    }
    fn publish<R: Router>(&self, routes: &R, sync: &SyncCore) {
        self.lease(&self.original, self.identity, &self.routes); R::verify(); routes.assert_active();
        self.oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE); self.oracle.code.initialize(0, &self.published);
        self.oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC); sync.synchronize().unwrap();
        self.lease(&self.published, self.identity, &self.routes);
    }
    fn restore<R: Router>(&self, routes: &R, sync: &SyncCore) {
        self.lease(&self.published, self.identity, &self.routes); R::verify(); routes.assert_active();
        self.oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE); self.oracle.code.initialize(0, &self.original);
        self.oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC); sync.synchronize().unwrap(); routes.deactivate();
        self.lease(&self.original, self.identity, &self.routes);
    }
    fn path(&self) -> Vec<u64> {
        let base = self.oracle.code.address();
        [base + PRELUDE as u64, base + PRELUDE as u64 + 5].into_iter()
            .chain(self.fixture.description().heads.iter().filter(|&&at| at >= self.entry && at <= self.fixture.fault_at().unwrap_or(4)).map(|&at| self.body + at as u64))
            .chain((!self.fault).then(|| self.oracle.return_pc())).collect()
    }
}

// The new profile uses the real opaque schedule and the same shared planner.
// The actual PreparedArtifact adapter supplies a bound, never substitute bytes.
fn physical_plan(
    request: &ArtifactRequest<'_>, predecessor: &Composition, selected: &[u64], certificate: SizeCertificate,
) -> (liteinst2::quiescent::ArtifactObservationPlan, usize) {
    let body = request.site.base_address;
    assert_eq!(request.site.code, PHYSICAL_BODY); assert_eq!(selected, [body + 2, body + 3]);
    let unchanged = predecessor.clone();
    let same_site = seal_artifact_observation_window_min5(request, selected)
        .expect_err("same-site POP/POP/RET is only three bytes");
    assert_eq!(same_site.reason, Refusal::NoPatchWindow);
    assert!(same_site.attempts.is_empty() && same_site.search.runs.is_empty());
    assert!(!same_site.search.accepted && !same_site.search.classification_complete);
    let schedule = seal_artifact_observation_windows_upstream_min5(request, selected).unwrap();
    assert_eq!(schedule.selected_span(), range(body + 2, 2));
    assert_eq!(schedule.observation_pcs(), selected);
    assert_eq!(schedule.matches_request(request, selected), Ok(()));
    let policy = schedule.search_policy();
    assert_eq!((policy.tactics, policy.max_upstream_bytes, policy.max_displaced_bytes, policy.max_sites),
        (TacticPolicy::RelocationOnly, 64, 256, 64));
    assert_eq!(schedule.physical_domain(), [body + 2, body]);
    assert_eq!(schedule.rows().iter().map(|row| (row.ordinal(), row.physical_pc())).collect::<Vec<_>>(),
        [(0, body + 2), (1, body)]);
    assert_eq!(schedule.rows()[0].outcome(), Err(&Refusal::NoPatchWindow));
    assert_eq!(schedule.rows()[1].outcome(), Ok(body + 5));
    assert_eq!(schedule.rows()[0].qualification().len(), 1);
    assert_eq!(schedule.rows()[0].qualification()[0].reason, Refusal::NoPatchWindow);
    assert!(schedule.rows()[1].qualification().is_empty());
    assert_eq!(schedule.source_dependency(), Some((range(body, 5), PHYSICAL_BODY.as_slice())));
    let mut mask = [false; 4];
    for &head in &PHYSICAL_HEADS[1..] { mask[head - 1] = true; }
    assert_eq!(mask, [false, true, true, true]);
    let size_bound = certificate(body, &PHYSICAL_BODY, selected, request.emission);
    assert!(262 < size_bound && size_bound <= PAGE, "required actual bound; no alternate fixture");
    let fixed = plan_artifact_observation_windows_upstream_after_with_placement(
        request, &schedule, predecessor, &[], ArtifactRelocationPlacement::Fixed06).unwrap_err();
    assert_eq!(fixed.reason, Refusal::AllocationUnavailable);
    assert_eq!(fixed.attempts.iter().map(|attempt| (attempt.physical_pc, attempt.refusal.as_ref())).collect::<Vec<_>>(),
        [(body + 2, Some(&Refusal::NoPatchWindow)), (body, Some(&Refusal::AllocationUnavailable))]);
    assert_eq!(predecessor, &unchanged);
    let planned = plan_artifact_observation_windows_upstream_after_with_placement(
        request, &schedule, predecessor, &[], ArtifactRelocationPlacement::EntryAlphabetV1)
        .expect("required actual earlier-physical plan; no retry/fallback");
    assert_eq!(predecessor, &unchanged);
    assert_eq!(planned.search().runs.iter().map(|run| (run.domain, run.limit, run.examined, run.stop)).collect::<Vec<_>>(), [
        (SearchDomain::PhysicalSites, 64, 2, SearchStop::Accepted),
        (SearchDomain::SelectedImages, 1, 1, SearchStop::Accepted),
    ]);
    assert_eq!(planned.search().runs[0].finite_total, Some(2));
    assert_eq!(planned.search().runs[1].finite_total, None);
    assert_eq!(planned.search().runs[1].candidates, None);
    assert!(planned.search().accepted && !planned.search().classification_complete);
    assert_eq!(planned.search().refusals, schedule.rows()[0].qualification(), "qualification recorded once");
    let liteinst2::emission::ArtifactMetrics::Single(metrics) = planned.artifact().metrics() else { panic!("one actual shared relocation result") };
    assert_eq!((metrics.upstream_bytes, metrics.displaced_bytes, metrics.prefix_instructions, metrics.allocation_attempts), (2, 5, 1, 1));
    assert_eq!(metrics.attempts.iter().map(|attempt| (attempt.physical_pc, attempt.refusal.as_ref())).collect::<Vec<_>>(),
        [(body + 2, Some(&Refusal::NoPatchWindow)), (body, None)]);
    assert!(metrics.attempts.iter().all(|attempt| attempt.tactic == liteinst2::quiescent::PatchTactic::Relocation));
    (planned, size_bound)
}

fn original(owner: &Owner, seed: u64) -> Baseline {
    let path = owner.path();
    let result = if owner.fault { owner.oracle.original_fault(&path, seed, (libc::SIGSEGV, 2, owner.oracle.initial_rsp)) }
        else { owner.oracle.original(&path, seed) };
    assert_eq!(result.points.iter().map(|p| p.logical_pc).collect::<Vec<_>>(), path);
    let pop_points: Vec<_> = result.points.iter().filter(|p| owner.selected.contains(&p.logical_pc)).collect();
    let completed = if owner.fixture.fault == Fault::Pop {
        assert_eq!(pop_points.len(), 1); assert_eq!(pop_points[0].logical_pc, owner.body + 2);
        assert_eq!(pop_points[0].registers.rsp, owner.oracle.initial_rsp);
        let (register, _) = owner.fixture.description().pop(2);
        assert_eq!(register.value(&pop_points[0].registers), register.value(&result.initial)); 0
    } else { pop_points.len() };
    let lower = if owner.fault { completed as u64 * 8 } else { 96 };
    for (i, point) in pop_points[..completed].iter().enumerate() {
        assert_eq!(point.registers.rsp, owner.oracle.initial_rsp - lower + i as u64 * 8);
        let (register, next) = owner.fixture.description().pop(usize::try_from(point.logical_pc - owner.body).unwrap());
        let following = result.points.iter().find(|p| p.logical_pc == owner.body + next as u64).unwrap();
        let value = register.value(&following.registers);
        assert_eq!(value, 0x1020_3040_5060_7080 + i as u64);
        assert_eq!(following.registers.rsp, point.registers.rsp + 8);
    }
    if let Some(fault) = &result.fault {
        assert_eq!(fault.state.logical_pc, owner.body + owner.fixture.fault_at().unwrap() as u64);
        assert_eq!(fault.state.registers.rsp, owner.oracle.initial_rsp);
        assert_state(result.points.last().unwrap(), &fault.state);
        if owner.fixture.fault == Fault::Pop {
            let (register, _) = owner.fixture.description().pop(2);
            assert_eq!(register.value(&fault.state.registers), register.value(&result.initial));
        }
    } else {
        assert_eq!(result.points.last().unwrap().registers.rsp, owner.oracle.initial_rsp - 96 + (pop_points.len() as u64 + 1) * 8);
    }
    if owner.fixture.placement == ArtifactRelocationPlacement::EntryAlphabetV1 {
        // The unchanged shared scratch inequalities are checked against original
        // RSP values before publishing or executing any helper in these cases.
        let expected_events = events(&owner.oracle, &result.points, &owner.selected, owner.needed);
        assert_eq!(expected_events.len(), pop_points.len());
        if owner.fixture.fault == Fault::Pop {
            assert_eq!(expected_events, [event(owner.body + 2, owner.oracle.initial_rsp)]);
        }
    }
    result
}
fn trace(owner: &Owner, baseline: &Baseline, route_counter: u64, installed: bool) -> (usize, usize) {
    let _active = owner.journal.activate(); let child = Tracee::fork(); let mut budget = Budget { used: 0 };
    budget.charge(&child, 2); child.set_registers(&baseline.initial); child.set_xstate(&baseline.xstate);
    let mut boundaries: BTreeMap<u64, u64> = baseline.points.iter().map(|p| (p.logical_pc, p.logical_pc)).collect();
    if installed { for &(logical, physical) in &owner.bodies { boundaries.remove(&logical); assert!(boundaries.insert(physical, logical).is_none()); } }
    let mut index = 0; let mut callbacks = Vec::new(); let mut deliveries = 0;
    let mut active_call: Option<(u64, u64)> = None;
    loop {
        budget.charge(&child, 0); let pc = child.registers().rip; owner.immutable(&child, installed);
        assert_eq!(counter(&child, route_counter), deliveries);
        if installed {
            if let Some(&route) = owner.routes.iter().find(|r| r.original == pc) {
                assert!(index == 2 && active_call.is_none()); assert_eq!(pc, owner.body + owner.entry as u64);
                if owner.fixture.placement == ArtifactRelocationPlacement::EntryAlphabetV1 && owner.entry == 2 { assert_eq!(child.memory(pc, 1), [0x07]); }
                assert_eq!(deliveries, 0); deliver(&child, &mut budget, route, route_counter, deliveries); deliveries += 1; continue;
            }
            if let Some(&(call, logical)) = owner.calls.iter().find(|c| c.0 == pc) {
                assert!(active_call.is_none()); let expected = &baseline.points[index]; assert_eq!(logical, expected.logical_pc);
                let rsp = child.registers().rsp; assert_eq!(rsp % 16, 0); budget.step(&child);
                assert_eq!(child.registers().rsp, rsp - 8);
                assert_hook_context(&owner.oracle, owner.state, owner.hook.address(), &child, expected, call + 5);
                active_call = Some((call + 5, rsp)); callbacks.push(event(logical, expected.registers.rsp));
                budget.step(&child); continue;
            }
            assert_ne!(pc, owner.hook.address(), "callback without witnessed CALL");
            if let Some((_, rsp)) = active_call.filter(|(returned, _)| pc == *returned) {
                assert_eq!(child.registers().rsp, rsp); active_call = None; owner.journal.assert_events(&child, &callbacks);
            }
        }
        if let Some(&logical) = boundaries.get(&pc) {
            assert!(active_call.is_none()); let expected = baseline.points.get(index).expect("extra native boundary");
            assert_eq!(logical, expected.logical_pc); assert_state(expected, &owner.oracle.snapshot(&child, logical, if installed { &owner.published } else { &owner.original }));
            let expected_events = if installed { events(&owner.oracle, &baseline.points[..=index], &owner.selected, owner.needed) } else { vec![] };
            assert_eq!(callbacks, expected_events); owner.journal.assert_events(&child, &expected_events); index += 1;
            if index == baseline.points.len() { break; }
        }
        budget.step(&child);
    }
    assert_eq!(index, baseline.points.len()); assert!(active_call.is_none());
    assert_eq!(deliveries, u64::from(installed && owner.entry != 0));
    let expected_events = if installed { events(&owner.oracle, &baseline.points, &owner.selected, owner.needed) } else { vec![] };
    assert_eq!(callbacks, expected_events); owner.journal.assert_events(&child, &callbacks);
    if let Some(expected) = &baseline.fault {
        budget.charge(&child, 1);
        let at = owner.fixture.fault_at().unwrap(); let logical = owner.body + at as u64;
        let physical = if installed { owner.bodies[owner.fixture.description().heads.iter().position(|&head| head == at).unwrap()].1 } else { logical };
        let actual = owner.oracle.capture_fault(&child, physical, logical);
        assert_eq!((actual.signal, actual.code, actual.address), (expected.signal, expected.code, expected.address));
        assert_state(&expected.state, &actual.state); assert_eq!(actual.state.registers.rsp, owner.oracle.initial_rsp);
        owner.journal.assert_events(&child, &callbacks); owner.immutable(&child, installed);
    }
    for bad in [vec![event(owner.body + 4, owner.oracle.initial_rsp)], callbacks.iter().cloned().chain([event(0, 0)]).collect()] {
        rejected(|| owner.journal.assert_events(&child, &bad));
    }
    if !callbacks.is_empty() { rejected(|| owner.journal.assert_events(&child, &callbacks[..callbacks.len() - 1])); }
    // The real child's positive complete-page comparison precedes expected-byte
    // mutants. No tracee writes or alternate expected native state are used.
    for (address, bytes) in [
        (owner.oracle.code.address(), if installed { &owner.published } else { &owner.original }),
        (owner.image.address(), &owner.image_bytes), (owner.hook.address(), &owner.hook_bytes),
    ] {
        assert_eq!(child.memory(address, PAGE), *bytes);
        for at in [0, PAGE - 1] {
            let mut bad = bytes.clone(); bad[at] ^= 1;
            rejected(|| assert_eq!(child.memory(address, PAGE), bad));
        }
    }
    let result = (callbacks.len(), deliveries as usize); finish(&child); result
}
fn run<R: Router>(entry: usize, seed: u64, fault: bool, certificate: SizeCertificate) -> (usize, usize) {
    run_owner::<R>(Owner::new(entry, fault, certificate), seed)
}
fn run_owner<R: Router>(owner: Owner, seed: u64) -> (usize, usize) {
    owner.lease(&owner.original, owner.identity, &owner.routes);
    let mut wrong_identity = owner.identity; wrong_identity.generation += 1;
    rejected(|| owner.lease(&owner.original, wrong_identity, &owner.routes));
    let mut wrong_source = owner.original.clone(); wrong_source[owner.fixture.body_offset() + 4] ^= 1;
    rejected(|| owner.lease(&wrong_source, owner.identity, &owner.routes));
    let mut wrong_routes = owner.routes.clone(); wrong_routes.last_mut().unwrap().generated += 1;
    rejected(|| owner.lease(&owner.original, owner.identity, &wrong_routes));
    let sync = SyncCore::prepare().unwrap(); R::prepare(); R::verify();
    let routes = R::stage(&owner.routes); routes.assert_active(); let route_counter = routes.counter_address();
    let baseline = original(&owner, seed); owner.publish::<R>(&routes, &sync);
    let result = trace(&owner, &baseline, route_counter, true); owner.restore::<R>(&routes, &sync);
    assert_eq!(trace(&owner, &baseline, route_counter, false), (0, 0)); result
}
pub fn entries<R: Router>(certificate: SizeCertificate) {
    let mut census = [0_usize; 3];
    for entry in HEADS { for seed in SEEDS { let (hooks, routes) = run::<R>(entry, seed, false, certificate); census[0] += 1; census[1] += hooks; census[2] += routes; } }
    assert_eq!(census, [8, 12, 6]); // each case captures original, installed and restored children
}
pub fn ret_faults<R: Router>(certificate: SizeCertificate) {
    let mut census = [0_usize; 3];
    for entry in [0, 1] { for seed in SEEDS { let (hooks, routes) = run::<R>(entry, seed, true, certificate); census[0] += 1; census[1] += hooks; census[2] += routes; } }
    assert_eq!(census, [4, 10, 2]);
}

pub fn alphabet_entries<R: Router>(certificate: SizeCertificate) {
    let mut census = [0_usize; 3];
    for entry in HEADS { for seed in SEEDS {
        let owner = Owner::with_fixture(entry, Fixture { placement: ArtifactRelocationPlacement::EntryAlphabetV1, fault: Fault::None, window: Window::SelectedMin5 }, certificate);
        let (hooks, routes) = run_owner::<R>(owner, seed); census[0] += 1; census[1] += hooks; census[2] += routes;
    } }
    assert_eq!(census, [8, 12, 6]);
}
pub fn alphabet_ret_faults<R: Router>(certificate: SizeCertificate) {
    let mut census = [0_usize; 3];
    for entry in [0, 1] { for seed in SEEDS {
        let owner = Owner::with_fixture(entry, Fixture { placement: ArtifactRelocationPlacement::EntryAlphabetV1, fault: Fault::Ret, window: Window::SelectedMin5 }, certificate);
        let (hooks, routes) = run_owner::<R>(owner, seed); census[0] += 1; census[1] += hooks; census[2] += routes;
    } }
    assert_eq!(census, [4, 10, 2]);
}
pub fn alphabet_pop_faults<R: Router>(certificate: SizeCertificate) {
    let mut census = [0_usize; 3];
    for seed in SEEDS {
        let owner = Owner::with_fixture(2, Fixture { placement: ArtifactRelocationPlacement::EntryAlphabetV1, fault: Fault::Pop, window: Window::SelectedMin5 }, certificate);
        let (hooks, routes) = run_owner::<R>(owner, seed); census[0] += 1; census[1] += hooks; census[2] += routes;
    }
    assert_eq!(census, [2, 2, 2]);
}

// Separate registrations call these through the single inherited oracle module.
pub fn physical_entries<R: Router>(certificate: SizeCertificate) {
    let mut census = [0_usize; 3];
    for entry in PHYSICAL_HEADS { for seed in SEEDS {
        let owner = Owner::with_fixture(entry, Fixture { placement: ArtifactRelocationPlacement::EntryAlphabetV1,
            fault: Fault::None, window: Window::PhysicalMin5 }, certificate);
        let (hooks, routes) = run_owner::<R>(owner, seed); census[0] += 1; census[1] += hooks; census[2] += routes;
    } }
    assert_eq!(census, [8, 10, 6]);
}
pub fn physical_ret_faults<R: Router>(certificate: SizeCertificate) {
    let mut census = [0_usize; 3];
    for entry in [2, 3] { for seed in SEEDS {
        let owner = Owner::with_fixture(entry, Fixture { placement: ArtifactRelocationPlacement::EntryAlphabetV1,
            fault: Fault::Ret, window: Window::PhysicalMin5 }, certificate);
        let (hooks, routes) = run_owner::<R>(owner, seed); census[0] += 1; census[1] += hooks; census[2] += routes;
    } }
    assert_eq!(census, [4, 6, 4]);
}
pub fn physical_pop_faults<R: Router>(certificate: SizeCertificate) {
    let mut census = [0_usize; 3];
    for seed in SEEDS {
        let owner = Owner::with_fixture(2, Fixture { placement: ArtifactRelocationPlacement::EntryAlphabetV1,
            fault: Fault::Pop, window: Window::PhysicalMin5 }, certificate);
        let (hooks, routes) = run_owner::<R>(owner, seed); census[0] += 1; census[1] += hooks; census[2] += routes;
    }
    assert_eq!(census, [2, 2, 2]);
}
