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
use liteinst2::quiescent::{AllocationPolicy, ArtifactObservationSearchRequest, SearchPolicy, TacticPolicy,
    plan_artifact_observation_window_upstream_after, seal_artifact_observation_window_min5};
use liteinst2::sync_core::SyncCore;
use liteinst2::trampoline::{SavedExtendedStateLayout, HOOK_CONTEXT_STACK_PREFIX_BYTES};

const BODY: [u8; 5] = [0x5b, 0x5d, 0x41, 0x5c, 0xc3];
const HEADS: [usize; 4] = [0, 1, 2, 4];
const PRELUDE: usize = 0x100;
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
fn range(address: u64, length: usize) -> AddressRange { AddressRange::new(address, length).unwrap() }
fn rejected(f: impl FnOnce()) { assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err()); }

pub type SizeCertificate = fn(u64, &[u8], &[u64], &ArtifactEmission) -> usize;

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
}
impl Owner {
    fn new(entry: usize, fault: bool, certificate: SizeCertificate) -> Self {
        assert!(HEADS.contains(&entry));
        if fault { assert!([0, 1].contains(&entry)); }
        let lower = if fault { if entry == 0 { 24 } else { 16 } } else { 96 };
        let mut code = vec![0xcc; PRELUDE + 10];
        code[..5].copy_from_slice(&BODY);
        code[PRELUDE..PRELUDE + 6].copy_from_slice(&[0x48, 0x8d, 0x64, 0x24, 0_u8.wrapping_sub(lower), 0xe9]);
        code[PRELUDE + 6..].copy_from_slice(&i32::try_from(entry as i64 - (PRELUDE + 10) as i64).unwrap().to_le_bytes());
        let (mut oracle, mut adjacent, mut arena) = NativeOracle::with_neighbor_fixture(&code, &[PAGE]);
        let hook = adjacent.pop().unwrap(); assert!(adjacent.is_empty());
        let base = oracle.code.address(); assert_eq!(base % PAGE as u64, 0);
        assert_eq!(hook.address(), base + PAGE as u64);
        let guard = if fault {
            assert_eq!(oracle.stack.len, STACK_BYTES + PAGE);
            let guard = Mapping {
                // SAFETY: transfer the owned final page without any unmapped interval.
                address: unsafe { oracle.stack.address.add(STACK_BYTES) }, len: PAGE,
            };
            oracle.stack.len = STACK_BYTES; oracle.initial_rsp = guard.address();
            guard.protect(libc::PROT_NONE); Some(guard)
        } else { None };
        let suffix = HEADS.iter().filter(|&&at| at >= entry && at != 4).count();
        let start_rsp = oracle.initial_rsp - u64::from(lower);
        for i in 0..suffix {
            let value = 0x1020_3040_5060_7080_u64 + i as u64;
            oracle.stack.initialize((start_rsp - oracle.stack.address()) as usize + 8 * i, &value.to_le_bytes());
        }
        if fault { assert_eq!(start_rsp + 8 * suffix as u64, oracle.initial_rsp); }
        else { oracle.stack.initialize((start_rsp - oracle.stack.address()) as usize + 8 * suffix, &oracle.return_pc().to_le_bytes()); }
        let identity = CodeIdentity { source: SourceIdentity([0x35; 32]), mapping: base, generation: 1 };
        let function = range(base, BODY.len());
        let heads = HEADS.map(|at| base + at as u64);
        let selected = heads[..3].to_vec();
        let entries = LegalEntrySet {
            identity, scope: function,
            provenance: EntryProvenance::Declared("complete finite three-POP/RET literal grammar".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: heads.map(|address| LegalEntry { address, requires_endbr: false }).to_vec(),
            resumes: ResumeObligation::NoneExist,
        };
        let target = base + 5 + 0x0601_0606;
        let storage = target & !4095; assert_eq!(target - storage, 0x60b);
        let image = arena.take_writable(storage, PAGE);
        let allocation = AllocationPolicy { ranges: vec![range(storage, PAGE)], preferred_address: None,
            max_candidates: 1, max_mappings: 1, max_mapped_bytes: PAGE };
        let state = SavedExtendedStateLayout::detect().unwrap();
        let needed = state.len() + HOOK_CONTEXT_STACK_PREFIX_BYTES as u64 + PAGE as u64 + 64;
        let emission = ArtifactEmission::new(TargetProfile::linux_x86_64_legacy_evex(state, 7).unwrap(),
            SymbolicHook { identity: 11, address: Some(hook.address()) },
            vec![range(base, PAGE), range(hook.address(), PAGE)]);
        let request = ArtifactRequest { site: PlanningSite {
            identity, code: &BODY, base_address: base, function, block: function, logical_pc: base,
            entries: &entries, semantics: HookSemantics::Observe, allocation: &allocation,
            search: SearchPolicy { max_upstream_bytes: 64, max_sites: 64, max_displaced_bytes: 256,
                tactics: TacticPolicy::RelocationOnly },
        }, emission: &emission };
        let predecessor = Composition::new(identity, vec![ExpectedBytes { address: base, bytes: BODY.to_vec() }]).unwrap();
        let old = plan_artifact_observation_window_upstream_after(&ArtifactObservationSearchRequest {
            artifact: request, end: base + 4, observation_pcs: &selected,
        }, &predecessor, &[]).expect_err("old four-byte profile must still refuse");
        assert_eq!(old.reason, Refusal::NoPatchWindow);
        let seal = seal_artifact_observation_window_min5(&request, &selected).unwrap();
        assert_eq!(seal.selected_span(), range(base, 4)); assert_eq!(seal.retained_span(), function);
        assert_eq!(seal.matches_request(&request, &selected), Ok(()));
        let size_bound = certificate(base, &BODY, &selected, &emission);
        assert!(size_bound <= PAGE - (target - storage) as usize);
        let planned = plan_artifact_observation_window_upstream_after(&ArtifactObservationSearchRequest {
            artifact: request, end: seal.retained_span().end(), observation_pcs: &selected,
        }, &predecessor, &[]).expect("required exact retained plan; no retry/fallback");
        assert_eq!(planned.observation_pcs(), selected);
        let artifact = planned.artifact(); assert!(!artifact.qualification_complete());
        assert_eq!(artifact.source_steps().len(), 1);
        let step = &artifact.source_steps()[0]; let parts = step.parts();
        assert_eq!(parts.identity, identity); assert_eq!(parts.entries, entries);
        assert_eq!(parts.displaced, function); assert_eq!(parts.reads, predecessor.originals());
        assert_eq!(parts.writes, [ByteEdit { address: base, bytes: vec![0xe9, 6, 6, 1, 6] }]);
        assert_eq!(parts.allocations, [AllocationRequest { range: range(storage, PAGE), alignment: PAGE }]);
        assert_eq!(parts.requirements, PublicationRequirements { quiescent: true, sync_core: true, sigill_router: true });
        step.check_entry_obligations().unwrap();
        let views: Vec<_> = artifact.images().collect(); assert_eq!(views.len(), 1); let view = &views[0];
        assert_eq!(view.address(), target); assert!(view.bytes().len() <= size_bound); assert!(range(storage, PAGE).covers(range(target, view.bytes().len())));
        assert_eq!(view.entry_routes().iter().map(|r| r.0).collect::<Vec<_>>(), heads);
        let bodies = view.instruction_boundaries().to_vec(); assert_eq!(bodies.iter().map(|r| r.0).collect::<Vec<_>>(), heads);
        assert_eq!(view.entry_routes()[3], bodies[3]);
        assert_eq!(view.bytes()[(bodies[3].1 - target) as usize], 0xc3);
        for &(pc, body) in &bodies { assert!(view.program_counter_mappings().iter().any(|m| m.translate(body) == Some(pc))); }
        let routes: Vec<_> = parts.obligations.iter().filter_map(|o| match o { EntryObligation::Routed(r) => Some(*r), _ => None }).collect();
        assert_eq!(routes, view.entry_routes()[1..].iter().map(|&(original, generated)| EntryRoute { original, generated }).collect::<Vec<_>>());
        let fields: Vec<_> = view.metadata().fields().iter().filter(|f| f.role == "HookCall").collect(); assert_eq!(fields.len(), 3);
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
        assert_eq!(composed.final_bytes().len(), 1); assert_eq!(composed.final_bytes()[0].address, base);
        published[..5].copy_from_slice(&composed.final_bytes()[0].bytes);
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
            selected, state, needed, entry, fault }
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
            .chain(HEADS.iter().filter(|&&at| at >= self.entry).map(|&at| base + at as u64))
            .chain((!self.fault).then(|| self.oracle.return_pc())).collect()
    }
}

fn original(owner: &Owner, seed: u64) -> Baseline {
    let path = owner.path();
    let result = if owner.fault { owner.oracle.original_fault(&path, seed, (libc::SIGSEGV, 2, owner.oracle.initial_rsp)) }
        else { owner.oracle.original(&path, seed) };
    assert_eq!(result.points.iter().map(|p| p.logical_pc).collect::<Vec<_>>(), path);
    let pop_points: Vec<_> = result.points.iter().filter(|p| owner.selected.contains(&p.logical_pc)).collect();
    let lower = if owner.fault { pop_points.len() as u64 * 8 } else { 96 };
    for (i, point) in pop_points.iter().enumerate() {
        assert_eq!(point.registers.rsp, owner.oracle.initial_rsp - lower + i as u64 * 8);
        let following = result.points.iter().find(|p| p.logical_pc == match point.logical_pc - owner.oracle.code.address() { 0 => point.logical_pc + 1, 1 => point.logical_pc + 1, 2 => point.logical_pc + 2, _ => unreachable!() }).unwrap();
        let value = match point.logical_pc - owner.oracle.code.address() { 0 => following.registers.rbx, 1 => following.registers.rbp, 2 => following.registers.r12, _ => unreachable!() };
        assert_eq!(value, 0x1020_3040_5060_7080 + i as u64);
        assert_eq!(following.registers.rsp, point.registers.rsp + 8);
    }
    if let Some(fault) = &result.fault {
        assert_eq!(fault.state.logical_pc, owner.oracle.code.address() + 4);
        assert_eq!(fault.state.registers.rsp, owner.oracle.initial_rsp);
        assert_state(result.points.last().unwrap(), &fault.state);
    } else {
        assert_eq!(result.points.last().unwrap().registers.rsp, owner.oracle.initial_rsp - 96 + (pop_points.len() as u64 + 1) * 8);
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
                assert!(index == 2 && active_call.is_none()); assert_eq!(pc, owner.oracle.code.address() + owner.entry as u64);
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
            if let Some((returned, rsp)) = active_call {
                if pc == returned { assert_eq!(child.registers().rsp, rsp); active_call = None; owner.journal.assert_events(&child, &callbacks); }
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
        budget.charge(&child, 1); let physical = if installed { owner.bodies[3].1 } else { owner.oracle.code.address() + 4 };
        let actual = owner.oracle.capture_fault(&child, physical, owner.oracle.code.address() + 4);
        assert_eq!((actual.signal, actual.code, actual.address), (expected.signal, expected.code, expected.address));
        assert_state(&expected.state, &actual.state); assert_eq!(actual.state.registers.rsp, owner.oracle.initial_rsp);
        owner.journal.assert_events(&child, &callbacks); owner.immutable(&child, installed);
    }
    for bad in [vec![event(owner.oracle.code.address() + 4, owner.oracle.initial_rsp)], callbacks.iter().cloned().chain([event(0, 0)]).collect()] {
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
    let owner = Owner::new(entry, fault, certificate); owner.lease(&owner.original, owner.identity, &owner.routes);
    let mut wrong_identity = owner.identity; wrong_identity.generation += 1;
    rejected(|| owner.lease(&owner.original, wrong_identity, &owner.routes));
    let mut wrong_source = owner.original.clone(); wrong_source[4] ^= 1;
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
