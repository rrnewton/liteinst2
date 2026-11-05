// Finite native execution of read-only artifact-window images. The authored
// prefix owns its five-byte E9; this does not test planner/router admission.
use super::*;
use liteinst::contracts::AddressRange;
use liteinst::emission::{ArtifactEmission, SymbolicHook, TargetProfile};
use liteinst::scanner::InstructionScanner;
use liteinst::trampoline::{
    ArtifactObservationWindow, ArtifactWindowImage, HookContext, SavedExtendedStateLayout,
    HOOK_CONTEXT_STACK_PREFIX_BYTES,
};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const WINDOW: usize = 16;

pub(super) fn event(pc: u64, rsp: u64) -> HookEvent {
    // With the separately exact PC this encoding is invertible, not a hash.
    HookEvent { probe_id: rsp.rotate_left(32) ^ pc, logical_pc: pc }
}

pub(super) unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the fixed child owns this live frame and private event page.
    unsafe {
        let context = &*context;
        let e = event(context.instruction_pointer, context.stack_pointer);
        record_hook_event(e.probe_id, e.logical_pc);
        core::arch::asm!("add rax, 1", "pxor xmm0, xmm0", "fninit",
            out("rax") _, out("xmm0") _, options(nostack));
    }
}

fn fixture(body: &[u8], entry: usize, lower: u8) -> Vec<u8> {
    assert!(lower > 0 && lower <= 127);
    assert!(entry < body.len());
    // Same unobserved LEA in both executions; only this owned E9 is retargeted.
    let mut code = vec![0x48, 0x8d, 0x64, 0x24, 0_u8.wrapping_sub(lower), 0xe9];
    code.extend_from_slice(&i32::try_from(WINDOW + entry - 10).unwrap().to_le_bytes());
    code.resize(WINDOW, 0x90);
    code.extend_from_slice(body);
    code.push(0x90); // terminal is stopped before execution
    code
}

fn copy_page(mapping: &Mapping, bytes: &[u8]) {
    assert!(bytes.len() <= PAGE);
    mapping.protect(libc::PROT_READ | libc::PROT_WRITE);
    mapping.initialize(0, &vec![0xcc; PAGE]);
    mapping.initialize(0, bytes);
    mapping.protect(libc::PROT_READ | libc::PROT_EXEC);
}

fn emit(
    oracle: &NativeOracle, pages: &[Mapping], code: &[u8], length: usize,
    heads: &[usize], selected: &[usize],
) -> (ArtifactWindowImage, u64) {
    assert_eq!(pages.len(), 2);
    let base = oracle.code.address() + WINDOW as u64;
    let pcs: Vec<_> = selected.iter().map(|pc| base + *pc as u64).collect();
    let state = SavedExtendedStateLayout::detect().unwrap();
    // Include worst alignment slack and one fixed callback-stack page. No
    // runtime stack, state component or target-profile refusal is skipped.
    let needed = state.len() + HOOK_CONTEXT_STACK_PREFIX_BYTES as u64 + PAGE as u64 + 64;
    let target = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(state, 7).unwrap(),
        SymbolicHook { identity: 11, address: Some(pages[1].address()) },
        vec![AddressRange::new(oracle.code.address(), PAGE).unwrap(),
            AddressRange::new(pages[1].address(), PAGE).unwrap()],
    );
    let scan = InstructionScanner::default().scan(code, oracle.code.address()).unwrap();
    let window = ArtifactObservationWindow::checked(&scan, base, base + length as u64, &pcs).unwrap();
    let output = window.emit_at(pages[0].address(), &target).unwrap();
    assert_eq!(output.observation_pcs(), pcs);
    let image = output.image();
    let expected: Vec<_> = heads.iter().map(|pc| base + *pc as u64).collect();
    assert_eq!(image.entry_routes().iter().map(|r| r.0).collect::<Vec<_>>(), expected);
    assert_eq!(image.instruction_boundaries().iter().map(|r| r.0).collect::<Vec<_>>(), expected);
    for (&(pc, entry), &(body_pc, body)) in image.entry_routes().iter().zip(image.instruction_boundaries()) {
        assert_eq!(pc, body_pc);
        if pcs.contains(&pc) { assert!(entry < body); } else { assert_eq!(entry, body); }
    }
    assert!(!image.metadata().qualification_complete());
    copy_page(&pages[0], image.bytes());
    // The near symbolic target jumps to the real callback without touching the
    // already-saved application state; this is the existing artifact stub form.
    let mut hook = vec![0x48, 0xb8];
    hook.extend_from_slice(&(observe as *const () as usize as u64).to_le_bytes());
    hook.extend_from_slice(&[0xff, 0xe0]);
    copy_page(&pages[1], &hook);
    (output, needed)
}

pub(super) fn events(oracle: &NativeOracle, points: &[Snapshot], selected: &[u64], needed: u64) -> Vec<HookEvent> {
    let mut result = Vec::new();
    for point in points.iter().filter(|p| selected.contains(&p.logical_pc)) {
        let rsp = point.registers.rsp;
        // Descriptor ends at rsp-128. Keep every helper byte outside the
        // unchanged [initial_rsp-128, stack.end) application snapshot.
        assert!(rsp <= oracle.initial_rsp);
        assert!(rsp.checked_sub(needed).unwrap() > oracle.stack.address() + PAGE as u64);
        result.push(event(point.logical_pc, rsp));
    }
    let ids: BTreeSet<_> = result.iter().map(|e| e.probe_id).collect();
    assert_eq!(ids.len(), result.len());
    result
}

fn redirect(oracle: &NativeOracle, image: &ArtifactWindowImage, entry: usize) {
    let pc = oracle.code.address() + WINDOW as u64 + entry as u64;
    let target = image.image().entry_routes().iter().find(|r| r.0 == pc).unwrap().1;
    let mut patch = vec![0xe9];
    patch.extend_from_slice(&i32::try_from(i128::from(target) - i128::from(oracle.code.address() + 10))
        .unwrap().to_le_bytes());
    oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
    oracle.code.initialize(5, &patch);
    oracle.code.protect(libc::PROT_READ | libc::PROT_EXEC);
    oracle.assert_publication(&[(oracle.code.address() + 5, patch)]);
}

fn map(oracle: &NativeOracle, image: &ArtifactWindowImage, end: usize) -> TraceMap {
    let base = oracle.code.address();
    let view = image.image();
    let mut boundaries = vec![(base, base), (base + 5, base + 5)];
    boundaries.extend_from_slice(view.instruction_boundaries());
    boundaries.push((base + WINDOW as u64 + end as u64, base + WINDOW as u64 + end as u64));
    TraceMap {
        boundaries, gateways: vec![],
        generated_ranges: std::iter::once(view.address()..view.address() + view.bytes().len() as u64).collect(),
    }
}

pub fn every_entry() {
    // Six-POP adjacency with flag-preserving LEA EAX,[RAX+1] / MOVZX EAX,AL.
    // These literal native operands are not the corpus XOR (undefined AF).
    let body = [0x5b, 0x5d, 0x8d, 0x40, 1, 0x41, 0x5c, 0x41,
        0x5d, 0x0f, 0xb6, 0xc0, 0x41, 0x5e, 0x41, 0x5f];
    let heads = [0, 1, 2, 5, 7, 9, 12, 14];
    let selected = [0, 1, 5, 7, 12, 14];
    let mut census = [0_usize; 2];
    for &entry in &heads {
        let code = fixture(&body, entry, 96);
        let (oracle, pages) = NativeOracle::with_adjacent_code_mappings(&code, &[PAGE, PAGE]);
        let base = oracle.code.address();
        let all: Vec<_> = [base, base + 5].into_iter()
            .chain(heads.map(|pc| base + WINDOW as u64 + pc as u64)).collect();
        let end = base + WINDOW as u64 + body.len() as u64;
        let originals: Vec<_> = SEEDS.iter().map(|seed| {
            let trace = oracle.trace_original(base, &all, &[end], *seed);
            let expected: Vec<_> = [base, base + 5].into_iter()
                .chain(heads.iter().filter(|pc| **pc >= entry).map(|pc| base + WINDOW as u64 + *pc as u64))
                .chain([end]).collect();
            assert_eq!(trace.visits(), expected);
            trace
        }).collect();
        let (image, needed) = emit(&oracle, &pages, &code, body.len(), &heads, &selected);
        redirect(&oracle, &image, entry);
        let log = HookEventLog::new();
        for trace in originals {
            let expected = events(&oracle, &trace.baseline.points, image.observation_pcs(), needed);
            assert_eq!(expected.len(), selected.iter().filter(|pc| **pc >= entry).count());
            oracle.assert_trace(&trace, base, &map(&oracle, &image, body.len()), &[],
                Some(HookExpectation { log: &log, enabled: &expected }));
            census[0] += 1;
            census[1] += expected.len();
        }
    }
    assert_eq!(census, [16, 54]);
}

pub fn branch_paths() {
    // JZ +2 skips POP RBX and an unselected NOP, targeting POP RBP's observer.
    let body = [0x74, 2, 0x5b, 0x90, 0x5d, 0x41, 0x5c];
    let heads = [0, 2, 3, 4, 5];
    let selected = [2, 4, 5];
    let mut census = [0_usize; 3];
    for &entry in &heads {
        let code = fixture(&body, entry, 96);
        let (oracle, pages) = NativeOracle::with_seeded_memory_and_flags_adjacent(&code, 0xabc, &[PAGE, PAGE]);
        let base = oracle.code.address();
        let all: Vec<_> = [base, base + 5].into_iter()
            .chain(heads.map(|pc| base + WINDOW as u64 + pc as u64)).collect();
        let end = base + WINDOW as u64 + body.len() as u64;
        let originals: Vec<_> = SEEDS.iter().map(|seed| {
            let trace = oracle.trace_original(base, &all, &[end], *seed);
            let taken = entry == 0 && seed & 0x40 != 0;
            let body_path: Vec<_> = heads.iter().copied().filter(|pc| *pc >= entry && !(taken && [2, 3].contains(pc))).collect();
            let expected: Vec<_> = [base, base + 5].into_iter()
                .chain(body_path.iter().map(|pc| base + WINDOW as u64 + *pc as u64)).chain([end]).collect();
            assert_eq!(trace.visits(), expected);
            if entry == 0 { census[usize::from(taken)] += 1; }
            trace
        }).collect();
        let (image, needed) = emit(&oracle, &pages, &code, body.len(), &heads, &selected);
        redirect(&oracle, &image, entry);
        let log = HookEventLog::new();
        for trace in originals {
            let expected = events(&oracle, &trace.baseline.points, image.observation_pcs(), needed);
            oracle.assert_trace(&trace, base, &map(&oracle, &image, body.len()), &[],
                Some(HookExpectation { log: &log, enabled: &expected }));
            census[2] += 1;
        }
    }
    assert_eq!(census, [1, 1, 10]);
}

pub fn rsp_effects() {
    // PUSH RSP; POP RAX; POP RSP; POP RDX; NOP. Loaded RSP differs from old+8.
    let body = [0x54, 0x58, 0x5c, 0x5a, 0x90];
    let heads = [0, 1, 2, 3, 4];
    let selected = [0, 1, 2, 3];
    let code = fixture(&body, 0, 96);
    let (oracle, pages) = NativeOracle::with_adjacent_code_mappings(&code, &[PAGE, PAGE]);
    let base = oracle.code.address();
    let start_rsp = oracle.initial_rsp - 96;
    let loaded = oracle.initial_rsp - 64;
    assert_ne!(loaded, start_rsp + 8);
    oracle.stack.initialize((start_rsp - oracle.stack.address()) as usize, &loaded.to_le_bytes());
    let all: Vec<_> = [base, base + 5].into_iter()
        .chain(heads.map(|pc| base + WINDOW as u64 + pc as u64)).collect();
    let end = base + WINDOW as u64 + body.len() as u64;
    let originals: Vec<_> = SEEDS.iter().map(|seed| {
        let trace = oracle.trace_original(base, &all, &[end], *seed);
        assert_eq!(trace.visits(), all.iter().copied().chain([end]).collect::<Vec<_>>());
        let points = &trace.baseline.points;
        assert_eq!(points[2].registers.rsp, start_rsp);
        assert_eq!(points[3].registers.rsp, start_rsp - 8);
        let at = usize::try_from((start_rsp - 8) - (oracle.initial_rsp - 128)).unwrap();
        assert_eq!(u64::from_le_bytes(points[3].application_stack[at..at + 8].try_into().unwrap()), start_rsp);
        assert_eq!(points[4].registers.rax, start_rsp);
        assert_eq!(points[4].registers.rsp, start_rsp);
        assert_eq!(points[5].registers.rsp, loaded);
        assert_eq!(points[6].registers.rsp, loaded + 8);
        assert_eq!(points[6].registers.rdx, 0x5a5a_5a5a_5a5a_5a5a);
        trace
    }).collect();
    let (image, needed) = emit(&oracle, &pages, &code, body.len(), &heads, &selected);
    redirect(&oracle, &image, 0);
    let log = HookEventLog::new();
    for trace in originals {
        let expected = events(&oracle, &trace.baseline.points, image.observation_pcs(), needed);
        assert_eq!(expected, [event(base + WINDOW as u64, start_rsp),
            event(base + WINDOW as u64 + 1, start_rsp - 8), event(base + WINDOW as u64 + 2, start_rsp),
            event(base + WINDOW as u64 + 3, loaded)]);
        oracle.assert_trace(&trace, base, &map(&oracle, &image, body.len()), &[],
            Some(HookExpectation { log: &log, enabled: &expected }));
    }
}

pub fn later_operand_fault() {
    let body = [0x58, 0x5b, 0x59, 0x90, 0x90]; // third POP faults, no commit
    let heads = [0, 1, 2, 3, 4];
    let selected = [0, 1, 2];
    let code = fixture(&body, 0, 16);
    let (mut oracle, pages) = NativeOracle::with_adjacent_code_mappings(&code, &[PAGE, PAGE]);
    assert_eq!(oracle.stack.len, STACK_BYTES + PAGE);
    let guard = Mapping {
        // SAFETY: transfer the owned final page without creating a mapping hole.
        address: unsafe { oracle.stack.address.add(STACK_BYTES) }, len: PAGE,
    };
    oracle.stack.len = STACK_BYTES;
    oracle.initial_rsp = guard.address();
    assert_eq!(oracle.stack.address() + oracle.stack.len as u64, guard.address());
    guard.protect(libc::PROT_NONE);
    let base = oracle.code.address();
    let path = [base, base + 5, base + WINDOW as u64, base + WINDOW as u64 + 1, base + WINDOW as u64 + 2];
    let originals: Vec<_> = SEEDS.iter().map(|seed| {
        let original = oracle.original_fault(&path, *seed, (libc::SIGSEGV, 2, guard.address()));
        let points = &original.points;
        assert_eq!(points[2].registers.rsp, guard.address() - 16);
        assert_eq!(points[3].registers.rsp, guard.address() - 8);
        assert_eq!(points[4].registers.rsp, guard.address());
        assert_eq!(points[3].registers.rax, 0x5a5a_5a5a_5a5a_5a5a);
        // The second word is the constructor's literal return address.
        assert_eq!(points[4].registers.rbx, oracle.return_pc());
        assert_state(points.last().unwrap(), &original.fault.as_ref().unwrap().state);
        original
    }).collect();
    let (image, needed) = emit(&oracle, &pages, &code, body.len(), &heads, &selected);
    redirect(&oracle, &image, 0);
    let log = HookEventLog::new();
    let boundaries = map(&oracle, &image, body.len()).boundaries;
    for original in originals {
        let expected = events(&oracle, &original.points, image.observation_pcs(), needed);
        assert_eq!(expected, [event(path[2], guard.address() - 16),
            event(path[3], guard.address() - 8), event(path[4], guard.address())]);
        let _active = log.activate();
        oracle.assert_patched_inspecting(&original, base, &boundaries, &[], |child| {
            log.assert_events(child, &expected);
        });
    }
}
