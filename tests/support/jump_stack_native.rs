// Finite ordinary-observer emitter controls, not new admission or a model of
// arbitrary stack instructions. Handwritten opcodes/heads and ISA expectations
// are independent of the scanner/emitter used only to construct each candidate.
use super::*;
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::{HookCallback, HookContext, TrampolineImage, TrampolinePlan};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the active fixture owns the live context and private event log.
    // No allocation, unwinding, stack pivot or application-memory write occurs.
    unsafe {
        let context = &*context;
        record_hook_event(context.stack_pointer, context.instruction_pointer);
        core::arch::asm!(
            "add rax, 1", "pxor xmm0, xmm0", "fninit",
            out("rax") _, out("xmm0") _, options(nostack),
        );
    }
}

fn register(r: &libc::user_regs_struct, number: usize) -> u64 {
    [
        r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12,
        r.r13, r.r14, r.r15,
    ][number]
}

fn expected(before: &Snapshot, pc: u64, rsp: u64, stack: Vec<u8>) -> Snapshot {
    let mut registers = before.registers;
    registers.rip = pc;
    registers.rsp = rsp;
    Snapshot {
        logical_pc: pc,
        registers,
        xstate: before.xstate.clone(),
        data: before.data.clone(),
        application_stack: stack,
    }
}

fn image(
    oracle: &NativeOracle,
    memory: &Mapping,
    code: &[u8],
    hooks: &[u64],
    ordered: bool,
) -> TrampolineImage {
    let base = oracle.code.address();
    let scan = InstructionScanner::default().scan(code, base).unwrap();
    let plan = if ordered {
        let actions: Vec<_> = hooks
            .iter()
            .map(|pc| (*pc, observe as HookCallback, false))
            .collect();
        TrampolinePlan::from_actions(&scan, base, base + 5, &actions).unwrap()
    } else {
        TrampolinePlan::from_scan(&scan, base, observe).unwrap()
    };
    assert_eq!(plan.return_address(), base + 5);
    let image = plan.emit_at(memory.address()).unwrap();
    assert!(image.bytes().len() <= PAGE);
    // The lower guard remains inaccessible. One extra page below the checked
    // context/save extent is reserved for this tiny fixed callback's stack.
    let needed = image.layout().saved_extended_state.len()
        + image
            .layout()
            .observation_stack_profile
            .context_stack_prefix_bytes() as u64
        + PAGE as u64;
    assert!(oracle.initial_rsp - 8 - (oracle.stack.address() + PAGE as u64) > needed);
    memory.protect(libc::PROT_READ | libc::PROT_WRITE);
    memory.initialize(0, &vec![0xcc; PAGE]);
    memory.initialize(0, image.bytes());
    memory.protect(libc::PROT_READ | libc::PROT_EXEC);
    image
}

fn compare(
    oracle: &NativeOracle,
    trace: &NativeTrace,
    image: &TrampolineImage,
    log: &HookEventLog,
    events: &[HookEvent],
) {
    let end = oracle.code.address() + 5;
    let mut boundaries = image.instruction_boundaries().to_vec();
    boundaries.push((end, end));
    oracle.assert_trace(
        trace,
        image.address(),
        &TraceMap {
            boundaries,
            gateways: vec![],
            generated_ranges: std::iter::once(
                image.address()..image.address() + image.bytes().len() as u64,
            )
            .collect(),
        },
        &[],
        Some(HookExpectation {
            log,
            enabled: events,
        }),
    );
}

fn pairs(numbers: std::ops::Range<usize>) {
    for number in numbers {
        // PUSH/POP register opcodes: REX.B selects R8..R15. No decoder supplies
        // the fixture heads or the initial-RSP/old-register expectations.
        let mut code = Vec::new();
        if number >= 8 {
            code.push(0x41);
        }
        code.push(0x50 + (number % 8) as u8);
        let pop = code.len();
        if number >= 8 {
            code.push(0x41);
        }
        code.push(0x58 + (number % 8) as u8);
        let after_pop = code.len();
        code.resize(6, 0x90); // Exact five-byte emitter window, then stopped NOP.
        let (oracle, mappings) = NativeOracle::with_adjacent_code_mappings(&code, &[PAGE]);
        let base = oracle.code.address();
        let mut heads = vec![base, base + pop as u64];
        heads.extend((after_pop..5).map(|n| base + n as u64));
        let log = HookEventLog::new();
        for seed in SEEDS {
            let trace = oracle.trace_original(base, &heads, &[base + 5], seed);
            let points = &trace.baseline.points;
            assert_eq!(points.len(), heads.len() + 1);
            let before = &points[0];
            let old_rsp = before.registers.rsp;
            let value = register(&before.registers, number);
            let mut stack = before.application_stack.clone();
            // The exact pushed word lies 120 bytes into the fixed red-zone
            // snapshot. In particular PUSH RSP stores old_rsp, not old_rsp-8.
            assert_eq!(old_rsp, oracle.initial_rsp);
            stack[120..128].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                u64::from_le_bytes(points[1].application_stack[120..128].try_into().unwrap()),
                value
            );
            if number == 4 {
                assert_eq!(value, old_rsp);
            }
            assert_state(
                &expected(before, base + pop as u64, old_rsp - 8, stack.clone()),
                &points[1],
            );
            // Inspect the intermediate PUSH, not just a cancelling final pair.
            assert_state(
                &expected(before, base + after_pop as u64, old_rsp, stack),
                &points[2],
            );
            for ordered in [false, true] {
                let image = image(
                    &oracle,
                    &mappings[0],
                    &code,
                    &[base, base + pop as u64],
                    ordered,
                );
                let mut events = vec![HookEvent {
                    probe_id: old_rsp,
                    logical_pc: base,
                }];
                if ordered {
                    events.push(HookEvent {
                        probe_id: old_rsp - 8,
                        logical_pc: base + pop as u64,
                    });
                }
                compare(&oracle, &trace, &image, &log, &events);
            }
        }
    }
}

pub fn low_gprs() {
    pairs(0..8);
}
pub fn high_gprs() {
    pairs(8..16);
}

pub fn rsp_loaded_value() {
    let code = [0x5c, 0x90, 0x90, 0x90, 0x90, 0x90]; // POP RSP, stopped after padding.
    let (oracle, mappings) = NativeOracle::with_adjacent_code_mappings(&code, &[PAGE]);
    let base = oracle.code.address();
    let loaded = oracle.initial_rsp + 64;
    assert_ne!(loaded, oracle.initial_rsp + 8);
    oracle.stack.initialize(
        (oracle.initial_rsp - oracle.stack.address()) as usize,
        &loaded.to_le_bytes(),
    );
    let heads: Vec<_> = (0..5).map(|n| base + n).collect();
    let log = HookEventLog::new();
    for seed in SEEDS {
        let trace = oracle.trace_original(base, &heads, &[base + 5], seed);
        let before = &trace.baseline.points[0];
        assert_eq!(
            u64::from_le_bytes(before.application_stack[128..136].try_into().unwrap()),
            loaded
        );
        for point in &trace.baseline.points[1..] {
            assert_state(
                &expected(
                    before,
                    point.logical_pc,
                    loaded,
                    before.application_stack.clone(),
                ),
                point,
            );
        }
        for ordered in [false, true] {
            let image = image(&oracle, &mappings[0], &code, &[base], ordered);
            compare(
                &oracle,
                &trace,
                &image,
                &log,
                &[HookEvent {
                    probe_id: oracle.initial_rsp,
                    logical_pc: base,
                }],
            );
        }
    }
}

pub fn operand_faults() {
    for opcode in [0x50, 0x54, 0x58, 0x5c] {
        // PUSH RAX/RSP; POP RAX/RSP.
        let push = opcode < 0x58;
        let code = [opcode, 0x90, 0x90, 0x90, 0x90, 0x90];
        let (mut oracle, mappings) = NativeOracle::with_adjacent_code_mappings(&code, &[PAGE]);
        let base = oracle.code.address();
        assert_eq!(oracle.stack.len, STACK_BYTES + PAGE);
        // Transfer the upper page to a distinct guard owner without unmapping
        // any hole. The ordinary oracle still compares every byte from
        // initial_rsp-128 to the end of its *mapped application stack*.
        let guard = Mapping {
            // SAFETY: this is the last complete page of the sole owned map.
            address: unsafe { oracle.stack.address.add(STACK_BYTES) },
            len: PAGE,
        };
        oracle.stack.len = STACK_BYTES;
        oracle.initial_rsp = guard.address() + if push { 8 } else { 0 };
        assert_eq!(
            oracle.stack.address() + oracle.stack.len as u64,
            guard.address()
        );
        assert!(oracle.initial_rsp - 128 < guard.address());
        guard.protect(libc::PROT_NONE);
        let log = HookEventLog::new();
        for seed in SEEDS {
            let baseline =
                oracle.original_fault(&[base], seed, (libc::SIGSEGV, 2, guard.address()));
            // Both native operand faults are before architectural commit:
            // every GPR (including destination/RSP), flags, XSAVE and mapped
            // application byte still equals the pre-instruction snapshot.
            assert_state(&baseline.points[0], &baseline.fault.as_ref().unwrap().state);
            for ordered in [false, true] {
                let image = image(&oracle, &mappings[0], &code, &[base], ordered);
                let _active = log.activate();
                oracle.assert_patched_inspecting(
                    &baseline,
                    image.address(),
                    image.instruction_boundaries(),
                    &[],
                    |child| {
                        log.assert_events(
                            child,
                            &[HookEvent {
                                probe_id: oracle.initial_rsp,
                                logical_pc: base,
                            }],
                        )
                    },
                );
            }
        }
    }
}
