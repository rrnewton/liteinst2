//! JIT vs O1 ptrace oracle cross-checks. One sequential test: the
//! JIT fault path uses process-global dispatcher state (P1a
//! single-threaded envelope), so cases must not run concurrently.

use liteinst_jit::exec::{Executable, ProcessMemory, RunError};
use liteinst_jit::fixtures;
use liteinst_jit::handler::CaptureHandler;
use liteinst_jit::harness::{MappedGuest, RETURN_SENTINEL};
use liteinst_jit::o1::{OracleOutcome, run_o1};
use liteinst_jit::types::{CountProfile, Generation};
use liteinst_jit::{GuestState, Refuse};

const CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-o1-child");

struct JitResult {
    outcome: Result<liteinst_jit::exec::Outcome, RunError>,
    written: Vec<u8>,
    dst: Vec<u8>,
    base: u64,
    stack_top: u64,
}

fn run_jit(name: &str, tweak: impl FnOnce(&mut GuestState)) -> JitResult {
    let fixture = fixtures::by_name(name);
    let guest = MappedGuest::map(&fixture.bytes).expect("map");
    guest.plant_below_rsp(liteinst_jit::harness::REDZONE_MARKER);
    let region = guest.region(&fixture.bytes, Generation(1));
    let mut exec = Executable::prepare(&region, guest.base, CountProfile::BranchesAndInstructions)
        .expect("prepare");
    let data: Vec<u64> = (0..16).collect();
    let mut dst = vec![0u8; 32];
    let src: Vec<u8> = (0..32u8).collect();
    let mut state = guest.initial_state();
    let (rdi, rsi, rdx, rax, rcx) = MappedGuest::fixture_args(
        name,
        guest.base,
        data.as_ptr() as u64,
        dst.as_mut_ptr() as u64,
        src.as_ptr() as u64,
    );
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = rax;
    state.rcx = rcx;
    tweak(&mut state);
    let mut handler = CaptureHandler::default();
    let outcome = exec.run(state, &mut handler, &ProcessMemory, RETURN_SENTINEL);
    JitResult {
        outcome,
        written: handler.written,
        dst,
        base: guest.base,
        stack_top: guest.stack_top(),
    }
}

fn compare(name: &str) -> (liteinst_jit::exec::Outcome, OracleOutcome) {
    let jit = run_jit(name, |_| {});
    let out = jit.outcome.unwrap_or_else(|e| panic!("{name} jit: {e:?}"));
    let o1 = run_o1(std::path::Path::new(CHILD), name, |_, _| {});
    assert_eq!(o1.fault, None, "{name}: oracle faulted");
    assert_eq!(out.branches, o1.branches, "{name}: branch count");
    assert_eq!(
        out.instructions, o1.instructions,
        "{name}: instruction count"
    );
    assert_eq!(out.state.rax, o1.state.rax, "{name}: rax");
    if name == "syscall_write" {
        // RCX holds the syscall return address in each engine's own
        // mapping; compare fixture offsets, not absolute values.
        assert_eq!(
            out.state.rcx - jit.base,
            o1.state.rcx - o1.base,
            "{name}: rcx offset"
        );
    } else {
        assert_eq!(out.state.rcx, o1.state.rcx, "{name}: rcx");
    }
    (out, o1)
}

#[test]
fn jit_matches_o1_oracle_on_corpus_v1() {
    // Oracle self-check against hand-computed counts first (the
    // negative control: an off-by-one oracle must fail here, not
    // silently agree with an equally wrong JIT).
    let o1 = run_o1(std::path::Path::new(CHILD), "sum_loop", |_, _| {});
    assert_eq!(o1.branches, 17, "oracle sum_loop branches (n+1 jae)");
    assert_eq!(
        o1.instructions,
        2 + 16 * 5 + 2 + 1,
        "oracle sum_loop instructions"
    );
    assert_eq!(o1.state.rax, 120);

    for name in [
        "sum_loop",
        "branchy_even_sum",
        "flags_adc",
        "call_helper",
        "rip_data",
        "rep_movsb",
        "loop_insn",
        "jrcxz",
        "syscall_write",
        "cpuid_leaf",
    ] {
        let (jit, o1) = compare(name);
        match name {
            "sum_loop" => assert_eq!(jit.state.rax, 120),
            "branchy_even_sum" => assert_eq!(jit.state.rax, 2 + 4 + 6 + 8 + 10 + 12 + 14),
            "call_helper" => assert_eq!(jit.state.rax, 121),
            "rip_data" => assert_eq!(jit.state.rax, 42),
            "loop_insn" => assert_eq!(jit.state.rax, 7),
            "jrcxz" => assert_eq!(jit.state.rax, 2),
            "cpuid_leaf" => {
                assert_eq!(jit.state.rbx, o1.state.rbx, "cpuid rbx");
                assert_eq!(jit.state.rcx, o1.state.rcx, "cpuid rcx");
                assert_eq!(jit.state.rdx, o1.state.rdx, "cpuid rdx");
            }
            _ => {}
        }
    }

    // rep_movsb buffer equivalence (JIT local vs oracle child dst).
    let jit = run_jit("rep_movsb", |_| {});
    assert!(jit.outcome.is_ok());
    let o1 = run_o1(std::path::Path::new(CHILD), "rep_movsb", |_, _| {});
    assert_eq!(jit.dst, o1.dst_bytes);
    assert_eq!(jit.dst, (0..32u8).collect::<Vec<_>>());

    // syscall_write captured bytes equivalence.
    let jit = run_jit("syscall_write", |_| {});
    assert!(jit.outcome.is_ok());
    let o1 = run_o1(std::path::Path::new(CHILD), "syscall_write", |_, _| {});
    assert_eq!(jit.written, o1.stdout_tail);
    assert_eq!(jit.written.len(), 5);

    // flags_adc taken path (equal operands): CF=0, adc adds 100.
    let jit = run_jit("flags_adc", |s| {
        s.rdi = 5;
        s.rsi = 5;
    });
    let out = jit.outcome.expect("flags_adc taken");
    assert_eq!(out.state.rax, 110);
    let o1 = run_o1(std::path::Path::new(CHILD), "flags_adc", |r, _| {
        r.rdi = 5;
        r.rsi = 5;
    });
    assert_eq!(out.branches, o1.branches);
    assert_eq!(out.state.rax, o1.state.rax);

    // jrcxz not-taken path.
    let jit = run_jit("jrcxz", |s| s.rcx = 9);
    let out = jit.outcome.expect("jrcxz nonzero");
    assert_eq!(out.state.rax, 1);
    let o1 = run_o1(std::path::Path::new(CHILD), "jrcxz", |r, _| r.rcx = 9);
    assert_eq!(out.branches, o1.branches);
    assert_eq!(out.instructions, o1.instructions);

    // Fault: both engines must name the same faulting instruction
    // with the same retired counts before it.
    let jit = run_jit("fault_load", |s| s.rdi = 0x0dea_d000);
    let jit_fault = match jit.outcome {
        Err(RunError::Fault(f)) => f,
        other => panic!("fault_load jit: {other:?}"),
    };
    let o1 = run_o1(std::path::Path::new(CHILD), "fault_load", |r, _| {
        r.rdi = 0x0dea_d000;
    });
    let (o1_pc, o1_sig) = o1.fault.expect("oracle fault");
    assert_eq!(jit_fault.signum, o1_sig);
    assert_eq!(jit_fault.branches, o1.branches, "fault branches");
    assert_eq!(
        jit_fault.instructions, o1.instructions,
        "fault instructions"
    );
    assert_eq!(jit_fault.branches, 3);
    // Source PCs differ by load base; compare offsets into fixture.
    assert_eq!(
        jit_fault.src_pc - jit.base,
        o1_pc - o1.base,
        "fault pc offset"
    );

    // F2: entry and re-entry must not write the red zone.
    {
        let (jit, o1) = compare("redzone_reentry");
        assert_eq!(jit.state.rax, 0, "red-zone marker disturbed");
        assert_eq!(o1.state.rax, 0);
    }
    // F3: ret imm16 pops the immediate as well as the return slot.
    {
        let jit = run_jit("ret_imm16", |_| {});
        let out = jit.outcome.expect("ret_imm16 jit");
        assert_eq!(out.state.rsp - jit.stack_top, 24, "jit ret imm16 rsp delta");
        let o1 = run_o1(std::path::Path::new(CHILD), "ret_imm16", |_, _| {});
        assert_eq!(o1.state.rsp - o1.stack_top, 24, "o1 ret imm16 rsp delta");
        assert_eq!(out.instructions, o1.instructions);
        assert_eq!(out.branches, o1.branches);
    }
    // F3: a faulting return stack read retires only prior insns.
    {
        let jit = run_jit("fault_ret", |s| s.rdi = 0x0dea_d000);
        let f = match jit.outcome {
            Err(RunError::Fault(f)) => f,
            other => panic!("fault_ret jit: {other:?}"),
        };
        assert_eq!(f.instructions, 1, "only the mov retired");
        assert_eq!(f.branches, 0);
        assert_eq!(f.state.rsp, 0x0dea_d000);
        let o1 = run_o1(std::path::Path::new(CHILD), "fault_ret", |r, _| {
            r.rdi = 0x0dea_d000;
        });
        assert_eq!(o1.instructions, 1);
        assert_eq!(o1.branches, 0);
        let (o1_pc, o1_sig) = o1.fault.expect("o1 fault_ret fault");
        assert_eq!(o1_sig, f.signum);
        assert_eq!(f.src_pc - jit.base, o1_pc - o1.base);
    }
    // F6: the reference handler serves CPUID only, by identity.
    {
        let jit = run_jit("rdtsc_exit", |_| {});
        assert!(matches!(
            jit.outcome,
            Err(RunError::Refuse(Refuse::NoHandler { .. }))
        ));
    }

    // F1: fault on the call sequence's own stack store recovers
    // the exact pre-call state (Astra counterexample shape).
    {
        let jit = run_jit("call_store_fault", |s| {
            s.rax = 0x1122_3344_5566_7788;
            s.rdi = s.rip + 16; // inside the RX code page
        });
        let f = match jit.outcome {
            Err(RunError::Fault(f)) => f,
            other => panic!("call_store_fault jit: {other:?}"),
        };
        assert_eq!(f.state.rax, 0x1122_3344_5566_7788, "pre-call rax");
        assert_eq!(f.state.rsp - jit.base, 16, "pre-call rsp");
        assert_eq!(f.src_pc - jit.base, 3, "call pc offset");
        assert_eq!(f.instructions, 1, "only the mov retired");
        let o1 = run_o1(
            std::path::Path::new(CHILD),
            "call_store_fault",
            |r, info| {
                r.rax = 0x1122_3344_5566_7788;
                r.rdi = info.base + 16;
            },
        );
        let (o1_pc, o1_sig) = o1.fault.expect("o1 call fault");
        assert_eq!(o1_sig, f.signum);
        assert_eq!(o1.instructions, 1);
        assert_eq!(o1.state.rax, f.state.rax);
        assert_eq!(o1.state.rsp - o1.base, f.state.rsp - jit.base);
        assert_eq!(o1_pc - o1.base, 3);
    }

    // Indirect control flow refuses by name (P1a boundary).
    let jit = run_jit("indirect_jmp", |_| {});
    assert!(matches!(
        jit.outcome,
        Err(RunError::Refuse(Refuse::IndirectUnresolved { .. }))
    ));

    // Invalidation: after invalidate(), running refuses stale.
    let fixture = fixtures::by_name("sum_loop");
    let guest = MappedGuest::map(&fixture.bytes).expect("map");
    guest.plant_below_rsp(liteinst_jit::harness::REDZONE_MARKER);
    let region = guest.region(&fixture.bytes, Generation(1));
    let mut exec =
        Executable::prepare(&region, guest.base, CountProfile::Branches).expect("prepare");
    let dropped = exec
        .invalidate(guest.base, guest.base + 0x1000, Generation(2))
        .expect("invalidate");
    assert!(dropped >= 1);
    let state = guest.initial_state();
    let mut handler = CaptureHandler::default();
    let r = exec.run(state, &mut handler, &ProcessMemory, RETURN_SENTINEL);
    assert!(matches!(
        r,
        Err(RunError::Refuse(Refuse::StaleGeneration { .. }))
    ));
}
