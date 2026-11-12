//! JIT vs O1 ptrace oracle cross-checks with full normalized
//! architectural-state equality. One sequential test: the JIT
//! fault path uses process-global dispatcher state (P1a
//! single-threaded envelope), so cases must not run concurrently.

use liteinst_jit::exec::{Executable, Outcome, ProcessMemory, RunError};
use liteinst_jit::fixtures;
use liteinst_jit::handler::CaptureHandler;
use liteinst_jit::harness::{GuardedDst, MappedGuest, RETURN_SENTINEL};
use liteinst_jit::o1::OracleOutcome;
use liteinst_jit::types::{CountProfile, Generation};
use liteinst_jit::{GuestState, Refuse};

#[path = "common/deadline.rs"]
mod deadline;

const CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-o1-child");
const STATUS_MASK: u64 = 0xcd5; // OF|DF|SF|ZF|AF|PF|CF

struct JitResult {
    outcome: Result<Outcome, RunError>,
    written: Vec<u8>,
    dst: Vec<u8>,
    data_bytes: Vec<u8>,
    stack_window: Vec<u8>,
    base: u64,
    stack_top: u64,
    dst_ptr: u64,
    ranges: [(u64, u64); 4],
}

fn ranges_of(base: u64, data: u64, dst: u64, src: u64, buf_len: u64) -> [(u64, u64); 4] {
    [(base, 4096), (data, 128), (dst, buf_len), (src, buf_len)]
}

fn norm(v: u64, ranges: &[(u64, u64); 4]) -> u64 {
    for (i, &(base, len)) in ranges.iter().enumerate() {
        // Inclusive: a one-past-end pointer is the same identity.
        if v >= base && v <= base + len {
            return (((i as u64) + 1) << 56) | (v - base);
        }
    }
    // Guarded dst writes end at a page boundary: the byte just
    // past the writable tail is a pointer identity too.
    v
}

fn run_jit(name: &str, tweak: impl FnOnce(&mut GuestState)) -> JitResult {
    let fixture = fixtures::by_name(name);
    run_jit_bytes(name, &fixture.bytes, true, tweak)
}

fn run_jit_bytes(
    name: &str,
    bytes: &[u8],
    use_args: bool,
    tweak: impl FnOnce(&mut GuestState),
) -> JitResult {
    let guest = MappedGuest::map(bytes).expect("map");
    guest.plant_below_rsp(liteinst_jit::harness::REDZONE_MARKER);
    let region = guest.region(bytes, Generation(1));
    let mut exec = Executable::prepare(&region, guest.base, CountProfile::BranchesAndInstructions)
        .expect("prepare");
    let data: Vec<u64> = (0..16).collect();
    let mut dst = vec![0u8; 8192];
    let src: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
    let guarded = (name == "rep_stosb_partial").then(|| GuardedDst::new().expect("guarded dst"));
    let mut state = guest.initial_state();
    if use_args {
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
    }
    if let Some(g) = &guarded {
        state.rdi = g.ptr;
    }
    tweak(&mut state);
    let ranges = ranges_of(
        guest.base,
        data.as_ptr() as u64,
        guarded
            .as_ref()
            .map_or(dst.as_ptr() as u64, |g| g.ptr - 4080),
        src.as_ptr() as u64,
        8192,
    );
    let mut handler = CaptureHandler::default();
    let outcome = exec.run(state, &mut handler, &ProcessMemory, RETURN_SENTINEL);
    let dst_out = match &guarded {
        Some(g) => g.head16(),
        None => dst[..32].to_vec(),
    };
    let data_bytes = data.iter().flat_map(|v| v.to_le_bytes()).collect();
    let stack_window = guest.stack_window();
    JitResult {
        outcome,
        written: handler.written,
        dst: dst_out,
        data_bytes,
        stack_window,
        base: guest.base,
        stack_top: guest.stack_top(),
        dst_ptr: guarded.as_ref().map_or(dst.as_ptr() as u64, |g| g.ptr),
        ranges,
    }
}

/// Full normalized state equality: every GPR (pointer-normalized),
/// RSP delta, status flags, RIP offset, data, and stack window.
fn assert_full_state(name: &str, jit: &Outcome, jr: &JitResult, o1: &OracleOutcome) {
    assert_eq!(jit.branches, o1.branches, "{name}: branches");
    assert_eq!(jit.instructions, o1.instructions, "{name}: instructions");
    let o1_ranges = ranges_of(o1.info.base, o1.info.data, o1.info.dst, o1.info.src, 32);
    let regs: [(&str, u64, u64); 15] = [
        ("rax", jit.state.rax, o1.state.rax),
        ("rbx", jit.state.rbx, o1.state.rbx),
        ("rcx", jit.state.rcx, o1.state.rcx),
        ("rdx", jit.state.rdx, o1.state.rdx),
        ("rsi", jit.state.rsi, o1.state.rsi),
        ("rdi", jit.state.rdi, o1.state.rdi),
        ("rbp", jit.state.rbp, o1.state.rbp),
        ("r8", jit.state.r8, o1.state.r8),
        ("r9", jit.state.r9, o1.state.r9),
        ("r10", jit.state.r10, o1.state.r10),
        ("r11", jit.state.r11, o1.state.r11),
        ("r12", jit.state.r12, o1.state.r12),
        ("r13", jit.state.r13, o1.state.r13),
        ("r14", jit.state.r14, o1.state.r14),
        ("r15", jit.state.r15, o1.state.r15),
    ];
    // The guarded-dst pointer identity differs in kind (JIT ranges
    // anchor it 4080 early); skip pointer regs for that fixture and
    // compare its fault state separately.
    for (r, jv, ov) in regs {
        if name == "rep_stosb_partial" && (r == "rdi" || r == "rsi") {
            continue;
        }
        // Only a stepped syscall leaves the tracer's TF in the
        // kernel-saved R11 flags image; mask TF there and nowhere
        // else (ordinary R11 data compares exactly, bit 8 too).
        let (jv, ov) = if r == "r11" && name == "syscall_write" {
            (jv & !0x100, ov & !0x100)
        } else {
            (jv, ov)
        };
        assert_eq!(
            norm(jv, &jr.ranges),
            norm(ov, &o1_ranges),
            "{name}: register {r} (jit {jv:#x} vs o1 {ov:#x})"
        );
    }
    assert_eq!(
        jit.state.rsp as i64 - jr.stack_top as i64,
        o1.state.rsp as i64 - o1.stack_top as i64,
        "{name}: rsp delta"
    );
    assert_eq!(
        jit.state.rflags & STATUS_MASK,
        o1.state.rflags & STATUS_MASK,
        "{name}: status flags"
    );
    assert_eq!(jit.state.rip, o1.state.rip, "{name}: rip (sentinel)");
    assert_eq!(jr.data_bytes, o1.data_bytes, "{name}: data buffer");
    let norm_window = |w: &[u8], ranges: &[(u64, u64); 4]| -> Vec<u64> {
        w.as_chunks::<8>()
            .0
            .iter()
            .map(|c| norm(u64::from_le_bytes(*c), ranges))
            .collect()
    };
    assert_eq!(
        norm_window(&jr.stack_window, &jr.ranges),
        norm_window(&o1.stack_window, &o1_ranges),
        "{name}: stack window (incl. red zone)"
    );
}

fn off(pc: u64, base: u64) -> u64 {
    assert!(
        pc >= base && pc < base + 4096,
        "pc {pc:#x} outside source range from {base:#x}"
    );
    pc - base
}

fn compare(name: &str) -> (Outcome, OracleOutcome) {
    let jr = run_jit(name, |_| {});
    let out = jr
        .outcome
        .as_ref()
        .unwrap_or_else(|e| panic!("{name} jit: {e:?}"))
        .clone();
    let o1 = deadline::o1(CHILD, name, |_, _| {});
    assert_eq!(o1.fault, None, "{name}: oracle faulted");
    assert_full_state(name, &out, &jr, &o1);
    (out, o1)
}

#[test]
fn jit_matches_o1_oracle_on_corpus_v1() {
    let _bound = deadline::TestBound::arm();
    // Oracle self-check against hand-computed counts (an off-by-one
    // oracle must fail here, not silently agree with a wrong JIT).
    let o1 = deadline::o1(CHILD, "sum_loop", |_, _| {});
    assert_eq!(o1.branches, 17);
    assert_eq!(o1.instructions, 2 + 16 * 5 + 2 + 1);
    assert_eq!(o1.state.rax, 120);

    for name in [
        "sum_loop",
        "branchy_even_sum",
        "flags_adc",
        "call_helper",
        "rip_data",
        "rep_movsb",
        "rep_zero",
        "rep_movsw_prefix",
        "loop_insn",
        "jrcxz",
        "syscall_write",
        "cpuid_leaf",
        "compiled_c",
        "redzone_reentry",
        "ret_imm16",
        "loopne_insn",
        "loope_insn",
        "rep_stosb_ok",
        "repne_scasb",
        "rep_lodsq",
        "r11_data",
    ] {
        let (jit, _o1) = compare(name);
        match name {
            "sum_loop" | "call_helper" => {
                assert_eq!(jit.state.rax, if name == "sum_loop" { 120 } else { 121 })
            }
            "branchy_even_sum" => assert_eq!(jit.state.rax, 56),
            "compiled_c" => assert_eq!(jit.state.rax as i64, 64 - 8),
            "rip_data" => assert_eq!(jit.state.rax, 42),
            "loop_insn" => assert_eq!(jit.state.rax, 7),
            "jrcxz" => assert_eq!(jit.state.rax, 2),
            "r11_data" => assert_eq!(jit.state.rax, 0x100),
            "redzone_reentry" => assert_eq!(jit.state.rax, 0, "red-zone marker disturbed"),
            "ret_imm16" => {}
            _ => {}
        }
    }

    // T6 executed width assertion: MOV + completed REP LODSQ +
    // RET is exactly 3 retired instructions on both engines.
    {
        let (jit, o1) = compare("rep_lodsq");
        assert_eq!(jit.instructions, 3, "jit rep lodsq count");
        assert_eq!(o1.instructions, 3, "o1 rep lodsq count");
        assert_eq!(jit.state.rax, o1.state.rax);
    }

    // rep buffers and captured writes, byte-exact.
    for name in ["rep_movsb", "rep_zero", "rep_movsw_prefix"] {
        let jr = run_jit(name, |_| {});
        assert!(jr.outcome.is_ok(), "{name}");
        let o1 = deadline::o1(CHILD, name, |_, _| {});
        assert_eq!(jr.dst, o1.dst_bytes, "{name} dst");
    }
    {
        let jr = run_jit("syscall_write", |_| {});
        let o1 = deadline::o1(CHILD, "syscall_write", |_, _| {});
        assert_eq!(jr.written, o1.stdout_tail);
        assert_eq!(jr.written.len(), 5);
    }

    // flags_adc taken path, with instruction equality too.
    {
        let jr = run_jit("flags_adc", |s| {
            s.rdi = 5;
            s.rsi = 5;
        });
        let out = jr.outcome.as_ref().expect("flags_adc taken").clone();
        let o1 = deadline::o1(CHILD, "flags_adc", |r, _| {
            r.rdi = 5;
            r.rsi = 5;
        });
        assert_eq!(out.state.rax, 110);
        assert_full_state("flags_adc(taken)", &out, &jr, &o1);
    }
    // jrcxz not-taken path.
    {
        let jr = run_jit("jrcxz", |s| s.rcx = 9);
        let out = jr.outcome.as_ref().expect("jrcxz nonzero").clone();
        assert_eq!(out.state.rax, 1);
        let o1 = deadline::o1(CHILD, "jrcxz", |r, _| r.rcx = 9);
        assert_full_state("jrcxz(nonzero)", &out, &jr, &o1);
    }
    // rep_zero with a nonzero count as well as zero.
    {
        let jr = run_jit("rep_zero", |s| s.rdx = 5);
        let out = jr.outcome.as_ref().expect("rep_zero 5").clone();
        let o1 = deadline::o1(CHILD, "rep_zero", |r, _| r.rdx = 5);
        assert_full_state("rep_zero(5)", &out, &jr, &o1);
        assert_eq!(jr.dst[..5], o1.dst_bytes[..5]);
    }

    // Exhaustive Jcc: every condition code, short and near
    // encodings, six flag-setting operand pairs, exact counts.
    let pairs: [(u64, u64); 7] = [
        (1, 2),
        (2, 1),
        (1, 1),
        (u64::MAX, 1),
        (1, u64::MAX),
        (0x8000_0000, 1),
        (0x7fff_ffff, 0xffff_ffff),
    ];
    let mut jcc_seen: std::collections::HashMap<(u8, bool), std::collections::HashSet<u64>> =
        std::collections::HashMap::new();
    for cc in 0u8..16 {
        for near in [false, true] {
            let bytes: Vec<u8> = if near {
                let mut v = vec![0x39, 0xf7, 0x0f, 0x80 + cc, 6, 0, 0, 0];
                v.extend_from_slice(&[0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3]);
                v
            } else {
                vec![
                    0x39,
                    0xf7,
                    0x70 + cc,
                    6,
                    0xb8,
                    0,
                    0,
                    0,
                    0,
                    0xc3,
                    0xb8,
                    1,
                    0,
                    0,
                    0,
                    0xc3,
                ]
            };
            for &(a, b) in &pairs {
                let jr = run_jit_bytes("jcc_gen", &bytes, false, |s| {
                    s.rdi = a;
                    s.rsi = b;
                });
                let out = jr
                    .outcome
                    .as_ref()
                    .unwrap_or_else(|e| panic!("jcc cc={cc} near={near} ({a},{b}): {e:?}"))
                    .clone();
                let o1 = deadline::o1_bytes(CHILD, &bytes, |r, _| {
                    r.rdi = a;
                    r.rsi = b;
                });
                assert_eq!(o1.fault, None, "jcc cc={cc}");
                assert_eq!(out.branches, 1, "jcc cc={cc} branches");
                assert_full_state("jcc_gen", &out, &jr, &o1);
                jcc_seen
                    .entry((cc, near))
                    .or_default()
                    .insert(out.state.rax);
            }
        }
    }

    for cc in 0u8..16 {
        for near in [false, true] {
            let seen = &jcc_seen[&(cc, near)];
            assert!(
                seen.contains(&0) && seen.contains(&1),
                "jcc cc={cc} near={near} outcomes {seen:?} (want both taken and not)"
            );
        }
    }

    // Faulting load: same faulting instruction, counts, and state.
    {
        let jr = run_jit("fault_load", |s| s.rdi = 0x0dea_d000);
        let f = match jr.outcome {
            Err(RunError::Fault(f)) => f,
            other => panic!("fault_load jit: {other:?}"),
        };
        let o1 = deadline::o1(CHILD, "fault_load", |r, _| {
            r.rdi = 0x0dea_d000;
        });
        let (o1_pc, o1_sig) = o1.fault.expect("oracle fault");
        assert_eq!(o1_sig, f.signum);
        assert_eq!(f.branches, o1.branches);
        assert_eq!(f.instructions, o1.instructions);
        assert_eq!(f.branches, 3);
        assert_eq!(
            off(f.src_pc, jr.base),
            off(o1_pc, o1.base),
            "fault pc offset"
        );
        assert_eq!(f.state.rcx, o1.state.rcx);
        assert_eq!(f.state.rdi, o1.state.rdi);
        assert_eq!(f.kind, liteinst_jit::exec::FaultKind::GuestFault);
    }
    // DIV by zero: SIGFPE on both engines, div not retired.
    {
        let jr = run_jit("div_zero", |_| {});
        let f = match jr.outcome {
            Err(RunError::Fault(f)) => f,
            other => panic!("div_zero jit: {other:?}"),
        };
        assert_eq!(f.signum, libc::SIGFPE);
        assert_eq!(f.instructions, 3);
        // R3: SIGFPE si_addr is an instruction address and must be
        // reported as the source PC, never the cache PC.
        assert_eq!(f.addr, f.src_pc, "div fault addr is source pc");
        assert_eq!(off(f.addr, jr.base), 9, "div offset");
        let o1 = deadline::o1(CHILD, "div_zero", |_, _| {});
        assert_eq!(o1.fault.map(|x| x.1), Some(libc::SIGFPE));
        assert_eq!(o1.instructions, 3);
        assert_eq!(off(o1.fault_addr, o1.base), 9, "o1 div addr offset");
    }
    // REP STOSB partial progress into a guard page: 16 bytes land,
    // RCX/RDI stop exactly at the boundary on both engines.
    {
        let jr = run_jit("rep_stosb_partial", |_| {});
        let f = match jr.outcome {
            Err(RunError::Fault(f)) => f,
            other => panic!("rep partial jit: {other:?}"),
        };
        assert_eq!(f.instructions, 2, "mov+mov retired, rep did not");
        assert_eq!(f.state.rcx, 48, "64-16 iterations remain");
        assert_eq!(f.state.rdi - jr.dst_ptr, 16, "destination advanced 16");
        assert_eq!(f.addr - jr.dst_ptr, 16, "fault at guard boundary");
        assert_eq!(jr.dst, vec![0x5au8; 16]);
        let o1 = deadline::o1(CHILD, "rep_stosb_partial", |_, _| {});
        assert_eq!(o1.fault.map(|x| x.1), Some(f.signum));
        assert_eq!(o1.instructions, 2);
        assert_eq!(o1.state.rcx, 48);
        assert_eq!(o1.state.rdi - o1.info.dst, 16);
        assert_eq!(o1.state.rsi, f.state.rsi);
        assert_eq!(o1.state.rflags & STATUS_MASK, f.state.rflags & STATUS_MASK);
        assert_eq!(o1.fault_addr - o1.info.dst, 16);
        assert_eq!(o1.dst_bytes, jr.dst);
    }
    // Faulting call store: exact pre-call state (external review F1 shape).
    {
        let jr = run_jit("call_store_fault", |s| {
            s.rax = 0x1122_3344_5566_7788;
            s.rdi = s.rip + 16;
        });
        let f = match jr.outcome {
            Err(RunError::Fault(f)) => f,
            other => panic!("call_store_fault jit: {other:?}"),
        };
        assert_eq!(f.state.rax, 0x1122_3344_5566_7788);
        assert_eq!(f.state.rsp - jr.base, 16);
        assert_eq!(off(f.src_pc, jr.base), 3);
        assert_eq!(f.instructions, 1);
        let o1 = deadline::o1(CHILD, "call_store_fault", |r, info| {
            r.rax = 0x1122_3344_5566_7788;
            r.rdi = info.base + 16;
        });
        let (o1_pc, _) = o1.fault.expect("o1 call fault");
        assert_eq!(o1.instructions, 1);
        assert_eq!(o1.state.rax, f.state.rax);
        assert_eq!(o1.state.rsp - o1.base, 16);
        assert_eq!(off(o1_pc, o1.base), 3);
    }
    // Faulting return stack read: only the mov retired (F3).
    {
        let jr = run_jit("fault_ret", |s| s.rdi = 0x0dea_d000);
        let f = match jr.outcome {
            Err(RunError::Fault(f)) => f,
            other => panic!("fault_ret jit: {other:?}"),
        };
        assert_eq!(f.instructions, 1);
        assert_eq!(f.state.rsp, 0x0dea_d000);
        let o1 = deadline::o1(CHILD, "fault_ret", |r, _| {
            r.rdi = 0x0dea_d000;
        });
        assert_eq!(o1.instructions, 1);
        assert_eq!(o1.fault.map(|x| x.1), Some(f.signum));
    }
    // R2: guest DF is preserved in saved state while host handler
    // code observes DF clear at its first instruction.
    {
        struct DfProbe {
            host_flags: u64,
            guest_flags: u64,
            inner: CaptureHandler,
        }
        impl liteinst_jit::exec::Handler for DfProbe {
            fn syscall(
                &mut self,
                state: &mut GuestState,
                insn_pc: u64,
                next_pc: u64,
            ) -> Result<liteinst_jit::exec::Resume, Refuse> {
                self.inner.syscall(state, insn_pc, next_pc)
            }
            fn nondet(
                &mut self,
                state: &mut GuestState,
                kind: liteinst_jit::decode::NondetKind,
                insn_pc: u64,
                next_pc: u64,
            ) -> Result<liteinst_jit::exec::Resume, Refuse> {
                let flags: u64;
                // SAFETY: pushfq/pop only reads flags into a register.
                unsafe {
                    core::arch::asm!("pushfq; pop {}", out(reg) flags);
                }
                self.host_flags = flags;
                self.guest_flags = state.rflags;
                self.inner.nondet(state, kind, insn_pc, next_pc)
            }
        }
        let fixture = fixtures::by_name("std_cld");
        let guest = MappedGuest::map(&fixture.bytes).expect("map");
        let region = guest.region(&fixture.bytes, Generation(1));
        let mut exec =
            Executable::prepare(&region, guest.base, CountProfile::Branches).expect("prepare");
        let state = guest.initial_state();
        let mut probe = DfProbe {
            host_flags: u64::MAX,
            guest_flags: 0,
            inner: CaptureHandler::default(),
        };
        let out = exec
            .run(state, &mut probe, &ProcessMemory, RETURN_SENTINEL)
            .expect("std_cld run");
        assert_eq!(probe.host_flags & 0x400, 0, "host DF clear in handler");
        assert_ne!(probe.guest_flags & 0x400, 0, "guest DF preserved in state");
        assert_eq!(out.state.rflags & 0x400, 0, "guest executed its cld");
        let _ = compare("std_cld");
    }

    // Oracle trap provenance: a native int3 is a guest trap, not a
    // completed step; the JIT refuses int3 at translation (F4).
    {
        let o1 = deadline::o1(CHILD, "int3_trap", |_, _| {});
        assert_eq!(o1.fault, Some((o1.base, libc::SIGTRAP)));
        assert_eq!(o1.instructions, 0);
        let fixture = fixtures::by_name("int3_trap");
        let guest = MappedGuest::map(&fixture.bytes).expect("map");
        let region = guest.region(&fixture.bytes, Generation(1));
        assert!(matches!(
            Executable::prepare(&region, guest.base, CountProfile::Branches),
            Err(Refuse::Unrelocatable { .. })
        ));
    }
    // Reference handler serves CPUID only, by identity (F6).
    {
        let jr = run_jit("rdtsc_exit", |_| {});
        assert!(matches!(
            jr.outcome,
            Err(RunError::Refuse(Refuse::NoHandler { .. }))
        ));
    }
    // A fault before a block's conditional branch credits no
    // branch. The native arm runs first so a JIT-side failure
    // (e.g. mutant 05) can never suppress the oracle comparison.
    {
        let o1 = deadline::o1(CHILD, "fault_before_branch", |r, _| {
            r.rdi = 0x0dea_d000;
        });
        assert_eq!(o1.branches, 0, "native arm branches");
        assert_eq!(o1.instructions, 0, "native arm instructions");
        let jr = run_jit("fault_before_branch", |s| s.rdi = 0x0dea_d000);
        let f = match jr.outcome {
            Err(RunError::Fault(f)) => f,
            other => panic!("fault_before_branch jit: {other:?}"),
        };
        assert_eq!(f.branches, o1.branches, "fault_before_branch branches");
        assert_eq!(f.instructions, o1.instructions);
    }

    // T7 live: a store whose target numerically equals its own
    // generated PC keeps the raw data address (no fetch bit).
    {
        let bytes = [0x89u8, 0x07, 0xc3]; // mov [rdi],eax; ret
        let guest = MappedGuest::map(&bytes).expect("map");
        guest.plant_below_rsp(liteinst_jit::harness::REDZONE_MARKER);
        let region = guest.region(&bytes, Generation(1));
        let mut exec =
            Executable::prepare(&region, guest.base, CountProfile::Branches).expect("prepare");
        let gen_mov = exec
            .translation()
            .pcmap
            .entries()
            .iter()
            .find(|e| e.src_pc == guest.base && e.phase == liteinst_jit::Phase::Copied)
            .map(|e| e.gen_start)
            .expect("copied mov entry");
        let mut state = guest.initial_state();
        state.rdi = gen_mov;
        let mut handler = CaptureHandler::default();
        let out = exec.run(state, &mut handler, &ProcessMemory, RETURN_SENTINEL);
        let f = match out {
            Err(RunError::Fault(f)) => f,
            other => panic!("data_addr jit: {other:?}"),
        };
        assert_eq!(f.addr, gen_mov, "data address preserved raw");
        assert_eq!(f.src_pc, guest.base);
        assert_eq!(f.kind, liteinst_jit::exec::FaultKind::GuestFault);
    }

    // Indirect call and jump-table edges refuse by name too.
    for name in ["indirect_call", "jump_table"] {
        let jr = run_jit(name, |_| {});
        assert!(
            matches!(
                jr.outcome,
                Err(RunError::Refuse(Refuse::IndirectUnresolved { .. }))
            ),
            "{name}: {:?}",
            jr.outcome
        );
    }
    // RIP-relative store faults identically on the RX guest page.
    {
        let jr = run_jit("rip_store_fault", |s| s.rdi = 0x2a);
        let f = match jr.outcome {
            Err(RunError::Fault(f)) => f,
            other => panic!("rip_store_fault jit: {other:?}"),
        };
        assert_eq!(f.instructions, 0);
        assert_eq!(off(f.addr, jr.base), 15);
        let o1 = deadline::o1(CHILD, "rip_store_fault", |r, _| {
            r.rdi = 0x2a;
        });
        assert_eq!(o1.instructions, 0);
        assert_eq!(off(o1.fault_addr, o1.base), 15);
        assert_eq!(o1.fault.map(|x| x.1), Some(f.signum));
    }

    // Indirect control flow refuses by name (P1a boundary).
    {
        let jr = run_jit("indirect_jmp", |_| {});
        assert!(matches!(
            jr.outcome,
            Err(RunError::Refuse(Refuse::IndirectUnresolved { .. }))
        ));
    }
    // Invalidation: after invalidate(), running refuses stale.
    {
        let fixture = fixtures::by_name("sum_loop");
        let guest = MappedGuest::map(&fixture.bytes).expect("map");
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
    // R5 progress bound: a pending async signal stops a long
    // in-cache loop at a poll exit instead of being deferred
    // until the (effectively unbounded) run returns.
    {
        let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
        let mut old: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        }
        let me = unsafe { libc::pthread_self() };
        let killer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            unsafe {
                libc::pthread_kill(me, libc::SIGUSR1);
            }
        });
        let jr = run_jit("loop_insn", |s| s.rsi = 400_000_000);
        killer.join().expect("killer thread");
        match jr.outcome {
            Err(RunError::Fault(f)) => {
                assert_eq!(f.kind, liteinst_jit::exec::FaultKind::AsyncSignal);
                assert_eq!(f.signum, libc::SIGUSR1);
                assert!(f.branches > 0 && f.branches < 400_000_000, "{f:?}");
            }
            other => panic!("poll async outcome: {other:?}"),
        }
        // Consume the pending signal while still blocked, then restore.
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::sigtimedwait(&set, &mut info, &ts);
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, core::ptr::null_mut());
        }
    }

    // T1/T2/T3 signal-envelope regressions.
    {
        extern "C" fn noop_handler(_sig: i32) {}
        let rt = libc::SIGRTMIN();
        // Installed RT handler must refuse admission by name.
        let mut act: libc::sigaction = unsafe { core::mem::zeroed() };
        act.sa_sigaction = noop_handler as *const () as usize;
        let mut prev: libc::sigaction = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::sigaction(rt, &act, &mut prev) }, 0);
        let jr = run_jit("sum_loop", |_| {});
        assert!(
            matches!(
                jr.outcome,
                Err(RunError::Refuse(Refuse::SignalOwnership { signum, .. })) if signum == rt
            ),
            "rt admission: {:?}",
            jr.outcome
        );
        assert_eq!(
            unsafe { libc::sigaction(rt, &prev, core::ptr::null_mut()) },
            0
        );

        // Pending RT signal is found by the poll (full range).
        let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
        let mut old: libc::sigset_t = unsafe { core::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, rt);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
            libc::raise(rt);
        }
        let jr = run_jit("loop_insn", |s| s.rsi = 400_000_000);
        match jr.outcome {
            Err(RunError::Fault(f)) => {
                assert_eq!(f.kind, liteinst_jit::exec::FaultKind::AsyncSignal);
                assert_eq!(f.signum, rt, "rt pending signum");
            }
            other => panic!("rt pending outcome: {other:?}"),
        }
        // T2: CPUID exits must not renew the poll budget.
        unsafe {
            libc::raise(libc::SIGUSR1);
        }
        let jr = run_jit("cpuid_loop", |_| {});
        match jr.outcome {
            Err(RunError::Fault(f)) => {
                assert_eq!(f.kind, liteinst_jit::exec::FaultKind::AsyncSignal);
                assert_eq!(f.signum, libc::SIGUSR1);
                assert!(f.branches < 20_000, "cpuid loop stopped early: {f:?}");
            }
            other => panic!("pending_cpuid outcome: {other:?}"),
        }
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::sigtimedwait(&set, &mut info, &ts);
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, core::ptr::null_mut());
        }
    }
    // T3: an originally unblocked default-terminate signal must
    // return as AsyncSignal, not kill the caller on mask restore.
    {
        unsafe {
            libc::signal(libc::SIGUSR1, libc::SIG_DFL);
        }
        let me = unsafe { libc::pthread_self() };
        let killer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            unsafe {
                libc::pthread_kill(me, libc::SIGUSR1);
            }
        });
        let jr = run_jit("loop_insn", |s| s.rsi = 400_000_000);
        killer.join().expect("killer");
        match jr.outcome {
            Err(RunError::Fault(f)) => {
                assert_eq!(f.kind, liteinst_jit::exec::FaultKind::AsyncSignal);
                assert_eq!(f.signum, libc::SIGUSR1);
            }
            other => panic!("default_stop outcome: {other:?}"),
        }
        // Reaching here at all proves custody: the pending fatal
        // signal was dequeued before the mask was restored.
    }

    // T3 two-signal custody: SIGUSR1+SIGUSR2 both pending and
    // default-disposition; both must be taken into custody and
    // reported, and the caller must survive mask restoration.
    {
        unsafe {
            libc::signal(libc::SIGUSR1, libc::SIG_DFL);
            libc::signal(libc::SIGUSR2, libc::SIG_DFL);
        }
        let me = unsafe { libc::pthread_self() };
        let killer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            unsafe {
                libc::pthread_kill(me, libc::SIGUSR1);
                libc::pthread_kill(me, libc::SIGUSR2);
            }
        });
        let jr = run_jit("loop_insn", |s| s.rsi = 400_000_000);
        killer.join().expect("killer");
        match jr.outcome {
            Err(RunError::Fault(f)) => {
                assert_eq!(f.kind, liteinst_jit::exec::FaultKind::AsyncSignal);
                assert_eq!(f.signum, libc::SIGUSR1, "first custody signal reported");
                assert_eq!(
                    f.also_pending,
                    vec![libc::SIGUSR2],
                    "second pending signal in custody, not delivered"
                );
            }
            other => panic!("two-signal custody outcome: {other:?}"),
        }
        // Reaching here proves neither default signal killed us
        // when run() restored the original (unblocked) mask.
    }

    // Driver binary agrees with its per-fixture expectations (F6).
    {
        let status = deadline::command_status(&mut std::process::Command::new(env!(
            "CARGO_BIN_EXE_liteinst-jit-run"
        )))
        .expect("run driver");
        assert!(status.success(), "driver rc: {status}");
    }
}

/// Spawn census (I1-H H2c): every child this binary starts carries
/// a run deadline (`common/deadline.rs`).
#[test]
fn spawn_census() {
    deadline::spawn_census(include_str!("o1_compare.rs"), "o1_compare.rs");
}

/// Bound census (I1-H H2d): every test here arms a `TestBound`
/// (`common/deadline.rs`).
#[test]
fn bound_census() {
    deadline::bound_census(
        include_str!("o1_compare.rs"),
        "o1_compare.rs",
        &["spawn_census", "bound_census"],
    );
}
