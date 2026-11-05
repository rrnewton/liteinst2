//! Remote (ptrace) vs in-process differential checks (P1b
//! I1-B): the same direct fixtures must produce exact state
//! and counts through both backends, and synchronous faults
//! must recover identically through the shared recovery core.
//! One sequential test: both backends use process-global
//! ptrace/signal state, so cases must not run concurrently.

use liteinst_jit::exec::{Executable, Fault, Outcome, ProcessMemory, RunError};
use liteinst_jit::fixtures;
use liteinst_jit::handler::CaptureHandler;
use liteinst_jit::harness::{GuardedDst, MappedGuest, RETURN_SENTINEL};
use liteinst_jit::remote::RemoteExecutable;
use liteinst_jit::types::{CountProfile, Generation};
use liteinst_jit::{GuestState, Refuse};

const CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-remote-child");
const STATUS_MASK: u64 = 0xcd5;

fn ranges_of(base: u64, data: u64, dst: u64, src: u64) -> [(u64, u64); 4] {
    [(base, 4096), (data, 128), (dst, 8192), (src, 8192)]
}

fn norm(v: u64, ranges: &[(u64, u64); 4]) -> u64 {
    for (i, &(base, len)) in ranges.iter().enumerate() {
        if v >= base && v <= base + len {
            return (((i as u64) + 1) << 56) | (v - base);
        }
    }
    v
}

struct BothResult {
    jit: Result<Outcome, RunError>,
    remote: Result<Outcome, RunError>,
    jit_ranges: [(u64, u64); 4],
    remote_ranges: [(u64, u64); 4],
    jit_stack_top: u64,
    remote_stack_top: u64,
    jit_dst: Vec<u8>,
    remote_dst: Vec<u8>,
    jit_data: Vec<u8>,
    remote_data: Vec<u8>,
    jit_stack: Vec<u8>,
    remote_stack: Vec<u8>,
    jit_written: Vec<u8>,
}

/// Per-fixture state tweaks, identical to o1_compare's fault
/// cases so both engines fault at the same guest instruction.
fn apply_tweak(name: &str, state: &mut GuestState, base: u64) {
    match name {
        "fault_load" | "fault_ret" | "fault_before_branch" => state.rdi = 0x0dea_d000,
        "call_store_fault" => {
            state.rax = 0x1122_3344_5566_7788;
            state.rdi = base + 16;
        }
        "rip_store_fault" => state.rdi = 0x2a,
        _ => {}
    }
}

fn run_both(name: &str) -> BothResult {
    let fixture = fixtures::by_name(name);
    // In-process reference run (same arrangement as o1_compare).
    let guest = MappedGuest::map(&fixture.bytes).expect("map");
    guest.plant_below_rsp(liteinst_jit::harness::REDZONE_MARKER);
    let region = guest.region(&fixture.bytes, Generation(1));
    let mut exec = Executable::prepare(&region, guest.base, CountProfile::BranchesAndInstructions)
        .expect("prepare");
    let data: Vec<u64> = (0..16).collect();
    let mut dst = vec![0u8; 8192];
    let src: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
    let guarded = (name == "rep_stosb_partial").then(|| GuardedDst::new().expect("guarded dst"));
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
    if let Some(g) = &guarded {
        state.rdi = g.ptr;
    }
    apply_tweak(name, &mut state, guest.base);
    let jit_ranges = ranges_of(
        guest.base,
        data.as_ptr() as u64,
        guarded
            .as_ref()
            .map_or(dst.as_ptr() as u64, |g| g.ptr - 4080),
        src.as_ptr() as u64,
    );
    let jit_stack_top = guest.stack_top();
    let mut handler = CaptureHandler::default();
    let jit = exec.run(state, &mut handler, &ProcessMemory, RETURN_SENTINEL);
    let jit_dst = match &guarded {
        Some(g) => g.head16(),
        None => dst[..32].to_vec(),
    };
    let jit_data: Vec<u8> = data.iter().flat_map(|v| v.to_le_bytes()).collect();
    let jit_stack = guest.stack_window();
    let jit_written = handler.written.clone();
    drop(exec);
    drop(guest);

    // Remote run in a fresh traced child.
    let mut remote =
        RemoteExecutable::spawn_named(std::path::Path::new(CHILD), name).expect("spawn remote");
    let info = remote.info();
    let rregion = liteinst_jit::types::RegionFacts {
        base: info.base,
        bytes: fixture.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    let remote = {
        let prep = remote.prepare(&rregion, info.base, CountProfile::BranchesAndInstructions);
        match prep {
            Ok(()) => {
                let mut rstate = remote.initial_state();
                let (rdi, rsi, rdx, rax, rcx) =
                    MappedGuest::fixture_args(name, info.base, info.data, info.dst, info.src);
                rstate.rdi = rdi;
                rstate.rsi = rsi;
                rstate.rdx = rdx;
                rstate.rax = rax;
                rstate.rcx = rcx;
                apply_tweak(name, &mut rstate, info.base);
                let out = remote.run(rstate, RETURN_SENTINEL);
                let mut rdst = vec![0u8; if guarded.is_some() { 16 } else { 32 }];
                assert!(
                    remote.read_mem(info.dst, &mut rdst),
                    "{name}: read remote dst"
                );
                let mut rdata = vec![0u8; 128];
                assert!(
                    remote.read_mem(info.data, &mut rdata),
                    "{name}: read remote data"
                );
                let mut rstack = vec![0u8; 136];
                assert!(
                    remote.read_mem(info.stack_top - 128, &mut rstack),
                    "{name}: read remote stack"
                );
                (out, rdst, rdata, rstack)
            }
            Err(e) => (Err(e.into()), Vec::new(), Vec::new(), Vec::new()),
        }
    };
    BothResult {
        jit,
        remote: remote.0,
        jit_ranges,
        remote_ranges: ranges_of(info.base, info.data, info.dst, info.src),
        jit_stack_top,
        remote_stack_top: info.stack_top,
        jit_dst,
        remote_dst: remote.1,
        jit_data,
        remote_data: remote.2,
        jit_stack,
        remote_stack: remote.3,
        jit_written,
    }
}

fn assert_same_outcome(name: &str, b: &BothResult) {
    let jit = b
        .jit
        .as_ref()
        .unwrap_or_else(|e| panic!("{name} in-process: {e:?}"));
    let rem = b
        .remote
        .as_ref()
        .unwrap_or_else(|e| panic!("{name} remote: {e:?}"));
    assert_eq!(rem.branches, jit.branches, "{name}: branches");
    assert_eq!(rem.instructions, jit.instructions, "{name}: instructions");
    assert_eq!(rem.exits, jit.exits, "{name}: exits");
    let regs: [(&str, u64, u64); 15] = [
        ("rax", rem.state.rax, jit.state.rax),
        ("rbx", rem.state.rbx, jit.state.rbx),
        ("rcx", rem.state.rcx, jit.state.rcx),
        ("rdx", rem.state.rdx, jit.state.rdx),
        ("rsi", rem.state.rsi, jit.state.rsi),
        ("rdi", rem.state.rdi, jit.state.rdi),
        ("rbp", rem.state.rbp, jit.state.rbp),
        ("r8", rem.state.r8, jit.state.r8),
        ("r9", rem.state.r9, jit.state.r9),
        ("r10", rem.state.r10, jit.state.r10),
        ("r11", rem.state.r11, jit.state.r11),
        ("r12", rem.state.r12, jit.state.r12),
        ("r13", rem.state.r13, jit.state.r13),
        ("r14", rem.state.r14, jit.state.r14),
        ("r15", rem.state.r15, jit.state.r15),
    ];
    for (r, rv, jv) in regs {
        if name == "rep_stosb_partial" && (r == "rdi" || r == "rsi") {
            continue;
        }
        // The kernel syscall path leaves TF in the saved R11
        // flags image after a stepped syscall; mask it there only.
        let (rv, jv) = if r == "r11" && name == "syscall_write" {
            (rv & !0x100, jv & !0x100)
        } else {
            (rv, jv)
        };
        assert_eq!(
            norm(rv, &b.remote_ranges),
            norm(jv, &b.jit_ranges),
            "{name}: register {r} (remote {rv:#x} vs jit {jv:#x})"
        );
    }
    assert_eq!(
        rem.state.rsp as i64 - b.remote_stack_top as i64,
        jit.state.rsp as i64 - b.jit_stack_top as i64,
        "{name}: rsp delta"
    );
    assert_eq!(
        rem.state.rflags & STATUS_MASK,
        jit.state.rflags & STATUS_MASK,
        "{name}: status flags"
    );
    assert_eq!(rem.state.rip, jit.state.rip, "{name}: rip");
    assert_eq!(b.remote_data, b.jit_data, "{name}: data buffer");
    assert_eq!(b.remote_dst, b.jit_dst, "{name}: dst buffer");
    let norm_window = |w: &[u8], ranges: &[(u64, u64); 4]| -> Vec<u64> {
        w.as_chunks::<8>()
            .0
            .iter()
            .map(|c| norm(u64::from_le_bytes(*c), ranges))
            .collect()
    };
    if name != "rep_stosb_partial" {
        assert_eq!(
            norm_window(&b.remote_stack, &b.remote_ranges),
            norm_window(&b.jit_stack, &b.jit_ranges),
            "{name}: stack window"
        );
    }
}

fn fault_of<'a>(r: &'a Result<Outcome, RunError>, name: &str, side: &str) -> &'a Fault {
    match r {
        Err(RunError::Fault(f)) => f,
        other => panic!("{name} {side}: expected fault, got {other:?}"),
    }
}

fn check_direct_corpus() {
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
        "compiled_c",
        "std_cld",
        "loopne_insn",
        "loope_insn",
        "rep_stosb_ok",
        "repne_scasb",
        "rep_lodsq",
        "r11_data",
        "rep_zero",
        "rep_movsw_prefix",
        "cpuid_loop",
    ] {
        let b = run_both(name);
        assert_same_outcome(name, &b);
        if name == "syscall_write" {
            // In-process captures the write; remote really wrote
            // to the child fd 1. The observable guest outcome is
            // the return value, already compared via RAX.
            assert_eq!(b.jit_written.len(), 5, "capture handler saw the write");
        }
        println!("{name}: remote == in-process");
    }
}

fn check_faults_and_refusals() {
    for name in [
        "fault_load",
        "fault_ret",
        "call_store_fault",
        "div_zero",
        "rip_store_fault",
        "fault_before_branch",
        "rep_stosb_partial",
    ] {
        let b = run_both(name);
        let jf = fault_of(&b.jit, name, "in-process");
        let rf = fault_of(&b.remote, name, "remote");
        assert_eq!(rf.kind, jf.kind, "{name}: fault kind");
        assert_eq!(rf.signum, jf.signum, "{name}: signum");
        assert_eq!(rf.branches, jf.branches, "{name}: fault branches");
        assert_eq!(
            rf.instructions, jf.instructions,
            "{name}: fault instructions"
        );
        // Source PCs are child-base absolute in both engines;
        // compare offsets from each engine's fixture base.
        assert_eq!(
            rf.src_pc - b.remote_ranges[0].0,
            jf.src_pc - b.jit_ranges[0].0,
            "{name}: fault src offset"
        );
    }
    // Named refusals: rdtsc is outside the corpus-bounded
    // pass-through set in both engines; indirect targets and
    // int3 refuse identically (prepare-time for int3).
    let b = run_both("rdtsc_exit");
    assert!(
        matches!(b.jit, Err(RunError::Refuse(Refuse::NoHandler { .. }))),
        "jit rdtsc: {:?}",
        b.jit
    );
    assert!(
        matches!(b.remote, Err(RunError::Refuse(Refuse::NoHandler { .. }))),
        "remote rdtsc: {:?}",
        b.remote
    );
    for name in ["indirect_jmp", "indirect_call", "jump_table"] {
        let b = run_both(name);
        assert!(
            matches!(
                b.remote,
                Err(RunError::Refuse(Refuse::IndirectUnresolved { .. }))
            ),
            "{name} remote: {:?}",
            b.remote
        );
    }
}

fn check_no_leaked_child() {
    // Prepare-time refusal (region base mismatch) and a
    // not-prepared run both return errors; dropping the
    // executable must kill and reap the child on every path.
    let fixture = fixtures::by_name("sum_loop");
    let mut remote =
        RemoteExecutable::spawn_named(std::path::Path::new(CHILD), "sum_loop").expect("spawn");
    let pid = remote.child_pid_for_test();
    let bad_region = liteinst_jit::types::RegionFacts {
        base: 0xdead_0000,
        bytes: fixture.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    assert!(
        remote
            .prepare(&bad_region, 0xdead_0000, CountProfile::Branches)
            .is_err()
    );
    assert!(remote.run(remote.initial_state(), RETURN_SENTINEL).is_err());
    drop(remote);
    // SAFETY: existence probe with signal 0.
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!alive, "child {pid} leaked after early-return drop");
}

fn check_poll_async_stop() {
    // A signal pending in the child at a poll exit stops the
    // run as a recovered AsyncSignal fault; it is never
    // delivered to a guest handler in I1-B.
    let fixture = fixtures::by_name("cpuid_loop");
    let mut remote =
        RemoteExecutable::spawn_named(std::path::Path::new(CHILD), "cpuid_loop").expect("spawn");
    let info = remote.info();
    let region = liteinst_jit::types::RegionFacts {
        base: info.base,
        bytes: fixture.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(&region, info.base, CountProfile::BranchesAndInstructions)
        .expect("prepare");
    // Queue SIGUSR1 to the stopped child before entry; it stays
    // pending (not delivered while stopped) until the poll exit
    // observes it.
    let pid = remote.child_pid_for_test();
    // SAFETY: signalling our own traced child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR1) }, 0);
    let mut state = remote.initial_state();
    state.rsi = 20_000;
    let r = remote.run(state, RETURN_SENTINEL);
    let f = fault_of(&r, "cpuid_loop poll", "remote");
    assert_eq!(f.kind, liteinst_jit::exec::FaultKind::AsyncSignal);
    assert_eq!(f.signum, libc::SIGUSR1);
}

/// One sequential test: the in-process executor and the O1/
/// remote children all use process-global signal/ptrace state,
/// so cases must not run concurrently (same constraint as
/// o1_compare).
#[test]
fn remote_compare_all() {
    check_direct_corpus();
    check_faults_and_refusals();
    check_no_leaked_child();
    check_poll_async_stop();
}
