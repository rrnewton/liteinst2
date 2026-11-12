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

#[path = "common/deadline.rs"]
mod deadline;

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

/// RSP comparison that works for both stack-relative values
/// (compare delta from each engine's stack top) and absolute
/// values a fixture installed itself (compare verbatim).
fn norm_rsp(v: u64, stack_top: u64, ranges: &[(u64, u64); 4]) -> i64 {
    let n = norm(v, ranges);
    if n != v {
        return n as i64;
    }
    let delta = v as i64 - stack_top as i64;
    if delta.abs() <= 8192 { delta } else { v as i64 }
}

fn norm_window(w: &[u8], ranges: &[(u64, u64); 4]) -> Vec<u64> {
    w.as_chunks::<8>()
        .0
        .iter()
        .map(|c| norm(u64::from_le_bytes(*c), ranges))
        .collect()
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
    let (mut remote, _deadline) = deadline::remote_named(CHILD, name).expect("spawn remote");
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
                if name == "rep_stosb_partial" {
                    // Same equivalent input as in-process: the
                    // remote child's guarded destination pointer.
                    rstate.rdi = info.dst;
                }
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
    let remote_dst_base = if name == "rep_stosb_partial" {
        info.dst - 4080
    } else {
        info.dst
    };
    BothResult {
        jit,
        remote: remote.0,
        jit_ranges,
        remote_ranges: ranges_of(info.base, info.data, remote_dst_base, info.src),
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
    assert_eq!(
        norm_window(&b.remote_stack, &b.remote_ranges),
        norm_window(&b.jit_stack, &b.jit_ranges),
        "{name}: stack window"
    );
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
        // Full recovered state, fault address, and effects —
        // the same strength as the outcome comparator, so a
        // wrong-input or wrong-recovery case cannot hide behind
        // kind/count equality (the delta-review F3 defect).
        let regs: [(&str, u64, u64); 15] = [
            ("rax", rf.state.rax, jf.state.rax),
            ("rbx", rf.state.rbx, jf.state.rbx),
            ("rcx", rf.state.rcx, jf.state.rcx),
            ("rdx", rf.state.rdx, jf.state.rdx),
            ("rsi", rf.state.rsi, jf.state.rsi),
            ("rdi", rf.state.rdi, jf.state.rdi),
            ("rbp", rf.state.rbp, jf.state.rbp),
            ("r8", rf.state.r8, jf.state.r8),
            ("r9", rf.state.r9, jf.state.r9),
            ("r10", rf.state.r10, jf.state.r10),
            ("r11", rf.state.r11, jf.state.r11),
            ("r12", rf.state.r12, jf.state.r12),
            ("r13", rf.state.r13, jf.state.r13),
            ("r14", rf.state.r14, jf.state.r14),
            ("r15", rf.state.r15, jf.state.r15),
        ];
        for (r, rv, jv) in regs {
            assert_eq!(
                norm(rv, &b.remote_ranges),
                norm(jv, &b.jit_ranges),
                "{name}: fault register {r} (remote {rv:#x} vs jit {jv:#x})"
            );
        }
        assert_eq!(
            norm_rsp(rf.state.rsp, b.remote_stack_top, &b.remote_ranges),
            norm_rsp(jf.state.rsp, b.jit_stack_top, &b.jit_ranges),
            "{name}: fault rsp (remote {:#x} vs jit {:#x})",
            rf.state.rsp,
            jf.state.rsp
        );
        assert_eq!(
            rf.state.rflags & STATUS_MASK,
            jf.state.rflags & STATUS_MASK,
            "{name}: fault status flags"
        );
        assert_eq!(
            rf.state.rip, rf.src_pc,
            "{name}: recovered rip is the source pc"
        );
        assert_eq!(
            norm(rf.addr, &b.remote_ranges),
            norm(jf.addr, &b.jit_ranges),
            "{name}: normalized fault address (remote {:#x} vs jit {:#x})",
            rf.addr,
            jf.addr
        );
        assert_eq!(b.remote_data, b.jit_data, "{name}: fault data buffer");
        assert_eq!(b.remote_dst, b.jit_dst, "{name}: fault dst effects");
        assert_eq!(
            norm_window(&b.remote_stack, &b.remote_ranges),
            norm_window(&b.jit_stack, &b.jit_ranges),
            "{name}: fault stack window"
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
    let (mut remote, _deadline) = deadline::remote_named(CHILD, "sum_loop").expect("spawn");
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

/// The caller holds the returned deadline across its run.
fn prepare_remote(
    name: &str,
    blocked: &[i32],
) -> (
    RemoteExecutable,
    liteinst_jit::remote::RemoteChildInfo,
    deadline::Deadline,
) {
    let fixture = fixtures::by_name(name);
    let (mut remote, deadline) = if blocked.is_empty() {
        deadline::remote_named(CHILD, name).expect("spawn")
    } else {
        deadline::remote_named_with_blocked(CHILD, name, blocked).expect("spawn blocked")
    };
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
    (remote, info, deadline)
}

fn check_immediate_and_poll_async_stops() {
    // Immediate pre-entry stops: a user signal queued while the
    // child is stopped is delivered at the first resume, before
    // any guest instruction retires. Genuine SIGTRAP here is
    // asynchronous by siginfo cause, never a dispatcher exit.
    for sig in [libc::SIGUSR1, libc::SIGTRAP] {
        let (mut remote, info, _deadline) = prepare_remote("cpuid_leaf", &[]);
        let pid = remote.child_pid_for_test();
        // SAFETY: signalling our own traced child.
        assert_eq!(unsafe { libc::kill(pid, sig) }, 0);
        let r = remote.run(remote.initial_state(), RETURN_SENTINEL);
        let f = fault_of(&r, "immediate async", "remote");
        assert_eq!(
            f.kind,
            liteinst_jit::exec::FaultKind::AsyncSignal,
            "sig {sig}"
        );
        assert_eq!(f.signum, sig);
        assert_eq!(f.src_pc, info.base, "sig {sig}: entry source pc");
        assert_eq!(f.branches, 0, "sig {sig}");
        assert_eq!(f.instructions, 0, "sig {sig}");
    }
    // Genuine poll boundary with BLOCKED pending signals (I1-H
    // W4): with SIGUSR1+SIGUSR2 blocked in the child's initial
    // mask, queued signals stay pending through cache execution
    // AND through every poll exit, because natively a blocked
    // pending signal is not an event. The run completes exactly
    // like the same input with nothing pending, crossing many
    // poll exits; nothing is delivered and nothing is lost: both
    // are still pending in the kernel afterwards. (Until W4 the
    // first poll exit stopped this run with a recovered
    // AsyncSignal, which design review ruled a bug.)
    {
        // 40000 iterations of `xor; cpuid; dec r12; jne`. The
        // cpuid exit splits each iteration into two block
        // entries, so the run makes about 80000 block entries
        // and crosses several poll exits (one per 16384 block
        // entries), as well as one cpuid exit per iteration.
        let state_of = |remote: &RemoteExecutable| {
            let mut state = remote.initial_state();
            state.rsi = 40_000;
            state
        };
        let (mut quiet, _, _quiet_deadline) =
            prepare_remote("cpuid_loop", &[libc::SIGUSR1, libc::SIGUSR2]);
        let q = quiet
            .run(state_of(&quiet), RETURN_SENTINEL)
            .expect("cpuid_loop with nothing pending");
        let (mut remote, _info, _deadline) =
            prepare_remote("cpuid_loop", &[libc::SIGUSR1, libc::SIGUSR2]);
        let pid = remote.child_pid_for_test();
        // SAFETY: signalling our own traced child.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR2) }, 0);
        assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR1) }, 0);
        let out = remote
            .run(state_of(&remote), RETURN_SENTINEL)
            .unwrap_or_else(|e| panic!("cpuid_loop with blocked pending signals completes: {e:?}"));
        assert!(
            out.branches > 2 * liteinst_jit::exec::POLL_BUDGET,
            "crossed poll exits: {} branches",
            out.branches
        );
        assert_eq!(
            (out.branches, out.instructions),
            (q.branches, q.instructions),
            "counts equal the run with nothing pending"
        );
        // Exact (review P3): one `jne` per iteration, four
        // instructions per iteration plus the entry `mov` and
        // the final `ret`, and the counter run down to zero.
        assert_eq!(
            (out.branches, out.instructions, out.state.r12),
            (40_000, 160_002, 0),
            "exact counts and final counter"
        );
        assert_eq!(out.exits, q.exits, "same dispatcher exits as the quiet run");
        eprintln!("W4 cpuid_loop: {} dispatcher exits", out.exits);
        assert_eq!(
            (
                out.state.rsi,
                out.state.rdi,
                out.state.rip,
                out.state.rflags & STATUS_MASK
            ),
            (
                q.state.rsi,
                q.state.rdi,
                q.state.rip,
                q.state.rflags & STATUS_MASK
            ),
            "final state equals the run with nothing pending"
        );
        let both = (1u64 << (libc::SIGUSR1 - 1)) | (1u64 << (libc::SIGUSR2 - 1));
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("child status");
        let pending = status
            .lines()
            .filter_map(|l| {
                l.strip_prefix("SigPnd:")
                    .or_else(|| l.strip_prefix("ShdPnd:"))
            })
            .map(|v| u64::from_str_radix(v.trim(), 16).expect("pending hex"))
            .fold(0, |acc, v| acc | v);
        assert_eq!(
            pending & both,
            both,
            "both still pending in the kernel, none delivered"
        );
    }
    // Stepping-phase asynchronous interruption (live): a write
    // loop passes through the tracer's syscall stepping on
    // every iteration; a helper thread queues SIGUSR1 mid-run.
    // Whichever resume it lands on (generated entry, syscall
    // entry, or single-step equivalent), the outcome must be
    // an exact AsyncSignal at a source PC with progress, never
    // an executor error or a credited-but-unexecuted step.
    // (Deterministic phase-by-phase provenance is pinned by
    // the classifier unit tests in remote.rs.)
    {
        // mov eax,1; syscall; dec rcx; jne loop; ret
        let bytes: &[u8] = &[
            0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0xff, 0xc9, 0x75, 0xf4, 0xc3,
        ];
        let (mut remote, _deadline) = deadline::remote_bytes(CHILD, bytes).expect("spawn");
        let info = remote.info();
        let region = liteinst_jit::types::RegionFacts {
            base: info.base,
            bytes: bytes.to_vec(),
            generation: Generation(1),
            immutable_private: true,
        };
        remote
            .prepare(&region, info.base, CountProfile::BranchesAndInstructions)
            .expect("prepare write loop");
        let pid = remote.child_pid_for_test();
        let killer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            // SAFETY: signalling the test's traced child; the
            // run is still in its long stepping loop here.
            unsafe { libc::kill(pid, libc::SIGUSR1) };
        });
        let mut state = remote.initial_state();
        state.rdi = 9999; // invalid fd: write fails fast, loops on stepping path
        state.rsi = info.src;
        state.rdx = 1;
        state.rcx = 5_000_000;
        let r = remote.run(state, RETURN_SENTINEL);
        killer.join().expect("killer thread");
        let f = fault_of(&r, "write-loop stepping async", "remote");
        assert_eq!(f.kind, liteinst_jit::exec::FaultKind::AsyncSignal);
        assert_eq!(f.signum, libc::SIGUSR1);
        assert!(
            [0, 5, 7, 10].contains(&(f.src_pc - info.base)),
            "stepping async src is an exact loop instruction pc: {:#x}",
            f.src_pc
        );
        assert!(
            f.branches > 0,
            "stepping async progress: branches {}",
            f.branches
        );
        assert!(
            f.instructions > f.branches,
            "stepping async instruction progress"
        );
    }
}

fn check_blocked_write_restart_fails_closed() {
    // Blocked-pipe syscall restart: the guest loops
    // SYS_write(1, src, 8192) into its stdout pipe, which
    // nobody drains after the handshake, so a write soon
    // blocks in the kernel. A helper thread then delivers
    // SIGUSR1. The syscall-exit stop for the interrupted write
    // carries a kernel restart result, which must fail closed
    // as the named substrate refusal — never AsyncSignal,
    // never completion credit, never resumed.
    //
    // Timing control (stated honestly): the killer sleeps
    // 250 ms before its first signal so the first writes fill
    // the 64 KiB pipe (nine writes at tracer-stepping speed is
    // well under that bound), then repeats every 50 ms until
    // the run returns. The 64-iteration bound plus the first
    // signal landing in the blocked exit wait make the outcome
    // deterministic in practice; the assertions below would
    // fail loudly (not pass vacuously) if it landed elsewhere.
    let bytes: &[u8] = &[
        0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0xff, 0xc9, 0x75, 0xf4, 0xc3,
    ];
    let (mut remote, _deadline) = deadline::remote_bytes(CHILD, bytes).expect("spawn");
    let info = remote.info();
    let region = liteinst_jit::types::RegionFacts {
        base: info.base,
        bytes: bytes.to_vec(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(&region, info.base, CountProfile::BranchesAndInstructions)
        .expect("prepare blocked write");
    let pid = remote.child_pid_for_test();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done2 = done.clone();
    let killer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(250));
        for _ in 0..40 {
            if done2.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            // SAFETY: signalling the test's traced child.
            unsafe { libc::kill(pid, libc::SIGUSR1) };
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
    let mut state = remote.initial_state();
    state.rdi = 1; // child stdout pipe: fills, then blocks
    state.rsi = info.src;
    state.rdx = 8192;
    state.rcx = 64;
    let r = remote.run(state, RETURN_SENTINEL);
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    killer.join().expect("killer thread");
    match r {
        Err(RunError::Refuse(Refuse::RemoteSubstrate { operation, .. })) => {
            assert_eq!(operation, "syscall restart pending at exit stop");
        }
        other => panic!("blocked write: expected restart refusal, got {other:?}"),
    }
    drop(remote);
    // SAFETY: existence probe with signal 0.
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!alive, "child {pid} leaked after restart refusal drop");
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
    check_immediate_and_poll_async_stops();
    check_blocked_write_restart_fails_closed();
}

/// Spawn census (I1-H H2c): every child this binary starts carries
/// a run deadline (`common/deadline.rs`).
#[test]
fn spawn_census() {
    deadline::spawn_census(include_str!("remote_compare.rs"), "remote_compare.rs");
}
