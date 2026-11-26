//! Remaining-RCB budget experiment (mini-JIT tail plan, first
//! experiment): on every corpus-v1 fixture and up to 20 targets k,
//! a budgeted translation must land exactly where the O1 oracle,
//! single-stepping natively, stands once k conditional branches have
//! retired: all registers, RIP, retired instructions, the data and
//! destination buffers and the stack window, in the in-process mode,
//! in the remote (traced child) mode, and in the attach mode (an O1
//! host process driven by the attach-mode driver).
//!
//! Witnesses per row, judged by `judge_row`:
//! - W1: the JIT credited exactly k (n plus the owed count for a
//!   handoff), and the oracle stopped at the same count;
//! - W2: the JIT arm made no single-step (remote: the counter reads
//!   0; in-process: no tracer exists), while the oracle arm did; a
//!   plain remote cpuid run and `w2_control_attach` are the counter's positive controls;
//! - W3: the PMU delta over the stretch is 2 x JIT branches + poll
//!   entries (guest RCBs, one budget `jnz` per credit, one poll
//!   `jnz` per block entry); in-process, only when the ret-only
//!   calibration reads exactly 1 per entry (c = 0, fixed before
//!   the run). The LOOP-class shortfall is a named finding, never a
//!   PASS;
//! - non-vacuity, judged before W3: k = 0 rows are sanity rows only;
//!   every fixture with branches needs a non-vacuous row, and only
//!   the pre-stated handoff set may hand off.
//!
//! One sequential corpus test, `#[ignore]`d and run by name: the
//! in-process dispatcher keeps process-global state, and all three
//! modes share ptrace and signals. The judge self-tests run by default.

use liteinst_jit::GuestState;
use liteinst_jit::Refuse;
use liteinst_jit::attach::AttachedExecutable;
use liteinst_jit::exec::{BudgetEnd, BudgetStop, Executable, ProcessMemory, RunError};
use liteinst_jit::fixtures;
use liteinst_jit::harness::{MappedGuest, REDZONE_MARKER, RETURN_SENTINEL};
use liteinst_jit::o1::{O1Stop, OracleOutcome};
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};

#[path = "common/deadline.rs"]
mod deadline;

const O1_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-o1-child");
const REMOTE_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-remote-child");
const STATUS_MASK: u64 = 0xcd5; // OF|DF|SF|ZF|AF|PF|CF

/// The corpus-v1 fixtures of `jit_matches_o1_oracle_on_corpus_v1`,
/// then the five P1b.1 corpus fixtures (in-region indirect
/// transfers, resolved by the dispatcher with the budget unchanged).
const FIXTURES: [&str; 26] = [
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
    "ind_jmp_reg",
    "ind_call_reg",
    "ind_jmp_table",
    "ind_call_mem",
    "ind_jmp_known",
];

/// Ret-only calibration entries before and after the corpus.
const CALIBRATION_ENTRIES: usize = 8;

/// Deterministic targets for a fixture whose full run retires
/// `total` RCBs: {0, 1, 2, T-1, T} and T*i/16 for i in 1..16, each
/// at most T, de-duplicated (at most 20).
fn targets(total: u64) -> Vec<u64> {
    let mut v: Vec<u64> = vec![0, 1, 2, total.saturating_sub(1), total];
    v.extend((1..16u64).map(|i| total * i / 16));
    v.retain(|&k| k <= total);
    v.sort_unstable();
    v.dedup();
    v
}

// ---------------------------------------------------------------
// PMU access (raw perf_event_open; user-only counting).

/// `perf_event_attr` up to `PERF_ATTR_SIZE_VER0` (64 bytes).
#[repr(C)]
#[derive(Default)]
struct PerfAttr {
    kind: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}

const PERF_TYPE_RAW: u32 = 4;
const ATTR_DISABLED: u64 = 1;
const ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
const ATTR_EXCLUDE_HV: u64 = 1 << 6;

/// The retired-conditional-branch raw event for this CPU vendor:
/// AMD PMCx0D1 (Zen and later); Intel BR_INST_RETIRED.CONDITIONAL
/// (event C4, umask 01), believed right for the models rr names,
/// not measured here. Any other vendor has no event.
fn rcb_event() -> Option<u64> {
    let r = core::arch::x86_64::__cpuid(0);
    match (r.ebx, r.edx, r.ecx) {
        (0x6874_7541, 0x6974_6e65, 0x444d_4163) => Some(0xd1),
        (0x756e_6547, 0x4965_6e69, 0x6c65_746e) => Some(0x01c4),
        _ => None,
    }
}

/// Open a user-only RCB counter on `pid` (0: this thread), created
/// disabled when `disabled` (the in-process window enables it).
fn perf_open(pid: i32, disabled: bool) -> Option<i32> {
    let event = rcb_event()?;
    let attr = PerfAttr {
        kind: PERF_TYPE_RAW,
        size: core::mem::size_of::<PerfAttr>() as u32,
        config: event,
        flags: ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV | if disabled { ATTR_DISABLED } else { 0 },
        ..PerfAttr::default()
    };
    // SAFETY: `attr` is a live, fully initialized VER0 record.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            core::ptr::addr_of!(attr),
            pid,
            -1i32,
            -1i32,
            0u64,
        )
    };
    (fd >= 0).then_some(fd as i32)
}

fn perf_read(fd: i32) -> Option<u64> {
    let mut v: u64 = 0;
    // SAFETY: reads at most 8 bytes into a live u64.
    let n = unsafe { libc::read(fd, core::ptr::addr_of_mut!(v).cast(), 8) };
    (n == 8).then_some(v)
}

fn perf_close(fd: Option<i32>) {
    if let Some(fd) = fd {
        // SAFETY: closing a perf fd this test opened.
        unsafe {
            libc::close(fd);
        }
    }
}

// ---------------------------------------------------------------
// Normalized end-state views.

fn norm(v: u64, ranges: &[(u64, u64); 4]) -> u64 {
    for (i, &(base, len)) in ranges.iter().enumerate() {
        // Inclusive: a one-past-end pointer is the same identity.
        if v >= base && v <= base + len {
            return (((i as u64) + 1) << 56) | (v - base);
        }
    }
    v
}

/// Everything compared between two engines, pointer-normalized.
#[derive(Debug, PartialEq)]
struct View {
    regs: Vec<(&'static str, u64)>,
    rsp_delta: i64,
    flags: u64,
    rip: u64,
    instructions: u64,
    data: Vec<u8>,
    dst: Vec<u8>,
    stack: Vec<u64>,
}

struct Mem<'a> {
    ranges: [(u64, u64); 4],
    stack_top: u64,
    data: &'a [u8],
    dst: &'a [u8],
    stack: &'a [u8],
}

fn view(name: &str, s: &GuestState, instructions: u64, m: &Mem<'_>) -> View {
    let raw: [(&'static str, u64); 15] = [
        ("rax", s.rax),
        ("rbx", s.rbx),
        ("rcx", s.rcx),
        ("rdx", s.rdx),
        ("rsi", s.rsi),
        ("rdi", s.rdi),
        ("rbp", s.rbp),
        ("r8", s.r8),
        ("r9", s.r9),
        ("r10", s.r10),
        ("r11", s.r11),
        ("r12", s.r12),
        ("r13", s.r13),
        ("r14", s.r14),
        ("r15", s.r15),
    ];
    let regs = raw
        .iter()
        .map(|&(r, v)| {
            // Only a stepped syscall leaves the tracer's TF in the
            // kernel-saved R11 image (as in o1_compare).
            let v = if r == "r11" && name == "syscall_write" {
                v & !0x100
            } else {
                v
            };
            (r, norm(v, &m.ranges))
        })
        .collect();
    View {
        regs,
        rsp_delta: s.rsp as i64 - m.stack_top as i64,
        flags: s.rflags & STATUS_MASK,
        rip: norm(s.rip, &m.ranges),
        instructions,
        data: m.data.to_vec(),
        dst: m.dst.to_vec(),
        stack: m
            .stack
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| norm(u64::from_le_bytes(*c), &m.ranges))
            .collect(),
    }
}

/// The first field where two views differ, by name.
fn first_mismatch(jit: &View, o1: &View) -> Option<String> {
    for ((r, a), (_, b)) in jit.regs.iter().zip(o1.regs.iter()) {
        if a != b {
            return Some(format!("register {r}: jit {a:#x} vs o1 {b:#x}"));
        }
    }
    let fields: [(&str, bool); 7] = [
        ("rsp delta", jit.rsp_delta == o1.rsp_delta),
        ("status flags", jit.flags == o1.flags),
        ("rip", jit.rip == o1.rip),
        ("retired instructions", jit.instructions == o1.instructions),
        ("data buffer", jit.data == o1.data),
        ("dst buffer", jit.dst == o1.dst),
        ("stack window", jit.stack == o1.stack),
    ];
    fields
        .iter()
        .find(|(_, same)| !same)
        .map(|(f, _)| format!("{f}: jit {jit:?} vs o1 {o1:?}"))
}

fn oracle_view(name: &str, o: &OracleOutcome) -> View {
    let i = &o.info;
    let mem = Mem {
        ranges: [(i.base, 4096), (i.data, 128), (i.dst, 32), (i.src, 32)],
        stack_top: o.stack_top,
        data: &o.data_bytes,
        dst: &o.dst_bytes,
        stack: &o.stack_window,
    };
    view(name, &o.state, o.instructions, &mem)
}

// ---------------------------------------------------------------
// The three JIT arms: in-process and remote here, attach in the Attach
// arm's section below.

/// One budgeted JIT run, measured.
struct Measured {
    stop: Result<BudgetStop, String>,
    view: Option<View>,
    pmu_delta: Option<u64>,
    single_steps: Option<u64>,
    /// The JIT arm's fixture base: a handoff PC minus this is the
    /// base-relative offset the oracle child (mapped elsewhere) stops
    /// at. 0 when the run failed before mapping.
    base: u64,
}

fn failed(e: String) -> Measured {
    Measured {
        stop: Err(e),
        view: None,
        pmu_delta: None,
        single_steps: None,
        base: 0,
    }
}

fn run_inprocess(name: &str, k: u64, pmu: Option<i32>) -> Measured {
    let fixture = fixtures::by_name(name);
    let guest = MappedGuest::map(&fixture.bytes).expect("map");
    guest.plant_below_rsp(REDZONE_MARKER);
    let region = guest.region(&fixture.bytes, Generation(1));
    let profile = CountProfile::BranchesAndInstructions;
    let mut exec = match Executable::prepare_budgeted(&region, guest.base, profile) {
        Ok(e) => e,
        Err(e) => return failed(format!("prepare: {e:?}")),
    };
    exec.set_pmu_window_for_test(pmu);
    let data: Vec<u64> = (0..16).collect();
    let mut dst = vec![0u8; 8192];
    let src: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
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
    let before = pmu.and_then(perf_read);
    let stop = exec.run_budgeted(state, &ProcessMemory, RETURN_SENTINEL, k);
    let after = pmu.and_then(perf_read);
    let data_bytes: Vec<u8> = data.iter().flat_map(|v| v.to_le_bytes()).collect();
    let stack = guest.stack_window();
    let mem = Mem {
        ranges: [
            (guest.base, 4096),
            (data.as_ptr() as u64, 128),
            (dst.as_ptr() as u64, 8192),
            (src.as_ptr() as u64, 8192),
        ],
        stack_top: guest.stack_top(),
        data: &data_bytes,
        dst: &dst[..32],
        stack: &stack,
    };
    let view = stop
        .as_ref()
        .ok()
        .map(|s| view(name, &s.outcome.state, s.outcome.instructions, &mem));
    Measured {
        stop: stop.map_err(|e| format!("{e:?}")),
        view,
        pmu_delta: before.zip(after).map(|(b, a)| a.wrapping_sub(b)),
        single_steps: None,
        base: guest.base,
    }
}

fn run_remote(name: &str, k: u64) -> Measured {
    let fixture = fixtures::by_name(name);
    let (mut remote, _deadline) = match deadline::remote_named(REMOTE_CHILD, name) {
        Ok(pair) => pair,
        Err(e) => return failed(format!("spawn: {e:?}")),
    };
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: fixture.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    let profile = CountProfile::BranchesAndInstructions;
    if let Err(e) = remote.prepare_budgeted(&region, info.base, profile) {
        return failed(format!("prepare: {e:?}"));
    }
    let mut state = remote.initial_state();
    let (rdi, rsi, rdx, rax, rcx) =
        MappedGuest::fixture_args(name, info.base, info.data, info.dst, info.src);
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = rax;
    state.rcx = rcx;
    // Opened after the publish handshake, while the child is
    // stopped: from here on the child runs only generated code.
    let pmu = perf_open(remote.child_pid_for_test(), false);
    let before = pmu.and_then(perf_read);
    let stop = remote.run_budgeted(state, RETURN_SENTINEL, k);
    let after = pmu.and_then(perf_read);
    perf_close(pmu);
    let single_steps = Some(remote.single_steps_for_test());
    let mut data = vec![0u8; 128];
    let mut dst = vec![0u8; 32];
    let mut stack = vec![0u8; 136];
    let read = remote.read_mem(info.data, &mut data)
        && remote.read_mem(info.dst, &mut dst)
        && remote.read_mem(info.stack_top - 128, &mut stack);
    let mem = Mem {
        ranges: [
            (info.base, 4096),
            (info.data, 128),
            (info.dst, 8192),
            (info.src, 8192),
        ],
        stack_top: info.stack_top,
        data: &data,
        dst: &dst,
        stack: &stack,
    };
    let view = match (&stop, read) {
        (Ok(s), true) => Some(view(name, &s.outcome.state, s.outcome.instructions, &mem)),
        _ => None,
    };
    let stop = match (stop, read) {
        (Ok(s), true) => Ok(s),
        (Ok(_), false) => Err("remote memory read failed".to_string()),
        (Err(e), _) => Err(format!("{e:?}")),
    };
    Measured {
        stop,
        view,
        pmu_delta: before.zip(after).map(|(b, a)| a.wrapping_sub(b)),
        single_steps,
        base: info.base,
    }
}

/// Ret-only in-process calibration: each reading is the window's
/// count for one entry that runs one poll stub (one `jnz`) and the
/// return exit. `None` when anything needed is unavailable.
fn calibrate(pmu: Option<i32>) -> Vec<Option<u64>> {
    (0..CALIBRATION_ENTRIES)
        .map(|_| {
            let fd = pmu?;
            let bytes = [0xc3u8];
            let guest = MappedGuest::map(&bytes).ok()?;
            let region = guest.region(&bytes, Generation(1));
            let profile = CountProfile::BranchesAndInstructions;
            let mut exec = Executable::prepare_budgeted(&region, guest.base, profile).ok()?;
            exec.set_pmu_window_for_test(Some(fd));
            let before = perf_read(fd)?;
            let stop = exec
                .run_budgeted(guest.initial_state(), &ProcessMemory, RETURN_SENTINEL, 1)
                .ok()?;
            let after = perf_read(fd)?;
            let shape = stop.end == BudgetEnd::Ended && stop.entries == 1 && stop.poll_entries == 1;
            shape.then(|| after.wrapping_sub(before))
        })
        .collect()
}

/// W2 positive control: a plain (unbudgeted) remote run of
/// cpuid_leaf steps its cpuid through the remote single-step site,
/// so the JIT-side counter must read more than 0 there. A counter
/// that never counts would otherwise pass W2 unnoticed.
fn w2_control() -> Result<u64, String> {
    let name = "cpuid_leaf";
    let fixture = fixtures::by_name(name);
    let (mut remote, _deadline) =
        deadline::remote_named(REMOTE_CHILD, name).map_err(|e| format!("spawn: {e:?}"))?;
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: fixture.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    let profile = CountProfile::BranchesAndInstructions;
    remote
        .prepare(&region, info.base, profile)
        .map_err(|e| format!("prepare: {e:?}"))?;
    let mut state = remote.initial_state();
    let (rdi, rsi, rdx, rax, rcx) =
        MappedGuest::fixture_args(name, info.base, info.data, info.dst, info.src);
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = rax;
    state.rcx = rcx;
    remote
        .run(state, RETURN_SENTINEL)
        .map_err(|e| format!("run: {e:?}"))?;
    Ok(remote.single_steps_for_test())
}

// ---------------------------------------------------------------
// The CPU caps and the SIGXCPU premise reads, each a named failure:
// B1, SIGXCPU is not caught in a host (`SigCgt` bit 24 clear); B2, a
// CPU-cap hit ends the test binary by signal 24; B3, SIGXCPU is not
// blocked in a host, nor ignored or blocked in the test process.

/// SIGXCPU (signal 24) as a `/proc/<pid>/status` mask bit.
const SIGXCPU_BIT: u64 = 1 << (libc::SIGXCPU - 1);

/// One `/proc/<pid>/status` mask field, in hex. It must appear exactly
/// once: a missing or repeated line fails closed, never reads as 0.
fn status_field(text: &str, name: &str) -> Result<u64, String> {
    let mut found = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix(name) {
            if found.is_some() {
                return Err(format!("{name} repeated"));
            }
            let v = v.trim();
            found = Some(u64::from_str_radix(v, 16).map_err(|_| format!("{name} not hex: {v:?}"))?);
        }
    }
    found.ok_or_else(|| format!("{name} absent"))
}

/// The test process's own CPU cap: `RLIMIT_CPU` = {soft, hard}
/// CPU-seconds, inherited by each child at fork and lowered to the
/// child cap when the child is armed. Soft < hard, so a hit is
/// SIGXCPU, whose default action ends the test process with signal
/// 24; cargo reports it, and that is the named CPU-cap FAIL (B2).
fn own_cpu_cap(soft: u64, hard: u64) {
    assert!(soft < hard, "own_cpu_cap: soft {soft} must be below hard {hard}");
    let lim = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: setrlimit on this process with a valid limit.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CPU, &lim) };
    assert!(
        rc == 0,
        "setrlimit(RLIMIT_CPU, {soft}/{hard}): {}",
        std::io::Error::last_os_error()
    );
}

/// B3, the test process: SIGXCPU is neither ignored (`SigIgn`, which
/// is process-wide) nor blocked in this thread (`SigBlk`, which is per
/// thread), so a CPU-cap hit is delivered with its default action.
fn sigxcpu_premise_self() -> Result<(), String> {
    let proc_text = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("B3: read /proc/self/status: {e}"))?;
    let thread_text = std::fs::read_to_string("/proc/thread-self/status")
        .map_err(|e| format!("B3: read /proc/thread-self/status: {e}"))?;
    let ign = status_field(&proc_text, "SigIgn:").map_err(|e| format!("B3: {e}"))?;
    let blk = status_field(&thread_text, "SigBlk:").map_err(|e| format!("B3: {e}"))?;
    if ign & SIGXCPU_BIT != 0 {
        return Err(format!(
            "B3: SIGXCPU is ignored in the test process (SigIgn {ign:016x})"
        ));
    }
    if blk & SIGXCPU_BIT != 0 {
        return Err(format!(
            "B3: SIGXCPU is blocked in the test thread (SigBlk {blk:016x})"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------
// The Attach arm (an O1 host driven by the attach-mode driver).

/// The O1 host's real dst allocation, as the oracle's own view has it:
/// a 32-byte box, except rep_stosb_partial's guarded tail, which ends
/// 16 bytes before a PROT_NONE page (`GuardedDst`).
fn host_dst_len(name: &str) -> u64 {
    if name == "rep_stosb_partial" { 16 } else { 32 }
}

/// The host premise reads, before any stretch, from one
/// `/proc/<pid>/status` read of the stopped host:
/// - B1: SIGXCPU is not caught (`SigCgt` bit 24 clear);
/// - B3: SIGXCPU is not blocked (`SigBlk` bit 24 clear);
/// - the mirror comparison: for every signal, the queried mirror holds
///   a custom action exactly where `SigCgt` has the bit, and an ignored
///   one exactly where `SigIgn` has it.
///
/// So a CPU-cap hit reaches the tracer as a signal-delivery stop, and
/// no action word the engine consults is wrong. Any failure is named.
fn host_premise(pid: i32, exec: &AttachedExecutable) -> Result<(), String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|e| format!("PREMISE: read /proc/{pid}/status: {e}"))?;
    let field = |name: &str| status_field(&text, name).map_err(|e| format!("PREMISE: {e}"));
    let cgt = field("SigCgt:")?;
    let ign = field("SigIgn:")?;
    let blk = field("SigBlk:")?;
    if cgt & SIGXCPU_BIT != 0 {
        return Err(format!(
            "B1: SIGXCPU is caught in the host (SigCgt {cgt:016x})"
        ));
    }
    if blk & SIGXCPU_BIT != 0 {
        return Err(format!(
            "B3: SIGXCPU is blocked in the host (SigBlk {blk:016x})"
        ));
    }
    let registry = exec.registry();
    for sig in 1..=64i32 {
        let bit = 1u64 << (sig - 1);
        let action = registry.action(sig);
        if action.is_custom() != (cgt & bit != 0) || action.is_ignore() != (ign & bit != 0) {
            return Err(format!(
                "MIRROR: signal {sig}: mirror {action:?}, SigCgt {cgt:016x}, SigIgn {ign:016x}"
            ));
        }
    }
    Ok(())
}

/// How an Attach run's error is reported (the child CPU-cap naming
/// rule). A SIGXCPU inside a stretch takes one of four cases. (1) From
/// the remote engine's KernelAsync arm, it surfaces as `RunError::Fault`
/// with signum 24, because 24 is not a fault signal
/// (`recovery::is_fault_signal`), named "CPU-cap FAIL: SIGXCPU (signal
/// 24) at <pc>". (2) At a POLL exit, the engine instead names the
/// lowest-numbered unblocked pending signal when none is deliverable,
/// which is 24 when SIGXCPU is that signal. (3) If the stop's siginfo
/// cannot be read, the run is refused as `RemoteSubstrate`. (4) On any
/// other path (for example a syscall-exit-phase stop, which classifies
/// Unexpected), this function names SIGXCPU only for a Fault whose
/// signum is 24, so no other outcome is named SIGXCPU. Within a stretch,
/// a signal yields `Refuse::RcbBudget` only when `delivery_action` admits
/// it, and the admission sets never admit 24. `Refuse::RcbBudget` also
/// arises, with no signal involved, from the engine's own wiring
/// refusals. Every `Refuse::RcbBudget` stays named "budget refusal,
/// cause not named (no signum)": never a pass, and never named SIGXCPU.
/// Any other error is its Debug text.
fn attach_error(e: &RunError) -> String {
    match e {
        RunError::Refuse(Refuse::RcbBudget { .. }) => {
            "budget refusal, cause not named (no signum)".to_string()
        }
        RunError::Fault(f) if f.signum == libc::SIGXCPU => {
            format!("CPU-cap FAIL: SIGXCPU (signal {}) at {:#x}", f.signum, f.src_pc)
        }
        other => format!("{other:?}"),
    }
}

/// The Attach arm: one budgeted run of `name` to `k` in its own O1 host
/// process, through the attach-mode driver. The procedure is
/// `run_remote`'s; the memory ranges are the host's real allocations,
/// as the oracle's view has them.
fn run_attach(name: &str, k: u64) -> Measured {
    let fixture = fixtures::by_name(name);
    let (host, _deadline) = match deadline::attach_host(O1_CHILD, name) {
        Ok(pair) => pair,
        Err(e) => return failed(format!("attach host: {e:?}")),
    };
    let info = host.info;
    let region = RegionFacts {
        base: info.base,
        bytes: fixture.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    let profile = CountProfile::BranchesAndInstructions;
    let mut exec = match AttachedExecutable::new(
        host.tracee,
        &host.site,
        host.arena,
        &info,
        region,
        info.base,
        profile,
    ) {
        Ok(exec) => exec,
        Err(e) => return failed(format!("attach: {e:?}")),
    };
    if let Err(e) = host_premise(host.pid, &exec) {
        return failed(e);
    }
    if let Err(e) = exec.prepare_budgeted() {
        return failed(format!("prepare: {e:?}"));
    }
    let mut state = exec.initial_state();
    let (rdi, rsi, rdx, rax, rcx) =
        MappedGuest::fixture_args(name, info.base, info.data, info.dst, info.src);
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = rax;
    state.rcx = rcx;
    // Opened after the install, while the host is stopped: from here
    // on the host runs only generated code.
    let pmu = perf_open(host.pid, false);
    let before = pmu.and_then(perf_read);
    let stop = exec.run_budgeted(state, RETURN_SENTINEL, k);
    let after = pmu.and_then(perf_read);
    perf_close(pmu);
    let single_steps = Some(exec.single_steps_for_test());
    let mut data = vec![0u8; 128];
    let mut dst = vec![0u8; 32];
    let mut stack = vec![0u8; 136];
    let read = exec.read_mem(info.data, &mut data)
        && exec.read_mem(info.dst, &mut dst)
        && exec.read_mem(info.stack_top - 128, &mut stack);
    let mem = Mem {
        ranges: [
            (info.base, 4096),
            (info.data, 128),
            (info.dst, host_dst_len(name)),
            (info.src, 32),
        ],
        stack_top: info.stack_top,
        data: &data,
        dst: &dst,
        stack: &stack,
    };
    let view = match (&stop, read) {
        (Ok(s), true) => Some(view(name, &s.outcome.state, s.outcome.instructions, &mem)),
        _ => None,
    };
    let stop = match (stop, read) {
        (Ok(s), true) => Ok(s),
        (Ok(_), false) => Err("attach memory read failed".to_string()),
        (Err(e), _) => Err(attach_error(&e)),
    };
    Measured {
        stop,
        view,
        pmu_delta: before.zip(after).map(|(b, a)| a.wrapping_sub(b)),
        single_steps,
        base: info.base,
    }
}

/// The Attach arm's W2 positive control: a plain unbudgeted attach
/// run of cpuid_leaf, on its own host process, steps its cpuid through
/// the remote engine's single-step site, so the counter the Attach rows
/// read must exceed 0 here. 0 is a W2 FAIL for the Attach arm. The
/// premise reads run first: the unbudgeted run consults the mirror.
fn w2_control_attach() -> Result<u64, String> {
    let name = "cpuid_leaf";
    let fixture = fixtures::by_name(name);
    let (host, _deadline) =
        deadline::attach_host(O1_CHILD, name).map_err(|e| format!("attach host: {e:?}"))?;
    let info = host.info;
    let region = RegionFacts {
        base: info.base,
        bytes: fixture.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    let profile = CountProfile::BranchesAndInstructions;
    let mut exec = AttachedExecutable::new(
        host.tracee,
        &host.site,
        host.arena,
        &info,
        region,
        info.base,
        profile,
    )
    .map_err(|e| format!("attach: {e:?}"))?;
    host_premise(host.pid, &exec)?;
    exec.prepare().map_err(|e| format!("prepare: {e:?}"))?;
    let mut state = exec.initial_state();
    let (rdi, rsi, rdx, rax, rcx) =
        MappedGuest::fixture_args(name, info.base, info.data, info.dst, info.src);
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = rax;
    state.rcx = rcx;
    exec.run(state, RETURN_SENTINEL)
        .map_err(|e| format!("run: {}", attach_error(&e)))?;
    Ok(exec.single_steps_for_test())
}

/// The core-limit premise, named C1 in failure messages: RLIMIT_CORE
/// soft = 1 for the test process, inherited by every
/// child at fork, so a CPU-cap hit leaves no piped core. That the kernel
/// aborts a piped dump at exactly 1 is what the core probe (`core_probe`) proves
/// or refutes on this host. Only the SOFT limit changes: the current
/// hard limit is kept, never lowered irreversibly. A hard limit below 1
/// cannot hold soft 1 and is a named failure.
fn core_limit_one() {
    let mut cur = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit on this process with a live struct.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut cur) };
    assert!(
        rc == 0,
        "C1: getrlimit(RLIMIT_CORE): {}",
        std::io::Error::last_os_error()
    );
    assert!(
        cur.rlim_max >= 1,
        "C1: RLIMIT_CORE hard limit {} is below 1",
        cur.rlim_max
    );
    let lim = libc::rlimit {
        rlim_cur: 1,
        rlim_max: cur.rlim_max,
    };
    // SAFETY: setrlimit on this process with a valid limit (soft <= hard).
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
    assert!(
        rc == 0,
        "C1: setrlimit(RLIMIT_CORE): {}",
        std::io::Error::last_os_error()
    );
}

/// One host for the naming controls: `attach_host`, then (the CPU-cap control only) the
/// host's own RLIMIT_CPU lowered to `cap` straight after it, then
/// `AttachedExecutable::new` over `bytes`, then the host premise reads.
/// Lowering a limit of this test's own same-uid child needs no
/// privilege.
fn control_host(
    name: &str,
    bytes: Vec<u8>,
    cap: Option<(u64, u64)>,
) -> Result<(AttachedExecutable, deadline::AttachHost, deadline::Deadline), String> {
    let (host, bound) =
        deadline::attach_host(O1_CHILD, name).map_err(|e| format!("attach host: {e:?}"))?;
    if let Some((soft, hard)) = cap {
        let lim = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        // SAFETY: prlimit on this test's own child, spawned and not
        // reaped; `lim` lowers its limits and no old limit is read.
        let rc =
            unsafe { libc::prlimit(host.pid, libc::RLIMIT_CPU, &lim, core::ptr::null_mut()) };
        if rc != 0 {
            return Err(format!("prlimit: {}", std::io::Error::last_os_error()));
        }
    }
    let info = host.info;
    let region = RegionFacts {
        base: info.base,
        bytes,
        generation: Generation(1),
        immutable_private: true,
    };
    let exec = AttachedExecutable::new(
        host.tracee,
        &host.site,
        host.arena,
        &info,
        region,
        info.base,
        CountProfile::BranchesAndInstructions,
    )
    .map_err(|e| format!("attach: {e:?}"))?;
    host_premise(host.pid, &exec)?;
    Ok((exec, host, bound))
}

/// PC-1, N1 and N2, the naming rule's controls. Each part has its own
/// host (prepare is one-shot). The result is the failures, empty when
/// all three pass.
/// - PC-1: a `jmp $` host whose own RLIMIT_CPU is lowered to {1, 2}
///   must stop with a Fault of signum 24, named
///   "CPU-cap FAIL: SIGXCPU (signal 24) at 0x...".
/// - N1: a load fault (fault_load, with rdi unmapped) must not be named
///   SIGXCPU.
/// - N2: a budgeted run of an unbudgeted translation must read exactly
///   "budget refusal, cause not named (no signum)".
fn naming_controls() -> Vec<String> {
    let mut failures = Vec::new();

    // PC-1.
    let pc1 = (|| -> Result<RunError, String> {
        let (mut exec, _host, _bound) = control_host("hex:ebfe", vec![0xeb, 0xfe], Some((1, 2)))?;
        exec.prepare_budgeted()
            .map_err(|e| format!("prepare: {e:?}"))?;
        let state = exec.initial_state();
        match exec.run_budgeted(state, RETURN_SENTINEL, 1) {
            Ok(stop) => Err(format!("run returned Ok: {stop:?}")),
            Err(e) => Ok(e),
        }
    })();
    match pc1 {
        Ok(e) => {
            let named = attach_error(&e);
            let is24 = matches!(&e, RunError::Fault(f) if f.signum == libc::SIGXCPU);
            if !(is24 && named.starts_with("CPU-cap FAIL: SIGXCPU (signal 24) at 0x")) {
                failures.push(format!(
                    "PC-1: expected Fault with signum 24, got {e:?} ({named})"
                ));
            }
        }
        Err(e) => failures.push(format!("PC-1: expected Fault with signum 24, got {e}")),
    }

    // N1.
    let n1 = (|| -> Result<RunError, String> {
        let name = "fault_load";
        let (mut exec, _host, _bound) = control_host(name, fixtures::by_name(name).bytes, None)?;
        exec.prepare_budgeted()
            .map_err(|e| format!("prepare: {e:?}"))?;
        let info = _host.info;
        let mut state = exec.initial_state();
        let (rdi, rsi, rdx, rax, rcx) =
            MappedGuest::fixture_args(name, info.base, info.data, info.dst, info.src);
        state.rdi = rdi;
        state.rsi = rsi;
        state.rdx = rdx;
        state.rax = rax;
        state.rcx = rcx;
        // An unmapped address, as remote_compare does for this fixture:
        // fixture_args gives rdi = data, a valid buffer, so the load
        // could never fault without it.
        state.rdi = 0x0dea_d000;
        match exec.run_budgeted(state, RETURN_SENTINEL, 1000) {
            Ok(stop) => Err(format!("run returned Ok: {stop:?}")),
            Err(e) => Ok(e),
        }
    })();
    match n1 {
        Ok(e) => {
            let named = attach_error(&e);
            let not24 = matches!(&e, RunError::Fault(f) if f.signum != libc::SIGXCPU);
            if !(not24 && !named.contains("SIGXCPU")) {
                failures.push(format!(
                    "N1: expected a Fault not named SIGXCPU, got {e:?} ({named})"
                ));
            }
        }
        Err(e) => failures.push(format!("N1: expected a Fault not named SIGXCPU, got {e}")),
    }

    // N2.
    let n2 = (|| -> Result<RunError, String> {
        let name = "sum_loop";
        let (mut exec, _host, _bound) = control_host(name, fixtures::by_name(name).bytes, None)?;
        exec.prepare().map_err(|e| format!("prepare: {e:?}"))?;
        let state = exec.initial_state();
        match exec.run_budgeted(state, RETURN_SENTINEL, 1) {
            Ok(stop) => Err(format!("run returned Ok: {stop:?}")),
            Err(e) => Ok(e),
        }
    })();
    match n2 {
        Ok(e) => {
            let named = attach_error(&e);
            if named != "budget refusal, cause not named (no signum)" {
                failures.push(format!(
                    "N2: expected exactly \"budget refusal, cause not named (no signum)\", got {e:?} ({named})"
                ));
            }
        }
        Err(e) => failures.push(format!(
            "N2: expected exactly \"budget refusal, cause not named (no signum)\", got {e}"
        )),
    }
    failures
}

/// PC-2, the proof of the core-limit premise on this host. The probe is this test binary
/// running `sigxcpu_core_probe`, untraced, started only through
/// `deadline::command_child`. Straight after that returns, and before
/// the wait, this parent lowers the probe's RLIMIT_CPU to {1, 65}: the
/// armed {60, 65} always comes first, so this only LOWERS the soft
/// limit, and the hard limit stays 65 so a hard-limit SIGKILL cannot
/// cut a slow dump short. PASS iff the probe ends by signal 24 with no
/// core dumped; a core means the core-limit premise FAILS.
fn core_probe() -> Result<(), String> {
    use std::os::unix::process::ExitStatusExt;
    let exe = std::env::current_exe().map_err(|e| format!("PC-2: current_exe: {e}"))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args([
        "--exact",
        "sigxcpu_core_probe",
        "--ignored",
        "--test-threads=1",
    ])
    .env("LITEINST_SIGXCPU_CORE_PROBE", "1")
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null());
    let (mut child, bound) =
        deadline::command_child(&mut cmd).map_err(|e| format!("PC-2: spawn: {e}"))?;
    let lim = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 65,
    };
    // SAFETY: prlimit on this test's own child, spawned and not reaped;
    // `lim` lowers its soft limit below the armed {60, 65}.
    let rc = unsafe {
        libc::prlimit(
            child.id() as i32,
            libc::RLIMIT_CPU,
            &lim,
            core::ptr::null_mut(),
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        drop(bound);
        return Err(format!("PC-2: prlimit: {err}"));
    }
    let status = child.wait().map_err(|e| format!("PC-2: wait: {e}"))?;
    drop(bound);
    if status.core_dumped() {
        return Err(format!(
            "PC-2: C1 FAILS: core dumped under RLIMIT_CORE 1: {status:?}"
        ));
    }
    if status.signal() != Some(libc::SIGXCPU) {
        return Err(format!(
            "PC-2: the probe did not end by signal 24: {status:?}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------
// The judge (pure; exercised on synthetic rows by the self-test).

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    InProcess,
    Remote,
    /// The attach-mode driver over an O1 host (LAST everywhere,
    /// so the arm-specific mutant kill lines keep their meaning).
    Attach,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum End {
    Landed,
    Handoff,
    Ended,
    Error,
}

/// One measured row: everything the judge reads.
#[derive(Clone, Debug)]
struct Row {
    mode: Mode,
    fixture: &'static str,
    k: u64,
    end: End,
    /// JIT-credited RCBs at the end (n for a handoff).
    jit_branches: u64,
    /// RCBs still owed at the end (k - n for a handoff).
    remaining: u64,
    /// The comparison oracle run reached its stop.
    oracle_stopped: bool,
    /// Oracle retired RCBs at that stop.
    oracle_branches: u64,
    /// Oracle class split at that stop: [Jcc, LOOP*, J*CXZ].
    by_class: [u64; 3],
    /// Single-steps of the oracle run to k (the oracle arm).
    oracle_steps: u64,
    /// The oracle run to k reached k (for a handoff: the tail
    /// can finish from the handoff point).
    tail_reachable: bool,
    /// First state/memory/count mismatch against the oracle.
    state_mismatch: Option<String>,
    /// Remote: single-steps in the JIT arm; in-process: no tracer.
    jit_single_steps: Option<u64>,
    exits: u64,
    entries: u64,
    poll_entries: u64,
    pmu_delta: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Verdict {
    /// Every witness holds on a landed row with k >= 1.
    Pass,
    /// Every witness holds on a handoff row (named, counted).
    HandoffPass,
    /// k = 0: entry landing; checked, never a PASS.
    Sanity,
    /// The PMU delta matches only without the LOOP class.
    Finding(&'static str),
    /// In-process calibration was not accepted: W3 not judged.
    Uncalibrated,
    /// No PMU reading on this host: W3 not judged, never a PASS
    /// (the suite stays green on hosts without a usable counter).
    NoPmu,
    Fail(String),
}

const LOOP_FINDING: &str = "PMU-LOOP-CLASS-NOT-COUNTED";

fn judge_row(r: &Row, inproc_calibrated: bool) -> Verdict {
    let fail = Verdict::Fail;
    // W1 first, so a budget off-by-one names W1 before the state.
    match r.end {
        End::Error => {
            return fail(format!(
                "RUN: {}",
                r.state_mismatch.clone().unwrap_or_default()
            ));
        }
        End::Ended => return fail(format!("W1: ended before k={}", r.k)),
        End::Landed => {
            if r.jit_branches != r.k || r.remaining != 0 {
                return fail(format!(
                    "W1: jit credited {} (owes {}), target {}",
                    r.jit_branches, r.remaining, r.k
                ));
            }
            if !r.oracle_stopped || r.oracle_branches != r.k {
                return fail(format!(
                    "W1: oracle at {} (stopped {}), target {}",
                    r.oracle_branches, r.oracle_stopped, r.k
                ));
            }
        }
        End::Handoff => {
            if r.jit_branches >= r.k || r.jit_branches + r.remaining != r.k {
                return fail(format!(
                    "W1: handoff n={} owes {}, target {}",
                    r.jit_branches, r.remaining, r.k
                ));
            }
            if !r.oracle_stopped || r.oracle_branches != r.jit_branches {
                return fail(format!(
                    "W1: oracle handoff point at {} (stopped {}), n={}",
                    r.oracle_branches, r.oracle_stopped, r.jit_branches
                ));
            }
            if !r.tail_reachable {
                return fail(format!("W1: oracle tail does not reach k={}", r.k));
            }
        }
    }
    if let Some(m) = &r.state_mismatch {
        return fail(format!("STATE: {m}"));
    }
    // W2. Attach is a tracer arm like Remote: Some(0) only, and never
    // judged as InProcess (so the calibration rule below skips it).
    match (r.mode, r.jit_single_steps) {
        (Mode::Remote, Some(0)) | (Mode::InProcess, None) | (Mode::Attach, Some(0)) => {}
        (m, s) => return fail(format!("W2: {m:?} jit single-steps {s:?}")),
    }
    if r.k >= 1 && r.oracle_steps == 0 {
        return fail("W2: oracle arm made no single-step".to_string());
    }
    // Non-vacuity, before any "W3 not judged" label: a missing
    // counter or a rejected calibration never exempts a row from it.
    if r.k == 0 {
        return Verdict::Sanity;
    }
    if r.exits == 0 {
        return fail("VACUOUS: no cache exit".to_string());
    }
    // W3.
    let Some(delta) = r.pmu_delta else {
        return Verdict::NoPmu;
    };
    if r.mode == Mode::InProcess && r.entries > 0 && !inproc_calibrated {
        return Verdict::Uncalibrated;
    }
    let expected = 2 * r.jit_branches + r.poll_entries;
    let loop_class = r.by_class[1] + r.by_class[2];
    if delta != expected {
        if loop_class > 0 && loop_class <= expected && delta == expected - loop_class {
            return Verdict::Finding(LOOP_FINDING);
        }
        return fail(format!("W3: PMU delta {delta}, expected {expected}"));
    }
    if r.end == End::Handoff {
        Verdict::HandoffPass
    } else {
        Verdict::Pass
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FixtureVerdict {
    Pass,
    /// Every k >= 1 row handed off (pre-stated handoff set only).
    HandoffOnly,
    /// The fixture retires no RCB: k = 0 only, not counted.
    NoRcb,
    /// A row is a named finding, uncalibrated or without a PMU
    /// reading; none failed and a non-vacuous row exists.
    NotPassed,
    Fail(String),
}

/// The fixtures E2 pre-states may hand off (syscall, cpuid). A
/// handoff anywhere else fails its fixture.
const E2_HANDOFF: [&str; 2] = ["syscall_write", "cpuid_leaf"];

/// Fixture verdict, in this order: any FAIL; no RCB; only sanity
/// rows (no non-vacuous row) is a FAIL; any row that ended in a
/// handoff (`handoff_rows`, keyed on the row's end, whatever its
/// verdict) on a fixture outside E2's set is a FAIL; then any
/// finding, uncalibrated or no-PMU row is NOT PASSED; then PASS, or
/// HANDOFF-ONLY.
fn judge_fixture(
    total: u64,
    verdicts: &[Verdict],
    handoff_rows: usize,
    handoff_allowed: bool,
) -> FixtureVerdict {
    if let Some(Verdict::Fail(f)) = verdicts.iter().find(|v| matches!(v, Verdict::Fail(_))) {
        return FixtureVerdict::Fail(f.clone());
    }
    if total == 0 {
        return FixtureVerdict::NoRcb;
    }
    if verdicts.iter().all(|v| *v == Verdict::Sanity) {
        return FixtureVerdict::Fail("no non-vacuous row".to_string());
    }
    if !handoff_allowed && handoff_rows > 0 {
        return FixtureVerdict::Fail("E2: handoff outside the pre-stated set".to_string());
    }
    if verdicts.iter().any(|v| {
        matches!(
            v,
            Verdict::Finding(_) | Verdict::Uncalibrated | Verdict::NoPmu
        )
    }) {
        return FixtureVerdict::NotPassed;
    }
    if verdicts.contains(&Verdict::Pass) {
        FixtureVerdict::Pass
    } else {
        FixtureVerdict::HandoffOnly
    }
}

/// Fixed before the run: every ret-only reading equals 1 (the
/// poll `jnz`), so the in-process window constant c is 0.
fn calibration_accepted(readings: &[Option<u64>]) -> bool {
    readings.len() == 2 * CALIBRATION_ENTRIES && readings.iter().all(|r| *r == Some(1))
}

#[derive(Debug, Eq, PartialEq)]
enum MutantVerdict {
    Killed,
    NoKill(&'static str),
}

/// A mutant is KILLED only by a libtest `test result: FAILED` line
/// together with the named W1 assertion text; a compile error is
/// never a kill.
fn judge_mutant_log(log: &str) -> MutantVerdict {
    if log.contains("error[E") || log.contains("could not compile") {
        return MutantVerdict::NoKill("compile error");
    }
    if !log.lines().any(|l| l.starts_with("test result: FAILED")) {
        return MutantVerdict::NoKill("no FAILED result line");
    }
    // The panic summary names the first failure ("first: ... W1: ...");
    // a W1 text anywhere else (a ROW line, a diagnostic) is not a kill.
    let first_is_w1 = log
        .lines()
        .any(|l| l.find("first: ").is_some_and(|i| l[i..].contains("W1: ")));
    if !first_is_w1 {
        return MutantVerdict::NoKill("first failure is not the W1 assertion");
    }
    MutantVerdict::Killed
}

// ---------------------------------------------------------------
// Row construction and the corpus run.

fn row(mode: Mode, name: &'static str, k: u64, m: &Measured, to_k: &OracleOutcome) -> Row {
    let mut r = Row {
        mode,
        fixture: name,
        k,
        end: End::Error,
        jit_branches: 0,
        remaining: 0,
        oracle_stopped: to_k.stopped_at_target,
        oracle_branches: to_k.branches,
        by_class: to_k.by_class,
        oracle_steps: to_k.steps,
        tail_reachable: to_k.stopped_at_target,
        state_mismatch: None,
        jit_single_steps: m.single_steps,
        exits: 0,
        entries: 0,
        poll_entries: 0,
        pmu_delta: m.pmu_delta,
    };
    let stop = match &m.stop {
        Ok(s) => s,
        Err(e) => {
            r.state_mismatch = Some(e.clone());
            return r;
        }
    };
    r.jit_branches = stop.outcome.branches;
    r.remaining = stop.remaining;
    r.exits = stop.outcome.exits;
    r.entries = stop.entries;
    r.poll_entries = stop.poll_entries;
    let cmp = match &stop.end {
        BudgetEnd::Landed => {
            r.end = End::Landed;
            None
        }
        BudgetEnd::Handoff { at, .. } => {
            r.end = End::Handoff;
            let stop_at = O1Stop {
                branches: stop.outcome.branches,
                at_offset: Some(at.wrapping_sub(m.base)),
            };
            Some(deadline::o1_until(O1_CHILD, name, stop_at))
        }
        BudgetEnd::Ended => {
            r.end = End::Ended;
            return r;
        }
    };
    let oracle = cmp.as_ref().unwrap_or(to_k);
    if cmp.is_some() {
        r.oracle_stopped = oracle.stopped_at_target;
        r.oracle_branches = oracle.branches;
        r.by_class = oracle.by_class;
    }
    if oracle.fault.is_some() {
        r.state_mismatch = Some(format!("oracle faulted: {:?}", oracle.fault));
        return r;
    }
    r.state_mismatch = match &m.view {
        Some(v) => first_mismatch(v, &oracle_view(name, oracle)),
        None => Some("no JIT view".to_string()),
    };
    r
}

fn end_label(r: &Row) -> &'static str {
    match r.end {
        End::Landed => "landed",
        End::Handoff => "handoff",
        End::Ended => "ended",
        End::Error => "error",
    }
}

/// The experiment itself. `#[ignore]`d on purpose: it needs a usable
/// PMU for its W3 witness, so it stays out of the crate's default
/// `cargo test` (and so out of every 01-05 mutation chain and the
/// run.sh baseline), and the launcher runs it by name with
/// `--ignored --exact`.
#[test]
#[ignore]
fn budget_tail_corpus_v1() {
    let _bound = deadline::TestBound::arm();
    // B2 and B3 (the CPU-cap section above): SIGXCPU must reach this
    // process with its default action, then the CPU caps. The test
    // process runs at {1800, 1805} CPU-s, and every child armed from
    // here at {60, 65}; soft < hard, so a cap hit is a NAMED SIGXCPU.
    sigxcpu_premise_self().unwrap_or_else(|e| panic!("{e}"));
    core_limit_one();
    own_cpu_cap(1800, 1805);
    deadline::set_child_cpu_cap(60, 65);
    let mut failures: Vec<String> = Vec::new();
    let control = w2_control();
    println!("W2-CONTROL\tsingle_steps={control:?}");
    if !matches!(control, Ok(n) if n > 0) {
        failures.push(format!("W2 control: counter did not count: {control:?}"));
    }
    let pmu_in = perf_open(0, true);
    println!(
        "PMU\tevent={:?}\tinprocess_fd_open={}",
        rcb_event(),
        pmu_in.is_some()
    );
    let mut readings = calibrate(pmu_in);
    let mut rows: Vec<(Row, u64)> = Vec::new();
    for name in FIXTURES {
        let full = deadline::o1(O1_CHILD, name, |_, _| {});
        assert_eq!(full.fault, None, "{name}: oracle full run faulted");
        let total = full.branches;
        let ks = targets(total);
        println!("FIXTURE\t{name}\tT={total}\ttargets={}", ks.len());
        for k in ks {
            let stop_k = O1Stop {
                branches: k,
                at_offset: None,
            };
            let to_k = deadline::o1_until(O1_CHILD, name, stop_k);
            let inproc = run_inprocess(name, k, pmu_in);
            rows.push((row(Mode::InProcess, name, k, &inproc, &to_k), total));
            let remote = run_remote(name, k);
            rows.push((row(Mode::Remote, name, k, &remote, &to_k), total));
            let attach = run_attach(name, k);
            rows.push((row(Mode::Attach, name, k, &attach, &to_k), total));
        }
    }
    readings.extend(calibrate(pmu_in));
    perf_close(pmu_in);
    let calibrated = calibration_accepted(&readings);
    println!("CALIBRATION\treadings={readings:?}\taccepted={calibrated}");
    println!(
        "COLUMNS\tmode\tfixture\tk\tT\tend\tjit_branches\tremaining\toracle_branches\t\
         oracle_steps\tby_class\tjit_single_steps\texits\tentries\tpoll_entries\tpmu_delta\t\
         expected\tverdict"
    );
    let mut judged: Vec<(Row, u64, Verdict)> = Vec::new();
    for (r, total) in rows {
        let v = judge_row(&r, calibrated);
        println!(
            "ROW\t{:?}\t{}\t{}\t{total}\t{}\t{}\t{}\t{}\t{}\t\
             {:?}\t{:?}\t{}\t{}\t{}\t{:?}\t{}\t{v:?}",
            r.mode,
            r.fixture,
            r.k,
            end_label(&r),
            r.jit_branches,
            r.remaining,
            r.oracle_branches,
            r.oracle_steps,
            r.by_class,
            r.jit_single_steps,
            r.exits,
            r.entries,
            r.poll_entries,
            r.pmu_delta,
            2 * r.jit_branches + r.poll_entries,
        );
        judged.push((r, total, v));
    }
    for mode in [Mode::InProcess, Mode::Remote, Mode::Attach] {
        let (mut landed, mut handoff) = (0u64, 0u64);
        for name in FIXTURES {
            let mine: Vec<&(Row, u64, Verdict)> = judged
                .iter()
                .filter(|(r, _, _)| r.mode == mode && r.fixture == name)
                .collect();
            let total = mine.first().map_or(0, |(_, t, _)| *t);
            let verdicts: Vec<Verdict> = mine.iter().map(|(_, _, v)| v.clone()).collect();
            for (r, _, v) in &mine {
                if let Verdict::Fail(f) = v {
                    failures.push(format!("{mode:?} {name} k={}: {f}", r.k));
                }
                if r.k >= 1 {
                    match r.end {
                        End::Landed => landed += 1,
                        End::Handoff => handoff += 1,
                        End::Ended | End::Error => {}
                    }
                }
            }
            let handoff_rows = mine
                .iter()
                .filter(|(r, _, _)| r.end == End::Handoff)
                .count();
            let fv = judge_fixture(total, &verdicts, handoff_rows, E2_HANDOFF.contains(&name));
            if let FixtureVerdict::Fail(f) = &fv {
                failures.push(format!("{mode:?} {name}: fixture: {f}"));
            }
            println!("VERDICT\t{mode:?}\t{name}\tT={total}\t{fv:?}");
        }
        println!("LANDED-FRACTION\t{mode:?}\tlanded={landed}\thandoff={handoff}");
        let count = |want: fn(&Verdict) -> bool| {
            judged
                .iter()
                .filter(|(r, _, v)| r.mode == mode && want(v))
                .count()
        };
        println!(
            "COUNTS\t{mode:?}\tpass={}\thandoff_pass={}\tsanity={}\tfinding={}\tuncalibrated={}\t\
             no_pmu={}\tfail={}",
            count(|v| *v == Verdict::Pass),
            count(|v| *v == Verdict::HandoffPass),
            count(|v| *v == Verdict::Sanity),
            count(|v| matches!(v, Verdict::Finding(_))),
            count(|v| *v == Verdict::Uncalibrated),
            count(|v| *v == Verdict::NoPmu),
            count(|v| matches!(v, Verdict::Fail(_))),
        );
    }
    // The Attach arm's W2 positive control. Its failure is pushed
    // LAST, as every Attach failure is, so the arm-specific mutant kill
    // lines keep naming the first failing InProcess or Remote row.
    let control_attach = w2_control_attach();
    println!("W2-CONTROL-ATTACH\tsingle_steps={control_attach:?}");
    if !matches!(control_attach, Ok(n) if n > 0) {
        failures.push(format!(
            "Attach W2 control: counter did not count: {control_attach:?}"
        ));
    }
    // PC-1, N1 and N2, the naming rule's controls, then PC-2, the proof
    // of the core-limit premise on this host. Their failures are pushed
    // LAST, as every Attach failure is.
    let naming = naming_controls();
    println!("NAMING-CONTROLS\t{naming:?}");
    failures.extend(naming);
    let probe = core_probe();
    println!("CORE-PROBE\t{probe:?}");
    if let Err(e) = probe {
        failures.push(e);
    }
    assert!(
        failures.is_empty(),
        "budget tail FAILED: {} failing rows or fixtures; first: {}",
        failures.len(),
        failures.first().map_or("", String::as_str)
    );
}

// ---------------------------------------------------------------
// Judge self-test on synthetic rows (no child, no JIT).

fn synthetic() -> Row {
    Row {
        mode: Mode::Remote,
        fixture: "synthetic",
        k: 5,
        end: End::Landed,
        jit_branches: 5,
        remaining: 0,
        oracle_stopped: true,
        oracle_branches: 5,
        by_class: [5, 0, 0],
        oracle_steps: 40,
        tail_reachable: true,
        state_mismatch: None,
        jit_single_steps: Some(0),
        exits: 3,
        entries: 3,
        poll_entries: 4,
        pmu_delta: Some(14),
    }
}

fn is_fail_named(v: &Verdict, prefix: &str) -> bool {
    matches!(v, Verdict::Fail(s) if s.starts_with(prefix))
}

/// The Attach arm's single W2 change: an Attach row passes W2 with `Some(0)`
/// single-steps only, and is never judged as InProcess, so the
/// in-process calibration rule never applies to it.
#[test]
fn judge_selftest_attach_w2() {
    let _bound = deadline::TestBound::arm();
    let mut base = synthetic();
    base.mode = Mode::Attach;
    assert_eq!(
        judge_row(&base, true),
        Verdict::Pass,
        "an Attach row with Some(0) passes W2"
    );
    for steps in [Some(1), None] {
        let mut r = base.clone();
        r.jit_single_steps = steps;
        assert!(
            is_fail_named(&judge_row(&r, true), "W2: "),
            "an Attach row with jit single-steps {steps:?} must fail W2"
        );
    }
    assert!(base.entries > 0, "the synthetic row has cache entries");
    assert_ne!(
        judge_row(&base, false),
        Verdict::Uncalibrated,
        "an Attach row is never judged as InProcess"
    );
    assert_eq!(
        judge_row(&base, false),
        Verdict::Pass,
        "an Attach row's W3 does not depend on in-process calibration"
    );
}

#[test]
fn judge_selftest_rows() {
    let _bound = deadline::TestBound::arm();
    let base = synthetic();
    assert_eq!(judge_row(&base, true), Verdict::Pass, "true PASS");

    let mut r = base.clone();
    r.k = 0;
    r.jit_branches = 0;
    r.oracle_branches = 0;
    r.by_class = [0, 0, 0];
    r.oracle_steps = 0;
    r.exits = 0;
    r.entries = 0;
    r.poll_entries = 0;
    r.pmu_delta = Some(0);
    assert_eq!(judge_row(&r, true), Verdict::Sanity, "k=0 is sanity only");
    assert_eq!(
        judge_fixture(5, &[Verdict::Sanity], 0, false),
        FixtureVerdict::Fail("no non-vacuous row".to_string()),
        "a fixture with branches and only k=0 must not pass"
    );
    assert_eq!(
        judge_fixture(0, &[Verdict::Sanity], 0, false),
        FixtureVerdict::NoRcb
    );

    // R-3: a missing PMU reading never exempts from non-vacuity.
    let mut sanity_no_pmu = r.clone();
    sanity_no_pmu.pmu_delta = None;
    assert_eq!(
        judge_row(&sanity_no_pmu, true),
        Verdict::Sanity,
        "a k=0 row is sanity whatever the PMU"
    );
    assert_eq!(
        judge_fixture(5, &[judge_row(&sanity_no_pmu, true)], 0, false),
        FixtureVerdict::Fail("no non-vacuous row".to_string()),
        "a no-PMU fixture with only sanity rows must FAIL"
    );
    let mut vacuous_no_pmu = base.clone();
    vacuous_no_pmu.exits = 0;
    vacuous_no_pmu.pmu_delta = None;
    assert!(
        is_fail_named(&judge_row(&vacuous_no_pmu, true), "VACUOUS: "),
        "a vacuous row with no PMU reading must FAIL"
    );
    let mut vacuous_uncal = vacuous_no_pmu.clone();
    vacuous_uncal.mode = Mode::InProcess;
    vacuous_uncal.jit_single_steps = None;
    vacuous_uncal.pmu_delta = Some(14);
    assert!(
        is_fail_named(&judge_row(&vacuous_uncal, false), "VACUOUS: "),
        "a vacuous row with a rejected calibration must FAIL"
    );

    let mut r = base.clone();
    r.jit_branches = 6;
    assert!(is_fail_named(&judge_row(&r, true), "W1: "), "W1 off by one");

    let mut r = base.clone();
    r.oracle_branches = 4;
    assert!(
        is_fail_named(&judge_row(&r, true), "W1: "),
        "oracle off by one"
    );

    let mut r = base.clone();
    r.end = End::Ended;
    assert!(
        is_fail_named(&judge_row(&r, true), "W1: "),
        "ended before k"
    );

    let mut r = base.clone();
    r.jit_single_steps = Some(1);
    assert!(is_fail_named(&judge_row(&r, true), "W2: "), "W2 = 1");

    let mut r = base.clone();
    r.mode = Mode::InProcess;
    r.jit_single_steps = Some(0);
    assert!(
        is_fail_named(&judge_row(&r, true), "W2: "),
        "in-process has no tracer: a step count is a wiring error"
    );

    let mut r = base.clone();
    r.oracle_steps = 0;
    assert!(
        is_fail_named(&judge_row(&r, true), "W2: "),
        "vacuous oracle arm"
    );

    let mut r = base.clone();
    r.pmu_delta = Some(15);
    assert!(is_fail_named(&judge_row(&r, true), "W3: "), "W3 off by one");

    let mut r = base.clone();
    r.pmu_delta = None;
    assert_eq!(
        judge_row(&r, true),
        Verdict::NoPmu,
        "no PMU is never a PASS"
    );
    assert_eq!(
        judge_fixture(5, &[Verdict::Pass, Verdict::NoPmu], 0, false),
        FixtureVerdict::NotPassed,
        "a row without a PMU reading keeps the fixture from PASS"
    );

    let mut r = base.clone();
    r.by_class = [2, 3, 0];
    r.pmu_delta = Some(14 - 3);
    assert_eq!(
        judge_row(&r, true),
        Verdict::Finding(LOOP_FINDING),
        "LOOP-class pattern is a named finding"
    );
    assert_eq!(
        judge_fixture(
            5,
            &[Verdict::Pass, Verdict::Finding(LOOP_FINDING)],
            0,
            false
        ),
        FixtureVerdict::NotPassed,
        "a finding never makes a fixture PASS"
    );

    let mut r = base.clone();
    r.mode = Mode::InProcess;
    r.jit_single_steps = None;
    assert_eq!(
        judge_row(&r, false),
        Verdict::Uncalibrated,
        "uncalibrated c"
    );
    assert_eq!(judge_row(&r, true), Verdict::Pass, "calibrated in-process");

    let mut r = base.clone();
    r.end = End::Handoff;
    r.jit_branches = 2;
    r.remaining = 2;
    r.oracle_branches = 2;
    r.pmu_delta = Some(2 * 2 + 4);
    assert!(
        is_fail_named(&judge_row(&r, true), "W1: "),
        "handoff with an n mismatch"
    );
    r.remaining = 3;
    assert_eq!(judge_row(&r, true), Verdict::HandoffPass, "counted handoff");
    r.tail_reachable = false;
    assert!(
        is_fail_named(&judge_row(&r, true), "W1: "),
        "unreachable tail"
    );

    let mut r = base.clone();
    r.state_mismatch = Some("register rax".to_string());
    assert!(
        is_fail_named(&judge_row(&r, true), "STATE: "),
        "state mismatch"
    );

    let mut r = base.clone();
    r.end = End::Error;
    r.state_mismatch = Some("prepare: refused".to_string());
    assert!(is_fail_named(&judge_row(&r, true), "RUN: "), "run error");

    assert_eq!(
        judge_fixture(5, &[Verdict::HandoffPass], 1, true),
        FixtureVerdict::HandoffOnly,
        "handoff-only inside E2's set"
    );
    assert_eq!(
        judge_fixture(5, &[Verdict::Pass, Verdict::HandoffPass], 1, false),
        FixtureVerdict::Fail("E2: handoff outside the pre-stated set".to_string()),
        "a handoff outside E2's set fails its fixture"
    );
    assert_eq!(
        judge_fixture(5, &[Verdict::Pass, Verdict::NoPmu], 1, false),
        FixtureVerdict::Fail("E2: handoff outside the pre-stated set".to_string()),
        "N2-5: a handoff row whose verdict is NoPmu still fails E2"
    );
    assert_eq!(
        judge_fixture(5, &[Verdict::Pass, Verdict::HandoffPass], 1, true),
        FixtureVerdict::Pass
    );
    assert_eq!(
        judge_fixture(
            5,
            &[Verdict::Pass, Verdict::Fail("W1: x".to_string())],
            0,
            true
        ),
        FixtureVerdict::Fail("W1: x".to_string())
    );
    assert_eq!(
        judge_fixture(5, &[], 0, false),
        FixtureVerdict::Fail("no non-vacuous row".to_string()),
        "no rows at all is not a pass"
    );
    assert!(E2_HANDOFF.iter().all(|f| FIXTURES.contains(f)));

    let ok = vec![Some(1u64); 2 * CALIBRATION_ENTRIES];
    assert!(calibration_accepted(&ok));
    let mut two = ok.clone();
    two[3] = Some(2);
    assert!(!calibration_accepted(&two), "a reading of 2 rejects c = 0");
    let mut none = ok.clone();
    none[0] = None;
    assert!(!calibration_accepted(&none), "a missing reading rejects");
    assert!(
        !calibration_accepted(&ok[1..]),
        "a short calibration rejects"
    );

    assert_eq!(targets(0), vec![0]);
    assert_eq!(targets(2), vec![0, 1, 2]);
    assert_eq!(targets(17).len(), 18);
    assert!(targets(1000).len() <= 20);
    assert_eq!(targets(1000).first(), Some(&0));
    assert_eq!(targets(1000).last(), Some(&1000));
}

#[test]
fn judge_selftest_mutant_logs() {
    let _bound = deadline::TestBound::arm();
    let killed = "running 1 test\nbudget tail FAILED: 3 failing rows or fixtures; first: \
                  Remote sum_loop k=1: W1: jit credited 2 (owes 0), target 1\n\
                  test result: FAILED. 2 passed; 1 failed\n";
    assert_eq!(judge_mutant_log(killed), MutantVerdict::Killed);
    let green = "running 1 test\ntest result: ok. 3 passed; 0 failed\n";
    assert_eq!(
        judge_mutant_log(green),
        MutantVerdict::NoKill("no FAILED result line")
    );
    let compile = "error[E0308]: mismatched types\nerror: could not compile `liteinst-jit`\n";
    assert_eq!(
        judge_mutant_log(compile),
        MutantVerdict::NoKill("compile error")
    );
    let other = "first: Remote sum_loop k=1: W3: PMU delta 9, expected 8\n\
                 test result: FAILED. 2 passed; 1 failed\n";
    assert_eq!(
        judge_mutant_log(other),
        MutantVerdict::NoKill("first failure is not the W1 assertion")
    );
    // W1 text on a ROW line only, with a W3 first failure: no kill.
    let w1_elsewhere = "ROW\tRemote\tsum_loop\t1\tFail(\"W1: x\")\n\
                        budget tail FAILED: 2 failing rows; first: Remote k=1: W3: delta\n\
                        test result: FAILED. 0 passed; 1 failed\n";
    assert_eq!(
        judge_mutant_log(w1_elsewhere),
        MutantVerdict::NoKill("first failure is not the W1 assertion")
    );
}

/// The mutant leg's verdict: judges the log named by
/// `BUDGET_MUTANT_LOG` and fails unless the mutant was KILLED. Run
/// only by the launcher (`--ignored`); without the variable it
/// fails by name, never passes vacuously.
#[test]
#[ignore]
fn mutant_log_verdict() {
    let _bound = deadline::TestBound::arm();
    let path = std::env::var("BUDGET_MUTANT_LOG").expect("BUDGET_MUTANT_LOG unset");
    let log = std::fs::read_to_string(&path).expect("read the mutant log");
    let v = judge_mutant_log(&log);
    println!("MUTANT-VERDICT\t{path}\t{v:?}");
    assert_eq!(v, MutantVerdict::Killed, "mutant not killed");
}

/// PC-2's probe (`core_probe`). It
/// spins only when LITEINST_SIGXCPU_CORE_PROBE is set, which only PC-2 sets; any other run returns at once.
/// It sets no CPU limit of its own: PC-2's parent lowers it, so the
/// order of the two prlimit calls is fixed in one thread. It is not
/// traced, and it inherits the core-limit premise's RLIMIT_CORE {soft 1, hard = the test
/// process's current hard limit}.
#[test]
#[ignore]
fn sigxcpu_core_probe() {
    let _bound = deadline::TestBound::arm();
    if std::env::var_os("LITEINST_SIGXCPU_CORE_PROBE").is_none() {
        return;
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Spawn census: every child this binary starts carries a run
/// deadline (`common/deadline.rs`).
#[test]
fn spawn_census() {
    deadline::spawn_census(include_str!("budget_tail.rs"), "budget_tail.rs");
}

/// Bound census: every test here arms a `TestBound`.
#[test]
fn bound_census() {
    deadline::bound_census(
        include_str!("budget_tail.rs"),
        "budget_tail.rs",
        &["spawn_census", "bound_census"],
    );
}
