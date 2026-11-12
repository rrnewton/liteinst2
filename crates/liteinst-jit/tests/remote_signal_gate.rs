//! I1-H H1 gate evidence: deterministic signal arrival at
//! generated PCs, checked against the O1-S native oracle.
//!
//! - **Arrival.** The tracer's test seam arms one hardware
//!   execute breakpoint (DR0/DR7) at a chosen generated PC and,
//!   on its chosen hit, sends SIGUSR1 to its own child. The
//!   kernel then presents the delivery stop exactly there (see
//!   `ArrivalSeam`). No trace flag is involved.
//! - **Oracle.** For every delivered arrival, the seam records
//!   the recovered `(src_pc, instructions, branches)`. O1-S then
//!   steps the same bytes natively and sends SIGUSR1 to its own
//!   child after exactly that many retired instructions. Both
//!   runs must agree on:
//!   - the handler-visible frame: siginfo, all 18 ucontext
//!     registers, and the saved mask;
//!   - the final register image;
//!   - the instruction and branch counts;
//!   - the guest buffer.
//!
//!   Addresses are normalized to (region, offset), because each
//!   run gets its own child.
//! - **Classes.** Each arrival is classified by the PC-map
//!   class of its generated PC: delivered-and-equal, a named
//!   refusal in an allowed window (W1: the common exit; W2: no
//!   PC-map entry), or a failure.
//! - **Instance (H2a).** The survey's counting runs record what
//!   recovery names at every hit; each arrival must recover
//!   exactly that record for its (PC, hit), independent of the
//!   seam's own hit counter. Plan sizes and outcome totals are
//!   pinned, and a sweep that reaches its cap fails.
//! - **Closed in H2a.** W5 (the poll's blocked mask is the
//!   kernel's `SigBlk`) and the poll budget after a delivery from
//!   a budget-0 stop (polls are counted by the seam).
//! - **Closed in H2b.** W1 (arrivals in the common exit of a
//!   RETURN, SYSCALL, NONDET or POLL exit deliver; INDIRECT keeps
//!   the named refusal) and W3 (an arrival before the original
//!   `cpuid` step delivers). Comparisons use tagged normalization.
//!
//! Fixture layout (buffer at r13 = dst; r13 is never written by
//! guest code):
//! - one SA_SIGINFO handler at offset 0, logging into `SLOT`;
//! - the restorer;
//! - main, whose prologue block installs the handler;
//! - the body, which starts at the next block.
//!
//! Each test holds `SERIAL`, so ptrace children and signals from
//! different tests never overlap. Every child, remote or O1-S,
//! also carries a run deadline (`common/deadline.rs`).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[path = "common/corpus.rs"]
mod corpus;
#[path = "common/deadline.rs"]
mod deadline;

use iced_x86::BlockEncoderOptions;
use iced_x86::code_asm::*;
use liteinst_jit::exec::{FaultKind, Outcome, RunError};
use liteinst_jit::harness::RETURN_SENTINEL;
use liteinst_jit::o1::{O1sEnd, O1sOutcome};
use liteinst_jit::remote::{
    ArrivalReport, ArrivalSeam, RemoteChildInfo, RemoteExecutable, SeamHit, W3Perturb,
};
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};
use liteinst_jit::{CallStage, CommonStage, ExitStage, PcMapEntry, Recovery, StubStage};

const REMOTE_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-remote-child");

static SERIAL: Mutex<()> = Mutex::new(());

/// One test's hold: the serial lock, and the corpus guard every
/// pinning test carries (see `corpus`).
struct Serial {
    _corpus: corpus::Guard,
    _lock: std::sync::MutexGuard<'static, ()>,
}

fn lock() -> Serial {
    Serial {
        _lock: SERIAL.lock().unwrap_or_else(|e| e.into_inner()),
        _corpus: corpus::guard(),
    }
}

/// A remote child for `bytes`, armed with its run deadline (see
/// `common/deadline.rs`). Hold the deadline as long as the
/// executable (the pidfd makes the drop order irrelevant to safety).
fn spawn_remote(bytes: &[u8]) -> (RemoteExecutable, deadline::Deadline) {
    deadline::remote_bytes(REMOTE_CHILD, bytes).expect("spawn remote")
}

const USR1: i32 = libc::SIGUSR1;
/// SA_SIGINFO | SA_RESTORER.
const FLAGS: u32 = 0x0400_0004;

/// Buffer offsets at r13 (dst, 8 KiB in the remote child).
const ACT: i32 = 0;
const RC: i32 = 64;
const COUNT: i32 = 72;
/// Handler log: siginfo words 0..4, uc gregs 0..18, uc_sigmask.
const SLOT: i32 = 128;
const SLOT_WORDS: usize = 4 + 18 + 1;
const SCRATCH: i32 = 512;
/// Bytes of dst compared between runs.
const REPORT: usize = 1024;

/// `uc_mcontext` R15 (greg 7): the handler adds `R15_MARK` to it
/// in the frame, so the resumed state must come from the frame.
const UC_R15: i32 = 40 + 7 * 8;
const R15_MARK: i32 = 0x100;

/// Ucontext greg names in kernel order, for messages.
const GREG_NAMES: [&str; 18] = [
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp", "rbx", "rdx", "rax",
    "rcx", "rsp", "rip", "eflags",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Body {
    /// Straight-line body exercising every machinery class:
    /// flags arithmetic, a 3-iteration loop, a direct call, a
    /// taken conditional, a pass-through `write`, and `cpuid`.
    Mixed,
    /// A counted loop of `n` iterations (a poll-crossing loop
    /// under the poll-budget seam).
    Loop(u32),
}

struct Gx {
    bytes: Vec<u8>,
    handler_off: u64,
    restorer_off: u64,
    main_off: u64,
    /// First source offset after the install (the body).
    body_off: u64,
    /// Offset of the body's `cpuid` (Mixed only).
    cpuid_off: Option<u64>,
    /// The Mixed body's dispatcher exits in execution order: the
    /// helper's `ret`, the `write` syscall, `cpuid`, main's final
    /// `ret`.
    exit_offs: Option<[u64; 4]>,
}

fn emit_handler(a: &mut CodeAssembler) {
    emit_handler_body(a, SLOT, COUNT);
    a.ret().unwrap();
}

/// The logging handler without its `ret`: siginfo words 0..4, uc
/// gregs and mask into `slot`, the R15 mark in the frame, and one
/// increment of the counter at `count`. With `SLOT` and `COUNT`
/// these are exactly `emit_handler`'s bytes (pinned fixtures).
fn emit_handler_body(a: &mut CodeAssembler, slot: i32, count: i32) {
    for i in 0..4 {
        a.mov(rax, qword_ptr(rsi + 8 * i)).unwrap();
        a.mov(qword_ptr(r13 + (slot + 8 * i)), rax).unwrap();
    }
    for i in 0..18 {
        a.mov(rax, qword_ptr(rdx + (40 + 8 * i))).unwrap();
        a.mov(qword_ptr(r13 + (slot + 32 + 8 * i)), rax).unwrap();
    }
    a.mov(rax, qword_ptr(rdx + 296)).unwrap();
    a.mov(qword_ptr(r13 + (slot + 176)), rax).unwrap();
    a.add(qword_ptr(rdx + UC_R15), R15_MARK).unwrap();
    a.inc(qword_ptr(r13 + count)).unwrap();
}

fn build(body: Body) -> Gx {
    let mut a = CodeAssembler::new(64).unwrap();
    let mut handler = a.create_label();
    let mut restorer = a.create_label();
    let mut main = a.create_label();
    let mut body_l = a.create_label();
    let mut cpuid_l = a.create_label();
    let mut write_l = a.create_label();
    let mut helper_ret_l = a.create_label();
    let mut main_ret_l = a.create_label();
    a.set_label(&mut handler).unwrap();
    emit_handler(&mut a);
    a.set_label(&mut restorer).unwrap();
    a.db(&[0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05]).unwrap();
    // Prologue block: install the USR1 handler (ends at the
    // rt_sigaction syscall, so the body is the next block).
    a.set_label(&mut main).unwrap();
    a.lea(rax, qword_ptr(rbp)).unwrap();
    a.mov(qword_ptr(r13 + ACT), rax).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 8)), FLAGS).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 12)), 0u32).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 16)), r12).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 24)), 0).unwrap();
    a.mov(edi, USR1 as u32).unwrap();
    a.lea(rsi, qword_ptr(r13 + ACT)).unwrap();
    a.xor(edx, edx).unwrap();
    a.mov(r10d, 8u32).unwrap();
    a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
    a.syscall().unwrap();
    a.set_label(&mut body_l).unwrap();
    a.mov(qword_ptr(r13 + RC), rax).unwrap();
    // Translator reachability for the handler block.
    a.cmp(rcx, rcx).unwrap();
    a.jne(handler).unwrap();
    let mut has_cpuid = false;
    match body {
        Body::Mixed => {
            let mut lp = a.create_label();
            let mut helper = a.create_label();
            let mut skip = a.create_label();
            a.xor(r15d, r15d).unwrap();
            a.mov(ecx, 3u32).unwrap();
            a.set_label(&mut lp).unwrap();
            a.add(r15, rcx).unwrap();
            a.lea(r14, qword_ptr(r15 + r15 * 2)).unwrap();
            a.dec(ecx).unwrap();
            a.jnz(lp).unwrap();
            a.call(helper).unwrap();
            a.test(r15b, 1).unwrap();
            a.je(skip).unwrap();
            a.inc(r14).unwrap();
            a.set_label(&mut skip).unwrap();
            // CF from a compare (6 < 18 borrows), consumed by adc.
            a.cmp(r15, r14).unwrap();
            a.adc(r14, 0).unwrap();
            a.mov(qword_ptr(r13 + SCRATCH), r14).unwrap();
            // write(-1, NULL, 0): a deterministic -EBADF.
            a.mov(edi, u32::MAX).unwrap();
            a.xor(esi, esi).unwrap();
            a.xor(edx, edx).unwrap();
            a.mov(eax, libc::SYS_write as u32).unwrap();
            a.set_label(&mut write_l).unwrap();
            a.syscall().unwrap();
            a.mov(qword_ptr(r13 + (SCRATCH + 8)), rax).unwrap();
            // cpuid leaf 0: identical on every core.
            a.xor(eax, eax).unwrap();
            a.xor(ecx, ecx).unwrap();
            a.set_label(&mut cpuid_l).unwrap();
            a.cpuid().unwrap();
            a.mov(qword_ptr(r13 + (SCRATCH + 16)), rbx).unwrap();
            a.mov(eax, 42u32).unwrap();
            a.set_label(&mut main_ret_l).unwrap();
            a.ret().unwrap();
            a.set_label(&mut helper).unwrap();
            a.lea(r10, qword_ptr(r15 + 5)).unwrap();
            a.set_label(&mut helper_ret_l).unwrap();
            a.ret().unwrap();
            has_cpuid = true;
        }
        Body::Loop(n) => {
            let mut lp = a.create_label();
            a.xor(r15d, r15d).unwrap();
            a.mov(ecx, n).unwrap();
            a.set_label(&mut lp).unwrap();
            a.add(r15, rcx).unwrap();
            a.dec(ecx).unwrap();
            a.jnz(lp).unwrap();
            a.mov(qword_ptr(r13 + SCRATCH), r15).unwrap();
            a.mov(eax, 42u32).unwrap();
            a.ret().unwrap();
        }
    }
    let res = a
        .assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .unwrap();
    assert_eq!(res.label_ip(&handler).unwrap(), 0, "handler at 0");
    let id = match body {
        Body::Mixed => "H1 sweep mixed".to_string(),
        Body::Loop(n) => format!("H1 sweep loop {n}"),
    };
    corpus::check(&id, &res.inner.code_buffer);
    Gx {
        bytes: res.inner.code_buffer.clone(),
        handler_off: 0,
        restorer_off: res.label_ip(&restorer).unwrap(),
        main_off: res.label_ip(&main).unwrap(),
        body_off: res.label_ip(&body_l).unwrap(),
        cpuid_off: has_cpuid.then(|| res.label_ip(&cpuid_l).unwrap()),
        exit_offs: has_cpuid.then(|| {
            [&helper_ret_l, &write_l, &cpuid_l, &main_ret_l].map(|l| res.label_ip(l).unwrap())
        }),
    }
}

/// A normalized word (I1-H H2b, Q-d): tagged, so a raw value can
/// never compare equal to a region offset or the own-pid token,
/// whatever its bits. Equal tagged words are equal under the old
/// untagged encoding too, so tagging only adds failures, and only
/// where a raw value collides with a token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Norm {
    Raw(u64),
    /// (region id, offset).
    Region(u8, u64),
    /// The child's own pid in the low half (each run has its own
    /// child); `high` is the word's upper half (0 in RDI, the uid
    /// in a siginfo sender word).
    OwnPid {
        high: u64,
    },
}

/// Normalize a value to its (region, offset) when it points into
/// one of the child's known regions; other values stay raw.
/// Generated (arena) addresses are deliberately not a region: one
/// leaking into guest state is a mismatch.
fn norm(v: u64, info: &RemoteChildInfo, code_len: u64) -> Norm {
    let stack_lo = info.stack_top - 64 * 1024 + 8;
    let regions = [
        (info.base, code_len),
        (stack_lo, info.stack_top + 8 - stack_lo),
        (info.dst, 8192),
        (info.src, 8192),
        (info.data, 128),
    ];
    for (i, &(lo, len)) in regions.iter().enumerate() {
        if v >= lo && v <= lo + len {
            return Norm::Region(i as u8 + 1, v - lo);
        }
    }
    Norm::Raw(v)
}

fn word(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

/// The 18 registers of a `GuestState`, in ucontext greg order.
fn state_gregs(s: &liteinst_jit::GuestState) -> [u64; 18] {
    [
        s.r8, s.r9, s.r10, s.r11, s.r12, s.r13, s.r14, s.r15, s.rdi, s.rsi, s.rbp, s.rbx, s.rdx,
        s.rax, s.rcx, s.rsp, s.rip, s.rflags,
    ]
}

/// Normalized registers. EFLAGS compares exactly: neither
/// engine's guest sets TF or RF, so an observer flag leaking into
/// guest-visible state (the seam's RF, the oracle's TF) is a
/// mismatch, not noise.
fn norm_gregs(g: &[u64; 18], info: &RemoteChildInfo, code_len: u64) -> [Norm; 18] {
    core::array::from_fn(|i| {
        if i == 17 {
            Norm::Raw(g[i])
        } else {
            norm(g[i], info, code_len)
        }
    })
}

/// Normalized guest buffer: `REPORT` bytes as words.
/// A siginfo sender word (pid | uid << 32) logged for an arrival
/// needs no special case: both engines' arrival signal comes from
/// this test process, and the word lies in no address region. A
/// signal the guest sends itself carries its own child's pid, so
/// that one word is named by exact position (`norm_buffer_pid`).
fn norm_buffer(d: &[u8], info: &RemoteChildInfo, code_len: u64) -> Vec<Norm> {
    norm_buffer_pid(d, info, code_len, 0, &[])
}

/// [`norm_buffer`], with the words at `own_pid_words` (buffer word
/// indices of self-sent siginfo sender words) tagged as the own
/// pid when their low half is `pid` (I1-H H2b, Q-d). No other word
/// is pid-normalized.
fn norm_buffer_pid(
    d: &[u8],
    info: &RemoteChildInfo,
    code_len: u64,
    pid: i32,
    own_pid_words: &[usize],
) -> Vec<Norm> {
    (0..REPORT / 8)
        .map(|i| {
            let w = word(d, i * 8);
            if own_pid_words.contains(&i) && (w & 0xffff_ffff) == u64::from(pid as u32) {
                Norm::OwnPid { high: w >> 32 }
            } else {
                norm(w, info, code_len)
            }
        })
        .collect()
}

struct TArrival {
    out: Result<Outcome, RunError>,
    report: ArrivalReport,
    data: Vec<u8>,
    info: RemoteChildInfo,
    /// The arrival's generated PC and its PC-map entry.
    target: Option<(u64, PcMapEntry)>,
    entries: usize,
    /// DR0/DR7 read back after the run.
    debug_regs: Option<(u64, u64)>,
    /// The child's pid.
    pid: i32,
}

/// Knobs for one translated run.
#[derive(Clone, Copy, Default)]
struct Knobs {
    /// Arrival at PC-map entry `index`, on hit `hit`.
    arrival: Option<(usize, u64)>,
    /// The arrival's signal (`None`: SIGUSR1).
    arrival_sig: Option<i32>,
    poll_budget: Option<u64>,
    pre_original_step_signal: Option<i32>,
    /// Seam (I1-H H2c): SIGUSR1 interrupts per successive original
    /// instruction (overrides `pre_original_step_signal`).
    pre_original_step_plan: Option<&'static [u32]>,
    /// Seam: a raw poll budget of 0 at every mid-block restore.
    zero_raw_poll_at_restore: bool,
    /// Seam: perturb one comparand of the W3 provenance guard.
    w3_perturb: Option<W3Perturb>,
}

fn run_translated(gx: &Gx, k: Knobs) -> TArrival {
    let (mut remote, deadline) = spawn_remote(&gx.bytes);
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: gx.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(
            &region,
            info.base + gx.main_off,
            CountProfile::BranchesAndInstructions,
        )
        .expect("prepare remote");
    let (entries, target) = {
        let t = remote.translation_for_test().expect("prepared");
        let target = k.arrival.map(|(idx, _)| {
            let e = t.pcmap.entries()[idx];
            (e.gen_start, e)
        });
        (t.pcmap.len(), target)
    };
    remote.set_arrival_for_test(
        k.arrival
            .zip(target)
            .map(|((_, hit), (gen_pc, _))| ArrivalSeam {
                gen_pc,
                hit,
                sig: k.arrival_sig.unwrap_or(USR1),
            }),
    );
    remote.set_poll_budget_for_test(k.poll_budget);
    match k.pre_original_step_plan {
        Some(plan) => remote.set_pre_original_step_plan_for_test(USR1, plan.to_vec()),
        None => remote.set_pre_original_step_signal_for_test(k.pre_original_step_signal),
    }
    remote.set_zero_raw_poll_at_restore_for_test(k.zero_raw_poll_at_restore);
    remote.set_w3_guard_perturb_for_test(k.w3_perturb);
    let mut s = remote.initial_state();
    s.rip = info.base + gx.main_off;
    s.rbp = info.base + gx.handler_off;
    s.r12 = info.base + gx.restorer_off;
    s.r13 = info.dst;
    let out = remote.run(s, RETURN_SENTINEL);
    // A run past its deadline fails here, by name.
    drop(deadline);
    let report = remote.arrival_report_for_test();
    let debug_regs = remote.debug_regs_for_test();
    let pid = remote.child_pid_for_test();
    let mut data = vec![0u8; REPORT];
    assert!(remote.read_mem(info.dst, &mut data), "read translated dst");
    TArrival {
        out,
        report,
        data,
        info,
        target,
        entries,
        debug_regs,
        pid,
    }
}

fn run_native(gx: &Gx, arrival: Option<(u64, i32)>) -> O1sOutcome {
    let (main, restorer, handler) = (gx.main_off, gx.restorer_off, gx.handler_off);
    deadline::o1s(
        REMOTE_CHILD,
        &gx.bytes,
        &[],
        |r, info| {
            r.rip = info.base + main;
            r.rbp = info.base + handler;
            r.r12 = info.base + restorer;
            r.r13 = info.dst;
        },
        arrival,
        |_| {},
    )
}

fn code_len(gx: &Gx) -> u64 {
    gx.bytes.len().div_ceil(4096) as u64 * 4096
}

/// PC-map class of an entry, for the coverage table.
fn class_of(e: &PcMapEntry) -> String {
    fn stub(s: StubStage) -> &'static str {
        match s {
            StubStage::BeforeCreditPristine => "BeforeCreditPristine",
            StubStage::BeforeCreditSpilled => "BeforeCreditSpilled",
            StubStage::AfterCreditSpilled => "AfterCreditSpilled",
            StubStage::AfterCreditFlagsRestored => "AfterCreditFlagsRestored",
            StubStage::Committed => "Committed",
        }
    }
    fn exit(s: ExitStage) -> &'static str {
        match s {
            ExitStage::Pristine => "Pristine",
            ExitStage::Spilled => "Spilled",
        }
    }
    match e.recovery {
        Recovery::Copied => "Copied".into(),
        Recovery::BranchStub { stage, .. } => format!("BranchStub/{}", stub(stage)),
        Recovery::InsnCountStub { stage, .. } => format!("InsnCountStub/{}", stub(stage)),
        Recovery::PollStub { stage, .. } => format!("PollStub/{}", stub(stage)),
        Recovery::Call { stage, .. } => format!(
            "Call/{}",
            match stage {
                CallStage::Pristine => "Pristine",
                CallStage::RaxSpilled => "RaxSpilled",
                CallStage::RspDecremented => "RspDecremented",
                CallStage::CommittedSpilled => "CommittedSpilled",
                CallStage::Committed => "Committed",
            }
        ),
        Recovery::ExitStub { stage } => format!("ExitStub/{}", exit(stage)),
        Recovery::PollExitStub { stage } => format!("PollExitStub/{}", exit(stage)),
        Recovery::CommonExit { stage } => format!(
            "CommonExit/{}",
            match stage {
                CommonStage::BeforeRspSave => "BeforeRspSave",
                CommonStage::RspSaved => "RspSaved",
                CommonStage::FlagsSaved => "FlagsSaved",
                CommonStage::AllSaved => "AllSaved",
            }
        ),
        Recovery::Fallthrough { .. } => "Fallthrough".into(),
    }
}

/// How one arrival ended.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Verdict {
    /// Delivered, and every compared item equals O1-S.
    Equal,
    /// The `hit`-th execution never happened.
    NotReached,
    /// An asynchronous stop in the common exit stayed a recovered
    /// AsyncSignal: since I1-H H2b only for an INDIRECT (or
    /// unknown) exit kind. The sweeps require none.
    RefusedW1,
}

/// One survey hit of a PC-map entry, as recovery names it: the
/// recovered source offset (from the fixture base), totals, and
/// the dispatcher's exit kind there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HitRec {
    src_off: u64,
    instructions: u64,
    branches: u64,
    exit_kind: u64,
}

fn hit_rec(h: &SeamHit, info: &RemoteChildInfo) -> HitRec {
    HitRec {
        src_off: h.src_pc.wrapping_sub(info.base),
        instructions: h.instructions,
        branches: h.branches,
        exit_kind: h.exit_kind,
    }
}

/// The kernel sets RFLAGS.RF at every execute-breakpoint stop
/// (`hw_breakpoint_handler`), before the tracer reads it; pinned
/// here as a kernel rule (the seam's own "ensure RF" step is
/// therefore an equivalent mutant on this kernel).
fn assert_rf_at_every_hit(report: &ArrivalReport, label: &str) {
    assert_eq!(
        report.rf_at_hits.len() as u64,
        report.hits,
        "{label}: one RF sample per hit"
    );
    assert!(
        report.rf_at_hits.iter().all(|&rf| rf),
        "{label}: RF set by the kernel at every hit: {:?}",
        report.rf_at_hits
    );
}

/// Which generated PC an expected delivery must carry.
#[derive(Clone, Copy, Debug)]
enum GenPc {
    /// The arrival seam's target PC.
    Arrival,
    /// Any: a delivery the guest caused itself (a self-sent signal
    /// presented at the next block head).
    Any,
    /// Exactly this value (0: from an original step, W3).
    Exactly(u64),
}

/// One expected delivery, in delivery order, and where its handler
/// logs (siginfo, gregs, mask at `slot`; a counter at `count`).
#[derive(Clone, Copy, Debug)]
struct Want {
    signo: i32,
    gen_pc: GenPc,
    slot: i32,
    count: i32,
}

/// What `compare_delivered` checks a delivered run against (I1-H
/// H2b): the exact delivery list in both engines, paired by index,
/// with the full H1 equality for each pair.
#[derive(Clone, Copy, Debug)]
struct Spec<'a> {
    /// The arrival signal (seam and O1-S).
    sig: i32,
    deliveries: &'a [Want],
    /// Index in `deliveries` of the arrival: O1-S is signalled at
    /// its recovered count.
    arrival: usize,
    /// Buffer word indices holding the child's own pid in their
    /// low half (a self-sent siginfo sender word `pid | uid << 32`,
    /// or a logged RDI after `getpid`), compared as the tagged own
    /// pid.
    own_pid_words: &'a [usize],
    /// The fixture leaves the child's own pid in RDI (`getpid`):
    /// RDI compares as the tagged own pid wherever it holds it.
    pid_in_rdi: bool,
    /// O1-S can run the fixture. False only for an indirect `jmp`,
    /// which the O1 oracle refuses to verify (its RIP-delta check
    /// predicts `Unverifiable`): a refusal is then checked against
    /// the survey's recovery only, with no O1-S leg.
    o1s: bool,
}

/// The H1 single-arrival shape: one SIGUSR1 delivery at the seam's
/// target, logged by the one handler.
const SINGLE: Spec<'static> = Spec {
    sig: USR1,
    deliveries: &[Want {
        signo: USR1,
        gen_pc: GenPc::Arrival,
        slot: SLOT,
        count: COUNT,
    }],
    arrival: 0,
    own_pid_words: &[],
    pid_in_rdi: false,
    o1s: true,
};

/// Run one arrival in both engines; panic on any mismatch.
/// `want` is the survey's recovery at this (PC, hit).
fn check_arrival(
    gx: &Gx,
    idx: usize,
    hit: u64,
    poll_budget: Option<u64>,
    label: &str,
    want: HitRec,
) -> Verdict {
    let knobs = Knobs {
        arrival: Some((idx, hit)),
        poll_budget,
        ..Knobs::default()
    };
    check_arrival_full(gx, knobs, label, want, &SINGLE).0
}

/// [`check_arrival`] for any knobs and delivery spec; also returns
/// the translated run (its seam report counts polls).
///
/// Check order is fixed, so the first failing assertion names
/// the cause deterministically: the seam reached the hit (the
/// unsent branch), then it fired on exactly that hit, then the
/// arrival's instance matches the survey's recovery there, then
/// the outcome comparisons.
fn check_arrival_full(
    gx: &Gx,
    knobs: Knobs,
    label: &str,
    want: HitRec,
    spec: &Spec,
) -> (Verdict, TArrival) {
    let (_, hit) = knobs.arrival.expect("an arrival");
    let t = run_translated(gx, knobs);
    assert_eq!(
        t.debug_regs,
        Some((0, 0)),
        "{label}: debug registers cleared after the run"
    );
    let (gen_pc, entry) = t.target.expect("arrival target");
    let class = class_of(&entry);
    if !t.report.sent {
        assert!(
            t.report.hits < hit,
            "{label}: unsent after {} of {hit} hits",
            t.report.hits
        );
        let out = t
            .out
            .as_ref()
            .unwrap_or_else(|e| panic!("{label}: unreached arrival, run failed: {e:?}"));
        assert_eq!(out.state.rax, 42, "{label}: unreached arrival result");
        assert_eq!(
            t.report.deliveries.len(),
            spec.arrival,
            "{label}: only the deliveries before the arrival"
        );
        return (Verdict::NotReached, t);
    }
    // The seam fired on the requested hit, not later.
    assert_eq!(t.report.hits, hit, "{label}: arrival fired on hit");
    // Instance identity, independent of the seam's own hit
    // counter: the arrival recovers exactly what the survey's
    // counting run recorded at this (PC, hit). It shares
    // `recover` with the arrival, so it pins which dynamic
    // instance was hit, not recovery correctness (the O1-S
    // comparisons below do that).
    let got = match (&t.out, t.report.deliveries.get(spec.arrival)) {
        (Err(RunError::Fault(f)), _) if f.kind == FaultKind::AsyncSignal => {
            (f.src_pc, f.instructions, f.branches)
        }
        (_, Some(d)) => (d.src_pc, d.instructions, d.branches),
        (out, None) => panic!("{label}: sent, but neither delivered nor refused: {out:?}"),
    };
    assert_eq!(
        (got.0.wrapping_sub(t.info.base), got.1, got.2),
        (want.src_off, want.instructions, want.branches),
        "{label}: arrival instance (source offset, instructions, branches) vs the survey's \
         recovery at hit {hit}"
    );
    assert_rf_at_every_hit(&t.report, label);
    let clen = code_len(gx);
    if let Err(RunError::Fault(f)) = &t.out
        && f.kind == FaultKind::AsyncSignal
    {
        assert_eq!(f.signum, spec.sig, "{label}: refused signal");
        assert!(
            class.starts_with("CommonExit/"),
            "{label}: refusal outside the common exit at {class} (gen {gen_pc:#x}): {f:?}"
        );
        assert_eq!(
            t.report.deliveries.len(),
            spec.arrival,
            "{label}: refused, no arrival delivery"
        );
        // A common-exit refusal (since I1-H H2b only for an
        // INDIRECT or unknown exit kind; the sweeps require none)
        // must still name the right source state: O1-S signalled
        // after the recovered retired count delivers at the
        // recovered source PC with the same totals. Not for a
        // fixture O1-S cannot run (`spec.o1s`).
        if !spec.o1s {
            return (Verdict::RefusedW1, t);
        }
        let n = run_native(gx, Some((f.instructions, spec.sig)));
        assert_eq!(n.end, O1sEnd::Returned, "{label}: refused, O1-S end");
        assert!(
            n.arrival_sent,
            "{label}: refused, O1-S reached k = {}",
            f.instructions
        );
        assert_eq!(
            n.deliveries.len(),
            spec.arrival + 1,
            "{label}: refused, O1-S deliveries"
        );
        let nd = &n.deliveries[spec.arrival];
        assert_eq!(
            (nd.instructions, nd.branches),
            (f.instructions, f.branches),
            "{label}: refused, recovered totals vs O1-S at delivery"
        );
        assert_eq!(
            norm(nd.gregs[16], &n.info, clen),
            norm(f.src_pc, &t.info, clen),
            "{label}: refused, recovered source PC vs O1-S frame RIP"
        );
        return (Verdict::RefusedW1, t);
    }
    if let Err(e) = &t.out {
        panic!("{label}: arrival at {class} hit {hit}: translated error {e:?}");
    }
    assert!(
        spec.o1s,
        "{label}: arrival at {class} hit {hit} delivered where only a refusal is checkable \
         (O1-S cannot run this fixture): {:?}",
        t.report.deliveries
    );
    compare_delivered(
        gx,
        &t,
        spec,
        Some(gen_pc),
        &format!("{label}: arrival at {class} hit {hit}"),
    );
    (Verdict::Equal, t)
}

/// One handler's log: siginfo words 0..4, uc gregs 0..18, mask.
fn slot_words(data: &[u8], slot: i32) -> Vec<u64> {
    (0..SLOT_WORDS)
        .map(|i| word(data, slot as usize + 8 * i))
        .collect()
}

/// A delivered translated run against O1-S, per `spec`: the exact
/// delivery list in both engines (signal numbers in order, and
/// each translated delivery's generated PC), paired by index; per
/// pair, the retired totals at delivery, frame RIP against the
/// recovered source PC, O1-S's handler log against its own frame
/// read, and the handler-visible frame register by register
/// (RFLAGS exact); each handler's counter; then the guest buffer,
/// the final registers and the final counts. `arrival_gen` is the
/// seam's target PC (`GenPc::Arrival`).
fn compare_delivered(gx: &Gx, t: &TArrival, spec: &Spec, arrival_gen: Option<u64>, ctx: &str) {
    let clen = code_len(gx);
    let out = t
        .out
        .as_ref()
        .unwrap_or_else(|e| panic!("{ctx}: translated run failed: {e:?}"));
    assert_eq!(out.state.rax, 42, "{ctx}: translated result");
    let want_sigs: Vec<i32> = spec.deliveries.iter().map(|w| w.signo).collect();
    assert_eq!(
        t.report
            .deliveries
            .iter()
            .map(|d| d.signum)
            .collect::<Vec<_>>(),
        want_sigs,
        "{ctx}: translated deliveries in order: {:?}",
        t.report.deliveries
    );
    for (d, w) in t.report.deliveries.iter().zip(spec.deliveries) {
        let want_gen = match w.gen_pc {
            GenPc::Arrival => arrival_gen,
            GenPc::Any => None,
            GenPc::Exactly(g) => Some(g),
        };
        if let Some(g) = want_gen {
            assert_eq!(
                (d.signum, d.gen_pc),
                (w.signo, g),
                "{ctx}: delivery provenance"
            );
        }
    }
    let a = t.report.deliveries[spec.arrival];
    let n = run_native(gx, Some((a.instructions, spec.sig)));
    assert_eq!(n.end, O1sEnd::Returned, "{ctx}: O1-S end");
    assert!(n.arrival_sent, "{ctx}: O1-S reached k = {}", a.instructions);
    assert_eq!(
        n.deliveries.iter().map(|d| d.signo).collect::<Vec<_>>(),
        want_sigs,
        "{ctx}: O1-S deliveries in order"
    );
    let gregs = |g: &[u64; 18], info: &RemoteChildInfo, pid: i32| {
        if spec.pid_in_rdi {
            norm_gregs_pid(g, info, clen, pid)
        } else {
            norm_gregs(g, info, clen)
        }
    };
    for (i, ((d, nd), w)) in t
        .report
        .deliveries
        .iter()
        .zip(&n.deliveries)
        .zip(spec.deliveries)
        .enumerate()
    {
        let ctx = format!("{ctx}: delivery {i} (signal {})", w.signo);
        assert_eq!(
            (nd.instructions, nd.branches),
            (d.instructions, d.branches),
            "{ctx}: retired totals at delivery (O1-S vs recovered)"
        );
        assert_eq!(
            norm(nd.gregs[16], &n.info, clen),
            norm(d.src_pc, &t.info, clen),
            "{ctx}: frame RIP is the recovered source PC"
        );
        // The handler's own log in O1-S equals O1-S's frame read.
        let n_slot = slot_words(&n.dst_bytes, w.slot);
        assert_eq!(
            &n_slot[0..4],
            &nd.siginfo[..],
            "{ctx}: O1-S logged siginfo vs frame"
        );
        assert_eq!(&n_slot[4..22], &nd.gregs[..], "{ctx}: O1-S log vs frame");
        assert_eq!(
            n_slot[22], nd.uc_sigmask,
            "{ctx}: O1-S logged mask vs frame"
        );
        // Handler-visible frame, register by register.
        let tg: [u64; 18] = slot_words(&t.data, w.slot)[4..22].try_into().unwrap();
        let (tn, nn) = (gregs(&tg, &t.info, t.pid), gregs(&nd.gregs, &n.info, n.pid));
        for (r, name) in GREG_NAMES.iter().enumerate() {
            assert_eq!(
                tn[r], nn[r],
                "{ctx}: frame {name} translated {:#x} vs native {:#x}",
                tg[r], nd.gregs[r]
            );
        }
    }
    let mut counts: BTreeMap<i32, u64> = BTreeMap::new();
    for w in spec.deliveries {
        *counts.entry(w.count).or_default() += 1;
    }
    for (&count, &runs) in &counts {
        assert_eq!(
            (
                word(&t.data, count as usize),
                word(&n.dst_bytes, count as usize)
            ),
            (runs, runs),
            "{ctx}: handler counter at {count} (translated, native)"
        );
    }
    assert_eq!(
        norm_buffer_pid(&t.data, &t.info, clen, t.pid, spec.own_pid_words),
        norm_buffer_pid(&n.dst_bytes, &n.info, clen, n.pid, spec.own_pid_words),
        "{ctx}: guest buffer (siginfo, mask, results)"
    );
    let (ts, ns) = (state_gregs(&out.state), state_gregs(&n.state));
    let (tsn, nsn) = (gregs(&ts, &t.info, t.pid), gregs(&ns, &n.info, n.pid));
    for (r, name) in GREG_NAMES.iter().enumerate() {
        assert_eq!(
            tsn[r], nsn[r],
            "{ctx}: final {name} translated {:#x} vs native {:#x}",
            ts[r], ns[r]
        );
    }
    assert_eq!(
        (out.instructions, out.branches),
        (n.instructions, n.branches),
        "{ctx}: final counts"
    );
}

/// The quiet run (no arrival) in both engines: equal, and the
/// reference PC-map size.
fn quiet(gx: &Gx, poll_budget: Option<u64>, label: &str) -> (TArrival, O1sOutcome) {
    let t = run_translated(
        gx,
        Knobs {
            poll_budget,
            ..Knobs::default()
        },
    );
    let out = t
        .out
        .as_ref()
        .unwrap_or_else(|e| panic!("{label}: quiet translated: {e:?}"));
    let n = run_native(gx, None);
    assert_eq!(n.end, O1sEnd::Returned, "{label}: quiet O1-S");
    assert!(n.deliveries.is_empty());
    assert_eq!(
        (out.instructions, out.branches),
        (n.instructions, n.branches),
        "{label}: quiet counts"
    );
    let clen = code_len(gx);
    assert_eq!(
        norm_gregs(&state_gregs(&out.state), &t.info, clen),
        norm_gregs(&state_gregs(&n.state), &n.info, clen),
        "{label}: quiet final state"
    );
    (t, n)
}

/// Every hit of one PC-map entry over a whole quiet run (the
/// arrival breakpoint stays armed and never fires), each as
/// recovery names it.
fn entry_hits(
    gx: &Gx,
    poll_budget: Option<u64>,
    idx: usize,
    entries: usize,
    label: &str,
) -> Vec<HitRec> {
    let t = run_translated(
        gx,
        Knobs {
            arrival: Some((idx, u64::MAX)),
            poll_budget,
            ..Knobs::default()
        },
    );
    assert_eq!(t.entries, entries, "{label}: PC-map size is stable");
    let out = t
        .out
        .as_ref()
        .unwrap_or_else(|e| panic!("{label}: counting run {idx}: {e:?}"));
    assert_eq!(out.state.rax, 42, "{label}: counting run {idx}");
    assert!(!t.report.sent, "{label}: counting run never fires");
    assert_eq!(t.debug_regs, Some((0, 0)), "{label}: DR cleared");
    assert_rf_at_every_hit(&t.report, label);
    assert_eq!(
        t.report.hit_stops.len() as u64,
        t.report.hits,
        "{label}: one recovery per hit"
    );
    t.report
        .hit_stops
        .iter()
        .map(|h| hit_rec(h, &t.info))
        .collect()
}

/// [`entry_hits`] for every PC-map entry.
fn hit_records(gx: &Gx, poll_budget: Option<u64>, entries: usize, label: &str) -> Vec<Vec<HitRec>> {
    (0..entries)
        .map(|idx| entry_hits(gx, poll_budget, idx, entries, label))
        .collect()
}

/// Hits of `e` that run after the handler install. The prologue
/// (before `body_off`) and the handler/restorer (before
/// `main_off`) never qualify: before the install, SIGUSR1 still
/// has its default action. The common exit's first execution is
/// the install's own syscall exit, so its post-install hits
/// start at 2.
fn post_install_hits(gx: &Gx, e: &PcMapEntry, base: u64, h: u64) -> std::ops::RangeInclusive<u64> {
    if matches!(e.recovery, Recovery::CommonExit { .. }) {
        return 2..=h;
    }
    let off = e.src_pc.wrapping_sub(base);
    if off < gx.body_off || off >= gx.bytes.len() as u64 {
        return std::ops::RangeInclusive::new(1, 0);
    }
    1..=h
}

#[derive(Default)]
struct Tally {
    entries: u64,
    executed: u64,
    arrivals: u64,
    equal: u64,
    refused_w1: u64,
    not_reached: u64,
}

fn print_table(label: &str, table: &BTreeMap<String, Tally>) {
    eprintln!(
        "{label}: {:<34} {:>7} {:>8} {:>8} {:>6} {:>9} {:>11}",
        "class", "entries", "executed", "arrivals", "equal", "refusedW1", "not-reached"
    );
    for (class, t) in table {
        eprintln!(
            "{label}: {class:<34} {:>7} {:>8} {:>8} {:>6} {:>9} {:>11}",
            t.entries, t.executed, t.arrivals, t.equal, t.refused_w1, t.not_reached
        );
    }
}

/// SplitMix64: a recorded-seed sample generator.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// Wall-clock cap for each sweep (coord7 Q5: about 2 minutes in
/// total across the two). A sweep that reaches it FAILS (I1-H H2,
/// coord7 Q3): a truncated sweep would claim coverage it did not
/// run. Measured at H2a (446dc02b, release): mixed 2.5 s survey +
/// 3.4 s, loop 3.4 s; H2b re-measures with W1 delivering.
const SWEEP_CAP: Duration = Duration::from_secs(60);
const SWEEP_SEED: u64 = 0x11e4_5eed_2026_1111;
/// Sample size for the poll-crossing loop (coord7 Q5).
const LOOP_SAMPLES: usize = 256;
/// Poll budget for the loop sweep: 120 iterations cross several
/// poll exits instead of needing 16384 block entries.
const LOOP_POLL_BUDGET: u64 = 16;
/// Pinned plan sizes (I1-H H2, coord7 P3): what the planner
/// derives from the pinned fixture bytes. A changed translation,
/// fixture or survey fails here visibly.
const MIXED_ENTRIES: usize = 633;
const MIXED_PLAN: usize = 448;
const LOOP_ENTRIES: usize = 365;
const LOOP_POPULATION: usize = 4338;
const LOOP_TOPUPS: usize = 5;

/// Run `plan` (entry index, hit) under the cap, filling the
/// per-class table, with every arrival checked against the
/// survey's recovery `hits[idx][hit - 1]`. Reaching the cap fails.
fn run_plan(
    gx: &Gx,
    poll_budget: Option<u64>,
    plan: &[(usize, u64)],
    table: &mut BTreeMap<String, Tally>,
    classes: &[String],
    hits: &[Vec<HitRec>],
    label: &str,
) {
    let started = Instant::now();
    let mut ran = 0;
    for &(idx, hit) in plan {
        assert!(
            started.elapsed() <= SWEEP_CAP,
            "{label}: TRUNCATED at the {SWEEP_CAP:?} cap: ran {ran} of {} planned arrivals; \
             {} not run",
            plan.len(),
            plan.len() - ran
        );
        ran += 1;
        let want = hits[idx][hit as usize - 1];
        let v = check_arrival(
            gx,
            idx,
            hit,
            poll_budget,
            &format!("{label} #{idx}@{hit}"),
            want,
        );
        let t = table.get_mut(&classes[idx]).expect("class row");
        t.arrivals += 1;
        match v {
            Verdict::Equal => t.equal += 1,
            Verdict::RefusedW1 => t.refused_w1 += 1,
            Verdict::NotReached => t.not_reached += 1,
        }
    }
    eprintln!(
        "{label}: {ran} of {} planned arrivals run in {:?}",
        plan.len(),
        started.elapsed()
    );
}

/// Outcomes of a survey-derived plan. Every planned (PC, hit)
/// was observed executed by the survey's counting run, so an
/// arrival that never sent is a seam or plan defect, never
/// coverage (the deliberately unreachable W1 hit-6 control runs
/// outside any plan). And every class with an executed entry got
/// at least one SENT arrival, delivered and equal or a common-exit
/// refusal (the sweeps then require no refusal at all). (A
/// truncated sweep has already failed in `run_plan`.)
fn assert_plan_outcomes(label: &str, table: &BTreeMap<String, Tally>) {
    for (class, t) in table {
        assert_eq!(
            t.not_reached, 0,
            "{label}: {class}: survey-observed arrivals not reached"
        );
    }
    for (class, t) in table {
        assert!(
            t.executed == 0 || t.equal + t.refused_w1 > 0,
            "{label}: executed class {class} got no sent arrival"
        );
    }
}

/// Classes and counts for one fixture: the quiet run, then one
/// counting run per PC-map entry.
fn survey(
    gx: &Gx,
    poll_budget: Option<u64>,
    label: &str,
) -> (Vec<String>, Vec<PcMapEntry>, Vec<Vec<HitRec>>, u64) {
    let (t, _) = quiet(gx, poll_budget, label);
    let entries = t.entries;
    let (map, base) = pcmap_of(gx);
    assert_eq!(map.len(), entries, "{label}: PC-map size");
    let classes: Vec<String> = map.iter().map(class_of).collect();
    let hits = hit_records(gx, poll_budget, entries, label);
    (classes, map, hits, base)
}

/// The PC map of one prepared child, and that child's fixture
/// base (entry `src_pc`s are absolute).
fn pcmap_of(gx: &Gx) -> (Vec<PcMapEntry>, u64) {
    let (mut remote, _deadline) = spawn_remote(&gx.bytes);
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: gx.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(
            &region,
            info.base + gx.main_off,
            CountProfile::BranchesAndInstructions,
        )
        .expect("prepare");
    let map = remote
        .translation_for_test()
        .expect("prepared")
        .pcmap
        .entries()
        .to_vec();
    (map, info.base)
}

/// Exhaustive sweep (coord7 Q5): every (generated PC, hit) of the
/// mixed fixture that executes after the handler install, through
/// every PC-map class. Every arrival must be delivered and equal
/// O1-S exactly: since I1-H H2b (W1) no class refuses, the common
/// exit included.
#[test]
fn sweep_mixed_exhaustive() {
    let _g = lock();
    let gx = build(Body::Mixed);
    let label = "sweep-mixed";
    let started = Instant::now();
    let (classes, map, hits, base) = survey(&gx, None, label);
    let mut table: BTreeMap<String, Tally> = BTreeMap::new();
    let mut plan = Vec::new();
    for (idx, e) in map.iter().enumerate() {
        let row = table.entry(classes[idx].clone()).or_default();
        row.entries += 1;
        let range = post_install_hits(&gx, e, base, hits[idx].len() as u64);
        if !range.is_empty() {
            row.executed += 1;
        }
        plan.extend(range.map(|h| (idx, h)));
    }
    eprintln!(
        "{label}: {} PC-map entries, {} planned arrivals (survey {:?})",
        map.len(),
        plan.len(),
        started.elapsed()
    );
    assert_eq!(map.len(), MIXED_ENTRIES, "{label}: pinned PC-map size");
    assert_eq!(plan.len(), MIXED_PLAN, "{label}: pinned plan size");
    run_plan(&gx, None, &plan, &mut table, &classes, &hits, label);
    print_table(label, &table);
    assert_plan_outcomes(label, &table);
    let equal: u64 = table.values().map(|t| t.equal).sum();
    let refused: u64 = table.values().map(|t| t.refused_w1).sum();
    // Non-vacuity, exactly: every planned arrival delivered and
    // equal (H2a pinned 336 / 112 while W1 still refused).
    assert_eq!(
        (equal, refused),
        (MIXED_PLAN as u64, 0),
        "{label}: equal and refused arrivals"
    );
    for (class, t) in &table {
        assert_eq!(t.refused_w1, 0, "{label}: {class} refusals");
    }
}

/// Seeded sample (coord7 Q5: N = 256, seed recorded) over the
/// poll-crossing loop's (generated PC, hit) pairs after the
/// install, including the poll-exit path.
#[test]
fn sweep_poll_loop_sampled() {
    let _g = lock();
    let gx = build(Body::Loop(120));
    let label = "sweep-loop";
    let budget = Some(LOOP_POLL_BUDGET);
    let (classes, map, hits, base) = survey(&gx, budget, label);
    let mut table: BTreeMap<String, Tally> = BTreeMap::new();
    let mut population = Vec::new();
    for (idx, e) in map.iter().enumerate() {
        let row = table.entry(classes[idx].clone()).or_default();
        row.entries += 1;
        let range = post_install_hits(&gx, e, base, hits[idx].len() as u64);
        if !range.is_empty() {
            row.executed += 1;
        }
        population.extend(range.map(|h| (idx, h)));
    }
    let mut rng = SplitMix(SWEEP_SEED);
    let mut chosen = std::collections::BTreeSet::new();
    let n = LOOP_SAMPLES.min(population.len());
    while chosen.len() < n {
        chosen.insert((rng.next() % population.len() as u64) as usize);
    }
    let mut plan: Vec<(usize, u64)> = chosen.iter().map(|&i| population[i]).collect();
    let sampled = plan.len();
    // Per-class top-up, deterministic: every executed class the
    // sample missed gets its first (PC, hit) pair.
    let mut covered: std::collections::BTreeSet<&str> =
        plan.iter().map(|&(i, _)| classes[i].as_str()).collect();
    for &(idx, hit) in &population {
        if covered.insert(classes[idx].as_str()) {
            plan.push((idx, hit));
        }
    }
    eprintln!(
        "{label}: seed {SWEEP_SEED:#x}, {sampled} of {} (PC, hit) pairs sampled, plus {} \
         per-class top-ups, poll budget {LOOP_POLL_BUDGET}",
        population.len(),
        plan.len() - sampled
    );
    assert_eq!(map.len(), LOOP_ENTRIES, "{label}: pinned PC-map size");
    assert_eq!(
        population.len(),
        LOOP_POPULATION,
        "{label}: pinned population"
    );
    assert_eq!(
        (sampled, plan.len() - sampled),
        (LOOP_SAMPLES, LOOP_TOPUPS),
        "{label}: pinned sample and top-ups"
    );
    run_plan(&gx, budget, &plan, &mut table, &classes, &hits, label);
    print_table(label, &table);
    assert_plan_outcomes(label, &table);
    let equal: u64 = table.values().map(|t| t.equal).sum();
    let refused: u64 = table.values().map(|t| t.refused_w1).sum();
    // Non-vacuity, exactly: every planned arrival delivered and
    // equal (H2a pinned 244 / 17 while W1 still refused).
    assert_eq!(
        (equal, refused),
        ((LOOP_SAMPLES + LOOP_TOPUPS) as u64, 0),
        "{label}: equal and refused arrivals"
    );
    for (class, t) in &table {
        assert_eq!(t.refused_w1, 0, "{label}: {class} refusals");
    }
    let poll_path = table
        .iter()
        .filter(|(c, _)| c.starts_with("PollExitStub/"))
        .map(|(_, t)| t.executed)
        .sum::<u64>();
    assert!(poll_path > 0, "{label}: the poll-exit path executed");
}

/// W1 (closed in I1-H H2b): arrivals in the common exit deliver.
/// The remote translation has one common exit; its entries run
/// once per dispatcher exit: hit 1 is the install's
/// `rt_sigaction`, hits 2..=5 are the Mixed body's exits in order
/// (the helper's `ret`, `write`, `cpuid`, main's final `ret`:
/// RETURN, SYSCALL, NONDET, RETURN), and there is no hit 6.
/// SIGUSR1 arriving at each post-install hit, at the first entry
/// of each recovery stage and at the final `int3`, is delivered
/// at that exit's source PC (the terminator not yet run) and
/// equals O1-S arriving at the recovered count.
#[test]
fn w1_common_exit_arrival_delivers() {
    let _g = lock();
    let gx = build(Body::Mixed);
    let (map, _) = pcmap_of(&gx);
    let first_of = |stage: CommonStage| {
        map.iter()
            .position(|e| e.recovery == Recovery::CommonExit { stage })
            .expect("common exit stage entry")
    };
    // The final AllSaved entry is the trap byte (`int3`).
    let trap = map
        .iter()
        .rposition(|e| {
            e.recovery
                == Recovery::CommonExit {
                    stage: CommonStage::AllSaved,
                }
        })
        .expect("common exit trap byte");
    let entries = [
        ("BeforeRspSave", first_of(CommonStage::BeforeRspSave)),
        ("RspSaved", first_of(CommonStage::RspSaved)),
        ("FlagsSaved", first_of(CommonStage::FlagsSaved)),
        ("AllSaved", first_of(CommonStage::AllSaved)),
        ("int3", trap),
    ];
    assert_ne!(
        entries[3].1, trap,
        "W1: the trap byte is not the first AllSaved entry"
    );
    let names = ["helper ret", "write", "cpuid", "main ret"];
    let exit_offs = gx.exit_offs.unwrap();
    use liteinst_jit::state::exit_kind::{NONDET, RETURN, SYSCALL};
    let mut delivered = 0;
    for (stage, idx) in entries {
        // The survey's per-hit record names each exit: its source
        // PC and the exit kind the dispatcher data holds (H2a).
        let recs = entry_hits(&gx, None, idx, map.len(), "W1 survey");
        assert_eq!(recs.len(), 5, "W1 survey at {stage}: five common-exit hits");
        assert_eq!(
            recs[1..]
                .iter()
                .map(|r| (r.src_off, r.exit_kind))
                .collect::<Vec<_>>(),
            exit_offs
                .into_iter()
                .zip([RETURN, SYSCALL, NONDET, RETURN])
                .collect::<Vec<_>>(),
            "W1 survey at {stage}: post-install hits name the four exits and their kinds"
        );
        for (k, name) in names.iter().enumerate() {
            let hit = k as u64 + 2;
            let label = format!("W1 {stage} hit {hit} ({name})");
            assert_eq!(
                check_arrival(&gx, idx, hit, None, &label, recs[k + 1]),
                Verdict::Equal,
                "{label}: delivered, equal to O1-S"
            );
            delivered += 1;
        }
    }
    assert_eq!(delivered, 20, "W1: 5 entries x 4 exits");
    // Exactly five executions: hit 6 is never reached.
    let t = run_translated(
        &gx,
        Knobs {
            arrival: Some((entries[0].1, 6)),
            ..Knobs::default()
        },
    );
    assert!(!t.report.sent, "W1: no sixth common-exit execution");
    assert_eq!(t.report.hits, 5, "W1: exactly five common-exit executions");
    assert_eq!(t.out.as_ref().map(|o| o.state.rax).ok(), Some(42));
    assert_eq!(t.debug_regs, Some((0, 0)), "W1: DR cleared, unreached");
}

/// W3 (closed in I1-H H2b): SIGUSR1 sent just before the tracer
/// single-steps the original `cpuid` (the H1 pre-step seam) is
/// delivered at the `cpuid` source PC with the `cpuid` not run
/// (RAX and RBX at their source values, 0 and 0), and the run
/// equals O1-S arriving at the same retired count, by the full
/// comparator: frame registers with RFLAGS exact (this is the
/// only delivery made from a stop entered by `PTRACE_SINGLESTEP`,
/// so a leaked trace flag would show there), siginfo, mask,
/// buffer, final state and totals. After sigreturn the `cpuid`
/// runs once (its vendor word reaches the buffer).
#[test]
fn w3_original_step_arrival_delivers() {
    let _g = lock();
    let gx = build(Body::Mixed);
    let label = "W3";
    let t = run_translated(
        &gx,
        Knobs {
            pre_original_step_signal: Some(USR1),
            ..Knobs::default()
        },
    );
    // Exactly one delivery: the pre-step seam is one-shot, so the
    // retried `cpuid` steps again unsignalled (H2b record-pass
    // finding: a persistent seam re-signalled every retry).
    assert_eq!(
        (t.report.deliveries.len(), word(&t.data, COUNT as usize)),
        (1, 1),
        "{label}: exactly one delivery, handler ran once: {:?}",
        t.out.as_ref().err()
    );
    let cpuid = t.info.base + gx.cpuid_off.unwrap();
    assert_eq!(
        t.report.deliveries.first().map(|d| d.src_pc),
        Some(cpuid),
        "{label}: delivered at the cpuid source PC: {:?}",
        t.report.deliveries
    );
    let frame = slot_words(&t.data, SLOT);
    const RAX: usize = 4 + 13;
    const RBX: usize = 4 + 11;
    const RIP: usize = 4 + 16;
    assert_eq!(
        (frame[RIP], frame[RAX], frame[RBX]),
        (cpuid, 0, 0),
        "{label}: frame RIP is the cpuid, which has not run"
    );
    let spec = Spec {
        sig: USR1,
        deliveries: &[Want {
            signo: USR1,
            gen_pc: GenPc::Exactly(0),
            slot: SLOT,
            count: COUNT,
        }],
        arrival: 0,
        own_pid_words: &[],
        pid_in_rdi: false,
        o1s: true,
    };
    compare_delivered(&gx, &t, &spec, None, label);
    assert_ne!(
        word(&t.data, (SCRATCH + 16) as usize),
        0,
        "{label}: the cpuid ran after sigreturn (vendor word)"
    );
    // The seam is inert by default: the same run completes.
    let quiet = run_translated(&gx, Knobs::default());
    assert_eq!(quiet.out.as_ref().map(|o| o.state.rax).ok(), Some(42));
    assert!(quiet.report.deliveries.is_empty(), "{label}: quiet run");
}

/// W3 provenance guard (I1-H H2b, Q-a): a real stop never fails it
/// (the kernel dequeues the step's synchronous SIGTRAP ahead of any
/// asynchronous signal), so a seam perturbs one comparand per case:
/// the PC the stop's RIP is compared against, one GPR of the
/// recorded pre-step copy, or its RFLAGS. Each must refuse by name
/// with no delivery and the handler never run; without the seam
/// the same stop delivers.
#[test]
fn w3_provenance_guard_refuses_by_name() {
    let _g = lock();
    let gx = build(Body::Mixed);
    for p in [W3Perturb::Pc, W3Perturb::Gpr, W3Perturb::Rflags] {
        let label = format!("W3 guard {p:?}");
        let t = run_translated(
            &gx,
            Knobs {
                pre_original_step_signal: Some(USR1),
                w3_perturb: Some(p),
                ..Knobs::default()
            },
        );
        assert_eq!(
            t.out.as_ref().err(),
            Some(&RunError::Refuse(liteinst_jit::Refuse::RemoteSubstrate {
                operation: "original step: signal stop not at the pre-step state",
                errno: 0,
            })),
            "{label}: the guard refuses by name"
        );
        assert!(t.report.deliveries.is_empty(), "{label}: no delivery");
        assert_eq!(
            word(&t.data, COUNT as usize),
            0,
            "{label}: handler never ran"
        );
    }
    let t = run_translated(
        &gx,
        Knobs {
            pre_original_step_signal: Some(USR1),
            ..Knobs::default()
        },
    );
    assert_eq!(t.out.as_ref().map(|o| o.state.rax).ok(), Some(42));
    assert_eq!(
        t.report.deliveries.len(),
        1,
        "W3 guard: unperturbed, delivered"
    );
    assert_eq!(
        word(&t.data, COUNT as usize),
        1,
        "W3 guard: handler ran once"
    );
}

/// `W3_RETRY_LIMIT` in remote.rs, pinned as a literal (I1-H H2c):
/// a change there must change this pin.
const W3_RETRY_LIMIT: u32 = 64;
/// The bound's exact named reason (coord7, H2c design review Q2):
/// it keeps the refusal distinguishable from every other
/// `BudgetExceeded`.
const W3_RETRY_REFUSAL: &str = "original step interrupted without progress";
/// Seam plans for the bound tests (named constants, so each is
/// `'static`).
const PLAN_AT_LIMIT: [u32; 1] = [W3_RETRY_LIMIT];
const PLAN_OVER_LIMIT: [u32; 1] = [W3_RETRY_LIMIT + 1];
const PLAN_RESET: [u32; 2] = [W3_RETRY_LIMIT, 1];

/// The W3 retry bound admits exactly `W3_RETRY_LIMIT` consecutive
/// deliveries (I1-H H2c): the mixed fixture's `cpuid` is interrupted
/// 64 times in a row, then steps and the run completes. Each
/// delivery is at the `cpuid` source PC. O1-S injects one arrival
/// only, so the 64-delivery totals are checked by linearity against
/// the same binary's quiet and single-delivery runs: each delivery
/// adds the same handler and restorer path and nothing for the
/// interrupted `cpuid`. R15 carries one R15_MARK per delivery.
#[test]
fn w3_retry_bound_admits_the_limit() {
    let _g = lock();
    let gx = build(Body::Mixed);
    let label = "W3 bound admits";
    let n = u64::from(W3_RETRY_LIMIT);
    let quiet = run_translated(&gx, Knobs::default());
    let one = run_translated(
        &gx,
        Knobs {
            pre_original_step_signal: Some(USR1),
            ..Knobs::default()
        },
    );
    let t = run_translated(
        &gx,
        Knobs {
            pre_original_step_plan: Some(&PLAN_AT_LIMIT),
            ..Knobs::default()
        },
    );
    let cpuid = t.info.base + gx.cpuid_off.unwrap();
    let out = |r: &TArrival, what: &str| -> Outcome {
        r.out
            .clone()
            .unwrap_or_else(|e| panic!("{label}: {what} run failed: {e:?}"))
    };
    let (q, o, f) = (
        out(&quiet, "quiet"),
        out(&one, "single"),
        out(&t, "bounded"),
    );
    assert_eq!(
        (
            t.report.deliveries.len() as u64,
            word(&t.data, COUNT as usize)
        ),
        (n, n),
        "{label}: exactly 64 deliveries, handler ran 64 times"
    );
    assert!(
        t.report.deliveries.iter().all(|d| d.src_pc == cpuid),
        "{label}: every delivery at the cpuid source PC: {:?}",
        t.report.deliveries
    );
    assert_eq!(f.state.rax, 42, "{label}: the run completed");
    assert_eq!(
        word(&t.data, (SCRATCH + 16) as usize),
        word(&quiet.data, (SCRATCH + 16) as usize),
        "{label}: the cpuid ran once, after the last sigreturn (vendor word)"
    );
    assert_eq!(
        f.state.r15,
        q.state.r15 + n * R15_MARK as u64,
        "{label}: one R15_MARK per delivery"
    );
    assert_eq!(
        (f.instructions, f.branches),
        (
            q.instructions + n * (o.instructions - q.instructions),
            q.branches + n * (o.branches - q.branches)
        ),
        "{label}: totals = quiet + 64 x (single delivery - quiet)"
    );
}

/// The 65th consecutive interrupt refuses by the exact named reason
/// (I1-H H2c): 64 deliveries, then `BudgetExceeded` with
/// `W3_RETRY_REFUSAL`, and that interrupt is not delivered.
#[test]
fn w3_retry_bound_refuses_by_name() {
    let _g = lock();
    let gx = build(Body::Mixed);
    let label = "W3 bound refuses";
    let n = u64::from(W3_RETRY_LIMIT);
    let t = run_translated(
        &gx,
        Knobs {
            pre_original_step_plan: Some(&PLAN_OVER_LIMIT),
            ..Knobs::default()
        },
    );
    assert_eq!(
        t.out.as_ref().err(),
        Some(&RunError::Refuse(liteinst_jit::Refuse::BudgetExceeded {
            what: W3_RETRY_REFUSAL,
        })),
        "{label}: the exact named reason"
    );
    assert_eq!(
        (
            t.report.deliveries.len() as u64,
            word(&t.data, COUNT as usize)
        ),
        (n, n),
        "{label}: 64 delivered; the 65th interrupt is not"
    );
}

/// A completed original step resets the bound (I1-H H2c): on the
/// two-`cpuid` fixture, 64 interrupts at the first `cpuid`, which
/// then steps, and one at the second. All 65 are delivered and the
/// run completes.
#[test]
fn w3_retry_bound_resets_on_progress() {
    let _g = lock();
    let (gx, [first, second]) = build_two_cpuid();
    let label = "W3 bound resets";
    let n = u64::from(W3_RETRY_LIMIT);
    let t = run_translated(
        &gx,
        Knobs {
            pre_original_step_plan: Some(&PLAN_RESET),
            ..Knobs::default()
        },
    );
    let out = t
        .out
        .as_ref()
        .unwrap_or_else(|e| panic!("{label}: run failed: {e:?}"));
    assert_eq!(out.state.rax, 42, "{label}: the run completed");
    let srcs: Vec<u64> = t
        .report
        .deliveries
        .iter()
        .map(|d| d.src_pc - t.info.base)
        .collect();
    let mut want = vec![first; n as usize];
    want.push(second);
    assert_eq!(
        srcs, want,
        "{label}: 64 deliveries at the first cpuid, then 1 at the second"
    );
    assert_eq!(
        word(&t.data, COUNT as usize),
        n + 1,
        "{label}: handler ran 65 times"
    );
}

/// The two-`cpuid` fixture (I1-H H2c): main installs the SIGUSR1
/// handler, then runs `cpuid` leaf 0 twice (each result's EBX to
/// scratch) and returns 42. Returns the fixture and both `cpuid`
/// offsets.
fn build_two_cpuid() -> (Gx, [u64; 2]) {
    let mut a = CodeAssembler::new(64).unwrap();
    let mut handler = a.create_label();
    let mut restorer = a.create_label();
    let mut main = a.create_label();
    let mut body_l = a.create_label();
    let mut c1 = a.create_label();
    let mut c2 = a.create_label();
    a.set_label(&mut handler).unwrap();
    emit_handler(&mut a);
    a.set_label(&mut restorer).unwrap();
    a.db(&[0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05]).unwrap();
    a.set_label(&mut main).unwrap();
    a.lea(rax, qword_ptr(rbp)).unwrap();
    a.mov(qword_ptr(r13 + ACT), rax).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 8)), FLAGS).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 12)), 0u32).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 16)), r12).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 24)), 0).unwrap();
    a.mov(edi, USR1 as u32).unwrap();
    a.lea(rsi, qword_ptr(r13 + ACT)).unwrap();
    a.xor(edx, edx).unwrap();
    a.mov(r10d, 8u32).unwrap();
    a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
    a.syscall().unwrap();
    a.set_label(&mut body_l).unwrap();
    a.cmp(rcx, rcx).unwrap();
    a.jne(handler).unwrap();
    a.xor(eax, eax).unwrap();
    a.xor(ecx, ecx).unwrap();
    a.set_label(&mut c1).unwrap();
    a.cpuid().unwrap();
    a.mov(qword_ptr(r13 + (SCRATCH + 16)), rbx).unwrap();
    a.xor(eax, eax).unwrap();
    a.xor(ecx, ecx).unwrap();
    a.set_label(&mut c2).unwrap();
    a.cpuid().unwrap();
    a.mov(qword_ptr(r13 + (SCRATCH + 24)), rbx).unwrap();
    a.mov(eax, 42u32).unwrap();
    a.ret().unwrap();
    let res = a
        .assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .unwrap();
    assert_eq!(res.label_ip(&handler).unwrap(), 0, "handler at 0");
    corpus::check("H2c W3 two cpuid", &res.inner.code_buffer);
    let main_off = res.label_ip(&main).unwrap();
    (
        Gx {
            bytes: res.inner.code_buffer.clone(),
            handler_off: 0,
            restorer_off: res.label_ip(&restorer).unwrap(),
            main_off,
            body_off: res.label_ip(&body_l).unwrap(),
            cpuid_off: Some(res.label_ip(&c1).unwrap()),
            exit_offs: None,
        },
        [res.label_ip(&c1).unwrap(), res.label_ip(&c2).unwrap()],
    )
}

/// The run deadline kills a child that outlives it and fails by
/// name (I1-H H2c; see `deadline::self_test`).
#[test]
fn deadline_self_test() {
    deadline::self_test();
}

/// Spawn census (I1-H H2c): every child this binary starts carries
/// a run deadline (`common/deadline.rs`).
#[test]
fn spawn_census() {
    deadline::spawn_census(
        include_str!("remote_signal_gate.rs"),
        "remote_signal_gate.rs",
    );
}

/// POLL pass (I1-H H2b, D1): poll exits after a POLL-kind
/// common-exit arrival. The quiet loop 120 at budget 16 takes
/// `D7_QUIET_POLLS` (8) poll exits; the arrival replaces the first
/// (j = 1) and every later one still happens, all after sigreturn:
/// 8 - 1 = 7. Not to be re-derived without a re-review.
const POLL_PASS_AFTER: u64 = 7;

/// W1 under POLL exits (I1-H H2b): at every one of the 28 common-exit
/// entries of the loop fixture (budget 16), one arrival at the
/// first hit whose survey record is POLL-kind: the run's first poll
/// exit, the instance the D7 test interrupts. Each is delivered,
/// equal to O1-S, with no "poll budget zero at mid-block restore"
/// refusal (the POLL-kind stop recovers to its block start and
/// resumes through the block index), and polls exactly
/// `POLL_PASS_AFTER` times, all after sigreturn.
#[test]
fn w1_poll_kind_common_exit_arrivals() {
    let _g = lock();
    let gx = build(Body::Loop(120));
    let label = "W1 POLL pass";
    let budget = Some(LOOP_POLL_BUDGET);
    let quiet = run_translated(
        &gx,
        Knobs {
            poll_budget: budget,
            ..Knobs::default()
        },
    );
    let quiet_polls = quiet.report.poll_exits;
    assert_eq!(quiet_polls, D7_QUIET_POLLS, "{label}: quiet poll exits");
    let (map, _) = pcmap_of(&gx);
    let common: Vec<usize> = map
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.recovery, Recovery::CommonExit { .. }))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(common.len(), 28, "{label}: common-exit entries");
    use liteinst_jit::state::exit_kind::POLL;
    let mut ran = 0;
    for idx in common {
        let recs = entry_hits(&gx, budget, idx, map.len(), label);
        // Every poll exit passes every common-exit entry once.
        assert_eq!(
            recs.iter().filter(|r| r.exit_kind == POLL).count() as u64,
            quiet_polls,
            "{label} #{idx}: POLL-kind hits are the quiet run's poll exits"
        );
        let h0 = recs
            .iter()
            .position(|r| r.exit_kind == POLL)
            .expect("a POLL-kind hit");
        let j = recs[..=h0].iter().filter(|r| r.exit_kind == POLL).count() as u64;
        assert_eq!(j, 1, "{label} #{idx}: the run's first poll exit");
        assert_eq!(POLL_PASS_AFTER, quiet_polls - j, "{label}: derivation");
        let hit = h0 as u64 + 1;
        let l = format!("{label} #{idx}@{hit}");
        let (v, t) = check_arrival_full(
            &gx,
            Knobs {
                arrival: Some((idx, hit)),
                poll_budget: budget,
                ..Knobs::default()
            },
            &l,
            recs[h0],
            &SINGLE,
        );
        assert_eq!(v, Verdict::Equal, "{l}: delivered, equal to O1-S");
        assert_eq!(
            (t.report.poll_exits, t.report.poll_exits_after_sigreturn),
            (POLL_PASS_AFTER, POLL_PASS_AFTER),
            "{l}: poll exits (total, after sigreturn): {:?}",
            t.report
        );
        ran += 1;
    }
    assert_eq!(ran, 28, "{label}: pass size");
}

/// Live-frame fixture buffer layout (I1-H H2b): the USR2 handler's
/// sigaction, log slot and counter, clear of every H1 word.
const ACT2: i32 = 32;
const COUNT2: i32 = 80;
const SLOT2: i32 = SLOT + 8 * SLOT_WORDS as i32;
const _: () = assert!(
    SLOT2 + 8 * SLOT_WORDS as i32 <= SCRATCH,
    "SLOT2 below SCRATCH"
);
const USR2: i32 = libc::SIGUSR2;

/// The live-frame fixture: main installs a SIGUSR1 handler
/// (`sa_mask` empty, so SIGUSR2 is not blocked in it) and a SIGUSR2
/// handler, sends itself SIGUSR1 (`getpid; kill`) and returns 42.
/// The SIGUSR1 handler logs to `SLOT`, counts at `COUNT`, then sets
/// DF (`std`) just before its `ret`, so the FlagsSaved recovery
/// stage's RFLAGS restore is observable at that exit (the common
/// exit's `cld` is the only flag it changes). The SIGUSR2 handler
/// logs to `SLOT2` and counts at `COUNT2`. Returns the fixture and
/// the offsets of the SIGUSR1 handler's `ret` and of main's resume
/// point after its `kill`.
fn build_live_frame() -> (Gx, u64, u64) {
    let mut a = CodeAssembler::new(64).unwrap();
    let mut handler = a.create_label();
    let mut handler2 = a.create_label();
    let mut usr1_ret = a.create_label();
    let mut restorer = a.create_label();
    let mut main = a.create_label();
    let mut after_kill = a.create_label();
    a.set_label(&mut handler).unwrap();
    emit_handler_body(&mut a, SLOT, COUNT);
    a.std().unwrap();
    a.set_label(&mut usr1_ret).unwrap();
    a.ret().unwrap();
    a.set_label(&mut handler2).unwrap();
    emit_handler_body(&mut a, SLOT2, COUNT2);
    a.ret().unwrap();
    a.set_label(&mut restorer).unwrap();
    a.db(&[0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05]).unwrap();
    a.set_label(&mut main).unwrap();
    // rt_sigaction(SIGUSR1, {handler, FLAGS, restorer, mask 0}).
    a.lea(rax, qword_ptr(rbp)).unwrap();
    a.mov(qword_ptr(r13 + ACT), rax).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 8)), FLAGS).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 12)), 0u32).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 16)), r12).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 24)), 0).unwrap();
    a.mov(edi, USR1 as u32).unwrap();
    a.lea(rsi, qword_ptr(r13 + ACT)).unwrap();
    a.xor(edx, edx).unwrap();
    a.mov(r10d, 8u32).unwrap();
    a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
    a.syscall().unwrap();
    // rt_sigaction(SIGUSR2, {handler2, FLAGS, restorer, mask 0}).
    a.lea(rax, qword_ptr(handler2)).unwrap();
    a.mov(qword_ptr(r13 + ACT2), rax).unwrap();
    a.mov(dword_ptr(r13 + (ACT2 + 8)), FLAGS).unwrap();
    a.mov(dword_ptr(r13 + (ACT2 + 12)), 0u32).unwrap();
    a.mov(qword_ptr(r13 + (ACT2 + 16)), r12).unwrap();
    a.mov(qword_ptr(r13 + (ACT2 + 24)), 0).unwrap();
    a.mov(edi, USR2 as u32).unwrap();
    a.lea(rsi, qword_ptr(r13 + ACT2)).unwrap();
    a.xor(edx, edx).unwrap();
    a.mov(r10d, 8u32).unwrap();
    a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
    a.syscall().unwrap();
    // Translator reachability for both handler blocks.
    a.cmp(rcx, rcx).unwrap();
    a.jne(handler).unwrap();
    a.cmp(rcx, rcx).unwrap();
    a.jne(handler2).unwrap();
    a.mov(eax, libc::SYS_getpid as u32).unwrap();
    a.syscall().unwrap();
    a.mov(rdi, rax).unwrap();
    a.mov(esi, USR1 as u32).unwrap();
    a.mov(eax, libc::SYS_kill as u32).unwrap();
    a.syscall().unwrap();
    a.set_label(&mut after_kill).unwrap();
    a.mov(eax, 42u32).unwrap();
    a.ret().unwrap();
    let res = a
        .assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .unwrap();
    assert_eq!(res.label_ip(&handler).unwrap(), 0, "handler at 0");
    corpus::check("H2 W1 live frame", &res.inner.code_buffer);
    let main_off = res.label_ip(&main).unwrap();
    (
        Gx {
            bytes: res.inner.code_buffer.clone(),
            handler_off: 0,
            restorer_off: res.label_ip(&restorer).unwrap(),
            main_off,
            body_off: main_off,
            cpuid_off: None,
            exit_offs: None,
        },
        res.label_ip(&usr1_ret).unwrap(),
        res.label_ip(&after_kill).unwrap(),
    )
}

/// W1 in a live handler frame (I1-H H2b, coord7 item 3): SIGUSR2
/// arrives in the common exit of the SIGUSR1 handler's own `ret`
/// exit, the sigreturn interception exit, at each of its 28
/// entries. The path: a nested frame built on the live SIGUSR1
/// frame, the SIGUSR2 handler, its sigreturn back into the SIGUSR1
/// handler's exit stub (DF = 1 restored), the restorer pop, then
/// the SIGUSR1 sigreturn to main. Both engines make exactly two
/// deliveries, SIGUSR1 (self-sent, at main's resume point) then
/// SIGUSR2 (at the `ret`), compared pair by pair with separate log
/// slots; SIGUSR2's frame mask is exactly {SIGUSR1}, so a SIGUSR2
/// held until after the outer sigreturn cannot pass. The self-sent
/// SIGUSR1's siginfo sender word carries each run's own child pid
/// and is compared as the tagged own pid at that word only.
/// Host dependency: the self-sent `kill` needs the NSpid proof (one
/// NSpid entry), as every self-send does.
#[test]
fn w1_common_exit_arrival_in_live_handler() {
    let _g = lock();
    let (gx, usr1_ret, after_kill) = build_live_frame();
    let label = "W1 live frame";
    let (map, _) = pcmap_of(&gx);
    let common: Vec<usize> = map
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.recovery, Recovery::CommonExit { .. }))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(common.len(), 28, "{label}: common-exit entries");
    use liteinst_jit::state::exit_kind::RETURN;
    let spec = Spec {
        sig: USR2,
        deliveries: &[
            Want {
                signo: USR1,
                gen_pc: GenPc::Any,
                slot: SLOT,
                count: COUNT,
            },
            Want {
                signo: USR2,
                gen_pc: GenPc::Arrival,
                slot: SLOT2,
                count: COUNT2,
            },
        ],
        arrival: 1,
        // The SIGUSR1 siginfo sender word (si_pid at offset 16),
        // and the RDI the SIGUSR1 handler logged (greg 8 of the
        // slot's gregs at offset 32): SIGUSR1 interrupts the
        // guest right after `kill(getpid(), SIGUSR1)`, so that RDI
        // is each run's own pid (H2b record-pass finding: word 28
        // was compared raw, 3486203 vs 3486208).
        own_pid_words: &[(SLOT as usize + 16) / 8, (SLOT as usize + 32) / 8 + 8],
        pid_in_rdi: true,
        o1s: true,
    };
    let usr1_mask = 1u64 << (USR1 - 1);
    for idx in common {
        let recs = entry_hits(&gx, None, idx, map.len(), label);
        let h0 = recs
            .iter()
            .position(|r| r.exit_kind == RETURN && r.src_off == usr1_ret)
            .expect("the SIGUSR1 handler's ret exit");
        let hit = h0 as u64 + 1;
        let l = format!("{label} #{idx}@{hit}");
        let (v, t) = check_arrival_full(
            &gx,
            Knobs {
                arrival: Some((idx, hit)),
                arrival_sig: Some(USR2),
                ..Knobs::default()
            },
            &l,
            recs[h0],
            &spec,
        );
        assert_eq!(v, Verdict::Equal, "{l}: delivered, equal to O1-S");
        let d = &t.report.deliveries;
        assert_eq!(
            (d[0].src_pc - t.info.base, d[1].src_pc - t.info.base),
            (after_kill, usr1_ret),
            "{l}: SIGUSR1 at main's resume point, SIGUSR2 at the handler's ret"
        );
        let s2 = slot_words(&t.data, SLOT2);
        assert_eq!(
            s2[22], usr1_mask,
            "{l}: SIGUSR2 frame mask is exactly {{SIGUSR1}} (not deferred)"
        );
        assert_eq!(s2[4 + 16], t.info.base + usr1_ret, "{l}: SIGUSR2 frame RIP");
        let out = t.out.as_ref().expect("delivered");
        // Registers start at zero; only the SIGUSR1 mark survives
        // (the SIGUSR2 handler marks the SIGUSR1 handler's live R15,
        // which the SIGUSR1 sigreturn discards).
        assert_eq!(out.state.r15, R15_MARK as u64, "{l}: final R15");
    }
}

/// The INDIRECT refusal's retired totals (instructions, branches),
/// counted by hand from `build_indirect`, never derived from the
/// recovery code (coord7, H2b review P3-2). Main retires 15
/// instructions before the `jmp`: the 11 that build and pass the
/// sigaction (lea, 5 movs, mov edi, lea rsi, xor, mov r10d, mov
/// eax), then `syscall`, `cmp`, `jne` and `lea rax`. The `jmp`
/// itself has not run. One conditional branch retires: the
/// not-taken `jne` (O1-S counts Jcc/loop/jrcxz only).
const INDIRECT_REFUSAL_TOTALS: (u64, u64) = (15, 1);

/// The INDIRECT fixture (I1-H H2b, Q-c): main installs the SIGUSR1
/// handler, then `lea rax, [rip + t]; jmp rax`; `t` returns 42.
/// The translated run refuses at the `jmp` (IndirectUnresolved).
/// O1-S cannot run it: the O1 oracle refuses to verify an indirect
/// `jmp`, so the INDIRECT test pins `INDIRECT_REFUSAL_TOTALS`
/// instead. Returns the fixture and the `jmp` offset.
fn build_indirect() -> (Gx, u64) {
    let mut a = CodeAssembler::new(64).unwrap();
    let mut handler = a.create_label();
    let mut restorer = a.create_label();
    let mut main = a.create_label();
    let mut jmp_l = a.create_label();
    let mut target = a.create_label();
    a.set_label(&mut handler).unwrap();
    emit_handler(&mut a);
    a.set_label(&mut restorer).unwrap();
    a.db(&[0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05]).unwrap();
    a.set_label(&mut main).unwrap();
    a.lea(rax, qword_ptr(rbp)).unwrap();
    a.mov(qword_ptr(r13 + ACT), rax).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 8)), FLAGS).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 12)), 0u32).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 16)), r12).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 24)), 0).unwrap();
    a.mov(edi, USR1 as u32).unwrap();
    a.lea(rsi, qword_ptr(r13 + ACT)).unwrap();
    a.xor(edx, edx).unwrap();
    a.mov(r10d, 8u32).unwrap();
    a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
    a.syscall().unwrap();
    a.cmp(rcx, rcx).unwrap();
    a.jne(handler).unwrap();
    a.lea(rax, qword_ptr(target)).unwrap();
    a.set_label(&mut jmp_l).unwrap();
    a.jmp(rax).unwrap();
    a.set_label(&mut target).unwrap();
    a.mov(eax, 42u32).unwrap();
    a.ret().unwrap();
    let res = a
        .assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .unwrap();
    assert_eq!(res.label_ip(&handler).unwrap(), 0, "handler at 0");
    corpus::check("H2 W1 indirect", &res.inner.code_buffer);
    let main_off = res.label_ip(&main).unwrap();
    (
        Gx {
            bytes: res.inner.code_buffer.clone(),
            handler_off: 0,
            restorer_off: res.label_ip(&restorer).unwrap(),
            main_off,
            body_off: main_off,
            cpuid_off: None,
            exit_offs: None,
        },
        res.label_ip(&jmp_l).unwrap(),
    )
}

/// W1's INDIRECT boundary (I1-H H2b, Q-c; the Q5 non-claim): an
/// arrival in the common exit of an INDIRECT exit keeps the named
/// refusal at every one of the 28 entries: AsyncSignal at the `jmp`
/// (`exit_src`), the handler never run, the debug registers
/// cleared, the arrival instance (source offset and totals) equal
/// to the survey's recovery at that hit, and the refusal's totals
/// equal to the literal `INDIRECT_REFUSAL_TOTALS`. The survey
/// shares `recover` with the arrival, so only the literal pin
/// checks the totals independently. There is no O1-S leg: the O1
/// oracle refuses to verify an indirect `jmp`, so the native run
/// cannot get past it (H2b record-pass finding: the leg panicked
/// in O1's RIP-delta check; coord7 approved the exemption on the
/// condition of the literal pin). Without an arrival the run
/// refuses IndirectUnresolved at the `jmp`.
#[test]
fn w1_indirect_kind_arrival_is_named_refusal() {
    let _g = lock();
    let (gx, jmp_off) = build_indirect();
    let label = "W1 indirect";
    let quiet = run_translated(&gx, Knobs::default());
    assert_eq!(
        quiet.out.as_ref().err(),
        Some(&RunError::Refuse(
            liteinst_jit::Refuse::IndirectUnresolved {
                src_pc: quiet.info.base + jmp_off,
            }
        )),
        "{label}: no arrival: IndirectUnresolved at the jmp"
    );
    let (map, _) = pcmap_of(&gx);
    let common: Vec<usize> = map
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.recovery, Recovery::CommonExit { .. }))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(common.len(), 28, "{label}: common-exit entries");
    use liteinst_jit::state::exit_kind::INDIRECT;
    for idx in common {
        // Survey: the counting run refuses at the jmp, so it is read
        // directly rather than through `entry_hits`.
        let s = run_translated(
            &gx,
            Knobs {
                arrival: Some((idx, u64::MAX)),
                ..Knobs::default()
            },
        );
        assert!(!s.report.sent, "{label} #{idx}: counting run never fires");
        let recs: Vec<HitRec> = s
            .report
            .hit_stops
            .iter()
            .map(|h| hit_rec(h, &s.info))
            .collect();
        let h0 = recs
            .iter()
            .position(|r| r.exit_kind == INDIRECT)
            .expect("the INDIRECT exit");
        assert_eq!(recs[h0].src_off, jmp_off, "{label} #{idx}: the jmp's exit");
        let hit = h0 as u64 + 1;
        let l = format!("{label} #{idx}@{hit}");
        let (v, t) = check_arrival_full(
            &gx,
            Knobs {
                arrival: Some((idx, hit)),
                ..Knobs::default()
            },
            &l,
            recs[h0],
            &Spec {
                o1s: false,
                ..SINGLE
            },
        );
        assert_eq!(v, Verdict::RefusedW1, "{l}: named refusal");
        match &t.out {
            Err(RunError::Fault(f)) => {
                assert_eq!(
                    (f.kind, f.src_pc),
                    (FaultKind::AsyncSignal, t.info.base + jmp_off),
                    "{l}: AsyncSignal at exit_src"
                );
                assert_eq!(
                    (f.instructions, f.branches),
                    INDIRECT_REFUSAL_TOTALS,
                    "{l}: retired totals at the refusal vs the literal count from the fixture"
                );
            }
            other => panic!("{l}: expected the named refusal, got {other:?}"),
        }
        assert_eq!(word(&t.data, COUNT as usize), 0, "{l}: handler never ran");
    }
}

/// W2 evidence: the "generated PC with no PC-map entry" class is
/// empty in the remote substrate. Every byte the remote
/// translation emits (exit style `TrapToDispatcher`) lies in
/// exactly one PC-map entry, contiguously from the generated base
/// to the end of the code: the tracer enters blocks by setting
/// registers, so there is no generated entry bridge. The arena's
/// only other code is the signal-entry stub, which only a kernel
/// delivery enters (covered as back-to-back setup by I1-G1).
/// Checked for both sweep fixtures and every corpus-v1 fixture
/// that translates.
#[test]
fn w2_remote_translation_maps_every_generated_byte() {
    // Builds (and so pins) both sweep fixtures without `lock()`.
    let _corpus = corpus::guard();
    let gen_base = TRANSLATION_GEN_BASE;
    let mut checked = 0;
    for (name, t) in remote_translations() {
        let e = t.pcmap.entries();
        assert_eq!(
            e.first().map(|x| x.gen_start),
            Some(gen_base),
            "{name}: first"
        );
        for w in e.windows(2) {
            assert_eq!(
                w[1].gen_start, w[0].gen_end,
                "{name}: gap at {:#x}",
                w[0].gen_end
            );
        }
        assert_eq!(
            e.last().map(|x| x.gen_end),
            Some(gen_base + t.code.len() as u64),
            "{name}: last"
        );
        checked += 1;
    }
    assert!(checked >= 20, "fixtures checked: {checked}");
    eprintln!("W2: {checked} translations, every generated byte mapped");
}

const TRANSLATION_GEN_BASE: u64 = 0x10_4000_0000;

/// Remote-style translations (exit style `TrapToDispatcher`) of
/// both sweep fixtures and every corpus-v1 fixture that translates,
/// by name. Building the sweep fixtures pins them: callers hold a
/// corpus guard.
fn remote_translations() -> Vec<(String, liteinst_jit::Translation)> {
    use liteinst_jit::exec::CODE_CAP;
    use liteinst_jit::{ExitStyle, translate_with_exit_style};
    let base = 0x10_0000_0000u64;
    let gen_base = TRANSLATION_GEN_BASE;
    let mut cases: Vec<(String, Vec<u8>, u64)> = vec![
        (
            "sweep-mixed".into(),
            build(Body::Mixed).bytes,
            build(Body::Mixed).main_off,
        ),
        (
            "sweep-loop".into(),
            build(Body::Loop(120)).bytes,
            build(Body::Loop(120)).main_off,
        ),
    ];
    for f in liteinst_jit::fixtures::all() {
        cases.push((f.name.to_string(), f.bytes, 0));
    }
    cases
        .into_iter()
        .filter_map(|(name, bytes, entry_off)| {
            let region = RegionFacts {
                base,
                bytes,
                generation: Generation(1),
                immutable_private: true,
            };
            translate_with_exit_style(
                &region,
                base + entry_off,
                CountProfile::BranchesAndInstructions,
                gen_base,
                gen_base + CODE_CAP as u64,
                ExitStyle::TrapToDispatcher,
            )
            .ok()
            .map(|t| (name, t))
        })
        .collect()
}

/// P3-5 guard (I1-H H2b): every poll path recovers to a block start.
/// The mid-block restore's refusal of a raw poll budget of 0 is
/// unreachable because every stop that can hold that 0 (PollStub,
/// PollExitStub, a POLL-kind common exit) recovers to a block start
/// that resumes through the block index. Pinned on the PC map, in
/// every remote translation: each `PollStub` block and each
/// `PollExitStub` source PC is a `block_gen` key, and the two sets
/// are equal (one poll exit per poll-stub block).
#[test]
fn poll_paths_recover_to_block_starts() {
    let _corpus = corpus::guard();
    use std::collections::BTreeSet;
    let mut checked = 0;
    for (name, t) in remote_translations() {
        let mut stub_blocks = BTreeSet::new();
        let mut exit_srcs = BTreeSet::new();
        for e in t.pcmap.entries() {
            match e.recovery {
                Recovery::PollStub { block, .. } => {
                    stub_blocks.insert(block);
                }
                Recovery::PollExitStub { .. } => {
                    exit_srcs.insert(e.src_pc);
                }
                _ => {}
            }
        }
        assert!(!stub_blocks.is_empty(), "{name}: has poll stubs");
        for b in &stub_blocks {
            assert!(
                t.block_gen.contains_key(b),
                "{name}: poll stub block {b:#x} is a block start"
            );
        }
        for src in &exit_srcs {
            assert!(
                t.block_gen.contains_key(src),
                "{name}: poll exit stub source {src:#x} is a block start"
            );
        }
        assert_eq!(
            stub_blocks, exit_srcs,
            "{name}: one poll exit per poll-stub block"
        );
        checked += 1;
    }
    assert!(checked >= 20, "translations checked: {checked}");
}

/// P3-5 guard (I1-H H2b): the poll-budget seam refuses a budget of 0,
/// which would hand every poll a raw 0 and break the invariant the
/// mid-block restore check rests on. The production budget is a
/// non-zero constant.
#[test]
#[should_panic(expected = "poll budget seam: 0 breaks")]
fn poll_budget_seam_refuses_zero() {
    let _g = lock();
    let (mut remote, _deadline) = spawn_remote(&[0xc3]);
    remote.set_poll_budget_for_test(Some(0));
}

/// Q-d (I1-H H2b): tagged normalization never equates a raw value
/// with a token. Each pair below compared equal under the old
/// untagged words: a raw RDI equal to the old pid token vs the own
/// pid; a raw value equal to the old region encoding vs a code
/// address; a raw siginfo sender word vs the own-pid sender word.
/// The own-pid tag applies at a named buffer word only.
#[test]
fn tagged_normalization_never_equates_raw_and_token() {
    let info = RemoteChildInfo {
        base: 0x10_0000_0000,
        stack_top: 0x7fff_0000_0000,
        data: 0x20_0000_0000,
        dst: 0x21_0000_0000,
        src: 0x22_0000_0000,
        arena_base: 0x30_0000_0000,
        mailbox: 0x31_0000_0000,
    };
    let clen = 4096;
    let pid = 4242;
    let (mut g, mut h) = ([0u64; 18], [0u64; 18]);
    g[8] = 0x7e00_0000_0000_0001;
    h[8] = pid as u64;
    assert_eq!(
        norm_gregs_pid(&h, &info, clen, pid)[8],
        Norm::OwnPid { high: 0 }
    );
    assert_ne!(
        norm_gregs_pid(&g, &info, clen, pid),
        norm_gregs_pid(&h, &info, clen, pid),
        "raw RDI vs own pid"
    );
    assert_eq!(norm(info.base + 0x10, &info, clen), Norm::Region(1, 0x10));
    assert_ne!(
        norm(0x0100_0000_0000_0010, &info, clen),
        norm(info.base + 0x10, &info, clen),
        "raw value vs code address"
    );
    let uid = 1000u64;
    let w = 18usize;
    let (mut raw, mut own) = (vec![0u8; REPORT], vec![0u8; REPORT]);
    raw[w * 8..w * 8 + 8].copy_from_slice(&(0x7e00_0000_0000_0001u64 | (uid << 32)).to_le_bytes());
    own[w * 8..w * 8 + 8].copy_from_slice(&(pid as u64 | (uid << 32)).to_le_bytes());
    assert_eq!(
        norm_buffer_pid(&own, &info, clen, pid, &[w])[w],
        Norm::OwnPid { high: uid }
    );
    assert_ne!(
        norm_buffer_pid(&raw, &info, clen, pid, &[w]),
        norm_buffer_pid(&own, &info, clen, pid, &[w]),
        "raw sender word vs own-pid sender word"
    );
    assert_eq!(
        norm_buffer_pid(&own, &info, clen, pid, &[])[w],
        Norm::Raw(pid as u64 | (uid << 32)),
        "the own-pid tag applies at named words only"
    );
}

/// The three W5 shapes (I1-H H2). In each, main installs a
/// SIGUSR1 handler and sends SIGUSR1 to itself; the handler's
/// first USR1 run sends a second signal that the kernel keeps
/// blocked for the handler's duration, then spins past several
/// poll exits (budget `W5_POLL_BUDGET`) and returns.
#[derive(Clone, Copy, Debug)]
enum W5 {
    /// SIGUSR2 in the handler's `sa_mask`, no handler for it:
    /// after sigreturn its default action ends the native child.
    MaskDefault,
    /// SIGRTMIN+2 (34) in `sa_mask`, with the same handler: after
    /// sigreturn it is delivered.
    MaskRt,
    /// SIGUSR1 itself, no `SA_NODEFER`: the kernel blocks a
    /// handler's own signal; after sigreturn it is delivered
    /// again (the handler sends only on its first run).
    OwnSignal,
    /// SIGUSR1 itself, but the handler first resets it to
    /// `SIG_DFL`: ineligible, so the pre-H2a mirror poll stopped
    /// in the handler; after sigreturn its default action ends
    /// the native child.
    OwnSignalDefault,
}

const W5_POLL_BUDGET: u64 = 16;
/// D7: poll exits of the quiet loop 120 at budget 16 (pinned).
const D7_QUIET_POLLS: u64 = 8;
/// Handler spin iterations: each is a block entry, so the
/// handler crosses several poll exits.
const W5_SPIN: u32 = 64;
const RT34: i32 = 34;

/// A W5 fixture, and the offset of main's resume point after its
/// own `kill` (where the post-sigreturn signal acts).
fn build_w5(case: W5) -> (Gx, u64) {
    let (masked, mask_bits) = match case {
        W5::MaskDefault => (libc::SIGUSR2, 1u64 << (libc::SIGUSR2 - 1)),
        W5::MaskRt => (RT34, 1u64 << (RT34 - 1)),
        W5::OwnSignal | W5::OwnSignalDefault => (USR1, 0),
    };
    let mut a = CodeAssembler::new(64).unwrap();
    let mut handler = a.create_label();
    let mut restorer = a.create_label();
    let mut main = a.create_label();
    let mut no_send = a.create_label();
    let mut spin = a.create_label();
    let mut after_kill = a.create_label();
    a.set_label(&mut handler).unwrap();
    // Only the first SIGUSR1 run sends.
    a.cmp(edi, USR1 as u32).unwrap();
    a.jne(no_send).unwrap();
    a.cmp(qword_ptr(r13 + COUNT), 0).unwrap();
    a.jne(no_send).unwrap();
    if matches!(case, W5::OwnSignalDefault) {
        // rt_sigaction(SIGUSR1, {SIG_DFL}, NULL, 8)
        a.mov(qword_ptr(r13 + ACT), 0).unwrap();
        a.mov(qword_ptr(r13 + (ACT + 8)), 0).unwrap();
        a.mov(qword_ptr(r13 + (ACT + 16)), 0).unwrap();
        a.mov(qword_ptr(r13 + (ACT + 24)), 0).unwrap();
        a.mov(edi, USR1 as u32).unwrap();
        a.lea(rsi, qword_ptr(r13 + ACT)).unwrap();
        a.xor(edx, edx).unwrap();
        a.mov(r10d, 8u32).unwrap();
        a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
        a.syscall().unwrap();
    }
    a.mov(eax, libc::SYS_getpid as u32).unwrap();
    a.syscall().unwrap();
    a.mov(rdi, rax).unwrap();
    a.mov(esi, masked as u32).unwrap();
    a.mov(eax, libc::SYS_kill as u32).unwrap();
    a.syscall().unwrap();
    a.set_label(&mut no_send).unwrap();
    a.mov(ecx, W5_SPIN).unwrap();
    a.set_label(&mut spin).unwrap();
    a.dec(ecx).unwrap();
    a.jnz(spin).unwrap();
    a.inc(qword_ptr(r13 + COUNT)).unwrap();
    a.ret().unwrap();
    a.set_label(&mut restorer).unwrap();
    a.db(&[0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05]).unwrap();
    a.set_label(&mut main).unwrap();
    let install = |a: &mut CodeAssembler, sig: i32, mask: u64| {
        a.lea(rax, qword_ptr(rbp)).unwrap();
        a.mov(qword_ptr(r13 + ACT), rax).unwrap();
        a.mov(dword_ptr(r13 + (ACT + 8)), FLAGS).unwrap();
        a.mov(dword_ptr(r13 + (ACT + 12)), 0u32).unwrap();
        a.mov(qword_ptr(r13 + (ACT + 16)), r12).unwrap();
        a.mov(rax, mask).unwrap();
        a.mov(qword_ptr(r13 + (ACT + 24)), rax).unwrap();
        a.mov(edi, sig as u32).unwrap();
        a.lea(rsi, qword_ptr(r13 + ACT)).unwrap();
        a.xor(edx, edx).unwrap();
        a.mov(r10d, 8u32).unwrap();
        a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
        a.syscall().unwrap();
    };
    install(&mut a, USR1, mask_bits);
    if matches!(case, W5::MaskRt) {
        install(&mut a, RT34, 0);
    }
    a.cmp(rcx, rcx).unwrap();
    a.jne(handler).unwrap();
    a.mov(eax, libc::SYS_getpid as u32).unwrap();
    a.syscall().unwrap();
    a.mov(rdi, rax).unwrap();
    a.mov(esi, USR1 as u32).unwrap();
    a.mov(eax, libc::SYS_kill as u32).unwrap();
    a.syscall().unwrap();
    a.set_label(&mut after_kill).unwrap();
    a.mov(eax, 42u32).unwrap();
    a.ret().unwrap();
    let res = a
        .assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .unwrap();
    assert_eq!(res.label_ip(&handler).unwrap(), 0, "handler at 0");
    let id = match case {
        W5::MaskDefault => "H2 W5 sa_mask default",
        W5::MaskRt => "H2 W5 sa_mask RT",
        W5::OwnSignal => "H2 W5 own signal",
        W5::OwnSignalDefault => "H2 W5 own signal default",
    };
    corpus::check(id, &res.inner.code_buffer);
    let main_off = res.label_ip(&main).unwrap();
    (
        Gx {
            bytes: res.inner.code_buffer.clone(),
            handler_off: 0,
            restorer_off: res.label_ip(&restorer).unwrap(),
            main_off,
            body_off: main_off,
            cpuid_off: None,
            exit_offs: None,
        },
        res.label_ip(&after_kill).unwrap(),
    )
}

/// Normalized registers with the child's own pid tagged in RDI
/// only: the fixtures' `getpid; mov rdi, rax` leave it there, and
/// every run has its own child. No other slot is touched; RFLAGS
/// stays exact (review rev-h2a-cx P2-1). The tag cannot collide
/// with any raw RDI value (I1-H H2b, Q-d).
fn norm_gregs_pid(g: &[u64; 18], info: &RemoteChildInfo, code_len: u64, pid: i32) -> [Norm; 18] {
    const RDI: usize = 8;
    let mut n = norm_gregs(g, info, code_len);
    if g[RDI] == pid as u64 {
        n[RDI] = Norm::OwnPid { high: 0 };
    }
    n
}

/// Polls that ran before the last intercepted sigreturn: here,
/// the handler's own.
fn polls_before_sigreturn(report: &ArrivalReport) -> u64 {
    report.poll_exits - report.poll_exits_after_sigreturn
}

/// A W5 shape whose blocked signal has no handler when the
/// handler returns (`sig`): the poll takes blocking from the
/// kernel's `SigBlk`, so the run no longer stops inside the
/// handler (it crosses several polls there); after sigreturn the
/// kernel unblocks it and its default action ends the native
/// child, and the translated run stops by name at the same source
/// PC, with equal counts and registers. The pre-H2a poll, which
/// read the mirror, stopped inside the handler in both shapes
/// (the W5-mirror mutant).
fn w5_default_waits_for_sigreturn(case: W5, sig: i32, label: &str) {
    let (gx, after_kill) = build_w5(case);
    let t = run_translated(
        &gx,
        Knobs {
            poll_budget: Some(W5_POLL_BUDGET),
            ..Knobs::default()
        },
    );
    let n = run_native(&gx, None);
    assert_eq!(n.end, O1sEnd::Killed(sig), "{label}: native end");
    let f = match &t.out {
        Err(RunError::Fault(f)) => f,
        other => panic!("{label}: expected a stop after sigreturn, got {other:?}"),
    };
    assert_eq!(
        (f.kind, f.signum),
        (FaultKind::AsyncSignal, sig),
        "{label}: kind and signal"
    );
    assert_eq!(
        f.src_pc,
        t.info.base + after_kill,
        "{label}: stop at main's resume point, not in the handler"
    );
    let clen = code_len(&gx);
    assert_eq!(
        norm(n.state.rip, &n.info, clen),
        norm(f.src_pc, &t.info, clen),
        "{label}: the native child ends at the same source PC"
    );
    assert_eq!(
        (f.instructions, f.branches),
        (n.instructions, n.branches),
        "{label}: counts at the stop vs native"
    );
    assert_eq!(
        norm_gregs_pid(&state_gregs(&f.state), &t.info, clen, t.pid),
        norm_gregs_pid(&state_gregs(&n.state), &n.info, clen, n.pid),
        "{label}: registers at the stop vs native"
    );
    assert_eq!(
        word(&t.data, COUNT as usize),
        1,
        "{label}: the handler finished"
    );
    assert!(
        polls_before_sigreturn(&t.report) >= 2,
        "{label}: the handler crossed polls while the signal was pending and blocked ({:?})",
        t.report
    );
}

/// W5: SIGUSR2 in the handler's `sa_mask`, no handler for it.
#[test]
fn w5_sa_mask_blocked_signal_waits_for_sigreturn_like_native() {
    let _g = lock();
    w5_default_waits_for_sigreturn(W5::MaskDefault, libc::SIGUSR2, "W5 sa_mask default");
}

/// W5, the handler's own signal (no `SA_NODEFER`) made ineligible
/// inside the handler (reset to `SIG_DFL`), then sent: blocked by
/// the kernel for the handler's duration, so no stop in the
/// handler (review coord7 P3-2: the discriminating own-signal
/// case).
#[test]
fn w5_own_signal_default_waits_for_sigreturn_like_native() {
    let _g = lock();
    w5_default_waits_for_sigreturn(W5::OwnSignalDefault, USR1, "W5 own signal default");
}

/// Translated vs O1-S for a W5 shape whose blocked signal is
/// delivered after sigreturn: equal counts, final registers and
/// guest buffer, two deliveries each, and the handler crossed
/// polls. Regression and O1-S-equality coverage only: an
/// eligible pending signal was deferred, never a stop, under the
/// pre-H2a mirror poll as well (review coord7 P3-2), so these
/// shapes do not tell the fix from the old code; the two
/// default-action shapes above do.
fn w5_delivered_after_sigreturn(case: W5, label: &str) {
    let (gx, _) = build_w5(case);
    let t = run_translated(
        &gx,
        Knobs {
            poll_budget: Some(W5_POLL_BUDGET),
            ..Knobs::default()
        },
    );
    let out = t
        .out
        .as_ref()
        .unwrap_or_else(|e| panic!("{label}: translated: {e:?}"));
    let n = run_native(&gx, None);
    assert_eq!(n.end, O1sEnd::Returned, "{label}: O1-S end");
    assert_eq!(out.state.rax, 42, "{label}: translated result");
    assert_eq!(
        (out.instructions, out.branches),
        (n.instructions, n.branches),
        "{label}: final counts vs O1-S"
    );
    let clen = code_len(&gx);
    assert_eq!(
        norm_gregs_pid(&state_gregs(&out.state), &t.info, clen, t.pid),
        norm_gregs_pid(&state_gregs(&n.state), &n.info, clen, n.pid),
        "{label}: final registers vs O1-S"
    );
    assert_eq!(
        norm_buffer(&t.data, &t.info, clen),
        norm_buffer(&n.dst_bytes, &n.info, clen),
        "{label}: guest buffer vs O1-S"
    );
    assert_eq!(
        word(&t.data, COUNT as usize),
        2,
        "{label}: two handler runs"
    );
    assert_eq!(
        (t.report.deliveries.len(), n.deliveries.len()),
        (2, 2),
        "{label}: deliveries"
    );
    assert!(
        polls_before_sigreturn(&t.report) >= 2,
        "{label}: the handler crossed polls ({:?})",
        t.report
    );
}

/// W5 regression, eligible RT variant: signal 34 blocked by
/// `sa_mask` is delivered after sigreturn, equal to O1-S.
#[test]
fn w5_sa_mask_blocked_rt_signal_delivers_after_sigreturn() {
    let _g = lock();
    w5_delivered_after_sigreturn(W5::MaskRt, "W5 sa_mask RT");
}

/// W5 regression, eligible own signal: the handler's own signal
/// (no `SA_NODEFER`) sent inside it stays blocked through the
/// handler's polls and is delivered after sigreturn, equal to
/// O1-S.
#[test]
fn w5_own_signal_without_nodefer_delivers_after_sigreturn() {
    let _g = lock();
    w5_delivered_after_sigreturn(W5::OwnSignal, "W5 own signal");
}

/// D7 (I1-H H2): a delivery from a stop whose raw poll budget is
/// 0 (the poll path: here the first post-install PollExitStub
/// hit of the loop) restarts the budget, so polls keep firing in
/// the handler and after sigreturn. Before H2 the handler took
/// the 0, its first `dec` wrapped it to 2^64 - 1, and no poll
/// fired for the rest of the run. Polls are counted by the seam;
/// the reset is a pure function of the stop state, so a repeated
/// run counts identically.
#[test]
fn poll_budget_restarts_after_a_delivery_at_a_poll_exit() {
    let _g = lock();
    let gx = build(Body::Loop(120));
    let label = "D7 poll budget";
    let budget = Some(LOOP_POLL_BUDGET);
    let (map, base) = pcmap_of(&gx);
    let quiet = run_translated(
        &gx,
        Knobs {
            poll_budget: budget,
            ..Knobs::default()
        },
    );
    let quiet_polls = quiet.report.poll_exits;
    // Pinned (review coord7 P3-1): the quiet loop 120 at budget 16
    // takes 8 poll exits.
    assert_eq!(quiet_polls, D7_QUIET_POLLS, "{label}: quiet poll exits");
    // The first PollExitStub/Pristine entry executed after the
    // install, at its first hit.
    let (idx, want) = map
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.recovery
                == Recovery::PollExitStub {
                    stage: ExitStage::Pristine,
                }
        })
        .find_map(|(idx, e)| {
            let recs = entry_hits(&gx, budget, idx, map.len(), label);
            (!post_install_hits(&gx, e, base, recs.len() as u64).is_empty()).then(|| (idx, recs[0]))
        })
        .expect("an executed poll exit stub");
    assert_eq!(
        check_arrival(&gx, idx, 1, budget, label, want),
        Verdict::Equal,
        "{label}: the arrival delivers, equal to O1-S"
    );
    let runs: Vec<ArrivalReport> = (0..2)
        .map(|_| {
            run_translated(
                &gx,
                Knobs {
                    arrival: Some((idx, 1)),
                    poll_budget: budget,
                    ..Knobs::default()
                },
            )
            .report
        })
        .collect();
    let r = &runs[0];
    assert!(
        r.sent && r.deliveries.len() == 1,
        "{label}: one delivery: {r:?}"
    );
    // Exact (review coord7 P3-1): the arrival replaces the first
    // poll exit it interrupts; the handler (under 16 block
    // entries) polls 0 times; every later poll of the quiet run
    // still happens, all after sigreturn. A budget wrapped to
    // 2^64 - 1 gives 0, and a budget restored wrongly at the
    // block-start resume moves this count.
    assert_eq!(
        (r.poll_exits, r.poll_exits_after_sigreturn),
        (quiet_polls - 1, quiet_polls - 1),
        "{label}: poll exits (total, after sigreturn): {r:?}"
    );
    assert_eq!(
        (runs[1].poll_exits, runs[1].poll_exits_after_sigreturn),
        (r.poll_exits, r.poll_exits_after_sigreturn),
        "{label}: a repeated run polls identically"
    );
}

/// D7 rule 2 (scope rev 1.1, coord7): a raw poll budget of 0 at a
/// mid-block sigreturn restore is a broken invariant (every
/// budget-0 stop is on the poll path and resumes at its block
/// start), so the restore refuses it by name instead of resetting
/// it. The seam presents that 0 at the restore of a delivery
/// whose resume is a mid-block re-entry (a copied instruction
/// that does not start its block): the run must refuse by name.
/// Without the seam the same arrival delivers, equal to O1-S.
#[test]
fn poll_budget_zero_at_midblock_restore_refuses_by_name() {
    let _g = lock();
    let gx = build(Body::Mixed);
    let label = "D7 restore invariant";
    let (map, base, starts) = {
        let (mut remote, _deadline) = spawn_remote(&gx.bytes);
        let info = remote.info();
        let region = RegionFacts {
            base: info.base,
            bytes: gx.bytes.clone(),
            generation: Generation(1),
            immutable_private: true,
        };
        remote
            .prepare(
                &region,
                info.base + gx.main_off,
                CountProfile::BranchesAndInstructions,
            )
            .expect("prepare");
        let t = remote.translation_for_test().expect("prepared");
        let starts: std::collections::BTreeSet<u64> =
            t.block_gen.keys().map(|pc| pc - info.base).collect();
        (t.pcmap.entries().to_vec(), info.base, starts)
    };
    // The first post-install copied instruction that does not
    // start its block, at its first hit.
    let (idx, want) = map
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            let off = e.src_pc.wrapping_sub(base);
            e.recovery == Recovery::Copied
                && off >= gx.body_off
                && off < gx.bytes.len() as u64
                && !starts.contains(&off)
        })
        .find_map(|(idx, _)| {
            let recs = entry_hits(&gx, None, idx, map.len(), label);
            recs.first().map(|r| (idx, *r))
        })
        .expect("an executed mid-block copied instruction");
    assert_eq!(
        check_arrival(&gx, idx, 1, None, label, want),
        Verdict::Equal,
        "{label}: without the seam the arrival delivers, equal to O1-S"
    );
    let t = run_translated(
        &gx,
        Knobs {
            arrival: Some((idx, 1)),
            zero_raw_poll_at_restore: true,
            ..Knobs::default()
        },
    );
    assert!(
        t.report.sent && t.report.deliveries.len() == 1,
        "{label}: delivered"
    );
    assert_eq!(
        t.out.as_ref().err(),
        Some(&RunError::Refuse(liteinst_jit::Refuse::RemoteSubstrate {
            operation: "poll budget zero at mid-block restore",
            errno: 0,
        })),
        "{label}: the restore refuses by name"
    );
    assert_eq!(t.debug_regs, Some((0, 0)), "{label}: DR cleared");
}

/// O1-S negative case (review rev-h2a-cx P2-2): a stop that has
/// the handler-argument register shape but is an ordinary step.
/// SIGUSR1 is ignored (`SIG_IGN`); RDI holds 10 (SIGUSR1) and RDX
/// holds RSP + 8 as plain guest values. O1-S sends SIGUSR1 before
/// the first `nop`, re-injects it with the step, the kernel
/// discards it, the `nop` retires, and the trap reports si_code
/// TRAP_TRACE (2) with that shape still in the registers. O1-S
/// must count a retirement, not record a delivery: only the
/// si_code SIGTRAP pin tells the two apart.
#[test]
fn o1s_ignored_signal_with_handler_shaped_registers_is_a_retirement() {
    let _g = lock();
    let mut a = CodeAssembler::new(64).unwrap();
    let mut main = a.create_label();
    a.set_label(&mut main).unwrap();
    // rt_sigaction(SIGUSR1, {SIG_IGN}, NULL, 8)
    a.mov(qword_ptr(r13 + ACT), 1).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 8)), 0).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 16)), 0).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 24)), 0).unwrap();
    a.mov(edi, USR1 as u32).unwrap();
    a.lea(rsi, qword_ptr(r13 + ACT)).unwrap();
    a.xor(edx, edx).unwrap();
    a.mov(r10d, 8u32).unwrap();
    a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
    a.syscall().unwrap();
    // The handler-argument shape, as ordinary values.
    a.mov(edi, USR1 as u32).unwrap();
    a.lea(rdx, qword_ptr(rsp + 8)).unwrap();
    a.nop().unwrap();
    a.nop().unwrap();
    a.mov(eax, 42u32).unwrap();
    a.ret().unwrap();
    let res = a
        .assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .unwrap();
    corpus::check("H2 O1-S ignored signal shape", &res.inner.code_buffer);
    let gx = Gx {
        bytes: res.inner.code_buffer.clone(),
        handler_off: 0,
        restorer_off: 0,
        main_off: res.label_ip(&main).unwrap(),
        body_off: 0,
        cpuid_off: None,
        exit_offs: None,
    };
    let label = "O1-S ignored signal shape";
    let quiet = run_native(&gx, None);
    assert_eq!(quiet.end, O1sEnd::Returned, "{label}: quiet end");
    assert!(quiet.deliveries.is_empty(), "{label}: quiet deliveries");
    assert!(quiet.injections.is_empty(), "{label}: quiet injections");
    // Arrive before the first `nop` (the last four instructions are
    // nop, nop, mov, ret).
    let k = quiet.instructions - 4;
    let n = run_native(&gx, Some((k, USR1)));
    // P3-A (I1-H H2b): the step the arrival was injected with, shape
    // first, so an arrival moved off the shaped step fails here by
    // name rather than passing vacuously.
    assert_eq!(
        n.injections.len(),
        1,
        "{label}: one injected step: {:?}",
        n.injections
    );
    let inj = n.injections[0];
    assert!(
        inj.entry_shape,
        "{label}: arrival step has the handler-entry shape: {inj:?}"
    );
    assert_eq!(
        inj.si_code, 2,
        "{label}: the injected step reports TRAP_TRACE (2): {inj:?}"
    );
    assert_eq!(inj.signo, USR1, "{label}: injected signal: {inj:?}");
    assert_eq!(
        inj.instructions, k,
        "{label}: injected at the arrival count: {inj:?}"
    );
    assert!(n.arrival_sent, "{label}: arrival sent at k = {k}");
    assert_eq!(n.end, O1sEnd::Returned, "{label}: end");
    assert!(
        n.deliveries.is_empty(),
        "{label}: an ignored signal's step is not a delivery: {:?}",
        n.deliveries
    );
    assert_eq!(
        (n.instructions, n.branches),
        (quiet.instructions, quiet.branches),
        "{label}: the stepped nop is counted as retired"
    );
    assert_eq!(n.state.rax, 42, "{label}: result");
}

/// coord7 Q4: O1-S shares no classification code with the
/// translator, shown from the source module graph rather than
/// asserted. `src/o1.rs` may name only `crate::harness`,
/// `crate::state`, and, from `crate::remote`, the plain
/// `RemoteChildInfo` record (whose item text names no other crate
/// item). The modules reachable from those never include the
/// translator's decode, translate, pcmap, recovery, exec or
/// cache modules. Its `liteinst_x86` import is exactly the shared
/// decoder and its plain types: that shared decoder is the stated
/// common-mode risk for branch counts (SIGNAL-CORPUS.md), which
/// the per-step RIP-delta check bounds.
#[test]
fn o1_oracle_imports_no_translator_classification() {
    use std::collections::BTreeSet;
    let sources: BTreeMap<&str, &str> = BTreeMap::from([
        ("o1", include_str!("../src/o1.rs")),
        ("harness", include_str!("../src/harness.rs")),
        ("state", include_str!("../src/state.rs")),
        ("types", include_str!("../src/types.rs")),
        ("refuse", include_str!("../src/refuse.rs")),
    ]);
    let paths = |text: &str| -> BTreeSet<(String, String)> {
        let ident = |s: &str| -> String {
            s.chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect()
        };
        text.match_indices("crate::")
            .map(|(i, _)| {
                let rest = &text[i + 7..];
                let module = ident(rest);
                let item = rest[module.len()..]
                    .strip_prefix("::")
                    .map(ident)
                    .unwrap_or_default();
                (module, item)
            })
            .collect()
    };
    let o1 = paths(sources["o1"]);
    let o1_modules: BTreeSet<&str> = o1.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(
        o1_modules,
        BTreeSet::from(["harness", "remote", "state"]),
        "o1.rs crate modules"
    );
    let remote_items: BTreeSet<&str> = o1
        .iter()
        .filter(|(m, _)| m == "remote")
        .map(|(_, i)| i.as_str())
        .collect();
    assert_eq!(
        remote_items,
        BTreeSet::from(["RemoteChildInfo"]),
        "remote items"
    );
    let x86: Vec<&str> = sources["o1"]
        .lines()
        .filter(|l| l.contains("liteinst_x86"))
        .collect();
    assert_eq!(
        x86,
        ["use liteinst_x86::{Code, Instruction, Mnemonic, OpKind, decoder64};"],
        "o1.rs shared-decoder import"
    );
    // Module graph closure from the allowed modules.
    let forbidden = ["decode", "translate", "pcmap", "recovery", "exec", "cache"];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut work: Vec<String> = vec!["harness".into(), "state".into()];
    while let Some(m) = work.pop() {
        if !seen.insert(m.clone()) {
            continue;
        }
        assert!(!forbidden.contains(&m.as_str()), "o1.rs reaches {m}");
        let text = sources
            .get(m.as_str())
            .unwrap_or_else(|| panic!("module {m} not in the checked set"));
        work.extend(paths(text).into_iter().map(|(m, _)| m));
    }
    assert_eq!(
        seen,
        ["harness", "refuse", "state", "types"]
            .into_iter()
            .map(String::from)
            .collect(),
        "modules reachable from o1.rs"
    );
    // The one remote item is plain data.
    let remote = include_str!("../src/remote.rs");
    let start = remote.find("pub struct RemoteChildInfo").expect("item");
    let end = start + remote[start..].find("\nfn remote_err").expect("item end");
    let item = &remote[start..end];
    for word in ["crate::", "super::", "Self::"] {
        assert!(!item.contains(word), "RemoteChildInfo names `{word}`");
    }
    let fields = [
        "base",
        "stack_top",
        "data",
        "dst",
        "src",
        "arena_base",
        "mailbox",
    ];
    for (i, _) in item.match_indices("self.") {
        let name: String = item[i + 5..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        assert!(
            fields.contains(&name.as_str()),
            "RemoteChildInfo reads self.{name}"
        );
    }
}

/// The corpus pin's own checks: SHA-256 known answers (FIPS
/// 180-4 examples) and a well-formed table (no duplicate IDs,
/// every pinned row a 64-digit hash).
#[test]
fn corpus_hash_known_answers_and_table() {
    assert_eq!(
        corpus::hex(&corpus::sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        corpus::hex(&corpus::sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        corpus::hex(&corpus::sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // Every pinned ID, exactly: a row added or dropped is a
    // reviewed edit here too. (Each test's own `check` proves its
    // IDs are present and current.)
    let table = corpus::table();
    assert_eq!(table.len(), 83, "pinned fixtures");
}
