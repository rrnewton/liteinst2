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
//!
//! Fixture layout (buffer at r13 = dst; r13 is never written by
//! guest code):
//! - one SA_SIGINFO handler at offset 0, logging into `SLOT`;
//! - the restorer;
//! - main, whose prologue block installs the handler;
//! - the body, which starts at the next block.
//!
//! Each test holds `SERIAL`, so ptrace children and signals from
//! different tests never overlap.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[path = "common/corpus.rs"]
mod corpus;

use iced_x86::BlockEncoderOptions;
use iced_x86::code_asm::*;
use liteinst_jit::exec::{FaultKind, Outcome, RunError};
use liteinst_jit::harness::RETURN_SENTINEL;
use liteinst_jit::o1::{O1sEnd, O1sOutcome, run_o1s};
use liteinst_jit::remote::{ArrivalReport, ArrivalSeam, RemoteChildInfo, RemoteExecutable};
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};
use liteinst_jit::{CallStage, CommonStage, ExitStage, PcMapEntry, Recovery, StubStage};

const REMOTE_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-remote-child");

static SERIAL: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
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
    for i in 0..4 {
        a.mov(rax, qword_ptr(rsi + 8 * i)).unwrap();
        a.mov(qword_ptr(r13 + (SLOT + 8 * i)), rax).unwrap();
    }
    for i in 0..18 {
        a.mov(rax, qword_ptr(rdx + (40 + 8 * i))).unwrap();
        a.mov(qword_ptr(r13 + (SLOT + 32 + 8 * i)), rax).unwrap();
    }
    a.mov(rax, qword_ptr(rdx + 296)).unwrap();
    a.mov(qword_ptr(r13 + (SLOT + 176)), rax).unwrap();
    a.add(qword_ptr(rdx + UC_R15), R15_MARK).unwrap();
    a.inc(qword_ptr(r13 + COUNT)).unwrap();
    a.ret().unwrap();
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

/// Normalize a value to `(region id << 56) | offset` when it
/// points into one of the child's known regions; other values
/// stay raw. Generated (arena) addresses are deliberately not a
/// region: one leaking into guest state is a mismatch.
fn norm(v: u64, info: &RemoteChildInfo, code_len: u64) -> u64 {
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
            return ((i as u64 + 1) << 56) | (v - lo);
        }
    }
    v
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
fn norm_gregs(g: &[u64; 18], info: &RemoteChildInfo, code_len: u64) -> [u64; 18] {
    core::array::from_fn(|i| {
        if i == 17 {
            g[i]
        } else {
            norm(g[i], info, code_len)
        }
    })
}

/// Normalized guest buffer: `REPORT` bytes as words.
/// The siginfo sender word (pid | uid << 32) needs no special
/// case: both engines' arrival signal comes from this test
/// process, and the word lies in no address region.
fn norm_buffer(d: &[u8], info: &RemoteChildInfo, code_len: u64) -> Vec<u64> {
    (0..REPORT / 8)
        .map(|i| norm(word(d, i * 8), info, code_len))
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
}

/// Knobs for one translated run.
#[derive(Clone, Copy, Default)]
struct Knobs {
    /// Arrival at PC-map entry `index`, on hit `hit`.
    arrival: Option<(usize, u64)>,
    poll_budget: Option<u64>,
    pre_original_step_signal: Option<i32>,
}

fn run_translated(gx: &Gx, k: Knobs) -> TArrival {
    let mut remote = RemoteExecutable::spawn_bytes(std::path::Path::new(REMOTE_CHILD), &gx.bytes)
        .expect("spawn remote");
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
                sig: USR1,
            }),
    );
    remote.set_poll_budget_for_test(k.poll_budget);
    remote.set_pre_original_step_signal_for_test(k.pre_original_step_signal);
    let mut s = remote.initial_state();
    s.rip = info.base + gx.main_off;
    s.rbp = info.base + gx.handler_off;
    s.r12 = info.base + gx.restorer_off;
    s.r13 = info.dst;
    let out = remote.run(s, RETURN_SENTINEL);
    let report = remote.arrival_report_for_test();
    let debug_regs = remote.debug_regs_for_test();
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
    }
}

fn run_native(gx: &Gx, arrival: Option<(u64, i32)>) -> O1sOutcome {
    let (main, restorer, handler) = (gx.main_off, gx.restorer_off, gx.handler_off);
    run_o1s(
        std::path::Path::new(REMOTE_CHILD),
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
    /// W1: an asynchronous stop in the common exit stays a
    /// recovered AsyncSignal (today's named refusal).
    RefusedW1,
}

/// Run one arrival in both engines; panic on any mismatch.
fn check_arrival(gx: &Gx, idx: usize, hit: u64, poll_budget: Option<u64>, label: &str) -> Verdict {
    let t = run_translated(
        gx,
        Knobs {
            arrival: Some((idx, hit)),
            poll_budget,
            ..Knobs::default()
        },
    );
    assert_eq!(
        t.debug_regs,
        Some((0, 0)),
        "{label}: debug registers cleared after the run"
    );
    let (gen_pc, entry) = t.target.expect("arrival target");
    let class = class_of(&entry);
    if !t.report.sent {
        let out = t
            .out
            .as_ref()
            .unwrap_or_else(|e| panic!("{label}: unreached arrival, run failed: {e:?}"));
        assert_eq!(out.state.rax, 42, "{label}: unreached arrival result");
        assert!(t.report.deliveries.is_empty(), "{label}: no delivery");
        return Verdict::NotReached;
    }
    let clen = code_len(gx);
    match &t.out {
        Err(RunError::Fault(f)) if f.kind == FaultKind::AsyncSignal => {
            assert_eq!(f.signum, USR1, "{label}: refused signal");
            assert!(
                class.starts_with("CommonExit/"),
                "{label}: refusal outside W1-W3 at {class} (gen {gen_pc:#x}): {f:?}"
            );
            assert!(
                t.report.deliveries.is_empty(),
                "{label}: refused, no delivery"
            );
            return Verdict::RefusedW1;
        }
        Err(e) => panic!("{label}: arrival at {class} hit {hit}: translated error {e:?}"),
        Ok(_) => {}
    }
    let out = t.out.as_ref().unwrap();
    assert_eq!(out.state.rax, 42, "{label}: translated result");
    assert_eq!(
        t.report.deliveries.len(),
        1,
        "{label}: one delivery recorded: {:?}",
        t.report.deliveries
    );
    let d = t.report.deliveries[0];
    assert_eq!(
        (d.signum, d.gen_pc),
        (USR1, gen_pc),
        "{label}: delivery provenance"
    );
    let n = run_native(gx, Some((d.instructions, USR1)));
    assert_eq!(n.end, O1sEnd::Returned, "{label}: O1-S end");
    assert!(
        n.arrival_sent,
        "{label}: O1-S reached k = {}",
        d.instructions
    );
    assert_eq!(n.deliveries.len(), 1, "{label}: O1-S deliveries");
    let nd = &n.deliveries[0];
    assert_eq!(
        (nd.instructions, nd.branches),
        (d.instructions, d.branches),
        "{label}: retired totals at delivery (O1-S vs recovered)"
    );
    assert_eq!(
        norm(nd.gregs[16], &n.info, clen),
        norm(d.src_pc, &t.info, clen),
        "{label}: frame RIP is the recovered source PC"
    );
    // The handler's own log in O1-S equals O1-S's frame read.
    let slot = |data: &[u8]| -> Vec<u64> {
        (0..SLOT_WORDS)
            .map(|i| word(data, SLOT as usize + 8 * i))
            .collect()
    };
    let n_slot = slot(&n.dst_bytes);
    assert_eq!(&n_slot[4..22], &nd.gregs[..], "{label}: O1-S log vs frame");
    // Handler-visible frame, register by register.
    let tg: [u64; 18] = slot(&t.data)[4..22].try_into().unwrap();
    let (tn, nn) = (
        norm_gregs(&tg, &t.info, clen),
        norm_gregs(&nd.gregs, &n.info, clen),
    );
    for (i, name) in GREG_NAMES.iter().enumerate() {
        assert_eq!(
            tn[i], nn[i],
            "{label}: arrival at {class} hit {hit}: frame {name} translated {:#x} vs native {:#x}",
            tg[i], nd.gregs[i]
        );
    }
    assert_eq!(
        norm_buffer(&t.data, &t.info, clen),
        norm_buffer(&n.dst_bytes, &n.info, clen),
        "{label}: arrival at {class} hit {hit}: guest buffer (siginfo, mask, results)"
    );
    let (ts, ns) = (state_gregs(&out.state), state_gregs(&n.state));
    let (tsn, nsn) = (
        norm_gregs(&ts, &t.info, clen),
        norm_gregs(&ns, &n.info, clen),
    );
    for (i, name) in GREG_NAMES.iter().enumerate() {
        assert_eq!(
            tsn[i], nsn[i],
            "{label}: arrival at {class} hit {hit}: final {name} translated {:#x} vs native {:#x}",
            ts[i], ns[i]
        );
    }
    assert_eq!(
        (out.instructions, out.branches),
        (n.instructions, n.branches),
        "{label}: arrival at {class} hit {hit}: final counts"
    );
    Verdict::Equal
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

/// Hits of one PC-map entry over a whole quiet run: the arrival
/// breakpoint stays armed and never fires.
fn hit_counts(gx: &Gx, poll_budget: Option<u64>, entries: usize, label: &str) -> Vec<u64> {
    (0..entries)
        .map(|idx| {
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
            t.report.hits
        })
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
/// total across the two); any truncation is printed with counts.
const SWEEP_CAP: Duration = Duration::from_secs(60);
const SWEEP_SEED: u64 = 0x11e4_5eed_2026_1111;
/// Sample size for the poll-crossing loop (coord7 Q5).
const LOOP_SAMPLES: usize = 256;
/// Poll budget for the loop sweep: 120 iterations cross several
/// poll exits instead of needing 16384 block entries.
const LOOP_POLL_BUDGET: u64 = 16;

/// Run `plan` (entry index, hit) under the cap; return the
/// per-class table, with every arrival checked.
fn run_plan(
    gx: &Gx,
    poll_budget: Option<u64>,
    plan: &[(usize, u64)],
    table: &mut BTreeMap<String, Tally>,
    classes: &[String],
    label: &str,
) -> bool {
    let started = Instant::now();
    let mut ran = 0;
    for &(idx, hit) in plan {
        if started.elapsed() > SWEEP_CAP {
            eprintln!(
                "{label}: TRUNCATED at the {SWEEP_CAP:?} cap: ran {ran} of {} planned arrivals; \
                 {} not run",
                plan.len(),
                plan.len() - ran
            );
            break;
        }
        ran += 1;
        let v = check_arrival(gx, idx, hit, poll_budget, &format!("{label} #{idx}@{hit}"));
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
    ran < plan.len()
}

/// Every class with an executed entry got at least one arrival.
/// A truncated sweep cannot claim this; it says so instead.
fn assert_executed_classes_arrived(label: &str, table: &BTreeMap<String, Tally>, truncated: bool) {
    if truncated {
        eprintln!("{label}: class coverage NOT asserted (sweep truncated)");
        return;
    }
    for (class, t) in table {
        assert!(
            t.executed == 0 || t.arrivals > 0,
            "{label}: executed class {class} got no arrival"
        );
    }
}

/// Classes and counts for one fixture: the quiet run, then one
/// counting run per PC-map entry.
fn survey(
    gx: &Gx,
    poll_budget: Option<u64>,
    label: &str,
) -> (Vec<String>, Vec<PcMapEntry>, Vec<u64>, u64) {
    let (t, _) = quiet(gx, poll_budget, label);
    let entries = t.entries;
    let (map, base) = pcmap_of(gx);
    assert_eq!(map.len(), entries, "{label}: PC-map size");
    let classes: Vec<String> = map.iter().map(class_of).collect();
    let hits = hit_counts(gx, poll_budget, entries, label);
    (classes, map, hits, base)
}

/// The PC map of one prepared child, and that child's fixture
/// base (entry `src_pc`s are absolute).
fn pcmap_of(gx: &Gx) -> (Vec<PcMapEntry>, u64) {
    let mut remote = RemoteExecutable::spawn_bytes(std::path::Path::new(REMOTE_CHILD), &gx.bytes)
        .expect("spawn remote");
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
/// every PC-map class. Delivered arrivals must equal O1-S exactly;
/// the only refusal allowed today is W1 (common exit).
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
        let range = post_install_hits(&gx, e, base, hits[idx]);
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
    let truncated = run_plan(&gx, None, &plan, &mut table, &classes, label);
    print_table(label, &table);
    assert_executed_classes_arrived(label, &table, truncated);
    let equal: u64 = table.values().map(|t| t.equal).sum();
    let refused: u64 = table.values().map(|t| t.refused_w1).sum();
    assert!(equal > 0 && refused > 0, "{label}: both outcomes seen");
    for (class, t) in &table {
        if class.starts_with("CommonExit/") {
            assert_eq!(t.equal, 0, "{label}: {class} delivers nothing today");
        } else {
            assert_eq!(t.refused_w1, 0, "{label}: {class} refusals");
        }
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
        let range = post_install_hits(&gx, e, base, hits[idx]);
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
    let truncated = run_plan(&gx, budget, &plan, &mut table, &classes, label);
    print_table(label, &table);
    assert_executed_classes_arrived(label, &table, truncated);
    for (class, t) in &table {
        if !class.starts_with("CommonExit/") {
            assert_eq!(t.refused_w1, 0, "{label}: {class} refusals");
        }
    }
    let poll_path = table
        .iter()
        .filter(|(c, _)| c.starts_with("PollExitStub/"))
        .map(|(_, t)| t.executed)
        .sum::<u64>();
    assert!(poll_path > 0, "{label}: the poll-exit path executed");
}

/// W1 held arrivals (flip in H2). The remote translation has one
/// common exit, and its first instruction (`BeforeRspSave`) runs
/// once per dispatcher exit: hit 1 is the install's
/// `rt_sigaction`, hits 2..=5 are the Mixed body's exits in order
/// (the helper's `ret`, `write`, `cpuid`, main's final `ret`),
/// and there is no hit 6. SIGUSR1 arriving at each post-install
/// hit is today a recovered AsyncSignal at that exit's source PC,
/// the handler never runs, and the debug registers are cleared.
#[test]
fn w1_common_exit_arrival_is_named_refusal_today() {
    let _g = lock();
    let gx = build(Body::Mixed);
    let (map, _) = pcmap_of(&gx);
    let idx = map
        .iter()
        .position(|e| {
            e.recovery
                == Recovery::CommonExit {
                    stage: CommonStage::BeforeRspSave,
                }
        })
        .expect("common exit entry");
    let names = ["helper ret", "write", "cpuid", "main ret"];
    for (k, (off, name)) in gx.exit_offs.unwrap().into_iter().zip(names).enumerate() {
        let hit = k as u64 + 2;
        let t = run_translated(
            &gx,
            Knobs {
                arrival: Some((idx, hit)),
                ..Knobs::default()
            },
        );
        assert!(t.report.sent, "W1 hit {hit} ({name}): arrival fired");
        assert_eq!(
            t.debug_regs,
            Some((0, 0)),
            "W1 hit {hit} ({name}): DR cleared on the refusal path"
        );
        match &t.out {
            Err(RunError::Fault(f)) => {
                assert_eq!(f.kind, FaultKind::AsyncSignal, "W1 hit {hit}: kind");
                assert_eq!(f.signum, USR1, "W1 hit {hit}: signal");
                assert_eq!(
                    f.src_pc,
                    t.info.base + off,
                    "W1 hit {hit}: the {name} exit's source PC"
                );
            }
            other => panic!("W1 hit {hit} ({name}): expected today's named refusal, got {other:?}"),
        }
        assert_eq!(
            word(&t.data, COUNT as usize),
            0,
            "W1 hit {hit} ({name}): handler never ran"
        );
    }
    // Exactly five executions: hit 6 is never reached.
    let t = run_translated(
        &gx,
        Knobs {
            arrival: Some((idx, 6)),
            ..Knobs::default()
        },
    );
    assert!(!t.report.sent, "W1: no sixth common-exit execution");
    assert_eq!(t.out.as_ref().map(|o| o.state.rax).ok(), Some(42));
    assert_eq!(t.debug_regs, Some((0, 0)), "W1: DR cleared, unreached");
}

/// W3 held arrival (flips in H2): SIGUSR1 sent just before the
/// tracer single-steps the original `cpuid` is today a recovered
/// AsyncSignal at the `cpuid` source PC, with `cpuid` not
/// executed (RBX still zero, not a vendor word).
#[test]
fn w3_original_step_arrival_is_named_refusal_today() {
    let _g = lock();
    let gx = build(Body::Mixed);
    let t = run_translated(
        &gx,
        Knobs {
            pre_original_step_signal: Some(USR1),
            ..Knobs::default()
        },
    );
    match &t.out {
        Err(RunError::Fault(f)) => {
            assert_eq!(f.kind, FaultKind::AsyncSignal, "W3: kind");
            assert_eq!(f.signum, USR1, "W3: signal");
            assert_eq!(
                f.src_pc,
                t.info.base + gx.cpuid_off.unwrap(),
                "W3: the cpuid source PC"
            );
            assert_eq!((f.state.rax, f.state.rbx), (0, 0), "W3: cpuid did not run");
        }
        other => panic!("W3: expected today's named refusal, got {other:?}"),
    }
    assert_eq!(word(&t.data, COUNT as usize), 0, "W3: handler never ran");
    // The seam is inert by default: the same run completes.
    let quiet = run_translated(&gx, Knobs::default());
    assert_eq!(quiet.out.as_ref().map(|o| o.state.rax).ok(), Some(42));
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
    use liteinst_jit::exec::CODE_CAP;
    use liteinst_jit::{ExitStyle, translate_with_exit_style};
    let base = 0x10_0000_0000u64;
    let gen_base = 0x10_4000_0000u64;
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
    let mut checked = 0;
    for (name, bytes, entry_off) in cases {
        let region = RegionFacts {
            base,
            bytes,
            generation: Generation(1),
            immutable_private: true,
        };
        let Ok(t) = translate_with_exit_style(
            &region,
            base + entry_off,
            CountProfile::BranchesAndInstructions,
            gen_base,
            gen_base + CODE_CAP as u64,
            ExitStyle::TrapToDispatcher,
        ) else {
            continue;
        };
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

/// W5 held behaviour (flips in H2): the mirrored mask is stale
/// during a handler. The SIGUSR1 handler has SIGUSR2 in its
/// `sa_mask`, sends SIGUSR2 (no handler, so not deliverable in
/// this stage) to itself, and spins past a poll exit. Today the
/// poll reads SIGUSR2 as unblocked and stops the run inside the
/// handler, although the kernel has SIGUSR2 blocked there.
#[test]
fn w5_stale_mirror_stops_in_handler_today() {
    let _g = lock();
    const USR2: i32 = libc::SIGUSR2;
    let mut a = CodeAssembler::new(64).unwrap();
    let mut handler = a.create_label();
    let mut restorer = a.create_label();
    let mut main = a.create_label();
    let mut spin = a.create_label();
    a.set_label(&mut handler).unwrap();
    a.mov(eax, libc::SYS_getpid as u32).unwrap();
    a.syscall().unwrap();
    a.mov(rdi, rax).unwrap();
    a.mov(esi, USR2 as u32).unwrap();
    a.mov(eax, libc::SYS_kill as u32).unwrap();
    a.syscall().unwrap();
    a.mov(ecx, 40_000u32).unwrap();
    a.set_label(&mut spin).unwrap();
    a.dec(ecx).unwrap();
    a.jnz(spin).unwrap();
    a.inc(qword_ptr(r13 + COUNT)).unwrap();
    a.ret().unwrap();
    a.set_label(&mut restorer).unwrap();
    a.db(&[0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05]).unwrap();
    a.set_label(&mut main).unwrap();
    a.lea(rax, qword_ptr(rbp)).unwrap();
    a.mov(qword_ptr(r13 + ACT), rax).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 8)), FLAGS).unwrap();
    a.mov(dword_ptr(r13 + (ACT + 12)), 0u32).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 16)), r12).unwrap();
    a.mov(qword_ptr(r13 + (ACT + 24)), 1i32 << (USR2 - 1))
        .unwrap();
    a.mov(edi, USR1 as u32).unwrap();
    a.lea(rsi, qword_ptr(r13 + ACT)).unwrap();
    a.xor(edx, edx).unwrap();
    a.mov(r10d, 8u32).unwrap();
    a.mov(eax, libc::SYS_rt_sigaction as u32).unwrap();
    a.syscall().unwrap();
    a.cmp(rcx, rcx).unwrap();
    a.jne(handler).unwrap();
    a.mov(eax, libc::SYS_getpid as u32).unwrap();
    a.syscall().unwrap();
    a.mov(rdi, rax).unwrap();
    a.mov(esi, USR1 as u32).unwrap();
    a.mov(eax, libc::SYS_kill as u32).unwrap();
    a.syscall().unwrap();
    a.mov(eax, 42u32).unwrap();
    a.ret().unwrap();
    let res = a
        .assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .unwrap();
    let restorer_off = res.label_ip(&restorer).unwrap();
    corpus::check("H1 W5 stale mirror", &res.inner.code_buffer);
    let gx = Gx {
        bytes: res.inner.code_buffer.clone(),
        handler_off: 0,
        restorer_off,
        main_off: res.label_ip(&main).unwrap(),
        body_off: res.label_ip(&main).unwrap(),
        cpuid_off: None,
        exit_offs: None,
    };
    let mut remote = RemoteExecutable::spawn_bytes(std::path::Path::new(REMOTE_CHILD), &gx.bytes)
        .expect("spawn remote");
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
    let mut s = remote.initial_state();
    s.rip = info.base + gx.main_off;
    s.rbp = info.base;
    s.r12 = info.base + restorer_off;
    s.r13 = info.dst;
    let out = remote.run(s, RETURN_SENTINEL);
    let f = match out {
        Err(RunError::Fault(f)) => f,
        other => panic!("W5: expected today's stop in the handler, got {other:?}"),
    };
    assert_eq!(f.kind, FaultKind::AsyncSignal, "W5: kind");
    assert_eq!(f.signum, USR2, "W5: the sa_mask-blocked signal");
    assert!(
        f.src_pc >= info.base && f.src_pc < info.base + restorer_off,
        "W5: stop inside the handler (src {:#x})",
        f.src_pc - info.base
    );
    let status = std::fs::read_to_string(format!("/proc/{}/status", remote.child_pid_for_test()))
        .expect("child status");
    let field = |name: &str| -> u64 {
        let v = status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .expect("status field");
        u64::from_str_radix(v.trim(), 16).expect("hex")
    };
    let bit = 1u64 << (USR2 - 1);
    assert_ne!(
        field("SigBlk:") & bit,
        0,
        "W5: the kernel had SIGUSR2 blocked"
    );
    assert_ne!(
        (field("SigPnd:") | field("ShdPnd:")) & bit,
        0,
        "W5: SIGUSR2 still pending"
    );
    let mut count = [0u8; 8];
    assert!(remote.read_mem(info.dst + COUNT as u64, &mut count));
    assert_eq!(
        u64::from_le_bytes(count),
        0,
        "W5: the handler did not finish"
    );
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
    assert_eq!(table.len(), 74, "pinned fixtures");
}
