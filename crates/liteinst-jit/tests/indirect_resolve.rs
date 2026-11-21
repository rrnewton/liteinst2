//! P1b.1: dispatcher-resolved indirect transfers.
//!
//! - `resolver_forms` (T3): the pure resolver's targets, kinds and
//!   next IPs, with pinned memory that tells the right effective
//!   address from the wrong ones, and the forms it refuses.
//! - `refusal_{inprocess,remote}` (T4): out-of-region targets refuse
//!   at the instruction before any push or write; an interior entry
//!   refuses with the state before; a RETURN to an untranslated
//!   in-region address still refuses as in P1a.
//! - `fault_{inprocess,remote}` (T6): a faulting memory operand is a
//!   guest fault at the instruction, which does not retire.
//! - `discovery_{inprocess,remote}` and `install_failure_remote`
//!   (T7): new targets are translated on first use and reused after,
//!   and a failed remote install refuses and poisons the executable.
//!
//! The in-process dispatcher and the traced children share
//! process-global state, so every test holds the serial lock.

use std::collections::BTreeMap;

use liteinst_jit::decode::{DecodedInsn, decode_one};
use liteinst_jit::exec::{
    BudgetEnd, BudgetStop, Executable, FaultKind, Outcome, ProcessMemory, RunError,
};
use liteinst_jit::fixtures;
use liteinst_jit::handler::CaptureHandler;
use liteinst_jit::harness::{MappedGuest, REDZONE_MARKER, RETURN_SENTINEL};
use liteinst_jit::indirect::{IndirectKind, ResolveError, Resolved, resolve};
use liteinst_jit::remote::{RemoteChildInfo, RemoteExecutable};
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};
use liteinst_jit::{GuestState, Refuse};

#[path = "common/deadline.rs"]
mod deadline;

const REMOTE_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-remote-child");
/// A budget no fixture here reaches, so a budget run ends only at a
/// handoff or the sentinel.
const BIG: u64 = 100;

/// A RETURN to an in-region address that no direct edge reaches.
const RET_UNTRANSLATED: &[u8] = &[
    0x48, 0x8d, 0x05, 0x03, 0x00, 0x00, 0x00, // 00 lea rax, [rip+3] (L)
    0x50, // 07 push rax
    0xc3, // 08 ret (to L)
    0x90, // 09 nop (never decoded)
    0xc3, // 0a L: ret
];
const RET_L: u64 = 0x0a;

/// Out-of-region refusals: (fixture, offset of the indirect insn).
const OUT_OF_REGION: [(&str, u64); 3] = [
    ("ind_call_out", 0x00),
    ("indirect_jmp", 0x03),
    ("jump_table", 0x00),
];

/// T7: (fixture, retranslations after one run on a fresh executable).
const DISCOVERY: [(&str, u64); 6] = [
    ("ind_jmp_reg", 1),
    ("ind_call_reg", 1),
    ("ind_jmp_table", 4),
    ("ind_call_mem", 1),
    ("indirect_call", 1),
    ("ind_jmp_known", 0),
];

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// One test's hold: the serial lock, then the test's bound (see
/// `common/deadline.rs`). The bound starts only after the lock is
/// held, and is dropped after it.
struct Serial {
    _lock: std::sync::MutexGuard<'static, ()>,
    _bound: deadline::TestBound,
}

fn lock() -> Serial {
    Serial {
        _lock: deadline::serial_lock(&SERIAL),
        _bound: deadline::TestBound::arm(),
    }
}

/// An in-process executable for `bytes` with `name`'s inputs; the
/// guest mapping must outlive every run.
fn inproc(name: &str, bytes: &[u8], budgeted: bool) -> (MappedGuest, Executable, GuestState) {
    let guest = MappedGuest::map(bytes).expect("map");
    guest.plant_below_rsp(REDZONE_MARKER);
    let region = guest.region(bytes, Generation(1));
    let profile = CountProfile::BranchesAndInstructions;
    let prepared = if budgeted {
        Executable::prepare_budgeted(&region, guest.base, profile)
    } else {
        Executable::prepare(&region, guest.base, profile)
    };
    let exec = prepared.expect("prepare");
    let mut state = guest.initial_state();
    let (rdi, rsi, rdx, rax, rcx) = MappedGuest::fixture_args(name, guest.base, 0, 0, 0);
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = rax;
    state.rcx = rcx;
    (guest, exec, state)
}

/// A remote executable for `bytes` with `name`'s inputs, armed with
/// its run deadline (hold it as long as the executable).
fn remote(
    name: &str,
    bytes: &[u8],
    budgeted: bool,
) -> (
    RemoteExecutable,
    deadline::Deadline,
    GuestState,
    RemoteChildInfo,
) {
    let spawned = deadline::remote_bytes(REMOTE_CHILD, bytes);
    let (mut remote, dl) = spawned.expect("spawn remote");
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: bytes.to_vec(),
        generation: Generation(1),
        immutable_private: true,
    };
    let profile = CountProfile::BranchesAndInstructions;
    let prepared = if budgeted {
        remote.prepare_budgeted(&region, info.base, profile)
    } else {
        remote.prepare(&region, info.base, profile)
    };
    prepared.expect("prepare remote");
    let mut state = remote.initial_state();
    let (rdi, rsi, rdx, rax, rcx) =
        MappedGuest::fixture_args(name, info.base, info.data, info.dst, info.src);
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = rax;
    state.rcx = rcx;
    (remote, dl, state, info)
}

fn run_inproc(exec: &mut Executable, state: GuestState) -> Result<Outcome, RunError> {
    let mut handler = CaptureHandler::default();
    exec.run(state, &mut handler, &ProcessMemory, RETURN_SENTINEL)
}

fn budget_stop(what: &str, stop: Result<BudgetStop, RunError>) -> BudgetStop {
    match stop {
        Ok(s) => s,
        Err(e) => panic!("{what}: budget run: {e:?}"),
    }
}

/// The qword in the slot right below the initial RSP (the slot a
/// call's push writes), in-process.
fn below_rsp(guest: &MappedGuest) -> u64 {
    let w = guest.stack_window();
    u64::from_le_bytes(w[120..128].try_into().expect("8 bytes"))
}

/// Whether any tracer write touched the 8 bytes right below `rsp`.
fn wrote_below(writes: &[(u64, usize)], rsp: u64) -> bool {
    writes
        .iter()
        .any(|&(a, l)| a < rsp && a + l as u64 > rsp - 8)
}

/// `stop` is a handoff at `at` whose refusal is IndirectUnresolved
/// at the same address.
fn assert_unresolved_handoff(what: &str, stop: &BudgetStop, at: u64) {
    match &stop.end {
        BudgetEnd::Handoff {
            refusal: Refuse::IndirectUnresolved { src_pc },
            at: h,
        } => {
            assert_eq!(*h, at, "{what}: handoff point");
            assert_eq!(*src_pc, at, "{what}: refusal src_pc");
        }
        other => panic!("{what}: want an IndirectUnresolved handoff: {other:?}"),
    }
}

/// Resolve `d` from `s`, reading guest qwords from `m` only.
fn res(d: &DecodedInsn, s: &GuestState, m: &BTreeMap<u64, u64>) -> Result<Resolved, ResolveError> {
    resolve(&d.instruction, d.pc, d.len, s, &mut |a| m.get(&a).copied())
}

/// T3: the pure resolver.
#[test]
fn resolver_forms() {
    let _g = lock();
    let pc = 0x40_0000u64;
    let at = |bytes: &[u8]| decode_one(bytes, pc).expect("decodes");
    let mut s = GuestState::default();
    let no_mem = BTreeMap::new();

    // jmp r11
    s.r11 = 0x40_1234;
    let r = res(&at(&[0x41, 0xff, 0xe3]), &s, &no_mem).expect("jmp r11");
    assert_eq!(r.kind, IndirectKind::Jump, "jmp r11: kind");
    assert_eq!(r.target, 0x40_1234, "jmp r11: target");

    // call rax: pushes pc + 2.
    s.rax = 0x40_2222;
    let r = res(&at(&[0xff, 0xd0]), &s, &no_mem).expect("call rax");
    assert_eq!(r.kind, IndirectKind::Call, "call rax: kind");
    assert_eq!(r.target, 0x40_2222, "call rax: target");
    assert_eq!(r.next_ip, pc + 2, "call rax: next ip");

    // jmp [rdx+rax*8+0x10], rax = 2: the index counts. Different
    // memory sits at the address without the index.
    s.rax = 2;
    s.rdx = 0x60_0000;
    let mem = BTreeMap::from([(0x60_0020u64, 0x40_3000u64), (0x60_0010, 0x0bad)]);
    let r = res(&at(&[0xff, 0x64, 0xc2, 0x10]), &s, &mem).expect("jmp [rdx+rax*8+0x10]");
    assert_eq!(r.target, 0x40_3000, "jmp [rdx+rax*8+0x10]: target");

    // call [rsp]: the target read at rsp before the push.
    s.rsp = 0x7f_f000;
    let mem = BTreeMap::from([(0x7f_f000u64, 0x40_4000u64)]);
    let r = res(&at(&[0xff, 0x14, 0x24]), &s, &mem).expect("call [rsp]");
    assert_eq!(r.kind, IndirectKind::Call, "call [rsp]: kind");
    assert_eq!(r.target, 0x40_4000, "call [rsp]: target");
    assert_eq!(r.next_ip, pc + 3, "call [rsp]: next ip");

    // jmp [rip+0x100]: the base is the next IP (pc + 6). Different
    // memory sits at pc + 0x100 (the instruction's own address).
    let mem = BTreeMap::from([(pc + 6 + 0x100, 0x40_5000u64), (pc + 0x100, 0x0bad)]);
    let r = res(&at(&[0xff, 0x25, 0x00, 0x01, 0x00, 0x00]), &s, &mem).expect("jmp [rip+d]");
    assert_eq!(r.target, 0x40_5000, "jmp [rip+d]: target");
    assert_eq!(r.next_ip, pc + 6, "jmp [rip+d]: next ip");

    // A faulting read names its address.
    s.rdx = 0x10;
    let r = res(&at(&[0xff, 0x22]), &s, &no_mem);
    let want = Err(ResolveError::ReadFault { addr: 0x10 });
    assert_eq!(r, want, "jmp [rdx]: fault");

    // Out of scope, refused by name: far, segment override, 32-bit
    // addressing.
    for (form, bytes) in [
        ("jmp far [rsp]", &[0xff, 0x2c, 0x24][..]),
        ("jmp fs:[rax]", &[0x64, 0xff, 0x20][..]),
        ("jmp [eax]", &[0x67, 0xff, 0x20][..]),
    ] {
        let r = res(&at(bytes), &s, &no_mem);
        assert_eq!(r, Err(ResolveError::Unsupported), "{form}: refused");
    }
}

/// T4, in-process.
#[test]
fn refusal_inprocess() {
    let _g = lock();
    for (name, off) in OUT_OF_REGION {
        let bytes = fixtures::by_name(name).bytes;
        let (guest, mut exec, state) = inproc(name, &bytes, false);
        match run_inproc(&mut exec, state) {
            Err(RunError::Refuse(Refuse::IndirectUnresolved { src_pc })) => {
                assert_eq!(src_pc, guest.base + off, "{name}: src_pc");
            }
            other => panic!("{name}: expected IndirectUnresolved, got {other:?}"),
        }
        assert_eq!(below_rsp(&guest), REDZONE_MARKER, "{name}: rsp-8 written");
        let (guest, mut exec, state) = inproc(name, &bytes, true);
        let r = exec.run_budgeted(state, &ProcessMemory, RETURN_SENTINEL, BIG);
        let stop = budget_stop(name, r);
        assert_unresolved_handoff(name, &stop, guest.base + off);
        let rsp = stop.outcome.state.rsp;
        assert_eq!(rsp, state.rsp, "{name}: rsp at the refusal");
        assert_eq!(stop.outcome.state.rip, guest.base + off, "{name}: rip");
        assert_eq!(below_rsp(&guest), REDZONE_MARKER, "{name}: rsp-8 written");
    }
    {
        let name = "ind_interior";
        let bytes = fixtures::by_name(name).bytes;
        let (_guest, mut exec, state) = inproc(name, &bytes, false);
        let out = run_inproc(&mut exec, state);
        assert!(
            matches!(out, Err(RunError::Refuse(Refuse::InteriorEntry { .. }))),
            "{name}: {out:?}"
        );
        let (guest, mut exec, state) = inproc(name, &bytes, true);
        let r = exec.run_budgeted(state, &ProcessMemory, RETURN_SENTINEL, BIG);
        check_interior(name, &budget_stop(name, r), guest.base, state.rsp);
    }
    {
        let name = "ret_untranslated";
        let (guest, mut exec, state) = inproc(name, RET_UNTRANSLATED, false);
        match run_inproc(&mut exec, state) {
            Err(RunError::Refuse(Refuse::IndirectUnresolved { src_pc })) => {
                assert_eq!(src_pc, guest.base + RET_L, "{name}: src_pc is the target");
            }
            other => panic!("{name}: expected IndirectUnresolved, got {other:?}"),
        }
        let (guest, mut exec, state) = inproc(name, RET_UNTRANSLATED, true);
        let r = exec.run_budgeted(state, &ProcessMemory, RETURN_SENTINEL, BIG);
        let stop = budget_stop(name, r);
        assert_unresolved_handoff(name, &stop, guest.base + RET_L);
        let rsp = stop.outcome.state.rsp;
        assert_eq!(rsp, state.rsp, "{name}: rsp after the pop");
    }
}

/// ind_interior's budget stop: InteriorEntry at its `jmp rax` (0x0c),
/// with the state before it (test, jz, lea retired).
fn check_interior(what: &str, stop: &BudgetStop, base: u64, rsp: u64) {
    match &stop.end {
        BudgetEnd::Handoff {
            refusal: Refuse::InteriorEntry { .. },
            at,
        } => assert_eq!(*at, base + 0x0c, "{what}: handoff point"),
        other => panic!("{what}: want an InteriorEntry handoff: {other:?}"),
    }
    assert_eq!(stop.outcome.instructions, 3, "{what}: instructions");
    assert_eq!(stop.outcome.branches, 1, "{what}: branches");
    assert_eq!(stop.outcome.state.rip, base + 0x0c, "{what}: rip");
    assert_eq!(stop.outcome.state.rsp, rsp, "{what}: rsp");
}

/// T4, remote.
#[test]
fn refusal_remote() {
    let _g = lock();
    for (name, off) in OUT_OF_REGION {
        let bytes = fixtures::by_name(name).bytes;
        let (mut rx, _dl, state, info) = remote(name, &bytes, false);
        match rx.run(state, RETURN_SENTINEL) {
            Err(RunError::Refuse(Refuse::IndirectUnresolved { src_pc })) => {
                assert_eq!(src_pc, info.base + off, "{name} remote: src_pc");
            }
            other => panic!("{name} remote: expected IndirectUnresolved, got {other:?}"),
        }
        let writes = rx.tracer_writes_for_test();
        assert!(
            !wrote_below(&writes, state.rsp),
            "{name} remote: tracer wrote the slot below rsp: {writes:?}"
        );
        assert_eq!(rx.proc_mem_writes(), 0, "{name} remote: proc_mem_writes");
        let (mut rx, _dl, state, info) = remote(name, &bytes, true);
        let stop = budget_stop(name, rx.run_budgeted(state, RETURN_SENTINEL, BIG));
        assert_unresolved_handoff(name, &stop, info.base + off);
        let rsp = stop.outcome.state.rsp;
        assert_eq!(rsp, state.rsp, "{name} remote: rsp at the refusal");
        let writes = rx.tracer_writes_for_test();
        assert!(
            !wrote_below(&writes, state.rsp),
            "{name} remote: tracer wrote the slot below rsp: {writes:?}"
        );
    }
    {
        let name = "ind_interior";
        let bytes = fixtures::by_name(name).bytes;
        let (mut rx, _dl, state, _info) = remote(name, &bytes, false);
        let out = rx.run(state, RETURN_SENTINEL);
        assert!(
            matches!(out, Err(RunError::Refuse(Refuse::InteriorEntry { .. }))),
            "{name} remote: {out:?}"
        );
        assert_eq!(rx.proc_mem_writes(), 0, "{name} remote: proc_mem_writes");
        let (mut rx, _dl, state, info) = remote(name, &bytes, true);
        let stop = budget_stop(name, rx.run_budgeted(state, RETURN_SENTINEL, BIG));
        check_interior(name, &stop, info.base, state.rsp);
    }
    {
        let name = "ret_untranslated";
        let (mut rx, _dl, state, info) = remote(name, RET_UNTRANSLATED, true);
        let stop = budget_stop(name, rx.run_budgeted(state, RETURN_SENTINEL, BIG));
        assert_unresolved_handoff(name, &stop, info.base + RET_L);
        let rsp = stop.outcome.state.rsp;
        assert_eq!(rsp, state.rsp, "{name} remote: rsp after the pop");
    }
}

/// ind_fault_mem's stop: a guest fault at its `jmp qword [rdx]`
/// (0x07), the read address 0x10, nothing retired past the jae.
fn check_fault(what: &str, out: Result<Outcome, RunError>, base: u64, rsp: u64) {
    let f = match out {
        Err(RunError::Fault(f)) => f,
        other => panic!("{what}: expected a fault, got {other:?}"),
    };
    assert_eq!(f.kind, FaultKind::GuestFault, "{what}: kind");
    assert_eq!(f.src_pc, base + 7, "{what}: src_pc");
    assert_eq!(f.addr, 0x10, "{what}: addr");
    assert_eq!(f.instructions, 3, "{what}: instructions");
    assert_eq!(f.branches, 1, "{what}: branches");
    assert_eq!(f.state.rip, base + 7, "{what}: rip");
    assert_eq!(f.state.rsp, rsp, "{what}: rsp");
}

/// T6, in-process.
#[test]
fn fault_inprocess() {
    let _g = lock();
    let name = "ind_fault_mem";
    let bytes = fixtures::by_name(name).bytes;
    let (guest, mut exec, state) = inproc(name, &bytes, false);
    check_fault(name, run_inproc(&mut exec, state), guest.base, state.rsp);
}

/// T6, remote.
#[test]
fn fault_remote() {
    let _g = lock();
    let name = "ind_fault_mem";
    let bytes = fixtures::by_name(name).bytes;
    let (mut rx, _dl, state, info) = remote(name, &bytes, false);
    check_fault(name, rx.run(state, RETURN_SENTINEL), info.base, state.rsp);
}

/// T7, in-process: retranslations on the first run, none on the
/// second, the same result both times.
#[test]
fn discovery_inprocess() {
    let _g = lock();
    for (name, retr) in DISCOVERY {
        let bytes = fixtures::by_name(name).bytes;
        let (_guest, mut exec, state) = inproc(name, &bytes, false);
        let first = match run_inproc(&mut exec, state) {
            Ok(o) => o,
            Err(e) => panic!("{name}: first run: {e:?}"),
        };
        let n = exec.retranslations();
        assert_eq!(n, retr, "{name}: retranslations after one run");
        let again = match run_inproc(&mut exec, state) {
            Ok(o) => o,
            Err(e) => panic!("{name}: second run: {e:?}"),
        };
        let n = exec.retranslations();
        assert_eq!(n, retr, "{name}: retranslations after two runs");
        let (a, b) = (again.state.rax, first.state.rax);
        assert_eq!(a, b, "{name}: second run result");
    }
}

/// T7, remote.
#[test]
fn discovery_remote() {
    let _g = lock();
    for (name, retr) in DISCOVERY {
        let bytes = fixtures::by_name(name).bytes;
        let (mut rx, _dl, state, _info) = remote(name, &bytes, false);
        let first = match rx.run(state, RETURN_SENTINEL) {
            Ok(o) => o,
            Err(e) => panic!("{name} remote: first run: {e:?}"),
        };
        let n = rx.retranslations();
        assert_eq!(n, retr, "{name} remote: retranslations after one run");
        let again = match rx.run(state, RETURN_SENTINEL) {
            Ok(o) => o,
            Err(e) => panic!("{name} remote: second run: {e:?}"),
        };
        let n = rx.retranslations();
        assert_eq!(n, retr, "{name} remote: retranslations after two runs");
        let (a, b) = (again.state.rax, first.state.rax);
        assert_eq!(a, b, "{name} remote: second run result");
    }
}

/// T7, remote: an install that fails after its first byte refuses by
/// name, and the executable is poisoned: the next run refuses before
/// resuming the possibly torn arena.
#[test]
fn install_failure_remote() {
    let _g = lock();
    let name = "ind_call_reg";
    let bytes = fixtures::by_name(name).bytes;
    let (mut rx, _dl, state, _info) = remote(name, &bytes, false);
    rx.force_install_failure_after(1);
    let first = rx.run(state, RETURN_SENTINEL);
    assert!(
        matches!(
            &first,
            Err(RunError::Refuse(Refuse::CodeInstall {
                reason: "/proc mem write",
                ..
            }))
        ),
        "{name}: a failed install refuses by name: {first:?}"
    );
    assert_eq!(rx.retranslations(), 0, "{name}: retranslations");
    let again = rx.run(state, RETURN_SENTINEL);
    assert!(
        matches!(
            &again,
            Err(RunError::Refuse(Refuse::CodeInstall {
                reason: "poisoned after a failed install",
                ..
            }))
        ),
        "{name}: the run after a torn install must refuse poisoned: {again:?}"
    );
}

/// Spawn census (I1-H H2c): every child this binary starts carries
/// a run deadline (`common/deadline.rs`).
#[test]
fn spawn_census() {
    deadline::spawn_census(include_str!("indirect_resolve.rs"), "indirect_resolve.rs");
}

/// Bound census (I1-H H2d): every test here arms a `TestBound`
/// (`common/deadline.rs`).
#[test]
fn bound_census() {
    deadline::bound_census(
        include_str!("indirect_resolve.rs"),
        "indirect_resolve.rs",
        &["spawn_census", "bound_census"],
    );
}
