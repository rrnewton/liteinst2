//! P1b.1 T10: a budgeted run that hands off at an INDIRECT exit
//! reports the state before the indirect instruction, with its
//! block-head pre-credit excluded, in both modes. `ind_jmp_out_budget`
//! jumps through rdi = 0, outside the region. With a budget of 5 the
//! run hands off at the `jmp` after one credited branch, with 3
//! retired instructions (xor, cmp, jae), equal to the O1 oracle
//! stopped at that point.
//!
//! This file uses only APIs the budget-stub base already has
//! (`run_budgeted`, `deadline::o1_until`, `fixtures::by_name`), so it
//! also runs on the base tree, where both tests fail on the
//! over-count (4 instructions against the oracle's 3).
//!
//! The in-process dispatcher and the traced child share
//! process-global state, so each test holds the serial lock.

use liteinst_jit::Refuse;
use liteinst_jit::exec::{BudgetEnd, BudgetStop, Executable, ProcessMemory, RunError};
use liteinst_jit::fixtures;
use liteinst_jit::harness::{MappedGuest, RETURN_SENTINEL};
use liteinst_jit::o1::O1Stop;
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};

#[path = "common/deadline.rs"]
mod deadline;

const O1_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-o1-child");
const REMOTE_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-remote-child");
const NAME: &str = "ind_jmp_out_budget";
/// More than the fixture's one branch, so the run can only end at
/// the handoff.
const BUDGET: u64 = 5;
/// The offset of the `jmp rdi` in the fixture.
const JMP_OFF: u64 = 7;

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

/// Judge one mode's stop against the oracle stopped at the jmp.
fn check_handoff(mode: &str, stop: Result<BudgetStop, RunError>, base: u64) {
    let stop = match stop {
        Ok(s) => s,
        Err(e) => panic!("{mode}: budget run: {e:?}"),
    };
    match &stop.end {
        BudgetEnd::Handoff {
            refusal: Refuse::IndirectUnresolved { src_pc },
            at,
        } => {
            assert_eq!(*at, base + JMP_OFF, "{mode}: handoff point");
            assert_eq!(*src_pc, base + JMP_OFF, "{mode}: refusal src_pc");
        }
        other => panic!("{mode}: want an IndirectUnresolved handoff: {other:?}"),
    }
    let o1 = deadline::o1_until(
        O1_CHILD,
        NAME,
        O1Stop {
            branches: 1,
            at_offset: Some(JMP_OFF),
        },
    );
    assert_eq!(o1.branches, 1, "{mode}: oracle branches");
    assert_eq!(o1.instructions, 3, "{mode}: oracle instructions");
    let o1_off = o1.state.rip - o1.base;
    assert_eq!(o1_off, JMP_OFF, "{mode}: oracle stop offset");
    assert_eq!(stop.outcome.branches, 1, "{mode}: credited branches");
    assert_eq!(
        stop.outcome.instructions, o1.instructions,
        "{mode}: instructions at the indirect handoff (the jmp did not retire)"
    );
    assert_eq!(stop.outcome.state.rip, base + JMP_OFF, "{mode}: rip");
    assert_eq!(stop.remaining, BUDGET - 1, "{mode}: budget still owed");
}

#[test]
fn budget_handoff_inprocess() {
    let _g = lock();
    let fixture = fixtures::by_name(NAME);
    let guest = MappedGuest::map(&fixture.bytes).expect("map");
    let region = guest.region(&fixture.bytes, Generation(1));
    let profile = CountProfile::BranchesAndInstructions;
    let prepared = Executable::prepare_budgeted(&region, guest.base, profile);
    let mut exec = prepared.expect("prepare_budgeted");
    let mut state = guest.initial_state();
    let (rdi, rsi, rdx, rax, rcx) = MappedGuest::fixture_args(NAME, guest.base, 0, 0, 0);
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = rax;
    state.rcx = rcx;
    let stop = exec.run_budgeted(state, &ProcessMemory, RETURN_SENTINEL, BUDGET);
    check_handoff("in-process", stop, guest.base);
}

#[test]
fn budget_handoff_remote() {
    let _g = lock();
    let fixture = fixtures::by_name(NAME);
    let spawned = deadline::remote_named(REMOTE_CHILD, NAME);
    let (mut remote, _deadline) = spawned.expect("spawn remote");
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: fixture.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    let profile = CountProfile::BranchesAndInstructions;
    remote
        .prepare_budgeted(&region, info.base, profile)
        .expect("prepare_budgeted");
    let mut state = remote.initial_state();
    let (rdi, rsi, rdx, rax, rcx) =
        MappedGuest::fixture_args(NAME, info.base, info.data, info.dst, info.src);
    state.rdi = rdi;
    state.rsi = rsi;
    state.rdx = rdx;
    state.rax = rax;
    state.rcx = rcx;
    let stop = remote.run_budgeted(state, RETURN_SENTINEL, BUDGET);
    check_handoff("remote", stop, info.base);
}

/// Spawn census (I1-H H2c): every child this binary starts carries
/// a run deadline (`common/deadline.rs`).
#[test]
fn spawn_census() {
    deadline::spawn_census(
        include_str!("indirect_budget_handoff.rs"),
        "indirect_budget_handoff.rs",
    );
}

/// Bound census (I1-H H2d): every test here arms a `TestBound`
/// (`common/deadline.rs`).
#[test]
fn bound_census() {
    deadline::bound_census(
        include_str!("indirect_budget_handoff.rs"),
        "indirect_budget_handoff.rs",
        &["spawn_census", "bound_census"],
    );
}
