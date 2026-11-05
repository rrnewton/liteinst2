//! Live return-transition custody tests.
//!
//! The Refuse and query-denied cases run in the owned
//! `liteinst-jit-custody-child` process so a custody failure is a
//! named test failure, not a dead test harness.

use liteinst_jit::exec::{Executable, ProcessMemory};
use liteinst_jit::fixtures;
use liteinst_jit::handler::CaptureHandler;
use liteinst_jit::harness::{MappedGuest, RETURN_SENTINEL};
use liteinst_jit::types::{CountProfile, Generation};

const CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-custody-child");

#[test]
fn custody_refuse_child_retains_pending_set() {
    let status = std::process::Command::new(CHILD)
        .arg("refuse")
        .status()
        .expect("run custody refuse child");
    assert!(status.success(), "custody refuse child: {status}");
}

#[test]
fn custody_query_denied_child_returns_signal_ownership() {
    let status = std::process::Command::new(CHILD)
        .arg("denied")
        .status()
        .expect("run custody denied child");
    assert!(status.success(), "custody denied child: {status}");
}

#[test]
fn custody_ok_return_reports_also_pending() {
    // Pre-block and queue one signal ourselves: it belongs to no
    // poll stop (the fixture finishes in one entry), so only the
    // wrapper return transition can take custody of it.
    let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
    let mut old: libc::sigset_t = unsafe { core::mem::zeroed() };
    // SAFETY: this test thread blocks, queues, and restores one
    // signal whose disposition it first pins to default.
    unsafe {
        assert_ne!(libc::signal(libc::SIGUSR1, libc::SIG_DFL), libc::SIG_ERR);
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old), 0);
        assert_eq!(libc::raise(libc::SIGUSR1), 0);
    }
    let fixture = fixtures::by_name("sum_loop");
    let guest = MappedGuest::map(&fixture.bytes).expect("map");
    let region = guest.region(&fixture.bytes, Generation(1));
    let mut exec =
        Executable::prepare(&region, guest.base, CountProfile::Branches).expect("prepare");
    let data: Vec<u64> = (0..16).collect();
    let mut state = guest.initial_state();
    state.rdi = data.as_ptr() as u64;
    state.rsi = 16;
    let mut handler = CaptureHandler::default();
    let outcome = exec
        .run(state, &mut handler, &ProcessMemory, RETURN_SENTINEL)
        .expect("successful run takes pending signal into custody");
    assert_eq!(outcome.branches, 17, "sum_loop: branches");
    assert_eq!(outcome.also_pending, vec![libc::SIGUSR1]);
    // SAFETY: restoring this thread's mask saved above; the
    // signal was dequeued, so unblocking cannot deliver it.
    unsafe {
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, core::ptr::null_mut()),
            0
        );
    }
}
