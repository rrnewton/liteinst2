//! Prospective controls: UNRUN. These exercise the constructor's exact private
//! terminal boundary in fresh exec children. Final-DSO kernel-exec observation
//! at original AT_ENTRY remains a separate required package/native control.

use super::{initialize_terminal, liteinst_bootstrap_status};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const OUTER_SELECTOR: &str = "LITEINST_BOOTSTRAP_BOUNDARY_OUTER";
const INNER_SELECTOR: &str = "LITEINST_BOOTSTRAP_BOUNDARY_INNER";

#[derive(Clone, Copy)]
enum Refusal {
    Error,
    Panic,
}

#[derive(Clone, Copy)]
enum Descriptor {
    FullBlockingPipe,
    Closed,
}

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    refusal: Refusal,
    descriptor: Descriptor,
}

const CASES: [Case; 4] = [
    Case {
        name: "tests::error_with_full_blocking_stderr",
        refusal: Refusal::Error,
        descriptor: Descriptor::FullBlockingPipe,
    },
    Case {
        name: "tests::panic_with_full_blocking_stderr",
        refusal: Refusal::Panic,
        descriptor: Descriptor::FullBlockingPipe,
    },
    Case {
        name: "tests::error_with_closed_stderr",
        refusal: Refusal::Error,
        descriptor: Descriptor::Closed,
    },
    Case {
        name: "tests::panic_with_closed_stderr",
        refusal: Refusal::Panic,
        descriptor: Descriptor::Closed,
    },
];

#[test]
fn error_with_full_blocking_stderr() {
    run(CASES[0]);
}

#[test]
fn panic_with_full_blocking_stderr() {
    run(CASES[1]);
}

#[test]
fn error_with_closed_stderr() {
    run(CASES[2]);
}

#[test]
fn panic_with_closed_stderr() {
    run(CASES[3]);
}

fn run(case: Case) {
    if let Some(selected) = std::env::var_os(INNER_SELECTOR) {
        assert_eq!(selected, std::ffi::OsStr::new(case.name));
        terminal_child(case);
    }
    // Reuse the exact repository helper: CPU 20 s, wall 30 s, bounded 2 s
    // cleanup, pinned process group and peer inventory. No helper copy/fork.
    super::isolated_native_test::run(case.name, OUTER_SELECTOR, observe_child);
}

fn observe_child() {
    let name = std::env::var(OUTER_SELECTOR).expect("fixed outer case");
    let case = CASES.iter().find(|case| case.name == name).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", case.name, "--nocapture", "--test-threads=1"])
        .env(INNER_SELECTOR, case.name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        // Inherit the outer helper's owned process group and CPU limit. Any
        // setup/assertion failure is still covered by its exact group cleanup.
        .spawn()
        .expect("fresh exec terminal-boundary child");
    let deadline = Instant::now() + Duration::from_secs(5);
    let observed = loop {
        if let Some(status) = child.try_wait().expect("poll owned terminal child") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if observed.is_none() {
        // The direct child has not been reaped, so this exact Child still owns
        // its PID. A killed timeout is a failure even if a late exit races it.
        child.kill().expect("kill timed-out owned terminal child");
        let cleanup_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if child
                .try_wait()
                .expect("reap owned terminal child")
                .is_some()
            {
                break;
            }
            assert!(
                Instant::now() < cleanup_deadline,
                "terminal child cleanup deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let status = observed.expect("terminal refusal exceeded five seconds; timeout is not refusal");
    assert_eq!(
        status.code(),
        Some(125),
        "exact refusal exit required; a signal fails"
    );
}

fn fixture_failure() -> ! {
    // Setup errors remain distinguishable from the production refusal code.
    unsafe { libc::_exit(113) }
}

fn terminal_child(case: Case) -> ! {
    assert_eq!(liteinst_bootstrap_status(), 0);
    // Restore the real default hook before creating the hostile stderr case.
    // A missing production hook replacement would block on a full pipe.
    drop(std::panic::take_hook());
    match case.descriptor {
        Descriptor::FullBlockingPipe => make_full_blocking_stderr(),
        Descriptor::Closed => {
            if unsafe { libc::close(2) } != 0 {
                fixture_failure();
            }
            if unsafe { libc::fcntl(2, libc::F_GETFD) } != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
            {
                fixture_failure();
            }
        }
    }
    // SAFETY: a fresh isolated test process runs only this selected body. It
    // owns its panic hook, is not panicking, and the closure cannot change the
    // hook or spawn a thread. This tests the boundary, not real core activation.
    unsafe {
        initialize_terminal(|| -> Result<(), ()> {
            match case.refusal {
                Refusal::Error => Err(()),
                Refusal::Panic => panic!("injected startup panic"),
            }
        });
    }
    // Any return/handoff is failure even if completion was accidentally set.
    unsafe { libc::_exit(124) }
}

fn make_full_blocking_stderr() {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        fixture_failure();
    }
    // These controls start with inherited stderr. Refuse unusual descriptor
    // reuse rather than accidentally closing fd 2 after dup2 below.
    if fds[0] <= 2 || fds[1] <= 2 {
        fixture_failure();
    }
    let capacity = unsafe { libc::fcntl(fds[1], libc::F_GETPIPE_SZ) };
    if capacity <= 0 || capacity > 1024 * 1024 {
        fixture_failure();
    }
    let bytes = [0x5a_u8; 4096];
    let mut filled = 0;
    while filled < capacity {
        let count = usize::try_from((capacity - filled).min(bytes.len() as i32)).unwrap();
        let written = unsafe { libc::write(fds[1], bytes.as_ptr().cast(), count) };
        if written <= 0 {
            fixture_failure();
        }
        filled += i32::try_from(written).unwrap();
    }
    // Prove all capacity is occupied, plus a one-byte nonblocking write really
    // returns EAGAIN; then turn the actual fd 2 writer back into blocking mode.
    let mut pending: libc::c_int = 0;
    if unsafe { libc::ioctl(fds[0], libc::FIONREAD, &mut pending) } != 0 || pending != capacity {
        fixture_failure();
    }
    if unsafe { libc::write(fds[1], bytes.as_ptr().cast(), 1) } != -1
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EAGAIN)
    {
        fixture_failure();
    }
    let flags = unsafe { libc::fcntl(fds[1], libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fds[1], libc::F_SETFL, flags & !libc::O_NONBLOCK) } != 0 {
        fixture_failure();
    }
    if unsafe { libc::dup2(fds[1], 2) } != 2 || unsafe { libc::close(fds[1]) } != 0 {
        fixture_failure();
    }
    let flags = unsafe { libc::fcntl(2, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_NONBLOCK != 0 {
        fixture_failure();
    }
    // Keep fds[0] open and unread until _exit, preventing EPIPE/SIGPIPE from
    // disguising a blocking write. No parent/reader drains this pipe.
}

#[test]
fn success_restores_exact_prior_hook_before_completion() {
    super::isolated_native_test::run(
        "tests::success_restores_exact_prior_hook_before_completion",
        OUTER_SELECTOR,
        || {
            use std::sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            };
            struct Witness(Arc<AtomicUsize>);
            impl Witness {
                fn held(&self) {}
            }
            impl Drop for Witness {
                fn drop(&mut self) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }
            assert_eq!(liteinst_bootstrap_status(), 0);
            assert_eq!(
                std::mem::size_of_val(&super::LITEINST_BOOTSTRAP_COMPLETION_V1),
                8
            );
            assert_eq!(
                std::mem::align_of_val(&super::LITEINST_BOOTSTRAP_COMPLETION_V1),
                8
            );
            assert_eq!(
                (&super::LITEINST_BOOTSTRAP_COMPLETION_V1 as *const _ as usize) % 8,
                0
            );
            let original = std::panic::take_hook();
            let calls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let witness = Witness(Arc::clone(&drops));
            let hook_calls = Arc::clone(&calls);
            let prior: Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static> =
                Box::new(move |_| {
                    witness.held();
                    hook_calls.fetch_add(1, Ordering::SeqCst);
                });
            let pointer = (&*prior) as *const _ as *const ();
            std::panic::set_hook(prior);
            // SAFETY: this fresh selected body exclusively owns the hook; the
            // successful closure has no side effects and cannot change it.
            unsafe { initialize_terminal(|| Ok::<(), ()>(())) };
            assert_eq!(liteinst_bootstrap_status(), 1);
            assert_eq!(
                super::LITEINST_BOOTSTRAP_COMPLETION_V1.load(Ordering::Acquire),
                1
            );
            let restored = std::panic::take_hook();
            assert_eq!((&*restored) as *const _ as *const (), pointer);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            std::panic::set_hook(restored);
            assert!(std::panic::catch_unwind(|| panic!("restored hook control")).is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let restored = std::panic::take_hook();
            assert_eq!((&*restored) as *const _ as *const (), pointer);
            drop(restored);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            std::panic::set_hook(original);
        },
    );
}
