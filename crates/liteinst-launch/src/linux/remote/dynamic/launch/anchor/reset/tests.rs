//! Actual private children and waits; these controls do not qualify a signal
//! frame or turn failed startup into success. No application is released here.
use super::*;
use std::sync::mpsc;

const TIMEOUT: Duration = Duration::from_secs(3);

fn worker(action: impl FnOnce() + Send + 'static) {
    let caller = BlockedSignals::new().unwrap();
    let (send, receive) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let blocked = BlockedSignals::new().unwrap();
        assert_eq!(current_mask().unwrap(), BLOCKED);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
        drop(blocked);
        send.send(result).unwrap();
    });
    // After spawn, an unproved owner completion must not detach a tracer with
    // live helpers. Abort this validation command under its existing bound.
    if caller.restore().is_err() {
        std::process::abort();
    }
    let result = match receive.recv_timeout(TIMEOUT) {
        Ok(result) => result,
        Err(_) => std::process::abort(),
    };
    if thread.join().is_err() {
        std::process::abort();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

fn prepared(fault: u32, held: bool) -> ResetLaunch {
    let request = AnchorRequest::new(ANCHOR_EVIDENCE_BOUND).unwrap();
    let archive = AnchorArchive::new(request, 1).unwrap();
    let bootstrap = Bootstrap {
        anchor: None,
        release: -1,
        parent_release: -1,
        error_read: -1,
        error_write: -1,
        program: std::ptr::null(),
        argv: std::ptr::null(),
        envp: std::ptr::null(),
        fail_before_ready: false,
        die_before_ready: false,
    };
    let reset = ResetLaunch::prepare(1, bootstrap, archive).unwrap();
    unsafe {
        (*reset.mapping.context()).test_fault = fault;
        if held {
            (*reset.mapping.context()).broker =
                (*reset.mapping.context()).broker.hold_before_stop();
        }
    }
    reset
}

fn duplicate(fd: &OwnedFd) -> OwnedFd {
    let value = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    assert!(value >= 0);
    unsafe { OwnedFd::from_raw_fd(value) }
}

fn pin(pid: i32) -> OwnedFd {
    // Independent direct-parent wait probe establishes eligibility before pin.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::waitid(libc::P_PID, pid as u32, &raw mut info, WAIT_FLAGS) },
        0
    );
    assert!([0, pid].contains(&unsafe { info.si_pid() }));
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0);
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

fn gone(pin: &OwnedFd) {
    let mut event = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut event, 1, 0) }, 1);
    assert_ne!(event.revents & libc::POLLIN, 0);
    assert_ne!(event.revents & libc::POLLHUP, 0);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pin.as_raw_fd() as u32,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
            )
        },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn empty() {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::waitid(libc::P_ALL, 0, &raw mut info, WAIT_FLAGS) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn clone_only(reset: &mut ResetLaunch) -> OwnedFd {
    let lock = crate::TEST_FILE_FORK.lock().unwrap();
    reset.start_clone().unwrap();
    drop(lock);
    duplicate(reset.children[0].as_ref().unwrap().pin.as_ref().unwrap())
}

fn failed_s(fault: u32, expected_child: bool, missing_pid: bool, expected_signal: bool) {
    worker(move || {
        let mut reset = prepared(fault, false);
        let lock = crate::TEST_FILE_FORK.lock().unwrap();
        let outcome = reset.launch(Instant::now() + TIMEOUT, &AtomicBool::new(false));
        drop(lock);
        let s = duplicate(reset.children[0].as_ref().unwrap().pin.as_ref().unwrap());
        let until = Instant::now() + TIMEOUT;
        let mut r = None;
        loop {
            reset.wait_one(false).unwrap();
            if let Some(child) = &reset.children[1] {
                r = Some(pin(child.pid));
            }
            if reset.children[0].as_ref().unwrap().terminal.is_some()
                && (r.is_some() || !expected_child)
            {
                break;
            }
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
        let status = reset.children[0].as_ref().unwrap().terminal.unwrap();
        if expected_signal {
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        } else {
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 125);
        }
        let context = unsafe { &*reset.mapping.context() };
        if fault == 3 {
            assert_eq!(context.send_observed, 1);
            assert_eq!(context.send_result, -i64::from(libc::EBADF));
        } else {
            assert_eq!(context.send_observed, 0);
            assert_eq!(context.send_result, i64::MIN);
        }
        assert_eq!(r.is_some(), expected_child);
        if missing_pid {
            assert_eq!(unsafe { (*reset.mapping.context()).packet.pid }, 0);
        }
        assert!(!reset.packet_received);
        assert!(!reset.handed_off);
        let started = Instant::now();
        reset.cleanup().unwrap();
        assert!(started.elapsed() < TIMEOUT);
        assert!(matches!(
            outcome,
            Err(LaunchError::Invalid(
                "reset lineage did not reach the exact handoff"
            ))
        ));
        gone(&s);
        if let Some(r) = r {
            gone(&r);
        }
        empty();
        let prefix = reset.archive.reader().snapshot();
        assert!(!prefix.complete);
        assert!(!prefix.exec_exit_authenticated);
        assert!(
            prefix
                .reset
                .iter()
                .any(|r| r.phase == AnchorResetPhase::CloneReturn && r.result > 0)
        );
        assert!(
            !prefix
                .reset
                .iter()
                .any(|r| r.phase == AnchorResetPhase::BrokerTransferReady)
        );
    });
}

#[test]
fn packet_send_failure_retains_real_reaper_cleanup() {
    failed_s(3, true, false, false);
}

#[test]
fn transient_killed_before_reaper_clone_is_actually_empty() {
    failed_s(1, false, true, true);
}

#[test]
fn transient_killed_after_reaper_clone_retains_both_pins() {
    failed_s(2, true, false, true);
}

#[test]
fn absent_pid_publication_does_not_mean_no_reaper() {
    failed_s(4, true, true, true);
}

#[test]
fn live_reaper_before_self_stop_is_recovered_through_procfs() {
    worker(|| {
        let mut reset = prepared(3, true);
        let s = clone_only(&mut reset);
        let pid = unsafe { (*reset.mapping.context()).packet.pid };
        assert!(pid > 0);
        let r = pin(pid);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::waitid(libc::P_PID, pid as u32, &raw mut info, WAIT_FLAGS) },
            0
        );
        assert_eq!(
            unsafe { info.si_pid() },
            0,
            "live eligibility without any stopped/terminal status"
        );
        assert!(reset.children[1].is_none());
        assert!(!reset.packet_received);
        // Exercise the missing-interface-compatible one-level fallback even on
        // kernels that also supply the optional task children file.
        reset.discovery.use_proc_candidates();
        let started = Instant::now();
        reset.cleanup().unwrap();
        assert!(started.elapsed() < TIMEOUT);
        gone(&s);
        gone(&r);
        empty();
        let child = reset.children[1].as_ref().unwrap();
        assert_eq!(child.pid, pid);
        assert!(libc::WIFSIGNALED(child.terminal.unwrap()));
        assert_eq!(libc::WTERMSIG(child.terminal.unwrap()), libc::SIGKILL);
    });
}

#[test]
fn original_deadline_expires_with_live_pre_stop_reaper() {
    worker(|| {
        let cancel = AtomicBool::new(false);
        // A genuinely expired whole-launch deadline refuses before cloning;
        // this is distinct from the live-child continuation exercised below.
        let mut expired = prepared(0, true);
        let expired_until = Instant::now();
        let outcome = expired.launch(expired_until, &cancel);
        assert!(matches!(
            outcome,
            Err(LaunchError::Timeout("initial reset lineage"))
        ));
        assert!(!expired.spawned);
        assert!(!expired.handed_off);
        assert!(expired.children.iter().all(Option::is_none));
        assert!(expired.archive.reader().snapshot().reset.is_empty());
        empty();
        drop(expired);

        let mut reset = prepared(0, true);
        // Fixture-I/O lock contention and scheduling the real reset clone are
        // setup, under worker's unchanged three-second completion guard. The
        // measured phase starts only after both original children are proved.
        let setup_until = Instant::now() + TIMEOUT;
        let s = clone_only(&mut reset);
        reset.receive().unwrap();
        while !reset.children[0].as_ref().unwrap().physical() {
            reset.wait_one(false).unwrap();
            assert!(Instant::now() < setup_until);
            std::thread::yield_now();
        }
        let s_status = reset.children[0].as_ref().unwrap().terminal.unwrap();
        assert!(libc::WIFEXITED(s_status));
        assert_eq!(libc::WEXITSTATUS(s_status), 0);
        gone(&s);
        assert!(reset.packet_received);
        let context = unsafe { &*reset.mapping.context() };
        assert_eq!(context.send_observed, 1);
        assert_eq!(context.send_result, 64);
        let child = reset.children[1].as_ref().unwrap();
        assert_eq!(child.pid, context.packet.pid);
        assert!(child.terminal.is_none());
        assert!(child.stopped.is_none());
        let r = duplicate(child.pin.as_ref().unwrap());
        assert!(!broker::hup(&r));
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::waitid(libc::P_PID, child.pid as u32, &raw mut info, WAIT_FLAGS) },
            0
        );
        assert_eq!(unsafe { info.si_pid() }, 0);
        assert!(!reset.handed_off);

        // This is the exact production post-clone loop. It receives one
        // deadline, and never restarts it while the genuine R cannot self-stop.
        let started = Instant::now();
        let until = started + Duration::from_millis(100);
        let outcome = reset.await_handoff(until, &cancel);
        let elapsed = started.elapsed();
        let still_live = reset.children[1].as_ref().unwrap().terminal.is_none()
            && reset.children[1].as_ref().unwrap().stopped.is_none()
            && !broker::hup(&r);
        let cleanup = Instant::now();
        reset.cleanup().unwrap();
        assert!(cleanup.elapsed() < TIMEOUT);
        assert!(matches!(
            outcome,
            Err(LaunchError::Timeout("initial reset lineage"))
        ));
        assert!(elapsed >= Duration::from_millis(100) && elapsed < TIMEOUT);
        assert!(still_live);
        assert!(!reset.handed_off);
        gone(&s);
        gone(&r);
        empty();
        let prefix = reset.archive.reader().snapshot();
        assert_eq!(
            prefix
                .reset
                .iter()
                .filter(|row| row.phase == AnchorResetPhase::CloneAttempt)
                .count(),
            1
        );
        assert!(
            !prefix
                .reset
                .iter()
                .any(|row| row.phase == AnchorResetPhase::BrokerTransferReady)
        );
    });
}

#[test]
fn missing_reaper_pin_retains_wait_authority_and_failure() {
    worker(|| {
        let mut reset = prepared(2, false);
        reset.deny_pin = true;
        let s = clone_only(&mut reset);
        let pid = unsafe { (*reset.mapping.context()).packet.pid };
        let r = pin(pid);
        let until = Instant::now() + TIMEOUT;
        while reset.children[1].is_none() {
            reset.wait_one(false).unwrap();
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
        assert!(reset.children[1].as_ref().unwrap().pin.is_none());
        assert!(reset.failed);
        let cleanup = Instant::now();
        let outcome = reset.cleanup();
        assert!(cleanup.elapsed() < TIMEOUT);
        assert!(matches!(
            outcome,
            Err(LaunchError::Invalid(
                "reset lineage cleanup evidence failed"
            ))
        ));
        gone(&s);
        gone(&r);
        empty();
    });
}

struct BrokerGuard(Option<broker::Broker>);
impl BrokerGuard {
    fn drain(&mut self) -> Result<(), LaunchError> {
        let broker = self.0.as_mut().unwrap();
        loop {
            broker.cancel();
            let _ = broker.poll();
            let mut status = 0;
            let got = unsafe {
                libc::waitpid(
                    broker.pid,
                    &raw mut status,
                    libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                )
            };
            if got == broker.pid {
                broker.terminal(status);
            }
            match broker.finished() {
                Ok(true) => return Ok(()),
                Err(error) => return Err(error),
                Ok(false) => {}
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for BrokerGuard {
    fn drop(&mut self) {
        if self.0.is_some() {
            let _ = self.drain();
        }
    }
}

#[test]
fn abort_before_start_receives_empty_done_without_application() {
    worker(|| {
        let mut reset = prepared(0, false);
        let cancel = AtomicBool::new(false);
        let lock = crate::TEST_FILE_FORK.lock().unwrap();
        let broker = reset.launch(Instant::now() + TIMEOUT, &cancel).unwrap();
        let pid = broker.pid;
        let mut guard = BrokerGuard(Some(broker));
        drop(lock);
        let r = pin(pid);
        assert!(guard.0.as_ref().unwrap().anchor_no_application_possible());
        let cleanup = Instant::now();
        guard.drain().unwrap();
        assert!(cleanup.elapsed() < TIMEOUT);
        let broker = guard.0.as_ref().unwrap();
        assert!(broker.done);
        assert!(broker.root.is_none());
        assert!(broker.physical.is_empty());
        gone(&r);
        empty();
        drop(guard);
        drop(reset);
    });
}
