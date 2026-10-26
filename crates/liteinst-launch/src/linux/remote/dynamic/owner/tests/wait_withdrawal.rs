//! A real LISTEN transition withdraws a peeked group stop without running
//! original instructions. No wait result or cleanup result is substituted.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Peek {
    tid: libc::pid_t,
    signal: i32,
    code: i32,
    status: i32,
}

pub(in crate::linux::remote::dynamic::owner) struct ListenWithdrawal {
    tid: libc::pid_t,
    until: Instant,
    peek: Option<Peek>,
    listen_attempted: bool,
    listen_succeeded: bool,
    listen_result: Option<libc::c_long>,
    listen_errno: Option<i32>,
    consumed: Option<libc::pid_t>,
}

pub(in crate::linux::remote::dynamic::owner) fn before_consume(
    owner: &mut Owner,
    tid: libc::pid_t,
    info: &libc::siginfo_t,
) -> Result<(), LaunchError> {
    let Some(control) = owner.wait_withdrawal.as_ref() else {
        return Ok(());
    };
    if control.peek.is_some() {
        return Ok(());
    }
    let expected_tid = control.tid;
    let until = control.until;
    let observed = Peek {
        tid: unsafe { info.si_pid() },
        signal: info.si_signo,
        code: info.si_code,
        status: unsafe { info.si_status() },
    };
    owner.wait_withdrawal.as_mut().unwrap().peek = Some(observed);
    if tid != expected_tid
        || observed
            != (Peek {
                tid: expected_tid,
                signal: libc::SIGCHLD,
                code: libc::CLD_TRAPPED,
                status: (libc::PTRACE_EVENT_STOP << 8) | libc::SIGSTOP,
            })
        || !owner.owned.contains(&tid)
        || !owner.handles.contains_key(&tid)
        || owner.stopped.contains_key(&tid)
    {
        return Err(LaunchError::Invalid(
            "wait withdrawal requires exact pinned group stop",
        ));
    }
    owner.time_left(until, "actual LISTEN after WNOWAIT")?;
    owner.wait_withdrawal.as_mut().unwrap().listen_attempted = true;
    // The genuine seized group stop remains stopped, but LISTEN removes its
    // waitable ptrace-stop condition. No other waiter or user-code release.
    let (result, errno) = unsafe {
        *libc::__errno_location() = 0;
        let result = libc::ptrace(libc::PTRACE_LISTEN, tid, 0usize, 0usize);
        (result, *libc::__errno_location())
    };
    let control = owner.wait_withdrawal.as_mut().unwrap();
    control.listen_result = Some(result);
    control.listen_errno = Some(errno);
    if result != 0 || errno != 0 {
        return Err(LaunchError::Invalid("actual LISTEN request failed"));
    }
    owner.wait_withdrawal.as_mut().unwrap().listen_succeeded = true;
    owner.released(tid);
    Ok(())
}

pub(in crate::linux::remote::dynamic::owner) fn after_consume(
    owner: &mut Owner,
    result: libc::pid_t,
) {
    if let Some(control) = owner.wait_withdrawal.as_mut()
        && control.listen_succeeded
        && control.consumed.is_none()
    {
        control.consumed = Some(result);
    }
}

#[test]
fn actual_listen_withdrawal_preserves_pinned_wait_and_cleanup() {
    let fixture = Fixture::new(false);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    let root = pin(ready.pid);
    let broker = pin(harness.owner().broker.as_ref().unwrap().pid);
    let until = Instant::now() + TIMEOUT;
    // Queue a real application SIGSTOP, then observe its signal-delivery stop.
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                root.as_raw_fd(),
                libc::SIGSTOP,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
    ptrace(libc::PTRACE_CONT, ready.pid, 0, 0).unwrap();
    harness.owner().released(ready.pid);
    let (tid, status) = harness
        .owner()
        .wait_raw(until, "withdrawal signal delivery")
        .unwrap();
    assert_eq!(tid, ready.pid);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
    assert_eq!(status >> 16, 0);
    // Deliver it and arm the hook only for the resulting genuine group stop.
    ptrace(libc::PTRACE_CONT, tid, 0, libc::SIGSTOP as usize).unwrap();
    harness.owner().released(tid);
    let original_descriptor = harness.owner().handles[&tid].as_raw_fd();
    harness.owner().wait_withdrawal = Some(ListenWithdrawal {
        tid,
        until,
        peek: None,
        listen_attempted: false,
        listen_succeeded: false,
        listen_result: None,
        listen_errno: None,
        consumed: None,
    });
    loop {
        let owner = harness.owner();
        owner
            .time_left(until, "withdrawal group-stop observation")
            .unwrap();
        assert!(owner.poll_raw().unwrap().is_none());
        if owner.wait_withdrawal.as_ref().unwrap().consumed.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let owner = harness.owner();
    let control = owner.wait_withdrawal.as_ref().unwrap();
    assert_eq!(
        control.peek,
        Some(Peek {
            tid,
            signal: libc::SIGCHLD,
            code: libc::CLD_TRAPPED,
            status: (libc::PTRACE_EVENT_STOP << 8) | libc::SIGSTOP
        })
    );
    assert!(control.listen_attempted && control.listen_succeeded);
    assert_eq!(control.listen_result, Some(0));
    assert_eq!(control.listen_errno, Some(0));
    assert_eq!(control.consumed, Some(0));
    assert_eq!(owner.owned, BTreeSet::from([tid]));
    assert_eq!(owner.handles.len(), 1);
    assert_eq!(owner.handles[&tid].as_raw_fd(), original_descriptor);
    assert!(owner.pin_kinds == BTreeMap::from([(tid, PinKind::Process)]));
    assert!(
        owner.stopped.is_empty() && owner.reaped.is_empty() && owner.tracer_terminal.is_empty()
    );
    assert!(!owner.lost_wait && !owner.missing_pin);
    assert!(!broker::hup(&root) && !broker::hup(&broker));
    let cleanup = owner.cleanup().unwrap();
    assert_eq!(cleanup.reaped, [tid]);
    reaped(&root);
    reaped(&broker);
    assert_eq!(owner.wait_withdrawal.as_ref().unwrap().consumed, Some(0));
    assert!(owner.owned.is_empty() && owner.stopped.is_empty());
    assert!(!owner.lost_wait && !owner.missing_pin);
    assert!(harness.finish().reaped.is_empty());
}
