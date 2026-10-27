//! A real fatal signal changes GETEVENTMSG after a consumed creation stop.
//! Numeric cleanup authority must come from an independent child wait witness.
use super::*;

#[test]
fn creation_candidate_cannot_acquire_another_tracer_threads_child() {
    let fixture = Fixture::new(false);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    let root = pin(ready.pid);
    let helper = pin(harness.owner().broker.as_ref().unwrap().pid);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (finish_tx, finish_rx) = std::sync::mpsc::sync_channel(1);
    // Harness already blocks this thread's signals, so the new tracer inherits
    // that mask before establishing its own exclusive child wait domain.
    let worker = std::thread::spawn(move || {
        let fixture = Fixture::new(false);
        let mut harness = Harness::new();
        let ready = harness.launch(&fixture).unwrap();
        let root = pin(ready.pid);
        let helper = pin(harness.owner().broker.as_ref().unwrap().pid);
        ready_tx.send(ready.pid).unwrap();
        let requested = finish_rx.recv_timeout(TIMEOUT);
        let cleanup = harness.finish();
        reaped(&root);
        reaped(&helper);
        assert_eq!(cleanup.reaped, [ready.pid]);
        requested.unwrap();
    });
    let foreign = ready_rx.recv_timeout(TIMEOUT).unwrap();
    let owner = harness.owner();
    let result = owner.pin_creation_candidate(foreign);
    let observed_owned = owner.owned.clone();
    let observed_handles = owner.handles.keys().copied().collect::<BTreeSet<_>>();
    // A regressed __WNOTHREAD guard must not signal or wait for the other
    // tracer's child during fixture cleanup; retain its observed failure.
    owner.owned.remove(&foreign);
    owner.handles.remove(&foreign);
    owner.pin_kinds.remove(&foreign);
    let requested = finish_tx.send(());
    let joined = worker.join();
    let cleanup = owner.cleanup().unwrap();
    reaped(&root);
    reaped(&helper);
    requested.unwrap();
    joined.unwrap();
    assert_eq!(cleanup.reaped, [ready.pid]);
    assert!(
        matches!(result, Err(LaunchError::System { source, .. }) if source.raw_os_error() == Some(libc::ECHILD))
    );
    assert_eq!(observed_owned, BTreeSet::from([ready.pid]));
    assert_eq!(observed_handles, BTreeSet::from([ready.pid]));
    assert!(!owner.lost_wait && !owner.missing_pin);
    assert!(harness.finish().reaped.is_empty());
}

#[test]
fn creation_custody_accepts_unready_application_but_excludes_helper_and_nonchild() {
    let fixture = Fixture::new(false);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    let root = pin(ready.pid);
    let helper_pid = harness.owner().broker.as_ref().unwrap().pid;
    let helper = pin(helper_pid);
    ptrace(libc::PTRACE_CONT, ready.pid, 0, 0).unwrap();
    harness.owner().released(ready.pid);
    // The original is a live infinite loop: it has no ready stop or terminal.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PID,
                ready.pid as libc::id_t,
                &raw mut info,
                libc::WEXITED
                    | libc::WSTOPPED
                    | libc::WNOHANG
                    | libc::WNOWAIT
                    | libc::__WALL
                    | libc::__WNOTHREAD,
            )
        },
        0
    );
    assert_eq!(unsafe { info.si_pid() }, 0);
    let owner = harness.owner();
    let descriptor = owner.handles[&ready.pid].as_raw_fd();
    let application = owner.pin_creation_candidate(ready.pid);
    let helper_result = owner.pin_creation_candidate(helper_pid);
    let caller = std::process::id() as libc::pid_t;
    let nonchild = owner.pin_creation_candidate(caller);
    let invalid = owner.pin_creation_candidate(0);
    let actual_owned = owner.owned.clone();
    let actual_handles = owner.handles.keys().copied().collect::<BTreeSet<_>>();
    // Preserve the failed observation but safely clean a deliberately regressed
    // helper guard. The broker's actual ownership remains in owner.broker.
    for candidate in [helper_pid, caller, 0] {
        owner.owned.remove(&candidate);
        owner.handles.remove(&candidate);
        owner.pin_kinds.remove(&candidate);
    }
    let cleanup = owner.cleanup().unwrap();
    assert_eq!(cleanup.reaped, [ready.pid]);
    reaped(&root);
    reaped(&helper);
    assert!(application.is_ok());
    assert!(matches!(
        helper_result,
        Err(LaunchError::Invalid("invalid creation custody candidate"))
    ));
    assert!(
        matches!(nonchild, Err(LaunchError::System { source, .. }) if source.raw_os_error() == Some(libc::ECHILD))
    );
    assert!(matches!(
        invalid,
        Err(LaunchError::Invalid("invalid creation custody candidate"))
    ));
    assert_eq!(actual_owned, BTreeSet::from([ready.pid]));
    assert_eq!(actual_handles, BTreeSet::from([ready.pid]));
    assert_eq!(owner.handles[&ready.pid].as_raw_fd(), descriptor);
    assert!(!owner.lost_wait && !owner.missing_pin);
    assert!(harness.finish().reaped.is_empty());
}

#[test]
fn replaced_creation_payload_cannot_authorize_an_exit_status_as_a_task() {
    let fixture = Fixture::new(true);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    let root = pin(ready.pid);
    let helper = pin(harness.owner().broker.as_ref().unwrap().pid);
    let until = Instant::now() + TIMEOUT;
    ptrace(libc::PTRACE_CONT, ready.pid, 0, 0).unwrap();
    harness.owner().released(ready.pid);
    let mut creation = None;
    let mut newborn = None;
    while creation.is_none() || newborn.is_none() {
        let (tid, status) = harness
            .owner()
            .wait_raw(until, "creation identity fixture")
            .unwrap();
        assert!(libc::WIFSTOPPED(status));
        if tid == ready.pid {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_FORK);
            assert!(creation.replace(status).is_none());
        } else {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_STOP);
            assert!(newborn.replace(tid).is_none());
        }
    }
    let child = newborn.unwrap();
    let child_pin = pin(child);
    let original_owned = BTreeSet::from([ready.pid, child]);
    assert_eq!(harness.owner().owned, original_owned);

    // No broker cancellation or application continuation: the actual fatal
    // signal alone withdraws the parent's old stop and reaches pre-exit.
    kill(&root);
    let (tid, exit_status) = harness
        .owner()
        .wait_raw(until, "creation replaced by actual EXIT")
        .unwrap();
    assert_eq!(tid, ready.pid);
    assert!(libc::WIFSTOPPED(exit_status));
    assert_eq!(exit_status >> 16, libc::PTRACE_EVENT_EXIT);
    let mut payload = 0_u64;
    ptrace(
        libc::PTRACE_GETEVENTMSG,
        tid,
        0,
        (&raw mut payload) as usize,
    )
    .unwrap();
    assert_eq!(payload, libc::SIGKILL as u64);
    let false_candidate = libc::pid_t::try_from(payload).unwrap();
    assert!(!original_owned.contains(&false_candidate));
    assert_ne!(
        harness.owner().broker.as_ref().unwrap().pid,
        false_candidate
    );

    // Establish independently that this number is not in our child domain.
    // This is not a reaping receipt for either of the real retained tasks.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PID,
                false_candidate as libc::id_t,
                &raw mut info,
                libc::WEXITED
                    | libc::WSTOPPED
                    | libc::WNOHANG
                    | libc::WNOWAIT
                    | libc::__WALL
                    | libc::__WNOTHREAD,
            )
        },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    let owner = harness.owner();
    let descriptors = owner
        .handles
        .iter()
        .map(|(&tid, pin)| (tid, pin.as_raw_fd()))
        .collect::<BTreeMap<_, _>>();
    owner.discover_event_child(ready.pid, creation.unwrap());
    let observed_owned = owner.owned.clone();
    let observed_descriptors = owner
        .handles
        .iter()
        .map(|(&tid, pin)| (tid, pin.as_raw_fd()))
        .collect::<BTreeMap<_, _>>();

    // Make a deliberately regressed implementation safe to test: retain the
    // observed failure, but never let its proven non-child number reach tkill
    // or its unrelated pidfd keep the genuine cleanup owner alive forever.
    // No real child row, pin or terminal evidence is removed here.
    owner.owned.remove(&false_candidate);
    owner.handles.remove(&false_candidate);
    owner.pin_kinds.remove(&false_candidate);
    let cleanup = owner.cleanup().unwrap();
    assert_eq!(
        cleanup.reaped.iter().copied().collect::<BTreeSet<_>>(),
        original_owned
    );
    assert_eq!(cleanup.reaped.len(), 2);
    assert!(owner.owned.is_empty() && owner.stopped.is_empty());
    assert!(!owner.lost_wait && !owner.missing_pin);
    assert_eq!(owner.tracer_terminal.len(), 2);
    assert_eq!(owner.tracer_terminal[&ready.pid], libc::SIGKILL);
    assert_eq!(owner.tracer_terminal[&child], libc::SIGKILL);
    reaped(&root);
    reaped(&child_pin);
    reaped(&helper);
    assert_eq!(
        observed_owned, original_owned,
        "exit payload acquired numeric authority"
    );
    assert_eq!(
        observed_descriptors, descriptors,
        "exit payload acquired a retained pin"
    );
    assert!(harness.finish().reaped.is_empty());
}
