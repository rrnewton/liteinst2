//! The outer subreaper is a different process from the tracer host. Otherwise
//! ptrace_reparented can collapse the two waits into one and miss the defect.
use super::*;
use std::os::unix::process::CommandExt;

const ROLE: &str = "LITEINST_DYNAMIC_HELPER_DEATH_ROLE";
const CHANNEL: &str = "LITEINST_DYNAMIC_HELPER_DEATH_CHANNEL";
const MAGIC: i64 = 0x4c49_3248_4445_4154;
const READY: i64 = 1;
const HELPER_KILLED: i64 = 2;
const RETAINED: i64 = 3;
const ZOMBIE_HELD: i64 = 4;
const NO_RECEIPT: i64 = 5;
const REAPED: i64 = 6;
const FAILED_PROOF: i64 = 7;
const STILL_OWNED: i64 = 8;
const KNOWN_TEST: &str = "helper_death_retains_owner_until_external_natural_parent_reaps";
const UNKNOWN_TEST: &str = "helper_death_before_ready_retains_unknown_bootstrap_ownership";

struct Wire {
    descriptor: OwnedFd,
    sender: libc::ucred,
}

impl Wire {
    fn send(&self, phase: i64, app: i32, helper: i32) {
        let packet = [MAGIC, phase, i64::from(app), i64::from(helper)];
        let until = Instant::now() + TIMEOUT;
        loop {
            let sent = unsafe {
                libc::send(
                    self.descriptor.as_raw_fd(),
                    packet.as_ptr().cast(),
                    32,
                    libc::MSG_NOSIGNAL,
                )
            };
            if sent == 32 {
                return;
            }
            assert_eq!(sent, -1);
            assert!(matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN | libc::EINTR)
            ));
            assert!(
                Instant::now() < until,
                "private helper-death IPC send timeout"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn receive(&self, phase: i64) -> (i32, i32) {
        let until = Instant::now() + TIMEOUT;
        loop {
            let mut packet = [0_i64; 4];
            let mut control = [0_usize; 8];
            let mut iov = libc::iovec {
                iov_base: packet.as_mut_ptr().cast(),
                iov_len: 32,
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &raw mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = std::mem::size_of_val(&control);
            let received = unsafe {
                libc::recvmsg(
                    self.descriptor.as_raw_fd(),
                    &raw mut message,
                    libc::MSG_CMSG_CLOEXEC,
                )
            };
            if received < 0 {
                assert!(matches!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN | libc::EINTR)
                ));
                assert!(
                    Instant::now() < until,
                    "private helper-death IPC receive timeout"
                );
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            assert_eq!(received, 32);
            assert_eq!(message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
            // This test channel never transfers descriptors. The kernel attaches
            // the actual sender's per-message credentials after exec.
            let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
            assert!(!header.is_null());
            let credentials = unsafe {
                assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
                assert_eq!((*header).cmsg_type, libc::SCM_CREDENTIALS);
                assert_eq!(
                    (*header).cmsg_len,
                    libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) as usize
                );
                assert!(libc::CMSG_NXTHDR(&message, header).is_null());
                std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
            };
            assert_eq!(credentials.pid, self.sender.pid);
            assert_eq!(credentials.uid, self.sender.uid);
            assert_eq!(credentials.gid, self.sender.gid);
            assert_eq!(packet[0], MAGIC);
            assert_eq!(packet[1], phase);
            return (
                i32::try_from(packet[2]).unwrap(),
                i32::try_from(packet[3]).unwrap(),
            );
        }
    }
}

fn credentials(pid: i32) -> libc::ucred {
    libc::ucred {
        pid,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    }
}

fn command(role: &str, test_name: &str) -> ProcessCommand {
    let test = format!("{}::{test_name}", module_path!());
    let mut command = ProcessCommand::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            test.split_once("::").unwrap().1,
            "--test-threads=1",
            "--nocapture",
        ])
        .env(ROLE, role)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn check_output(output: std::process::Output, witness: &str) {
    assert!(
        output.status.success(),
        "nested helper-death fixture failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "nested fixture must execute exactly one test: {text}"
    );
    assert!(
        text.lines().any(|line| line.ends_with(witness)),
        "nested fixture lacks its final completion witness: {text}"
    );
}

fn wait_child(child: &mut Child) {
    let until = Instant::now() + Duration::from_secs(12);
    loop {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        assert!(
            Instant::now() < until,
            "nested helper-death fixture exceeded deadline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

// This guard exists only in the exec-isolated outer subreaper. It owns every
// process in that private fixture, and never raw-waits its Child-owned driver.
struct DriverTree {
    child: Option<Child>,
    app: Option<OwnedFd>,
}
impl Drop for DriverTree {
    fn drop(&mut self) {
        if let Some(app) = &self.app {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    app.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Err(error) if error.raw_os_error() == Some(libc::ECHILD) => break,
                    _ => std::thread::sleep(Duration::from_millis(1)),
                }
            }
        }
        // H is now physically reaped. Any surviving R observes its host pidfd,
        // kills/drains A and exits. A already orphaned by killed R is also killed
        // above. Keep S alive to collect all such actual natural-parent waits.
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG | libc::__WALL) };
            if pid > 0 {
                continue;
            }
            if pid < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn parent_of(pid: i32) -> i32 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:\t"))
        .unwrap()
        .parse()
        .unwrap()
}

fn wait_natural_status(handle: &OwnedFd, app: i32, consume: bool, code: i32, status: i32) {
    let until = Instant::now() + TIMEOUT;
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let flags =
            libc::WEXITED | libc::WNOHANG | libc::__WALL | if consume { 0 } else { libc::WNOWAIT };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    handle.as_raw_fd() as libc::id_t,
                    &raw mut info,
                    flags,
                )
            },
            0
        );
        if unsafe { info.si_pid() } == app {
            assert_eq!(info.si_code, code);
            assert_eq!(unsafe { info.si_status() }, status);
            return;
        }
        assert_eq!(unsafe { info.si_pid() }, 0);
        assert!(
            Instant::now() < until,
            "outer natural-parent terminal never became waitable"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_natural_zombie(handle: &OwnedFd, app: i32, consume: bool) {
    wait_natural_status(handle, app, consume, libc::CLD_KILLED, libc::SIGKILL);
}

fn outer_subreaper() {
    // Only this exec-isolated process changes its process-global subreaper bit.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let mut sockets = [-1; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                sockets.as_mut_ptr(),
            )
        },
        0
    );
    let parent = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
    let host = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
    let enable = 1_i32;
    for socket in sockets {
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&raw const enable).cast(),
                    4,
                )
            },
            0
        );
    }
    let host_fd = host.as_raw_fd();
    let mut command = command("host", KNOWN_TEST);
    command.env(CHANNEL, host_fd.to_string());
    // Only this one endpoint crosses exec; H restores CLOEXEC before launching A.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(host_fd, libc::F_SETFD, 0) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = {
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        command.spawn().unwrap()
    };
    let host_pid = child.id() as i32;
    let mut tree = DriverTree {
        child: Some(child),
        app: None,
    };
    drop(host);
    let wire = Wire {
        descriptor: parent,
        sender: credentials(host_pid),
    };
    let (app, helper) = wire.receive(READY);
    assert_eq!(parent_of(app), helper);
    assert_eq!(parent_of(helper), host_pid);
    let app_handle = pin(app);
    let helper_handle = pin(helper);
    tree.app = Some(app_handle.try_clone().unwrap());
    kill(&helper_handle);
    wire.send(HELPER_KILLED, app, helper);
    assert_eq!(wire.receive(RETAINED), (app, helper));
    assert!(broker::hup(&helper_handle));
    assert_eq!(parent_of(app), unsafe { libc::getpid() });
    // This actual waitable natural-parent zombie is available only after H has
    // retired the ptrace terminal. Do not substitute a sleep for that witness.
    wait_natural_zombie(&app_handle, app, false);
    assert!(!broker::hup(&app_handle));
    wire.send(ZOMBIE_HELD, app, helper);
    assert_eq!(wire.receive(NO_RECEIPT), (app, helper));
    wait_natural_zombie(&app_handle, app, false);
    assert!(!broker::hup(&app_handle));
    wait_natural_zombie(&app_handle, app, true);
    reaped(&app_handle);
    wire.send(REAPED, app, helper);
    assert_eq!(wire.receive(FAILED_PROOF), (app, helper));
    wait_child(tree.child.as_mut().unwrap());
    let output = tree.child.take().unwrap().wait_with_output().unwrap();
    check_output(output, "DYNAMIC_HELPER_DEATH_HOST_COMPLETED=1");
    reaped(&helper_handle);
    drop(tree);
    println!("DYNAMIC_HELPER_DEATH_SUBREAPER_COMPLETED=1");
}

fn tracer_host() {
    let fd: i32 = std::env::var(CHANNEL).unwrap().parse().unwrap();
    let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    let wire = Wire {
        descriptor,
        sender: credentials(unsafe { libc::getppid() }),
    };
    let fixture = Fixture::new(false);
    let mut session = {
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        DynamicSession::launch(&LaunchCommand::new(&fixture.path), TIMEOUT).unwrap()
    };
    let app = session.pid();
    let helper = parent_of(app);
    let app_handle = pin(app);
    let helper_handle = pin(helper);
    wire.send(READY, app, helper);
    assert_eq!(wire.receive(HELPER_KILLED), (app, helper));
    let (_, replacement) = channel();
    let completion = std::mem::replace(&mut session.done, replacement);
    drop(session);
    let until = Instant::now() + TIMEOUT;
    loop {
        assert!(
            matches!(
                completion.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "helper death retired the owner before physical removal"
        );
        let mut event = libc::pollfd {
            fd: app_handle.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&raw mut event, 1, 0) };
        if ready == 1 && event.revents & libc::POLLIN != 0 && broker::hup(&helper_handle) {
            break;
        }
        assert!(
            Instant::now() < until,
            "helper/application terminals were not consumed"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!broker::hup(&app_handle));
    wire.send(RETAINED, app, helper);
    assert_eq!(wire.receive(ZOMBIE_HELD), (app, helper));
    // S has now authenticated its actual waitable zombie and R is already HUP.
    // The fixed negative observation window exercises the former Err-return
    // branch; it is not an execution-speed tolerance or a weakened comparator.
    assert!(matches!(
        completion.recv_timeout(Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(!broker::hup(&app_handle));
    wire.send(NO_RECEIPT, app, helper);
    assert_eq!(wire.receive(REAPED), (app, helper));
    assert!(matches!(
        completion.recv_timeout(TIMEOUT).unwrap(),
        Err(LaunchError::Invalid(
            "private physical reaper ownership failed"
        ))
    ));
    reaped(&app_handle);
    reaped(&helper_handle);
    wire.send(FAILED_PROOF, app, helper);
    println!("DYNAMIC_HELPER_DEATH_HOST_COMPLETED=1");
}

#[test]
fn helper_death_retains_owner_until_external_natural_parent_reaps() {
    match std::env::var(ROLE).ok().as_deref() {
        Some("subreaper") => outer_subreaper(),
        Some("host") => tracer_host(),
        None => {
            let child = {
                let _guard = crate::TEST_FILE_FORK.lock().unwrap();
                command("subreaper", KNOWN_TEST).spawn().unwrap()
            };
            let mut child = IsolatedChild(Some(child));
            wait_child(child.0.as_mut().unwrap());
            check_output(
                child.0.take().unwrap().wait_with_output().unwrap(),
                "DYNAMIC_HELPER_DEATH_SUBREAPER_COMPLETED=1",
            );
        }
        other => panic!("unexpected isolated helper-death role: {other:?}"),
    }
}

fn unknown_outer_subreaper() {
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let mut sockets = [-1; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                sockets.as_mut_ptr(),
            )
        },
        0
    );
    let parent = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
    let host = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
    let enable = 1_i32;
    for socket in sockets {
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&raw const enable).cast(),
                    4,
                )
            },
            0
        );
    }
    let host_fd = host.as_raw_fd();
    let mut command = command("host", UNKNOWN_TEST);
    command.env(CHANNEL, host_fd.to_string());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(host_fd, libc::F_SETFD, 0) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = {
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        command.spawn().unwrap()
    };
    let host_pid = child.id() as i32;
    let mut tree = DriverTree {
        child: Some(child),
        app: None,
    };
    drop(host);
    let wire = Wire {
        descriptor: parent,
        sender: credentials(host_pid),
    };
    let (unknown, helper) = wire.receive(READY);
    assert_eq!(unknown, 0, "H must not fabricate an application identity");
    assert!(helper > 0 && helper != host_pid);
    // H never received the application PID. S discovers only its own actual
    // natural-parent terminal, holds it unreaped, and pins before any consume.
    let until = Instant::now() + TIMEOUT;
    let app = loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &raw mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                )
            },
            0
        );
        let pid = unsafe { info.si_pid() };
        if pid != 0 {
            assert_ne!(pid, host_pid, "driver exited before the ownership witness");
            assert_ne!(pid, helper, "H must reap its original helper");
            assert_eq!(info.si_code, libc::CLD_EXITED);
            assert_eq!(
                unsafe { info.si_status() },
                127,
                "unreleased bootstrap must take its actual error exit"
            );
            break pid;
        }
        assert!(
            Instant::now() < until,
            "unknown bootstrap never became an owned natural-parent zombie"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(parent_of(app), unsafe { libc::getpid() });
    let app_handle = pin(app);
    tree.app = Some(app_handle.try_clone().unwrap());
    assert!(!broker::hup(&app_handle));
    wire.send(ZOMBIE_HELD, app, helper);
    assert_eq!(wire.receive(NO_RECEIPT), (app, helper));
    wait_natural_status(&app_handle, app, false, libc::CLD_EXITED, 127);
    assert!(!broker::hup(&app_handle));
    wait_natural_status(&app_handle, app, true, libc::CLD_EXITED, 127);
    reaped(&app_handle);
    wire.send(REAPED, app, helper);
    assert_eq!(wire.receive(STILL_OWNED), (app, helper));
    wait_child(tree.child.as_mut().unwrap());
    let output = tree.child.take().unwrap().wait_with_output().unwrap();
    check_output(output, "DYNAMIC_UNKNOWN_HELPER_HOST_COMPLETED=1");
    drop(tree);
    println!("DYNAMIC_UNKNOWN_HELPER_SUBREAPER_COMPLETED=1");
}

fn unknown_tracer_host() {
    let fd: i32 = std::env::var(CHANNEL).unwrap().parse().unwrap();
    let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    let wire = Wire {
        descriptor,
        sender: credentials(unsafe { libc::getppid() }),
    };
    let fixture = Fixture::new(false);
    let path = fixture.path.clone();
    let (announced, ready) = channel();
    let (completed, completion) = channel();
    let mask = launch::BlockedSignals::new().unwrap();
    let inherited = mask.original();
    // The exact tracer remains in its original thread, even when cleanup cannot
    // establish a physical proof. This process is deliberately the fixture's
    // containment boundary; its normal exit later terminates the retained thread.
    let tracer = std::thread::spawn(move || {
        launch::set_current_mask(u64::MAX).unwrap();
        let mut harness = Harness::new();
        harness.owner().die_before_ready = true;
        let result = {
            let _guard = crate::TEST_FILE_FORK.lock().unwrap();
            launch::start(
                harness.owner(),
                &LaunchCommand::new(path),
                inherited,
                Instant::now() + TIMEOUT,
            )
        };
        assert!(matches!(
            result,
            Err(LaunchError::Invalid(
                "private reaper protocol ended without drain receipt"
            ))
        ));
        assert_eq!(harness.owner().pid, 0);
        assert!(harness.owner().handles.is_empty());
        assert!(!harness.owner().missing_pin);
        let helper = harness.owner().broker.as_ref().unwrap().pid;
        // launch never consumed this real child's terminal; pin and authenticate
        // its actual SIGKILL before cleanup retires the numeric helper identity.
        let helper_handle = pin(helper);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    helper_handle.as_raw_fd() as libc::id_t,
                    &raw mut info,
                    libc::WEXITED | libc::WNOWAIT | libc::__WALL,
                )
            },
            0
        );
        assert_eq!(unsafe { info.si_pid() }, helper);
        assert_eq!(info.si_code, libc::CLD_KILLED);
        assert_eq!(unsafe { info.si_status() }, libc::SIGKILL);
        announced.send((helper, helper_handle)).unwrap();
        let result = harness.owner().cleanup();
        // Reaching this send is the defect: neither a success nor a failed-proof
        // result is justified when the app was never pinned and Done is absent.
        let _ = completed.send(result);
        harness.owner.take();
    });
    mask.restore().unwrap();
    drop(tracer);
    let (helper, helper_handle) = ready.recv_timeout(TIMEOUT).unwrap();
    let until = Instant::now() + TIMEOUT;
    loop {
        assert!(
            matches!(
                completion.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "unknown bootstrap incorrectly retired cleanup ownership"
        );
        if broker::hup(&helper_handle) {
            break;
        }
        assert!(
            Instant::now() < until,
            "original helper was not physically reaped"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    wire.send(READY, 0, helper);
    let (app, observed_helper) = wire.receive(ZOMBIE_HELD);
    assert!(app > 0);
    assert_eq!(observed_helper, helper);
    assert!(matches!(
        completion.recv_timeout(Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    wire.send(NO_RECEIPT, app, helper);
    assert_eq!(wire.receive(REAPED), (app, helper));
    // S's external knowledge is intentionally not inserted into Owner. Even
    // after physical reap, H cannot reconstruct the missing incarnation proof.
    assert!(matches!(
        completion.recv_timeout(Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    reaped(&helper_handle);
    wire.send(STILL_OWNED, app, helper);
    println!("DYNAMIC_UNKNOWN_HELPER_HOST_COMPLETED=1");
}

#[test]
fn helper_death_before_ready_retains_unknown_bootstrap_ownership() {
    match std::env::var(ROLE).ok().as_deref() {
        Some("subreaper") => unknown_outer_subreaper(),
        Some("host") => unknown_tracer_host(),
        None => {
            let child = {
                let _guard = crate::TEST_FILE_FORK.lock().unwrap();
                command("subreaper", UNKNOWN_TEST).spawn().unwrap()
            };
            let mut child = IsolatedChild(Some(child));
            wait_child(child.0.as_mut().unwrap());
            check_output(
                child.0.take().unwrap().wait_with_output().unwrap(),
                "DYNAMIC_UNKNOWN_HELPER_SUBREAPER_COMPLETED=1",
            );
        }
        other => panic!("unexpected isolated unknown-helper role: {other:?}"),
    }
}
