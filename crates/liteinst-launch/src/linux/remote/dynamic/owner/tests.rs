use super::*;

mod helper_death;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command as ProcessCommand, Stdio};

const TIMEOUT: Duration = Duration::from_secs(3);
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct IsolatedChild(Option<Child>);

impl Drop for IsolatedChild {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        // Child's own cached wait status is the only reaping authority here.
        // A panic before wait_with_output must still retain cleanup ownership.
        let _ = child.kill();
        let until = Instant::now() + TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
                _ => {}
            }
            if Instant::now() >= until {
                std::thread::spawn(move || {
                    loop {
                        match child.try_wait() {
                            Ok(Some(_)) => break,
                            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => break,
                            _ => std::thread::sleep(Duration::from_millis(1)),
                        }
                    }
                });
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}

impl Fixture {
    fn new(fork: bool) -> Self {
        Self::code(if fork {
            // SYS_fork; both branches remain in original user-space loops.
            &[0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0xeb, 0xfe]
        } else {
            &[0xeb, 0xfe]
        })
    }
    fn code(code: &[u8]) -> Self {
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-private-{}-{}",
                std::process::id(),
                FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("fixture");
        let mut bytes = vec![0_u8; 8192];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (offset, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(20, 1_u32), (64, 1), (68, 5)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (24, 0x401000_u64),
            (32, 64),
            (80, 0x400000),
            (96, 8192),
            (104, 8192),
            (112, 4096),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[4096..4096 + code.len()].copy_from_slice(code);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);
        Self { directory, path }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

struct Harness {
    owner: Option<Owner>,
    mask: Option<launch::BlockedSignals>,
}

impl Harness {
    fn new() -> Self {
        Self {
            owner: Some(Owner::new(0, Arc::new(AtomicBool::new(false)))),
            mask: Some(launch::BlockedSignals::new().unwrap()),
        }
    }
    fn owner(&mut self) -> &mut Owner {
        self.owner.as_mut().unwrap()
    }
    fn launch(&mut self, fixture: &Fixture) -> Result<Ready, LaunchError> {
        let inherited = self.mask.as_ref().unwrap().original();
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        launch::start(
            self.owner(),
            &LaunchCommand::new(&fixture.path),
            inherited,
            Instant::now() + TIMEOUT,
        )
    }
    fn finish(mut self) -> DynamicCleanup {
        let result = self.owner().cleanup();
        self.owner.take();
        self.mask.take().unwrap().restore().unwrap();
        result.unwrap()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(owner) = &mut self.owner {
            // A failed assertion must not leave the private failure injection
            // disabling the very cleanup needed during unwinding.
            owner.deny_kill_for_test = false;
            let _ = owner.cleanup();
        }
        // The mask guard restores only after the private wait domain is empty.
    }
}

fn pin(pid: libc::pid_t) -> OwnedFd {
    // SAFETY: the fixture is exclusively owned and has not been reaped.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(raw >= 0, "pidfd_open: {}", io::Error::last_os_error());
    // SAFETY: one successful pidfd_open produces one owned descriptor.
    unsafe { OwnedFd::from_raw_fd(raw as i32) }
}

fn tracer_retired(handle: &OwnedFd) {
    let mut event = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the initialized descriptor pins the original child incarnation.
    assert_eq!(unsafe { libc::poll(&raw mut event, 1, 0) }, 1);
    assert_ne!(
        event.revents & libc::POLLIN,
        0,
        "original child is not terminal"
    );
    // SAFETY: a pidfd names only the original incarnation, and WNOWAIT never
    // consumes a cleanup owner's terminal status.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                handle.as_raw_fd() as libc::id_t,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn reaped(handle: &OwnedFd) {
    tracer_retired(handle);
    assert!(
        broker::hup(handle),
        "original task remains physically present"
    );
}

fn kill(handle: &OwnedFd) {
    signal(handle, libc::SIGKILL);
}

fn signal(handle: &OwnedFd, signal: i32) {
    // SAFETY: the descriptor pins the exact original owned incarnation.
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                handle.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
}

#[test]
fn unexpected_newborn_is_reaped_without_public_creation_support() {
    let fixture = Fixture::new(true);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    let root_handle = pin(ready.pid);
    // Private fault injection deliberately bypasses the public syscall refusal.
    // The actual kernel FORK/automatic child-stop events exercise cleanup.
    ptrace(libc::PTRACE_CONT, ready.pid, 0, 0).unwrap();
    let (tid, status) = harness
        .owner()
        .wait_raw(Instant::now() + TIMEOUT, "private newborn")
        .unwrap();
    assert!(libc::WIFSTOPPED(status));
    assert!(tid != ready.pid || status >> 16 == libc::PTRACE_EVENT_FORK);
    let cleanup = harness.finish();
    assert_eq!(cleanup.reaped.len(), 2);
    assert!(cleanup.reaped.contains(&ready.pid));
    assert_ne!(cleanup.reaped[0], cleanup.reaped[1]);
    reaped(&root_handle);
}

#[test]
fn late_parent_payload_cannot_reacquire_a_reaped_child_identity() {
    let fixture = Fixture::new(true);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    ptrace(libc::PTRACE_CONT, ready.pid, 0, 0).unwrap();
    let until = Instant::now() + TIMEOUT;
    let mut child_stop = None;
    let parent_status = loop {
        let (tid, status) = harness
            .owner()
            .wait_raw(until, "private fork payload")
            .unwrap();
        assert!(libc::WIFSTOPPED(status));
        if tid == ready.pid {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_FORK);
            break status;
        }
        assert!(child_stop.replace(tid).is_none());
    };
    let mut child = 0_u64;
    ptrace(
        libc::PTRACE_GETEVENTMSG,
        ready.pid,
        0,
        (&raw mut child) as usize,
    )
    .unwrap();
    let child = libc::pid_t::try_from(child).unwrap();
    assert!(child > 0 && child != ready.pid);
    if let Some(stopped) = child_stop {
        assert_eq!(stopped, child);
    } else {
        let (tid, status) = harness
            .owner()
            .wait_raw(until, "private automatic child stop")
            .unwrap();
        assert_eq!(tid, child);
        assert!(libc::WIFSTOPPED(status));
    }
    let child_handle = pin(child);
    kill(&child_handle);
    // SIGKILL can replace the automatic stop; continue if it remains stopped.
    let _ = ptrace(libc::PTRACE_CONT, child, 0, 0);
    loop {
        let (tid, status) = harness
            .owner()
            .wait_raw(until, "private child terminal")
            .unwrap();
        assert_eq!(tid, child);
        if libc::WIFSIGNALED(status) {
            assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
            break;
        }
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(status >> 16, libc::PTRACE_EVENT_EXIT);
        ptrace(libc::PTRACE_CONT, child, 0, 0).unwrap();
    }
    tracer_retired(&child_handle);
    assert!(
        !broker::hup(&child_handle),
        "held real parent must still own the zombie"
    );
    assert!(!harness.owner().owned.contains(&child));
    harness
        .owner()
        .discover_event_child(ready.pid, parent_status);
    assert!(
        !harness.owner().owned.contains(&child),
        "late payload restored numeric signalling authority"
    );
    let cleanup = harness.finish();
    assert_eq!(cleanup.reaped.len(), 2);
    assert!(cleanup.reaped.contains(&ready.pid));
    assert!(cleanup.reaped.contains(&child));
    reaped(&child_handle);
}

#[test]
fn tracer_unwind_and_client_drop_keep_the_original_cleanup_owner() {
    let fixture = Fixture::new(false);
    for panic in [false, true] {
        let mut session = {
            let _guard = crate::TEST_FILE_FORK.lock().unwrap();
            DynamicSession::launch(&LaunchCommand::new(&fixture.path), TIMEOUT).unwrap()
        };
        let pid = session.pid();
        let handle = pin(pid);
        if panic {
            let (reply, response) = channel();
            session
                .commands
                .send(Command {
                    request: Request::PanicForCleanupTest,
                    until: Instant::now() + TIMEOUT,
                    reply,
                })
                .unwrap();
            assert!(response.recv_timeout(TIMEOUT).is_err());
            assert_eq!(session.terminate(TIMEOUT).unwrap().reaped, [pid]);
        } else {
            // Retain only the receipt in this private test; the public Drop still
            // owns no wait and only requests cancellation.
            let (_unused_sender, replacement) = channel();
            let done = std::mem::replace(&mut session.done, replacement);
            drop(session);
            assert_eq!(done.recv_timeout(TIMEOUT).unwrap().unwrap().reaped, [pid]);
        }
        reaped(&handle);
    }
}

#[test]
fn bootstrap_and_seized_cleanup_survive_sigchld_autoreap_in_isolated_process() {
    const CHILD_ENV: &str = "LITEINST_DYNAMIC_ISOLATED_CLEANUP";
    if std::env::var_os(CHILD_ENV).is_none() {
        let test = format!(
            "{}::bootstrap_and_seized_cleanup_survive_sigchld_autoreap_in_isolated_process",
            module_path!()
        );
        let test = test.split_once("::").unwrap().1;
        let mut child = IsolatedChild(Some({
            let _guard = crate::TEST_FILE_FORK.lock().unwrap();
            ProcessCommand::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--test-threads=1", "--nocapture"])
                .env(CHILD_ENV, "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        }));
        let until = Instant::now() + Duration::from_secs(12);
        loop {
            if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= until {
                panic!("isolated cleanup timed out; subprocess cleanup remains owned");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        // try_wait above already cached terminal status in this same Child.
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "isolated cleanup failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "isolated libtest must execute exactly one test: {text}"
        );
        assert!(
            text.lines()
                .any(|line| line.ends_with("DYNAMIC_ISOLATED_CLEANUP_COMPLETED=4")),
            "all four isolated cases must reach their completion witness: {text}"
        );
        return;
    }
    // This is an exec-isolated test process, never the shared parallel harness.
    for flags in [0, libc::SA_NOCLDWAIT] {
        // SAFETY: valid initialized native action. Only this isolated process's
        // SIGCHLD disposition changes; no application callback is installed.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = if flags == 0 {
            libc::SIG_IGN
        } else {
            libc::SIG_DFL
        };
        action.sa_flags = flags;
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, &raw const action, std::ptr::null_mut()) },
            0
        );
        let fixture = Fixture::new(false);
        for fail_before_seize in [true, false] {
            let mut harness = Harness::new();
            harness.owner().fail_before_seize = fail_before_seize;
            let result = harness.launch(&fixture);
            if fail_before_seize {
                assert!(matches!(
                    result,
                    Err(LaunchError::Invalid("injected cancellation before SEIZE"))
                ));
            } else {
                assert!(result.is_ok());
            }
            let pid = harness.owner().pid;
            assert!(pid > 0);
            let handle = harness.owner().handles[&pid].try_clone().unwrap();
            if fail_before_seize {
                // H is not the real parent before SEIZE. Authenticate R's
                // actual natural-parent SIGKILL wait; never invent ptrace wait.
                harness
                    .owner()
                    .broker
                    .as_mut()
                    .unwrap()
                    .acknowledge(false)
                    .unwrap();
                let until = Instant::now() + TIMEOUT;
                loop {
                    harness.owner().poll_broker().unwrap();
                    if let Some(&status) =
                        harness.owner().broker.as_ref().unwrap().physical.get(&pid)
                    {
                        assert!(libc::WIFSIGNALED(status));
                        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
                        break;
                    }
                    assert!(Instant::now() < until, "missing physical bootstrap receipt");
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            assert_eq!(harness.finish().reaped, [pid]);
            reaped(&handle);
        }
    }
    println!("DYNAMIC_ISOLATED_CLEANUP_COMPLETED=4");
}

#[test]
fn missing_kill_success_never_releases_original_instructions() {
    let fixture = Fixture::new(false);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    let handle = pin(ready.pid);
    let registers = read_registers(ready.pid).unwrap();
    let state = xstate(ready.pid).unwrap();
    harness.owner().deny_kill_for_test = true;
    let killed = harness.owner().kill_owned();
    assert!(killed.is_empty());
    harness.owner().release_killed_stops(&killed);
    assert_eq!(read_registers(ready.pid).unwrap(), registers);
    assert_eq!(xstate(ready.pid).unwrap(), state);
    assert_eq!(
        read_memory(ready.pid, registers.rip, 2).unwrap(),
        [0xeb, 0xfe]
    );
    assert!(harness.owner().stopped.contains_key(&ready.pid));
    assert!(harness.owner().poll_raw().unwrap().is_none());
    harness.owner().deny_kill_for_test = false;
    assert_eq!(harness.finish().reaped, [ready.pid]);
    reaped(&handle);
}

#[test]
fn failed_exec_preserves_errno_and_reaps_the_consumed_exit_stop() {
    let fixture = Fixture::new(false);
    // ELF validation succeeds, then the real child execve fails EACCES.
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let mut harness = Harness::new();
    let result = harness.launch(&fixture);
    assert!(
        matches!(result, Err(LaunchError::System { operation: "seized child execve", source })
        if source.raw_os_error() == Some(libc::EACCES))
    );
    let pid = harness.owner().pid;
    let handle = pin(pid);
    assert_eq!(harness.owner().stopped[&pid] >> 16, libc::PTRACE_EVENT_EXIT);
    assert_eq!(harness.finish().reaped, [pid]);
    reaped(&handle);
}

#[test]
fn queued_syscall_stop_preserves_deferred_interrupt_then_job_control() {
    let mut descriptors = [-1_i32; 2];
    // SAFETY: two writable descriptor slots, adopted immediately on success.
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let _writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    // SAFETY: the original fixture inherits this specific pipe reader.
    assert_eq!(
        unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let mut code = vec![0xb8, 0, 0, 0, 0, 0xbf]; // read(pipe, RSP-16, 1).
    code.extend_from_slice(&(reader.as_raw_fd() as u32).to_le_bytes());
    code.extend_from_slice(&[
        0x48, 0x8d, 0x74, 0x24, 0xf0, 0xba, 1, 0, 0, 0, 0x0f, 0x05, 0xeb, 0xfe,
    ]);
    let fixture = Fixture::code(&code);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    let handle = pin(ready.pid);
    let until = Instant::now() + TIMEOUT;
    harness
        .owner()
        .resume(ready.event.stop_token().unwrap(), DynamicResume::Continue)
        .unwrap();
    let event = harness.owner().wait_event(until).unwrap();
    assert!(matches!(
        event.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false
        }
    ));
    harness
        .owner()
        .resume(event.stop_token().unwrap(), DynamicResume::Continue)
        .unwrap();
    let event = harness.owner().wait_event(until).unwrap();
    assert!(matches!(
        event.kind,
        DynamicEventKind::SyscallEntry { number: 0, .. }
    ));
    harness
        .owner()
        .resume(event.stop_token().unwrap(), DynamicResume::Continue)
        .unwrap();
    // SIGSTOP interrupts the blocking read and queues a syscall-exit stop.
    signal(&handle, libc::SIGSTOP);
    loop {
        // SAFETY: WNOWAIT observes the exact owned incarnation without consuming
        // its status. This forces the stop to predate PTRACE_INTERRUPT below.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    handle.as_raw_fd() as libc::id_t,
                    &raw mut info,
                    libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                )
            },
            0
        );
        if unsafe { info.si_pid() } != 0 {
            assert_eq!(unsafe { info.si_pid() }, ready.pid);
            assert_eq!(info.si_code, libc::CLD_TRAPPED);
            assert_eq!(unsafe { info.si_status() }, libc::SIGTRAP | 0x80);
            break;
        }
        assert!(Instant::now() < until, "queued-stop witness timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
    let Response::Event(event) = harness.owner().execute(Request::Interrupt, until).unwrap() else {
        panic!("missing interruption response");
    };
    assert!(matches!(
        event.kind,
        DynamicEventKind::SyscallExit {
            result: -512,
            is_error: true
        }
    ));
    assert_eq!(harness.owner().interrupt_stops_remaining, 1);
    harness
        .owner()
        .resume(event.stop_token().unwrap(), DynamicResume::Continue)
        .unwrap();
    let event = harness.owner().wait_event(until).unwrap();
    assert_eq!(event.kind, DynamicEventKind::Interrupted);
    assert_eq!(harness.owner().interrupt_stops_remaining, 0);
    harness
        .owner()
        .resume(event.stop_token().unwrap(), DynamicResume::Continue)
        .unwrap();
    let event = harness.owner().wait_event(until).unwrap();
    assert!(
        matches!(event.kind, DynamicEventKind::SignalDelivery(ref info) if info.signal() == libc::SIGSTOP)
    );
    harness
        .owner()
        .resume(event.stop_token().unwrap(), DynamicResume::DeliverOriginal)
        .unwrap();
    let event = harness.owner().wait_event(until).unwrap();
    assert_eq!(
        event.kind,
        DynamicEventKind::GroupStop {
            signal: libc::SIGSTOP
        }
    );
    let registers = read_registers(ready.pid).unwrap();
    let state = xstate(ready.pid).unwrap();
    harness
        .owner()
        .resume(event.stop_token().unwrap(), DynamicResume::Listen)
        .unwrap();
    assert!(harness.owner().poll_raw().unwrap().is_none());
    signal(&handle, libc::SIGCONT);
    let event = harness.owner().wait_event(until).unwrap();
    assert_eq!(event.kind, DynamicEventKind::GroupContinued);
    assert_eq!(read_registers(ready.pid).unwrap(), registers);
    assert_eq!(xstate(ready.pid).unwrap(), state);
    assert_eq!(harness.finish().reaped, [ready.pid]);
    reaped(&handle);
}

#[test]
fn helper_failure_after_application_clone_before_ready_still_drains_both() {
    let fixture = Fixture::new(false);
    let mut harness = Harness::new();
    harness.owner().fail_before_ready = true;
    assert!(matches!(
        harness.launch(&fixture),
        Err(LaunchError::Invalid("private reaper bootstrap failed"))
    ));
    assert_eq!(harness.owner().pid, 0, "no Ready identity was fabricated");
    let helper = harness.owner().broker.as_ref().unwrap().pid;
    let helper_handle = pin(helper);
    // R has not received Abort and therefore retains even a dead A unreaped.
    let app = harness
        .owner()
        .broker
        .as_ref()
        .unwrap()
        .failure_root
        .unwrap();
    assert!(app > 0 && app != helper);
    let app_handle = pin(app);
    assert!(!broker::hup(&app_handle));
    let result = harness.owner().cleanup();
    assert!(
        result.is_err(),
        "failed bootstrap cannot produce successful cleanup qualification"
    );
    let physical = &harness.owner().broker.as_ref().unwrap().physical;
    assert_eq!(physical.len(), 1);
    assert!(libc::WIFSIGNALED(physical[&app]));
    assert_eq!(libc::WTERMSIG(physical[&app]), libc::SIGKILL);
    assert!(harness.owner().broker.as_ref().unwrap().done);
    reaped(&app_handle);
    reaped(&helper_handle);
    harness.owner.take();
    harness.mask.take().unwrap().restore().unwrap();
}

#[test]
fn abort_before_seize_acknowledgement_keeps_broker_cleanup_owned() {
    let fixture = Fixture::new(false);
    let mut harness = Harness::new();
    harness.owner().abort_before_seize = true;
    assert!(matches!(
        harness.launch(&fixture),
        Err(LaunchError::Invalid("injected abort before SEIZE"))
    ));
    assert!(!harness.owner().attached);
    let app = harness.owner().pid;
    let app_handle = harness.owner().handles[&app].try_clone().unwrap();
    let helper = harness.owner().broker.as_ref().unwrap().pid;
    let helper_handle = pin(helper);
    assert!(!broker::hup(&app_handle));
    assert!(!broker::hup(&helper_handle));
    // Harness Drop takes the same cancellation path without a successful
    // attachment acknowledgement or an earlier test-generated SIGKILL.
    drop(harness);
    reaped(&app_handle);
    reaped(&helper_handle);
}

#[test]
fn helper_eof_without_done_reports_failure_after_physical_cleanup() {
    let fixture = Fixture::new(false);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    let app_handle = pin(ready.pid);
    let helper_handle = pin(harness.owner().broker.as_ref().unwrap().pid);
    harness
        .owner()
        .broker
        .as_ref()
        .unwrap()
        .disconnect_for_test();
    assert!(
        harness.owner().cleanup().is_err(),
        "missing Done cannot become successful cleanup"
    );
    assert!(!harness.owner().broker.as_ref().unwrap().done);
    assert!(harness.owner().owned.is_empty());
    assert!(harness.owner().tracer_terminal.contains_key(&ready.pid));
    reaped(&app_handle);
    reaped(&helper_handle);
    harness.owner.take();
    harness.mask.take().unwrap().restore().unwrap();
}

#[test]
fn newborn_pidfd_failure_retains_wait_authority_and_drains_without_qualification() {
    let fixture = Fixture::new(true);
    let mut harness = Harness::new();
    let ready = harness.launch(&fixture).unwrap();
    let root_handle = pin(ready.pid);
    let helper_handle = pin(harness.owner().broker.as_ref().unwrap().pid);
    harness.owner().deny_pin_for_test = true;
    ptrace(libc::PTRACE_CONT, ready.pid, 0, 0).unwrap();
    let until = Instant::now() + TIMEOUT;
    let mut child = None;
    loop {
        match harness
            .owner()
            .wait_raw(until, "private newborn pidfd failure")
        {
            Ok((tid, status)) => {
                assert_eq!(tid, ready.pid);
                assert_eq!(status >> 16, libc::PTRACE_EVENT_FORK);
                let mut pid = 0_u64;
                ptrace(libc::PTRACE_GETEVENTMSG, tid, 0, (&raw mut pid) as usize).unwrap();
                child = Some(i32::try_from(pid).unwrap());
                harness.owner().discover_event_child(tid, status);
            }
            Err(LaunchError::System {
                operation: "pidfd_open dynamic process",
                source,
            }) => {
                assert_eq!(source.raw_os_error(), Some(libc::EMFILE));
                break;
            }
            other => panic!("unexpected allocation-failure fixture event: {other:?}"),
        }
    }
    let child = child.unwrap_or_else(|| {
        *harness
            .owner()
            .owned
            .iter()
            .find(|&&tid| tid != ready.pid)
            .unwrap()
    });
    assert!(harness.owner().owned.contains(&child));
    assert!(!harness.owner().handles.contains_key(&child));
    // This independent fixture pin strengthens final evidence. It is never
    // supplied to the owner whose actual allocation failure is under test.
    let child_handle = pin(child);
    assert!(
        harness.owner().cleanup().is_err(),
        "missing owner pin cannot qualify HUP cleanup"
    );
    assert!(harness.owner().owned.is_empty());
    assert!(harness.owner().tracer_terminal.contains_key(&child));
    assert!(harness.owner().broker.as_ref().unwrap().done);
    reaped(&root_handle);
    reaped(&child_handle);
    reaped(&helper_handle);
    harness.owner.take();
    harness.mask.take().unwrap().restore().unwrap();
}
