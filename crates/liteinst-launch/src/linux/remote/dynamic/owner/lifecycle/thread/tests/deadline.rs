//! Exact timeout-origin tests. The native owner always retains its wait domain;
//! a bounded channel proxy can delay only command dispatch or reply delivery.
use super::*;

const EVENT_TIMEOUT: Duration = Duration::from_millis(100);

struct Pair {
    session: Option<DynamicSession>,
    parent: DynamicEvent,
    worker: DynamicEvent,
    pins: Vec<(i32, OwnedFd)>,
}

fn pin(tid: i32, flags: i32) -> OwnedFd {
    // SAFETY: each numeric identity is authenticated and continuously held.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, flags) };
    assert!(fd >= 0);
    // SAFETY: the successful syscall returned one owned descriptor.
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

impl Pair {
    fn new(fixture: &Fixture) -> Self {
        let session = {
            let _file = crate::TEST_FILE_FORK.lock().unwrap();
            DynamicSession::launch_with_lifecycle(
                &LaunchCommand::new(&fixture.path),
                DynamicLifecycleOptions::thread_only(),
                TIMEOUT,
            )
            .unwrap()
        };
        let initial = session.initial_event().clone();
        let leader = session.pid();
        let mut pair = Self {
            session: Some(session),
            parent: initial.clone(),
            worker: initial.clone(),
            pins: Vec::new(),
        };
        pair.pins.push((leader, pin(leader, 0)));
        pair.release(&initial);
        let exit = pair.session().next_event(TIMEOUT).unwrap();
        assert_eq!(
            exit.kind,
            DynamicEventKind::SyscallExit {
                result: 0,
                is_error: false,
            }
        );
        pair.release(&exit);
        let entry = pair.session().next_event(TIMEOUT).unwrap();
        assert!(
            matches!(entry.kind, DynamicEventKind::SyscallEntry { number, .. }
            if number == libc::SYS_clone as u64)
        );
        pair.release(&entry);
        let created = pair.session().next_event(TIMEOUT).unwrap();
        assert!(matches!(created.kind, DynamicEventKind::Created { .. }));
        let worker = pair.session().next_event(TIMEOUT).unwrap();
        assert!(matches!(worker.kind, DynamicEventKind::Newborn { .. }));
        pair.pins.push((worker.tid, pin(worker.tid, libc::O_EXCL)));
        pair.release(&created);
        let parent = pair.session().next_event(TIMEOUT).unwrap();
        assert_eq!(
            parent.kind,
            DynamicEventKind::SyscallExit {
                result: i64::from(worker.tid),
                is_error: false,
            }
        );
        assert_eq!(parent.task.unwrap().process, worker.task.unwrap().process);
        assert_eq!(
            parent.task.unwrap().address_space,
            worker.task.unwrap().address_space
        );
        pair.parent = parent;
        pair.worker = worker;
        pair
    }

    fn session(&mut self) -> &mut DynamicSession {
        self.session.as_mut().unwrap()
    }

    fn release(&mut self, event: &DynamicEvent) {
        self.session()
            .resume(event.stop_token().unwrap(), DynamicResume::Continue)
            .unwrap();
    }

    fn spin(&mut self) {
        let parent = self.parent.clone();
        let worker = self.worker.clone();
        self.release(&parent);
        self.release(&worker);
    }

    fn frame(&mut self, event: &DynamicEvent) -> Evidence {
        let token = event.stop_token().unwrap();
        Evidence {
            registers: self.session().read_registers(token).unwrap(),
            extended: self.session().read_xstate(token).unwrap(),
            mask: self.session().signal_mask(token).unwrap(),
            code: self.session().read_memory(token, 0x400000, 0x2000).unwrap(),
            storage: self.session().read_memory(token, DATA, 0x4000).unwrap(),
        }
    }

    fn finish(mut self) {
        let cleanup = self.session.take().unwrap().terminate(TIMEOUT);
        let physically_gone = self.pins.iter().all(|(_, fd)| broker::hup(fd));
        let mut expected = self.pins.iter().map(|(tid, _)| *tid).collect::<Vec<_>>();
        let mut reaped = cleanup.unwrap().reaped;
        expected.sort_unstable();
        reaped.sort_unstable();
        assert_eq!(reaped, expected);
        assert!(physically_gone, "both application pidfds must report HUP");
        for (_, fd) in &self.pins {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    libc::waitid(
                        libc::P_PIDFD,
                        fd.as_raw_fd() as u32,
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
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let _ = session.terminate(TIMEOUT);
        }
    }
}

#[derive(Clone, Copy)]
enum Delay {
    Reply,
    Dispatch,
}

#[derive(Debug)]
struct ProxyReport {
    owner_timeout: Option<&'static str>,
    owner_invalid: Option<&'static str>,
    dispatched_expired: bool,
    delivered: bool,
}

struct Proxy {
    release: Sender<()>,
    done: Receiver<Result<ProxyReport, &'static str>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

fn proxy_once(
    input: Receiver<Command>,
    real: Sender<Command>,
    release: Receiver<()>,
    delay: Delay,
) -> Result<ProxyReport, &'static str> {
    let end = Instant::now() + TIMEOUT;
    let command = input
        .recv_timeout(end.saturating_duration_since(Instant::now()))
        .map_err(|_| "proxy did not receive a command")?;
    if !matches!(command.request, Request::Wait) {
        return Err("proxy received a non-wait command");
    }
    if command.until > end {
        return Err("command deadline exceeds proxy bound");
    }
    if matches!(delay, Delay::Dispatch) {
        while Instant::now() < command.until {
            match release.recv_timeout(command.until.saturating_duration_since(Instant::now())) {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                _ => return Err("dispatch gate was cancelled before command expiry"),
            }
        }
    }
    let dispatched_expired = Instant::now() >= command.until;
    let (captured, owner_reply) = channel();
    real.send(Command {
        request: command.request,
        until: command.until,
        reply: captured,
    })
    .map_err(|_| "real owner command channel closed")?;
    let result = owner_reply
        .recv_timeout(end.saturating_duration_since(Instant::now()))
        .map_err(|_| "real owner reply did not arrive within proxy bound")?;
    let owner_timeout = match &result {
        Err(LaunchError::Timeout(label)) => Some(*label),
        _ => None,
    };
    let owner_invalid = match &result {
        Err(LaunchError::Invalid(label)) => Some(*label),
        _ => None,
    };
    if matches!(delay, Delay::Reply) {
        release
            .recv_timeout(end.saturating_duration_since(Instant::now()))
            .map_err(|_| "reply gate did not receive its bounded release")?;
    }
    let delivered = command.reply.send(result).is_ok();
    Ok(ProxyReport {
        owner_timeout,
        owner_invalid,
        dispatched_expired,
        delivered,
    })
}

impl Proxy {
    fn install(session: &mut DynamicSession, delay: Delay) -> Self {
        let (sender, input) = channel();
        let real = std::mem::replace(&mut session.commands, sender);
        let (release, released) = channel();
        let (finished, done) = channel();
        let worker = std::thread::spawn(move || {
            let result = proxy_once(input, real, released, delay);
            let _ = finished.send(result);
        });
        Self {
            release,
            done,
            worker: Some(worker),
        }
    }

    fn join_bounded(&mut self) -> Result<(), &'static str> {
        let end = Instant::now() + TIMEOUT;
        while !self
            .worker
            .as_ref()
            .is_none_or(|worker| worker.is_finished())
        {
            if Instant::now() >= end {
                return Err("proxy thread did not finish within its bound");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| "proxy thread unwound")?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<ProxyReport, &'static str> {
        let _ = self.release.send(());
        let result = self
            .done
            .recv_timeout(TIMEOUT)
            .map_err(|_| "proxy completion receipt did not arrive");
        self.join_bounded()?;
        result?
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.release.send(());
        let _ = self.join_bounded();
    }
}

#[test]
fn deadline_pairs_share_one_start_and_retain_exact_default_equality() {
    let before = Instant::now();
    let (event, response) = command_deadlines(EVENT_TIMEOUT, TIMEOUT).unwrap();
    let after = Instant::now();
    assert!(event >= before + EVENT_TIMEOUT && event <= after + EVENT_TIMEOUT);
    assert_eq!(response.duration_since(event), TIMEOUT - EVENT_TIMEOUT);
    let (event, response) = command_deadlines(EVENT_TIMEOUT, EVENT_TIMEOUT).unwrap();
    assert_eq!(event, response);
    let (event, response) = command_deadlines(MAX_LAUNCH_TIMEOUT, MAX_LAUNCH_TIMEOUT).unwrap();
    assert_eq!(event, response);
}

#[test]
fn invalid_budgets_precede_queueing_and_preserve_both_native_held_states() {
    let fixture = Fixture::new(ordinary(&[0xeb, 0xfe]));
    let mut pair = Pair::new(&fixture);
    let parent = pair.parent.clone();
    let worker = pair.worker.clone();
    let parent_before = pair.frame(&parent);
    let worker_before = pair.frame(&worker);
    let registry = pair.session().lifecycle_snapshot().unwrap();
    // A disconnected queue would report a different error if submission were
    // attempted. No artificial queue can reach or mutate the actual owner.
    let (closed, receiver) = channel();
    drop(receiver);
    let real = std::mem::replace(&mut pair.session().commands, closed);
    let over = MAX_LAUNCH_TIMEOUT + Duration::from_nanos(1);
    let mut results = Vec::new();
    for (event, response) in [
        (Duration::ZERO, TIMEOUT),
        (EVENT_TIMEOUT, Duration::ZERO),
        (Duration::ZERO, Duration::ZERO),
        (over, over),
        (EVENT_TIMEOUT, over),
        (over, MAX_LAUNCH_TIMEOUT),
        (TIMEOUT, EVENT_TIMEOUT),
    ] {
        results.push(
            pair.session()
                .next_event_with_response_timeout(event, response),
        );
    }
    pair.session().commands = real;
    let cancelled = pair.session().cancel.load(Ordering::Acquire);
    let parent_after = pair.frame(&parent);
    let worker_after = pair.frame(&worker);
    let registry_after = pair.session().lifecycle_snapshot().unwrap();
    pair.finish();
    assert!(!cancelled);
    assert_eq!(parent_after, parent_before);
    assert_eq!(worker_after, worker_before);
    assert_eq!(registry_after, registry);
    for (index, result) in results.into_iter().enumerate() {
        let expected = if index == 6 {
            "response timeout must not precede event timeout"
        } else {
            "operation timeout must be in (0, 30 seconds]"
        };
        assert!(matches!(result, Err(LaunchError::Invalid(reason)) if reason == expected));
    }
}

#[test]
fn actual_owner_expiry_on_two_spinners_retains_the_native_event_timeout() {
    let fixture = Fixture::new(ordinary(&[0xeb, 0xfe]));
    let mut h = Harness::new();
    let entry = h.entry(&fixture, libc::SYS_clone as u64);
    let (created, born) = h.created(&entry);
    let parent = h.parent_exit(&created, &born);
    h.resume(&parent);
    h.resume(&born);
    let start = Instant::now();
    let result = h.owner().execute(Request::Wait, start + EVENT_TIMEOUT);
    let elapsed = start.elapsed();
    let closing = h.owner().closing;
    h.finish(&[parent.tid, born.tid]);
    assert!(matches!(
        result,
        Err(LaunchError::Timeout("native lifecycle event"))
    ));
    assert!(elapsed >= EVENT_TIMEOUT && elapsed < TIMEOUT);
    assert!(closing);
}

#[test]
fn separate_response_budget_delivers_native_expiry_without_extending_event_wait() {
    let fixture = Fixture::new(ordinary(&[0xeb, 0xfe]));
    let mut pair = Pair::new(&fixture);
    pair.spin();
    let start = Instant::now();
    let result = pair
        .session()
        .next_event_with_response_timeout(EVENT_TIMEOUT, TIMEOUT);
    let elapsed = start.elapsed();
    let closing = pair.session().next_event(TIMEOUT);
    pair.finish();
    assert!(matches!(
        result,
        Err(LaunchError::Timeout("native lifecycle event"))
    ));
    assert!(elapsed >= EVENT_TIMEOUT && elapsed < TIMEOUT);
    assert!(matches!(
        closing,
        Err(LaunchError::Invalid("dynamic session is closing"))
    ));
}

#[test]
fn default_response_deadline_still_expires_when_the_real_reply_is_withheld() {
    let fixture = Fixture::new(ordinary(&[0xeb, 0xfe]));
    let mut pair = Pair::new(&fixture);
    // Both tasks remain held: the real owner immediately rejects Wait. This
    // isolates delayed reply delivery from the separate native-expiry proof.
    let proxy = Proxy::install(pair.session(), Delay::Reply);
    let start = Instant::now();
    let result = pair.session().next_event(EVENT_TIMEOUT);
    let elapsed = start.elapsed();
    let report = proxy.finish();
    let closing = pair.session().next_event(TIMEOUT);
    pair.finish();
    assert!(matches!(
        result,
        Err(LaunchError::Timeout("dynamic tracer response"))
    ));
    assert!(elapsed >= EVENT_TIMEOUT && elapsed < TIMEOUT);
    let report = report.unwrap();
    assert!(!report.dispatched_expired);
    assert_eq!(report.owner_timeout, None);
    assert_eq!(
        report.owner_invalid,
        Some("dynamic wait requires a released task")
    );
    assert!(!report.delivered);
    assert!(matches!(
        closing,
        Err(LaunchError::Invalid("dynamic session is closing"))
    ));
}

#[test]
fn delayed_dispatch_does_not_restart_or_relabel_the_original_command_deadline() {
    let fixture = Fixture::new(ordinary(&[0xeb, 0xfe]));
    let mut pair = Pair::new(&fixture);
    pair.spin();
    let proxy = Proxy::install(pair.session(), Delay::Dispatch);
    let start = Instant::now();
    let result = pair
        .session()
        .next_event_with_response_timeout(EVENT_TIMEOUT, TIMEOUT);
    let elapsed = start.elapsed();
    let report = proxy.finish();
    let closing = pair.session().next_event(TIMEOUT);
    pair.finish();
    assert!(matches!(
        result,
        Err(LaunchError::Timeout("dynamic command"))
    ));
    assert!(elapsed >= EVENT_TIMEOUT && elapsed < TIMEOUT);
    let report = report.unwrap();
    assert!(report.dispatched_expired);
    assert_eq!(report.owner_timeout, Some("dynamic command"));
    assert_eq!(report.owner_invalid, None);
    assert!(report.delivered);
    assert!(matches!(
        closing,
        Err(LaunchError::Invalid("dynamic session is closing"))
    ));
}
