//! These tests reorder two actual, already-owned stopped kernel statuses. They
//! force decoder observation order, not kernel scheduling, and never synthesize
//! a PID, wait status, syscall result, or physical-reaping witness.
use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

const TIMEOUT: Duration = Duration::from_secs(3);
const CODE: &[u8] = &[0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0xeb, 0xfe];
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let _file = crate::TEST_FILE_FORK.lock().unwrap();
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-fork-private-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("original");
        let mut bytes = vec![0; 8192];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
            bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (at, value) in [(20, 1_u32), (64, 1), (68, 5)] {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (at, value) in [
            (24, 0x401000_u64),
            (32, 64),
            (80, 0x400000),
            (96, 8192),
            (104, 8192),
            (112, 4096),
        ] {
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[4096..4096 + CODE.len()].copy_from_slice(CODE);
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
        let mut owner = Owner::new(0, Arc::new(AtomicBool::new(false)));
        owner.lifecycle_options = Some(DynamicLifecycleOptions::fork_only());
        Self {
            owner: Some(owner),
            mask: Some(launch::BlockedSignals::new().unwrap()),
        }
    }
    fn owner(&mut self) -> &mut Owner {
        self.owner.as_mut().unwrap()
    }
    fn launch(&mut self, fixture: &Fixture) -> DynamicEvent {
        let inherited = self.mask.as_ref().unwrap().original();
        let _file = crate::TEST_FILE_FORK.lock().unwrap();
        launch::start(
            self.owner(),
            &LaunchCommand::new(&fixture.path),
            inherited,
            Instant::now() + TIMEOUT,
        )
        .unwrap()
        .event
    }
    #[track_caller]
    fn request(&mut self, request: Request) -> Response {
        self.owner()
            .execute(request, Instant::now() + TIMEOUT)
            .unwrap()
    }
    #[track_caller]
    fn next(&mut self) -> DynamicEvent {
        let Response::Event(event) = self.request(Request::Wait) else {
            panic!("event response")
        };
        event
    }
    fn resume(&mut self, event: &DynamicEvent) {
        assert!(matches!(
            self.request(Request::Resume(
                event.stop_token().unwrap().clone(),
                DynamicResume::Continue
            )),
            Response::Unit
        ));
    }
    fn entry(&mut self, fixture: &Fixture) -> DynamicEvent {
        let exec = self.launch(fixture);
        self.resume(&exec);
        let exit = self.next();
        assert_eq!(
            exit.kind,
            DynamicEventKind::SyscallExit {
                result: 0,
                is_error: false
            }
        );
        self.resume(&exit);
        let entry = self.next();
        assert!(matches!(
            entry.kind,
            DynamicEventKind::SyscallEntry { number: 57, .. }
        ));
        entry
    }
    fn finish(mut self, expected: &[i32]) {
        let mut actual = self.owner().cleanup().unwrap().reaped;
        let mut expected = expected.to_vec();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
        for handle in self.owner().handles.values() {
            assert!(broker::hup(handle));
        }
        self.owner.take();
        self.mask.take().unwrap().restore().unwrap();
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(owner) = &mut self.owner {
            let _ = owner.cleanup();
        }
    }
}
struct Stops {
    parent: (i32, i32),
    child: (i32, i32),
}
fn collect(harness: &mut Harness, entry: &DynamicEvent) -> Stops {
    harness.resume(entry);
    let until = Instant::now() + TIMEOUT;
    let mut parent = None;
    let mut child = None;
    while parent.is_none() || child.is_none() {
        let (tid, status) = harness
            .owner()
            .wait_raw(until, "collect actual fork stops")
            .unwrap();
        assert!(libc::WIFSTOPPED(status));
        if tid == entry.tid {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_FORK);
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            assert!(parent.replace((tid, status)).is_none());
        } else {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_STOP);
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            assert!(child.replace((tid, status)).is_none());
        }
    }
    let parent = parent.unwrap();
    let child = child.unwrap();
    let mut payload = 0_u64;
    ptrace(
        libc::PTRACE_GETEVENTMSG,
        parent.0,
        0,
        (&raw mut payload) as usize,
    )
    .unwrap();
    assert_eq!(payload, child.0 as u64);
    for tid in [parent.0, child.0] {
        assert!(harness.owner().owned.contains(&tid));
        assert!(harness.owner().stopped.contains_key(&tid));
        assert!(harness.owner().handles.contains_key(&tid));
        assert_eq!(read_memory(tid, 0x401000, CODE.len()).unwrap(), CODE);
    }
    Stops { parent, child }
}
fn force_order(child_first: bool) {
    let fixture = Fixture::new();
    let mut harness = Harness::new();
    let entry = harness.entry(&fixture);
    let before = read_registers(entry.tid).unwrap();
    let extended = xstate(entry.tid).unwrap();
    let mask = launch::task_mask(entry.tid).unwrap();
    let stops = collect(&mut harness, &entry);
    let mut lifecycle = harness.owner().lifecycle.take().unwrap();
    if !child_first {
        // A real request races the already-held, not-yet-interpreted FORK
        // status. This is source-driven observation order, not a claimed
        // kernel scheduler order. Record exactly the production request bound.
        ptrace(libc::PTRACE_INTERRUPT, entry.tid, 0, 0).unwrap();
        lifecycle
            .tasks
            .get_mut(&entry.tid)
            .unwrap()
            .interrupt_stops_remaining = 2;
    }
    let (first, second) = if child_first {
        (stops.child, stops.parent)
    } else {
        (stops.parent, stops.child)
    };
    assert!(
        lifecycle
            .observe(harness.owner(), first.0, first.1)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        lifecycle.registry.snapshot().tasks().count(),
        1,
        "one half of creation cannot mint a task"
    );
    let created = lifecycle
        .observe(harness.owner(), second.0, second.1)
        .unwrap()
        .unwrap();
    let DynamicEventKind::Created { child } = created.kind else {
        panic!("creation event")
    };
    assert_ne!(created.task.unwrap().address_space, child.address_space);
    let newborn = lifecycle.events.pop_front().unwrap();
    assert_eq!(newborn.task, Some(child));
    assert!(lifecycle.events.is_empty());
    if !child_first {
        assert_eq!(
            lifecycle.tasks[&entry.tid].interrupt_stops_remaining, 1,
            "actual FORK observation must consume an interrupt credit"
        );
    }
    let mut forged = newborn.stop_token().unwrap().clone();
    forged.tid = created.tid;
    forged.sequence = created.stop_token().unwrap().sequence;
    assert!(
        lifecycle.require_stop(&forged).is_err(),
        "sibling identity cannot be substituted"
    );
    assert_eq!(read_registers(entry.tid).unwrap(), before);
    assert_eq!(xstate(entry.tid).unwrap(), extended);
    let mut expected = before;
    expected.rax = 0;
    assert_eq!(read_registers(stops.child.0).unwrap(), expected);
    assert_eq!(xstate(stops.child.0).unwrap(), extended);
    assert_eq!(launch::task_mask(stops.child.0).unwrap(), mask);
    for task in lifecycle.tasks.values() {
        assert!(matches!(task.state, State::Held(_)));
    }
    harness.owner().lifecycle = Some(lifecycle);
    harness.resume(&created);
    let mut returned = harness.next();
    if !child_first {
        assert_eq!(returned.tid, entry.tid);
        assert_eq!(
            harness.owner().lifecycle.as_ref().unwrap().tasks[&entry.tid].interrupt_stops_remaining,
            0,
            "the next actual parent stop consumes the second credit"
        );
        if returned.kind == DynamicEventKind::Interrupted {
            harness.resume(&returned);
            returned = harness.next();
        }
    }
    assert_eq!(
        returned.kind,
        DynamicEventKind::SyscallExit {
            result: i64::from(stops.child.0),
            is_error: false
        }
    );
    expected = before;
    expected.rax = stops.child.0 as u64;
    assert_eq!(read_registers(entry.tid).unwrap(), expected);
    harness.resume(&newborn);
    let returned = harness.next();
    assert_eq!(
        returned.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false
        }
    );
    expected = before;
    expected.rax = 0;
    assert_eq!(read_registers(stops.child.0).unwrap(), expected);
    harness.finish(&[stops.parent.0, stops.child.0]);
}
#[test]
fn actual_parent_then_newborn_observation_pairs_both_held_incarnations() {
    force_order(false);
}
#[test]
fn actual_newborn_then_parent_observation_pairs_both_held_incarnations() {
    force_order(true);
}
#[test]
fn fork_tf_refusal_precedes_kernel_entry_and_keeps_original_source() {
    let fixture = Fixture::new();
    let mut harness = Harness::new();
    let entry = harness.entry(&fixture);
    let mut registers = read_registers(entry.tid).unwrap();
    registers.eflags |= 0x100;
    set_registers(entry.tid, &registers).unwrap();
    let result = harness.owner().execute(
        Request::Resume(entry.stop_token().unwrap().clone(), DynamicResume::Continue),
        Instant::now() + TIMEOUT,
    );
    assert!(matches!(
        result,
        Err(LaunchError::Invalid("fork entry did not authenticate"))
    ));
    assert!(harness.owner().closing);
    assert_eq!(harness.owner().owned.len(), 1);
    assert_eq!(read_registers(entry.tid).unwrap(), registers);
    assert_eq!(read_memory(entry.tid, 0x401000, CODE.len()).unwrap(), CODE);
    harness.finish(&[entry.tid]);
}
#[test]
fn late_fork_payload_cannot_reacquire_a_consumed_terminal_incarnation() {
    let fixture = Fixture::new();
    let mut harness = Harness::new();
    let entry = harness.entry(&fixture);
    let stops = collect(&mut harness, &entry);
    let child = stops.child.0;
    let handle = &harness.owner().handles[&child];
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                handle.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
    let _ = ptrace(libc::PTRACE_CONT, child, 0, 0);
    let until = Instant::now() + TIMEOUT;
    loop {
        let (tid, status) = harness
            .owner()
            .wait_raw(until, "actual child terminal before fork payload")
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
    assert!(!harness.owner().owned.contains(&child));
    let mut lifecycle = harness.owner().lifecycle.take().unwrap();
    let result = lifecycle.observe(harness.owner(), stops.parent.0, stops.parent.1);
    assert!(matches!(
        result,
        Err(LaunchError::Invalid(
            "fork payload names a retired incarnation"
        ))
    ));
    assert!(!harness.owner().owned.contains(&child));
    assert_eq!(lifecycle.registry.snapshot().tasks().count(), 1);
    harness.owner().lifecycle = Some(lifecycle);
    harness.finish(&[stops.parent.0, child]);
}
#[test]
fn targeted_interrupt_retains_queued_sibling_and_counts_actual_stops() {
    let fixture = Fixture::new();
    let mut harness = Harness::new();
    let entry = harness.entry(&fixture);
    harness.resume(&entry);
    let created = harness.next();
    assert!(matches!(created.kind, DynamicEventKind::Created { .. }));
    // Newborn is deliberately still queued. Releasing the parent and asking
    // for its interruption must not return this unrelated child event.
    harness.resume(&created);
    let id = created.task.unwrap().task;
    let Response::Event(target) = harness.request(Request::InterruptTask(id)) else {
        panic!("event response")
    };
    assert_eq!(target.task, created.task);
    let remaining =
        harness.owner().lifecycle.as_ref().unwrap().tasks[&entry.tid].interrupt_stops_remaining;
    assert_eq!(
        remaining, 1,
        "one consumed stop uses exactly one conservative credit"
    );
    let newborn = harness.next();
    assert!(matches!(newborn.kind, DynamicEventKind::Newborn { .. }));
    assert_ne!(newborn.task, created.task);
    harness.resume(&target);
    // The conservative bound permits the request to have cleared on the first
    // stop. Force an additional real observation without resetting its stored
    // credit, rather than assuming a second deferred stop always occurs.
    ptrace(libc::PTRACE_INTERRUPT, entry.tid, 0, 0).unwrap();
    let next = harness.next();
    assert_eq!(next.task, created.task);
    assert_eq!(
        harness.owner().lifecycle.as_ref().unwrap().tasks[&entry.tid].interrupt_stops_remaining,
        0
    );
    harness.finish(&[entry.tid, newborn.tid]);
}
