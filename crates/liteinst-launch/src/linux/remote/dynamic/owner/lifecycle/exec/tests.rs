//! Source-driven ordering of real kernel stops; no synthetic EXEC/status/PID.
use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

const TIMEOUT: Duration = Duration::from_secs(3);
const ENTRY: u64 = 0x401000;
const PATH_ADDRESS: u64 = 0x401800;
const SPIN: &[u8] = &[0xeb, 0xfe];
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    code: Vec<u8>,
}
impl Fixture {
    fn new(missing: bool) -> Self {
        let _file = crate::TEST_FILE_FORK.lock().unwrap();
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-exec-private-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.join(if missing { "absent" } else { "replacement" });
        if !missing {
            write_image(&target, SPIN, &[]);
        }
        let mut code = vec![0xb8, 59, 0, 0, 0, 0x48, 0xbf];
        code.extend_from_slice(&PATH_ADDRESS.to_le_bytes());
        // Native execve(path, NULL, NULL), followed by original UD2 on error.
        code.extend_from_slice(&[0x31, 0xf6, 0x31, 0xd2, 0x0f, 0x05, 0x0f, 0x0b]);
        let mut path_bytes = target.as_os_str().as_bytes().to_vec();
        path_bytes.push(0);
        let path = directory.join("original");
        write_image(&path, &code, &path_bytes);
        Self {
            directory,
            path,
            code,
        }
    }
}
fn write_image(path: &Path, code: &[u8], path_bytes: &[u8]) {
    let mut bytes = vec![0; 8192];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [(20, 1_u32), (64, 1), (68, 5)] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [
        (24, ENTRY),
        (32, 64),
        (80, 0x400000),
        (96, 8192),
        (104, 8192),
        (112, 4096),
    ] {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    assert!(code.len() < 2048 && path_bytes.len() < 2048);
    bytes[4096..4096 + code.len()].copy_from_slice(code);
    bytes[6144..6144 + path_bytes.len()].copy_from_slice(path_bytes);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
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
        owner.lifecycle_options = Some(DynamicLifecycleOptions::default());
        owner.exec_policy = DynamicExecPolicy::ExecveOnce;
        Self {
            owner: Some(owner),
            mask: Some(launch::BlockedSignals::new().unwrap()),
        }
    }
    fn owner(&mut self) -> &mut Owner {
        self.owner.as_mut().unwrap()
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
        let inherited = self.mask.as_ref().unwrap().original();
        let event = {
            let _file = crate::TEST_FILE_FORK.lock().unwrap();
            launch::start(
                self.owner(),
                &LaunchCommand::new(&fixture.path),
                inherited,
                Instant::now() + TIMEOUT,
            )
            .unwrap()
            .event
        };
        self.resume(&event);
        let initial_exit = self.next();
        assert_eq!(
            initial_exit.kind,
            DynamicEventKind::SyscallExit {
                result: 0,
                is_error: false
            }
        );
        self.resume(&initial_exit);
        let entry = self.next();
        assert!(matches!(
            entry.kind,
            DynamicEventKind::SyscallEntry { number: 59, .. }
        ));
        assert_eq!(
            read_memory(entry.tid, ENTRY, fixture.code.len()).unwrap(),
            fixture.code
        );
        entry
    }
    fn replacement(&mut self, entry: &DynamicEvent) -> DynamicEvent {
        self.resume(entry);
        let event = self.next();
        assert!(
            matches!(&event.kind, DynamicEventKind::ExecReplaced { previous, .. } if Some(*previous) == entry.task)
        );
        event
    }
    fn exit(&mut self, event: &DynamicEvent) -> DynamicEvent {
        let mut expected = read_registers(event.tid).unwrap();
        assert_eq!(expected.rax, (-i64::from(libc::ENOSYS)) as u64);
        self.resume(event);
        let exit = self.next();
        assert_eq!(exit.task, event.task);
        assert_eq!(
            exit.kind,
            DynamicEventKind::SyscallExit {
                result: 0,
                is_error: false
            }
        );
        expected.rax = 0;
        assert_eq!(read_registers(exit.tid).unwrap(), expected);
        exit
    }
    fn finish(mut self, pid: i32) {
        assert_eq!(self.owner().cleanup().unwrap().reaped, vec![pid]);
        assert!(self.owner().owned.is_empty());
        assert!(self.owner().handles.values().all(broker::hup));
        let helper = self.owner().broker.as_ref().unwrap().pid;
        for tid in [pid, helper] {
            let mut status = 0;
            assert_eq!(
                unsafe {
                    libc::waitpid(
                        tid,
                        &raw mut status,
                        libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                    )
                },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
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

#[test]
fn actual_exec_queued_before_interrupt_returns_replacement_and_consumes_credits() {
    let fixture = Fixture::new(false);
    let mut h = Harness::new();
    let entry = h.entry(&fixture);
    let old = entry.task.unwrap();
    let app_fd = h.owner().handles[&entry.tid].as_raw_fd();
    let helper = h.owner().broker.as_ref().unwrap().pid;
    let mask = launch::task_mask(entry.tid).unwrap();
    h.resume(&entry);
    // Peek without consuming or altering the kernel's real held EXEC status.
    // The production targeted-interrupt path still owns the subsequent wait.
    let until = Instant::now() + TIMEOUT;
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    entry.tid as u32,
                    &raw mut info,
                    libc::WSTOPPED
                        | libc::WNOHANG
                        | libc::WNOWAIT
                        | libc::__WALL
                        | libc::__WNOTHREAD,
                )
            },
            0
        );
        if unsafe { info.si_pid() } != 0 {
            assert_eq!(unsafe { info.si_pid() }, entry.tid);
            assert_eq!(info.si_code, libc::CLD_TRAPPED);
            assert_eq!(
                unsafe { info.si_status() },
                (libc::PTRACE_EVENT_EXEC << 8) | libc::SIGTRAP
            );
            break;
        }
        assert!(Instant::now() < until, "actual queued EXEC deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
    let Response::Event(event) = h.request(Request::InterruptTask(old.task)) else {
        panic!("replacement response")
    };
    assert!(
        matches!(&event.kind, DynamicEventKind::ExecReplaced { previous, .. } if *previous == old)
    );
    let new = event.task.unwrap();
    assert_ne!(new.task, old.task);
    assert_ne!(new.address_space, old.address_space);
    assert_eq!(new.process, old.process);
    assert_eq!(h.owner().handles[&entry.tid].as_raw_fd(), app_fd);
    assert_eq!(h.owner().broker.as_ref().unwrap().pid, helper);
    assert!(h.owner().reaped.is_empty());
    assert!(h.owner().tracer_terminal.is_empty());
    assert_eq!(h.owner().owned, BTreeSet::from([entry.tid]));
    assert!(!broker::hup(&h.owner().handles[&entry.tid]));
    assert_eq!(
        h.owner().lifecycle.as_ref().unwrap().tasks[&entry.tid].interrupt_stops_remaining,
        1
    );
    let old_token = entry.stop_token().unwrap().clone();
    assert!(
        h.owner()
            .execute(
                Request::Registers(old_token.clone()),
                Instant::now() + TIMEOUT
            )
            .is_err()
    );
    assert!(
        h.owner()
            .execute(
                Request::Resume(old_token, DynamicResume::Continue),
                Instant::now() + TIMEOUT
            )
            .is_err()
    );
    assert!(!h.owner().closing);
    let event_registers = read_registers(entry.tid).unwrap();
    assert_eq!(event_registers.rax, (-i64::from(libc::ENOSYS)) as u64);
    assert_eq!(launch::task_mask(entry.tid).unwrap(), mask);
    assert_eq!(read_memory(entry.tid, ENTRY, SPIN.len()).unwrap(), SPIN);
    h.resume(&event);
    let mut next = h.next();
    assert_eq!(next.task, Some(new));
    assert_eq!(
        h.owner().lifecycle.as_ref().unwrap().tasks[&entry.tid].interrupt_stops_remaining,
        0
    );
    if next.kind == DynamicEventKind::Interrupted {
        assert_eq!(read_registers(entry.tid).unwrap(), event_registers);
        h.resume(&next);
        next = h.next();
    }
    assert_eq!(
        next.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false
        }
    );
    let mut expected = event_registers;
    expected.rax = 0;
    assert_eq!(read_registers(entry.tid).unwrap(), expected);
    assert_eq!(launch::task_mask(entry.tid).unwrap(), mask);
    h.resume(&next);
    let Response::Event(interrupted) = h.request(Request::Interrupt) else {
        panic!("current root interruption")
    };
    assert_eq!(interrupted.task, Some(new));
    assert_eq!(interrupted.kind, DynamicEventKind::Interrupted);
    let registers = read_registers(entry.tid).unwrap();
    let extended = xstate(entry.tid).unwrap();
    assert_eq!(read_registers(entry.tid).unwrap(), registers);
    assert_eq!(xstate(entry.tid).unwrap(), extended);
    assert_eq!(read_memory(entry.tid, ENTRY, SPIN.len()).unwrap(), SPIN);
    h.finish(entry.tid);
}

#[test]
fn explicit_cleanup_at_exec_entry_event_and_exit_physically_reaps_one_incarnation() {
    for phase in 0..3 {
        let fixture = Fixture::new(false);
        let mut h = Harness::new();
        let entry = h.entry(&fixture);
        let held = if phase == 0 {
            entry.clone()
        } else {
            let event = h.replacement(&entry);
            if phase == 1 { event } else { h.exit(&event) }
        };
        let before = read_registers(entry.tid).unwrap();
        let extended = xstate(entry.tid).unwrap();
        assert!(held.stop_token().is_some());
        assert_eq!(read_registers(entry.tid).unwrap(), before);
        assert_eq!(xstate(entry.tid).unwrap(), extended);
        let source = if phase == 0 { &fixture.code[..] } else { SPIN };
        assert_eq!(read_memory(entry.tid, ENTRY, source.len()).unwrap(), source);
        h.owner().cancel.store(true, Ordering::Release);
        h.finish(entry.tid);
    }
}

#[test]
fn failed_exec_exit_closes_without_inventing_old_mm_continuity() {
    let fixture = Fixture::new(true);
    let mut h = Harness::new();
    let entry = h.entry(&fixture);
    let mut expected = read_registers(entry.tid).unwrap();
    let extended = xstate(entry.tid).unwrap();
    h.resume(&entry);
    let running = h.owner().lifecycle.as_ref().unwrap().registry.snapshot();
    let result = h.owner().execute(Request::Wait, Instant::now() + TIMEOUT);
    assert!(matches!(
        result,
        Err(LaunchError::Invalid(
            "native exec failure has no proved old-mm continuity"
        ))
    ));
    assert!(h.owner().closing);
    assert_eq!(
        h.owner().lifecycle.as_ref().unwrap().registry.snapshot(),
        running
    );
    assert_eq!(h.owner().lifecycle.as_ref().unwrap().exec_successes, 0);
    expected.rax = (-i64::from(libc::ENOENT)) as u64;
    assert_eq!(read_registers(entry.tid).unwrap(), expected);
    assert_eq!(xstate(entry.tid).unwrap(), extended);
    assert_eq!(
        read_memory(entry.tid, ENTRY, fixture.code.len()).unwrap(),
        fixture.code
    );
    h.finish(entry.tid);
}

#[test]
fn native_exec_tf_refusal_precedes_kernel_entry_and_keeps_image() {
    let fixture = Fixture::new(false);
    let mut h = Harness::new();
    let entry = h.entry(&fixture);
    let mut registers = read_registers(entry.tid).unwrap();
    registers.eflags |= 0x100;
    set_registers(entry.tid, &registers).unwrap();
    let before = h.owner().lifecycle.as_ref().unwrap().registry.snapshot();
    let result = h.owner().execute(
        Request::Resume(entry.stop_token().unwrap().clone(), DynamicResume::Continue),
        Instant::now() + TIMEOUT,
    );
    assert!(matches!(
        result,
        Err(LaunchError::Invalid(
            "native exec entry did not authenticate"
        ))
    ));
    assert!(h.owner().closing);
    assert_eq!(
        h.owner().lifecycle.as_ref().unwrap().registry.snapshot(),
        before
    );
    assert_eq!(read_registers(entry.tid).unwrap(), registers);
    assert_eq!(
        read_memory(entry.tid, ENTRY, fixture.code.len()).unwrap(),
        fixture.code
    );
    h.finish(entry.tid);
}

// These private observations precede serve()'s required cleanup after a policy
// error. Public clients receive the refusal and physical-cleanup receipt, not a
// post-close inspection capability.
#[derive(Debug, Eq, PartialEq)]
struct HeldEvidence {
    registers: RegisterSnapshot,
    extended: Vec<u8>,
    mask: u64,
    stack: Vec<u8>,
    image: Vec<u8>,
    registry: Option<crate::lifecycle::RegistrySnapshot>,
}
fn held_evidence(h: &mut Harness, tid: i32) -> HeldEvidence {
    let registers = read_registers(tid).unwrap();
    HeldEvidence {
        registers,
        extended: xstate(tid).unwrap(),
        mask: launch::task_mask(tid).unwrap(),
        stack: read_memory(tid, registers.rsp, 32).unwrap(),
        image: read_memory(tid, 0x400000, 8192).unwrap(),
        registry: h.owner().lifecycle.as_ref().map(|l| l.registry.snapshot()),
    }
}
fn mov_literal(code: &mut Vec<u8>, reg: u8, value: u64) {
    code.extend_from_slice(&[if reg < 8 { 0x48 } else { 0x49 }, 0xb8 + (reg & 7)]);
    code.extend_from_slice(&value.to_le_bytes());
}
fn seeded_prefix() -> Vec<u8> {
    let mut code = vec![0x48, 0x83, 0xec, 64]; // Private original stack area.
    for offset in [0_u8, 8, 16, 24] {
        code.extend_from_slice(&[0x48, 0xc7, 0x44, 0x24, offset]);
        code.extend_from_slice(&(0x12345600_u32 + u32::from(offset)).to_le_bytes());
    }
    code.extend_from_slice(&[0xdb, 0xe3, 0xd9, 0xe8, 0x66, 0x0f, 0x76, 0xc9]);
    for reg in 0_u8..16 {
        if reg != 4 {
            mov_literal(&mut code, reg, 0x1234567890000000 + u64::from(reg));
        }
    }
    code.push(0x68);
    code.extend_from_slice(&0xed7_u32.to_le_bytes());
    code.push(0x9d);
    code
}
fn seeded_exec(number: i64) -> Vec<u8> {
    let mut code = seeded_prefix();
    if number == libc::SYS_execve {
        mov_literal(&mut code, 7, PATH_ADDRESS);
        mov_literal(&mut code, 6, 0);
        mov_literal(&mut code, 2, 0);
    } else {
        assert_eq!(number, libc::SYS_execveat);
        mov_literal(&mut code, 7, libc::AT_FDCWD as u64);
        mov_literal(&mut code, 6, PATH_ADDRESS);
        mov_literal(&mut code, 2, 0);
        mov_literal(&mut code, 10, 0);
        mov_literal(&mut code, 8, 0);
    }
    mov_literal(&mut code, 0, number as u64);
    code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    code
}
fn refusal_fixture(number: i64, replacement: &[u8]) -> Fixture {
    let mut fixture = Fixture::new(true);
    let _file = crate::TEST_FILE_FORK.lock().unwrap();
    let target = fixture.directory.join("absent");
    let mut path_bytes = target.as_os_str().as_bytes().to_vec();
    path_bytes.push(0);
    // Both targets really exist. Refusal evidence cannot be mistaken for an
    // attempted exec which merely failed to resolve the requested filename.
    write_image(&target, replacement, &path_bytes);
    fixture.path = fixture.directory.join("seeded-original");
    fixture.code = seeded_exec(number);
    write_image(&fixture.path, &fixture.code, &path_bytes);
    fixture
}
fn first_entry(h: &mut Harness, fixture: &Fixture, number: i64) -> DynamicEvent {
    let inherited = h.mask.as_ref().unwrap().original();
    let event = {
        let _file = crate::TEST_FILE_FORK.lock().unwrap();
        launch::start(
            h.owner(),
            &LaunchCommand::new(&fixture.path),
            inherited,
            Instant::now() + TIMEOUT,
        )
        .unwrap()
        .event
    };
    h.resume(&event);
    let boot_exit = h.next();
    assert_eq!(
        boot_exit.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false,
        }
    );
    h.resume(&boot_exit);
    let entry = h.next();
    assert!(
        matches!(entry.kind, DynamicEventKind::SyscallEntry { number: actual, .. } if actual == number as u64)
    );
    assert_eq!(
        read_memory(entry.tid, ENTRY, fixture.code.len()).unwrap(),
        fixture.code
    );
    entry
}
fn refusal_unchanged(h: &mut Harness, entry: &DynamicEvent, message: &'static str) {
    let before = held_evidence(h, entry.tid);
    assert_eq!(before.registers.rax, (-i64::from(libc::ENOSYS)) as u64);
    let result = h.owner().execute(
        Request::Resume(entry.stop_token().unwrap().clone(), DynamicResume::Continue),
        Instant::now() + TIMEOUT,
    );
    assert!(matches!(result, Err(LaunchError::Invalid(actual)) if actual == message));
    assert!(h.owner().closing);
    assert_eq!(held_evidence(h, entry.tid), before);
    assert!(h.owner().stopped.contains_key(&entry.tid));
    assert!(!broker::hup(&h.owner().handles[&entry.tid]));
}
fn finish_many(mut h: Harness, expected: &[i32]) {
    let mut actual = h.owner().cleanup().unwrap().reaped;
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected);
    assert!(h.owner().owned.is_empty());
    assert!(h.owner().handles.values().all(broker::hup));
    let helper = h.owner().broker.as_ref().unwrap().pid;
    for tid in expected.into_iter().chain([helper]) {
        let mut status = 0;
        assert_eq!(
            unsafe {
                libc::waitpid(
                    tid,
                    &raw mut status,
                    libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
    h.owner.take();
    h.mask.take().unwrap().restore().unwrap();
}

#[test]
fn second_exec_budget_refusal_preserves_full_held_state_before_cleanup() {
    let replacement = seeded_exec(libc::SYS_execve);
    let fixture = refusal_fixture(libc::SYS_execve, &replacement);
    let mut h = Harness::new();
    let first = first_entry(&mut h, &fixture, libc::SYS_execve);
    let replaced = h.replacement(&first);
    let exit = h.exit(&replaced);
    h.resume(&exit);
    let second = h.next();
    assert!(matches!(
        second.kind,
        DynamicEventKind::SyscallEntry { number: 59, .. }
    ));
    assert_eq!(h.owner().lifecycle.as_ref().unwrap().exec_successes, 1);
    assert_eq!(
        read_memory(second.tid, ENTRY, replacement.len()).unwrap(),
        replacement
    );
    refusal_unchanged(&mut h, &second, "native exec success budget exhausted");
    h.finish(second.tid);
}

#[test]
fn default_explicit_refuse_and_execveat_refusals_preserve_full_held_state() {
    for mode in 0..3 {
        let number = if mode == 2 {
            libc::SYS_execveat
        } else {
            libc::SYS_execve
        };
        let fixture = refusal_fixture(number, SPIN);
        let mut h = Harness::new();
        if mode < 2 {
            h.owner().exec_policy = DynamicExecPolicy::Refuse;
        }
        if mode == 0 {
            h.owner().lifecycle_options = None;
        }
        let entry = first_entry(&mut h, &fixture, number);
        assert_eq!(h.owner().lifecycle.is_some(), mode != 0);
        refusal_unchanged(
            &mut h,
            &entry,
            "dynamic creation and later exec are not yet qualified",
        );
        h.finish(entry.tid);
    }
}

#[test]
fn exec_then_second_fork_budget_refusal_preserves_both_held_tasks() {
    let mut replacement = seeded_prefix();
    for _ in 0..2 {
        mov_literal(&mut replacement, 0, libc::SYS_fork as u64);
        replacement.extend_from_slice(&[0x0f, 0x05]);
    }
    replacement.extend_from_slice(&[0x0f, 0x0b]);
    let fixture = refusal_fixture(libc::SYS_execve, &replacement);
    let mut h = Harness::new();
    h.owner().lifecycle_options = Some(DynamicLifecycleOptions {
        creation: DynamicCreationPolicy::Fork,
        max_tasks: 2,
    });
    let first = first_entry(&mut h, &fixture, libc::SYS_execve);
    let replaced = h.replacement(&first);
    let exit = h.exit(&replaced);
    h.resume(&exit);
    let fork = h.next();
    assert!(matches!(
        fork.kind,
        DynamicEventKind::SyscallEntry { number: 57, .. }
    ));
    h.resume(&fork);
    let created = h.next();
    let DynamicEventKind::Created { child } = created.kind else {
        panic!("{created:?}")
    };
    let born = h.next();
    assert_eq!(born.task, Some(child));
    assert_eq!(
        born.kind,
        DynamicEventKind::Newborn {
            parent: fork.task.unwrap()
        }
    );
    let mut expected = read_registers(created.tid).unwrap();
    h.resume(&created);
    let fork_exit = h.next();
    assert_eq!(fork_exit.tid, first.tid);
    assert_eq!(
        fork_exit.kind,
        DynamicEventKind::SyscallExit {
            result: i64::from(born.tid),
            is_error: false
        }
    );
    expected.rax = born.tid as u64;
    assert_eq!(read_registers(fork_exit.tid).unwrap(), expected);
    h.resume(&fork_exit);
    let second = h.next();
    assert!(matches!(
        second.kind,
        DynamicEventKind::SyscallEntry { number: 57, .. }
    ));
    assert_eq!(
        h.owner()
            .lifecycle
            .as_ref()
            .unwrap()
            .registry
            .snapshot()
            .tasks()
            .count(),
        3
    );
    let child_before = held_evidence(&mut h, born.tid);
    refusal_unchanged(&mut h, &second, "dynamic lifetime task bound exhausted");
    assert_eq!(held_evidence(&mut h, born.tid), child_before);
    assert!(h.owner().stopped.contains_key(&born.tid));
    finish_many(h, &[first.tid, born.tid]);
}
