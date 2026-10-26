//! Private native proof of real stop pairing and held-state refusal. Forced
//! observation order uses actual owned kernel statuses, not synthetic events.
use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

const TIMEOUT: Duration = Duration::from_secs(3);
const ENTRY: u64 = 0x401000;
const DATA: u64 = 0x600000;
const PARENT_SP: u64 = 0x601f00;
const CHILD_SP: u64 = 0x603f00;
const FLAGS: u64 = 0xed7;
static NEXT: AtomicU64 = AtomicU64::new(0);

fn literal(code: &mut Vec<u8>, register: u8, value: u64) {
    code.extend_from_slice(&[0x48 | (register >> 3), 0xb8 | (register & 7)]);
    code.extend_from_slice(&value.to_le_bytes());
}
fn flags(code: &mut Vec<u8>) {
    code.push(0x68);
    code.extend_from_slice(&(FLAGS as u32).to_le_bytes());
    code.push(0x9d);
}
fn program(number: i64, args: [u64; 5], suffix: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    for register in 0..16 {
        literal(
            &mut code,
            register,
            0x1234_5678_0000_0000 | u64::from(register),
        );
    }
    literal(&mut code, 4, PARENT_SP);
    // Original x87/SIMD initialization; the checked XSTATE is never normalized.
    code.extend_from_slice(&[0xdb, 0xe3, 0xd9, 0xe8, 0x66, 0x0f, 0x76, 0xc0]);
    for (register, value) in [0, 7, 6, 2, 10, 8].into_iter().zip([
        number as u64,
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
    ]) {
        literal(&mut code, register, value);
    }
    flags(&mut code);
    code.extend_from_slice(&[0x0f, 0x05]);
    code.extend_from_slice(suffix);
    code
}
fn ordinary(suffix: &[u8]) -> Vec<u8> {
    program(libc::SYS_clone, [THREAD_FLAGS, CHILD_SP, 0, 0, 0], suffix)
}
struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    code: Vec<u8>,
}
impl Fixture {
    fn new(code: Vec<u8>) -> Self {
        let _file = crate::TEST_FILE_FORK.lock().unwrap();
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-thread-private-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("original");
        let mut bytes = vec![0; 0x6000];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 2)] {
            bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&ENTRY.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        for (at, offset, address, len, perms) in [
            (64_usize, 0_u64, 0x400000_u64, 0x2000_u64, 5_u32),
            (120, 0x2000, DATA, 0x4000, 6),
        ] {
            bytes[at..at + 4].copy_from_slice(&1_u32.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&perms.to_le_bytes());
            for (slot, value) in [(8, offset), (16, address), (32, len), (40, len), (48, 4096)] {
                bytes[at + slot..at + slot + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        assert!(code.len() < 4096);
        bytes[4096..4096 + code.len()].copy_from_slice(&code);
        for (index, byte) in bytes[0x2000..].iter_mut().enumerate() {
            *byte = (index.wrapping_mul(17).wrapping_add(43) & 0xff) as u8;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);
        Self {
            directory,
            path,
            code,
        }
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
        owner.lifecycle_options = Some(DynamicLifecycleOptions::thread_only());
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
    fn entry(&mut self, fixture: &Fixture, number: u64) -> DynamicEvent {
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
        assert!(
            matches!(entry.kind, DynamicEventKind::SyscallEntry { number: observed, .. } if observed == number)
        );
        assert_eq!(
            read_memory(entry.tid, ENTRY, fixture.code.len()).unwrap(),
            fixture.code
        );
        entry
    }
    fn created(&mut self, entry: &DynamicEvent) -> (DynamicEvent, DynamicEvent) {
        self.resume(entry);
        let created = self.next();
        assert!(matches!(created.kind, DynamicEventKind::Created { .. }));
        let born = self.next();
        assert!(matches!(born.kind, DynamicEventKind::Newborn { .. }));
        assert_eq!(created.task.unwrap().process, born.task.unwrap().process);
        assert_eq!(
            created.task.unwrap().address_space,
            born.task.unwrap().address_space
        );
        (created, born)
    }
    fn parent_exit(&mut self, created: &DynamicEvent, born: &DynamicEvent) -> DynamicEvent {
        let mut expected = read_registers(created.tid).unwrap();
        self.resume(created);
        let exit = self.next();
        assert_eq!(
            exit.kind,
            DynamicEventKind::SyscallExit {
                result: i64::from(born.tid),
                is_error: false
            }
        );
        expected.rax = born.tid as u64;
        assert_eq!(read_registers(created.tid).unwrap(), expected);
        exit
    }
    fn finish(mut self, expected: &[i32]) {
        let mut actual = self.owner().cleanup().unwrap().reaped;
        let mut expected = expected.to_vec();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
        assert!(self.owner().owned.is_empty());
        assert!(self.owner().handles.values().all(broker::hup));
        let helper = self.owner().broker.as_ref().unwrap().pid;
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
                io::Error::last_os_error().raw_os_error(),
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
#[derive(Debug, Eq, PartialEq)]
struct Evidence {
    registers: RegisterSnapshot,
    extended: Vec<u8>,
    mask: u64,
    code: Vec<u8>,
    storage: Vec<u8>,
}
fn evidence(tid: i32) -> Evidence {
    Evidence {
        registers: read_registers(tid).unwrap(),
        extended: xstate(tid).unwrap(),
        mask: launch::task_mask(tid).unwrap(),
        code: read_memory(tid, 0x400000, 0x2000).unwrap(),
        storage: read_memory(tid, DATA, 0x4000).unwrap(),
    }
}
fn refused(h: &mut Harness, event: &DynamicEvent, message: &'static str, other: Option<i32>) {
    let before = evidence(event.tid);
    let sibling = other.map(evidence);
    let registry = h
        .owner()
        .lifecycle
        .as_ref()
        .map(|state| state.registry.snapshot());
    let owned = h.owner().owned.clone();
    let stopped = h.owner().stopped.clone();
    let result = h.owner().execute(
        Request::Resume(event.stop_token().unwrap().clone(), DynamicResume::Continue),
        Instant::now() + TIMEOUT,
    );
    assert!(
        matches!(result, Err(LaunchError::Invalid(value)) if value == message),
        "expected {message}"
    );
    assert!(h.owner().closing);
    assert_eq!(evidence(event.tid), before);
    assert_eq!(other.map(evidence), sibling);
    assert_eq!(
        h.owner()
            .lifecycle
            .as_ref()
            .map(|state| state.registry.snapshot()),
        registry
    );
    assert_eq!(h.owner().owned, owned);
    assert_eq!(h.owner().stopped, stopped);
}

fn forced_order(child_first: bool) {
    let fixture = Fixture::new(ordinary(&[0x0f, 0x0b]));
    let mut h = Harness::new();
    let entry = h.entry(&fixture, libc::SYS_clone as u64);
    let before = evidence(entry.tid);
    h.resume(&entry);
    let until = Instant::now() + TIMEOUT;
    let mut parent = None;
    let mut child = None;
    while parent.is_none() || child.is_none() {
        let (tid, status) = h
            .owner()
            .wait_raw(until, "collect actual clone stops")
            .unwrap();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        if tid == entry.tid {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_CLONE);
            assert!(parent.replace((tid, status)).is_none());
        } else {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_STOP);
            assert!(child.replace((tid, status)).is_none());
            assert_eq!(h.owner().pin_kinds[&tid], PinKind::Thread);
            assert!(!broker::hup(&h.owner().handles[&tid]));
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
    let mut state = h.owner().lifecycle.take().unwrap();
    if !child_first {
        // Actual request against a queued real CLONE stop, not fabricated credit.
        ptrace(libc::PTRACE_INTERRUPT, parent.0, 0, 0).unwrap();
        state
            .tasks
            .get_mut(&parent.0)
            .unwrap()
            .interrupt_stops_remaining = 2;
    }
    let (first, second) = if child_first {
        (child, parent)
    } else {
        (parent, child)
    };
    assert!(
        state
            .observe(h.owner(), first.0, first.1)
            .unwrap()
            .is_none()
    );
    assert_eq!(state.registry.snapshot().tasks().count(), 1);
    let created = state
        .observe(h.owner(), second.0, second.1)
        .unwrap()
        .unwrap();
    let born = state.events.pop_front().unwrap();
    assert!(state.events.is_empty());
    assert_ne!(created.task.unwrap().task, born.task.unwrap().task);
    assert_eq!(created.task.unwrap().process, born.task.unwrap().process);
    assert_eq!(
        created.task.unwrap().address_space,
        born.task.unwrap().address_space
    );
    assert_eq!(state.registry.snapshot().address_spaces().count(), 1);
    if !child_first {
        assert_eq!(state.tasks[&parent.0].interrupt_stops_remaining, 1);
    }
    assert_eq!(evidence(parent.0), before);
    let mut expected = before.registers;
    expected.rax = 0;
    expected.rsp = CHILD_SP;
    let child_before = evidence(child.0);
    assert_eq!(child_before.registers, expected);
    assert_eq!(child_before.extended, before.extended);
    assert_eq!(child_before.mask, before.mask);
    assert_eq!(child_before.code, before.code);
    assert_eq!(child_before.storage, before.storage);
    assert_eq!(
        state.registry.task(born.task.unwrap().task).unwrap().state,
        crate::lifecycle::TaskState::Held {
            pc: expected.rip,
            reason: HoldReason::NewbornReturnReady
        }
    );
    assert!(!state.tasks[&child.0].syscall_open);
    h.owner().lifecycle = Some(state);
    h.resume(&created);
    let mut exit = h.next();
    if !child_first {
        assert_eq!(exit.tid, parent.0);
        assert_eq!(
            h.owner().lifecycle.as_ref().unwrap().tasks[&parent.0].interrupt_stops_remaining,
            0
        );
        if exit.kind == DynamicEventKind::Interrupted {
            h.resume(&exit);
            exit = h.next();
        }
    }
    assert_eq!(
        exit.kind,
        DynamicEventKind::SyscallExit {
            result: i64::from(child.0),
            is_error: false
        }
    );
    expected = before.registers;
    expected.rax = child.0 as u64;
    assert_eq!(read_registers(parent.0).unwrap(), expected);
    assert_eq!(xstate(parent.0).unwrap(), before.extended);
    assert_eq!(launch::task_mask(parent.0).unwrap(), before.mask);
    let parent_held = evidence(parent.0);
    h.resume(&born);
    let fault = h.next();
    let DynamicEventKind::SignalDelivery(ref info) = fault.kind else {
        panic!("{fault:?}")
    };
    assert_eq!(fault.tid, child.0);
    assert_eq!(info.signal(), libc::SIGILL);
    assert_eq!(info.code(), 2);
    assert_eq!(info.fault_address(), Some(before.registers.rip));
    expected = child_before.registers;
    expected.orig_rax = u64::MAX;
    expected.eflags |= 1 << 16;
    let actual = evidence(child.0);
    assert_eq!(actual.registers, expected);
    assert_eq!(actual.extended, before.extended);
    assert_eq!(actual.mask, before.mask);
    assert_eq!(actual.code, before.code);
    assert_eq!(actual.storage, before.storage);
    assert_eq!(evidence(parent.0), parent_held);
    h.finish(&[parent.0, child.0]);
}
#[test]
fn actual_clone_parent_then_newborn_preserves_shared_identity_and_full_return_state() {
    forced_order(false);
}
#[test]
fn actual_clone_newborn_then_parent_preserves_shared_identity_and_full_return_state() {
    forced_order(true);
}

#[test]
fn thread_entry_refusals_preserve_full_held_state_and_never_create() {
    let good = [THREAD_FLAGS, CHILD_SP, 0, 0, 0];
    let mut rows = Vec::new();
    for value in [
        THREAD_FLAGS | (1 << 32),
        THREAD_FLAGS | 0x80000,
        THREAD_FLAGS | libc::SIGCHLD as u64,
        0x100,
    ] {
        let mut args = good;
        args[0] = value;
        rows.push((
            libc::SYS_clone,
            args,
            "native thread clone profile refuses arguments",
        ));
    }
    for index in [2, 3, 4] {
        let mut args = good;
        args[index] = DATA;
        rows.push((
            libc::SYS_clone,
            args,
            "native thread clone profile refuses arguments",
        ));
    }
    for stack in [0, 127, ENTRY + 128, u64::MAX] {
        let mut args = good;
        args[1] = stack;
        rows.push((
            libc::SYS_clone,
            args,
            "native thread stack lacks writable storage",
        ));
    }
    rows.push((libc::SYS_fork, good, "dynamic fork policy refuses creation"));
    for number in [libc::SYS_clone3, libc::SYS_vfork] {
        rows.push((
            number,
            good,
            "dynamic creation and later exec are not yet qualified",
        ));
    }
    assert_eq!(rows.len(), 14);
    for (number, args, error) in rows {
        let fixture = Fixture::new(program(number, args, &[0x0f, 0x0b]));
        let mut h = Harness::new();
        let entry = h.entry(&fixture, number as u64);
        refused(&mut h, &entry, error, None);
        assert_eq!(h.owner().owned.len(), 1);
        h.finish(&[entry.tid]);
    }
    let fixture = Fixture::new(ordinary(&[0x0f, 0x0b]));
    let mut h = Harness::new();
    let entry = h.entry(&fixture, libc::SYS_clone as u64);
    let mut registers = read_registers(entry.tid).unwrap();
    registers.eflags |= 0x100;
    set_registers(entry.tid, &registers).unwrap();
    refused(
        &mut h,
        &entry,
        "native thread entry did not authenticate",
        None,
    );
    h.finish(&[entry.tid]);
}

#[test]
fn live_thread_exec_and_second_clone_refusals_leave_both_full_states_held() {
    for row in 0..3 {
        let mut suffix = Vec::new();
        literal(
            &mut suffix,
            0,
            if row == 2 {
                libc::SYS_clone
            } else {
                libc::SYS_execve
            } as u64,
        );
        suffix.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
        let fixture = Fixture::new(ordinary(&suffix));
        let mut h = Harness::new();
        h.owner().exec_policy = DynamicExecPolicy::ExecveOnce;
        let entry = h.entry(&fixture, libc::SYS_clone as u64);
        let (created, born) = h.created(&entry);
        let parent = h.parent_exit(&created, &born);
        let (selected, sibling, error) = match row {
            0 => (
                &parent,
                born.tid,
                "native exec requires physically removed workers",
            ),
            1 => (&born, parent.tid, "native nonleader exec is not qualified"),
            _ => (&parent, born.tid, "dynamic lifetime task bound exhausted"),
        };
        h.resume(selected);
        let next = h.next();
        assert_eq!(next.tid, selected.tid);
        assert!(
            matches!(next.kind, DynamicEventKind::SyscallEntry { number, .. } if number == if row == 2 { libc::SYS_clone } else { libc::SYS_execve } as u64)
        );
        refused(&mut h, &next, error, Some(sibling));
        h.finish(&[parent.tid, born.tid]);
    }
}

#[test]
fn leader_pre_exit_remains_owned_until_worker_finishes_without_broker_worker_reap() {
    let mut suffix = vec![0x48, 0x85, 0xc0, 0x74, 0];
    let branch = 4;
    flags(&mut suffix);
    literal(&mut suffix, 7, 5);
    literal(&mut suffix, 0, libc::SYS_exit as u64);
    suffix.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    let child_at = suffix.len();
    suffix[branch] = u8::try_from(child_at - (branch + 1)).unwrap();
    flags(&mut suffix);
    literal(&mut suffix, 7, 7);
    literal(&mut suffix, 0, libc::SYS_exit as u64);
    suffix.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    let fixture = Fixture::new(ordinary(&suffix));
    let mut h = Harness::new();
    let entry = h.entry(&fixture, libc::SYS_clone as u64);
    let (created, born) = h.created(&entry);
    let parent = h.parent_exit(&created, &born);
    h.resume(&parent);
    let exit_entry = h.next();
    assert!(matches!(
        exit_entry.kind,
        DynamicEventKind::SyscallEntry { number: 60, .. }
    ));
    assert_eq!(read_registers(parent.tid).unwrap().eflags, FLAGS);
    let worker = evidence(born.tid);
    h.resume(&exit_entry);
    let exiting = h.next();
    assert_eq!(exiting.task, parent.task);
    assert_eq!(
        exiting.kind,
        DynamicEventKind::TaskExiting {
            status: ExitStatus::Code(5)
        }
    );
    assert!(exiting.stop_token().is_none());
    assert!(matches!(
        h.owner().lifecycle.as_ref().unwrap().tasks[&parent.tid].state,
        State::Exiting
    ));
    assert_eq!(
        h.owner()
            .lifecycle
            .as_ref()
            .unwrap()
            .registry
            .task(parent.task.unwrap().task)
            .unwrap()
            .state,
        crate::lifecycle::TaskState::Exiting {
            event_status: ExitStatus::Code(5)
        }
    );
    assert!(h.owner().owned.contains(&parent.tid));
    assert!(!h.owner().tracer_terminal.contains_key(&parent.tid));
    assert!(!broker::hup(&h.owner().handles[&parent.tid]));
    assert!(matches!(
        h.owner()
            .execute(Request::Interrupt, Instant::now() + TIMEOUT),
        Err(LaunchError::Invalid(
            "dynamic interruption requires running execution"
        ))
    ));
    assert!(!h.owner().closing);
    assert_eq!(evidence(born.tid), worker);
    h.resume(&born);
    let worker_exit = h.next();
    assert_eq!(worker_exit.tid, born.tid);
    assert!(matches!(
        worker_exit.kind,
        DynamicEventKind::SyscallEntry { number: 60, .. }
    ));
    assert_eq!(read_registers(born.tid).unwrap().eflags, FLAGS);
    h.resume(&worker_exit);
    let mut terminal = BTreeSet::new();
    let mut worker_exiting = false;
    while terminal.len() != 2 {
        let event = h.next();
        assert!(event.stop_token().is_none());
        match event.kind {
            DynamicEventKind::TaskExiting {
                status: ExitStatus::Code(7),
            } => {
                assert_eq!(event.tid, born.tid);
                assert!(!worker_exiting);
                worker_exiting = true;
            }
            DynamicEventKind::TaskTerminal {
                status: ExitStatus::Code(7),
            } => {
                assert!(terminal.insert(event.tid));
                if event.tid == born.tid {
                    assert!(worker_exiting);
                    assert_eq!(h.owner().pin_kinds[&born.tid], PinKind::Thread);
                    assert!(broker::hup(&h.owner().handles[&born.tid]));
                }
            }
            _ => panic!("unexpected actual exit phase: {event:?}"),
        }
    }
    assert_eq!(terminal, BTreeSet::from([parent.tid, born.tid]));
    h.owner().poll_broker().unwrap();
    assert!(
        !h.owner()
            .broker
            .as_ref()
            .unwrap()
            .physical
            .contains_key(&born.tid)
    );
    h.finish(&[parent.tid, born.tid]);
}
