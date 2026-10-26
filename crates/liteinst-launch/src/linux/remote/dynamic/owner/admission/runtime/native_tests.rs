//! Real initial startup only. No original instruction is executed by the
//! admitted lane, and no Partial source observation is treated as a permit.
use super::super::super::tests::{Fixture, Harness, pin, reaped};
use super::super::runtime_capture::{CaptureFailure, CaptureFailureKind, CaptureStage};
use super::*;
use crate::linux::remote::dynamic::{Request, Response};
use liteinst_admission::entries::{Completeness, EntryProvenance};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::AtomicU64;

const TIMEOUT: Duration = Duration::from_secs(3);
const BASE: u64 = 0x400000;
const ENTRY: u64 = BASE + 4096;
// Executing the first original instruction changes RAX to this literal. The
// expected ready RAX remains the actual exec return, so execution is visible.
const CODE: &[u8] = &[
    0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xeb, 0xfe,
];
static SESSION: AtomicU64 = AtomicU64::new(800_000);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NativeMap {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) permissions: [u8; 4],
    pub(super) x_column: usize,
    pub(super) raw: Vec<u8>,
}

pub(super) fn maps(pid: i32) -> Vec<u8> {
    // Independent test observation; production's retained parser is not used
    // to derive the expected raw descriptor or its single allowed X change.
    let bytes = std::fs::read(format!("/proc/{pid}/maps")).unwrap();
    assert!(!bytes.is_empty() && bytes.ends_with(b"\n") && !bytes.contains(&0));
    bytes
}

pub(super) fn rows(bytes: &[u8]) -> Vec<NativeMap> {
    assert!(bytes.ends_with(b"\n"));
    let mut result = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let range_end = line.iter().position(|byte| *byte == b' ').unwrap();
        let mut range = std::str::from_utf8(&line[..range_end]).unwrap().split('-');
        let start = u64::from_str_radix(range.next().unwrap(), 16).unwrap();
        let end = u64::from_str_radix(range.next().unwrap(), 16).unwrap();
        assert!(range.next().is_none() && start < end);
        assert_eq!(start % 4096, 0);
        assert_eq!(end % 4096, 0);
        let permission_start = range_end + 1;
        let permissions: [u8; 4] = line[permission_start..permission_start + 4]
            .try_into()
            .unwrap();
        assert!(matches!(permissions[0], b'r' | b'-'));
        assert!(matches!(permissions[1], b'w' | b'-'));
        assert!(matches!(permissions[2], b'x' | b'-'));
        assert!(matches!(permissions[3], b'p' | b's'));
        assert_eq!(line[permission_start + 4], b' ');
        if let Some(prior) = result.last() {
            let prior: &NativeMap = prior;
            assert!(prior.end <= start);
        }
        result.push(NativeMap {
            start,
            end,
            permissions,
            x_column: permission_start + 2,
            raw: line.to_vec(),
        });
    }
    result
}

pub(super) fn bytes(pid: i32, address: u64, length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);
    while result.len() < length {
        let cursor = address.checked_add(result.len() as u64).unwrap();
        let aligned = cursor & !7;
        unsafe {
            *libc::__errno_location() = 0;
        }
        let word = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKDATA,
                pid,
                aligned as usize as *mut libc::c_void,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        let errno = unsafe { *libc::__errno_location() };
        assert!(
            word != -1 || errno == 0,
            "independent source PEEK failed: {errno}"
        );
        let data = (word as u64).to_ne_bytes();
        let offset = (cursor - aligned) as usize;
        let count = (length - result.len()).min(8 - offset);
        result.extend_from_slice(&data[offset..offset + count]);
    }
    result
}

pub(super) fn state(pid: i32) -> TaskStateSnapshot {
    let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    ptrace(libc::PTRACE_GETREGS, pid, 0, (&raw mut registers) as usize).unwrap();
    let mut xstate = vec![0; MAX_XSTATE];
    let pointer = xstate.as_mut_ptr().cast::<libc::c_void>();
    let mut vector = libc::iovec {
        iov_base: pointer,
        iov_len: xstate.len(),
    };
    ptrace(
        libc::PTRACE_GETREGSET,
        pid,
        NT_X86_XSTATE,
        (&raw mut vector) as usize,
    )
    .unwrap();
    assert_eq!(vector.iov_base, pointer);
    assert!((512..MAX_XSTATE).contains(&vector.iov_len));
    xstate.truncate(vector.iov_len);
    let mut mask = 0;
    ptrace(libc::PTRACE_GETSIGMASK, pid, 8, (&raw mut mask) as usize).unwrap();
    TaskStateSnapshot {
        registers: registers.into(),
        xstate,
        mask,
    }
}

struct Before {
    state: TaskStateSnapshot,
    maps: Vec<u8>,
    code: Vec<u8>,
}
impl Before {
    fn capture(pid: i32) -> Self {
        let result = Self {
            state: state(pid),
            maps: maps(pid),
            code: bytes(pid, BASE, 8192),
        };
        assert_eq!(result.state.registers.rip, ENTRY);
        assert_eq!(result.state.registers.cs, 0x33);
        assert_eq!(result.state.registers.orig_rax, libc::SYS_execve as u64);
        assert_eq!(
            result.state.registers.rax,
            (-i64::from(libc::ENOSYS)) as u64
        );
        assert_eq!(&result.code[4096..4096 + CODE.len()], CODE);
        let original = rows(&result.maps);
        let main = original
            .iter()
            .filter(|row| row.start == BASE && row.end == BASE + 8192)
            .collect::<Vec<_>>();
        assert_eq!(main.len(), 1);
        assert_eq!(main[0].permissions, *b"r-xp");
        result
    }
    fn unchanged(&self, pid: i32) {
        assert_eq!(state(pid), self.state);
        assert!(maps(pid) == self.maps, "complete pristine maps changed");
        assert_eq!(bytes(pid, BASE, 8192), self.code);
    }
}

fn with_owner<T>(
    fixture: &Fixture,
    action: impl FnOnce(&mut Owner, &DynamicStop, Instant, &Before) -> T,
) -> T {
    with_owner_cleanup(fixture, action, |_, _| {})
}

fn with_owner_cleanup<T>(
    fixture: &Fixture,
    action: impl FnOnce(&mut Owner, &DynamicStop, Instant, &Before) -> T,
    after_cleanup: impl FnOnce(&Owner, &T),
) -> T {
    let mut harness = Harness::new();
    // Harness's legacy zero session is suitable for its raw tests; this new
    // census uses a real nonzero Owner constructed before any child exists.
    *harness.owner() = Owner::new(
        SESSION.fetch_add(1, Ordering::Relaxed),
        Arc::new(AtomicBool::new(false)),
    );
    harness.owner().lifecycle_options = Some(DynamicLifecycleOptions::default());
    let until = Instant::now() + TIMEOUT;
    let ready = harness.launch(fixture).unwrap();
    let app = pin(ready.pid);
    let broker = pin(harness.owner().broker.as_ref().unwrap().pid);
    let initial = ready.event.stop_token().unwrap().clone();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let before = Before::capture(ready.pid);
        assert!(Instant::now() < until);
        action(harness.owner(), &initial, until, &before)
    }));
    let cleanup = harness.owner().cleanup().unwrap();
    assert_eq!(cleanup.reaped, [ready.pid]);
    reaped(&app);
    reaped(&broker);
    let outcome = match outcome {
        Ok(value) => catch_unwind(AssertUnwindSafe(|| {
            after_cleanup(harness.owner(), &value);
            value
        })),
        Err(payload) => Err(payload),
    };
    // Finish retains the existing mask restoration and Owner destruction.
    // The completed cleanup has no new terminal child to report a second time.
    assert!(harness.finish().reaped.is_empty());
    match outcome {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    }
}

pub(super) fn start(
    owner: &mut Owner,
    initial: &DynamicStop,
    options: DynamicRuntimeOptions,
    until: Instant,
) -> Result<AdmissionReply, GateError> {
    match owner.execute(
        Request::Admission(Box::new(AdmissionRequest::StartRuntime {
            initial: initial.clone(),
            options,
        })),
        until,
    ) {
        Ok(Response::Admission(result)) => *result,
        Ok(_) => panic!("startup returned a non-admission response"),
        Err(error) => Err(GateError::Control(error)),
    }
}

pub(super) fn ready(reply: Result<AdmissionReply, GateError>) -> DynamicAdmissionState {
    match reply.unwrap() {
        AdmissionReply::RuntimeReady(state, _progress) => state,
        _ => panic!("startup did not return RuntimeReady"),
    }
}

pub(super) fn exact_nx_maps(original: &[u8], current: &[u8], island: &std::ops::Range<u64>) {
    let before = rows(original);
    let after = rows(current);
    assert_eq!(after.len(), before.len() + 1);
    let island_rows = after
        .iter()
        .filter(|row| row.start == island.start && row.end == island.end)
        .collect::<Vec<_>>();
    assert_eq!(island_rows.len(), 1);
    assert_eq!(island.end - island.start, 4096);
    assert_eq!(island_rows[0].permissions, *b"r-xp");
    let fields = std::str::from_utf8(&island_rows[0].raw)
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 5);
    assert_eq!(u64::from_str_radix(fields[2], 16).unwrap(), 0);
    assert_eq!(fields[3], "00:00");
    assert_eq!(fields[4], "0");
    for old in before {
        assert!(old.end <= island.start || island.end <= old.start);
        let new = after
            .iter()
            .filter(|row| row.start == old.start && row.end == old.end)
            .collect::<Vec<_>>();
        assert_eq!(new.len(), 1);
        let mut expected = old.raw.clone();
        let vsyscall = old.raw.ends_with(b"[vsyscall]");
        if old.permissions[2] == b'x' && !vsyscall {
            expected[old.x_column] = b'-';
        }
        assert!(
            new[0].raw == expected,
            "full original descriptor changed beyond the exact X column"
        );
    }
}

fn check_bootstrap(owner: &Owner, before: &Before) {
    let runtime = owner.runtime.as_ref().unwrap();
    let prepared = runtime.bootstrap.as_ref().unwrap();
    let boot = prepared.completed().unwrap();
    let evidence = &boot.evidence;
    assert_eq!(evidence.exec_event, before.state);
    let mut exit = before.state.clone();
    exit.registers.rax = 0;
    assert_eq!(evidence.exec_exit, exit);
    let mut first = exit.registers;
    first.rip = ENTRY + 1;
    first.orig_rax = u64::MAX;
    assert_eq!(evidence.entry_trap.registers, first);
    assert_eq!(evidence.entry_trap.mask, exit.mask);
    let mut restored = evidence.entry_trap.clone();
    restored.registers.rip = ENTRY;
    assert_eq!(evidence.restored_entry, restored);
    assert_eq!(state(owner.pid), restored);
    assert_eq!(bytes(owner.pid, BASE, 8192), before.code);
    assert_eq!(restored.registers.rax, 0, "first original MOV executed");
    let progress = prepared.progress();
    assert!(progress.first_failure.is_none());
    assert!(
        progress.exec_queries_started
            && progress.first_user_queries_started
            && progress.runner_queries_started
    );
    for (wait, signal) in [
        (progress.exec_wait, libc::SIGTRAP | 0x80),
        (progress.first_user_wait, libc::SIGTRAP),
        (progress.runner_wait, libc::SIGTRAP),
    ] {
        let (pid, status) = wait.unwrap();
        assert_eq!(pid, owner.pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), signal);
        assert_eq!(status >> 16, 0);
    }
    assert!(
        progress
            .effects()
            .iter()
            .all(|record| record.is_some_and(|record| record.complete))
    );
    let diagnostics = prepared.diagnostics();
    for slot in &diagnostics.states[..3] {
        assert!(slot.complete);
        for request in [
            slot.registers_request,
            slot.xstate_request,
            slot.mask_request,
        ] {
            let request = request.unwrap();
            assert_eq!(request.result, 0);
            assert_eq!(request.errno, None);
        }
        assert_eq!(slot.returned_pointer, slot.requested_pointer);
        assert!((512..MAX_XSTATE).contains(&slot.returned_length));
    }
    assert_eq!(diagnostics.exit_maps.bytes(), before.maps);
    let observed_maps = maps(owner.pid);
    assert_eq!(diagnostics.current_maps.bytes(), observed_maps);
    exact_nx_maps(&before.maps, &observed_maps, &boot.island.range);
    let native = runtime.native.as_ref().unwrap();
    native.require_admission_stop(&boot.stop).unwrap();
    assert_eq!(
        native.admission_current(boot.stop.identity.task).unwrap(),
        boot.stop
    );
    assert_eq!(boot.stop.token.session, owner.session);
    assert_eq!(boot.stop.token.tid, owner.pid);
    assert_eq!(boot.stop.identity.generation, 0);
    assert!(owner.lifecycle.is_none() && owner.admission.is_none());
}

fn check_ready(owner: &Owner, before: &Before, ready: &DynamicAdmissionState, until: Instant) {
    check_bootstrap(owner, before);
    let runtime = owner.runtime.as_ref().unwrap();
    assert_eq!(runtime.until, until);
    assert_eq!(runtime.stage, RuntimeStage::Ready);
    assert!(
        runtime.ready_issued && runtime.ready_xstate.is_empty() && runtime.origin_xstate.is_empty()
    );
    let boot = runtime.bootstrap.as_ref().unwrap().completed().unwrap();
    assert_eq!(ready.task, boot.stop.identity);
    assert_eq!(ready.registers, boot.evidence.restored_entry.registers);
    assert_eq!(ready.xstate, boot.evidence.restored_entry.xstate);
    assert_eq!(ready.signal_mask, boot.evidence.restored_entry.mask);
    let sources = &runtime.sources;
    assert!(
        sources.original_complete() && sources.capture_complete() && sources.recheck_complete()
    );
    assert_eq!(sources.failure(), None);
    let (original, progress) = sources.original_maps();
    assert_eq!(
        initial_maps_prefix(original, progress).unwrap(),
        before.maps
    );
    assert_eq!(original.len(), 64 * 1024);
    assert!(
        original[progress.copied_bytes..]
            .iter()
            .all(|byte| *byte == 0)
    );
    let (quarantine, progress) = sources.quarantine_maps();
    assert!(progress.complete && progress.failure.is_none());
    assert_eq!(&quarantine[..progress.copied_bytes], maps(owner.pid));
    assert_eq!(sources.vmas().len(), 1);
    assert_eq!(sources.window_count(), 1);
    let vma = &sources.vmas()[0];
    assert_eq!((vma.start, vma.end, vma.offset), (BASE, BASE + 8192, 0));
    let mut target = BASE;
    let mut page_index = 0;
    for index in 0..sources.window_count() {
        let window = sources.window(index).unwrap();
        assert_eq!(window.id.index(), index);
        let identity = window.id.identity();
        assert_eq!(
            window.snapshot.mapping,
            liteinst_admission::MappingId(identity.mapping)
        );
        assert_eq!(
            window.snapshot.generation,
            liteinst_admission::Generation(identity.generation)
        );
        assert_eq!(
            window.snapshot.writes,
            liteinst_admission::scan::WriteControl::Owned
        );
        assert_eq!(
            window.snapshot.before,
            liteinst_admission::scan::Boundary::NonExecutable
        );
        assert_eq!(
            window.snapshot.after,
            liteinst_admission::scan::Boundary::NonExecutable
        );
        assert_eq!((window.vma.start, window.vma.end), (BASE, BASE + 8192));
        assert_eq!(window.target.start(), target);
        assert!(window.target.end() <= BASE + 8192);
        assert_eq!(window.entries.completeness(), Completeness::Partial);
        let expected_heads = if window.snapshot.range().contains(ENTRY) {
            vec![(ENTRY, EntryProvenance::Loader)]
        } else {
            Vec::new()
        };
        assert_eq!(window.entries.heads().collect::<Vec<_>>(), expected_heads);
        let start = usize::try_from(window.snapshot.range().start() - BASE).unwrap();
        let end = usize::try_from(window.snapshot.range().end() - BASE).unwrap();
        assert_eq!(window.snapshot.bytes(), &before.code[start..end]);
        assert_eq!(
            window.snapshot.bytes(),
            bytes(owner.pid, window.snapshot.range().start(), end - start)
        );
        let (_, capture, recheck) = sources.window_progress(index).unwrap();
        for progress in [capture, recheck] {
            assert!(progress.complete && progress.failure.is_none());
            assert_eq!(progress.copied_bytes, end - start);
            assert_eq!(progress.requested_bytes, end - start);
        }
        while target < window.target.end() {
            assert_eq!(
                runtime.pages[page_index],
                RuntimePage {
                    address: target,
                    window: index,
                    executable: false
                }
            );
            target += 4096;
            page_index += 1;
        }
    }
    assert_eq!(target, BASE + 8192);
    assert_eq!(page_index, 2);
    assert_eq!(runtime.pages.len(), page_index);
    let census = runtime.census.as_ref().unwrap();
    assert_eq!(census.generation(), 0);
    assert_eq!(census.history().len(), 0);
    let active = census.active().collect::<Vec<_>>();
    assert_eq!(active.len(), 1);
    assert_eq!(census.rows().count(), 1);
    assert_eq!(Some(active[0].row.id), runtime.initial_origin);
    assert_eq!(active[0].row.kind, OriginKind::CurrentHeldPc);
    assert_eq!(active[0].row.pc, ENTRY);
    assert_eq!(active[0].current, &active[0].row.initial);
    assert_eq!(active[0].current.token, boot.stop.token);
    assert_eq!(active[0].current.task, ready.task);
    assert_eq!(active[0].current.registers, ready.registers);
    assert_eq!(active[0].current.xstate, ready.xstate);
    assert_eq!(active[0].current.signal_mask, ready.signal_mask);
    assert_eq!(active[0].current.phase, StopPhase::UserCheckpoint);
    assert_eq!(active[0].current.signal, None);
    assert_eq!(census.charged(), runtime.startup.charged());
    for debit in [census.charged(), census.used()] {
        assert_eq!(
            (
                debit.epochs,
                debit.origins,
                debit.reports,
                debit.witnesses,
                debit.plan_history
            ),
            (1, 1, 0, 0, 0)
        );
        assert!(debit.source_fact_bytes > 0 && debit.source_fact_bytes <= 64 * 1024 * 1024);
    }
    assert!(census.used().source_fact_bytes <= census.charged().source_fact_bytes);
}

// Independent raw fixture: genuine EXEC and SYSCALL_INFO EXIT, then one
// literal entry INT3 before the first original instruction. It does not call
// either production bootstrap implementation or fabricate lifecycle events.
fn raw_first_user(fixture: &Fixture) -> TaskStateSnapshot {
    with_owner(fixture, |owner, initial, until, before| {
        owner.resume(initial, DynamicResume::Continue).unwrap();
        let (pid, status) = owner.wait_raw(until, "raw initial EXIT").unwrap();
        assert_eq!(pid, owner.pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP | 0x80);
        assert_eq!(status >> 16, 0);
        let mut raw = [0_u8; 88];
        let count = unsafe {
            libc::ptrace(
                libc::PTRACE_GET_SYSCALL_INFO,
                pid,
                raw.len() as *mut libc::c_void,
                raw.as_mut_ptr().cast::<libc::c_void>(),
            )
        };
        assert!(count >= 33);
        assert_eq!(size_of::<libc::ptrace_syscall_info>(), raw.len());
        let info =
            unsafe { std::ptr::read_unaligned(raw.as_ptr().cast::<libc::ptrace_syscall_info>()) };
        let exit = state(pid);
        assert_eq!(info.op, libc::PTRACE_SYSCALL_INFO_EXIT);
        assert_eq!(info.arch, 0xc000003e);
        assert_eq!(info.instruction_pointer, exit.registers.rip);
        assert_eq!(info.stack_pointer, exit.registers.rsp);
        let returned = unsafe { info.u.exit };
        assert_eq!(returned.sval, 0);
        assert_eq!(returned.is_error, 0);
        let mut expected = before.state.clone();
        expected.registers.rax = 0;
        assert_eq!(exit, expected);
        assert_eq!(maps(pid), before.maps);
        let original: [u8; 8] = before.code[4096..4104].try_into().unwrap();
        let mut patch = original;
        patch[0] = 0xcc;
        owner.time_left(until, "raw initial entry patch").unwrap();
        ptrace(
            libc::PTRACE_POKEDATA,
            pid,
            ENTRY as usize,
            u64::from_ne_bytes(patch) as usize,
        )
        .unwrap();
        assert_eq!(bytes(pid, ENTRY, 8), patch);
        owner
            .time_left(until, "raw initial first-user release")
            .unwrap();
        ptrace(libc::PTRACE_CONT, pid, 0, 0).unwrap();
        owner.released(pid);
        let (actual_pid, status) = owner
            .wait_raw(until, "raw initial first-user stop")
            .unwrap();
        assert_eq!(actual_pid, pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        assert_eq!(status >> 16, 0);
        let mut signal: libc::siginfo_t = unsafe { std::mem::zeroed() };
        ptrace(libc::PTRACE_GETSIGINFO, pid, 0, (&raw mut signal) as usize).unwrap();
        assert_eq!(signal.si_signo, libc::SIGTRAP);
        assert!(matches!(signal.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
        let first = state(pid);
        let mut registers = exit.registers;
        registers.rip = ENTRY + 1;
        registers.orig_rax = u64::MAX;
        assert_eq!(first.registers, registers);
        assert_eq!(first.mask, exit.mask);
        assert_eq!(bytes(pid, ENTRY, 8), patch);
        owner
            .time_left(until, "raw initial entry restoration")
            .unwrap();
        ptrace(
            libc::PTRACE_POKEDATA,
            pid,
            ENTRY as usize,
            u64::from_ne_bytes(original) as usize,
        )
        .unwrap();
        let mut restored = first.clone();
        restored.registers.rip = ENTRY;
        let mut native: libc::user_regs_struct = restored.registers.into();
        owner
            .time_left(until, "raw initial register restoration")
            .unwrap();
        ptrace(libc::PTRACE_SETREGS, pid, 0, (&raw mut native) as usize).unwrap();
        assert_eq!(state(pid), restored);
        assert_eq!(bytes(pid, BASE, 8192), before.code);
        assert_eq!(maps(pid), before.maps);
        owner
            .time_left(until, "raw initial observation complete")
            .unwrap();
        first
    })
}

#[test]
fn initial_runtime_startup_preserves_real_boundary_state_sources_and_nx() {
    let fixture = Fixture::code(CODE);
    let raw = raw_first_user(&fixture);
    with_owner(&fixture, |owner, initial, until, before| {
        let ready = ready(start(
            owner,
            initial,
            DynamicRuntimeOptions::default(),
            until,
        ));
        check_ready(owner, before, &ready, until);
        let first = &owner
            .runtime
            .as_ref()
            .unwrap()
            .bootstrap
            .as_ref()
            .unwrap()
            .completed()
            .unwrap()
            .evidence
            .entry_trap;
        // Stack addresses belong to different real processes. Each lane's
        // complete GPR relation is checked above; no address/flag masking is
        // applied. Kernel first-user XSTATE and inherited mask compare exactly.
        assert_eq!(first.xstate, raw.xstate);
        assert_eq!(first.mask, raw.mask);
    });
}

#[test]
fn initial_runtime_owner_refuses_raw_bypass_and_repeated_start() {
    let fixture = Fixture::code(CODE);
    with_owner(&fixture, |owner, initial, until, before| {
        let ready = ready(start(
            owner,
            initial,
            DynamicRuntimeOptions::default(),
            until,
        ));
        check_ready(owner, before, &ready, until);
        let held = state(owner.pid);
        let map = maps(owner.pid);
        let runtime = owner.runtime.as_ref().unwrap();
        let charged = runtime.census.as_ref().unwrap().charged();
        let origin = runtime.initial_origin;
        let binding = runtime.sources.current_binding().unwrap().clone();
        let identities = (0..runtime.sources.window_count())
            .map(|index| runtime.sources.window(index).unwrap().id)
            .collect::<Vec<_>>();
        let registry = runtime.native.as_ref().unwrap().admission_snapshot();
        assert!(matches!(
            owner.execute(
                Request::Resume(initial.clone(), DynamicResume::Continue),
                until
            ),
            Err(LaunchError::Invalid(
                "raw dynamic requests cannot bypass admission ownership"
            ))
        ));
        assert_eq!(state(owner.pid), held);
        assert_eq!(maps(owner.pid), map);
        assert!(matches!(
            start(owner, initial, DynamicRuntimeOptions::default(), until),
            Err(GateError::Refused("runtime startup cannot be repeated"))
        ));
        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
        assert_eq!(state(owner.pid), held);
        assert_eq!(maps(owner.pid), map);
        let runtime = owner.runtime.as_ref().unwrap();
        assert_eq!(runtime.census.as_ref().unwrap().charged(), charged);
        assert_eq!(runtime.initial_origin, origin);
        assert_eq!(runtime.sources.current_binding(), Some(&binding));
        assert_eq!(
            (0..runtime.sources.window_count())
                .map(|index| runtime.sources.window(index).unwrap().id)
                .collect::<Vec<_>>(),
            identities
        );
        assert_eq!(
            runtime.native.as_ref().unwrap().admission_snapshot(),
            registry
        );
        check_ready(owner, before, &ready, until);
    });
}

#[test]
fn initial_runtime_expired_original_deadline_keeps_pristine_exec() {
    let fixture = Fixture::code(CODE);
    with_owner(&fixture, |owner, initial, until, before| {
        // Keep the actual EXEC held until the SAME deadline established before
        // launch expires. No substitute timestamp or renewed budget is passed.
        while Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(
            start(owner, initial, DynamicRuntimeOptions::default(), until),
            Err(GateError::Control(LaunchError::Timeout("dynamic command")))
        ));
        assert!(owner.runtime.is_none() && owner.lifecycle.is_none());
        before.unchanged(owner.pid);
        owner.require_stop(initial).unwrap();
    });
}

#[test]
fn initial_runtime_one_short_bootstrap_reservation_keeps_pristine_exec() {
    let fixture = Fixture::code(CODE);
    with_owner(&fixture, |owner, initial, until, before| {
        let mut options = DynamicRuntimeOptions::default();
        let allocated = RuntimeOwner::allocate(
            RuntimeStartOptions {
                capture: InitialCaptureProfile {
                    max_vmas: options.capture.max_vmas,
                    max_windows: options.capture.max_windows,
                    max_window_bytes: options.capture.max_window_bytes,
                    max_total_capture_bytes: options.capture.max_total_capture_bytes,
                },
                limits: options.limits,
            },
            until,
        )
        .unwrap();
        let first_charge = allocated.startup.charged();
        drop(allocated);
        let shape = InitialBootstrapShape::from_original(&before.maps).unwrap();
        let bootstrap = shape
            .reservation_bytes()
            .unwrap()
            .checked_sub(size_of::<PreparedInitialBootstrap>())
            .unwrap();
        assert!(bootstrap > 0);
        let exact = first_charge
            .source_fact_bytes
            .checked_add(bootstrap)
            .unwrap();
        options.limits.source_fact_bytes = exact.checked_sub(1).unwrap();
        assert!(options.limits.source_fact_bytes >= first_charge.source_fact_bytes);
        assert!(matches!(
            start(owner, initial, options, until),
            Err(GateError::Refused(
                "dynamic continuation lifetime capacity exhausted"
            ))
        ));
        before.unchanged(owner.pid);
        owner.require_stop(initial).unwrap();
        let runtime = owner.runtime.as_ref().unwrap();
        assert_eq!(runtime.stage, RuntimeStage::BootstrapAllocation);
        assert_eq!(runtime.startup.charged(), first_charge);
        assert!(
            runtime.bootstrap.is_none() && runtime.native.is_none() && runtime.census.is_none()
        );
        assert!(
            !runtime.ready_issued && runtime.initial_origin.is_none() && runtime.pages.is_empty()
        );
        let (storage, progress) = runtime.sources.original_maps();
        assert_eq!(initial_maps_prefix(storage, progress).unwrap(), before.maps);
        assert!(runtime.sources.original_complete());
        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
    });
}

#[test]
fn initial_runtime_source_window_refusal_retains_completed_bootstrap() {
    let fixture = Fixture::code(CODE);
    with_owner_cleanup(
        &fixture,
        |owner, initial, until, before| {
            let mut options = DynamicRuntimeOptions::default();
            // Actual main VMA was independently proved to be 8192 bytes. With
            // dependency context this 8192-byte source buffer covers one 4096-byte
            // target page, so a second target is necessary, without host guessing.
            options.capture.max_windows = 1;
            options.capture.max_window_bytes = 8192;
            options.capture.max_total_capture_bytes = 8192;
            assert!(matches!(
                start(owner, initial, options, until),
                Err(GateError::Refused(
                    "initial runtime window count exceeds its bound"
                ))
            ));
            check_bootstrap(owner, before);
            let runtime = owner.runtime.as_ref().unwrap();
            assert_eq!(runtime.stage, RuntimeStage::RuntimeCapture);
            assert!(
                !runtime.ready_issued
                    && runtime.census.is_none()
                    && runtime.initial_origin.is_none()
            );
            assert_eq!(
                runtime.sources.failure().unwrap().stage,
                CaptureStage::Geometry
            );
            assert_eq!(
                runtime.sources.failure().unwrap().kind,
                CaptureFailureKind::Refused("initial runtime window count exceeds its bound")
            );
            assert_eq!(runtime.sources.window_count(), 1);
            assert!(!runtime.sources.capture_complete() && !runtime.sources.recheck_complete());
            assert!(runtime.sources.window(0).is_none());
            let (storage, capture, recheck) = runtime.sources.window_progress(0).unwrap();
            assert!(storage.iter().all(|byte| *byte == 0));
            assert!(!capture.started && !capture.attempted && !capture.complete);
            assert!(!recheck.started && !recheck.attempted && !recheck.complete);
            assert_eq!(
                runtime.sources.current_xstate().unwrap(),
                state(owner.pid).xstate
            );
            assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
            (
                runtime.sources.failure(),
                runtime.sources.current_binding().unwrap().clone(),
                runtime.sources.current_xstate().unwrap().to_vec(),
                runtime.sources.original_maps().0.to_vec(),
                runtime.sources.quarantine_maps().0.to_vec(),
                runtime.startup.charged(),
            )
        },
        |owner, (failure, binding, xstate, original, quarantine, charge)| {
            let runtime = owner.runtime.as_ref().unwrap();
            assert_eq!(&runtime.sources.failure(), failure);
            assert_eq!(runtime.sources.current_binding(), Some(binding));
            assert_eq!(runtime.sources.current_xstate().unwrap(), xstate);
            assert_eq!(runtime.sources.original_maps().0, original.as_slice());
            assert_eq!(runtime.sources.quarantine_maps().0, quarantine.as_slice());
            assert_eq!(&runtime.startup.charged(), charge);
            let boot = runtime.bootstrap.as_ref().unwrap().completed().unwrap();
            assert_eq!(boot.stop, binding.stop);
            assert_eq!(boot.evidence.restored_entry.registers, binding.registers);
            assert_eq!(boot.evidence.restored_entry.xstate, *xstate);
            assert_eq!(boot.evidence.restored_entry.mask, binding.signal_mask);
        },
    );
}

#[test]
fn initial_runtime_unwind_retains_native_bootstrap_until_physical_cleanup() {
    let fixture = Fixture::code(CODE);
    with_owner_cleanup(
        &fixture,
        |owner, initial, until, before| {
            owner.runtime_panic_after_bootstrap = true;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let _ = start(owner, initial, DynamicRuntimeOptions::default(), until);
            }));
            let payload = outcome.unwrap_err();
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
            assert_eq!(
                message,
                Some("injected runtime unwind after actual bootstrap custody transfer")
            );
            assert!(!owner.runtime_panic_after_bootstrap);
            check_bootstrap(owner, before);
            let runtime = owner.runtime.as_ref().unwrap();
            assert_eq!(runtime.stage, RuntimeStage::Bootstrap);
            assert!(
                !runtime.ready_issued
                    && runtime.census.is_none()
                    && runtime.initial_origin.is_none()
            );
            assert!(runtime.sources.original_complete());
            assert!(!runtime.sources.capture_complete() && !runtime.sources.recheck_complete());
            assert!(runtime.sources.current_binding().is_none());
            assert_eq!(
                runtime.sources.failure(),
                Some(CaptureFailure {
                    stage: CaptureStage::Original,
                    window: None,
                    kind: CaptureFailureKind::Aborted,
                })
            );
            let stop = runtime
                .bootstrap
                .as_ref()
                .unwrap()
                .completed()
                .unwrap()
                .stop
                .clone();
            let retained = runtime
                .bootstrap
                .as_ref()
                .unwrap()
                .completed()
                .unwrap()
                .evidence
                .restored_entry
                .clone();
            let registry = runtime.native.as_ref().unwrap().admission_snapshot();
            let original_maps = runtime.sources.original_maps().0.to_vec();
            let first_charge = runtime.startup.charged();
            (stop, retained, registry, original_maps, first_charge)
        },
        |owner, (stop, retained, registry, original_maps, first_charge)| {
            // Physical cleanup does not turn history into a new callable stop.
            // These are exact retained values; no post-reap ptrace query occurs.
            let runtime = owner.runtime.as_ref().unwrap();
            assert_eq!(
                &runtime
                    .bootstrap
                    .as_ref()
                    .unwrap()
                    .completed()
                    .unwrap()
                    .stop,
                stop
            );
            assert_eq!(
                &runtime
                    .bootstrap
                    .as_ref()
                    .unwrap()
                    .completed()
                    .unwrap()
                    .evidence
                    .restored_entry,
                retained
            );
            assert_eq!(
                &runtime.native.as_ref().unwrap().admission_snapshot(),
                registry
            );
            assert_eq!(runtime.sources.original_maps().0, original_maps.as_slice());
            assert_eq!(&runtime.startup.charged(), first_charge);
            assert_eq!(
                runtime.sources.failure(),
                Some(CaptureFailure {
                    stage: CaptureStage::Original,
                    window: None,
                    kind: CaptureFailureKind::Aborted,
                })
            );
        },
    );
}
