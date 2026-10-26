//! Real held selected bridges and closed-profile refusals. CPU outputs below
//! are explicit scripted values; they are never described as native CPU results.
use super::*;
use crate::DynamicAdmissionSession;
use crate::linux::remote::dynamic::owner::admission::census::{HistoryRecord, OriginRow};
use crate::linux::remote::dynamic::owner::admission::runtime::native_tests::{
    bytes as read_bytes, exact_nx_maps, maps as read_maps, ready, rows, start, state as read_state,
};
use crate::linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::assert_unreleased;
use crate::linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::support::{
    after_cleanup as ordinary_after_cleanup, retained as ordinary_retained,
};
use crate::linux::remote::dynamic::owner::tests::{Fixture, Harness, pin, reaped};
use crate::linux::remote::dynamic::{Request as DynamicRequest, Response};
use crate::selected::{InstructionProvider, SemanticsError, SyscallResult};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::AtomicU64;

const TIMEOUT: Duration = Duration::from_secs(3);
const BASE: u64 = 0x400000;
const ENTRY: u64 = BASE + 4096;
const DR_BASE: u64 = 0xffff_0ff0;
const DR_TRACE: u64 = 0xffff_4ff0;
const MARK12: u64 = 0x1122_3344_5566_7788;
const MARK13: u64 = 0x8877_6655_4433_2211;
const SCRIPT: SelectedResult = SelectedResult::Cpuid {
    eax: 0x8765_4321,
    ebx: 0xfedc_ba98,
    ecx: 0x1357_2468,
    edx: 0xabcd_1234,
};
static SESSION: AtomicU64 = AtomicU64::new(840_000);
mod cross_page;

fn live(pin: &OwnedFd) {
    let mut event = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut event, 1, 0) }, 0);
    assert_eq!(event.revents, 0);
}

fn debug(pid: i32) -> [u64; 6] {
    [0usize, 1, 2, 3, 6, 7].map(|index| {
        let offset = std::mem::offset_of!(libc::user, u_debugreg) + index * 8;
        unsafe {
            *libc::__errno_location() = 0;
        }
        let value = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKUSER,
                pid,
                offset as *mut libc::c_void,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        let errno = unsafe { *libc::__errno_location() };
        assert!(
            value != -1 || errno == 0,
            "independent debug read failed: {errno}"
        );
        value as u64
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CetQueryRetained {
    request: Request,
    bytes: Vec<u8>,
    requested_pointer: usize,
    returned_pointer: usize,
    returned_length: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct CetStatusRetained {
    bytes: Vec<u8>,
    length: usize,
    open: Option<Request>,
    filesystem_request: Option<Request>,
    last_read: Option<Request>,
    filesystem: Option<i64>,
    complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct CetRetained {
    queries: Vec<Option<CetQueryRetained>>,
    status: Vec<CetStatusRetained>,
    complete: bool,
}
type RetainedStateRequests = (
    Option<Request>,
    Option<Request>,
    Option<Request>,
    usize,
    usize,
    usize,
    bool,
);
type RetainedMap = (Vec<u8>, usize, Option<Request>, Option<i64>, bool);
type RetainedControlProfile = ([u64; 6], [Option<Request>; 6], [u8; 24], Option<Request>);
#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedRetained {
    until: Instant,
    phase: SelectedPhase,
    failure: Option<(SelectedPhase, SelectedFailure)>,
    token: RuntimePendingToken,
    stop: AdmissionStop,
    before: ObservedStop,
    successor: ObservedStop,
    input: Option<SelectedInput>,
    decision: Option<ProviderDecision>,
    completed: Option<CompletedInstruction>,
    source: Vec<Vec<u8>>,
    progress: Vec<SourceReadProgress>,
    states: Vec<TaskStateSnapshot>,
    requests: Vec<RetainedStateRequests>,
    effects: [Option<NativeEffectRecord>; 4],
    maps: Vec<RetainedMap>,
    profiles: Vec<RetainedControlProfile>,
    cet: Vec<CetRetained>,
    wait: Option<(i32, i32)>,
    queries_started: bool,
    signal: ([u8; 128], Option<Request>),
    restored: Option<AdmissionStop>,
}
fn selected_retained(owner: &Owner) -> Vec<SelectedRetained> {
    owner
        .runtime
        .as_ref()
        .unwrap()
        .selected_attempts
        .iter()
        .map(|a| SelectedRetained {
            until: a.until,
            phase: a.phase,
            failure: a.first_failure,
            token: a.token.clone(),
            stop: a.stop.clone(),
            before: a.before.clone(),
            successor: a.successor.clone(),
            input: a.input.clone(),
            decision: a.decision,
            completed: a.completed.clone(),
            source: a.source_bytes.to_vec(),
            progress: a.source_progress.to_vec(),
            states: a
                .native
                .states
                .iter()
                .map(|slot| slot.initialized_state().clone())
                .collect(),
            requests: a
                .native
                .states
                .iter()
                .map(|slot| {
                    (
                        slot.registers_request,
                        slot.xstate_request,
                        slot.mask_request,
                        slot.requested_pointer,
                        slot.returned_pointer,
                        slot.returned_length,
                        slot.complete,
                    )
                })
                .collect(),
            effects: a.native.effects,
            maps: a
                .native
                .maps
                .iter()
                .map(|maps| {
                    (
                        maps.bytes().to_vec(),
                        maps.length,
                        maps.request,
                        maps.filesystem,
                        maps.complete,
                    )
                })
                .collect(),
            profiles: a
                .native
                .profiles
                .iter()
                .map(|p| (p.debug.values, p.debug.requests, p.rseq, p.rseq_request))
                .collect(),
            // The certificate's public query/status projections are diagnostic;
            // its opaque disabled-proof authority is never copied or fabricated.
            cet: a
                .native
                .profiles
                .iter()
                .map(|p| CetRetained {
                    queries: p
                        .cet
                        .queries
                        .iter()
                        .map(|query| {
                            query.map(|query| CetQueryRetained {
                                request: query.request,
                                bytes: query.bytes.to_vec(),
                                requested_pointer: query.requested_pointer,
                                returned_pointer: query.returned_pointer,
                                returned_length: query.returned_length,
                            })
                        })
                        .collect(),
                    status: p
                        .cet
                        .status
                        .iter()
                        .map(|status| CetStatusRetained {
                            bytes: status.bytes.to_vec(),
                            length: status.length,
                            open: status.open,
                            filesystem_request: status.filesystem_request,
                            last_read: status.last_read,
                            filesystem: status.filesystem,
                            complete: status.complete,
                        })
                        .collect(),
                    complete: p.cet.complete,
                })
                .collect(),
            wait: a.native.wait,
            queries_started: a.native.queries_started,
            signal: (a.native.signal.bytes, a.native.signal.request),
            restored: a.native.restored.clone(),
        })
        .collect()
}

struct Memory {
    descriptor: File,
    stack_start: u64,
    stack: Vec<u8>,
    source: Vec<u8>,
    maps: Vec<u8>,
}
impl Memory {
    fn capture(pid: i32, pin: &OwnedFd, actual_maps: Vec<u8>) -> Self {
        live(pin);
        let inventory = rows(&actual_maps);
        let stacks = inventory
            .iter()
            .filter(|row| row.raw.ends_with(b"[stack]"))
            .collect::<Vec<_>>();
        assert_eq!(stacks.len(), 1);
        assert_eq!(stacks[0].permissions, *b"rw-p");
        let stack_start = stacks[0].start;
        let stack_len = usize::try_from(stacks[0].end - stack_start).unwrap();
        let descriptor = File::open(format!("/proc/{pid}/mem")).unwrap();
        let mut stack = vec![0; stack_len];
        descriptor.read_exact_at(&mut stack, stack_start).unwrap();
        let mut source = vec![0; 8192];
        descriptor.read_exact_at(&mut source, BASE).unwrap();
        live(pin);
        Self {
            descriptor,
            stack_start,
            stack,
            source,
            maps: actual_maps,
        }
    }
    fn unchanged(&self, pid: i32, pin: &OwnedFd) {
        live(pin);
        let mut stack = vec![0; self.stack.len()];
        self.descriptor
            .read_exact_at(&mut stack, self.stack_start)
            .unwrap();
        assert_eq!(stack, self.stack, "whole lane-local initial stack changed");
        let mut source = vec![0; self.source.len()];
        self.descriptor.read_exact_at(&mut source, BASE).unwrap();
        assert_eq!(source, self.source, "whole original ELF bytes changed");
        assert_eq!(
            read_maps(pid),
            self.maps,
            "complete same-lane NX inventory changed"
        );
        live(pin);
    }
}

fn with_owner(code: &[u8], action: impl FnOnce(&mut Owner, &OwnedFd, &Memory, Instant)) {
    let fixture = Fixture::code(code);
    let mut harness = Harness::new();
    *harness.owner() = Owner::new(
        SESSION.fetch_add(1, Ordering::Relaxed),
        Arc::new(AtomicBool::new(false)),
    );
    harness.owner().lifecycle_options = Some(DynamicLifecycleOptions::default());
    // One unchanged operation deadline starts before launch and all reads.
    let until = Instant::now() + TIMEOUT;
    let launched = harness.launch(&fixture).unwrap();
    // A failed pin allocation is a validation-command failure, never a reason
    // to unwind an unobserved live owner into a passing fixture.
    let pins = catch_unwind(AssertUnwindSafe(|| {
        (
            pin(launched.pid),
            pin(harness.owner().broker.as_ref().unwrap().pid),
        )
    }));
    let (app, broker) = match pins {
        Ok(pins) => pins,
        Err(_) => {
            let _ = harness.owner().cleanup();
            std::process::abort();
        }
    };
    assert_ne!(app.as_raw_fd(), broker.as_raw_fd());
    let initial = launched.event.stop_token().unwrap().clone();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        live(&app);
        live(&broker);
        let original = read_maps(launched.pid);
        let original_source = read_bytes(launched.pid, BASE, 8192);
        assert_eq!(&original_source[4096..4096 + code.len()], code);
        let state = ready(start(
            harness.owner(),
            &initial,
            DynamicRuntimeOptions::default(),
            until,
        ));
        let owner = harness.owner();
        let actual = read_state(owner.pid);
        assert_eq!(actual.registers, state.registers);
        assert_eq!(actual.xstate, state.xstate);
        assert_eq!(actual.mask, state.signal_mask);
        assert_eq!(state.registers.rip, ENTRY);
        assert_eq!(state.registers.rax, 0);
        assert_eq!(state.registers.orig_rax, u64::MAX);
        assert_eq!(state.task.generation, 0);
        let boot = owner
            .runtime
            .as_ref()
            .unwrap()
            .bootstrap
            .as_ref()
            .unwrap()
            .completed()
            .unwrap();
        let closed = read_maps(owner.pid);
        exact_nx_maps(&original, &closed, &boot.island.range);
        let memory = Memory::capture(owner.pid, &app, closed);
        assert_eq!(memory.source, original_source);
        assert_eq!(debug(owner.pid), [0, 0, 0, 0, DR_BASE, 0]);
        assert!(Instant::now() < until);
        action(owner, &app, &memory, until);
        assert!(Instant::now() < until);
        (ordinary_retained(owner), selected_retained(owner))
    }));
    // The action's error/panic is rethrown only after both original incarnations
    // are physically reaped. Cleanup has its established separate 3s bound.
    let cleanup = harness
        .owner()
        .cleanup()
        .unwrap_or_else(|_| std::process::abort());
    assert_eq!(cleanup.reaped, [launched.pid]);
    reaped(&app);
    reaped(&broker);
    let outcome = match outcome {
        Ok((ordinary, selected)) => catch_unwind(AssertUnwindSafe(|| {
            ordinary_after_cleanup(harness.owner(), &ordinary);
            assert_eq!(selected_retained(harness.owner()), selected);
        })),
        Err(payload) => Err(payload),
    };
    assert!(harness.finish().reaped.is_empty());
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
}

#[derive(Clone)]
struct Current {
    actual: TaskStateSnapshot,
    stop: AdmissionStop,
    observed: ObservedStop,
    origin: OriginId,
    rows: Vec<OriginRow>,
    history: Vec<HistoryRecord>,
    charged: BudgetCharge,
    used: BudgetCharge,
}
fn current(owner: &Owner, app: &OwnedFd, memory: &Memory) -> Current {
    memory.unchanged(owner.pid, app);
    let runtime = owner.runtime.as_ref().unwrap();
    assert!(owner.admission.is_none() && owner.lifecycle.is_none());
    assert_eq!(runtime.stage, RuntimeStage::Ready);
    assert!(runtime.pages.iter().all(|page| !page.executable));
    let census = runtime.census.as_ref().unwrap();
    assert_eq!(census.generation(), 0);
    assert_eq!(census.active().count(), 1);
    let origin = runtime.initial_origin.unwrap();
    let observed = census.current_observation(origin).unwrap().clone();
    let stop = runtime
        .native
        .as_ref()
        .unwrap()
        .admission_current(observed.task.task)
        .unwrap();
    assert_eq!(stop.token, observed.token);
    assert_eq!(stop.identity, observed.task);
    assert!(stop.signal.is_none() && observed.signal.is_none());
    assert_eq!(observed.phase, StopPhase::UserCheckpoint);
    let actual = read_state(owner.pid);
    assert_eq!(actual.registers, observed.registers);
    assert_eq!(actual.xstate, observed.xstate);
    assert_eq!(actual.mask, observed.signal_mask);
    assert_eq!(observed.logical_pc, actual.registers.rip);
    live(app);
    Current {
        actual,
        stop,
        observed,
        origin,
        rows: census.rows().cloned().collect(),
        history: census.history().to_vec(),
        charged: census.charged(),
        used: census.used(),
    }
}
fn same_current(before: &Current, after: &Current) {
    assert_eq!(after.actual, before.actual);
    assert_eq!(after.stop, before.stop);
    assert_eq!(after.observed, before.observed);
    assert_eq!(after.origin, before.origin);
    assert_eq!(after.rows, before.rows);
    assert_eq!(after.history, before.history);
}
fn invoke(
    owner: &mut Owner,
    request: AdmissionRequest,
    until: Instant,
) -> Result<AdmissionReply, GateError> {
    match owner
        .execute(DynamicRequest::Admission(Box::new(request)), until)
        .unwrap()
    {
        Response::Admission(reply) => *reply,
        _ => panic!("runtime command returned a different response namespace"),
    }
}
fn pending(owner: &mut Owner, until: Instant) -> Box<RuntimeProviderInput> {
    match invoke(owner, AdmissionRequest::Advance, until).unwrap() {
        AdmissionReply::RuntimeProvider(input) => input,
        _ => panic!("selected input did not reach the runtime provider boundary"),
    }
}
fn check_pending(
    owner: &Owner,
    before: &Current,
    input: &RuntimeProviderInput,
    encoding: &[u8],
    until: Instant,
) {
    assert_eq!(input.input.registers(), &before.actual.registers);
    assert_eq!(input.input.instruction().bytes(), encoding);
    assert_eq!(
        input.input.instruction().logical_pc(),
        before.actual.registers.rip
    );
    assert_eq!(input.token.stop, before.stop.token);
    assert_eq!(input.token.task, before.stop.identity);
    assert_eq!(input.token.pc, before.actual.registers.rip);
    let runtime = owner.runtime.as_ref().unwrap();
    let index = runtime.selected_pending.unwrap();
    let attempt = &runtime.selected_attempts[index];
    assert_eq!(attempt.token, input.token);
    assert_eq!(attempt.until, until);
    assert_eq!(attempt.phase, SelectedPhase::Pending);
    assert!(attempt.first_failure.is_none());
    assert!(attempt.source_progress[0].complete);
    assert_eq!(
        attempt.source_progress[0].copied_bytes,
        attempt.source_bytes[0].len()
    );
    assert_eq!(
        attempt.source_bytes[0],
        runtime
            .sources
            .window(input.token.window)
            .unwrap()
            .snapshot
            .bytes()
    );
    assert_eq!(
        runtime.sources.window(input.token.window).unwrap().id,
        attempt.source
    );
    assert_no_selected_effects(attempt);
}
fn assert_no_selected_effects(attempt: &RuntimeSelectedAttempt) {
    assert!(attempt.native.effects.iter().all(Option::is_none));
    assert!(
        attempt.native.wait.is_none()
            && !attempt.native.queries_started
            && attempt.native.restored.is_none()
    );
    for state in &attempt.native.states {
        assert!(!state.complete);
        assert!(
            state.registers_request.is_none()
                && state.xstate_request.is_none()
                && state.mask_request.is_none()
        );
    }
    assert!(attempt.prepared.is_none() && attempt.completed.is_none() && attempt.public.is_none());
}
fn cpuid_expected(before: &TaskStateSnapshot) -> TaskStateSnapshot {
    let mut expected = before.clone();
    expected.registers.rip = expected.registers.rip.checked_add(2).unwrap();
    expected.registers.rax = 0x8765_4321;
    expected.registers.rbx = 0xfedc_ba98;
    expected.registers.rcx = 0x1357_2468;
    expected.registers.rdx = 0xabcd_1234;
    expected
}
fn finish(
    owner: &mut Owner,
    input: &RuntimeProviderInput,
    result: SelectedResult,
    before: &Current,
    expected: &TaskStateSnapshot,
    context: (&OwnedFd, &Memory, Instant),
) -> Current {
    let (app, memory, until) = context;
    let completion = match invoke(
        owner,
        AdmissionRequest::CompleteRuntime {
            token: input.token.clone(),
            decision: ProviderDecision::Complete(result),
        },
        until,
    )
    .unwrap()
    {
        AdmissionReply::Event(DynamicAdmissionEvent::Completed(completion)) => completion,
        _ => panic!("scripted CPU input did not yield a distinct selected completion"),
    };
    assert_eq!(completion.before_task, before.observed.task);
    assert_eq!(completion.after_task, before.observed.task);
    assert_eq!(completion.selected.input, input.input);
    assert_eq!(completion.selected.execution, SelectedExecution::Scripted);
    assert_eq!(completion.selected.after, expected.registers);
    assert_eq!(completion.selected.before_xstate, before.actual.xstate);
    assert_eq!(completion.selected.xstate, expected.xstate);
    assert_eq!(completion.before_signal_mask, before.actual.mask);
    assert_eq!(completion.signal_mask, expected.mask);
    let after = current(owner, app, memory);
    assert_eq!(after.actual, *expected);
    assert_eq!(after.observed.task, before.observed.task);
    assert!(after.stop.token.sequence > before.stop.token.sequence);
    assert_ne!(after.origin, before.origin);
    assert_eq!(&after.rows[..before.rows.len()], before.rows.as_slice());
    assert_eq!(after.rows.len(), before.rows.len() + 1);
    assert_eq!(
        &after.history[..before.history.len()],
        before.history.as_slice()
    );
    assert_eq!(after.history.len(), before.history.len() + 1);
    assert_eq!(after.used.origins, before.used.origins + 1);
    assert_eq!(after.used.witnesses, before.used.witnesses + 1);
    assert_eq!(
        (
            after.used.epochs,
            after.used.reports,
            after.used.plan_history
        ),
        (
            before.used.epochs,
            before.used.reports,
            before.used.plan_history
        )
    );
    let runtime = owner.runtime.as_ref().unwrap();
    assert!(runtime.selected_pending.is_none());
    let attempt = runtime.selected_attempts.last().unwrap();
    assert_eq!(attempt.phase, SelectedPhase::Completed);
    assert!(attempt.first_failure.is_none());
    assert!(
        attempt
            .source_progress
            .iter()
            .all(|progress| progress.complete)
    );
    for source in &attempt.source_bytes {
        assert_eq!(
            source,
            runtime
                .sources
                .window(attempt.token.window)
                .unwrap()
                .snapshot
                .bytes()
        );
    }
    for (record, effect) in attempt.native.effects.iter().zip([
        NativeEffect::Apply,
        NativeEffect::Inject,
        NativeEffect::Release,
        NativeEffect::Restore,
    ]) {
        assert_eq!(
            *record,
            Some(NativeEffectRecord {
                effect,
                result: Some(Request {
                    result: 0,
                    errno: None
                })
            })
        );
    }
    let (tid, status) = attempt.native.wait.unwrap();
    assert_eq!(tid, owner.pid);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
    assert_eq!(status >> 16, 0);
    assert!(attempt.native.queries_started);
    assert_eq!(
        attempt.native.signal.request,
        Some(Request {
            result: 0,
            errno: None
        })
    );
    let signal = unsafe {
        std::ptr::read_unaligned(
            attempt
                .native
                .signal
                .bytes
                .as_ptr()
                .cast::<libc::siginfo_t>(),
        )
    };
    assert_eq!(signal.si_signo, libc::SIGTRAP);
    assert_eq!(signal.si_errno, 0);
    assert_eq!(signal.si_code, libc::SI_KERNEL);
    let mut injected = expected.clone();
    let island = &runtime
        .bootstrap
        .as_ref()
        .unwrap()
        .completed()
        .unwrap()
        .island;
    injected.registers.rip = island.range.start + 2;
    injected.registers.orig_rax = u64::MAX;
    injected.registers.eflags &= !(0x100 | 0x10000 | 0x40000);
    let mut trap = injected.clone();
    trap.registers.rip += 1;
    for (slot, expected_state) in attempt
        .native
        .states
        .iter()
        .zip([expected, &injected, &trap, expected])
    {
        assert!(slot.complete);
        assert_eq!(
            slot.registers_request,
            Some(Request {
                result: 0,
                errno: None
            })
        );
        assert_eq!(
            slot.xstate_request,
            Some(Request {
                result: 0,
                errno: None
            })
        );
        assert_eq!(
            slot.mask_request,
            Some(Request {
                result: 0,
                errno: None
            })
        );
        assert_eq!(slot.requested_pointer, slot.returned_pointer);
        assert_eq!(slot.returned_length, expected_state.xstate.len());
        assert_eq!(slot.initialized_state(), expected_state);
    }
    assert_eq!(attempt.native.final_stop().unwrap(), &after.stop);
    for maps in &attempt.native.maps {
        assert_eq!(maps.bytes(), memory.maps);
    }
    let dr6 = debug(owner.pid)[4];
    for profile in &attempt.native.profiles {
        assert_eq!(profile.debug.values, [0, 0, 0, 0, dr6, 0]);
        assert!(
            profile
                .debug
                .requests
                .iter()
                .all(|request| request.is_some_and(|request| request.errno.is_none()))
        );
    }
    after
}

#[test]
fn runtime_selected_cpu_and_ordinary_keep_exact_control_lineage() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_cpu_and_ordinary_keep_exact_control_lineage",
        || {
            // Every selected class is the actual first original opcode in its own lane.
            // No feature-dependent native CPU opcode is executed by the scripted bridge.
            let cases: &[(&[u8], SelectedResult)] = &[
                (&[0x0f, 0xa2], SCRIPT),
                (
                    &[0x0f, 0x31],
                    SelectedResult::Rdtsc {
                        counter: 0x1234_5678_9abc_def0,
                    },
                ),
                (
                    &[0x0f, 0x01, 0xf9],
                    SelectedResult::Rdtscp {
                        counter: 0x1234_5678_9abc_def0,
                        auxiliary: 0xcafe_babe,
                    },
                ),
                (
                    &[0x48, 0x0f, 0xc7, 0xf0],
                    SelectedResult::Rdrand {
                        value: 0xfedc_ba98_7654_3210,
                        carry: true,
                    },
                ),
                (
                    &[0x41, 0x0f, 0xc7, 0xf9],
                    SelectedResult::Rdseed {
                        value: 0x89ab_cdef,
                        carry: true,
                    },
                ),
                (
                    &[0xf3, 0x41, 0x0f, 0xc7, 0xfa],
                    SelectedResult::Rdpid {
                        auxiliary: 0x8765_4321,
                    },
                ),
            ];
            for (index, &(encoding, result)) in cases.iter().enumerate() {
                let mut code = encoding.to_vec();
                code.extend_from_slice(&[0x49, 0xbc]);
                code.extend_from_slice(&MARK12.to_le_bytes());
                code.extend_from_slice(&[0xeb, 0xfe]);
                with_owner(&code, |owner, app, memory, until| {
                    let before = current(owner, app, memory);
                    assert_ne!(before.actual.registers.r12, MARK12);
                    let input = pending(owner, until);
                    check_pending(owner, &before, &input, encoding, until);
                    same_current(&before, &current(owner, app, memory));
                    let mut expected = before.actual.clone();
                    expected.registers.rip += encoding.len() as u64;
                    match index {
                        0 => expected = cpuid_expected(&before.actual),
                        1 => {
                            expected.registers.rax = 0x9abc_def0;
                            expected.registers.rdx = 0x1234_5678;
                        }
                        2 => {
                            expected.registers.rax = 0x9abc_def0;
                            expected.registers.rdx = 0x1234_5678;
                            expected.registers.rcx = 0xcafe_babe;
                        }
                        3 => {
                            expected.registers.rax = 0xfedc_ba98_7654_3210;
                            expected.registers.eflags = (expected.registers.eflags & !0x8d5) | 1;
                        }
                        4 => {
                            expected.registers.r9 = 0x89ab_cdef;
                            expected.registers.eflags = (expected.registers.eflags & !0x8d5) | 1;
                        }
                        5 => expected.registers.r10 = 0x8765_4321,
                        _ => unreachable!(),
                    }
                    finish(
                        owner,
                        &input,
                        result,
                        &before,
                        &expected,
                        (app, memory, until),
                    );
                    assert_eq!(debug(owner.pid), [0, 0, 0, 0, DR_BASE, 0]);
                    assert!(owner.runtime.as_ref().unwrap().ordinary_attempts.is_empty());
                    assert_eq!(
                        read_state(owner.pid).registers.r12,
                        before.actual.registers.r12,
                        "the first ordinary marker must remain unexecuted"
                    );
                });
            }
            let mut code = vec![0x0f, 0xa2, 0x49, 0xbc];
            code.extend_from_slice(&MARK12.to_le_bytes());
            code.extend_from_slice(&[0x0f, 0xa2, 0x49, 0xbd]);
            code.extend_from_slice(&MARK13.to_le_bytes());
            code.extend_from_slice(&[0x0f, 0xa2, 0xeb, 0xfe]);
            with_owner(&code, |owner, app, memory, until| {
                let mut before = current(owner, app, memory);
                assert_ne!(before.actual.registers.r12, MARK12);
                assert_ne!(before.actual.registers.r13, MARK13);
                for index in 0..3 {
                    let input = pending(owner, until);
                    if index != 0 {
                        let mut expected = before.actual.clone();
                        expected.registers.rip += 10;
                        if index == 1 {
                            expected.registers.r12 = MARK12;
                        } else {
                            expected.registers.r13 = MARK13;
                        }
                        let after = current(owner, app, memory);
                        assert_eq!(after.actual, expected);
                        assert_ne!(after.origin, before.origin);
                        assert_eq!(after.observed.task, before.observed.task);
                        assert!(after.stop.token.sequence > before.stop.token.sequence);
                        assert_eq!(
                            &after.history[..before.history.len()],
                            before.history.as_slice()
                        );
                        assert_eq!(after.history.len(), before.history.len() + 7);
                        assert_eq!(after.used.origins, before.used.origins + 1);
                        assert_eq!(after.used.witnesses, before.used.witnesses + 7);
                        assert_eq!(
                            (
                                after.used.epochs,
                                after.used.reports,
                                after.used.plan_history
                            ),
                            (
                                before.used.epochs,
                                before.used.reports,
                                before.used.plan_history
                            )
                        );
                        assert_eq!(debug(owner.pid), [0, 0, 0, 0, DR_TRACE, 0]);
                        before = after;
                    }
                    check_pending(owner, &before, &input, &[0x0f, 0xa2], until);
                    let expected = cpuid_expected(&before.actual);
                    before = finish(
                        owner,
                        &input,
                        SCRIPT,
                        &before,
                        &expected,
                        (app, memory, until),
                    );
                    assert_eq!(
                        owner.runtime.as_ref().unwrap().ordinary_attempts.len(),
                        index
                    );
                    assert_eq!(
                        debug(owner.pid),
                        [0, 0, 0, 0, if index == 0 { DR_BASE } else { DR_TRACE }, 0]
                    );
                }
                let runtime = owner.runtime.as_ref().unwrap();
                assert_eq!(runtime.selected_attempts.len(), 3);
                assert_eq!(runtime.metrics.selected.scripted_completions, 3);
                assert_eq!(
                    runtime
                        .metrics
                        .selected
                        .callbacks
                        .values()
                        .copied()
                        .sum::<usize>(),
                    3
                );
            });
            public_transport(false);
        },
    );
}

fn pending_accounting(
    before: &Current,
    after: &Current,
    attempt: &RuntimeSelectedAttempt,
    public: Option<&RuntimeProviderInput>,
) {
    same_current(before, after);
    assert_eq!(
        (
            after.used.epochs,
            after.used.reports,
            after.used.origins,
            after.used.witnesses,
            after.used.plan_history
        ),
        (
            before.used.epochs,
            before.used.reports,
            before.used.origins,
            before.used.witnesses,
            before.used.plan_history
        )
    );
    let encoding = attempt
        .input
        .as_ref()
        .unwrap()
        .instruction()
        .retained_capacity();
    let expected = attempt.allocated_bytes().unwrap()
        + size_of::<Box<RuntimeSelectedAttempt>>()
        + encoding
        + public.map_or(0, |input| {
            size_of::<RuntimeProviderInput>() + input.input.instruction().retained_capacity()
        });
    assert_eq!(
        after.used.source_fact_bytes,
        before.used.source_fact_bytes + expected
    );
    assert_eq!(
        (
            after.charged.epochs,
            after.charged.reports,
            after.charged.origins,
            after.charged.witnesses,
            after.charged.plan_history
        ),
        (
            before.charged.epochs,
            before.charged.reports,
            before.charged.origins + 1,
            before.charged.witnesses + 1,
            before.charged.plan_history
        )
    );
    assert!(after.charged.source_fact_bytes > before.charged.source_fact_bytes);
    assert!(after.used.source_fact_bytes <= after.charged.source_fact_bytes);
}

#[test]
fn runtime_selected_native_refuses_without_ordinary_fallback() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_native_refuses_without_ordinary_fallback",
        || {
            with_owner(
                &[
                    0x0f, 0xa2, 0x49, 0xbc, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xeb,
                    0xfe,
                ],
                |owner, app, memory, until| {
                    let before = current(owner, app, memory);
                    let input = pending(owner, until);
                    check_pending(owner, &before, &input, &[0x0f, 0xa2], until);
                    let pending_state = current(owner, app, memory);
                    assert!(matches!(
                        invoke(
                            owner,
                            AdmissionRequest::CompleteRuntime {
                                token: input.token.clone(),
                                decision: ProviderDecision::Native
                            },
                            until
                        ),
                        Err(GateError::Refused(
                            "runtime selected Native transport is not qualified"
                        ))
                    ));
                    let after = current(owner, app, memory);
                    same_current(&pending_state, &after);
                    assert_eq!(after.charged, pending_state.charged);
                    assert_eq!(after.used, pending_state.used);
                    let runtime = owner.runtime.as_ref().unwrap();
                    let attempt = runtime.selected_attempts.last().unwrap();
                    pending_accounting(&before, &after, attempt, Some(&input));
                    assert_eq!(attempt.token, input.token);
                    assert_eq!(attempt.until, until);
                    assert_eq!(
                        attempt.first_failure,
                        Some((
                            SelectedPhase::SourceAfterProvider,
                            SelectedFailure::Refused(
                                "runtime selected Native transport is not qualified"
                            )
                        ))
                    );
                    assert!(attempt.source_progress[1].complete);
                    assert_no_selected_effects(attempt);
                    assert_unreleased(runtime, &[]);
                    assert_eq!(debug(owner.pid), [0, 0, 0, 0, DR_BASE, 0]);
                    assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                },
            );
            public_transport(true);
        },
    );
}

#[test]
fn runtime_selected_syscall_refuses_without_ordinary_fallback() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_syscall_refuses_without_ordinary_fallback",
        || {
            // The original MOV really establishes a valid getpid input. Neither Native
            // nor a semantically valid getpid result may enter the CPU-only transport.
            for decision in [
                ProviderDecision::Native,
                ProviderDecision::Complete(SelectedResult::Syscall(SyscallResult::LinuxX64GetId {
                    value: 123,
                })),
            ] {
                with_owner(
                    &[
                        0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0x49, 0xbc, 0x88, 0x77, 0x66, 0x55, 0x44,
                        0x33, 0x22, 0x11, 0xeb, 0xfe,
                    ],
                    |owner, app, memory, until| {
                        let initial = current(owner, app, memory);
                        let input = pending(owner, until);
                        let before = current(owner, app, memory);
                        let mut expected = initial.actual.clone();
                        expected.registers.rax = 39;
                        expected.registers.rip += 5;
                        assert_eq!(before.actual, expected);
                        check_pending(owner, &before, &input, &[0x0f, 0x05], until);
                        assert!(matches!(
                            input.input.instruction().operation(),
                            Operation::Syscall { .. }
                        ));
                        let reason = match decision {
                            ProviderDecision::Native => {
                                "runtime selected Native transport is not qualified"
                            }
                            _ => "runtime selected syscall transport is not qualified",
                        };
                        assert!(
                            matches!(invoke(owner, AdmissionRequest::CompleteRuntime { token: input.token.clone(), decision }, until),
                Err(GateError::Refused(actual)) if actual == reason)
                        );
                        let after = current(owner, app, memory);
                        same_current(&before, &after);
                        assert_eq!(after.charged, before.charged);
                        assert_eq!(after.used, before.used);
                        let runtime = owner.runtime.as_ref().unwrap();
                        assert_eq!(runtime.ordinary_attempts.len(), 1);
                        assert_eq!(runtime.selected_attempts.len(), 1);
                        let attempt = &runtime.selected_attempts[0];
                        assert_eq!(attempt.token, input.token);
                        assert_eq!(attempt.until, until);
                        assert_eq!(
                            attempt.first_failure,
                            Some((
                                SelectedPhase::SourceAfterProvider,
                                SelectedFailure::Refused(reason)
                            ))
                        );
                        assert!(
                            attempt.source_progress[0].complete
                                && attempt.source_progress[1].complete
                        );
                        assert_no_selected_effects(attempt);
                        assert_eq!(debug(owner.pid), [0, 0, 0, 0, DR_TRACE, 0]);
                        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                    },
                );
            }
        },
    );
}

#[test]
fn runtime_ordinary_memory_and_stack_refuse_before_effects() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_ordinary_memory_and_stack_refuse_before_effects",
        || {
            for (encoding, reason) in [
                (
                    &[0x48, 0x8b, 0x04, 0x24][..],
                    "runtime ordinary data-access footprint is unqualified",
                ),
                (
                    &[0x48, 0x89, 0x04, 0x24][..],
                    "runtime ordinary data-access footprint is unqualified",
                ),
                (
                    &[0x50][..],
                    "runtime ordinary stack footprint is unqualified",
                ),
                (
                    &[0x58][..],
                    "runtime ordinary stack footprint is unqualified",
                ),
                (
                    &[0xc3][..],
                    "runtime ordinary stack footprint is unqualified",
                ),
            ] {
                let mut code = encoding.to_vec();
                code.extend_from_slice(&[0x0f, 0xa2, 0xeb, 0xfe]);
                with_owner(&code, |owner, app, memory, until| {
                    let before = current(owner, app, memory);
                    assert!(matches!(invoke(owner, AdmissionRequest::Advance, until),
                Err(GateError::Refused(actual)) if actual == reason));
                    let after = current(owner, app, memory);
                    same_current(&before, &after);
                    assert_eq!(
                        (
                            after.used.epochs,
                            after.used.reports,
                            after.used.origins,
                            after.used.witnesses,
                            after.used.plan_history
                        ),
                        (
                            before.used.epochs,
                            before.used.reports,
                            before.used.origins,
                            before.used.witnesses,
                            before.used.plan_history
                        )
                    );
                    assert!(after.used.source_fact_bytes > before.used.source_fact_bytes);
                    assert!(after.charged.source_fact_bytes > before.charged.source_fact_bytes);
                    assert_eq!(after.charged.origins, before.charged.origins + 1);
                    assert_eq!(after.charged.witnesses, before.charged.witnesses + 7);
                    let runtime = owner.runtime.as_ref().unwrap();
                    assert!(
                        runtime.selected_attempts.is_empty() && runtime.selected_pending.is_none()
                    );
                    assert_eq!(
                        runtime
                            .metrics
                            .selected
                            .callbacks
                            .values()
                            .copied()
                            .sum::<usize>(),
                        0
                    );
                    assert_unreleased(runtime, &[false]);
                    assert_eq!(debug(owner.pid), [0, 0, 0, 0, DR_BASE, 0]);
                    assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                });
            }
        },
    );
}

#[test]
fn runtime_actual_dr7_refuses_before_original_release() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_actual_dr7_refuses_before_original_release",
        || {
            for (encoding, selected) in [
                (&[0x0f, 0xa2][..], true),
                (
                    &[0x49, 0xbc, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11][..],
                    false,
                ),
            ] {
                let mut code = encoding.to_vec();
                code.extend_from_slice(&[0x0f, 0xa2, 0xeb, 0xfe]);
                with_owner(&code, |owner, app, memory, until| {
                    let before = current(owner, app, memory);
                    live(app);
                    // Actual architectural debug state, not a classifier argument or
                    // fake profile. DR0 remains zero, so this cannot hit the code page.
                    let offset = std::mem::offset_of!(libc::user, u_debugreg) + 7 * 8;
                    assert!(Instant::now() < until);
                    ptrace(libc::PTRACE_POKEUSER, owner.pid, offset, 1).unwrap();
                    assert_eq!(debug(owner.pid), [0, 0, 0, 0, DR_BASE, 1]);
                    assert!(Instant::now() < until);
                    assert!(matches!(
                        invoke(owner, AdmissionRequest::Advance, until),
                        Err(GateError::Control(LaunchError::Invalid(
                            "owned instruction debug profile differs"
                        )))
                    ));
                    let after = current(owner, app, memory);
                    same_current(&before, &after);
                    assert_eq!(debug(owner.pid), [0, 0, 0, 0, DR_BASE, 1]);
                    let runtime = owner.runtime.as_ref().unwrap();
                    if selected {
                        assert_unreleased(runtime, &[]);
                        assert_eq!(runtime.selected_attempts.len(), 1);
                        let attempt = &runtime.selected_attempts[0];
                        assert_eq!(
                            attempt.first_failure,
                            Some((
                                SelectedPhase::SourceBefore,
                                SelectedFailure::Invalid("owned instruction debug profile differs")
                            ))
                        );
                        assert!(attempt.source_progress[0].complete);
                        assert_eq!(
                            attempt.native.profiles[0].debug.values,
                            [0, 0, 0, 0, DR_BASE, 1]
                        );
                        assert!(
                            attempt.native.profiles[0]
                                .debug
                                .requests
                                .iter()
                                .all(|request| request
                                    .is_some_and(|request| request.errno.is_none()))
                        );
                        assert_no_selected_effects(attempt);
                        pending_accounting(&before, &after, attempt, None);
                    } else {
                        assert!(runtime.selected_attempts.is_empty());
                        assert_unreleased(runtime, &[true]);
                        assert_eq!(
                            (
                                after.used.epochs,
                                after.used.reports,
                                after.used.origins,
                                after.used.witnesses,
                                after.used.plan_history
                            ),
                            (
                                before.used.epochs,
                                before.used.reports,
                                before.used.origins,
                                before.used.witnesses,
                                before.used.plan_history
                            )
                        );
                        assert_eq!(
                            (
                                after.charged.epochs,
                                after.charged.reports,
                                after.charged.origins,
                                after.charged.witnesses,
                                after.charged.plan_history
                            ),
                            (
                                before.charged.epochs,
                                before.charged.reports,
                                before.charged.origins + 1,
                                before.charged.witnesses + 7,
                                before.charged.plan_history
                            )
                        );
                        assert!(after.used.source_fact_bytes > before.used.source_fact_bytes);
                        assert!(after.used.source_fact_bytes <= after.charged.source_fact_bytes);
                    }
                    assert_eq!(
                        runtime
                            .metrics
                            .selected
                            .callbacks
                            .values()
                            .copied()
                            .sum::<usize>(),
                        0
                    );
                    assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                });
            }
        },
    );
}

struct PublicProvider {
    thread: std::thread::ThreadId,
    expected: Option<RegisterSnapshot>,
    inputs: Vec<SelectedInput>,
    refuse: bool,
}
impl InstructionProvider for PublicProvider {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        assert_eq!(std::thread::current().id(), self.thread);
        assert_eq!(
            *input.registers(),
            self.expected
                .take()
                .expect("one expected public invocation")
        );
        assert_eq!(input.instruction().bytes(), &[0x0f, 0xa2]);
        assert_eq!(input.instruction().operation(), Operation::Cpuid);
        self.inputs.push(input.clone());
        Ok(if self.refuse {
            ProviderDecision::Native
        } else {
            ProviderDecision::Complete(SCRIPT)
        })
    }
}
fn parent(pid: i32) -> i32 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let parents = status
        .lines()
        .filter_map(|line| line.strip_prefix("PPid:\t"))
        .collect::<Vec<_>>();
    assert_eq!(parents.len(), 1);
    let parent = parents[0].parse::<i32>().unwrap();
    assert!(parent > 1 && parent != pid && parent != std::process::id() as i32);
    parent
}
fn public_transport(refuse: bool) {
    let mut code = vec![0x0f, 0xa2, 0x49, 0xbc];
    code.extend_from_slice(&MARK12.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0xa2, 0xeb, 0xfe]);
    let fixture = Fixture::code(&code);
    let command = fixture.command();
    let provider = PublicProvider {
        thread: std::thread::current().id(),
        expected: None,
        inputs: Vec::new(),
        refuse,
    };
    // SAFETY: this owned immutable fixture has no signal/threads/writers or
    // escaping control flow. Its only admitted original operation is MOV.
    let mut session = Some({
        let _fork = crate::TEST_FILE_FORK.lock().unwrap();
        unsafe {
            DynamicAdmissionSession::launch_runtime(
                &command,
                DynamicRuntimeOptions::default(),
                provider,
                TIMEOUT,
            )
        }
        .unwrap()
    });
    let mut app = None;
    let mut broker = None;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let session = session.as_mut().unwrap();
        app = Some(pin(session.pid()));
        let app = app.as_ref().unwrap();
        live(app);
        let broker_pid = parent(session.pid());
        broker = Some(pin(broker_pid));
        live(broker.as_ref().unwrap());
        assert_eq!(parent(session.pid()), broker_pid);
        live(app);
        let initial = session.initial_state().clone();
        assert_eq!(initial.registers.rip, ENTRY);
        assert_eq!(initial.registers.orig_rax, u64::MAX);
        assert_eq!(session.state(initial.task.task).unwrap(), initial);
        let memory = Memory::capture(session.pid(), app, read_maps(session.pid()));
        assert_eq!(&memory.source[4096..4096 + code.len()], code);
        let inventory = rows(&memory.maps);
        let main = inventory
            .iter()
            .filter(|row| row.start == BASE && row.end == BASE + 8192)
            .collect::<Vec<_>>();
        assert_eq!(main.len(), 1);
        assert_eq!(main[0].permissions, *b"r--p");
        let executable = inventory
            .iter()
            .filter(|row| row.permissions[2] == b'x' && !row.raw.ends_with(b"[vsyscall]"))
            .collect::<Vec<_>>();
        assert_eq!(
            executable.len(),
            1,
            "only the owned private island may remain executable"
        );
        assert_eq!(executable[0].end - executable[0].start, 4096);
        assert_eq!(executable[0].permissions, *b"r-xp");
        let fields = std::str::from_utf8(&executable[0].raw)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[2], "00000000");
        assert_eq!(fields[3], "00:00");
        assert_eq!(fields[4], "0");
        assert_eq!(
            session.read_memory(initial.task.task, BASE, 8192).unwrap(),
            memory.source
        );
        let mut expected = TaskStateSnapshot {
            registers: initial.registers,
            xstate: initial.xstate.clone(),
            mask: initial.signal_mask,
        };
        for index in 0..if refuse { 1 } else { 2 } {
            if index == 1 {
                expected.registers.r12 = MARK12;
                expected.registers.rip += 10;
            }
            session.provider_mut().expected = Some(expected.registers);
            if refuse {
                assert!(matches!(
                    session.next_event(),
                    Err(GateError::Refused(
                        "runtime selected Native transport is not qualified"
                    ))
                ));
                assert!(session.is_closed());
                assert_eq!(session.provider().inputs.len(), 1);
                // Cancellation may already have physically killed the task;
                // do not invent a post-cancel held read or a native prefix.
                break;
            }
            let completion = match session.next_event().unwrap() {
                DynamicAdmissionEvent::Completed(completion) => completion,
                _ => panic!("public runtime exchange did not yield selected completion"),
            };
            assert_eq!(completion.selected.input.registers(), &expected.registers);
            assert_eq!(completion.selected.before_xstate, expected.xstate);
            assert_eq!(completion.before_signal_mask, expected.mask);
            expected = cpuid_expected(&expected);
            assert_eq!(completion.selected.after, expected.registers);
            assert_eq!(completion.selected.xstate, expected.xstate);
            assert_eq!(completion.signal_mask, expected.mask);
            assert_eq!(completion.selected.execution, SelectedExecution::Scripted);
            assert_eq!(completion.before_task, initial.task);
            assert_eq!(completion.after_task, initial.task);
            let actual = session.state(initial.task.task).unwrap();
            assert_eq!(actual.task, initial.task);
            assert_eq!(actual.registers, expected.registers);
            assert_eq!(actual.xstate, expected.xstate);
            assert_eq!(actual.signal_mask, expected.mask);
            memory.unchanged(session.pid(), app);
            assert_eq!(
                session.read_memory(initial.task.task, BASE, 8192).unwrap(),
                memory.source
            );
            assert_eq!(session.provider().inputs.len(), index + 1);
            assert!(session.provider().expected.is_none() && !session.is_closed());
        }
    }));
    let pid = session.as_ref().unwrap().pid();
    let cleanup = session
        .take()
        .unwrap()
        .terminate(TIMEOUT)
        .unwrap_or_else(|_| std::process::abort());
    assert_eq!(cleanup.reaped, [pid]);
    let (Some(app), Some(broker)) = (app, broker) else {
        std::process::abort();
    };
    reaped(&app);
    reaped(&broker);
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
}
