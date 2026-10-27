use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime::native_tests::{
    bytes, exact_nx_maps, maps, ready, rows, start, state,
};
use crate::linux::remote::dynamic::owner::tests::{Fixture, Harness, pin, reaped};
use crate::linux::remote::dynamic::{Request as DynamicRequest, Response};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::AtomicU64;

pub(super) const TIMEOUT: Duration = Duration::from_secs(3);
pub(super) const BASE: u64 = 0x400000;
pub(super) const MARK: u64 = 0x1122_3344_5566_7788;
pub(super) const SCRIPT: SelectedResult = SelectedResult::Cpuid {
    eax: 0x7654_3210,
    ebx: 0xfedc_ba98,
    ecx: 0x1357_2468,
    edx: 0xabcd_1234,
};
static SESSION: AtomicU64 = AtomicU64::new(950_000);

pub(super) fn failure_diagnostic(label: &str, message: &str) {
    let bytes = message.as_bytes();
    let _ = writeln!(
        std::io::stderr().lock(),
        "runtime kernel {label}: {:?}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(8192)])
    );
}
pub(super) fn panic_diagnostic(label: &str, payload: &(dyn std::any::Any + Send)) {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("non-string panic payload");
    failure_diagnostic(label, message);
}

pub(super) fn live(pin: &OwnedFd) {
    let mut event = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut event, 1, 0) }, 0);
    assert_eq!(event.revents, 0);
}
pub(super) fn parent(pid: i32) -> i32 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let values = status
        .lines()
        .filter_map(|line| line.strip_prefix("PPid:\t"))
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 1);
    let parent = values[0].parse::<i32>().unwrap();
    assert!(parent > 1 && parent != pid && parent != std::process::id() as i32);
    parent
}
pub(super) fn options() -> DynamicRuntimeOptions {
    DynamicRuntimeOptions {
        kernel: RuntimeKernelProfile::IdentityAndTermination,
        ..DynamicRuntimeOptions::default()
    }
}
pub(super) fn code(number: u8, terminate: u8, cpu: bool) -> Vec<u8> {
    // Initial RAX is independently checked to be zero. Real MOV AL sets the
    // finite original number without a fixture-only register mutation.
    let mut code = vec![0xb0, number, 0x0f, 0x05];
    if cpu {
        code.extend_from_slice(&[0x0f, 0xa2, 0x49, 0xbc]);
        code.extend_from_slice(&MARK.to_le_bytes());
    }
    code.extend_from_slice(&[0xb8, terminate, 0, 0, 0, 0xbf, 7, 0, 0, 0, 0x0f, 0x05]);
    // Any mistaken return or extra original instruction changes a marker.
    code.extend_from_slice(&[0x49, 0xbd]);
    code.extend_from_slice(&(!MARK).to_le_bytes());
    code.extend_from_slice(&[0xeb, 0xfe]);
    code
}
pub(super) struct Memory {
    file: File,
    stack_start: u64,
    pub(super) stack: Vec<u8>,
    pub(super) source: Vec<u8>,
    pub(super) maps: Vec<u8>,
}
impl Memory {
    pub(super) fn capture(pid: i32, pin: &OwnedFd, inventory: Vec<u8>) -> Self {
        live(pin);
        let parsed = rows(&inventory);
        let stack = parsed
            .iter()
            .filter(|row| row.raw.ends_with(b"[stack]"))
            .collect::<Vec<_>>();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].permissions, *b"rw-p");
        let length = usize::try_from(stack[0].end - stack[0].start).unwrap();
        assert!((1..=1024 * 1024).contains(&length));
        let file = File::open(format!("/proc/{pid}/mem")).unwrap();
        let mut bytes = vec![0; length];
        file.read_exact_at(&mut bytes, stack[0].start).unwrap();
        let mut source = vec![0; 8192];
        file.read_exact_at(&mut source, BASE).unwrap();
        live(pin);
        Self {
            file,
            stack_start: stack[0].start,
            stack: bytes,
            source,
            maps: inventory,
        }
    }
    pub(super) fn unchanged(&self, pid: i32, pin: &OwnedFd) {
        live(pin);
        let mut stack = vec![0; self.stack.len()];
        self.file
            .read_exact_at(&mut stack, self.stack_start)
            .unwrap();
        let mut source = vec![0; 8192];
        self.file.read_exact_at(&mut source, BASE).unwrap();
        assert_eq!(stack, self.stack, "entire same-lane original stack changed");
        assert_eq!(source, self.source, "entire original ELF source changed");
        assert_eq!(
            maps(pid),
            self.maps,
            "complete same-lane NX inventory changed"
        );
        live(pin);
    }
}

pub(super) fn with_owner(
    entry: usize,
    code: &[u8],
    options: DynamicRuntimeOptions,
    action: impl FnOnce(&mut Owner, &OwnedFd, &Memory, Instant),
) {
    let fixture = if entry == 4096 {
        Fixture::code(code)
    } else {
        Fixture::code_at_entry(entry, code)
    };
    let mut harness = Harness::new();
    *harness.owner() = Owner::new(
        SESSION.fetch_add(1, Ordering::Relaxed),
        Arc::new(AtomicBool::new(false)),
    );
    harness.owner().lifecycle_options = Some(DynamicLifecycleOptions::default());
    // Existing Harness::launch has its own unchanged launch bound. This one
    // original absolute runtime bound starts first and gates every new effect.
    let until = Instant::now() + TIMEOUT;
    let launched = harness.launch(&fixture).unwrap();
    let pins = catch_unwind(AssertUnwindSafe(|| {
        (
            pin(launched.pid),
            pin(harness.owner().broker.as_ref().unwrap().pid),
        )
    }));
    let (app, broker) = pins.unwrap_or_else(|payload| {
        panic_diagnostic("initial pins", payload.as_ref());
        if let Err(error) = harness.owner().cleanup() {
            failure_diagnostic("pin cleanup", &format!("{error:?}"));
        }
        std::process::abort()
    });
    assert_ne!(app.as_raw_fd(), broker.as_raw_fd());
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        live(&app);
        live(&broker);
        let original = maps(launched.pid);
        let mut memory = Memory::capture(launched.pid, &app, original.clone());
        assert_eq!(&memory.source[entry..entry + code.len()], code);
        let initial = launched.event.stop_token().unwrap().clone();
        let ready = ready(start(harness.owner(), &initial, options, until));
        assert_eq!(ready.registers.rip, BASE + entry as u64);
        assert_eq!(
            (ready.registers.rax, ready.registers.orig_rax),
            (0, u64::MAX)
        );
        assert_eq!(
            state(launched.pid),
            TaskStateSnapshot {
                registers: ready.registers,
                xstate: ready.xstate.clone(),
                mask: ready.signal_mask
            }
        );
        let closed = maps(launched.pid);
        let island = &harness
            .owner()
            .runtime
            .as_ref()
            .unwrap()
            .bootstrap
            .as_ref()
            .unwrap()
            .completed()
            .unwrap()
            .island;
        exact_nx_maps(&original, &closed, &island.range);
        memory.maps = closed;
        memory.unchanged(launched.pid, &app);
        assert_eq!(bytes(launched.pid, BASE, 8192), memory.source);
        assert!(Instant::now() < until);
        action(harness.owner(), &app, &memory, until);
        assert!(Instant::now() < until);
        (
            archive::retained(harness.owner()),
            harness.owner().kernel_journal.reader().snapshot(),
        )
    }));
    if let Err(payload) = &outcome {
        // Preserve the first assertion failure before cleanup can fail-stop.
        panic_diagnostic("native body", payload.as_ref());
    }
    let cleanup = harness.owner().cleanup().unwrap_or_else(|error| {
        failure_diagnostic("physical cleanup", &format!("{error:?}"));
        std::process::abort()
    });
    assert_eq!(cleanup.reaped, [launched.pid]);
    reaped(&app);
    reaped(&broker);
    let outcome = match outcome {
        Ok((before, journal)) => {
            catch_unwind(AssertUnwindSafe(|| {
                assert_eq!(archive::retained(harness.owner()), before);
                let after = harness.owner().kernel_journal.reader().snapshot();
                assert_eq!(after.writer,crate::linux::remote::dynamic::owner::kernel_journal::KernelWriterStatus::Cleaned);
                assert!(!after.archive_poisoned);
                assert_eq!(after.runtime_attempts.len(), journal.runtime_attempts.len());
                for (old, new) in journal.runtime_attempts.iter().zip(&after.runtime_attempts) {
                    if old.failure.is_some() {assert_eq!(new.failure,old.failure);}
                else if old.facts.iter().any(|fact|matches!(fact,crate::linux::remote::dynamic::owner::kernel_journal::RuntimeKernelFact::ReturnCommitted{..}|crate::linux::remote::dynamic::owner::kernel_journal::RuntimeKernelFact::TerminalCommitted{..})) {assert_eq!(new.failure,None);}
                else {assert_eq!(new.failure.unwrap().kind,crate::linux::remote::dynamic::owner::kernel_journal::KernelFailureKind::Cancelled);}
                }
            }))
        }
        Err(payload) => Err(payload),
    };
    assert!(harness.finish().reaped.is_empty());
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Current {
    pub(super) state: TaskStateSnapshot,
    pub(super) stop: AdmissionStop,
    pub(super) observed: ObservedStop,
    pub(super) origin: OriginId,
    pub(super) rows: Vec<crate::linux::remote::dynamic::owner::admission::census::OriginRow>,
    pub(super) history: crate::linux::remote::dynamic::owner::admission::census::HistorySnapshot,
    pub(super) charged: BudgetCharge,
    pub(super) used: BudgetCharge,
}
pub(super) fn current(owner: &Owner, app: &OwnedFd, memory: &Memory, until: Instant) -> Current {
    assert!(Instant::now() < until);
    memory.unchanged(owner.pid, app);
    let runtime = owner.runtime.as_ref().unwrap();
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
    assert_eq!(observed.token, stop.token);
    assert_eq!(observed.task, stop.identity);
    assert!(observed.signal.is_none() && stop.signal.is_none());
    let actual = state(owner.pid);
    assert_eq!(
        actual,
        TaskStateSnapshot {
            registers: observed.registers,
            xstate: observed.xstate.clone(),
            mask: observed.signal_mask
        }
    );
    assert_eq!(observed.logical_pc, actual.registers.rip);
    assert!(Instant::now() < until);
    Current {
        state: actual,
        stop,
        observed,
        origin,
        rows: census.rows().cloned().collect(),
        history: census.history_snapshot().unwrap(),
        charged: census.charged(),
        used: census.used(),
    }
}
pub(super) fn same_current(a: &Current, b: &Current) {
    assert_eq!(a.state, b.state);
    assert_eq!(a.stop, b.stop);
    assert_eq!(a.observed, b.observed);
    assert_eq!(a.origin, b.origin);
    assert_eq!(a.rows, b.rows);
    assert_eq!(a.history, b.history);
}
pub(super) fn invoke(
    owner: &mut Owner,
    request: AdmissionRequest,
    until: Instant,
) -> Result<AdmissionReply, GateError> {
    match owner
        .execute(DynamicRequest::Admission(Box::new(request)), until)
        .unwrap()
    {
        Response::Admission(reply) => *reply,
        _ => panic!("runtime kernel response namespace differs"),
    }
}
pub(super) fn pending(owner: &mut Owner, until: Instant) -> Box<RuntimeProviderInput> {
    match invoke(owner, AdmissionRequest::Advance, until).unwrap() {
        AdmissionReply::RuntimeProvider(input) => input,
        _ => panic!("original selected invocation did not request provider decision"),
    }
}
pub(super) fn complete(
    owner: &mut Owner,
    input: &RuntimeProviderInput,
    decision: ProviderDecision,
    until: Instant,
) -> Result<AdmissionReply, GateError> {
    invoke(
        owner,
        AdmissionRequest::CompleteRuntime {
            token: input.token.clone(),
            decision,
        },
        until,
    )
}
pub(super) fn syscall_after(before: &TaskStateSnapshot, pid: i32) -> TaskStateSnapshot {
    let mut after = before.clone();
    after.registers.rip += 2;
    after.registers.rcx = after.registers.rip;
    after.registers.r11 = before.registers.eflags & !0x10000;
    after.registers.eflags &= !0x10000;
    after.registers.orig_rax = before.registers.rax;
    after.registers.rax = pid as u64;
    after
}
pub(super) fn cpu_after(before: &TaskStateSnapshot) -> TaskStateSnapshot {
    let mut after = before.clone();
    after.registers.rip += 2;
    after.registers.rax = 0x7654_3210;
    after.registers.rbx = 0xfedc_ba98;
    after.registers.rcx = 0x1357_2468;
    after.registers.rdx = 0xabcd_1234;
    after
}
pub(super) fn completed(
    reply: AdmissionReply,
    before: &Current,
    input: &RuntimeProviderInput,
    expected: &TaskStateSnapshot,
    execution: SelectedExecution,
) {
    let AdmissionReply::Event(DynamicAdmissionEvent::Completed(value)) = reply else {
        panic!("missing exact returning completion")
    };
    assert_eq!(
        (value.before_task, value.after_task),
        (before.observed.task, before.observed.task)
    );
    assert_eq!(value.selected.input, input.input);
    assert_eq!(value.selected.execution, execution);
    assert_eq!(value.selected.after, expected.registers);
    assert_eq!(value.selected.before_xstate, before.state.xstate);
    assert_eq!(value.selected.xstate, expected.xstate);
    assert_eq!(value.before_signal_mask, before.state.mask);
    assert_eq!(value.signal_mask, expected.mask);
}
pub(super) fn advance_count(before: &Current, after: &Current, origins: usize, witnesses: usize) {
    assert_eq!(&after.rows[..before.rows.len()], before.rows.as_slice());
    assert_eq!(
        after.history.prefix(before.history.len()).unwrap(),
        before.history
    );
    assert_eq!(after.rows.len(), before.rows.len() + origins);
    assert_eq!(after.history.len(), before.history.len() + witnesses);
    assert_eq!(after.used.origins, before.used.origins + origins);
    assert_eq!(after.used.witnesses, before.used.witnesses + witnesses);
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
    assert!(after.used.source_fact_bytes > before.used.source_fact_bytes);
    for (used, charged) in [
        (after.used.epochs, after.charged.epochs),
        (after.used.origins, after.charged.origins),
        (after.used.witnesses, after.charged.witnesses),
        (after.used.reports, after.charged.reports),
        (after.used.plan_history, after.charged.plan_history),
        (
            after.used.source_fact_bytes,
            after.charged.source_fact_bytes,
        ),
    ] {
        assert!(used <= charged);
    }
    assert!(after.charged.source_fact_bytes <= DynamicAdmissionLimits::default().source_fact_bytes);
}
