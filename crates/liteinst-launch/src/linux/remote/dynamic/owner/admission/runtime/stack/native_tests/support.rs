use super::*;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicU64;
static SESSION: AtomicU64 = AtomicU64::new(990_000);
pub(super) const TIMEOUT: Duration = Duration::from_secs(3);
pub(super) struct Before {
    initial: crate::linux::remote::dynamic::DynamicEvent,
    pub(super) state: TaskStateSnapshot,
    pub(super) maps: Vec<u8>,
    pub(super) source: Vec<u8>,
    pub(super) stack_range: std::ops::Range<u64>,
    /// Positive fixtures retain the complete stack before admission. A read
    /// does not establish exclusivity; cross-page fixtures check actual page
    /// eligibility first. Negative raw fixtures never select this mode.
    pub(super) stack: Option<Vec<u8>>,
    pub(super) memory: File,
}
impl Before {
    pub(super) fn capture(
        owner: &Owner,
        initial: &crate::linux::remote::dynamic::DynamicEvent,
        until: Instant,
        read_stack: bool,
        cross_page_stack: bool,
    ) -> Self {
        held(owner, until);
        assert_eq!(initial.tid, owner.pid);
        owner.require_stop(initial.stop_token().unwrap()).unwrap();
        let inventory = maps(owner.pid);
        let parsed = rows(&inventory);
        let stack = parsed
            .iter()
            .filter(|row| row.raw.ends_with(b"[stack]"))
            .collect::<Vec<_>>();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].permissions, *b"rw-p");
        let range = stack[0].start..stack[0].end;
        let length = usize::try_from(range.end - range.start).unwrap();
        assert!((1..=1024 * 1024).contains(&length));
        // Check both real entries before opening mem or touching any stack byte.
        let initial_pair = cross_page_stack.then(|| {
            assert!(read_stack);
            resident_pair(owner, until, &range)
        });
        let memory = File::open(format!("/proc/{}/mem", owner.pid)).unwrap();
        // Validate the actual fixed table after eligibility and before the
        // complete stack read; retain it for the later unchanged-byte check.
        let initial_table = initial_pair.as_ref().map(|initial| {
            held(owner, until);
            let mut table = [0_u8; 4120];
            assert_eq!(
                memory.read_at(&mut table, initial.registers.rsp).unwrap(),
                table.len()
            );
            let word = |index: usize| {
                u64::from_le_bytes(table[index * 8..(index + 1) * 8].try_into().unwrap())
            };
            assert_eq!(word(0), 513);
            assert_eq!(word(514), 0);
            for index in 1..=513 {
                assert!(range.contains(&word(index)));
            }
            held(owner, until);
            table
        });
        let stack = read_stack.then(|| {
            let mut bytes = vec![0; length];
            memory.read_exact_at(&mut bytes, range.start).unwrap();
            bytes
        });
        let mut source = vec![0; 8192];
        memory.read_exact_at(&mut source, BASE).unwrap();
        let value = Self {
            initial: initial.clone(),
            state: state(owner.pid),
            maps: inventory,
            source,
            stack_range: range,
            stack,
            memory,
        };
        if let Some(initial) = initial_pair {
            assert_eq!(value.state, initial);
            let original = value.stack.as_ref().unwrap();
            let start = usize::try_from(initial.registers.rsp - value.stack_range.start).unwrap();
            let table = &original[start..start + 4120];
            assert_eq!(table, initial_table.as_ref().unwrap());
            let word = |index: usize| {
                u64::from_le_bytes(table[index * 8..(index + 1) * 8].try_into().unwrap())
            };
            assert_eq!(word(0), 513);
            assert_eq!(word(514), 0);
            for index in 1..=513 {
                let pointer = word(index);
                assert!(value.stack_range.contains(&pointer));
                if index > 1 {
                    let offset = usize::try_from(pointer - value.stack_range.start).unwrap();
                    assert_eq!(original[offset], 0);
                }
            }
            owner
                .require_stop(value.initial.stop_token().unwrap())
                .unwrap();
        }
        held(owner, until);
        value
    }
    pub(super) fn read_stack(&self, owner: &Owner, until: Instant) -> Vec<u8> {
        let custody = diagnostic_held(owner, until);
        let mut value =
            vec![0; usize::try_from(self.stack_range.end - self.stack_range.start).unwrap()];
        self.memory
            .read_exact_at(&mut value, self.stack_range.start)
            .unwrap();
        assert_eq!(diagnostic_held(owner, until), custody);
        value
    }
    pub(super) fn require_source(&self, owner: &Owner, until: Instant) {
        let custody = diagnostic_held(owner, until);
        let mut actual = vec![0; 8192];
        self.memory.read_exact_at(&mut actual, BASE).unwrap();
        assert_eq!(actual, self.source);
        assert_eq!(diagnostic_held(owner, until), custody);
    }
}
/// Independent positive-fixture check, not an operand or completion authority.
fn resident_pair(owner: &Owner, until: Instant, stack: &std::ops::Range<u64>) -> TaskStateSnapshot {
    held(owner, until);
    let initial = state(owner.pid);
    let rsp = initial.registers.rsp;
    assert_eq!(rsp & 15, 0);
    let table_end = rsp.checked_add(4120).unwrap();
    assert!(stack.start <= rsp && table_end <= stack.end);
    let boundary = (rsp & !4095).checked_add(4096).unwrap();
    let first = boundary.checked_sub(8).unwrap();
    let end = boundary.checked_add(8).unwrap();
    assert!(rsp <= first && end <= table_end);
    assert!(stack.start <= first && end <= stack.end);
    assert_eq!((end - 1) / 4096, first / 4096 + 1);
    let offset = (first / 4096).checked_mul(8).unwrap();
    let pagemap = File::open(format!("/proc/{}/pagemap", owner.pid)).unwrap();
    let mut entries = [0_u8; 16];
    assert_eq!(pagemap.read_at(&mut entries, offset).unwrap(), 16);
    const PRESENT: u64 = 1 << 63;
    const EXCLUSIVE: u64 = 1 << 56;
    const ALLOWED: u64 = PRESENT | EXCLUSIVE | (1 << 55) | ((1 << 55) - 1);
    for bytes in entries.chunks_exact(8) {
        let entry = u64::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(entry & (PRESENT | EXCLUSIVE), PRESENT | EXCLUSIVE);
        assert_eq!(entry & !ALLOWED, 0);
    }
    drop(pagemap);
    held(owner, until);
    initial
}
pub(super) fn held(owner: &Owner, until: Instant) {
    owner
        .time_left(until, "stack oracle original deadline")
        .unwrap();
    assert!(owner.owned.contains(&owner.pid));
    assert!(
        owner
            .stopped
            .get(&owner.pid)
            .is_some_and(|s| libc::WIFSTOPPED(*s))
    );
    assert!(
        owner
            .handles
            .get(&owner.pid)
            .is_some_and(|pin| !broker::hup(pin))
    );
}
/// Physical read-only custody, including after cancellation. This does not
/// authorize an owner operation, reset cancellation, or extend its deadline.
/// Compare the same retained task/pin/status on both sides of every read.
pub(super) fn diagnostic_held(
    owner: &Owner,
    until: Instant,
) -> (libc::pid_t, i32, i32, bool, bool) {
    assert!(Instant::now() < until, "stack diagnostic original deadline");
    assert!(owner.pid > 0 && owner.attached);
    assert!(!owner.lost_wait && !owner.missing_pin);
    assert!(owner.owned.contains(&owner.pid));
    assert!(!owner.reaped.contains(&owner.pid));
    assert!(!owner.tracer_terminal.contains_key(&owner.pid));
    let status = *owner.stopped.get(&owner.pid).unwrap();
    assert!(libc::WIFSTOPPED(status));
    assert_ne!(status >> 16, libc::PTRACE_EVENT_EXIT);
    let pin = owner.handles.get(&owner.pid).unwrap();
    let mut event = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    // SAFETY: initialized poll entry; the original Owner still owns this pidfd.
    assert_eq!(unsafe { libc::poll(&raw mut event, 1, 0) }, 0);
    assert_eq!(event.revents, 0);
    assert!(Instant::now() < until, "stack diagnostic original deadline");
    (
        owner.pid,
        pin.as_raw_fd(),
        status,
        owner.closing,
        owner.cancel.load(Ordering::Acquire),
    )
}

pub(super) fn require_diagnostic_held(owner: &Owner, until: Instant) {
    diagnostic_held(owner, until);
}

pub(super) fn observe_state(owner: &Owner, until: Instant) -> TaskStateSnapshot {
    let custody = diagnostic_held(owner, until);
    let observed = state(owner.pid);
    assert_eq!(diagnostic_held(owner, until), custody);
    observed
}

pub(super) fn observe_maps(owner: &Owner, until: Instant) -> Vec<u8> {
    let custody = diagnostic_held(owner, until);
    let observed = maps(owner.pid);
    assert_eq!(diagnostic_held(owner, until), custody);
    observed
}

pub(super) fn diagnostic(label: &str, payload: &(dyn std::any::Any + Send)) {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("non-string sentinel");
    let bytes = message.as_bytes();
    let _ = writeln!(
        std::io::stderr().lock(),
        "owned stack {label}: {:?}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(8192)])
    );
}
pub(super) fn with_owner<T>(
    program: &Program,
    read_stack: bool,
    action: impl FnOnce(&mut Owner, &DynamicStop, Instant, &Before) -> T,
    after_cleanup: impl FnOnce(&Owner, &T),
) -> T {
    let mut harness = Harness::new();
    *harness.owner() = Owner::new(
        SESSION.fetch_add(1, Ordering::Relaxed),
        Arc::new(AtomicBool::new(false)),
    );
    harness.owner().lifecycle_options = Some(DynamicLifecycleOptions::default());
    let until = Instant::now() + TIMEOUT;
    let cross_page_stack = program.cross_page_stack();
    let launched = if cross_page_stack {
        harness.launch_stack_pair(&program.fixture, until).unwrap()
    } else {
        harness.launch(&program.fixture).unwrap()
    };
    let app = pin(launched.pid);
    let helper = pin(harness.owner().broker.as_ref().unwrap().pid);
    assert_ne!(app.as_raw_fd(), helper.as_raw_fd());
    let initial = launched.event.stop_token().unwrap().clone();
    // This owner survives the action catch, including partial preparation.
    let mut preparation = seed::Evidence::empty(program.preparation);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        preparation.prepare(harness.owner(), &launched.event, program, until, read_stack);
        let before = Before::capture(
            harness.owner(),
            &launched.event,
            until,
            read_stack,
            cross_page_stack,
        );
        assert_eq!(before.state.registers.rip, program.entry);
        assert_eq!(before.state.registers.orig_rax, libc::SYS_execve as u64);
        preparation.require_before(&before);
        action(harness.owner(), &initial, until, &before)
    }));
    if let Err(payload) = &outcome {
        diagnostic("body", payload.as_ref());
    }
    let prepared = catch_unwind(AssertUnwindSafe(|| preparation.retained()));
    let cleanup = harness.owner().cleanup().unwrap_or_else(|error| {
        let _ = writeln!(std::io::stderr().lock(), "owned stack cleanup: {error:?}");
        std::process::abort()
    });
    assert_eq!(cleanup.reaped, [launched.pid]);
    reaped(&app);
    reaped(&helper);
    let retained = match prepared {
        Ok(check) => catch_unwind(AssertUnwindSafe(|| {
            check(&preparation);
            preparation.require_attempts(harness.owner());
        })),
        Err(payload) => Err(payload),
    };
    let outcome = match (outcome, retained) {
        (Err(first), Err(secondary)) => {
            diagnostic("secondary seed retention", secondary.as_ref());
            Err(first)
        }
        (Err(first), Ok(())) => Err(first),
        (Ok(_), Err(payload)) => Err(payload),
        (Ok(value), Ok(())) => Ok(value),
    };
    let outcome = match outcome {
        Ok(value) => catch_unwind(AssertUnwindSafe(|| {
            after_cleanup(harness.owner(), &value);
            value
        })),
        Err(payload) => Err(payload),
    };
    assert!(harness.finish().reaped.is_empty());
    match outcome {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    }
}
pub(super) fn options() -> DynamicRuntimeOptions {
    DynamicRuntimeOptions {
        stack: RuntimeStackProfile::OriginalResidentWord,
        ..DynamicRuntimeOptions::default()
    }
}
pub(super) fn begin(
    owner: &mut Owner,
    initial: &DynamicStop,
    until: Instant,
    before: &Before,
    options: DynamicRuntimeOptions,
) -> TaskStateSnapshot {
    let reply = ready(start(owner, initial, options, until));
    let runtime = owner.runtime.as_ref().unwrap();
    let boot = runtime.bootstrap.as_ref().unwrap().completed().unwrap();
    assert_eq!(boot.evidence.exec_event, before.state);
    let mut exit = before.state.clone();
    exit.registers.rax = 0;
    assert_eq!(boot.evidence.exec_exit, exit);
    let mut first = exit.registers;
    first.rip += 1;
    first.orig_rax = u64::MAX;
    assert_eq!(boot.evidence.entry_trap.registers, first);
    assert_eq!(boot.evidence.entry_trap.mask, exit.mask);
    let mut expected = boot.evidence.entry_trap.clone();
    expected.registers.rip -= 1;
    assert_eq!(boot.evidence.restored_entry, expected);
    assert_eq!(state(owner.pid), expected);
    assert_eq!(reply.registers, expected.registers);
    assert_eq!(reply.xstate, expected.xstate);
    assert_eq!(reply.signal_mask, expected.mask);
    exact_nx_maps(&before.maps, &maps(owner.pid), &boot.island.range);
    assert_eq!(
        runtime.sources.runtime_baseline_maps().unwrap(),
        maps(owner.pid)
    );
    assert_eq!(runtime.sources.window_count(), 1);
    assert_eq!(
        runtime.sources.window(0).unwrap().snapshot.bytes(),
        before.source
    );
    assert!(runtime.pages.iter().all(|page| !page.executable));
    if let Some(stack) = &runtime.stack {
        assert!(stack.startup_complete);
        assert_eq!(stack.startup_actual, stack.startup_settled);
        assert!(stack.failure.is_none() && stack.settlement_failure.is_none());
        let identity = stack.profile.identity().unwrap();
        assert_eq!(identity.description().initial_rsp, expected.registers.rsp);
        assert_eq!(identity.description().stack.range(), before.stack_range);
    }
    before.require_source(owner, until);
    if let Some(original) = &before.stack {
        assert_eq!(before.read_stack(owner, until), *original);
    }
    expected
}
/// Calls the connected root adapter at one actual PC, retaining the same
/// catch/reinstall discipline so assertions can observe each stack boundary.
/// Public Advance is separately exercised for refusal and mixed-chain tests.
pub(super) fn one(owner: &mut Owner, until: Instant) -> Result<(), GateError> {
    let mut runtime = owner.runtime.take().unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let current = runtime
            .census
            .as_ref()
            .unwrap()
            .current_observation(runtime.initial_origin.unwrap())
            .unwrap();
        let index = runtime
            .pages
            .iter()
            .find(|page| page.address == (current.logical_pc & !4095))
            .unwrap()
            .window;
        runtime.stack(owner, index, until)
    }));
    owner.runtime = Some(runtime);
    match result {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    }
}
pub(super) fn ordinary(owner: &mut Owner, until: Instant) {
    let mut runtime = owner.runtime.take().unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let pc = runtime
            .census
            .as_ref()
            .unwrap()
            .current_observation(runtime.initial_origin.unwrap())
            .unwrap()
            .logical_pc;
        let index = runtime
            .pages
            .iter()
            .find(|page| page.address == (pc & !4095))
            .unwrap()
            .window;
        runtime.ordinary(owner, index, until)
    }));
    owner.runtime = Some(runtime);
    match result {
        Ok(value) => value.unwrap(),
        Err(payload) => resume_unwind(payload),
    }
}
pub(super) fn invoke(
    owner: &mut Owner,
    request: AdmissionRequest,
    until: Instant,
) -> Result<AdmissionReply, GateError> {
    match owner
        .execute(DynamicRequest::Admission(Box::new(request)), until)
        .map_err(GateError::Control)?
    {
        Response::Admission(reply) => *reply,
        _ => panic!("stack response namespace differs"),
    }
}

/// Expected early unwinds use the real command receiver and client transport,
/// on the original tracer thread. The client must observe reply disconnect and
/// cancel before its Session drops. No flag is assigned by this helper. The
/// caller still inspects the exact panic payload and all held evidence before
/// actual cleanup establishes closing. This is a scoped transport oracle, not
/// a claim that public owner::run returns the original panic to its client.
pub(super) fn invoke_unwind(
    owner: &mut Owner,
    before: &Before,
    request: AdmissionRequest,
    until: Instant,
) -> ! {
    held(owner, until);
    assert!(!owner.closing && !owner.cancel.load(Ordering::Acquire));
    assert_eq!(before.initial.tid, owner.pid);
    let (commands, receiver) = std::sync::mpsc::channel();
    // No completion receipt is manufactured or consumed. Physical cleanup and
    // both original pins remain with with_owner on this same tracer thread.
    let (_done_sender, done) = std::sync::mpsc::channel();
    let mut session = crate::linux::remote::dynamic::DynamicSession {
        pid: owner.pid,
        initial: before.initial.clone(),
        commands,
        cancel: Arc::clone(&owner.cancel),
        done,
        operation_timeout: TIMEOUT,
    };
    let (outcome, client) = std::thread::scope(|scope| {
        let client = scope.spawn(move || {
            let reply = session.admission_call_for_journal_test(request, until, until);
            let cancelled_before_drop = session.cancel.load(Ordering::Acquire);
            (reply, cancelled_before_drop)
        });
        let outcome = catch_unwind(AssertUnwindSafe(|| owner.serve(receiver)));
        // The client's wait uses the original absolute until. Join before any
        // diagnostic reads; no child/owner wait domain moves to this thread.
        (outcome, client.join())
    });
    let (reply, cancelled_before_drop) = match client {
        Ok(result) => result,
        Err(payload) => resume_unwind(payload),
    };
    assert!(matches!(
        reply,
        Err(GateError::Control(LaunchError::Invalid(
            "dynamic tracer is closed"
        )))
    ));
    assert!(cancelled_before_drop);
    assert!(owner.cancel.load(Ordering::Acquire));
    assert!(!owner.closing, "early unwind precedes physical cleanup");
    match outcome {
        Err(payload) => resume_unwind(payload),
        Ok(_) => panic!("expected actual owner serve unwind"),
    }
}

/// Two-pin lower-layer fixture. There is deliberately no runtime startup or
/// original-stack permit. All newborn pidfds are retained before the body can
/// continue, and both actual task terminal states are checked after cleanup.
pub(super) fn with_raw_owner<T: FnOnce()>(
    program: &Program,
    action: impl FnOnce(&mut Owner, &DynamicStop, Instant, &Before) -> T,
) {
    assert_eq!(
        program.preparation,
        fixture::InitialStackPreparation::Unchanged
    );
    let mut harness = Harness::new();
    *harness.owner() = Owner::new(
        SESSION.fetch_add(1, Ordering::Relaxed),
        Arc::new(AtomicBool::new(false)),
    );
    harness.owner().lifecycle_options = Some(DynamicLifecycleOptions::default());
    let until = Instant::now() + TIMEOUT;
    let ready = harness.launch(&program.fixture).unwrap();
    let app = pin(ready.pid);
    let helper = pin(harness.owner().broker.as_ref().unwrap().pid);
    let initial = ready.event.stop_token().unwrap().clone();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let before = Before::capture(harness.owner(), &ready.event, until, false, false);
        assert!(before.stack.is_none());
        action(harness.owner(), &initial, until, &before)
    }));
    if let Err(payload) = &outcome {
        diagnostic("raw lower fixture", payload.as_ref());
    }
    let expected = harness.owner().owned.iter().copied().collect::<Vec<_>>();
    let pins = expected
        .iter()
        .filter(|pid| **pid != ready.pid)
        .map(|pid| pin(*pid))
        .collect::<Vec<_>>();
    let cleanup = harness.owner().cleanup().unwrap_or_else(|error| {
        let _ = writeln!(
            std::io::stderr().lock(),
            "owned stack raw cleanup: {error:?}"
        );
        std::process::abort()
    });
    let mut actual = cleanup.reaped;
    actual.sort();
    assert_eq!(actual, expected);
    reaped(&app);
    for pin in &pins {
        reaped(pin);
    }
    reaped(&helper);
    // The action returns an owning evidence check: every successful or failed
    // raw prefix remains alive until all original pins have been reaped.
    let outcome = match outcome {
        Ok(check) => catch_unwind(AssertUnwindSafe(check)),
        Err(payload) => Err(payload),
    };
    assert!(harness.finish().reaped.is_empty());
    match outcome {
        Ok(()) => {}
        Err(payload) => resume_unwind(payload),
    }
}

/// Extract an expected unwind without a Debug bound on successful wire replies.
pub(super) fn panic_payload<T>(result: std::thread::Result<T>) -> Box<dyn std::any::Any + Send> {
    match result {
        Err(payload) => payload,
        Ok(_) => panic!("expected the original sentinel unwind"),
    }
}
pub(super) fn sum(a: BudgetCharge, b: BudgetCharge) -> BudgetCharge {
    BudgetCharge {
        epochs: a.epochs.checked_add(b.epochs).unwrap(),
        source_fact_bytes: a
            .source_fact_bytes
            .checked_add(b.source_fact_bytes)
            .unwrap(),
        reports: a.reports.checked_add(b.reports).unwrap(),
        origins: a.origins.checked_add(b.origins).unwrap(),
        witnesses: a.witnesses.checked_add(b.witnesses).unwrap(),
        plan_history: a.plan_history.checked_add(b.plan_history).unwrap(),
    }
}
