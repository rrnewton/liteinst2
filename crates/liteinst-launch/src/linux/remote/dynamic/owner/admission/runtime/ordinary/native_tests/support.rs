use super::*;
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicU64;
static SESSION: AtomicU64 = AtomicU64::new(920_000);

pub(super) const BASE: u64 = 0x400000;
pub(super) const ENTRY: u64 = BASE + 4096;
const TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct Before {
    pub(super) initial: crate::linux::remote::dynamic::DynamicEvent,
    pub(super) state: TaskStateSnapshot,
    pub(super) maps: Vec<u8>,
    pub(super) source: Vec<u8>,
    memory: std::fs::File,
    stack_start: u64,
    stack: Vec<u8>,
}

impl Before {
    pub(super) fn diagnostic_stack(&self) -> (&std::fs::File, u64, &[u8]) {
        (&self.memory, self.stack_start, &self.stack)
    }

    pub(super) fn stack_unchanged(&self, owner: &Owner, until: Instant) {
        owner
            .time_left(until, "ordinary full stack observation")
            .unwrap();
        assert!(
            owner
                .handles
                .get(&owner.pid)
                .is_some_and(|pin| !broker::hup(pin))
        );
        assert!(
            owner
                .stopped
                .get(&owner.pid)
                .is_some_and(|status| libc::WIFSTOPPED(*status))
        );
        let mut actual = vec![0; self.stack.len()];
        self.memory
            .read_exact_at(&mut actual, self.stack_start)
            .unwrap();
        assert_eq!(actual, self.stack);
        assert!(
            owner
                .handles
                .get(&owner.pid)
                .is_some_and(|pin| !broker::hup(pin))
        );
        owner
            .time_left(until, "ordinary full stack observation complete")
            .unwrap();
    }
}

/// Same private Owner/Harness custody as the startup controls, but no fixed
/// CODE assumption. A failed assertion is rethrown only after both pins reap.
pub(super) fn with_owner<T>(
    fixture: &Fixture,
    code: &[u8],
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
    let ready = harness.launch(fixture).unwrap();
    let app = pin(ready.pid);
    let broker = pin(harness.owner().broker.as_ref().unwrap().pid);
    let initial = ready.event.stop_token().unwrap().clone();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let original_maps = maps(ready.pid);
        let stacks = rows(&original_maps)
            .into_iter()
            .filter(|row| row.raw.ends_with(b"[stack]"))
            .collect::<Vec<_>>();
        assert_eq!(stacks.len(), 1);
        assert_eq!(stacks[0].permissions, *b"rw-p");
        let stack_length = usize::try_from(stacks[0].end - stacks[0].start).unwrap();
        assert!((1..=1024 * 1024).contains(&stack_length));
        assert!(
            harness
                .owner()
                .handles
                .get(&ready.pid)
                .is_some_and(|pin| !broker::hup(pin))
        );
        let memory_file = std::fs::File::open(format!("/proc/{}/mem", ready.pid)).unwrap();
        let mut stack = vec![0; stack_length];
        memory_file
            .read_exact_at(&mut stack, stacks[0].start)
            .unwrap();
        let before = Before {
            initial: ready.event.clone(),
            state: state(ready.pid),
            maps: original_maps,
            source: memory(ready.pid, BASE, 8192),
            memory: memory_file,
            stack_start: stacks[0].start,
            stack,
        };
        before.stack_unchanged(harness.owner(), until);
        assert_eq!(before.state.registers.rip, ENTRY);
        assert_eq!(before.state.registers.orig_rax, libc::SYS_execve as u64);
        assert_eq!(
            before.state.registers.rax,
            (-i64::from(libc::ENOSYS)) as u64
        );
        assert_eq!(&before.source[4096..4096 + code.len()], code);
        let main = rows(&before.maps)
            .into_iter()
            .filter(|row| row.start == BASE && row.end == BASE + 8192)
            .collect::<Vec<_>>();
        assert_eq!(main.len(), 1);
        assert_eq!(main[0].permissions, *b"r-xp");
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
    assert!(harness.finish().reaped.is_empty());
    match outcome {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    }
}

pub(super) fn begin(
    owner: &mut Owner,
    initial: &DynamicStop,
    until: Instant,
    before: &Before,
) -> TaskStateSnapshot {
    let ready = ready(start(
        owner,
        initial,
        DynamicRuntimeOptions::default(),
        until,
    ));
    let runtime = owner.runtime.as_ref().unwrap();
    let boot = runtime.bootstrap.as_ref().unwrap().completed().unwrap();
    assert_eq!(boot.evidence.exec_event, before.state);
    let mut exit = before.state.clone();
    exit.registers.rax = 0;
    assert_eq!(boot.evidence.exec_exit, exit);
    let mut first = exit.registers;
    first.rip = ENTRY + 1;
    first.orig_rax = u64::MAX;
    assert_eq!(boot.evidence.entry_trap.registers, first);
    assert_eq!(boot.evidence.entry_trap.mask, exit.mask);
    let mut expected = boot.evidence.entry_trap.clone();
    expected.registers.rip = ENTRY;
    assert_eq!(boot.evidence.restored_entry, expected);
    assert_eq!(state(owner.pid), expected);
    before.stack_unchanged(owner, until);
    assert_eq!(ready.registers, expected.registers);
    assert_eq!(ready.xstate, expected.xstate);
    assert_eq!(ready.signal_mask, expected.mask);
    assert_eq!(ready.task, boot.stop.identity);
    assert_eq!(runtime.stage, RuntimeStage::Ready);
    assert_eq!(runtime.until, until);
    assert!(runtime.ready_issued && runtime.control_lineage.is_some());
    assert!(runtime.sources.capture_complete() && runtime.sources.recheck_complete());
    assert_eq!(runtime.sources.failure(), None);
    assert_eq!(runtime.sources.vmas().len(), 1);
    assert_eq!(runtime.sources.window_count(), 1);
    assert_eq!(
        runtime.sources.window(0).unwrap().snapshot.bytes(),
        before.source
    );
    assert_eq!(memory(owner.pid, BASE, 8192), before.source);
    exact_nx_maps(&before.maps, &maps(owner.pid), &boot.island.range);
    assert_eq!(
        runtime.sources.runtime_baseline_maps().unwrap(),
        maps(owner.pid)
    );
    let census = runtime.census.as_ref().unwrap();
    assert_eq!(census.history().len(), 0);
    assert_eq!(census.rows().count(), 1);
    assert_eq!(census.active().count(), 1);
    assert_eq!(
        runtime
            .native
            .as_ref()
            .unwrap()
            .admission_current(ready.task.task)
            .unwrap(),
        boot.stop
    );
    assert!(!owner.closing && !owner.cancel.load(Ordering::Acquire));
    expected
}

pub(super) fn one(owner: &mut Owner, until: Instant) {
    let mut runtime = owner.runtime.take().unwrap();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let census = runtime.census.as_ref().unwrap();
        let pc = census
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
    match outcome {
        Ok(result) => result.unwrap(),
        Err(payload) => resume_unwind(payload),
    }
}

fn same_architecture(observed: &ObservedStop, expected: &TaskStateSnapshot) {
    assert_eq!(observed.logical_pc, expected.registers.rip);
    assert_eq!(observed.registers, expected.registers);
    assert_eq!(observed.xstate, expected.xstate);
    assert_eq!(observed.signal_mask, expected.mask);
}

// Full resolved header/bytes; this borrowed view grants no native authority.
fn same_history_architecture(observed: census::ObservationView<'_>, expected: &TaskStateSnapshot) {
    assert_eq!(observed.logical_pc, expected.registers.rip);
    assert_eq!(*observed.registers, expected.registers);
    assert_eq!(observed.xstate, expected.xstate.as_slice());
    assert_eq!(observed.signal_mask, expected.mask);
}

fn complete(slot: &StateSlot) {
    assert!(slot.complete);
    for query in [
        slot.registers_request,
        slot.xstate_request,
        slot.mask_request,
    ] {
        assert_eq!(
            query,
            Some(NativeRequest {
                result: 0,
                errno: None
            })
        );
    }
    assert_eq!(slot.returned_pointer, slot.requested_pointer);
    assert_eq!(slot.returned_length, slot.state.xstate.len());
    assert!((512..MAX_XSTATE).contains(&slot.returned_length));
}

/// Independent literal-fixture projection. Only the full two-page main VMA
/// splits; the first page stays NX and the exact second page becomes RX. Its
/// backing suffix stays byte-identical and its offset advances by one page.
fn opened_maps(baseline: &[u8], actual: &[u8]) {
    let baseline = rows(baseline);
    let mut expected = Vec::new();
    let mut split = 0;
    for row in baseline {
        if row.start == BASE && row.end == BASE + 8192 {
            split += 1;
            assert_eq!(row.permissions, *b"r--p");
            let range_end = row.raw.iter().position(|byte| *byte == b' ').unwrap();
            let offset_start = range_end + 6;
            let offset_end = offset_start
                + row.raw[offset_start..]
                    .iter()
                    .position(|byte| *byte == b' ')
                    .unwrap();
            let offset = u64::from_str_radix(
                std::str::from_utf8(&row.raw[offset_start..offset_end]).unwrap(),
                16,
            )
            .unwrap();
            assert_eq!(offset, 0);
            for (start, end, permissions) in
                [(BASE, ENTRY, *b"r--p"), (ENTRY, BASE + 8192, *b"r-xp")]
            {
                expected.extend_from_slice(format!("{start:08x}-{end:08x} ").as_bytes());
                expected.extend_from_slice(&permissions);
                expected.push(b' ');
                expected.extend_from_slice(format!("{:08x}", offset + start - BASE).as_bytes());
                expected.extend_from_slice(&row.raw[offset_end..]);
                expected.push(b'\n');
            }
        } else {
            expected.extend_from_slice(&row.raw);
            expected.push(b'\n');
        }
    }
    assert_eq!(split, 1);
    assert_eq!(actual, expected);
}

/// Read both current native state and the independently retained raw request
/// results. Expected state is authored from the literal instruction, never
/// from the completion's own successor. Every comparison is full and exact.
pub(super) fn check(
    owner: &Owner,
    before: &TaskStateSnapshot,
    expected: &TaskStateSnapshot,
    original: &Before,
    ordinal: usize,
    until: Instant,
) {
    owner
        .time_left(until, "ordinary native control observation")
        .unwrap();
    assert_eq!(state(owner.pid), *expected);
    original.stack_unchanged(owner, until);
    assert_eq!(memory(owner.pid, BASE, 8192), original.source);
    let runtime = owner.runtime.as_ref().unwrap();
    let boot = runtime.bootstrap.as_ref().unwrap().completed().unwrap();
    exact_nx_maps(&original.maps, &maps(owner.pid), &boot.island.range);
    assert_eq!(
        maps(owner.pid),
        runtime.sources.runtime_baseline_maps().unwrap()
    );
    assert!(runtime.pages.iter().all(|page| !page.executable));
    assert_eq!(runtime.ordinary_attempts.len(), ordinal + 1);
    assert!(runtime.selected_attempts.is_empty() && runtime.selected_pending.is_none());
    assert!(!owner.closing && !owner.cancel.load(Ordering::Acquire));
    let attempt = &runtime.ordinary_attempts[ordinal];
    assert_eq!(attempt.stage, AttemptStage::Complete);
    assert!(!attempt.failed && !attempt.unwound);
    same_architecture(&attempt.before, before);
    let progress = attempt.native.progress();
    assert_eq!(progress.phase, runtime_native::InstructionPhase::Closed);
    assert!(
        progress.first_failure.is_none() && progress.instruction_completed && progress.nx_closed
    );
    assert_eq!(progress.queries_started, [true; 7]);
    let diagnostic = attempt.native.diagnostics();
    complete(&diagnostic.states[0]);
    assert_eq!(diagnostic.states[0].state, *before);
    complete(&diagnostic.states[4]);
    assert_eq!(diagnostic.states[4].state, *expected);
    for index in 0..7 {
        let (tid, status) = progress.waits[index].unwrap();
        assert_eq!(tid, owner.pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        assert_eq!(status >> 16, 0);
        complete(&diagnostic.states[index + 1]);
        let signal = &diagnostic.signals[index];
        assert_eq!(
            signal.request,
            Some(NativeRequest {
                result: 0,
                errno: None
            })
        );
        let info =
            unsafe { std::ptr::read_unaligned(signal.bytes.as_ptr().cast::<libc::siginfo_t>()) };
        assert_eq!(info.si_signo, libc::SIGTRAP);
        assert_eq!(info.si_errno, 0);
        if index == 3 {
            assert_eq!(info.si_code, libc::TRAP_TRACE);
            assert_eq!(
                unsafe { info.si_addr() } as usize as u64,
                expected.registers.rip
            );
        } else {
            assert!(matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
        }
        for (request, value) in diagnostic.debug[index]
            .requests
            .iter()
            .zip(diagnostic.debug[index].values)
        {
            let request = request.unwrap();
            assert_eq!(request.errno, None);
            assert_eq!(request.result as u64, value);
        }
        let dr6 = if ordinal == 0 && index < 3 {
            0xffff_0ff0
        } else {
            0xffff_4ff0
        };
        assert_eq!(diagnostic.debug[index].values, [0, 0, 0, 0, dr6, 0]);
    }
    let effects = progress.effects();
    let mut release = 0;
    let mut private = Vec::new();
    for row in effects {
        let row = row.unwrap();
        assert!(row.complete);
        match row.effect {
            InstructionEffect::OriginalRelease => {
                release += 1;
                assert_eq!(row.result, None);
            }
            InstructionEffect::PrivateRelease { wait } => {
                private.push(wait);
                assert_eq!(
                    row.result,
                    Some(NativeRequest {
                        result: 0,
                        errno: None
                    })
                );
            }
            _ => assert_eq!(
                row.result,
                Some(NativeRequest {
                    result: 0,
                    errno: None
                })
            ),
        }
    }
    assert_eq!(release, 1);
    assert_eq!(private, [0, 1, 2, 4, 5, 6]);
    for (bytes, progress) in attempt.source.bytes.iter().zip(&attempt.source.progress) {
        assert_eq!(bytes, &original.source);
        assert!(
            progress.started
                && progress.attempted
                && progress.complete
                && progress.failure.is_none()
        );
        assert_eq!(progress.copied_bytes, original.source.len());
        assert_eq!(progress.requested_bytes, original.source.len());
    }
    assert_eq!(
        diagnostic.maps[0].bytes(),
        runtime.sources.runtime_baseline_maps().unwrap()
    );
    assert_eq!(diagnostic.maps[3].bytes(), diagnostic.maps[0].bytes());
    assert_eq!(diagnostic.maps[2].bytes(), diagnostic.maps[1].bytes());
    opened_maps(diagnostic.maps[0].bytes(), diagnostic.maps[1].bytes());
    for map in diagnostic.maps {
        assert!(map.complete);
        assert_eq!(map.length, map.bytes().len());
        assert_eq!(
            map.request,
            Some(NativeRequest {
                result: 0,
                errno: None
            })
        );
        assert_eq!(map.filesystem, Some(libc::PROC_SUPER_MAGIC));
    }
    let opened = rows(diagnostic.maps[1].bytes());
    let fetch = opened
        .iter()
        .find(|row| row.start <= before.registers.rip && before.registers.rip < row.end)
        .unwrap();
    assert_eq!(fetch.permissions, *b"r-xp");
    assert_eq!((fetch.start, fetch.end), (ENTRY, ENTRY + 4096));
    let census = runtime.census.as_ref().unwrap();
    assert_eq!(census.rows().count(), ordinal + 2);
    assert_eq!(census.active().count(), 1);
    assert_eq!(census.history().len(), (ordinal + 1) * 7);
    let history = &census.history()[ordinal * 7..(ordinal + 1) * 7];
    let next_row = census.rows().nth(ordinal + 1).unwrap();
    let old_row = census.rows().nth(ordinal).unwrap();
    let mut prior_token = attempt.stop.token.clone();
    for (i, record) in history.iter().enumerate() {
        let record = census.history_view(record).unwrap();
        if i == 3 {
            assert!(
                matches!(&record, census::HistoryView::Consumed { origin, .. } if *origin == old_row.id)
            );
            let census::HistoryView::Consumed { evidence, .. } = record else {
                unreachable!("checked resolved consumption");
            };
            assert_eq!(evidence.before.token, &prior_token);
            same_history_architecture(evidence.before, before);
            assert_eq!(
                evidence.successor,
                census::ObservationView::of(&next_row.initial)
            );
            assert!(next_row.initial.token.sequence > prior_token.sequence);
            assert_eq!(next_row.initial.task, attempt.stop.identity);
            assert_eq!(next_row.initial.token.session, owner.session);
            same_architecture(&next_row.initial, expected);
            prior_token = next_row.initial.token.clone();
            continue;
        }
        let census::HistoryView::Refreshed {
            before: from,
            after: to,
            ..
        } = record
        else {
            panic!("missing actual private checkpoint");
        };
        if i < 3 {
            same_history_architecture(from, before);
            same_history_architecture(to, before);
        } else {
            same_history_architecture(from, expected);
            same_history_architecture(to, expected);
        }
        assert_eq!(to.task, attempt.stop.identity);
        assert_eq!(to.token.session, owner.session);
        assert_eq!(from.token, &prior_token);
        assert!(to.token.sequence > prior_token.sequence);
        prior_token = (*to.token).clone();
        assert_eq!(to.phase, StopPhase::UserCheckpoint);
        assert_eq!(to.signal, None);
    }
    let active = census.active().next().unwrap();
    assert_eq!(Some(active.row.id), runtime.initial_origin);
    assert_ne!(active.row.id, census.rows().nth(ordinal).unwrap().id);
    same_architecture(active.current, expected);
    same_architecture(&active.row.initial, expected);
    assert!(matches!(
        active.row.initial.phase,
        StopPhase::OwnedOrdinaryComplete { .. }
    ));
    assert_eq!(
        active.row.initial.signal.as_ref().unwrap().raw,
        diagnostic.signals[3].bytes
    );
    assert_eq!(active.current.phase, StopPhase::UserCheckpoint);
    assert_eq!(active.current.signal, None);
    let stop = runtime
        .native
        .as_ref()
        .unwrap()
        .admission_current(active.current.task.task)
        .unwrap();
    assert_eq!(stop.token, active.current.token);
    assert_eq!(stop, *attempt.native.completed().unwrap().final_stop());
    for usage in [census.used(), census.charged()] {
        assert_eq!(
            (
                usage.epochs,
                usage.origins,
                usage.reports,
                usage.witnesses,
                usage.plan_history
            ),
            (1, ordinal + 2, 0, (ordinal + 1) * 7, 0)
        );
        assert!(usage.source_fact_bytes > 0 && usage.source_fact_bytes <= 64 * 1024 * 1024);
    }
    owner
        .time_left(until, "ordinary native control observation complete")
        .unwrap();
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateEvidence {
    state: TaskStateSnapshot,
    requests: [Option<NativeRequest>; 3],
    requested_pointer: usize,
    returned_pointer: usize,
    returned_length: usize,
    complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct MapEvidence {
    bytes: Vec<u8>,
    length: usize,
    request: Option<NativeRequest>,
    filesystem: Option<i64>,
    complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct CetQueryEvidence {
    request: NativeRequest,
    bytes: Vec<u8>,
    requested_pointer: usize,
    returned_pointer: usize,
    returned_length: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct CetStatusEvidence {
    bytes: Vec<u8>,
    length: usize,
    open: Option<NativeRequest>,
    filesystem_request: Option<NativeRequest>,
    last_read: Option<NativeRequest>,
    filesystem: Option<i64>,
    complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProfileEvidence {
    debug_values: [u64; 6],
    debug_requests: [Option<NativeRequest>; 6],
    rseq: [u8; 24],
    rseq_request: Option<NativeRequest>,
    cet_queries: Vec<Option<CetQueryEvidence>>,
    cet_status: Vec<CetStatusEvidence>,
    cet_complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct MemoryEvidence {
    address: u64,
    requested: usize,
    copied: usize,
    last_word: [u8; 8],
    bytes: [u8; 68],
    last_request: Option<NativeRequest>,
    complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct AttemptEvidence {
    census: census::OrdinaryPreparationHistorySnapshot,
    stage: AttemptStage,
    failed: bool,
    unwound: bool,
    phase: runtime_native::InstructionPhase,
    first_failure: Option<(
        runtime_native::InstructionPhase,
        runtime_native::InstructionFailure,
    )>,
    waits: [Option<(i32, i32)>; 7],
    queries_started: [bool; 7],
    instruction_completed: bool,
    nx_closed: bool,
    states: Vec<StateEvidence>,
    maps: Vec<MapEvidence>,
    signals: Vec<([u8; 128], Option<NativeRequest>)>,
    debug: Vec<([u64; 6], [Option<NativeRequest>; 6])>,
    profile: ProfileEvidence,
    memory: MemoryEvidence,
    effects: Vec<Option<runtime_native::InstructionEffectRecord>>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::runtime) struct Retained {
    history: census::HistorySnapshot,
    origins: Vec<census::OriginRow>,
    current: ObservedStop,
    charged: BudgetCharge,
    used: BudgetCharge,
    registry: crate::lifecycle::RegistrySnapshot,
    source: Vec<Vec<u8>>,
    source_progress: Vec<SourceReadProgress>,
    attempts: Vec<AttemptEvidence>,
}
pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn retained(
    owner: &Owner,
) -> Retained {
    let runtime = owner.runtime.as_ref().unwrap();
    let census = runtime.census.as_ref().unwrap();
    Retained {
        history: census.history_snapshot().unwrap(),
        origins: census.rows().cloned().collect(),
        current: census
            .current_observation(runtime.initial_origin.unwrap())
            .unwrap()
            .clone(),
        charged: census.charged(),
        used: census.used(),
        registry: runtime.native.as_ref().unwrap().admission_snapshot(),
        source: runtime
            .ordinary_attempts
            .iter()
            .flat_map(|a| a.source.bytes.iter().cloned())
            .collect(),
        source_progress: runtime
            .ordinary_attempts
            .iter()
            .flat_map(|a| a.source.progress)
            .collect(),
        attempts: runtime
            .ordinary_attempts
            .iter()
            .map(|attempt| {
                let progress = attempt.native.progress();
                let diagnostic = attempt.native.diagnostics();
                let profile = diagnostic.profile;
                let memory = diagnostic.memory;
                AttemptEvidence {
                    census: attempt.census.history_snapshot().unwrap(),
                    stage: attempt.stage,
                    failed: attempt.failed,
                    unwound: attempt.unwound,
                    phase: progress.phase,
                    first_failure: progress.first_failure,
                    waits: progress.waits,
                    queries_started: progress.queries_started,
                    instruction_completed: progress.instruction_completed,
                    nx_closed: progress.nx_closed,
                    states: diagnostic
                        .states
                        .iter()
                        .map(|slot| StateEvidence {
                            state: slot.state.clone(),
                            requests: [
                                slot.registers_request,
                                slot.xstate_request,
                                slot.mask_request,
                            ],
                            requested_pointer: slot.requested_pointer,
                            returned_pointer: slot.returned_pointer,
                            returned_length: slot.returned_length,
                            complete: slot.complete,
                        })
                        .collect(),
                    maps: diagnostic
                        .maps
                        .iter()
                        .map(|map| MapEvidence {
                            bytes: map.bytes().to_vec(),
                            length: map.length,
                            request: map.request,
                            filesystem: map.filesystem,
                            complete: map.complete,
                        })
                        .collect(),
                    signals: diagnostic
                        .signals
                        .iter()
                        .map(|signal| (signal.bytes, signal.request))
                        .collect(),
                    debug: diagnostic
                        .debug
                        .iter()
                        .map(|debug| (debug.values, debug.requests))
                        .collect(),
                    profile: ProfileEvidence {
                        debug_values: profile.debug.values,
                        debug_requests: profile.debug.requests,
                        rseq: profile.rseq,
                        rseq_request: profile.rseq_request,
                        cet_queries: profile
                            .cet
                            .queries
                            .iter()
                            .map(|query| {
                                query.map(|query| CetQueryEvidence {
                                    request: query.request,
                                    bytes: query.bytes.to_vec(),
                                    requested_pointer: query.requested_pointer,
                                    returned_pointer: query.returned_pointer,
                                    returned_length: query.returned_length,
                                })
                            })
                            .collect(),
                        cet_status: profile
                            .cet
                            .status
                            .iter()
                            .map(|status| CetStatusEvidence {
                                bytes: status.bytes.to_vec(),
                                length: status.length,
                                open: status.open,
                                filesystem_request: status.filesystem_request,
                                last_read: status.last_read,
                                filesystem: status.filesystem,
                                complete: status.complete,
                            })
                            .collect(),
                        cet_complete: profile.cet.complete,
                    },
                    memory: MemoryEvidence {
                        address: memory.address,
                        requested: memory.requested,
                        copied: memory.copied,
                        last_word: memory.last_word,
                        bytes: memory.bytes,
                        last_request: memory.last_request,
                        complete: memory.complete,
                    },
                    effects: progress.effects().to_vec(),
                }
            })
            .collect(),
    }
}
pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn after_cleanup(
    owner: &Owner,
    expected: &Retained,
) {
    assert_eq!(retained(owner), *expected);
}
