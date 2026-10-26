//! Next-increment two-page fetch control. No prior fixture/checker is changed.
use super::*;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicU64;

const BASE: u64 = 0x400000;
const TIMEOUT: Duration = Duration::from_secs(3);
static SESSION: AtomicU64 = AtomicU64::new(960_000);

pub(in crate::linux::remote::dynamic::owner::admission::runtime) struct Context {
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) entry: u64,
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) before: TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) source: Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) closed_maps: Vec<u8>,
    descriptor: std::fs::File,
    stack_start: u64,
    stack: Vec<u8>,
}

fn live(pin: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut poll, 1, 0) }, 0);
    assert_eq!(poll.revents, 0);
}
impl Context {
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn unchanged(
        &self,
        owner: &Owner,
        pin: &OwnedFd,
        until: Instant,
    ) {
        owner
            .time_left(until, "cross-page full memory observation")
            .unwrap();
        live(pin);
        assert!(owner.owned.contains(&owner.pid));
        assert!(
            owner
                .stopped
                .get(&owner.pid)
                .is_some_and(|status| libc::WIFSTOPPED(*status))
        );
        let mut stack = vec![0; self.stack.len()];
        self.descriptor
            .read_exact_at(&mut stack, self.stack_start)
            .unwrap();
        assert_eq!(stack, self.stack);
        let mut source = vec![0; 8192];
        self.descriptor.read_exact_at(&mut source, BASE).unwrap();
        assert_eq!(source, self.source);
        assert_eq!(maps(owner.pid), self.closed_maps);
        live(pin);
        owner
            .time_left(until, "cross-page full memory observation complete")
            .unwrap();
    }
}

/// Shared only by the two new cross-page cases. All existing fixed-entry
/// wrappers remain byte-identical. Action and copied diagnostics stay under
/// the original Owner; cleanup and both physical pin checks precede rethrow.
pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn with_entry<T>(
    offset: usize,
    code: &[u8],
    action: impl FnOnce(&mut Owner, &OwnedFd, &Context, Instant) -> T,
    after_cleanup: impl FnOnce(&Owner, &T),
) {
    assert!(matches!(offset, 4093 | 4095));
    let entry = BASE + offset as u64;
    let fixture = Fixture::code_at_entry(offset, code);
    let mut harness = Harness::new();
    *harness.owner() = Owner::new(
        SESSION.fetch_add(1, Ordering::Relaxed),
        Arc::new(AtomicBool::new(false)),
    );
    harness.owner().lifecycle_options = Some(DynamicLifecycleOptions::default());
    let until = Instant::now() + TIMEOUT;
    let launched = harness.launch(&fixture).unwrap();
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
    let initial = launched.event.stop_token().unwrap().clone();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        live(&app);
        live(&broker);
        let owner = harness.owner();
        owner
            .time_left(until, "cross-page original observation")
            .unwrap();
        let original_state = state(owner.pid);
        assert_eq!(original_state.registers.rip, entry);
        assert_eq!(original_state.registers.orig_rax, libc::SYS_execve as u64);
        assert_eq!(
            original_state.registers.rax,
            (-i64::from(libc::ENOSYS)) as u64
        );
        let original_maps = maps(owner.pid);
        let original_rows = rows(&original_maps);
        let main = original_rows
            .iter()
            .filter(|row| row.start == BASE && row.end == BASE + 8192)
            .collect::<Vec<_>>();
        assert_eq!(main.len(), 1);
        assert_eq!(main[0].permissions, *b"r-xp");
        let stacks = original_rows
            .iter()
            .filter(|row| row.raw.ends_with(b"[stack]"))
            .collect::<Vec<_>>();
        assert_eq!(stacks.len(), 1);
        assert_eq!(stacks[0].permissions, *b"rw-p");
        let stack_start = stacks[0].start;
        let stack_length = usize::try_from(stacks[0].end - stack_start).unwrap();
        assert!((1..=1024 * 1024).contains(&stack_length));
        assert!(
            stack_start <= original_state.registers.rsp
                && original_state.registers.rsp < stacks[0].end
        );
        let descriptor = std::fs::File::open(format!("/proc/{}/mem", owner.pid)).unwrap();
        let mut stack = vec![0; stack_length];
        descriptor.read_exact_at(&mut stack, stack_start).unwrap();
        let source = memory(owner.pid, BASE, 8192);
        assert_eq!(
            u64::from_le_bytes(source[24..32].try_into().unwrap()),
            entry
        );
        assert_eq!(&source[offset..offset + code.len()], code);
        live(&app);
        owner
            .time_left(until, "cross-page original observation complete")
            .unwrap();
        let ready = ready(start(
            owner,
            &initial,
            DynamicRuntimeOptions::default(),
            until,
        ));
        let runtime = owner.runtime.as_ref().unwrap();
        let boot = runtime.bootstrap.as_ref().unwrap().completed().unwrap();
        assert_eq!(boot.evidence.exec_event, original_state);
        let mut exit = original_state.clone();
        exit.registers.rax = 0;
        assert_eq!(boot.evidence.exec_exit, exit);
        let mut first = exit.registers;
        first.rip = entry + 1;
        first.orig_rax = u64::MAX;
        assert_eq!(boot.evidence.entry_trap.registers, first);
        assert_eq!(boot.evidence.entry_trap.mask, exit.mask);
        let mut expected = boot.evidence.entry_trap.clone();
        expected.registers.rip = entry;
        assert_eq!(boot.evidence.restored_entry, expected);
        assert_eq!(state(owner.pid), expected);
        assert_eq!(ready.registers, expected.registers);
        assert_eq!(ready.xstate, expected.xstate);
        assert_eq!(ready.signal_mask, expected.mask);
        assert_eq!(ready.task, boot.stop.identity);
        assert_eq!(runtime.sources.vmas().len(), 1);
        assert_eq!(runtime.sources.window_count(), 1);
        let window = runtime.sources.window(0).unwrap();
        assert_eq!(window.snapshot.bytes(), source);
        assert_eq!((window.vma.start, window.vma.end), (BASE, BASE + 8192));
        assert_eq!(window.id.identity().mapping, window.snapshot.mapping.0);
        assert_eq!(
            window.id.identity().generation,
            window.snapshot.generation.0
        );
        assert_eq!(runtime.until, until);
        assert!(runtime.sources.capture_complete() && runtime.sources.recheck_complete());
        assert_eq!(runtime.sources.failure(), None);
        let closed_maps = maps(owner.pid);
        exact_nx_maps(&original_maps, &closed_maps, &boot.island.range);
        assert_eq!(
            runtime.sources.runtime_baseline_maps().unwrap(),
            closed_maps
        );
        let context = Context {
            entry,
            before: expected,
            source,
            closed_maps,
            descriptor,
            stack_start,
            stack,
        };
        context.unchanged(owner, &app, until);
        let value = action(owner, &app, &context, until);
        context.unchanged(owner, &app, until);
        owner
            .time_left(until, "cross-page action complete")
            .unwrap();
        (support::retained(owner), value)
    }));
    let cleanup = harness
        .owner()
        .cleanup()
        .unwrap_or_else(|_| std::process::abort());
    assert_eq!(cleanup.reaped, [launched.pid]);
    reaped(&app);
    reaped(&broker);
    let outcome = match outcome {
        Ok((retained, value)) => catch_unwind(AssertUnwindSafe(|| {
            support::after_cleanup(harness.owner(), &retained);
            after_cleanup(harness.owner(), &value);
        })),
        Err(payload) => Err(payload),
    };
    assert!(harness.finish().reaped.is_empty());
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
}

fn complete(slot: &StateSlot) {
    assert!(slot.complete);
    assert_eq!(
        slot.registers_request,
        Some(NativeRequest {
            result: 0,
            errno: None
        })
    );
    assert_eq!(
        slot.xstate_request,
        Some(NativeRequest {
            result: 0,
            errno: None
        })
    );
    assert_eq!(
        slot.mask_request,
        Some(NativeRequest {
            result: 0,
            errno: None
        })
    );
    assert_eq!(slot.requested_pointer, slot.returned_pointer);
    assert_eq!(slot.returned_length, slot.state.xstate.len());
    assert!((512..MAX_XSTATE).contains(&slot.returned_length));
}

fn full_vma_rx(baseline: &[u8], actual: &[u8]) {
    let mut expected = Vec::new();
    let mut changed = 0;
    for mut row in rows(baseline) {
        if row.start == BASE && row.end == BASE + 8192 {
            assert_eq!(row.permissions, *b"r--p");
            row.raw[row.x_column] = b'x';
            changed += 1;
        }
        expected.extend_from_slice(&row.raw);
        expected.push(b'\n');
    }
    assert_eq!(changed, 1);
    assert_eq!(actual, expected);
}

#[test]
fn runtime_ordinary_cross_page_move_preserves_exact_two_page_fetch() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::cross_page::runtime_ordinary_cross_page_move_preserves_exact_two_page_fetch",
        || {
            let value = 0x1234_5678_9abc_def0;
            let marker = 0x0fed_cba9_8765_4321;
            // MOV RAX,imm64 begins three bytes before the page boundary; its immediate
            // crosses that boundary. The following MOV RBX marker is on page two.
            let code = [
                0x48, 0xb8, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x48, 0xbb, 0x21, 0x43,
                0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f, 0xeb, 0xfe,
            ];
            with_entry(
                4093,
                &code,
                |owner, app, context, until| {
                    let before = &context.before;
                    assert_eq!(context.entry, BASE + 4093);
                    assert!(context.entry < BASE + 4096 && context.entry + 10 > BASE + 4096);
                    assert_ne!(before.registers.rbx, marker);
                    let mut expected = before.clone();
                    expected.registers.rax = value;
                    expected.registers.rip += 10;
                    support::one(owner, until);
                    assert_eq!(state(owner.pid), expected);
                    context.unchanged(owner, app, until);
                    let runtime = owner.runtime.as_ref().unwrap();
                    assert_eq!(runtime.ordinary_attempts.len(), 1);
                    assert!(
                        runtime.selected_attempts.is_empty() && runtime.selected_pending.is_none()
                    );
                    assert!(runtime.pages.iter().all(|page| !page.executable));
                    let attempt = &runtime.ordinary_attempts[0];
                    assert_eq!(attempt.stage, AttemptStage::Complete);
                    assert!(!attempt.failed && !attempt.unwound);
                    assert_eq!(attempt.before.registers, before.registers);
                    assert_eq!(attempt.before.xstate, before.xstate);
                    assert_eq!(attempt.before.signal_mask, before.mask);
                    let progress = attempt.native.progress();
                    assert_eq!(progress.phase, runtime_native::InstructionPhase::Closed);
                    assert!(
                        progress.first_failure.is_none()
                            && progress.instruction_completed
                            && progress.nx_closed
                    );
                    assert_eq!(progress.queries_started, [true; 7]);
                    let diagnostic = attempt.native.diagnostics();
                    complete(&diagnostic.states[0]);
                    assert_eq!(diagnostic.states[0].state, *before);
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
                        let info = unsafe {
                            std::ptr::read_unaligned(
                                signal.bytes.as_ptr().cast::<libc::siginfo_t>(),
                            )
                        };
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
                        let dr6 = if index < 3 { 0xffff_0ff0 } else { 0xffff_4ff0 };
                        assert_eq!(diagnostic.debug[index].values, [0, 0, 0, 0, dr6, 0]);
                        for (request, value) in diagnostic.debug[index]
                            .requests
                            .iter()
                            .zip(diagnostic.debug[index].values)
                        {
                            assert_eq!(
                                request.unwrap(),
                                NativeRequest {
                                    result: value as i64,
                                    errno: None
                                }
                            );
                        }
                    }
                    assert_eq!(diagnostic.states[4].state, expected);
                    // These are the actual retained syscall-trap registers, not arguments
                    // reconstructed from FetchGeometry. Both protection calls cover 8192.
                    for (slot, protection) in
                        [(2, libc::PROT_READ | libc::PROT_EXEC), (6, libc::PROT_READ)]
                    {
                        let observed = diagnostic.states[slot].state.registers;
                        assert_eq!(
                            (observed.rdi, observed.rsi, observed.rdx),
                            (BASE, 8192, protection as u64)
                        );
                        assert_eq!(
                            (observed.r10, observed.r8, observed.r9, observed.rax),
                            (0, 0, 0, 0)
                        );
                    }
                    let mut private = Vec::new();
                    let mut original = 0;
                    for record in progress.effects() {
                        let record = record.unwrap();
                        assert!(record.complete);
                        match record.effect {
                            InstructionEffect::OriginalRelease => {
                                original += 1;
                                assert_eq!(record.result, None);
                            }
                            InstructionEffect::PrivateRelease { wait } => {
                                private.push(wait);
                                assert_eq!(
                                    record.result,
                                    Some(NativeRequest {
                                        result: 0,
                                        errno: None
                                    })
                                );
                            }
                            _ => assert_eq!(
                                record.result,
                                Some(NativeRequest {
                                    result: 0,
                                    errno: None
                                })
                            ),
                        }
                    }
                    assert_eq!(original, 1);
                    assert_eq!(private, [0, 1, 2, 4, 5, 6]);
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
                    assert_eq!(diagnostic.maps[0].bytes(), context.closed_maps);
                    full_vma_rx(&context.closed_maps, diagnostic.maps[1].bytes());
                    assert_eq!(diagnostic.maps[2].bytes(), diagnostic.maps[1].bytes());
                    assert_eq!(diagnostic.maps[3].bytes(), context.closed_maps);
                    for (source, progress) in
                        attempt.source.bytes.iter().zip(attempt.source.progress)
                    {
                        assert_eq!(source, &context.source);
                        assert!(
                            progress.started
                                && progress.attempted
                                && progress.complete
                                && progress.failure.is_none()
                        );
                        assert_eq!(
                            (progress.requested_bytes, progress.copied_bytes),
                            (8192, 8192)
                        );
                    }
                    let census = runtime.census.as_ref().unwrap();
                    assert_eq!(census.rows().count(), 2);
                    assert_eq!(census.active().count(), 1);
                    assert_eq!(census.history().len(), 7);
                    let old = census.rows().next().unwrap();
                    let active = census.active().next().unwrap();
                    let original_stop = &runtime
                        .bootstrap
                        .as_ref()
                        .unwrap()
                        .completed()
                        .unwrap()
                        .stop;
                    assert_eq!(attempt.stop, *original_stop);
                    assert_eq!(original_stop.token.session, owner.session);
                    assert_eq!(original_stop.token.tid, owner.pid);
                    assert_eq!(original_stop.token.task, Some(original_stop.identity.task));
                    let same_identity = |observed: &census::ObservedStop| {
                        assert_eq!(observed.token.session, original_stop.token.session);
                        assert_eq!(observed.token.tid, original_stop.token.tid);
                        assert_eq!(observed.token.task, original_stop.token.task);
                        assert_eq!(observed.task, original_stop.identity);
                    };
                    same_identity(&attempt.before);
                    for row in census.rows() {
                        same_identity(&row.initial);
                    }
                    same_identity(active.current);
                    assert_ne!(old.id, active.row.id);
                    assert_eq!(Some(active.row.id), runtime.initial_origin);
                    let mut prior = attempt.stop.token.clone();
                    for (index, history) in census.history().iter().enumerate() {
                        if index == 3 {
                            assert!(
                                matches!(history, census::HistoryRecord::Consumed { origin, .. } if *origin == old.id)
                            );
                            assert!(active.row.initial.token.sequence > prior.sequence);
                            prior = active.row.initial.token.clone();
                        } else {
                            let census::HistoryRecord::Refreshed {
                                before: from,
                                after: to,
                                ..
                            } = history
                            else {
                                panic!("missing cross-page private refresh");
                            };
                            let expected_state = if index < 3 { before } else { &expected };
                            for observed in [from, to] {
                                same_identity(observed);
                                assert_eq!(observed.registers, expected_state.registers);
                                assert_eq!(observed.xstate, expected_state.xstate);
                                assert_eq!(observed.signal_mask, expected_state.mask);
                                assert_eq!(observed.task, attempt.stop.identity);
                            }
                            assert_eq!(from.token, prior);
                            assert!(to.token.sequence > prior.sequence);
                            assert_eq!(to.phase, StopPhase::UserCheckpoint);
                            assert_eq!(to.signal, None);
                            prior = to.token.clone();
                        }
                    }
                    for observed in [&active.row.initial, active.current] {
                        assert_eq!(observed.registers, expected.registers);
                        assert_eq!(observed.xstate, expected.xstate);
                        assert_eq!(observed.signal_mask, expected.mask);
                        assert_eq!(observed.logical_pc, BASE + 4103);
                    }
                    assert!(matches!(
                        active.row.initial.phase,
                        StopPhase::OwnedOrdinaryComplete { .. }
                    ));
                    assert_eq!(
                        active.row.initial.signal.as_ref().unwrap().raw,
                        diagnostic.signals[3].bytes
                    );
                    assert_eq!(active.current.token, prior);
                    assert_eq!(active.current.phase, StopPhase::UserCheckpoint);
                    assert_eq!(active.current.signal, None);
                    let final_stop = runtime
                        .native
                        .as_ref()
                        .unwrap()
                        .admission_current(active.current.task.task)
                        .unwrap();
                    assert_eq!(final_stop.token, active.current.token);
                    assert_eq!(final_stop.identity, active.current.task);
                    assert_eq!(
                        final_stop,
                        *attempt.native.completed().unwrap().final_stop()
                    );
                    for usage in [census.charged(), census.used()] {
                        assert_eq!(
                            (
                                usage.epochs,
                                usage.origins,
                                usage.reports,
                                usage.witnesses,
                                usage.plan_history
                            ),
                            (1, 2, 0, 7, 0)
                        );
                        assert!(
                            usage.source_fact_bytes > 0
                                && usage.source_fact_bytes <= 64 * 1024 * 1024
                        );
                    }
                    assert_eq!(state(owner.pid).registers.rbx, before.registers.rbx);
                    assert_eq!(&context.source[4103..4113], &code[10..20]);
                    assert!(!owner.closing && !owner.cancel.load(Ordering::Acquire));
                },
                |_, ()| {},
            );
        },
    );
}
