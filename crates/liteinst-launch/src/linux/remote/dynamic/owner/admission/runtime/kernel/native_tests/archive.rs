//! Independent literal phase checks plus immutable post-cleanup evidence copies.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime::native_tests::rows;
use crate::linux::remote::dynamic::owner::kernel_journal::{
    RuntimeKernelAttemptSnapshot, RuntimeKernelFact, RuntimeKernelRawRecord, RuntimeKernelRequest,
    RuntimeKernelStateRecord, RuntimeKernelStateSlot,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadCopy {
    metadata: String,
    initialized: Vec<u8>,
    logical: Option<TaskStateSnapshot>,
}
fn copy_read(view: RuntimeStateReadView<'_>) -> ReadCopy {
    ReadCopy {
        metadata: format!(
            "{:?}",
            (
                view.registers,
                view.registers_request,
                view.xstate_request,
                view.requested_pointer,
                view.returned_pointer,
                view.requested_length,
                view.returned_length,
                view.mask,
                view.mask_request,
                view.complete
            )
        ),
        initialized: view.xstate_initialized.to_vec(),
        logical: view.state.cloned(),
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct RawCopy {
    metadata: String,
    state: Option<ReadCopy>,
    maps: Option<(String, Vec<u8>)>,
    control: String,
}
fn copy_raw(raw: RuntimeRawWaitView<'_>) -> RawCopy {
    let p = raw.control;
    let cet = p
        .cet
        .queries
        .iter()
        .map(|q| {
            q.map(|q| {
                (
                    q.request,
                    q.bytes.to_vec(),
                    q.requested_pointer,
                    q.returned_pointer,
                    q.returned_length,
                )
            })
        })
        .collect::<Vec<_>>();
    let status = p
        .cet
        .status
        .iter()
        .map(|s| {
            (
                s.bytes.to_vec(),
                s.length,
                s.open,
                s.filesystem_request,
                s.last_read,
                s.filesystem,
                s.complete,
            )
        })
        .collect::<Vec<_>>();
    RawCopy {
        metadata: format!(
            "{:?}",
            (
                raw.ordinal,
                raw.tid,
                raw.status,
                raw.queries_started,
                raw.fixed.syscall_info,
                raw.fixed.syscall_info_request,
                raw.fixed.event_message,
                raw.fixed.event_message_request,
                raw.fixed.signal,
                raw.fixed.signal_request,
                raw.failure
            )
        ),
        state: raw.state.map(copy_read),
        maps: raw.maps.map(|m| {
            (
                format!(
                    "{:?}",
                    (
                        m.length,
                        m.directory_open,
                        m.filesystem_request,
                        m.filesystem,
                        m.maps_open,
                        m.read_calls,
                        m.last_read,
                        m.overflow_probe,
                        m.complete
                    )
                ),
                m.initialized.to_vec(),
            )
        }),
        control: format!(
            "{:?}",
            (
                p.debug.values,
                p.debug.requests,
                p.rseq,
                p.rseq_request,
                cet,
                status,
                p.cet.complete
            )
        ),
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct AttemptCopy {
    root: String,
    before: ObservedStop,
    checkpoint: ObservedStop,
    source: Vec<Vec<u8>>,
    progress: Vec<SourceReadProgress>,
    identity: Vec<u8>,
    raw: Vec<Option<RawCopy>>,
    readback: Option<(String, ReadCopy)>,
    effects: Vec<Option<RuntimeKernelEffectRecord>>,
}
type JournalPayload = (
    Vec<RuntimeKernelStateRecord>,
    Vec<Option<RuntimeKernelRawRecord>>,
    Vec<RuntimeKernelFact>,
);
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Retained {
    history: crate::linux::remote::dynamic::owner::admission::census::HistorySnapshot,
    rows: Vec<crate::linux::remote::dynamic::owner::admission::census::OriginRow>,
    current: Option<ObservedStop>,
    charged: BudgetCharge,
    used: BudgetCharge,
    registry: crate::lifecycle::RegistrySnapshot,
    journal: Vec<JournalPayload>,
    sources: Vec<String>,
    attempts: Vec<AttemptCopy>,
}
pub(super) fn retained(owner: &Owner) -> Retained {
    let runtime = owner.runtime.as_ref().unwrap();
    let census = runtime.census.as_ref().unwrap();
    Retained {
        history: census.history_snapshot().unwrap(),
        rows: census.rows().cloned().collect(),
        current: runtime
            .initial_origin
            .map(|id| census.current_observation(id).unwrap().clone()),
        charged: census.charged(),
        used: census.used(),
        registry: runtime.native.as_ref().unwrap().admission_snapshot(),
        // Cleanup may add the first Cancelled failure/writer status; all
        // already observed raw/state/fact payloads must remain byte-exact.
        journal: owner
            .kernel_journal
            .reader()
            .snapshot()
            .runtime_attempts
            .iter()
            .map(|a| (a.states.to_vec(), a.raw.to_vec(), a.facts.clone()))
            .collect(),
        sources: (0..runtime.sources.window_count())
            .map(|i| {
                let w = runtime.sources.window(i).unwrap();
                format!("{:?}", (w.id, w.vma, w.target, w.snapshot, w.entries))
            })
            .collect(),
        attempts: runtime
            .kernel_attempts
            .iter()
            .map(|a| AttemptCopy {
                root: format!(
                    "{:?}",
                    (
                        a.until,
                        a.stage,
                        a.first_failure,
                        &a.token,
                        &a.stop,
                        a.origin,
                        &a.identity,
                        &a.input,
                        a.decision,
                        a.native.test_failure(),
                        a.debited
                    )
                ),
                before: a.before.clone(),
                checkpoint: a.checks.checkpoint.clone(),
                source: a.checks.bytes.to_vec(),
                progress: a.checks.progress.to_vec(),
                identity: a.checks.identity.clone(),
                raw: (0..9).map(|i| a.native.raw_view(i).map(copy_raw)).collect(),
                readback: a
                    .native
                    .last_readback_view()
                    .map(|(kind, stop, state)| (format!("{kind:?}:{stop:?}"), copy_read(state))),
                effects: a.native.test_effects().to_vec(),
            })
            .collect(),
    }
}

pub(super) fn no_effects(owner: &Owner, expected: usize) {
    let runtime = owner.runtime.as_ref().unwrap();
    assert_eq!(runtime.kernel_attempts.len(), expected);
    for a in &runtime.kernel_attempts {
        assert!(
            a.native.test_effects().is_empty(),
            "no setter or release may have been attempted"
        );
        assert!((0..9).all(|i| a.native.raw_view(i).is_none()));
        assert_eq!(a.native.test_failure(), None);
    }
}
fn zero() -> Request {
    Request {
        result: 0,
        errno: None,
    }
}
fn public_zero() -> RuntimeKernelRequest {
    RuntimeKernelRequest {
        result: 0,
        errno: None,
    }
}
pub(super) fn complete_state(view: RuntimeStateReadView<'_>) -> TaskStateSnapshot {
    assert!(view.complete);
    assert_eq!(view.registers_request, Some(zero()));
    assert_eq!(view.xstate_request, Some(zero()));
    assert_eq!(view.mask_request, Some(zero()));
    assert_eq!(view.requested_pointer, view.returned_pointer);
    assert_ne!(view.requested_pointer, 0);
    assert_eq!(view.requested_length, MAX_XSTATE);
    assert_eq!(view.xstate_initialized.len(), MAX_XSTATE);
    assert!((512..MAX_XSTATE).contains(&view.returned_length));
    let actual = TaskStateSnapshot {
        registers: RegisterSnapshot::from(unsafe {
            std::ptr::read_unaligned(view.registers.as_ptr().cast::<libc::user_regs_struct>())
        }),
        xstate: view.xstate_initialized[..view.returned_length].to_vec(),
        mask: u64::from_ne_bytes(*view.mask),
    };
    assert_eq!(view.state, Some(&actual));
    actual
}
pub(super) fn public_state(record: &RuntimeKernelStateRecord) -> TaskStateSnapshot {
    assert!(record.captured && record.finalized && record.complete);
    assert_eq!(record.registers_request, Some(public_zero()));
    assert_eq!(record.xstate_request, Some(public_zero()));
    assert_eq!(record.mask_request, Some(public_zero()));
    assert_eq!(record.requested_length, MAX_XSTATE);
    assert_eq!(record.initialized_xstate.len(), MAX_XSTATE);
    assert_eq!(record.requested_pointer, record.returned_pointer);
    assert_ne!(record.requested_pointer, 0);
    assert!((512..MAX_XSTATE).contains(&record.returned_length));
    TaskStateSnapshot {
        registers: RegisterSnapshot::from(unsafe {
            std::ptr::read_unaligned(record.registers.as_ptr().cast::<libc::user_regs_struct>())
        }),
        xstate: record.initialized_xstate[..record.returned_length].to_vec(),
        mask: u64::from_ne_bytes(record.mask),
    }
}
pub(super) fn state_slot(
    attempt: &RuntimeKernelAttemptSnapshot,
    slot: RuntimeKernelStateSlot,
) -> &RuntimeKernelStateRecord {
    let values = attempt
        .states
        .iter()
        .filter(|r| r.slot == slot)
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 1);
    values[0]
}

// Build the complete expected table independently from the actual NX baseline.
// Only the literal ELF descriptor splits; dev/inode/path/padding and every
// unrelated raw row remain exact. The source file has offset zero at BASE.
fn opened(baseline: &[u8], two: bool) -> Vec<u8> {
    let parsed = rows(baseline);
    let mut count = 0;
    let mut result = Vec::new();
    for row in parsed {
        if row.start == BASE && row.end == BASE + 8192 {
            count += 1;
            assert_eq!(row.permissions, *b"r--p");
            let range_end = row.raw.iter().position(|b| *b == b' ').unwrap();
            let offset_start = range_end + 6;
            let offset_end = offset_start
                + row.raw[offset_start..]
                    .iter()
                    .position(|b| *b == b' ')
                    .unwrap();
            assert_eq!(
                u64::from_str_radix(
                    std::str::from_utf8(&row.raw[offset_start..offset_end]).unwrap(),
                    16
                )
                .unwrap(),
                0
            );
            let dash = row.raw[..range_end]
                .iter()
                .position(|b| *b == b'-')
                .unwrap();
            let render = |start: u64, end: u64, offset: u64, x: bool| {
                let mut line = row.raw.clone();
                let range = format!("{start:0width$x}-{end:0width$x}", width = dash);
                assert_eq!(range.len(), range_end);
                line[..range_end].copy_from_slice(range.as_bytes());
                let value = format!("{offset:0width$x}", width = offset_end - offset_start);
                assert_eq!(value.len(), offset_end - offset_start);
                line[offset_start..offset_end].copy_from_slice(value.as_bytes());
                line[row.x_column] = if x { b'x' } else { b'-' };
                line.push(b'\n');
                line
            };
            if two {
                result.extend(render(BASE, BASE + 8192, 0, true));
            } else {
                result.extend(render(BASE, BASE + 4096, 0, false));
                result.extend(render(BASE + 4096, BASE + 8192, 4096, true));
            }
        } else {
            result.extend(row.raw);
            result.push(b'\n');
        }
    }
    assert_eq!(count, 1);
    result
}

pub(super) fn native(
    owner: &Owner,
    index: usize,
    before: &TaskStateSnapshot,
    returned: Option<&TaskStateSnapshot>,
    baseline: &[u8],
    two: bool,
) {
    let runtime = owner.runtime.as_ref().unwrap();
    let a = &runtime.kernel_attempts[index];
    assert!(a.first_failure.is_none());
    assert_eq!(a.native.test_failure(), None);
    let identity = a.identity.as_ref().unwrap();
    assert_eq!(identity.until(), a.until);
    assert_eq!(a.before.registers, before.registers);
    assert_eq!(a.before.xstate, before.xstate);
    assert_eq!(a.before.signal_mask, before.mask);
    let count = if returned.is_some() { 9 } else { 6 };
    let open = opened(baseline, two);
    let island = &runtime
        .bootstrap
        .as_ref()
        .unwrap()
        .completed()
        .unwrap()
        .island;
    let public = owner.kernel_journal.reader().snapshot();
    let published = &public.runtime_attempts[index];
    let mut entry = before.clone();
    entry.registers.rip += 2;
    entry.registers.rcx = entry.registers.rip;
    entry.registers.r11 = before.registers.eflags & !0x10000;
    entry.registers.eflags &= !0x10000;
    entry.registers.orig_rax = before.registers.rax;
    entry.registers.rax = (-libc::ENOSYS as i64) as u64;
    for ordinal in 0..9 {
        if ordinal >= count {
            assert!(a.native.raw_view(ordinal).is_none());
            continue;
        }
        let raw = a.native.raw_view(ordinal).unwrap();
        assert_eq!((raw.ordinal, raw.tid), (ordinal, owner.pid));
        assert_eq!(raw.failure, None);
        if returned.is_none() && ordinal == 5 {
            assert!(libc::WIFEXITED(raw.status));
            assert_eq!(libc::WEXITSTATUS(raw.status), 7);
            assert!(!raw.queries_started && raw.state.is_none() && raw.maps.is_none());
            assert!(
                raw.fixed.syscall_info_request.is_none()
                    && raw.fixed.event_message_request.is_none()
                    && raw.fixed.signal_request.is_none()
            );
            continue;
        }
        assert!(libc::WIFSTOPPED(raw.status) && raw.queries_started);
        let selected = ordinal == 3 || (returned.is_some() && ordinal == 4);
        assert_eq!(
            libc::WSTOPSIG(raw.status),
            if selected {
                libc::SIGTRAP | 0x80
            } else {
                libc::SIGTRAP
            }
        );
        assert_eq!(
            raw.status >> 16,
            if returned.is_none() && ordinal == 4 {
                libc::PTRACE_EVENT_EXIT
            } else {
                0
            }
        );
        let actual = complete_state(raw.state.unwrap());
        assert!(
            raw.fixed.syscall_info_request.is_some()
                && raw.fixed.event_message_request.is_some()
                && raw.fixed.signal_request.is_some()
        );
        let published_raw = published.raw[ordinal].as_ref().unwrap();
        assert_eq!(published_raw.registers, *raw.state.unwrap().registers);
        assert_eq!(published_raw.mask, *raw.state.unwrap().mask);
        assert_eq!(published_raw.syscall_info, *raw.fixed.syscall_info);
        assert_eq!(published_raw.event_message, raw.fixed.event_message);
        assert_eq!(published_raw.signal, *raw.fixed.signal);
        assert_eq!(published_raw.status, raw.status);
        if let Some(slot) = published_raw.state_slot {
            assert_eq!(public_state(state_slot(published, slot)), actual);
        }
        if !selected && !(returned.is_none() && ordinal == 4) {
            assert_eq!(raw.fixed.signal_request, Some(zero()));
            let signal = unsafe {
                std::ptr::read_unaligned(raw.fixed.signal.as_ptr().cast::<libc::siginfo_t>())
            };
            assert_eq!(
                (signal.si_signo, signal.si_errno, signal.si_code),
                (libc::SIGTRAP, 0, libc::SI_KERNEL)
            );
            let canonical = if ordinal < 3 {
                before
            } else {
                returned.unwrap()
            };
            let mut expected = canonical.registers;
            expected.orig_rax = u64::MAX;
            expected.eflags &= !(0x100 | 0x10000 | 0x40000);
            if ordinal == 5 {
                expected.rip = island.trap() + 1;
            } else {
                let arguments = if matches!(ordinal, 1 | 7) {
                    [
                        if two { BASE } else { BASE + 4096 },
                        if two { 8192 } else { 4096 },
                        if ordinal == 1 { 5 } else { 1 },
                        0,
                        0,
                        0,
                    ]
                } else {
                    [32, 0, 0, 0, 0, 0]
                };
                expected.rdi = arguments[0];
                expected.rsi = arguments[1];
                expected.rdx = arguments[2];
                expected.r10 = arguments[3];
                expected.r8 = arguments[4];
                expected.r9 = arguments[5];
                expected.rax = 0;
                expected.rcx = island.range.start + 2;
                expected.r11 = expected.eflags;
                expected.rip = island.range.start + 3;
            }
            assert_eq!(actual.registers, expected);
            assert_eq!(actual.mask, canonical.mask);
            // Raw private XSTATE is retained in full. Only the separately
            // restored checkpoints claim equality to original logical XSTATE.
        }
        let map = raw.maps.unwrap();
        assert_eq!(map.initialized.len(), 65536);
        assert!(map.complete && map.length > 0 && map.length < 65536);
        assert_eq!(map.filesystem, Some(0x9fa0));
        assert_eq!(map.last_read, Some(zero()));
        assert!(map.read_calls >= 1);
        let nx = ordinal == 0 || (returned.is_some() && ordinal >= 7);
        assert_eq!(
            &map.initialized[..map.length],
            if nx { baseline } else { open.as_slice() }
        );
        assert!(
            map.directory_open
                .is_some_and(|r| r.result >= 0 && r.errno.is_none())
        );
        assert_eq!(map.filesystem_request, Some(zero()));
        assert!(
            map.maps_open
                .is_some_and(|r| r.result >= 0 && r.errno.is_none())
        );
        if ordinal == 3 {
            assert_eq!(actual, entry);
            syscall_info(raw, 1, &entry, identity.number(), identity.arguments());
        }
        if let Some(returned) = returned
            && ordinal == 4
        {
            assert_eq!(&actual, returned);
            syscall_info(raw, 2, &actual, identity.number(), identity.arguments());
        }
        if returned.is_none() && ordinal == 4 {
            assert_eq!(raw.fixed.event_message_request, Some(zero()));
            assert_eq!(raw.fixed.event_message, 7 << 8);
        }
        for (request, value) in raw
            .control
            .debug
            .requests
            .iter()
            .zip(raw.control.debug.values)
        {
            let r = request.unwrap();
            assert_eq!(r.errno, None);
            assert_eq!(r.result as u64, value);
        }
        assert_eq!(raw.control.debug.values, [0, 0, 0, 0, 0xffff_4ff0, 0]);
    }
    let effects = a.native.test_effects();
    assert!(effects.len() <= 37);
    let mut original = 0;
    let mut entry_releases = 0;
    let mut pre_exit = 0;
    let mut private = Vec::new();
    for record in effects {
        let record = record.unwrap();
        assert!(record.complete);
        assert_eq!(record.result, Some(zero()));
        match record.effect {
            RuntimeKernelEffect::OriginalRelease => original += 1,
            RuntimeKernelEffect::EntryRelease => entry_releases += 1,
            RuntimeKernelEffect::PreExitRelease => pre_exit += 1,
            RuntimeKernelEffect::PrivateRelease { ordinal } => private.push(ordinal),
            _ => {}
        }
    }
    assert_eq!(
        (original, entry_releases, pre_exit),
        (1, 1, usize::from(returned.is_none()))
    );
    assert_eq!(
        private,
        if returned.is_some() {
            vec![0, 1, 2, 5, 6, 7, 8]
        } else {
            vec![0, 1, 2]
        }
    );
    let complete_sources = if returned.is_some() { 5 } else { 4 };
    for (i, (bytes, progress)) in a.checks.bytes.iter().zip(a.checks.progress).enumerate() {
        if i < complete_sources {
            assert!(progress.complete && progress.failure.is_none());
            assert_eq!(
                bytes,
                runtime
                    .sources
                    .window(a.token.window)
                    .unwrap()
                    .snapshot
                    .bytes()
            );
        } else {
            assert!(!progress.started && !progress.complete);
        }
    }
}
fn syscall_info(
    raw: RuntimeRawWaitView<'_>,
    op: u8,
    state: &TaskStateSnapshot,
    number: u64,
    args: [u64; 6],
) {
    let r = raw.fixed.syscall_info_request.unwrap();
    assert_eq!(r.errno, None);
    assert!(((if op == 1 { 80 } else { 33 })..=88).contains(&r.result));
    let b = raw.fixed.syscall_info;
    assert_eq!(b[0], op);
    assert_eq!(u32::from_ne_bytes(b[4..8].try_into().unwrap()), 0xc000_003e);
    let word = |i| u64::from_ne_bytes(b[i..i + 8].try_into().unwrap());
    assert_eq!(word(8), state.registers.rip);
    assert_eq!(word(16), state.registers.rsp);
    if op == 1 {
        assert_eq!(word(24), number);
        for (i, v) in args.into_iter().enumerate() {
            assert_eq!(word(32 + i * 8), v);
        }
    } else {
        assert_eq!(word(24), state.registers.rax);
        assert_eq!(b[32], 0);
    }
}

pub(super) fn journal(
    attempt: &RuntimeKernelAttemptSnapshot,
    before: &TaskStateSnapshot,
    returned: Option<&TaskStateSnapshot>,
    pid: i32,
) {
    assert_eq!(attempt.input_registers, before.registers);
    assert_eq!(attempt.instruction, [0x0f, 0x05]);
    assert_eq!(attempt.logical_pc, before.registers.rip);
    assert_eq!(attempt.number, before.registers.rax);
    assert!(attempt.failure.is_none());
    assert_eq!(
        public_state(state_slot(attempt, RuntimeKernelStateSlot::Original)),
        *before
    );
    assert_eq!(
        attempt.facts.len(),
        if returned.is_some() { 25 } else { 20 }
    );
    let count = if returned.is_some() { 9 } else { 6 };
    for (i, raw) in attempt.raw.iter().enumerate() {
        if i >= count {
            assert!(raw.is_none());
            continue;
        }
        let raw = raw.as_ref().unwrap();
        assert_eq!((raw.ordinal, raw.tid), (i, pid));
        assert!(raw.finalized);
        assert_eq!(raw.custody.expected_tid, pid);
        assert_eq!(raw.custody.session, attempt.id.session);
        assert!(raw.custody.retained_pin.is_some());
        assert!(!raw.custody.lost_wait && !raw.custody.missing_pin);
        assert_eq!(raw.failure, None);
        if returned.is_none() && i == 5 {
            assert!(!raw.queries_started);
            assert!(
                raw.registers_request.is_none()
                    && raw.xstate_request.is_none()
                    && raw.mask_request.is_none()
                    && raw.syscall_request.is_none()
                    && raw.event_request.is_none()
                    && raw.signal_request.is_none()
            );
            assert!(raw.maps.is_none());
        } else {
            assert!(raw.queries_started);
            assert_eq!(raw.custody.stopped_status, Some(raw.status));
            assert_eq!(raw.registers_request, Some(public_zero()));
        }
    }
    for state in &attempt.states {
        let expected = if returned.is_some() {
            matches!(
                state.slot,
                RuntimeKernelStateSlot::Original
                    | RuntimeKernelStateSlot::Entry
                    | RuntimeKernelStateSlot::Exit
                    | RuntimeKernelStateSlot::BridgeTrap
                    | RuntimeKernelStateSlot::RestoredReturn
                    | RuntimeKernelStateSlot::Closed
            )
        } else {
            matches!(
                state.slot,
                RuntimeKernelStateSlot::Original
                    | RuntimeKernelStateSlot::Entry
                    | RuntimeKernelStateSlot::PreExit
            )
        };
        assert_eq!(state.captured, expected);
        assert_eq!(state.initialized_xstate.len(), MAX_XSTATE);
        if expected {
            let _ = public_state(state);
        } else {
            assert!(
                !state.finalized
                    && !state.complete
                    && state.registers_request.is_none()
                    && state.xstate_request.is_none()
                    && state.mask_request.is_none()
            );
        }
    }
    let mut entry = before.clone();
    entry.registers.rip += 2;
    entry.registers.rcx = entry.registers.rip;
    entry.registers.r11 = before.registers.eflags & !0x10000;
    entry.registers.eflags &= !0x10000;
    entry.registers.orig_rax = before.registers.rax;
    entry.registers.rax = (-libc::ENOSYS as i64) as u64;
    assert_eq!(
        public_state(state_slot(attempt, RuntimeKernelStateSlot::Entry)),
        entry
    );
    if let Some(expected) = returned {
        for slot in [
            RuntimeKernelStateSlot::Exit,
            RuntimeKernelStateSlot::RestoredReturn,
            RuntimeKernelStateSlot::Closed,
        ] {
            assert_eq!(public_state(state_slot(attempt, slot)), *expected);
        }
        assert!(matches!(
            attempt.facts.last(),
            Some(RuntimeKernelFact::ReturnCommitted { .. })
        ));
        assert!(!attempt.facts.iter().any(|f| matches!(
            f,
            RuntimeKernelFact::Terminal { .. }
                | RuntimeKernelFact::TerminalCommitted { .. }
                | RuntimeKernelFact::PreExit { .. }
        )));
    } else {
        assert!(
            matches!(attempt.facts.last(),Some(RuntimeKernelFact::TerminalCommitted{status,..})if libc::WIFEXITED(*status)&&libc::WEXITSTATUS(*status)==7)
        );
        assert!(attempt.facts.iter().any(|f|matches!(f,RuntimeKernelFact::Terminal{ordinal:5,status,physical_status,pin_revents,..}if status==physical_status&&libc::WIFEXITED(*status)&&libc::WEXITSTATUS(*status)==7&&*pin_revents==(libc::POLLIN|libc::POLLHUP))));
        assert!(!attempt.facts.iter().any(|f| matches!(
            f,
            RuntimeKernelFact::Returned { .. } | RuntimeKernelFact::ReturnCommitted { .. }
        )));
    }
}
