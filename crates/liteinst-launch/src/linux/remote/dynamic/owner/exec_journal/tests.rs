//! Synthetic archive controls only. No model stop, read result, returned value
//! or cleanup flag in these cases is native execution or physical-cleanup proof.
use super::*;
use crate::lifecycle::{HoldReason, LifecycleRegistry, Limits};
use crate::selected::{SyscallAliases, decode};
use std::panic::{AssertUnwindSafe, catch_unwind};

const SESSION: u64 = 903;
const PC: u64 = 0x401000;
const NEW_PC: u64 = 0x501000;
fn identities() -> (DynamicTask, DynamicTask) {
    let mut registry = LifecycleRegistry::new(
        Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 2,
            obligations: 8,
        },
        100,
        PC,
    )
    .unwrap();
    let old = registry.root_task();
    let current = |registry: &LifecycleRegistry, task| {
        let row = registry.task(task).unwrap();
        DynamicTask {
            task,
            process: row.process,
            address_space: row.address_space,
            generation: 0,
        }
    };
    let previous = current(&registry, old);
    registry.resume(old, 0).unwrap();
    registry
        .observe_stop(old, 1, PC + 2, HoldReason::SyscallEntry)
        .unwrap();
    let ticket = registry.prepare_exec(old).unwrap();
    registry.resume(old, 1).unwrap();
    let event = registry
        .observe_exec_event(ticket, 2, 100, 100, NEW_PC)
        .unwrap();
    assert_eq!(registry.task(event.task).unwrap().sequence, 0);
    (previous, current(&registry, event.task))
}
fn stop(identity: DynamicTask, sequence: u64) -> DynamicStop {
    DynamicStop {
        session: SESSION,
        tid: 100,
        task: Some(identity.task),
        sequence,
    }
}
fn state(pc: u64) -> TaskStateSnapshot {
    let mut registers = zero_registers();
    registers.cs = 0x33;
    registers.ss = 0x2b;
    registers.eflags = 0x202;
    registers.rax = libc::SYS_execve as u64;
    registers.orig_rax = u64::MAX;
    registers.rip = pc;
    registers.rsp = 0x700000;
    registers.rdi = 0x600000;
    registers.rsi = 0x601000;
    registers.rdx = 0x602000;
    TaskStateSnapshot {
        registers,
        xstate: vec![0x5a; 832],
        mask: 0x200,
    }
}
fn binding() -> (PendingToken, SelectedInput, TaskStateSnapshot, DynamicTask) {
    let (previous, next) = identities();
    let before = state(PC);
    let input = SelectedInput::new(
        decode(PC, &[0x0f, 0x05], &SyscallAliases::default()).unwrap(),
        before.registers,
    )
    .unwrap();
    (
        PendingToken {
            stop: stop(previous, 40),
            task: previous,
            epoch: 0,
            plan: 9,
            invocation: 1,
        },
        input,
        before,
        next,
    )
}
fn attached() -> (
    ExecJournalWriter,
    ExecAttemptHandle,
    PendingToken,
    TaskStateSnapshot,
    DynamicTask,
) {
    let (pending, input, before, next) = binding();
    let mut writer = ExecJournalWriter::new(SESSION);
    let prepared = writer
        .prepare(
            &pending,
            &input,
            &before,
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
    let handle = writer.attach(prepared).unwrap();
    (writer, handle, pending, before, next)
}
fn refused<T>(result: Result<T, LaunchError>, message: &'static str) {
    assert!(matches!(result, Err(LaunchError::Invalid(actual)) if actual == message));
}
fn seed_ready(writer: &ExecJournalWriter, handle: ExecAttemptHandle) {
    writer.original_restore_attempt(handle).unwrap();
    writer.original_restore_complete(handle).unwrap();
    let mut guard = lock(&writer.archive);
    let attempt = attempt(&mut guard, handle).unwrap();
    // Explicit synthetic fixture seam, never a prepared native-owner witness.
    attempt.original_stop = Some((&stop(attempt.pending.task, 41)).into());
    attempt.native_phase = NativePhase::Ready;
}
fn seed_raw(
    writer: &ExecJournalWriter,
    handle: ExecAttemptHandle,
    state: &TaskStateSnapshot,
    status: i32,
    operation: u8,
) -> u8 {
    let mut guard = lock(&writer.archive);
    let attempt = attempt(&mut guard, handle).unwrap();
    let ordinal = attempt.raw_count as u8;
    assert!(usize::from(ordinal) < RAW_SLOTS);
    attempt.append(ExecJournalFact::Raw { ordinal }).unwrap();
    attempt.raw_count += 1;
    attempt.pending_raw = Some(ordinal);
    let raw = &mut attempt.raw[usize::from(ordinal)].record;
    raw.ordinal = ordinal;
    raw.tid = 100;
    raw.status = status;
    raw.pin = KernelPinKind::Process;
    raw.held = true;
    raw.complete = true;
    let ok = Some(ExecReadOutcome {
        result: 0,
        errno: None,
    });
    raw.registers_read = ok;
    raw.registers = state.registers;
    raw.xstate_query = Some(ExecXstateQuery {
        outcome: ok.unwrap(),
        reported_bytes: state.xstate.len(),
        pointer_unchanged: true,
    });
    raw.initialized_xstate[..state.xstate.len()].copy_from_slice(&state.xstate);
    raw.mask_read = ok;
    raw.signal_mask = state.mask;
    raw.event_read = ok;
    raw.event_message = 100;
    raw.siginfo_read = ok;
    raw.siginfo[..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
    raw.syscall_read = Some(ExecReadOutcome {
        result: if operation == 1 { 80 } else { 33 },
        errno: None,
    });
    raw.syscall_info[0] = operation;
    raw.syscall_info[4..8].copy_from_slice(&0xc000_003e_u32.to_ne_bytes());
    raw.syscall_info[8..16].copy_from_slice(&state.registers.rip.to_ne_bytes());
    raw.syscall_info[16..24].copy_from_slice(&state.registers.rsp.to_ne_bytes());
    if operation == 1 {
        raw.syscall_info[24..32].copy_from_slice(&(libc::SYS_execve as u64).to_ne_bytes());
        for (index, argument) in attempt.input.arguments.iter().enumerate() {
            raw.syscall_info[32 + index * 8..40 + index * 8]
                .copy_from_slice(&argument.to_ne_bytes());
        }
    }
    raw.maps.tid = 100;
    raw.maps.raw_status = status;
    raw.maps.status = ExecMapsStatus::Complete;
    raw.maps.initialized[..4].copy_from_slice(b"map\n");
    raw.maps.observed_bytes = 4;
    ordinal
}
fn event(identity: DynamicTask, sequence: u64, kind: DynamicEventKind) -> DynamicEvent {
    DynamicEvent {
        tid: 100,
        task: Some(identity),
        kind,
        stop: Some(stop(identity, sequence)),
    }
}
fn model_native() -> (
    ExecJournalWriter,
    ExecAttemptHandle,
    ExecJournalObserver,
    DynamicTask,
    TaskStateSnapshot,
) {
    let (writer, handle, pending, mut before, next) = attached();
    seed_ready(&writer, handle);
    let mut observer = writer.observer(handle).unwrap();
    ExecObservation::release_attempt(
        &mut observer,
        ExecRelease::Original,
        &stop(pending.task, 41),
    )
    .unwrap();
    ExecObservation::release_succeeded(
        &mut observer,
        ExecRelease::Original,
        &stop(pending.task, 41),
    )
    .unwrap();
    before.registers.rip = PC + 2;
    seed_raw(
        &writer,
        handle,
        &before,
        ((libc::SIGTRAP | 0x80) << 8) | 0x7f,
        1,
    );
    let arguments = lock(&writer.archive)
        .attempt
        .as_ref()
        .unwrap()
        .input
        .arguments;
    ExecObservation::entry(
        &mut observer,
        &event(
            pending.task,
            42,
            DynamicEventKind::SyscallEntry {
                number: libc::SYS_execve as u64,
                arguments,
            },
        ),
        &before,
    )
    .unwrap();
    ExecObservation::release_attempt(&mut observer, ExecRelease::Entry, &stop(pending.task, 42))
        .unwrap();
    ExecObservation::release_succeeded(&mut observer, ExecRelease::Entry, &stop(pending.task, 42))
        .unwrap();
    let mut state = state(NEW_PC);
    seed_raw(
        &writer,
        handle,
        &state,
        (libc::PTRACE_EVENT_EXEC << 16) | (libc::SIGTRAP << 8) | 0x7f,
        0,
    );
    let replaced = event(
        next,
        0,
        DynamicEventKind::ExecReplaced {
            previous: pending.task,
            evidence: EntryEvidence {
                first_image: FirstImage::Executable,
                executable_entry: NEW_PC,
                interpreter_base: 0,
                initial_instruction: NEW_PC,
                interpreter: None,
            },
        },
    );
    ExecObservation::replaced(&mut observer, pending.task, &replaced, &state).unwrap();
    ExecObservation::release_attempt(&mut observer, ExecRelease::ExecEvent, &stop(next, 0))
        .unwrap();
    ExecObservation::release_succeeded(&mut observer, ExecRelease::ExecEvent, &stop(next, 0))
        .unwrap();
    state.registers.rax = 0;
    seed_raw(
        &writer,
        handle,
        &state,
        ((libc::SIGTRAP | 0x80) << 8) | 0x7f,
        2,
    );
    ExecObservation::exit(
        &mut observer,
        &event(
            next,
            1,
            DynamicEventKind::SyscallExit {
                result: 0,
                is_error: false,
            },
        ),
        &state,
    )
    .unwrap();
    (writer, handle, observer, next, state)
}
fn pair(observer: &mut ExecJournalObserver, effect: BootstrapEffect, result: Option<u64>) {
    ReplacedBootstrapObservation::before_effect(observer, effect).unwrap();
    ReplacedBootstrapObservation::effect_complete(observer, effect, result).unwrap();
}
fn model_bootstrap(
    count: usize,
) -> (
    ExecJournalWriter,
    ExecAttemptHandle,
    ExecJournalObserver,
    AdmissionStop,
) {
    let (writer, handle, mut observer, identity, mut restored) = model_native();
    let exit_state = restored.clone();
    pair(&mut observer, BootstrapEffect::PatchEntry, None);
    pair(&mut observer, BootstrapEffect::FirstUserResume, None);
    let mut trap = restored.clone();
    trap.registers.rip += 1;
    trap.registers.orig_rax = u64::MAX;
    // A real first-user image may change XSTATE (for example PKRU); retain the
    // actual model trap bytes and compare restored state against those bytes.
    trap.xstate[600] ^= 0x08;
    seed_raw(&writer, handle, &trap, (libc::SIGTRAP << 8) | 0x7f, 0);
    ReplacedBootstrapObservation::entry_trap(&mut observer, &trap).unwrap();
    pair(&mut observer, BootstrapEffect::RestoreEntry, None);
    let trap_state = trap.clone();
    restored = trap;
    restored.registers.rip -= 1;
    let restored_stop = AdmissionStop {
        token: stop(identity, 2),
        identity,
        phase: trusted::AdmissionPhase::Restored,
        signal: None,
    };
    ReplacedBootstrapObservation::restored_entry(&mut observer, &restored_stop, &restored).unwrap();
    pair(&mut observer, BootstrapEffect::WriteStub, None);
    pair(&mut observer, BootstrapEffect::MapIsland, Some(0x900000));
    pair(
        &mut observer,
        BootstrapEffect::WriteIsland { address: 0x900000 },
        None,
    );
    pair(
        &mut observer,
        BootstrapEffect::ProtectIsland {
            address: 0x900000,
            length: 4096,
        },
        None,
    );
    pair(&mut observer, BootstrapEffect::QueryMembarrier, Some(0x7f));
    pair(&mut observer, BootstrapEffect::RegisterMembarrier, None);
    pair(&mut observer, BootstrapEffect::BootstrapSync, None);
    pair(&mut observer, BootstrapEffect::RestoreOriginal, None);
    pair(&mut observer, BootstrapEffect::QuarantineSyncBefore, None);
    let originals: Vec<_> = (0..count)
        .map(|index| MemoryMapping {
            start: NEW_PC + index as u64 * 4096,
            end: NEW_PC + (index as u64 + 1) * 4096,
            permissions: "r-xp".into(),
            file_offset: 0,
            pathname: None,
        })
        .collect();
    for map in &originals {
        pair(
            &mut observer,
            BootstrapEffect::Quarantine {
                start: map.start,
                length: 4096,
            },
            None,
        );
    }
    pair(&mut observer, BootstrapEffect::QuarantineSyncAfter, None);
    let stop = AdmissionStop {
        token: stop(identity, 20),
        identity,
        phase: trusted::AdmissionPhase::Restored,
        signal: None,
    };
    let boot = BootstrapMm {
        island: trusted::TrustedIsland {
            address_space: identity.address_space,
            generation: 0,
            range: 0x900000..0x901000,
            page_size: 4096,
        },
        original_executables: originals,
        mappings: Vec::new(),
        stop: stop.clone(),
        evidence: super::super::bootstrap::BootstrapEvidence {
            exec_event: state(NEW_PC),
            exec_exit: exit_state,
            entry_trap: trap_state,
            restored_entry: restored,
        },
    };
    ReplacedBootstrapObservation::complete(&mut observer, &boot).unwrap();
    (writer, handle, observer, stop)
}
fn seed_final_maps(writer: &ExecJournalWriter, handle: ExecAttemptHandle, stop: &AdmissionStop) {
    let mut guard = lock(&writer.archive);
    let attempt = attempt(&mut guard, handle).unwrap();
    assert_eq!(attempt.native_phase, NativePhase::BootstrapComplete);
    attempt
        .append(ExecJournalFact::QuarantinedMapsAttempt {
            stop: (&stop.token).into(),
        })
        .unwrap();
    let maps = &mut attempt.final_maps.record;
    maps.tid = 100;
    maps.raw_status = (libc::SIGTRAP << 8) | 0x7f;
    maps.status = ExecMapsStatus::Complete;
    maps.initialized[..3].copy_from_slice(b"nx\n");
    maps.observed_bytes = 3;
    attempt
        .append(ExecJournalFact::QuarantinedMapsComplete {
            stop: (&stop.token).into(),
        })
        .unwrap();
    attempt.native_phase = NativePhase::MapsComplete;
}

#[test]
fn exec_archive_preparation_is_disjoint_exact_and_unpublished() {
    let (pending, input, before, _) = binding();
    let mut expired = ExecJournalWriter::new(SESSION);
    assert!(matches!(
        expired.prepare(&pending, &input, &before, Instant::now()),
        Err(LaunchError::Timeout("admitted exec journal"))
    ));
    assert!(expired.reader().snapshot().attempt.is_none());
    for number in [
        libc::SYS_getpid as u64,
        libc::SYS_rt_sigaction as u64,
        libc::SYS_mmap as u64,
        0x4000_003b,
        u64::MAX,
    ] {
        let mut writer = ExecJournalWriter::new(SESSION);
        let mut altered = before.clone();
        altered.registers.rax = number;
        let input = SelectedInput::new(input.instruction().clone(), altered.registers).unwrap();
        refused(
            writer.prepare(
                &pending,
                &input,
                &altered,
                Instant::now() + Duration::from_secs(3),
            ),
            "exec journal input is not exact native execve",
        );
        assert!(writer.reader().snapshot().attempt.is_none());
    }
    for row in 0..6 {
        let mut writer = ExecJournalWriter::new(SESSION);
        let mut pending = pending.clone();
        let mut before = before.clone();
        match row {
            0 => pending.stop.session += 1,
            1 => pending.stop.tid = 0,
            2 => pending.epoch += 1,
            3 => pending.invocation = 0,
            4 => before.registers.rbx ^= 1,
            5 => before.xstate.resize(MAX_XSTATE, 0),
            _ => unreachable!(),
        }
        refused(
            writer.prepare(
                &pending,
                &input,
                &before,
                Instant::now() + Duration::from_secs(3),
            ),
            "exec journal binding is not an exact finite invocation",
        );
        assert!(writer.reader().snapshot().attempt.is_none());
    }
}

#[test]
fn exec_archive_allocates_fourteen_full_buffers_and_never_refunds_preparation() {
    let (pending, input, before, _) = binding();
    let mut writer = ExecJournalWriter::new(SESSION);
    let base = writer.allocated_bytes();
    let prepared = writer
        .prepare(
            &pending,
            &input,
            &before,
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
    let payload = prepared
        .attempt
        .raw
        .iter()
        .map(|raw| {
            raw.record.initialized_xstate.capacity() + raw.record.maps.initialized.capacity()
        })
        .sum::<usize>()
        + prepared.attempt.before.xstate.capacity()
        + prepared.attempt.restored_entry.xstate.capacity()
        + prepared.attempt.final_state.xstate.capacity()
        + prepared.attempt.final_maps.record.initialized.capacity();
    assert!(payload >= 14 * MAX_XSTATE);
    assert_eq!(
        prepared.allocated_bytes(),
        base + std::mem::size_of::<Attempt>() + payload
    );
    assert_eq!(writer.allocated_bytes(), prepared.allocated_bytes());
    assert!(writer.reader().snapshot().attempt.is_none());
    let charged = prepared.allocated_bytes();
    drop(prepared);
    assert_eq!(writer.allocated_bytes(), charged);
    refused(
        writer.prepare(
            &pending,
            &input,
            &before,
            Instant::now() + Duration::from_secs(3),
        ),
        "exec journal binding is not an exact finite invocation",
    );
}

#[test]
fn exec_archive_foreign_preparation_and_handle_cannot_alias_equal_sessions() {
    let (pending, input, before, _) = binding();
    let mut first = ExecJournalWriter::new(SESSION);
    let mut second = ExecJournalWriter::new(SESSION);
    let prepared = first
        .prepare(
            &pending,
            &input,
            &before,
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
    refused(
        second.attach(prepared),
        "exec journal prepared archive differs",
    );
    assert!(first.reader().snapshot().attempt.is_none());
    assert!(second.reader().snapshot().attempt.is_none());
    let (writer, handle, ..) = attached();
    refused(
        second.observer(handle),
        "exec journal handle belongs to another archive",
    );
    assert_eq!(
        writer.reader().snapshot().attempt.unwrap().facts,
        [ExecJournalFact::Attached]
    );
}

#[test]
fn exec_archive_independent_failed_read_substrates_remain_initialized() {
    let (writer, handle, _, before, _) = attached();
    let ordinal = seed_raw(
        &writer,
        handle,
        &before,
        ((libc::SIGTRAP | 0x80) << 8) | 0x7f,
        1,
    );
    {
        let mut guard = lock(&writer.archive);
        let attempt = attempt(&mut guard, handle).unwrap();
        let raw = &mut attempt.raw[usize::from(ordinal)].record;
        raw.complete = false;
        raw.registers_read = Some(ExecReadOutcome {
            result: -1,
            errno: Some(libc::EIO),
        });
        raw.registers.r15 = 0xfeed;
        raw.initialized_xstate[MAX_XSTATE - 1] = 0xab;
        raw.xstate_query.as_mut().unwrap().reported_bytes = MAX_XSTATE + 8;
        raw.mask_read = Some(ExecReadOutcome {
            result: -1,
            errno: Some(libc::ESRCH),
        });
        raw.maps.status = ExecMapsStatus::Failed(KernelFailureKind::NativeIo(Some(libc::EACCES)));
        assert!(
            matches!(capture::complete_reads(raw), Err(LaunchError::System { source, .. }) if source.raw_os_error() == Some(libc::EIO))
        );
    }
    writer.fail_error(&io_error(
        "synthetic read",
        io::Error::from_raw_os_error(libc::EIO),
    ));
    let snapshot = writer.reader().snapshot();
    let raw = &snapshot.attempt.unwrap().raw[0];
    assert!(!raw.complete);
    assert_eq!(raw.registers.r15, 0xfeed);
    assert_eq!(raw.initialized_xstate.len(), MAX_XSTATE);
    assert_eq!(raw.initialized_xstate[MAX_XSTATE - 1], 0xab);
    assert_eq!(raw.xstate_query.unwrap().reported_bytes, MAX_XSTATE + 8);
    assert_eq!(raw.mask_read.unwrap().errno, Some(libc::ESRCH));
    assert_eq!(raw.syscall_read.unwrap().result, 80);
    assert_eq!(raw.event_read.unwrap().result, 0);
    assert_eq!(raw.siginfo_read.unwrap().result, 0);
    assert_eq!(raw.maps.observed_bytes, 4);
    assert_eq!(&raw.maps.initialized[..4], b"map\n");
    assert!(raw.maps.initialized[4..].iter().all(|byte| *byte == 0));
    assert_eq!(
        snapshot.first_failure.unwrap().1,
        KernelFailureKind::NativeIo(Some(libc::EIO))
    );
}

#[test]
fn exec_archive_required_xstate_and_status_info_checks_remain_exact() {
    for row in 0..7 {
        let (writer, handle, _, before, _) = attached();
        seed_raw(
            &writer,
            handle,
            &before,
            ((libc::SIGTRAP | 0x80) << 8) | 0x7f,
            1,
        );
        let mut guard = lock(&writer.archive);
        let raw = &mut attempt(&mut guard, handle).unwrap().raw[0].record;
        match row {
            0 => raw.xstate_query.as_mut().unwrap().pointer_unchanged = false,
            1 => raw.xstate_query.as_mut().unwrap().reported_bytes = 511,
            2 => raw.xstate_query.as_mut().unwrap().reported_bytes = MAX_XSTATE,
            3 => raw.syscall_read.as_mut().unwrap().result = 79,
            4 => raw.syscall_read.as_mut().unwrap().result = 89,
            5 => raw.syscall_info[0] = 0,
            6 => raw.registers_read.as_mut().unwrap().result = 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            capture::complete_reads(raw),
            Err(LaunchError::Invalid(_))
        ));
    }
}

#[test]
fn exec_archive_real_registry_birth_zero_retains_ordinal_chronology() {
    let (writer, handle, _, next, _) = model_native();
    let snapshot = writer.reader().snapshot().attempt.unwrap();
    assert_eq!(snapshot.pending_stop.sequence, 40);
    assert_eq!(snapshot.replacement, Some(next));
    let validations: Vec<_> = snapshot
        .facts
        .iter()
        .filter_map(|fact| match fact {
            ExecJournalFact::Validated {
                phase,
                ordinal,
                stop,
                ..
            } => Some((*phase, *ordinal, stop.sequence)),
            _ => None,
        })
        .collect();
    assert_eq!(
        validations,
        [
            (ExecValidatedPhase::Entry, 0, 42),
            (ExecValidatedPhase::Replaced, 1, 0),
            (ExecValidatedPhase::Exit, 2, 1)
        ]
    );
    assert_eq!(snapshot.id, handle.id());
    assert_eq!(snapshot.raw.len(), 3);
    assert!(
        snapshot
            .facts
            .iter()
            .all(|fact| !matches!(fact, ExecJournalFact::AdmissionComplete { .. }))
    );
}

#[test]
fn exec_archive_validated_state_never_masks_register_mask_or_xstate_corruption() {
    for row in 0..4 {
        let (writer, handle, pending, mut before, _) = attached();
        seed_ready(&writer, handle);
        let mut observer = writer.observer(handle).unwrap();
        ExecObservation::release_attempt(
            &mut observer,
            ExecRelease::Original,
            &stop(pending.task, 41),
        )
        .unwrap();
        ExecObservation::release_succeeded(
            &mut observer,
            ExecRelease::Original,
            &stop(pending.task, 41),
        )
        .unwrap();
        before.registers.rip = PC + 2;
        seed_raw(
            &writer,
            handle,
            &before,
            ((libc::SIGTRAP | 0x80) << 8) | 0x7f,
            1,
        );
        let mut altered = before.clone();
        match row {
            0 => altered.registers.rbx ^= 1,
            1 => altered.mask ^= 1,
            2 => altered.xstate[700] ^= 1,
            3 => altered.xstate.push(0),
            _ => unreachable!(),
        }
        let arguments = lock(&writer.archive)
            .attempt
            .as_ref()
            .unwrap()
            .input
            .arguments;
        refused(
            ExecObservation::entry(
                &mut observer,
                &event(
                    pending.task,
                    42,
                    DynamicEventKind::SyscallEntry {
                        number: 59,
                        arguments,
                    },
                ),
                &altered,
            ),
            "exec journal validated full state differs from raw capture",
        );
        let snapshot = writer.reader().snapshot();
        let attempt = snapshot.attempt.unwrap();
        assert_eq!(attempt.raw[0].registers, before.registers);
        assert_eq!(&attempt.raw[0].initialized_xstate[..832], before.xstate);
        assert!(
            !attempt
                .facts
                .iter()
                .any(|fact| matches!(fact, ExecJournalFact::Validated { .. }))
        );
        assert_eq!(
            snapshot.first_failure.unwrap().1,
            KernelFailureKind::InvalidState
        );
    }
}

#[test]
fn exec_archive_full_sixty_four_mapping_schedule_stays_within_fixed_capacity() {
    let (writer, handle, _, stop) = model_bootstrap(64);
    seed_final_maps(&writer, handle, &stop);
    writer
        .sources_requested(handle, 7, &stop, 64, 64 * 4096)
        .unwrap();
    writer.sources_accepted(handle, 7, 64).unwrap();
    let ready = lock(&writer.archive)
        .attempt
        .as_ref()
        .unwrap()
        .final_state
        .snapshot();
    let ready = TaskStateSnapshot {
        registers: ready.registers,
        xstate: ready.xstate,
        mask: ready.signal_mask,
    };
    writer.admission_complete(handle, &stop, &ready).unwrap();
    let snapshot = writer.reader().snapshot();
    let attempt = snapshot.attempt.unwrap();
    assert_eq!(attempt.raw.len(), 4);
    assert_eq!(attempt.facts.len(), 178);
    assert_eq!(MAX_SCHEDULE, 179);
    assert_eq!(FACTS, 192);
    assert_eq!(
        attempt
            .facts
            .iter()
            .filter(|fact| matches!(fact, ExecJournalFact::EffectAttempt { .. }))
            .count(),
        77
    );
    assert_eq!(
        attempt
            .facts
            .iter()
            .filter(|fact| matches!(fact, ExecJournalFact::EffectComplete { .. }))
            .count(),
        77
    );
    assert_eq!(attempt.restored_entry, attempt.final_state);
    assert_eq!(snapshot.first_failure, None);
    assert!(matches!(
        attempt.facts.last(),
        Some(ExecJournalFact::AdmissionComplete { .. })
    ));
}

#[test]
fn exec_archive_effect_geometry_pair_and_capacity_refuse_before_next_effect() {
    for row in 0..3 {
        let (writer, handle, mut observer, _, _) = model_native();
        if row == 2 {
            let mut guard = lock(&writer.archive);
            let attempt = attempt(&mut guard, handle).unwrap();
            while attempt.fact_count < FACTS - 1 {
                attempt.append(ExecJournalFact::Attached).unwrap();
            }
        }
        let prefix = writer.reader().snapshot().attempt.unwrap().facts;
        let result = ReplacedBootstrapObservation::before_effect(
            &mut observer,
            if row == 0 {
                BootstrapEffect::RestoreEntry
            } else {
                BootstrapEffect::PatchEntry
            },
        );
        if row == 1 {
            result.unwrap();
            refused(
                ReplacedBootstrapObservation::effect_complete(
                    &mut observer,
                    BootstrapEffect::WriteStub,
                    None,
                ),
                "exec journal bootstrap completion pair differs",
            );
            assert_eq!(
                writer.reader().snapshot().attempt.unwrap().facts.len(),
                prefix.len() + 1
            );
        } else {
            refused(
                result,
                if row == 2 {
                    "exec journal bootstrap pair capacity exhausted"
                } else {
                    "exec journal bootstrap effect order or geometry differs"
                },
            );
            let snapshot = writer.reader().snapshot();
            assert_eq!(snapshot.attempt.unwrap().facts, prefix);
            if row == 2 {
                assert_eq!(
                    snapshot.first_failure.unwrap().1,
                    KernelFailureKind::Capacity
                );
            }
        }
    }
    let (writer, handle, mut observer, _) = model_bootstrap(64);
    {
        let guard = lock(&writer.archive);
        let stored = guard.attempt.as_ref().unwrap();
        assert_eq!(stored.quarantine_count, 64);
    }
    let prefix = writer.reader().snapshot().attempt.unwrap().facts;
    refused(
        ReplacedBootstrapObservation::before_effect(
            &mut observer,
            BootstrapEffect::Quarantine {
                start: 0xa00000,
                length: 4096,
            },
        ),
        "exec journal bootstrap effect order or geometry differs",
    );
    assert_eq!(writer.reader().snapshot().attempt.unwrap().facts, prefix);
    assert_eq!(handle.id().session, SESSION);
}

#[test]
fn exec_archive_effect_return_value_survives_later_payload_refusal() {
    let (writer, handle, mut observer, _, _) = model_native();
    {
        let mut guard = lock(&writer.archive);
        let attempt = attempt(&mut guard, handle).unwrap();
        // Synthetic fixture places the next typed operation at mmap, without
        // claiming earlier bootstrap operations or native execution occurred.
        attempt.native_phase = NativePhase::Bootstrapping;
        attempt.effect_index = 4;
    }
    ReplacedBootstrapObservation::before_effect(&mut observer, BootstrapEffect::MapIsland).unwrap();
    refused(
        ReplacedBootstrapObservation::effect_complete(
            &mut observer,
            BootstrapEffect::MapIsland,
            Some(3),
        ),
        "exec journal mapped island result differs",
    );
    let snapshot = writer.reader().snapshot();
    assert!(matches!(
        snapshot.attempt.unwrap().facts.last(),
        Some(ExecJournalFact::EffectComplete {
            effect: ExecBootstrapEffect::MapIsland,
            result: Some(3)
        })
    ));
    assert_eq!(
        snapshot.first_failure.unwrap().1,
        KernelFailureKind::InvalidState
    );
}

#[test]
fn exec_archive_maps_borrows_bind_validated_exit_and_distinct_final_capture() {
    let (writer, handle, _, stop) = model_bootstrap(1);
    refused(
        writer.with_source_maps(handle, |_| ()),
        "exec journal source maps are incomplete",
    );
    seed_final_maps(&writer, handle, &stop);
    writer
        .with_source_maps(handle, |view| {
            assert_eq!(view.exit_ordinal, 2);
            assert_eq!(view.exit_stop.sequence, 1);
            assert_eq!(view.final_stop.sequence, 20);
            assert_ne!(view.previous.task, view.replacement.task);
            assert_ne!(view.previous.address_space, view.replacement.address_space);
            assert_eq!(view.previous.process, view.replacement.process);
            assert_eq!(view.exit_bytes, b"map\n");
            assert_eq!(view.quarantine_bytes, b"nx\n");
            assert_eq!(view.exit.initialized.len(), MAP_BYTES);
            assert_eq!(view.quarantine.initialized.len(), MAP_BYTES);
        })
        .unwrap();
    writer
        .with_raw_maps(handle, 2, |record, bytes| {
            assert_eq!(record.observed_bytes, 4);
            assert_eq!(bytes, b"map\n");
        })
        .unwrap();
    writer
        .with_quarantined_maps(handle, |record, bytes| {
            assert_eq!(record.observed_bytes, 3);
            assert_eq!(bytes, b"nx\n");
        })
        .unwrap();
    refused(
        writer.with_raw_maps(handle, 4, |_, _| ()),
        "exec journal raw map ordinal is absent",
    );
}

#[test]
fn exec_archive_source_acceptance_keeps_exact_deadline_request_and_ready_stop() {
    for row in 0..4 {
        let (writer, handle, _, stop) = model_bootstrap(1);
        seed_final_maps(&writer, handle, &stop);
        let original_until = writer.reader().snapshot().attempt.unwrap().original_until;
        writer.sources_requested(handle, 7, &stop, 1, 4096).unwrap();
        if row == 0 {
            refused(
                writer.sources_accepted(handle, 8, 1),
                "exec journal source acceptance differs",
            );
        } else if row == 1 {
            refused(
                writer.sources_requested(handle, 7, &stop, 1, 4096),
                "exec journal source request binding differs",
            );
        } else {
            writer.sources_accepted(handle, 7, 1).unwrap();
            let mut changed = stop.clone();
            if row == 2 {
                changed.token.sequence += 1;
            } else {
                changed.identity.generation += 1;
            }
            let ready = lock(&writer.archive)
                .attempt
                .as_ref()
                .unwrap()
                .final_state
                .snapshot();
            let ready = TaskStateSnapshot {
                registers: ready.registers,
                xstate: ready.xstate,
                mask: ready.signal_mask,
            };
            refused(
                writer.admission_complete(handle, &changed, &ready),
                "exec journal admission completion differs",
            );
        }
        let snapshot = writer.reader().snapshot();
        let attempt = snapshot.attempt.unwrap();
        assert_eq!(attempt.original_until, original_until);
        assert!(
            !attempt
                .facts
                .iter()
                .any(|fact| matches!(fact, ExecJournalFact::AdmissionComplete { .. }))
        );
    }
}

#[test]
fn exec_archive_unwind_first_failure_and_cleanup_are_independently_retained() {
    let (writer, handle, ..) = attached();
    let reader = writer.reader();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _scope = writer.panic_scope();
        panic!("synthetic owner unwind");
    }));
    assert!(result.is_err());
    let prefix = reader.snapshot().attempt.unwrap().facts;
    writer.fail_error(&LaunchError::Timeout("later synthetic timeout"));
    writer.finish_cleanup(true);
    writer.finish_cleanup(false);
    drop(writer);
    let snapshot = reader.snapshot();
    assert_eq!(
        snapshot.first_failure.unwrap().1,
        KernelFailureKind::CaughtPanic
    );
    assert!(snapshot.closing);
    assert_eq!(snapshot.cleanup_complete, Some(false));
    assert_eq!(snapshot.attempt.as_ref().unwrap().facts, prefix);
    assert_eq!(snapshot.attempt.unwrap().id, handle.id());
}
