use super::*;
use liteinst_launch::{
    DynamicAdmissionState, DynamicSourceCaptureId, ExecAttemptSnapshot, ExecBootstrapEffect,
    ExecJournalFact, ExecJournalStage, ExecMapsStatus, ExecProgressSnapshot, ExecRawRecord,
    ExecReleasePhase, ExecValidatedPhase, KernelFailureKind,
};

use liteinst_launch::{ExecMapsRecord, KernelPinKind, KernelStopIdentity};

pub fn architecture(raw: &ExecRawRecord) -> Architecture {
    assert!(raw.held && raw.complete);
    assert_eq!(raw.pin, KernelPinKind::Process);
    for read in [raw.registers_read, raw.mask_read] {
        let read = read.unwrap();
        assert_eq!((read.result, read.errno), (0, None));
    }
    let query = raw.xstate_query.unwrap();
    assert_eq!((query.outcome.result, query.outcome.errno), (0, None));
    assert!(query.pointer_unchanged && (512..65536).contains(&query.reported_bytes));
    assert_eq!(raw.initialized_xstate.len(), 65536);
    assert!(
        raw.initialized_xstate[query.reported_bytes..]
            .iter()
            .all(|b| *b == 0)
    );
    // Even non-applicable queries remain actual outcomes; no missing family
    // is silently interpreted as a successful zero-filled record.
    assert!(raw.syscall_read.is_some() && raw.event_read.is_some() && raw.siginfo_read.is_some());
    Architecture {
        registers: raw.registers,
        xstate: raw.initialized_xstate[..query.reported_bytes].to_vec(),
        mask: raw.signal_mask,
    }
}
pub fn maps(record: &ExecMapsRecord) -> Maps {
    assert_eq!(record.status, ExecMapsStatus::Complete);
    assert_eq!(record.initialized.len(), 65536);
    assert!(record.observed_bytes > 0 && record.observed_bytes <= 65536 && record.read_calls > 0);
    assert!(
        record.initialized[record.observed_bytes..]
            .iter()
            .all(|b| *b == 0)
    );
    let open = record.open.unwrap();
    assert!(open.result >= 0 && open.errno.is_none());
    for outcome in [record.filesystem, record.close, record.last_read] {
        let out = outcome.unwrap();
        assert_eq!((out.result, out.errno), (0, None));
    }
    assert_eq!(record.filesystem_type, libc::PROC_SUPER_MAGIC);
    assert_eq!(record.overflow_byte, 0);
    Maps::parse(record.initialized[..record.observed_bytes].to_vec())
}
#[derive(Clone, Debug)]
pub struct Context {
    pub stack: Stack,
    pub before: DynamicAdmissionState,
    pub tid: i32,
    pub request: liteinst_launch::DynamicSourceRequestId,
    pub capture: DynamicSourceCaptureId,
    pub incarnation: u64,
    pub journal_bytes: usize,
    pub attempt: liteinst_launch::KernelAttemptId,
    pub until: Instant,
    pub candidate: liteinst_launch::DynamicTask,
    pub source: Vec<u8>,
    pub data: Vec<u8>,
    pub current: Maps,
    pub old_maps: Maps,
}
fn info(raw: &ExecRawRecord, op: u8, reference: Option<&(usize, [u8; 88])>) {
    let outcome = raw.syscall_read.unwrap();
    assert!(outcome.errno.is_none() && outcome.result >= 0);
    let len = outcome.result as usize;
    assert!(if op == 1 {
        (80..=88).contains(&len)
    } else {
        (33..=88).contains(&len)
    });
    let bytes = &raw.syscall_info;
    assert_eq!(bytes[0], op);
    assert_eq!(
        u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        0xc000003e
    );
    assert_eq!(
        u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        raw.registers.rip
    );
    assert_eq!(
        u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
        raw.registers.rsp
    );
    if let Some((size, expected)) = reference {
        assert_eq!(len, *size);
        assert_eq!(bytes, expected);
    }
    if op == 2 {
        assert_eq!(i64::from_ne_bytes(bytes[24..32].try_into().unwrap()), 0);
        assert_eq!(bytes[32], 0);
    }
}
fn stop_bound(
    stop: KernelStopIdentity,
    snapshot: &ExecAttemptSnapshot,
    task: liteinst_launch::DynamicTask,
) {
    assert_eq!(stop.session, snapshot.id.session);
    assert_eq!(stop.tid, snapshot.pending_stop.tid);
    assert_eq!(stop.task, Some(task.task));
}
pub fn check(
    f: &Fixture,
    reference: &raw::Transcript,
    snapshot: &ExecProgressSnapshot,
    context: &Context,
    complete: bool,
    cleaned: bool,
) -> Architecture {
    assert!(!snapshot.archive_poisoned);
    assert!(snapshot.allocated_bytes >= 14 * 65536);
    assert_eq!(snapshot.allocated_bytes, context.journal_bytes);
    assert_eq!(snapshot.cleanup_complete, cleaned.then_some(true));
    assert_eq!(snapshot.closing, cleaned);
    if complete {
        assert_eq!(snapshot.first_failure, None);
    } else if cleaned {
        assert_eq!(
            snapshot.first_failure,
            Some((ExecJournalStage::Sources, KernelFailureKind::Cancelled))
        );
    } else {
        assert_eq!(snapshot.first_failure, None);
    }
    assert_eq!(
        snapshot.stage,
        if cleaned {
            ExecJournalStage::Closing
        } else if complete {
            ExecJournalStage::Admission
        } else {
            ExecJournalStage::Sources
        }
    );
    let a = snapshot.attempt.as_ref().unwrap();
    assert_eq!(a.id.session, snapshot.session);
    assert_eq!(a.id.session, context.request.session());
    assert_eq!(a.id, context.attempt);
    assert!(a.id.invocation > 0);
    assert_eq!(a.previous, context.before.task);
    assert_eq!(a.pending_stop.tid, context.tid);
    stop_bound(a.pending_stop, a, a.previous);
    assert_eq!(a.source_epoch, a.previous.generation);
    assert!(a.source_plan > 0);
    assert_eq!(a.original_until, context.until);
    assert_eq!(
        Architecture::captured(&a.before),
        Architecture::admitted(&context.before)
    );
    assert_eq!(
        Architecture::captured(&a.before),
        reference.before_exec.architecture
    );
    assert_eq!(a.input.logical_pc, f.exec);
    assert_eq!(a.input.next_pc, f.exec + 2);
    assert_eq!(
        a.input.registers,
        reference.before_exec.architecture.registers
    );
    assert_eq!(a.input.instruction_bytes, 2);
    assert_eq!(&a.input.initialized_instruction[..2], &[0x0f, 0x05]);
    assert!(a.input.initialized_instruction[2..].iter().all(|b| *b == 0));
    let r = a.input.registers;
    assert_eq!(a.input.arguments, [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9]);
    let new = a.replacement.unwrap();
    assert_eq!(new, context.candidate);
    assert_ne!(new.task, a.previous.task);
    assert_ne!(new.address_space, a.previous.address_space);
    assert_eq!(new.process, a.previous.process);
    assert_eq!(new.generation, 0);
    assert_eq!(a.raw.len(), 4);
    let mut raw_arch = Vec::new();
    let mut raw_maps = Vec::new();
    for (index, raw) in a.raw.iter().enumerate() {
        assert_eq!(raw.ordinal as usize, index);
        assert_eq!(raw.tid, context.tid);
        assert_eq!((raw.maps.tid, raw.maps.raw_status), (raw.tid, raw.status));
        raw_arch.push(architecture(raw));
        raw_maps.push(maps(&raw.maps));
    }
    assert!(
        raw_maps[0] == context.old_maps,
        "complete original ENTRY maps changed"
    );
    assert_eq!(a.raw[0].status, reference.entry_status);
    assert_eq!(raw_arch[0], reference.entry.architecture);
    info(&a.raw[0], 1, Some(&reference.entry_info));
    assert_eq!(
        a.raw[1].status,
        (libc::PTRACE_EVENT_EXEC << 16) | (libc::SIGTRAP << 8) | 0x7f
    );
    let event = a.raw[1].event_read.unwrap();
    assert_eq!((event.result, event.errno), (0, None));
    assert_eq!(a.raw[1].event_message, context.tid as u64);
    compare::initial_stack(f, &context.stack);
    assert_eq!(
        raw_arch[1].registers,
        compare::exec_registers(&context.stack, f.first_cpu)
    );
    assert_eq!(raw_arch[1].mask, APP_MASK);
    assert_eq!(raw_arch[1].xstate, reference.exec.architecture.xstate);
    assert_eq!(a.raw[2].status, ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
    info(&a.raw[2], 2, None);
    let mut expected_exit = raw_arch[1].clone();
    expected_exit.registers.rax = 0;
    assert_eq!(raw_arch[2], expected_exit);
    assert_eq!(raw_arch[2].xstate, reference.exit.architecture.xstate);
    assert!(raw_maps[1] == raw_maps[2], "complete EXEC/EXIT maps differ");
    assert!(
        raw_maps[2] == raw_maps[3],
        "complete EXIT/first-user maps differ"
    );
    assert_eq!(a.raw[3].status, (libc::SIGTRAP << 8) | 0x7f);
    let signal = a.raw[3].siginfo_read.unwrap();
    assert_eq!((signal.result, signal.errno), (0, None));
    assert_eq!(
        i32::from_ne_bytes(a.raw[3].siginfo[..4].try_into().unwrap()),
        libc::SIGTRAP
    );
    assert_eq!(
        i32::from_ne_bytes(a.raw[3].siginfo[8..12].try_into().unwrap()),
        libc::SI_KERNEL
    );
    let mut expected_trap = expected_exit.registers;
    expected_trap.rip = f.first_cpu + 1;
    expected_trap.orig_rax = u64::MAX;
    assert_eq!(raw_arch[3].registers, expected_trap);
    assert_eq!(raw_arch[3].mask, APP_MASK);
    assert_eq!(raw_arch[3].xstate, reference.trap.architecture.xstate);
    let mut restored = raw_arch[3].clone();
    restored.registers.rip = f.first_cpu;
    assert_eq!(
        Architecture::captured(a.restored_entry.as_ref().unwrap()),
        restored
    );
    assert_eq!(
        Architecture::captured(a.final_state.as_ref().unwrap()),
        restored
    );
    let final_maps = maps(&a.quarantined_maps);
    assert!(
        final_maps == context.current,
        "complete quarantine maps changed"
    );
    let island = compare::quarantine(&raw_maps[2], &final_maps);
    assert_eq!(context.source, f.new_source);
    assert_eq!(context.data, f.new_data);
    assert_eq!(context.capture.request(), context.request);
    assert_eq!(context.capture.index(), 0);
    assert_ne!(context.incarnation, 0);
    let validations = a
        .facts
        .iter()
        .filter_map(|fact| {
            if let ExecJournalFact::Validated {
                phase,
                ordinal,
                stop,
                identity,
            } = fact
            {
                Some((*phase, *ordinal, *stop, *identity))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(validations.len(), 3);
    for (index, (phase, ordinal, stop, identity)) in validations.iter().enumerate() {
        assert_eq!(
            *phase,
            [
                ExecValidatedPhase::Entry,
                ExecValidatedPhase::Replaced,
                ExecValidatedPhase::Exit
            ][index]
        );
        assert_eq!(*ordinal, index as u8);
        assert_eq!(*identity, if index == 0 { a.previous } else { new });
        stop_bound(*stop, a, *identity);
    }
    let original = a.restored_original_stop.unwrap();
    stop_bound(original, a, a.previous);
    assert!(original.sequence >= a.pending_stop.sequence);
    let entry = validations[0].2;
    let exec = validations[1].2;
    let exit = validations[2].2;
    assert!(entry.sequence > original.sequence);
    assert_eq!(exec.sequence, 0);
    assert!(exit.sequence > exec.sequence);
    let only_stop = |kind: u8| {
        let values = a
            .facts
            .iter()
            .filter_map(|fact| match (kind, fact) {
                (0, ExecJournalFact::RestoredEntry { stop })
                | (1, ExecJournalFact::BootstrapComplete { stop }) => Some(*stop),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 1);
        values[0]
    };
    let first = only_stop(0);
    let final_stop = only_stop(1);
    stop_bound(first, a, new);
    stop_bound(final_stop, a, new);
    assert!(first.sequence > exit.sequence && final_stop.sequence > first.sequence);
    let query = a
        .facts
        .iter()
        .filter_map(|f| match f {
            ExecJournalFact::EffectComplete {
                effect: ExecBootstrapEffect::QueryMembarrier,
                result: Some(value),
            } => Some(*value),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(query.len(), 1);
    assert_eq!(query[0] & ((1 << 5) | (1 << 6)), (1 << 5) | (1 << 6));
    let mut facts = vec![
        ExecJournalFact::Attached,
        ExecJournalFact::RestoreAttempt,
        ExecJournalFact::RestoreComplete,
    ];
    for (index, (phase, stop)) in [
        (ExecReleasePhase::Original, original),
        (ExecReleasePhase::Entry, entry),
        (ExecReleasePhase::ExecEvent, exec),
    ]
    .into_iter()
    .enumerate()
    {
        facts.push(ExecJournalFact::ReleaseAttempt { phase, stop });
        facts.push(ExecJournalFact::ReleaseSucceeded { phase, stop });
        facts.push(ExecJournalFact::Raw {
            ordinal: index as u8,
        });
        let (phase, ordinal, stop, identity) = validations[index];
        facts.push(ExecJournalFact::Validated {
            phase,
            ordinal,
            stop,
            identity,
        });
    }
    let pair = |facts: &mut Vec<ExecJournalFact>, effect, result| {
        facts.push(ExecJournalFact::EffectAttempt { effect });
        facts.push(ExecJournalFact::EffectComplete { effect, result });
    };
    pair(&mut facts, ExecBootstrapEffect::PatchEntry, None);
    pair(&mut facts, ExecBootstrapEffect::FirstUserResume, None);
    facts.push(ExecJournalFact::Raw { ordinal: 3 });
    facts.push(ExecJournalFact::FirstUserTrap { ordinal: 3 });
    pair(&mut facts, ExecBootstrapEffect::RestoreEntry, None);
    facts.push(ExecJournalFact::RestoredEntry { stop: first });
    for (effect, result) in [
        (ExecBootstrapEffect::WriteStub, None),
        (ExecBootstrapEffect::MapIsland, Some(island.start)),
        (
            ExecBootstrapEffect::WriteIsland {
                address: island.start,
            },
            None,
        ),
        (
            ExecBootstrapEffect::ProtectIsland {
                address: island.start,
                length: PAGE,
            },
            None,
        ),
        (ExecBootstrapEffect::QueryMembarrier, Some(query[0])),
        (ExecBootstrapEffect::RegisterMembarrier, None),
        (ExecBootstrapEffect::BootstrapSync, None),
        (ExecBootstrapEffect::RestoreOriginal, None),
        (ExecBootstrapEffect::QuarantineSyncBefore, None),
    ] {
        pair(&mut facts, effect, result);
    }
    let ranges = raw_maps[2]
        .rows
        .iter()
        .filter(|m| m.permissions.as_bytes()[2] == b'x' && m.path.as_deref() != Some("[vsyscall]"))
        .collect::<Vec<_>>();
    assert!(!ranges.is_empty() && ranges.len() <= 64);
    for map in ranges {
        pair(
            &mut facts,
            ExecBootstrapEffect::Quarantine {
                start: map.start,
                length: (map.end - map.start) as usize,
            },
            None,
        );
    }
    pair(&mut facts, ExecBootstrapEffect::QuarantineSyncAfter, None);
    facts.push(ExecJournalFact::BootstrapComplete { stop: final_stop });
    facts.push(ExecJournalFact::QuarantinedMapsAttempt { stop: final_stop });
    facts.push(ExecJournalFact::QuarantinedMapsComplete { stop: final_stop });
    facts.push(ExecJournalFact::SourcesRequested {
        request: context.request.serial(),
        stop: final_stop,
        images: 1,
        bytes: CODE,
    });
    if complete {
        facts.push(ExecJournalFact::SourcesAccepted {
            request: context.request.serial(),
            heads: f.new_heads.len(),
        });
        facts.push(ExecJournalFact::AdmissionComplete { stop: final_stop });
    }
    assert_eq!(a.facts, facts);
    assert!(facts.len() <= 192);
    assert_eq!(a.quarantined_maps.tid, context.tid);
    restored
}
