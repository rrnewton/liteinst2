//! Test-only borrowed inspection of private retained evidence. No seal producer.
use super::*;
use crate::linux::remote::dynamic::owner::kernel_journal::{
    RuntimeKernelAttemptSnapshot, RuntimeKernelFact, RuntimeKernelJournalStage,
    RuntimeKernelStateRecord, RuntimeKernelStateSlot,
};

fn architecture(
    observed: &ObservedStop,
    registers: RegisterSnapshot,
    xstate: &[u8],
    mask: u64,
    original: &ObservedStop,
    phase: StopPhase,
) {
    assert_eq!(observed.task, original.task);
    assert_eq!(observed.token.session, original.token.session);
    assert_eq!(observed.token.tid, original.token.tid);
    assert_eq!(observed.token.task, original.token.task);
    assert_eq!(observed.token.task, Some(original.task.task));
    assert_eq!(observed.task.generation, 0);
    assert_eq!(observed.registers, registers);
    assert_eq!(observed.logical_pc, registers.rip);
    assert_eq!(observed.xstate, xstate);
    assert_eq!(observed.signal_mask, mask);
    assert_eq!(observed.phase, phase);
    assert!(observed.signal.is_none());
}
fn slot(
    journal: &RuntimeKernelAttemptSnapshot,
    slot: RuntimeKernelStateSlot,
) -> &RuntimeKernelStateRecord {
    let rows = journal
        .states
        .iter()
        .filter(|r| r.slot == slot)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    rows[0]
}
fn observed_copy(observed: &ObservedStop, record: &RuntimeKernelStateRecord) {
    assert!(record.captured && record.finalized && record.complete);
    assert_eq!(record.initialized_xstate.len(), MAX_XSTATE_BYTES);
    assert_eq!(record.returned_length, observed.xstate.len());
    assert_eq!(
        &record.initialized_xstate[..record.returned_length],
        observed.xstate.as_slice()
    );
    assert_eq!(u64::from_ne_bytes(record.mask), observed.signal_mask);
    // Independently decode the complete x86-64 GETREGS UAPI order, without
    // pointer casts or the production register conversion.
    let words: [u64; 27] = std::array::from_fn(|index| {
        u64::from_ne_bytes(
            record.registers[index * 8..index * 8 + 8]
                .try_into()
                .expect("fixed register word"),
        )
    });
    let registers = RegisterSnapshot {
        r15: words[0],
        r14: words[1],
        r13: words[2],
        r12: words[3],
        rbp: words[4],
        rbx: words[5],
        r11: words[6],
        r10: words[7],
        r9: words[8],
        r8: words[9],
        rax: words[10],
        rcx: words[11],
        rdx: words[12],
        rsi: words[13],
        rdi: words[14],
        orig_rax: words[15],
        rip: words[16],
        cs: words[17],
        eflags: words[18],
        rsp: words[19],
        ss: words[20],
        fs_base: words[21],
        gs_base: words[22],
        ds: words[23],
        es: words[24],
        fs: words[25],
        gs: words[26],
    };
    assert_eq!(registers, observed.registers);
}
fn validated(
    journal: &RuntimeKernelAttemptSnapshot,
    stage: RuntimeKernelJournalStage,
    stop: &DynamicStop,
) {
    let facts = journal
        .facts
        .iter()
        .filter_map(|fact| {
            if let RuntimeKernelFact::Validated {
                stage: actual,
                stop,
            } = fact
            {
                (*actual == stage).then_some(*stop)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(facts, [KernelStopIdentity::from(stop)]);
}

impl ResumeCensus {
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_runtime_kernel_chain(
        &self,
        original: &ObservedStop,
        start: usize,
        identity: &RuntimeKernelIdentity,
        journal: &RuntimeKernelAttemptSnapshot,
        current: Option<OriginId>,
    ) {
        let history = &self.state.history[start..];
        assert_eq!(history.len(), if current.is_some() { 8 } else { 4 });
        assert_eq!(identity.pending().stop, original.token);
        assert_eq!(identity.task(), original.task);
        assert_eq!(journal.id, identity.attempt());
        assert_eq!(
            journal.original_stop,
            KernelStopIdentity::from(&original.token)
        );
        assert_eq!(journal.task, original.task);
        assert_eq!(journal.input_registers, original.registers);
        assert_eq!(journal.logical_pc, original.logical_pc);
        assert_eq!(journal.original_until, identity.until());
        assert_eq!(journal.source, identity.source_id().identity());
        assert_eq!(journal.window, identity.source_id().index());
        assert_eq!(journal.origin, identity.journal_origin());
        assert_eq!(journal.execution, identity.journal_execution());
        assert_eq!(journal.number, identity.number());
        assert_eq!(journal.arguments, identity.arguments());
        assert_eq!(identity.encoding(), [0x0f, 0x05]);
        let mut previous = original;
        for record in &history[..3] {
            let HistoryRecord::Refreshed {
                origin,
                before,
                after,
            } = record
            else {
                panic!("opening checkpoint missing")
            };
            assert_eq!(*origin, identity.origin());
            assert_eq!(before, previous);
            architecture(
                after,
                original.registers,
                &original.xstate,
                original.signal_mask,
                original,
                StopPhase::UserCheckpoint,
            );
            assert!(after.token.sequence > before.token.sequence);
            previous = after;
        }
        let opened = previous;
        validated(journal, RuntimeKernelJournalStage::Opened, &opened.token);
        let (evidence, exit) = match &history[3] {
            HistoryRecord::Consumed { origin, evidence } => {
                assert_eq!(*origin, identity.origin());
                assert_eq!(&evidence.before, opened);
                let Consumption::RuntimeKernel(records) = &evidence.evidence else {
                    panic!("consumption lacks native kernel evidence")
                };
                assert_eq!(records.len(), 1);
                (&records[0], Some(&evidence.successor))
            }
            HistoryRecord::RuntimeKernelTerminal {
                origin,
                before,
                evidence,
            } => {
                assert_eq!(*origin, identity.origin());
                assert_eq!(before, opened);
                assert_eq!(evidence.len(), 1);
                (&evidence[0], None)
            }
            _ => panic!("kernel consumption kind differs"),
        };
        assert_eq!(&evidence.identity, identity);
        let entry = evidence.entry.as_ref().unwrap();
        let mut registers = original.registers;
        registers.rip = identity.next_pc();
        registers.rcx = registers.rip;
        registers.r11 = original.registers.eflags & !0x10000;
        registers.eflags &= !0x10000;
        registers.orig_rax = identity.number();
        registers.rax = (-i64::from(libc::ENOSYS)) as u64;
        architecture(
            entry,
            registers,
            &original.xstate,
            original.signal_mask,
            original,
            StopPhase::SyscallEntry {
                syscall: identity.number(),
            },
        );
        assert!(entry.token.sequence > opened.token.sequence);
        observed_copy(entry, slot(journal, RuntimeKernelStateSlot::Entry));
        validated(journal, RuntimeKernelJournalStage::Entry, &entry.token);
        let outcome = evidence.outcome.as_ref().unwrap();
        if let Some(id) = current {
            let (recorded, trace) = outcome.returned.as_ref().unwrap();
            assert_eq!(*recorded, id);
            assert!(outcome.terminal.is_none());
            assert_eq!(trace.attempt, identity.attempt());
            assert_eq!(trace.dr6, 0xffff_4ff0);
            assert_eq!(
                (
                    trace.entry_ordinal,
                    trace.exit_ordinal,
                    trace.bridge_ordinal,
                    trace.closed_ordinal
                ),
                (3, 4, 5, 8)
            );
            assert_eq!(trace.released, KernelStopIdentity::from(&opened.token));
            assert_eq!(trace.entry, KernelStopIdentity::from(&entry.token));
            let exit = exit.unwrap();
            registers.rax = original.token.tid as u64;
            architecture(
                exit,
                registers,
                &original.xstate,
                original.signal_mask,
                original,
                StopPhase::ParentSyscallExit {
                    syscall: identity.number(),
                    result: i64::from(original.token.tid),
                    is_error: false,
                },
            );
            assert!(exit.token.sequence > entry.token.sequence);
            assert_eq!(trace.exit, KernelStopIdentity::from(&exit.token));
            observed_copy(exit, slot(journal, RuntimeKernelStateSlot::Exit));
            validated(journal, RuntimeKernelJournalStage::Exit, &exit.token);
            previous = exit;
            for (index, record) in history[4..].iter().enumerate() {
                let HistoryRecord::Refreshed {
                    origin,
                    before,
                    after,
                } = record
                else {
                    panic!("bridge/closing checkpoint missing")
                };
                assert_eq!(*origin, id);
                assert_eq!(before, previous);
                architecture(
                    after,
                    registers,
                    &original.xstate,
                    original.signal_mask,
                    original,
                    StopPhase::UserCheckpoint,
                );
                assert!(after.token.sequence > before.token.sequence);
                if index == 0 {
                    assert_eq!(trace.bridge, KernelStopIdentity::from(&after.token));
                    observed_copy(after, slot(journal, RuntimeKernelStateSlot::RestoredReturn));
                }
                previous = after;
            }
            let row = self
                .state
                .origins
                .iter()
                .filter(|v| v.row.id == id)
                .collect::<Vec<_>>();
            assert_eq!(row.len(), 1);
            let row = row[0];
            assert!(row.active);
            assert_eq!(row.row.kind, OriginKind::CurrentHeldPc);
            assert_eq!(row.row.created_generation, 0);
            assert_eq!(row.row.pc, identity.next_pc());
            assert_eq!(&row.row.initial, exit);
            assert_eq!(&row.current, previous);
            assert_eq!(trace.closed, KernelStopIdentity::from(&previous.token));
            observed_copy(previous, slot(journal, RuntimeKernelStateSlot::Closed));
            validated(journal, RuntimeKernelJournalStage::Closed, &previous.token);
            assert!(
                matches!(journal.facts.last(),Some(RuntimeKernelFact::ReturnCommitted{current,stop})if *current==(id.census,id.serial)&&*stop==trace.closed)
            );
            assert_eq!(
                journal
                    .facts
                    .iter()
                    .filter(|f| matches!(f,RuntimeKernelFact::Returned{stop}if *stop==trace.closed))
                    .count(),
                1
            );
            assert_eq!(
                trace.original_release,
                Request {
                    result: 0,
                    errno: None
                }
            );
            assert_eq!(
                trace.entry_release,
                Request {
                    result: 0,
                    errno: None
                }
            );
        } else {
            assert!(exit.is_none() && outcome.returned.is_none());
            let terminal = outcome.terminal.as_ref().unwrap();
            let trace = terminal.trace;
            let status = crate::lifecycle::ExitStatus::Code(7);
            assert_eq!(identity.arguments()[0], 7);
            for event in [&terminal.exiting, &terminal.terminal] {
                assert_eq!(event.tid, original.token.tid);
                assert_eq!(event.task, Some(original.task));
                assert!(event.stop_token().is_none());
            }
            assert_eq!(
                terminal.exiting.kind,
                DynamicEventKind::TaskExiting { status }
            );
            assert_eq!(
                terminal.terminal.kind,
                DynamicEventKind::TaskTerminal { status }
            );
            assert_eq!(trace.attempt, identity.attempt());
            assert_eq!(trace.released, KernelStopIdentity::from(&opened.token));
            assert_eq!(trace.entry, KernelStopIdentity::from(&entry.token));
            assert_eq!((trace.pre_exit_ordinal, trace.terminal_ordinal), (4, 5));
            assert_eq!(
                (trace.pre_exit_tid, trace.terminal_tid),
                (original.token.tid, original.token.tid)
            );
            assert!(
                trace.exiting_sequence > entry.token.sequence
                    && trace.terminal_sequence > trace.exiting_sequence
            );
            assert_eq!(
                trace.pre_exit_status,
                journal.raw[4].as_ref().unwrap().status
            );
            assert_eq!(trace.event_message, 7 << 8);
            assert_eq!(
                trace.event_message,
                journal.raw[4].as_ref().unwrap().event_message
            );
            assert_eq!(trace.terminal_status, 7 << 8);
            assert_eq!(trace.physical_status, trace.terminal_status);
            assert_eq!(
                trace.terminal_status,
                journal.raw[5].as_ref().unwrap().status
            );
            assert_eq!(
                trace.pin_poll,
                Request {
                    result: 1,
                    errno: None
                }
            );
            assert_eq!(trace.pin_revents, libc::POLLIN | libc::POLLHUP);
            assert_eq!(
                journal.raw[3].as_ref().unwrap().custody.retained_pin,
                Some(trace.pin_fd)
            );
            for request in [
                trace.original_release,
                trace.entry_release,
                trace.pre_exit_release,
                trace.event_message_request,
            ] {
                assert_eq!(
                    request,
                    Request {
                        result: 0,
                        errno: None
                    }
                );
            }
            assert_eq!(self.active().count(), 0);
            assert!(
                !self
                    .state
                    .origins
                    .iter()
                    .find(|v| v.row.id == identity.origin())
                    .unwrap()
                    .active
            );
            assert!(
                matches!(journal.facts.last(),Some(RuntimeKernelFact::TerminalCommitted{sequence,status})if *sequence==trace.terminal_sequence&&*status==trace.terminal_status)
            );
            assert_eq!(journal.facts.iter().filter(|f|matches!(f,RuntimeKernelFact::Terminal{ordinal:5,sequence,status,physical_status,pin_revents}if *sequence==trace.terminal_sequence&&*status==trace.terminal_status&&*physical_status==trace.physical_status&&*pin_revents==trace.pin_revents)).count(),1);
        }
        let old = self
            .state
            .origins
            .iter()
            .filter(|v| v.row.id == identity.origin())
            .collect::<Vec<_>>();
        assert_eq!(old.len(), 1);
        assert!(!old[0].active);
    }
}
