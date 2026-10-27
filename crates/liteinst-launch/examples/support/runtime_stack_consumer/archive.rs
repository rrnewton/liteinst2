//! Public diagnostic checks. None constructs a release or census capability.
use super::{Result, require};
use liteinst_launch::selected::{SelectedArguments, SelectedInput, SyscallAbi};
use liteinst_launch::{
    DynamicAdmissionState, DynamicTask, KernelStopIdentity, RegisterSnapshot,
    RuntimeKernelAttemptSnapshot as Attempt, RuntimeKernelFact as Fact,
    RuntimeKernelJournalStage as Stage, RuntimeKernelRawRecord as Raw,
    RuntimeKernelReleasePhase as Release, RuntimeKernelReleaseSource as Source,
    RuntimeKernelRequest as Request, RuntimeKernelStateRecord as Record,
    RuntimeKernelStateSlot as Slot,
};

const MAX: usize = 65536;
const SLOTS: [Slot; 8] = [
    Slot::Original,
    Slot::Entry,
    Slot::Exit,
    Slot::BridgeTrap,
    Slot::RestoredReturn,
    Slot::Closed,
    Slot::PreExit,
    Slot::Unexpected,
];
fn zero() -> Option<Request> {
    Some(Request {
        result: 0,
        errno: None,
    })
}

#[derive(Eq, PartialEq)]
struct State {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    mask: u64,
}
fn registers(bytes: &[u8; 216]) -> RegisterSnapshot {
    // SAFETY: the whole initialized ABI-sized byte array is readable; this is
    // a scalar copy, not a ptrace query or authority derived from diagnostics.
    RegisterSnapshot::from(unsafe {
        std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::user_regs_struct>())
    })
}
fn state(record: &Record) -> Result<State> {
    require(
        record.captured
            && record.finalized
            && record.complete
            && record.registers_request == zero()
            && record.xstate_request == zero()
            && record.mask_request == zero()
            && record.requested_length == MAX
            && record.initialized_xstate.len() == MAX
            && record.requested_pointer != 0
            && record.requested_pointer == record.returned_pointer
            && (512..MAX).contains(&record.returned_length),
        "journal_state",
    )?;
    Ok(State {
        registers: registers(&record.registers),
        xstate: record.initialized_xstate[..record.returned_length].to_vec(),
        mask: u64::from_ne_bytes(record.mask),
    })
}
fn slot(attempt: &Attempt, wanted: Slot) -> Result<&Record> {
    let mut values = attempt.states.iter().filter(|s| s.slot == wanted);
    let value = values.next().ok_or("journal_slots")?;
    require(values.next().is_none(), "journal_slots")?;
    Ok(value)
}
fn raw(attempt: &Attempt, ordinal: usize) -> Result<&Raw> {
    attempt
        .raw
        .get(ordinal)
        .and_then(Option::as_ref)
        .ok_or("journal_wait")
}
fn stop(value: KernelStopIdentity, attempt: &Attempt, pid: i32) -> Result<()> {
    require(
        value.session == attempt.id.session
            && value.tid == pid
            && value.task == Some(attempt.task.task),
        "journal_stop_identity",
    )
}
fn validated(attempt: &Attempt, stage: Stage) -> Result<KernelStopIdentity> {
    let mut values = attempt.facts.iter().filter_map(|fact| match fact {
        Fact::Validated {
            stage: actual,
            stop,
        } if *actual == stage => Some(*stop),
        _ => None,
    });
    let value = values.next().ok_or("journal_validated")?;
    require(values.next().is_none(), "journal_validated")?;
    Ok(value)
}
fn info(raw: &Raw, expected: &State, number: u64, args: [u64; 6], entry: bool) -> Result<()> {
    let request = raw.syscall_request.ok_or("journal_syscall_info")?;
    let bytes = &raw.syscall_info;
    let word =
        |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().expect("fixed ABI word"));
    require(
        request.errno.is_none()
            && ((if entry { 80 } else { 33 })..=88).contains(&request.result)
            && bytes[0] == if entry { 1 } else { 2 }
            && u32::from_ne_bytes(bytes[4..8].try_into().expect("fixed ABI architecture"))
                == 0xc000_003e
            && word(8) == expected.registers.rip
            && word(16) == expected.registers.rsp,
        "journal_syscall_info",
    )?;
    if entry {
        require(
            word(24) == number && args.iter().enumerate().all(|(i, v)| word(32 + i * 8) == *v),
            "journal_syscall_info",
        )
    } else {
        require(
            word(24) == expected.registers.rax && bytes[32] == 0,
            "journal_syscall_info",
        )
    }
}
fn release(facts: &mut Vec<Fact>, phase: Release, source: Source) {
    facts.push(Fact::ReleaseAttempt { phase, source });
    facts.push(Fact::ReleaseResult {
        phase,
        request: Request {
            result: 0,
            errno: None,
        },
    });
}

pub(super) fn check(
    attempt: &Attempt,
    input: &SelectedInput,
    xstate: &[u8],
    mask: u64,
    returned: Option<&DynamicAdmissionState>,
    task: &DynamicTask,
    pid: i32,
) -> Result<()> {
    let SelectedArguments::Syscall {
        abi: SyscallAbi::LinuxX64,
        number,
        arguments,
    } = input.arguments()
    else {
        return Err("journal_input");
    };
    require(
        attempt.task == *task
            && task.generation == 0
            && attempt.input_registers == *input.registers()
            && attempt.logical_pc == input.instruction().logical_pc()
            && attempt.instruction == [0x0f, 0x05]
            && attempt.number == number
            && attempt.arguments == arguments
            && attempt.failure.is_none()
            && attempt.id.session != 0
            && attempt.id.invocation != 0
            && attempt.retained_bytes > 0
            && attempt.execution.0 == attempt.id.session
            && attempt.execution.1 > 0
            && attempt.origin.0 == attempt.id.session
            && attempt.origin.1 > 0
            && attempt.source.generation == task.generation
            && attempt.source.mapping != 0,
        "journal_input",
    )?;
    stop(attempt.original_stop, attempt, pid)?;
    let before = State {
        registers: *input.registers(),
        xstate: xstate.to_vec(),
        mask,
    };
    let original = slot(attempt, Slot::Original)?;
    require(
        original.stop == Some(attempt.original_stop)
            && original.raw_ordinal.is_none()
            && state(original)? == before,
        "journal_original",
    )?;
    for (index, record) in attempt.states.iter().enumerate() {
        require(
            record.slot == SLOTS[index] && record.initialized_xstate.len() == MAX,
            "journal_slots",
        )?;
        let used = if returned.is_some() {
            index < 6
        } else {
            matches!(record.slot, Slot::Original | Slot::Entry | Slot::PreExit)
        };
        require(record.captured == used, "journal_slots")?;
        if used {
            let _ = state(record)?;
        } else {
            require(
                !record.complete
                    && !record.finalized
                    && record.registers_request.is_none()
                    && record.xstate_request.is_none()
                    && record.mask_request.is_none(),
                "journal_unused_state",
            )?;
        }
    }
    let count = if returned.is_some() { 9 } else { 6 };
    for (ordinal, record) in attempt.raw.iter().enumerate() {
        if ordinal >= count {
            require(record.is_none(), "journal_extra_wait")?;
            continue;
        }
        let record = record.as_ref().ok_or("journal_wait")?;
        require(
            record.ordinal == ordinal
                && record.tid == pid
                && record.finalized
                && record.failure.is_none()
                && record.custody.session == attempt.id.session
                && record.custody.expected_tid == pid
                && record.custody.retained_pin.is_some()
                && !record.custody.lost_wait
                && !record.custody.missing_pin,
            "journal_wait",
        )?;
        let terminal = returned.is_none() && ordinal == 5;
        if terminal {
            require(
                libc::WIFEXITED(record.status)
                    && libc::WEXITSTATUS(record.status) == 7
                    && record.custody.tracer_terminal == Some(record.status)
                    && !record.queries_started
                    && record.registers_request.is_none()
                    && record.xstate_request.is_none()
                    && record.mask_request.is_none()
                    && record.syscall_request.is_none()
                    && record.event_request.is_none()
                    && record.signal_request.is_none()
                    && record.state_slot.is_none()
                    && record.maps.is_none(),
                "journal_terminal_wait",
            )?;
            continue;
        }
        let syscall = ordinal == 3 || (returned.is_some() && ordinal == 4);
        require(
            libc::WIFSTOPPED(record.status)
                && record.queries_started
                && libc::WSTOPSIG(record.status)
                    == if syscall {
                        libc::SIGTRAP | 0x80
                    } else {
                        libc::SIGTRAP
                    }
                && record.status >> 16
                    == if returned.is_none() && ordinal == 4 {
                        libc::PTRACE_EVENT_EXIT
                    } else {
                        0
                    }
                && record.custody.owned
                && record.custody.stopped_status == Some(record.status)
                && record.registers_request == zero()
                && record.xstate_request == zero()
                && record.mask_request == zero()
                && record.requested_length == MAX
                && record.requested_pointer != 0
                && record.requested_pointer == record.returned_pointer
                && (512..MAX).contains(&record.returned_length)
                && record.syscall_request.is_some()
                && record.event_request.is_some()
                && record.signal_request.is_some(),
            "journal_held_wait",
        )?;
        let maps = record.maps.ok_or("journal_maps_summary")?;
        require(
            maps.complete
                && (1..MAX).contains(&maps.observed_bytes)
                && maps.filesystem == Some(0x9fa0)
                && maps.filesystem_request == zero()
                && maps
                    .directory_open
                    .is_some_and(|r| r.result >= 0 && r.errno.is_none())
                && maps
                    .maps_open
                    .is_some_and(|r| r.result >= 0 && r.errno.is_none())
                && maps.last_read == zero()
                && maps.read_calls > 0,
            "journal_maps_summary",
        )?;
        if let Some(purpose) = record.state_slot {
            let copied = slot(attempt, purpose)?;
            require(
                copied.raw_ordinal == Some(ordinal)
                    && copied.registers == record.registers
                    && copied.mask == record.mask
                    && copied.requested_pointer == record.requested_pointer
                    && copied.returned_pointer == record.returned_pointer
                    && copied.returned_length == record.returned_length,
                "journal_copy_binding",
            )?;
        }
    }
    let mut entry = State {
        registers: before.registers,
        xstate: before.xstate.clone(),
        mask,
    };
    entry.registers.rip = input.instruction().next_pc();
    entry.registers.rcx = entry.registers.rip;
    entry.registers.r11 = before.registers.eflags & !0x10000;
    entry.registers.eflags &= !0x10000;
    entry.registers.orig_rax = number;
    entry.registers.rax = (-libc::ENOSYS as i64) as u64;
    require(
        state(slot(attempt, Slot::Entry)?)? == entry,
        "journal_entry_state",
    )?;
    info(raw(attempt, 3)?, &entry, number, arguments, true)?;
    let opened = validated(attempt, Stage::Opened)?;
    let entered = validated(attempt, Stage::Entry)?;
    stop(opened, attempt, pid)?;
    stop(entered, attempt, pid)?;
    require(
        attempt.original_stop.sequence < opened.sequence && opened.sequence < entered.sequence,
        "journal_sequence",
    )?;
    // Raw ENTRY/EXIT copies precede semantic dispatch and have no stop token.
    // Their real ordinals/full state bind the later Validated event facts.
    require(
        slot(attempt, Slot::Entry)?.stop.is_none()
            && slot(attempt, Slot::Entry)?.raw_ordinal == Some(3),
        "journal_entry_stop",
    )?;
    let mut facts = vec![Fact::State {
        slot: Slot::Original,
    }];
    facts.extend((0..3).map(|ordinal| Fact::Wait { ordinal }));
    facts.push(Fact::Validated {
        stage: Stage::Opened,
        stop: opened,
    });
    release(&mut facts, Release::Original, Source::Stop(opened));
    facts.push(Fact::Wait { ordinal: 3 });
    facts.push(Fact::State { slot: Slot::Entry });
    facts.push(Fact::Validated {
        stage: Stage::Entry,
        stop: entered,
    });
    release(&mut facts, Release::Entry, Source::Stop(entered));
    if let Some(after) = returned {
        let expected = State {
            registers: after.registers,
            xstate: after.xstate.clone(),
            mask: after.signal_mask,
        };
        for purpose in [Slot::Exit, Slot::RestoredReturn, Slot::Closed] {
            require(
                state(slot(attempt, purpose)?)? == expected,
                "journal_return_state",
            )?;
        }
        info(raw(attempt, 4)?, &expected, number, arguments, false)?;
        let exited = validated(attempt, Stage::Exit)?;
        let closed = validated(attempt, Stage::Closed)?;
        let bridge = slot(attempt, Slot::RestoredReturn)?
            .stop
            .ok_or("journal_bridge_stop")?;
        for checkpoint in [exited, bridge, closed] {
            stop(checkpoint, attempt, pid)?;
        }
        require(
            entered.sequence < exited.sequence
                && exited.sequence < bridge.sequence
                && bridge.sequence < closed.sequence
                && slot(attempt, Slot::Exit)?.stop.is_none()
                && slot(attempt, Slot::Exit)?.raw_ordinal == Some(4)
                && slot(attempt, Slot::Closed)?.stop == Some(closed),
            "journal_sequence",
        )?;
        let Fact::ReturnCommitted {
            current,
            stop: committed,
        } = attempt.facts.last().copied().ok_or("journal_commit")?
        else {
            return Err("journal_commit");
        };
        require(
            committed == closed && current.0 == attempt.origin.0 && current.1 > attempt.origin.1,
            "journal_commit",
        )?;
        facts.extend([
            Fact::Wait { ordinal: 4 },
            Fact::State { slot: Slot::Exit },
            Fact::Validated {
                stage: Stage::Exit,
                stop: exited,
            },
            Fact::Wait { ordinal: 5 },
            Fact::State {
                slot: Slot::BridgeTrap,
            },
            Fact::State {
                slot: Slot::RestoredReturn,
            },
        ]);
        facts.extend((6..9).map(|ordinal| Fact::Wait { ordinal }));
        facts.extend([
            Fact::State { slot: Slot::Closed },
            Fact::Validated {
                stage: Stage::Closed,
                stop: closed,
            },
            Fact::Returned { stop: closed },
            Fact::ReturnCommitted {
                current,
                stop: closed,
            },
        ]);
    } else {
        require(number == 231 && arguments[0] == 7, "journal_terminal_input")?;
        let pre = raw(attempt, 4)?;
        let terminal = raw(attempt, 5)?;
        require(
            pre.event_request == zero() && pre.event_message == 7 << 8,
            "journal_pre_exit",
        )?;
        let Fact::TerminalCommitted { sequence, status } =
            attempt.facts.last().copied().ok_or("journal_commit")?
        else {
            return Err("journal_commit");
        };
        require(
            sequence > entered.sequence && status == terminal.status,
            "journal_terminal_commit",
        )?;
        facts.extend([
            Fact::Wait { ordinal: 4 },
            Fact::State {
                slot: Slot::PreExit,
            },
            Fact::PreExit {
                ordinal: 4,
                message: 7 << 8,
            },
        ]);
        release(
            &mut facts,
            Release::PreExit,
            Source::PreExit {
                ordinal: 4,
                tid: pid,
                status: pre.status,
            },
        );
        facts.extend([
            Fact::Wait { ordinal: 5 },
            Fact::Terminal {
                ordinal: 5,
                sequence,
                status,
                physical_status: status,
                pin_revents: libc::POLLIN | libc::POLLHUP,
            },
            Fact::TerminalCommitted { sequence, status },
        ]);
    }
    require(attempt.facts == facts, "journal_fact_chain")
}

pub(super) fn chain(attempts: &[Attempt]) -> Result<()> {
    require(attempts.len() == 3, "journal_chain")?;
    for pair in attempts.windows(2) {
        let a = &pair[0];
        let b = &pair[1];
        let Fact::ReturnCommitted { stop, .. } = a.facts.last().copied().ok_or("journal_chain")?
        else {
            return Err("journal_chain");
        };
        require(
            a.task == b.task
                && a.id.session == b.id.session
                && a.id.invocation < b.id.invocation
                && a.execution.0 == b.execution.0
                && a.execution.1 < b.execution.1
                && a.origin.0 == b.origin.0
                && a.origin.1 < b.origin.1
                && b.original_stop.session == stop.session
                && b.original_stop.tid == stop.tid
                && b.original_stop.task == stop.task
                && b.original_stop.sequence > stop.sequence,
            "journal_chain",
        )?;
    }
    Ok(())
}
