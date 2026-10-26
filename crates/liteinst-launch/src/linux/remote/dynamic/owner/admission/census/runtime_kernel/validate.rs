use super::*;
use crate::lifecycle::ExitStatus;

const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
const TF_RF: u64 = (1 << 8) | (1 << 16);

fn valid_state(state: &TaskStateSnapshot) -> bool {
    state.registers.cs == 0x33
        && state.registers.rip != 0
        && (512..MAX_XSTATE_BYTES).contains(&state.xstate.len())
}
fn same_state(before: &ObservedStop, state: &TaskStateSnapshot) -> bool {
    before.registers == state.registers
        && before.xstate == state.xstate
        && before.signal_mask == state.mask
}
pub(super) fn arguments(registers: &RegisterSnapshot) -> [u64; 6] {
    [
        registers.rdi,
        registers.rsi,
        registers.rdx,
        registers.r10,
        registers.r8,
        registers.r9,
    ]
}
fn request_ok(request: Request) -> bool {
    request.result == 0 && request.errno.is_none()
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
pub(super) fn syscall_flags(before: &RegisterSnapshot, next: u64, number: u64) -> RegisterSnapshot {
    RegisterSnapshot {
        rip: next,
        rcx: next,
        orig_rax: number,
        rax: (-i64::from(libc::ENOSYS)) as u64,
        r11: before.eflags & !(1 << 16),
        eflags: before.eflags & !(1 << 16),
        ..*before
    }
}
pub(super) fn binding(
    census: &ResumeCensus,
    identity: &RuntimeKernelIdentity,
    before: &ObservedStop,
) -> Result<(), CensusError> {
    before.validate(census.session, census.space)?;
    census.runtime_register_provenance(identity.origin())?;
    let pending = identity.pending();
    let source = identity.source_id();
    if identity.session() != census.session
        || identity.tid() != before.token.tid
        || identity.task() != before.task
        || identity.origin().census != census.identity
        || identity.execution().session != census.session
        || identity.execution().serial == 0
        || identity.attempt()
            != (KernelAttemptId {
                session: census.session,
                invocation: identity.execution().serial,
            })
        || pending.stop != before.token
        || pending.task != before.task
        || pending.pc != before.logical_pc
        || pending.invocation != identity.execution().serial
        || pending.mapping.0 != source.identity().mapping
        || pending.window != source.index()
        || pending.generation.0 != census.state.generation
        || source.identity().mapping == 0
        || source.identity().generation != census.state.generation
        || identity.pc() != before.logical_pc
        || identity.number() != before.registers.rax
        || identity.arguments() != arguments(&before.registers)
    {
        return Err(CensusError::IdentityMismatch);
    }
    if before.phase != StopPhase::UserCheckpoint
        || before.signal.is_some()
        || before.task.generation != census.state.generation
        || census.state.generation != 0
        || before.registers.eflags & TF_RF != 0
        || Instant::now() >= identity.until()
        || !(512..MAX_XSTATE_BYTES).contains(&before.xstate.len())
    {
        return Err(CensusError::StaleObservation);
    }
    let number = match identity.operation() {
        RuntimeKernelOperation::Getpid => libc::SYS_getpid,
        RuntimeKernelOperation::Gettid => libc::SYS_gettid,
        RuntimeKernelOperation::Exit => libc::SYS_exit,
        RuntimeKernelOperation::ExitGroup => libc::SYS_exit_group,
    } as u64;
    if identity.encoding() != [0x0f, 0x05]
        || identity.pc().checked_add(2) != Some(identity.next_pc())
        || identity.next_pc() >= (1u64 << 47)
        || identity.number() != number
        || identity.operation().number() != number
    {
        return Err(CensusError::InvalidConsumption);
    }
    if census.active().count() != 1 {
        return Err(CensusError::PersistentUnknown);
    }
    Ok(())
}
pub(super) fn capacity(
    census: &ResumeCensus,
    operation: RuntimeKernelOperation,
) -> Result<(), CensusError> {
    if (operation.returns() && census.state.origins.len() == census.state.origins.capacity())
        || census
            .state
            .history
            .capacity()
            .saturating_sub(census.state.history.len())
            < witnesses(operation)
    {
        return Err(CensusError::Capacity);
    }
    Ok(())
}
fn settled(before: &ObservedStop, value: NativeCheckpoint<'_>) -> bool {
    value.stop.identity == before.task
        && value.stop.token.session == before.token.session
        && value.stop.token.tid == before.token.tid
        && value.stop.token.task == before.token.task
        && value.stop.signal.is_none()
        && valid_state(value.state)
}
fn register_bytes(registers: &RegisterSnapshot, raw: &[u8; 216]) -> bool {
    let r = registers;
    [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ]
    .iter()
    .enumerate()
    .all(|(index, value)| word(raw, index * 8) == *value)
}
fn complete_raw_state(
    raw: super::super::super::runtime_kernel_native::RuntimeRawWaitView<'_>,
    actual: &TaskStateSnapshot,
) -> bool {
    let Some(state) = raw.state else {
        return false;
    };
    raw.queries_started
        && raw.failure.is_none()
        && state.complete
        && state.state == Some(actual)
        && state.registers_request.is_some_and(request_ok)
        && register_bytes(&actual.registers, state.registers)
        && state.xstate_request.is_some_and(request_ok)
        && state.mask_request.is_some_and(request_ok)
        && state.requested_pointer != 0
        && state.returned_pointer == state.requested_pointer
        && state.requested_length == MAX_XSTATE_BYTES
        && state.returned_length == actual.xstate.len()
        && state.returned_length < MAX_XSTATE_BYTES
        && state.xstate_initialized.len() == MAX_XSTATE_BYTES
        && state.xstate_initialized[..state.returned_length] == actual.xstate
        && u64::from_ne_bytes(*state.mask) == actual.mask
}
fn raw_state(value: NativeSyscallCheckpoint<'_>, ordinal: usize) -> bool {
    let raw = value.raw;
    let Some(token) = value.event.stop_token() else {
        return false;
    };
    raw.ordinal == ordinal
        && raw.tid == value.event.tid
        && raw.tid == token.tid
        && libc::WIFSTOPPED(raw.status)
        && libc::WSTOPSIG(raw.status) == (libc::SIGTRAP | 0x80)
        && raw.status >> 16 == 0
        && complete_raw_state(raw, value.state)
}
fn event_identity(before: &ObservedStop, event: &DynamicEvent) -> bool {
    event.tid == before.token.tid
        && event.task == Some(before.task)
        && event.stop_token().is_some_and(|token| {
            token.session == before.token.session
                && token.tid == before.token.tid
                && token.task == before.token.task
        })
}
fn syscall_info(
    value: NativeSyscallCheckpoint<'_>,
    identity: &RuntimeKernelIdentity,
    entry: bool,
) -> bool {
    let bytes = value.raw.fixed.syscall_info;
    let Some(request) = value.raw.fixed.syscall_info_request else {
        return false;
    };
    let length = if entry { 80 } else { 33 };
    if request.errno.is_some()
        || request.result < length
        || request.result > 88
        || bytes[0] != if entry { 1 } else { 2 }
        || u32::from_ne_bytes(bytes[4..8].try_into().unwrap()) != AUDIT_ARCH_X86_64
        || word(bytes, 8) != identity.next_pc()
        || word(bytes, 16) != value.state.registers.rsp
    {
        return false;
    }
    if entry {
        word(bytes, 24) == identity.number()
            && (0..6).all(|index| word(bytes, 32 + index * 8) == identity.arguments()[index])
    } else {
        word(bytes, 24) == value.state.registers.rax && bytes[32] == 0
    }
}
fn entry(before: &ObservedStop, model: &Model<'_>, sequence: u64) -> Result<u64, CensusError> {
    let value = model.entry;
    if !event_identity(before, value.event)
        || !valid_state(value.state)
        || !raw_state(value, 3)
        || !syscall_info(value, model.identity, true)
        || value.event.kind
            != (DynamicEventKind::SyscallEntry {
                number: model.identity.number(),
                arguments: model.identity.arguments(),
            })
        || value.state.registers
            != syscall_flags(
                &before.registers,
                model.identity.next_pc(),
                model.identity.number(),
            )
        || value.state.xstate != before.xstate
        || value.state.mask != before.signal_mask
    {
        return Err(CensusError::InvalidConsumption);
    }
    let token = value.event.stop_token().unwrap();
    if token.sequence <= sequence {
        return Err(CensusError::InvalidConsumption);
    }
    Ok(token.sequence)
}
fn return_outcome(
    before: &ObservedStop,
    model: &Model<'_>,
    sequence: u64,
) -> Result<(), CensusError> {
    let Some(ReturnModel {
        exit,
        bridge,
        closing,
        trace,
    }) = &model.outcome.returned
    else {
        return Err(CensusError::InvalidConsumption);
    };
    if model.outcome.terminal.is_some()
        || !model.identity.operation().returns()
        || !event_identity(before, exit.event)
        || !valid_state(exit.state)
        || !raw_state(*exit, 4)
        || !syscall_info(*exit, model.identity, false)
        || exit.event.kind
            != (DynamicEventKind::SyscallExit {
                result: i64::from(before.token.tid),
                is_error: false,
            })
        || exit.state.registers
            != (RegisterSnapshot {
                rax: before.token.tid as u64,
                ..model.entry.state.registers
            })
        || exit.state.xstate != before.xstate
        || exit.state.mask != before.signal_mask
    {
        return Err(CensusError::InvalidConsumption);
    }
    let exit_token = exit.event.stop_token().unwrap();
    if exit_token.sequence <= sequence {
        return Err(CensusError::InvalidConsumption);
    }
    let mut sequence = exit_token.sequence;
    for stop in std::iter::once(*bridge).chain(closing.iter().copied()) {
        if !settled(before, stop)
            || stop.stop.phase != AdmissionPhase::Restored
            || stop.stop.token.sequence <= sequence
            || stop.state != exit.state
        {
            return Err(CensusError::InvalidConsumption);
        }
        sequence = stop.stop.token.sequence;
    }
    if trace.attempt != model.identity.attempt()
        || trace.entry_ordinal != 3
        || trace.exit_ordinal != 4
        || trace.bridge_ordinal != 5
        || trace.closed_ordinal != 8
        || trace.released != KernelStopIdentity::from(&model.opening[2].stop.token)
        || trace.entry != KernelStopIdentity::from(model.entry.event.stop_token().unwrap())
        || trace.exit != KernelStopIdentity::from(exit_token)
        || trace.bridge != KernelStopIdentity::from(&bridge.stop.token)
        || trace.closed != KernelStopIdentity::from(&closing[2].stop.token)
        || !request_ok(trace.original_release)
        || !request_ok(trace.entry_release)
        || trace.namespace.inode == 0
    {
        return Err(CensusError::InvalidConsumption);
    }
    // Namespace object equality and unchanged DR6 are native seal predicates.
    // Their exact projection is retained; arbitrary scalar traces cannot reach
    // the production entry point and do not replace that native authority.
    Ok(())
}
fn terminal_outcome(
    before: &ObservedStop,
    model: &Model<'_>,
    sequence: u64,
) -> Result<(), CensusError> {
    let Some(TerminalModel {
        pre_exit,
        exiting,
        terminal,
        trace,
    }) = &model.outcome.terminal
    else {
        return Err(CensusError::InvalidConsumption);
    };
    let code = (model.identity.arguments()[0] & 0xff) as u8;
    let status = i32::from(code) << 8;
    if model.outcome.returned.is_some()
        || model.identity.operation().returns()
        || !valid_state(pre_exit.state)
        || pre_exit.raw.ordinal != 4
        || pre_exit.raw.tid != before.token.tid
        || !libc::WIFSTOPPED(pre_exit.raw.status)
        || libc::WSTOPSIG(pre_exit.raw.status) != libc::SIGTRAP
        || pre_exit.raw.status >> 16 != libc::PTRACE_EVENT_EXIT
        || !complete_raw_state(pre_exit.raw, pre_exit.state)
        || pre_exit.event_message != status as u64
        || !request_ok(pre_exit.event_message_request)
        || pre_exit.raw.fixed.event_message != pre_exit.event_message
        || pre_exit.raw.fixed.event_message_request != Some(pre_exit.event_message_request)
        || exiting.tid != before.token.tid
        || exiting.task != Some(before.task)
        || exiting.stop_token().is_some()
        || exiting.kind
            != (DynamicEventKind::TaskExiting {
                status: ExitStatus::Code(code),
            })
        || terminal.tid != before.token.tid
        || terminal.task != Some(before.task)
        || terminal.stop_token().is_some()
        || terminal.kind
            != (DynamicEventKind::TaskTerminal {
                status: ExitStatus::Code(code),
            })
        || trace.attempt != model.identity.attempt()
        || trace.released != KernelStopIdentity::from(&model.opening[2].stop.token)
        || trace.entry != KernelStopIdentity::from(model.entry.event.stop_token().unwrap())
        || trace.pre_exit_ordinal != 4
        || trace.pre_exit_tid != before.token.tid
        || trace.pre_exit_status != pre_exit.raw.status
        || trace.event_message != pre_exit.event_message
        || trace.event_message_request != pre_exit.event_message_request
        || !request_ok(trace.original_release)
        || !request_ok(trace.entry_release)
        || !request_ok(trace.pre_exit_release)
        || trace.exiting_sequence <= sequence
        || trace.terminal_sequence <= trace.exiting_sequence
        || trace.terminal_ordinal != 5
        || trace.terminal_tid != before.token.tid
        || trace.terminal_status != status
        || !libc::WIFEXITED(trace.terminal_status)
        || libc::WEXITSTATUS(trace.terminal_status) != i32::from(code)
        || trace.physical_status != trace.terminal_status
        || trace.pin_fd < 0
        || trace.pin_poll.result != 1
        || trace.pin_poll.errno.is_some()
        || trace.pin_revents != (libc::POLLIN | libc::POLLHUP)
        || trace.namespace.inode == 0
    {
        return Err(CensusError::InvalidConsumption);
    }
    // Pre-exit is not a syscall EXIT or a user successor. Its complete actual
    // state is retained by native, while this record preserves its typed trace.
    Ok(())
}

pub(super) fn model(
    census: &ResumeCensus,
    reservation: Reservation,
    actual: &Model<'_>,
    prepared: &PreparedRuntimeKernelCensus,
) -> Result<(usize, u64, BudgetCharge, BudgetCharge), CensusError> {
    let expected = &prepared.binding;
    if prepared.receipt.is_some()
        || expected.census != census.identity
        || expected.reservation != reservation
        || &expected.identity != actual.identity
    {
        return Err(CensusError::IdentityMismatch);
    }
    let index = census.active_index(expected.identity.origin())?;
    let before = census.current_observation(expected.identity.origin())?;
    if before != &prepared.before {
        return Err(CensusError::StaleObservation);
    }
    binding(census, actual.identity, before)?;
    if !settled(before, actual.logical)
        || actual.logical.stop.token != before.token
        || !matches!(
            actual.logical.stop.phase,
            AdmissionPhase::EntryReady | AdmissionPhase::Restored
        )
        || !same_state(before, actual.logical.state)
    {
        return Err(CensusError::InvalidConsumption);
    }
    let mut sequence = before.token.sequence;
    for stop in actual.opening {
        if !settled(before, stop)
            || stop.stop.phase != AdmissionPhase::Restored
            || stop.stop.token.sequence <= sequence
            || !same_state(before, stop.state)
        {
            return Err(CensusError::InvalidConsumption);
        }
        sequence = stop.stop.token.sequence;
    }
    let sequence = entry(before, actual, sequence)?;
    if actual.identity.operation().returns() {
        return_outcome(before, actual, sequence)?;
    } else {
        terminal_outcome(before, actual, sequence)?;
    }
    let operation = actual.identity.operation();
    capacity(census, operation)?;
    if prepared.before.xstate.capacity() != MAX_XSTATE_BYTES
        || prepared.buffers.iter().enumerate().any(|(index, value)| {
            !value.is_empty()
                || value.capacity()
                    != if index < states(operation) - 1 {
                        MAX_XSTATE_BYTES
                    } else {
                        0
                    }
        })
        || prepared.evidence.as_ref().is_none_or(|value| {
            value.len() != 1
                || value[0].identity != expected.identity
                || value[0].entry.is_some()
                || value[0].outcome.is_some()
        })
        || prepared.preparation_debit != preparation_bytes(states(operation) * MAX_XSTATE_BYTES)?
    {
        return Err(CensusError::Capacity);
    }
    if census.state.next_serial != expected.candidate_serial {
        return Err(CensusError::StaleObservation);
    }
    let next = if operation.returns() {
        census
            .state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?
    } else {
        census.state.next_serial
    };
    let (remaining, used) = census.prepare_debit(reservation, prepared.remaining_charge()?)?;
    Ok((index, next, remaining, used))
}
