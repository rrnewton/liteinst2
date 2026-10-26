//! Pure exact comparisons, called only after the native owner retained reads.
use super::*;

#[cfg(test)]
mod tests;

pub(super) fn next_stop(before: &AdmissionStop, after: &AdmissionStop) -> Result<(), LaunchError> {
    if before.identity != after.identity
        || before.token.session != after.token.session
        || before.token.tid != after.token.tid
        || before.token.task != after.token.task
        || after.token.sequence <= before.token.sequence
        || after.signal.is_some()
        || after.phase != AdmissionPhase::Restored
    {
        return Err(LaunchError::Invalid(
            "runtime kernel checkpoint lineage differs",
        ));
    }
    Ok(())
}
pub(super) fn syscall_event(tid: i32, expected: i32, status: i32) -> Result<(), LaunchError> {
    if tid != expected
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != (libc::SIGTRAP | 0x80)
        || status >> 16 != 0
    {
        return Err(LaunchError::Invalid(
            "runtime kernel expected native syscall stop differs",
        ));
    }
    Ok(())
}
pub(super) fn entry_registers(
    before: RegisterSnapshot,
    next: u64,
    number: u64,
) -> RegisterSnapshot {
    RegisterSnapshot {
        rip: next,
        rcx: next,
        orig_rax: number,
        rax: (-i64::from(libc::ENOSYS)) as u64,
        r11: before.eflags & !0x10000,
        eflags: before.eflags & !0x10000,
        ..before
    }
}
fn same_architecture(
    actual: &TaskStateSnapshot,
    registers: RegisterSnapshot,
    payload: &TaskStateSnapshot,
) -> bool {
    actual.registers == registers && actual.xstate == payload.xstate && actual.mask == payload.mask
}
fn event_identity(
    identity: &RuntimeKernelIdentity,
    event: &DynamicEvent,
) -> Result<(), LaunchError> {
    let token = event.stop_token().ok_or(LaunchError::Invalid(
        "runtime kernel actual event token absent",
    ))?;
    if event.tid != identity.tid()
        || event.task != Some(identity.task())
        || token.session != identity.session()
        || token.tid != identity.tid()
        || token.task != Some(identity.task().task)
        || token.sequence <= identity.pending().stop.sequence
    {
        return Err(LaunchError::Invalid(
            "runtime kernel actual event identity differs",
        ));
    }
    Ok(())
}
pub(super) fn entry_state(
    identity: &RuntimeKernelIdentity,
    before: &TaskStateSnapshot,
    event: &DynamicEvent,
    actual: &TaskStateSnapshot,
) -> Result<(), LaunchError> {
    event_identity(identity, event)?;
    if event.kind
        != (DynamicEventKind::SyscallEntry {
            number: identity.number(),
            arguments: identity.arguments(),
        })
        || !same_architecture(
            actual,
            entry_registers(before.registers, identity.next_pc(), identity.number()),
            before,
        )
    {
        return Err(LaunchError::Invalid(
            "runtime kernel original ENTRY full state differs",
        ));
    }
    Ok(())
}
pub(super) fn exit_state(
    identity: &RuntimeKernelIdentity,
    before: &TaskStateSnapshot,
    event: &DynamicEvent,
    actual: &TaskStateSnapshot,
) -> Result<(), LaunchError> {
    event_identity(identity, event)?;
    // Positive namespace-object equality and singleton TGID/TID membership are
    // separately authenticated by native. No cross-namespace PID normalization.
    let result = i64::from(identity.tid());
    let expected = RegisterSnapshot {
        rax: result as u64,
        ..entry_registers(before.registers, identity.next_pc(), identity.number())
    };
    if !identity.operation().returns()
        || event.kind
            != (DynamicEventKind::SyscallExit {
                result,
                is_error: false,
            })
        || !same_architecture(actual, expected, before)
    {
        return Err(LaunchError::Invalid(
            "runtime kernel original EXIT full state differs",
        ));
    }
    Ok(())
}
pub(super) fn terminal_status(
    identity: &RuntimeKernelIdentity,
    tid: i32,
    status: i32,
) -> Result<(), LaunchError> {
    if identity.operation().returns()
        || tid != identity.tid()
        || !libc::WIFEXITED(status)
        || status != ((identity.arguments()[0] & 0xff) as i32) << 8
    {
        return Err(LaunchError::Invalid(
            "runtime kernel actual terminal status differs",
        ));
    }
    Ok(())
}
