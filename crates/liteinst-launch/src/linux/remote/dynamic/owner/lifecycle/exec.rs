//! One native leader exec, with logical identity replacement at its real event.
//! Physical process ownership remains exclusively in Owner and its broker.
use super::*;
use crate::lifecycle::ExecTicket;

#[cfg(test)]
mod tests;

pub(super) struct ExecPending {
    pub(super) task: TaskId,
    ticket: ExecTicket,
    mask: u64,
    event_registers: Option<RegisterSnapshot>,
}

impl NativeLifecycle {
    pub(super) fn prepare_native_exec(&mut self, tid: libc::pid_t) -> Result<(), LaunchError> {
        if self.exec_successes != 0 {
            return Err(LaunchError::Invalid("native exec success budget exhausted"));
        }
        if self.pending.is_some()
            || self.exec_pending.is_some()
            || self.tasks.values().any(|task| task.fork_return.is_some())
        {
            return Err(LaunchError::Invalid(
                "native lifecycle transaction is already pending",
            ));
        }
        same_pid_namespace(tid)?;
        single_task(tid)?;
        native_leader(tid)?;
        let registers = read_registers(tid)?;
        let info = syscall_info(tid)?;
        if info.op != libc::PTRACE_SYSCALL_INFO_ENTRY
            || info.arch != AUDIT_ARCH_X86_64
            || registers.cs != 0x33
            || registers.orig_rax != libc::SYS_execve as u64
            || registers.rax != (-i64::from(libc::ENOSYS)) as u64
            || registers.eflags & 0x100 != 0
            || info.instruction_pointer != registers.rip
            || info.stack_pointer != registers.rsp
        {
            return Err(LaunchError::Invalid(
                "native exec entry did not authenticate",
            ));
        }
        // SAFETY: ENTRY authenticates the initialized union member.
        let entry = unsafe { info.u.entry };
        if entry.nr != libc::SYS_execve as u64 || entry.args != arguments(&registers) {
            return Err(LaunchError::Invalid("native exec arguments differ"));
        }
        let task = self.tasks[&tid].identity.task;
        let mask = launch::task_mask(tid)?;
        let ticket = recorded(self.registry.prepare_exec(task))?;
        self.exec_pending = Some(ExecPending {
            task,
            ticket,
            mask,
            event_registers: None,
        });
        Ok(())
    }

    pub(super) fn observe_native_exec(
        &mut self,
        owner: &Owner,
        tid: libc::pid_t,
    ) -> Result<DynamicEvent, LaunchError> {
        let previous = self.tasks[&tid].identity;
        let pending = self.exec_pending.as_ref().ok_or(LaunchError::Invalid(
            "native EXEC event lacks an owned intent",
        ))?;
        if self.exec_policy != DynamicExecPolicy::ExecveOnce
            || pending.task != previous.task
            || pending.event_registers.is_some()
            || self.exec_successes != 0
            || !owner.owned.contains(&tid)
            || !owner.stopped.contains_key(&tid)
            || owner.reaped.contains(&tid)
            || owner.tracer_terminal.contains_key(&tid)
            || owner.handles.get(&tid).is_none_or(broker::hup)
            || !matches!(self.tasks[&tid].state, State::Running)
            || !self.tasks[&tid].syscall_open
        {
            return Err(LaunchError::Invalid(
                "native EXEC ownership did not authenticate",
            ));
        }
        same_pid_namespace(tid)?;
        single_task(tid)?;
        native_leader(tid)?;
        let mut former = 0_u64;
        ptrace(libc::PTRACE_GETEVENTMSG, tid, 0, (&raw mut former) as usize)?;
        if former != tid as u64 {
            return Err(LaunchError::Invalid(
                "native nonleader exec is not qualified",
            ));
        }
        let registers = read_registers(tid)?;
        if registers.cs != 0x33
            || registers.orig_rax != libc::SYS_execve as u64
            || registers.rax != (-i64::from(libc::ENOSYS)) as u64
            || registers.eflags != 0x202
            || launch::task_mask(tid)? != pending.mask
        {
            return Err(LaunchError::Invalid(
                "native EXEC register or mask evidence differs",
            ));
        }
        let evidence = launch::replaced_entry_evidence(tid, &registers)?;
        // This changes registry identity only. No physical terminal, pidfd
        // acquisition, broker Ready, signal mask write or source mutation occurs.
        let transition = recorded(self.registry.observe_exec_event(
            pending.ticket,
            self.sequence(tid)?,
            tid,
            tid,
            registers.rip,
        ))?;
        if transition.superseded != [previous.task] {
            return Err(LaunchError::Invalid(
                "native EXEC replaced unexpected tasks",
            ));
        }
        let record = recorded(self.registry.task(transition.task))?;
        let identity = DynamicTask {
            task: record.id,
            process: record.process,
            address_space: record.address_space,
            generation: recorded(self.registry.address_space(record.address_space))?.generation,
        };
        if identity.process != previous.process {
            return Err(LaunchError::Invalid("native EXEC changed process identity"));
        }
        let task = self.tasks.get_mut(&tid).unwrap();
        // Preserve the residual control-stop credit for this same kernel task.
        // observe() already consumed one credit for the actual EXEC stop.
        task.identity = identity;
        task.syscall_open = true;
        task.fork_return = None;
        let pending = self.exec_pending.as_mut().unwrap();
        pending.task = identity.task;
        pending.event_registers = Some(registers);
        self.exec_successes += 1;
        self.held(tid, DynamicEventKind::ExecReplaced { previous, evidence })
    }

    pub(super) fn complete_native_exec(
        &mut self,
        tid: libc::pid_t,
        sequence: u64,
        registers: &RegisterSnapshot,
        result: i64,
        is_error: bool,
    ) -> Result<(), LaunchError> {
        let pending = self.exec_pending.as_ref().unwrap();
        // exec can fail after replacing its mm but before emitting EXEC. Errno
        // alone is not an old-mm continuity witness; do not invoke the pure
        // observe_exec_failure transition and do not release original code.
        let Some(mut expected) = pending.event_registers else {
            return Err(LaunchError::Invalid(
                "native exec failure has no proved old-mm continuity",
            ));
        };
        expected.rax = 0;
        if result != 0
            || is_error
            || *registers != expected
            || launch::task_mask(tid)? != pending.mask
        {
            return Err(LaunchError::Invalid("native exec return changed state"));
        }
        recorded(self.registry.observe_stop(
            pending.task,
            sequence,
            registers.rip,
            HoldReason::SyscallExit,
        ))?;
        self.exec_pending = None;
        Ok(())
    }
}

fn native_leader(tid: libc::pid_t) -> Result<(), LaunchError> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status"))
        .map_err(|error| io_error("read native exec thread group", error))?;
    let tgid = status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:\t"))
        .and_then(|value| value.parse::<i32>().ok());
    if tgid != Some(tid) {
        return Err(LaunchError::Invalid(
            "native nonleader exec is not qualified",
        ));
    }
    Ok(())
}
