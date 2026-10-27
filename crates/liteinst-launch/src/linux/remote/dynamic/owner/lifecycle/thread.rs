//! One native thread clone. These observations grant execution ownership only;
//! they are not exclusion or page-publication capabilities.
use super::*;

#[cfg(test)]
mod tests;

/// CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD.
const THREAD_FLAGS: u64 = 0x10f00;
mod cet;

/// Accepts either an exact disabled-state report or a separately authenticated
/// native Linux ABI absence certificate. Neither grants publication authority.
pub(super) fn shadow_stack_disabled(tid: libc::pid_t) -> Result<(), LaunchError> {
    cet::disabled(tid).map(|_| ())
}

fn thread_pin_supported(tid: libc::pid_t) -> Result<(), LaunchError> {
    // SAFETY: the owned stopped leader cannot retire/reuse its numeric identity.
    // PIDFD_THREAD is requested explicitly even for this leader, so unsupported
    // kernels refuse before creation. The temporary fd does not replace its
    // process pin or establish ownership of any other task.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, libc::O_EXCL) };
    if descriptor < 0 {
        return Err(system("pidfd_open native thread capability"));
    }
    // SAFETY: this syscall returned one newly owned descriptor.
    drop(unsafe { OwnedFd::from_raw_fd(descriptor as i32) });
    Ok(())
}

impl NativeLifecycle {
    pub(super) fn prepare_native_thread(
        &mut self,
        owner: &Owner,
        tid: libc::pid_t,
    ) -> Result<(), LaunchError> {
        if self.tasks.len() >= self.options.max_tasks
            || self.pending.is_some()
            || self.exec_pending.is_some()
            || self.tasks.values().any(|task| task.fork_return.is_some())
        {
            return Err(LaunchError::Invalid(
                "dynamic lifetime task bound exhausted",
            ));
        }
        if tid != owner.pid
            || !owner.owned.contains(&tid)
            || !owner.stopped.contains_key(&tid)
            || owner.handles.get(&tid).is_none_or(broker::hup)
            || owner.pin_kinds.get(&tid) != Some(&PinKind::Process)
        {
            return Err(LaunchError::Invalid(
                "native thread clone requires the owned singleton leader",
            ));
        }
        same_pid_namespace(tid)?;
        single_task(tid)?;
        exec::native_leader(tid)?;
        let registers = read_registers(tid)?;
        let info = syscall_info(tid)?;
        if info.op != libc::PTRACE_SYSCALL_INFO_ENTRY
            || info.arch != AUDIT_ARCH_X86_64
            || registers.cs != 0x33
            || registers.orig_rax != libc::SYS_clone as u64
            || registers.rax != (-i64::from(libc::ENOSYS)) as u64
            || registers.eflags & 0x100 != 0
            || info.instruction_pointer != registers.rip
            || info.stack_pointer != registers.rsp
        {
            return Err(LaunchError::Invalid(
                "native thread entry did not authenticate",
            ));
        }
        // SAFETY: ENTRY authenticated the initialized member.
        let entry = unsafe { info.u.entry };
        if entry.nr != libc::SYS_clone as u64 || entry.args != arguments(&registers) {
            return Err(LaunchError::Invalid("native thread entry arguments differ"));
        }
        if registers.rdi != THREAD_FLAGS
            || registers.rdx != 0
            || registers.r10 != 0
            || registers.r8 != 0
        {
            return Err(LaunchError::Invalid(
                "native thread clone profile refuses arguments",
            ));
        }
        let bottom = registers.rsi.checked_sub(128).ok_or(LaunchError::Invalid(
            "native thread stack lacks writable storage",
        ))?;
        if !read_maps(tid)?.iter().any(|mapping| {
            mapping.start <= bottom
                && registers.rsi <= mapping.end
                && mapping.permissions.as_bytes().starts_with(b"rw")
        }) {
            return Err(LaunchError::Invalid(
                "native thread stack lacks writable storage",
            ));
        }
        thread_pin_supported(tid)?;
        shadow_stack_disabled(tid)?;
        let extended = xstate(tid)?;
        let mask = launch::task_mask(tid)?;
        let task = self.tasks[&tid].identity.task;
        let ticket = recorded(self.registry.prepare_creation(
            task,
            CreationRequest::Clone {
                flags: THREAD_FLAGS,
            },
        ))?;
        self.pending = Some(ForkPending {
            kind: CreationKind::Thread {
                stack: registers.rsi,
            },
            parent: task,
            ticket,
            entry: registers,
            xstate: extended,
            mask,
            child: None,
            parent_event: false,
            newborn: None,
        });
        Ok(())
    }

    pub(super) fn observe_thread_exiting(
        &mut self,
        owner: &mut Owner,
        tid: libc::pid_t,
        signal: i32,
    ) -> Result<DynamicEvent, LaunchError> {
        if signal != libc::SIGTRAP
            || !matches!(self.tasks[&tid].state, State::Running | State::Listening)
            || !owner.stopped.contains_key(&tid)
            || !owner.owned.contains(&tid)
            || owner.handles.get(&tid).is_none_or(broker::hup)
        {
            return Err(LaunchError::Invalid(
                "native pre-exit ownership did not authenticate",
            ));
        }
        let mut payload = 0_u64;
        ptrace(
            libc::PTRACE_GETEVENTMSG,
            tid,
            0,
            (&raw mut payload) as usize,
        )?;
        let raw = i32::try_from(payload)
            .map_err(|_| LaunchError::Invalid("native pre-exit status overflow"))?;
        let status = if libc::WIFEXITED(raw) {
            ExitStatus::Code(libc::WEXITSTATUS(raw) as u8)
        } else if libc::WIFSIGNALED(raw) && (1..=64).contains(&libc::WTERMSIG(raw)) {
            ExitStatus::Signal(libc::WTERMSIG(raw) as u8)
        } else {
            return Err(LaunchError::Invalid(
                "native pre-exit payload is not an exit status",
            ));
        };
        let identity = self.tasks[&tid].identity;
        // This event cannot return to original instructions. Record the explicit
        // Exiting phase only after the kernel-only continuation succeeds.
        ptrace(libc::PTRACE_CONT, tid, 0, 0)?;
        owner.released(tid);
        self.tasks.get_mut(&tid).unwrap().state = State::Exiting;
        recorded(
            self.registry
                .observe_exit_event(identity.task, self.sequence(tid)?, status),
        )?;
        Ok(DynamicEvent {
            tid,
            task: Some(identity),
            kind: DynamicEventKind::TaskExiting { status },
            stop: None,
        })
    }
}

#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner) use cet::CetRetainedSnapshot;
pub(in crate::linux::remote::dynamic::owner) use cet::{BoundedCet, certify_bounded_cet};
