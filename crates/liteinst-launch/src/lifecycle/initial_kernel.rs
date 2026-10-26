//! Phase-specific initial singleton checks for an original kernel operation.
//! These descriptive model checks grant no held-stop or native release proof.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitialKernelPhase {
    Entry,
    Exit,
    PreExit,
}
impl LifecycleRegistry {
    pub(crate) fn require_initial_kernel_singleton(
        &self,
        selected: TaskId,
        process: ProcessId,
        space: AddressSpaceId,
        tid: i32,
        phase: InitialKernelPhase,
    ) -> Result<(), LifecycleError> {
        self.state.releasable(space)?;
        let task = self.task(selected)?;
        let address_space = self.address_space(space)?;
        if address_space.generation != 0 {
            return Err(LifecycleError::Stale);
        }
        let phase_matches = match phase {
            InitialKernelPhase::Entry => {
                matches!(
                    task.state,
                    TaskState::Held {
                        reason: HoldReason::SyscallEntry,
                        ..
                    }
                ) && task.syscall_open
            }
            InitialKernelPhase::Exit => {
                matches!(
                    task.state,
                    TaskState::Held {
                        reason: HoldReason::SyscallExit,
                        ..
                    }
                ) && !task.syscall_open
            }
            InitialKernelPhase::PreExit => {
                matches!(task.state, TaskState::Running) && task.syscall_open
            }
        };
        if !phase_matches
            || self.state.root != selected
            || self.state.tasks.len() != 1
            || self.state.tids.len() != 1
            || self.state.processes.len() != 1
            || self.state.spaces.len() != 1
            || !self.state.obligations.is_empty()
            || task.id != selected
            || task.tid != tid
            || task.process != process
            || task.address_space != space
            || task.origin != TaskOrigin::InitialExecSyscallExit
            || task.pending.is_some()
            || address_space.id != space
            || address_space.origin != AddressSpaceOrigin::Initial
            || self.state.tids.get(&tid) != Some(&selected)
            || self
                .state
                .processes
                .get(&process)
                .is_none_or(|record| record.tgid != tid)
        {
            return Err(LifecycleError::WrongState);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
