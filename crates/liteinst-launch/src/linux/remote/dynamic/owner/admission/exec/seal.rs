//! The one native constructor of a consuming old-mm/new-mm census witness.
use super::*;

#[cfg(test)]
mod tests;

/// Both full-state copies are allocated before restoring the original syscall.
/// An abandoned preparation never grants authority or refunds its reservation.
pub(super) struct PreparedExecSeal {
    binding: ExecCensusBinding,
    original: PendingToken,
    next_pc: u64,
    until: Instant,
    before: ObservedStop,
    bound: bool,
    new_xstate: Vec<u8>,
}

/// Native proof is moved once. The caller retains transition/bootstrap while
/// the census consumes only the exact before/after accounting witness.
pub(super) struct SealedExec {
    pub(super) commit: ExecCensusCommit,
    pub(super) transition: ExecTransition,
    pub(super) bootstrap: BootstrapMm,
    pub(super) observed: ObservedStop,
}

impl PreparedExecSeal {
    pub(super) fn prepare(
        binding: ExecCensusBinding,
        pending: &PendingInvocation,
    ) -> Result<Self, GateError> {
        use crate::selected::{Operation, SyscallAbi};
        if binding.session != pending.token.stop.session
            || binding.space != pending.token.task.address_space
            || binding.generation != pending.token.epoch
            || ExecutionId::from_owner(binding.session, pending.token.invocation).ok()
                != Some(binding.invocation)
            || pending.stop.token != pending.token.stop
            || pending.stop.identity != pending.token.task
            || pending.before.token != pending.stop.token
            || pending.before.task != pending.stop.identity
            || pending.before.registers != *pending.input.registers()
            || pending.before.logical_pc != pending.input.instruction().logical_pc()
            || pending.before.logical_pc != pending.before.registers.rip
            || pending.before.phase != StopPhase::UserCheckpoint
            || pending.before.signal.is_some()
            || pending.before.registers.orig_rax != u64::MAX
            || !(512..MAX_XSTATE).contains(&pending.before.xstate.len())
            || pending.input.registers().rax != libc::SYS_execve as u64
            || !matches!(
                pending.input.instruction().operation(),
                Operation::Syscall {
                    abi: SyscallAbi::LinuxX64
                }
            )
        {
            return Err(refused(
                "exec seal preparation has a different original invocation",
            ));
        }
        let mut old_xstate = Vec::new();
        let mut new_xstate = Vec::new();
        old_xstate
            .try_reserve_exact(MAX_XSTATE)
            .map_err(|_| refused("exec old-state seal allocation failed"))?;
        new_xstate
            .try_reserve_exact(MAX_XSTATE)
            .map_err(|_| refused("exec new-state seal allocation failed"))?;
        old_xstate.extend_from_slice(&pending.before.xstate);
        let before = ObservedStop {
            token: pending.before.token.clone(),
            task: pending.before.task,
            logical_pc: pending.before.logical_pc,
            registers: pending.before.registers,
            xstate: old_xstate,
            signal_mask: pending.before.signal_mask,
            phase: pending.before.phase,
            signal: None,
        };
        Ok(Self {
            binding,
            original: pending.token.clone(),
            next_pc: pending.input.instruction().next_pc(),
            until: pending.until,
            before,
            bound: false,
            new_xstate,
        })
    }

    pub(super) fn retained_bytes(&self) -> Result<usize, GateError> {
        size_of::<Self>()
            .checked_add(self.before.xstate.capacity())
            .and_then(|bytes| bytes.checked_add(self.new_xstate.capacity()))
            .ok_or_else(|| refused("exec seal storage size overflows"))
    }

    /// Called once after all old-mm private restoration/settlement, immediately
    /// before executing the original syscall. The census must still contain
    /// this exact checkpoint when its eventual handoff is committed.
    pub(super) fn bind_before(&mut self, before: &ObservedStop) -> Result<(), GateError> {
        if self.bound
            || before.logical_pc != self.before.logical_pc
            || before.registers != self.before.registers
            || before.xstate != self.before.xstate
            || before.signal_mask != self.before.signal_mask
            || before.task != self.original.task
            || before.token.session != self.original.stop.session
            || before.token.tid != self.original.stop.tid
            || before.token.task != self.original.stop.task
            || before.token.sequence < self.original.stop.sequence
            || before.phase != StopPhase::UserCheckpoint
            || before.signal.is_some()
            || before.logical_pc != before.registers.rip
            || before.registers.orig_rax != u64::MAX
            || before.registers.rax != libc::SYS_execve as u64
            || before.registers.cs != 0x33
            || before.registers.eflags & (0x100 | 0x10000) != 0
            || !(512..MAX_XSTATE).contains(&before.xstate.len())
            || before.xstate.len() > self.before.xstate.capacity()
        {
            return Err(refused("exec seal lacks its exact last old-mm checkpoint"));
        }
        self.before.token = before.token.clone();
        self.bound = true;
        Ok(())
    }

    /// Consumes the actual native proof only after a fresh read-only check of
    /// the final held bootstrap. This never reads an old-mm numeric address.
    pub(super) fn seal(
        mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        ready: ExecBootstrapReady,
        until: Instant,
    ) -> Result<SealedExec, GateError> {
        owner.time_left(until, "exec census native seal")?;
        if !self.bound || until != self.until {
            return Err(refused(
                "exec seal lacks its original deadline and pre-release binding",
            ));
        }
        let before = self.before;
        let transition = ready.transition();
        let boot = ready.bootstrap();
        let entry = transition
            .entry()
            .stop_token()
            .ok_or_else(|| refused("exec native seal lacks actual ENTRY"))?;
        let exec = transition
            .exec_event()
            .stop_token()
            .ok_or_else(|| refused("exec native seal lacks actual EXEC"))?;
        let exit = transition
            .exit()
            .stop_token()
            .ok_or_else(|| refused("exec native seal lacks actual EXIT"))?;
        let mut expected_entry = before.registers;
        expected_entry.rip = self.next_pc;
        expected_entry.rcx = self.next_pc;
        expected_entry.orig_rax = libc::SYS_execve as u64;
        expected_entry.rax = (-i64::from(libc::ENOSYS)) as u64;
        expected_entry.r11 = before.registers.eflags & !0x10000;
        expected_entry.eflags &= !0x10000;
        if transition.until() != until
            || transition.previous() != before.task
            || transition.current() != boot.stop.identity
            || entry.session != before.token.session
            || entry.task != before.token.task
            || entry.tid != before.token.tid
            || entry.sequence <= before.token.sequence
            || transition.entry_state().registers != expected_entry
            || transition.entry_state().xstate != before.xstate
            || transition.entry_state().mask != before.signal_mask
            || exec.sequence != 0
            || exec.task == before.token.task
            || transition.current().address_space == before.task.address_space
            || transition.current().process != before.task.process
            || transition.current().generation != 0
            || exec.task != Some(transition.current().task)
            || exec.session != before.token.session
            || exec.tid != before.token.tid
            || exit.task != exec.task
            || exit.session != exec.session
            || exit.tid != exec.tid
            || exit.sequence <= exec.sequence
            || boot.stop.token.task != exit.task
            || boot.stop.token.session != exit.session
            || boot.stop.token.tid != exit.tid
            || boot.stop.token.sequence <= exit.sequence
        {
            return Err(refused(
                "exec census seal differs from the actual native identity chain",
            ));
        }
        authenticate_bootstrap(owner, native, boot, until)?;
        let actual = TaskStateSnapshot::read(boot.stop.token.tid)?;
        if actual != boot.evidence.restored_entry
            || actual.registers.orig_rax != u64::MAX
            || actual.registers.eflags & (0x100 | 0x10000) != 0
            || !(512..MAX_XSTATE).contains(&actual.xstate.len())
            || actual.xstate.len() > self.new_xstate.capacity()
        {
            return Err(refused("exec census seal lost the full first-user state"));
        }
        self.new_xstate.extend_from_slice(&actual.xstate);
        let after = ObservedStop {
            token: boot.stop.token.clone(),
            task: boot.stop.identity,
            logical_pc: actual.registers.rip,
            registers: actual.registers,
            xstate: self.new_xstate,
            signal_mask: actual.mask,
            phase: StopPhase::UserCheckpoint,
            signal: None,
        };
        let observed = ObservedStop {
            token: after.token.clone(),
            task: after.task,
            logical_pc: after.logical_pc,
            registers: actual.registers,
            xstate: actual.xstate,
            signal_mask: actual.mask,
            phase: after.phase,
            signal: None,
        };
        owner.time_left(until, "exec census native seal")?;
        let (transition, bootstrap) = ready.into_parts();
        Ok(SealedExec {
            commit: ExecCensusCommit {
                binding: self.binding,
                before,
                after,
            },
            transition,
            bootstrap,
            observed,
        })
    }
}

pub(super) fn authenticate_bootstrap(
    owner: &Owner,
    native: &NativeLifecycle,
    boot: &BootstrapMm,
    until: Instant,
) -> Result<(), GateError> {
    super::super::source_identity::authenticate_bootstrap(owner, native, boot, until)
}
