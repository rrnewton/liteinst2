//! Finite native control profile. Descriptive classifier flags grant nothing.
use super::super::super::lifecycle::{BoundedCet, certify_bounded_cet};
use super::super::runtime_kernel_native::OwnedRuntimeKernelReturn;
use super::*;
use crate::linux::remote::dynamic::owner::kernel_journal::{KernelAttemptId, KernelStopIdentity};
#[cfg(test)]
mod native_oracle;
#[cfg(test)]
pub(super) use native_oracle::{ControlLineageSnapshot, ProfileSnapshot};
const DR_BASE: u64 = 0xffff_0ff0;
pub(in crate::linux::remote::dynamic::owner::admission) const DR_TRACE: u64 = DR_BASE ^ 0x4000;

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::linux::remote::dynamic::owner::admission) struct DebugRead {
    pub(in crate::linux::remote::dynamic::owner::admission) values: [u64; 6],
    pub(in crate::linux::remote::dynamic::owner::admission) requests: [Option<Request>; 6],
}
impl DebugRead {
    pub(in crate::linux::remote::dynamic::owner::admission) fn capture(
        &mut self,
        tid: i32,
    ) -> Result<(), LaunchError> {
        for (slot, index) in [0usize, 1, 2, 3, 6, 7].into_iter().enumerate() {
            let offset = std::mem::offset_of!(libc::user, u_debugreg) + index * size_of::<u64>();
            let result = request(libc::PTRACE_PEEKUSER, tid, offset, 0);
            self.values[slot] = result.result as u64;
            self.requests[slot] = Some(result);
        }
        for result in self.requests.iter().flatten() {
            if let Some(errno) = result.errno {
                return Err(io_error(
                    "PTRACE_PEEKUSER debug state",
                    std::io::Error::from_raw_os_error(errno),
                ));
            }
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require(
        &self,
        dr6: u64,
    ) -> Result<(), LaunchError> {
        if self
            .requests
            .iter()
            .any(|result| result.is_none_or(|result| result.errno.is_some()))
            || self
                .requests
                .iter()
                .zip(self.values)
                .any(|(request, value)| {
                    request.is_some_and(|request| request.result as u64 != value)
                })
            || self.values != [0, 0, 0, 0, dr6, 0]
        {
            return Err(LaunchError::Invalid(
                "owned instruction debug profile differs",
            ));
        }
        Ok(())
    }
}
#[derive(Default)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ControlProfile {
    pub(in crate::linux::remote::dynamic::owner::admission) debug: DebugRead,
    pub(in crate::linux::remote::dynamic::owner::admission) rseq: [u8; 24],
    pub(in crate::linux::remote::dynamic::owner::admission) rseq_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) cet: BoundedCet,
    complete: bool,
    tid: Option<i32>,
}
impl ControlProfile {
    /// Named temporary evidence in capture, in addition to retained Self.
    pub(in crate::linux::remote::dynamic::owner::admission) fn temporary_bytes()
    -> Result<usize, LaunchError> {
        BoundedCet::temporary_bytes()?
            .checked_add(size_of::<Request>())
            .and_then(|bytes| {
                size_of::<Result<(), LaunchError>>()
                    .checked_mul(2)
                    .and_then(|results| bytes.checked_add(results))
            })
            .ok_or(LaunchError::Invalid(
                "owned control temporary storage overflows",
            ))
    }

    /// Caller owns a positively authenticated live stopped pin throughout.
    pub(in crate::linux::remote::dynamic::owner::admission) fn capture(
        &mut self,
        owner: &Owner,
        until: Instant,
    ) -> Result<(), LaunchError> {
        if self.rseq_request.is_some() || self.complete {
            return Err(LaunchError::Invalid(
                "owned instruction control storage reused",
            ));
        }
        bootstrap::physical(owner, until)?;
        self.tid = Some(owner.pid);
        let debug_result = self.debug.capture(owner.pid);
        let rseq = request(
            0x420f,
            owner.pid,
            self.rseq.len(),
            self.rseq.as_mut_ptr() as usize,
        );
        self.rseq_request = Some(rseq);
        let cet_result = certify_bounded_cet(owner, &mut self.cet, until);
        debug_result?;
        if let Some(errno) = rseq.errno {
            return Err(io_error(
                "PTRACE_GET_RSEQ_CONFIGURATION",
                std::io::Error::from_raw_os_error(errno),
            ));
        }
        if rseq.result != 24 || self.rseq != [0; 24] {
            return Err(LaunchError::Invalid(
                "owned instruction requires exact unregistered rseq",
            ));
        }
        cet_result?;
        bootstrap::physical(owner, until)?;
        self.complete = true;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require(
        &self,
        dr6: u64,
    ) -> Result<(), LaunchError> {
        if !self.complete
            || !self.cet.complete
            || self.rseq != [0; 24]
            || self.rseq_request
                != Some(Request {
                    result: 24,
                    errno: None,
                })
        {
            return Err(LaunchError::Invalid(
                "owned instruction control profile incomplete",
            ));
        }
        self.debug.require(dr6)
    }
}
/// Historical control provenance only. Actual profile/current state must be
/// reread before every release. No Clone, public constructor or DR6 argument.
pub(in crate::linux::remote::dynamic::owner::admission) struct ControlLineage {
    checkpoint: AdmissionStop,
    dr6: u64,
    kernel: Option<KernelControlOrigin>,
}
/// Minted only by kernel_successor from the borrowed native return seal.
/// The complete native/census histories retain the actual ENTRY/EXIT payloads;
/// this inline projection binds their immutable provenance to every successor.
#[derive(Clone)]
struct KernelControlOrigin {
    attempt: KernelAttemptId,
    returned: AdmissionStop,
    number: u64,
}
impl ControlLineage {
    /// The BootstrapMm is the actual native bootstrap proof already retained
    /// by the owner. This operation allocates nothing and performs no query.
    pub(in crate::linux::remote::dynamic::owner::admission) fn from_bootstrap(
        boot: &bootstrap::BootstrapMm,
    ) -> Result<Self, LaunchError> {
        if boot.stop.identity.generation != 0
            || boot.stop.signal.is_some()
            || !matches!(
                boot.stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || boot.stop.identity.address_space != boot.island.address_space
            || boot.island.generation != 0
            || boot.evidence.restored_entry.registers.cs != 0x33
            || boot.evidence.restored_entry.registers.orig_rax != u64::MAX
        {
            return Err(LaunchError::Invalid(
                "owned instruction control seed is not original bootstrap",
            ));
        }
        Ok(Self {
            checkpoint: boot.stop.clone(),
            dr6: DR_BASE,
            kernel: None,
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn authenticate(
        &self,
        stop: &AdmissionStop,
        profile: &ControlProfile,
    ) -> Result<(), LaunchError> {
        if *stop != self.checkpoint || profile.tid != Some(stop.token.tid) {
            return Err(LaunchError::Invalid(
                "owned instruction control lineage is stale",
            ));
        }
        self.require_orig_rax(stop, self.inherited_orig_rax())?;
        profile.require(self.dr6)
    }
    fn inherited_orig_rax(&self) -> u64 {
        self.kernel
            .as_ref()
            .map_or(u64::MAX, |origin| origin.number)
    }
    /// No scalar permission is accepted: the exact current token and retained
    /// sealed-return lineage must agree with the independently observed value.
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_orig_rax(
        &self,
        stop: &AdmissionStop,
        actual: u64,
    ) -> Result<(), LaunchError> {
        if stop != &self.checkpoint {
            return Err(LaunchError::Invalid(
                "owned instruction control lineage is stale",
            ));
        }
        if let Some(origin) = &self.kernel {
            if origin.attempt.session != stop.token.session
                || origin.attempt.invocation == 0
                || origin.returned.identity != stop.identity
                || origin.returned.token.session != stop.token.session
                || origin.returned.token.tid != stop.token.tid
                || origin.returned.token.task != stop.token.task
                || origin.returned.token.sequence > stop.token.sequence
                || origin.returned.phase != AdmissionPhase::Restored
                || origin.returned.signal.is_some()
                || stop.phase != AdmissionPhase::Restored
                || stop.signal.is_some()
                || (origin.number != libc::SYS_getpid as u64
                    && origin.number != libc::SYS_gettid as u64)
            {
                return Err(LaunchError::Invalid(
                    "owned instruction kernel control provenance differs",
                ));
            }
        }
        if actual != self.inherited_orig_rax() {
            return Err(LaunchError::Invalid(
                "owned instruction inherited orig_rax differs",
            ));
        }
        Ok(())
    }
    fn selected_orig_rax(
        &self,
        stop: &AdmissionStop,
        before: u64,
        after: u64,
    ) -> Result<(), LaunchError> {
        self.require_orig_rax(stop, before)?;
        if after != before {
            return Err(LaunchError::Invalid(
                "selected native orig_rax was not preserved",
            ));
        }
        Ok(())
    }
    /// Allocation-free staged lineage. Root installs it only after the census
    /// consumes this same one-shot seal and commits its complete retained rows.
    /// This borrow never claims the seal or constructs a native completion.
    pub(in crate::linux::remote::dynamic::owner::admission) fn kernel_successor(
        &self,
        proof: &OwnedRuntimeKernelReturn<'_>,
    ) -> Result<Self, LaunchError> {
        let binding = proof.binding();
        let before = proof.logical_before();
        self.require_orig_rax(before.stop, before.state.registers.orig_rax)?;
        let trace = proof.trace();
        if !binding.operation().returns()
            || binding.pending().stop != before.stop.token
            || binding.task() != before.stop.identity
            || binding.attempt() != trace.attempt
            || trace.dr6 != self.dr6
            || binding.encoding() != [0x0f, 0x05]
            || binding.pc() != before.state.registers.rip
            || binding.pc().checked_add(2) != Some(binding.next_pc())
        {
            return Err(LaunchError::Invalid(
                "kernel control return binding differs",
            ));
        }
        let opening = proof.opening();
        let mut previous = before.stop;
        for checkpoint in &opening {
            runner::next_stop(previous, checkpoint.stop)?;
            if checkpoint.stop.phase != AdmissionPhase::Restored || checkpoint.state != before.state
            {
                return Err(LaunchError::Invalid("kernel control opening differs"));
            }
            previous = checkpoint.stop;
        }
        let entry = proof.entry();
        let exit = proof.exit();
        let entry_token = entry
            .event
            .stop_token()
            .ok_or(LaunchError::Invalid("kernel control ENTRY token absent"))?;
        let exit_token = exit
            .event
            .stop_token()
            .ok_or(LaunchError::Invalid("kernel control EXIT token absent"))?;
        if entry.event.task != Some(before.stop.identity)
            || exit.event.task != Some(before.stop.identity)
            || entry.event.tid != before.stop.token.tid
            || exit.event.tid != before.stop.token.tid
            || entry_token.session != before.stop.token.session
            || exit_token.session != before.stop.token.session
            || entry_token.tid != before.stop.token.tid
            || exit_token.tid != before.stop.token.tid
            || entry_token.task != before.stop.token.task
            || exit_token.task != before.stop.token.task
            || entry_token.sequence <= previous.token.sequence
            || exit_token.sequence <= entry_token.sequence
            || entry.event.kind
                != (DynamicEventKind::SyscallEntry {
                    number: binding.number(),
                    arguments: binding.arguments(),
                })
            || exit.event.kind
                != (DynamicEventKind::SyscallExit {
                    result: i64::from(before.stop.token.tid),
                    is_error: false,
                })
            || entry.state.registers.orig_rax != binding.number()
            || exit.state.registers.orig_rax != binding.number()
            || exit.state.registers.rip != binding.next_pc()
            || trace.entry_ordinal != 3
            || trace.exit_ordinal != 4
            || trace.bridge_ordinal != 5
            || trace.closed_ordinal != 8
            || trace.released != KernelStopIdentity::from(&opening[2].stop.token)
            || trace.entry != KernelStopIdentity::from(entry_token)
            || trace.exit != KernelStopIdentity::from(exit_token)
        {
            return Err(LaunchError::Invalid(
                "kernel control actual syscall lineage differs",
            ));
        }
        let bridge = proof.bridge();
        let closing = proof.closing();
        if bridge.stop.token.sequence <= exit_token.sequence {
            return Err(LaunchError::Invalid(
                "kernel control bridge sequence differs",
            ));
        }
        // next_stop also binds session/TID/task/mm, without fabricating an
        // AdmissionStop for the actual syscall EXIT.
        for checkpoint in std::iter::once(bridge).chain(closing.iter().copied()) {
            if checkpoint.stop.phase != AdmissionPhase::Restored || checkpoint.state != exit.state {
                return Err(LaunchError::Invalid("kernel control closed state differs"));
            }
            runner::next_stop(previous, checkpoint.stop)?;
            previous = checkpoint.stop;
        }
        if trace.bridge != KernelStopIdentity::from(&bridge.stop.token)
            || trace.closed != KernelStopIdentity::from(&previous.token)
        {
            return Err(LaunchError::Invalid("kernel control closed trace differs"));
        }
        Ok(Self {
            checkpoint: previous.clone(),
            dr6: self.dr6,
            kernel: Some(KernelControlOrigin {
                attempt: binding.attempt(),
                returned: previous.clone(),
                number: exit.state.registers.orig_rax,
            }),
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn selected_successor(
        &self,
        proof: super::super::runtime::selected::native::NativeSelectedProof,
        before: &ControlProfile,
        after: &ControlProfile,
    ) -> Result<Self, LaunchError> {
        self.authenticate(proof.before(), before)?;
        self.selected_orig_rax(
            proof.before(),
            proof.before_orig_rax(),
            proof.after_orig_rax(),
        )?;
        runner::next_stop(proof.before(), proof.after())?;
        if proof.after().phase != AdmissionPhase::Restored
            || proof.after().signal.is_some()
            || after.tid != Some(proof.after().token.tid)
        {
            return Err(LaunchError::Invalid("selected control successor differs"));
        }
        after.require(self.dr6)?;
        Ok(Self {
            checkpoint: proof.after().clone(),
            dr6: self.dr6,
            kernel: self.kernel.clone(),
        })
    }
    /// Stage lineage from the sole real stack completion; this does not
    /// consume it or install the next current origin. Root installs only after
    /// census successfully consumes that same borrowed native witness.
    pub(in crate::linux::remote::dynamic::owner::admission) fn stack_successor(
        &self,
        proof: &super::super::runtime_stack_native::OwnedStackCompletion<'_>,
    ) -> Result<Self, LaunchError> {
        let identity = proof.identity();
        let before = proof.logical_before();
        self.require_orig_rax(before.stop, before.state.registers.orig_rax)?;
        if identity.stop() != before.stop
            || identity.until() != identity.operand_description().until
            || identity.operand_description().stop != *before.stop
        {
            return Err(LaunchError::Invalid("owned stack control binding differs"));
        }
        let opening = proof.opening();
        let mut previous = before.stop;
        for checkpoint in &opening {
            runner::next_stop(previous, checkpoint.stop)?;
            if checkpoint.stop.phase != AdmissionPhase::Restored || checkpoint.state != before.state
            {
                return Err(LaunchError::Invalid("owned stack control opening differs"));
            }
            previous = checkpoint.stop;
        }
        let step = proof.step();
        let trace = proof.trace();
        runner::next_stop(previous, step.stop)?;
        if step.stop.phase != AdmissionPhase::NativeCompleted
            || step.state.registers.orig_rax != u64::MAX
            || trace.ordinal != 3
            || trace.tid != before.stop.token.tid
            || trace.dr6 != DR_TRACE
            || !libc::WIFSTOPPED(trace.status)
            || libc::WSTOPSIG(trace.status) != libc::SIGTRAP
            || trace.status >> 16 != 0
        {
            return Err(LaunchError::Invalid("owned stack control trace differs"));
        }
        let words = proof.words();
        if words.operand != identity.operand_description()
            || words.profile.stack != identity.stack_descriptor()
            || words.profile.metadata != identity.stack_metadata()
            || words.profile.layout != identity.pku_layout()
            || words.profile.initial_rsp != identity.initial_rsp()
            || words.profile.restored != *identity.initial_stop()
            || words
                .captures
                .iter()
                .any(|capture| !capture.complete || capture.first_failure.is_some())
            || words.captures[0].word.bytes != words.captures[1].word.bytes
            || words.captures[2].word.bytes != words.captures[3].word.bytes
        {
            return Err(LaunchError::Invalid(
                "owned stack control word identity differs",
            ));
        }
        super::super::runtime_stack::operand::validate_effect(
            before.state,
            step.state,
            words.operand,
            &words.captures[0].word.bytes,
            &words.captures[2].word.bytes,
        )
        .map_err(|_| LaunchError::Invalid("owned stack control effect differs"))?;
        previous = step.stop;
        for checkpoint in &proof.closing() {
            runner::next_stop(previous, checkpoint.stop)?;
            if checkpoint.stop.phase != AdmissionPhase::Restored || checkpoint.state != step.state {
                return Err(LaunchError::Invalid("owned stack control closing differs"));
            }
            previous = checkpoint.stop;
        }
        Ok(Self {
            checkpoint: previous.clone(),
            dr6: DR_TRACE,
            kernel: None,
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn from_completion(
        completion: &OwnedInstructionCompletion<'_>,
    ) -> Result<Self, LaunchError> {
        let stop = completion.closing()[2].stop;
        let trace = completion.trace();
        if stop.phase != AdmissionPhase::Restored
            || stop.signal.is_some()
            || trace.dr6 != DR_TRACE
            || completion.step().state.registers.orig_rax != u64::MAX
            || completion
                .closing()
                .iter()
                .any(|checkpoint| checkpoint.state.registers.orig_rax != u64::MAX)
        {
            return Err(LaunchError::Invalid(
                "owned instruction control successor differs",
            ));
        }
        Ok(Self {
            checkpoint: stop.clone(),
            dr6: DR_TRACE,
            kernel: None,
        })
    }
}

#[cfg(test)]
mod tests;
