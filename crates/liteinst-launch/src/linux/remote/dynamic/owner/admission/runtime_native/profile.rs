//! Finite native control profile. Descriptive classifier flags grant nothing.
use super::super::super::lifecycle::{BoundedCet, certify_bounded_cet};
use super::*;
const DR_BASE: u64 = 0xffff_0ff0;
pub(super) const DR_TRACE: u64 = DR_BASE ^ 0x4000;

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::linux::remote::dynamic::owner::admission) struct DebugRead {
    pub(in crate::linux::remote::dynamic::owner::admission) values: [u64; 6],
    pub(in crate::linux::remote::dynamic::owner::admission) requests: [Option<Request>; 6],
}
impl DebugRead {
    pub(super) fn capture(&mut self, tid: i32) -> Result<(), LaunchError> {
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
    pub(super) fn require(&self, dr6: u64) -> Result<(), LaunchError> {
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
    fn require(&self, dr6: u64) -> Result<(), LaunchError> {
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
        profile.require(self.dr6)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn selected_successor(
        &self,
        proof: super::super::runtime::selected::native::NativeSelectedProof,
        before: &ControlProfile,
        after: &ControlProfile,
    ) -> Result<Self, LaunchError> {
        self.authenticate(proof.before(), before)?;
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
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn from_completion(
        completion: &OwnedInstructionCompletion<'_>,
    ) -> Result<Self, LaunchError> {
        let stop = completion.closing()[2].stop;
        let trace = completion.trace();
        if stop.phase != AdmissionPhase::Restored || stop.signal.is_some() || trace.dr6 != DR_TRACE
        {
            return Err(LaunchError::Invalid(
                "owned instruction control successor differs",
            ));
        }
        Ok(Self {
            checkpoint: stop.clone(),
            dr6: DR_TRACE,
        })
    }
}

#[cfg(test)]
mod tests;
