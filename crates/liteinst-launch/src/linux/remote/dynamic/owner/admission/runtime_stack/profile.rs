//! Prepared initial profile records and descriptive validation. This type is
//! deliberately not OriginalStackIdentity: only a future actual held-stop
//! acquisition seam may issue that certificate after native authentication.
use super::access::{PkuLayout, PkuLayoutEvidence, validate_state};
use super::metadata::{StackDescriptor, StackMetadata, validate_smaps};
use super::storage::StackObservationStorage;
use super::*;

pub(in crate::linux::remote::dynamic::owner::admission) struct ProfileInput<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) bootstrap: &'a BootstrapMm,
    pub(in crate::linux::remote::dynamic::owner::admission) original_maps: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner::admission) baseline_maps: &'a [u8],
}
#[derive(Debug)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ProfileDescription {
    pub(in crate::linux::remote::dynamic::owner::admission) stack: StackDescriptor,
    pub(in crate::linux::remote::dynamic::owner::admission) metadata: StackMetadata,
    pub(in crate::linux::remote::dynamic::owner::admission) layout: PkuLayout,
    pub(in crate::linux::remote::dynamic::owner::admission) initial_rsp: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) island: Range<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission) restored: AdmissionStop,
}
pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedStackProfile {
    pub(in crate::linux::remote::dynamic::owner::admission) observation: StackObservationStorage,
    pub(in crate::linux::remote::dynamic::owner::admission) layout_evidence: PkuLayoutEvidence,
    attempted: bool,
    first_failure: Option<StackError>,
    description: Option<ProfileDescription>,
}
impl PreparedStackProfile {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            observation: StackObservationStorage::empty(),
            layout_evidence: PkuLayoutEvidence::default(),
            attempted: false,
            first_failure: None,
            description: None,
        }
    }
    // Standalone-owner formula for pure controls; native wrappers charge their own headers.
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_bytes()
    -> Result<usize, StackError> {
        add(size_of::<Self>(), 3 * BYTES)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_payloads(
        &mut self,
    ) -> Result<(), StackError> {
        self.observation.allocate_payloads()
    }
    // Pure-control total; production wrappers use the checked payload_bytes tally.
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocated_bytes(
        &self,
    ) -> Result<usize, StackError> {
        add(size_of::<Self>(), self.observation.payload_bytes()?)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        self.observation.mark_aborted();
        if self.first_failure().is_none() {
            self.first_failure = Some(StackError::Aborted);
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn first_failure(
        &self,
    ) -> Option<StackError> {
        self.first_failure
            .or(self.observation.allocation.first_failure)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn description(
        &self,
    ) -> Option<&ProfileDescription> {
        if self.first_failure().is_none() {
            self.description.as_ref()
        } else {
            None
        }
    }
    /// Supplied records are descriptive. No live token or original permission
    /// is acquired here, and failure cannot be retried on this retained owner.
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate(
        &mut self,
        input: ProfileInput<'_>,
    ) -> Result<&ProfileDescription, StackError> {
        if self.attempted || self.first_failure().is_some() {
            return Err(StackError::Reused);
        }
        self.attempted = true;
        let result = self.validate_inner(input);
        match result {
            Ok(description) => {
                self.description = Some(description);
                Ok(self.description.as_ref().expect("installed description"))
            }
            Err(error) => {
                self.first_failure = Some(error);
                Err(error)
            }
        }
    }
    fn validate_inner(&self, input: ProfileInput<'_>) -> Result<ProfileDescription, StackError> {
        self.observation.require_ready()?;
        let boot = input.bootstrap;
        if boot.stop.identity.generation != 0
            || boot.island.generation != 0
            || boot.stop.identity.address_space != boot.island.address_space
            || boot.stop.token.task != Some(boot.stop.identity.task)
            || boot.stop.token.session == 0
            || boot.stop.token.tid <= 0
            || boot.stop.token.sequence == 0
            || boot.stop.signal.is_some()
            || !matches!(
                boot.stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || boot.island.page_size != PAGE as usize
            || boot.island.range.start % PAGE != 0
            || boot.island.range.end.checked_sub(boot.island.range.start) != Some(PAGE)
        {
            return Err(StackError::Provenance);
        }
        validate_bootstrap_data(
            &boot.evidence.exec_event,
            &boot.evidence.exec_exit,
            &boot.evidence.entry_trap,
            &boot.evidence.restored_entry,
        )?;
        let layout = self.layout_evidence.validate()?;
        validate_state(&self.observation.state, layout)?;
        if self.observation.state.state != boot.evidence.restored_entry {
            return Err(StackError::State);
        }
        let captured_maps = self
            .observation
            .maps_capture
            .bytes(&self.observation.maps)?;
        if captured_maps != input.baseline_maps {
            return Err(StackError::Maps);
        }
        let smaps = self
            .observation
            .smaps_capture
            .bytes(&self.observation.smaps)?;
        let initial_rsp = boot.evidence.restored_entry.registers.rsp;
        let stack = StackDescriptor::validate(
            input.original_maps,
            captured_maps,
            initial_rsp,
            &boot.island.range,
        )?;
        let metadata = validate_smaps(smaps, captured_maps, stack.baseline_index)?;
        Ok(ProfileDescription {
            stack,
            metadata,
            layout,
            initial_rsp,
            island: boot.island.range.clone(),
            restored: boot.stop.clone(),
        })
    }
}
/// Exact historical data relations used by bootstrap, with actual first-user
/// XSTATE retained independently because hardware return may initialize PKRU.
/// Raw waits/physical stops remain a separate mandatory future producer proof.
pub(in crate::linux::remote::dynamic::owner::admission) fn validate_bootstrap_data(
    exec: &TaskStateSnapshot,
    exit: &TaskStateSnapshot,
    first_user: &TaskStateSnapshot,
    restored: &TaskStateSnapshot,
) -> Result<(), StackError> {
    if exec.registers.cs != 0x33
        || exec.registers.orig_rax != libc::SYS_execve as u64
        || exec.registers.rax != (-i64::from(libc::ENOSYS)) as u64
        || !low(exec.registers.rip)
        || !low(exec.registers.rsp)
    {
        return Err(StackError::Provenance);
    }
    let mut expected = exec.registers;
    expected.rax = 0;
    if exit.registers != expected || exit.xstate != exec.xstate || exit.mask != exec.mask {
        return Err(StackError::State);
    }
    expected.rip = expected
        .rip
        .checked_add(1)
        .filter(|pc| low(*pc))
        .ok_or(StackError::Geometry)?;
    expected.orig_rax = u64::MAX;
    if first_user.registers != expected || first_user.mask != exit.mask {
        return Err(StackError::State);
    }
    expected.rip = exec.registers.rip;
    if restored.registers != expected
        || restored.xstate != first_user.xstate
        || restored.mask != first_user.mask
    {
        return Err(StackError::State);
    }
    Ok(())
}
