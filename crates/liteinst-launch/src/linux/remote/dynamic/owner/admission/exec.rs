//! One original exec replaces the live mm while retaining the old mm as history.
//! Only the native exec/bootstrap witnesses can authorize the census handoff.
//! A source reply, syscall number or descriptive identity cannot create it.
use super::super::bootstrap::{BootstrapMm, ExecBootstrapReady};
use super::super::exec_journal::ExecAttemptHandle;
use super::super::selected::ExecTransition;
use super::census::{
    CensusError, ExecCensusBinding, ExecCensusIdentity, PreparedExecCensus, Reservation,
    RetiredCensus,
};
use super::*;
use std::ops::Range;

mod budget;
mod history;
mod inputs;
mod observer;
#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission) mod oracle;
mod seal;
mod sources;
#[cfg(test)]
mod tests;
mod transaction;
use inputs::ExecInputs;
use seal::{PreparedExecSeal, SealedExec};
use sources::{CapturedExecSources, PreparedExecSources};

/// The two live-mm configurations never compose. One lifetime account remains
/// in AdmissionOwner; this object contains no independent budget or refund.
pub(super) struct ExecState {
    profile: DynamicExecProfile,
    options: DynamicAdmissionOptions,
    attempt: Option<Box<ExecAttempt>>,
    retired: Option<RetiredMm>,
}

struct ExecAttempt {
    original: PendingInvocation,
    reservation: Reservation,
    future: BudgetCharge,
    journal: ExecAttemptHandle,
    census: Option<PreparedExecCensus>,
    seal: Option<PreparedExecSeal>,
    inputs: ExecInputs,
    forbidden: Vec<Range<u64>>,
    old_mappings: Vec<MemoryMapping>,
    window: Option<routes::OriginalWindow>,
    scratch: PreparedExecSources,
    bootstrap: Option<ExecBootstrapReady>,
    layout: Option<ExecBootstrapLayout>,
    captured: Option<CapturedExecSources>,
    request: Option<DynamicSourceRequest>,
    reply: Option<DynamicSourceFacts>,
    transition: Option<ExecTransition>,
    admitted: bool,
}

struct ExecBootstrapLayout {
    original_executables: Vec<MemoryMapping>,
    mappings: Vec<MemoryMapping>,
    stop: AdmissionStop,
}

/// Kept inline in ExecState, so moving the old census/domain here cannot
/// allocate or fail after census.commit_exec_mm. None of these fields has a
/// Drop path that reads, restores or revokes an old numeric child address.
struct RetiredMm {
    domain: Domain,
    census: RetiredCensus,
    island: TrustedIsland,
    bootstrap: BootstrapEvidence,
    origins: BTreeMap<TaskId, OriginId>,
}

impl ExecState {
    pub(super) fn new(profile: DynamicExecProfile, options: DynamicAdmissionOptions) -> Self {
        Self {
            profile,
            options,
            attempt: None,
            retired: None,
        }
    }

    pub(super) fn has_pending(&self) -> bool {
        self.attempt
            .as_ref()
            .is_some_and(|attempt| !attempt.admitted)
    }

    pub(super) fn pending_until(&self) -> Option<Instant> {
        self.attempt
            .as_ref()
            .filter(|attempt| !attempt.admitted)
            .map(|attempt| attempt.original.until)
    }
}

pub(super) fn is_exec(input: &SelectedInput) -> bool {
    use crate::selected::{Operation, SyscallAbi};
    matches!(
        input.instruction().operation(),
        Operation::Syscall {
            abi: SyscallAbi::LinuxX64
        }
    ) && input.registers().rax == libc::SYS_execve as u64
}

/// Consumed by the existing census. The production constructor is private to
/// the native handoff below; tests can construct synthetic model inputs only.
pub(super) struct ExecCensusCommit {
    binding: ExecCensusBinding,
    before: ObservedStop,
    after: ObservedStop,
}

impl ExecCensusCommit {
    pub(super) fn validate_census_transition(
        &self,
        identity: &ExecCensusIdentity<'_>,
    ) -> Result<(), CensusError> {
        if self.binding != identity.binding {
            return Err(CensusError::IdentityMismatch);
        }
        if self.before != *identity.before || self.after != *identity.after {
            return Err(CensusError::StaleObservation);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn synthetic_for_test(
        binding: ExecCensusBinding,
        before: ObservedStop,
        after: ObservedStop,
    ) -> Self {
        Self {
            binding,
            before,
            after,
        }
    }
}

fn refused(reason: &'static str) -> GateError {
    GateError::Refused(reason)
}
