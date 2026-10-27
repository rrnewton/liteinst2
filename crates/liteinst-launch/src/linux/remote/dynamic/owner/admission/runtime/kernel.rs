//! Opt-in original-site native identity and termination operations.
//! A compact copied descriptor grants no source or execution authority.
use super::super::runtime_capture::{RuntimeWindowProof, SourceWindowId};
use super::super::runtime_native::ControlLineage;
use super::maps::FetchGeometry;
use super::*;
use crate::linux::remote::dynamic::admission::RuntimePendingToken;
use crate::linux::remote::dynamic::owner::kernel_journal::KernelAttemptId;
use crate::selected::{SelectedArguments, SelectedInput, SyscallAbi};

#[cfg(feature = "dev-owned-stack-consumer-oracle")]
mod consumer_oracle;
mod drive;
pub(in crate::linux::remote::dynamic::owner) mod namespace;
mod observer;
mod storage;
use super::super::census::{
    PreparedRuntimeKernelCensus, Reservation, runtime_kernel_census_charge,
};
use super::super::runtime_capture::{
    CapturedKernelRead, CapturedRuntimeRead, KernelCatalogCheckpoint, RuntimeCatalogCheckpoint,
};
use super::super::runtime_kernel_native::*;
use super::super::runtime_native::{ControlProfile, NativeCheckpoint};
use super::super::source_identity::SourceReadProgress;
use crate::gate::{SelectedCompletion, SelectedExecution};
use crate::linux::remote::dynamic::admission::{RuntimeKernelProfile, RuntimeProviderInput};
use crate::linux::remote::dynamic::owner::kernel_journal::{
    KernelFailureKind, PreparedRuntimeJournal, RuntimeJournalBefore, RuntimeJournalShape,
    RuntimeJournalSink, RuntimeKernelHandle, RuntimeKernelJournalStage, RuntimeKernelReleasePhase,
};
use crate::selected::{ProviderDecision, SyscallAliases};
use observer::KernelObserver;
pub(super) use storage::RuntimeKernelAttempt;
use storage::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum RuntimeKernelOperation {
    Getpid,
    Gettid,
    Exit,
    ExitGroup,
}
impl RuntimeKernelOperation {
    pub(super) fn from_number(number: u64) -> Option<Self> {
        match number {
            value if value == libc::SYS_getpid as u64 => Some(Self::Getpid),
            value if value == libc::SYS_gettid as u64 => Some(Self::Gettid),
            value if value == libc::SYS_exit as u64 => Some(Self::Exit),
            value if value == libc::SYS_exit_group as u64 => Some(Self::ExitGroup),
            _ => None,
        }
    }

    pub(in crate::linux::remote::dynamic::owner) fn from_input(
        input: &SelectedInput,
    ) -> Result<Self, LaunchError> {
        if input.instruction().bytes() != [0x0f, 0x05] {
            return Err(LaunchError::Invalid(
                "runtime kernel operation is not exact native SYSCALL",
            ));
        }
        let SelectedArguments::Syscall {
            abi: SyscallAbi::LinuxX64,
            number,
            ..
        } = input.arguments()
        else {
            return Err(LaunchError::Invalid("runtime kernel operation ABI differs"));
        };
        match number {
            value if value == libc::SYS_getpid as u64 => Ok(Self::Getpid),
            value if value == libc::SYS_gettid as u64 => Ok(Self::Gettid),
            value if value == libc::SYS_exit as u64 => Ok(Self::Exit),
            value if value == libc::SYS_exit_group as u64 => Ok(Self::ExitGroup),
            _ => Err(LaunchError::Invalid(
                "runtime kernel operation is outside its finite profile",
            )),
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn number(self) -> u64 {
        match self {
            Self::Getpid => libc::SYS_getpid as u64,
            Self::Gettid => libc::SYS_gettid as u64,
            Self::Exit => libc::SYS_exit as u64,
            Self::ExitGroup => libc::SYS_exit_group as u64,
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn returns(self) -> bool {
        matches!(self, Self::Getpid | Self::Gettid)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct RuntimeKernelIdentity {
    pending: RuntimePendingToken,
    source: SourceWindowId,
    origin: OriginId,
    execution: ExecutionId,
    attempt: KernelAttemptId,
    operation: RuntimeKernelOperation,
    encoding: [u8; 2],
    next_pc: u64,
    arguments: [u64; 6],
    until: Instant,
}
impl RuntimeKernelIdentity {
    // Add inside RuntimeKernelIdentity impl. No RuntimeKernelBinding or native seal is constructed.
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn synthetic_for_census(
        pending: RuntimePendingToken,
        source: SourceWindowId,
        origin: OriginId,
        execution: ExecutionId,
        operation: RuntimeKernelOperation,
        arguments: [u64; 6],
        until: Instant,
    ) -> Self {
        Self {
            next_pc: pending.pc.wrapping_add(2),
            attempt: KernelAttemptId {
                session: pending.stop.session,
                invocation: pending.invocation,
            },
            pending,
            source,
            origin,
            execution,
            operation,
            encoding: [0x0f, 0x05],
            arguments,
            until,
        }
    }

    pub(in crate::linux::remote::dynamic::owner) fn attempt(&self) -> KernelAttemptId {
        self.attempt
    }
    pub(in crate::linux::remote::dynamic::owner) fn pending(&self) -> &RuntimePendingToken {
        &self.pending
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn source_id(&self) -> SourceWindowId {
        self.source
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn origin(&self) -> OriginId {
        self.origin
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn execution(&self) -> ExecutionId {
        self.execution
    }
    pub(in crate::linux::remote::dynamic::owner) fn task(&self) -> DynamicTask {
        self.pending.task
    }
    pub(in crate::linux::remote::dynamic::owner) fn session(&self) -> u64 {
        self.attempt.session
    }
    pub(in crate::linux::remote::dynamic::owner) fn tid(&self) -> i32 {
        self.pending.stop.tid
    }
    pub(in crate::linux::remote::dynamic::owner) fn operation(&self) -> RuntimeKernelOperation {
        self.operation
    }
    pub(in crate::linux::remote::dynamic::owner) fn pc(&self) -> u64 {
        self.pending.pc
    }
    pub(in crate::linux::remote::dynamic::owner) fn next_pc(&self) -> u64 {
        self.next_pc
    }
    pub(in crate::linux::remote::dynamic::owner) fn encoding(&self) -> &[u8] {
        &self.encoding
    }
    pub(in crate::linux::remote::dynamic::owner) fn number(&self) -> u64 {
        self.operation.number()
    }
    pub(in crate::linux::remote::dynamic::owner) fn arguments(&self) -> [u64; 6] {
        self.arguments
    }
    pub(in crate::linux::remote::dynamic::owner) fn until(&self) -> Instant {
        self.until
    }
    pub(in crate::linux::remote::dynamic::owner) fn journal_source(
        &self,
    ) -> (liteinst2::contracts::CodeIdentity, usize) {
        (self.source.identity(), self.source.index())
    }
    pub(in crate::linux::remote::dynamic::owner) fn journal_origin(&self) -> (u64, u64) {
        self.origin.journal_identity()
    }
    pub(in crate::linux::remote::dynamic::owner) fn journal_execution(&self) -> (u64, u64) {
        self.execution.journal_identity()
    }
}

/// Only the actual read proof constructs this invocation binding. Full source
/// and before-state payloads remain borrowed; the native copy is descriptive.
pub(in crate::linux::remote::dynamic::owner) struct RuntimeKernelBinding<'a> {
    source: RuntimeWindowProof<'a>,
    input: &'a SelectedInput,
    pending: &'a RuntimePendingToken,
    geometry: FetchGeometry,
    identity: RuntimeKernelIdentity,
    island: &'a TrustedIsland,
    lineage: &'a ControlLineage,
}
/// Owner-only preparation description, with no constructor outside runtime.
struct BindingRequest<'a> {
    input: &'a SelectedInput,
    pending: &'a RuntimePendingToken,
    origin: OriginId,
    island: &'a TrustedIsland,
    lineage: &'a ControlLineage,
}
impl<'a> RuntimeKernelBinding<'a> {
    fn new(
        source: RuntimeWindowProof<'a>,
        census: &ResumeCensus,
        request: BindingRequest<'a>,
    ) -> Result<Self, GateError> {
        let BindingRequest {
            input,
            pending,
            origin,
            island,
            lineage,
        } = request;
        let window = source.window();
        let before = source.observed();
        let stop = source.stop();
        let operation = RuntimeKernelOperation::from_input(input)?;
        let SelectedArguments::Syscall {
            abi: SyscallAbi::LinuxX64,
            number,
            arguments,
        } = input.arguments()
        else {
            return Err(GateError::Refused(
                "runtime kernel selected invocation differs",
            ));
        };
        let pc = input.registers().rip;
        let next_pc = pc
            .checked_add(2)
            .ok_or(GateError::Refused("runtime kernel next PC overflows"))?;
        let offset = pc
            .checked_sub(window.snapshot.range().start())
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(GateError::Refused(
                "runtime kernel PC is outside its source",
            ))?;
        let end = offset
            .checked_add(2)
            .ok_or(GateError::Refused("runtime kernel source offset overflows"))?;
        if input.registers() != &before.registers
            || window.snapshot.bytes().get(offset..end) != Some(&[0x0f, 0x05][..])
            || before.logical_pc != pc
            || before.token != stop.token
            || before.task != stop.identity
            || before.phase != StopPhase::UserCheckpoint
            || before.signal.is_some()
            || stop.signal.is_some()
            || !matches!(
                stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || stop.identity.generation != 0
            || stop.identity.address_space != island.address_space
            || island.generation != 0
            || census.generation() != 0
            || island.page_size != 4096
            || island.range.start % 4096 != 0
            || island.range.end.checked_sub(island.range.start) != Some(4096)
            || pending.stop != stop.token
            || pending.task != stop.identity
            || pending.generation != window.snapshot.generation
            || pending.mapping != window.snapshot.mapping
            || pending.window != window.id.index()
            || pending.pc != pc
            || pending.invocation == 0
            || number != operation.number()
        {
            return Err(GateError::Refused(
                "runtime kernel exact source/checkpoint binding differs",
            ));
        }
        census
            .check_current_origin(origin, before)
            .map_err(census_error)?;
        let geometry = FetchGeometry::for_initial_source(
            window.initial_source(),
            liteinst_admission::AddressRange::new(pc, next_pc).ok_or(GateError::Refused(
                "runtime kernel instruction range differs",
            ))?,
        )?;
        if (geometry.pages().start() < island.range.end
            && island.range.start < geometry.pages().end())
            || island.range.contains(&next_pc)
            || (0xffff_ffff_ff60_0000..0xffff_ffff_ff60_1000).contains(&next_pc)
        {
            return Err(GateError::Refused(
                "runtime kernel instruction overlaps private or fixed code",
            ));
        }
        geometry.projected_rows(source.baseline_maps())?;
        let execution = ExecutionId::from_owner(stop.token.session, pending.invocation)
            .map_err(census_error)?;
        let identity = RuntimeKernelIdentity {
            pending: pending.clone(),
            source: window.id,
            origin,
            execution,
            attempt: KernelAttemptId {
                session: stop.token.session,
                invocation: pending.invocation,
            },
            operation,
            encoding: [0x0f, 0x05],
            next_pc,
            arguments,
            until: source.until(),
        };
        Ok(Self {
            source,
            input,
            pending,
            geometry,
            identity,
            island,
            lineage,
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn identity(&self) -> &RuntimeKernelIdentity {
        &self.identity
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn source_id(&self) -> SourceWindowId {
        self.identity.source_id()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn origin(&self) -> OriginId {
        self.identity.origin()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn execution(&self) -> ExecutionId {
        self.identity.execution()
    }
    pub(in crate::linux::remote::dynamic::owner) fn attempt(&self) -> KernelAttemptId {
        self.identity.attempt()
    }
    pub(in crate::linux::remote::dynamic::owner) fn pending(&self) -> &'a RuntimePendingToken {
        self.pending
    }
    pub(in crate::linux::remote::dynamic::owner) fn operation(&self) -> RuntimeKernelOperation {
        self.identity.operation()
    }
    pub(in crate::linux::remote::dynamic::owner) fn input(&self) -> &'a SelectedInput {
        self.input
    }
    pub(in crate::linux::remote::dynamic::owner) fn stop(&self) -> &'a AdmissionStop {
        self.source.stop()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn before(&self) -> &'a ObservedStop {
        self.source.observed()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn geometry(&self) -> &FetchGeometry {
        &self.geometry
    }
    pub(in crate::linux::remote::dynamic::owner) fn island(&self) -> &'a TrustedIsland {
        self.island
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn lineage(
        &self,
    ) -> &'a ControlLineage {
        self.lineage
    }
    pub(in crate::linux::remote::dynamic::owner) fn baseline_maps(&self) -> &'a [u8] {
        self.source.baseline_maps()
    }
    pub(in crate::linux::remote::dynamic::owner) fn until(&self) -> Instant {
        self.source.until()
    }
}

// Insert before the existing cfg(test) tests declaration; do not append after it.
#[cfg(test)]
mod native_tests;

#[cfg(test)]
mod tests;
