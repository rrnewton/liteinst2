//! Bounded continuation bookkeeping for the native admission owner.
//!
//! Inputs are facts authenticated by the parent owner. This module performs no
//! ptrace operation, establishes no exclusion, resolves no native route and
//! grants no executable permission. In particular, a projection is not a saved
//! context completeness certificate. CALL-return history remains in the
//! separate append-only CallReturnLedger; this module cannot retire it.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
mod exec;
pub(super) use exec::{
    ExecCensusBinding, ExecCensusIdentity, PreparedExecCensus, RetiredCensus, exec_initial_charge,
};
#[cfg(test)]
mod panic_custody;
mod runtime;
pub(super) use runtime::{InitialRuntimeReservation, initial_runtime_origin_charge};
mod ordinary;
pub(super) use ordinary::{OrdinaryCensusResult, PreparedOrdinaryCensus, ordinary_census_charge};
mod selected_runtime;
pub(super) use selected_runtime::PreparedRuntimeSelected;
mod signal;
pub(super) use signal::{FrameFacts, SignalReturnWitness};
use std::sync::atomic::{AtomicU64, Ordering};

use iced_x86::{Decoder, DecoderOptions};
use liteinst_admission::entries::{LegalEntrySet, ResumeKind};
use liteinst_admission::{AddressRange, Generation, MappingId};

use super::super::super::SignalFrameId;
use crate::lifecycle::{AddressSpaceId, TaskId};
use crate::selected::{CompletedInstruction, SelectedInput};
use crate::{DynamicSignalInfo, DynamicStop, DynamicTask, RegisterSnapshot};

static NEXT_CENSUS: AtomicU64 = AtomicU64::new(1);
const MAX_ITEMS: usize = 1_048_576;
const MAX_RETAINED_BYTES: usize = 1 << 30;
const MAX_XSTATE_BYTES: usize = 64 * 1024;

/// Lifetime limits, including the initial generation, consumed origins and all retained witnesses.
/// `source_fact_bytes` covers retained state/instruction payloads here AND the
/// parent's CALL/report/plan source storage. It is not only executable bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Limits {
    pub(super) epochs: usize,
    pub(super) source_fact_bytes: usize,
    pub(super) reports: usize,
    pub(super) origins: usize,
    pub(super) witnesses: usize,
    pub(super) plan_history: usize,
}

impl Limits {
    pub(super) fn validate(self) -> Result<Self, CensusError> {
        if [
            self.epochs,
            self.reports,
            self.origins,
            self.witnesses,
            self.plan_history,
        ]
        .into_iter()
        .any(|value| value == 0 || value > MAX_ITEMS)
            || self.source_fact_bytes == 0
            || self.source_fact_bytes > MAX_RETAINED_BYTES
        {
            return Err(CensusError::InvalidLimits);
        }
        Ok(self)
    }
}

/// A conservative charge reserved BEFORE native writes or clone entry.
/// Reservation charges are lifetime charges: finishing an unused reservation
/// does not refund them or remove any historical record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct BudgetCharge {
    pub(super) epochs: usize,
    pub(super) source_fact_bytes: usize,
    pub(super) reports: usize,
    pub(super) origins: usize,
    pub(super) witnesses: usize,
    pub(super) plan_history: usize,
}

impl BudgetCharge {
    fn add(self, other: Self) -> Result<Self, CensusError> {
        Ok(Self {
            epochs: self
                .epochs
                .checked_add(other.epochs)
                .ok_or(CensusError::Capacity)?,
            source_fact_bytes: self
                .source_fact_bytes
                .checked_add(other.source_fact_bytes)
                .ok_or(CensusError::Capacity)?,
            reports: self
                .reports
                .checked_add(other.reports)
                .ok_or(CensusError::Capacity)?,
            origins: self
                .origins
                .checked_add(other.origins)
                .ok_or(CensusError::Capacity)?,
            witnesses: self
                .witnesses
                .checked_add(other.witnesses)
                .ok_or(CensusError::Capacity)?,
            plan_history: self
                .plan_history
                .checked_add(other.plan_history)
                .ok_or(CensusError::Capacity)?,
        })
    }

    fn subtract(self, other: Self) -> Result<Self, CensusError> {
        Ok(Self {
            epochs: self
                .epochs
                .checked_sub(other.epochs)
                .ok_or(CensusError::ReservationExhausted)?,
            source_fact_bytes: self
                .source_fact_bytes
                .checked_sub(other.source_fact_bytes)
                .ok_or(CensusError::ReservationExhausted)?,
            reports: self
                .reports
                .checked_sub(other.reports)
                .ok_or(CensusError::ReservationExhausted)?,
            origins: self
                .origins
                .checked_sub(other.origins)
                .ok_or(CensusError::ReservationExhausted)?,
            witnesses: self
                .witnesses
                .checked_sub(other.witnesses)
                .ok_or(CensusError::ReservationExhausted)?,
            plan_history: self
                .plan_history
                .checked_sub(other.plan_history)
                .ok_or(CensusError::ReservationExhausted)?,
        })
    }

    fn fits(self, limits: Limits) -> bool {
        self.epochs <= limits.epochs
            && self.source_fact_bytes <= limits.source_fact_bytes
            && self.reports <= limits.reports
            && self.origins <= limits.origins
            && self.witnesses <= limits.witnesses
            && self.plan_history <= limits.plan_history
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CensusError {
    InvalidLimits,
    Capacity,
    Allocation,
    OutstandingReservation,
    StaleReservation,
    ReservationExhausted,
    UnknownOrigin,
    InactiveOrigin,
    IdentityMismatch,
    StaleObservation,
    InvalidObservation,
    WrongOriginPhase,
    PersistentUnknown,
    InvalidConsumption,
    GenerationNotAdvanced,
    MissingImage,
    OverlappingImages,
    ProjectionMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct OriginId {
    census: u64,
    serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Reservation {
    census: u64,
    serial: u64,
}

/// The admission owner allocates this identity for an actual execution permit
/// or selected invocation. It is not a permission to execute by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExecutionId {
    session: u64,
    serial: u64,
}

impl ExecutionId {
    pub(super) fn from_owner(session: u64, serial: u64) -> Result<Self, CensusError> {
        if session == 0 || serial == 0 {
            return Err(CensusError::IdentityMismatch);
        }
        Ok(Self { session, serial })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OriginKind {
    CurrentHeldPc,
    /// A separately retained actual frame return or declared prospective edit.
    /// It is never consumed by an ordinary selected instruction or task exit.
    SignalFrame {
        frame: SignalFrameId,
        prospective: bool,
    },
    ParentSyscallReturn {
        syscall: u64,
    },
    NewbornStart {
        parent: TaskId,
        syscall: u64,
    },
    /// Signal frames, nonlocal buffers and other unqualified persistent facts.
    /// Equal addresses/kinds do not merge their independent origin identities.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "unqualified persistent origins remain an explicit refused class; native import is not enabled"
        )
    )]
    UnknownPersistent {
        kind: ResumeKind,
    },
}

impl OriginKind {
    pub(super) fn resume_kind(self) -> ResumeKind {
        match self {
            Self::CurrentHeldPc | Self::NewbornStart { .. } => ResumeKind::ParkedThread,
            Self::ParentSyscallReturn { .. } => ResumeKind::SyscallReturn,
            Self::UnknownPersistent { kind } => kind,
            Self::SignalFrame { .. } => ResumeKind::SignalFrame,
        }
    }
}

/// Exact owner-classified phase. This enum cannot authenticate a kernel event;
/// that remains the native owner's responsibility before calling this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StopPhase {
    UserCheckpoint,
    OriginalSignal,
    SignalReturn,
    OwnedFetch,
    Interrupted,
    OwnedGuard,
    SyscallEntry {
        syscall: u64,
    },
    ParentSyscallExit {
        syscall: u64,
        result: i64,
        is_error: bool,
    },
    NewbornReturnReady {
        parent: TaskId,
        syscall: u64,
    },
    SelectedComplete {
        invocation: ExecutionId,
    },
    /// One genuine owned trace completion, inserted only by the consumed
    /// ordinary seal adapter. Generic current-origin insertion stays closed.
    OwnedOrdinaryComplete {
        execution: ExecutionId,
    },
}

/// Full original observation. A raw INT3 RIP may be logical_pc + 1; the input
/// comparison below adjusts only that explicitly classified PC, never flags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ObservedStop {
    pub(super) token: DynamicStop,
    pub(super) task: DynamicTask,
    pub(super) logical_pc: u64,
    pub(super) registers: RegisterSnapshot,
    pub(super) xstate: Vec<u8>,
    pub(super) signal_mask: u64,
    pub(super) phase: StopPhase,
    pub(super) signal: Option<DynamicSignalInfo>,
}

impl ObservedStop {
    fn validate(&self, session: u64, space: AddressSpaceId) -> Result<(), CensusError> {
        if session == 0
            || self.token.session != session
            || self.token.tid <= 0
            || self.token.task != Some(self.task.task)
            || self.task.address_space != space
        {
            return Err(CensusError::IdentityMismatch);
        }
        let pc_matches = self.registers.rip == self.logical_pc
            || (self.phase == StopPhase::OwnedGuard
                && self.logical_pc.checked_add(1) == Some(self.registers.rip));
        if self.logical_pc == 0
            || !pc_matches
            || self.registers.cs != 0x33
            || self.xstate.is_empty()
            || self.xstate.len() > MAX_XSTATE_BYTES
        {
            return Err(CensusError::InvalidObservation);
        }
        match self.phase {
            StopPhase::OwnedOrdinaryComplete { execution }
                if execution.session != session
                    || execution.serial == 0
                    || self.signal.as_ref().map(DynamicSignalInfo::signal)
                        != Some(libc::SIGTRAP)
                    || self.signal.as_ref().map(DynamicSignalInfo::code)
                        != Some(libc::TRAP_TRACE) =>
            {
                return Err(CensusError::InvalidObservation);
            }
            StopPhase::OriginalSignal if self.signal.is_none() => {
                return Err(CensusError::InvalidObservation);
            }
            StopPhase::SignalReturn if self.registers.orig_rax != u64::MAX => {
                return Err(CensusError::InvalidObservation);
            }
            StopPhase::OwnedFetch
                if self.signal.as_ref().map(DynamicSignalInfo::signal) != Some(libc::SIGSEGV) =>
            {
                return Err(CensusError::InvalidObservation);
            }
            StopPhase::OwnedGuard
                if self.signal.as_ref().map(DynamicSignalInfo::signal) != Some(libc::SIGTRAP) =>
            {
                return Err(CensusError::InvalidObservation);
            }
            StopPhase::SyscallEntry { syscall } if self.registers.orig_rax != syscall => {
                return Err(CensusError::InvalidObservation);
            }
            StopPhase::ParentSyscallExit {
                syscall, result, ..
            } if self.registers.orig_rax != syscall || self.registers.rax != result as u64 => {
                return Err(CensusError::InvalidObservation);
            }
            StopPhase::NewbornReturnReady { parent, .. }
                if parent == self.task.task || self.registers.rax != 0 =>
            {
                return Err(CensusError::InvalidObservation);
            }
            _ => {}
        }
        Ok(())
    }

    fn logical_registers(&self) -> RegisterSnapshot {
        RegisterSnapshot {
            rip: self.logical_pc,
            ..self.registers
        }
    }

    fn retained_bytes(&self) -> usize {
        // Include fixed metadata as well as all separately allocated payloads.
        std::mem::size_of::<Self>() + self.xstate.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OriginRow {
    pub(super) id: OriginId,
    pub(super) kind: OriginKind,
    pub(super) pc: u64,
    pub(super) created_generation: u64,
    pub(super) initial: ObservedStop,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ActiveOrigin<'a> {
    pub(super) row: &'a OriginRow,
    pub(super) current: &'a ObservedStop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredOrigin {
    row: OriginRow,
    current: ObservedStop,
    active: bool,
    frame: Option<Arc<FrameFacts>>,
}

/// Full evidence of the one already-authorized native clone invocation.
/// Retained unchanged across admission-generation rebinding; it is neither a
/// new provider callback nor a reusable instruction execution permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompletedKernel {
    invocation: ExecutionId,
    before: ObservedStop,
    input: SelectedInput,
    entry: ObservedStop,
    parent_exit: ObservedStop,
    newborn: ObservedStop,
}

impl CompletedKernel {
    pub(super) fn clone_from_owner(
        invocation: ExecutionId,
        before: ObservedStop,
        input: SelectedInput,
        entry: ObservedStop,
        parent_exit: ObservedStop,
        newborn: ObservedStop,
    ) -> Result<Self, CensusError> {
        input_matches(&before, &input, invocation)?;
        let instruction = decode_whole(
            input.instruction().logical_pc(),
            input.instruction().bytes(),
        )?;
        if instruction.code() != iced_x86::Code::Syscall
            || input.registers().rax != libc::SYS_clone as u64
            || entry.phase
                != (StopPhase::SyscallEntry {
                    syscall: libc::SYS_clone as u64,
                })
            || !same_task(&before, &entry)
            || !same_task(&entry, &parent_exit)
            || entry.token.sequence <= before.token.sequence
            || parent_exit.token.sequence <= entry.token.sequence
            || entry.logical_pc != input.instruction().next_pc()
            || parent_exit.logical_pc != input.instruction().next_pc()
            || newborn.logical_pc != input.instruction().next_pc()
            || newborn.task.task == before.task.task
            || newborn.task.process != before.task.process
            || newborn.task.address_space != before.task.address_space
            || newborn.task.generation != before.task.generation
            || newborn.token.session != before.token.session
            || newborn.registers.rax != 0
            || parent_exit.phase
                != (StopPhase::ParentSyscallExit {
                    syscall: libc::SYS_clone as u64,
                    result: i64::from(newborn.token.tid),
                    is_error: false,
                })
            || parent_exit.registers.rax != newborn.token.tid as u64
            || newborn.phase
                != (StopPhase::NewbornReturnReady {
                    parent: before.task.task,
                    syscall: libc::SYS_clone as u64,
                })
        {
            return Err(CensusError::InvalidConsumption);
        }
        for stop in [&entry, &parent_exit, &newborn] {
            stop.validate(before.token.session, before.task.address_space)?;
        }
        Ok(Self {
            invocation,
            before,
            input,
            entry,
            parent_exit,
            newborn,
        })
    }

    #[cfg(test)]
    pub(super) fn invocation(&self) -> ExecutionId {
        self.invocation
    }
    #[cfg(test)]
    pub(super) fn parent_exit(&self) -> &ObservedStop {
        &self.parent_exit
    }
    #[cfg(test)]
    pub(super) fn newborn(&self) -> &ObservedStop {
        &self.newborn
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Consumption {
    Selected {
        invocation: ExecutionId,
        input: Box<SelectedInput>,
        completed: Box<CompletedInstruction>,
    },
    OriginalProgress {
        execution: ExecutionId,
        first_instruction: Vec<u8>,
    },
    /// Exactly one preallocated immutable record; actual authority was consumed.
    OwnedOrdinary(Box<[ordinary::OrdinaryEvidence]>),
    KernelClone(Box<CompletedKernel>),
    Signal(Box<signal::SignalConsumption>),
}

/// Private owner-issued evidence, with semantic consistency checks here. Only
/// the parent native owner may authenticate actual execution and event lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OwnerConsumption {
    before: ObservedStop,
    successor: ObservedStop,
    evidence: Consumption,
}

/// A terminal wait is not a held stop. The owner must authenticate the actual
/// wait and the retained incarnation's pidfd poll; these are recorded facts,
/// not a numeric PID reacquisition or a native physical-reap capability.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ObservedTerminal {
    pub(super) session: u64,
    pub(super) task: DynamicTask,
    pub(super) tid: libc::pid_t,
    pub(super) sequence: u64,
    pub(super) wait_status: i32,
    pub(super) pidfd_events: i16,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OwnerTerminal {
    before: ObservedStop,
    terminal: ObservedTerminal,
}

#[cfg(test)]
impl OwnerTerminal {
    pub(super) fn from_owner(
        before: ObservedStop,
        terminal: ObservedTerminal,
    ) -> Result<Self, CensusError> {
        before.validate(before.token.session, before.task.address_space)?;
        if terminal.session != before.token.session
            || terminal.task.task != before.task.task
            || terminal.task.process != before.task.process
            || terminal.task.address_space != before.task.address_space
            || terminal.task.generation < before.task.generation
            || terminal.tid != before.token.tid
            || terminal.sequence <= before.token.sequence
            || !(libc::WIFEXITED(terminal.wait_status) || libc::WIFSIGNALED(terminal.wait_status))
            || (libc::WIFSIGNALED(terminal.wait_status)
                && !(1..=64).contains(&libc::WTERMSIG(terminal.wait_status)))
            || terminal.pidfd_events != (libc::POLLIN | libc::POLLHUP)
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(Self { before, terminal })
    }

    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.before.retained_bytes()
            + std::mem::size_of::<HistoryRecord>()
    }
}

impl OwnerConsumption {
    pub(super) fn completed_selected(
        invocation: ExecutionId,
        before: ObservedStop,
        input: SelectedInput,
        completed: CompletedInstruction,
        successor: ObservedStop,
    ) -> Result<Self, CensusError> {
        input_matches(&before, &input, invocation)?;
        successor_matches(&before, &successor)?;
        if completed.instruction != *input.instruction()
            || completed.before != *input.registers()
            || completed.after != successor.registers
            || successor.logical_pc != input.instruction().next_pc()
            || successor.phase != (StopPhase::SelectedComplete { invocation })
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(Self {
            before,
            successor,
            evidence: Consumption::Selected {
                invocation,
                input: Box::new(input),
                completed: Box::new(completed),
            },
        })
    }

    /// A real different-PC owned fetch/guard/checkpoint after an original-run
    /// permit. The owner must prove uninterrupted original execution lineage;
    /// the token/PC checks alone are not that proof. This deliberately does not
    /// accept interruptions, syscall-entry stops or same-PC fetch/guard traps.
    pub(super) fn original_progress(
        execution: ExecutionId,
        before: ObservedStop,
        first_instruction: Vec<u8>,
        successor: ObservedStop,
    ) -> Result<Self, CensusError> {
        decode_whole(before.logical_pc, &first_instruction)?;
        successor_matches(&before, &successor)?;
        if execution.session != before.token.session
            || successor.logical_pc == before.logical_pc
            || !matches!(
                successor.phase,
                StopPhase::OwnedFetch | StopPhase::OwnedGuard | StopPhase::UserCheckpoint
            )
            || matches!(before.phase, StopPhase::SyscallEntry { .. })
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(Self {
            before,
            successor,
            evidence: Consumption::OriginalProgress {
                execution,
                first_instruction,
            },
        })
    }

    pub(super) fn completed_kernel(kernel: CompletedKernel) -> Self {
        Self {
            before: kernel.before.clone(),
            successor: kernel.parent_exit.clone(),
            evidence: Consumption::KernelClone(Box::new(kernel)),
        }
    }

    fn retained_bytes(&self) -> usize {
        let payload = match &self.evidence {
            Consumption::Selected {
                input, completed, ..
            } => {
                std::mem::size_of::<SelectedInput>()
                    + std::mem::size_of::<CompletedInstruction>()
                    + input.instruction().bytes().len()
                    + completed.instruction.bytes().len()
            }
            Consumption::OriginalProgress {
                first_instruction, ..
            } => first_instruction.len(),
            Consumption::Signal(signal) => signal.retained_bytes(),
            Consumption::OwnedOrdinary(records) => {
                records.len() * std::mem::size_of::<ordinary::OrdinaryEvidence>()
            }
            Consumption::KernelClone(kernel) => {
                kernel.before.retained_bytes()
                    + kernel.entry.retained_bytes()
                    + kernel.parent_exit.retained_bytes()
                    + kernel.newborn.retained_bytes()
                    + kernel.input.instruction().bytes().len()
                    + std::mem::size_of::<CompletedKernel>()
            }
        };
        std::mem::size_of::<Self>()
            + self.before.retained_bytes()
            + self.successor.retained_bytes()
            + payload
    }
}

fn decode_whole(pc: u64, bytes: &[u8]) -> Result<iced_x86::Instruction, CensusError> {
    if bytes.is_empty() || bytes.len() > 15 {
        return Err(CensusError::InvalidConsumption);
    }
    let instruction = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE).decode();
    if instruction.is_invalid()
        || instruction.len() != bytes.len()
        || pc.checked_add(bytes.len() as u64) != Some(instruction.next_ip())
    {
        return Err(CensusError::InvalidConsumption);
    }
    Ok(instruction)
}

fn same_task(before: &ObservedStop, after: &ObservedStop) -> bool {
    before.token.session == after.token.session
        && before.token.tid == after.token.tid
        && before.task == after.task
        && before.token.task == after.token.task
}

fn successor_matches(before: &ObservedStop, successor: &ObservedStop) -> Result<(), CensusError> {
    before.validate(before.token.session, before.task.address_space)?;
    successor.validate(before.token.session, before.task.address_space)?;
    if !same_task(before, successor) || successor.token.sequence <= before.token.sequence {
        return Err(CensusError::InvalidConsumption);
    }
    Ok(())
}

fn input_matches(
    before: &ObservedStop,
    input: &SelectedInput,
    invocation: ExecutionId,
) -> Result<(), CensusError> {
    before.validate(before.token.session, before.task.address_space)?;
    decode_whole(
        input.instruction().logical_pc(),
        input.instruction().bytes(),
    )?;
    if invocation.session != before.token.session
        || before.logical_pc != input.instruction().logical_pc()
        || before.logical_registers() != *input.registers()
        || !matches!(
            before.phase,
            StopPhase::OwnedGuard | StopPhase::UserCheckpoint
        )
    {
        return Err(CensusError::InvalidConsumption);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum HistoryRecord {
    Refreshed {
        origin: OriginId,
        before: ObservedStop,
        after: ObservedStop,
    },
    Consumed {
        origin: OriginId,
        evidence: OwnerConsumption,
    },
    // Model-only until physical terminal evidence is wired into the dispatcher.
    #[cfg(test)]
    Terminal {
        origin: OriginId,
        evidence: OwnerTerminal,
    },
    SignalFrameRefreshed(Box<signal::FrameRefresh>),
    SignalFrameReturned(Box<signal::FrameReturn>),
    SignalDelivered(Box<signal::SignalDelivered>),
    Epoch {
        before: u64,
        after: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ImageScope {
    pub(super) mapping: MappingId,
    pub(super) range: AddressRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Projection {
    pub(super) mapping: MappingId,
    pub(super) generation: Generation,
    pub(super) scope: AddressRange,
    pub(super) origins: Vec<OriginId>,
    pub(super) resumes: BTreeMap<u64, BTreeSet<ResumeKind>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    generation: u64,
    next_serial: u64,
    charged: BudgetCharge,
    used: BudgetCharge,
    reservation: Option<(Reservation, BudgetCharge)>,
    origins: Vec<StoredOrigin>,
    history: Vec<HistoryRecord>,
}

/// One mm's bounded original/current origin inventory. This intentionally has
/// no Clone implementation and no origin/history removal or CALL-ledger API.
pub(super) struct ResumeCensus {
    identity: u64,
    session: u64,
    space: AddressSpaceId,
    limits: Limits,
    state: State,
}

impl ResumeCensus {
    /// Counts the supplied initial generation as one used and charged epoch.
    /// This records resource ownership only, not native generation authority.
    pub(super) fn new(
        session: u64,
        space: AddressSpaceId,
        generation: u64,
        limits: Limits,
    ) -> Result<Self, CensusError> {
        let limits = limits.validate()?;
        if session == 0 {
            return Err(CensusError::IdentityMismatch);
        }
        let identity = NEXT_CENSUS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CensusError::Capacity)?;
        Ok(Self {
            identity,
            session,
            space,
            limits,
            state: State {
                generation,
                next_serial: 1,
                charged: BudgetCharge {
                    epochs: 1,
                    ..BudgetCharge::default()
                },
                used: BudgetCharge {
                    epochs: 1,
                    ..BudgetCharge::default()
                },
                reservation: None,
                origins: Vec::new(),
                history: Vec::new(),
            },
        })
    }

    pub(super) fn generation(&self) -> u64 {
        self.state.generation
    }
    pub(super) fn charged(&self) -> BudgetCharge {
        self.state.charged
    }
    pub(super) fn used(&self) -> BudgetCharge {
        self.state.used
    }
    pub(super) fn rows(&self) -> impl Iterator<Item = &OriginRow> {
        self.state.origins.iter().map(|entry| &entry.row)
    }
    pub(super) fn history(&self) -> &[HistoryRecord] {
        &self.state.history
    }
    pub(super) fn active(&self) -> impl Iterator<Item = ActiveOrigin<'_>> {
        self.state
            .origins
            .iter()
            .filter(|entry| entry.active)
            .map(|entry| ActiveOrigin {
                row: &entry.row,
                current: &entry.current,
            })
    }

    pub(super) fn reserve(&mut self, charge: BudgetCharge) -> Result<Reservation, CensusError> {
        if self.state.reservation.is_some() {
            return Err(CensusError::OutstandingReservation);
        }
        let charged = self.state.charged.add(charge)?;
        if !charged.fits(self.limits) {
            return Err(CensusError::Capacity);
        }
        let next = self
            .state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        let history = charge
            .witnesses
            .checked_add(charge.epochs)
            .ok_or(CensusError::Capacity)?;
        self.state
            .origins
            .try_reserve(charge.origins)
            .map_err(|_| CensusError::Allocation)?;
        self.state
            .history
            .try_reserve(history)
            .map_err(|_| CensusError::Allocation)?;
        let token = Reservation {
            census: self.identity,
            serial: self.state.next_serial,
        };
        self.state.next_serial = next;
        self.state.charged = charged;
        self.state.reservation = Some((token, charge));
        Ok(token)
    }

    /// Validate the remaining reservation before a native operation. This does
    /// not consume capacity, refund earlier charges, or authenticate a native
    /// effect. The actual retained evidence must still be debited afterward.
    pub(super) fn check_reserved(
        &self,
        token: Reservation,
        charge: BudgetCharge,
    ) -> Result<(), CensusError> {
        self.prepare_debit(token, charge).map(|_| ())
    }

    pub(super) fn finish_reservation(&mut self, token: Reservation) -> Result<(), CensusError> {
        self.remaining(token)?;
        self.state.reservation = None;
        Ok(())
    }

    /// Charge parent-retained CALL/report/plan payload before native mutation.
    /// This records resource use only; it does not authenticate those facts.
    pub(super) fn account_external(
        &mut self,
        token: Reservation,
        charge: BudgetCharge,
    ) -> Result<(), CensusError> {
        if charge.epochs != 0 || charge.origins != 0 || charge.witnesses != 0 {
            return Err(CensusError::ReservationExhausted);
        }
        let (remaining, used) = self.prepare_debit(token, charge)?;
        self.commit_debit(token, remaining, used);
        Ok(())
    }

    pub(super) fn insert(
        &mut self,
        token: Reservation,
        kind: OriginKind,
        pc: u64,
        observed: ObservedStop,
    ) -> Result<OriginId, CensusError> {
        observed.validate(self.session, self.space)?;
        if observed.task.generation != self.state.generation {
            return Err(CensusError::StaleObservation);
        }
        if pc == 0 {
            return Err(CensusError::InvalidObservation);
        }
        match kind {
            OriginKind::CurrentHeldPc
                if pc == observed.logical_pc
                    && matches!(
                        observed.phase,
                        StopPhase::UserCheckpoint
                            | StopPhase::OwnedFetch
                            | StopPhase::Interrupted
                            | StopPhase::OwnedGuard
                            | StopPhase::SelectedComplete { .. }
                    ) => {}
            OriginKind::ParentSyscallReturn { syscall }
                if pc == observed.logical_pc
                    && matches!(observed.phase, StopPhase::ParentSyscallExit { syscall: number, .. } if syscall == number) =>
                {}
            OriginKind::NewbornStart { parent, syscall }
                if pc == observed.logical_pc
                    && observed.phase == (StopPhase::NewbornReturnReady { parent, syscall }) => {}
            OriginKind::UnknownPersistent { .. } => {}
            _ => return Err(CensusError::WrongOriginPhase),
        }
        let bytes = observed
            .retained_bytes()
            .checked_mul(2)
            .and_then(|value| value.checked_add(std::mem::size_of::<StoredOrigin>()))
            .ok_or(CensusError::Capacity)?;
        let charge = BudgetCharge {
            origins: 1,
            source_fact_bytes: bytes,
            ..BudgetCharge::default()
        };
        let (remaining, used) = self.prepare_debit(token, charge)?;
        let next = self
            .state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        let id = OriginId {
            census: self.identity,
            serial: self.state.next_serial,
        };
        self.state.origins.push(StoredOrigin {
            row: OriginRow {
                id,
                kind,
                pc,
                created_generation: self.state.generation,
                initial: observed.clone(),
            },
            current: observed,
            active: true,
            frame: None,
        });
        self.state.next_serial = next;
        self.commit_debit(token, remaining, used);
        Ok(id)
    }

    /// Refresh a still-unexecuted continuation. Same-PC NX/interrupt/guard
    /// evidence never marks it consumed. A new generation may rebind identical
    /// held physical evidence, but the old observation remains in history.
    pub(super) fn refresh_same_pc(
        &mut self,
        token: Reservation,
        id: OriginId,
        after: ObservedStop,
    ) -> Result<(), CensusError> {
        let index = self.active_index(id)?;
        let stored = &self.state.origins[index];
        if matches!(
            stored.row.kind,
            OriginKind::UnknownPersistent { .. } | OriginKind::SignalFrame { .. }
        ) {
            return Err(CensusError::PersistentUnknown);
        }
        after.validate(self.session, self.space)?;
        let before = &stored.current;
        if after.task.generation != self.state.generation
            || after.task.generation < before.task.generation
            || after.token.sequence < before.token.sequence
            || after.token.session != before.token.session
            || after.token.tid != before.token.tid
            || after.task.task != before.task.task
            || after.task.process != before.task.process
            || after.logical_pc != stored.row.pc
            || matches!(after.phase, StopPhase::SyscallEntry { .. })
        {
            return Err(CensusError::StaleObservation);
        }
        if after.token.sequence == before.token.sequence {
            let mut rebound = before.clone();
            rebound.task.generation = after.task.generation;
            if rebound != after {
                return Err(CensusError::StaleObservation);
            }
        }
        if before == &after {
            self.remaining(token)?;
            return Ok(());
        }
        // History stores both observations, while the separately retained
        // current observation also grows when the new XSTATE payload is larger.
        // A later shrink never refunds the earlier lifetime charge.
        let current_growth = after.xstate.len().saturating_sub(before.xstate.len());
        let bytes = before
            .retained_bytes()
            .checked_add(after.retained_bytes())
            .and_then(|value| value.checked_add(std::mem::size_of::<HistoryRecord>()))
            .and_then(|value| value.checked_add(current_growth))
            .ok_or(CensusError::Capacity)?;
        let (remaining, used) = self.prepare_debit(
            token,
            BudgetCharge {
                witnesses: 1,
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )?;
        self.state.history.push(HistoryRecord::Refreshed {
            origin: id,
            before: before.clone(),
            after: after.clone(),
        });
        self.state.origins[index].current = after;
        self.commit_debit(token, remaining, used);
        Ok(())
    }

    pub(super) fn consume(
        &mut self,
        token: Reservation,
        id: OriginId,
        evidence: OwnerConsumption,
    ) -> Result<(), CensusError> {
        let index = self.active_index(id)?;
        let stored = &self.state.origins[index];
        if matches!(
            stored.row.kind,
            OriginKind::UnknownPersistent { .. } | OriginKind::SignalFrame { .. }
        ) {
            return Err(CensusError::PersistentUnknown);
        }
        if evidence.before != stored.current
            || evidence.before.logical_pc != stored.row.pc
            || evidence.before.task.generation != self.state.generation
        {
            return Err(CensusError::StaleObservation);
        }
        let charge = BudgetCharge {
            witnesses: 1,
            source_fact_bytes: evidence.retained_bytes(),
            ..BudgetCharge::default()
        };
        let (remaining, used) = self.prepare_debit(token, charge)?;
        self.state.history.push(HistoryRecord::Consumed {
            origin: id,
            evidence,
        });
        self.state.origins[index].active = false;
        self.commit_debit(token, remaining, used);
        Ok(())
    }

    /// Physical task removal retires only its register continuation. No saved
    /// memory context or potential CALL return is removed, even at the same PC.
    #[cfg(test)]
    pub(super) fn retire_terminal(
        &mut self,
        token: Reservation,
        id: OriginId,
        evidence: OwnerTerminal,
    ) -> Result<(), CensusError> {
        let index = self.active_index(id)?;
        let stored = &self.state.origins[index];
        if matches!(
            stored.row.kind,
            OriginKind::UnknownPersistent { .. } | OriginKind::SignalFrame { .. }
        ) {
            return Err(CensusError::PersistentUnknown);
        }
        if evidence.before != stored.current
            || evidence.terminal.task.generation != self.state.generation
        {
            return Err(CensusError::StaleObservation);
        }
        let charge = BudgetCharge {
            witnesses: 1,
            source_fact_bytes: evidence.retained_bytes(),
            ..BudgetCharge::default()
        };
        let (remaining, used) = self.prepare_debit(token, charge)?;
        self.state.history.push(HistoryRecord::Terminal {
            origin: id,
            evidence,
        });
        self.state.origins[index].active = false;
        self.commit_debit(token, remaining, used);
        Ok(())
    }

    /// Native invalidation must already be under the owner's release interlock.
    /// This only records its new epoch; old current observations stay stale until
    /// individually refreshed. No active origin/history is erased by rebinding.
    pub(super) fn rebind_epoch(
        &mut self,
        token: Reservation,
        generation: u64,
    ) -> Result<(), CensusError> {
        if self.state.generation.checked_add(1) != Some(generation) {
            return Err(CensusError::GenerationNotAdvanced);
        }
        let charge = BudgetCharge {
            epochs: 1,
            source_fact_bytes: std::mem::size_of::<HistoryRecord>(),
            ..BudgetCharge::default()
        };
        let (remaining, used) = self.prepare_debit(token, charge)?;
        self.state.history.push(HistoryRecord::Epoch {
            before: self.state.generation,
            after: generation,
        });
        self.state.generation = generation;
        self.commit_debit(token, remaining, used);
        Ok(())
    }

    /// A necessary bookkeeping check for a real held owner's route validator.
    /// Success is NOT a native resolution or capability.
    pub(super) fn check_current_origin(
        &self,
        id: OriginId,
        actual: &ObservedStop,
    ) -> Result<&OriginRow, CensusError> {
        let stored = &self.state.origins[self.active_index(id)?];
        if matches!(
            stored.row.kind,
            OriginKind::UnknownPersistent { .. } | OriginKind::SignalFrame { .. }
        ) {
            return Err(CensusError::PersistentUnknown);
        }
        actual.validate(self.session, self.space)?;
        if actual != &stored.current
            || actual.task.generation != self.state.generation
            || actual.logical_pc != stored.row.pc
        {
            return Err(CensusError::StaleObservation);
        }
        Ok(&stored.row)
    }

    /// Complete projection: every ACTIVE origin must be covered by exactly one
    /// supplied image. Distinct origins remain in `origins` even when resumes
    /// deduplicate; omission or overlap refuses instead of hiding an origin.
    pub(super) fn project(&self, images: &[ImageScope]) -> Result<Vec<Projection>, CensusError> {
        if images.len() > self.limits.reports {
            return Err(CensusError::Capacity);
        }
        for (index, image) in images.iter().enumerate() {
            if images[..index]
                .iter()
                .any(|old| old.mapping == image.mapping || old.range.overlaps(image.range))
            {
                return Err(CensusError::OverlappingImages);
            }
        }
        let mut result: Vec<_> = images
            .iter()
            .map(|image| Projection {
                mapping: image.mapping,
                generation: Generation(self.state.generation),
                scope: image.range,
                origins: Vec::new(),
                resumes: BTreeMap::new(),
            })
            .collect();
        for origin in self.active() {
            let image = result
                .iter_mut()
                .find(|image| image.scope.contains(origin.row.pc))
                .ok_or(CensusError::MissingImage)?;
            image.origins.push(origin.row.id);
            image
                .resumes
                .entry(origin.row.pc)
                .or_default()
                .insert(origin.row.kind.resume_kind());
        }
        Ok(result)
    }

    pub(super) fn validate_projection(&self, entries: &[LegalEntrySet]) -> Result<(), CensusError> {
        let scopes: Vec<_> = entries
            .iter()
            .map(|entry| ImageScope {
                mapping: entry.mapping(),
                range: entry.scope(),
            })
            .collect();
        let projection = self.project(&scopes)?;
        if projection.iter().zip(entries).any(|(projected, entry)| {
            projected.generation != entry.generation() || &projected.resumes != entry.resumes()
        }) {
            return Err(CensusError::ProjectionMismatch);
        }
        Ok(())
    }

    fn active_index(&self, id: OriginId) -> Result<usize, CensusError> {
        if id.census != self.identity {
            return Err(CensusError::UnknownOrigin);
        }
        let index = self
            .state
            .origins
            .iter()
            .position(|origin| origin.row.id == id)
            .ok_or(CensusError::UnknownOrigin)?;
        if !self.state.origins[index].active {
            return Err(CensusError::InactiveOrigin);
        }
        Ok(index)
    }

    fn remaining(&self, token: Reservation) -> Result<BudgetCharge, CensusError> {
        self.state
            .reservation
            .filter(|(expected, _)| *expected == token)
            .map(|(_, remaining)| remaining)
            .ok_or(CensusError::StaleReservation)
    }

    fn prepare_debit(
        &self,
        token: Reservation,
        charge: BudgetCharge,
    ) -> Result<(BudgetCharge, BudgetCharge), CensusError> {
        Ok((
            self.remaining(token)?.subtract(charge)?,
            self.state.used.add(charge)?,
        ))
    }

    fn commit_debit(&mut self, token: Reservation, remaining: BudgetCharge, used: BudgetCharge) {
        self.state.reservation = Some((token, remaining));
        self.state.used = used;
    }
}

#[cfg(test)]
mod tests;
