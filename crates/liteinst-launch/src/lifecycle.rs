//! Bounded lifecycle bookkeeping for a future native execution owner.
//!
//! Every input is an event the controller must independently authenticate. This
//! module neither traces tasks nor excludes instruction fetches, kernel writers,
//! aliases, or saved contexts. An [`ExclusionCandidate`] is only a consistent
//! registry snapshot; it is deliberately not a core quiescence lease.
//! Terminal records and continuation obligations are retained for audit. No
//! transition here authorizes freeing mappings or forgetting a saved return.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use liteinst_admission::entries::ResumeKind;

static NEXT_REGISTRY: AtomicU64 = AtomicU64::new(1);
const MAX_RECORDS: usize = 65_536;
const MAX_OBLIGATIONS: usize = 1_048_576;
const CLONE_VM: u64 = 0x100;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_VFORK: u64 = 0x4000;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_UNTRACED: u64 = 0x800000;
const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;
const KNOWN_CLONE_FLAGS: u64 = 0x3ffffff00;

macro_rules! identity {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
        pub struct $name {
            registry: u64,
            serial: u64,
        }
        impl $name {
            /// Registry-local serial; IDs also contain a non-reused registry identity.
            pub fn serial(self) -> u64 {
                self.serial
            }
        }
    };
}
identity!(
    TaskId,
    "One task incarnation, distinct even when a numeric TID is reused."
);
identity!(
    ProcessId,
    "One thread-group lifetime; exec preserves this identity."
);
identity!(
    AddressSpaceId,
    "One mm incarnation; exec always creates a fresh identity."
);
identity!(
    ObligationId,
    "One retained signal or saved-context obligation."
);

/// Lifetime storage budgets, including terminal and superseded records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum task incarnations, including terminal tasks.
    pub tasks: usize,
    /// Maximum process incarnations.
    pub processes: usize,
    /// Maximum address-space incarnations, including replaced images.
    pub address_spaces: usize,
    /// Maximum original and inherited obligation records.
    pub obligations: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            tasks: 4096,
            processes: 1024,
            address_spaces: 4096,
            obligations: 65_536,
        }
    }
}

/// A bookkeeping refusal. No error changes the registry snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// A zero or excessive configured storage budget.
    InvalidLimits,
    /// Nonpositive or conflicting numeric task identity.
    InvalidTid,
    /// An ID does not belong to this registry or is unknown.
    UnknownIdentity,
    /// An event sequence, private ticket, or candidate has become stale.
    Stale,
    /// An event is incompatible with the task's current phase.
    WrongState,
    /// A storage or monotonic-identity bound would be exceeded.
    Exhausted,
    /// Unknown/untraced clone flags or inconsistent sharing semantics.
    UnsupportedClone,
    /// Kernel event kind, identities, or syscall result differ from the intent.
    EventMismatch,
    /// A vfork parent cannot run while its child still uses the shared mm.
    VforkBlocked,
    /// At least one member of the address space is not held.
    NotHeld,
    /// The mm has no remaining live tasks.
    NoLiveTasks,
    /// An invalidation transaction already excludes application release.
    Invalidating,
    /// A poisoned address space cannot resume or yield another candidate.
    Poisoned,
    /// Invalid signal number or saved-context address.
    InvalidObligation,
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lifecycle bookkeeping refused: {self:?}")
    }
}
impl std::error::Error for LifecycleError {}

/// Why an authenticated task stop is held.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldReason {
    /// First user entry following a checked exec transition.
    Exec,
    /// Authenticated initial exec syscall exit, before the kernel user return.
    ExecSyscallExit,
    /// Automatic ptrace stop before a newborn task can execute.
    Newborn,
    /// An active controller interruption, not an application signal delivery.
    Interrupt,
    /// Kernel syscall entry.
    SyscallEntry,
    /// Kernel syscall exit.
    SyscallExit,
    /// Application signal delivery; full siginfo remains the controller's duty.
    Signal,
    /// An authenticated instrumentation stop.
    OwnedTrap,
    /// Kernel task-creation event.
    Creation,
    /// Kernel vfork-done event.
    VforkDone,
    /// Authenticated job-control group stop, without signal-queue provenance.
    GroupStop,
    /// Authenticated end of a group stop after LISTEN.
    GroupContinued,
}

/// Terminal identity transition; this enum is not an OS reaping receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReason {
    /// A consumed kernel terminal wait status.
    Exit(ExitStatus),
    /// Exec replaced this task incarnation, possibly also its numeric TID.
    ExecReplaced,
}

/// A native task's terminal wait outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitStatus {
    /// Normal exit status, in the kernel's eight-bit range.
    Code(u8),
    /// Terminating signal; validated as 1 through 64.
    Signal(u8),
}

/// Execution ownership recorded for one incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    /// Owned creation event seen, but the child's automatic stop is not yet seen.
    Newborn,
    /// An authenticated stop with its actual original or controller PC.
    Held {
        /// Stopped PC, not a promise of an instruction-head census.
        pc: u64,
        /// Stop classification supplied by the native controller.
        reason: HoldReason,
    },
    /// The controller has released this task.
    Running,
    /// No longer executing; native cleanup obligations remain external.
    Terminal(TerminalReason),
}

/// Event that minted one task incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskOrigin {
    /// Initial checked first-user checkpoint.
    Initial,
    /// Initial authenticated exec syscall exit; user return has not occurred.
    InitialExecSyscallExit,
    /// A checked creation event from a particular parent incarnation.
    Created {
        /// Creating task, retained even after it exits.
        parent: TaskId,
        /// Exact creation syscall and flags.
        request: CreationRequest,
    },
    /// Successful exec replaced the prior incarnation.
    Exec {
        /// Prior execing task, possibly with a different numeric TID.
        previous: TaskId,
    },
}

/// Read-only task record. Sequence numbers count kernel events, not resumes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRecord {
    /// Non-reused task identity.
    pub id: TaskId,
    /// Numeric TID at this incarnation; terminal values must not be signalled.
    pub tid: i32,
    /// Owning thread-group lifetime.
    pub process: ProcessId,
    /// Current address-space incarnation.
    pub address_space: AddressSpaceId,
    /// Latest authenticated event sequence.
    pub sequence: u64,
    /// Current recorded execution state.
    pub state: TaskState,
    /// Exact identity-producing event.
    pub origin: TaskOrigin,
    syscall_open: bool,
    pending: Option<Pending>,
}

/// A retained address-space generation, independent of page dependency tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressSpaceRecord {
    /// Non-reused mm identity.
    pub id: AddressSpaceId,
    /// Monotonic invalidation epoch; a new mm starts at zero.
    pub generation: u64,
    /// A failed/uncertain native transaction must permanently close release.
    pub poisoned: bool,
    /// Checked event creating this mm and its source generation, when copied.
    pub origin: AddressSpaceOrigin,
    invalidation: Option<InvalidationTicket>,
}

/// Source of a new address-space incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceOrigin {
    /// Initial execution domain.
    Initial,
    /// Copied mm, with the parent's generation frozen at the fork event.
    Fork {
        /// Original mm; a copied mm is never silently treated as shared.
        parent: AddressSpaceId,
        /// Parent generation when the kernel copied it.
        generation: u64,
    },
    /// Exec replaced a previous image; old records remain retained.
    Exec {
        /// The execing task's previous mm.
        previous: AddressSpaceId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessRecord {
    tgid: i32,
}

/// Native creation syscall whose entry was independently checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreationRequest {
    /// Linux fork: a new process and a copied mm.
    Fork,
    /// Linux vfork: a new process temporarily sharing the parent's mm.
    Vfork,
    /// Linux clone; low eight bits contain the exit signal.
    Clone {
        /// Exact checked syscall flags, including its low-byte exit signal.
        flags: u64,
    },
    /// Linux clone3; flag and exit-signal fields are separate.
    Clone3 {
        /// Exact checked clone_args flags.
        flags: u64,
        /// Exact checked clone_args exit_signal.
        exit_signal: u32,
    },
}

/// Which authenticated ptrace creation event must match the syscall intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreationEventKind {
    /// PTRACE_EVENT_FORK.
    Fork,
    /// PTRACE_EVENT_VFORK.
    Vfork,
    /// PTRACE_EVENT_CLONE.
    Clone,
}

#[derive(Clone, Copy)]
struct Sharing {
    vm: bool,
    thread: bool,
    vfork: bool,
    event: CreationEventKind,
}

impl CreationRequest {
    fn sharing(self) -> Result<Sharing, LifecycleError> {
        let (flags, signal) = match self {
            Self::Fork => (0, 17),
            Self::Vfork => (CLONE_VM | CLONE_VFORK, 17),
            Self::Clone { flags } => (flags & !0xff, (flags & 0xff) as u32),
            Self::Clone3 { flags, exit_signal } => {
                // CLONE_NEWTIME occupies 0x80 only in clone3's separate flags.
                if flags & 0x7f != 0 {
                    return Err(LifecycleError::UnsupportedClone);
                }
                (flags & !0x80, exit_signal)
            }
        };
        if signal > 64
            || flags & !KNOWN_CLONE_FLAGS != 0
            || flags & CLONE_UNTRACED != 0
            || (flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0)
            || (flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0)
            || (flags & CLONE_CLEAR_SIGHAND != 0 && flags & CLONE_SIGHAND != 0)
        {
            return Err(LifecycleError::UnsupportedClone);
        }
        Ok(Sharing {
            vm: flags & CLONE_VM != 0,
            thread: flags & CLONE_THREAD != 0,
            vfork: flags & CLONE_VFORK != 0,
            event: if flags & CLONE_VFORK != 0 {
                CreationEventKind::Vfork
            } else if signal == 17 {
                CreationEventKind::Fork
            } else {
                CreationEventKind::Clone
            },
        })
    }
}

/// A single checked creation intent; private fields prevent fabrication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreationTicket {
    task: TaskId,
    nonce: u64,
    request: CreationRequest,
}

/// Kernel facts accompanying a creation event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreationEvent {
    /// Actual ptrace event classification.
    pub kind: CreationEventKind,
    /// Child TID in the controller's PID namespace.
    pub child_tid: i32,
    /// Child TGID in the controller's PID namespace.
    pub child_tgid: i32,
    /// Child ID returned in the parent's namespace, independently authenticated.
    pub parent_visible_tid: i32,
    /// Parent PC at the creation event.
    pub parent_pc: u64,
}

/// A single checked exec intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecTicket {
    task: TaskId,
    nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Pending {
    Creation {
        ticket: CreationTicket,
        child: Option<TaskId>,
        return_tid: i32,
        vfork_done: bool,
    },
    Exec(ExecTicket),
}

/// Kernel signal queue to which a pending delivery belongs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalScope {
    /// Queue provenance is unavailable. Retain conservatively across exec; this
    /// obligation must never be treated as a classified or discharged queue.
    Unknown,
    /// Per-thread pending delivery, preserved only for the execing task.
    Task,
    /// Process-directed pending delivery, preserved across exec.
    Process,
}

/// Authenticated signal-delivery facts needed by the lifecycle ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalEvent {
    /// Actual stopped PC.
    pub pc: u64,
    /// Signal number, 1 through 64.
    pub signal: u8,
    /// Exact signal code.
    pub code: i32,
    /// Independently authenticated queue, or Unknown when unavailable.
    pub scope: SignalScope,
}

/// A retained obligation, not an assertion that the list is exhaustive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObligationKind {
    /// Pending kernel signal; fork does not inherit pending signal queues.
    PendingSignal {
        /// Signal number, 1 through 64.
        signal: u8,
        /// Exact observed signal code; full siginfo remains externally owned.
        code: i32,
        /// Whether exec preserves the creating task's or process's queue.
        scope: SignalScope,
    },
    /// One authenticated saved context, conservatively retained across forks.
    SavedResume {
        /// Original saved continuation address.
        pc: u64,
        /// Existing admission-layer provenance classification.
        kind: ResumeKind,
    },
}

/// An immutable original or inherited obligation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObligationRecord {
    /// Non-reused obligation identity.
    pub id: ObligationId,
    /// Task incarnation owning this record.
    pub task: TaskId,
    /// Address-space incarnation to which the obligation belongs.
    pub address_space: AddressSpaceId,
    /// Signal or saved-context facts.
    pub kind: ObligationKind,
    /// Source record when fork or exec conservatively transferred a fact.
    pub inherited_from: Option<ObligationId>,
}

/// Consistent held-membership bookkeeping, never an executable capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExclusionCandidate {
    registry: u64,
    revision: u64,
    /// Address space being considered.
    pub address_space: AddressSpaceId,
    /// Exact generation at the snapshot.
    pub generation: u64,
    /// Every currently live task sharing this mm, including other TGIDs.
    pub tasks: Vec<TaskId>,
    /// Retained obligations still needing the publisher's independent proof.
    pub obligations: Vec<ObligationRecord>,
}

/// One mm generation transition. Completion does not admit any executable page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidationTicket {
    registry: u64,
    nonce: u64,
    /// Address space whose execution must remain excluded by the native owner.
    pub address_space: AddressSpaceId,
    /// Invalidated old generation.
    pub previous_generation: u64,
    /// New, still uncertified generation.
    pub generation: u64,
    tasks: Vec<TaskId>,
}

/// Result of an exec identity transition, not a cleanup or publication receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecTransition {
    /// Fresh task incarnation at the exec stop.
    pub task: TaskId,
    /// Fresh mm, initially generation zero.
    pub address_space: AddressSpaceId,
    /// Old thread identities; terminal records and obligations remain retained.
    pub superseded: Vec<TaskId>,
}

/// Equality-comparable audit snapshot. It cannot be restored into a registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrySnapshot {
    registry: u64,
    revision: u64,
    next_id: u64,
    limits: Limits,
    root: TaskId,
    tasks: BTreeMap<TaskId, TaskRecord>,
    tids: BTreeMap<i32, TaskId>,
    processes: BTreeMap<ProcessId, ProcessRecord>,
    spaces: BTreeMap<AddressSpaceId, AddressSpaceRecord>,
    obligations: BTreeMap<ObligationId, ObligationRecord>,
}

/// Single-owner, bounded event registry with transactional error handling.
///
/// It is a model of authenticated events, not their authenticator. In particular
/// it does not justify a ptrace operation on a raw TID, establish an exhaustive
/// saved-PC census, or satisfy a core lease by itself.
pub struct LifecycleRegistry {
    state: RegistrySnapshot,
}

impl LifecycleRegistry {
    /// Starts with one held leader after authenticated exec completion and the
    /// first-user transition, before any original application instruction.
    pub fn new(limits: Limits, leader_tid: i32, entry_pc: u64) -> Result<Self, LifecycleError> {
        Self::initialize(
            limits,
            leader_tid,
            entry_pc,
            HoldReason::Exec,
            TaskOrigin::Initial,
        )
    }

    /// Starts at an authenticated initial exec syscall-exit stop. This is before
    /// the actual kernel return to user mode; neither stable first-user XSTATE
    /// nor execution permission is inferred. The original earlier exec event is
    /// not relabelled. This constructor supplies bookkeeping only.
    pub fn new_after_exec_syscall_exit(
        limits: Limits,
        leader_tid: i32,
        entry_pc: u64,
    ) -> Result<Self, LifecycleError> {
        Self::initialize(
            limits,
            leader_tid,
            entry_pc,
            HoldReason::ExecSyscallExit,
            TaskOrigin::InitialExecSyscallExit,
        )
    }

    fn initialize(
        limits: Limits,
        leader_tid: i32,
        entry_pc: u64,
        initial_reason: HoldReason,
        initial_origin: TaskOrigin,
    ) -> Result<Self, LifecycleError> {
        if [limits.tasks, limits.processes, limits.address_spaces]
            .into_iter()
            .any(|limit| limit == 0 || limit > MAX_RECORDS)
            || limits.obligations == 0
            || limits.obligations > MAX_OBLIGATIONS
        {
            return Err(LifecycleError::InvalidLimits);
        }
        if leader_tid <= 0 {
            return Err(LifecycleError::InvalidTid);
        }
        let registry = NEXT_REGISTRY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| LifecycleError::Exhausted)?;
        let task = TaskId {
            registry,
            serial: 1,
        };
        let process = ProcessId {
            registry,
            serial: 2,
        };
        let space = AddressSpaceId {
            registry,
            serial: 3,
        };
        Ok(Self {
            state: RegistrySnapshot {
                registry,
                revision: 0,
                next_id: 4,
                limits,
                root: task,
                tasks: BTreeMap::from([(
                    task,
                    TaskRecord {
                        id: task,
                        tid: leader_tid,
                        process,
                        address_space: space,
                        sequence: 0,
                        state: TaskState::Held {
                            pc: entry_pc,
                            reason: initial_reason,
                        },
                        origin: initial_origin,
                        syscall_open: false,
                        pending: None,
                    },
                )]),
                tids: BTreeMap::from([(leader_tid, task)]),
                processes: BTreeMap::from([(process, ProcessRecord { tgid: leader_tid })]),
                spaces: BTreeMap::from([(
                    space,
                    AddressSpaceRecord {
                        id: space,
                        generation: 0,
                        poisoned: false,
                        origin: AddressSpaceOrigin::Initial,
                        invalidation: None,
                    },
                )]),
                obligations: BTreeMap::new(),
            },
        })
    }

    /// Initial task identity, retained even after exec or exit.
    pub fn root_task(&self) -> TaskId {
        self.state.root
    }

    /// Returns a retained task record without exposing mutation.
    pub fn task(&self, task: TaskId) -> Result<&TaskRecord, LifecycleError> {
        self.state
            .tasks
            .get(&task)
            .ok_or(LifecycleError::UnknownIdentity)
    }

    /// Looks up a currently live numeric TID. Old terminal IDs are never reused.
    pub fn task_for_tid(&self, tid: i32) -> Option<TaskId> {
        self.state.tids.get(&tid).copied()
    }

    /// Returns a retained mm generation record.
    pub fn address_space(
        &self,
        space: AddressSpaceId,
    ) -> Result<&AddressSpaceRecord, LifecycleError> {
        self.state
            .spaces
            .get(&space)
            .ok_or(LifecycleError::UnknownIdentity)
    }

    /// Captures every field for auditing rollback and event ordering.
    pub fn snapshot(&self) -> RegistrySnapshot {
        self.state.clone()
    }

    /// All original and inherited obligations; none is silently drained.
    pub fn obligations(&self) -> impl Iterator<Item = &ObligationRecord> {
        self.state.obligations.values()
    }

    fn transaction<T>(
        &mut self,
        action: impl FnOnce(&mut RegistrySnapshot) -> Result<T, LifecycleError>,
    ) -> Result<T, LifecycleError> {
        // Staging is bounded by Limits. No fallible transition can partly consume
        // an event, incarnation ID, signal obligation, or invalidation ticket.
        let mut next = self.state.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(LifecycleError::Exhausted)?;
        let value = action(&mut next)?;
        self.state = next;
        Ok(value)
    }

    /// Records release of one held incarnation after native controller checks.
    /// Pending signal/return records remain retained; release is not a drain proof.
    pub fn resume(&mut self, task: TaskId, expected_sequence: u64) -> Result<(), LifecycleError> {
        self.transaction(|state| {
            let record = state.task(task)?;
            if record.sequence != expected_sequence {
                return Err(LifecycleError::Stale);
            }
            if !matches!(record.state, TaskState::Held { .. }) {
                return Err(LifecycleError::WrongState);
            }
            state.releasable(record.address_space)?;
            if let Some(Pending::Creation {
                ticket,
                child: Some(child),
                ..
            }) = record.pending
            {
                if ticket.request.sharing()?.vfork
                    && !matches!(state.task(child)?.state, TaskState::Terminal(_))
                {
                    return Err(LifecycleError::VforkBlocked);
                }
            }
            state.tasks.get_mut(&task).unwrap().state = TaskState::Running;
            Ok(())
        })
    }

    /// Records an ordinary stop. Creation/exec/newborn transitions use their
    /// dedicated methods so they cannot be relabelled as generic stops.
    pub fn observe_stop(
        &mut self,
        task: TaskId,
        sequence: u64,
        pc: u64,
        reason: HoldReason,
    ) -> Result<(), LifecycleError> {
        self.transaction(|state| {
            if !matches!(
                reason,
                HoldReason::Interrupt
                    | HoldReason::SyscallEntry
                    | HoldReason::SyscallExit
                    | HoldReason::OwnedTrap
                    | HoldReason::GroupStop
                    | HoldReason::GroupContinued
            ) {
                return Err(LifecycleError::EventMismatch);
            }
            let record = state.running(task, sequence)?;
            if record.pending.is_some()
                && matches!(reason, HoldReason::SyscallEntry | HoldReason::SyscallExit)
            {
                return Err(LifecycleError::EventMismatch);
            }
            if (reason == HoldReason::SyscallEntry && record.syscall_open)
                || (reason == HoldReason::SyscallExit && !record.syscall_open)
            {
                return Err(LifecycleError::EventMismatch);
            }
            state.hold(task, sequence, pc, reason);
            if matches!(reason, HoldReason::SyscallEntry | HoldReason::SyscallExit) {
                state.tasks.get_mut(&task).unwrap().syscall_open =
                    reason == HoldReason::SyscallEntry;
            }
            Ok(())
        })
    }

    /// Atomically records an application signal stop and its retained delivery
    /// obligation. Signal stops cannot enter through the generic stop method.
    pub fn observe_signal(
        &mut self,
        task: TaskId,
        sequence: u64,
        event: SignalEvent,
    ) -> Result<ObligationId, LifecycleError> {
        self.transaction(|state| {
            let record = state.running(task, sequence)?;
            if !(1..=64).contains(&event.signal) {
                return Err(LifecycleError::InvalidObligation);
            }
            let id = state.add_obligation(
                task,
                record.address_space,
                ObligationKind::PendingSignal {
                    signal: event.signal,
                    code: event.code,
                    scope: event.scope,
                },
                None,
            )?;
            state.hold(task, sequence, event.pc, HoldReason::Signal);
            Ok(id)
        })
    }

    /// Binds an exact creation request to the parent's current syscall-entry stop.
    pub fn prepare_creation(
        &mut self,
        parent: TaskId,
        request: CreationRequest,
    ) -> Result<CreationTicket, LifecycleError> {
        self.transaction(|state| {
            request.sharing()?;
            state.ready_intent(parent)?;
            let ticket = CreationTicket {
                task: parent,
                nonce: state.allocate()?,
                request,
            };
            state.tasks.get_mut(&parent).unwrap().pending = Some(Pending::Creation {
                ticket,
                child: None,
                return_tid: 0,
                vfork_done: false,
            });
            Ok(ticket)
        })
    }

    /// Registers ownership before a newborn is permitted to run. Namespace
    /// translations and ptrace event payloads must be authenticated externally.
    pub fn observe_creation(
        &mut self,
        ticket: CreationTicket,
        sequence: u64,
        event: CreationEvent,
    ) -> Result<TaskId, LifecycleError> {
        self.transaction(|state| {
            let parent = state.running(ticket.task, sequence)?.clone();
            if parent.pending
                != Some(Pending::Creation {
                    ticket,
                    child: None,
                    return_tid: 0,
                    vfork_done: false,
                })
            {
                return Err(LifecycleError::Stale);
            }
            let sharing = ticket.request.sharing()?;
            if event.kind != sharing.event
                || event.child_tid <= 0
                || event.parent_visible_tid <= 0
                || state.tids.contains_key(&event.child_tid)
            {
                return Err(LifecycleError::EventMismatch);
            }
            if state.processes.iter().any(|(id, process)| {
                process.tgid == event.child_tid
                    && state.tasks.values().any(|task| {
                        task.process == *id && !matches!(task.state, TaskState::Terminal(_))
                    })
            }) {
                return Err(LifecycleError::EventMismatch);
            }
            let tgid = state.processes[&parent.process].tgid;
            if event.child_tgid
                != if sharing.thread {
                    tgid
                } else {
                    event.child_tid
                }
            {
                return Err(LifecycleError::EventMismatch);
            }
            if state.tasks.len() == state.limits.tasks {
                return Err(LifecycleError::Exhausted);
            }
            let process = if sharing.thread {
                parent.process
            } else {
                state.new_process(event.child_tgid)?
            };
            let space = if sharing.vm {
                parent.address_space
            } else {
                state.new_space(AddressSpaceOrigin::Fork {
                    parent: parent.address_space,
                    generation: state.spaces[&parent.address_space].generation,
                })?
            };
            let child = TaskId {
                registry: state.registry,
                serial: state.allocate()?,
            };
            if !sharing.vm {
                let inherited: Vec<_> = state
                    .obligations
                    .values()
                    .filter(|record| {
                        record.address_space == parent.address_space
                            && matches!(record.kind, ObligationKind::SavedResume { .. })
                    })
                    .cloned()
                    .collect();
                for record in inherited {
                    state.add_obligation(child, space, record.kind, Some(record.id))?;
                }
            }
            state.tasks.insert(
                child,
                TaskRecord {
                    id: child,
                    tid: event.child_tid,
                    process,
                    address_space: space,
                    sequence: 0,
                    state: TaskState::Newborn,
                    origin: TaskOrigin::Created {
                        parent: parent.id,
                        request: ticket.request,
                    },
                    syscall_open: true,
                    pending: None,
                },
            );
            state.tids.insert(event.child_tid, child);
            state.hold(ticket.task, sequence, event.parent_pc, HoldReason::Creation);
            state.tasks.get_mut(&ticket.task).unwrap().pending = Some(Pending::Creation {
                ticket,
                child: Some(child),
                return_tid: event.parent_visible_tid,
                vfork_done: false,
            });
            Ok(child)
        })
    }

    /// Authenticates the first stopped state of a registered newborn incarnation.
    pub fn observe_newborn_stop(
        &mut self,
        task: TaskId,
        sequence: u64,
        pc: u64,
    ) -> Result<(), LifecycleError> {
        self.transaction(|state| {
            let record = state.task(task)?;
            if record.state != TaskState::Newborn || sequence != 1 {
                return Err(LifecycleError::WrongState);
            }
            state.hold(task, sequence, pc, HoldReason::Newborn);
            Ok(())
        })
    }

    /// Records the actual parent vfork-done event after child exec or exit.
    pub fn observe_vfork_done(
        &mut self,
        ticket: CreationTicket,
        sequence: u64,
        child: TaskId,
        pc: u64,
    ) -> Result<(), LifecycleError> {
        self.transaction(|state| {
            let parent = state.running(ticket.task, sequence)?;
            let Some(Pending::Creation {
                ticket: expected,
                child: Some(expected_child),
                return_tid,
                vfork_done: false,
            }) = parent.pending
            else {
                return Err(LifecycleError::WrongState);
            };
            if ticket != expected
                || child != expected_child
                || !ticket.request.sharing()?.vfork
                || !matches!(state.task(child)?.state, TaskState::Terminal(_))
            {
                return Err(LifecycleError::EventMismatch);
            }
            state.hold(ticket.task, sequence, pc, HoldReason::VforkDone);
            state.tasks.get_mut(&ticket.task).unwrap().pending = Some(Pending::Creation {
                ticket,
                child: Some(child),
                return_tid,
                vfork_done: true,
            });
            Ok(())
        })
    }

    /// Completes creation with its exact parent return, or an errno with no child.
    pub fn observe_creation_exit(
        &mut self,
        ticket: CreationTicket,
        sequence: u64,
        pc: u64,
        result: i64,
    ) -> Result<(), LifecycleError> {
        self.transaction(|state| {
            let parent = state.running(ticket.task, sequence)?;
            let Some(Pending::Creation {
                ticket: expected,
                child,
                return_tid,
                vfork_done,
            }) = parent.pending
            else {
                return Err(LifecycleError::WrongState);
            };
            if ticket != expected {
                return Err(LifecycleError::Stale);
            }
            if child.is_some() {
                if result != i64::from(return_tid)
                    || (ticket.request.sharing()?.vfork && !vfork_done)
                {
                    return Err(LifecycleError::EventMismatch);
                }
            } else if !(-4095..=-1).contains(&result) {
                return Err(LifecycleError::EventMismatch);
            }
            state.hold(ticket.task, sequence, pc, HoldReason::SyscallExit);
            let task = state.tasks.get_mut(&ticket.task).unwrap();
            task.pending = None;
            task.syscall_open = false;
            Ok(())
        })
    }

    /// Binds one exec request to an actual syscall-entry stop.
    pub fn prepare_exec(&mut self, task: TaskId) -> Result<ExecTicket, LifecycleError> {
        self.transaction(|state| {
            state.ready_intent(task)?;
            let ticket = ExecTicket {
                task,
                nonce: state.allocate()?,
            };
            state.tasks.get_mut(&task).unwrap().pending = Some(Pending::Exec(ticket));
            Ok(ticket)
        })
    }

    /// Records failed exec without changing task/mm identities or obligations.
    pub fn observe_exec_failure(
        &mut self,
        ticket: ExecTicket,
        sequence: u64,
        pc: u64,
        errno_result: i64,
    ) -> Result<(), LifecycleError> {
        self.transaction(|state| {
            let task = state.running(ticket.task, sequence)?;
            if task.pending != Some(Pending::Exec(ticket)) {
                return Err(LifecycleError::Stale);
            }
            if !(-4095..=-1).contains(&errno_result) {
                return Err(LifecycleError::EventMismatch);
            }
            state.hold(ticket.task, sequence, pc, HoldReason::SyscallExit);
            let task = state.tasks.get_mut(&ticket.task).unwrap();
            task.pending = None;
            task.syscall_open = false;
            Ok(())
        })
    }

    /// Commits an authenticated successful exec, including nonleader TID rebasing.
    ///
    /// The controller must authenticate the exec event and its former-TID payload,
    /// and own cleanup of all superseded threads. Supersession is not a claim
    /// that terminal wait statuses were reaped. Pending signals survive according
    /// to their queue scope; old saved resumes remain in the old-mm audit record.
    pub fn observe_exec(
        &mut self,
        ticket: ExecTicket,
        sequence: u64,
        former_tid: i32,
        new_tid: i32,
        pc: u64,
    ) -> Result<ExecTransition, LifecycleError> {
        self.transaction(|state| {
            let old = state.running(ticket.task, sequence)?.clone();
            if old.pending != Some(Pending::Exec(ticket)) {
                return Err(LifecycleError::Stale);
            }
            if old.tid != former_tid || state.processes[&old.process].tgid != new_tid {
                return Err(LifecycleError::EventMismatch);
            }
            if state
                .tids
                .get(&new_tid)
                .is_some_and(|id| state.tasks[id].process != old.process)
            {
                return Err(LifecycleError::EventMismatch);
            }
            if state.tasks.len() == state.limits.tasks {
                return Err(LifecycleError::Exhausted);
            }
            let space = state.new_space(AddressSpaceOrigin::Exec {
                previous: old.address_space,
            })?;
            let task = TaskId {
                registry: state.registry,
                serial: state.allocate()?,
            };
            let superseded: Vec<_> = state
                .tasks
                .values()
                .filter(|record| {
                    record.process == old.process && !matches!(record.state, TaskState::Terminal(_))
                })
                .map(|record| record.id)
                .collect();
            let inherited: Vec<_> = state
                .obligations
                .values()
                .filter(|record| {
                    record.address_space == old.address_space
                        && state.tasks[&record.task].process == old.process
                        && match record.kind {
                            ObligationKind::PendingSignal {
                                scope: SignalScope::Unknown,
                                ..
                            } => true,
                            ObligationKind::PendingSignal {
                                scope: SignalScope::Process,
                                ..
                            } => true,
                            ObligationKind::PendingSignal {
                                scope: SignalScope::Task,
                                ..
                            } => record.task == old.id,
                            ObligationKind::SavedResume { .. } => false,
                        }
                })
                .cloned()
                .collect();
            for record in inherited {
                state.add_obligation(task, space, record.kind, Some(record.id))?;
            }
            for id in &superseded {
                let record = state.tasks.get_mut(id).unwrap();
                state.tids.remove(&record.tid);
                record.state = TaskState::Terminal(TerminalReason::ExecReplaced);
            }
            state.tasks.get_mut(&old.id).unwrap().sequence = sequence;
            state.tasks.insert(
                task,
                TaskRecord {
                    id: task,
                    tid: new_tid,
                    process: old.process,
                    address_space: space,
                    sequence: 0,
                    state: TaskState::Held {
                        pc,
                        reason: HoldReason::Exec,
                    },
                    origin: TaskOrigin::Exec { previous: old.id },
                    syscall_open: true,
                    pending: None,
                },
            );
            state.tids.insert(new_tid, task);
            Ok(ExecTransition {
                task,
                address_space: space,
                superseded,
            })
        })
    }

    /// Records one terminal wait event. It never deletes old identity or context
    /// records; a later reused numeric TID must receive a fresh incarnation.
    pub fn observe_exit(
        &mut self,
        task: TaskId,
        sequence: u64,
        status: ExitStatus,
    ) -> Result<(), LifecycleError> {
        self.transaction(|state| {
            let record = state.task(task)?;
            state.sequence(record, sequence)?;
            if matches!(record.state, TaskState::Terminal(_)) {
                return Err(LifecycleError::WrongState);
            }
            if matches!(status, ExitStatus::Signal(signal) if !(1..=64).contains(&signal)) {
                return Err(LifecycleError::EventMismatch);
            }
            let tid = record.tid;
            let record = state.tasks.get_mut(&task).unwrap();
            record.sequence = sequence;
            record.state = TaskState::Terminal(TerminalReason::Exit(status));
            state.tids.remove(&tid);
            Ok(())
        })
    }

    /// Retains a signal or saved context under a held task. This does not assert
    /// completeness; a native owner must track full signal data and actual frames.
    pub fn record_obligation(
        &mut self,
        task: TaskId,
        kind: ObligationKind,
    ) -> Result<ObligationId, LifecycleError> {
        self.transaction(|state| {
            let record = state.task(task)?;
            if !matches!(record.state, TaskState::Held { .. }) {
                return Err(LifecycleError::NotHeld);
            }
            match kind {
                ObligationKind::PendingSignal { signal, .. } if !(1..=64).contains(&signal) => {
                    return Err(LifecycleError::InvalidObligation);
                }
                ObligationKind::SavedResume { pc: 0, .. } => {
                    return Err(LifecycleError::InvalidObligation);
                }
                _ => {}
            }
            state.add_obligation(task, record.address_space, kind, None)
        })
    }

    /// Snapshots all held mm members and retained contexts. Native exclusion,
    /// writer control and continuation routing must still be independently proved.
    pub fn exclusion_candidate(
        &self,
        space: AddressSpaceId,
        generation: u64,
    ) -> Result<ExclusionCandidate, LifecycleError> {
        self.state.releasable(space)?;
        if self.address_space(space)?.generation != generation {
            return Err(LifecycleError::Stale);
        }
        Ok(ExclusionCandidate {
            registry: self.state.registry,
            revision: self.state.revision,
            address_space: space,
            generation,
            tasks: self.state.held_tasks(space)?,
            obligations: self
                .obligations()
                .filter(|record| record.address_space == space)
                .cloned()
                .collect(),
        })
    }

    /// Rejects candidates after any registry mutation, including unrelated events.
    pub fn validate_candidate(&self, candidate: &ExclusionCandidate) -> Result<(), LifecycleError> {
        if candidate.registry != self.state.registry
            || candidate.revision != self.state.revision
            || self.exclusion_candidate(candidate.address_space, candidate.generation)?
                != *candidate
        {
            return Err(LifecycleError::Stale);
        }
        Ok(())
    }

    /// Advances the mm generation and blocks recorded application release.
    /// The native owner must revoke execution/dependencies before allowing writes.
    pub fn begin_invalidation(
        &mut self,
        candidate: &ExclusionCandidate,
    ) -> Result<InvalidationTicket, LifecycleError> {
        self.validate_candidate(candidate)?;
        self.transaction(|state| {
            let generation = candidate
                .generation
                .checked_add(1)
                .ok_or(LifecycleError::Exhausted)?;
            let ticket = InvalidationTicket {
                registry: state.registry,
                nonce: state.allocate()?,
                address_space: candidate.address_space,
                previous_generation: candidate.generation,
                generation,
                tasks: candidate.tasks.clone(),
            };
            let space = state.spaces.get_mut(&candidate.address_space).unwrap();
            space.generation = generation;
            space.invalidation = Some(ticket.clone());
            Ok(ticket)
        })
    }

    /// Completes bookkeeping for a new uncertified generation. This is neither
    /// page admission nor permission to retire routes or saved contexts.
    pub fn finish_invalidation(
        &mut self,
        ticket: &InvalidationTicket,
    ) -> Result<(), LifecycleError> {
        self.transaction(|state| {
            let space = state
                .spaces
                .get(&ticket.address_space)
                .ok_or(LifecycleError::UnknownIdentity)?;
            if space.poisoned {
                return Err(LifecycleError::Poisoned);
            }
            if ticket.registry != state.registry || space.invalidation.as_ref() != Some(ticket) {
                return Err(LifecycleError::Stale);
            }
            if state.held_tasks(ticket.address_space)? != ticket.tasks {
                return Err(LifecycleError::Stale);
            }
            state
                .spaces
                .get_mut(&ticket.address_space)
                .unwrap()
                .invalidation = None;
            Ok(())
        })
    }

    /// Permanently blocks mm release after an uncertain native operation.
    /// Exit observations and external owned cleanup remain possible.
    pub fn poison(&mut self, space: AddressSpaceId) -> Result<(), LifecycleError> {
        self.transaction(|state| {
            let space = state
                .spaces
                .get_mut(&space)
                .ok_or(LifecycleError::UnknownIdentity)?;
            if space.poisoned {
                return Err(LifecycleError::Poisoned);
            }
            space.poisoned = true;
            Ok(())
        })
    }
}

impl RegistrySnapshot {
    /// Retained task incarnations, including terminal records.
    pub fn tasks(&self) -> impl Iterator<Item = &TaskRecord> {
        self.tasks.values()
    }
    /// Retained address-space identities; no admission authority is implied.
    pub fn address_spaces(&self) -> impl Iterator<Item = &AddressSpaceRecord> {
        self.spaces.values()
    }
    fn allocate(&mut self) -> Result<u64, LifecycleError> {
        let value = self.next_id;
        self.next_id = value.checked_add(1).ok_or(LifecycleError::Exhausted)?;
        Ok(value)
    }
    fn task(&self, task: TaskId) -> Result<&TaskRecord, LifecycleError> {
        self.tasks.get(&task).ok_or(LifecycleError::UnknownIdentity)
    }
    fn sequence(&self, task: &TaskRecord, sequence: u64) -> Result<(), LifecycleError> {
        if task.sequence.checked_add(1) != Some(sequence) {
            return Err(LifecycleError::Stale);
        }
        Ok(())
    }
    fn running(&self, task: TaskId, sequence: u64) -> Result<&TaskRecord, LifecycleError> {
        let task = self.task(task)?;
        self.sequence(task, sequence)?;
        if task.state != TaskState::Running {
            return Err(LifecycleError::WrongState);
        }
        Ok(task)
    }
    fn hold(&mut self, task: TaskId, sequence: u64, pc: u64, reason: HoldReason) {
        let task = self.tasks.get_mut(&task).unwrap();
        task.sequence = sequence;
        task.state = TaskState::Held { pc, reason };
    }
    fn ready_intent(&self, task: TaskId) -> Result<(), LifecycleError> {
        let task = self.task(task)?;
        if !matches!(
            task.state,
            TaskState::Held {
                reason: HoldReason::SyscallEntry,
                ..
            }
        ) || task.pending.is_some()
        {
            return Err(LifecycleError::WrongState);
        }
        self.releasable(task.address_space)
    }
    fn releasable(&self, space: AddressSpaceId) -> Result<(), LifecycleError> {
        let space = self
            .spaces
            .get(&space)
            .ok_or(LifecycleError::UnknownIdentity)?;
        if space.poisoned {
            return Err(LifecycleError::Poisoned);
        }
        if space.invalidation.is_some() {
            return Err(LifecycleError::Invalidating);
        }
        Ok(())
    }
    fn held_tasks(&self, space: AddressSpaceId) -> Result<Vec<TaskId>, LifecycleError> {
        let tasks: Vec<_> = self
            .tasks
            .values()
            .filter(|record| {
                record.address_space == space && !matches!(record.state, TaskState::Terminal(_))
            })
            .collect();
        if tasks.is_empty() {
            return Err(LifecycleError::NoLiveTasks);
        }
        if tasks
            .iter()
            .any(|record| !matches!(record.state, TaskState::Held { .. }))
        {
            return Err(LifecycleError::NotHeld);
        }
        Ok(tasks.iter().map(|record| record.id).collect())
    }
    fn new_process(&mut self, tgid: i32) -> Result<ProcessId, LifecycleError> {
        if self.processes.len() == self.limits.processes {
            return Err(LifecycleError::Exhausted);
        }
        let id = ProcessId {
            registry: self.registry,
            serial: self.allocate()?,
        };
        self.processes.insert(id, ProcessRecord { tgid });
        Ok(id)
    }
    fn new_space(&mut self, origin: AddressSpaceOrigin) -> Result<AddressSpaceId, LifecycleError> {
        if self.spaces.len() == self.limits.address_spaces {
            return Err(LifecycleError::Exhausted);
        }
        let id = AddressSpaceId {
            registry: self.registry,
            serial: self.allocate()?,
        };
        self.spaces.insert(
            id,
            AddressSpaceRecord {
                id,
                generation: 0,
                poisoned: false,
                origin,
                invalidation: None,
            },
        );
        Ok(id)
    }
    fn add_obligation(
        &mut self,
        task: TaskId,
        space: AddressSpaceId,
        kind: ObligationKind,
        inherited_from: Option<ObligationId>,
    ) -> Result<ObligationId, LifecycleError> {
        if self.obligations.len() == self.limits.obligations {
            return Err(LifecycleError::Exhausted);
        }
        let id = ObligationId {
            registry: self.registry,
            serial: self.allocate()?,
        };
        self.obligations.insert(
            id,
            ObligationRecord {
                id,
                task,
                address_space: space,
                kind,
                inherited_from,
            },
        );
        Ok(id)
    }
}
