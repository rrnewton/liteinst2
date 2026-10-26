//! Bounded admitted-exec diagnostics outside the movable admission transaction.
//! All records are evidence only. Native custody, input validation, publication
//! and replacement commit remain the connected owner's responsibilities.
use super::super::admission::PendingToken;
use super::bootstrap::{BootstrapEffect, BootstrapMm, ReplacedBootstrapObservation};
use super::kernel_journal::{
    KernelAttemptId, KernelCapturedState, KernelFailureKind, KernelPinKind, KernelStopIdentity,
};
use super::selected::{ExecInvocation, ExecObservation, ExecRelease};
use super::trusted::{AdmissionStop, TaskStateSnapshot};
use super::*;
use crate::gate::GateError;
use crate::selected::{Operation, SelectedInput, SyscallAbi};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Mutex, MutexGuard};

mod capture;
mod observation;
mod storage;
#[cfg(test)]
mod tests;
use storage::*;

const FACTS: usize = 192;
const RAW_SLOTS: usize = 5;
const QUARANTINE_LIMIT: usize = 64;
const MAP_BYTES: usize = 64 * 1024;
// 1 attach + 2 restore + 6 releases + 5 raw + 3 native validations +
// 1 trap + 1 restored state + 2*(13+64) effects + 1 bootstrap +
// 2 final maps + 2 source transaction + 1 commit. Successful path has 4 raw.
const MAX_SCHEDULE: usize = 179;
const _: () = assert!(MAX_SCHEDULE <= FACTS);

/// Diagnostic stage; it does not imply completion of the named operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecJournalStage {
    /// Storage has been prepared without release authority.
    Prepared,
    /// Original selected source bytes are being restored.
    OriginalRestore,
    /// The original pre-kernel continuation is being released.
    OriginalRelease,
    /// Independent reads of an actual pinned wait are in progress.
    RawCapture,
    /// The real syscall ENTRY has passed native checks.
    Entry,
    /// The authenticated ENTRY is being released into the kernel.
    EntryRelease,
    /// The actual EXEC has replaced the task and address-space identities.
    Replaced,
    /// The actual EXEC stop is being released toward syscall EXIT.
    ExecRelease,
    /// The real new-mm syscall EXIT has passed native checks.
    Exit,
    /// A typed replacement bootstrap operation is in progress.
    Bootstrap,
    /// Final new-mm nonexecutable map evidence is being captured.
    QuarantinedMaps,
    /// Complete source facts are being requested or accepted.
    Sources,
    /// The owner has committed the replacement admission state.
    Admission,
    /// The owner is closing; this alone does not prove physical cleanup.
    Closing,
}

/// Public diagnostic name for an original ptrace release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecReleasePhase {
    /// Toward the original instruction's actual ENTRY.
    Original,
    /// From ENTRY into the original exec implementation.
    Entry,
    /// From actual EXEC toward actual new-mm EXIT.
    ExecEvent,
}

/// Closed bootstrap operations, separate from their request/completion facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecBootstrapEffect {
    /// Install the owned first-user trap.
    PatchEntry,
    /// Continue from actual EXIT to that first-user trap.
    FirstUserResume,
    /// Restore the original byte and the actual trap state with only RIP undone.
    RestoreEntry,
    /// Install the authenticated bootstrap stub.
    WriteStub,
    /// Allocate the new-mm private island.
    MapIsland,
    /// Write the private island at the actual returned address.
    WriteIsland {
        /// Actual new-mm address.
        address: u64,
    },
    /// Seal the private island executable.
    ProtectIsland {
        /// Actual new-mm address.
        address: u64,
        /// Exact byte length.
        length: usize,
    },
    /// Read kernel membarrier capabilities.
    QueryMembarrier,
    /// Register the required membarrier operation.
    RegisterMembarrier,
    /// Synchronize the bootstrap code.
    BootstrapSync,
    /// Restore original source and complete application state.
    RestoreOriginal,
    /// Synchronize before original executable pages become nonexecutable.
    QuarantineSyncBefore,
    /// Remove execution from one complete original executable mapping.
    Quarantine {
        /// Exact mapping start.
        start: u64,
        /// Exact mapping length.
        length: usize,
    },
    /// Synchronize after all original executable mappings are nonexecutable.
    QuarantineSyncAfter,
}

/// Unmodified outcome of one native read request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecReadOutcome {
    /// Exact return value; absence of this object means the read was not attempted.
    pub result: i64,
    /// OS errno captured immediately after a minus-one return.
    pub errno: Option<i32>,
}

/// Exact GETREGSET metadata, independent of other read outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecXstateQuery {
    /// Unmodified request result and immediate errno.
    pub outcome: ExecReadOutcome,
    /// Actual returned iovec length, including invalid lengths on failure.
    pub reported_bytes: usize,
    /// Whether the kernel left the originally supplied buffer pointer unchanged.
    pub pointer_unchanged: bool,
}

/// Completion of a bounded maps read; complete does not mean parsed or trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecMapsStatus {
    /// No read was attempted.
    Unused,
    /// A read began but has not completed; its initialized prefix remains evidence.
    InProgress,
    /// The original procfs stream reached actual EOF within the fixed bound.
    Complete,
    /// The stream or its identity/size/deadline check failed.
    Failed(KernelFailureKind),
}

/// Exact bounded procfs observation, including independent operation outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecMapsRecord {
    /// Explicit stream completeness, independent of parser acceptance.
    pub status: ExecMapsStatus,
    /// Actual numeric task bound to the original retained pin.
    pub tid: i32,
    /// Raw stopped status authenticated before this read.
    pub raw_status: i32,
    /// Exact open result, if attempted.
    pub open: Option<ExecReadOutcome>,
    /// Exact fstatfs result, if attempted.
    pub filesystem: Option<ExecReadOutcome>,
    /// Initialized filesystem type, authenticated only on successful fstatfs.
    pub filesystem_type: i64,
    /// Number of actual read requests, including EOF/overflow discrimination.
    pub read_calls: usize,
    /// Exact last read result, if any; earlier successes contribute to the prefix.
    pub last_read: Option<ExecReadOutcome>,
    /// Initialized overflow-discrimination byte, not part of the retained prefix.
    pub overflow_byte: u8,
    /// Exact close result, if an opened descriptor was closed.
    pub close: Option<ExecReadOutcome>,
    /// Number of bytes actually copied by successful reads.
    pub observed_bytes: usize,
    /// Entire initialized 64KiB storage; the unread suffix is not observed data.
    pub initialized: Vec<u8>,
}

/// One chronological pinned raw wait, before lifecycle/ELF interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecRawRecord {
    /// Zero-based archive ordinal, unrelated to per-task stop sequence numbers.
    pub ordinal: u8,
    /// Actual task number returned by the pinned wait.
    pub tid: i32,
    /// Original wait status, never replaced with a semantic phase label.
    pub status: i32,
    /// Kind of original retained pidfd.
    pub pin: KernelPinKind,
    /// Whether the original pin and a stopped status allowed read attempts.
    pub held: bool,
    /// True only after all status-required reads completed successfully.
    pub complete: bool,
    /// Independent GETREGS outcome, absent if no held read was attempted.
    pub registers_read: Option<ExecReadOutcome>,
    /// Complete initialized scalar substrate, including failed partial writes.
    pub registers: RegisterSnapshot,
    /// Independent maximum-capacity XSTATE query metadata.
    pub xstate_query: Option<ExecXstateQuery>,
    /// Entire initialized maximum-capacity XSTATE buffer.
    pub initialized_xstate: Vec<u8>,
    /// Independent GETSIGMASK outcome.
    pub mask_read: Option<ExecReadOutcome>,
    /// Initialized native mask word, including any failed request write.
    pub signal_mask: u64,
    /// Independent GET_SYSCALL_INFO outcome, including actual returned length.
    pub syscall_read: Option<ExecReadOutcome>,
    /// Entire initialized native syscall-info buffer.
    pub syscall_info: [u8; 88],
    /// Independent GETEVENTMSG outcome.
    pub event_read: Option<ExecReadOutcome>,
    /// Initialized event message, authenticated only on successful read.
    pub event_message: u64,
    /// Independent GETSIGINFO outcome.
    pub siginfo_read: Option<ExecReadOutcome>,
    /// Entire initialized signal-info buffer.
    pub siginfo: [u8; 128],
    /// Maps read at this exact raw wait, not at a fabricated later phase.
    pub maps: ExecMapsRecord,
}

/// Fixed, exact original exec input; no resolver or serialized control authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecOriginalInput {
    /// Original selected instruction address.
    pub logical_pc: u64,
    /// Exact decoded original fallthrough address.
    pub next_pc: u64,
    /// Original initialized instruction-byte storage.
    pub initialized_instruction: [u8; 15],
    /// Exact decoded instruction length; suffix bytes are padding, not code.
    pub instruction_bytes: usize,
    /// Full original GPR, flags, segment and kernel bookkeeping state.
    pub registers: RegisterSnapshot,
    /// Native syscall arguments in ABI order.
    pub arguments: [u64; 6],
}

/// A validated native phase points back to an immutable raw observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecValidatedPhase {
    /// Original task's actual syscall ENTRY.
    Entry,
    /// New task/mm's actual EXEC, at its birth sequence zero.
    Replaced,
    /// New task/mm's actual syscall EXIT.
    Exit,
}

/// Ordered evidence facts; none is a release or replacement capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecJournalFact {
    /// One exact original invocation's storage was attached before effects.
    Attached,
    /// Original source restoration was about to start.
    RestoreAttempt,
    /// The owner's original source restoration finished.
    RestoreComplete,
    /// A native release was about to be attempted.
    ReleaseAttempt {
        /// Typed release purpose.
        phase: ExecReleasePhase,
        /// Exact historical source stop.
        stop: KernelStopIdentity,
    },
    /// The native release call succeeded; no next stop is implied.
    ReleaseSucceeded {
        /// Typed release purpose.
        phase: ExecReleasePhase,
        /// Same exact historical source stop.
        stop: KernelStopIdentity,
    },
    /// A raw pinned wait was retained before any phase classification.
    Raw {
        /// Stable chronological record index.
        ordinal: u8,
    },
    /// Existing native validation agreed with the entire corresponding raw state.
    Validated {
        /// Which native checks completed.
        phase: ExecValidatedPhase,
        /// Original raw observation index.
        ordinal: u8,
        /// Exact historical stop.
        stop: KernelStopIdentity,
        /// Actual task/mm identity.
        identity: DynamicTask,
    },
    /// The genuine first-user trap state passed native validation.
    FirstUserTrap {
        /// Raw record containing the complete actual state.
        ordinal: u8,
    },
    /// Exact actual first-user state was restored with only owned RIP correction.
    RestoredEntry {
        /// Historical new-mm checkpoint.
        stop: KernelStopIdentity,
    },
    /// A typed bootstrap effect was about to start.
    EffectAttempt {
        /// Exact effect and geometry.
        effect: ExecBootstrapEffect,
    },
    /// A typed bootstrap effect returned successfully, before later checks.
    EffectComplete {
        /// Exact matching effect and geometry.
        effect: ExecBootstrapEffect,
        /// Actual result for value-returning operations.
        result: Option<u64>,
    },
    /// Final bootstrap state was checked; final raw maps are a separate capture.
    BootstrapComplete {
        /// Exact final held checkpoint.
        stop: KernelStopIdentity,
    },
    /// Read-only final quarantine map capture began under the actual held proof.
    QuarantinedMapsAttempt {
        /// Exact final held checkpoint.
        stop: KernelStopIdentity,
    },
    /// Final quarantine maps reached complete bounded EOF under the same pin.
    QuarantinedMapsComplete {
        /// Exact final held checkpoint.
        stop: KernelStopIdentity,
    },
    /// The owner issued one bound, immutable source request.
    SourcesRequested {
        /// Owner-issued request identity.
        request: u64,
        /// Exact read-only capture checkpoint.
        stop: KernelStopIdentity,
        /// Number of complete captured image VMAs.
        images: usize,
        /// Total actual source bytes in the request.
        bytes: usize,
    },
    /// The owner's exact source-reply checks completed.
    SourcesAccepted {
        /// Same owner-issued request identity.
        request: u64,
        /// Actual complete head inventory size.
        heads: usize,
    },
    /// Replacement admission commit completed; this is distinct from syscall EXIT.
    AdmissionComplete {
        /// Exact ready checkpoint.
        stop: KernelStopIdentity,
    },
}

/// A single detached attempt, preserving complete states and incomplete reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecAttemptSnapshot {
    /// Original session/invocation identity.
    pub id: KernelAttemptId,
    /// Original selected stop, before source restoration.
    pub pending_stop: KernelStopIdentity,
    /// Old task/process/mm/generation identity.
    pub previous: DynamicTask,
    /// Original admission generation.
    pub source_epoch: u64,
    /// Original admission plan identity.
    pub source_plan: u64,
    /// Exact original absolute deadline, never renewed by a phase change.
    pub original_until: Instant,
    /// Fixed original instruction/input description.
    pub input: ExecOriginalInput,
    /// Full original pre-instruction state.
    pub before: KernelCapturedState,
    /// Fresh native stop after source restoration, if authenticated.
    pub restored_original_stop: Option<KernelStopIdentity>,
    /// Actual replacement identity, only after validated EXEC.
    pub replacement: Option<DynamicTask>,
    /// Ordered immutable facts, without synthesized omitted phases.
    pub facts: Vec<ExecJournalFact>,
    /// Actual pinned raw waits in observation order, including partial records.
    pub raw: Vec<ExecRawRecord>,
    /// Actual trap state with only the owned RIP correction, when complete.
    pub restored_entry: Option<KernelCapturedState>,
    /// Actual final-bootstrap state, when complete.
    pub final_state: Option<KernelCapturedState>,
    /// Separately captured final nonexecutable maps, including partial failures.
    pub quarantined_maps: ExecMapsRecord,
}

/// A detached archive snapshot; reading never asks the tracer to run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecProgressSnapshot {
    /// Immutable owner session identity.
    pub session: u64,
    /// Nonrefunded managed allocation reservation, including unused capacity
    /// and an abandoned preparation; it is not a current allocator/RSS gauge.
    pub allocated_bytes: usize,
    /// Latest diagnostic stage, independent of success.
    pub stage: ExecJournalStage,
    /// One attempt at most; preparation alone does not attach an attempt.
    pub attempt: Option<ExecAttemptSnapshot>,
    /// First failure and its stage; cleanup never overwrites it.
    pub first_failure: Option<(ExecJournalStage, KernelFailureKind)>,
    /// Whether the owner has closed further transaction writes.
    pub closing: bool,
    /// Owner-reported physical cleanup result, absent until actually reported.
    pub cleanup_complete: Option<bool>,
    /// Whether archive poisoning was observed; snapshots remain diagnostic only.
    pub archive_poisoned: bool,
}

/// Cloneable read-only in-memory evidence, retained after session failure/drop.
#[derive(Clone)]
pub struct ExecProgressReader {
    archive: Arc<Mutex<Archive>>,
}
impl ExecProgressReader {
    /// Copies retained evidence; no native operation or execution authority.
    pub fn snapshot(&self) -> ExecProgressSnapshot {
        let (archive, poisoned) = match self.archive.lock() {
            Ok(guard) => (guard, false),
            Err(error) => (error.into_inner(), true),
        };
        ExecProgressSnapshot {
            session: archive.session,
            allocated_bytes: archive.allocated_bytes,
            stage: archive.stage,
            attempt: archive.attempt.as_ref().map(|attempt| attempt.snapshot()),
            first_failure: archive.first_failure,
            closing: archive.closing,
            cleanup_complete: archive.cleanup_complete,
            archive_poisoned: archive.poisoned || poisoned,
        }
    }
}

fn invalid(message: &'static str) -> LaunchError {
    LaunchError::Invalid(message)
}
fn failure(error: &LaunchError) -> KernelFailureKind {
    match error {
        LaunchError::Invalid(
            "exec journal fact capacity exhausted"
            | "exec journal bootstrap pair capacity exhausted"
            | "exec journal release pair capacity exhausted"
            | "exec journal restoration pair capacity exhausted"
            | "exec journal final maps pair capacity exhausted"
            | "exec journal maps exceeds fixed capture"
            | "exec journal allocation failed",
        ) => KernelFailureKind::Capacity,
        _ => super::kernel_journal::failure_kind(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePhase {
    Attached,
    RestoreStarted,
    Restored,
    Ready,
    OriginalAttempted,
    OriginalReleased,
    EntrySeen,
    EntryAttempted,
    EntryReleased,
    ExecSeen,
    ExecAttempted,
    ExecReleased,
    ExitSeen,
    Bootstrapping,
    BootstrapComplete,
    MapsStarted,
    MapsComplete,
    SourcesRequested,
    SourcesAccepted,
    Complete,
}

struct StoredState {
    registers: RegisterSnapshot,
    mask: u64,
    xstate: Vec<u8>,
    length: usize,
    complete: bool,
}
struct StoredMaps {
    record: ExecMapsRecord,
}
struct RawBuffer {
    record: ExecRawRecord,
}
struct Attempt {
    id: KernelAttemptId,
    pending: PendingToken,
    input: ExecOriginalInput,
    until: Instant,
    facts: [Option<ExecJournalFact>; FACTS],
    fact_count: usize,
    raw: [RawBuffer; RAW_SLOTS],
    raw_count: usize,
    pending_raw: Option<u8>,
    before: StoredState,
    restored_entry: StoredState,
    final_state: StoredState,
    final_maps: StoredMaps,
    native_phase: NativePhase,
    original_stop: Option<KernelStopIdentity>,
    entry_stop: Option<KernelStopIdentity>,
    exec_stop: Option<KernelStopIdentity>,
    exit_stop: Option<KernelStopIdentity>,
    final_stop: Option<KernelStopIdentity>,
    replacement: Option<DynamicTask>,
    trap_raw: Option<u8>,
    effect_index: usize,
    quarantine_count: usize,
    quarantine_end: u64,
    outstanding_effect: Option<ExecBootstrapEffect>,
    island: Option<u64>,
    source_request: Option<u64>,
}
struct Archive {
    session: u64,
    allocated_bytes: usize,
    prepared: bool,
    attempt: Option<Box<Attempt>>,
    stage: ExecJournalStage,
    first_failure: Option<(ExecJournalStage, KernelFailureKind)>,
    closing: bool,
    cleanup_complete: Option<bool>,
    poisoned: bool,
}

/// The prepared box has one custodian; abandonment never reopens preparation.
pub(in crate::linux::remote::dynamic::owner) struct PreparedExecAttempt {
    archive: Arc<Mutex<Archive>>,
    attempt: Box<Attempt>,
    bytes: usize,
}
/// An internal archive reference, not native execution or replacement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct ExecAttemptHandle {
    id: KernelAttemptId,
    archive: usize,
}
impl ExecAttemptHandle {
    pub(in crate::linux::remote::dynamic::owner) fn id(self) -> KernelAttemptId {
        self.id
    }
}
pub(in crate::linux::remote::dynamic) struct ExecJournalWriter {
    archive: Arc<Mutex<Archive>>,
    _thread: PhantomData<Rc<()>>,
}
pub(in crate::linux::remote::dynamic::owner) struct ExecJournalObserver {
    archive: Arc<Mutex<Archive>>,
    handle: ExecAttemptHandle,
    _thread: PhantomData<Rc<()>>,
}
pub(in crate::linux::remote::dynamic::owner) struct ExecJournalUnwind {
    archive: Arc<Mutex<Archive>>,
}

/// Borrowed immutable evidence for the owner's existing strict maps parser.
/// The closure using this view must not perform native operations or reenter
/// the archive while its lock is held. It supplies no mapping authority.
pub(in crate::linux::remote::dynamic::owner) struct ExecSourceMaps<'a> {
    pub(in crate::linux::remote::dynamic::owner) previous: DynamicTask,
    pub(in crate::linux::remote::dynamic::owner) replacement: DynamicTask,
    pub(in crate::linux::remote::dynamic::owner) exit_ordinal: u8,
    pub(in crate::linux::remote::dynamic::owner) exit_stop: KernelStopIdentity,
    pub(in crate::linux::remote::dynamic::owner) final_stop: KernelStopIdentity,
    pub(in crate::linux::remote::dynamic::owner) exit: &'a ExecMapsRecord,
    pub(in crate::linux::remote::dynamic::owner) exit_bytes: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner) quarantine: &'a ExecMapsRecord,
    pub(in crate::linux::remote::dynamic::owner) quarantine_bytes: &'a [u8],
}
