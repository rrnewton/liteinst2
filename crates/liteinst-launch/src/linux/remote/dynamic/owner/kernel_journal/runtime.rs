//! Runtime-selected kernel evidence has no installed plan or rearm generation.
//! This archive copies diagnostics; it cannot construct native/census authority.
use super::super::admission::runtime::kernel::RuntimeKernelIdentity;
use super::super::admission::runtime_kernel_native::{
    NativeKernelReturnTrace, NativeKernelTerminalTrace, RuntimeKernelFailure,
    RuntimeKernelReadback, RuntimeMapsReadView, RuntimeRawWaitView, RuntimeStateReadView,
    RuntimeWaitCustody,
};
use super::super::admission::{
    RuntimeKernelCommitOutcome, RuntimeKernelCommitReceipt, RuntimeKernelCommitView,
};
use super::super::bootstrap::Request;
use super::*;
use crate::linux::remote::dynamic::admission::RuntimePendingToken;
use liteinst2::contracts::CodeIdentity;
use std::mem::size_of;

mod finish;
mod observation;
mod storage;
pub(in crate::linux::remote::dynamic::owner) use storage::{
    PreparedRuntimeJournal, RuntimeJournalShape,
};
#[cfg(test)]
mod tests;

const RAW: usize = 9;
const STATE_COUNT: usize = 8;
const FACT_COUNT: usize = 32;
// Return: waits9 + copies6 + releases4 + opened/entry/exit/closed4 +
// native-return1 + census1 =25. Terminal: waits6 + copies3 + releases6 +
// opened/entry/pre-exit3 + terminal1 + census1 =20. First unexpected adds1.
const _: () = assert!(25 < FACT_COUNT && 20 < FACT_COUNT);

/// Exact result of one request. None at a containing field means unattempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeKernelRequest {
    /// Actual numeric return value, including failed requests.
    pub result: i64,
    /// Errno captured by the native collector immediately after its request.
    pub errno: Option<i32>,
}
impl From<Request> for RuntimeKernelRequest {
    fn from(value: Request) -> Self {
        Self {
            result: value.result,
            errno: value.errno,
        }
    }
}
impl RuntimeKernelRequest {
    fn zero(self) -> bool {
        self.result == 0 && self.errno.is_none()
    }
}

/// One selected-purpose state copy. A phase name identifies its intended slot;
/// only a separate validated fact establishes the actual native phase.
/// Private-call payloads stay native-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKernelStateSlot {
    /// Actual before-provider query, after exact input equality.
    Original,
    /// Original syscall ENTRY raw state.
    Entry,
    /// Original syscall EXIT raw state.
    Exit,
    /// Actual neutral INT3 state before restoring the EXIT state.
    BridgeTrap,
    /// Actual complete restored EXIT readback, before work-buffer reuse.
    RestoredReturn,
    /// Actual final closing-sync restored readback.
    Closed,
    /// Actual held PTRACE_EVENT_EXIT state; this is not syscall EXIT.
    PreExit,
    /// First failed or unexpected initialized state, including pre-open failure.
    Unexpected,
}
impl RuntimeKernelStateSlot {
    fn index(self) -> usize {
        self as usize
    }
}

/// Full initialized selected-state substrate, including failed query writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeKernelStateRecord {
    /// Fixed one-use purpose.
    pub slot: RuntimeKernelStateSlot,
    /// A real native read view has been copied; unused storage is not evidence.
    pub captured: bool,
    /// The observer completed copying this view, including on native failure.
    pub finalized: bool,
    /// All native state requests and exact complete-state predicates succeeded.
    pub complete: bool,
    /// Associated actual raw wait, absent for independent readback copies.
    pub raw_ordinal: Option<usize>,
    /// Exact validated readback stop, absent before that validation.
    pub stop: Option<KernelStopIdentity>,
    /// Entire initialized native GETREGS storage.
    pub registers: [u8; 216],
    /// Actual independent GETREGS outcome.
    pub registers_request: Option<RuntimeKernelRequest>,
    /// Entire initialized MAX buffer; its suffix is not logical XSTATE.
    pub initialized_xstate: Vec<u8>,
    /// Actual independent GETREGSET outcome.
    pub xstate_request: Option<RuntimeKernelRequest>,
    /// Actual original iovec pointer, diagnostic only.
    pub requested_pointer: usize,
    /// Actual returned iovec pointer, including invalid results.
    pub returned_pointer: usize,
    /// Actual originally requested iovec extent.
    pub requested_length: usize,
    /// Actual returned extent, including invalid results.
    pub returned_length: usize,
    /// Entire initialized native mask storage.
    pub mask: [u8; 8],
    /// Actual independent GETSIGMASK outcome.
    pub mask_request: Option<RuntimeKernelRequest>,
}

/// Fixed maps-read metadata. Full map bytes remain in RuntimeOwner's archive.
/// Earlier successful reads contribute to the native retained prefix; this is
/// not a separate record of every request in a variable-length read loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeKernelMapsSummary {
    /// Number of bytes actually read into native initialized storage.
    pub observed_bytes: usize,
    /// Actual proc task-directory open result.
    pub directory_open: Option<RuntimeKernelRequest>,
    /// Actual procfs identity request result.
    pub filesystem_request: Option<RuntimeKernelRequest>,
    /// Observed filesystem type, if acquired.
    pub filesystem: Option<i64>,
    /// Actual maps-file open result.
    pub maps_open: Option<RuntimeKernelRequest>,
    /// Actual number of read requests.
    pub read_calls: usize,
    /// Last actual read result, including EOF or failure.
    pub last_read: Option<RuntimeKernelRequest>,
    /// Actual bounded overflow discrimination request.
    pub overflow_probe: Option<RuntimeKernelRequest>,
    /// The complete bounded stream reached EOF; no parser authority follows.
    pub complete: bool,
}

/// Owner custody as it existed immediately after the actual wait. These copied
/// fields do not keep an FD open or authorize any subsequent native query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeKernelWaitCustody {
    /// Owner session observed at callback.
    pub session: u64,
    /// Expected original numeric task.
    pub expected_tid: i32,
    /// Retained original pin descriptor at the observation, diagnostic only.
    pub retained_pin: Option<i32>,
    /// Process versus thread pin, when known.
    pub pin: Option<KernelPinKind>,
    /// Owner still retained the numeric task in its custody set.
    pub owned: bool,
    /// Exact stopped status in the Owner, if still held.
    pub stopped_status: Option<i32>,
    /// Actual tracer-terminal record, if the wait was terminal.
    pub tracer_terminal: Option<i32>,
    /// Existing wait-custody failure flag.
    pub lost_wait: bool,
    /// Existing missing-pin failure flag.
    pub missing_pin: bool,
}

/// Actual raw wait and independent fixed request outcomes, before semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeKernelRawRecord {
    /// Genuine chronological ordinal within this invocation.
    pub ordinal: usize,
    /// Actual wait task identifier.
    pub tid: i32,
    /// Actual wait status; terminal is never relabelled syscall EXIT.
    pub status: i32,
    /// Immediate descriptive custody before held/query gates.
    pub custody: RuntimeKernelWaitCustody,
    /// True only after the native stopped/live-pin gate allowed queries.
    pub queries_started: bool,
    /// Raw callback completed; true does not imply native validation success.
    pub finalized: bool,
    /// Entire initialized native scalar storage, even for failed requests.
    pub registers: [u8; 216],
    /// Independent GETREGS result, if attempted.
    pub registers_request: Option<RuntimeKernelRequest>,
    /// Independent maximum-extent GETREGSET result.
    pub xstate_request: Option<RuntimeKernelRequest>,
    /// Actual requested pointer; its numeric value grants no access.
    pub requested_pointer: usize,
    /// Actual returned pointer, including invalid values.
    pub returned_pointer: usize,
    /// Actual requested extent.
    pub requested_length: usize,
    /// Actual returned extent, including malformed values.
    pub returned_length: usize,
    /// Initialized mask substrate.
    pub mask: [u8; 8],
    /// Independent GETSIGMASK result.
    pub mask_request: Option<RuntimeKernelRequest>,
    /// Initialized syscall-info storage, not inferred from GPRs or events.
    pub syscall_info: [u8; 88],
    /// Actual GET_SYSCALL_INFO result, including returned byte count.
    pub syscall_request: Option<RuntimeKernelRequest>,
    /// Initialized event message, not interpreted without its successful request.
    pub event_message: u64,
    /// Independent GETEVENTMSG result.
    pub event_request: Option<RuntimeKernelRequest>,
    /// Initialized siginfo storage.
    pub signal: [u8; 128],
    /// Independent GETSIGINFO result.
    pub signal_request: Option<RuntimeKernelRequest>,
    /// Metadata only; complete raw map bytes remain native-owned until Owner drop.
    pub maps: Option<RuntimeKernelMapsSummary>,
    /// Separate public MAX copy, when this is a selected or failed state purpose.
    pub state_slot: Option<RuntimeKernelStateSlot>,
    /// First native capture failure class, independent of later interpretation.
    pub failure: Option<KernelFailureKind>,
}

/// Native original releases, distinct from private runner effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKernelReleasePhase {
    /// Toward actual original syscall ENTRY.
    Original,
    /// From actual ENTRY into the kernel implementation.
    Entry,
    /// Kernel-only continuation from actual PTRACE_EVENT_EXIT.
    PreExit,
}
/// Actual source of an original release; pre-exit has no fabricated token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKernelReleaseSource {
    /// A validated held logical checkpoint or actual ENTRY.
    Stop(KernelStopIdentity),
    /// The genuine held pre-exit raw observation.
    PreExit {
        /// Actual retained wait ordinal.
        ordinal: usize,
        /// Actual original task.
        tid: i32,
        /// Actual PTRACE_EVENT_EXIT wait status.
        status: i32,
    },
}
/// Runtime journal phase; it never substitutes for an actual native event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKernelJournalStage {
    /// Allocation attached, with no release authority.
    Prepared,
    /// Native original input capture.
    Original,
    /// Native raw header/query copying.
    Raw,
    /// Exact logical executable window validated.
    Opened,
    /// Actual syscall ENTRY validated.
    Entry,
    /// Actual syscall EXIT validated.
    Exit,
    /// Actual neutral restored return checkpoint validated.
    RestoredReturn,
    /// Exact final NX checkpoint validated.
    Closed,
    /// Actual pre-exit event validated.
    PreExit,
    /// Actual terminal event and physical application receipt observed.
    Terminal,
    /// Native return transport observed; census not yet committed.
    Returned,
    /// Entire census transaction committed.
    Committed,
}
/// First failure remains independently available if fixed fact storage is full.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeKernelJournalFailure {
    /// Phase reached when this first failure was recorded.
    pub stage: RuntimeKernelJournalStage,
    /// Closed failure class; paths/freeform text are not exported.
    pub kind: KernelFailureKind,
}
/// Compact phase facts link to independent raw/copy records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKernelFact {
    /// Actual immediate wait header was retained.
    Wait {
        /// Index of the actual retained raw wait.
        ordinal: usize,
    },
    /// A selected-purpose initialized state view was copied.
    State {
        /// Actual initialized state-copy purpose.
        slot: RuntimeKernelStateSlot,
    },
    /// Original release was recorded before attempting its request.
    ReleaseAttempt {
        /// Original release role, distinct from private runner effects.
        phase: RuntimeKernelReleasePhase,
        /// Exact preceding observation, with no invented pre-exit token.
        source: RuntimeKernelReleaseSource,
    },
    /// Actual release result; no execution completion is inferred.
    ReleaseResult {
        /// Release attempt to which this result belongs.
        phase: RuntimeKernelReleasePhase,
        /// Actual request result and immediately captured errno.
        request: RuntimeKernelRequest,
    },
    /// Source callback validated a real native checkpoint/event.
    Validated {
        /// Actual validated role.
        stage: RuntimeKernelJournalStage,
        /// Exact real same-task stop, descriptive only.
        stop: KernelStopIdentity,
    },
    /// Actual pre-exit header/message passed native interpretation.
    PreExit {
        /// Index of the actual PTRACE_EVENT_EXIT wait.
        ordinal: usize,
        /// Actual successfully requested event message.
        message: u64,
    },
    /// Native returning path reached its real final NX-closed stop.
    Returned {
        /// Exact final closing-sync token.
        stop: KernelStopIdentity,
    },
    /// Actual tracer-terminal and matching physical application status.
    Terminal {
        /// Index of the actual terminal wait; no held token exists.
        ordinal: usize,
        /// Actual native lifecycle sequence assigned to termination.
        sequence: u64,
        /// Actual terminal wait status.
        status: i32,
        /// Matching physical-owner retained status.
        physical_status: i32,
        /// Actual poll events from the retained original pin.
        pin_revents: i16,
    },
    /// Same-generation census committed a distinct successor origin.
    ReturnCommitted {
        /// New origin's census identity and serial, descriptive only.
        current: (u64, u64),
        /// Exact final stop linked by the private committed receipt.
        stop: KernelStopIdentity,
    },
    /// Census retired the terminal origin without a fictitious successor.
    TerminalCommitted {
        /// Exact native terminal sequence from the committed receipt.
        sequence: u64,
        /// Exact terminal status from the committed receipt.
        status: i32,
    },
}

/// Read-only invocation projection. No plan number or manufactured epoch exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeKernelAttemptSnapshot {
    /// Session and monotone invocation.
    pub id: KernelAttemptId,
    /// Exact original full task/process/mm/generation identity.
    pub task: DynamicTask,
    /// Actual original selected stop.
    pub original_stop: KernelStopIdentity,
    /// Retained complete source identity and full-VMA mapping binding.
    pub source: CodeIdentity,
    /// Original source-window index, not a substituted VMA.
    pub window: usize,
    /// Original census identity/serial, descriptive only.
    pub origin: (u64, u64),
    /// Original execution identity/serial, descriptive only.
    pub execution: (u64, u64),
    /// Exact original PC.
    pub logical_pc: u64,
    /// Exact original native64 SYSCALL bytes.
    pub instruction: [u8; 2],
    /// Complete original GPR input.
    pub input_registers: RegisterSnapshot,
    /// Exact native syscall number.
    pub number: u64,
    /// Exact original native ABI arguments.
    pub arguments: [u64; 6],
    /// Original absolute deadline, never restarted by capture.
    pub original_until: Instant,
    /// Actual pre-effect newly retained charge, with no refund of old capacity.
    pub retained_bytes: usize,
    /// All nine raw purposes; unused slots are absent.
    pub raw: [Option<RuntimeKernelRawRecord>; RAW],
    /// All eight initialized MAX allocations with explicit unused/capture state.
    pub states: [RuntimeKernelStateRecord; STATE_COUNT],
    /// Chronological fixed facts, including incomplete prefixes.
    pub facts: Vec<RuntimeKernelFact>,
    /// First failure, outside fixed fact capacity.
    pub failure: Option<RuntimeKernelJournalFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Binding {
    pending: RuntimePendingToken,
    original: AdmissionStop,
    source: CodeIdentity,
    window: usize,
    origin: (u64, u64),
    execution: (u64, u64),
    registers: RegisterSnapshot,
    original_mask: u64,
    original_xstate_len: usize,
    number: u64,
    arguments: [u64; 6],
    until: Instant,
}
impl Binding {
    fn id(&self) -> KernelAttemptId {
        KernelAttemptId {
            session: self.pending.stop.session,
            invocation: self.pending.invocation,
        }
    }
    fn returns(&self) -> bool {
        self.number == libc::SYS_getpid as u64 || self.number == libc::SYS_gettid as u64
    }
    fn matches(&self, identity: &RuntimeKernelIdentity) -> bool {
        self.id() == identity.attempt()
            && self.pending == *identity.pending()
            && (self.source, self.window) == identity.journal_source()
            && self.origin == identity.journal_origin()
            && self.execution == identity.journal_execution()
            && self.pending.task == identity.task()
            && self.number == identity.number()
            && self.arguments == identity.arguments()
            && self.until == identity.until()
            && self.pending.pc == identity.pc()
            && identity.encoding() == [0x0f, 0x05]
            && identity.pc().checked_add(2) == Some(identity.next_pc())
    }
}

struct RuntimeAttempt {
    binding: Binding,
    charge: usize,
    raw: [Option<RuntimeKernelRawRecord>; RAW],
    raw_count: usize,
    states: [RuntimeKernelStateRecord; STATE_COUNT],
    facts: [Option<RuntimeKernelFact>; FACT_COUNT],
    fact_count: usize,
    stage: RuntimeKernelJournalStage,
    failure: Option<RuntimeKernelJournalFailure>,
    completed: bool,
}
#[derive(Default)]
pub(super) struct RuntimeArchive {
    attempts: Vec<RuntimeAttempt>,
    active: Option<RuntimeKernelHandle>,
    version: u64,
}
impl RuntimeArchive {
    pub(super) fn allows_legacy(&self, id: KernelAttemptId) -> bool {
        self.active.is_none()
            && self
                .attempts
                .iter()
                .all(|value| value.binding.id().invocation < id.invocation)
    }
    pub(super) fn fail_active(&mut self, kind: KernelFailureKind) {
        if let Some(handle) = self.active {
            if let Some(attempt) = self.attempts.get_mut(handle.index) {
                if attempt.binding.id() == handle.id {
                    attempt.fail(kind);
                }
            }
        }
    }
    pub(super) fn snapshot(&self) -> Vec<RuntimeKernelAttemptSnapshot> {
        self.attempts.iter().map(RuntimeAttempt::snapshot).collect()
    }
}
impl RuntimeAttempt {
    fn fail(&mut self, kind: KernelFailureKind) {
        if self.failure.is_none() && !self.completed {
            self.failure = Some(RuntimeKernelJournalFailure {
                stage: self.stage,
                kind,
            });
        }
    }
    fn append(&mut self, fact: RuntimeKernelFact) -> Result<(), LaunchError> {
        if self.completed {
            return Err(invalid("runtime journal attempt is already complete"));
        }
        if self.fact_count == FACT_COUNT {
            self.fail(KernelFailureKind::Capacity);
            return Err(invalid("runtime journal fact capacity exhausted"));
        }
        self.facts[self.fact_count] = Some(fact);
        self.fact_count += 1;
        Ok(())
    }
    fn facts(&self) -> impl Iterator<Item = &RuntimeKernelFact> {
        self.facts[..self.fact_count]
            .iter()
            .map(|value| value.as_ref().unwrap())
    }
    fn snapshot(&self) -> RuntimeKernelAttemptSnapshot {
        let b = &self.binding;
        RuntimeKernelAttemptSnapshot {
            id: b.id(),
            task: b.pending.task,
            original_stop: (&b.original.token).into(),
            source: b.source,
            window: b.window,
            origin: b.origin,
            execution: b.execution,
            logical_pc: b.pending.pc,
            instruction: [0x0f, 0x05],
            input_registers: b.registers,
            number: b.number,
            arguments: b.arguments,
            original_until: b.until,
            retained_bytes: self.charge,
            raw: self.raw.clone(),
            states: self.states.clone(),
            facts: self.facts().copied().collect(),
            failure: self.failure,
        }
    }
}

/// Borrowed existing observed state; converting it never clones XSTATE.
pub(in crate::linux::remote::dynamic::owner) struct RuntimeJournalBefore<'a> {
    pub(in crate::linux::remote::dynamic::owner) registers: &'a RegisterSnapshot,
    pub(in crate::linux::remote::dynamic::owner) xstate: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner) mask: u64,
}

/// Diagnostic handle only. It never authorizes a native effect or census commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct RuntimeKernelHandle {
    id: KernelAttemptId,
    index: usize,
}
impl RuntimeKernelHandle {
    pub(in crate::linux::remote::dynamic::owner) fn id(self) -> KernelAttemptId {
        self.id
    }
}

/// No lock or mutable writer loan survives a callback into native execution.
pub(in crate::linux::remote::dynamic::owner) struct RuntimeJournalSink {
    archive: Arc<Mutex<Archive>>,
    handle: RuntimeKernelHandle,
    _thread: PhantomData<Rc<()>>,
}
impl RuntimeJournalSink {
    fn with<R>(
        &mut self,
        identity: &RuntimeKernelIdentity,
        operation: impl FnOnce(&mut RuntimeAttempt) -> Result<R, LaunchError>,
    ) -> Result<R, LaunchError> {
        let mut archive = match self.archive.lock() {
            Ok(value) => value,
            Err(error) => {
                let mut value = error.into_inner();
                value.poisoned = true;
                value
                    .runtime
                    .fail_active(KernelFailureKind::ArchivePoisoned);
                return Err(invalid("runtime journal archive poisoned"));
            }
        };
        if archive.poisoned
            || archive.status != KernelWriterStatus::Active
            || archive.runtime.active != Some(self.handle)
        {
            return Err(invalid("runtime journal sink is inactive or closed"));
        }
        let attempt = archive
            .runtime
            .attempts
            .get_mut(self.handle.index)
            .ok_or(invalid("runtime journal handle absent"))?;
        if attempt.binding.id() != self.handle.id || !attempt.binding.matches(identity) {
            return Err(invalid("runtime journal identity differs"));
        }
        operation(attempt)
    }
    pub(in crate::linux::remote::dynamic::owner) fn fail(
        &mut self,
        stage: RuntimeKernelJournalStage,
        kind: KernelFailureKind,
    ) {
        let mut archive = match self.archive.lock() {
            Ok(value) => value,
            Err(error) => {
                let mut value = error.into_inner();
                value.poisoned = true;
                value
            }
        };
        if let Some(attempt) = archive.runtime.attempts.get_mut(self.handle.index) {
            if attempt.binding.id() == self.handle.id && !attempt.completed {
                attempt.stage = stage;
                attempt.fail(kind);
            }
        }
    }
}
fn native_failure(value: RuntimeKernelFailure) -> KernelFailureKind {
    match value {
        RuntimeKernelFailure::System(_, errno) => KernelFailureKind::NativeIo(errno),
        RuntimeKernelFailure::Timeout(_) => KernelFailureKind::Timeout,
        RuntimeKernelFailure::Unwound => KernelFailureKind::CaughtPanic,
        _ => KernelFailureKind::InvalidState,
    }
}
