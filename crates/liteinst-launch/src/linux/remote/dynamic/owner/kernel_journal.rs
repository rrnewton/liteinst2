//! Bounded diagnostic evidence, anchored outside the taken admission owner.
//! No value in this module can authorize a ptrace operation or replay.
use super::super::admission::PendingToken;
use super::trusted::{AdmissionStop, TaskStateSnapshot};
use super::*;
use crate::selected::{Operation, SelectedInput, SyscallAbi};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Mutex, MutexGuard};

mod mapping;
pub(in crate::linux::remote::dynamic::owner) use mapping::{
    MAPPING_CAPTURE_BYTES, MappingCaptureArchive,
};
pub use mapping::{
    MappingCapturePhase, MappingCaptureRecord, MappingCaptureSlot, MappingCaptureSnapshot,
    MappingCaptureStatus,
};

#[cfg(test)]
pub(super) mod tests;

const FACTS: usize = 32;
const STATES: usize = 8;
// The longest successful clone path uses 26 facts: original release 2,
// ENTRY 6, parent/newborn raw captures 5, joined creation/release 3,
// EXIT 4, two bridges 4, transport 1, admission 1. The dedicated failure
// marker is outside this array; overflow never overwrites a committed fact.
const LONGEST_SUCCESS: usize = 26;
const _: () = assert!(LONGEST_SUCCESS <= FACTS);

/// One original provider invocation, unique within its owning session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelAttemptId {
    /// Original owner session identity, not an operating-system PID.
    pub session: u64,
    /// Monotonically issued original execution identity.
    pub invocation: u64,
}

/// Historical stop identity. Unlike DynamicStop this is never a control token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelStopIdentity {
    /// Owning session.
    pub session: u64,
    /// Physical held-stop sequence at this observation.
    pub sequence: u64,
    /// Original task number, meaningful only with its retained incarnation.
    pub tid: i32,
    /// Authenticated logical identity, absent before newborn pairing.
    pub task: Option<crate::lifecycle::TaskId>,
}
impl From<&DynamicStop> for KernelStopIdentity {
    fn from(token: &DynamicStop) -> Self {
        Self {
            session: token.session,
            sequence: token.sequence,
            tid: token.tid,
            task: token.task,
        }
    }
}

/// How the real wait-domain owner pinned the observed kernel incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelPinKind {
    /// Whole-process pidfd acquired by the owning launcher.
    Process,
    /// Explicit PIDFD_THREAD pin acquired before consuming the task wait.
    Thread,
}

/// Distinct preallocated complete-state purposes; never interchangeable phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelStateSlot {
    /// Exact selected instruction input, before source restoration.
    Original,
    /// Actual parent syscall ENTRY stop.
    Entry,
    /// Actual parent CLONE event stop, when present.
    Creation,
    /// Automatic newborn return-ready stop; never a child syscall EXIT.
    Newborn,
    /// Actual parent syscall EXIT stop.
    Exit,
    /// Actual parent neutral return checkpoint.
    ParentBridge,
    /// Actual newborn neutral return checkpoint.
    NewbornBridge,
    /// First unexpected held observation, requiring closure.
    Unexpected,
}
impl KernelStateSlot {
    fn index(self) -> usize {
        self as usize
    }
}

/// A complete initialized native state; partial reads are never exposed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelCapturedState {
    /// Every native general register, flags, segment and kernel bookkeeping field.
    pub registers: RegisterSnapshot,
    /// Complete initialized NT_X86_XSTATE payload of the kernel-reported length.
    pub xstate: Vec<u8>,
    /// Exact eight-byte native signal mask.
    pub signal_mask: u64,
}

/// Closed failure classes. Arbitrary kernel paths/error text are not retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelFailureKind {
    /// The original operation deadline expired.
    Timeout,
    /// A native read/control call failed, with its optional actual OS errno.
    NativeIo(Option<i32>),
    /// An identity, phase, complete state or finite-profile check failed.
    InvalidState,
    /// Reserved fixed journal storage was exhausted.
    Capacity,
    /// The later admission/census/rearming operation refused.
    AdmissionRejected,
    /// Cancellation closed an incomplete invocation.
    Cancelled,
    /// A caught owner unwind left this invocation incomplete.
    CaughtPanic,
    /// An archive critical section unwound; inspection remains incomplete.
    ArchivePoisoned,
    /// A private test-only failure seam was reached.
    Injected,
}

/// Diagnostic phase at failure; it never substitutes for a kernel observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelJournalStage {
    /// Reserved storage is attached; this does not prove any native execution.
    Prepared,
    /// Original release was attempted or acknowledged by ptrace.
    OriginalRelease,
    /// A successful pinned wait delivery is being captured.
    RawCapture,
    /// The actual ENTRY passed the existing transport checks.
    EntryValidation,
    /// The kernel-entering ENTRY release was attempted or acknowledged.
    EntryRelease,
    /// Actual parent/newborn observations were joined to logical identities.
    CreationValidation,
    /// The parent's creation-return release was attempted or acknowledged.
    CreationRelease,
    /// The actual parent EXIT passed the existing transport checks.
    ExitValidation,
    /// A parent neutral return bridge is in progress.
    ParentBridge,
    /// A newborn neutral return bridge is in progress.
    NewbornBridge,
    /// Required return bridges completed, before admission rearming.
    Transport,
    /// Existing final admission/census/rearming checks completed.
    Admission,
    /// Session closure; physical cleanup is an independent writer status.
    Closing,
}

/// A failure retained separately even when all ordinary fact slots are occupied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelJournalFailure {
    /// Last committed diagnostic phase, not a fabricated execution boundary.
    pub stage: KernelJournalStage,
    /// First recorded failure class; later cleanup does not overwrite it.
    pub kind: KernelFailureKind,
}

/// Capture state is committed only after all GPR/XSTATE/mask reads succeed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelCaptureStatus {
    /// The reserved slot has never been used.
    Unused,
    /// A read started but has not committed a complete initialized state.
    InProgress,
    /// Every required read and length check completed.
    Complete,
    /// A read failed; no partial state is exposed as complete.
    Failed(KernelFailureKind),
}

/// An immutable diagnostic projection of one reserved state slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelStateRecord {
    /// Distinct purpose assigned before execution.
    pub slot: KernelStateSlot,
    /// Explicit completeness of this slot.
    pub status: KernelCaptureStatus,
    /// Present only for a complete initialized capture.
    pub state: Option<KernelCapturedState>,
}

/// Initialized GET_SYSCALL_INFO bytes and the actual kernel-reported length.
/// The operation tag is not inferred from a lifecycle event or register value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelSyscallInfo {
    /// Actual kernel return count, independently of the operation tag.
    pub returned_bytes: usize,
    /// Entire zero-initialized native buffer, including untouched padding.
    pub initialized: [u8; 88],
}
impl KernelSyscallInfo {
    /// Actual kernel operation tag; not inferred from lifecycle bookkeeping.
    pub fn operation(&self) -> u8 {
        self.initialized[0]
    }
    fn ip(&self) -> u64 {
        u64::from_ne_bytes(self.initialized[8..16].try_into().unwrap())
    }
    fn sp(&self) -> u64 {
        u64::from_ne_bytes(self.initialized[16..24].try_into().unwrap())
    }
    fn arch(&self) -> u32 {
        u32::from_ne_bytes(self.initialized[4..8].try_into().unwrap())
    }
    fn word(&self, at: usize) -> u64 {
        u64::from_ne_bytes(self.initialized[at..at + 8].try_into().unwrap())
    }
}

/// A request attempt and a successful ptrace request remain distinct facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelReleasePhase {
    /// Release toward the original instruction's actual syscall ENTRY.
    Original,
    /// Release from authenticated ENTRY into the kernel implementation.
    Entry,
    /// Release the parent from its authenticated creation event.
    Creation,
}

/// Ordered immutable facts. Raw wait order is preserved independently of the
/// later Created/Newborn dispatch order. No fact is an execution capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelJournalFact {
    /// Raw successful pinned wait delivery, before lifecycle validation.
    RawStop {
        /// Monotone raw observation ordinal within this invocation.
        record: u8,
        /// Numeric task identifier bound to the retained owner pin.
        tid: i32,
        /// Original wait status, unchanged by logical event classification.
        status: i32,
        /// Kind of actual retained kernel identity.
        pin: KernelPinKind,
        /// Logical identity known at capture; absent for an unjoined newborn.
        task: Option<DynamicTask>,
    },
    /// Actual GET_SYSCALL_INFO result associated with a raw wait.
    SyscallInfo {
        /// Original raw observation ordinal.
        record: u8,
        /// Initialized bytes and actual kernel-reported length.
        info: KernelSyscallInfo,
    },
    /// Actual creation event message, before newborn join validation.
    EventMessage {
        /// Original parent raw observation ordinal.
        record: u8,
        /// Unmodified native event payload.
        value: u64,
    },
    /// All native state reads for this raw wait committed successfully.
    StateCaptured {
        /// Original raw observation ordinal.
        record: u8,
        /// Complete reserved state slot.
        slot: KernelStateSlot,
    },
    /// Release was prepared for the following ptrace call; it may still fail.
    ReleaseAttempt {
        /// Which actual continuation was requested.
        phase: KernelReleasePhase,
        /// Historical exact source stop, never a replay token.
        stop: KernelStopIdentity,
    },
    /// The matching ptrace request returned success; execution remains unknown.
    ReleaseSucceeded {
        /// Which continuation was successfully requested.
        phase: KernelReleasePhase,
        /// Exact source stop matching the preceding attempt.
        stop: KernelStopIdentity,
    },
    /// Captured ENTRY passed original ABI, identity and full-state checks.
    ValidatedEntry {
        /// Original raw ENTRY ordinal.
        record: u8,
        /// Authenticated ENTRY's historical logical stop.
        stop: KernelStopIdentity,
    },
    /// Two previously captured observations passed creation joining.
    ValidatedCreation {
        /// Actual parent creation raw ordinal.
        parent_record: u8,
        /// Actual automatic newborn raw ordinal, regardless of arrival order.
        newborn_record: u8,
        /// Authenticated parent historical stop.
        parent: KernelStopIdentity,
        /// Authenticated newborn historical stop, established only by joining.
        newborn: KernelStopIdentity,
    },
    /// Captured parent EXIT passed the original full-state checks.
    ValidatedExit {
        /// Actual parent EXIT raw ordinal.
        record: u8,
        /// Authenticated EXIT's historical logical stop.
        stop: KernelStopIdentity,
    },
    /// A neutral bridge is about to run; completion is not implied.
    BridgeBegin {
        /// Original EXIT or automatic newborn state ordinal.
        source_record: u8,
        /// Actual task selected for this bridge.
        task: DynamicTask,
    },
    /// An actual bridge returned with every saved state byte preserved.
    BridgeComplete {
        /// Parent or newborn reserved bridge slot.
        slot: KernelStateSlot,
        /// Actual resulting private stop, for diagnostics only.
        stop: KernelStopIdentity,
    },
    /// All required original-return bridges completed; admission is unfinished.
    TransportComplete {
        /// Actual parent return checkpoint.
        parent: KernelStopIdentity,
        /// Actual child return checkpoint for a successful clone, otherwise None.
        newborn: Option<KernelStopIdentity>,
    },
    /// The existing census, source rearm and final admission checks completed.
    AdmissionComplete {
        /// Same logical selected task in its newly rearmed generation.
        task: DynamicTask,
    },
}

/// Archive writer lifetime, separate from each invocation's completion phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelWriterStatus {
    /// The original owner can still append progress facts.
    Active,
    /// The original owner has entered cleanup; no completion is inferred.
    Closing,
    /// The original cleanup function returned its successful physical receipt.
    Cleaned,
    /// Cleanup returned an error; this status does not substitute for pidfd proof.
    FailedCleanup,
}

/// Immutable inspection of an original attempt and its retained prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelAttemptSnapshot {
    /// Exact owning session and original invocation identity.
    pub id: KernelAttemptId,
    /// Historical stop used to prepare this invocation.
    pub original_stop: KernelStopIdentity,
    /// Exact original decode and complete logical input registers.
    pub input: SelectedInput,
    /// Original source/admission generation, never retroactively rewritten.
    pub source_generation: u64,
    /// Original pending plan identity.
    pub source_plan: u64,
    /// Original absolute transaction deadline; journal capture never restarts it.
    pub original_until: Instant,
    /// Full pre-effect lifetime debit for this reserved archive storage.
    pub reserved_bytes: usize,
    /// Ordered committed facts, preserving actual raw capture order.
    pub facts: Vec<KernelJournalFact>,
    /// All eight reserved state purposes with explicit completeness.
    pub states: Vec<KernelStateRecord>,
    /// First failure retained separately from the fixed fact array.
    pub failure: Option<KernelJournalFailure>,
    /// Optional complete/partial raw-map diagnostics. They survive admission
    /// unwind and do not grant a mapping, release or physical-cleanup receipt.
    pub mapping: Option<MappingCaptureSnapshot>,
}

/// Read-only archive snapshot; a terminal observation does not imply cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelProgressSnapshot {
    /// Current owner-side archive lifetime status.
    pub writer: KernelWriterStatus,
    /// True when an archive critical section unwound; no completeness claim follows.
    pub archive_poisoned: bool,
    /// Immutable copies of all attached attempts, including incomplete prefixes.
    pub attempts: Vec<KernelAttemptSnapshot>,
}

/// Diagnostic archive handle. It sends no command and survives closed/dropped
/// sessions in the embedding process. It is not a crash-resistant disk journal.
#[derive(Clone)]
pub struct KernelProgressReader {
    archive: Arc<Mutex<Archive>>,
}
impl KernelProgressReader {
    /// Copy the retained diagnostics without sending a command to the tracer.
    /// A poisoned archive remains readable with an explicit incomplete flag.
    pub fn snapshot(&self) -> KernelProgressSnapshot {
        let (archive, poisoned) = match self.archive.lock() {
            Ok(guard) => (guard, false),
            Err(error) => (error.into_inner(), true),
        };
        KernelProgressSnapshot {
            writer: archive.status,
            archive_poisoned: archive.poisoned || poisoned,
            attempts: archive.attempts.iter().map(Attempt::snapshot).collect(),
        }
    }
}

struct StateBuffer {
    bytes: Option<Vec<u8>>,
    length: usize,
    registers: Option<RegisterSnapshot>,
    mask: u64,
    status: KernelCaptureStatus,
}
impl StateBuffer {
    fn new() -> Result<Self, LaunchError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_XSTATE)
            .map_err(|_| invalid("kernel journal state allocation failed"))?;
        bytes.resize(MAX_XSTATE, 0);
        Ok(Self {
            bytes: Some(bytes),
            length: 0,
            registers: None,
            mask: 0,
            status: KernelCaptureStatus::Unused,
        })
    }
    fn snapshot(&self, slot: KernelStateSlot) -> KernelStateRecord {
        let state = if self.status == KernelCaptureStatus::Complete {
            Some(KernelCapturedState {
                registers: self.registers.expect("committed complete registers"),
                xstate: self.bytes.as_ref().expect("committed complete buffer")[..self.length]
                    .to_vec(),
                signal_mask: self.mask,
            })
        } else {
            None
        };
        KernelStateRecord {
            slot,
            status: self.status,
            state,
        }
    }
}

#[derive(Clone)]
pub(super) struct KernelAttemptBinding {
    pub(super) pending: PendingToken,
    pub(super) original_stop: AdmissionStop,
    pub(super) input: SelectedInput,
    pub(super) before: TaskStateSnapshot,
    pub(super) until: Instant,
}

struct Attempt {
    binding: KernelAttemptBinding,
    id: KernelAttemptId,
    charge: usize,
    facts: [Option<KernelJournalFact>; FACTS],
    length: usize,
    states: [StateBuffer; STATES],
    raw_slots: [Option<u8>; STATES],
    raw_count: u8,
    stage: KernelJournalStage,
    failure: Option<KernelJournalFailure>,
    mapping: Option<MappingCaptureArchive>,
}
impl Attempt {
    fn append(&mut self, fact: KernelJournalFact) -> Result<(), LaunchError> {
        if self.failure.is_some() {
            return Err(invalid("kernel journal attempt is closed"));
        }
        if self.length == FACTS {
            self.fail(KernelFailureKind::Capacity);
            return Err(invalid("kernel journal fact capacity exhausted"));
        }
        self.facts[self.length] = Some(fact);
        self.length += 1;
        Ok(())
    }
    fn fail(&mut self, kind: KernelFailureKind) {
        if self.failure.is_none() {
            self.failure = Some(KernelJournalFailure {
                stage: self.stage,
                kind,
            });
        }
    }
    fn facts(&self) -> impl Iterator<Item = &KernelJournalFact> {
        self.facts[..self.length]
            .iter()
            .map(|fact| fact.as_ref().unwrap())
    }
    fn snapshot(&self) -> KernelAttemptSnapshot {
        let slots = [
            KernelStateSlot::Original,
            KernelStateSlot::Entry,
            KernelStateSlot::Creation,
            KernelStateSlot::Newborn,
            KernelStateSlot::Exit,
            KernelStateSlot::ParentBridge,
            KernelStateSlot::NewbornBridge,
            KernelStateSlot::Unexpected,
        ];
        KernelAttemptSnapshot {
            id: self.id,
            original_stop: (&self.binding.original_stop.token).into(),
            input: self.binding.input.clone(),
            source_generation: self.binding.pending.epoch,
            source_plan: self.binding.pending.plan,
            original_until: self.binding.until,
            reserved_bytes: self.charge,
            facts: self.facts().copied().collect(),
            states: slots
                .into_iter()
                .map(|slot| self.states[slot.index()].snapshot(slot))
                .collect(),
            failure: self.failure,
            mapping: self.mapping.as_ref().map(MappingCaptureArchive::snapshot),
        }
    }
}

struct Archive {
    session: u64,
    status: KernelWriterStatus,
    poisoned: bool,
    attempts: Vec<Attempt>,
}

/// Prepared storage is not attached and grants no native execution authority.
pub(super) struct PreparedKernelAttempt {
    archive: Arc<Mutex<Archive>>,
    attempt: Attempt,
}
impl PreparedKernelAttempt {
    pub(super) fn retained_bytes(&self) -> usize {
        self.attempt.charge
    }
}

/// Private one-use archive reference. Identity equality never grants release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic) struct KernelAttemptHandle {
    id: KernelAttemptId,
    index: usize,
}
impl KernelAttemptHandle {
    pub(super) fn id(self) -> KernelAttemptId {
        self.id
    }
}

pub(in crate::linux::remote::dynamic) struct KernelJournalWriter {
    archive: Arc<Mutex<Archive>>,
    active: Option<KernelAttemptHandle>,
    _thread: PhantomData<Rc<()>>,
}

fn invalid(message: &'static str) -> LaunchError {
    LaunchError::Invalid(message)
}
pub(super) fn failure_kind(error: &LaunchError) -> KernelFailureKind {
    match error {
        LaunchError::Timeout(_) => KernelFailureKind::Timeout,
        LaunchError::Invalid("dynamic operation cancelled") => KernelFailureKind::Cancelled,
        LaunchError::System { source, .. } => KernelFailureKind::NativeIo(source.raw_os_error()),
        _ => KernelFailureKind::InvalidState,
    }
}

pub(super) struct JournalUnwind {
    archive: Arc<Mutex<Archive>>,
}
impl Drop for JournalUnwind {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let mut archive = match self.archive.lock() {
            Ok(guard) => guard,
            Err(error) => {
                let mut guard = error.into_inner();
                guard.poisoned = true;
                guard
            }
        };
        if let Some(attempt) = archive.attempts.last_mut() {
            if !attempt
                .facts()
                .any(|fact| matches!(fact, KernelJournalFact::AdmissionComplete { .. }))
            {
                attempt.fail(KernelFailureKind::CaughtPanic);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum InvocationProfile {
    Ordinary,
    Mapping,
}

impl KernelJournalWriter {
    pub(in crate::linux::remote::dynamic) fn new(session: u64) -> Self {
        Self {
            archive: Arc::new(Mutex::new(Archive {
                session,
                status: KernelWriterStatus::Active,
                poisoned: false,
                attempts: Vec::new(),
            })),
            active: None,
            _thread: PhantomData,
        }
    }
    pub(in crate::linux::remote::dynamic) fn reader(&self) -> KernelProgressReader {
        KernelProgressReader {
            archive: Arc::clone(&self.archive),
        }
    }
    pub(super) fn panic_scope(&self) -> JournalUnwind {
        JournalUnwind {
            archive: Arc::clone(&self.archive),
        }
    }
    pub(super) fn fail_gate(&mut self, error: &crate::gate::GateError) {
        self.fail_active(match error {
            crate::gate::GateError::Control(error) => failure_kind(error),
            _ => KernelFailureKind::AdmissionRejected,
        });
    }
    fn lock(&self) -> MutexGuard<'_, Archive> {
        match self.archive.lock() {
            Ok(guard) => guard,
            Err(error) => {
                let mut guard = error.into_inner();
                guard.poisoned = true;
                guard
            }
        }
    }
    fn attempt_mut(
        archive: &mut Archive,
        handle: KernelAttemptHandle,
    ) -> Result<&mut Attempt, LaunchError> {
        if archive.session != handle.id.session
            || archive.poisoned
            || archive.status != KernelWriterStatus::Active
        {
            return Err(invalid(
                "kernel journal archive is foreign, closed or poisoned",
            ));
        }
        let attempt = archive
            .attempts
            .get_mut(handle.index)
            .ok_or(invalid("kernel journal handle is absent"))?;
        if attempt.id != handle.id {
            return Err(invalid("kernel journal handle identity differs"));
        }
        Ok(attempt)
    }
    pub(super) fn prepare(
        &mut self,
        binding: KernelAttemptBinding,
    ) -> Result<PreparedKernelAttempt, LaunchError> {
        self.prepare_profile(binding, InvocationProfile::Ordinary)
    }
    pub(super) fn prepare_mapping(
        &mut self,
        binding: KernelAttemptBinding,
    ) -> Result<PreparedKernelAttempt, LaunchError> {
        self.prepare_profile(binding, InvocationProfile::Mapping)
    }
    fn prepare_profile(
        &mut self,
        binding: KernelAttemptBinding,
        profile: InvocationProfile,
    ) -> Result<PreparedKernelAttempt, LaunchError> {
        let number = binding.input.registers().rax;
        // These disjoint finite lists bound observations, not execution. The
        // caller authenticates its native policy before preparing evidence and
        // original release. Mapping opt-in must not widen ordinary preparation.
        let permitted = match profile {
            InvocationProfile::Ordinary => matches!(
                number as libc::c_long,
                libc::SYS_getpid
                    | libc::SYS_gettid
                    | libc::SYS_exit
                    | libc::SYS_exit_group
                    | libc::SYS_clone
                    | libc::SYS_rt_sigaction
                    | libc::SYS_sigaltstack
            ),
            InvocationProfile::Mapping => matches!(
                number as libc::c_long,
                libc::SYS_mmap | libc::SYS_mprotect | libc::SYS_munmap
            ),
        };
        if !matches!(
            binding.input.instruction().operation(),
            Operation::Syscall {
                abi: SyscallAbi::LinuxX64
            }
        ) || !permitted
            || number > i32::MAX as u64
            || number & 0x4000_0000 != 0
            || binding.pending.invocation == 0
            || binding.pending.stop.session == 0
            || binding.pending.stop.tid <= 0
            || binding.pending.stop != binding.original_stop.token
            || binding.pending.task != binding.original_stop.identity
            || binding.pending.epoch != binding.pending.task.generation
            || binding.original_stop.token.task != Some(binding.original_stop.identity.task)
            || binding.original_stop.signal.is_some()
            || !matches!(
                binding.original_stop.phase,
                trusted::AdmissionPhase::Restored | trusted::AdmissionPhase::EntryReady
            )
            || binding.before.registers != *binding.input.registers()
            || binding.before.xstate.len() < 512
            || binding.before.xstate.len() >= MAX_XSTATE
            || binding.input.instruction().bytes().is_empty()
            || binding.input.instruction().bytes().len() > 15
            || binding.before.registers.rip != binding.input.instruction().logical_pc()
            || self.active.is_some()
        {
            return Err(invalid(
                "kernel journal binding is not an exact finite invocation",
            ));
        }
        let id = KernelAttemptId {
            session: binding.pending.stop.session,
            invocation: binding.pending.invocation,
        };
        let capacity_charge = {
            let mut archive = self.lock();
            if archive.status != KernelWriterStatus::Active
                || archive.session != id.session
                || archive.poisoned
                || archive
                    .attempts
                    .iter()
                    .any(|attempt| attempt.id.invocation >= id.invocation)
            {
                return Err(invalid("kernel journal invocation is stale or foreign"));
            }
            let capacity = archive.attempts.capacity();
            archive
                .attempts
                .try_reserve_exact(1)
                .map_err(|_| invalid("kernel journal archive allocation failed"))?;
            archive
                .attempts
                .capacity()
                .saturating_sub(capacity)
                .max(1)
                .checked_mul(std::mem::size_of::<Attempt>())
                .ok_or(invalid("kernel journal archive charge overflows"))?
        };
        let mut states = Vec::new();
        states
            .try_reserve_exact(STATES)
            .map_err(|_| invalid("kernel journal slots allocation failed"))?;
        for _ in 0..STATES {
            states.push(StateBuffer::new()?);
        }
        let mut charge = capacity_charge
            .checked_add(
                std::mem::size_of::<Archive>()
                    + std::mem::size_of::<KernelJournalWriter>()
                    + std::mem::size_of::<PreparedKernelAttempt>(),
            )
            .ok_or(invalid("kernel journal charge overflows"))?;
        for state in &states {
            charge = charge
                .checked_add(state.bytes.as_ref().unwrap().capacity())
                .ok_or(invalid("kernel journal charge overflows"))?;
        }
        charge = charge
            .checked_add(binding.before.xstate.capacity())
            .and_then(|value| value.checked_add(binding.input.instruction().bytes().len()))
            .ok_or(invalid("kernel journal input charge overflows"))?;
        let first = &mut states[0];
        first.bytes.as_mut().unwrap()[..binding.before.xstate.len()]
            .copy_from_slice(&binding.before.xstate);
        first.length = binding.before.xstate.len();
        first.registers = Some(binding.before.registers);
        first.mask = binding.before.mask;
        first.status = KernelCaptureStatus::Complete;
        let states: [StateBuffer; STATES] = states
            .try_into()
            .map_err(|_| invalid("kernel journal slot shape differs"))?;
        Ok(PreparedKernelAttempt {
            archive: Arc::clone(&self.archive),
            attempt: Attempt {
                binding,
                id,
                charge,
                facts: [None; FACTS],
                length: 0,
                states,
                raw_slots: [None; STATES],
                raw_count: 0,
                stage: KernelJournalStage::Prepared,
                failure: None,
                mapping: None,
            },
        })
    }
    /// Caller has already debited this exact retained charge from its census.
    pub(super) fn attach(
        &mut self,
        prepared: PreparedKernelAttempt,
    ) -> Result<KernelAttemptHandle, LaunchError> {
        if self.active.is_some() || !Arc::ptr_eq(&prepared.archive, &self.archive) {
            return Err(invalid(
                "kernel journal prepared attempt is foreign or already active",
            ));
        }
        let handle = {
            let mut archive = self.lock();
            let id = prepared.attempt.id;
            if archive.status != KernelWriterStatus::Active
                || archive.poisoned
                || id.session != archive.session
                || archive.attempts.len() == archive.attempts.capacity()
                || archive
                    .attempts
                    .iter()
                    .any(|attempt| attempt.id.invocation >= id.invocation)
            {
                return Err(invalid("kernel journal prepared invocation cannot attach"));
            }
            let handle = KernelAttemptHandle {
                id,
                index: archive.attempts.len(),
            };
            archive.attempts.push(prepared.attempt);
            handle
        };
        self.active = Some(handle);
        Ok(handle)
    }
    fn append(
        &mut self,
        handle: KernelAttemptHandle,
        fact: KernelJournalFact,
    ) -> Result<(), LaunchError> {
        if self.active != Some(handle) {
            return Err(invalid("kernel journal handle is not active"));
        }
        Self::attempt_mut(&mut self.lock(), handle)?.append(fact)
    }
    pub(super) fn fail_active(&mut self, kind: KernelFailureKind) {
        let Some(handle) = self.active else {
            return;
        };
        let mut archive = self.lock();
        if let Some(attempt) = archive.attempts.get_mut(handle.index) {
            if attempt.id == handle.id {
                attempt.fail(kind);
            }
        }
    }
    pub(super) fn close(&mut self, status: KernelWriterStatus, kind: Option<KernelFailureKind>) {
        if let Some(kind) = kind {
            self.fail_active(kind);
        }
        self.lock().status = status;
    }
    pub(super) fn finish_admission(
        &mut self,
        handle: KernelAttemptHandle,
        task: DynamicTask,
    ) -> Result<(), LaunchError> {
        {
            let mut archive = self.lock();
            let attempt = Self::attempt_mut(&mut archive, handle)?;
            if self.active != Some(handle)
                || attempt.failure.is_some()
                || !attempt
                    .facts()
                    .any(|fact| matches!(fact, KernelJournalFact::TransportComplete { .. }))
                || task.task != attempt.binding.pending.task.task
                || task.process != attempt.binding.pending.task.process
                || task.address_space != attempt.binding.pending.task.address_space
                || task.generation <= attempt.binding.pending.epoch
            {
                return Err(invalid(
                    "kernel journal lacks a rearmed completed invocation",
                ));
            }
            attempt.stage = KernelJournalStage::Admission;
            attempt.append(KernelJournalFact::AdmissionComplete { task })?;
        }
        self.active = None;
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod fault;

mod capture;
mod validation;
