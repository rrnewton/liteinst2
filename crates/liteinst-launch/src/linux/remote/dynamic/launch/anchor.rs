//! Opt-in initial exception metadata from a genuine pre-exec signal frame.
//!
//! The helper never executes rt_sigreturn. Its real syscall stops, signal
//! delivery and AnchorReady write are owned under the original launch deadline.
//! This is a private launch prerequisite, not signal admission or cleanup proof.
use super::super::owner::trusted::TaskStateSnapshot;
use super::*;

mod archive;
mod certificate;
mod protocol;
mod raw;
mod reset;
mod start;
mod storage;
pub(in crate::linux::remote::dynamic) use archive::AnchorArchive;
pub use archive::{AnchorFailure, AnchorProgress, AnchorReader};
pub use certificate::RseqObservation as AnchorRseqObservation;
pub use protocol::SyscallObservation as AnchorSyscallObservation;
pub(in crate::linux::remote::dynamic) use reset::ResetLaunch;
pub use reset::{AnchorResetObservation, AnchorResetPhase};
pub(super) use start::start;

pub(in crate::linux::remote::dynamic) const ANCHOR_EVIDENCE_BOUND: usize = 6 * 1024 * 1024;
const MAX_STOPS: usize = 64;
const MAX_XSTATE: usize = 64 * 1024;
const STACK_BYTES: usize = 128 * 1024;
const FRAME_BYTES: usize = 72 * 1024;
const PROBE_SIGNAL: i32 = 44;
const BLOCKED: u64 = !(1_u64 << (libc::SIGKILL - 1)) & !(1_u64 << (libc::SIGSTOP - 1));
const MAGIC: u64 = 0x4c49_3241_4e43_4831;

#[derive(Clone, Copy, Debug)]
pub(in crate::linux::remote::dynamic) struct AnchorRequest {
    allowance: usize,
}
impl AnchorRequest {
    pub(in crate::linux::remote::dynamic) fn new(
        source_fact_allowance: usize,
    ) -> Result<Self, LaunchError> {
        if source_fact_allowance < ANCHOR_EVIDENCE_BOUND {
            return Err(LaunchError::Invalid(
                "initial exception anchor exceeds reserved source facts",
            ));
        }
        Ok(Self {
            allowance: ANCHOR_EVIDENCE_BOUND,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic) struct ExceptionMetadata {
    pub(in crate::linux::remote::dynamic) trapno: u64,
    pub(in crate::linux::remote::dynamic) error_code: u64,
    pub(in crate::linux::remote::dynamic) cr2: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Requested capture stage. A row separately says whether its phase passed
/// authentication; an unexpected raw stop retains the stage being attempted.
pub enum AnchorPhase {
    /// First actual SEIZE interruption.
    InitialControl,
    /// Expected native syscall ENTRY.
    SyscallEntry,
    /// Expected native syscall EXIT.
    SyscallExit,
    /// Expected genuine queued self-signal delivery.
    ProbeDelivery,
    /// Expected actual AnchorReady write EXIT.
    AnchorWriteExit,
    /// Raw initial EXEC event before application-mask restoration.
    ExecEvent,
    /// Same held EXEC after exact application-mask restoration.
    ExecMaskRestored,
    /// Read-only capture of the later actual initial exec syscall stop.
    ExecExit,
}

/// Which native reads completed; initialized partial buffers remain diagnostic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnchorCaptureProgress {
    /// GETREGS returned success.
    pub registers_read: bool,
    /// Actual GETREGSET result, absent until attempted.
    pub xstate_result: Option<i64>,
    /// Actual errno when GETREGSET returned -1.
    pub xstate_errno: Option<i32>,
    /// Initialized iovec length after the attempted GETREGSET.
    pub xstate_length: Option<usize>,
    /// GETSIGMASK returned success.
    pub mask_read: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One bounded launch observation; partial captures never authorize release.
pub struct AnchorObservation {
    phase: AnchorPhase,
    tid: i32,
    status: Option<i32>,
    complete: bool,
    authenticated: bool,
    capture: AnchorCaptureProgress,
    state: AnchorCapturedState,
    syscall: Option<protocol::SyscallObservation>,
}
impl AnchorObservation {
    fn allocate() -> Result<Self, LaunchError> {
        let mut extended = Vec::new();
        extended
            .try_reserve_exact(MAX_XSTATE)
            .map_err(|_| LaunchError::Invalid("reserve anchor extended state"))?;
        extended.resize(MAX_XSTATE, 0);
        let registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        Ok(Self {
            phase: AnchorPhase::InitialControl,
            tid: 0,
            status: None,
            complete: false,
            authenticated: false,
            capture: AnchorCaptureProgress::default(),
            state: AnchorCapturedState {
                registers: registers.into(),
                xstate: extended,
                mask: 0,
            },
            syscall: None,
        })
    }
    /// Diagnostic expected phase; only `state()` identifies a complete capture.
    pub fn phase(&self) -> AnchorPhase {
        self.phase
    }
    /// Whether the observed phase passed the corresponding native checks.
    /// This does not mean the whole launch or its cleanup completed.
    pub fn phase_authenticated(&self) -> bool {
        self.authenticated
    }
    /// Actual consumed wait status, never a physical-reap receipt.
    pub fn status(&self) -> Option<i32> {
        self.status
    }
    /// Actual wait identity under the original owner, never new numeric authority.
    pub fn tid(&self) -> i32 {
        self.tid
    }
    /// Complete initialized capture, absent when a native read failed.
    pub fn state(&self) -> Option<&AnchorCapturedState> {
        self.complete.then_some(&self.state)
    }
    /// Read progress, including failed native extended-state reads.
    pub fn capture_progress(&self) -> AnchorCaptureProgress {
        self.capture
    }
    /// Initialized buffers even after failure. Only fields named complete by
    /// capture_progress were read successfully; this is not complete state.
    pub fn initialized_state(&self) -> &AnchorCapturedState {
        &self.state
    }
    /// Initialized syscall-info result, which may precede a failed state read.
    pub fn syscall(&self) -> Option<&AnchorSyscallObservation> {
        self.syscall.as_ref()
    }
}

/// Complete native state retained by the private launch observer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorCapturedState {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    mask: u64,
}
impl AnchorCapturedState {
    /// Every native general register and kernel register bookkeeping field.
    pub fn registers(&self) -> RegisterSnapshot {
        self.registers
    }
    /// Complete kernel-reported extended-state bytes, without normalization.
    pub fn xstate(&self) -> &[u8] {
        &self.xstate
    }
    /// Exact eight-byte native mask observed at this stop.
    pub fn signal_mask(&self) -> u64 {
        self.mask
    }
}

pub(in crate::linux::remote::dynamic) struct InitialExceptionMetadata {
    session: u64,
    tid: i32,
    metadata: ExceptionMetadata,
    exec_event: usize,
    archive: AnchorArchive,
}
impl InitialExceptionMetadata {
    pub(in crate::linux::remote::dynamic) fn metadata(&self) -> ExceptionMetadata {
        self.metadata
    }
    pub(in crate::linux::remote::dynamic) fn session(&self) -> u64 {
        self.session
    }
    pub(in crate::linux::remote::dynamic) fn tid(&self) -> i32 {
        self.tid
    }
    /// Capture at the owner's initial-exec syscall-stop seam, before that
    /// seam's fallible phase/equality interpretation. No wait status is invented:
    /// this row is an inspection of the already-held original task.
    pub(in crate::linux::remote::dynamic) fn capture_exec_exit(
        &self,
        tid: i32,
    ) -> Result<(), LaunchError> {
        let captured =
            protocol::capture_current(&self.archive, self.tid, tid, None, AnchorPhase::ExecExit);
        // Preserve the independent raw rseq result even if the initialized
        // syscall/state capture later refuses its phase or completeness.
        let needs_rseq = tid == self.tid && self.archive.data().rseq_observations[2].is_none();
        if needs_rseq {
            let configured = certificate::observe_configuration(tid);
            self.archive.data().rseq_observations[2] = Some(configured);
        }
        captured.map(|_| ())
    }
    /// Read-only authentication at the caller's genuine initial exec EXIT.
    /// The owner authenticates the actual EXIT and exact EXEC→EXIT full state
    /// first. No old-mm pointer is dereferenced after exec.
    pub(in crate::linux::remote::dynamic) fn authenticate_exec_exit(
        &self,
        tid: i32,
        exit: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        let mut data = self.archive.data();
        let index = data.exec_exit_index.ok_or(LaunchError::Invalid(
            "exception anchor initial EXIT was not captured",
        ))?;
        let configured = data.rseq_observations[2].ok_or(LaunchError::Invalid(
            "exception anchor EXIT rseq read missing",
        ))?;
        if tid != self.tid
            || self.exec_event >= index
            || !data.complete
            || data.exec_exit_authenticated
        {
            return Err(LaunchError::Invalid(
                "exception anchor exec identity differs",
            ));
        }
        let current = &data.observations[index];
        protocol::authenticate_exec_exit(current)?;
        let last = &data.observations[self.exec_event];
        let mut expected = last.state.registers;
        expected.rax = 0;
        if !last.complete
            || last.phase != AnchorPhase::ExecMaskRestored
            || exit.registers != expected
            || exit.xstate != last.state.xstate
            || exit.mask != last.state.mask
            || current.state.registers != exit.registers
            || current.state.xstate != exit.xstate
            || current.state.mask != exit.mask
        {
            return Err(LaunchError::Invalid(
                "exception anchor actual exec EXIT differs",
            ));
        }
        let before = read_registers(tid)?;
        if before != exit.registers
            || !configured.configuration()?.is_zero()
            || read_registers(tid)? != before
        {
            return Err(LaunchError::Invalid(
                "exception anchor exec rseq reset did not authenticate",
            ));
        }
        data.observations[index].authenticated = true;
        data.exec_exit_authenticated = true;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct ChildConfig {
    context: *mut storage::Context,
    channel: i32,
    parent_channel: i32,
}
impl ChildConfig {
    pub(super) unsafe fn close_all(self) {
        unsafe {
            libc::syscall(libc::SYS_close, self.channel);
            libc::syscall(libc::SYS_close, self.parent_channel);
        }
    }
    pub(super) unsafe fn run(self) -> ! {
        unsafe { raw::enter(self.context) }
    }
}
