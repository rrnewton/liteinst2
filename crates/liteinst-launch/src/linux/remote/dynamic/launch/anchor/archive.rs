//! Fixed, pre-effect diagnostic storage. A reader never grants launch authority.
use super::*;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// First closed failure class; native facts already retained are not discarded.
pub enum AnchorFailure {
    /// A finite-profile or native-state check refused.
    Invalid,
    /// A native operation failed, retaining its actual optional errno.
    NativeIo(Option<i32>),
    /// A real child wait status did not match the required launch phase.
    Child(i32),
    /// The original launch deadline expired.
    Timeout,
    /// The launch scope ended without committing its anchor receipt.
    Incomplete,
    /// The owner unwound while the anchor was incomplete.
    Panic,
    /// A capture critical section unwound; complete evidence is not claimed.
    Poisoned,
}

/// Copied diagnostic facts. Complete anchor and physical cleanup are separate.
#[derive(Clone, Debug)]
pub struct AnchorProgress {
    /// Owning session identity, with no control authority.
    pub session: u64,
    /// Ordered fixed reset-launch facts, retained across handoff failures.
    pub reset: Vec<super::AnchorResetObservation>,
    /// More reset facts occurred than the finite retained prefix could hold.
    pub reset_overflow: bool,
    /// Ordered actual wait/current-stop captures, including incomplete reads.
    pub observations: Vec<AnchorObservation>,
    /// Actual observed signal-frame address, zero until observed.
    pub frame_start: u64,
    /// Exact initialized PEEKDATA prefix retained even if the read failed.
    pub frame: Vec<u8>,
    /// Complete bounded original frame passed native-layout/state checks.
    pub frame_complete: bool,
    /// Exact prefix reread while held after restoring the helper signal state.
    pub restored_frame: Vec<u8>,
    /// Complete reread equals the retained original frame byte for byte.
    pub restored_frame_complete: bool,
    /// Actual initial/recheck/exec-EXIT kernel rseq query results in order.
    pub rseq: Vec<super::AnchorRseqObservation>,
    /// Actual exec EXIT and zero rseq registration authenticated separately.
    pub exec_exit_authenticated: bool,
    /// Initialized GETSIGINFO buffer, including a failed partial read.
    pub raw_signal: Option<[u8; 128]>,
    /// The stored GETSIGINFO buffer came from a successful native read.
    pub signal_read_complete: bool,
    /// Actual errno for a failed GETSIGINFO attempt, if available.
    pub signal_read_errno: Option<i32>,
    /// Validated original frame tuple [trap number, error code, CR2].
    pub metadata: Option<[u64; 3]>,
    /// Metadata anchor reached held EXEC; not a whole signal transaction pass.
    pub complete: bool,
    /// First launch/capture failure, independent of physical cleanup.
    pub failure: Option<AnchorFailure>,
    /// Owner's independent final physical-cleanup outcome, if available.
    pub cleanup_complete: Option<bool>,
}

pub(super) struct Data {
    pub(super) session: u64,
    pub(super) reset: [Option<super::AnchorResetObservation>; 16],
    pub(super) reset_length: usize,
    pub(super) reset_overflow: bool,
    pub(super) observations: Vec<AnchorObservation>,
    pub(super) observed: usize,
    pub(super) frame: Vec<u8>,
    pub(super) frame_length: usize,
    pub(super) frame_start: u64,
    pub(super) frame_complete: bool,
    pub(super) frame_check: Vec<u8>,
    pub(super) frame_check_length: usize,
    pub(super) frame_check_complete: bool,
    pub(super) rseq_observations: [Option<certificate::RseqObservation>; 3],
    pub(super) exec_exit_authenticated: bool,
    pub(super) exec_exit_index: Option<usize>,
    pub(super) code: Vec<u8>,
    pub(super) raw_signal: Option<[u8; 128]>,
    pub(super) signal_read_complete: bool,
    pub(super) signal_read_errno: Option<i32>,
    pub(super) metadata: Option<ExceptionMetadata>,
    pub(super) prepared: Option<storage::Context>,
    pub(super) restored: Option<storage::Context>,
    pub(super) rseq: Option<certificate::RseqEvidence>,
    pub(super) complete: bool,
    failure: Option<AnchorFailure>,
    cleanup_complete: Option<bool>,
    retained: usize,
}

#[derive(Clone)]
pub(in crate::linux::remote::dynamic) struct AnchorArchive(Arc<Mutex<Data>>);
#[derive(Clone)]
/// Diagnostic handle retained across constructor errors and owner unwinding.
pub struct AnchorReader(AnchorArchive);

fn bytes(count: usize) -> Result<Vec<u8>, LaunchError> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(count)
        .map_err(|_| LaunchError::Invalid("reserve fixed anchor evidence"))?;
    value.resize(count, 0);
    Ok(value)
}
fn failure_kind(error: &LaunchError) -> AnchorFailure {
    match error {
        LaunchError::Invalid(_) => AnchorFailure::Invalid,
        LaunchError::System { source, .. } => AnchorFailure::NativeIo(source.raw_os_error()),
        LaunchError::Child { status } => AnchorFailure::Child(*status),
        LaunchError::Timeout(_) => AnchorFailure::Timeout,
    }
}
impl AnchorArchive {
    pub(in crate::linux::remote::dynamic) fn new(
        request: AnchorRequest,
        session: u64,
    ) -> Result<Self, LaunchError> {
        if request.allowance != ANCHOR_EVIDENCE_BOUND || session == 0 {
            return Err(LaunchError::Invalid("invalid fixed anchor reservation"));
        }
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_STOPS)
            .map_err(|_| LaunchError::Invalid("reserve anchor stop slots"))?;
        for _ in 0..MAX_STOPS {
            observations.push(AnchorObservation::allocate()?);
        }
        let frame = bytes(FRAME_BYTES)?;
        let frame_check = bytes(FRAME_BYTES)?;
        let code = bytes(16 * 1024)?;
        let retained = std::mem::size_of::<Data>() + observations.capacity() * std::mem::size_of::<AnchorObservation>()
            + observations.iter().map(|o| o.state.xstate.capacity()).sum::<usize>()
            + frame.capacity() + frame_check.capacity() + code.capacity()
            // Both bounded private stacks, context mappings and fixed recovery
            // buffers are reserved before clone; no later allowance increase.
            + 512 * 1024
            + std::mem::size_of::<Mutex<Data>>() + 2 * std::mem::size_of::<usize>();
        if retained > request.allowance {
            return Err(LaunchError::Invalid(
                "fixed anchor evidence exceeds prior allowance",
            ));
        }
        Ok(Self(Arc::new(Mutex::new(Data {
            session,
            reset: [None; 16],
            reset_length: 0,
            reset_overflow: false,
            observations,
            observed: 0,
            frame,
            frame_length: 0,
            frame_start: 0,
            frame_complete: false,
            frame_check,
            frame_check_length: 0,
            frame_check_complete: false,
            code,
            rseq_observations: [None; 3],
            exec_exit_authenticated: false,
            exec_exit_index: None,
            raw_signal: None,
            signal_read_complete: false,
            signal_read_errno: None,
            metadata: None,
            prepared: None,
            restored: None,
            rseq: None,
            complete: false,
            failure: None,
            cleanup_complete: None,
            retained,
        }))))
    }
    pub(super) fn data(&self) -> MutexGuard<'_, Data> {
        match self.0.lock() {
            Ok(data) => data,
            Err(poison) => {
                let mut data = poison.into_inner();
                data.failure.get_or_insert(AnchorFailure::Poisoned);
                data.complete = false;
                data
            }
        }
    }
    pub(in crate::linux::remote::dynamic) fn reader(&self) -> AnchorReader {
        AnchorReader(self.clone())
    }
    pub(in crate::linux::remote::dynamic) fn session(&self) -> u64 {
        self.data().session
    }
    pub(in crate::linux::remote::dynamic) fn retained_bytes(&self) -> usize {
        self.data().retained
    }
    pub(in crate::linux::remote::dynamic) fn record_failure(&self, error: &LaunchError) {
        self.fail(failure_kind(error));
    }
    /// Constructor errors after authenticated initial EXIT remain constructor
    /// errors but cannot erase the independently completed anchor. The test and
    /// update share this lock with EXIT authentication, including client races.
    pub(in crate::linux::remote::dynamic) fn record_initial_failure(&self, error: &LaunchError) {
        let mut data = self.data();
        if !data.exec_exit_authenticated {
            data.failure.get_or_insert(failure_kind(error));
            data.complete = false;
        }
    }
    pub(in crate::linux::remote::dynamic) fn record_panic(&self) {
        self.fail(AnchorFailure::Panic);
    }
    pub(in crate::linux::remote::dynamic) fn record_cleanup(&self, complete: bool) {
        self.data().cleanup_complete = Some(complete);
    }
    fn fail(&self, failure: AnchorFailure) {
        let mut data = self.data();
        data.failure.get_or_insert(failure);
        data.complete = false;
    }
    pub(super) fn guard(&self) -> Guard {
        Guard {
            archive: self.clone(),
            committed: false,
        }
    }
}
impl AnchorReader {
    /// Copy the bounded in-memory archive without requesting tracer execution.
    /// Neither complete state nor a complete anchor is a cleanup receipt.
    pub fn snapshot(&self) -> AnchorProgress {
        let data = self.0.data();
        AnchorProgress {
            session: data.session,
            reset: data.reset[..data.reset_length]
                .iter()
                .flatten()
                .copied()
                .collect(),
            reset_overflow: data.reset_overflow,
            observations: data.observations[..data.observed].to_vec(),
            frame_start: data.frame_start,
            frame: data.frame[..data.frame_length].to_vec(),
            frame_complete: data.frame_complete,
            restored_frame: data.frame_check[..data.frame_check_length].to_vec(),
            restored_frame_complete: data.frame_check_complete,
            rseq: data.rseq_observations.iter().flatten().copied().collect(),
            exec_exit_authenticated: data.exec_exit_authenticated,
            raw_signal: data.raw_signal,
            signal_read_complete: data.signal_read_complete,
            signal_read_errno: data.signal_read_errno,
            metadata: data.metadata.map(|m| [m.trapno, m.error_code, m.cr2]),
            complete: data.complete,
            failure: data.failure,
            cleanup_complete: data.cleanup_complete,
        }
    }
}
pub(super) struct Guard {
    archive: AnchorArchive,
    committed: bool,
}
impl Guard {
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.committed {
            self.archive.fail(if std::thread::panicking() {
                AnchorFailure::Panic
            } else {
                AnchorFailure::Incomplete
            });
        }
    }
}
