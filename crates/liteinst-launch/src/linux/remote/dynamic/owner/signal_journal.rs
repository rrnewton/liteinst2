//! Preallocated signal evidence owned outside the movable admission transaction.
//! Facts are diagnostic only; actual exclusion and typed frame routes live in
//! the owner. No snapshot permits replay, resume or a native state mutation.
use super::trusted::TaskStateSnapshot;
use super::*;
use std::sync::{Mutex, MutexGuard};

// Fixed physical records. A raw stop stores its exact wait/info/state linkage
// together, and public snapshots losslessly expand those three logical facts.
const FACT_SLOTS: usize = 64;
const STATE_SLOTS: usize = 16;
const FRAME_SLOTS: usize = 32;
pub(in crate::linux::remote::dynamic) const FRAME_BOUND: usize = MAX_XSTATE + 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalJournalPhase {
    Prepared,
    DeliveryPending,
    DeliveryRelease,
    HandlerFetch,
    FrameCapture,
    Projection,
    HandlerGuard,
    HandlerReady,
    FrameRevalidation,
    ReturnEntry,
    ReturnRelease,
    ReturnObserved,
    ReturnBridge,
    ReturnRearmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalJournalFailure {
    Timeout,
    NativeIo(Option<i32>),
    InvalidState,
    Capacity,
    Cancelled,
    CaughtPanic,
    ArchivePoisoned,
}

/// Typed original observation. A raw status is never replaced by a validated
/// label; the separate Validated fact names which checks actually completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignalJournalFact {
    Phase(SignalJournalPhase),
    RawWait {
        tid: i32,
        status: i32,
    },
    Siginfo {
        tid: i32,
        result: i64,
        errno: Option<i32>,
        raw: [u8; 128],
    },
    /// Initialized ABI bytes and the unmodified request result, even on error.
    SyscallInfo {
        tid: i32,
        result: i64,
        errno: Option<i32>,
        initialized: [u8; 88],
    },
    State {
        slot: usize,
        tid: i32,
        stop: Option<KernelStopIdentity>,
    },
    Frame {
        slot: usize,
        address: u64,
    },
    ReleaseAttempt {
        token: KernelStopIdentity,
    },
    Released {
        token: KernelStopIdentity,
    },
    Validated {
        phase: SignalJournalPhase,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalRegisterRead {
    pub result: i64,
    pub errno: Option<i32>,
    /// Initialized scalar fields, including any partial kernel write. Only
    /// result==0 authenticates these as a complete register observation.
    pub initialized: RegisterSnapshot,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalXstateRead {
    pub result: i64,
    pub errno: Option<i32>,
    pub reported_bytes: usize,
    pub pointer_unchanged: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalMaskRead {
    pub result: i64,
    pub errno: Option<i32>,
    pub initialized: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalStateRecord {
    pub slot: usize,
    pub complete: bool,
    pub registers: Option<RegisterSnapshot>,
    pub register_read: Option<SignalRegisterRead>,
    /// All initialized buffer bytes on a failed request; only a complete
    /// record claims these bytes are an authenticated kernel XSTATE image.
    pub xstate: Vec<u8>,
    pub xstate_read: Option<SignalXstateRead>,
    pub signal_mask: Option<u64>,
    pub signal_mask_read: Option<SignalMaskRead>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalFrameRecord {
    pub slot: usize,
    pub address: u64,
    pub requested: usize,
    pub complete: bool,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalProgressSnapshot {
    pub session: u64,
    pub reserved_bytes: usize,
    pub phase: SignalJournalPhase,
    pub facts: Vec<SignalJournalFact>,
    pub states: Vec<SignalStateRecord>,
    pub frames: Vec<SignalFrameRecord>,
    pub first_failure: Option<(SignalJournalPhase, SignalJournalFailure)>,
    pub closing: bool,
    pub cleanup_complete: Option<bool>,
    pub poisoned: bool,
}

/// Read-only in-memory diagnostics, valid after session error or drop. This is
/// not a durable disk journal and never asserts native cleanup from an event.
#[derive(Clone)]
pub struct SignalProgressReader {
    archive: Arc<Mutex<Archive>>,
    anchor: AnchorReader,
}
impl SignalProgressReader {
    pub fn anchor(&self) -> AnchorReader {
        self.anchor.clone()
    }
    pub fn snapshot(&self) -> SignalProgressSnapshot {
        let (archive, poisoned) = match self.archive.lock() {
            Ok(guard) => (guard, false),
            Err(error) => (error.into_inner(), true),
        };
        SignalProgressSnapshot {
            session: archive.session,
            reserved_bytes: evidence_bound(),
            phase: archive.phase,
            facts: archive.facts[..archive.fact_count]
                .iter()
                .flatten()
                .flat_map(StoredFact::logical_facts)
                .collect(),
            states: archive
                .states
                .iter()
                .take(archive.state_count)
                .enumerate()
                .map(|(slot, state)| SignalStateRecord {
                    slot,
                    complete: state.complete,
                    registers: state.registers,
                    register_read: state.register_read,
                    xstate: state.xstate[..state.length].to_vec(),
                    xstate_read: state.xstate_read,
                    signal_mask: state.mask,
                    signal_mask_read: state.mask_read,
                })
                .collect(),
            frames: archive
                .frames
                .iter()
                .take(archive.frame_count)
                .enumerate()
                .map(|(slot, frame)| SignalFrameRecord {
                    slot,
                    address: frame.address,
                    requested: frame.requested,
                    complete: frame.complete,
                    bytes: frame.bytes[..frame.length].to_vec(),
                })
                .collect(),
            first_failure: archive.failure,
            closing: archive.closing,
            cleanup_complete: archive.cleanup,
            poisoned: archive.poisoned || poisoned,
        }
    }
}

struct StateBuffer {
    registers: Option<RegisterSnapshot>,
    register_read: Option<SignalRegisterRead>,
    xstate: Vec<u8>,
    returned: Option<Vec<u8>>,
    length: usize,
    xstate_read: Option<SignalXstateRead>,
    mask: Option<u64>,
    mask_read: Option<SignalMaskRead>,
    complete: bool,
}
struct FrameBuffer {
    address: u64,
    requested: usize,
    bytes: Vec<u8>,
    returned: Option<Vec<u8>>,
    length: usize,
    complete: bool,
}
// Lossless storage aggregation, not evidence suppression. A raw wait is
// committed first and survives failure to reserve/capture its state. Existing
// public facts retain their original order and partial-query representation.
enum StoredFact {
    One(SignalJournalFact),
    Stop {
        tid: i32,
        status: i32,
        information: Option<SignalJournalFact>,
        state: Option<usize>,
    },
}
impl StoredFact {
    fn logical_facts(&self) -> impl Iterator<Item = SignalJournalFact> {
        let facts = match self {
            Self::One(fact) => [Some(fact.clone()), None, None],
            Self::Stop {
                tid,
                status,
                information,
                state,
            } => [
                Some(SignalJournalFact::RawWait {
                    tid: *tid,
                    status: *status,
                }),
                information.clone(),
                state.map(|slot| SignalJournalFact::State {
                    slot,
                    tid: *tid,
                    stop: None,
                }),
            ],
        };
        facts.into_iter().flatten()
    }
}
struct Archive {
    session: u64,
    phase: SignalJournalPhase,
    facts: [Option<StoredFact>; FACT_SLOTS],
    fact_count: usize,
    states: Vec<StateBuffer>,
    state_count: usize,
    frames: Vec<FrameBuffer>,
    frame_count: usize,
    failure: Option<(SignalJournalPhase, SignalJournalFailure)>,
    closing: bool,
    cleanup: Option<bool>,
    poisoned: bool,
}

/// Full fixed payload allocation is charged before original signal effects.
/// Retained usage and unused reservation remain distinct; neither is refunded.
pub(in crate::linux::remote::dynamic) fn evidence_bound() -> usize {
    std::mem::size_of::<Archive>()
        + STATE_SLOTS * (std::mem::size_of::<StateBuffer>() + 2 * MAX_XSTATE)
        + FRAME_SLOTS * (std::mem::size_of::<FrameBuffer>() + 2 * FRAME_BOUND)
        + 4096
}
fn buffer(length: usize) -> Result<Vec<u8>, LaunchError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| LaunchError::Invalid("signal journal allocation failed"))?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn failure(error: &LaunchError) -> SignalJournalFailure {
    match error {
        LaunchError::Timeout(_) => SignalJournalFailure::Timeout,
        LaunchError::System { source, .. } => SignalJournalFailure::NativeIo(source.raw_os_error()),
        _ => SignalJournalFailure::InvalidState,
    }
}

#[derive(Clone)]
pub(in crate::linux::remote::dynamic) struct SignalJournalWriter {
    archive: Arc<Mutex<Archive>>,
    anchor: AnchorReader,
}
impl SignalJournalWriter {
    pub(in crate::linux::remote::dynamic) fn new(
        session: u64,
        anchor: AnchorReader,
    ) -> Result<Self, LaunchError> {
        if session == 0 {
            return Err(LaunchError::Invalid(
                "signal journal lacks session identity",
            ));
        }
        let mut states = Vec::new();
        states
            .try_reserve_exact(STATE_SLOTS)
            .map_err(|_| LaunchError::Invalid("signal journal state slots allocation failed"))?;
        for _ in 0..STATE_SLOTS {
            states.push(StateBuffer {
                registers: None,
                register_read: None,
                xstate: buffer(MAX_XSTATE)?,
                returned: Some(buffer(MAX_XSTATE)?),
                length: 0,
                xstate_read: None,
                mask: None,
                mask_read: None,
                complete: false,
            });
        }
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(FRAME_SLOTS)
            .map_err(|_| LaunchError::Invalid("signal journal frame slots allocation failed"))?;
        for _ in 0..FRAME_SLOTS {
            frames.push(FrameBuffer {
                address: 0,
                requested: 0,
                bytes: buffer(FRAME_BOUND)?,
                returned: Some(buffer(FRAME_BOUND)?),
                length: 0,
                complete: false,
            });
        }
        Ok(Self {
            archive: Arc::new(Mutex::new(Archive {
                session,
                phase: SignalJournalPhase::Prepared,
                facts: std::array::from_fn(|_| None),
                fact_count: 0,
                states,
                state_count: 0,
                frames,
                frame_count: 0,
                failure: None,
                closing: false,
                cleanup: None,
                poisoned: false,
            })),
            anchor,
        })
    }
    fn lock(&self) -> MutexGuard<'_, Archive> {
        match self.archive.lock() {
            Ok(guard) => guard,
            Err(error) => {
                let mut guard = error.into_inner();
                guard.poisoned = true;
                if guard.failure.is_none() {
                    guard.failure = Some((guard.phase, SignalJournalFailure::ArchivePoisoned));
                }
                guard
            }
        }
    }
    pub(in crate::linux::remote::dynamic) fn reader(&self) -> SignalProgressReader {
        SignalProgressReader {
            archive: Arc::clone(&self.archive),
            anchor: self.anchor.clone(),
        }
    }
    pub(super) fn phase(&self, phase: SignalJournalPhase) -> Result<(), LaunchError> {
        self.append(SignalJournalFact::Phase(phase))?;
        self.lock().phase = phase;
        Ok(())
    }
    pub(super) fn append(&self, fact: SignalJournalFact) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        if archive.failure.is_some() || archive.closing || archive.fact_count == FACT_SLOTS {
            if archive.failure.is_none() {
                archive.failure = Some((archive.phase, SignalJournalFailure::Capacity));
            }
            return Err(LaunchError::Invalid(
                "signal journal fact capacity exhausted or closed",
            ));
        }
        let slot = archive.fact_count;
        archive.facts[slot] = Some(StoredFact::One(fact));
        archive.fact_count += 1;
        Ok(())
    }
    // The three independent read requests all run into already reserved
    // storage. A failed component never hides the other components' raw
    // outcomes; only a complete record may be used as native full-state proof.
    fn read_state_into(
        state: &mut StateBuffer,
        tid: i32,
    ) -> Result<TaskStateSnapshot, LaunchError> {
        // Every field is integer scalar storage; initialize all fields before
        // the kernel can partially write them. No struct padding is read as
        // bytes when constructing the retained RegisterSnapshot.
        let mut initialized: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                tid,
                0,
                &mut initialized as *mut libc::user_regs_struct,
            )
        };
        let errno = (result == -1)
            .then(|| io::Error::last_os_error().raw_os_error())
            .flatten();
        let mut first_error = Self::retain_registers(state, result, errno, initialized.into());
        let pointer = state.xstate.as_mut_ptr();
        let mut iov = libc::iovec {
            iov_base: pointer.cast(),
            iov_len: MAX_XSTATE,
        };
        // SAFETY: the original stopped identity is held by the caller; the
        // vector points to exclusive, initialized, preallocated storage.
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                tid,
                NT_X86_XSTATE,
                &mut iov as *mut libc::iovec,
            )
        };
        let errno = (result == -1)
            .then(|| io::Error::last_os_error().raw_os_error())
            .flatten();
        state.xstate_read = Some(SignalXstateRead {
            result,
            errno,
            reported_bytes: iov.iov_len,
            pointer_unchanged: iov.iov_base == pointer.cast(),
        });
        state.length = MAX_XSTATE;
        let xstate_error = if result == -1 {
            Some(io_error(
                "signal journal GETREGSET",
                io::Error::from_raw_os_error(errno.unwrap_or(libc::EIO)),
            ))
        } else if result != 0
            || iov.iov_base != pointer.cast()
            || iov.iov_len < 512
            || iov.iov_len >= MAX_XSTATE
        {
            Some(LaunchError::Invalid(
                "signal state XSTATE read is incomplete",
            ))
        } else {
            state.length = iov.iov_len;
            None
        };
        if first_error.is_none() {
            first_error = xstate_error;
        }
        let mut initialized = 0_u64;
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_GETSIGMASK,
                tid,
                KERNEL_SIGSET_BYTES,
                &mut initialized as *mut u64,
            )
        };
        let errno = (result == -1)
            .then(|| io::Error::last_os_error().raw_os_error())
            .flatten();
        state.mask_read = Some(SignalMaskRead {
            result,
            errno,
            initialized,
        });
        let mask_error = if result == -1 {
            Some(io_error(
                "signal journal GETSIGMASK",
                io::Error::from_raw_os_error(errno.unwrap_or(libc::EIO)),
            ))
        } else if result != 0 {
            Some(LaunchError::Invalid("signal mask read result differs"))
        } else {
            state.mask = Some(initialized);
            None
        };
        if first_error.is_none() {
            first_error = mask_error;
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        let registers = state.registers.ok_or(LaunchError::Invalid(
            "signal state lacks complete registers",
        ))?;
        let mut returned = state.returned.take().ok_or(LaunchError::Invalid(
            "signal state return storage was consumed",
        ))?;
        returned[..state.length].copy_from_slice(&state.xstate[..state.length]);
        returned.truncate(state.length);
        state.complete = true;
        Ok(TaskStateSnapshot {
            registers,
            xstate: returned,
            mask: initialized,
        })
    }
    fn retain_registers(
        state: &mut StateBuffer,
        result: i64,
        errno: Option<i32>,
        initialized: RegisterSnapshot,
    ) -> Option<LaunchError> {
        state.register_read = Some(SignalRegisterRead {
            result,
            errno,
            initialized,
        });
        if result == 0 {
            state.registers = Some(initialized);
            None
        } else if result == -1 {
            Some(io_error(
                "signal journal GETREGS",
                io::Error::from_raw_os_error(errno.unwrap_or(libc::EIO)),
            ))
        } else {
            Some(LaunchError::Invalid("signal register read result differs"))
        }
    }
    pub(super) fn capture_signal_state(
        &self,
        tid: i32,
        status: i32,
    ) -> Result<([u8; 128], TaskStateSnapshot), LaunchError> {
        self.capture_pair_with(tid, status, Self::read_siginfo_into, Self::read_state_into)
    }
    /// The same MAX-capacity initialized read used for diagnostics, additionally
    /// returning its exact successful query metadata for the initial ABI-size
    /// certificate. Failure outcomes remain in the ordinary fixed archive.
    pub(super) fn capture_extent_state(
        &self,
        tid: i32,
        status: i32,
    ) -> Result<([u8; 128], TaskStateSnapshot, SignalXstateRead), LaunchError> {
        let mut query = None;
        let (info, state) =
            self.capture_pair_with(tid, status, Self::read_siginfo_into, |slot, tid| {
                let result = Self::read_state_into(slot, tid);
                query = slot.xstate_read;
                result
            })?;
        let query = query.ok_or(LaunchError::Invalid(
            "signal extent lacks its actual XSTATE request",
        ))?;
        Ok((info, state, query))
    }
    fn read_siginfo_into(
        fact: &mut Option<SignalJournalFact>,
        tid: i32,
    ) -> Result<[u8; 128], LaunchError> {
        let mut raw = [0_u8; 128];
        let result = unsafe { libc::ptrace(libc::PTRACE_GETSIGINFO, tid, 0, raw.as_mut_ptr()) };
        let errno = (result == -1)
            .then(|| io::Error::last_os_error().raw_os_error())
            .flatten();
        *fact = Some(SignalJournalFact::Siginfo {
            tid,
            result,
            errno,
            raw,
        });
        if result != 0 {
            return Err(if result == -1 {
                io_error(
                    "signal journal GETSIGINFO",
                    io::Error::from_raw_os_error(errno.unwrap_or(libc::EIO)),
                )
            } else {
                LaunchError::Invalid("signal journal siginfo result differs")
            });
        }
        Ok(raw)
    }
    /// Commit the raw wait and reserve its state slot before either read.
    /// Both read-only observations are retained before applying first failure;
    /// that gate then prevents every later effect or generic capture.
    pub(super) fn capture_syscall_state(
        &self,
        tid: i32,
        status: i32,
    ) -> Result<
        (
            (libc::ptrace_syscall_info, [u8; 88], usize),
            TaskStateSnapshot,
        ),
        LaunchError,
    > {
        self.capture_pair_with(tid, status, Self::read_syscall_into, Self::read_state_into)
    }
    fn capture_pair_with<T>(
        &self,
        tid: i32,
        status: i32,
        info: impl FnOnce(&mut Option<SignalJournalFact>, i32) -> Result<T, LaunchError>,
        state_capture: impl FnOnce(&mut StateBuffer, i32) -> Result<TaskStateSnapshot, LaunchError>,
    ) -> Result<(T, TaskStateSnapshot), LaunchError> {
        let mut archive = self.lock();
        if archive.failure.is_some() || archive.closing || archive.fact_count == FACT_SLOTS {
            drop(archive);
            return self.capacity();
        }
        let fact = archive.fact_count;
        archive.fact_count += 1;
        archive.facts[fact] = Some(StoredFact::Stop {
            tid,
            status,
            information: None,
            state: None,
        });
        // The real wait cannot be lost because a later diagnostic state slot
        // is unavailable. Neither query runs unless its whole pair fits.
        if archive.state_count == STATE_SLOTS {
            if archive.failure.is_none() {
                archive.failure = Some((archive.phase, SignalJournalFailure::Capacity));
            }
            return Err(LaunchError::Invalid(
                "signal journal preallocated capacity exhausted",
            ));
        }
        let slot = archive.state_count;
        archive.state_count += 1;
        let Some(StoredFact::Stop {
            information, state, ..
        }) = &mut archive.facts[fact]
        else {
            unreachable!()
        };
        *state = Some(slot);
        // Do not use `?` between these calls: either observation may fail while
        // the other still provides independently useful native evidence.
        let info = info(information, tid);
        let state = state_capture(&mut archive.states[slot], tid);
        let result = match (info, state) {
            (Ok(info), Ok(state)) => Ok((info, state)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        if let Err(error) = &result {
            if archive.failure.is_none() {
                archive.failure = Some((archive.phase, failure(error)));
            }
        }
        result
    }
    fn read_syscall_into(
        fact: &mut Option<SignalJournalFact>,
        tid: i32,
    ) -> Result<(libc::ptrace_syscall_info, [u8; 88], usize), LaunchError> {
        const _: () = assert!(std::mem::size_of::<libc::ptrace_syscall_info>() == 88);
        #[repr(C, align(8))]
        struct SyscallBytes([u8; 88]);
        let mut raw = SyscallBytes([0_u8; 88]);
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_GET_SYSCALL_INFO,
                tid,
                raw.0.len(),
                raw.0.as_mut_ptr(),
            )
        };
        let errno = (result == -1)
            .then(|| io::Error::last_os_error().raw_os_error())
            .flatten();
        let initialized = raw.0;
        *fact = Some(SignalJournalFact::SyscallInfo {
            tid,
            result,
            errno,
            initialized,
        });
        Self::interpret_syscall(result, errno, initialized)
    }
    fn interpret_syscall(
        result: i64,
        errno: Option<i32>,
        initialized: [u8; 88],
    ) -> Result<(libc::ptrace_syscall_info, [u8; 88], usize), LaunchError> {
        if result == -1 {
            return Err(io_error(
                "signal journal GET_SYSCALL_INFO",
                io::Error::from_raw_os_error(errno.unwrap_or(libc::EIO)),
            ));
        }
        // Interpret only after retaining the initialized ABI substrate. Padding
        // is never read back from this Rust value to construct raw evidence.
        let info = unsafe {
            std::ptr::read_unaligned(initialized.as_ptr().cast::<libc::ptrace_syscall_info>())
        };
        let minimum = match info.op {
            libc::PTRACE_SYSCALL_INFO_ENTRY => 80,
            libc::PTRACE_SYSCALL_INFO_EXIT => 33,
            _ => return Err(LaunchError::Invalid("signal journal syscall phase differs")),
        };
        if result < minimum || result > 88 {
            return Err(LaunchError::Invalid(
                "signal journal syscall information is incomplete",
            ));
        }
        Ok((info, initialized, result as usize))
    }
    /// Each successful PEEK word is committed before the next read. A failed
    /// later read therefore exposes the actual prefix and complete=false.
    pub(super) fn capture_frame(
        &self,
        tid: i32,
        address: u64,
        length: usize,
        until: Instant,
    ) -> Result<Vec<u8>, LaunchError> {
        let slot = {
            let mut archive = self.lock();
            if length == 0
                || length > FRAME_BOUND
                || address.checked_add(length as u64).is_none()
                || archive.failure.is_some()
                || archive.closing
                || archive.frame_count == FRAME_SLOTS
            {
                drop(archive);
                return self.capacity();
            }
            let slot = archive.frame_count;
            archive.frame_count += 1;
            archive.frames[slot].address = address;
            archive.frames[slot].requested = length;
            slot
        };
        self.append(SignalJournalFact::Frame { slot, address })?;
        let result = (|| {
            let end = address + length as u64;
            let mut cursor = address;
            while cursor < end {
                if Instant::now() >= until {
                    return Err(LaunchError::Timeout("signal frame capture"));
                }
                let aligned = cursor & !7;
                let word = unsafe {
                    *libc::__errno_location() = 0;
                    let result = libc::ptrace(libc::PTRACE_PEEKDATA, tid, aligned as usize, 0);
                    if result == -1 && *libc::__errno_location() != 0 {
                        return Err(system("signal journal PEEKDATA"));
                    }
                    (result as u64).to_ne_bytes()
                };
                let start = (cursor - aligned) as usize;
                let count = (8 - start).min((end - cursor) as usize);
                let mut archive = self.lock();
                let frame = &mut archive.frames[slot];
                frame.bytes[frame.length..frame.length + count]
                    .copy_from_slice(&word[start..start + count]);
                frame.length += count;
                cursor += count as u64;
            }
            let mut archive = self.lock();
            let frame = &mut archive.frames[slot];
            let mut returned = frame.returned.take().ok_or(LaunchError::Invalid(
                "signal frame return storage was consumed",
            ))?;
            returned[..length].copy_from_slice(&frame.bytes[..length]);
            returned.truncate(length);
            frame.complete = true;
            Ok(returned)
        })();
        if let Err(error) = &result {
            self.fail(failure(error));
        }
        result
    }
    fn capacity<T>(&self) -> Result<T, LaunchError> {
        self.fail(SignalJournalFailure::Capacity);
        Err(LaunchError::Invalid(
            "signal journal preallocated capacity exhausted",
        ))
    }
    pub(super) fn fail(&self, kind: SignalJournalFailure) {
        let mut archive = self.lock();
        if archive.failure.is_none() {
            archive.failure = Some((archive.phase, kind));
        }
    }
    pub(super) fn fail_error(&self, error: &LaunchError) {
        self.fail(failure(error));
    }
    pub(super) fn close(&self, cleanup: Option<bool>) {
        let mut archive = self.lock();
        archive.closing = true;
        if let Some(value) = cleanup {
            archive.cleanup = Some(value);
        }
    }
}

#[cfg(test)]
mod tests;
