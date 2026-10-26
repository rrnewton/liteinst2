//! Fixed mapping-read diagnostics owned by the persistent kernel attempt.
//! A capture is not a mapping lease, wait receipt or successful native effect.
use super::*;

#[cfg(test)]
mod tests;

pub(in crate::linux::remote::dynamic::owner) const MAPPING_CAPTURE_BYTES: usize = 64 * 1024;
const MAPPING_CAPTURES: usize = 5;

/// Distinct one-use capture purposes. Raw wait slots have no semantic syscall
/// classification until the separate native journal validates their states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingCaptureSlot {
    /// Held map census before private restoration or original execution.
    BeforeWindow,
    /// Logical map census after private restoration, before original release.
    LogicalWindow,
    /// First successful pinned wait delivery, not an inferred ENTRY.
    FirstWait,
    /// Second successful pinned wait delivery, not an inferred EXIT.
    SecondWait,
    /// Map census after the original effect and actual NX quarantine.
    Quarantined,
}
impl MappingCaptureSlot {
    fn index(self) -> usize {
        self as usize
    }
    fn raw_wait(self) -> bool {
        matches!(self, Self::FirstWait | Self::SecondWait)
    }
}

/// Actual read/interpretation phase; no phase implies a native effect succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingCapturePhase {
    /// Opening the owned task's procfs map file.
    Open,
    /// Authenticating the opened file's procfs identity.
    ProcIdentity,
    /// Reading into initialized bounded storage.
    Read,
    /// A further byte exceeded the fixed storage bound.
    Overflow,
    /// Interpreting a complete retained raw table.
    Parse,
    /// Reading and interpretation finished before archive commit.
    Complete,
}

/// One-way slot state. Failed and unwound prefixes are never complete tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingCaptureStatus {
    /// This slot was never attempted.
    Unused,
    /// The header is retained; the exclusive reader still owns its buffer.
    InProgress,
    /// The full raw table and its strict interpretation completed.
    Complete,
    /// A read or interpretation refused. A complete malformed raw table is
    /// retained with read_complete=true, without being a valid map census.
    Failed {
        /// Last actual read/interpretation phase.
        phase: MappingCapturePhase,
        /// Actual positive OS errno, when the failing operation supplied one.
        errno: Option<i32>,
        /// EOF was observed before interpretation failed.
        read_complete: bool,
    },
    /// The local capture unwound before committing; initialized bytes survive.
    Unwound {
        /// Last phase reached before the unwind.
        phase: MappingCapturePhase,
        /// Whether EOF had already been observed.
        read_complete: bool,
    },
    /// A normal error/drop abandoned an unfinished capture without a panic.
    Abandoned {
        /// Last phase reached before the capture was abandoned.
        phase: MappingCapturePhase,
        /// Whether EOF had already been observed.
        read_complete: bool,
    },
}
impl MappingCaptureStatus {
    fn terminal(self) -> bool {
        !matches!(self, Self::Unused | Self::InProgress)
    }
    fn valid(self, len: usize) -> bool {
        let (phase, read_complete) = match self {
            Self::Unused | Self::InProgress => return false,
            Self::Complete => return len != 0,
            Self::Failed {
                phase,
                errno,
                read_complete,
            } => {
                if errno.is_some_and(|value| value <= 0) || phase == MappingCapturePhase::Complete {
                    return false;
                }
                (phase, read_complete)
            }
            Self::Unwound {
                phase,
                read_complete,
            }
            | Self::Abandoned {
                phase,
                read_complete,
            } => (phase, read_complete),
        };
        match phase {
            MappingCapturePhase::Open | MappingCapturePhase::ProcIdentity => {
                len == 0 && !read_complete
            }
            MappingCapturePhase::Read => !read_complete,
            MappingCapturePhase::Overflow => len == MAPPING_CAPTURE_BYTES && !read_complete,
            MappingCapturePhase::Parse | MappingCapturePhase::Complete => read_complete,
        }
    }
}

/// Immutable inspection of one initialized capture. Bytes are shared with the
/// persistent owner archive; cloning a snapshot never duplicates their payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingCaptureRecord {
    /// One-use purpose assigned by the mapping transaction.
    pub slot: MappingCaptureSlot,
    /// Actual observed task number, present only after begin.
    pub tid: Option<i32>,
    /// Original raw wait status, present only for a raw wait slot.
    pub wait_status: Option<i32>,
    /// Explicit unused, incomplete or terminal result.
    pub status: MappingCaptureStatus,
    /// Number of bytes actually read into the initialized storage.
    pub initialized_len: usize,
    bytes: Option<Arc<[u8]>>,
}
impl MappingCaptureRecord {
    /// Actual initialized read prefix. This may be incomplete or malformed;
    /// callers must inspect status, never treat its presence as authority.
    pub fn bytes(&self) -> Option<&[u8]> {
        self.bytes
            .as_ref()
            .map(|bytes| &bytes[..self.initialized_len])
    }
    /// Complete initialized backing storage, including bytes beyond the read
    /// prefix. Those suffix bytes are not observations of the task's maps.
    pub fn initialized_storage(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
}

/// Fixed, read-only diagnostic projection. It provides no native control and
/// neither complete tables nor syscall EXIT observations prove physical cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingCaptureSnapshot {
    /// Exact kernel attempt to which this archive may attach once.
    pub attempt: KernelAttemptId,
    /// A poisoned archive remains inspectable but cannot accept more writes.
    pub archive_poisoned: bool,
    /// All five fixed slots, including unused slots.
    pub records: [MappingCaptureRecord; MAPPING_CAPTURES],
}

struct MappingArchive {
    attempt: KernelAttemptId,
    attached: bool,
    poisoned: bool,
    records: [MappingCaptureRecord; MAPPING_CAPTURES],
}

/// Private writer handle. Owner's kernel journal retains the same allocation
/// independently of movable AdmissionOwner/MappingRecord and any client handle.
#[derive(Clone)]
pub(in crate::linux::remote::dynamic::owner) struct MappingCaptureArchive {
    archive: Arc<Mutex<MappingArchive>>,
}
impl MappingCaptureArchive {
    pub(in crate::linux::remote::dynamic::owner) fn new(
        attempt: KernelAttemptId,
    ) -> Result<Self, LaunchError> {
        if attempt.session == 0 || attempt.invocation == 0 {
            return Err(invalid("mapping archive identity is zero"));
        }
        let slots = [
            MappingCaptureSlot::BeforeWindow,
            MappingCaptureSlot::LogicalWindow,
            MappingCaptureSlot::FirstWait,
            MappingCaptureSlot::SecondWait,
            MappingCaptureSlot::Quarantined,
        ];
        Ok(Self {
            archive: Arc::new(Mutex::new(MappingArchive {
                attempt,
                attached: false,
                poisoned: false,
                records: slots.map(|slot| MappingCaptureRecord {
                    slot,
                    tid: None,
                    wait_status: None,
                    status: MappingCaptureStatus::Unused,
                    initialized_len: 0,
                    bytes: None,
                }),
            })),
        })
    }

    /// Fixed archive allocation and all five shared initialized payloads. The
    /// caller allocates the payloads before effects and debits this once; sharing
    /// the same Arcs in MappingRecord is not a second raw-byte allocation.
    pub(in crate::linux::remote::dynamic::owner) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<Mutex<MappingArchive>>()
            + 2 * std::mem::size_of::<usize>()
            + MAPPING_CAPTURES * (MAPPING_CAPTURE_BYTES + 2 * std::mem::size_of::<usize>())
    }

    fn lock(&self) -> MutexGuard<'_, MappingArchive> {
        match self.archive.lock() {
            Ok(guard) => guard,
            Err(error) => {
                let mut guard = error.into_inner();
                guard.poisoned = true;
                guard
            }
        }
    }

    pub(in crate::linux::remote::dynamic::owner) fn begin(
        &self,
        slot: MappingCaptureSlot,
        tid: i32,
        wait_status: Option<i32>,
    ) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        if archive.poisoned
            || tid <= 0
            || slot.raw_wait() != wait_status.is_some()
            || archive.records[slot.index()].status != MappingCaptureStatus::Unused
            || (slot != MappingCaptureSlot::BeforeWindow && !archive.attached)
        {
            return Err(invalid(
                "mapping capture cannot begin in this archive state",
            ));
        }
        archive.records[slot.index()].tid = Some(tid);
        archive.records[slot.index()].wait_status = wait_status;
        archive.records[slot.index()].status = MappingCaptureStatus::InProgress;
        Ok(())
    }

    /// The caller owns the buffer exclusively until this one-way commit. It
    /// must not publish an Arc clone before native reading is finished. Once
    /// shared, safe Arc mutation cannot change the archive's retained bytes.
    pub(in crate::linux::remote::dynamic::owner) fn commit(
        &self,
        slot: MappingCaptureSlot,
        bytes: Arc<[u8]>,
        initialized_len: usize,
        status: MappingCaptureStatus,
    ) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        if archive.poisoned
            || archive.records[slot.index()].status != MappingCaptureStatus::InProgress
            || bytes.len() != MAPPING_CAPTURE_BYTES
            || initialized_len > bytes.len()
            || !status.terminal()
            || !status.valid(initialized_len)
        {
            return Err(invalid(
                "mapping capture cannot commit this terminal prefix",
            ));
        }
        let record = &mut archive.records[slot.index()];
        record.bytes = Some(bytes);
        record.initialized_len = initialized_len;
        record.status = status;
        Ok(())
    }

    fn attach(&self, attempt: KernelAttemptId) -> Result<(), LaunchError> {
        let mut archive = self.lock();
        if archive.poisoned
            || archive.attached
            || archive.attempt != attempt
            || archive.records.iter().any(|record| match record.slot {
                MappingCaptureSlot::BeforeWindow => !matches!(
                    record.status,
                    MappingCaptureStatus::Unused | MappingCaptureStatus::Complete
                ),
                _ => record.status != MappingCaptureStatus::Unused,
            })
        {
            return Err(invalid("mapping archive is foreign, used or incomplete"));
        }
        archive.attached = true;
        Ok(())
    }

    pub(in crate::linux::remote::dynamic::owner) fn snapshot(&self) -> MappingCaptureSnapshot {
        let archive = self.lock();
        MappingCaptureSnapshot {
            attempt: archive.attempt,
            archive_poisoned: archive.poisoned,
            records: archive.records.clone(),
        }
    }
}

impl KernelJournalWriter {
    /// The caller already debited archive.retained_bytes(), in addition to the
    /// prepared kernel attempt. This attach precedes every kernel release fact.
    pub(in crate::linux::remote::dynamic::owner) fn attach_mapping(
        &mut self,
        handle: KernelAttemptHandle,
        mapping: MappingCaptureArchive,
    ) -> Result<(), LaunchError> {
        if self.active != Some(handle) {
            return Err(invalid("mapping archive kernel handle is not active"));
        }
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        if attempt.failure.is_some()
            || attempt.length != 0
            || attempt.stage != KernelJournalStage::Prepared
            || attempt.mapping.is_some()
            || !matches!(
                attempt.binding.input.registers().rax as libc::c_long,
                libc::SYS_mmap | libc::SYS_mprotect | libc::SYS_munmap
            )
        {
            return Err(invalid(
                "mapping archive must attach before its original release",
            ));
        }
        let charge = attempt
            .charge
            .checked_add(mapping.retained_bytes())
            .ok_or(invalid("mapping archive charge overflows"))?;
        mapping.attach(handle.id)?;
        attempt.charge = charge;
        attempt.mapping = Some(mapping);
        Ok(())
    }
}
