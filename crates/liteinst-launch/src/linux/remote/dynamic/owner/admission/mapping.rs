//! Original singleton anonymous mapping effects and held source acquisition.
//! Captures and catalog keys are evidence only; native window seals supply the
//! separate authority to advance the actually quarantined mm.
use super::super::kernel_journal::{KernelAttemptBinding, KernelAttemptId};
use super::super::kernel_journal::{
    MAPPING_CAPTURE_BYTES, MappingCaptureArchive, MappingCapturePhase as MapCapturePhase,
    MappingCaptureSlot, MappingCaptureStatus,
};
use super::super::selected::{
    self as native_selected, MappingObservation, OriginalEvidence, OriginalOutcome,
};
use super::census::Reservation;
use super::*;
use crate::gate::domain::{self as planning, Image, PAGE};
use crate::linux::remote::dynamic::admission::{
    DynamicMappingProfile, DynamicSourceCaptureId, DynamicSourceFacts, DynamicSourceImage,
    DynamicSourceRequest, DynamicSourceRequestId, PendingSourceToken,
};
use crate::selected::{Operation, SyscallAbi};
use std::io::Read;
use std::mem::size_of;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::sync::Arc;

mod maps;
mod profile;
mod proof;
mod staging;
mod transaction;
use maps::{MapEntry, ParsedMaps};
pub(super) use proof::{ReplacementCommit, VerifiedMappingExit};

const MAP_CAPTURE_BYTES: usize = MAPPING_CAPTURE_BYTES;
const MAP_CAPTURE_ROWS: usize = 512;

fn invalid(message: &'static str) -> LaunchError {
    LaunchError::Invalid(message)
}
fn refused(message: &'static str) -> GateError {
    GateError::Refused(message)
}
fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Initialized storage is reserved before the original release. A partial or
/// failed read remains distinguishable from a complete retained map capture.
struct MapCapture {
    storage: Arc<[u8]>,
    len: usize,
    attempted: bool,
    complete: bool,
    phase: MapCapturePhase,
    archive: Option<(MappingCaptureArchive, MappingCaptureSlot)>,
    archived: bool,
}
impl MapCapture {
    fn reserve() -> Result<Self, GateError> {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(MAP_CAPTURE_BYTES)
            .map_err(|_| refused("mapping capture allocation failed"))?;
        storage.resize(MAP_CAPTURE_BYTES, 0);
        Ok(Self {
            storage: Arc::from(storage),
            len: 0,
            attempted: false,
            complete: false,
            phase: MapCapturePhase::Open,
            archive: None,
            archived: false,
        })
    }
    fn archived(
        archive: &MappingCaptureArchive,
        slot: MappingCaptureSlot,
    ) -> Result<Self, GateError> {
        let mut capture = Self::reserve()?;
        capture.archive = Some((archive.clone(), slot));
        Ok(capture)
    }
    fn capture(&mut self, tid: i32) -> Result<(), LaunchError> {
        self.capture_wait(tid, None)
    }
    fn capture_wait(&mut self, tid: i32, wait_status: Option<i32>) -> Result<(), LaunchError> {
        if self.attempted || tid <= 0 {
            return Err(invalid("mapping capture slot is stale"));
        }
        if let Some((archive, slot)) = &self.archive {
            archive.begin(*slot, tid, wait_status)?;
        }
        self.attempted = true;
        let result = self.capture_inner(tid);
        let status = if let Err(error) = &result {
            let errno = match error {
                LaunchError::System { source, .. } => source.raw_os_error(),
                _ => None,
            };
            MappingCaptureStatus::Failed {
                phase: self.phase,
                errno,
                read_complete: self.complete,
            }
        } else {
            MappingCaptureStatus::Complete
        };
        self.archive_terminal(status)?;
        result
    }
    fn archive_terminal(&mut self, status: MappingCaptureStatus) -> Result<(), LaunchError> {
        if let Some((archive, slot)) = &self.archive {
            archive.commit(*slot, Arc::clone(&self.storage), self.len, status)?;
        }
        self.archived = true;
        Ok(())
    }
    fn capture_inner(&mut self, tid: i32) -> Result<(), LaunchError> {
        let mut file = std::fs::File::open(format!("/proc/{tid}/maps"))
            .map_err(|error| io_error("open mapping capture", error))?;
        self.phase = MapCapturePhase::ProcIdentity;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: the retained open file owns its fd; the initialized output
        // has exactly the native statfs layout and is inspected only on success.
        if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(system("authenticate mapping procfs"));
        }
        // SAFETY: successful fstatfs initialized the complete output above.
        if unsafe { filesystem.assume_init() }.f_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t
        {
            return Err(invalid("mapping capture is not a procfs file"));
        }
        self.phase = MapCapturePhase::Read;
        loop {
            if self.len == self.storage.len() {
                let mut extra = [0_u8; 1];
                if file
                    .read(&mut extra)
                    .map_err(|error| io_error("read mapping capture bound", error))?
                    != 0
                {
                    self.phase = MapCapturePhase::Overflow;
                    return Err(invalid("mapping capture exceeds reserved bytes"));
                }
                break;
            }
            let storage = Arc::get_mut(&mut self.storage).ok_or_else(|| {
                invalid("mapping capture storage was shared before reading completed")
            })?;
            let count = file
                .read(&mut storage[self.len..])
                .map_err(|error| io_error("read mapping capture", error))?;
            if count == 0 {
                break;
            }
            self.len += count;
        }
        // Mark the raw read complete before interpreting it. A malformed map
        // table is still the actual complete raw observation, not an empty row.
        self.complete = true;
        self.phase = MapCapturePhase::Parse;
        self.view()?;
        self.phase = MapCapturePhase::Complete;
        Ok(())
    }
    fn view(&self) -> Result<ParsedMaps<'_>, LaunchError> {
        if !self.complete {
            return Err(invalid("mapping capture is incomplete"));
        }
        ParsedMaps::parse(&self.storage[..self.len], MAP_CAPTURE_ROWS)
            .map_err(|_| invalid("mapping capture is malformed or exceeds row bound"))
    }
}

impl Drop for MapCapture {
    fn drop(&mut self) {
        if self.attempted && !self.archived {
            let status = if std::thread::panicking() {
                MappingCaptureStatus::Unwound {
                    phase: self.phase,
                    read_complete: self.complete,
                }
            } else {
                MappingCaptureStatus::Abandoned {
                    phase: self.phase,
                    read_complete: self.complete,
                }
            };
            // No user/native operation occurs under this archive lock. On a
            // poisoned archive, its existing InProgress marker remains visible.
            let _ = self.archive_terminal(status);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Protection {
    Writable,
    Executable,
}
impl Protection {
    fn bytes(self) -> [u8; 4] {
        match self {
            Self::Writable => *b"rw-p",
            Self::Executable => *b"r-xp",
        }
    }
}
#[derive(Clone, Debug)]
struct OwnedMapping {
    incarnation: u64,
    range: Range<u64>,
    protection: Protection,
}
#[derive(Clone, Debug)]
enum MappingOperation {
    Create {
        incarnation: u64,
    },
    Protect {
        incarnation: u64,
        before: Protection,
        after: Protection,
    },
    Remove {
        incarnation: u64,
        before: Protection,
    },
}
impl MappingOperation {
    fn before(&self) -> Option<Protection> {
        match self {
            Self::Create { .. } => None,
            Self::Protect { before, .. } | Self::Remove { before, .. } => Some(*before),
        }
    }
    fn after(&self) -> Option<Protection> {
        match self {
            Self::Create { .. } => Some(Protection::Writable),
            Self::Protect { after, .. } => Some(*after),
            Self::Remove { .. } => None,
        }
    }
    fn incarnation(&self) -> u64 {
        match self {
            Self::Create { incarnation }
            | Self::Protect { incarnation, .. }
            | Self::Remove { incarnation, .. } => *incarnation,
        }
    }
}

struct RawMappingWait {
    tid: i32,
    status: i32,
    capture: MapCapture,
}
struct MappingRecord {
    archive: MappingCaptureArchive,
    original: PendingToken,
    operation: MappingOperation,
    range: Range<u64>,
    number: u64,
    arguments: [u64; 6],
    before_window: MapCapture,
    logical_window: MapCapture,
    waits: [RawMappingWait; 2],
    wait_count: usize,
    entry: Option<DynamicEvent>,
    exit: Option<DynamicEvent>,
    result: Option<(i64, bool)>,
    quarantined: MapCapture,
    completion: Option<usize>,
    source_request: Option<DynamicSourceRequest>,
    source_facts: Option<DynamicSourceFacts>,
    proof: Option<VerifiedMappingExit>,
}

/// Records remain append-only, including rejected/abandoned kernel attempts.
pub(super) struct MappingState {
    profile: DynamicMappingProfile,
    evidence: profile::MappingProfileEvidence,
    owned: Vec<OwnedMapping>,
    records: Vec<MappingRecord>,
    next_incarnation: u64,
    requests: u64,
    pending: Option<PendingMapping>,
}

struct PendingMapping {
    record: usize,
    reservation: Reservation,
    revoked: routes::MappingRevocation,
    request: Option<DynamicSourceRequest>,
    source_page: u64,
    state: TaskStateSnapshot,
    until: Instant,
}

impl MappingState {
    pub(super) fn new(
        owner: &Owner,
        profile: DynamicMappingProfile,
        boot: &super::super::bootstrap::BootstrapMm,
        until: Instant,
    ) -> Result<Self, GateError> {
        let evidence = profile::MappingProfileEvidence::acquire(owner, boot, until)?;
        Ok(Self {
            profile,
            evidence,
            owned: Vec::new(),
            records: Vec::new(),
            next_incarnation: 1,
            requests: 0,
            pending: None,
        })
    }
    pub(super) fn xstate_extent(&self) -> usize {
        self.evidence.extent()
    }
    pub(super) fn verify_extent(
        &self,
        token: &DynamicStop,
        identity: DynamicTask,
        state: &TaskStateSnapshot,
    ) -> Result<(), GateError> {
        self.evidence.verify(token, identity, state)
    }
    pub(super) fn pending_until(&self) -> Option<Instant> {
        self.pending.as_ref().map(|pending| pending.until)
    }
    pub(super) fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(super) fn initial_bytes(profile: &DynamicMappingProfile) -> Result<usize, GateError> {
        Self::configuration_bytes(profile)?
            .checked_add(profile::MappingProfileEvidence::reservation_bytes()?)
            .ok_or_else(|| refused("mapping initial evidence size overflows"))
    }
    pub(super) fn retained_bytes(&self) -> Result<usize, GateError> {
        let payload = self
            .evidence
            .retained_bytes()?
            .checked_sub(size_of::<profile::MappingProfileEvidence>())
            .ok_or_else(|| refused("mapping retained evidence header differs"))?;
        Self::configuration_bytes(&self.profile)?
            .checked_add(payload)
            .ok_or_else(|| refused("mapping retained evidence size overflows"))
    }
    fn configuration_bytes(profile: &DynamicMappingProfile) -> Result<usize, GateError> {
        size_of::<Self>()
            .checked_add(
                profile
                    .allowed_ranges
                    .len()
                    .checked_mul(size_of::<Range<u64>>())
                    .ok_or_else(|| refused("mapping profile size overflows"))?,
            )
            .ok_or_else(|| refused("mapping profile size overflows"))
    }

    fn prepare(
        &mut self,
        pending: &PendingInvocation,
        domain: &Domain,
    ) -> Result<MappingRecord, GateError> {
        let input = &pending.input;
        let registers = input.registers();
        let range = registers.rdi
            ..registers
                .rdi
                .checked_add(registers.rsi)
                .ok_or_else(|| refused("mapping range overflows"))?;
        if !is_mapping(input)
            || input.instruction().bytes() != [0x0f, 0x05]
            || !self.profile.contains_range(&range)
            || self.records.len() >= self.profile.max_operations
            || self.pending.is_some()
        {
            return Err(refused(
                "mapping invocation exceeds its owned singleton profile",
            ));
        }
        if [
            registers.rip,
            input.instruction().next_pc(),
            registers.rsp,
            registers.fs_base,
            registers.gs_base,
        ]
        .into_iter()
        .any(|pc| range.contains(&pc))
            || domain.returns.obligations().any(|obligation| {
                range.contains(&obligation.return_pc)
                    || obligation
                        .call_address
                        .checked_add(obligation.call_bytes.len() as u64)
                        .is_none_or(|end| overlaps(&range, &(obligation.call_address..end)))
            })
        {
            return Err(refused(
                "mapping effect intersects a retained continuation or live context",
            ));
        }
        let archive = MappingCaptureArchive::new(KernelAttemptId {
            session: pending.token.stop.session,
            invocation: pending.token.invocation,
        })?;
        let mut before_window = MapCapture::archived(&archive, MappingCaptureSlot::BeforeWindow)?;
        before_window.capture(pending.stop.token.tid)?;
        let maps = before_window.view()?;
        if maps
            .entries()
            .any(|entry| entry.end == range.start || entry.start == range.end)
        {
            return Err(refused("mapping effect needs an isolated complete VMA"));
        }
        let operation = if registers.rax == libc::SYS_mmap as u64 {
            if registers.rdx != (libc::PROT_READ | libc::PROT_WRITE) as u64
                || registers.r10
                    != (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64
                || registers.r8 != u64::MAX
                || registers.r9 != 0
                || self.owned.len() >= self.profile.max_live_mappings
                || maps
                    .entries()
                    .any(|entry| overlaps(&(entry.start..entry.end), &range))
                || self.owned.iter().any(|old| overlaps(&old.range, &range))
            {
                return Err(refused(
                    "mapping creation is not an isolated private anonymous RW operation",
                ));
            }
            self.owned
                .try_reserve(1)
                .map_err(|_| refused("owned mapping allocation failed"))?;
            let incarnation = self.next_incarnation;
            self.next_incarnation = incarnation
                .checked_add(1)
                .ok_or_else(|| refused("mapping incarnation space exhausted"))?;
            MappingOperation::Create { incarnation }
        } else {
            let old = self
                .owned
                .iter()
                .find(|old| old.range == range)
                .ok_or_else(|| refused("mapping effect lacks its whole owned incarnation"))?;
            let mut affected = maps
                .entries()
                .filter(|entry| overlaps(&(entry.start..entry.end), &range));
            let entry = affected
                .next()
                .ok_or_else(|| refused("owned mapping is absent"))?;
            // Gate-imposed NX is separately authenticated by the current domain
            // release proof. It is not the application's logical protection.
            let expected_nx =
                old.protection == Protection::Executable && entry.permissions.bytes() == *b"r--p";
            if expected_nx
                && (range.start..range.end)
                    .step_by(PAGE as usize)
                    .any(|page| domain.pages.get(&page) != Some(&false))
            {
                return Err(refused("owned executable NX range lacks the current gate"));
            }
            if !anonymous_identity(entry, &range)
                || (!expected_nx && entry.permissions.bytes() != old.protection.bytes())
                || affected.next().is_some()
            {
                return Err(refused("owned mapping incarnation descriptor changed"));
            }
            if registers.rax == libc::SYS_mprotect as u64 {
                let after = match registers.rdx as libc::c_int {
                    value if value == libc::PROT_READ | libc::PROT_WRITE => Protection::Writable,
                    value if value == libc::PROT_READ | libc::PROT_EXEC => Protection::Executable,
                    _ => return Err(refused("mapping protection is outside the RW/RX profile")),
                };
                if registers.rdx > i32::MAX as u64 || old.protection == after {
                    return Err(refused(
                        "mapping protection must change between logical RW and RX",
                    ));
                }
                if after == Protection::Executable
                    && self.requests >= self.profile.max_source_requests as u64
                {
                    return Err(refused("mapping source acquisition budget exhausted"));
                }
                MappingOperation::Protect {
                    incarnation: old.incarnation,
                    before: old.protection,
                    after,
                }
            } else {
                MappingOperation::Remove {
                    incarnation: old.incarnation,
                    before: old.protection,
                }
            }
        };
        self.records
            .try_reserve(1)
            .map_err(|_| refused("mapping record allocation failed"))?;
        Ok(MappingRecord {
            original: pending.token.clone(),
            operation,
            range,
            number: registers.rax,
            arguments: [
                registers.rdi,
                registers.rsi,
                registers.rdx,
                registers.r10,
                registers.r8,
                registers.r9,
            ],
            before_window,
            logical_window: MapCapture::archived(&archive, MappingCaptureSlot::LogicalWindow)?,
            waits: [
                RawMappingWait {
                    tid: 0,
                    status: 0,
                    capture: MapCapture::archived(&archive, MappingCaptureSlot::FirstWait)?,
                },
                RawMappingWait {
                    tid: 0,
                    status: 0,
                    capture: MapCapture::archived(&archive, MappingCaptureSlot::SecondWait)?,
                },
            ],
            wait_count: 0,
            entry: None,
            exit: None,
            result: None,
            quarantined: MapCapture::archived(&archive, MappingCaptureSlot::Quarantined)?,
            completion: None,
            archive,
            source_request: None,
            source_facts: None,
            proof: None,
        })
    }

    fn commit_owned(&mut self, index: usize) -> Result<(), GateError> {
        let record = &self.records[index];
        let (_, failed) = record
            .result
            .ok_or_else(|| refused("mapping owned commit lacks a result"))?;
        if failed {
            return Ok(());
        }
        match record.operation {
            MappingOperation::Create { incarnation } => {
                if self
                    .owned
                    .iter()
                    .any(|old| overlaps(&old.range, &record.range))
                {
                    return Err(refused(
                        "mapping owned creation overlaps a retained incarnation",
                    ));
                }
                self.owned.push(OwnedMapping {
                    incarnation,
                    range: record.range.clone(),
                    protection: Protection::Writable,
                });
            }
            MappingOperation::Protect {
                incarnation,
                before,
                after,
            } => {
                let old = self
                    .owned
                    .iter_mut()
                    .find(|old| old.incarnation == incarnation && old.range == record.range)
                    .ok_or_else(|| refused("mapping protection lost its owned incarnation"))?;
                if old.protection != before {
                    return Err(refused("mapping owned protection changed"));
                }
                old.protection = after;
            }
            MappingOperation::Remove {
                incarnation,
                before,
            } => {
                let index = self
                    .owned
                    .iter()
                    .position(|old| {
                        old.incarnation == incarnation
                            && old.range == record.range
                            && old.protection == before
                    })
                    .ok_or_else(|| refused("mapping removal lost its owned incarnation"))?;
                self.owned.remove(index);
            }
        }
        Ok(())
    }
}

pub(super) fn is_mapping(input: &SelectedInput) -> bool {
    matches!(
        input.instruction().operation(),
        Operation::Syscall {
            abi: SyscallAbi::LinuxX64
        }
    ) && matches!(
        input.registers().rax as libc::c_long,
        libc::SYS_mmap | libc::SYS_mprotect | libc::SYS_munmap
    ) && input.registers().rax <= i32::MAX as u64
}

fn exact_anonymous(entry: MapEntry<'_>, range: &Range<u64>, protection: Protection) -> bool {
    entry.permissions.bytes() == protection.bytes() && anonymous_identity(entry, range)
}
fn anonymous_identity(entry: MapEntry<'_>, range: &Range<u64>) -> bool {
    entry.start == range.start
        && entry.end == range.end
        && entry.file_offset == 0
        && entry.device_major == 0
        && entry.device_minor == 0
        && entry.inode == 0
        && entry.pathname.is_none()
}

impl MappingObservation for MappingRecord {
    fn raw(&mut self, tid: i32, status: i32) -> Result<(), LaunchError> {
        if self.wait_count == self.waits.len() {
            return Err(invalid("mapping syscall produced an extra raw wait"));
        }
        let row = &mut self.waits[self.wait_count];
        self.wait_count += 1;
        row.tid = tid;
        row.status = status;
        if tid != self.original.stop.tid || !libc::WIFSTOPPED(status) {
            return Err(invalid("mapping raw wait lost its original stopped task"));
        }
        row.capture.capture_wait(tid, Some(status))
    }
    fn entry(
        &mut self,
        event: &DynamicEvent,
        _state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        if self.wait_count != 1
            || self.entry.is_some()
            || event.task != Some(self.original.task)
            || event.tid != self.original.stop.tid
            || event.kind
                != (DynamicEventKind::SyscallEntry {
                    number: self.number,
                    arguments: self.arguments,
                })
            || self.waits[0].capture.view()?.raw() != self.logical_window.view()?.raw()
        {
            return Err(invalid(
                "mapping original ENTRY or logical map census differs",
            ));
        }
        self.entry = Some(event.clone());
        Ok(())
    }
    fn exit(
        &mut self,
        event: &DynamicEvent,
        _state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        if self.wait_count != 2
            || self.entry.is_none()
            || self.exit.is_some()
            || event.task != Some(self.original.task)
            || event.tid != self.original.stop.tid
        {
            return Err(invalid("mapping EXIT lacks its exact original ENTRY"));
        }
        // Retain the actual event/result before any map-result interpretation.
        self.exit = Some(event.clone());
        let DynamicEventKind::SyscallExit { result, is_error } = event.kind else {
            return Err(invalid("mapping EXIT has another native event kind"));
        };
        self.result = Some((result, is_error));
        if is_error != (-4095..=-1).contains(&result)
            || (!is_error
                && result
                    != if matches!(self.operation, MappingOperation::Create { .. }) {
                        self.range.start as i64
                    } else {
                        0
                    })
        {
            return Err(invalid(
                "mapping original result differs from the owned operation",
            ));
        }
        let before = self.waits[0].capture.view()?;
        let after = self.waits[1].capture.view()?;
        // Non-target rows must remain byte-identical. The whole owned target
        // is isolated from adjacent VMAs before entry, so no merge/split outside
        // it is an allowed effect. Failed syscalls get this same real readback.
        let outside = |entry: &MapEntry<'_>| !overlaps(&(entry.start..entry.end), &self.range);
        if !before
            .entries()
            .filter(outside)
            .map(|entry| entry.raw_line)
            .eq(after.entries().filter(outside).map(|entry| entry.raw_line))
        {
            return Err(invalid("mapping syscall changed an unrelated VMA"));
        }
        let expected = if is_error {
            self.operation.before()
        } else {
            self.operation.after()
        };
        let mut affected = after
            .entries()
            .filter(|entry| overlaps(&(entry.start..entry.end), &self.range));
        match expected {
            Some(protection) => {
                if !affected
                    .next()
                    .is_some_and(|entry| exact_anonymous(entry, &self.range, protection))
                    || affected.next().is_some()
                {
                    return Err(invalid(
                        "mapping result lacks the exact anonymous incarnation",
                    ));
                }
            }
            None => {
                if affected.next().is_some() {
                    return Err(invalid("mapping removed/absent range still has a VMA"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod capture_tests;
