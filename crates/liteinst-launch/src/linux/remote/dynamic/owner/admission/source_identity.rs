//! Borrowed native source identity and complete raw-map interpretation.
//! Initial EXEC and post-bootstrap reads are distinct authorities. No source
//! head, instruction plan, replacement seal or public resume handle is created.
use super::super::bootstrap::BootstrapMm;
use super::mapping::maps::{MapEntry, ParsedMaps};
use super::*;
use crate::linux::{EntryEvidence, FirstImage};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;

pub(super) const MAP_BYTES: usize = 64 * 1024;
pub(super) const MAP_ROWS: usize = 512;
pub(super) const PAGE: u64 = 4096;

fn refused(reason: &'static str) -> GateError {
    GateError::Refused(reason)
}

pub(super) mod backing;
mod coalesced;
mod geometry;
pub(super) use coalesced::{
    InitialOriginalInventory, InitialSourceInventory, InitialSourceValidation, InitialSourceVma,
    SourceContainer,
};
mod initial;
mod read;
pub(in crate::linux::remote::dynamic::owner) use backing::ExecutableIdentity;
pub(super) use geometry::{SourceGeometry, SourceInventory};
pub(in crate::linux::remote::dynamic::owner) use initial::require_initial_task_identity;
pub(in crate::linux::remote::dynamic::owner) use initial::{
    InitialCheckpointSourceRead, InitialReadScratch, InitialSourceCheckpoint,
};
pub(super) use initial::{
    RuntimeKernelReadCheckpoint, RuntimeKernelSourceRead, RuntimeReadCheckpoint, RuntimeSourceRead,
};
#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner) use read::{SourceReadFailure, SourceReadRequest};
pub(in crate::linux::remote::dynamic::owner) use read::{SourceReadOperation, SourceReadProgress};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct FileIdentity {
    pub(in crate::linux::remote::dynamic::owner) major: u32,
    pub(in crate::linux::remote::dynamic::owner) minor: u32,
    pub(in crate::linux::remote::dynamic::owner) inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ImageRole {
    Executable,
    Interpreter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceVma {
    pub(super) original_index: usize,
    pub(super) current_index: usize,
    pub(super) original_span: (usize, usize),
    pub(super) current_span: (usize, usize),
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) offset: u64,
    pub(super) file: FileIdentity,
    pub(super) role: ImageRole,
}

/// Initial-only fixed managed scratch/query peak, excluding the separately
/// owned InitialReadScratch and caller map/window payloads. Membership's
/// allocation-free root seam owns its own fixed scalar request storage.
/// This is not allocator bookkeeping, libc internals, or a process RSS bound.
pub(super) fn initial_temporary_bytes() -> usize {
    let authentication = 2 * size_of::<SourceReadProgress>()
        + size_of::<RegisterSnapshot>()
        + size_of::<libc::iovec>()
        + 2 * size_of::<libc::statfs>()
        + 3 * size_of::<File>()
        + 2 * 68
        + 32
        + 11;
    let borrowed_context = size_of::<HeldSourceRead<'_>>().max(size_of::<OriginalSourceRead<'_>>());
    // Projection and authentication happen sequentially. The borrowed reader
    // stays live through either; no source payload or private page is copied.
    borrowed_context + authentication.max(backing::temporary_bytes())
}

struct SourceReadContext<'a> {
    owner: &'a Owner,
    until: Instant,
    bounded: bool,
}

pub(super) struct HeldSourceRead<'a> {
    context: SourceReadContext<'a>,
    native: &'a NativeLifecycle,
    boot: &'a BootstrapMm,
    scratch: Option<&'a InitialReadScratch>,
}
impl<'a> HeldSourceRead<'a> {
    pub(super) fn acquire(
        owner: &'a Owner,
        native: &'a NativeLifecycle,
        boot: &'a BootstrapMm,
        until: Instant,
    ) -> Result<Self, GateError> {
        let read = Self {
            context: SourceReadContext {
                owner,
                until,
                bounded: false,
            },
            native,
            boot,
            scratch: None,
        };
        read.reauthenticate()?;
        Ok(read)
    }
    pub(super) fn acquire_initial(
        owner: &'a Owner,
        native: &'a NativeLifecycle,
        boot: &'a BootstrapMm,
        until: Instant,
        scratch: &'a InitialReadScratch,
    ) -> Result<Self, GateError> {
        let read = Self {
            context: SourceReadContext {
                owner,
                until,
                bounded: true,
            },
            native,
            boot,
            scratch: Some(scratch),
        };
        read.reauthenticate()?;
        Ok(read)
    }
    pub(super) fn reauthenticate(&self) -> Result<(), GateError> {
        if let Some(scratch) = self.scratch {
            return initial::authenticate(&self.context, self.native, self.boot, scratch);
        }
        authenticate_bootstrap(
            self.context.owner,
            self.native,
            self.boot,
            self.context.until,
        )?;
        if TaskStateSnapshot::read(self.context.owner.pid)? != self.boot.evidence.restored_entry {
            return Err(refused(
                "exec source acquisition changed complete bootstrap state",
            ));
        }
        self.context.owner.time_left(
            self.context.until,
            "exec source current-state authentication",
        )?;
        Ok(())
    }
    pub(super) fn executable_projection(
        &self,
        storage: &mut [u8],
    ) -> Result<backing::ExecutableIdentity, GateError> {
        backing::observe(&self.context, storage)
    }
    /// Legacy complete-map read; its original error/prefix behavior is retained.
    pub(super) fn read_maps_into(&self, storage: &mut [u8]) -> Result<usize, GateError> {
        read_maps_into(&self.context, storage)
    }
    /// Initial runtime capture owns both initialized storage and progress.
    pub(super) fn read_maps_capture(
        &self,
        storage: &mut [u8],
        progress: &mut SourceReadProgress,
    ) -> Result<usize, GateError> {
        read::maps_capture(&self.context, storage, progress, || self.reauthenticate())
    }
    pub(super) fn read_memory_into(
        &self,
        address: u64,
        storage: &mut [u8],
        progress: &mut SourceReadProgress,
    ) -> Result<(), GateError> {
        read::memory_capture(&self.context, address, storage, progress, || {
            self.reauthenticate()
        })
    }
}

/// This borrow cannot cross Owner's mutable EXEC-to-EXIT bootstrap transition.
pub(in crate::linux::remote::dynamic::owner) struct OriginalSourceRead<'a> {
    context: SourceReadContext<'a>,
    initial: &'a DynamicStop,
    scratch: &'a InitialReadScratch,
}
impl<'a> OriginalSourceRead<'a> {
    pub(in crate::linux::remote::dynamic::owner) fn acquire(
        owner: &'a Owner,
        initial: &'a DynamicStop,
        until: Instant,
        scratch: &'a InitialReadScratch,
    ) -> Result<Self, GateError> {
        let read = Self {
            context: SourceReadContext {
                owner,
                until,
                bounded: true,
            },
            initial,
            scratch,
        };
        read.reauthenticate()?;
        Ok(read)
    }
    fn reauthenticate(&self) -> Result<(), GateError> {
        let owner = self.context.owner;
        owner.time_left(
            self.context.until,
            "initial source original EXEC authentication",
        )?;
        let event = owner.require_stop(self.initial)?;
        if !matches!(event.kind, DynamicEventKind::Exec { .. })
            || owner.lifecycle.is_some()
            || owner.lifecycle_options.is_none()
            || owner.owned.len() != 1
            || !owner.owned.contains(&owner.pid)
            || self.initial.session != owner.session
            || self.initial.tid != owner.pid
            || self.initial.task.is_some()
            || owner.pin_kinds.get(&owner.pid) != Some(&PinKind::Process)
            || owner.handles.get(&owner.pid).is_none_or(broker::hup)
            || owner.reaped.contains(&owner.pid)
            || owner.tracer_terminal.contains_key(&owner.pid)
            || owner
                .stopped
                .get(&owner.pid)
                .is_none_or(|status| !libc::WIFSTOPPED(*status))
        {
            return Err(refused(
                "initial source lacks the original held singleton EXEC",
            ));
        }
        initial::original_singleton(&self.context, self.scratch)?;
        let registers = read_registers(owner.pid)?;
        if owner.initial_exec != Some(registers)
            || registers.cs != 0x33
            || registers.orig_rax != libc::SYS_execve as u64
            || registers.rax != (-i64::from(libc::ENOSYS)) as u64
        {
            return Err(refused(
                "initial source original EXEC register identity differs",
            ));
        }
        if owner.handles.get(&owner.pid).is_none_or(broker::hup) {
            return Err(refused(
                "initial source original process pin is no longer live",
            ));
        }
        owner.time_left(
            self.context.until,
            "initial source original EXEC authentication",
        )?;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner) fn read_maps_capture(
        &self,
        storage: &mut [u8],
        progress: &mut SourceReadProgress,
    ) -> Result<usize, GateError> {
        read::maps_capture(&self.context, storage, progress, || self.reauthenticate())
    }
    pub(in crate::linux::remote::dynamic::owner) fn read_memory_capture(
        &self,
        address: u64,
        storage: &mut [u8],
        progress: &mut SourceReadProgress,
    ) -> Result<(), GateError> {
        read::memory_capture(&self.context, address, storage, progress, || {
            self.reauthenticate()
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn executable_projection(
        &self,
        storage: &mut [u8],
    ) -> Result<ExecutableIdentity, GateError> {
        self.reauthenticate()?;
        let result = backing::observe(&self.context, storage)?;
        self.reauthenticate()?;
        Ok(result)
    }
}

pub(super) fn authenticate_bootstrap(
    owner: &Owner,
    native: &NativeLifecycle,
    boot: &BootstrapMm,
    until: Instant,
) -> Result<(), GateError> {
    owner.time_left(until, "exec held bootstrap authentication")?;
    native.require_admission_stop(&boot.stop)?;
    let task = boot.stop.identity;
    let members = native.check_admission_mm(owner, task.task)?;
    if owner.lifecycle.is_some()
        || owner.owned.len() != 1
        || !owner.owned.contains(&owner.pid)
        || boot.stop.token.tid != owner.pid
        || boot.stop.token.session != owner.session
        || owner.pin_kinds.get(&owner.pid) != Some(&PinKind::Process)
        || owner.handles.get(&owner.pid).is_none_or(broker::hup)
        || owner.reaped.contains(&owner.pid)
        || owner.tracer_terminal.contains_key(&owner.pid)
        || !native.admission_events_empty()
        || native.admission_interrupt_credit(owner.pid)? != 0
        || !matches!(
            boot.stop.phase,
            AdmissionPhase::EntryReady | AdmissionPhase::Restored
        )
        || boot.stop.signal.is_some()
        || task.generation != 0
        || members.address_space != task.address_space
        || members.process != task.process
        || members.generation != 0
        || members.tgid != owner.pid
        || members.tids.len() != 1
        || !members.tids.contains(&owner.pid)
        || members.candidate.tasks.as_slice() != [task.task]
        || boot.island.address_space != task.address_space
        || boot.island.generation != 0
        || owner
            .stopped
            .get(&owner.pid)
            .is_none_or(|status| !libc::WIFSTOPPED(*status))
    {
        return Err(refused(
            "exec bootstrap no longer owns the exact held singleton",
        ));
    }
    boot.island.verify(owner.pid)?;
    owner.time_left(until, "exec held bootstrap authentication")?;
    Ok(())
}

fn proc_directory(context: &SourceReadContext<'_>) -> Result<File, GateError> {
    if context.bounded {
        return initial::proc_directory(context);
    }
    context
        .owner
        .time_left(context.until, "exec source proc directory")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(format!("/proc/{}", context.owner.pid))
        .map_err(|error| io_error("open exec source proc directory", error))?;
    let mut raw = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: the owned descriptor and initialized native statfs output live
    // through the synchronous read-only kernel request.
    if unsafe { libc::fstatfs(file.as_raw_fd(), raw.as_mut_ptr()) } != 0 {
        return Err(system("stat exec source proc filesystem").into());
    }
    // SAFETY: successful fstatfs initialized the output.
    if unsafe { raw.assume_init() }.f_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t {
        return Err(refused("exec source directory is not procfs"));
    }
    context
        .owner
        .time_left(context.until, "exec source proc directory")?;
    Ok(file)
}

fn read_maps_into(context: &SourceReadContext<'_>, storage: &mut [u8]) -> Result<usize, GateError> {
    if storage.len() != MAP_BYTES {
        return Err(refused("exec source maps scratch differs"));
    }
    storage.fill(0);
    let directory = proc_directory(context)?;
    // SAFETY: fixed component; owned directory and resulting fd remain local.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"maps".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(system("open current exec source maps").into());
    }
    // SAFETY: this successful descriptor has no other owner.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut length = 0;
    loop {
        context
            .owner
            .time_left(context.until, "read current exec source maps")?;
        if length == storage.len() {
            let mut extra = [0_u8; 1];
            if file
                .read(&mut extra)
                .map_err(|e| io_error("read exec source maps bound", e))?
                != 0
            {
                return Err(refused("exec source maps exceed fixed capture bound"));
            }
            break;
        }
        let count = file
            .read(&mut storage[length..])
            .map_err(|e| io_error("read current exec source maps", e))?;
        context
            .owner
            .time_left(context.until, "read current exec source maps")?;
        if count == 0 {
            break;
        }
        length += count;
    }
    context
        .owner
        .time_left(context.until, "read current exec source maps")?;
    parse(&storage[..length])?;
    Ok(length)
}

pub(super) fn parse(raw: &[u8]) -> Result<ParsedMaps<'_>, GateError> {
    if raw.len() > MAP_BYTES {
        return Err(refused("exec source maps exceed fixed capture bound"));
    }
    ParsedMaps::parse(raw, MAP_ROWS)
        .map_err(|_| refused("exec source maps are malformed or excessive"))
}

pub(in crate::linux::remote::dynamic::owner::admission) fn file_identity(
    row: MapEntry<'_>,
) -> FileIdentity {
    FileIdentity {
        major: row.device_major,
        minor: row.device_minor,
        inode: row.inode,
    }
}
pub(in crate::linux::remote::dynamic::owner::admission) fn row_matches(
    row: &SourceVma,
    map: MapEntry<'_>,
) -> bool {
    row.start == map.start
        && row.end == map.end
        && row.offset == map.file_offset
        && row.file == file_identity(map)
}
pub(in crate::linux::remote::dynamic::owner::admission) fn line_span(
    raw: &[u8],
    line: &[u8],
) -> (usize, usize) {
    // Both slices come from the same fully validated immutable ParsedMaps.
    (line.as_ptr() as usize - raw.as_ptr() as usize, line.len())
}
pub(in crate::linux::remote::dynamic::owner::admission) fn descriptor_fields(
    row: MapEntry<'_>,
    map: &MemoryMapping,
) -> bool {
    row.start == map.start
        && row.end == map.end
        && row.file_offset == map.file_offset
        && row.pathname == map.pathname.as_ref().map(|path| path.as_bytes())
}
pub(in crate::linux::remote::dynamic::owner::admission) fn same_descriptor(
    row: MapEntry<'_>,
    map: &MemoryMapping,
) -> bool {
    descriptor_fields(row, map) && row.permissions.bytes().as_slice() == map.permissions.as_bytes()
}
pub(in crate::linux::remote::dynamic::owner::admission) fn fixed_vsyscall(
    row: MapEntry<'_>,
) -> bool {
    row.start == 0xffff_ffff_ff60_0000
        && row.end == 0xffff_ffff_ff60_1000
        && row.permissions.bytes() == *b"--xp"
        && row.file_offset == 0
        && row.device_major == 0
        && row.device_minor == 0
        && row.inode == 0
        && row.pathname == Some(b"[vsyscall]".as_slice())
}
pub(in crate::linux::remote::dynamic::owner::admission) fn exact_nx(
    old: MapEntry<'_>,
    new: MapEntry<'_>,
) -> bool {
    if old.permissions.bytes() != *b"r-xp"
        || new.permissions.bytes() != *b"r--p"
        || old.raw_line.len() != new.raw_line.len()
    {
        return false;
    }
    let Some(start) = old.raw_line.iter().position(|b| *b == b' ') else {
        return false;
    };
    let Some(skip) = old.raw_line[start..].iter().position(|b| *b != b' ') else {
        return false;
    };
    let column = start + skip + 2;
    old.raw_line
        .iter()
        .zip(new.raw_line)
        .enumerate()
        .all(|(index, (a, b))| {
            if index == column {
                *a == b'x' && *b == b'-'
            } else {
                a == b
            }
        })
}
