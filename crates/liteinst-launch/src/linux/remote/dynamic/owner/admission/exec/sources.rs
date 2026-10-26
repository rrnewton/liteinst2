//! Runtime whole-VMA source observations after actual exec and NX bootstrap.
//! No parser, instruction-head authority, native transition or account lives here.
use super::super::super::exec_journal::{
    ExecAttemptHandle, ExecJournalWriter, ExecMapsStatus, ExecSourceMaps,
};
use super::super::super::kernel_journal::{KernelAttemptId, KernelStopIdentity};
use super::super::mapping::maps::{MapEntry, ParsedMaps};
use super::*;
use crate::linux::remote::dynamic::admission::{
    DynamicExecProfile, DynamicSourceCaptureId, DynamicSourceImage, DynamicSourceRequestId,
};
use crate::linux::{EntryEvidence, FirstImage};
use std::alloc::Layout;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::Arc;

const MAP_BYTES: usize = 64 * 1024;
const MAP_ROWS: usize = 512;
const PAGE: u64 = 4096;

#[cfg(test)]
mod tests;

pub(super) struct ExecSourceContext<'a> {
    pub(super) owner: &'a Owner,
    pub(super) native: &'a NativeLifecycle,
    pub(super) journal: &'a ExecJournalWriter,
    pub(super) attempt: ExecAttemptHandle,
    pub(super) until: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    major: u32,
    minor: u32,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImageRole {
    Executable,
    Interpreter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceRow {
    original_index: usize,
    current_index: usize,
    original_span: (usize, usize),
    current_span: (usize, usize),
    start: u64,
    end: u64,
    offset: u64,
    file: FileIdentity,
    role: ImageRole,
}

struct Geometry<'a> {
    originals: &'a [MemoryMapping],
    current: &'a [MemoryMapping],
    island: &'a Range<u64>,
    entry: &'a EntryEvidence,
    executable: FileIdentity,
    profile: &'a DynamicExecProfile,
}

pub(super) struct PreparedExecSources {
    profile: DynamicExecProfile,
    maps: Vec<u8>,
    rows: Vec<SourceRow>,
    staging: Vec<Vec<u8>>,
    images: Vec<DynamicSourceImage>,
    started: bool,
}

pub(super) struct CapturedExecSources {
    profile: DynamicExecProfile,
    attempt: KernelAttemptId,
    request: DynamicSourceRequestId,
    first_incarnation: u64,
    previous: DynamicTask,
    current: DynamicTask,
    exit: DynamicStop,
    stop: DynamicStop,
    until: Instant,
    exit_ordinal: u8,
    executable: FileIdentity,
    rows: Vec<SourceRow>,
    images: Arc<[DynamicSourceImage]>,
}

fn checked_add(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_add(b)
        .ok_or_else(|| refused("exec source allocation size overflows"))
}
fn checked_mul(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_mul(b)
        .ok_or_else(|| refused("exec source allocation size overflows"))
}
fn arc_bytes<T>(count: usize) -> Result<usize, GateError> {
    let array =
        Layout::array::<T>(count).map_err(|_| refused("exec source Arc layout overflows"))?;
    Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
        .extend(array)
        .map(|(layout, _)| layout.pad_to_align().size())
        .map_err(|_| refused("exec source Arc layout overflows"))
}
fn reserve<T>(count: usize) -> Result<Vec<T>, GateError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| refused("exec source allocation failed"))?;
    Ok(values)
}
fn bounds(profile: &DynamicExecProfile) -> Result<(), GateError> {
    if !(1..=64).contains(&profile.max_capture_images)
        || profile.max_capture_bytes == 0
        || profile.max_capture_bytes > MAP_BYTES
        || profile.max_capture_bytes % PAGE as usize != 0
        || profile.max_total_capture_bytes < profile.max_capture_bytes
        || profile.max_total_capture_bytes % PAGE as usize != 0
        || checked_mul(profile.max_capture_images, profile.max_capture_bytes)?
            < profile.max_total_capture_bytes
    {
        return Err(refused("exec source capture profile differs"));
    }
    Ok(())
}

impl PreparedExecSources {
    /// Source-owned allocation upper, including staging/Arc conversion peaks.
    /// Root separately reserves native bootstrap/helper, Domain and journal work.
    pub(super) fn reservation_bytes(profile: &DynamicExecProfile) -> Result<usize, GateError> {
        bounds(profile)?;
        let n = profile.max_capture_images;
        let mut bytes = checked_add(size_of::<Self>(), size_of::<CapturedExecSources>())?;
        bytes = checked_add(bytes, MAP_BYTES)?;
        bytes = checked_add(bytes, checked_mul(2, MAX_XSTATE)?)?;
        bytes = checked_add(
            bytes,
            checked_mul(
                n,
                size_of::<SourceRow>() + size_of::<Vec<u8>>() + size_of::<DynamicSourceImage>(),
            )?,
        )?;
        bytes = checked_add(bytes, checked_mul(n, profile.max_capture_bytes)?)?;
        // One temporary bounded read, immutable source Arcs, image-array Arc,
        // and four descriptor/path copies per selected row coexist in the peak.
        bytes = checked_add(bytes, profile.max_capture_bytes)?;
        bytes = checked_add(
            bytes,
            checked_mul(n, arc_bytes::<u8>(profile.max_capture_bytes)?)?,
        )?;
        bytes = checked_add(bytes, arc_bytes::<DynamicSourceImage>(n)?)?;
        bytes = checked_add(bytes, checked_mul(checked_mul(4, n)?, MAP_BYTES + 4)?)?;
        // Proc query strings and complete scalar/descriptor request storage.
        checked_add(
            bytes,
            256 + size_of::<libc::statfs>() + size_of::<FileIdentity>(),
        )
    }

    pub(super) fn new(profile: &DynamicExecProfile) -> Result<Self, GateError> {
        bounds(profile)?;
        let mut maps = reserve(MAP_BYTES)?;
        maps.resize(MAP_BYTES, 0);
        let mut staging = reserve(profile.max_capture_images)?;
        for _ in 0..profile.max_capture_images {
            staging.push(reserve(profile.max_capture_bytes)?);
        }
        let prepared = Self {
            profile: profile.clone(),
            maps,
            rows: reserve(profile.max_capture_images)?,
            images: reserve(profile.max_capture_images)?,
            staging,
            started: false,
        };
        if prepared.allocated_bytes()? > Self::reservation_bytes(profile)? {
            return Err(refused(
                "exec source allocator exceeded its pre-effect envelope",
            ));
        }
        Ok(prepared)
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize, GateError> {
        let mut bytes = checked_add(size_of::<Self>(), self.maps.capacity())?;
        bytes = checked_add(
            bytes,
            checked_mul(self.rows.capacity(), size_of::<SourceRow>())?,
        )?;
        bytes = checked_add(
            bytes,
            checked_mul(self.images.capacity(), size_of::<DynamicSourceImage>())?,
        )?;
        bytes = checked_add(
            bytes,
            checked_mul(self.staging.capacity(), size_of::<Vec<u8>>())?,
        )?;
        for slot in &self.staging {
            bytes = checked_add(bytes, slot.capacity())?;
        }
        // Images may be present after a failed partial capture; keep their
        // real payloads counted without calling the batch complete.
        for image in &self.images {
            bytes = checked_add(bytes, image_payload(image)?)?;
        }
        Ok(bytes)
    }

    pub(super) fn capture(
        &mut self,
        context: &ExecSourceContext<'_>,
        ready: &ExecBootstrapReady,
        request: DynamicSourceRequestId,
        first_incarnation: u64,
    ) -> Result<CapturedExecSources, GateError> {
        if self.started || !self.rows.is_empty() || !self.images.is_empty() {
            return Err(refused("exec source preparation was already used"));
        }
        self.started = true;
        let transition = ready.transition();
        let boot = ready.bootstrap();
        if transition.until() != context.until
            || context.attempt.id().session != request.session
            || request.session != boot.stop.token.session
            || request.serial == 0
            || first_incarnation == 0
            || first_incarnation
                .checked_add(self.profile.max_capture_images as u64)
                .is_none()
        {
            return Err(refused("exec source request identity differs"));
        }
        current(context, boot)?;
        let executable = executable_object(context)?;
        let entry = match &transition.exec_event().kind {
            DynamicEventKind::ExecReplaced { previous, evidence }
                if *previous == transition.previous() =>
            {
                evidence
            }
            _ => return Err(refused("exec source lacks actual replaced entry evidence")),
        };
        let exit = transition
            .exit()
            .stop_token()
            .ok_or_else(|| refused("exec source lacks actual EXIT token"))?;
        let geometry = Geometry {
            originals: &boot.original_executables,
            current: &boot.mappings,
            island: &boot.island.range,
            entry,
            executable,
            profile: &self.profile,
        };
        let exit_ordinal = context.journal.with_source_maps(context.attempt, |view| {
            bind_view(
                &view,
                transition.previous(),
                transition.current(),
                exit,
                &boot.stop.token,
            )?;
            let original = parse(view.exit_bytes)?;
            let quarantine = parse(view.quarantine_bytes)?;
            derive_rows(original, quarantine, &geometry, &mut self.rows)?;
            Ok::<_, GateError>(view.exit_ordinal)
        })??;
        // No native read or allocation happens inside the journal closure.
        let len = read_maps_into(context, &mut self.maps)?;
        context.journal.with_source_maps(context.attempt, |view| {
            bind_view(
                &view,
                transition.previous(),
                transition.current(),
                exit,
                &boot.stop.token,
            )?;
            if view.exit_ordinal != exit_ordinal || &self.maps[..len] != view.quarantine_bytes {
                return Err(refused("exec current maps differ from final quarantine"));
            }
            Ok::<_, GateError>(())
        })??;
        let quarantine = parse(&self.maps[..len])?;
        for (index, row) in self.rows.iter().enumerate() {
            context
                .owner
                .time_left(context.until, "exec source whole VMA capture")?;
            let map = quarantine
                .entries()
                .nth(row.current_index)
                .ok_or_else(|| refused("exec source map row disappeared"))?;
            if !row_matches(row, map) {
                return Err(refused("exec source map identity differs"));
            }
            let count = usize::try_from(row.end - row.start)
                .map_err(|_| refused("exec source VMA length overflows"))?;
            let bytes = read_memory(context.owner.pid, row.start, count)?;
            context
                .owner
                .time_left(context.until, "exec source whole VMA capture")?;
            if bytes.len() != count || self.staging[index].capacity() < count {
                return Err(refused("exec source whole VMA read is incomplete"));
            }
            self.staging[index].extend_from_slice(&bytes);
            let lower = row
                .current_index
                .checked_sub(1)
                .and_then(|i| quarantine.entries().nth(i))
                .filter(|m| m.end == row.start);
            let upper = quarantine
                .entries()
                .nth(row.current_index + 1)
                .filter(|m| m.start == row.end);
            if lower.is_some_and(|m| m.permissions.bytes()[2] == b'x')
                || upper.is_some_and(|m| m.permissions.bytes()[2] == b'x')
            {
                return Err(refused("exec source has an executable adjacent mapping"));
            }
            self.images.push(DynamicSourceImage {
                id: DynamicSourceCaptureId { request, index },
                mapping_incarnation: first_incarnation
                    .checked_add(index as u64)
                    .ok_or_else(|| refused("exec source incarnation exhausted"))?,
                original: descriptor(map, *b"r-xp")?,
                quarantined: descriptor(map, *b"r--p")?,
                bytes: Arc::from(std::mem::take(&mut self.staging[index])),
                lower_neighbor: lower
                    .map(|m| descriptor(m, m.permissions.bytes()))
                    .transpose()?,
                upper_neighbor: upper
                    .map(|m| descriptor(m, m.permissions.bytes()))
                    .transpose()?,
            });
        }
        let len = read_maps_into(context, &mut self.maps)?;
        context.journal.with_source_maps(context.attempt, |view| {
            bind_view(
                &view,
                transition.previous(),
                transition.current(),
                exit,
                &boot.stop.token,
            )?;
            if view.exit_ordinal != exit_ordinal || &self.maps[..len] != view.quarantine_bytes {
                return Err(refused("exec source maps changed during capture"));
            }
            Ok::<_, GateError>(())
        })??;
        if executable_object(context)? != executable {
            return Err(refused("exec executable object changed during capture"));
        }
        current(context, boot)?;
        Ok(CapturedExecSources {
            profile: self.profile.clone(),
            attempt: context.attempt.id(),
            request,
            first_incarnation,
            previous: transition.previous(),
            current: transition.current(),
            exit: exit.clone(),
            stop: boot.stop.token.clone(),
            until: context.until,
            exit_ordinal,
            executable,
            rows: std::mem::take(&mut self.rows),
            images: Arc::from(std::mem::take(&mut self.images)),
        })
    }
}

impl CapturedExecSources {
    pub(super) fn images(&self) -> &Arc<[DynamicSourceImage]> {
        &self.images
    }

    pub(super) fn retained_bytes(&self) -> Result<usize, GateError> {
        let mut bytes = checked_add(
            size_of::<Self>(),
            checked_mul(self.rows.capacity(), size_of::<SourceRow>())?,
        )?;
        bytes = checked_add(bytes, arc_bytes::<DynamicSourceImage>(self.images.len())?)?;
        for image in self.images.iter() {
            bytes = checked_add(bytes, image_payload(image)?)?;
        }
        Ok(bytes)
    }

    /// Increment after preparation was debited. The containing ExecAttempt
    /// already owns this inline header, and capture moves the precharged row
    /// Vec without allocating it again. Every new Arc and string still counts.
    pub(super) fn newly_retained_bytes(&self) -> Result<usize, GateError> {
        let transferred = checked_add(
            size_of::<Self>(),
            checked_mul(self.rows.capacity(), size_of::<SourceRow>())?,
        )?;
        self.retained_bytes()?
            .checked_sub(transferred)
            .ok_or_else(|| refused("exec source transferred allocation differs"))
    }

    pub(super) fn reauthenticate(
        &self,
        context: &ExecSourceContext<'_>,
        boot: &BootstrapMm,
        scratch: &mut PreparedExecSources,
    ) -> Result<(), GateError> {
        if self.attempt != context.attempt.id()
            || self.until != context.until
            || self.stop != boot.stop.token
            || self.current != boot.stop.identity
            || self.request.session != self.stop.session
            || self.request.serial == 0
            || self.images.len() != self.rows.len()
            || self.images.is_empty()
            || self.images.len() > self.profile.max_capture_images
            || scratch.maps.len() != MAP_BYTES
        {
            return Err(refused("exec source receipt no longer binds the capture"));
        }
        current(context, boot)?;
        if executable_object(context)? != self.executable {
            return Err(refused("exec source executable object identity differs"));
        }
        let len = read_maps_into(context, &mut scratch.maps)?;
        context.journal.with_source_maps(context.attempt, |view| {
            bind_view(&view, self.previous, self.current, &self.exit, &self.stop)?;
            if view.exit_ordinal != self.exit_ordinal
                || &scratch.maps[..len] != view.quarantine_bytes
            {
                return Err(refused("exec source receipt maps changed"));
            }
            let old = parse(view.exit_bytes)?;
            let new = parse(view.quarantine_bytes)?;
            for (index, row) in self.rows.iter().enumerate() {
                let a = old
                    .entries()
                    .nth(row.original_index)
                    .ok_or_else(|| refused("exec original source row disappeared"))?;
                let b = new
                    .entries()
                    .nth(row.current_index)
                    .ok_or_else(|| refused("exec current source row disappeared"))?;
                if !row_matches(row, a)
                    || !row_matches(row, b)
                    || match row.role {
                        ImageRole::Executable => row.file != self.executable,
                        ImageRole::Interpreter => row.file == self.executable,
                    }
                    || line_span(view.exit_bytes, a.raw_line) != row.original_span
                    || line_span(view.quarantine_bytes, b.raw_line) != row.current_span
                    || !exact_nx(a, b)
                    || !image_matches(
                        &self.images[index],
                        row,
                        b,
                        new,
                        self.request,
                        index,
                        self.first_incarnation,
                    )
                {
                    return Err(refused("exec source receipt raw identity differs"));
                }
            }
            Ok::<_, GateError>(())
        })??;
        for (index, image) in self.images.iter().enumerate() {
            context
                .owner
                .time_left(context.until, "exec source callback byte recheck")?;
            let row = &self.rows[index];
            if image.id
                != (DynamicSourceCaptureId {
                    request: self.request,
                    index,
                })
                || image.original.start != row.start
                || image.original.end != row.end
                || read_memory(context.owner.pid, row.start, image.bytes.len())?.as_slice()
                    != image.bytes.as_ref()
            {
                return Err(refused("exec source bytes changed after source callback"));
            }
            context
                .owner
                .time_left(context.until, "exec source callback byte recheck")?;
        }
        let len = read_maps_into(context, &mut scratch.maps)?;
        context.journal.with_source_maps(context.attempt, |view| {
            bind_view(&view, self.previous, self.current, &self.exit, &self.stop)?;
            if view.exit_ordinal != self.exit_ordinal
                || &scratch.maps[..len] != view.quarantine_bytes
            {
                return Err(refused("exec source maps changed during callback recheck"));
            }
            Ok::<_, GateError>(())
        })??;
        if executable_object(context)? != self.executable {
            return Err(refused(
                "exec source executable object changed during recheck",
            ));
        }
        current(context, boot)
    }
}

fn image_payload(image: &DynamicSourceImage) -> Result<usize, GateError> {
    let mut bytes = arc_bytes::<u8>(image.bytes.len())?;
    for map in [
        Some(&image.original),
        Some(&image.quarantined),
        image.lower_neighbor.as_ref(),
        image.upper_neighbor.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        bytes = checked_add(bytes, map.permissions.capacity())?;
        bytes = checked_add(bytes, map.pathname.as_ref().map_or(0, String::capacity))?;
    }
    Ok(bytes)
}

fn current(context: &ExecSourceContext<'_>, boot: &BootstrapMm) -> Result<(), GateError> {
    super::seal::authenticate_bootstrap(context.owner, context.native, boot, context.until)?;
    if TaskStateSnapshot::read(context.owner.pid)? != boot.evidence.restored_entry {
        return Err(refused(
            "exec source acquisition changed complete bootstrap state",
        ));
    }
    context
        .owner
        .time_left(context.until, "exec source current-state authentication")?;
    Ok(())
}

fn proc_directory(context: &ExecSourceContext<'_>) -> Result<File, GateError> {
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

fn executable_object(context: &ExecSourceContext<'_>) -> Result<FileIdentity, GateError> {
    let directory = proc_directory(context)?;
    // Follow proc's actual exe object, not a readlink pathname. The task/pin
    // remains held; fstatfs applies to directory, not the executable filesystem.
    // SAFETY: fixed NUL-terminated component and owned directory descriptor.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"exe".as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(system("open actual exec source object").into());
    }
    // SAFETY: this is the successful new descriptor's sole owner.
    let file = unsafe { File::from_raw_fd(fd) };
    let stat = file
        .metadata()
        .map_err(|error| io_error("stat actual exec source object", error))?;
    if !stat.is_file() || stat.ino() == 0 {
        return Err(refused(
            "exec source object is not an identified regular file",
        ));
    }
    let identity = FileIdentity {
        major: libc::major(stat.dev()),
        minor: libc::minor(stat.dev()),
        inode: stat.ino(),
    };
    context
        .owner
        .time_left(context.until, "exec source object authentication")?;
    Ok(identity)
}

fn read_maps_into(context: &ExecSourceContext<'_>, storage: &mut [u8]) -> Result<usize, GateError> {
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

fn parse(raw: &[u8]) -> Result<ParsedMaps<'_>, GateError> {
    if raw.len() > MAP_BYTES {
        return Err(refused("exec source maps exceed fixed capture bound"));
    }
    ParsedMaps::parse(raw, MAP_ROWS)
        .map_err(|_| refused("exec source maps are malformed or excessive"))
}

fn bind_view(
    view: &ExecSourceMaps<'_>,
    previous: DynamicTask,
    current: DynamicTask,
    exit: &DynamicStop,
    final_stop: &DynamicStop,
) -> Result<(), GateError> {
    if view.previous != previous
        || view.replacement != current
        || view.exit_stop != KernelStopIdentity::from(exit)
        || view.final_stop != KernelStopIdentity::from(final_stop)
        || view.exit.status != ExecMapsStatus::Complete
        || view.quarantine.status != ExecMapsStatus::Complete
        || view.exit.tid != exit.tid
        || view.quarantine.tid != final_stop.tid
        || view.exit.observed_bytes != view.exit_bytes.len()
        || view.quarantine.observed_bytes != view.quarantine_bytes.len()
        || view.exit.filesystem_type != libc::PROC_SUPER_MAGIC
        || view.quarantine.filesystem_type != libc::PROC_SUPER_MAGIC
    {
        return Err(refused("exec source journal phase or identity differs"));
    }
    Ok(())
}

fn file_identity(row: MapEntry<'_>) -> FileIdentity {
    FileIdentity {
        major: row.device_major,
        minor: row.device_minor,
        inode: row.inode,
    }
}
fn row_matches(row: &SourceRow, map: MapEntry<'_>) -> bool {
    row.start == map.start
        && row.end == map.end
        && row.offset == map.file_offset
        && row.file == file_identity(map)
}
fn line_span(raw: &[u8], line: &[u8]) -> (usize, usize) {
    // Both slices come from the same fully validated immutable ParsedMaps.
    (line.as_ptr() as usize - raw.as_ptr() as usize, line.len())
}
fn descriptor_fields(row: MapEntry<'_>, map: &MemoryMapping) -> bool {
    row.start == map.start
        && row.end == map.end
        && row.file_offset == map.file_offset
        && row.pathname == map.pathname.as_ref().map(|path| path.as_bytes())
}
fn same_descriptor(row: MapEntry<'_>, map: &MemoryMapping) -> bool {
    descriptor_fields(row, map) && row.permissions.bytes().as_slice() == map.permissions.as_bytes()
}
fn image_matches(
    image: &DynamicSourceImage,
    row: &SourceRow,
    map: MapEntry<'_>,
    maps: ParsedMaps<'_>,
    request: DynamicSourceRequestId,
    index: usize,
    first_incarnation: u64,
) -> bool {
    let lower = row
        .current_index
        .checked_sub(1)
        .and_then(|i| maps.entries().nth(i))
        .filter(|m| m.end == row.start);
    let upper = maps
        .entries()
        .nth(row.current_index + 1)
        .filter(|m| m.start == row.end);
    let neighbor = |raw: Option<MapEntry<'_>>, saved: Option<&MemoryMapping>| match (raw, saved) {
        (None, None) => true,
        (Some(raw), Some(saved)) => {
            raw.permissions.bytes()[2] != b'x' && same_descriptor(raw, saved)
        }
        _ => false,
    };
    image.id == (DynamicSourceCaptureId { request, index })
        && first_incarnation.checked_add(index as u64) == Some(image.mapping_incarnation)
        && image.mapping_incarnation != 0
        && u64::try_from(image.bytes.len()).ok() == row.end.checked_sub(row.start)
        && descriptor_fields(map, &image.original)
        && image.original.permissions == "r-xp"
        && same_descriptor(map, &image.quarantined)
        && image.quarantined.permissions == "r--p"
        && neighbor(lower, image.lower_neighbor.as_ref())
        && neighbor(upper, image.upper_neighbor.as_ref())
}
fn fixed_vsyscall(row: MapEntry<'_>) -> bool {
    row.start == 0xffff_ffff_ff60_0000
        && row.end == 0xffff_ffff_ff60_1000
        && row.permissions.bytes() == *b"--xp"
        && row.file_offset == 0
        && row.device_major == 0
        && row.device_minor == 0
        && row.inode == 0
        && row.pathname == Some(b"[vsyscall]".as_slice())
}
fn exact_nx(old: MapEntry<'_>, new: MapEntry<'_>) -> bool {
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

fn derive_rows(
    old: ParsedMaps<'_>,
    new: ParsedMaps<'_>,
    geometry: &Geometry<'_>,
    output: &mut Vec<SourceRow>,
) -> Result<(), GateError> {
    bounds(geometry.profile)?;
    if !output.is_empty() || output.capacity() < geometry.profile.max_capture_images {
        return Err(refused("exec source geometry storage differs"));
    }
    if new.entries().len()
        != old
            .entries()
            .len()
            .checked_add(1)
            .ok_or_else(|| refused("exec source map count overflows"))?
        || geometry.current.len() != new.entries().len()
        || !new
            .entries()
            .zip(geometry.current)
            .all(|(row, map)| same_descriptor(row, map))
    {
        return Err(refused("exec source final bootstrap inventory differs"));
    }
    let island = new
        .entries()
        .find(|m| m.start == geometry.island.start && m.end == geometry.island.end)
        .ok_or_else(|| refused("exec source trusted island mapping is absent"))?;
    if island.permissions.bytes() != *b"r-xp"
        || island.file_offset != 0
        || island.device_major != 0
        || island.device_minor != 0
        || island.inode != 0
        || island.pathname.is_some()
        || old
            .entries()
            .any(|m| m.start < island.end && island.start < m.end)
    {
        return Err(refused("exec source trusted island mapping differs"));
    }
    let mut executable_index = 0;
    for prior in old.entries() {
        let current = new
            .entries()
            .find(|m| m.start == prior.start && m.end == prior.end)
            .ok_or_else(|| refused("exec quarantine changed whole VMA geometry"))?;
        if prior.permissions.bytes()[2] == b'x' && !fixed_vsyscall(prior) {
            if !exact_nx(prior, current)
                || geometry
                    .originals
                    .get(executable_index)
                    .is_none_or(|m| !same_descriptor(prior, m))
            {
                return Err(refused(
                    "exec quarantine changed executable descriptor identity",
                ));
            }
            executable_index += 1;
        } else if prior.raw_line != current.raw_line {
            return Err(refused("exec quarantine changed an unaffected mapping"));
        }
    }
    if executable_index != geometry.originals.len() {
        return Err(refused("exec original executable inventory is incomplete"));
    }
    let main = old
        .entries()
        .find(|row| {
            row.start <= geometry.entry.executable_entry
                && geometry.entry.executable_entry < row.end
        })
        .ok_or_else(|| refused("exec main entry mapping is absent"))?;
    if main.permissions.bytes() != *b"r-xp"
        || main.inode == 0
        || file_identity(main) != geometry.executable
    {
        #[cfg(test)]
        eprintln!(
            "exec backing mismatch: map={:?}, executable={:?}, permissions={:?}, entry={:#x}",
            file_identity(main),
            geometry.executable,
            main.permissions.bytes(),
            geometry.entry.executable_entry,
        );
        return Err(refused(
            "exec main entry is not the actual executable object",
        ));
    }
    let interpreter = match geometry.entry.first_image {
        FirstImage::Executable => {
            if geometry.entry.interpreter.is_some()
                || geometry.entry.interpreter_base != 0
                || geometry.entry.initial_instruction != geometry.entry.executable_entry
            {
                return Err(refused("exec main-only entry facts differ"));
            }
            None
        }
        FirstImage::Interpreter => {
            if geometry.entry.interpreter.is_none() {
                return Err(refused("exec interpreter fact is absent"));
            }
            let initial = old
                .entries()
                .find(|row| {
                    row.start <= geometry.entry.initial_instruction
                        && geometry.entry.initial_instruction < row.end
                })
                .ok_or_else(|| refused("exec interpreter entry mapping is absent"))?;
            let base = geometry.entry.interpreter_base;
            let header = if base == 0 {
                initial
            } else {
                old.entries()
                    .find(|row| row.start <= base && base < row.end)
                    .ok_or_else(|| refused("exec interpreter header mapping is absent"))?
            };
            if initial.permissions.bytes() != *b"r-xp"
                || initial.inode == 0
                || file_identity(initial) == geometry.executable
                || file_identity(header) != file_identity(initial)
                || header.file_offset != 0
                || (base != 0 && header.start != base)
                || header.end - header.start < 64
                || (base == 0
                    && geometry.entry.initial_instruction == geometry.entry.executable_entry)
            {
                return Err(refused("exec interpreter backing identity differs"));
            }
            Some(file_identity(initial))
        }
    };
    let mut total = 0_usize;
    for (index, row) in old.entries().enumerate() {
        let role = if file_identity(row) == geometry.executable {
            Some(ImageRole::Executable)
        } else if Some(file_identity(row)) == interpreter {
            Some(ImageRole::Interpreter)
        } else {
            None
        };
        if row.permissions.bytes()[2] != b'x' || role.is_none() {
            continue;
        }
        let count = usize::try_from(row.end - row.start)
            .map_err(|_| refused("exec source VMA length overflows"))?;
        total = checked_add(total, count)?;
        if row.permissions.bytes() != *b"r-xp"
            || row.file_offset % PAGE != 0
            || row.pathname.is_none_or(|name| name.is_empty())
            || row.start == 0
            || count > geometry.profile.max_capture_bytes
            || total > geometry.profile.max_total_capture_bytes
            || output.len() == geometry.profile.max_capture_images
        {
            return Err(refused(
                "exec whole source VMA exceeds its declared profile",
            ));
        }
        let file_end = row
            .file_offset
            .checked_add(row.end - row.start)
            .ok_or_else(|| refused("exec source backing interval overflows"))?;
        for (other_index, other) in old.entries().enumerate() {
            if other_index == index || file_identity(other) != file_identity(row) {
                continue;
            }
            let other_end = other
                .file_offset
                .checked_add(other.end - other.start)
                .ok_or_else(|| refused("exec alias backing interval overflows"))?;
            if row.file_offset < other_end && other.file_offset < file_end {
                return Err(refused("exec source has a visible file-offset alias"));
            }
        }
        let (current_index, current) = new
            .entries()
            .enumerate()
            .find(|(_, m)| m.start == row.start && m.end == row.end)
            .ok_or_else(|| refused("exec source quarantine row is absent"))?;
        output.push(SourceRow {
            original_index: index,
            current_index,
            original_span: line_span(old.raw(), row.raw_line),
            current_span: line_span(new.raw(), current.raw_line),
            start: row.start,
            end: row.end,
            offset: row.file_offset,
            file: file_identity(row),
            role: role.ok_or_else(|| refused("exec source role is absent"))?,
        });
    }
    if output.is_empty() {
        return Err(refused("exec source set is empty"));
    }
    Ok(())
}

fn text(bytes: &[u8]) -> Result<String, GateError> {
    let value =
        std::str::from_utf8(bytes).map_err(|_| refused("exec source descriptor is not UTF-8"))?;
    let mut string = String::new();
    string
        .try_reserve_exact(bytes.len())
        .map_err(|_| refused("exec source descriptor allocation failed"))?;
    string.push_str(value);
    Ok(string)
}
fn descriptor(row: MapEntry<'_>, permissions: [u8; 4]) -> Result<MemoryMapping, GateError> {
    Ok(MemoryMapping {
        start: row.start,
        end: row.end,
        file_offset: row.file_offset,
        permissions: text(&permissions)?,
        pathname: row.pathname.map(text).transpose()?,
    })
}
