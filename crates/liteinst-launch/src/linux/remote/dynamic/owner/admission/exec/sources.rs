//! Runtime whole-VMA source observations after actual exec and NX bootstrap.
//! No parser, instruction-head authority, native transition or account lives here.
use super::super::super::exec_journal::{
    ExecAttemptHandle, ExecJournalWriter, ExecMapsStatus, ExecSourceMaps,
};
use super::super::super::kernel_journal::{KernelAttemptId, KernelStopIdentity};
use super::super::mapping::maps::{MapEntry, ParsedMaps};
use super::*;
use crate::linux::EntryEvidence;
#[cfg(test)]
use crate::linux::FirstImage;
use crate::linux::remote::dynamic::admission::{
    DynamicExecProfile, DynamicSourceCaptureId, DynamicSourceImage, DynamicSourceRequestId,
};
use std::alloc::Layout;
use std::sync::Arc;

use super::super::source_identity::{
    FileIdentity, HeldSourceRead, ImageRole, MAP_BYTES, PAGE, SourceGeometry, SourceInventory,
    SourceVma as SourceRow, descriptor_fields, exact_nx, line_span, parse, row_matches,
    same_descriptor,
};
#[cfg(test)]
use super::super::source_identity::{MAP_ROWS, fixed_vsyscall};

mod backing;
#[cfg(test)]
mod tests;

pub(super) struct ExecSourceContext<'a> {
    pub(super) owner: &'a Owner,
    pub(super) native: &'a NativeLifecycle,
    pub(super) journal: &'a ExecJournalWriter,
    pub(super) attempt: ExecAttemptHandle,
    pub(super) until: Instant,
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
    opened: backing::DescriptorIdentity,
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
            256 + size_of::<libc::statfs>()
                + size_of::<FileIdentity>()
                + backing::temporary_bytes(),
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
        let read = HeldSourceRead::acquire(context.owner, context.native, boot, context.until)?;
        // This scratch is not borrowed by the journal or source parser here.
        let object = backing::observe(&read, &mut self.maps)?;
        let executable = object.vma;
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
        let len = read.read_maps_into(&mut self.maps)?;
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
        let len = read.read_maps_into(&mut self.maps)?;
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
        // All child-map borrows above have ended; the probe wipes/reuses scratch.
        if backing::observe(&read, &mut self.maps)? != object {
            return Err(refused("exec executable object changed during capture"));
        }
        read.reauthenticate()?;
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
            opened: object.opened,
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
        let read = HeldSourceRead::acquire(context.owner, context.native, boot, context.until)?;
        if backing::observe(&read, &mut scratch.maps)?
            != (backing::ExecutableIdentity {
                opened: self.opened,
                vma: self.executable,
            })
        {
            return Err(refused("exec source executable object identity differs"));
        }
        let len = read.read_maps_into(&mut scratch.maps)?;
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
        let len = read.read_maps_into(&mut scratch.maps)?;
        context.journal.with_source_maps(context.attempt, |view| {
            bind_view(&view, self.previous, self.current, &self.exit, &self.stop)?;
            if view.exit_ordinal != self.exit_ordinal
                || &scratch.maps[..len] != view.quarantine_bytes
            {
                return Err(refused("exec source maps changed during callback recheck"));
            }
            Ok::<_, GateError>(())
        })??;
        if backing::observe(&read, &mut scratch.maps)?
            != (backing::ExecutableIdentity {
                opened: self.opened,
                vma: self.executable,
            })
        {
            return Err(refused(
                "exec source executable object changed during recheck",
            ));
        }
        read.reauthenticate()
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
    let inventory = SourceInventory::new(
        old,
        new,
        &SourceGeometry {
            originals: geometry.originals,
            current: geometry.current,
            island: geometry.island,
            entry: geometry.entry,
            executable: geometry.executable,
        },
    )?;
    let mut total = 0_usize;
    for (index, row) in old.entries().enumerate() {
        let role = inventory.role(row);
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
        output.push(inventory.source(index)?);
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

#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
pub(super) fn backing_cleanup_leaf(owner: &Owner, path: &std::path::Path, until: Instant) {
    backing::cleanup_leaf(owner, path, until);
}
