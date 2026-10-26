//! Native readbacks behind the mapping window's consuming authority.
use super::super::domain::ReplacementIdentity;
use super::*;

/// Created only after the exact original syscall and its neutral return bridge
/// have completed, with a retained complete ENTRY/EXIT and map difference.
pub(in super::super) struct VerifiedMappingExit {
    task: DynamicTask,
    bridge: AdmissionStop,
    state: TaskStateSnapshot,
    logical: Vec<MemoryMapping>,
    raw_logical: Vec<u8>,
    originals: Vec<(u64, Arc<[u8]>)>,
    affected: Range<u64>,
    old_binding: super::super::domain::SourceBinding,
    old_entry_version: u64,
}

impl VerifiedMappingExit {
    pub(in super::super) fn retained_bytes(&self) -> Result<usize, GateError> {
        let mut bytes = size_of::<Self>()
            .checked_add(self.state.xstate.len())
            .and_then(|value| value.checked_add(self.raw_logical.len()))
            .ok_or_else(|| refused("mapping proof size overflows"))?;
        for mapping in &self.logical {
            bytes = bytes
                .checked_add(size_of::<MemoryMapping>())
                .and_then(|value| value.checked_add(mapping.permissions.len()))
                .and_then(|value| {
                    value.checked_add(mapping.pathname.as_ref().map_or(0, String::len))
                })
                .ok_or_else(|| refused("mapping proof size overflows"))?;
        }
        for (_, source) in &self.originals {
            bytes = bytes
                .checked_add(size_of::<(u64, Arc<[u8]>)>() + 2 * size_of::<usize>())
                .and_then(|value| value.checked_add(source.len()))
                .ok_or_else(|| refused("mapping proof size overflows"))?;
        }
        Ok(bytes)
    }
    pub(super) fn from_completed(
        record: &MappingRecord,
        domain: &Domain,
        completed: &native_selected::OriginalCompletion,
    ) -> Result<Self, GateError> {
        let OriginalEvidence::Syscall(kernel) = &completed.evidence else {
            return Err(refused(
                "mapping proof requires actual native syscall evidence",
            ));
        };
        if record.entry.as_ref() != Some(&kernel.entry)
            || record.exit.as_ref() != Some(&kernel.exit)
            || kernel.entry.task != Some(record.original.task)
            || completed.stop.identity != record.original.task
            || completed.state != kernel.exit_state
            || !kernel.newborns.is_empty()
            || !completed.newborns.is_empty()
            || !completed.events.is_empty()
        {
            return Err(refused(
                "mapping proof differs from its exact observed kernel attempt",
            ));
        }
        let (_, failed) = record
            .result
            .ok_or_else(|| refused("mapping result is absent"))?;
        let logical = logical_inventory(record, domain)?;
        let mut originals = Vec::new();
        originals
            .try_reserve(domain.images.len() + 1)
            .map_err(|_| refused("mapping source proof allocation failed"))?;
        for image in &domain.images {
            if logical.contains(&image.mapping) {
                originals.push((image.mapping.start, Arc::from(image.snapshot.bytes())));
            }
        }
        if !failed
            && matches!(
                record.operation,
                MappingOperation::Protect {
                    after: Protection::Executable,
                    ..
                }
            )
        {
            let bytes = read_memory(
                completed.stop.token.tid,
                record.range.start,
                (record.range.end - record.range.start) as usize,
            )?;
            originals.push((record.range.start, Arc::from(bytes)));
        }
        let raw_logical = record.waits[1].capture.view()?.raw().to_vec();
        Ok(Self {
            task: record.original.task,
            bridge: completed.stop.clone(),
            state: completed.state.clone(),
            logical,
            raw_logical,
            originals,
            affected: record.range.clone(),
            old_binding: domain.source_binding,
            old_entry_version: domain.entry_version,
        })
    }

    pub(super) fn captured_source(&self) -> Option<Arc<[u8]>> {
        self.originals
            .iter()
            .find(|(start, _)| *start == self.affected.start)
            .map(|(_, bytes)| Arc::clone(bytes))
    }

    pub(super) fn make_commit(
        &self,
        held: &HeldMmStop<'_>,
        staged: &super::super::domain::StagedReplacement,
        census: &super::super::census::ResumeCensus,
    ) -> Result<ReplacementCommit, GateError> {
        self.authenticate_state(held, true)?;
        self.authenticate_bytes(held)?;
        let identity = staged.identity();
        if identity.old_binding != self.old_binding
            || identity.old_generation != self.task.generation
            || identity.old_entry_version != self.old_entry_version
            || identity.new_generation != held.membership().generation
            || census.generation() != identity.new_generation
            || staged.mappings() != self.logical
            || staged.pages().values().any(|executable| *executable)
        {
            return Err(refused(
                "mapping replacement differs from its native old/new source identities",
            ));
        }
        let mut maps = MapCapture::reserve()?;
        maps.capture(held.selected_token()?.tid)?;
        let original = ParsedMaps::parse(&self.raw_logical, MAP_CAPTURE_ROWS)
            .map_err(|_| refused("retained logical map census is invalid"))?;
        check_permission_projection(maps.view()?, original, &self.logical)?;
        for image in staged.images() {
            if image.snapshot.generation.0 != identity.new_generation
                || image.entries.version() != identity.new_entry_version
                || held.read_memory(image.mapping.start, image.snapshot.bytes().len())?
                    != image.snapshot.bytes()
                || !self.originals.iter().any(|(start, bytes)| {
                    *start == image.mapping.start && bytes.as_ref() == image.snapshot.bytes()
                })
            {
                return Err(refused(
                    "mapping replacement source lacks the actual immutable capture",
                ));
            }
        }
        census
            .validate_projection(
                &staged
                    .images()
                    .iter()
                    .map(|image| image.entries.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(census_error)?;
        Ok(ReplacementCommit { identity })
    }

    pub(in super::super) fn authenticate(
        &self,
        held: &HeldMmStop<'_>,
        opened: &AdmissionStop,
    ) -> Result<(), GateError> {
        let current = held.selected_stop()?;
        if opened.identity != self.task
            || current != self.bridge
            || opened.token.session != current.token.session
            || opened.token.tid != current.token.tid
            || opened.token.sequence >= current.token.sequence
        {
            return Err(refused(
                "mapping EXIT lost its actual opened window and bridge",
            ));
        }
        self.authenticate_state(held, false)?;
        let mut maps = MapCapture::reserve()?;
        maps.capture(current.token.tid)?;
        if maps.view()?.raw() != self.raw_logical {
            return Err(refused(
                "mapping logical EXIT census changed during return bridge",
            ));
        }
        self.authenticate_bytes(held)
    }
    pub(in super::super) fn logical_executables(&self) -> &[MemoryMapping] {
        &self.logical
    }
    pub(in super::super) fn authenticate_closed(
        &self,
        held: &HeldMmStop<'_>,
    ) -> Result<(), GateError> {
        self.authenticate_state(held, false)?;
        let mut maps = MapCapture::reserve()?;
        maps.capture(held.selected_token()?.tid)?;
        let original = ParsedMaps::parse(&self.raw_logical, MAP_CAPTURE_ROWS)
            .map_err(|_| refused("retained logical map census is invalid"))?;
        check_permission_projection(maps.view()?, original, &self.logical)?;
        self.authenticate_bytes(held)
    }
    fn authenticate_state(&self, held: &HeldMmStop<'_>, advanced: bool) -> Result<(), GateError> {
        let current = held.selected_stop()?;
        let mut expected = self.task;
        if advanced {
            expected.generation = expected
                .generation
                .checked_add(1)
                .ok_or_else(|| refused("mapping epoch overflows"))?;
        }
        let members = held.membership();
        if current.identity != expected
            || current.token.session != self.bridge.token.session
            || current.token.tid != self.bridge.token.tid
            || current.token.sequence < self.bridge.token.sequence
            || members.candidate.tasks.as_slice() != [expected.task]
            || members.address_space != expected.address_space
            || members.process != expected.process
            || members.generation != expected.generation
            || TaskStateSnapshot::read(current.token.tid)? != self.state
        {
            return Err(refused("mapping proof lost its exact held singleton state"));
        }
        Ok(())
    }
    fn authenticate_bytes(&self, held: &HeldMmStop<'_>) -> Result<(), GateError> {
        for (start, bytes) in &self.originals {
            if held.read_memory(*start, bytes.len())? != bytes.as_ref() {
                return Err(refused("mapping proof original bytes changed"));
            }
        }
        Ok(())
    }
}

fn logical_inventory(
    record: &MappingRecord,
    domain: &Domain,
) -> Result<Vec<MemoryMapping>, GateError> {
    let (_, failed) = record
        .result
        .ok_or_else(|| refused("mapping result is absent"))?;
    let mut logical = domain.original_executables.clone();
    if !failed {
        logical.retain(|mapping| !overlaps(&(mapping.start..mapping.end), &record.range));
        if record.operation.after() == Some(Protection::Executable) {
            let map = record.waits[1]
                .capture
                .view()?
                .entries()
                .find(|entry| exact_anonymous(*entry, &record.range, Protection::Executable))
                .ok_or_else(|| refused("mapping source has no original RX descriptor"))?;
            logical.push(MemoryMapping {
                start: map.start,
                end: map.end,
                permissions: "r-xp".into(),
                file_offset: map.file_offset,
                pathname: None,
            });
        }
    }
    logical.sort_by_key(|mapping| mapping.start);
    Ok(logical)
}

/// Independent native maker; catalog code can compare but cannot create it.
pub(in super::super) struct ReplacementCommit {
    identity: ReplacementIdentity,
}
impl ReplacementCommit {
    pub(in super::super) fn validate_catalog_transition(
        &self,
        expected: ReplacementIdentity,
    ) -> Result<(), GateError> {
        if self.identity != expected {
            return Err(refused(
                "mapping native catalog transition identity differs",
            ));
        }
        Ok(())
    }
}

/// Compare complete backing/path/offset topology while accounting only for
/// owner-imposed NX. Kernel VMA splitting/coalescing changes row boundaries,
/// so compare each exact interval, never normalized pathname strings/digests.
fn check_permission_projection(
    actual: ParsedMaps<'_>,
    logical: ParsedMaps<'_>,
    executable: &[MemoryMapping],
) -> Result<(), GateError> {
    compare_projection(actual, logical, executable, None)
}

pub(super) fn check_opening_projection(
    record: &MappingRecord,
    domain: &Domain,
) -> Result<(), GateError> {
    compare_projection(
        record.before_window.view()?,
        record.logical_window.view()?,
        &domain.original_executables,
        Some(opening_pages(domain)?),
    )
}

fn opening_pages(domain: &Domain) -> Result<&BTreeSet<u64>, GateError> {
    let retired = domain
        .generations
        .last()
        .ok_or_else(|| refused("mapping opening lacks its retained epoch"))?;
    if retired.generation != domain.generation
        || retired.source_binding != domain.source_binding
        || retired.entry_version != domain.entry_version
    {
        return Err(refused("mapping opening retained epoch differs"));
    }
    Ok(&retired.executable_pages)
}

fn compare_projection(
    actual: ParsedMaps<'_>,
    logical: ParsedMaps<'_>,
    executable: &[MemoryMapping],
    previously_executable: Option<&BTreeSet<u64>>,
) -> Result<(), GateError> {
    let mut previous_end = 0;
    for mapping in executable {
        if mapping.start == 0
            || mapping.start >= mapping.end
            || mapping.start < previous_end
            || mapping.start % PAGE != 0
            || mapping.end % PAGE != 0
            || mapping.permissions != "r-xp"
        {
            return Err(refused(
                "mapping projection inventory is not disjoint logical RX",
            ));
        }
        let mut covered = mapping.start;
        for entry in logical
            .entries()
            .filter(|entry| entry.end > mapping.start && entry.start < mapping.end)
        {
            if entry.start > covered || entry.permissions.bytes() != *b"r-xp" {
                return Err(refused(
                    "mapping projection lacks complete logical RX coverage",
                ));
            }
            covered = entry.end.min(mapping.end);
        }
        if covered != mapping.end {
            return Err(refused("mapping projection logical inventory is absent"));
        }
        previous_end = mapping.end;
    }
    if previously_executable.is_some_and(|pages| {
        pages.iter().any(|page| {
            page % PAGE != 0
                || !executable
                    .iter()
                    .any(|mapping| mapping.start <= *page && *page < mapping.end)
        })
    }) {
        return Err(refused(
            "mapping projection retired page is outside its logical inventory",
        ));
    }
    let mut actual_rows = actual.entries();
    let mut logical_rows = logical.entries();
    let mut a = actual_rows.next();
    let mut b = logical_rows.next();
    let mut cursor = None;
    loop {
        let (Some(left), Some(right)) = (a, b) else {
            if a.is_none() && b.is_none() {
                return Ok(());
            }
            return Err(refused("quarantine changed mapping topology"));
        };
        let start = if let Some(cursor) = cursor {
            cursor
        } else {
            if left.start != right.start {
                return Err(refused("quarantine changed mapping start"));
            }
            left.start
        };
        if left.start > start || right.start > start || left.end <= start || right.end <= start {
            return Err(refused("quarantine introduced a mapping gap"));
        }
        let mut end = left.end.min(right.end);
        for mapping in executable {
            for boundary in [mapping.start, mapping.end] {
                if start < boundary && boundary < end {
                    end = boundary;
                }
            }
        }
        let mut protection = right.permissions.bytes();
        if executable
            .iter()
            .any(|mapping| mapping.start <= start && start < mapping.end)
        {
            let page = start & !(PAGE - 1);
            end = end.min(
                page.checked_add(PAGE)
                    .ok_or_else(|| refused("mapping page end overflows"))?,
            );
            if !previously_executable.is_some_and(|pages| pages.contains(&page)) {
                protection[2] = b'-';
            }
        }
        let offset = |entry: MapEntry<'_>| -> Option<u64> {
            if entry.inode == 0 {
                Some(entry.file_offset)
            } else {
                entry.file_offset.checked_add(start - entry.start)
            }
        };
        if left.permissions.bytes() != protection
            || left.device_major != right.device_major
            || left.device_minor != right.device_minor
            || left.inode != right.inode
            || left.pathname != right.pathname
            || offset(left).is_none()
            || offset(left) != offset(right)
        {
            return Err(refused(
                "quarantine changed a permission, backing or pathname fact",
            ));
        }
        let finished_a = end == left.end;
        let finished_b = end == right.end;
        if finished_a {
            a = actual_rows.next();
        }
        if finished_b {
            b = logical_rows.next();
        }
        cursor = if finished_a && finished_b {
            None
        } else {
            Some(end)
        };
    }
}

#[cfg(test)]
mod tests;
