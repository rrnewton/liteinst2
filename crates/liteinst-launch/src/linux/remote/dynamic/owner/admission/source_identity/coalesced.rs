//! Initial-runtime descriptions only. Original RX identity is never enlarged
//! to its current NX container. The completed native bootstrap proof is a
//! separate prerequisite at the capture entrypoint.
use super::super::initial_coalescence::{InitialMapPlan, InitialMapProjection, InitialMapView};
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct SourceContainer {
    pub(in crate::linux::remote::dynamic::owner::admission) current_index: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) current_span: (usize, usize),
    pub(in crate::linux::remote::dynamic::owner::admission) start: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) end: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) offset: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) file: FileIdentity,
}
impl SourceContainer {
    pub(in crate::linux::remote::dynamic::owner::admission) fn matches(
        &self,
        row: MapEntry<'_>,
    ) -> bool {
        self.start == row.start
            && self.end == row.end
            && self.offset == row.file_offset
            && self.file == file_identity(row)
            && row.permissions.bytes() == *b"r--p"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct InitialSourceVma {
    original: SourceVma,
    container: SourceContainer,
}
impl InitialSourceVma {
    /// Strict-path description: current and original ranges remain identical.
    pub(in crate::linux::remote::dynamic::owner::admission) fn strict(source: SourceVma) -> Self {
        Self {
            original: source,
            container: SourceContainer {
                current_index: source.current_index,
                current_span: source.current_span,
                start: source.start,
                end: source.end,
                offset: source.offset,
                file: source.file,
            },
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn from_inventory(
        originals: &InitialOriginalInventory<'_>,
        view: &InitialMapView<'_>,
        index: usize,
    ) -> Result<Self, GateError> {
        if originals.originals().raw() != view.originals().raw() {
            return Err(refused("initial coalesced original raw inventory differs"));
        }
        let original = originals.source(index)?;
        let pair = view.source(index)?;
        if original.raw_line != pair.original.raw_line {
            return Err(refused("initial coalesced source inventory differs"));
        }
        let source = SourceVma {
            original_index: pair.original_index,
            current_index: pair.current_index,
            original_span: pair.original_span,
            current_span: pair.current_span,
            start: original.start,
            end: original.end,
            offset: original.file_offset,
            file: file_identity(original),
            role: ImageRole::Executable,
        };
        let container = SourceContainer {
            current_index: pair.current_index,
            current_span: pair.current_span,
            start: pair.current.start,
            end: pair.current.end,
            offset: pair.current.file_offset,
            file: file_identity(pair.current),
        };
        // The complete projection above, not this containing-range check,
        // proves the only permitted separate/union relationship.
        if !container.matches(pair.current)
            || container.start > source.start
            || container.end < source.end
            || container.offset.checked_add(source.start - container.start) != Some(source.offset)
        {
            return Err(refused(
                "initial coalesced RX/container relationship differs",
            ));
        }
        Ok(Self {
            original: source,
            container,
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn source(&self) -> &SourceVma {
        &self.original
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn container(&self) -> SourceContainer {
        self.container
    }
}

/// Pure preflight over the complete original capture. No mapping IDs, source
/// heads, snapshots or native permits are constructed here.
pub(in crate::linux::remote::dynamic::owner::admission) struct InitialOriginalInventory<'a> {
    maps: ParsedMaps<'a>,
    executable: FileIdentity,
}
impl<'a> InitialOriginalInventory<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn new(
        original: &'a [u8],
        entry: &EntryEvidence,
        executable: FileIdentity,
        plan: &InitialMapPlan,
    ) -> Result<Self, GateError> {
        if InitialMapPlan::select(
            original,
            entry,
            (executable.major, executable.minor, executable.inode),
        )? != Some(*plan)
        {
            return Err(refused("initial coalescence original source plan differs"));
        }
        // select requires the finite main-only entry profile and actual main
        // backing identity. Interpreter authority is not inferred from a pair.
        Ok(Self {
            maps: parse(original)?,
            executable,
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn originals(&self) -> ParsedMaps<'a> {
        self.maps
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn eligible(
        &self,
        row: MapEntry<'_>,
    ) -> bool {
        row.permissions.bytes()[2] == b'x' && file_identity(row) == self.executable
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn source(
        &self,
        index: usize,
    ) -> Result<MapEntry<'a>, GateError> {
        let row = self
            .maps
            .entries()
            .nth(index)
            .ok_or_else(|| refused("initial source original row disappeared"))?;
        if !self.eligible(row)
            || row.permissions.bytes() != *b"r-xp"
            || row.file_offset % PAGE != 0
            || row.pathname.is_none_or(|name| name.is_empty())
            || row.start == 0
        {
            return Err(refused(
                "exec whole source VMA exceeds its declared profile",
            ));
        }
        let file_end = row
            .file_offset
            .checked_add(row.end - row.start)
            .ok_or_else(|| refused("exec source backing interval overflows"))?;
        for (other_index, other) in self.maps.entries().enumerate() {
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
        Ok(row)
    }
}

pub(in crate::linux::remote::dynamic::owner::admission) struct InitialSourceValidation<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) boot: &'a BootstrapMm,
    pub(in crate::linux::remote::dynamic::owner::admission) entry: &'a EntryEvidence,
    pub(in crate::linux::remote::dynamic::owner::admission) executable: FileIdentity,
    pub(in crate::linux::remote::dynamic::owner::admission) projection: &'a InitialMapProjection,
}

pub(in crate::linux::remote::dynamic::owner::admission) struct InitialSourceInventory;
impl InitialSourceInventory {
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate(
        original: &[u8],
        current: &[u8],
        geometry: &InitialSourceValidation<'_>,
        rows: &mut Vec<SourceVma>,
        sources: &mut Vec<InitialSourceVma>,
        max_vmas: usize,
    ) -> Result<(), GateError> {
        let InitialSourceValidation {
            boot,
            entry,
            executable,
            projection,
        } = *geometry;
        if projection.cleared_prefix() != projection.plan().executable_count()
            || max_vmas == 0
            || max_vmas > MAP_ROWS
            || !rows.is_empty()
            || !sources.is_empty()
            || rows.capacity() < max_vmas
            || sources.capacity() < max_vmas
        {
            return Err(refused(
                "initial coalesced source storage or completed prefix differs",
            ));
        }
        let originals =
            InitialOriginalInventory::new(original, entry, executable, projection.plan())?;
        let view = projection.view(original, current, &boot.island.range)?;
        if view.current().entries().len() != boot.mappings.len()
            || !view
                .current()
                .entries()
                .zip(&boot.mappings)
                .all(|(row, map)| same_descriptor(row, map))
        {
            return Err(refused(
                "initial coalesced final bootstrap inventory differs",
            ));
        }
        let mut executable_index = 0;
        for row in view.originals().entries() {
            if row.permissions.bytes()[2] == b'x' && !fixed_vsyscall(row) {
                if boot
                    .original_executables
                    .get(executable_index)
                    .is_none_or(|map| !same_descriptor(row, map))
                {
                    return Err(refused(
                        "initial coalesced original executable descriptor differs",
                    ));
                }
                executable_index += 1;
            }
        }
        if executable_index != boot.original_executables.len() {
            return Err(refused(
                "initial coalesced original executable inventory is incomplete",
            ));
        }
        for (index, row) in originals.originals().entries().enumerate() {
            if !originals.eligible(row) {
                continue;
            }
            if rows.len() == max_vmas {
                return Err(refused("initial source VMA inventory exceeds its bound"));
            }
            let source = InitialSourceVma::from_inventory(&originals, &view, index)?;
            rows.push(*source.source());
            sources.push(source);
        }
        if rows.is_empty() {
            return Err(refused("exec source set is empty"));
        }
        Ok(())
    }
}
