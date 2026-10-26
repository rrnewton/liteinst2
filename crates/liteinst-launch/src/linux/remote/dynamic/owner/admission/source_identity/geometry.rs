//! Allocation-free complete inventory and file-role proof, independent of
//! how many bytes an authenticated caller captures inside a whole VMA.
use super::*;
#[cfg(test)]
mod tests;

pub(in crate::linux::remote::dynamic::owner::admission) struct SourceGeometry<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) originals: &'a [MemoryMapping],
    pub(in crate::linux::remote::dynamic::owner::admission) current: &'a [MemoryMapping],
    pub(in crate::linux::remote::dynamic::owner::admission) island: &'a Range<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission) entry: &'a EntryEvidence,
    pub(in crate::linux::remote::dynamic::owner::admission) executable: FileIdentity,
}

pub(in crate::linux::remote::dynamic::owner::admission) struct SourceInventory<'a> {
    old: ParsedMaps<'a>,
    new: ParsedMaps<'a>,
    executable: FileIdentity,
    interpreter: Option<FileIdentity>,
}
impl<'a> SourceInventory<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn new(
        old: ParsedMaps<'a>,
        new: ParsedMaps<'a>,
        geometry: &SourceGeometry<'_>,
    ) -> Result<Self, GateError> {
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
        Ok(Self {
            old,
            new,
            executable: geometry.executable,
            interpreter,
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn role(
        &self,
        row: MapEntry<'_>,
    ) -> Option<ImageRole> {
        if file_identity(row) == self.executable {
            Some(ImageRole::Executable)
        } else if Some(file_identity(row)) == self.interpreter {
            Some(ImageRole::Interpreter)
        } else {
            None
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn source(
        &self,
        index: usize,
    ) -> Result<SourceVma, GateError> {
        let row = self
            .old
            .entries()
            .nth(index)
            .ok_or_else(|| refused("exec source map row disappeared"))?;
        let role = self
            .role(row)
            .ok_or_else(|| refused("exec source role is absent"))?;
        if row.permissions.bytes() != *b"r-xp"
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
        for (other_index, other) in self.old.entries().enumerate() {
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
        let (current_index, current) = self
            .new
            .entries()
            .enumerate()
            .find(|(_, m)| m.start == row.start && m.end == row.end)
            .ok_or_else(|| refused("exec source quarantine row is absent"))?;
        Ok(SourceVma {
            original_index: index,
            current_index,
            original_span: line_span(self.old.raw(), row.raw_line),
            current_span: line_span(self.new.raw(), current.raw_line),
            start: row.start,
            end: row.end,
            offset: row.file_offset,
            file: file_identity(row),
            role,
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate(
        original: &'a [u8],
        quarantine: &'a [u8],
        boot: &BootstrapMm,
        entry: &EntryEvidence,
        executable: FileIdentity,
        output: &mut Vec<SourceVma>,
        max_vmas: usize,
    ) -> Result<Self, GateError> {
        if max_vmas == 0
            || max_vmas > MAP_ROWS
            || !output.is_empty()
            || output.capacity() < max_vmas
        {
            return Err(refused("initial source geometry storage differs"));
        }
        let inventory = Self::new(
            parse(original)?,
            parse(quarantine)?,
            &SourceGeometry {
                originals: &boot.original_executables,
                current: &boot.mappings,
                island: &boot.island.range,
                entry,
                executable,
            },
        )?;
        inventory.collect(output, max_vmas)?;
        Ok(inventory)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn collect(
        &self,
        output: &mut Vec<SourceVma>,
        max_vmas: usize,
    ) -> Result<(), GateError> {
        if max_vmas == 0
            || max_vmas > MAP_ROWS
            || !output.is_empty()
            || output.capacity() < max_vmas
        {
            return Err(refused("initial source geometry storage differs"));
        }
        for (index, row) in self.old.entries().enumerate() {
            if row.permissions.bytes()[2] != b'x' || self.role(row).is_none() {
                continue;
            }
            if output.len() == max_vmas {
                return Err(refused("initial source VMA inventory exceeds its bound"));
            }
            output.push(self.source(index)?);
        }
        if output.is_empty() {
            return Err(refused("exec source set is empty"));
        }
        Ok(())
    }
}

pub(in crate::linux::remote::dynamic::owner::admission) struct SourceVmaView<'a> {
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) original: MapEntry<'a>,
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) quarantined: MapEntry<'a>,
    pub(in crate::linux::remote::dynamic::owner::admission) lower_original: Option<MapEntry<'a>>,
    pub(in crate::linux::remote::dynamic::owner::admission) upper_original: Option<MapEntry<'a>>,
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) lower_quarantined: Option<MapEntry<'a>>,
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) upper_quarantined: Option<MapEntry<'a>>,
}
impl SourceVma {
    pub(in crate::linux::remote::dynamic::owner::admission) fn view<'a>(
        &self,
        original: &'a [u8],
        quarantine: &'a [u8],
    ) -> Result<SourceVmaView<'a>, GateError> {
        let old = parse(original)?;
        let new = parse(quarantine)?;
        let a = old
            .entries()
            .nth(self.original_index)
            .ok_or_else(|| refused("exec original source row disappeared"))?;
        let b = new
            .entries()
            .nth(self.current_index)
            .ok_or_else(|| refused("exec current source row disappeared"))?;
        if !row_matches(self, a)
            || !row_matches(self, b)
            || line_span(original, a.raw_line) != self.original_span
            || line_span(quarantine, b.raw_line) != self.current_span
            || !exact_nx(a, b)
        {
            return Err(refused("exec source receipt raw identity differs"));
        }
        let lower = |maps: ParsedMaps<'a>, index: usize| {
            index
                .checked_sub(1)
                .and_then(|i| maps.entries().nth(i))
                .filter(|m| m.end == self.start)
        };
        let upper = |maps: ParsedMaps<'a>, index: usize| {
            maps.entries()
                .nth(index + 1)
                .filter(|m| m.start == self.end)
        };
        Ok(SourceVmaView {
            #[cfg(test)]
            original: a,
            #[cfg(test)]
            quarantined: b,
            lower_original: lower(old, self.original_index),
            upper_original: upper(old, self.original_index),
            #[cfg(test)]
            lower_quarantined: lower(new, self.current_index),
            #[cfg(test)]
            upper_quarantined: upper(new, self.current_index),
        })
    }
}
