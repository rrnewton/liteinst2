//! Descriptive permission projection for one original instruction's fetch
//! pages. This module never mints a held-stop or native execution permission.
use super::super::source_identity::{InitialSourceVma, SourceContainer, SourceVma};
use super::*;
use liteinst_admission::AddressRange;

const PAGE: u64 = 4096;
const MAP_ROWS: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct FetchGeometry {
    source: SourceVma,
    container: Option<SourceContainer>,
    instruction: AddressRange,
    fetch: AddressRange,
}
impl FetchGeometry {
    pub(in crate::linux::remote::dynamic::owner::admission) fn for_instruction(
        source: SourceVma,
        instruction: AddressRange,
    ) -> Result<Self, GateError> {
        let length = instruction.end() - instruction.start();
        let source_range = AddressRange::new(source.start, source.end)
            .ok_or(GateError::Refused("runtime fetch source range differs"))?;
        if source.start % PAGE != 0
            || source.end % PAGE != 0
            || !(1..=15).contains(&length)
            || !source_range.covers(instruction)
        {
            return Err(GateError::Refused(
                "runtime fetch instruction geometry differs",
            ));
        }
        let start = instruction.start() & !(PAGE - 1);
        let last = instruction
            .end()
            .checked_sub(1)
            .ok_or(GateError::Refused("runtime fetch instruction is empty"))?;
        let end = (last & !(PAGE - 1))
            .checked_add(PAGE)
            .ok_or(GateError::Refused("runtime fetch page range overflows"))?;
        let fetch = AddressRange::new(start, end)
            .filter(|fetch| source_range.covers(*fetch) && fetch.end() - fetch.start() <= 2 * PAGE)
            .ok_or(GateError::Refused(
                "runtime fetch pages leave their source VMA",
            ))?;
        Ok(Self {
            source,
            container: None,
            instruction,
            fetch,
        })
    }
    /// The source identity and allowed pages remain the original RX VMA.
    /// Only this distinct initial description can name its authenticated NX
    /// container. A containing row supplied to the strict constructor still fails.
    pub(in crate::linux::remote::dynamic::owner::admission) fn for_initial_source(
        source: InitialSourceVma,
        instruction: AddressRange,
    ) -> Result<Self, GateError> {
        let mut geometry = Self::for_instruction(*source.source(), instruction)?;
        let container = source.container();
        let original = source.source();
        if container.current_index != original.current_index
            || container.current_span != original.current_span
            || container.start > original.start
            || container.end < original.end
            || container.start % PAGE != 0
            || container.end % PAGE != 0
            || container.file != original.file
            || container
                .offset
                .checked_add(original.start - container.start)
                != Some(original.offset)
        {
            return Err(GateError::Refused(
                "runtime original source/container binding differs",
            ));
        }
        geometry.container = Some(container);
        Ok(geometry)
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn source(&self) -> &SourceVma {
        &self.source
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn instruction(&self) -> AddressRange {
        self.instruction
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn pages(&self) -> AddressRange {
        self.fetch
    }

    /// Prove the exact bounded baseline shape before effects. The baseline is
    /// still only supplied evidence here; the current native reader and owner
    /// source/census checks must authenticate it before issuing any permit.
    pub(in crate::linux::remote::dynamic::owner::admission) fn projected_rows(
        &self,
        baseline: &[u8],
    ) -> Result<usize, GateError> {
        let maps = parse(baseline)?;
        let mut rows = 0usize;
        let mut matched = false;
        for (index, row) in maps.entries().enumerate() {
            rows = rows
                .checked_add(1)
                .ok_or(GateError::Refused("runtime map row count overflows"))?;
            if index == self.source.current_index {
                self.require_source(row)?;
                if let Some(container) = self.container {
                    let span = (
                        row.raw_line.as_ptr() as usize - baseline.as_ptr() as usize,
                        row.raw_line.len(),
                    );
                    if span != container.current_span {
                        return Err(GateError::Refused(
                            "runtime fetch container raw span differs",
                        ));
                    }
                }
                matched = true;
                rows = rows
                    .checked_add(usize::from(self.fetch.start() > row.start))
                    .and_then(|rows| rows.checked_add(usize::from(self.fetch.end() < row.end)))
                    .ok_or(GateError::Refused("runtime map row count overflows"))?;
            }
        }
        if !matched || rows > MAP_ROWS {
            return Err(GateError::Refused(
                "runtime temporary map projection exceeds its bound",
            ));
        }
        Ok(rows)
    }

    /// Match every observed row. Only the bound current source container may
    /// split, at original fetch-page boundaries; source identity stays original.
    pub(in crate::linux::remote::dynamic::owner::admission) fn verify_open(
        &self,
        baseline: &[u8],
        observed: &[u8],
    ) -> Result<(), GateError> {
        let expected_rows = self.projected_rows(baseline)?;
        let baseline = parse(baseline)?;
        let observed = parse(observed)?;
        let mut actual = observed.entries();
        let mut count = 0usize;
        for (index, original) in baseline.entries().enumerate() {
            if index != self.source.current_index {
                let row = actual.next().ok_or(GateError::Refused(
                    "runtime temporary maps omit a baseline row",
                ))?;
                if row.raw_line != original.raw_line {
                    return Err(GateError::Refused(
                        "runtime temporary maps changed an unrelated row",
                    ));
                }
                count += 1;
                continue;
            }
            self.require_source(original)?;
            let mut start = original.start;
            while start < original.end {
                let executable = self.fetch.contains(start);
                let end = if start < self.fetch.start() {
                    self.fetch.start()
                } else if executable {
                    self.fetch.end()
                } else {
                    original.end
                };
                let row = actual.next().ok_or(GateError::Refused(
                    "runtime temporary maps omit a source piece",
                ))?;
                let offset = original
                    .file_offset
                    .checked_add(start - original.start)
                    .ok_or(GateError::Refused(
                        "runtime source projection offset overflows",
                    ))?;
                let permissions = if executable { *b"r-xp" } else { *b"r--p" };
                if row.start != start
                    || row.end != end
                    || row.file_offset != offset
                    || row.permissions.bytes() != permissions
                    || row.device_major != original.device_major
                    || row.device_minor != original.device_minor
                    || row.inode != original.inode
                    || row.pathname != original.pathname
                    || row.pathname_column != original.pathname_column
                {
                    return Err(GateError::Refused(
                        "runtime temporary source projection differs",
                    ));
                }
                count += 1;
                start = end;
            }
        }
        if actual.next().is_some() || count != expected_rows {
            return Err(GateError::Refused(
                "runtime temporary maps contain extra rows",
            ));
        }
        Ok(())
    }

    fn require_source(&self, row: MapEntry<'_>) -> Result<(), GateError> {
        if let Some(container) = self.container {
            return if container.matches(row) {
                Ok(())
            } else {
                Err(GateError::Refused(
                    "runtime fetch container identity differs",
                ))
            };
        }
        if row.start != self.source.start
            || row.end != self.source.end
            || row.file_offset != self.source.offset
            || row.permissions.bytes() != *b"r--p"
            || row.device_major != self.source.file.major
            || row.device_minor != self.source.file.minor
            || row.inode != self.source.file.inode
        {
            return Err(GateError::Refused("runtime fetch source identity differs"));
        }
        Ok(())
    }
}

fn parse(bytes: &[u8]) -> Result<ParsedMaps<'_>, GateError> {
    if bytes.len() > 64 * 1024 {
        return Err(GateError::Refused("runtime map capture exceeds its bound"));
    }
    ParsedMaps::parse(bytes, MAP_ROWS)
        .map_err(|_| GateError::Refused("runtime map capture is malformed"))
}

pub(in crate::linux::remote::dynamic::owner::admission) fn verify_closed(
    baseline: &[u8],
    observed: &[u8],
) -> Result<(), GateError> {
    parse(baseline)?;
    parse(observed)?;
    if baseline != observed {
        return Err(GateError::Refused(
            "runtime NX restoration changed the complete map inventory",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
