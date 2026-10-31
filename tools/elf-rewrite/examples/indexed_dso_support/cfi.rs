//! Bounded original-CFI interpretation for this compiled SysV fixture only.
//!
//! The supplied metadata is an immutable source byte view, not a certificate:
//! its unique ELF ownership, source identity and lifetime remain caller-owned.
//! Exact byte/coordinate joins and complete CFI interpretation do not prove
//! that machine instructions implement these rules, or admit native unwinding.
//! Unselected original records (including the PLT's CFA expression) remain
//! opaque in OriginalIndex; this helper refuses unsupported selected programs.
#![forbid(unsafe_code)]

use li2core::generated_unwind::artifact::OriginalArtifactCfi;
use std::ops::Range;

pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_ROWS: usize = 256;
pub const MAX_STATE_STACK: usize = 16;
pub const MAX_METADATA_BYTES: usize = 1024 * 1024;
/// DWARF columns in each public row: RBX, RBP, R12, R13, R14, R15, RA.
pub const COLUMNS: [usize; 7] = [3, 6, 12, 13, 14, 15, 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Owner,
    Envelope,
    Function,
    Program,
    Unsupported,
    Arithmetic,
    State,
    Point,
}
type Result<T> = std::result::Result<T, Error>;

/// Callers may tighten these ceilings, never enlarge the fixture profile.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub record_bytes: usize,
    pub rows: usize,
    pub state_stack: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            record_bytes: MAX_RECORD_BYTES,
            rows: MAX_ROWS,
            state_stack: MAX_STATE_STACK,
        }
    }
}

/// Complete original metadata bytes in the same module-coordinate domain as
/// the records. Ordinarily this is the authenticated original .eh_frame view.
#[derive(Clone, Copy)]
pub struct Metadata<'a> {
    pub address: u64,
    pub bytes: &'a [u8],
}
impl Metadata<'_> {
    fn contains_exact(&self, address: u64, bytes: &[u8]) -> Result<()> {
        let start = address.checked_sub(self.address).ok_or(Error::Owner)?;
        let start = usize::try_from(start).map_err(|_| Error::Owner)?;
        let end = start.checked_add(bytes.len()).ok_or(Error::Arithmetic)?;
        if self.bytes.get(start..end) != Some(bytes) {
            return Err(Error::Owner);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rule {
    /// No rule has been specified. Consumer defaults require separate proof.
    Unspecified,
    Undefined,
    Same,
    /// Address of the saved value relative to the CFA, never a value offset.
    Offset(i64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cfa {
    pub register: u8,
    pub offset: i64,
}

/// A half-open location interval with owned recovery rules. Undefined columns
/// are retained as Undefined; interpreting them as Same is never permitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub start: u64,
    pub end: u64,
    pub cfa: Cfa,
    pub columns: [Rule; 7],
}

#[derive(Clone, Debug)]
pub struct Table {
    function: Range<u64>,
    rows: Vec<Row>,
    cie_baseline: [Rule; 17],
    restored_columns: [bool; 17],
}
impl Table {
    pub fn function(&self) -> Range<u64> {
        self.function.clone()
    }
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }
    /// Completed CIE rules, retained independently of later FDE rows. A GNU
    /// consumer that treats DW_CFA_restore as UNSAVED cannot implement an
    /// arbitrary nondefault CIE baseline; consumer policy must check this.
    pub const fn cie_baseline(&self) -> [Rule; 17] {
        self.cie_baseline
    }
    /// Every column named by either restore encoding, including the full tail.
    /// Remember/restore_state does not erase this program-wide usage record.
    pub const fn restored_columns(&self) -> [bool; 17] {
        self.restored_columns
    }
    /// This is an exact location query, without an implicit return-PC minus
    /// one convention. The caller supplies the independently chosen location.
    pub fn row_at(&self, point: u64) -> Result<Row> {
        self.rows
            .iter()
            .find(|row| row.start <= point && point < row.end)
            .copied()
            .ok_or(Error::Point)
    }
}

#[derive(Clone, Copy)]
struct State {
    cfa: Option<Cfa>,
    registers: [Rule; 17],
}
impl State {
    const EMPTY: Self = Self {
        cfa: None,
        registers: [Rule::Unspecified; 17],
    };
    fn row(self, start: u64, end: u64) -> Result<Row> {
        Ok(Row {
            start,
            end,
            cfa: self.cfa.ok_or(Error::State)?,
            columns: COLUMNS.map(|column| self.registers[column]),
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(count).ok_or(Error::Arithmetic)?;
        let bytes = self.bytes.get(self.at..end).ok_or(Error::Envelope)?;
        self.at = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn unsigned(&mut self) -> Result<u64> {
        let value = self.leb(false)?;
        u64::try_from(value).map_err(|_| Error::Arithmetic)
    }
    fn signed(&mut self) -> Result<i64> {
        i64::try_from(self.leb(true)?).map_err(|_| Error::Arithmetic)
    }
    // Decode in a wider integer, then require a minimal, representable 64-bit
    // operand. A terminated overlong operand is not silently normalized.
    fn leb(&mut self, signed: bool) -> Result<i128> {
        let mut value = 0_i128;
        for index in 0..10 {
            let byte = self.byte()?;
            value |= i128::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                if signed && byte & 0x40 != 0 {
                    value -= 1_i128 << (7 * (index + 1));
                }
                let mut rest = value;
                let mut length = 0;
                loop {
                    let low = rest & 0x7f;
                    rest >>= 7;
                    length += 1;
                    if (!signed && rest == 0)
                        || (signed
                            && ((rest == 0 && low & 0x40 == 0) || (rest == -1 && low & 0x40 != 0)))
                    {
                        break;
                    }
                }
                return if length == index + 1 {
                    Ok(value)
                } else {
                    Err(Error::Program)
                };
            }
        }
        Err(Error::Program)
    }
    fn column(&mut self) -> Result<usize> {
        let column = usize::try_from(self.unsigned()?).map_err(|_| Error::Arithmetic)?;
        if column >= 17 {
            return Err(Error::Unsupported);
        }
        Ok(column)
    }
    fn cfa_register(&mut self) -> Result<u8> {
        let register = self.unsigned()?;
        if register >= 16 {
            return Err(Error::Unsupported);
        }
        Ok(register as u8)
    }
}

fn factored(value: i128) -> Result<i64> {
    i64::try_from(value.checked_mul(-8).ok_or(Error::Arithmetic)?).map_err(|_| Error::Arithmetic)
}

fn append(rows: &mut Vec<Row>, state: State, start: u64, end: u64, limit: usize) -> Result<()> {
    if rows.len() >= limit {
        return Err(Error::Limit);
    }
    rows.push(state.row(start, end)?);
    Ok(())
}

/// `None` interprets the CIE baseline: no location or state-stack operations.
/// FDE restoration always reads that completed immutable CIE baseline; saved
/// states contain every rule and the CFA, but never restore the location.
fn program(
    bytes: &[u8],
    baseline: State,
    function: Option<&Range<u64>>,
    limits: Limits,
) -> Result<(State, Vec<Row>, [bool; 17])> {
    let mut reader = Reader::new(bytes);
    let mut state = baseline;
    let mut restored_columns = [false; 17];
    let mut saved = Vec::new();
    let mut rows = Vec::new();
    let mut pc = function.map_or(0, |range| range.start);
    while reader.at < bytes.len() {
        let opcode = reader.byte()?;
        let advance = if opcode & 0xc0 == 0x40 {
            Some(u64::from(opcode & 0x3f))
        } else if (2..=4).contains(&opcode) {
            let width = 1_usize << (opcode - 2);
            let mut raw = [0; 8];
            raw[..width].copy_from_slice(reader.take(width)?);
            Some(u64::from_le_bytes(raw))
        } else {
            None
        };
        if let Some(amount) = advance {
            let range = function.ok_or(Error::Program)?;
            let next = pc.checked_add(amount).ok_or(Error::Arithmetic)?;
            if amount == 0 || next > range.end {
                return Err(Error::Program);
            }
            append(&mut rows, state, pc, next, limits.rows)?;
            pc = next;
            continue;
        }
        if opcode & 0xc0 == 0x80 {
            let column = usize::from(opcode & 0x3f);
            if column >= 17 {
                return Err(Error::Unsupported);
            }
            state.registers[column] = Rule::Offset(factored(i128::from(reader.unsigned()?))?);
            continue;
        }
        if opcode & 0xc0 == 0xc0 {
            let column = usize::from(opcode & 0x3f);
            if column >= 17 {
                return Err(Error::Unsupported);
            }
            if function.is_none() {
                return Err(Error::Program);
            }
            restored_columns[column] = true;
            state.registers[column] = baseline.registers[column];
            continue;
        }
        match opcode {
            0 => {}
            5 | 0x11 => {
                let column = reader.column()?;
                let factor = if opcode == 5 {
                    i128::from(reader.unsigned()?)
                } else {
                    i128::from(reader.signed()?)
                };
                state.registers[column] = Rule::Offset(factored(factor)?);
            }
            6 => {
                let column = reader.column()?;
                if function.is_none() {
                    return Err(Error::Program);
                }
                restored_columns[column] = true;
                state.registers[column] = baseline.registers[column];
            }
            7 | 8 => {
                let column = reader.column()?;
                state.registers[column] = if opcode == 7 {
                    Rule::Undefined
                } else {
                    Rule::Same
                };
            }
            0x0a => {
                if function.is_none() {
                    return Err(Error::Program);
                }
                if saved.len() >= limits.state_stack {
                    return Err(Error::Limit);
                }
                saved.push(state);
            }
            0x0b => {
                if function.is_none() {
                    return Err(Error::Program);
                }
                state = saved.pop().ok_or(Error::State)?;
            }
            0x0c | 0x12 => {
                let register = reader.cfa_register()?;
                let offset = if opcode == 0x0c {
                    i64::try_from(reader.unsigned()?).map_err(|_| Error::Arithmetic)?
                } else {
                    factored(i128::from(reader.signed()?))?
                };
                state.cfa = Some(Cfa { register, offset });
            }
            0x0d => {
                let register = reader.cfa_register()?;
                state.cfa = Some(Cfa {
                    register,
                    ..state.cfa.ok_or(Error::State)?
                });
            }
            0x0e | 0x13 => {
                let offset = if opcode == 0x0e {
                    i64::try_from(reader.unsigned()?).map_err(|_| Error::Arithmetic)?
                } else {
                    factored(i128::from(reader.signed()?))?
                };
                state.cfa = Some(Cfa {
                    offset,
                    ..state.cfa.ok_or(Error::State)?
                });
            }
            // set_loc, register rules, expression/value rules, GNU extensions
            // and unknown opcodes are outside this fixture-specific profile.
            _ => return Err(Error::Unsupported),
        }
    }
    if !saved.is_empty() {
        return Err(Error::State);
    }
    if let Some(range) = function {
        if pc < range.end {
            append(&mut rows, state, pc, range.end, limits.rows)?;
        }
    } else if state.cfa.is_none() {
        return Err(Error::State);
    }
    Ok((state, rows, restored_columns))
}

/// Authenticate both complete raw records and interpret their complete programs
/// before returning any row. The exact expected function must equal the FDE's
/// decoded half-open extent; lookup does not establish instruction boundaries.
/// Location advances at function end are accepted, but all following operands,
/// state operations and opcodes still have to pass. No bad tail is ignored.
pub fn parse(
    record: &OriginalArtifactCfi,
    owner: Metadata<'_>,
    function: Range<u64>,
    limits: Limits,
) -> Result<Table> {
    if limits.record_bytes == 0
        || limits.record_bytes > MAX_RECORD_BYTES
        || limits.rows == 0
        || limits.rows > MAX_ROWS
        || limits.state_stack > MAX_STATE_STACK
        || record.cie.len() > limits.record_bytes
        || record.fde.len() > limits.record_bytes
        || owner.bytes.len() > MAX_METADATA_BYTES
    {
        return Err(Error::Limit);
    }
    owner
        .address
        .checked_add(u64::try_from(owner.bytes.len()).map_err(|_| Error::Arithmetic)?)
        .ok_or(Error::Arithmetic)?;
    owner.contains_exact(record.cie_address, &record.cie)?;
    owner.contains_exact(record.fde_address, &record.fde)?;
    let cie_end = record
        .cie_address
        .checked_add(u64::try_from(record.cie.len()).map_err(|_| Error::Arithmetic)?)
        .ok_or(Error::Arithmetic)?;
    if cie_end > record.fde_address || function.start >= function.end {
        return Err(Error::Function);
    }
    let mut cie = Reader::new(&record.cie);
    if u64::from(cie.word()?) + 4 != record.cie.len() as u64
        || cie.word()? != 0
        || cie.take(9)? != [1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b]
    {
        return Err(Error::Envelope);
    }
    let (baseline, _, _) = program(&record.cie[cie.at..], State::EMPTY, None, limits)?;
    let mut fde = Reader::new(&record.fde);
    if u64::from(fde.word()?) + 4 != record.fde.len() as u64 {
        return Err(Error::Envelope);
    }
    let delta = u64::from(fde.word()?);
    if record
        .fde_address
        .checked_add(4)
        .and_then(|p| p.checked_sub(delta))
        != Some(record.cie_address)
    {
        return Err(Error::Envelope);
    }
    let start_delta = i64::from(fde.word()? as i32);
    let start = record
        .fde_address
        .checked_add(8)
        .and_then(|p| p.checked_add_signed(start_delta))
        .ok_or(Error::Envelope)?;
    let size = u64::try_from(fde.word()? as i32).map_err(|_| Error::Function)?;
    if start != function.start || start.checked_add(size) != Some(function.end) {
        return Err(Error::Function);
    }
    // Canonical zero-length FDE augmentation for the exact zR profile.
    if fde.byte()? != 0 {
        return Err(Error::Envelope);
    }
    let (_, rows, restored_columns) =
        program(&record.fde[fde.at..], baseline, Some(&function), limits)?;
    Ok(Table {
        function,
        rows,
        cie_baseline: baseline.registers,
        restored_columns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1000;
    const METADATA: u64 = 0x2000;
    const CIE_PROGRAM: &[u8] = &[0x0c, 7, 8, 0x90, 1];

    fn record(
        cie_program: &[u8],
        fde_program: &[u8],
        start: u64,
        size: u32,
    ) -> OriginalArtifactCfi {
        let mut cie = vec![0; 8];
        cie.extend_from_slice(&[1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b]);
        cie.extend_from_slice(cie_program);
        let length = u32::try_from(cie.len() - 4).unwrap();
        cie[..4].copy_from_slice(&length.to_le_bytes());
        let fde_address = METADATA + u64::try_from(cie.len()).unwrap();
        let mut fde = vec![0; 4];
        fde.extend_from_slice(
            &u32::try_from(fde_address + 4 - METADATA)
                .unwrap()
                .to_le_bytes(),
        );
        let displacement = i32::try_from(i128::from(start) - i128::from(fde_address + 8)).unwrap();
        fde.extend_from_slice(&displacement.to_le_bytes());
        fde.extend_from_slice(&size.to_le_bytes());
        fde.push(0);
        fde.extend_from_slice(fde_program);
        let length = u32::try_from(fde.len() - 4).unwrap();
        fde[..4].copy_from_slice(&length.to_le_bytes());
        OriginalArtifactCfi {
            cie_address: METADATA,
            cie,
            fde_address,
            fde,
        }
    }
    fn read(record: &OriginalArtifactCfi, function: Range<u64>, limits: Limits) -> Result<Table> {
        let bytes: Vec<_> = record.cie.iter().chain(&record.fde).copied().collect();
        parse(
            record,
            Metadata {
                address: METADATA,
                bytes: &bytes,
            },
            function,
            limits,
        )
    }
    fn ordinary(program: &[u8]) -> Result<Table> {
        read(
            &record(CIE_PROGRAM, program, BASE, 64),
            BASE..BASE + 64,
            Limits::default(),
        )
    }

    #[test]
    fn gnu_caller_rows_preserve_complete_prologue_epilogue_and_return_locations() {
        // Literal GNU work/reference FDE programs from the retained fixed C
        // build. Assertions are independent numeric ABI rows, not a parser
        // round trip. The owner envelope is constructed separately above.
        for (start, size, allocation, advance, tail, point, cfa) in [
            (0x13d0, 866, 0xd0, 0x61, 0x44, 0x1689, 336),
            (0x1740, 855, 0xc0, 0x57, 0x46, 0x19da, 320),
        ] {
            let program = [
                0x42, 0x0e, 0x10, 0x8f, 2, 0x42, 0x0e, 0x18, 0x8e, 3, 0x42, 0x0e, 0x20, 0x8d, 4,
                0x42, 0x0e, 0x28, 0x8c, 5, 0x41, 0x0e, 0x30, 0x86, 6, 0x41, 0x0e, 0x38, 0x83, 7,
                0x47, 0x0e, allocation, 2, 2, advance, 0x0a, 0x0e, 0x38, 0x41, 0x0e, 0x30, 0x41,
                0x0e, 0x28, 0x42, 0x0e, 0x20, 0x42, 0x0e, 0x18, 0x42, 0x0e, 0x10, 0x42, 0x0e, 8,
                tail, 0x0b,
            ];
            let table = read(
                &record(CIE_PROGRAM, &program, start, size),
                start..start + u64::from(size),
                Limits::default(),
            )
            .unwrap();
            assert_eq!(table.function(), start..start + u64::from(size));
            assert_eq!(
                table.rows().first().unwrap().cfa,
                Cfa {
                    register: 7,
                    offset: 8
                }
            );
            assert_eq!(table.rows().last().unwrap().end, start + u64::from(size));
            assert!(
                table
                    .rows()
                    .windows(2)
                    .all(|pair| pair[0].end == pair[1].start)
            );
            let row = table.row_at(point).unwrap();
            assert_eq!(
                row.cfa,
                Cfa {
                    register: 7,
                    offset: cfa
                }
            );
            assert_eq!(
                row.columns,
                [-56, -48, -40, -32, -24, -16, -8].map(Rule::Offset)
            );
            assert!(
                table
                    .rows()
                    .iter()
                    .any(|row| row.cfa.offset == 8 && row.start > start)
            );
        }
    }

    #[test]
    fn restore_uses_completed_cie_baseline_and_saved_state_includes_cfa() {
        let cie = [0x0c, 7, 8, 0x90, 1, 8, 3, 0x86, 2];
        let fde = [
            0x83, 4, 8, 6, 0x0e, 32, 0x41, 0x0a, 0x0d, 6, 0x0e, 16, 0xc3, 6, 6, 0x41, 0x0b, 0x41,
        ];
        let table = read(
            &record(&cie, &fde, BASE, 64),
            BASE..BASE + 64,
            Limits::default(),
        )
        .unwrap();
        let first = table.row_at(BASE).unwrap();
        assert_eq!(first.columns[0], Rule::Offset(-32));
        assert_eq!(first.columns[1], Rule::Same);
        let restored = table.row_at(BASE + 1).unwrap();
        assert_eq!(restored.columns[0], Rule::Same);
        assert_eq!(restored.columns[1], Rule::Offset(-16));
        assert_eq!(
            restored.cfa,
            Cfa {
                register: 6,
                offset: 16
            }
        );
        let saved = table.row_at(BASE + 2).unwrap();
        assert_eq!(saved.columns, first.columns);
        assert_eq!(saved.cfa, first.cfa);
        assert_eq!(saved.start, BASE + 2);
    }

    #[test]
    fn undefined_same_and_offsets_are_distinct_without_implicit_defaults() {
        let table = ordinary(&[0x41, 8, 3, 0x41, 7, 3, 0x41, 0x83, 2, 0x41, 0xc3]).unwrap();
        assert_eq!(table.row_at(BASE).unwrap().columns[0], Rule::Unspecified);
        assert_eq!(table.row_at(BASE + 1).unwrap().columns[0], Rule::Same);
        assert_eq!(table.row_at(BASE + 2).unwrap().columns[0], Rule::Undefined);
        assert_eq!(
            table.row_at(BASE + 3).unwrap().columns[0],
            Rule::Offset(-16)
        );
        assert_eq!(
            table.row_at(BASE + 4).unwrap().columns[0],
            Rule::Unspecified
        );
        assert_eq!(
            ordinary(&[7, 16]).unwrap().row_at(BASE).unwrap().columns[6],
            Rule::Undefined
        );
        assert_eq!(
            ordinary(&[8, 16]).unwrap().row_at(BASE).unwrap().columns[6],
            Rule::Same
        );
    }

    #[test]
    fn unspecified_is_distinct_from_explicit_same_and_undefined_in_cie_and_fde() {
        let table = ordinary(&[0x41, 8, 3, 0x41, 7, 3, 0x41, 0xc3]).unwrap();
        assert_eq!(table.cie_baseline()[3], Rule::Unspecified);
        assert_eq!(table.cie_baseline()[16], Rule::Offset(-8));
        assert_eq!(table.row_at(BASE).unwrap().columns[0], Rule::Unspecified);
        assert_eq!(table.row_at(BASE + 1).unwrap().columns[0], Rule::Same);
        assert_eq!(table.row_at(BASE + 2).unwrap().columns[0], Rule::Undefined);
        assert_eq!(
            table.row_at(BASE + 3).unwrap().columns[0],
            Rule::Unspecified
        );
        for (opcode, expected) in [(7, Rule::Undefined), (8, Rule::Same)] {
            let mut cie = CIE_PROGRAM.to_vec();
            cie.extend_from_slice(&[opcode, 3]);
            let table = read(
                &record(&cie, &[0x83, 3, 0x41, 0xc3], BASE, 64),
                BASE..BASE + 64,
                Limits::default(),
            )
            .unwrap();
            assert_eq!(table.cie_baseline()[3], expected);
            assert_eq!(table.row_at(BASE + 1).unwrap().columns[0], expected);
        }
    }

    #[test]
    fn restore_usage_retains_nondefault_baseline_and_invisible_tail_operations() {
        let mut cie = CIE_PROGRAM.to_vec();
        cie.extend_from_slice(&[0x83, 2]);
        let table = read(
            &record(
                &cie,
                &[8, 3, 0x41, 0xc3, 0x0a, 6, 6, 0x0b, 2, 63, 6, 16],
                BASE,
                64,
            ),
            BASE..BASE + 64,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(table.cie_baseline()[3], Rule::Offset(-16));
        assert_eq!(
            table.row_at(BASE + 1).unwrap().columns[0],
            Rule::Offset(-16)
        );
        let mask = table.restored_columns();
        assert_eq!(mask.iter().filter(|&&used| used).count(), 3);
        assert!(mask[3] && mask[6] && mask[16]);
        assert_eq!(table.cie_baseline()[16], Rule::Offset(-8));
        // This interpreter preserves CIE restoration. GNU's UNSAVED restore
        // differs here, so a consumer must refuse these nondefault restores.
        assert!(
            ordinary(&[])
                .unwrap()
                .restored_columns()
                .iter()
                .all(|&x| !x)
        );
    }

    #[test]
    fn complete_program_tail_and_unsupported_rules_refuse_before_any_lookup() {
        for bad in [1, 9, 0x0f, 0x10, 0x14, 0x15, 0x16, 0x2e, 0x3f] {
            assert_eq!(ordinary(&[0x41, bad]).err(), Some(Error::Unsupported));
            assert_eq!(ordinary(&[2, 64, bad]).err(), Some(Error::Unsupported));
            let mut cie = CIE_PROGRAM.to_vec();
            cie.push(bad);
            assert_eq!(
                read(
                    &record(&cie, &[], BASE, 64),
                    BASE..BASE + 64,
                    Limits::default()
                )
                .err(),
                Some(Error::Unsupported)
            );
        }
        assert_eq!(ordinary(&[2, 64, 0x0b]).err(), Some(Error::State));
        assert_eq!(ordinary(&[2, 64, 0x83]).err(), Some(Error::Envelope));
        assert_eq!(ordinary(&[0x91, 1]).err(), Some(Error::Unsupported));
        assert_eq!(ordinary(&[0xd1]).err(), Some(Error::Unsupported));
        assert_eq!(ordinary(&[0x0c, 16, 8]).err(), Some(Error::Unsupported));
        assert_eq!(ordinary(&[5, 17, 1]).err(), Some(Error::Unsupported));
        assert!(ordinary(&[2, 64, 0, 0]).is_ok());
    }

    #[test]
    fn exact_owner_record_coordinates_function_and_lookup_extents_are_required() {
        let original = record(CIE_PROGRAM, &[], BASE, 64);
        let bytes: Vec<_> = original.cie.iter().chain(&original.fde).copied().collect();
        let owner = Metadata {
            address: METADATA,
            bytes: &bytes,
        };
        let table = parse(&original, owner, BASE..BASE + 64, Limits::default()).unwrap();
        assert_eq!(table.row_at(BASE - 1), Err(Error::Point));
        assert_eq!(table.row_at(BASE + 64), Err(Error::Point));
        assert!(table.row_at(BASE + 63).is_ok());
        for function in [BASE + 1..BASE + 64, BASE..BASE + 65, BASE..BASE] {
            assert_eq!(
                parse(&original, owner, function, Limits::default()).err(),
                Some(Error::Function)
            );
        }
        for cie in [true, false] {
            let mut changed = original.clone();
            if cie {
                changed.cie[8] ^= 1;
            } else {
                changed.fde[8] ^= 1;
            }
            assert_eq!(
                parse(&changed, owner, BASE..BASE + 64, Limits::default()).err(),
                Some(Error::Owner)
            );
            let mut changed = original.clone();
            if cie {
                changed.cie_address += 1;
            } else {
                changed.fde_address += 1;
            }
            assert_eq!(
                parse(&changed, owner, BASE..BASE + 64, Limits::default()).err(),
                Some(Error::Owner)
            );
        }
        assert_eq!(
            parse(
                &original,
                Metadata {
                    address: METADATA,
                    bytes: &bytes[..bytes.len() - 1]
                },
                BASE..BASE + 64,
                Limits::default()
            )
            .err(),
            Some(Error::Owner)
        );
    }

    #[test]
    fn canonical_envelopes_and_finite_minimal_operands_are_required() {
        let original = record(CIE_PROGRAM, &[], BASE, 64);
        for at in [0, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
            let mut changed = original.clone();
            changed.cie[at] ^= 1;
            assert_eq!(
                read(&changed, BASE..BASE + 64, Limits::default()).err(),
                Some(Error::Envelope)
            );
        }
        for at in [0, 4, 16] {
            let mut changed = original.clone();
            changed.fde[at] ^= 1;
            assert_eq!(
                read(&changed, BASE..BASE + 64, Limits::default()).err(),
                Some(Error::Envelope)
            );
        }
        for size in [0, u32::MAX, 65] {
            let changed = record(CIE_PROGRAM, &[], BASE, size);
            assert_eq!(
                read(&changed, BASE..BASE + 64, Limits::default()).err(),
                Some(Error::Function)
            );
        }
        assert_eq!(ordinary(&[0x83, 0x81, 0]).err(), Some(Error::Program));
        assert_eq!(ordinary(&[0x11, 3, 0xff, 0x7f]).err(), Some(Error::Program));
        assert_eq!(ordinary(&[0x83, 0x80]).err(), Some(Error::Envelope));
        let mut endless = vec![0x83];
        endless.extend_from_slice(&[0x80; 10]);
        assert_eq!(ordinary(&endless).err(), Some(Error::Program));
    }

    #[test]
    fn remembered_states_have_strict_depth_balance_and_no_location_rewind() {
        assert_eq!(ordinary(&[0x0b]).err(), Some(Error::State));
        assert_eq!(ordinary(&[0x0a]).err(), Some(Error::State));
        let mut maximum = vec![0x0a; MAX_STATE_STACK];
        maximum.extend_from_slice(&[0x0b; MAX_STATE_STACK]);
        assert!(ordinary(&maximum).is_ok());
        let mut too_many = vec![0x0a; MAX_STATE_STACK + 1];
        too_many.extend_from_slice(&[0x0b; MAX_STATE_STACK + 1]);
        assert_eq!(ordinary(&too_many).err(), Some(Error::Limit));
        let table = ordinary(&[0x0a, 0x41, 0x0b]).unwrap();
        assert_eq!(table.rows().len(), 2);
        assert_eq!(table.rows()[1].start, BASE + 1);
        let mut cie = CIE_PROGRAM.to_vec();
        cie.push(0x0a);
        assert_eq!(
            read(
                &record(&cie, &[], BASE, 64),
                BASE..BASE + 64,
                Limits::default()
            )
            .err(),
            Some(Error::Program)
        );
    }

    #[test]
    fn signed_extended_offsets_and_cfa_variants_preserve_checked_meaning() {
        let table = ordinary(&[
            5, 3, 2, 0x11, 6, 0x7e, 0x12, 6, 0x7e, 0x41, 0x13, 2, 0x41, 0x0d, 7,
        ])
        .unwrap();
        let first = table.row_at(BASE).unwrap();
        assert_eq!(first.columns[0], Rule::Offset(-16));
        assert_eq!(first.columns[1], Rule::Offset(16));
        assert_eq!(
            first.cfa,
            Cfa {
                register: 6,
                offset: 16
            }
        );
        assert_eq!(
            table.row_at(BASE + 1).unwrap().cfa,
            Cfa {
                register: 6,
                offset: -16
            }
        );
        assert_eq!(
            table.row_at(BASE + 2).unwrap().cfa,
            Cfa {
                register: 7,
                offset: -16
            }
        );
        let overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1];
        for prefix in [&[0x83][..], &[0x0e][..], &[0x11, 3][..], &[0x12, 7][..]] {
            let mut program = prefix.to_vec();
            program.extend_from_slice(&overflow);
            assert_eq!(ordinary(&program).err(), Some(Error::Arithmetic));
        }
        assert_eq!(
            read(
                &record(&[0x0d, 7], &[], BASE, 64),
                BASE..BASE + 64,
                Limits::default()
            )
            .err(),
            Some(Error::State)
        );
    }

    #[test]
    fn record_row_state_and_address_limits_cannot_be_relaxed_by_the_caller() {
        let original = record(CIE_PROGRAM, &[0x41], BASE, 64);
        for limits in [
            Limits {
                record_bytes: MAX_RECORD_BYTES + 1,
                ..Limits::default()
            },
            Limits {
                rows: MAX_ROWS + 1,
                ..Limits::default()
            },
            Limits {
                state_stack: MAX_STATE_STACK + 1,
                ..Limits::default()
            },
            Limits {
                rows: 0,
                ..Limits::default()
            },
            Limits {
                record_bytes: 1,
                ..Limits::default()
            },
            Limits {
                rows: 1,
                ..Limits::default()
            },
        ] {
            assert_eq!(
                read(&original, BASE..BASE + 64, limits).err(),
                Some(Error::Limit)
            );
        }
        assert_eq!(ordinary(&[0x40]).err(), Some(Error::Program));
        assert_eq!(
            ordinary(&[4, 0xff, 0xff, 0xff, 0xff]).err(),
            Some(Error::Program)
        );
        let table = record(CIE_PROGRAM, &[0x41; 255], BASE, 256);
        assert_eq!(
            read(&table, BASE..BASE + 256, Limits::default())
                .unwrap()
                .rows()
                .len(),
            256
        );
        let too_many = record(CIE_PROGRAM, &[0x41; 256], BASE, 257);
        assert_eq!(
            read(&too_many, BASE..BASE + 257, Limits::default()).err(),
            Some(Error::Limit)
        );
        let mut maximum_record = record(CIE_PROGRAM, &[], BASE, 64);
        maximum_record.fde.resize(MAX_RECORD_BYTES, 0);
        maximum_record.fde[..4]
            .copy_from_slice(&u32::try_from(MAX_RECORD_BYTES - 4).unwrap().to_le_bytes());
        assert!(read(&maximum_record, BASE..BASE + 64, Limits::default()).is_ok());
        maximum_record.fde.push(0);
        assert_eq!(
            read(&maximum_record, BASE..BASE + 64, Limits::default()).err(),
            Some(Error::Limit)
        );
        assert_eq!(
            parse(
                &original,
                Metadata {
                    address: u64::MAX,
                    bytes: &[0, 1]
                },
                BASE..BASE + 64,
                Limits::default()
            )
            .err(),
            Some(Error::Arithmetic)
        );
    }
}
