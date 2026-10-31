//! Independent exact-point proof for the annotated compiled leaf cohort.
//! Byte ownership and build/hook/runtime authority are separate obligations.
#![forbid(unsafe_code)]
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};
use li2core::generated_unwind::artifact::OriginalArtifactCfi;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Code,
    Prefix,
    Flow,
    Cfi,
    Row,
}
type Result<T> = std::result::Result<T, Error>;
const CALLEE: [usize; 6] = [3, 6, 12, 13, 14, 15];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rule {
    Undefined,
    Same,
    Offset(i64),
}
#[derive(Clone, Copy)]
struct Row {
    cfa: Option<(u64, u64)>,
    registers: [Rule; 17],
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(length).ok_or(Error::Bounds)?;
        let result = self.bytes.get(self.at..end).ok_or(Error::Cfi)?;
        self.at = end;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    // i128 arithmetic and a target-point interpreter are intentionally distinct
    // from the product parser's row inventory and u64/sign-extension decoder.
    fn leb(&mut self, signed: bool) -> Result<i64> {
        let mut result = 0_i128;
        for index in 0..10 {
            let byte = self.byte()?;
            let shift = 7 * index;
            result |= i128::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if signed && byte & 0x40 != 0 {
                    result -= 1_i128 << (shift + 7);
                }
                return i64::try_from(result).map_err(|_| Error::Cfi);
            }
        }
        Err(Error::Cfi)
    }
    fn unsigned(&mut self) -> Result<u64> {
        u64::try_from(self.leb(false)?).map_err(|_| Error::Cfi)
    }
    fn column(&mut self) -> Result<usize> {
        let column = usize::try_from(self.unsigned()?).map_err(|_| Error::Cfi)?;
        if column >= 17 {
            return Err(Error::Cfi);
        }
        Ok(column)
    }
}
fn program(
    bytes: &[u8],
    mut row: Row,
    start: u64,
    end: u64,
    target: u64,
    cie: bool,
) -> Result<Row> {
    let mut reader = Reader { bytes, at: 0 };
    let mut pc = start;
    while reader.at < bytes.len() {
        let opcode = reader.byte()?;
        let advance = if opcode & 0xc0 == 0x40 {
            Some(u64::from(opcode & 0x3f))
        } else if (2..=4).contains(&opcode) {
            let width = 1 << (opcode - 2);
            let mut raw = [0_u8; 8];
            raw[..width].copy_from_slice(reader.take(width)?);
            Some(u64::from_le_bytes(raw))
        } else {
            None
        };
        if let Some(amount) = advance {
            let next = pc.checked_add(amount).ok_or(Error::Bounds)?;
            if cie || amount == 0 || next > end {
                return Err(Error::Cfi);
            }
            if next > target {
                return Ok(row);
            }
            pc = next;
            continue;
        }
        if opcode & 0xc0 == 0x80 {
            let column = usize::from(opcode & 0x3f);
            if column >= 17 {
                return Err(Error::Cfi);
            }
            row.registers[column] =
                Rule::Offset(reader.leb(false)?.checked_mul(-8).ok_or(Error::Bounds)?);
            continue;
        }
        match opcode {
            0 => (),
            5 => {
                let column = reader.column()?;
                row.registers[column] =
                    Rule::Offset(reader.leb(false)?.checked_mul(-8).ok_or(Error::Bounds)?);
            }
            7 | 8 => {
                let column = reader.column()?;
                row.registers[column] = if opcode == 7 {
                    Rule::Undefined
                } else {
                    Rule::Same
                };
            }
            0x0c => {
                row.cfa = Some((reader.unsigned()?, reader.unsigned()?));
            }
            0x0d => {
                row.cfa = Some((reader.unsigned()?, row.cfa.ok_or(Error::Cfi)?.1));
            }
            0x0e => {
                row.cfa = Some((row.cfa.ok_or(Error::Cfi)?.0, reader.unsigned()?));
            }
            _ => return Err(Error::Cfi),
        }
    }
    Ok(row)
}
fn exact_row(record: &OriginalArtifactCfi, base: u64, end: u64, target: u64) -> Result<()> {
    if record.cie.len() > 65536 || record.fde.len() > 65536 {
        return Err(Error::Bounds);
    }
    let mut cie = Reader {
        bytes: &record.cie,
        at: 0,
    };
    if usize::try_from(cie.word()?)
        .ok()
        .and_then(|n| n.checked_add(4))
        != Some(record.cie.len())
        || cie.word()? != 0
        || cie.byte()? != 1
        || cie.take(3)? != b"zR\0"
        || cie.unsigned()? != 1
        || cie.leb(true)? != -8
        || cie.byte()? != 16
        || cie.unsigned()? != 1
        || cie.byte()? != 0x1b
    {
        return Err(Error::Cfi);
    }
    let initial = program(
        &record.cie[cie.at..],
        Row {
            cfa: None,
            registers: [Rule::Undefined; 17],
        },
        0,
        0,
        0,
        true,
    )?;
    let mut fde = Reader {
        bytes: &record.fde,
        at: 0,
    };
    if usize::try_from(fde.word()?)
        .ok()
        .and_then(|n| n.checked_add(4))
        != Some(record.fde.len())
    {
        return Err(Error::Cfi);
    }
    let cie_delta = u64::from(fde.word()?);
    if record
        .fde_address
        .checked_add(4)
        .and_then(|p| p.checked_sub(cie_delta))
        != Some(record.cie_address)
    {
        return Err(Error::Cfi);
    }
    let start_delta = i64::from(fde.word()? as i32);
    let encoded_start = record
        .fde_address
        .checked_add(8)
        .and_then(|field| field.checked_add_signed(start_delta))
        .ok_or(Error::Cfi)?;
    let length = u64::try_from(fde.word()? as i32).map_err(|_| Error::Cfi)?;
    if encoded_start != base
        || encoded_start.checked_add(length) != Some(end)
        || target < base
        || target >= end
        || fde.unsigned()? != 0
    {
        return Err(Error::Cfi);
    }
    let row = program(&record.fde[fde.at..], initial, base, end, target, false)?;
    if row.cfa != Some((7, 8))
        || row.registers[16] != Rule::Offset(-8)
        || CALLEE
            .into_iter()
            .any(|column| row.registers[column] != Rule::Same)
    {
        return Err(Error::Row);
    }
    Ok(())
}
fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Proves entry-to-site frame preservation from the actual compiled prefix,
/// excludes direct branches into that prefix or either certified point, then
/// independently interprets CFI at NOP5 and its exact continuation. The source
/// owner must establish the ordinary SysV return contract: later instructions
/// preserve the return word and inputs/outputs do not alias it. This helper
/// does not prove those later memory effects or arbitrary RET targets. It also
/// does not infer legal external entries or exclude jumps into an instruction's
/// interior; the source-owned entry set remains a separate premise.
pub fn prove(
    code: &[u8],
    base: u64,
    selected: u64,
    record: &OriginalArtifactCfi,
) -> Result<Vec<u64>> {
    if code.is_empty() || code.len() > 4096 {
        return Err(Error::Bounds);
    }
    let end = base.checked_add(code.len() as u64).ok_or(Error::Bounds)?;
    let offset = usize::try_from(selected.checked_sub(base).ok_or(Error::Bounds)?)
        .map_err(|_| Error::Bounds)?;
    if code.get(offset..offset.checked_add(5).ok_or(Error::Bounds)?)
        != Some(&[0x0f, 0x1f, 0x44, 0, 0])
    {
        return Err(Error::Code);
    }
    let continuation = selected.checked_add(5).ok_or(Error::Bounds)?;
    let mut decoder = Decoder::with_ip(64, code, base, DecoderOptions::NONE);
    let mut info = InstructionInfoFactory::new();
    let mut heads = Vec::new();
    let mut branches = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.next_ip() > end {
            return Err(Error::Code);
        }
        heads.push(instruction.ip());
        if instruction.ip() < selected {
            if instruction.next_ip() > selected
                || instruction.flow_control() != FlowControl::Next
                || !matches!(
                    instruction.mnemonic(),
                    Mnemonic::Mov
                        | Mnemonic::Movzx
                        | Mnemonic::Movsx
                        | Mnemonic::Movsxd
                        | Mnemonic::Lea
                        | Mnemonic::Xor
                        | Mnemonic::Add
                        | Mnemonic::Sub
                        | Mnemonic::And
                        | Mnemonic::Or
                        | Mnemonic::Cmp
                        | Mnemonic::Test
                        | Mnemonic::Nop
                )
            {
                return Err(Error::Prefix);
            }
            let effects = info.info(&instruction);
            if effects
                .used_memory()
                .iter()
                .any(|memory| writes(memory.access()))
                || effects.used_registers().iter().any(|register| {
                    writes(register.access())
                        && (!register.register().is_gpr()
                            || matches!(
                                register.register().full_register(),
                                Register::RSP
                                    | Register::RBX
                                    | Register::RBP
                                    | Register::R12
                                    | Register::R13
                                    | Register::R14
                                    | Register::R15
                            ))
                })
            {
                return Err(Error::Prefix);
            }
        }
        match instruction.flow_control() {
            FlowControl::Next if instruction.next_ip() < end => (),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                if instruction.op0_kind() == OpKind::NearBranch64 =>
            {
                if instruction.flow_control() == FlowControl::ConditionalBranch
                    && instruction.next_ip() == end
                {
                    return Err(Error::Flow);
                }
                branches.push(instruction.near_branch_target());
            }
            FlowControl::Return
                if instruction.mnemonic() == Mnemonic::Ret && instruction.op_count() == 0 => {}
            _ => return Err(Error::Flow),
        }
    }
    if heads.binary_search(&selected).is_err() || heads.binary_search(&continuation).is_err() {
        return Err(Error::Code);
    }
    // Every direct branch stays in the decoded function, strictly after both
    // certified points. Indirect jumps, calls, external tail calls and outward
    // fallthrough refuse. Ordinary RET is an ABI exit under the source owner's
    // separate return-word/non-aliasing proof, not an inferred direct edge.
    if branches
        .iter()
        .any(|target| *target <= continuation || heads.binary_search(target).is_err())
    {
        return Err(Error::Flow);
    }
    exact_row(record, base, end, selected)?;
    exact_row(record, base, end, continuation)?;
    Ok(heads)
}
