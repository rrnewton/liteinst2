use super::{Limits, Refusal, parser};
use crate::frame_trace::{FrameState, OriginalRegisterLocation};
use iced_x86::Register;

const CALLEE: [u8; 6] = [3, 6, 12, 13, 14, 15];

#[derive(Clone, Debug)]
pub(super) struct Row {
    pub start: u64,
    pub end: u64,
    pub instructions: Vec<u8>,
}

fn register(number: u8) -> Result<Register, Refusal> {
    match number {
        0 => Ok(Register::RAX),
        1 => Ok(Register::RDX),
        2 => Ok(Register::RCX),
        3 => Ok(Register::RBX),
        4 => Ok(Register::RSI),
        5 => Ok(Register::RDI),
        6 => Ok(Register::RBP),
        7 => Ok(Register::RSP),
        8 => Ok(Register::R8),
        9 => Ok(Register::R9),
        10 => Ok(Register::R10),
        11 => Ok(Register::R11),
        12 => Ok(Register::R12),
        13 => Ok(Register::R13),
        14 => Ok(Register::R14),
        15 => Ok(Register::R15),
        _ => Err(Refusal::CallerRule),
    }
}
fn number(register: Register) -> Result<u8, Refusal> {
    for value in 0..16 {
        if self::register(value)? == register {
            return Ok(value);
        }
    }
    Err(Refusal::CallerRule)
}
pub(super) fn uleb(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        output.push(byte | if value != 0 { 0x80 } else { 0 });
        if value == 0 {
            break;
        }
    }
}
pub(super) fn sleb(mut value: i64, output: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        output.push(byte | if done { 0 } else { 0x80 });
        if done {
            break;
        }
    }
}
fn breg(reg: Register, offset: i64, output: &mut Vec<u8>) -> Result<(), Refusal> {
    output.push(0x70 + number(reg)?);
    sleb(offset, output);
    Ok(())
}
fn original_rsp(state: Option<&FrameState>) -> (Register, i64) {
    state.map_or((Register::RSP, 0), |state| {
        let (anchor, offset) = state.original_rsp_rule();
        (anchor, i64::from(offset))
    })
}
fn location(
    state: Option<&FrameState>,
    reg: Register,
) -> Result<OriginalRegisterLocation, Refusal> {
    state.map_or_else(
        || {
            Ok(if reg == Register::RSP {
                OriginalRegisterLocation::OriginalStackPointer
            } else {
                OriginalRegisterLocation::Live(reg)
            })
        },
        |state| state.original_register(reg).ok_or(Refusal::CallerRule),
    )
}
fn value(state: Option<&FrameState>, reg: Register) -> Result<Vec<u8>, Refusal> {
    let mut expr = Vec::new();
    match location(state, reg)? {
        OriginalRegisterLocation::Live(live) => breg(live, 0, &mut expr)?,
        OriginalRegisterLocation::Stack(offset) => {
            let (anchor, bias) = original_rsp(state);
            breg(
                anchor,
                bias.checked_add(i64::from(offset))
                    .ok_or(Refusal::Arithmetic)?,
                &mut expr,
            )?;
            expr.push(0x06); // DW_OP_deref: recover the original base register's value.
        }
        OriginalRegisterLocation::OriginalStackPointer => {
            let (anchor, bias) = original_rsp(state);
            breg(anchor, bias, &mut expr)?;
        }
    }
    Ok(expr)
}
fn block(
    opcode: u8,
    register: Option<u8>,
    expr: &[u8],
    limits: Limits,
    output: &mut Vec<u8>,
) -> Result<(), Refusal> {
    if expr.len() > limits.expression_bytes {
        return Err(Refusal::Limit);
    }
    output.push(opcode);
    if let Some(register) = register {
        uleb(u64::from(register), output);
    }
    uleb(expr.len() as u64, output);
    output.extend_from_slice(expr);
    Ok(())
}
pub(super) fn compose(
    start: u64,
    end: u64,
    original: &parser::Row,
    state: Option<&FrameState>,
    limits: Limits,
) -> Result<Row, Refusal> {
    if start >= end || end - start > 15 {
        return Err(Refusal::FrameShape);
    }
    let (base, offset) = original.cfa.ok_or(Refusal::CallerRule)?;
    if base != 6 && base != 7 {
        return Err(Refusal::CallerRule);
    }
    let mut cfa = value(state, register(base)?)?;
    if offset != 0 {
        cfa.push(0x11);
        sleb(offset, &mut cfa);
        cfa.push(0x22);
    }
    let mut output = Vec::new();
    block(0x0f, None, &cfa, limits, &mut output)?; // def_cfa_expression
    for reg in CALLEE.into_iter().chain(core::iter::once(16)) {
        match original.registers[usize::from(reg)] {
            parser::Rule::Undefined => return Err(Refusal::CallerRule),
            parser::Rule::Offset(offset) => {
                // This remains caller memory relative to the COMPOSED CFA.
                // It is never replaced with the application's context slot.
                if offset % -8 != 0 {
                    return Err(Refusal::CallerRule);
                }
                output.push(0x11);
                uleb(u64::from(reg), &mut output);
                sleb(
                    offset.checked_div(-8).ok_or(Refusal::Arithmetic)?,
                    &mut output,
                );
            }
            parser::Rule::Same => {
                if reg == 16 {
                    return Err(Refusal::CallerRule);
                }
                match location(state, register(reg)?)? {
                    OriginalRegisterLocation::Live(live) if number(live)? == reg => {
                        output.push(8);
                        uleb(u64::from(reg), &mut output);
                    }
                    OriginalRegisterLocation::Live(live) => {
                        output.push(9);
                        uleb(u64::from(reg), &mut output);
                        uleb(u64::from(number(live)?), &mut output);
                    }
                    OriginalRegisterLocation::Stack(offset) => {
                        let (anchor, bias) = original_rsp(state);
                        let mut address = Vec::new();
                        breg(
                            anchor,
                            bias.checked_add(i64::from(offset))
                                .ok_or(Refusal::Arithmetic)?,
                            &mut address,
                        )?;
                        // expression gives a location, with NO final dereference.
                        block(0x10, Some(reg), &address, limits, &mut output)?;
                    }
                    OriginalRegisterLocation::OriginalStackPointer => {
                        block(
                            0x16,
                            Some(reg),
                            &value(state, Register::RSP)?,
                            limits,
                            &mut output,
                        )?;
                    }
                }
            }
        }
    }
    Ok(Row {
        start,
        end,
        instructions: output,
    })
}

fn record(body: &[u8], output: &mut Vec<u8>) -> Result<usize, Refusal> {
    let start = output.len();
    let padded = body.len().checked_add(3).ok_or(Refusal::Arithmetic)? & !3;
    let length = u32::try_from(padded).map_err(|_| Refusal::Arithmetic)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(body);
    output.resize(
        start
            .checked_add(4)
            .and_then(|n| n.checked_add(padded))
            .ok_or(Refusal::Arithmetic)?,
        0,
    );
    Ok(start)
}

// Encoded .eh_frame bytes and (start, end, FDE byte offset) inventory.
type EncodedFrameRecords = (Vec<u8>, Vec<(u64, u64, usize)>);

pub(super) fn encode(rows: &[Row], limits: Limits) -> Result<EncodedFrameRecords, Refusal> {
    encode_records(rows, None, limits)
}

/// ELF-coordinate encoding: every initial-location field is pcrel/sdata4.
/// A common load bias leaves both the pointer and the CFI expressions unchanged.
pub(super) fn encode_relative(
    rows: &[Row],
    address: u64,
    limits: Limits,
) -> Result<EncodedFrameRecords, Refusal> {
    if rows
        .iter()
        .any(|row| row.start >= row.end || row.end - row.start > 15)
    {
        return Err(Refusal::FrameShape);
    }
    encode_records(rows, Some(address), limits)
}

fn encode_records(
    rows: &[Row],
    address: Option<u64>,
    limits: Limits,
) -> Result<EncodedFrameRecords, Refusal> {
    if rows.is_empty() || rows.len() > limits.rows {
        return Err(Refusal::Limit);
    }
    let mut output = Vec::new();
    // Actual .eh_frame CIE: ID=0, v1, zR, code-align1, data-align-8,
    // RA=16, augmentation length1. Live records retain absolute eight-byte
    // locations; artifact records use signed four-byte PC-relative locations.
    record(
        &[
            0,
            0,
            0,
            0,
            1,
            b'z',
            b'R',
            0,
            1,
            0x78,
            16,
            1,
            if address.is_some() { 0x1b } else { 0 },
        ],
        &mut output,
    )?;
    let mut fdes = Vec::new();
    let mut index = 0;
    while index < rows.len() {
        if fdes.len() == limits.fdes {
            return Err(Refusal::Limit);
        }
        let begin = index;
        let start = rows[index].start;
        let mut end = rows[index].end;
        index += 1;
        while index < rows.len() && rows[index].start == end {
            end = rows[index].end;
            index += 1;
        }
        if index < rows.len() && rows[index].start < end {
            return Err(Refusal::FrameShape);
        }
        let fde = output.len();
        let mut body = Vec::new();
        body.extend_from_slice(
            &u32::try_from(fde.checked_add(4).ok_or(Refusal::Arithmetic)?)
                .map_err(|_| Refusal::Arithmetic)?
                .to_le_bytes(),
        );
        if let Some(address) = address {
            let field = address
                .checked_add(u64::try_from(fde).map_err(|_| Refusal::Arithmetic)?)
                .and_then(|at| at.checked_add(8))
                .ok_or(Refusal::Arithmetic)?;
            let delta = i32::try_from(i128::from(start) - i128::from(field))
                .map_err(|_| Refusal::Arithmetic)?;
            let extent = end.checked_sub(start).ok_or(Refusal::Arithmetic)?;
            let extent = i32::try_from(extent).map_err(|_| Refusal::Arithmetic)?;
            body.extend_from_slice(&delta.to_le_bytes());
            body.extend_from_slice(&extent.to_le_bytes());
        } else {
            body.extend_from_slice(&start.to_le_bytes());
            body.extend_from_slice(&(end - start).to_le_bytes());
        }
        body.push(0); // zero-length FDE augmentation
        let mut current = start;
        for row in &rows[begin..index] {
            if row.start != current {
                body.push(4); // advance_loc4, code alignment is one
                body.extend_from_slice(
                    &u32::try_from(row.start.checked_sub(current).ok_or(Refusal::Arithmetic)?)
                        .map_err(|_| Refusal::Arithmetic)?
                        .to_le_bytes(),
                );
            }
            body.extend_from_slice(&row.instructions);
            current = row.start;
            if body.len() > limits.metadata_bytes {
                return Err(Refusal::Limit);
            }
        }
        record(&body, &mut output)?;
        fdes.push((start, end, fde));
        if output.len().checked_add(4).ok_or(Refusal::Arithmetic)? > limits.metadata_bytes {
            return Err(Refusal::Limit);
        }
    }
    output.extend_from_slice(&[0; 4]);
    if let Some(address) = address {
        address
            .checked_add(u64::try_from(output.len()).map_err(|_| Refusal::Arithmetic)?)
            .ok_or(Refusal::Arithmetic)?;
    }
    Ok((output, fdes))
}
