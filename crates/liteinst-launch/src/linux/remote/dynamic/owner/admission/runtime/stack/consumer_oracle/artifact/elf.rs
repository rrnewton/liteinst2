use super::*;
use iced_x86::{Code, Decoder, DecoderOptions};

fn bad() -> OracleError {
    OracleError::Invalid("artifact ELF or closed path differs")
}
fn bytes(raw: &[u8], offset: usize, length: usize) -> Result<&[u8], OracleError> {
    raw.get(offset..offset.checked_add(length).ok_or_else(bad)?)
        .ok_or_else(bad)
}
fn u16_at(raw: &[u8], offset: usize) -> Result<u16, OracleError> {
    Ok(u16::from_le_bytes(
        bytes(raw, offset, 2)?.try_into().map_err(|_| bad())?,
    ))
}
fn u32_at(raw: &[u8], offset: usize) -> Result<u32, OracleError> {
    Ok(u32::from_le_bytes(
        bytes(raw, offset, 4)?.try_into().map_err(|_| bad())?,
    ))
}
fn u64_at(raw: &[u8], offset: usize) -> Result<u64, OracleError> {
    Ok(u64::from_le_bytes(
        bytes(raw, offset, 8)?.try_into().map_err(|_| bad())?,
    ))
}
fn index(value: u64) -> Result<usize, OracleError> {
    usize::try_from(value).map_err(|_| bad())
}
fn range(start: u64, size: u64) -> Result<Range<u64>, OracleError> {
    let end = start.checked_add(size).ok_or_else(bad)?;
    if start == 0 || end <= start || end > 0x0000_8000_0000_0000 {
        return Err(bad());
    }
    Ok(start..end)
}
pub(super) fn inspect(raw: &[u8]) -> Result<ArtifactPlan, OracleError> {
    if raw.len() > FILE_CAP
        || bytes(raw, 0, 9)? != b"\x7fELF\x02\x01\x01\x00\x00"
        || bytes(raw, 9, 7)?.iter().any(|b| *b != 0)
        || u16_at(raw, 16)? != 2
        || u16_at(raw, 18)? != 62
        || u32_at(raw, 20)? != 1
        || u32_at(raw, 48)? != 0
        || u16_at(raw, 52)? != 64
        || u16_at(raw, 54)? != 56
        || u16_at(raw, 58)? != 64
    {
        return Err(bad());
    }
    let entry = u64_at(raw, 24)?;
    let phoff = index(u64_at(raw, 32)?)?;
    let phnum = usize::from(u16_at(raw, 56)?);
    if phoff != 64 || !(2..=16).contains(&phnum) {
        return Err(bad());
    }
    bytes(raw, phoff, phnum.checked_mul(56).ok_or_else(bad)?)?;
    let mut loads = [None; 2];
    let mut count = 0;
    let mut stack = false;
    let mut phdr = None;
    for p in 0..phnum {
        let row = bytes(raw, phoff + p * 56, 56)?;
        let kind = u32_at(row, 0)?;
        let flags = u32_at(row, 4)?;
        let offset = u64_at(row, 8)?;
        let address = u64_at(row, 16)?;
        let filesz = u64_at(row, 32)?;
        let memsz = u64_at(row, 40)?;
        match kind {
            1 => {
                if count == 2
                    || !matches!(flags, 4 | 5)
                    || filesz == 0
                    || filesz > 4096
                    || memsz != filesz
                    || offset % 4096 != 0
                    || address % 4096 != 0
                    || u64_at(row, 24)? != address
                    || u64_at(row, 48)? != 4096
                {
                    return Err(bad());
                }
                bytes(raw, index(offset)?, index(filesz)?)?;
                loads[count] = Some((offset, address, filesz, flags));
                count += 1;
            }
            6 => {
                if phdr.is_some()
                    || flags != 4
                    || offset != 64
                    || filesz != phnum as u64 * 56
                    || memsz != filesz
                    || u64_at(row, 24)? != address
                    || u64_at(row, 48)? != 8
                {
                    return Err(bad());
                }
                phdr = Some(address);
            }
            0x6474e551 => {
                if stack || flags != 6 || filesz != 0 || memsz != 0 {
                    return Err(bad());
                }
                stack = true;
            }
            _ => return Err(bad()),
        }
    }
    if count != 2 || !stack {
        return Err(bad());
    }
    let (roff, raddr, rsize, rflags) = loads[0].ok_or_else(bad)?;
    let (xoff, xaddr, xsize, xflags) = loads[1].ok_or_else(bad)?;
    if roff != 0
        || xoff != 4096
        || rflags != 4
        || xflags != 5
        || raddr.checked_add(4096) != Some(xaddr)
        || rsize < (64 + 56 * phnum) as u64
        || phdr != raddr.checked_add(64)
    {
        return Err(bad());
    }
    let read_load = range(raddr, 4096)?;
    let text_load = range(xaddr, 4096)?;
    let executable = range(xaddr, xsize)?;
    let shoff = index(u64_at(raw, 40)?)?;
    let shnum = usize::from(u16_at(raw, 60)?);
    if !(2..=64).contains(&shnum) || usize::from(u16_at(raw, 62)?) >= shnum {
        return Err(bad());
    }
    let sections = bytes(raw, shoff, shnum.checked_mul(64).ok_or_else(bad)?)?;
    let mut symtab = None;
    for (i, row) in sections.chunks_exact(64).enumerate() {
        let kind = u32_at(row, 4)?;
        let flags = u64_at(row, 8)?;
        let size = u64_at(row, 32)?;
        if (matches!(kind, 4 | 6 | 9 | 11) && size != 0) || (kind == 8 && flags & 2 != 0) {
            return Err(bad());
        }
        if kind != 8 {
            bytes(raw, index(u64_at(row, 24)?)?, index(size)?)?;
        }
        if kind == 2 {
            if symtab.is_some() || u64_at(row, 56)? != 24 || size % 24 != 0 || size / 24 > 256 {
                return Err(bad());
            }
            symtab = Some(i);
        }
    }
    let sym = bytes(sections, symtab.ok_or_else(bad)? * 64, 64)?;
    let strings = bytes(
        sections,
        usize::try_from(u32_at(sym, 40)?)
            .map_err(|_| bad())?
            .checked_mul(64)
            .ok_or_else(bad)?,
        64,
    )?;
    if u32_at(strings, 4)? != 3 {
        return Err(bad());
    }
    let strings = bytes(
        raw,
        index(u64_at(strings, 24)?)?,
        index(u64_at(strings, 32)?)?,
    )?;
    let symbols = bytes(raw, index(u64_at(sym, 24)?)?, index(u64_at(sym, 32)?)?)?;
    let mut start = None;
    let mut helper = None;
    for symbol in symbols.chunks_exact(24) {
        if symbol[4] & 15 != 2 {
            continue;
        }
        let shindex = usize::from(u16_at(symbol, 6)?);
        if shindex == 0 || shindex >= shnum {
            return Err(bad());
        }
        let section = bytes(sections, shindex * 64, 64)?;
        let section_address = u64_at(section, 16)?;
        let section_extent = range(section_address, u64_at(section, 32)?)?;
        if u32_at(section, 4)? != 1
            || u64_at(section, 8)? != 6
            || section_extent.start < executable.start
            || section_extent.end > executable.end
            || u64_at(section, 24)? != xoff.checked_add(section_address - xaddr).ok_or_else(bad)?
        {
            return Err(bad());
        }
        let name = index(u64::from(u32_at(symbol, 0)?))?;
        let name = strings.get(name..).ok_or_else(bad)?;
        let name = &name[..name.iter().position(|b| *b == 0).ok_or_else(bad)?];
        let value = range(u64_at(symbol, 8)?, u64_at(symbol, 16)?)?;
        if value.start < section_extent.start || value.end > section_extent.end {
            return Err(bad());
        }
        let destination = match name {
            b"_start" if symbol[4] >> 4 == 1 => &mut start,
            b"add_seven" if symbol[4] >> 4 == 0 => &mut helper,
            _ => return Err(bad()),
        };
        if destination.replace(value).is_some() {
            return Err(bad());
        }
    }
    let start = start.ok_or_else(bad)?;
    let helper = helper.ok_or_else(bad)?;
    if entry != start.start || (start.start < helper.end && helper.start < start.end) {
        return Err(bad());
    }
    let mut plan = ArtifactPlan {
        entry,
        start,
        helper,
        read_load,
        text_load,
        read_filesz: index(rsize)?,
        text_filesz: index(xsize)?,
        instructions: [None; PLAN_CAP],
        count: 0,
        call: usize::MAX,
        ret: usize::MAX,
        syscalls: [usize::MAX; 3],
    };
    let mut pc = plan.entry;
    let mut continuation = None;
    let mut returned = false;
    let mut syscalls = 0;
    let mut ordinary = 0;
    loop {
        if plan.count == PLAN_CAP {
            return Err(bad());
        }
        let in_helper = continuation.is_some() && !returned;
        let scope = if in_helper { &plan.helper } else { &plan.start };
        if !scope.contains(&pc) {
            return Err(bad());
        }
        let offset = index(4096 + pc - xaddr)?;
        let remaining = bytes(raw, offset, index(scope.end - pc)?)?;
        let mut decoder = Decoder::with_ip(64, remaining, pc, DecoderOptions::NONE);
        let decoded = decoder.decode();
        let length = decoded.len();
        if decoded.is_invalid() || !(1..=15).contains(&length) || length > remaining.len() {
            return Err(bad());
        }
        let encoding = &remaining[..length];
        let next = pc.checked_add(length as u64).ok_or_else(bad)?;
        let kind = match decoded.code() {
            Code::Call_rel32_64 => {
                if in_helper
                    || continuation.is_some()
                    || encoding.len() != 5
                    || encoding[0] != 0xe8
                    || syscalls != 1
                {
                    return Err(bad());
                }
                let disp = i32::from_le_bytes(encoding[1..].try_into().map_err(|_| bad())?);
                let target = next.checked_add_signed(i64::from(disp)).ok_or_else(bad)?;
                if target != plan.helper.start || next >= plan.start.end {
                    return Err(bad());
                }
                continuation = Some(next);
                plan.call = plan.count;
                PlannedKind::Call
            }
            Code::Retnq => {
                if !in_helper || returned || encoding != [0xc3] || next != plan.helper.end {
                    return Err(bad());
                }
                plan.ret = plan.count;
                returned = true;
                PlannedKind::Ret
            }
            Code::Syscall => {
                if in_helper
                    || encoding != [0x0f, 0x05]
                    || syscalls == 3
                    || (syscalls != 0 && !returned)
                {
                    return Err(bad());
                }
                let number = [39, 186, 231][syscalls];
                plan.syscalls[syscalls] = plan.count;
                syscalls += 1;
                if number == 231 && next != plan.start.end {
                    return Err(bad());
                }
                PlannedKind::Syscall { number }
            }
            _ => {
                super::super::dataflow::require_ordinary(&decoded, encoding)?;
                ordinary += 1;
                if ordinary > 30 {
                    return Err(bad());
                }
                PlannedKind::Ordinary
            }
        };
        let mut encoded = [0; 15];
        encoded[..length].copy_from_slice(encoding);
        plan.instructions[plan.count] = Some(PlannedInstruction {
            ordinal: plan.count,
            pc,
            bytes: encoded,
            length,
            kind,
            decoded,
        });
        plan.count += 1;
        pc = match kind {
            PlannedKind::Call => plan.helper.start,
            PlannedKind::Ret => continuation.ok_or_else(bad)?,
            _ => next,
        };
        if kind == (PlannedKind::Syscall { number: 231 }) {
            break;
        }
    }
    if syscalls != 3 || plan.call == usize::MAX || plan.ret == usize::MAX || !returned {
        return Err(bad());
    }
    // The walked symbol extents have no hidden gaps or fall-through branches.
    let main_bytes: usize = plan
        .instructions()
        .filter(|i| !plan.helper.contains(&i.pc))
        .map(|i| i.length)
        .sum();
    let helper_bytes: usize = plan
        .instructions()
        .filter(|i| plan.helper.contains(&i.pc))
        .map(|i| i.length)
        .sum();
    if main_bytes != index(plan.start.end - plan.start.start)?
        || helper_bytes != index(plan.helper.end - plan.helper.start)?
    {
        return Err(bad());
    }
    Ok(plan)
}
