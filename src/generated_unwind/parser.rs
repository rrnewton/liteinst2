use super::{Limits, Refusal};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Rule {
    Undefined,
    Same,
    Offset(i64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Row {
    pub pc: u64,
    pub cfa: Option<(u8, i64)>,
    pub registers: [Rule; 17],
}

#[derive(Clone, Debug)]
pub(super) struct Rows {
    pub start: u64,
    pub end: u64,
    pub rows: Vec<Row>,
}

impl Rows {
    pub fn at(&self, pc: u64) -> Result<&Row, Refusal> {
        if pc < self.start || pc >= self.end {
            return Err(Refusal::SourcePoint);
        }
        self.rows
            .iter()
            .rev()
            .find(|row| row.pc <= pc)
            .ok_or(Refusal::SourcePoint)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    address: u64,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], address: u64) -> Self {
        Self {
            bytes,
            at: 0,
            address,
        }
    }
    fn byte(&mut self) -> Result<u8, Refusal> {
        let value = *self.bytes.get(self.at).ok_or(Refusal::MalformedCfi)?;
        self.at += 1;
        Ok(value)
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], Refusal> {
        let end = self.at.checked_add(len).ok_or(Refusal::Arithmetic)?;
        let value = self.bytes.get(self.at..end).ok_or(Refusal::MalformedCfi)?;
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, Refusal> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, Refusal> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn uleb(&mut self) -> Result<u64, Refusal> {
        let mut value = 0_u64;
        for index in 0..10 {
            let byte = self.byte()?;
            if index == 9 && byte & 0xfe != 0 {
                return Err(Refusal::MalformedCfi);
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Refusal::MalformedCfi)
    }
    fn sleb(&mut self) -> Result<i64, Refusal> {
        let mut value = 0_u64;
        for index in 0..10 {
            let byte = self.byte()?;
            if index == 9 && byte != 0 && byte != 0x7f {
                return Err(Refusal::MalformedCfi);
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                let bits = (index + 1) * 7;
                if bits < 64 && byte & 0x40 != 0 {
                    value |= !0_u64 << bits;
                }
                return Ok(value as i64);
            }
        }
        Err(Refusal::MalformedCfi)
    }
    fn register(&mut self) -> Result<usize, Refusal> {
        let register = usize::try_from(self.uleb()?).map_err(|_| Refusal::Arithmetic)?;
        if register > 16 {
            return Err(Refusal::UnsupportedCfi);
        }
        Ok(register)
    }
    fn pointer(&mut self, encoding: u8) -> Result<u64, Refusal> {
        match encoding {
            0 => self.u64(),
            0x1b => {
                let field = self
                    .address
                    .checked_add(self.at as u64)
                    .ok_or(Refusal::Arithmetic)?;
                field
                    .checked_add_signed(i64::from(self.u32()? as i32))
                    .ok_or(Refusal::Arithmetic)
            }
            _ => Err(Refusal::UnsupportedCfi),
        }
    }
}

fn instructions(
    bytes: &[u8],
    initial: &Row,
    start: u64,
    end: u64,
    cie: bool,
    limits: Limits,
) -> Result<Vec<Row>, Refusal> {
    let mut reader = Reader::new(bytes, 0);
    let mut state = initial.clone();
    state.pc = start;
    let mut output = Vec::new();
    let mut stack = Vec::new();
    while reader.at < bytes.len() {
        let opcode = reader.byte()?;
        let mut advance = None;
        match opcode & 0xc0 {
            0x40 => advance = Some(u64::from(opcode & 0x3f)),
            0x80 => {
                let reg = usize::from(opcode & 0x3f);
                if reg > 16 {
                    return Err(Refusal::UnsupportedCfi);
                }
                let offset = i64::try_from(reader.uleb()?).map_err(|_| Refusal::Arithmetic)?;
                state.registers[reg] =
                    Rule::Offset(offset.checked_mul(-8).ok_or(Refusal::Arithmetic)?);
            }
            0xc0 => {
                let reg = usize::from(opcode & 0x3f);
                if reg > 16 {
                    return Err(Refusal::UnsupportedCfi);
                }
                state.registers[reg] = initial.registers[reg];
            }
            _ => match opcode {
                0 => {}
                2 => advance = Some(u64::from(reader.byte()?)),
                3 => {
                    advance = Some(u64::from(u16::from_le_bytes(
                        reader.take(2)?.try_into().unwrap(),
                    )))
                }
                4 => advance = Some(u64::from(reader.u32()?)),
                5 | 0x11 => {
                    let register = reader.register()?;
                    let factor = if opcode == 5 {
                        i64::try_from(reader.uleb()?).map_err(|_| Refusal::Arithmetic)?
                    } else {
                        reader.sleb()?
                    };
                    state.registers[register] =
                        Rule::Offset(factor.checked_mul(-8).ok_or(Refusal::Arithmetic)?);
                }
                6 => {
                    let reg = reader.register()?;
                    state.registers[reg] = initial.registers[reg];
                }
                7 => {
                    let reg = reader.register()?;
                    state.registers[reg] = Rule::Undefined;
                }
                8 => {
                    let reg = reader.register()?;
                    state.registers[reg] = Rule::Same;
                }
                0x0a => {
                    if stack.len() == 8 {
                        return Err(Refusal::Limit);
                    }
                    stack.push(state.clone());
                }
                0x0b => {
                    let pc = state.pc;
                    state = stack.pop().ok_or(Refusal::MalformedCfi)?;
                    state.pc = pc;
                }
                0x0c | 0x12 => {
                    let register = reader.register()? as u8;
                    if register != 6 && register != 7 {
                        return Err(Refusal::UnsupportedCfi);
                    }
                    let offset = if opcode == 0x0c {
                        i64::try_from(reader.uleb()?).map_err(|_| Refusal::Arithmetic)?
                    } else {
                        reader.sleb()?.checked_mul(-8).ok_or(Refusal::Arithmetic)?
                    };
                    state.cfa = Some((register, offset));
                }
                0x0d => {
                    let register = reader.register()? as u8;
                    if register != 6 && register != 7 {
                        return Err(Refusal::UnsupportedCfi);
                    }
                    state.cfa = Some((register, state.cfa.ok_or(Refusal::MalformedCfi)?.1));
                }
                0x0e | 0x13 => {
                    let offset = if opcode == 0x0e {
                        i64::try_from(reader.uleb()?).map_err(|_| Refusal::Arithmetic)?
                    } else {
                        reader.sleb()?.checked_mul(-8).ok_or(Refusal::Arithmetic)?
                    };
                    state.cfa = Some((state.cfa.ok_or(Refusal::MalformedCfi)?.0, offset));
                }
                _ => return Err(Refusal::UnsupportedCfi),
            },
        }
        if let Some(amount) = advance {
            if cie || amount == 0 {
                return Err(Refusal::UnsupportedCfi);
            }
            if output.len() == limits.rows {
                return Err(Refusal::Limit);
            }
            output.push(state.clone());
            state.pc = state.pc.checked_add(amount).ok_or(Refusal::Arithmetic)?;
            if state.pc > end {
                return Err(Refusal::MalformedCfi);
            }
        }
    }
    if !stack.is_empty() {
        return Err(Refusal::MalformedCfi);
    }
    if state.pc < end || cie {
        if output.len() == limits.rows {
            return Err(Refusal::Limit);
        }
        output.push(state);
    }
    Ok(output)
}

pub(super) fn parse(
    cie_address: u64,
    cie_bytes: &[u8],
    fde_address: u64,
    fde_bytes: &[u8],
    limits: Limits,
) -> Result<Rows, Refusal> {
    if cie_bytes.len() > limits.source_record_bytes || fde_bytes.len() > limits.source_record_bytes
    {
        return Err(Refusal::Limit);
    }
    let mut cie = Reader::new(cie_bytes, cie_address);
    let length = cie.u32()?;
    if length == u32::MAX
        || usize::try_from(length).ok().and_then(|n| n.checked_add(4)) != Some(cie_bytes.len())
        || cie.u32()? != 0
        || cie.byte()? != 1
    {
        return Err(Refusal::UnsupportedCfi);
    }
    let mut augmentation = Vec::new();
    loop {
        let byte = cie.byte()?;
        if byte == 0 {
            break;
        }
        if augmentation.len() == 2 {
            return Err(Refusal::UnsupportedCfi);
        }
        augmentation.push(byte);
    }
    if cie.uleb()? != 1 || cie.sleb()? != -8 || cie.byte()? != 16 {
        return Err(Refusal::UnsupportedCfi);
    }
    let augmented = augmentation == b"zR";
    let encoding = if augmented {
        if cie.uleb()? != 1 {
            return Err(Refusal::UnsupportedCfi);
        }
        cie.byte()?
    } else if augmentation.is_empty() {
        0
    } else {
        return Err(Refusal::UnsupportedCfi);
    };
    if encoding != 0 && encoding != 0x1b {
        return Err(Refusal::UnsupportedCfi);
    }
    let empty = Row {
        pc: 0,
        cfa: None,
        registers: [Rule::Undefined; 17],
    };
    let initial = instructions(&cie_bytes[cie.at..], &empty, 0, 0, true, limits)?;
    if initial.len() != 1 {
        return Err(Refusal::MalformedCfi);
    }
    let mut fde = Reader::new(fde_bytes, fde_address);
    let length = fde.u32()?;
    if length == u32::MAX
        || usize::try_from(length).ok().and_then(|n| n.checked_add(4)) != Some(fde_bytes.len())
    {
        return Err(Refusal::MalformedCfi);
    }
    let cie_pointer = fde.u32()?;
    if fde_address
        .checked_add(4)
        .and_then(|field| field.checked_sub(u64::from(cie_pointer)))
        != Some(cie_address)
    {
        return Err(Refusal::SourceIdentity);
    }
    let start = fde.pointer(encoding)?;
    let size = if encoding & 0x0f == 0 {
        fde.u64()?
    } else {
        let signed = fde.u32()? as i32;
        u64::try_from(signed).map_err(|_| Refusal::MalformedCfi)?
    };
    let end = start
        .checked_add(size)
        .filter(|end| *end > start)
        .ok_or(Refusal::Arithmetic)?;
    if augmented && fde.uleb()? != 0 {
        return Err(Refusal::UnsupportedCfi);
    }
    let rows = instructions(&fde_bytes[fde.at..], &initial[0], start, end, false, limits)?;
    if rows.is_empty() {
        return Err(Refusal::MalformedCfi);
    }
    Ok(Rows { start, end, rows })
}
