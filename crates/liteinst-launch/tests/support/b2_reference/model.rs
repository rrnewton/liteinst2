//! Handwritten finite decoder and state machine. No iced decoder, production
//! SelectedInput completion, register helpers, admission plans or native_result.
use super::*;
use image::{DATA, DATA_LEN};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct State {
    pub(super) registers: RegisterSnapshot,
    pub(super) xstate: Vec<u8>,
    pub(super) mask: u64,
    pub(super) data: Vec<u8>,
}
pub(super) fn reg(r: &RegisterSnapshot, n: usize) -> u64 {
    [
        r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12,
        r.r13, r.r14, r.r15,
    ][n]
}
pub(super) fn set(r: &mut RegisterSnapshot, n: usize, value: u64) {
    match n {
        0 => r.rax = value,
        1 => r.rcx = value,
        2 => r.rdx = value,
        3 => r.rbx = value,
        4 => r.rsp = value,
        5 => r.rbp = value,
        6 => r.rsi = value,
        7 => r.rdi = value,
        8 => r.r8 = value,
        9 => r.r9 = value,
        10 => r.r10 = value,
        11 => r.r11 = value,
        12 => r.r12 = value,
        13 => r.r13 = value,
        14 => r.r14 = value,
        15 => r.r15 = value,
        _ => panic!("fixture register outside x86 GPR set"),
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Selected {
    Cpuid,
    Rdrand { destination: usize, width: u8 },
    Rdseed { destination: usize, width: u8 },
    Rdpid { destination: usize },
    Rdtsc,
    Rdtscp,
    Syscall,
}
impl Selected {
    pub(super) fn class(self) -> SiteClass {
        match self {
            Self::Cpuid => SiteClass::Cpuid,
            Self::Rdrand { .. } => SiteClass::Rdrand,
            Self::Rdseed { .. } => SiteClass::Rdseed,
            Self::Rdpid { .. } => SiteClass::Rdpid,
            Self::Rdtsc => SiteClass::Rdtsc,
            Self::Rdtscp => SiteClass::Rdtscp,
            Self::Syscall => SiteClass::Syscall,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Effect {
    Selected(Selected),
    Mov {
        destination: usize,
        width: u8,
        value: u64,
    },
    Store {
        source: usize,
        address: u64,
    },
    Nop,
    Jump(u64),
    Call(u64),
    Ret,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Instruction {
    pub(super) len: usize,
    pub(super) effect: Effect,
}
fn relative(next: u64, bytes: &[u8]) -> Option<u64> {
    next.checked_add_signed(i64::from(i32::from_le_bytes(
        bytes.get(..4)?.try_into().ok()?,
    )))
}

pub(super) fn decode(pc: u64, bytes: &[u8]) -> Result<Instruction, &'static str> {
    let make = |len, effect| Ok(Instruction { len, effect });
    if bytes.starts_with(&[0x0f, 0xa2]) {
        return make(2, Effect::Selected(Selected::Cpuid));
    }
    if bytes.starts_with(&[0x0f, 0x31]) {
        return make(2, Effect::Selected(Selected::Rdtsc));
    }
    if bytes.starts_with(&[0x0f, 0x01, 0xf9]) {
        return make(3, Effect::Selected(Selected::Rdtscp));
    }
    if bytes.starts_with(&[0x0f, 0x05]) {
        return make(2, Effect::Selected(Selected::Syscall));
    }
    if bytes.first() == Some(&0x90) {
        return make(1, Effect::Nop);
    }
    if bytes.first() == Some(&0xc3) {
        return make(1, Effect::Ret);
    }
    if matches!(bytes.first(), Some(0xe8 | 0xe9)) {
        let target = relative(pc.checked_add(5).ok_or("PC overflow")?, &bytes[1..])
            .ok_or("branch bytes/range")?;
        return make(
            5,
            if bytes[0] == 0xe8 {
                Effect::Call(target)
            } else {
                Effect::Jump(target)
            },
        );
    }
    let mut i = 0;
    let prefix = bytes.first().copied().filter(|b| matches!(b, 0x66 | 0xf3));
    if prefix.is_some() {
        i += 1;
    }
    let rex = bytes
        .get(i)
        .copied()
        .filter(|b| (0x40..=0x4f).contains(b))
        .unwrap_or(0);
    if rex != 0 {
        i += 1;
    }
    let width = if rex & 8 != 0 {
        64
    } else if prefix == Some(0x66) {
        16
    } else {
        32
    };
    if bytes.get(i..i + 2) == Some(&[0x0f, 0xc7]) {
        let m = *bytes.get(i + 2).ok_or("random modrm absent")?;
        if rex & 6 != 0 || m < 0xf0 {
            return Err("unsupported random addressing");
        }
        let destination = usize::from(m & 7) + if rex & 1 != 0 { 8 } else { 0 };
        let selected = if prefix == Some(0xf3) && m & 0xf8 == 0xf8 {
            Selected::Rdpid { destination }
        } else if prefix != Some(0xf3) && m & 0xf8 == 0xf0 {
            Selected::Rdrand { destination, width }
        } else if prefix != Some(0xf3) && m & 0xf8 == 0xf8 {
            Selected::Rdseed { destination, width }
        } else {
            return Err("unsupported random prefix");
        };
        return make(i + 3, Effect::Selected(selected));
    }
    if let Some(opcode) = bytes.get(i).copied().filter(|b| (0xb8..=0xbf).contains(b)) {
        if prefix == Some(0xf3) || rex & 6 != 0 {
            return Err("unsupported MOV prefix");
        }
        let size = usize::from(width / 8);
        let immediate = bytes
            .get(i + 1..i + 1 + size)
            .ok_or("MOV immediate absent")?;
        let mut padded = [0; 8];
        padded[..size].copy_from_slice(immediate);
        return make(
            i + 1 + size,
            Effect::Mov {
                destination: usize::from(opcode & 7) + if rex & 1 != 0 { 8 } else { 0 },
                width,
                value: u64::from_le_bytes(padded),
            },
        );
    }
    if prefix.is_none() && matches!(rex, 0x48 | 0x4c) && bytes.get(i) == Some(&0x89) {
        let m = *bytes.get(i + 1).ok_or("store modrm absent")?;
        if m & 0xc7 != 0x05 {
            return Err("store addressing outside fixture");
        }
        let len = i + 6;
        let address = relative(
            pc.checked_add(len as u64).ok_or("PC overflow")?,
            bytes.get(i + 2..).ok_or("store displacement absent")?,
        )
        .ok_or("store displacement/range")?;
        return make(
            len,
            Effect::Store {
                source: usize::from((m >> 3) & 7) + if rex & 4 != 0 { 8 } else { 0 },
                address,
            },
        );
    }
    Err("instruction outside independent finite decoder")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Reply {
    Cpuid([u32; 4]),
    Rdrand { value: u64, carry: bool },
    Rdseed { value: u64, carry: bool },
    Rdpid(u32),
    Rdtsc(u64),
    Rdtscp(u64, u32),
    GetId(u32),
}
impl Reply {
    // Only the provider boundary uses production result types. Expected effects
    // below never call this conversion or any production semantic helper.
    pub(super) fn result(self) -> SelectedResult {
        match self {
            Self::Cpuid([eax, ebx, ecx, edx]) => SelectedResult::Cpuid { eax, ebx, ecx, edx },
            Self::Rdrand { value, carry } => SelectedResult::Rdrand { value, carry },
            Self::Rdseed { value, carry } => SelectedResult::Rdseed { value, carry },
            Self::Rdpid(auxiliary) => SelectedResult::Rdpid { auxiliary },
            Self::Rdtsc(counter) => SelectedResult::Rdtsc { counter },
            Self::Rdtscp(counter, auxiliary) => SelectedResult::Rdtscp { counter, auxiliary },
            Self::GetId(value) => SelectedResult::Syscall(SyscallResult::LinuxX64GetId { value }),
        }
    }
}
fn assign(
    r: &mut RegisterSnapshot,
    destination: usize,
    width: u8,
    value: u64,
) -> Result<(), &'static str> {
    let mask = match width {
        16 => 0xffff,
        32 => 0xffff_ffff,
        64 => u64::MAX,
        _ => return Err("invalid width"),
    };
    if value & !mask != 0 {
        return Err("script value exceeds width");
    }
    let result = if width == 16 {
        (reg(r, destination) & !mask) | value
    } else {
        value
    };
    set(r, destination, result);
    Ok(())
}
impl State {
    fn memory_offset(&self, address: u64) -> Result<usize, &'static str> {
        let offset = usize::try_from(address.checked_sub(DATA).ok_or("memory below data")?)
            .map_err(|_| "memory offset")?;
        if self.data.len() != DATA_LEN
            || offset
                .checked_add(8)
                .is_none_or(|end| end > self.data.len())
        {
            return Err("memory outside fixed data");
        }
        Ok(offset)
    }
    fn store(&mut self, address: u64, value: u64) -> Result<(), &'static str> {
        let offset = self.memory_offset(address)?;
        self.data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn load(&self, address: u64) -> Result<u64, &'static str> {
        let offset = self.memory_offset(address)?;
        Ok(u64::from_le_bytes(
            self.data[offset..offset + 8].try_into().unwrap(),
        ))
    }
    pub(super) fn ordinary(
        &self,
        instruction: Instruction,
        fixture: &Fixture,
    ) -> Result<Self, &'static str> {
        let mut after = self.clone();
        let next = self
            .registers
            .rip
            .checked_add(instruction.len as u64)
            .ok_or("next PC overflow")?;
        after.registers.rip = next;
        match instruction.effect {
            Effect::Selected(_) => return Err("selected instruction must be intercepted"),
            Effect::Mov {
                destination,
                width,
                value,
            } => assign(&mut after.registers, destination, width, value)?,
            Effect::Store { source, address } => {
                after.store(address, reg(&self.registers, source))?
            }
            Effect::Nop => {}
            Effect::Call(target) => {
                after.registers.rsp = self.registers.rsp.checked_sub(8).ok_or("stack underflow")?;
                after.store(after.registers.rsp, next)?;
                after.registers.rip = target;
            }
            Effect::Jump(target) => after.registers.rip = target,
            Effect::Ret => {
                after.registers.rip = self.load(self.registers.rsp)?;
                after.registers.rsp = self.registers.rsp.checked_add(8).ok_or("stack overflow")?;
            }
        }
        if !fixture.heads.contains(&after.registers.rip) {
            return Err("successor is not declared head");
        }
        if matches!(
            instruction.effect,
            Effect::Call(_) | Effect::Jump(_) | Effect::Ret
        ) && !fixture.blocks.contains(&after.registers.rip)
        {
            return Err("transfer is not declared block entry");
        }
        Ok(after)
    }
    pub(super) fn selected(
        &self,
        instruction: Instruction,
        reply: Reply,
    ) -> Result<Self, &'static str> {
        if self.registers.eflags & 0x10100 != 0 || self.registers.orig_rax != u64::MAX {
            return Err("selected input outside declared user flag/phase profile");
        }
        let mut after = self.clone();
        after.registers.rip = self
            .registers
            .rip
            .checked_add(instruction.len as u64)
            .ok_or("next PC overflow")?;
        match (instruction.effect, reply) {
            (Effect::Selected(Selected::Cpuid), Reply::Cpuid([a, b, c, d])) => {
                after.registers.rax = u64::from(a);
                after.registers.rbx = u64::from(b);
                after.registers.rcx = u64::from(c);
                after.registers.rdx = u64::from(d);
            }
            (
                Effect::Selected(Selected::Rdrand { destination, width }),
                Reply::Rdrand { value, carry },
            )
            | (
                Effect::Selected(Selected::Rdseed { destination, width }),
                Reply::Rdseed { value, carry },
            ) => {
                if !carry && value != 0 {
                    return Err("failed random must zero its destination");
                }
                assign(&mut after.registers, destination, width, value)?;
                after.registers.eflags = (self.registers.eflags & !0x8d5) | u64::from(carry);
            }
            (Effect::Selected(Selected::Rdpid { destination }), Reply::Rdpid(value)) => {
                assign(&mut after.registers, destination, 32, u64::from(value))?
            }
            (Effect::Selected(Selected::Rdtsc), Reply::Rdtsc(counter)) => {
                after.registers.rax = counter & 0xffff_ffff;
                after.registers.rdx = counter >> 32;
            }
            (Effect::Selected(Selected::Rdtscp), Reply::Rdtscp(counter, aux)) => {
                after.registers.rax = counter & 0xffff_ffff;
                after.registers.rdx = counter >> 32;
                after.registers.rcx = u64::from(aux);
            }
            (Effect::Selected(Selected::Syscall), Reply::GetId(value)) => {
                if !matches!(self.registers.rax, 39 | 186) || value == 0 || value > i32::MAX as u32
                {
                    return Err("scripted syscall outside literal getid profile");
                }
                after.registers.rax = u64::from(value);
                after.registers.rcx = after.registers.rip;
                after.registers.r11 = self.registers.eflags;
            }
            _ => return Err("script/class mismatch"),
        }
        Ok(after)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Row {
    pub(super) selected: Selected,
    pub(super) bytes: Vec<u8>,
    pub(super) before: State,
    pub(super) after: State,
    pub(super) reply: Reply,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Trace {
    pub(super) rows: Vec<Row>,
    pub(super) ordinary: Vec<(u64, State)>,
    pub(super) blocks: Vec<u64>,
}
pub(super) fn checked_decode(fixture: &Fixture, pc: u64) -> Result<Instruction, &'static str> {
    if !fixture.heads.contains(&pc) {
        return Err("PC not in exact declared head census");
    }
    decode(pc, fixture.bytes_at(pc).ok_or("PC outside original image")?)
}
pub(super) fn interpret(
    fixture: &Fixture,
    initial: State,
    replies: &[Reply],
    budget: usize,
) -> Result<Trace, &'static str> {
    if replies.is_empty() {
        return Err("empty scripted trajectory");
    }
    let mut state = initial;
    let mut trace = Trace {
        rows: Vec::new(),
        ordinary: Vec::new(),
        blocks: Vec::new(),
    };
    for _ in 0..budget {
        let pc = state.registers.rip;
        if fixture.blocks.contains(&pc) {
            trace.blocks.push(pc);
        }
        let instruction = checked_decode(fixture, pc)?;
        if let Effect::Selected(selected) = instruction.effect {
            let reply = replies[trace.rows.len()];
            let after = state.selected(instruction, reply)?;
            let bytes = fixture.bytes_at(pc).ok_or("PC outside image")?[..instruction.len].to_vec();
            trace.rows.push(Row {
                selected,
                bytes,
                before: state,
                after: after.clone(),
                reply,
            });
            state = after;
            if trace.rows.len() == replies.len() {
                return Ok(trace);
            }
        } else {
            state = state.ordinary(instruction, fixture)?;
            trace.ordinary.push((pc, state.clone()));
        }
    }
    Err("strict fixture instruction budget exhausted")
}
