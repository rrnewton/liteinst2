//! Independent effects of the original bounded digit/space scanner only.
//! This does not admit SDK code, compare candidate state, or authenticate owners.
use super::super::{DEBUGGER_FLAGS, MAX_STEPS};
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, OpAccess,
    OpKind, Register,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Digits,
    Spaces,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Case(usize);
pub const CASES: [Case; 8] = [
    Case(0),
    Case(1),
    Case(2),
    Case(3),
    Case(4),
    Case(5),
    Case(6),
    Case(7),
];
impl Case {
    pub fn new(index: usize) -> Self {
        assert!(index < CASES.len());
        Self(index)
    }
    pub fn index(self) -> usize {
        self.0
    }
    pub fn bound(self) -> usize {
        [0, 5, 1, 1, 10, 64, 64, 64][self.0]
    }
    pub fn input(self) -> [u8; 64] {
        let mut bytes = [0xa7; 64];
        match self.0 {
            0 => {}
            1 => bytes[..5].copy_from_slice(b"/09: "),
            2 => bytes[0] = b' ',
            3 => bytes[0] = b'/',
            4 => {
                bytes[..10].copy_from_slice(&[0, 0x1f, 0x20, 0x21, 9, 0x2f, 0x30, 0x39, 0x3a, 0xff])
            }
            5 => bytes.fill(b'9'),
            6 => bytes.fill(b' '),
            7 => {
                for pair in bytes.chunks_exact_mut(2) {
                    pair.copy_from_slice(b"0 ");
                }
            }
            _ => unreachable!(),
        }
        bytes
    }
    pub fn expected(self, operation: Operation) -> u64 {
        match operation {
            Operation::Digits => [0, 2, 0, 0, 2, 64, 0, 32][self.0],
            Operation::Spaces => [0, 1, 1, 0, 1, 0, 64, 32][self.0],
        }
    }
}
pub fn scalar(operation: Operation, input: &[u8]) -> u64 {
    assert!(input.len() <= 64);
    input
        .iter()
        .filter(|&&b| match operation {
            Operation::Digits => b.is_ascii_digit(),
            Operation::Spaces => b == b' ',
        })
        .count() as u64
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Coverage {
    pub heads: BTreeSet<u64>,
    pub edges: BTreeSet<(u64, u64)>,
    pub returns: BTreeSet<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    code: Vec<u8>,
    heads: Vec<u64>,
    codes: Vec<(u64, Code)>,
    declared: Coverage,
    padding: BTreeSet<u64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Move,
    ZeroExtend,
    Lea,
    Add,
    Sub,
    And,
    Or,
    Xor,
    Cmp,
    Test,
    Inc,
    Dec,
    Nop,
    Branch(u8),
    Jump,
    Return,
}

// Exhaustive frozen Code list: mnemonic similarity never grants an effect.
fn kind(code: Code) -> Kind {
    match code {
        Code::Mov_rm8_r8
        | Code::Mov_rm16_r16
        | Code::Mov_rm32_r32
        | Code::Mov_rm64_r64
        | Code::Mov_r8_rm8
        | Code::Mov_r16_rm16
        | Code::Mov_r32_rm32
        | Code::Mov_r64_rm64
        | Code::Mov_r8_imm8
        | Code::Mov_r16_imm16
        | Code::Mov_r32_imm32
        | Code::Mov_r64_imm64
        | Code::Mov_rm8_imm8
        | Code::Mov_rm16_imm16
        | Code::Mov_rm32_imm32
        | Code::Mov_rm64_imm32 => Kind::Move,
        Code::Movzx_r16_rm8
        | Code::Movzx_r32_rm8
        | Code::Movzx_r64_rm8
        | Code::Movzx_r32_rm16
        | Code::Movzx_r64_rm16 => Kind::ZeroExtend,
        Code::Lea_r16_m | Code::Lea_r32_m | Code::Lea_r64_m => Kind::Lea,
        Code::Add_rm8_r8
        | Code::Add_rm16_r16
        | Code::Add_rm32_r32
        | Code::Add_rm64_r64
        | Code::Add_r8_rm8
        | Code::Add_r16_rm16
        | Code::Add_r32_rm32
        | Code::Add_r64_rm64
        | Code::Add_AL_imm8
        | Code::Add_AX_imm16
        | Code::Add_EAX_imm32
        | Code::Add_RAX_imm32
        | Code::Add_rm8_imm8
        | Code::Add_rm16_imm16
        | Code::Add_rm32_imm32
        | Code::Add_rm64_imm32
        | Code::Add_rm16_imm8
        | Code::Add_rm32_imm8
        | Code::Add_rm64_imm8 => Kind::Add,
        Code::Sub_rm8_r8
        | Code::Sub_rm16_r16
        | Code::Sub_rm32_r32
        | Code::Sub_rm64_r64
        | Code::Sub_r8_rm8
        | Code::Sub_r16_rm16
        | Code::Sub_r32_rm32
        | Code::Sub_r64_rm64
        | Code::Sub_AL_imm8
        | Code::Sub_AX_imm16
        | Code::Sub_EAX_imm32
        | Code::Sub_RAX_imm32
        | Code::Sub_rm8_imm8
        | Code::Sub_rm16_imm16
        | Code::Sub_rm32_imm32
        | Code::Sub_rm64_imm32
        | Code::Sub_rm16_imm8
        | Code::Sub_rm32_imm8
        | Code::Sub_rm64_imm8 => Kind::Sub,
        Code::And_rm8_r8
        | Code::And_rm16_r16
        | Code::And_rm32_r32
        | Code::And_rm64_r64
        | Code::And_r8_rm8
        | Code::And_r16_rm16
        | Code::And_r32_rm32
        | Code::And_r64_rm64
        | Code::And_AL_imm8
        | Code::And_AX_imm16
        | Code::And_EAX_imm32
        | Code::And_RAX_imm32
        | Code::And_rm8_imm8
        | Code::And_rm16_imm16
        | Code::And_rm32_imm32
        | Code::And_rm64_imm32
        | Code::And_rm16_imm8
        | Code::And_rm32_imm8
        | Code::And_rm64_imm8 => Kind::And,
        Code::Or_rm8_r8
        | Code::Or_rm16_r16
        | Code::Or_rm32_r32
        | Code::Or_rm64_r64
        | Code::Or_r8_rm8
        | Code::Or_r16_rm16
        | Code::Or_r32_rm32
        | Code::Or_r64_rm64
        | Code::Or_AL_imm8
        | Code::Or_AX_imm16
        | Code::Or_EAX_imm32
        | Code::Or_RAX_imm32
        | Code::Or_rm8_imm8
        | Code::Or_rm16_imm16
        | Code::Or_rm32_imm32
        | Code::Or_rm64_imm32
        | Code::Or_rm16_imm8
        | Code::Or_rm32_imm8
        | Code::Or_rm64_imm8 => Kind::Or,
        Code::Xor_rm8_r8
        | Code::Xor_rm16_r16
        | Code::Xor_rm32_r32
        | Code::Xor_rm64_r64
        | Code::Xor_r8_rm8
        | Code::Xor_r16_rm16
        | Code::Xor_r32_rm32
        | Code::Xor_r64_rm64
        | Code::Xor_AL_imm8
        | Code::Xor_AX_imm16
        | Code::Xor_EAX_imm32
        | Code::Xor_RAX_imm32
        | Code::Xor_rm8_imm8
        | Code::Xor_rm16_imm16
        | Code::Xor_rm32_imm32
        | Code::Xor_rm64_imm32
        | Code::Xor_rm16_imm8
        | Code::Xor_rm32_imm8
        | Code::Xor_rm64_imm8 => Kind::Xor,
        Code::Cmp_rm8_r8
        | Code::Cmp_rm16_r16
        | Code::Cmp_rm32_r32
        | Code::Cmp_rm64_r64
        | Code::Cmp_r8_rm8
        | Code::Cmp_r16_rm16
        | Code::Cmp_r32_rm32
        | Code::Cmp_r64_rm64
        | Code::Cmp_AL_imm8
        | Code::Cmp_AX_imm16
        | Code::Cmp_EAX_imm32
        | Code::Cmp_RAX_imm32
        | Code::Cmp_rm8_imm8
        | Code::Cmp_rm16_imm16
        | Code::Cmp_rm32_imm32
        | Code::Cmp_rm64_imm32
        | Code::Cmp_rm16_imm8
        | Code::Cmp_rm32_imm8
        | Code::Cmp_rm64_imm8 => Kind::Cmp,
        Code::Test_rm8_r8
        | Code::Test_rm16_r16
        | Code::Test_rm32_r32
        | Code::Test_rm64_r64
        | Code::Test_AL_imm8
        | Code::Test_AX_imm16
        | Code::Test_EAX_imm32
        | Code::Test_RAX_imm32
        | Code::Test_rm8_imm8
        | Code::Test_rm16_imm16
        | Code::Test_rm32_imm32
        | Code::Test_rm64_imm32 => Kind::Test,
        Code::Inc_rm8 | Code::Inc_rm16 | Code::Inc_rm32 | Code::Inc_rm64 => Kind::Inc,
        Code::Dec_rm8 | Code::Dec_rm16 | Code::Dec_rm32 | Code::Dec_rm64 => Kind::Dec,
        Code::Nopw | Code::Nopd | Code::Nopq | Code::Nop_rm16 | Code::Nop_rm32 | Code::Nop_rm64 => {
            Kind::Nop
        }
        Code::Jo_rel8_64 | Code::Jo_rel32_64 => Kind::Branch(0),
        Code::Jno_rel8_64 | Code::Jno_rel32_64 => Kind::Branch(1),
        Code::Jb_rel8_64 | Code::Jb_rel32_64 => Kind::Branch(2),
        Code::Jae_rel8_64 | Code::Jae_rel32_64 => Kind::Branch(3),
        Code::Je_rel8_64 | Code::Je_rel32_64 => Kind::Branch(4),
        Code::Jne_rel8_64 | Code::Jne_rel32_64 => Kind::Branch(5),
        Code::Jbe_rel8_64 | Code::Jbe_rel32_64 => Kind::Branch(6),
        Code::Ja_rel8_64 | Code::Ja_rel32_64 => Kind::Branch(7),
        Code::Js_rel8_64 | Code::Js_rel32_64 => Kind::Branch(8),
        Code::Jns_rel8_64 | Code::Jns_rel32_64 => Kind::Branch(9),
        Code::Jp_rel8_64 | Code::Jp_rel32_64 => Kind::Branch(10),
        Code::Jnp_rel8_64 | Code::Jnp_rel32_64 => Kind::Branch(11),
        Code::Jl_rel8_64 | Code::Jl_rel32_64 => Kind::Branch(12),
        Code::Jge_rel8_64 | Code::Jge_rel32_64 => Kind::Branch(13),
        Code::Jle_rel8_64 | Code::Jle_rel32_64 => Kind::Branch(14),
        Code::Jg_rel8_64 | Code::Jg_rel32_64 => Kind::Branch(15),
        Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => Kind::Jump,
        Code::Retnq => Kind::Return,
        _ => panic!("unsupported scanner Code"),
    }
}
fn gpr(r: Register) -> bool {
    r.is_gpr()
        && matches!(
            r.full_register(),
            Register::RAX
                | Register::RCX
                | Register::RDX
                | Register::RSI
                | Register::RDI
                | Register::R8
                | Register::R9
                | Register::R10
                | Register::R11
        )
}
fn width(r: Register) -> usize {
    assert!(gpr(r));
    if r.is_gpr8() {
        1
    } else if r.is_gpr16() {
        2
    } else if r.is_gpr32() {
        4
    } else {
        assert!(r.is_gpr64());
        8
    }
}
fn memory_form(i: &Instruction) {
    assert!(i.memory_base().is_gpr64() && gpr(i.memory_base()));
    assert!(
        i.memory_index() == Register::None
            || (i.memory_index().is_gpr64() && gpr(i.memory_index()))
    );
    assert!(matches!(i.memory_index_scale(), 1 | 2 | 4 | 8));
}
fn immediate(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}
fn operand_width(i: &Instruction, n: u32) -> usize {
    match i.op_kind(n) {
        OpKind::Register => width(i.op_register(n)),
        OpKind::Memory => {
            let w = i.memory_size().size();
            assert!(matches!(w, 1 | 2 | 4 | 8));
            w
        }
        _ => panic!("operand has no scalar width"),
    }
}
fn validate(i: &Instruction, raw: &[u8]) -> Kind {
    assert!(!i.is_invalid() && !i.is_privileged());
    assert!(!i.has_lock_prefix() && !i.has_rep_prefix() && !i.has_repne_prefix());
    assert_eq!(i.segment_prefix(), Register::None);
    let k = kind(i.code());
    match k {
        Kind::Return => {
            assert_eq!(raw, [0xc3]);
            assert_eq!(i.op_count(), 0);
            assert_eq!(i.flow_control(), FlowControl::Return);
            return k;
        }
        Kind::Branch(_) | Kind::Jump => {
            assert!(match k {
                Kind::Branch(_) =>
                    matches!(raw, [0x70..=0x7f, _] | [0x0f, 0x80..=0x8f, _, _, _, _]),
                _ => matches!(raw, [0xeb, _] | [0xe9, _, _, _, _]),
            });
            assert_eq!(
                i.flow_control(),
                if k == Kind::Jump {
                    FlowControl::UnconditionalBranch
                } else {
                    FlowControl::ConditionalBranch
                }
            );
            assert_eq!(i.op_count(), 1);
            assert_eq!(i.op_kind(0), OpKind::NearBranch64);
            assert_ne!(i.near_branch_target(), i.ip());
            return k;
        }
        _ => {}
    }
    assert_eq!(i.flow_control(), FlowControl::Next);
    // Exactly one optional operand-size prefix followed by one optional REX.
    let mut at = usize::from(raw.first() == Some(&0x66));
    if raw.get(at).is_some_and(|b| (0x40..=0x4f).contains(b)) {
        at += 1;
    }
    let opcode = *raw.get(at).unwrap();
    assert!(!matches!(
        opcode,
        0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0x40..=0x4f | 0xf0 | 0xf2 | 0xf3
    ));
    let expected_count = match k {
        Kind::Inc | Kind::Dec => 1,
        Kind::Nop if matches!(i.code(), Code::Nopw | Code::Nopd | Code::Nopq) => 0,
        Kind::Nop => 1,
        _ => 2,
    };
    assert_eq!(i.op_count(), expected_count);
    let mut memory = 0;
    for n in 0..i.op_count() {
        match i.op_kind(n) {
            OpKind::Register => assert!(gpr(i.op_register(n))),
            OpKind::Memory => {
                memory += 1;
                memory_form(i);
                assert!(n != 0 || matches!(k, Kind::Cmp | Kind::Test | Kind::Nop));
            }
            op if immediate(op) => assert_eq!(n, 1),
            _ => panic!("unsupported scanner operand"),
        }
    }
    assert!(memory <= 1);
    if !matches!(k, Kind::Cmp | Kind::Test | Kind::Nop) {
        assert_eq!(i.op_kind(0), OpKind::Register);
    }
    if k == Kind::Lea {
        assert_eq!(i.op_kind(1), OpKind::Memory);
    } else if !matches!(k, Kind::Nop | Kind::Inc | Kind::Dec) && !immediate(i.op_kind(1)) {
        let a = operand_width(i, 0);
        let b = operand_width(i, 1);
        if k == Kind::ZeroExtend {
            assert!(b < a && matches!(b, 1 | 2));
        } else {
            assert_eq!(a, b);
        }
    }
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(i);
    if memory == 0 || matches!(k, Kind::Lea | Kind::Nop) {
        assert!(info.used_memory().is_empty(), "no hidden memory access");
    } else {
        assert_eq!(info.used_memory().len(), 1);
        assert_eq!(info.used_memory()[0].access(), OpAccess::Read);
        assert!(matches!(i.memory_size().size(), 1 | 2 | 4 | 8));
    }
    k
}
impl Plan {
    pub fn decode(code: &[u8]) -> Self {
        assert!((5..=256).contains(&code.len()));
        let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
        let mut instructions = BTreeMap::new();
        while decoder.can_decode() {
            let i = decoder.decode();
            assert!(i.next_ip() <= code.len() as u64);
            let k = validate(&i, &code[i.ip() as usize..i.next_ip() as usize]);
            assert!(instructions.insert(i.ip(), (i, k)).is_none());
        }
        assert_eq!(decoder.position(), code.len());
        assert!(!instructions.is_empty() && instructions.len() <= 256);
        let mut next = BTreeMap::new();
        let mut leaders = BTreeSet::from([0]);
        for (&pc, (i, k)) in &instructions {
            let mut successors = BTreeSet::new();
            match k {
                Kind::Return => {}
                Kind::Branch(_) | Kind::Jump => {
                    successors.insert(i.near_branch_target());
                    leaders.insert(i.near_branch_target());
                    if *k != Kind::Jump {
                        successors.insert(i.next_ip());
                        leaders.insert(i.next_ip());
                    }
                }
                _ => {
                    successors.insert(i.next_ip());
                }
            }
            assert!(
                successors.iter().all(|p| instructions.contains_key(p)),
                "complete internal successors"
            );
            next.insert(pc, successors);
        }
        let mut declared = Coverage::default();
        let mut pending = vec![0];
        while let Some(pc) = pending.pop() {
            if declared.heads.insert(pc) {
                if instructions[&pc].1 == Kind::Return {
                    declared.returns.insert(pc);
                }
                for &to in &next[&pc] {
                    declared.edges.insert((pc, to));
                    pending.push(to);
                }
            }
        }
        assert!((1..=4).contains(&declared.returns.len()));
        let mut reaches_ret = declared.returns.clone();
        for _ in 0..instructions.len() {
            for &(from, to) in &declared.edges {
                if reaches_ret.contains(&to) {
                    reaches_ret.insert(from);
                }
            }
        }
        assert_eq!(
            reaches_ret, declared.heads,
            "every reachable head has a path to RET"
        );
        let mut padding = BTreeSet::new();
        let mut blocks = 0;
        let mut block_start = true;
        for (&pc, (i, k)) in &instructions {
            if !declared.heads.contains(&pc) {
                assert_eq!(*k, Kind::Nop, "only unreachable NOP padding");
                padding.insert(pc);
                block_start = true;
                continue;
            }
            if block_start || leaders.contains(&pc) {
                blocks += 1;
            }
            block_start = i.flow_control() != FlowControl::Next;
        }
        assert!(blocks <= 32);
        Self {
            code: code.to_vec(),
            heads: instructions.keys().copied().collect(),
            codes: instructions
                .iter()
                .map(|(&p, (i, _))| (p, i.code()))
                .collect(),
            declared,
            padding,
        }
    }
    pub fn code(&self) -> &[u8] {
        &self.code
    }
    pub fn heads(&self) -> &[u64] {
        &self.heads
    }
    pub fn declared(&self) -> &Coverage {
        &self.declared
    }
    pub fn padding(&self) -> &BTreeSet<u64> {
        &self.padding
    }
    pub fn codes(&self) -> &[(u64, Code)] {
        &self.codes
    }
}

#[derive(Clone, Copy)]
pub struct State<'a> {
    pub registers: &'a libc::user_regs_struct,
    pub xstate: &'a [u8],
    pub data: &'a [u8],
    pub stack: &'a [u8],
}
#[derive(Clone, Copy)]
pub struct Step<'a> {
    pub before: State<'a>,
    pub after: State<'a>,
}
pub struct Observation<'a> {
    pub entry: u64,
    pub continuation: u64,
    pub input_address: u64,
    pub data_address: u64,
    pub stack_address: u64,
    pub code: &'a [u8],
    pub input: &'a [u8],
    pub steps: &'a [Step<'a>],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Read {
    pub at: u64,
    pub address: u64,
    pub width: usize,
}
#[derive(Clone, Debug)]
pub struct Trace {
    entry: u64,
    code: Vec<u8>,
    visits: usize,
    ret_offset: u64,
    value: u64,
    reads: Vec<Read>,
    input_bytes: usize,
    input_offsets: BTreeSet<usize>,
    observed: Coverage,
    declared: Coverage,
    effect_heads: BTreeSet<u64>,
    effects_checked: usize,
    undefined_flag_heads: BTreeSet<u64>,
}
impl Trace {
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn code(&self) -> &[u8] {
        &self.code
    }
    pub fn visits(&self) -> usize {
        self.visits
    }
    pub fn ret_offset(&self) -> u64 {
        self.ret_offset
    }
    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn input_reads(&self) -> usize {
        self.reads.len()
    }
    pub fn input_bytes(&self) -> usize {
        self.input_bytes
    }
    pub fn reads(&self) -> &[Read] {
        &self.reads
    }
    pub fn input_offsets(&self) -> &BTreeSet<usize> {
        &self.input_offsets
    }
    pub fn observed(&self) -> &Coverage {
        &self.observed
    }
    pub fn declared(&self) -> &Coverage {
        &self.declared
    }
    pub fn effect_heads(&self) -> &BTreeSet<u64> {
        &self.effect_heads
    }
    pub fn effects_checked(&self) -> usize {
        self.effects_checked
    }
    pub fn undefined_flag_heads(&self) -> &BTreeSet<u64> {
        &self.undefined_flag_heads
    }
}
fn bytes_at(bytes: &[u8], base: u64, address: u64, width: usize) -> &[u8] {
    let at = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    &bytes[at..at.checked_add(width).unwrap()]
}
fn mask(width: usize) -> u64 {
    assert!(matches!(width, 1 | 2 | 4 | 8));
    if width == 8 {
        u64::MAX
    } else {
        (1u64 << (width * 8)) - 1
    }
}
fn full(r: &libc::user_regs_struct, n: Register) -> u64 {
    match n {
        Register::None => 0,
        Register::RAX => r.rax,
        Register::RCX => r.rcx,
        Register::RDX => r.rdx,
        Register::RSI => r.rsi,
        Register::RDI => r.rdi,
        Register::R8 => r.r8,
        Register::R9 => r.r9,
        Register::R10 => r.r10,
        Register::R11 => r.r11,
        _ => panic!("nonadmitted scanner register"),
    }
}
fn shift(n: Register) -> usize {
    if matches!(n, Register::AH | Register::CH | Register::DH) {
        8
    } else {
        0
    }
}
fn register(r: &libc::user_regs_struct, n: Register) -> u64 {
    (full(r, n.full_register()) >> shift(n)) & mask(width(n))
}
fn set(r: &mut libc::user_regs_struct, n: Register, value: u64) {
    let w = width(n);
    let old = full(r, n.full_register());
    let m = mask(w);
    let value = if w >= 4 {
        value & m
    } else {
        (old & !(m << shift(n))) | ((value & m) << shift(n))
    };
    *match n.full_register() {
        Register::RAX => &mut r.rax,
        Register::RCX => &mut r.rcx,
        Register::RDX => &mut r.rdx,
        Register::RSI => &mut r.rsi,
        Register::RDI => &mut r.rdi,
        Register::R8 => &mut r.r8,
        Register::R9 => &mut r.r9,
        Register::R10 => &mut r.r10,
        Register::R11 => &mut r.r11,
        _ => unreachable!(),
    } = value;
}
fn address(i: &Instruction, r: &libc::user_regs_struct) -> u64 {
    full(r, i.memory_base())
        .wrapping_add(full(r, i.memory_index()).wrapping_mul(u64::from(i.memory_index_scale())))
        .wrapping_add(i.memory_displacement64())
}
#[derive(Clone, Copy)]
struct Domain {
    input: u64,
    bound: usize,
    data: u64,
    stack: u64,
    continuation: u64,
}
fn input_read(i: &Instruction, k: Kind, before: State<'_>, domain: Domain) -> Option<(u64, usize)> {
    if matches!(k, Kind::Lea | Kind::Nop | Kind::Return)
        || !(0..i.op_count()).any(|n| i.op_kind(n) == OpKind::Memory)
    {
        return None;
    }
    let a = address(i, before.registers);
    let w = i.memory_size().size();
    assert!(matches!(w, 1 | 2 | 4 | 8));
    assert!(
        domain.input <= a
            && a.checked_add(w as u64).unwrap()
                <= domain.input.checked_add(domain.bound as u64).unwrap(),
        "complete input read range"
    );
    let _ = bytes_at(before.data, domain.data, a, w);
    Some((a, w))
}
fn operand(i: &Instruction, n: u32, before: State<'_>, domain: Domain) -> u64 {
    match i.op_kind(n) {
        OpKind::Register => register(before.registers, i.op_register(n)),
        OpKind::Memory => {
            let bytes = bytes_at(
                before.data,
                domain.data,
                address(i, before.registers),
                i.memory_size().size(),
            );
            let mut word = [0u8; 8];
            word[..bytes.len()].copy_from_slice(bytes);
            u64::from_le_bytes(word)
        }
        OpKind::Immediate8 => u64::from(i.immediate8()),
        OpKind::Immediate16 => u64::from(i.immediate16()),
        OpKind::Immediate32 => u64::from(i.immediate32()),
        OpKind::Immediate64 => i.immediate64(),
        OpKind::Immediate8to16 => i.immediate8to16() as u16 as u64,
        OpKind::Immediate8to32 => i.immediate8to32() as u32 as u64,
        OpKind::Immediate8to64 => i.immediate8to64() as u64,
        OpKind::Immediate32to64 => i.immediate32to64() as u64,
        _ => panic!("unsupported effect operand"),
    }
}
const CF: u64 = 1;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;
const ARITHMETIC: u64 = CF | PF | AF | ZF | SF | OF;
fn common_flags(value: u64, width: usize) -> u64 {
    let sign = 1u64 << (width * 8 - 1);
    (u64::from((value as u8).count_ones() % 2 == 0) * PF)
        | (u64::from(value == 0) * ZF)
        | (u64::from(value & sign != 0) * SF)
}
fn arithmetic(old: u64, a: u64, b: u64, w: usize, subtract: bool, preserve_cf: bool) -> (u64, u64) {
    let m = mask(w);
    let a = a & m;
    let b = b & m;
    let result = (if subtract {
        a.wrapping_sub(b)
    } else {
        a.wrapping_add(b)
    }) & m;
    let sign = 1u64 << (w * 8 - 1);
    let carry = if subtract {
        a < b
    } else {
        u128::from(a) + u128::from(b) > u128::from(m)
    };
    let overflow = if subtract {
        (a ^ b) & (a ^ result) & sign != 0
    } else {
        !(a ^ b) & (a ^ result) & sign != 0
    };
    let changed = if preserve_cf {
        ARITHMETIC & !CF
    } else {
        ARITHMETIC
    };
    let flags = common_flags(result, w)
        | (u64::from(carry) * CF)
        | ((a ^ b ^ result) & AF)
        | (u64::from(overflow) * OF);
    (result, (old & !changed) | (flags & changed))
}
fn condition(n: u8, flags: u64) -> bool {
    let c = flags & CF != 0;
    let p = flags & PF != 0;
    let z = flags & ZF != 0;
    let s = flags & SF != 0;
    let o = flags & OF != 0;
    match n {
        0 => o,
        1 => !o,
        2 => c,
        3 => !c,
        4 => z,
        5 => !z,
        6 => c || z,
        7 => !c && !z,
        8 => s,
        9 => !s,
        10 => p,
        11 => !p,
        12 => s != o,
        13 => s == o,
        14 => z || s != o,
        15 => !z && s == o,
        _ => unreachable!(),
    }
}
fn registers_equal(
    expected: &libc::user_regs_struct,
    actual: &libc::user_regs_struct,
    ignored_flags: u64,
) {
    macro_rules! same { ($($field:ident),+ $(,)?) => { $(assert_eq!(expected.$field, actual.$field, stringify!($field));)+ }; }
    same!(
        rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15, rip,
        orig_rax, cs, ss, ds, es, fs, gs, fs_base, gs_base
    );
    assert_eq!(
        expected.eflags & !ignored_flags,
        actual.eflags & !ignored_flags,
        "flags"
    );
}
fn unchanged_memory(before: State<'_>, after: State<'_>) {
    assert_eq!(before.xstate, after.xstate, "full XSAVE");
    assert_eq!(before.data, after.data, "full data page");
    assert_eq!(before.stack, after.stack, "full protected stack");
}
// Returns actual input-read facts and whether logical AF is undefined. This
// exception applies only to this independent prediction, never assert_state.
fn effect(
    i: &Instruction,
    k: Kind,
    step: Step<'_>,
    domain: Domain,
) -> (Option<(u64, usize)>, bool) {
    let before = step.before;
    let mut expected = *before.registers;
    assert_eq!(expected.rip, i.ip());
    expected.rip = i.next_ip();
    let read = input_read(i, k, before, domain);
    let mut undefined_af = false;
    match k {
        Kind::Move | Kind::ZeroExtend => set(
            &mut expected,
            i.op_register(0),
            operand(i, 1, before, domain),
        ),
        Kind::Lea => set(
            &mut expected,
            i.op_register(0),
            address(i, before.registers),
        ),
        Kind::Add | Kind::Sub | Kind::Cmp | Kind::Inc | Kind::Dec => {
            let a = operand(i, 0, before, domain);
            let unary = matches!(k, Kind::Inc | Kind::Dec);
            let b = if unary {
                1
            } else {
                operand(i, 1, before, domain)
            };
            let (value, flags) = arithmetic(
                expected.eflags,
                a,
                b,
                operand_width(i, 0),
                matches!(k, Kind::Sub | Kind::Cmp | Kind::Dec),
                unary,
            );
            expected.eflags = flags;
            if k != Kind::Cmp {
                set(&mut expected, i.op_register(0), value);
            }
        }
        Kind::And | Kind::Or | Kind::Xor | Kind::Test => {
            let a = operand(i, 0, before, domain);
            let b = operand(i, 1, before, domain);
            let w = operand_width(i, 0);
            let value = (match k {
                Kind::And | Kind::Test => a & b,
                Kind::Or => a | b,
                _ => a ^ b,
            }) & mask(w);
            expected.eflags = (expected.eflags & !(ARITHMETIC & !AF)) | common_flags(value, w);
            undefined_af = true;
            if k != Kind::Test {
                set(&mut expected, i.op_register(0), value);
            }
        }
        Kind::Nop => {}
        Kind::Branch(n) => {
            if condition(n, expected.eflags) {
                expected.rip = i.near_branch_target();
            }
        }
        Kind::Jump => expected.rip = i.near_branch_target(),
        Kind::Return => {
            let word = u64::from_le_bytes(
                bytes_at(before.stack, domain.stack, expected.rsp, 8)
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(word, domain.continuation);
            expected.rip = word;
            expected.rsp = expected.rsp.checked_add(8).unwrap();
        }
    }
    unchanged_memory(before, step.after);
    registers_equal(
        &expected,
        step.after.registers,
        DEBUGGER_FLAGS | if undefined_af { AF } else { 0 },
    );
    (read, undefined_af)
}
pub fn inspect(operation: Operation, case: Case, plan: &Plan, observed: Observation<'_>) -> Trace {
    assert_eq!(plan.code(), observed.code);
    assert!(!observed.steps.is_empty() && observed.steps.len() <= MAX_STEPS);
    assert_ne!(observed.entry, 0);
    let end = observed
        .entry
        .checked_add(observed.code.len() as u64)
        .unwrap();
    assert!(observed.continuation < observed.entry || observed.continuation >= end);
    let first = observed.steps[0].before;
    assert_eq!(first.data.len(), 4096);
    assert!(!first.xstate.is_empty() && !first.stack.is_empty());
    let data_end = observed
        .data_address
        .checked_add(first.data.len() as u64)
        .unwrap();
    let stack_end = observed
        .stack_address
        .checked_add(first.stack.len() as u64)
        .unwrap();
    assert!(data_end <= observed.stack_address || stack_end <= observed.data_address);
    observed.input_address.checked_add(64).unwrap();
    let input = case.input();
    assert_eq!(observed.input, &input[..case.bound()]);
    assert_eq!(
        (
            first.registers.rip,
            first.registers.rdi,
            first.registers.rsi
        ),
        (observed.entry, observed.input_address, case.bound() as u64)
    );
    let rsp = first.registers.rsp;
    assert_eq!(rsp % 16, 8);
    let _ = bytes_at(first.stack, observed.stack_address, rsp, 8);
    let domain = Domain {
        input: observed.input_address,
        bound: case.bound(),
        data: observed.data_address,
        stack: observed.stack_address,
        continuation: observed.continuation,
    };
    let mut trace = Trace {
        entry: observed.entry,
        code: observed.code.to_vec(),
        visits: observed.steps.len(),
        ret_offset: u64::MAX,
        value: u64::MAX,
        reads: Vec::new(),
        input_bytes: 0,
        input_offsets: BTreeSet::new(),
        observed: Coverage::default(),
        declared: plan.declared().clone(),
        effect_heads: BTreeSet::new(),
        effects_checked: 0,
        undefined_flag_heads: BTreeSet::new(),
    };
    for (n, &step) in observed.steps.iter().enumerate() {
        if n > 0 {
            let previous = observed.steps[n - 1].after;
            registers_equal(previous.registers, step.before.registers, 0);
            unchanged_memory(previous, step.before);
        }
        assert_eq!(step.before.registers.rsp, rsp);
        assert_eq!(step.before.data.len(), 4096);
        assert_eq!(
            bytes_at(
                step.before.data,
                observed.data_address,
                observed.input_address,
                64
            ),
            input
        );
        let pc = step
            .before
            .registers
            .rip
            .checked_sub(observed.entry)
            .unwrap();
        assert!(plan.declared.heads.contains(&pc));
        let mut decoder = Decoder::with_ip(
            64,
            &observed.code[pc as usize..],
            step.before.registers.rip,
            DecoderOptions::NONE,
        );
        let i = decoder.decode();
        let raw = &observed.code[pc as usize..pc as usize + i.len()];
        let k = validate(&i, raw);
        assert_eq!(
            i.code(),
            plan.codes[plan.heads.binary_search(&pc).unwrap()].1
        );
        let (read, undefined) = effect(&i, k, step, domain);
        trace.observed.heads.insert(pc);
        trace.effect_heads.insert(pc);
        trace.effects_checked += 1;
        if undefined {
            trace.undefined_flag_heads.insert(pc);
        }
        if let Some((a, w)) = read {
            trace.reads.push(Read {
                at: pc,
                address: a,
                width: w,
            });
            trace.input_bytes = trace.input_bytes.checked_add(w).unwrap();
            let offset = usize::try_from(a.checked_sub(observed.input_address).unwrap()).unwrap();
            trace
                .input_offsets
                .extend(offset..offset.checked_add(w).unwrap());
        }
        if k == Kind::Return {
            assert_eq!(n + 1, observed.steps.len(), "only the final step is RET");
            assert!(trace.declared.returns.contains(&pc));
            trace.observed.returns.insert(pc);
            trace.ret_offset = pc;
            trace.value = step.after.registers.rax;
        } else {
            let to = step
                .after
                .registers
                .rip
                .checked_sub(observed.entry)
                .unwrap();
            assert!(trace.declared.edges.contains(&(pc, to)));
            trace.observed.edges.insert((pc, to));
        }
    }
    assert_eq!(trace.observed.returns.len(), 1);
    assert_eq!(trace.input_offsets, (0..case.bound()).collect());
    if case.bound() == 0 {
        assert_eq!((trace.input_reads(), trace.input_bytes()), (0, 0));
    }
    assert_eq!(trace.value, scalar(operation, observed.input));
    assert_eq!(trace.value, case.expected(operation));
    assert_eq!(trace.effects_checked, trace.visits);
    assert_eq!(trace.effect_heads, trace.observed.heads);
    trace
}

#[cfg(test)]
#[path = "scanner/tests.rs"]
mod tests;
