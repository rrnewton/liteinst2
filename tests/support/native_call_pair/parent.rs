//! Independent original-instruction geometry and concrete effects. This does not
//! consume the frontend admission certificate or relax the pair comparator.
use super::*;
use copied_rust::effects::{copy, offset, read, register, set};
use iced_x86::{Code, Instruction, OpKind, Register};
use rust_invoke::Operand;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Op {
    Push(Register),
    Pop(Register),
    Mov(Operand, Operand),
    Lea(Register, Register, i32),
    Adjust(i32),
    Shift(Register),
    Or(Register, Register),
    Call,
    Ret,
    Nop,
}
#[derive(Clone, Debug)]
pub(super) struct Step {
    pub(super) offset: u64,
    pub(super) code: Code,
    pub(super) len: usize,
    pub(super) op: Op,
}
#[derive(Clone, Debug)]
pub(super) struct Parent {
    pub(super) code: Vec<u8>,
    pub(super) steps: Vec<Step>,
    pub(super) call: u64,
    pub(super) continuation: u64,
    pub(super) delta: u64,
}
fn gpr(r: Register) -> Register {
    assert!(matches!(
        r,
        Register::RAX
            | Register::RBX
            | Register::RCX
            | Register::RDX
            | Register::RDI
            | Register::RSI
            | Register::RBP
            | Register::RSP
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
    ));
    r
}
fn operand(i: &Instruction, n: u32) -> Operand {
    match i.op_kind(n) {
        OpKind::Register => Operand::Register(gpr(i.op_register(n))),
        OpKind::Memory => {
            assert_eq!(i.memory_index(), Register::None);
            assert_eq!(i.memory_index_scale(), 1);
            assert!(!i.is_ip_rel_memory_operand());
            let displacement = i32::try_from(i.memory_displacement64() as i64).unwrap();
            assert!((-64..=64).contains(&displacement));
            Operand::Memory {
                base: gpr(i.memory_base()),
                displacement,
            }
        }
        _ => panic!("parent full-width operand"),
    }
}
fn reg(i: &Instruction, n: u32) -> Register {
    let Operand::Register(r) = operand(i, n) else {
        panic!("parent GPR")
    };
    r
}
fn location(regs: &BTreeMap<Register, i32>, base: Register, displacement: i32, sp: i32) -> i32 {
    let at = regs[&base].checked_add(displacement).unwrap();
    assert!(sp <= at && at < 0 && at % 8 == 0 && at + 8 <= 0);
    at
}
impl Parent {
    pub(super) fn decode(code: &[u8], entry: u64, child: u64) -> Self {
        assert!((5..=80).contains(&code.len()) && entry != 0 && child != 0);
        let end = entry.checked_add(code.len() as u64).unwrap();
        assert!(!(entry..end).contains(&child));
        let mut d = Decoder::with_ip(64, code, entry, DecoderOptions::NONE);
        let mut regs = BTreeMap::from([(Register::RSP, 0i32)]);
        let mut slots = BTreeMap::<i32, Option<i32>>::new();
        let mut sp = 0i32;
        let mut steps = Vec::new();
        let mut call = None;
        while d.can_decode() {
            let i = d.decode();
            assert!(!i.is_invalid() && i.next_ip() <= end);
            let raw = &code[(i.ip() - entry) as usize..(i.next_ip() - entry) as usize];
            assert_eq!(i.segment_prefix(), Register::None);
            assert!(
                !i.has_lock_prefix()
                    && !i.has_rep_prefix()
                    && !i.has_repne_prefix()
                    && !i.is_privileged()
            );
            let prefix = usize::from((0x40..=0x4f).contains(&raw[0]));
            assert!(raw.get(prefix).is_some_and(|b| !matches!(
                *b,
                0x40..=0x4f
                    | 0x66
                    | 0x67
                    | 0xf0
                    | 0xf2
                    | 0xf3
                    | 0x26
                    | 0x2e
                    | 0x36
                    | 0x3e
                    | 0x64
                    | 0x65
            )));
            let mut write_reg = None;
            let op = match i.code() {
                Code::Push_r64 => {
                    let r = reg(&i, 0);
                    assert_ne!(r, Register::RSP);
                    sp -= 8;
                    slots.insert(sp, regs.get(&r).copied());
                    Op::Push(r)
                }
                Code::Pop_r64 => {
                    let r = reg(&i, 0);
                    assert_ne!(r, Register::RSP);
                    write_reg = Some((r, slots.remove(&sp).expect("initialized pop")));
                    sp += 8;
                    Op::Pop(r)
                }
                Code::Mov_r64_rm64 | Code::Mov_rm64_r64 => {
                    let a = operand(&i, 0);
                    let b = operand(&i, 1);
                    let origin = match b {
                        Operand::Register(r) => regs.get(&r).copied(),
                        Operand::Memory { base, displacement } => *slots
                            .get(&location(&regs, base, displacement, sp))
                            .expect("initialized read"),
                    };
                    match a {
                        Operand::Register(r) => write_reg = Some((r, origin)),
                        Operand::Memory { base, displacement } => {
                            slots.insert(location(&regs, base, displacement, sp), origin);
                        }
                    }
                    Op::Mov(a, b)
                }
                Code::Lea_r64_m => {
                    let r = reg(&i, 0);
                    let Operand::Memory { base, displacement } = operand(&i, 1) else {
                        panic!("LEA memory")
                    };
                    let v = regs[&base].checked_add(displacement).unwrap();
                    assert!((-64..=0).contains(&v) && v % 8 == 0);
                    write_reg = Some((r, Some(v)));
                    Op::Lea(r, base, displacement)
                }
                Code::Add_rm64_imm8
                | Code::Add_rm64_imm32
                | Code::Sub_rm64_imm8
                | Code::Sub_rm64_imm32 => {
                    assert_eq!(reg(&i, 0), Register::RSP);
                    let a = match i.op1_kind() {
                        OpKind::Immediate8to64 => i.immediate8to64(),
                        OpKind::Immediate32to64 => i.immediate32to64(),
                        _ => panic!("stack immediate"),
                    };
                    assert!(a > 0 && a <= 64 && a % 8 == 0);
                    let delta = a as i32
                        * if matches!(i.code(), Code::Sub_rm64_imm8 | Code::Sub_rm64_imm32) {
                            -1
                        } else {
                            1
                        };
                    sp += delta;
                    Op::Adjust(delta)
                }
                Code::Shl_rm64_imm8 => {
                    let r = reg(&i, 0);
                    assert!(call.is_some());
                    assert_eq!(i.op1_kind(), OpKind::Immediate8);
                    assert_eq!(i.immediate8(), 32);
                    assert_ne!(r, Register::RSP);
                    write_reg = Some((r, None));
                    Op::Shift(r)
                }
                Code::Or_rm64_r64 | Code::Or_r64_rm64 => {
                    let a = reg(&i, 0);
                    let b = reg(&i, 1);
                    assert!(call.is_some());
                    assert_ne!(a, Register::RSP);
                    write_reg = Some((a, None));
                    Op::Or(a, b)
                }
                Code::Call_rel32_64 => {
                    assert!(call.is_none() && raw.len() == 5 && raw[0] == 0xe8);
                    assert_eq!(i.op0_kind(), OpKind::NearBranch64);
                    assert_eq!(i.near_branch_target(), child);
                    assert_eq!((8 + sp).rem_euclid(16), 0);
                    let delta = u64::try_from(8 - sp).unwrap();
                    assert!([16, 32, 48, 64].contains(&delta));
                    call = Some((i.ip() - entry, i.next_ip() - entry, delta));
                    for r in [
                        Register::RAX,
                        Register::RCX,
                        Register::RDX,
                        Register::RDI,
                        Register::RSI,
                        Register::R8,
                        Register::R9,
                        Register::R10,
                        Register::R11,
                    ] {
                        regs.remove(&r);
                    }
                    Op::Call
                }
                Code::Retnq => {
                    assert!(raw == [0xc3] && i.next_ip() == end && call.is_some() && sp == 0);
                    Op::Ret
                }
                Code::Nopd => {
                    assert_eq!(raw, [0x90]);
                    Op::Nop
                }
                _ => panic!("unsupported independent parent instruction"),
            };
            if let Some((r, v)) = write_reg {
                if r == Register::RSP {
                    sp = v.expect("stack origin");
                }
                if let Some(v) = v {
                    regs.insert(r, v);
                } else {
                    regs.remove(&r);
                }
            }
            assert!((-64..=0).contains(&sp) && sp % 8 == 0);
            regs.insert(Register::RSP, sp);
            slots.retain(|&a, _| a >= sp);
            assert_eq!(
                i.flow_control(),
                match op {
                    Op::Call => FlowControl::Call,
                    Op::Ret => FlowControl::Return,
                    _ => FlowControl::Next,
                }
            );
            if op != Op::Ret {
                assert!(i.next_ip() < end);
            }
            steps.push(Step {
                offset: i.ip() - entry,
                code: i.code(),
                len: i.len(),
                op,
            });
        }
        assert_eq!(d.position(), code.len());
        assert_eq!(steps.last().unwrap().op, Op::Ret);
        let (call, continuation, delta) = call.unwrap();
        Self {
            code: code.to_vec(),
            steps,
            call,
            continuation,
            delta,
        }
    }
    pub(super) fn heads(&self) -> Vec<u64> {
        self.steps.iter().map(|s| s.offset).collect()
    }
    pub(super) fn edges(&self) -> BTreeSet<(u64, u64)> {
        self.steps
            .windows(2)
            .map(|s| (s[0].offset, s[1].offset))
            .collect()
    }
    pub(super) fn ret(&self) -> u64 {
        self.steps.last().unwrap().offset
    }
}
fn szp(value: u64) -> u64 {
    u64::from(value == 0) << 6
        | (value >> 63) << 7
        | u64::from((value as u8).count_ones() % 2 == 0) << 2
}
pub(super) fn effect(
    p: &Parent,
    entry: u64,
    child: u64,
    before: &Snapshot,
    after: &Snapshot,
    stack: u64,
) {
    let at = before.logical_pc.checked_sub(entry).unwrap();
    let s = p.steps.iter().find(|s| s.offset == at).unwrap();
    let i = Decoder::with_ip(64, &p.code[at as usize..], entry + at, DecoderOptions::NONE).decode();
    assert_eq!((i.code(), i.len()), (s.code, s.len));
    let mut e = copy(before);
    e.logical_pc = i.next_ip();
    match s.op {
        Op::Push(r) => {
            let v = register(&before.registers, r);
            e.registers.rsp = e.registers.rsp.checked_sub(8).unwrap();
            put_word(&mut e.application_stack, stack, e.registers.rsp, v);
        }
        Op::Pop(r) => {
            let v = word_at(&before.application_stack, stack, before.registers.rsp);
            set(&mut e.registers, r, v);
            e.registers.rsp = e.registers.rsp.checked_add(8).unwrap();
        }
        Op::Mov(a, b) => {
            let v = read(before, b, stack);
            match a {
                Operand::Register(r) => set(&mut e.registers, r, v),
                Operand::Memory { base, displacement } => {
                    let address = offset(register(&before.registers, base), displacement);
                    put_word(&mut e.application_stack, stack, address, v);
                }
            }
        }
        Op::Lea(r, base, displacement) => set(
            &mut e.registers,
            r,
            offset(register(&before.registers, base), displacement),
        ),
        Op::Adjust(delta) => {
            e.registers.eflags = arithmetic_flags(
                before.registers.eflags,
                before.registers.rsp,
                u64::from(delta.unsigned_abs()),
                delta < 0,
            );
            e.registers.rsp = offset(before.registers.rsp, delta);
        }
        Op::Shift(r) => {
            let v = register(&before.registers, r);
            let result = v << 32;
            set(&mut e.registers, r, result);
            // AF/OF undefined for SHL count32: prediction only. The original vs
            // candidate comparator still compares these flags without exception.
            let undefined = (1 << 4) | (1 << 11);
            let defined = 1 | (1 << 2) | (1 << 6) | (1 << 7);
            e.registers.eflags = (before.registers.eflags & !(defined | undefined))
                | (after.registers.eflags & undefined)
                | szp(result)
                | ((v >> 32) & 1);
        }
        Op::Or(a, b) => {
            let result = register(&before.registers, a) | register(&before.registers, b);
            set(&mut e.registers, a, result);
            let defined = 1 | (1 << 2) | (1 << 6) | (1 << 7) | (1 << 11);
            let undefined = 1 << 4;
            e.registers.eflags = (before.registers.eflags & !(defined | undefined))
                | (after.registers.eflags & undefined)
                | szp(result);
        }
        Op::Call => {
            e.logical_pc = child;
            e.registers.rsp = e.registers.rsp.checked_sub(8).unwrap();
            put_word(
                &mut e.application_stack,
                stack,
                e.registers.rsp,
                i.next_ip(),
            );
        }
        Op::Ret => {
            e.logical_pc = word_at(&before.application_stack, stack, before.registers.rsp);
            e.registers.rsp = e.registers.rsp.checked_add(8).unwrap();
        }
        Op::Nop => {}
    }
    e.registers.rip = e.logical_pc;
    assert_eq!(after.logical_pc, e.logical_pc);
    assert_state(&e, after);
}
