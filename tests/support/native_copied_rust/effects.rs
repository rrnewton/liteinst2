//! Independent concrete effects of the admitted original instruction stream.
use super::*;
use iced_x86::{Code, Register};
use rust_invoke::{Operand, Operation};
pub(super) fn offset(base: u64, delta: i32) -> u64 {
    if delta < 0 {
        base.checked_sub(u64::from(delta.unsigned_abs())).unwrap()
    } else {
        base.checked_add(delta as u64).unwrap()
    }
}
pub(super) fn register(r: &libc::user_regs_struct, n: Register) -> u64 {
    match n {
        Register::RAX => r.rax,
        Register::RBX => r.rbx,
        Register::RCX => r.rcx,
        Register::RDX => r.rdx,
        Register::RSI => r.rsi,
        Register::RDI => r.rdi,
        Register::RBP => r.rbp,
        Register::RSP => r.rsp,
        Register::R8 => r.r8,
        Register::R9 => r.r9,
        Register::R10 => r.r10,
        Register::R11 => r.r11,
        Register::R12 => r.r12,
        Register::R13 => r.r13,
        Register::R14 => r.r14,
        Register::R15 => r.r15,
        _ => panic!("full GPR only"),
    }
}
fn set(r: &mut libc::user_regs_struct, n: Register, value: u64) {
    *match n {
        Register::RAX => &mut r.rax,
        Register::RBX => &mut r.rbx,
        Register::RCX => &mut r.rcx,
        Register::RDX => &mut r.rdx,
        Register::RSI => &mut r.rsi,
        Register::RDI => &mut r.rdi,
        Register::RBP => &mut r.rbp,
        Register::RSP => &mut r.rsp,
        Register::R8 => &mut r.r8,
        Register::R9 => &mut r.r9,
        Register::R10 => &mut r.r10,
        Register::R11 => &mut r.r11,
        Register::R12 => &mut r.r12,
        Register::R13 => &mut r.r13,
        Register::R14 => &mut r.r14,
        Register::R15 => &mut r.r15,
        _ => panic!("full GPR only"),
    } = value;
}
fn copy(p: &Snapshot) -> Snapshot {
    Snapshot {
        logical_pc: p.logical_pc,
        registers: p.registers,
        xstate: p.xstate.clone(),
        data: p.data.clone(),
        application_stack: p.application_stack.clone(),
    }
}
fn read(p: &Snapshot, operand: Operand, stack: u64) -> u64 {
    match operand {
        Operand::Register(r) => register(&p.registers, r),
        Operand::Memory { base, displacement } => word_at(
            &p.application_stack,
            stack,
            offset(register(&p.registers, base), displacement),
        ),
    }
}
pub(in super::super) fn outer_effect(before: &Snapshot, after: &Snapshot, stack: u64) {
    let mut expected = copy(before);
    let continuation = word_at(&before.application_stack, stack, before.registers.rsp);
    expected.logical_pc = continuation;
    expected.registers.rip = continuation;
    expected.registers.rsp = before.registers.rsp.checked_add(8).unwrap();
    assert_eq!(
        (after.logical_pc, after.registers.rip),
        (continuation, continuation)
    );
    assert_state(&expected, after);
}
pub(in super::super) fn caller_effects(points: &[Snapshot], ready: &Ready, data: u64, stack: u64) {
    caller_effects_view(points, ready.view(), data, stack);
}
pub(in super::super) fn caller_effects_view(
    points: &[Snapshot],
    ready: CallerView<'_>,
    data: u64,
    stack: u64,
) {
    let seen: Vec<_> = points
        .iter()
        .filter_map(|p| {
            p.logical_pc
                .checked_sub(ready.caller)
                .filter(|o| ready.plan.heads().contains(o))
        })
        .collect();
    assert_eq!(
        seen,
        ready.plan.heads(),
        "complete admitted caller heads exactly once"
    );
    for pair in points.windows(2) {
        if pair[0]
            .logical_pc
            .checked_sub(ready.caller)
            .is_some_and(|o| ready.plan.heads().contains(&o))
        {
            step_view(&pair[0], &pair[1], ready, data, stack);
        }
    }
}
pub(super) fn step(before: &Snapshot, after: &Snapshot, ready: &Ready, data: u64, stack: u64) {
    step_view(before, after, ready.view(), data, stack);
}
fn step_view(before: &Snapshot, after: &Snapshot, ready: CallerView<'_>, data: u64, stack: u64) {
    let at = before.logical_pc.checked_sub(ready.caller).unwrap();
    let s = ready.plan.steps().iter().find(|s| s.offset == at).unwrap();
    let instruction = Decoder::with_ip(
        64,
        &ready.plan.bytes()[at as usize..],
        ready.caller + at,
        DecoderOptions::NONE,
    )
    .decode();
    assert_eq!(instruction.code(), s.code);
    assert_eq!(instruction.len(), usize::from(s.length));
    if s.operation == Operation::Return {
        assert_eq!(s.code, Code::Retnq);
        outer_effect(before, after, stack);
        return;
    }
    let mut expected = copy(before);
    expected.logical_pc = instruction.next_ip();
    match s.operation {
        Operation::Push(n) => {
            assert_eq!(s.code, Code::Push_r64);
            let v = register(&before.registers, n);
            expected.registers.rsp = before.registers.rsp.checked_sub(8).unwrap();
            put_word(
                &mut expected.application_stack,
                stack,
                expected.registers.rsp,
                v,
            );
        }
        Operation::Pop(n) => {
            assert_eq!(s.code, Code::Pop_r64);
            let v = word_at(&before.application_stack, stack, before.registers.rsp);
            set(&mut expected.registers, n, v);
            expected.registers.rsp = before.registers.rsp.checked_add(8).unwrap();
        }
        Operation::Move {
            destination,
            source,
        } => {
            assert!(matches!(s.code, Code::Mov_r64_rm64 | Code::Mov_rm64_r64));
            let v = read(before, source, stack);
            match destination {
                Operand::Register(n) => set(&mut expected.registers, n, v),
                Operand::Memory { base, displacement } => {
                    let address = offset(register(&before.registers, base), displacement);
                    if at == ready.plan.continuations()[0] {
                        assert_eq!(source, Operand::Register(Register::RAX));
                        assert_eq!(address, data + RESULTS as u64);
                        put_word(&mut expected.data, data, address, v);
                    } else {
                        put_word(&mut expected.application_stack, stack, address, v);
                    }
                }
            }
        }
        Operation::Lea {
            destination,
            base,
            displacement,
        } => {
            assert_eq!(s.code, Code::Lea_r64_m);
            set(
                &mut expected.registers,
                destination,
                offset(register(&before.registers, base), displacement),
            );
        }
        Operation::AdjustStack { delta } => {
            let sub = matches!(s.code, Code::Sub_rm64_imm8 | Code::Sub_rm64_imm32);
            assert!(sub || matches!(s.code, Code::Add_rm64_imm8 | Code::Add_rm64_imm32));
            assert!(if sub { delta < 0 } else { delta > 0 });
            expected.registers.eflags = arithmetic_flags(
                before.registers.eflags,
                before.registers.rsp,
                u64::from(delta.unsigned_abs()),
                sub,
            );
            expected.registers.rsp = offset(before.registers.rsp, delta);
        }
        Operation::Call { target } => {
            assert_eq!(s.code, Code::Call_rm64);
            assert_eq!(at, ready.plan.calls()[0]);
            assert_eq!(register(&before.registers, target), ready.target().entry);
            expected.registers.rsp = before.registers.rsp.checked_sub(8).unwrap();
            put_word(
                &mut expected.application_stack,
                stack,
                expected.registers.rsp,
                instruction.next_ip(),
            );
            expected.logical_pc = ready.target().entry;
        }
        Operation::Return => unreachable!(),
    }
    expected.registers.rip = expected.logical_pc;
    assert_eq!(
        (after.logical_pc, after.registers.rip),
        (expected.logical_pc, expected.logical_pc)
    );
    assert_state(&expected, after);
}
