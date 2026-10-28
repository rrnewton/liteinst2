//! Closed private native caller: no Frame/TLS predicates are claimed here.
use super::{Profile, Ready, Snapshot, Tracee, assert_state};

pub const STENCIL: &[u8] = &[
    0x53, 0x49, 0x89, 0xfb, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x41, 0xff, 0xd3, 0x5b, 0xc3,
];
pub const HEADS: &[u64] = &[0, 1, 4, 7, 10, 13, 14];

pub(super) fn arguments(r: &libc::user_regs_struct, ready: &Ready, input: u64, length: usize) {
    assert_eq!(ready.profile, Profile::NativeCall);
    assert_eq!((r.rdi, r.rsi, r.rdx), (ready.entry, input, 1024));
    assert_eq!(length, 1024);
    assert_eq!(r.rip, ready.gate);
    assert_eq!(r.rsp % 16, 8);
}
pub(super) fn callee_saves(before: &libc::user_regs_struct, after: &libc::user_regs_struct) {
    assert_eq!(
        (
            after.rbx, after.rbp, after.r12, after.r13, after.r14, after.r15, after.rsp
        ),
        (
            before.rbx, before.rbp, before.r12, before.r13, before.r14, before.r15, before.rsp
        ),
        "native callee saves restored before harness restoration"
    );
}
fn word(bytes: &[u8], base: u64, address: u64) -> u64 {
    let at = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// Independent literal instruction semantics for every wrapper transition.
/// Full original body semantics are checked separately by call_tree::truth.
pub(super) fn stencil(points: &[Snapshot], gate: u64, root: u64, stack_base: u64) {
    assert_eq!(points.len(), 339);
    assert_eq!(points[0].logical_pc, gate);
    assert_eq!(points[5].logical_pc, root);
    assert_eq!(points[337].logical_pc, gate + 13);
    assert_eq!(points[338].logical_pc, gate + 14);
    for (index, offset) in [(0, 0), (1, 1), (2, 4), (3, 7), (4, 10), (337, 13)] {
        let before = &points[index];
        let after = &points[index + 1];
        assert_eq!(before.registers.rip, gate + offset);
        let mut registers = before.registers;
        let mut stack = before.application_stack.clone();
        match offset {
            0 => {
                registers.rsp = registers.rsp.checked_sub(8).unwrap();
                let at = usize::try_from(registers.rsp.checked_sub(stack_base).unwrap()).unwrap();
                stack[at..at + 8].copy_from_slice(&registers.rbx.to_le_bytes());
                registers.rip += 1;
            }
            1 => {
                registers.r11 = registers.rdi;
                registers.rip += 3;
            }
            4 => {
                registers.rdi = registers.rsi;
                registers.rip += 3;
            }
            7 => {
                registers.rsi = registers.rdx;
                registers.rip += 3;
            }
            10 => {
                assert_eq!(registers.r11, root);
                registers.rsp = registers.rsp.checked_sub(8).unwrap();
                let at = usize::try_from(registers.rsp.checked_sub(stack_base).unwrap()).unwrap();
                stack[at..at + 8].copy_from_slice(&(gate + 13).to_le_bytes());
                registers.rip = root;
            }
            13 => {
                registers.rbx = word(&stack, stack_base, registers.rsp);
                registers.rsp = registers.rsp.checked_add(8).unwrap();
                registers.rip += 1;
            }
            _ => unreachable!(),
        }
        assert_eq!(
            registers.rip, after.registers.rip,
            "actual stencil successor"
        );
        let expected = Snapshot {
            logical_pc: registers.rip,
            registers,
            xstate: before.xstate.clone(),
            data: before.data.clone(),
            application_stack: stack,
        };
        assert_state(&expected, after);
    }
    callee_saves(&points[0].registers, &points[338].registers);
}

pub(super) fn before_outer(
    child: &Tracee,
    ready: &Ready,
    rsp: u64,
) -> Option<libc::user_regs_struct> {
    let before = child.registers();
    if before.rip != ready.gate + 10 {
        return None;
    }
    check_outer_before(ready, rsp, &before, &child.memory(before.rip, 3));
    Some(before)
}
pub(super) fn after_outer(child: &Tracee, ready: &Ready, before: libc::user_regs_struct) {
    let after = child.registers();
    check_outer_after(ready, &before, &after, &child.memory(after.rsp, 8));
}
fn check_outer_before(ready: &Ready, rsp: u64, before: &libc::user_regs_struct, bytes: &[u8]) {
    assert_eq!(bytes, [0x41, 0xff, 0xd3]);
    assert_eq!(
        (before.rip, before.r11, before.rsp),
        (ready.gate + 10, ready.entry, rsp - 8)
    );
}
fn check_outer_after(
    ready: &Ready,
    before: &libc::user_regs_struct,
    after: &libc::user_regs_struct,
    saved: &[u8],
) {
    assert_eq!(
        (after.rip, after.rsp, after.rax),
        (ready.entry, before.rsp - 8, before.rax)
    );
    assert_eq!(saved, ready.continuation.to_le_bytes());
}
pub(super) fn callback(
    child: &Tracee,
    ready: &Ready,
    noop: u64,
    gate_rsp: u64,
    seen: &mut Vec<u64>,
) {
    assert_eq!(child.memory(noop, 1), [0xc3], "literal preserving callback");
    let r = child.registers();
    assert_eq!(r.rip, noop);
    let context = child.memory(r.rdi, 16);
    let pc = word(&context, 0, 0);
    callback_role(ready, pc, word(&context, 0, 8), gate_rsp - 16, seen);
}
fn callback_role(ready: &Ready, pc: u64, rsp: u64, root_rsp: u64, seen: &mut Vec<u64>) {
    let roles = [
        ready.entry,
        ready.entry + 32,
        ready.entry + 70,
        ready.entry + 14,
        ready.entry + 22,
    ];
    assert_eq!(
        roles.get(seen.len()),
        Some(&pc),
        "all five actual callback roles in order"
    );
    let deltas = [0, 16, 16, 8, 0];
    assert_eq!(
        rsp,
        root_rsp - deltas[seen.len()],
        "actual role stack pointer"
    );
    seen.push(pc);
}

#[cfg(test)]
#[path = "native_native_call/tests.rs"]
mod tests;
