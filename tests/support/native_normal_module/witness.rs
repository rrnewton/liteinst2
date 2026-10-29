//! Original-only helper effects; shared full-state comparator, no masks added.
use super::*;
pub(super) fn caller_effects(points: &[Snapshot], ready: &Ready, data: u64, stack: u64) {
    let seen: Vec<_> = points
        .iter()
        .filter_map(|p| {
            p.logical_pc
                .checked_sub(ready.caller)
                .filter(|n| bytes::HEADS.contains(n))
        })
        .collect();
    assert_eq!(
        seen,
        bytes::HEADS,
        "all 40 helper heads exactly once, in order"
    );
    for pair in points.windows(2) {
        if pair[0]
            .logical_pc
            .checked_sub(ready.caller)
            .is_some_and(|n| bytes::HEADS.contains(&n))
        {
            step(&pair[0], &pair[1], ready, data, stack);
        }
    }
}
pub(super) fn step(before: &Snapshot, after: &Snapshot, ready: &Ready, data: u64, stack: u64) {
    let offset = before.logical_pc.checked_sub(ready.caller).unwrap();
    assert!(bytes::HEADS.contains(&offset) && offset != bytes::OUTER_RET);
    let mut expected = Snapshot {
        logical_pc: 0,
        registers: before.registers,
        xstate: before.xstate.clone(),
        data: before.data.clone(),
        application_stack: before.application_stack.clone(),
    };
    let r = &mut expected.registers;
    let index = bytes::HEADS.iter().position(|&n| n == offset).unwrap();
    expected.logical_pc = ready.caller + bytes::HEADS[index + 1];
    match offset {
        0 | 2 | 4 | 9 | 14 | 18 => {
            let value = match offset {
                0 => r.r15,
                2 => r.r14,
                4 => r.r13,
                9 => r.r12,
                14 => r.rbp,
                _ => r.rbx,
            };
            r.rsp = r.rsp.checked_sub(8).unwrap();
            put_word(&mut expected.application_stack, stack, r.rsp, value);
        }
        6 => r.r13 = r.rdi,
        11 => r.r12 = r.rdx,
        15 => r.rbp = r.rsi,
        19 => {
            r.eflags = arithmetic_flags(r.eflags, r.rsp, 8, true);
            r.rsp = r.rsp.checked_sub(8).unwrap();
        }
        23 | 54 => r.rdi = word_at(&before.data, data, r.rbp),
        27 => r.rsi = word_at(&before.data, data, r.rsi.checked_add(8).unwrap()),
        31 | 50 | 70 | 93 => {
            let call = bytes::CALLS.iter().position(|&n| n == offset).unwrap();
            assert_eq!(r.r13, data + TARGETS as u64);
            let target = word_at(&before.data, data, r.r13 + (call % 2 * 8) as u64);
            assert_eq!(target, ready.target(call).entry);
            r.rsp = r.rsp.checked_sub(8).unwrap();
            put_word(
                &mut expected.application_stack,
                stack,
                r.rsp,
                expected.logical_pc,
            );
            expected.logical_pc = target;
        }
        35 | 77 => r.rdi = word_at(&before.data, data, r.rbp.checked_add(16).unwrap()),
        39 | 58 | 81 | 100 => {
            assert_eq!(r.r12, data + RESULTS as u64);
            let call = bytes::RESULT_STORES
                .iter()
                .position(|&n| n == offset)
                .unwrap();
            put_word(&mut expected.data, data, r.r12 + call as u64 * 8, r.rax);
        }
        43 => r.rbx = r.rax,
        46 | 89 => r.rsi = word_at(&before.data, data, r.rbp.checked_add(24).unwrap()),
        63 => r.r15 = r.rax,
        66 => r.rsi = word_at(&before.data, data, r.rbp.checked_add(8).unwrap()),
        74 | 97 => {
            let value = if offset == 74 { r.r15 } else { r.r14 };
            r.eflags = arithmetic_flags(r.eflags, r.rbx, value, false);
            r.rbx = r.rbx.wrapping_add(value);
        }
        86 => r.r14 = r.rax,
        105 => {
            r.eflags = arithmetic_flags(r.eflags, r.rsp, 8, false);
            r.rsp = r.rsp.checked_add(8).unwrap();
        }
        109 => {
            r.eflags = arithmetic_flags(r.eflags, r.rax, r.rbx, false);
            r.rax = r.rax.wrapping_add(r.rbx);
        }
        112 | 113 | 114 | 116 | 118 | 120 => {
            let value = word_at(&before.application_stack, stack, r.rsp);
            match offset {
                112 => r.rbx = value,
                113 => r.rbp = value,
                114 => r.r12 = value,
                116 => r.r13 = value,
                118 => r.r14 = value,
                _ => r.r15 = value,
            }
            r.rsp = r.rsp.checked_add(8).unwrap();
        }
        _ => panic!("closed module helper instruction"),
    }
    assert_eq!(after.registers.rip, expected.logical_pc);
    assert_state(&expected, after);
}
