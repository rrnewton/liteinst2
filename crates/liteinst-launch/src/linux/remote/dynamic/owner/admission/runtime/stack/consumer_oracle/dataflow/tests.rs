use super::super::artifact::tests::{model, parse};
use super::*;
#[test]
fn consumer_expression_preserves_distinct_pid_helper_tid_dependencies() {
    let p = Expression::symbol(0);
    let h = Expression::symbol(1);
    let t = Expression::symbol(2);
    assert_ne!(h.add(t, true), Expression::constant(7));
    assert_ne!(
        p.add(Expression::constant(7), false).add(t, true),
        h.add(t, true)
    );
    assert_eq!(h.add(t, true).add(t, false), h);
    let plan = parse(&model()).unwrap();
    let contract = prove_dataflow(&plan).unwrap();
    let mut before: Vec<_> = (0..plan.len())
        .map(|_| super::super::observe::empty_state().state)
        .collect();
    let mut after: Vec<_> = (0..plan.len())
        .map(|_| super::super::observe::empty_state().state)
        .collect();
    before[plan.call].registers.rdi = 17;
    before[plan.ret].registers.rax = 24;
    before[plan.syscalls[2]].registers.rax = 231;
    before[plan.syscalls[2]].registers.rdi = 7;
    after[plan.syscalls[0]].registers.rax = 17;
    after[plan.syscalls[1]].registers.rax = 17;
    let check = |before: &[TaskStateSnapshot], after: &[TaskStateSnapshot]| {
        compare_value_flow(&plan, &contract, |ordinal| {
            Ok((
                &before[ordinal],
                if ordinal == plan.syscalls[2] {
                    None
                } else {
                    Some(&after[ordinal])
                },
            ))
        })
    };
    check(&before, &after).unwrap();
    before[plan.syscalls[2]].registers.rdi = 0x100_0000_0000_0007;
    assert!(check(&before, &after).is_err());
    before[plan.syscalls[2]].registers.rdi = 7;
    after[plan.syscalls[1]].registers.rax = 18;
    assert!(check(&before, &after).is_err());
    after[plan.syscalls[1]].registers.rax = 17;
    before[plan.ret].registers.rbx = 1;
    assert!(check(&before, &after).is_err());
    before[plan.ret].registers.rbx = 0;
    before[plan.call].registers.rdi = 18;
    assert!(check(&before, &after).is_err());
}
#[test]
fn consumer_expression_rejects_unused_helper_constant_terminal_model() {
    let mut raw = model();
    let tail = raw[0x101c..0x1026].to_vec();
    raw[0x1019..0x101e].copy_from_slice(&[0xbe, 7, 0, 0, 0]);
    raw[0x101e..0x1028].copy_from_slice(&tail);
    raw[0x2058 + 16..0x2058 + 24].copy_from_slice(&40_u64.to_le_bytes());
    let constant = parse(&raw).unwrap();
    assert!(prove_dataflow(&constant).is_err());
    let h = Expression::symbol(1);
    assert_ne!(h.add(Expression::symbol(2), true), Expression::constant(7));
    let plan = parse(&model()).unwrap();
    prove_dataflow(&plan).unwrap();
}
#[test]
fn consumer_expression_rejects_wrong_helper_argument_and_increment() {
    let raw = model();
    for (at, value) in [(0x1009, 0xcf), (0x1083, 8), (0x1011, 0xc1)] {
        let mut changed = raw.clone();
        changed[at] = value;
        let plan = parse(&changed).unwrap();
        assert!(prove_dataflow(&plan).is_err());
    }

    // Supplied ELF models, not compiler output or native observations. Save
    // caller RSP in RSI. The helper adds its actual S-8 and subtracts saved S.
    let wrong = parse(&rsp_read_model(7, false, 0)).unwrap();
    assert!(prove_dataflow(&wrong).is_err());
    let correct = parse(&rsp_read_model(15, false, 0)).unwrap();
    prove_dataflow(&correct).unwrap();
    // Independent literal arithmetic calibrates the exact +/-8 consequence.
    let (p, s) = (17_u64, 0x1000_u64);
    assert_eq!((p + 7) + (s - 8) - s, 16);
    assert_eq!((p + 15) + (s - 8) - s, 24);

    // Save caller S independently in RDX, then add current RSP and subtract
    // that saved value after RET. A missing C3 +8 breaks the first model and
    // incorrectly admits the second model's compensating +8.
    let restored = parse(&rsp_read_model(15, true, 0)).unwrap();
    prove_dataflow(&restored).unwrap();
    let extra = parse(&rsp_read_model(15, true, 8)).unwrap();
    assert!(prove_dataflow(&extra).is_err());
    assert_eq!(24_u64 + s - s, 24);
    assert_eq!(24_u64 + s - s + 8, 32);
}
#[test]
fn consumer_expression_keeps_initial_callee_registers_distinct() {
    assert_ne!(Expression::symbol(3 + 3), Expression::symbol(3 + 5));
    assert!(Expression::symbol(0).width(32).is_err());
    assert!(Expression::symbol(1).width(32).is_err());
    assert_eq!(
        Expression::constant(1).add(Expression::constant(u64::MAX), false),
        Expression::constant(0)
    );
    assert_eq!(
        Expression::constant(0xffff_ffff_0000_0027)
            .width(32)
            .unwrap(),
        Expression::constant(39)
    );
}
#[test]
fn consumer_expression_checks_literal_add_sub_flags_without_tolerance() {
    assert_eq!(flags(0x202, 0xffff_ffff, 1, 0, 32, false), 0x257);
    assert_eq!(flags(0x202, 0, 1, u64::MAX, 64, true), 0x297);
    assert_eq!(flags(0x202, 0x7fff_ffff, 1, 0x8000_0000, 32, false), 0xa96);
}

// Construct only supplied parser records. Both function symbols, the text
// section and both initialized RX extents name every new instruction byte.
fn rsp_read_model(helper_increment: u8, post_return: bool, extra: u8) -> Vec<u8> {
    let mut raw = model();
    let mut main = vec![
        0xb8, 39, 0, 0, 0, 0x0f, 0x05, // getpid
        0x48, 0x89, 0xc7, // mov rdi,rax: actual P argument
        0x48, 0x89, 0xe6, // mov rsi,rsp: save caller S
    ];
    if post_return {
        main.extend_from_slice(&[0x48, 0x89, 0xe2]); // mov rdx,rsp
    }
    let call = main.len();
    main.push(0xe8);
    main.extend_from_slice(&(0x80_i32 - (call as i32 + 5)).to_le_bytes());
    if post_return {
        main.extend_from_slice(&[0x48, 0x01, 0xe0, 0x48, 0x29, 0xd0]); // add rax,rsp; sub rax,rdx
        if extra != 0 {
            main.extend_from_slice(&[0x48, 0x83, 0xc0, extra]); // add rax,extra
        }
    }
    main.extend_from_slice(&[
        0x48, 0x89, 0xc6, // mov rsi,rax: preserve helper H
        0xb8, 186, 0, 0, 0, 0x0f, 0x05, // gettid
        0x48, 0x29, 0xc6, 0x48, 0x89, 0xf7, // sub rsi,rax; mov rdi,rsi
        0xb8, 231, 0, 0, 0, 0x0f, 0x05, // exit_group(H-T)
    ]);
    let helper = [
        0x48,
        0x8d,
        0x47,
        helper_increment, // lea rax,[rdi+increment]
        0x48,
        0x01,
        0xe0, // add rax,rsp
        0x48,
        0x29,
        0xf0, // sub rax,rsi
        0xc3,
    ];
    raw[0x1000..0x1080].fill(0);
    raw[0x1000..0x1000 + main.len()].copy_from_slice(&main);
    raw[0x1080..0x1080 + helper.len()].copy_from_slice(&helper);
    let text_size = 0x80 + helper.len() as u64;
    for (offset, value) in [
        (64 + 2 * 56 + 32, text_size),
        (64 + 2 * 56 + 40, text_size),
        (0x2240 + 32, text_size),
        (0x2058 + 16, main.len() as u64),
        (0x2070 + 16, helper.len() as u64),
    ] {
        raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    raw
}
