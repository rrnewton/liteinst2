//! Fabricated state only; these controls do not execute the ABI or code bytes.
use super::*;
fn ready() -> Ready {
    Ready {
        profile: Profile::NativeCall,
        entry: 0x2000,
        gate: 0x1000,
        continuation: 0x100d,
        heads: vec![],
        returns: vec![],
        boundaries: vec![],
        immutable: vec![],
        original_source: vec![],
    }
}
fn registers() -> libc::user_regs_struct {
    let mut r: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    r.rip = 0x1000;
    r.rsp = 0x8008;
    r.rdi = 0x2000;
    r.rsi = 0x4000;
    r.rdx = 1024;
    r.rax = 7;
    r.rbx = 11;
    r.rbp = 13;
    r.r12 = 17;
    r.r13 = 19;
    r.r14 = 23;
    r.r15 = 29;
    r.eflags = 0xad7;
    r.orig_rax = u64::MAX;
    r
}
fn refused(f: impl FnOnce() + std::panic::UnwindSafe) {
    assert!(std::panic::catch_unwind(f).is_err());
}

#[test]
fn literal_native_profile_has_no_transient_exclusions_or_legacy_alias() {
    let ready = ready();
    assert_eq!(
        STENCIL,
        [
            0x53, 0x49, 0x89, 0xfb, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x41, 0xff, 0xd3, 0x5b,
            0xc3
        ]
    );
    assert_eq!(HEADS, [0, 1, 4, 7, 10, 13, 14]);
    assert_eq!(
        (
            Profile::NativeCall.after_call(),
            Profile::NativeCall.outer_ret(),
            Profile::NativeCall.entry_delta()
        ),
        (13, 14, 16)
    );
    for &head in HEADS {
        assert!(Profile::NativeCall.comparison(0x1000, 0x1000 + head));
    }
    super::super::check_gate(&ready, STENCIL);
    for i in 0..STENCIL.len() {
        let mut bytes = STENCIL.to_vec();
        bytes[i] ^= 1;
        refused(|| super::super::check_gate(&ready, &bytes));
    }
    for n in 0..STENCIL.len() {
        refused(|| super::super::check_gate(&ready, &STENCIL[..n]));
    }
    let mut wrong = ready;
    wrong.continuation += 1;
    refused(|| super::super::check_gate(&wrong, STENCIL));
    wrong.continuation -= 1;
    wrong.profile = Profile::Legacy;
    refused(|| super::super::check_gate(&wrong, STENCIL));
}
#[test]
fn actual_target_input_length_and_alignment_are_required() {
    let ready = ready();
    let r = registers();
    arguments(&r, &ready, 0x4000, 1024);
    for field in 0..5 {
        let mut bad = r;
        match field {
            0 => bad.rdi ^= 1,
            1 => bad.rsi ^= 1,
            2 => bad.rdx ^= 1,
            3 => bad.rip ^= 1,
            4 => bad.rsp ^= 8,
            _ => unreachable!(),
        }
        refused(|| arguments(&bad, &ready, 0x4000, 1024));
    }
    refused(|| arguments(&r, &ready, 0x4000, 1023));
}
#[test]
fn every_callee_save_must_restore_before_harness() {
    let r = registers();
    callee_saves(&r, &r);
    for field in 0..7 {
        let mut bad = r;
        match field {
            0 => bad.rbx ^= 1,
            1 => bad.rbp ^= 1,
            2 => bad.r12 ^= 1,
            3 => bad.r13 ^= 1,
            4 => bad.r14 ^= 1,
            5 => bad.r15 ^= 1,
            6 => bad.rsp ^= 1,
            _ => unreachable!(),
        }
        refused(|| callee_saves(&r, &bad));
    }
}
#[test]
fn outer_call_requires_exact_instruction_target_stack_successor_and_saved_word() {
    let ready = ready();
    let mut before = registers();
    before.rip += 10;
    before.r11 = ready.entry;
    before.rsp -= 8;
    let bytes = [0x41, 0xff, 0xd3];
    check_outer_before(&ready, 0x8008, &before, &bytes);
    let mut after = before;
    after.rip = ready.entry;
    after.rsp -= 8;
    check_outer_after(&ready, &before, &after, &ready.continuation.to_le_bytes());
    for field in 0..3 {
        let mut bad = before;
        match field {
            0 => bad.rip ^= 1,
            1 => bad.r11 ^= 1,
            2 => bad.rsp ^= 1,
            _ => unreachable!(),
        }
        refused(|| check_outer_before(&ready, 0x8008, &bad, &bytes));
        let mut bad = after;
        match field {
            0 => bad.rip ^= 1,
            1 => bad.rax ^= 1,
            2 => bad.rsp ^= 1,
            _ => unreachable!(),
        }
        refused(|| check_outer_after(&ready, &before, &bad, &ready.continuation.to_le_bytes()));
        let mut bad = bytes;
        bad[field] ^= 1;
        refused(|| check_outer_before(&ready, 0x8008, &before, &bad));
    }
    refused(|| {
        check_outer_after(
            &ready,
            &before,
            &after,
            &(ready.continuation + 1).to_le_bytes(),
        )
    });
}
#[test]
fn callback_order_count_and_stack_geometry_are_exact() {
    let ready = ready();
    let roles = [
        (0x2000, 0x8000),
        (0x2020, 0x7ff0),
        (0x2046, 0x7ff0),
        (0x200e, 0x7ff8),
        (0x2016, 0x8000),
    ];
    let mut seen = Vec::new();
    for (pc, rsp) in roles {
        let prefix = seen.clone();
        refused(|| callback_role(&ready, pc ^ 1, rsp, 0x8000, &mut prefix.clone()));
        refused(|| callback_role(&ready, pc, rsp ^ 1, 0x8000, &mut prefix.clone()));
        callback_role(&ready, pc, rsp, 0x8000, &mut seen);
    }
    refused(|| callback_role(&ready, 0x2000, 0x8000, 0x8000, &mut seen.clone()));
}

fn copy(point: &Snapshot) -> Snapshot {
    Snapshot {
        logical_pc: point.logical_pc,
        registers: point.registers,
        xstate: point.xstate.clone(),
        data: point.data.clone(),
        application_stack: point.application_stack.clone(),
    }
}
fn stencil_fixture() -> Vec<Snapshot> {
    let base = Snapshot {
        logical_pc: 0x1000,
        registers: registers(),
        xstate: vec![0x5a; 576],
        data: vec![0xa5; 4096],
        application_stack: vec![0x9a; 168],
    };
    let mut p: Vec<_> = (0..339).map(|_| copy(&base)).collect();
    p[1].registers.rip = 0x1001;
    p[1].registers.rsp = 0x8000;
    p[1].application_stack[152..160].copy_from_slice(&11_u64.to_le_bytes());
    p[2] = copy(&p[1]);
    p[2].registers.rip = 0x1004;
    p[2].registers.r11 = 0x2000;
    p[3] = copy(&p[2]);
    p[3].registers.rip = 0x1007;
    p[3].registers.rdi = 0x4000;
    p[4] = copy(&p[3]);
    p[4].registers.rip = 0x100a;
    p[4].registers.rsi = 1024;
    p[5] = copy(&p[4]);
    p[5].registers.rip = 0x2000;
    p[5].registers.rsp = 0x7ff8;
    p[5].application_stack[144..152].copy_from_slice(&0x100d_u64.to_le_bytes());
    p[337] = copy(&p[5]);
    p[337].registers.rip = 0x100d;
    p[337].registers.rsp = 0x8000;
    p[337].registers.rax = 123;
    p[337].registers.eflags = 0x202;
    p[338] = copy(&p[337]);
    p[338].registers.rip = 0x100e;
    p[338].registers.rsp = 0x8008;
    for point in &mut p {
        point.logical_pc = point.registers.rip;
    }
    p
}
#[test]
fn wrapper_semantics_compare_all_unaffected_state_and_complete_stack() {
    let p = stencil_fixture();
    stencil(&p, 0x1000, 0x2000, 0x7f68);
    for index in [1, 2, 3, 4, 5, 338] {
        for field in 0..8 {
            let mut bad = stencil_fixture();
            match field {
                0 => bad[index].registers.rsp ^= 1,
                1 => bad[index].registers.r11 ^= 1,
                2 => bad[index].registers.eflags ^= 1,
                3 => bad[index].xstate[500] ^= 1,
                4 => bad[index].data[4000] ^= 1,
                5 => bad[index].application_stack[0] ^= 1,
                6 => bad[index].registers.rip ^= 1,
                7 => bad[index].application_stack[150] ^= 1,
                _ => unreachable!(),
            }
            refused(|| stencil(&bad, 0x1000, 0x2000, 0x7f68));
        }
    }
}
