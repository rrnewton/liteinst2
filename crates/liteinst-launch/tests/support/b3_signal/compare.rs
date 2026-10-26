//! Independent literal effects and strict whole-state comparisons. The only
//! observer translation is authenticated post-INT3 RIP in raw.rs, never flags.
use super::*;

pub fn register(r: &RegisterSnapshot, n: usize) -> u64 {
    [
        r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12,
        r.r13, r.r14, r.r15,
    ][n]
}
pub fn seeded(image: &Image, state: &State) {
    for n in 0..16 {
        assert_eq!(register(&state.registers, n), seed(n), "literal GPR {n}");
    }
    assert_eq!(state.registers.rip, image.ready_pc);
    assert_eq!(state.registers.eflags, FLAGS);
    assert_eq!(state.registers.orig_rax, u64::MAX);
    assert_eq!(
        [
            state.registers.cs,
            state.registers.ss,
            state.registers.ds,
            state.registers.es,
            state.registers.fs,
            state.registers.gs
        ],
        [0x33, 0x2b, 0, 0, 0, 0]
    );
    assert_eq!([state.registers.fs_base, state.registers.gs_base], [0, 0]);
    assert_eq!(state.mask, APP_MASK);
    assert_eq!(&state.xstate[..2], &0x037f_u16.to_le_bytes());
    assert_eq!(&state.xstate[2..4], &0x3800_u16.to_le_bytes());
    assert_eq!(state.xstate[4], 0x80);
    assert_eq!(&state.xstate[24..28], &0x1f80_u32.to_le_bytes());
    assert_eq!(
        &state.xstate[32..42],
        &[0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f]
    );
    assert_eq!(&state.xstate[160..176], &XMM_SEED);
    let mut data = image.data.clone();
    data[..8].copy_from_slice(&READY_VALUE.to_le_bytes());
    for call in &image.setup {
        let offset = (call.result_slot - DATA) as usize;
        data[offset..offset + 8].copy_from_slice(&0_u64.to_le_bytes());
    }
    assert_eq!(state.data, data);
    let mut normal = vec![0x5a; STACK_LEN];
    let slot = (SP - 8 - NORMAL) as usize;
    normal[slot..slot + 8].copy_from_slice(&FLAGS.to_le_bytes());
    assert_eq!(state.normal, normal);
    assert_eq!(state.alternate, vec![0xc3; STACK_LEN]);
}

pub fn frame_setup(
    image: &Image,
    before: &State,
    handler: &State,
    frame: &Frame,
    signal: &[u8; 128],
) {
    let mut expected = before.registers;
    expected.rax = 0;
    expected.rdi = SIGNAL as u64;
    expected.rsi = frame.address + FRAME_INFO as u64;
    expected.rdx = frame.address + FRAME_UC as u64;
    expected.rsp = frame.address;
    expected.rip = HANDLER;
    expected.eflags = FLAGS & !(1 << 10); // Kernel's actual DF-clear handler transition.
    assert_eq!(handler.registers, expected);
    assert_eq!(
        handler.mask,
        APP_MASK | ACTION_MASK | (1_u64 << (SIGNAL - 1))
    );
    assert_eq!(&handler.xstate[..2], &0x037f_u16.to_le_bytes());
    assert_eq!(&handler.xstate[2..4], &0_u16.to_le_bytes());
    assert_eq!(&handler.xstate[24..28], &0x1f80_u32.to_le_bytes());
    assert_eq!(&handler.xstate[160..176], &[0; 16]);
    assert_eq!(handler.data, before.data);
    assert_eq!(&frame.bytes[FRAME_INFO..FRAME_INFO + 128], signal);
    let sc = FRAME_UC + UC_CONTEXT;
    let order = [8, 9, 10, 11, 12, 13, 14, 15, 7, 6, 5, 3, 2, 0, 1, 4];
    for (slot, reg) in order.into_iter().enumerate() {
        assert_eq!(
            word(&frame.bytes, sc + slot * 8),
            register(&before.registers, reg)
        );
    }
    assert_eq!(word(&frame.bytes, sc + SC_RIP), image.ready_pc);
    assert_eq!(word(&frame.bytes, sc + SC_FLAGS), FLAGS);
    assert_eq!(word(&frame.bytes, sc + 168), APP_MASK);
    assert_eq!(word(&frame.bytes, FRAME_UC + UC_MASK), APP_MASK);
    if image.trajectory.altstack() {
        assert!((ALT..ALT + STACK_LEN as u64).contains(&frame.address));
        assert_eq!(handler.normal, before.normal);
        assert_eq!(word(&frame.bytes, FRAME_UC + 16), ALT);
        assert_eq!(dword(&frame.bytes, FRAME_UC + 24), 0);
        assert_eq!(word(&frame.bytes, FRAME_UC + 32), STACK_LEN as u64);
    } else {
        assert!((NORMAL..SP).contains(&frame.address));
        assert_eq!(handler.alternate, before.alternate);
        assert_eq!(word(&frame.bytes, FRAME_UC + 16), 0);
        // Both lanes positively establish stored raw flags zero before exec:
        // the pristine child uses its own checked setter, and the gated lane
        // independently checks its authentic original anchor frame. Exec
        // clears only sp/size; a disabled sigaltstack query is not this fact.
        assert_eq!(dword(&frame.bytes, FRAME_UC + 24), 0);
        assert_eq!(word(&frame.bytes, FRAME_UC + 32), 0);
    }
    let fp = (frame.fpstate - frame.address) as usize;
    assert_eq!(&frame.bytes[fp..fp + 2], &0x037f_u16.to_le_bytes());
    assert_eq!(&frame.bytes[fp + 2..fp + 4], &0x3800_u16.to_le_bytes());
    assert_eq!(&frame.bytes[fp + 160..fp + 176], &XMM_SEED);
}
pub fn cpuid(before: &State, after: &State) {
    // This literal original CPU instruction is a second independent value
    // check, not the production SelectedInput completion implementation.
    let values =
        std::arch::x86_64::__cpuid_count(before.registers.rax as u32, before.registers.rcx as u32);
    let mut expected = before.clone();
    expected.registers.rax = u64::from(values.eax);
    expected.registers.rbx = u64::from(values.ebx);
    expected.registers.rcx = u64::from(values.ecx);
    expected.registers.rdx = u64::from(values.edx);
    expected.registers.rip += 2;
    assert_eq!(after, &expected);
}
pub fn edited_frame(image: &Image, before: &Frame, after: &Frame) {
    let mut expected = before.clone();
    if image.trajectory.edited() {
        let sc = FRAME_UC + UC_CONTEXT;
        for (offset, value) in [
            (sc + SC_RIP, LANDING),
            (sc + SC_RAX, EDITED_RAX),
            (sc + SC_FLAGS, FLAGS & !1),
            (FRAME_UC + UC_MASK, RETURN_MASK),
        ] {
            expected.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        let fp = (expected.fpstate - expected.address) as usize;
        expected.bytes[fp + 160..fp + 176].copy_from_slice(&XMM_EDIT);
    }
    assert_eq!(after, &expected);
}
pub fn returned(image: &Image, before: &State, input: &State, actual: &State) {
    let mut expected = before.clone();
    // The kernel consumes the frame but never erases it or the original
    // handler's record stores. Full post-handler memory remains exact.
    expected.data = input.data.clone();
    expected.normal = input.normal.clone();
    expected.alternate = input.alternate.clone();
    if image.trajectory.edited() {
        expected.registers.rip = LANDING;
        expected.registers.rax = EDITED_RAX;
        expected.registers.eflags = FLAGS & !1;
        expected.mask = RETURN_MASK;
        expected.xstate[160..176].copy_from_slice(&XMM_EDIT);
    }
    assert_eq!(
        actual, &expected,
        "actual sigreturn restores the full original frame"
    );
    assert_eq!(actual.registers.orig_rax, u64::MAX);
    assert_eq!(actual.registers.eflags & (1 << 10), 1 << 10);
    if image.trajectory.edited() {
        assert_eq!(actual.registers.rax as i64, -22);
    }
}

/// The advertised cross-lane comparison remains a whole value equality.
/// Corruption controls call the same predicate; there is no field mask.
pub fn exact(left: &State, right: &State, left_frame: &Frame, right_frame: &Frame) -> bool {
    left == right && left_frame == right_frame
}
pub fn corruptions(state: &State, frame: &Frame) {
    assert!(exact(state, state, frame, frame));
    for offset in [
        FRAME_UC + UC_CONTEXT + SC_TRAP,
        FRAME_UC + UC_CONTEXT + SC_ERROR,
        FRAME_UC + UC_CONTEXT + SC_CR2,
        FRAME_UC + UC_CONTEXT + SC_RAX,
        FRAME_UC + UC_CONTEXT + SC_FLAGS,
        FRAME_UC + UC_MASK,
        FRAME_INFO + 24,
    ] {
        let mut changed = frame.clone();
        changed.bytes[offset] ^= 1;
        assert!(
            !exact(state, state, frame, &changed),
            "frame corruption at {offset}"
        );
    }
    let mut fp = frame.clone();
    let offset = (fp.fpstate - fp.address) as usize + 160;
    fp.bytes[offset] ^= 1;
    assert!(!exact(state, state, frame, &fp));
    for kind in 0..8 {
        let mut changed = state.clone();
        match kind {
            0 => changed.registers.r11 ^= 1,
            1 => changed.registers.eflags ^= 1 << 10,
            2 => changed.registers.orig_rax ^= 1,
            3 => changed.xstate[160] ^= 1,
            4 => changed.mask ^= 1 << 2,
            5 => changed.data[0x80] ^= 1,
            6 => changed.normal[0] ^= 1,
            7 => changed.alternate[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            !exact(state, &changed, frame, frame),
            "state corruption {kind}"
        );
    }
}
