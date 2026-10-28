//! Metadata and static assembled-byte controls; no subject/gate invocation.
use super::*;
use iced_x86::{Decoder, DecoderOptions, Mnemonic};

fn identity() -> Identity {
    Identity {
        gate: 0x8000,
        pid: 7,
        tid: 8,
        target: 0x1000,
        continuation: 0x5000,
    }
}
fn original() -> Frame {
    Frame {
        phase: ARMED,
        sequence: 19,
        gate: 0x8000,
        pid: 7,
        tid: 8,
        target: 0x1000,
        observed_target: 0x1000,
        pre_call_rsp: 0x8000,
        resumed_rsp: 0x8000,
        stack_start: 0x7000,
        stack_end: 0x9000,
        ..Frame::default()
    }
}
fn observation(leg: ReferenceLeg) -> (ReferenceFrame, ReferenceFrame) {
    let armed = arm_reference(ReferenceFrame::default(), identity(), 19, 2201, leg).unwrap();
    let observed = ReferenceFrame {
        phase: RETURNED,
        start_lo: 100,
        start_hi: 1,
        start_aux: 7,
        end_lo: 200,
        end_hi: 1,
        end_aux: 7,
        before_rax: 0x1234,
        before_rcx: 0x5678,
        before_rdx: 0x9abc,
        after_rax: 42,
        after_rcx: 0xabcd,
        after_rdx: 0xef12,
        ..armed
    };
    (armed, observed)
}

#[test]
fn external_identity_leg_and_actual_sequence_are_not_raw_ordinals() {
    for leg in [ReferenceLeg::Original, ReferenceLeg::Installed] {
        let (armed, f) = observation(leg);
        let row = observed(f, armed, original(), identity(), leg, 42).unwrap();
        assert_eq!(row.external_id(), 2201);
        assert_eq!(row.gate_sequence(), 19);
        assert_eq!(row.leg(), leg);
        assert_eq!(row.elapsed_ticks(), Some(100));
        assert_eq!(row.pre_call_rsp(), row.resumed_rsp());
        for field in 0..11 {
            let mut bad = f;
            match field {
                0 => bad.phase = ARMED,
                1 => bad.sequence += 1,
                2 => bad.gate += 1,
                3 => bad.pid += 1,
                4 => bad.tid += 1,
                5 => bad.target += 1,
                6 => bad.continuation += 1,
                7 => bad.external_id += 1,
                8 => bad.leg ^= 3,
                9 => bad.canary ^= 1,
                _ => bad.after_rax ^= 1,
            }
            assert!(
                observed(bad, armed, original(), identity(), leg, 42).is_err(),
                "{field}"
            );
        }
        let mut wrong_call = original();
        wrong_call.sequence += 1;
        assert!(observed(f, armed, wrong_call, identity(), leg, 42).is_err());
    }
    let old = ReferenceFrame {
        sequence: 5,
        ..ReferenceFrame::default()
    };
    // Calibration/original/Legacy calls may precede the first attached raw row.
    assert_eq!(
        arm_reference(old, identity(), 19, 0, ReferenceLeg::Original)
            .unwrap()
            .sequence,
        19
    );
    for sequence in [0, 4, 5] {
        assert_eq!(
            arm_reference(old, identity(), sequence, 0, ReferenceLeg::Original),
            Err(GateError::Sequence)
        );
    }
    let max = ReferenceFrame {
        sequence: u64::MAX,
        ..ReferenceFrame::default()
    };
    assert_eq!(
        arm_reference(max, identity(), 1, 0, ReferenceLeg::Original),
        Err(GateError::Sequence)
    );
}

#[test]
fn clock_words_aux_and_order_refuse_instead_of_inventing_elapsed() {
    let (armed, f) = observation(ReferenceLeg::Original);
    for field in 0..8 {
        let mut bad = f;
        match field {
            0 => bad.start_lo |= 1 << 32,
            1 => bad.start_hi |= 1 << 32,
            2 => bad.start_aux |= 1 << 32,
            3 => bad.end_lo |= 1 << 32,
            4 => bad.end_hi |= 1 << 32,
            5 => bad.end_aux |= 1 << 32,
            6 => bad.end_aux += 1,
            _ => bad.end_lo = 99,
        }
        assert_eq!(
            observed(
                bad,
                armed,
                original(),
                identity(),
                ReferenceLeg::Original,
                42
            ),
            Err(GateError::ReferenceClock)
        );
    }
    let equal = ReferenceFrame {
        end_lo: f.start_lo,
        ..f
    };
    assert_eq!(
        observed(
            equal,
            armed,
            original(),
            identity(),
            ReferenceLeg::Original,
            42
        )
        .unwrap()
        .elapsed_ticks(),
        Some(0)
    );
}

#[test]
fn original_and_installed_gate_predicates_remain_distinct() {
    let f = original();
    assert!(original_resumed(f, identity(), 42).is_ok());
    assert!(resumed(f, identity(), 42, &[0x1012]).is_err());
    let mut installed = f;
    installed.phase = COMPLETED;
    installed.entry_rsp = 0x7ff8;
    installed.return_word = 0x5000;
    installed.return_pc = 0x1012;
    assert!(resumed(installed, identity(), 42, &[0x1012]).is_ok());
    assert!(original_resumed(installed, identity(), 42).is_err());
}

fn descriptor() -> CallGate {
    CallGate {
        profile: GateProfile::ReferenceAmdV1,
        target: 0x1000,
        returns: vec![0x1012].into(),
        pid: std::process::id(),
    }
}
// Actual Pending/Flight commit/drop implementation, with local Copy-only cells.
// This is synthetic postflight refusal coverage, not a fabricated native return.
fn pending<'a>(
    gate: &'a CallGate,
    frame: &UnsafeCell<Frame>,
    reference: &UnsafeCell<ReferenceFrame>,
) -> Pending<'a, OriginalCallResult> {
    let id = gate.identity().unwrap();
    let mut f = original();
    f.gate = id.gate;
    f.pid = id.pid;
    f.tid = id.tid;
    let armed = arm_reference(
        ReferenceFrame::default(),
        id,
        f.sequence,
        2201,
        ReferenceLeg::Original,
    )
    .unwrap();
    let (_, sample) = observation(ReferenceLeg::Original);
    let r = ReferenceFrame {
        phase: RETURNED,
        start_lo: sample.start_lo,
        start_hi: sample.start_hi,
        start_aux: sample.start_aux,
        end_lo: sample.end_lo,
        end_hi: sample.end_hi,
        end_aux: sample.end_aux,
        after_rax: 42,
        ..armed
    };
    let call = original_resumed(f, id, 42).unwrap();
    let interval = observed(r, armed, f, id, ReferenceLeg::Original, 42).unwrap();
    unsafe {
        frame.get().write(f);
        reference.get().write(r);
    }
    Pending {
        gate,
        flight: Flight {
            frame: frame.get(),
            reference: reference.get(),
            finished: false,
            _local: PhantomData,
        },
        frame: f,
        reference_frame: r,
        call,
        interval,
    }
}

#[test]
fn failed_owner_aftercheck_keeps_both_slots_poisoned_and_unpublished() {
    let gate = descriptor();
    let frame = UnsafeCell::new(Frame::default());
    let reference = UnsafeCell::new(ReferenceFrame::default());
    let result: Result<(OriginalCallResult, ReferenceInterval), GateError> = (|| {
        let pending = pending(&gate, &frame, &reference);
        // Same `?` ordering as the owning preparation's complete source aftercheck.
        Err::<(), _>(GateError::Identity)?;
        pending.commit()
    })();
    assert_eq!(result, Err(GateError::Identity));
    let f = unsafe { frame.get().read() };
    let r = unsafe { reference.get().read() };
    assert_eq!(f.phase, POISONED);
    assert_eq!(r.phase, POISONED);
    assert_eq!(f.sequence, 19);
    assert_eq!(r.external_id, 2201);
    assert!(idle(f).is_err());
    assert!(reference_idle(r).is_err());
    assert!(arm(f, gate.identity().unwrap(), 0x7000, 0x9000).is_err());
    assert!(arm_reference(r, gate.identity().unwrap(), 20, 2, ReferenceLeg::Original).is_err());
}

#[test]
fn commit_checks_actual_cells_then_resets_only_after_success() {
    let gate = descriptor();
    for corrupt in 0..3 {
        let frame = UnsafeCell::new(Frame::default());
        let reference = UnsafeCell::new(ReferenceFrame::default());
        let pending = pending(&gate, &frame, &reference);
        if corrupt == 1 {
            unsafe {
                (*reference.get()).external_id += 1;
            }
        }
        if corrupt == 2 {
            unsafe {
                (*frame.get()).resumed_rsp += 8;
            }
        }
        let result = pending.commit();
        if corrupt != 0 {
            assert_eq!(result, Err(GateError::Identity));
            assert_eq!(unsafe { frame.get().read() }.phase, POISONED);
            assert_eq!(unsafe { reference.get().read() }.phase, POISONED);
        } else {
            let (call, row) = result.unwrap();
            assert_eq!(call.value, 42);
            assert_eq!(row.gate_sequence(), 19);
            assert_eq!(idle(unsafe { frame.get().read() }), Ok(19));
            assert_eq!(reference_idle(unsafe { reference.get().read() }), Ok(19));
        }
    }
}

#[test]
fn mismatched_methods_refuse_before_tls_or_hardware_reads() {
    let scope = super::super::drain_tests::FrameScope::new();
    let before = super::super::drain_tests::snapshot();
    let legacy = super::super::drain_tests::descriptor();
    assert_eq!(legacy.require_reference(), Err(GateError::Profile));
    let reference = descriptor();
    let stack = ReadableStack {
        start: 0x7000,
        end: 0x9000,
    };
    assert_eq!(
        unsafe { reference.invoke(core::ptr::null(), 0, &stack) },
        Err(GateError::Profile)
    );
    assert_eq!(
        unsafe { reference.invoke_original(core::ptr::null(), 0, &stack) },
        Err(GateError::Profile)
    );
    assert_eq!(super::super::drain_tests::snapshot(), before);
    drop(scope);
}

// Independent hand-encoded stencil. The tested bytes are the linked new stub,
// not a fabricated output of this array. No call into it occurs in this test.
const STENCIL: &[u8] = &[
    0x53, 0x41, 0x54, 0x48, 0x8d, 0x64, 0x24, 0xf8, 0x48, 0x89, 0xfb, 0x49, 0x89, 0xcc, 0x48, 0x89,
    0xf7, 0x48, 0x89, 0xd6, 0x4c, 0x8b, 0x5b, 0x28, 0x4c, 0x89, 0x5b, 0x30, 0x48, 0x89, 0x63, 0x38,
    0x49, 0x89, 0x44, 0x24, 0x78, 0x49, 0x89, 0x8c, 0x24, 0x80, 0, 0, 0, 0x49, 0x89, 0x94, 0x24,
    0x88, 0, 0, 0, 0x0f, 0xae, 0xe8, 0x0f, 0x01, 0xf9, 0x0f, 0xae, 0xe8, 0x41, 0x89, 0x44, 0x24,
    0x48, 0x41, 0x89, 0x54, 0x24, 0x50, 0x41, 0x89, 0x4c, 0x24, 0x58, 0x49, 0x8b, 0x44, 0x24, 0x78,
    0x49, 0x8b, 0x8c, 0x24, 0x80, 0, 0, 0, 0x49, 0x8b, 0x94, 0x24, 0x88, 0, 0, 0, 0x41, 0xff, 0xd3,
    0x48, 0x89, 0x63, 0x40, 0x49, 0x89, 0x84, 0x24, 0x90, 0, 0, 0, 0x49, 0x89, 0x8c, 0x24, 0x98, 0,
    0, 0, 0x49, 0x89, 0x94, 0x24, 0xa0, 0, 0, 0, 0x0f, 0xae, 0xe8, 0x0f, 0x01, 0xf9, 0x0f, 0xae,
    0xe8, 0x41, 0x89, 0x44, 0x24, 0x60, 0x41, 0x89, 0x54, 0x24, 0x68, 0x41, 0x89, 0x4c, 0x24, 0x70,
    0x49, 0x8b, 0x84, 0x24, 0x90, 0, 0, 0, 0x49, 0x8b, 0x8c, 0x24, 0x98, 0, 0, 0, 0x49, 0x8b, 0x94,
    0x24, 0xa0, 0, 0, 0, 0x49, 0xc7, 0x04, 0x24, 0x02, 0, 0, 0, 0x48, 0x8d, 0x64, 0x24, 0x08, 0x41,
    0x5c, 0x5b, 0xc3,
];

#[test]
fn linked_stencil_offsets_flags_and_register_restore_are_exact() {
    let start = __rapid_profiler_reference_call_v1 as *const () as usize;
    let end = core::ptr::addr_of!(__rapid_profiler_reference_call_end_v1) as usize;
    assert_eq!(end.checked_sub(start), Some(194));
    assert_eq!(STENCIL.len(), 194);
    // SAFETY: this library's immutable text labels bound one complete stub.
    let linked = unsafe { core::slice::from_raw_parts(start as *const u8, 194) };
    assert_eq!(linked, STENCIL);
    for (label, offset) in [
        (
            core::ptr::addr_of!(__rapid_profiler_reference_before_start_v1),
            32,
        ),
        (
            core::ptr::addr_of!(__rapid_profiler_reference_after_start_v1),
            98,
        ),
        (
            core::ptr::addr_of!(__rapid_profiler_reference_after_call_v1),
            101,
        ),
        (
            core::ptr::addr_of!(__rapid_profiler_reference_before_end_v1),
            105,
        ),
        (
            core::ptr::addr_of!(__rapid_profiler_reference_after_end_v1),
            185,
        ),
    ] {
        assert_eq!((label as usize).checked_sub(start), Some(offset));
    }
    let decoded: Vec<_> = Decoder::with_ip(64, linked, 0, DecoderOptions::NONE)
        .into_iter()
        .collect();
    assert_eq!(
        decoded
            .iter()
            .filter(|i| i.mnemonic() == Mnemonic::Rdtscp)
            .count(),
        2
    );
    assert_eq!(
        decoded
            .iter()
            .filter(|i| i.mnemonic() == Mnemonic::Lfence)
            .count(),
        4
    );
    assert_eq!(
        decoded
            .iter()
            .filter(|i| i.mnemonic() == Mnemonic::Call)
            .count(),
        1
    );
    assert_eq!(
        decoded
            .iter()
            .filter(|i| i.mnemonic() == Mnemonic::Ret)
            .count(),
        1
    );
    assert!(
        decoded
            .iter()
            .all(|i| !i.is_invalid() && i.rflags_modified() == 0)
    );
    assert_eq!(decoded.last().unwrap().next_ip(), 194);
}
