//! Synthetic parser and edit-policy controls. These tests create no process,
//! kernel frame, execution permission, publication lease or native evidence.
//! Literal offsets below are independently transcribed from the x86-64 UAPI;
//! the production parser's offset constants do not construct expected bytes.
use super::*;

const NORMAL: u64 = 0x700000;
const ALT: u64 = 0x800000;
const STACK_SIZE: u64 = 0x10000;
const FRAME_OFFSET: u64 = 0xe008;
const FP_OFFSET: usize = 504;
const XSAVE_SIZE: usize = 832;
const FRAME_SIZE: usize = FP_OFFSET + XSAVE_SIZE + 4;
const ID: SignalFrameId = SignalFrameId {
    session: 17,
    serial: 3,
};

fn write64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn write32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn original_metadata() -> DynamicExceptionMetadata {
    DynamicExceptionMetadata {
        trapno: 14,
        error_code: 7,
        cr2: 0x900000,
    }
}

struct Fixture {
    profile: DynamicSignalProfile,
    interrupted: TaskStateSnapshot,
    fetch: TaskStateSnapshot,
    signal: DynamicSignalInfo,
    bytes: Vec<u8>,
    address: u64,
    post_exec_altstack_flags: u32,
}
impl Fixture {
    fn new(alternate: bool, edits: bool) -> Self {
        let profile = DynamicSignalProfile {
            signal: 44,
            action_mask: 1 << 14,
            queued_value: 0x13579bdf2468ace0,
            handler: 0x402000,
            restorer: 0x403000,
            delivery_pc: 0x401080,
            normal_stack: NORMAL..NORMAL + STACK_SIZE,
            alternate_stack: alternate.then_some(ALT..ALT + STACK_SIZE),
            frame_edits: edits.then_some(DynamicSignalFrameEdits {
                landing_pc: 0x405000,
                rax: (-22_i64) as u64,
                clear_carry: true,
                signal_mask: 1 << 9,
                xmm0: [0x9d; 16],
            }),
        };
        let registers = RegisterSnapshot {
            r15: 15,
            r14: 14,
            r13: 13,
            r12: 12,
            rbp: 5,
            rbx: 3,
            r11: 11,
            r10: 10,
            r9: 9,
            r8: 8,
            rax: 0x1122334455667788,
            rcx: 1,
            rdx: 2,
            rsi: 6,
            rdi: 7,
            orig_rax: 0x123,
            rip: profile.delivery_pc,
            cs: 0x33,
            eflags: 0xed7,
            rsp: NORMAL + 0xff00,
            ss: 0x2b,
            fs_base: 0x12340000,
            gs_base: 0x56780000,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        };
        let interrupted = TaskStateSnapshot {
            registers,
            xstate: vec![0x31; XSAVE_SIZE],
            mask: (1 << 9) | (1 << 11),
        };
        let address = if alternate { ALT } else { NORMAL } + FRAME_OFFSET;
        let fpstate = address + FP_OFFSET as u64;
        let mut fetch = interrupted.clone();
        fetch.registers.rip = profile.handler;
        fetch.registers.rsp = address;
        fetch.registers.rax = 0;
        fetch.registers.rdi = 44;
        fetch.registers.rsi = address + 312;
        fetch.registers.rdx = address + 8;
        fetch.registers.eflags = (registers.eflags & !0x400) | 0x10000;
        fetch.mask |= (1 << 43) | profile.action_mask;
        let mut signal = DynamicSignalInfo { raw: [0; 128] };
        write32(&mut signal.raw, 0, 44);
        write32(&mut signal.raw, 8, libc::SI_QUEUE as u32);
        write32(&mut signal.raw, 16, 1234);
        write32(&mut signal.raw, 20, 1000);
        write64(&mut signal.raw, 24, profile.queued_value);
        let mut bytes = vec![0x5a; FRAME_SIZE];
        for (at, value) in [
            (0, profile.restorer),
            (8, 7),
            (16, 0),
            (24, if alternate { ALT } else { 0 }),
            (40, if alternate { STACK_SIZE } else { 0 }),
            (192, 0x002b000000000033),
            (200, 0),
            (208, 3),
            (216, interrupted.mask),
            (224, 0x414000),
            (232, fpstate),
            (304, interrupted.mask),
        ] {
            write64(&mut bytes, at, value);
        }
        write32(
            &mut bytes,
            32,
            if alternate {
                0
            } else {
                libc::SS_DISABLE as u32
            },
        );
        let values = [
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            7,
            6,
            5,
            3,
            2,
            0x1122334455667788,
            1,
            NORMAL + 0xff00,
            0x401080,
            0xed7,
        ];
        for (index, value) in values.into_iter().enumerate() {
            write64(&mut bytes, 48 + index * 8, value);
        }
        bytes[312..440].copy_from_slice(&signal.raw);
        bytes[FP_OFFSET..FP_OFFSET + XSAVE_SIZE].copy_from_slice(&interrupted.xstate);
        write32(&mut bytes, FP_OFFSET + 464, 0x46505853);
        write32(&mut bytes, FP_OFFSET + 468, XSAVE_SIZE as u32 + 4);
        write32(&mut bytes, FP_OFFSET + 480, XSAVE_SIZE as u32);
        write32(&mut bytes, FRAME_SIZE - 4, 0x46505845);
        Self {
            profile,
            interrupted,
            fetch,
            signal,
            bytes,
            address,
            post_exec_altstack_flags: libc::SS_DISABLE as u32,
        }
    }
    fn read(&self, address: u64, length: usize) -> Result<Vec<u8>, GateError> {
        let start = address
            .checked_sub(self.address)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(GateError::Refused("synthetic read precedes frame"))?;
        let end = start
            .checked_add(length)
            .ok_or(GateError::Refused("synthetic read size overflow"))?;
        self.bytes
            .get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or(GateError::Refused("synthetic read exceeds frame"))
    }
    fn capture_with(
        &self,
        read: impl FnMut(u64, usize) -> Result<Vec<u8>, GateError>,
    ) -> Result<CapturedFrame, GateError> {
        CapturedFrame::read(
            read,
            ID,
            &self.profile,
            &self.interrupted,
            &self.fetch,
            &self.signal,
            AnchoredFrameState {
                metadata: original_metadata(),
                post_exec_altstack_flags: self.post_exec_altstack_flags,
            },
        )
    }
    fn capture(&self) -> CapturedFrame {
        self.capture_with(|address, length| self.read(address, length))
            .unwrap()
    }
    fn projection(&self) -> Vec<u8> {
        let mut expected = self.bytes.clone();
        write64(&mut expected, 200, 7);
        write64(&mut expected, 208, 14);
        write64(&mut expected, 224, 0x900000);
        expected
    }
    fn final_bytes(&self) -> Vec<u8> {
        let mut expected = self.projection();
        if self.profile.frame_edits.is_some() {
            write64(&mut expected, 176, 0x405000);
            write64(&mut expected, 152, (-22_i64) as u64);
            write64(&mut expected, 184, 0xed6);
            write64(&mut expected, 304, 1 << 9);
            expected[FP_OFFSET + 160..FP_OFFSET + 176].fill(0x9d);
        }
        expected
    }
}

#[test]
fn projection_preserves_every_byte_outside_three_metadata_words() {
    for alternate in [false, true] {
        let fixture = Fixture::new(alternate, false);
        let captured = fixture.capture();
        assert_eq!(captured.raw.id, ID);
        assert_eq!(captured.projected.id, ID);
        assert_eq!(captured.raw.version, 0);
        assert_eq!(captured.projected.version, 1);
        assert_eq!(captured.raw.address, fixture.address);
        assert_eq!(captured.raw.fpstate, fixture.address + FP_OFFSET as u64);
        assert_eq!(captured.projected.address, captured.raw.address);
        assert_eq!(captured.projected.fpstate, captured.raw.fpstate);
        assert_eq!(captured.raw.bytes, fixture.bytes);
        assert_eq!(captured.projected.bytes, fixture.projection());
        assert_eq!(captured.final_image, fixture.projection());
        assert_ne!(captured.raw.bytes, captured.projected.bytes);
        assert_eq!(
            CapturedFrame::metadata(&captured.projected.bytes).unwrap(),
            original_metadata()
        );
        for index in 0..FRAME_SIZE {
            if ![200..216, 224..232]
                .iter()
                .any(|range| range.contains(&index))
            {
                assert_eq!(captured.raw.bytes[index], captured.projected.bytes[index]);
            }
        }
    }
}

#[test]
fn incomplete_header_fp_and_full_reads_never_create_a_frame() {
    let fixture = Fixture::new(false, false);
    for short_read in 1..=3 {
        let mut count = 0;
        let result = fixture.capture_with(|address, length| {
            count += 1;
            let mut bytes = fixture.read(address, length)?;
            if count == short_read {
                bytes.pop();
            }
            Ok(bytes)
        });
        assert!(result.is_err(), "truncated observation {short_read}");
    }
    for failed_read in 1..=3 {
        let mut count = 0;
        let result = fixture.capture_with(|address, length| {
            count += 1;
            if count == failed_read {
                return Err(GateError::Refused("injected read failure"));
            }
            fixture.read(address, length)
        });
        assert!(result.is_err(), "failed observation {failed_read}");
    }
}

#[test]
fn full_capture_must_agree_with_both_earlier_layout_reads() {
    let fixture = Fixture::new(false, false);
    for changed_offset in [
        24,
        304,
        FP_OFFSET + 160,
        FP_OFFSET + 464,
        FP_OFFSET + 468,
        FP_OFFSET + 480,
    ] {
        let mut count = 0;
        let result = fixture.capture_with(|address, length| {
            count += 1;
            let mut bytes = fixture.read(address, length)?;
            if count == 3 {
                bytes[changed_offset] ^= 1;
            }
            Ok(bytes)
        });
        assert!(result.is_err(), "changed final read at {changed_offset}");
    }
}

#[test]
fn saved_gpr_flags_segments_masks_and_signal_bytes_are_exact() {
    for changed_offset in (48..200)
        .step_by(8)
        .chain([0, 8, 16, 24, 32, 40, 216, 304, 312, 336])
    {
        let mut fixture = Fixture::new(true, false);
        fixture.bytes[changed_offset] ^= 1;
        assert!(
            fixture
                .capture_with(|address, length| fixture.read(address, length))
                .is_err(),
            "corrupt fixed frame field at {changed_offset}"
        );
    }
    // The anchor supplies one exact pre-exec stored flag, not a two-value
    // allowance. Exec removes the old range while retaining that flag.
    for anchored in [0_u32, libc::SS_DISABLE as u32] {
        let mut fixture = Fixture::new(false, false);
        fixture.post_exec_altstack_flags = anchored;
        write32(&mut fixture.bytes, 32, anchored);
        let captured = fixture.capture();
        assert_eq!(captured.raw.bytes, fixture.bytes);
        assert_eq!(captured.projected.bytes, fixture.projection());
        let wrong = if anchored == 0 {
            libc::SS_DISABLE as u32
        } else {
            0
        };
        for observed in [wrong, libc::SS_ONSTACK as u32, 0x8000_0000, u32::MAX] {
            write32(&mut fixture.bytes, 32, observed);
            assert!(matches!(
                fixture.capture_with(|address, length| fixture.read(address, length)),
                Err(GateError::Refused(
                    "signal frame saved alternate stack differs"
                ))
            ));
        }

        // A genuine configured application altstack supersedes the disabled
        // post-exec range; its exact flags remain zero for either anchor.
        let mut fixture = Fixture::new(true, false);
        fixture.post_exec_altstack_flags = anchored;
        let captured = fixture.capture();
        assert_eq!(captured.raw.bytes, fixture.bytes);
        assert_eq!(captured.projected.bytes, fixture.projection());
        for observed in [
            libc::SS_DISABLE as u32,
            libc::SS_ONSTACK as u32,
            0x8000_0000,
        ] {
            write32(&mut fixture.bytes, 32, observed);
            assert!(matches!(
                fixture.capture_with(|address, length| fixture.read(address, length)),
                Err(GateError::Refused(
                    "signal frame saved alternate stack differs"
                ))
            ));
        }
    }
    for alternate in [false, true] {
        for unsupported in [libc::SS_ONSTACK as u32, 0x8000_0000, u32::MAX] {
            let mut fixture = Fixture::new(alternate, false);
            fixture.post_exec_altstack_flags = unsupported;
            assert!(matches!(
                fixture.capture_with(|address, length| fixture.read(address, length)),
                Err(GateError::Refused(
                    "signal frame anchor alternate-stack flags differ"
                ))
            ));
        }
    }
}

#[test]
fn unbounded_misaligned_and_malformed_fp_storage_refuses() {
    for pointer in [0, 0x70e100, 0x70e201, u64::MAX - 16, 0x710000] {
        let mut fixture = Fixture::new(false, false);
        write64(&mut fixture.bytes, 232, pointer);
        assert!(
            fixture
                .capture_with(|address, length| fixture.read(address, length))
                .is_err()
        );
    }
    for (offset, value) in [
        (FP_OFFSET + 464, 0),
        (FP_OFFSET + 468, 512),
        (FP_OFFSET + 480, 512),
        (FP_OFFSET + 480, 65537),
        (FRAME_SIZE - 4, 0),
    ] {
        let mut fixture = Fixture::new(false, false);
        write32(&mut fixture.bytes, offset, value);
        assert!(
            fixture
                .capture_with(|address, length| fixture.read(address, length))
                .is_err()
        );
    }
}

#[test]
fn handler_abi_and_original_stack_bounds_cannot_be_guessed() {
    for mutation in 0..12 {
        let mut fixture = Fixture::new(false, false);
        match mutation {
            0 => fixture.fetch.registers.rip += 1,
            1 => fixture.fetch.registers.rdi += 1,
            2 => fixture.fetch.registers.rsi += 1,
            3 => fixture.fetch.registers.rdx += 1,
            4 => fixture.fetch.registers.rax = 1,
            5 => fixture.fetch.registers.cs = 0x23,
            6 => fixture.fetch.registers.ss = 0,
            7 => fixture.fetch.registers.rsp += 1,
            8 => fixture.interrupted.registers.rsp = NORMAL,
            9 => fixture.interrupted.registers.rsp = NORMAL + STACK_SIZE + 1,
            10 => fixture.interrupted.registers.eflags |= 0x100,
            11 => fixture.interrupted.registers.eflags |= 0x10000,
            _ => unreachable!(),
        }
        assert!(
            fixture
                .capture_with(|address, length| fixture.read(address, length))
                .is_err(),
            "invalid original/handler ABI case {mutation}"
        );
    }
    for alternate in [false, true] {
        for bit in 0..64 {
            let mut fixture = Fixture::new(alternate, false);
            fixture.fetch.mask ^= 1_u64 << bit;
            assert!(
                fixture
                    .capture_with(|address, length| fixture.read(address, length))
                    .is_err(),
                "handler mask bit {bit} differs with alternate stack {alternate}"
            );
        }
    }
}

fn editable_fields() -> [Range<usize>; 5] {
    [
        176..184,
        152..160,
        184..192,
        304..312,
        FP_OFFSET + 160..FP_OFFSET + 176,
    ]
}

#[test]
fn all_declared_edit_subsets_remain_exact_and_return_requires_every_edit() {
    let fixture = Fixture::new(true, true);
    let captured = fixture.capture();
    let projected = fixture.projection();
    let final_bytes = fixture.final_bytes();
    assert_eq!(captured.final_image, final_bytes);
    for subset in 0..32 {
        let mut current = projected.clone();
        for (index, range) in editable_fields().into_iter().enumerate() {
            if subset & (1 << index) != 0 {
                current[range.clone()].copy_from_slice(&final_bytes[range]);
            }
        }
        assert_eq!(
            captured.validate_current(current.clone(), false).unwrap(),
            current
        );
        assert_eq!(
            captured.validate_current(current.clone(), true).is_ok(),
            subset == 31
        );
    }
    assert_eq!(captured.raw.bytes, fixture.bytes);
    assert_eq!(captured.projected.bytes, projected);
}

#[test]
fn every_undeclared_byte_including_padding_metadata_and_fp_is_immutable() {
    let fixture = Fixture::new(true, true);
    let captured = fixture.capture();
    let expected = fixture.projection();
    for index in 0..expected.len() {
        if editable_fields().iter().any(|range| range.contains(&index)) {
            continue;
        }
        let mut changed = expected.clone();
        changed[index] ^= 1;
        assert!(
            captured.validate_current(changed, false).is_err(),
            "undeclared byte {index} became writable"
        );
    }
}

#[test]
fn neither_torn_declared_fields_nor_unlisted_flag_edits_are_allowed() {
    let fixture = Fixture::new(true, true);
    let captured = fixture.capture();
    for offset in [152, FP_OFFSET + 160] {
        let mut torn = fixture.projection();
        torn[offset] = fixture.final_bytes()[offset];
        assert!(captured.validate_current(torn, false).is_err());
    }
    let mut third_pc = fixture.projection();
    write64(&mut third_pc, 176, 0x406000);
    assert!(captured.validate_current(third_pc, false).is_err());
    let mut changed_df = fixture.projection();
    write64(&mut changed_df, 184, 0xad6);
    assert!(captured.validate_current(changed_df, false).is_err());
    let mut changed_mask = fixture.projection();
    write64(&mut changed_mask, 304, 1 << 10);
    assert!(captured.validate_current(changed_mask, false).is_err());
}

#[test]
fn live_frame_length_and_unedited_policy_never_relax() {
    let fixture = Fixture::new(false, false);
    let captured = fixture.capture();
    let expected = fixture.projection();
    for final_only in [false, true] {
        assert_eq!(
            captured
                .validate_current(expected.clone(), final_only)
                .unwrap(),
            expected
        );
        for length in [0, expected.len() - 1, expected.len() + 1] {
            let mut changed = expected.clone();
            changed.resize(length, 0);
            assert!(captured.validate_current(changed, final_only).is_err());
        }
        let mut undeclared = expected.clone();
        undeclared[152] ^= 1;
        assert!(captured.validate_current(undeclared, final_only).is_err());
    }
}

#[test]
fn errno_looking_return_changes_only_declared_state_and_native_bookkeeping() {
    for edits in [false, true] {
        let fixture = Fixture::new(true, edits);
        let captured = fixture.capture();
        let before = fixture.interrupted.clone();
        let mut expected = before.clone();
        expected.registers.orig_rax = u64::MAX;
        if edits {
            expected.registers.rip = 0x405000;
            expected.registers.rax = (-22_i64) as u64;
            expected.registers.eflags = 0xed6;
            expected.mask = 1 << 9;
            expected.xstate[160..176].fill(0x9d);
        }
        assert_eq!(
            captured.expected_return(&before, &fixture.profile).unwrap(),
            expected
        );
        assert_eq!(fixture.interrupted, before);
        assert_eq!(captured.raw.bytes, fixture.bytes);
        assert_eq!(captured.projected.bytes, fixture.projection());
    }
}
