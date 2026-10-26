//! Pure eligibility controls. These fabricated snapshots establish no held
//! source proof, native control-lineage certificate or execution completion.
use super::super::super::runtime_instruction::{DebugDisposition, classify};
use super::*;
use crate::selected::SyscallAliases;
use liteinst_admission::scan::{Boundary, Snapshot, WriteControl};
use liteinst_admission::{Generation, MappingId};

fn input_test(bytes: &[u8], pc: u64, test: impl FnOnce(&Snapshot, &RegisterSnapshot)) {
    let snapshot = Snapshot::new(
        MappingId(19),
        Generation(0),
        pc,
        bytes.to_vec(),
        Boundary::Unknown,
        Boundary::Unknown,
        WriteControl::Owned,
    )
    .unwrap();
    // Deliberately invalid data addresses. The accepted profile must not
    // perform an implicit read/write or indirect-target read using them.
    let registers = RegisterSnapshot {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        rbp: 0x3000,
        rbx: 3,
        r11: 11,
        r10: 10,
        r9: 9,
        r8: 8,
        rax: u64::MAX,
        rcx: 1,
        rdx: 2,
        rsi: 6,
        rdi: 7,
        orig_rax: u64::MAX,
        rip: pc,
        cs: 0x33,
        eflags: 0x202,
        rsp: u64::MAX,
        ss: 0x2b,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    };
    test(&snapshot, &registers);
}

fn candidate_test(bytes: &[u8], pc: u64, test: impl FnOnce(&InstructionCandidate<'_>)) {
    input_test(bytes, pc, |snapshot, registers| {
        let candidate = classify(
            snapshot,
            registers,
            DebugDisposition::Absent,
            &SyscallAliases::default(),
        )
        .unwrap();
        test(&candidate);
    });
}

#[test]
fn register_and_immediate_encodings_need_no_data_footprint() {
    for bytes in [
        &[0x48, 0x89, 0xc3][..],
        &[0xb8, 9, 0, 0, 0],
        &[0x66, 0x83, 0xc3, 1],
        &[0x48, 0x31, 0xd2],
        &[0x48, 0x39, 0xc3],
        &[0x84, 0xc0],
        &[0x48, 0x83, 0xe8, 1],
    ] {
        candidate_test(bytes, 0x1000, |candidate| {
            assert!(require_operand_free(candidate, &(0x8000..0x9000)).is_ok());
        });
    }
}

#[test]
fn lea_and_memory_encoded_nop_access_no_data() {
    for bytes in [&[0x48, 0x8d, 0x58, 0x08][..], &[0x0f, 0x1f, 0x40, 0x00]] {
        candidate_test(bytes, 0x1000, |candidate| {
            assert!(require_operand_free(candidate, &(0x8000..0x9000)).is_ok());
        });
    }
}

#[test]
fn actual_load_store_and_compare_memory_need_separate_footprints() {
    for bytes in [
        &[0x48, 0x8b, 0x18][..],
        &[0x48, 0x89, 0x18],
        &[0x48, 0x39, 0x18],
        &[0x48, 0x83, 0x00, 1],
    ] {
        candidate_test(bytes, 0x1000, |candidate| {
            assert!(matches!(
                require_operand_free(candidate, &(0x8000..0x9000)),
                Err(GateError::Refused(
                    "runtime ordinary data-access footprint is unqualified"
                ))
            ));
        });
    }
}

#[test]
fn stack_and_calls_remain_ineligible_even_at_exact_source_page_end() {
    for bytes in [&[0x50][..], &[0x58], &[0xc3], &[0xe8, 0, 0, 0, 0]] {
        candidate_test(bytes, 0x2000 - bytes.len() as u64, |candidate| {
            assert_eq!(candidate.next_pc(), 0x2000);
            assert_eq!(candidate.snapshot().range().end(), 0x2000);
            assert!(matches!(
                require_operand_free(candidate, &(0x8000..0x9000)),
                Err(GateError::Refused(
                    "runtime ordinary stack footprint is unqualified"
                ))
            ));
        });
    }
}

#[test]
fn both_register_and_memory_indirect_jumps_require_their_own_proof() {
    for bytes in [&[0xff, 0xe0][..], &[0xff, 0x20]] {
        candidate_test(bytes, 0x1000, |candidate| {
            assert!(matches!(
                require_operand_free(candidate, &(0x8000..0x9000)),
                Err(GateError::Refused(
                    "runtime indirect-transfer footprint is unqualified"
                ))
            ));
        });
    }
}

#[test]
fn relative_self_branch_and_unseen_next_page_are_eligible_descriptions() {
    for bytes in [&[0xeb, 0xfe][..], &[0x75, 0xfe], &[0x90]] {
        candidate_test(bytes, 0x2000 - bytes.len() as u64, |candidate| {
            assert_eq!(candidate.next_pc(), 0x2000);
            assert!(require_operand_free(candidate, &(0x8000..0x9000)).is_ok());
        });
    }
}

#[test]
fn branch_target_fallthrough_and_current_pc_exclude_private_code() {
    for (bytes, pc) in [
        (&[0xeb, 0x00][..], 0x7ffe),
        (&[0x90][..], 0x7fff),
        (&[0x90][..], 0x8000),
    ] {
        candidate_test(bytes, pc, |candidate| {
            assert!(matches!(
                require_operand_free(candidate, &(0x8000..0x9000)),
                Err(GateError::Refused(
                    "runtime ordinary continuation enters private or fixed code"
                ))
            ));
        });
    }
    candidate_test(&[0xeb, 0x00], VSYSCALL_START - 2, |candidate| {
        assert!(require_operand_free(candidate, &(0x8000..0x9000)).is_err());
    });
    assert!(require_original_pc(0x9000, &(0x8000..0x9000)).is_ok());
    assert!(require_original_pc(VSYSCALL_END, &(0x8000..0x9000)).is_ok());
}

#[test]
fn selected_candidate_never_enters_ordinary_transport() {
    candidate_test(&[0x0f, 0xa2], 0x1000, |candidate| {
        assert!(matches!(
            require_operand_free(candidate, &(0x8000..0x9000)),
            Err(GateError::Refused(
                "runtime selected instruction needs its own completion"
            ))
        ));
    });
}

#[test]
fn unsupported_inc_is_refused_by_the_closed_classifier() {
    input_test(&[0x48, 0xff, 0xc0], 0x1000, |snapshot, registers| {
        assert!(matches!(
            classify(
                snapshot,
                registers,
                DebugDisposition::Absent,
                &SyscallAliases::default()
            ),
            Err(
                super::super::super::runtime_instruction::InstructionRefusal::Unsupported(
                    iced_x86::Code::Inc_rm64
                )
            )
        ));
    });
}
