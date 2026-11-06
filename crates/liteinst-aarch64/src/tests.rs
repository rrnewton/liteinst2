use super::*;

#[test]
fn decodes_the_exclusive_pair_of_a_gcc_rmw_loop() {
    // ldaxr x4, [x3] / add x4, x4, #1 / stlxr w5, x4, [x3] / cbnz w5, -12
    assert_eq!(
        decode(0xc85f_fc64),
        Insn::LoadExcl {
            size: Size::X,
            ord: Ordering {
                acquire: true,
                release: false
            },
            rt: 4,
            rn: 3
        }
    );
    assert_eq!(
        decode(0x9100_0484),
        Insn::Alu {
            op: AluOp::Add,
            sf: true,
            rd: 4,
            rn: 4,
            operand: Operand::Imm(1)
        }
    );
    assert_eq!(
        decode(0xc805_fc64),
        Insn::StoreExcl {
            size: Size::X,
            ord: Ordering {
                acquire: false,
                release: true
            },
            rs: 5,
            rt: 4,
            rn: 3
        }
    );
    assert_eq!(
        decode(0x35ff_ffa5),
        Insn::CompareBranch {
            nonzero: true,
            sf: false,
            rt: 5,
            offset: -12
        }
    );
}

#[test]
fn exclusive_size_field_decodes_every_width() {
    // Regression cover for the Size::from_bits audit: the only call site
    // passes bits 31:30, and every two-bit pattern must map to its size.
    for (bits, size) in [(0, Size::B), (1, Size::H), (2, Size::W), (3, Size::X)] {
        let word = (0xc85f_fc64 & 0x3fff_ffff) | (bits << 30);
        assert_eq!(
            decode(word),
            Insn::LoadExcl {
                size,
                ord: Ordering {
                    acquire: true,
                    release: false
                },
                rt: 4,
                rn: 3
            },
            "size bits {bits:#b}"
        );
    }
}

#[test]
fn a_compare_and_swap_is_not_decoded_as_an_exclusive() {
    // casa w1, w2, [x0] shares the exclusive major group but sets bit 23.
    assert_eq!(decode(0x88e1_7c02), Insn::Other);
}

#[test]
fn pairs_are_recognised_and_never_treated_as_single_exclusives() {
    // ldaxp x0, x1, [x2] / stlxp w3, x4, x5, [x2]
    assert_eq!(decode(0xc87f_8440), Insn::ExclPair);
    assert_eq!(decode(0xc823_9444), Insn::ExclPair);
}

#[test]
fn svc_and_brk_carry_imm16_while_hvc_smc_stay_other() {
    assert_eq!(decode(0xd400_0001), Insn::Svc { imm16: 0 });
    assert_eq!(decode(svc(0xffff)), Insn::Svc { imm16: 0xffff });
    assert_eq!(decode(brk(0x1234)), Insn::Brk { imm16: 0x1234 });
    assert_eq!(brk(0x1234), 0xd420_0000 | (0x1234 << 5));
    // HVC #0 and SMC #0 share the exception-generation group; neither
    // may be mistaken for a patchable supervisor call.
    assert_eq!(decode(0xd400_0002), Insn::Other);
    assert_eq!(decode(0xd400_0003), Insn::Other);
    for imm in [0u16, 1, 0x7fff, 0x8000, 0xffff] {
        assert_eq!(decode(svc(imm)), Insn::Svc { imm16: imm });
        assert_eq!(decode(brk(imm)), Insn::Brk { imm16: imm });
    }
}

#[test]
fn adr_and_adrp_offsets_are_signed_and_scaled() {
    assert_eq!(
        decode(adr(false, 3, -4).unwrap()),
        Insn::Adr {
            page: false,
            rd: 3,
            offset: -4
        }
    );
    assert_eq!(
        decode(adr(true, 2, 0x1000).unwrap()),
        Insn::Adr {
            page: true,
            rd: 2,
            offset: 0x1000
        }
    );
    // ADR reaches a signed byte offset; ADRP needs whole 4 KiB pages.
    assert!(adr(false, 0, (1 << 20) - 1).is_some());
    assert_eq!(adr(false, 0, 1 << 20), None);
    assert!(adr(true, 0, -(1 << 32)).is_some());
    assert_eq!(adr(true, 0, 0x1001), None);
    for offset in [-1i64, 0, 1, 123_457, -(1 << 20)] {
        assert_eq!(
            decode(adr(false, 9, offset).unwrap()).pc_relative_offset(),
            Some(offset)
        );
    }
}

fn literal_word(opc: u32, simd: bool, imm19: u32, rt: Reg) -> u32 {
    (opc << 30) | (0b011 << 27) | ((simd as u32) << 26) | ((imm19 & 0x7ffff) << 5) | rt as u32
}

#[test]
fn load_literal_classes_and_offsets() {
    for (opc, simd, class) in [
        (0, false, LiteralClass::Word32),
        (1, false, LiteralClass::Word64),
        (2, false, LiteralClass::SignedWord),
        (3, false, LiteralClass::Prefetch),
        (0, true, LiteralClass::Simd32),
        (1, true, LiteralClass::Simd64),
        (2, true, LiteralClass::Simd128),
    ] {
        assert_eq!(
            decode(literal_word(opc, simd, 2, 7)),
            Insn::LoadLiteral {
                class,
                rt: 7,
                offset: 8
            },
            "opc {opc} simd {simd}"
        );
    }
    // Negative imm19 reaches backwards; V=1 opc=0b11 is unallocated.
    assert_eq!(
        decode(literal_word(1, false, 0x7ffff, 0)).pc_relative_offset(),
        Some(-4)
    );
    assert_eq!(decode(literal_word(3, true, 0, 0)), Insn::Other);
}

#[test]
fn branch_offsets_are_signed_byte_offsets() {
    assert_eq!(
        decode(0x1400_0002),
        Insn::Branch {
            link: false,
            offset: 8
        }
    );
    assert_eq!(
        decode(0x17ff_fffe),
        Insn::Branch {
            link: false,
            offset: -8
        }
    );
    assert_eq!(
        decode(0x5400_0061),
        Insn::CondBranch {
            cond: 1,
            offset: 12
        }
    );
    // BL carries the same imm26 range as B: +/-128 MiB in bytes.
    assert_eq!(
        decode(branch(true, (1 << 27) - 4).unwrap()),
        Insn::Branch {
            link: true,
            offset: (1 << 27) - 4
        }
    );
    assert_eq!(branch(false, 1 << 27), None);
    assert_eq!(branch(false, 2), None);
    assert_eq!(cond_branch(0, 1 << 20), None);
}

#[test]
fn a_bc_cond_decodes_as_the_conditional_branch_it_is() {
    // BC.ne .+8 (FEAT_HBC) differs from B.cond only in bit 4.
    assert_eq!(decode(0x5400_0051), Insn::CondBranch { cond: 1, offset: 8 });
    assert_eq!(
        decode(0x5400_0061),
        Insn::CondBranch {
            cond: 1,
            offset: 12
        }
    );
}

#[test]
fn test_branch_carries_register_bit_and_offset() {
    for bit in [0u32, 31, 32, 63] {
        assert_eq!(
            decode(test_branch(true, 5, bit, -8).unwrap()),
            Insn::TestBranch {
                nonzero: true,
                rt: 5,
                bit,
                offset: -8
            },
            "bit {bit}"
        );
    }
    assert_eq!(test_branch(false, 0, 64, 0), None);
    assert_eq!(test_branch(false, 0, 0, 1 << 15), None);
}

#[test]
fn cmpbr_branches_decode_with_full_operands() {
    // CBEQ X6, X6, .+8 (register, cc=0b110).
    assert_eq!(
        decode(0xf4c6_0046),
        Insn::CompareAndBranch {
            sf: true,
            cc: 0b110,
            rt: 6,
            operand: CmpOperand::Reg {
                rm: 6,
                extend: CmpExtend::Full
            },
            offset: 8
        }
    );
    // CBEQ X6, #0, .+8 (immediate, cc=0b110).
    assert_eq!(
        decode(0xf5c0_0046),
        Insn::CompareAndBranch {
            sf: true,
            cc: 0b110,
            rt: 6,
            operand: CmpOperand::Imm(0),
            offset: 8
        }
    );
    // CBBEQ / CBHEQ W6, W6, .+8 (byte/half extended register forms).
    for (word, extend) in [
        (0x74c6_8046, CmpExtend::Byte),
        (0x74c6_c046, CmpExtend::Half),
    ] {
        assert_eq!(
            decode(word),
            Insn::CompareAndBranch {
                sf: false,
                cc: 0b110,
                rt: 6,
                operand: CmpOperand::Reg { rm: 6, extend },
                offset: 8
            },
            "{word:#x}"
        );
    }
}

#[test]
fn cmpbr_unallocated_combinations_stay_other() {
    // Register sz=0b01 is unallocated.
    assert_eq!(decode(0xf4c6_0046 | (0b01 << 14)), Insn::Other);
    // Byte form with sf=1 is unallocated (CBB/CBH are 32-bit only).
    assert_eq!(decode(0xf4c6_8046), Insn::Other);
    // Immediate form with bit 14 set is unallocated.
    assert_eq!(decode(0xf5c0_0046 | (1 << 14)), Insn::Other);
    // cc=0b100 and 0b101 name no condition in either form.
    for cc in [0b100u32, 0b101] {
        let reg = (0xf4c6_0046 & !(0x7 << 21)) | (cc << 21);
        let imm = (0xf5c0_0046 & !(0x7 << 21)) | (cc << 21);
        assert_eq!(decode(reg), Insn::Other, "cc {cc:#b}");
        assert_eq!(decode(imm), Insn::Other, "cc {cc:#b}");
    }
}

#[test]
fn register_branches_and_bti_pads_decode() {
    assert_eq!(
        decode(0xd61f_0200),
        Insn::BranchReg {
            kind: BranchRegKind::Branch,
            rn: 16
        }
    );
    // BLR X8: the zpoline-analogue word, 0xD63F0000 | (8 << 5).
    assert_eq!(
        decode(0xd63f_0100),
        Insn::BranchReg {
            kind: BranchRegKind::Link,
            rn: 8
        }
    );
    assert_eq!(
        decode(0xd65f_03c0),
        Insn::BranchReg {
            kind: BranchRegKind::Return,
            rn: 30
        }
    );
    for target in [
        BtiTarget::None,
        BtiTarget::Call,
        BtiTarget::Jump,
        BtiTarget::JumpCall,
    ] {
        assert_eq!(decode(bti(target)), Insn::Bti { target });
    }
}

#[test]
fn decode_le_needs_a_full_word() {
    assert_eq!(decode_le(&[]), None);
    assert_eq!(decode_le(&[0x01, 0x00, 0x00]), None);
    assert_eq!(
        decode_le(&0xd400_0001u32.to_le_bytes()),
        Some(Insn::Svc { imm16: 0 })
    );
}

#[test]
fn checked_encoders_reject_out_of_range_registers() {
    // Reg is an unrestricted u8; checked encoders must refuse values
    // that do not fit the five-bit field instead of spilling into the
    // neighbouring immediate (review witness: adr(false, 32, 0) once
    // emitted 0x1000_0020, which decodes as rd 0, offset +4).
    assert_eq!(
        decode(0x1000_0020),
        Insn::Adr {
            page: false,
            rd: 0,
            offset: 4
        }
    );
    for reg in [32u8, 33, 63, 255] {
        assert_eq!(adr(false, reg, 0), None, "adr rd {reg}");
        assert_eq!(adr(true, reg, 0), None, "adrp rd {reg}");
        assert_eq!(compare_branch(false, true, reg, 0), None, "cbz rt {reg}");
        assert_eq!(compare_branch(true, false, reg, 0), None, "cbnz rt {reg}");
        assert_eq!(test_branch(false, reg, 0, 0), None, "tbz rt {reg}");
        assert_eq!(test_branch(true, reg, 63, 0), None, "tbnz rt {reg}");
        assert_eq!(movz_for(true, reg, 1), None, "movz_for rd {reg}");
    }
    // The condition field gets the same treatment: 4 bits, no masking.
    assert_eq!(cond_branch(16, 0), None);
    assert_eq!(cond_branch(u32::MAX, 0), None);
}

#[test]
fn checked_encoders_accept_register_31() {
    // Boundary just below refusal: every checked family still encodes
    // register 31 and decodes it back unchanged.
    assert_eq!(
        decode(adr(false, 31, 0).unwrap()),
        Insn::Adr {
            page: false,
            rd: 31,
            offset: 0
        }
    );
    assert_eq!(
        decode(compare_branch(true, true, 31, 8).unwrap()),
        Insn::CompareBranch {
            nonzero: true,
            sf: true,
            rt: 31,
            offset: 8
        }
    );
    assert_eq!(
        decode(test_branch(false, 31, 63, -4).unwrap()),
        Insn::TestBranch {
            nonzero: false,
            rt: 31,
            bit: 63,
            offset: -4
        }
    );
    assert!(movz_for(true, 31, 1).is_some());
    assert!(cond_branch(15, 0).is_some());
}

#[test]
fn unknown_encodings_decode_as_other() {
    for word in [0xf900_0000, 0x9ac0_0800, 0xd400_0002, 0xd400_0003] {
        assert_eq!(decode(word), Insn::Other, "word {word:#010x}");
    }
}
