//! Differential tests against the `yaxpeax-arm` oracle (dev-dependency
//! only). The oracle is a reference where it decodes: encodings it
//! rejects (for example SVE/SME space and, in 0.5.0, FEAT_CMPBR) make no
//! assertion either way. Where both decoders classify a word, the
//! PC-relative offsets and SVC/BRK immediates must agree exactly.

use super::*;
use yaxpeax_arch::{Arch, Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{ARMv8, Instruction, Opcode, Operand};

fn oracle(word: u32) -> Option<Instruction> {
    let bytes = word.to_le_bytes();
    let mut reader = U8Reader::new(&bytes);
    <ARMv8 as Arch>::Decoder::default().decode(&mut reader).ok()
}

fn oracle_pc_offset(inst: &Instruction) -> Option<i64> {
    inst.operands.iter().find_map(|op| match op {
        Operand::PCOffset(value) => Some(*value),
        _ => None,
    })
}

fn oracle_imm16(inst: &Instruction) -> Option<u16> {
    inst.operands.iter().find_map(|op| match op {
        Operand::Imm16(value) => Some(*value),
        _ => None,
    })
}

fn literal_word(opc: u32, simd: bool, imm19: u32, rt: Reg) -> u32 {
    (opc << 30) | (0b011 << 27) | ((simd as u32) << 26) | ((imm19 & 0x7ffff) << 5) | rt as u32
}

/// Every word our own encoders can emit for the branch/PC-relative
/// families must decode under the oracle to the same offset.
#[test]
fn directed_encoders_agree_with_oracle() {
    fn check(word: u32) {
        let ours = decode(word);
        let theirs = oracle(word)
            .unwrap_or_else(|| panic!("oracle rejected directed word {word:#010x} ({ours:?})"));
        assert_eq!(
            ours.pc_relative_offset(),
            oracle_pc_offset(&theirs),
            "word {word:#010x} ours {ours:?} oracle {:?}",
            theirs.opcode
        );
    }
    for link in [false, true] {
        for offset in [-(1 << 27), -4, 0, 4, (1 << 27) - 4] {
            check(branch(link, offset).unwrap());
        }
    }
    for cond in 0..16 {
        check(cond_branch(cond, -8).unwrap());
        check(cond_branch(cond, 8).unwrap());
    }
    for sf in [false, true] {
        for nonzero in [false, true] {
            for rt in [0, 5, 31] {
                check(compare_branch(nonzero, sf, rt, 16).unwrap());
            }
        }
    }
    for bit in [0, 31, 32, 63] {
        check(test_branch(false, 3, bit, -16).unwrap());
        check(test_branch(true, 3, bit, 16).unwrap());
    }
    for offset in [-4096, -1, 0, 1, 4095] {
        check(adr(false, 4, offset).unwrap());
    }
    for pages in [-2i64, -1, 0, 1, 2] {
        check(adr(true, 4, pages * 4096).unwrap());
    }
    for opc in 0..3 {
        check(literal_word(opc, false, 0x7fffe, 9));
    }
}

#[test]
fn svc_and_brk_agree_with_oracle_exactly() {
    for imm in [0u16, 1, 0x1234, 0x8000, 0xffff] {
        for (word, opcode) in [(svc(imm), Opcode::SVC), (brk(imm), Opcode::BRK)] {
            let theirs = oracle(word).expect("oracle decodes SVC/BRK");
            assert_eq!(theirs.opcode, opcode, "word {word:#010x}");
            assert_eq!(oracle_imm16(&theirs), Some(imm), "word {word:#010x}");
        }
    }
}

#[test]
fn cmpbr_offsets_agree_where_oracle_decodes() {
    // yaxpeax-arm 0.5.0 has no FEAT_CMPBR; this asserts agreement only
    // if a future oracle decodes these words, and pins our own decode
    // either way (encoding fields per LLVM AArch64InstrFormats.td).
    for word in [0xf4c6_0046u32, 0xf5c0_0046, 0x74c6_8046, 0x74c6_c046] {
        assert_eq!(decode(word).pc_relative_offset(), Some(8));
        if let Some(theirs) = oracle(word)
            && let Some(offset) = oracle_pc_offset(&theirs)
        {
            assert_eq!(offset, 8, "word {word:#010x}");
        }
    }
}

/// Deterministic xorshift sweep over the comparator this suite actually
/// has: SVC/BRK identity plus immediate must match in both directions,
/// and PC-relative offsets must match wherever both decoders expose one.
/// This is not full decode equivalence (other operand fields are not
/// compared), and oracle rejections skip the word.
#[test]
fn seeded_sweep_agrees_where_oracle_decodes() {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut compared_offsets = 0u32;
    for _ in 0..60_000 {
        let word = (next() >> 32) as u32;
        let ours = decode(word);
        let Some(theirs) = oracle(word) else { continue };
        match (ours, theirs.opcode) {
            (Insn::Svc { imm16 }, Opcode::SVC) | (Insn::Brk { imm16 }, Opcode::BRK) => {
                assert_eq!(oracle_imm16(&theirs), Some(imm16), "word {word:#010x}");
            }
            (Insn::Svc { .. }, _) | (Insn::Brk { .. }, _) => {
                panic!(
                    "word {word:#010x}: ours {ours:?} oracle {:?}",
                    theirs.opcode
                );
            }
            (_, Opcode::SVC) | (_, Opcode::BRK) => {
                panic!(
                    "word {word:#010x}: oracle {:?} ours {ours:?}",
                    theirs.opcode
                );
            }
            _ => {}
        }
        if let (Some(mine), Some(theirs_offset)) =
            (ours.pc_relative_offset(), oracle_pc_offset(&theirs))
        {
            // ADRP carries a page offset in both decoders; every other
            // compared family carries a plain byte offset.
            assert_eq!(
                mine, theirs_offset,
                "word {word:#010x} ours {ours:?} oracle {:?}",
                theirs.opcode
            );
            compared_offsets += 1;
        }
    }
    // Prove the sweep was not vacuous: unconditional branches alone are
    // 1/32 of the encoding space.
    assert!(
        compared_offsets > 1_000,
        "only {compared_offsets} offsets compared"
    );
}
