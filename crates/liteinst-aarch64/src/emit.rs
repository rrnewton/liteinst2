//! Emission facts for single-word SVC patching. Every constructor is
//! checked: an
//! unencodable request yields `None`, never a masked or spilled word.
//! Nothing here maps memory, writes code, or maintains caches; the
//! caller owns the island allocation (near probing, dual RW/RX mapping),
//! the aligned word store, and the DC/IC/barrier sequence.

use super::{
    BtiTarget, CmpExtend, CmpOperand, Insn, LiteralClass, Reg, adr, branch, brk, bti, checked_reg,
    compare_branch, cond_branch, decode, movk_shifted, movz_shifted, test_branch,
};

/// How a patch site reaches its handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// `SVC` replaced by a direct `B` to a near island entry.
    Branch,
    /// `SVC` replaced by `BRK`, handled by the caller's trap handler.
    /// Needs no island allocation and terminates the placement chain.
    Trap,
}

/// One replacement word and the strategy it implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Patch {
    /// The word to store at the site (one aligned four-byte store).
    pub word: u32,
    /// Which strategy the word implements.
    pub strategy: Strategy,
}

/// Whether a direct branch from `from` can reach `to` (signed imm26,
/// times 4: `[-128 MiB, +128 MiB - 4]`, both addresses word aligned).
pub fn in_branch_range(from: u64, to: u64) -> bool {
    if !from.is_multiple_of(4) || !to.is_multiple_of(4) {
        return false;
    }
    let offset = to as i128 - from as i128;
    (-(1i128 << 27)..(1i128 << 27)).contains(&offset)
}

fn branch_word(from: u64, to: u64) -> Option<u32> {
    if !from.is_multiple_of(4) || !to.is_multiple_of(4) {
        return None;
    }
    branch(false, i64::try_from(to as i128 - from as i128).ok()?)
}

/// The `B` word replacing an `SVC` site, branching to `island_entry`.
/// `None` when the site word is not `SVC`, either address is misaligned,
/// or the entry is out of branch range.
pub fn svc_patch_word(site_word: u32, site_addr: u64, island_entry: u64) -> Option<u32> {
    if !matches!(decode(site_word), Insn::Svc { .. }) {
        return None;
    }
    branch_word(site_addr, island_entry)
}

/// The `BRK` fallback word replacing an `SVC` site, carrying `brk_imm`
/// in the caller's reserved immediate namespace. `None` when the site
/// word is not `SVC`.
pub fn svc_fallback_word(site_word: u32, brk_imm: u16) -> Option<u32> {
    if !matches!(decode(site_word), Insn::Svc { .. }) {
        return None;
    }
    Some(brk(brk_imm))
}

/// Choose a patch for an `SVC` site: branch to `island_entry` when an
/// island is offered and reachable, otherwise the `BRK` trap fallback
/// (the placement chain never dead-ends). `None` when the site word is
/// not `SVC` or the site address is not word aligned.
pub fn patch_svc(
    site_word: u32,
    site_addr: u64,
    island_entry: Option<u64>,
    brk_imm: u16,
) -> Option<Patch> {
    // A misaligned site cannot name an aligned A64 instruction word to
    // replace; that defect is not repairable by either strategy, so it
    // is refused before the fallback is even considered. (A missing or
    // unreachable island at an aligned site still falls back to BRK.)
    if !site_addr.is_multiple_of(4) {
        return None;
    }
    if let Some(entry) = island_entry
        && let Some(word) = svc_patch_word(site_word, site_addr, entry)
    {
        return Some(Patch {
            word,
            strategy: Strategy::Branch,
        });
    }
    svc_fallback_word(site_word, brk_imm).map(|word| Patch {
        word,
        strategy: Strategy::Trap,
    })
}

/// How an island entry is reached, which decides its landing pad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryReach {
    /// Reached only by direct branches (`B`): no pad required.
    Direct,
    /// Reached by call-indirect (`BLR` family): `BTI c`.
    Call,
    /// Reached by jump-indirect (`BR` family): `BTI j`.
    Jump,
    /// Reached both ways: `BTI jc`.
    Dual,
}

/// The complete lazy-promotion island for one SVC site:
/// `[original SVC, B resume]` where resume is `site_addr + 4`.
/// `None` when `original` is not an `SVC`, either address is
/// misaligned, or the return branch cannot encode. Executing the
/// original SVC inside the island preserves its immediate and every
/// register/memory effect; only the indirect control flow differs.
pub fn svc_island_words(original: u32, site_addr: u64, entry: u64) -> Option<[u32; 2]> {
    if !matches!(decode(original), Insn::Svc { .. }) {
        return None;
    }
    if !site_addr.is_multiple_of(4) || !entry.is_multiple_of(4) {
        return None;
    }
    let resume = site_addr.checked_add(4)?;
    let back = branch(
        false,
        i64::try_from(resume as i128 - (entry as i128 + 4)).ok()?,
    )?;
    Some([original, back])
}

/// As [`svc_island_words`], prefixed with the landing pad for
/// `reach` when one is required (indirect entries). Returns the
/// words and their live count (2 without a pad, 3 with).
pub fn svc_island_words_padded(
    reach: EntryReach,
    original: u32,
    site_addr: u64,
    entry: u64,
) -> Option<([u32; 3], usize)> {
    match landing_pad(reach) {
        None => {
            let pair = svc_island_words(original, site_addr, entry)?;
            Some(([pair[0], pair[1], 0], 2))
        }
        Some(pad) => {
            if !matches!(decode(original), Insn::Svc { .. }) {
                return None;
            }
            if !site_addr.is_multiple_of(4) || !entry.is_multiple_of(4) {
                return None;
            }
            let resume = site_addr.checked_add(4)?;
            let back = branch(
                false,
                i64::try_from(resume as i128 - (entry as i128 + 8)).ok()?,
            )?;
            Some(([pad, original, back], 3))
        }
    }
}

/// The `BTI` landing-pad word a branch of this reach class requires,
/// or `None` for a direct-branch-only entry (emit no pad). In guarded
/// pages `BR` sets the expected landing type (`BTypeNext`) to `0b01`
/// when branching through X16/X17 and to `0b11` through any other
/// register, and the X16/X17 veneer pattern (entered as a call,
/// continuing with `BR`) interacts with call pads; which pads accept
/// a given `BR` landing is therefore register-dependent. This matrix
/// stays conservative regardless: a call-only pad is never selected
/// for jump reach.
pub fn landing_pad(reach: EntryReach) -> Option<u32> {
    match reach {
        EntryReach::Direct => None,
        EntryReach::Call => Some(bti(BtiTarget::Call)),
        EntryReach::Jump => Some(bti(BtiTarget::Jump)),
        EntryReach::Dual => Some(bti(BtiTarget::JumpCall)),
    }
}

/// A far jump to any 64-bit `target`, for a near veneer island whose
/// handler body lives out of branch range: optional landing pad, then
/// `MOVZ`/`MOVK` materialising `target` in `scratch`, then `BR scratch`.
/// Returns the words and their count (5 without a pad, 6 with). The full
/// four-chunk materialisation is always emitted, so zero chunks need no
/// special case (`MOVZ` zeroes the register first). `scratch` is
/// clobbered: callers restoring the SVC register contract must preserve
/// it (X16/X17 are the conventional veneer registers). `None` when
/// `scratch` is not a writable architectural register: register 31 is
/// the zero register in these positions, so its materialisation writes
/// would be discarded and no requested target could result.
pub fn far_jump_words(reach: EntryReach, scratch: Reg, target: u64) -> Option<([u32; 6], usize)> {
    if scratch >= 31 {
        return None;
    }
    let field = checked_reg(scratch)?;
    let mut words = [0u32; 6];
    let mut n = 0;
    if let Some(pad) = landing_pad(reach) {
        words[n] = pad;
        n += 1;
    }
    words[n] = movz_shifted(true, scratch, (target & 0xffff) as u32, 0);
    words[n + 1] = movk_shifted(true, scratch, ((target >> 16) & 0xffff) as u32, 1);
    words[n + 2] = movk_shifted(true, scratch, ((target >> 32) & 0xffff) as u32, 2);
    words[n + 3] = movk_shifted(true, scratch, ((target >> 48) & 0xffff) as u32, 3);
    words[n + 4] = 0xd61f_0000 | (field << 5);
    Some((words, n + 5))
}

/// The bytes an island occupies for `payload_bytes` of words under the
/// caller's page size (queried at runtime, for example via `AT_PAGESZ`;
/// 4 KiB and 64 KiB systems both occur). `None` when `page_size` is not
/// a nonzero power of two or the rounding overflows.
pub fn page_span(page_size: u64, payload_bytes: u64) -> Option<u64> {
    if !page_size.is_power_of_two() {
        return None;
    }
    let rounded = payload_bytes.checked_add(page_size - 1)?;
    Some(rounded & !(page_size - 1))
}

/// Whether one island of `island_len` bytes at `island_base` serves a
/// site at `site_addr` in both directions: the patch branch reaches the
/// entry at the island base, and a return branch from the island's last
/// word still reaches the resume address `site_addr + 4`.
pub fn island_reaches(site_addr: u64, island_base: u64, island_len: u64) -> bool {
    if island_len < 4 || !island_len.is_multiple_of(4) {
        return false;
    }
    let resume = match site_addr.checked_add(4) {
        Some(resume) => resume,
        None => return false,
    };
    let last_word = match island_base.checked_add(island_len - 4) {
        Some(last) => last,
        None => return false,
    };
    in_branch_range(site_addr, island_base) && in_branch_range(last_word, resume)
}

fn shifted(from: u64, offset: i64, to: u64) -> Option<i64> {
    i64::try_from(from as i128 + i128::from(offset) - to as i128).ok()
}

fn encode_literal(class: LiteralClass, rt: Reg, offset: i64) -> Option<u32> {
    if offset % 4 != 0 || !(-(1 << 20)..(1 << 20)).contains(&offset) {
        return None;
    }
    let (opc, simd): (u32, u32) = match class {
        LiteralClass::Word32 => (0, 0),
        LiteralClass::Word64 => (1, 0),
        LiteralClass::SignedWord => (2, 0),
        LiteralClass::Prefetch => (3, 0),
        LiteralClass::Simd32 => (0, 1),
        LiteralClass::Simd64 => (1, 1),
        LiteralClass::Simd128 => (2, 1),
    };
    let imm = ((offset / 4) as u32) & 0x7ffff;
    Some((opc << 30) | (0b011 << 27) | (simd << 26) | (imm << 5) | checked_reg(rt)?)
}

fn encode_cmpbr(sf: bool, cc: u8, rt: Reg, operand: CmpOperand, offset: i64) -> Option<u32> {
    if offset % 4 != 0 || !(-(1 << 10)..(1 << 10)).contains(&offset) {
        return None;
    }
    if !matches!(cc, 0 | 1 | 2 | 3 | 6 | 7) {
        return None;
    }
    let imm9 = ((offset / 4) as u32) & 0x1ff;
    let base = ((sf as u32) << 31) | ((cc as u32) << 21) | (imm9 << 5) | checked_reg(rt)?;
    match operand {
        CmpOperand::Reg { rm, extend } => {
            let sz = match (extend, sf) {
                (CmpExtend::Full, _) => 0b00,
                (CmpExtend::Byte, false) => 0b10,
                (CmpExtend::Half, false) => 0b11,
                _ => return None,
            };
            Some(base | (0b1110100 << 24) | (checked_reg(rm)? << 16) | (sz << 14))
        }
        CmpOperand::Imm(imm) => {
            if imm > 0x3f {
                return None;
            }
            Some(base | (0b1110101 << 24) | (imm << 15))
        }
    }
}

/// Re-encode a copied instruction for execution at `to_addr` instead of
/// `from_addr`, preserving its absolute target: direct branches,
/// ADR/ADRP and literal loads get a recomputed offset, and every other
/// decoded instruction copies unchanged. `None` when either address is
/// misaligned, the word is outside the decoded subset ([`Insn::Other`]
/// is never copied), or the preserved target is unencodable at the new
/// address. A relocated FEAT_HBC `BC.cond` keeps its bit-4 marker.
pub fn relocate(word: u32, from_addr: u64, to_addr: u64) -> Option<u32> {
    if !from_addr.is_multiple_of(4) || !to_addr.is_multiple_of(4) {
        return None;
    }
    match decode(word) {
        Insn::Branch { link, offset } => branch(link, shifted(from_addr, offset, to_addr)?),
        Insn::CondBranch { cond, offset } => {
            let encoded = cond_branch(cond, shifted(from_addr, offset, to_addr)?)?;
            Some(encoded | (word & 0x10))
        }
        Insn::CompareBranch {
            nonzero,
            sf,
            rt,
            offset,
        } => compare_branch(nonzero, sf, rt, shifted(from_addr, offset, to_addr)?),
        Insn::TestBranch {
            nonzero,
            rt,
            bit,
            offset,
        } => test_branch(nonzero, rt, bit, shifted(from_addr, offset, to_addr)?),
        Insn::CompareAndBranch {
            sf,
            cc,
            rt,
            operand,
            offset,
        } => encode_cmpbr(sf, cc, rt, operand, shifted(from_addr, offset, to_addr)?),
        Insn::Adr {
            page: false,
            rd,
            offset,
        } => adr(false, rd, shifted(from_addr, offset, to_addr)?),
        Insn::Adr {
            page: true,
            rd,
            offset,
        } => {
            let target = (from_addr & !0xfff) as i128 + i128::from(offset);
            let new_offset = target - (to_addr & !0xfff) as i128;
            adr(true, rd, i64::try_from(new_offset).ok()?)
        }
        Insn::LoadLiteral { class, rt, offset } => {
            encode_literal(class, rt, shifted(from_addr, offset, to_addr)?)
        }
        Insn::Other => None,
        _ => Some(word),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BtiTarget, CmpExtend, CmpOperand, Insn, LiteralClass, brk, decode, svc};
    use super::*;

    const SITE: u64 = 0x4000_0000;

    #[test]
    fn svc_island_words_preserve_original_and_return() {
        let original = svc(0x1234);
        let entry = SITE + 0x1000;
        let words = svc_island_words(original, SITE, entry).unwrap();
        assert_eq!(words[0], original);
        assert_eq!(
            decode(words[1]),
            Insn::Branch {
                link: false,
                offset: (SITE as i64 + 4) - (entry as i64 + 4)
            }
        );
        assert_eq!(svc_island_words(brk(0), SITE, entry), None);
        assert_eq!(svc_island_words(original, SITE + 1, entry), None);
        assert_eq!(svc_island_words(original, SITE, SITE + (1 << 28)), None);
        let (padded, n) = svc_island_words_padded(EntryReach::Dual, original, SITE, entry).unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            decode(padded[0]),
            Insn::Bti {
                target: BtiTarget::JumpCall
            }
        );
        assert_eq!(padded[1], original);
        assert_eq!(
            decode(padded[2]),
            Insn::Branch {
                link: false,
                offset: (SITE as i64 + 4) - (entry as i64 + 8)
            }
        );
    }

    #[test]
    fn svc_patch_word_respects_branch_range_edges() {
        let word = svc(0);
        assert_eq!(
            svc_patch_word(word, SITE, SITE + (1 << 27) - 4).map(decode),
            Some(Insn::Branch {
                link: false,
                offset: (1 << 27) - 4
            })
        );
        assert_eq!(svc_patch_word(word, SITE, SITE + (1 << 27)), None);
        assert_eq!(
            svc_patch_word(word, SITE, SITE - (1 << 27)).map(decode),
            Some(Insn::Branch {
                link: false,
                offset: -(1 << 27)
            })
        );
        assert_eq!(svc_patch_word(word, SITE, SITE + 2), None);
        assert_eq!(svc_patch_word(word, SITE + 2, SITE), None);
        assert_eq!(svc_patch_word(brk(0), SITE, SITE + 8), None);
    }

    #[test]
    fn patch_svc_falls_back_to_trap_without_reachable_island() {
        let word = svc(7);
        let near = patch_svc(word, SITE, Some(SITE + 0x1000), 0x4c00).unwrap();
        assert_eq!(near.strategy, Strategy::Branch);
        for island in [None, Some(SITE + (1 << 28))] {
            let patch = patch_svc(word, SITE, island, 0x4c00).unwrap();
            assert_eq!(patch.strategy, Strategy::Trap);
            assert_eq!(decode(patch.word), Insn::Brk { imm16: 0x4c00 });
        }
        assert_eq!(patch_svc(0xd65f_03c0, SITE, None, 0), None);
    }

    #[test]
    fn far_jump_refuses_the_zero_register_as_scratch() {
        // Register 31 is XZR here, not SP: MOVZ/MOVK writes to it are
        // discarded, so no nonzero target could ever materialise
        // (review probe: far_jump_words(Direct, 31, 0x12345678)).
        for reach in [
            EntryReach::Direct,
            EntryReach::Call,
            EntryReach::Jump,
            EntryReach::Dual,
        ] {
            for target in [0u64, 0x1234_5678, u64::MAX] {
                assert_eq!(
                    far_jump_words(reach, 31, target),
                    None,
                    "target {target:#x}"
                );
            }
        }
        // Writable boundaries stay accepted.
        assert!(far_jump_words(EntryReach::Direct, 0, 0x1234_5678).is_some());
        assert!(far_jump_words(EntryReach::Direct, 30, 0x1234_5678).is_some());
    }

    #[test]
    fn patch_svc_refuses_misaligned_sites_before_fallback() {
        // A missing island is repairable by trapping; a site that cannot
        // name an aligned A64 word is not (review probe: site 0x1001
        // once returned a Trap patch). All residues refuse, with and
        // without an island on offer.
        for residue in [1u64, 2, 3] {
            let site = SITE + residue;
            assert_eq!(patch_svc(svc(0), site, None, 0), None, "residue {residue}");
            assert_eq!(
                patch_svc(svc(0), site, Some(SITE + 0x1000), 0),
                None,
                "residue {residue} with island"
            );
        }
        // Aligned control: distant island still falls back to BRK.
        let patch = patch_svc(svc(0), SITE, Some(SITE + (1 << 28)), 7).unwrap();
        assert_eq!(patch.strategy, Strategy::Trap);
        assert_eq!(decode(patch.word), Insn::Brk { imm16: 7 });
    }

    #[test]
    fn landing_pads_match_the_reach_matrix() {
        assert_eq!(landing_pad(EntryReach::Direct), None);
        assert_eq!(
            landing_pad(EntryReach::Call).map(decode),
            Some(Insn::Bti {
                target: BtiTarget::Call
            })
        );
        assert_eq!(
            landing_pad(EntryReach::Jump).map(decode),
            Some(Insn::Bti {
                target: BtiTarget::Jump
            })
        );
        assert_eq!(
            landing_pad(EntryReach::Dual).map(decode),
            Some(Insn::Bti {
                target: BtiTarget::JumpCall
            })
        );
    }

    #[test]
    fn far_jump_materialises_the_full_target() {
        for target in [0u64, 0x1234, 0xdead_beef_cafe_f00d, u64::MAX] {
            let (words, n) = far_jump_words(EntryReach::Dual, 16, target).unwrap();
            assert_eq!(n, 6);
            assert_eq!(
                decode(words[0]),
                Insn::Bti {
                    target: BtiTarget::JumpCall
                }
            );
            // Simulate MOVZ/MOVK field semantics from the raw words.
            let mut value: u64 = 0;
            for word in &words[1..5] {
                let hw = (word >> 21) & 0x3;
                let imm = u64::from((word >> 5) & 0xffff) << (hw * 16);
                let mask = 0xffffu64 << (hw * 16);
                if word >> 29 == 0b101 {
                    value = imm; // MOVZ zeroes the rest
                } else {
                    value = (value & !mask) | imm; // MOVK keeps other chunks
                }
                assert_eq!(word & 0x1f, 16, "scratch register field");
            }
            assert_eq!(value, target, "materialised target");
            assert_eq!(
                decode(words[5]),
                Insn::BranchReg {
                    kind: super::super::BranchRegKind::Branch,
                    rn: 16
                }
            );
        }
        assert_eq!(far_jump_words(EntryReach::Direct, 32, 0), None);
        assert_eq!(far_jump_words(EntryReach::Direct, 255, 0), None);
        let (_, n) = far_jump_words(EntryReach::Direct, 17, 8).unwrap();
        assert_eq!(n, 5);
    }

    #[test]
    fn page_span_rounds_for_4k_and_64k_pages() {
        for page in [4096u64, 65536] {
            assert_eq!(page_span(page, 0), Some(0));
            assert_eq!(page_span(page, 1), Some(page));
            assert_eq!(page_span(page, page), Some(page));
            assert_eq!(page_span(page, page + 1), Some(page * 2));
        }
        assert_eq!(page_span(0, 4), None);
        assert_eq!(page_span(12288, 4), None);
        assert_eq!(page_span(4096, u64::MAX), None);
    }

    #[test]
    fn island_reachability_checks_both_directions() {
        assert!(island_reaches(SITE, SITE + 0x1000, 0x1000));
        // Entry in range, but a huge island's last word cannot branch back.
        assert!(!island_reaches(SITE, SITE + 0x1000, 1 << 28));
        assert!(!island_reaches(SITE, SITE + (1 << 27), 16));
        assert!(!island_reaches(SITE, SITE + 0x1000, 0));
        assert!(!island_reaches(SITE, SITE + 0x1000, 6));
    }

    #[test]
    fn relocate_preserves_absolute_targets() {
        let to = SITE + 0x2000;
        let cases: [(u32, i64); 5] = [
            (super::super::branch(false, 0x400).unwrap(), 0x400),
            (super::super::cond_branch(1, -0x40).unwrap(), -0x40),
            (
                super::super::compare_branch(true, true, 3, 0x80).unwrap(),
                0x80,
            ),
            (
                super::super::test_branch(true, 4, 63, -0x20).unwrap(),
                -0x20,
            ),
            (super::super::adr(false, 5, 0x123).unwrap(), 0x123),
        ];
        for (word, offset) in cases {
            let moved = relocate(word, SITE, to).unwrap();
            assert_eq!(
                to as i128 + i128::from(decode(moved).pc_relative_offset().unwrap()),
                SITE as i128 + i128::from(offset),
                "word {word:#010x}"
            );
        }
        // ADRP targets are page based from both addresses.
        let word = super::super::adr(true, 6, 0x3000).unwrap();
        let moved = relocate(word, SITE + 0x800, SITE + 0x1800).unwrap();
        assert_eq!(
            decode(moved),
            Insn::Adr {
                page: true,
                rd: 6,
                offset: 0x2000
            }
        );
        // Literal loads re-encode with class intact.
        let word = 0x5800_0040; // LDR X0, .+8
        assert_eq!(
            decode(word),
            Insn::LoadLiteral {
                class: LiteralClass::Word64,
                rt: 0,
                offset: 8
            }
        );
        let moved = relocate(word, SITE, SITE + 4).unwrap();
        assert_eq!(decode(moved).pc_relative_offset(), Some(4));
        // CMPBR round-trips through relocation.
        let moved = relocate(0xf4c6_0046, SITE, SITE + 4).unwrap();
        assert_eq!(
            decode(moved),
            Insn::CompareAndBranch {
                sf: true,
                cc: 0b110,
                rt: 6,
                operand: CmpOperand::Reg {
                    rm: 6,
                    extend: CmpExtend::Full
                },
                offset: 4
            }
        );
    }

    #[test]
    fn relocate_refuses_unknown_and_unreachable() {
        assert_eq!(relocate(0xf900_0000, SITE, SITE + 4), None);
        let word = super::super::branch(false, 4).unwrap();
        assert_eq!(relocate(word, SITE, SITE + (1 << 28)), None);
        assert_eq!(relocate(word, SITE + 1, SITE), None);
        // Position-independent decoded words copy unchanged.
        assert_eq!(relocate(svc(3), SITE, SITE + 4), Some(svc(3)));
        assert_eq!(relocate(0x9100_0484, SITE, SITE + 4), Some(0x9100_0484));
    }
}
