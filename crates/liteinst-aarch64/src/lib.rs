//! Shared descriptive AArch64 facts, never instruction-head or execution
//! authority.
//!
//! Walkers choose their own linear/all-start policy, bounds and error
//! mapping. Decoded families do not grant CPU support, an emitter ABI,
//! entry ownership, mapping freshness or a complete control-flow graph.
//!
//! Decoding is deliberately partial and total: every 32-bit word maps to
//! a variant, and everything outside the subset becomes [`Insn::Other`],
//! which no rewrite idiom may accept. A word is only ever rewritten when
//! every instruction of its sequence decoded into a known variant, so an
//! unrecognised encoding can never be rewritten by accident.
//!
//! Field positions follow the Arm Architecture Reference Manual for
//! A-profile (DDI 0487): the C6.2 instruction encodings, C3.2.6 for
//! exclusives and C3.2.12 for FEAT_LSE atomics. FEAT_CMPBR (an Armv9.6-A
//! extension) fields are cross-checked against LLVM's
//! `AArch64InstrFormats.td` `BaseCmpBranchRegister` /
//! `BaseCmpBranchImmediate` classes and `AArch64InstrInfo.td` definitions.
//!
//! The exclusive/RMW subset is copied and generalized from Hermit's
//! `detcore/src/aarch64_lse/insn.rs`; see this crate's README for
//! provenance. The SVC/BRK, PC-relative, register-branch and BTI
//! families serve single-word patch-site analysis: identifying `SVC`
//! words and recovering numeric PC-relative offsets for relocation.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// A general-purpose register number. Architectural values are 0..=31;
/// the alias itself does not enforce that range. Value 31 reads as SP or
/// as the zero register depending on the instruction and operand
/// position (for example ADD-immediate and exclusive base positions are
/// SP positions, most value positions are zero-register positions); the
/// decoder reports the raw number and never chooses between them.
///
/// Checked (`Option`-returning) encoders reject values above 31 with
/// `None`. Infallible encoders require in-range registers and
/// debug-assert the bound.
pub type Reg = u8;

/// The zero register, XZR or WZR, in the positions these encodings use it.
pub const ZR: Reg = 31;

/// The fixed A64 instruction length, in bytes.
pub const INSN_LEN: usize = 4;

/// Access size of an exclusive or atomic access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    /// A byte.
    B = 0,
    /// A halfword.
    H = 1,
    /// A word, with 32-bit value registers.
    W = 2,
    /// A doubleword, with 64-bit value registers.
    X = 3,
}

impl Size {
    /// Decode the two-bit size field at bits 31:30. The mask keeps this
    /// total for any caller-supplied shift result: only the low two bits
    /// are the field, so there is no reserved-pattern leak.
    fn from_bits(bits: u32) -> Size {
        match bits & 0b11 {
            0 => Size::B,
            1 => Size::H,
            2 => Size::W,
            _ => Size::X,
        }
    }

    /// Whether the value registers of this access are 64-bit.
    pub fn is_64(self) -> bool {
        matches!(self, Size::X)
    }
}

/// Memory ordering carried by one half of an exclusive pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ordering {
    /// Load-acquire semantics (`LDAXR`, or the `A` of an atomic).
    pub acquire: bool,
    /// Store-release semantics (`STLXR`, or the `L` of an atomic).
    pub release: bool,
}

/// The data-processing operations an RMW idiom may use between its pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    /// `ADD`.
    Add,
    /// `SUB`.
    Sub,
    /// `AND`.
    And,
    /// `ORR`.
    Orr,
    /// `EOR`.
    Eor,
    /// `BIC`: and with the complement.
    Bic,
}

/// The second operand of a decoded data-processing instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// A register, unshifted.
    Reg(Reg),
    /// An immediate, already shifted into place.
    Imm(u32),
}

/// How the register operand of a FEAT_CMPBR register-form compare is
/// extended before comparison (the `sz` field, bits 15:14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpExtend {
    /// Full register width per `sf` (`sz` = 0b00): plain `CB<cc>`.
    Full,
    /// Low byte, zero extended (`sz` = 0b10, `sf` = 0): `CBB<cc>`.
    Byte,
    /// Low halfword, zero extended (`sz` = 0b11, `sf` = 0): `CBH<cc>`.
    Half,
}

/// The compared operand of a FEAT_CMPBR compare-and-branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOperand {
    /// Register form: compare against `Rm`, extended per `extend`.
    Reg {
        /// The compared register.
        rm: Reg,
        /// The extension applied to both compared registers.
        extend: CmpExtend,
    },
    /// Immediate form: compare against this unsigned 6-bit immediate.
    Imm(u32),
}

/// The payload class of a load-literal encoding (`opc` and `V` fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiteralClass {
    /// `LDR Wt` (32-bit GPR).
    Word32,
    /// `LDR Xt` (64-bit GPR).
    Word64,
    /// `LDRSW Xt` (sign-extended 32-bit load).
    SignedWord,
    /// `PRFM` (prefetch; the register field is a prefetch operation).
    Prefetch,
    /// `LDR St` (32-bit SIMD&FP).
    Simd32,
    /// `LDR Dt` (64-bit SIMD&FP).
    Simd64,
    /// `LDR Qt` (128-bit SIMD&FP).
    Simd128,
}

/// Which indirect branch a [`Insn::BranchReg`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchRegKind {
    /// `BR Xn`.
    Branch,
    /// `BLR Xn`: also writes the return address to X30.
    Link,
    /// `RET Xn`.
    Return,
}

/// The landing-pad class a `BTI` instruction authorises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtiTarget {
    /// Plain `BTI`: no indirect-branch landing authorised.
    None,
    /// `BTI c`: call landings (`BLR` family).
    Call,
    /// `BTI j`: jump landings (`BR` family).
    Jump,
    /// `BTI jc`: both call and jump landings.
    JumpCall,
}

/// One decoded instruction: the subset callers reason about, and
/// [`Insn::Other`] for everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insn {
    /// LDXR/LDAXR and their byte and halfword forms.
    LoadExcl {
        /// The access size.
        size: Size,
        /// Acquire or not.
        ord: Ordering,
        /// The loaded register.
        rt: Reg,
        /// The base address register.
        rn: Reg,
    },
    /// STXR/STLXR and their byte and halfword forms.
    StoreExcl {
        /// The access size.
        size: Size,
        /// Release or not.
        ord: Ordering,
        /// The status register: 0 when the store succeeded, 1 on failure.
        rs: Reg,
        /// The stored register.
        rt: Reg,
        /// The base address register.
        rn: Reg,
    },
    /// LDXP/LDAXP/STXP/STLXP: recognised so they are reported, never
    /// treated as single exclusives.
    ExclPair,
    /// ADD/SUB/AND/ORR/EOR/BIC, register form with no shift, or immediate
    /// form. `rd` is never the zero register here: a flag-setting or
    /// discarding form decodes as [`Insn::Cmp`] or [`Insn::Other`].
    Alu {
        /// The operation.
        op: AluOp,
        /// 64-bit (`X` registers) rather than 32-bit.
        sf: bool,
        /// The destination.
        rd: Reg,
        /// The first operand.
        rn: Reg,
        /// The second operand.
        operand: Operand,
    },
    /// UXTB/UXTH: a zero extension, which proves the bits above its width
    /// are clear in the destination.
    ZeroExtend {
        /// The width kept: 8 for UXTB, 16 for UXTH.
        bits: u32,
        /// The destination.
        rd: Reg,
        /// The source.
        rn: Reg,
    },
    /// SUBS with a discarded result: CMP, register or immediate.
    Cmp {
        /// 64-bit rather than 32-bit.
        sf: bool,
        /// The first operand.
        rn: Reg,
        /// The second operand.
        operand: Operand,
    },
    /// `SVC #imm16`: the supervisor call a patch site replaces. The
    /// immediate is ignored by the Linux syscall ABI (number in X8) but
    /// is part of the encoding identity.
    Svc {
        /// The 16-bit immediate at bits 20:5.
        imm16: u16,
    },
    /// `BRK #imm16`: a breakpoint trap, used as the no-trampoline patch
    /// representation. Foreign immediates belong to other owners (kernel
    /// BUG, kprobes, sanitizer traps) and must not be claimed by value
    /// alone; this variant only reports the encoding fact.
    Brk {
        /// The 16-bit immediate at bits 20:5.
        imm16: u16,
    },
    /// ADR/ADRP: form a PC-relative address.
    Adr {
        /// ADRP (`offset` is a 4 KiB page offset from `Align(PC, 4096)`)
        /// rather than ADR (byte offset from PC).
        page: bool,
        /// The destination register.
        rd: Reg,
        /// Byte offset: signed imm21 for ADR, imm21 << 12 for ADRP.
        offset: i64,
    },
    /// Load register (literal) and PRFM (literal).
    LoadLiteral {
        /// Which payload the encoding loads (or prefetches).
        class: LiteralClass,
        /// The destination register (prefetch operation for PRFM).
        rt: Reg,
        /// Byte offset from this instruction (signed imm19, times 4).
        offset: i64,
    },
    /// CBZ/CBNZ.
    CompareBranch {
        /// CBNZ rather than CBZ.
        nonzero: bool,
        /// 64-bit rather than 32-bit.
        sf: bool,
        /// The tested register.
        rt: Reg,
        /// Byte offset from this instruction.
        offset: i64,
    },
    /// FEAT_CMPBR compare-and-branch: `CB<cc>` register/immediate and the
    /// byte/halfword `CBB<cc>`/`CBH<cc>` register forms. The raw `cc`
    /// field is reported without normalisation because register and
    /// immediate forms name conditions asymmetrically (immediate GT/GE
    /// style aliases fold a +/-1 into the immediate).
    CompareAndBranch {
        /// 64-bit rather than 32-bit (always false for byte/half forms).
        sf: bool,
        /// The raw condition selector at bits 23:21 (allocated values
        /// are 0b000, 0b001, 0b010, 0b011, 0b110 and 0b111).
        cc: u8,
        /// The first compared register.
        rt: Reg,
        /// The second compared operand.
        operand: CmpOperand,
        /// Byte offset from this instruction (signed imm9, times 4).
        offset: i64,
    },
    /// B.cond (and FEAT_HBC BC.cond, which differs only in bit 4).
    CondBranch {
        /// The condition code.
        cond: u32,
        /// Byte offset from this instruction.
        offset: i64,
    },
    /// B and BL.
    Branch {
        /// BL rather than B.
        link: bool,
        /// Byte offset from this instruction.
        offset: i64,
    },
    /// TBZ/TBNZ.
    TestBranch {
        /// TBNZ rather than TBZ.
        nonzero: bool,
        /// The tested register.
        rt: Reg,
        /// The tested bit number, 0..=63 (`b5:b40`).
        bit: u32,
        /// Byte offset from this instruction (signed imm14, times 4).
        offset: i64,
    },
    /// BR/BLR/RET (unauthenticated forms only; pointer-authenticated
    /// variants decode as [`Insn::Other`]).
    BranchReg {
        /// Which indirect branch this is.
        kind: BranchRegKind,
        /// The register holding the target address.
        rn: Reg,
    },
    /// BTI landing pad.
    Bti {
        /// Which indirect landings this pad authorises.
        target: BtiTarget,
    },
    /// CLREX: clears the local exclusive monitor.
    Clrex,
    /// NOP.
    Nop,
    /// Anything outside the decoded subset, including HVC/SMC and every
    /// authenticated indirect branch.
    Other,
}

impl Insn {
    /// The PC-relative byte offset this instruction carries, if any.
    /// For [`Insn::Adr`] with `page` set this is the page offset from
    /// `Align(PC, 4096)`, not from PC itself.
    pub fn pc_relative_offset(self) -> Option<i64> {
        match self {
            Insn::Adr { offset, .. }
            | Insn::LoadLiteral { offset, .. }
            | Insn::CompareBranch { offset, .. }
            | Insn::CompareAndBranch { offset, .. }
            | Insn::CondBranch { offset, .. }
            | Insn::Branch { offset, .. }
            | Insn::TestBranch { offset, .. } => Some(offset),
            _ => None,
        }
    }

    /// Whether this is a direct (immediate) branch whose target moves
    /// with the instruction when copied.
    pub fn is_direct_branch(self) -> bool {
        matches!(
            self,
            Insn::CompareBranch { .. }
                | Insn::CompareAndBranch { .. }
                | Insn::CondBranch { .. }
                | Insn::Branch { .. }
                | Insn::TestBranch { .. }
        )
    }
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

/// Decode one instruction word. Total: every word decodes, to
/// [`Insn::Other`] when it is outside the subset.
pub fn decode(word: u32) -> Insn {
    // Exception generation: SVC and BRK share mask 0xFFE0001F. HVC/SMC
    // and the DCPS forms stay Other on purpose: no caller here may
    // mistake them for a patchable supervisor call.
    if word & 0xffe0_001f == SVC_BASE {
        return Insn::Svc {
            imm16: ((word >> 5) & 0xffff) as u16,
        };
    }
    if word & 0xffe0_001f == BRK_BASE {
        return Insn::Brk {
            imm16: ((word >> 5) & 0xffff) as u16,
        };
    }
    // C3.2.6: exclusives share bits 29:24 = 001000 with the FEAT_LSE
    // compare-and-swap instructions, which set bit 23; those stay Other.
    if (word >> 24) & 0x3f == 0b001000 && (word >> 23) & 1 == 0 {
        let size = Size::from_bits(word >> 30);
        let load = (word >> 22) & 1 == 1;
        let pair = (word >> 21) & 1 == 1;
        let rs = ((word >> 16) & 0x1f) as Reg;
        let o0 = (word >> 15) & 1 == 1;
        let rt2 = ((word >> 10) & 0x1f) as Reg;
        let rn = ((word >> 5) & 0x1f) as Reg;
        let rt = (word & 0x1f) as Reg;
        if pair {
            // CASP shares this encoding space with LDXP and STXP and is
            // told apart by its size field: exclusive pairs use 0b10 and
            // 0b11 (32- and 64-bit), CASP 0b00 and 0b01. CASP is an LSE
            // atomic and no exclusive at all.
            return if matches!(size, Size::B | Size::H) {
                Insn::Other
            } else {
                Insn::ExclPair
            };
        }
        if rt2 != ZR {
            return Insn::Other;
        }
        return if load {
            // A load-exclusive leaves Rs unused and encoded as 0b11111.
            if rs != ZR {
                Insn::Other
            } else {
                Insn::LoadExcl {
                    size,
                    ord: Ordering {
                        acquire: o0,
                        release: false,
                    },
                    rt,
                    rn,
                }
            }
        } else {
            Insn::StoreExcl {
                size,
                ord: Ordering {
                    acquire: false,
                    release: o0,
                },
                rs,
                rt,
                rn,
            }
        };
    }
    if word == NOP {
        return Insn::Nop;
    }
    // CLREX takes a CRm barrier operand; only the architectural default
    // is recognised, and any other operand stays Other.
    if word == CLREX {
        return Insn::Clrex;
    }
    match word {
        BTI => {
            return Insn::Bti {
                target: BtiTarget::None,
            };
        }
        BTI_C => {
            return Insn::Bti {
                target: BtiTarget::Call,
            };
        }
        BTI_J => {
            return Insn::Bti {
                target: BtiTarget::Jump,
            };
        }
        BTI_JC => {
            return Insn::Bti {
                target: BtiTarget::JumpCall,
            };
        }
        _ => {}
    }
    // Add/subtract (immediate): sf op S 100010 sh imm12 Rn Rd.
    if (word >> 23) & 0x3f == 0b100010 {
        let sf = word >> 31 == 1;
        let sub = (word >> 30) & 1 == 1;
        let set_flags = (word >> 29) & 1 == 1;
        let shift12 = (word >> 22) & 1 == 1;
        let imm = (word >> 10) & 0xfff;
        let rn = ((word >> 5) & 0x1f) as Reg;
        let rd = (word & 0x1f) as Reg;
        let imm = if shift12 { imm << 12 } else { imm };
        return match (set_flags, sub, rd) {
            (true, true, ZR) if !shift12 => Insn::Cmp {
                sf,
                rn,
                operand: Operand::Imm(imm),
            },
            (false, _, ZR) => Insn::Other,
            (false, _, _) => Insn::Alu {
                op: if sub { AluOp::Sub } else { AluOp::Add },
                sf,
                rd,
                rn,
                operand: Operand::Imm(imm),
            },
            _ => Insn::Other,
        };
    }
    // Add/subtract (shifted register): sf op S 01011 shift(2) 0 Rm imm6
    // Rn Rd. Only the unshifted form is decoded.
    if (word >> 24) & 0x1f == 0b01011 && (word >> 21) & 1 == 0 {
        let sf = word >> 31 == 1;
        let sub = (word >> 30) & 1 == 1;
        let set_flags = (word >> 29) & 1 == 1;
        let shift = (word >> 22) & 3;
        let rm = ((word >> 16) & 0x1f) as Reg;
        let imm6 = (word >> 10) & 0x3f;
        let rn = ((word >> 5) & 0x1f) as Reg;
        let rd = (word & 0x1f) as Reg;
        if shift != 0 || imm6 != 0 {
            return Insn::Other;
        }
        return match (set_flags, sub, rd) {
            (true, true, ZR) => Insn::Cmp {
                sf,
                rn,
                operand: Operand::Reg(rm),
            },
            (false, _, ZR) => Insn::Other,
            (false, _, _) => Insn::Alu {
                op: if sub { AluOp::Sub } else { AluOp::Add },
                sf,
                rd,
                rn,
                operand: Operand::Reg(rm),
            },
            _ => Insn::Other,
        };
    }
    // Logical (shifted register): sf opc(2) 01010 shift(2) N Rm imm6 Rn
    // Rd. Only the unshifted AND/BIC/ORR/EOR forms are decoded.
    if (word >> 24) & 0x1f == 0b01010 {
        let sf = word >> 31 == 1;
        let opc = (word >> 29) & 3;
        let shift = (word >> 22) & 3;
        let negate = (word >> 21) & 1 == 1;
        let rm = ((word >> 16) & 0x1f) as Reg;
        let imm6 = (word >> 10) & 0x3f;
        let rn = ((word >> 5) & 0x1f) as Reg;
        let rd = (word & 0x1f) as Reg;
        if shift != 0 || imm6 != 0 || rd == ZR {
            return Insn::Other;
        }
        let op = match (opc, negate) {
            (0b00, false) => AluOp::And,
            (0b00, true) => AluOp::Bic,
            (0b01, false) => AluOp::Orr,
            (0b10, false) => AluOp::Eor,
            _ => return Insn::Other,
        };
        return Insn::Alu {
            op,
            sf,
            rd,
            rn,
            operand: Operand::Reg(rm),
        };
    }
    // Unsigned bitfield move (32-bit, immr = 0): UXTB is UBFM Wd, Wn, #0,
    // #7 and UXTH is UBFM Wd, Wn, #0, #15.
    if (word >> 22) & 0x3ff == 0b01_0100_1100 {
        let imms = (word >> 10) & 0x3f;
        let immr = (word >> 16) & 0x3f;
        let rn = ((word >> 5) & 0x1f) as Reg;
        let rd = (word & 0x1f) as Reg;
        if immr == 0 && (imms == 7 || imms == 15) {
            return Insn::ZeroExtend {
                bits: imms + 1,
                rd,
                rn,
            };
        }
        return Insn::Other;
    }
    // PC-relative address: op immlo(2) 10000 immhi(19) Rd. ADR offset is
    // the signed 21-bit byte value; ADRP scales it by 4096.
    if (word >> 24) & 0x1f == 0b10000 {
        let page = word >> 31 == 1;
        let imm21 = (((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 0x3);
        let imm = sign_extend(imm21, 21);
        return Insn::Adr {
            page,
            rd: (word & 0x1f) as Reg,
            offset: if page { imm << 12 } else { imm },
        };
    }
    // Load (literal): opc(2) 011 V 00 imm19 Rt.
    if (word >> 27) & 0x7 == 0b011 && (word >> 24) & 0x3 == 0 {
        let opc = (word >> 30) & 0x3;
        let simd = (word >> 26) & 1 == 1;
        let class = match (simd, opc) {
            (false, 0) => LiteralClass::Word32,
            (false, 1) => LiteralClass::Word64,
            (false, 2) => LiteralClass::SignedWord,
            (false, _) => LiteralClass::Prefetch,
            (true, 0) => LiteralClass::Simd32,
            (true, 1) => LiteralClass::Simd64,
            (true, 2) => LiteralClass::Simd128,
            // V=1, opc=0b11 is unallocated.
            (true, _) => return Insn::Other,
        };
        return Insn::LoadLiteral {
            class,
            rt: (word & 0x1f) as Reg,
            offset: sign_extend((word >> 5) & 0x7ffff, 19) * 4,
        };
    }
    // Compare and branch (immediate): sf 011010 op imm19 Rt.
    if (word >> 25) & 0x3f == 0b011010 {
        return Insn::CompareBranch {
            nonzero: (word >> 24) & 1 == 1,
            sf: word >> 31 == 1,
            rt: (word & 0x1f) as Reg,
            offset: sign_extend((word >> 5) & 0x7ffff, 19) * 4,
        };
    }
    // Test and branch (immediate): b5 011011 op b40 imm14 Rt.
    if (word >> 25) & 0x3f == 0b011011 {
        return Insn::TestBranch {
            nonzero: (word >> 24) & 1 == 1,
            rt: (word & 0x1f) as Reg,
            bit: (((word >> 31) & 1) << 5) | ((word >> 19) & 0x1f),
            offset: sign_extend((word >> 5) & 0x3fff, 14) * 4,
        };
    }
    // Conditional branch (immediate): 0101010 o1 imm19 o0 cond. Bit 4
    // set is FEAT_HBC BC.cond, the same direct branch and imm19 target.
    if (word >> 24) & 0xff == 0b0101_0100 {
        return Insn::CondBranch {
            cond: word & 0xf,
            offset: sign_extend((word >> 5) & 0x7ffff, 19) * 4,
        };
    }
    // FEAT_CMPBR compare-and-branch (Armv9.6-A): bits 30:24 = 1110100
    // (register) or 1110101 (immediate), cc at 23:21, signed imm9 at
    // 13:5 (times 4). Only allocated combinations decode: register
    // sz 0b01, byte/half forms with sf=1, immediate-form bit 14 set,
    // and cc values 0b100/0b101 are unallocated and stay Other.
    let top7 = (word >> 24) & 0x7f;
    if top7 == 0b1110100 || top7 == 0b1110101 {
        let sf = word >> 31 == 1;
        let cc = ((word >> 21) & 0x7) as u8;
        let offset = sign_extend((word >> 5) & 0x1ff, 9) * 4;
        let rt = (word & 0x1f) as Reg;
        let operand = if top7 == 0b1110101 {
            if (word >> 14) & 1 == 1 {
                return Insn::Other;
            }
            CmpOperand::Imm((word >> 15) & 0x3f)
        } else {
            let rm = ((word >> 16) & 0x1f) as Reg;
            let extend = match ((word >> 14) & 0x3, sf) {
                (0b00, _) => CmpExtend::Full,
                (0b10, false) => CmpExtend::Byte,
                (0b11, false) => CmpExtend::Half,
                _ => return Insn::Other,
            };
            CmpOperand::Reg { rm, extend }
        };
        if !matches!(cc, 0 | 1 | 2 | 3 | 6 | 7) {
            return Insn::Other;
        }
        return Insn::CompareAndBranch {
            sf,
            cc,
            rt,
            operand,
            offset,
        };
    }
    // Unconditional branch (immediate): op 00101 imm26.
    if (word >> 26) & 0x1f == 0b00101 {
        return Insn::Branch {
            link: word >> 31 == 1,
            offset: sign_extend(word & 0x03ff_ffff, 26) * 4,
        };
    }
    // Unauthenticated register branches; bits 4:0 must be zero. The
    // authenticated (BRAA/BLRAA/RETAA family) encodings stay Other.
    let kind = match word & 0xffff_fc1f {
        0xd61f_0000 => Some(BranchRegKind::Branch),
        0xd63f_0000 => Some(BranchRegKind::Link),
        0xd65f_0000 => Some(BranchRegKind::Return),
        _ => None,
    };
    if let Some(kind) = kind {
        return Insn::BranchReg {
            kind,
            rn: ((word >> 5) & 0x1f) as Reg,
        };
    }
    Insn::Other
}

/// Decode one little-endian instruction word from bytes, or `None` when
/// fewer than [`INSN_LEN`] bytes remain. Short input stays a caller
/// policy matter, exactly as in `liteinst-x86`.
pub fn decode_le(bytes: &[u8]) -> Option<Insn> {
    let bytes = bytes.get(..INSN_LEN)?;
    Some(decode(u32::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
    ])))
}

/// The `SVC #0` encoding base (mask `0xFFE0_001F`).
pub const SVC_BASE: u32 = 0xd400_0001;
/// The `BRK #0` encoding base (mask `0xFFE0_001F`).
pub const BRK_BASE: u32 = 0xd420_0000;
/// The `NOP` encoding.
pub const NOP: u32 = 0xd503_201f;
/// The `CLREX` encoding (with the default, ignored, `CRm`).
pub const CLREX: u32 = 0xd503_3f5f;
/// The `BTI` encoding (no landing authorised).
pub const BTI: u32 = 0xd503_241f;
/// The `BTI c` encoding (call landings).
pub const BTI_C: u32 = 0xd503_245f;
/// The `BTI j` encoding (jump landings).
pub const BTI_J: u32 = 0xd503_249f;
/// The `BTI jc` encoding (call and jump landings).
pub const BTI_JC: u32 = 0xd503_24df;

fn sf_bit(sf: bool) -> u32 {
    if sf { 1 << 31 } else { 0 }
}

/// The five-bit encoding field for `reg` in an infallible encoder.
/// Callers must pass an architectural register number (see [`Reg`]);
/// debug builds assert the bound.
fn f5(reg: Reg) -> u32 {
    debug_assert!(reg < 32);
    (reg as u32) & 0x1f
}

/// The five-bit encoding field for `reg` in a checked encoder, or `None`
/// when `reg` is not an architectural register number. Rejecting here,
/// rather than masking, keeps an invalid register from silently
/// becoming a different operand (or spilling into an immediate).
fn checked_reg(reg: Reg) -> Option<u32> {
    if reg < 32 { Some(reg as u32) } else { None }
}

/// `SVC #imm16`.
pub fn svc(imm16: u16) -> u32 {
    SVC_BASE | ((imm16 as u32) << 5)
}

/// `BRK #imm16`.
pub fn brk(imm16: u16) -> u32 {
    BRK_BASE | ((imm16 as u32) << 5)
}

/// The `BTI` word authorising `target` landings.
pub fn bti(target: BtiTarget) -> u32 {
    match target {
        BtiTarget::None => BTI,
        BtiTarget::Call => BTI_C,
        BtiTarget::Jump => BTI_J,
        BtiTarget::JumpCall => BTI_JC,
    }
}

/// `MOV Rd, Rm` (ORR Rd, ZR, Rm).
pub fn mov_reg(sf: bool, rd: Reg, rm: Reg) -> u32 {
    sf_bit(sf) | 0x2a00_03e0 | (f5(rm) << 16) | f5(rd)
}

/// `MOV Rd, #imm16` (MOVZ, no shift).
pub fn movz(sf: bool, rd: Reg, imm16: u32) -> u32 {
    movz_shifted(sf, rd, imm16, 0)
}

/// `MOVZ Rd, #imm16, LSL #(16 * hw)`. Requires an allocated shift
/// (`hw < 4` for 64-bit, `hw < 2` for 32-bit; 32-bit shifts of 32/48 are
/// unallocated) and `imm16 <= 0xffff` (debug-asserted), like the
/// register bound.
pub fn movz_shifted(sf: bool, rd: Reg, imm16: u32, hw: u32) -> u32 {
    debug_assert!(hw < if sf { 4 } else { 2 } && imm16 <= 0xffff);
    sf_bit(sf) | 0x5280_0000 | ((hw & 0x3) << 21) | ((imm16 & 0xffff) << 5) | f5(rd)
}

/// `MOVK Rd, #imm16, LSL #(16 * hw)`. Requires an allocated shift
/// (`hw < 4` for 64-bit, `hw < 2` for 32-bit; 32-bit shifts of 32/48 are
/// unallocated) and `imm16 <= 0xffff` (debug-asserted), like the
/// register bound.
pub fn movk_shifted(sf: bool, rd: Reg, imm16: u32, hw: u32) -> u32 {
    debug_assert!(hw < if sf { 4 } else { 2 } && imm16 <= 0xffff);
    sf_bit(sf) | 0x7280_0000 | ((hw & 0x3) << 21) | ((imm16 & 0xffff) << 5) | f5(rd)
}

/// The single MOVZ that materialises `value`, if one exists: the
/// immediate is 16 bits at a multiple-of-16 shift, so only a value whose
/// nonzero bits fall inside one such window fits one instruction.
pub fn movz_for(sf: bool, rd: Reg, value: u64) -> Option<u32> {
    checked_reg(rd)?;
    for hw in 0..if sf { 4 } else { 2 } {
        let shift = 16 * hw;
        if value >> shift << shift == value && (value >> shift) <= 0xffff {
            return Some(movz_shifted(sf, rd, (value >> shift) as u32, hw));
        }
    }
    None
}

/// `MOVN Rd, #imm16`: Rd = !imm16, so `movn(imm - 1)` materialises `-imm`.
/// Requires `imm16 <= 0xffff` (debug-asserted).
pub fn movn(sf: bool, rd: Reg, imm16: u32) -> u32 {
    debug_assert!(imm16 <= 0xffff);
    sf_bit(sf) | 0x1280_0000 | ((imm16 & 0xffff) << 5) | f5(rd)
}

/// `NEG Rd, Rm` (SUB Rd, ZR, Rm).
pub fn neg(sf: bool, rd: Reg, rm: Reg) -> u32 {
    sf_bit(sf) | 0x4b00_03e0 | (f5(rm) << 16) | f5(rd)
}

/// `MVN Rd, Rm` (ORN Rd, ZR, Rm).
pub fn mvn(sf: bool, rd: Reg, rm: Reg) -> u32 {
    sf_bit(sf) | 0x2a20_03e0 | (f5(rm) << 16) | f5(rd)
}

/// The FEAT_LSE atomic memory operations emitters may need (C3.2.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOp {
    /// `LDADD`.
    Add = 0,
    /// `LDCLR`: clear the bits set in the operand.
    Clr = 1,
    /// `LDEOR`.
    Eor = 2,
    /// `LDSET`: set the bits set in the operand.
    Set = 3,
    /// `SWP`.
    Swp = 8,
}

/// `LD<op>{A}{L}<size> Rs, Rt, [Rn]`, or `SWP{A}{L}<size>`.
pub fn atomic(op: AtomicOp, size: Size, ord: Ordering, rs: Reg, rt: Reg, rn: Reg) -> u32 {
    let (o3, opc) = if matches!(op, AtomicOp::Swp) {
        (1, 0)
    } else {
        (0, op as u32)
    };
    ((size as u32) << 30)
        | (0b111000 << 24)
        | ((ord.acquire as u32) << 23)
        | ((ord.release as u32) << 22)
        | (1 << 21)
        | (f5(rs) << 16)
        | (o3 << 15)
        | (opc << 12)
        | (f5(rn) << 5)
        | f5(rt)
}

/// `CAS{A}{L}<size> Rs, Rt, [Rn]`: Rs carries the expected value in and
/// the loaded value out, Rt is the value stored on a match.
pub fn cas(size: Size, ord: Ordering, rs: Reg, rt: Reg, rn: Reg) -> u32 {
    ((size as u32) << 30)
        | (0b001000 << 24)
        | (1 << 23)
        | ((ord.acquire as u32) << 22)
        | (1 << 21)
        | (f5(rs) << 16)
        | ((ord.release as u32) << 15)
        | (0b11111 << 10)
        | (f5(rn) << 5)
        | f5(rt)
}

/// A scaled PC-relative field of `bits` bits for byte `offset`, or `None`
/// when the offset is misaligned or out of range.
fn imm_scaled(offset: i64, bits: u32) -> Option<u32> {
    let range = 1i64 << (bits + 1);
    if offset % 4 != 0 || !(-range..range).contains(&offset) {
        return None;
    }
    Some(((offset / 4) as u32) & ((1u32 << bits) - 1))
}

fn imm19(offset: i64) -> Option<u32> {
    imm_scaled(offset, 19)
}

/// `B .+offset` or `BL .+offset` (signed imm26, times 4).
pub fn branch(link: bool, offset: i64) -> Option<u32> {
    imm_scaled(offset, 26).map(|imm| (if link { 0x9400_0000 } else { 0x1400_0000 }) | imm)
}

/// `B.<cond> .+offset`, re-encoded at a new address. `cond` must fit
/// the four-bit condition field; larger values are refused, not masked.
pub fn cond_branch(cond: u32, offset: i64) -> Option<u32> {
    if cond > 0xf {
        return None;
    }
    imm19(offset).map(|imm| 0x5400_0000 | (imm << 5) | cond)
}

/// `CBZ`/`CBNZ Rt, .+offset`, re-encoded at a new address.
pub fn compare_branch(nonzero: bool, sf: bool, rt: Reg, offset: i64) -> Option<u32> {
    let rt = checked_reg(rt)?;
    imm19(offset).map(|imm| sf_bit(sf) | 0x3400_0000 | ((nonzero as u32) << 24) | (imm << 5) | rt)
}

/// `TBZ`/`TBNZ Rt, #bit, .+offset` (signed imm14, times 4).
pub fn test_branch(nonzero: bool, rt: Reg, bit: u32, offset: i64) -> Option<u32> {
    let rt = checked_reg(rt)?;
    if bit > 63 {
        return None;
    }
    imm_scaled(offset, 14).map(|imm| {
        (((bit >> 5) & 1) << 31)
            | 0x3600_0000
            | ((nonzero as u32) << 24)
            | ((bit & 0x1f) << 19)
            | (imm << 5)
            | rt
    })
}

/// `ADR Rd, .+offset` or `ADRP Rd, .+offset` (page offset for ADRP, a
/// multiple of 4096), or `None` when unencodable.
pub fn adr(page: bool, rd: Reg, offset: i64) -> Option<u32> {
    let rd = checked_reg(rd)?;
    let imm = if page {
        if offset % 4096 != 0 {
            return None;
        }
        offset / 4096
    } else {
        offset
    };
    if !(-(1 << 20)..(1 << 20)).contains(&imm) {
        return None;
    }
    let imm = (imm as u32) & 0x1f_ffff;
    Some(
        (if page { 1 << 31 } else { 0 })
            | ((imm & 0x3) << 29)
            | 0x1000_0000
            | ((imm >> 2) << 5)
            | rd,
    )
}

/// Patch-word and island emission facts built on the decoder:
/// SVC replacement words, landing pads, far-jump veneers, copied
/// instruction relocation and page-size layout arithmetic. Emission is
/// pure byte construction; mapping, writing and cache maintenance stay
/// with the caller.
pub mod emit;

#[cfg(test)]
mod differential_tests;
#[cfg(test)]
mod tests;
