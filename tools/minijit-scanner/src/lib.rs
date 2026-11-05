//! Table-driven x86-64 length+class scanner prototype.
//!
//! The scanner starts only at known instruction boundaries (an
//! entry point or a boundary obtained from a prior accepted scan /
//! full decode). It never resynchronizes by guessing: when the
//! encoding form is not positively modelled, it reports
//! `needs_full_decode`. A result is fast-path movable only when the
//! table proves a non-relative, non-RIP-relative, non-intercept
//! instruction from the scanner's positively modelled subset of
//! the liteinst-jit P1a Ordinary envelope. The binary in this crate
//! validates that subset against `liteinst_jit::decode` as oracle;
//! the scanner itself does not redefine admission — every other
//! Ordinary candidate falls back to full decode.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Scan {
    /// Instruction length in bytes, or 0 when length cannot be
    /// proved from the tables (truncated or unmodelled encoding).
    pub len: usize,
    pub relative_branch_or_call: bool,
    pub rip_relative: bool,
    pub interception_target: bool,
    /// Scanner-proved subset of P1a allowlisted Ordinary forms.
    pub allowlisted_movable: bool,
    /// Everything not fast-path movable needs full decode in the
    /// measured end-to-end path, including known patch/intercept
    /// sites. The class flags above still describe those sites.
    pub needs_full_decode: bool,
}

#[derive(Clone, Copy)]
struct Prefix {
    len: usize,
    /// Effective operand size in bits after prefix ordering:
    /// a legacy prefix cancels a preceding REX, and an effective
    /// REX.W after 66 selects 64, matching iced's prefix state.
    operand_size: u8,
    has66: bool,
    rex_w: bool,
    addr32: bool,
    lock: bool,
    rep: bool,
    repne: bool,
    segment: bool,
}

impl Default for Prefix {
    fn default() -> Self {
        Self {
            len: 0,
            operand_size: 32,
            has66: false,
            rex_w: false,
            addr32: false,
            lock: false,
            rep: false,
            repne: false,
            segment: false,
        }
    }
}

impl Prefix {
    /// Sign-extended IW/ID immediate size: 2 for effective
    /// operand size 16, otherwise 4 (including REX.W 64).
    #[inline]
    fn os_imm(self) -> usize {
        if self.operand_size == 16 { 2 } else { 4 }
    }
    #[inline]
    fn mov_imm(self) -> usize {
        if self.rex_w {
            8
        } else if self.operand_size == 16 {
            2
        } else {
            4
        }
    }
    #[inline]
    fn moffs(self) -> usize {
        if self.addr32 { 4 } else { 8 }
    }
    #[inline]
    fn reset_rex(&mut self) {
        self.rex_w = false;
        self.operand_size = if self.has66 { 16 } else { 32 };
    }
}

#[inline]
fn is_prefix_byte(b: u8) -> bool {
    matches!(
        b,
        0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0x40..=0x4f
    )
}

#[inline]
fn parse_prefix(bytes: &[u8]) -> Prefix {
    let mut p = Prefix::default();
    // Fast paths: no prefix, or one effective REX immediately
    // before the opcode (the overwhelmingly common shapes).
    match bytes.first() {
        Some(&b0) if (0x40..=0x4f).contains(&b0) => {
            if bytes.get(1).is_some_and(|&n| !is_prefix_byte(n)) {
                p.len = 1;
                if b0 & 8 != 0 {
                    p.rex_w = true;
                    p.operand_size = 64;
                }
                return p;
            }
        }
        Some(&b0) if !is_prefix_byte(b0) => return p,
        _ => {}
    }
    while let Some(&b) = bytes.get(p.len) {
        match b {
            0xf0 => {
                p.lock = true;
                p.reset_rex();
            }
            0xf2 => {
                p.repne = true;
                p.rep = false;
                p.reset_rex();
            }
            0xf3 => {
                p.rep = true;
                p.repne = false;
                p.reset_rex();
            }
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => {
                p.segment = true;
                p.reset_rex();
            }
            0x66 => {
                p.has66 = true;
                p.reset_rex();
            }
            0x67 => {
                p.addr32 = true;
                p.reset_rex();
            }
            0x40..=0x4f => {
                if b & 8 != 0 {
                    p.rex_w = true;
                    p.operand_size = 64;
                } else {
                    p.rex_w = false;
                    p.operand_size = if p.has66 { 16 } else { 32 };
                }
            }
            _ => break,
        }
        p.len += 1;
        if p.len > 15 {
            break;
        }
    }
    p
}

struct ModRm {
    len: usize,
    reg: u8,
    is_mem: bool,
    rip_relative: bool,
}

/// Length of ModRM + optional SIB + displacement at `pos`.
#[inline]
fn modrm(bytes: &[u8], pos: usize) -> Option<ModRm> {
    let m = *bytes.get(pos)?;
    let mode = m >> 6;
    let reg = (m >> 3) & 7;
    let rm = m & 7;
    if mode == 3 {
        return Some(ModRm {
            len: 1,
            reg,
            is_mem: false,
            rip_relative: false,
        });
    }
    let mut len = 1usize;
    let mut rip_relative = false;
    let mut disp = match mode {
        0 => 0,
        1 => 1,
        _ => 4,
    };
    if rm == 4 {
        let sib = *bytes.get(pos + len)?;
        len += 1;
        if mode == 0 && (sib & 7) == 5 {
            disp = 4;
        }
    } else if mode == 0 && rm == 5 {
        disp = 4;
        rip_relative = true;
    }
    len += disp;
    if pos + len > bytes.len() {
        return None;
    }
    Some(ModRm {
        len,
        reg,
        is_mem: true,
        rip_relative,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Imm {
    None,
    B,
    Os,
    Mov,
    Moffs,
    W,
    Enter,
    Rel32,
}

impl Imm {
    fn len(self, p: Prefix) -> usize {
        match self {
            Imm::None => 0,
            Imm::B => 1,
            Imm::Os => p.os_imm(),
            Imm::Mov => p.mov_imm(),
            Imm::Moffs => p.moffs(),
            Imm::W => 2,
            Imm::Enter => 3,
            Imm::Rel32 => 4,
        }
    }
}

/// (has ModRM, immediate, direct-relative, interception target)
/// for a legacy one-byte opcode. `None` means unmodelled length.
#[inline]
fn legacy_form(op: u8) -> Option<(bool, Imm, bool, bool)> {
    let f = match op {
        0x00..=0x3f => match op & 7 {
            0..=3 => (true, Imm::None, false, false),
            4 => (false, Imm::B, false, false),
            5 => (false, Imm::Os, false, false),
            _ => (false, Imm::None, false, false),
        },
        0x50..=0x5f => (false, Imm::None, false, false),
        0x63 => (true, Imm::None, false, false),
        0x68 => (false, Imm::Os, false, false),
        0x69 => (true, Imm::Os, false, false),
        0x6a => (false, Imm::B, false, false),
        0x6b => (true, Imm::B, false, false),
        0x70..=0x7f => (false, Imm::B, true, false),
        0x80 | 0x82 | 0x83 => (true, Imm::B, false, false),
        0x81 => (true, Imm::Os, false, false),
        0x84..=0x8f => (true, Imm::None, false, false),
        0x90..=0x9f => (false, Imm::None, false, false),
        0xa0..=0xa3 => (false, Imm::Moffs, false, false),
        0xa4..=0xa7 | 0xaa..=0xaf => (false, Imm::None, false, false),
        0xa8 => (false, Imm::B, false, false),
        0xa9 => (false, Imm::Os, false, false),
        0xb0..=0xb7 => (false, Imm::B, false, false),
        0xb8..=0xbf => (false, Imm::Mov, false, false),
        0xc0 | 0xc1 => (true, Imm::B, false, false),
        0xc2 => (false, Imm::W, false, false),
        0xc3 => (false, Imm::None, false, false),
        0xc6 => (true, Imm::B, false, false),
        0xc7 => (true, Imm::Os, false, false),
        0xc8 => (false, Imm::Enter, false, false),
        0xc9 => (false, Imm::None, false, false),
        0xcc => (false, Imm::None, false, false),
        0xcd => (false, Imm::B, false, true),
        // INTO is invalid in 64-bit mode; IRET is in the
        // liteinst syscall class only for the 16-bit mnemonic
        // form (iced distinguishes Iret/Iretd/Iretq), applied
        // by operand size in scan_one.
        0xce | 0xcf => (false, Imm::None, false, false),
        0xd0..=0xd3 => (true, Imm::None, false, false),
        0xd6 | 0xd7 => (false, Imm::None, false, false),
        0xd8..=0xdf => (true, Imm::None, false, false),
        0xe0..=0xe3 | 0xeb => (false, Imm::B, true, false),
        0xe4..=0xe7 => (false, Imm::B, false, false),
        0xec..=0xef => (false, Imm::None, false, false),
        0xe8 | 0xe9 => (false, Imm::Rel32, true, false),
        0xea => return None,
        0xf1 | 0xf4 | 0xf5 | 0xf8..=0xfd => (false, Imm::None, false, false),
        0xf6 | 0xf7 | 0xfe | 0xff => (true, Imm::None, false, false),
        _ => return None,
    };
    Some(f)
}

/// Whether the modelled form can carry XACQUIRE/XRELEASE
/// semantics under iced's opcode-aware rules (mirrored by
/// liteinst-jit admission). `legacy_op` is set only for the
/// one-byte map, where the no-LOCK HLE forms live.
#[inline]
fn transactional(p: Prefix, is_mem: bool, legacy_op: Option<u8>) -> bool {
    if !is_mem || (!p.lock && !p.rep && !p.repne) {
        return false;
    }
    if p.lock {
        return p.rep || p.repne;
    }
    match legacy_op {
        Some(0x86 | 0x87) => p.rep || p.repne,
        Some(0x88 | 0x89 | 0xc6 | 0xc7) => p.rep,
        _ => false,
    }
}

#[inline]
fn legacy_movable(op: u8, reg: Option<u8>) -> bool {
    match op {
        // ALU reg/mem and accumulator-immediate families:
        // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP.
        0x00..=0x3f => matches!(op & 7, 0..=5),
        0x50..=0x5f | 0x63 | 0x68 | 0x69 | 0x6a | 0x6b => true,
        0x80..=0x83 => true,
        0x84..=0x8b | 0x8d => true,
        0x8f => reg == Some(0),
        0x90..=0x99 | 0x9e | 0x9f => true,
        0xa0..=0xaf => true,
        0xb0..=0xbf => true,
        // Shift groups: /6 decodes as distinct mnemonic SAL in
        // iced, which liteinst-jit does not allowlist (only SHL).
        0xc0 | 0xc1 => matches!(reg, Some(0..=5 | 7)),
        0xc6 | 0xc7 => reg == Some(0),
        0xc9 => true,
        0xd0..=0xd3 => matches!(reg, Some(0..=5 | 7)),
        0xf6 | 0xf7 => matches!(reg, Some(0..=7)),
        0xfc | 0xfd => true,
        0xfe => matches!(reg, Some(0 | 1)),
        0xff => matches!(reg, Some(0 | 1 | 6)),
        _ => false,
    }
}

/// Form for opcode in the 0F map. Most 0F opcodes carry ModRM;
/// the no-ModRM exceptions below are the architecturally defined
/// register/implicit forms encountered in valid 64-bit code.
#[inline]
fn map0f_form(op: u8) -> (bool, Imm, bool, bool) {
    match op {
        0x05 | 0x07 | 0x34 => (false, Imm::None, false, true),
        0x06 | 0x08 | 0x09 | 0x0b | 0x0e | 0x30 | 0x35 | 0x77 | 0xa0 | 0xa1 => {
            (false, Imm::None, false, false)
        }
        0x0f => (true, Imm::B, false, false), // 3DNow: ModRM + imm8
        0x31 | 0xa2 => (false, Imm::None, false, true),
        0x32 | 0x33 | 0x37 | 0xa8 | 0xa9 | 0xaa => (false, Imm::None, false, false),
        0x70..=0x73 | 0xa4 | 0xac | 0xc2 | 0xc4 | 0xc5 | 0xc6 => (true, Imm::B, false, false),
        0x80..=0x8f => (false, Imm::Rel32, true, false),
        0xba => (true, Imm::B, false, false),
        0xc8..=0xcf => (false, Imm::None, false, false),
        _ => (true, Imm::None, false, false),
    }
}

#[inline]
fn map0f_movable(op: u8, reg: Option<u8>, p: Prefix, modrm_byte: Option<u8>) -> bool {
    match op {
        0x1f => reg == Some(0), // NOP Ev only /0; other regs are Reservednop
        0x40..=0x4f => true,    // CMOVcc
        0x90..=0x9f => true,    // SETcc
        0xa3 | 0xab | 0xb0 | 0xb1 | 0xb3 | 0xbb => true, // BT/BTS/CMPXCHG/BTR/BTC
        0xaf => true,           // IMUL
        0xb6 | 0xb7 | 0xbe | 0xbf => true, // MOVZX/MOVSX
        0xb8 => p.rep,          // POPCNT only with F3; bare 0F B8 is not admitted
        0xba => matches!(reg, Some(4..=7)),
        0xbc | 0xbd => true, // BSF/TZCNT, BSR/LZCNT (F3 forms included)
        0xc0 | 0xc1 => true, // XADD
        0xc8..=0xcf => true, // BSWAP
        0x1e => p.rep && matches!(modrm_byte, Some(0xfa | 0xfb)), // ENDBR64/32
        _ => false,
    }
}

/// Immediate length for VEX/EVEX by map. Map 1 is 0F, 2 is
/// 0F38 (no immediate in the modelled forms), 3 is 0F3A (imm8).
#[inline]
fn vex_evex_imm_len(map: u8, op: u8) -> usize {
    match map {
        3 => 1,
        1 if matches!(op, 0x70..=0x73 | 0xc2 | 0xc4 | 0xc5 | 0xc6) => 1,
        _ => 0,
    }
}

fn vex_evex_has_modrm(is_evex: bool, map: u8, op: u8) -> bool {
    // Only VEX map-1 opcode 77 (VZEROUPPER/VZEROALL) lacks a
    // ModRM byte. EVEX opcode 77 in maps 1/2 is a ModRM form.
    is_evex || !(map == 1 && op == 0x77)
}

fn unknown() -> Scan {
    Scan {
        needs_full_decode: true,
        ..Scan::default()
    }
}

#[inline]
fn finish(mut s: Scan, total: usize, bytes_len: usize, movable: bool, segment: bool) -> Scan {
    if total == 0 || total > 15 || total > bytes_len {
        return unknown();
    }
    s.len = total;
    s.allowlisted_movable = movable
        && !segment
        && !s.rip_relative
        && !s.relative_branch_or_call
        && !s.interception_target;
    s.needs_full_decode = !s.allowlisted_movable;
    s
}

/// Scan one instruction at a known boundary. `bytes` starts at
/// `pc`; the PC value itself does not affect length/class except
/// through the caller's known-boundary contract.
#[inline]
pub fn scan_one(bytes: &[u8], _pc: u64) -> Scan {
    if bytes.is_empty() {
        return unknown();
    }
    let mut s = unknown();
    // VEX2: C5 <R/vvvv/L/pp> <0F opcode>
    if bytes[0] == 0xc5 {
        if bytes.len() < 3 {
            return s;
        }
        let op = bytes[2];
        let mut cur = 3usize;
        if vex_evex_has_modrm(false, 1, op) {
            let Some(m) = modrm(bytes, cur) else { return s };
            s.rip_relative = m.rip_relative;
            cur += m.len;
        }
        cur += vex_evex_imm_len(1, op);
        return finish(s, cur, bytes.len(), false, false);
    }
    // VEX3: C4 <RXB/map> <W/vvvv/L/pp> <opcode>
    if bytes[0] == 0xc4 {
        if bytes.len() < 4 {
            return s;
        }
        let map = bytes[1] & 0x1f;
        if !(1..=3).contains(&map) {
            return s;
        }
        let op = bytes[3];
        let mut cur = 4usize;
        if vex_evex_has_modrm(false, map, op) {
            let Some(m) = modrm(bytes, cur) else { return s };
            s.rip_relative = m.rip_relative;
            cur += m.len;
        }
        cur += vex_evex_imm_len(map, op);
        return finish(s, cur, bytes.len(), false, false);
    }
    // EVEX: 62 <P0> <P1> <P2> <opcode>; map is P0 bits 1:0.
    if bytes[0] == 0x62 {
        if bytes.len() < 5 {
            return s;
        }
        let map = bytes[1] & 0x03;
        if !(1..=3).contains(&map) {
            return s;
        }
        let op = bytes[4];
        let mut cur = 5usize;
        if vex_evex_has_modrm(true, map, op) {
            let Some(m) = modrm(bytes, cur) else { return s };
            s.rip_relative = m.rip_relative;
            cur += m.len;
        }
        cur += vex_evex_imm_len(map, op);
        return finish(s, cur, bytes.len(), false, false);
    }

    let p = parse_prefix(bytes);
    let pos = p.len;
    let Some(&op) = bytes.get(pos) else { return s };

    if op == 0x0f {
        let Some(&op2) = bytes.get(pos + 1) else {
            return s;
        };
        if op2 == 0x38 || op2 == 0x3a {
            let Some(&op3) = bytes.get(pos + 2) else {
                return s;
            };
            let _ = op3;
            let mut cur = pos + 3;
            let Some(m) = modrm(bytes, cur) else { return s };
            s.rip_relative = m.rip_relative;
            cur += m.len;
            if op2 == 0x3a {
                cur += 1;
            }
            return finish(s, cur, bytes.len(), false, p.segment);
        }
        let (has_modrm, imm, relative, intercept) = map0f_form(op2);
        s.relative_branch_or_call = relative;
        s.interception_target = intercept;
        let mut cur = pos + 2;
        let mut reg = None;
        let mut modrm_byte = None;
        let mut is_mem = false;
        // MOV to/from control/debug/test registers carry a
        // register-only ModRM byte: no SIB, displacement, or
        // RIP-relative form exists in the encoding.
        let register_only_modrm = matches!(op2, 0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x26);
        if has_modrm && register_only_modrm {
            let Some(&mb) = bytes.get(cur) else { return s };
            reg = Some((mb >> 3) & 7);
            modrm_byte = Some(mb);
            cur += 1;
        } else if has_modrm {
            let Some(m) = modrm(bytes, cur) else { return s };
            reg = Some(m.reg);
            modrm_byte = bytes.get(cur).copied();
            is_mem = m.is_mem;
            s.rip_relative = m.rip_relative;
            cur += m.len;
            if op2 == 0x01 && matches!(modrm_byte, Some(0xf9 | 0xd0)) {
                s.interception_target = true; // RDTSCP / XGETBV
            }
            if op2 == 0xc7 && !is_mem {
                // Register forms only: /6 RDRAND (no F2/F3),
                // /7 RDSEED (no F3) or RDPID (F3). RDPID's
                // 64-bit code is selected by 64-bit execution
                // mode in liteinst-jit/iced, not by effective
                // operand size, so no REX.W condition applies.
                s.interception_target = match reg {
                    Some(6) => !p.rep && !p.repne,
                    Some(7) => true,
                    _ => false,
                };
            }
            // SSE4a EXTRQ/INSERTQ immediate forms: 66/F2 0F 78
            // carry two imm8 bytes after the ModRM byte.
            if op2 == 0x78 && !p.rep && (p.repne || p.has66) {
                cur += 2;
            }
        }
        cur += imm.len(p);
        let movable = map0f_movable(op2, reg, p, modrm_byte) && !transactional(p, is_mem, None);
        return finish(s, cur, bytes.len(), movable, p.segment);
    }

    let Some((has_modrm, imm, relative, intercept)) = legacy_form(op) else {
        return s;
    };
    s.relative_branch_or_call = relative;
    s.interception_target = intercept || (op == 0xcf && p.operand_size == 16);
    let mut cur = pos + 1;
    let mut reg = None;
    let mut is_mem = false;
    if has_modrm {
        let Some(m) = modrm(bytes, cur) else { return s };
        reg = Some(m.reg);
        is_mem = m.is_mem;
        s.rip_relative = m.rip_relative;
        cur += m.len;
        if matches!(op, 0xf6 | 0xf7) && matches!(reg, Some(0 | 1)) {
            cur += if op == 0xf6 { 1 } else { p.os_imm() };
        }
    }
    cur += imm.len(p);
    let movable = legacy_movable(op, reg) && !transactional(p, is_mem, Some(op));
    finish(s, cur, bytes.len(), movable, p.segment)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(bytes: &[u8]) -> Scan {
        scan_one(bytes, 0x1000)
    }

    #[test]
    fn known_lengths_and_classes() {
        // mov rax, imm64; syscall
        let s = scan(&[0x48, 0xb8, 59, 0, 0, 0, 1, 0, 0, 0, 0x0f, 0x05]);
        assert_eq!(s.len, 10);
        assert!(s.allowlisted_movable);
        let s = scan(&[0x0f, 0x05]);
        assert_eq!(s.len, 2);
        assert!(s.interception_target);
        assert!(!s.allowlisted_movable);
        // call rel32
        let s = scan(&[0xe8, 0, 0, 0, 0]);
        assert_eq!(s.len, 5);
        assert!(s.relative_branch_or_call);
        // mov rax,[rip+0]
        let s = scan(&[0x48, 0x8b, 0x05, 0, 0, 0, 0]);
        assert_eq!(s.len, 7);
        assert!(s.rip_relative);
        assert!(!s.allowlisted_movable);
        // cpuid, rdtsc, rdtscp, xgetbv, rdrand rax
        assert!(scan(&[0x0f, 0xa2]).interception_target);
        assert!(scan(&[0x0f, 0x31]).interception_target);
        assert!(scan(&[0x0f, 0x01, 0xf9]).interception_target);
        assert!(scan(&[0x0f, 0x01, 0xd0]).interception_target);
        assert!(scan(&[0x48, 0x0f, 0xc7, 0xf0]).interception_target);
        // vzeroupper has no ModRM.
        assert_eq!(scan(&[0xc5, 0xf8, 0x77]).len, 3);
        // endbr64
        let s = scan(&[0xf3, 0x0f, 0x1e, 0xfa]);
        assert_eq!(s.len, 4);
        assert!(s.allowlisted_movable);
        // truncated movabs cannot be proved.
        assert_eq!(scan(&[0x48, 0xb8, 1]).len, 0);
    }
}
