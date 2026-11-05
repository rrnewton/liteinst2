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

#[derive(Clone, Copy, Default)]
struct Prefix {
    len: usize,
    rex_w: bool,
    op66: bool,
    addr67: bool,
    rep: bool,
    repne: bool,
    segment: bool,
}

impl Prefix {
    fn os_imm(self) -> usize {
        if self.op66 { 2 } else { 4 }
    }
    fn mov_imm(self) -> usize {
        if self.rex_w {
            8
        } else if self.op66 {
            2
        } else {
            4
        }
    }
    fn moffs(self) -> usize {
        if self.addr67 { 4 } else { 8 }
    }
}

#[inline]
fn parse_prefix(bytes: &[u8]) -> Prefix {
    let mut p = Prefix::default();
    while let Some(&b) = bytes.get(p.len) {
        match b {
            0xf0 => {}
            0xf2 => p.repne = true,
            0xf3 => p.rep = true,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => p.segment = true,
            0x66 => p.op66 = true,
            0x67 => p.addr67 = true,
            0x40..=0x4f => p.rex_w = b & 8 != 0,
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
        0xce | 0xcf => (false, Imm::None, false, true),
        0xd0..=0xd3 | 0xd6 | 0xd7 => (true, Imm::None, false, false),
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
        0xc0 | 0xc1 => matches!(reg, Some(0..=7)),
        0xc6 | 0xc7 => reg == Some(0),
        0xc9 => true,
        0xd0..=0xd3 => true,
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
        0x05 | 0x07 | 0x34 | 0x35 => (false, Imm::None, false, true),
        0x0b | 0x0e | 0x77 => (false, Imm::None, false, false),
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
        0x1f => true,                                    // NOP Ev
        0x40..=0x4f => true,                             // CMOVcc
        0x90..=0x9f => true,                             // SETcc
        0xa3 | 0xab | 0xb0 | 0xb1 | 0xb3 | 0xbb => true, // BT/BTS/CMPXCHG/BTR/BTC
        0xaf => true,                                    // IMUL
        0xb6 | 0xb7 | 0xbe | 0xbf => true,               // MOVZX/MOVSX
        0xb8 => p.rep, // POPCNT only with F3; bare 0F B8 is not admitted
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
        1 if matches!(op, 0x70..=0x73 | 0xc2 | 0xc6) => 1,
        _ => 0,
    }
}

fn vex_evex_has_modrm(op: u8) -> bool {
    // VZEROUPPER/VZEROALL (VEX 0F 77) are the common no-ModRM forms.
    op != 0x77
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
        if vex_evex_has_modrm(op) {
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
        if vex_evex_has_modrm(op) {
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
        if vex_evex_has_modrm(op) {
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
        if has_modrm {
            let Some(m) = modrm(bytes, cur) else { return s };
            reg = Some(m.reg);
            modrm_byte = bytes.get(cur).copied();
            s.rip_relative = m.rip_relative;
            cur += m.len;
            if op2 == 0x01 && matches!(modrm_byte, Some(0xf9 | 0xd0)) {
                s.interception_target = true; // RDTSCP / XGETBV
            }
            if op2 == 0xc7 && matches!(reg, Some(6 | 7)) {
                s.interception_target = true; // RDRAND / RDSEED / RDPID
            }
        }
        cur += imm.len(p);
        let movable = map0f_movable(op2, reg, p, modrm_byte);
        return finish(s, cur, bytes.len(), movable, p.segment);
    }

    let Some((has_modrm, imm, relative, intercept)) = legacy_form(op) else {
        return s;
    };
    s.relative_branch_or_call = relative;
    s.interception_target = intercept;
    let mut cur = pos + 1;
    let mut reg = None;
    if has_modrm {
        let Some(m) = modrm(bytes, cur) else { return s };
        reg = Some(m.reg);
        s.rip_relative = m.rip_relative;
        cur += m.len;
        if matches!(op, 0xf6 | 0xf7) && matches!(reg, Some(0 | 1)) {
            cur += if op == 0xf6 { 1 } else { p.os_imm() };
        }
    }
    cur += imm.len(p);
    finish(s, cur, bytes.len(), legacy_movable(op, reg), p.segment)
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
