//! Exact opt-in journal state. Null consumers retain their original branches.
//! This module does not supply input/build/runtime admission.
use std::ffi::OsString;

pub const PROFILE: &str = "bounded-journal-v1";
pub const FLAG: &str = "--recording-profile=bounded-journal-v1";
pub const CORE_HOOK: u64 = 0x401970;
pub const CORE_HOOK_BYTES: usize = 211;
pub const JOURNAL_BYTES: usize = 131144;
const LOW: u64 = 0x6c69326a6f75726e;
const HIGH: u64 = 0x7265636f72647321;
const CAPACITY: u64 = 16384;

pub fn arguments(args: &mut Vec<OsString>) -> bool {
    let enabled = args.last().is_some_and(|a| a == FLAG);
    if enabled {
        args.pop();
    }
    assert!(
        !args
            .iter()
            .any(|a| a.to_string_lossy().starts_with("--recording-profile"))
    );
    enabled
}

#[cfg(test)]
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn put(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}

/// The entire initialized object, not a marker match, identifies the single
/// journal in the two already hash-admitted original images. The caller also
/// requires its complete extent to belong to the original RW LOAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Journal {
    pub address: u64,
    pub offset: usize,
}
impl Journal {
    pub fn initial() -> Vec<u8> {
        let mut b = vec![0; JOURNAL_BYTES];
        put(&mut b, 0, LOW);
        put(&mut b, 8, 1);
        put(&mut b, 16, CAPACITY);
        put(&mut b, JOURNAL_BYTES - 8, HIGH);
        b
    }
    pub fn locate(base: &[u8], image_start: u64, rw_start: u64, rw_end: u64) -> Self {
        let initial = Self::initial();
        let found: Vec<_> = (0..=base.len().checked_sub(JOURNAL_BYTES).unwrap())
            .step_by(8)
            .filter(|&at| base[at..at + JOURNAL_BYTES] == initial)
            .collect();
        assert_eq!(
            found.len(),
            1,
            "one complete immutable original journal object"
        );
        let offset = found[0];
        let address = image_start.checked_add(offset as u64).unwrap();
        assert!(
            rw_start <= address && address.checked_add(JOURNAL_BYTES as u64).unwrap() <= rw_end
        );
        Self { address, offset }
    }
    pub fn seed(self, base: &mut [u8]) {
        assert_eq!(
            &base[self.offset..self.offset + JOURNAL_BYTES],
            Self::initial()
        );
        // One explicit parent-image initialization, before either child exists.
        put(base, self.offset + 24, 1);
    }
    pub fn expected(self, seeded: &[u8], pc: Option<u64>) -> Vec<u8> {
        let mut seed = Self::initial();
        put(&mut seed, 24, 1);
        assert_eq!(&seeded[self.offset..self.offset + JOURNAL_BYTES], seed);
        let mut out = seeded.to_vec();
        if let Some(pc) = pc {
            assert!(pc != 0);
            put(&mut out, self.offset + 64, pc);
            put(&mut out, self.offset + 32, 1);
        }
        out
    }
    pub fn journal(self, base: &[u8]) -> &[u8] {
        &base[self.offset..self.offset + JOURNAL_BYTES]
    }
}

pub const E9_BEFORE: &[u8] = &[
    0x48, 0x8d, 0xa4, 0x24, 0, 0xc0, 0xff, 0xff, 0x41, 0x53, 0x41, 0x52, 0x50, 0x41, 0x51, 0x41,
    0x50, 0x51, 0x52, 0x56, 0x57, 0x0f, 0x90, 0xc0, 0x9f, 0x50,
];
pub const E9_AFTER: &[u8] = &[
    0x58, 0x04, 0x7f, 0x9e, 0x5f, 0x5e, 0x5a, 0x59, 0x41, 0x58, 0x41, 0x59, 0x58, 0x41, 0x5a, 0x41,
    0x5b, 0x48, 0x8d, 0xa4, 0x24, 0, 0x40, 0, 0,
];
pub const E9_PREFIX_BYTES: usize = 63;

pub fn e9_prefix(pc: u64, logical: u64, hook: u64) -> Vec<u8> {
    let mut b = E9_BEFORE.to_vec();
    b.extend_from_slice(&[0x48, 0x8d, 0x3d]);
    let next = pc.checked_add(b.len() as u64 + 4).unwrap();
    b.extend_from_slice(
        &i32::try_from(i128::from(logical) - i128::from(next))
            .unwrap()
            .to_le_bytes(),
    );
    b.push(0xe8);
    let next = pc.checked_add(b.len() as u64 + 4).unwrap();
    b.extend_from_slice(
        &i32::try_from(i128::from(hook) - i128::from(next))
            .unwrap()
            .to_le_bytes(),
    );
    b.extend_from_slice(E9_AFTER);
    assert_eq!(b.len(), E9_PREFIX_BYTES);
    b
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Independently joins the complete dynsym extent and every reserved LOAD to
/// the actual held hook ELF. No guessed RET boundary or caller extent.
pub fn e9_hook(data: &[u8], base: u64, entry: u64, code: &[u8]) -> Vec<(u64, u64, u32, Vec<u8>)> {
    assert!(data.len() >= 64);
    assert_eq!(&data[..7], b"\x7fELF\x02\x01\x01");
    assert_eq!(
        (
            u16_at(data, 16),
            u16_at(data, 18),
            u16_at(data, 52),
            u16_at(data, 54)
        ),
        (3, 62, 64, 56)
    );
    let ph = u64_at(data, 32) as usize;
    let n = usize::from(u16_at(data, 56));
    assert!((1..=128).contains(&n) && ph.checked_add(n * 56).unwrap() <= data.len());
    let mut loads = Vec::new();
    for at in (ph..ph + n * 56).step_by(56) {
        if u32_at(data, at) != 1 {
            continue;
        }
        let flags = u32_at(data, at + 4);
        let off = u64_at(data, at + 8);
        let va = u64_at(data, at + 16);
        let fs = u64_at(data, at + 32);
        let ms = u64_at(data, at + 40);
        assert!(matches!(flags, 4..=6) && fs <= ms && ms > 0 && ms <= 16_777_216);
        assert!(off.checked_add(fs).unwrap() <= data.len() as u64);
        assert_eq!(off % 4096, va % 4096);
        let start = base.checked_add(va).unwrap();
        let end = start.checked_add(ms).unwrap();
        assert!(end < 1 << 31);
        let mut bytes = data[off as usize..(off + fs) as usize].to_vec();
        bytes.resize(ms as usize, 0);
        loads.push((start, end, flags, bytes));
    }
    let sh = u64_at(data, 40) as usize;
    let n = usize::from(u16_at(data, 60));
    assert_eq!(u16_at(data, 58), 64);
    assert!((1..=4096).contains(&n) && sh.checked_add(n * 64).unwrap() <= data.len());
    let tables: Vec<_> = (sh..sh + n * 64)
        .step_by(64)
        .filter(|&at| u32_at(data, at + 4) == 11)
        .collect();
    assert_eq!(tables.len(), 1);
    let t = tables[0];
    let off = u64_at(data, t + 24) as usize;
    let size = u64_at(data, t + 32) as usize;
    let link = u32_at(data, t + 40) as usize;
    assert_eq!(u64_at(data, t + 56), 24);
    assert!(
        size % 24 == 0
            && size / 24 <= 4096
            && off.checked_add(size).unwrap() <= data.len()
            && link < n
    );
    let s = sh + link * 64;
    assert_eq!(u32_at(data, s + 4), 3);
    let a = u64_at(data, s + 24) as usize;
    let len = u64_at(data, s + 32) as usize;
    assert!(a.checked_add(len).unwrap() <= data.len());
    let names = &data[a..a + len];
    let mut found = 0;
    for at in (off..off + size).step_by(24) {
        let name = u32_at(data, at) as usize;
        assert!(name < names.len());
        let end = names[name..].iter().position(|&b| b == 0).unwrap();
        if &names[name..name + end] != b"li2_e9_record" {
            continue;
        }
        found += 1;
        assert_eq!(data[at + 4], 0x12);
        assert_ne!(u16_at(data, at + 6), 0);
        assert_eq!(base.checked_add(u64_at(data, at + 8)).unwrap(), entry);
        assert_eq!(u64_at(data, at + 16), code.len() as u64);
        assert!(!code.is_empty() && code.len() <= 4096);
        let owners: Vec<_> = loads
            .iter()
            .filter(|p| p.2 == 5 && p.0 <= entry && entry + code.len() as u64 <= p.1)
            .collect();
        assert_eq!(owners.len(), 1);
        let p = owners[0];
        let i = (entry - p.0) as usize;
        assert_eq!(&p.3[i..i + code.len()], code);
    }
    assert_eq!(found, 1);
    loads
}

/// Whole 64 KiB expected image, including every clean-call push and CALL word.
/// No region is excluded. The exact template leaves these bytes behind after
/// POP/RET; it changes no application-stack byte. The callback itself must keep
/// RSP unchanged until its literal RET and the native comparator checks all bytes.
pub fn e9_stack(
    before: &[u8],
    stack_start: u64,
    application_start: u64,
    rsp: u64,
    flags: u64,
    gprs: [u64; 9],
    return_pc: u64,
) -> Vec<u8> {
    assert_eq!(before.len(), 65536);
    let mut out = before.to_vec();
    let mut sp = rsp.checked_sub(16384).unwrap();
    let lahf = ((flags & 0xd5) | 2) << 8;
    let saved_rax = (gprs[2] & !0xffff) | lahf | ((flags >> 11) & 1);
    for value in [
        gprs[0], gprs[1], gprs[2], gprs[3], gprs[4], gprs[5], gprs[6], gprs[7], gprs[8], saved_rax,
        return_pc,
    ] {
        sp = sp.checked_sub(8).unwrap();
        assert!(stack_start <= sp && sp + 8 <= application_start);
        let at = usize::try_from(sp - stack_start).unwrap();
        put(&mut out, at, value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_trailing_profile_preserves_legacy_arguments_and_rejects_aliases() {
        let legacy = vec![
            OsString::from("driver"),
            OsString::from("replay-common-core"),
            OsString::from("original"),
        ];
        let mut a = legacy.clone();
        assert!(!arguments(&mut a));
        assert_eq!(a, legacy);
        a.push(OsString::from(FLAG));
        assert!(arguments(&mut a));
        assert_eq!(a, legacy);
        for flags in [vec![FLAG, FLAG], vec!["--recording-profile=other"]] {
            let mut bad = legacy.clone();
            bad.extend(flags.into_iter().map(OsString::from));
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| arguments(&mut bad)))
                    .is_err()
            );
        }
    }
    #[test]
    fn entire_journal_append_and_unselected_state_are_exact() {
        let mut base = vec![0xa5; JOURNAL_BYTES + 32];
        base[16..16 + JOURNAL_BYTES].copy_from_slice(&Journal::initial());
        let j = Journal::locate(&base, 0x400000, 0x400000, 0x500000);
        assert_eq!((j.address, j.offset), (0x400010, 16));
        j.seed(&mut base);
        assert_eq!(j.expected(&base, None), base);
        let actual = j.expected(&base, Some(0x401810));
        let mut independent = base.clone();
        independent[48..56].copy_from_slice(&1u64.to_le_bytes());
        independent[80..88].copy_from_slice(&0x401810u64.to_le_bytes());
        assert_eq!(actual, independent);
        assert_eq!(word(j.journal(&actual), 32), 1);
    }
    #[test]
    fn journal_owner_header_tail_and_existing_record_mutations_refuse() {
        for at in [0, 8, 16, 24, 32, 40, 48, 56, 64, JOURNAL_BYTES - 8] {
            let mut b = Journal::initial();
            b[at] ^= 1;
            assert!(
                std::panic::catch_unwind(|| Journal::locate(&b, 0, 0, JOURNAL_BYTES as u64))
                    .is_err()
            );
        }
        let b = Journal::initial();
        assert!(
            std::panic::catch_unwind(|| Journal::locate(&b, 0, 8, JOURNAL_BYTES as u64)).is_err()
        );
        let mut duplicate = b.clone();
        duplicate.extend_from_slice(&b);
        assert!(
            std::panic::catch_unwind(|| Journal::locate(&duplicate, 0, 0, duplicate.len() as u64))
                .is_err()
        );
    }
    #[test]
    fn clean_call_stack_words_have_independent_offsets_and_full_tail() {
        let rsp = 0x100008u64;
        let gprs = [11, 10, 0x123456789abcdef0, 9, 8, 3, 2, 6, 7];
        let b = vec![0x5a; 65536];
        let start = rsp - 32776;
        let out = e9_stack(&b, start, rsp - 128, rsp, 0xad7, gprs, 0x1234);
        let mut expected = b.clone();
        let values = [
            11u64,
            10,
            0x123456789abcdef0,
            9,
            8,
            3,
            2,
            6,
            7,
            0x123456789abcd701,
            0x1234,
        ];
        for (i, value) in values.into_iter().enumerate() {
            let at = 16384 - (i + 1) * 8 + 8;
            expected[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        assert_eq!(out, expected);
    }
    #[test]
    fn exact_clean_template_encodes_logical_argument_call_and_return() {
        let b = e9_prefix(0x1000000, 0x401810, 0x1400000);
        let mut expected = vec![
            0x48, 0x8d, 0xa4, 0x24, 0, 0xc0, 0xff, 0xff, 0x41, 0x53, 0x41, 0x52, 0x50, 0x41, 0x51,
            0x41, 0x50, 0x51, 0x52, 0x56, 0x57, 0x0f, 0x90, 0xc0, 0x9f, 0x50, 0x48, 0x8d, 0x3d,
        ];
        expected.extend_from_slice(&(-12576785i32).to_le_bytes());
        expected.push(0xe8);
        expected.extend_from_slice(&(4194266i32).to_le_bytes());
        expected.extend_from_slice(&[
            0x58, 0x04, 0x7f, 0x9e, 0x5f, 0x5e, 0x5a, 0x59, 0x41, 0x58, 0x41, 0x59, 0x58, 0x41,
            0x5a, 0x41, 0x5b, 0x48, 0x8d, 0xa4, 0x24, 0, 0x40, 0, 0,
        ]);
        assert_eq!(b, expected);
        assert!(std::panic::catch_unwind(|| e9_prefix(0, 1, 1u64 << 40)).is_err());
    }
    fn hook_fixture() -> Vec<u8> {
        let mut b = vec![0; 1024];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [
            (16, 3u16),
            (18, 62),
            (52, 64),
            (54, 56),
            (56, 1),
            (58, 64),
            (60, 3),
        ] {
            b[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        put(&mut b, 32, 64);
        put(&mut b, 40, 512);
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&5u32.to_le_bytes());
        put(&mut b, 96, 1024);
        put(&mut b, 104, 1024);
        put(&mut b, 112, 4096);
        b[256] = 0xc3;
        // Complete two-entry dynsym and its independently indexed string table.
        b[580..584].copy_from_slice(&11u32.to_le_bytes());
        put(&mut b, 600, 384);
        put(&mut b, 608, 48);
        b[616..620].copy_from_slice(&2u32.to_le_bytes());
        put(&mut b, 632, 24);
        b[644..648].copy_from_slice(&3u32.to_le_bytes());
        put(&mut b, 664, 448);
        put(&mut b, 672, 15);
        b[448..463].copy_from_slice(b"\0li2_e9_record\0");
        b[408..412].copy_from_slice(&1u32.to_le_bytes());
        b[412] = 0x12;
        b[414..416].copy_from_slice(&1u16.to_le_bytes());
        put(&mut b, 416, 256);
        put(&mut b, 424, 1);
        b
    }
    #[test]
    fn complete_hook_symbol_extent_and_load_bytes_are_exact() {
        let b = hook_fixture();
        assert_eq!(
            e9_hook(&b, 0x1400000, 0x1400100, &[0xc3]),
            vec![(0x1400000, 0x1400400, 5, b.clone())]
        );
        for (at, value) in [
            (16, 2),
            (18, 63),
            (68, 7),
            (412, 0x11),
            (414, 0),
            (416, 1),
            (424, 2),
            (256, 0x90),
        ] {
            let mut bad = b.clone();
            bad[at] = value;
            assert!(
                std::panic::catch_unwind(|| e9_hook(&bad, 0x1400000, 0x1400100, &[0xc3])).is_err()
            );
        }
        assert!(std::panic::catch_unwind(|| e9_hook(&b, 0x1400000, 0x1400101, &[0xc3])).is_err());
        assert!(std::panic::catch_unwind(|| e9_hook(&b, 0x1400000, 0x1400100, &[0x90])).is_err());
    }
}
