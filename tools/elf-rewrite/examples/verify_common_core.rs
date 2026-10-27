//! Read-only, finite core-null witness construction. Never plans, emits or executes.
#![forbid(unsafe_code)]
use formats::{Compatibility, ContentId, Metadata, Outcome};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use li2core::contracts::{CONTRACT_VERSION, EntryCompleteness, ResumeObligation};
use li2core::trampoline::{SavedExtendedStateFormat, SavedExtendedStateLayout};
use liteinst_rewrite::carrier::elf64::{Elf64, ElfVaddr, ParseLimits, SegmentType, Storage};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "../../../tests/support/e9_common_seed.rs"]
mod seed;

#[path = "support/common_core_foreign.rs"]
mod common_core_foreign;
#[path = "../../../tests/support/e9_common_planning_profile.rs"]
mod planning_profile;
use planning_profile::PlanningProfile;

const INPUT: usize = 1_048_576;
const OUTPUT: usize = 16_777_216;
const HOOK: u64 = 0x401960;
const IMAGE_END: u64 = 0x425000;

fn hash(bytes: &[u8]) -> String {
    hex(&ContentId::of(bytes).0)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() & 1, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn n(s: &str) -> u64 {
    s.parse().unwrap()
}
fn end(n: u64) -> u64 {
    n.checked_add(4095).unwrap() & !4095
}
fn owner(m: &std::fs::Metadata) -> [i128; 8] {
    [
        m.dev().into(),
        m.ino().into(),
        m.mode().into(),
        m.len().into(),
        m.mtime().into(),
        m.mtime_nsec().into(),
        m.ctime().into(),
        m.ctime_nsec().into(),
    ]
}
struct Bound {
    path: PathBuf,
    file: File,
    bytes: Vec<u8>,
    owner: [i128; 8],
}
impl Bound {
    fn read(path: &Path, max: usize, empty: bool) -> Self {
        assert!(path.is_absolute());
        assert_eq!(path.canonicalize().unwrap().as_os_str(), path.as_os_str());
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(0x20000 | 0x800)
            .open(path)
            .unwrap(); // Linux NOFOLLOW|NONBLOCK.
        let m = file.metadata().unwrap();
        assert!(m.is_file() && m.len() <= max as u64);
        let mut bytes = Vec::new();
        (&file)
            .take((max + 1) as u64)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len() as u64, m.len());
        assert!(empty || !bytes.is_empty());
        let v = Self {
            path: path.to_owned(),
            file,
            bytes,
            owner: owner(&m),
        };
        v.stable();
        v
    }
    fn stable(&self) {
        use std::os::unix::fs::FileExt;
        assert_eq!(owner(&self.file.metadata().unwrap()), self.owner);
        assert_eq!(
            owner(&std::fs::symlink_metadata(&self.path).unwrap()),
            self.owner
        );
        let mut b = vec![0; self.bytes.len()];
        self.file.read_exact_at(&mut b, 0).unwrap();
        assert_eq!(b, self.bytes);
        assert_eq!(owner(&self.file.metadata().unwrap()), self.owner);
    }
}
fn rows(bytes: &[u8]) -> Vec<Vec<&str>> {
    assert!(bytes.ends_with(b"\n"));
    std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|l| l.split('\t').collect())
        .collect()
}
fn one<'a>(rows: &'a [Vec<&'a str>], tag: &str) -> &'a Vec<&'a str> {
    let found: Vec<_> = rows.iter().filter(|r| r[0] == tag).collect();
    assert_eq!(found.len(), 1);
    found[0]
}
fn decoded(bytes: &[u8], pc: u64) -> Instruction {
    let mut d = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE);
    let i = d.decode();
    assert!(!i.is_invalid() && i.len() > 0 && i.len() <= bytes.len());
    i
}
fn file_at(elf: &Elf64<'_>, pc: u64, len: usize) -> usize {
    let v = elf.virtual_to_storage(ElfVaddr(pc), len as u64).unwrap();
    let Storage::FileBacked(r) = v.storage else {
        panic!("file-backed owner required")
    };
    usize::try_from(r.start().0).unwrap()
}
fn target(state: SavedExtendedStateLayout) -> Vec<u8> {
    let kind = if state.format() == SavedExtendedStateFormat::FXSAVE64 {
        "fxsave64"
    } else {
        assert_eq!(state.format(), SavedExtendedStateFormat::XSAVE64_STANDARD);
        "xsave64-standard"
    };
    let mut out = format!(
        "LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t1\nformat\t{kind}\nallocation_bytes\t{}\nimage_bytes\t{}\nxcr0_mask\t{}\nqualification_complete\tfalse\n",
        state.len(),
        state.image_len(),
        state.mask()
    );
    for c in state.components() {
        writeln!(
            &mut out,
            "component\t{}\t{}\t{}",
            c.xfeature(),
            c.offset(),
            c.size()
        )
        .unwrap();
    }
    out.into_bytes()
}

// Independent finite byte recognizer for the existing ordinary artifact helper.
// These bytes are only compared with actual output; they are never emitted/mapped.
fn helper(pc: u64, logical: u64, state: SavedExtendedStateLayout) -> Vec<u8> {
    let mut b = unhex(
        "488d642480488d6424e09c5051525355565741504151415241534154415541564157488d84242001000050488d050000000048ba",
    );
    let anchor = pc.checked_add(b.len() as u64 - 2).unwrap();
    b.extend_from_slice(
        &i64::try_from(i128::from(logical) - i128::from(anchor))
            .unwrap()
            .to_le_bytes(),
    );
    b.extend(unhex("4801d0504989e4"));
    let fx = state.format() == SavedExtendedStateFormat::FXSAVE64;
    assert!(fx || state.format() == SavedExtendedStateFormat::XSAVE64_STANDARD);
    b.extend_from_slice(if fx {
        &[0x48, 0x83, 0xe4, 0xf0]
    } else {
        &[0x48, 0x83, 0xe4, 0xc0]
    });
    b.extend_from_slice(&[0x48, 0x81, 0xec]);
    b.extend_from_slice(&i32::try_from(state.len()).unwrap().to_le_bytes());
    let mask = state.mask();
    if fx {
        b.extend(unhex("480fae0424"));
    } else {
        b.extend(unhex("31c0"));
        for offset in (512_i32..576).step_by(8) {
            b.extend(unhex("48898424"));
            b.extend_from_slice(&offset.to_le_bytes());
        }
        if mask & 512 != 0 {
            let c = state
                .components()
                .iter()
                .find(|c| c.xfeature() == 512)
                .unwrap();
            assert_eq!(c.size(), 8);
            assert!(
                c.offset() >= 576 && c.offset() % 8 == 0 && c.offset() + 8 <= state.image_len()
            );
            b.extend(unhex("898424"));
            b.extend_from_slice(&i32::try_from(c.offset() + 4).unwrap().to_le_bytes());
        }
        b.push(0xb8);
        b.extend_from_slice(&(mask as u32).to_le_bytes());
        b.push(0xba);
        b.extend_from_slice(&((mask >> 32) as u32).to_le_bytes());
        b.extend(unhex("480fae2424"));
    }
    b.extend(unhex("4989a42490000000"));
    for (offset, value) in [
        (152_u32, state.len()),
        (160, mask),
        (168, state.format().raw()),
    ] {
        b.extend(unhex("48b8"));
        b.extend_from_slice(&value.to_le_bytes());
        b.extend(unhex("49898424"));
        b.extend_from_slice(&offset.to_le_bytes());
    }
    b.extend(unhex("fc4c89e7e8"));
    let next = pc + b.len() as u64 + 4;
    b.extend_from_slice(
        &i32::try_from(i128::from(HOOK) - i128::from(next))
            .unwrap()
            .to_le_bytes(),
    );
    if fx {
        b.extend(unhex("480fae0c24"));
    } else {
        b.push(0xb8);
        b.extend_from_slice(&(mask as u32).to_le_bytes());
        b.push(0xba);
        b.extend_from_slice(&((mask >> 32) as u32).to_le_bytes());
        b.extend(unhex("480fae2c24"));
    }
    b.extend(unhex(
        "4c89e44883c410415f415e415d415c415b415a415941585f5e5d5b5a59589d488d642420488da42480000000",
    ));
    b
}

#[derive(Clone)]
struct Head {
    logical: u64,
    route: u64,
    body: u64,
    bytes: Vec<u8>,
    target: u64,
    walk: Vec<(u64, u64, Vec<u8>)>,
}
struct Image {
    address: u64,
    bytes: Vec<u8>,
}

// The inspected corpus has only these direct branches, without prefixes. All
// other relocated instructions must retain their complete original bytes.
fn branch_kind(bytes: &[u8]) -> u8 {
    match bytes {
        [0x72, _] | [0x0f, 0x82, _, _, _, _] => 2,
        [0x73, _] | [0x0f, 0x83, _, _, _, _] => 3,
        [0x76, _] | [0x0f, 0x86, _, _, _, _] => 6,
        [0x75, _] | [0x0f, 0x85, _, _, _, _] => 5,
        [0xeb, _] | [0xe9, _, _, _, _] => 16,
        _ => panic!("unsupported branch encoding"),
    }
}

// Reconstruct only the finite published carrier layout from authenticated
// actual images. This does not invoke the planner, encoder or carrier producer.
fn carrier(
    original: &[u8],
    overlay: &[u8],
    old: &Elf64<'_>,
    images: &[Image],
    metadata: &[u8],
    plan: &[u8],
    carrier: u64,
) -> Vec<u8> {
    let old_count = old.program_headers().len();
    let existing: Vec<_> = old.segments(SegmentType::ProgramHeaders).collect();
    assert!(existing.len() <= 1);
    let insert = usize::from(existing.is_empty());
    let count = old_count + insert + 1 + images.len();
    assert!(count <= 512);
    let offset = end(original.len() as u64);
    let table_len = count as u64 * 56;
    let payload_at = (offset + table_len + 7) & !7;
    let mut payload = b"LI2TOOL-CANDIDATE-UNREADY-V1\0".to_vec();
    payload.extend_from_slice(&ContentId::of(metadata).0);
    payload.extend_from_slice(&ContentId::of(plan).0);
    let mut length = payload_at + payload.len() as u64;
    let mut loads = vec![(carrier, offset, length - offset, 4_u32)];
    let mut places = Vec::new();
    for image in images {
        let lo = image.address & !4095;
        let prefix = image.address - lo;
        let at = end(length);
        let size = prefix + image.bytes.len() as u64;
        places.push(at + prefix);
        loads.push((lo, at, size, 5));
        length = at + size;
    }
    assert!(length <= OUTPUT as u64 && length - original.len() as u64 <= 12_582_912);
    loads.sort_unstable();
    let mut expected = overlay.to_vec();
    expected.resize(length as usize, 0);
    let encode = |bytes: &mut [u8],
                  at: usize,
                  kind: u32,
                  flags: u32,
                  file: u64,
                  va: u64,
                  size: u64,
                  align: u64| {
        bytes[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        for (i, value) in [file, va, va, size, size, align].into_iter().enumerate() {
            bytes[at + 8 + i * 8..at + 16 + i * 8].copy_from_slice(&value.to_le_bytes());
        }
    };
    if insert == 1 {
        encode(
            &mut expected,
            offset as usize,
            6,
            4,
            offset,
            carrier,
            table_len,
            8,
        );
    }
    for ph in old.program_headers() {
        let to = offset as usize + (ph.index + insert) * 56;
        if ph.kind == SegmentType::ProgramHeaders {
            encode(&mut expected, to, 6, 4, offset, carrier, table_len, 8);
        } else {
            let from = old.header().program_offset.0 as usize + ph.index * 56;
            expected[to..to + 56].copy_from_slice(&original[from..from + 56]);
        }
    }
    for (i, (va, file, size, flags)) in loads.iter().enumerate() {
        encode(
            &mut expected,
            offset as usize + (old_count + insert + i) * 56,
            1,
            *flags,
            *file,
            *va,
            *size,
            4096,
        );
    }
    expected[payload_at as usize..payload_at as usize + payload.len()].copy_from_slice(&payload);
    for (image, at) in images.iter().zip(places) {
        expected[at as usize..at as usize + image.bytes.len()].copy_from_slice(&image.bytes);
    }
    expected[32..40].copy_from_slice(&offset.to_le_bytes());
    expected[56..58].copy_from_slice(&(count as u16).to_le_bytes());
    expected
}

fn field(
    offset: usize,
    width: usize,
    encoding: &str,
    origin: u64,
    target: u64,
    role: &str,
    image: &[u8],
) -> Vec<String> {
    vec![
        offset.to_string(),
        width.to_string(),
        encoding.to_owned(),
        origin.to_string(),
        target.to_string(),
        "1".to_owned(),
        hex(role.as_bytes()),
        hex(&image[offset..offset + width]),
    ]
}

fn ledger_shape(rows: &[Vec<&str>]) {
    for r in rows {
        let length = match r[0] {
            "LI2LEDGER"
            | "original_sha256"
            | "selection_sha256"
            | "bias_policy"
            | "bias_domain"
            | "qualification_complete"
            | "execution_authority"
            | "grouping"
            | "unresolved"
            | "CARRIER-EXTENSION"
            | "candidate_sha256"
            | "new_load_pages"
            | "phdr_vaddr" => 2,
            "requirement" | "route" | "restored-boundary" | "unmet-requirement"
            | "entry-preserved" => 4,
            "hook"
            | "step-read"
            | "semantic-write"
            | "live-store-span"
            | "pc-range"
            | "elf-change"
            | "original-symbol-reference" => 5,
            "step" => 8,
            "live-prerequisites-not-receipts" | "allocation" | "elf-image" => 6,
            "source-relay-geometry-hex"
            | "byte-lock"
            | "original-file-dependency"
            | "phdr_file"
            | "original-loader-table"
            | "original-loader-protected" => 3,
            "image" | "original-loader-write" => 7,
            "field" => 10,
            _ => panic!("unknown or unsupported ledger record {}", r[0]),
        };
        assert_eq!(r.len(), length);
    }
    for (tag, value) in [
        ("LI2LEDGER", "1"),
        ("bias_policy", "common-additive-module-relative-v1"),
        ("bias_domain", "1"),
        ("qualification_complete", "false"),
        ("execution_authority", "none"),
        ("grouping", "separate-backing-only"),
        ("unresolved", "loader-abi-cpu-unwind-cet"),
        ("CARRIER-EXTENSION", "1"),
    ] {
        assert_eq!(one(rows, tag)[1], value);
    }
    assert_eq!(
        *one(rows, "requirement"),
        [
            "requirement",
            "0",
            "101",
            "declared-entry-completeness-not-proven"
        ]
    );
}

// Finite policy admission for the two already authenticated original ELFs.
// This reader does not call common_sites, any planner, or a producer allocator.
const SLOT: u64 = 65536;
const DOMAIN: (u64, u64) = (65536, 65536 + 1_073_741_824);
const CARRIER: (u64, u64) = (0x2000_0000, 0x2000_8000);
const ENTRY_OPCODES: [u8; 14] = [
    0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlacementProfile {
    FixedV1,
    OriginalDerivedV1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Permit {
    range: (u64, u64),
    preferred: u64,
}
fn disjoint(a: (u64, u64), b: (u64, u64)) -> bool {
    a.1 <= b.0 || b.1 <= a.0
}
fn policy_number(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).unwrap()
    } else {
        n(s)
    }
}
fn policy_profile(
    policy: &[u8],
    original: &[u8],
    compact_target: &[u8],
    provenance: &str,
    elf: &Elf64<'_>,
) -> PlacementProfile {
    assert!(policy.len() <= 65536);
    assert!(policy.is_ascii() && policy.ends_with(b"\n") && !policy.contains(&b'\r'));
    let r: Vec<Vec<_>> = std::str::from_utf8(policy)
        .unwrap()
        .lines()
        .map(|l| {
            let row: Vec<_> = l.split(' ').collect();
            assert!(row.iter().all(|s| !s.is_empty()));
            row
        })
        .collect();
    let profile = match r[0].as_slice() {
        ["LI2COMMON", "1"] => PlacementProfile::FixedV1,
        ["LI2COMMON", "2"] => PlacementProfile::OriginalDerivedV1,
        _ => panic!("exact fixed-v1 or original-derived-v1 policy required"),
    };
    let derived = usize::from(profile == PlacementProfile::OriginalDerivedV1);
    assert_eq!(r.len(), 16 + derived);
    for (at, tag, expected) in [
        (1, "original", hash(original)),
        (2, "target", hash(compact_target)),
        (3, "provenance", provenance.to_owned()),
    ] {
        assert_eq!(r[at], [tag, expected.as_str()]);
    }
    // These exact owner coordinates come from the frozen preparation, not the
    // candidate or its policy. Whole original identity was checked by main.
    assert_eq!(r[4].len(), 5);
    assert_eq!(r[4][0], "text");
    assert_eq!(
        r[4][1..4]
            .iter()
            .map(|s| policy_number(s))
            .collect::<Vec<_>>(),
        [0x401100, 0x1100, 0x943]
    );
    assert_eq!(file_at(elf, 0x401100, 0x943), 0x1100);
    assert_eq!(
        r[4][4],
        hash(elf.executable_bytes(ElfVaddr(0x401100), 0x943).unwrap())
    );
    for (index, (source, name)) in seed::ORIGINAL_RANGES
        .iter()
        .zip(["li2_array_store", "li2_sift_down", "li2_heap_sort"])
        .enumerate()
    {
        let row = &r[5 + index];
        assert_eq!(row.len(), 5);
        assert_eq!(&row[..2], ["function", name]);
        assert_eq!(
            (policy_number(row[2]), policy_number(row[3])),
            (source.pc, source.bytes.len() as u64)
        );
        assert_eq!(
            file_at(elf, source.pc, source.bytes.len()) as u64,
            source.file_offset
        );
        let bytes = elf
            .executable_bytes(ElfVaddr(source.pc), source.bytes.len() as u64)
            .unwrap();
        assert_eq!(bytes, source.bytes);
        assert_eq!(row[4], hash(bytes));
    }
    for (index, id, pc, len) in [(8, "2", HOOK, 1), (9, "3", 0x401970, 211)] {
        let row = &r[index];
        assert_eq!(row.len(), 5);
        assert_eq!(&row[..2], ["hook", id]);
        assert_eq!((policy_number(row[2]), policy_number(row[3])), (pc, len));
        assert_eq!(
            row[4],
            hash(elf.executable_bytes(ElfVaddr(pc), len).unwrap())
        );
    }
    assert_eq!(r[10].len(), 2);
    assert_eq!(r[10][0], "carrier");
    assert_eq!(policy_number(r[10][1]), CARRIER.0);
    if derived == 1 {
        assert_eq!(r[11].len(), 4);
        assert_eq!(&r[11][..2], ["placement", "original-derived-v1"]);
        assert_eq!(
            (policy_number(r[11][2]), policy_number(r[11][3])),
            (DOMAIN.0, DOMAIN.1 - DOMAIN.0)
        );
    }
    for (index, role, base) in [(11, "selected", 0x1000_0000), (12, "victim", 0x1800_0000)] {
        let row = &r[index + derived];
        assert_eq!(row.len(), if derived == 0 { 6 } else { 4 });
        assert_eq!(&row[..2], ["arena", role]);
        let values: Vec<_> = row[2..].iter().map(|s| policy_number(s)).collect();
        if derived == 0 {
            assert_eq!(values, [base, SLOT, SLOT, 65536]);
        } else {
            assert_eq!(values, [SLOT, 65536]);
        }
    }
    assert_eq!(r[13 + derived].len(), 10);
    assert_eq!(r[13 + derived][0], "limits");
    assert_eq!(
        r[13 + derived][1..]
            .iter()
            .map(|s| policy_number(s))
            .collect::<Vec<_>>(),
        [
            1_048_576,
            64,
            256,
            8_388_608,
            2048,
            16_777_216,
            12_582_912,
            512,
            1_073_741_824
        ]
    );
    assert_eq!(r[14 + derived].len(), 6);
    assert_eq!(r[14 + derived][0], "search");
    assert_eq!(
        r[14 + derived][1..]
            .iter()
            .map(|s| policy_number(s))
            .collect::<Vec<_>>(),
        [64, 256, 64, 256, 4096]
    );
    assert_eq!(r[15 + derived], ["END"]);
    profile
}

fn original_load_ranges(elf: &Elf64<'_>) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    for h in elf.segments(SegmentType::Load) {
        assert!(h.memory_size > 0);
        let range = (
            h.vaddr.0 & !4095,
            end(h.vaddr.0.checked_add(h.memory_size).unwrap()),
        );
        assert!(range.0 < range.1 && range.1 <= 1 << 47);
        assert!(ranges.iter().all(|&prior| disjoint(prior, range)));
        ranges.push(range);
    }
    // The two fixed whole-original identities have exactly these four owners.
    assert_eq!(
        ranges,
        [
            (0x400000, 0x401000),
            (0x401000, 0x402000),
            (0x402000, 0x403000),
            (0x403000, IMAGE_END)
        ]
    );
    assert_eq!(ranges.iter().map(|&(a, b)| (b - a) / 4096).sum::<u64>(), 37);
    assert!(ranges.iter().all(|&r| disjoint(r, CARRIER)));
    ranges
}

// Independent ceiling construction: keep each possible higher prefix, raise
// exactly one byte, and fill the lower bytes with their permitted minima.
// There are four pivot choices, not a scan through the allocation domain.
#[derive(Clone)]
struct Displacement {
    next: u64,
    digits: [Vec<u8>; 4],
}
impl Displacement {
    fn plain(next: u64) -> Self {
        Self {
            next,
            digits: std::array::from_fn(|_| (0..=255).collect()),
        }
    }
    fn ceiling(&self, lower: u32) -> Option<u32> {
        if self.digits.iter().any(Vec::is_empty) {
            return None;
        }
        let bytes = lower.to_le_bytes();
        if (0..4).all(|i| self.digits[i].contains(&bytes[i])) {
            return Some(lower);
        }
        let mut best = None;
        for pivot in 0..4 {
            if !(pivot + 1..4).all(|i| self.digits[i].contains(&bytes[i])) {
                continue;
            }
            let Some(raised) = self.digits[pivot]
                .iter()
                .copied()
                .find(|&b| b > bytes[pivot])
            else {
                continue;
            };
            let mut candidate = bytes;
            candidate[pivot] = raised;
            for (i, b) in candidate.iter_mut().enumerate().take(pivot) {
                *b = self.digits[i][0];
            }
            let value = u32::from_le_bytes(candidate);
            best = Some(best.map_or(value, |old: u32| old.min(value)));
        }
        best
    }
    fn first(&self, interval: (u64, u64)) -> Option<u64> {
        if interval.0 >= interval.1 {
            return None;
        }
        let low = (i128::from(interval.0) - i128::from(self.next)).max(i128::from(i32::MIN));
        let high = (i128::from(interval.1 - 1) - i128::from(self.next)).min(i128::from(i32::MAX));
        if low > high {
            return None;
        }
        for (a, b) in [(low, high.min(-1)), (low.max(0), high)] {
            if a > b {
                continue;
            }
            let value = self.ceiling(a as i32 as u32);
            if let Some(value) = value.filter(|&v| v <= b as i32 as u32) {
                return u64::try_from(i128::from(self.next) + i128::from(value as i32)).ok();
            }
        }
        None
    }
}
fn original_block(head: &seed::Head) -> (u64, u64) {
    let function = seed::ORIGINAL_RANGES
        .iter()
        .find(|r| r.function == head.function)
        .unwrap();
    let stop = function.pc + function.bytes.len() as u64;
    let mut cuts = BTreeSet::from([function.pc, stop]);
    for h in seed::HEADS.iter().filter(|h| h.function == head.function) {
        if h.flow != seed::Flow::Next && h.pc + u64::from(h.length) < stop {
            cuts.insert(h.pc + u64::from(h.length));
        }
        match h.flow {
            seed::Flow::Jb(t)
            | seed::Flow::Jae(t)
            | seed::Flow::Jbe(t)
            | seed::Flow::Jne(t)
            | seed::Flow::Jump(t) => {
                cuts.insert(t);
            }
            _ => {}
        }
    }
    let cuts: Vec<_> = cuts.into_iter().collect();
    let pair = cuts
        .windows(2)
        .find(|v| v[0] <= head.pc && head.pc < v[1])
        .unwrap();
    (pair[0], pair[1])
}
fn pun_displacement(head: &seed::Head, prefixes: usize) -> Option<Displacement> {
    let pc = head.pc;
    let len = usize::from(head.length);
    let function = seed::ORIGINAL_RANGES
        .iter()
        .find(|r| r.function == head.function)
        .unwrap();
    let block = original_block(head);
    let stop = pc.checked_add(len as u64)?;
    let next = pc.checked_add(5 + prefixes as u64)?;
    let store_len = len.next_power_of_two() as u64;
    let store = pc.min((pc | 63).checked_sub(store_len - 1)?);
    if !(1..=4).contains(&len)
        || prefixes >= len
        || stop > block.1
        || next > function.pc + function.bytes.len() as u64
        || pc / 64 != (stop - 1) / 64
        || store < function.pc
        || store.checked_add(store_len)? > function.pc + function.bytes.len() as u64
    {
        return None;
    }
    let offset = (pc - function.pc) as usize;
    let free = len - prefixes - 1;
    let suffix = function.bytes.get(offset + len..offset + 5 + prefixes)?;
    let mut raw = [0; 4];
    raw[free..].copy_from_slice(suffix);
    // The producer/core require the complete pun window to be representable
    // before clipping it to the caller's declared domain.
    let low = u64::try_from(i128::from(next) + i128::from(i32::from_le_bytes(raw))).ok()?;
    low.checked_add(1_u64 << (free * 8))?;
    let mut rule = Displacement::plain(next);
    for (digit, byte) in rule.digits.iter_mut().zip(raw).skip(free) {
        *digit = vec![byte];
    }
    Some(rule)
}
fn original_displacements(head: &seed::Head) -> Vec<Displacement> {
    let mut rules: Vec<_> = pun_displacement(head, 0).into_iter().collect();
    let block = original_block(head);
    let function_heads: Vec<_> = seed::HEADS
        .iter()
        .filter(|h| h.function == head.function)
        .collect();
    let mut physical: Vec<_> = function_heads
        .iter()
        .copied()
        .filter(|h| block.0 <= h.pc && h.pc < block.1 && h.pc <= head.pc && head.pc - h.pc <= 64)
        .collect();
    physical.sort_by_key(|h| (h.pc != head.pc, h.pc % 64 > 56, head.pc - h.pc));
    for physical in physical.into_iter().take(64) {
        let needed = (physical.pc + 5).max(head.pc + u64::from(head.length));
        let window: Vec<_> = function_heads
            .iter()
            .copied()
            .filter(|h| physical.pc <= h.pc && h.pc < needed && h.pc < block.1)
            .collect();
        let stop = window
            .last()
            .map_or(physical.pc, |h| h.pc + u64::from(h.length));
        if stop < needed
            || stop > block.1
            || stop - physical.pc > 256
            || window.iter().any(|h| {
                matches!(h.flow, seed::Flow::Call(_))
                    || (h.flow != seed::Flow::Next && h.pc + u64::from(h.length) != stop)
            })
        {
            continue;
        }
        let mut rule = Displacement::plain(physical.pc + 5);
        for h in &function_heads {
            if physical.pc < h.pc && h.pc < rule.next {
                rule.digits[(h.pc - physical.pc - 1) as usize] = ENTRY_OPCODES.to_vec();
            }
        }
        rules.push(rule);
    }
    for prefixes in 1..usize::from(head.length).min(4) {
        rules.extend(pun_displacement(head, prefixes));
    }
    rules
}
fn vacant_permit(
    occupied: &[(u64, u64)],
    rule: &Displacement,
    reach: (u64, u64),
) -> Option<Permit> {
    let mut obstacles = occupied.to_vec();
    obstacles.sort_unstable();
    obstacles.push((DOMAIN.1, DOMAIN.1));
    let mut left = DOMAIN.0;
    for (a, b) in obstacles {
        if a > left && a - left >= SLOT {
            // Last preferred byte is in the last page whose entire 64KiB
            // reservation fits. The preferred PC need not be the page base.
            let last_page = a - SLOT;
            if let Some(pc) = rule.first((left.max(reach.0), (last_page + 4096).min(reach.1))) {
                let start = pc & !4095;
                return Some(Permit {
                    range: (start, start + SLOT),
                    preferred: pc,
                });
            }
        }
        left = left.max(b);
    }
    None
}
fn common_reach(heads: impl Iterator<Item = u64>) -> (u64, u64) {
    let (mut low, mut high) = (0_i128, 1_i128 << 47);
    for pc in heads {
        let next = i128::from(pc.checked_add(5).unwrap());
        low = low.max(next + i128::from(i32::MIN));
        high = high.min(next + i128::from(i32::MAX) + 1);
    }
    assert!(low < high);
    (u64::try_from(low).unwrap(), u64::try_from(high).unwrap())
}
fn derived_permits(original: &[(u64, u64)], pcs: &[u64]) -> Vec<[Permit; 2]> {
    assert!(!pcs.is_empty() && pcs.len() <= 64 && pcs.windows(2).all(|v| v[0] < v[1]));
    let mut occupied = original.to_vec();
    occupied.push(CARRIER);
    assert!(
        occupied
            .iter()
            .all(|&(a, b)| DOMAIN.0 <= a && a < b && b <= DOMAIN.1)
    );
    let blank = Permit {
        range: (0, 0),
        preferred: 0,
    };
    let mut permits = vec![[blank; 2]; pcs.len()];
    let mut pending = Vec::new();
    for (i, &pc) in pcs.iter().enumerate() {
        let h = seed::HEADS.iter().find(|h| h.pc == pc).unwrap();
        let found = original_displacements(h)
            .iter()
            .find_map(|rule| vacant_permit(&occupied, rule, DOMAIN));
        if let Some(permit) = found {
            occupied.push(permit.range);
            permits[i][0] = permit;
        } else {
            pending.push(i);
        }
    }
    // Neutral placement never claims that B2/B1/T1 or a compound tactic fits.
    // In particular ID15 stays selected even when its original patterns miss.
    for i in pending {
        let pc = pcs[i];
        let permit = vacant_permit(
            &occupied,
            &Displacement::plain(pc + 5),
            common_reach([pc].into_iter()),
        )
        .expect("complete neutral selected slot required");
        occupied.push(permit.range);
        permits[i][0] = permit;
    }
    for (i, &pc) in pcs.iter().enumerate() {
        let h = seed::HEADS.iter().find(|h| h.pc == pc).unwrap();
        let reach = common_reach(
            seed::HEADS
                .iter()
                .filter(|v| v.function == h.function)
                .map(|v| v.pc),
        );
        let permit = vacant_permit(&occupied, &Displacement::plain(pc + 5), reach)
            .expect("complete neutral victim slot required");
        occupied.push(permit.range);
        permits[i][1] = permit;
    }
    for (index, &range) in occupied.iter().enumerate() {
        assert!(
            occupied[..index]
                .iter()
                .all(|&prior| disjoint(prior, range))
        );
    }
    permits
}

fn main() {
    let mut args: Vec<_> = std::env::args_os().collect();
    let planning = PlanningProfile::arguments(&mut args, 7);
    assert_eq!(
        args.len(),
        7,
        "verify_common_core ORIGINAL INSTRUCTIONS TARGET INVENTORY_DIRECTORY BUNDLE NEW_WITNESS"
    );
    let original = Bound::read(Path::new(&args[1]), INPUT, false);
    assert!(
        [
            seed::ORIGINAL_SHA256,
            "1c7c66c58376c98df1dc3e5fd76d3c22a82ad7e96ef7aee1543a7c5b90a6f529"
        ]
        .contains(&hash(&original.bytes).as_str()),
        "one of the two frozen actual originals"
    );
    let instructions = Bound::read(Path::new(&args[2]), 16_384, false);
    let target_input = Bound::read(Path::new(&args[3]), 16_384, false);
    let inventory = Path::new(&args[4]);
    let directory = Path::new(&args[5]);
    assert!(inventory.is_absolute() && directory.is_absolute());
    assert_eq!(
        inventory.canonicalize().unwrap().as_os_str(),
        inventory.as_os_str()
    );
    assert_eq!(
        directory.canonicalize().unwrap().as_os_str(),
        directory.as_os_str()
    );
    let selection = Bound::read(&inventory.join("selection.txt"), INPUT, false);
    let inventory_table = Bound::read(&inventory.join("instructions.tsv"), 16_384, false);
    assert_eq!(inventory_table.bytes, instructions.bytes);
    let inventory_names = [
        "blocks.tsv",
        "instructions.tsv",
        "memory-writes.tsv",
        "padding.tsv",
        "policy.txt",
        "selection.txt",
        "sites.tsv",
        "status.tsv",
        "target.txt",
    ];
    let inventory_inputs: BTreeMap<_, _> = inventory_names
        .into_iter()
        .map(|name| (name, Bound::read(&inventory.join(name), INPUT, true)))
        .collect();
    let inventory_complete = Bound::read(&inventory.join("COMPLETE"), 16_384, false);
    let expected_index = String::from("LI2COMMONFILES\t1\n")
        + &inventory_inputs
            .iter()
            .map(|(name, b)| format!("{}\t{}\t{name}\n", hash(&b.bytes), b.bytes.len()))
            .collect::<String>();
    assert_eq!(inventory_complete.bytes, expected_index.as_bytes());
    assert_eq!(
        std::fs::read_dir(inventory)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect::<BTreeSet<_>>(),
        inventory_names
            .into_iter()
            .chain(["COMPLETE"])
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(inventory_inputs["selection.txt"].bytes, selection.bytes);
    assert_eq!(
        inventory_inputs["instructions.tsv"].bytes,
        instructions.bytes
    );
    let status = rows(&inventory_inputs["status.tsv"].bytes);
    assert_eq!(status[0], ["LI2COMMONRESULT", "1"]);
    assert_eq!(status.len(), 12);
    let provenance: Vec<_> = std::str::from_utf8(&inventory_inputs["policy.txt"].bytes)
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_prefix("provenance "))
        .collect();
    assert_eq!(provenance.len(), 1);
    assert!(
        provenance[0].len() == 64
            && provenance[0]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(one(&status, "caller_provenance_sha256")[1], provenance[0]);
    for (key, value) in [
        ("original_sha256", hash(&original.bytes)),
        ("policy_sha256", hash(&inventory_inputs["policy.txt"].bytes)),
        ("target_sha256", hash(&inventory_inputs["target.txt"].bytes)),
        ("selection_sha256", hash(&selection.bytes)),
        ("hook", "null".to_owned()),
        ("instruction_heads", "87".to_owned()),
        ("complete_static_policy", "true".to_owned()),
        ("qualification_complete", "false".to_owned()),
    ] {
        assert_eq!(one(&status, key)[1], value);
    }
    let s = liteinst_rewrite::selection::parse(&selection.bytes).unwrap();
    assert_eq!(s.original, ContentId::of(&original.bytes));
    assert_eq!(s.bias_domain, 1);
    assert_eq!(s.carrier_pc, 0x20000000);
    assert_eq!(
        (
            s.limits.input_bytes,
            s.limits.sites,
            s.limits.images,
            s.limits.image_bytes
        ),
        (INPUT, 64, 256, 8_388_608)
    );
    assert_eq!(
        (
            s.limits.new_load_pages,
            s.limits.output_bytes,
            s.limits.added_file_bytes,
            s.limits.program_headers,
            s.limits.virtual_span
        ),
        (2048, 16_777_216, 12_582_912, 512, 1_073_741_824)
    );
    assert_eq!(target(s.target), target_input.bytes);
    assert_eq!(s.hooks.len(), 1);
    let compact = if s.target.format() == SavedExtendedStateFormat::FXSAVE64 {
        "target fxsave64\n".to_owned()
    } else {
        let mut line = format!("target xsave64 {}", s.target.mask());
        for c in s.target.components() {
            write!(&mut line, " {}:{}:{}", c.xfeature(), c.offset(), c.size()).unwrap();
        }
        line.push('\n');
        line
    };
    assert_eq!(inventory_inputs["target.txt"].bytes, compact.as_bytes());
    let h = &s.hooks[0];
    assert_eq!((h.id, h.pc, h.length), (2, HOOK, 1));
    assert_eq!(h.expected, ContentId::of(&[0xc3]));
    let ranges: Vec<_> = seed::ORIGINAL_RANGES
        .iter()
        .map(|r| seed::SourceRange {
            function: r.function,
            pc: r.pc,
            file_offset: r.file_offset,
            bytes: &original.bytes[r.file_offset as usize..r.file_offset as usize + r.bytes.len()],
        })
        .collect();
    let _ = seed::authenticate(&instructions.bytes, &ranges).unwrap();
    let source_elf = Elf64::parse(
        &original.bytes,
        ParseLimits {
            max_program_headers: 512,
        },
    )
    .unwrap();
    source_elf.check_load_page_congruence(4096).unwrap();
    let original_ranges = original_load_ranges(&source_elf);
    let profile = policy_profile(
        &inventory_inputs["policy.txt"].bytes,
        &original.bytes,
        compact.as_bytes(),
        provenance[0],
        &source_elf,
    );
    let selected: BTreeMap<_, _> = s.sites.iter().map(|x| (x.pc, x)).collect();
    assert_eq!(selected.len(), s.sites.len());
    let jump: BTreeSet<_> = seed::HEADS
        .iter()
        .filter(|h| {
            matches!(
                h.flow,
                seed::Flow::Jb(_)
                    | seed::Flow::Jae(_)
                    | seed::Flow::Jbe(_)
                    | seed::Flow::Jne(_)
                    | seed::Flow::Jump(_)
            )
        })
        .map(|h| h.pc)
        .collect();
    let chosen: BTreeSet<_> = selected.keys().copied().collect();
    assert!(chosen == jump || chosen == BTreeSet::from([0x401840]));
    assert!(s.sites.windows(2).all(|v| v[0].id < v[1].id));
    assert_eq!(n(one(&status, "selected_sites")[1]), s.sites.len() as u64);
    assert_eq!(
        one(&status, "style")[1],
        if chosen == jump {
            "jump-site"
        } else {
            "heap-write"
        }
    );
    let derived = if profile == PlacementProfile::OriginalDerivedV1 {
        Some(derived_permits(
            &original_ranges,
            &s.sites.iter().map(|x| x.pc).collect::<Vec<_>>(),
        ))
    } else {
        None
    };
    for (index, x) in s.sites.iter().enumerate() {
        let ordinal = seed::HEADS.iter().position(|h| h.pc == x.pc).unwrap();
        let head = &seed::HEADS[ordinal];
        assert_eq!(x.id, ordinal as u64 + 1);
        assert_eq!((x.block.start(), x.block.end()), original_block(head));
        assert_eq!(x.length, head.length);
        assert_eq!(x.hook, 2);
        assert_eq!(x.completeness, EntryCompleteness::Complete);
        assert_eq!(x.resumes, ResumeObligation::NoneExist);
        assert_eq!(x.semantics, li2core::planner::HookSemantics::Observe);
        assert!(x.forced.is_none() && x.forced_victim.is_none());
        assert_eq!(
            x.search.tactics,
            li2core::quiescent::TacticPolicy::PreferGeneralizedPun
        );
        assert_eq!(
            (
                x.search.max_upstream_bytes,
                x.search.max_displaced_bytes,
                x.search.max_sites,
                x.max_victims,
                x.max_pairs
            ),
            (64, 256, 64, 256, 4096)
        );
        let range = seed::ORIGINAL_RANGES
            .iter()
            .find(|r| r.function == head.function)
            .unwrap();
        assert_eq!(
            (
                x.function.start(),
                x.function.end(),
                x.snapshot.start(),
                x.snapshot.end()
            ),
            (
                range.pc,
                range.pc + range.bytes.len() as u64,
                range.pc,
                range.pc + range.bytes.len() as u64
            )
        );
        assert_eq!(x.file_offset, range.file_offset + x.pc - range.pc);
        assert_eq!(
            x.provenance,
            ContentId::of(&inventory_inputs["policy.txt"].bytes)
        );
        assert_eq!(
            x.heads
                .iter()
                .map(|h| (h.address, h.requires_endbr))
                .collect::<Vec<_>>(),
            seed::HEADS
                .iter()
                .filter(|h| h.function == head.function)
                .map(|h| (h.pc, false))
                .collect::<Vec<_>>()
        );
        if let Some(permits) = &derived {
            for (a, expected) in [&x.selected_allocation, &x.victim_allocation]
                .into_iter()
                .zip(permits[index])
            {
                assert_eq!(a.ranges.len(), 1);
                assert_eq!((a.ranges[0].start(), a.ranges[0].end()), expected.range);
                assert_eq!(a.preferred_address, Some(expected.preferred));
                assert_eq!(
                    (a.max_candidates, a.max_mappings, a.max_mapped_bytes),
                    (65536, 1, 65536)
                );
            }
        } else {
            for (base, a) in [
                (0x10000000_u64, &x.selected_allocation),
                (0x18000000, &x.victim_allocation),
            ] {
                let address = base + index as u64 * 65536;
                assert_eq!(a.ranges.len(), 1);
                assert_eq!(
                    (a.ranges[0].start(), a.ranges[0].end()),
                    (address, address + 65536)
                );
                assert_eq!(a.preferred_address, Some(address));
                assert_eq!(
                    (a.max_candidates, a.max_mappings, a.max_mapped_bytes),
                    (65536, 1, 65536)
                );
            }
        }
    }
    let complete = Bound::read(&directory.join("COMPLETE"), 1024, false);
    let index = Bound::read(&directory.join("bundle-index.tsv"), INPUT, false);
    assert_eq!(complete.bytes,format!("LI2TOOL-DIRECTORY 1\nindex_sha256 {}\ncandidate_complete true\nqualification_complete false\n",hash(&index.bytes)).as_bytes());
    let ir = rows(&index.bytes);
    assert_eq!(ir[0], vec!["LI2BUNDLE", "1"]);
    assert_eq!(one(&ir, "original_sha256")[1], hash(&original.bytes));
    assert_eq!(one(&ir, "qualification_complete")[1], "false");
    assert_eq!(
        one(&ir, "consumer_action")[1],
        "RuntimeScan-while-gated-until-qualified"
    );
    let mut files = BTreeMap::new();
    let mut previous = String::new();
    for r in ir.iter().skip(4) {
        assert_eq!(r.len(), 4);
        assert_eq!(r[0], "file");
        assert!(r[1] > previous.as_str());
        previous = r[1].to_owned();
        assert!(
            r[1].bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && !r[1].starts_with('.')
        );
        assert!(n(r[2]) <= OUTPUT as u64);
        let f = Bound::read(&directory.join(r[1]), OUTPUT, true);
        assert_eq!(f.bytes.len() as u64, n(r[2]));
        assert_eq!(hash(&f.bytes), r[3]);
        assert!(files.insert(r[1].to_owned(), f).is_none());
    }
    planning.marker(
        files
            .get(planning_profile::MARKER)
            .map(|f| f.bytes.as_slice()),
    );
    assert_eq!(files["selection.txt"].bytes, selection.bytes);
    assert_eq!(files["target.tsv"].bytes, target_input.bytes);
    let actual: BTreeSet<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    let mut names: BTreeSet<_> = files.keys().cloned().collect();
    names.extend(["COMPLETE".to_owned(), "bundle-index.tsv".to_owned()]);
    assert_eq!(actual, names);
    let policy = Compatibility {
        planner: CONTRACT_VERSION,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&target_input.bytes),
        binding: ContentId::of(&selection.bytes),
    };
    let meta = Metadata::decode(
        &files["metadata.li2meta"].bytes,
        &policy,
        formats::Limits {
            bytes: OUTPUT,
            chunks: INPUT.div_ceil(formats::CHUNK_BYTES),
            sites: 64,
        },
    )
    .unwrap();
    meta.verify_original(&original.bytes).unwrap();
    meta.verify_selection(
        ContentId::of(&selection.bytes),
        &s.sites.iter().map(|x| x.id).collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(meta.declares_complete_trampoline_coverage());
    for (a, b) in meta.sites().iter().zip(&s.sites) {
        assert_eq!(
            (a.id, a.original_pc, a.file_offset, a.length),
            (b.id, b.pc, b.file_offset, b.length)
        );
        assert!(matches!(a.outcome, Outcome::Rewritten(_)));
    }
    let report = rows(&files["report.tsv"].bytes);
    assert_eq!(report[0], ["LI2REPORT", "1"]);
    assert_eq!(report.len(), 6 + s.sites.len());
    assert_eq!(one(&report, "original_sha256")[1], hash(&original.bytes));
    assert_eq!(one(&report, "selection_sha256")[1], hash(&selection.bytes));
    assert_eq!(one(&report, "candidate_complete")[1], "true");
    assert_eq!(one(&report, "qualification_complete")[1], "false");
    for ((row, site), metadata) in report[6..].iter().zip(&s.sites).zip(meta.sites()) {
        assert_eq!(row.len(), 9);
        assert_eq!(
            (n(row[0]), n(row[1]), n(row[2]), n(row[3])),
            (site.id, site.pc, site.file_offset, u64::from(site.length))
        );
        assert_eq!(&row[5..], ["true", "none", "none", ""]);
        let Outcome::Rewritten(tactic) = metadata.outcome else {
            unreachable!()
        };
        let name = match tactic {
            formats::Tactic::Relocation => "B1",
            formats::Tactic::GeneralizedPun => "B2",
            formats::Tactic::PrefixedPun => "T1",
            formats::Tactic::SuccessorEviction => "T2",
            formats::Tactic::NeighborEviction => "T3",
        };
        assert_eq!(row[4], name);
    }
    let candidate = &files["candidate.elf"].bytes;
    assert!(
        candidate.len() > original.bytes.len()
            && candidate.len() - original.bytes.len() <= 12_582_912
    );
    let limits = ParseLimits {
        max_program_headers: 512,
    };
    let old = Elf64::parse(&original.bytes, limits).unwrap();
    let elf = Elf64::parse(candidate, limits).unwrap();
    old.check_load_page_congruence(4096).unwrap();
    elf.check_load_page_congruence(4096).unwrap();
    assert_eq!(elf.header().entry, old.header().entry);
    assert_eq!(
        old.header().object_type,
        liteinst_rewrite::carrier::elf64::ObjectType::Executable
    );
    assert_eq!(elf.header().object_type, old.header().object_type);
    assert_eq!(old.executable_bytes(ElfVaddr(HOOK), 1).unwrap(), [0xc3]);
    assert_eq!(elf.executable_bytes(ElfVaddr(HOOK), 1).unwrap(), [0xc3]);
    let plan = &files["plan-ledger.tsv"].bytes;
    let full = &files["ledger.tsv"].bytes;
    assert!(full.starts_with(plan));
    assert!(!rows(plan).iter().any(|r| r[0] == "CARRIER-EXTENSION"));
    assert!(full[plan.len()..].starts_with(b"CARRIER-EXTENSION\t1\n"));
    let r = rows(full);
    ledger_shape(&r);
    assert_eq!(r[0], vec!["LI2LEDGER", "1"]);
    assert_eq!(one(&r, "original_sha256")[1], hash(&original.bytes));
    assert_eq!(one(&r, "selection_sha256")[1], hash(&selection.bytes));
    assert_eq!(one(&r, "candidate_sha256")[1], hash(candidate));
    assert_eq!(
        *one(&r, "hook"),
        [
            "hook".to_owned(),
            "2".to_owned(),
            HOOK.to_string(),
            "1".to_owned(),
            hash(&[0xc3])
        ]
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
    );
    assert!(!r.iter().any(|x| x[0] == "entry-router-required"));
    let foreign_pairs = if planning == PlanningProfile::OwnedForeignNeighbors {
        common_core_foreign::pairs(&s.sites, &r, &report)
    } else {
        Vec::new()
    };
    let mut overlay = original.bytes.clone();
    let mut steps = BTreeSet::new();
    let mut step_counts = BTreeMap::<u64, u64>::new();
    let mut allocations = Vec::new();
    for step in r.iter().filter(|x| x[0] == "step") {
        assert_eq!(step.len(), 8);
        assert!(steps.insert((n(step[1]), n(step[2]))));
        assert!(s.sites.iter().any(|x| x.id == n(step[1])));
        let count = step_counts.entry(n(step[1])).or_default();
        assert_eq!(n(step[2]), *count);
        *count += 1;
        assert!(matches!(
            step[3],
            "relocation" | "generalized-pun" | "prefixed-pun"
        ));
        assert!(n(step[6]) < n(step[7]));
        assert!(seed::HEADS.iter().any(|h| h.pc == n(step[4])));
        assert!(
            seed::ORIGINAL_RANGES
                .iter()
                .any(|q| q.pc <= n(step[6]) && n(step[7]) <= q.pc + q.bytes.len() as u64)
        );
        let live: Vec<_> = r
            .iter()
            .filter(|x| {
                x[0] == "live-prerequisites-not-receipts" && x[1] == step[1] && x[2] == step[2]
            })
            .collect();
        assert_eq!(live.len(), 1);
        assert_eq!(&live[0][3..], ["true", "true", "false"]);
        if planning == PlanningProfile::OwnedForeignNeighbors {
            common_core_foreign::check_current_read(&s.sites, &r, step, &overlay);
            for pair in &foreign_pairs {
                pair.before_step(&s.sites, &r, step, &overlay);
            }
        }
        for read in r
            .iter()
            .filter(|x| x[0] == "step-read" && x[1] == step[1] && x[2] == step[2])
        {
            assert_eq!(read.len(), 5);
            let b = unhex(read[4]);
            let at = file_at(&old, n(read[3]), b.len());
            assert_eq!(&overlay[at..at + b.len()], b);
        }
        for write in r
            .iter()
            .filter(|x| x[0] == "semantic-write" && x[1] == step[1] && x[2] == step[2])
        {
            assert_eq!(write.len(), 5);
            let b = unhex(write[4]);
            let pc = n(write[3]);
            assert!(
                seed::ORIGINAL_RANGES
                    .iter()
                    .any(|q| q.pc <= pc && pc + b.len() as u64 <= q.pc + q.bytes.len() as u64)
            );
            let at = file_at(&old, pc, b.len());
            overlay[at..at + b.len()].copy_from_slice(&b);
        }
        for store in r
            .iter()
            .filter(|x| x[0] == "live-store-span" && x[1] == step[1] && x[2] == step[2])
        {
            let b = unhex(store[4]);
            let at = file_at(&old, n(store[3]), b.len());
            assert_eq!(
                &overlay[at..at + b.len()],
                b,
                "complete prospective publication span"
            );
        }
        for a in r
            .iter()
            .filter(|x| x[0] == "allocation" && x[1] == step[1] && x[2] == step[2])
        {
            let (lo, hi, align) = (n(a[3]), n(a[4]), n(a[5]));
            assert!(lo < hi && align.is_power_of_two() && lo % align == 0 && hi <= 1 << 47);
            assert!(
                original_ranges
                    .iter()
                    .all(|&range| disjoint(range, (lo, hi)))
            );
            assert!(disjoint(CARRIER, (lo, hi)));
            assert!(allocations.iter().all(|&(_, a, b)| hi <= a || b <= lo));
            let site = s.sites.iter().find(|x| x.id == n(step[1])).unwrap();
            assert!(
                site.selected_allocation
                    .ranges
                    .iter()
                    .chain(&site.victim_allocation.ranges)
                    .any(|range| range.start() <= lo && hi <= range.end())
            );
            allocations.push((n(step[1]), lo, hi));
        }
    }
    assert_eq!(
        step_counts.keys().copied().collect::<BTreeSet<_>>(),
        s.sites.iter().map(|x| x.id).collect()
    );
    for row in &r {
        if matches!(
            row[0],
            "step-read"
                | "semantic-write"
                | "live-store-span"
                | "entry-preserved"
                | "allocation"
                | "live-prerequisites-not-receipts"
        ) {
            assert!(steps.contains(&(n(row[1]), n(row[2]))));
        }
    }
    let locks: Vec<_> = r
        .iter()
        .filter(|x| x[0] == "byte-lock")
        .map(|x| (n(x[1]), n(x[2])))
        .collect();
    assert!(locks.windows(2).all(|x| x[0].1 <= x[1].0));
    for &(a, b) in &locks {
        assert!(
            a < b
                && seed::ORIGINAL_RANGES
                    .iter()
                    .any(|q| q.pc <= a && b <= q.pc + q.bytes.len() as u64)
        );
    }
    for write in r.iter().filter(|x| x[0] == "semantic-write") {
        let a = n(write[3]);
        let b = a + unhex(write[4]).len() as u64;
        assert!(locks.iter().any(|&(lo, hi)| lo <= a && b <= hi));
    }
    let dependencies: Vec<_> = r
        .iter()
        .filter(|x| x[0] == "original-file-dependency")
        .map(|x| {
            let (a, b) = (n(x[1]), n(x[2]));
            assert!(a < b && b <= original.bytes.len() as u64);
            liteinst_rewrite::carrier::elf64::FileRange::checked(
                liteinst_rewrite::carrier::elf64::FileOffset(a),
                b - a,
            )
            .unwrap()
        })
        .collect();
    let dynamic = liteinst_rewrite::carrier::dynamic::inspect(
        &old,
        liteinst_rewrite::carrier::dynamic::Limits::default(),
    )
    .unwrap();
    dynamic.check_source_ranges(&dependencies).unwrap();
    let kernel_dependencies: Vec<_> = seed::ORIGINAL_RANGES
        .iter()
        .map(|q| {
            liteinst_rewrite::carrier::elf64::FileRange::checked(
                liteinst_rewrite::carrier::elf64::FileOffset(q.file_offset),
                q.bytes.len() as u64,
            )
            .unwrap()
        })
        .chain([liteinst_rewrite::carrier::elf64::FileRange::checked(
            liteinst_rewrite::carrier::elf64::FileOffset(file_at(&old, HOOK, 1) as u64),
            1,
        )
        .unwrap()])
        .collect();
    dynamic.check_source_ranges(&kernel_dependencies).unwrap();
    let mut dynamic_rows = Vec::new();
    for v in &dynamic.writes {
        dynamic_rows.push(format!(
            "original-loader-write\t{:?}\t{}\t{}\t{}\t{}\t{}",
            v.table,
            v.record,
            v.kind,
            v.symbol,
            v.range.start().0,
            v.range.len()
        ));
    }
    for v in &dynamic.symbol_references {
        dynamic_rows.push(format!(
            "original-symbol-reference\t{:?}\t{}\t{}\t{}",
            v.table, v.record, v.kind, v.symbol
        ));
    }
    for v in &dynamic.tables {
        dynamic_rows.push(format!(
            "original-loader-table\t{}\t{}",
            v.start().0,
            v.len()
        ));
    }
    for v in &dynamic.protected {
        dynamic_rows.push(format!(
            "original-loader-protected\t{}\t{}",
            v.start().0,
            v.len()
        ));
    }
    assert_eq!(
        r.iter()
            .filter(|x| matches!(
                x[0],
                "original-loader-write"
                    | "original-symbol-reference"
                    | "original-loader-table"
                    | "original-loader-protected"
            ))
            .map(|x| x.join("\t"))
            .collect::<Vec<_>>(),
        dynamic_rows
    );
    let sparse = formats::sparse_wire::decode(
        &files["source.li2sparse"].bytes,
        &original.bytes,
        formats::sparse_wire::Limits {
            bytes: OUTPUT,
            content: formats::sparse::Limits {
                edits: INPUT,
                edited_bytes: INPUT,
                pages: INPUT.div_ceil(4096),
            },
        },
    )
    .unwrap();
    let mut sparse_view = original.bytes.clone();
    for e in sparse.edits() {
        let at = e.offset as usize;
        sparse_view[at..at + e.replacement.len()].copy_from_slice(&e.replacement);
    }
    assert_eq!(sparse_view, overlay);
    overlay[32..40].copy_from_slice(&candidate[32..40]);
    overlay[56..58].copy_from_slice(&candidate[56..58]);
    assert_eq!(&candidate[..original.bytes.len()], overlay);
    let mut images = Vec::new();
    let mut all_heads = BTreeMap::new();
    let mut expected_names = BTreeSet::from(
        [
            "candidate.elf",
            "metadata.li2meta",
            "source.li2sparse",
            "target.tsv",
            "selection.txt",
            "report.tsv",
            "ledger.tsv",
            "plan-ledger.tsv",
        ]
        .map(str::to_owned),
    );
    if planning == PlanningProfile::OwnedForeignNeighbors {
        expected_names.insert(planning_profile::MARKER.to_owned());
    }
    for site in &s.sites {
        expected_names.insert(format!("site-{}.diagnostics.txt", site.id));
    }
    for row in r.iter().filter(|x| x[0] == "image") {
        assert_eq!(row.len(), 7);
        let id = n(row[1]);
        assert_eq!(id, images.len() as u64);
        assert!(id < 256);
        assert!(s.sites.iter().any(|x| x.id == n(row[2])));
        let address = n(row[3]);
        let filename = format!("image-{id:04}.bin");
        assert_eq!(row[6], filename);
        expected_names.insert(filename.clone());
        let bytes = files[&filename].bytes.clone();
        assert_eq!(n(row[4]), bytes.len() as u64);
        assert_eq!(row[5], hash(&bytes));
        assert!(!bytes.is_empty());
        assert_eq!(
            allocations
                .iter()
                .filter(|&&(site, lo, hi)| site == n(row[2])
                    && lo <= address
                    && address + bytes.len() as u64 <= hi)
                .count(),
            1
        );
        assert_eq!(
            elf.executable_bytes(ElfVaddr(address), bytes.len() as u64)
                .unwrap(),
            bytes
        );
        let er: Vec<_> = r
            .iter()
            .filter(|x| x[0] == "elf-image" && n(x[1]) == id)
            .collect();
        assert_eq!(er.len(), 1);
        assert_eq!(er[0].len(), 6);
        let storage = elf
            .virtual_to_storage(ElfVaddr(address), bytes.len() as u64)
            .unwrap();
        assert_eq!(storage.flags.0, 5);
        assert_eq!(
            (n(er[0][2]), n(er[0][3]), n(er[0][4]), n(er[0][5])),
            (
                address,
                file_at(&elf, address, bytes.len()) as u64,
                bytes.len() as u64,
                storage.program_header as u64
            )
        );
        let routes: Vec<_> = r
            .iter()
            .filter(|x| x[0] == "route" && n(x[1]) == id)
            .collect();
        let restored: Vec<_> = r
            .iter()
            .filter(|x| x[0] == "restored-boundary" && n(x[1]) == id)
            .collect();
        assert!(!routes.is_empty() && routes.len() == restored.len());
        let mut heads: Vec<Head> = Vec::new();
        let mut cursor = address;
        let mut expected_fields = Vec::new();
        let mut expected_pc_ranges = Vec::new();
        let mut hooks = 0;
        for route in routes {
            assert_eq!(route.len(), 4);
            let logical = n(route[2]);
            let entry = n(route[3]);
            assert_eq!(entry, cursor);
            let src = seed::HEADS.iter().find(|h| h.pc == logical).unwrap();
            assert!(
                !matches!(src.flow, seed::Flow::Call(_)),
                "Observe CALL displacement unsupported"
            );
            if let Some(previous) = heads.last() {
                let original = seed::HEADS
                    .iter()
                    .find(|h| h.pc == previous.logical)
                    .unwrap();
                assert_eq!(logical, original.pc + u64::from(original.length));
            }
            let bs: Vec<_> = restored.iter().filter(|x| n(x[2]) == logical).collect();
            assert_eq!(bs.len(), 1);
            let body = n(bs[0][3]);
            assert!(entry <= body && body < address + bytes.len() as u64);
            let mut walk = Vec::new();
            if selected.contains_key(&logical) {
                let expected = helper(entry, logical, s.target);
                assert_eq!(body, entry + expected.len() as u64);
                assert_eq!(
                    &bytes[(entry - address) as usize..(body - address) as usize],
                    expected
                );
                hooks += 1;
                expected_fields.push(field(
                    (entry - address) as usize + 52,
                    8,
                    "Delta",
                    entry - address + 50,
                    logical,
                    "LogicalPc",
                    &bytes,
                ));
                let mut at = entry;
                while at < body {
                    let i = decoded(&bytes[(at - address) as usize..], at);
                    let next = at + i.len() as u64;
                    let raw = bytes[(at - address) as usize..(next - address) as usize].to_vec();
                    if i.flow_control() == FlowControl::Call {
                        assert_eq!(i.near_branch_target(), HOOK);
                        assert_eq!(raw.len(), 5);
                        assert_eq!(raw[0], 0xe8);
                        expected_fields.push(field(
                            (at - address) as usize + 1,
                            4,
                            "Relative",
                            next - address,
                            HOOK,
                            "HookCall",
                            &bytes,
                        ));
                        walk.push((at, HOOK, raw));
                        walk.push((HOOK, next, vec![0xc3]));
                    } else {
                        assert_eq!(i.flow_control(), FlowControl::Next);
                        walk.push((at, next, raw));
                    }
                    at = next;
                }
            } else {
                assert_eq!(entry, body);
            }
            let actual = decoded(&bytes[(body - address) as usize..], body);
            let source_at = file_at(&old, logical, usize::from(src.length));
            let source = decoded(
                &original.bytes[source_at..source_at + usize::from(src.length)],
                logical,
            );
            let branch = matches!(
                source.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            );
            let dest = if branch {
                actual.near_branch_target()
            } else {
                0
            };
            let raw =
                bytes[(body - address) as usize..(body - address) as usize + actual.len()].to_vec();
            cursor = body + actual.len() as u64;
            let original_raw = &original.bytes[source_at..source_at + usize::from(src.length)];
            if branch {
                assert_eq!(branch_kind(&raw), branch_kind(original_raw));
                assert_eq!(actual.flow_control(), source.flow_control());
            } else {
                assert_eq!(raw, original_raw, "whole original instruction bytes");
            }
            if branch {
                let width = if raw.len() == 2 { 1 } else { 4 };
                let offset = (body - address) as usize + raw.len() - width;
                expected_fields.push(field(
                    offset,
                    width,
                    "Relative",
                    cursor - address,
                    dest,
                    &format!("OriginalBranch {{ original_pc: {logical} }}"),
                    &bytes,
                ));
            }
            expected_pc_ranges.push(vec![
                entry.to_string(),
                cursor.to_string(),
                logical.to_string(),
            ]);
            let head = Head {
                logical,
                route: entry,
                body,
                bytes: raw,
                target: dest,
                walk,
            };
            assert!(all_heads.insert(logical, head.clone()).is_none());
            heads.push(head);
        }
        assert_eq!(address + bytes.len() as u64, cursor + 5);
        let jump = decoded(&bytes[(cursor - address) as usize..], cursor);
        assert_eq!(jump.flow_control(), FlowControl::UnconditionalBranch);
        assert_eq!(jump.len(), 5);
        assert_eq!(bytes[(cursor - address) as usize], 0xe9);
        let last = heads.last().unwrap();
        let h = seed::HEADS.iter().find(|x| x.pc == last.logical).unwrap();
        assert_eq!(jump.near_branch_target(), h.pc + u64::from(h.length));
        expected_fields.push(field(
            (cursor - address) as usize + 1,
            4,
            "Relative",
            cursor - address + 5,
            h.pc + u64::from(h.length),
            "Return",
            &bytes,
        ));
        expected_fields.sort();
        let mut actual_fields: Vec<_> = r
            .iter()
            .filter(|x| x[0] == "field" && n(x[1]) == id)
            .map(|x| x[2..].iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .collect();
        actual_fields.sort();
        assert_eq!(actual_fields, expected_fields);
        expected_pc_ranges.push(vec![
            cursor.to_string(),
            (cursor + 5).to_string(),
            (h.pc + u64::from(h.length)).to_string(),
        ]);
        assert_eq!(
            r.iter()
                .filter(|x| x[0] == "pc-range" && n(x[1]) == id)
                .map(|x| x[2..].iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            expected_pc_ranges
        );
        let mut requirements: Vec<_> = r
            .iter()
            .filter(|x| x[0] == "unmet-requirement" && n(x[1]) == id)
            .map(|x| (n(x[2]), n(x[3])))
            .collect();
        requirements.sort();
        let mut expected: Vec<_> = [1, 2, 3, 4, 7, 8].map(|v| (v, 0)).to_vec();
        if hooks > 0 {
            expected.push((5, 2));
        }
        expected.sort();
        assert_eq!(requirements, expected);
        images.push(Image { address, bytes });
    }
    assert_eq!(
        files.keys().cloned().collect::<BTreeSet<_>>(),
        expected_names
    );
    for pair in &foreign_pairs {
        pair.images(&all_heads, &images);
    }
    assert!(!images.is_empty());
    assert!(images.iter().map(|i| i.bytes.len()).sum::<usize>() <= 8_388_608);
    for pc in selected.keys() {
        let head = all_heads
            .get(pc)
            .expect("every selected site has its actual null helper");
        assert_eq!(
            head.walk
                .iter()
                .filter(|(_, next, _)| *next == HOOK)
                .count(),
            1
        );
    }
    for row in &r {
        if matches!(
            row[0],
            "route"
                | "restored-boundary"
                | "pc-range"
                | "field"
                | "unmet-requirement"
                | "elf-image"
        ) {
            assert!(n(row[1]) < images.len() as u64);
        }
    }
    assert_eq!(
        carrier(
            &original.bytes,
            &sparse_view,
            &old,
            &images,
            &files["metadata.li2meta"].bytes,
            plan,
            s.carrier_pc
        ),
        *candidate,
        "complete candidate carrier bytes including padding, old headers, payload and all LOADs"
    );
    assert_eq!(n(one(&r, "phdr_file")[1]), elf.header().program_offset.0);
    assert_eq!(
        n(one(&r, "phdr_file")[2]),
        u64::from(elf.header().program_count) * 56
    );
    assert_eq!(n(one(&r, "phdr_vaddr")[1]), s.carrier_pc);
    let mut declared_changes = original.bytes.clone();
    let mut changed = BTreeSet::new();
    for change in r.iter().filter(|x| x[0] == "elf-change") {
        let at = usize::try_from(n(change[2])).unwrap();
        let a = unhex(change[3]);
        let b = unhex(change[4]);
        assert!(!a.is_empty() && a.len() == b.len());
        assert_eq!(&original.bytes[at..at + a.len()], a);
        for i in at..at + a.len() {
            assert!(changed.insert(i));
        }
        match change[1] {
            "ProgramHeaderOffset" => assert_eq!((at, a.len()), (32, 8)),
            "ProgramHeaderCount" => assert_eq!((at, a.len()), (56, 2)),
            "DeclaredSource" => assert_eq!(&sparse_view[at..at + b.len()], b),
            _ => panic!("unknown carrier change"),
        };
        declared_changes[at..at + b.len()].copy_from_slice(&b);
    }
    assert_eq!(declared_changes, candidate[..original.bytes.len()]);
    for head in all_heads.values() {
        if head.target != 0 {
            let h = seed::HEADS.iter().find(|x| x.pc == head.logical).unwrap();
            let t = match h.flow {
                seed::Flow::Jb(t)
                | seed::Flow::Jae(t)
                | seed::Flow::Jbe(t)
                | seed::Flow::Jne(t)
                | seed::Flow::Jump(t) => t,
                _ => unreachable!(),
            };
            assert!(head.target == t || all_heads.get(&t).is_some_and(|v| v.route == head.target));
        }
    }
    let mut witness = format!(
        "LI2COMMONCORE\t1\nscope\tSTRUCTURAL_CORE_NULL_WITNESSES_ONLY\noriginal_sha256\t{}\ninstructions_sha256\t{}\ntarget_sha256\t{}\nselection_sha256\t{}\ncandidate_sha256\t{}\nqualification_complete\tfalse\n",
        hash(&original.bytes),
        hash(&instructions.bytes),
        hash(&target_input.bytes),
        hash(&selection.bytes),
        hash(candidate)
    );
    for (name, f) in &files {
        writeln!(
            &mut witness,
            "file\t{name}\t{}\t{}",
            f.bytes.len(),
            hash(&f.bytes)
        )
        .unwrap();
    }
    for (name, f) in [("COMPLETE", &complete), ("bundle-index.tsv", &index)] {
        writeln!(
            &mut witness,
            "file\t{name}\t{}\t{}",
            f.bytes.len(),
            hash(&f.bytes)
        )
        .unwrap();
    }
    let mut pages = BTreeSet::new();
    let mut added = 0;
    let mut carrier_count = 0;
    let mut original_loads_seen = BTreeSet::new();
    for load in elf.segments(SegmentType::Load) {
        assert!(matches!(load.flags.0, 4..=6));
        let lo = load.vaddr.0 & !4095;
        let hi = end(load.vaddr.0 + load.memory_size);
        assert!(hi <= 1 << 47);
        for page in (lo..hi).step_by(4096) {
            assert!(pages.insert(page));
        }
        let same = old
            .segments(SegmentType::Load)
            .filter(|x| x.vaddr == load.vaddr)
            .collect::<Vec<_>>();
        if !same.is_empty() {
            assert_eq!(same.len(), 1);
            let x = same[0];
            assert!(original_loads_seen.insert(x.index));
            assert_eq!(
                (load.raw_type, load.physical_address),
                (x.raw_type, x.physical_address)
            );
            assert_eq!(
                (
                    load.offset,
                    load.file_size,
                    load.memory_size,
                    load.flags,
                    load.alignment
                ),
                (x.offset, x.file_size, x.memory_size, x.flags, x.alignment)
            );
        } else {
            assert!(
                lo < hi
                    && original_ranges
                        .iter()
                        .all(|&range| disjoint(range, (lo, hi)))
            );
            added += (hi - lo) / 4096;
            if lo == s.carrier_pc {
                assert_eq!(load.flags.0, 4);
                assert!(CARRIER.0 == lo && hi <= CARRIER.1);
                carrier_count += 1;
            } else {
                assert_eq!(load.flags.0, 5);
                assert!(disjoint(CARRIER, (lo, hi)));
                assert_eq!(images.iter().filter(|i| i.address & !4095 == lo).count(), 1);
                assert_eq!(
                    allocations
                        .iter()
                        .filter(|&&(_, a, b)| a <= lo && hi <= b)
                        .count(),
                    1
                );
            }
        }
        writeln!(
            &mut witness,
            "load\t{}\t{}\t{}\t{}\t{}",
            load.offset.0, load.vaddr.0, load.file_size, load.memory_size, load.flags.0
        )
        .unwrap();
    }
    assert_eq!(
        original_loads_seen,
        old.segments(SegmentType::Load)
            .map(|x| x.index)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(carrier_count, 1);
    assert!(added <= 2048);
    assert_eq!(n(one(&r, "new_load_pages")[1]), added);
    assert!(pages.last().unwrap() + 4096 - pages.first().unwrap() <= 1_073_741_824);
    for src in seed::HEADS {
        let mut head = all_heads.get(&src.pc).cloned().unwrap_or_else(|| {
            let at = file_at(&old, src.pc, usize::from(src.length));
            let b = original.bytes[at..at + usize::from(src.length)].to_vec();
            assert_eq!(
                elf.executable_bytes(ElfVaddr(src.pc), u64::from(src.length))
                    .unwrap(),
                b
            );
            Head {
                logical: src.pc,
                route: src.pc,
                body: src.pc,
                bytes: b,
                target: match src.flow {
                    seed::Flow::Jb(t)
                    | seed::Flow::Jae(t)
                    | seed::Flow::Jbe(t)
                    | seed::Flow::Jne(t)
                    | seed::Flow::Jump(t)
                    | seed::Flow::Call(t) => t,
                    _ => 0,
                },
                walk: Vec::new(),
            }
        });
        let mut gateway = Vec::new();
        let mut at = src.pc;
        let mut seen = BTreeSet::new();
        while at != head.route {
            assert!(seen.insert(at) && seen.len() < 20000);
            assert!(
                seed::ORIGINAL_RANGES
                    .iter()
                    .any(|q| q.pc <= at && at < q.pc + q.bytes.len() as u64)
            );
            let off = file_at(&elf, at, 1);
            let i = decoded(&candidate[off..candidate.len().min(off + 15)], at);
            assert_eq!(i.flow_control(), FlowControl::UnconditionalBranch);
            let b = candidate[off..off + i.len()].to_vec();
            let next = i.near_branch_target();
            gateway.push((at, next, b));
            at = next;
        }
        gateway.append(&mut head.walk);
        head.walk = gateway;
        writeln!(
            &mut witness,
            "head\t{}\t{}\t{}\t{}",
            src.pc,
            head.body,
            head.target,
            hex(&head.bytes)
        )
        .unwrap();
        for (pc, next, b) in head.walk {
            writeln!(&mut witness, "walk\t{}\t{pc}\t{next}\t{}", src.pc, hex(&b)).unwrap();
        }
    }
    writeln!(&mut witness, "complete\t87\t174\t2\tE9_UNIMPLEMENTED_UNRUN").unwrap();
    for f in files.values().chain(inventory_inputs.values()).chain([
        &inventory_complete,
        &complete,
        &index,
        &original,
        &instructions,
        &target_input,
        &selection,
        &inventory_table,
    ]) {
        f.stable();
    }
    assert_eq!(
        std::fs::read_dir(directory)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect::<BTreeSet<_>>(),
        names
    );
    assert_eq!(
        std::fs::read_dir(inventory)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect::<BTreeSet<_>>(),
        inventory_names
            .into_iter()
            .chain(["COMPLETE"])
            .map(str::to_owned)
            .collect()
    );
    let output = Path::new(&args[6]);
    assert!(output.is_absolute());
    assert_eq!(
        output.parent().unwrap().canonicalize().unwrap().as_os_str(),
        output.parent().unwrap().as_os_str()
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .unwrap();
    file.write_all(witness.as_bytes()).unwrap();
    file.sync_all().unwrap();
    println!(
        "core null witness complete: heads=87 normal=174 faults=2 execution=false qualification_complete=false"
    );
}

#[cfg(test)]
mod placement_tests {
    use super::*;

    // Synthetic metadata fixture only. This is not either admitted application
    // and cannot pass main's whole-original identity gate.
    fn policy_fixture(derived: bool) -> (Vec<u8>, Vec<u8>) {
        let mut b = vec![0; 0x24190];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[16..18].copy_from_slice(&2_u16.to_le_bytes());
        b[18..20].copy_from_slice(&62_u16.to_le_bytes());
        b[20..24].copy_from_slice(&1_u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x401840_u64.to_le_bytes());
        b[32..40].copy_from_slice(&64_u64.to_le_bytes());
        b[52..54].copy_from_slice(&64_u16.to_le_bytes());
        b[54..56].copy_from_slice(&56_u16.to_le_bytes());
        b[56..58].copy_from_slice(&4_u16.to_le_bytes());
        for (index, (offset, pc, fs, ms, flags)) in [
            (0_u64, 0x400000_u64, 0x8b0_u64, 0x8b0_u64, 4_u32),
            (0x1000, 0x401000, 0xa51, 0xa51, 5),
            (0x2000, 0x402000, 0xe1c, 0xe1c, 4),
            (0x3e00, 0x403e00, 0x20358, 0x20390, 6),
        ]
        .into_iter()
        .enumerate()
        {
            let at = 64 + index * 56;
            b[at..at + 4].copy_from_slice(&1_u32.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            for (i, value) in [offset, pc, pc, fs, ms, 4096].into_iter().enumerate() {
                b[at + 8 + i * 8..at + 16 + i * 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        b[0x1100..0x1a43].fill(0x90);
        for r in seed::ORIGINAL_RANGES {
            b[r.file_offset as usize..r.file_offset as usize + r.bytes.len()]
                .copy_from_slice(r.bytes);
        }
        b[0x1960] = 0xc3;
        let mut p = format!(
            "LI2COMMON {}\noriginal {}\ntarget {}\nprovenance {}\ntext 0x401100 4352 2371 {}\n",
            if derived { 2 } else { 1 },
            hash(&b),
            hash(b"target fxsave64\n"),
            "a".repeat(64),
            hash(&b[0x1100..0x1a43])
        );
        for (r, name) in
            seed::ORIGINAL_RANGES
                .iter()
                .zip(["li2_array_store", "li2_sift_down", "li2_heap_sort"])
        {
            writeln!(
                p,
                "function {name} {} {} {}",
                r.pc,
                r.bytes.len(),
                hash(r.bytes)
            )
            .unwrap();
        }
        writeln!(
            p,
            "hook 2 {HOOK} 1 {}\nhook 3 4200816 211 {}\ncarrier 0x20000000",
            hash(&[0xc3]),
            hash(&b[0x1970..0x1a43])
        )
        .unwrap();
        p.push_str(if derived {
            "placement original-derived-v1 65536 1073741824\narena selected 65536 65536\narena victim 65536 65536\n"
        } else {
            "arena selected 0x10000000 65536 65536 65536\narena victim 0x18000000 65536 65536 65536\n"
        });
        p.push_str("limits 1048576 64 256 8388608 2048 16777216 12582912 512 1073741824\nsearch 64 256 64 256 4096\nEND\n");
        (b, p.into_bytes())
    }

    #[test]
    fn complete_policy_versions_preserve_caps_and_authenticate_original_owners() {
        for derived in [false, true] {
            let (original, policy) = policy_fixture(derived);
            let elf = Elf64::parse(
                &original,
                ParseLimits {
                    max_program_headers: 512,
                },
            )
            .unwrap();
            let provenance = "a".repeat(64);
            let verify =
                |p: &[u8]| policy_profile(p, &original, b"target fxsave64\n", &provenance, &elf);
            assert_eq!(
                verify(&policy),
                if derived {
                    PlacementProfile::OriginalDerivedV1
                } else {
                    PlacementProfile::FixedV1
                }
            );
            let policy = String::from_utf8(policy).unwrap();
            // Leading zeroes keep the offset's numeric value unchanged, so
            // these records isolate the exact byte bound from other fields.
            let boundary = policy.replacen(
                "text 0x401100 4352 ",
                &format!("text 0x401100 {}4352 ", "0".repeat(65536 - policy.len())),
                1,
            );
            assert_eq!(boundary.len(), 65536);
            assert_eq!(verify(boundary.as_bytes()), verify(policy.as_bytes()));
            let over_bound = boundary.replacen("text 0x401100 ", "text 0x401100 0", 1);
            assert_eq!(over_bound.len(), 65537);
            let mut bad = vec![
                policy.replace("original ", "unexpected "),
                policy.replace(&hash(&original), &"0".repeat(64)),
                policy.replace(&hash(b"target fxsave64\n"), &"0".repeat(64)),
                policy.replace("text 0x401100 4352 2371", "text 0x401100 4353 2371"),
                policy.replace("hook 3 4200816 211", "hook 3 4200817 211"),
                policy.replace("search 64 256 64 256 4096", "search 65 256 64 256 4096"),
                policy.replace("END\n", "END\nextra\n"),
            ];
            if derived {
                bad.extend([
                    policy.replace("original-derived-v1", "unbounded"),
                    policy.replace("65536 1073741824", "65537 1073741824"),
                    policy.replace("arena selected 65536 65536", "arena selected 65536 65537"),
                    policy.replace("arena victim 65536 65536", "arena victim 131072 65536"),
                ]);
            } else {
                bad.push(policy.replace("arena selected 0x10000000", "arena selected 0x10010000"));
            }
            bad.extend([
                policy.replacen("LI2COMMON ", "LI2COMMON\t", 1),
                policy.replacen("LI2COMMON ", "LI2COMMON  ", 1),
                format!(" {policy}"),
                policy.replacen('\n', " \n", 1),
                policy.replace('\n', "\r\n"),
                policy.strip_suffix('\n').unwrap().to_owned(),
                over_bound,
            ]);
            for candidate in bad {
                assert_ne!(candidate, policy);
                assert!(std::panic::catch_unwind(|| verify(candidate.as_bytes())).is_err());
            }
        }
    }

    #[test]
    fn four_pivot_ceiling_matches_bounded_bruteforce_and_signed_edges() {
        for choices in [vec![6, 7, 0xce], vec![0, 127, 255], vec![255]] {
            let mut rule = Displacement::plain(0x8000_0000);
            rule.digits[0] = choices;
            rule.digits[1] = vec![0, 1, 3, 127, 255];
            rule.digits[2] = vec![0];
            rule.digits[3] = vec![0];
            for lower in (0..65536_u32).step_by(251) {
                let expected = (lower..65536).find(|v| {
                    v.to_le_bytes()
                        .iter()
                        .enumerate()
                        .all(|(i, b)| rule.digits[i].contains(b))
                });
                assert_eq!(rule.ceiling(lower), expected);
            }
        }
        let plain = Displacement::plain(0x8000_0000);
        assert_eq!(plain.first((0, 1)), Some(0));
        assert_eq!(plain.first((0xffff_ffff, 0x1_0000_0000)), Some(0xffff_ffff));
        assert_eq!(plain.first((0x1_0000_0000, 0x1_0000_0001)), None);
        let all_entries = Displacement {
            next: 0x4000_0000,
            digits: std::array::from_fn(|_| ENTRY_OPCODES.to_vec()),
        };
        assert_eq!(all_entries.first((0, 0x8000_0000)), Some(0x0e06_0606));
    }

    #[test]
    fn original_blocks_all_sites_and_heap_permit_have_independent_expected_coordinates() {
        let (original, _) = policy_fixture(true);
        let elf = Elf64::parse(
            &original,
            ParseLimits {
                max_program_headers: 512,
            },
        )
        .unwrap();
        let owners = original_load_ranges(&elf);
        let table = rows(seed::EXPECTED_INSTRUCTIONS);
        assert_eq!(table.len(), 88);
        assert_eq!((seed::HEAD_COUNT, seed::CASE_COUNT), (87, 176));
        for (h, row) in seed::HEADS.iter().zip(table.into_iter().skip(1)) {
            assert_eq!(
                original_block(h),
                (policy_number(row[9]), policy_number(row[10]))
            );
        }
        let heap = derived_permits(&owners, &[0x401840]);
        assert_eq!(
            heap,
            [[
                Permit {
                    range: (0x0640_1000, 0x0641_1000),
                    preferred: 0x0640_1845
                },
                Permit {
                    range: (0x10000, 0x20000),
                    preferred: 0x10000
                },
            ]]
        );
        let pcs = [
            0x40186a, 0x40186c, 0x401889, 0x4018a6, 0x4018b4, 0x4018c4, 0x4018d4, 0x401905,
            0x401946,
        ];
        assert_eq!(
            seed::HEADS
                .iter()
                .filter(|h| matches!(
                    h.flow,
                    seed::Flow::Jb(_)
                        | seed::Flow::Jae(_)
                        | seed::Flow::Jbe(_)
                        | seed::Flow::Jne(_)
                        | seed::Flow::Jump(_)
                ))
                .map(|h| h.pc)
                .collect::<Vec<_>>(),
            pcs
        );
        let result = derived_permits(&owners, &pcs);
        assert_eq!(result.len(), 9);
        let unplaceable = seed::HEADS.iter().find(|h| h.pc == 0x40186c).unwrap();
        let rules = original_displacements(unplaceable);
        assert_eq!(rules.len(), 1);
        assert!(rules.iter().all(|r| r.first(DOMAIN).is_none()));
        // Its neutral slot remains a required input; this does not assert a
        // successful tactic/candidate or remove the independent ID15 refusal.
        for pair in result {
            for permit in pair {
                assert_eq!(permit.range.1 - permit.range.0, SLOT);
                assert!(permit.range.0 <= permit.preferred && permit.preferred < permit.range.1);
                assert!(owners.iter().all(|&r| disjoint(r, permit.range)));
            }
        }
    }
}
