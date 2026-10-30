//! Finite adjacent-B2 fixture vocabulary. No host queries, planning or execution.
//! The image witness is a byte recognizer, never a source of producer images.
use liteinst2::trampoline::{SavedExtendedStateFormat, SavedExtendedStateLayout};
use std::collections::BTreeMap;
use std::fmt::Write as _;

pub const B: u64 = 0x1000_06f9;
pub const HOOK: u64 = 0x1000_16f9;
pub const UPPER: u64 = 0x11c0_7000;
pub const LOWER: u64 = 0x7900_f000;
pub const DATA: u64 = 0x403000;
pub const LOG: u64 = 0x404000;
pub const STACK: u64 = 0x406000;
pub const STACK_END: u64 = 0x416000;
pub const CALLER_RSP: u64 = STACK_END - 256;
pub const HEADS: [u64; 4] = [B, B + 2, B + 4, B + 10];
pub const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
pub const FINAL: [u8; 11] = [0xe9, 2, 0xe9, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3];
pub const LIMIT: usize = 1024 * 1024;
pub const FILE_BYTES: usize = 0x18000;
/// (file offset, virtual address, length, ELF permission bits).
pub const LOADS: [(u64, u64, u64, u32); 9] = [
    (0, 0x400000, 4096, 4),
    (0x1000, 0x401000, 4096, 5),
    (0x2000, DATA, 4096, 6),
    (0x3000, LOG, 4096, 6),
    (0x4000, STACK, 65536, 6),
    (0x14000, 0x10000000, 4096, 5),
    (0x15000, 0x10001000, 4096, 5),
    (0x16000, UPPER, 4096, 5),
    (0x17000, LOWER, 4096, 5),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub routing: bool,
    pub recording: bool,
}
impl Request {
    pub const ALL: [Self; 4] = [
        Self {
            routing: false,
            recording: false,
        },
        Self {
            routing: false,
            recording: true,
        },
        Self {
            routing: true,
            recording: false,
        },
        Self {
            routing: true,
            recording: true,
        },
    ];
    pub fn name(self) -> String {
        format!(
            "{}-xs64-{}-v2",
            if self.routing { "routing" } else { "primary" },
            if self.recording { "recording" } else { "null" }
        )
    }
    pub fn source(self) -> [u8; 11] {
        [
            0x75,
            2,
            0x75,
            if self.routing { 6 } else { 0 },
            0x69,
            0xc0,
            1,
            0,
            0,
            0,
            0xc3,
        ]
    }
    pub fn visits(self, head: usize, zf: bool) -> Vec<u64> {
        assert!(head < 4);
        let offsets: &[u64] = match (head, zf, self.routing) {
            (0, false, _) => &[0, 4, 10],
            (0, true, _) => &[0, 2, 4, 10],
            (1, false, true) => &[2, 10],
            (1, _, _) => &[2, 4, 10],
            (2, _, _) => &[4, 10],
            (3, _, _) => &[10],
            _ => unreachable!(),
        };
        offsets
            .iter()
            .map(|x| B + x)
            .chain([call_pc(head) + 5])
            .collect()
    }
}
pub fn call_pc(head: usize) -> u64 {
    assert!(head < 4);
    0x401080 + 16 * head as u64
}
pub fn flags(seed: u64, zf: bool) -> u64 {
    (0xad7 & !0x40) | ((seed & 1) << 10) | (u64::from(zf) << 6)
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0 && text.bytes().all(|c| c.is_ascii_hexdigit()));
    let b: Vec<_> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(hex(&b), text, "canonical lower-case hex");
    b
}
pub fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn put(bytes: &mut [u8], at: usize, value: u64, width: usize) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
pub fn transfer(op: u8, pc: u64, target: u64) -> Vec<u8> {
    let mut b = vec![op];
    b.extend_from_slice(
        &i32::try_from(i128::from(target) - i128::from(pc) - 5)
            .unwrap()
            .to_le_bytes(),
    );
    b
}
pub fn target_text(s: SavedExtendedStateLayout) -> Vec<u8> {
    assert_eq!(s.format(), SavedExtendedStateFormat::XSAVE64_STANDARD);
    assert!(s.len() <= 32768 && s.image_len() <= s.len());
    let mut t = format!(
        "LI2ADJTARGET\t2\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t7\nformat\t2\nallocation\t{}\nimage\t{}\nmask\t{}\n",
        s.len(),
        s.image_len(),
        s.mask()
    );
    for c in s.components() {
        writeln!(
            t,
            "component\t{}\t{}\t{}",
            c.xfeature(),
            c.offset(),
            c.size()
        )
        .unwrap();
    }
    t.push_str("qualification_complete\tfalse\nEND\n");
    t.into_bytes()
}
pub fn parse_target(bytes: &[u8]) -> SavedExtendedStateLayout {
    assert!(bytes.len() <= 65536);
    let rows: Vec<Vec<_>> = std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|l| l.split('\t').collect())
        .collect();
    assert!(rows.len() >= 12);
    assert_eq!(rows[0], ["LI2ADJTARGET", "2"]);
    assert_eq!(rows[1], ["os", "linux"]);
    assert_eq!(rows[2], ["isa", "x86-64-legacy-evex"]);
    assert_eq!(rows[3], ["cet", "unqualified"]);
    assert_eq!(rows[4], ["page_bytes", "4096"]);
    assert_eq!(rows[5], ["bias_domain", "7"]);
    assert_eq!(rows[6], ["format", "2"]);
    assert_eq!(rows[7][0], "allocation");
    assert_eq!(rows[7].len(), 2);
    assert_eq!(rows[8][0], "image");
    assert_eq!(rows[8].len(), 2);
    assert_eq!(rows[9][0], "mask");
    assert_eq!(rows[9].len(), 2);
    let components: Vec<_> = rows[10..rows.len() - 2]
        .iter()
        .map(|r| {
            assert_eq!(r.len(), 4);
            assert_eq!(r[0], "component");
            (
                r[1].parse().unwrap(),
                r[2].parse().unwrap(),
                r[3].parse().unwrap(),
            )
        })
        .collect();
    let state =
        SavedExtendedStateLayout::describe_target_xsave64(rows[9][1].parse().unwrap(), &components)
            .unwrap();
    assert_eq!(
        target_text(state),
        bytes,
        "complete canonical target manifest"
    );
    state
}

#[derive(Clone, Debug)]
pub struct Instruction {
    pub bytes: Vec<u8>,
    pub next: Vec<u64>,
}
#[derive(Clone, Debug)]
pub struct Code {
    pub base: u64,
    pub bytes: Vec<u8>,
    pub instructions: BTreeMap<u64, Instruction>,
}
impl Code {
    fn new(base: u64) -> Self {
        Self {
            base,
            bytes: Vec::new(),
            instructions: BTreeMap::new(),
        }
    }
    fn add(&mut self, bytes: &[u8]) -> u64 {
        let pc = self.base + self.bytes.len() as u64;
        assert!(
            self.instructions
                .insert(
                    pc,
                    Instruction {
                        bytes: bytes.to_vec(),
                        next: vec![pc + bytes.len() as u64]
                    }
                )
                .is_none()
        );
        self.bytes.extend_from_slice(bytes);
        pc
    }
    fn literal(&mut self, text: &str) {
        self.add(&unhex(text));
    }
    fn imm(&mut self, prefix: &str, value: u64, width: usize) {
        let mut b = unhex(prefix);
        b.extend_from_slice(&value.to_le_bytes()[..width]);
        self.add(&b);
    }
    fn short(&mut self, opcode: u8) -> u64 {
        self.add(&[opcode, 0])
    }
    fn resolve(&mut self, pc: u64, target: u64, conditional: bool) {
        let at = usize::try_from(pc - self.base).unwrap();
        let d = i8::try_from(i128::from(target) - i128::from(pc) - 2).unwrap() as u8;
        self.bytes[at + 1] = d;
        let i = self.instructions.get_mut(&pc).unwrap();
        i.bytes[1] = d;
        i.next = if conditional {
            vec![pc + 2, target]
        } else {
            vec![target]
        };
    }
}
/// Authored loader startup and four real subject CALLs, with exact instruction starts.
pub fn bootstrap() -> Code {
    let mut c = Code::new(0x401000);
    c.literal("48833c2402");
    let bad_argc = c.short(0x75);
    c.literal("488b742410");
    c.literal("807e0100");
    let bad_len = c.short(0x75);
    c.literal("0fb606");
    c.literal("83e830");
    c.literal("83f803");
    let bad_head = c.short(0x77);
    c.imm("bc", CALLER_RSP, 4);
    c.literal("c1e004");
    c.imm("05", call_pc(0), 4);
    let jump = c.add(&[0xff, 0xe0]);
    c.instructions.get_mut(&jump).unwrap().next = (0..4).map(call_pc).collect();
    let bad = c.add(&[0x0f, 0x0b]);
    for at in [bad_argc, bad_len, bad_head] {
        c.resolve(at, bad, true);
    }
    c.instructions.get_mut(&bad).unwrap().next.clear();
    assert!(c.bytes.len() < 0x80);
    c.bytes.resize(0x80, 0xcc);
    for (h, &target) in HEADS.iter().enumerate() {
        assert_eq!(c.base + c.bytes.len() as u64, call_pc(h));
        let pc = c.add(&transfer(0xe8, call_pc(h), target));
        c.instructions.get_mut(&pc).unwrap().next = vec![target];
        c.add(&[0x0f, 0x0b]);
        c.bytes.resize(0x80 + (h + 1) * 16, 0xcc);
    }
    c.bytes.resize(4096, 0xcc);
    c
}
/// Both payloads use the exact frozen hook entry. Recording never writes application memory.
pub fn hook(recording: bool) -> Code {
    let mut c = Code::new(HOOK);
    if !recording {
        c.add(&[0xc3]);
        return c;
    }
    c.imm("48ba", LOG, 8);
    c.literal("488b0a");
    c.literal("4883f902");
    let full = c.short(0x73);
    c.literal("488b07");
    c.imm("41b8", 1, 4);
    c.imm("483d", B, 4);
    let lower = c.short(0x74);
    c.literal("41ffc0");
    c.imm("483d", B + 2, 4);
    let invalid = c.short(0x75);
    let append = c.base + c.bytes.len() as u64;
    c.literal("48c1e104");
    c.literal("4c89440a10");
    c.literal("4889440a18");
    c.literal("48ff02");
    let done = c.short(0xeb);
    let overflow = c.base + c.bytes.len() as u64;
    c.literal("48c7420801000000");
    let overflow_done = c.short(0xeb);
    assert!(c.bytes.len() < 127);
    c.bytes.resize(127, 0xcc);
    let ret = c.add(&[0xc3]);
    c.resolve(full, overflow, true);
    c.resolve(invalid, overflow, true);
    c.resolve(lower, append, true);
    c.resolve(done, ret, false);
    c.resolve(overflow_done, ret, false);
    c
}

#[derive(Clone, Debug)]
pub struct ImageWitness {
    pub code: Code,
    pub logical: u64,
    pub body: u64,
    pub call: u64,
    pub returned: u64,
    pub branch_target: u64,
}
/// Independent ordinary-helper grammar pinned to verify_common_core.rs:189-269.
/// Called by verification only: producer images must come from the actual pair API.
pub fn image_witness(req: Request, state: SavedExtendedStateLayout, upper: bool) -> ImageWitness {
    image_witness_at(req, state, upper, if upper { UPPER } else { LOWER })
}
/// The separately required h128 singleton uses the same unchanged grammar.
pub fn image_witness_at(
    req: Request,
    state: SavedExtendedStateLayout,
    upper: bool,
    base: u64,
) -> ImageWitness {
    assert_eq!(state.format(), SavedExtendedStateFormat::XSAVE64_STANDARD);
    assert!(if upper {
        base == UPPER || base == UPPER + 128
    } else {
        base == LOWER
    });
    let logical = B + if upper { 2 } else { 0 };
    let mut c = Code::new(base);
    c.literal("488d642480");
    c.literal("488d6424e0");
    c.literal("9c");
    for b in [0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57] {
        c.add(&[b]);
    }
    for b in 0x50..=0x57 {
        c.add(&[0x41, b]);
    }
    c.literal("488d842420010000");
    c.literal("50");
    c.literal("488d0500000000");
    assert_eq!(c.bytes.len(), 50);
    c.imm(
        "48ba",
        i64::try_from(i128::from(logical) - i128::from(base + 50)).unwrap() as u64,
        8,
    );
    c.literal("4801d0");
    c.literal("50");
    c.literal("4989e4");
    c.literal("4883e4c0");
    c.imm("4881ec", state.len(), 4);
    c.literal("31c0");
    for offset in (512..576).step_by(8) {
        c.imm("48898424", offset, 4);
    }
    if state.mask() & 512 != 0 {
        let component = state
            .components()
            .iter()
            .find(|v| v.xfeature() == 512)
            .unwrap();
        assert_eq!(component.size(), 8);
        assert_eq!(component.offset() % 8, 0);
        c.imm("898424", component.offset() + 4, 4);
    }
    c.imm("b8", state.mask() as u32 as u64, 4);
    c.imm("ba", state.mask() >> 32, 4);
    c.literal("480fae2424");
    c.literal("4989a42490000000");
    for (offset, value) in [
        (152, state.len()),
        (160, state.mask()),
        (168, state.format().raw()),
    ] {
        c.imm("48b8", value, 8);
        c.imm("49898424", offset, 4);
    }
    c.literal("fc");
    c.literal("4c89e7");
    let call = base + c.bytes.len() as u64;
    c.add(&transfer(0xe8, call, HOOK));
    c.instructions.get_mut(&call).unwrap().next = vec![HOOK];
    let returned = call + 5;
    c.imm("b8", state.mask() as u32 as u64, 4);
    c.imm("ba", state.mask() >> 32, 4);
    c.literal("480fae2c24");
    c.literal("4c89e4");
    c.literal("4883c410");
    for b in (0x58..=0x5f).rev() {
        c.add(&[0x41, b]);
    }
    for b in [0x5f, 0x5e, 0x5d, 0x5b, 0x5a, 0x59, 0x58, 0x9d] {
        c.add(&[b]);
    }
    c.literal("488d642420");
    c.literal("488da42480000000");
    let extra = if state.mask() & 512 == 0 { 0 } else { 7 };
    assert_eq!(c.bytes.len(), 289 + extra);
    assert_eq!(call, base + 225 + extra as u64);
    assert_eq!(returned, base + 230 + extra as u64);
    let body = base + c.bytes.len() as u64;
    let branch_target = if upper && req.routing { B + 10 } else { B + 4 };
    let mut branch = vec![0x0f, 0x85];
    branch.extend_from_slice(
        &i32::try_from(i128::from(branch_target) - i128::from(body) - 6)
            .unwrap()
            .to_le_bytes(),
    );
    c.add(&branch);
    c.instructions.get_mut(&body).unwrap().next = vec![body + 6, branch_target];
    let tail = body + 6;
    c.add(&transfer(0xe9, tail, logical + 2));
    c.instructions.get_mut(&tail).unwrap().next = vec![logical + 2];
    assert!(c.bytes.len() <= 4096);
    ImageWitness {
        code: c,
        logical,
        body,
        call,
        returned,
        branch_target,
    }
}

/// Bounded fixed descriptor. Hashes come from the concrete tool verifier, never a callback.
pub fn descriptor(
    req: Request,
    state: SavedExtendedStateLayout,
    phase: usize,
    lengths: [usize; 2],
    hashes: [[u8; 32]; 7],
) -> [u8; 512] {
    assert!(phase < 3);
    let mut d = [0; 512];
    d[..16].copy_from_slice(b"LI2ADJ-NATIVE-V2");
    for (at, value) in [
        (0x10, 2),
        (0x14, u64::from(req.routing)),
        (0x18, u64::from(req.recording)),
        (0x1c, phase as u64),
    ] {
        put(&mut d, at, value, 4);
    }
    for (at, value) in [
        (0x20, B),
        (0x28, HOOK),
        (0x30, UPPER),
        (0x38, LOWER),
        (0x40, 11),
        (0x48, lengths[0] as u64),
        (0x50, lengths[1] as u64),
        (0x58, state.len()),
        (0x60, state.image_len()),
        (0x68, state.mask()),
        (0x70, state.format().raw()),
        (0x78, if req.recording { 128 } else { 1 }),
        (0x80, LOG),
        (0x88, 2),
        (0x90, STACK),
        (0x98, STACK_END),
    ] {
        put(&mut d, at, value, 8);
    }
    for h in 0..4 {
        put(&mut d, 0xa0 + h * 8, call_pc(h), 8);
    }
    for (i, seed) in SEEDS.iter().enumerate() {
        put(&mut d, 0xc0 + i * 8, *seed, 8);
    }
    for (i, hash) in hashes.iter().enumerate() {
        d[0xd0 + i * 32..0xf0 + i * 32].copy_from_slice(hash);
    }
    d
}
/// Packages actual image slices only; this function has no planner or witness call.
pub fn elf(req: Request, phase: usize, images: [&[u8]; 2], descriptor: &[u8; 512]) -> Vec<u8> {
    assert!(phase < 3 && images.iter().all(|b| !b.is_empty() && b.len() <= 4096));
    let mut b = vec![0; FILE_BYTES];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, v, n) in [
        (16, 2, 2),
        (18, 62, 2),
        (20, 1, 4),
        (24, 0x401000, 8),
        (32, 64, 8),
        (52, 64, 2),
        (54, 56, 2),
        (56, 11, 2),
    ] {
        put(&mut b, at, v, n);
    }
    let mut ph =
        |index: usize, kind: u64, flags: u32, offset: u64, addr: u64, len: u64, align: u64| {
            let p = 64 + index * 56;
            put(&mut b, p, kind, 4);
            put(&mut b, p + 4, u64::from(flags), 4);
            for (i, value) in [offset, addr, addr, len, len, align].iter().enumerate() {
                put(&mut b, p + 8 + i * 8, *value, 8);
            }
        };
    ph(0, 6, 4, 64, 0x400040, 616, 8);
    for (i, &(off, addr, len, flags)) in LOADS.iter().enumerate() {
        ph(i + 1, 1, flags, off, addr, len, 4096);
    }
    ph(10, 0x6474_e551, 6, 0, 0, 0, 16);
    b[0x400..0x600].copy_from_slice(descriptor);
    b[0x1000..0x2000].copy_from_slice(&bootstrap().bytes);
    for (i, byte) in b[0x2000..0x3000].iter_mut().enumerate() {
        *byte = (i * 37 + 11) as u8;
    }
    b[0x4000..0x14000].fill(0x5a);
    b[0x14000..].fill(0xcc);
    let source = if phase == 1 { FINAL } else { req.source() };
    b[0x146f9..0x14704].copy_from_slice(&source);
    let h = hook(req.recording);
    b[0x156f9..0x156f9 + h.bytes.len()].copy_from_slice(&h.bytes);
    for (offset, image) in [0x16000, 0x17000].into_iter().zip(images) {
        b[offset..offset + image.len()].copy_from_slice(image);
    }
    b
}

/// Page-level closure supplements the legacy maps()/provider joins.
pub fn close_owners(text: &str, inode: u64) {
    assert!(text.len() <= 65536 && text.ends_with('\n'));
    let mut all_pages = std::collections::BTreeSet::new();
    let mut end = 0;
    let mut kernel_executable_names = std::collections::BTreeSet::new();
    for line in text.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        assert!(f.len() >= 5);
        let (a, z) = f[0].split_once('-').unwrap();
        let a = u64::from_str_radix(a, 16).unwrap();
        let z = u64::from_str_radix(z, 16).unwrap();
        assert!(a < z && a >= end && a % 4096 == 0 && z % 4096 == 0);
        end = z;
        let file: u64 = f[4].parse().unwrap();
        let offset = u64::from_str_radix(f[2], 16).unwrap();
        if file != 0 {
            assert_eq!(file, inode, "unexpected file-backed owner");
            for page in (a..z).step_by(4096) {
                let owners: Vec<_> = LOADS
                    .iter()
                    .filter(|l| l.1 <= page && page + 4096 <= l.1 + l.2)
                    .collect();
                assert_eq!(owners.len(), 1, "extra executable-file page");
                let l = owners[0];
                assert_eq!(offset + page - a, l.0 + page - l.1);
                assert_eq!(
                    f[1],
                    match l.3 {
                        4 => "r--p",
                        5 => "r-xp",
                        6 => "rw-p",
                        _ => unreachable!(),
                    }
                );
                assert!(all_pages.insert(page));
            }
        } else {
            assert!(
                f.len() == 5 || (f.len() == 6 && f[5].starts_with('[') && f[5].ends_with(']')),
                "inode-zero mapping must have no file pathname"
            );
            if !f[1].contains('x') {
                assert!(z <= 0x405000 || a >= STACK, "guard mapped");
                continue;
            }
            assert_eq!(f.len(), 6, "unnamed executable owner");
            assert_eq!(offset, 0);
            assert_eq!(f[3], "00:00");
            assert!(
                kernel_executable_names.insert(f[5]),
                "duplicate kernel executable owner"
            );
            assert!(
                (f[5] == "[vdso]" && f[1] == "r-xp")
                    || (f[5] == "[vsyscall]"
                        && f[1] == "--xp"
                        && a == 0xffffffffff600000
                        && z == a + 4096),
                "unexpected executable owner"
            );
        }
        assert!(z <= 0x405000 || a >= STACK, "guard mapped");
    }
    assert_eq!(
        all_pages.len(),
        24,
        "complete fixture file-backed page denominator"
    );
}

/// Only the named expected refusal runs under a silent hook. The catch encloses
/// the entire user closure; hook restoration precedes payload drop and the
/// unexpected-acceptance assertion. Controls run serially on the driver thread.
pub fn expect_refusal(label: &str, call: impl FnOnce()) {
    static CONTROL_HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let serial = CONTROL_HOOK.lock().unwrap();
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(call));
    std::panic::set_hook(original);
    drop(serial);
    assert!(
        outcome.is_err(),
        "required hostile control accepted: {label}"
    );
}
