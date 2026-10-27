//! Controlled E9 pairs consuming an externally authenticated JSON/TSV pair.
//! Null remains the default; recording requires its exact trailing profile.
//! No loader execution, producer admission or whole-A3 claim.
use super::*;
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStringExt;

const MAX_INPUT: usize = 16_777_216;
const MAX_PAGES: usize = 2048;
const MAX_PREFIX: usize = 32;

fn text(input: &Input) -> &str {
    std::str::from_utf8(&input.bytes).unwrap()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn bytes(s: &str) -> Vec<u8> {
    assert_eq!(s.len() & 1, 0);
    assert!(
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn digest(s: &str) {
    assert_eq!(bytes(s).len(), 32);
}
fn n(s: &str) -> u64 {
    let v: u64 = s.parse().unwrap();
    assert_eq!(v.to_string(), s);
    v
}
fn signed(s: &str) -> i128 {
    let v: i128 = s.parse().unwrap();
    assert_eq!(v.to_string(), s);
    v
}
fn read_empty(path: &Path) -> Input {
    assert!(path.is_absolute());
    assert_eq!(path.canonicalize().unwrap().as_os_str(), path.as_os_str());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .unwrap();
    let m = file.metadata().unwrap();
    assert!(m.is_file() && m.len() <= MAX_INPUT as u64);
    let mut bytes = Vec::new();
    (&file)
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len() as u64, m.len());
    let input = Input {
        path: path.to_owned(),
        file,
        owner: identity(&m),
        bytes,
    };
    input.stable();
    input
}
struct Rows<'a> {
    rows: Vec<Vec<&'a str>>,
    at: usize,
}
impl<'a> Rows<'a> {
    fn new(input: &'a Input) -> Self {
        assert!(input.bytes.ends_with(b"\n") && !input.bytes.contains(&b'\r'));
        let rows: Vec<Vec<_>> = text(input)
            .lines()
            .map(|s| s.split('\t').collect())
            .collect();
        assert!(
            rows.len() <= 50000
                && rows
                    .iter()
                    .all(|r| !r.is_empty() && r.iter().all(|s| !s.is_empty()))
        );
        Self { rows, at: 0 }
    }
    fn is(&self, key: &str) -> bool {
        self.rows.get(self.at).is_some_and(|r| r[0] == key)
    }
    fn take(&mut self, key: &str, count: usize) -> Vec<&'a str> {
        let r = self.rows.get(self.at).unwrap();
        assert_eq!(r.len(), count);
        assert_eq!(r[0], key);
        self.at += 1;
        r.clone()
    }
    fn exact(&mut self, row: &[&str]) {
        assert_eq!(self.take(row[0], row.len()), row);
    }
}
#[derive(Clone)]
struct Walk {
    pc: u64,
    next: u64,
    bytes: Vec<u8>,
}
struct Clean {
    entry: u64,
    hook: u64,
    return_pc: u64,
    bytes: Vec<u8>,
}
struct Head {
    pc: u64,
    body: u64,
    walk: Vec<Walk>,
    operation: Vec<(u64, Vec<u8>)>,
    clean: Option<Clean>,
}
struct Case {
    steps: Vec<Walk>,
    finish: u64,
}
#[derive(Clone)]
struct Page {
    address: u64,
    flags: u32,
    bytes: Vec<u8>,
}
struct PageOwner {
    page: Page,
    order: u64,
    offset: u64,
    count: usize,
    zero: usize,
}
struct Candidate {
    inputs: Vec<Input>,
    heads: Vec<Head>,
    cases: Vec<Case>,
    pages: Vec<Page>,
    base: Vec<u8>,
    journal: Option<recording::Journal>,
    hook: Option<(u64, Vec<u8>)>,
}

fn relative(opcode: &[u8], pc: u64, target: u64) -> Vec<u8> {
    let delta = i128::from(target) - i128::from(pc.checked_add(opcode.len() as u64 + 4).unwrap());
    let mut result = opcode.to_vec();
    result.extend_from_slice(&i32::try_from(delta).unwrap().to_le_bytes());
    result
}
fn operation(src: seed::Head, original: &[u8], body: u64) -> Vec<Vec<u8>> {
    if body == src.pc {
        return vec![original.to_vec()];
    }
    match src.flow {
        seed::Flow::Call(target) => {
            assert_eq!(original[0], 0xe8);
            assert_eq!(original.len(), 5);
            let mut push = vec![0x68];
            push.extend_from_slice(&i32::try_from(src.pc + 5).unwrap().to_le_bytes());
            vec![push, relative(&[0xe9], body + 5, target)]
        }
        seed::Flow::Jump(target) => {
            assert_eq!(original[0], 0xeb);
            vec![relative(&[0xe9], body, target)]
        }
        seed::Flow::Jb(target)
        | seed::Flow::Jae(target)
        | seed::Flow::Jbe(target)
        | seed::Flow::Jne(target) => {
            assert!(matches!(original[0], 0x72 | 0x73 | 0x75 | 0x76));
            assert_eq!(original.len(), 2);
            vec![relative(&[0x0f, original[0] + 0x10], body, target)]
        }
        seed::Flow::Next | seed::Flow::Return => vec![original.to_vec()],
    }
}
fn jump(pc: u64, code: &[u8]) -> u64 {
    let delta = if code.len() == 2 && code[0] == 0xeb {
        i128::from(code[1] as i8)
    } else {
        assert!((5..=9).contains(&code.len()));
        let prefix = code.len() - 5;
        assert_eq!(&code[..prefix], &[0x48, 0x26, 0x36, 0x3e][..prefix]);
        assert_eq!(code[prefix], 0xe9);
        i128::from(i32::from_le_bytes(code[prefix + 1..].try_into().unwrap()))
    };
    u64::try_from(i128::from(pc) + code.len() as i128 + delta).unwrap()
}
fn logical(spec: &seed::SeedSpec) -> u64 {
    match spec.completion {
        seed::Completion::OriginalPc { pc, .. } | seed::Completion::Fault { pc, .. } => pc,
    }
}
fn endpoint(head: &Head, spec: &seed::SeedSpec) -> u64 {
    let src = seed::HEADS[spec.head_index];
    if matches!(spec.completion, seed::Completion::Fault { .. }) {
        return head.body;
    }
    let (last, raw) = head.operation.last().unwrap();
    match src.flow {
        seed::Flow::Next => last + raw.len() as u64,
        seed::Flow::Return | seed::Flow::Call(_) | seed::Flow::Jump(_) => logical(spec),
        seed::Flow::Jb(t) | seed::Flow::Jae(t) | seed::Flow::Jbe(t) | seed::Flow::Jne(t) => {
            if logical(spec) == t {
                t
            } else {
                assert_eq!(logical(spec), src.pc + u64::from(src.length));
                last + raw.len() as u64
            }
        }
    }
}

impl Candidate {
    fn read(
        witness: &Input,
        original: &Input,
        table: &Input,
        target: &Input,
        specs: &[seed::SeedSpec],
        record: bool,
    ) -> Self {
        let mut rows = Rows::new(witness);
        rows.exact(&["LI2COMMONE9NATIVE", "1"]);
        rows.exact(&["status", "COMPLETE_BYTE_WITNESSES"]);
        digest(rows.take("witness_json_sha256", 2)[1]);
        if record {
            rows.exact(&["scope", "STRUCTURAL_E9_RECORDING_COMPLETION_WITNESSES_ONLY"]);
        } else {
            rows.exact(&["scope", "STRUCTURAL_E9_NULL_COMPLETION_WITNESSES_ONLY"]);
        }
        for key in [
            "original_sha256",
            "instructions_sha256",
            "target_sha256",
            "selection_sha256",
            "candidate_sha256",
            "source_seed_sha256",
        ] {
            digest(rows.take(key, 2)[1]);
        }
        rows.exact(&["native_admission", "false"]);
        rows.exact(&["qualification_complete", "false"]);
        let mut inputs = Vec::new();
        let mut roles = Vec::new();
        while rows.is("file") {
            let r = rows.take("file", 11);
            let role = r[1].to_owned();
            assert!(roles.last().is_none_or(|old| old < &role));
            let path = PathBuf::from(std::ffi::OsString::from_vec(bytes(r[2])));
            let input = read_empty(&path);
            digest(r[4]);
            assert_eq!(input.bytes.len() as u64, n(r[3]));
            let owner = input.owner;
            assert_eq!(
                [
                    owner[0],
                    owner[1],
                    owner[2],
                    owner[3],
                    owner[4] * 1_000_000_000 + owner[5],
                    owner[6] * 1_000_000_000 + owner[7]
                ],
                std::array::from_fn::<_, 6, _>(|i| signed(r[i + 5]))
            );
            inputs.push(input);
            roles.push(role);
            if record {
                assert!(inputs.len() <= 24);
            } else {
                assert!(inputs.len() <= 23);
            }
        }
        let mut required: Vec<String> = [
            "inputs",
            "structural_envelope",
            "instructions",
            "target",
            "structural_reader",
            "witness_reader",
        ]
        .map(str::to_owned)
        .to_vec();
        for role in [
            "original",
            "selection",
            "policy",
            "candidate",
            "frontend",
            "backend",
            "loader",
            "transport_frontend",
            "helper",
            "transport_request",
            "transport_receipt",
            "transport_stdout",
            "transport_stderr",
            "producer_request",
            "producer_receipt",
            "producer_stdout",
            "producer_stderr",
        ] {
            required.push(format!("producer/{role}"));
        }
        if record {
            required.push("producer/hook_elf".to_owned());
        }
        required.sort();
        assert_eq!(roles, required);
        let get = |role: &str| -> &Input { &inputs[roles.iter().position(|s| s == role).unwrap()] };
        for (role, input) in [
            ("producer/original", original),
            ("instructions", table),
            ("target", target),
        ] {
            assert_eq!(get(role).path.as_os_str(), input.path.as_os_str());
            assert_eq!(get(role).owner, input.owner);
            assert_eq!(get(role).bytes, input.bytes);
        }
        let elf = &get("producer/candidate").bytes;
        assert_eq!(&elf[..7], b"\x7fELF\x02\x01\x01");
        assert_eq!(
            (
                u16_at(elf, 16),
                u16_at(elf, 18),
                u16_at(elf, 52),
                u16_at(elf, 54)
            ),
            (2, 62, 64, 56)
        );
        let phoff = usize::try_from(word(elf, 32)).unwrap();
        let count = usize::from(u16_at(elf, 56));
        assert!((1..=128).contains(&count) && phoff.checked_add(count * 56).unwrap() <= elf.len());
        let mut all = BTreeMap::<u64, PageOwner>::new();
        let mut order = 0;
        let mut load_tuples = Vec::new();
        for i in 0..count {
            let p = phoff + i * 56;
            if u32_at(elf, p) != 1 {
                continue;
            }
            let r = rows.take("load", 8);
            let (off, va, fs, ms, flags) = (
                word(elf, p + 8),
                word(elf, p + 16),
                word(elf, p + 32),
                word(elf, p + 40),
                u32_at(elf, p + 4),
            );
            assert_eq!(
                [
                    n(r[1]),
                    n(r[2]),
                    n(r[3]),
                    n(r[4]),
                    n(r[5]),
                    n(r[6]),
                    n(r[7])
                ],
                [order, i as u64, off, va, fs, ms, u64::from(flags)]
            );
            assert!(matches!(flags, 4..=6) && fs <= ms && ms > 0);
            assert!(
                off.checked_add(fs).unwrap() <= elf.len() as u64
                    && va.checked_add(ms).unwrap() < 1 << 47
            );
            assert_eq!(off % 4096, va % 4096);
            let lo = va & !4095;
            let hi = page_end(va + ms);
            for address in (lo..hi).step_by(PAGE) {
                assert!(!all.contains_key(&address));
                let offset = (off & !4095) + address - lo;
                let count = if address < page_end(va + fs) {
                    PAGE.min(elf.len().saturating_sub(usize::try_from(offset).unwrap()))
                } else {
                    0
                };
                let zero = if ms > fs {
                    PAGE.min((va + fs).saturating_sub(address) as usize)
                } else {
                    PAGE
                };
                let mut b = vec![0; PAGE];
                if count > 0 {
                    let at = offset as usize;
                    b[..count].copy_from_slice(&elf[at..at + count]);
                }
                b[zero..].fill(0);
                all.insert(
                    address,
                    PageOwner {
                        page: Page {
                            address,
                            flags,
                            bytes: b,
                        },
                        order,
                        offset,
                        count,
                        zero,
                    },
                );
                assert!(all.len() <= MAX_PAGES);
            }
            load_tuples.push((off, va, fs, ms, flags));
            order += 1;
        }
        assert_eq!(&load_tuples[..4], &LOADS);
        while rows.is("mapping") {
            let r = rows.take("mapping", 7);
            assert_eq!(n(r[1]), order);
            assert!(matches!(r[2], "trampoline" | "refactoring"));
            let (va, len, prot, off) = (n(r[3]), n(r[4]), n(r[5]), n(r[6]));
            assert!(len > 0 && [va, len, off].iter().all(|v| v & 4095 == 0));
            assert!(
                va.checked_add(len).unwrap() < 1 << 47
                    && off.checked_add(len).unwrap() <= elf.len() as u64
            );
            if record {
                assert!(matches!(prot, 1 | 3 | 5));
            } else {
                assert!(matches!(prot, 1 | 5));
            }
            let flags = if record && prot == 3 {
                6
            } else if prot == 5 {
                5
            } else {
                4
            };
            for address in (va..va + len).step_by(PAGE) {
                assert_eq!(all.contains_key(&address), r[2] == "refactoring");
                if r[2] == "refactoring" {
                    assert_eq!(all[&address].page.flags, 5);
                }
                let offset = off + address - va;
                let at = offset as usize;
                all.insert(
                    address,
                    PageOwner {
                        page: Page {
                            address,
                            flags,
                            bytes: elf[at..at + PAGE].to_vec(),
                        },
                        order,
                        offset,
                        count: PAGE,
                        zero: PAGE,
                    },
                );
                assert!(all.len() <= MAX_PAGES);
            }
            order += 1;
            assert!(order <= 4096);
        }
        let mut pages = Vec::new();
        let mut base = vec![0; (IMAGE_END - IMAGE_START) as usize];
        let mut base_pages = 0;
        for (&address, p) in &all {
            let r = rows.take("page", 8);
            digest(r[7]);
            assert_eq!(
                [n(r[1]), n(r[2]), n(r[3]), n(r[4]), n(r[5]), n(r[6])],
                [
                    address,
                    u64::from(p.page.flags),
                    p.order,
                    p.offset,
                    p.count as u64,
                    p.zero as u64
                ]
            );
            for (lo, hi) in [
                (ARRAY - 4096, ARRAY + 8192),
                (STACK_START - 4096, STACK_STOP + 4096),
            ] {
                assert!(address + 4096 <= lo || address >= hi);
            }
            if (IMAGE_START..IMAGE_END).contains(&address) {
                let flags = LOADS
                    .iter()
                    .find(|l| l.1 & !4095 <= address && address < page_end(l.1 + l.3))
                    .unwrap()
                    .4;
                assert_eq!(p.page.flags, flags);
                base_pages += 1;
                let at = (address - IMAGE_START) as usize;
                base[at..at + PAGE].copy_from_slice(&p.page.bytes);
            } else {
                if !record {
                    assert_ne!(p.page.flags, 6);
                }
                pages.push(p.page.clone());
            }
        }
        assert_eq!(base_pages, 37);
        let mut candidate = Self {
            inputs,
            heads: Vec::new(),
            cases: Vec::new(),
            pages,
            base,
            journal: None,
            hook: None,
        };
        let original_view = original_pages(&original.bytes);
        if record {
            let j = recording::Journal::locate(
                &original_view,
                IMAGE_START,
                LOADS[3].1,
                LOADS[3].1 + LOADS[3].3,
            );
            assert_eq!(j.journal(&candidate.base), j.journal(&original_view));
            let row = rows.take("recording-hook", 3);
            let entry = n(row[1]);
            let code = bytes(row[2]);
            let hook_input =
                &candidate.inputs[roles.iter().position(|r| r == "producer/hook_elf").unwrap()];
            let base =
                page_end(LOADS.iter().map(|p| p.1 + p.3).max().unwrap() + 0x1000000 + 8 * 4096);
            let loads = recording::e9_hook(&hook_input.bytes, base, entry, &code);
            for (a, b, flags, raw) in &loads {
                let row = rows.take("hook-load", 4);
                assert_eq!(
                    [n(row[1]), n(row[2]), n(row[3])],
                    [*a, *b, u64::from(*flags)]
                );
                for (i, &value) in raw.iter().enumerate() {
                    let pc = a + i as u64;
                    let p = candidate
                        .pages
                        .iter()
                        .find(|p| p.address <= pc && pc < p.address + 4096)
                        .unwrap();
                    assert_eq!(p.flags, *flags);
                    assert_eq!(p.bytes[(pc - p.address) as usize], value);
                }
            }
            for p in &candidate.pages {
                if p.flags == 6 {
                    assert_eq!(
                        loads
                            .iter()
                            .filter(|(a, b, f, _)| *f == 6
                                && *a & !4095 <= p.address
                                && p.address + 4096 <= page_end(*b))
                            .count(),
                        1,
                        "only exact hook-owned RW pages"
                    );
                }
            }
            j.seed(&mut candidate.base);
            candidate.journal = Some(j);
            candidate.hook = Some((entry, code));
        }
        for (index, src) in seed::HEADS.iter().copied().enumerate() {
            let id = index as u64 + 1;
            let r = rows.take("head", 5);
            assert_eq!((n(r[1]), n(r[2])), (id, src.pc));
            let body = n(r[3]);
            let at = (src.pc - IMAGE_START) as usize;
            let old = &original_view[at..at + usize::from(src.length)];
            assert_eq!(bytes(r[4]), old);
            let mut walk = Vec::new();
            let mut pc = src.pc;
            let mut seen = BTreeSet::new();
            while rows.is("walk") {
                let r = rows.take("walk", 5);
                assert_eq!((n(r[1]), n(r[2])), (id, pc));
                assert!(seen.insert(pc));
                let code = bytes(r[4]);
                let next = n(r[3]);
                assert_eq!(jump(pc, &code), next);
                assert_eq!(candidate.bytes_at(pc, code.len()), code);
                walk.push(Walk {
                    pc,
                    next,
                    bytes: code,
                });
                pc = next;
                assert!(walk.len() <= MAX_PREFIX);
            }
            let clean = if record && rows.is("clean") {
                let r = rows.take("clean", 6);
                assert_eq!((n(r[1]), n(r[2])), (id, pc));
                let hook = candidate.hook.as_ref().unwrap().0;
                assert_eq!(n(r[3]), hook);
                let raw = recording::e9_prefix(pc, src.pc, hook);
                assert_eq!(bytes(r[5]), raw);
                assert_eq!(
                    n(r[4]),
                    pc + raw.len() as u64 - recording::E9_AFTER.len() as u64
                );
                for (i, &value) in raw.iter().enumerate() {
                    assert_eq!(candidate.bytes_at(pc + i as u64, 1), [value]);
                }
                let clean = Clean {
                    entry: pc,
                    hook,
                    return_pc: n(r[4]),
                    bytes: raw,
                };
                pc += recording::E9_PREFIX_BYTES as u64;
                Some(clean)
            } else {
                None
            };
            assert_eq!(pc, body);
            let expected = operation(src, old, body);
            let mut operation = Vec::new();
            for code in expected {
                let r = rows.take("op", 4);
                assert_eq!((n(r[1]), n(r[2])), (id, pc));
                assert_eq!(bytes(r[3]), code);
                assert_eq!(candidate.bytes_at(pc, code.len()), code);
                operation.push((pc, code.clone()));
                pc = pc.checked_add(code.len() as u64).unwrap();
            }
            if body != src.pc {
                let r = rows.take("continue", 6);
                assert_eq!(
                    (n(r[1]), n(r[2]), n(r[5])),
                    (id, pc, src.pc + u64::from(src.length))
                );
                let code = bytes(r[4]);
                assert_eq!(code.len(), 5);
                assert_eq!(code[0], 0xe9);
                assert_eq!(candidate.bytes_at(pc, 5), code);
                let next = n(r[3]);
                assert_eq!(jump(pc, &code), next);
                let mut bypass = src.pc + u64::from(src.length);
                let mut seen = BTreeSet::new();
                let mut count = 0;
                while rows.is("bypass") {
                    let r = rows.take("bypass", 5);
                    assert_eq!((n(r[1]), n(r[2])), (id, bypass));
                    assert!(seen.insert(bypass));
                    let code = bytes(r[4]);
                    assert_eq!(candidate.bytes_at(bypass, code.len()), code);
                    let to = n(r[3]);
                    assert_eq!(jump(bypass, &code), to);
                    bypass = to;
                    count += 1;
                    assert!(count <= MAX_PREFIX);
                }
                assert_eq!(bypass, next); // This continuation is authenticated, never executed for completion.
            }
            candidate.heads.push(Head {
                pc: src.pc,
                body,
                walk,
                operation,
                clean,
            });
        }
        for spec in specs {
            let r = rows.take("case", 7);
            let id = spec.case_index as u64;
            assert_eq!(
                [n(r[1]), n(r[2]), n(r[3]), n(r[4]), n(r[5])],
                [
                    id,
                    spec.head_index as u64 + 1,
                    spec.state_index as u64,
                    spec.seed,
                    spec.registers.rflags
                ]
            );
            let fault = matches!(spec.completion, seed::Completion::Fault { .. });
            assert_eq!(r[6], if fault { "true" } else { "false" });
            let h = &candidate.heads[spec.head_index];
            let finish = endpoint(h, spec);
            let mut steps = Vec::new();
            assert!(!h.operation.is_empty() && h.operation.len() <= 2);
            if h.operation.len() == 2 {
                assert!(matches!(
                    seed::HEADS[spec.head_index].flow,
                    seed::Flow::Call(_)
                ));
                assert!(!fault);
            }
            for (i, (pc, code)) in h.operation.iter().enumerate() {
                let r = rows.take("step", 5);
                let next = if i + 1 < h.operation.len() {
                    h.operation[i + 1].0
                } else {
                    finish
                };
                assert_eq!([n(r[1]), n(r[2]), n(r[3])], [id, *pc, next]);
                assert_eq!(bytes(r[4]), *code);
                steps.push(Walk {
                    pc: *pc,
                    next,
                    bytes: code.clone(),
                });
            }
            let r = rows.take("done", 9);
            assert_eq!((n(r[1]), n(r[3]), n(r[4])), (id, finish, logical(spec)));
            match spec.completion {
                seed::Completion::Fault {
                    signal,
                    code,
                    address,
                    ..
                } => {
                    assert_eq!(r[2], "fault");
                    assert_eq!(
                        [n(r[5]), n(r[6]), n(r[7])],
                        [signal as u64, code as u64, address]
                    );
                    assert_eq!(r[8], "none");
                }
                seed::Completion::OriginalPc { .. } => {
                    assert_eq!(r[2], "original-boundary");
                    assert_eq!(&r[5..8], &["none"; 3]);
                    if matches!(seed::HEADS[spec.head_index].flow, seed::Flow::Call(_)) {
                        assert_eq!(n(r[8]), h.pc + 5);
                    } else {
                        assert_eq!(r[8], "none");
                    }
                }
            }
            candidate.cases.push(Case { steps, finish });
        }
        rows.exact(&["complete", "87", "174", "2"]);
        assert_eq!(rows.at, rows.rows.len());
        assert_eq!((candidate.heads.len(), candidate.cases.len()), (87, 176));
        candidate.stable();
        candidate
    }
    fn bytes_at(&self, pc: u64, len: usize) -> Vec<u8> {
        assert!((1..=15).contains(&len));
        let stop = pc.checked_add(len as u64).unwrap();
        let mut out = Vec::new();
        for at in pc..stop {
            if (IMAGE_START..IMAGE_END).contains(&at) {
                assert!(
                    LOADS
                        .iter()
                        .any(|l| l.4 == 5 && l.1 & !4095 <= at && at < page_end(l.1 + l.3))
                );
                out.push(self.base[(at - IMAGE_START) as usize]);
            } else {
                let page = self
                    .pages
                    .iter()
                    .find(|p| p.address <= at && at < p.address + 4096)
                    .unwrap();
                assert_eq!(page.flags, 5);
                out.push(page.bytes[(at - page.address) as usize]);
            }
        }
        out
    }
    fn stable(&self) {
        for input in &self.inputs {
            input.stable();
        }
    }
}

struct Versions<'a> {
    original: &'a OwnedImage,
    candidate: &'a Candidate,
    extra: Vec<Mapping>,
}
impl<'a> Versions<'a> {
    fn new(original: &'a OwnedImage, candidate: &'a Candidate) -> Self {
        let extra = candidate
            .pages
            .iter()
            .map(|p| reserve(p.address, PAGE))
            .collect();
        Self {
            original,
            candidate,
            extra,
        }
    }
    fn install(&self, candidate: bool) {
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        self.original
            .image
            .protect(libc::PROT_READ | libc::PROT_WRITE);
        self.original.image.initialize(
            0,
            if candidate {
                &self.candidate.base
            } else {
                &self.original.pages
            },
        );
        for &(_, address, _, len, flags) in &LOADS {
            let lo = address & !4095;
            protect(
                lo,
                (page_end(address + len) - lo) as usize,
                protection(flags),
            );
        }
        for (m, p) in self.extra.iter().zip(&self.candidate.pages) {
            if candidate {
                m.protect(libc::PROT_READ | libc::PROT_WRITE);
                m.initialize(0, &p.bytes);
                m.protect(protection(p.flags));
            } else {
                m.protect(libc::PROT_NONE);
            }
        }
    }
    fn capture(
        &self,
        child: &Tracee,
        spec: &seed::SeedSpec,
        dir: &Path,
        stem: &str,
        logical: u64,
        physical: u64,
    ) -> Captured {
        let registers = child.registers();
        let raw = child.xstate();
        let stack = child.memory(STACK_START, seed::STACK_BYTES);
        let state = Snapshot {
            logical_pc: logical,
            registers,
            xstate: canonical_xstate(&raw),
            data: child.memory(ARRAY, PAGE),
            application_stack: stack[(spec.compared_stack_start - STACK_START) as usize..].to_vec(),
        };
        save_named_snapshot(dir, stem, &state);
        write_new(&dir.join(format!("{stem}.xstate-raw")), &raw);
        write_new(&dir.join(format!("{stem}.stack-owned")), &stack);
        let base = child.memory(IMAGE_START, self.candidate.base.len());
        write_new(&dir.join(format!("{stem}.loads")), &base);
        let mut generated = Vec::new();
        for p in &self.candidate.pages {
            generated.extend(child.memory(p.address, PAGE));
        }
        write_new(&dir.join(format!("{stem}.generated")), &generated);
        map_record(child, spec, dir, stem);
        assert_eq!(
            registers.rip, physical,
            "exact admitted physical boundary before logical comparison"
        );
        assert_eq!(target(), self.original.target);
        xstate_ready(&raw, &self.original.target);
        if let Some(j) = self.candidate.journal {
            let h = &self.candidate.heads[spec.head_index];
            let recorded = stem != "before" && h.clean.is_some();
            assert_eq!(
                base,
                j.expected(&self.candidate.base, recorded.then_some(h.pc)),
                "entire LOAD image; exact append and all other bytes unchanged"
            );
        } else {
            assert_eq!(
                base, self.candidate.base,
                "all candidate original pages including globals/journal remain exact"
            );
        }
        let maps = std::fs::read_to_string(dir.join(format!("{stem}.maps"))).unwrap();
        for (index, p) in self.candidate.pages.iter().enumerate() {
            assert_eq!(&generated[index * PAGE..(index + 1) * PAGE], p.bytes);
            let mut matches = 0;
            for line in maps.lines() {
                let f: Vec<_> = line.split_ascii_whitespace().collect();
                let (a, b) = f[0].split_once('-').unwrap();
                let a = u64::from_str_radix(a, 16).unwrap();
                let b = u64::from_str_radix(b, 16).unwrap();
                if a <= p.address && p.address + 4096 <= b {
                    matches += 1;
                    assert_eq!(f.len(), 5);
                    if self.candidate.journal.is_some() && p.flags == 6 {
                        assert_eq!(f[1], "rw-p");
                    } else {
                        assert_eq!(f[1], if p.flags == 5 { "r-xp" } else { "r--p" });
                    }
                    assert_eq!(u64::from_str_radix(f[2], 16).unwrap(), 0);
                    assert_eq!((f[3], f[4]), ("00:00", "0"));
                }
            }
            assert_eq!(matches, 1);
        }
        Captured { state, raw, stack }
    }
}

fn pair(
    versions: &Versions<'_>,
    spec: &seed::SeedSpec,
    context: &Context,
    before: &Captured,
    after: &Captured,
    dir: &Path,
) {
    let head = &versions.candidate.heads[spec.head_index];
    let case = &versions.candidate.cases[spec.case_index];
    let child = Tracee::fork();
    child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
    assert_eq!(inherited(&child.registers()), inherited(&context.registers));
    let raw = child.xstate();
    assert_eq!(raw.len(), context.xstate.len());
    xstate_ready(&raw, &versions.original.target);
    let wanted = apply(spec, context.registers);
    let seeded = seeded_xstate(context.xstate.clone(), spec.seed);
    child.set_registers(&wanted);
    child.set_xstate(&seeded); // Sole declared seed, before either path.
    let entry = versions.capture(&child, spec, dir, "before", head.pc, head.pc);
    assert_state(&before.state, &entry.state);
    assert_eq!(entry.stack, before.stack);
    let mut trace = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dir.join("trace.tsv"))
        .unwrap();
    trace
        .write_all(b"phase\tbefore_pc\tafter_pc\tbytes\n")
        .unwrap();
    let mut steps = 0;
    for w in &head.walk {
        assert_eq!(child.registers().rip, w.pc);
        assert_eq!(child.memory(w.pc, w.bytes.len()), w.bytes);
        step(&child, &mut steps);
        let actual = child.registers().rip;
        writeln!(
            &mut trace,
            "prefix\t{}\t{}\t{}",
            w.pc,
            actual,
            hex(&w.bytes)
        )
        .unwrap();
        trace.flush().unwrap();
        assert_eq!(actual, w.next);
    }
    if let Some(clean) = &head.clean {
        let mut decoder = iced_x86::Decoder::with_ip(
            64,
            &clean.bytes,
            clean.entry,
            iced_x86::DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            let instruction = decoder.decode();
            assert!(!instruction.is_invalid());
            let pc = instruction.ip();
            let at = (pc - clean.entry) as usize;
            let raw = &clean.bytes[at..at + instruction.len()];
            assert_eq!(child.registers().rip, pc);
            assert_eq!(child.memory(pc, raw.len()), raw);
            step(&child, &mut steps);
            let next = child.registers().rip;
            writeln!(&mut trace, "clean-prefix\t{pc}\t{next}\t{}", hex(raw)).unwrap();
            trace.flush().unwrap();
            if instruction.flow_control() == iced_x86::FlowControl::Call {
                assert_eq!(instruction.near_branch_target(), clean.hook);
                assert_eq!(next, clean.hook);
                assert_eq!(instruction.next_ip(), clean.return_pc);
                recording_native::callback(
                    &child,
                    recording_native::Callback {
                        start: clean.hook,
                        code: &versions.candidate.hook.as_ref().unwrap().1,
                        return_pc: clean.return_pc,
                        logical: head.pc,
                        core: false,
                    },
                    &mut steps,
                    &mut trace,
                );
            } else {
                assert_eq!(instruction.flow_control(), iced_x86::FlowControl::Next);
                assert_eq!(next, instruction.next_ip());
            }
        }
        assert_eq!(decoder.ip(), head.body);
    }
    let stack_expected = |base: &[u8]| {
        if let Some(clean) = &head.clean {
            let r = &before.state.registers;
            recording::e9_stack(
                base,
                STACK_START,
                spec.compared_stack_start,
                r.rsp,
                r.eflags,
                [r.r11, r.r10, r.rax, r.r9, r.r8, r.rcx, r.rdx, r.rsi, r.rdi],
                clean.return_pc,
            )
        } else {
            base.to_vec()
        }
    };
    let restored = versions.capture(&child, spec, dir, "restored", head.pc, head.body);
    assert_state(&before.state, &restored.state);
    assert_eq!(restored.raw.len(), before.raw.len());
    if head.clean.is_some() {
        assert_eq!(
            restored.stack,
            stack_expected(&before.stack),
            "entire stack equals exact clean-call byte model"
        );
    } else {
        assert_eq!(
            restored.stack, before.stack,
            "null stateless gateway cannot claim private scratch writes"
        );
    }
    if let Some(effect) = spec.memory_effect {
        if effect.access == seed::Access::Read {
            assert_eq!(child.memory(effect.address, 8), effect.bytes);
        }
    }
    let mut fault = None;
    for (index, w) in case.steps.iter().enumerate() {
        assert_eq!(child.registers().rip, w.pc);
        assert_eq!(child.memory(w.pc, w.bytes.len()), w.bytes);
        if matches!(spec.completion, seed::Completion::Fault { .. }) {
            assert_eq!(case.steps.len(), 1);
            assert!(steps < MAX_STEPS && Instant::now() < child.deadline);
            steps += 1;
            fault = Some(child.synchronous_fault());
        } else {
            step(&child, &mut steps);
        }
        let actual = child.registers().rip;
        writeln!(
            &mut trace,
            "operation-{index}\t{}\t{}\t{}",
            w.pc,
            actual,
            hex(&w.bytes)
        )
        .unwrap();
        trace.flush().unwrap();
        assert_eq!(
            actual, w.next,
            "predeclared operation endpoint; never execute continue to find equal state"
        );
        if index + 1 < case.steps.len() {
            assert_eq!((index, case.steps.len()), (0, 2));
            assert!(matches!(
                seed::HEADS[spec.head_index].flow,
                seed::Flow::Call(_)
            ));
            assert_eq!(w.bytes[0], 0x68);
            assert_eq!(w.bytes.len(), 5);
            let address = before.state.registers.rsp.checked_sub(8).unwrap();
            let return_word = head.pc + 5;
            assert_eq!(
                i32::from_le_bytes(w.bytes[1..].try_into().unwrap()) as u64,
                return_word
            );
            assert_eq!(child.registers().rsp, address);
            assert_eq!(word(&child.memory(address, 8), 0), return_word);
            let mut expected_stack = stack_expected(&before.stack);
            let at = usize::try_from(address.checked_sub(STACK_START).unwrap()).unwrap();
            expected_stack[at..at + 8].copy_from_slice(&return_word.to_le_bytes());
            let mut expected = Snapshot {
                logical_pc: head.pc,
                registers: before.state.registers,
                xstate: before.state.xstate.clone(),
                data: before.state.data.clone(),
                application_stack: expected_stack
                    [(spec.compared_stack_start - STACK_START) as usize..]
                    .to_vec(),
            };
            expected.registers.rsp = address;
            let intermediate = versions.capture(&child, spec, dir, "operation-00", head.pc, w.next);
            assert_state(&expected, &intermediate.state);
            assert_eq!(intermediate.stack, expected_stack);
            assert_eq!(intermediate.raw.len(), before.raw.len());
        }
    }
    let final_state = versions.capture(&child, spec, dir, "after", logical(spec), case.finish);
    assert_state(&after.state, &final_state.state);
    assert_eq!(final_state.raw.len(), after.raw.len());
    if head.clean.is_some() {
        assert_eq!(
            final_state.stack,
            stack_expected(&after.stack),
            "complete owned stack, exact clean-call words plus original effect"
        );
    } else {
        assert_eq!(
            final_state.stack, after.stack,
            "complete owned stack, with no scratch exception"
        );
    }
    match spec.completion {
        seed::Completion::Fault {
            signal,
            code,
            address,
            ..
        } => {
            assert_eq!(fault, Some((signal, code, address)));
            assert_state(&restored.state, &final_state.state);
        }
        seed::Completion::OriginalPc { .. } => {
            assert!(fault.is_none());
            if let Some(effect) = spec.memory_effect {
                if effect.access == seed::Access::Write {
                    assert_eq!(child.memory(effect.address, 8), effect.bytes);
                }
            }
            if matches!(seed::HEADS[spec.head_index].flow, seed::Flow::Call(_)) {
                assert_eq!(
                    word(&child.memory(final_state.state.registers.rsp, 8), 0),
                    head.pc + 5
                );
            }
        }
    }
    let pid = child.pid;
    drop(child);
    let mut status = 0;
    // SAFETY: query only the exact child already reaped by the unchanged Tracee owner.
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    write_new(&dir.join("complete.tsv"),format!("LI2E9PAIRCHILD\t1\ncase\t{}\nsteps\t{}\nphysical_completion\t{}\nlogical_completion\t{}\nfault\t{:?}\ncomparisons\t3\ncall_intermediate_checks\t{}\nreaped_echild\ttrue\nqualification_complete\tfalse\n",spec.case_index,steps,case.finish,logical(spec),fault,usize::from(case.steps.len()==2)).as_bytes());
}

pub fn main() {
    let mut args: Vec<_> = std::env::args_os().collect();
    let record = recording::arguments(&mut args);
    assert_eq!(
        args.len(),
        8,
        "replay-common-e9 ORIGINAL INSTRUCTIONS TARGET WITNESS_JSON NATIVE_TSV NEW_CAPTURES"
    );
    assert_eq!(args[1], "replay-common-e9");
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    // SAFETY: scalar identity query only.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        libc::c_long::from(std::process::id())
    );
    let original = Input::open(Path::new(&args[2]), MAX_INPUT);
    let instructions = Input::open(Path::new(&args[3]), 16384);
    let requested_target = Input::open(Path::new(&args[4]), 16384);
    assert_eq!(requested_target.bytes, target_tsv().as_bytes());
    let json = Input::open(Path::new(&args[5]), MAX_INPUT);
    let witness = Input::open(Path::new(&args[6]), MAX_INPUT);
    let inventory = admit(&original.bytes, &instructions.bytes);
    let mut original_view = original_pages(&original.bytes);
    let anchors = seed::Anchors::new(ARRAY, FRAME).unwrap();
    let specs: Vec<_> = (0..seed::CASE_COUNT)
        .map(|i| inventory.case(i, anchors).unwrap())
        .collect();
    let candidate = Candidate::read(
        &witness,
        &original,
        &instructions,
        &requested_target,
        &specs,
        record,
    );
    if let Some(j) = candidate.journal {
        j.seed(&mut original_view);
    }
    let expanded = candidate
        .cases
        .iter()
        .filter(|c| c.steps.len() == 2)
        .count();
    assert!(expanded <= 12);
    let dir = Path::new(&args[7]);
    assert!(dir.is_absolute());
    assert_eq!(
        dir.parent().unwrap().canonicalize().unwrap().as_os_str(),
        dir.parent().unwrap().as_os_str()
    );
    std::fs::create_dir(dir).unwrap();
    for (name, b) in [
        ("original.elf", &original.bytes),
        ("instructions.tsv", &instructions.bytes),
        ("runtime-target.tsv", &requested_target.bytes),
        ("e9-witness.json", &json.bytes),
        ("e9-native.tsv", &witness.bytes),
        ("original-pages.bin", &original_view),
    ] {
        write_new(&dir.join(name), b);
    }
    let mut owners = format!(
        "whole_hash_and_reader_projection_admission\tCALLER_REQUIRED\noriginal\t{:?}\ninstructions\t{:?}\ntarget\t{:?}\njson\t{:?}\ntsv\t{:?}\n",
        original.owner, instructions.owner, requested_target.owner, json.owner, witness.owner
    );
    for input in &candidate.inputs {
        use std::os::unix::ffi::OsStrExt;
        owners.push_str(&format!(
            "{}\t{:?}\n",
            hex(input.path.as_os_str().as_bytes()),
            input.owner
        ));
    }
    let records = text(&witness)
        .lines()
        .filter(|s| s.starts_with("file\t"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    write_new(&dir.join("bundle-inputs.tsv"), records.as_bytes());
    write_new(&dir.join("input-owners.tsv"), owners.as_bytes());
    let mut pages = candidate.base.clone();
    let mut page_plan = String::new();
    for p in &candidate.pages {
        page_plan.push_str(&format!("{}\t{}\t{}\n", p.address, p.flags, pages.len()));
        pages.extend_from_slice(&p.bytes);
    }
    write_new(&dir.join("candidate-pages.bin"), &pages);
    write_new(&dir.join("page-plan.tsv"), page_plan.as_bytes());
    let mut plan = String::from(
        "case\thead\tstate\toriginal_pc\tbody_pc\tcompletion_pc\tlogical_completion\toperation_steps\n",
    );
    for spec in &specs {
        let h = &candidate.heads[spec.head_index];
        let c = &candidate.cases[spec.case_index];
        plan.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            spec.case_index,
            spec.head_index,
            spec.state_index,
            h.pc,
            h.body,
            c.finish,
            logical(spec),
            c.steps.len()
        ));
    }
    write_new(&dir.join("planned-cases.tsv"), plan.as_bytes());
    let mut names: Vec<String> = [
        "original.elf",
        "instructions.tsv",
        "runtime-target.tsv",
        "e9-witness.json",
        "e9-native.tsv",
        "original-pages.bin",
        "bundle-inputs.tsv",
        "input-owners.tsv",
        "candidate-pages.bin",
        "page-plan.tsv",
        "planned-cases.tsv",
        "capture-inventory.tsv",
        "complete.tsv",
    ]
    .map(str::to_owned)
    .to_vec();
    for spec in &specs {
        let case = format!("case-{:03}", spec.case_index);
        for name in ["pair.tsv", "witness.tsv"] {
            names.push(format!("{case}/{name}"));
        }
        for name in ["seed.tsv", "complete.tsv"] {
            names.push(format!("{case}/original/{name}"));
        }
        for stem in ["before", "after"] {
            for suffix in [
                "regs",
                "xstate",
                "xstate-raw",
                "data",
                "stack",
                "stack-owned",
                "loads",
                "maps",
            ] {
                names.push(format!("{case}/original/{stem}.{suffix}"));
            }
        }
        for name in ["trace.tsv", "complete.tsv"] {
            names.push(format!("{case}/candidate/{name}"));
        }
        let mut stems = vec!["before", "restored", "after"];
        if candidate.cases[spec.case_index].steps.len() == 2 {
            stems.push("operation-00");
        }
        for stem in stems {
            for suffix in [
                "regs",
                "xstate",
                "xstate-raw",
                "data",
                "stack",
                "stack-owned",
                "loads",
                "maps",
                "generated",
            ] {
                names.push(format!("{case}/candidate/{stem}.{suffix}"));
            }
        }
    }
    let files = 8637 + 9 * expanded;
    assert_eq!(names.len(), files);
    assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), names.len());
    write_new(
        &dir.join("capture-inventory.tsv"),
        (names.join("\n") + "\n").as_bytes(),
    );
    let owned = OwnedImage::new(original_view);
    let versions = Versions::new(&owned, &candidate);
    let mut context = None;
    for spec in &specs {
        let case = dir.join(format!("case-{:03}", spec.case_index));
        std::fs::create_dir(&case).unwrap();
        let original_dir = case.join("original");
        let candidate_dir = case.join("candidate");
        std::fs::create_dir(&original_dir).unwrap();
        std::fs::create_dir(&candidate_dir).unwrap();
        write_new(&original_dir.join("seed.tsv"),format!("case\t{}\nhead\t{}\nstate\t{}\nseed\t{}\npc\t{}\nrsp\t{}\nrflags\t{}\narray\t{}\nframe\t{}\nstack_start\t{}\nstack_end\t{}\ncomparison_start\t{}\neffect\t{:?}\ncompletion\t{:?}\n",spec.case_index,spec.head_index,spec.state_index,spec.seed,spec.registers.rip,spec.registers.get(seed::Reg::Rsp),spec.registers.rflags,ARRAY,FRAME,STACK_START,STACK_STOP,spec.compared_stack_start,spec.memory_effect,spec.completion).as_bytes());
        let h = &candidate.heads[spec.head_index];
        let c = &candidate.cases[spec.case_index];
        let mut record = format!(
            "original\t{}\nbody\t{}\ncompletion\t{}\nlogical\t{}\n",
            h.pc,
            h.body,
            c.finish,
            logical(spec)
        );
        for w in &h.walk {
            record.push_str(&format!(
                "prefix\t{}\t{}\t{}\n",
                w.pc,
                w.next,
                hex(&w.bytes)
            ));
        }
        for w in &c.steps {
            record.push_str(&format!(
                "operation\t{}\t{}\t{}\n",
                w.pc,
                w.next,
                hex(&w.bytes)
            ));
        }
        write_new(&case.join("witness.tsv"), record.as_bytes());
        let (before, after) = reference(&owned, spec, &mut context, &original_dir);
        owned.initialize(spec);
        versions.install(true);
        pair(
            &versions,
            spec,
            context.as_ref().unwrap(),
            &before,
            &after,
            &candidate_dir,
        );
        versions.install(false);
        for input in [&original, &instructions, &requested_target, &json, &witness] {
            input.stable();
        }
        candidate.stable();
        write_new(&case.join("pair.tsv"),format!("LI2E9PAIR\t1\ncase\t{}\ncomparisons\t3\nchildren\t2\ncall_intermediate_checks\t{}\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n",spec.case_index,usize::from(c.steps.len()==2)).as_bytes());
    }
    if record {
        write_new(&dir.join("complete.tsv"),format!("LI2COMMONE9RECORDINGPAIRS\t1\nheads\t87\nnormal_pairs\t174\nfault_pairs\t2\nchildren\t352\ncomparisons\t528\ncall_intermediate_checks\t{expanded}\nsnapshots\t{}\nfiles\t{files}\nrecording_profile\tbounded-journal-v1\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n",880+expanded).as_bytes());
        println!(
            "E9 recording pairs complete: heads=87 normal=174 faults=2 comparisons=528 call_intermediates={expanded} files={files} qualification_complete=false"
        );
        return;
    }
    write_new(&dir.join("complete.tsv"),format!("LI2COMMONE9PAIRS\t1\nheads\t87\nnormal_pairs\t174\nfault_pairs\t2\nchildren\t352\ncomparisons\t528\ncall_intermediate_checks\t{expanded}\nsnapshots\t{}\nfiles\t{files}\nrecording_hooks\tUNIMPLEMENTED_UNRUN\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n",880+expanded).as_bytes());
    println!(
        "E9 null pairs complete: heads=87 normal=174 faults=2 comparisons=528 call_intermediates={expanded} files={files} qualification_complete=false"
    );
}
