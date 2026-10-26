//! Finite original heap-sort observer. This is not an equivalence oracle.
//! One temporary INT3/one RIP decrement locates the real before_sort call;
//! every subsequent kernel instruction executes normally under SINGLESTEP.
//! The enclosing recipe authenticates original/inventory/runtime-owner inputs.
use super::*;
use liteinst2::cache_line::CacheLineSize;
use liteinst2::scanner::InstructionScanner;
use std::collections::BTreeMap;
use std::os::unix::fs::DirBuilderExt;

#[path = "e9_common_app_data.rs"]
mod data;

const APP_SECONDS: u64 = 60;
const HARD_STEPS: usize = 1_048_576;
const BRIDGE_STEPS: usize = 128;
const JOURNAL_BYTES: usize = 131_144;
const NAMES: [&str; 3] = ["li2_array_store", "li2_sift_down", "li2_heap_sort"];
const INSTRUCTION_HEADER: &str = "id\tpc\tlength\tfile_offset\tfunction\tbytes\tmnemonic\tflow\tdirect_target\tblock_start\tblock_end\tjump_site\theap_write\trsp_depth";
const SITE_HEADER: &str = "id\tpc\tlength\tfile_offset\tfunction\tstyle\n";

fn read(path: &Path, max: usize) -> Vec<u8> {
    let file = File::open(path).unwrap();
    assert!(file.metadata().unwrap().is_file());
    let mut bytes = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut bytes).unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= max);
    bytes
}
fn text(path: &Path, max: usize) -> String {
    let value = String::from_utf8(read(path, max)).unwrap();
    assert!(value.is_ascii() && value.ends_with('\n') && !value.contains('\r'));
    value
}
fn num(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x") {
        assert!(!hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        u64::from_str_radix(hex, 16).unwrap()
    } else {
        assert!(!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
        s.parse().unwrap()
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn end(start: u64, len: u64) -> u64 {
    start.checked_add(len).unwrap()
}
fn stat(m: &std::fs::Metadata) -> [i128; 8] {
    [
        i128::from(m.dev()),
        i128::from(m.ino()),
        i128::from(m.mode()),
        i128::from(m.len()),
        i128::from(m.mtime()),
        i128::from(m.mtime_nsec()),
        i128::from(m.ctime()),
        i128::from(m.ctime_nsec()),
    ]
}
fn regs(r: &libc::user_regs_struct) -> [u64; 27] {
    [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ]
}
fn words(values: &[u64]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}
#[derive(Clone)]
struct Segment {
    offset: u64,
    address: u64,
    file: u64,
    memory: u64,
    flags: u32,
}
struct Owner {
    path: PathBuf,
    file: File,
    bytes: Vec<u8>,
    identity: [i128; 8],
    provider: provider::Provider,
    fdinfo: String,
    loads: Vec<Segment>,
    kind: u16,
    interpreter: Option<PathBuf>,
}
impl Owner {
    fn open(path: &Path) -> Self {
        assert!(path.is_absolute() && path.canonicalize().unwrap().as_os_str() == path.as_os_str());
        let file = File::open(path).unwrap();
        let before = file.metadata().unwrap();
        assert!(before.is_file() && before.len() <= 16 * 1024 * 1024);
        let bytes = read(path, 16 * 1024 * 1024);
        let identity = stat(&before);
        assert_eq!(identity, stat(&file.metadata().unwrap()));
        assert_eq!(identity, stat(&std::fs::metadata(path).unwrap()));
        assert_eq!(&bytes[..7], b"\x7fELF\x02\x01\x01");
        assert_eq!(u16_at(&bytes, 18), 62);
        assert_eq!(u16_at(&bytes, 52), 64);
        assert_eq!(u16_at(&bytes, 54), 56);
        let kind = u16_at(&bytes, 16);
        assert!(matches!(kind, 2 | 3));
        let phoff = word(&bytes, 32);
        let count = u16_at(&bytes, 56);
        assert!((1..=128).contains(&count));
        assert!(end(phoff, u64::from(count) * 56) <= bytes.len() as u64);
        let mut loads = Vec::new();
        let mut interpreter = None;
        for n in 0..count {
            let p = usize::try_from(phoff + u64::from(n) * 56).unwrap();
            let k = u32_at(&bytes, p);
            let flags = u32_at(&bytes, p + 4);
            let offset = word(&bytes, p + 8);
            let address = word(&bytes, p + 16);
            let fs = word(&bytes, p + 32);
            let ms = word(&bytes, p + 40);
            if k == 1 {
                assert!(fs <= ms && ms > 0 && end(offset, fs) <= bytes.len() as u64);
                assert!(matches!(flags, 4..=6) && address % 4096 == offset % 4096);
                let alignment = word(&bytes, p + 48);
                assert!(alignment.is_power_of_two() && alignment >= 4096);
                end(address, ms);
                loads.push(Segment {
                    offset,
                    address,
                    file: fs,
                    memory: ms,
                    flags,
                });
            } else if k == 3 {
                assert!(
                    interpreter.is_none()
                        && fs > 1
                        && fs <= 4096
                        && end(offset, fs) <= bytes.len() as u64
                );
                let raw = &bytes[offset as usize..(offset + fs) as usize];
                assert_eq!(raw.last(), Some(&0));
                let p = PathBuf::from(std::str::from_utf8(&raw[..raw.len() - 1]).unwrap());
                assert!(p.is_absolute());
                interpreter = Some(p.canonicalize().unwrap());
            } else if k == 0x6474_e551 {
                assert_eq!(flags, 6, "non-executable stack");
            }
        }
        assert!((1..=8).contains(&loads.len()));
        loads.sort_by_key(|l| l.address);
        for pair in loads.windows(2) {
            assert!(end(pair[0].address, pair[0].memory) <= pair[1].address);
        }
        let (fdinfo, provider) = observe_provider(&file);
        Self {
            path: path.to_owned(),
            file,
            bytes,
            identity,
            provider,
            fdinfo,
            loads,
            kind,
            interpreter,
        }
    }
    fn stable(&self) {
        assert_eq!(self.identity, stat(&self.file.metadata().unwrap()));
        assert_eq!(self.identity, stat(&std::fs::metadata(&self.path).unwrap()));
        assert_eq!(read(&self.path, 16 * 1024 * 1024), self.bytes);
    }
    fn slice(&self, pc: u64, len: usize, flags: u32) -> (usize, &[u8]) {
        let candidates: Vec<_> = self
            .loads
            .iter()
            .filter(|l| {
                l.flags == flags && l.address <= pc && end(pc, len as u64) <= end(l.address, l.file)
            })
            .collect();
        assert_eq!(candidates.len(), 1, "one exact file-backed LOAD owner");
        let l = candidates[0];
        let off = usize::try_from(l.offset + pc - l.address).unwrap();
        (off, &self.bytes[off..off + len])
    }
    fn object(&self, pc: u64, len: u64) {
        assert_eq!(
            self.loads
                .iter()
                .filter(|l| l.flags == 6
                    && l.address <= pc
                    && end(pc, len) <= end(l.address, l.memory))
                .count(),
            1
        );
    }
}
#[derive(Clone)]
struct Function {
    name: String,
    pc: u64,
    len: usize,
}
struct Layout {
    functions: Vec<Function>,
    main: Function,
    before: u64,
    after: u64,
    run: u64,
    journal: u64,
}
fn layout(path: &Path, image: &Owner) -> Layout {
    let value = text(path, 16 * 1024);
    let lines: Vec<_> = value.lines().collect();
    assert_eq!(lines.len(), 10);
    assert_eq!(lines[0], "LI2COMMONOBSERVER\t1");
    assert_eq!(lines[9], "END");
    let mut symbols = Vec::new();
    for (line, (tag, name)) in lines[1..9].iter().zip([
        ("function", NAMES[0]),
        ("function", NAMES[1]),
        ("function", NAMES[2]),
        ("function", "main"),
        ("marker", "li2_before_sort"),
        ("marker", "li2_after_sort"),
        ("object", "li2_run"),
        ("object", "li2_journal"),
    ]) {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 4);
        assert_eq!((f[0], f[1]), (tag, name));
        let pc = num(f[2]);
        let len = usize::try_from(num(f[3])).unwrap();
        assert!(len > 0 && len <= JOURNAL_BYTES);
        if tag == "object" {
            image.object(pc, len as u64);
        } else {
            image.slice(pc, len, 5);
        }
        symbols.push(Function {
            name: name.to_owned(),
            pc,
            len,
        });
    }
    assert_eq!(symbols[4].len, 1);
    assert_eq!(symbols[5].len, 1);
    for i in [4, 5] {
        assert_eq!(image.slice(symbols[i].pc, 1, 5).1, b"\xc3");
    }
    assert_eq!(symbols[6].len, 88);
    assert_eq!(symbols[7].len, JOURNAL_BYTES);
    assert_eq!(
        image.slice(symbols[0].pc, symbols[0].len, 5).1,
        b"\x48\x89\x14\xf7\xc3"
    );
    for a in 0..symbols.len() {
        for b in a + 1..symbols.len() {
            assert!(
                end(symbols[a].pc, symbols[a].len as u64) <= symbols[b].pc
                    || end(symbols[b].pc, symbols[b].len as u64) <= symbols[a].pc
            );
        }
    }
    assert!(
        symbols[..3]
            .windows(2)
            .all(|p| end(p[0].pc, p[0].len as u64) <= p[1].pc)
    );
    assert!(end(symbols[2].pc, symbols[2].len as u64) - symbols[0].pc <= 65536);
    Layout {
        functions: symbols[..3].to_vec(),
        main: symbols[3].clone(),
        before: symbols[4].pc,
        after: symbols[5].pc,
        run: symbols[6].pc,
        journal: symbols[7].pc,
    }
}
#[derive(Clone)]
struct Head {
    id: usize,
    pc: u64,
    len: usize,
    offset: usize,
    function: usize,
    bytes: Vec<u8>,
    mnemonic: String,
    flow: String,
    target: Option<u64>,
    jump: bool,
    heap: bool,
    depth: Option<i64>,
}
fn decoded(image: &Owner, f: &Function, fi: usize) -> Vec<Head> {
    let (base, bytes) = image.slice(f.pc, f.len, 5);
    InstructionScanner::new(CacheLineSize::new(64).unwrap())
        .scan(bytes, f.pc)
        .unwrap()
        .instructions()
        .iter()
        .map(|s| {
            let i = s.instruction();
            let flow = format!("{:?}", i.flow_control());
            let target = matches!(
                flow.as_str(),
                "Call" | "ConditionalBranch" | "UnconditionalBranch"
            )
            .then(|| i.near_branch_target());
            let mnemonic = format!("{:?}", i.mnemonic());
            let jump = mnemonic.to_ascii_lowercase().starts_with('j');
            Head {
                id: 0,
                pc: s.address(),
                len: s.len(),
                offset: base + s.offset(),
                function: fi,
                bytes: bytes[s.offset()..s.offset() + s.len()].to_vec(),
                mnemonic,
                flow,
                target,
                jump,
                heap: fi == 0 && s.address() == f.pc,
                depth: Some(0),
            }
        })
        .collect()
}
fn status(directory: &Path, style: &str, heads: usize, sites: usize) -> Vec<String> {
    let value = text(&directory.join("status.tsv"), 16384);
    let rows: Vec<_> = value.lines().collect();
    assert_eq!(rows.len(), 12);
    assert_eq!(rows[0], "LI2COMMONRESULT\t1");
    let keys = [
        "original_sha256",
        "policy_sha256",
        "caller_provenance_sha256",
        "target_sha256",
        "style",
        "hook",
        "instruction_heads",
        "selected_sites",
        "complete_static_policy",
        "qualification_complete",
        "selection_sha256",
    ];
    let mut values = Vec::new();
    for (row, key) in rows[1..].iter().zip(keys) {
        let f: Vec<_> = row.split('\t').collect();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0], key);
        values.push(f[1].to_owned());
    }
    for i in [0, 1, 2, 3, 10] {
        assert!(
            values[i].len() == 64
                && values[i]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
    assert_eq!(values[4], style);
    assert!(matches!(values[5].as_str(), "null" | "journal"));
    assert_eq!(num(&values[6]), heads as u64);
    assert_eq!(num(&values[7]), sites as u64);
    assert_eq!(values[8], "true");
    assert_eq!(values[9], "false");
    // The recipe verifies these whole SHA-256 indexes and source owners before launch.
    // Here an incomplete static-policy result cannot masquerade as an admitted table.
    assert!(read(&directory.join("selection.txt"), 1024 * 1024).starts_with(b"LI2TOOL 1\n"));
    assert!(read(&directory.join("COMPLETE"), 16384).starts_with(b"LI2COMMONFILES\t1\n"));
    values
}
fn inventory(
    image: &Owner,
    l: &Layout,
    instructions: &Path,
    jumps: &Path,
    heap: &Path,
) -> BTreeMap<u64, Head> {
    let value = text(instructions, 1024 * 1024);
    let mut rows = value.lines();
    assert_eq!(rows.next(), Some(INSTRUCTION_HEADER));
    let mut result = BTreeMap::new();
    let mut id = 0;
    let mut expected = [SITE_HEADER.to_owned(), SITE_HEADER.to_owned()];
    for (fi, f) in l.functions.iter().enumerate() {
        for mut h in decoded(image, f, fi) {
            id += 1;
            assert!(id <= 4096);
            h.id = id;
            let row: Vec<_> = rows
                .next()
                .expect("complete static instruction inventory")
                .split('\t')
                .collect();
            assert_eq!(row.len(), 14);
            assert_eq!(
                (num(row[0]), num(row[1]), num(row[2]), num(row[3])),
                (id as u64, h.pc, h.len as u64, h.offset as u64)
            );
            assert_eq!(
                (row[4], row[5], row[6], row[7]),
                (
                    f.name.as_str(),
                    hex(&h.bytes).as_str(),
                    h.mnemonic.as_str(),
                    h.flow.as_str()
                )
            );
            let target = h
                .target
                .map_or_else(|| "none".to_owned(), |p| format!("0x{p:x}"));
            assert_eq!(row[8], target);
            assert!(
                num(row[9]) <= h.pc
                    && end(h.pc, h.len as u64) <= num(row[10])
                    && f.pc <= num(row[9])
                    && num(row[10]) <= end(f.pc, f.len as u64)
            );
            assert_eq!(
                (row[11], row[12]),
                (
                    if h.jump { "true" } else { "false" },
                    if h.heap { "true" } else { "false" }
                )
            );
            h.depth = if row[13] == "unproven" {
                assert_eq!(h.mnemonic, "Nop");
                None
            } else {
                let depth: i64 = row[13].parse().expect("complete static RSP-depth proof");
                assert!((-65536..=0).contains(&depth));
                Some(depth)
            };
            assert!(matches!(
                h.flow.as_str(),
                "Next" | "Call" | "Return" | "ConditionalBranch" | "UnconditionalBranch"
            ));
            if h.flow == "Call" {
                assert!(l.functions.iter().any(|f| Some(f.pc) == h.target));
            } else if let Some(to) = h.target {
                assert!(f.pc <= to && to < end(f.pc, f.len as u64));
            }
            for (chosen, k, style) in [(h.jump, 0, "jump-site"), (h.heap, 1, "heap-write")] {
                if chosen {
                    expected[k].push_str(&format!(
                        "{}\t0x{:x}\t{}\t{}\t{}\t{}\n",
                        h.id, h.pc, h.len, h.offset, f.name, style
                    ));
                }
            }
            assert!(result.insert(h.pc, h).is_none());
        }
    }
    assert!(rows.next().is_none());
    assert_eq!(text(jumps, 256 * 1024), expected[0]);
    assert_eq!(text(heap, 256 * 1024), expected[1]);
    assert_eq!(result.values().filter(|h| h.heap).count(), 1);
    assert_eq!(instructions.file_name().unwrap(), "instructions.tsv");
    assert_eq!(jumps.file_name().unwrap(), "sites.tsv");
    assert_eq!(heap.file_name().unwrap(), "sites.tsv");
    assert_eq!(instructions.parent(), jumps.parent());
    assert_eq!(
        text(
            &heap.parent().unwrap().join("instructions.tsv"),
            1024 * 1024
        ),
        value
    );
    let js = status(
        jumps.parent().unwrap(),
        "jump-site",
        result.len(),
        result.values().filter(|h| h.jump).count(),
    );
    let hs = status(heap.parent().unwrap(), "heap-write", result.len(), 1);
    for i in [0, 1, 2, 3, 5, 6, 8, 9] {
        assert_eq!(
            js[i], hs[i],
            "same original/policy/target/head inventory and hook selection"
        );
    }
    for h in result.values() {
        if let Some(to) = h.target {
            assert!(result.contains_key(&to));
        }
    }
    result
}
struct Map {
    start: u64,
    end: u64,
    offset: u64,
    permissions: String,
    inode: u64,
    device: (u64, u64),
    name: String,
}
fn maps(child: &Tracee, owners: &[Owner], dir: &Path, phase: &str, all: bool) -> Vec<Map> {
    assert_eq!(
        std::fs::read_dir(format!("/proc/{}/task", child.pid))
            .unwrap()
            .count(),
        1
    );
    let exe = std::fs::read_link(format!("/proc/{}/exe", child.pid)).unwrap();
    assert_eq!(exe.as_os_str(), owners[0].path.as_os_str());
    assert_eq!(
        stat(&std::fs::metadata(format!("/proc/{}/exe", child.pid)).unwrap()),
        owners[0].identity
    );
    let mountinfo = text(
        Path::new(&format!("/proc/{}/mountinfo", child.pid)),
        1024 * 1024,
    );
    write_new(
        &dir.join(format!("{phase}.mountinfo")),
        mountinfo.as_bytes(),
    );
    let raw = text(Path::new(&format!("/proc/{}/maps", child.pid)), 128 * 1024);
    write_new(&dir.join(format!("{phase}.maps")), raw.as_bytes());
    let mut result = Vec::new();
    let mut observed = BTreeSet::new();
    let mut links = String::new();
    let mut biases = BTreeMap::<usize, u64>::new();
    for row in raw.lines() {
        let f: Vec<_> = row.split_ascii_whitespace().collect();
        assert!((5..=6).contains(&f.len()));
        let (a, b) = f[0].split_once('-').unwrap();
        let start = u64::from_str_radix(a, 16).unwrap();
        let stop = u64::from_str_radix(b, 16).unwrap();
        let (major, minor) = f[3].split_once(':').unwrap();
        let device = (
            u64::from_str_radix(major, 16).unwrap(),
            u64::from_str_radix(minor, 16).unwrap(),
        );
        let offset = u64::from_str_radix(f[2], 16).unwrap();
        let inode = num(f[4]);
        let permission = f[1];
        assert!(
            start < stop
                && start % 4096 == 0
                && stop % 4096 == 0
                && permission.len() == 4
                && permission.ends_with('p')
        );
        assert!(
            !(permission.contains('w') && permission.contains('x')),
            "no RWX mapping"
        );
        let name = f.get(5).copied().unwrap_or("");
        if inode != 0 {
            let link =
                std::fs::read_link(format!("/proc/{}/map_files/{start:x}-{stop:x}", child.pid))
                    .unwrap();
            let matches: Vec<_> = owners
                .iter()
                .enumerate()
                .filter(|(_, o)| o.path.as_os_str() == link.as_os_str())
                .collect();
            assert_eq!(matches.len(), 1, "selected runtime owner");
            let (oi, o) = matches[0];
            observed.insert(oi);
            provider::map_owner(
                &o.provider,
                &o.path,
                o.identity[1] as u64,
                device,
                inode,
                &link,
            )
            .unwrap();
            assert_eq!(
                provider::parse(&o.fdinfo, &mountinfo, inode).unwrap(),
                o.provider,
                "same held-FD mount record in child"
            );
            assert_eq!(name.as_bytes(), o.path.as_os_str().as_bytes());
            links.push_str(&format!(
                "{start:x}-{stop:x}\t{oi}\t{}\n",
                hex(link.as_os_str().as_bytes())
            ));
            let mut candidates = BTreeSet::new();
            for l in &o.loads {
                let lo = l.offset & !4095;
                let hi = page_end(end(l.offset, l.file));
                if lo <= offset && offset < hi && end(offset, stop - start) <= hi {
                    let virtual_start = (l.address & !4095) + (offset - lo);
                    if start >= virtual_start {
                        candidates.insert(start - virtual_start);
                    }
                }
            }
            if let Some(bias) = biases.get(&oi) {
                assert!(candidates.contains(bias));
            } else {
                // Offset-zero LOAD starts determine the owner, never sorted-name heuristics.
                let zero: Vec<_> = o
                    .loads
                    .iter()
                    .filter(|l| l.offset & !4095 == 0 && offset == 0)
                    .collect();
                assert_eq!(
                    zero.len(),
                    1,
                    "first file mapping must select offset-zero LOAD"
                );
                let bias = start.checked_sub(zero[0].address & !4095).unwrap();
                assert!(candidates.contains(&bias));
                if oi == 0 {
                    assert_eq!(bias, 0);
                }
                biases.insert(oi, bias);
            }
            let bias = biases[&oi];
            let permitted = o.loads.iter().any(|l| {
                let a = bias + (l.address & !4095);
                let b = bias + page_end(end(l.address, l.memory));
                a <= start
                    && stop <= b
                    && (!permission.contains('x') || l.flags & 1 != 0)
                    && (!permission.contains('w') || l.flags & 2 != 0)
            });
            assert!(permitted, "LOAD permissions and interval");
            if permission.contains('x') {
                assert!(stop - start <= 16 * 1024 * 1024);
                let mut expected = vec![0_u8; (stop - start) as usize];
                let available = (o.bytes.len() as u64)
                    .saturating_sub(offset)
                    .min(stop - start) as usize;
                expected[..available]
                    .copy_from_slice(&o.bytes[offset as usize..offset as usize + available]);
                assert_eq!(
                    child.memory(start, expected.len()),
                    expected,
                    "whole executable mapping bytes"
                );
            }
        } else {
            assert_eq!(device, (0, 0));
            assert!(matches!(
                name,
                "" | "[heap]" | "[stack]" | "[vdso]" | "[vvar]" | "[vvar_vclock]" | "[vsyscall]"
            ));
            if permission.contains('x') {
                assert!(matches!(name, "[vdso]" | "[vsyscall]"));
            }
        }
        result.push(Map {
            start,
            end: stop,
            offset,
            permissions: permission.to_owned(),
            inode,
            device,
            name: name.to_owned(),
        });
    }
    assert!(result.len() <= 512);
    assert!(observed.contains(&0));
    if all {
        assert_eq!(
            observed.len(),
            owners.len(),
            "every preselected runtime owner actually mapped"
        );
    }
    write_new(&dir.join(format!("{phase}.map-files")), links.as_bytes());
    // Entire main LOAD memory coverage, including its ordinary anonymous BSS.
    for l in &owners[0].loads {
        let mut at = l.address & !4095;
        let stop = page_end(end(l.address, l.memory));
        while at < stop {
            let found: Vec<_> = result
                .iter()
                .filter(|m| m.start <= at && at < m.end)
                .collect();
            assert_eq!(found.len(), 1);
            let m = found[0];
            assert!(m.permissions.starts_with('r'));
            // Rejoin every file-backed main LOAD page to the original owner.
            // A selected library at a coincident address cannot satisfy this join.
            let mut page = at;
            while page < m.end.min(stop) {
                if page < page_end(end(l.address, l.file)) {
                    assert_eq!(
                        m.inode, owners[0].identity[1] as u64,
                        "main LOAD original inode"
                    );
                    assert_eq!(
                        m.device, owners[0].provider.device,
                        "main LOAD original provider device"
                    );
                    assert_eq!(
                        m.name.as_bytes(),
                        owners[0].path.as_os_str().as_bytes(),
                        "main LOAD original raw path"
                    );
                    assert_eq!(
                        m.offset.checked_add(page - m.start).unwrap(),
                        (l.offset & !4095)
                            .checked_add(page - (l.address & !4095))
                            .unwrap(),
                        "main LOAD exact file offset for every page"
                    );
                }
                page = end(page, 4096);
            }
            if l.flags & 1 != 0 {
                assert_eq!(m.permissions, "r-xp");
            }
            if at >= page_end(end(l.address, l.file)) {
                assert_eq!(m.inode, 0);
                assert_eq!(m.name, "");
            }
            at = (m.end).min(stop);
        }
    }
    result
}
fn owns(maps: &[Map], start: u64, len: u64, permissions: &str) {
    let mut at = start;
    let stop = end(start, len);
    while at < stop {
        let m: Vec<_> = maps
            .iter()
            .filter(|m| m.start <= at && at < m.end)
            .collect();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].permissions, permissions);
        assert_eq!(m[0].inode, 0);
        assert_eq!(m[0].device, (0, 0));
        assert_eq!(m[0].offset, 0);
        assert_eq!(m[0].name, "");
        at = m[0].end.min(stop);
    }
}
fn zero_journal(active: u64) -> Vec<u8> {
    let mut result = vec![0_u8; JOURNAL_BYTES];
    for (i, v) in [
        (0, 0x6c69_326a_6f75_726e),
        (1, 1),
        (2, 16384),
        (3, active),
        (16392, 0x7265_636f_7264_7321),
    ] {
        result[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    result
}
fn boundary(
    child: &Tracee,
    l: &Layout,
    owners: &[Owner],
    dataset: &data::Dataset,
    dir: &Path,
    phase: &str,
    sorted: bool,
) -> [u64; 11] {
    let mappings = maps(child, owners, dir, phase, true);
    let bytes = child.memory(l.run, 88);
    write_new(&dir.join(format!("{phase}.run")), &bytes);
    let r: Vec<_> = bytes
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let r: [u64; 11] = r.try_into().unwrap();
    assert_eq!(
        (r[0], r[10]),
        (0x7261_6e67_652d_6c6f, 0x7261_6e67_652d_6869)
    );
    assert_eq!(
        (r[2], r[4], r[7], r[8], r[9]),
        (12288, 4096, dataset.input.len() as u64, dataset.id, 1)
    );
    assert_eq!(r[1] % 4096, 0);
    assert_eq!(r[3], end(r[1], 4096));
    assert_eq!(r[5], end(r[3], 64));
    assert_eq!(r[6], end(r[5], r[7] * 8));
    owns(&mappings, r[1], 4096, "---p");
    owns(&mappings, r[3], 4096, "rw-p");
    owns(&mappings, end(r[3], 4096), 4096, "---p");
    let actual = child.memory(r[3], 4096);
    write_new(&dir.join(format!("{phase}.middle")), &actual);
    let mut expected = vec![0xa5; 4096];
    let values = if sorted {
        dataset.expected
    } else {
        dataset.input
    };
    expected[64..64 + values.len() * 8].copy_from_slice(&words(values));
    assert_eq!(actual, expected, "entire guarded middle page");
    let journal = child.memory(l.journal, JOURNAL_BYTES);
    write_new(&dir.join(format!("{phase}.journal")), &journal);
    assert_eq!(
        journal,
        zero_journal(1),
        "original journal before close is active with zero visits"
    );
    let regs = child.registers();
    let stack: Vec<_> = mappings
        .iter()
        .filter(|m| {
            m.name == "[stack]"
                && m.permissions == "rw-p"
                && m.start <= regs.rsp
                && end(regs.rsp, 8) <= m.end
        })
        .collect();
    assert_eq!(stack.len(), 1);
    r
}
struct Events {
    file: File,
    pcs: File,
    count: usize,
    steps: usize,
    limit: usize,
}
impl Events {
    fn wait(&mut self, child: &Tracee, request: u32) -> (i32, Option<libc::user_regs_struct>, i32) {
        assert!(Instant::now() < child.deadline, "application wall deadline");
        let status = child.wait();
        let mut code = 0;
        let mut rip = 0;
        let mut registers = None;
        let mut message = 0_u64;
        if libc::WIFSTOPPED(status) {
            let r = child.registers();
            rip = r.rip;
            registers = Some(r);
            if status >> 16 == 0 {
                // SAFETY: initialized output for the exact stopped tracee.
                let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
                child.request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
                code = info.si_code;
            }
        }
        if libc::WIFSTOPPED(status) && status >> 16 != 0 {
            child.request(libc::PTRACE_GETEVENTMSG, 0, (&raw mut message) as usize);
        }
        self.file.write_all(&request.to_le_bytes()).unwrap();
        self.file.write_all(&status.to_le_bytes()).unwrap();
        self.file.write_all(&rip.to_le_bytes()).unwrap();
        self.file
            .write_all(&(self.steps as u64).to_le_bytes())
            .unwrap();
        self.file.write_all(&code.to_le_bytes()).unwrap();
        self.file.write_all(&0_u32.to_le_bytes()).unwrap();
        self.file.write_all(&message.to_le_bytes()).unwrap();
        self.count += 1;
        assert!(self.count <= self.limit + 8);
        assert!(Instant::now() < child.deadline, "application wall deadline");
        (status, registers, code)
    }
    fn step(&mut self, child: &Tracee) -> libc::user_regs_struct {
        assert!(self.steps < self.limit, "derived application stop budget");
        self.pcs
            .write_all(&child.registers().rip.to_le_bytes())
            .unwrap();
        self.steps += 1;
        child.request(libc::PTRACE_SINGLESTEP, 0, 0);
        let (status, r, code) = self.wait(child, libc::PTRACE_SINGLESTEP);
        assert!(
            libc::WIFSTOPPED(status)
                && libc::WSTOPSIG(status) == libc::SIGTRAP
                && status >> 16 == 0
        );
        assert_eq!(code, libc::TRAP_TRACE);
        r.unwrap()
    }
}
fn create(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}
fn exec(image: &Owner, dataset: &data::Dataset, dir: &Path, events: &mut Events) -> Tracee {
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    // SAFETY: scalar process/thread identifiers.
    assert_eq!(
        unsafe { libc::getpid() },
        unsafe { libc::syscall(libc::SYS_gettid) } as i32
    );
    let stdout = create(&dir.join("stdout"));
    let stderr = create(&dir.join("stderr"));
    let arguments = [
        CString::new(image.path.as_os_str().as_bytes()).unwrap(),
        CString::new(dataset.name).unwrap(),
        CString::new(dir.join("journal.bin").as_os_str().as_bytes()).unwrap(),
    ];
    let argv = [
        arguments[0].as_ptr(),
        arguments[1].as_ptr(),
        arguments[2].as_ptr(),
        core::ptr::null(),
    ];
    let environment = [
        CString::new("LANG=C").unwrap(),
        CString::new("LC_ALL=C").unwrap(),
        CString::new("PATH=/usr/bin:/bin").unwrap(),
    ];
    let env = [
        environment[0].as_ptr(),
        environment[1].as_ptr(),
        environment[2].as_ptr(),
        core::ptr::null(),
    ];
    // SAFETY: single-threaded parent; child uses only async-signal-safe libc calls and never unwinds.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            if libc::dup2(stdout.as_raw_fd(), 1) != 1
                || libc::dup2(stderr.as_raw_fd(), 2) != 2
                || libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize) == -1
            {
                libc::_exit(120);
            }
            libc::fexecve(image.file.as_raw_fd(), argv.as_ptr(), env.as_ptr());
            libc::_exit(121);
        }
    }
    let child = Tracee {
        pid,
        deadline: Instant::now() + Duration::from_secs(APP_SECONDS),
        reaped: Cell::new(false),
    };
    let (status, _, _) = events.wait(&child, 0);
    assert!(
        libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP && status >> 16 == 0,
        "kernel exec trap"
    );
    child.request(
        libc::PTRACE_SETOPTIONS,
        0,
        (libc::PTRACE_O_EXITKILL
            | libc::PTRACE_O_TRACEEXIT
            | libc::PTRACE_O_TRACEEXEC
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACECLONE) as usize,
    );
    child
}
fn marker_call(image: &Owner, child: &Tracee, pc: u64, main: &Function) -> u64 {
    let r = child.registers();
    assert_eq!(r.rip, pc);
    let ret = word(&child.memory(r.rsp, 8), 0);
    assert!(main.pc <= ret.checked_sub(5).unwrap() && ret <= end(main.pc, main.len as u64));
    let call = image.slice(ret - 5, 5, 5).1;
    assert_eq!(call[0], 0xe8);
    assert_eq!(
        i128::from(ret) + i128::from(i32::from_le_bytes(call[1..].try_into().unwrap())),
        i128::from(pc)
    );
    ret
}
#[derive(Clone)]
struct Frame {
    function: usize,
    rsp: u64,
    ret: u64,
    call: u64,
}
fn observe(
    owners: &[Owner],
    l: &Layout,
    heads: &BTreeMap<u64, Head>,
    dataset: &data::Dataset,
    dir: &Path,
) {
    let n = dataset.input.len();
    assert!(n <= 64);
    let calls = if n < 2 { 0 } else { n / 2 + n - 1 };
    let levels = if n < 2 {
        0
    } else {
        (usize::BITS - 1 - n.leading_zeros()) as usize
    };
    let iterations = calls.checked_mul(levels).unwrap();
    let stores = if n < 2 { 0 } else { 2 * (iterations + n - 1) };
    let bounds = [
        stores,
        iterations + calls,
        if n < 2 { 1 } else { n / 2 + n },
    ];
    let limit = heads
        .values()
        .map(|h| bounds[h.function])
        .sum::<usize>()
        .checked_add(BRIDGE_STEPS)
        .unwrap();
    assert!(limit <= HARD_STEPS);
    write_new(&dir.join("budget.tsv"),format!("n\t{n}\nsift_calls\t{calls}\nsift_iterations\t{iterations}\nstore_calls\t{stores}\nper_head\t{}\t{}\t{}\nderived_steps\t{limit}\nhard_steps\t{HARD_STEPS}\nwall_seconds\t{APP_SECONDS}\nbridge_steps\t{BRIDGE_STEPS}\n",bounds[0],bounds[1],bounds[2]).as_bytes());
    let mut events = Events {
        file: create(&dir.join("events.bin")),
        pcs: create(&dir.join("all-pcs.bin")),
        count: 0,
        steps: 0,
        limit,
    };
    let child = exec(&owners[0], dataset, dir, &mut events);
    maps(&child, owners, dir, "exec", false);
    // The only intervention: replace one original RET byte with INT3, then undo it.
    let aligned = l.before & !7;
    let offset = (l.before - aligned) as usize;
    let original = child.memory(aligned, 8);
    assert_eq!(original, owners[0].slice(aligned, 8, 5).1);
    assert_eq!(original[offset], 0xc3);
    let mut trap = original.clone();
    trap[offset] = 0xcc;
    write_new(&dir.join("breakpoint.original"), &original);
    write_new(&dir.join("breakpoint.installed"), &trap);
    child.request(
        libc::PTRACE_POKETEXT,
        aligned as usize,
        word(&trap, 0) as usize,
    );
    assert_eq!(child.memory(aligned, 8), trap);
    child.request(libc::PTRACE_CONT, 0, 0);
    let (status, r, code) = events.wait(&child, libc::PTRACE_CONT);
    assert!(
        libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP && status >> 16 == 0
    );
    assert!(matches!(code, libc::TRAP_BRKPT | libc::SI_KERNEL));
    let trapped = r.unwrap();
    assert_eq!(trapped.rip, end(l.before, 1));
    let xstate = child.xstate();
    write_new(
        &dir.join("breakpoint.trapped.regs"),
        &words(&regs(&trapped)),
    );
    write_new(&dir.join("breakpoint.trapped.xstate"), &xstate);
    child.request(
        libc::PTRACE_POKETEXT,
        aligned as usize,
        word(&original, 0) as usize,
    );
    assert_eq!(child.memory(aligned, 8), original);
    let mut restored = trapped;
    restored.rip = l.before;
    child.set_registers(&restored);
    let actual = child.registers();
    assert_eq!(regs(&actual), regs(&restored));
    assert_eq!(child.xstate(), xstate);
    let mut expected = regs(&trapped);
    expected[16] = l.before;
    assert_eq!(regs(&actual), expected);
    write_new(
        &dir.join("breakpoint.restored.regs"),
        &words(&regs(&actual)),
    );
    write_new(&dir.join("breakpoint.restored.xstate"), &child.xstate());
    let before_return = marker_call(&owners[0], &child, l.before, &l.main);
    let run = boundary(&child, l, owners, dataset, dir, "before", false);
    let saved_maps = text(&dir.join("before.maps"), 128 * 1024);
    let stack_rows: Vec<_> = saved_maps
        .lines()
        .filter(|row| row.split_ascii_whitespace().last() == Some("[stack]"))
        .collect();
    assert_eq!(stack_rows.len(), 1);
    let (stack_a, stack_b) = stack_rows[0]
        .split_ascii_whitespace()
        .next()
        .unwrap()
        .split_once('-')
        .unwrap();
    let stack_start = u64::from_str_radix(stack_a, 16).unwrap();
    let stack_end = u64::from_str_radix(stack_b, 16).unwrap();
    let mut current = events.step(&child);
    assert_eq!(current.rip, before_return);
    assert_eq!(current.rsp, end(actual.rsp, 8));
    let main: BTreeMap<_, _> = decoded(&owners[0], &l.main, 3)
        .into_iter()
        .map(|h| (h.pc, h))
        .collect();
    let mut frames = Vec::<Frame>::new();
    let mut visits = BTreeMap::<u64, usize>::new();
    let mut bridge = 1;
    let mut heap_calls = 0;
    let mut store_calls = 0;
    let mut jumps = create(&dir.join("jump-pcs.bin"));
    let mut writes = create(&dir.join("heap-pcs.bin"));
    let mut calls_file = create(&dir.join("calls.tsv"));
    let mut stores_file = create(&dir.join("stores.tsv"));
    calls_file
        .write_all(b"step\tcall_pc\tcallee\treturn_pc\tcallee_rsp\n")
        .unwrap();
    stores_file
        .write_all(b"step\tcall_pc\tstore_pc\tbase\tindex\tvalue\tea\told\tnew\n")
        .unwrap();
    loop {
        assert!(
            stack_start <= current.rsp.checked_sub(128).unwrap()
                && end(current.rsp, 8) <= stack_end,
            "owned application stack/redzone"
        );
        if current.rip == l.after {
            assert!(frames.is_empty() && heap_calls == 1);
            break;
        }
        let h = if let Some(h) = heads.get(&current.rip) {
            let frame = frames.last().expect("kernel requires observed direct CALL");
            assert_eq!(frame.function, h.function);
            assert_eq!(
                i128::from(current.rsp),
                i128::from(frame.rsp)
                    + i128::from(
                        h.depth
                            .expect("executed head requires a static RSP-depth proof")
                    ),
                "observed RSP equals complete static frame proof"
            );
            let count = visits.entry(h.pc).or_default();
            *count += 1;
            assert!(
                *count <= bounds[h.function],
                "per-head algorithmic visit bound"
            );
            h
        } else {
            assert!(frames.is_empty());
            bridge += 1;
            assert!(bridge <= BRIDGE_STEPS);
            main.get(&current.rip)
                .expect("only the finite main bridge outside kernel")
        };
        assert_eq!(
            child.memory(h.pc, h.len),
            h.bytes,
            "no rewritten or self-modified kernel/bridge"
        );
        if h.function < 3 && h.jump {
            jumps.write_all(&h.pc.to_le_bytes()).unwrap();
        }
        if h.heap {
            writes.write_all(&h.pc.to_le_bytes()).unwrap();
        }
        let before = current;
        let pending_store = if h.heap {
            let frame = frames.last().unwrap();
            assert_eq!(before.rdi, run[5]);
            assert!(before.rsi < run[7]);
            let ea = end(before.rdi, before.rsi.checked_mul(8).unwrap());
            assert!(run[5] <= ea && end(ea, 8) <= run[6]);
            store_calls += 1;
            assert!(store_calls <= stores);
            Some((ea, word(&child.memory(ea, 8), 0), frame.call))
        } else {
            None
        };
        let ret = if h.flow == "Return" {
            Some(word(&child.memory(before.rsp, 8), 0))
        } else {
            None
        };
        if h.flow == "Call" {
            let to = h.target.unwrap();
            if let Some(fi) = l.functions.iter().position(|f| f.pc == to) {
                assert!(!frames.iter().any(|f| f.function == fi));
                if frames.is_empty() {
                    assert_eq!(fi, 2);
                    heap_calls += 1;
                    assert_eq!(heap_calls, 1);
                }
                assert_eq!(before.rdi, run[5]);
                if fi == 2 {
                    assert_eq!(before.rsi, run[7]);
                }
                if fi == 1 {
                    assert!(before.rsi <= run[7] && before.rdx < before.rsi);
                }
                let frame = Frame {
                    function: fi,
                    rsp: before.rsp.checked_sub(8).unwrap(),
                    ret: end(h.pc, h.len as u64),
                    call: h.pc,
                };
                writeln!(
                    calls_file,
                    "{}\t0x{:x}\t0x{:x}\t0x{:x}\t0x{:x}",
                    events.steps, h.pc, to, frame.ret, frame.rsp
                )
                .unwrap();
                frames.push(frame);
                assert!(frames.len() <= 3);
            } else {
                assert!(
                    frames.is_empty() && heap_calls == 1 && to == l.after,
                    "no foreign kernel/bridge call"
                );
            }
        }
        current = events.step(&child);
        match h.flow.as_str() {
            "Next" => assert_eq!(current.rip, end(h.pc, h.len as u64)),
            "Call" => {
                assert_eq!(current.rip, h.target.unwrap());
                assert_eq!(current.rsp, before.rsp - 8);
                assert_eq!(
                    word(&child.memory(current.rsp, 8), 0),
                    end(h.pc, h.len as u64)
                );
            }
            "Return" => {
                let frame = frames.pop().expect("owned kernel return");
                assert_eq!(before.rsp, frame.rsp);
                assert_eq!(ret, Some(frame.ret));
                assert_eq!(current.rip, frame.ret);
                assert_eq!(current.rsp, end(frame.rsp, 8));
            }
            "ConditionalBranch" => {
                assert!(current.rip == h.target.unwrap() || current.rip == end(h.pc, h.len as u64))
            }
            "UnconditionalBranch" => assert_eq!(current.rip, h.target.unwrap()),
            _ => panic!("unsupported observed control flow"),
        }
        if let Some((ea, old, call)) = pending_store {
            let value = word(&child.memory(ea, 8), 0);
            assert_eq!(value, before.rdx);
            writeln!(
                stores_file,
                "{}\t0x{call:x}\t0x{:x}\t0x{:x}\t{}\t{}\t0x{ea:x}\t{old}\t{value}",
                events.steps - 1,
                h.pc,
                before.rdi,
                before.rsi,
                before.rdx
            )
            .unwrap();
        }
    }
    let after_return = marker_call(&owners[0], &child, l.after, &l.main);
    assert_eq!(
        boundary(&child, l, owners, dataset, dir, "after", true),
        run
    );
    write_new(
        &dir.join("markers.tsv"),
        format!(
            "before\t0x{:x}\t0x{before_return:x}\nafter\t0x{:x}\t0x{after_return:x}\n",
            l.before, l.after
        )
        .as_bytes(),
    );
    // No seed, mapper, register repair, signal suppression or hook after the initial undo.
    child.request(libc::PTRACE_CONT, 0, 0);
    let (status, _, _) = events.wait(&child, libc::PTRACE_CONT);
    assert!(
        libc::WIFSTOPPED(status)
            && libc::WSTOPSIG(status) == libc::SIGTRAP
            && status >> 16 == libc::PTRACE_EVENT_EXIT
    );
    let mut message = 0_u64;
    child.request(libc::PTRACE_GETEVENTMSG, 0, (&raw mut message) as usize);
    assert_eq!(message, 0);
    child.request(libc::PTRACE_CONT, 0, 0);
    let (status, _, _) = events.wait(&child, libc::PTRACE_CONT);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert_eq!(read(&dir.join("stdout"), 16384), dataset.stdout.as_bytes());
    assert_eq!(std::fs::metadata(dir.join("stderr")).unwrap().len(), 0);
    assert_eq!(
        read(&dir.join("journal.bin"), JOURNAL_BYTES),
        zero_journal(0)
    );
    let mut coverage = String::from("id\tpc\tjump_site\theap_write\tvisits\n");
    for h in heads.values() {
        coverage.push_str(&format!(
            "{}\t0x{:x}\t{}\t{}\t{}\n",
            h.id,
            h.pc,
            h.jump,
            h.heap,
            visits.get(&h.pc).copied().unwrap_or(0)
        ));
    }
    write_new(&dir.join("coverage.tsv"), coverage.as_bytes());
    for owner in owners {
        owner.stable();
    }
    write_new(&dir.join("observations.tsv"),format!("status\tpassed\ndataset\t{}\nstatic_heads\t{}\nstatic_jump_sites\t{}\nstatic_heap_sites\t1\nsteps\t{}\nevents\t{}\nheap_calls\t1\nstore_calls\t{store_calls}\noriginal_only\ttrue\nfull_architectural_equivalence\tfalse\n",dataset.name,heads.len(),heads.values().filter(|h|h.jump).count(),events.steps,events.count).as_bytes());
}

pub fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        10,
        "observe-common-app ORIGINAL LAYOUT INSTRUCTIONS JUMP_SITES HEAP_SITES RUNTIME_OWNERS DATASET NEW_DIRECTORY"
    );
    let input_paths: Vec<_> = args[2..8].iter().map(PathBuf::from).collect();
    for path in &input_paths {
        assert!(path.is_absolute() && path.canonicalize().unwrap().as_os_str() == path.as_os_str());
    }
    let mut consumed: Vec<(PathBuf, Vec<u8>)> = input_paths
        .iter()
        .skip(1)
        .map(|p| (p.clone(), read(p, 1024 * 1024)))
        .collect();
    for directory in [
        input_paths[3].parent().unwrap(),
        input_paths[4].parent().unwrap(),
    ] {
        for name in [
            "instructions.tsv",
            "status.tsv",
            "selection.txt",
            "COMPLETE",
        ] {
            let path = directory.join(name);
            assert_eq!(path.canonicalize().unwrap().as_os_str(), path.as_os_str());
            consumed.push((path.clone(), read(&path, 1024 * 1024)));
        }
    }
    let dataset = data::DATASETS
        .iter()
        .find(|d| Some(d.name) == args[8].to_str())
        .expect("one of eight fixed datasets");
    let owners_text = text(&input_paths[5], 65536);
    let mut lines = owners_text.lines();
    assert_eq!(lines.next(), Some("LI2COMMONOWNERS\t1"));
    let mut owners = Vec::new();
    for line in lines {
        assert!(!line.is_empty() && !line.contains('\t') && !line.contains(' '));
        owners.push(Owner::open(Path::new(line)));
    }
    assert!((2..=16).contains(&owners.len()));
    assert_eq!(owners[0].path.as_os_str(), input_paths[0].as_os_str());
    assert_eq!(owners[0].kind, 2);
    assert!(owners.iter().enumerate().all(|(i, o)| {
        owners[..i]
            .iter()
            .all(|p| p.path != o.path && p.identity[..2] != o.identity[..2])
    }));
    assert!(
        owners
            .iter()
            .skip(1)
            .any(|o| Some(&o.path) == owners[0].interpreter.as_ref())
    );
    let l = layout(&input_paths[1], &owners[0]);
    let heads = inventory(
        &owners[0],
        &l,
        &input_paths[2],
        &input_paths[3],
        &input_paths[4],
    );
    let output = PathBuf::from(&args[9]);
    assert!(
        output.is_absolute()
            && output.parent().unwrap().canonicalize().unwrap().as_os_str()
                == output.parent().unwrap().as_os_str()
    );
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&output)
        .unwrap();
    for (i, path) in input_paths.iter().enumerate().skip(1) {
        write_new(
            &output.join(format!("input-{i}.txt")),
            &read(path, 1024 * 1024),
        );
    }
    for (i, owner) in owners.iter().enumerate() {
        write_new(
            &output.join(format!("owner-{i}.txt")),
            format!(
                "path_hex\t{}\nstat\t{:?}\nfdinfo_bytes\t{}\n{}mount_record_bytes\t{}\n{}",
                hex(owner.path.as_os_str().as_bytes()),
                owner.identity,
                owner.fdinfo.len(),
                owner.fdinfo,
                owner.provider.mount_record.len(),
                owner.provider.mount_record
            )
            .as_bytes(),
        );
    }
    for (i, (_, bytes)) in consumed.iter().enumerate() {
        write_new(&output.join(format!("consumed-{i}.bin")), bytes);
    }
    observe(&owners, &l, &heads, dataset, &output);
    for (path, bytes) in consumed {
        assert_eq!(
            read(&path, 1024 * 1024),
            bytes,
            "unchanged consumed inventory/layout/owner records"
        );
    }
    write_new(&output.join("inputs-unchanged"), b"complete\n");
    write_new(
        &output.join("complete.tsv"),
        &read(&output.join("observations.tsv"), 16384),
    );
    println!(
        "PASS original common-app dataset={} complete static inventory and ordered jump/store observations",
        dataset.name
    );
}
