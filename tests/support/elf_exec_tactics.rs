//! Additive finite B2/T1/T2/T3 normal-kernel-exec oracle.
//! B1 keeps its own exact parser, startup, seed and capture contract unchanged.
//! COMPLETE/index/SHA-256 authentication remains the recipe/verifier boundary.
//! This adapter authenticates every consumed LOAD/image/source/fixup byte and
//! runs the unchanged full-state comparator after one observed before-CALL seed.
use super::*;
use std::collections::BTreeMap;
use std::ops::Deref;

#[path = "elf_exec_tactics_contract.rs"]
mod contract;

const SUBJECT: u64 = 0x421100;
const CARRIER: u64 = 0x422000;
const ORIGINAL_LOADS: &[(u64, u64, u32)] = &[
    (0x400000, 4096, 4),
    (0x401000, 4096, 5),
    (DATA, 4096, 6),
    (JOURNAL, 4096, 6),
    (STACK, 65536, 6),
    (0x421000, 4096, 5),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    B2,
    T1,
    T2,
    T3,
}
impl Family {
    fn parse(name: &std::ffi::OsStr) -> Self {
        match name.to_str().unwrap() {
            "B2" => Self::B2,
            "T1" => Self::T1,
            "T2" => Self::T2,
            "T3" => Self::T3,
            _ => panic!("only the four fixed additive tactic families"),
        }
    }
    fn heads(self) -> &'static [u64] {
        match self {
            Self::B2 => &[0, 3, 8],
            Self::T1 => &[0, 2, 7],
            Self::T2 => &[0, 3, 11, 16, 64, 74],
            Self::T3 => &[0, 2, 3, 64, 74],
        }
    }
    fn body(self) -> Vec<u8> {
        let mut b = match self {
            Self::B2 => hex_bytes("0f1f00b82a000000c3"),
            Self::T1 => hex_bytes("89c0b82a000000c3"),
            Self::T2 => hex_bytes("0f1f000f1f840000000000b82a000000c3"),
            Self::T3 => hex_bytes("750190c3"),
        };
        if self.images() == 2 {
            b.resize(64, 0x90);
            b.extend_from_slice(&hex_bytes("48b82a00000000000000c3"));
        }
        b
    }
    fn selected(self) -> u64 {
        match self {
            Self::B2 => 0x2afa9105,
            Self::T1 => 0x423bbe,
            Self::T2 => 0x572b9105,
            Self::T3 => 0x4421100,
        }
    }
    fn victim(self) -> Option<(u64, u64)> {
        match self {
            Self::T2 => Some((SUBJECT + 3, 0x54455e)),
            Self::T3 => Some((SUBJECT + 64, 0x6421100)),
            _ => None,
        }
    }
    fn images(self) -> usize {
        if matches!(self, Self::T2 | Self::T3) {
            2
        } else {
            1
        }
    }
    fn load_permitted(self, address: u64, len: u64, flags: u32, candidate: bool) -> bool {
        ORIGINAL_LOADS.contains(&(address, len, flags))
            || (candidate
                && ((address == CARRIER && len <= 4096 && flags == 4)
                    || (flags == 5
                        && len <= 8192
                        && (address == (self.selected() & !4095)
                            || self.victim().is_some_and(|(_, v)| address == (v & !4095))))))
    }
    fn path(self, head: usize, seed: u64) -> Vec<u64> {
        let offset = self.heads()[head];
        let mut offsets: Vec<u64> = if offset >= 64 {
            if offset == 64 { vec![64, 74] } else { vec![74] }
        } else if self == Self::T3 && offset == 0 && seed & 1 == 0 {
            vec![0, 3]
        } else {
            self.heads()
                .iter()
                .copied()
                .filter(|h| *h >= offset && *h < 64)
                .collect()
        };
        for p in &mut offsets {
            *p += SUBJECT;
        }
        offsets.push(call_pc(head) + 5);
        offsets
    }
    fn comparisons(self) -> usize {
        match self {
            Self::B2 | Self::T1 => 120,
            Self::T2 => 248,
            Self::T3 => 188,
        }
    }
}
fn hex_bytes(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit()));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn call_pc(head: usize) -> u64 {
    0x401400 + 16 * head as u64
}

struct TacticExecutable(Executable);
impl Deref for TacticExecutable {
    type Target = Executable;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl TacticExecutable {
    fn copy(family: Family, input: &Path, output: &Path, candidate: bool) -> Self {
        let input = input.canonicalize().unwrap();
        let mut source = File::open(&input).unwrap();
        let before = source.metadata().unwrap();
        assert!(before.is_file() && before.len() <= 1024 * 1024);
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes).unwrap();
        let after = source.metadata().unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.mode(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.dev(),
                after.ino(),
                after.mode(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        let path_owner = std::fs::metadata(&input).unwrap();
        assert_eq!(
            (path_owner.dev(), path_owner.ino()),
            (before.dev(), before.ino())
        );
        assert_eq!(bytes.len() as u64, before.len());
        let mut producer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(output)
            .unwrap();
        producer.write_all(&bytes).unwrap();
        drop(producer);
        let file = File::open(output).unwrap();
        let stat = file.metadata().unwrap();
        assert_eq!(stat.mode() & 0o777, 0o500);
        let mut readback = Vec::new();
        (&file).read_to_end(&mut readback).unwrap();
        assert_eq!(readback, bytes);
        assert!(bytes.len() >= 64);
        assert_eq!(&bytes[..7], b"\x7fELF\x02\x01\x01");
        assert_eq!(u16_at(&bytes, 16), 2, "ET_EXEC only");
        assert_eq!(u16_at(&bytes, 18), 62);
        assert_eq!(word(&bytes, 24), ENTRY);
        assert_eq!(u16_at(&bytes, 52), 64);
        assert_eq!(u16_at(&bytes, 54), 56);
        let phoff = word(&bytes, 32);
        let phnum = u16_at(&bytes, 56);
        assert_eq!(
            usize::from(phnum),
            if candidate { 9 + family.images() } else { 8 }
        );
        assert!(phoff.checked_add(u64::from(phnum) * 56).unwrap() <= bytes.len() as u64);
        let mut loads = Vec::new();
        let mut phdr = Vec::new();
        let mut stack_policy = 0;
        for index in 0..phnum {
            let p = usize::try_from(phoff + u64::from(index) * 56).unwrap();
            let kind = u32_at(&bytes, p);
            let flags = u32_at(&bytes, p + 4);
            let offset = word(&bytes, p + 8);
            let address = word(&bytes, p + 16);
            let len = word(&bytes, p + 32);
            let memory = word(&bytes, p + 40);
            match kind {
                1 => {
                    assert!(matches!(flags, 4..=6));
                    assert!(len > 0 && len == memory, "no anonymous BSS fixture pages");
                    assert_eq!(address % 4096, 0);
                    assert_eq!(offset % 4096, 0);
                    assert_eq!(word(&bytes, p + 48), 4096);
                    assert!(offset.checked_add(len).unwrap() <= bytes.len() as u64);
                    assert!(family.load_permitted(address, len, flags, candidate));
                    loads.push(Load {
                        offset,
                        address,
                        len,
                        flags,
                    });
                }
                6 => {
                    assert_eq!(flags, 4);
                    assert_eq!(offset, phoff);
                    assert_eq!(len, u64::from(phnum) * 56);
                    assert_eq!(memory, len);
                    phdr.push((address, len));
                }
                0x6474_e551 => {
                    assert_eq!(flags, 6);
                    stack_policy += 1;
                }
                _ => panic!(
                    "unexpected PHDR {kind:#x}: no interpreter, dynamic loader or alternate provider"
                ),
            }
        }
        assert_eq!(phdr.len(), 1);
        assert_eq!(stack_policy, 1);
        loads.sort_by_key(|l| l.address);
        assert_eq!(loads.len(), if candidate { 7 + family.images() } else { 6 });
        for &(address, len, flags) in ORIGINAL_LOADS {
            assert_eq!(
                loads
                    .iter()
                    .filter(|l| (l.address, l.len, l.flags) == (address, len, flags))
                    .count(),
                1
            );
        }
        for pair in loads.windows(2) {
            assert!(page_end(pair[0].address + pair[0].len) <= pair[1].address);
        }
        let owner = loads
            .iter()
            .filter(|l| {
                l.flags == 4
                    && phdr[0].0 >= l.address
                    && phdr[0].0 + phdr[0].1 <= l.address + l.len
                    && l.offset + phdr[0].0 - l.address == phoff
            })
            .count();
        assert_eq!(
            owner, 1,
            "PHDR table must have one actual R-only LOAD owner"
        );
        let (fdinfo, provider) = observe_provider(&file);
        let mut record = format!(
            "elf-exec-provider-v1\nstat_dev\t{}\nstat_inode\t{}\nstat_bytes\t{}\nfdinfo_bytes\t{}\n",
            stat.dev(), stat.ino(), stat.len(), fdinfo.len()
        ).into_bytes();
        record.extend_from_slice(fdinfo.as_bytes());
        record.extend_from_slice(
            format!("mount_record_bytes\t{}\n", provider.mount_record.len()).as_bytes(),
        );
        record.extend_from_slice(provider.mount_record.as_bytes());
        write_new(&output.with_extension("provider"), &record);
        Self(Executable {
            file,
            path: output.canonicalize().unwrap(),
            bytes,
            loads,
            phoff,
            phnum,
            dev: stat.dev(),
            inode: stat.ino(),
            provider,
        })
    }
    fn maps(&self, child: &Tracee, capture: &Path, phase: &str) {
        self.unchanged();
        let executable = std::fs::metadata(format!("/proc/{}/exe", child.pid)).unwrap();
        assert_eq!(
            (executable.dev(), executable.ino(), executable.len()),
            (self.dev, self.inode, self.bytes.len() as u64)
        );
        let text = std::fs::read_to_string(format!("/proc/{}/maps", child.pid)).unwrap();
        assert!(text.len() <= 65536);
        write_new(&capture.join(format!("{phase}.maps")), text.as_bytes());
        let (fdinfo, observed) = observe_provider(&self.file);
        assert_eq!(observed, self.provider);
        let child_mountinfo =
            std::fs::read_to_string(format!("/proc/{}/mountinfo", child.pid)).unwrap();
        assert_eq!(
            provider::parse(&fdinfo, &child_mountinfo, self.inode).unwrap(),
            self.provider
        );
        let mut witnesses = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(capture.join(format!("{phase}.map-files")))
            .unwrap();
        witnesses.write_all(b"elf-exec-map-files-v1\n").unwrap();
        let mut maps = Vec::new();
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert!(fields.len() >= 5);
            let (start, end) = fields[0].split_once('-').unwrap();
            let start = u64::from_str_radix(start, 16).unwrap();
            let end = u64::from_str_radix(end, 16).unwrap();
            assert!(start < end);
            let offset = u64::from_str_radix(fields[2], 16).unwrap();
            let (major, minor) = fields[3].split_once(':').unwrap();
            let device = (
                u64::from_str_radix(major, 16).unwrap(),
                u64::from_str_radix(minor, 16).unwrap(),
            );
            let inode = number(fields[4]);
            if inode != 0 {
                let path =
                    std::fs::read_link(format!("/proc/{}/map_files/{start:x}-{end:x}", child.pid))
                        .unwrap();
                let path_bytes = path.as_os_str().as_bytes();
                witnesses
                    .write_all(format!("{}\t{}\n", fields[0], path_bytes.len()).as_bytes())
                    .unwrap();
                witnesses.write_all(path_bytes).unwrap();
                witnesses.write_all(b"\n").unwrap();
                assert_eq!(inode, self.inode, "no other file-backed provider");
                assert_eq!(device, self.provider.device);
                provider::map_owner(&self.provider, &self.path, self.inode, device, inode, &path)
                    .unwrap();
            }
            assert!(
                end <= GUARD || start >= STACK,
                "owned lower stack guard must be unmapped"
            );
            maps.push((start, end, fields[1].to_string(), offset, device, inode));
        }
        for pair in maps.windows(2) {
            assert!(pair[0].1 <= pair[1].0);
        }
        let mut pages = 0;
        for load in &self.loads {
            for address in (load.address..page_end(load.address + load.len)).step_by(PAGE) {
                let owners: Vec<_> = maps
                    .iter()
                    .filter(|m| m.0 <= address && address + 4096 <= m.1)
                    .collect();
                assert_eq!(owners.len(), 1);
                let row = owners[0];
                assert_eq!(row.5, self.inode);
                assert_eq!(row.4, self.provider.device);
                assert_eq!(
                    row.3 + address - row.0,
                    load.offset + address - load.address
                );
                assert_eq!(
                    row.2,
                    match load.flags {
                        4 => "r--p",
                        5 => "r-xp",
                        6 => "rw-p",
                        _ => unreachable!(),
                    }
                );
                pages += 1;
            }
        }
        assert!(pages <= 26);
        let auxv = std::fs::read(format!("/proc/{}/auxv", child.pid)).unwrap();
        assert!(auxv.len() <= 8192 && auxv.len() % 16 == 0);
        let mut pairs = Vec::new();
        for pair in auxv.chunks_exact(16) {
            pairs.push((word(pair, 0), word(pair, 8)));
        }
        let actual_aux = |key| {
            let rows: Vec<_> = pairs.iter().filter(|p| p.0 == key).collect();
            assert_eq!(rows.len(), 1);
            rows[0].1
        };
        let phdr_owner: Vec<_> = self
            .loads
            .iter()
            .filter(|l| {
                l.offset <= self.phoff
                    && self.phoff + u64::from(self.phnum) * 56 <= l.offset + l.len
            })
            .collect();
        assert_eq!(phdr_owner.len(), 1);
        assert_eq!(
            actual_aux(libc::AT_PHDR),
            phdr_owner[0].address + self.phoff - phdr_owner[0].offset
        );
        assert_eq!(actual_aux(libc::AT_PHENT), 56);
        assert_eq!(actual_aux(libc::AT_PHNUM), u64::from(self.phnum));
        assert_eq!(actual_aux(libc::AT_ENTRY), ENTRY);
        assert_eq!(
            actual_aux(libc::AT_BASE),
            0,
            "freestanding kernel load, no interpreter"
        );
        write_new(&capture.join(format!("{phase}.auxv")), &auxv);
        self.unchanged();
    }
    fn original(&self, family: Family, stripped: bool) {
        assert_eq!(self.phnum, 8);
        assert_eq!(self.loads.len(), 6);
        let shoff = word(&self.bytes, 40) as usize;
        let shnum = usize::from(u16_at(&self.bytes, 60));
        assert!(shnum > 0 && shnum <= 64);
        assert_eq!(u16_at(&self.bytes, 58), 64);
        assert!(shoff.checked_add(shnum * 64).unwrap() <= self.bytes.len());
        assert_eq!(
            (0..shnum)
                .filter(|i| u32_at(&self.bytes, shoff + i * 64 + 4) == 2)
                .count(),
            usize::from(!stripped)
        );
        assert!((0..shnum).all(|i| u32_at(&self.bytes, shoff + i * 64 + 4) != 11));
        let mut startup = vec![0xcc; PAGE];
        let mut occupied = BTreeSet::new();
        for &(start, text) in contract::regions(family) {
            let bytes = hex_bytes(text);
            let at = usize::try_from(start - ENTRY).unwrap();
            assert!(at + bytes.len() <= PAGE);
            for i in at..at + bytes.len() {
                assert!(occupied.insert(i));
            }
            startup[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        assert_eq!(self.slice(ENTRY, PAGE), startup);
        let mut subject = vec![0xcc; PAGE];
        subject[0xf0..0x100].fill(0x90);
        let body = family.body();
        subject[0x100..0x100 + body.len()].copy_from_slice(&body);
        assert_eq!(self.slice(SUBJECT & !4095, PAGE), subject);
        assert_eq!(self.slice(NULL_HOOK, 1), [0xc3]);
        assert_eq!(self.slice(JOURNAL_HOOK, 19), journal_hook());
        assert_eq!(
            self.slice(DATA, PAGE),
            (0..PAGE).map(|i| (i * 37 + 11) as u8).collect::<Vec<_>>()
        );
        assert_eq!(self.slice(JOURNAL, PAGE), vec![0; PAGE]);
        assert_eq!(self.slice(STACK, 65536), vec![0x5a; 65536]);
        for (i, &head) in family.heads().iter().enumerate() {
            assert_eq!(
                self.slice(call_pc(i), 5),
                transfer(0xe8, call_pc(i), SUBJECT + head)
            );
        }
    }
}

fn exec(file: &Executable, head: usize) -> Tracee {
    let tasks: Vec<_> = std::fs::read_dir("/proc/self/task").unwrap().collect();
    assert_eq!(tasks.len(), 1, "standalone main-thread driver only");
    // SAFETY: gettid has no pointer arguments and changes no process state.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        libc::c_long::from(std::process::id())
    );
    let argv = [
        CString::new("elf-exec-fixture").unwrap(),
        CString::new(head.to_string()).unwrap(),
    ];
    let argv_ptrs = [argv[0].as_ptr(), argv[1].as_ptr(), std::ptr::null()];
    let env = [
        CString::new("LC_ALL=C").unwrap(),
        CString::new("PATH=/usr/bin:/bin").unwrap(),
    ];
    let env_ptrs = [env[0].as_ptr(), env[1].as_ptr(), std::ptr::null()];
    let fd = file.file.as_raw_fd();
    // SAFETY: all allocation and argument construction precedes fork. The child uses
    // only ptrace, fexecve and _exit; it never returns into Rust.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // SAFETY: arguments and retained read-only executable fd are live in
        // this child. Only async-signal-safe calls run before exec or _exit.
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize) != 0 {
                libc::_exit(120);
            }
            libc::fexecve(fd, argv_ptrs.as_ptr(), env_ptrs.as_ptr());
            libc::_exit(121);
        }
    }
    let child = Tracee {
        pid,
        deadline: Instant::now() + CHILD_BUDGET,
        reaped: Cell::new(false),
    };
    let status = child.wait();
    assert!(
        libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP,
        "kernel exec stop required: {status:#x}"
    );
    assert_eq!(child.registers().rip, ENTRY);
    child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
    child
}
fn seed(child: &Tracee, seed: u64) -> libc::user_regs_struct {
    let mut initial = child.registers();
    let rip = initial.rip;
    let mut state = seed;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    initial.rax = next();
    initial.rbx = next();
    initial.rcx = next();
    initial.rdx = next();
    initial.rbp = next();
    initial.rsi = DATA + 512;
    initial.rdi = DATA + 256;
    initial.r8 = next();
    initial.r9 = next();
    initial.r10 = next();
    initial.r11 = next();
    initial.r12 = next();
    initial.r13 = next();
    initial.r14 = next();
    initial.r15 = next();
    initial.orig_rax = u64::MAX;
    initial.eflags = if seed & 1 == 0 { 0xa97 } else { 0xed7 };
    assert_eq!(initial.rsp, CALLER_RSP);
    assert_eq!(
        initial.rip, rip,
        "RIP is observed startup state, not a seed destination"
    );
    child.set_registers(&initial);
    child.set_xstate(&seeded_xstate(child.xstate(), seed));
    initial
}

struct Image {
    address: u64,
    bytes: Vec<u8>,
    restored: BTreeMap<u64, u64>,
    ranges: Vec<(u64, u64, u64)>,
}
impl Image {
    fn contains(&self, pc: u64) -> bool {
        self.address <= pc && pc < self.address + self.bytes.len() as u64
    }
}
struct Candidate {
    executable: TacticExecutable,
    images: Vec<Image>,
    hook: u64,
    hook_return: u64,
    journal: bool,
    edges: Vec<(u64, u64, Vec<u8>)>,
}
fn file_offset(executable: &Executable, address: u64, len: usize) -> usize {
    let owners: Vec<_> = executable
        .loads
        .iter()
        .filter(|l| {
            l.address <= address && address.checked_add(len as u64).unwrap() <= l.address + l.len
        })
        .collect();
    assert_eq!(owners.len(), 1);
    usize::try_from(owners[0].offset + address - owners[0].address).unwrap()
}
fn one_row<'a>(rows: &'a [Vec<&'a str>], kind: &str) -> &'a [&'a str] {
    let matching: Vec<_> = rows.iter().filter(|r| r[0] == kind).collect();
    assert_eq!(matching.len(), 1, "exact one {kind}");
    matching[0]
}
impl Candidate {
    fn read(
        family: Family,
        original: &TacticExecutable,
        directory: &Path,
        copy: &Path,
        journal: bool,
    ) -> Self {
        let complete = std::fs::read_to_string(directory.join("COMPLETE")).unwrap();
        let complete_rows: Vec<_> = complete.lines().collect();
        assert_eq!(complete_rows.len(), 4);
        assert_eq!(complete_rows[0], "LI2TOOL-DIRECTORY 1");
        let index_hash = complete_rows[1].strip_prefix("index_sha256 ").unwrap();
        assert!(index_hash.len() == 64 && index_hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(complete_rows[2], "candidate_complete true");
        assert_eq!(complete_rows[3], "qualification_complete false");
        let executable =
            TacticExecutable::copy(family, &directory.join("candidate.elf"), copy, true);
        for load in &original.loads {
            assert!(executable.loads.contains(load));
        }
        assert_eq!(
            executable.phnum,
            original.phnum + 1 + family.images() as u16
        );
        assert!(executable.phoff >= original.bytes.len() as u64);
        let carrier: Vec<_> = executable
            .loads
            .iter()
            .filter(|l| l.address == CARRIER)
            .collect();
        assert_eq!(carrier.len(), 1);
        assert_eq!(carrier[0].flags, 4);
        assert_eq!(carrier[0].offset, executable.phoff);
        assert_eq!(
            carrier[0].len,
            u64::from(executable.phnum) * 56 + b"LI2TOOL-CANDIDATE-UNREADY-V1\0".len() as u64 + 64
        );
        assert_eq!(
            executable.slice(
                CARRIER + u64::from(executable.phnum) * 56,
                b"LI2TOOL-CANDIDATE-UNREADY-V1\0".len()
            ),
            b"LI2TOOL-CANDIDATE-UNREADY-V1\0"
        );
        let text = std::fs::read_to_string(directory.join("plan-ledger.tsv")).unwrap();
        assert!(text.len() <= 65536 && text.starts_with("LI2LEDGER\t1\n"));
        let rows: Vec<Vec<_>> = text.lines().map(|l| l.split('\t').collect()).collect();
        assert_eq!(
            one_row(&rows, "qualification_complete"),
            ["qualification_complete", "false"]
        );
        assert_eq!(
            one_row(&rows, "execution_authority"),
            ["execution_authority", "none"]
        );
        assert_eq!(one_row(&rows, "bias_domain"), ["bias_domain", "1"]);
        assert!(rows.iter().all(|r| r[0] != "entry-router-required"));
        // The recipe owns cryptographic directory authentication. Here, every
        // actual source step is replayed in producer order on a private byte
        // overlay, preserving the T2/T3 predecessor dependency.
        let steps: Vec<_> = rows.iter().filter(|r| r[0] == "step").collect();
        assert_eq!(steps.len(), family.images());
        let mut expected_logical = Vec::new();
        if let Some((pc, _)) = family.victim() {
            expected_logical.push(pc);
        }
        expected_logical.push(SUBJECT);
        let mut overlay = original.bytes.clone();
        let mut source_writes = BTreeSet::new();
        for (step_index, row) in steps.iter().enumerate() {
            assert_eq!(row.len(), 8);
            assert_eq!(row[1], "1");
            assert_eq!(number(row[2]), step_index as u64);
            assert_eq!(number(row[4]), expected_logical[step_index]);
            assert_eq!(number(row[5]), number(row[4]));
            assert_eq!(number(row[6]), number(row[4]));
            let length = if number(row[4]) == SUBJECT {
                if matches!(family, Family::B2 | Family::T2) {
                    3
                } else {
                    2
                }
            } else if family == Family::T2 {
                8
            } else {
                10
            };
            assert_eq!(number(row[7]), number(row[4]) + length);
            let expected_kind = if number(row[4]) != SUBJECT || family == Family::T3 {
                "relocation"
            } else if family == Family::T1 {
                "prefixed-pun"
            } else {
                "generalized-pun"
            };
            assert_eq!(row[3], expected_kind);
            let members: Vec<_> = rows
                .iter()
                .filter(|r| {
                    r.len() >= 3
                        && r[1] == "1"
                        && r[2] == row[2]
                        && matches!(r[0], "step-read" | "semantic-write" | "live-store-span")
                })
                .collect();
            let reads: Vec<_> = members.iter().filter(|r| r[0] == "step-read").collect();
            let writes: Vec<_> = members
                .iter()
                .filter(|r| r[0] == "semantic-write")
                .collect();
            assert!(!reads.is_empty() && !writes.is_empty());
            for read in reads {
                assert_eq!(read.len(), 5);
                let bytes = hex_bytes(read[4]);
                let address = number(read[3]);
                assert!(
                    address >= SUBJECT - 16
                        && address + bytes.len() as u64 <= SUBJECT + family.body().len() as u64
                );
                let offset = file_offset(original, address, bytes.len());
                assert_eq!(&overlay[offset..offset + bytes.len()], bytes);
            }
            for write in writes {
                assert_eq!(write.len(), 5);
                let bytes = hex_bytes(write[4]);
                let address = number(write[3]);
                assert!(
                    address >= SUBJECT
                        && address + bytes.len() as u64 <= SUBJECT + family.body().len() as u64
                );
                let offset = file_offset(original, address, bytes.len());
                overlay[offset..offset + bytes.len()].copy_from_slice(&bytes);
                source_writes.extend(offset..offset + bytes.len());
            }
            for store in members.iter().filter(|r| r[0] == "live-store-span") {
                assert_eq!(store.len(), 5);
                let bytes = hex_bytes(store[4]);
                let address = number(store[3]);
                assert!(
                    address >= SUBJECT - 16
                        && address + bytes.len() as u64 <= SUBJECT + family.body().len() as u64
                );
                let offset = file_offset(original, address, bytes.len());
                assert_eq!(&overlay[offset..offset + bytes.len()], bytes);
            }
        }
        for (offset, expected) in overlay.iter().enumerate() {
            if (32..40).contains(&offset) || (56..58).contains(&offset) {
                continue;
            }
            assert_eq!(
                executable.bytes[offset], *expected,
                "undeclared original file change {offset:#x}"
            );
        }
        assert!(!source_writes.is_empty());
        let image_rows: Vec<_> = rows.iter().filter(|r| r[0] == "image").collect();
        assert_eq!(image_rows.len(), family.images());
        let mut images = Vec::new();
        let mut expected_addresses = vec![family.selected()];
        if let Some((_, address)) = family.victim() {
            expected_addresses.push(address);
        }
        let mut actual_addresses = BTreeSet::new();
        for (id, row) in image_rows.iter().enumerate() {
            assert_eq!(row.len(), 7);
            assert_eq!(number(row[1]), id as u64);
            assert_eq!(row[2], "1");
            assert_eq!(row[6], format!("image-{id:04}.bin"));
            let address = number(row[3]);
            assert!(expected_addresses.contains(&address) && actual_addresses.insert(address));
            let bytes = std::fs::read(directory.join(row[6])).unwrap();
            assert_eq!(bytes.len() as u64, number(row[4]));
            assert!(!bytes.is_empty() && address + bytes.len() as u64 <= (address & !4095) + 8192);
            let owners: Vec<_> = executable
                .loads
                .iter()
                .filter(|l| l.address == (address & !4095))
                .collect();
            assert_eq!(owners.len(), 1);
            assert_eq!(owners[0].flags, 5);
            assert_eq!(
                owners[0].len,
                address - owners[0].address + bytes.len() as u64
            );
            assert_eq!(executable.slice(address, bytes.len()), bytes);
            let elf_images: Vec<_> = rows
                .iter()
                .filter(|r| r[0] == "elf-image" && number(r[1]) == id as u64)
                .collect();
            assert_eq!(elf_images.len(), 1);
            let e = elf_images[0];
            assert_eq!(e.len(), 6);
            assert_eq!(
                (number(e[2]), number(e[3]), number(e[4])),
                (
                    address,
                    owners[0].offset + address - owners[0].address,
                    bytes.len() as u64
                )
            );
            let p = usize::try_from(executable.phoff + number(e[5]) * 56).unwrap();
            assert!(number(e[5]) < u64::from(executable.phnum));
            assert_eq!(
                (
                    u32_at(&executable.bytes, p),
                    word(&executable.bytes, p + 16)
                ),
                (1, owners[0].address)
            );
            let logical = if address == family.selected() {
                SUBJECT
            } else {
                family.victim().unwrap().0
            };
            let routes: Vec<_> = rows
                .iter()
                .filter(|r| r[0] == "route" && number(r[1]) == id as u64)
                .collect();
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].len(), 4);
            assert_eq!(
                (number(routes[0][2]), number(routes[0][3])),
                (logical, address)
            );
            let mut restored = BTreeMap::new();
            for r in rows
                .iter()
                .filter(|r| r[0] == "restored-boundary" && number(r[1]) == id as u64)
            {
                assert_eq!(r.len(), 4);
                let generated = number(r[3]);
                assert!(address <= generated && generated < address + bytes.len() as u64);
                assert!(restored.insert(number(r[2]), generated).is_none());
            }
            assert_eq!(restored.len(), 1);
            assert!(restored.contains_key(&logical));
            let mut ranges = Vec::new();
            for r in rows
                .iter()
                .filter(|r| r[0] == "pc-range" && number(r[1]) == id as u64)
            {
                assert_eq!(r.len(), 5);
                let (start, end, pc) = (number(r[2]), number(r[3]), number(r[4]));
                assert!(address <= start && start < end && end <= address + bytes.len() as u64);
                assert!(family.heads().iter().any(|h| SUBJECT + h == pc));
                ranges.push((start, end, pc));
            }
            assert!(!ranges.is_empty());
            for pair in ranges.windows(2) {
                assert!(pair[0].1 <= pair[1].0);
            }
            assert_eq!(
                ranges
                    .iter()
                    .filter(|r| r.0 <= restored[&logical]
                        && restored[&logical] < r.1
                        && r.2 == logical)
                    .count(),
                1
            );
            images.push(Image {
                address,
                bytes,
                restored,
                ranges,
            });
        }
        let allocations: Vec<_> = rows.iter().filter(|r| r[0] == "allocation").collect();
        assert_eq!(allocations.len(), family.images());
        for (step_index, logical) in expected_logical.iter().enumerate() {
            let address = if *logical == SUBJECT {
                family.selected()
            } else {
                family.victim().unwrap().1
            };
            let image = images.iter().find(|i| i.address == address).unwrap();
            let a: Vec<_> = allocations
                .iter()
                .filter(|a| a[1] == "1" && number(a[2]) == step_index as u64)
                .collect();
            assert_eq!(a.len(), 1);
            assert_eq!(a[0].len(), 6);
            assert_eq!(
                (number(a[0][3]), number(a[0][4]), number(a[0][5])),
                (
                    address & !4095,
                    page_end(address + image.bytes.len() as u64),
                    4096
                )
            );
            let preserved: Vec<_> = rows
                .iter()
                .filter(|r| {
                    r[0] == "entry-preserved" && r[1] == "1" && number(r[2]) == step_index as u64
                })
                .collect();
            let expected_entries: Vec<_> = if *logical == SUBJECT && family != Family::T3 {
                family
                    .heads()
                    .iter()
                    .copied()
                    .filter(|offset| *offset < if family == Family::T1 { 6 } else { 5 })
                    .map(|offset| SUBJECT + offset)
                    .collect()
            } else {
                vec![*logical]
            };
            assert_eq!(preserved.len(), expected_entries.len());
            for (r, expected) in preserved.iter().zip(expected_entries) {
                assert_eq!(r.len(), 4);
                assert_eq!(number(r[3]), expected);
            }
        }
        let hook = if journal { JOURNAL_HOOK } else { NULL_HOOK };
        let hook_row = one_row(&rows, "hook");
        assert_eq!(hook_row.len(), 5);
        assert_eq!(
            (
                number(hook_row[1]),
                number(hook_row[2]),
                number(hook_row[3])
            ),
            (
                if journal { 3 } else { 2 },
                hook,
                if journal { 19 } else { 1 }
            )
        );
        assert!(hook_row[4].len() == 64 && hook_row[4].bytes().all(|b| b.is_ascii_hexdigit()));
        let mut hook_return = None;
        let fields: Vec<_> = rows.iter().filter(|r| r[0] == "field").collect();
        assert_eq!(
            fields.len(),
            match family {
                Family::T3 => 5,
                Family::T2 => 4,
                _ => 3,
            }
        );
        let mut seen = BTreeSet::new();
        let mut field_bytes = BTreeSet::new();
        for f in fields {
            assert_eq!(f.len(), 10);
            let id = usize::try_from(number(f[1])).unwrap();
            let image = &images[id];
            let offset = usize::try_from(number(f[2])).unwrap();
            let width = usize::try_from(number(f[3])).unwrap();
            let origin = number(f[5]);
            let target: i128 = f[6].parse().unwrap();
            assert_eq!(f[7], "1");
            assert!(origin <= image.bytes.len() as u64);
            let encoded = &image.bytes[offset..offset + width];
            assert_eq!(encoded, hex_bytes(f[9]));
            for p in offset..offset + width {
                assert!(field_bytes.insert((id, p)));
            }
            let delta = match width {
                1 => i128::from(i8::from_le_bytes(encoded.try_into().unwrap())),
                4 => i128::from(i32::from_le_bytes(encoded.try_into().unwrap())),
                8 => i128::from(i64::from_le_bytes(encoded.try_into().unwrap())),
                _ => panic!("unknown fixed image field width"),
            };
            assert_eq!(
                i128::from(image.address) + i128::from(origin) + delta,
                target
            );
            let role = String::from_utf8(hex_bytes(f[8])).unwrap();
            assert!(seen.insert((id, role.clone())));
            match role.as_str() {
                "LogicalPc" => {
                    assert_eq!(image.address, family.selected());
                    assert_eq!((f[4], width, target), ("Delta", 8, i128::from(SUBJECT)));
                    assert_eq!(origin as usize, offset - 2);
                    assert_eq!(&image.bytes[offset - 2..offset], [0x48, 0xba]);
                    assert_eq!(
                        &image.bytes[offset - 9..offset - 2],
                        [0x48, 0x8d, 5, 0, 0, 0, 0]
                    );
                }
                "HookCall" => {
                    assert_eq!(image.address, family.selected());
                    assert_eq!((f[4], width, target), ("Relative", 4, i128::from(hook)));
                    assert_eq!(origin as usize, offset + 4);
                    assert_eq!(image.bytes[offset - 1], 0xe8);
                    assert!(hook_return.replace(image.address + origin).is_none());
                }
                "Return" => {
                    let end = if image.address == family.selected() {
                        SUBJECT
                            + if matches!(family, Family::B2 | Family::T2) {
                                3
                            } else {
                                2
                            }
                    } else {
                        family.victim().unwrap().0 + if family == Family::T2 { 8 } else { 10 }
                    };
                    assert_eq!((f[4], width, target), ("Relative", 4, i128::from(end)));
                    assert_eq!(origin as usize, offset + 4);
                    assert_eq!(image.bytes[offset - 1], 0xe9);
                }
                _ => {
                    assert_eq!(family, Family::T3);
                    assert_eq!(role, format!("OriginalBranch {{ original_pc: {SUBJECT} }}"));
                    assert_eq!(image.address, family.selected());
                    assert_eq!(f[4], "Relative");
                    assert!(matches!(width, 1 | 4));
                    assert_eq!(target, i128::from(SUBJECT + 3));
                    assert_eq!(origin as usize, offset + width);
                    let b = image.restored[&SUBJECT];
                    let instruction = iced_x86::Decoder::with_ip(
                        64,
                        &image.bytes[(b - image.address) as usize..],
                        b,
                        iced_x86::DecoderOptions::NONE,
                    )
                    .decode();
                    assert_eq!(instruction.mnemonic(), iced_x86::Mnemonic::Jne);
                    assert_eq!(instruction.near_branch_target(), SUBJECT + 3);
                    assert_eq!(instruction.next_ip(), image.address + origin);
                }
            }
        }
        let mut edges = Vec::new();
        if family == Family::T3 {
            let relay = SUBJECT + 69;
            let displacement = i8::try_from(relay as i128 - SUBJECT as i128 - 2).unwrap();
            edges.push((SUBJECT, relay, vec![0xeb, displacement as u8]));
            edges.push((
                relay,
                family.selected(),
                transfer(0xe9, relay, family.selected()),
            ));
        } else if family == Family::T1 {
            let mut bytes = vec![0x2e];
            bytes.extend_from_slice(&transfer(0xe9, SUBJECT + 1, family.selected()));
            edges.push((SUBJECT, family.selected(), bytes));
        } else {
            edges.push((
                SUBJECT,
                family.selected(),
                transfer(0xe9, SUBJECT, family.selected()),
            ));
        }
        if let Some((pc, address)) = family.victim() {
            edges.push((pc, address, transfer(0xe9, pc, address)));
        }
        for (source, _, bytes) in &edges {
            assert_eq!(executable.slice(*source, bytes.len()), bytes);
        }
        assert_eq!(
            std::fs::read_to_string(directory.join("target.tsv")).unwrap(),
            target_tsv()
        );
        Self {
            executable,
            images,
            hook,
            hook_return: hook_return.unwrap(),
            journal,
            edges,
        }
    }
    fn boundary(&self, logical: u64) -> u64 {
        let matches: Vec<_> = self
            .images
            .iter()
            .filter_map(|i| i.restored.get(&logical))
            .collect();
        assert!(matches.len() <= 1);
        matches.first().map_or(logical, |p| **p)
    }
    fn owns_generated(&self, pc: u64) -> bool {
        self.images
            .iter()
            .filter(|i| i.contains(pc) && i.ranges.iter().any(|r| r.0 <= pc && pc < r.1))
            .count()
            == 1
    }
}

fn journal(child: &Tracee, recorded: bool) {
    let mut expected = vec![0; PAGE];
    if recorded {
        expected[..8].copy_from_slice(&1_u64.to_le_bytes());
        expected[8..16].copy_from_slice(&SUBJECT.to_le_bytes());
    }
    assert_eq!(
        child.memory(JOURNAL, PAGE),
        expected,
        "exact private count/logical-PC/zero tail"
    );
}
fn arrive(executable: &TacticExecutable, head: usize, directory: &Path) -> (Tracee, usize) {
    std::fs::create_dir(directory).unwrap();
    let child = exec(executable, head);
    executable.maps(&child, directory, "exec");
    let mut steps = 0;
    let mut startup = Vec::new();
    while child.registers().rip != call_pc(head) {
        let pc = child.registers().rip;
        assert!(
            contract::ARRIVAL.contains(&pc),
            "actual startup must reach only the selected CALL: {pc:#x}"
        );
        startup.extend_from_slice(&pc.to_le_bytes());
        step(&child, &mut steps);
    }
    assert_eq!(startup.len(), steps * 8);
    write_new(&directory.join("startup-pcs.bin"), &startup);
    executable.immutable(&child);
    assert_eq!(child.registers().rsp, CALLER_RSP);
    assert_eq!(
        (child.registers().fs_base, child.registers().gs_base),
        (0, 0)
    );
    assert_eq!(child.memory(DATA, PAGE), executable.slice(DATA, PAGE));
    assert_eq!(child.memory(STACK, 65536), executable.slice(STACK, 65536));
    journal(&child, false);
    let actual = target();
    let xstate = child.xstate();
    assert!(xstate.len() as u64 >= actual.image_len());
    for c in actual.components() {
        assert!(components(&xstate).contains(&(
            c.xfeature().trailing_zeros(),
            c.offset() as usize,
            c.size() as usize
        )));
    }
    for load in &executable.loads {
        for address in (load.address..page_end(load.address + load.len)).step_by(PAGE) {
            let bytes = child.memory(address, PAGE);
            assert_eq!(bytes, executable.page(load, address));
            write_new(&directory.join(format!("loaded-{address:x}.bin")), &bytes);
        }
    }
    write_new(
        &directory.join("before-seed.tsv"),
        format!(
            "entry\t{ENTRY}\ncall\t{}\nstartup_steps\t{steps}\npid\t{}\n",
            call_pc(head),
            child.pid
        )
        .as_bytes(),
    );
    (child, steps)
}
fn call(
    family: Family,
    executable: &Executable,
    child: &Tracee,
    steps: &mut usize,
    head: usize,
    directory: &Path,
) -> (Snapshot, Snapshot) {
    assert_eq!(child.registers().rip, call_pc(head));
    assert_eq!(
        child.memory(call_pc(head), 5),
        transfer(0xe8, call_pc(head), SUBJECT + family.heads()[head])
    );
    assert_eq!(child.memory(CALLER_RSP - 8, 8), [0x5a; 8]);
    let before = snapshot(executable, child, call_pc(head));
    save_named_snapshot(directory, "before-call", &before);
    step(child, steps);
    assert_eq!(child.registers().rip, SUBJECT + family.heads()[head]);
    assert_eq!(child.registers().rsp, CALLER_RSP - 8);
    assert_eq!(
        child.memory(CALLER_RSP - 8, 8),
        (call_pc(head) + 5).to_le_bytes()
    );
    let after = snapshot(executable, child, SUBJECT + family.heads()[head]);
    save_named_snapshot(directory, "after-call", &after);
    (before, after)
}
fn finish(
    executable: &TacticExecutable,
    child: &Tracee,
    steps: usize,
    head: usize,
    directory: &Path,
) {
    assert_eq!(child.registers().rip, call_pc(head) + 5);
    assert_eq!(child.registers().rsp, CALLER_RSP);
    assert_eq!(
        child.memory(CALLER_RSP - 8, 8),
        (call_pc(head) + 5).to_le_bytes()
    );
    executable.maps(child, directory, "terminal");
    executable.unchanged();
    write_new(&directory.join("journal.bin"), &child.memory(JOURNAL, PAGE));
    // SAFETY: exact still-live owned tracee. The inherited Drop remains the
    // bounded cleanup authority for every panic/failure before this point.
    assert_eq!(unsafe { libc::kill(child.pid, libc::SIGKILL) }, 0);
    let status = child.wait();
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);
    assert!(child.reaped.get());
    write_new(
        &directory.join("complete.tsv"),
        format!(
            "status\tpassed\nsteps\t{steps}\nterminal\t{}\nowned_tracee_killed_and_reaped\ttrue\n",
            call_pc(head) + 5
        )
        .as_bytes(),
    );
}
// Independent finite ISA effects, supplied by the original fixture grammar.
// No emitted metadata or rewritten output determines these expected values.
fn original_effect(family: Family, before: &Snapshot, next: u64, head: usize) -> Snapshot {
    let offset = before.logical_pc - SUBJECT;
    let mut registers = before.registers;
    let (length, effect) = match (family, offset) {
        (Family::B2 | Family::T2, 0) => (3, 0),
        (Family::T1, 0) => (2, 1),
        (Family::B2, 3) | (Family::T1, 2) | (Family::T2, 11) => (5, 2),
        (Family::T2, 3) => (8, 0),
        (Family::T2 | Family::T3, 64) => (10, 2),
        (Family::T3, 0) => (2, 3),
        (Family::T3, 2) => (1, 0),
        (Family::B2, 8)
        | (Family::T1, 7)
        | (Family::T2, 16)
        | (Family::T2 | Family::T3, 74)
        | (Family::T3, 3) => (1, 4),
        _ => panic!("not an authored original instruction"),
    };
    match effect {
        0 => assert_eq!(next, before.logical_pc + length),
        1 => {
            registers.rax = u64::from(registers.rax as u32);
            assert_eq!(next, before.logical_pc + length);
        }
        2 => {
            registers.rax = 42;
            assert_eq!(next, before.logical_pc + length);
        }
        3 => assert_eq!(
            next,
            if registers.eflags & (1 << 6) == 0 {
                SUBJECT + 3
            } else {
                SUBJECT + 2
            }
        ),
        4 => {
            assert_eq!(registers.rsp, CALLER_RSP - 8);
            assert_eq!(next, call_pc(head) + 5);
            registers.rsp += 8;
        }
        _ => unreachable!(),
    }
    registers.rip = next;
    Snapshot {
        logical_pc: next,
        registers,
        xstate: before.xstate.clone(),
        data: before.data.clone(),
        application_stack: before.application_stack.clone(),
    }
}
fn original(
    family: Family,
    executable: &TacticExecutable,
    head: usize,
    state_seed: u64,
    directory: &Path,
) -> Original {
    let (child, mut steps) = arrive(executable, head, directory);
    let initial = seed(&child, state_seed);
    let xstate = child.xstate();
    let (before, after) = call(family, executable, &child, &mut steps, head, directory);
    let heads = family.path(head, state_seed);
    let mut points = Vec::new();
    let mut expected_effect = None;
    for (index, &pc) in heads.iter().enumerate() {
        assert_eq!(child.registers().rip, pc);
        let state = snapshot(executable, &child, pc);
        if let Some(expected) = expected_effect.take() {
            assert_state(&expected, &state);
        }
        save_named_snapshot(directory, &format!("point-{index}"), &state);
        journal(&child, false);
        if index + 1 < heads.len() {
            expected_effect = Some(original_effect(family, &state, heads[index + 1], head));
            if executable.slice(pc, 1) == [0xc3] {
                assert_eq!(
                    word(&child.memory(child.registers().rsp, 8), 0),
                    call_pc(head) + 5
                );
            }
        }
        points.push(state);
        if index + 1 < heads.len() {
            step(&child, &mut steps);
        }
    }
    write_new(&directory.join("transfers.tsv"), b"source\ttarget\tbytes\n");
    finish(executable, &child, steps, head, directory);
    Original {
        initial,
        xstate,
        before,
        after,
        points,
    }
}

fn hook(
    candidate: &Candidate,
    child: &Tracee,
    expected: &Snapshot,
    seeded: &[u8],
    directory: &Path,
) {
    let registers = child.registers();
    journal(child, false);
    assert_eq!(registers.rip, candidate.hook);
    assert_eq!(registers.rsp % 16, 8, "SysV hook entry stack alignment");
    assert!(registers.rsp >= STACK && registers.rsp + 8 <= CALLER_RSP - 8 - 128);
    assert_eq!(
        word(&child.memory(registers.rsp, 8), 0),
        candidate.hook_return
    );
    assert!(registers.rdi >= STACK && registers.rdi + 176 <= CALLER_RSP - 8 - 128);
    let context = child.memory(registers.rdi, 176);
    let r = &expected.registers;
    let words = [
        SUBJECT, r.rsp, r.r15, r.r14, r.r13, r.r12, r.r11, r.r10, r.r9, r.r8, r.rdi, r.rsi, r.rbp,
        r.rbx, r.rdx, r.rcx, r.rax,
    ];
    for (index, expected) in words.iter().enumerate() {
        assert_eq!(word(&context, index * 8), *expected);
    }
    assert_eq!(
        word(&context, 136) & !DEBUGGER_FLAGS,
        r.eflags & !DEBUGGER_FLAGS
    );
    let state = target();
    let address = word(&context, 144);
    assert_eq!(address % 64, 0);
    assert_eq!(
        (
            word(&context, 152),
            word(&context, 160),
            word(&context, 168)
        ),
        (state.len(), state.mask(), state.format().raw())
    );
    assert!(address >= STACK && address + state.len() <= registers.rdi);
    let image = child.memory(address, state.len() as usize);
    write_new(&directory.join("hook-context.bin"), &context);
    write_new(&directory.join("hook-saved-xstate.bin"), &image);
    // Compare the architectural image extent, not its allocation padding.
    // The full allocation is captured, and the full original NT_X86_XSTATE
    // representation is still compared at every restored application boundary
    // by the unchanged assert_state.
    let image_len = state.image_len() as usize;
    assert!(seeded.len() >= image_len);
    assert_eq!(
        canonical_xstate(&image[..image_len]),
        canonical_xstate(&seeded[..image_len])
    );
    write_new(
        &directory.join("hook-call.tsv"),
        format!(
            "pc\t{}\nrsp\t{}\nreturn_word\t{}\n",
            candidate.hook, registers.rsp, candidate.hook_return
        )
        .as_bytes(),
    );
}
fn compare(
    family: Family,
    candidate: &Candidate,
    baseline: &Original,
    head: usize,
    state_seed: u64,
    directory: &Path,
) -> usize {
    let executable = &candidate.executable;
    let (child, mut steps) = arrive(executable, head, directory);
    let initial = seed(&child, state_seed);
    assert_eq!(initial.rip, baseline.initial.rip);
    assert_eq!(
        canonical_xstate(&child.xstate()),
        canonical_xstate(&baseline.xstate)
    );
    let (before, after) = call(family, executable, &child, &mut steps, head, directory);
    assert_state(&baseline.before, &before);
    assert_state(&baseline.after, &after);
    let mut seen_hook = false;
    let mut witnessed_hook_call = false;
    let mut witnessed_hook_ret = false;
    let mut observed_edges = Vec::new();
    let mut transfer_text = String::from("source\ttarget\tbytes\n");
    for (index, expected) in baseline.points.iter().enumerate() {
        let boundary = candidate.boundary(expected.logical_pc);
        while child.registers().rip != boundary {
            let pc = child.registers().rip;
            if let Some((source, target, bytes)) = candidate.edges.iter().find(|e| e.0 == pc) {
                assert_eq!(child.memory(*source, bytes.len()), *bytes);
                observed_edges.push((*source, *target));
                transfer_text.push_str(&format!(
                    "{source}\t{target}\t{}\n",
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ));
                step(&child, &mut steps);
                assert_eq!(child.registers().rip, *target);
                continue;
            }
            assert!(
                candidate.owns_generated(pc)
                    || (candidate.hook..candidate.hook + if candidate.journal { 19 } else { 1 })
                        .contains(&pc),
                "unexpected generated/control-flow owner {pc:#x}"
            );
            if pc == candidate.hook {
                assert!(!seen_hook && head == 0 && witnessed_hook_call);
                hook(
                    candidate,
                    &child,
                    &baseline.points[0],
                    &baseline.xstate,
                    directory,
                );
                seen_hook = true;
            }
            if pc == candidate.hook_return - 5 {
                assert!(!witnessed_hook_call && head == 0);
                let rsp = child.registers().rsp;
                assert_eq!(child.memory(pc, 5), transfer(0xe8, pc, candidate.hook));
                step(&child, &mut steps);
                assert_eq!(child.registers().rip, candidate.hook);
                assert_eq!(child.registers().rsp, rsp - 8);
                assert_eq!(word(&child.memory(rsp - 8, 8), 0), candidate.hook_return);
                witnessed_hook_call = true;
                continue;
            }
            if pc == candidate.hook + if candidate.journal { 18 } else { 0 } {
                assert!(seen_hook && !witnessed_hook_ret);
                journal(&child, candidate.journal);
                let rsp = child.registers().rsp;
                assert_eq!(child.memory(pc, 1), [0xc3]);
                assert_eq!(word(&child.memory(rsp, 8), 0), candidate.hook_return);
                step(&child, &mut steps);
                assert_eq!(child.registers().rip, candidate.hook_return);
                assert_eq!(child.registers().rsp, rsp + 8);
                witnessed_hook_ret = true;
                write_new(
                    &directory.join("hook-ret.tsv"),
                    format!(
                        "pc\t{pc}\nreturn_pc\t{}\nrsp_before\t{rsp}\n",
                        candidate.hook_return
                    )
                    .as_bytes(),
                );
                continue;
            }
            step(&child, &mut steps);
        }
        let actual = snapshot(executable, &child, expected.logical_pc);
        assert_state(expected, &actual);
        save_named_snapshot(directory, &format!("point-{index}"), &actual);
        journal(&child, candidate.journal && head == 0);
        if index + 1 < baseline.points.len() {
            if baseline.points[index + 1].logical_pc == call_pc(head) + 5 {
                assert_eq!(child.memory(boundary, 1), [0xc3]);
                assert_eq!(
                    word(&child.memory(child.registers().rsp, 8), 0),
                    call_pc(head) + 5
                );
            }
            step(&child, &mut steps);
        }
    }
    let mut expected_edges = Vec::new();
    if head == 0 {
        if family == Family::T3 {
            expected_edges.extend([(SUBJECT, SUBJECT + 69), (SUBJECT + 69, family.selected())]);
        } else {
            expected_edges.push((SUBJECT, family.selected()));
        }
    }
    if let Some((pc, address)) = family.victim() {
        if (family == Family::T2 && head <= 1) || SUBJECT + family.heads()[head] == pc {
            expected_edges.push((pc, address));
        }
    }
    assert_eq!(observed_edges, expected_edges);
    assert_eq!(seen_hook, head == 0);
    assert_eq!(witnessed_hook_call, head == 0);
    assert_eq!(witnessed_hook_ret, head == 0);
    write_new(&directory.join("transfers.tsv"), transfer_text.as_bytes());
    finish(executable, &child, steps, head, directory);
    2 + baseline.points.len()
}

fn capture_names(
    family: Family,
    originals: &[TacticExecutable; 2],
    candidates: &[Candidate],
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for name in [
        "runtime-target.tsv",
        "capture-inventory.tsv",
        "complete.tsv",
        "original-unstripped",
        "original-stripped",
    ] {
        assert!(names.insert(name.to_string()));
    }
    for name in ["original-unstripped", "original-stripped"] {
        names.insert(format!("{name}.provider"));
    }
    for i in 0..4 {
        names.insert(format!("candidate-{i}"));
        names.insert(format!("candidate-{i}.provider"));
    }
    for (strip, original) in originals.iter().enumerate() {
        for head in 0..family.heads().len() {
            for (seed_index, &seed) in SEEDS.iter().enumerate() {
                for phase in 0..3 {
                    let suffix = if phase == 0 {
                        "original".to_string()
                    } else {
                        format!("hook-{}", phase - 1)
                    };
                    let prefix = format!("strip-{strip}-head-{head}-seed-{seed_index}-{suffix}");
                    for name in [
                        "exec.maps",
                        "exec.map-files",
                        "exec.auxv",
                        "terminal.maps",
                        "terminal.map-files",
                        "terminal.auxv",
                        "startup-pcs.bin",
                        "before-seed.tsv",
                        "journal.bin",
                        "transfers.tsv",
                        "complete.tsv",
                    ] {
                        names.insert(format!("{prefix}/{name}"));
                    }
                    for stem in ["before-call".to_string(), "after-call".to_string()]
                        .into_iter()
                        .chain((0..family.path(head, seed).len()).map(|i| format!("point-{i}")))
                    {
                        for extension in ["regs", "xstate", "data", "stack"] {
                            names.insert(format!("{prefix}/{stem}.{extension}"));
                        }
                    }
                    let executable = if phase == 0 {
                        original
                    } else {
                        &candidates[strip * 2 + phase - 1].executable
                    };
                    for load in &executable.loads {
                        for address in
                            (load.address..page_end(load.address + load.len)).step_by(PAGE)
                        {
                            names.insert(format!("{prefix}/loaded-{address:x}.bin"));
                        }
                    }
                    if phase != 0 && head == 0 {
                        for name in [
                            "hook-context.bin",
                            "hook-saved-xstate.bin",
                            "hook-call.tsv",
                            "hook-ret.tsv",
                        ] {
                            names.insert(format!("{prefix}/{name}"));
                        }
                    }
                }
            }
        }
    }
    names
}
fn observed_files(root: &Path) -> BTreeSet<String> {
    let mut pending = vec![root.to_path_buf()];
    let mut names = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                pending.push(entry.path());
            } else {
                assert!(kind.is_file());
                names.insert(
                    entry
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string(),
                );
            }
        }
    }
    names
}
pub fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        10,
        "run-tactics TACTIC ORIGINAL_UNSTRIPPED ORIGINAL_STRIPPED U_NULL U_JOURNAL S_NULL S_JOURNAL NEW_CAPTURES"
    );
    assert_eq!(args[1], "run-tactics");
    let family = Family::parse(&args[2]);
    let output = Path::new(&args[9]);
    assert!(
        output.is_absolute()
            && output.parent().unwrap().canonicalize().unwrap().as_os_str()
                == output.parent().unwrap().as_os_str()
    );
    assert!(!output.exists());
    std::fs::create_dir(output).unwrap();
    write_new(&output.join("runtime-target.tsv"), target_tsv().as_bytes());
    let originals = [
        TacticExecutable::copy(
            family,
            Path::new(&args[3]),
            &output.join("original-unstripped"),
            false,
        ),
        TacticExecutable::copy(
            family,
            Path::new(&args[4]),
            &output.join("original-stripped"),
            false,
        ),
    ];
    for (i, original) in originals.iter().enumerate() {
        original.original(family, i == 1);
    }
    assert_eq!(originals[0].loads, originals[1].loads);
    for load in &originals[0].loads {
        let first = originals[0].slice(load.address, load.len as usize);
        let second = originals[1].slice(load.address, load.len as usize);
        for (offset, (left, right)) in first.iter().zip(second).enumerate() {
            if load.address == 0x400000
                && ((40..48).contains(&offset) || (58..64).contains(&offset))
            {
                continue;
            }
            assert_eq!(
                left, right,
                "strip changed a non-section-coordinate LOAD byte"
            );
        }
    }
    let mut candidates = Vec::new();
    for i in 0..4 {
        candidates.push(Candidate::read(
            family,
            &originals[i / 2],
            Path::new(&args[5 + i]),
            &output.join(format!("candidate-{i}")),
            i % 2 == 1,
        ));
    }
    // Freeze the exact filename set from authenticated ELF/plan geometry before
    // the first child is created. No successful output can supply its own set.
    let inventory = capture_names(family, &originals, &candidates);
    let original_count = 4 * family.heads().len();
    let point_count: usize = (0..family.heads().len())
        .flat_map(|head| SEEDS.map(move |seed| (head, seed)))
        .map(|(head, seed)| 2 * family.path(head, seed).len())
        .sum();
    let candidate_pages: usize = candidates
        .iter()
        .map(|c| {
            c.executable
                .loads
                .iter()
                .map(|l| ((page_end(l.address + l.len) - l.address) / 4096) as usize)
                .sum::<usize>()
        })
        .sum();
    assert_eq!(
        inventory.len(),
        15 + 19 * 3 * original_count
            + 12 * point_count
            + 21 * original_count
            + 2 * family.heads().len() * candidate_pages
            + 32
    );
    let inventory_text = format!(
        "elf-exec-tactics-captures-v1\n{}\n",
        inventory.iter().cloned().collect::<Vec<_>>().join("\n")
    );
    write_new(
        &output.join("capture-inventory.tsv"),
        inventory_text.as_bytes(),
    );
    let mut original_traces = 0;
    let mut rewritten_traces = 0;
    let mut comparisons = 0;
    for (strip, executable) in originals.iter().enumerate() {
        for head in 0..family.heads().len() {
            for (seed_index, &state_seed) in SEEDS.iter().enumerate() {
                let name = format!("strip-{strip}-head-{head}-seed-{seed_index}");
                let baseline = original(
                    family,
                    executable,
                    head,
                    state_seed,
                    &output.join(format!("{name}-original")),
                );
                original_traces += 1;
                for hook_index in 0..2 {
                    comparisons += compare(
                        family,
                        &candidates[strip * 2 + hook_index],
                        &baseline,
                        head,
                        state_seed,
                        &output.join(format!("{name}-hook-{hook_index}")),
                    );
                    rewritten_traces += 1;
                }
            }
        }
    }
    assert_eq!(original_traces, 4 * family.heads().len());
    assert_eq!(rewritten_traces, 8 * family.heads().len());
    assert_eq!(comparisons, family.comparisons());
    let mut before_complete = inventory.clone();
    assert!(before_complete.remove("complete.tsv"));
    assert_eq!(observed_files(output), before_complete);
    let traces = original_traces + rewritten_traces;
    write_new(&output.join("complete.tsv"),format!(
        "status\tpassed\ntactic\t{family:?}\noriginal_traces\t{original_traces}\nrewritten_traces\t{rewritten_traces}\nfull_state_comparisons\t{comparisons}\nsubject_call_ret_witnesses\t{traces}\nhook_call_return_witnesses\t8\nrecording_hook_rows\t4\nmanual_load_mappings\t0\npost_seed_state_repairs\t0\ncapture_files\t{}\n",inventory.len()).as_bytes());
    assert_eq!(observed_files(output), inventory);
    println!(
        "PASS kernel-exec {family:?}: {original_traces} original + {rewritten_traces} rewritten traces; {comparisons} full-state comparisons; {traces} subject CALL/RETs; 8 hook CALL/RETs; 4 journal rows"
    );
}
