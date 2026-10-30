//! Kernel-exec adapter for the unchanged native-state comparator and Tracee.
//! The fixture's real startup reaches the selected CALL before the sole seed.
//! No PT_LOAD is manually mapped, no instruction is injected, and no state is
//! repaired after that seed. This is a finite freestanding ET_EXEC oracle.
//! The recipe authenticates COMPLETE's SHA-256, the bundle index and its whole
//! file set before invocation. This driver checks their consumed syntax and
//! actual byte/owner/state relationships; it does not implement a hash verifier.
use super::*;
use liteinst2::trampoline::{SavedExtendedStateFormat, SavedExtendedStateLayout};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[path = "elf_exec_tactics.rs"]
pub mod tactics;

#[path = "e9_common_app.rs"]
pub mod common_app;

#[path = "e9_common_image.rs"]
// This shared support module also compiles in workspace test crates without
// their own MSRV; keep Clippy's syntax suggestions within the root crate's 1.85.
#[clippy::msrv = "1.85"]
pub mod common_image;

#[path = "elf_exec_provider.rs"]
mod provider;

const ENTRY: u64 = 0x401000;
const SUBJECT: u64 = 0x401100;
const NULL_HOOK: u64 = 0x401200;
const JOURNAL_HOOK: u64 = 0x401220;
const DATA: u64 = 0x403000;
const JOURNAL: u64 = 0x404000;
const GUARD: u64 = 0x405000;
const STACK: u64 = 0x406000;
const STACK_END: u64 = 0x416000;
const CALLER_RSP: u64 = STACK_END - 256;
const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const BODY: [u8; 6] = [0xb8, 5, 0, 0, 0, 0xc3];

fn number(value: &str) -> u64 {
    value.parse().expect("decimal producer field")
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn page_end(value: u64) -> u64 {
    value.checked_add(4095).unwrap() & !4095
}
fn write_new(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn observe_provider(file: &File) -> (String, provider::Provider) {
    let fdinfo =
        std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).unwrap();
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let provider = provider::parse(&fdinfo, &mountinfo, file.metadata().unwrap().ino()).unwrap();
    (fdinfo, provider)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Load {
    offset: u64,
    address: u64,
    len: u64,
    flags: u32,
}
struct Executable {
    file: File,
    path: PathBuf,
    bytes: Vec<u8>,
    loads: Vec<Load>,
    phoff: u64,
    phnum: u16,
    dev: u64,
    inode: u64,
    provider: provider::Provider,
}
impl Executable {
    fn copy(input: &Path, output: &Path) -> Self {
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
        assert!((7..=16).contains(&phnum));
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
                    assert!(address >= 0x400000 && page_end(address + len) <= 0x430000);
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
        assert!((5..=7).contains(&loads.len()));
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
        Self {
            file,
            path: output.canonicalize().unwrap(),
            bytes,
            loads,
            phoff,
            phnum,
            dev: stat.dev(),
            inode: stat.ino(),
            provider,
        }
    }
    fn slice(&self, address: u64, len: usize) -> &[u8] {
        let owners: Vec<_> = self
            .loads
            .iter()
            .filter(|l| {
                l.address <= address
                    && address.checked_add(len as u64).unwrap() <= l.address + l.len
            })
            .collect();
        assert_eq!(owners.len(), 1);
        let start = usize::try_from(owners[0].offset + address - owners[0].address).unwrap();
        &self.bytes[start..start + len]
    }
    fn page(&self, load: &Load, address: u64) -> Vec<u8> {
        let start = usize::try_from(load.offset + address - load.address).unwrap();
        let mut bytes = vec![0; PAGE];
        let available = (self.bytes.len() - start).min(PAGE);
        bytes[..available].copy_from_slice(&self.bytes[start..start + available]);
        bytes
    }
    fn unchanged(&self) {
        let stat = self.file.metadata().unwrap();
        assert_eq!(
            (stat.dev(), stat.ino(), stat.len()),
            (self.dev, self.inode, self.bytes.len() as u64)
        );
        assert_eq!(
            self.path.canonicalize().unwrap().as_os_str(),
            self.path.as_os_str()
        );
        assert!(std::fs::symlink_metadata(&self.path).unwrap().is_file());
        let path_owner = std::fs::metadata(&self.path).unwrap();
        assert_eq!(
            (path_owner.dev(), path_owner.ino(), path_owner.len()),
            (self.dev, self.inode, self.bytes.len() as u64)
        );
        assert_eq!(observe_provider(&self.file).1, self.provider);
        assert_eq!(std::fs::read(&self.path).unwrap(), self.bytes);
    }
    fn original(&self, stripped: bool) {
        assert_eq!(self.loads.len(), 5);
        assert_eq!(self.slice(SUBJECT, 6), BODY);
        assert_eq!(self.slice(NULL_HOOK, 1), [0xc3]);
        assert_eq!(self.slice(JOURNAL_HOOK, 19), journal_hook());
        let shoff = word(&self.bytes, 40) as usize;
        let shnum = usize::from(u16_at(&self.bytes, 60));
        assert!(shnum > 0 && shnum <= 64);
        assert_eq!(u16_at(&self.bytes, 58), 64);
        assert!(shoff.checked_add(shnum * 64).unwrap() <= self.bytes.len());
        let symbol_tables = (0..shnum)
            .filter(|index| u32_at(&self.bytes, shoff + index * 64 + 4) == 2)
            .count();
        assert_eq!(symbol_tables, usize::from(!stripped));
        assert!((0..shnum).all(|index| u32_at(&self.bytes, shoff + index * 64 + 4) != 11));
        let shape: Vec<_> = self
            .loads
            .iter()
            .map(|l| (l.address, l.len, l.flags))
            .collect();
        assert_eq!(
            shape,
            [
                (0x400000, 4096, 4),
                (0x401000, 4096, 5),
                (DATA, 4096, 6),
                (JOURNAL, 4096, 6),
                (STACK, 65536, 6)
            ]
        );
        assert_eq!(
            self.slice(DATA, PAGE),
            (0..PAGE).map(|i| (i * 37 + 11) as u8).collect::<Vec<_>>()
        );
        assert_eq!(self.slice(JOURNAL, PAGE), vec![0; PAGE]);
        assert_eq!(self.slice(STACK, 65536), vec![0x5a; 65536]);
        for head in 0..2 {
            let call = call_pc(head);
            assert_eq!(
                self.slice(call, 5),
                transfer(0xe8, call, SUBJECT + 5 * head as u64)
            );
        }
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
        assert!(pages <= 24);
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
    fn immutable(&self, child: &Tracee) {
        for load in &self.loads {
            if load.flags & 2 == 0 {
                for address in (load.address..page_end(load.address + load.len)).step_by(PAGE) {
                    assert_eq!(
                        child.memory(address, PAGE),
                        self.page(load, address),
                        "complete immutable LOAD page at {address:#x}"
                    );
                }
            }
        }
    }
}

fn transfer(opcode: u8, source: u64, target: u64) -> Vec<u8> {
    let mut bytes = vec![opcode];
    bytes.extend_from_slice(
        &i32::try_from(i128::from(target) - i128::from(source) - 5)
            .unwrap()
            .to_le_bytes(),
    );
    bytes
}
fn journal_hook() -> Vec<u8> {
    let mut bytes = vec![0x48, 0x8b, 0x07, 0x48, 0x89, 0x05];
    bytes.extend_from_slice(
        &i32::try_from(JOURNAL as i64 + 8 - JOURNAL_HOOK as i64 - 10)
            .unwrap()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&[0x48, 0x83, 0x05]);
    bytes.extend_from_slice(
        &i32::try_from(JOURNAL as i64 - JOURNAL_HOOK as i64 - 18)
            .unwrap()
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&[1, 0xc3]);
    bytes
}
fn call_pc(head: usize) -> u64 {
    [0x401080, 0x401090][head]
}

struct Candidate {
    executable: Executable,
    image: u64,
    image_end: u64,
    restored: u64,
    hook: u64,
    hook_return: u64,
    journal: bool,
}
impl Candidate {
    fn read(original: &Executable, directory: &Path, copy: &Path, journal: bool) -> Self {
        let complete = std::fs::read_to_string(directory.join("COMPLETE")).unwrap();
        let complete_rows: Vec<_> = complete.lines().collect();
        assert_eq!(complete_rows.len(), 4);
        assert_eq!(complete_rows[0], "LI2TOOL-DIRECTORY 1");
        let index_hash = complete_rows[1].strip_prefix("index_sha256 ").unwrap();
        assert!(index_hash.len() == 64 && index_hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(complete_rows[2], "candidate_complete true");
        assert_eq!(complete_rows[3], "qualification_complete false");
        let executable = Executable::copy(&directory.join("candidate.elf"), copy);
        assert_eq!(&executable.loads[..5], original.loads);
        assert_eq!(executable.loads.len(), 7);
        assert_eq!(executable.loads[5].address, 0x418000);
        assert_eq!(executable.loads[5].flags, 4);
        assert_eq!(executable.loads[6].address, 0x420000);
        assert_eq!(executable.loads[6].flags, 5);
        assert_eq!(executable.phnum, original.phnum + 2);
        assert!(executable.phoff >= original.bytes.len() as u64);
        let ledger = std::fs::read_to_string(directory.join("plan-ledger.tsv")).unwrap();
        assert!(ledger.len() <= 65536 && ledger.starts_with("LI2LEDGER\t1\n"));
        let rows: Vec<Vec<_>> = ledger.lines().map(|l| l.split('\t').collect()).collect();
        let one = |kind: &str| {
            let matching: Vec<_> = rows.iter().filter(|r| r[0] == kind).collect();
            assert_eq!(matching.len(), 1, "exact one {kind}");
            matching[0].as_slice().to_vec()
        };
        let image_row = one("image");
        assert_eq!(image_row.len(), 7);
        assert_eq!(&image_row[..3], ["image", "0", "1"]);
        assert_eq!(image_row[6], "image-0000.bin");
        let image = number(image_row[3]);
        assert_eq!(image, 0x420000);
        let image_bytes = std::fs::read(directory.join("image-0000.bin")).unwrap();
        assert_eq!(image_bytes.len() as u64, number(image_row[4]));
        assert!(image_bytes.len() <= 4096);
        let image_end = image.checked_add(image_bytes.len() as u64).unwrap();
        assert_eq!(executable.loads[6].len, image_bytes.len() as u64);
        assert_eq!(executable.slice(image, image_bytes.len()), image_bytes);
        let route = one("route");
        assert_eq!(route.len(), 4);
        assert_eq!(&route[..3], ["route", "0", "4198656"]);
        assert_eq!(number(route[3]), image);
        let restored_row = one("restored-boundary");
        assert_eq!(restored_row.len(), 4);
        assert_eq!(&restored_row[..3], ["restored-boundary", "0", "4198656"]);
        let restored = number(restored_row[3]);
        assert!(image <= restored && restored.checked_add(5).unwrap() <= image_end);
        assert_eq!(executable.slice(restored, 5), &BODY[..5]);
        assert_eq!(executable.slice(SUBJECT, 5), transfer(0xe9, SUBJECT, image));
        assert_eq!(executable.slice(SUBJECT + 5, 1), [0xc3]);
        let hook = if journal { JOURNAL_HOOK } else { NULL_HOOK };
        let mut hook_return = None;
        let fields: Vec<_> = rows.iter().filter(|r| r[0] == "field").collect();
        assert_eq!(fields.len(), 3);
        let mut roles = BTreeSet::new();
        for f in fields {
            assert_eq!(f.len(), 10);
            assert_eq!(f[1], "0");
            let offset = usize::try_from(number(f[2])).unwrap();
            let width = usize::try_from(number(f[3])).unwrap();
            let origin = number(f[5]);
            let target = number(f[6]);
            assert_eq!(f[7], "1");
            assert!(roles.insert(f[8]));
            let encoded = &image_bytes[offset..offset + width];
            assert_eq!(
                encoded
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                f[9]
            );
            let delta = match width {
                4 => i64::from(i32::from_le_bytes(encoded.try_into().unwrap())),
                8 => i64::from_le_bytes(encoded.try_into().unwrap()),
                _ => panic!("unexpected symbolic field width"),
            };
            assert_eq!(
                i128::from(image) + i128::from(origin) + i128::from(delta),
                i128::from(target)
            );
            match f[8] {
                "4c6f676963616c5063" => {
                    assert_eq!((f[4], width, target), ("Delta", 8, SUBJECT));
                    assert_eq!(origin as usize, offset - 2);
                    assert_eq!(&image_bytes[offset - 2..offset], [0x48, 0xba]);
                    assert_eq!(
                        &image_bytes[offset - 9..offset - 2],
                        [0x48, 0x8d, 5, 0, 0, 0, 0]
                    );
                }
                "486f6f6b43616c6c" => {
                    assert_eq!((f[4], width, target), ("Relative", 4, hook));
                    assert_eq!(origin as usize, offset + 4);
                    assert_eq!(image_bytes[offset - 1], 0xe8);
                    hook_return = Some(image + origin);
                }
                "52657475726e" => {
                    assert_eq!((f[4], width, target), ("Relative", 4, SUBJECT + 5));
                    assert_eq!(origin as usize, offset + 4);
                    assert_eq!(image_bytes[offset - 1], 0xe9);
                }
                _ => panic!("foreign fixup role"),
            }
        }
        let source_offset = original.loads[1].offset as usize + 0x100;
        for (offset, expected) in original.bytes.iter().enumerate() {
            if (32..40).contains(&offset)
                || (56..58).contains(&offset)
                || (source_offset..source_offset + 5).contains(&offset)
            {
                continue;
            }
            assert_eq!(
                executable.bytes[offset], *expected,
                "undeclared original file edit at {offset:#x}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(directory.join("target.tsv")).unwrap(),
            target_tsv()
        );
        Self {
            executable,
            image,
            image_end,
            restored,
            hook,
            hook_return: hook_return.unwrap(),
            journal,
        }
    }
}

fn target() -> SavedExtendedStateLayout {
    let layout = SavedExtendedStateLayout::detect().unwrap();
    assert_eq!(layout.format(), SavedExtendedStateFormat::XSAVE64_STANDARD);
    assert!(layout.len() <= 32768 && layout.image_len() <= layout.len());
    assert!(CALLER_RSP - 8 - 128 - STACK > layout.len() + 4096);
    layout
}
fn target_tsv() -> String {
    let state = target();
    let mut text = format!(
        "LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t1\nformat\txsave64-standard\nallocation_bytes\t{}\nimage_bytes\t{}\nxcr0_mask\t{}\nqualification_complete\tfalse\n",
        state.len(),
        state.image_len(),
        state.mask()
    );
    for c in state.components() {
        text.push_str(&format!(
            "component\t{}\t{}\t{}\n",
            c.xfeature(),
            c.offset(),
            c.size()
        ));
    }
    text
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
        CString::new(if head == 0 { "m" } else { "r" }).unwrap(),
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
fn step(child: &Tracee, count: &mut usize) {
    assert!(
        *count < MAX_STEPS,
        "20,000-stop budget includes exec startup and application window"
    );
    assert!(Instant::now() < child.deadline);
    *count += 1;
    child.step(&[]);
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
        "exact count/logical-PC and complete zero tail"
    );
}
fn snapshot(executable: &Executable, child: &Tracee, logical_pc: u64) -> Snapshot {
    executable.immutable(child);
    Snapshot {
        logical_pc,
        registers: child.registers(),
        xstate: canonical_xstate(&child.xstate()),
        data: child.memory(DATA, PAGE),
        application_stack: child.memory(
            CALLER_RSP - 8 - 128,
            (STACK_END - (CALLER_RSP - 8 - 128)) as usize,
        ),
    }
}
fn save_named_snapshot(directory: &Path, stem: &str, snapshot: &Snapshot) {
    let r = &snapshot.registers;
    let registers = [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ];
    let bytes: Vec<u8> = registers.iter().flat_map(|r| r.to_le_bytes()).collect();
    write_new(&directory.join(format!("{stem}.regs")), &bytes);
    write_new(&directory.join(format!("{stem}.xstate")), &snapshot.xstate);
    write_new(&directory.join(format!("{stem}.data")), &snapshot.data);
    write_new(
        &directory.join(format!("{stem}.stack")),
        &snapshot.application_stack,
    );
}
struct Original {
    initial: libc::user_regs_struct,
    xstate: Vec<u8>,
    before: Snapshot,
    after: Snapshot,
    points: Vec<Snapshot>,
}
fn arrive(executable: &Executable, head: usize, directory: &Path) -> (Tracee, usize) {
    std::fs::create_dir(directory).unwrap();
    let child = exec(executable, head);
    executable.maps(&child, directory, "exec");
    let mut steps = 0;
    let mut startup = Vec::new();
    while child.registers().rip != call_pc(head) {
        let pc = child.registers().rip;
        assert!(
            (ENTRY..ENTRY + 0x80).contains(&pc),
            "startup must reach authored before-CALL without entering a body/hook"
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
    initial.eflags = 0xad7 | ((seed & 1) << 10);
    assert_eq!(initial.rsp, CALLER_RSP);
    assert_eq!(
        initial.rip, rip,
        "RIP is observed startup state, not a seed destination"
    );
    child.set_registers(&initial);
    child.set_xstate(&seeded_xstate(child.xstate(), seed));
    initial
}
fn call(
    executable: &Executable,
    child: &Tracee,
    steps: &mut usize,
    head: usize,
    directory: &Path,
) -> (Snapshot, Snapshot) {
    assert_eq!(child.registers().rip, call_pc(head));
    assert_eq!(child.memory(CALLER_RSP - 8, 8), [0x5a; 8]);
    let before = snapshot(executable, child, call_pc(head));
    save_named_snapshot(directory, "before-call", &before);
    step(child, steps);
    assert_eq!(child.registers().rip, SUBJECT + 5 * head as u64);
    assert_eq!(child.registers().rsp, CALLER_RSP - 8);
    assert_eq!(
        child.memory(CALLER_RSP - 8, 8),
        (call_pc(head) + 5).to_le_bytes()
    );
    let after = snapshot(executable, child, SUBJECT + 5 * head as u64);
    save_named_snapshot(directory, "after-call", &after);
    (before, after)
}
fn finish(executable: &Executable, child: &Tracee, steps: usize, head: usize, directory: &Path) {
    assert_eq!(child.registers().rip, call_pc(head) + 5);
    assert_eq!(child.registers().rsp, CALLER_RSP);
    assert_eq!(
        child.memory(CALLER_RSP - 8, 8),
        (call_pc(head) + 5).to_le_bytes()
    );
    executable.maps(child, directory, "terminal");
    executable.unchanged();
    write_new(&directory.join("journal.bin"), &child.memory(JOURNAL, PAGE));
    // Explicit kill/reap records the normal fixture-window teardown. Drop still
    // owns the unchanged bounded cleanup on every panic/failure path.
    // SAFETY: exact still-live owned tracee; no other pid or process group.
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
fn original(executable: &Executable, head: usize, state_seed: u64, directory: &Path) -> Original {
    let (child, mut steps) = arrive(executable, head, directory);
    let initial = seed(&child, state_seed);
    let xstate = child.xstate();
    let (before, after) = call(executable, &child, &mut steps, head, directory);
    let heads: Vec<_> = if head == 0 {
        vec![SUBJECT, SUBJECT + 5, call_pc(head) + 5]
    } else {
        vec![SUBJECT + 5, call_pc(head) + 5]
    };
    let mut points = Vec::new();
    for (index, pc) in heads.iter().enumerate() {
        assert_eq!(child.registers().rip, *pc);
        let state = snapshot(executable, &child, *pc);
        save_named_snapshot(directory, &format!("point-{index}"), &state);
        journal(&child, false);
        points.push(state);
        if index + 1 < heads.len() {
            step(&child, &mut steps);
        }
    }
    assert_eq!(
        child.registers().rax,
        if head == 0 { 5 } else { initial.rax }
    );
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
    candidate: &Candidate,
    baseline: &Original,
    head: usize,
    state_seed: u64,
    directory: &Path,
) {
    let executable = &candidate.executable;
    let (child, mut steps) = arrive(executable, head, directory);
    let initial = seed(&child, state_seed);
    assert_eq!(initial.rip, baseline.initial.rip);
    assert_eq!(
        canonical_xstate(&child.xstate()),
        canonical_xstate(&baseline.xstate)
    );
    let (before, after) = call(executable, &child, &mut steps, head, directory);
    assert_state(&baseline.before, &before);
    assert_state(&baseline.after, &after);
    let mut seen_hook = false;
    let mut witnessed_hook_call = false;
    let mut witnessed_hook_ret = false;
    for (index, expected) in baseline.points.iter().enumerate() {
        let boundary = if expected.logical_pc == SUBJECT {
            candidate.restored
        } else {
            expected.logical_pc
        };
        while child.registers().rip != boundary {
            let pc = child.registers().rip;
            assert!(
                pc == SUBJECT
                    || (candidate.image..candidate.image_end).contains(&pc)
                    || (candidate.hook..candidate.hook + if candidate.journal { 19 } else { 1 })
                        .contains(&pc),
                "unexpected instrumented control-flow owner {pc:#x}"
            );
            if pc == candidate.hook {
                assert!(!seen_hook && head == 0);
                assert!(witnessed_hook_call);
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
            if pc == candidate.hook + (if candidate.journal { 18 } else { 0 }) {
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
            step(&child, &mut steps);
        }
    }
    assert_eq!(seen_hook, head == 0);
    assert_eq!(witnessed_hook_call, head == 0);
    assert_eq!(witnessed_hook_ret, head == 0);
    assert_eq!(
        child.registers().rax,
        if head == 0 { 5 } else { baseline.initial.rax }
    );
    finish(executable, &child, steps, head, directory);
}

pub fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 2 && args[1] == "target" {
        let state = target();
        print!("target xsave64 {}", state.mask());
        for c in state.components() {
            print!(" {}:{}:{}", c.xfeature(), c.offset(), c.size());
        }
        println!();
        return;
    }
    assert_eq!(
        args.len(),
        9,
        "run ORIGINAL_UNSTRIPPED ORIGINAL_STRIPPED U_NULL U_JOURNAL S_NULL S_JOURNAL NEW_CAPTURES"
    );
    assert_eq!(args[1], "run");
    let output = Path::new(&args[8]);
    assert!(
        output.is_absolute()
            && output.parent().unwrap().canonicalize().unwrap() == output.parent().unwrap()
    );
    assert!(!output.exists());
    std::fs::create_dir(output).unwrap();
    write_new(&output.join("runtime-target.tsv"), target_tsv().as_bytes());
    let originals = [
        Executable::copy(Path::new(&args[2]), &output.join("original-unstripped")),
        Executable::copy(Path::new(&args[3]), &output.join("original-stripped")),
    ];
    for (index, original) in originals.iter().enumerate() {
        original.original(index == 1);
    }
    assert_eq!(originals[0].loads, originals[1].loads);
    for load in &originals[0].loads {
        let first = originals[0].slice(load.address, load.len as usize);
        let second = originals[1].slice(load.address, load.len as usize);
        for (offset, (left, right)) in first.iter().zip(second).enumerate() {
            // strip changes section-table bookkeeping, not any runtime header,
            // instruction, hook, application byte or owned-stack byte.
            if load.address == 0x400000
                && ((40..48).contains(&offset) || (58..64).contains(&offset))
            {
                continue;
            }
            assert_eq!(
                left, right,
                "stripping changed a non-section-coordinate LOAD byte"
            );
        }
    }
    let mut candidates = Vec::new();
    for index in 0..4 {
        candidates.push(Candidate::read(
            &originals[index / 2],
            Path::new(&args[4 + index]),
            &output.join(format!("candidate-{index}")),
            index % 2 == 1,
        ));
    }
    let mut traces = 0;
    for (strip, executable) in originals.iter().enumerate() {
        for head in 0..2 {
            for (seed_index, &state_seed) in SEEDS.iter().enumerate() {
                let name = format!("strip-{strip}-head-{head}-seed-{seed_index}");
                let baseline = original(
                    executable,
                    head,
                    state_seed,
                    &output.join(format!("{name}-original")),
                );
                traces += 1;
                for hook_index in 0..2 {
                    compare(
                        &candidates[strip * 2 + hook_index],
                        &baseline,
                        head,
                        state_seed,
                        &output.join(format!("{name}-hook-{hook_index}")),
                    );
                    traces += 1;
                }
            }
        }
    }
    assert_eq!(traces, 24);
    write_new(&output.join("complete.tsv"), b"status\tpassed\noriginal_traces\t8\nrewritten_traces\t16\nfull_state_comparisons\t72\nsubject_call_ret_witnesses\t24\nhook_call_return_witnesses\t8\nrecording_hook_rows\t4\nmanual_load_mappings\t0\npost_seed_state_repairs\t0\n");
    println!(
        "PASS kernel-exec MOV5/RET: 8 original + 16 rewritten traces; 72 full-state comparisons; 24 subject CALL/RETs; 8 hook CALL/RETs; 4 journal rows"
    );
}

// Additive adjacent-pair adapter; existing comparator and shape checks remain literal.
#[path = "adjacent_b2_native.rs"]
pub mod adjacent_b2;
