//! Shared immutable bytes and declared control-flow census; no production decoder.
use super::*;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) const PAGE: usize = 4096;
pub(super) const BASE: u64 = 0x400000;
pub(super) const DATA: u64 = 0x600000;
pub(super) const DATA_LEN: usize = 2 * PAGE;
pub(super) const STACK: u64 = DATA + DATA_LEN as u64 - 128;
pub(super) const FLAGS: u64 = 0xed7;
pub(super) const MASK: u64 = 1 << (libc::SIGUSR1 - 1);
static NEXT: AtomicUsize = AtomicUsize::new(0);

pub(super) fn seed(register: usize) -> u64 {
    match register {
        0 => 0x1122_3344_0000_0001,
        1 => 0x5566_7788_0000_0000,
        4 => STACK,
        _ => 0x2233_4455_6677_8800 | register as u64,
    }
}
fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub(super) struct Builder {
    pub(super) bytes: Vec<u8>,
    pub(super) heads: BTreeSet<u64>,
    pub(super) blocks: BTreeSet<u64>,
    pub(super) cursor: usize,
    pub(super) marker: u64,
}
impl Builder {
    pub(super) fn new(pages: usize) -> Self {
        assert!((2..=4).contains(&pages));
        let mut bytes = vec![0; pages * PAGE];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2), (18, 62), (52, 64), (54, 56), (56, 3)] {
            put16(&mut bytes, at, value);
        }
        for (at, value) in [
            (20, 1),
            (64, 1),
            (68, 5),
            (120, 1),
            (124, 6),
            (176, 0x6474e551),
            (180, 6),
        ] {
            put32(&mut bytes, at, value);
        }
        for (at, value) in [
            (24, BASE + PAGE as u64),
            (32, 64),
            (80, BASE),
            (96, (pages * PAGE) as u64),
            (104, (pages * PAGE) as u64),
            (112, PAGE as u64),
            (128, (pages * PAGE) as u64),
            (136, DATA),
            (152, DATA_LEN as u64),
            (160, DATA_LEN as u64),
            (168, PAGE as u64),
            (224, 16),
        ] {
            put64(&mut bytes, at, value);
        }
        let mut this = Self {
            bytes,
            heads: BTreeSet::new(),
            blocks: BTreeSet::new(),
            cursor: PAGE,
            marker: 0,
        };
        this.mov(4, STACK);
        this.emit(&[0xdb, 0xe3]); // FNINIT; deterministic x87/SSE state at fixed PCs.
        this.emit(&[0xd9, 0xe8]);
        this.emit(&[0x66, 0x0f, 0x76, 0xc9]);
        this.emit(&[0x66, 0x0f, 0x6f, 0xd1]);
        for register in 0..16 {
            if register != 4 {
                this.mov(register, seed(register));
            }
        }
        this.emit(&[0x68, 0xd7, 0x0e, 0, 0]); // PUSH/POPF execute only in setup.
        this.emit(&[0x9d]);
        this.marker = this.emit(&[0x90]);
        this.blocks.insert(this.pc());
        this
    }
    pub(super) fn pc(&self) -> u64 {
        BASE + self.cursor as u64
    }
    pub(super) fn emit(&mut self, bytes: &[u8]) -> u64 {
        let pc = self.pc();
        assert!(self.heads.insert(pc));
        assert!(self.cursor + bytes.len() <= self.bytes.len());
        self.bytes[self.cursor..self.cursor + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        pc
    }
    pub(super) fn mov(&mut self, register: usize, value: u64) {
        assert!(register < 16);
        let mut bytes = vec![0x48 | (register >> 3) as u8, 0xb8 | (register & 7) as u8];
        bytes.extend_from_slice(&value.to_le_bytes());
        self.emit(&bytes);
    }
    pub(super) fn store(&mut self, register: usize, slot: usize) {
        assert!(register < 16 && slot < 32);
        let next = self.pc() + 7;
        let mut bytes = vec![
            0x48 | (((register >> 3) as u8) << 2),
            0x89,
            0x05 | (((register & 7) as u8) << 3),
        ];
        bytes.extend_from_slice(
            &i32::try_from((DATA + (8 * slot) as u64) as i64 - next as i64)
                .unwrap()
                .to_le_bytes(),
        );
        self.emit(&bytes);
    }
    pub(super) fn branch(&mut self, opcode: u8, target: u64) -> u64 {
        assert!(matches!(opcode, 0xe8 | 0xe9));
        let next = self.pc() + 5;
        let mut bytes = vec![opcode];
        bytes.extend_from_slice(
            &i32::try_from(target as i64 - next as i64)
                .unwrap()
                .to_le_bytes(),
        );
        let site = self.emit(&bytes);
        self.blocks.insert(target);
        if opcode == 0xe8 {
            self.blocks.insert(next);
        }
        site
    }
    pub(super) fn finish(mut self) -> Fixture {
        self.emit(&[0xeb, 0xfe]); // Never executed by a successful comparison lane.
        assert!(self.blocks.iter().all(|pc| self.heads.contains(pc)));
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "b2-mode-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Fixture {
            path: directory.join("image"),
            directory,
            bytes: self.bytes,
            heads: self.heads,
            blocks: self.blocks,
            marker: self.marker,
        };
        let _fork = FILE_FORK.lock().unwrap();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o500)
            .open(&fixture.path)
            .unwrap();
        file.write_all(&fixture.bytes).unwrap();
        file.write_all(&vec![0x5a; DATA_LEN]).unwrap();
        drop(file);
        fixture
    }
}

pub(super) struct Fixture {
    pub(super) path: PathBuf,
    directory: PathBuf,
    pub(super) bytes: Vec<u8>,
    pub(super) heads: BTreeSet<u64>,
    pub(super) blocks: BTreeSet<u64>,
    pub(super) marker: u64,
}
impl Fixture {
    pub(super) fn facts(&self) -> ImageFacts {
        ImageFacts {
            start: BASE,
            bytes: self.bytes.clone(),
            heads: self.heads.clone(),
        }
    }
    pub(super) fn bytes_at(&self, pc: u64) -> Option<&[u8]> {
        self.bytes
            .get(usize::try_from(pc.checked_sub(BASE)?).ok()?..)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
