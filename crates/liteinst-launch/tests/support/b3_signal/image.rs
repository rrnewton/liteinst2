//! Hand-encoded immutable original program. No production decoder, signal-frame
//! parser or completion helper participates in constructing the reference.
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const PAGE: usize = 4096;
pub const BASE: u64 = 0x400000;
pub const ENTRY: u64 = BASE + PAGE as u64;
pub const HANDLER: u64 = BASE + 2 * PAGE as u64;
pub const RESTORER: u64 = BASE + 3 * PAGE as u64;
pub const LANDING: u64 = BASE + 4 * PAGE as u64;
pub const SOURCE_LEN: usize = 5 * PAGE;
pub const DATA: u64 = 0x600000;
pub const NORMAL: u64 = 0x700000;
pub const ALT: u64 = 0x800000;
pub const STACK_LEN: usize = 128 * 1024;
pub const SP: u64 = NORMAL + STACK_LEN as u64 - 128;
pub const SIGNAL: i32 = 44;
pub const APP_MASK: u64 = (1 << (libc::SIGUSR1 - 1)) | (1 << (libc::SIGUSR2 - 1));
pub const RETURN_MASK: u64 = 1 << (libc::SIGUSR1 - 1);
pub const ACTION_MASK: u64 = 1 << (libc::SIGTERM - 1);
pub const FLAGS: u64 = 0xed7;
pub const EDITED_RAX: u64 = (-22_i64) as u64;
pub const READY: u64 = DATA;
pub const READY_VALUE: u64 = 0x5a61_6c32_5349_474e;
pub const HANDLER_RECORD: u64 = DATA + 0x20;
pub const HANDLER_DONE: u64 = DATA + 0x28;
pub const LANDING_DONE: u64 = DATA + 0x30;
pub const ACTION: u64 = DATA + 0x100;
pub const ALT_CONFIG: u64 = DATA + 0x140;
pub const SETUP_RESULTS: u64 = DATA + 0x180;
pub const SIMD: u64 = DATA + 0x200;
pub const PAYLOAD: u64 = 0x1357_9bdf_2468_ace0;
pub const XMM_SEED: [u8; 16] = [
    0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f, 0x91, 0xa3, 0xb5, 0xc7, 0xd9, 0xeb, 0xfd, 0x0f,
];
pub const XMM_EDIT: [u8; 16] = [
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

// Pinned Linux x86-64 UAPI, independently derived from rt_sigframe/ucontext/
// sigcontext_64. This is the kernel ucontext (304 bytes), not glibc's larger one.
pub const FRAME_UC: usize = 8;
pub const UC_CONTEXT: usize = 40;
pub const UC_MASK: usize = 296;
pub const FRAME_INFO: usize = 312;
pub const FRAME_FIXED: usize = 440;
pub const SC_RAX: usize = 104;
pub const SC_RIP: usize = 128;
pub const SC_FLAGS: usize = 136;
pub const SC_ERROR: usize = 152;
pub const SC_TRAP: usize = 160;
pub const SC_CR2: usize = 176;
pub const SC_FP: usize = 184;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trajectory {
    Ordinary,
    Altstack,
    Edited,
}
impl Trajectory {
    pub fn altstack(self) -> bool {
        self != Self::Ordinary
    }
    pub fn edited(self) -> bool {
        self == Self::Edited
    }
}

#[derive(Clone, Debug)]
pub struct SetupCall {
    pub instruction: u64,
    pub next_pc: u64,
    pub number: u64,
    pub arguments: [u64; 6],
    pub result_slot: u64,
}

pub struct Image {
    pub path: PathBuf,
    pub trajectory: Trajectory,
    pub source: Vec<u8>,
    pub data: Vec<u8>,
    pub heads: BTreeSet<u64>,
    pub setup: Vec<SetupCall>,
    pub pre_signal_cpuid: u64,
    pub ready_pc: u64,
    pub handler_after_cpuid: u64,
    pub sigreturn: u64,
    pub landing_after_cpuid: u64,
}

fn u16_at(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn u32_at(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn u64_at(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

struct Asm<'a> {
    source: &'a mut [u8],
    heads: &'a mut BTreeSet<u64>,
    cursor: usize,
}
impl Asm<'_> {
    fn emit(&mut self, bytes: &[u8]) -> u64 {
        let pc = BASE + self.cursor as u64;
        assert!(self.heads.insert(pc));
        self.source[self.cursor..self.cursor + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        pc
    }
    fn pc(&self) -> u64 {
        BASE + self.cursor as u64
    }
    fn mov(&mut self, register: u8, value: u64) {
        assert!(register < 16);
        let mut b = vec![0x48 | (register >> 3), 0xb8 | (register & 7)];
        b.extend_from_slice(&value.to_le_bytes());
        self.emit(&b);
    }
    fn store_rax(&mut self, address: u64) {
        self.mov(7, address);
        self.emit(&[0x48, 0x89, 0x07]);
    }
    fn store_frame(&mut self, offset: usize, value: u64) {
        self.mov(0, value);
        let mut b = vec![0x48, 0x89, 0x84, 0x24];
        b.extend_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
        self.emit(&b);
    }
    fn syscall(&mut self, number: u64, args: [u64; 6], result_slot: u64) -> SetupCall {
        self.mov(0, number);
        for (reg, value) in [7, 6, 2, 10, 8, 9].into_iter().zip(args) {
            self.mov(reg, value);
        }
        let instruction = self.emit(&[0x0f, 0x05]);
        let next_pc = self.pc();
        self.store_rax(result_slot);
        SetupCall {
            instruction,
            next_pc,
            number,
            arguments: args,
            result_slot,
        }
    }
}

pub fn seed(reg: usize) -> u64 {
    match reg {
        0 => READY_VALUE,
        4 => SP,
        7 => READY,
        _ => 0x1234_5678_9000_0000 + reg as u64 * 0x0101_0101,
    }
}

impl Image {
    pub fn write(directory: &Path, trajectory: Trajectory) -> Self {
        let mut source = vec![0x90; SOURCE_LEN];
        source[..PAGE].fill(0);
        source[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, v) in [(16, 2), (18, 62), (52, 64), (54, 56), (56, 5)] {
            u16_at(&mut source, at, v);
        }
        u32_at(&mut source, 20, 1);
        u64_at(&mut source, 24, ENTRY);
        u64_at(&mut source, 32, 64);
        let segments: [(u64, u64, u64, u32); 4] = [
            (0, BASE, SOURCE_LEN as u64, 5),
            (SOURCE_LEN as u64, DATA, PAGE as u64, 6),
            ((SOURCE_LEN + PAGE) as u64, NORMAL, STACK_LEN as u64, 6),
            (
                (SOURCE_LEN + PAGE + STACK_LEN) as u64,
                ALT,
                STACK_LEN as u64,
                6,
            ),
        ];
        for (n, (offset, address, len, flags)) in segments.into_iter().enumerate() {
            let p = 64 + n * 56;
            u32_at(&mut source, p, 1);
            u32_at(&mut source, p + 4, flags);
            for (at, value) in [
                (8, offset),
                (16, address),
                (24, address),
                (32, len),
                (40, len),
                (48, PAGE as u64),
            ] {
                u64_at(&mut source, p + at, value);
            }
        }
        u32_at(&mut source, 64 + 4 * 56, 0x6474e551);
        u32_at(&mut source, 64 + 4 * 56 + 4, 6);
        u64_at(&mut source, 64 + 4 * 56 + 48, 16);
        let mut data = vec![0xa5; PAGE];
        for at in [0, 0x20, 0x28, 0x30] {
            u64_at(&mut data, at, 0);
        }
        let action_flags = 0x0400_0004_u64
            | if trajectory.altstack() {
                0x0800_0000
            } else {
                0
            };
        for (at, value) in [
            (0x100, HANDLER),
            (0x108, action_flags),
            (0x110, RESTORER),
            (0x118, ACTION_MASK),
            (0x140, ALT),
            (0x148, 0),
            (0x150, STACK_LEN as u64),
        ] {
            u64_at(&mut data, at, value);
        }
        data[0x200..0x210].copy_from_slice(&XMM_SEED);
        u32_at(&mut data, 0x210, 0x1f80);
        let mut heads = BTreeSet::new();
        let mut a = Asm {
            source: &mut source,
            heads: &mut heads,
            cursor: PAGE,
        };
        // No ASLR-dependent exec stack participates after this first literal.
        a.mov(4, SP);
        for reg in 0..16 {
            if reg != 4 {
                a.mov(reg, seed(reg as usize));
            }
        }
        let mut setup = vec![a.syscall(
            libc::SYS_rt_sigaction as u64,
            [SIGNAL as u64, ACTION, 0, 8, 0, 0],
            SETUP_RESULTS,
        )];
        if trajectory.altstack() {
            setup.push(a.syscall(
                libc::SYS_sigaltstack as u64,
                [ALT_CONFIG, 0, 0, 0, 0, 0],
                SETUP_RESULTS + 8,
            ));
        }
        a.mov(0, 0);
        a.mov(1, 0);
        let pre_signal_cpuid = a.emit(&[0x0f, 0xa2]);
        a.emit(&[0xdb, 0xe3]); // FNINIT
        a.emit(&[0xd9, 0xe8]); // FLD1
        a.mov(0, SIMD);
        a.emit(&[0xf3, 0x0f, 0x6f, 0x00]); // MOVDQU XMM0,[RAX]
        a.emit(&[0x0f, 0xae, 0x50, 0x10]); // LDMXCSR [RAX+16]
        let mut push = vec![0x68];
        push.extend_from_slice(&(FLAGS as u32).to_le_bytes());
        a.emit(&push);
        a.emit(&[0x9d]);
        for reg in 0..16 {
            a.mov(reg, seed(reg as usize));
        }
        // The marker is the final store. Its only successor is the self-loop,
        // so an interrupt after observing it cannot catch unfinished seeding.
        a.emit(&[0x48, 0x89, 0x07]); // [RDI=READY] = RAX=READY_VALUE
        let ready_pc = a.emit(&[0xeb, 0xfe]);
        assert!(a.cursor < 2 * PAGE);

        a.cursor = 2 * PAGE;
        a.emit(&[0x0f, 0xa2]);
        let handler_after_cpuid = a.pc();
        a.mov(7, HANDLER_RECORD);
        a.emit(&[0x48, 0x89, 0x27]); // Save actual handler RSP.
        if trajectory.edited() {
            a.store_frame(FRAME_UC + UC_CONTEXT + SC_RIP, LANDING);
            a.store_frame(FRAME_UC + UC_CONTEXT + SC_RAX, EDITED_RAX);
            // One declared application edit, not a comparison mask.
            let mut and = vec![0x48, 0x83, 0xa4, 0x24];
            and.extend_from_slice(&((FRAME_UC + UC_CONTEXT + SC_FLAGS) as u32).to_le_bytes());
            and.push(0xfe);
            a.emit(&and); // Clear CF in saved RFLAGS only.
            a.store_frame(FRAME_UC + UC_MASK, RETURN_MASK);
            let mut load = vec![0x48, 0x8b, 0x94, 0x24];
            load.extend_from_slice(&((FRAME_UC + UC_CONTEXT + SC_FP) as u32).to_le_bytes());
            a.emit(&load); // RDX = the genuine kernel frame's FP pointer.
            for (offset, value) in [
                (160, u64::from_le_bytes(XMM_EDIT[..8].try_into().unwrap())),
                (168, u64::from_le_bytes(XMM_EDIT[8..].try_into().unwrap())),
            ] {
                a.mov(0, value);
                let mut store = vec![0x48, 0x89, 0x82];
                store.extend_from_slice(&(offset as u32).to_le_bytes());
                a.emit(&store);
            }
        }
        a.mov(0, 0x4841_4e44_4c45_5221);
        a.store_rax(HANDLER_DONE);
        a.emit(&[0xc3]);
        assert!(a.cursor < 3 * PAGE);
        a.cursor = 3 * PAGE;
        a.emit(&[0xb8, 0x0f, 0, 0, 0]); // MOV EAX,15.
        let sigreturn = a.emit(&[0x0f, 0x05]);
        a.emit(&[0x0f, 0x0b]);
        a.cursor = 4 * PAGE;
        a.emit(&[0x0f, 0xa2]);
        let landing_after_cpuid = a.pc();
        a.mov(0, 0x4c41_4e44_494e_4721);
        a.store_rax(LANDING_DONE);
        a.emit(&[0xeb, 0xfe]);
        assert!(a.cursor < SOURCE_LEN);
        let path = directory.join("original-signal.elf");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&source).unwrap();
        file.write_all(&data).unwrap();
        file.write_all(&vec![0x5a; STACK_LEN]).unwrap();
        file.write_all(&vec![0xc3; STACK_LEN]).unwrap();
        drop(file);
        Self {
            path,
            trajectory,
            source,
            data,
            heads,
            setup,
            pre_signal_cpuid,
            ready_pc,
            handler_after_cpuid,
            sigreturn,
            landing_after_cpuid,
        }
    }

    pub fn facts(&self) -> liteinst_launch::gate::ImageFacts {
        liteinst_launch::gate::ImageFacts {
            start: BASE,
            bytes: self.source.clone(),
            heads: self.heads.clone(),
        }
    }
}
