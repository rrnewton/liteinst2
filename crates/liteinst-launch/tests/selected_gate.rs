#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Independent, bounded fixture interpreter versus actual scripted page execution.
//! The expectation decoder below does not use iced-x86 or selected::complete.
//! Native setup is captured by separate raw ptrace code at an authenticated INT3.
//! The strict backend retains prefix/default-policy refusals; the explicit
//! coverage backend separately qualifies overlapping selected streams.

use std::collections::{BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use liteinst_admission::scan::{Policy, SiteClass};
use liteinst_launch::gate::{
    GateError, ImageFacts, SelectedEvent, SelectedExecution, SelectedPageGate,
};
use liteinst_launch::selected::{
    Gpr, InstructionFault, InstructionProvider, OperandWidth, ProviderDecision, SelectedArguments,
    SelectedInput, SelectedResult, SemanticsError, SyscallAbi, SyscallAliases, SyscallResult,
    SysenterConvention,
};
use liteinst_launch::{ExecCheckpoint, LaunchCommand, RegisterSnapshot};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const STACK: u64 = 0x600000;
const STACK_LEN: usize = 64 * 1024;
const SP: u64 = STACK + STACK_LEN as u64 / 2;
const TIMEOUT: Duration = Duration::from_secs(3);
static NEXT: AtomicUsize = AtomicUsize::new(0);
// Exclude only file writes and forks; fixture executions may run concurrently.
static FILE_FORK: Mutex<()> = Mutex::new(());

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-tmp");
        fs::create_dir_all(&root).unwrap();
        let path = root.join(format!(
            "selected-gate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        let _guard = FILE_FORK.lock().unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        drop(file);
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Elf {
    bytes: Vec<u8>,
    heads: BTreeSet<usize>,
    cursor: usize,
    pie: bool,
}
impl Elf {
    fn new(pages: usize, pie: bool) -> Self {
        let mut bytes = vec![0xcc; pages * PAGE];
        bytes[..PAGE].fill(0);
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, if pie { 3 } else { 2 });
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        let base = if pie { 0 } else { BASE };
        let code_len = bytes.len() as u64;
        put64(&mut bytes, 24, base + PAGE as u64);
        put64(&mut bytes, 32, 64);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 3);
        put32(&mut bytes, 64, 1); // Private RX code, including ELF headers.
        put32(&mut bytes, 68, 5);
        put64(&mut bytes, 80, base);
        put64(&mut bytes, 96, code_len);
        put64(&mut bytes, 104, code_len);
        put64(&mut bytes, 112, PAGE as u64);
        put32(&mut bytes, 120, 1); // A separate fixed RW/NX application stack.
        put32(&mut bytes, 124, 6);
        put64(&mut bytes, 128, code_len);
        put64(&mut bytes, 136, if pie { STACK - BASE } else { STACK });
        put64(&mut bytes, 152, PAGE as u64);
        put64(&mut bytes, 160, STACK_LEN as u64);
        put64(&mut bytes, 168, PAGE as u64);
        put32(&mut bytes, 176, 0x6474_e551);
        put32(&mut bytes, 180, 6);
        put64(&mut bytes, 224, 16);
        Self {
            bytes,
            heads: BTreeSet::new(),
            cursor: PAGE,
            pie,
        }
    }
    fn emit(&mut self, instruction: &[u8]) -> usize {
        let at = self.cursor;
        assert!(self.heads.insert(at));
        self.bytes[at..at + instruction.len()].copy_from_slice(instruction);
        self.cursor += instruction.len();
        at
    }
    fn mov64(&mut self, reg: usize, value: u64) {
        assert!(reg < 16);
        let mut bytes = vec![0x48 | (reg as u8 >> 3), 0xb8 | (reg as u8 & 7)];
        bytes.extend_from_slice(&value.to_le_bytes());
        self.emit(&bytes);
    }
    fn mov32(&mut self, reg: usize, value: u32) {
        assert!(reg < 8);
        let mut bytes = vec![0xb8 | reg as u8];
        bytes.extend_from_slice(&value.to_le_bytes());
        self.emit(&bytes);
    }
    fn flags(&mut self) {
        self.emit(&[0x68, 0xd7, 0x0a, 0, 0]); // All arithmetic flags initially set.
        self.emit(&[0x9d]);
    }
    fn store(&mut self, reg: usize, offset: u8) {
        assert!(reg < 8 && offset < 128);
        self.emit(&[0x48, 0x89, 0x44 | ((reg as u8) << 3), 0x24, offset]);
    }
    fn setup(&mut self) {
        self.mov64(4, SP);
        self.emit(&[0xdb, 0xe3]); // FNINIT; nontrivial x87 and SSE setup.
        self.emit(&[0xd9, 0xe8]);
        self.emit(&[0x66, 0x0f, 0x76, 0xc9]);
        self.emit(&[0x66, 0x0f, 0x6f, 0xd1]);
        for reg in 0..16 {
            if reg != 4 {
                self.mov64(reg, 0x8899_aabb_ccdd_0000 + reg as u64);
            }
        }
        self.flags();
    }
    fn jump(&mut self, destination: usize) {
        let distance = i32::try_from(destination as i64 - (self.cursor + 5) as i64).unwrap();
        let mut bytes = vec![0xe9];
        bytes.extend_from_slice(&distance.to_le_bytes());
        self.emit(&bytes);
    }
    fn interpreter(&mut self, path: &Path) {
        let name = path.as_os_str().as_bytes();
        assert!(name.len() < 1024);
        put16(&mut self.bytes, 56, 4);
        put32(&mut self.bytes, 232, 3);
        put32(&mut self.bytes, 236, 4);
        put64(&mut self.bytes, 240, 512);
        put64(&mut self.bytes, 248, BASE + 512);
        put64(&mut self.bytes, 264, name.len() as u64 + 1);
        put64(&mut self.bytes, 272, name.len() as u64 + 1);
        put64(&mut self.bytes, 280, 1);
        self.bytes[512..512 + name.len()].copy_from_slice(name);
    }
    fn file_bytes(&self) -> Vec<u8> {
        let mut bytes = self.bytes.clone();
        bytes.resize(bytes.len() + PAGE, 0);
        bytes
    }
    fn write(&self, directory: &Directory, name: &str) -> PathBuf {
        directory.write(name, &self.file_bytes())
    }
    fn facts(&self, base: u64) -> ImageFacts {
        ImageFacts {
            start: base,
            bytes: self.bytes.clone(),
            heads: self.heads.iter().map(|at| base + *at as u64).collect(),
        }
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

// This small decoder is deliberately limited to the manually authored fixtures.
// Unknown bytes and unbounded execution fail; there is no native fallback.
#[derive(Clone, Copy, Debug)]
struct Decoded {
    class: SiteClass,
    len: usize,
    destination: usize,
    bits: u32,
}
fn selected(bytes: &[u8]) -> Option<Decoded> {
    let fixed = [
        (&[0x0f, 0xa2][..], SiteClass::Cpuid),
        (&[0x0f, 0x31][..], SiteClass::Rdtsc),
        (&[0x0f, 0x01, 0xf9][..], SiteClass::Rdtscp),
    ];
    for (encoding, class) in fixed {
        if bytes.starts_with(encoding) {
            return Some(Decoded {
                class,
                len: encoding.len(),
                destination: 0,
                bits: 0,
            });
        }
    }
    let mut prefix = 0;
    let mut bits = 32;
    let mut high = 0;
    let rdpid = bytes.first() == Some(&0xf3);
    if rdpid || bytes.first() == Some(&0x66) {
        bits = if rdpid { 64 } else { 16 };
        prefix += 1;
    }
    if let Some(&rex @ 0x40..=0x4f) = bytes.get(prefix) {
        high = usize::from(rex & 1) * 8;
        if rex & 8 != 0 {
            bits = 64;
        }
        prefix += 1;
    }
    if bytes.get(prefix..prefix + 2) != Some(&[0x0f, 0xc7]) {
        return None;
    }
    let operand = *bytes.get(prefix + 2)?;
    let class = match operand & 0xf8 {
        0xf0 if !rdpid => SiteClass::Rdrand,
        0xf8 => {
            if rdpid {
                SiteClass::Rdpid
            } else {
                SiteClass::Rdseed
            }
        }
        _ => return None,
    };
    Some(Decoded {
        class,
        len: prefix + 3,
        destination: high + usize::from(operand & 7),
        bits,
    })
}

#[derive(Clone, Copy, Debug)]
enum Reply {
    Cpuid([u32; 4]),
    Random { seed: bool, value: u64, carry: bool },
    Counter { value: u64, auxiliary: Option<u32> },
    Processor(u32),
}
impl Reply {
    fn result(self) -> SelectedResult {
        match self {
            Self::Cpuid([eax, ebx, ecx, edx]) => SelectedResult::Cpuid { eax, ebx, ecx, edx },
            Self::Random {
                seed: false,
                value,
                carry,
            } => SelectedResult::Rdrand { value, carry },
            Self::Random {
                seed: true,
                value,
                carry,
            } => SelectedResult::Rdseed { value, carry },
            Self::Counter {
                value,
                auxiliary: None,
            } => SelectedResult::Rdtsc { counter: value },
            Self::Counter {
                value,
                auxiliary: Some(auxiliary),
            } => SelectedResult::Rdtscp {
                counter: value,
                auxiliary,
            },
            Self::Processor(auxiliary) => SelectedResult::Rdpid { auxiliary },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    stack: Vec<u8>,
}
fn reg(r: &RegisterSnapshot, index: usize) -> u64 {
    [
        r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12,
        r.r13, r.r14, r.r15,
    ][index]
}
fn set_reg(r: &mut RegisterSnapshot, index: usize, value: u64) {
    let out = match index {
        0 => &mut r.rax,
        1 => &mut r.rcx,
        2 => &mut r.rdx,
        3 => &mut r.rbx,
        4 => &mut r.rsp,
        5 => &mut r.rbp,
        6 => &mut r.rsi,
        7 => &mut r.rdi,
        8 => &mut r.r8,
        9 => &mut r.r9,
        10 => &mut r.r10,
        11 => &mut r.r11,
        12 => &mut r.r12,
        13 => &mut r.r13,
        14 => &mut r.r14,
        15 => &mut r.r15,
        _ => panic!("unknown fixture register"),
    };
    *out = value;
}
impl State {
    fn store(&mut self, address: u64, value: u64) {
        let offset = usize::try_from(address.checked_sub(STACK).unwrap()).unwrap();
        self.stack[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn step_to_selected(&mut self, image: &Elf) -> (Decoded, Vec<u8>) {
        for _ in 0..256 {
            let pc = usize::try_from(self.registers.rip - BASE).unwrap();
            assert!(
                image.heads.contains(&pc),
                "fixture jumped to undeclared head"
            );
            let bytes = &image.bytes[pc..];
            if let Some(decoded) = selected(bytes) {
                return (decoded, bytes[..decoded.len].to_vec());
            }
            let len = match bytes {
                [rex @ 0x48..=0x49, opcode @ 0xb8..=0xbf, rest @ ..] => {
                    let index = usize::from(opcode - 0xb8) + usize::from(rex & 1) * 8;
                    set_reg(
                        &mut self.registers,
                        index,
                        u64::from_le_bytes(rest[..8].try_into().unwrap()),
                    );
                    10
                }
                [opcode @ 0xb8..=0xbf, rest @ ..] => {
                    set_reg(
                        &mut self.registers,
                        usize::from(opcode - 0xb8),
                        u64::from(u32::from_le_bytes(rest[..4].try_into().unwrap())),
                    );
                    5
                }
                [0x48, 0x89, operand, 0x24, offset, ..] if operand & 0xc7 == 0x44 => {
                    let value = reg(&self.registers, usize::from((operand >> 3) & 7));
                    self.store(self.registers.rsp + u64::from(*offset), value);
                    5
                }
                [0x68, rest @ ..] => {
                    let value = i32::from_le_bytes(rest[..4].try_into().unwrap()) as i64 as u64;
                    self.registers.rsp -= 8;
                    self.store(self.registers.rsp, value);
                    5
                }
                [0x90, ..] => 1,
                [0x9d, ..] => {
                    let offset = usize::try_from(self.registers.rsp - STACK).unwrap();
                    self.registers.eflags =
                        u64::from_le_bytes(self.stack[offset..offset + 8].try_into().unwrap());
                    self.registers.rsp += 8;
                    1
                }
                [0xe9, rest @ ..] => {
                    let displacement = i32::from_le_bytes(rest[..4].try_into().unwrap());
                    self.registers.rip = self
                        .registers
                        .rip
                        .checked_add_signed(i64::from(displacement) + 5)
                        .unwrap();
                    continue;
                }
                _ => panic!(
                    "instruction outside the strict fixture interpreter at {pc:#x}: {:02x?}",
                    &bytes[..8]
                ),
            };
            self.registers.rip += len;
        }
        panic!("strict fixture interpreter exceeded its instruction budget");
    }
    fn complete(&mut self, instruction: Decoded, reply: Reply) {
        let r = &mut self.registers;
        match (instruction.class, reply) {
            (SiteClass::Cpuid, Reply::Cpuid(values)) => {
                for (index, value) in [0, 3, 1, 2].into_iter().zip(values) {
                    set_reg(r, index, u64::from(value));
                }
            }
            (SiteClass::Rdrand | SiteClass::Rdseed, Reply::Random { seed, value, carry }) => {
                assert_eq!(seed, instruction.class == SiteClass::Rdseed);
                assert!(carry || value == 0);
                let value = match instruction.bits {
                    16 => {
                        assert!(value <= 0xffff);
                        (reg(r, instruction.destination) & !0xffff) | value
                    }
                    32 => {
                        assert!(value <= 0xffff_ffff);
                        value
                    }
                    64 => value,
                    _ => panic!("invalid fixture operand width"),
                };
                set_reg(r, instruction.destination, value);
                // Architectural OF/SF/ZF/AF/PF/CF, independent of the production constants.
                r.eflags = (r.eflags & !0x8d5) | u64::from(carry);
            }
            (SiteClass::Rdtsc | SiteClass::Rdtscp, Reply::Counter { value, auxiliary }) => {
                assert_eq!(auxiliary.is_some(), instruction.class == SiteClass::Rdtscp);
                r.rax = value & 0xffff_ffff;
                r.rdx = value >> 32;
                if let Some(auxiliary) = auxiliary {
                    r.rcx = u64::from(auxiliary);
                }
            }
            (SiteClass::Rdpid, Reply::Processor(value)) => {
                set_reg(r, instruction.destination, u64::from(value))
            }
            _ => panic!("fixture script class mismatch"),
        }
        r.eflags &= !0x10000; // Successful architectural completion clears RF.
        r.rip += instruction.len as u64;
    }
}

#[derive(Clone, Debug)]
struct Row {
    class: SiteClass,
    bytes: Vec<u8>,
    before: RegisterSnapshot,
    after: State,
    decision: ProviderDecision,
}
#[derive(Debug, Default)]
struct RecordingProvider {
    rows: VecDeque<Row>,
    calls: usize,
    consumed: usize,
}
impl InstructionProvider for RecordingProvider {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        self.calls += 1;
        let row = self.rows.front().ok_or(SemanticsError::ScriptExhausted)?;
        assert_eq!(
            input.registers(),
            &row.before,
            "complete callback input state"
        );
        assert_eq!(input.instruction().logical_pc(), row.before.rip);
        assert_eq!(input.instruction().bytes(), row.bytes);
        assert_eq!(input.instruction().operation().class(), row.class);
        let row = self.rows.pop_front().unwrap();
        self.consumed += 1;
        Ok(row.decision)
    }
}
fn rows(image: &Elf, mut state: State, replies: &[Reply]) -> Vec<Row> {
    replies
        .iter()
        .map(|&reply| {
            let (instruction, bytes) = state.step_to_selected(image);
            let before = state.registers;
            state.complete(instruction, reply);
            Row {
                class: instruction.class,
                bytes,
                before,
                after: state.clone(),
                decision: ProviderDecision::Complete(reply.result()),
            }
        })
        .collect()
}
fn launch(path: &Path) -> ExecCheckpoint {
    let _guard = FILE_FORK.lock().unwrap();
    ExecCheckpoint::launch(&LaunchCommand::new(path), TIMEOUT).unwrap()
}
fn page_gate(
    checkpoint: ExecCheckpoint,
    facts: Vec<ImageFacts>,
    policy: Policy,
    rows: &[Row],
) -> SelectedPageGate<RecordingProvider> {
    // SAFETY: the hand-authored private ELF and fixed RW stacks have exhaustive
    // heads, one task, no external aliases/readers/writers, code-as-data reads,
    // handlers, mapping changes, private-island entries or independent reapers.
    unsafe {
        SelectedPageGate::new(
            checkpoint,
            facts,
            policy,
            SyscallAliases::new(),
            RecordingProvider {
                rows: rows.iter().cloned().collect(),
                ..RecordingProvider::default()
            },
            TIMEOUT,
        )
    }
    .unwrap()
}
fn check_completed(gate: &mut SelectedPageGate<RecordingProvider>, row: &Row) {
    let SelectedEvent::Completed(completed) = gate.next_event().unwrap() else {
        panic!("expected selected completion");
    };
    assert_eq!(completed.input.registers(), &row.before);
    assert_eq!(completed.execution, SelectedExecution::Scripted);
    assert_eq!(completed.after, row.after.registers);
    assert_eq!(completed.before_xstate, row.after.xstate);
    assert_eq!(completed.xstate, row.after.xstate);
    assert_eq!(gate.read_registers().unwrap(), row.after.registers);
    assert_eq!(gate.read_xstate().unwrap(), row.after.xstate);
    assert_eq!(gate.read_memory(STACK, STACK_LEN).unwrap(), row.after.stack);
}

fn covered_gate(
    checkpoint: ExecCheckpoint,
    facts: Vec<ImageFacts>,
    rows: &[Row],
) -> SelectedPageGate<RecordingProvider> {
    // SAFETY: same complete closed-world fixture ownership as page_gate. Every
    // alternate entry is explicitly enumerated and all guarded entries have
    // clear TF/RF. The new backend preserves each overlapping decode separately.
    unsafe {
        SelectedPageGate::new_with_coverage(
            checkpoint,
            facts,
            Policy::default(),
            SyscallAliases::new(),
            RecordingProvider {
                rows: rows.iter().cloned().collect(),
                ..RecordingProvider::default()
            },
            TIMEOUT,
            Default::default(),
        )
    }
    .unwrap()
}

#[test]
fn covered_default_rdpid_and_deliberate_rdseed_suffix_match_independent_block_states() {
    let directory = Directory::new();
    let mut image = Elf::new(2, false);
    image.setup();
    let first = image.emit(&[0xf3, 0x0f, 0xc7, 0xfa]);
    image.heads.insert(first + 1);
    image.jump(first + 1);
    let expected = rows(
        &image,
        native_seed(&directory, &image, first),
        &[
            Reply::Processor(0xabcd_1234),
            Reply::Random {
                seed: true,
                value: 0x1234_5678,
                carry: true,
            },
        ],
    );
    let path = image.write(&directory, "covered-alternate");
    let mut gate = covered_gate(launch(&path), vec![image.facts(BASE)], &expected);
    for row in &expected {
        check_completed(&mut gate, row);
    }
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdpid), Some(&1));
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdseed), Some(&1));
    assert_eq!(gate.gate_metrics().covered_candidates, 2);
    assert_eq!(gate.gate_metrics().collateral_completions, 0);
}

#[test]
fn covered_random_widths_and_all_gprs_match_independent_block_states() {
    let directory = Directory::new();
    let mut image = Elf::new(3, false);
    image.setup();
    let first = image.cursor;
    let mut replies = Vec::new();
    for seed in [false, true] {
        for bits in [16, 32, 64] {
            for destination in 0..16 {
                for carry in [true, false] {
                    image.mov64(4, SP);
                    image.mov64(
                        destination,
                        if destination == 4 {
                            SP
                        } else {
                            0x8877_6655_4433_2211
                        },
                    );
                    image.flags();
                    let mut instruction = Vec::new();
                    if bits == 16 {
                        instruction.push(0x66);
                    }
                    let rex = 0x40
                        | if bits == 64 { 8 } else { 0 }
                        | if destination >= 8 { 1 } else { 0 };
                    if rex != 0x40 {
                        instruction.push(rex);
                    }
                    instruction.extend_from_slice(&[
                        0x0f,
                        0xc7,
                        (if seed { 0xf8 } else { 0xf0 }) + (destination & 7) as u8,
                    ]);
                    image.emit(&instruction);
                    replies.push(Reply::Random {
                        seed,
                        value: if !carry {
                            0
                        } else if bits == 16 {
                            0x9876
                        } else if bits == 32 {
                            0xfedc_9876
                        } else {
                            0xfedc_ba98_7654_3210
                        },
                        carry,
                    });
                }
            }
        }
    }
    image.emit(&[0x0f, 0x0b]);
    let expected = rows(&image, native_seed(&directory, &image, first), &replies);
    let path = image.write(&directory, "covered-widths");
    let mut gate = covered_gate(launch(&path), vec![image.facts(BASE)], &expected);
    for row in &expected {
        check_completed(&mut gate, row);
    }
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdrand), Some(&96));
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdseed), Some(&96));
    assert_eq!(gate.provider().consumed, 192);
    assert!(gate.gate_metrics().covered_candidates > 192);
}

#[test]
fn covered_embedded_constant_executes_original_mov_without_an_extra_callback() {
    let directory = Directory::new();
    let mut image = Elf::new(2, false);
    image.setup();
    let first = image.cursor;
    image.mov64(3, 0x9090_9090_f8c7_0f90);
    image.store(3, 0);
    image.emit(&[0x0f, 0x31]);
    image
        .heads
        .extend([first + 3, first + 6, first + 7, first + 8, first + 9]);
    image.jump(first + 3);
    image.emit(&[0x0f, 0x0b]);
    let expected = rows(
        &image,
        native_seed(&directory, &image, first),
        &[
            Reply::Counter {
                value: 0x1122_3344_5566_7788,
                auxiliary: None,
            },
            Reply::Random {
                seed: true,
                value: 0xfedc_1234,
                carry: true,
            },
            Reply::Counter {
                value: 0x8877_6655_4433_2211,
                auxiliary: None,
            },
        ],
    );
    let path = image.write(&directory, "covered-immediate");
    let mut gate = covered_gate(launch(&path), vec![image.facts(BASE)], &expected);
    check_completed(&mut gate, &expected[0]);
    check_completed(&mut gate, &expected[1]);
    check_completed(&mut gate, &expected[2]);
    assert_eq!(gate.metrics().callbacks.len(), 2);
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdtsc), Some(&2));
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdseed), Some(&1));
    assert_eq!(gate.gate_metrics().collateral_guards, 1);
    assert_eq!(gate.gate_metrics().collateral_completions, 1);
}

#[test]
fn covered_unqualified_collateral_refuses_before_any_write() {
    let directory = Directory::new();
    let mut image = Elf::new(2, false);
    // PUSH imm32 contains RDTSC; stack mutation/debug-step semantics are not
    // qualified by the MOV collateral executor, so this remains a refusal.
    image.emit(&[0x68, 0x0f, 0x31, 0x90, 0x90]);
    image.emit(&[0x0f, 0x0b]);
    let path = image.write(&directory, "covered-refusal");
    let mut gate = covered_gate(launch(&path), vec![image.facts(BASE)], &[]);
    assert!(
        format!("{:?}", gate.next_event().unwrap_err()).contains("collateral instruction lacks")
    );
    assert_eq!(
        gate.read_memory(BASE, image.bytes.len()).unwrap(),
        image.bytes
    );
    assert_eq!(gate.provider().calls, 0);
    assert!(!gate.is_admitted(BASE + PAGE as u64));
    assert_nx(gate.pid(), BASE + PAGE as u64);
}

#[test]
fn covered_rdpid_straddler_closes_both_pages_before_dispatch() {
    let directory = Directory::new();
    let mut image = Elf::new(3, false);
    image.setup();
    let first = 2 * PAGE - 2;
    image.jump(first);
    image.cursor = first;
    image.emit(&[0xf3, 0x0f, 0xc7, 0xfa]);
    image.emit(&[0x0f, 0x0b]);
    let expected = rows(
        &image,
        native_seed(&directory, &image, first),
        &[Reply::Processor(0x1234_5678)],
    );
    let path = image.write(&directory, "covered-straddler");
    let mut gate = covered_gate(launch(&path), vec![image.facts(BASE)], &expected);
    check_completed(&mut gate, &expected[0]);
    assert!(gate.is_admitted(BASE + first as u64));
    assert!(gate.is_admitted(BASE + first as u64 + 3));
    assert_eq!(gate.gate_metrics().covered_candidates, 2);
}

#[test]
fn covered_saved_call_return_into_never_executed_page_preserves_original_head() {
    let directory = Directory::new();
    let mut image = Elf::new(4, false);
    image.setup();
    let call = 2 * PAGE - 5;
    image.jump(call);
    image.cursor = call;
    let mut bytes = vec![0xe8];
    bytes.extend_from_slice(&i32::try_from(3 * PAGE - (call + 5)).unwrap().to_le_bytes());
    image.emit(&bytes);
    let first = image.emit(&[0xf3, 0x0f, 0xc7, 0xfa]);
    assert_eq!(first, 2 * PAGE);
    image.emit(&[0x0f, 0x0b]);
    image.cursor = 3 * PAGE;
    image.emit(&[0xc3]);
    let expected = rows(
        &image,
        native_seed(&directory, &image, first),
        &[Reply::Processor(0x1234_5678)],
    );
    let path = image.write(&directory, "covered-call-return");
    let mut gate = covered_gate(launch(&path), vec![image.facts(BASE)], &expected);
    check_completed(&mut gate, &expected[0]);
    assert_eq!(
        gate.read_memory(SP - 8, 8).unwrap(),
        (BASE + first as u64).to_le_bytes()
    );
    assert_eq!(gate.gate_metrics().admitted_pages, 3);
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdpid), Some(&1));
}
fn policy(classes: &[SiteClass]) -> Policy {
    Policy {
        version: 1,
        selected: classes.iter().copied().collect(),
    }
}
fn assert_nx(pid: libc::pid_t, address: u64) {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    let line = maps
        .lines()
        .find(|line| {
            let range = line.split_whitespace().next().unwrap();
            let (start, end) = range.split_once('-').unwrap();
            u64::from_str_radix(start, 16).unwrap() <= address
                && address < u64::from_str_radix(end, 16).unwrap()
        })
        .unwrap();
    assert_eq!(line.split_whitespace().nth(1).unwrap().as_bytes()[2], b'-');
}

// Independent original setup observer. Terminal ownership is retired before
// assertions, and delayed cleanup retains the unreaped Child until completion.
struct Native(Option<Child>);
impl Native {
    fn launch(path: &Path) -> Self {
        let mut command = Command::new(path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the post-fork closure performs only the raw TRACEME syscall.
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = {
            let _guard = FILE_FORK.lock().unwrap();
            Self(Some(command.spawn().unwrap()))
        };
        let status = child.wait();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        child.trace(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        child
    }
    fn pid(&self) -> libc::pid_t {
        self.0.as_ref().unwrap().id() as libc::pid_t
    }
    fn trace(&self, request: u32, address: usize, data: usize) {
        // SAFETY: this owner supplies request-valid pointers/scalars for its traced child.
        assert_ne!(
            unsafe { libc::ptrace(request, self.pid(), address, data) },
            -1,
            "raw ptrace: {}",
            io::Error::last_os_error()
        );
    }
    fn wait(&mut self) -> i32 {
        let until = Instant::now() + TIMEOUT;
        loop {
            let mut status = 0;
            // SAFETY: exclusively owned, unreaped child. Numeric identity retires on terminal/ECHILD.
            let result =
                unsafe { libc::waitpid(self.pid(), &mut status, libc::__WALL | libc::WNOHANG) };
            if result == self.pid() {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.0.take();
                }
                return status;
            }
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.0.take();
                }
                panic!("native fixture wait: {error}");
            }
            assert!(Instant::now() < until, "native fixture deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn registers(&self) -> RegisterSnapshot {
        let mut raw = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
        self.trace(libc::PTRACE_GETREGS, 0, raw.as_mut_ptr() as usize);
        // SAFETY: successful GETREGS filled the full output structure.
        unsafe { raw.assume_init() }.into()
    }
    fn xstate(&self) -> Vec<u8> {
        let mut bytes = vec![0; 64 * 1024];
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        self.trace(libc::PTRACE_GETREGSET, 0x202, (&raw mut vector) as usize);
        assert!(vector.iov_len >= 512 && vector.iov_len < bytes.len());
        bytes.truncate(vector.iov_len);
        bytes
    }
    fn memory(&self, address: u64, len: usize) -> Vec<u8> {
        assert_eq!(address % 8, 0);
        assert_eq!(len % 8, 0);
        let mut bytes = Vec::with_capacity(len);
        for offset in (0..len).step_by(8) {
            // SAFETY: PEEKDATA reads only this stopped child's mapped fixture stack.
            let word = unsafe {
                *libc::__errno_location() = 0;
                let word = libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    self.pid(),
                    address as usize + offset,
                    0,
                );
                assert!(word != -1 || *libc::__errno_location() == 0);
                word as u64
            };
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}
fn terminal(pid: libc::pid_t) -> bool {
    let mut status = 0;
    // SAFETY: cleanup retains exclusive unreaped identity until this function returns true.
    let result = unsafe { libc::waitpid(pid, &mut status, libc::__WALL | libc::WNOHANG) };
    (result == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)))
        || (result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
}
impl Drop for Native {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let pid = child.id() as libc::pid_t;
            let until = Instant::now() + TIMEOUT;
            while !terminal(pid) {
                if Instant::now() >= until {
                    std::thread::spawn(move || {
                        while !terminal(pid) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        drop(child); // Raw wait consumed status; never call Child::wait again.
                    });
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(child);
        }
    }
}
fn native_seed(directory: &Directory, image: &Elf, first: usize) -> State {
    assert!(!image.pie);
    let mut bytes = image.file_bytes();
    bytes[first] = 0xcc;
    let path = directory.write("native-seed", &bytes);
    let mut native = Native::launch(&path);
    native.trace(libc::PTRACE_CONT, 0, 0);
    let status = native.wait();
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    native.trace(libc::PTRACE_GETSIGINFO, 0, info.as_mut_ptr() as usize);
    // SAFETY: successful GETSIGINFO initialized the complete siginfo structure.
    let info = unsafe { info.assume_init() };
    assert_eq!(info.si_signo, libc::SIGTRAP);
    assert!(matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
    let mut registers = native.registers();
    assert_eq!(registers.rip, BASE + first as u64 + 1);
    registers.rip -= 1; // Only the authenticated INT3's post-instruction PC is translated.
    assert_eq!(registers.rsp, SP);
    State {
        registers,
        xstate: native.xstate(),
        stack: native.memory(STACK, STACK_LEN),
    }
}

#[test]
fn masked_cpuid_still_dispatches_random_and_time_against_independent_block_model() {
    let directory = Directory::new();
    let mut image = Elf::new(2, false);
    image.setup();
    image.mov32(0, 1);
    image.mov32(1, 0);
    let first = image.emit(&[0x0f, 0xa2]);
    for (index, register) in [0, 3, 1, 2].into_iter().enumerate() {
        image.store(register, (index * 8) as u8);
    }
    image.mov32(0, 7);
    image.mov32(1, 0);
    image.emit(&[0x0f, 0xa2]);
    for (index, register) in [0, 3, 1, 2].into_iter().enumerate() {
        image.store(register, (32 + index * 8) as u8);
    }
    // No CPUID-conditioned branch: both masked instructions are deliberately executed.
    for (encoding, register, offset) in [
        ([0x0f, 0xc7, 0xf0], 0, 64),
        ([0x0f, 0xc7, 0xf3], 3, 72),
        ([0x0f, 0xc7, 0xfa], 2, 80),
        ([0x0f, 0xc7, 0xf9], 1, 88),
    ] {
        // Each 32-bit destination begins with nonzero upper bits, so retaining
        // those bits cannot pass merely because an earlier CPUID cleared them.
        image.mov64(register, 0x8877_6655_4433_2211 + register as u64);
        image.flags();
        image.emit(&encoding);
        image.store(register, offset);
    }
    image.emit(&[0x0f, 0x31]);
    image.store(0, 96);
    image.store(2, 104);
    image.emit(&[0x0f, 0x01, 0xf9]);
    image.store(1, 112);
    image.emit(&[0x0f, 0xa2]); // Final selected marker verifies all prior stores.
    image.emit(&[0x0f, 0x0b]);
    let feature1 = [1, 0x1234_5678, 0, 0x8765_4321];
    let feature7 = [7, 0x1234_5678 & !(1 << 18), 0, 0x1020_3040];
    assert_eq!(feature1[2] & (1 << 30), 0);
    assert_eq!(feature7[1] & (1 << 18), 0);
    let replies = [
        Reply::Cpuid(feature1),
        Reply::Cpuid(feature7),
        Reply::Random {
            seed: false,
            value: 0xfedc_ba98,
            carry: true,
        },
        Reply::Random {
            seed: false,
            value: 0,
            carry: false,
        },
        Reply::Random {
            seed: true,
            value: 0x8765_4321,
            carry: true,
        },
        Reply::Random {
            seed: true,
            value: 0,
            carry: false,
        },
        Reply::Counter {
            value: 0x1122_3344_aabb_ccdd,
            auxiliary: None,
        },
        Reply::Counter {
            value: 0x5566_7788_99aa_bbcc,
            auxiliary: Some(0xdead_beef),
        },
        Reply::Cpuid([0x1357, 0x2468, 0x3579, 0x468a]),
    ];
    let initial = native_seed(&directory, &image, first);
    let expected = rows(&image, initial, &replies);
    let path = image.write(&directory, "scripted");
    let mut gate = page_gate(
        launch(&path),
        vec![image.facts(BASE)],
        Policy::default(),
        &expected,
    );
    for row in &expected {
        check_completed(&mut gate, row);
    }
    assert_eq!(gate.provider().consumed, replies.len());
    assert_eq!(gate.provider().calls, replies.len());
    assert!(gate.provider().rows.is_empty());
    assert_eq!(gate.metrics().scripted_completions, replies.len());
    assert_eq!(gate.metrics().native_completions, 0);
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Cpuid), Some(&3));
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdrand), Some(&2));
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdseed), Some(&2));
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdtsc), Some(&1));
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Rdtscp), Some(&1));
    assert_eq!(
        expected
            .iter()
            .filter(|r| r.class == SiteClass::Rdrand)
            .count(),
        2
    );
    assert_eq!(
        expected
            .iter()
            .filter(|r| r.class == SiteClass::Rdseed)
            .count(),
        2
    );
    let final_state = &expected.last().unwrap().after;
    for mutate in [0, 1, 2, 3, 4] {
        let mut wrong = final_state.clone();
        match mutate {
            0 => wrong.registers.rsp += 16,
            1 => wrong.registers.r11 ^= 1,
            2 => wrong.registers.eflags ^= 1,
            3 => wrong.xstate[160] ^= 1,
            _ => wrong.stack[(SP - STACK) as usize] ^= 1,
        }
        assert_ne!(&wrong, final_state, "complete oracle rejects state drift");
    }
}

#[test]
fn rdpid_only_policy_dispatches_aux_without_relaxing_default_policy() {
    let directory = Directory::new();
    let mut image = Elf::new(2, false);
    image.setup();
    let first = image.emit(&[0xf3, 0x0f, 0xc7, 0xfa]); // RDPID RDX.
    image.store(2, 0);
    image.emit(&[0xf3, 0x0f, 0xc7, 0xf9]); // RDPID RCX.
    image.emit(&[0x0f, 0x0b]);
    let expected = rows(
        &image,
        native_seed(&directory, &image, first),
        &[Reply::Processor(0xfedc_ba98), Reply::Processor(0x8765_4321)],
    );
    let path = image.write(&directory, "rdpid");
    let mut gate = page_gate(
        launch(&path),
        vec![image.facts(BASE)],
        policy(&[SiteClass::Rdpid]),
        &expected,
    );
    for row in &expected {
        check_completed(&mut gate, row);
    }
    assert_eq!(gate.provider().consumed, 2);
    assert_eq!(expected[0].after.registers.rdx, 0xfedc_ba98);
}

#[test]
fn bare_rdseed_cross_page_fetch_admits_both_pages_and_matches_block_model() {
    let directory = Directory::new();
    let mut image = Elf::new(3, false);
    image.setup();
    let first = 2 * PAGE - 1;
    image.jump(first);
    image.cursor = first;
    image.emit(&[0x0f, 0xc7, 0xfa]);
    image.store(2, 0);
    image.emit(&[0x0f, 0x31]);
    image.emit(&[0x0f, 0x0b]);
    let expected = rows(
        &image,
        native_seed(&directory, &image, first),
        &[
            Reply::Random {
                seed: true,
                value: 0xabcd_0123,
                carry: true,
            },
            Reply::Counter {
                value: 0x1020_3040_5060_7080,
                auxiliary: None,
            },
        ],
    );
    let path = image.write(&directory, "cross-page");
    let mut gate = page_gate(
        launch(&path),
        vec![image.facts(BASE)],
        Policy::default(),
        &expected,
    );
    for row in &expected {
        check_completed(&mut gate, row);
    }
    assert!(gate.is_admitted(BASE + first as u64));
    assert!(gate.is_admitted(BASE + first as u64 + 2));
    assert_eq!(gate.provider().consumed, 2);
}

#[test]
fn selected_interpreter_and_executable_instruction_one_complete_exactly_once() {
    let directory = Directory::new();
    let mut interpreter = Elf::new(2, true);
    interpreter.emit(&[0x0f, 0x31]); // The interpreter's literal first instruction.
    interpreter.mov64(0, BASE + PAGE as u64);
    interpreter.emit(&[0xff, 0xe0]); // JMP RAX to the executable's entry.
    let interpreter_path = interpreter.write(&directory, "interpreter");
    let mut image = Elf::new(2, false);
    image.emit(&[0x0f, 0xc7, 0xf8]); // RDSEED EAX is the executable's first instruction.
    image.mov32(7, 73);
    image.mov32(0, 60);
    image.emit(&[0x0f, 0x05]); // Unselected, allowlisted native exit.
    image.emit(&[0x0f, 0x0b]);
    image.interpreter(&interpreter_path);
    let path = image.write(&directory, "main");
    let checkpoint = launch(&path);
    let interpreter_base = checkpoint.entries().interpreter_base;
    assert_ne!(interpreter_base, 0);
    let mut first_input = *checkpoint.initial_registers();
    assert_eq!(first_input.rip, interpreter_base + PAGE as u64);
    assert_eq!(first_input.rax, (-i64::from(libc::ENOSYS)) as u64);
    // PTRACE_EVENT_EXEC precedes the kernel's successful exec return. The
    // independently calibrated first-user transition in checkpoint.rs sets
    // RAX=0; do not copy the gate's observed value into this expectation.
    first_input.rax = 0;
    // The authenticated INT3 stop has no active syscall; no architectural GPR
    // or flag is normalized. This is the independently specified kernel field.
    first_input.orig_rax = u64::MAX;
    let mut gate = page_gate(
        checkpoint,
        vec![image.facts(BASE), interpreter.facts(interpreter_base)],
        policy(&[SiteClass::Rdtsc, SiteClass::Rdseed]),
        &[],
    );
    let entry_stack = gate.read_memory(first_input.rsp, 32).unwrap();
    let xstate = gate.read_xstate().unwrap();
    let mut expected = State {
        registers: first_input,
        xstate,
        stack: vec![0; STACK_LEN],
    };
    let first_reply = Reply::Counter {
        value: 0x1234_5678_9abc_def0,
        auxiliary: None,
    };
    expected.complete(selected(&[0x0f, 0x31]).unwrap(), first_reply);
    let first = Row {
        class: SiteClass::Rdtsc,
        bytes: vec![0x0f, 0x31],
        before: first_input,
        after: expected.clone(),
        decision: ProviderDecision::Complete(first_reply.result()),
    };
    // Independently model the two ordinary interpreter instructions.
    expected.registers.rax = BASE + PAGE as u64;
    expected.registers.rip = BASE + PAGE as u64;
    let second_input = expected.registers;
    let second_reply = Reply::Random {
        seed: true,
        value: 0xfedc_ba98,
        carry: true,
    };
    expected.complete(selected(&[0x0f, 0xc7, 0xf8]).unwrap(), second_reply);
    let second = Row {
        class: SiteClass::Rdseed,
        bytes: vec![0x0f, 0xc7, 0xf8],
        before: second_input,
        after: expected,
        decision: ProviderDecision::Complete(second_reply.result()),
    };
    gate.provider_mut().rows = [first.clone(), second.clone()].into_iter().collect();
    check_completed(&mut gate, &first);
    assert!(!gate.is_admitted(BASE + PAGE as u64));
    check_completed(&mut gate, &second);
    assert_eq!(gate.read_memory(first_input.rsp, 32).unwrap(), entry_stack);
    assert!(matches!(
        gate.next_event().unwrap(),
        SelectedEvent::Exited(73)
    ));
    assert_eq!(gate.provider().calls, 2);
    assert_eq!(gate.provider().consumed, 2);
    assert_eq!(gate.metrics().scripted_completions, 2);
    assert_eq!(gate.metrics().native_completions, 0);
}

#[test]
fn prefixed_random_and_default_rdpid_keep_embedded_suffix_refusals() {
    for encoding in [
        &[0x66, 0x0f, 0xc7, 0xf0][..],
        &[0x48, 0x0f, 0xc7, 0xf0],
        &[0x41, 0x0f, 0xc7, 0xf1],
        &[0x66, 0x0f, 0xc7, 0xf4],
        &[0x48, 0x0f, 0xc7, 0xf4],
        &[0x66, 0x0f, 0xc7, 0xf8],
        &[0x48, 0x0f, 0xc7, 0xf8],
        &[0x41, 0x0f, 0xc7, 0xf9],
        &[0x66, 0x0f, 0xc7, 0xfc],
        &[0x48, 0x0f, 0xc7, 0xfc],
        &[0xf3, 0x0f, 0xc7, 0xf8],
    ] {
        let directory = Directory::new();
        let mut image = Elf::new(2, false);
        image.emit(encoding);
        image.emit(&[0x0f, 0x0b]);
        let path = image.write(&directory, "suffix-refusal");
        let mut gate = page_gate(
            launch(&path),
            vec![image.facts(BASE)],
            Policy::default(),
            &[],
        );
        let error = gate.next_event().unwrap_err();
        assert!(
            format!("{error:?}").contains("EmbeddedCandidate"),
            "{error:?}"
        );
        assert_eq!(gate.provider().calls, 0);
        assert_eq!(
            gate.read_memory(BASE, image.bytes.len()).unwrap(),
            image.bytes
        );
        assert!(!gate.is_admitted(BASE + PAGE as u64));
        assert_nx(gate.pid(), BASE + PAGE as u64);
    }
}

#[test]
fn selected_bytes_inside_immediates_never_run_or_consume_provider_rows() {
    for embedded in [[0x0f, 0xc7, 0xf0], [0x0f, 0xc7, 0xf8], [0x0f, 0x31, 0x90]] {
        let directory = Directory::new();
        let mut image = Elf::new(2, false);
        let mut immediate = [0x90; 8];
        immediate[..3].copy_from_slice(&embedded);
        image.mov64(0, u64::from_le_bytes(immediate));
        image.emit(&[0x0f, 0x0b]);
        let path = image.write(&directory, "embedded");
        let mut gate = page_gate(
            launch(&path),
            vec![image.facts(BASE)],
            Policy::default(),
            &[],
        );
        let error = gate.next_event().unwrap_err();
        assert!(
            format!("{error:?}").contains("EmbeddedCandidate"),
            "{error:?}"
        );
        assert_eq!(gate.provider().calls, 0);
        assert_eq!(
            gate.read_memory(BASE, image.bytes.len()).unwrap(),
            image.bytes
        );
        assert_nx(gate.pid(), BASE + PAGE as u64);
    }
}

#[test]
fn scripted_fault_keeps_full_uncompleted_state_and_closes_execution() {
    let directory = Directory::new();
    let mut image = Elf::new(2, false);
    image.setup();
    let first = image.emit(&[0x0f, 0xc7, 0xf0]);
    image.emit(&[0x0f, 0x0b]);
    let before = native_seed(&directory, &image, first);
    let row = Row {
        class: SiteClass::Rdrand,
        bytes: vec![0x0f, 0xc7, 0xf0],
        before: before.registers,
        after: before.clone(),
        decision: ProviderDecision::Fault(InstructionFault::InvalidOpcode),
    };
    let path = image.write(&directory, "fault");
    let mut gate = page_gate(
        launch(&path),
        vec![image.facts(BASE)],
        Policy::default(),
        &[row],
    );
    let SelectedEvent::Fault(fault) = gate.next_event().unwrap() else {
        panic!("fault must not become completion");
    };
    assert_eq!(fault.fault, InstructionFault::InvalidOpcode);
    assert_eq!(fault.input.registers(), &before.registers);
    assert_eq!(gate.read_registers().unwrap(), before.registers);
    assert_eq!(gate.read_xstate().unwrap(), before.xstate);
    assert_eq!(gate.read_memory(STACK, STACK_LEN).unwrap(), before.stack);
    assert_eq!(gate.provider().consumed, 1);
    assert!(gate.next_event().is_err());
    assert_eq!(gate.provider().consumed, 1);
}

#[test]
fn exhausted_provider_never_executes_the_original_random_instruction() {
    let directory = Directory::new();
    let mut image = Elf::new(2, false);
    image.setup();
    let first = image.emit(&[0x0f, 0xc7, 0xf0]);
    image.emit(&[0x0f, 0x0b]);
    let before = native_seed(&directory, &image, first);
    let path = image.write(&directory, "exhausted");
    let mut gate = page_gate(
        launch(&path),
        vec![image.facts(BASE)],
        Policy::default(),
        &[],
    );
    let error = gate.next_event().unwrap_err();
    assert!(
        format!("{error:?}").contains("ScriptExhausted"),
        "{error:?}"
    );
    assert_eq!(gate.provider().calls, 1);
    assert_eq!(gate.provider().consumed, 0);
    assert_eq!(gate.read_registers().unwrap(), before.registers);
    assert_eq!(gate.read_xstate().unwrap(), before.xstate);
    assert_eq!(gate.read_memory(STACK, STACK_LEN).unwrap(), before.stack);
    assert_eq!(
        gate.read_memory(BASE + first as u64, 3).unwrap(),
        [0xcc, 0xc7, 0xf0]
    );
    assert!(gate.next_event().is_err());
    assert_eq!(gate.provider().calls, 1);
    assert_eq!(gate.metrics().refusals, 1);
}

#[test]
fn native_seed_owner_retires_terminal_identity_before_assertion_unwinding() {
    let directory = Directory::new();
    let mut image = Elf::new(2, false);
    image.mov32(7, 0);
    image.mov32(0, 60);
    image.emit(&[0x0f, 0x05]);
    let path = image.write(&directory, "native-early-exit");
    let mut native = Native::launch(&path);
    native.trace(libc::PTRACE_CONT, 0, 0);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let status = native.wait();
        assert!(
            libc::WIFSTOPPED(status),
            "the absent marker must still fail"
        );
    }));
    assert!(outcome.is_err());
    assert!(
        native.0.is_none(),
        "terminal wait retires identity before caller assertion"
    );
}

#[test]
fn independent_model_checks_all_random_widths_and_rsp_without_claiming_page_support() {
    // These are pure semantic checks. The native page refusal test above remains
    // mandatory for every prefixed encoding, including RSP/high-register forms.
    for seed in [false, true] {
        for bits in [16, 32, 64] {
            for destination in 0..16 {
                for carry in [false, true] {
                    let mut bytes = Vec::new();
                    if bits == 16 {
                        bytes.push(0x66);
                    }
                    let rex = 0x40
                        | if bits == 64 { 8 } else { 0 }
                        | if destination >= 8 { 1 } else { 0 };
                    if rex != 0x40 {
                        bytes.push(rex);
                    }
                    bytes.extend_from_slice(&[
                        0x0f,
                        0xc7,
                        (if seed { 0xf8 } else { 0xf0 }) | (destination & 7) as u8,
                    ]);
                    // SAFETY: user_regs_struct consists entirely of integer fields.
                    let raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
                    let mut registers: RegisterSnapshot = raw.into();
                    for index in 0..16 {
                        set_reg(&mut registers, index, 0x8899_aabb_ccdd_0000 + index as u64);
                    }
                    registers.cs = 0x33;
                    registers.rip = BASE + PAGE as u64;
                    registers.eflags = 0x1_0ad7;
                    registers.orig_rax = u64::MAX;
                    let value = if !carry {
                        0
                    } else if bits == 16 {
                        0xabcd
                    } else if bits == 32 {
                        0x89ab_cdef
                    } else {
                        0x0123_4567_89ab_cdef
                    };
                    let reply = Reply::Random { seed, value, carry };
                    let mut expected = State {
                        registers,
                        xstate: vec![],
                        stack: vec![],
                    };
                    expected.complete(selected(&bytes).unwrap(), reply);
                    // Production code is the subject, never the expected-state implementation.
                    let actual = SelectedInput::new(
                        liteinst_launch::selected::decode(
                            registers.rip,
                            &bytes,
                            &SyscallAliases::new(),
                        )
                        .unwrap(),
                        registers,
                    )
                    .unwrap()
                    .complete(reply.result())
                    .unwrap();
                    assert_eq!(actual.before, registers);
                    assert_eq!(
                        actual.after, expected.registers,
                        "seed={seed} bits={bits} register={destination} carry={carry}"
                    );
                }
            }
        }
    }
}

fn alias_gate(
    checkpoint: ExecCheckpoint,
    facts: Vec<ImageFacts>,
    aliases: SyscallAliases,
    rows: &[Row],
) -> SelectedPageGate<RecordingProvider> {
    // SAFETY: these fixed single-task fixtures have complete heads, immutable
    // private code, no aliases or code-as-data reads, no handlers or mapping
    // changes, no private-island entries and no independent child controller.
    // TF/RF are clear at original selected entries. Alias outcomes are explicit
    // provider faults; this fixture never executes an alias in the kernel.
    unsafe {
        SelectedPageGate::new(
            checkpoint,
            facts,
            policy(&[SiteClass::Cpuid, SiteClass::Int80, SiteClass::Sysenter]),
            aliases,
            RecordingProvider {
                rows: rows.iter().cloned().collect(),
                ..RecordingProvider::default()
            },
            TIMEOUT,
        )
    }
    .unwrap()
}

#[test]
fn scripted_getpid_gettid_match_independent_full_state_and_replacement_metadata() {
    let directory = Directory::new();
    let mut image = Elf::new(2, false);
    image.setup();
    image.emit(&[0x68, 0xd7, 0x0e, 0, 0]); // Ordinary flags including DF, no TF/RF.
    image.emit(&[0x9d]);
    image.mov64(0, 39); // Linux x86-64 getpid, literal independent ABI number.
    let first = image.emit(&[0x0f, 0x05]);
    image.store(0, 0);
    image.store(1, 8);
    image.mov64(0, 186); // Linux x86-64 gettid.
    image.mov64(1, 0x8877_6655_4433_2211);
    image.mov64(11, 0x9988_7766_5544_3322);
    let second = image.emit(&[0x0f, 0x05]);
    image.emit(&[0x0f, 0x0b]);

    let initial = native_seed(&directory, &image, first);
    assert_eq!(initial.registers.rax, 39);
    assert_eq!(initial.registers.eflags, 0xed7);
    assert_eq!(initial.registers.orig_rax, u64::MAX);
    let mut first_after = initial.clone();
    // These are independent literal replacement effects, not a kernel-exit
    // snapshot: orig_rax remains the pre-instruction no-syscall sentinel.
    first_after.registers.rax = 17;
    first_after.registers.rip = BASE + first as u64 + 2;
    first_after.registers.rcx = first_after.registers.rip;
    first_after.registers.r11 = 0xed7;
    let first_row = Row {
        class: SiteClass::Syscall,
        bytes: vec![0x0f, 0x05],
        before: initial.registers,
        after: first_after.clone(),
        decision: ProviderDecision::Complete(SelectedResult::Syscall(
            SyscallResult::LinuxX64GetId { value: 17 },
        )),
    };
    let mut second_before = first_after;
    second_before.store(SP, 17);
    second_before.store(SP + 8, BASE + first as u64 + 2);
    second_before.registers.rax = 186;
    second_before.registers.rcx = 0x8877_6655_4433_2211;
    second_before.registers.r11 = 0x9988_7766_5544_3322;
    second_before.registers.rip = BASE + second as u64;
    let mut second_after = second_before.clone();
    second_after.registers.rax = 29;
    second_after.registers.rip += 2;
    second_after.registers.rcx = second_after.registers.rip;
    second_after.registers.r11 = 0xed7;
    let second_row = Row {
        class: SiteClass::Syscall,
        bytes: vec![0x0f, 0x05],
        before: second_before.registers,
        after: second_after,
        decision: ProviderDecision::Complete(SelectedResult::Syscall(
            SyscallResult::LinuxX64GetId { value: 29 },
        )),
    };
    let expected = [first_row, second_row];
    let path = image.write(&directory, "scripted-getid");
    let mut gate = page_gate(
        launch(&path),
        vec![image.facts(BASE)],
        Policy::default(),
        &expected,
    );
    for (row, number, result) in [(&expected[0], 39, 17), (&expected[1], 186, 29)] {
        let SelectedEvent::Completed(completed) = gate.next_event().unwrap() else {
            panic!("scripted getid must report a completed replacement");
        };
        assert_eq!(completed.execution, SelectedExecution::Scripted);
        assert_eq!(completed.input.registers(), &row.before);
        assert_eq!(
            completed.input.arguments(),
            SelectedArguments::Syscall {
                abi: SyscallAbi::LinuxX64,
                number,
                arguments: [
                    row.before.rdi,
                    row.before.rsi,
                    row.before.rdx,
                    row.before.r10,
                    row.before.r8,
                    row.before.r9
                ],
            }
        );
        assert_eq!(completed.after, row.after.registers);
        assert_eq!(completed.after.rax, result);
        assert_eq!(completed.after.rcx, row.before.rip + 2);
        assert_eq!(completed.after.r11, row.before.eflags);
        assert_eq!(completed.after.eflags, row.before.eflags);
        assert_eq!(completed.after.orig_rax, u64::MAX);
        assert_ne!(completed.after.orig_rax, number);
        assert_eq!(completed.before_xstate, initial.xstate);
        assert_eq!(completed.xstate, initial.xstate);
        assert_eq!(gate.read_registers().unwrap(), row.after.registers);
        assert_eq!(gate.read_xstate().unwrap(), initial.xstate);
        assert_eq!(gate.read_memory(STACK, STACK_LEN).unwrap(), row.after.stack);
    }
    assert_eq!(gate.provider().calls, 2);
    assert_eq!(gate.provider().consumed, 2);
    assert!(gate.provider().rows.is_empty());
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Syscall), Some(&2));
    assert_eq!(gate.metrics().scripted_completions, 2);
    assert_eq!(gate.metrics().native_completions, 0);
    assert_eq!(gate.metrics().provider_faults, 0);
    assert_eq!(gate.metrics().native_signals, 0);
}

#[test]
fn declared_int80_and_sysenter_dispatch_typed_inputs_and_fault_without_execution() {
    let convention = SysenterConvention::new(
        0x5359_5345_4e54,
        Gpr::R12,
        [Gpr::R13, Gpr::R14, Gpr::R15, Gpr::Rbp, Gpr::Rsp, Gpr::Rbx],
        OperandWidth::Bits32,
    )
    .unwrap();
    for (name, bytes, class, abi, fault) in [
        (
            "int80",
            &[0xcd, 0x80][..],
            SiteClass::Int80,
            SyscallAbi::LinuxI386Int80,
            InstructionFault::InvalidOpcode,
        ),
        (
            "sysenter",
            &[0x0f, 0x34][..],
            SiteClass::Sysenter,
            SyscallAbi::DeclaredSysenter(convention),
            InstructionFault::GeneralProtection { error_code: 0 },
        ),
    ] {
        let directory = Directory::new();
        let mut image = Elf::new(2, false);
        image.setup();
        image.mov64(0, 0x1234_5678_0000_0014);
        let first = image.emit(bytes);
        image.emit(&[0x0f, 0x0b]);
        let before = native_seed(&directory, &image, first);
        let row = Row {
            class,
            bytes: bytes.to_vec(),
            before: before.registers,
            after: before.clone(),
            decision: ProviderDecision::Fault(fault),
        };
        let mut aliases = SyscallAliases::new();
        aliases.declare(BASE + first as u64, abi).unwrap();
        let path = image.write(&directory, name);
        let mut gate = alias_gate(launch(&path), vec![image.facts(BASE)], aliases, &[row]);
        let SelectedEvent::Fault(observed) = gate.next_event().unwrap() else {
            panic!("declared alias provider fault must remain an uncompleted fault");
        };
        assert_eq!(observed.fault, fault);
        assert_eq!(observed.input.registers(), &before.registers);
        assert_eq!(
            observed.input.instruction().logical_pc(),
            BASE + first as u64
        );
        assert_eq!(observed.input.instruction().bytes(), bytes);
        let (number, arguments) = if class == SiteClass::Int80 {
            (
                20,
                [
                    0xccdd_0003,
                    0xccdd_0001,
                    0xccdd_0002,
                    0xccdd_0006,
                    0xccdd_0007,
                    0xccdd_0005,
                ],
            )
        } else {
            (
                0xccdd_000c,
                [
                    0xccdd_000d,
                    0xccdd_000e,
                    0xccdd_000f,
                    0xccdd_0005,
                    SP,
                    0xccdd_0003,
                ],
            )
        };
        assert_eq!(
            observed.input.arguments(),
            SelectedArguments::Syscall {
                abi,
                number,
                arguments,
            }
        );
        assert_eq!(gate.read_registers().unwrap(), before.registers);
        assert_eq!(gate.read_xstate().unwrap(), before.xstate);
        assert_eq!(gate.read_memory(STACK, STACK_LEN).unwrap(), before.stack);
        assert_eq!(
            gate.read_memory(BASE + first as u64, bytes.len()).unwrap(),
            [&[0xcc][..], &bytes[1..]].concat()
        );
        assert_eq!(gate.provider().calls, 1);
        assert_eq!(gate.provider().consumed, 1);
        assert_eq!(gate.metrics().callbacks.get(&class), Some(&1));
        assert_eq!(gate.metrics().provider_faults, 1);
        assert_eq!(gate.metrics().scripted_completions, 0);
        assert_eq!(gate.metrics().native_completions, 0);
        assert_eq!(gate.metrics().native_signals, 0);
        assert!(gate.next_event().is_err());
        assert_eq!(gate.provider().calls, 1);
        assert_eq!(gate.read_registers().unwrap(), before.registers);
    }
}

#[test]
fn undeclared_mismatched_and_misplaced_aliases_refuse_before_publication_or_callback() {
    let sysenter = SyscallAbi::DeclaredSysenter(
        SysenterConvention::new(
            7,
            Gpr::Rax,
            [Gpr::Rdi, Gpr::Rsi, Gpr::Rdx, Gpr::R10, Gpr::R8, Gpr::R9],
            OperandWidth::Bits64,
        )
        .unwrap(),
    );
    for (bytes, correct, wrong) in [
        (&[0xcd, 0x80][..], SyscallAbi::LinuxI386Int80, sysenter),
        (&[0x0f, 0x34][..], sysenter, SyscallAbi::LinuxI386Int80),
    ] {
        for declaration in 0..3 {
            let directory = Directory::new();
            let mut image = Elf::new(2, false);
            let first = image.emit(bytes);
            image.emit(&[0x0f, 0x0b]);
            let mut aliases = SyscallAliases::new();
            let expected = match declaration {
                0 => SemanticsError::UndeclaredAlias,
                1 => {
                    aliases.declare(BASE + first as u64, wrong).unwrap();
                    SemanticsError::AliasClassMismatch
                }
                _ => {
                    aliases.declare(BASE + first as u64 + 1, correct).unwrap();
                    SemanticsError::UndeclaredAlias
                }
            };
            let path = image.write(&directory, "alias-refusal");
            let mut gate = alias_gate(launch(&path), vec![image.facts(BASE)], aliases, &[]);
            let error = gate.next_event().unwrap_err();
            assert!(
                matches!(error, GateError::Selected(actual) if actual == expected),
                "expected {expected:?}, got {error:?}"
            );
            assert_eq!(gate.provider().calls, 0);
            assert_eq!(gate.provider().consumed, 0);
            assert_eq!(gate.gate_metrics().observations, 0);
            assert_eq!(gate.gate_metrics().admitted_pages, 0);
            assert_eq!(
                gate.read_memory(BASE, image.bytes.len()).unwrap(),
                image.bytes
            );
            assert!(!gate.is_admitted(BASE + first as u64));
            assert_nx(gate.pid(), BASE + first as u64);
            assert!(gate.next_event().is_err());
            assert_eq!(gate.provider().calls, 0);
            assert_eq!(gate.metrics().refusals, 1);
        }
    }
}
