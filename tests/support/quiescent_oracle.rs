//! Native x86-64 no-op oracle. This module does not decode or emulate code.
//!
//! Original and patched executions are forked from the same private mappings,
//! so application code, data, stack, TLS bases and return PCs have identical
//! addresses. Every child starts from the same explicit integer and XSAVE state.
//! The caller declares original instruction heads and supplies generated heads;
//! save/restore scaffolding is never a comparison point. Equal step counts are
//! deliberately irrelevant.
//!
//! Coverage: all 16 GPRs, RSP, logical RIP, all RFLAGS except debugger-owned TF
//! and RF, segment selectors/bases, x87 fields/registers, MXCSR, XMM, and all
//! CPUID-described user XSAVE components exposed by NT_X86_XSTATE. XSAVE reserved
//! bytes, software metadata, and the in-use bitmap are not architectural state;
//! an absent component is compared in its architectural initial state. x87 slot
//! padding and the reserved FXSAVE byte 5 are omitted. The ISA grammar in the
//! companion fixtures uses MOV/LEA/NOP/RET and ADD: none leaves flags undefined.
//! Every byte of the application data page and [initial RSP - 128, stack end)
//! is compared. [stack base, initial RSP - 128) is a fixed, declared 60-KiB-ish
//! instrumentation-private stack reserve, bounded by an inaccessible guard page.
//! Declared synchronous faults compare signal, si_code, fault address and the
//! exact logical instruction PC, with the same full state comparison.
//! Application fixtures must not use that reserve. Code pages are checked against
//! exact original/published images at every boundary, not broadly masked out.
//!
//! This is finite native execution evidence, not a concurrent-publication, CET,
//! asynchronous-signal, arbitrary-instruction, or arbitrary-memory oracle.

use core::arch::x86_64::{__cpuid_count, _xgetbv};
use std::cell::Cell;
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const STACK_BYTES: usize = 64 * 1024;
const NT_X86_XSTATE: usize = 0x202;
const CHILD_BUDGET: Duration = Duration::from_secs(15);
const MAX_STEPS: usize = 20_000;
const DEBUGGER_FLAGS: u64 = (1 << 8) | (1 << 16); // TF and RF only.

pub struct Mapping {
    address: *mut u8,
    len: usize,
}

impl Mapping {
    pub fn new(len: usize) -> Self {
        // SAFETY: a fresh private anonymous mapping, never a fixed/clobbering map.
        let address = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED, "oracle mmap failed");
        Self {
            address: address.cast(),
            len,
        }
    }

    pub fn address(&self) -> u64 {
        self.address as u64
    }

    pub fn writable(&self) -> *mut u8 {
        self.address
    }

    pub fn protect(&self, protection: i32) {
        // SAFETY: this object owns the complete page-aligned mapping.
        assert_eq!(
            unsafe { libc::mprotect(self.address.cast(), self.len, protection) },
            0
        );
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: live readable mapping; the test never mutates it concurrently.
        unsafe { core::slice::from_raw_parts(self.address, self.len) }
    }

    fn initialize(&self, offset: usize, bytes: &[u8]) {
        assert!(offset + bytes.len() <= self.len);
        // SAFETY: caller owns this writable mapping and the checked destination.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.address.add(offset), bytes.len())
        };
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: all child executions have ended before their mappings drop.
        assert_eq!(unsafe { libc::munmap(self.address.cast(), self.len) }, 0);
    }
}

pub struct NativeOracle {
    pub code: Mapping,
    data: Mapping,
    stack: Mapping,
    initial_rsp: u64,
    return_pc: u64,
    original_code: Vec<u8>,
}

pub struct Baseline {
    initial: libc::user_regs_struct,
    xstate: Vec<u8>,
    points: Vec<Snapshot>,
    fault: Option<FaultSnapshot>,
}

struct FaultSnapshot {
    signal: i32,
    code: i32,
    address: u64,
    state: Snapshot,
}

struct Snapshot {
    logical_pc: u64,
    registers: libc::user_regs_struct,
    xstate: Vec<u8>,
    data: Vec<u8>,
    application_stack: Vec<u8>,
}

impl NativeOracle {
    pub fn new(code: &[u8]) -> Self {
        assert!(code.len() < PAGE / 2);
        let code_mapping = Mapping::new(PAGE);
        code_mapping.initialize(0, &vec![0xcc; PAGE]);
        code_mapping.initialize(0, code);
        let data = Mapping::new(PAGE);
        data.initialize(
            0,
            &(0..PAGE).map(|i| (i * 37 + 11) as u8).collect::<Vec<_>>(),
        );
        let stack = Mapping::new(STACK_BYTES + PAGE);
        stack.initialize(0, &vec![0x5a; STACK_BYTES + PAGE]);
        // SAFETY: first page is an owned, page-aligned lower stack guard.
        assert_eq!(
            unsafe { libc::mprotect(stack.writable().cast(), PAGE, libc::PROT_NONE) },
            0
        );
        let initial_rsp = stack.address() + STACK_BYTES as u64 - 8;
        let return_pc = code_mapping.address() + (PAGE / 2) as u64;
        stack.initialize(
            (initial_rsp - stack.address()) as usize,
            &return_pc.to_ne_bytes(),
        );
        let original_code = code_mapping.bytes().to_vec();
        Self {
            code: code_mapping,
            data,
            stack,
            initial_rsp,
            return_pc,
            original_code,
        }
    }

    pub fn return_pc(&self) -> u64 {
        self.return_pc
    }

    /// Verify every original-code byte against precisely the authorized edits.
    pub fn assert_publication(&self, edits: &[(u64, Vec<u8>)]) {
        let mut expected = self.original_code.clone();
        for (address, bytes) in edits {
            let offset =
                usize::try_from(address.checked_sub(self.code.address()).unwrap()).unwrap();
            expected[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
        assert_eq!(
            self.code.bytes(),
            expected,
            "publication changed undeclared source bytes"
        );
    }

    /// Capture one original entry. Call for every entry before publishing code.
    /// `heads` includes this entry and every subsequent original instruction,
    /// followed by `return_pc()` after RET. No library decoder constructs it.
    pub fn original(&self, heads: &[u64], seed: u64) -> Baseline {
        self.capture_original(heads, seed, None)
    }

    /// Capture a declared synchronous fault after the last listed instruction
    /// head. The expected (signal, si_code, si_addr) comes from fixture semantics,
    /// not from the patched execution. All state is compared at the fault too.
    pub fn original_fault(&self, heads: &[u64], seed: u64, expected: (i32, i32, u64)) -> Baseline {
        self.capture_original(heads, seed, Some(expected))
    }

    fn capture_original(
        &self,
        heads: &[u64],
        seed: u64,
        expected_fault: Option<(i32, i32, u64)>,
    ) -> Baseline {
        assert!(!heads.is_empty());
        self.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        let child = Tracee::fork();
        let mut initial = child.registers();
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
        initial.rsi = self.data.address() + 512;
        initial.rdi = self.data.address();
        initial.r8 = next();
        initial.r9 = next();
        initial.r10 = next();
        initial.r11 = next();
        initial.r12 = next();
        initial.r13 = next();
        initial.r14 = next();
        initial.r15 = next();
        initial.rsp = self.initial_rsp;
        initial.rip = heads[0];
        initial.orig_rax = u64::MAX;
        // Seed arithmetic flags and alternate DF. Callback dispatch must CLD
        // and restore DF, while fixture instructions themselves do not use it.
        initial.eflags = 0xad7 | ((seed & 1) << 10);
        let xstate = seeded_xstate(child.xstate(), seed);
        child.set_registers(&initial);
        child.set_xstate(&xstate);
        let xstate = child.xstate(); // authenticated kernel-normalized seed
        let points = self.walk(&child, heads, heads, &[], self.code.bytes());
        let fault = expected_fault.map(|expected| {
            let pc = *heads.last().unwrap();
            let fault = self.capture_fault(&child, pc, pc);
            assert_eq!(
                (fault.signal, fault.code, fault.address),
                expected,
                "original fixture did not produce its declared fault"
            );
            fault
        });
        Baseline {
            initial,
            xstate,
            points,
            fault,
        }
    }

    /// Execute a patched sibling. Owned SIGILL faults may be delivered only at
    /// the exact declared routed entries. Other faults are allowed only at a
    /// declared terminal fault boundary, where their complete state is compared.
    /// The native signal router executes normally, under single-step observation.
    pub fn assert_patched(
        &self,
        baseline: &Baseline,
        entry: u64,
        instruction_boundaries: &[(u64, u64)],
        owned_sigill_heads: &[u64],
    ) {
        self.code.protect(libc::PROT_READ | libc::PROT_EXEC);
        let child = Tracee::fork();
        let mut initial = baseline.initial;
        initial.rip = entry;
        child.set_registers(&initial);
        child.set_xstate(&baseline.xstate);
        let logical: Vec<_> = baseline
            .points
            .iter()
            .map(|point| point.logical_pc)
            .collect();
        let generated: Vec<_> = logical
            .iter()
            .map(|pc| {
                instruction_boundaries
                    .iter()
                    .find(|(original, _)| original == pc)
                    .map_or(*pc, |(_, generated)| *generated)
            })
            .collect();
        let actual = self.walk(
            &child,
            &generated,
            &logical,
            owned_sigill_heads,
            self.code.bytes(),
        );
        for (expected, actual) in baseline.points.iter().zip(&actual) {
            assert_state(expected, actual);
        }
        if let Some(expected) = &baseline.fault {
            let actual =
                self.capture_fault(&child, *generated.last().unwrap(), *logical.last().unwrap());
            assert_eq!(
                actual.signal, expected.signal,
                "synchronous fault signal mismatch"
            );
            assert_eq!(
                actual.code, expected.code,
                "synchronous fault si_code mismatch"
            );
            assert_eq!(
                actual.address, expected.address,
                "synchronous fault address mismatch"
            );
            assert_state(&expected.state, &actual.state);
        }
    }

    fn capture_fault(&self, child: &Tracee, physical_pc: u64, logical_pc: u64) -> FaultSnapshot {
        let (signal, code, address) = child.synchronous_fault();
        assert_eq!(
            child.registers().rip,
            physical_pc,
            "fault was not attributed to the declared instruction"
        );
        FaultSnapshot {
            signal,
            code,
            address,
            state: self.snapshot(child, logical_pc, self.code.bytes()),
        }
    }

    fn snapshot(&self, child: &Tracee, logical_pc: u64, expected_code: &[u8]) -> Snapshot {
        assert_eq!(
            child.memory(self.code.address(), PAGE),
            expected_code,
            "unauthorized code write at {logical_pc:#x}"
        );
        Snapshot {
            logical_pc,
            registers: child.registers(),
            xstate: canonical_xstate(&child.xstate()),
            data: child.memory(self.data.address(), PAGE),
            application_stack: child.memory(
                self.initial_rsp - 128,
                (self.stack.address() + self.stack.len as u64 - (self.initial_rsp - 128)) as usize,
            ),
        }
    }

    fn walk(
        &self,
        child: &Tracee,
        boundary_pcs: &[u64],
        logical_pcs: &[u64],
        owned_sigill_heads: &[u64],
        expected_code: &[u8],
    ) -> Vec<Snapshot> {
        let mut points = Vec::new();
        let mut steps = 0;
        for (&boundary, &logical_pc) in boundary_pcs.iter().zip(logical_pcs) {
            while child.registers().rip != boundary {
                assert!(
                    steps < MAX_STEPS,
                    "oracle instruction budget exhausted before {logical_pc:#x}"
                );
                child.step(owned_sigill_heads);
                steps += 1;
            }
            points.push(self.snapshot(child, logical_pc, expected_code));
        }
        points
    }
}

fn assert_state(expected: &Snapshot, actual: &Snapshot) {
    macro_rules! register {
        ($field:ident) => {
            assert_eq!(
                expected.registers.$field,
                actual.registers.$field,
                "{} mismatch at original PC {:#x}",
                stringify!($field),
                expected.logical_pc
            );
        };
    }
    register!(rax);
    register!(rbx);
    register!(rcx);
    register!(rdx);
    register!(rsi);
    register!(rdi);
    register!(rbp);
    register!(rsp);
    register!(r8);
    register!(r9);
    register!(r10);
    register!(r11);
    register!(r12);
    register!(r13);
    register!(r14);
    register!(r15);
    register!(orig_rax);
    register!(cs);
    register!(ss);
    register!(ds);
    register!(es);
    register!(fs);
    register!(gs);
    register!(fs_base);
    register!(gs_base);
    assert_eq!(expected.logical_pc, actual.logical_pc);
    assert_eq!(
        expected.registers.eflags & !DEBUGGER_FLAGS,
        actual.registers.eflags & !DEBUGGER_FLAGS,
        "defined RFLAGS mismatch at {:#x}",
        expected.logical_pc
    );
    assert_eq!(
        expected.xstate, actual.xstate,
        "extended state mismatch at {:#x}",
        expected.logical_pc
    );
    assert_eq!(
        expected.data, actual.data,
        "application data mismatch at {:#x}",
        expected.logical_pc
    );
    assert_eq!(
        expected.application_stack, actual.application_stack,
        "application stack/redzone mismatch at {:#x}",
        expected.logical_pc
    );
}

/// CPUID extents, not the library's saved-state descriptor, define coverage.
// CPUID intrinsics were unsafe at the crate's Rust 1.85 minimum version.
#[allow(unused_unsafe)]
fn components(bytes: &[u8]) -> Vec<(u32, usize, usize)> {
    // SAFETY: x86-64 supports CPUID. NT_X86_XSTATE requires OS XSAVE support.
    let supported = unsafe { __cpuid_count(0xd, 0) };
    // SAFETY: Linux returned a standard XSAVE image, establishing OSXSAVE.
    let enabled = unsafe { _xgetbv(0) } & ((supported.edx as u64) << 32 | supported.eax as u64);
    let mut result = Vec::new();
    for bit in 2..64 {
        if enabled & (1 << bit) == 0 {
            continue;
        }
        // SAFETY: this component is enumerated by CPUID leaf 0xd, subleaf 0.
        let leaf = unsafe { __cpuid_count(0xd, bit) };
        let start = leaf.ebx as usize;
        let len = leaf.eax as usize;
        assert!(start >= 576 && len > 0);
        // Linux may omit dynamically unavailable components (e.g. AMX) from
        // this task's regset; absence must be uniform in both sibling children.
        if start + len <= bytes.len() {
            result.push((bit, start, len));
        }
    }
    result
}

fn seeded_xstate(mut bytes: Vec<u8>, seed: u64) -> Vec<u8> {
    let component_ranges = components(&bytes);
    let metadata = bytes[464..512].to_vec();
    let mxcsr_mask = bytes[28..32].to_vec();
    bytes.fill(0);
    bytes[464..512].copy_from_slice(&metadata);
    bytes[28..32].copy_from_slice(&mxcsr_mask);
    bytes[0..2].copy_from_slice(&0x037f_u16.to_le_bytes());
    bytes[4] = 0xff; // eight non-empty finite 80-bit x87 registers
    bytes[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes());
    for index in 0..8 {
        let start = 32 + 16 * index;
        bytes[start..start + 8]
            .copy_from_slice(&(0x8000_0000_0000_0000_u64 | seed | index as u64).to_le_bytes());
        bytes[start + 8..start + 10].copy_from_slice(&0x3fff_u16.to_le_bytes());
    }
    for (index, byte) in bytes[160..416].iter_mut().enumerate() {
        *byte = (index as u64 * 29 + seed) as u8;
    }
    let mut in_use = 3_u64;
    for (bit, start, len) in component_ranges {
        // AVX and AVX-512 register components accept arbitrary bit patterns.
        // Other components begin in their architectural zero/init state;
        // arbitrary PKRU/AMX configuration could invalidate the fixture itself.
        if matches!(bit, 2 | 5 | 6 | 7) {
            for (index, byte) in bytes[start..start + len].iter_mut().enumerate() {
                *byte = (index as u64 * 17 + seed + bit as u64) as u8;
            }
            in_use |= 1 << bit;
        }
    }
    bytes[512..520].copy_from_slice(&in_use.to_le_bytes());
    bytes
}

fn canonical_xstate(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(
        &bytes[520..528],
        &[0; 8],
        "oracle requires standard non-compacted XSAVE"
    );
    let in_use = u64::from_le_bytes(bytes[512..520].try_into().unwrap());
    let mut canonical = Vec::new();
    let mut x87 = [0_u8; 24];
    x87[0..2].copy_from_slice(&0x037f_u16.to_le_bytes());
    if in_use & 1 != 0 {
        x87.copy_from_slice(&bytes[..24]);
    }
    canonical.extend_from_slice(&x87[..5]);
    canonical.extend_from_slice(&x87[6..24]);
    for index in 0..8 {
        if in_use & 1 == 0 {
            canonical.extend_from_slice(&[0; 10]);
        } else {
            let start = 32 + 16 * index;
            canonical.extend_from_slice(&bytes[start..start + 10]);
        }
    }
    // MXCSR is shared SSE/AVX state and is saved even when one component is init.
    canonical.extend_from_slice(&bytes[24..28]);
    if in_use & 2 == 0 {
        canonical.extend_from_slice(&[0; 256]);
    } else {
        canonical.extend_from_slice(&bytes[160..416]);
    }
    for (bit, start, len) in components(bytes) {
        canonical.extend_from_slice(&bit.to_le_bytes());
        canonical.extend_from_slice(&(len as u64).to_le_bytes());
        if in_use & (1 << bit) == 0 {
            canonical.resize(canonical.len() + len, 0);
        } else {
            canonical.extend_from_slice(&bytes[start..start + len]);
        }
    }
    canonical
}

struct Tracee {
    pid: libc::pid_t,
    deadline: Instant,
    reaped: Cell<bool>,
}

impl Tracee {
    fn fork() -> Self {
        // SAFETY: child calls only async-signal-safe syscalls until ptrace takes
        // over. In particular it does not allocate, lock, panic or run destructors.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "oracle fork failed");
        if pid == 0 {
            // SAFETY: this child requests its direct parent as tracer, stops,
            // and never returns into Rust's multithreaded test harness.
            unsafe {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize) == -1 {
                    libc::_exit(120);
                }
                libc::kill(libc::getpid(), libc::SIGSTOP);
                libc::_exit(121);
            }
        }
        let child = Self {
            pid,
            deadline: Instant::now() + CHILD_BUDGET,
            reaped: Cell::new(false),
        };
        let status = child.wait();
        assert!(
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP,
            "oracle child did not enter ptrace stop: {status:#x}"
        );
        child
    }

    fn wait(&self) -> i32 {
        loop {
            let mut status = 0;
            // SAFETY: exact owned child pid and initialized writable status.
            let result =
                unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WALL) };
            if result == self.pid {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.reaped.set(true);
                }
                return status;
            }
            assert_eq!(
                result,
                0,
                "oracle waitpid failed: {}",
                std::io::Error::last_os_error()
            );
            assert!(
                Instant::now() < self.deadline,
                "oracle child wall deadline exhausted"
            );
            std::thread::sleep(Duration::from_micros(100));
        }
    }

    fn request(&self, request: libc::c_uint, address: usize, data: usize) {
        // SAFETY: all callers supply the pointer/address form required by the
        // request, and this exact child is stopped and owned by this tracer.
        let result = unsafe { libc::ptrace(request, self.pid, address, data) };
        assert_eq!(
            result,
            0,
            "ptrace {request:#x} failed: {}",
            std::io::Error::last_os_error()
        );
    }

    fn registers(&self) -> libc::user_regs_struct {
        // SAFETY: plain integer output structure.
        let mut registers = unsafe { core::mem::zeroed() };
        self.request(libc::PTRACE_GETREGS, 0, (&raw mut registers) as usize);
        registers
    }

    fn set_registers(&self, registers: &libc::user_regs_struct) {
        self.request(
            libc::PTRACE_SETREGS,
            0,
            (registers as *const libc::user_regs_struct) as usize,
        );
    }

    fn xstate(&self) -> Vec<u8> {
        let mut bytes = vec![0_u8; 64 * 1024];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        self.request(
            libc::PTRACE_GETREGSET,
            NT_X86_XSTATE,
            (&raw mut iov) as usize,
        );
        assert!((576..=bytes.len()).contains(&iov.iov_len));
        bytes.truncate(iov.iov_len);
        bytes
    }

    fn set_xstate(&self, bytes: &[u8]) {
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        self.request(
            libc::PTRACE_SETREGSET,
            NT_X86_XSTATE,
            (&raw mut iov) as usize,
        );
        assert_eq!(iov.iov_len, bytes.len());
    }

    fn memory(&self, address: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; len];
        let local = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: address as usize as *mut libc::c_void,
            iov_len: len,
        };
        // SAFETY: local is live writable storage, remote is a fixture-owned
        // mapped range, and this stopped child is ptrace-owned by the caller.
        let read = unsafe { libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        assert_eq!(
            read,
            len as isize,
            "oracle memory read failed: {}",
            std::io::Error::last_os_error()
        );
        bytes
    }

    fn synchronous_fault(&self) -> (i32, i32, u64) {
        self.request(libc::PTRACE_SINGLESTEP, 0, 0);
        let status = self.wait();
        assert!(
            libc::WIFSTOPPED(status),
            "faulting child exited/crashed: {status:#x}"
        );
        let signal = libc::WSTOPSIG(status);
        assert!(
            matches!(
                signal,
                libc::SIGSEGV | libc::SIGBUS | libc::SIGFPE | libc::SIGILL
            ),
            "expected synchronous fault, received signal {signal}"
        );
        // SAFETY: fully initialized native output storage for this stopped child.
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        self.request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
        assert_eq!(info.si_signo, signal);
        // SAFETY: the four accepted synchronous signals select the fault-address
        // siginfo union variant; unrelated/user-sent signals are not fixture inputs.
        (signal, info.si_code, unsafe { info.si_addr() } as usize
            as u64)
    }

    fn step(&self, owned_sigill_heads: &[u64]) {
        self.request(libc::PTRACE_SINGLESTEP, 0, 0);
        let status = self.wait();
        assert!(
            libc::WIFSTOPPED(status),
            "oracle child crashed/exited: wait status {status:#x}"
        );
        let signal = libc::WSTOPSIG(status);
        if signal == libc::SIGILL {
            let pc = self.registers().rip;
            assert!(
                owned_sigill_heads.contains(&pc),
                "unowned SIGILL at {pc:#x}"
            );
            self.request(libc::PTRACE_SINGLESTEP, 0, libc::SIGILL as usize);
            let delivered = self.wait();
            assert!(
                libc::WIFSTOPPED(delivered) && libc::WSTOPSIG(delivered) == libc::SIGTRAP,
                "owned SIGILL delivery failed: wait status {delivered:#x}"
            );
        } else {
            assert_eq!(
                signal,
                libc::SIGTRAP,
                "unexpected signal {signal} at {:#x}",
                self.registers().rip
            );
        }
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        if self.reaped.get() {
            return;
        }
        // SAFETY: exact owned child; kill even on assertion failure so no
        // stopped/running descendants escape a failed oracle or exhausted budget.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            // SAFETY: exact owned child and initialized writable status.
            let result =
                unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WALL) };
            if result == -1
                || result == self.pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
            {
                break;
            }
            if Instant::now() >= deadline {
                // Do not panic again during unwinding; SIGKILL has already been
                // sent. Normal completion requires successful bounded cleanup.
                assert!(std::thread::panicking(), "oracle child could not be reaped");
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[cfg(test)]
mod calibration {
    use super::*;

    fn mutated_instruction(original: &[u8], mutated: &[u8]) {
        assert_eq!(original.len(), mutated.len());
        let mut code = original.to_vec();
        code.push(0xc3);
        let oracle = NativeOracle::new(&code);
        let base = oracle.code.address();
        let baseline = oracle.original(
            &[base, base + original.len() as u64, oracle.return_pc()],
            42,
        );
        oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        oracle.code.initialize(0, mutated);
        oracle.assert_publication(&[(base, mutated.to_vec())]);
        oracle.assert_patched(&baseline, base, &[], &[]);
    }

    // These deliberate semantic mutants calibrate the independent oracle. They
    // are not library refusals counted as positive rewrite coverage.
    #[test]
    #[should_panic(expected = "synchronous fault address mismatch")]
    fn rejects_fault_address_corruption() {
        // MOV EAX,0; MOV RAX,[RAX+0]; RET. Mutating only the displacement
        // preserves all pre-fault boundaries/state but changes si_addr to 8.
        let oracle = NativeOracle::new(&[0xb8, 0, 0, 0, 0, 0x48, 0x8b, 0x40, 0, 0xc3]);
        let base = oracle.code.address();
        let baseline = oracle.original_fault(&[base, base + 5], 42, (libc::SIGSEGV, 1, 0));
        oracle.code.protect(libc::PROT_READ | libc::PROT_WRITE);
        oracle.code.initialize(8, &[8]);
        oracle.assert_publication(&[(base + 8, vec![8])]);
        oracle.assert_patched(&baseline, base, &[], &[]);
    }

    #[test]
    #[should_panic(expected = "rax mismatch")]
    fn rejects_gpr_corruption() {
        mutated_instruction(&[0x48, 0x89, 0xc0], &[0x48, 0xff, 0xc0]); // MOV RAX,RAX -> INC RAX
    }

    #[test]
    #[should_panic(expected = "defined RFLAGS mismatch")]
    fn rejects_defined_flag_corruption() {
        mutated_instruction(&[0x90], &[0xf8]); // NOP -> CLC
    }

    #[test]
    #[should_panic(expected = "extended state mismatch")]
    fn rejects_simd_corruption() {
        mutated_instruction(&[0x0f, 0x1f, 0x00], &[0x0f, 0x57, 0xc0]); // NOP -> XORPS XMM0,XMM0
    }

    #[test]
    #[should_panic(expected = "application data mismatch")]
    fn rejects_application_memory_corruption() {
        mutated_instruction(&[0x0f, 0x1f, 0x00], &[0x48, 0x89, 0x07]); // NOP -> MOV [RDI],RAX
    }

    #[test]
    #[should_panic(expected = "application stack/redzone mismatch")]
    fn rejects_redzone_corruption() {
        mutated_instruction(
            &[0x0f, 0x1f, 0x44, 0x00, 0x00],
            &[0x48, 0x89, 0x44, 0x24, 0x80], // NOP -> MOV [RSP-128],RAX
        );
    }
}
