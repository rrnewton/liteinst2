//! 28 sibling pairs: all newly emitted gate instructions, before legacy save.
//! This is a finite architectural prefix oracle; never used in timed execution.
use super::inline_clock::InlineProgram;
use super::{CASES, Case, single_main};
use liteinst2::backedge_clock::{CLOCK_CANARY, ClockMode, ClockWords};
use std::arch::x86_64::{__cpuid_count, _xgetbv};
use std::cell::Cell;
use std::path::Path;
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const STACK_BYTES: usize = 64 * 1024;
const NT_X86_XSTATE: usize = 0x202;
const CHILD_BUDGET: Duration = Duration::from_secs(15);
const MAX_STEPS: usize = 20_000;
const DEBUGGER_FLAGS: u64 = (1 << 8) | (1 << 16);
struct Snapshot {
    logical_pc: u64,
    registers: libc::user_regs_struct,
    xstate: Vec<u8>,
    data: Vec<u8>,
    application_stack: Vec<u8>,
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

// Both children inherit only pristine application storage. No clock/control,
// allocation lease, worker, callback TLS or generated image exists before fork.
struct Arena {
    data: u64,
    stack: u64,
}
impl Arena {
    fn new(seed: u64) -> Self {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE + STACK_BYTES + 2 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        let data = p as usize as u64;
        let stack = data + (2 * PAGE) as u64;
        for i in 0..PAGE {
            unsafe {
                (data as usize as *mut u8)
                    .add(i)
                    .write((i as u64 * 37 + seed) as u8)
            };
        }
        for i in 0..STACK_BYTES {
            unsafe {
                (stack as usize as *mut u8)
                    .add(i)
                    .write((i as u64 * 17 + seed) as u8)
            };
        }
        assert_eq!(
            unsafe {
                libc::mprotect(
                    (data + PAGE as u64) as usize as *mut _,
                    PAGE,
                    libc::PROT_NONE,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                libc::mprotect(
                    (stack + STACK_BYTES as u64) as usize as *mut _,
                    PAGE,
                    libc::PROT_NONE,
                )
            },
            0
        );
        Self { data, stack }
    }
}
impl Drop for Arena {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::munmap(self.data as usize as *mut _, PAGE + STACK_BYTES + 2 * PAGE) },
            0
        );
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Ready {
    native: u64,
    source: u64,
    source_len: u64,
    site: u64,
    clock: u64,
    gate: u64,
    fast: u64,
    slow: u64,
    image: u64,
    image_len: u64,
}
impl Tracee {
    fn ready(case: Case, quantum: u64) -> (Self, Ready) {
        single_main();
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // The parent has exactly one thread; no core owner/lock/TLS has been
        // staged. Child constructs all clock/control/image authority afresh.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(pipe[0]);
            }
            let program = InlineProgram::new(case, ClockMode::Stop);
            let lease = unsafe { program.clock.acquire(quantum, 32768) }.unwrap();
            let call = lease.begin_call().unwrap();
            let ready = Ready {
                native: program.inner.native.address,
                source: program.inner.candidate.address,
                source_len: program.inner.candidate.original.len() as u64,
                site: program.inner.site.offset as u64,
                clock: program.clock.address(),
                gate: program.gate.entry,
                fast: program.gate.original_body,
                slow: program.gate.observing_entry,
                image: program.image.0,
                image_len: program.image.1 as u64,
            };
            // This fixed handoff fits PIPE_BUF. Parent reads only after SIGSTOP.
            unsafe {
                if libc::write(
                    pipe[1],
                    (&raw const ready).cast(),
                    std::mem::size_of::<Ready>(),
                ) != std::mem::size_of::<Ready>() as isize
                {
                    libc::_exit(120);
                }
                libc::close(pipe[1]);
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0usize, 0usize) == -1 {
                    libc::_exit(120);
                }
                libc::kill(libc::getpid(), libc::SIGSTOP);
                // Tracer seeds a branch state while both lexical guards live;
                // it always kills/reaps at a boundary, never returns here.
                std::hint::black_box((&program, &lease, &call));
                libc::_exit(121);
            }
        }
        unsafe {
            libc::close(pipe[1]);
        }
        let child = Self {
            pid,
            deadline: Instant::now() + CHILD_BUDGET,
            reaped: Cell::new(false),
        };
        let status = child.wait();
        assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);
        let mut ready = Ready::default();
        let n = unsafe {
            libc::read(
                pipe[0],
                (&raw mut ready).cast(),
                std::mem::size_of::<Ready>(),
            )
        };
        unsafe {
            libc::close(pipe[0]);
        }
        assert_eq!(n, std::mem::size_of::<Ready>() as isize);
        child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        assert_eq!(ready.source_len, case.bytes().len() as u64);
        assert_eq!(
            ready.site,
            super::corpus::admit(&case.bytes(), ready.source)
                .unwrap()
                .offset as u64
        );
        assert!(ready.image_len > 0 && ready.image_len <= 8192);
        assert_eq!(ready.gate, ready.image);
        assert!(ready.fast > ready.gate && ready.slow > ready.gate && ready.fast != ready.slow);
        assert!(
            ready.fast < ready.image + ready.image_len
                && ready.slow < ready.image + ready.image_len
        );
        assert_eq!(
            child.memory(ready.native, ready.source_len as usize),
            case.bytes()
        );
        (child, ready)
    }
    fn finish(self) {
        assert_eq!(unsafe { libc::kill(self.pid, libc::SIGKILL) }, 0);
        let status = self.wait();
        assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);
        assert!(self.reaped.get());
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WALL) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}
fn snapshot(child: &Tracee, arena: &Arena, logical_pc: u64) -> Snapshot {
    Snapshot {
        logical_pc,
        registers: child.registers(),
        xstate: canonical_xstate(&child.xstate()),
        data: child.memory(arena.data, PAGE),
        application_stack: child.memory(arena.stack, STACK_BYTES),
    }
}
fn flags(case: Case, taken: bool, seed: u64) -> u64 {
    // Independent literal arithmetic flags, then independently checked by the
    // existing hardware SETcc suite. No predicate supplies its own expected bit.
    let base = 2 | ((seed & 1) << 2) | ((seed & 1) << 4);
    base | match case {
        Case::Countdown | Case::Signed => {
            if taken {
                0
            } else {
                1 << 6
            }
        }
        Case::Unsigned => u64::from(taken),
        Case::Direct => 0,
    }
}
fn pair(case: Case, taken: bool, remaining: u64, seed: u64) -> (usize, &'static str) {
    single_main();
    let arena = Arena::new(seed);
    // Fork both from the same pristine parent mapping topology, before any
    // XSAVE/data capture allocations. Never transplant a parent clock lease.
    let (original, first) = Tracee::ready(case, remaining);
    let (candidate, second) = Tracee::ready(case, remaining);
    assert_eq!(
        first, second,
        "exact sibling source/image/clock address geometry"
    );
    let mut regs = original.registers();
    regs.rax = 0x1234_5678_9abc_0000 | seed;
    regs.rbx = 0x1122_3344_5566_0000 | seed;
    regs.rcx = 0x9988_7766_5544_0000 | seed;
    regs.rdx = 0x8877_6655_4433_0000 | seed;
    regs.rsi = arena.data + 64;
    regs.rdi = arena.data;
    regs.rbp = arena.stack + 512;
    regs.r8 = 0x101 + seed;
    regs.r9 = 0x202 + seed;
    regs.r10 = 0x303 + seed;
    regs.r11 = 0x404 + seed;
    regs.r12 = 0x505 + seed;
    regs.r13 = 0x606 + seed;
    regs.r14 = 0x707 + seed;
    regs.r15 = 0x808 + seed;
    regs.rsp = arena.stack + STACK_BYTES as u64 - 256;
    regs.orig_rax = u64::MAX;
    regs.eflags = flags(case, taken, seed);
    assert_eq!(
        super::corpus::taken(
            super::corpus::admit(&case.bytes(), first.source)
                .unwrap()
                .condition,
            regs.eflags
        ),
        taken
    );
    regs.rip = first.native + first.site;
    let xstate = seeded_xstate(original.xstate(), seed);
    original.set_registers(&regs);
    original.set_xstate(&xstate);
    let expected = snapshot(&original, &arena, first.native + first.site);
    regs.rip = second.source + second.site;
    candidate.set_registers(&regs);
    candidate.set_xstate(&xstate);
    let source = candidate.memory(second.source, second.source_len as usize);
    let image = candidate.memory(second.image, second.image_len as usize);
    assert_eq!(
        source,
        original.memory(first.source, first.source_len as usize)
    );
    assert_eq!(
        image,
        original.memory(first.image, first.image_len as usize)
    );
    assert_eq!(
        candidate.memory(second.clock, 32),
        [0u8; 24]
            .into_iter()
            .chain(remaining.to_le_bytes())
            .collect::<Vec<_>>()
    );
    let (boundary, label) = if taken && remaining == 1 {
        (second.slow, "zero-before-save")
    } else {
        (second.fast, "fast-before-original-branch")
    };
    let mut steps = 0;
    while candidate.registers().rip != boundary {
        assert!(steps < MAX_STEPS, "unchanged instruction budget exhausted");
        candidate.step(&[]);
        steps += 1;
        let pc = candidate.registers().rip;
        assert!(
            pc == boundary || (second.image..second.image + second.image_len).contains(&pc),
            "gate escaped its owned image"
        );
        assert!(
            pc != if boundary == second.slow {
                second.fast
            } else {
                second.slow
            },
            "wrong path boundary"
        );
    }
    assert!(steps > 0);
    assert_state(
        &expected,
        &snapshot(&candidate, &arena, first.native + first.site),
    );
    let clock = candidate.memory(second.clock, PAGE);
    let words = ClockWords {
        saved_rcx: regs.rcx,
        encounters: 1,
        counted: u64::from(taken),
        remaining: remaining - u64::from(taken),
    };
    let expected_words = [
        words.saved_rcx,
        words.encounters,
        words.counted,
        words.remaining,
    ]
    .into_iter()
    .flat_map(u64::to_le_bytes)
    .collect::<Vec<_>>();
    assert_eq!(&clock[..32], expected_words);
    assert_eq!(&clock[32..], &[CLOCK_CANARY; 4064]);
    assert_eq!(candidate.memory(second.source, source.len()), source);
    assert_eq!(candidate.memory(second.image, image.len()), image);
    assert_eq!(
        candidate.memory(second.native, second.source_len as usize),
        case.bytes()
    );
    original.finish();
    candidate.finish();
    (steps, label)
}
pub(super) fn qualify(output: &Path) {
    let mut rows = String::from("case,taken,remaining,seed,boundary,steps,status\n");
    let mut count = 0;
    for case in CASES {
        let outcomes: &[bool] = if case == Case::Direct {
            &[true]
        } else {
            &[false, true]
        };
        for &taken in outcomes {
            for remaining in [1, 2] {
                for seed in [7, 42] {
                    let (steps, boundary) = pair(case, taken, remaining, seed);
                    rows.push_str(&format!(
                        "{},{taken},{remaining},{seed},{boundary},{steps},PASS\n",
                        case.name()
                    ));
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 28);
    std::fs::write(output.join("gate-controls.csv"), rows).unwrap();
    std::fs::write(output.join("summary.json"),"{\"status\":\"PASS\",\"profile\":\"inline-clock-v1\",\"pairs\":28,\"children\":56,\"comparisons\":28,\"stack_bytes\":65536,\"scope\":\"new-gate-prefix-only\"}\n").unwrap();
    println!("preemption:inline-gates:28-pairs:56-children:28-full-state-prefixes");
}
