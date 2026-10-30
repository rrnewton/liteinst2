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
//! Ordered traces additionally exercise DEC, CMP, Jcc and LOOP with defined
//! or preserved flags. They compare every repeated native visit in order.
//! The optional hook log owns a separate zeroed private page and a thread-local
//! pointer/capacity pair; neither changes the application-memory coverage above.
//! Its entire page is checked for the exact event prefix, zero unused bytes and
//! overflow at each restored boundary. The capacity is declared before fork.
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
    seeded_arithmetic_flags: bool,
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
        Self::with_adjacent_code_mappings(code, &[]).0
    }

    /// Reserve source and fixture images together, then transfer disjoint,
    /// page-aligned ownership without ever unmapping a hole. Every region is
    /// within one rel32 envelope; the source snapshot remains exactly one page.
    /// Empty lengths preserve new()'s historical one-page code allocation.
    pub fn with_adjacent_code_mappings(code: &[u8], lengths: &[usize]) -> (Self, Vec<Mapping>) {
        assert!(code.len() < PAGE / 2);
        let mut total = PAGE;
        for &len in lengths {
            assert!(len != 0 && len % PAGE == 0);
            total = total
                .checked_add(len)
                .expect("fixture mapping length overflow");
        }
        assert!(
            total <= i32::MAX as usize,
            "fixture exceeds one rel32 envelope"
        );
        // Reserve collection storage before acquiring the mapping. Later pushes
        // cannot allocate, and every split keeps a live owner for every page.
        let mut adjacent = Vec::with_capacity(lengths.len());
        let mut code_mapping = Mapping::new(total);
        for &len in lengths.iter().rev() {
            let remaining = code_mapping.len.checked_sub(len).unwrap();
            // SAFETY: this tail lies within the sole live private reservation.
            // No syscall releases/replaces it; the two owners become disjoint
            // before the infallible preallocated push below.
            let tail = Mapping {
                address: unsafe { code_mapping.address.add(remaining) },
                len,
            };
            code_mapping.len = remaining;
            adjacent.push(tail);
        }
        adjacent.reverse();
        (Self::from_code_mapping(code, code_mapping), adjacent)
    }

    // Both ordinary and reserved fixtures use the identical one-page snapshot,
    // data, stack, return PC, and unseeded flag initialization.
    fn from_code_mapping(code: &[u8], code_mapping: Mapping) -> Self {
        assert!(code.len() < PAGE / 2);
        assert_eq!(code_mapping.len, PAGE);
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
            seeded_arithmetic_flags: false,
        }
    }

    /// Opt-in campaign initialization. All 4096 application data bytes use
    /// SplitMix64 outputs in little-endian eight-byte chunks. The memory seed
    /// is independent of each trace's GPR/xstate/flag seed. Existing callers
    /// of new() keep the exact historical data and flags initialization.
    pub fn with_seeded_memory_and_flags(code: &[u8], memory_seed: u64) -> Self {
        Self::with_seeded_memory_and_flags_adjacent(code, memory_seed, &[]).0
    }

    /// The identical seeded initializer with privately adjacent code regions.
    pub fn with_seeded_memory_and_flags_adjacent(
        code: &[u8],
        memory_seed: u64,
        lengths: &[usize],
    ) -> (Self, Vec<Mapping>) {
        let (mut oracle, adjacent) = Self::with_adjacent_code_mappings(code, lengths);
        oracle.initialize_seeded_memory_and_flags(memory_seed);
        (oracle, adjacent)
    }

    fn initialize_seeded_memory_and_flags(&mut self, memory_seed: u64) {
        let mut state = memory_seed;
        let mut memory = [0_u8; PAGE];
        for chunk in memory.chunks_exact_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut word = state;
            word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            word ^= word >> 31;
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        self.data.initialize(0, &memory);
        self.seeded_arithmetic_flags = true;
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
        if self.seeded_arithmetic_flags {
            initial.eflags = 0x202 | (seed & 0xcd5);
        }
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
        self.snapshot_with_registers(child, logical_pc, child.registers())
    }

    // Both callers check the complete code page before entering this helper.
    // Registers must be this child's actual full observation at its current
    // stop, with no intervening resume, register write, or signal delivery.
    fn snapshot_with_registers(
        &self,
        child: &Tracee,
        logical_pc: u64,
        registers: libc::user_regs_struct,
    ) -> Snapshot {
        Snapshot {
            logical_pc,
            registers,
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
            let registers = loop {
                let registers = child.registers();
                if registers.rip == boundary {
                    break registers;
                }
                assert!(
                    steps < MAX_STEPS,
                    "oracle instruction budget exhausted before {logical_pc:#x}"
                );
                child.step(owned_sigill_heads);
                steps += 1;
            };
            // The matching GETREGS belongs to this uninterrupted stop.
            assert_eq!(
                child.memory(self.code.address(), PAGE),
                expected_code,
                "unauthorized code write at {logical_pc:#x}"
            );
            points.push(self.snapshot_with_registers(child, logical_pc, registers));
        }
        points
    }
}

#[cfg(test)]
mod campaign_initialization_calibration {
    use super::*;

    fn fnv1a(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3)
        })
    }

    #[test]
    fn campaign_initializer_keeps_default_memory_and_flags_exact() {
        let oracle = NativeOracle::new(&[0x90, 0xc3]);
        assert!(!oracle.seeded_arithmetic_flags);
        let expected: Vec<_> = (0..PAGE).map(|i| (i * 37 + 11) as u8).collect();
        assert_eq!(oracle.data.bytes(), expected);
        for seed in [0, 1, 0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567] {
            let baseline = oracle.original(&[oracle.code.address()], seed);
            assert_eq!(baseline.initial.eflags, 0xad7 | ((seed & 1) << 10));
            assert_eq!(baseline.points[0].registers.eflags, baseline.initial.eflags);
            assert_eq!(baseline.points[0].data, expected);
        }
    }

    #[test]
    fn campaign_initializer_matches_independent_memory_vectors_and_flags() {
        // Golden full-page FNV-1a values and edge words were generated by the
        // separate pure-Python SplitMix64 implementation before native execution.
        for (memory_seed, hash, first, last) in [
            (
                0,
                0xb2eb_6d1c_be26_89f9,
                0xe220_a839_7b1d_cdaf,
                0x4980_af32_6a4b_65d8,
            ),
            (
                u64::MAX,
                0xe71c_8b44_c06d_0ce0,
                0xe4d9_7177_1b65_2c20,
                0x4a3b_4c96_b4eb_3f84,
            ),
        ] {
            let oracle = NativeOracle::with_seeded_memory_and_flags(&[0x90, 0xc3], memory_seed);
            assert!(oracle.seeded_arithmetic_flags);
            assert_eq!(fnv1a(oracle.data.bytes()), hash);
            assert_eq!(
                u64::from_le_bytes(oracle.data.bytes()[..8].try_into().unwrap()),
                first
            );
            assert_eq!(
                u64::from_le_bytes(oracle.data.bytes()[PAGE - 8..].try_into().unwrap()),
                last
            );
            // 0xcd5 sets every opted-in flag without approaching the unchanged
            // xstate initializer's non-wrapping seed-addition limit.
            for state_seed in [0, 0x0cd5, 0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567] {
                let baseline = oracle.original(&[oracle.code.address()], state_seed);
                assert_eq!(baseline.initial.eflags, 0x202 | (state_seed & 0xcd5));
                assert_eq!(baseline.points[0].registers.eflags, baseline.initial.eflags);
                assert_eq!(baseline.points[0].data, oracle.data.bytes());
            }
        }
    }
}

// This shared helper is also compiled by the legacy oracle integration test,
// which intentionally continues using its original linear-boundary API.
#[allow(dead_code)]
mod ordered_trace {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::ops::Range;

    // Additive genuine signal-resume support; legacy entry methods are exact.
    mod saved_signal {
        include!("entry_signal.rs");
    }
    pub use saved_signal::SignalResume;

    // Additive private prepublication parked-context fixture support.
    mod parked_signal {
        include!("parked_signal.rs");
    }
    pub use parked_signal::ParkedPublication;

    // Additive restored-boundary signal oracle; all prior methods stay exact.
    pub mod boundary_signal {
        include!("boundary_signal.rs");
    }

    // Additive Word-sync schedules; every existing method is unchanged.
    mod word_sync {
        include!("word_sync.rs");
    }
    pub type ScheduleKind = word_sync::ScheduleKind;
    pub use word_sync::WordPublication;
    include!("word_trace_method.rs");

    const EVENT_CAPACITY: usize = 128;
    thread_local! {
        static ACTIVE_LOG: Cell<(*mut u64, usize)> = const { Cell::new((core::ptr::null_mut(), 0)) };
    }

    /// One logical callback, also used to declare enabled probes in hook order.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct HookEvent {
        pub probe_id: u64,
        pub logical_pc: u64,
    }

    /// Separate instrumentation-private storage; application memory is still
    /// compared by the unchanged state comparator. Overflow always fails.
    pub struct HookEventLog {
        memory: Mapping,
        capacity: usize,
    }

    impl HookEventLog {
        pub fn new() -> Self {
            Self::with_capacity(EVENT_CAPACITY)
        }

        pub fn with_capacity(capacity: usize) -> Self {
            assert!((1..=EVENT_CAPACITY).contains(&capacity));
            let memory = Mapping::new(PAGE);
            memory.initialize(0, &vec![0; PAGE]);
            Self { memory, capacity }
        }

        fn activate(&self) -> ActiveLog {
            self.memory.initialize(0, &vec![0; PAGE]);
            ActiveLog(ACTIVE_LOG.replace((self.memory.writable().cast(), self.capacity)))
        }

        fn assert_events(&self, child: &Tracee, expected: &[HookEvent]) {
            let bytes = child.memory(self.memory.address(), PAGE);
            let word = |index: usize| {
                u64::from_ne_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
            };
            assert_eq!(word(1), 0, "hook event log overflow");
            let count = usize::try_from(word(0)).unwrap();
            assert!(count <= self.capacity, "invalid hook event count");
            let actual: Vec<_> = (0..count)
                .map(|index| HookEvent {
                    probe_id: word(2 + 2 * index),
                    logical_pc: word(3 + 2 * index),
                })
                .collect();
            assert_eq!(actual, expected, "hook event trace mismatch");
            assert!(
                bytes[(2 + 2 * count) * 8..].iter().all(|&byte| byte == 0),
                "hook event log wrote beyond its declared entries"
            );
        }
    }

    struct ActiveLog((*mut u64, usize));
    impl Drop for ActiveLog {
        fn drop(&mut self) {
            ACTIVE_LOG.set(self.0);
        }
    }

    /// Append from an oracle child's callback without allocation or locking.
    /// The log pointer is inherited from its test thread across fork.
    ///
    /// # Safety
    /// Call only in an oracle child executing under an active HookExpectation.
    /// No concurrent or recursively reentrant writer may access this log.
    pub unsafe fn record_hook_event(probe_id: u64, logical_pc: u64) {
        ACTIVE_LOG.with(|active| {
            let (pointer, capacity) = active.get();
            if pointer.is_null() {
                // SAFETY: fail the isolated child instead of unwinding a C hook.
                unsafe { libc::_exit(122) };
            }
            // SAFETY: activation owns the live private page; all accesses are
            // bounded by EVENT_CAPACITY, which fits entirely inside that page.
            unsafe {
                let count = pointer.read_volatile() as usize;
                if count >= capacity {
                    pointer.add(1).write_volatile(1);
                    return;
                }
                pointer.add(2 + 2 * count).write_volatile(probe_id);
                pointer.add(3 + 2 * count).write_volatile(logical_pc);
                pointer.write_volatile((count + 1) as u64);
            }
        });
    }

    pub struct HookExpectation<'a> {
        pub log: &'a HookEventLog,
        /// Each matching native visit requires these callbacks, in this order.
        pub enabled: &'a [HookEvent],
    }

    /// Complete restored-state boundaries, flattened from any number of images.
    /// Several physical copies may implement one logical instruction. Gateway
    /// PCs are original redirect entries, never state-comparison points.
    #[derive(Default)]
    pub struct TraceMap {
        pub boundaries: Vec<(u64, u64)>, // (logical, physical)
        pub gateways: Vec<u64>,
        pub generated_ranges: Vec<Range<u64>>,
    }

    /// One explicitly authorized internal source relay. The victim extent is
    /// derived from a pristine native execution, never accepted from this record.
    /// Exact independent grammars qualify CS-prefixed MOVABS, JNZ, RIP-relative
    /// loads, MOFFS loads and self-LOOP. Conditional witnesses must establish
    /// fallthrough: a branch's observed destination alone never proves length.
    pub struct SourceRelay<'a> {
        pub logical_pc: u64,
        pub relay_pc: u64,
        pub target: u64,
        pub victim_trace: &'a NativeTrace,
    }

    /// Independent short-original witness; length/grammar are never supplied.
    pub struct ShortSourceRelay<'a> {
        pub logical_pc: u64,
        pub relay_pc: u64,
        pub target: u64,
        pub victim_trace: &'a NativeTrace,
    }

    /// Negative controls only: each variant corrupts an actual captured witness.
    #[cfg(test)]
    pub enum ShortWitnessMutation {
        NoFirstStep,
        InteriorFirstStep,
        RemoveFirstSnapshot,
        RemoveSecondSnapshot,
        RemoveOriginalByte,
        ChangeObservedRax,
        ChangeObservedRcx,
        PartialFetch,
    }

    struct RelayCoordinates {
        logical_pc: u64,
        relay_pc: u64,
        target: u64,
    }

    // Constructed only after the corresponding private relay validator.
    struct ValidatedTrace<'a> {
        map: &'a TraceMap,
        physical: BTreeMap<u64, u64>,
        relay_map: BTreeMap<u64, usize>,
        relays: Vec<RelayCoordinates>,
    }

    impl Mapping {
        /// One checked non-clobbering page attempt for hand-emitted calibration.
        /// Unavailable/nonexact mappings fail; there is no alternative or retry.
        #[cfg(test)]
        pub fn exact_page(address: u64) -> Self {
            assert_eq!(address % PAGE as u64, 0, "unaligned exact fixture page");
            address
                .checked_add(PAGE as u64)
                .expect("exact fixture page overflow");
            let pointer = usize::try_from(address).expect("unrepresentable fixture address");
            // SAFETY: MAP_FIXED_NOREPLACE cannot replace existing ownership.
            let actual = unsafe {
                libc::mmap(
                    pointer as *mut libc::c_void,
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            assert_ne!(
                actual,
                libc::MAP_FAILED,
                "required exact fixture page unavailable"
            );
            // Own even an unexpected returned mapping before any assertion.
            let owned = Self {
                address: actual.cast(),
                len: PAGE,
            };
            assert_eq!(
                owned.address(),
                address,
                "exact fixture page was not honored"
            );
            owned
        }
    }

    pub struct NativeTrace {
        baseline: Baseline,
        heads: BTreeSet<u64>,
        terminals: BTreeSet<u64>,
        source_base: u64,
        original_code: Vec<u8>,
        /// Captured immediately around the first raw PTRACE_SINGLESTEP, before
        /// any subsequent head lookup or snapshot can classify its destination.
        first_step: Option<(u64, u64)>,
    }

    impl NativeTrace {
        pub fn visits(&self) -> Vec<u64> {
            self.baseline
                .points
                .iter()
                .map(|point| point.logical_pc)
                .collect()
        }
    }

    impl NativeOracle {
        /// Execute one native instruction between successive snapshots, even
        /// when a branch returns to the same PC. Every visited PC must be a
        /// declared original head or terminal; no decoder supplies these facts.
        pub fn trace_original(
            &self,
            entry: u64,
            heads: &[u64],
            terminals: &[u64],
            seed: u64,
        ) -> NativeTrace {
            self.assert_publication(&[]);
            let heads: BTreeSet<_> = heads.iter().copied().collect();
            let terminals: BTreeSet<_> = terminals.iter().copied().collect();
            assert!(heads.contains(&entry), "undeclared original trace entry");
            assert!(!terminals.is_empty(), "original trace needs a terminal");
            assert!(
                heads.is_disjoint(&terminals),
                "terminal is an executable head"
            );
            // Reuse the existing seed path exactly; this short-lived child is
            // reaped before tracing begins. The legacy API remains unchanged.
            let mut baseline = self.original(&[entry], seed);
            let child = Tracee::fork();
            child.set_registers(&baseline.initial);
            child.set_xstate(&baseline.xstate);
            baseline.points.clear();
            let mut first_step = None;
            for step in 0..=MAX_STEPS {
                assert!(
                    Instant::now() < child.deadline,
                    "original trace wall deadline exhausted"
                );
                let pc = child.registers().rip;
                assert!(
                    heads.contains(&pc) || terminals.contains(&pc),
                    "original trace reached undeclared instruction {pc:#x}"
                );
                baseline
                    .points
                    .push(self.snapshot(&child, pc, self.code.bytes()));
                if terminals.contains(&pc) {
                    return NativeTrace {
                        baseline,
                        heads,
                        terminals,
                        source_base: self.code.address(),
                        original_code: self.original_code.clone(),
                        first_step,
                    };
                }
                assert!(
                    step < MAX_STEPS,
                    "original trace instruction budget exhausted"
                );
                child.step(&[]);
                if step == 0 {
                    first_step = Some((pc, child.registers().rip));
                }
            }
            unreachable!()
        }

        /// Compare every native visit against the first restored boundary
        /// actually reached. Unexpected boundaries fail immediately; scaffolding
        /// is traversed only within the existing step and child wall budgets.
        pub fn assert_trace(
            &self,
            trace: &NativeTrace,
            entry: u64,
            map: &TraceMap,
            owned_sigill_heads: &[u64],
            hooks: Option<HookExpectation<'_>>,
        ) {
            self.assert_trace_with_relays(trace, entry, map, &[], owned_sigill_heads, hooks);
        }

        /// Add strictly proved source relays to the unchanged ordered oracle.
        /// A relay is checked before its E9 and does not consume a native visit
        /// or callback event. Its next raw step must reach the exact image entry.
        pub fn assert_trace_with_relays(
            &self,
            trace: &NativeTrace,
            entry: u64,
            map: &TraceMap,
            relays: &[SourceRelay<'_>],
            owned_sigill_heads: &[u64],
            hooks: Option<HookExpectation<'_>>,
        ) {
            let physical = self.ordered_physical(trace, map);
            let relay_map = self.validate_relays(trace, map, &physical, relays);
            let coordinates = relays
                .iter()
                .map(|r| RelayCoordinates {
                    logical_pc: r.logical_pc,
                    relay_pc: r.relay_pc,
                    target: r.target,
                })
                .collect();
            self.assert_validated_trace(
                trace,
                entry,
                ValidatedTrace {
                    map,
                    physical,
                    relay_map,
                    relays: coordinates,
                },
                owned_sigill_heads,
                hooks,
            );
        }

        /// Separately proved short relays; the long relay validator is unchanged.
        pub fn assert_trace_with_short_relays(
            &self,
            trace: &NativeTrace,
            entry: u64,
            map: &TraceMap,
            relays: &[ShortSourceRelay<'_>],
            owned_sigill_heads: &[u64],
            hooks: Option<HookExpectation<'_>>,
        ) {
            let physical = self.ordered_physical(trace, map);
            let relay_map = self.validate_short_relays(trace, map, &physical, relays);
            let coordinates = relays
                .iter()
                .map(|r| RelayCoordinates {
                    logical_pc: r.logical_pc,
                    relay_pc: r.relay_pc,
                    target: r.target,
                })
                .collect();
            self.assert_validated_trace(
                trace,
                entry,
                ValidatedTrace {
                    map,
                    physical,
                    relay_map,
                    relays: coordinates,
                },
                owned_sigill_heads,
                hooks,
            );
        }

        fn ordered_physical(&self, trace: &NativeTrace, map: &TraceMap) -> BTreeMap<u64, u64> {
            let logical: BTreeSet<_> = trace.heads.union(&trace.terminals).copied().collect();
            let mut physical = BTreeMap::new();
            for &(original, generated) in &map.boundaries {
                assert!(
                    logical.contains(&original),
                    "undeclared logical restored boundary"
                );
                assert!(
                    physical.insert(generated, original).is_none(),
                    "duplicate physical restored boundary"
                );
                assert!(
                    generated == original
                        || map
                            .generated_ranges
                            .iter()
                            .any(|range| range.contains(&generated)),
                    "restored boundary outside declared generated images"
                );
            }
            for original in logical {
                assert!(
                    physical.values().any(|&pc| pc == original),
                    "missing restored boundary for {original:#x}"
                );
            }
            for &gateway in &map.gateways {
                assert!(trace.heads.contains(&gateway), "undeclared source gateway");
                assert!(
                    !physical.contains_key(&gateway),
                    "gateway is a restored boundary"
                );
            }
            physical
        }

        fn assert_validated_trace(
            &self,
            trace: &NativeTrace,
            entry: u64,
            validated: ValidatedTrace<'_>,
            owned_sigill_heads: &[u64],
            hooks: Option<HookExpectation<'_>>,
        ) {
            let ValidatedTrace {
                map,
                physical,
                relay_map,
                relays,
            } = validated;
            let relays = &relays;
            if let Some(hooks) = &hooks {
                let mut ids = BTreeSet::new();
                for event in hooks.enabled {
                    assert!(
                        trace.heads.contains(&event.logical_pc),
                        "hook outside original heads"
                    );
                    assert!(
                        ids.insert(event.probe_id),
                        "duplicate enabled probe identity"
                    );
                }
            }
            let _active_log = hooks.as_ref().map(|hooks| hooks.log.activate());
            self.code.protect(libc::PROT_READ | libc::PROT_EXEC);
            let child = Tracee::fork();
            let mut initial = trace.baseline.initial;
            initial.rip = entry;
            child.set_registers(&initial);
            child.set_xstate(&trace.baseline.xstate);
            let mut next = 0;
            let mut events = Vec::new();
            let mut relay_visits = BTreeMap::<u64, usize>::new();
            let mut relay_target = None;
            for step in 0..=MAX_STEPS {
                assert!(
                    Instant::now() < child.deadline,
                    "patched trace wall deadline exhausted"
                );
                let pc = child.registers().rip;
                if let Some(target) = relay_target.take() {
                    assert_eq!(
                        pc, target,
                        "source relay did not reach its exact image entry"
                    );
                }
                if let Some(&original) = physical.get(&pc) {
                    let expected = trace
                        .baseline
                        .points
                        .get(next)
                        .expect("extra restored boundary after native trace");
                    assert_eq!(
                        original, expected.logical_pc,
                        "unexpected restored boundary at visit {next}"
                    );
                    assert_state(
                        expected,
                        &self.snapshot(&child, original, self.code.bytes()),
                    );
                    if let Some(hooks) = &hooks {
                        events.extend(
                            hooks
                                .enabled
                                .iter()
                                .filter(|event| event.logical_pc == original)
                                .copied(),
                        );
                        hooks.log.assert_events(&child, &events);
                    }
                    next += 1;
                    if trace.terminals.contains(&original) {
                        assert_eq!(
                            next,
                            trace.baseline.points.len(),
                            "missing native trace visits"
                        );
                        for relay in relays {
                            let required = trace
                                .baseline
                                .points
                                .iter()
                                .filter(|point| point.logical_pc == relay.logical_pc)
                                .count();
                            assert_eq!(
                                relay_visits.get(&relay.relay_pc).copied().unwrap_or(0),
                                required,
                                "missing or duplicate source relay visits"
                            );
                        }
                        return;
                    }
                } else if let Some(&index) = relay_map.get(&pc) {
                    let relay = &relays[index];
                    let expected = trace
                        .baseline
                        .points
                        .get(next)
                        .expect("extra source relay after native trace");
                    assert_eq!(
                        relay.logical_pc, expected.logical_pc,
                        "unexpected source relay at visit {next}"
                    );
                    assert_state(
                        expected,
                        &self.snapshot(&child, relay.logical_pc, self.code.bytes()),
                    );
                    if let Some(hooks) = &hooks {
                        hooks.log.assert_events(&child, &events);
                    }
                    *relay_visits.entry(pc).or_default() += 1;
                    relay_target = Some(relay.target);
                } else if (self.code.address()..self.code.address() + PAGE as u64).contains(&pc) {
                    assert!(
                        map.gateways.contains(&pc),
                        "unclassified source head {pc:#x}"
                    );
                }
                assert!(
                    step < MAX_STEPS,
                    "patched trace instruction budget exhausted"
                );
                child.step(owned_sigill_heads);
            }
            unreachable!()
        }

        /// Trace a genuine signal-frame resume, with unchanged comparisons.
        pub fn trace_original_after_signal(
            &self,
            entry: u64,
            heads: &[u64],
            terminals: &[u64],
            seed: u64,
            signal: &SignalResume,
        ) -> NativeTrace {
            self.assert_publication(&[]);
            let heads: BTreeSet<_> = heads.iter().copied().collect();
            let terminals: BTreeSet<_> = terminals.iter().copied().collect();
            assert!(heads.contains(&entry), "undeclared original trace entry");
            assert!(!terminals.is_empty(), "original trace needs a terminal");
            assert!(
                heads.is_disjoint(&terminals),
                "terminal is an executable head"
            );
            // Reuse the existing seed path exactly; this short-lived child is
            // reaped before tracing begins. The legacy API remains unchanged.
            let mut baseline = self.original(&[entry], seed);
            let child = Tracee::fork();
            child.set_registers(&baseline.initial);
            child.set_xstate(&baseline.xstate);
            signal.resume(self, &child);
            baseline.points.clear();
            let mut first_step = None;
            for step in 0..=MAX_STEPS {
                assert!(
                    Instant::now() < child.deadline,
                    "original trace wall deadline exhausted"
                );
                let pc = child.registers().rip;
                assert!(
                    heads.contains(&pc) || terminals.contains(&pc),
                    "original trace reached undeclared instruction {pc:#x}"
                );
                baseline
                    .points
                    .push(self.snapshot(&child, pc, self.code.bytes()));
                if terminals.contains(&pc) {
                    return NativeTrace {
                        baseline,
                        heads,
                        terminals,
                        source_base: self.code.address(),
                        original_code: self.original_code.clone(),
                        first_step,
                    };
                }
                assert!(
                    step < MAX_STEPS,
                    "original trace instruction budget exhausted"
                );
                child.step(&[]);
                if step == 0 {
                    first_step = Some((pc, child.registers().rip));
                }
            }
            unreachable!()
        }

        /// Resume via witnessed rt_sigreturn, then use the exact existing trace comparator.
        pub fn assert_trace_after_signal(
            &self,
            trace: &NativeTrace,
            entry: u64,
            map: &TraceMap,
            owned_sigill_heads: &[u64],
            hooks: Option<HookExpectation<'_>>,
            signal: &SignalResume,
        ) {
            let relays: &[SourceRelay<'_>] = &[];
            let logical: BTreeSet<_> = trace.heads.union(&trace.terminals).copied().collect();
            let mut physical = BTreeMap::new();
            for &(original, generated) in &map.boundaries {
                assert!(
                    logical.contains(&original),
                    "undeclared logical restored boundary"
                );
                assert!(
                    physical.insert(generated, original).is_none(),
                    "duplicate physical restored boundary"
                );
                assert!(
                    generated == original
                        || map
                            .generated_ranges
                            .iter()
                            .any(|range| range.contains(&generated)),
                    "restored boundary outside declared generated images"
                );
            }
            for original in logical {
                assert!(
                    physical.values().any(|&pc| pc == original),
                    "missing restored boundary for {original:#x}"
                );
            }
            for &gateway in &map.gateways {
                assert!(trace.heads.contains(&gateway), "undeclared source gateway");
                assert!(
                    !physical.contains_key(&gateway),
                    "gateway is a restored boundary"
                );
            }
            let relay_map = self.validate_relays(trace, map, &physical, relays);
            if let Some(hooks) = &hooks {
                let mut ids = BTreeSet::new();
                for event in hooks.enabled {
                    assert!(
                        trace.heads.contains(&event.logical_pc),
                        "hook outside original heads"
                    );
                    assert!(
                        ids.insert(event.probe_id),
                        "duplicate enabled probe identity"
                    );
                }
            }
            let _active_log = hooks.as_ref().map(|hooks| hooks.log.activate());
            self.code.protect(libc::PROT_READ | libc::PROT_EXEC);
            let child = Tracee::fork();
            let mut initial = trace.baseline.initial;
            initial.rip = entry;
            child.set_registers(&initial);
            child.set_xstate(&trace.baseline.xstate);
            signal.resume(self, &child);
            let mut next = 0;
            let mut events = Vec::new();
            let mut relay_visits = BTreeMap::<u64, usize>::new();
            let mut relay_target = None;
            for step in 0..=MAX_STEPS {
                assert!(
                    Instant::now() < child.deadline,
                    "patched trace wall deadline exhausted"
                );
                let pc = child.registers().rip;
                if let Some(target) = relay_target.take() {
                    assert_eq!(
                        pc, target,
                        "source relay did not reach its exact image entry"
                    );
                }
                if let Some(&original) = physical.get(&pc) {
                    let expected = trace
                        .baseline
                        .points
                        .get(next)
                        .expect("extra restored boundary after native trace");
                    assert_eq!(
                        original, expected.logical_pc,
                        "unexpected restored boundary at visit {next}"
                    );
                    assert_state(
                        expected,
                        &self.snapshot(&child, original, self.code.bytes()),
                    );
                    if let Some(hooks) = &hooks {
                        events.extend(
                            hooks
                                .enabled
                                .iter()
                                .filter(|event| event.logical_pc == original)
                                .copied(),
                        );
                        hooks.log.assert_events(&child, &events);
                    }
                    next += 1;
                    if trace.terminals.contains(&original) {
                        assert_eq!(
                            next,
                            trace.baseline.points.len(),
                            "missing native trace visits"
                        );
                        for relay in relays {
                            let required = trace
                                .baseline
                                .points
                                .iter()
                                .filter(|point| point.logical_pc == relay.logical_pc)
                                .count();
                            assert_eq!(
                                relay_visits.get(&relay.relay_pc).copied().unwrap_or(0),
                                required,
                                "missing or duplicate source relay visits"
                            );
                        }
                        return;
                    }
                } else if let Some(&index) = relay_map.get(&pc) {
                    let relay = &relays[index];
                    let expected = trace
                        .baseline
                        .points
                        .get(next)
                        .expect("extra source relay after native trace");
                    assert_eq!(
                        relay.logical_pc, expected.logical_pc,
                        "unexpected source relay at visit {next}"
                    );
                    assert_state(
                        expected,
                        &self.snapshot(&child, relay.logical_pc, self.code.bytes()),
                    );
                    if let Some(hooks) = &hooks {
                        hooks.log.assert_events(&child, &events);
                    }
                    *relay_visits.entry(pc).or_default() += 1;
                    relay_target = Some(relay.target);
                } else if (self.code.address()..self.code.address() + PAGE as u64).contains(&pc) {
                    assert!(
                        map.gateways.contains(&pc),
                        "unclassified source head {pc:#x}"
                    );
                }
                assert!(
                    step < MAX_STEPS,
                    "patched trace instruction budget exhausted"
                );
                child.step(owned_sigill_heads);
            }
            unreachable!()
        }

        /// Witness child publication while the actual signal frame is parked.
        pub fn assert_trace_parked_publication(
            &self,
            trace: &NativeTrace,
            entry: u64,
            map: &TraceMap,
            owned_sigill_heads: &[u64],
            hooks: Option<HookExpectation<'_>>,
            parked: &ParkedPublication,
        ) {
            let relays: &[SourceRelay<'_>] = &[];
            let logical: BTreeSet<_> = trace.heads.union(&trace.terminals).copied().collect();
            let mut physical = BTreeMap::new();
            for &(original, generated) in &map.boundaries {
                assert!(
                    logical.contains(&original),
                    "undeclared logical restored boundary"
                );
                assert!(
                    physical.insert(generated, original).is_none(),
                    "duplicate physical restored boundary"
                );
                assert!(
                    generated == original
                        || map
                            .generated_ranges
                            .iter()
                            .any(|range| range.contains(&generated)),
                    "restored boundary outside declared generated images"
                );
            }
            for original in logical {
                assert!(
                    physical.values().any(|&pc| pc == original),
                    "missing restored boundary for {original:#x}"
                );
            }
            for &gateway in &map.gateways {
                assert!(trace.heads.contains(&gateway), "undeclared source gateway");
                assert!(
                    !physical.contains_key(&gateway),
                    "gateway is a restored boundary"
                );
            }
            let relay_map = self.validate_relays(trace, map, &physical, relays);
            if let Some(hooks) = &hooks {
                let mut ids = BTreeSet::new();
                for event in hooks.enabled {
                    assert!(
                        trace.heads.contains(&event.logical_pc),
                        "hook outside original heads"
                    );
                    assert!(
                        ids.insert(event.probe_id),
                        "duplicate enabled probe identity"
                    );
                }
            }
            let _active_log = hooks.as_ref().map(|hooks| hooks.log.activate());
            self.code.protect(libc::PROT_READ | libc::PROT_EXEC);
            let _parked_active = parked.activate();
            let child = Tracee::fork();
            let mut initial = trace.baseline.initial;
            initial.rip = entry;
            child.set_registers(&initial);
            child.set_xstate(&trace.baseline.xstate);
            parked.publish_and_resume(
                self,
                &child,
                hooks
                    .as_ref()
                    .expect("parked publication requires an active hook log")
                    .log,
            );
            let mut next = 0;
            let mut events = Vec::new();
            let mut relay_visits = BTreeMap::<u64, usize>::new();
            let mut relay_target = None;
            for step in 0..=MAX_STEPS {
                assert!(
                    Instant::now() < child.deadline,
                    "patched trace wall deadline exhausted"
                );
                let pc = child.registers().rip;
                if let Some(target) = relay_target.take() {
                    assert_eq!(
                        pc, target,
                        "source relay did not reach its exact image entry"
                    );
                }
                if let Some(&original) = physical.get(&pc) {
                    let expected = trace
                        .baseline
                        .points
                        .get(next)
                        .expect("extra restored boundary after native trace");
                    assert_eq!(
                        original, expected.logical_pc,
                        "unexpected restored boundary at visit {next}"
                    );
                    assert_state(
                        expected,
                        &self.snapshot(&child, original, parked.expected_source()),
                    );
                    if let Some(hooks) = &hooks {
                        events.extend(
                            hooks
                                .enabled
                                .iter()
                                .filter(|event| event.logical_pc == original)
                                .copied(),
                        );
                        hooks.log.assert_events(&child, &events);
                    }
                    next += 1;
                    if trace.terminals.contains(&original) {
                        assert_eq!(
                            next,
                            trace.baseline.points.len(),
                            "missing native trace visits"
                        );
                        for relay in relays {
                            let required = trace
                                .baseline
                                .points
                                .iter()
                                .filter(|point| point.logical_pc == relay.logical_pc)
                                .count();
                            assert_eq!(
                                relay_visits.get(&relay.relay_pc).copied().unwrap_or(0),
                                required,
                                "missing or duplicate source relay visits"
                            );
                        }
                        return;
                    }
                } else if let Some(&index) = relay_map.get(&pc) {
                    let relay = &relays[index];
                    let expected = trace
                        .baseline
                        .points
                        .get(next)
                        .expect("extra source relay after native trace");
                    assert_eq!(
                        relay.logical_pc, expected.logical_pc,
                        "unexpected source relay at visit {next}"
                    );
                    assert_state(
                        expected,
                        &self.snapshot(&child, relay.logical_pc, parked.expected_source()),
                    );
                    if let Some(hooks) = &hooks {
                        hooks.log.assert_events(&child, &events);
                    }
                    *relay_visits.entry(pc).or_default() += 1;
                    relay_target = Some(relay.target);
                } else if (self.code.address()..self.code.address() + PAGE as u64).contains(&pc) {
                    assert!(
                        map.gateways.contains(&pc),
                        "unclassified source head {pc:#x}"
                    );
                }
                assert!(
                    step < MAX_STEPS,
                    "patched trace instruction budget exhausted"
                );
                child.step(owned_sigill_heads);
            }
            unreachable!()
        }

        /// Consumes an actual capture; no corrupted witness escapes. This seam
        /// never forks or executes generated code. The positive validation and
        /// original owned capture are outside the expected-refusal catcher.
        #[cfg(test)]
        pub fn assert_short_witness_rejected(
            &self,
            trace: &NativeTrace,
            mut witness: NativeTrace,
            map: &TraceMap,
            coordinates: [u64; 3],
            mutation: ShortWitnessMutation,
        ) {
            let [logical_pc, relay_pc, target] = coordinates;
            let physical = self.ordered_physical(trace, map);
            self.validate_short_relays(
                trace,
                map,
                &physical,
                &[ShortSourceRelay {
                    logical_pc,
                    relay_pc,
                    target,
                    victim_trace: &witness,
                }],
            );
            let reason = match mutation {
                ShortWitnessMutation::NoFirstStep => {
                    witness.first_step = None;
                    "short victim lacks native first step"
                }
                ShortWitnessMutation::InteriorFirstStep => {
                    let (victim, next) = witness.first_step.unwrap();
                    witness.first_step = Some((victim.checked_add(1).unwrap(), next));
                    "short witness entry mismatch"
                }
                ShortWitnessMutation::RemoveFirstSnapshot => {
                    witness.baseline.points.remove(0);
                    "short initial logical PC mismatch"
                }
                ShortWitnessMutation::RemoveSecondSnapshot => {
                    witness.baseline.points.truncate(1);
                    "missing short second snapshot"
                }
                ShortWitnessMutation::RemoveOriginalByte => {
                    witness.original_code.pop().unwrap();
                    "foreign short witness page"
                }
                ShortWitnessMutation::ChangeObservedRax => {
                    witness.baseline.points[1].registers.rax ^= 1;
                    "rax mismatch"
                }
                ShortWitnessMutation::ChangeObservedRcx => {
                    witness.baseline.points[1].registers.rcx ^= 1;
                    "rcx mismatch"
                }
                ShortWitnessMutation::PartialFetch => {
                    let victim = self.code.address().checked_add(PAGE as u64 - 6).unwrap();
                    witness.baseline.initial.rip = victim;
                    witness.baseline.points[0].logical_pc = victim;
                    witness.baseline.points[0].registers.rip = victim;
                    witness.first_step = Some((victim, victim.checked_add(6).unwrap()));
                    "short fetch outside source"
                }
            };
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.validate_short_relays(
                    trace,
                    map,
                    &physical,
                    &[ShortSourceRelay {
                        logical_pc,
                        relay_pc,
                        target,
                        victim_trace: &witness,
                    }],
                );
            }))
            .expect_err("corrupted captured short witness accepted");
            let message = failure
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| failure.downcast_ref::<&str>().copied())
                .expect("nontext short refusal");
            assert!(
                message.contains(reason),
                "expected {reason:?}, observed {message:?}"
            );
        }

        fn validate_short_relays(
            &self,
            trace: &NativeTrace,
            map: &TraceMap,
            physical: &BTreeMap<u64, u64>,
            relays: &[ShortSourceRelay<'_>],
        ) -> BTreeMap<u64, usize> {
            let source_start = self.code.address();
            let source_end = source_start.checked_add(PAGE as u64).unwrap();
            let source_range = source_start..source_end;
            assert_eq!(self.original_code.len(), PAGE, "incomplete original page");
            assert_eq!(
                trace.source_base, source_start,
                "foreign short execution trace"
            );
            assert_eq!(
                trace.original_code, self.original_code,
                "foreign short original page"
            );
            let mut expected_page = self.original_code.clone();
            let mut edits = BTreeMap::<u64, u8>::new();
            for relay in relays {
                let next = relay.logical_pc.checked_add(2).expect("short EB overflow");
                assert!(
                    source_range.contains(&relay.logical_pc) && next <= source_end,
                    "short EB outside source"
                );
                let displacement = i8::try_from(i128::from(relay.relay_pc) - i128::from(next))
                    .expect("short EB outside signed reach");
                let offset = usize::try_from(relay.logical_pc - source_start).unwrap();
                let patch = [0xeb, displacement as u8];
                assert_eq!(
                    &self.code.bytes()[offset..offset + 2],
                    &patch,
                    "short selected EB mismatch"
                );
                for (i, byte) in patch.into_iter().enumerate() {
                    let address = relay.logical_pc.checked_add(i as u64).unwrap();
                    if let Some(old) = edits.insert(address, byte) {
                        assert_eq!(old, byte, "incompatible short source overlap");
                    }
                    expected_page[offset + i] = byte;
                }
            }
            let mut result = BTreeMap::new();
            let mut victims = Vec::<Range<u64>>::new();
            for (index, relay) in relays.iter().enumerate() {
                let witness = relay.victim_trace;
                assert_eq!(
                    witness.source_base, source_start,
                    "foreign short victim witness"
                );
                assert_eq!(
                    witness.original_code, self.original_code,
                    "foreign short witness page"
                );
                assert_eq!(
                    witness.heads, trace.heads,
                    "short witness head set mismatch"
                );
                assert_eq!(
                    witness.terminals, trace.terminals,
                    "short witness terminal mismatch"
                );
                let (victim, native_next) = witness
                    .first_step
                    .expect("short victim lacks native first step");
                assert_eq!(
                    witness.baseline.initial.rip, victim,
                    "short witness entry mismatch"
                );
                let before = witness
                    .baseline
                    .points
                    .first()
                    .expect("missing short first snapshot");
                let after = witness
                    .baseline
                    .points
                    .get(1)
                    .expect("missing short second snapshot");
                assert_eq!(
                    before.logical_pc, victim,
                    "short initial logical PC mismatch"
                );
                assert_eq!(
                    before.registers.rip, victim,
                    "short initial raw PC mismatch"
                );
                assert!(
                    source_range.contains(&victim),
                    "short victim outside source"
                );
                let fetch_end = victim.checked_add(10).expect("short fetch overflow");
                assert!(fetch_end <= source_end, "short fetch outside source");
                let offset = usize::try_from(victim - source_start).unwrap();
                let original = self
                    .original_code
                    .get(offset..)
                    .expect("short original bytes missing");
                assert!(original.len() >= 10, "partial short original fetch");
                let prefixes = original.iter().take(4).take_while(|&&b| b == 0x2e).count();
                let opcode = &original[prefixes..];
                let mut registers = before.registers;
                let victim_len = if (1..=4).contains(&prefixes) && opcode.first() == Some(&0xb8) {
                    let immediate = opcode.get(1..5).expect("short MOV immediate missing");
                    registers.rax = u64::from(u32::from_le_bytes(immediate.try_into().unwrap()));
                    prefixes + 5
                } else if prefixes <= 2 && opcode.starts_with(&[0x48, 0x8b, 0x0d]) {
                    let displacement = i32::from_le_bytes(
                        opcode
                            .get(3..7)
                            .expect("short RIP displacement missing")
                            .try_into()
                            .unwrap(),
                    );
                    let len = prefixes + 7;
                    let next = victim.checked_add(len as u64).unwrap();
                    let target = u64::try_from(i128::from(next) + i128::from(displacement))
                        .expect("short RIP target overflow");
                    let start = usize::try_from(
                        target
                            .checked_sub(source_start)
                            .expect("short RIP read below owned source"),
                    )
                    .unwrap();
                    let end = start.checked_add(8).expect("short RIP read overflow");
                    let bytes = self
                        .original_code
                        .get(start..end)
                        .expect("short RIP read outside owned source");
                    registers.rcx = u64::from_le_bytes(bytes.try_into().unwrap());
                    len
                } else if prefixes <= 3 && opcode.starts_with(&[0x0f, 0x85]) {
                    let displacement = i32::from_le_bytes(
                        opcode
                            .get(2..6)
                            .expect("short JNZ displacement missing")
                            .try_into()
                            .unwrap(),
                    );
                    assert_ne!(
                        witness.baseline.initial.eflags & (1 << 6),
                        0,
                        "short JNZ needs initial ZF-set fallthrough witness"
                    );
                    assert_ne!(
                        before.registers.eflags & (1 << 6),
                        0,
                        "short JNZ needs observed ZF-set fallthrough witness"
                    );
                    let len = prefixes + 6;
                    let next = victim.checked_add(len as u64).unwrap();
                    let target = u64::try_from(i128::from(next) + i128::from(displacement))
                        .expect("short JNZ target overflow");
                    assert!(
                        trace.heads.contains(&target) || trace.terminals.contains(&target),
                        "short JNZ target is not declared original entry"
                    );
                    len
                } else {
                    panic!("short victim lacks independent MOV/RIP/JNZ grammar");
                };
                assert!(
                    (6..=9).contains(&victim_len),
                    "short victim length outside6..9"
                );
                let victim_end = victim.checked_add(victim_len as u64).unwrap();
                assert_eq!(
                    native_next, victim_end,
                    "short raw step does not prove full fallthrough"
                );
                assert_eq!(
                    after.logical_pc, victim_end,
                    "short second logical PC mismatch"
                );
                assert_eq!(
                    after.registers.rip, victim_end,
                    "short second raw PC mismatch"
                );
                registers.rip = victim_end;
                let expected_after = Snapshot {
                    logical_pc: victim_end,
                    registers,
                    xstate: before.xstate.clone(),
                    data: before.data.clone(),
                    application_stack: before.application_stack.clone(),
                };
                assert_state(&expected_after, after);
                assert_eq!(
                    relay.relay_pc,
                    victim.checked_add(5).unwrap(),
                    "short relay offset mismatch"
                );
                let victim_range = victim..victim_end;
                assert!(
                    trace.heads.contains(&victim),
                    "undeclared relay victim head"
                );
                assert!(
                    trace.heads.contains(&relay.logical_pc),
                    "undeclared relay logical head"
                );
                assert!(
                    map.gateways.contains(&victim) && map.gateways.contains(&relay.logical_pc),
                    "relay requires both original source gateways"
                );
                assert!(
                    !victim_range.contains(&relay.logical_pc),
                    "selected relay head overlaps victim"
                );
                for &head in trace
                    .heads
                    .iter()
                    .chain(&trace.terminals)
                    .chain(&witness.heads)
                    .chain(&witness.terminals)
                {
                    assert!(
                        head == victim || !victim_range.contains(&head),
                        "original head overlaps relay victim interior"
                    );
                }
                assert!(
                    physical.keys().all(|pc| !victim_range.contains(pc)),
                    "restored boundary overlaps relay victim span"
                );
                assert!(
                    map.gateways
                        .iter()
                        .all(|pc| *pc == victim || !victim_range.contains(pc)),
                    "source gateway overlaps relay victim interior"
                );
                assert!(
                    victims
                        .iter()
                        .all(|range| range.end <= victim || victim_end <= range.start),
                    "overlapping relay victim spans"
                );
                victims.push(victim_range);
                assert!(
                    result.insert(relay.relay_pc, index).is_none(),
                    "duplicate source relay"
                );
                let relay_offset = usize::try_from(relay.relay_pc - source_start).unwrap();
                let relay_bytes = &self.code.bytes()[relay_offset..relay_offset + 5];
                assert_eq!(
                    relay_bytes,
                    exact_e9(relay.relay_pc, relay.target),
                    "short E9 target mismatch"
                );
                let victim_bytes = &self.code.bytes()[offset..offset + 5];
                assert_eq!(victim_bytes[0], 0xe9, "short victim entry is not E9");
                let victim_target = u64::try_from(
                    i128::from(victim)
                        + 5
                        + i128::from(i32::from_le_bytes(victim_bytes[1..].try_into().unwrap())),
                )
                .expect("short victim target overflow");
                assert_ne!(
                    victim_target, relay.target,
                    "victim and selected images coincide"
                );
                let mut owned_images = Vec::<Range<u64>>::new();
                for (target, logical) in [(victim_target, victim), (relay.target, relay.logical_pc)]
                {
                    let images: Vec<_> = map
                        .generated_ranges
                        .iter()
                        .filter(|range| range.start == target)
                        .collect();
                    assert_eq!(images.len(), 1, "relay target is not one exact image entry");
                    let image = images[0];
                    assert!(image.start < image.end, "malformed relay image range");
                    assert!(
                        owned_images
                            .iter()
                            .all(|range| range.end <= image.start || image.end <= range.start),
                        "relay image ranges overlap"
                    );
                    owned_images.push((*image).clone());
                    assert!(
                        image.end <= source_start || source_end <= image.start,
                        "relay image overlaps original source"
                    );
                    assert!(
                        map.boundaries
                            .iter()
                            .any(|&(pc, generated)| pc == logical && image.contains(&generated)),
                        "relay image has no matching logical restored boundary"
                    );
                    assert!(
                        map.boundaries
                            .iter()
                            .all(|&(pc, generated)| !image.contains(&generated) || pc == logical),
                        "relay image owns a different logical instruction"
                    );
                }
                let free = victim_len - 6;
                let mut fixed = [0_u8; 4];
                fixed[free..].copy_from_slice(&expected_page[offset + victim_len..offset + 10]);
                let start =
                    u64::try_from(i128::from(fetch_end) + i128::from(i32::from_le_bytes(fixed)))
                        .expect("short window start overflow");
                let end = start
                    .checked_add(1_u64 << (8 * free))
                    .expect("short window end overflow");
                assert!(
                    (start..end).contains(&relay.target),
                    "short target outside fixed-suffix window"
                );
                let mut patch = exact_e9(victim, victim_target).to_vec();
                patch.extend_from_slice(&exact_e9(relay.relay_pc, relay.target));
                assert_eq!(
                    &patch[victim_len..],
                    &expected_page[offset + victim_len..offset + 10],
                    "short relay changes authenticated successor overlay"
                );
                for (i, byte) in patch.into_iter().enumerate() {
                    let address = victim.checked_add(i as u64).unwrap();
                    if let Some(old) = edits.insert(address, byte) {
                        assert_eq!(old, byte, "incompatible short source overlap");
                    }
                    expected_page[offset + i] = byte;
                }
            }
            assert_eq!(
                self.code.bytes(),
                expected_page,
                "unauthorized short source publication"
            );
            result
        }

        fn validate_relays(
            &self,
            trace: &NativeTrace,
            map: &TraceMap,
            physical: &BTreeMap<u64, u64>,
            relays: &[SourceRelay<'_>],
        ) -> BTreeMap<u64, usize> {
            let source_start = self.code.address();
            let source_end = source_start.checked_add(PAGE as u64).unwrap();
            let source_range = source_start..source_end;
            let mut result = BTreeMap::new();
            let mut victims = Vec::<Range<u64>>::new();
            for (index, relay) in relays.iter().enumerate() {
                let witness = relay.victim_trace;
                assert_eq!(
                    witness.source_base, source_start,
                    "foreign relay victim witness"
                );
                assert_eq!(
                    witness.original_code, self.original_code,
                    "relay witness uses a different original source snapshot"
                );
                assert_eq!(
                    trace.source_base, source_start,
                    "foreign relay execution trace"
                );
                assert_eq!(
                    trace.original_code, self.original_code,
                    "relay execution uses a different original source snapshot"
                );
                let (victim, native_next) = witness
                    .first_step
                    .expect("relay victim lacks a raw native first-step witness");
                assert_eq!(
                    witness.baseline.initial.rip, victim,
                    "relay witness did not enter its victim"
                );
                assert_eq!(
                    witness.baseline.points.first().unwrap().logical_pc,
                    victim,
                    "relay witness omitted its initial instruction"
                );
                assert!(
                    source_range.contains(&victim),
                    "relay victim outside source"
                );
                let offset = usize::try_from(victim - source_start).unwrap();
                let original = &self.original_code[offset..];
                let prefixes = original.iter().take_while(|&&byte| byte == 0x2e).count();
                // Independent literal grammars, never production decoder output.
                // Branch witnesses additionally prove the fallthrough condition;
                // a raw taken branch alone would not establish instruction size.
                let opcode = &original[prefixes..];
                let victim_len = if prefixes <= 5 && opcode.starts_with(&[0x48, 0xb8]) {
                    prefixes + 10 // MOVABS RAX,imm64 (the original grammar)
                } else if (4..=9).contains(&prefixes) && opcode.starts_with(&[0x0f, 0x85]) {
                    assert_ne!(
                        witness.baseline.initial.eflags & (1 << 6),
                        0,
                        "JNZ relay witness must start with ZF set"
                    );
                    prefixes + 6
                } else if (3..=8).contains(&prefixes) && opcode.starts_with(&[0x48, 0x8b, 0x0d]) {
                    prefixes + 7 // MOV RCX,[RIP+disp32]
                } else if prefixes <= 5 && opcode.starts_with(&[0x48, 0xa1]) {
                    prefixes + 10 // MOV RAX,moffs64; witness must complete natively
                } else if (8..=13).contains(&prefixes) && opcode.first() == Some(&0xe2) {
                    assert_eq!(
                        witness.baseline.initial.rcx, 1,
                        "LOOP relay witness must start with RCX one"
                    );
                    let len = prefixes + 2;
                    assert_eq!(
                        opcode.get(1).copied().map(|byte| byte as i8),
                        Some(-(len as i8)),
                        "LOOP relay witness must target its own original head"
                    );
                    len
                } else {
                    panic!(
                        "relay victim is not an independently qualified MOVABS, JNZ, RIP load, MOFFS load or self-LOOP"
                    );
                };
                assert!(
                    (10..=15).contains(&victim_len) && original.len() >= victim_len,
                    "malformed relay victim encoding"
                );
                let victim_end = victim.checked_add(victim_len as u64).unwrap();
                assert_eq!(
                    native_next, victim_end,
                    "native relay victim step disagrees with its exact encoding"
                );
                let victim_range = victim..victim_end;
                assert!(victim_end <= source_end, "relay victim exceeds source");
                assert_eq!(
                    relay.relay_pc,
                    victim.checked_add(5).unwrap(),
                    "relay is not the second five-byte victim jump"
                );
                assert!(
                    relay.relay_pc.checked_add(5).unwrap() <= victim_end,
                    "relay exceeds native victim span"
                );
                assert!(
                    trace.heads.contains(&victim),
                    "undeclared relay victim head"
                );
                assert!(
                    trace.heads.contains(&relay.logical_pc),
                    "undeclared relay logical head"
                );
                assert!(
                    map.gateways.contains(&victim) && map.gateways.contains(&relay.logical_pc),
                    "relay requires both original source gateways"
                );
                assert!(
                    !victim_range.contains(&relay.logical_pc),
                    "selected relay head overlaps victim"
                );
                for &head in trace
                    .heads
                    .iter()
                    .chain(&trace.terminals)
                    .chain(&witness.heads)
                    .chain(&witness.terminals)
                {
                    assert!(
                        head == victim || !victim_range.contains(&head),
                        "original head overlaps relay victim interior"
                    );
                }
                assert!(
                    physical.keys().all(|pc| !victim_range.contains(pc)),
                    "restored boundary overlaps relay victim span"
                );
                assert!(
                    map.gateways
                        .iter()
                        .all(|pc| *pc == victim || !victim_range.contains(pc)),
                    "source gateway overlaps relay victim interior"
                );
                assert!(
                    victims
                        .iter()
                        .all(|range| range.end <= victim || victim_end <= range.start),
                    "overlapping relay victim spans"
                );
                victims.push(victim_range);
                assert!(
                    result.insert(relay.relay_pc, index).is_none(),
                    "duplicate source relay"
                );
                let logical_offset = usize::try_from(
                    relay
                        .logical_pc
                        .checked_sub(source_start)
                        .expect("relay logical head below source"),
                )
                .unwrap();
                let selected = self
                    .code
                    .bytes()
                    .get(logical_offset..logical_offset + 2)
                    .expect("relay logical jump exceeds source");
                assert_eq!(
                    selected[0], 0xeb,
                    "selected relay gateway is not exact EB rel8"
                );
                assert_eq!(
                    i128::from(relay.logical_pc) + 2 + i128::from(selected[1] as i8),
                    i128::from(relay.relay_pc),
                    "selected EB does not reach source relay"
                );
                let relay_offset = usize::try_from(relay.relay_pc - source_start).unwrap();
                let relay_bytes = &self.code.bytes()[relay_offset..relay_offset + 5];
                let expected = exact_e9(relay.relay_pc, relay.target);
                assert_eq!(relay_bytes, expected, "source relay E9 target mismatch");
                let victim_bytes = &self.code.bytes()[offset..offset + 5];
                assert_eq!(victim_bytes[0], 0xe9, "victim entry is not exact E9 rel32");
                let victim_target = u64::try_from(
                    i128::from(victim)
                        + 5
                        + i128::from(i32::from_le_bytes(victim_bytes[1..].try_into().unwrap())),
                )
                .expect("victim E9 target outside address space");
                assert_ne!(
                    victim_target, relay.target,
                    "victim and selected images coincide"
                );
                let mut owned_images = Vec::<Range<u64>>::new();
                for (target, logical) in [(victim_target, victim), (relay.target, relay.logical_pc)]
                {
                    let images: Vec<_> = map
                        .generated_ranges
                        .iter()
                        .filter(|range| range.start == target)
                        .collect();
                    assert_eq!(images.len(), 1, "relay target is not one exact image entry");
                    let image = images[0];
                    assert!(image.start < image.end, "malformed relay image range");
                    assert!(
                        owned_images
                            .iter()
                            .all(|range| range.end <= image.start || image.end <= range.start),
                        "relay image ranges overlap"
                    );
                    owned_images.push((*image).clone());
                    assert!(
                        image.end <= source_start || source_end <= image.start,
                        "relay image overlaps original source"
                    );
                    assert!(
                        map.boundaries
                            .iter()
                            .any(|&(pc, generated)| pc == logical && image.contains(&generated)),
                        "relay image has no matching logical restored boundary"
                    );
                    assert!(
                        map.boundaries
                            .iter()
                            .all(|&(pc, generated)| !image.contains(&generated) || pc == logical),
                        "relay image owns a different logical instruction"
                    );
                }
                assert_eq!(
                    &self.code.bytes()[offset + 10..offset + victim_len],
                    &original[10..victim_len],
                    "relay changed original victim tail"
                );
            }
            result
        }
    }

    fn exact_e9(source: u64, target: u64) -> [u8; 5] {
        let displacement = i32::try_from(i128::from(target) - i128::from(source) - 5)
            .expect("relay target is outside rel32 reach");
        let mut bytes = [0; 5];
        bytes[0] = 0xe9;
        bytes[1..].copy_from_slice(&displacement.to_le_bytes());
        bytes
    }
}

#[allow(unused_imports)] // The legacy oracle integration crate uses its older API.
pub use ordered_trace::*;

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

// Borrowed process-text adapter for the standalone exception fixture.
#[allow(dead_code)]
#[path = "process_text.rs"]
pub mod process_text;

// Additive normal-kernel-exec fixture adapter; all existing oracle bodies remain literal.
#[allow(dead_code)]
#[path = "elf_exec_oracle.rs"]
pub mod elf_exec_oracle;

// Private address-space ownership for the same-function short-neighbor cohort.
#[cfg(test)]
#[allow(dead_code)]
#[path = "neighbor_fixture_arena.rs"]
pub(crate) mod neighbor_fixture_arena;
