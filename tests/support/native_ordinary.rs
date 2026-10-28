//! Finite ordinary leaf adapter. The parent oracle's comparator, XSAVE rules,
//! 15-second deadline, 20,000-step budget and Tracee cleanup are unchanged.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::fd::FromRawFd;

// Complete current library assembly, including the real indirect CALL and C3.
// A change to the production gate requires an explicit adapter review.
pub const GATE_BYTES: &[u8] = &[
    0x53, 0x48, 0x89, 0xfb, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x4c, 0x8b, 0x5b, 0x28, 0x4c, 0x89,
    0x5b, 0x30, 0x48, 0x89, 0x63, 0x38, 0x41, 0xff, 0xd3, 0x48, 0x89, 0x63, 0x40, 0x5b, 0xc3,
];
const GATE_HEADS: &[u64] = &[0, 1, 4, 7, 10, 14, 18, 22, 25, 29, 30];
const AFTER_CALL: u64 = 25;
const OUTER_RET: u64 = 30;
const WIRE_LIMIT: usize = 128 * 1024;

/// Closed fixture profiles, not caller-supplied instruction maps or masks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Legacy,
    Reference { external_id: u64 },
    NativeCall,
}
impl Profile {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Legacy => GATE_BYTES,
            Self::Reference { .. } => reference::STENCIL,
            Self::NativeCall => native_call::STENCIL,
        }
    }
    fn heads(self) -> &'static [u64] {
        match self {
            Self::Legacy => GATE_HEADS,
            Self::Reference { .. } => reference::HEADS,
            Self::NativeCall => native_call::HEADS,
        }
    }
    fn after_call(self) -> u64 {
        match self {
            Self::Legacy => AFTER_CALL,
            Self::Reference { .. } => reference::AFTER_CALL,
            Self::NativeCall => 13,
        }
    }
    fn outer_ret(self) -> u64 {
        match self {
            Self::Legacy => OUTER_RET,
            Self::Reference { .. } => reference::OUTER_RET,
            Self::NativeCall => 14,
        }
    }
    fn pre_call_delta(self) -> u64 {
        match self {
            Self::Legacy => 8,
            Self::Reference { .. } => 24,
            Self::NativeCall => 8,
        }
    }
    fn entry_delta(self) -> u64 {
        self.pre_call_delta() + 8
    }
    fn comparison(self, gate: u64, pc: u64) -> bool {
        self == Self::NativeCall || self == Self::Legacy || !reference::transient(gate, pc)
    }
}

/// Constructed from the actual child-local source certificate and bundle.
/// This is fixture inspection data, never an admission or a forged gate token.
pub struct Ready {
    pub profile: Profile,
    pub entry: u64,
    pub gate: u64,
    pub continuation: u64,
    pub heads: Vec<u64>,
    pub returns: Vec<u64>,
    pub boundaries: Vec<(u64, u64)>,
    /// Full source page(s) first, then complete generated executable images.
    pub immutable: Vec<(u64, Vec<u8>)>,
    pub original_source: Vec<u8>,
}

impl Ready {
    fn validate(&self, candidate: bool) -> BTreeMap<u64, u64> {
        self.validate_profile(
            candidate,
            self.profile.after_call(),
            self.profile.bytes().len(),
        )
    }
    fn validate_profile(
        &self,
        candidate: bool,
        after_call: u64,
        gate_bytes: usize,
    ) -> BTreeMap<u64, u64> {
        assert_eq!(
            self.continuation,
            self.gate.checked_add(after_call).unwrap()
        );
        assert!(!self.heads.is_empty() && self.heads.len() <= 256);
        assert_eq!(self.heads[0], self.entry);
        assert!(self.heads.windows(2).all(|w| w[0] < w[1]));
        assert!((1..=4).contains(&self.returns.len()));
        assert!(self.returns.windows(2).all(|w| w[0] < w[1]));
        assert!(self.returns.iter().all(|r| self.heads.contains(r)));
        assert!((1..=6).contains(&self.immutable.len()));
        let (source, bytes) = &self.immutable[0];
        assert_eq!(source % PAGE as u64, 0);
        assert!(matches!(bytes.len(), PAGE | 8192));
        assert_eq!(bytes.len(), self.original_source.len());
        assert!(
            self.heads
                .iter()
                .all(|p| *source <= *p && *p < *source + bytes.len() as u64)
        );
        let mut ranges = vec![(self.gate, self.gate.checked_add(gate_bytes as u64).unwrap())];
        for (index, (address, bytes)) in self.immutable.iter().enumerate() {
            assert!(!bytes.is_empty() && bytes.len() <= 8192);
            let end = address.checked_add(bytes.len() as u64).unwrap();
            assert!(ranges.iter().all(|&(a, b)| end <= a || b <= *address));
            if index != 0 {
                assert!(candidate);
            }
            ranges.push((*address, end));
        }
        assert_eq!(
            self.boundaries.len(),
            self.heads.len(),
            "one restored point per original head"
        );
        let mut logical = BTreeSet::new();
        let mut physical = BTreeMap::new();
        for &(original, generated) in &self.boundaries {
            assert!(self.heads.contains(&original));
            assert!(
                logical.insert(original),
                "duplicate logical head/RET mapping"
            );
            assert!(
                physical.insert(generated, original).is_none(),
                "duplicate physical mapping"
            );
            assert!(
                generated == original
                    || candidate
                        && self.immutable[1..]
                            .iter()
                            .any(|(a, b)| { *a <= generated && generated < *a + b.len() as u64 }),
                "mapping outside owned generated image"
            );
        }
        assert_eq!(logical, self.heads.iter().copied().collect());
        assert!(
            self.returns.iter().all(|r| logical.contains(r)),
            "missing original RET mapping"
        );
        if !candidate {
            assert_eq!(self.immutable.len(), 1);
            assert_eq!(self.immutable[0].1, self.original_source);
            assert!(self.boundaries.iter().all(|(a, b)| a == b));
        }
        physical
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        let word = |b: &mut Vec<u8>, n: u64| b.extend_from_slice(&n.to_le_bytes());
        match self.profile {
            Profile::Legacy => word(&mut b, 0),
            Profile::NativeCall => word(&mut b, 2),
            Profile::Reference { external_id } => {
                word(&mut b, 1);
                word(&mut b, external_id);
            }
        }
        for n in [self.entry, self.gate, self.continuation] {
            word(&mut b, n);
        }
        for list in [&self.heads, &self.returns] {
            word(&mut b, list.len() as u64);
            for &n in list {
                word(&mut b, n);
            }
        }
        word(&mut b, self.boundaries.len() as u64);
        for &(a, p) in &self.boundaries {
            word(&mut b, a);
            word(&mut b, p);
        }
        word(&mut b, self.immutable.len() as u64);
        for (a, data) in &self.immutable {
            word(&mut b, *a);
            word(&mut b, data.len() as u64);
            b.extend_from_slice(data);
        }
        word(&mut b, self.original_source.len() as u64);
        b.extend_from_slice(&self.original_source);
        assert!(b.len() <= WIRE_LIMIT);
        b
    }

    fn decode(mut bytes: &[u8]) -> Self {
        fn word(b: &mut &[u8]) -> u64 {
            assert!(b.len() >= 8);
            let n = u64::from_le_bytes(b[..8].try_into().unwrap());
            *b = &b[8..];
            n
        }
        fn data(b: &mut &[u8]) -> Vec<u8> {
            let n = usize::try_from(word(b)).unwrap();
            assert!((1..=8192).contains(&n) && n <= b.len());
            let v = b[..n].to_vec();
            *b = &b[n..];
            v
        }
        fn list(b: &mut &[u8]) -> Vec<u64> {
            let n = word(b);
            assert!((1..=256).contains(&n));
            (0..n).map(|_| word(b)).collect()
        }
        let profile = match word(&mut bytes) {
            0 => Profile::Legacy,
            1 => Profile::Reference {
                external_id: word(&mut bytes),
            },
            2 => Profile::NativeCall,
            _ => panic!("unknown ordinary native profile"),
        };
        let (entry, gate, continuation) = (word(&mut bytes), word(&mut bytes), word(&mut bytes));
        let (heads, returns) = (list(&mut bytes), list(&mut bytes));
        let n = word(&mut bytes);
        assert!((1..=256).contains(&n));
        let boundaries = (0..n)
            .map(|_| (word(&mut bytes), word(&mut bytes)))
            .collect();
        let n = word(&mut bytes);
        assert!((1..=6).contains(&n));
        let immutable = (0..n)
            .map(|_| (word(&mut bytes), data(&mut bytes)))
            .collect();
        let original_source = data(&mut bytes);
        assert!(bytes.is_empty(), "no unparsed readiness tail");
        Self {
            profile,
            entry,
            gate,
            continuation,
            heads,
            returns,
            boundaries,
            immutable,
            original_source,
        }
    }
}

fn check_gate(ready: &Ready, bytes: &[u8]) {
    assert_eq!(
        ready.continuation,
        ready.gate.checked_add(ready.profile.after_call()).unwrap()
    );
    assert_eq!(bytes, ready.profile.bytes(), "whole immutable gate");
}

fn same_arguments(a: &libc::user_regs_struct, b: &libc::user_regs_struct) {
    assert_eq!(
        (a.rdi, a.rsi, a.rdx, a.fs_base, a.gs_base),
        (b.rdi, b.rsi, b.rdx, b.fs_base, b.gs_base),
        "actual ready frame/args/TLS identity"
    );
}

fn same_ready(a: &Ready, b: &Ready) {
    assert_eq!(a.profile, b.profile);
    assert_eq!(
        (a.entry, a.gate, a.continuation),
        (b.entry, b.gate, b.continuation)
    );
    assert_eq!(a.heads, b.heads);
    assert_eq!(a.returns, b.returns);
    assert_eq!(a.immutable[0].0, b.immutable[0].0);
    assert_eq!(a.original_source, b.original_source);
}

fn harness_resume_flags(saved: u64, after_ret: u64) -> u64 {
    const TF: u64 = 1 << 8;
    assert_eq!(saved & TF, 0, "ordinary harness did not enable tracing");
    assert_eq!(
        after_ret & !TF,
        saved,
        "outer RET preserves every other flag"
    );
    after_ret & !TF
}

// Subject input is closed independently of the immutable CALL-gate profile.
#[derive(Clone, Copy)]
enum Subject {
    Checksum,
    Cache {
        case: cache::truth::Case,
        deadline: Instant,
    },
    Tree {
        case: call_tree::truth::Case,
        deadline: Instant,
    },
}

/// Parent-owned mappings inherited at the same addresses, live until both reap.
pub struct OrdinaryOracle {
    data: Mapping,
    stack: Mapping,
    seed: u64,
    subject: Subject,
}

/// Passed only to the child-local fixture. No gate private state is exposed.
pub struct ChildContext<'a> {
    oracle: &'a OrdinaryOracle,
    write: i32,
    output: Option<i32>,
    length: usize,
}
impl ChildContext<'_> {
    /// Closed cache identity; no caller-supplied result, mask or address map.
    pub fn cache_case(&self) -> Option<(cache::truth::Case, u64)> {
        match self.oracle.subject {
            Subject::Checksum | Subject::Tree { .. } => None,
            Subject::Cache { case, .. } => Some((case, self.oracle.seed)),
        }
    }
    /// Closed two-function subject; never a caller-provided expected result.
    pub fn tree_case(&self) -> Option<(call_tree::truth::Case, u64)> {
        match self.oracle.subject {
            Subject::Tree { case, .. } => Some((case, self.oracle.seed)),
            Subject::Checksum | Subject::Cache { .. } => None,
        }
    }
    pub fn input(&self) -> &[u8] {
        &self.oracle.data.bytes()[128..128 + self.length]
    }
    pub fn stack_range(&self) -> (u64, u64) {
        (
            self.oracle.stack.address() + PAGE as u64,
            self.oracle.stack.address() + STACK_BYTES as u64,
        )
    }
    pub fn gate_rsp(&self) -> u64 {
        self.oracle.gate_rsp()
    }
    /// One dedicated fixed-size output pipe; take exactly once before ready().
    pub fn reference_output(&mut self) -> reference::Output {
        reference::Output::new(self.output.take().expect("reference result channel"))
    }
    /// Metadata is written before ptrace; the real invoke must follow this stop.
    pub fn ready(self, ready: &Ready) {
        let bytes = ready.encode();
        // SAFETY: the fork branch owns this single pipe endpoint.
        let mut file = unsafe { std::fs::File::from_raw_fd(self.write) };
        file.write_all(&bytes).unwrap();
        drop(file);
        // SAFETY: direct child explicitly requests this exact parent as tracer.
        unsafe {
            assert_eq!(libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize), 0);
            assert_eq!(libc::raise(libc::SIGSTOP), 0);
        }
    }
}

/// Borrowed original-only observations, after both real children have reaped.
/// Source bytes were compared against actual child memory at EVERY unchanged
/// snapshot. Instruction expectations must come from an independent consumer,
/// never this fixture's certificate or relocation map.
pub struct OriginalObservation<'a> {
    pub entry: u64,
    pub continuation: u64,
    pub source_address: u64,
    pub source: &'a [u8],
    pub input_address: u64,
    pub input: &'a [u8],
    data_address: u64,
    stack_address: u64,
    points: &'a [Snapshot],
}
pub struct OriginalStep<'a> {
    pub before: libc::user_regs_struct,
    pub after: libc::user_regs_struct,
    pub data_address: u64,
    pub data: &'a [u8],
    pub stack_address: u64,
    pub stack: &'a [u8],
}
impl OriginalObservation<'_> {
    /// Consecutive actual SINGLESTEP states, including the gate and subject.
    /// Operand reads are reconstructed from these real bytes/registers plus
    /// independently authenticated instruction semantics, not hardware events.
    pub fn steps(&self) -> impl Iterator<Item = OriginalStep<'_>> {
        self.points.windows(2).map(move |pair| OriginalStep {
            before: pair[0].registers,
            after: pair[1].registers,
            data_address: self.data_address,
            data: &pair[0].data,
            stack_address: self.stack_address,
            stack: &pair[0].application_stack,
        })
    }
}

pub struct PairResult {
    pub comparisons: usize,
    pub original_steps: usize,
    pub candidate_steps: usize,
    pub visits: usize,
    pub returns: BTreeSet<u64>,
    pub declared_returns: BTreeSet<u64>,
    pub value: u64,
}

struct Pipe([i32; 2]);
impl Pipe {
    fn new() -> Self {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        Self(fds)
    }
    fn close_write(&mut self) {
        assert_eq!(unsafe { libc::close(self.0[1]) }, 0);
        self.0[1] = -1;
    }
    fn read(&self, child: &Tracee) -> Ready {
        let mut result = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            assert!(Instant::now() < child.deadline, "ready metadata deadline");
            let mut poll = libc::pollfd {
                fd: self.0[0],
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&raw mut poll, 1, 10) };
            assert!(n >= 0);
            if n == 0 {
                continue;
            }
            let n = unsafe { libc::read(self.0[0], buffer.as_mut_ptr().cast(), buffer.len()) };
            assert!(n >= 0);
            if n == 0 {
                break;
            }
            result.extend_from_slice(&buffer[..n as usize]);
            assert!(result.len() <= WIRE_LIMIT);
        }
        Ready::decode(&result)
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        for fd in self.0 {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

struct Walk<'a> {
    child: &'a Tracee,
    steps: usize,
}
impl Walk<'_> {
    fn step(&mut self, phase: &str) {
        assert!(
            self.steps < MAX_STEPS,
            "whole ordinary child 20000-step budget: phase={phase} steps={} rip={:#x} pid={}",
            self.steps,
            self.child.registers().rip,
            self.child.pid
        );
        assert!(Instant::now() < self.child.deadline);
        self.steps += 1;
        self.child.step(&[]);
    }
    fn reach_gate(&mut self, ready: &Ready, phase: &str) -> libc::user_regs_struct {
        while self.child.registers().rip != ready.gate {
            self.step(phase);
        }
        check_gate(
            ready,
            &self.child.memory(ready.gate, ready.profile.bytes().len()),
        );
        self.child.registers()
    }
}

impl OrdinaryOracle {
    pub fn new(seed: u64) -> Self {
        let data = Mapping::new(PAGE);
        let bytes: Vec<_> = (0..PAGE)
            .map(|i| (i as u64 * 37 + 11 + seed) as u8)
            .collect();
        data.initialize(0, &bytes);
        let stack = Mapping::new(STACK_BYTES + PAGE);
        stack.initialize(0, &[0x5a; STACK_BYTES + PAGE]);
        assert_eq!(
            unsafe { libc::mprotect(stack.writable().cast(), PAGE, libc::PROT_NONE) },
            0
        );
        assert_eq!(
            unsafe {
                libc::mprotect(
                    stack.writable().add(STACK_BYTES).cast(),
                    PAGE,
                    libc::PROT_NONE,
                )
            },
            0
        );
        Self {
            data,
            stack,
            seed,
            subject: Subject::Checksum,
        }
    }

    /// Starts the one absolute child deadline BEFORE mappings/input allocation.
    /// Bytes outside this input retain the old complete-page seeded pattern.
    pub fn new_cache(case: cache::truth::Case, seed: u64) -> Self {
        let deadline = Instant::now() + CHILD_BUDGET;
        let mut oracle = Self::new(seed);
        oracle
            .data
            .initialize(128, &cache::truth::input(case, seed));
        oracle.subject = Subject::Cache { case, deadline };
        assert!(Instant::now() < deadline, "cache mapping/input deadline");
        oracle
    }

    pub fn cache_deadline(&self) -> Instant {
        match self.subject {
            Subject::Cache { deadline, .. } => deadline,
            Subject::Checksum | Subject::Tree { .. } => panic!("not a cache subject"),
        }
    }

    /// Fixed full input and Legacy gate. Every old state/return/cleanup check
    /// below remains in the common engine; inspection follows both real reaps.
    pub fn pair_cache<F, O>(&self, setup: F, inspect: O) -> PairResult
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
        O: for<'a> FnOnce(OriginalObservation<'a>),
    {
        assert!(matches!(self.subject, Subject::Cache { .. }));
        self.pair_profile(cache::truth::INPUT_BYTES, setup, inspect, None)
            .0
    }

    /// The closed tree keeps the Legacy CALL gate and starts the same absolute
    /// deadline before allocating either inherited mapping.
    pub fn new_tree(case: call_tree::truth::Case, seed: u64) -> Self {
        let deadline = Instant::now() + CHILD_BUDGET;
        let mut oracle = Self::new(seed);
        oracle
            .data
            .initialize(128, &call_tree::truth::input(case, seed));
        oracle.subject = Subject::Tree { case, deadline };
        assert!(Instant::now() < deadline, "tree mapping/input deadline");
        oracle
    }
    pub fn tree_deadline(&self) -> Instant {
        match self.subject {
            Subject::Tree { deadline, .. } => deadline,
            _ => panic!("not a tree subject"),
        }
    }
    pub fn pair_tree<F, O>(&self, setup: F, inspect: O) -> PairResult
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
        O: for<'a> FnOnce(OriginalObservation<'a>),
    {
        assert!(matches!(self.subject, Subject::Tree { .. }));
        self.pair_profile(call_tree::truth::INPUT_BYTES, setup, inspect, None)
            .0
    }
    /// Same full comparator and budget, with the private no-Frame caller and
    /// a real five-role preserving no-op candidate. No timing runs here.
    pub fn pair_tree_native_call<F, O>(&self, noop: u64, setup: F, inspect: O) -> PairResult
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
        O: for<'a> FnOnce(OriginalObservation<'a>),
    {
        assert!(matches!(self.subject, Subject::Tree { .. }));
        assert_ne!(noop, 0);
        self.pair_profile_requested(
            call_tree::truth::INPUT_BYTES,
            setup,
            inspect,
            None,
            Some(noop),
        )
        .0
    }
    fn stack_start(&self, profile: Profile) -> u64 {
        match self.subject {
            Subject::Tree { .. } => {
                if profile != Profile::NativeCall {
                    assert_eq!(profile, Profile::Legacy);
                }
                self.gate_rsp() - 160
            }
            _ => self.gate_rsp() - profile.entry_delta() - 128,
        }
    }

    fn gate_rsp(&self) -> u64 {
        self.stack.address() + STACK_BYTES as u64 - 8
    }
    fn snapshot(&self, child: &Tracee, ready: &Ready, pc: u64) -> Snapshot {
        check_gate(
            ready,
            &child.memory(ready.gate, ready.profile.bytes().len()),
        );
        for (address, bytes) in &ready.immutable {
            assert_eq!(
                child.memory(*address, bytes.len()),
                *bytes,
                "whole source/image bytes"
            );
        }
        let start = self.stack_start(ready.profile);
        Snapshot {
            logical_pc: pc,
            registers: child.registers(),
            xstate: canonical_xstate(&child.xstate()),
            data: child.memory(self.data.address(), PAGE),
            application_stack: child.memory(
                start,
                (self.stack.address() + STACK_BYTES as u64 - start) as usize,
            ),
        }
    }
    fn armed_frame(
        &self,
        child: &Tracee,
        actual: &libc::user_regs_struct,
        ready: &Ready,
    ) -> Vec<u64> {
        // Read-only observation of the current private repr(C) Frame: fourteen
        // u64 fields. Never expose an arming API or write any private state.
        let words: Vec<_> = child
            .memory(actual.rdi, 14 * 8)
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect();
        assert_eq!(&words[..2], &[1, 1], "first real ARMED invocation");
        assert_ne!(words[2], 0, "actual immutable gate identity");
        assert_eq!(
            &words[3..6],
            &[child.pid as u64, child.pid as u64, ready.entry]
        );
        assert_eq!(&words[6..9], &[0; 3]);
        assert_eq!(
            &words[9..11],
            &[
                self.stack.address() + PAGE as u64,
                self.stack.address() + STACK_BYTES as u64
            ]
        );
        assert_eq!(&words[11..], &[0; 3]);
        words
    }
    fn frame_after(
        &self,
        child: &Tracee,
        actual: &libc::user_regs_struct,
        ready: &Ready,
        armed: &[u64],
        ret: Option<u64>,
    ) {
        let mut expected = armed.to_vec();
        expected[6] = ready.entry;
        expected[7] = self.gate_rsp() - ready.profile.pre_call_delta();
        expected[8] = self.gate_rsp() - ready.profile.pre_call_delta();
        if let Some(pc) = ret {
            expected[0] = 3; // COMPLETED only after existing model postconditions.
            expected[11] = self.gate_rsp() - ready.profile.entry_delta();
            expected[12] = ready.continuation;
            expected[13] = pc;
        }
        let bytes: Vec<_> = expected.iter().flat_map(|n| n.to_le_bytes()).collect();
        assert_eq!(
            child.memory(actual.rdi, bytes.len()),
            bytes,
            "complete private gate state before harness restore"
        );
    }
    fn seed(&self, child: &Tracee, actual: libc::user_regs_struct, length: usize) {
        assert_eq!(actual.rsi, self.data.address() + 128);
        assert_eq!(actual.rdx, length as u64);
        assert_eq!(actual.rsp % 16, 8);
        assert_ne!(actual.rdi, 0, "actual privately armed frame pointer");
        let mut r = actual;
        let mut s = self.seed;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        r.rax = next();
        r.rbx = next();
        r.rcx = next();
        r.rbp = next();
        r.r8 = next();
        r.r9 = next();
        r.r10 = next();
        r.r11 = next();
        r.r12 = next();
        r.r13 = next();
        r.r14 = next();
        r.r15 = next();
        r.rsp = self.gate_rsp();
        r.orig_rax = u64::MAX;
        // Same arithmetic/DF seed as the inherited finite scalar oracle. No
        // string instruction occurs in the admitted body; callback dispatch
        // must clear DF internally and restore the saved application value.
        r.eflags = 0xad7 | ((self.seed & 1) << 10);
        child.set_registers(&r);
        child.set_xstate(&seeded_xstate(child.xstate(), self.seed));
    }

    /// Single-main, lock-free parent; setup is executed only after each fork.
    /// Both children and their pipe endpoints are owned before any parent reads.
    pub fn pair<F>(&self, length: usize, setup: F) -> PairResult
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
    {
        self.pair_with_original(length, setup, |_| {})
    }

    /// Same pair/state/cleanup contract; optional source-independent inspection
    /// borrows already captured original state only after both normal reaps.
    pub fn pair_with_original<F, O>(&self, length: usize, setup: F, inspect: O) -> PairResult
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
        O: for<'a> FnOnce(OriginalObservation<'a>),
    {
        assert!(matches!(self.subject, Subject::Checksum));
        self.pair_profile(length, setup, inspect, None).0
    }

    fn pair_profile<F, O>(
        &self,
        length: usize,
        setup: F,
        inspect: O,
        reference: Option<(Instant, u64)>,
    ) -> (PairResult, Option<reference::Stats>)
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
        O: for<'a> FnOnce(OriginalObservation<'a>),
    {
        self.pair_profile_requested(length, setup, inspect, reference, None)
    }
    fn pair_profile_requested<F, O>(
        &self,
        length: usize,
        setup: F,
        inspect: O,
        reference: Option<(Instant, u64)>,
        native_noop: Option<u64>,
    ) -> (PairResult, Option<reference::Stats>)
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
        O: for<'a> FnOnce(OriginalObservation<'a>),
    {
        if native_noop.is_some() {
            assert!(reference.is_none());
            assert!(matches!(self.subject, Subject::Tree { .. }));
        }
        match self.subject {
            Subject::Checksum => {
                assert!(matches!(length, 1 | 64));
            }
            Subject::Cache { deadline, .. } => {
                assert_eq!(length, cache::truth::INPUT_BYTES);
                assert!(reference.is_none(), "cache uses only the Legacy gate");
                assert!(Instant::now() < deadline, "cache pre-fork deadline");
            }
            Subject::Tree { deadline, .. } => {
                assert_eq!(length, call_tree::truth::INPUT_BYTES);
                assert!(reference.is_none(), "tree uses only the Legacy gate");
                assert!(Instant::now() < deadline, "tree pre-fork deadline");
            }
        }
        if let Some((deadline, _)) = reference {
            assert!(Instant::now() < deadline);
        }
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            libc::c_long::from(std::process::id())
        );
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        let mut pipes = [Pipe::new(), Pipe::new()];
        let mut outputs = reference.map(|_| [Pipe::new(), Pipe::new()]);
        let deadline = match self.subject {
            Subject::Checksum => reference.map_or_else(|| Instant::now() + CHILD_BUDGET, |r| r.0),
            Subject::Cache { deadline, .. } => deadline,
            Subject::Tree { deadline, .. } => deadline,
        };
        let mut pids = [0; 2];
        for index in 0..2 {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                for (n, pipe) in pipes.iter().enumerate() {
                    unsafe {
                        libc::close(pipe.0[0]);
                    }
                    if n != index {
                        unsafe {
                            libc::close(pipe.0[1]);
                        }
                    }
                }
                if let Some(outputs) = &outputs {
                    for (n, pipe) in outputs.iter().enumerate() {
                        unsafe {
                            libc::close(pipe.0[0]);
                        }
                        if n != index {
                            unsafe {
                                libc::close(pipe.0[1]);
                            }
                        }
                    }
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    setup(
                        index == 1,
                        ChildContext {
                            oracle: self,
                            write: pipes[index].0[1],
                            output: outputs.as_ref().map(|p| p[index].0[1]),
                            length,
                        },
                    );
                }));
                // Do not unwind inherited parent mappings or sibling guards.
                unsafe {
                    libc::_exit(if result.is_ok() { 0 } else { 122 });
                }
            }
            if pid < 0 {
                if index == 1 {
                    drop(Tracee {
                        pid: pids[0],
                        deadline,
                        reaped: Cell::new(false),
                    });
                }
                panic!("ordinary fixture fork failed");
            }
            pids[index] = pid;
        }
        // No allocation/read/validation occurred between the two parent forks.
        let children = pids.map(|pid| Tracee {
            pid,
            deadline,
            reaped: Cell::new(false),
        });
        for pipe in &mut pipes {
            pipe.close_write();
        }
        if let Some(outputs) = &mut outputs {
            for pipe in outputs {
                pipe.close_write();
            }
            assert!(Instant::now() < deadline, "reference setup deadline");
        }
        let original = pipes[0].read(&children[0]);
        let candidate = pipes[1].read(&children[1]);
        for child in &children {
            let status = child.wait();
            assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);
            child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        }
        let original_map = original.validate(false);
        let candidate_map = candidate.validate(true);
        same_ready(&original, &candidate);
        let profile = if native_noop.is_some() {
            Profile::NativeCall
        } else {
            reference.map_or(Profile::Legacy, |(_, external_id)| Profile::Reference {
                external_id,
            })
        };
        assert_eq!(original.profile, profile, "requested fixture profile");
        let mut tree_witnesses = if matches!(self.subject, Subject::Tree { .. }) {
            Some([
                if native_noop.is_some() {
                    call_tree::Witness::new_native(&original, self.gate_rsp())
                } else {
                    call_tree::Witness::new(&original, self.gate_rsp())
                },
                if native_noop.is_some() {
                    call_tree::Witness::new_native(&candidate, self.gate_rsp())
                } else {
                    call_tree::Witness::new(&candidate, self.gate_rsp())
                },
            ])
        } else {
            None
        };
        let mut a = Walk {
            child: &children[0],
            steps: 0,
        };
        let mut b = Walk {
            child: &children[1],
            steps: 0,
        };
        let ar = a.reach_gate(&original, "reach_original_gate");
        let br = b.reach_gate(&candidate, "reach_candidate_gate");
        same_arguments(&ar, &br);
        let ax = a.child.xstate();
        let bx = b.child.xstate();
        assert_eq!(ax.len(), bx.len());
        let aw = a.child.memory(ar.rsp, 8);
        let bw = b.child.memory(br.rsp, 8);
        let frames = if native_noop.is_some() {
            native_call::arguments(&ar, &original, self.data.address() + 128, length);
            native_call::arguments(&br, &candidate, self.data.address() + 128, length);
            None
        } else {
            Some([
                self.armed_frame(a.child, &ar, &original),
                self.armed_frame(b.child, &br, &candidate),
            ])
        };
        let mut witnesses = match profile {
            Profile::Legacy | Profile::NativeCall => None,
            Profile::Reference { external_id } => {
                assert_eq!(ar.rcx, br.rcx, "actual same-address reference cells");
                Some([
                    reference::Witness::new(
                        self,
                        a.child,
                        &original,
                        ar,
                        &frames.as_ref().unwrap()[0],
                        external_id,
                        false,
                    ),
                    reference::Witness::new(
                        self,
                        b.child,
                        &candidate,
                        br,
                        &frames.as_ref().unwrap()[1],
                        external_id,
                        true,
                    ),
                ])
            }
        };
        self.seed(a.child, ar, length);
        self.seed(b.child, br, length);
        if witnesses.is_some() {
            reference::seed_argument(a.child, ar);
            reference::seed_argument(b.child, br);
        }
        let native_initial = native_noop.map(|noop| {
            assert_eq!(a.child.memory(noop, 1), [0xc3]);
            assert_eq!(b.child.memory(noop, 1), [0xc3]);
            [a.child.registers(), b.child.registers()]
        });
        let mut native_callbacks = Vec::new();
        let mut outer_calls = [0_usize; 2];
        let mut points = Vec::new();
        let mut reference_points = Vec::new();
        let mut visits = Vec::new();
        let mut returns = BTreeSet::new();
        loop {
            let pc = a.child.registers().rip;
            let logical = if profile.heads().iter().any(|p| original.gate + p == pc) {
                pc
            } else {
                *original_map
                    .get(&pc)
                    .expect("original escaped exact ordinary heads/gate")
            };
            if original.heads.contains(&logical) {
                visits.push(logical);
            }
            if original.returns.contains(&logical) {
                returns.insert(logical);
            }
            let point = self.snapshot(a.child, &original, logical);
            if let Some(witnesses) = &mut witnesses {
                witnesses[0].observe(a.child, &original, &point);
                reference_points.push(reference::copy_snapshot(&point));
            }
            if profile.comparison(original.gate, pc) {
                points.push(point);
            }
            if pc == original.gate + profile.outer_ret() {
                break;
            }
            let transfer = tree_witnesses
                .as_ref()
                .and_then(|w| w[0].before(a.child, pc));
            let outer = native_noop
                .and_then(|_| native_call::before_outer(a.child, &original, self.gate_rsp()));
            a.step("original_body");
            if let Some(before) = outer {
                native_call::after_outer(a.child, &original, before);
                outer_calls[0] += 1;
            }
            if let Some(transfer) = transfer {
                tree_witnesses.as_mut().unwrap()[0].after(a.child, transfer);
            }
        }
        let mut next = 0;
        loop {
            let pc = b.child.registers().rip;
            if let Some(noop) = native_noop {
                if pc == noop {
                    native_call::callback(
                        b.child,
                        &candidate,
                        noop,
                        self.gate_rsp(),
                        &mut native_callbacks,
                    );
                }
            }
            let logical = if profile.heads().iter().any(|p| candidate.gate + p == pc) {
                Some(pc)
            } else {
                candidate_map.get(&pc).copied()
            };
            if let Some(logical) = logical {
                let point = self.snapshot(b.child, &candidate, logical);
                if let Some(witnesses) = &mut witnesses {
                    witnesses[1].observe(b.child, &candidate, &point);
                }
                if profile.comparison(candidate.gate, pc) {
                    let expected = points.get(next).expect("extra candidate restored boundary");
                    assert_eq!(
                        logical, expected.logical_pc,
                        "ordered original visits, including loops/RET"
                    );
                    assert_state(expected, &point);
                    next += 1;
                }
                if pc == candidate.gate + profile.outer_ret() {
                    break;
                }
            }
            let transfer = tree_witnesses
                .as_ref()
                .and_then(|w| w[1].before(b.child, pc));
            let outer = native_noop
                .and_then(|_| native_call::before_outer(b.child, &candidate, self.gate_rsp()));
            b.step("candidate_body");
            if let Some(before) = outer {
                native_call::after_outer(b.child, &candidate, before);
                outer_calls[1] += 1;
            }
            if let Some(transfer) = transfer {
                tree_witnesses.as_mut().unwrap()[1].after(b.child, transfer);
            }
        }
        assert_eq!(next, points.len(), "all original boundary comparisons");
        if let Some(witnesses) = &tree_witnesses {
            for witness in witnesses {
                assert_eq!(witness.finish(), 3, "CALL and both real subject RETs");
            }
            assert_eq!(
                returns,
                BTreeSet::from([original.entry + 22, original.entry + 70])
            );
            if native_noop.is_some() {
                assert_eq!(outer_calls, [1, 1], "both actual outer CALLs");
                assert_eq!(
                    native_callbacks,
                    [
                        original.entry,
                        original.entry + 32,
                        original.entry + 70,
                        original.entry + 14,
                        original.entry + 22
                    ]
                );
                native_call::stencil(
                    &points,
                    original.gate,
                    original.entry,
                    self.stack_start(profile),
                );
                for (child, seeded) in [a.child, b.child].into_iter().zip(native_initial.unwrap()) {
                    native_call::callee_saves(&seeded, &child.registers());
                }
            } else {
                let [af, bf] = frames.as_ref().unwrap();
                self.frame_after(a.child, &ar, &original, af, None);
                call_tree::frame_after(b.child, &br, &candidate, bf, self.gate_rsp());
            }
        } else {
            assert_eq!(returns.len(), 1, "one real subject RET per call");
            let [af, bf] = frames.as_ref().unwrap();
            self.frame_after(a.child, &ar, &original, af, None);
            self.frame_after(b.child, &br, &candidate, bf, returns.first().copied());
        }
        let value = match self.subject {
            Subject::Checksum => {
                self.data.bytes()[128..128 + length]
                    .iter()
                    .map(|b| u64::from(b ^ 0x5a))
                    .sum::<u64>()
                    ^ 0x9e37_79b9_7f4a_7c15
            }
            Subject::Cache { case, .. } => {
                assert_eq!(
                    &self.data.bytes()[128..128 + length],
                    &cache::truth::input(case, self.seed)
                );
                cache::truth::scalar(case, self.seed)
            }
            Subject::Tree { case, .. } => {
                assert_eq!(
                    &self.data.bytes()[128..128 + length],
                    &call_tree::truth::input(case, self.seed)
                );
                call_tree::truth::scalar(case, self.seed)
            }
        };
        let expected_records = witnesses.as_ref().map(|w| {
            [
                w[0].record(value, None),
                w[1].record(value, returns.first().copied()),
            ]
        });
        for (walk, ready, saved, xstate, word) in [
            (&mut a, &original, ar, ax, aw),
            (&mut b, &candidate, br, bx, bw),
        ] {
            let actual = walk.child.registers();
            assert_eq!(actual.rip, ready.gate + profile.outer_ret());
            assert_eq!(actual.rsp, self.gate_rsp());
            assert_eq!(actual.rax, value);
            assert_eq!(
                walk.child.memory(self.data.address(), PAGE),
                self.data.bytes()
            );
            assert_eq!(
                walk.child.memory(saved.rsp, 8),
                word,
                "real harness return word unchanged"
            );
            let continuation = u64::from_le_bytes(word.as_slice().try_into().unwrap());
            let mut restored = saved;
            restored.rax = actual.rax;
            restored.rip = actual.rip; // Still the actual outer C3, never its continuation.
            walk.child.set_registers(&restored);
            walk.child.set_xstate(&xstate);
            walk.step("outer_return"); // Execute the actual outer RET on its own original stack.
            let after = walk.child.registers();
            assert_eq!(after.rip, continuation);
            assert_eq!(after.rsp, saved.rsp.checked_add(8).unwrap());
            assert_eq!(after.rax, value);
            assert_eq!(
                walk.child.memory(saved.rsp, 8),
                word,
                "RET did not rewrite return word"
            );
            // The explicit outer-RET SINGLESTEP can leave TF set. Remove only
            // that debugger bit after proving every other flag still equals
            // this child's saved harness flags with TF clear. No application state
            // comparison or return instruction is skipped or repaired here.
            let mut continuation_registers = after;
            continuation_registers.eflags = harness_resume_flags(saved.eflags, after.eflags);
            walk.child.set_registers(&continuation_registers);
            walk.child.request(libc::PTRACE_CONT, 0, 0);
            let status = walk.child.wait();
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "real invoke validation failed {status:#x}; saved_flags={:#x} after_ret_flags={:#x} stopped={:?}",
                saved.eflags,
                after.eflags,
                if libc::WIFSTOPPED(status) {
                    let registers = walk.child.registers();
                    let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
                    walk.child
                        .request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
                    Some((registers.rip, registers.eflags, info.si_code, walk.steps))
                } else {
                    None
                }
            );
            assert!(walk.child.reaped.get());
            let mut status = 0;
            assert_eq!(
                unsafe {
                    libc::waitpid(
                        walk.child.pid,
                        &raw mut status,
                        libc::WNOHANG | libc::__WALL,
                    )
                },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
        if matches!(self.subject, Subject::Cache { .. }) {
            assert!(Instant::now() < deadline, "cache complete reaps deadline");
        }
        if matches!(self.subject, Subject::Tree { .. }) {
            assert!(Instant::now() < deadline, "tree complete reaps deadline");
        }
        let reference_stats = expected_records.map(|expected| {
            let pipes = outputs.as_ref().expect("owned reference result pipes");
            for index in 0..2 {
                let actual = reference::read_record(&pipes[index], &children[index]);
                reference::check_record(&actual, &expected[index]);
            }
            assert!(Instant::now() < deadline, "reference complete deadline");
            reference::Stats {
                reader_checks: 4,
                timestamp_joins: 4,
                records: 2,
            }
        });
        inspect(OriginalObservation {
            entry: original.entry,
            continuation: original.continuation,
            source_address: original.immutable[0].0,
            source: &original.original_source,
            input_address: self.data.address() + 128,
            input: &self.data.bytes()[128..128 + length],
            data_address: self.data.address(),
            stack_address: self.stack_start(profile),
            points: if reference_stats.is_some() {
                &reference_points
            } else {
                &points
            },
        });
        if reference_stats.is_some() {
            assert!(Instant::now() < deadline, "reference inspection deadline");
        }
        if matches!(self.subject, Subject::Cache { .. }) {
            assert!(
                Instant::now() < deadline,
                "cache trace/model inspection deadline"
            );
        }
        if matches!(self.subject, Subject::Tree { .. }) {
            assert!(
                Instant::now() < deadline,
                "tree trace/model inspection deadline"
            );
        }
        (
            PairResult {
                comparisons: next,
                original_steps: a.steps,
                candidate_steps: b.steps,
                visits: visits.len(),
                returns,
                declared_returns: original.returns.into_iter().collect(),
                value,
            },
            reference_stats,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_harness_resume_only_removes_debugger_tf() {
        assert_eq!(harness_resume_flags(0x203, 0x303), 0x203);
        assert_eq!(harness_resume_flags(0x203, 0x203), 0x203);
        assert!(std::panic::catch_unwind(|| harness_resume_flags(0x303, 0x303)).is_err());
        for bit in 0..64 {
            if bit != 8 {
                assert!(
                    std::panic::catch_unwind(|| harness_resume_flags(0x203, 0x303 ^ (1 << bit)))
                        .is_err()
                );
            }
        }
    }
    fn ready() -> Ready {
        Ready {
            profile: Profile::Legacy,
            entry: 0x2000,
            gate: 0x1000,
            continuation: 0x1019,
            heads: vec![0x2000, 0x2005],
            returns: vec![0x2005],
            boundaries: vec![(0x2000, 0x2000), (0x2005, 0x2005)],
            immutable: vec![(0x2000, vec![0x90; PAGE])],
            original_source: vec![0x90; PAGE],
        }
    }
    #[test]
    fn ordinary_map_missing_and_duplicate_ret_refuse() {
        ready().validate(false);
        let mut r = ready();
        r.boundaries.pop();
        assert!(std::panic::catch_unwind(|| r.validate(false)).is_err());
        let mut r = ready();
        r.boundaries[0] = r.boundaries[1];
        assert!(std::panic::catch_unwind(|| r.validate(false)).is_err());
    }
    #[test]
    fn ordinary_gate_and_ready_identity_refuse() {
        let a = ready();
        let mut b = ready();
        b.continuation += 1;
        assert!(std::panic::catch_unwind(|| b.validate(false)).is_err());
        let mut b = ready();
        b.entry += 1;
        assert!(std::panic::catch_unwind(|| same_ready(&a, &b)).is_err());
        let mut bytes = GATE_BYTES.to_vec();
        bytes[22] ^= 1;
        assert!(std::panic::catch_unwind(|| check_gate(&a, &bytes)).is_err());
        let decoded = Ready::decode(&a.encode());
        same_ready(&a, &decoded);
    }
    #[test]
    fn ordinary_actual_frame_data_and_tls_mismatch_refuse() {
        let a: libc::user_regs_struct = unsafe { core::mem::zeroed() };
        same_arguments(&a, &a);
        for field in 0..5 {
            let mut b = a;
            match field {
                0 => b.rdi = 1,
                1 => b.rsi = 1,
                2 => b.rdx = 1,
                3 => b.fs_base = 1,
                _ => b.gs_base = 1,
            }
            assert!(std::panic::catch_unwind(|| same_arguments(&a, &b)).is_err());
        }
    }
    #[test]
    fn ordinary_full_data_and_redzone_comparator_refuses() {
        let snapshot = || Snapshot {
            logical_pc: 0x2000,
            registers: unsafe { core::mem::zeroed() },
            xstate: vec![1; 64],
            data: vec![2; PAGE],
            application_stack: vec![3; 152],
        };
        let expected = snapshot();
        assert_state(&expected, &snapshot());
        let mut changed = snapshot();
        changed.data[PAGE - 1] ^= 1;
        assert!(std::panic::catch_unwind(|| assert_state(&expected, &changed)).is_err());
        let mut changed = snapshot();
        changed.application_stack[0] ^= 1;
        assert!(std::panic::catch_unwind(|| assert_state(&expected, &changed)).is_err());
    }
}

// Separate scratch ABI; all existing adapter bodies and populations stay literal.
#[path = "native_precontext.rs"]
pub mod precontext;

// Actual optional frontend, separately qualified from both existing profiles.
#[path = "native_optional_frontend.rs"]
pub mod optional_frontend;

#[path = "native_reference.rs"]
pub mod reference;

// Closed loaded linked-memory subject and source-independent observation checks.
#[path = "native_cache.rs"]
pub mod cache;

// Closed real CALL tree; old leaf profiles and populations remain separate.
#[path = "native_call_tree.rs"]
pub mod call_tree;

#[path = "native_native_call.rs"]
pub mod native_call;
