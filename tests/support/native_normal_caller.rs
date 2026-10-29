//! Fixed ordinary C caller, separate from every gate/Frame profile.
//! Both target calls are fully compared. No timing or native execution claim.
use super::*;
use iced_x86::{Decoder, DecoderOptions, FlowControl};
register_native_fixture!(caller_bytes);
#[path = "native_normal_csv.rs"]
pub mod csv;
#[path = "native_normal_module.rs"]
pub mod module;
use module::WalkReady;
#[path = "native_call_pair.rs"]
pub mod call_pair;
#[path = "native_copied_capture.rs"]
mod copied_capture;
#[path = "native_copied_rust.rs"]
pub mod copied_rust;
#[path = "native_leaf_set_copied.rs"]
pub mod leaf_set_copied;
#[path = "native_normal_reference.rs"]
pub mod reference;
#[path = "native_rust_invoke.rs"]
pub mod rust_invoke;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallerProfile<'a> {
    Legacy,
    Reference,
    Module,
    CopiedRust(&'a rust_invoke::Plan),
    OriginalRust(&'a rust_invoke::Plan),
}
impl<'a> CallerProfile<'a> {
    fn bytes(self) -> &'a [u8] {
        match self {
            Self::Legacy => BYTES,
            Self::Reference => reference::bytes::BYTES,
            Self::Module => module::bytes::BYTES,
            Self::CopiedRust(plan) => plan.bytes(),
            Self::OriginalRust(plan) => plan.bytes(),
        }
    }
    fn heads(self) -> &'a [u64] {
        match self {
            Self::Legacy => HEADS,
            Self::Reference => reference::bytes::HEADS,
            Self::Module => module::bytes::HEADS,
            Self::CopiedRust(plan) => plan.heads(),
            Self::OriginalRust(plan) => plan.heads(),
        }
    }
    fn calls(self) -> &'a [u64] {
        match self {
            Self::Legacy => &CALLS,
            Self::Reference => &reference::bytes::CALLS,
            Self::Module => &module::bytes::CALLS,
            Self::CopiedRust(plan) => plan.calls(),
            Self::OriginalRust(plan) => plan.calls(),
        }
    }
    fn continuations(self) -> &'a [u64] {
        match self {
            Self::Legacy => &CONTINUATIONS,
            Self::Reference => &reference::bytes::CONTINUATIONS,
            Self::Module => &module::bytes::CONTINUATIONS,
            Self::CopiedRust(plan) => plan.continuations(),
            Self::OriginalRust(plan) => plan.continuations(),
        }
    }
    fn outer_ret(self) -> u64 {
        match self {
            Self::Legacy => OUTER_RET,
            Self::Reference => reference::bytes::OUTER_RET,
            Self::Module => module::bytes::OUTER_RET,
            Self::CopiedRust(plan) => plan.outer_ret(),
            Self::OriginalRust(plan) => plan.outer_ret(),
        }
    }
    fn compare(self, offset: u64) -> bool {
        self != Self::Reference || reference::bytes::RESTORED_HEADS.contains(&offset)
    }
}
use super::strnlen::{CASES, Case, Deadline, SEEDS};
use caller_bytes::{
    BYTES, CALLS, CONTINUATIONS, HEADS, OUTER_RET, PROTECTED_STACK_BELOW_CALLER, SUBJECT_RSP_DELTA,
};
impl CallerProfile<'_> {
    fn call_before(
        self,
        r: &libc::user_regs_struct,
        ready: &WalkReady,
        index: usize,
        rsp: u64,
        data: u64,
        bound: usize,
    ) {
        match self {
            Self::OriginalRust(_) => panic!("nested phase required"),
            Self::Legacy => call_before(r, ready.single(), index, rsp, data, bound),
            Self::Reference => reference::call_before(r, ready.single(), index, rsp, data, bound),
            Self::Module => module::call_before(r, ready.module(), index, rsp, data, bound),
            Self::CopiedRust(_) => {
                if matches!(ready, WalkReady::LeafSetCopied(_)) {
                    copied_rust::call_before_view(r, ready.copied_view(), index, rsp, data, bound)
                } else {
                    copied_rust::call_before(r, ready.copied_rust(), index, rsp, data, bound)
                }
            }
        }
    }
    fn call_after(
        self,
        r: &libc::user_regs_struct,
        ready: &WalkReady,
        index: usize,
        rsp: u64,
        word: u64,
    ) {
        match self {
            Self::OriginalRust(_) => panic!("nested phase required"),
            Self::Legacy => call_after(r, ready.single(), index, rsp, word),
            Self::Reference => reference::call_after(r, ready.single(), index, rsp, word),
            Self::Module => module::call_after(r, ready.module(), index, rsp, word),
            Self::CopiedRust(_) => {
                if matches!(ready, WalkReady::LeafSetCopied(_)) {
                    copied_rust::call_after_view(r, ready.copied_view(), index, rsp, word)
                } else {
                    copied_rust::call_after(r, ready.copied_rust(), index, rsp, word)
                }
            }
        }
    }
    fn ret_before(
        self,
        r: &libc::user_regs_struct,
        ready: &WalkReady,
        index: usize,
        rsp: u64,
        value: u64,
        word: u64,
    ) {
        match self {
            Self::OriginalRust(_) => panic!("nested phase required"),
            Self::Legacy => ret_before(r, ready.single(), index, rsp, value, word),
            Self::Reference => reference::ret_before(r, ready.single(), index, rsp, value, word),
            Self::Module => module::ret_before(r, ready.module(), index, rsp, value, word),
            Self::CopiedRust(_) => {
                if matches!(ready, WalkReady::LeafSetCopied(_)) {
                    copied_rust::ret_before_view(r, ready.copied_view(), index, rsp, value, word)
                } else {
                    copied_rust::ret_before(r, ready.copied_rust(), index, rsp, value, word)
                }
            }
        }
    }
    fn ret_after(
        self,
        r: &libc::user_regs_struct,
        ready: &WalkReady,
        index: usize,
        rsp: u64,
        value: u64,
        word: u64,
    ) {
        match self {
            Self::OriginalRust(_) => panic!("nested phase required"),
            Self::Legacy => ret_after(r, ready.single(), index, rsp, value, word),
            Self::Reference => reference::ret_after(r, ready.single(), index, rsp, value, word),
            Self::Module => module::ret_after(r, ready.module(), index, rsp, value, word),
            Self::CopiedRust(_) => {
                if matches!(ready, WalkReady::LeafSetCopied(_)) {
                    copied_rust::ret_after_view(r, ready.copied_view(), index, rsp, value, word)
                } else {
                    copied_rust::ret_after(r, ready.copied_rust(), index, rsp, value, word)
                }
            }
        }
    }
    fn journal_words(
        self,
        ready: &WalkReady,
        mode: Mode,
        pid: u64,
        rsp: u64,
        returns: &[u64],
    ) -> [u64; 512] {
        match self {
            Self::OriginalRust(_) => panic!("nested phase required"),
            Self::Legacy => journal_words(ready.single(), mode, pid, rsp, returns),
            Self::Reference => reference::journal_words(ready.single(), mode, pid, rsp, returns),
            Self::Module => module::journal_words(ready.module(), pid, rsp, returns, true),
            Self::CopiedRust(_) => {
                if matches!(ready, WalkReady::LeafSetCopied(_)) {
                    copied_rust::journal_words_view(ready.copied_view(), pid, rsp, returns, true)
                } else {
                    copied_rust::journal_words(ready.copied_rust(), pid, rsp, returns, true)
                }
            }
        }
    }
}

const INPUT: usize = 128;
const REQUESTS: usize = 256;
const RESULTS: usize = 320;
const ACK_MAGIC: u64 = 0x6e6f726d616c7631;
const ACK_WORDS: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Stable,
    CrossedOwner,
}
/// Closed Exact37 input; the independent binary-level interpreter checks every
/// original instruction. This scalar is only the harness's transfer expectation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactCase {
    seed_index: usize,
    length: usize,
}
impl ExactCase {
    pub fn new(seed: u64, length: usize) -> Self {
        let seed_index = SEEDS
            .iter()
            .position(|&s| s == seed)
            .expect("closed Exact seed");
        assert!(matches!(length, 1 | 64));
        Self { seed_index, length }
    }
    pub fn length(self) -> usize {
        self.length
    }
    pub fn input(self) -> [u8; 64] {
        std::array::from_fn(|j| (37 * j + 11 + self.seed_index) as u8)
    }
    pub fn scalar(self) -> u64 {
        self.input()[..self.length]
            .iter()
            .map(|b| u64::from(*b ^ 0x5a))
            .sum::<u64>()
            ^ 0x9e37_79b9_7f4a_7c15
    }
    pub fn counts(self) -> (usize, usize, usize, usize) {
        (
            6 * self.length + 5,
            self.length,
            self.length - 1,
            self.length + 1,
        )
    }
}
#[derive(Clone, Copy)]
enum Body {
    Strnlen(Case),
    Exact(ExactCase),
    Csv(csv::Case),
    Scanner(
        leaf_set_copied::scanner::Operation,
        leaf_set_copied::scanner::Case,
    ),
}
impl Body {
    fn input(self) -> [u8; 64] {
        match self {
            Self::Strnlen(case) => strnlen::cases::input(case),
            Self::Exact(case) => case.input(),
            Self::Csv(case) => case.input(),
            Self::Scanner(_, case) => case.input(),
        }
    }
    fn bound(self) -> usize {
        match self {
            Self::Strnlen(case) => case.bound,
            Self::Exact(case) => case.length(),
            Self::Csv(case) => case.length(),
            Self::Scanner(_, case) => case.bound(),
        }
    }
    fn scalar(self) -> u64 {
        match self {
            Self::Strnlen(case) => strnlen::cases::scalar(case),
            Self::Exact(case) => case.scalar(),
            Self::Csv(case) => case.expected(),
            Self::Scanner(operation, case) => case.expected(operation),
        }
    }
    fn strnlen(self) -> Case {
        match self {
            Self::Strnlen(case) => case,
            Self::Exact(_) => panic!("not a strnlen case"),
            Self::Csv(_) => panic!("not a strnlen case"),
            Self::Scanner(..) => panic!("not a strnlen case"),
        }
    }
}
/// Borrowed ORIGINAL subject slice, bounded by authenticated actual C CALL/RET.
/// It has no gate frame or invented OriginalObservation authority.
pub struct OriginalBody<'a> {
    pub entry: u64,
    pub continuation: u64,
    pub code: &'a [u8],
    pub input_address: u64,
    pub input: &'a [u8],
    pub steps: &'a [OriginalStep<'a>],
}

#[derive(Clone, Debug)]
pub struct JournalReady {
    pub address: u64,
    pub a_generation: u64,
    pub b_generation: Option<u64>,
    pub helper_tid: Option<u64>,
}
/// Child-local authenticated source/map metadata, never a gate authority.
#[derive(Clone)]
pub struct NormalReady {
    pub caller: u64,
    pub caller_immutable: Vec<(u64, Vec<u8>)>,
    pub entry: u64,
    pub heads: Vec<u64>,
    pub returns: Vec<u64>,
    pub boundaries: Vec<(u64, u64)>,
    pub immutable: Vec<(u64, Vec<u8>)>,
    pub original_source: Vec<u8>,
    pub journal: Option<JournalReady>,
}
fn bytes_at(bytes: &[u8], base: u64, address: u64, count: usize) -> &[u8] {
    let begin = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    &bytes[begin..begin.checked_add(count).unwrap()]
}
fn word_at(bytes: &[u8], base: u64, address: u64) -> u64 {
    u64::from_le_bytes(bytes_at(bytes, base, address, 8).try_into().unwrap())
}
fn word(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn take_word(bytes: &mut &[u8]) -> u64 {
    assert!(bytes.len() >= 8);
    let result = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    *bytes = &bytes[8..];
    result
}
fn take_data(bytes: &mut &[u8]) -> Vec<u8> {
    let n = usize::try_from(take_word(bytes)).unwrap();
    assert!((1..=8192).contains(&n) && n <= bytes.len());
    let result = bytes[..n].to_vec();
    *bytes = &bytes[n..];
    result
}
impl NormalReady {
    fn validate(&self, candidate: bool, extent: usize, mode: Mode) -> BTreeMap<u64, u64> {
        self.validate_profile(candidate, extent, mode, CallerProfile::Legacy)
    }
    fn validate_profile(
        &self,
        candidate: bool,
        extent: usize,
        mode: Mode,
        profile: CallerProfile,
    ) -> BTreeMap<u64, u64> {
        if profile == CallerProfile::Reference {
            assert_eq!(mode, Mode::Stable);
            assert_eq!(extent, 37);
            reference::bytes::validate_body(profile.bytes()).unwrap();
        }
        assert!((5..=80).contains(&extent));
        self.validate_body(candidate, extent, mode, profile)
    }
    fn validate_body(
        &self,
        candidate: bool,
        extent: usize,
        mode: Mode,
        profile: CallerProfile,
    ) -> BTreeMap<u64, u64> {
        assert_eq!(self.caller_immutable.len(), 1);
        let (caller_page, caller_bytes) = &self.caller_immutable[0];
        assert_eq!(caller_page % PAGE as u64, 0);
        assert_eq!(caller_bytes.len(), PAGE);
        assert_eq!(
            bytes_at(
                caller_bytes,
                *caller_page,
                self.caller,
                profile.bytes().len()
            ),
            profile.bytes()
        );
        assert!(!self.heads.is_empty() && self.heads.len() <= extent);
        assert_eq!(self.heads[0], self.entry);
        assert!(self.heads.windows(2).all(|w| w[0] < w[1]));
        assert!((1..=4).contains(&self.returns.len()));
        assert!(self.returns.windows(2).all(|w| w[0] < w[1]));
        let end = self.entry.checked_add(extent as u64).unwrap();
        assert!(self.heads.iter().all(|&p| self.entry <= p && p < end));
        assert!((1..=6).contains(&self.immutable.len()));
        let (source, source_bytes) = &self.immutable[0];
        assert_eq!(source % PAGE as u64, 0);
        assert!(matches!(source_bytes.len(), PAGE | 8192));
        assert_eq!(source_bytes.len(), self.original_source.len());
        let _ = bytes_at(source_bytes, *source, self.entry, extent);
        let code = bytes_at(&self.original_source, *source, self.entry, extent);
        let mut decoder = Decoder::with_ip(64, code, self.entry, DecoderOptions::NONE);
        let mut decoded = Vec::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            assert!(!instruction.is_invalid() && instruction.next_ip() <= end);
            decoded.push(instruction.ip());
        }
        assert_eq!(decoder.position(), extent);
        assert_eq!(
            self.heads, decoded,
            "all original heads, including retained padding maps"
        );
        for &ret in &self.returns {
            assert!(self.heads.contains(&ret));
            assert_eq!(bytes_at(&self.original_source, *source, ret, 1), [0xc3]);
        }
        let mut ranges = vec![(*caller_page, caller_page.checked_add(PAGE as u64).unwrap())];
        for (index, (address, data)) in self.immutable.iter().enumerate() {
            assert!(!data.is_empty() && data.len() <= 8192);
            let end = address.checked_add(data.len() as u64).unwrap();
            assert!(ranges.iter().all(|&(a, b)| end <= a || b <= *address));
            assert!(index == 0 || candidate);
            ranges.push((*address, end));
        }
        assert_eq!(self.boundaries.len(), self.heads.len());
        let mut logical = BTreeSet::new();
        let mut physical = BTreeMap::new();
        for &(original, generated) in &self.boundaries {
            assert!(self.heads.contains(&original) && logical.insert(original));
            assert!(physical.insert(generated, original).is_none());
            assert!(
                generated == original
                    || candidate
                        && self.immutable[1..]
                            .iter()
                            .any(|(a, b)| *a <= generated && generated < *a + b.len() as u64)
            );
        }
        assert_eq!(logical, self.heads.iter().copied().collect());
        if candidate {
            let j = self.journal.as_ref().expect("normal candidate journal");
            assert_eq!(j.address % PAGE as u64, 0);
            let end = j.address.checked_add(PAGE as u64).unwrap();
            assert!(ranges.iter().all(|&(a, b)| end <= a || b <= j.address));
            assert_ne!(j.a_generation, 0);
            match mode {
                Mode::Stable => {
                    assert!(j.b_generation.is_none() && j.helper_tid.is_none());
                }
                Mode::CrossedOwner => {
                    assert!(
                        j.b_generation
                            .is_some_and(|b| b != 0 && b != j.a_generation)
                    );
                    assert!(j.helper_tid.is_some_and(|t| t != 0));
                }
            }
        } else {
            assert!(self.journal.is_none());
            assert_eq!(self.immutable.len(), 1);
            assert_eq!(self.immutable[0].1, self.original_source);
            assert!(self.boundaries.iter().all(|(a, b)| a == b));
        }
        physical
    }
    fn same_source(&self, other: &Self) {
        assert_eq!((self.caller, self.entry), (other.caller, other.entry));
        assert_eq!(self.caller_immutable, other.caller_immutable);
        assert_eq!(self.heads, other.heads);
        assert_eq!(self.returns, other.returns);
        assert_eq!(self.immutable[0].0, other.immutable[0].0);
        assert_eq!(self.original_source, other.original_source);
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for n in [self.caller, self.entry] {
            word(&mut bytes, n);
        }
        for list in [&self.heads, &self.returns] {
            word(&mut bytes, list.len() as u64);
            for &n in list {
                word(&mut bytes, n);
            }
        }
        word(&mut bytes, self.boundaries.len() as u64);
        for &(a, b) in &self.boundaries {
            word(&mut bytes, a);
            word(&mut bytes, b);
        }
        for list in [&self.caller_immutable, &self.immutable] {
            word(&mut bytes, list.len() as u64);
            for (address, data) in list {
                word(&mut bytes, *address);
                word(&mut bytes, data.len() as u64);
                bytes.extend(data);
            }
        }
        word(&mut bytes, self.original_source.len() as u64);
        bytes.extend(&self.original_source);
        word(&mut bytes, u64::from(self.journal.is_some()));
        if let Some(j) = &self.journal {
            for n in [
                j.address,
                j.a_generation,
                j.b_generation.unwrap_or(0),
                j.helper_tid.unwrap_or(0),
            ] {
                word(&mut bytes, n);
            }
        }
        assert!(bytes.len() <= WIRE_LIMIT);
        bytes
    }
    fn decode(mut bytes: &[u8]) -> Self {
        fn list(b: &mut &[u8]) -> Vec<u64> {
            let n = take_word(b);
            assert!((1..=256).contains(&n));
            (0..n).map(|_| take_word(b)).collect()
        }
        fn images(b: &mut &[u8]) -> Vec<(u64, Vec<u8>)> {
            let n = take_word(b);
            assert!((1..=6).contains(&n));
            (0..n).map(|_| (take_word(b), take_data(b))).collect()
        }
        let caller = take_word(&mut bytes);
        let entry = take_word(&mut bytes);
        let heads = list(&mut bytes);
        let returns = list(&mut bytes);
        let n = take_word(&mut bytes);
        assert!((1..=256).contains(&n));
        let boundaries = (0..n)
            .map(|_| (take_word(&mut bytes), take_word(&mut bytes)))
            .collect();
        let caller_immutable = images(&mut bytes);
        let immutable = images(&mut bytes);
        let original_source = take_data(&mut bytes);
        let journal = match take_word(&mut bytes) {
            0 => None,
            1 => {
                let address = take_word(&mut bytes);
                let a_generation = take_word(&mut bytes);
                let b = take_word(&mut bytes);
                let t = take_word(&mut bytes);
                Some(JournalReady {
                    address,
                    a_generation,
                    b_generation: (b != 0).then_some(b),
                    helper_tid: (t != 0).then_some(t),
                })
            }
            _ => panic!("unknown normal journal tag"),
        };
        assert!(bytes.is_empty(), "no normal readiness tail");
        Self {
            caller,
            caller_immutable,
            entry,
            heads,
            returns,
            boundaries,
            immutable,
            original_source,
            journal,
        }
    }
}

// Nonblocking, bounded, owned endpoints. No system-wide timeout or clock reset.
struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}
fn pipe() -> [Fd; 2] {
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    fds.map(Fd)
}
fn wait_fd(fd: i32, events: i16, deadline: Deadline) {
    loop {
        deadline.check();
        let mut p = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let n = unsafe { libc::poll(&raw mut p, 1, 10) };
        deadline.check();
        if n < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
            continue;
        }
        if n == 0 {
            continue;
        }
        assert_eq!(p.revents & (libc::POLLERR | libc::POLLNVAL), 0);
        if p.revents & (events | libc::POLLHUP) != 0 {
            return;
        }
    }
}
fn write_all(fd: i32, mut bytes: &[u8], deadline: Deadline) {
    while !bytes.is_empty() {
        wait_fd(fd, libc::POLLOUT, deadline);
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        deadline.check();
        if n < 0 {
            assert!(matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN)
            ));
            continue;
        }
        assert!(n > 0);
        bytes = &bytes[n as usize..];
    }
}
fn read_exact(fd: i32, mut bytes: &mut [u8], deadline: Deadline) {
    while !bytes.is_empty() {
        wait_fd(fd, libc::POLLIN, deadline);
        let n = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        deadline.check();
        if n < 0 {
            assert!(matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN)
            ));
            continue;
        }
        assert!(n > 0, "truncated normal control record");
        bytes = &mut bytes[n as usize..];
    }
}
fn read_closed(fd: i32, deadline: Deadline, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        wait_fd(fd, libc::POLLIN, deadline);
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        deadline.check();
        if n < 0 {
            assert!(matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN)
            ));
            continue;
        }
        if n == 0 {
            return out;
        }
        assert!(out.len().checked_add(n as usize).unwrap() <= limit);
        out.extend_from_slice(&chunk[..n as usize]);
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ControlStatus {
    pub helper_tid: u64,
    pub a_generation: u64,
    pub b_generation: u64,
    pub a_ready: bool,
    pub b_ready: bool,
    pub history_len: usize,
    pub current: u64,
}
pub struct ControlChild {
    command: Fd,
    ack: Fd,
    deadline: Deadline,
    next: usize,
    pending: bool,
}
impl ControlChild {
    pub fn receive(&mut self) -> usize {
        assert!(!self.pending && (1..=2).contains(&self.next));
        let mut bytes = [0; 16];
        read_exact(self.command.0, &mut bytes, self.deadline);
        let mut b = &bytes[..];
        assert_eq!(take_word(&mut b), ACK_MAGIC);
        assert_eq!(take_word(&mut b), self.next as u64);
        self.pending = true;
        self.next
    }
    pub fn acknowledge(&mut self, stage: usize, status: ControlStatus) {
        assert!(self.pending && stage == self.next && (1..=2).contains(&stage));
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) } as u64,
            status.helper_tid
        );
        let words = [
            ACK_MAGIC,
            stage as u64,
            unsafe { libc::getpid() } as u64,
            status.helper_tid,
            status.a_generation,
            status.b_generation,
            u64::from(status.a_ready),
            u64::from(status.b_ready),
            status.history_len as u64,
            status.current,
        ];
        let bytes: Vec<_> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        write_all(self.ack.0, &bytes, self.deadline);
        self.pending = false;
        self.next += 1;
    }
}
struct ControlParent {
    command: Fd,
    ack: Fd,
    next: usize,
}
fn check_ack(words: &[u64], stage: usize, pid: u64, j: &JournalReady) {
    assert!((1..=2).contains(&stage));
    assert_eq!(
        words,
        &[
            ACK_MAGIC,
            stage as u64,
            pid,
            j.helper_tid.unwrap(),
            j.a_generation,
            j.b_generation.unwrap(),
            u64::from(stage == 2),
            0,
            3,
            j.b_generation.unwrap()
        ]
    );
    assert_ne!(
        j.helper_tid.unwrap(),
        pid,
        "helper is distinct, untraced thread"
    );
}
impl ControlParent {
    fn request(&mut self, stage: usize, child: &Tracee, j: &JournalReady, deadline: Deadline) {
        self.request_with(stage, deadline, |words| {
            check_ack(words, stage, child.pid as u64, j)
        });
    }
    fn request_with(&mut self, stage: usize, deadline: Deadline, check: impl FnOnce(&[u64])) {
        assert_eq!(stage, self.next);
        assert!((1..=2).contains(&stage));
        let bytes: Vec<_> = [ACK_MAGIC, stage as u64]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        write_all(self.command.0, &bytes, deadline);
        let mut bytes = [0; ACK_WORDS * 8];
        read_exact(self.ack.0, &mut bytes, deadline);
        let words: Vec<_> = bytes
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect();
        check(&words);
        self.next += 1;
    }
    fn finish(self, deadline: Deadline) {
        assert_eq!(self.next, 3);
        assert!(
            read_closed(self.ack.0, deadline, 0).is_empty(),
            "no duplicate ACK tail"
        );
    }
}

pub struct NormalOracle {
    data: Mapping,
    stack: Mapping,
    seed: u64,
    body: Body,
    extent: usize,
    deadline: Deadline,
    mode: Mode,
    reference: Option<reference::Cells>,
    module: Option<module::Case>,
    copied_rust: Option<copied_rust::Profile>,
    leaf_set_copied: Option<leaf_set_copied::Profile>,
    call_pair: Option<call_pair::Profile>,
}
pub struct NormalContext<'a> {
    oracle: &'a NormalOracle,
    write: Fd,
    control: Option<ControlChild>,
    output: Option<reference::Output>,
}
impl NormalContext<'_> {
    pub fn input(&self) -> &[u8] {
        &self.oracle.data.bytes()[INPUT..INPUT + 64]
    }
    pub fn data_address(&self) -> u64 {
        self.oracle.data.address()
    }
    pub fn data_len(&self) -> usize {
        PAGE
    }
    pub fn requests_address(&self) -> u64 {
        self.data_address() + REQUESTS as u64
    }
    pub fn results_address(&self) -> u64 {
        self.data_address() + RESULTS as u64
    }
    pub fn stack_range(&self) -> (u64, u64) {
        (
            self.oracle.stack.address() + PAGE as u64,
            self.oracle.stack.address() + STACK_BYTES as u64,
        )
    }
    pub fn caller_rsp(&self) -> u64 {
        self.oracle.caller_rsp()
    }
    pub fn case(&self) -> Case {
        self.oracle.body.strnlen()
    }
    pub fn exact_case(&self) -> Option<ExactCase> {
        match self.oracle.body {
            Body::Exact(case) => Some(case),
            Body::Strnlen(_) => None,
            Body::Csv(_) => None,
            Body::Scanner(..) => None,
        }
    }
    pub fn csv_case(&self) -> Option<csv::Case> {
        match self.oracle.body {
            Body::Csv(case) => Some(case),
            _ => None,
        }
    }
    pub fn deadline(&self) -> Deadline {
        self.oracle.deadline
    }
    pub fn take_control(&mut self) -> Option<ControlChild> {
        self.control.take()
    }
    pub fn reference_cells_address(&self) -> Option<u64> {
        self.oracle
            .reference
            .as_ref()
            .map(reference::Cells::address)
    }
    pub fn reference_output(&mut self) -> reference::Output {
        self.output.take().expect("one reference postflight output")
    }
    pub fn ready_reference(self, ready: &reference::ReferenceReady) {
        assert_eq!(self.oracle.profile(), CallerProfile::Reference);
        assert_eq!(Some(ready.cells), self.reference_cells_address());
        assert!(self.control.is_none() && self.output.is_none());
        write_all(self.write.0, &ready.encode(), self.oracle.deadline);
        drop(self.write);
        self.oracle.deadline.check();
        unsafe {
            assert_eq!(libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize), 0);
            assert_eq!(libc::raise(libc::SIGSTOP), 0);
        }
    }
    pub fn ready(self, ready: &NormalReady) {
        assert!(self.oracle.leaf_set_copied.is_none());
        assert!(self.oracle.copied_rust.is_none());
        assert!(self.oracle.module.is_none());
        assert!(self.oracle.reference.is_none() && self.output.is_none());
        assert!(
            self.control.is_none(),
            "helper endpoint must be consumed before readiness"
        );
        write_all(self.write.0, &ready.encode(), self.oracle.deadline);
        drop(self.write);
        self.oracle.deadline.check();
        // Only this main thread becomes traced; no PTRACE_O_TRACECLONE is set.
        unsafe {
            assert_eq!(libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize), 0);
            assert_eq!(libc::raise(libc::SIGSTOP), 0);
        }
        // Post-stop deadline enforcement belongs to the parent reach/step path.
    }
}
fn mode_case(seed: u64, case: Case, extent: usize, mode: Mode) {
    assert!(SEEDS.contains(&seed) && CASES.contains(&case));
    assert!((5..=80).contains(&extent));
    if mode == Mode::CrossedOwner {
        assert_eq!(seed, SEEDS[0]);
        assert_eq!(case, CASES[7]);
    }
}
impl NormalOracle {
    pub fn new(seed: u64, case: Case, extent: usize, deadline: Deadline, mode: Mode) -> Self {
        deadline.check();
        mode_case(seed, case, extent, mode);
        Self::new_body(seed, Body::Strnlen(case), extent, deadline, mode)
    }
    pub fn new_csv(seed: u64, case: csv::Case, extent: usize, deadline: Deadline) -> Self {
        deadline.check();
        csv::profile(seed, case, extent);
        Self::new_body(seed, Body::Csv(case), extent, deadline, Mode::Stable)
    }
    pub fn new_exact(seed: u64, length: usize, deadline: Deadline) -> Self {
        deadline.check();
        let case = ExactCase::new(seed, length);
        Self::new_body(seed, Body::Exact(case), 37, deadline, Mode::Stable)
    }
    pub fn new_reference_exact(seed: u64, length: usize, deadline: Deadline) -> Self {
        deadline.check();
        let mut oracle = Self::new_exact(seed, length, deadline);
        oracle.reference = Some(reference::Cells::new(deadline));
        deadline.check();
        oracle
    }
    fn profile(&self) -> CallerProfile<'_> {
        if let Some(profile) = &self.call_pair {
            assert!(
                self.copied_rust.is_none()
                    && self.leaf_set_copied.is_none()
                    && self.module.is_none()
                    && self.reference.is_none()
            );
            assert_eq!(self.mode, Mode::Stable);
            profile.case.assert_valid();
            return CallerProfile::OriginalRust(&profile.plan);
        }
        if let Some(profile) = &self.leaf_set_copied {
            assert!(
                self.copied_rust.is_none() && self.module.is_none() && self.reference.is_none()
            );
            assert_eq!(self.mode, Mode::Stable);
            profile.case.assert_valid();
            CallerProfile::CopiedRust(&profile.plan)
        } else if let Some(profile) = &self.copied_rust {
            assert!(self.module.is_none() && self.reference.is_none());
            assert_eq!(self.mode, Mode::Stable);
            profile.case.assert_valid();
            CallerProfile::CopiedRust(&profile.plan)
        } else if self.module.is_some() {
            assert!(self.reference.is_none());
            CallerProfile::Module
        } else if self.reference.is_some() {
            CallerProfile::Reference
        } else {
            CallerProfile::Legacy
        }
    }
    fn has_rust_caller(&self) -> bool {
        self.call_pair.is_some() || self.has_copied_caller()
    }
    fn has_copied_caller(&self) -> bool {
        self.copied_rust.is_some() || self.leaf_set_copied.is_some()
    }
    fn new_body(seed: u64, body: Body, extent: usize, deadline: Deadline, mode: Mode) -> Self {
        let data = Mapping::new(PAGE);
        let mut bytes: Vec<_> = (0..PAGE)
            .map(|i| (i as u64 * 37 + 11 + seed) as u8)
            .collect();
        bytes[INPUT..INPUT + 64].copy_from_slice(&body.input());
        let address = data.address() + INPUT as u64;
        for at in [REQUESTS, REQUESTS + 16] {
            bytes[at..at + 8].copy_from_slice(&address.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&(body.bound() as u64).to_le_bytes());
        }
        bytes[RESULTS..RESULTS + 16].fill(0);
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
        deadline.check();
        Self {
            data,
            stack,
            seed,
            body,
            extent,
            deadline,
            mode,
            reference: None,
            module: None,
            copied_rust: None,
            leaf_set_copied: None,
            call_pair: None,
        }
    }
    fn caller_rsp(&self) -> u64 {
        self.stack.address() + STACK_BYTES as u64 - 8
    }
    fn stack_start(&self) -> u64 {
        self.caller_rsp() - self.stack_below()
    }
    fn step(&self, walk: &mut Walk<'_>, phase: &str) {
        self.deadline.check();
        walk.step(phase);
        self.deadline.check();
    }
    fn snapshot(&self, child: &Tracee, ready: &WalkReady, logical: u64) -> Snapshot {
        self.deadline.check();
        if self.call_pair.is_some() {
            return copied_capture::nested_snapshot(self, child, ready, logical);
        }
        if self.has_copied_caller() {
            return copied_capture::snapshot(self, child, ready, logical);
        }
        for (a, b) in ready.caller_immutable().iter().chain(ready.immutable()) {
            assert_eq!(
                child.memory(*a, b.len()),
                *b,
                "complete normal caller/source/image bytes"
            );
        }
        let point = Snapshot {
            logical_pc: logical,
            registers: child.registers(),
            xstate: canonical_xstate(&child.xstate()),
            data: child.memory(self.data.address(), PAGE),
            application_stack: child.memory(self.stack_start(), (self.stack_below() + 8) as usize),
        };
        self.check_data(ready, &point.data, false);
        self.deadline.check();
        point
    }
    fn reach_caller(&self, walk: &mut Walk<'_>, ready: &WalkReady) -> libc::user_regs_struct {
        // Enforce the post-ready deadline without tracing supervisory clock code.
        self.deadline.check();
        let mut last = None;
        while walk.child.registers().rip != ready.caller() {
            let before = walk.child.registers();
            let code = walk.child.memory(before.rip, 15);
            let instruction =
                Decoder::with_ip(64, &code, before.rip, DecoderOptions::NONE).decode();
            self.step(walk, "normal reach actual caller CALL");
            last = Some((before, instruction));
        }
        let after = walk.child.registers();
        let (before, instruction) = last.expect("actual enclosing machine CALL");
        assert!(matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ));
        assert_eq!(after.rsp, before.rsp.checked_sub(8).unwrap());
        assert_eq!(
            word_at(&walk.child.memory(after.rsp, 8), after.rsp, after.rsp),
            instruction.next_ip()
        );
        assert_eq!(after.rsp % 16, 8);
        if self.call_pair.is_some() {
            copied_rust::entry_arguments_view(
                &after,
                ready.call_pair().view(),
                self.data.address(),
            );
        } else if self.leaf_set_copied.is_some() {
            copied_rust::entry_arguments_view(&after, ready.copied_view(), self.data.address());
        } else if self.copied_rust.is_some() {
            copied_rust::entry_arguments(&after, ready.copied_rust(), self.data.address());
        } else {
            assert_eq!(
                (after.rdi, after.rsi, after.rdx),
                (
                    self.first_argument(ready),
                    self.data.address() + REQUESTS as u64,
                    self.data.address() + RESULTS as u64
                )
            );
        }
        assert_eq!(
            walk.child
                .memory(ready.caller(), self.profile().bytes().len()),
            self.profile().bytes()
        );
        if let Some(cells) = &self.reference {
            assert_eq!(after.rcx, cells.address());
        }
        self.deadline.check();
        after
    }
    fn seed(&self, child: &Tracee, actual: libc::user_regs_struct) -> libc::user_regs_struct {
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
        r.rsp = self.caller_rsp();
        r.orig_rax = u64::MAX;
        r.eflags = 0xad7 | ((self.seed & 1) << 10);
        child.set_registers(&r);
        child.set_xstate(&seeded_xstate(child.xstate(), self.seed));
        r
    }
}

fn guard_data(initial: &[u8], actual: &[u8]) {
    assert_eq!(initial.len(), PAGE);
    assert_eq!(actual.len(), PAGE);
    assert_eq!(&actual[..RESULTS], &initial[..RESULTS]);
    assert_eq!(&actual[RESULTS + 16..], &initial[RESULTS + 16..]);
}
fn final_data(initial: &[u8], actual: &[u8], value: u64) {
    guard_data(initial, actual);
    assert_eq!(&actual[RESULTS..RESULTS + 8], &value.to_le_bytes());
    assert_eq!(&actual[RESULTS + 8..RESULTS + 16], &value.to_le_bytes());
}
fn callee_saves(before: &libc::user_regs_struct, after: &libc::user_regs_struct) {
    assert_eq!(
        [
            before.rbx, before.rbp, before.r12, before.r13, before.r14, before.r15, before.rsp
        ],
        [
            after.rbx, after.rbp, after.r12, after.r13, after.r14, after.r15, after.rsp
        ],
        "actual helper epilogue before harness restoration"
    );
}
fn call_order(calls: usize, returns: usize, index: usize) {
    assert!(index < 2);
    assert_eq!(index, calls);
    assert_eq!(returns, index);
}
fn ret_order(calls: usize, returns: usize) {
    assert!(returns < 2 && calls == returns + 1);
}
fn call_before(
    r: &libc::user_regs_struct,
    ready: &NormalReady,
    index: usize,
    rsp: u64,
    data: u64,
    bound: usize,
) {
    assert!(index < 2);
    assert_eq!(
        (r.rip, r.r13, r.rdi, r.rsi, r.rsp),
        (
            ready.caller + CALLS[index],
            ready.entry,
            data + INPUT as u64,
            bound as u64,
            rsp - SUBJECT_RSP_DELTA + 8
        )
    );
}
fn call_after(r: &libc::user_regs_struct, ready: &NormalReady, index: usize, rsp: u64, word: u64) {
    assert_eq!(
        (r.rip, r.rsp, word),
        (
            ready.entry,
            rsp - SUBJECT_RSP_DELTA,
            ready.caller + CONTINUATIONS[index]
        )
    );
}
fn ret_before(
    r: &libc::user_regs_struct,
    ready: &NormalReady,
    index: usize,
    rsp: u64,
    value: u64,
    word: u64,
) {
    assert!(index < 2);
    assert!(
        ready
            .boundaries
            .iter()
            .any(|(logical, physical)| *physical == r.rip && ready.returns.contains(logical))
    );
    assert_eq!(
        (r.rsp, r.rax, word),
        (
            rsp - SUBJECT_RSP_DELTA,
            value,
            ready.caller + CONTINUATIONS[index]
        )
    );
}
fn ret_after(
    r: &libc::user_regs_struct,
    ready: &NormalReady,
    index: usize,
    rsp: u64,
    value: u64,
    word: u64,
) {
    assert_eq!(
        (r.rip, r.rsp, r.rax, word),
        (
            ready.caller + CONTINUATIONS[index],
            rsp - SUBJECT_RSP_DELTA + 8,
            value,
            ready.caller + CONTINUATIONS[index]
        )
    );
}
fn journal_words(
    ready: &NormalReady,
    mode: Mode,
    pid: u64,
    rsp: u64,
    returns: &[u64],
) -> [u64; 512] {
    assert!((1..=2).contains(&returns.len()));
    let j = ready.journal.as_ref().unwrap();
    let mut expected = [0; 512];
    expected[..4].copy_from_slice(&[returns.len() as u64 * 2, 0, pid, 1]);
    for (n, &ret) in returns.iter().enumerate() {
        assert!(ready.returns.contains(&ret));
        let crossed = mode == Mode::CrossedOwner && n == 1;
        let generation = if crossed {
            j.b_generation.unwrap()
        } else {
            j.a_generation
        };
        let invocation = if crossed { 1 } else { n as u64 + 1 };
        let prefix = if crossed { 3 } else { 1 };
        let bits = invocation | (prefix << 13);
        let start = 4 + n * 14;
        let word = ready.caller + CONTINUATIONS[n];
        expected[start..start + 7].copy_from_slice(&[
            1,
            n as u64 + 1,
            ready.entry,
            rsp - SUBJECT_RSP_DELTA,
            word,
            generation,
            bits,
        ]);
        expected[start + 7..start + 14].copy_from_slice(&[
            2,
            n as u64 + 1,
            ret,
            rsp - SUBJECT_RSP_DELTA,
            word,
            generation,
            bits,
        ]);
    }
    expected
}
fn check_journal(actual: &[u8], expected: &[u64; 512]) {
    assert_eq!(actual.len(), PAGE);
    for (word, expected) in actual.chunks_exact(8).zip(expected) {
        assert_eq!(
            u64::from_le_bytes(word.try_into().unwrap()),
            *expected,
            "whole pending normal journal"
        );
    }
}

/// All values are joined after two actual normal child reaps; no gate sequence.
pub struct NormalPairResult<const N: usize = 2> {
    pub comparisons: usize,
    pub original_steps: usize,
    pub candidate_steps: usize,
    pub visits: [usize; N],
    pub returns: [u64; N],
    pub declared_returns: BTreeSet<u64>,
    pub values: [u64; N],
    pub outer_value: u64,
    pub target_calls: usize,
    pub target_returns: usize,
    pub outer_returns: usize,
    pub normal_reaps: usize,
}
impl NormalOracle {
    pub fn pair<F>(&self, setup: F) -> (NormalPairResult, NormalTrace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        let case = self.body.strnlen();
        let (result, trace) = self.pair_observed(setup, |ready, points| {
            let trace = self.inspect(ready, points);
            let visits = trace.bodies.each_ref().map(|t| t.visits);
            (trace, visits)
        });
        validate_pair(case, &result, &trace);
        self.deadline.check();
        (result, trace)
    }
    pub fn pair_csv<F>(&self, setup: F) -> (NormalPairResult, csv::Trace)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
    {
        let Body::Csv(case) = self.body else {
            panic!("not a CSV pair")
        };
        let (result, trace) = self.pair_observed(setup, |ready, points| {
            let bodies =
                self.inspect_bodies(ready, points, |_, body| csv::inspect(case, ready, body));
            let visits = bodies.each_ref().map(|b| b.visits);
            (csv::Trace { bodies }, visits)
        });
        csv::validate_pair(case, &result, &trace);
        self.deadline.check();
        (result, trace)
    }
    pub fn pair_exact<F, O>(
        &self,
        setup: F,
        mut inspect: O,
    ) -> (NormalPairResult, [(usize, usize, usize, usize); 2])
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
        O: for<'a> FnMut(usize, OriginalBody<'a>) -> (usize, usize, usize, usize),
    {
        let Body::Exact(case) = self.body else {
            panic!("not an Exact pair")
        };
        let (result, counts) = self.pair_observed(setup, |ready, points| {
            assert_eq!(ready.returns, [ready.entry.checked_add(36).unwrap()]);
            let mut visits = [0; 2];
            let counts = self.inspect_bodies(ready, points, |i, body| {
                visits[i] = body.steps.len();
                inspect(i, body)
            });
            (counts, visits)
        });
        validate_exact_pair(case, &result, &counts);
        self.deadline.check();
        (result, counts)
    }
    pub fn pair_reference_exact<F, O>(&self, setup: F, mut inspect: O) -> reference::PairResult
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
        O: for<'a> FnMut(usize, OriginalBody<'a>) -> (usize, usize, usize, usize),
    {
        assert!(self.reference.is_some());
        let Body::Exact(case) = self.body else {
            panic!("reference Exact37 only")
        };
        let (result, counts, stats) = self.pair_observed_inner(setup, |ready, points| {
            assert_eq!(ready.returns, [ready.entry.checked_add(36).unwrap()]);
            let mut visits = [0; 2];
            let counts = self.inspect_bodies(ready, points, |i, body| {
                visits[i] = body.steps.len();
                inspect(i, body)
            });
            (counts, visits)
        });
        let stats = stats.unwrap();
        reference::validate_pair(case, &result, &counts, &stats);
        self.deadline.check();
        (result, counts, stats)
    }
    fn pair_observed<F, O, T>(&self, setup: F, inspect: O) -> (NormalPairResult, T)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
        O: FnOnce(&NormalReady, &[Snapshot]) -> (T, [usize; 2]),
    {
        assert!(
            self.reference.is_none(),
            "legacy route has no reference cells"
        );
        let (pair, trace, stats) = self.pair_observed_inner(setup, inspect);
        assert!(stats.is_none());
        (pair, trace)
    }
    fn pair_observed_inner<F, O, T>(
        &self,
        setup: F,
        inspect: O,
    ) -> (NormalPairResult, T, Option<reference::Stats>)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
        O: FnOnce(&NormalReady, &[Snapshot]) -> (T, [usize; 2]),
    {
        assert!(self.leaf_set_copied.is_none());
        assert!(self.copied_rust.is_none());
        assert!(self.module.is_none());
        self.pair_engine::<F, _, T, 2>(setup, |ready, points| inspect(ready.single(), points))
    }
    fn pair_engine<F, O, T, const N: usize>(
        &self,
        setup: F,
        inspect: O,
    ) -> (NormalPairResult<N>, T, Option<reference::Stats>)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
        O: FnOnce(&WalkReady, &[Snapshot]) -> (T, [usize; N]),
    {
        self.pair_engine_ready(setup, |original, _candidate, points| {
            inspect(original, points)
        })
    }
    fn pair_engine_ready<F, O, T, const N: usize>(
        &self,
        setup: F,
        inspect: O,
    ) -> (NormalPairResult<N>, T, Option<reference::Stats>)
    where
        F: for<'a> Fn(bool, NormalContext<'a>) -> i32,
        O: FnOnce(&WalkReady, &WalkReady, &[Snapshot]) -> (T, [usize; N]),
    {
        self.deadline.check();
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            unsafe { libc::getpid() } as i64
        );
        assert_eq!(
            std::fs::read_dir("/proc/self/task").unwrap().count(),
            1,
            "single-main native parent"
        );
        let profile = self.profile();
        assert_eq!(
            N,
            if matches!(profile, CallerProfile::CopiedRust(_)) {
                1
            } else if profile == CallerProfile::Module {
                4
            } else {
                2
            }
        );
        let pipes = [pipe(), pipe()];
        let output_pipes = self.reference.as_ref().map(|_| [pipe(), pipe()]);
        let control = (self.mode == Mode::CrossedOwner
            || self
                .call_pair
                .as_ref()
                .is_some_and(|p| p.case.scenario.helper()))
        .then(|| (pipe(), pipe()));
        let mut pids = [0; 2];
        for index in 0..2 {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                for (n, p) in pipes.iter().enumerate() {
                    unsafe {
                        libc::close(p[0].0);
                    }
                    if n != index {
                        unsafe {
                            libc::close(p[1].0);
                        }
                    }
                }
                let output = output_pipes.as_ref().map(|pipes| {
                    for (n, p) in pipes.iter().enumerate() {
                        unsafe {
                            libc::close(p[0].0);
                        }
                        if n != index {
                            unsafe {
                                libc::close(p[1].0);
                            }
                        }
                    }
                    reference::Output::new(Fd(pipes[index][1].0), self.deadline)
                });
                let child_control = control.as_ref().and_then(|(command, ack)| {
                    unsafe {
                        libc::close(command[1].0);
                        libc::close(ack[0].0);
                    }
                    if index == 0 {
                        unsafe {
                            libc::close(command[0].0);
                            libc::close(ack[1].0);
                        }
                        None
                    } else {
                        Some(ControlChild {
                            command: Fd(command[0].0),
                            ack: Fd(ack[1].0),
                            deadline: self.deadline,
                            next: 1,
                            pending: false,
                        })
                    }
                });
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    setup(
                        index == 1,
                        NormalContext {
                            oracle: self,
                            write: Fd(pipes[index][1].0),
                            control: child_control,
                            output,
                        },
                    )
                }));
                // Do not unwind inherited parent maps or duplicate inherited FD owners.
                unsafe {
                    libc::_exit(if matches!(result, Ok(0)) { 0 } else { 122 });
                }
            }
            if pid < 0 {
                if index == 1 {
                    drop(Tracee {
                        pid: pids[0],
                        deadline: self.deadline.end(),
                        reaped: Cell::new(false),
                    });
                }
                panic!("normal pair fork failed");
            }
            pids[index] = pid;
        }
        // Both guards precede all fallible parent work after the forks.
        let children = pids.map(|pid| Tracee {
            pid,
            deadline: self.deadline.end(),
            reaped: Cell::new(false),
        });
        let reads = pipes.map(|[read, write]| {
            drop(write);
            read
        });
        let output_reads = output_pipes.map(|pipes| {
            pipes.map(|[read, write]| {
                drop(write);
                read
            })
        });
        let mut control = control.map(|(command, ack)| {
            let [read, write] = command;
            drop(read);
            let [ack_read, ack_write] = ack;
            drop(ack_write);
            ControlParent {
                command: write,
                ack: ack_read,
                next: 1,
            }
        });
        self.deadline.check();
        let ready = reads.map(|p| {
            let wire = read_closed(p.0, self.deadline, WIRE_LIMIT);
            if let Some(expected) = &self.call_pair {
                WalkReady::CallPair(call_pair::Ready::decode(&wire, expected))
            } else if let Some(expected) = &self.leaf_set_copied {
                WalkReady::LeafSetCopied(leaf_set_copied::Ready::decode(
                    &wire,
                    expected.case,
                    &expected.plan,
                ))
            } else if let Some(expected) = &self.copied_rust {
                WalkReady::CopiedRust(copied_rust::Ready::decode(
                    &wire,
                    expected.case,
                    &expected.plan,
                ))
            } else if let Some(case) = self.module {
                WalkReady::Module(if case.is_session() {
                    module::Ready::decode_session(&wire)
                } else {
                    module::Ready::decode(&wire)
                })
            } else {
                WalkReady::Single(match &self.reference {
                    None => NormalReady::decode(&wire),
                    Some(cells) => reference::ReferenceReady::decode(&wire, cells.address()),
                })
            }
        });
        for child in &children {
            let status = child.wait();
            self.deadline.check();
            assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);
            child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        }
        let maps = if let Some(expected) = &self.call_pair {
            [
                ready[0].call_pair().validate(false, expected),
                ready[1].call_pair().validate(true, expected),
            ]
        } else if let Some(expected) = &self.leaf_set_copied {
            [
                ready[0].leaf_set_copied().validate(false, expected),
                ready[1].leaf_set_copied().validate(true, expected),
            ]
        } else if let Some(expected) = &self.copied_rust {
            [
                ready[0].copied_rust().validate(false, expected),
                ready[1].copied_rust().validate(true, expected),
            ]
        } else if let Some(case) = self.module {
            [
                ready[0].module().validate(false, case),
                ready[1].module().validate(true, case),
            ]
        } else if let Body::Csv(case) = self.body {
            assert_eq!(profile, CallerProfile::Legacy);
            assert_eq!(self.mode, Mode::Stable);
            csv::profile(self.seed, case, self.extent);
            [
                csv::validate_ready(ready[0].single(), false, self.extent),
                csv::validate_ready(ready[1].single(), true, self.extent),
            ]
        } else if profile == CallerProfile::Legacy {
            [
                ready[0].single().validate(false, self.extent, self.mode),
                ready[1].single().validate(true, self.extent, self.mode),
            ]
        } else {
            [
                ready[0]
                    .single()
                    .validate_profile(false, self.extent, self.mode, profile),
                ready[1]
                    .single()
                    .validate_profile(true, self.extent, self.mode, profile),
            ]
        };
        ready[0].same_source(&ready[1]);
        for r in &ready {
            self.disjoint(r);
        }
        let copied_dispatch = if let CallerProfile::CopiedRust(plan) = profile {
            Some(
                ready
                    .each_ref()
                    .map(|r| copied_capture::Dispatch::new(plan, r.caller())),
            )
        } else {
            None
        };
        let mut walks = [
            Walk {
                child: &children[0],
                steps: 0,
            },
            Walk {
                child: &children[1],
                steps: 0,
            },
        ];
        let saved = [
            self.reach_caller(&mut walks[0], &ready[0]),
            self.reach_caller(&mut walks[1], &ready[1]),
        ];
        assert_eq!(
            (saved[0].rdi, saved[0].rsi, saved[0].rdx),
            (saved[1].rdi, saved[1].rsi, saved[1].rdx)
        );
        if self.has_rust_caller() {
            assert_eq!(saved[0].rcx, saved[1].rcx);
        }
        let xstate = children.each_ref().map(|child| child.xstate());
        let words = [
            children[0].memory(saved[0].rsp, 8),
            children[1].memory(saved[1].rsp, 8),
        ];
        let seeded = [
            self.seed(&children[0], saved[0]),
            self.seed(&children[1], saved[1]),
        ];
        let seeded = if self.has_rust_caller() {
            assert_eq!(words[0], words[1], "one actual bridge continuation");
            let continuation = u64::from_le_bytes(words[0].as_slice().try_into().unwrap());
            std::array::from_fn(|index| {
                let mut registers = seeded[index];
                (registers.rdi, registers.rsi, registers.rdx, registers.rcx) = (
                    saved[index].rdi,
                    saved[index].rsi,
                    saved[index].rdx,
                    saved[index].rcx,
                );
                children[index].request(
                    libc::PTRACE_POKEDATA,
                    self.caller_rsp() as usize,
                    continuation as usize,
                );
                assert_eq!(children[index].memory(self.caller_rsp(), 8), words[index]);
                children[index].set_registers(&registers);
                registers
            })
        } else if self.reference.is_some() {
            std::array::from_fn(|index| {
                let mut registers = seeded[index];
                registers.rcx = saved[index].rcx; // Fourth ABI argument, after unchanged legacy RNG sequence.
                children[index].set_registers(&registers);
                registers
            })
        } else {
            seeded
        };
        let mut witnesses = self.reference.as_ref().map(|_| {
            std::array::from_fn::<_, 2, _>(|i| reference::Witness::new(self, ready[i].single()))
        });
        let mut points = Vec::new();
        let mut comparison_indices = Vec::new();
        let mut returns = [Vec::new(), Vec::new()];
        let mut calls = [0; 2];
        let mut compared = 0;
        for index in 0..2 {
            let walk = &mut walks[index];
            let r = &ready[index];
            let mut nested = self
                .call_pair
                .as_ref()
                .map(|_| call_pair::Phase::new(r.call_pair()));
            loop {
                let pc = walk.child.registers().rip;
                let caller_pc = if let Some(dispatch) = &copied_dispatch {
                    dispatch[index].is_head(pc)
                } else {
                    profile
                        .heads()
                        .iter()
                        .any(|&offset| r.caller() + offset == pc)
                };
                let logical = if caller_pc {
                    Some(pc)
                } else {
                    maps[index].get(&pc).copied()
                };
                let mut helper_before = None;
                if let Some(logical) = logical {
                    if let Some(nested) = nested.as_mut() {
                        nested.logical(self, walk.child, r.call_pair(), logical);
                    }
                    let point = self.snapshot(walk.child, r, logical);
                    if let Some(witnesses) = witnesses.as_mut() {
                        witnesses[index].unchanged(walk.child);
                        if caller_pc {
                            witnesses[index].head(&point, walk.child);
                            helper_before = Some(reference::copy_snapshot(&point));
                        }
                    }
                    let compare = !caller_pc || profile.compare(pc - r.caller());
                    if index == 0 {
                        if compare {
                            comparison_indices.push(points.len());
                        }
                        points.push(point);
                    } else if compare {
                        let at = *comparison_indices
                            .get(compared)
                            .expect("extra normal comparison point");
                        let expected = &points[at];
                        assert_eq!(
                            logical, expected.logical_pc,
                            "complete ordered declared caller/subject comparisons"
                        );
                        assert_state(expected, &point);
                        compared += 1;
                    }
                    let outer = if let Some(dispatch) = &copied_dispatch {
                        dispatch[index].outer()
                    } else {
                        r.caller() + profile.outer_ret()
                    };
                    if pc == outer {
                        break;
                    }
                }
                if let Some(nested) = nested.as_mut() {
                    let event = nested.before(self, walk, r.call_pair(), logical, &mut control);
                    self.step(
                        walk,
                        if index == 0 {
                            "nested original"
                        } else {
                            "nested candidate"
                        },
                    );
                    nested.after(event, self, walk, r.call_pair());
                    match event {
                        call_pair::phase::Event::ParentCall
                        | call_pair::phase::Event::ChildCall => calls[index] += 1,
                        call_pair::phase::Event::ChildReturn
                        | call_pair::phase::Event::ParentReturn => {
                            returns[index].push(logical.unwrap())
                        }
                        call_pair::phase::Event::None => {}
                    }
                    continue;
                }
                let call = if let Some(dispatch) = &copied_dispatch {
                    dispatch[index].call(pc)
                } else {
                    profile
                        .calls()
                        .iter()
                        .position(|&offset| r.caller() + offset == pc)
                };
                let ret = logical.filter(|logical| r.is_return(*logical));
                if let Some(n) = call {
                    if let CallerProfile::CopiedRust(plan) = profile {
                        copied_rust::call_order(calls[index], returns[index].len(), n);
                        let step = copied_dispatch.as_ref().unwrap()[index].call_step();
                        assert_eq!(
                            walk.child.memory(pc, usize::from(step.length)),
                            plan.bytes()[step.offset as usize
                                ..step.offset as usize + usize::from(step.length)]
                        );
                    } else if profile == CallerProfile::Module {
                        module::call_order(calls[index], returns[index].len(), n);
                        assert_eq!(walk.child.memory(pc, 4), module::call_bytes(n));
                    } else {
                        call_order(calls[index], returns[index].len(), n);
                        assert_eq!(walk.child.memory(pc, 3), [0x41, 0xff, 0xd5]);
                    }
                    profile.call_before(
                        &walk.child.registers(),
                        r,
                        n,
                        self.caller_rsp(),
                        self.data.address(),
                        self.bound(n),
                    );
                }
                if let Some(logical_ret) = ret {
                    let n = returns[index].len();
                    if matches!(profile, CallerProfile::CopiedRust(_)) {
                        copied_rust::ret_order(calls[index], n);
                    } else if profile == CallerProfile::Module {
                        module::ret_order(calls[index], n);
                    } else {
                        ret_order(calls[index], n);
                    }
                    assert_eq!(walk.child.memory(pc, 1), [0xc3]);
                    let regs = walk.child.registers();
                    let word = word_at(&walk.child.memory(regs.rsp, 8), regs.rsp, regs.rsp);
                    profile.ret_before(&regs, r, n, self.caller_rsp(), self.value(n), word);
                    returns[index].push(logical_ret);
                    if index == 1 {
                        let j = r.journal().unwrap();
                        let expected = profile.journal_words(
                            r,
                            self.mode,
                            walk.child.pid as u64,
                            self.caller_rsp(),
                            &returns[index],
                        );
                        check_journal(&walk.child.memory(j.address, PAGE), &expected);
                        if let Some(channel) = control.as_mut() {
                            let stopped = self.snapshot(walk.child, r, logical_ret);
                            channel.request(n + 1, walk.child, j, self.deadline);
                            // Main remains at this actual C3; helper cannot mutate application state.
                            assert_eq!(walk.child.registers().rip, pc);
                            assert_state(&stopped, &self.snapshot(walk.child, r, logical_ret));
                            check_journal(&walk.child.memory(j.address, PAGE), &expected);
                        }
                    }
                }
                self.step(
                    walk,
                    if index == 0 {
                        "normal original"
                    } else {
                        "normal candidate"
                    },
                );
                if let (Some(before), Some(witnesses)) = (helper_before, witnesses.as_mut()) {
                    let after = self.snapshot(walk.child, r, walk.child.registers().rip);
                    witnesses[index].step(&before, &after, walk.child);
                }
                if let Some(n) = call {
                    let regs = walk.child.registers();
                    let word = word_at(&walk.child.memory(regs.rsp, 8), regs.rsp, regs.rsp);
                    profile.call_after(&regs, r, n, self.caller_rsp(), word);
                    calls[index] += 1;
                }
                if ret.is_some() {
                    let n = returns[index].len() - 1;
                    let regs = walk.child.registers();
                    let address = self.caller_rsp() - self.subject_delta();
                    let word = word_at(&walk.child.memory(address, 8), address, address);
                    profile.ret_after(&regs, r, n, self.caller_rsp(), self.value(n), word);
                }
            }
            if let Some(nested) = &nested {
                nested.finish();
            }
            assert_eq!(calls[index], N);
            assert_eq!(returns[index].len(), N);
            let actual = walk.child.registers();
            callee_saves(&seeded[index], &actual);
            if !self.has_rust_caller() {
                assert_eq!(actual.rax, self.sum());
            }
            self.check_data(r, &walk.child.memory(self.data.address(), PAGE), true);
        }
        assert_eq!(compared, comparison_indices.len());
        if profile != CallerProfile::Reference {
            assert_eq!(compared, points.len());
        }
        assert_eq!(returns[0], returns[1]);
        let mut outer_point: Option<Snapshot> = None;
        for index in 0..2 {
            let walk = &mut walks[index];
            let actual = walk.child.registers();
            assert_eq!(actual.rip, ready[index].caller() + profile.outer_ret());
            assert_eq!(walk.child.memory(saved[index].rsp, 8), words[index]);
            let continuation = u64::from_le_bytes(words[index].as_slice().try_into().unwrap());
            let mut after = if self.has_rust_caller() {
                assert_eq!(walk.child.memory(self.caller_rsp(), 8), words[index]);
                let before = self.snapshot(walk.child, &ready[index], actual.rip);
                self.step(walk, "copied Rust actual outer RET before restoration");
                let point = self.snapshot(walk.child, &ready[index], continuation);
                copied_rust::outer_effect(&before, &point, self.stack_start());
                if index == 0 {
                    outer_point = Some(point);
                } else {
                    assert_state(outer_point.as_ref().unwrap(), &point);
                    compared += 1;
                }
                let mut resume = saved[index];
                resume.rip = continuation;
                resume.rsp = saved[index].rsp.checked_add(8).unwrap();
                resume.rax = actual.rax;
                // The actual RET flags were compared above; now restore the
                // separate saved harness state together with its GPRs/XSAVE.
                walk.child.set_xstate(&xstate[index]);
                resume
            } else {
                let mut restored = saved[index];
                restored.rip = actual.rip;
                restored.rax = actual.rax;
                walk.child.set_registers(&restored);
                walk.child.set_xstate(&xstate[index]);
                self.step(walk, "normal actual outer RET");
                let after = walk.child.registers();
                assert_eq!(
                    (after.rip, after.rsp, after.rax),
                    (continuation, saved[index].rsp + 8, actual.rax)
                );
                after
            };
            assert_eq!(walk.child.memory(saved[index].rsp, 8), words[index]);
            if let Some(witnesses) = witnesses.as_mut() {
                witnesses[index].returned(walk.child);
            }
            after.eflags = harness_resume_flags(saved[index].eflags, after.eflags);
            walk.child.set_registers(&after);
            walk.child.request(libc::PTRACE_CONT, 0, 0);
            let status = walk.child.wait();
            self.deadline.check();
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "normal child postflight/checkpoint/join failed: {status:#x}"
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
            self.deadline.check();
        }
        if let Some(point) = outer_point {
            points.push(point);
            assert_eq!(compared, points.len());
        }
        if let Some(channel) = control {
            channel.finish(self.deadline);
        }
        let stats = match (witnesses, output_reads) {
            (None, None) => None,
            (Some(witnesses), Some(reads)) => {
                let exports =
                    reads.map(|fd| read_closed(fd.0, self.deadline, reference::bytes::CELLS_BYTES));
                Some(reference::finish_pair(witnesses, exports))
            }
            _ => panic!("reference postflight ownership mismatch"),
        };
        // Original effects/body interpretations happen only after both normal reaps.
        if profile == CallerProfile::Legacy {
            caller_effects(
                &points,
                ready[0].caller(),
                ready[0].single().entry,
                self.data.address(),
                self.stack_start(),
            );
        }
        if profile == CallerProfile::Module {
            module::caller_effects(
                &points,
                ready[0].module(),
                self.data.address(),
                self.stack_start(),
            );
        }
        if self.call_pair.is_some() {
            copied_rust::caller_effects_view(
                &points,
                ready[0].call_pair().view(),
                self.data.address(),
                self.stack_start(),
            );
        } else if self.leaf_set_copied.is_some() {
            copied_rust::caller_effects_view(
                &points,
                ready[0].copied_view(),
                self.data.address(),
                self.stack_start(),
            );
        } else if self.copied_rust.is_some() {
            copied_rust::caller_effects(
                &points,
                ready[0].copied_rust(),
                self.data.address(),
                self.stack_start(),
            );
        }
        let (trace, visits) = inspect(&ready[0], &ready[1], &points);
        let (values, outer_value) = if let Some(profile) = &self.call_pair {
            assert_eq!(N, 2);
            (
                std::array::from_fn(|i| {
                    if i == 0 {
                        profile.case.value()
                    } else {
                        profile.case.fields()
                    }
                }),
                points.last().unwrap().registers.rax,
            )
        } else if let Some(profile) = &self.leaf_set_copied {
            (
                [profile.case.value(); N],
                points.last().unwrap().registers.rax,
            )
        } else if let Some(profile) = &self.copied_rust {
            (
                [profile.case.value(); N],
                points.last().unwrap().registers.rax,
            )
        } else if let Some(case) = self.module {
            (std::array::from_fn(|n| case.value(n)), case.sum())
        } else {
            let value = self.body.scalar();
            ([value; N], value.wrapping_mul(2))
        };
        let result = NormalPairResult {
            comparisons: compared,
            original_steps: walks[0].steps,
            candidate_steps: walks[1].steps,
            visits,
            returns: returns[0].clone().try_into().unwrap(),
            declared_returns: ready[0].declared_returns(),
            values,
            outer_value,
            target_calls: 2 * N,
            target_returns: 2 * N,
            outer_returns: 2,
            normal_reaps: 2,
        };
        self.deadline.check();
        (result, trace, stats)
    }
    fn disjoint(&self, ready: &WalkReady) {
        let owned = [
            (self.data.address(), self.data.address() + PAGE as u64),
            (
                self.stack.address(),
                self.stack.address() + (STACK_BYTES + PAGE) as u64,
            ),
        ];
        if let Some(cells) = &self.reference {
            cells.disjoint(ready.single(), &owned);
        }
        for (a, b) in ready.caller_immutable().iter().chain(ready.immutable()) {
            let end = a.checked_add(b.len() as u64).unwrap();
            assert!(owned.iter().all(|&(low, high)| end <= low || high <= *a));
        }
        if let Some(j) = ready.journal() {
            let end = j.address.checked_add(PAGE as u64).unwrap();
            assert!(
                owned
                    .iter()
                    .all(|&(low, high)| end <= low || high <= j.address)
            );
        }
    }
    fn inspect(&self, ready: &NormalReady, points: &[Snapshot]) -> NormalTrace {
        let case = self.body.strnlen();
        let bodies = self.inspect_bodies(ready, points, |_, body| {
            strnlen::inspect_normal_body(
                case,
                body.entry,
                body.continuation,
                body.input_address,
                body.code,
                body.steps,
            )
        });
        NormalTrace { bodies }
    }
    fn inspect_bodies<T, O>(
        &self,
        ready: &NormalReady,
        points: &[Snapshot],
        mut inspect: O,
    ) -> [T; 2]
    where
        O: for<'a> FnMut(usize, OriginalBody<'a>) -> T,
    {
        let steps: Vec<_> = points
            .windows(2)
            .map(|w| OriginalStep {
                before: w[0].registers,
                after: w[1].registers,
                data_address: self.data.address(),
                data: &w[0].data,
                stack_address: self.stack_start(),
                stack: &w[0].application_stack,
            })
            .collect();
        let starts: Vec<_> = steps
            .iter()
            .enumerate()
            .filter_map(|(n, s)| (s.before.rip == ready.entry).then_some(n))
            .collect();
        assert_eq!(starts.len(), 2);
        let code = bytes_at(
            &ready.original_source,
            ready.immutable[0].0,
            ready.entry,
            self.extent,
        );
        std::array::from_fn(|index| {
            let start = starts[index];
            assert_eq!(
                steps[start - 1].before.rip,
                ready.caller + self.profile().calls()[index]
            );
            let finish = (start..steps.len())
                .find(|&n| ready.returns.contains(&steps[n].before.rip))
                .unwrap();
            assert!(index == 1 || finish < starts[1]);
            assert_eq!(
                steps[finish].after.rip,
                ready.caller + self.profile().continuations()[index]
            );
            inspect(
                index,
                OriginalBody {
                    entry: ready.entry,
                    continuation: ready.caller + self.profile().continuations()[index],
                    input_address: self.data.address() + INPUT as u64,
                    input: &self.data.bytes()[INPUT..INPUT + self.body.bound()],
                    code,
                    steps: &steps[start..=finish],
                },
            )
        })
    }
}

fn arithmetic_flags(old: u64, a: u64, b: u64, subtract: bool) -> u64 {
    let (result, carry) = if subtract {
        a.overflowing_sub(b)
    } else {
        a.overflowing_add(b)
    };
    let overflow = if subtract {
        ((a ^ b) & (a ^ result)) >> 63 != 0
    } else {
        (!(a ^ b) & (a ^ result)) >> 63 != 0
    };
    const FLAGS: u64 = 1 | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    (old & !FLAGS)
        | u64::from(carry)
        | (u64::from((result as u8).count_ones() % 2 == 0) << 2)
        | (u64::from((a ^ b ^ result) & 0x10 != 0) << 4)
        | (u64::from(result == 0) << 6)
        | ((result >> 63) << 7)
        | (u64::from(overflow) << 11)
}
fn put_word(bytes: &mut [u8], base: u64, address: u64, value: u64) {
    let at = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
/// Independent original-only interpretation of every fixed caller instruction.
/// The two subject traces are inspected separately; no candidate defines truth.
fn caller_effects(points: &[Snapshot], caller: u64, target: u64, data: u64, stack: u64) {
    let seen: Vec<_> = points
        .iter()
        .filter_map(|p| {
            p.logical_pc
                .checked_sub(caller)
                .filter(|offset| HEADS.contains(offset))
        })
        .collect();
    assert_eq!(seen, HEADS, "all 24 caller heads once, in order");
    for pair in points.windows(2) {
        let before = &pair[0];
        let after = &pair[1];
        if before
            .logical_pc
            .checked_sub(caller)
            .is_some_and(|o| HEADS.contains(&o))
        {
            caller_step(before, after, caller, target, data, stack);
        }
    }
}
fn caller_step(
    before: &Snapshot,
    after: &Snapshot,
    caller: u64,
    target: u64,
    data: u64,
    stack: u64,
) {
    let offset = before.logical_pc.checked_sub(caller).unwrap();
    assert!(HEADS.contains(&offset) && offset != OUTER_RET);
    let mut expected = Snapshot {
        logical_pc: 0,
        registers: before.registers,
        xstate: before.xstate.clone(),
        data: before.data.clone(),
        application_stack: before.application_stack.clone(),
    };
    let r = &mut expected.registers;
    let index = HEADS.iter().position(|&n| n == offset).unwrap();
    expected.logical_pc = caller + HEADS[index + 1];
    match offset {
        0 | 5 | 10 | 14 => {
            let value = match offset {
                0 => r.r13,
                5 => r.r12,
                10 => r.rbp,
                _ => r.rbx,
            };
            r.rsp = r.rsp.checked_sub(8).unwrap();
            put_word(&mut expected.application_stack, stack, r.rsp, value);
        }
        2 => r.r13 = r.rdi,
        7 => r.r12 = r.rdx,
        11 => r.rbp = r.rsi,
        15 => {
            r.eflags = arithmetic_flags(r.eflags, r.rsp, 8, true);
            r.rsp = r.rsp.checked_sub(8).unwrap();
        }
        19 => r.rdi = word_at(&before.data, data, r.rbp),
        23 => r.rsi = word_at(&before.data, data, r.rsi.checked_add(8).unwrap()),
        27 | 45 => {
            assert_eq!(r.r13, target);
            r.rsp = r.rsp.checked_sub(8).unwrap();
            put_word(
                &mut expected.application_stack,
                stack,
                r.rsp,
                expected.logical_pc,
            );
            expected.logical_pc = target;
        }
        30 => r.rdi = word_at(&before.data, data, r.rbp.checked_add(16).unwrap()),
        34 => {
            assert_eq!(r.r12, data + RESULTS as u64);
            put_word(&mut expected.data, data, r.r12, r.rax);
        }
        38 => r.rbx = r.rax,
        41 => r.rsi = word_at(&before.data, data, r.rbp.checked_add(24).unwrap()),
        48 => {
            assert_eq!(r.r12, data + RESULTS as u64);
            put_word(&mut expected.data, data, r.r12 + 8, r.rax);
        }
        53 => {
            r.eflags = arithmetic_flags(r.eflags, r.rsp, 8, false);
            r.rsp = r.rsp.checked_add(8).unwrap();
        }
        57 => {
            r.eflags = arithmetic_flags(r.eflags, r.rax, r.rbx, false);
            r.rax = r.rax.wrapping_add(r.rbx);
        }
        60 | 61 | 62 | 64 => {
            let value = word_at(&before.application_stack, stack, r.rsp);
            match offset {
                60 => r.rbx = value,
                61 => r.rbp = value,
                62 => r.r12 = value,
                _ => r.r13 = value,
            };
            r.rsp = r.rsp.checked_add(8).unwrap();
        }
        _ => panic!("unhandled fixed caller instruction"),
    }
    assert_eq!(
        after.registers.rip, expected.logical_pc,
        "actual original successor"
    );
    assert_state(&expected, after);
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub(super) struct BodyCoverage {
    pub(super) heads: BTreeSet<u64>,
    pub(super) edges: BTreeSet<(u64, u64)>,
    pub(super) returns: BTreeSet<u64>,
}
impl BodyCoverage {
    fn extend(&mut self, other: &Self) {
        self.heads.extend(&other.heads);
        self.edges.extend(&other.edges);
        self.returns.extend(&other.returns);
    }
    fn subset(&self, other: &Self) -> bool {
        self.heads.is_subset(&other.heads)
            && self.edges.is_subset(&other.edges)
            && self.returns.is_subset(&other.returns)
    }
}
#[derive(Clone)]
pub struct BodyTrace {
    pub(super) entry: u64,
    pub(super) code: Vec<u8>,
    pub(super) declared: BodyCoverage,
    pub(super) observed: BodyCoverage,
    pub visits: usize,
    pub input_reads: usize,
    pub input_bytes: usize,
    pub ret_offset: u64,
}
impl BodyTrace {
    pub fn observed_heads(&self) -> usize {
        self.observed.heads.len()
    }
    pub fn observed_edges(&self) -> usize {
        self.observed.edges.len()
    }
    pub fn declared_heads(&self) -> usize {
        self.declared.heads.len()
    }
    pub fn declared_edges(&self) -> usize {
        self.declared.edges.len()
    }
    pub fn declared_returns(&self) -> usize {
        self.declared.returns.len()
    }
}
pub struct NormalTrace {
    pub bodies: [BodyTrace; 2],
}
fn validate_pair(case: Case, pair: &NormalPairResult, trace: &NormalTrace) {
    assert!(CASES.contains(&case));
    assert_eq!(
        (
            pair.target_calls,
            pair.target_returns,
            pair.outer_returns,
            pair.normal_reaps
        ),
        (4, 4, 2, 2)
    );
    assert_eq!(pair.values, [strnlen::cases::scalar(case); 2]);
    assert_eq!(
        pair.outer_value,
        pair.values[0].wrapping_add(pair.values[1])
    );
    assert_eq!(pair.visits, trace.bodies.each_ref().map(|b| b.visits));
    assert!(pair.visits.iter().all(|&n| n > 0));
    assert_eq!(
        pair.comparisons,
        HEADS.len() + pair.visits[0] + pair.visits[1]
    );
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
    let [a, b] = &trace.bodies;
    assert_eq!(
        (a.entry, &a.code, &a.declared),
        (b.entry, &b.code, &b.declared)
    );
    for (n, body) in trace.bodies.iter().enumerate() {
        assert_eq!(
            pair.returns[n],
            body.entry.checked_add(body.ret_offset).unwrap()
        );
        assert_eq!(body.observed.returns, BTreeSet::from([body.ret_offset]));
        assert!(body.observed.subset(&body.declared));
        assert_eq!(
            pair.declared_returns,
            body.declared
                .returns
                .iter()
                .map(|r| body.entry.checked_add(*r).unwrap())
                .collect()
        );
        if case.bound == 0 {
            assert_eq!((body.input_reads, body.input_bytes), (0, 0));
        } else {
            assert!(body.input_reads > 0);
        }
        assert!(body.input_reads <= body.visits);
        assert!(
            (body.input_reads..=body.input_reads.checked_mul(8).unwrap())
                .contains(&body.input_bytes)
        );
    }
}
fn validate_exact_pair(
    case: ExactCase,
    pair: &NormalPairResult,
    counts: &[(usize, usize, usize, usize); 2],
) {
    assert_eq!(*counts, [case.counts(); 2]);
    assert_eq!(pair.visits, [case.counts().0; 2]);
    assert_eq!(pair.comparisons, HEADS.len() + 2 * case.counts().0);
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
    assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
    assert_eq!(pair.values, [case.scalar(); 2]);
    assert_eq!(pair.outer_value, case.scalar().wrapping_mul(2));
    assert_eq!(pair.returns, [pair.returns[0]; 2]);
    assert_eq!(pair.declared_returns, BTreeSet::from([pair.returns[0]]));
    assert_eq!(
        (
            pair.target_calls,
            pair.target_returns,
            pair.outer_returns,
            pair.normal_reaps
        ),
        (4, 4, 2, 2)
    );
}

#[derive(Default)]
pub struct Population {
    next: usize,
    declared: Option<(Vec<u8>, BodyCoverage)>,
    observed: BodyCoverage,
    comparisons: usize,
    input_reads: usize,
    input_bytes: usize,
}
pub struct Totals {
    pub comparisons: usize,
    pub input_reads: usize,
    pub input_bytes: usize,
}
impl Population {
    pub fn record(&mut self, seed: u64, case: Case, pair: &NormalPairResult, trace: &NormalTrace) {
        assert!(self.next < 16);
        assert_eq!(seed, SEEDS[self.next / 8]);
        assert_eq!(case, CASES[self.next % 8]);
        validate_pair(case, pair, trace);
        for body in &trace.bodies {
            if let Some((code, declared)) = &self.declared {
                assert_eq!(code, &body.code);
                assert_eq!(declared, &body.declared);
            } else {
                self.declared = Some((body.code.clone(), body.declared.clone()));
            }
            self.observed.extend(&body.observed);
            self.input_reads = self.input_reads.checked_add(body.input_reads).unwrap();
            self.input_bytes = self.input_bytes.checked_add(body.input_bytes).unwrap();
        }
        if self.next % 8 == 7 {
            assert_eq!(
                &self.observed,
                &self.declared.as_ref().unwrap().1,
                "each seed's complete two-call CFG/RET union"
            );
            self.observed = BodyCoverage::default();
        }
        self.comparisons = self.comparisons.checked_add(pair.comparisons).unwrap();
        self.next += 1;
    }
    pub fn finish(self) -> Totals {
        assert_eq!(self.next, 16);
        assert_eq!(self.observed, BodyCoverage::default());
        assert!(self.declared.is_some());
        Totals {
            comparisons: self.comparisons,
            input_reads: self.input_reads,
            input_bytes: self.input_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    fn rejects(f: impl FnOnce()) {
        assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
    }
    fn regs() -> libc::user_regs_struct {
        unsafe { core::mem::zeroed() }
    }
    fn ready(candidate: bool, mode: Mode) -> NormalReady {
        let mut caller = vec![0; PAGE];
        caller[..BYTES.len()].copy_from_slice(BYTES);
        let mut code = vec![0; PAGE];
        code[..5].copy_from_slice(&[0x31, 0xc0, 0x90, 0x90, 0xc3]);
        NormalReady {
            caller: 0x1000,
            caller_immutable: vec![(0x1000, caller)],
            entry: 0x3000,
            heads: vec![0x3000, 0x3002, 0x3003, 0x3004],
            returns: vec![0x3004],
            boundaries: vec![
                (0x3000, 0x3000),
                (0x3002, 0x3002),
                (0x3003, 0x3003),
                (0x3004, 0x3004),
            ],
            immutable: vec![(0x3000, code.clone())],
            original_source: code,
            journal: candidate.then_some(JournalReady {
                address: 0x7000,
                a_generation: 11,
                b_generation: (mode == Mode::CrossedOwner).then_some(12),
                helper_tid: (mode == Mode::CrossedOwner).then_some(99),
            }),
        }
    }
    #[test]
    fn normal_ready_refuses_wrong_caller_maps_and_extents() {
        ready(false, Mode::Stable).validate(false, 5, Mode::Stable);
        ready(true, Mode::Stable).validate(true, 5, Mode::Stable);
        for index in 0..BYTES.len() {
            let mut r = ready(false, Mode::Stable);
            r.caller_immutable[0].1[index] ^= 1;
            rejects(|| {
                r.validate(false, 5, Mode::Stable);
            });
        }
        for change in 0..9 {
            let mut r = ready(true, Mode::Stable);
            match change {
                0 => {
                    r.boundaries.pop();
                }
                1 => r.boundaries[3] = r.boundaries[0],
                2 => r.boundaries[0].1 = 0x5000,
                3 => r.heads[1] += 1,
                4 => r.returns[0] -= 1,
                5 => r.caller += 1,
                6 => r.caller_immutable[0].1.pop().map(|_| ()).unwrap(),
                7 => r.immutable[0].0 = 0x1000,
                _ => r.journal.as_mut().unwrap().address = 0x3000,
            }
            rejects(|| {
                r.validate(true, 5, Mode::Stable);
            });
        }
        for extent in [4, 6, 81] {
            rejects(|| {
                ready(false, Mode::Stable).validate(false, extent, Mode::Stable);
            });
        }
    }
    #[test]
    fn normal_wire_refuses_truncation_tail_and_journal_profile() {
        for candidate in [false, true] {
            let r = ready(candidate, Mode::Stable);
            let bytes = r.encode();
            let decoded = NormalReady::decode(&bytes);
            r.same_source(&decoded);
            decoded.validate(candidate, 5, Mode::Stable);
            for cut in [0, 7, 16, bytes.len() - 1] {
                rejects(|| {
                    NormalReady::decode(&bytes[..cut]);
                });
            }
            let mut tail = bytes.clone();
            tail.push(0);
            rejects(|| {
                NormalReady::decode(&tail);
            });
        }
        let cross = ready(true, Mode::CrossedOwner);
        cross.validate(true, 5, Mode::CrossedOwner);
        rejects(|| {
            cross.validate(true, 5, Mode::Stable);
        });
        rejects(|| {
            ready(true, Mode::Stable).validate(true, 5, Mode::CrossedOwner);
        });
        rejects(|| {
            ready(false, Mode::Stable).validate(true, 5, Mode::Stable);
        });
        let mut r = ready(true, Mode::CrossedOwner);
        r.journal.as_mut().unwrap().b_generation = Some(11);
        rejects(|| {
            r.validate(true, 5, Mode::CrossedOwner);
        });
    }
    #[test]
    fn normal_transfers_refuse_wrong_target_word_rsp_and_order() {
        let r = ready(false, Mode::Stable);
        let rsp = 0x9008;
        let data = 0x20000;
        for n in 0..2 {
            call_order(n, n, n);
            ret_order(n + 1, n);
            let mut before = regs();
            before.rip = r.caller + CALLS[n];
            before.r13 = r.entry;
            before.rdi = data + INPUT as u64;
            before.rsi = 64;
            before.rsp = rsp - 40;
            call_before(&before, &r, n, rsp, data, 64);
            for field in 0..5 {
                let mut bad = before;
                match field {
                    0 => bad.rip += 1,
                    1 => bad.r13 += 1,
                    2 => bad.rdi += 1,
                    3 => bad.rsi -= 1,
                    _ => bad.rsp -= 8,
                };
                rejects(|| call_before(&bad, &r, n, rsp, data, 64));
            }
            let mut entry = before;
            entry.rip = r.entry;
            entry.rsp -= 8;
            let word = r.caller + CONTINUATIONS[n];
            call_after(&entry, &r, n, rsp, word);
            rejects(|| call_after(&entry, &r, n, rsp, word + 1));
            let mut exit = entry;
            exit.rip = r.returns[0];
            exit.rax = 64;
            ret_before(&exit, &r, n, rsp, 64, word);
            rejects(|| ret_before(&exit, &r, n, rsp, 63, word));
            rejects(|| ret_before(&exit, &r, n, rsp + 8, 64, word));
            let mut returned = exit;
            returned.rip = word;
            returned.rsp += 8;
            ret_after(&returned, &r, n, rsp, 64, word);
            rejects(|| ret_after(&returned, &r, n, rsp, 64, word + 1));
        }
        for (calls, returns, index) in [(1, 0, 1), (0, 0, 1), (2, 2, 2), (1, 1, 0)] {
            rejects(|| call_order(calls, returns, index));
        }
        for (calls, returns) in [(0, 0), (1, 1), (2, 0), (3, 2)] {
            rejects(|| ret_order(calls, returns));
        }
    }
    #[test]
    fn normal_epilogue_data_and_pending_journal_refuse() {
        let base = regs();
        callee_saves(&base, &base);
        for n in 0..7 {
            let mut r = base;
            match n {
                0 => r.rbx = 1,
                1 => r.rbp = 1,
                2 => r.r12 = 1,
                3 => r.r13 = 1,
                4 => r.r14 = 1,
                5 => r.r15 = 1,
                _ => r.rsp = 8,
            };
            rejects(|| callee_saves(&base, &r));
        }
        let initial = vec![0x7e; PAGE];
        let mut data = initial.clone();
        data[RESULTS..RESULTS + 8].copy_from_slice(&64_u64.to_le_bytes());
        data[RESULTS + 8..RESULTS + 16].copy_from_slice(&64_u64.to_le_bytes());
        final_data(&initial, &data, 64);
        for at in [
            0,
            INPUT,
            REQUESTS,
            RESULTS,
            RESULTS + 8,
            RESULTS + 16,
            PAGE - 1,
        ] {
            let mut changed = data.clone();
            changed[at] ^= 1;
            rejects(|| final_data(&initial, &changed, 64));
        }
        for mode in [Mode::Stable, Mode::CrossedOwner] {
            let r = ready(true, mode);
            for count in 1..=2 {
                let expected = journal_words(&r, mode, 42, 0x9008, &vec![0x3004; count]);
                let bytes: Vec<_> = expected.iter().flat_map(|n| n.to_le_bytes()).collect();
                check_journal(&bytes, &expected);
                assert_eq!(expected[3], 1, "pre-RET receipt still pending");
                for at in [0, 1, 3, 4, 7, 9, 10, 4 + 14 * count - 1, 511] {
                    let mut changed = bytes.clone();
                    changed[at * 8] ^= 1;
                    rejects(|| check_journal(&changed, &expected));
                }
            }
        }
    }
    fn point(pc: u64) -> Snapshot {
        let mut r = regs();
        r.rip = pc;
        r.rsp = 0x8100;
        r.eflags = 0x202;
        Snapshot {
            logical_pc: pc,
            registers: r,
            xstate: vec![7; 64],
            data: vec![0; PAGE],
            application_stack: vec![0; 512],
        }
    }
    fn copy(p: &Snapshot) -> Snapshot {
        Snapshot {
            logical_pc: p.logical_pc,
            registers: p.registers,
            xstate: p.xstate.clone(),
            data: p.data.clone(),
            application_stack: p.application_stack.clone(),
        }
    }
    #[test]
    fn normal_original_caller_transition_effects_refuse() {
        let caller = 0x1000;
        let target = 0x3000;
        let data = 0x20000;
        let stack = 0x8000;
        let mut before = point(caller);
        before.registers.r13 = 0x1234;
        let mut after = copy(&before);
        after.logical_pc = caller + 2;
        after.registers.rip = caller + 2;
        after.registers.rsp -= 8;
        put_word(&mut after.application_stack, stack, 0x80f8, 0x1234);
        caller_step(&before, &after, caller, target, data, stack);
        let mut wrong = copy(&after);
        wrong.application_stack[0xf8] ^= 1;
        rejects(|| caller_step(&before, &wrong, caller, target, data, stack));
        let mut before = point(caller + 27);
        before.registers.r13 = target;
        let mut after = copy(&before);
        after.logical_pc = target;
        after.registers.rip = target;
        after.registers.rsp -= 8;
        put_word(&mut after.application_stack, stack, 0x80f8, caller + 30);
        caller_step(&before, &after, caller, target, data, stack);
        let mut wrong = copy(&after);
        wrong.registers.rip += 1;
        rejects(|| caller_step(&before, &wrong, caller, target, data, stack));
        let mut before = point(caller + 48);
        before.registers.r12 = data + RESULTS as u64;
        before.registers.rax = 37;
        let mut after = copy(&before);
        after.logical_pc = caller + 53;
        after.registers.rip = caller + 53;
        after.data[RESULTS + 8..RESULTS + 16].copy_from_slice(&37_u64.to_le_bytes());
        caller_step(&before, &after, caller, target, data, stack);
        let mut wrong = copy(&after);
        wrong.data[RESULTS] = 37;
        rejects(|| caller_step(&before, &wrong, caller, target, data, stack));
        let mut before = point(caller + 57);
        before.registers.rax = u64::MAX;
        before.registers.rbx = 1;
        let mut after = copy(&before);
        after.logical_pc = caller + 60;
        after.registers.rip = caller + 60;
        after.registers.rax = 0;
        after.registers.eflags = 0x257;
        caller_step(&before, &after, caller, target, data, stack);
        for field in 0..3 {
            let mut wrong = copy(&after);
            match field {
                0 => wrong.registers.eflags ^= 1,
                1 => wrong.xstate[5] ^= 1,
                _ => wrong.registers.r12 ^= 1,
            };
            rejects(|| caller_step(&before, &wrong, caller, target, data, stack));
        }
        assert_eq!(arithmetic_flags(0x202, 0, 1, true), 0x297);
    }
    #[test]
    fn normal_control_ack_refuses_wrong_stage_identity_owner_and_tail() {
        let ready = ready(true, Mode::CrossedOwner);
        let j = ready.journal.unwrap();
        for stage in 1..=2 {
            let good = [
                ACK_MAGIC,
                stage as u64,
                42,
                99,
                11,
                12,
                u64::from(stage == 2),
                0,
                3,
                12,
            ];
            check_ack(&good, stage, 42, &j);
            for n in 0..ACK_WORDS {
                let mut bad = good;
                bad[n] ^= 1;
                rejects(|| check_ack(&bad, stage, 42, &j));
            }
            let mut duplicate = good.to_vec();
            duplicate.extend(good);
            rejects(|| check_ack(&duplicate, stage, 42, &j));
            rejects(|| check_ack(&good[..ACK_WORDS - 1], stage, 42, &j));
            rejects(|| check_ack(&good, 3 - stage, 42, &j));
        }
        rejects(|| check_ack(&[], 0, 42, &j));
        rejects(|| check_ack(&[], 3, 42, &j));
        let same = JournalReady {
            helper_tid: Some(42),
            ..j
        };
        rejects(|| check_ack(&[ACK_MAGIC, 1, 42, 42, 11, 12, 0, 0, 3, 12], 1, 42, &same));
    }
    fn pair(case: Case) -> (NormalPairResult, NormalTrace) {
        let declared = BodyCoverage {
            heads: BTreeSet::from([0, 4]),
            edges: BTreeSet::from([(0, 4)]),
            returns: BTreeSet::from([4]),
        };
        let t = BodyTrace {
            entry: 0x3000,
            code: vec![0x31, 0xc0, 0x90, 0x90, 0xc3],
            declared: declared.clone(),
            observed: declared,
            visits: 2,
            input_reads: usize::from(case.bound != 0),
            input_bytes: usize::from(case.bound != 0),
            ret_offset: 4,
        };
        let value = strnlen::cases::scalar(case);
        (
            NormalPairResult {
                comparisons: 28,
                original_steps: 29,
                candidate_steps: 41,
                visits: [2; 2],
                returns: [0x3004; 2],
                declared_returns: BTreeSet::from([0x3004]),
                values: [value; 2],
                outer_value: value * 2,
                target_calls: 4,
                target_returns: 4,
                outer_returns: 2,
                normal_reaps: 2,
            },
            NormalTrace {
                bodies: [t.clone(), t],
            },
        )
    }
    #[test]
    fn normal_population_refuses_missing_second_body_order_and_coverage() {
        let mut population = Population::default();
        for seed in SEEDS {
            for case in CASES {
                let (p, t) = pair(case);
                population.record(seed, case, &p, &t);
            }
        }
        assert_eq!(population.finish().comparisons, 16 * 28);
        let (p, t) = pair(CASES[0]);
        rejects(|| Population::default().record(SEEDS[1], CASES[0], &p, &t));
        rejects(|| Population::default().record(SEEDS[0], CASES[1], &p, &t));
        rejects(|| {
            Population::default().finish();
        });
        let mut wrong = t;
        wrong.bodies[1].ret_offset = 3;
        rejects(|| validate_pair(CASES[0], &p, &wrong));
        let (_, mut missing) = pair(CASES[0]);
        missing.bodies[0].declared.heads.insert(2);
        missing.bodies[1].declared.heads.insert(2);
        rejects(|| {
            let mut population = Population::default();
            for case in CASES {
                let (p, mut t) = pair(case);
                t.bodies[0].declared = missing.bodies[0].declared.clone();
                t.bodies[1].declared = missing.bodies[1].declared.clone();
                population.record(SEEDS[0], case, &p, &t);
            }
        });
    }
    #[test]
    fn normal_mode_and_completion_counts_preserve_fixed_bounds() {
        mode_case(SEEDS[0], CASES[7], 5, Mode::CrossedOwner);
        mode_case(SEEDS[1], CASES[0], 80, Mode::Stable);
        for extent in [0, 4, 81, 256] {
            rejects(|| mode_case(SEEDS[0], CASES[7], extent, Mode::Stable));
        }
        rejects(|| mode_case(SEEDS[1], CASES[7], 5, Mode::CrossedOwner));
        rejects(|| mode_case(SEEDS[0], CASES[6], 5, Mode::CrossedOwner));
        for change in 0..9 {
            let (mut p, t) = pair(CASES[7]);
            validate_pair(CASES[7], &p, &t);
            match change {
                0 => p.normal_reaps = 1,
                1 => p.outer_returns = 1,
                2 => p.target_calls = 3,
                3 => p.target_returns = 3,
                4 => p.comparisons -= 1,
                5 => p.original_steps = MAX_STEPS + 1,
                6 => p.candidate_steps = MAX_STEPS + 1,
                7 => p.values[1] -= 1,
                _ => p.visits[1] = 0,
            };
            rejects(|| validate_pair(CASES[7], &p, &t));
        }
    }
}

#[cfg(test)]
mod exact_tests {
    use super::*;
    fn rejects(f: impl FnOnce() + std::panic::UnwindSafe) {
        assert!(std::panic::catch_unwind(f).is_err());
    }
    fn pair(case: ExactCase) -> NormalPairResult {
        let comparisons = 24 + 2 * case.counts().0;
        NormalPairResult {
            comparisons,
            original_steps: comparisons,
            candidate_steps: comparisons,
            visits: [case.counts().0; 2],
            returns: [0x1024; 2],
            declared_returns: BTreeSet::from([0x1024]),
            values: [case.scalar(); 2],
            outer_value: case.scalar().wrapping_mul(2),
            target_calls: 4,
            target_returns: 4,
            outer_returns: 2,
            normal_reaps: 2,
        }
    }
    #[test]
    fn exact_normal_closed_cases_input_and_counts() {
        for (index, seed) in SEEDS.into_iter().enumerate() {
            for length in [1, 64] {
                let case = ExactCase::new(seed, length);
                assert_eq!(case.length(), length);
                assert_eq!(
                    case.input(),
                    std::array::from_fn(|j| ((37 * j + 11 + index) % 256) as u8)
                );
                let sum = (0..length).fold(0_u64, |sum, j| {
                    sum + u64::from(((37 * j + 11 + index) % 256) as u8 ^ 0x5a)
                });
                assert_eq!(case.scalar(), sum ^ 0x9e3779b97f4a7c15);
                assert_eq!(
                    case.counts(),
                    if length == 1 {
                        (11, 1, 0, 2)
                    } else {
                        (389, 64, 63, 65)
                    }
                );
                assert_eq!(Body::Exact(case).bound(), length);
                assert_eq!(Body::Exact(case).input(), case.input());
                assert_eq!(Body::Exact(case).scalar(), case.scalar());
                rejects(|| {
                    Body::Exact(case).strnlen();
                });
            }
        }
        for length in [0, 2, 63, 65, usize::MAX] {
            rejects(|| {
                ExactCase::new(SEEDS[0], length);
            });
        }
        rejects(|| {
            ExactCase::new(0, 1);
        });
        for case in CASES {
            assert_eq!(Body::Strnlen(case).strnlen(), case);
            assert_eq!(Body::Strnlen(case).bound(), case.bound);
            assert_eq!(Body::Strnlen(case).input(), strnlen::cases::input(case));
            assert_eq!(Body::Strnlen(case).scalar(), strnlen::cases::scalar(case));
        }
    }
    #[test]
    fn exact_normal_pair_rejects_count_step_return_value_or_reap_drift() {
        for seed in SEEDS {
            for length in [1, 64] {
                let case = ExactCase::new(seed, length);
                validate_exact_pair(case, &pair(case), &[case.counts(); 2]);
                for field in 0..13 {
                    let mut bad = pair(case);
                    match field {
                        0 => bad.comparisons += 1,
                        1 => bad.original_steps = bad.comparisons - 1,
                        2 => bad.candidate_steps = MAX_STEPS + 1,
                        3 => bad.visits[1] += 1,
                        4 => bad.values[0] ^= 1,
                        5 => bad.outer_value ^= 1,
                        6 => bad.returns[1] += 1,
                        7 => {
                            bad.declared_returns.insert(0x1025);
                        }
                        8 => bad.target_calls -= 1,
                        9 => bad.target_returns -= 1,
                        10 => bad.outer_returns -= 1,
                        11 => bad.normal_reaps -= 1,
                        12 => bad.original_steps = MAX_STEPS + 1,
                        _ => unreachable!(),
                    }
                    rejects(|| validate_exact_pair(case, &bad, &[case.counts(); 2]));
                }
                for index in 0..2 {
                    for field in 0..4 {
                        let mut counts = [case.counts(); 2];
                        match field {
                            0 => counts[index].0 += 1,
                            1 => counts[index].1 += 1,
                            2 => counts[index].2 += 1,
                            3 => counts[index].3 += 1,
                            _ => unreachable!(),
                        }
                        rejects(|| validate_exact_pair(case, &pair(case), &counts));
                    }
                }
            }
        }
    }
}
