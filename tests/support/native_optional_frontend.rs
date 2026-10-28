//! Actual optional frontend gate adapter; no raw arming or fixture callback.
use super::precontext::{eof, final_ack, helper_ack, read_exact, send_words, words, write_all};
use super::*;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::mpsc;
use std::thread::JoinHandle;

pub const GATE: [u8; 37] = [
    0x53, 0x48, 0x89, 0xfb, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x4c, 0x8b, 0x5b, 0x70, 0x4c, 0x89,
    0x5b, 0x78, 0x48, 0x89, 0xa3, 0x80, 0, 0, 0, 0x41, 0xff, 0xd3, 0x48, 0x89, 0xa3, 0x88, 0, 0, 0,
    0x5b, 0xc3,
];
const HEADS: [u64; 11] = [0, 1, 4, 7, 10, 14, 18, 25, 28, 35, 36];
const AFTER: u64 = 28;
const OUTER: u64 = 36;
const FRAME_WORDS: usize = 23;

/// Genuine source/image metadata; observers are the authenticated image entries.
pub struct Ready {
    pub base: super::Ready,
    pub observers: Vec<(u64, u64)>,
}
impl std::ops::Deref for Ready {
    type Target = super::Ready;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}
impl Ready {
    fn validate(&self, candidate: bool) -> BTreeMap<u64, u64> {
        assert_eq!(self.base.profile, super::Profile::Legacy);
        let map = self.base.validate_profile(candidate, AFTER, GATE.len());
        let expected: Vec<_> = if candidate {
            std::iter::once(self.entry)
                .chain(self.returns.iter().copied())
                .collect()
        } else {
            Vec::new()
        };
        assert_eq!(
            self.observers.iter().map(|&(pc, _)| pc).collect::<Vec<_>>(),
            expected
        );
        let mut seen = BTreeSet::new();
        for &(_, pc) in &self.observers {
            assert!(seen.insert(pc));
            assert!(
                self.immutable[1..]
                    .iter()
                    .any(|(a, b)| *a <= pc && pc < *a + b.len() as u64)
            );
            assert!(
                !map.contains_key(&pc),
                "observer is not an original restored head"
            );
        }
        map
    }
    fn encode(&self) -> Vec<u8> {
        let inner = self.base.encode();
        let mut out = Vec::new();
        out.extend_from_slice(&(inner.len() as u64).to_le_bytes());
        out.extend_from_slice(&inner);
        out.extend_from_slice(&(self.observers.len() as u64).to_le_bytes());
        for &(a, b) in &self.observers {
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
        assert!(out.len() <= WIRE_LIMIT);
        out
    }
    fn decode(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 16 && bytes.len() <= WIRE_LIMIT);
        let n = usize::try_from(u64::from_le_bytes(bytes[..8].try_into().unwrap())).unwrap();
        assert!(n <= bytes.len() - 16);
        let base = super::Ready::decode(&bytes[8..8 + n]);
        let count =
            usize::try_from(u64::from_le_bytes(bytes[8 + n..16 + n].try_into().unwrap())).unwrap();
        assert!(count <= 5);
        assert_eq!(bytes.len(), 16 + n + count * 16);
        let observers = bytes[16 + n..]
            .chunks_exact(16)
            .map(|b| {
                (
                    u64::from_le_bytes(b[..8].try_into().unwrap()),
                    u64::from_le_bytes(b[8..].try_into().unwrap()),
                )
            })
            .collect();
        Self { base, observers }
    }
}

fn check_gate(ready: &Ready, bytes: &[u8]) {
    assert_eq!(ready.continuation, ready.gate.checked_add(AFTER).unwrap());
    assert_eq!(bytes, GATE, "whole immutable optional frontend gate");
}
fn armed(words: &[u64], process: u64, ready: &Ready, start: u64, end: u64) {
    assert_eq!(words.len(), FRAME_WORDS);
    assert_eq!(&words[..9], &[0, 1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&words[9..11], &[1, 1], "first real ARMED invocation");
    assert_ne!(words[11], 0, "real immutable gate identity");
    assert_eq!(&words[12..15], &[process, process, ready.entry]);
    assert_eq!(&words[15..18], &[0; 3]);
    assert_eq!(&words[18..20], &[start, end]);
    assert_eq!(&words[20..], &[0; 3]);
}
fn expected_frame(
    initial: &[u64],
    ready: &Ready,
    rsp: u64,
    rcx: u64,
    path: Option<bool>,
    ret: Option<u64>,
) -> Vec<u64> {
    assert_eq!(initial.len(), FRAME_WORDS);
    let mut expected = initial.to_vec();
    expected[15] = ready.entry;
    expected[16] = rsp + 8;
    if let Some(slow) = path {
        expected[..9].copy_from_slice(&[
            rcx,
            if ret.is_some() { 3 } else { 2 },
            if slow { 2 } else { 1 },
            ready.entry,
            rsp,
            ready.continuation,
            ret.unwrap_or(0),
            if ret.is_some() { rsp } else { 0 },
            if ret.is_some() { ready.continuation } else { 0 },
        ]);
        if slow {
            expected[9] = if ret.is_some() { 3 } else { 2 };
            expected[20] = rsp;
            expected[21] = ready.continuation;
            expected[22] = ret.unwrap_or(0);
        }
    }
    // This checkpoint is after the actual gate continuation iff a RET is supplied.
    if ret.is_some() {
        expected[17] = rsp + 8;
    }
    expected
}
fn frame_matches(actual: &[u64], expected: &[u64]) {
    assert_eq!(actual, expected, "all 184 bytes of real optional TLS frame");
}
fn observer_sequence(ready: &Ready, actual: &[u64], slow: bool, ret: u64) {
    let lookup = |pc| ready.observers.iter().find(|&&(p, _)| p == pc).unwrap().1;
    let expected = if slow {
        vec![lookup(ready.entry), lookup(ret)]
    } else {
        Vec::new()
    };
    assert_eq!(
        actual, expected,
        "exact optional entry and RET observer visits"
    );
}
fn frame(child: &Tracee, address: u64) -> Vec<u64> {
    child
        .memory(address, FRAME_WORDS * 8)
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect()
}

struct Channels {
    request: Pipe,
    ack: Pipe,
}
impl Channels {
    fn new() -> Self {
        let c = Self {
            request: Pipe::new(),
            ack: Pipe::new(),
        };
        for fd in c.fds() {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
        c
    }
    fn fds(&self) -> [i32; 4] {
        [
            self.request.0[0],
            self.request.0[1],
            self.ack.0[0],
            self.ack.0[1],
        ]
    }
    fn parent(&mut self) {
        for fd in [&mut self.request.0[0], &mut self.ack.0[1]] {
            assert_eq!(unsafe { libc::close(*fd) }, 0);
            *fd = -1;
        }
    }
}
/// Only the candidate's real controller helper uses this bounded handshake.
pub struct Helper<T> {
    request: OwnedFd,
    ack: OwnedFd,
    returned: mpsc::Receiver<T>,
    deadline: Instant,
}
impl<T> Helper<T> {
    pub fn transition(self, initial: bool, operation: impl FnOnce() -> bool) -> T {
        let process = u64::from(std::process::id());
        let thread = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
        assert_ne!(process, thread);
        send_words(
            self.ack.as_raw_fd(),
            &[1, process, thread, u64::from(initial)],
            self.deadline,
        );
        assert_eq!(words::<1>(self.request.as_raw_fd(), self.deadline), [1]);
        eof(self.request.as_raw_fd(), self.deadline);
        let after = operation();
        assert_eq!(after, !initial);
        send_words(
            self.ack.as_raw_fd(),
            &[2, process, thread, u64::from(after)],
            self.deadline,
        );
        drop(self.ack);
        drop(self.request);
        self.returned
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .expect("actual executor post-return acknowledgement")
    }
}
pub struct Controller<T, R> {
    returned: Option<mpsc::SyncSender<T>>,
    thread: Option<JoinHandle<R>>,
    deadline: Instant,
}
impl<T, R> Controller<T, R> {
    fn wait(&self) {
        let end = self.deadline.min(Instant::now() + Duration::from_secs(2));
        while !self.thread.as_ref().unwrap().is_finished() {
            if Instant::now() >= end {
                std::process::abort();
            }
            std::thread::yield_now();
        }
    }
    pub fn finish(mut self, value: T) -> R {
        assert!(Instant::now() < self.deadline);
        assert!(self.returned.take().unwrap().try_send(value).is_ok());
        self.wait();
        let result = self
            .thread
            .take()
            .unwrap()
            .join()
            .expect("real controller helper failed");
        assert!(Instant::now() < self.deadline);
        result
    }
}
impl<T, R> Drop for Controller<T, R> {
    fn drop(&mut self) {
        self.returned.take();
        if self.thread.is_some() {
            self.wait();
            let _ = self.thread.take().unwrap().join();
        }
    }
}

pub struct ChildContext<'a> {
    oracle: &'a OptionalOracle,
    write: OwnedFd,
    channels: Option<(OwnedFd, OwnedFd)>,
    length: usize,
    deadline: Instant,
}
impl ChildContext<'_> {
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
    pub fn controller<T: Send + 'static, R: Send + 'static>(
        &mut self,
        f: impl FnOnce(Helper<T>) -> R + Send + 'static,
    ) -> Controller<T, R> {
        let (request, ack) = self.channels.take().expect("one candidate controller");
        let (tx, rx) = mpsc::sync_channel(1);
        let deadline = self.deadline;
        let thread = std::thread::spawn(move || {
            f(Helper {
                request,
                ack,
                returned: rx,
                deadline,
            })
        });
        Controller {
            returned: Some(tx),
            thread: Some(thread),
            deadline,
        }
    }
    pub fn ready(self, ready: &Ready) {
        assert!(
            self.channels.is_none(),
            "candidate controller must already own handshake"
        );
        write_all(self.write.as_raw_fd(), &ready.encode(), self.deadline);
        drop(self.write);
        // Thread-directed readiness leaves the candidate's real controller runnable.
        unsafe {
            let mut mask: libc::sigset_t = core::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &raw mut mask),
                0
            );
            assert_eq!(libc::sigismember(&mask, libc::SIGTRAP), 0);
            assert_eq!(libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize), 0);
            assert_eq!(
                libc::syscall(
                    libc::SYS_tgkill,
                    std::process::id(),
                    libc::syscall(libc::SYS_gettid),
                    libc::SIGTRAP
                ),
                0
            );
        }
    }
}
fn read_ready(pipe: &Pipe, child: &Tracee) -> Ready {
    let mut result = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        super::precontext::wait_io(pipe.0[0], libc::POLLIN, child.deadline);
        let n = unsafe { libc::read(pipe.0[0], buffer.as_mut_ptr().cast(), buffer.len()) };
        assert!(n >= 0);
        if n == 0 {
            break;
        }
        result.extend_from_slice(&buffer[..n as usize]);
        assert!(result.len() <= WIRE_LIMIT);
    }
    Ready::decode(&result)
}
struct OptionalOracle {
    oracle: OrdinaryOracle,
}
impl std::ops::Deref for OptionalOracle {
    type Target = OrdinaryOracle;
    fn deref(&self) -> &Self::Target {
        &self.oracle
    }
}
impl OptionalOracle {
    fn snapshot(&self, child: &Tracee, ready: &Ready, pc: u64) -> Snapshot {
        check_gate(ready, &child.memory(ready.gate, GATE.len()));
        for (address, bytes) in &ready.immutable {
            assert_eq!(
                child.memory(*address, bytes.len()),
                *bytes,
                "whole source/image bytes"
            );
        }
        let start = self.gate_rsp() - 16 - 128;
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
    fn reach(walk: &mut Walk<'_>, ready: &Ready, phase: &str) -> libc::user_regs_struct {
        while walk.child.registers().rip != ready.gate {
            walk.step(phase);
        }
        check_gate(ready, &walk.child.memory(ready.gate, GATE.len()));
        walk.child.registers()
    }
}

// The pair body below retains the inherited comparator, seeding and actual outer
// RET restoration/TF cleanup verbatim. Only the fixed gate/frame and handshake
// checkpoints differ. Both traces share one deadline and their own one counter.

/// Eight pairs are selected by the driver: two modes × two seeds × lengths1/64.
/// The deadline precedes mappings, pipes and forks; there is no setup exemption.
pub fn pair<F>(seed: u64, length: usize, slow: bool, setup: F) -> PairResult
where
    F: for<'a> Fn(bool, ChildContext<'a>),
{
    let deadline = Instant::now() + CHILD_BUDGET;
    let fixture = OptionalOracle {
        oracle: OrdinaryOracle::new(seed),
    };
    assert!(
        Instant::now() < deadline,
        "optional pair mapping/setup deadline"
    );
    fixture.run_pair(length, slow, setup, deadline)
}
impl OptionalOracle {
    fn run_pair<F>(&self, length: usize, slow: bool, setup: F, deadline: Instant) -> PairResult
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
    {
        assert!(matches!(length, 1 | 64));
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            libc::c_long::from(std::process::id())
        );
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        let mut pipes = [Pipe::new(), Pipe::new()];
        let mut channels = Channels::new();
        for pipe in &pipes {
            for fd in pipe.0 {
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                assert!(flags >= 0);
                assert_eq!(
                    unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                    0
                );
            }
        }
        let mut pids = [0; 2];
        for index in 0..2 {
            assert!(Instant::now() < deadline, "optional pair pre-fork deadline");
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
                let keep = if index == 1 {
                    Some((channels.request.0[0], channels.ack.0[1]))
                } else {
                    None
                };
                for fd in channels.fds() {
                    if !keep.is_some_and(|(a, b)| fd == a || fd == b) {
                        assert_eq!(unsafe { libc::close(fd) }, 0);
                    }
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    setup(
                        index == 1,
                        ChildContext {
                            oracle: self,
                            write: unsafe { OwnedFd::from_raw_fd(pipes[index].0[1]) },
                            channels: keep.map(|(a, b)| unsafe {
                                (OwnedFd::from_raw_fd(a), OwnedFd::from_raw_fd(b))
                            }),
                            length,
                            deadline,
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
        channels.parent();
        let original = read_ready(&pipes[0], &children[0]);
        let candidate = read_ready(&pipes[1], &children[1]);
        let mut ack = [0; 32];
        read_exact(channels.ack.0[0], &mut ack, deadline);
        let helper = helper_ack(&ack, 1, children[1].pid as u64, None, slow).unwrap();
        for child in &children {
            let status = child.wait();
            assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP);
            let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
            child.request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
            assert_eq!(
                (info.si_signo, info.si_code),
                (libc::SIGTRAP, libc::SI_TKILL)
            );
            assert_eq!(unsafe { info.si_pid() }, child.pid);
            child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        }
        let original_map = original.validate(false);
        let candidate_map = candidate.validate(true);
        same_ready(&original, &candidate);
        let mut a = Walk {
            child: &children[0],
            steps: 0,
        };
        let mut b = Walk {
            child: &children[1],
            steps: 0,
        };
        let ar = Self::reach(&mut a, &original, "reach_original_gate");
        let br = Self::reach(&mut b, &candidate, "reach_candidate_gate");
        same_arguments(&ar, &br);
        let ax = a.child.xstate();
        let bx = b.child.xstate();
        assert_eq!(ax.len(), bx.len());
        let aw = a.child.memory(ar.rsp, 8);
        let bw = b.child.memory(br.rsp, 8);
        let af = frame(a.child, ar.rdi);
        let bf = frame(b.child, br.rdi);
        for (f, child, r) in [(&af, a.child, &original), (&bf, b.child, &candidate)] {
            armed(
                f,
                child.pid as u64,
                r,
                self.stack.address() + PAGE as u64,
                self.stack.address() + STACK_BYTES as u64,
            );
        }
        self.seed(a.child, ar, length);
        self.seed(b.child, br, length);
        let mut points = Vec::new();
        let mut visits = Vec::new();
        let mut returns = BTreeSet::new();
        loop {
            let pc = a.child.registers().rip;
            let logical = if HEADS.iter().any(|p| original.gate + p == pc) {
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
            points.push(self.snapshot(a.child, &original, logical));
            if pc == original.gate + OUTER {
                break;
            }
            a.step("original_body");
        }
        let mut next = 0;
        let mut observers = Vec::new();
        let mut transitioned = false;
        loop {
            let pc = b.child.registers().rip;
            if candidate.observers.iter().any(|&(_, p)| p == pc) {
                observers.push(pc);
                assert!(observers.len() <= 2);
            }
            let logical = if HEADS.iter().any(|p| candidate.gate + p == pc) {
                Some(pc)
            } else {
                candidate_map.get(&pc).copied()
            };
            if let Some(logical) = logical {
                let expected = points.get(next).expect("extra candidate restored boundary");
                assert_eq!(
                    logical, expected.logical_pc,
                    "ordered original visits, including loops/RET"
                );
                assert_state(expected, &self.snapshot(b.child, &candidate, logical));
                if logical == candidate.entry && !transitioned {
                    assert_eq!(observers.len(), usize::from(slow));
                    frame_matches(
                        &frame(b.child, br.rdi),
                        &expected_frame(
                            &bf,
                            &candidate,
                            self.gate_rsp() - 16,
                            expected.registers.rcx,
                            Some(slow),
                            None,
                        ),
                    );
                    send_words(channels.request.0[1], &[1], deadline);
                    assert_eq!(unsafe { libc::close(channels.request.0[1]) }, 0);
                    channels.request.0[1] = -1;
                    final_ack(
                        channels.ack.0[0],
                        deadline,
                        b.child.pid as u64,
                        helper,
                        !slow,
                    );
                    transitioned = true;
                }
                next += 1;
                if pc == candidate.gate + OUTER {
                    break;
                }
            }
            b.step("candidate_body");
        }
        assert_eq!(next, points.len(), "all original boundary comparisons");
        assert_eq!(returns.len(), 1, "one real subject RET per call");
        assert!(transitioned);
        let ret = *returns.first().unwrap();
        observer_sequence(&candidate, &observers, slow, ret);
        let ret_rcx = points
            .iter()
            .find(|p| p.logical_pc == ret)
            .unwrap()
            .registers
            .rcx;
        frame_matches(
            &frame(a.child, ar.rdi),
            &expected_frame(&af, &original, self.gate_rsp() - 16, 0, None, Some(ret)),
        );
        frame_matches(
            &frame(b.child, br.rdi),
            &expected_frame(
                &bf,
                &candidate,
                self.gate_rsp() - 16,
                ret_rcx,
                Some(slow),
                Some(ret),
            ),
        );
        let value = self.data.bytes()[128..128 + length]
            .iter()
            .map(|b| u64::from(b ^ 0x5a))
            .sum::<u64>()
            ^ 0x9e37_79b9_7f4a_7c15;
        for (walk, ready, saved, xstate, word) in [
            (&mut a, &original, ar, ax, aw),
            (&mut b, &candidate, br, bx, bw),
        ] {
            let actual = walk.child.registers();
            assert_eq!(actual.rip, ready.gate + OUTER);
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
        assert!(
            Instant::now() < deadline,
            "both successful normal reaps before original deadline"
        );
        PairResult {
            comparisons: next,
            original_steps: a.steps,
            candidate_steps: b.steps,
            visits: visits.len(),
            returns,
            declared_returns: original.returns.iter().copied().collect(),
            value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready(candidate: bool) -> Ready {
        Ready {
            base: super::super::Ready {
                profile: super::super::Profile::Legacy,
                entry: 0x4000,
                gate: 0x1000,
                continuation: 0x101c,
                heads: vec![0x4000, 0x4005],
                returns: vec![0x4005],
                boundaries: if candidate {
                    vec![(0x4000, 0x6100), (0x4005, 0x6105)]
                } else {
                    vec![(0x4000, 0x4000), (0x4005, 0x4005)]
                },
                immutable: if candidate {
                    vec![(0x4000, vec![0x90; 4096]), (0x6000, vec![0x90; 512])]
                } else {
                    vec![(0x4000, vec![0x90; 4096])]
                },
                original_source: vec![0x90; 4096],
            },
            observers: if candidate {
                vec![(0x4000, 0x6000), (0x4005, 0x6020)]
            } else {
                vec![]
            },
        }
    }
    const ARMED: [u64; 23] = [
        0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0x8000, 42, 42, 0x4000, 0, 0, 0, 0x10000, 0x20000, 0, 0, 0,
    ];
    #[test]
    fn optional_frontend_gate_bytes_offsets_and_extent_refuse() {
        let r = ready(false);
        check_gate(&r, &GATE);
        assert_eq!(
            (GATE.len(), HEADS, AFTER, OUTER),
            (37, [0, 1, 4, 7, 10, 14, 18, 25, 28, 35, 36], 28, 36)
        );
        // Every opcode, ModRM and displacement byte is exact, including the two
        // disp32 stores. A mandatory 31-byte profile cannot pass this predicate.
        for n in 0..37 {
            let mut b = GATE;
            b[n] ^= 1;
            assert!(std::panic::catch_unwind(|| check_gate(&r, &b)).is_err());
        }
        assert!(std::panic::catch_unwind(|| check_gate(&r, super::super::GATE_BYTES)).is_err());
        let mut r = ready(false);
        r.base.continuation += 1;
        assert!(std::panic::catch_unwind(|| check_gate(&r, &GATE)).is_err());
    }
    #[test]
    fn optional_frontend_complete_frame_phase_and_owner_refuse() {
        let r = ready(false);
        armed(&ARMED, 42, &r, 0x10000, 0x20000);
        for n in 0..23 {
            let mut f = ARMED;
            if n == 11 {
                f[n] = 0;
            } else {
                f[n] ^= 1;
            }
            assert!(std::panic::catch_unwind(|| armed(&f, 42, &r, 0x10000, 0x20000)).is_err());
        }
        assert!(
            std::panic::catch_unwind(|| armed(&ARMED[..22], 42, &r, 0x10000, 0x20000)).is_err()
        );
        // Literal independent expected values for real entry/return checkpoints.
        let fast_entry = [
            0x55, 2, 1, 0x4000, 0x1ffe8, 0x101c, 0, 0, 0, 1, 1, 0x8000, 42, 42, 0x4000, 0x4000,
            0x1fff0, 0, 0x10000, 0x20000, 0, 0, 0,
        ];
        let slow_return = [
            0x66, 3, 2, 0x4000, 0x1ffe8, 0x101c, 0x4005, 0x1ffe8, 0x101c, 3, 1, 0x8000, 42, 42,
            0x4000, 0x4000, 0x1fff0, 0x1fff0, 0x10000, 0x20000, 0x1ffe8, 0x101c, 0x4005,
        ];
        let original_return = [
            0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0x8000, 42, 42, 0x4000, 0x4000, 0x1fff0, 0x1fff0,
            0x10000, 0x20000, 0, 0, 0,
        ];
        let slow_entry = [
            0x55, 2, 2, 0x4000, 0x1ffe8, 0x101c, 0, 0, 0, 2, 1, 0x8000, 42, 42, 0x4000, 0x4000,
            0x1fff0, 0, 0x10000, 0x20000, 0x1ffe8, 0x101c, 0,
        ];
        let fast_return = [
            0x66, 3, 1, 0x4000, 0x1ffe8, 0x101c, 0x4005, 0x1ffe8, 0x101c, 1, 1, 0x8000, 42, 42,
            0x4000, 0x4000, 0x1fff0, 0x1fff0, 0x10000, 0x20000, 0, 0, 0,
        ];
        assert_eq!(
            expected_frame(&ARMED, &r, 0x1ffe8, 0x55, Some(true), None),
            slow_entry
        );
        assert_eq!(
            expected_frame(&ARMED, &r, 0x1ffe8, 0x66, Some(false), Some(0x4005)),
            fast_return
        );
        assert_eq!(
            expected_frame(&ARMED, &r, 0x1ffe8, 0x55, Some(false), None),
            fast_entry
        );
        assert_eq!(
            expected_frame(&ARMED, &r, 0x1ffe8, 0x66, Some(true), Some(0x4005)),
            slow_return
        );
        assert_eq!(
            expected_frame(&ARMED, &r, 0x1ffe8, 0, None, Some(0x4005)),
            original_return
        );
        for expected in [
            fast_entry,
            slow_entry,
            fast_return,
            slow_return,
            original_return,
        ] {
            frame_matches(&expected, &expected);
            for n in 0..23 {
                let mut wrong = expected;
                wrong[n] ^= 1;
                assert!(std::panic::catch_unwind(|| frame_matches(&wrong, &expected)).is_err());
            }
        }
    }
    #[test]
    fn optional_frontend_observer_omission_extra_and_order_refuse() {
        let r = ready(true);
        observer_sequence(&r, &[], false, 0x4005);
        observer_sequence(&r, &[0x6000, 0x6020], true, 0x4005);
        for actual in [
            vec![],
            vec![0x6000],
            vec![0x6020],
            vec![0x6020, 0x6000],
            vec![0x6000, 0x6020, 0x6020],
            vec![0x6000, 0x6021],
        ] {
            assert!(
                std::panic::catch_unwind(|| observer_sequence(&r, &actual, true, 0x4005)).is_err()
            );
        }
        assert!(
            std::panic::catch_unwind(|| observer_sequence(&r, &[0x6000], false, 0x4005)).is_err()
        );
    }
    #[test]
    fn optional_frontend_ready_full_mapping_and_observer_identity_refuse() {
        for candidate in [false, true] {
            let r = ready(candidate);
            r.validate(candidate);
            let restored = Ready::decode(&r.encode());
            same_ready(&r, &restored);
            assert_eq!(r.observers, restored.observers);
            restored.validate(candidate);
        }
        for which in 0..6 {
            let mut r = ready(true);
            match which {
                0 => {
                    r.observers.pop();
                }
                1 => r.observers[1].0 = 0x4000,
                2 => r.observers[1].1 = 0x6000,
                3 => r.observers[1].1 = 0x7000,
                4 => r.observers[1].1 = 0x6105,
                _ => {
                    r.base.boundaries.pop();
                }
            }
            assert!(std::panic::catch_unwind(|| r.validate(true)).is_err());
        }
        let mut bytes = ready(true).encode();
        bytes.push(0);
        assert!(std::panic::catch_unwind(|| Ready::decode(&bytes)).is_err());
    }
}
