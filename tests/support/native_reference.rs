//! Four-pair reference profile. No timing accuracy or calibration assertion.
//! The old architectural comparator and child/step bounds are reused unchanged.
use super::*;

// Independently hand-encoded instruction stencil for the frozen reference ABI.
// This array never executes and is not imported from the SDK's own tests.
pub const STENCIL: &[u8] = &[
    0x53, 0x41, 0x54, 0x48, 0x8d, 0x64, 0x24, 0xf8, 0x48, 0x89, 0xfb, 0x49, 0x89, 0xcc, 0x48, 0x89,
    0xf7, 0x48, 0x89, 0xd6, 0x4c, 0x8b, 0x5b, 0x28, 0x4c, 0x89, 0x5b, 0x30, 0x48, 0x89, 0x63, 0x38,
    0x49, 0x89, 0x44, 0x24, 0x78, 0x49, 0x89, 0x8c, 0x24, 0x80, 0, 0, 0, 0x49, 0x89, 0x94, 0x24,
    0x88, 0, 0, 0, 0x0f, 0xae, 0xe8, 0x0f, 0x01, 0xf9, 0x0f, 0xae, 0xe8, 0x41, 0x89, 0x44, 0x24,
    0x48, 0x41, 0x89, 0x54, 0x24, 0x50, 0x41, 0x89, 0x4c, 0x24, 0x58, 0x49, 0x8b, 0x44, 0x24, 0x78,
    0x49, 0x8b, 0x8c, 0x24, 0x80, 0, 0, 0, 0x49, 0x8b, 0x94, 0x24, 0x88, 0, 0, 0, 0x41, 0xff, 0xd3,
    0x48, 0x89, 0x63, 0x40, 0x49, 0x89, 0x84, 0x24, 0x90, 0, 0, 0, 0x49, 0x89, 0x8c, 0x24, 0x98, 0,
    0, 0, 0x49, 0x89, 0x94, 0x24, 0xa0, 0, 0, 0, 0x0f, 0xae, 0xe8, 0x0f, 0x01, 0xf9, 0x0f, 0xae,
    0xe8, 0x41, 0x89, 0x44, 0x24, 0x60, 0x41, 0x89, 0x54, 0x24, 0x68, 0x41, 0x89, 0x4c, 0x24, 0x70,
    0x49, 0x8b, 0x84, 0x24, 0x90, 0, 0, 0, 0x49, 0x8b, 0x8c, 0x24, 0x98, 0, 0, 0, 0x49, 0x8b, 0x94,
    0x24, 0xa0, 0, 0, 0, 0x49, 0xc7, 0x04, 0x24, 2, 0, 0, 0, 0x48, 0x8d, 0x64, 0x24, 8, 0x41, 0x5c,
    0x5b, 0xc3,
];
pub(super) const HEADS: &[u64] = &[
    0, 1, 3, 8, 11, 14, 17, 20, 24, 28, 32, 37, 45, 53, 56, 59, 62, 67, 72, 77, 82, 90, 98, 101,
    105, 113, 121, 129, 132, 135, 138, 143, 148, 153, 161, 169, 177, 185, 190, 192, 193,
];
pub const AFTER_CALL: u64 = 101;
pub(super) const OUTER_RET: u64 = 193;
const WORDS: usize = 22;
const CANARY: u64 = 0x7265_6654_5343_7631;
pub const RESULT_WORDS: usize = 17;
const RESULT_BYTES: usize = RESULT_WORDS * 8;

/// Exact actual exported labels, supplied by address-only symbol linkage.
pub fn check_layout(gate: u64, labels: [u64; 6], bytes: &[u8]) {
    assert_eq!(bytes, STENCIL);
    assert_eq!(bytes.len(), 194);
    assert_eq!(
        labels,
        [32, 98, 101, 105, 185, 194].map(|n| gate.checked_add(n).unwrap())
    );
    assert_eq!(&bytes[56..59], &[0x0f, 0x01, 0xf9]);
    assert_eq!(&bytes[132..135], &[0x0f, 0x01, 0xf9]);
}
pub(super) fn transient(gate: u64, pc: u64) -> bool {
    pc.checked_sub(gate)
        .is_some_and(|n| (32 < n && n < 98) || (105 < n && n < 185))
}
pub fn deadline() -> Instant {
    Instant::now() + CHILD_BUDGET
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stats {
    pub reader_checks: usize,
    pub timestamp_joins: usize,
    pub records: usize,
}

impl OrdinaryOracle {
    /// The caller creates deadline BEFORE allocating this oracle's mappings.
    pub fn pair_reference<F, O>(
        &self,
        length: usize,
        external_id: u64,
        deadline: Instant,
        setup: F,
        inspect: O,
    ) -> (PairResult, Stats)
    where
        F: for<'a> Fn(bool, ChildContext<'a>),
        O: for<'a> FnOnce(OriginalObservation<'a>),
    {
        let (pair, stats) =
            self.pair_profile(length, setup, inspect, Some((deadline, external_id)));
        (
            pair,
            stats.expect("reference observations and postflight records"),
        )
    }
}

/// Test transport only. Each child owns one distinct empty pipe and writes one
/// 136-byte record; total queued bytes per pipe stay below Linux PIPE_BUF.
pub struct Output(std::fs::File);
impl Output {
    pub(super) fn new(fd: i32) -> Self {
        // SAFETY: ChildContext transfers its unique selected pipe endpoint once.
        Self(unsafe { std::fs::File::from_raw_fd(fd) })
    }
    /// Call only after the real facade/original-owner postflight returned.
    pub fn complete(mut self, record: [u64; RESULT_WORDS]) {
        let bytes: Vec<_> = record.iter().flat_map(|n| n.to_le_bytes()).collect();
        assert_eq!(bytes.len(), RESULT_BYTES);
        assert!(bytes.len() <= 4096);
        self.0.write_all(&bytes).unwrap();
    }
}
fn decode_record(bytes: &[u8]) -> [u64; RESULT_WORDS] {
    assert_eq!(
        bytes.len(),
        RESULT_BYTES,
        "one complete result, no tail or duplicate"
    );
    std::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
}
pub(super) fn read_record(pipe: &Pipe, child: &Tracee) -> [u64; RESULT_WORDS] {
    assert!(
        child.reaped.get(),
        "normal child completion precedes result credit"
    );
    let mut bytes = Vec::with_capacity(RESULT_BYTES + 1);
    let mut buffer = [0; RESULT_BYTES + 1];
    loop {
        assert!(Instant::now() < child.deadline, "reference output deadline");
        let mut poll = libc::pollfd {
            fd: pipe.0[0],
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&raw mut poll, 1, 10) };
        assert!(n >= 0);
        if n == 0 {
            continue;
        }
        let n = unsafe { libc::read(pipe.0[0], buffer.as_mut_ptr().cast(), buffer.len()) };
        assert!(n >= 0);
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..n as usize]);
        assert!(bytes.len() <= RESULT_BYTES, "extra returned reference data");
    }
    decode_record(&bytes)
}
pub(super) fn check_record(actual: &[u64; RESULT_WORDS], expected: &[u64; RESULT_WORDS]) {
    assert_eq!(
        actual, expected,
        "real facade output matches the observed reference cell"
    );
    assert!(matches!(actual[0], 1 | 2));
    assert!(actual[3] > 0 && actual[4] > 0 && actual[5] == actual[4]);
    assert_eq!(actual[8], actual[9]);
    assert_eq!(actual[8] % 16, 0);
    assert!(u32::try_from(actual[11]).is_ok() && u32::try_from(actual[13]).is_ok());
    assert_eq!(actual[11], actual[13], "qualified same AUX");
    assert!(
        actual[10] <= actual[12],
        "qualified ordered reference endpoints"
    );
    if actual[0] == 1 {
        assert_eq!(
            &actual[15..],
            &[0, 0],
            "original gives no callback entry/RET credit"
        );
    } else {
        assert_eq!(actual[15].checked_add(8), Some(actual[8]));
        assert_ne!(actual[16], 0);
    }
}
pub(super) fn copy_snapshot(s: &Snapshot) -> Snapshot {
    Snapshot {
        logical_pc: s.logical_pc,
        registers: s.registers,
        xstate: s.xstate.clone(),
        data: s.data.clone(),
        application_stack: s.application_stack.clone(),
    }
}
fn transparent(before: &Snapshot, after: &Snapshot, physical: (u64, u64)) {
    assert_eq!(
        (before.registers.rip, after.registers.rip),
        physical,
        "authenticate physical reader endpoints before logical normalization"
    );
    assert_eq!((before.logical_pc, after.logical_pc), physical);
    let mut normalized = copy_snapshot(after);
    normalized.logical_pc = before.logical_pc; // No register or memory edit.
    assert_state(before, &normalized);
}
pub(super) fn seed_argument(child: &Tracee, actual: libc::user_regs_struct) {
    let mut registers = child.registers();
    registers.rcx = actual.rcx; // Real fourth ABI argument, not a fabricated TLS pointer.
    child.set_registers(&registers);
}
fn words(child: &Tracee, address: u64) -> [u64; WORDS] {
    let bytes = child.memory(address, WORDS * 8);
    std::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
}
fn exact_cell(actual: &[u64; WORDS], expected: &[u64; WORDS]) {
    assert_eq!(
        actual, expected,
        "all reference words, spill slots and canary"
    );
}
fn independent_ranges(cell: u64, frame: u64, ranges: &[(u64, u64)]) {
    assert_ne!(cell, 0);
    assert_eq!(cell % 8, 0);
    assert_ne!(frame, 0);
    assert_eq!(frame % 8, 0);
    let end = cell.checked_add((WORDS * 8) as u64).unwrap();
    let frame_end = frame.checked_add(112).unwrap();
    assert!(
        end <= frame || frame_end <= cell,
        "separate old Frame/reference cell"
    );
    assert!(ranges.iter().all(|&(a, b)| end <= a || b <= cell));
    assert!(ranges.iter().all(|&(a, b)| frame_end <= a || b <= frame));
}
fn callee_values(r: &libc::user_regs_struct) -> [u64; 7] {
    [r.rbx, r.rbp, r.r12, r.r13, r.r14, r.r15, r.rsp]
}

pub(super) struct Witness {
    cell: u64,
    frame: u64,
    expected: [u64; WORDS],
    gate: u64,
    s: u64,
    previous: Option<(u64, libc::user_regs_struct)>,
    before_start: Option<Snapshot>,
    before_end: Option<Snapshot>,
    outputs: [Option<[u64; 3]>; 2],
    checks: usize,
    last_pc: u64,
    initial_callee: Option<[u64; 7]>,
    callee_checked: bool,
}
impl Witness {
    pub(super) fn new(
        oracle: &OrdinaryOracle,
        child: &Tracee,
        ready: &Ready,
        actual: libc::user_regs_struct,
        armed: &[u64],
        id: u64,
        candidate: bool,
    ) -> Self {
        assert_eq!(ready.profile, Profile::Reference { external_id: id });
        let mut ranges: Vec<_> = ready
            .immutable
            .iter()
            .map(|(a, b)| (*a, a.checked_add(b.len() as u64).unwrap()))
            .collect();
        ranges.extend([
            (
                ready.gate,
                ready.gate.checked_add(STENCIL.len() as u64).unwrap(),
            ),
            (oracle.data.address(), oracle.data.address() + PAGE as u64),
            (
                oracle.stack.address(),
                oracle.stack.address() + (STACK_BYTES + PAGE) as u64,
            ),
        ]);
        independent_ranges(actual.rcx, actual.rdi, &ranges);
        let mut expected = [0; WORDS];
        expected[..9].copy_from_slice(&[
            1,
            armed[1],
            armed[2],
            child.pid as u64,
            child.pid as u64,
            ready.entry,
            ready.continuation,
            id,
            if candidate { 2 } else { 1 },
        ]);
        expected[21] = CANARY;
        exact_cell(&words(child, actual.rcx), &expected);
        Self {
            cell: actual.rcx,
            frame: actual.rdi,
            expected,
            gate: ready.gate,
            s: oracle.gate_rsp(),
            previous: None,
            before_start: None,
            before_end: None,
            outputs: [None; 2],
            checks: 0,
            last_pc: 0,
            initial_callee: None,
            callee_checked: false,
        }
    }
    fn observe_entry(&mut self, now: &Snapshot) {
        assert_eq!((now.registers.rip, now.logical_pc), (self.gate, self.gate));
        assert_eq!(now.registers.rsp, self.s);
        assert!(
            self.initial_callee.is_none(),
            "one actual seeded gate entry"
        );
        self.initial_callee = Some(callee_values(&now.registers));
    }
    fn check_callee_return(&mut self, now: &Snapshot) {
        let outer = self.gate.checked_add(OUTER_RET).unwrap();
        assert_eq!((now.registers.rip, now.logical_pc), (outer, outer));
        assert!(!self.callee_checked, "one actual completed epilogue");
        assert_eq!(
            callee_values(&now.registers),
            self.initial_callee
                .expect("observed seeded entry before epilogue"),
            "actual epilogue restores RBX/RBP/R12-R15/RSP before harness restoration"
        );
        self.callee_checked = true;
    }
    fn transition(&mut self, previous: u64, before: libc::user_regs_struct, now: &Snapshot) {
        let n = previous.checked_sub(self.gate);
        let saved = match n {
            Some(32) => Some((15, before.rax)),
            Some(37) => Some((16, before.rcx)),
            Some(45) => Some((17, before.rdx)),
            Some(105) => Some((18, before.rax)),
            Some(113) => Some((19, before.rcx)),
            Some(121) => Some((20, before.rdx)),
            _ => None,
        };
        if let Some((slot, value)) = saved {
            self.expected[slot] = value;
        }
        if let Some(reader) = match n {
            Some(56) => Some(0),
            Some(132) => Some(1),
            _ => None,
        } {
            assert_eq!(now.registers.rip, previous + 3);
            assert!(self.outputs[reader].is_none(), "one actual RDTSCP per side");
            let output = [now.registers.rax, now.registers.rdx, now.registers.rcx];
            assert!(output.iter().all(|x| u32::try_from(*x).is_ok()));
            self.outputs[reader] = Some(output);
        }
        let store = match n {
            Some(62) => Some((0, 0, 9, before.rax)),
            Some(67) => Some((0, 1, 10, before.rdx)),
            Some(72) => Some((0, 2, 11, before.rcx)),
            Some(138) => Some((1, 0, 12, before.rax)),
            Some(143) => Some((1, 1, 13, before.rdx)),
            Some(148) => Some((1, 2, 14, before.rcx)),
            _ => None,
        };
        if let Some((reader, component, slot, register)) = store {
            let observed =
                self.outputs[reader].expect("actual reader precedes each store")[component];
            assert_eq!(
                register, observed,
                "store consumes this exact RDTSCP output"
            );
            self.expected[slot] = observed;
        }
        if n == Some(177) {
            self.expected[0] = 2;
        }
    }
    pub(super) fn observe(&mut self, child: &Tracee, ready: &Ready, now: &Snapshot) {
        if let Some((pc, before)) = self.previous {
            self.transition(pc, before, now);
        }
        exact_cell(&words(child, self.cell), &self.expected);
        let pc = now.registers.rip;
        let offset = pc.checked_sub(self.gate);
        if offset == Some(0) {
            self.observe_entry(now);
        }
        if offset == Some(32) {
            assert!(self.before_start.is_none());
            assert_eq!(
                (now.registers.rbx, now.registers.r12),
                (self.frame, self.cell)
            );
            assert_eq!(now.registers.rsp, self.s - 24);
            self.before_start = Some(copy_snapshot(now));
        }
        if offset == Some(105) {
            assert!(self.before_end.is_none());
            assert_eq!(now.registers.rsp, self.s - 24);
            self.before_end = Some(copy_snapshot(now));
        }
        if offset.is_some_and(|n| 32 < n && n <= 98) {
            let before = self.before_start.as_ref().expect("actual start boundary");
            assert_eq!(now.data, before.data);
            assert_eq!(now.application_stack, before.application_stack);
            if offset == Some(98) {
                transparent(before, now, (self.gate + 32, self.gate + 98));
                self.checks += 1;
            }
        }
        if offset.is_some_and(|n| 105 < n && n <= 185) {
            let before = self.before_end.as_ref().expect("actual end boundary");
            assert_eq!(now.data, before.data);
            assert_eq!(now.application_stack, before.application_stack);
            if offset == Some(185) {
                transparent(before, now, (self.gate + 105, self.gate + 185));
                self.checks += 1;
            }
        }
        if ready.heads.contains(&now.logical_pc) {
            assert_eq!(now.registers.rsp, self.s - 32);
            assert_eq!(
                child.memory(self.s - 32, 8),
                ready.continuation.to_le_bytes()
            );
        }
        if offset == Some(AFTER_CALL) {
            assert_eq!(now.registers.rsp, self.s - 24);
        }
        if offset == Some(OUTER_RET) {
            self.check_callee_return(now);
        }
        self.last_pc = pc;
        self.previous = Some((pc, now.registers));
    }
    pub(super) fn record(&self, value: u64, ret: Option<u64>) -> [u64; RESULT_WORDS] {
        assert!(
            self.initial_callee.is_some() && self.callee_checked,
            "returned-record credit requires actual entry/epilogue restoration"
        );
        assert_eq!((self.last_pc, self.checks), (self.gate + OUTER_RET, 2));
        assert!(self.outputs.iter().all(Option::is_some));
        for (observed, slots) in self.outputs.iter().zip([9, 12]) {
            assert_eq!(
                observed.unwrap().as_slice(),
                &self.expected[slots..slots + 3],
                "every returned endpoint retains its observed RDTSCP words"
            );
        }
        assert_eq!(self.expected[0], 2);
        assert_eq!(
            self.expected[18], value,
            "reader preserves actual subject RAX"
        );
        assert_eq!(self.expected[8] == 2, ret.is_some());
        let f = &self.expected;
        let record = [
            f[8],
            f[7],
            f[2],
            f[1],
            f[3],
            f[4],
            f[5],
            f[6],
            self.s - 24,
            self.s - 24,
            f[10] << 32 | f[9],
            f[11],
            f[13] << 32 | f[12],
            f[14],
            value,
            if ret.is_some() { self.s - 32 } else { 0 },
            ret.unwrap_or(0),
        ];
        check_record(&record, &record);
        record
    }
}

#[cfg(test)]
#[path = "native_reference/tests.rs"]
mod tests;
