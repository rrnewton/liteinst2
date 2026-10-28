//! Closed ReferenceAmdV1 normal-caller witness. Not a timestamp-accuracy oracle.
//! Every helper instruction is stepped; transient reader heads are checked
//! against the SAME child's actual RDTSCP outputs, never normalized across children.
pub use super::caller_bytes;
use super::*;
#[path = "../../tools/rapid-profiler/normal-work/reference_bytes.rs"]
pub mod bytes;

const CELLS_AT: usize = 128;
const MAGIC: u64 = 0x6e72656672647931;

#[derive(Clone)]
pub struct ReferenceReady {
    pub normal: NormalReady,
    pub cells: u64,
}
impl ReferenceReady {
    pub(super) fn encode(&self) -> Vec<u8> {
        let normal = self.normal.encode();
        let mut out = Vec::new();
        for value in [MAGIC, self.cells, normal.len() as u64] {
            word(&mut out, value);
        }
        out.extend_from_slice(&normal);
        assert!(out.len() <= WIRE_LIMIT);
        out
    }
    pub(super) fn decode(mut input: &[u8], cells: u64) -> NormalReady {
        assert_eq!(take_word(&mut input), MAGIC);
        assert_eq!(take_word(&mut input), cells);
        assert_eq!(usize::try_from(take_word(&mut input)).unwrap(), input.len());
        NormalReady::decode(input)
    }
}
fn cell_bytes(cells: &[bytes::ReferenceCell; 2]) -> &[u8] {
    // The canonical repr(C) definition asserts 18 u64 words, no padding.
    unsafe { std::slice::from_raw_parts(cells.as_ptr().cast(), bytes::CELLS_BYTES) }
}
fn decode_cells(input: &[u8]) -> [bytes::ReferenceCell; 2] {
    assert_eq!(input.len(), bytes::CELLS_BYTES);
    // All fields are u64; every bit pattern is valid. No borrowed pointer escapes.
    unsafe { std::ptr::read_unaligned(input.as_ptr().cast()) }
}

pub(super) struct Cells {
    page: Mapping,
}
impl Cells {
    pub(super) fn new(deadline: Deadline) -> Self {
        deadline.check();
        let page = Mapping::new(PAGE);
        page.initialize(0, &[0x6d; PAGE]);
        page.initialize(
            CELLS_AT,
            cell_bytes(&bytes::fresh_cells(1, [1, 2]).unwrap()),
        );
        deadline.check();
        Self { page }
    }
    pub(super) fn address(&self) -> u64 {
        self.page.address() + CELLS_AT as u64
    }
    pub(super) fn disjoint(&self, ready: &NormalReady, owned: &[(u64, u64)]) {
        let mut ranges = owned.to_vec();
        ranges.extend(
            ready
                .caller_immutable
                .iter()
                .chain(&ready.immutable)
                .map(|(a, b)| (*a, a.checked_add(b.len() as u64).unwrap())),
        );
        if let Some(j) = &ready.journal {
            ranges.push((j.address, j.address.checked_add(PAGE as u64).unwrap()));
        }
        check_cell_ranges(self.address(), &ranges);
    }
}

fn check_cell_ranges(address: u64, ranges: &[(u64, u64)]) {
    bytes::validate_cell_area(address, ranges).unwrap();
    let a = address.checked_sub(CELLS_AT as u64).unwrap();
    assert_eq!(a % PAGE as u64, 0);
    let b = a.checked_add(PAGE as u64).unwrap();
    assert!(
        ranges.iter().all(|&(low, high)| b <= low || high <= a),
        "whole separate cell page"
    );
}

/// Consume only after actual helper return and complete child postflight/checkpoint.
/// The parent independently joins these bytes after BOTH normal reaps.
pub struct Output {
    fd: Fd,
    deadline: Deadline,
}
impl Output {
    pub(super) fn new(fd: Fd, deadline: Deadline) -> Self {
        Self { fd, deadline }
    }
    pub fn complete(self, cells: &[bytes::ReferenceCell; 2]) {
        write_all(self.fd.0, cell_bytes(cells), self.deadline);
    }
}

pub struct Stats {
    pub reader_checks: usize,
    pub output_stores: usize,
    pub helper_heads: usize,
    pub interior_heads: usize,
    pub returned_cells: usize,
    pub endpoints: [[bytes::Enclosure; 2]; 2],
}

pub type PairResult = (NormalPairResult, [(usize, usize, usize, usize); 2], Stats);

pub(super) struct Witness {
    page: Vec<u8>,
    page_address: u64,
    cells: u64,
    caller: u64,
    target: u64,
    data: u64,
    stack: u64,
    rsp: u64,
    value: u64,
    heads: usize,
    readers: usize,
    stores: usize,
    interiors: usize,
    outputs: [Option<[u64; 3]>; 4],
    reader_start: Option<Snapshot>,
    outer_return: bool,
}
pub(super) fn copy_snapshot(p: &Snapshot) -> Snapshot {
    Snapshot {
        logical_pc: p.logical_pc,
        registers: p.registers,
        xstate: p.xstate.clone(),
        data: p.data.clone(),
        application_stack: p.application_stack.clone(),
    }
}
impl Witness {
    pub(super) fn new(oracle: &NormalOracle, ready: &NormalReady) -> Self {
        let cells = oracle.reference.as_ref().unwrap();
        Self {
            page: cells.page.bytes().to_vec(),
            page_address: cells.page.address(),
            cells: cells.address(),
            caller: ready.caller,
            target: ready.entry,
            data: oracle.data.address(),
            stack: oracle.stack_start(),
            rsp: oracle.caller_rsp(),
            value: oracle.body.scalar(),
            heads: 0,
            readers: 0,
            stores: 0,
            interiors: 0,
            outputs: [None; 4],
            reader_start: None,
            outer_return: false,
        }
    }
    pub(super) fn unchanged(&self, child: &Tracee) {
        self.check_page(&child.memory(self.page_address, PAGE));
    }
    fn check_page(&self, actual: &[u8]) {
        assert_eq!(actual, self.page, "whole guarded reference page");
    }
    pub(super) fn head(&mut self, point: &Snapshot, child: &Tracee) {
        self.unchanged(child);
        self.observe_head(point);
    }
    fn observe_head(&mut self, point: &Snapshot) {
        let offset = point.logical_pc.checked_sub(self.caller).unwrap();
        assert_eq!(
            bytes::HEADS.get(self.heads),
            Some(&offset),
            "all80 helper heads in order"
        );
        self.heads += 1;
        self.interiors += usize::from(bytes::transient(offset));
        if bytes::READERS.iter().any(|r| r.after == offset) {
            let mut before = self.reader_start.take().expect("reader start observed");
            before.logical_pc = point.logical_pc;
            assert_state(&before, point); // All GPR/flags/XSAVE/application data/stack.
            self.readers += 1;
        }
        if bytes::READERS.iter().any(|r| r.before == offset) {
            assert!(self.reader_start.is_none());
            self.reader_start = Some(copy_snapshot(point));
        }
    }
    pub(super) fn step(&mut self, before: &Snapshot, after: &Snapshot, child: &Tracee) {
        self.effect(before, after);
        self.unchanged(child);
    }
    /// Actual pure transition validator, also used by mutation controls.
    fn effect(&mut self, before: &Snapshot, after: &Snapshot) {
        let offset = before.logical_pc.checked_sub(self.caller).unwrap();
        let n = bytes::HEADS.iter().position(|&x| x == offset).unwrap();
        assert_ne!(offset, bytes::OUTER_RET);
        let mut expected = copy_snapshot(before);
        expected.logical_pc = self.caller + bytes::HEADS[n + 1];
        let r = &mut expected.registers;
        if let Some((reader_index, reader)) = bytes::READERS
            .iter()
            .enumerate()
            .find(|(_, r)| r.before <= offset && offset < r.after)
        {
            let cell = self.cells + reader.cell as u64 * bytes::CELL_BYTES as u64;
            assert_eq!(r.r14, cell);
            let first = bytes::HEADS
                .iter()
                .position(|&x| x == reader.before)
                .unwrap();
            let index = n - first;
            let spills = if reader.phase.is_some() {
                [112, 120, 128]
            } else {
                [88, 96, 104]
            };
            let outputs = if reader.phase.is_some() {
                [64, 72, 80]
            } else {
                [40, 48, 56]
            };
            match index {
                0..=2 => put_word(
                    &mut self.page,
                    self.page_address,
                    cell + spills[index],
                    [r.rax, r.rcx, r.rdx][index],
                ),
                3 | 5 => {} // LFENCE changes no architectural application state.
                4 => {
                    assert_eq!(offset, reader.rdtscp);
                    assert!(self.outputs[reader_index].is_none(), "one physical RDTSCP");
                    let actual = [
                        after.registers.rax,
                        after.registers.rdx,
                        after.registers.rcx,
                    ];
                    assert!(actual.iter().all(|&v| u32::try_from(v).is_ok()));
                    self.outputs[reader_index] = Some(actual);
                    r.rax = actual[0];
                    r.rdx = actual[1];
                    r.rcx = actual[2];
                }
                6..=8 => {
                    let k = index - 6;
                    assert_eq!(offset, reader.stores[k]);
                    let actual = self.outputs[reader_index].expect("actual preceding RDTSCP")[k];
                    assert_eq!([r.rax, r.rdx, r.rcx][k], actual);
                    let at = usize::try_from(cell + outputs[k] - self.page_address).unwrap();
                    self.page[at..at + 4].copy_from_slice(&(actual as u32).to_le_bytes());
                    self.stores += 1;
                }
                9..=11 => {
                    let value = word_at(&self.page, self.page_address, cell + spills[index - 9]);
                    match index {
                        9 => r.rax = value,
                        10 => r.rcx = value,
                        _ => r.rdx = value,
                    }
                }
                12 => {
                    assert_eq!(reader.phase, Some(offset));
                    put_word(&mut self.page, self.page_address, cell, 2);
                }
                _ => panic!("closed reader instruction"),
            }
        } else {
            match offset {
                0 | 5 | 10 | 14 | 15 => {
                    let value = match offset {
                        0 => r.r13,
                        5 => r.r12,
                        10 => r.rbp,
                        14 => r.rbx,
                        _ => r.r14,
                    };
                    r.rsp = r.rsp.checked_sub(8).unwrap();
                    put_word(&mut expected.application_stack, self.stack, r.rsp, value);
                }
                2 => r.r13 = r.rdi,
                7 => r.r12 = r.rdx,
                11 => r.rbp = r.rsi,
                17 => {
                    assert_eq!(r.rcx, self.cells);
                    r.r14 = r.rcx;
                }
                20 | 156 => {
                    r.rdi = word_at(
                        &before.data,
                        self.data,
                        r.rbp + if offset == 20 { 0 } else { 16 },
                    )
                }
                24 | 160 => {
                    r.rsi = word_at(
                        &before.data,
                        self.data,
                        r.rbp + if offset == 24 { 8 } else { 24 },
                    )
                }
                28 | 80 | 164 | 216 => {
                    let cell_index = usize::from(offset >= 164);
                    assert_eq!(
                        r.r14,
                        self.cells + cell_index as u64 * bytes::CELL_BYTES as u64
                    );
                    assert_eq!(r.rsp, self.rsp - 40);
                    let field = if matches!(offset, 28 | 164) { 24 } else { 32 };
                    put_word(&mut self.page, self.page_address, r.r14 + field, r.rsp);
                }
                77 | 213 => {
                    assert_eq!(r.r13, self.target);
                    r.rsp = r.rsp.checked_sub(8).unwrap();
                    put_word(
                        &mut expected.application_stack,
                        self.stack,
                        r.rsp,
                        expected.logical_pc,
                    );
                    expected.logical_pc = self.target;
                }
                142 | 278 => {
                    assert_eq!(r.r12, self.data + RESULTS as u64);
                    let at = r.r12 + if offset == 142 { 0 } else { 8 };
                    put_word(&mut expected.data, self.data, at, r.rax);
                }
                146 => r.rbx = r.rax,
                149 => {
                    assert_eq!(r.r14, self.cells);
                    r.r14 = r.r14.checked_add(144).unwrap();
                }
                283 => {
                    r.eflags = arithmetic_flags(r.eflags, r.rax, r.rbx, false);
                    r.rax = r.rax.wrapping_add(r.rbx);
                }
                286 | 288 | 289 | 290 | 292 => {
                    let value = word_at(&before.application_stack, self.stack, r.rsp);
                    match offset {
                        286 => r.r14 = value,
                        288 => r.rbx = value,
                        289 => r.rbp = value,
                        290 => r.r12 = value,
                        _ => r.r13 = value,
                    }
                    r.rsp = r.rsp.checked_add(8).unwrap();
                }
                _ => panic!("unhandled reference helper instruction"),
            }
        }
        assert_eq!(
            after.registers.rip, expected.logical_pc,
            "actual physical helper successor"
        );
        assert_eq!(after.logical_pc, expected.logical_pc);
        assert_state(&expected, after);
    }
    pub(super) fn returned(&mut self, child: &Tracee) {
        assert!(!self.outer_return);
        self.unchanged(child);
        self.outer_return = true; // Called only after parent authenticated the actual outer C3 step.
    }
    fn finish(self, exported: &[u8]) -> [bytes::Enclosure; 2] {
        assert!(self.outer_return && self.reader_start.is_none());
        assert_eq!(
            (self.heads, self.readers, self.stores, self.interiors),
            (80, 4, 12, 46)
        );
        assert!(self.outputs.iter().all(Option::is_some));
        assert_eq!(
            exported,
            &self.page[CELLS_AT..CELLS_AT + bytes::CELLS_BYTES]
        );
        let cells = decode_cells(exported);
        let result = std::array::from_fn(|k| {
            cells[k]
                .enclosure(k as u64 + 1, k as u64 + 1, self.rsp - 40, self.value)
                .unwrap()
        });
        assert_eq!(
            result[0].start.aux, result[1].start.aux,
            "same admitted singleton CPU"
        );
        assert!(result[0].end.ticks <= result[1].start.ticks);
        result
    }
}
pub(super) fn finish_pair(witnesses: [Witness; 2], exports: [Vec<u8>; 2]) -> Stats {
    let [a, b] = witnesses;
    let [ea, eb] = exports;
    Stats {
        reader_checks: 8,
        output_stores: 24,
        helper_heads: 160,
        interior_heads: 92,
        returned_cells: 4,
        endpoints: [a.finish(&ea), b.finish(&eb)],
    }
}

pub(super) fn validate_pair(
    case: ExactCase,
    pair: &NormalPairResult,
    counts: &[(usize, usize, usize, usize); 2],
    stats: &Stats,
) {
    assert_eq!(*counts, [case.counts(); 2]);
    assert_eq!(pair.visits, [case.counts().0; 2]);
    assert_eq!(pair.comparisons, 34 + 2 * case.counts().0);
    let minimum = pair.comparisons.checked_add(46).unwrap();
    assert!((minimum..=MAX_STEPS).contains(&pair.original_steps));
    assert!((minimum..=MAX_STEPS).contains(&pair.candidate_steps));
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
    assert_eq!(
        (
            stats.reader_checks,
            stats.output_stores,
            stats.helper_heads,
            stats.interior_heads,
            stats.returned_cells
        ),
        (8, 24, 160, 92, 4)
    );
}

// Closed geometry variants; old Legacy transfer/journal validators stay literal.
pub(super) fn call_before(
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
            ready.caller + bytes::CALLS[index],
            ready.entry,
            data + INPUT as u64,
            bound as u64,
            rsp - SUBJECT_RSP_DELTA + 8
        )
    );
}
pub(super) fn call_after(
    r: &libc::user_regs_struct,
    ready: &NormalReady,
    index: usize,
    rsp: u64,
    word: u64,
) {
    assert_eq!(
        (r.rip, r.rsp, word),
        (
            ready.entry,
            rsp - SUBJECT_RSP_DELTA,
            ready.caller + bytes::CONTINUATIONS[index]
        )
    );
}
pub(super) fn ret_before(
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
            ready.caller + bytes::CONTINUATIONS[index]
        )
    );
}
pub(super) fn ret_after(
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
            ready.caller + bytes::CONTINUATIONS[index],
            rsp - SUBJECT_RSP_DELTA + 8,
            value,
            ready.caller + bytes::CONTINUATIONS[index]
        )
    );
}
pub(super) fn journal_words(
    ready: &NormalReady,
    mode: Mode,
    pid: u64,
    rsp: u64,
    returns: &[u64],
) -> [u64; 512] {
    assert_eq!(mode, Mode::Stable);
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
        let word = ready.caller + bytes::CONTINUATIONS[n];
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

#[cfg(test)]
#[path = "native_normal_reference_tests.rs"]
mod tests;
