//! Private qualification fixture: complete ordinary-ABI reference enclosure.
//! Hand-authored bytes are the authority; labels/decoder observations must match.
//! No invocation, ELF loader, hardware admission or native accuracy is provided.
pub use super::caller_bytes::{Request, Target};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

pub const SYMBOL: &str = "normal_reference_caller";
pub const BYTES: &[u8] = &[
    0x41, 0x55, 0x49, 0x89, 0xfd, 0x41, 0x54, 0x49, 0x89, 0xd4, 0x55, 0x48, 0x89, 0xf5, 0x53, 0x41,
    0x56, 0x49, 0x89, 0xce, 0x48, 0x8b, 0x7d, 0x00, 0x48, 0x8b, 0x75, 0x08, 0x49, 0x89, 0x66, 0x18,
    0x49, 0x89, 0x46, 0x58, 0x49, 0x89, 0x4e, 0x60, 0x49, 0x89, 0x56, 0x68, 0x0f, 0xae, 0xe8, 0x0f,
    0x01, 0xf9, 0x0f, 0xae, 0xe8, 0x41, 0x89, 0x46, 0x28, 0x41, 0x89, 0x56, 0x30, 0x41, 0x89, 0x4e,
    0x38, 0x49, 0x8b, 0x46, 0x58, 0x49, 0x8b, 0x4e, 0x60, 0x49, 0x8b, 0x56, 0x68, 0x41, 0xff, 0xd5,
    0x49, 0x89, 0x66, 0x20, 0x49, 0x89, 0x46, 0x70, 0x49, 0x89, 0x4e, 0x78, 0x49, 0x89, 0x96, 0x80,
    0x00, 0x00, 0x00, 0x0f, 0xae, 0xe8, 0x0f, 0x01, 0xf9, 0x0f, 0xae, 0xe8, 0x41, 0x89, 0x46, 0x40,
    0x41, 0x89, 0x56, 0x48, 0x41, 0x89, 0x4e, 0x50, 0x49, 0x8b, 0x46, 0x70, 0x49, 0x8b, 0x4e, 0x78,
    0x49, 0x8b, 0x96, 0x80, 0x00, 0x00, 0x00, 0x49, 0xc7, 0x06, 0x02, 0x00, 0x00, 0x00, 0x49, 0x89,
    0x04, 0x24, 0x48, 0x89, 0xc3, 0x4d, 0x8d, 0xb6, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x7d, 0x10,
    0x48, 0x8b, 0x75, 0x18, 0x49, 0x89, 0x66, 0x18, 0x49, 0x89, 0x46, 0x58, 0x49, 0x89, 0x4e, 0x60,
    0x49, 0x89, 0x56, 0x68, 0x0f, 0xae, 0xe8, 0x0f, 0x01, 0xf9, 0x0f, 0xae, 0xe8, 0x41, 0x89, 0x46,
    0x28, 0x41, 0x89, 0x56, 0x30, 0x41, 0x89, 0x4e, 0x38, 0x49, 0x8b, 0x46, 0x58, 0x49, 0x8b, 0x4e,
    0x60, 0x49, 0x8b, 0x56, 0x68, 0x41, 0xff, 0xd5, 0x49, 0x89, 0x66, 0x20, 0x49, 0x89, 0x46, 0x70,
    0x49, 0x89, 0x4e, 0x78, 0x49, 0x89, 0x96, 0x80, 0x00, 0x00, 0x00, 0x0f, 0xae, 0xe8, 0x0f, 0x01,
    0xf9, 0x0f, 0xae, 0xe8, 0x41, 0x89, 0x46, 0x40, 0x41, 0x89, 0x56, 0x48, 0x41, 0x89, 0x4e, 0x50,
    0x49, 0x8b, 0x46, 0x70, 0x49, 0x8b, 0x4e, 0x78, 0x49, 0x8b, 0x96, 0x80, 0x00, 0x00, 0x00, 0x49,
    0xc7, 0x06, 0x02, 0x00, 0x00, 0x00, 0x49, 0x89, 0x44, 0x24, 0x08, 0x48, 0x01, 0xd8, 0x41, 0x5e,
    0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0xc3,
];
pub const HEADS: &[u64] = &[
    0, 2, 5, 7, 10, 11, 14, 15, 17, 20, 24, 28, 32, 36, 40, 44, 47, 50, 53, 57, 61, 65, 69, 73, 77,
    80, 84, 88, 92, 99, 102, 105, 108, 112, 116, 120, 124, 128, 135, 142, 146, 149, 156, 160, 164,
    168, 172, 176, 180, 183, 186, 189, 193, 197, 201, 205, 209, 213, 216, 220, 224, 228, 235, 238,
    241, 244, 248, 252, 256, 260, 264, 271, 278, 283, 286, 288, 289, 290, 292, 294,
];
pub const CALLS: [u64; 2] = [77, 213];
pub const CONTINUATIONS: [u64; 2] = [80, 216];
pub const OUTER_RET: u64 = 294;
pub const END: u64 = 295;
pub const H: usize = 34;
pub const SUBJECT_RSP_DELTA: u64 = 48;
pub const PROTECTED_STACK_BELOW_CALLER: u64 = 176;
pub const RESTORED_HEADS: &[u64] = &[
    0, 2, 5, 7, 10, 11, 14, 15, 17, 20, 24, 28, 32, 77, 80, 84, 142, 146, 149, 156, 160, 164, 168,
    213, 216, 220, 278, 283, 286, 288, 289, 290, 292, 294,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reader {
    pub cell: usize,
    pub before: u64,
    pub rdtscp: u64,
    pub stores: [u64; 3],
    pub after: u64,
    pub phase: Option<u64>,
}
pub const READERS: [Reader; 4] = [
    Reader {
        cell: 0,
        before: 32,
        rdtscp: 47,
        stores: [53, 57, 61],
        after: 77,
        phase: None,
    },
    Reader {
        cell: 0,
        before: 84,
        rdtscp: 102,
        stores: [108, 112, 116],
        after: 142,
        phase: Some(135),
    },
    Reader {
        cell: 1,
        before: 168,
        rdtscp: 183,
        stores: [189, 193, 197],
        after: 213,
        phase: None,
    },
    Reader {
        cell: 1,
        before: 220,
        rdtscp: 238,
        stores: [244, 248, 252],
        after: 278,
        phase: Some(271),
    },
];
// These symbols must come from the independently trusted complete ELF, not candidate guesses.
pub const LABELS: &[(&str, u64)] = &[
    ("normal_reference_c0_start_before", 32),
    ("normal_reference_c0_start_rdtscp", 47),
    ("normal_reference_c0_start_lo", 53),
    ("normal_reference_c0_start_hi", 57),
    ("normal_reference_c0_start_aux", 61),
    ("normal_reference_c0_start_after", 77),
    ("normal_reference_call0", 77),
    ("normal_reference_continuation0", 80),
    ("normal_reference_c0_end_before", 84),
    ("normal_reference_c0_end_rdtscp", 102),
    ("normal_reference_c0_end_lo", 108),
    ("normal_reference_c0_end_hi", 112),
    ("normal_reference_c0_end_aux", 116),
    ("normal_reference_c0_end_phase", 135),
    ("normal_reference_c0_end_after", 142),
    ("normal_reference_c1_start_before", 168),
    ("normal_reference_c1_start_rdtscp", 183),
    ("normal_reference_c1_start_lo", 189),
    ("normal_reference_c1_start_hi", 193),
    ("normal_reference_c1_start_aux", 197),
    ("normal_reference_c1_start_after", 213),
    ("normal_reference_call1", 213),
    ("normal_reference_continuation1", 216),
    ("normal_reference_c1_end_before", 220),
    ("normal_reference_c1_end_rdtscp", 238),
    ("normal_reference_c1_end_lo", 244),
    ("normal_reference_c1_end_hi", 248),
    ("normal_reference_c1_end_aux", 252),
    ("normal_reference_c1_end_phase", 271),
    ("normal_reference_c1_end_after", 278),
    ("normal_reference_outer_ret", 294),
    ("normal_reference_end", 295),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bytes,
    Geometry,
    Identity,
    Cell,
    Range,
}
type Result<T> = std::result::Result<T, Error>;
fn require(ok: bool, error: Error) -> Result<()> {
    if ok { Ok(()) } else { Err(error) }
}

/// Only interior reader heads have nondeterministic transient timestamp GPRs.
/// Future qualification must still SINGLESTEP and independently witness all of
/// them; this predicate is not permission to skip work or mask application data.
pub fn transient(offset: u64) -> bool {
    READERS
        .iter()
        .any(|r| r.before < offset && offset < r.after)
}
fn memory(i: &Instruction, operand: u32, offset: u64, width: usize) -> bool {
    i.op_kind(operand) == OpKind::Memory
        && i.memory_base() == Register::R14
        && i.memory_index() == Register::None
        && i.memory_displacement64() == offset
        && i.memory_size().size() == width
        && i.segment_prefix() == Register::None
}
fn store(i: &Instruction, register: Register, offset: u64, width: usize) -> bool {
    i.mnemonic() == Mnemonic::Mov
        && i.op_count() == 2
        && memory(i, 0, offset, width)
        && i.op1_kind() == OpKind::Register
        && i.op1_register() == register
}
fn restore(i: &Instruction, register: Register, offset: u64) -> bool {
    i.mnemonic() == Mnemonic::Mov
        && i.op_count() == 2
        && i.op0_kind() == OpKind::Register
        && i.op0_register() == register
        && memory(i, 1, offset, 8)
}
fn reader_shape(all: &[Instruction], r: Reader) -> Result<()> {
    let start = all
        .iter()
        .position(|i| i.ip() == r.before)
        .ok_or(Error::Geometry)?;
    let count = if r.phase.is_some() { 13 } else { 12 };
    let b = all.get(start..start + count).ok_or(Error::Geometry)?;
    let (spills, outputs) = if r.phase.is_some() {
        ([112, 120, 128], [64, 72, 80])
    } else {
        ([88, 96, 104], [40, 48, 56])
    };
    for k in 0..3 {
        require(
            store(
                &b[k],
                [Register::RAX, Register::RCX, Register::RDX][k],
                spills[k],
                8,
            ),
            Error::Geometry,
        )?;
        require(
            store(
                &b[6 + k],
                [Register::EAX, Register::EDX, Register::ECX][k],
                outputs[k],
                4,
            ) && b[6 + k].ip() == r.stores[k],
            Error::Geometry,
        )?;
        require(
            restore(
                &b[9 + k],
                [Register::RAX, Register::RCX, Register::RDX][k],
                spills[k],
            ),
            Error::Geometry,
        )?;
    }
    require(
        b[3].mnemonic() == Mnemonic::Lfence
            && b[3].op_count() == 0
            && b[4].mnemonic() == Mnemonic::Rdtscp
            && b[4].op_count() == 0
            && b[4].ip() == r.rdtscp
            && b[5].mnemonic() == Mnemonic::Lfence
            && b[5].op_count() == 0
            && b.last().unwrap().next_ip() == r.after,
        Error::Geometry,
    )?;
    if let Some(pc) = r.phase {
        let i = &b[12];
        require(
            i.ip() == pc
                && i.mnemonic() == Mnemonic::Mov
                && i.op_count() == 2
                && memory(i, 0, 0, 8)
                && i.op1_kind() == OpKind::Immediate32to64
                && i.immediate32to64() == 2,
            Error::Geometry,
        )?;
    }
    Ok(())
}

/// Pure body validator. It reads no process, code pointer, ELF or hardware state.
/// A future owner must separately authenticate the independent entire ELF, its
/// exact function extent, every named label, immutable fd and complete live RX page.
pub fn validate_body(code: &[u8]) -> Result<()> {
    require(code == BYTES, Error::Bytes)?;
    require(
        code.len() == 295
            && END == 295
            && HEADS.len() == 80
            && RESTORED_HEADS.len() == H
            && H == 34,
        Error::Geometry,
    )?;
    let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    let mut decoded = Vec::with_capacity(HEADS.len());
    for &pc in HEADS {
        let i = decoder.decode();
        require(
            !i.is_invalid()
                && i.ip() == pc
                && !i.has_lock_prefix()
                && !i.has_rep_prefix()
                && !i.has_repne_prefix()
                && i.segment_prefix() == Register::None,
            Error::Geometry,
        )?;
        if let Some(k) = CALLS.iter().position(|&p| p == pc) {
            require(
                i.flow_control() == FlowControl::IndirectCall
                    && i.op0_kind() == OpKind::Register
                    && i.op0_register() == Register::R13
                    && i.next_ip() == CONTINUATIONS[k],
                Error::Geometry,
            )?;
        } else {
            require(
                i.flow_control()
                    == if pc == OUTER_RET {
                        FlowControl::Return
                    } else {
                        FlowControl::Next
                    },
                Error::Geometry,
            )?;
        }
        decoded.push(i);
    }
    require(
        !decoder.can_decode()
            && decoder.position() == code.len()
            && decoded.last().unwrap().next_ip() == END
            && code[OUTER_RET as usize..] == [0xc3],
        Error::Geometry,
    )?;
    for r in READERS {
        reader_shape(&decoded, r)?;
    }
    let restored: Vec<_> = HEADS.iter().copied().filter(|&pc| !transient(pc)).collect();
    require(restored == RESTORED_HEADS, Error::Geometry)
}

/// The caller supplies observed absolute addresses in exact LABELS order. The
/// source/name/ELF ownership of those addresses remains the loader's obligation.
/// Matching invented addresses is not an authentication of an actual mapping.
pub fn validate_layout(entry: u64, actual_labels: &[u64], code: &[u8]) -> Result<()> {
    validate_body(code)?;
    require(
        entry != 0
            && entry % 4096 == 0
            && entry.checked_add(END).is_some()
            && actual_labels.len() == LABELS.len(),
        Error::Geometry,
    )?;
    for (&actual, &(_, offset)) in actual_labels.iter().zip(LABELS) {
        require(entry.checked_add(offset) == Some(actual), Error::Geometry)?;
    }
    Ok(())
}

const ARMED: u64 = 1;
const END_READER_STORED: u64 = 2;
const CANARY: u64 = 0x6e72_6566_6365_6c31;
pub const CELL_BYTES: usize = 144;
pub const CELLS_BYTES: usize = 288;

/// Private writable memory, not a profiler receipt or a published result.
/// END_READER_STORED is reached before the helper's actual RET. Neither this
/// phase nor `enclosure()` proves physical return, postflight or checkpoint.
/// Upper halves of the six timestamp words start at zero: assembly writes only
/// four bytes to each, while qualification authenticates the entire 144 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceCell {
    phase: u64,
    sequence: u64,
    external_id: u64,
    pre_call_rsp: u64,
    resumed_rsp: u64,
    start_lo: u64,
    start_hi: u64,
    start_aux: u64,
    end_lo: u64,
    end_hi: u64,
    end_aux: u64,
    before_rax: u64,
    before_rcx: u64,
    before_rdx: u64,
    after_rax: u64,
    after_rcx: u64,
    after_rdx: u64,
    canary: u64,
}
const _: () = {
    // Five saved registers, the subject CALL word, and its SysV red zone.
    assert!(SUBJECT_RSP_DELTA == 5 * 8 + 8);
    assert!(PROTECTED_STACK_BELOW_CALLER == SUBJECT_RSP_DELTA + 128);
    assert!(core::mem::size_of::<Request>() == 16);
    assert!(core::mem::align_of::<Request>() == 8);
    assert!(core::mem::offset_of!(Request, data) == 0);
    assert!(core::mem::offset_of!(Request, bound) == 8);
    assert!(core::mem::size_of::<ReferenceCell>() == CELL_BYTES);
    assert!(core::mem::align_of::<ReferenceCell>() == 8);
    assert!(core::mem::size_of::<[ReferenceCell; 2]>() == CELLS_BYTES);
    assert!(core::mem::offset_of!(ReferenceCell, phase) == 0);
    assert!(core::mem::offset_of!(ReferenceCell, sequence) == 8);
    assert!(core::mem::offset_of!(ReferenceCell, external_id) == 16);
    assert!(core::mem::offset_of!(ReferenceCell, pre_call_rsp) == 24);
    assert!(core::mem::offset_of!(ReferenceCell, resumed_rsp) == 32);
    assert!(core::mem::offset_of!(ReferenceCell, start_lo) == 40);
    assert!(core::mem::offset_of!(ReferenceCell, start_hi) == 48);
    assert!(core::mem::offset_of!(ReferenceCell, start_aux) == 56);
    assert!(core::mem::offset_of!(ReferenceCell, end_lo) == 64);
    assert!(core::mem::offset_of!(ReferenceCell, end_hi) == 72);
    assert!(core::mem::offset_of!(ReferenceCell, end_aux) == 80);
    assert!(core::mem::offset_of!(ReferenceCell, before_rax) == 88);
    assert!(core::mem::offset_of!(ReferenceCell, before_rcx) == 96);
    assert!(core::mem::offset_of!(ReferenceCell, before_rdx) == 104);
    assert!(core::mem::offset_of!(ReferenceCell, after_rax) == 112);
    assert!(core::mem::offset_of!(ReferenceCell, after_rcx) == 120);
    assert!(core::mem::offset_of!(ReferenceCell, after_rdx) == 128);
    assert!(core::mem::offset_of!(ReferenceCell, canary) == 136);
};

/// Raw unsafe ABI only. There is intentionally no safe invocation wrapper.
/// Invoke only through a retained, independently authenticated helper owner;
/// on each actual calling thread admit the existing ReferenceAmdV1 hardware
/// predicate and singleton CPU affinity under stable-platform custody. Both
/// calls use the same admitted immutable scalar target and normal SysV returns.
/// Requests, results, cells, full input, code, journal and protected stack must
/// have disjoint valid extents (the two input slices may share immutable bytes).
/// Cells are fresh for exactly one helper invocation; do not read/export them
/// during execution or treat their phase as a return witness. No active CET,
/// signals, reentry, fork, cancellation, source writer, mapping change or unload.
/// Final source/input/cell checks follow actual helper return and precede any
/// normal-runtime checkpoint/exposure. The helper itself does no checkpoint.
pub type Caller = unsafe extern "C" fn(Target, *const Request, *mut u64, *mut ReferenceCell) -> u64;

pub fn fresh_cells(first_sequence: u64, external_ids: [u64; 2]) -> Result<[ReferenceCell; 2]> {
    require(
        first_sequence != 0
            && first_sequence.checked_add(1).is_some()
            && external_ids.iter().all(|&n| n != 0)
            && external_ids[0] != external_ids[1],
        Error::Identity,
    )?;
    Ok(std::array::from_fn(|k| ReferenceCell {
        phase: ARMED,
        sequence: first_sequence + k as u64,
        external_id: external_ids[k],
        pre_call_rsp: 0,
        resumed_rsp: 0,
        start_lo: 0,
        start_hi: 0,
        start_aux: 0,
        end_lo: 0,
        end_hi: 0,
        end_aux: 0,
        before_rax: 0,
        before_rcx: 0,
        before_rdx: 0,
        after_rax: 0,
        after_rcx: 0,
        after_rdx: 0,
        canary: CANARY,
    }))
}

/// Validate a separate cell area against the complete protected range list.
/// The consumer/oracle must supply every code/data/stack/journal range; this
/// arithmetic does not discover mappings or prove that a list is complete.
pub fn validate_cell_area(address: u64, protected: &[(u64, u64)]) -> Result<()> {
    require(
        address != 0 && address % 8 == 0 && !protected.is_empty(),
        Error::Range,
    )?;
    let end = address
        .checked_add(CELLS_BYTES as u64)
        .ok_or(Error::Range)?;
    require(
        protected
            .iter()
            .all(|&(a, b)| a < b && (end <= a || b <= address)),
        Error::Range,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub ticks: u64,
    pub aux: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Enclosure {
    pub start: Timestamp,
    pub end: Timestamp,
}
impl ReferenceCell {
    /// Pure cell consistency only, after separately proved helper return and
    /// postflight. No actual RDTSCP provenance, receipt, owner or clock-accuracy
    /// credit follows from this validator; the future same-child witness must
    /// join every output/spill/store and complete application state independently.
    pub fn enclosure(
        &self,
        sequence: u64,
        external_id: u64,
        pre_call_rsp: u64,
        value: u64,
    ) -> Result<Enclosure> {
        require(
            sequence != 0
                && external_id != 0
                && (self.sequence, self.external_id) == (sequence, external_id),
            Error::Identity,
        )?;
        require(
            self.phase == END_READER_STORED
                && self.canary == CANARY
                && pre_call_rsp != 0
                && pre_call_rsp % 16 == 0
                && self.pre_call_rsp == pre_call_rsp
                && self.resumed_rsp == pre_call_rsp
                && self.after_rax == value,
            Error::Cell,
        )?;
        let words = [
            self.start_lo,
            self.start_hi,
            self.start_aux,
            self.end_lo,
            self.end_hi,
            self.end_aux,
        ];
        require(words.iter().all(|&n| u32::try_from(n).is_ok()), Error::Cell)?;
        let start = Timestamp {
            ticks: self.start_hi << 32 | self.start_lo,
            aux: self.start_aux as u32,
        };
        let end = Timestamp {
            ticks: self.end_hi << 32 | self.end_lo,
            aux: self.end_aux as u32,
        };
        require(
            start.aux == end.aux && start.ticks <= end.ticks,
            Error::Cell,
        )?;
        Ok(Enclosure { start, end })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn labels(entry: u64) -> Vec<u64> {
        LABELS.iter().map(|&(_, n)| entry + n).collect()
    }
    fn returned() -> ReferenceCell {
        let mut c = fresh_cells(7, [101, 103]).unwrap()[0];
        c.phase = END_READER_STORED;
        c.pre_call_rsp = 0x8000;
        c.resumed_rsp = 0x8000;
        c.start_lo = 13;
        c.end_lo = 29;
        c.start_aux = 5;
        c.end_aux = 5;
        c.after_rax = 91;
        c
    }
    #[test]
    fn normal_reference_body_every_opcode_bit_and_extent() {
        assert_eq!(validate_body(BYTES), Ok(()));
        for at in 0..BYTES.len() {
            for bit in 0..8 {
                let mut bad = BYTES.to_vec();
                bad[at] ^= 1 << bit;
                assert_eq!(validate_body(&bad), Err(Error::Bytes));
            }
        }
        assert_eq!(validate_body(&BYTES[..BYTES.len() - 1]), Err(Error::Bytes));
        let mut extra = BYTES.to_vec();
        extra.push(0x90);
        assert_eq!(validate_body(&extra), Err(Error::Bytes));
        assert_eq!((HEADS.len(), RESTORED_HEADS.len(), H), (80, 34, 34));
        assert_eq!(CALLS, [77, 213]);
        assert_eq!(CONTINUATIONS, [80, 216]);
        assert_eq!((OUTER_RET, END), (294, 295));
    }
    #[test]
    fn normal_reference_labels_require_exact_addresses_and_no_wrap() {
        let entry = 0x10000;
        let good = labels(entry);
        assert_eq!(validate_layout(entry, &good, BYTES), Ok(()));
        for k in 0..good.len() {
            let mut bad = good.clone();
            bad[k] += 1;
            assert_eq!(validate_layout(entry, &bad, BYTES), Err(Error::Geometry));
        }
        assert_eq!(
            validate_layout(entry, &good[..good.len() - 1], BYTES),
            Err(Error::Geometry)
        );
        let mut extra = good.clone();
        extra.push(entry);
        assert_eq!(validate_layout(entry, &extra, BYTES), Err(Error::Geometry));
        assert_eq!(validate_layout(0, &good, BYTES), Err(Error::Geometry));
        assert_eq!(
            validate_layout(entry + 1, &good, BYTES),
            Err(Error::Geometry)
        );
        assert_eq!(
            validate_layout(u64::MAX, &good, BYTES),
            Err(Error::Geometry)
        );
    }
    #[test]
    fn normal_reference_reader_boundaries_and_cell_isolation() {
        assert_eq!(READERS.map(|r| r.rdtscp), [47, 102, 183, 238]);
        assert_eq!(READERS.map(|r| r.cell), [0, 0, 1, 1]);
        for r in READERS {
            assert!(!transient(r.before));
            assert!(!transient(r.after));
            assert!(transient(r.rdtscp));
            assert!(r.stores.into_iter().all(transient));
        }
        let address = 0x2000;
        assert_eq!(
            validate_cell_area(address, &[(0x1000, address), (address + 288, 0x3000)]),
            Ok(())
        );
        for bad in [0, address + 1, u64::MAX - 7] {
            assert_eq!(
                validate_cell_area(bad, &[(0x1000, 0x1800)]),
                Err(Error::Range)
            );
        }
        for range in [
            (address - 1, address + 1),
            (address + 287, address + 289),
            (address, address + 288),
            (3, 3),
            (4, 3),
        ] {
            assert_eq!(validate_cell_area(address, &[range]), Err(Error::Range));
        }
        assert_eq!(validate_cell_area(address, &[]), Err(Error::Range));
    }
    #[test]
    fn normal_reference_fresh_identity_phase_stack_result_and_canary() {
        let cells = fresh_cells(7, [101, 103]).unwrap();
        assert_eq!((cells[0].sequence, cells[1].sequence), (7, 8));
        assert_eq!((cells[0].external_id, cells[1].external_id), (101, 103));
        assert_eq!(cells[0].enclosure(7, 101, 0x8000, 91), Err(Error::Cell));
        for (seq, ids) in [
            (0, [1, 2]),
            (u64::MAX, [1, 2]),
            (1, [0, 2]),
            (1, [1, 0]),
            (1, [1, 1]),
        ] {
            assert_eq!(fresh_cells(seq, ids), Err(Error::Identity));
        }
        let c = returned();
        assert!(c.enclosure(7, 101, 0x8000, 91).is_ok());
        assert_eq!(c.enclosure(8, 101, 0x8000, 91), Err(Error::Identity));
        assert_eq!(c.enclosure(7, 103, 0x8000, 91), Err(Error::Identity));
        for k in 0..5 {
            let mut bad = c;
            match k {
                0 => bad.phase = 1,
                1 => bad.canary ^= 1,
                2 => bad.pre_call_rsp += 8,
                3 => bad.resumed_rsp += 16,
                _ => bad.after_rax ^= 1,
            }
            assert_eq!(bad.enclosure(7, 101, 0x8000, 91), Err(Error::Cell));
        }
        assert_eq!(c.enclosure(7, 101, 0x8008, 91), Err(Error::Cell));
    }
    #[test]
    fn normal_reference_endpoint_high_words_aux_and_regression() {
        for k in 0..6 {
            let mut c = returned();
            match k {
                0 => c.start_lo |= 1 << 32,
                1 => c.start_hi |= 1 << 32,
                2 => c.start_aux |= 1 << 32,
                3 => c.end_lo |= 1 << 32,
                4 => c.end_hi |= 1 << 32,
                _ => c.end_aux |= 1 << 32,
            }
            assert_eq!(c.enclosure(7, 101, 0x8000, 91), Err(Error::Cell));
        }
        let mut c = returned();
        c.end_aux += 1;
        assert_eq!(c.enclosure(7, 101, 0x8000, 91), Err(Error::Cell));
        c = returned();
        c.end_lo = 12;
        assert_eq!(c.enclosure(7, 101, 0x8000, 91), Err(Error::Cell));
    }
    #[test]
    fn normal_reference_zero_and_full_width_endpoints_are_retained() {
        let mut c = returned();
        c.start_lo = 0;
        c.end_lo = 0;
        c.start_aux = 0;
        c.end_aux = 0;
        let zero = c.enclosure(7, 101, 0x8000, 91).unwrap();
        assert_eq!(
            zero,
            Enclosure {
                start: Timestamp { ticks: 0, aux: 0 },
                end: Timestamp { ticks: 0, aux: 0 }
            }
        );
        c.start_hi = u32::MAX as u64;
        c.start_lo = u32::MAX as u64;
        c.end_hi = c.start_hi;
        c.end_lo = c.start_lo;
        let max = c.enclosure(7, 101, 0x8000, 91).unwrap();
        assert_eq!((max.start.ticks, max.end.ticks), (u64::MAX, u64::MAX));
    }
}
