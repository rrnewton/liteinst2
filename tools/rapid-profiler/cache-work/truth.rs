//! Exact finite architectural work for one independent 39-byte linked leaf.
//! No scanner, certificate, planner, relocation map, timestamp or PMU input.
//! Native state/operand observations must separately authenticate execution.

pub const INPUT_BYTES: usize = 1024;
pub const MAX_STEPS: usize = 326;
pub const BYTES: [u8; 39] = [
    0x48, 0x8b, 0x4f, 0x10, 0x31, 0xc0, 0x31, 0xd2, 0x4c, 0x8b, 0x44, 0x17, 0x08, 0x4c, 0x01, 0xc0,
    0x48, 0x8b, 0x14, 0x17, 0x48, 0xff, 0xc9, 0x75, 0xef, 0x48, 0xba, 0x15, 0x7c, 0x4a, 0x7f, 0xb9,
    0x79, 0x37, 0x9e, 0x48, 0x31, 0xd0, 0xc3,
];
pub const HEADS: [u8; 11] = [0, 4, 6, 8, 13, 16, 20, 23, 25, 35, 38];
const KEY: u64 = 0x9e37_79b9_7f4a_7c15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Case {
    Reuse4,
    Cold16,
    Chase8,
    Fit2,
    Conflict3,
    Capacity12,
}
pub const ALL: [Case; 6] = [
    Case::Reuse4,
    Case::Cold16,
    Case::Chase8,
    Case::Fit2,
    Case::Conflict3,
    Case::Capacity12,
];
impl Case {
    pub fn name(self) -> &'static str {
        match self {
            Self::Reuse4 => "reuse4",
            Self::Cold16 => "cold16",
            Self::Chase8 => "chase8",
            Self::Fit2 => "fit2",
            Self::Conflict3 => "conflict3",
            Self::Capacity12 => "capacity12",
        }
    }
    pub fn iterations(self) -> usize {
        if self == Self::Cold16 { 16 } else { 64 }
    }
    pub fn cycle(self) -> &'static [usize] {
        match self {
            Self::Reuse4 => &[0, 1, 2, 3],
            Self::Cold16 => &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            Self::Chase8 => &[0, 3, 6, 1, 4, 7, 2, 5],
            Self::Fit2 => &[0, 4],
            Self::Conflict3 => &[0, 4, 8],
            Self::Capacity12 => &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Counts {
    pub instructions: usize,
    pub conditional: usize,
    pub taken: usize,
    pub input_reads: usize,
    pub return_reads: usize,
}
pub fn counts(case: Case) -> Counts {
    let n = case.iterations();
    Counts {
        instructions: 5 * n + 6,
        conditional: n,
        taken: n - 1,
        input_reads: 2 * n + 1,
        return_reads: 1,
    }
}
/// Hand-derived fixed-model totals, including the distinct final RET line.
pub fn expected_misses(case: Case) -> usize {
    match case {
        Case::Reuse4 => 5,
        Case::Cold16 => 17,
        Case::Chase8 => 9,
        Case::Fit2 => 3,
        Case::Conflict3 | Case::Capacity12 => 65,
    }
}
fn payload(node: usize, seed: u64) -> u64 {
    seed ^ KEY.wrapping_mul(node as u64 + 1)
}
/// Complete deterministic input, including unused nodes and padding bytes.
pub fn input(case: Case, seed: u64) -> [u8; INPUT_BYTES] {
    let mut bytes = [0; INPUT_BYTES];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed
            .wrapping_add((i as u64).wrapping_mul(37))
            .wrapping_add(11) as u8;
    }
    let cycle = case.cycle();
    for node in 0..16 {
        let next = cycle
            .iter()
            .position(|&i| i == node)
            .map_or(node, |i| cycle[(i + 1) % cycle.len()]);
        let offset = node * 64;
        bytes[offset..offset + 8].copy_from_slice(&((next * 64) as u64).to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&payload(node, seed).to_le_bytes());
    }
    bytes[16..24].copy_from_slice(&(case.iterations() as u64).to_le_bytes());
    bytes
}
/// Case arithmetic only: does not inspect fixture links or interpreted state.
pub fn scalar(case: Case, seed: u64) -> u64 {
    let cycle = case.cycle();
    (0..case.iterations()).fold(0_u64, |sum, j| {
        sum.wrapping_add(payload(cycle[j % cycle.len()], seed))
    }) ^ KEY
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bytes,
    Length,
    Count,
    Address,
    Offset,
    State,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadKind {
    Count,
    Payload,
    Link,
    ReturnWord,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Read {
    pub kind: ReadKind,
    pub address: u64,
    pub width: u8,
    pub value: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Step {
    pub pc: u64,
    pub next_pc: u64,
    pub branch_taken: Option<bool>,
    pub read: Option<Read>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Truth {
    pub steps: Vec<Step>,
    pub value: u64,
    pub resumed_rsp: u64,
}
pub fn check_bytes(bytes: &[u8]) -> Result<(), Error> {
    if bytes == BYTES {
        Ok(())
    } else {
        Err(Error::Bytes)
    }
}
fn word(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let end = offset.checked_add(8).ok_or(Error::Address)?;
    let value = bytes.get(offset..end).ok_or(Error::Address)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| Error::Length)?,
    ))
}
fn addresses(data: u64, rsp: u64) -> Result<u64, Error> {
    if data % 64 != 0 {
        return Err(Error::Address);
    }
    data.checked_add(INPUT_BYTES as u64).ok_or(Error::Address)?;
    rsp.checked_add(8).ok_or(Error::Address)
}
fn read(input: &[u8], data: u64, offset: u64, kind: ReadKind) -> Result<Read, Error> {
    let index = usize::try_from(offset).map_err(|_| Error::Address)?;
    Ok(Read {
        kind,
        address: data.checked_add(offset).ok_or(Error::Address)?,
        width: 8,
        value: word(input, index)?,
    })
}

/// Interpret exactly the original symbol. These checked integers are not live
/// mapping authority; the native caller proves ownership and actual arguments.
pub fn interpret(
    bytes: &[u8],
    input: &[u8],
    entry: u64,
    data: u64,
    entry_rsp: u64,
    return_word: u64,
) -> Result<Truth, Error> {
    check_bytes(bytes)?;
    if input.len() != INPUT_BYTES {
        return Err(Error::Length);
    }
    if !matches!(word(input, 16)?, 16 | 64) {
        return Err(Error::Count);
    }
    for node in 0..16 {
        let link = word(input, node * 64)?;
        if link % 64 != 0 || link > 960 {
            return Err(Error::Offset);
        }
    }
    entry
        .checked_add(BYTES.len() as u64)
        .ok_or(Error::Address)?;
    let resumed_rsp = addresses(data, entry_rsp)?;
    let (mut offset, mut rax, mut rcx, mut rdx, mut r8) = (0_usize, 0_u64, 0_u64, 0_u64, 0_u64);
    let mut zero = false;
    let mut steps = Vec::with_capacity(MAX_STEPS);
    loop {
        if steps.len() == MAX_STEPS {
            return Err(Error::State);
        }
        let (mut operand, mut branch_taken) = (None, None);
        let next = match offset {
            0 => {
                let r = read(input, data, 16, ReadKind::Count)?;
                rcx = r.value;
                operand = Some(r);
                4
            }
            4 => {
                rax = 0;
                zero = true;
                6
            }
            6 => {
                rdx = 0;
                zero = true;
                8
            }
            8 => {
                let r = read(
                    input,
                    data,
                    rdx.checked_add(8).ok_or(Error::Address)?,
                    ReadKind::Payload,
                )?;
                r8 = r.value;
                operand = Some(r);
                13
            }
            13 => {
                rax = rax.wrapping_add(r8);
                zero = rax == 0;
                16
            }
            16 => {
                let r = read(input, data, rdx, ReadKind::Link)?;
                rdx = r.value;
                operand = Some(r);
                20
            }
            20 => {
                rcx = rcx.wrapping_sub(1);
                zero = rcx == 0;
                23
            }
            23 => {
                branch_taken = Some(!zero);
                if zero { 25 } else { 8 }
            }
            25 => {
                rdx = KEY;
                35
            }
            35 => {
                rax ^= rdx;
                zero = rax == 0;
                38
            }
            38 => {
                operand = Some(Read {
                    kind: ReadKind::ReturnWord,
                    address: entry_rsp,
                    width: 8,
                    value: return_word,
                });
                BYTES.len()
            }
            _ => return Err(Error::State),
        };
        steps.push(Step {
            pc: entry + offset as u64,
            next_pc: if offset == 38 {
                return_word
            } else {
                entry + next as u64
            },
            branch_taken,
            read: operand,
        });
        if offset == 38 {
            return Ok(Truth {
                steps,
                value: rax,
                resumed_rsp,
            });
        }
        offset = next;
    }
}

/// Independent expected operands from the closed cycle/seed, never from an
/// interpreter result or a walk of the fixture's stored links.
pub fn expected_reads(
    case: Case,
    seed: u64,
    data: u64,
    entry_rsp: u64,
    return_word: u64,
) -> Result<Vec<Read>, Error> {
    addresses(data, entry_rsp)?;
    let mut reads = Vec::with_capacity(2 * case.iterations() + 2);
    reads.push(Read {
        kind: ReadKind::Count,
        address: data + 16,
        width: 8,
        value: case.iterations() as u64,
    });
    let cycle = case.cycle();
    for j in 0..case.iterations() {
        let node = cycle[j % cycle.len()];
        let next = cycle[(j + 1) % cycle.len()];
        reads.push(Read {
            kind: ReadKind::Payload,
            address: data + (node * 64 + 8) as u64,
            width: 8,
            value: payload(node, seed),
        });
        reads.push(Read {
            kind: ReadKind::Link,
            address: data + (node * 64) as u64,
            width: 8,
            value: (next * 64) as u64,
        });
    }
    reads.push(Read {
        kind: ReadKind::ReturnWord,
        address: entry_rsp,
        width: 8,
        value: return_word,
    });
    Ok(reads)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ENTRY: u64 = 0x1000;
    const DATA: u64 = 0x2000;
    const STACK: u64 = 0x4008;
    const RETURN: u64 = 0x5000;
    fn run(case: Case, seed: u64) -> Truth {
        interpret(&BYTES, &input(case, seed), ENTRY, DATA, STACK, RETURN).unwrap()
    }
    #[test]
    fn cache_literal_fixture_and_first_iteration() {
        let input = input(Case::Cold16, 0);
        assert_eq!(
            &input[..24],
            &[
                64, 0, 0, 0, 0, 0, 0, 0, 0x15, 0x7c, 0x4a, 0x7f, 0xb9, 0x79, 0x37, 0x9e, 16, 0, 0,
                0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(word(&input, 72).unwrap(), 0x3c6e_f372_fe94_f82a);
        assert_eq!(word(&input, 15 * 64).unwrap(), 0);
        let got = run(Case::Cold16, 0);
        assert_eq!(
            got.steps[..8]
                .iter()
                .map(|s| s.pc - ENTRY)
                .collect::<Vec<_>>(),
            [0, 4, 6, 8, 13, 16, 20, 23]
        );
        assert_eq!(got.steps[7].next_pc, ENTRY + 8);
        assert_eq!(got.steps[7].branch_taken, Some(true));
        assert_eq!(
            got.steps[0].read,
            Some(Read {
                kind: ReadKind::Count,
                address: DATA + 16,
                width: 8,
                value: 16
            })
        );
        assert_eq!(
            got.steps[3].read,
            Some(Read {
                kind: ReadKind::Payload,
                address: DATA + 8,
                width: 8,
                value: 0x9e37_79b9_7f4a_7c15
            })
        );
        assert_eq!(
            got.steps[5].read,
            Some(Read {
                kind: ReadKind::Link,
                address: DATA,
                width: 8,
                value: 64
            })
        );
    }
    #[test]
    fn cache_all_cases_join_independent_cycles_scalar_counts_and_ret() {
        // With seed0 the six payload coefficient sums are respectively
        // 160,136,288,192,316,400; these literal outputs are not from interpret.
        for (case, expected) in ALL.into_iter().zip([
            0x7c9b_6a56_f1c7_f135,
            0x934f_d332_e0db_973d,
            0x605f_8916_4c81_ebb5,
            0x37ac_32a6_0897_73d5,
            0xd24d_3940_60bb_55f9,
            0xa899_486f_9b2b_9cc5,
        ]) {
            assert_eq!(scalar(case, 0), expected);
            assert_eq!(run(case, 0).value, expected);
        }
        for seed in [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567] {
            for case in ALL {
                let got = run(case, seed);
                let n = counts(case);
                assert_eq!(got.steps.len(), n.instructions);
                assert_eq!(
                    got.steps
                        .iter()
                        .filter(|s| s.branch_taken.is_some())
                        .count(),
                    n.conditional
                );
                assert_eq!(
                    got.steps
                        .iter()
                        .filter(|s| s.branch_taken == Some(true))
                        .count(),
                    n.taken
                );
                let reads: Vec<_> = got.steps.iter().filter_map(|s| s.read).collect();
                assert_eq!(
                    reads,
                    expected_reads(case, seed, DATA, STACK, RETURN).unwrap()
                );
                assert_eq!(reads.len(), n.input_reads + n.return_reads);
                assert_eq!(got.value, scalar(case, seed));
                assert_eq!(got.resumed_rsp, STACK + 8);
                let heads: std::collections::BTreeSet<_> =
                    got.steps.iter().map(|s| s.pc - ENTRY).collect();
                assert_eq!(heads, HEADS.iter().map(|&p| u64::from(p)).collect());
                assert_eq!(
                    got.steps.last().unwrap(),
                    &Step {
                        pc: ENTRY + 38,
                        next_pc: RETURN,
                        branch_taken: None,
                        read: Some(Read {
                            kind: ReadKind::ReturnWord,
                            address: STACK,
                            width: 8,
                            value: RETURN
                        })
                    }
                );
                assert_eq!(got.steps[got.steps.len() - 4].branch_taken, Some(false));
            }
        }
    }
    #[test]
    fn cache_valid_link_or_payload_mutation_cannot_relabel_the_case() {
        let case = Case::Chase8;
        let original = input(case, 7);
        let mut changed = original;
        changed[..8].copy_from_slice(&0_u64.to_le_bytes()); // valid self-loop, wrong case
        let got = interpret(&BYTES, &changed, ENTRY, DATA, STACK, RETURN).unwrap();
        assert_ne!(
            got.steps.iter().filter_map(|s| s.read).collect::<Vec<_>>(),
            expected_reads(case, 7, DATA, STACK, RETURN).unwrap()
        );
        changed = original;
        changed[8] ^= 1;
        let got = interpret(&BYTES, &changed, ENTRY, DATA, STACK, RETURN).unwrap();
        assert_ne!(got.value, scalar(case, 7));
        assert_ne!(
            got.steps.iter().filter_map(|s| s.read).collect::<Vec<_>>(),
            expected_reads(case, 7, DATA, STACK, RETURN).unwrap()
        );
    }
    #[test]
    fn cache_every_changed_opcode_bit_is_refused() {
        for offset in 0..BYTES.len() {
            for bit in 0..8 {
                let mut changed = BYTES;
                changed[offset] ^= 1 << bit;
                assert_eq!(
                    interpret(
                        &changed,
                        &input(Case::Cold16, 0),
                        ENTRY,
                        DATA,
                        STACK,
                        RETURN
                    ),
                    Err(Error::Bytes)
                );
            }
        }
    }
    #[test]
    fn cache_invalid_header_links_extent_and_wrap_are_refused() {
        let original = input(Case::Cold16, 0);
        assert_eq!(
            interpret(&BYTES, &original[..1023], ENTRY, DATA, STACK, RETURN),
            Err(Error::Length)
        );
        for count in [0_u64, 1, 15, 17, 63, 65, u64::MAX] {
            let mut changed = original;
            changed[16..24].copy_from_slice(&count.to_le_bytes());
            assert_eq!(
                interpret(&BYTES, &changed, ENTRY, DATA, STACK, RETURN),
                Err(Error::Count)
            );
        }
        for link in [1_u64, 1024, u64::MAX] {
            let mut changed = original;
            changed[..8].copy_from_slice(&link.to_le_bytes());
            assert_eq!(
                interpret(&BYTES, &changed, ENTRY, DATA, STACK, RETURN),
                Err(Error::Offset)
            );
        }
        for (entry, data, stack) in [
            (u64::MAX - 10, DATA, STACK),
            (ENTRY, u64::MAX - 63, STACK),
            (ENTRY, DATA + 1, STACK),
            (ENTRY, DATA, u64::MAX - 3),
        ] {
            assert_eq!(
                interpret(&BYTES, &original, entry, data, stack, RETURN),
                Err(Error::Address)
            );
        }
    }
}
