//! Independent, finite work oracle for one exact 37-byte symbol.
//! No production scanner, certificate, planner, relocation map, timing or PMU
//! input. This models work/PC/read/branch/result semantics, not complete machine
//! state. Existing native full-state comparisons remain a separate requirement.

pub const BYTES: [u8; 37] = [
    0x31, 0xc0, 0x4c, 0x8d, 0x04, 0x37, 0x0f, 0xb6, 0x0f, 0x83, 0xf1, 0x5a, 0x48, 0x01, 0xc8, 0x48,
    0xff, 0xc7, 0x4c, 0x39, 0xc7, 0x72, 0xef, 0x48, 0xba, 0x15, 0x7c, 0x4a, 0x7f, 0xb9, 0x79, 0x37,
    0x9e, 0x48, 0x31, 0xd0, 0xc3,
];
pub const HEADS: [u8; 11] = [0, 2, 6, 9, 12, 15, 18, 21, 23, 33, 36];
pub const MAX_STEPS: usize = 389; // 6*64+5, includes the subject RET.
const KEY: u64 = 0x9e37_79b9_7f4a_7c15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bytes,
    Length,
    Address,
    State,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadKind {
    InputByte,
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

/// Accept only the independently specified symbol, including its entire extent.
pub fn check_bytes(bytes: &[u8]) -> Result<(), Error> {
    if bytes == BYTES {
        Ok(())
    } else {
        Err(Error::Bytes)
    }
}

/// Interpret the unmodified symbol. `return_word` is the complete actual saved
/// gate continuation, read independently from the original's entry stack slot.
/// Addresses are abstract checked inputs here; the native harness separately
/// authenticates their real mappings, contents and gate ownership.
pub fn interpret(
    bytes: &[u8],
    input: &[u8],
    entry: u64,
    data: u64,
    entry_rsp: u64,
    return_word: u64,
) -> Result<Truth, Error> {
    check_bytes(bytes)?;
    if !(1..=64).contains(&input.len()) {
        return Err(Error::Length);
    }
    entry
        .checked_add(BYTES.len() as u64)
        .ok_or(Error::Address)?;
    let end = data.checked_add(input.len() as u64).ok_or(Error::Address)?;
    let resumed_rsp = entry_rsp.checked_add(8).ok_or(Error::Address)?;
    let (mut offset, mut cursor) = (0_usize, data);
    let (mut rax, mut rcx, mut rdx, mut r8) = (0_u64, 0_u64, 0_u64, 0_u64);
    let mut carry = false;
    let mut steps = Vec::with_capacity(MAX_STEPS);
    loop {
        if steps.len() == MAX_STEPS {
            return Err(Error::State);
        }
        let (mut read, mut branch_taken) = (None, None);
        let next = match offset {
            0 => {
                rax = 0;
                carry = false;
                2
            } // XOR clears CF; no initial RAX use.
            2 => {
                r8 = end;
                6
            } // LEA leaves flags unchanged.
            6 => {
                let index = usize::try_from(cursor.checked_sub(data).ok_or(Error::State)?)
                    .map_err(|_| Error::State)?;
                let value = u64::from(*input.get(index).ok_or(Error::State)?);
                rcx = value; // MOVZX to ECX also zeros upper RCX.
                read = Some(Read {
                    kind: ReadKind::InputByte,
                    address: cursor,
                    width: 1,
                    value,
                });
                9
            }
            9 => {
                rcx ^= 0x5a;
                carry = false;
                12
            } // Exact positive imm8.
            12 => {
                let (sum, cf) = rax.overflowing_add(rcx);
                rax = sum;
                carry = cf;
                15
            }
            15 => {
                cursor = cursor.checked_add(1).ok_or(Error::Address)?;
                18
            } // INC preserves CF.
            18 => {
                carry = cursor < r8;
                21
            } // CMP's unsigned borrow, not preceding ADD/INC flags.
            21 => {
                branch_taken = Some(carry);
                if carry { 6 } else { 23 }
            }
            23 => {
                rdx = KEY;
                33
            } // MOV leaves flags unchanged.
            33 => {
                rax ^= rdx;
                carry = false;
                36
            }
            36 => {
                read = Some(Read {
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
            next_pc: if offset == 36 {
                return_word
            } else {
                entry + next as u64
            },
            branch_taken,
            read,
        });
        if offset == 36 {
            return Ok(Truth {
                steps,
                value: rax,
                resumed_rsp,
            });
        }
        offset = next;
    }
}

/// Algebraic third check, separate from the instruction walk.
pub fn counts(n: usize) -> Result<(usize, usize, usize, usize), Error> {
    if !(1..=64).contains(&n) {
        return Err(Error::Length);
    }
    Ok((6 * n + 5, n, n - 1, n + 1)) // instructions, conditional, taken, reads (RET included).
}

/// Scalar result model; it does not inspect the interpreted states or trace.
pub fn checksum(input: &[u8]) -> Result<u64, Error> {
    if !(1..=64).contains(&input.len()) {
        return Err(Error::Length);
    }
    Ok(input.iter().map(|b| u64::from(b ^ 0x5a)).sum::<u64>() ^ KEY)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ENTRY: u64 = 0x1000;
    const DATA: u64 = 0x2000;
    const STACK: u64 = 0x3000;
    const RETURN: u64 = 0x4000;
    fn run(bytes: &[u8], input: &[u8]) -> Result<Truth, Error> {
        interpret(bytes, input, ENTRY, DATA, STACK, RETURN)
    }
    #[test]
    fn literal_one_iteration_trace_includes_real_ret_read() {
        let got = run(&BYTES, &[0x5a]).unwrap();
        assert_eq!(
            got.steps.iter().map(|s| s.pc - ENTRY).collect::<Vec<_>>(),
            [0, 2, 6, 9, 12, 15, 18, 21, 23, 33, 36]
        );
        assert_eq!(
            got.steps.iter().filter_map(|s| s.read).collect::<Vec<_>>(),
            [
                Read {
                    kind: ReadKind::InputByte,
                    address: DATA,
                    width: 1,
                    value: 0x5a
                },
                Read {
                    kind: ReadKind::ReturnWord,
                    address: STACK,
                    width: 8,
                    value: RETURN
                },
            ]
        );
        assert_eq!(got.steps[7].branch_taken, Some(false));
        assert_eq!(got.steps.last().unwrap().next_pc, RETURN);
        assert_eq!(got.resumed_rsp, STACK + 8);
        assert_eq!(got.value, 0x9e37_79b9_7f4a_7c15);
    }
    #[test]
    fn every_length_matches_algebra_input_order_and_scalar_model() {
        let input: Vec<_> = (0..64).map(|i| (i * 37 + 11) as u8).collect();
        for n in 1..=64 {
            let got = run(&BYTES, &input[..n]).unwrap();
            let branches: Vec<_> = got.steps.iter().filter_map(|s| s.branch_taken).collect();
            let reads: Vec<_> = got.steps.iter().filter_map(|s| s.read).collect();
            assert_eq!(
                (
                    got.steps.len(),
                    branches.len(),
                    branches.iter().filter(|&&b| b).count(),
                    reads.len()
                ),
                counts(n).unwrap()
            );
            assert!(branches[..n - 1].iter().all(|&b| b));
            assert!(!branches[n - 1]);
            assert_eq!(
                reads[..n]
                    .iter()
                    .map(|r| (r.address, r.width, r.value))
                    .collect::<Vec<_>>(),
                input[..n]
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| (DATA + i as u64, 1, u64::from(b)))
                    .collect::<Vec<_>>()
            );
            assert_eq!(got.value, checksum(&input[..n]).unwrap());
        }
    }
    #[test]
    fn unsigned_loop_comparison_is_independent_of_input_xor_zero_flag() {
        let got = run(&BYTES, &[0x5a, 0]).unwrap();
        assert_eq!(
            got.steps
                .iter()
                .filter_map(|s| s.branch_taken)
                .collect::<Vec<_>>(),
            [true, false]
        );
        assert_eq!(got.value, 0x9e37_79b9_7f4a_7c4f);
    }
    #[test]
    fn changed_opcode_displacement_immediate_and_extent_all_refuse() {
        for index in 0..BYTES.len() {
            for bit in 0..8 {
                let mut changed = BYTES;
                changed[index] ^= 1 << bit;
                assert_eq!(run(&changed, &[1]), Err(Error::Bytes));
            }
        }
        assert_eq!(run(&BYTES[1..], &[1]), Err(Error::Bytes));
        assert_eq!(run(&BYTES[..36], &[1]), Err(Error::Bytes));
        let mut extended = BYTES.to_vec();
        extended.push(0x90);
        assert_eq!(run(&extended, &[1]), Err(Error::Bytes));
    }
    #[test]
    fn invalid_length_and_address_wrap_refuse() {
        assert_eq!(run(&BYTES, &[]), Err(Error::Length));
        assert_eq!(run(&BYTES, &[0; 65]), Err(Error::Length));
        for (entry, data, stack) in [
            (u64::MAX, DATA, STACK),
            (ENTRY, u64::MAX, STACK),
            (ENTRY, DATA, u64::MAX),
        ] {
            assert_eq!(
                interpret(&BYTES, &[1], entry, data, stack, RETURN),
                Err(Error::Address)
            );
        }
    }
}
