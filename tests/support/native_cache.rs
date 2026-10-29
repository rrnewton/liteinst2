//! Closed linked-memory subject: actual original read reconstruction, not PMU data.
//! The existing ordinary oracle owns both children, state comparisons and reaps.
use super::{OriginalObservation, OriginalStep};
use std::collections::BTreeSet;

#[path = "../../tools/rapid-profiler/cache-work/model.rs"]
pub mod model;
register_native_fixture!(cache_truth);

pub struct Stats {
    pub counts: truth::Counts,
    pub model: model::Summary,
}

fn bytes_at(bytes: &[u8], base: u64, address: u64, count: usize) -> &[u8] {
    let offset = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    &bytes[offset..offset.checked_add(count).unwrap()]
}
fn word(bytes: &[u8], base: u64, address: u64) -> u64 {
    u64::from_le_bytes(bytes_at(bytes, base, address, 8).try_into().unwrap())
}
fn check_shape(actual: &[OriginalStep<'_>], expected: &[truth::Step], entry: u64) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "complete original trace length"
    );
    assert_eq!(
        actual
            .iter()
            .map(|s| s.before.rip.checked_sub(entry).unwrap())
            .collect::<BTreeSet<_>>(),
        truth::HEADS
            .iter()
            .map(|&p| u64::from(p))
            .collect::<BTreeSet<_>>(),
        "all literal cache instruction heads"
    );
    for (a, p) in actual.iter().zip(expected) {
        assert_eq!(
            (a.before.rip, a.after.rip),
            (p.pc, p.next_pc),
            "ordered cache PCs"
        );
    }
}

// Authenticate the operand and instruction result from ACTUAL before/after
// registers and the complete captured memory. No certificate-derived semantics.
fn check_step(
    actual: &OriginalStep<'_>,
    predicted: &truth::Step,
    entry: u64,
    data: u64,
) -> Option<truth::Read> {
    use truth::{Read, ReadKind};
    let before = &actual.before;
    let after = &actual.after;
    assert_eq!((before.rip, after.rip), (predicted.pc, predicted.next_pc));
    assert_eq!(before.rdi, data, "unchanged actual input base");
    assert_eq!(
        before.rsi,
        truth::INPUT_BYTES as u64,
        "full actual input length"
    );
    let offset = before.rip.checked_sub(entry).unwrap();
    let input_read = |kind, address: u64| {
        assert!(
            data <= address
                && address.checked_add(8).unwrap()
                    <= data.checked_add(truth::INPUT_BYTES as u64).unwrap()
        );
        assert_eq!(address % 8, 0);
        Read {
            kind,
            address,
            width: 8,
            value: word(actual.data, actual.data_address, address),
        }
    };
    let read = match offset {
        0 => {
            let r = input_read(ReadKind::Count, before.rdi.checked_add(16).unwrap());
            assert_eq!(after.rcx, r.value);
            Some(r)
        }
        4 => {
            assert_eq!(after.rax, 0);
            None
        }
        6 => {
            assert_eq!(after.rdx, 0);
            None
        }
        8 => {
            assert_eq!(before.rdx % 64, 0);
            assert!(before.rdx <= 960);
            let address = before
                .rdi
                .checked_add(before.rdx)
                .unwrap()
                .checked_add(8)
                .unwrap();
            let r = input_read(ReadKind::Payload, address);
            assert_eq!(after.r8, r.value, "actual payload destination");
            Some(r)
        }
        13 => {
            assert_eq!(after.rax, before.rax.wrapping_add(before.r8));
            None
        }
        16 => {
            assert_eq!(before.rdx % 64, 0);
            assert!(before.rdx <= 960);
            let r = input_read(ReadKind::Link, before.rdi.checked_add(before.rdx).unwrap());
            assert_eq!(after.rdx, r.value, "link uses old RDX for its address");
            Some(r)
        }
        20 => {
            assert!((1..=64).contains(&before.rcx));
            assert_eq!(after.rcx, before.rcx - 1);
            assert_eq!(
                after.eflags & (1 << 6) != 0,
                after.rcx == 0,
                "DEC's actual ZF"
            );
            None
        }
        23 => {
            assert!(before.rcx < 64);
            let taken = before.eflags & (1 << 6) == 0;
            assert_eq!(taken, before.rcx != 0, "JNZ consumes DEC's ZF");
            assert_eq!(predicted.branch_taken, Some(taken));
            None
        }
        25 => {
            assert_eq!(after.rdx, 0x9e37_79b9_7f4a_7c15);
            None
        }
        35 => {
            assert_eq!(after.rax, before.rax ^ before.rdx);
            None
        }
        38 => {
            assert_eq!(before.rsp % 8, 0, "aligned actual RET operand");
            let r = Read {
                kind: ReadKind::ReturnWord,
                address: before.rsp,
                width: 8,
                value: word(actual.stack, actual.stack_address, before.rsp),
            };
            assert_eq!(after.rip, r.value);
            assert_eq!(after.rsp, before.rsp.checked_add(8).unwrap());
            Some(r)
        }
        _ => panic!("nonliteral cache instruction head"),
    };
    if offset != 23 {
        assert_eq!(predicted.branch_taken, None);
    }
    assert_eq!(
        read, predicted.read,
        "full actual operand kind/address/width/value"
    );
    read
}

fn check_result(
    actual: &OriginalStep<'_>,
    entry: u64,
    return_word: u64,
    expected: &truth::Truth,
    scalar: u64,
) {
    assert_eq!(actual.before.rip, entry + 38);
    assert_eq!(
        (actual.after.rip, actual.after.rsp, actual.after.rax),
        (return_word, expected.resumed_rsp, expected.value)
    );
    assert_eq!(actual.after.rax, scalar);
}

/// Both normal reaps precede this borrowed observation. No runtime artifact is
/// reread, and neither the planner nor the candidate supplies expected work.
pub fn inspect(case: truth::Case, seed: u64, observed: OriginalObservation<'_>) -> Stats {
    let code = bytes_at(
        observed.source,
        observed.source_address,
        observed.entry,
        truth::BYTES.len(),
    );
    truth::check_bytes(code).unwrap();
    let input = truth::input(case, seed);
    assert_eq!(observed.input, &input[..]);
    assert_eq!(observed.input_address % 64, 0);
    let steps: Vec<_> = observed.steps().collect();
    let starts: Vec<_> = steps
        .iter()
        .enumerate()
        .filter_map(|(i, s)| (s.before.rip == observed.entry).then_some(i))
        .collect();
    assert_eq!(starts.len(), 1, "one actual cache entry");
    let first = &steps[starts[0]];
    assert_eq!(
        (first.before.rdi, first.before.rsi),
        (observed.input_address, truth::INPUT_BYTES as u64)
    );
    let return_word = word(first.stack, first.stack_address, first.before.rsp);
    assert_eq!(return_word, observed.continuation);
    let expected = truth::interpret(
        code,
        &input,
        observed.entry,
        observed.input_address,
        first.before.rsp,
        return_word,
    )
    .unwrap();
    let end = starts[0].checked_add(expected.steps.len()).unwrap();
    let body = &steps[starts[0]..end];
    check_shape(body, &expected.steps, observed.entry);
    // Fixed Legacy gate has eight instructions before target entry and two
    // steps after target RET; the outer C3 is a final snapshot, then really run.
    assert_eq!(starts[0], 8);
    assert_eq!(steps.len(), body.len() + 10);
    assert_eq!(steps[end].before.rip, observed.continuation);
    let mut reads = Vec::new();
    let (mut conditional, mut taken) = (0, 0);
    for (actual, predicted) in body.iter().zip(&expected.steps) {
        assert_eq!(
            bytes_at(
                actual.data,
                actual.data_address,
                observed.input_address,
                input.len()
            ),
            &input[..]
        );
        if let Some(read) = check_step(actual, predicted, observed.entry, observed.input_address) {
            reads.push(read);
        }
        if let Some(branch) = predicted.branch_taken {
            conditional += 1;
            taken += usize::from(branch);
        }
    }
    let last = body.last().unwrap();
    check_result(
        last,
        observed.entry,
        return_word,
        &expected,
        truth::scalar(case, seed),
    );
    assert_eq!(
        reads,
        truth::expected_reads(
            case,
            seed,
            observed.input_address,
            first.before.rsp,
            return_word
        )
        .unwrap()
    );
    let counts = truth::Counts {
        instructions: body.len(),
        conditional,
        taken,
        input_reads: reads
            .iter()
            .filter(|r| r.kind != truth::ReadKind::ReturnWord)
            .count(),
        return_reads: reads
            .iter()
            .filter(|r| r.kind == truth::ReadKind::ReturnWord)
            .count(),
    };
    assert_eq!(counts, truth::counts(case));
    let model = model::check(case, observed.input_address, first.before.rsp, &reads).unwrap();
    assert_eq!(model.accesses, counts.input_reads + counts.return_reads);
    assert_eq!(model.hit_by_read.len(), reads.len());
    Stats { counts, model }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ENTRY: u64 = 0x2000;
    const DATA: u64 = 0x1080;
    const RSP: u64 = 0x8000;
    const RETURN: u64 = 0x9000;
    fn registers(pc: u64) -> libc::user_regs_struct {
        // Pure metadata fixture; no native process or fabricated gate receipt.
        let mut r: libc::user_regs_struct = unsafe { core::mem::zeroed() };
        r.rip = pc;
        r.rdi = DATA;
        r.rsi = truth::INPUT_BYTES as u64;
        r.rsp = RSP;
        r
    }
    fn refusal(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    #[test]
    fn cache_actual_qword_reads_require_address_width_and_all_bytes() {
        let input = truth::input(truth::Case::Reuse4, 7);
        let stack = RETURN.to_le_bytes();
        let mut a = OriginalStep {
            before: registers(ENTRY + 8),
            after: registers(ENTRY + 13),
            data_address: DATA,
            data: &input,
            stack_address: RSP,
            stack: &stack,
        };
        a.before.rdx = 64;
        a.after.r8 = word(&input, DATA, DATA + 72);
        let p = truth::Step {
            pc: ENTRY + 8,
            next_pc: ENTRY + 13,
            branch_taken: None,
            read: Some(truth::Read {
                kind: truth::ReadKind::Payload,
                address: DATA + 72,
                width: 8,
                value: a.after.r8,
            }),
        };
        check_step(&a, &p, ENTRY, DATA);
        let good = a.after.r8;
        a.after.r8 ^= 1 << 63;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
        a.after.r8 = good;
        let mut corrupt = input;
        corrupt[79] ^= 0x80;
        a.data = &corrupt;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
        a.data = &input;
        a.before.rdx = 128;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
        a.before.rdx = 64;
        let mut q = p;
        q.read.as_mut().unwrap().width = 1;
        refusal(|| {
            check_step(&a, &q, ENTRY, DATA);
        });
        a.before.rip = ENTRY + 16;
        a.after.rip = ENTRY + 20;
        a.after.rdx = 128;
        let p = truth::Step {
            pc: ENTRY + 16,
            next_pc: ENTRY + 20,
            branch_taken: None,
            read: Some(truth::Read {
                kind: truth::ReadKind::Link,
                address: DATA + 64,
                width: 8,
                value: 128,
            }),
        };
        check_step(&a, &p, ENTRY, DATA);
        a.before.rdx = a.after.rdx;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
    }
    #[test]
    fn cache_actual_dec_jnz_requires_counter_zf_and_successor() {
        let input = truth::input(truth::Case::Cold16, 7);
        let stack = RETURN.to_le_bytes();
        let mut a = OriginalStep {
            before: registers(ENTRY + 20),
            after: registers(ENTRY + 23),
            data_address: DATA,
            data: &input,
            stack_address: RSP,
            stack: &stack,
        };
        a.before.rcx = 2;
        a.after.rcx = 1;
        let p = truth::Step {
            pc: ENTRY + 20,
            next_pc: ENTRY + 23,
            branch_taken: None,
            read: None,
        };
        check_step(&a, &p, ENTRY, DATA);
        a.after.rcx = 0;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
        a.after.rcx = 1;
        a.after.eflags = 1 << 6;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
        a.before.rip = ENTRY + 23;
        a.after.rip = ENTRY + 8;
        a.before.rcx = 1;
        let p = truth::Step {
            pc: ENTRY + 23,
            next_pc: ENTRY + 8,
            branch_taken: Some(true),
            read: None,
        };
        check_step(&a, &p, ENTRY, DATA);
        a.before.eflags = 1 << 6;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
        a.before.eflags = 0;
        a.after.rip = ENTRY + 25;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
    }
    #[test]
    fn cache_actual_ret_requires_full_word_and_physical_successor() {
        let input = truth::input(truth::Case::Cold16, 7);
        let stack = RETURN.to_le_bytes();
        let mut a = OriginalStep {
            before: registers(ENTRY + 38),
            after: registers(RETURN),
            data_address: DATA,
            data: &input,
            stack_address: RSP,
            stack: &stack,
        };
        a.after.rsp = RSP + 8;
        let p = truth::Step {
            pc: ENTRY + 38,
            next_pc: RETURN,
            branch_taken: None,
            read: Some(truth::Read {
                kind: truth::ReadKind::ReturnWord,
                address: RSP,
                width: 8,
                value: RETURN,
            }),
        };
        check_step(&a, &p, ENTRY, DATA);
        let expected = truth::Truth {
            steps: Vec::new(),
            value: 42,
            resumed_rsp: RSP + 8,
        };
        a.after.rax = 42;
        check_result(&a, ENTRY, RETURN, &expected, 42);
        a.after.rax = 43;
        refusal(|| check_result(&a, ENTRY, RETURN, &expected, 42));
        a.after.rax = 42;
        refusal(|| check_result(&a, ENTRY, RETURN, &expected, 43));
        let bad = (RETURN ^ (1 << 56)).to_le_bytes();
        a.stack = &bad;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
        a.stack = &stack;
        a.after.rsp += 8;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
        a.after.rsp -= 8;
        a.after.rip += 1;
        refusal(|| {
            check_step(&a, &p, ENTRY, DATA);
        });
    }
    #[test]
    fn cache_complete_visit_sequence_refuses_omission_insertion_and_reorder() {
        let input = truth::input(truth::Case::Cold16, 7);
        let stack = RETURN.to_le_bytes();
        let expected = truth::interpret(&truth::BYTES, &input, ENTRY, DATA, RSP, RETURN).unwrap();
        let mut offsets = vec![0_u64, 4, 6];
        for _ in 0..16 {
            offsets.extend([8, 13, 16, 20, 23]);
        }
        offsets.extend([25, 35, 38]);
        assert_eq!(offsets.len(), 86);
        let mut actual: Vec<_> = offsets
            .iter()
            .enumerate()
            .map(|(i, &p)| OriginalStep {
                before: registers(ENTRY + p),
                after: registers(offsets.get(i + 1).map_or(RETURN, |&n| ENTRY + n)),
                data_address: DATA,
                data: &input,
                stack_address: RSP,
                stack: &stack,
            })
            .collect();
        check_shape(&actual, &expected.steps, ENTRY);
        refusal(|| check_shape(&actual[..actual.len() - 1], &expected.steps, ENTRY));
        actual.swap(3, 4);
        refusal(|| check_shape(&actual, &expected.steps, ENTRY));
        actual.swap(3, 4);
        actual[3].after.rip += 1;
        refusal(|| check_shape(&actual, &expected.steps, ENTRY));
        actual[3].after.rip -= 1;
        actual.push(OriginalStep {
            before: registers(ENTRY + 38),
            after: registers(RETURN),
            data_address: DATA,
            data: &input,
            stack_address: RSP,
            stack: &stack,
        });
        refusal(|| check_shape(&actual, &expected.steps, ENTRY));
    }
}
