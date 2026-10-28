//! Exact37 ORIGINAL body checks shared by gated and ordinary C caller routes.
//! No gate, certificate or generated map supplies the independent expectations.
use crate::{exact_truth as truth, oracle};
use oracle::native_ordinary::OriginalStep;
use std::collections::BTreeSet;
fn bytes_at(bytes: &[u8], base: u64, address: u64, count: usize) -> &[u8] {
    let offset = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
    &bytes[offset..offset.checked_add(count).unwrap()]
}
pub(crate) fn source(code: &[u8], entry: u64, heads: &[u64], returns: &[u64]) {
    truth::check_bytes(code).unwrap();
    assert_eq!(
        heads,
        truth::HEADS.map(|p| entry.checked_add(u64::from(p)).unwrap())
    );
    assert_eq!(returns, [entry.checked_add(36).unwrap()]);
}
pub(crate) fn check(
    code: &[u8],
    input: &[u8],
    entry: u64,
    input_address: u64,
    continuation: u64,
    body: &[OriginalStep<'_>],
) -> (usize, usize, usize, usize) {
    truth::check_bytes(code).unwrap();
    let first = body.first().expect("nonempty exact body");
    assert_eq!(
        (first.before.rdi, first.before.rsi),
        (input_address, input.len() as u64)
    );
    let captured = bytes_at(
        first.data,
        first.data_address,
        first.before.rdi,
        input.len(),
    );
    assert_eq!(captured, input);
    let return_word = u64::from_le_bytes(
        bytes_at(first.stack, first.stack_address, first.before.rsp, 8)
            .try_into()
            .unwrap(),
    );
    assert_eq!(return_word, continuation);
    let expected = truth::interpret(
        code,
        input,
        entry,
        first.before.rdi,
        first.before.rsp,
        return_word,
    )
    .unwrap();
    assert_eq!(
        body.len(),
        expected.steps.len(),
        "complete body, no omitted or extra step"
    );
    assert_eq!(
        body.iter()
            .map(|s| s.before.rip - entry)
            .collect::<BTreeSet<_>>(),
        truth::HEADS
            .iter()
            .map(|&p| u64::from(p))
            .collect::<BTreeSet<_>>()
    );
    let (mut conditional, mut taken, mut reads) = (0, 0, 0);
    for (actual, predicted) in body.iter().zip(&expected.steps) {
        assert_eq!(
            (actual.before.rip, actual.after.rip),
            (predicted.pc, predicted.next_pc)
        );
        assert_eq!(
            bytes_at(actual.data, actual.data_address, input_address, input.len()),
            input
        );
        if let Some(branch) = predicted.branch_taken {
            conditional += 1;
            let actual_taken = actual.before.eflags & 1 != 0; // Fixed JB consumes CMP's CF.
            assert_eq!(actual_taken, branch);
            taken += usize::from(actual_taken);
        }
        if let Some(read) = predicted.read {
            reads += 1;
            match read.kind {
                truth::ReadKind::InputByte => {
                    assert_eq!((read.address, read.width), (actual.before.rdi, 1));
                    assert_eq!(
                        read.value,
                        u64::from(
                            bytes_at(actual.data, actual.data_address, actual.before.rdi, 1)[0]
                        )
                    );
                    assert_eq!(actual.after.rcx, read.value); // MOVZX really consumed that byte.
                }
                truth::ReadKind::ReturnWord => {
                    assert_eq!((read.address, read.width), (actual.before.rsp, 8));
                    assert_eq!(
                        read.value,
                        u64::from_le_bytes(
                            bytes_at(actual.stack, actual.stack_address, actual.before.rsp, 8)
                                .try_into()
                                .unwrap()
                        )
                    );
                    assert_eq!(actual.after.rip, read.value);
                    assert_eq!(actual.after.rsp, actual.before.rsp.checked_add(8).unwrap());
                }
            }
        }
    }
    let last = body.last().unwrap();
    assert_eq!(last.before.rip, entry + 36);
    assert_eq!(
        (last.after.rip, last.after.rsp, last.after.rax),
        (return_word, expected.resumed_rsp, expected.value)
    );
    assert_eq!(last.after.rax, truth::checksum(input).unwrap());
    let counts = (body.len(), conditional, taken, reads);
    assert_eq!(counts, truth::counts(input.len()).unwrap());
    counts
}

#[cfg(test)]
#[path = "exact_body/tests.rs"]
mod tests;
