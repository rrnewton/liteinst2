use super::*;
const ENTRY: u64 = 0x1000;
const DATA: u64 = 0x2000;
const STACK: u64 = 0x3000;
fn rejects(f: impl FnOnce() + std::panic::UnwindSafe) {
    assert!(std::panic::catch_unwind(f).is_err());
}
// Synthetic metadata for pure predicate controls, never native state credit.
fn fixture<'a>(input: &'a [u8], stack: &'a [u8]) -> Vec<OriginalStep<'a>> {
    let return_word = u64::from_le_bytes(stack.try_into().unwrap());
    let t = truth::interpret(&truth::BYTES, input, ENTRY, DATA, STACK, return_word).unwrap();
    let mut cursor = DATA;
    t.steps
        .iter()
        .map(|p| {
            let mut before: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            before.rip = p.pc;
            before.rsp = STACK;
            before.rdi = cursor;
            before.rsi = input.len() as u64;
            if let Some(taken) = p.branch_taken {
                before.eflags = u64::from(taken);
            }
            let mut after = before;
            after.rip = p.next_pc;
            if p.pc == ENTRY + 15 {
                cursor += 1;
                after.rdi = cursor;
            }
            if let Some(read) = p.read {
                match read.kind {
                    truth::ReadKind::InputByte => after.rcx = read.value,
                    truth::ReadKind::ReturnWord => {
                        after.rsp = STACK + 8;
                        after.rax = t.value;
                    }
                }
            }
            OriginalStep {
                before,
                after,
                data_address: DATA,
                data: input,
                stack_address: STACK,
                stack,
            }
        })
        .collect()
}
fn checked(input: &[u8], stack: &[u8], body: &[OriginalStep<'_>]) -> (usize, usize, usize, usize) {
    check(
        &truth::BYTES,
        input,
        ENTRY,
        DATA,
        u64::from_le_bytes(stack.try_into().unwrap()),
        body,
    )
}
#[test]
fn exact_normal_source_requires_all_bytes_heads_and_ret36() {
    let heads = truth::HEADS.map(|p| ENTRY + u64::from(p));
    source(&truth::BYTES, ENTRY, &heads, &[ENTRY + 36]);
    for index in 0..truth::BYTES.len() {
        let mut bad = truth::BYTES;
        bad[index] ^= 1;
        rejects(|| source(&bad, ENTRY, &heads, &[ENTRY + 36]));
    }
    rejects(|| source(&truth::BYTES[..36], ENTRY, &heads, &[ENTRY + 36]));
    let mut long = truth::BYTES.to_vec();
    long.extend_from_slice(&[0; 4]);
    rejects(|| source(&long, ENTRY, &heads, &[ENTRY + 36]));
    for index in 0..heads.len() {
        let mut bad = heads;
        bad[index] += 1;
        rejects(|| source(&truth::BYTES, ENTRY, &bad, &[ENTRY + 36]));
    }
    rejects(|| source(&truth::BYTES, ENTRY, &heads[..10], &[ENTRY + 36]));
    for returns in [
        vec![],
        vec![ENTRY + 34],
        vec![ENTRY + 40],
        vec![ENTRY + 36, ENTRY + 36],
    ] {
        rejects(|| source(&truth::BYTES, ENTRY, &heads, &returns));
    }
}
#[test]
fn exact_normal_body_accepts_two_real_continuation_shapes_and_closed_lengths() {
    for seed_index in 0..2 {
        for length in [1, 64] {
            let input: Vec<_> = (0..length)
                .map(|j| ((37 * j + 11 + seed_index) % 256) as u8)
                .collect();
            for return_word in [0x401e_u64, 0x4030] {
                let stack = return_word.to_le_bytes();
                let body = fixture(&input, &stack);
                assert_eq!(
                    checked(&input, &stack, &body),
                    if length == 1 {
                        (11, 1, 0, 2)
                    } else {
                        (389, 64, 63, 65)
                    }
                );
            }
        }
    }
}
#[test]
fn exact_normal_body_mutations_refuse_without_omitted_suffix_or_read() {
    let input: Vec<_> = (0..64).map(|j| ((37 * j + 11) % 256) as u8).collect();
    let stack = 0x401e_u64.to_le_bytes();
    let body = fixture(&input, &stack);
    assert_eq!(checked(&input, &stack, &body), (389, 64, 63, 65));
    for mutation in 0..12 {
        let mut bad = fixture(&input, &stack);
        let load = bad.iter().position(|s| s.before.rip == ENTRY + 6).unwrap();
        let branch = bad.iter().position(|s| s.before.rip == ENTRY + 21).unwrap();
        let last = bad.len() - 1;
        match mutation {
            0 => bad[load].before.rip += 1,
            1 => bad[branch].after.rip += 1,
            2 => bad[branch].before.eflags ^= 1,
            3 => bad[load].before.rdi += 1,
            4 => bad[load].after.rcx ^= 1,
            5 => bad[last].before.rsp += 1,
            6 => bad[last].after.rip += 1,
            7 => bad[last].after.rsp += 8,
            8 => bad[last].after.rax ^= 1,
            9 => {
                bad.remove(load);
            }
            10 => {
                let duplicate = fixture(&input, &stack).remove(load);
                bad.insert(load, duplicate);
            }
            11 => bad[0].before.rsi -= 1,
            _ => unreachable!(),
        }
        rejects(|| {
            checked(&input, &stack, &bad);
        });
    }
    let mut wrong_input = input.clone();
    wrong_input[0] ^= 1;
    rejects(|| {
        checked(&wrong_input, &stack, &body);
    });
    let wrong_word = 0x4030_u64.to_le_bytes();
    rejects(|| {
        checked(&input, &wrong_word, &body);
    });
    rejects(|| {
        checked(&input, &stack, &body[..body.len() - 1]);
    });
    // Operand width comes from the exact instruction bytes, not a reported width.
    let mut wider = truth::BYTES;
    wider[6] = 0x48;
    rejects(|| {
        check(&wider, &input, ENTRY, DATA, 0x401e, &body);
    });
}
