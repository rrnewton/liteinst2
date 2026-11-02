//! Exact full-value publisher shared by the qualification observer and controls.
use crate::oracle::native_ordinary::normal_caller::module::early_entry::{JOURNAL, WITNESS_WORDS};

// The witness is always the complete 128-word header and 512-word journal.
const _: () = assert!(JOURNAL == 128 && WITNESS_WORDS == 640);

#[inline]
pub(super) fn publish_words<const N: usize>(destination: &mut [u64; N], source: &[u64; N]) {
    const { assert!(N == 128 || N == 512) };
    // SAFETY: these valid array references cover disjoint source/destination
    // ranges. N is 128 or 512, so N*8 is divisible by 256. At each offset
    // 0,256,...,N*8-256, the four ordered 64-byte groups access 16 bytes at
    // offset+0,16,...,240, all in bounds. MOVDQU needs no 16-byte alignment,
    // and SSE2 is baseline on this x86-64 oracle. All memory and flags effects
    // remain compiler-visible; every modified register is an explicit output.
    unsafe {
        std::arch::asm!(
            "2:",
            "movdqu xmm0, xmmword ptr [{source} + {offset}]",
            "movdqu xmm1, xmmword ptr [{source} + {offset} + 16]",
            "movdqu xmm2, xmmword ptr [{source} + {offset} + 32]",
            "movdqu xmm3, xmmword ptr [{source} + {offset} + 48]",
            "movdqu xmmword ptr [{destination} + {offset}], xmm0",
            "movdqu xmmword ptr [{destination} + {offset} + 16], xmm1",
            "movdqu xmmword ptr [{destination} + {offset} + 32], xmm2",
            "movdqu xmmword ptr [{destination} + {offset} + 48], xmm3",
            "movdqu xmm0, xmmword ptr [{source} + {offset} + 64]",
            "movdqu xmm1, xmmword ptr [{source} + {offset} + 80]",
            "movdqu xmm2, xmmword ptr [{source} + {offset} + 96]",
            "movdqu xmm3, xmmword ptr [{source} + {offset} + 112]",
            "movdqu xmmword ptr [{destination} + {offset} + 64], xmm0",
            "movdqu xmmword ptr [{destination} + {offset} + 80], xmm1",
            "movdqu xmmword ptr [{destination} + {offset} + 96], xmm2",
            "movdqu xmmword ptr [{destination} + {offset} + 112], xmm3",
            "movdqu xmm0, xmmword ptr [{source} + {offset} + 128]",
            "movdqu xmm1, xmmword ptr [{source} + {offset} + 144]",
            "movdqu xmm2, xmmword ptr [{source} + {offset} + 160]",
            "movdqu xmm3, xmmword ptr [{source} + {offset} + 176]",
            "movdqu xmmword ptr [{destination} + {offset} + 128], xmm0",
            "movdqu xmmword ptr [{destination} + {offset} + 144], xmm1",
            "movdqu xmmword ptr [{destination} + {offset} + 160], xmm2",
            "movdqu xmmword ptr [{destination} + {offset} + 176], xmm3",
            "movdqu xmm0, xmmword ptr [{source} + {offset} + 192]",
            "movdqu xmm1, xmmword ptr [{source} + {offset} + 208]",
            "movdqu xmm2, xmmword ptr [{source} + {offset} + 224]",
            "movdqu xmm3, xmmword ptr [{source} + {offset} + 240]",
            "movdqu xmmword ptr [{destination} + {offset} + 192], xmm0",
            "movdqu xmmword ptr [{destination} + {offset} + 208], xmm1",
            "movdqu xmmword ptr [{destination} + {offset} + 224], xmm2",
            "movdqu xmmword ptr [{destination} + {offset} + 240], xmm3",
            "add {offset}, 256",
            "cmp {offset}, {bytes}",
            "jne 2b",
            source = in(reg) source.as_ptr(),
            destination = in(reg) destination.as_mut_ptr(),
            offset = inout(reg) 0usize => _,
            bytes = in(reg) N * std::mem::size_of::<u64>(),
            out("xmm0") _,
            out("xmm1") _,
            out("xmm2") _,
            out("xmm3") _,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(16))]
    struct Aligned<const N: usize>([u64; N]);

    fn guarded<const N: usize>() -> Aligned<N> {
        Aligned(std::array::from_fn(|i| 0xcafe_0000_0000_0000 | i as u64))
    }

    fn values() -> [u64; WITNESS_WORDS] {
        std::array::from_fn(|i| {
            0x0123_4567_89ab_cdef ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        })
    }

    fn guards_unchanged<const N: usize>(actual: &Aligned<N>, before: &[u64; N], start: usize) {
        assert_eq!(&actual.0[..start], &before[..start]);
        assert_eq!(
            &actual.0[start + WITNESS_WORDS..],
            &before[start + WITNESS_WORDS..],
        );
    }

    fn publish_complete(
        destination: &mut [u64; WITNESS_WORDS],
        header: &[u64; JOURNAL],
        journal: &[u64; WITNESS_WORDS - JOURNAL],
    ) {
        let (header_out, journal_out) = destination.split_at_mut(JOURNAL);
        publish_words(header_out.try_into().unwrap(), header);
        publish_words(journal_out.try_into().unwrap(), journal);
    }

    #[test]
    fn full_value_publisher_covers_all640_and_preserves_partition_and_bounds() {
        let expected = values();
        let header: [u64; JOURNAL] = expected[..JOURNAL].try_into().unwrap();
        let journal: [u64; WITNESS_WORDS - JOURNAL] = expected[JOURNAL..].try_into().unwrap();
        let header_before = header;
        let journal_before = journal;
        let mut destination = guarded::<644>();
        let before = destination.0;
        let start = 2;

        // Publish only the header first: even the adjacent journal must remain
        // at its original nonzero values until its own exact-range call.
        publish_words(
            (&mut destination.0[start..start + JOURNAL])
                .try_into()
                .unwrap(),
            &header,
        );
        assert_eq!(&destination.0[start..start + JOURNAL], header.as_slice());
        assert_eq!(
            &destination.0[start + JOURNAL..start + WITNESS_WORDS],
            &before[start + JOURNAL..start + WITNESS_WORDS],
        );
        guards_unchanged(&destination, &before, start);
        assert_eq!(header, header_before);
        assert_eq!(journal, journal_before);

        publish_words(
            (&mut destination.0[start + JOURNAL..start + WITNESS_WORDS])
                .try_into()
                .unwrap(),
            &journal,
        );
        assert_eq!(
            &destination.0[start..start + WITNESS_WORDS],
            expected.as_slice(),
        );
        guards_unchanged(&destination, &before, start);
        assert_eq!(header, header_before);
        assert_eq!(journal, journal_before);
    }

    #[test]
    fn full_value_publisher_propagates_every_single_cell_change_and_zero_reset() {
        let baseline = values();
        let mut destination = guarded::<644>();
        let before = destination.0;
        let start = 3;
        // Reuse the witness, so each iteration must also overwrite the previous
        // mutation. Every header/journal cell, including the last tail cell,
        // is independently changed without weakening the full-array comparison.
        for changed in 0..WITNESS_WORDS {
            let mut input = baseline;
            input[changed] ^= u64::MAX;
            let source_before = input;
            assert_ne!(input[changed], baseline[changed]);
            publish_complete(
                (&mut destination.0[start..start + WITNESS_WORDS])
                    .try_into()
                    .unwrap(),
                input[..JOURNAL].try_into().unwrap(),
                input[JOURNAL..].try_into().unwrap(),
            );
            assert_eq!(
                &destination.0[start..start + WITNESS_WORDS],
                input.as_slice(),
                "single changed cell {changed}",
            );
            guards_unchanged(&destination, &before, start);
            assert_eq!(input, source_before);
        }

        destination.0[start..start + WITNESS_WORDS].fill(u64::MAX);
        let zero = [0_u64; WITNESS_WORDS];
        publish_complete(
            (&mut destination.0[start..start + WITNESS_WORDS])
                .try_into()
                .unwrap(),
            zero[..JOURNAL].try_into().unwrap(),
            zero[JOURNAL..].try_into().unwrap(),
        );
        assert_eq!(
            &destination.0[start..start + WITNESS_WORDS],
            zero.as_slice(),
        );
        guards_unchanged(&destination, &before, start);
        assert_eq!(zero, [0; WITNESS_WORDS]);
    }

    #[test]
    fn full_value_publisher_handles_eight_and_sixteen_byte_alignment_with_canaries() {
        let expected = values();
        // The aligned base plus two/three words makes actual addresses 0/8
        // modulo 16. Cover all eight independent source/destination choices.
        for header_start in [2, 3] {
            for journal_start in [2, 3] {
                for destination_start in [2, 3] {
                    let mut header = guarded::<132>();
                    let mut journal = guarded::<516>();
                    let mut destination = guarded::<644>();
                    header.0[header_start..header_start + JOURNAL]
                        .copy_from_slice(&expected[..JOURNAL]);
                    journal.0[journal_start..journal_start + WITNESS_WORDS - JOURNAL]
                        .copy_from_slice(&expected[JOURNAL..]);
                    let header_before = header.0;
                    let journal_before = journal.0;
                    let destination_before = destination.0;
                    let header_in: &[u64; JOURNAL] = header.0[header_start..header_start + JOURNAL]
                        .try_into()
                        .unwrap();
                    let journal_in: &[u64; WITNESS_WORDS - JOURNAL] = journal.0
                        [journal_start..journal_start + WITNESS_WORDS - JOURNAL]
                        .try_into()
                        .unwrap();
                    let destination_out: &mut [u64; WITNESS_WORDS] = (&mut destination.0
                        [destination_start..destination_start + WITNESS_WORDS])
                        .try_into()
                        .unwrap();
                    assert_eq!(header_in.as_ptr() as usize % 16, 8 * (header_start % 2));
                    assert_eq!(journal_in.as_ptr() as usize % 16, 8 * (journal_start % 2));
                    assert_eq!(
                        destination_out.as_ptr() as usize % 16,
                        8 * (destination_start % 2),
                    );
                    publish_complete(destination_out, header_in, journal_in);
                    assert_eq!(
                        &destination.0[destination_start..destination_start + WITNESS_WORDS],
                        expected.as_slice(),
                    );
                    guards_unchanged(&destination, &destination_before, destination_start);
                    assert_eq!(header.0, header_before);
                    assert_eq!(journal.0, journal_before);
                }
            }
        }
    }
}
