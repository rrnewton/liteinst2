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

// This capability belongs to the one preparation passed to the child setup.
// Callers cannot select an ISA or supply a declared saved-state layout.
pub(super) struct Publisher {
    avx2: bool,
}

impl Publisher {
    #[cfg_attr(test, allow(dead_code))] // Calibration tests use actual emitted images below.
    pub(super) fn for_preparation(
        preparation: &rapid_profiler::frontend_native::EarlyEntryModuleSitePreparation,
    ) -> Self {
        Self::for_images(preparation.plan().images())
    }

    fn for_images(images: &[liteinst2::trampoline::TrampolineImage]) -> Self {
        use liteinst2::trampoline::SavedExtendedStateLayout;

        // std's detector includes OS support for XMM/YMM state. Equality also
        // binds every actual emitted image to this worker's current full save
        // layout, including enabled AVX-512 components. No vacuous empty proof.
        let avx2 = std::is_x86_feature_detected!("avx2")
            && !images.is_empty()
            && SavedExtendedStateLayout::detect().is_ok_and(|current| {
                covers_ymm(current)
                    && images.iter().all(|image| {
                        let layout = image.layout();
                        layout.instrumentation_len > 0
                            && layout.restore_len > 0
                            && layout.saved_extended_state == current
                    })
            });
        Self { avx2 }
    }

    #[inline]
    pub(super) fn publish_words<const N: usize>(
        &self,
        destination: &mut [u64; N],
        source: &[u64; N],
    ) {
        const { assert!(N == 128 || N == 512) };
        if self.avx2 {
            // SAFETY: the only production constructor authenticated CPU/OS AVX2
            // and all actual images of this immutable preparation. The child
            // publishes that same preparation before installing this observer;
            // its no-signal/no-reentry contract and save layout remain in force.
            unsafe { publish_words_avx2(destination, source) }
        } else {
            publish_words(destination, source);
        }
    }
}

fn covers_ymm(layout: liteinst2::trampoline::SavedExtendedStateLayout) -> bool {
    use liteinst2::trampoline::SavedExtendedStateFormat;

    // The full upper halves of all16 YMM registers must be saved, not only the
    // four explicit asm outputs: LLVM may emit vzeroupper at the ISA boundary.
    layout.format() == SavedExtendedStateFormat::XSAVE64_STANDARD
        && layout.mask() & 0b111 == 0b111
        && layout.components().iter().any(|component| {
            component.xfeature() == 1 << 2
                && component.size() == 256
                && component.offset() >= 576
                && component
                    .offset()
                    .checked_add(256)
                    .is_some_and(|end| end <= layout.image_len() && end <= layout.len())
        })
}

#[target_feature(enable = "avx2")]
unsafe fn publish_words_avx2<const N: usize>(destination: &mut [u64; N], source: &[u64; N]) {
    const { assert!(N == 128 || N == 512) };
    // SAFETY: valid disjoint arrays cover all N*8 bytes (1024 or4096), each a
    // positive multiple of256. Each iteration touches exactly offsets0..255,
    // in two ordered128-byte groups, then advances256. VMOVDQU accepts their
    // ordinary8-byte alignment. Caller proves AVX2/OS state. All memory and
    // flags effects remain visible, and every modified register is declared.
    // No manual vzeroupper with an incomplete clobber set is hidden here.
    unsafe {
        std::arch::asm!(
            "2:",
            "vmovdqu ymm0, ymmword ptr [{source} + {offset}]",
            "vmovdqu ymm1, ymmword ptr [{source} + {offset} + 32]",
            "vmovdqu ymm2, ymmword ptr [{source} + {offset} + 64]",
            "vmovdqu ymm3, ymmword ptr [{source} + {offset} + 96]",
            "vmovdqu ymmword ptr [{destination} + {offset}], ymm0",
            "vmovdqu ymmword ptr [{destination} + {offset} + 32], ymm1",
            "vmovdqu ymmword ptr [{destination} + {offset} + 64], ymm2",
            "vmovdqu ymmword ptr [{destination} + {offset} + 96], ymm3",
            "vmovdqu ymm0, ymmword ptr [{source} + {offset} + 128]",
            "vmovdqu ymm1, ymmword ptr [{source} + {offset} + 160]",
            "vmovdqu ymm2, ymmword ptr [{source} + {offset} + 192]",
            "vmovdqu ymm3, ymmword ptr [{source} + {offset} + 224]",
            "vmovdqu ymmword ptr [{destination} + {offset} + 128], ymm0",
            "vmovdqu ymmword ptr [{destination} + {offset} + 160], ymm1",
            "vmovdqu ymmword ptr [{destination} + {offset} + 192], ymm2",
            "vmovdqu ymmword ptr [{destination} + {offset} + 224], ymm3",
            "add {offset}, 256",
            "cmp {offset}, {bytes}",
            "jne 2b",
            source = in(reg) source.as_ptr(),
            destination = in(reg) destination.as_mut_ptr(),
            offset = inout(reg) 0usize => _,
            bytes = in(reg) N * std::mem::size_of::<u64>(),
            out("ymm0") _,
            out("ymm1") _,
            out("ymm2") _,
            out("ymm3") _,
        );
    }
}

#[cfg(test)]
mod avx2_tests {
    use super::*;
    use liteinst2::scanner::InstructionScanner;
    use liteinst2::trampoline::{
        HookContext, SavedExtendedStateLayout, TrampolineImage, TrampolinePlan,
    };

    unsafe extern "C" fn unused_hook(_: *mut HookContext) {}

    fn images() -> [TrampolineImage; 2] {
        let scan = InstructionScanner::default()
            .scan(&[0x90; 5], 0x1000)
            .unwrap();
        let plan = TrampolinePlan::from_scan(&scan, 0x1000, unused_hook).unwrap();
        // Real emission computes the layout used by its save/restore bytes.
        // These bytes are never mapped or called by either control.
        [plan.emit_at(0x2000).unwrap(), plan.emit_at(0x4000).unwrap()]
    }

    #[test]
    fn avx2_selection_requires_every_actual_image_and_complete_ymm_state() {
        let images = images();
        let current = SavedExtendedStateLayout::detect().unwrap();
        for image in &images {
            assert_eq!(image.layout().saved_extended_state, current);
        }
        let selected = Publisher::for_images(&images);
        assert_eq!(selected.avx2, std::is_x86_feature_detected!("avx2"));
        if selected.avx2 {
            assert_eq!(current.mask() & 7, 7);
            let upper = current
                .components()
                .iter()
                .find(|component| component.xfeature() == 4)
                .unwrap();
            assert_eq!(upper.size(), 256);
            assert!(upper.offset() >= 576);
            assert!(upper.offset() + upper.size() <= current.image_len());
            assert!(current.image_len() <= current.len());
        }
        assert!(!Publisher::for_images(&[]).avx2);

        let scan = InstructionScanner::default()
            .scan(&[0x90; 5], 0x1000)
            .unwrap();
        let no_hook = TrampolinePlan::from_instruction(&scan, 0x1000)
            .unwrap()
            .emit_at(0x6000)
            .unwrap();
        // Even callback-free images carry a detected layout descriptor. They
        // have no save/restore sequence and cannot serve as hook evidence.
        assert_eq!(no_hook.layout().instrumentation_len, 0);
        assert_eq!(no_hook.layout().restore_len, 0);
        for index in 0..images.len() {
            let mut mixed = images.clone();
            mixed[index] = no_hook.clone();
            assert!(!Publisher::for_images(&mixed).avx2, "missing image{index}");
        }

        assert!(!covers_ymm(SavedExtendedStateLayout::UNAVAILABLE));
        assert!(!covers_ymm(
            SavedExtendedStateLayout::describe_target_fxsave64(),
        ));
        let short = SavedExtendedStateLayout::describe_target_xsave64(7, &[(4, 576, 128)]).unwrap();
        assert!(!covers_ymm(short));
        let absent = SavedExtendedStateLayout::describe_target_xsave64(3, &[]).unwrap();
        assert!(!covers_ymm(absent));
        // Declared metadata above only challenges the coverage predicate; it
        // cannot construct the positive production capability.
    }

    #[repr(align(32))]
    struct Aligned<const N: usize>([u64; N]);

    fn guarded<const N: usize>() -> Aligned<N> {
        Aligned(std::array::from_fn(|i| 0xcafe_0000_0000_0000 | i as u64))
    }

    fn complete(
        publisher: &Publisher,
        destination: &mut [u64; WITNESS_WORDS],
        input: &[u64; WITNESS_WORDS],
    ) {
        let (header, journal) = destination.split_at_mut(JOURNAL);
        publisher.publish_words::<JOURNAL>(
            header.try_into().unwrap(),
            input[..JOURNAL].try_into().unwrap(),
        );
        publisher.publish_words::<{ WITNESS_WORDS - JOURNAL }>(
            journal.try_into().unwrap(),
            input[JOURNAL..].try_into().unwrap(),
        );
    }

    #[test]
    fn selected_publisher_preserves_all640_cells_resets_partition_and_alignment() {
        let images = images();
        let selected = Publisher::for_images(&images);
        let fallback = Publisher::for_images(&[]);
        assert!(!fallback.avx2);
        if selected.avx2 {
            eprintln!("AVX2 publisher helper coverage: actual emitted-image selection");
        } else {
            eprintln!(
                "AVX2 publisher helper coverage: UNOBSERVED; complete SSE2 fallback exercised"
            );
        }
        let values: [u64; WITNESS_WORDS] = std::array::from_fn(|i| {
            0x0123_4567_89ab_cdef ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        });
        for publisher in [&fallback, &selected] {
            let mut destination = guarded::<648>();
            let guards = destination.0;
            let start = 5;
            for changed in 0..WITNESS_WORDS {
                let mut input = values;
                input[changed] ^= u64::MAX;
                assert_ne!(input[changed], values[changed]);
                let source_before = input;
                complete(
                    publisher,
                    (&mut destination.0[start..start + WITNESS_WORDS])
                        .try_into()
                        .unwrap(),
                    &input,
                );
                assert_eq!(
                    &destination.0[start..start + WITNESS_WORDS],
                    input.as_slice(),
                    "cell{changed}",
                );
                assert_eq!(&destination.0[..start], &guards[..start]);
                assert_eq!(
                    &destination.0[start + WITNESS_WORDS..],
                    &guards[start + WITNESS_WORDS..],
                );
                assert_eq!(input, source_before);
            }
            destination.0[start..start + WITNESS_WORDS].fill(u64::MAX);
            let zero = [0; WITNESS_WORDS];
            complete(
                publisher,
                (&mut destination.0[start..start + WITNESS_WORDS])
                    .try_into()
                    .unwrap(),
                &zero,
            );
            assert_eq!(
                &destination.0[start..start + WITNESS_WORDS],
                zero.as_slice()
            );
            assert_eq!(&destination.0[..start], &guards[..start]);
            assert_eq!(
                &destination.0[start + WITNESS_WORDS..],
                &guards[start + WITNESS_WORDS..],
            );
            assert_eq!(zero, [0; WITNESS_WORDS]);

            // All64 independent combinations of actual0/8/16/24 mod32 addresses.
            for header_start in 4..8 {
                for journal_start in 4..8 {
                    for out_start in 4..8 {
                        let mut header = guarded::<136>();
                        let mut journal = guarded::<520>();
                        let mut output = guarded::<648>();
                        header.0[header_start..header_start + JOURNAL]
                            .copy_from_slice(&values[..JOURNAL]);
                        journal.0[journal_start..journal_start + WITNESS_WORDS - JOURNAL]
                            .copy_from_slice(&values[JOURNAL..]);
                        let header_before = header.0;
                        let journal_before = journal.0;
                        let output_before = output.0;
                        let header_in: &[u64; JOURNAL] = header.0
                            [header_start..header_start + JOURNAL]
                            .try_into()
                            .unwrap();
                        let journal_in: &[u64; WITNESS_WORDS - JOURNAL] = journal.0
                            [journal_start..journal_start + WITNESS_WORDS - JOURNAL]
                            .try_into()
                            .unwrap();
                        assert_eq!(header_in.as_ptr() as usize % 32, (header_start % 4) * 8,);
                        assert_eq!(journal_in.as_ptr() as usize % 32, (journal_start % 4) * 8,);
                        assert_eq!(
                            output.0[out_start..].as_ptr() as usize % 32,
                            (out_start % 4) * 8,
                        );
                        publisher.publish_words(
                            (&mut output.0[out_start..out_start + JOURNAL])
                                .try_into()
                                .unwrap(),
                            header_in,
                        );
                        assert_eq!(
                            &output.0[out_start..out_start + JOURNAL],
                            header_in.as_slice()
                        );
                        assert_eq!(
                            &output.0[out_start + JOURNAL..],
                            &output_before[out_start + JOURNAL..],
                        );
                        assert_eq!(&output.0[..out_start], &output_before[..out_start]);
                        publisher.publish_words(
                            (&mut output.0[out_start + JOURNAL..out_start + WITNESS_WORDS])
                                .try_into()
                                .unwrap(),
                            journal_in,
                        );
                        assert_eq!(
                            &output.0[out_start..out_start + WITNESS_WORDS],
                            values.as_slice(),
                        );
                        assert_eq!(&output.0[..out_start], &output_before[..out_start]);
                        assert_eq!(
                            &output.0[out_start + WITNESS_WORDS..],
                            &output_before[out_start + WITNESS_WORDS..],
                        );
                        assert_eq!(header.0, header_before);
                        assert_eq!(journal.0, journal_before);
                    }
                }
            }
        }
    }
}
