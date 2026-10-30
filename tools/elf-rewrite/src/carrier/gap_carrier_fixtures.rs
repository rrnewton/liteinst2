//! Added layout capability; all earlier append-profile controls remain intact.
use super::*;

fn gap(
    original: &[u8],
    address: u64,
    payload: &[u8],
    images: &[RxImage],
    bounds: ImagePolicy,
) -> Result<CarrierOutput, Error> {
    append_exec_carrier_with_interleaved_loads(
        &parse(original),
        ImageRequest {
            carrier_vaddr: ElfVaddr(address),
            payload,
            images,
            source_dependencies: &[dependency()],
        },
        &[edit(original)],
        bounds,
    )
}

#[test]
fn gap_carrier_preserves_complete_headers_pages_and_images() {
    for interpreter in [false, true] {
        for existing_phdr in [false, true] {
            let mut original = interleaved_fixture(interpreter);
            if !existing_phdr {
                put32(&mut original, 64, 0);
            }
            let saved = original.clone();
            let images = interleaved_images();
            for address in [0x8000, 0x20000, 0x402000, 0x404000, 0x405000, 0x409000] {
                let output = gap(
                    &original,
                    address,
                    b"metadata",
                    &images,
                    interleaved_policy(),
                )
                .unwrap();
                assert_eq!(original, saved);
                assert_interleaved_preservation(&original, &output, &images);
                assert_eq!(output.program_table_vaddr, ElfVaddr(address));
                assert_eq!(output.new_load_pages, 4);
                assert_eq!(output.bytes().len(), 0x6009);
            }
        }
    }
}

#[test]
fn gap_carrier_rejects_original_file_bss_and_partial_page_overlap() {
    let original = interleaved_fixture(true);
    let images = interleaved_images();
    gap(
        &original,
        0x405000,
        b"metadata",
        &images,
        interleaved_policy(),
    )
    .unwrap();
    for address in [0x400000, 0x401000, 0x406000, 0x407000] {
        assert_eq!(
            gap(
                &original,
                address,
                b"metadata",
                &images,
                interleaved_policy()
            )
            .unwrap_err(),
            Error::CarrierPlacement
        );
    }
    assert_eq!(
        gap(
            &original,
            0x405000,
            &[0; 4096],
            &images,
            interleaved_policy()
        )
        .unwrap_err(),
        Error::CarrierPlacement
    );
    // The file ends inside the first RW page; the whole BSS tail still owns it.
    let mut partial = original.clone();
    put64(&mut partial, 64 + 4 * 56 + 40, 0x1001);
    assert_eq!(
        gap(
            &partial,
            0x407000,
            b"metadata",
            &images,
            interleaved_policy()
        )
        .unwrap_err(),
        Error::CarrierPlacement
    );
}

#[test]
fn gap_carrier_rejects_declared_metadata_and_new_image_aliases() {
    for kind in [4, 0x70000042] {
        let mut original = interleaved_fixture(true);
        encode_phdr(
            &mut original,
            64 + 6 * 56,
            EncodedHeader {
                kind,
                flags: 4,
                offset: 0x600,
                vaddr: 0x402800,
                file_size: 16,
                memory_size: 16,
                alignment: 8,
            },
        )
        .unwrap();
        assert_eq!(
            gap(
                &original,
                0x402000,
                b"metadata",
                &interleaved_images(),
                interleaved_policy()
            )
            .unwrap_err(),
            Error::CarrierMetadataOverlap { index: 6 }
        );
    }
    let original = interleaved_fixture(true);
    assert_eq!(
        gap(
            &original,
            0x403000,
            b"metadata",
            &interleaved_images(),
            interleaved_policy()
        )
        .unwrap_err(),
        Error::InvalidImage { index: 2 }
    );
}

#[test]
fn gap_carrier_union_span_includes_highest_original_load() {
    let original = interleaved_fixture(true);
    let images = [RxImage {
        entry: ElfVaddr(0x402003),
        bytes: vec![0xc3],
    }];
    let required = 0x408000 - 0x10000;
    let exact = ImagePolicy {
        layout: CarrierPolicy {
            max_virtual_span: required,
            ..interleaved_policy().layout
        },
        ..interleaved_policy()
    };
    let output = gap(&original, 0x10000, b"metadata", &images, exact).unwrap();
    assert_interleaved_preservation(&original, &output, &images);
    let smaller = ImagePolicy {
        layout: CarrierPolicy {
            max_virtual_span: required - 1,
            ..exact.layout
        },
        ..exact
    };
    assert_eq!(
        gap(&original, 0x10000, b"metadata", &images, smaller).unwrap_err(),
        Error::Budget {
            resource: "virtual span",
            required,
            limit: required - 1
        }
    );
}

#[test]
fn gap_carrier_resource_and_address_bounds_remain_exact() {
    let original = interleaved_fixture(true);
    let images = interleaved_images();
    let bounds = ImagePolicy {
        layout: CarrierPolicy {
            max_program_headers: 11,
            max_added_file_bytes: 0x3009,
            max_output_file_bytes: 0x6009,
            max_virtual_span: 0x40d000 - 0x10000,
            ..interleaved_policy().layout
        },
        max_images: 3,
        max_new_load_pages: 4,
        ..interleaved_policy()
    };
    let output = gap(&original, 0x402000, b"metadata", &images, bounds).unwrap();
    assert_eq!(
        (
            output.bytes().len(),
            output.new_load_pages,
            output.program_table.len()
        ),
        (0x6009, 4, 11 * 56)
    );
    for (resource, required, limit, small) in [
        (
            "images",
            3,
            2,
            ImagePolicy {
                max_images: 2,
                ..bounds
            },
        ),
        (
            "new load pages",
            4,
            3,
            ImagePolicy {
                max_new_load_pages: 3,
                ..bounds
            },
        ),
        (
            "program headers",
            11,
            10,
            ImagePolicy {
                layout: CarrierPolicy {
                    max_program_headers: 10,
                    ..bounds.layout
                },
                ..bounds
            },
        ),
        (
            "added file bytes",
            0x3009,
            0x3008,
            ImagePolicy {
                layout: CarrierPolicy {
                    max_added_file_bytes: 0x3008,
                    ..bounds.layout
                },
                ..bounds
            },
        ),
        (
            "output file bytes",
            0x6009,
            0x6008,
            ImagePolicy {
                layout: CarrierPolicy {
                    max_output_file_bytes: 0x6008,
                    ..bounds.layout
                },
                ..bounds
            },
        ),
    ] {
        assert_eq!(
            gap(&original, 0x402000, b"metadata", &images, small).unwrap_err(),
            Error::Budget {
                resource,
                required,
                limit
            }
        );
    }
    assert_eq!(
        gap(&original, 0x402001, b"metadata", &images, bounds).unwrap_err(),
        Error::CarrierPlacement
    );
    assert_eq!(
        gap(
            &original,
            bounds.layout.user_address_limit,
            b"metadata",
            &images,
            bounds
        )
        .unwrap_err(),
        Error::AddressLimit { index: None }
    );
    assert!(matches!(
        gap(&original, u64::MAX - 4095, b"metadata", &images, bounds),
        Err(Error::Arithmetic { .. })
    ));
}

#[test]
fn gap_carrier_is_explicit_exec_only_and_legacy_refusals_remain() {
    let original = interleaved_fixture(true);
    let images = interleaved_images();
    gap(
        &original,
        0x402000,
        b"metadata",
        &images,
        interleaved_policy(),
    )
    .unwrap();
    for writer in [
        append_carrier_with_images,
        append_exec_carrier_with_interleaved_images,
    ] {
        assert_eq!(
            writer(
                &parse(&original),
                ImageRequest {
                    carrier_vaddr: ElfVaddr(0x402000),
                    payload: b"metadata",
                    images: &images,
                    source_dependencies: &[dependency()],
                },
                &[edit(&original)],
                interleaved_policy()
            )
            .unwrap_err(),
            Error::CarrierPlacement
        );
    }
    let mut dynamic = original;
    put16(&mut dynamic, 16, 3);
    assert_eq!(
        gap(
            &dynamic,
            0x402000,
            b"metadata",
            &images,
            interleaved_policy()
        )
        .unwrap_err(),
        Error::UnsupportedObjectType
    );
}

#[test]
fn gap_carrier_above_originals_is_byte_identical_to_interleaved_images() {
    let original = interleaved_fixture(true);
    let images = interleaved_images();
    let old = interleaved_append(&original, &images, interleaved_policy()).unwrap();
    let new = gap(
        &original,
        0x40a000,
        b"metadata",
        &images,
        interleaved_policy(),
    )
    .unwrap();
    assert_eq!(new.bytes(), old.bytes());
    assert_eq!(new.changes(), old.changes());
    assert_eq!(new.images, old.images);
    assert_eq!(new.original_to_output_header, old.original_to_output_header);
    assert_eq!(
        (
            new.program_table,
            new.program_table_vaddr,
            new.payload,
            new.phdr_index,
            new.carrier_index,
            new.new_load_pages
        ),
        (
            old.program_table,
            old.program_table_vaddr,
            old.payload,
            old.phdr_index,
            old.carrier_index,
            old.new_load_pages
        )
    );
}

#[test]
fn gap_carrier_zero_file_bss_empty_load_ties_and_original_high_span() {
    let images = interleaved_images();
    let mut original = interleaved_fixture(true);
    // Preserve the dynamic record between the original RW LOAD and this added
    // original BSS-only LOAD. It owns pages despite owning no file bytes.
    encode_phdr(
        &mut original,
        64 + 6 * 56,
        EncodedHeader {
            kind: 1,
            flags: 6,
            offset: 0x3000,
            vaddr: 0x409000,
            file_size: 0,
            memory_size: 0x1001,
            alignment: 4096,
        },
    )
    .unwrap();
    let output = gap(
        &original,
        0x402000,
        b"metadata",
        &images,
        interleaved_policy(),
    )
    .unwrap();
    assert_interleaved_preservation(&original, &output, &images);
    for address in [0x409000, 0x40a000] {
        assert_eq!(
            gap(
                &original,
                address,
                b"metadata",
                &images,
                interleaved_policy()
            )
            .unwrap_err(),
            Error::CarrierPlacement
        );
    }
    // A truly empty LOAD reserves its original order, but no mapped pages.
    put64(&mut original, 64 + 6 * 56 + 40, 0);
    let output = gap(
        &original,
        0x409000,
        b"metadata",
        &images,
        interleaved_policy(),
    )
    .unwrap();
    assert_interleaved_preservation(&original, &output, &images);
    assert!(output.original_to_output_header[6] < output.carrier_index);
    let original = interleaved_fixture(true);
    let images = [RxImage {
        entry: ElfVaddr(0x10005),
        bytes: vec![0xc3],
    }];
    let exact = ImagePolicy {
        layout: CarrierPolicy {
            max_virtual_span: 0x3f8000,
            ..interleaved_policy().layout
        },
        ..interleaved_policy()
    };
    let output = gap(&original, 0x404000, b"metadata", &images, exact).unwrap();
    assert_interleaved_preservation(&original, &output, &images);
    let smaller = ImagePolicy {
        layout: CarrierPolicy {
            max_virtual_span: 0x3f7fff,
            ..exact.layout
        },
        ..exact
    };
    assert_eq!(
        gap(&original, 0x404000, b"metadata", &images, smaller).unwrap_err(),
        Error::Budget {
            resource: "virtual span",
            required: 0x3f8000,
            limit: 0x3f7fff
        }
    );
}

#[test]
fn gap_carrier_retains_rx_metadata_mutual_overlap_and_target_policy_guards() {
    let mut original = interleaved_fixture(true);
    let mut images = interleaved_images();
    let bounds = interleaved_policy();
    gap(&original, 0x402000, b"metadata", &images, bounds).unwrap();
    images.push(images[0].clone());
    assert_eq!(
        gap(&original, 0x402000, b"metadata", &images, bounds).unwrap_err(),
        Error::InvalidImage { index: 3 }
    );
    images.pop();
    let invalid = ImagePolicy {
        layout: CarrierPolicy {
            page_size: 3,
            ..bounds.layout
        },
        ..bounds
    };
    assert_eq!(
        gap(&original, 0x402000, b"metadata", &images, invalid).unwrap_err(),
        Error::InvalidTargetPolicy
    );
    let limited = ImagePolicy {
        layout: CarrierPolicy {
            user_address_limit: 0x407000,
            ..bounds.layout
        },
        ..bounds
    };
    assert_eq!(
        gap(&original, 0x402000, b"metadata", &images, limited).unwrap_err(),
        Error::AddressLimit { index: Some(4) }
    );
    encode_phdr(
        &mut original,
        64 + 6 * 56,
        EncodedHeader {
            kind: 4,
            flags: 4,
            offset: 0x600,
            vaddr: 0x10080,
            file_size: 16,
            memory_size: 16,
            alignment: 8,
        },
    )
    .unwrap();
    assert_eq!(
        gap(&original, 0x402000, b"metadata", &images, bounds).unwrap_err(),
        Error::CarrierMetadataOverlap { index: 6 }
    );
}
