//! Structural layout controls only; no fixture is executed by these tests.
use super::*;

fn packed(
    original: &[u8],
    base: u64,
    images: &[RxImage],
    bounds: ImagePolicy,
) -> Result<CarrierOutput, Error> {
    append_carrier_with_linux_rx_runs(
        &parse(original),
        ImageRequest {
            carrier_vaddr: ElfVaddr(base + 0x6000),
            payload: b"metadata",
            images,
            source_dependencies: &[dependency()],
        },
        &[edit(original)],
        bounds,
    )
}

fn reverse_pair(base: u64) -> Vec<RxImage> {
    vec![
        RxImage {
            entry: ElfVaddr(base + 0x8005),
            bytes: vec![0xb8, 42, 0, 0, 0, 0xc3],
        },
        RxImage {
            entry: ElfVaddr(base + 0x7003),
            bytes: vec![0x90, 0xc3],
        },
    ]
}

fn inspect_packed(original: &[u8], output: &CarrierOutput, images: &[RxImage]) {
    let old = parse(original);
    let new = Elf64::parse(
        output.bytes(),
        ParseLimits {
            max_program_headers: 2910,
        },
    )
    .unwrap();
    let mut expected = original.to_vec();
    assert_eq!(output.changes().len(), 3);
    for change in output.changes() {
        let at = change.edit.offset.0 as usize;
        assert_eq!(
            &original[at..at + change.edit.expected.len()],
            change.edit.expected
        );
        expected[at..at + change.edit.replacement.len()].copy_from_slice(&change.edit.replacement);
    }
    assert_eq!(&output.bytes()[..original.len()], expected);
    assert_eq!(new.header().entry, old.header().entry);
    assert_eq!(new.header().object_type, old.header().object_type);
    assert_eq!(
        output.original_to_output_header.len(),
        old.program_headers().len()
    );
    assert!(
        output
            .original_to_output_header
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    for item in old.program_headers() {
        if item.kind != SegmentType::ProgramHeaders {
            let before = old.header().program_offset.0 as usize + item.index * 56;
            let after = output.program_table.start().0 as usize
                + output.original_to_output_header[item.index] * 56;
            assert_eq!(
                &original[before..before + 56],
                &output.bytes()[after..after + 56]
            );
        }
    }
    let first_load = new.segments(SegmentType::Load).next().unwrap().index;
    assert_eq!(new.segments(SegmentType::ProgramHeaders).count(), 1);
    assert!(output.phdr_index < first_load);
    assert!(
        new.segments(SegmentType::Interpreter)
            .all(|item| item.index < first_load)
    );
    let table = new
        .file_to_virtual(output.program_table.start(), output.program_table.len())
        .unwrap();
    assert_eq!(
        (
            table.program_header,
            table.virtual_range.start(),
            table.flags.0
        ),
        (output.carrier_index, output.program_table_vaddr, 4)
    );
    let phdr = &new.program_headers()[output.phdr_index];
    assert_eq!(
        (phdr.offset, phdr.vaddr, phdr.file_size, phdr.memory_size),
        (
            output.program_table.start(),
            output.program_table_vaddr,
            output.program_table.len(),
            output.program_table.len()
        )
    );
    assert_eq!(output.images.len(), images.len());
    let mut page_union = std::collections::BTreeSet::new();
    for (image, placement) in images.iter().zip(&output.images) {
        assert_eq!(placement.entry, image.entry);
        assert_eq!(placement.file.len(), image.bytes.len() as u64);
        assert_eq!(
            new.executable_bytes(image.entry, image.bytes.len() as u64)
                .unwrap(),
            image.bytes
        );
        let mapping = new
            .file_to_virtual(placement.file.start(), placement.file.len())
            .unwrap();
        assert_eq!(
            (
                mapping.program_header,
                mapping.virtual_range.start(),
                mapping.flags.0
            ),
            (placement.program_header, image.entry, 5)
        );
        let header = &new.program_headers()[placement.program_header];
        assert_eq!((header.flags.0, header.file_size), (5, header.memory_size));
        assert_eq!(
            (
                header.offset.0 % 4096,
                header.vaddr.0 % 4096,
                header.alignment
            ),
            (0, 0, 4096)
        );
        assert_eq!(
            placement.file.start().0 - header.offset.0,
            image.entry.0 - header.vaddr.0
        );
        let start = align_down(image.entry.0, 4096);
        let end = align_up(image.entry.0 + image.bytes.len() as u64, 4096).unwrap();
        for page in (start..end).step_by(4096) {
            assert!(page_union.insert(page));
        }
    }
    let carrier = &new.program_headers()[output.carrier_index];
    assert_eq!(carrier.flags.0, 4);
    for page in (carrier.vaddr.0..align_up(carrier.vaddr.0 + carrier.memory_size, 4096).unwrap())
        .step_by(4096)
    {
        assert!(page_union.insert(page));
    }
    assert_eq!(output.new_load_pages, page_union.len() as u64);
    // Only padding outside every image's exact file extent is zero. A later
    // member's prefix relative to its shared header contains earlier images.
    for header in new.segments(SegmentType::Load).filter(|h| {
        !output.original_to_output_header.contains(&h.index) && h.index != output.carrier_index
    }) {
        let mut members: Vec<_> = output
            .images
            .iter()
            .filter(|image| image.program_header == header.index)
            .collect();
        members.sort_by_key(|image| image.file.start());
        assert!(!members.is_empty());
        let mut cursor = header.offset.0;
        for image in members {
            assert!(cursor <= image.file.start().0);
            assert!(
                output.bytes()[cursor as usize..image.file.start().0 as usize]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            cursor = image.file.end().0;
        }
        assert!(cursor <= header.offset.0 + header.file_size);
        assert!(
            output.bytes()[cursor as usize..(header.offset.0 + header.file_size) as usize]
                .iter()
                .all(|byte| *byte == 0)
        );
    }
}

#[test]
fn rx_runs_repack_reverse_file_order_and_preserve_legacy_layout() {
    for (kind, base, interpreter) in [(2, 0x400000, true), (3, 0, true), (3, 0, false)] {
        let original = fixture(kind, base, interpreter, &[]);
        let images = reverse_pair(base);
        let legacy = append(
            &original,
            base,
            &images,
            &[edit(&original)],
            &[dependency()],
            policy(),
        )
        .unwrap();
        assert_eq!(
            legacy.images[0].file,
            FileRange::checked(FileOffset(0x4005), 6).unwrap()
        );
        assert_eq!(
            legacy.images[1].file,
            FileRange::checked(FileOffset(0x5003), 2).unwrap()
        );
        assert_ne!(
            legacy.images[0].program_header,
            legacy.images[1].program_header
        );
        assert_eq!(legacy.bytes().len(), 0x5005);
        let output = packed(&original, base, &images, policy()).unwrap();
        inspect_packed(&original, &output, &images);
        assert_eq!(
            output.images[0].file,
            FileRange::checked(FileOffset(0x5005), 6).unwrap()
        );
        assert_eq!(
            output.images[1].file,
            FileRange::checked(FileOffset(0x4003), 2).unwrap()
        );
        assert_eq!(
            output.images[0].program_header,
            output.images[1].program_header
        );
        assert_eq!(output.bytes().len(), 0x500b);
        assert_eq!(output.new_load_pages, legacy.new_load_pages);
        assert_eq!(output.program_table.len() + 56, legacy.program_table.len());
    }
}

#[test]
fn rx_runs_keep_full_page_veneer_envelope_and_partial_prefix_bytes() {
    let original = fixture(3, 0, true, &[]);
    // Opaque artifact storage: RET body, owned padding, then an E9 back to its
    // storage base. The carrier does not claim native instruction qualification.
    let mut envelope = vec![0xcc; 4096];
    envelope[0] = 0xc3;
    envelope[4091..].copy_from_slice(&[0xe9, 0, 0xf0, 0xff, 0xff]);
    let images = vec![
        RxImage {
            entry: ElfVaddr(0x8000),
            bytes: envelope,
        },
        RxImage {
            entry: ElfVaddr(0x7003),
            bytes: vec![0x90, 0xc3],
        },
    ];
    let output = packed(&original, 0, &images, policy()).unwrap();
    inspect_packed(&original, &output, &images);
    assert_eq!(
        output.images[0].program_header,
        output.images[1].program_header
    );
    assert_eq!(
        output.images[0].file,
        FileRange::checked(FileOffset(0x5000), 4096).unwrap()
    );
    assert_eq!(output.bytes().len(), 0x6000);
    let elf = parse(output.bytes());
    let load = &elf.program_headers()[output.images[0].program_header];
    assert_eq!(
        (load.vaddr.0, load.file_size, load.memory_size),
        (0x7000, 8192, 8192)
    );
    assert_eq!(
        elf.executable_bytes(ElfVaddr(0x8ffb), 5).unwrap(),
        &[0xe9, 0, 0xf0, 0xff, 0xff]
    );
    assert_eq!(&output.bytes()[0x4005..0x5000], vec![0; 4091]);
}

#[test]
fn rx_runs_never_bridge_carrier_or_unmapped_pages() {
    let original = fixture(3, 0, false, &[]);
    let images = vec![
        RxImage {
            entry: ElfVaddr(0x9003),
            bytes: vec![0x90; 4096],
        },
        RxImage {
            entry: ElfVaddr(0x7001),
            bytes: vec![0xc3],
        },
        RxImage {
            entry: ElfVaddr(0x5001),
            bytes: vec![0xc3],
        },
    ];
    let output = packed(&original, 0, &images, policy()).unwrap();
    inspect_packed(&original, &output, &images);
    let elf = parse(output.bytes());
    assert_eq!(output.new_load_pages, 5);
    assert_eq!(output.program_table.len(), (6 + 1 + 3) * 56);
    let indices: std::collections::BTreeSet<_> =
        output.images.iter().map(|i| i.program_header).collect();
    assert_eq!(indices.len(), 3);
    assert!(!indices.contains(&output.carrier_index));
    assert!(elf.executable_bytes(ElfVaddr(0x8000), 1).is_err());
    assert!(elf.executable_bytes(ElfVaddr(0x6000), 1).is_err());
    let multi = &elf.program_headers()[output.images[0].program_header];
    assert_eq!(
        (multi.vaddr.0, multi.file_size, multi.memory_size),
        (0x9000, 4099, 4099)
    );
}

#[test]
fn rx_runs_reject_empty_overlap_original_bss_and_invalid_geometry() {
    let original = fixture(3, 0, false, &[]);
    for address in [0x1000, 0x3000, 0x6000] {
        let images = [RxImage {
            entry: ElfVaddr(address),
            bytes: vec![0xc3],
        }];
        assert_eq!(
            packed(&original, 0, &images, policy()).unwrap_err(),
            Error::InvalidImage { index: 0 }
        );
    }
    let images = [RxImage {
        entry: ElfVaddr(0x7000),
        bytes: vec![],
    }];
    assert_eq!(
        packed(&original, 0, &images, policy()).unwrap_err(),
        Error::InvalidImage { index: 0 }
    );
    let images = [
        RxImage {
            entry: ElfVaddr(0x7000),
            bytes: vec![0x90],
        },
        RxImage {
            entry: ElfVaddr(0x7008),
            bytes: vec![0xc3],
        },
    ];
    assert_eq!(
        packed(&original, 0, &images, policy()).unwrap_err(),
        Error::InvalidImage { index: 1 }
    );
    let images = [RxImage {
        entry: ElfVaddr(u64::MAX),
        bytes: vec![0x90, 0xc3],
    }];
    assert_eq!(
        packed(&original, 0, &images, policy()).unwrap_err(),
        Error::Arithmetic {
            operation: "image virtual extent"
        }
    );
    let images = [RxImage {
        entry: ElfVaddr(1 << 47),
        bytes: vec![0xc3],
    }];
    assert_eq!(
        packed(&original, 0, &images, policy()).unwrap_err(),
        Error::AddressLimit { index: None }
    );
    let mut bounds = policy();
    bounds.layout.page_size = 8192;
    assert_eq!(
        packed(&original, 0, &reverse_pair(0), bounds).unwrap_err(),
        Error::InvalidTargetPolicy
    );
}

#[test]
fn rx_runs_keep_image_page_file_header_and_span_budgets() {
    let original = fixture(3, 0, false, &[]);
    let images = reverse_pair(0);
    let output = packed(&original, 0, &images, policy()).unwrap();
    assert_eq!(
        (
            output.images.len(),
            output.new_load_pages,
            output.program_table.len(),
            output.bytes().len()
        ),
        (2, 3, 448, 0x500b)
    );
    let mut bounds = policy();
    bounds.max_images = 1;
    assert_eq!(
        packed(&original, 0, &images, bounds).unwrap_err(),
        Error::Budget {
            resource: "images",
            required: 2,
            limit: 1
        }
    );
    let mut bounds = policy();
    bounds.max_new_load_pages = 2;
    assert_eq!(
        packed(&original, 0, &images, bounds).unwrap_err(),
        Error::Budget {
            resource: "new load pages",
            required: 3,
            limit: 2
        }
    );
    let mut bounds = policy();
    bounds.layout.max_program_headers = 7;
    assert_eq!(
        packed(&original, 0, &images, bounds).unwrap_err(),
        Error::Budget {
            resource: "program headers",
            required: 8,
            limit: 7
        }
    );
    let mut bounds = policy();
    bounds.layout.max_output_file_bytes = 0x500a;
    assert_eq!(
        packed(&original, 0, &images, bounds).unwrap_err(),
        Error::Budget {
            resource: "output file bytes",
            required: 0x500b,
            limit: 0x500a
        }
    );
    let mut bounds = policy();
    bounds.layout.max_added_file_bytes = 0x200a;
    assert_eq!(
        packed(&original, 0, &images, bounds).unwrap_err(),
        Error::Budget {
            resource: "added file bytes",
            required: 0x200b,
            limit: 0x200a
        }
    );
    let mut bounds = policy();
    bounds.layout.max_virtual_span = 0x8fff;
    assert_eq!(
        packed(&original, 0, &images, bounds).unwrap_err(),
        Error::Budget {
            resource: "virtual span",
            required: 0x9000,
            limit: 0x8fff
        }
    );
}

#[test]
fn rx_runs_retain_source_byte_and_dependency_refusals() {
    let original = fixture(3, 0, false, &[]);
    let images = reverse_pair(0);
    let elf = parse(&original);
    let request = || ImageRequest {
        carrier_vaddr: ElfVaddr(0x6000),
        payload: b"metadata",
        images: &images,
        source_dependencies: &[],
    };
    assert_eq!(
        append_carrier_with_linux_rx_runs(&elf, request(), &[edit(&original)], policy())
            .unwrap_err(),
        Error::MissingEditDependency { index: 0 }
    );
    let mut stale = edit(&original);
    stale.expected[0] ^= 1;
    assert_eq!(
        append_carrier_with_linux_rx_runs(
            &elf,
            ImageRequest {
                source_dependencies: &[dependency()],
                ..request()
            },
            &[stale],
            policy()
        )
        .unwrap_err(),
        Error::StaleEdit { index: 0 }
    );
}

fn complete_profile() -> ImagePolicy {
    ImagePolicy {
        layout: CarrierPolicy {
            page_size: 4096,
            user_address_limit: 1 << 47,
            max_added_file_bytes: 12026544,
            max_output_file_bytes: 12120064,
            max_program_headers: 2910,
            max_virtual_span: 2147483648,
        },
        dynamic: dynamic::Limits::default(),
        max_images: 2896,
        max_new_load_pages: 2936,
    }
}

#[test]
fn rx_runs_linux_header_boundary_is_opt_in_and_exact() {
    let original = fixture(3, 0, false, &[]);
    let images: Vec<_> = (0..1164)
        .map(|i| RxImage {
            entry: ElfVaddr(0x100000 + i * 8192),
            bytes: vec![0xc3],
        })
        .collect();
    let at_limit = packed(&original, 0, &images[..1163], complete_profile()).unwrap();
    let elf = Elf64::parse(
        at_limit.bytes(),
        ParseLimits {
            max_program_headers: 2910,
        },
    )
    .unwrap();
    assert_eq!(elf.header().program_count, 1170);
    assert_eq!(at_limit.program_table.len(), 65520);
    assert_eq!(at_limit.images.len(), 1163);
    assert_eq!(
        packed(&original, 0, &images, complete_profile()).unwrap_err(),
        Error::Budget {
            resource: "Linux ELF64 program headers",
            required: 1171,
            limit: 1170
        }
    );
    let legacy = append(
        &original,
        0,
        &images,
        &[edit(&original)],
        &[dependency()],
        complete_profile(),
    )
    .unwrap();
    let old = Elf64::parse(
        legacy.bytes(),
        ParseLimits {
            max_program_headers: 2910,
        },
    )
    .unwrap();
    assert_eq!(old.header().program_count, 1171);
    assert_eq!(legacy.images.len(), 1164);
}

#[test]
fn rx_runs_pack_more_than_kernel_header_count_without_losing_images() {
    let original = fixture(3, 0, false, &[]);
    let images: Vec<_> = (0..1172)
        .rev()
        .map(|i| RxImage {
            entry: ElfVaddr(0x100000 + i * 4096),
            bytes: vec![(i % 251) as u8],
        })
        .collect();
    let output = packed(&original, 0, &images, complete_profile()).unwrap();
    inspect_packed(&original, &output, &images);
    assert_eq!(output.images.len(), 1172);
    assert_eq!(output.program_table.len(), 448);
    assert_eq!(output.new_load_pages, 1173);
    assert!(
        output
            .images
            .iter()
            .all(|image| image.program_header == output.images[0].program_header)
    );
    let elf = parse(output.bytes());
    let load = &elf.program_headers()[output.images[0].program_header];
    assert_eq!(
        (load.vaddr.0, load.file_size, load.memory_size),
        (0x100000, 1171 * 4096 + 1, 1171 * 4096 + 1)
    );
}
