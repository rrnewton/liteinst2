use super::*;

pub fn original_shape(elf: &Elf64<'_>) -> Result<()> {
    let h = elf.header();
    let ph = elf.program_headers();
    require(
        h.object_type == ObjectType::Executable
            && h.entry.0 == 0x401000
            && h.program_offset.0 == 64
            && h.program_entry_size == 56
            && h.program_count == 6,
        "fixed original ELF header",
    )?;
    require(
        ph.iter().map(|p| p.raw_type).collect::<Vec<_>>() == [6, 1, 1, 1, 4, 0x6474e551],
        "fixed original PHDR roster",
    )?;
    for (p, (flags, address, size)) in elf.segments(SegmentType::Load).zip([
        (4, 0x400000, 4096),
        (5, 0x401000, 12288),
        (6, 0x404000, 335872),
    ]) {
        require(
            p.flags.0 == flags
                && p.vaddr.0 == address
                && p.physical_address == address
                && p.file_size == size
                && p.memory_size == size
                && p.alignment == 4096,
            "complete original LOAD ownership",
        )?;
    }
    checked(elf.check_load_page_congruence(4096))
}
fn payload(metadata: &[u8], plan: &[u8]) -> Vec<u8> {
    let mut out = b"LI2TOOL-CANDIDATE-UNREADY-V1\0".to_vec();
    out.extend_from_slice(&ContentId::of(metadata).0);
    out.extend_from_slice(&ContentId::of(plan).0);
    out
}
#[derive(Clone, Debug)]
struct Added {
    address: u64,
    offset: u64,
    size: u64,
    flags: u32,
    image: Option<usize>,
}
#[derive(Debug)]
struct Layout {
    table: FileRange,
    payload: FileRange,
    images: Vec<carrier::ImagePlacement>,
    changes: Vec<carrier::Change>,
    pages: u64,
    carrier: usize,
    original_indices: Vec<usize>,
}

/// This proof consumes no CarrierOutput. A writer agreeing with corrupt bytes
/// cannot bypass it; all new table fields, payload/image bytes and zero gaps are
/// covered, and every original byte is preserved except exact joined edits.
fn direct(
    original: &[u8],
    joined: &ledger::Joined,
    payload: &[u8],
    candidate: &[u8],
) -> Result<Layout> {
    require(
        original.len() <= TEXT
            && candidate.len() <= OUTPUT
            && candidate.len() >= original.len()
            && candidate.len() - original.len() <= TEXT
            && !joined.images.is_empty()
            && joined.images.len() <= 32,
        "whole file/image caps",
    )?;
    let old = checked(Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: 128,
        },
    ))?;
    original_shape(&old)?;
    let output = checked(Elf64::parse(
        candidate,
        ParseLimits {
            max_program_headers: 128,
        },
    ))?;
    checked(output.check_load_page_congruence(4096))?;
    let count = old.program_headers().len() + joined.images.len() + 1;
    let c = page(original.len() as u64)?;
    let table = checked(FileRange::checked(FileOffset(c), count as u64 * 56))?;
    let payload_start = add(table.end().0, 7)? & !7;
    let payload_range = checked(FileRange::checked(
        FileOffset(payload_start),
        payload.len() as u64,
    ))?;
    let mut cursor = payload_range.end().0;
    let mut added = vec![Added {
        address: 0x480000,
        offset: c,
        size: cursor - c,
        flags: 4,
        image: None,
    }];
    let mut placements = Vec::new();
    for (id, image) in joined.images.iter().enumerate() {
        require(
            !image.bytes.is_empty() && image.bytes.len() <= 131072,
            "nonempty bounded image",
        )?;
        let base = image.entry.0 & !4095;
        let prefix = image.entry.0 - base;
        let file = add(page(cursor)?, prefix)?;
        let range = checked(FileRange::checked(
            FileOffset(file),
            image.bytes.len() as u64,
        ))?;
        added.push(Added {
            address: base,
            offset: file - prefix,
            size: add(prefix, image.bytes.len() as u64)?,
            flags: 5,
            image: Some(id),
        });
        placements.push(carrier::ImagePlacement {
            entry: image.entry,
            file: range,
            program_header: usize::MAX,
        });
        cursor = range.end().0;
    }
    require(
        cursor == candidate.len() as u64 && count <= 128,
        "exact complete appended length/table count",
    )?;
    let mut expected_header = old.header().clone();
    expected_header.program_offset = FileOffset(c);
    expected_header.program_count = checked(u16::try_from(count))?;
    require(
        output.header() == &expected_header,
        "all ELF header fields including entry and opaque section fields",
    )?;
    added.sort_by_key(|x| x.address);
    let mut order: Vec<(bool, usize)> = Vec::new();
    let mut next = 0;
    for p in old.program_headers() {
        if p.kind == SegmentType::Load {
            while next < added.len() && added[next].address < p.vaddr.0 {
                order.push((false, next));
                next += 1;
            }
        }
        order.push((true, p.index));
    }
    while next < added.len() {
        order.push((false, next));
        next += 1;
    }
    require(order.len() == count, "complete header order")?;
    let mut carrier_index = None;
    let mut original_indices = vec![usize::MAX; 6];
    for (index, (is_old, source)) in order.into_iter().enumerate() {
        let p = &output.program_headers()[index];
        if is_old && source != 0 {
            original_indices[source] = index;
            require(
                slice(candidate, add(c, index as u64 * 56)?, 56)?
                    == slice(original, add(64, source as u64 * 56)?, 56)?,
                "every original non-PHDR record unchanged and ordered",
            )?;
        } else {
            let (kind, flags, offset, address, size, align) = if is_old {
                original_indices[0] = index;
                (6, 4, c, 0x480000, table.len(), 8)
            } else {
                let a = &added[source];
                if let Some(id) = a.image {
                    placements[id].program_header = index;
                } else {
                    require(carrier_index.replace(index).is_none(), "one carrier header")?;
                }
                (1, a.flags, a.offset, a.address, a.size, 4096)
            };
            require(
                (
                    p.raw_type,
                    p.flags.0,
                    p.offset.0,
                    p.vaddr.0,
                    p.physical_address,
                    p.file_size,
                    p.memory_size,
                    p.alignment,
                ) == (kind, flags, offset, address, address, size, size, align),
                "all new/redirected PHDR fields",
            )?;
        }
    }
    let carrier_index = carrier_index.ok_or("missing R carrier")?;
    require(
        original_indices[0]
            < output
                .segments(SegmentType::Load)
                .next()
                .ok_or("missing LOAD")?
                .index,
        "PHDR precedes LOAD",
    )?;
    let mut occupied = Vec::new();
    let mut pages = 0u64;
    for p in output.segments(SegmentType::Load) {
        let r = Range::new(p.vaddr.0 & !4095, page(add(p.vaddr.0, p.memory_size)?)?)?;
        require(
            r.end <= 1u64 << 47 && !occupied.iter().any(|old: &Range| old.overlaps(r)),
            "whole LOAD page occupancy/address limit",
        )?;
        occupied.push(r);
        if !original_indices.contains(&p.index) {
            pages = add(pages, r.len() / 4096)?;
        }
    }
    occupied.sort_unstable();
    require(
        pages <= 128 && occupied.last().ok_or("LOAD hull")?.end - occupied[0].start <= 2147483648,
        "full original/carrier/image hull and new page cap",
    )?;
    let mapping = checked(output.file_to_virtual(table.start(), table.len()))?;
    require(
        mapping.program_header == carrier_index
            && mapping.flags.0 == 4
            && mapping.virtual_range.start().0 == 0x480000,
        "unique R table mapping",
    )?;
    let reverse = checked(output.virtual_to_storage(ElfVaddr(0x480000), table.len()))?;
    require(
        reverse.program_header == carrier_index && reverse.storage == Storage::FileBacked(table),
        "carrier reverse ownership",
    )?;
    let mut covered = vec![false; candidate.len() - original.len()];
    let mut cover = |range: FileRange, expected: Option<&[u8]>| -> Result<()> {
        require(
            range.start().0 >= original.len() as u64 && range.end().0 <= candidate.len() as u64,
            "appended region bounds",
        )?;
        let start = host(range.start().0)? - original.len();
        let end = host(range.end().0)? - original.len();
        require(
            covered[start..end].iter().all(|v| !*v),
            "appended partitions cannot overlap",
        )?;
        covered[start..end].fill(true);
        if let Some(bytes) = expected {
            require(
                slice(candidate, range.start().0, range.len())? == bytes,
                "exact appended payload/image bytes",
            )?;
        }
        Ok(())
    };
    cover(table, None)?;
    cover(payload_range, Some(payload))?;
    for (image, p) in joined.images.iter().zip(&placements) {
        cover(p.file, Some(&image.bytes))?;
        let m = checked(output.file_to_virtual(p.file.start(), p.file.len()))?;
        require(
            m.program_header == p.program_header
                && m.flags.0 == 5
                && m.virtual_range.start() == image.entry,
            "unique RX image file mapping",
        )?;
        let inverse = checked(output.virtual_to_storage(image.entry, p.file.len()))?;
        require(
            inverse.program_header == p.program_header
                && inverse.flags.0 == 5
                && inverse.storage == Storage::FileBacked(p.file),
            "exact inverse image storage",
        )?;
    }
    for (at, is_covered) in covered.iter().enumerate() {
        if !is_covered {
            require(
                candidate[original.len() + at] == 0,
                "every alignment gap and image prefix is zero",
            )?;
        }
    }
    let mut changes = vec![
        carrier::Change {
            kind: carrier::ChangeKind::ProgramHeaderOffset,
            edit: carrier::DeclaredEdit {
                offset: FileOffset(32),
                expected: original[32..40].to_vec(),
                replacement: c.to_le_bytes().to_vec(),
            },
        },
        carrier::Change {
            kind: carrier::ChangeKind::ProgramHeaderCount,
            edit: carrier::DeclaredEdit {
                offset: FileOffset(56),
                expected: original[56..58].to_vec(),
                replacement: (count as u16).to_le_bytes().to_vec(),
            },
        },
    ];
    changes.extend(joined.edits.iter().cloned().map(|edit| carrier::Change {
        kind: carrier::ChangeKind::DeclaredSource,
        edit,
    }));
    changes.sort_by_key(|c| c.edit.offset);
    let mut preserved = original.to_vec();
    let mut end = 0;
    for change in &changes {
        let e = &change.edit;
        require(
            !e.expected.is_empty()
                && e.expected.len() == e.replacement.len()
                && e.offset.0 >= end
                && slice(original, e.offset.0, e.expected.len() as u64)? == e.expected,
            "exact nonoverlapping original changes",
        )?;
        end = add(e.offset.0, e.expected.len() as u64)?;
        preserved[host(e.offset.0)?..host(end)?].copy_from_slice(&e.replacement);
    }
    require(
        candidate[..original.len()] == preserved,
        "all original bytes including old PHDRs, headers, padding, notes, data, and tail",
    )?;
    Ok(Layout {
        table,
        payload: payload_range,
        images: placements,
        changes,
        pages,
        carrier: carrier_index,
        original_indices,
    })
}
fn extension(layout: &Layout, candidate: &[u8]) -> Vec<u8> {
    let mut text = format!(
        "CARRIER-EXTENSION\t1\ncandidate_sha256\t{}\nnew_load_pages\t{}\nphdr_file\t{}\t{}\nphdr_vaddr\t4718592\n",
        digest(candidate),
        layout.pages,
        layout.table.start().0,
        layout.table.len()
    );
    for (id, p) in layout.images.iter().enumerate() {
        writeln!(
            &mut text,
            "elf-image\t{id}\t{}\t{}\t{}\t{}",
            p.entry.0,
            p.file.start().0,
            p.file.len(),
            p.program_header
        )
        .unwrap();
    }
    for c in &layout.changes {
        writeln!(
            &mut text,
            "elf-change\t{:?}\t{}\t{}\t{}",
            c.kind,
            c.edit.offset.0,
            hex(&c.edit.expected),
            hex(&c.edit.replacement)
        )
        .unwrap();
    }
    text.into_bytes()
}
pub fn join(
    original: &[u8],
    facts: &Facts,
    joined: &ledger::Joined,
    metadata: &[u8],
    plan: &[u8],
    candidate: &[u8],
    ledger: &[u8],
) -> Result<()> {
    let payload = payload(metadata, plan);
    let layout = direct(original, joined, &payload, candidate)?;
    let mut expected_ledger = plan.to_vec();
    expected_ledger.extend_from_slice(&extension(&layout, candidate));
    require(
        ledger == expected_ledger,
        "complete independent carrier extension including exact plan prefix",
    )?;
    let elf = checked(Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: 128,
        },
    ))?;
    let l = facts.selection.limits;
    let reconstructed = checked(carrier::append_exec_carrier_with_interleaved_loads(
        &elf,
        carrier::ImageRequest {
            carrier_vaddr: ElfVaddr(facts.selection.carrier_pc),
            payload: &payload,
            images: &joined.images,
            source_dependencies: &joined.dependencies,
        },
        &joined.edits,
        carrier::ImagePolicy {
            layout: carrier::CarrierPolicy {
                page_size: 4096,
                user_address_limit: 1u64 << 47,
                max_added_file_bytes: l.added_file_bytes,
                max_output_file_bytes: l.output_bytes,
                max_program_headers: l.program_headers,
                max_virtual_span: l.virtual_span,
            },
            dynamic: Default::default(),
            max_images: l.images,
            max_new_load_pages: l.new_load_pages,
        },
    ))?;
    require(
        reconstructed.bytes() == candidate
            && reconstructed.program_table == layout.table
            && reconstructed.payload == layout.payload
            && reconstructed.images == layout.images
            && reconstructed.changes() == layout.changes
            && reconstructed.new_load_pages == layout.pages
            && reconstructed.carrier_index == layout.carrier
            && reconstructed.original_to_output_header == layout.original_indices
            && reconstructed.dynamic.writes.is_empty(),
        "checked carrier reconstruction agrees with every direct invariant",
    )
}

#[cfg(test)]
#[path = "candidate_tests.rs"]
mod tests;
