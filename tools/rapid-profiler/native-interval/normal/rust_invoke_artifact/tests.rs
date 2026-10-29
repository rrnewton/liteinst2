use super::*;

const CODE: &[u8] = &[
    0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0, 0x48,
    0x89, 0x03, 0x5b, 0xc3,
];
const SH: u64 = 0x1400;
fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn sh(b: &mut [u8], n: usize, kind: u32, layout: [u64; 4], links: [u32; 2], entry: u64) {
    let [flags, address, offset, size] = layout;
    let [link, info] = links;
    let at = SH as usize + n * 64;
    put32(b, at + 4, kind);
    put64(b, at + 8, flags);
    put64(b, at + 16, address);
    put64(b, at + 24, offset);
    put64(b, at + 32, size);
    put32(b, at + 40, link);
    put32(b, at + 44, info);
    put64(b, at + 48, 1);
    put64(b, at + 56, entry);
}
// Fabricated minimal regular ELF. No file is loaded or instruction executed.
fn elf() -> Vec<u8> {
    let mut b = vec![0; 0x1800];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut b, 16, 3);
    put16(&mut b, 18, 62);
    put32(&mut b, 20, 1);
    put64(&mut b, 32, 64);
    put64(&mut b, 40, SH);
    put16(&mut b, 52, 64);
    put16(&mut b, 54, 56);
    put16(&mut b, 56, 1);
    put16(&mut b, 58, 64);
    put16(&mut b, 60, 7);
    // Section names are empty strings, backed by the existing string table.
    put16(&mut b, 62, 2);
    put32(&mut b, 64, 1);
    put32(&mut b, 68, 5);
    put64(&mut b, 72, 0x1000);
    put64(&mut b, 80, 0x401000);
    put64(&mut b, 96, CODE.len() as u64);
    put64(&mut b, 104, CODE.len() as u64);
    put64(&mut b, 112, 4096);
    b[0x1000..0x1000 + CODE.len()].copy_from_slice(CODE);
    let strings = format!("\0{SYMBOL}\0alias\0").into_bytes();
    b[0x1100..0x1100 + strings.len()].copy_from_slice(&strings);
    put32(&mut b, 0x1218, 1);
    b[0x121c] = 0x12;
    put16(&mut b, 0x121e, 1);
    put64(&mut b, 0x1220, 0x401000);
    put64(&mut b, 0x1228, CODE.len() as u64);
    sh(
        &mut b,
        1,
        1,
        [6, 0x401000, 0x1000, CODE.len() as u64],
        [0, 0],
        0,
    );
    sh(
        &mut b,
        2,
        3,
        [0, 0, 0x1100, strings.len() as u64],
        [0, 0],
        0,
    );
    sh(&mut b, 3, 2, [0, 0, 0x1200, 72], [2, 1], 24);
    sh(&mut b, 4, 4, [0, 0x402000, 0x1300, 0], [3, 1], 24);
    sh(&mut b, 5, 11, [0, 0, 0x1380, 0], [2, 1], 24);
    sh(&mut b, 6, 1, [0, 0, 0x13f0, 0], [0, 0], 0);
    b
}

#[test]
fn rust_invoke_elf_unique_func_and_complete_extent_are_required() {
    let b = elf();
    let (s, p) = extract(&b).unwrap();
    let mut missing_strings = b.clone();
    put16(&mut missing_strings, 62, 0);
    assert!(extract(&missing_strings).is_err());
    assert_eq!(
        s,
        Selection {
            virtual_address: 0x401000,
            file_offset: 0x1000,
            section: 1,
            extent: 20
        }
    );
    assert_eq!(p.bytes(), CODE);
    let mut agreeing = b.clone();
    agreeing[0x1398..0x13b0].copy_from_slice(&b[0x1218..0x1230]);
    put64(&mut agreeing, SH as usize + 5 * 64 + 32, 48);
    assert_eq!(extract(&agreeing).unwrap(), (s, p.clone()));
    let mut conflict = agreeing.clone();
    put64(&mut conflict, 0x13a8, 19);
    assert!(extract(&conflict).is_err());
    let mut duplicate = b.clone();
    duplicate[0x1230..0x1248].copy_from_slice(&b[0x1218..0x1230]);
    assert!(extract(&duplicate).is_err());
    for (at, value) in [(0x121c, 0x11), (0x121c, 0x22), (0x121d, 2), (0x121e, 0)] {
        let mut bad = b.clone();
        bad[at] = value;
        assert!(extract(&bad).is_err());
    }
    for size in [0, 19, 21, 257, u64::MAX] {
        let mut bad = b.clone();
        put64(&mut bad, 0x1228, size);
        assert!(extract(&bad).is_err());
    }
    for len in [0, 63, 0x1005, 0x1401] {
        assert!(extract(&b[..len]).is_err());
    }
    let mut wrong = b.clone();
    wrong[5] = 2;
    assert!(extract(&wrong).is_err());
    put16(&mut wrong, 18, 3);
    assert!(extract(&wrong).is_err());
}

#[test]
fn rust_invoke_elf_load_section_permissions_and_offsets_are_exact() {
    let b = elf();
    for flags in [4, 6, 7] {
        let mut bad = b.clone();
        put32(&mut bad, 68, flags);
        assert!(extract(&bad).is_err());
    }
    for flags in [2, 3, 7] {
        let mut bad = b.clone();
        put64(&mut bad, SH as usize + 64 + 8, flags);
        assert!(extract(&bad).is_err());
    }
    for (at, value) in [
        (72, 0x1001),
        (80, 0x401001),
        (96, 19),
        (104, 19),
        (112, 3),
        (SH as usize + 64 + 24, 0x1001),
        (SH as usize + 64 + 16, 0x401001),
    ] {
        let mut bad = b.clone();
        put64(&mut bad, at, value);
        assert!(extract(&bad).is_err());
    }
    let mut overlap = b.clone();
    let ph = b[64..120].to_vec();
    overlap[120..176].copy_from_slice(&ph);
    put16(&mut overlap, 56, 2);
    assert!(extract(&overlap).is_err());
    let mut nobits = b.clone();
    put32(&mut nobits, SH as usize + 64 + 4, 8);
    assert!(extract(&nobits).is_err());
    let mut extension = b.clone();
    put16(&mut extension, 60, 0);
    assert!(extract(&extension).is_err());
}

#[test]
fn rust_invoke_elf_overlapping_symbols_and_relocations_refuse() {
    let b = elf();
    let mut alias = b.clone();
    alias[0x1230..0x1248].copy_from_slice(&b[0x1218..0x1230]);
    put32(&mut alias, 0x1230, (SYMBOL.len() + 2) as u32);
    assert!(extract(&alias).is_err());
    put64(&mut alias, 0x1240, 0);
    assert!(extract(&alias).is_err()); // Zero-sized interior definition.
    let mut relocation = b.clone();
    put64(&mut relocation, SH as usize + 4 * 64 + 32, 24);
    put64(&mut relocation, 0x1300, 0x401000);
    put64(&mut relocation, 0x1308, 1);
    assert!(extract(&relocation).is_err());
    put64(&mut relocation, 0x1300, 0x400ffc);
    assert!(extract(&relocation).is_err()); // Overlap starts before FUNC.
    put64(&mut relocation, 0x1300, 0x402000);
    assert!(extract(&relocation).is_ok());
    put64(&mut relocation, 0x1308, 0xffff);
    assert!(extract(&relocation).is_err());
    let mut packed = b.clone();
    put32(&mut packed, SH as usize + 4 * 64 + 4, 19);
    put64(&mut packed, SH as usize + 4 * 64 + 32, 8);
    assert!(extract(&packed).is_err());
    let mut truncated = b.clone();
    put64(&mut truncated, SH as usize + 4 * 64 + 32, 23);
    assert!(extract(&truncated).is_err());
    // A dynamic pointer not covered by an authenticated relocation section refuses.
    let mut hidden = b.clone();
    put16(&mut hidden, 56, 2);
    put32(&mut hidden, 120, 2);
    put64(&mut hidden, 128, 0x1300);
    put64(&mut hidden, 152, 64);
    for (n, tag, value) in [(0, 7, 0x403000), (1, 8, 24), (2, 9, 24)] {
        put64(&mut hidden, 0x1300 + n * 16, tag);
        put64(&mut hidden, 0x1308 + n * 16, value);
    }
    assert!(extract(&hidden).is_err());
    // A complete ordinary dynamic source and relocation source must both join
    // their sections and exactly one covering file-backed loader segment.
    let mut joined = b.clone();
    put16(&mut joined, 56, 3);
    put32(&mut joined, 120, 1);
    put32(&mut joined, 124, 6);
    put64(&mut joined, 128, 0x1300);
    put64(&mut joined, 136, 0x402300);
    put64(&mut joined, 152, 0x100);
    put64(&mut joined, 160, 0x100);
    put64(&mut joined, 168, 1);
    put32(&mut joined, 176, 2);
    put32(&mut joined, 180, 6);
    put64(&mut joined, 184, 0x1340);
    put64(&mut joined, 192, 0x402340);
    put64(&mut joined, 208, 64);
    put64(&mut joined, 216, 64);
    put64(&mut joined, 224, 8);
    sh(&mut joined, 4, 4, [2, 0x402300, 0x1300, 24], [3, 1], 24);
    sh(&mut joined, 6, 6, [3, 0x402340, 0x1340, 64], [2, 0], 16);
    put64(&mut joined, 0x1300, 0x403000);
    put64(&mut joined, 0x1308, 1);
    for (n, tag, value) in [(0, 7, 0x402300), (1, 8, 24), (2, 9, 24)] {
        put64(&mut joined, 0x1340 + n * 16, tag);
        put64(&mut joined, 0x1348 + n * 16, value);
    }
    assert!(extract(&joined).is_ok());
    // Harmless p_offset bytes cannot substitute for the dynamic bytes at VA.
    for (at, value) in [
        (184, 0x1380),
        (192, 0x402380),
        (208, 48),
        (216, 80),
        (SH as usize + 6 * 64 + 16, 0x402380),
        (SH as usize + 6 * 64 + 24, 0x1380),
        (SH as usize + 6 * 64 + 32, 48),
        (SH as usize + 6 * 64 + 56, 8),
    ] {
        let mut bad = joined.clone();
        put64(&mut bad, at, value);
        assert!(extract(&bad).is_err());
    }
    let mut no_section = joined.clone();
    put32(&mut no_section, SH as usize + 6 * 64 + 4, 1);
    assert!(extract(&no_section).is_err());
    let mut duplicate_dynamic = joined.clone();
    put16(&mut duplicate_dynamic, 56, 4);
    duplicate_dynamic[232..288].copy_from_slice(&joined[176..232]);
    assert!(extract(&duplicate_dynamic).is_err());
    // Previously a second load with a wrong offset was simply not counted.
    for (address, offset, size) in [
        (0x402300, 0x1300, 0x100),
        (0x402300, 0x1380, 0x80),
        (0x402308, 0x1308, 8),
        (0x402340, 0x1380, 64),
        (0x402348, 0x1348, 8),
    ] {
        let mut conflict = joined.clone();
        put16(&mut conflict, 56, 4);
        put32(&mut conflict, 232, 1);
        put32(&mut conflict, 236, 6);
        put64(&mut conflict, 240, offset);
        put64(&mut conflict, 248, address);
        put64(&mut conflict, 264, size);
        put64(&mut conflict, 272, size);
        put64(&mut conflict, 280, 1);
        assert!(extract(&conflict).is_err());
    }
    let mut hidden_pointer = joined.clone();
    put64(&mut hidden_pointer, 0x1348, 0x402380);
    assert!(extract(&hidden_pointer).is_err());
    let mut intersects = joined.clone();
    put64(&mut intersects, 0x1300, 0x401000);
    assert!(extract(&intersects).is_err());
}

#[test]
fn rust_invoke_held_file_identity_and_byte_custody_refuse() {
    let b = elf();
    let original = Stamp {
        dev: 1,
        ino: 2,
        len: b.len() as u64,
        mode: 0o100755,
        modified: (3, 4),
        changed: (5, 6),
    };
    assert!(source_matches(original, original, original, &b, &b).is_ok());
    let variants = [
        Stamp { dev: 2, ..original },
        Stamp { ino: 3, ..original },
        Stamp {
            len: original.len + 1,
            ..original
        },
        Stamp {
            mode: 0o100644,
            ..original
        },
        Stamp {
            modified: (3, 5),
            ..original
        },
        Stamp {
            changed: (5, 7),
            ..original
        },
    ];
    for changed in variants {
        assert!(source_matches(original, changed, original, &b, &b).is_err());
        assert!(source_matches(original, original, changed, &b, &b).is_err());
    }
    for at in [0, 0x1000, 0x1400, b.len() - 1] {
        let mut changed = b.clone();
        changed[at] ^= 1;
        assert!(source_matches(original, original, original, &b, &changed).is_err());
    }
    assert!(source_matches(original, original, original, &b, &b[..b.len() - 1]).is_err());
}
