//! Pure selection/page predicates, never a loader or callable owner.
use super::super::normal_module::{
    canonical_page_slice, check_overlay_slice, check_selection_slice, preflight,
};
use super::*;

#[test]
fn leaf_set_selection_count_order_and_source_are_exact() {
    let bytes = [0; 32];
    let selected: Vec<_> = (0..4)
        .map(|i| TrustedFunctionSelection::new(&bytes, 0x1000 + i * 16, 16, "leaf").unwrap())
        .collect();
    let refs: Vec<_> = selected.iter().collect();
    for n in 1..=4 {
        assert_eq!(check_selection_slice(&refs[..n]), Ok(()));
    }
    assert_eq!(check_selection_slice(&[]), Err(SetupRefusal::EntryExit));
    let five = [&selected[0]; 5];
    assert_eq!(check_selection_slice(&five), Err(SetupRefusal::EntryExit));
    assert_eq!(
        check_selection_slice(&[refs[1], refs[0]]),
        Err(SetupRefusal::EntryExit)
    );
    assert_eq!(
        check_selection_slice(&[refs[0], refs[0]]),
        Err(SetupRefusal::EntryExit)
    );
    let other_bytes = [1; 32];
    let other = TrustedFunctionSelection::new(&other_bytes, 0x1030, 16, "other").unwrap();
    assert_eq!(
        check_selection_slice(&[refs[0], refs[1], refs[2], &other]),
        Err(SetupRefusal::SourceBytes)
    );
}
#[test]
fn leaf_set_page_union_refuses_conflicts_gaps_and_third_page() {
    let a = vec![3; 4096];
    let b = vec![7; 4096];
    let pages =
        canonical_page_slice(&[(0x1000, &a), (0x5000, &b), (0x1000, &a), (0x5000, &b)]).unwrap();
    assert_eq!(
        pages.iter().map(|p| p.address).collect::<Vec<_>>(),
        [0x1000, 0x5000]
    );
    assert_eq!(pages.iter().map(|p| p.bytes.len()).sum::<usize>(), 8192); // no invented gap
    let interpolated = [ExpectedBytes {
        address: 0x1000,
        bytes: vec![0; 5 * 4096],
    }];
    assert_eq!(
        check_overlay_slice(&pages, &interpolated, &[]),
        Err(SetupRefusal::SourceBytes)
    );
    assert_eq!(
        canonical_page_slice(&[(0x1000, &a), (0x1000, &b)]),
        Err(SetupRefusal::SourceBytes)
    );
    assert_eq!(
        canonical_page_slice(&[(0x1000, &a), (0x2000, &a), (0x3000, &a)]),
        Err(SetupRefusal::Format)
    );
    for (start, bytes) in [
        (0x1001, a.as_slice()),
        (!4095, a.as_slice()),
        (0x1000, &a[..4095]),
    ] {
        assert_eq!(
            canonical_page_slice(&[(start, bytes)]),
            Err(SetupRefusal::Format)
        );
    }
}
#[test]
fn leaf_set_overlay_retains_every_unselected_byte() {
    let bytes = vec![0xa5; 4096];
    let pages = canonical_page_slice(&[(0x1000, &bytes)]).unwrap();
    let bodies = [
        (0x1010, 0x1020),
        (0x1030, 0x1040),
        (0x1050, 0x1060),
        (0x1070, 0x1080),
    ];
    let mut expected = pages.clone();
    for &(a, b) in &bodies {
        expected[0].bytes[(a - 0x1000) as usize..(b - 0x1000) as usize].fill(0xcc);
    }
    assert_eq!(check_overlay_slice(&pages, &expected, &bodies), Ok(()));
    for i in 0..4096 {
        if bodies
            .iter()
            .any(|&(a, b)| a <= 0x1000 + i as u64 && 0x1000 + (i as u64) < b)
        {
            continue;
        }
        expected[0].bytes[i] ^= 1;
        assert_eq!(
            check_overlay_slice(&pages, &expected, &bodies),
            Err(SetupRefusal::SourceBytes)
        );
        expected[0].bytes[i] ^= 1;
    }
    assert_eq!(
        check_overlay_slice(&pages, &[], &bodies),
        Err(SetupRefusal::SourceBytes)
    );
}

const BASE: u64 = 0x1010;
const CODE: &[u8] = &[0x48, 0x89, 0xf0, 0x48, 0x83, 0xc0, 1, 0xc3];
fn w16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn ph(b: &mut [u8], n: usize, kind: u32, flags: u32, offset: u64, size: u64) {
    let p = 64 + n * 56;
    w32(b, p, kind);
    w32(b, p + 4, flags);
    w64(b, p + 8, offset);
    w64(b, p + 16, offset);
    w64(b, p + 24, offset);
    w64(b, p + 32, size);
    w64(b, p + 40, size);
    w64(b, p + 48, 4096);
}
fn sh(b: &mut [u8], n: usize, fields: (u32, u32, u64, u64, u64, u32, u64)) {
    let (name, kind, flags, offset, size, link, entsize) = fields;
    let p = 0x3200 + n * 64;
    w32(b, p, name);
    w32(b, p + 4, kind);
    w64(b, p + 8, flags);
    w64(b, p + 16, if flags & 2 != 0 { offset } else { 0 });
    w64(b, p + 24, offset);
    w64(b, p + 32, size);
    w32(b, p + 40, link);
    w32(b, p + 44, if n == 2 { 1 } else { 0 });
    w64(b, p + 48, if n == 1 || n == 3 || n == 5 { 1 } else { 8 });
    w64(b, p + 56, entsize);
}
fn fixture() -> Vec<u8> {
    let mut b = vec![0; 0x3400];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    w16(&mut b, 16, 3);
    w16(&mut b, 18, 62);
    w32(&mut b, 20, 1);
    w64(&mut b, 32, 64);
    w64(&mut b, 40, 0x3200);
    w16(&mut b, 52, 64);
    w16(&mut b, 54, 56);
    w16(&mut b, 56, 6);
    w16(&mut b, 58, 64);
    w16(&mut b, 60, 6);
    w16(&mut b, 62, 5);
    ph(&mut b, 0, 1, 4, 0, 4096);
    ph(&mut b, 1, 1, 5, 4096, 4096);
    ph(&mut b, 2, 1, 6, 8192, 4096);
    ph(&mut b, 3, 2, 6, 8192, 112);
    ph(&mut b, 4, 0x6474_e552, 4, 8192, 4096);
    ph(&mut b, 5, 0x6474_e551, 6, 0, 0);
    b[0x1010..0x1010 + CODE.len()].copy_from_slice(CODE);
    b[0x280..0x28a].copy_from_slice(b"\0checksum\0");
    let names = b"\0.text\0.dynsym\0.dynstr\0.dynamic\0.shstrtab\0";
    b[0x300..0x300 + names.len()].copy_from_slice(names);
    w32(&mut b, 0x218, 1);
    b[0x21c] = 0x12;
    w16(&mut b, 0x21e, 1);
    w64(&mut b, 0x220, BASE);
    w64(&mut b, 0x228, CODE.len() as u64);
    for (n, v) in [1, 2, 1, 0, 0].into_iter().enumerate() {
        w32(&mut b, 0x400 + n * 4, v);
    }
    for (n, (tag, value)) in [
        (4, 0x400),
        (5, 0x280),
        (6, 0x200),
        (10, 10),
        (11, 24),
        (24, 0),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        w64(&mut b, 0x2000 + n * 16, tag);
        w64(&mut b, 0x2008 + n * 16, value);
    }
    sh(&mut b, 1, (1, 1, 6, BASE, CODE.len() as u64, 0, 0));
    sh(&mut b, 2, (7, 11, 2, 0x200, 48, 3, 24));
    sh(&mut b, 3, (15, 3, 2, 0x280, 10, 0, 0));
    sh(&mut b, 4, (23, 6, 3, 0x2000, 112, 3, 16));
    sh(&mut b, 5, (32, 3, 0, 0x300, names.len() as u64, 0, 0));
    b
}

#[test]
fn leaf_set_last_selection_refuses_before_loader() {
    let mut bytes = fixture();
    // Strip the named symbol; exact complete extents remain supplied externally.
    bytes[0x218..0x230].fill(0);
    bytes[0x280..0x28a].fill(0);
    w64(&mut bytes, 0x3200 + 2 * 64 + 32, 24);
    w64(&mut bytes, 0x3200 + 3 * 64 + 32, 1);
    w64(&mut bytes, 0x2038, 1);
    for (n, v) in [1, 1, 0, 0, 0].into_iter().enumerate() {
        w32(&mut bytes, 0x400 + n * 4, v);
    }
    // One complete RX section, four disjoint complete test leaves.
    w64(&mut bytes, 0x3200 + 64 + 32, 0x80);
    for offset in [0x10, 0x30, 0x50, 0x70] {
        bytes[0x1000 + offset..0x1000 + offset + CODE.len()].copy_from_slice(CODE);
    }
    let descriptors: Vec<_> = [0x1010, 0x1030, 0x1050, 0x1070]
        .into_iter()
        .map(|at| TrustedFunctionSelection::new(&bytes, at, CODE.len(), "leaf").unwrap())
        .collect();
    let refs: Vec<_> = descriptors.iter().collect();
    assert_eq!(preflight(&refs).unwrap().len(), 4);
    let last_bad = TrustedFunctionSelection::new(&bytes, 0x2000, CODE.len(), "bad").unwrap();
    assert_eq!(
        preflight(&[refs[0], refs[1], refs[2], &last_bad]).err(),
        Some(SetupRefusal::SymbolOwner)
    );
    // This is the actual complete preflight before retain_loader; no path, FD,
    // loader, loaded-owner or publication authority is fabricated.
}
