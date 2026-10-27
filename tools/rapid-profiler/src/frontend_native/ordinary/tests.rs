//! Prospective pure controls: no loader calls, executable maps or native credit.
use super::*;

// Independently authored scalar byte sum; two RETs and one backward local edge.
// 0:test rsi,rsi; 3:je 25; 5:xor eax,eax; 7:movzx edx,[rdi];
// 10:add rax,rdx; 13:add rdi,1; 17:sub rsi,1; 21:jne 7;
// 23:ret; 24:nop (unreachable alignment); 25:xor eax,eax; 27:ret.
const CODE: &[u8] = &[
    0x48, 0x85, 0xf6, 0x74, 0x14, 0x31, 0xc0, 0x0f, 0xb6, 0x17, 0x48, 0x01, 0xd0, 0x48, 0x83, 0xc7,
    0x01, 0x48, 0x83, 0xee, 0x01, 0x75, 0xf0, 0xc3, 0x90, 0x31, 0xc0, 0xc3,
];
const BASE: u64 = 0x1010;
fn positive() -> IntegerLeafCertificate {
    cfg::admit(CODE, BASE).unwrap()
}

#[test]
fn complete_scalar_cfg_has_both_returns_and_explicit_padding() {
    let c = positive();
    assert_eq!(c.range(), (BASE, BASE + 28));
    assert_eq!(c.returns(), &[BASE + 23, BASE + 27]);
    assert_eq!(c.padding_heads(), &[BASE + 24]);
    assert_eq!(
        c.blocks(),
        &[
            (BASE, BASE + 5),
            (BASE + 5, BASE + 7),
            (BASE + 7, BASE + 23),
            (BASE + 23, BASE + 24),
            (BASE + 25, BASE + 28)
        ]
    );
    assert!(c.edges().contains(&(BASE + 21, BASE + 7)));
    assert!(c.entries().contains(&(BASE + 25)));
    assert_eq!(c.heads().len(), 12);
}
#[test]
fn control_edges_must_land_on_local_heads() {
    positive();
    for displacement in [0x15, 0x7f, 0xfc] {
        let mut b = CODE.to_vec();
        b[4] = displacement;
        assert_eq!(cfg::admit(&b, BASE).err(), Some(SetupRefusal::EntryExit));
    }
    // A syntactic RET elsewhere does not make an unconditional cycle exiting.
    assert!(
        cfg::admit(
            &[0x85, 0xf6, 0x74, 6, 0xeb, 2, 0x90, 0x90, 0xeb, 0xfa, 0xc3],
            BASE
        )
        .is_err()
    );
}
#[test]
fn stack_system_call_and_noninteger_forms_refuse() {
    positive();
    for prefix in [
        &[0x50][..],
        &[0x48, 0x83, 0xec, 8],
        &[0x48, 0x89, 0xc3],
        &[0x0f, 0x05],
        &[0xcd, 0x80],
        &[0xe8, 0, 0, 0, 0],
        &[0xff, 0xd0],
        &[0x0f, 0x28, 0xc1],
        &[0xf3, 0x90],
        &[0x64, 0x8b, 0x07],
        &[0x48, 0x89, 0x07],
        &[0x48, 0x03, 0x04, 0x24],
        &[0x8e, 0xd8],
        &[0x0f, 0x20, 0xc0],
        &[0x67, 0x8b, 0x07],
        &[0x8b, 0x05, 0, 0, 0, 0],
    ] {
        let mut b = prefix.to_vec();
        b.push(0xc3);
        assert!(cfg::admit(&b, BASE).is_err(), "{prefix:02x?}");
    }
    for ret in [&[0xc2, 8, 0][..], &[0xcb], &[0xcf], &[0xf3, 0xc3]] {
        assert!(cfg::admit(ret, BASE).is_err());
    }
}
#[test]
fn bounds_and_unreachable_code_are_not_coverage_exemptions() {
    positive();
    let mut limit = vec![0x90; 255];
    limit.push(0xc3);
    assert!(cfg::admit(&limit, BASE).is_ok());
    limit.insert(0, 0x90);
    assert!(cfg::admit(&limit, BASE).is_err());
    assert!(cfg::admit(&[], BASE).is_err());
    assert!(cfg::admit(CODE, u64::MAX - 10).is_err());
    let mut b = CODE.to_vec();
    b[24] = 0x40; // REX folds the next XOR into dead bytes
    assert!(cfg::admit(&b, BASE).is_err());
    assert!(cfg::admit(&[0xeb, 2, 0x90, 0x90, 0xc3], BASE).is_ok());
    assert!(cfg::admit(&[0xeb, 2, 0x31, 0xc0, 0xc3], BASE).is_err());
    assert!(cfg::admit(&[0x31, 0xc0], BASE).is_err());
}
#[test]
fn explicit_external_contract_refusals_remain_separate() {
    let good = IntegerLeafContract {
        single_external_entry: true,
        ordinary_ret_only: true,
        no_active_cet: true,
    };
    assert!(good.check().is_ok());
    assert_eq!(
        IntegerLeafContract {
            single_external_entry: false,
            ..good
        }
        .check(),
        Err(SetupRefusal::EntryExit)
    );
    assert_eq!(
        IntegerLeafContract {
            ordinary_ret_only: false,
            ..good
        }
        .check(),
        Err(SetupRefusal::ExitSemantics)
    );
    assert_eq!(
        IntegerLeafContract {
            no_active_cet: false,
            ..good
        }
        .check(),
        Err(SetupRefusal::Cet)
    );
}

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
fn complete_elf_symbol_parser_accepts_bounded_synthetic_owner() {
    let b = fixture();
    let p = parse(&b, "checksum").unwrap();
    assert_eq!(p.code, CODE);
    assert_eq!(p.entry, BASE);
    assert_eq!(p.loads.len(), 3);
    assert_eq!(p.page, 4096);
    assert_eq!(p.page_offset, 4096);
    assert_eq!(p.source, &b[4096..8192]);
}
#[test]
fn elf_owner_symbol_and_runtime_loading_extensions_refuse() {
    let b = fixture();
    assert!(parse(&b, "checksum").is_ok());
    for (at, value) in [
        (16, 2),
        (18, 3),
        (0x21c, 0x1a),
        (0x21e, 0),
        (64 + 56 + 4, 7),
    ] {
        let mut bad = b.clone();
        bad[at] = value;
        assert!(parse(&bad, "checksum").is_err());
    }
    for tag in [1, 7, 12, 13, 17, 22, 23, 25, 26, 29, 35, 36, 37] {
        let mut bad = b.clone();
        w64(&mut bad, 0x2050, tag);
        assert!(parse(&bad, "checksum").is_err(), "tag {tag}");
    }
    let mut bad = b.clone();
    w64(&mut bad, 0x228, 257);
    assert!(parse(&bad, "checksum").is_err());
    let mut bad = b.clone();
    w64(&mut bad, 64 + 2 * 56 + 40, 8192);
    assert!(parse(&bad, "checksum").is_err());
    let mut bad = b.clone();
    w64(&mut bad, 64 + 56 + 16, 0x1001);
    assert!(parse(&bad, "checksum").is_err());
    let mut bad = b.clone();
    bad[0x28a..0x291].copy_from_slice(b"inside\0");
    w64(&mut bad, 0x3200 + 2 * 64 + 32, 72);
    w64(&mut bad, 0x3200 + 3 * 64 + 32, 17);
    w64(&mut bad, 0x2038, 17);
    w32(&mut bad, 0x230, 10);
    bad[0x234] = 0x12;
    w16(&mut bad, 0x236, 1);
    w64(&mut bad, 0x238, BASE + 7);
    w64(&mut bad, 0x240, 3);
    assert_eq!(parse(&bad, "checksum").err(), Some(SetupRefusal::EntryExit));
    assert!(parse(&b, "other").is_err());
}
