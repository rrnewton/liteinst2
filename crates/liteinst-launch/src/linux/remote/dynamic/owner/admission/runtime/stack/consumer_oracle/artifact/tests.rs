//! Synthetic ELF records exercise the parser only; no compiler/native claim.
use super::*;
fn put16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes())
}
fn put32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes())
}
fn put64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes())
}
pub(in super::super) fn model() -> Vec<u8> {
    let mut raw = vec![0; 0x2340];
    raw[..9].copy_from_slice(b"\x7fELF\x02\x01\x01\x00\x00");
    put16(&mut raw, 16, 2);
    put16(&mut raw, 18, 62);
    put32(&mut raw, 20, 1);
    put64(&mut raw, 24, 0x201000);
    put64(&mut raw, 32, 64);
    put64(&mut raw, 40, 0x2200);
    put16(&mut raw, 52, 64);
    put16(&mut raw, 54, 56);
    put16(&mut raw, 56, 4);
    put16(&mut raw, 58, 64);
    put16(&mut raw, 60, 5);
    put16(&mut raw, 62, 4);
    for (index, kind, flags, offset, address, size, align) in [
        (0, 6, 4, 64, 0x200040, 224, 8),
        (1, 1, 4, 0, 0x200000, 288, 4096),
        (2, 1, 5, 4096, 0x201000, 0x85, 4096),
        (3, 0x6474e551, 6, 0, 0, 0, 16),
    ] {
        let p = 64 + index * 56;
        put32(&mut raw, p, kind);
        put32(&mut raw, p + 4, flags);
        put64(&mut raw, p + 8, offset);
        put64(&mut raw, p + 16, address);
        put64(&mut raw, p + 24, address);
        put64(&mut raw, p + 32, size);
        put64(&mut raw, p + 40, size);
        put64(&mut raw, p + 48, align);
    }
    let mut main = vec![
        0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0xe8, 0, 0, 0, 0, 0x48, 0x89, 0xc6, 0xb8,
        186, 0, 0, 0, 0x0f, 0x05, 0x48, 0x29, 0xc6, 0x48, 0x89, 0xf7, 0xb8, 231, 0, 0, 0, 0x0f,
        0x05,
    ];
    main[11..15].copy_from_slice(&(0x80_i32 - 15).to_le_bytes());
    raw[0x1000..0x1000 + main.len()].copy_from_slice(&main);
    raw[0x1080..0x1085].copy_from_slice(&[0x48, 0x8d, 0x47, 7, 0xc3]);
    raw[0x2000..0x2012].copy_from_slice(b"\0_start\0add_seven\0");
    let text = 0x2240;
    put32(&mut raw, text + 4, 1);
    put64(&mut raw, text + 8, 6);
    put64(&mut raw, text + 16, 0x201000);
    put64(&mut raw, text + 24, 0x1000);
    put64(&mut raw, text + 32, 0x85);
    let strings = 0x2280;
    put32(&mut raw, strings + 4, 3);
    put64(&mut raw, strings + 24, 0x2000);
    put64(&mut raw, strings + 32, 18);
    let sym = 0x22c0;
    put32(&mut raw, sym + 4, 2);
    put64(&mut raw, sym + 24, 0x2040);
    put64(&mut raw, sym + 32, 72);
    put32(&mut raw, sym + 40, 2);
    put64(&mut raw, sym + 56, 24);
    for (at, name, info, value, size) in [
        (0x2058, 1, 0x12, 0x201000, main.len() as u64),
        (0x2070, 8, 0x02, 0x201080, 5),
    ] {
        put32(&mut raw, at, name);
        raw[at + 4] = info;
        put16(&mut raw, at + 6, 1);
        put64(&mut raw, at + 8, value);
        put64(&mut raw, at + 16, size);
    }
    raw
}
pub(in super::super) fn parse(raw: &[u8]) -> Result<ArtifactPlan, OracleError> {
    elf::inspect(raw)
}

#[test]
fn consumer_artifact_model_retains_short_file_extent_and_closed_path() {
    let raw = model();
    let plan = elf::inspect(&raw).unwrap();
    assert_eq!(plan.entry, 0x201000);
    assert_eq!(plan.text_filesz, 0x85);
    assert_eq!(plan.call, 3);
    assert_eq!(plan.ret, 5);
    assert_eq!(
        plan.instructions()
            .filter(|i| matches!(i.kind(), PlannedKind::Syscall { .. }))
            .count(),
        3
    );
    super::super::dataflow::prove_dataflow(&plan).unwrap();
    let mut excessive = raw.clone();
    let main = excessive[0x1000..0x1026].to_vec();
    excessive[0x1000..0x101f].fill(0x90);
    excessive[0x101f..0x1045].copy_from_slice(&main);
    excessive[0x102a..0x102e].copy_from_slice(&(0x80_i32 - 46).to_le_bytes());
    put64(&mut excessive, 0x2058 + 16, 69);
    assert!(elf::inspect(&excessive).is_err());
}
#[test]
fn consumer_artifact_rejects_writable_bss_overlap_and_interpreter_models() {
    let raw = model();
    for (offset, value) in [
        (64 + 2 * 56 + 4, 7_u64),
        (64 + 2 * 56 + 40, 0x86),
        (64 + 2 * 56 + 16, 0x200000),
        (64, 3),
    ] {
        let mut changed = raw.clone();
        if offset == 64 + 2 * 56 + 4 || offset == 64 {
            put32(&mut changed, offset, value as u32)
        } else {
            put64(&mut changed, offset, value)
        }
        assert!(elf::inspect(&changed).is_err());
    }
}
#[test]
fn consumer_artifact_rejects_symbol_alias_truncation_and_hidden_tail_models() {
    let raw = model();
    for (offset, value) in [
        (0x2070 + 8, 0x201000),
        (0x2058 + 16, 37),
        (0x2058 + 16, 39),
        (0x22c0 + 56, 16),
        (0x2240 + 8, 7),
        (0x2240 + 16, 0x201008),
        (0x2240 + 24, 0x1008),
        (64 + 16, 0x200048), // PHDR address must name the actual table.
        (64 + 24, 0x200048), // Physical descriptive address is exact too.
        (64 + 48, 16),
    ] {
        let mut changed = raw.clone();
        put64(&mut changed, offset, value);
        assert!(elf::inspect(&changed).is_err());
    }
}
#[test]
fn consumer_artifact_rejects_push_rsp_write_and_nonexact_call_models() {
    for bytes in [
        &[0x48, 0x89, 0xc4][..],
        &[0x89, 0xc4],
        &[0x66, 0x89, 0xc4],
        &[0x40, 0x88, 0xc4],
        &[0x48, 0x8d, 0x60, 0],
        &[0x48, 0x87, 0xe0],
        &[0x50],
        &[0x58],
        &[0x48, 0x8b, 0x07],
        &[0x48, 0x11, 0xc7],
    ] {
        let decoded =
            iced_x86::Decoder::with_ip(64, bytes, 0x201000, iced_x86::DecoderOptions::NONE)
                .decode();
        assert!(super::super::dataflow::require_ordinary(&decoded, bytes).is_err());
    }
    let raw = model();
    for (at, bytes) in [
        (0x1000, &[0x50][..]),
        (0x1007, &[0x48, 0x89, 0xc4][..]),
        (0x100a, &[0xff, 0xd0][..]),
        (0x1084, &[0xcb][..]),
    ] {
        let mut changed = raw.clone();
        changed[at..at + bytes.len()].copy_from_slice(bytes);
        assert!(elf::inspect(&changed).is_err());
    }
}
#[test]
fn consumer_artifact_segment_check_retains_uninterpreted_actual_tail() {
    let raw = model();
    let plan = elf::inspect(&raw).unwrap();
    let mut actual = vec![0xa5; 8192];
    actual[..plan.read_filesz].copy_from_slice(&raw[..plan.read_filesz]);
    actual[4096..4096 + plan.text_filesz].copy_from_slice(&raw[4096..4096 + plan.text_filesz]);
    plan.require_image(&raw, &actual).unwrap();
    actual[4096] ^= 1;
    assert!(plan.require_image(&raw, &actual).is_err());
}
