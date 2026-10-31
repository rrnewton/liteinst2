//! Pure format controls; real compiled ELF/load positivity remains the native test.
use super::*;

const ENTRY: u64 = 0x1010;
const DYNAMIC: usize = 0x2000;
fn w64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    let mut elf = super::super::tests::fixture();
    elf[ENTRY as usize..ENTRY as usize + bytes::BYTES.len()].copy_from_slice(bytes::BYTES);
    w64(&mut elf, 0x228, bytes::BYTES.len() as u64); // complete symbol extent
    w64(&mut elf, 0x3200 + 64 + 32, bytes::BYTES.len() as u64); // .text extent
    // Add the same harmless aligned empty LOAD shape as the compiler output.
    elf.copy_within(64 + 2 * 56..64 + 6 * 56, 64 + 3 * 56);
    elf[56..58].copy_from_slice(&7_u16.to_le_bytes());
    let empty = 64 + 2 * 56;
    elf[empty..empty + 56].fill(0);
    elf[empty..empty + 4].copy_from_slice(&1_u32.to_le_bytes());
    elf[empty + 4..empty + 8].copy_from_slice(&4_u32.to_le_bytes());
    for field in [8, 16, 24, 48] {
        w64(
            &mut elf,
            empty + field,
            if field == 48 { 4096 } else { 0x2000 },
        );
    }
    // Existing tags keep their values and order; insert SYMBOLIC before NULL.
    w64(&mut elf, DYNAMIC + 6 * 16, 16);
    for field in [32, 40] {
        w64(&mut elf, 64 + 4 * 56 + field, 128);
    }
    w64(&mut elf, 0x3200 + 4 * 64 + 32, 128);
    elf
}
fn parse(elf: &[u8]) -> Result<super::super::Parsed, SetupRefusal> {
    let selection = TrustedFunctionSelection::new(elf, ENTRY, 123, bytes::SYMBOL)?;
    selection::parse_module_caller(&selection, admit)
}

#[test]
fn owned_caller_symbolic_policy_is_separate_and_retains_all_dynamic_refusals() {
    let elf = fixture();
    let table = &elf[DYNAMIC..DYNAMIC + 128];
    assert!(dynamic(table).is_ok());
    assert_eq!(super::super::dynamic(table), Err(SetupRefusal::Format));
    let mut ordinary = table.to_vec();
    w64(&mut ordinary, 6 * 16, 0);
    assert!(super::super::dynamic(&ordinary).is_ok());
    assert_eq!(dynamic(&ordinary), Err(SetupRefusal::Format));
    // Insert before NULL without removing any required tag: refusals cannot
    // accidentally pass merely because the eager-binding marker was lost.
    let extra = |tag: u64, value: u64| {
        let mut added = table[..112].to_vec();
        added.extend_from_slice(&tag.to_le_bytes());
        added.extend_from_slice(&value.to_le_bytes());
        added.extend_from_slice(&[0; 16]);
        added
    };
    assert!(dynamic(&extra(30, 8)).is_ok());
    assert!(dynamic(&extra(0x6fff_fffb, 1)).is_ok());
    assert!(dynamic(&extra(16, 0)).is_err()); // duplicate SYMBOLIC before NULL
    // No dependency, relocator, initializer, TLS/path lookup, or unknown tag.
    for tag in [1, 7, 12, 13, 15, 17, 22, 23, 25, 26, 29, 35, 36, 37, 0xffff] {
        assert!(dynamic(&extra(tag, 0)).is_err(), "tag {tag}");
    }
    for (offset, value) in [
        (6 * 16 + 8, 1),     // SYMBOLIC is a zero-valued marker
        (7 * 16 + 8, 1),     // nonzero NULL payload
        (4 * 16 + 8, 23),    // wrong SYMENT
        (3 * 16 + 8, 0),     // empty string table
        (3 * 16 + 8, 65537), // original string-table limit
        (0, 14),             // no hash table
        (5 * 16, 14),        // no eager-binding marker
    ] {
        let mut bad = table.to_vec();
        w64(&mut bad, offset, value);
        assert!(dynamic(&bad).is_err(), "offset {offset}, value {value}");
    }
    for flags_tag in [30, 0x6fff_fffb] {
        // SYMBOLIC/unknown flag is not this profile; BIND_NOW is still present.
        assert!(dynamic(&extra(flags_tag, 2)).is_err());
    }
    let mut post_null = table.to_vec();
    post_null.extend_from_slice(&16_u64.to_le_bytes());
    post_null.extend_from_slice(&0_u64.to_le_bytes());
    assert!(dynamic(&post_null).is_err());
    assert!(dynamic(&table[..112]).is_err()); // no terminator
    assert!(dynamic(&table[..127]).is_err());
    assert!(dynamic(&[]).is_err());
    assert!(dynamic(&vec![0; 4112]).is_err());
}

#[test]
fn owned_caller_full_selection_keeps_code_and_empty_load_ownership_checks() {
    let elf = fixture();
    let parsed = parse(&elf).unwrap();
    assert_eq!(parsed.code, bytes::BYTES);
    assert_eq!(parsed.entry, ENTRY);
    assert_eq!(parsed.loads.len(), 3); // zero rounded extent owns no mapping
    assert_eq!(parsed.source, &elf[4096..8192]);
    assert_eq!(parsed.page, 4096);
    assert_eq!(parsed.page_offset, 4096);
    let selection = TrustedFunctionSelection::new(&elf, ENTRY, 123, bytes::SYMBOL).unwrap();
    assert_eq!(
        selection::parse(&selection).err(),
        Some(SetupRefusal::Format)
    );
    assert_eq!(
        selection::parse_with(&selection, admit).err(),
        Some(SetupRefusal::Format)
    );
    let empty = 64 + 2 * 56;
    for (offset, value) in [
        (empty + 8, 0x2001),       // file/VA congruence
        (empty + 16, 0x2001),      // empty unaligned interval would round to a page
        (empty + 32, 1),           // file/memory inequality
        (empty + 40, 1),           // no anonymous/BSS ownership
        (empty + 48, 8192),        // unchanged alignment
        (DYNAMIC + 6 * 16 + 8, 1), // full entry uses the dynamic policy
    ] {
        let mut bad = elf.clone();
        w64(&mut bad, offset, value);
        assert!(parse(&bad).is_err(), "offset {offset}, value {value}");
    }
    let mut writable = elf.clone();
    writable[64 + 56 + 4..64 + 56 + 8].copy_from_slice(&7_u32.to_le_bytes());
    assert!(parse(&writable).is_err());
    let mut changed_code = elf;
    changed_code[ENTRY as usize] ^= 1;
    assert_eq!(parse(&changed_code).err(), Some(SetupRefusal::EntryExit));
}
