//! Actual admission/resolver predicates only; no loader or native execution.
use super::super::selection as selected;
use super::*;

fn select(bytes: &[u8], entry: u64, length: usize) -> Result<Parsed, SetupRefusal> {
    let selection = TrustedFunctionSelection::new(bytes, entry, length, "internal-checksum")?;
    selected::parse(&selection)
}
fn stripped() -> Vec<u8> {
    let mut b = fixture();
    b[0x218..0x230].fill(0);
    b[0x280..0x28a].fill(0);
    w64(&mut b, 0x3200 + 2 * 64 + 32, 24); // Only the null dynamic symbol.
    w64(&mut b, 0x3200 + 3 * 64 + 32, 1);
    w64(&mut b, 0x2038, 1); // DT_STRSZ.
    for (n, value) in [1, 1, 0, 0, 0].into_iter().enumerate() {
        w32(&mut b, 0x400 + n * 4, value);
    }
    b
}

#[test]
fn selection_binds_final_bytes_and_rejects_invalid_descriptor_geometry() {
    let b = stripped();
    let s = TrustedFunctionSelection::new(&b, BASE, CODE.len(), "checksum-v1").unwrap();
    assert!(std::ptr::eq(s.trusted_final_elf(), b.as_slice()));
    assert_eq!(s.trusted_final_elf(), b);
    assert_eq!(s.elf_range(), (BASE, BASE + CODE.len() as u64));
    assert_eq!(s.label(), "checksum-v1");
    assert_eq!(selected::parse(&s).unwrap().code, CODE);
    for label in ["", "has space", "nul\0", "line\n", "nonascii-\u{e9}"] {
        assert_eq!(
            TrustedFunctionSelection::new(&b, BASE, CODE.len(), label).err(),
            Some(SetupRefusal::Format)
        );
    }
    assert!(TrustedFunctionSelection::new(&b, BASE, CODE.len(), &"x".repeat(256)).is_err());
    for length in [0, 257, usize::MAX] {
        assert_eq!(
            select(&b, BASE, length).err(),
            Some(SetupRefusal::SymbolOwner)
        );
    }
    assert_eq!(
        select(&b, u64::MAX - 1, CODE.len()).err(),
        Some(SetupRefusal::Format)
    );
    let mut other_final_file = b.clone();
    other_final_file[0x3000] ^= 1; // Outside selected code and every mapped LOAD.
    assert_ne!(s.trusted_final_elf(), other_final_file);
    // The descriptor has no setter/separate expected argument to rebind these
    // bytes. The unchanged retain_loader compares the entire file to this slice.
}

#[test]
fn hidden_and_stripped_selection_do_not_change_named_admission() {
    let mut hidden = fixture();
    hidden[0x21d] = 2; // STV_HIDDEN: the old named route still refuses.
    let stripped = stripped();
    for b in [&hidden, &stripped] {
        assert_eq!(parse(b, "checksum").err(), Some(SetupRefusal::SymbolOwner));
        let p = select(b, BASE, CODE.len()).unwrap();
        assert_eq!(p.code, CODE);
        assert_eq!((p.entry, p.page, p.page_offset), (BASE, 4096, 4096));
        assert_eq!(p.source, b[4096..8192]);
        let certificate = cfg::admit(&p.code, p.entry).unwrap();
        assert_eq!(certificate.returns(), &[BASE + 23, BASE + 27]);
    }
    let file = object::File::parse(stripped.as_slice()).unwrap();
    assert!(file.symbol_table().is_none());
    assert!(file.dynamic_symbol_table().is_some());
    assert!(!file.dynamic_symbols().any(|s| s.is_definition()));
    // This remains a section-bearing final ELF, not new sectionless support.
    let mut sectionless = stripped;
    w64(&mut sectionless, 40, 0);
    w16(&mut sectionless, 60, 0);
    w16(&mut sectionless, 62, 0);
    assert!(select(&sectionless, BASE, CODE.len()).is_err());
}

#[test]
fn selection_uses_elf_va_and_complete_rx_file_extent() {
    let mut b = stripped();
    // RX file offset stays 0x1000, but its ELF VA is 0x4000.
    w64(&mut b, 64 + 56 + 16, 0x4000);
    w64(&mut b, 64 + 56 + 24, 0x4000);
    w64(&mut b, 0x3200 + 64 + 16, 0x4010);
    let p = select(&b, 0x4010, CODE.len()).unwrap();
    assert_eq!((p.entry, p.page, p.page_offset), (0x4010, 0x4000, 0x1000));
    assert_eq!(p.code, CODE);
    assert_eq!(p.source, b[4096..8192]);
    for entry in [BASE, 0x2000, 0x3000, 0x4fff] {
        assert_eq!(
            select(&b, entry, CODE.len()).err(),
            Some(SetupRefusal::SymbolOwner)
        );
    }
    let mut limit = stripped();
    limit[0x1010..0x1110].fill(0x90);
    limit[0x110f] = 0xc3;
    assert_eq!(select(&limit, BASE, 256).unwrap().code.len(), 256);
    assert_eq!(
        select(&limit, BASE, 257).err(),
        Some(SetupRefusal::SymbolOwner)
    );
}

#[test]
fn known_overlap_and_legacy_refusal_order_remain_strict() {
    let b = fixture();
    assert!(select(&b, BASE, CODE.len()).is_ok());
    for (entry, length) in [
        (BASE + 25, 3),
        (BASE, CODE.len() - 1),
        (BASE - 1, CODE.len() + 1),
    ] {
        assert_eq!(
            select(&b, entry, length).err(),
            Some(SetupRefusal::EntryExit)
        );
    }
    let mut bad = b.clone();
    bad[0x21c] = 0x1a; // A visible dynamic IFUNC cannot become range authority.
    assert_eq!(
        select(&bad, BASE, CODE.len()).err(),
        Some(SetupRefusal::Relocation)
    );
    // Named selection validation still precedes the global IFUNC check.
    assert_eq!(
        parse(&bad, "checksum").err(),
        Some(SetupRefusal::SymbolOwner)
    );
    assert_eq!(parse(&bad, "absent").err(), Some(SetupRefusal::SymbolOwner));
    bad[0x21c] = 0x12;
    w64(&mut bad, 0x2050, 12); // Unsupported constructor before name lookup.
    assert_eq!(parse(&bad, "absent").err(), Some(SetupRefusal::Format));
    assert_eq!(
        select(&bad, BASE, CODE.len()).err(),
        Some(SetupRefusal::Format)
    );
}

#[test]
fn range_selection_keeps_elf_and_complete_cfg_refusals() {
    let b = stripped();
    assert!(select(&b, BASE, CODE.len()).is_ok());
    for tag in [1, 7, 12, 13, 17, 22, 23, 25, 26, 29, 35, 36, 37] {
        let mut bad = b.clone();
        w64(&mut bad, 0x2050, tag);
        assert_eq!(
            select(&bad, BASE, CODE.len()).err(),
            Some(SetupRefusal::Format)
        );
    }
    for (at, value) in [(16, 2), (18, 3), (64 + 56 + 4, 7)] {
        let mut bad = b.clone();
        bad[at] = value;
        assert!(select(&bad, BASE, CODE.len()).is_err());
    }
    for (offset, value) in [(4, 0x15), (23, 0xe8), (24, 0x40), (27, 0x90)] {
        let mut bad = b.clone();
        bad[0x1010 + offset] = value;
        assert_eq!(
            select(&bad, BASE, CODE.len()).err(),
            Some(SetupRefusal::EntryExit)
        );
    }
    let mut oversized = b;
    oversized.resize(1024 * 1024 + 1, 0);
    assert_eq!(
        select(&oversized, BASE, CODE.len()).err(),
        Some(SetupRefusal::Format)
    );
}

#[test]
fn missing_symbols_do_not_prove_function_completeness() {
    let b = stripped();
    // These three bytes form a valid independent CFG but are an interior tail
    // of the authored 28-byte function. Pure admission cannot detect that fact.
    // It remains forbidden by load_selected's unsafe complete-metadata contract.
    assert_eq!(select(&b, BASE + 25, 3).unwrap().code, &[0x31, 0xc0, 0xc3]);
}

#[test]
fn resolver_checks_handle_bias_and_containing_object_without_symbol_fallback() {
    assert_eq!(selected::relocated_entry(0x400000, BASE), Ok(0x401010));
    assert_eq!(selected::object_identity(0x400000, true, 0x400000), Ok(()));
    for (bias, entry) in [(0x400001, BASE), (!4095_u64, 4096), (0, 0)] {
        assert_eq!(
            selected::relocated_entry(bias, entry),
            Err(SetupRefusal::SymbolOwner)
        );
    }
    for (found, base) in [(false, 0x400000), (true, 0x500000), (true, 0)] {
        assert_eq!(
            selected::object_identity(0x400000, found, base),
            Err(SetupRefusal::SymbolOwner)
        );
    }
}
