//! Additive pure fixed-grammar controls; no loader call or native execution.
use super::*;

#[repr(C, align(8))]
struct AlignedBranch([u8; include_bytes!(env!("NATIVE_BRANCH_DSO")).len()]);

static ALIGNED_BRANCH: AlignedBranch = AlignedBranch(*include_bytes!(env!("NATIVE_BRANCH_DSO")));
const BRANCH: &[u8] = &ALIGNED_BRANCH.0;

fn changed_body(offset: usize, byte: u8) -> AlignedBranch {
    let elf = parse_branch(BRANCH).expect("the fixed original branch grammar");
    let at = file_range(&elf.loads, elf.entry, 36).unwrap();
    let mut copy = AlignedBranch(*include_bytes!(env!("NATIVE_BRANCH_DSO")));
    copy.0[at + offset] = byte;
    copy
}

#[test]
fn branch_fixture_has_explicit_alignment_and_exact_bytes() {
    let alignment = std::mem::align_of::<object::elf::FileHeader64<object::Endianness>>();
    assert_eq!(BRANCH.as_ptr().align_offset(8), 0);
    assert_eq!(BRANCH.as_ptr().align_offset(alignment), 0);
    assert_eq!(BRANCH, include_bytes!(env!("NATIVE_BRANCH_DSO")));
}

#[test]
fn branch_parser_accepts_complete_source_grammar() {
    let elf = parse_branch(BRANCH).expect("complete authored branch grammar");
    assert_eq!(elf.loads.len(), 4);
    assert_eq!(elf.code.len(), 36);
    assert_eq!(
        &elf.code[..8],
        &[0x48, 0x8d, 0x44, 0x7f, 0x07, 0x4c, 0x8b, 0x15]
    );
    assert_eq!(
        &elf.code[12..],
        &[
            0x49, 0x03, 0x02, 0x48, 0x83, 0xff, 0x00, 0x75, 0x07, 0x48, 0x8d, 0x00, 0x48, 0x89,
            0x06, 0xc3, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x89, 0x06, 0xc3,
        ]
    );
    assert_eq!((elf.code[27], elf.code[35]), (0xc3, 0xc3));
    assert_eq!(21 + u64::from(elf.code[20]), 28);
    assert_eq!(
        i128::from(elf.entry)
            + 12
            + i128::from(i32::from_le_bytes(elf.code[8..12].try_into().unwrap())),
        i128::from(elf.pointer)
    );
    assert_eq!(
        branch_exit_claims(elf.entry, &[elf.entry + 27, elf.entry + 35]),
        Ok(())
    );
}

#[test]
fn branch_parser_rejects_changed_condition() {
    let changed = changed_body(17, 0xfe);
    assert_eq!(
        parse_branch(&changed.0).err(),
        Some(SetupRefusal::SourceBytes)
    );
}

#[test]
fn branch_parser_rejects_changed_branch_destination() {
    let changed = changed_body(20, 8);
    assert_eq!(
        parse_branch(&changed.0).err(),
        Some(SetupRefusal::SourceBytes)
    );
}

#[test]
fn branch_parser_rejects_changed_return_opcode() {
    for offset in [27, 35] {
        let changed = changed_body(offset, 0x90);
        assert_eq!(
            parse_branch(&changed.0).err(),
            Some(SetupRefusal::SourceBytes)
        );
    }
}

#[test]
fn branch_exit_claim_rejects_missing_return() {
    let elf = parse_branch(BRANCH).unwrap();
    assert_eq!(
        branch_exit_claims(elf.entry, &[elf.entry + 27]),
        Err(SetupRefusal::EntryExit)
    );
}

#[test]
fn branch_exit_claim_rejects_duplicate_return() {
    let elf = parse_branch(BRANCH).unwrap();
    assert_eq!(
        branch_exit_claims(elf.entry, &[elf.entry + 27, elf.entry + 27]),
        Err(SetupRefusal::EntryExit)
    );
}

#[test]
fn branch_exit_claim_rejects_non_return_head() {
    let elf = parse_branch(BRANCH).unwrap();
    assert_eq!(
        branch_exit_claims(elf.entry, &[elf.entry + 24, elf.entry + 35]),
        Err(SetupRefusal::EntryExit)
    );
}

#[test]
fn branch_exit_claim_rejects_foreign_owner() {
    let elf = parse_branch(BRANCH).unwrap();
    // Pure owner-range refusal; real foreign-RET ownership is a native case.
    assert_eq!(
        branch_exit_claims(elf.entry, &[elf.entry + 27, elf.entry + 36]),
        Err(SetupRefusal::SymbolOwner)
    );
}
