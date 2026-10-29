//! Fabricated source bytes run only through actual pure admission; no loaded owner.
use super::*;
const PE: u64 = 0x1100;
const CE: u64 = 0x1200;
const CHILD: &[u8] = &[0x48, 0x89, 0xf0, 0x48, 0x83, 0xc0, 1, 0xc3];
fn fix_call(code: &mut [u8], entry: u64, target: u64) {
    let at = code.iter().position(|&b| b == 0xe8).unwrap();
    let displacement =
        i32::try_from(i128::from(target) - i128::from(entry + at as u64 + 5)).unwrap();
    code[at + 1..at + 5].copy_from_slice(&displacement.to_le_bytes());
}
fn code(entry: u64, child: u64, frame: u8) -> Vec<u8> {
    let mut b = vec![
        0x48, 0x83, 0xec, frame, 0x48, 0x89, 0x74, 0x24, 8, 0xe8, 0, 0, 0, 0, 0x48, 0x8b, 0x54,
        0x24, 8, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0x48, 0x83, 0xc4, frame, 0xc3,
    ];
    fix_call(&mut b, entry, child);
    b
}
fn elf() -> Vec<u8> {
    let mut bytes = super::super::tests::fixture();
    let parent = code(PE, CE, 24);
    bytes[PE as usize..PE as usize + parent.len()].copy_from_slice(&parent);
    bytes[CE as usize..CE as usize + CHILD.len()].copy_from_slice(CHILD);
    bytes
}
#[test]
fn parent_dataflow_accepts_distinct_frames_and_preserves_roles() {
    for frame in [24, 40, 56] {
        let bytes = code(PE, CE, frame);
        let (p, child) = certify(&bytes, PE, CHILD, CE).unwrap();
        assert_eq!(p.range(), (PE, PE + 31));
        assert_eq!(p.entries(), [PE, PE + 14]);
        assert_eq!(
            p.heads(),
            [
                PE,
                PE + 4,
                PE + 9,
                PE + 14,
                PE + 19,
                PE + 23,
                PE + 26,
                PE + 30
            ]
        );
        assert_eq!(p.blocks(), [(PE, PE + 9), (PE + 14, PE + 31)]);
        assert_eq!(p.edges().len(), 7);
        assert_eq!(p.returns(), [PE + 30]);
        assert_eq!(p.call_rsp_offset(), -i32::from(frame));
        assert_eq!(p.child_stack_delta(), u64::from(frame) + 8);
        assert_eq!(p.stack_allocation(), u64::from(frame));
        assert_eq!(p.initialized_stack_words(), [8 - i32::from(frame)]);
        assert_eq!(p.call().callee_entry(), child.entry());
        assert!(cfg::admit(&bytes, PE).is_err()); // old leaf admission still refuses CALL
    }
    // A second emitted shape uses a preserved frame base, initialized spill and POP.
    let mut other = vec![
        0x53, 0x48, 0x83, 0xec, 16, 0x48, 0x8d, 0x5c, 0x24, 8, 0x48, 0x89, 0x33, 0xe8, 0, 0, 0, 0,
        0x48, 0x8b, 0x13, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0x48, 0x83, 0xc4, 16, 0x5b, 0xc3,
    ];
    fix_call(&mut other, PE, CE);
    let p = parent::admit(&other, PE).unwrap();
    assert_eq!(p.call_rsp_offset(), -24);
    assert_eq!(p.initialized_stack_words(), [-16, -8]);
    let reverse = code(CE, PE, 24);
    assert_eq!(
        certify(&reverse, CE, CHILD, PE)
            .unwrap()
            .0
            .call()
            .callee_entry(),
        PE
    );
    let mut maximum = code(PE, CE, 24);
    maximum.pop();
    maximum.resize(79, 0x90);
    maximum.push(0xc3);
    assert_eq!(parent::admit(&maximum, PE).unwrap().range().1, PE + 80);
    maximum.insert(79, 0x90);
    assert!(parent::admit(&maximum, PE).is_err());
}
#[test]
fn parent_rejects_edges_and_incomplete_geometry() {
    let bytes = code(PE, CE, 24);
    for target in [PE, PE + 4, CE + 1, CE + 0x100] {
        let mut bad = bytes.clone();
        fix_call(&mut bad, PE, target);
        assert!(certify(&bad, PE, CHILD, CE).is_err());
    }
    for replacement in [
        vec![0xff, 0xd0, 0x90, 0x90, 0x90],
        vec![0xe9, 0, 0, 0, 0],
        vec![0x90; 5],
        vec![0xc3, 0x90, 0x90, 0x90, 0x90],
    ] {
        let mut bad = bytes.clone();
        bad[9..14].copy_from_slice(&replacement);
        assert!(parent::admit(&bad, PE).is_err());
    }
    let mut extra = bytes.clone();
    extra.splice(14..14, bytes[9..14].iter().copied());
    assert!(parent::admit(&extra, PE).is_err());
    for length in 0..bytes.len() {
        assert!(parent::admit(&bytes[..length], PE).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0x90);
    assert!(parent::admit(&trailing, PE).is_err());
    assert!(parent::admit(&bytes, 0).is_err());
    assert!(parent::admit(&bytes, u64::MAX - 8).is_err());
}
#[test]
fn parent_rejects_wrong_arguments_clobber_and_uninitialized_stack() {
    for instruction in [[0x48, 0x89, 0xf7], [0x48, 0x89, 0xfe], [0x48, 0x89, 0xf3]] {
        let mut bad = code(PE, CE, 24);
        bad.splice(9..9, instruction);
        fix_call(&mut bad, PE, CE);
        assert!(parent::admit(&bad, PE).is_err());
    }
    let mut bad = code(PE, CE, 24);
    bad[18] = 0;
    assert!(parent::admit(&bad, PE).is_err()); // initialized word is at RSP+8 only
    let mut bad = code(PE, CE, 24);
    bad.drain(14..19);
    assert!(parent::admit(&bad, PE).is_err()); // caller-saved RDX was invalidated by CALL
    let mut bad = code(PE, CE, 24);
    bad[22] = 31;
    assert!(parent::admit(&bad, PE).is_err());
    let mut bad = code(PE, CE, 24);
    bad[25] = 0xc0;
    assert!(parent::admit(&bad, PE).is_err()); // OR RAX,RAX does not incorporate length
    let mut bad = code(PE, CE, 24);
    bad[6] = 0x7c;
    assert!(parent::admit(&bad, PE).is_err()); // wrong encoded input/length storage
}
#[test]
fn parent_rejects_bad_frame_restoration_prefixes_and_unsupported_ops() {
    for frame in [0, 8, 16, 64, 72] {
        assert!(parent::admit(&code(PE, CE, frame), PE).is_err());
    }
    let mut bad = code(PE, CE, 24);
    bad[29] = 16;
    assert!(parent::admit(&bad, PE).is_err());
    for prefix in [0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x48] {
        let mut bad = code(PE, CE, 24);
        bad.insert(0, prefix);
        fix_call(&mut bad, PE, CE);
        assert!(parent::admit(&bad, PE).is_err());
    }
    for instruction in [
        vec![0x31, 0xc0],
        vec![0x75, 0],
        vec![0xc2, 0, 0],
        vec![0x48, 0x89, 0x07],
    ] {
        let mut bad = code(PE, CE, 24);
        bad.splice(14..14, instruction);
        assert!(parent::admit(&bad, PE).is_err());
    }
}
#[test]
fn pair_selection_and_contract_require_independent_disjoint_source() {
    let bytes = elf();
    let p = TrustedFunctionSelection::new(&bytes, PE, 31, "parent").unwrap();
    let c = TrustedFunctionSelection::new(&bytes, CE, CHILD.len(), "child").unwrap();
    let parsed = preflight(&p, &c).unwrap();
    assert_eq!(parsed[0].code, code(PE, CE, 24));
    assert_eq!(parsed[1].code, CHILD);
    assert!(selection::parse(&p).is_err());
    assert!(preflight(&c, &p).is_err());
    assert!(selections(&p, &p).is_err());
    let overlap = TrustedFunctionSelection::new(&bytes, PE + 1, 31, "overlap").unwrap();
    assert!(selections(&p, &overlap).is_err());
    let mut changed = bytes.clone();
    changed[0x3000] ^= 1;
    let other = TrustedFunctionSelection::new(&changed, CE, CHILD.len(), "other").unwrap();
    assert!(selections(&p, &other).is_err());
    for (at, value) in [(16, 2), (64 + 56 + 4, 7), (0x21c, 0x1a)] {
        let mut bad = bytes.clone();
        bad[at] = value;
        let a = TrustedFunctionSelection::new(&bad, PE, 31, "parent").unwrap();
        let b = TrustedFunctionSelection::new(&bad, CE, CHILD.len(), "child").unwrap();
        assert!(preflight(&a, &b).is_err());
    }
    let contract = NormalCallPairContract {
        parent_only_external_entry: true,
        ordinary_ret_only: true,
        no_active_cet: true,
    };
    assert_eq!(contract.check(), Ok(()));
    assert_eq!(
        NormalCallPairContract {
            parent_only_external_entry: false,
            ..contract
        }
        .check(),
        Err(SetupRefusal::EntryExit)
    );
    assert_eq!(
        NormalCallPairContract {
            ordinary_ret_only: false,
            ..contract
        }
        .check(),
        Err(SetupRefusal::ExitSemantics)
    );
    assert_eq!(
        NormalCallPairContract {
            no_active_cet: false,
            ..contract
        }
        .check(),
        Err(SetupRefusal::Cet)
    );
}
#[test]
fn pair_overlay_and_page_union_preserve_call_and_untouched_bytes() {
    let (parent, child) = certify(&code(PE, CE, 24), PE, CHILD, CE).unwrap();
    let original = normal_module::canonical_page_slice(&[(0x1000, &vec![0xa5; 4096])]).unwrap();
    let mut expected = original.clone();
    expected[0].bytes[0x100] ^= 1;
    expected[0].bytes[0x10e] ^= 1;
    expected[0].bytes[0x200] ^= 1;
    assert_eq!(check_overlay(&original, &expected, &parent, &child), Ok(()));
    for offset in [
        0, 0xff, 0x109, 0x10a, 0x10b, 0x10c, 0x10d, 0x11f, 0x208, 4095,
    ] {
        let mut bad = expected.clone();
        bad[0].bytes[offset] ^= 1;
        assert_eq!(
            check_overlay(&original, &bad, &parent, &child),
            Err(SetupRefusal::SourceBytes)
        );
    }
    assert!(check_overlay(&original, &[], &parent, &child).is_err());
    let a = vec![0; 4096];
    let mut b = a.clone();
    b[4095] = 1;
    assert!(normal_module::canonical_page_slice(&[(0x1000, &a), (0x1000, &b)]).is_err());
    assert!(
        normal_module::canonical_page_slice(&[(0x1000, &a), (0x3000, &a), (0x5000, &a)]).is_err()
    );
    let sparse = normal_module::canonical_page_slice(&[(0x5000, &a), (0x1000, &a)]).unwrap();
    assert_eq!(
        sparse.iter().map(|p| p.address).collect::<Vec<_>>(),
        [0x1000, 0x5000]
    );
}
