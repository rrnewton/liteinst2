//! Closed two-function admission only. No tree gate or execution authority.
//!
//! The root CALL must remain at its original PC in any later installation.
//! A separate deeper-stack instrumentation profile is required before execution;
//! this certificate does not qualify the ordinary leaf emitter for nested calls.
use super::{
    BodyOverlay, IntegerLeafCertificate, Parsed, Retained, SetupRefusal, cfg, loaded_symbol,
    parse_admitted, retain_loader, verify_expected_bodies,
};
use object::{Object, ObjectSymbol, SymbolFlags};
use std::ffi::CStr;
use std::path::Path;

const ROOT_BYTES: [u8; 23] = [
    0x48, 0x83, 0xec, 0x08, 0xb8, 0, 0, 0, 0, 0xe8, 0x12, 0, 0, 0, 0x48, 0x83, 0xc0, 0x01, 0x48,
    0x83, 0xc4, 0x08, 0xc3,
];
const CALLEE_BYTES: [u8; 39] = [
    0x48, 0x8b, 0x4f, 0x10, 0x31, 0xc0, 0x31, 0xd2, 0x4c, 0x8b, 0x44, 0x17, 0x08, 0x4c, 0x01, 0xc0,
    0x48, 0x8b, 0x14, 0x17, 0x48, 0xff, 0xc9, 0x75, 0xef, 0x48, 0xba, 0x15, 0x7c, 0x4a, 0x7f, 0xb9,
    0x79, 0x37, 0x9e, 0x48, 0x31, 0xd0, 0xc3,
];
const CHILD_OFFSET: u64 = 32;

/// External facts not established by ELF or instruction inspection.
#[derive(Clone, Copy, Debug)]
pub struct TreeContract {
    /// Only the root has an external caller. The sole child entry/return is
    /// the declared root CALL/+14 edge, with no foreign or saved interior entry.
    pub root_only_external_entry: bool,
    /// Both functions return normally; no unwind, longjmp or cancellation.
    pub ordinary_ret_only: bool,
    /// No active IBT or shadow stack; neither is disabled by this module.
    pub no_active_cet: bool,
}
impl TreeContract {
    fn check(self) -> Result<(), SetupRefusal> {
        if !self.root_only_external_entry {
            return Err(SetupRefusal::EntryExit);
        }
        if !self.ordinary_ret_only {
            return Err(SetupRefusal::ExitSemantics);
        }
        if !self.no_active_cet {
            return Err(SetupRefusal::Cet);
        }
        Ok(())
    }
}

/// Original source edge, not a saved-return token or relocated-CALL permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeCallEdge {
    call_pc: u64,
    callee_entry: u64,
    continuation: u64,
}
impl TreeCallEdge {
    pub fn call_pc(&self) -> u64 {
        self.call_pc
    }
    pub fn callee_entry(&self) -> u64 {
        self.callee_entry
    }
    pub fn continuation(&self) -> u64 {
        self.continuation
    }
    /// All five original CALL bytes must remain outside displaced/written spans.
    pub fn unrelocated_range(&self) -> (u64, u64) {
        (self.call_pc, self.continuation)
    }
}

/// Fixed caller geometry, deliberately not an IntegerLeafCertificate.
#[derive(Debug)]
pub struct TreeRootCertificate {
    entry: u64,
    end: u64,
    heads: [u64; 6],
    entries: [u64; 2],
    returns: [u64; 1],
    blocks: [(u64, u64); 2],
    edge: TreeCallEdge,
}
impl TreeRootCertificate {
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn range(&self) -> (u64, u64) {
        (self.entry, self.end)
    }
    pub fn heads(&self) -> &[u64] {
        &self.heads
    }
    /// Root entry and the declared original saved-resume PC; not foreign entries.
    pub fn entries(&self) -> &[u64] {
        &self.entries
    }
    pub fn returns(&self) -> &[u64] {
        &self.returns
    }
    pub fn blocks(&self) -> &[(u64, u64)] {
        &self.blocks
    }
    pub fn call(&self) -> TreeCallEdge {
        self.edge
    }
    /// Root entry RSP minus child entry RSP, from SUB 8 followed by real CALL.
    pub fn child_stack_delta(&self) -> u64 {
        16
    }
}

/// One complete closed root/child graph. No publication, frame or owner escapes.
#[derive(Debug)]
pub struct CallTreeCertificate {
    root: TreeRootCertificate,
    callee: IntegerLeafCertificate,
}
impl CallTreeCertificate {
    pub fn root(&self) -> &TreeRootCertificate {
        &self.root
    }
    pub fn callee(&self) -> &IntegerLeafCertificate {
        &self.callee
    }
    pub fn max_depth(&self) -> usize {
        2
    }
}

fn admit_root(code: &[u8], base: u64) -> Result<(), SetupRefusal> {
    if code != ROOT_BYTES || base == 0 || base.checked_add(ROOT_BYTES.len() as u64).is_none() {
        return Err(SetupRefusal::EntryExit);
    }
    Ok(())
}
fn admit_callee(code: &[u8], base: u64) -> Result<(), SetupRefusal> {
    if code != CALLEE_BYTES {
        return Err(SetupRefusal::EntryExit);
    }
    cfg::admit(code, base)?;
    Ok(())
}
fn certify(
    root: &[u8],
    root_entry: u64,
    callee: &[u8],
    callee_entry: u64,
) -> Result<CallTreeCertificate, SetupRefusal> {
    admit_root(root, root_entry)?;
    admit_callee(callee, callee_entry)?;
    let refusal = SetupRefusal::EntryExit;
    let end = root_entry
        .checked_add(ROOT_BYTES.len() as u64)
        .ok_or(refusal)?;
    let continuation = root_entry.checked_add(14).ok_or(refusal)?;
    let displacement = i32::from_le_bytes(root[10..14].try_into().map_err(|_| refusal)?);
    let target =
        u64::try_from(i128::from(continuation) + i128::from(displacement)).map_err(|_| refusal)?;
    if root_entry.checked_add(CHILD_OFFSET) != Some(callee_entry)
        || target != callee_entry
        || end > callee_entry
    {
        return Err(refusal);
    }
    // Exact byte equality above proves these six encodings and their full ends.
    // All offset additions are bounded by the checked root end.
    let heads = [0, 4, 9, 14, 18, 22].map(|offset| root_entry + offset);
    Ok(CallTreeCertificate {
        root: TreeRootCertificate {
            entry: root_entry,
            end,
            heads,
            entries: [root_entry, continuation],
            returns: [root_entry + 22],
            blocks: [(root_entry, continuation), (continuation, end)],
            edge: TreeCallEdge {
                call_pc: root_entry + 9,
                callee_entry,
                continuation,
            },
        },
        callee: cfg::admit(callee, callee_entry)?,
    })
}

fn parse_tree(
    bytes: &[u8],
    root_name: &str,
    callee_name: &str,
) -> Result<(Parsed, Parsed), SetupRefusal> {
    if root_name == callee_name {
        return Err(SetupRefusal::SymbolOwner);
    }
    // Two bounded pure passes reuse ALL existing envelope/ownership/symbol
    // guards. They do not create two loader handles or two mapping owners.
    let root = parse_admitted(bytes, root_name, admit_root)?;
    let callee = parse_admitted(bytes, callee_name, admit_callee)?;
    let file = object::File::parse(bytes).map_err(|_| SetupRefusal::Format)?;
    for name in [root_name, callee_name] {
        let rows: Vec<_> = file
            .dynamic_symbols()
            .filter(|s| s.name() == Ok(name) && s.is_definition())
            .collect();
        if rows.len() != 1
            || !matches!(
                rows[0].flags(),
                SymbolFlags::Elf {
                    st_info: 0x12,
                    st_other: 3
                }
            )
        {
            return Err(SetupRefusal::SymbolOwner);
        }
    }
    certify(&root.code, root.entry, &callee.code, callee.entry)?;
    if root.page != callee.page
        || root.page_offset != callee.page_offset
        || root.source.len() != 4096
        || callee.source != root.source
    {
        return Err(SetupRefusal::SymbolOwner);
    }
    Ok((root, callee))
}

/// One retained loader handle/fd for both functions and their complete shared RX
/// page. This exposes no callable pointer, writable code or publication authority.
pub struct LoadedCallTree {
    owner: &'static mut Retained,
    parsed: Parsed,
    callee_code: Vec<u8>,
    certificate: CallTreeCertificate,
    source_start: u64,
}
impl LoadedCallTree {
    /// Authenticate both named protected symbols and retain one ordinary loader
    /// owner. Calling or publishing requires the separate tree execution profile.
    ///
    /// # Safety
    /// `expected` is independently trusted complete ELF output, not a candidate
    /// self-hash. The root is the only external entry, and its direct E8 is the
    /// only child caller. One controlled calling thread, quiescence, ordinary
    /// exact SysV `(*const u8, usize) -> u64` behavior for both functions,
    /// immutable input with every actual qword read in bounds, bounded stack,
    /// termination of the count/offset-linked child loop,
    /// no CET, signal, nonlocal exit, alias writer, fork, unload or mapping change
    /// must hold through last use. No current leaf gate/emitter is qualified for
    /// this tree by successful admission. The original file stays immutable.
    pub unsafe fn load(
        path: &Path,
        expected: &[u8],
        root_symbol: &CStr,
        callee_symbol: &CStr,
        contract: TreeContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        let root_name = root_symbol
            .to_str()
            .map_err(|_| SetupRefusal::SymbolOwner)?;
        let callee_name = callee_symbol
            .to_str()
            .map_err(|_| SetupRefusal::SymbolOwner)?;
        let (parsed, child) = parse_tree(expected, root_name, callee_name)?;
        // SAFETY: both complete private parsers and explicit external contract.
        let owner = unsafe { retain_loader(path, expected)? };
        let (entry, bias) = loaded_symbol(owner, &parsed, root_symbol)?;
        let (callee_entry, callee_bias) = loaded_symbol(owner, &child, callee_symbol)?;
        if bias != callee_bias {
            return Err(SetupRefusal::SymbolOwner);
        }
        let source_start = bias.checked_add(parsed.page).ok_or(SetupRefusal::Format)?;
        let certificate = certify(&parsed.code, entry, &child.code, callee_entry)?;
        let loaded = Box::leak(Box::new(Self {
            owner,
            parsed,
            callee_code: child.code,
            certificate,
            source_start,
        }));
        loaded.verify_original()?;
        Ok(loaded)
    }
    pub fn certificate(&self) -> &CallTreeCertificate {
        &self.certificate
    }
    pub fn root_code(&self) -> &[u8] {
        &self.parsed.code
    }
    pub fn callee_code(&self) -> &[u8] {
        &self.callee_code
    }
    pub fn source_range(&self) -> (u64, u64) {
        (
            self.source_start,
            self.source_start + self.parsed.source.len() as u64,
        )
    }
    pub fn original_source(&self) -> &[u8] {
        &self.parsed.source
    }
    pub fn verify_original(&mut self) -> Result<(), SetupRefusal> {
        let root = self.parsed.code.clone();
        let callee = self.callee_code.clone();
        self.verify_expected_patch(&root, &callee)
    }
    // Only a later sealed tree factory may supply its two validated whole-body
    // overlays. Padding, CALL bytes and all other source bytes remain original.
    pub(in crate::frontend_native) fn verify_expected_patch(
        &mut self,
        root: &[u8],
        callee: &[u8],
    ) -> Result<(), SetupRefusal> {
        if root.len() != ROOT_BYTES.len()
            || callee.len() != CALLEE_BYTES.len()
            || root.get(9..14) != self.parsed.code.get(9..14)
        {
            return Err(SetupRefusal::SourceBytes);
        }
        verify_expected_bodies(
            self.owner,
            &self.parsed,
            self.certificate.root.entry,
            self.source_start,
            root,
            Some(BodyOverlay {
                entry: self.certificate.callee.entry(),
                expected: callee,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_admission_exact_original_call_and_resume_geometry() {
        let tree = certify(&ROOT_BYTES, 0x1010, &CALLEE_BYTES, 0x1030).unwrap();
        assert_eq!(
            tree.root().heads(),
            &[0x1010, 0x1014, 0x1019, 0x101e, 0x1022, 0x1026]
        );
        assert_eq!(tree.root().range(), (0x1010, 0x1027));
        assert_eq!(tree.root().entries(), &[0x1010, 0x101e]);
        assert_eq!(tree.root().call().unrelocated_range(), (0x1019, 0x101e));
        assert_eq!(tree.root().call().callee_entry(), 0x1030);
        assert_eq!(tree.callee().returns(), &[0x1056]);
        assert_eq!((tree.max_depth(), tree.root().child_stack_delta()), (2, 16));
        // The existing leaf grammar must still reject the actual caller.
        assert_eq!(
            cfg::admit(&ROOT_BYTES, 0x1010).err(),
            Some(SetupRefusal::EntryExit)
        );
    }

    #[test]
    fn tree_admission_changed_call_stack_ret_or_callee_refuses() {
        for at in [0, 3, 9, 10, 14, 18, 21, 22] {
            let mut root = ROOT_BYTES;
            root[at] ^= 1;
            assert_eq!(
                certify(&root, 0x1010, &CALLEE_BYTES, 0x1030).err(),
                Some(SetupRefusal::EntryExit)
            );
        }
        for at in [3, 12, 19, 24, 38] {
            let mut child = CALLEE_BYTES;
            child[at] ^= 1;
            assert_eq!(
                certify(&ROOT_BYTES, 0x1010, &child, 0x1030).err(),
                Some(SetupRefusal::EntryExit)
            );
        }
        for child in [0x1010, 0x1019, 0x1031, u64::MAX] {
            assert!(certify(&ROOT_BYTES, 0x1010, &CALLEE_BYTES, child).is_err());
        }
        assert!(certify(&ROOT_BYTES, u64::MAX - 20, &CALLEE_BYTES, 0x1030).is_err());
    }

    // Complete finite ELF input; no loader, mmap or executable subject is used.
    fn w16(b: &mut [u8], at: usize, value: u16) {
        b[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn w32(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn w64(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> Vec<u8> {
        let mut b = vec![0; 0x3400];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [
            (16, 3),
            (18, 62),
            (52, 64),
            (54, 56),
            (56, 6),
            (58, 64),
            (60, 6),
            (62, 5),
        ] {
            w16(&mut b, at, value);
        }
        w32(&mut b, 20, 1);
        w64(&mut b, 32, 64);
        w64(&mut b, 40, 0x3200);
        for (n, (kind, flags, offset, size)) in [
            (1, 4, 0, 4096),
            (1, 5, 4096, 4096),
            (1, 6, 8192, 4096),
            (2, 6, 8192, 112),
            (0x6474_e552, 4, 8192, 4096),
            (0x6474_e551, 6, 0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let p = 64 + n * 56;
            w32(&mut b, p, kind);
            w32(&mut b, p + 4, flags);
            for at in [8, 16, 24] {
                w64(&mut b, p + at, offset);
            }
            for at in [32, 40] {
                w64(&mut b, p + at, size);
            }
            w64(&mut b, p + 48, 4096);
        }
        b[0x1010..0x1027].copy_from_slice(&ROOT_BYTES);
        b[0x1030..0x1057].copy_from_slice(&CALLEE_BYTES);
        b[0x280..0x295].copy_from_slice(b"\0tree_root\0tree_work\0");
        let names = b"\0.text\0.dynsym\0.dynstr\0.dynamic\0.shstrtab\0";
        b[0x300..0x300 + names.len()].copy_from_slice(names);
        for (p, name, entry, size) in [(0x218, 1, 0x1010, 23), (0x230, 11, 0x1030, 39)] {
            w32(&mut b, p, name);
            b[p + 4] = 0x12;
            b[p + 5] = 3; // STV_PROTECTED
            w16(&mut b, p + 6, 1);
            w64(&mut b, p + 8, entry);
            w64(&mut b, p + 16, size);
        }
        // One SysV hash bucket, three symbols, root -> work -> end.
        for (n, value) in [1, 3, 1, 0, 2, 0].into_iter().enumerate() {
            w32(&mut b, 0x400 + n * 4, value);
        }
        for (n, (tag, value)) in [
            (4, 0x400),
            (5, 0x280),
            (6, 0x200),
            (10, 21),
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
        for (n, (name, kind, flags, offset, size, link, entsize)) in [
            (1, 1, 6, 0x1010, 71, 0, 0),
            (7, 11, 2, 0x200, 72, 3, 24),
            (15, 3, 2, 0x280, 21, 0, 0),
            (23, 6, 3, 0x2000, 112, 3, 16),
            (32, 3, 0, 0x300, names.len() as u64, 0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let section = n + 1;
            let p = 0x3200 + section * 64;
            w32(&mut b, p, name);
            w32(&mut b, p + 4, kind);
            w64(&mut b, p + 8, flags);
            w64(&mut b, p + 16, if flags & 2 != 0 { offset } else { 0 });
            w64(&mut b, p + 24, offset);
            w64(&mut b, p + 32, size);
            w32(&mut b, p + 40, link);
            w32(&mut b, p + 44, if section == 2 { 1 } else { 0 });
            w64(
                &mut b,
                p + 48,
                if matches!(section, 1 | 3 | 5) { 1 } else { 8 },
            );
            w64(&mut b, p + 56, entsize);
        }
        b
    }

    #[test]
    fn tree_admission_complete_elf_owns_both_protected_symbols_and_page() {
        let b = fixture();
        let (root, child) = parse_tree(&b, "tree_root", "tree_work").unwrap();
        assert_eq!((root.entry, child.entry), (0x1010, 0x1030));
        assert_eq!(
            (root.page, child.page, root.page_offset, child.page_offset),
            (4096, 4096, 4096, 4096)
        );
        assert_eq!(root.code, ROOT_BYTES);
        assert_eq!(child.code, CALLEE_BYTES);
        assert_eq!(root.source, b[4096..8192]);
        assert_eq!(child.source, root.source);
        // Root cannot gain execution authority through the old leaf parser.
        assert_eq!(
            super::super::parse(&b, "tree_root").err(),
            Some(SetupRefusal::EntryExit)
        );
        assert!(super::super::parse(&b, "tree_work").is_ok());
    }

    #[test]
    fn tree_admission_elf_visibility_alias_geometry_and_envelope_refuse() {
        let b = fixture();
        assert!(parse_tree(&b, "tree_root", "tree_work").is_ok());
        for (root, child) in [
            ("tree_root", "tree_root"),
            ("missing", "tree_work"),
            ("tree_work", "tree_root"),
        ] {
            assert!(parse_tree(&b, root, child).is_err());
        }
        for at in [0x21d, 0x235] {
            let mut bad = b.clone();
            bad[at] = 0; // Global default visibility is still valid for old leaves.
            assert!(parse_tree(&bad, "tree_root", "tree_work").is_err());
            if at == 0x235 {
                assert!(super::super::parse(&bad, "tree_work").is_ok());
            }
        }
        let mut duplicate = b.clone();
        w32(&mut duplicate, 0x230, 1); // Same name, distinct valid symbol rows.
        assert!(parse_tree(&duplicate, "tree_root", "tree_work").is_err());
        for (at, value) in [
            (0x238, 0x1019),      // Visible child overlaps root CALL.
            (0x238, 0x1031),      // Wrong original E8 target.
            (0x228, 22),          // Root omits its real RET.
            (0x240, 38),          // Child omits its real RET.
            (0x2050, 12),         // Constructor tag replaces BIND_NOW.
            (64 + 56 + 40, 4097), // BSS extension is not admitted.
        ] {
            let mut bad = b.clone();
            w64(&mut bad, at, value);
            assert!(parse_tree(&bad, "tree_root", "tree_work").is_err());
        }
        for at in [0x1019, 0x101a, 0x1026, 0x1056] {
            let mut bad = b.clone();
            bad[at] ^= 1;
            assert!(parse_tree(&bad, "tree_root", "tree_work").is_err());
        }
    }

    #[test]
    fn tree_admission_external_contract_is_not_inferred_from_bytes() {
        let good = TreeContract {
            root_only_external_entry: true,
            ordinary_ret_only: true,
            no_active_cet: true,
        };
        assert!(good.check().is_ok());
        assert_eq!(
            TreeContract {
                root_only_external_entry: false,
                ..good
            }
            .check(),
            Err(SetupRefusal::EntryExit)
        );
        assert_eq!(
            TreeContract {
                ordinary_ret_only: false,
                ..good
            }
            .check(),
            Err(SetupRefusal::ExitSemantics)
        );
        assert_eq!(
            TreeContract {
                no_active_cet: false,
                ..good
            }
            .check(),
            Err(SetupRefusal::Cet)
        );
    }
}
