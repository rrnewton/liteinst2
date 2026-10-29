//! A selected normal caller and leaf sharing one retained loader, not a gate.
use super::{
    IntegerLeafCertificate, Parsed, Retained, SetupRefusal, TrustedFunctionSelection, cfg,
    normal_module, retain_loader, selection, verify_live_source, verify_source_provenance,
};
use liteinst2::contracts::ExpectedBytes;
use std::path::Path;
mod parent;
#[cfg(test)]
mod tests;

/// External source/lifetime facts; the flags do not prove a native invocation.
#[derive(Clone, Copy, Debug)]
pub struct NormalCallPairContract {
    pub parent_only_external_entry: bool,
    pub ordinary_ret_only: bool,
    pub no_active_cet: bool,
}
impl NormalCallPairContract {
    fn check(self) -> Result<(), SetupRefusal> {
        if !self.parent_only_external_entry {
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
/// The one original E8; never permission to relocate or rewrite that CALL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalCallPairEdge {
    call_pc: u64,
    callee_entry: u64,
    continuation: u64,
}
impl NormalCallPairEdge {
    pub fn call_pc(&self) -> u64 {
        self.call_pc
    }
    pub fn callee_entry(&self) -> u64 {
        self.callee_entry
    }
    pub fn continuation(&self) -> u64 {
        self.continuation
    }
    pub fn unrelocated_range(&self) -> (u64, u64) {
        (self.call_pc, self.continuation)
    }
}
/// Complete emitted straight-line caller geometry and checked ABI dataflow.
/// Distinct from a leaf certificate; complete input/stack/native authority is external.
#[derive(Debug)]
pub struct NormalCallPairParentCertificate {
    entry: u64,
    end: u64,
    heads: Vec<u64>,
    entries: [u64; 2],
    returns: [u64; 1],
    blocks: [(u64, u64); 2],
    edges: Vec<(u64, u64)>,
    edge: NormalCallPairEdge,
    call_rsp: i32,
    child_stack_delta: u64,
    stack_allocation: u64,
    initialized: Vec<i32>,
}
impl NormalCallPairParentCertificate {
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn range(&self) -> (u64, u64) {
        (self.entry, self.end)
    }
    pub fn heads(&self) -> &[u64] {
        &self.heads
    }
    pub fn entries(&self) -> &[u64] {
        &self.entries
    }
    pub fn returns(&self) -> &[u64] {
        &self.returns
    }
    pub fn blocks(&self) -> &[(u64, u64)] {
        &self.blocks
    }
    pub fn edges(&self) -> &[(u64, u64)] {
        &self.edges
    }
    pub fn call(&self) -> NormalCallPairEdge {
        self.edge
    }
    pub fn call_rsp_offset(&self) -> i32 {
        self.call_rsp
    }
    pub fn child_stack_delta(&self) -> u64 {
        self.child_stack_delta
    }
    pub fn stack_allocation(&self) -> u64 {
        self.stack_allocation
    }
    pub fn initialized_stack_words(&self) -> &[i32] {
        &self.initialized
    }
}
pub struct NormalCallPairParent {
    label: String,
    parsed: Parsed,
    certificate: NormalCallPairParentCertificate,
    source_start: u64,
}
impl NormalCallPairParent {
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn entry(&self) -> u64 {
        self.certificate.entry()
    }
    pub fn elf_range(&self) -> (u64, u64) {
        (
            self.parsed.entry,
            self.parsed.entry + self.parsed.code.len() as u64,
        )
    }
    pub fn code(&self) -> &[u8] {
        &self.parsed.code
    }
    pub fn certificate(&self) -> &NormalCallPairParentCertificate {
        &self.certificate
    }
}
pub struct NormalCallPairChild {
    label: String,
    parsed: Parsed,
    certificate: IntegerLeafCertificate,
    source_start: u64,
}
impl NormalCallPairChild {
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn entry(&self) -> u64 {
        self.certificate.entry()
    }
    pub fn elf_range(&self) -> (u64, u64) {
        (
            self.parsed.entry,
            self.parsed.entry + self.parsed.code.len() as u64,
        )
    }
    pub fn code(&self) -> &[u8] {
        &self.parsed.code
    }
    pub fn certificate(&self) -> &IntegerLeafCertificate {
        &self.certificate
    }
}
/// One process-lived file/loader and the exact sorted one/two-page source union.
pub struct LoadedNormalCallPair {
    owner: &'static mut Retained,
    parent: NormalCallPairParent,
    child: NormalCallPairChild,
    pages: Vec<ExpectedBytes>,
}
fn selections(
    parent: &TrustedFunctionSelection<'_>,
    child: &TrustedFunctionSelection<'_>,
) -> Result<(), SetupRefusal> {
    let ordered = if parent.elf_range().0 < child.elf_range().0 {
        [parent, child]
    } else {
        [child, parent]
    };
    normal_module::check_selection_slice(&ordered)
}
fn certify(
    parent_code: &[u8],
    parent_entry: u64,
    child_code: &[u8],
    child_entry: u64,
) -> Result<(NormalCallPairParentCertificate, IntegerLeafCertificate), SetupRefusal> {
    let parent = parent::admit(parent_code, parent_entry)?;
    let child = cfg::admit(child_code, child_entry)?;
    if parent.call().callee_entry() != child.entry()
        || !(parent.range().1 <= child.entry() || child.range().1 <= parent.entry())
    {
        return Err(SetupRefusal::EntryExit);
    }
    Ok((parent, child))
}
fn preflight(
    parent: &TrustedFunctionSelection<'_>,
    child: &TrustedFunctionSelection<'_>,
) -> Result<[Parsed; 2], SetupRefusal> {
    selections(parent, child)?;
    let parent =
        selection::parse_with(parent, |code, entry| parent::admit(code, entry).map(|_| ()))?;
    let child = selection::parse(child)?;
    certify(&parent.code, parent.entry, &child.code, child.entry)?;
    normal_module::canonical_page_slice(&[
        (parent.page, &parent.source),
        (child.page, &child.source),
    ])?;
    Ok([parent, child])
}
fn check_overlay(
    original: &[ExpectedBytes],
    expected: &[ExpectedBytes],
    parent: &NormalCallPairParentCertificate,
    child: &IntegerLeafCertificate,
) -> Result<(), SetupRefusal> {
    // Even a publication overlay may not change one of the five original CALL bytes.
    normal_module::check_overlay_slice(
        original,
        expected,
        &[
            (parent.entry(), parent.call().call_pc()),
            (parent.call().continuation(), parent.range().1),
            child.range(),
        ],
    )
}
impl LoadedNormalCallPair {
    /// Authenticate both complete selections, then retain one normal-loader owner.
    /// Logical parent/child roles never depend on their ELF address order.
    ///
    /// # Safety
    /// Both ranges are independently trusted complete final functions in this exact
    /// final ELF, with SysV `(*const u8, usize)->u64` ABI. Parent is the sole external
    /// entry and child is entered only by its one selected original E8. One controlled
    /// caller uses depth two, valid readable input <=64 bytes and enough writable
    /// callback/XSAVE stack; every call returns normally. The child result's CSV
    /// meaning, termination and emitted-state qualification remain separate facts.
    /// No recursion, foreign/saved interior entry except the certified continuation,
    /// PLT/indirect edge, tail/nonlocal return, signal, unwind, cancellation, fork or
    /// active CET. Complete original file/mappings/permissions stay immutable except
    /// the one qualified publication; no alias writer, code-as-data, unload or
    /// protection change. Setup/publication requires full quiescence, and original
    /// calls have returned first. All owners remain process-lived, even on refusal.
    /// No installed call is allowed until a separately reviewed matching runtime
    /// exists and is attached; this preparation slice provides no such runtime.
    pub unsafe fn load_selected(
        path: &Path,
        parent: &TrustedFunctionSelection<'_>,
        child: &TrustedFunctionSelection<'_>,
        contract: NormalCallPairContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        let [p, c] = preflight(parent, child)?;
        // SAFETY: whole-file and continuous loader custody contract above.
        let owner = unsafe { retain_loader(path, parent.trusted_final_elf())? };
        let (pe, pb) = selection::resolve(owner, &p)?;
        let (ce, cb) = selection::resolve(owner, &c)?;
        if pb != cb {
            return Err(SetupRefusal::SymbolOwner);
        }
        let (pc, cc) = certify(&p.code, pe, &c.code, ce)?;
        let ps = pb.checked_add(p.page).ok_or(SetupRefusal::Format)?;
        let cs = cb.checked_add(c.page).ok_or(SetupRefusal::Format)?;
        let pages = normal_module::canonical_page_slice(&[(ps, &p.source), (cs, &c.source)])?;
        let loaded = Box::leak(Box::new(Self {
            owner,
            parent: NormalCallPairParent {
                label: parent.label().into(),
                parsed: p,
                certificate: pc,
                source_start: ps,
            },
            child: NormalCallPairChild {
                label: child.label().into(),
                parsed: c,
                certificate: cc,
                source_start: cs,
            },
            pages,
        }));
        loaded.verify_original()?;
        Ok(loaded)
    }
    pub fn parent(&self) -> &NormalCallPairParent {
        &self.parent
    }
    pub fn child(&self) -> &NormalCallPairChild {
        &self.child
    }
    pub fn edge(&self) -> NormalCallPairEdge {
        self.parent.certificate.call()
    }
    pub fn source_pages(&self) -> &[ExpectedBytes] {
        &self.pages
    }
    pub fn verify_original(&mut self) -> Result<(), SetupRefusal> {
        let original = self.pages.clone();
        self.verify_expected_pages(&original)
    }
    pub(in crate::frontend_native) fn verify_expected_pages(
        &mut self,
        expected: &[ExpectedBytes],
    ) -> Result<(), SetupRefusal> {
        check_overlay(
            &self.pages,
            expected,
            &self.parent.certificate,
            &self.child.certificate,
        )?;
        for (parsed, entry, source) in [
            (
                &self.parent.parsed,
                self.parent.entry(),
                self.parent.source_start,
            ),
            (
                &self.child.parsed,
                self.child.entry(),
                self.child.source_start,
            ),
        ] {
            verify_source_provenance(self.owner, parsed, entry, source, parsed.code.len())?;
        }
        for page in expected {
            // SAFETY: complete retained file/page provenance and continuous lease.
            unsafe {
                verify_live_source(page.address, &page.bytes)?;
            }
        }
        Ok(())
    }
}
// Pure admission only: never a fabricated loader, publication or callback token.
#[cfg(test)]
pub(in crate::frontend_native) fn admit_pair_for_planner_test(
    p: &[u8],
    pe: u64,
    c: &[u8],
    ce: u64,
) -> Result<(NormalCallPairParentCertificate, IntegerLeafCertificate), SetupRefusal> {
    certify(p, pe, c, ce)
}
