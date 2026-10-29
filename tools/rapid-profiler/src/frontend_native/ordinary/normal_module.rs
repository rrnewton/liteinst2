//! One retained normal-loader owner for two sequential, complete scalar leaves.
use super::{
    IntegerLeafCertificate, Parsed, Retained, SetupRefusal, TrustedFunctionSelection, cfg,
    retain_loader, selection, verify_live_source, verify_source_provenance,
};
use liteinst2::contracts::ExpectedBytes;
use std::path::Path;

/// External facts, not evidence of physical calls, returns or quiescence.
#[derive(Clone, Copy, Debug)]
pub struct NormalModuleContract {
    pub single_external_entry_per_function: bool,
    /// One calling thread, depth one, ordinary SysV CALLs and matching RETs.
    pub sequential_call_ret_only: bool,
    pub no_active_cet: bool,
}
impl NormalModuleContract {
    pub(super) fn check(self) -> Result<(), SetupRefusal> {
        if !self.single_external_entry_per_function {
            return Err(SetupRefusal::EntryExit);
        }
        if !self.sequential_call_ret_only {
            return Err(SetupRefusal::ExitSemantics);
        }
        if !self.no_active_cet {
            return Err(SetupRefusal::Cet);
        }
        Ok(())
    }
}

/// Immutable per-function geometry; never a separate loader or callable owner.
pub struct NormalModuleFunction {
    label: String,
    parsed: Parsed,
    certificate: IntegerLeafCertificate,
    source_start: u64,
}
impl NormalModuleFunction {
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn elf_range(&self) -> (u64, u64) {
        (
            self.parsed.entry,
            self.parsed.entry + self.parsed.code.len() as u64,
        )
    }
    pub fn entry(&self) -> u64 {
        self.certificate.entry()
    }
    pub fn code(&self) -> &[u8] {
        &self.parsed.code
    }
    pub fn certificate(&self) -> &IntegerLeafCertificate {
        &self.certificate
    }
    pub(in crate::frontend_native) fn source_range(&self) -> (u64, u64) {
        (
            self.source_start,
            self.source_start + self.parsed.source.len() as u64,
        )
    }
}

/// Exactly two complete disjoint selections and one canonical full-page union.
/// The handle/file and all later published owners remain process-lived.
pub struct LoadedNormalModule {
    owner: &'static mut Retained,
    functions: [NormalModuleFunction; 2],
    pages: Vec<ExpectedBytes>,
}
impl LoadedNormalModule {
    /// Authenticate both selections before loading one independently trusted DSO.
    /// The increasing ELF order becomes the immutable function index 0/1.
    /// No function is called, published or converted to a gated owner.
    ///
    /// # Safety
    /// Both descriptors identify complete functions in the same independently
    /// trusted final ELF, with exact SysV `(*const u8, usize) -> u64` ABI. Each
    /// function has one external entry and no saved interior resumes. One actual
    /// controlled thread calls them sequentially at depth one; every invocation
    /// has valid readable inputs and terminates by its matching ordinary RET.
    /// No callback recursion, inter-function CALL, tail entry, signal, unwind,
    /// longjmp, fork, cancellation or active CET is permitted. Original calls
    /// must finish before planning/publication; all setup/publication requires
    /// real quiescence. After publication, calls require a matching module
    /// attachment, which this loader/planner API does not provide.
    ///
    /// The complete original file, mappings and permissions stay immutable
    /// except for the one qualified publication. No alias writer, code-as-data,
    /// unload or protection change may invalidate either selection or any page
    /// of the union. Source, controls and generated owners stay process-lived,
    /// including on later refusal. Metadata drain never authorizes reclamation.
    pub unsafe fn load_selected_pair(
        path: &Path,
        selections: [&TrustedFunctionSelection<'_>; 2],
        contract: NormalModuleContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        // SAFETY: the unchanged complete pair/union custody contract above.
        let parts = unsafe { load_parts(path, &selections)? };
        let functions = parts
            .functions
            .try_into()
            .map_err(|_| SetupRefusal::Format)?;
        let loaded = Box::leak(Box::new(Self {
            owner: parts.owner,
            functions,
            pages: parts.pages,
        }));
        loaded.verify_original()?;
        Ok(loaded)
    }
    pub fn functions(&self) -> &[NormalModuleFunction; 2] {
        &self.functions
    }
    /// Sorted nonoverlapping complete 4096-byte pages; gaps are not snapshots.
    pub fn source_pages(&self) -> &[ExpectedBytes] {
        &self.pages
    }
    pub fn verify_original(&mut self) -> Result<(), SetupRefusal> {
        let expected = self.pages.clone();
        self.verify_expected_pages(&expected)
    }
    pub(in crate::frontend_native) fn verify_expected_pages(
        &mut self,
        expected: &[ExpectedBytes],
    ) -> Result<(), SetupRefusal> {
        verify_parts(self.owner, &self.functions, &self.pages, expected)
    }
}

#[cfg(test)]
fn check_selections(selections: [&TrustedFunctionSelection<'_>; 2]) -> Result<(), SetupRefusal> {
    check_selection_slice(&selections)
}
pub(super) fn check_selection_slice(
    selections: &[&TrustedFunctionSelection<'_>],
) -> Result<(), SetupRefusal> {
    if !(1..=4).contains(&selections.len()) {
        return Err(SetupRefusal::EntryExit);
    }
    if selections
        .iter()
        .any(|s| s.trusted_final_elf() != selections[0].trusted_final_elf())
    {
        return Err(SetupRefusal::SourceBytes);
    }
    let ranges: Vec<_> = selections.iter().map(|s| s.elf_range()).collect();
    if ranges.iter().any(|r| r.0 >= r.1) || ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(SetupRefusal::EntryExit);
    }
    Ok(())
}

pub(super) struct LoadedParts {
    pub(super) owner: &'static mut Retained,
    pub(super) functions: Vec<NormalModuleFunction>,
    pub(super) pages: Vec<ExpectedBytes>,
}
pub(super) fn preflight(
    selections: &[&TrustedFunctionSelection<'_>],
) -> Result<Vec<Parsed>, SetupRefusal> {
    check_selection_slice(selections)?;
    let parsed = selections
        .iter()
        .map(|s| selection::parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    canonical_page_slice(
        &parsed
            .iter()
            .map(|p| (p.page, p.source.as_slice()))
            .collect::<Vec<_>>(),
    )?;
    Ok(parsed)
}
pub(super) unsafe fn load_parts(
    path: &Path,
    selections: &[&TrustedFunctionSelection<'_>],
) -> Result<LoadedParts, SetupRefusal> {
    let parsed = preflight(selections)?;
    // SAFETY: every selected ELF/CFG and the complete union were checked before loading.
    let owner = unsafe { retain_loader(path, selections[0].trusted_final_elf())? };
    let resolved = parsed
        .iter()
        .map(|p| selection::resolve(owner, p))
        .collect::<Result<Vec<_>, _>>()?;
    let bias = resolved[0].1;
    if resolved.iter().any(|r| r.1 != bias) {
        return Err(SetupRefusal::SymbolOwner);
    }
    let functions = parsed
        .into_iter()
        .zip(resolved)
        .zip(selections)
        .map(|((parsed, (entry, _)), selection)| {
            let source_start = bias.checked_add(parsed.page).ok_or(SetupRefusal::Format)?;
            source_start
                .checked_add(parsed.source.len() as u64)
                .ok_or(SetupRefusal::Format)?;
            Ok(NormalModuleFunction {
                label: selection.label().into(),
                certificate: cfg::admit(&parsed.code, entry)?,
                parsed,
                source_start,
            })
        })
        .collect::<Result<Vec<_>, SetupRefusal>>()?;
    let pages = canonical_page_slice(
        &functions
            .iter()
            .map(|f| (f.source_start, f.parsed.source.as_slice()))
            .collect::<Vec<_>>(),
    )?;
    Ok(LoadedParts {
        owner,
        functions,
        pages,
    })
}
pub(super) fn verify_parts(
    owner: &mut Retained,
    functions: &[NormalModuleFunction],
    pages: &[ExpectedBytes],
    expected: &[ExpectedBytes],
) -> Result<(), SetupRefusal> {
    check_overlay_slice(
        pages,
        expected,
        &functions
            .iter()
            .map(|f| f.certificate.range())
            .collect::<Vec<_>>(),
    )?;
    for function in functions {
        verify_source_provenance(
            owner,
            &function.parsed,
            function.entry(),
            function.source_start,
            function.code().len(),
        )?;
    }
    for page in expected {
        // SAFETY: retained provenance and continuous complete-union lease.
        unsafe {
            verify_live_source(page.address, &page.bytes)?;
        }
    }
    Ok(())
}

// Exact pages, never a synthesized span between distant selected functions.
#[cfg(test)]
fn canonical_pages(sources: [(u64, &[u8]); 2]) -> Result<Vec<ExpectedBytes>, SetupRefusal> {
    canonical_page_slice(&sources)
}
pub(super) fn canonical_page_slice(
    sources: &[(u64, &[u8])],
) -> Result<Vec<ExpectedBytes>, SetupRefusal> {
    let mut pages: Vec<ExpectedBytes> = Vec::new();
    for &(start, source) in sources {
        if start % 4096 != 0 || !matches!(source.len(), 4096 | 8192) {
            return Err(SetupRefusal::Format);
        }
        start
            .checked_add(source.len() as u64)
            .ok_or(SetupRefusal::Format)?;
        for (index, bytes) in source.chunks_exact(4096).enumerate() {
            let address = start + index as u64 * 4096;
            if let Some(prior) = pages.iter().find(|page| page.address == address) {
                if prior.bytes != bytes {
                    return Err(SetupRefusal::SourceBytes);
                }
            } else {
                if pages.len() == 2 {
                    return Err(SetupRefusal::Format);
                }
                pages.push(ExpectedBytes {
                    address,
                    bytes: bytes.to_vec(),
                });
            }
        }
    }
    pages.sort_unstable_by_key(|page| page.address);
    Ok(pages)
}

// Every byte outside the two complete bodies stays original. Publication must
// additionally supply the exact plan/receipt and readable live image checks.
#[cfg(test)]
fn check_overlay(
    originals: &[ExpectedBytes],
    expected: &[ExpectedBytes],
    bodies: [(u64, u64); 2],
) -> Result<(), SetupRefusal> {
    check_overlay_slice(originals, expected, &bodies)
}
pub(super) fn check_overlay_slice(
    originals: &[ExpectedBytes],
    expected: &[ExpectedBytes],
    bodies: &[(u64, u64)],
) -> Result<(), SetupRefusal> {
    if originals.len() != expected.len() {
        return Err(SetupRefusal::SourceBytes);
    }
    for (before, after) in originals.iter().zip(expected) {
        if before.address != after.address || before.bytes.len() != after.bytes.len() {
            return Err(SetupRefusal::SourceBytes);
        }
        for (offset, (&old, &new)) in before.bytes.iter().zip(&after.bytes).enumerate() {
            let pc = before
                .address
                .checked_add(offset as u64)
                .ok_or(SetupRefusal::Format)?;
            if old != new && !bodies.iter().any(|&(start, end)| start <= pc && pc < end) {
                return Err(SetupRefusal::SourceBytes);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

// Real scalar admission for pure planner controls, never a fabricated owner or
// public execution authority. No loader or runtime operation occurs here.
#[cfg(test)]
pub(in crate::frontend_native) fn admit_for_planner_test(
    code: &[u8],
    entry: u64,
) -> Result<IntegerLeafCertificate, SetupRefusal> {
    cfg::admit(code, entry)
}
