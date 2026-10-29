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
    fn check(self) -> Result<(), SetupRefusal> {
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
        check_selections(selections)?;
        let parsed = [
            selection::parse(selections[0])?,
            selection::parse(selections[1])?,
        ];
        // Refuse excess page demand or disagreement before invoking the loader.
        canonical_pages([
            (parsed[0].page, parsed[0].source.as_slice()),
            (parsed[1].page, parsed[1].source.as_slice()),
        ])?;
        // SAFETY: both complete ELF/CFG checks and continuous union custody above.
        let owner = unsafe { retain_loader(path, selections[0].trusted_final_elf())? };
        let (entry0, bias0) = selection::resolve(owner, &parsed[0])?;
        let (entry1, bias1) = selection::resolve(owner, &parsed[1])?;
        if bias0 != bias1 {
            return Err(SetupRefusal::SymbolOwner);
        }
        let [first, second] = parsed;
        let make = |parsed: Parsed, entry, label: &str| -> Result<_, SetupRefusal> {
            let source_start = bias0.checked_add(parsed.page).ok_or(SetupRefusal::Format)?;
            source_start
                .checked_add(parsed.source.len() as u64)
                .ok_or(SetupRefusal::Format)?;
            Ok(NormalModuleFunction {
                label: label.into(),
                certificate: cfg::admit(&parsed.code, entry)?,
                parsed,
                source_start,
            })
        };
        let functions = [
            make(first, entry0, selections[0].label())?,
            make(second, entry1, selections[1].label())?,
        ];
        let pages = canonical_pages([
            (
                functions[0].source_start,
                functions[0].parsed.source.as_slice(),
            ),
            (
                functions[1].source_start,
                functions[1].parsed.source.as_slice(),
            ),
        ])?;
        let loaded = Box::leak(Box::new(Self {
            owner,
            functions,
            pages,
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
        check_overlay(
            &self.pages,
            expected,
            self.functions.each_ref().map(|f| f.certificate.range()),
        )?;
        for function in &self.functions {
            verify_source_provenance(
                self.owner,
                &function.parsed,
                function.entry(),
                function.source_start,
                function.code().len(),
            )?;
        }
        for page in expected {
            // SAFETY: both retained provenance checks and continuous union lease.
            unsafe {
                verify_live_source(page.address, &page.bytes)?;
            }
        }
        Ok(())
    }
}

fn check_selections(selections: [&TrustedFunctionSelection<'_>; 2]) -> Result<(), SetupRefusal> {
    if selections[0].trusted_final_elf() != selections[1].trusted_final_elf() {
        return Err(SetupRefusal::SourceBytes);
    }
    let [a, b] = selections.map(TrustedFunctionSelection::elf_range);
    if a.0 >= a.1 || a.1 > b.0 || b.0 >= b.1 {
        return Err(SetupRefusal::EntryExit);
    }
    Ok(())
}

// Exact pages, never a synthesized span between distant selected functions.
fn canonical_pages(sources: [(u64, &[u8]); 2]) -> Result<Vec<ExpectedBytes>, SetupRefusal> {
    let mut pages: Vec<ExpectedBytes> = Vec::new();
    for (start, source) in sources {
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
fn check_overlay(
    originals: &[ExpectedBytes],
    expected: &[ExpectedBytes],
    bodies: [(u64, u64); 2],
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
