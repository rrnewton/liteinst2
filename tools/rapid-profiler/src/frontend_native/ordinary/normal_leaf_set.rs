//! One retained loader for a canonical bounded set of complete scalar leaves.
use super::{
    NormalModuleContract, NormalModuleFunction, SetupRefusal, TrustedFunctionSelection,
    normal_module::{self, LoadedParts},
};
use liteinst2::contracts::ExpectedBytes;
use std::path::Path;

/// One independently authenticated file/loader and immutable function/page union.
/// Retained executable owners remain process-lived, including after refusal.
pub struct LoadedNormalLeafSet {
    parts: LoadedParts,
}
impl LoadedNormalLeafSet {
    /// Authenticate all 1..=4 complete selections in increasing ELF-VA order.
    /// No publication, execution or old-profile conversion occurs here.
    ///
    /// # Safety
    /// Every selection is a complete SysV `(*const u8, usize) -> u64` scalar leaf
    /// in the same independently trusted final ELF. One controlled thread calls
    /// them sequentially at depth one with valid readable inputs and ordinary
    /// matching CALL/RET. Each has one external entry; no saved interior resume,
    /// inter-function CALL, tail entry, recursion, signal, unwind, longjmp,
    /// cancellation, fork or active CET is permitted. All original calls finish
    /// before planning/publication under real complete-union quiescence.
    /// File/source/control/generated owners and permissions remain immutable and
    /// process-lived except for the qualified publication, with no alias writer,
    /// code-as-data, unload or protection change. Installed calls require a
    /// matching LeafSet attachment; metadata drain never authorizes code reuse.
    pub unsafe fn load_selected(
        path: &Path,
        selections: &[&TrustedFunctionSelection<'_>],
        contract: NormalModuleContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        // SAFETY: complete union-wide external custody contract above.
        let parts = unsafe { normal_module::load_parts(path, selections)? };
        let loaded = Box::leak(Box::new(Self { parts }));
        loaded.verify_original()?;
        Ok(loaded)
    }
    pub fn functions(&self) -> &[NormalModuleFunction] {
        &self.parts.functions
    }
    pub fn source_pages(&self) -> &[ExpectedBytes] {
        &self.parts.pages
    }
    pub fn verify_original(&mut self) -> Result<(), SetupRefusal> {
        let expected = self.parts.pages.clone();
        self.verify_expected_pages(&expected)
    }
    pub(in crate::frontend_native) fn verify_expected_pages(
        &mut self,
        expected: &[ExpectedBytes],
    ) -> Result<(), SetupRefusal> {
        normal_module::verify_parts(
            self.parts.owner,
            &self.parts.functions,
            &self.parts.pages,
            expected,
        )
    }
}
#[cfg(test)]
mod tests;
