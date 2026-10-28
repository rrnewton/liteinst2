//! Explicit two-caller authority; old single-caller contracts are unchanged.
use super::{
    IntegerLeafCertificate, LoadedIntegerLeaf, SetupRefusal, TrustedFunctionSelection,
    load_named_owner, selection::load_selected_owner,
};
use std::ffi::CStr;
use std::path::Path;

/// External facts for exactly two registered, nonrecursive ordinary callers.
/// These declarations do not prove thread readiness, actual return or quiescence.
#[derive(Clone, Copy, Debug)]
pub struct TwoCallerNormalLeafContract {
    /// The complete function has one external entry and no saved interior resume.
    pub single_external_entry: bool,
    /// Ordinary SysV CALL/matching RET only; no tail, signal or nonlocal entry/exit.
    pub ordinary_call_ret_only: bool,
    /// IBT and shadow stacks are not active; this API does not disable them.
    pub no_active_cet: bool,
}
impl TwoCallerNormalLeafContract {
    fn check(self) -> Result<(), SetupRefusal> {
        if !self.single_external_entry {
            return Err(SetupRefusal::EntryExit);
        }
        if !self.ordinary_call_ret_only {
            return Err(SetupRefusal::ExitSemantics);
        }
        if !self.no_active_cet {
            return Err(SetupRefusal::Cet);
        }
        Ok(())
    }
}

/// Process-lived owner whose type carries the two-caller profile. No conversion
/// from/to LoadedNormalLeaf, mutable inner owner or gated call is public.
/// The original loader's thread-local ownership is retained; no unsafe Send/Sync.
pub struct LoadedTwoCallerNormalLeaf {
    pub(in crate::frontend_native) inner: &'static mut LoadedIntegerLeaf,
}
impl LoadedTwoCallerNormalLeaf {
    /// Use the same complete final-ELF, named-symbol, source and scalar-CFG checks.
    ///
    /// # Safety
    /// The complete trusted output, sole external entry/no saved resume and exact
    /// SysV (*const u8, usize) -> u64 ABI are independently established. All
    /// actual reads use immutable valid input and every call terminates normally.
    /// There are at most two controlled calling threads, each nonrecursive D1.
    /// No signal/callback reentry, tail entry, unwind, longjmp, cancellation, fork,
    /// active CET, alias writer, unload, file or mapping/protection change occurs.
    /// The source file, source/generated code and their owners are process-lived.
    ///
    /// Loading, planning and publication are globally quiescent. Original calls
    /// must all return before planning/publication. After publication both actual
    /// workers must successfully attach and acknowledge Ready before either is
    /// allowed to call the sole entry. Their identities are never reused; each
    /// owns its stack/input/journal and acknowledges only its own returned calls.
    /// One worker's idle/checkpoint/detach cannot acknowledge the other. These
    /// caller barriers are not supplied or proved by loading. No per-call gate,
    /// input/source scan or executable-reclamation authority is supplied.
    pub unsafe fn load(
        path: &Path,
        expected: &[u8],
        symbol: &CStr,
        contract: TwoCallerNormalLeafContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        // SAFETY: complete loader and distinct two-caller custody above.
        let inner = unsafe { load_named_owner(path, expected, symbol)? };
        Ok(Box::leak(Box::new(Self { inner })))
    }
    /// Select from independent complete final-ELF virtual-address/extent metadata.
    ///
    /// # Safety
    /// Every load obligation holds. Selection authenticates these exact final
    /// bytes, complete extent and sole entry; a pre-strip extent requires proof
    /// of unchanged final geometry. No runtime pointer or symbol fallback exists.
    pub unsafe fn load_selected(
        path: &Path,
        selection: &TrustedFunctionSelection<'_>,
        contract: TwoCallerNormalLeafContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        // SAFETY: exact selection plus continuous two-caller custody above.
        let inner = unsafe { load_selected_owner(path, selection)? };
        Ok(Box::leak(Box::new(Self { inner })))
    }
    pub fn entry(&self) -> u64 {
        self.inner.entry()
    }
    pub fn code(&self) -> &[u8] {
        self.inner.code()
    }
    pub fn certificate(&self) -> &IntegerLeafCertificate {
        self.inner.certificate()
    }
    pub fn source_range(&self) -> (u64, u64) {
        self.inner.source_range()
    }
    pub fn original_source(&self) -> &[u8] {
        self.inner.original_source()
    }
    pub fn verify_original(&mut self) -> Result<(), SetupRefusal> {
        self.inner.verify_original()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two_caller_contract_refuses_missing_facts_before_source_access() {
        let valid = TwoCallerNormalLeafContract {
            single_external_entry: true,
            ordinary_call_ret_only: true,
            no_active_cet: true,
        };
        assert_eq!(valid.check(), Ok(()));
        for (contract, expected) in [
            (
                TwoCallerNormalLeafContract {
                    single_external_entry: false,
                    ..valid
                },
                SetupRefusal::EntryExit,
            ),
            (
                TwoCallerNormalLeafContract {
                    ordinary_call_ret_only: false,
                    ..valid
                },
                SetupRefusal::ExitSemantics,
            ),
            (
                TwoCallerNormalLeafContract {
                    no_active_cet: false,
                    ..valid
                },
                SetupRefusal::Cet,
            ),
        ] {
            // Refusal precedes even opening this nonexistent input; no loaded owner is fabricated.
            assert!(matches!(unsafe {
                LoadedTwoCallerNormalLeaf::load(Path::new("/nonexistent-two-caller-leaf"), &[], c"f", contract)
            }, Err(actual) if actual == expected));
        }
    }
}
