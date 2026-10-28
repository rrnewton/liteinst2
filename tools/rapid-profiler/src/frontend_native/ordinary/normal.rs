//! A separate owner for ordinary callers, sharing only the authenticated loader.
use super::{
    IntegerLeafCertificate, LoadedIntegerLeaf, SetupRefusal, TrustedFunctionSelection,
    load_named_owner, selection::load_selected_owner,
};
use std::ffi::CStr;
use std::path::Path;

/// External facts for calls made by application code without a library CALL gate.
/// These declarations do not prove a call, a physical return or code quiescence.
#[derive(Clone, Copy, Debug)]
pub struct NormalLeafContract {
    /// The complete function has one external entry and no saved interior resume.
    pub single_external_entry: bool,
    /// All entries are ordinary SysV CALLs and all exits are normal matching RETs.
    /// No tail entry, signal entry, callback recursion, unwind or nonlocal exit.
    pub ordinary_call_ret_only: bool,
    /// The caller establishes that IBT and shadow stacks are not active.
    pub no_active_cet: bool,
}
impl NormalLeafContract {
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

/// Process-lived admitted scalar leaf for the separate normal-caller profile.
/// No conversion to the gate-exclusive owner or callable pointer is exposed.
pub struct LoadedNormalLeaf {
    pub(in crate::frontend_native) inner: &'static mut LoadedIntegerLeaf,
}
impl LoadedNormalLeaf {
    /// Load a pinned scalar DSO with the same complete ELF/CFG checks as the
    /// gated profile. This does not call or publish any subject instruction.
    ///
    /// # Safety
    /// `expected` is independently trusted complete compiler/linker output.
    /// The caller proves complete entry/resume closure and the exact SysV
    /// `(*const u8, usize) -> u64` ABI. Every invocation uses valid readable input
    /// storage and terminates. There is at most one controlled calling thread.
    /// Loading, planning and publication run under real quiescence. Unpatched
    /// original calls may run after loading, under the same ABI/input/return
    /// obligations, and must all finish before planning or publication. After
    /// publication every call occurs on the attached thread, through an ordinary
    /// application CALL to the sole entry. No per-call gate, input scan or source scan is supplied.
    /// The caller continuously owns these input, source and thread obligations.
    ///
    /// No signal handler, callback recursion, tail entry, unwind, longjmp, fork,
    /// cancellation, active CET, alias writer, unload or mapping/protection
    /// change may invalidate the contract. The original file stays immutable.
    /// All source/generated owners remain process-lived. Attachment, publication
    /// and an after-calls checkpoint have their separate unsafe contracts.
    pub unsafe fn load(
        path: &Path,
        expected: &[u8],
        symbol: &CStr,
        contract: NormalLeafContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        // SAFETY: the complete normal-caller contract above, not a fabricated
        // assertion that an application CALL went through the old library gate.
        let inner = unsafe { load_named_owner(path, expected, symbol)? };
        Ok(Box::leak(Box::new(Self { inner })))
    }

    /// Load a complete selected scalar function, including stripped input.
    ///
    /// # Safety
    /// All `Self::load` obligations hold. The descriptor's complete final ELF
    /// bytes and complete function extent come from independent trusted metadata
    /// for those exact final bytes. Its address is an ELF virtual address, not a
    /// file offset or runtime PC. A pre-strip extent needs proof that final
    /// geometry is unchanged; decoding cannot prove sole-entry completeness.
    pub unsafe fn load_selected(
        path: &Path,
        selection: &TrustedFunctionSelection<'_>,
        contract: NormalLeafContract,
    ) -> Result<&'static mut Self, SetupRefusal> {
        contract.check()?;
        // SAFETY: complete selection and continuous normal-caller custody above.
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
    fn normal_contract_requires_entry_call_return_and_cet_facts_before_loading() {
        let valid = NormalLeafContract {
            single_external_entry: true,
            ordinary_call_ret_only: true,
            no_active_cet: true,
        };
        assert_eq!(valid.check(), Ok(()));
        for (invalid, expected) in [
            (
                NormalLeafContract {
                    single_external_entry: false,
                    ..valid
                },
                SetupRefusal::EntryExit,
            ),
            (
                NormalLeafContract {
                    ordinary_call_ret_only: false,
                    ..valid
                },
                SetupRefusal::ExitSemantics,
            ),
            (
                NormalLeafContract {
                    no_active_cet: false,
                    ..valid
                },
                SetupRefusal::Cet,
            ),
        ] {
            // The nonexistent path must never be consulted for a bad contract.
            assert!(matches!(unsafe {
                LoadedNormalLeaf::load(Path::new("/nonexistent-normal-leaf"), &[], c"f", invalid)
            }, Err(actual) if actual == expected));
        }
    }
}
