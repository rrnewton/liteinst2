//! Sealed normal-caller installation, distinct from every library CALL gate.
use super::*;

/// Complete entry/all-RET preparation for an ordinary application CALL.
/// Planning neither invokes code nor grants entry before successful publication.
pub struct NormalSitePreparation {
    owner: &'static mut LoadedNormalLeaf,
    planned: PlannedBundle,
    site: Arc<Site>,
}

/// A retained normal-caller installation. Cannot be converted to a gated site.
pub struct InstalledNormalSite {
    pub(in crate::frontend_native::always_on) site: Arc<Site>,
}

impl NormalSitePreparation {
    /// Install mandatory normal-caller entry and RET observations in one complete
    /// 5..=80-byte scalar function. Uses the same complete CFG, byte overlays,
    /// source-page custody, Legacy128 state preservation and allocation limits
    /// as `OrdinarySitePreparation::new_whole_function`.
    ///
    /// This profile has no library CALL gate, fixed return PC, gate frame, RBX
    /// convention or per-call input/source scan. The distinct loaded owner's
    /// continuous unsafe calling and source-custody contract supplies those
    /// obligations. The callbacks retain the actual entry stack/return word and
    /// require every original RET to match. A pre-RET observation alone never
    /// acknowledges physical return or releases an in-flight model receipt.
    pub fn new_whole_function(
        owner: &'static mut LoadedNormalLeaf,
        identity: CodeIdentity,
    ) -> Result<Self, SiteError> {
        let (planned, site) = prepare_source(
            owner.inner,
            CallbackProfile::Normal,
            identity,
            PreparationPolicy::WholeFunction,
        )?;
        Ok(Self {
            owner,
            planned,
            site,
        })
    }

    pub fn plan(&self) -> &PlannedBundle {
        &self.planned
    }

    /// Entry first, then all original RETs in ascending source order.
    pub fn role_pcs(&self) -> impl ExactSizeIterator<Item = u64> + '_ {
        self.site.roles.iter().map(|role| role.pc)
    }

    /// Retain the real publication and verify its complete source/image bytes.
    /// Failure also retains every owner; no rollback or executable reclamation.
    ///
    /// # Safety
    /// The successful real bundle publication, receipt, full source/generated
    /// quiescence leases and final RX bytes belong to this preparation. Source
    /// and image ranges are readable; no thread can execute a subject entry or
    /// saved resume until this seal and matching normal-thread attachment finish.
    /// There is no code-as-data use, source/alias writer, unload, fork, active
    /// CET, signal entry or nonlocal exit. The loaded owner's complete entry,
    /// ABI/input and normal-call/return obligations remain true, and callbacks
    /// have sufficient writable state-save/XSAVE stack. All source/generated
    /// owners remain process-lived; metadata checkpoints never authorize unmap.
    pub unsafe fn seal(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledNormalSite, SiteError> {
        let (prep, installed, receipt) = Box::leak(Box::new((self, installed, receipt)));
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        if !prep.site.is_normal() || prep.site.gate.is_some() || prep.site.terminal != 0 {
            return Err(SiteError::Correspondence);
        }
        // SAFETY: real retained publication and continuous complete custody above.
        unsafe { validate_publication(prep.owner.inner, &prep.planned, installed, receipt)? };
        Ok(InstalledNormalSite {
            site: Arc::clone(&prep.site),
        })
    }
}
