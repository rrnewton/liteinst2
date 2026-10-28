//! Two-caller factory authority over the unchanged whole-function preparation.
use super::*;
use crate::frontend_native::LoadedTwoCallerNormalLeaf;

/// Process-lived two-caller owner and exact full entry/all-RET plan.
pub struct TwoCallerNormalSitePreparation {
    owner: &'static mut LoadedTwoCallerNormalLeaf,
    planned: PlannedBundle,
    site: Arc<Site>,
}
/// Cannot be converted to a single-caller or gated installation.
pub struct InstalledTwoCallerNormalSite {
    pub(in crate::frontend_native::always_on) site: Arc<Site>,
}
impl TwoCallerNormalSitePreparation {
    /// Same complete 5..=80-byte CFG, all RETs, overlay, source/image and
    /// Legacy128 preservation checks. Only a two-caller owner selects this tag.
    pub fn new_whole_function(
        owner: &'static mut LoadedTwoCallerNormalLeaf,
        identity: CodeIdentity,
    ) -> Result<Self, SiteError> {
        let (planned, site) = prepare_source(
            owner.inner,
            CallbackProfile::NormalTwoCallers,
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
    pub fn role_pcs(&self) -> impl ExactSizeIterator<Item = u64> + '_ {
        self.site.roles.iter().map(|role| role.pc)
    }
    /// Retain successful real publication and verify every source/image byte.
    ///
    /// # Safety
    /// NormalSitePreparation::seal's complete publication/lease/readability and
    /// no-writer/no-unload contract applies. The distinct loaded two-caller
    /// contract remains continuous. Both actual workers stay quiescent until
    /// this seal and both successful attachment Ready handshakes complete.
    /// Each caller has sufficient full-state-save/XSAVE stack. Later same-thread
    /// checkpoints acknowledge only that worker; neither permits executable unmap.
    pub unsafe fn seal(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledTwoCallerNormalSite, SiteError> {
        let (prep, installed, receipt) = Box::leak(Box::new((self, installed, receipt)));
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        if !prep.site.is_normal_two_callers() || prep.site.gate.is_some() || prep.site.terminal != 0
        {
            return Err(SiteError::Correspondence);
        }
        // SAFETY: exact retained publication and complete continuous custody above.
        unsafe { validate_publication(prep.owner.inner, &prep.planned, installed, receipt)? };
        Ok(InstalledTwoCallerNormalSite {
            site: Arc::clone(&prep.site),
        })
    }
}
