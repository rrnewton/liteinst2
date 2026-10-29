//! One bounded complete function-set transaction, sharing the existing planner.
use super::normal_module::{
    ModuleFunctionSource, ModuleRole, check_publication, prepare_functions,
};
use super::*;
use crate::frontend_native::LoadedNormalLeafSet;
use liteinst2::controls::ControlIdentity;

pub(in crate::frontend_native::always_on) struct LeafSetSite {
    identity: CodeIdentity,
    functions: Vec<NormalModuleFunctionSite>,
    roles: Vec<ModuleRole>,
}
impl LeafSetSite {
    pub(in crate::frontend_native::always_on) fn identity(&self) -> CodeIdentity {
        self.identity
    }
    pub(in crate::frontend_native::always_on) fn functions(&self) -> &[NormalModuleFunctionSite] {
        &self.functions
    }
    pub(in crate::frontend_native::always_on) fn roles(
        &self,
    ) -> impl ExactSizeIterator<Item = NormalModuleRole> + '_ {
        self.roles.iter().map(|r| r.metadata)
    }
    fn role_at(&self, pc: u64, entry: bool) -> Option<&ModuleRole> {
        self.roles.iter().find(|r| {
            r.metadata.pc == pc && (r.metadata.kind == NormalModuleRoleKind::Entry) == entry
        })
    }
    pub(in crate::frontend_native::always_on) fn resolve(
        &self,
        pc: u64,
        control: ControlIdentity<'_>,
        entry: bool,
    ) -> Option<usize> {
        self.role_at(pc, entry)
            .filter(|r| r.control.has_identity(control))
            .map(|r| r.metadata.function_index)
    }
}
/// Complete unpublished preparation. It exposes no gate or callable owner.
pub struct NormalLeafSetSitePreparation {
    owner: &'static mut LoadedNormalLeafSet,
    planned: PlannedBundle,
    site: Arc<LeafSetSite>,
}
/// Retained successful publication; only the distinct LeafSet attachment applies.
pub struct InstalledNormalLeafSetSite {
    pub(in crate::frontend_native::always_on) site: Arc<LeafSetSite>,
}
impl InstalledNormalLeafSetSite {
    pub fn identity(&self) -> CodeIdentity {
        self.site.identity()
    }
    pub fn functions(&self) -> &[NormalModuleFunctionSite] {
        self.site.functions()
    }
    pub fn roles(&self) -> impl ExactSizeIterator<Item = NormalModuleRole> + '_ {
        self.site.roles()
    }
}
impl NormalLeafSetSitePreparation {
    pub fn new_certified_blocks(
        owner: &'static mut LoadedNormalLeafSet,
        identity: CodeIdentity,
    ) -> Result<Self, SiteError> {
        let count = owner.functions().len();
        Self::new_with_policies(
            owner,
            identity,
            &[NormalModulePreparationPolicy::CertifiedBlocks; 4][..count],
        )
    }
    /// Exactly one explicit policy per complete selected leaf. No fallback,
    /// omitted role, enlarged per-function search or aggregate budget is allowed.
    pub fn new_with_policies(
        owner: &'static mut LoadedNormalLeafSet,
        identity: CodeIdentity,
        policies: &[NormalModulePreparationPolicy],
    ) -> Result<Self, SiteError> {
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        if policies.len() != owner.functions().len() {
            return Err(SiteError::Correspondence);
        }
        owner.verify_original().map_err(SiteError::Source)?;
        let functions: Vec<_> = owner
            .functions()
            .iter()
            .map(|f| ModuleFunctionSource {
                code: f.code(),
                certificate: f.certificate(),
                source_range: f.source_range(),
            })
            .collect();
        let policies: Vec<_> = policies
            .iter()
            .copied()
            .map(NormalModulePreparationPolicy::internal)
            .collect();
        let (planned, functions, roles) =
            prepare_functions(&functions, owner.source_pages(), identity, &policies)?;
        let site = Arc::new(LeafSetSite {
            identity,
            functions,
            roles,
        });
        owner.verify_original().map_err(SiteError::Source)?;
        Ok(Self {
            owner,
            planned,
            site,
        })
    }
    pub fn plan(&self) -> &PlannedBundle {
        &self.planned
    }
    pub fn identity(&self) -> CodeIdentity {
        self.site.identity()
    }
    pub fn functions(&self) -> &[NormalModuleFunctionSite] {
        self.site.functions()
    }
    pub fn roles(&self) -> impl ExactSizeIterator<Item = NormalModuleRole> + '_ {
        self.site.roles()
    }
    /// Retain all publication owners before any fallible correspondence check.
    ///
    /// # Safety
    /// The real successful publication and receipt belong to this exact plan.
    /// Complete source/generated leases, final RX bytes and every owner remain
    /// readable, immutable and process-lived. Real union-wide quiescence holds;
    /// no selected entry or saved resume runs until a matching attachment exists.
    /// The loader's scalar ABI, inputs and sequential ordinary CALL/RET contract
    /// holds continuously, with sufficient callback save/XSAVE stack. No signal,
    /// unwind/nonlocal exit, CET, fork, code-as-data, alias writer or unload exists.
    /// Metadata drain grants no executable quiescence or reclamation authority.
    pub unsafe fn seal(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledNormalLeafSetSite, SiteError> {
        let (prep, installed, receipt) = Box::leak(Box::new((self, installed, receipt)));
        // SAFETY: the complete real transaction is retained above.
        unsafe {
            check_publication(&prep.planned, installed, receipt, prep.site.identity)?;
        }
        prep.owner
            .verify_expected_pages(prep.planned.plan().final_bytes())
            .map_err(SiteError::Source)?;
        Ok(InstalledNormalLeafSetSite {
            site: Arc::clone(&prep.site),
        })
    }
}
// Inert metadata only: no loaded owner, publication or opaque callback token.
#[cfg(test)]
impl LeafSetSite {
    pub(in crate::frontend_native::always_on) fn synthetic(
        identity: CodeIdentity,
        functions: &[(u64, u64, Vec<u64>)],
    ) -> Arc<Self> {
        assert!((1..=4).contains(&functions.len()));
        assert_eq!(identity.mapping, functions[0].0);
        assert_ne!(identity.generation, 0);
        assert!(functions.windows(2).all(|w| w[0].1 <= w[1].0));
        let functions: Vec<_> = functions
            .iter()
            .map(|(entry, end, returns)| {
                assert!(
                    *entry != 0
                        && end
                            .checked_sub(*entry)
                            .is_some_and(|n| (1..=256).contains(&n))
                );
                assert!((1..=4).contains(&returns.len()));
                assert!(returns.iter().all(|pc| entry < pc && pc < end));
                assert!(returns.windows(2).all(|w| w[0] < w[1]));
                NormalModuleFunctionSite {
                    entry: *entry,
                    end: *end,
                    returns: returns.clone(),
                }
            })
            .collect();
        let mut roles = Vec::new();
        for (function_index, function) in functions.iter().enumerate() {
            let pcs: Vec<_> = std::iter::once(function.entry())
                .chain(function.returns().iter().copied())
                .collect();
            roles.extend(
                mandatory_roles(&pcs, CallbackProfile::Normal)
                    .into_iter()
                    .enumerate()
                    .map(|(index, role)| ModuleRole {
                        metadata: NormalModuleRole {
                            function_index,
                            kind: if index == 0 {
                                NormalModuleRoleKind::Entry
                            } else {
                                NormalModuleRoleKind::Return
                            },
                            pc: role.pc,
                        },
                        control: role.control,
                    }),
            );
        }
        Arc::new(Self {
            identity,
            functions,
            roles,
        })
    }
    pub(in crate::frontend_native::always_on) fn control_for(
        &self,
        index: usize,
        entry: bool,
        pc: u64,
    ) -> Option<&ProbeControl> {
        self.role_at(pc, entry)
            .filter(|r| r.metadata.function_index == index)
            .map(|r| &r.control)
    }
    pub(in crate::frontend_native::always_on) fn resolve_control(
        &self,
        pc: u64,
        control: &ProbeControl,
        entry: bool,
    ) -> Option<usize> {
        self.role_at(pc, entry)
            .filter(|r| r.control == *control)
            .map(|r| r.metadata.function_index)
    }
}
#[cfg(test)]
mod tests;
