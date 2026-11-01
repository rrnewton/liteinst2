//! Closed optional-entry module factory. Every RET remains permanently enabled.
use super::*;
use liteinst2::controls::EarlyControlGateLayout;
use liteinst2::controls::{ControlWriter, EntryAdmissionAction};
use liteinst2::quiescent::{
    plan_entry_admission_detailed_after, plan_whole_function_entry_admission_detailed_after,
};
mod append;

/// No source is published and no invocation is permitted during preparation.
/// This profile cannot be converted to a mandatory normal site.
pub struct EarlyEntryModuleSitePreparation {
    owner: &'static mut LoadedNormalModule,
    planned: PlannedBundle,
    site: Arc<ModuleSite>,
    writers: Option<[ControlWriter; 2]>,
    gates: Vec<EarlyControlGateLayout>,
}
/// Real retained publication plus two exclusive entry writers. RET writers do
/// not exist. Neither this object nor a report grants executable retirement.
pub struct InstalledEarlyEntryModuleSite {
    pub(in crate::frontend_native::always_on) site: Arc<ModuleSite>,
    pub(in crate::frontend_native::always_on) writers: [ControlWriter; 2],
    gates: Vec<EarlyControlGateLayout>,
}
impl EarlyEntryModuleSitePreparation {
    pub fn new_certified_blocks(
        owner: &'static mut LoadedNormalModule,
        identity: CodeIdentity,
    ) -> Result<Self, SiteError> {
        Self::new_with_policies(
            owner,
            identity,
            [NormalModulePreparationPolicy::CertifiedBlocks; 2],
        )
    }
    /// Both explicit policies retain all original source, CFG, role and capacity
    /// checks. Only entry admission is optional; this is not a PointObservationAction.
    pub fn new_with_policies(
        owner: &'static mut LoadedNormalModule,
        identity: CodeIdentity,
        policies: [NormalModulePreparationPolicy; 2],
    ) -> Result<Self, SiteError> {
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        owner.verify_original().map_err(SiteError::Source)?;
        let sources = owner.functions().each_ref().map(|f| ModuleFunctionSource {
            code: f.code(),
            certificate: f.certificate(),
            source_range: f.source_range(),
        });
        let (planned, functions, roles, writers) = prepare_early_functions(
            &sources,
            owner.source_pages(),
            identity,
            &policies.map(NormalModulePreparationPolicy::internal),
        )?;
        owner.verify_original().map_err(SiteError::Source)?;
        let functions: [NormalModuleFunctionSite; 2] = functions
            .try_into()
            .map_err(|_| SiteError::Correspondence)?;
        let gates: Vec<_> = planned
            .images()
            .iter()
            .flat_map(|i| i.early_control_gates().iter().copied())
            .collect();
        if gates.iter().map(|g| g.logical_pc).collect::<Vec<_>>()
            != functions.iter().map(|f| f.entry).collect::<Vec<_>>()
        {
            return Err(SiteError::Correspondence);
        }
        let site = Arc::new(ModuleSite {
            identity,
            functions,
            roles,
            sealed_source: owner.has_sealed_source(),
            early_entry: true,
        });
        Ok(Self {
            owner,
            planned,
            site,
            writers: Some(writers),
            gates,
        })
    }
    pub fn plan(&self) -> &PlannedBundle {
        &self.planned
    }
    pub fn identity(&self) -> CodeIdentity {
        self.site.identity()
    }
    pub fn functions(&self) -> &[NormalModuleFunctionSite; 2] {
        self.site.functions()
    }
    pub fn roles(&self) -> impl ExactSizeIterator<Item = NormalModuleRole> + '_ {
        self.site.roles()
    }
    pub fn gates(&self) -> &[EarlyControlGateLayout] {
        &self.gates
    }
    /// # Safety
    /// Exact successful publication and complete quiescence receipts belong to
    /// this preparation. The loader's sole-entry, immutable source/alias and
    /// process-lived mapping obligations hold continuously. No call may occur
    /// until the distinct owned early-entry attachment succeeds. Both scalar
    /// functions and the sealed caller obey ordinary nonnested CALL/RET, without
    /// signal, unwind, cancellation, fork, CET or foreign writes. Callback stacks
    /// support the existing full state save/XSAVE. Disarm is not executable drain.
    pub unsafe fn seal(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledEarlyEntryModuleSite, SiteError> {
        let (prep, installed, receipt) = Box::leak(Box::new((self, installed, receipt)));
        // SAFETY: all actual publication owners were retained before checking.
        unsafe {
            check_publication(&prep.planned, installed, receipt, prep.site.identity)?;
        }
        prep.owner
            .verify_expected_pages(prep.planned.plan().final_bytes())
            .map_err(SiteError::Source)?;
        let writers = prep.writers.take().ok_or(SiteError::Correspondence)?;
        Ok(InstalledEarlyEntryModuleSite {
            site: Arc::clone(&prep.site),
            writers,
            gates: prep.gates.clone(),
        })
    }
}
impl InstalledEarlyEntryModuleSite {
    pub fn identity(&self) -> CodeIdentity {
        self.site.identity()
    }
    pub fn functions(&self) -> &[NormalModuleFunctionSite; 2] {
        self.site.functions()
    }
    pub fn roles(&self) -> impl ExactSizeIterator<Item = NormalModuleRole> + '_ {
        self.site.roles()
    }
    pub fn gates(&self) -> &[EarlyControlGateLayout] {
        &self.gates
    }
    /// Immutable identity-bearing controls only; no writer or callback mutation.
    pub fn role_controls(
        &self,
    ) -> impl ExactSizeIterator<Item = (NormalModuleRole, &ProbeControl)> + '_ {
        self.site.roles.iter().map(|r| (r.metadata, &r.control))
    }
}

type PreparedEarlyFunctions = (
    PlannedBundle,
    Vec<NormalModuleFunctionSite>,
    Vec<ModuleRole>,
    [ControlWriter; 2],
);

fn prepare_early_functions(
    functions: &[ModuleFunctionSource<'_>],
    originals: &[ExpectedBytes],
    identity: CodeIdentity,
    policies: &[PreparationPolicy],
) -> Result<PreparedEarlyFunctions, SiteError> {
    if functions.len() != 2 || policies.len() != functions.len() {
        return Err(SiteError::Correspondence);
    }
    if identity.mapping != functions[0].certificate.entry()
        || identity.generation == 0
        || functions
            .windows(2)
            .any(|w| w[0].certificate.range().1 > w[1].certificate.entry())
        || !(1..=2).contains(&originals.len())
        || originals
            .iter()
            .any(|p| p.address % 4096 != 0 || p.bytes.len() != 4096)
        || originals.windows(2).any(|w| w[0].address >= w[1].address)
    {
        return Err(SiteError::Correspondence);
    }
    let mut predecessor = Composition::new(identity, originals.to_vec())?;
    let mut union = originals.to_vec();
    let mut reserved = originals
        .iter()
        .map(|p| AddressRange::new(p.address, p.bytes.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut members = Vec::new();
    let mut all_roles = Vec::new();
    let mut writers = Vec::new();
    let sites = functions
        .iter()
        .map(|f| NormalModuleFunctionSite {
            entry: f.certificate.entry(),
            end: f.certificate.range().1,
            returns: f.certificate.returns().to_vec(),
        })
        .collect();
    let mut group_count = 0;
    for (function_index, function) in functions.iter().enumerate() {
        let entry = function.certificate.entry();
        let certificate = function.certificate;
        let scope = AddressRange::new(entry, function.code.len())?;
        let (source_start, source_end) = function.source_range;
        let source_len = usize::try_from(
            source_end
                .checked_sub(source_start)
                .ok_or(Refusal::InvalidRange)?,
        )
        .map_err(|_| Refusal::InvalidRange)?;
        let source = AddressRange::new(source_start, source_len)?;
        if certificate.range() != (entry, scope.end())
            || !(1..=256).contains(&function.code.len())
            || !source.covers(scope)
            || !matches!(source.len(), 4096 | 8192)
            || projection(originals, entry, function.code.len())? != function.code
        {
            return Err(SiteError::Correspondence);
        }
        let policy = policies[function_index];
        let groups = match policy {
            PreparationPolicy::CertifiedBlocks => groups(
                entry,
                certificate.returns(),
                certificate.blocks(),
                certificate.edges(),
            )?,
            PreparationPolicy::WholeFunction => whole::groups(
                scope,
                certificate.returns(),
                certificate.blocks(),
                certificate.edges(),
            )?,
        };
        let pcs: Vec<_> = std::iter::once(entry)
            .chain(certificate.returns().iter().copied())
            .collect();
        if pcs
            .iter()
            .any(|pc| !certificate.heads().contains(pc) || certificate.padding_heads().contains(pc))
            || certificate
                .blocks()
                .iter()
                .any(|&(a, b)| a < scope.start() || b > scope.end())
        {
            return Err(SiteError::Correspondence);
        }
        // SAFETY: this closed factory pairs these callbacks with the owned
        // depth-one protocol, mandatory RETs and exact sealed caller admission.
        let (first, writer) = unsafe {
            EntryAdmissionAction::entry(
                entry,
                crate::frontend_native::always_on::normal::early_entry_callback,
                false,
            )
        };
        writers.push(writer);
        let typed: Vec<_> = std::iter::once(first)
            .chain(certificate.returns().iter().map(|&pc| {
                EntryAdmissionAction::mandatory_return(
                    entry,
                    pc,
                    crate::frontend_native::always_on::normal::early_exit_callback,
                )
            }))
            .collect();
        let roles: Vec<_> = typed
            .iter()
            .map(|a| Role {
                pc: a.logical_pc(),
                control: a.control().clone(),
            })
            .collect();
        let entries = legal_entries(identity, scope, certificate);
        let mut overlay = function.code.to_vec();
        let mut full_overlay = projection(&union, source_start, source_len)?;
        FunctionPlanning {
            code: function.code,
            certificate,
            policy,
            identity,
            scope,
            groups: &groups,
            roles: &roles,
            entries: &entries,
            source_start,
        }
        .append_entry_admission(
            &typed,
            &mut predecessor,
            &mut reserved,
            &mut members,
            &mut overlay,
            &mut full_overlay,
        )?;
        replace_projection(&mut union, source_start, &full_overlay)?;
        group_count += groups.len();
        all_roles.extend(
            roles
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
    let planned = PlannedBundle::compose(originals.to_vec(), members, module_budget())?;
    if planned.images().len() != group_count
        || planned.plan().final_bytes() != predecessor.final_bytes()
        || planned.plan().final_bytes() != union
        || planned
            .images()
            .iter()
            .map(|i| i.controls().len())
            .sum::<usize>()
            != all_roles.len()
        || planned
            .images()
            .iter()
            .flat_map(|i| i.controls())
            .collect::<Vec<_>>()
            != all_roles.iter().map(|r| &r.control).collect::<Vec<_>>()
    {
        return Err(SiteError::Correspondence);
    }
    Ok((
        planned,
        sites,
        all_roles,
        writers.try_into().map_err(|_| SiteError::Correspondence)?,
    ))
}

#[cfg(test)]
impl ModuleSite {
    pub(in crate::frontend_native::always_on) fn synthetic_early(
        identity: CodeIdentity,
        functions: [(u64, u64, Vec<u64>); 2],
    ) -> (Arc<Self>, [ControlWriter; 2]) {
        let mut site = Self::synthetic(identity, functions);
        let site_mut = Arc::get_mut(&mut site).unwrap();
        site_mut.early_entry = true;
        site_mut.roles.clear();
        let mut writers = Vec::new();
        for (index, function) in site_mut.functions.iter().enumerate() {
            // SAFETY: pure metadata only; no opaque token or callable source minted.
            let (entry, writer) = unsafe {
                EntryAdmissionAction::entry(
                    function.entry,
                    crate::frontend_native::always_on::normal::early_entry_callback,
                    false,
                )
            };
            writers.push(writer);
            for action in std::iter::once(entry).chain(function.returns.iter().map(|&pc| {
                EntryAdmissionAction::mandatory_return(
                    function.entry,
                    pc,
                    crate::frontend_native::always_on::normal::early_exit_callback,
                )
            })) {
                site_mut.roles.push(ModuleRole {
                    metadata: NormalModuleRole {
                        function_index: index,
                        kind: if action.logical_pc() == function.entry {
                            NormalModuleRoleKind::Entry
                        } else {
                            NormalModuleRoleKind::Return
                        },
                        pc: action.logical_pc(),
                    },
                    control: action.control().clone(),
                });
            }
        }
        (site, writers.try_into().ok().unwrap())
    }
}
