//! One transaction for two complete scalar leaves, with immutable function roles.
use super::*;
use crate::frontend_native::{IntegerLeafCertificate, LoadedNormalModule};
use liteinst2::controls::ControlIdentity;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalModuleFunctionSite {
    entry: u64,
    end: u64,
    returns: Vec<u64>,
}
impl NormalModuleFunctionSite {
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn range(&self) -> (u64, u64) {
        (self.entry, self.end)
    }
    pub fn returns(&self) -> &[u64] {
        &self.returns
    }
}
/// Explicit per-function planning choice; never inferred from a failed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalModulePreparationPolicy {
    CertifiedBlocks,
    WholeFunction,
}
impl NormalModulePreparationPolicy {
    fn internal(self) -> PreparationPolicy {
        match self {
            Self::CertifiedBlocks => PreparationPolicy::CertifiedBlocks,
            Self::WholeFunction => PreparationPolicy::WholeFunction,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalModuleRoleKind {
    Entry,
    Return,
}
/// Metadata only; this value conveys no control or callback authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalModuleRole {
    pub function_index: usize,
    pub kind: NormalModuleRoleKind,
    pub pc: u64,
}
struct ModuleRole {
    metadata: NormalModuleRole,
    control: ProbeControl,
}
pub(in crate::frontend_native::always_on) struct ModuleSite {
    identity: CodeIdentity,
    functions: [NormalModuleFunctionSite; 2],
    roles: Vec<ModuleRole>,
}
impl ModuleSite {
    pub(in crate::frontend_native::always_on) fn identity(&self) -> CodeIdentity {
        self.identity
    }
    pub(in crate::frontend_native::always_on) fn functions(
        &self,
    ) -> &[NormalModuleFunctionSite; 2] {
        &self.functions
    }
    pub(in crate::frontend_native::always_on) fn roles(
        &self,
    ) -> impl ExactSizeIterator<Item = NormalModuleRole> + '_ {
        self.roles.iter().map(|role| role.metadata)
    }
    // Intentionally uncalled until the separate module attachment exists. The
    // sealed table cannot be replaced by a leaf Site or a fabricated token.
    #[allow(dead_code)]
    pub(in crate::frontend_native::always_on) fn resolve(
        &self,
        pc: u64,
        control: ControlIdentity<'_>,
        entry: bool,
    ) -> Option<usize> {
        self.role_at(pc, entry)
            .filter(|role| role.control.has_identity(control))
            .map(|role| role.metadata.function_index)
    }
    fn role_at(&self, pc: u64, entry: bool) -> Option<&ModuleRole> {
        self.roles.iter().find(|role| {
            role.metadata.pc == pc && (role.metadata.kind == NormalModuleRoleKind::Entry) == entry
        })
    }
}

// Nonexecuting metadata fixtures only. A synthetic table is never a loaded
// owner, successful publication or opaque managed callback token.
#[cfg(test)]
impl ModuleSite {
    pub(in crate::frontend_native::always_on) fn synthetic(
        identity: CodeIdentity,
        functions: [(u64, u64, Vec<u64>); 2],
    ) -> Arc<Self> {
        assert_eq!(identity.mapping, functions[0].0);
        assert_ne!(identity.generation, 0);
        assert!(functions[0].1 <= functions[1].0);
        let functions = functions.map(|(entry, end, returns)| {
            assert!(
                entry != 0
                    && end
                        .checked_sub(entry)
                        .is_some_and(|n| (1..=256).contains(&n))
            );
            assert!((1..=4).contains(&returns.len()));
            assert!(returns.iter().all(|&pc| entry < pc && pc < end));
            assert!(returns.windows(2).all(|w| w[0] < w[1]));
            NormalModuleFunctionSite {
                entry,
                end,
                returns,
            }
        });
        let mut roles = Vec::new();
        for (function_index, function) in functions.iter().enumerate() {
            let pcs: Vec<_> = std::iter::once(function.entry)
                .chain(function.returns.iter().copied())
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
        function_index: usize,
        entry: bool,
        pc: u64,
    ) -> Option<&ProbeControl> {
        self.role_at(pc, entry)
            .filter(|role| role.metadata.function_index == function_index)
            .map(|role| &role.control)
    }
    pub(in crate::frontend_native::always_on) fn resolve_control(
        &self,
        pc: u64,
        control: &ProbeControl,
        entry: bool,
    ) -> Option<usize> {
        self.role_at(pc, entry)
            .filter(|role| role.control == *control)
            .map(|role| role.metadata.function_index)
    }
}

/// Planning owns both functions; no source is published and no call is allowed.
pub struct NormalModuleSitePreparation {
    owner: &'static mut LoadedNormalModule,
    planned: PlannedBundle,
    site: Arc<ModuleSite>,
}
/// Successful retained publication, not a calling-thread attachment.
pub struct InstalledNormalModuleSite {
    pub(in crate::frontend_native::always_on) site: Arc<super::ModuleSite>,
}
impl InstalledNormalModuleSite {
    pub fn identity(&self) -> CodeIdentity {
        self.site.identity()
    }
    pub fn functions(&self) -> &[NormalModuleFunctionSite; 2] {
        self.site.functions()
    }
    pub fn roles(&self) -> impl ExactSizeIterator<Item = NormalModuleRole> + '_ {
        self.site.roles()
    }
}
impl NormalModuleSitePreparation {
    /// Prepare all entries and every RET in their own certified role blocks.
    /// The common identity names the first runtime entry and a nonzero generation.
    /// Each function retains its existing 256-byte/four-RET/five-group limits.
    /// No whole-function fallback or relaxed per-member search is available.
    ///
    /// The loaded owner's continuous unsafe custody contract remains in force.
    /// Original calls must already have returned. There is no module attachment
    /// in this API; even successful publication does not yet authorize calls.
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
    /// Prepare each complete function using its explicit policy. WholeFunction
    /// retains the original 5..=80-byte ceiling and complete-body checks;
    /// CertifiedBlocks retains the 256-byte certificate and separate role-block
    /// windows. There is no fallback, padding, splitting or omitted role.
    /// The same continuous owner/publication/attachment obligations apply.
    pub fn new_with_policies(
        owner: &'static mut LoadedNormalModule,
        identity: CodeIdentity,
        policies: [NormalModulePreparationPolicy; 2],
    ) -> Result<Self, SiteError> {
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        owner.verify_original().map_err(SiteError::Source)?;
        let functions = owner.functions().each_ref().map(|f| ModuleFunctionSource {
            code: f.code(),
            certificate: f.certificate(),
            source_range: f.source_range(),
        });
        let (planned, site) = prepare_module(
            functions,
            owner.source_pages(),
            identity,
            policies.map(NormalModulePreparationPolicy::internal),
        )?;
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
    pub fn functions(&self) -> &[NormalModuleFunctionSite; 2] {
        self.site.functions()
    }
    pub fn roles(&self) -> impl ExactSizeIterator<Item = NormalModuleRole> + '_ {
        self.site.roles()
    }

    /// Retain the entire real transaction before every fallible correspondence
    /// check. Refusal never rolls back, frees or unloads a published owner.
    ///
    /// # Safety
    /// The real successful publication, receipt, complete source/generated
    /// quiescence leases and final RX bytes belong to this exact preparation.
    /// All source/image ranges remain readable and process-lived. No subject
    /// entry or saved resume can run until sealing and a matching future module
    /// attachment finish. The loader's two-function, one-thread, depth-one ABI,
    /// input, termination and ordinary CALL/RET contract holds continuously.
    /// There is no code-as-data, alias writer, unload, fork, CET, signal entry,
    /// unwind/nonlocal exit or mapping/protection change; callbacks have enough
    /// writable state-save/XSAVE stack. Metadata drain is not executable drain.
    pub unsafe fn seal(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledNormalModuleSite, SiteError> {
        let (prep, installed, receipt) = Box::leak(Box::new((self, installed, receipt)));
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        if installed.is_retired()
            || !same_bundle(installed.plan(), prep.planned.plan())
            || !same_bundle(receipt.plan(), prep.planned.plan())
            || installed.trampolines().len() != prep.planned.images().len()
            || prep.site.identity != prep.planned.plan().identity()
        {
            return Err(SiteError::Correspondence);
        }
        for (image, executable) in prep.planned.images().iter().zip(installed.trampolines()) {
            // SAFETY: complete real retained publication/readability above.
            unsafe {
                check_image(image, executable)?;
            }
        }
        prep.owner
            .verify_expected_pages(prep.planned.plan().final_bytes())
            .map_err(SiteError::Source)?;
        Ok(InstalledNormalModuleSite {
            site: Arc::clone(&prep.site),
        })
    }
}

// Pure planning inputs, not a loader/caller authority. Production obtains each
// certificate only from the retained owner; tests use the real scalar decoder.
struct ModuleFunctionSource<'a> {
    code: &'a [u8],
    certificate: &'a IntegerLeafCertificate,
    source_range: (u64, u64),
}
fn module_budget() -> BundleBudget {
    BundleBudget {
        max_steps: 10,
        max_mappings: 10,
        max_virtual_bytes: 10 * 8192,
        max_backing_bytes: 10 * 8192,
        max_virtual_span: 1 << 32,
    }
}
fn prepare_module(
    functions: [ModuleFunctionSource<'_>; 2],
    originals: &[ExpectedBytes],
    identity: CodeIdentity,
    policies: [PreparationPolicy; 2],
) -> Result<(PlannedBundle, Arc<ModuleSite>), SiteError> {
    if identity.mapping != functions[0].certificate.entry()
        || identity.generation == 0
        || functions[0].certificate.range().1 > functions[1].certificate.entry()
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
    let sites = functions.each_ref().map(|f| NormalModuleFunctionSite {
        entry: f.certificate.entry(),
        end: f.certificate.range().1,
        returns: f.certificate.returns().to_vec(),
    });
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
        let roles = mandatory_roles(&pcs, CallbackProfile::Normal);
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
        .append(
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
        Arc::new(ModuleSite {
            identity,
            functions: sites,
            roles: all_roles,
        }),
    ))
}

fn projection(pages: &[ExpectedBytes], start: u64, len: usize) -> Result<Vec<u8>, SiteError> {
    let wanted = AddressRange::new(start, len)?;
    let mut result = Vec::with_capacity(len);
    let mut cursor = start;
    for page in pages {
        let end = page
            .address
            .checked_add(page.bytes.len() as u64)
            .ok_or(Refusal::InvalidRange)?;
        if cursor >= page.address && cursor < end && cursor < wanted.end() {
            let next = end.min(wanted.end());
            result.extend_from_slice(
                &page.bytes[(cursor - page.address) as usize..(next - page.address) as usize],
            );
            cursor = next;
        }
    }
    if cursor != wanted.end() {
        return Err(SiteError::Core(Refusal::DependencyNotHeld));
    }
    Ok(result)
}
fn replace_projection(
    pages: &mut [ExpectedBytes],
    start: u64,
    bytes: &[u8],
) -> Result<(), SiteError> {
    // Authenticate complete coverage before modifying the local expectation.
    projection(pages, start, bytes.len())?;
    let end = start
        .checked_add(bytes.len() as u64)
        .ok_or(Refusal::InvalidRange)?;
    for page in pages {
        let page_end = page
            .address
            .checked_add(page.bytes.len() as u64)
            .ok_or(Refusal::InvalidRange)?;
        let from = start.max(page.address);
        let to = end.min(page_end);
        if from < to {
            page.bytes[(from - page.address) as usize..(to - page.address) as usize]
                .copy_from_slice(&bytes[(from - start) as usize..(to - start) as usize]);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
