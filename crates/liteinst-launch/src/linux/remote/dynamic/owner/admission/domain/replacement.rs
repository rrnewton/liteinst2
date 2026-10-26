//! Additive live-set installation after a root-owned native mapping transaction.
//! Ordinary same-source finish_rebind remains a separate unchanged contract.
use super::super::census::ResumeCensus;
use super::super::mapping::ReplacementCommit;
use super::resource::StagedSourceSet;
use super::*;

/// Descriptive model identity. Only mapping::ReplacementCommit authenticates
/// the owner/mm/capture/revocation and actual native epoch behind this tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct ReplacementIdentity {
    pub(in super::super) old_binding: SourceBinding,
    pub(in super::super) new_binding: SourceBinding,
    pub(in super::super) old_generation: u64,
    pub(in super::super) new_generation: u64,
    pub(in super::super) old_entry_version: u64,
    pub(in super::super) new_entry_version: u64,
}

/// New facts are immutable/private until the consuming native commit. The
/// native maker must authenticate these exact fields under its current hold.
pub(in super::super) struct StagedReplacement {
    identity: ReplacementIdentity,
    images: Vec<Image>,
    maps: Vec<MemoryMapping>,
    pages: BTreeMap<u64, bool>,
    catalog: StagedSourceSet,
}

impl StagedReplacement {
    pub(in super::super) fn identity(&self) -> ReplacementIdentity {
        self.identity
    }
    pub(in super::super) fn catalog_bytes(&self) -> usize {
        self.catalog.retained_bytes()
    }
    pub(in super::super) fn images(&self) -> &[Image] {
        &self.images
    }
    pub(in super::super) fn mappings(&self) -> &[MemoryMapping] {
        &self.maps
    }
    pub(in super::super) fn pages(&self) -> &BTreeMap<u64, bool> {
        &self.pages
    }
}

impl Domain {
    /// Pre-effect allocation only; the caller also reserves every source and
    /// history payload in the existing nonrefundable lifetime account.
    pub(in super::super) fn reserve_replacement_catalog_slot(&mut self) -> Result<(), GateError> {
        self.resource_basis.reserve_append()
    }

    /// Exact private-layout bound for an additional copied source-set leaf.
    /// The native transaction separately charges its live images/request/maps
    /// and publication proof; this value alone is neither a reservation nor a
    /// permission to stage or install a new mapping.
    pub(in super::super) fn replacement_catalog_bytes_bound(
        &self,
        additional_source: Option<(usize, usize)>,
        resume_facts: usize,
    ) -> Result<usize, GateError> {
        self.resource_basis
            .stage_bytes_bound(self.source_binding, additional_source, resume_facts)
    }

    pub(in super::super) fn stage_replacement(
        &self,
        images: Vec<Image>,
        maps: Vec<MemoryMapping>,
        until: Instant,
    ) -> Result<StagedReplacement, GateError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(GateError::Refused("dynamic source generation exhausted"))?;
        let version = self
            .entry_version
            .checked_add(1)
            .ok_or(GateError::Refused("dynamic entry version exhausted"))?;
        if images.iter().any(|image| {
            image.snapshot.generation != Generation(generation)
                || image.entries.generation() != image.snapshot.generation
                || image.entries.version() != version
                || image.core_identity.generation != generation
        }) {
            return Err(GateError::Refused(
                "dynamic replacement source epoch differs",
            ));
        }
        let pages = planning::initial_pages(&maps)?;
        let catalog = self
            .resource_basis
            .stage(&images, &maps, &self.policy, until)?;
        let identity = ReplacementIdentity {
            old_binding: self.source_binding,
            new_binding: catalog.binding(),
            old_generation: self.generation,
            new_generation: generation,
            old_entry_version: self.entry_version,
            new_entry_version: version,
        };
        Ok(StagedReplacement {
            identity,
            images,
            maps,
            pages,
            catalog,
        })
    }

    fn validate_replacement(&self, staged: &StagedReplacement) -> Result<(), GateError> {
        // Revocation may remove live native mappings, but the old model facts
        // must still match their independent retained leaf until installation.
        self.validate_live_source()?;
        let id = staged.identity;
        if id.old_binding != self.source_binding
            || id.old_generation != self.generation
            || id.old_entry_version != self.entry_version
            || self.generation.checked_add(1) != Some(id.new_generation)
            || self.entry_version.checked_add(1) != Some(id.new_entry_version)
            || self.pages.values().any(|executable| *executable)
            || !self.guards.is_empty()
            || !self.sites.is_empty()
            || self.generations.last().is_none_or(|last| {
                last.generation != self.generation
                    || last.entry_version != self.entry_version
                    || last.source_binding != self.source_binding
            })
        {
            return Err(GateError::Refused(
                "dynamic replacement does not follow exact revocation",
            ));
        }
        self.resource_basis
            .validate_candidate(&staged.catalog, id)?;
        staged
            .catalog
            .validate_live(&staged.images, &staged.maps, &self.policy)?;
        staged.catalog.validate_pages(&staged.pages)?;
        if staged.pages.values().any(|executable| *executable)
            || staged.images.iter().any(|image| {
                image.snapshot.generation != Generation(id.new_generation)
                    || image.entries.generation() != image.snapshot.generation
                    || image.entries.version() != id.new_entry_version
                    || image.core_identity.generation != id.new_generation
            })
            || self
                .plans
                .iter()
                .any(|plan| plan.pending.snapshot().generation.0 > id.old_generation)
        {
            return Err(GateError::Refused(
                "dynamic replacement source epoch differs",
            ));
        }
        self.audit_retained_history_at(id.new_generation, id.new_entry_version, id.new_binding)
    }

    /// Install a complete new live source set only after native replacement,
    /// real epoch advance and refreshed exact continuation projection. Old
    /// leaves, plans, generations and the same CALL ledger remain retained.
    pub(in super::super) fn commit_replacement(
        &mut self,
        staged: StagedReplacement,
        native: ReplacementCommit,
        census: &ResumeCensus,
    ) -> Result<(), GateError> {
        self.validate_replacement(&staged)?;
        if census.generation() != staged.identity.new_generation {
            return Err(GateError::Refused(
                "dynamic replacement census epoch differs",
            ));
        }
        census
            .validate_projection(
                &staged
                    .images
                    .iter()
                    .map(|image| image.entries.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(super::super::census_error)?;
        self.resource_basis
            .commit(staged.catalog, &native, staged.identity)?;
        self.install_replacement_fields(staged.identity, staged.images, staged.maps, staged.pages);
        Ok(())
    }

    // All fallible validation and catalog insertion precede these moves. No
    // old CALL ledger, source leaf, plan or generation is replaced or cleared.
    fn install_replacement_fields(
        &mut self,
        identity: ReplacementIdentity,
        images: Vec<Image>,
        maps: Vec<MemoryMapping>,
        pages: BTreeMap<u64, bool>,
    ) {
        self.images = images;
        self.original_executables = maps;
        self.pages = pages;
        self.source_binding = identity.new_binding;
        self.generation = identity.new_generation;
        self.entry_version = identity.new_entry_version;
    }

    /// Pure tests deliberately supply only model histories; this does not
    /// create a ReplacementCommit or qualify any native mapping operation.
    #[cfg(test)]
    pub(super) fn commit_replacement_model(
        &mut self,
        staged: StagedReplacement,
    ) -> Result<(), GateError> {
        self.validate_replacement(&staged)?;
        self.resource_basis
            .commit_model(staged.catalog, staged.identity)?;
        self.install_replacement_fields(staged.identity, staged.images, staged.maps, staged.pages);
        Ok(())
    }
}
