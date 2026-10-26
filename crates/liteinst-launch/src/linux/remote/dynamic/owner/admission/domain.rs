//! Original source facts and append-only plans owned by one native mm.
//! Native permissions, current stops and resume routes are checked by the
//! transaction layer; none of this bookkeeping alone authorizes execution.
use super::*;
use crate::gate::domain::{
    self as planning, GateOracle, Image, PAGE, PendingAdmission, PendingTrapBackend,
};
use crate::trap_coverage::{TrapCoverageBudget, TrapGuard, TrapGuardRole};
use liteinst_admission::Generation;
use liteinst_admission::entries::LegalEntrySet;
use liteinst_admission::returns::CallReturnLedger;
use liteinst_admission::scan::{Candidate, Policy, Snapshot};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod exec_oracle;
mod replacement;
mod resource;

pub(super) use replacement::{ReplacementIdentity, StagedReplacement};
#[cfg(test)]
mod tests;
pub(super) use resource::SourceBinding;
use resource::{ResourceBasis, SourceCatalog};

pub(super) struct Domain {
    pub(super) images: Vec<Image>,
    pub(super) original_executables: Vec<MemoryMapping>,
    pub(super) pages: BTreeMap<u64, bool>,
    pub(super) sites: BTreeMap<u64, Candidate>,
    pub(super) guards: BTreeMap<u64, TrapGuard>,
    pub(super) oracle: GateOracle,
    pub(super) returns: CallReturnLedger,
    pub(super) policy: Policy,
    pub(super) backend: DynamicAdmissionBackend,
    pub(super) generation: u64,
    pub(super) entry_version: u64,
    pub(super) plans: Vec<InstalledPlan>,
    pub(super) generations: Vec<RetiredGeneration>,
    pub(super) source_binding: SourceBinding,
    resource_basis: SourceCatalog,
    next_plan: u64,
}

/// An armed receipt is native evidence retained for auditing, not a reusable
/// exclusion capability. Every later release reauthenticates its current facts.
pub(super) struct InstalledPlan {
    pub(super) id: u64,
    pub(super) source_binding: SourceBinding,
    pub(super) pending: PendingAdmission,
    pub(super) routes: Vec<super::routes::ResolvedRoute>,
}

pub(super) struct RetiredGeneration {
    pub(super) generation: u64,
    pub(super) entry_version: u64,
    pub(super) source_binding: SourceBinding,
    pub(super) executable_pages: BTreeSet<u64>,
    pub(super) guards: BTreeMap<u64, TrapGuard>,
    pub(super) sites: BTreeMap<u64, Candidate>,
}

impl Domain {
    pub(super) fn mapping_catalog_bytes(mappings: &[MemoryMapping]) -> Result<usize, GateError> {
        ResourceBasis::mapping_bytes(mappings)?
            .checked_add(std::mem::size_of::<SourceBinding>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceCatalog>()))
            .ok_or(GateError::Refused("dynamic resource basis size overflows"))
    }

    pub(super) fn new(
        facts: Vec<crate::gate::ImageFacts>,
        original_executables: Vec<MemoryMapping>,
        options: &DynamicAdmissionOptions,
        until: Instant,
        read: impl FnMut(u64, usize) -> Result<Vec<u8>, LaunchError>,
    ) -> Result<Self, GateError> {
        planning::validate_image_count(&facts)?;
        let pages = planning::initial_pages(&original_executables)?;
        let images = planning::prepare_images(facts, &original_executables, read)?;
        let policy = Policy::default();
        let (resource_basis, source_binding) =
            SourceCatalog::new(&images, &original_executables, &policy, until)?;
        Ok(Self {
            images,
            original_executables,
            pages,
            sites: BTreeMap::new(),
            guards: BTreeMap::new(),
            oracle: GateOracle::new(options.cache)?,
            returns: CallReturnLedger::new(),
            policy,
            backend: options.backend,
            generation: 0,
            entry_version: 0,
            plans: Vec::new(),
            generations: Vec::new(),
            source_binding,
            resource_basis,
            next_plan: 1,
        })
    }

    pub(super) fn source_candidate_bound(&self) -> Result<usize, GateError> {
        self.resource_basis.candidates(
            self.source_binding,
            &self.images,
            &self.original_executables,
            &self.policy,
        )
    }

    pub(super) fn resource_scan_decoded_starts(&self) -> usize {
        self.resource_basis.decoded_starts()
    }

    pub(super) fn resource_basis_bytes(&self) -> usize {
        self.resource_basis.retained_bytes()
    }

    /// The catalog and current binding headers are already embedded in Domain.
    /// Callers charging the whole Domain retain only this additional payload.
    pub(super) fn resource_payload_bytes(&self) -> Result<usize, GateError> {
        self.resource_basis_bytes()
            .checked_sub(std::mem::size_of::<SourceCatalog>())
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<SourceBinding>()))
            .ok_or(GateError::Refused(
                "dynamic resource embedded headers differ",
            ))
    }

    pub(super) fn image(&self, pc: u64) -> Result<&Image, GateError> {
        self.images
            .iter()
            .find(|image| image.snapshot.range().contains(pc))
            .ok_or(GateError::Refused(
                "dynamic continuation has no original image census",
            ))
    }

    pub(super) fn original_decode(&self, pc: u64) -> Result<Vec<u8>, GateError> {
        let image = self.image(pc)?;
        if !image.entries.heads().contains_key(&pc) {
            return Err(GateError::Refused(
                "dynamic continuation is not a declared instruction head",
            ));
        }
        self.original_candidate_decode(pc)
    }

    // All-start coverage guards may name embedded candidates. Only continuation
    // routes require the stricter declared-head check in original_decode.
    fn original_candidate_decode(&self, pc: u64) -> Result<Vec<u8>, GateError> {
        let image = self.image(pc)?;
        let offset = (pc - image.mapping.start) as usize;
        let instruction = iced_x86::Decoder::with_ip(
            64,
            &image.snapshot.bytes()[offset..],
            pc,
            iced_x86::DecoderOptions::NONE,
        )
        .decode();
        if instruction.is_invalid() || instruction.len() == 0 {
            return Err(GateError::Refused(
                "dynamic continuation lacks a whole original decode",
            ));
        }
        let end = offset
            .checked_add(instruction.len())
            .filter(|end| *end <= image.snapshot.bytes().len())
            .ok_or(GateError::Refused(
                "dynamic continuation decode leaves its source census",
            ))?;
        Ok(image.snapshot.bytes()[offset..end].to_vec())
    }

    pub(super) fn expected_image(&self, image: &Image) -> Vec<u8> {
        planning::armed_instruction(
            image.mapping.start,
            image.snapshot.bytes(),
            &self.sites,
            &self.guards,
        )
    }

    pub(super) fn expected_instruction(&self, pc: u64, original: &[u8]) -> Vec<u8> {
        planning::armed_instruction(pc, original, &self.sites, &self.guards)
    }

    pub(super) fn plan(&self, page: u64, until: Instant) -> Result<PendingAdmission, GateError> {
        if self.pages.get(&page) != Some(&false) {
            return Err(GateError::Refused(
                "dynamic admission requires a currently NX page",
            ));
        }
        let image = self.image(page)?;
        match self.backend {
            DynamicAdmissionBackend::StrictTrap => planning::prepare_admission_pending_resumes(
                (image, &self.oracle),
                page,
                &self.policy,
                &self.returns,
                (&self.guards, TrapCoverageBudget::default()),
                until,
            ),
            DynamicAdmissionBackend::CoverageTrap(budget) => {
                planning::prepare_covered_admission_pending_resumes(
                    (image, &self.oracle),
                    page,
                    &self.policy,
                    &self.returns,
                    (&self.guards, budget),
                    until,
                )
            }
        }
    }

    pub(super) fn validate_plan(&self, plan: &PendingAdmission) -> Result<(), GateError> {
        self.validate_live_source()?;
        let image = self.image(plan.target().start())?;
        if plan.snapshot() != &image.snapshot
            || plan.entries() != &image.entries
            || plan.policy() != &self.policy
            || plan.page_size() != PAGE
            || plan.installed_guards() != &self.guards
            || image.snapshot.generation != Generation(self.generation)
            || image.entries.version() != self.entry_version
        {
            return Err(GateError::Refused("dynamic pending plan facts are stale"));
        }
        for guard in plan.guards().values() {
            if self
                .guards
                .get(&guard.address())
                .is_some_and(|old| old != guard)
            {
                return Err(GateError::Refused(
                    "dynamic guard conflicts with an installed original decode",
                ));
            }
        }
        Ok(())
    }

    // Called only after native route qualification but BEFORE writes or X. A
    // later failure may retain conservative extra history; it never removes it.
    pub(super) fn record_callers(&mut self, plan: &PendingAdmission) -> Result<(), GateError> {
        self.validate_plan(plan)?;
        for &caller in plan.planned_callers() {
            match plan.backend() {
                PendingTrapBackend::Strict => {
                    self.returns
                        .record_before_admission(plan.snapshot(), caller, plan.entries())
                }
                PendingTrapBackend::Coverage => {
                    self.returns.record_independent_streams_before_admission(
                        plan.snapshot(),
                        caller,
                        plan.entries(),
                    )
                }
            }
            .map_err(|_| {
                GateError::Refused("dynamic CALL history conflicts with pending source facts")
            })?;
        }
        Ok(())
    }

    pub(super) fn allocate_plan_id(&mut self) -> Result<u64, GateError> {
        let id = self.next_plan;
        self.next_plan = id
            .checked_add(1)
            .ok_or(GateError::Refused("dynamic plan identity exhausted"))?;
        self.plans
            .try_reserve(1)
            .map_err(|_| GateError::Refused("dynamic plan history allocation failed"))?;
        Ok(id)
    }

    /// Caller supplies only a successfully applied native transaction and its
    /// exact final routes. This records evidence; it does not enable a release.
    pub(super) fn record_installed(
        &mut self,
        id: u64,
        plan: PendingAdmission,
        routes: Vec<super::routes::ResolvedRoute>,
    ) -> Result<(), GateError> {
        self.validate_plan(&plan)?;
        if id == 0 || id >= self.next_plan || self.plans.iter().any(|old| old.id == id) {
            return Err(GateError::Refused(
                "dynamic plan identity is stale or reused",
            ));
        }
        for guard in plan.guards().values() {
            self.guards.insert(guard.address(), guard.clone());
            if let TrapGuardRole::Selected(site) = guard.role() {
                self.sites.insert(site.address, site);
            }
        }
        for &page in plan.pages() {
            let Some(state) = self.pages.get_mut(&page) else {
                return Err(GateError::Refused(
                    "dynamic plan grants X outside the original page inventory",
                ));
            };
            *state = true;
        }
        self.plans.push(InstalledPlan {
            id,
            source_binding: self.source_binding,
            pending: plan,
            routes,
        });
        Ok(())
    }

    /// Stage complete entry facts before mutation. Initial construction uses
    /// generation zero; subsequent calls require exactly the next generation.
    pub(super) fn projected_images(
        &self,
        generation: u64,
        projections: &[super::census::Projection],
    ) -> Result<Vec<Image>, GateError> {
        if generation != self.generation && self.generation.checked_add(1) != Some(generation) {
            return Err(GateError::Refused(
                "dynamic source generation is not adjacent",
            ));
        }
        let version = if generation == self.generation {
            self.entry_version
        } else {
            self.entry_version
                .checked_add(1)
                .ok_or(GateError::Refused("dynamic entry version exhausted"))?
        };
        if projections.len() != self.images.len() {
            return Err(GateError::Refused(
                "dynamic resume projection image count differs",
            ));
        }
        self.images
            .iter()
            .zip(projections)
            .map(|(image, projection)| {
                if projection.mapping != image.snapshot.mapping
                    || projection.scope != image.snapshot.range()
                {
                    return Err(GateError::Refused(
                        "dynamic resume projection names another image",
                    ));
                }
                let snapshot = Snapshot::new(
                    image.snapshot.mapping,
                    Generation(generation),
                    image.mapping.start,
                    image.snapshot.bytes().to_vec(),
                    image.snapshot.before,
                    image.snapshot.after,
                    image.snapshot.writes,
                )
                .ok_or(GateError::Refused("dynamic rebound source range differs"))?;
                let heads = image
                    .entries
                    .heads()
                    .iter()
                    .flat_map(|(&pc, kinds)| kinds.iter().map(move |&kind| (pc, kind)));
                let resumes = projection
                    .resumes
                    .iter()
                    .flat_map(|(&pc, kinds)| kinds.iter().map(move |&kind| (pc, kind)));
                let entries = LegalEntrySet::new(
                    snapshot.mapping,
                    snapshot.generation,
                    version,
                    snapshot.range(),
                    image.entries.completeness(),
                    heads,
                    resumes,
                )
                .map_err(|_| {
                    GateError::Refused("dynamic projected entry leaves original census")
                })?;
                let mut core_identity = image.core_identity;
                core_identity.generation = generation;
                Ok(Image {
                    mapping: image.mapping.clone(),
                    snapshot,
                    entries,
                    core_identity,
                })
            })
            .collect()
    }

    /// Audit retained receipts without treating them as a fresh native permit.
    /// Invalidation never erases old guard geometry or changes a source version.
    pub(super) fn audit_history(&self) -> Result<(), GateError> {
        self.validate_live_source()?;
        self.audit_retained_history()
    }

    /// Match live source geometry separately from historical evidence. A later
    /// native replacement transaction must establish a new live binding; an
    /// old receipt never licenses changed bytes or mapping permissions.
    fn validate_live_source(&self) -> Result<(), GateError> {
        self.source_candidate_bound()?;
        self.resource_basis
            .validate_pages(self.source_binding, &self.pages)?;
        if self.images.iter().any(|image| {
            image.snapshot.generation != Generation(self.generation)
                || image.entries.generation() != image.snapshot.generation
                || image.entries.version() != self.entry_version
                || image.core_identity.generation != self.generation
        }) {
            return Err(GateError::Refused("dynamic live source epoch differs"));
        }
        Ok(())
    }

    fn source_for_generation(
        &self,
        generation: u64,
        current_generation: u64,
        current_binding: SourceBinding,
    ) -> Result<SourceBinding, GateError> {
        if generation == current_generation {
            return Ok(current_binding);
        }
        let retired = usize::try_from(generation)
            .ok()
            .and_then(|index| self.generations.get(index))
            .filter(|retired| retired.generation == generation)
            .ok_or(GateError::Refused(
                "dynamic historical source epoch is absent",
            ))?;
        Ok(retired.source_binding)
    }

    /// Retained evidence is checked against the separately owned original
    /// census. Neither a mutable live image nor a plan's own bytes can vouch
    /// for that plan. This is an audit, never native release authority.
    fn audit_retained_history(&self) -> Result<(), GateError> {
        self.audit_retained_history_at(self.generation, self.entry_version, self.source_binding)
    }

    // The ordinary audit passes its exact current identity. Replacement uses
    // the prospective next epoch while all old model fields remain unchanged.
    fn audit_retained_history_at(
        &self,
        generation: u64,
        entry_version: u64,
        source_binding: SourceBinding,
    ) -> Result<(), GateError> {
        if generation != entry_version || self.generations.len() as u64 != generation {
            return Err(GateError::Refused(
                "dynamic retained epoch chain is discontinuous",
            ));
        }
        for (index, retired) in self.generations.iter().enumerate() {
            if retired.generation != index as u64 || retired.entry_version != index as u64 {
                return Err(GateError::Refused(
                    "dynamic retired generation identity differs",
                ));
            }
            for &page in &retired.executable_pages {
                if !self
                    .resource_basis
                    .contains_page(retired.source_binding, page)?
                {
                    return Err(GateError::Refused(
                        "dynamic retired page lost its source identity",
                    ));
                }
            }
            // Authenticate even an empty retired generation's source binding.
            self.resource_basis
                .validate_binding(retired.source_binding)?;
            for (&pc, guard) in &retired.guards {
                if pc != guard.address()
                    || self
                        .resource_basis
                        .original_candidate_decode(retired.source_binding, pc)?
                        != guard.original_bytes()
                    || !self.plans.iter().any(|plan| {
                        plan.pending.snapshot().generation.0 == retired.generation
                            && plan.source_binding == retired.source_binding
                            && plan.pending.guards().get(&pc) == Some(guard)
                    })
                    || !retired.executable_pages.contains(&(pc & !(PAGE - 1)))
                {
                    return Err(GateError::Refused(
                        "dynamic retired guard lost its source identity",
                    ));
                }
                if let TrapGuardRole::Selected(site) = guard.role() {
                    if retired.sites.get(&pc) != Some(&site) {
                        return Err(GateError::Refused(
                            "dynamic retired selected site differs from its guard",
                        ));
                    }
                }
            }
            if retired.sites.iter().any(|(&pc, site)| {
                retired
                    .guards
                    .get(&pc)
                    .is_none_or(|guard| guard.role() != TrapGuardRole::Selected(*site))
            }) {
                return Err(GateError::Refused(
                    "dynamic retired selected inventory has an unguarded site",
                ));
            }
        }
        let mut last = 0;
        for plan in &self.plans {
            let plan_generation = plan.pending.snapshot().generation.0;
            if plan.id <= last
                || plan.id >= self.next_plan
                || plan_generation > generation
                || plan.pending.entries().generation() != plan.pending.snapshot().generation
                || plan.pending.entries().version() != plan_generation
                || plan.source_binding
                    != self.source_for_generation(plan_generation, generation, source_binding)?
            {
                return Err(GateError::Refused(
                    "dynamic retained plan identity is reused or stale",
                ));
            }
            self.resource_basis.validate_retained(
                plan.source_binding,
                plan.pending.snapshot(),
                plan.pending.entries(),
                plan.pending.policy(),
            )?;
            for route in &plan.routes {
                if route.generation != plan_generation
                    || route.entry_version != plan_generation
                    || route.plan != plan.id
                    || self
                        .resource_basis
                        .original_decode(plan.source_binding, route.pc)?
                        != route.original
                {
                    return Err(GateError::Refused(
                        "dynamic retained route lost its original plan facts",
                    ));
                }
            }
            last = plan.id;
        }
        Ok(())
    }

    pub(super) fn executable_pages(&self) -> BTreeSet<u64> {
        self.pages
            .iter()
            .filter_map(|(&page, &executable)| executable.then_some(page))
            .collect()
    }

    pub(super) fn protection(&self, page: u64, executable: bool) -> Result<i32, GateError> {
        let mapping = self
            .original_executables
            .iter()
            .find(|mapping| mapping.start <= page && page + PAGE <= mapping.end)
            .ok_or(GateError::Refused(
                "dynamic permission page is outside original mappings",
            ))?;
        let read = if mapping.permissions.as_bytes().first() == Some(&b'r') {
            libc::PROT_READ
        } else {
            0
        };
        Ok(read | if executable { libc::PROT_EXEC } else { 0 })
    }
}
