//! Owned per-physical geometry, never complete-selection or execution authority.
use super::*;
use crate::search::RefusalEvidence;

/// One immutable collector result. A refused row grants no retained window.
#[derive(Clone, Debug)]
pub struct ArtifactPhysicalWindowRow {
    ordinal: usize,
    physical_pc: u64,
    outcome: Result<u64, Refusal>,
    qualification: Box<[RefusalEvidence]>,
}
impl ArtifactPhysicalWindowRow {
    /// Position in the complete original physical-head order.
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }
    /// Original physical head, including refused rows.
    pub const fn physical_pc(&self) -> u64 {
        self.physical_pc
    }
    /// Exact minimal end or original collector refusal, not image acceptance.
    pub fn outcome(&self) -> Result<u64, &Refusal> {
        self.outcome.as_ref().copied()
    }
    /// Ordered qualification observations from this collector call only.
    pub fn qualification(&self) -> &[RefusalEvidence] {
        &self.qualification
    }
}

/// Frozen immutable-source geometry for one ordered observation population.
///
/// Rows contain no decoded instructions, entry/hook borrows, prepared object or
/// mapping authority. The caller must bind FULL selected-manifest membership,
/// including accepted/straddling sites, for all ready windows and their maximum
/// upstream envelope. These bytes also cover refused collectors' dependencies;
/// they do not authorize displacement or attest the whole source cryptographically.
#[derive(Clone, Debug)]
pub struct ArtifactPhysicalWindowSchedule {
    identity: CodeIdentity,
    source: AddressRange,
    function: AddressRange,
    block: AddressRange,
    selected: AddressRange,
    observation_pcs: Box<[u64]>,
    search: SearchPolicy,
    domain: Box<[u64]>,
    rows: Box<[ArtifactPhysicalWindowRow]>,
    dependency: Option<(AddressRange, Box<[u8]>)>,
}
impl ArtifactPhysicalWindowSchedule {
    /// Original first selected head through last selected instruction.
    pub const fn selected_span(&self) -> AddressRange {
        self.selected
    }
    /// Exact supplied population; completeness remains caller-owned.
    pub fn observation_pcs(&self) -> &[u64] {
        &self.observation_pcs
    }
    /// The one supplied physical-search policy, never member-summed.
    pub const fn search_policy(&self) -> SearchPolicy {
        self.search
    }
    /// Complete shared head order, including heads omitted by max_sites.
    pub fn physical_domain(&self) -> &[u64] {
        &self.domain
    }
    /// Frozen prefix only; a row is not evidence that planning visited it.
    pub fn rows(&self) -> &[ArtifactPhysicalWindowRow] {
        &self.rows
    }
    /// Exact bounded comparison bytes, including refused suffix/lookahead bytes.
    /// None means no rows were sealed, not a whole-source identity proof.
    pub fn source_dependency(&self) -> Option<(AddressRange, &[u8])> {
        self.dependency
            .as_ref()
            .map(|(range, bytes)| (*range, bytes.as_ref()))
    }
    /// Join caller population and bounded immutable request facts only.
    /// Planning must still revalidate source, domain, entries and current overlay.
    pub fn matches_request(
        &self,
        artifact: &ArtifactRequest<'_>,
        observation_pcs: &[u64],
    ) -> Result<(), Refusal> {
        let site = &artifact.site;
        if site.identity != self.identity {
            return Err(Refusal::StaleGeneration);
        }
        if AddressRange::new(site.base_address, site.code.len())? != self.source
            || site.function != self.function
            || site.block != self.block
            || site.logical_pc != self.selected.start()
        {
            return Err(Refusal::InvalidRange);
        }
        if search_tuple(site.search) != search_tuple(self.search)
            || observation_pcs != self.observation_pcs.as_ref()
        {
            return Err(Refusal::InvalidPlan);
        }
        if let Some((range, bytes)) = &self.dependency {
            if retained_source_bytes(site.code, self.source, *range)? != bytes.as_ref() {
                return Err(Refusal::ExpectedBytesChanged);
            }
        }
        Ok(())
    }
    pub(super) fn authenticate(
        &self,
        input: &ArtifactObservationRequest<'_>,
        request: &PlanningRequest<'_>,
        scan: &ScanResult,
        domain: &[u64],
    ) -> Result<(), Refusal> {
        self.matches_request(&input.artifact, input.observation_pcs)?;
        if selected_observation_span(
            request,
            scan,
            *input.observation_pcs.last().ok_or(Refusal::InvalidPlan)?,
        )? != self.selected
            || domain != self.domain.as_ref()
            || self.rows.len() != domain.len().min(request.search.max_sites)
            || self
                .rows
                .iter()
                .enumerate()
                .any(|(ordinal, row)| row.ordinal != ordinal || domain[ordinal] != row.physical_pc)
            || self.rows.is_empty() != self.dependency.is_none()
        {
            return Err(Refusal::InvalidPlan);
        }
        Ok(())
    }
    pub(super) fn authenticate_row(
        &self,
        ordinal: usize,
        physical: u64,
        result: &Result<RelocationWindow<'_>, Refusal>,
        qualification: &[RefusalEvidence],
    ) -> Result<(), Refusal> {
        let row = self.rows.get(ordinal).ok_or(Refusal::InvalidPlan)?;
        let outcome = result.as_ref().map(|window| window.end);
        if row.ordinal != ordinal
            || row.physical_pc != physical
            || outcome != row.outcome()
            || qualification != row.qualification()
        {
            return Err(Refusal::InvalidPlan);
        }
        Ok(())
    }
}

fn search_tuple(policy: SearchPolicy) -> (TacticPolicy, usize, usize, usize) {
    (
        policy.tactics,
        policy.max_upstream_bytes,
        policy.max_displaced_bytes,
        policy.max_sites,
    )
}
fn check_array<T>(len: usize) -> Result<(), Refusal> {
    let bytes = len
        .checked_mul(core::mem::size_of::<T>())
        .ok_or(Refusal::InvalidRange)?;
    if bytes > isize::MAX as usize {
        return Err(Refusal::InvalidRange);
    }
    Ok(())
}
fn buffer<T>(len: usize) -> Result<Vec<T>, Refusal> {
    check_array::<T>(len)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(len)
        .map_err(|_| Refusal::Backend("artifact physical schedule allocation failed".into()))?;
    Ok(result)
}
fn copy_slice<T: Clone>(slice: &[T]) -> Result<Box<[T]>, Refusal> {
    let mut result = buffer(slice.len())?;
    result.extend_from_slice(slice);
    Ok(result.into_boxed_slice())
}

/// Freeze one immutable bounded collector schedule before overlay mutation.
///
/// Complete domain enumeration is shared; only its max_sites prefix is collected.
/// Every row keeps its exact first whole end or refusal and qualification evidence.
/// No image is attempted and no PhysicalSites work is claimed here. Global source
/// or population failure returns no schedule, attempts or search runs.
/// Named frontend limits remain caller-bound; this generic API adds no hard cap.
pub fn seal_artifact_observation_windows_upstream_min5(
    artifact: &ArtifactRequest<'_>,
    observation_pcs: &[u64],
) -> Result<ArtifactPhysicalWindowSchedule, PlanningFailure> {
    let mut search = SearchEvidence::default();
    let result = (|| {
        let request = PlanningRequest::artifact(artifact);
        let (source, scan) = validated_source_core(&request).inspect_err(|reason| {
            search.qualification(SearchScope::default(), reason);
        })?;
        let input = ArtifactObservationRequest {
            artifact: *artifact,
            physical_pc: request.logical_pc,
            end: request.block.end(),
            observation_pcs,
        };
        validate_population(&input, &scan).inspect_err(|reason| {
            search.qualification(SearchScope::default(), reason);
        })?;
        let last = *observation_pcs.last().ok_or(Refusal::InvalidPlan)?;
        let selected = selected_observation_span(&request, &scan, last)?;
        let domain = physical_head_schedule(&request, &scan);
        check_array::<u64>(domain.len())?;
        let count = domain.len().min(request.search.max_sites);
        let mut rows = buffer(count)?;
        let mut dependencies = RelocationDependencies::default();
        for (ordinal, &physical_pc) in domain.iter().take(count).enumerate() {
            let mut local = SearchEvidence::default();
            let outcome = collect_relocation_window_with_dependencies(
                &request,
                &scan,
                physical_pc,
                last,
                None,
                &mut local,
                Some(&mut dependencies),
            )
            .map(|window| window.end);
            check_array::<RefusalEvidence>(local.refusals.len())?;
            rows.push(ArtifactPhysicalWindowRow {
                ordinal,
                physical_pc,
                outcome,
                qualification: local.refusals.into_boxed_slice(),
            });
        }
        let dependency = dependencies
            .span()?
            .map(|span| {
                // A head exactly at the displaced bound can require a full15 bytes.
                // Overflow of this conservative ceiling still cannot exceed source.
                let ceiling = request
                    .search
                    .max_upstream_bytes
                    .checked_add(request.search.max_displaced_bytes)
                    .and_then(|n| n.checked_add(15))
                    .unwrap_or(usize::MAX);
                let ceiling = u64::try_from(ceiling)
                    .map_err(|_| Refusal::InvalidRange)?
                    .min(source.len());
                if span.len() > ceiling {
                    return Err(Refusal::InvalidRange);
                }
                let bytes = retained_source_bytes(request.original_code, source, span)?;
                Ok((span, copy_slice(bytes)?))
            })
            .transpose()?;
        Ok(ArtifactPhysicalWindowSchedule {
            identity: request.identity,
            source,
            function: request.function,
            block: request.block,
            selected,
            observation_pcs: copy_slice(observation_pcs)?,
            search: request.search,
            domain: domain.into_boxed_slice(),
            rows: rows.into_boxed_slice(),
            dependency,
        })
    })();
    result.map_err(|reason| PlanningFailure {
        reason,
        attempts: Vec::new(),
        search,
    })
}

/// Consume the sealed physical-min5 schedule through the existing artifact loop.
///
/// FULL manifest membership and selected-PC equality are consumer obligations.
/// Pending is the complete outside-group original interval set. All current-byte,
/// entry/CET, one-page fitting, callback/POP-RSP scratch, loader and final atomic
/// publication obligations remain. A matching refused row is one physical trial;
/// a schedule mismatch aborts the unit, not a skippable trial or a second search.
/// No live conversion or new runtime/complete-CFG qualification is granted.
pub fn plan_artifact_observation_windows_upstream_after_with_placement(
    artifact: &ArtifactRequest<'_>,
    schedule: &ArtifactPhysicalWindowSchedule,
    predecessor: &Composition,
    pending: &[AddressRange],
    placement: ArtifactRelocationPlacement,
) -> Result<ArtifactObservationPlan, PlanningFailure> {
    plan_artifact_observation_windows_upstream_after_with_placement_and_suffix(
        artifact,
        schedule,
        predecessor,
        pending,
        placement,
        ArtifactRoutedSuffix::Qualified62,
    )
}

/// Plan an artifact observation group with an explicit routed-suffix encoding.
///
/// The frozen schedule, FULL manifest and pending obligations, bounded physical
/// search, one image per physical trial and final composition checks are exactly
/// those of the default physical-min5 API. SingleByte60 changes only actual
/// routed suffix bytes at or beyond physical + 5 during the same emission; it
/// neither catches ownership refusals nor re-encodes a rejected plan. The caller
/// must bind this opt-in encoding to its policy and portable identity. Ordinary
/// and singleton planners retain their existing encoding and search behavior.
pub fn plan_artifact_observation_windows_upstream_after_with_placement_and_suffix(
    artifact: &ArtifactRequest<'_>,
    schedule: &ArtifactPhysicalWindowSchedule,
    predecessor: &Composition,
    pending: &[AddressRange],
    placement: ArtifactRelocationPlacement,
    suffix: ArtifactRoutedSuffix,
) -> Result<ArtifactObservationPlan, PlanningFailure> {
    let input = ArtifactObservationRequest {
        artifact: *artifact,
        physical_pc: artifact.site.logical_pc,
        end: artifact.site.block.end(),
        observation_pcs: schedule.observation_pcs(),
    };
    plan_window_with_geometry(
        &input,
        predecessor,
        pending,
        PhysicalDomain::Upstream,
        placement,
        suffix,
        WindowGeometry::PhysicalMin5(schedule),
    )
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
