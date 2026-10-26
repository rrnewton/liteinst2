//! Operation-specific source storage and possible executable-source envelope.
//! It adds to the old transition; it never replaces or refunds it.
use super::*;
use crate::gate::domain::Image;
use crate::linux::remote::dynamic::admission::{
    DynamicSourceFacts, DynamicSourceHeads, DynamicSourceImage, DynamicSourceRequest,
    PendingSourceToken,
};

#[cfg(test)]
mod tests;

/// Chosen only after the native transaction validates its exact operation.
/// RetainedOnly cannot request/capture a new executable source; MayAcquireRx
/// reserves the dense source even if the subsequent kernel operation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum MappingSourceShape {
    RetainedOnly,
    MayAcquireRx { range_bytes: usize },
}

/// Source storage is an upper reservation only, never an actual-retained debit.
/// Actual shapes use the separate accounting helpers below. Publication remains
/// available for the ordinary full actual-plan charge; no extra native wait,
/// mapping capture, kernel journal or private-runner charge is hidden here.
pub(in super::super) struct MappingSourceBudget {
    pub(in super::super) storage_bytes: usize,
    pub(in super::super) publication: BudgetCharge,
}
impl MappingSourceBudget {
    pub(in super::super) fn charge(&self) -> Result<BudgetCharge, GateError> {
        combine(
            self.publication,
            BudgetCharge {
                source_fact_bytes: self.storage_bytes,
                ..BudgetCharge::default()
            },
        )
    }
}

impl AdmissionOwner {
    /// Call before the original mapping syscall, after the same whole-mm and
    /// census authentication as reserve_transition_with_charge. Only validated
    /// ProtectRX may choose MayAcquireRx; every byte remains a possible head.
    pub(in super::super) fn mapping_source_budget(
        &self,
        shape: MappingSourceShape,
    ) -> Result<MappingSourceBudget, GateError> {
        source_budget(&self.domain, self.census.active().count(), shape)
    }
}

fn checked_range_pages(range_bytes: usize) -> Result<usize, GateError> {
    if range_bytes == 0 || range_bytes > 64 * 1024 || range_bytes % PAGE as usize != 0 {
        return Err(GateError::Refused(
            "mapping source budget requires one complete bounded VMA",
        ));
    }
    Ok(range_bytes / PAGE as usize)
}

fn prospective_plan(
    domain: &Domain,
    active_origins: usize,
    range_bytes: usize,
) -> Result<BudgetCharge, GateError> {
    let pages = checked_range_pages(range_bytes)?;
    let (old_bytes, old_heads, resumes) = image_facts_bound(domain, active_origins, 0)?;
    let bytes = add(old_bytes, range_bytes)?;
    let heads = add(old_heads, range_bytes)?;
    let source_candidates = add(domain.source_candidate_bound()?, range_bytes)?;
    let reports = add(domain.pages.len(), pages)?;
    let budget = match domain.backend {
        DynamicAdmissionBackend::StrictTrap => TrapCoverageBudget::default(),
        DynamicAdmissionBackend::CoverageTrap(budget) => budget,
    };
    // Exactly the existing PlanShape formula, evaluated on an enlarged source
    // geometry. Full report multiplicity and 15-byte guard/decode payloads stay.
    let guards = add(source_candidates, heads)?.min(budget.max_guards);
    let decoded = add(heads, guards)?;
    let candidates = mul(reports, source_candidates)?;
    let obligations = add(candidates, mul(reports, total([heads, resumes, 6])?)?)?;
    let resume_requirements = mul(resumes, add(reports, 1)?)?;
    let calls = add(domain.returns.obligations().count(), mul(2, heads)?)?;
    PlanShape {
        facts: facts_bytes(bytes, heads, resumes)?,
        reports,
        report_facts: mul(reports, facts_bytes(bytes, heads, resumes)?)?,
        candidates,
        obligations,
        resolutions: obligations,
        resolution_guards: mul(obligations, INSTRUCTION_BYTES)?,
        pages: reports,
        dependencies: add(reports, decoded)?,
        guards,
        installed_guards: domain.guards.len(),
        decoded,
        resumes: resume_requirements,
        resume_kinds: mul(resume_requirements, 4)?,
        calls,
        callers: reports,
        source_records: reports,
        source_bytes: mul(reports, bytes)?,
        source_heads: mul(reports, heads)?,
        source_resumes: mul(reports, resumes)?,
        routes: add(active_origins, calls)?,
    }
    .charge()
}

fn source_budget(
    domain: &Domain,
    active_origins: usize,
    shape: MappingSourceShape,
) -> Result<MappingSourceBudget, GateError> {
    let (new_images, range_bytes, pages, additional_source, publication) = match shape {
        MappingSourceShape::RetainedOnly => (0, 0, 0, None, BudgetCharge::default()),
        MappingSourceShape::MayAcquireRx { range_bytes } => (
            1,
            range_bytes,
            checked_range_pages(range_bytes)?,
            Some((range_bytes, range_bytes)),
            prospective_plan(domain, active_origins, range_bytes)?,
        ),
    };
    // Authenticate the current leaf before sizing an additional immutable set.
    domain.source_candidate_bound()?;
    let (old_bytes, old_heads, resumes) = image_facts_bound(domain, active_origins, 0)?;
    let images = add(domain.images.len(), new_images)?;
    let bytes = add(old_bytes, range_bytes)?;
    let heads = add(old_heads, range_bytes)?;
    let strings = domain
        .images
        .iter()
        .try_fold(mul(new_images, 4)?, |sum, image| {
            add(
                sum,
                add(
                    image.mapping.permissions.len(),
                    image.mapping.pathname.as_ref().map_or(0, String::len),
                )?,
            )
        })?;
    // RetainedOnly keeps a complete current-set copy bound even when a source
    // will be removed. It cannot add bytes/heads/pages or a resolver request.
    // MayAcquireRx retains the full v2 dense new-source and reply envelope.
    let live_images = total([
        bytes,
        mul(images, size_of::<Image>())?,
        strings,
        mul(add(heads, resumes)?, ENTRY_FACT_BYTES)?,
    ])?;
    let logical_maps = domain.original_executables.iter().try_fold(
        mul(new_images, size_of::<MemoryMapping>() + 4)?,
        |sum, mapping| {
            total([
                sum,
                size_of::<MemoryMapping>(),
                mapping.permissions.len(),
                mapping.pathname.as_ref().map_or(0, String::len),
            ])
        },
    )?;
    let catalog = domain.replacement_catalog_bytes_bound(additional_source, resumes)?;
    let request_reply = match shape {
        MappingSourceShape::RetainedOnly => 0,
        MappingSourceShape::MayAcquireRx { range_bytes } => total([
            mul(2, size_of::<DynamicSourceRequest>())?,
            size_of::<DynamicSourceImage>(),
            size_of::<DynamicSourceFacts>(),
            size_of::<DynamicSourceHeads>(),
            size_of::<PendingSourceToken>(),
            mul(4, size_of::<usize>())?,
            8,
            range_bytes,
            mul(range_bytes, ENTRY_FACT_BYTES)?,
        ])?,
    };
    // Source staging and the final exact census validation each make complete
    // entry/projection records; their payloads must not become uncharged copies.
    let projection = total([
        mul(
            images,
            size_of::<census::Projection>() + size_of::<census::ImageScope>(),
        )?,
        mul(active_origins, size_of::<OriginId>() + ENTRY_FACT_BYTES)?,
        mul(images, size_of::<LegalEntrySet>())?,
        mul(add(heads, resumes)?, ENTRY_FACT_BYTES)?,
    ])?;
    let storage_bytes = total([
        live_images,
        logical_maps,
        catalog,
        request_reply,
        projection,
        size_of::<super::super::domain::StagedReplacement>(),
        mul(add(domain.pages.len(), pages)?, ENTRY_FACT_BYTES)?,
    ])?;
    // The original transition already reserves its complete old-domain plan.
    // An unchanged/subset source set with the same active-origin count cannot
    // exceed that geometry. Only MayAcquireRx adds a full prospective plan.
    Ok(MappingSourceBudget {
        storage_bytes,
        publication,
    })
}

// These account the actual retained shapes with the same fixed logical-entry
// metadata convention as the existing census. They do not report allocator
// capacity/RSS and do not turn the pre-effect maximum into observed evidence.
fn descriptor_bytes(mapping: &MemoryMapping) -> Result<usize, GateError> {
    total([
        size_of::<MemoryMapping>(),
        mapping.permissions.len(),
        mapping.pathname.as_ref().map_or(0, String::len),
    ])
}

/// Charge one retained request header. Excluding source payload is valid only
/// when the native owner has already charged the exact same retained Arc in its
/// exit witness; sharing must be actual allocation identity, not equal bytes.
pub(in super::super) fn mapping_request_storage_bytes(
    request: &DynamicSourceRequest,
    include_source_payload: bool,
) -> Result<usize, GateError> {
    let mut bytes = add(size_of::<DynamicSourceRequest>(), 2 * size_of::<usize>())?;
    for image in request.images() {
        bytes = total([
            bytes,
            size_of::<DynamicSourceImage>(),
            2 * size_of::<usize>(),
            if include_source_payload {
                image.bytes().len()
            } else {
                0
            },
            image.original_mapping().permissions.len(),
            image
                .original_mapping()
                .pathname
                .as_ref()
                .map_or(0, String::len),
            image.quarantined_mapping().permissions.len(),
            image
                .quarantined_mapping()
                .pathname
                .as_ref()
                .map_or(0, String::len),
        ])?;
        for neighbor in [image.lower_neighbor(), image.upper_neighbor()]
            .into_iter()
            .flatten()
        {
            // The optional descriptor header is already inside SourceImage.
            bytes = total([
                bytes,
                neighbor.permissions.len(),
                neighbor.pathname.as_ref().map_or(0, String::len),
            ])?;
        }
    }
    Ok(bytes)
}

pub(in super::super) fn mapping_reply_storage_bytes(
    facts: &DynamicSourceFacts,
) -> Result<usize, GateError> {
    facts
        .images
        .iter()
        .try_fold(size_of::<DynamicSourceFacts>(), |sum, image| {
            total([
                sum,
                size_of::<DynamicSourceHeads>(),
                mul(image.heads.len(), ENTRY_FACT_BYTES)?,
            ])
        })
}

/// Actual full staged live-set and independent catalog leaf. Request/reply and
/// native witness storage are charged separately at their retention boundaries.
pub(in super::super) fn mapping_staged_storage_bytes(
    staged: &super::super::domain::StagedReplacement,
) -> Result<usize, GateError> {
    let mut bytes = total([
        size_of::<super::super::domain::StagedReplacement>(),
        staged.catalog_bytes(),
        mul(staged.pages().len(), ENTRY_FACT_BYTES)?,
    ])?;
    for image in staged.images() {
        let (heads, resumes) = entry_facts(&image.entries)?;
        bytes = total([
            bytes,
            size_of::<Image>(),
            image.snapshot.bytes().len(),
            mul(add(heads, resumes)?, ENTRY_FACT_BYTES)?,
            image.mapping.permissions.len(),
            image.mapping.pathname.as_ref().map_or(0, String::len),
        ])?;
    }
    for mapping in staged.mappings() {
        bytes = add(bytes, descriptor_bytes(mapping)?)?;
    }
    Ok(bytes)
}
