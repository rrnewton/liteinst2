//! Pure source-set staging from an owner-retained NX capture and heads-only
//! reply. Neither these facts nor the new binding commit a native replacement.
use super::super::census::{ImageScope, Projection};
use super::super::domain::StagedReplacement;
use super::*;
use liteinst_admission::Generation;
use liteinst_admission::entries::LegalEntrySet;

#[cfg(test)]
mod tests;

impl AdmissionOwner {
    /// The caller has already consumed the original syscall, closed its native
    /// window and refreshed the current old-generation census. It separately
    /// checks the request against its original pending invocation, reads every
    /// affected/unaffected native descriptor and byte, and seals the eventual
    /// ReplacementCommit. This helper never substitutes its saved capture for
    /// that final native readback or advances a native/model epoch itself.
    pub(in super::super) fn stage_mapping_sources(
        &self,
        range: &Range<u64>,
        captures: Option<(&DynamicSourceRequest, &DynamicSourceFacts)>,
        logical_executables: Vec<MemoryMapping>,
        until: Instant,
    ) -> Result<StagedReplacement, GateError> {
        stage_sources(
            &self.domain,
            &self.census,
            range,
            captures,
            logical_executables,
            until,
        )
    }
}

fn stage_sources(
    domain: &Domain,
    census: &ResumeCensus,
    range: &Range<u64>,
    captures: Option<(&DynamicSourceRequest, &DynamicSourceFacts)>,
    logical_executables: Vec<MemoryMapping>,
    until: Instant,
) -> Result<StagedReplacement, GateError> {
    planning::remaining(until)?;
    if range.start == 0
        || range.start >= range.end
        || range.start % PAGE != 0
        || range.end % PAGE != 0
        || range.end - range.start > 64 * 1024
        || domain.generation != census.generation()
        || domain.images.iter().any(|image| {
            image.snapshot.generation != Generation(domain.generation)
                || image.entries.generation() != image.snapshot.generation
                || image.entries.version() != domain.entry_version
                || image.core_identity.generation != domain.generation
        })
    {
        return Err(refused("mapping source staging range or epoch differs"));
    }
    // Retained original equality remains an independent check even if native
    // revocation has already removed the affected VMA from the actual mm.
    domain.source_candidate_bound()?;
    validate_inventory(domain, range, captures.is_some(), &logical_executables)?;
    let next = domain
        .generation
        .checked_add(1)
        .ok_or_else(|| refused("dynamic source generation exhausted"))?;
    let version = domain
        .entry_version
        .checked_add(1)
        .ok_or_else(|| refused("dynamic entry version exhausted"))?;

    let mut images = Vec::new();
    images
        .try_reserve(
            domain
                .images
                .len()
                .checked_add(usize::from(captures.is_some()))
                .ok_or_else(|| refused("mapping source image count overflows"))?,
        )
        .map_err(|_| refused("mapping source staging allocation failed"))?;
    for image in &domain.images {
        let affected = overlaps(&(image.mapping.start..image.mapping.end), range);
        if affected && (captures.is_some() || !logical_executables.contains(&image.mapping)) {
            continue;
        }
        // Complete unchanged bytes/heads and source identity survive. Only
        // their next epoch and full dynamic resume projection change below.
        images.push(Image {
            mapping: image.mapping.clone(),
            snapshot: image.snapshot.clone(),
            entries: image.entries.clone(),
            core_identity: image.core_identity,
        });
    }

    if let Some((request, facts)) = captures {
        request.check_facts(facts)?;
        if request.images().len() != 1
            || request.previous_epoch() != domain.generation
            || request.candidate_epoch() != next
            || request.expires_at() != until
            || request.id().serial() == 0
            || request.task().generation != domain.generation
            || !census.active_registers().any(|origin| {
                origin.current.task == request.task()
                    && origin.current.token == request.token.capture_stop
                    && origin.current.token.session == request.id().session()
            })
        {
            return Err(refused(
                "mapping source capture differs from current census",
            ));
        }
        let capture = &request.images()[0];
        let original = capture.original_mapping();
        let quarantined = capture.quarantined_mapping();
        if capture.id()
            != (DynamicSourceCaptureId {
                request: request.id(),
                index: 0,
            })
            || capture.mapping_incarnation() == 0
            || capture.range() != *range
            || capture.bytes().len() as u64 != range.end - range.start
            || original.permissions != "r-xp"
            || original.file_offset != 0
            || original.pathname.is_some()
            || !logical_executables.contains(original)
            || quarantined.start != original.start
            || quarantined.end != original.end
            || quarantined.permissions != "r--p"
            || quarantined.file_offset != 0
            || quarantined.pathname.is_some()
            || capture.lower_neighbor().is_some()
            || capture.upper_neighbor().is_some()
        {
            return Err(refused(
                "mapping source capture is not an isolated complete NX image",
            ));
        }
        let reply = &facts.images[0]; // exact one-to-one reply checked above
        let fresh = planning::prepare_images(
            vec![ImageFacts {
                start: original.start,
                bytes: capture.bytes().to_vec(),
                heads: reply.heads.clone(),
            }],
            &logical_executables,
            |start, len| {
                if start != range.start || len != capture.bytes().len() {
                    return Err(invalid("mapping source read leaves retained capture"));
                }
                // This is comparison with the owner-retained complete capture,
                // not a new ptrace read or authority to trust a resolver's bytes.
                Ok(capture.bytes().to_vec())
            },
        )?;
        images.extend(fresh);
    }
    if images.len() > 64 {
        return Err(refused("too many image censuses"));
    }
    let scopes = images
        .iter()
        .map(|image| ImageScope {
            mapping: image.snapshot.mapping,
            range: image.snapshot.range(),
        })
        .collect::<Vec<_>>();
    // The complete projection rejects removal of ANY still-active origin. No
    // target, frame, parent-return or current-PC record is pruned to make a fit.
    let projections = census.project(&scopes).map_err(census_error)?;
    project_images(&mut images, &projections, domain.generation, next, version)?;
    planning::remaining(until)?;
    domain.stage_replacement(images, logical_executables, until)
}

fn validate_inventory(
    domain: &Domain,
    range: &Range<u64>,
    captured: bool,
    maps: &[MemoryMapping],
) -> Result<(), GateError> {
    for old in &domain.original_executables {
        let affected = overlaps(&(old.start..old.end), range);
        if (affected && (old.start != range.start || old.end != range.end))
            || (!affected && maps.iter().filter(|new| *new == old).count() != 1)
        {
            return Err(refused(
                "mapping source replacement changes an unaffected descriptor",
            ));
        }
    }
    for (index, mapping) in maps.iter().enumerate() {
        let affected = overlaps(&(mapping.start..mapping.end), range);
        if mapping.start >= mapping.end
            || mapping.start % PAGE != 0
            || mapping.end % PAGE != 0
            || maps[..index]
                .iter()
                .any(|old| overlaps(&(old.start..old.end), &(mapping.start..mapping.end)))
            || (affected && (mapping.start != range.start || mapping.end != range.end))
            || (!affected && !domain.original_executables.contains(mapping))
            || (!captured && affected && !domain.original_executables.contains(mapping))
            || (!affected && (mapping.end == range.start || mapping.start == range.end))
        {
            return Err(refused("mapping logical executable inventory differs"));
        }
    }
    if captured
        && maps
            .iter()
            .filter(|mapping| mapping.start == range.start && mapping.end == range.end)
            .count()
            != 1
    {
        return Err(refused(
            "mapping source capture has no original RX descriptor",
        ));
    }
    Ok(())
}

fn project_images(
    images: &mut [Image],
    projections: &[Projection],
    old: u64,
    next: u64,
    version: u64,
) -> Result<(), GateError> {
    if images.len() != projections.len() {
        return Err(refused("dynamic resume projection image count differs"));
    }
    for (image, projection) in images.iter_mut().zip(projections) {
        if projection.mapping != image.snapshot.mapping
            || projection.scope != image.snapshot.range()
            || projection.generation != Generation(old)
        {
            return Err(refused("dynamic resume projection names another image"));
        }
        image.snapshot.generation = Generation(next);
        image.core_identity.generation = next;
        image.entries = LegalEntrySet::new(
            image.snapshot.mapping,
            Generation(next),
            version,
            image.snapshot.range(),
            image.entries.completeness(),
            image
                .entries
                .heads()
                .iter()
                .flat_map(|(&pc, kinds)| kinds.iter().map(move |&kind| (pc, kind))),
            projection
                .resumes
                .iter()
                .flat_map(|(&pc, kinds)| kinds.iter().map(move |&kind| (pc, kind))),
        )
        .map_err(|_| refused("dynamic projected entry leaves original census"))?;
    }
    Ok(())
}
