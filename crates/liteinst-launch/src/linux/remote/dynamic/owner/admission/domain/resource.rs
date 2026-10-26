//! Immutable retained source catalog and conservative resource geometry.
//! This RuntimeScan is not a page-admission report or a cache hit. Demand scans,
//! original refusals, route proofs and actual payload accounting remain intact.
//! A catalog binding identifies recorded facts, never native mapping, writer,
//! stop, publication or release authority. The source set cannot be extended.
use super::*;
use liteinst_admission::scan::{AdmissionOracle, RuntimeScan};
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
mod tests;

static NEXT_SOURCE_BINDING: AtomicU64 = AtomicU64::new(1);

/// Opaque non-reused identity of one immutable retained source set. A copied
/// binding is only a lookup key; it cannot commit a different live mapping set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct SourceBinding(u64);

struct BasisImage {
    mapping_index: usize,
    core_identity: liteinst2::contracts::CodeIdentity,
    snapshot: Snapshot,
    entries: LegalEntrySet,
}

pub(super) struct ResourceBasis {
    binding: SourceBinding,
    policy: Policy,
    images: Vec<BasisImage>,
    // Includes uncensused original executable mappings, whose pages stay NX.
    // Keep the exact descriptors and strings, not a digest or mutable page map.
    original_executables: Vec<MemoryMapping>,
    candidates: usize,
    pub(super) decoded_starts: usize,
    pub(super) retained_bytes: usize,
}

fn add(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_add(b)
        .ok_or(GateError::Refused("dynamic resource basis size overflows"))
}

impl ResourceBasis {
    /// Additional retained descriptor payload. The caller reserves this before
    /// retaining the catalog; the result is also included in retained_bytes.
    pub(super) fn mapping_bytes(mappings: &[MemoryMapping]) -> Result<usize, GateError> {
        mappings.iter().try_fold(0_usize, |bytes, mapping| {
            add(
                bytes,
                add(
                    size_of::<MemoryMapping>(),
                    add(
                        mapping.permissions.len(),
                        mapping.pathname.as_ref().map_or(0, String::len),
                    )?,
                )?,
            )
        })
    }

    pub(super) fn new(
        images: &[Image],
        original_executables: &[MemoryMapping],
        policy: &Policy,
        until: Instant,
    ) -> Result<(Self, SourceBinding), GateError> {
        for (index, mapping) in original_executables.iter().enumerate() {
            if mapping.end <= mapping.start
                || mapping.start % PAGE != 0
                || mapping.end % PAGE != 0
                || mapping.permissions.as_bytes().get(1) == Some(&b'w')
                || mapping.permissions.as_bytes().get(2) != Some(&b'x')
                || mapping.permissions.as_bytes().get(3) != Some(&b'p')
                || original_executables[..index]
                    .iter()
                    .any(|old| old.start < mapping.end && mapping.start < old.end)
            {
                return Err(GateError::Refused(
                    "dynamic resource basis mapping inventory differs",
                ));
            }
        }
        let binding = SourceBinding(
            NEXT_SOURCE_BINDING
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| GateError::Refused("dynamic source binding space exhausted"))?,
        );
        let mut basis = Self {
            binding,
            policy: policy.clone(),
            images: Vec::new(),
            original_executables: Vec::new(),
            candidates: 0,
            decoded_starts: 0,
            // Also charge the opaque binding returned to and retained by
            // Domain, separately from this object's own binding field.
            retained_bytes: add(
                add(
                    add(size_of::<Self>(), size_of::<SourceBinding>())?,
                    policy
                        .selected
                        .len()
                        .checked_mul(64)
                        .ok_or(GateError::Refused("dynamic resource basis size overflows"))?,
                )?,
                Self::mapping_bytes(original_executables)?,
            )?,
        };
        basis
            .original_executables
            .try_reserve(original_executables.len())
            .map_err(|_| GateError::Refused("dynamic resource basis allocation failed"))?;
        basis
            .original_executables
            .extend_from_slice(original_executables);
        basis
            .images
            .try_reserve(images.len())
            .map_err(|_| GateError::Refused("dynamic resource basis allocation failed"))?;
        for (index, image) in images.iter().enumerate() {
            let mapping_index = original_executables
                .iter()
                .position(|mapping| mapping == &image.mapping)
                .filter(|_| {
                    image.snapshot.range().start() == image.mapping.start
                        && image.snapshot.range().end() == image.mapping.end
                        && image.entries.mapping() == image.snapshot.mapping
                        && image.entries.generation() == image.snapshot.generation
                        && image.entries.scope() == image.snapshot.range()
                        && image.core_identity.mapping == image.snapshot.mapping.0
                        && image.core_identity.generation == image.snapshot.generation.0
                        && !images[..index].iter().any(|old| {
                            old.snapshot.mapping == image.snapshot.mapping
                                || (old.mapping.start < image.mapping.end
                                    && image.mapping.start < old.mapping.end)
                        })
                })
                .ok_or(GateError::Refused(
                    "dynamic resource basis original source differs",
                ))?;
            planning::remaining(until)?;
            let report = RuntimeScan.inspect(
                &image.snapshot,
                image.snapshot.range(),
                &image.entries,
                policy,
            );
            planning::remaining(until)?;
            // Every future page candidate has the same original decoder input
            // at an address in this full range. Its Known/Embedded/Unresolved
            // classification may differ with halo visibility. Refused reports
            // still contain candidates and must not suppress this inventory.
            basis.candidates = add(basis.candidates, report.candidates().len())?;
            basis.decoded_starts = add(basis.decoded_starts, report.metrics().decoded_starts)?;
            let facts = image
                .entries
                .heads()
                .values()
                .map(|kinds| kinds.len())
                .chain(image.entries.resumes().values().map(|kinds| kinds.len()))
                .try_fold(0usize, add)?;
            let fact_bytes = facts
                .checked_mul(64)
                .ok_or(GateError::Refused("dynamic resource basis size overflows"))?;
            basis.retained_bytes = add(
                basis.retained_bytes,
                add(
                    size_of::<BasisImage>(),
                    add(image.snapshot.bytes().len(), fact_bytes)?,
                )?,
            )?;
            basis.images.push(BasisImage {
                mapping_index,
                core_identity: image.core_identity,
                snapshot: image.snapshot.clone(),
                entries: image.entries.clone(),
            });
        }
        planning::remaining(until)?;
        Ok((basis, binding))
    }

    pub(super) fn validate_binding(&self, binding: SourceBinding) -> Result<(), GateError> {
        if binding != self.binding {
            return Err(GateError::Refused(
                "dynamic retained source binding differs",
            ));
        }
        Ok(())
    }

    /// Current-source equality remains independent of history lookup. Epoch,
    /// entry-version and resume projection equality is checked by Domain and
    /// the real held-mm/census transaction, not by this immutable-source key.
    pub(super) fn validate_live(
        &self,
        binding: SourceBinding,
        images: &[Image],
        original_executables: &[MemoryMapping],
        policy: &Policy,
    ) -> Result<(), GateError> {
        self.validate_binding(binding)?;
        if policy != &self.policy || images.len() != self.images.len() {
            return Err(GateError::Refused(
                "dynamic resource basis identity differs",
            ));
        }
        if original_executables != self.original_executables.as_slice() {
            return Err(GateError::Refused(
                "dynamic resource basis mapping inventory differs",
            ));
        }
        for (image, basis) in images.iter().zip(&self.images) {
            let mut expected_identity = basis.core_identity;
            expected_identity.generation = image.snapshot.generation.0;
            if image.mapping != self.original_executables[basis.mapping_index]
                || image.core_identity != expected_identity
                || !same_source(&image.snapshot, &image.entries, basis)
            {
                return Err(GateError::Refused(
                    "dynamic resource basis original source differs",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn candidates(
        &self,
        binding: SourceBinding,
        images: &[Image],
        original_executables: &[MemoryMapping],
        policy: &Policy,
    ) -> Result<usize, GateError> {
        self.validate_live(binding, images, original_executables, policy)?;
        Ok(self.candidates)
    }

    /// Bind a retained plan's immutable source/head geometry to this catalog.
    /// Epoch/entry-version and retained plan/census provenance remain caller
    /// obligations. This neither discards the plan's original resume facts nor
    /// independently authenticates their completeness.
    pub(super) fn validate_retained(
        &self,
        binding: SourceBinding,
        snapshot: &Snapshot,
        entries: &LegalEntrySet,
        policy: &Policy,
    ) -> Result<(), GateError> {
        self.validate_binding(binding)?;
        if policy != &self.policy {
            return Err(GateError::Refused(
                "dynamic resource basis identity differs",
            ));
        }
        if !self
            .images
            .iter()
            .any(|basis| same_source(snapshot, entries, basis))
        {
            return Err(GateError::Refused(
                "dynamic resource basis original source differs",
            ));
        }
        Ok(())
    }

    /// Exact original page inventory; booleans are deliberately not native
    /// permission evidence. No page vector duplicates the retained ranges.
    pub(super) fn validate_pages(
        &self,
        binding: SourceBinding,
        pages: &BTreeMap<u64, bool>,
    ) -> Result<(), GateError> {
        self.validate_binding(binding)?;
        let count = self
            .original_executables
            .iter()
            .try_fold(0_usize, |sum, mapping| {
                let pages = usize::try_from((mapping.end - mapping.start) / PAGE)
                    .map_err(|_| GateError::Refused("dynamic resource basis size overflows"))?;
                add(sum, pages)
            })?;
        if pages.len() != count || pages.keys().any(|&page| !self.page_in_inventory(page)) {
            return Err(GateError::Refused(
                "dynamic retained page inventory differs",
            ));
        }
        Ok(())
    }

    pub(super) fn contains_page(
        &self,
        binding: SourceBinding,
        page: u64,
    ) -> Result<bool, GateError> {
        self.validate_binding(binding)?;
        Ok(self.page_in_inventory(page))
    }

    fn page_in_inventory(&self, page: u64) -> bool {
        page % PAGE == 0
            && page.checked_add(PAGE).is_some_and(|end| {
                self.original_executables
                    .iter()
                    .any(|mapping| mapping.start <= page && end <= mapping.end)
            })
    }

    fn image_at(&self, binding: SourceBinding, pc: u64) -> Result<&BasisImage, GateError> {
        self.validate_binding(binding)?;
        self.images
            .iter()
            .find(|image| image.snapshot.range().contains(pc))
            .ok_or(GateError::Refused(
                "dynamic continuation has no original image census",
            ))
    }

    pub(super) fn original_decode(
        &self,
        binding: SourceBinding,
        pc: u64,
    ) -> Result<Vec<u8>, GateError> {
        let image = self.image_at(binding, pc)?;
        if !image.entries.heads().contains_key(&pc) {
            return Err(GateError::Refused(
                "dynamic continuation is not a declared instruction head",
            ));
        }
        decode_candidate(image, pc)
    }

    pub(super) fn original_candidate_decode(
        &self,
        binding: SourceBinding,
        pc: u64,
    ) -> Result<Vec<u8>, GateError> {
        decode_candidate(self.image_at(binding, pc)?, pc)
    }
}

fn same_source(snapshot: &Snapshot, entries: &LegalEntrySet, basis: &BasisImage) -> bool {
    // Only generations, entry versions and the separately bounded resume census
    // may differ from the retained original. Internal snapshot/entries identity
    // must still agree; a digest/count is never a substitute for exact bytes.
    snapshot.mapping == basis.snapshot.mapping
        && snapshot.range() == basis.snapshot.range()
        && snapshot.before == basis.snapshot.before
        && snapshot.after == basis.snapshot.after
        && snapshot.writes == basis.snapshot.writes
        && snapshot.bytes() == basis.snapshot.bytes()
        && entries.mapping() == basis.entries.mapping()
        && entries.mapping() == snapshot.mapping
        && entries.generation() == snapshot.generation
        && entries.scope() == basis.entries.scope()
        && entries.scope() == snapshot.range()
        && entries.completeness() == basis.entries.completeness()
        && entries.heads() == basis.entries.heads()
}

fn decode_candidate(image: &BasisImage, pc: u64) -> Result<Vec<u8>, GateError> {
    let offset = (pc - image.snapshot.range().start()) as usize;
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
