//! Immutable source geometry used only for a conservative retention bound.
//! This RuntimeScan is not a page-admission report or a cache hit. Demand scans,
//! original refusals, route proofs and actual payload accounting remain intact.
use super::*;
use liteinst_admission::scan::{AdmissionOracle, RuntimeScan};
use std::mem::size_of;

struct BasisImage {
    snapshot: Snapshot,
    entries: LegalEntrySet,
}

pub(super) struct ResourceBasis {
    policy: Policy,
    images: Vec<BasisImage>,
    candidates: usize,
    pub(super) decoded_starts: usize,
    pub(super) retained_bytes: usize,
}

fn add(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_add(b)
        .ok_or(GateError::Refused("dynamic resource basis size overflows"))
}

impl ResourceBasis {
    pub(super) fn new(
        images: &[Image],
        policy: &Policy,
        until: Instant,
    ) -> Result<Self, GateError> {
        let mut basis = Self {
            policy: policy.clone(),
            images: Vec::new(),
            candidates: 0,
            decoded_starts: 0,
            retained_bytes: add(
                size_of::<Self>(),
                policy
                    .selected
                    .len()
                    .checked_mul(64)
                    .ok_or(GateError::Refused("dynamic resource basis size overflows"))?,
            )?,
        };
        basis
            .images
            .try_reserve(images.len())
            .map_err(|_| GateError::Refused("dynamic resource basis allocation failed"))?;
        for image in images {
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
                snapshot: image.snapshot.clone(),
                entries: image.entries.clone(),
            });
        }
        planning::remaining(until)?;
        Ok(basis)
    }

    pub(super) fn candidates(&self, images: &[Image], policy: &Policy) -> Result<usize, GateError> {
        if policy != &self.policy || images.len() != self.images.len() {
            return Err(GateError::Refused(
                "dynamic resource basis identity differs",
            ));
        }
        for (image, basis) in images.iter().zip(&self.images) {
            // Only generations, entry versions and the separately bounded
            // resume census may change. No digest or count equality stands in
            // for the original bytes, boundaries or complete head facts.
            if image.snapshot.mapping != basis.snapshot.mapping
                || image.snapshot.range() != basis.snapshot.range()
                || image.snapshot.before != basis.snapshot.before
                || image.snapshot.after != basis.snapshot.after
                || image.snapshot.writes != basis.snapshot.writes
                || image.snapshot.bytes() != basis.snapshot.bytes()
                || image.entries.mapping() != basis.entries.mapping()
                || image.entries.scope() != basis.entries.scope()
                || image.entries.completeness() != basis.entries.completeness()
                || image.entries.heads() != basis.entries.heads()
            {
                return Err(GateError::Refused(
                    "dynamic resource basis original source differs",
                ));
            }
        }
        Ok(self.candidates)
    }
}
