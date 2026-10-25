//! Ordered byte composition for caller-certified patch plans.
//!
//! This module validates snapshots, source-byte dependencies and allocation
//! ownership. It neither decodes instructions nor proves that a plan preserves
//! program behavior. Publication must still validate the original snapshots,
//! hold every dependency lease, and satisfy each plan's admission contract.

use std::collections::BTreeSet;

use crate::contracts::{
    AddressRange, ByteEdit, CodeIdentity, ExpectedBytes, GeneratedCode, PatchPlan, PlanKind,
    Refusal,
};

/// A virtual source image and the persistent byte locks of accepted steps.
///
/// Steps are appended in caller order. Reads authenticate the current virtual
/// image, including earlier edits; they are never compared only against the
/// initial image. Full read snapshots remain publication dependencies but do
/// not become persistent locks merely because a planner consulted them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Composition {
    identity: CodeIdentity,
    originals: Vec<ExpectedBytes>,
    final_bytes: Vec<ExpectedBytes>,
    locks: Vec<AddressRange>,
    allocations: Vec<AddressRange>,
    physical_sites: BTreeSet<u64>,
}

impl Composition {
    /// Starts with disjoint, nonempty snapshots, sorted by source address.
    /// An empty snapshot set represents an empty image and cannot admit a step.
    pub fn new(identity: CodeIdentity, mut originals: Vec<ExpectedBytes>) -> Result<Self, Refusal> {
        originals.sort_unstable_by_key(|snapshot| snapshot.address);
        let mut previous: Option<AddressRange> = None;
        for snapshot in &originals {
            let range = byte_range(snapshot.address, &snapshot.bytes)?;
            if previous.is_some_and(|prior| prior.overlaps(range)) {
                return Err(Refusal::OwnershipConflict);
            }
            previous = Some(range);
        }
        Ok(Self {
            identity,
            final_bytes: originals.clone(),
            originals,
            locks: Vec::new(),
            allocations: Vec::new(),
            physical_sites: BTreeSet::new(),
        })
    }

    /// Adds one plan transactionally; any refusal leaves all state unchanged.
    ///
    /// Earlier locked bytes may be stored again only with identical values.
    /// A physical interception site may occur only once, even when its bytes
    /// would be unchanged. Allocations are exclusive across the whole sequence.
    pub fn append(&mut self, plan: &PatchPlan) -> Result<(), Refusal> {
        let mut next = self.clone();
        next.append_inner(plan)?;
        *self = next;
        Ok(())
    }

    /// Current virtual bytes, with the same sorted extents as the originals.
    pub fn final_bytes(&self) -> &[ExpectedBytes] {
        &self.final_bytes
    }

    /// Immutable original snapshots required by publication and retirement.
    pub fn originals(&self) -> &[ExpectedBytes] {
        &self.originals
    }

    /// Sorted, merged source intervals protected from subsequent byte changes.
    pub fn locks(&self) -> &[AddressRange] {
        &self.locks
    }

    /// Mapping incarnation and generation shared by every accepted step.
    pub const fn identity(&self) -> CodeIdentity {
        self.identity
    }

    fn append_inner(&mut self, plan: &PatchPlan) -> Result<(), Refusal> {
        let parts = plan.parts();
        if parts.identity != self.identity {
            return Err(Refusal::StaleGeneration);
        }
        plan.check_entry_obligations()?;
        if !self.physical_sites.insert(parts.physical_pc) {
            return Err(Refusal::OwnershipConflict);
        }
        for &dependency in &parts.dependencies {
            if !covered(&self.originals, dependency)? {
                return Err(Refusal::DependencyNotHeld);
            }
        }
        for read in &parts.reads {
            if !bytes_match(&self.final_bytes, read.address, &read.bytes)? {
                return Err(Refusal::ExpectedBytesChanged);
            }
        }

        let mut edits: Vec<&ByteEdit> = parts.writes.iter().collect();
        let mut new_locks = Vec::new();
        match &parts.kind {
            PlanKind::Relocation => new_locks.push(parts.displaced),
            PlanKind::GeneralizedPun(pun) => {
                new_locks.push(pun.consumed);
                edits.push(&pun.store);
            }
        }
        for (index, edit) in edits.iter().enumerate() {
            let range = byte_range(edit.address, &edit.bytes)?;
            if !covered(&self.originals, range)? {
                return Err(Refusal::DependencyNotHeld);
            }
            for &locked in &self.locks {
                if let Some(shared) = intersection(range, locked) {
                    let expected = bytes_at(edit.address, &edit.bytes, shared);
                    if !bytes_match(&self.final_bytes, shared.start(), expected)? {
                        return Err(Refusal::OwnershipConflict);
                    }
                }
            }
            for other in &edits[..index] {
                let other_range = byte_range(other.address, &other.bytes)?;
                if let Some(shared) = intersection(range, other_range) {
                    if bytes_at(edit.address, &edit.bytes, shared)
                        != bytes_at(other.address, &other.bytes, shared)
                    {
                        return Err(Refusal::OwnershipConflict);
                    }
                }
            }
            new_locks.push(range);
        }
        for &range in &new_locks {
            if !covered(&self.originals, range)? {
                return Err(Refusal::DependencyNotHeld);
            }
        }

        for allocation in &parts.allocations {
            if self
                .originals
                .iter()
                .map(|snapshot| byte_range(snapshot.address, &snapshot.bytes))
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .chain(&self.allocations)
                .any(|range| range.overlaps(allocation.range))
            {
                return Err(Refusal::OwnershipConflict);
            }
            self.allocations.push(allocation.range);
        }
        validate_generated(&parts.generated)?;

        for edit in edits {
            apply(&mut self.final_bytes, edit)?;
        }
        self.locks.extend(new_locks);
        merge_ranges(&mut self.locks)?;
        Ok(())
    }
}

fn byte_range(address: u64, bytes: &[u8]) -> Result<AddressRange, Refusal> {
    AddressRange::new(address, bytes.len())
}

/// Coverage may span adjacent snapshots, but never an unowned gap.
fn covered(snapshots: &[ExpectedBytes], wanted: AddressRange) -> Result<bool, Refusal> {
    let mut cursor = wanted.start();
    for snapshot in snapshots {
        let range = byte_range(snapshot.address, &snapshot.bytes)?;
        if range.end() <= cursor {
            continue;
        }
        if range.start() > cursor {
            return Ok(false);
        }
        cursor = range.end().min(wanted.end());
        if cursor == wanted.end() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn intersection(left: AddressRange, right: AddressRange) -> Option<AddressRange> {
    let start = left.start().max(right.start());
    let end = left.end().min(right.end());
    (start < end).then(|| {
        // The intersection cannot exceed either input, whose length originated
        // as usize in AddressRange::new; subtraction cannot wrap here.
        AddressRange::new(start, (end - start) as usize).expect("valid subrange")
    })
}

fn bytes_at(address: u64, bytes: &[u8], range: AddressRange) -> &[u8] {
    // All callers intersect with or establish coverage by this byte image.
    let offset = (range.start() - address) as usize;
    &bytes[offset..offset + range.len() as usize]
}

fn bytes_match(
    snapshots: &[ExpectedBytes],
    address: u64,
    expected: &[u8],
) -> Result<bool, Refusal> {
    let wanted = byte_range(address, expected)?;
    if !covered(snapshots, wanted)? {
        return Err(Refusal::DependencyNotHeld);
    }
    for snapshot in snapshots {
        if let Some(shared) = intersection(byte_range(snapshot.address, &snapshot.bytes)?, wanted) {
            if bytes_at(snapshot.address, &snapshot.bytes, shared)
                != bytes_at(address, expected, shared)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn apply(snapshots: &mut [ExpectedBytes], edit: &ByteEdit) -> Result<(), Refusal> {
    let wanted = byte_range(edit.address, &edit.bytes)?;
    if !covered(snapshots, wanted)? {
        return Err(Refusal::DependencyNotHeld);
    }
    for snapshot in snapshots {
        if let Some(shared) = intersection(byte_range(snapshot.address, &snapshot.bytes)?, wanted) {
            let offset = (shared.start() - snapshot.address) as usize;
            snapshot.bytes[offset..offset + shared.len() as usize].copy_from_slice(bytes_at(
                edit.address,
                &edit.bytes,
                shared,
            ));
        }
    }
    Ok(())
}

fn merge_ranges(ranges: &mut Vec<AddressRange>) -> Result<(), Refusal> {
    ranges.sort_unstable_by_key(|range| range.start());
    let mut merged: Vec<AddressRange> = Vec::with_capacity(ranges.len());
    for &range in ranges.iter() {
        if let Some(previous) = merged
            .last_mut()
            .filter(|previous| range.start() <= previous.end())
        {
            let len = usize::try_from(range.end().max(previous.end()) - previous.start())
                .map_err(|_| Refusal::InvalidRange)?;
            *previous = AddressRange::new(previous.start(), len)?;
        } else {
            merged.push(range);
        }
    }
    *ranges = merged;
    Ok(())
}

fn mapping_range(
    mapping: &crate::trampoline::ProgramCounterMapping,
) -> Result<AddressRange, Refusal> {
    let len = mapping
        .generated_end()
        .checked_sub(mapping.generated_start())
        .and_then(|len| usize::try_from(len).ok())
        .ok_or(Refusal::InvalidRange)?;
    AddressRange::new(mapping.generated_start(), len)
}

fn validate_generated(images: &[GeneratedCode]) -> Result<(), Refusal> {
    for (index, image) in images.iter().enumerate() {
        let range = byte_range(image.address, &image.bytes)?;
        for (map_index, mapping) in image.program_counters.iter().enumerate() {
            let mapped = mapping_range(mapping)?;
            if !range.covers(mapped) {
                return Err(Refusal::InvalidPlan);
            }
            for prior in &image.program_counters[..map_index] {
                if mapping_range(prior)?.overlaps(mapped)
                    && prior.logical_address() != mapping.logical_address()
                {
                    return Err(Refusal::OwnershipConflict);
                }
            }
        }
        for prior in &images[..index] {
            let Some(shared) = intersection(range, byte_range(prior.address, &prior.bytes)?) else {
                continue;
            };
            if bytes_at(image.address, &image.bytes, shared)
                != bytes_at(prior.address, &prior.bytes, shared)
            {
                return Err(Refusal::OwnershipConflict);
            }
            // Equal bytes must also agree about executable/data classification
            // and logical PC throughout their common extent. Comparing each
            // mapping boundary suffices because translations are piecewise constant.
            let mut boundaries = vec![shared.start()];
            for mapping in image.program_counters.iter().chain(&prior.program_counters) {
                for pc in [mapping.generated_start(), mapping.generated_end()] {
                    if shared.contains(pc) {
                        boundaries.push(pc);
                    }
                }
            }
            for pc in boundaries {
                let translate = |image: &GeneratedCode| {
                    image
                        .program_counters
                        .iter()
                        .find_map(|mapping| mapping.translate(pc))
                };
                if translate(image) != translate(prior) {
                    return Err(Refusal::OwnershipConflict);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        AllocationRequest, ApplicationProfile, EntryCompleteness, EntryObligation, EntryProvenance,
        GeneralizedPun, LegalEntrySet, PlanParts, PublicationRequirements, ResumeObligation,
        SourceIdentity,
    };

    const BASE: u64 = 0x1000;

    fn identity() -> CodeIdentity {
        CodeIdentity {
            source: SourceIdentity([0x34; 32]),
            mapping: 7,
            generation: 3,
        }
    }

    fn originals() -> Vec<ExpectedBytes> {
        vec![ExpectedBytes {
            address: BASE,
            bytes: vec![0x90; 128],
        }]
    }

    // These plans satisfy only the public structural contract. Their synthetic
    // encodings and generated RET images are never published or executed; they
    // do not assert instruction semantics or valid native relocation.
    fn relocation_parts(reads: &[ExpectedBytes], pc: u64, bytes: &[u8], target: u64) -> PlanParts {
        let start = reads.iter().map(|read| read.address).min().unwrap();
        let end = reads
            .iter()
            .map(|read| byte_range(read.address, &read.bytes).unwrap().end())
            .max()
            .unwrap();
        let scope = AddressRange::new(start, (end - start) as usize).unwrap();
        PlanParts {
            identity: identity(),
            profile: ApplicationProfile::InstallOnce,
            kind: PlanKind::Relocation,
            logical_pc: pc,
            physical_pc: pc,
            displaced: AddressRange::new(pc, 5).unwrap(),
            reads: reads.to_vec(),
            writes: vec![ByteEdit {
                address: pc,
                bytes: bytes.to_vec(),
            }],
            dependencies: vec![scope],
            entries: LegalEntrySet {
                identity: identity(),
                scope,
                provenance: EntryProvenance::Declared("synthetic byte-composition fixture".into()),
                completeness: EntryCompleteness::Complete,
                entries: vec![],
                resumes: ResumeObligation::NoneExist,
            },
            obligations: vec![],
            allocations: vec![AllocationRequest {
                range: AddressRange::new(target & !4095, 4096).unwrap(),
                alignment: 4096,
            }],
            generated: vec![GeneratedCode {
                address: target,
                bytes: vec![0xc3],
                program_counters: vec![],
            }],
            requirements: PublicationRequirements {
                quiescent: true,
                sync_core: true,
                sigill_router: false,
            },
        }
    }

    fn relocation(reads: &[ExpectedBytes], pc: u64, bytes: &[u8], target: u64) -> PatchPlan {
        PatchPlan::checked(relocation_parts(reads, pc, bytes, target)).unwrap()
    }

    fn pun(reads: &[ExpectedBytes], pc: u64) -> PatchPlan {
        let read = reads
            .iter()
            .find(|read| byte_range(read.address, &read.bytes).unwrap().contains(pc))
            .unwrap();
        let offset = (pc - read.address) as usize;
        let original = &read.bytes[offset..offset + 5];
        let fixed = i32::from_le_bytes([0, 0, original[3], original[4]]);
        let low = u64::try_from(i128::from(pc + 5) + i128::from(fixed)).unwrap();
        let target = low + 0x1234;
        let mut parts = relocation_parts(reads, pc, &[0xe9, 0x34, 0x12], target);
        let store_address = if pc % 64 == 61 { pc - 1 } else { pc };
        let store_offset = (store_address - read.address) as usize;
        let mut stored = read.bytes[store_offset..store_offset + 4].to_vec();
        let changed = (pc - store_address) as usize;
        stored[changed..changed + 3].copy_from_slice(&parts.writes[0].bytes);
        parts.kind = PlanKind::GeneralizedPun(GeneralizedPun {
            instruction_len: 3,
            consumed: AddressRange::new(pc, 5).unwrap(),
            target_window: AddressRange::new(low, 65536).unwrap(),
            store: ByteEdit {
                address: store_address,
                bytes: stored,
            },
        });
        parts.displaced = AddressRange::new(pc, 3).unwrap();
        parts.obligations = vec![EntryObligation::Preserved(pc)];
        PatchPlan::checked(parts).unwrap()
    }

    #[test]
    fn disjoint_steps_in_one_snapshot_require_the_current_overlay() {
        let original = originals();
        let mut composition = Composition::new(identity(), original.clone()).unwrap();
        composition
            .append(&relocation(
                &original,
                BASE + 8,
                &[0xe9, 1, 2, 3, 4],
                0x100000,
            ))
            .unwrap();
        let first = composition.clone();
        assert_eq!(
            composition.append(&relocation(
                &original,
                BASE + 24,
                &[0xe9, 5, 6, 7, 8],
                0x200000
            )),
            Err(Refusal::ExpectedBytesChanged)
        );
        assert_eq!(composition, first);
        let second = relocation(
            composition.final_bytes(),
            BASE + 24,
            &[0xe9, 5, 6, 7, 8],
            0x200000,
        );
        composition.append(&second).unwrap();
        assert_eq!(composition.originals(), original);
        assert_eq!(composition.identity(), identity());
        assert_eq!(
            composition.locks(),
            [
                AddressRange::new(BASE + 8, 5).unwrap(),
                AddressRange::new(BASE + 24, 5).unwrap()
            ]
        );
        let mut expected = original;
        expected[0].bytes[8..13].copy_from_slice(&[0xe9, 1, 2, 3, 4]);
        expected[0].bytes[24..29].copy_from_slice(&[0xe9, 5, 6, 7, 8]);
        assert_eq!(composition.final_bytes(), expected);
    }

    #[test]
    fn successor_first_write_enables_a_pun_with_an_identical_locked_pad() {
        let mut original = originals();
        original[0].bytes[..3].copy_from_slice(&[0x0f, 0x1f, 0]);
        let mut composition = Composition::new(identity(), original.clone()).unwrap();
        composition
            .append(&relocation(
                &original,
                BASE + 3,
                &[0xe9, 0x34, 0x12, 0, 0],
                0x100000,
            ))
            .unwrap();
        let successor = composition.final_bytes()[0].bytes[3..8].to_vec();
        let later = pun(composition.final_bytes(), BASE);
        let PlanKind::GeneralizedPun(shape) = &later.parts().kind else {
            unreachable!()
        };
        assert_eq!(shape.store.bytes[3], 0xe9);
        assert_eq!(shape.target_window.start(), BASE + 5 + 0x34e9_0000);
        composition.append(&later).unwrap();
        assert_eq!(
            &composition.final_bytes()[0].bytes[..3],
            &[0xe9, 0x34, 0x12]
        );
        assert_eq!(&composition.final_bytes()[0].bytes[3..8], successor);
        assert_eq!(composition.originals(), original);
        assert_eq!(composition.locks(), [AddressRange::new(BASE, 8).unwrap()]);
    }

    #[test]
    fn consumed_successors_and_left_padding_remain_locked() {
        for (pc, changed) in [(BASE, BASE + 4), (BASE + 61, BASE + 60)] {
            let mut original = originals();
            let offset = (pc - BASE) as usize;
            original[0].bytes[offset..offset + 5].copy_from_slice(&[0x0f, 0x1f, 0, 0x48, 1]);
            let mut composition = Composition::new(identity(), original).unwrap();
            composition
                .append(&pun(composition.final_bytes(), pc))
                .unwrap();
            let prior = composition.clone();
            let later = relocation(composition.final_bytes(), changed, &[0xcc], 0x100000);
            assert_eq!(composition.append(&later), Err(Refusal::OwnershipConflict));
            assert_eq!(composition, prior);
        }
    }

    #[test]
    fn relocation_locks_unchanged_displaced_bytes_and_duplicate_physical_sites() {
        let mut composition = Composition::new(identity(), originals()).unwrap();
        let first = relocation(composition.final_bytes(), BASE + 8, &[0xcc], 0x100000);
        composition.append(&first).unwrap();
        let saved = composition.clone();
        for (pc, bytes) in [(BASE + 12, &[0xcc][..]), (BASE + 8, &[0xcc][..])] {
            let later = relocation(composition.final_bytes(), pc, bytes, 0x200000);
            assert_eq!(composition.append(&later), Err(Refusal::OwnershipConflict));
            assert_eq!(composition, saved);
        }
    }

    #[test]
    fn extra_source_stores_outside_displaced_are_also_locked() {
        let mut composition = Composition::new(identity(), originals()).unwrap();
        let mut parts = relocation_parts(composition.final_bytes(), BASE, &[0xcc], 0x100000);
        parts.writes.push(ByteEdit {
            address: BASE + 32,
            bytes: vec![0xcd; 2],
        });
        composition
            .append(&PatchPlan::checked(parts).unwrap())
            .unwrap();
        assert_eq!(
            composition.locks(),
            [
                AddressRange::new(BASE, 5).unwrap(),
                AddressRange::new(BASE + 32, 2).unwrap()
            ]
        );
        let saved = composition.clone();
        let later = relocation(composition.final_bytes(), BASE + 32, &[0x90], 0x200000);
        assert_eq!(composition.append(&later), Err(Refusal::OwnershipConflict));
        assert_eq!(composition, saved);
    }

    #[test]
    fn unresolved_entry_facts_are_rejected_without_reserving_the_site() {
        let mut composition = Composition::new(identity(), originals()).unwrap();
        let valid = relocation_parts(composition.final_bytes(), BASE, &[0xcc], 0x100000);
        let saved = composition.clone();
        for incomplete in 0..3 {
            let mut parts = valid.clone();
            match incomplete {
                0 => parts.entries.completeness = EntryCompleteness::Incomplete,
                1 => parts.entries.resumes = ResumeObligation::Unresolved,
                2 => {
                    parts.obligations.push(EntryObligation::Unresolved {
                        address: Some(BASE),
                        reason: "synthetic unresolved entry".into(),
                    });
                }
                _ => unreachable!(),
            }
            assert_eq!(
                composition.append(&PatchPlan::checked(parts).unwrap()),
                Err(Refusal::UnresolvedEntry)
            );
            assert_eq!(composition, saved);
        }
        composition
            .append(&PatchPlan::checked(valid).unwrap())
            .unwrap();
        assert_eq!(composition.final_bytes()[0].bytes[0], 0xcc);
    }

    #[test]
    fn adjacent_snapshots_support_multiple_reads_and_a_spanning_dependency() {
        let original = vec![
            ExpectedBytes {
                address: BASE + 8,
                bytes: vec![0x91; 8],
            },
            ExpectedBytes {
                address: BASE,
                bytes: vec![0x90; 8],
            },
        ];
        let mut composition = Composition::new(identity(), original).unwrap();
        let mut parts = relocation_parts(composition.final_bytes(), BASE + 4, &[0xcc; 2], 0x100000);
        parts.displaced = AddressRange::new(BASE + 4, 8).unwrap();
        parts.writes.push(ByteEdit {
            address: BASE + 10,
            bytes: vec![0xcd; 2],
        });
        composition
            .append(&PatchPlan::checked(parts).unwrap())
            .unwrap();
        assert_eq!(composition.originals()[0].address, BASE);
        assert_eq!(&composition.final_bytes()[0].bytes[4..6], &[0xcc; 2]);
        assert_eq!(&composition.final_bytes()[1].bytes[2..4], &[0xcd; 2]);
        assert_eq!(
            composition.locks(),
            [AddressRange::new(BASE + 4, 8).unwrap()]
        );
        let mut stale = relocation_parts(composition.final_bytes(), BASE, &[0x90], 0x200000);
        stale.reads[1].bytes[7] ^= 1;
        let saved = composition.clone();
        assert_eq!(
            composition.append(&PatchPlan::checked(stale).unwrap()),
            Err(Refusal::ExpectedBytesChanged)
        );
        assert_eq!(composition, saved);
    }

    #[test]
    fn initial_snapshot_overlap_overflow_and_dependency_gaps_are_refused() {
        assert_eq!(
            Composition::new(
                identity(),
                vec![ExpectedBytes {
                    address: u64::MAX,
                    bytes: vec![1]
                }]
            ),
            Err(Refusal::InvalidRange)
        );
        assert_eq!(
            Composition::new(
                identity(),
                vec![ExpectedBytes {
                    address: BASE,
                    bytes: vec![]
                }]
            ),
            Err(Refusal::InvalidRange)
        );
        let mut overlap = originals();
        overlap.push(ExpectedBytes {
            address: BASE + 1,
            bytes: vec![0x90],
        });
        assert_eq!(
            Composition::new(identity(), overlap),
            Err(Refusal::OwnershipConflict)
        );
        let original = vec![
            ExpectedBytes {
                address: BASE,
                bytes: vec![0x90; 8],
            },
            ExpectedBytes {
                address: BASE + 16,
                bytes: vec![0x90; 8],
            },
        ];
        let mut composition = Composition::new(identity(), original).unwrap();
        let later = relocation(composition.final_bytes(), BASE, &[0xcc], 0x100000);
        let saved = composition.clone();
        assert_eq!(composition.append(&later), Err(Refusal::DependencyNotHeld));
        assert_eq!(composition, saved);
    }

    #[test]
    fn generation_and_mapping_conflicts_leave_the_composition_unchanged() {
        let mut composition = Composition::new(identity(), originals()).unwrap();
        composition
            .append(&relocation(
                composition.final_bytes(),
                BASE,
                &[0xcc],
                0x100000,
            ))
            .unwrap();
        let saved = composition.clone();
        let mut stale = relocation_parts(composition.final_bytes(), BASE + 16, &[0xcd], 0x200000);
        stale.identity.generation += 1;
        stale.entries.identity = stale.identity;
        assert_eq!(
            composition.append(&PatchPlan::checked(stale).unwrap()),
            Err(Refusal::StaleGeneration)
        );
        assert_eq!(composition, saved);
        for target in [BASE, 0x100000] {
            let later = relocation(composition.final_bytes(), BASE + 16, &[0xcd], target);
            assert_eq!(composition.append(&later), Err(Refusal::OwnershipConflict));
            assert_eq!(composition, saved);
        }
        let mut within_step =
            relocation_parts(composition.final_bytes(), BASE + 16, &[0xcd], 0x200000);
        within_step.allocations.push(within_step.allocations[0]);
        assert_eq!(
            composition.append(&PatchPlan::checked(within_step).unwrap()),
            Err(Refusal::OwnershipConflict)
        );
        assert_eq!(composition, saved);
    }

    #[test]
    fn conflicting_generated_images_refuse_transactionally_and_allow_corrected_retry() {
        let mut composition = Composition::new(identity(), originals()).unwrap();
        let mut parts = relocation_parts(composition.final_bytes(), BASE, &[0xcc], 0x100000);
        parts.generated[0].bytes = vec![0xc3, 0x90];
        parts.generated.push(GeneratedCode {
            address: 0x100001,
            bytes: vec![0xcc],
            program_counters: vec![],
        });
        let saved = composition.clone();
        assert_eq!(
            composition.append(&PatchPlan::checked(parts.clone()).unwrap()),
            Err(Refusal::OwnershipConflict)
        );
        assert_eq!(composition, saved);
        parts.generated[1].bytes[0] = 0x90;
        composition
            .append(&PatchPlan::checked(parts).unwrap())
            .unwrap();
        assert_eq!(composition.final_bytes()[0].bytes[0], 0xcc);
    }
}
