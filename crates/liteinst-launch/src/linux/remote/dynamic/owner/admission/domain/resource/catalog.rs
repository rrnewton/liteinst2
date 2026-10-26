//! Append-only routing to independently retained immutable source-set leaves.
//! Staging, identity and lookup are model facts, never native replacement rights.
use super::super::super::mapping::ReplacementCommit;
use super::super::ReplacementIdentity;
use super::*;

pub(in super::super) struct SourceCatalog {
    owner: SourceBinding,
    leaves: Vec<ResourceBasis>,
    retained_bytes: usize,
    decoded_starts: usize,
}

/// An immutable candidate which has not become a live source set. Owning one
/// does not establish revocation, NX, a native epoch or execution permission.
pub(in super::super) struct StagedSourceSet {
    owner: SourceBinding,
    leaf: ResourceBasis,
}

impl StagedSourceSet {
    pub(in super::super) fn binding(&self) -> SourceBinding {
        self.leaf.binding
    }

    pub(in super::super) fn retained_bytes(&self) -> usize {
        self.leaf.retained_bytes
    }

    pub(in super::super) fn validate_live(
        &self,
        images: &[Image],
        maps: &[MemoryMapping],
        policy: &Policy,
    ) -> Result<(), GateError> {
        self.leaf
            .validate_live(self.binding(), images, maps, policy)
    }

    pub(in super::super) fn validate_pages(
        &self,
        pages: &BTreeMap<u64, bool>,
    ) -> Result<(), GateError> {
        self.leaf.validate_pages(self.binding(), pages)
    }
}

impl SourceCatalog {
    pub(in super::super) fn new(
        images: &[Image],
        maps: &[MemoryMapping],
        policy: &Policy,
        until: Instant,
    ) -> Result<(Self, SourceBinding), GateError> {
        let (leaf, binding) = ResourceBasis::new(images, maps, policy, until)?;
        let retained_bytes = add(size_of::<Self>(), leaf.retained_bytes)?;
        let decoded_starts = leaf.decoded_starts;
        let mut leaves = Vec::new();
        leaves
            .try_reserve(1)
            .map_err(|_| GateError::Refused("dynamic source catalog allocation failed"))?;
        leaves.push(leaf);
        Ok((
            Self {
                owner: binding,
                leaves,
                retained_bytes,
                decoded_starts,
            },
            binding,
        ))
    }

    /// Called in the transaction's pre-effect allocation phase. Capacity is
    /// not a lifetime debit; the owner must separately reserve the full payload.
    pub(in super::super) fn reserve_append(&mut self) -> Result<(), GateError> {
        self.leaves
            .try_reserve(1)
            .map_err(|_| GateError::Refused("dynamic source catalog allocation failed"))
    }

    pub(in super::super) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Full next copied leaf upper bound, in addition to all old retained
    /// leaves. Old immutable facts may be repeated; nothing is refunded. The
    /// new source may name every byte as a head, and current resume facts are
    /// separately added even when some duplicate the retained leaf projection.
    pub(in super::super) fn stage_bytes_bound(
        &self,
        binding: SourceBinding,
        additional_source: Option<(usize, usize)>,
        resume_facts: usize,
    ) -> Result<usize, GateError> {
        let resume_bytes = resume_facts
            .checked_mul(64)
            .ok_or(GateError::Refused("dynamic resource basis size overflows"))?;
        let additional = match additional_source {
            None => 0,
            Some((source_bytes, new_heads)) => {
                let head_bytes = new_heads
                    .checked_mul(64)
                    .ok_or(GateError::Refused("dynamic resource basis size overflows"))?;
                add(
                    add(size_of::<BasisImage>(), source_bytes)?,
                    add(head_bytes, add(size_of::<MemoryMapping>(), 4)?)?,
                )?
            }
        };
        add(
            add(
                self.leaf(binding)?.retained_bytes,
                size_of::<StagedSourceSet>(),
            )?,
            add(resume_bytes, additional)?,
        )
    }

    /// Work of retained leaves only. Failed/abandoned candidate work belongs to
    /// its native transaction diagnostics, not this committed-catalog counter.
    pub(in super::super) fn decoded_starts(&self) -> usize {
        self.decoded_starts
    }

    fn leaf(&self, binding: SourceBinding) -> Result<&ResourceBasis, GateError> {
        self.leaves
            .iter()
            .find(|leaf| leaf.binding == binding)
            .ok_or(GateError::Refused(
                "dynamic retained source binding differs",
            ))
    }

    pub(in super::super) fn stage(
        &self,
        images: &[Image],
        maps: &[MemoryMapping],
        policy: &Policy,
        until: Instant,
    ) -> Result<StagedSourceSet, GateError> {
        if self.leaf(self.owner)?.policy != *policy {
            return Err(GateError::Refused("dynamic replacement policy differs"));
        }
        // A known source identity may be reused only for that exact immutable
        // version. Neither equal addresses nor a new epoch permits new bytes,
        // heads, boundaries or mapping facts under an old source identity.
        for image in images {
            for leaf in &self.leaves {
                for old in &leaf.images {
                    if old.snapshot.mapping == image.snapshot.mapping
                        || old.core_identity.source == image.core_identity.source
                        || old.core_identity.mapping == image.core_identity.mapping
                    {
                        let mut identity = old.core_identity;
                        identity.generation = image.core_identity.generation;
                        if identity != image.core_identity
                            || leaf.original_executables.get(old.mapping_index)
                                != Some(&image.mapping)
                            || !same_source(&image.snapshot, &image.entries, old)
                        {
                            return Err(GateError::Refused(
                                "dynamic replacement reuses an immutable source identity",
                            ));
                        }
                    }
                }
            }
        }
        let (leaf, _) = ResourceBasis::new(images, maps, policy, until)?;
        Ok(StagedSourceSet {
            owner: self.owner,
            leaf,
        })
    }

    pub(in super::super) fn validate_candidate(
        &self,
        candidate: &StagedSourceSet,
        identity: ReplacementIdentity,
    ) -> Result<(), GateError> {
        self.validate_binding(identity.old_binding)?;
        if candidate.owner != self.owner
            || candidate.binding() != identity.new_binding
            || self
                .leaves
                .iter()
                .any(|leaf| leaf.binding == candidate.binding())
        {
            return Err(GateError::Refused(
                "dynamic replacement candidate is stale or foreign",
            ));
        }
        if self.leaves.len() == self.leaves.capacity() {
            return Err(GateError::Refused(
                "dynamic replacement catalog slot was not allocated",
            ));
        }
        add(self.retained_bytes, candidate.retained_bytes())?;
        add(self.decoded_starts, candidate.leaf.decoded_starts)?;
        Ok(())
    }

    /// The only production insertion requires the root-owned native witness.
    /// The caller has already validated its complete prospective Domain state.
    pub(in super::super) fn commit(
        &mut self,
        candidate: StagedSourceSet,
        native: &ReplacementCommit,
        identity: ReplacementIdentity,
    ) -> Result<(), GateError> {
        self.validate_candidate(&candidate, identity)?;
        native.validate_catalog_transition(identity)?;
        self.install_validated(candidate);
        Ok(())
    }

    // Called only after capacity/overflow/identity validation. No allocation or
    // fallible operation remains between insertion and the owner's field moves.
    fn install_validated(&mut self, candidate: StagedSourceSet) {
        self.retained_bytes += candidate.retained_bytes();
        self.decoded_starts += candidate.leaf.decoded_starts;
        self.leaves.push(candidate.leaf);
    }

    #[cfg(test)]
    pub(in super::super) fn commit_model(
        &mut self,
        candidate: StagedSourceSet,
        identity: ReplacementIdentity,
    ) -> Result<(), GateError> {
        self.validate_candidate(&candidate, identity)?;
        self.install_validated(candidate);
        Ok(())
    }

    pub(in super::super) fn validate_binding(
        &self,
        binding: SourceBinding,
    ) -> Result<(), GateError> {
        self.leaf(binding)?.validate_binding(binding)
    }

    pub(in super::super) fn candidates(
        &self,
        binding: SourceBinding,
        images: &[Image],
        maps: &[MemoryMapping],
        policy: &Policy,
    ) -> Result<usize, GateError> {
        self.leaf(binding)?
            .candidates(binding, images, maps, policy)
    }

    pub(in super::super) fn validate_retained(
        &self,
        binding: SourceBinding,
        snapshot: &Snapshot,
        entries: &LegalEntrySet,
        policy: &Policy,
    ) -> Result<(), GateError> {
        self.leaf(binding)?
            .validate_retained(binding, snapshot, entries, policy)
    }

    pub(in super::super) fn validate_pages(
        &self,
        binding: SourceBinding,
        pages: &BTreeMap<u64, bool>,
    ) -> Result<(), GateError> {
        self.leaf(binding)?.validate_pages(binding, pages)
    }

    pub(in super::super) fn contains_page(
        &self,
        binding: SourceBinding,
        page: u64,
    ) -> Result<bool, GateError> {
        self.leaf(binding)?.contains_page(binding, page)
    }

    pub(in super::super) fn original_decode(
        &self,
        binding: SourceBinding,
        pc: u64,
    ) -> Result<Vec<u8>, GateError> {
        self.leaf(binding)?.original_decode(binding, pc)
    }

    pub(in super::super) fn original_candidate_decode(
        &self,
        binding: SourceBinding,
        pc: u64,
    ) -> Result<Vec<u8>, GateError> {
        self.leaf(binding)?.original_candidate_decode(binding, pc)
    }
}

#[cfg(test)]
mod tests;
