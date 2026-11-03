//! One checked artifact target; descriptive arithmetic alone is not authority.
use super::*;
use crate::quiescent::feasibility::{ENTRY_BYTES, Rel32Constraints};

// Borrowed current emitter facts, never a public caller-supplied certificate.
pub(crate) struct RelocationPlacementFacts<'a> {
    pub(crate) physical: u64,
    pub(crate) mask: [bool; 4],
    pub(crate) policy: &'a AllocationPolicy,
    pub(crate) occupied: &'a [AddressRange],
    pub(crate) source: AddressRange,
    pub(crate) prepared_bound: usize,
}

// Non-Clone, private fields. Consumption rechecks the same prepared object,
// original-derived head mask, policy and occupied snapshot at the emitter.
pub(crate) struct CheckedRelocationTarget {
    physical: u64,
    next: u64,
    mask: [bool; 4],
    target: u64,
    displacement: i32,
    page: AddressRange,
    source: AddressRange,
    prepared_bound: usize,
}

pub(crate) fn entry_alphabet_fitting(
    facts: &RelocationPlacementFacts<'_>,
) -> Result<CheckedRelocationTarget, Refusal> {
    // Preserve the existing fitting refusal order, including the eager default
    // seed overflow check even when preferred_address is present.
    certificate(facts.prepared_bound)?;
    let free = free_pages(facts.policy, facts.occupied, facts.source)?;
    let next = facts.physical.checked_add(5).ok_or(Refusal::InvalidRange)?;
    next.checked_add(0x1_0000).ok_or(Refusal::InvalidRange)?;
    let target = match candidate_target(
        facts.physical,
        facts.mask,
        facts.policy.preferred_address,
        0,
    ) {
        Some(seed) if available(seed, &free) && certified(seed, facts.prepared_bound) => seed,
        _ => {
            let mut constraints = Rel32Constraints::plain(next);
            constraints.entries = facts.mask;
            let target = digits::minimum_target(constraints, &free)?;
            if !certified(target, facts.prepared_bound) {
                return Err(Refusal::AllocationUnavailable);
            }
            target
        }
    };
    let checked = CheckedRelocationTarget {
        physical: facts.physical,
        next,
        mask: facts.mask,
        target,
        displacement: i32::try_from(i128::from(target) - i128::from(next))
            .map_err(|_| Refusal::InvalidPlan)?,
        page: AddressRange::new(target & !(PAGE - 1), PAGE as usize)?,
        source: facts.source,
        prepared_bound: facts.prepared_bound,
    };
    checked.validate_geometry(facts)?;
    Ok(checked)
}

impl CheckedRelocationTarget {
    pub(crate) fn into_target(self, facts: &RelocationPlacementFacts<'_>) -> Result<u64, Refusal> {
        // No arithmetic reselection or second candidate is possible here.
        self.validate_geometry(facts)?;
        certificate(facts.prepared_bound)?;
        let free = free_pages(facts.policy, facts.occupied, facts.source)?;
        if !free.iter().any(|range| range.covers(self.page))
            || !certified(self.target, facts.prepared_bound)
        {
            return Err(Refusal::AllocationUnavailable);
        }
        Ok(self.target)
    }

    fn validate_geometry(&self, facts: &RelocationPlacementFacts<'_>) -> Result<(), Refusal> {
        let next = facts.physical.checked_add(5).ok_or(Refusal::InvalidPlan)?;
        let displacement = i32::try_from(i128::from(self.target) - i128::from(next))
            .map_err(|_| Refusal::InvalidPlan)?;
        let page = AddressRange::new(self.target & !(PAGE - 1), PAGE as usize)
            .map_err(|_| Refusal::InvalidPlan)?;
        if self.physical != facts.physical
            || self.next != next
            || self.mask != facts.mask
            || self.source != facts.source
            || self.prepared_bound != facts.prepared_bound
            || self.displacement != displacement
            || self.page != page
            || u64::try_from(i128::from(next) + i128::from(displacement)).ok() != Some(self.target)
            || displacement
                .to_le_bytes()
                .iter()
                .zip(facts.mask)
                .any(|(byte, required)| required && !ENTRY_BYTES.contains(byte))
        {
            return Err(Refusal::InvalidPlan);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
