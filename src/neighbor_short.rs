//! Opt-in same-function T3 with a fixed-suffix relay in a 6..=9 byte victim.
use super::*;

/// Forces short-victim T3; never falls back to the long-victim planner.
///
/// The selected original instruction is 2..=4 bytes; the disjoint original
/// victim is 6..=9 bytes. In addition to the unchanged original-instruction,
/// entry and image qualifications, the complete ten-byte fetch at the victim
/// must lie in the owned source, function and exhaustive entry scope. The
/// successor bytes after the victim constrain the selected image's rel32
/// target. They are preserved exactly, including any preceding selected EB
/// in the bundle's descending source overlay, and persistently locked.
///
/// This larger fetch/write/lease contract is explicitly opt-in. Publication
/// uses the existing quiescent bundle transaction, not a hardware-atomic
/// ten-byte store. Existing asynchronous signal/unwind restrictions remain.
/// Full mapping limits and NeighborSearch bounds are unchanged; unavailable
/// windows refuse without padding, extra permits or a different victim mode.
pub fn plan_neighbor_short(
    request: &InstallRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, Refusal> {
    plan_neighbor_short_detailed(request, victim_allocation, search, budget)
        .map_err(|failure| failure.reason)
}

/// Short-only live planner retaining all bounded candidate/refusal evidence.
pub fn plan_neighbor_short_detailed(
    request: &InstallRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<PlannedNeighbor, NeighborFailure> {
    plan_neighbor_mode(
        &PlanningRequest::live(request),
        victim_allocation,
        search,
        budget,
        true,
    )
}

/// Short-only artifact planner with the same full-fetch ownership contract.
/// Symbolic images remain unqualified for runtime publication or execution.
pub fn plan_neighbor_short_with_emission(
    request: &ArtifactRequest<'_>,
    victim_allocation: &AllocationPolicy,
    search: NeighborSearch,
    budget: BundleBudget,
) -> Result<ArtifactPlan, NeighborFailure> {
    plan_neighbor_mode(
        &PlanningRequest::artifact(request),
        victim_allocation,
        search,
        budget,
        true,
    )
    .map(|plan| {
        ArtifactPlan::bundle(
            plan.bundle(),
            ArtifactMetrics::Neighbor(*plan.geometry(), plan.metrics().clone()),
        )
    })
}

/// Private byte proof for a generated relay, never an original instruction head.
pub(super) struct Relay {
    fetch: AddressRange,
    len: usize,
    fixed: [u8; 4],
    window: AddressRange,
}

impl Relay {
    pub(super) fn new(
        request: &PlanningRequest<'_>,
        source: AddressRange,
        victim: AddressRange,
        selected_patch: [u8; 2],
    ) -> Result<Self, Refusal> {
        let len = usize::try_from(victim.len()).map_err(|_| Refusal::InvalidRange)?;
        if !(6..=9).contains(&len) {
            return Err(Refusal::NoPatchWindow);
        }
        let fetch = AddressRange::new(victim.start(), 10)?;
        if !source.covers(fetch) || !request.function.covers(fetch) {
            return Err(Refusal::NoPatchWindow);
        }
        if !request.entries.scope.covers(fetch) {
            return Err(Refusal::UnresolvedEntry);
        }
        let (_, _, expected_patch) = short_redirect(request.logical_pc, victim.start())?;
        if selected_patch != expected_patch {
            return Err(Refusal::InvalidPlan);
        }
        let offset =
            usize::try_from(fetch.start() - source.start()).map_err(|_| Refusal::InvalidRange)?;
        let end = offset.checked_add(10).ok_or(Refusal::InvalidRange)?;
        let bytes = request.code.get(offset..end).ok_or(Refusal::InvalidRange)?;
        let mut current = [0_u8; 10];
        current.copy_from_slice(bytes);
        // A selected member inside the suffix is higher than the victim and
        // composes first. Authenticate its exact EB before deriving the window.
        for (i, byte) in selected_patch.into_iter().enumerate() {
            let address = request
                .logical_pc
                .checked_add(i as u64)
                .ok_or(Refusal::InvalidRange)?;
            if fetch.contains(address) {
                current[(address - fetch.start()) as usize] = byte;
            }
        }
        let free = len - 6;
        let mut fixed = [0_u8; 4];
        fixed[free..].copy_from_slice(&current[len..]);
        let start = u64::try_from(i128::from(fetch.end()) + i128::from(i32::from_le_bytes(fixed)))
            .map_err(|_| Refusal::AllocationUnavailable)?;
        let window = AddressRange::new(start, 1_usize << (8 * free))?;
        Ok(Self {
            fetch,
            len,
            fixed,
            window,
        })
    }

    pub(super) fn victim(&self) -> u64 {
        self.fetch.start()
    }

    pub(super) fn window(&self) -> AddressRange {
        self.window
    }

    pub(super) fn check_patch(&self, patch: &[u8], target: u64) -> Result<(), Refusal> {
        if !self.window.contains(target) {
            return Err(Refusal::AllocationUnavailable);
        }
        if patch.len() != 10 || patch[0] != 0xe9 {
            return Err(Refusal::InvalidPlan);
        }
        let relay = self.victim().checked_add(5).ok_or(Refusal::InvalidRange)?;
        if patch[5..] != near_redirect(relay, target)? {
            return Err(Refusal::InvalidPlan);
        }
        if patch[self.len..] != self.fixed[self.len - 6..] {
            return Err(Refusal::ExpectedBytesChanged);
        }
        Ok(())
    }

    pub(super) fn check_current(
        &self,
        request: &PlanningRequest<'_>,
        source: AddressRange,
        patch: &[u8],
    ) -> Result<(), Refusal> {
        if !source.covers(self.fetch) || patch.len() != 10 {
            return Err(Refusal::InvalidRange);
        }
        let offset =
            usize::try_from(self.victim() - source.start()).map_err(|_| Refusal::InvalidRange)?;
        let end = offset.checked_add(10).ok_or(Refusal::InvalidRange)?;
        let current = request.code.get(offset..end).ok_or(Refusal::InvalidRange)?;
        if current[self.len..] != self.fixed[self.len - 6..]
            || patch[self.len..] != current[self.len..]
        {
            return Err(Refusal::ExpectedBytesChanged);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "neighbor_short/tests.rs"]
mod tests;
