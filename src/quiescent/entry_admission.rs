//! Certified-block planning for the separate optional-entry admission profile.

use super::*;
use crate::controls::EntryAdmissionAction;

/// Plan one certified block with optional entry and permanent RET roles.
///
/// Original decoding covers the complete 1..=256-byte function. Every displaced
/// entry/RET must have its exact typed action; all other RET blocks must be
/// planned by the caller. Requires Observe/RelocationOnly, complete entries and
/// no saved resumes. The image uses one mapping and at most 8192 page-rounded
/// bytes, with at most 256 candidates; every smaller caller cap still wins.
/// This neither selects a point-observer profile nor converts a mandatory one.
/// `request.hook` is unused. No fallback policy is attempted.
///
/// # Safety
/// All obligations of [`EntryAdmissionAction::entry`] apply. Authenticate the
/// complete scalar function/CFG, sole external entry, every permanent RET role
/// and depth-one owned caller, including bypassed physical calls. Complete
/// source/alias, stack, callback, normal-return and executable/control lifetime
/// ownership must hold continuously. The pairing runtime preserves live and
/// returned receipt owners across disable/rearm and fails closed on missing or
/// contradictory roles. Planning does not prove that runtime or publication.
pub unsafe fn plan_entry_admission_detailed(
    request: &InstallRequest<'_>,
    actions: &[EntryAdmissionAction],
) -> Result<PlannedInstall, PlanningFailure> {
    plan(request, actions, request.code)
}

/// Plan typed entry/RET roles after an authenticated original/current overlay.
///
/// The complete original function supplies decoding, while the predecessor
/// supplies current read expectations. Every displaced byte must still be
/// original. Append/exclude each member before planning the next, then validate
/// the complete bundle, full source-page snapshots and publication transaction.
///
/// # Safety
/// All requirements of [`plan_entry_admission_detailed`] apply in the exact
/// source namespace owned by the predecessor. An overlay authenticates bytes,
/// not the caller, physical-return census or retained receipt protocol.
pub unsafe fn plan_entry_admission_detailed_after(
    request: &InstallRequest<'_>,
    actions: &[EntryAdmissionAction],
    predecessor: &crate::composition::Composition,
) -> Result<PlannedInstall, PlanningFailure> {
    let current = predecessor
        .planning_overlay(request.identity, request.base_address, request.code)
        .map_err(|reason| {
            let mut search = SearchEvidence::default();
            search.qualification(SearchScope::default(), &reason);
            PlanningFailure {
                reason,
                attempts: Vec::new(),
                search,
            }
        })?;
    plan(request, actions, &current)
}

fn plan(
    input: &InstallRequest<'_>,
    actions: &[EntryAdmissionAction],
    current: &[u8],
) -> Result<PlannedInstall, PlanningFailure> {
    let mut allocation = input.allocation.clone();
    allocation.max_candidates = allocation.max_candidates.min(256);
    allocation.max_mappings = allocation.max_mappings.min(1);
    allocation.max_mapped_bytes = allocation.max_mapped_bytes.min(8192);
    let original = PlanningRequest::live(input);
    let mut request = original.with_code(current);
    request.site.allocation = &allocation;
    plan_coalesced_flavor(&request, CoalescedActions::EntryAdmission(actions), None)
}

pub(super) fn qualify(request: &PlanningRequest<'_>) -> Result<(), Refusal> {
    if request.semantics != HookSemantics::Observe
        || request.search.tactics != TacticPolicy::RelocationOnly
    {
        return Err(Refusal::UnsupportedSemantics(
            "entry admission requires Observe and RelocationOnly".into(),
        ));
    }
    let source = AddressRange::new(request.base_address, request.code.len())?;
    if request.base_address == 0
        || !(1..=256).contains(&request.code.len())
        || source != request.function
        || source != request.entries.scope
    {
        return Err(Refusal::InvalidRange);
    }
    if request.entries.completeness != EntryCompleteness::Complete
        || request.entries.resumes != ResumeObligation::NoneExist
        || request
            .entries
            .entries
            .iter()
            .any(|entry| entry.requires_endbr)
    {
        return Err(Refusal::UnresolvedEntry);
    }
    Ok(())
}
