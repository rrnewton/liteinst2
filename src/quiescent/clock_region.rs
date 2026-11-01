//! Separate proof for one closed region sharing two gates and one clock.

use super::*;
use crate::backedge_clock::{BackedgeClock, BackedgeClockRegion, ClockRegionGateLayout};
use crate::controls::ProbeControl;
use crate::emission::{EmissionContext, PlanningSite};
use crate::trampoline::{ObservationStackProfile, ProgramCounterMapping, TrampolineLayout};
use iced_x86::{Decoder, DecoderOptions, OpKind};
use std::collections::BTreeSet;

/// Relocate one complete owned scalar region with exactly two clocked backedges.
///
/// The region constructor binds two distinct enabled managed controls to the
/// same original bytes, generation, clock and mode. This planner revalidates
/// that binding against one complete scan and requires exact reachable leaders:
/// the sole external entry, every direct branch target and every conditional
/// fallthrough. Entries must be Complete, with no saved resumes or ENDBR needs.
///
/// The full 5..=80-byte source is displaced once. One image retains every
/// original instruction, both gates and one clock owner; this does not compose
/// two single-site plans. Allocation remains bounded by 256 candidates, one
/// mapping and 8192 bytes, and smaller caller budgets remain effective. Internal
/// source entries retain the ordinary invalid-opcode routes and router duties.
/// No predecessor overlay, publication or native execution is performed here.
///
/// # Safety
/// The caller authenticates the complete original region and its immutable
/// mapping/generation. Its only external entry is the region base: no external
/// branch, indirect call, recursive invocation, signal handler, saved context
/// or continuation may enter an interior head or generated suffix. Legal-entry
/// metadata describes internal leaders; it does not establish this exclusion.
/// No invocation may be in flight during displacement, and no foreign writer,
/// remapping, alias or loader change may invalidate the source through retirement.
/// Preserve all quiescent publication, signal, System V/no-CET and stack/state
/// contracts. Both callbacks must preserve saved state, return words and code,
/// must not unwind, and must retain their controls and clock for executable use.
///
/// Every invocation requires one exclusive lease and one call guard for the
/// entire region, acquired before its first instruction and released only after
/// execution drains. Do not reset or lease the clock separately at either gate.
/// The caller must establish finite aggregate `max_work` for all encounters and
/// taken decisions across both backedges (including untaken encounters), within
/// `backedge_clock::MAX_WORK`; structural paths to RET do not prove termination
/// or that bound. Clock storage must remain separate from source, generated code
/// and application storage, without other concurrent readers or writers.
pub unsafe fn plan_owned_clock_region_detailed(
    region: &BackedgeClockRegion,
    entries: &LegalEntrySet,
    allocation: &AllocationPolicy,
) -> Result<PlannedInstall, PlanningFailure> {
    let mut search = SearchEvidence::default();
    let mut attempts = Vec::new();
    let result = (|| {
        let first = &region.actions[0];
        // Refuse the finite profile before decoding or allocating scan storage.
        if first.base == 0 || !(5..=80).contains(&first.source.len()) {
            return Err(Refusal::NoPatchWindow);
        }
        let range = AddressRange::new(first.base, first.source.len())?;
        let scan = InstructionScanner::default()
            .scan(&first.source, first.base)
            .map_err(|error| Refusal::Backend(error.to_string()))?;
        let proof = Verified::new(region, entries, allocation, &scan)?;
        let request = PlanningRequest {
            site: PlanningSite {
                identity: first.identity,
                code: &first.source,
                base_address: first.base,
                function: range,
                block: range,
                logical_pc: first.logical_pc,
                entries,
                semantics: HookSemantics::Observe,
                allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 80,
                    max_sites: 1,
                },
            },
            original_code: &first.source,
            emission: EmissionContext::Live(first.control.callback()),
        };
        request.require_original(range)?;
        request.emission.qualify()?;
        let mut occupied = request.emission.occupied()?;
        // Both gates share this single RW owner; charge its range once here.
        occupied.push(region.clock().range());
        let sites = search.begin(
            SearchDomain::PhysicalSites,
            SearchScope::default(),
            1,
            Some(1),
        );
        search.visit(sites);
        let result = emit_relocation_window(
            &request,
            &scan,
            range,
            &occupied,
            (None, None),
            RelocationWindow {
                physical: range.start(),
                end: range.end(),
                displaced: range,
                instructions: scan.instructions().iter().collect(),
                authority: RelocationAuthority::OwnedClockRegion {
                    proof: &proof,
                    region,
                },
            },
            &mut search,
        );
        attempts.push(SiteAttempt {
            tactic: PatchTactic::Relocation,
            physical_pc: range.start(),
            refusal: result.as_ref().err().cloned(),
        });
        match result {
            Ok(plan) => {
                search.accept(sites);
                Ok(plan)
            }
            Err(reason) => {
                search.finish(sites);
                Err(reason)
            }
        }
    })();
    match result {
        Ok(mut plan) => {
            search.accepted = true;
            plan.metrics.search = search;
            plan.metrics.attempts = attempts;
            Ok(plan)
        }
        Err(reason) => {
            search.qualification(SearchScope::default(), &reason);
            Err(PlanningFailure {
                reason,
                attempts,
                search,
            })
        }
    }
}

/// Convenience wrapper preserving the detailed planner's exact refusal.
///
/// # Safety
/// All requirements of [`plan_owned_clock_region_detailed`] apply.
pub unsafe fn plan_owned_clock_region(
    region: &BackedgeClockRegion,
    entries: &LegalEntrySet,
    allocation: &AllocationPolicy,
) -> Result<PlannedInstall, Refusal> {
    // SAFETY: the caller assumes the identical whole-region contract above.
    unsafe { plan_owned_clock_region_detailed(region, entries, allocation) }
        .map_err(|failure| failure.reason)
}

pub(super) struct Verified {
    entries: LegalEntrySet,
    sites: [u64; 2],
}

impl Verified {
    fn new(
        region: &BackedgeClockRegion,
        entries: &LegalEntrySet,
        allocation: &AllocationPolicy,
        scan: &ScanResult,
    ) -> Result<Self, Refusal> {
        let first = &region.actions[0];
        if first.base == 0 || !(5..=80).contains(&first.source.len()) {
            return Err(Refusal::NoPatchWindow);
        }
        let range = AddressRange::new(first.base, first.source.len())?;
        if entries.identity != first.identity {
            return Err(Refusal::StaleGeneration);
        }
        if entries.scope != range {
            return Err(Refusal::InvalidRange);
        }
        if entries.completeness != EntryCompleteness::Complete
            || entries.resumes != ResumeObligation::NoneExist
            || entries.entries.iter().any(|entry| entry.requires_endbr)
        {
            return Err(Refusal::UnresolvedEntry);
        }
        if allocation.max_candidates > 256
            || allocation.max_mappings > 1
            || allocation.max_mapped_bytes > 8192
        {
            return Err(Refusal::AllocationUnavailable);
        }
        // The same scanned admission used by the constructor checks the closed
        // scalar CFG, both exact near backedges, sole final C3, reachability and
        // a structural path to RET from every head. It also rechecks all common
        // source/clock/control bindings without decoding a second snapshot.
        region
            .validate_scan(scan)
            .map_err(|_| Refusal::InvalidPlan)?;
        let mut leaders = BTreeSet::from([range.start()]);
        for item in scan.instructions() {
            let instruction = item.instruction();
            qualify_instruction(instruction)?;
            if matches!(
                instruction.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) {
                leaders.insert(instruction.near_branch_target());
                if instruction.flow_control() == FlowControl::ConditionalBranch {
                    leaders.insert(instruction.next_ip());
                }
            }
        }
        if entries
            .entries
            .iter()
            .map(|entry| entry.address)
            .collect::<Vec<_>>()
            != leaders.into_iter().collect::<Vec<_>>()
        {
            return Err(Refusal::UnresolvedEntry);
        }
        Ok(Self {
            entries: entries.clone(),
            sites: region.actions.each_ref().map(|action| action.logical_pc),
        })
    }

    pub(super) fn matches_request(
        &self,
        request: &PlanningRequest<'_>,
        scan: &ScanResult,
        region: &BackedgeClockRegion,
    ) -> bool {
        let first = &region.actions[0];
        request.identity == self.entries.identity
            && first.identity == self.entries.identity
            && request.entries == &self.entries
            && request.function == self.entries.scope
            && request.block == self.entries.scope
            && request.base_address == first.base
            && request.logical_pc == self.sites[0]
            && region.actions.each_ref().map(|action| action.logical_pc) == self.sites
            && request.code == first.source.as_slice()
            && request.original_code == first.source.as_slice()
            && scan.snapshot() == first.source.as_slice()
            && request.semantics == HookSemantics::Observe
            && request.search.tactics == TacticPolicy::RelocationOnly
            && request.search.max_upstream_bytes == 0
            && request.search.max_displaced_bytes == 80
            && request.search.max_sites == 1
            && request.allocation.max_candidates <= 256
            && request.allocation.max_mappings <= 1
            && request.allocation.max_mapped_bytes <= 8192
    }

    pub(super) fn verify_image(
        &self,
        scan: &ScanResult,
        region: &BackedgeClockRegion,
        image: &TrampolineImage,
    ) -> Result<(), Refusal> {
        if image.clock_gate().is_some()
            || image.precontext_selector().is_some()
            || !image.precontext_gates().is_empty()
            || image.artifact_metadata().is_some()
        {
            return Err(Refusal::InvalidPlan);
        }
        self.verify_view(scan, region, ImageView::from(image))
    }

    fn verify_view(
        &self,
        scan: &ScanResult,
        region: &BackedgeClockRegion,
        view: ImageView<'_>,
    ) -> Result<(), Refusal> {
        let items = scan.instructions();
        let ImageView {
            address,
            bytes,
            entries,
            bodies,
            maps,
            controls,
            clock,
            gates,
            layout,
        } = view;
        let image_end = address
            .checked_add(bytes.len() as u64)
            .ok_or(Refusal::InvalidRange)?;
        let jumpback = image_end
            .checked_sub(layout.return_len as u64)
            .filter(|&end| end > address)
            .ok_or(Refusal::InvalidPlan)?;
        if layout.observation_stack_profile != ObservationStackProfile::Legacy128
            || layout.total_len() != Some(bytes.len())
            || layout.return_len != 5
            || entries.len() != items.len()
            || bodies.len() != items.len()
            || entries.first().map(|entry| entry.1) != Some(address)
            || maps.len() != items.len() + 1
            || controls.len() != 2
            || controls
                .iter()
                .zip(&region.actions)
                .any(|(control, action)| control != &action.control)
            || clock != Some(region.clock())
            || gates.len() != 2
            || gates.iter().map(|gate| gate.logical_pc).collect::<Vec<_>>() != self.sites
            || maps.last().is_none_or(|map| {
                map.generated_start() != jumpback
                    || map.generated_end() != image_end
                    || map.logical_address() != self.entries.scope.end()
            })
        {
            return Err(Refusal::InvalidPlan);
        }
        for (index, item) in items.iter().enumerate() {
            let (source, entry) = entries[index];
            let (body_source, body) = bodies[index];
            let next = entries.get(index + 1).map_or(jumpback, |entry| entry.1);
            let gate = gates.iter().find(|gate| gate.logical_pc == source);
            if source != item.address()
                || body_source != source
                || !(address <= entry && entry <= body && body < next && next <= jumpback)
                || gate.is_some() != (entry < body)
                || maps[index].generated_start() != entry
                || maps[index].generated_end() != next
                || maps[index].logical_address() != source
            {
                return Err(Refusal::InvalidPlan);
            }
            if let Some(gate) = gate {
                // The emitter separately verifies each gate's complete machine
                // sequence, shared-word bindings and flag-neutral fast/slow
                // paths. This proof binds exactly those two gate layouts to
                // original heads, restored bodies and complete reverse maps.
                if gate.gate.entry != entry
                    || gate.gate.original_body != body
                    || !(entry < gate.gate.observing_entry && gate.gate.observing_entry < body)
                {
                    return Err(Refusal::InvalidPlan);
                }
            }
            let start = usize::try_from(body - address).map_err(|_| Refusal::InvalidRange)?;
            let end = usize::try_from(next - address).map_err(|_| Refusal::InvalidRange)?;
            let body_bytes = bytes.get(start..end).ok_or(Refusal::InvalidPlan)?;
            let emitted = Decoder::with_ip(64, body_bytes, body, DecoderOptions::NONE).decode();
            let original = item.instruction();
            if emitted.is_invalid()
                || emitted.next_ip() != next
                || emitted.code() != original.code()
                || emitted.mnemonic() != original.mnemonic()
                || emitted.flow_control() != original.flow_control()
            {
                return Err(Refusal::InvalidPlan);
            }
            match original.flow_control() {
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    let target = entries
                        .iter()
                        .find(|entry| entry.0 == original.near_branch_target())
                        .ok_or(Refusal::InvalidPlan)?
                        .1;
                    if emitted.op_count() != 1
                        || emitted.op0_kind() != OpKind::NearBranch64
                        || emitted.near_branch_target() != target
                    {
                        return Err(Refusal::InvalidPlan);
                    }
                }
                FlowControl::Return if body_bytes == [0xc3] => {}
                FlowControl::Next => {
                    let original_bytes =
                        &scan.snapshot()[item.offset()..item.offset() + item.len()];
                    if body_bytes != original_bytes {
                        return Err(Refusal::InvalidPlan);
                    }
                }
                _ => return Err(Refusal::InvalidPlan),
            }
        }
        let return_offset =
            usize::try_from(jumpback - address).map_err(|_| Refusal::InvalidRange)?;
        let returned = Decoder::with_ip(
            64,
            bytes.get(return_offset..).ok_or(Refusal::InvalidPlan)?,
            jumpback,
            DecoderOptions::NONE,
        )
        .decode();
        if returned.code() != iced_x86::Code::Jmp_rel32_64
            || returned.next_ip() != image_end
            || returned.near_branch_target() != self.entries.scope.end()
        {
            return Err(Refusal::InvalidPlan);
        }
        // Closed successors and exact branch-to-entry routing leave the normal
        // appended jumpback unreachable; no interior original head is omitted.
        Ok(())
    }
}

struct ImageView<'a> {
    address: u64,
    bytes: &'a [u8],
    entries: &'a [(u64, u64)],
    bodies: &'a [(u64, u64)],
    maps: &'a [ProgramCounterMapping],
    controls: &'a [ProbeControl],
    clock: Option<&'a BackedgeClock>,
    gates: &'a [ClockRegionGateLayout],
    layout: TrampolineLayout,
}
impl<'a> From<&'a TrampolineImage> for ImageView<'a> {
    fn from(image: &'a TrampolineImage) -> Self {
        Self {
            address: image.address(),
            bytes: image.bytes(),
            entries: image.entry_routes(),
            bodies: image.instruction_boundaries(),
            maps: image.program_counter_mappings(),
            controls: image.controls(),
            clock: image.clock(),
            gates: image.clock_region_gates(),
            layout: image.layout(),
        }
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
