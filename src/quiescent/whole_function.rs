//! Opt-in closed scalar region; this never changes basic-block admission.

use super::*;
use crate::control_flow::{self, Coverage};
use crate::controls::{ControlledAction, EntryAdmissionAction, EntryAdmissionRole, ProbeControl};
use crate::emission::{EmissionContext, PlanningSite};
use crate::trampoline::{ObservationStackProfile, ProgramCounterMapping, TrampolineLayout};
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

/// Exact original function and caller-certified external-entry ownership.
///
/// This initial profile is a read-only scalar function of 5..=80 bytes. It
/// retains the existing one-image, 256-candidate, 8192-byte allocation ceilings,
/// Legacy128 observing frames and ordinary quiescent publication requirements.
/// Planning is not publication, ABI qualification, termination or native proof.
pub struct WholeFunctionRequest<'a> {
    /// Non-reusable mapping/source generation.
    pub identity: CodeIdentity,
    /// Complete original function, without adjacent padding or omitted suffix.
    pub code: &'a [u8],
    /// Actual function entry and coordinate of code[0].
    pub base_address: u64,
    /// Complete entries in this exact function and generation. Positive facts
    /// include all decoded reachable leaders: entry, direct branch targets and
    /// conditional fallthroughs. Internal leaders remain routed, not erased.
    /// No saved resumes or ENDBR-required entries are admitted.
    pub entries: &'a LegalEntrySet,
    /// Placement within the existing finite resource ceilings; smaller limits
    /// may refuse and never permit a larger search or fallback mode.
    pub allocation: &'a AllocationPolicy,
}

/// Relocate one complete closed scalar function, with entry and all RET controls.
///
/// Actions must be the entry followed by every reachable literal C3 in address
/// order, each with a distinct control. All original heads are retained in the
/// image maps, internal direct targets enter before their action, and the full
/// function is displaced even when its last action precedes its final branch.
/// The existing jumpback stub remains emitted but is unreachable from entry.
/// Internal source heads retain the existing invalid-opcode routes/obligations;
/// publication still needs the SIGILL-router contract when routes exist.
///
/// # Safety
/// The caller authenticates the complete original function and its immutable
/// mapping/owner. The sole external entry is base_address: no external branch,
/// indirect call, signal/context restoration or saved continuation may enter an
/// interior head or generated suffix. No in-flight invocation may be displaced.
/// LegalEntrySet's internal leader facts do not prove these exclusion premises.
/// No foreign writer, remapping, alias or loader change may invalidate the
/// snapshot through publication/execution/retirement. Preserve the existing
/// quiescence, signal, System V/no-CET and stack/state preservation contracts.
/// Callbacks must not unwind or change saved architectural state, return words
/// or source code; they and their controls must outlive executable use. Pointer
/// validity, read-only application data, bounded termination and complete
/// function/entry metadata are caller obligations, not conclusions of decoding.
pub unsafe fn plan_whole_function_controlled_detailed(
    request: &WholeFunctionRequest<'_>,
    actions: &[ControlledAction],
) -> Result<PlannedInstall, PlanningFailure> {
    plan(request, actions, request.code, None)
}

/// As above, authenticating original bytes and the exact predecessor overlay.
///
/// Any earlier edit in the full displaced function refuses before image search.
/// Planning never appends to the predecessor; ordinary bundle/composition checks
/// still authenticate its allocations, locks and complete publication reads.
///
/// # Safety
/// All requirements of [`plan_whole_function_controlled_detailed`] apply, in
/// the exact source namespace owned by this authenticated predecessor.
pub unsafe fn plan_whole_function_controlled_detailed_after(
    request: &WholeFunctionRequest<'_>,
    actions: &[ControlledAction],
    predecessor: &crate::composition::Composition,
) -> Result<PlannedInstall, PlanningFailure> {
    let current = predecessor
        .planning_overlay(request.identity, request.base_address, request.code)
        .map_err(failure)?;
    plan(request, actions, &current, None)
}

/// Relocate the complete closed scalar function with optional entry admission.
///
/// The exact entry is the only early gate; every reachable C3 retains a distinct
/// permanently enabled return callback. The existing whole-function CFG,
/// entry/resume, complete-role and final-image checks all apply unchanged.
/// Smaller caller caps still win over the 256-candidate, one-image, 8192-byte
/// ceilings. No mandatory/point policy fallback is attempted.
///
/// # Safety
/// Both [`plan_whole_function_controlled_detailed`] and
/// [`EntryAdmissionAction::entry`] contracts apply. In particular the certified
/// depth-one caller/runtime must account for all physical calls independently
/// of sparse observed intervals, preserve live/returned owners across bypass
/// and rearm, and keep all RETs mandatory. Decoding does not prove that runtime.
pub unsafe fn plan_whole_function_entry_admission_detailed(
    request: &WholeFunctionRequest<'_>,
    actions: &[EntryAdmissionAction],
) -> Result<PlannedInstall, PlanningFailure> {
    plan_entry_admission(request, actions, request.code)
}

/// Authenticate a predecessor overlay before optional-entry whole-function planning.
/// Earlier edits anywhere in this complete displaced function still refuse.
///
/// # Safety
/// All requirements of [`plan_whole_function_entry_admission_detailed`] apply,
/// with the unchanged complete composition/publication ownership contract.
pub unsafe fn plan_whole_function_entry_admission_detailed_after(
    request: &WholeFunctionRequest<'_>,
    actions: &[EntryAdmissionAction],
    predecessor: &crate::composition::Composition,
) -> Result<PlannedInstall, PlanningFailure> {
    let current = predecessor
        .planning_overlay(request.identity, request.base_address, request.code)
        .map_err(failure)?;
    plan_entry_admission(request, actions, &current)
}

fn plan_entry_admission(
    input: &WholeFunctionRequest<'_>,
    actions: &[EntryAdmissionAction],
    current: &[u8],
) -> Result<PlannedInstall, PlanningFailure> {
    if !(2..=5).contains(&actions.len()) {
        return Err(failure(Refusal::InvalidPlan));
    }
    let controlled: Vec<_> = actions.iter().map(|a| a.controlled().clone()).collect();
    let mut allocation = input.allocation.clone();
    allocation.max_candidates = allocation.max_candidates.min(256);
    allocation.max_mappings = allocation.max_mappings.min(1);
    allocation.max_mapped_bytes = allocation.max_mapped_bytes.min(8192);
    let request = WholeFunctionRequest {
        identity: input.identity,
        code: input.code,
        base_address: input.base_address,
        entries: input.entries,
        allocation: &allocation,
    };
    plan(&request, &controlled, current, Some(actions))
}

fn failure(reason: Refusal) -> PlanningFailure {
    let mut search = SearchEvidence::default();
    search.qualification(SearchScope::default(), &reason);
    PlanningFailure {
        reason,
        attempts: Vec::new(),
        search,
    }
}

fn plan(
    input: &WholeFunctionRequest<'_>,
    actions: &[ControlledAction],
    current: &[u8],
    entry_admission: Option<&[EntryAdmissionAction]>,
) -> Result<PlannedInstall, PlanningFailure> {
    let mut search = SearchEvidence::default();
    let mut attempts = Vec::new();
    let result = (|| {
        // Refuse the finite profile before decoding or allocating scan storage.
        if input.base_address == 0 || !(5..=80).contains(&input.code.len()) {
            return Err(Refusal::NoPatchWindow);
        }
        let range = AddressRange::new(input.base_address, input.code.len())?;
        let scan = InstructionScanner::default()
            .scan(input.code, input.base_address)
            .map_err(|e| Refusal::Backend(e.to_string()))?;
        if let Some(roles) = entry_admission {
            crate::controls::entry_admission::validate(&scan, roles)?;
        }
        let proof = Verified::new(input, &scan, actions)?;
        // Only this verified mode uses a multi-block region in the shared
        // emission site. It never enters the legacy block-window selector.
        let request = PlanningRequest {
            site: PlanningSite {
                identity: input.identity,
                code: current,
                base_address: input.base_address,
                function: range,
                block: range,
                logical_pc: input.base_address,
                entries: input.entries,
                semantics: HookSemantics::Observe,
                allocation: input.allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 80,
                    max_sites: 1,
                },
            },
            original_code: input.code,
            emission: EmissionContext::Live(actions[0].control.callback()),
        };
        // Keep whole original-window authentication before address search or
        // occupancy work. The shared emitter repeats its existing check.
        request.require_original(range)?;
        request.emission.qualify()?;
        let occupied = request.emission.occupied()?;
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
            (
                Some(entry_admission.map_or(
                    CoalescedActions::Controlled(actions),
                    CoalescedActions::EntryAdmission,
                )),
                None,
            ),
            RelocationWindow {
                physical: range.start(),
                end: range.end(),
                displaced: range,
                instructions: scan.instructions().iter().collect(),
                authority: RelocationAuthority::WholeFunction(&proof),
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

fn unsupported() -> Refusal {
    Refusal::UnsupportedSemantics("whole-function closed scalar profile".into())
}

fn scalar(i: &Instruction) -> bool {
    crate::scalar_profile::read_only_caller_saved(i)
}

// Constructed only after exact closed-CFG, role and entry-fact validation.
// This proves structural paths to RET, never input-dependent termination or
// absence of unreported external/saved entries. Those are unsafe API premises.
#[derive(Debug)]
pub(super) struct Verified {
    end: u64,
}
impl Verified {
    fn new(
        request: &WholeFunctionRequest<'_>,
        scan: &ScanResult,
        actions: &[ControlledAction],
    ) -> Result<Self, Refusal> {
        let bytes = request.code;
        if request.base_address == 0 || !(5..=80).contains(&bytes.len()) {
            return Err(Refusal::NoPatchWindow);
        }
        let range = AddressRange::new(request.base_address, bytes.len())?;
        if request.entries.identity != request.identity {
            return Err(Refusal::StaleGeneration);
        }
        if request.entries.scope != range {
            return Err(Refusal::InvalidRange);
        }
        if request.entries.completeness != EntryCompleteness::Complete
            || request.entries.resumes != ResumeObligation::NoneExist
            || request.entries.entries.iter().any(|e| e.requires_endbr)
        {
            return Err(Refusal::UnresolvedEntry);
        }
        let policy = request.allocation;
        if policy.max_candidates > 256 || policy.max_mappings > 1 || policy.max_mapped_bytes > 8192
        {
            return Err(Refusal::AllocationUnavailable);
        }
        let items = scan.instructions();
        if scan.snapshot() != bytes
            || items.first().map(|i| i.address()) != Some(range.start())
            || items.last().map(|i| i.instruction().next_ip()) != Some(range.end())
        {
            return Err(Refusal::InvalidRange);
        }
        let graph = control_flow::build(scan, |n, item, row| {
            let i = item.instruction();
            let raw = &bytes[item.offset()..item.offset() + item.len()];
            if i.has_lock_prefix()
                || i.has_rep_prefix()
                || i.has_repne_prefix()
                || i.segment_prefix() != Register::None
                || i.is_privileged()
            {
                return Err(unsupported());
            }
            qualify_instruction(i)?;
            match i.flow_control() {
                FlowControl::Next => {
                    if !scalar(i) || n + 1 == items.len() {
                        return Err(unsupported());
                    }
                }
                FlowControl::Return if raw == [0xc3] => {}
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    if !matches!(
                        raw,
                        [0x70..=0x7f, _]
                            | [0x0f, 0x80..=0x8f, _, _, _, _]
                            | [0xeb, _]
                            | [0xe9, _, _, _, _]
                    ) || i.op_count() != 1
                        || i.op_kind(0) != OpKind::NearBranch64
                    {
                        return Err(unsupported());
                    }
                    let destination = row
                        .branch_target()
                        .and_then(|target| target.head())
                        .ok_or_else(unsupported)?;
                    if destination == 0 || destination == n {
                        return Err(unsupported());
                    }
                    if i.flow_control() == FlowControl::ConditionalBranch && n + 1 == items.len() {
                        return Err(unsupported());
                    }
                }
                _ => return Err(unsupported()),
            }
            Ok(())
        })?;
        let indexed = graph.indexed().map_err(|_| unsupported())?;
        let reached = indexed.reachable_from(0).map_err(|_| unsupported())?;
        if items
            .iter()
            .enumerate()
            .any(|(n, i)| !reached[n] && i.instruction().mnemonic() != Mnemonic::Nop)
        {
            return Err(unsupported());
        }
        let returns: Vec<_> = items
            .iter()
            .enumerate()
            .filter(|(n, i)| reached[*n] && i.instruction().flow_control() == FlowControl::Return)
            .map(|(_, i)| i.address())
            .collect();
        if !(1..=4).contains(&returns.len()) {
            return Err(unsupported());
        }
        let return_indices: Vec<_> = items
            .iter()
            .enumerate()
            .filter(|(_, item)| returns.contains(&item.address()))
            .map(|(index, _)| index)
            .collect();
        let can_return = indexed
            .can_reach_any(&return_indices)
            .map_err(|_| unsupported())?;
        if reached
            .iter()
            .zip(&can_return)
            .any(|(&r, &exit)| r && !exit)
        {
            return Err(unsupported());
        }
        let blocks = indexed
            .blocks(Coverage::Reachable(&reached))
            .map_err(|_| unsupported())?;
        if blocks.len() > 32 {
            return Err(unsupported());
        }
        let expected: Vec<_> = graph
            .branch_entries()
            .iter()
            .copied()
            .filter(|&n| reached[n])
            .map(|n| items[n].address())
            .collect();
        if request
            .entries
            .entries
            .iter()
            .map(|e| e.address)
            .collect::<Vec<_>>()
            != expected
        {
            return Err(Refusal::UnresolvedEntry);
        }
        let roles: Vec<_> = std::iter::once(range.start()).chain(returns).collect();
        if actions.iter().map(|a| a.logical_pc).collect::<Vec<_>>() != roles
            || actions
                .iter()
                .enumerate()
                .any(|(n, a)| actions[..n].iter().any(|b| b.control == a.control))
        {
            return Err(Refusal::InvalidPlan);
        }
        Ok(Self { end: range.end() })
    }

    pub(super) fn verify_image(
        &self,
        scan: &ScanResult,
        actions: &[ControlledAction],
        image: &TrampolineImage,
    ) -> Result<(), Refusal> {
        self.verify_view(scan, actions, ImageView::from(image))
    }

    pub(super) fn verify_entry_admission_image(
        &self,
        scan: &ScanResult,
        actions: &[EntryAdmissionAction],
        image: &TrampolineImage,
    ) -> Result<(), Refusal> {
        crate::controls::entry_admission::validate(scan, actions)?;
        let controlled: Vec<_> = actions.iter().map(|a| a.controlled().clone()).collect();
        self.verify_image(scan, &controlled, image)?;
        let [gate] = image.early_control_gates() else {
            return Err(Refusal::InvalidPlan);
        };
        if actions[0].role() != EntryAdmissionRole::Entry
            || gate.logical_pc != actions[0].function_entry()
            || image.entry_routes().first() != Some(&(gate.logical_pc, gate.entry))
            || image.instruction_boundaries().first()
                != Some(&(gate.logical_pc, gate.original_body))
        {
            return Err(Refusal::InvalidPlan);
        }
        Ok(())
    }

    fn verify_view(
        &self,
        scan: &ScanResult,
        actions: &[ControlledAction],
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
            layout,
        } = view;
        let jumpback = address
            .checked_add(
                bytes
                    .len()
                    .checked_sub(layout.return_len)
                    .ok_or(Refusal::InvalidPlan)? as u64,
            )
            .ok_or(Refusal::InvalidRange)?;
        if layout.observation_stack_profile != ObservationStackProfile::Legacy128
            || layout.total_len() != Some(bytes.len())
            || entries.len() != items.len()
            || bodies.len() != items.len()
            || entries.first().map(|x| x.1) != Some(address)
            || maps.len() != items.len() + 1
            || controls.len() != actions.len()
            || controls.iter().zip(actions).any(|(c, a)| c != &a.control)
            || !maps
                .iter()
                .any(|m| m.generated_start() == jumpback && m.logical_address() == self.end)
        {
            return Err(Refusal::InvalidPlan);
        }
        for (n, item) in items.iter().enumerate() {
            let (source, entry) = entries[n];
            let (body_source, body) = bodies[n];
            let next = entries.get(n + 1).map_or(jumpback, |x| x.1);
            let action = actions.iter().any(|a| a.logical_pc == source);
            if source != item.address()
                || body_source != source
                || !(address <= entry && entry <= body && body < next && next <= jumpback)
                || (action && entry == body)
                || (!action && entry != body)
                || maps[n].generated_start() != entry
                || maps[n].generated_end() != next
                || maps[n].logical_address() != source
            {
                return Err(Refusal::InvalidPlan);
            }
            let start = usize::try_from(body - address).map_err(|_| Refusal::InvalidRange)?;
            let end = usize::try_from(next - address).map_err(|_| Refusal::InvalidRange)?;
            let mut decoder = Decoder::with_ip(
                64,
                bytes.get(start..end).ok_or(Refusal::InvalidPlan)?,
                body,
                DecoderOptions::NONE,
            );
            let emitted = decoder.decode();
            let original = item.instruction();
            if emitted.is_invalid()
                || emitted.next_ip() != next
                || emitted.mnemonic() != original.mnemonic()
                || emitted.flow_control() != original.flow_control()
            {
                return Err(Refusal::InvalidPlan);
            }
            match original.flow_control() {
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    let target = entries
                        .iter()
                        .find(|x| x.0 == original.near_branch_target())
                        .ok_or(Refusal::InvalidPlan)?
                        .1;
                    if emitted.op0_kind() != OpKind::NearBranch64
                        || emitted.near_branch_target() != target
                    {
                        return Err(Refusal::InvalidPlan);
                    }
                }
                FlowControl::Return if bytes[start..end] != [0xc3] => {
                    return Err(Refusal::InvalidPlan);
                }
                FlowControl::Next => {
                    // Non-branch operands and exact original NOP encodings have
                    // no relocatable addresses in this profile.
                    let source_bytes = &scan.snapshot()[item.offset()..item.offset() + item.len()];
                    if bytes[start..end] != *source_bytes {
                        return Err(Refusal::InvalidPlan);
                    }
                }
                _ => {}
            }
        }
        // Verified closed successors plus exact generated entry destinations
        // prove no admitted application path reaches the appended jumpback.
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
            layout: image.layout(),
        }
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
