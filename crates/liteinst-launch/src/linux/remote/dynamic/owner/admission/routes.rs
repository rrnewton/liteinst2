//! Origin-by-origin continuation checks made under a real native mm hold.
//! A route describes final source geometry; it never erases an original scan
//! refusal. Retained evidence is not itself a future execution capability.
use super::census::{OriginId, OriginKind, ResumeCensus};
use super::domain::Domain;
use super::*;
use crate::gate::domain::{PAGE, PendingAdmission};
use crate::publication::PublicationStop;
use crate::trap_coverage::{TrapGuard, TrapGuardRole};
use liteinst_admission::returns::CallReturnObligation;
use std::collections::{BTreeMap, BTreeSet};

mod mapping;
pub(in crate::linux::remote::dynamic::owner) use mapping::MappingRevocation;
pub(super) use mapping::{close_mapping_window, open_mapping_window};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RouteOrigin {
    Census {
        id: OriginId,
        task: DynamicTask,
        token: DynamicStop,
        frame: Option<(SignalFrameId, u64)>,
    },
    Call {
        obligation: CallReturnObligation,
        planned: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Route {
    OriginalUnchanged,
    GuardedHead { role: TrapGuardRole },
    RetainedNx { page: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResolvedRoute {
    pub(super) origin: RouteOrigin,
    pub(super) pc: u64,
    pub(super) original: Vec<u8>,
    pub(super) route: Route,
    pub(super) generation: u64,
    pub(super) entry_version: u64,
    pub(super) plan: u64,
}

// This is private even to the dispatcher. Only the functions in this module
// can create it, and the owned borrow of HeldMmStop covers all checks and writes.
struct HeldRoutes<'a, 'owner> {
    held: &'a mut super::super::publication::HeldMmStop<'owner>,
    routes: Vec<ResolvedRoute>,
    final_executable: BTreeSet<u64>,
    final_guards: BTreeMap<u64, TrapGuard>,
}

fn refuse_census(_: super::census::CensusError) -> GateError {
    GateError::Refused("dynamic resume census does not match the current native hold")
}

fn frame_identity(
    census: &ResumeCensus,
    id: OriginId,
) -> Result<Option<(SignalFrameId, u64)>, GateError> {
    let row = census
        .active()
        .find(|row| row.row.id == id)
        .ok_or(GateError::Refused("dynamic route origin is not active"))?;
    match row.row.kind {
        OriginKind::SignalFrame { frame, .. } => {
            let (_, facts) = census
                .active_frames()
                .find(|(active, _)| active.row.id == id)
                .ok_or(GateError::Refused(
                    "dynamic frame route lacks immutable facts",
                ))?;
            if frame != facts.id {
                return Err(GateError::Refused("dynamic frame route identity differs"));
            }
            Ok(Some((frame, facts.version)))
        }
        _ => Ok(None),
    }
}
fn check_origin(
    census: &ResumeCensus,
    active: census::ActiveOrigin<'_>,
    token: &DynamicStop,
) -> Result<Option<(SignalFrameId, u64)>, GateError> {
    if active.current.token != *token {
        return Err(GateError::Refused(
            "dynamic route origin has a stale native token",
        ));
    }
    match active.row.kind {
        OriginKind::SignalFrame { .. } => {
            let (_, facts) = census
                .active_frames()
                .find(|(row, _)| row.row.id == active.row.id)
                .ok_or(GateError::Refused(
                    "dynamic saved frame has no exact version",
                ))?;
            let bytes = read_memory(token.tid, facts.address, facts.bytes.len())?;
            census
                .check_frame_origin(active.row.id, active.current, facts.address, &bytes)
                .map_err(refuse_census)?;
            Ok(Some((facts.id, facts.version)))
        }
        _ => {
            census
                .check_current_origin(active.row.id, active.current)
                .map_err(refuse_census)?;
            Ok(None)
        }
    }
}

fn whole_route(
    domain: &Domain,
    pc: u64,
    final_executable: &BTreeSet<u64>,
    final_guards: &BTreeMap<u64, TrapGuard>,
) -> Result<(Vec<u8>, Route), GateError> {
    let original = domain.original_decode(pc)?;
    let page = pc & !(PAGE - 1);
    if !domain.pages.contains_key(&page) {
        return Err(GateError::Refused(
            "dynamic resume page is outside the owned NX inventory",
        ));
    }
    if !final_executable.contains(&page) {
        return Ok((original, Route::RetainedNx { page }));
    }
    let end = pc
        .checked_add(original.len() as u64)
        .ok_or(GateError::Refused("dynamic resume decode overflows"))?;
    if let Some(guard) = final_guards.get(&pc) {
        if guard.original_bytes() != original {
            return Err(GateError::Refused(
                "dynamic resume head guard has another original decode",
            ));
        }
        if guard.role() == TrapGuardRole::Collateral {
            crate::gate::domain::qualify_collateral(guard)?;
        }
        return Ok((original, Route::GuardedHead { role: guard.role() }));
    }
    if final_guards.range(pc..end).next().is_some() {
        return Err(GateError::Refused(
            "dynamic resume intersects an edit without its own head guard",
        ));
    }
    let instruction =
        iced_x86::Decoder::with_ip(64, &original, pc, iced_x86::DecoderOptions::NONE).decode();
    use iced_x86::Mnemonic;
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Cpuid
            | Mnemonic::Rdtsc
            | Mnemonic::Rdtscp
            | Mnemonic::Rdrand
            | Mnemonic::Rdseed
            | Mnemonic::Rdpid
            | Mnemonic::Syscall
    ) {
        return Err(GateError::Refused(
            "unchanged resume route would bypass a default selected instruction",
        ));
    }
    Ok((original, Route::OriginalUnchanged))
}

fn authenticate_source(
    held: &super::super::publication::HeldMmStop<'_>,
    domain: &Domain,
) -> Result<(), GateError> {
    for image in &domain.images {
        let expected = domain.expected_image(image);
        if held.read_memory(image.mapping.start, expected.len())? != expected {
            return Err(GateError::Refused(
                "dynamic source or installed guard bytes changed",
            ));
        }
    }
    let maps = held.mappings();
    for (&page, &executable) in &domain.pages {
        let end = page + PAGE;
        let mapping = maps
            .iter()
            .find(|map| map.start <= page && end <= map.end)
            .ok_or(GateError::Refused("dynamic original page mapping changed"))?;
        let permissions = mapping.permissions.as_bytes();
        if permissions.get(3) != Some(&b'p')
            || permissions.get(1) == Some(&b'w')
            || (permissions.get(2) == Some(&b'x')) != executable
        {
            return Err(GateError::Refused(
                "dynamic original page permissions changed",
            ));
        }
    }
    Ok(())
}

impl<'a, 'owner> HeldRoutes<'a, 'owner> {
    fn prepare(
        held: &'a mut super::super::publication::HeldMmStop<'owner>,
        domain: &Domain,
        census: &ResumeCensus,
        plan: &PendingAdmission,
        id: u64,
    ) -> Result<Self, GateError> {
        domain.validate_plan(plan)?;
        if held.membership().generation != domain.generation
            || census.generation() != domain.generation
        {
            return Err(GateError::Refused(
                "dynamic route generation differs from the native hold",
            ));
        }
        census
            .check_signal_obligations(&held.membership().candidate.obligations)
            .map_err(refuse_census)?;
        census
            .validate_projection(
                &domain
                    .images
                    .iter()
                    .map(|image| image.entries.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(refuse_census)?;
        authenticate_source(held, domain)?;
        let final_executable = domain
            .executable_pages()
            .union(plan.pages())
            .copied()
            .collect::<BTreeSet<_>>();
        let mut final_guards = domain.guards.clone();
        for (&pc, guard) in plan.guards() {
            if final_guards.get(&pc).is_some_and(|old| old != guard) {
                return Err(GateError::Refused("dynamic final guard set conflicts"));
            }
            final_guards.insert(pc, guard.clone());
        }
        let mut routes = Vec::new();
        let mut covered_tasks = BTreeSet::new();
        for active in census.active() {
            if matches!(active.row.kind, OriginKind::UnknownPersistent { .. }) {
                return Err(GateError::Refused(
                    "dynamic unknown saved context has no native routing proof",
                ));
            }
            let token = held.native.admission_held_token(active.current.task.task)?;
            let frame = check_origin(census, active, &token)?;
            let state = super::super::trusted::TaskStateSnapshot::read(token.tid)?;
            if token != active.current.token
                || !held
                    .membership()
                    .candidate
                    .tasks
                    .contains(&active.current.task.task)
                || active.current.task.address_space != held.membership().address_space
                || active.current.task.process != held.membership().process
                || state.registers != active.current.registers
                || state.xstate != active.current.xstate
                || state.mask != active.current.signal_mask
            {
                return Err(GateError::Refused(
                    "dynamic resume origin is not the exact current held task state",
                ));
            }
            covered_tasks.insert(active.current.task.task);
            let (original, route) =
                whole_route(domain, active.row.pc, &final_executable, &final_guards)?;
            routes.push(ResolvedRoute {
                origin: RouteOrigin::Census {
                    id: active.row.id,
                    task: active.current.task,
                    token,
                    frame,
                },
                pc: active.row.pc,
                original,
                route,
                generation: domain.generation,
                entry_version: domain.entry_version,
                plan: id,
            });
        }
        if covered_tasks != held.membership().candidate.tasks.iter().copied().collect() {
            return Err(GateError::Refused(
                "dynamic resume census omits a live mm task",
            ));
        }
        for requirement in plan.resume_requirements() {
            use crate::trap_coverage::pending::ResumeRequirementSource;
            let source_matches = match requirement.source() {
                ResumeRequirementSource::Report {
                    report_index,
                    obligation_index,
                } => {
                    plan.reports()
                        .get(report_index)
                        .filter(|report| {
                            report.snapshot() == plan.snapshot()
                                && report.entries() == plan.entries()
                                && report.policy() == plan.policy()
                        })
                        .and_then(|report| report.obligations().get(obligation_index))
                        == Some(&liteinst_admission::scan::Obligation::SavedResume(
                            requirement.address(),
                        ))
                }
                ResumeRequirementSource::Dependency { index, range } => {
                    plan.dependencies().get(index) == Some(&range)
                        && range.contains(requirement.address())
                }
            };
            if !source_matches
                || plan.entries().resumes().get(&requirement.address()) != Some(requirement.kinds())
            {
                return Err(GateError::Refused(
                    "dynamic saved-resume requirement lost its original source",
                ));
            }
            for &kind in requirement.kinds() {
                let origins = census
                    .active()
                    .filter(|active| {
                        active.row.pc == requirement.address()
                            && active.row.kind.resume_kind() == kind
                    })
                    .count();
                let resolved = routes
                    .iter()
                    .filter(|route| {
                        route.pc == requirement.address()
                            && matches!(route.origin, RouteOrigin::Census { .. })
                    })
                    .count();
                // Every origin was checked individually above. Projection
                // equality and a nonempty per-kind inventory prohibit using one
                // good task to hide a second origin at the same address/kind.
                if origins == 0 || resolved < origins {
                    return Err(GateError::Refused(
                        "dynamic saved-resume requirement has no complete origin inventory",
                    ));
                }
            }
        }
        for requirement in plan.call_requirements() {
            let call = requirement.obligation();
            if !plan.dependencies().contains(&requirement.dependency())
                || !requirement.dependency().contains(call.return_pc)
            {
                return Err(GateError::Refused(
                    "dynamic CALL requirement lost its original dependency",
                ));
            }
            let (original, route) =
                whole_route(domain, call.return_pc, &final_executable, &final_guards)?;
            routes.push(ResolvedRoute {
                origin: RouteOrigin::Call {
                    obligation: call.clone(),
                    planned: requirement.origin()
                        == crate::gate::domain::CallRequirementOrigin::Planned,
                },
                pc: call.return_pc,
                original,
                route,
                generation: domain.generation,
                entry_version: domain.entry_version,
                plan: id,
            });
        }
        // A newly enabled CALL can also return into an earlier admitted page
        // outside this transaction's scanner dependencies. Authenticate that
        // existing executable route before enabling the caller. Other future
        // returns remain conservatively retained in the append-only ledger.
        for call in plan.planned_calls() {
            if domain.pages.get(&(call.return_pc & !(PAGE - 1))) == Some(&true) {
                let (original, route) =
                    whole_route(domain, call.return_pc, &final_executable, &final_guards)?;
                routes.push(ResolvedRoute {
                    origin: RouteOrigin::Call {
                        obligation: call.clone(),
                        planned: true,
                    },
                    pc: call.return_pc,
                    original,
                    route,
                    generation: domain.generation,
                    entry_version: domain.entry_version,
                    plan: id,
                });
            }
        }
        // RetainedNx is backed by the native mapping above, not by the domain's
        // Boolean alone. Every such page must remain outside the final X set.
        for route in &routes {
            if let Route::RetainedNx { page } = route.route {
                if final_executable.contains(&page) || domain.pages.get(&page) != Some(&false) {
                    return Err(GateError::Refused(
                        "retained NX route would become executable",
                    ));
                }
            }
        }
        Ok(Self {
            held,
            routes,
            final_executable,
            final_guards,
        })
    }

    fn verify_final(
        &mut self,
        domain: &Domain,
        census: &ResumeCensus,
        plan: &PendingAdmission,
    ) -> Result<(), GateError> {
        let maps = self.held.mappings();
        for image in &domain.images {
            let expected = crate::gate::domain::armed_instruction(
                image.mapping.start,
                image.snapshot.bytes(),
                &BTreeMap::new(),
                &self.final_guards,
            );
            if self.held.read_memory(image.mapping.start, expected.len())? != expected {
                return Err(GateError::Refused(
                    "dynamic final guard image did not verify",
                ));
            }
        }
        for &page in domain.pages.keys() {
            let mapping = maps
                .iter()
                .find(|map| map.start <= page && page + PAGE <= map.end)
                .ok_or(GateError::Refused("dynamic final page mapping is missing"))?;
            if mapping.permissions.as_bytes().get(3) != Some(&b'p')
                || mapping.permissions.as_bytes().get(1) == Some(&b'w')
                || (mapping.permissions.as_bytes().get(2) == Some(&b'x'))
                    != self.final_executable.contains(&page)
            {
                return Err(GateError::Refused(
                    "dynamic final executable set did not verify",
                ));
            }
        }
        domain.validate_plan(plan)?;
        for resolved in &mut self.routes {
            if let RouteOrigin::Census {
                id,
                task,
                token,
                frame,
            } = &mut resolved.origin
            {
                let active = census.active().find(|active| active.row.id == *id).ok_or(
                    GateError::Refused("dynamic origin disappeared during native publication"),
                )?;
                let current = self.held.native.admission_held_token(task.task)?;
                let state = super::super::trusted::TaskStateSnapshot::read(current.tid)?;
                // Private runner stops may refresh the token, but publication
                // may not alter an original live frame or its version.
                if frame_identity(census, *id)? != *frame {
                    return Err(GateError::Refused(
                        "dynamic final frame route version differs",
                    ));
                }
                if let Some((_, facts)) = census.active_frames().find(|(row, _)| row.row.id == *id)
                {
                    if read_memory(current.tid, facts.address, facts.bytes.len())? != facts.bytes {
                        return Err(GateError::Refused("dynamic final saved frame bytes differ"));
                    }
                }
                if current.session != token.session
                    || current.task != token.task
                    || current.tid != token.tid
                    || current.sequence < token.sequence
                    || state.registers != active.current.registers
                    || state.xstate != active.current.xstate
                    || state.mask != active.current.signal_mask
                {
                    return Err(GateError::Refused(
                        "dynamic final route lost its exact held continuation",
                    ));
                }
                // The actual borrowed holder permits only its authenticated
                // private island sequences. They preserve complete state and
                // refresh real native stops; retain that resulting token.
                *token = current;
            }

            let (original, route) = whole_route(
                domain,
                resolved.pc,
                &self.final_executable,
                &self.final_guards,
            )?;
            if original != resolved.original || route != resolved.route {
                return Err(GateError::Refused(
                    "dynamic resume route changed during publication",
                ));
            }
        }
        Ok(())
    }
}

/// Apply one exactly bound pending plan under an actual all-mm hold. The caller
/// already reserved retained metadata/source budgets and closed original release.
/// No completed public TrapCoveragePlan or Boolean exclusion is accepted.
pub(super) fn publish(
    held: &mut super::super::publication::HeldMmStop<'_>,
    domain: &mut Domain,
    census: &ResumeCensus,
    plan: PendingAdmission,
    id: u64,
    until: Instant,
) -> Result<(), GateError> {
    let mut checked = HeldRoutes::prepare(held, domain, census, &plan, id)?;
    domain.record_callers(&plan)?;
    let identity = domain.image(plan.target().start())?.core_identity;
    let image = domain.image(plan.target().start())?;
    let ranges = vec![
        liteinst2::contracts::AddressRange::new(image.mapping.start, image.snapshot.bytes().len())
            .map_err(GateError::Core)?,
    ];
    // SAFETY: the borrowed native hold owns every live mm task; complete immutable
    // source/entry/census/ledger facts and every affected original route were
    // authenticated above. External writer/alias/context exclusions come from
    // the closed constructor contract. Only this exact pending plan is applied.
    unsafe {
        checked
            .held
            .with_publication_lease(identity, ranges, |operations, _lease| {
                for &page in plan.pages() {
                    operations.mprotect(
                        page,
                        PAGE as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        super::control_remaining(until)?,
                    )?;
                }
                for guard in plan.guards().values() {
                    if !domain.guards.contains_key(&guard.address()) {
                        operations.exact_store_checked(
                            guard.address(),
                            &guard.original_bytes()[..1],
                            &[0xcc],
                            super::control_remaining(until)?,
                        )?;
                    }
                }
                // Authenticate the complete final source before X. Checking just the
                // newly written byte would miss a damaged enclosing decode or old guard.
                for image in &domain.images {
                    let expected = crate::gate::domain::armed_instruction(
                        image.mapping.start,
                        image.snapshot.bytes(),
                        &BTreeMap::new(),
                        &checked.final_guards,
                    );
                    if operations.read_memory(image.mapping.start, expected.len())? != expected {
                        return Err(LaunchError::Invalid(
                            "dynamic final source differs before X",
                        ));
                    }
                }
                // Synchronize completed stores while all edited source remains NX.
                operations.sync_core(super::control_remaining(until)?)?;
                for &page in plan.pages() {
                    let protection = domain.protection(page, true).map_err(|_| {
                        LaunchError::Invalid("dynamic planned permission identity differs")
                    })?;
                    operations.mprotect(
                        page,
                        PAGE as usize,
                        protection,
                        super::control_remaining(until)?,
                    )?;
                }
                operations.sync_core(super::control_remaining(until)?)
            })?;
    }
    checked.verify_final(domain, census, &plan)?;
    let routes = checked.routes;
    domain.record_installed(id, plan, routes)
}

/// One original instruction temporarily restored for exclusive execution. This
/// private value is created only after authenticated native restoration and is
/// consumed by the subsequent revoke/rebind transaction. It authorizes no second
/// execution, no provider invocation, and no independent source mutation.
pub(super) struct OriginalWindow {
    pc: u64,
    original: Vec<u8>,
    generation: u64,
    entry_version: u64,
}

/// A completed real revoke/restore transaction. It cannot be cloned or
/// constructed outside this module and is consumed by finish_rebind.
pub(super) struct RevokedDomain {
    generation: u64,
    entry_version: u64,
}

fn expected_with_window(
    domain: &Domain,
    image: &crate::gate::domain::Image,
    window: Option<&OriginalWindow>,
) -> Result<Vec<u8>, GateError> {
    let mut expected = domain.expected_image(image);
    if let Some(window) = window {
        if window.generation != domain.generation
            || window.entry_version != domain.entry_version
            || domain.original_decode(window.pc)? != window.original
        {
            return Err(GateError::Refused(
                "dynamic original-execution window is stale",
            ));
        }
        if image.snapshot.range().contains(window.pc) {
            let offset = (window.pc - image.mapping.start) as usize;
            let end = offset
                .checked_add(window.original.len())
                .filter(|end| *end <= expected.len())
                .ok_or(GateError::Refused(
                    "dynamic original execution crosses image identity",
                ))?;
            expected[offset..end].copy_from_slice(&window.original);
        }
    }
    Ok(expected)
}

/// Restore a whole selected/collateral decode under actual exclusion, then end
/// publication authority before its separate original-execution permit is used.
/// Sibling tasks stay held. The interlock must retain the returned window until
/// successful revoke/rearm or complete physical cleanup.
pub(super) fn restore_original(
    held: &mut super::super::publication::HeldMmStop<'_>,
    domain: &Domain,
    pc: u64,
    original: &[u8],
    until: Instant,
) -> Result<OriginalWindow, GateError> {
    authenticate_source(held, domain)?;
    if domain.original_decode(pc)? != original || !domain.guards.contains_key(&pc) {
        return Err(GateError::Refused(
            "dynamic original execution lacks its whole owned head guard",
        ));
    }
    let end = pc
        .checked_add(original.len() as u64)
        .ok_or(GateError::Refused("dynamic original instruction overflows"))?;
    let pages = BTreeSet::from([pc & !(PAGE - 1), (end - 1) & !(PAGE - 1)]);
    if pages
        .iter()
        .any(|page| domain.pages.get(page) != Some(&true))
    {
        return Err(GateError::Refused(
            "dynamic original execution dependency is not admitted",
        ));
    }
    let expected = domain.expected_instruction(pc, original);
    for &page in &pages {
        held.mprotect(
            page,
            PAGE as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            super::control_remaining(until)?,
        )?;
    }
    // Every intersecting head guard in a prefix/operand is restored too. The
    // complete decode, not only its first byte, must execute original semantics.
    held.write_memory_checked(pc, &expected, original)?;
    held.sync_core(super::control_remaining(until)?)?;
    if held.read_memory(pc, original.len())? != original {
        return Err(GateError::Refused(
            "dynamic original instruction restoration differs",
        ));
    }
    for &page in &pages {
        held.mprotect(
            page,
            PAGE as usize,
            domain.protection(page, true)?,
            super::control_remaining(until)?,
        )?;
    }
    held.sync_core(super::control_remaining(until)?)?;
    if held.read_memory(pc, original.len())? != original {
        return Err(GateError::Refused(
            "dynamic restored original changed before execution",
        ));
    }
    Ok(OriginalWindow {
        pc,
        original: original.to_vec(),
        generation: domain.generation,
        entry_version: domain.entry_version,
    })
}

/// Revoke the entire finite original domain and restore every installed edit.
/// Old metadata remains available until complete readback and sync succeed.
/// Caller reserves its generation/history/source budget before entering here.
pub(super) fn revoke_all(
    held: &mut super::super::publication::HeldMmStop<'_>,
    domain: &mut Domain,
    window: Option<OriginalWindow>,
    until: Instant,
) -> Result<RevokedDomain, GateError> {
    domain.audit_history()?;
    if held.membership().generation != domain.generation {
        return Err(GateError::Refused(
            "dynamic revocation has another native generation",
        ));
    }
    domain
        .generations
        .try_reserve(1)
        .map_err(|_| GateError::Refused("dynamic generation history allocation failed"))?;
    for image in &domain.images {
        let expected = expected_with_window(domain, image, window.as_ref())?;
        if held.read_memory(image.mapping.start, expected.len())? != expected {
            return Err(GateError::Refused(
                "dynamic old armed source changed before revocation",
            ));
        }
    }
    for &page in domain.pages.keys() {
        held.mprotect(
            page,
            PAGE as usize,
            domain.protection(page, false)?,
            super::control_remaining(until)?,
        )?;
    }
    held.sync_core(super::control_remaining(until)?)?;
    // All original source is now NX. Retained installed metadata is still the
    // authority for matching old live bytes, including an in-flight restoration.
    for image in &domain.images {
        let expected = expected_with_window(domain, image, window.as_ref())?;
        if expected != image.snapshot.bytes() {
            held.mprotect(
                image.mapping.start,
                image.snapshot.bytes().len(),
                libc::PROT_READ | libc::PROT_WRITE,
                super::control_remaining(until)?,
            )?;
            held.write_memory_checked(image.mapping.start, &expected, image.snapshot.bytes())?;
            held.mprotect(
                image.mapping.start,
                image.snapshot.bytes().len(),
                domain.protection(image.mapping.start, false)?,
                super::control_remaining(until)?,
            )?;
        }
        if held.read_memory(image.mapping.start, image.snapshot.bytes().len())?
            != image.snapshot.bytes()
        {
            return Err(GateError::Refused(
                "dynamic revoked source did not restore to original bytes",
            ));
        }
    }
    held.sync_core(super::control_remaining(until)?)?;
    let maps = held.mappings();
    for &page in domain.pages.keys() {
        if !maps.iter().any(|map| {
            map.start <= page
                && page + PAGE <= map.end
                && map.permissions.as_bytes().get(2) == Some(&b'-')
                && map.permissions.as_bytes().get(1) == Some(&b'-')
                && map.permissions.as_bytes().get(3) == Some(&b'p')
        }) {
            return Err(GateError::Refused(
                "dynamic revoked page is not private immutable NX",
            ));
        }
    }
    let retired = super::domain::RetiredGeneration {
        generation: domain.generation,
        entry_version: domain.entry_version,
        source_binding: domain.source_binding,
        executable_pages: domain.executable_pages(),
        guards: std::mem::take(&mut domain.guards),
        sites: std::mem::take(&mut domain.sites),
    };
    domain.generations.push(retired);
    domain.pages.values_mut().for_each(|value| *value = false);
    Ok(RevokedDomain {
        generation: domain.generation,
        entry_version: domain.entry_version,
    })
}

/// Bind staged entry facts only after the native registry has advanced the
/// actually revoked mm. Historical plans, guards and CALL source facts remain.
pub(super) fn finish_rebind(
    revoked: RevokedDomain,
    domain: &mut Domain,
    held: &super::super::publication::HeldMmStop<'_>,
    images: Vec<crate::gate::domain::Image>,
    census: &ResumeCensus,
) -> Result<(), GateError> {
    let generation = revoked
        .generation
        .checked_add(1)
        .ok_or(GateError::Refused("dynamic source generation exhausted"))?;
    let version = revoked
        .entry_version
        .checked_add(1)
        .ok_or(GateError::Refused("dynamic entry version exhausted"))?;
    if domain.generation != revoked.generation
        || domain.entry_version != revoked.entry_version
        || held.membership().generation != generation
        || census.generation() != generation
        || images.len() != domain.images.len()
        || domain.pages.values().any(|executable| *executable)
        || !domain.guards.is_empty()
        || !domain.sites.is_empty()
    {
        return Err(GateError::Refused(
            "dynamic native generation rebind is not exact",
        ));
    }
    for (old, new) in domain.images.iter().zip(&images) {
        if old.mapping != new.mapping
            || old.snapshot.mapping != new.snapshot.mapping
            || old.snapshot.bytes() != new.snapshot.bytes()
            || new.snapshot.generation != liteinst_admission::Generation(generation)
            || new.entries.generation() != new.snapshot.generation
            || new.entries.version() != version
            || old.entries.heads() != new.entries.heads()
            || old.entries.completeness() != new.entries.completeness()
            || old.entries.scope() != new.entries.scope()
        {
            return Err(GateError::Refused(
                "dynamic rebound original image or entries differ",
            ));
        }
        if held.read_memory(new.mapping.start, new.snapshot.bytes().len())? != new.snapshot.bytes()
        {
            return Err(GateError::Refused(
                "dynamic original bytes changed during generation rebind",
            ));
        }
    }
    census
        .validate_projection(
            &images
                .iter()
                .map(|image| image.entries.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(refuse_census)?;
    domain.images = images;
    domain.generation = generation;
    domain.entry_version = version;
    domain.audit_history()?;
    authenticate_source(held, domain)
}

// A release seal retains the actual held observations and immutable planning
// facts until the single consuming release. It does not turn a model candidate
// or an installed receipt into native authority. Construction requires the real
// borrowed HeldMmStop; release repeats every native check before its first
// ptrace resume. The owner remains on its original tracer thread throughout.
pub(super) struct ReleaseBatch<'facts> {
    domain: &'facts Domain,
    census: &'facts ResumeCensus,
    membership: super::super::lifecycle::admission::MmMembership,
    tasks: Vec<ReleaseTask>,
    routes: Vec<ResolvedRoute>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReleasePhase {
    Private(super::super::trusted::AdmissionStop),
    Generic(DynamicEvent),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReleaseTask {
    observation: super::census::ObservedStop,
    state: super::super::trusted::TaskStateSnapshot,
    phase: ReleasePhase,
    ready: bool,
}

fn same_release_membership(
    left: &super::super::lifecycle::admission::MmMembership,
    right: &super::super::lifecycle::admission::MmMembership,
) -> bool {
    left.address_space == right.address_space
        && left.generation == right.generation
        && left.process == right.process
        && left.tgid == right.tgid
        && left.tids == right.tids
        && left.candidate == right.candidate
}

/// Re-read the complete original/armed byte layer and real page permissions.
/// The caller authenticated this TID's retained incarnation and held status
/// before either proc read. No cached Boolean or numeric TID lookup is a pin.
fn authenticate_release_source(tid: i32, domain: &Domain) -> Result<(), GateError> {
    for image in &domain.images {
        let expected = domain.expected_image(image);
        if crate::linux::read_memory(tid, image.mapping.start, expected.len())? != expected {
            return Err(GateError::Refused(
                "dynamic release source or installed guard bytes changed",
            ));
        }
    }
    let maps = crate::linux::read_maps(tid)?;
    for (&page, &executable) in &domain.pages {
        let end = page
            .checked_add(PAGE)
            .ok_or(GateError::Refused("dynamic release page range overflows"))?;
        let mapping = maps
            .iter()
            .find(|map| map.start <= page && end <= map.end)
            .ok_or(GateError::Refused(
                "dynamic release original page mapping changed",
            ))?;
        let permissions = mapping.permissions.as_bytes();
        if permissions.get(3) != Some(&b'p')
            || permissions.get(1) == Some(&b'w')
            || (permissions.get(2) == Some(&b'x')) != executable
        {
            return Err(GateError::Refused(
                "dynamic release original page permissions changed",
            ));
        }
    }
    Ok(())
}

/// Necessary native and semantic checks shared by sealing and the final
/// pre-release pass. This function never resumes, mutates source, changes a
/// generation or retires an origin/CALL record.
fn release_view(
    owner: &super::super::Owner,
    native: &super::super::lifecycle::NativeLifecycle,
    domain: &Domain,
    census: &ResumeCensus,
    selected: crate::lifecycle::TaskId,
    ready: &BTreeSet<crate::lifecycle::TaskId>,
) -> Result<
    (
        super::super::lifecycle::admission::MmMembership,
        Vec<ReleaseTask>,
        Vec<ResolvedRoute>,
    ),
    GateError,
> {
    if owner.closing || owner.cancel.load(std::sync::atomic::Ordering::Acquire) {
        return Err(GateError::Refused("dynamic release owner is closing"));
    }
    domain.audit_history()?;
    let membership = native.check_admission_mm(owner, selected)?;
    let members = membership
        .candidate
        .tasks
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if members.len() != membership.candidate.tasks.len()
        || membership.generation != domain.generation
        || census.generation() != domain.generation
        || !ready.is_subset(&members)
    {
        return Err(GateError::Refused(
            "dynamic release membership or obligations differ",
        ));
    }
    census
        .check_signal_obligations(&membership.candidate.obligations)
        .map_err(refuse_census)?;
    census
        .validate_projection(
            &domain
                .images
                .iter()
                .map(|image| image.entries.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(refuse_census)?;

    let executable = domain.executable_pages();
    let mut tasks = Vec::new();
    let mut routes = Vec::new();
    let mut covered_origins = BTreeSet::new();
    for &task in &membership.candidate.tasks {
        let token = native.admission_held_token(task)?;
        if token.session != owner.session || token.task != Some(task) {
            return Err(GateError::Refused(
                "dynamic release token belongs to another owner",
            ));
        }
        let state = super::super::trusted::TaskStateSnapshot::read(token.tid)?;
        let phase = match native.admission_current(task) {
            Ok(stop) => {
                native.require_admission_stop(&stop)?;
                ReleasePhase::Private(stop)
            }
            Err(_) => ReleasePhase::Generic(native.admission_held_event(task)?),
        };
        let mut observation = None;
        for active in census
            .active()
            .filter(|active| active.current.task.task == task)
        {
            if matches!(active.row.kind, OriginKind::UnknownPersistent { .. }) {
                return Err(GateError::Refused(
                    "dynamic release retains an unknown saved context",
                ));
            }
            let frame = check_origin(census, active, &token)?;
            if active.current.token != token
                || active.current.task.address_space != membership.address_space
                || active.current.task.process != membership.process
                || active.current.task.generation != membership.generation
                || active.current.registers != state.registers
                || active.current.xstate != state.xstate
                || active.current.signal_mask != state.mask
            {
                return Err(GateError::Refused(
                    "dynamic release origin is not its exact held native state",
                ));
            }
            if observation
                .as_ref()
                .is_some_and(|old| old != active.current)
            {
                return Err(GateError::Refused(
                    "dynamic release origins disagree about one current task",
                ));
            }
            observation = Some(active.current.clone());
            if !covered_origins.insert(active.row.id) {
                return Err(GateError::Refused(
                    "dynamic release origin identity is duplicated",
                ));
            }
            let (original, route) =
                whole_route(domain, active.row.pc, &executable, &domain.guards)?;
            routes.push(ResolvedRoute {
                origin: RouteOrigin::Census {
                    id: active.row.id,
                    task: active.current.task,
                    token: token.clone(),
                    frame,
                },
                pc: active.row.pc,
                original,
                route,
                generation: domain.generation,
                entry_version: domain.entry_version,
                plan: 0,
            });
        }
        let observation = observation.ok_or(GateError::Refused(
            "dynamic release census omits a held task",
        ))?;
        match &phase {
            ReleasePhase::Private(stop)
                if stop.token == token && stop.identity == observation.task => {}
            ReleasePhase::Generic(event)
                if event.stop_token() == Some(&token) && event.task == Some(observation.task) => {}
            _ => {
                return Err(GateError::Refused(
                    "dynamic release native phase identity differs",
                ));
            }
        }
        let is_ready = ready.contains(&task);
        if is_ready {
            // A raw source INT3 has RIP=head+1. It cannot be resumed as if the
            // original head had been restored merely by choosing a logical PC.
            if state.registers.rip != observation.logical_pc {
                return Err(GateError::Refused(
                    "dynamic ready task has not restored its original logical PC",
                ));
            }
            if let ReleasePhase::Generic(event) = &phase {
                let actual = native.admission_original_interrupt(task)?;
                let status = owner.stopped.get(&token.tid).ok_or(GateError::Refused(
                    "dynamic ready interruption lacks its owned wait status",
                ))?;
                if actual != *event
                    || !matches!(event.kind, DynamicEventKind::Interrupted)
                    || observation.phase != super::census::StopPhase::Interrupted
                    || observation.signal.is_some()
                    || !libc::WIFSTOPPED(*status)
                    || libc::WSTOPSIG(*status) != libc::SIGTRAP
                    || *status >> 16 != libc::PTRACE_EVENT_STOP
                {
                    return Err(GateError::Refused(
                        "dynamic generic ready phase is not an exact user interruption",
                    ));
                }
            }
        }
        tasks.push(ReleaseTask {
            observation,
            state,
            phase,
            ready: is_ready,
        });
    }
    if covered_origins.len() != census.active().count() {
        return Err(GateError::Refused(
            "dynamic release census contains an unheld or foreign origin",
        ));
    }

    // Every retained caller generation remains relevant. A return to any X
    // page needs the complete current decode/guard route, even when its caller
    // or the destination's earlier admission is outside the latest plan.
    // Returns to NX or uncensused pages remain in the append-only ledger; they
    // are not discarded or treated as evidence that the CALL never executed.
    for call in domain.returns.obligations() {
        if domain.pages.get(&(call.return_pc & !(PAGE - 1))) == Some(&true) {
            let (original, route) =
                whole_route(domain, call.return_pc, &executable, &domain.guards)?;
            routes.push(ResolvedRoute {
                origin: RouteOrigin::Call {
                    obligation: call.clone(),
                    planned: false,
                },
                pc: call.return_pc,
                original,
                route,
                generation: domain.generation,
                entry_version: domain.entry_version,
                plan: 0,
            });
        }
    }
    let tid = native.admission_held_token(selected)?.tid;
    authenticate_release_source(tid, domain)?;
    Ok((membership, tasks, routes))
}

/// Validate the entire held mm before authorizing any subset to run. An empty
/// ready set gives the dispatcher the same read-only proof for preparing a
/// selected callback; it cannot subsequently produce an empty release.
///
/// Domain/census borrows keep the exact generation, entry projection, original
/// snapshots, installed guards and append-only CALL history immutable until the
/// batch is dropped or consumed. The held native borrow establishes the actual
/// exclusion at construction; no public Boolean or model token is accepted.
pub(super) fn check_release<'facts>(
    held: &super::super::publication::HeldMmStop<'_>,
    domain: &'facts Domain,
    census: &'facts ResumeCensus,
    ready: &BTreeSet<crate::lifecycle::TaskId>,
) -> Result<ReleaseBatch<'facts>, GateError> {
    let selected = held.selected_token()?.task.ok_or(GateError::Refused(
        "dynamic release selected token has no task identity",
    ))?;
    let (membership, tasks, routes) =
        release_view(held.owner, held.native, domain, census, selected, ready)?;
    if !same_release_membership(&membership, held.membership()) {
        return Err(GateError::Refused(
            "dynamic release native hold changed during sealing",
        ));
    }
    Ok(ReleaseBatch {
        domain,
        census,
        membership,
        tasks,
        routes,
        _thread: std::marker::PhantomData,
    })
}

impl ReleaseBatch<'_> {
    /// Exact before-state for one RunPermit per task that this batch will
    /// actually release. This iterator grants no permission to execute itself.
    pub(super) fn ready_observations(&self) -> impl Iterator<Item = &super::census::ObservedStop> {
        self.tasks
            .iter()
            .filter(|task| task.ready)
            .map(|task| &task.observation)
    }

    /// Consume this one-use seal on the same native owner after dropping the
    /// borrowed publication hold. No source/registry mutation is allowed between
    /// the final all-task validation and the first resume. The closed dispatcher
    /// and constructor contract exclude outside writers and unguarded lifecycle
    /// or mapping syscalls throughout the sequential releases.
    pub(super) fn release(
        self,
        owner: &mut super::super::Owner,
        native: &mut super::super::lifecycle::NativeLifecycle,
        until: Instant,
    ) -> Result<(), GateError> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.time_left(until, "dynamic group release")?;
            let ready = self
                .tasks
                .iter()
                .filter(|task| task.ready)
                .map(|task| task.observation.task.task)
                .collect::<BTreeSet<_>>();
            if ready.is_empty() {
                return Err(GateError::Refused(
                    "dynamic group release has no ready tasks",
                ));
            }
            let selected = self
                .tasks
                .first()
                .ok_or(GateError::Refused(
                    "dynamic group release has no held tasks",
                ))?
                .observation
                .task
                .task;
            let (membership, tasks, routes) =
                release_view(owner, native, self.domain, self.census, selected, &ready)?;
            if !same_release_membership(&membership, &self.membership)
                || tasks != self.tasks
                || routes != self.routes
            {
                return Err(GateError::Refused("dynamic group release seal is stale"));
            }
            owner.time_left(until, "dynamic group release")?;
            // All tasks and routes have passed together. Once the first task is
            // running a fresh whole-mm hold is unavailable; do not try to obtain
            // one between releases or treat a per-task check as replacement.
            for task in &self.tasks {
                if !task.ready {
                    continue;
                }
                owner.time_left(until, "dynamic group release")?;
                // SAFETY: this seal was minted under the actual whole-mm hold
                // and reauthenticated above with exact state/source/routes for
                // every member. Only the closed, fully guarded original-user
                // path is released; no syscall or application signal disposition
                // is accepted here. The immutable domain borrows and owner-thread
                // interlock preserve the complete proof during this batch.
                unsafe {
                    match &task.phase {
                        ReleasePhase::Private(stop) => native.release_admitted(owner, stop)?,
                        ReleasePhase::Generic(event) => native.resume_admission_event(
                            owner,
                            event
                                .stop_token()
                                .ok_or(GateError::Refused("sealed ready event lost its token"))?,
                            DynamicResume::Continue,
                        )?,
                    }
                }
            }
            Ok(())
        }));
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                owner.closing = true;
                owner
                    .cancel
                    .store(true, std::sync::atomic::Ordering::Release);
                Err(error)
            }
            Err(_) => {
                owner.closing = true;
                owner
                    .cancel
                    .store(true, std::sync::atomic::Ordering::Release);
                Err(GateError::Refused("dynamic group release panicked"))
            }
        }
    }
}
