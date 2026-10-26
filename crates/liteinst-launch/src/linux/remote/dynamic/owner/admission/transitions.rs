//! Native observations, append-only continuation transitions and pre-effect
//! resource envelopes. No model observation is an execution or publication
//! permit: the actual owner and whole-mm hold authenticate every native step.
use super::super::trusted::{self, StateTransform, TrapExpectation};
use super::census::{OwnerConsumption, Reservation};
use super::*;
use crate::gate::domain::{PAGE, PendingAdmission};
use crate::lifecycle::TaskState;
use crate::trap_coverage::{TrapCoverageBudget, TrapGuard};
use liteinst_admission::entries::LegalEntrySet;
use liteinst_admission::scan::{Candidate, Obligation, ScanReport, Snapshot};
use std::mem::size_of;

const MAX_TASKS: usize = 2;
const MAX_XSTATE: usize = 64 * 1024;
// A logical entry fact includes its key, provenance/kind, and map/set metadata.
// This is retained evidence accounting, not a claim about allocator capacity.
const ENTRY_FACT_BYTES: usize = 64;
const INSTRUCTION_BYTES: usize = 15;

fn overflow() -> GateError {
    GateError::Refused("dynamic transition evidence size overflows")
}
fn add(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_mul(b).ok_or_else(overflow)
}
fn total(values: impl IntoIterator<Item = usize>) -> Result<usize, GateError> {
    values.into_iter().try_fold(0, add)
}
fn combine(a: BudgetCharge, b: BudgetCharge) -> Result<BudgetCharge, GateError> {
    Ok(BudgetCharge {
        epochs: add(a.epochs, b.epochs)?,
        source_fact_bytes: add(a.source_fact_bytes, b.source_fact_bytes)?,
        reports: add(a.reports, b.reports)?,
        origins: add(a.origins, b.origins)?,
        witnesses: add(a.witnesses, b.witnesses)?,
        plan_history: add(a.plan_history, b.plan_history)?,
    })
}
fn state_bound() -> Result<usize, GateError> {
    add(size_of::<ObservedStop>(), MAX_XSTATE)
}
fn refresh_charge(count: usize) -> Result<BudgetCharge, GateError> {
    // Two history snapshots plus possible growth of the separately retained
    // current XSTATE. Shrinking a later state never refunds this reservation.
    let one = total([
        mul(2, state_bound()?)?,
        MAX_XSTATE,
        size_of::<census::HistoryRecord>(),
    ])?;
    Ok(BudgetCharge {
        witnesses: count,
        source_fact_bytes: mul(count, one)?,
        ..BudgetCharge::default()
    })
}
fn origin_bound() -> Result<usize, GateError> {
    total([
        mul(2, state_bound()?)?,
        size_of::<census::OriginRow>(),
        size_of::<ObservedStop>(),
        64,
    ])
}
fn consume_bound() -> Result<usize, GateError> {
    // CompletedKernel retains before/entry/parent/newborn in addition to the
    // generic before/successor, typed input and complete instruction bytes.
    total([
        mul(8, state_bound()?)?,
        size_of::<OwnerConsumption>(),
        size_of::<census::HistoryRecord>(),
        1024,
    ])
}
fn entry_facts(entries: &LegalEntrySet) -> Result<(usize, usize), GateError> {
    Ok((
        entries
            .heads()
            .values()
            .try_fold(0, |sum, kinds| add(sum, kinds.len()))?,
        entries
            .resumes()
            .values()
            .try_fold(0, |sum, kinds| add(sum, kinds.len()))?,
    ))
}
fn facts_bytes(bytes: usize, heads: usize, resumes: usize) -> Result<usize, GateError> {
    total([
        bytes,
        size_of::<Snapshot>(),
        size_of::<LegalEntrySet>(),
        mul(add(heads, resumes)?, ENTRY_FACT_BYTES)?,
    ])
}

/// One monotone sizing function serves both the pre-effect upper bound and
/// actual completed geometry. Reports retain complete source/entry facts;
/// prospective CALL source rows are charged separately before ledger append.
#[derive(Default)]
struct PlanShape {
    facts: usize,
    reports: usize,
    report_facts: usize,
    candidates: usize,
    obligations: usize,
    resolutions: usize,
    resolution_guards: usize,
    pages: usize,
    dependencies: usize,
    guards: usize,
    installed_guards: usize,
    decoded: usize,
    resumes: usize,
    resume_kinds: usize,
    calls: usize,
    callers: usize,
    source_records: usize,
    source_bytes: usize,
    source_heads: usize,
    source_resumes: usize,
    routes: usize,
}
impl PlanShape {
    fn charge(&self) -> Result<BudgetCharge, GateError> {
        let guard = total([size_of::<TrapGuard>(), INSTRUCTION_BYTES, size_of::<u64>()])?;
        let call = add(
            size_of::<crate::gate::domain::CallRouteRequirement>(),
            INSTRUCTION_BYTES,
        )?;
        let bytes = total([
            size_of::<super::domain::InstalledPlan>(),
            size_of::<PendingAdmission>(),
            self.facts,
            256,
            // GateOracle may retain another immutable report. Conservatively
            // charge both copies regardless of cache hits or eventual eviction.
            mul(
                2,
                total([
                    mul(self.reports, size_of::<ScanReport>() + 256)?,
                    self.report_facts,
                    mul(self.candidates, size_of::<Candidate>())?,
                    mul(self.obligations, size_of::<Obligation>())?,
                ])?,
            )?,
            mul(
                self.resolutions,
                size_of::<crate::trap_coverage::ResolvedTrapObligation>(),
            )?,
            mul(self.resolution_guards, size_of::<u64>())?,
            mul(self.pages, size_of::<u64>())?,
            mul(
                self.dependencies,
                size_of::<liteinst_admission::AddressRange>(),
            )?,
            mul(add(self.guards, self.installed_guards)?, guard)?,
            mul(
                self.decoded,
                size_of::<(u64, Vec<u8>)>() + INSTRUCTION_BYTES,
            )?,
            mul(self.resumes, 128)?,
            mul(
                self.resume_kinds,
                size_of::<liteinst_admission::entries::ResumeKind>(),
            )?,
            mul(self.calls, call)?,
            mul(self.callers, size_of::<liteinst_admission::AddressRange>())?,
            mul(self.source_records, 256)?,
            self.source_bytes,
            mul(
                add(self.source_heads, self.source_resumes)?,
                ENTRY_FACT_BYTES,
            )?,
            mul(
                self.routes,
                size_of::<routes::ResolvedRoute>() + 2 * INSTRUCTION_BYTES,
            )?,
        ])?;
        Ok(BudgetCharge {
            source_fact_bytes: bytes,
            reports: self.reports,
            plan_history: 1,
            ..BudgetCharge::default()
        })
    }
}

fn image_facts_bound(
    domain: &super::domain::Domain,
    active_origins: usize,
    extra_origins: usize,
) -> Result<(usize, usize, usize), GateError> {
    let mut bytes = 0;
    let mut heads = 0;
    let mut resumes = add(active_origins, extra_origins)?;
    for image in &domain.images {
        bytes = add(bytes, image.snapshot.bytes().len())?;
        let (h, r) = entry_facts(&image.entries)?;
        heads = add(heads, h)?;
        resumes = add(resumes, r)?;
    }
    Ok((bytes, heads, resumes))
}

fn plan_upper_bound(
    domain: &super::domain::Domain,
    active_origins: usize,
    extra_origins: usize,
) -> Result<BudgetCharge, GateError> {
    let (bytes, heads, resumes) = image_facts_bound(domain, active_origins, extra_origins)?;
    let budget = match domain.backend {
        DynamicAdmissionBackend::StrictTrap => TrapCoverageBudget::default(),
        DynamicAdmissionBackend::CoverageTrap(budget) => budget,
    };
    // One original report per distinct scanned page, never a flat fixture
    // constant. Strict planning can scan the entire supplied image domain.
    let reports = domain.pages.len();
    let source_candidates = domain.source_candidate_bound()?;
    // Coverage adds only selected starts or declared containing heads.
    // Count each page's retained candidates separately: a cross-page
    // instruction can occur in both reports through the leading halo.
    let guards = add(source_candidates, heads)?.min(budget.max_guards);
    let decoded = add(heads, guards)?;
    let candidates = mul(reports, source_candidates)?;
    let obligations = add(candidates, mul(reports, total([heads, resumes, 6])?)?)?;
    let resume_requirements = mul(resumes, add(reports, 1)?)?;
    let old_calls = domain.returns.obligations().count();
    let calls = add(old_calls, mul(2, heads)?)?;
    PlanShape {
        facts: facts_bytes(bytes, heads, resumes)?,
        reports,
        report_facts: mul(reports, facts_bytes(bytes, heads, resumes)?)?,
        candidates,
        obligations,
        resolutions: obligations,
        resolution_guards: mul(obligations, INSTRUCTION_BYTES)?,
        pages: reports,
        dependencies: add(reports, decoded)?,
        guards,
        installed_guards: domain.guards.len(),
        decoded,
        resumes: resume_requirements,
        resume_kinds: mul(resume_requirements, 4)?,
        calls,
        callers: reports,
        source_records: reports,
        source_bytes: mul(reports, bytes)?,
        source_heads: mul(reports, heads)?,
        source_resumes: mul(reports, resumes)?,
        routes: add(add(active_origins, extra_origins)?, calls)?,
    }
    .charge()
}

fn actual_plan_charge(
    plan: &PendingAdmission,
    active_origins: usize,
) -> Result<BudgetCharge, GateError> {
    let (heads, resumes) = entry_facts(plan.entries())?;
    let source = plan.planned_source_footprint();
    let mut shape = PlanShape {
        facts: facts_bytes(plan.snapshot().bytes().len(), heads, resumes)?,
        reports: plan.reports().len(),
        pages: plan.pages().len(),
        dependencies: plan.dependencies().len(),
        guards: plan.guards().len(),
        installed_guards: plan.installed_guards().len(),
        decoded: plan.decoded_heads().len(),
        resumes: plan.resume_requirements().len(),
        calls: add(plan.call_requirements().len(), plan.planned_calls().len())?,
        callers: plan.planned_callers().len(),
        source_records: source.records,
        source_bytes: source.snapshot_bytes,
        source_heads: source.head_facts,
        source_resumes: source.resume_facts,
        routes: total([
            active_origins,
            plan.call_requirements().len(),
            plan.planned_calls().len(),
        ])?,
        ..PlanShape::default()
    };
    for report in plan.reports() {
        let (heads, resumes) = entry_facts(report.entries())?;
        shape.report_facts = add(
            shape.report_facts,
            facts_bytes(report.snapshot().bytes().len(), heads, resumes)?,
        )?;
        shape.candidates = add(shape.candidates, report.candidates().len())?;
        shape.obligations = add(shape.obligations, report.obligations().len())?;
    }
    for resume in plan.resume_requirements() {
        shape.resume_kinds = add(shape.resume_kinds, resume.kinds().len())?;
    }
    if let Some(coverage) = plan.coverage() {
        shape.resolutions = coverage.resolutions().len();
        for resolution in coverage.resolutions() {
            shape.resolution_guards = add(shape.resolution_guards, resolution.guards.len())?;
        }
    }
    shape.charge()
}

/// Pure size bound only. Native callers must first authenticate the complete
/// held-mm set and its exact current census records. A larger successor count
/// reserves a possible child; it never authorizes creation or any native effect.
fn checked_task_bound(
    actual: &[DynamicTask],
    retained: &[DynamicTask],
    successors: usize,
) -> Result<usize, GateError> {
    if actual.is_empty()
        || actual.len() > MAX_TASKS
        || retained.len() > MAX_TASKS
        || successors > MAX_TASKS
    {
        return Err(GateError::Refused(
            "dynamic task bound exceeds finite membership",
        ));
    }
    let actual_set = actual
        .iter()
        .map(|task| (task.task, *task))
        .collect::<BTreeMap<_, _>>();
    let retained_set = retained
        .iter()
        .map(|task| (task.task, *task))
        .collect::<BTreeMap<_, _>>();
    let first = actual[0];
    if actual_set.len() != actual.len()
        || retained_set.len() != retained.len()
        || actual_set != retained_set
        || actual.iter().any(|task| {
            task.process != first.process
                || task.address_space != first.address_space
                || task.generation != first.generation
        })
    {
        return Err(GateError::Refused(
            "dynamic task bound differs from retained membership",
        ));
    }
    Ok(actual.len().max(successors))
}

fn rebind_charge(
    domain: &super::domain::Domain,
    active_origins: usize,
    extra_origins: usize,
    tasks: usize,
) -> Result<BudgetCharge, GateError> {
    let (bytes, heads, resumes) = image_facts_bound(domain, active_origins, extra_origins)?;
    let mapping_strings = domain.images.iter().try_fold(0, |sum, image| {
        add(
            sum,
            add(
                image.mapping.permissions.len(),
                image.mapping.pathname.as_ref().map_or(0, String::len),
            )?,
        )
    })?;
    let retained = total([
        facts_bytes(bytes, heads, resumes)?,
        mul(domain.images.len(), size_of::<crate::gate::domain::Image>())?,
        mapping_strings,
        size_of::<super::domain::RetiredGeneration>(),
        size_of::<census::HistoryRecord>(),
        mul(domain.pages.len(), size_of::<u64>())?,
        mul(
            domain.guards.len(),
            size_of::<TrapGuard>() + INSTRUCTION_BYTES,
        )?,
        mul(domain.sites.len(), size_of::<Candidate>())?,
    ])?;
    combine(
        BudgetCharge {
            epochs: 1,
            source_fact_bytes: retained,
            ..BudgetCharge::default()
        },
        refresh_charge(2 * tasks)?,
    )
}

fn effect_charge(
    domain: &super::domain::Domain,
    active_origins: usize,
    tasks: usize,
    successors: usize,
    rebind: bool,
    plans: usize,
) -> Result<BudgetCharge, GateError> {
    if tasks == 0 || tasks > MAX_TASKS || successors > tasks || plans > 1 {
        return Err(GateError::Refused(
            "dynamic transition exceeds finite task or plan shape",
        ));
    }
    let mut charge = BudgetCharge::default();
    if successors != 0 {
        charge.origins = successors;
        charge.witnesses = successors;
        charge.source_fact_bytes = mul(successors, add(origin_bound()?, consume_bound()?)?)?;
        // Full external completion, pending input, two event copies in
        // each diagnostic queue, and all scalar/owned-window metadata.
        charge.source_fact_bytes = add(
            charge.source_fact_bytes,
            total([
                mul(8, state_bound()?)?,
                mul(4, size_of::<DynamicEvent>())?,
                8192,
            ])?,
        )?;
        charge = combine(charge, refresh_charge(tasks)?)?;
    } else {
        charge.source_fact_bytes = total([state_bound()?, size_of::<PendingInvocation>(), 1024])?;
    }
    if rebind {
        charge = combine(
            charge,
            rebind_charge(domain, active_origins, successors, tasks)?,
        )?;
    }
    for _ in 0..plans {
        charge = combine(
            charge,
            plan_upper_bound(domain, active_origins, successors)?,
        )?;
        // Whole-mm settlement may happen before publish_page's planner,
        // even for a plan-only transaction. Together with the separate
        // held-mm prefix, reserve the bounded prepublication refresh slots
        // plus the whole-mm postpublication slots without relying on no-op debits.
        charge = combine(charge, refresh_charge(2 * tasks)?)?;
    }
    if successors != 0 {
        // Original release/completion: reconcile/normalize plus up to two
        // deferred interrupt stops and one actual NX fault or guard for
        // EACH authenticated task, before any affected page publication.
        // The at-most-six probes do not create origins or consume continuations.
        charge = combine(charge, refresh_charge(tasks + 3 * tasks)?)?;
        charge.source_fact_bytes = add(
            charge.source_fact_bytes,
            mul(
                tasks + 3 * tasks,
                add(state_bound()?, size_of::<RunPermit>() + INSTRUCTION_BYTES)?,
            )?,
        )?;
        // Each private task may need one neutral control-settling operation
        // before batch release; refreshes retain the real before/after,
        // never one fabricated row per internal kernel control stop.
        // One pass before revocation and another after real boundary
        // probes: a Fetch must become an actual neutral checkpoint even
        // when its interrupt-credit counter was already zero.
        charge = combine(charge, refresh_charge(2 * tasks * tasks)?)?;
    }
    Ok(charge)
}

impl AdmissionOwner {
    /// Re-read a current held incarnation. A raw instrumentation fault remains
    /// raw here; logical RIP does not silently change the register snapshot.
    pub(super) fn observe_current(
        &self,
        owner: &Owner,
        task: TaskId,
    ) -> Result<ObservedStop, GateError> {
        let token = self.native.admission_held_token(task)?;
        let snapshot = self.native.admission_snapshot();
        let record =
            snapshot
                .tasks()
                .find(|record| record.id == task)
                .ok_or(GateError::Refused(
                    "dynamic observation has no current task record",
                ))?;
        let space = snapshot
            .address_spaces()
            .find(|space| space.id == record.address_space)
            .ok_or(GateError::Refused(
                "dynamic observation has no address-space record",
            ))?;
        if token.session != owner.session
            || token.task != Some(task)
            || token.tid != record.tid
            || token.sequence != record.sequence
            || !matches!(record.state, TaskState::Held { .. })
            || record.address_space != self.island.address_space
            || space.generation != self.island.generation
            || space.poisoned
            || self.island.generation != self.census.generation()
            || !owner.owned.contains(&token.tid)
            || owner.handles.get(&token.tid).is_none_or(broker::hup)
        {
            return Err(GateError::Refused(
                "dynamic observation identity or ownership differs",
            ));
        }
        let status = *owner.stopped.get(&token.tid).ok_or(GateError::Refused(
            "dynamic observation has no owned held status",
        ))?;
        if !libc::WIFSTOPPED(status) {
            return Err(GateError::Refused(
                "dynamic observation is not a ptrace stop",
            ));
        }
        let raw = TaskStateSnapshot::read(token.tid)?;
        if raw.registers.cs != 0x33 || raw.xstate.is_empty() || raw.xstate.len() > MAX_XSTATE {
            return Err(GateError::Refused(
                "dynamic observation ABI or full XSTATE bound differs",
            ));
        }
        let identity = DynamicTask {
            task,
            process: record.process,
            address_space: record.address_space,
            generation: self.island.generation,
        };
        let (logical_pc, phase, signal) = match self.native.admission_current(task) {
            Ok(current) => {
                self.native.require_admission_stop(&current)?;
                if current.token != token || current.identity != identity {
                    return Err(GateError::Refused(
                        "dynamic private observation token differs",
                    ));
                }
                match current.phase {
                    AdmissionPhase::Fetch | AdmissionPhase::Guard => {
                        let pc = if current.phase == AdmissionPhase::Guard {
                            raw.registers.rip.checked_sub(1).ok_or_else(overflow)?
                        } else {
                            raw.registers.rip
                        };
                        let page = pc & !(PAGE - 1);
                        let original = self.domain.original_decode(pc)?;
                        let expectation = if current.phase == AdmissionPhase::Fetch {
                            if self.domain.pages.get(&page) != Some(&false) {
                                return Err(GateError::Refused(
                                    "dynamic fetch page is not retained NX",
                                ));
                            }
                            TrapExpectation::Fetch { pc, page }
                        } else {
                            let guard = self.domain.guards.get(&pc).ok_or(GateError::Refused(
                                "dynamic guard has no installed original decode",
                            ))?;
                            if guard.original_bytes() != original
                                || self.domain.pages.get(&page) != Some(&true)
                            {
                                return Err(GateError::Refused(
                                    "dynamic guard decode or executable page differs",
                                ));
                            }
                            TrapExpectation::Guard { address: pc }
                        };
                        let (authenticated, info, registers) =
                            trusted::authenticate_trap(owner, token.tid, status, expectation)?;
                        if authenticated != current.phase
                            || registers != raw.registers
                            || current.signal.as_ref().map(|signal| signal.raw) != Some(info)
                            || read_memory(token.tid, pc, original.len())?
                                != self.domain.expected_instruction(pc, &original)
                        {
                            return Err(GateError::Refused(
                                "dynamic original trap or armed instruction changed",
                            ));
                        }
                        (
                            pc,
                            if current.phase == AdmissionPhase::Fetch {
                                StopPhase::OwnedFetch
                            } else {
                                StopPhase::OwnedGuard
                            },
                            Some(DynamicSignalInfo { raw: info }),
                        )
                    }
                    AdmissionPhase::EntryReady
                    | AdmissionPhase::Restored
                    | AdmissionPhase::NativeCompleted => {
                        if status >> 16 != 0
                            || libc::WSTOPSIG(status) != libc::SIGTRAP
                            || current.signal.is_some()
                        {
                            return Err(GateError::Refused(
                                "dynamic private checkpoint has another signal phase",
                            ));
                        }
                        let mut info = [0_u8; 128];
                        ptrace(
                            libc::PTRACE_GETSIGINFO,
                            token.tid,
                            0,
                            info.as_mut_ptr() as usize,
                        )?;
                        let info = DynamicSignalInfo { raw: info };
                        let code_matches = if current.phase == AdmissionPhase::NativeCompleted {
                            info.code() == libc::TRAP_TRACE
                        } else {
                            matches!(info.code(), libc::SI_KERNEL | libc::TRAP_BRKPT)
                        };
                        if info.signal() != libc::SIGTRAP || !code_matches {
                            return Err(GateError::Refused(
                                "dynamic private checkpoint trap identity differs",
                            ));
                        }
                        // The phase owns the private trap, not an application
                        // signal. Its raw provenance is in native completion or
                        // bootstrap evidence; no pending signal is fabricated.
                        (raw.registers.rip, StopPhase::UserCheckpoint, None)
                    }
                }
            }
            Err(_) => {
                let event = self.native.admission_original_interrupt(task)?;
                if event.stop_token() != Some(&token)
                    || event.task != Some(identity)
                    || event.kind != DynamicEventKind::Interrupted
                    || status >> 16 != libc::PTRACE_EVENT_STOP
                    || libc::WSTOPSIG(status) != libc::SIGTRAP
                {
                    return Err(GateError::Refused(
                        "dynamic observation is not an authenticated original interruption",
                    ));
                }
                (raw.registers.rip, StopPhase::Interrupted, None)
            }
        };
        self.domain.original_decode(logical_pc)?;
        Ok(ObservedStop {
            token,
            task: identity,
            logical_pc,
            registers: raw.registers,
            xstate: raw.xstate,
            signal_mask: raw.mask,
            phase,
            signal,
        })
    }

    /// Authenticate the whole real held mm before shrinking a resource bound.
    /// The census is corroboration of the native set, never a stopped-task proof.
    pub(super) fn held_task_bound(
        &self,
        owner: &Owner,
        successors: usize,
    ) -> Result<usize, GateError> {
        if !self.running.is_empty() || !self.native.admission_events_empty() {
            return Err(GateError::Refused(
                "dynamic task bound has unresolved execution or events",
            ));
        }
        if self.domain.generation != self.census.generation() {
            return Err(GateError::Refused("dynamic task bound generation differs"));
        }
        let selected = *self.origins.keys().next().ok_or(GateError::Refused(
            "dynamic task bound has no retained held origin",
        ))?;
        let members = self.native.check_admission_mm(owner, selected)?;
        if members.generation != self.domain.generation {
            return Err(GateError::Refused(
                "dynamic task bound native generation differs",
            ));
        }
        let retained = self.census.active().take(MAX_TASKS + 1).collect::<Vec<_>>();
        if retained.len() > MAX_TASKS
            || self.origins.len() != retained.len()
            || retained
                .iter()
                .any(|origin| self.origins.get(&origin.current.task.task) != Some(&origin.row.id))
        {
            return Err(GateError::Refused(
                "dynamic task bound origin index differs",
            ));
        }
        let mut actual = Vec::new();
        for task in members.candidate.tasks {
            let observed = self.observe_current(owner, task)?;
            let origin = *self.origins.get(&task).ok_or(GateError::Refused(
                "dynamic task bound has an untracked native task",
            ))?;
            self.census
                .check_current_origin(origin, &observed)
                .map_err(census_error)?;
            actual.push(observed.task);
        }
        checked_task_bound(
            &actual,
            &retained
                .iter()
                .map(|origin| origin.current.task)
                .collect::<Vec<_>>(),
            successors,
        )
    }

    pub(super) fn reserve_transition(
        &mut self,
        owner: &Owner,
        successors: usize,
        rebind: bool,
        plans: usize,
    ) -> Result<Reservation, GateError> {
        // Restoration may use a runner before the actual completion. Reserve
        // that prefix separately so a second pre-effect check uses the same
        // complete remaining envelope after the prefix has been debited.
        let tasks = self.held_task_bound(owner, successors)?;
        let charge = combine(
            effect_charge(
                &self.domain,
                self.census.active().count(),
                tasks,
                successors,
                rebind,
                plans,
            )?,
            refresh_charge(tasks)?,
        )?;
        self.domain
            .plans
            .try_reserve(plans)
            .map_err(|_| GateError::Refused("dynamic plan reservation allocation failed"))?;
        self.domain
            .generations
            .try_reserve(usize::from(rebind))
            .map_err(|_| GateError::Refused("dynamic epoch reservation allocation failed"))?;
        self.census.reserve(charge).map_err(census_error)
    }

    pub(super) fn check_completion_budget(
        &self,
        owner: &Owner,
        reservation: Reservation,
        successors: usize,
        rebind: bool,
        plans: usize,
    ) -> Result<(), GateError> {
        let tasks = self.held_task_bound(owner, successors)?;
        self.census
            .check_reserved(
                reservation,
                effect_charge(
                    &self.domain,
                    self.census.active().count(),
                    tasks,
                    successors,
                    rebind,
                    plans,
                )?,
            )
            .map_err(census_error)
    }

    pub(super) fn account_plan(
        &mut self,
        owner: &Owner,
        reservation: Reservation,
        plan: &PendingAdmission,
    ) -> Result<(), GateError> {
        self.domain.validate_plan(plan)?;
        let tasks = self.held_task_bound(owner, 0)?;
        let charge = actual_plan_charge(plan, self.census.active().count())?;
        self.census
            .check_reserved(reservation, combine(charge, refresh_charge(tasks)?)?)
            .map_err(census_error)?;
        self.census
            .account_external(reservation, charge)
            .map_err(census_error)
    }

    pub(super) fn refresh_all_same_pc(
        &mut self,
        owner: &Owner,
        reservation: Reservation,
        selected: TaskId,
        until: Instant,
    ) -> Result<(), GateError> {
        owner.time_left(until, "dynamic admission census refresh")?;
        let members = self.native.check_admission_mm(owner, selected)?;
        let mut observations = Vec::new();
        for &task in &members.candidate.tasks {
            let actual = self.observe_current(owner, task)?;
            let id = *self
                .origins
                .get(&task)
                .ok_or(GateError::Refused("dynamic held task has no census origin"))?;
            let old = self
                .census
                .active()
                .find(|origin| origin.row.id == id)
                .ok_or(GateError::Refused(
                    "dynamic held origin is no longer active",
                ))?;
            if old.current.task.task != task || old.current.logical_pc != actual.logical_pc {
                return Err(GateError::Refused(
                    "dynamic private operation changed an original continuation",
                ));
            }
            observations.push((id, actual));
        }
        self.census
            .check_reserved(reservation, refresh_charge(observations.len())?)
            .map_err(census_error)?;
        for (id, actual) in observations {
            self.census
                .refresh_same_pc(reservation, id, actual)
                .map_err(census_error)?;
        }
        owner.time_left(until, "dynamic admission census refresh")?;
        Ok(())
    }

    pub(super) fn reconcile_running(
        &mut self,
        owner: &Owner,
        reservation: Reservation,
        task: TaskId,
        until: Instant,
    ) -> Result<(), GateError> {
        owner.time_left(until, "dynamic admission original progress")?;
        let actual = self.observe_current(owner, task)?;
        let origin = *self.origins.get(&task).ok_or(GateError::Refused(
            "dynamic running task has no retained origin",
        ))?;
        let before = self
            .census
            .active()
            .find(|row| row.row.id == origin)
            .ok_or(GateError::Refused(
                "dynamic running origin is no longer active",
            ))?
            .current
            .clone();
        if let Some(permit) = self.running.get(&task) {
            self.census
                .check_current_origin(origin, &permit.before)
                .map_err(census_error)?;
            if permit.before != before
                || self.domain.original_decode(before.logical_pc)? != permit.first_instruction
            {
                return Err(GateError::Refused(
                    "dynamic original-run lineage or first decode changed",
                ));
            }
        }
        if actual.logical_pc == before.logical_pc {
            self.census
                .check_reserved(reservation, refresh_charge(1)?)
                .map_err(census_error)?;
            self.census
                .refresh_same_pc(reservation, origin, actual)
                .map_err(census_error)?;
        } else {
            let permit = self.running.get(&task).ok_or(GateError::Refused(
                "dynamic changed PC lacks its issued original-run permit",
            ))?;
            if !matches!(actual.phase, StopPhase::OwnedFetch | StopPhase::OwnedGuard) {
                return Err(GateError::Refused(
                    "dynamic changed PC is not an owned original successor",
                ));
            }
            let evidence = OwnerConsumption::original_progress(
                permit.id,
                permit.before.clone(),
                permit.first_instruction.clone(),
                actual.clone(),
            )
            .map_err(census_error)?;
            let charge = BudgetCharge {
                origins: 1,
                witnesses: 1,
                source_fact_bytes: add(origin_bound()?, consume_bound()?)?,
                ..BudgetCharge::default()
            };
            self.census
                .check_reserved(reservation, charge)
                .map_err(census_error)?;
            self.census
                .consume(reservation, origin, evidence)
                .map_err(census_error)?;
            let next = self
                .census
                .insert(
                    reservation,
                    OriginKind::CurrentHeldPc,
                    actual.logical_pc,
                    actual,
                )
                .map_err(census_error)?;
            self.origins.insert(task, next);
        }
        self.running.remove(&task);
        owner.time_left(until, "dynamic admission original progress")?;
        Ok(())
    }

    pub(super) fn normalize_guards(
        &mut self,
        owner: &mut Owner,
        reservation: Reservation,
        until: Instant,
    ) -> Result<(), GateError> {
        if !self.running.is_empty() {
            return Err(GateError::Refused(
                "dynamic guard normalization has running original permits",
            ));
        }
        let Some(&selected) = self.origins.keys().next() else {
            return Ok(());
        };
        let members = self.native.check_admission_mm(owner, selected)?;
        let tasks = self.held_task_bound(owner, 0)?;
        for task in members.candidate.tasks {
            owner.time_left(until, "dynamic owned guard normalization")?;
            let before = self.observe_current(owner, task)?;
            if before.phase != StopPhase::OwnedGuard {
                continue;
            }
            let origin = *self
                .origins
                .get(&task)
                .ok_or(GateError::Refused("dynamic guard has no current origin"))?;
            self.census
                .check_current_origin(origin, &before)
                .map_err(census_error)?;
            self.census
                .check_reserved(reservation, refresh_charge(tasks)?)
                .map_err(census_error)?;
            let current = self.native.admission_current(task)?;
            let mut after = before.registers;
            after.rip = before.logical_pc;
            // The original instruction has not executed. Authenticate every
            // old armed byte while all members remain held, without calling a
            // runner on this raw RIP=head+1 phase.
            for image in &self.domain.images {
                owner.time_left(until, "dynamic owned guard source authentication")?;
                if read_memory(
                    before.token.tid,
                    image.mapping.start,
                    image.snapshot.bytes().len(),
                )? != self.domain.expected_image(image)
                {
                    return Err(GateError::Refused(
                        "dynamic source changed before guard normalization",
                    ));
                }
            }
            let maps = read_maps(before.token.tid)?;
            for (&page, &executable) in &self.domain.pages {
                let end = page.checked_add(PAGE).ok_or_else(overflow)?;
                if !maps.iter().any(|mapping| {
                    mapping.start <= page
                        && end <= mapping.end
                        && mapping.permissions.as_bytes().get(3) == Some(&b'p')
                        && mapping.permissions.as_bytes().get(1) != Some(&b'w')
                        && (mapping.permissions.as_bytes().get(2) == Some(&b'x')) == executable
                }) {
                    return Err(GateError::Refused(
                        "dynamic source permissions changed before guard normalization",
                    ));
                }
            }
            // SAFETY: exact current owned INT3, original decode/guard bytes,
            // complete held mm, and a RIP-only move from raw head+1 to head.
            // No continuation is consumed and no original instruction runs.
            unsafe {
                trusted::apply_scripted_completion(
                    owner,
                    &mut self.native,
                    &self.island,
                    &current,
                    StateTransform {
                        before: &before.registers,
                        after: &after,
                        before_xstate: &before.xstate,
                        before_mask: before.signal_mask,
                    },
                    until,
                )?;
            }
            let actual = self.observe_current(owner, task)?;
            if actual.registers != after
                || actual.xstate != before.xstate
                || actual.signal_mask != before.signal_mask
                || actual.logical_pc != before.logical_pc
                || actual.phase != StopPhase::UserCheckpoint
            {
                return Err(GateError::Refused(
                    "dynamic guard normalization changed complete original state",
                ));
            }
            self.refresh_all_same_pc(owner, reservation, task, until)?;
        }
        Ok(())
    }

    pub(super) fn settle_private_controls(
        &mut self,
        owner: &mut Owner,
        reservation: Reservation,
        until: Instant,
    ) -> Result<(), GateError> {
        if !self.running.is_empty() {
            return Err(GateError::Refused(
                "dynamic private control settling has running original permits",
            ));
        }
        let Some(&selected) = self.origins.keys().next() else {
            return Ok(());
        };
        let members = self.native.check_admission_mm(owner, selected)?;
        let tasks = self.held_task_bound(owner, 0)?;
        let mut pending = Vec::new();
        for &task in &members.candidate.tasks {
            if let Ok(current) = self.native.admission_current(task) {
                self.native.require_admission_stop(&current)?;
                if current.phase == AdmissionPhase::Fetch
                    || self.native.admission_interrupt_credit(current.token.tid)? != 0
                {
                    pending.push(task);
                }
            }
        }
        self.census
            .check_reserved(reservation, refresh_charge(mul(pending.len(), tasks)?)?)
            .map_err(census_error)?;
        for task in pending {
            owner.time_left(until, "dynamic private control settling")?;
            let Ok(current) = self.native.admission_current(task) else {
                continue;
            };
            self.native.require_admission_stop(&current)?;
            if current.phase != AdmissionPhase::Fetch
                && self.native.admission_interrupt_credit(current.token.tid)? == 0
            {
                continue;
            }
            let before = self.observe_current(owner, task)?;
            if before.phase == StopPhase::OwnedGuard || before.registers.rip != before.logical_pc {
                return Err(GateError::Refused(
                    "dynamic private control settling requires guard normalization",
                ));
            }
            let origin = *self.origins.get(&task).ok_or(GateError::Refused(
                "dynamic private control settling lacks an origin",
            ))?;
            self.census
                .check_current_origin(origin, &before)
                .map_err(census_error)?;
            self.census
                .check_reserved(reservation, refresh_charge(tasks)?)
                .map_err(census_error)?;
            {
                let mut held =
                    HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
                held.settle_owned_controls(control_remaining(until)?)?;
            }
            let after = self.observe_current(owner, task)?;
            if after.registers != before.registers
                || after.xstate != before.xstate
                || after.signal_mask != before.signal_mask
                || after.logical_pc != before.logical_pc
                || after.phase != StopPhase::UserCheckpoint
                || self.native.admission_interrupt_credit(after.token.tid)? != 0
            {
                return Err(GateError::Refused(
                    "dynamic private control settling changed original state or retained credits",
                ));
            }
            self.refresh_all_same_pc(owner, reservation, task, until)?;
        }
        Ok(())
    }

    pub(super) fn rebind(
        &mut self,
        owner: &mut Owner,
        reservation: Reservation,
        selected: TaskId,
        window: Option<routes::OriginalWindow>,
        until: Instant,
    ) -> Result<(), GateError> {
        owner.time_left(until, "dynamic admission generation transition")?;
        if !self.running.is_empty()
            || !self.native.admission_events_empty()
            || self.domain.generation != self.census.generation()
            || self.domain.generation != self.island.generation
        {
            return Err(GateError::Refused(
                "dynamic generation transition has unresolved execution or events",
            ));
        }
        let next = self.domain.generation.checked_add(1).ok_or_else(overflow)?;
        let metric = self
            .metrics
            .generation_changes
            .checked_add(1)
            .ok_or_else(overflow)?;
        let tasks = self.held_task_bound(owner, 0)?;
        let charge = rebind_charge(&self.domain, self.census.active().count(), 0, tasks)?;
        self.census
            .check_reserved(reservation, charge)
            .map_err(census_error)?;
        let members = self.native.check_admission_mm(owner, selected)?;
        for &task in &members.candidate.tasks {
            let actual = self.observe_current(owner, task)?;
            let origin = *self.origins.get(&task).ok_or(GateError::Refused(
                "dynamic generation transition has an untracked held task",
            ))?;
            self.census
                .check_current_origin(origin, &actual)
                .map_err(census_error)?;
            if matches!(actual.phase, StopPhase::OwnedGuard | StopPhase::OwnedFetch)
                || actual.registers.rip != actual.logical_pc
            {
                return Err(GateError::Refused(
                    "dynamic generation transition requires real normalized checkpoints",
                ));
            }
        }
        let scopes = self
            .domain
            .images
            .iter()
            .map(|image| census::ImageScope {
                mapping: image.snapshot.mapping,
                range: image.snapshot.range(),
            })
            .collect::<Vec<_>>();
        let mut projection = self.census.project(&scopes).map_err(census_error)?;
        for image in &mut projection {
            image.generation = liteinst_admission::Generation(next);
        }
        let staged = self.domain.projected_images(next, &projection)?;
        // Charge retained source/metadata before revocation. Epoch/history and
        // actual refreshes debit their own categories below; no refund occurs.
        let refresh = refresh_charge(2 * tasks)?;
        let source_bytes = charge
            .source_fact_bytes
            .checked_sub(refresh.source_fact_bytes)
            .and_then(|value| value.checked_sub(size_of::<census::HistoryRecord>()))
            .ok_or_else(overflow)?;
        self.census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: source_bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        let revoked = {
            let mut held =
                HeldMmStop::acquire(owner, &mut self.native, &mut self.island, selected, until)?;
            routes::revoke_all(&mut held, &mut self.domain, window, until)?
        };
        // Hidden private operations advanced the real runner sequence. Keep
        // that old-generation observation before changing the model identity.
        self.refresh_all_same_pc(owner, reservation, selected, until)?;
        if !self.native.admission_events_empty() {
            return Err(GateError::Refused(
                "dynamic generation transition acquired undrained events",
            ));
        }
        // SAFETY: revoke_all completed old armed-byte authentication, NX,
        // restoration, readback and sync under a real hold. That hold is gone;
        // the owner interlock remains closed and no original release occurred.
        let generation = unsafe {
            self.native
                .advance_admission_generation(owner, &mut self.island, selected)?
        };
        if generation != next {
            return Err(GateError::Refused(
                "dynamic native generation differs from staged evidence",
            ));
        }
        self.census
            .rebind_epoch(reservation, generation)
            .map_err(census_error)?;
        self.refresh_all_same_pc(owner, reservation, selected, until)?;
        {
            let held =
                HeldMmStop::acquire(owner, &mut self.native, &mut self.island, selected, until)?;
            routes::finish_rebind(revoked, &mut self.domain, &held, staged, &self.census)?;
        }
        self.metrics.generation_changes = metric;
        owner.time_left(until, "dynamic admission generation transition")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
