//! Admission state machine on the original native tracer thread.
//!
//! This owns the raw lifecycle dispatcher after pristine EXEC bootstrap. Public
//! raw-session requests cannot bypass its source, census or release interlock.
use super::super::admission::{AdmissionReply, AdmissionRequest, PendingToken, ProviderInput};
use super::bootstrap::BootstrapEvidence;
use super::lifecycle::NativeLifecycle;
use super::publication::HeldMmStop;
use super::trusted::{AdmissionPhase, AdmissionStop, TaskStateSnapshot, TrustedIsland};
use super::*;
use crate::gate::{GateError, ImageFacts};
use crate::lifecycle::TaskId;
use crate::selected::{ProviderDecision, SelectedInput};
use std::collections::VecDeque;

mod census;
mod completion;
mod domain;
mod drive;
mod routes;
mod transitions;
use census::{
    BudgetCharge, ExecutionId, ObservedStop, OriginId, OriginKind, ResumeCensus, StopPhase,
};
use domain::Domain;

pub(super) struct AdmissionOwner {
    native: NativeLifecycle,
    island: TrustedIsland,
    domain: Domain,
    census: ResumeCensus,
    origins: BTreeMap<TaskId, OriginId>,
    ready: BTreeSet<TaskId>,
    running: BTreeMap<TaskId, RunPermit>,
    work: VecDeque<PendingWork>,
    diagnostics: VecDeque<DynamicEvent>,
    lifecycle_history: Vec<DynamicEvent>,
    bootstrap: BootstrapEvidence,
    creation: DynamicCreationPolicy,
    completion_history: Vec<completion::CompletionRecord>,
    pending: Option<PendingInvocation>,
    next_execution: u64,
    metrics: DynamicAdmissionMetrics,
    closed: bool,
}

struct RunPermit {
    id: ExecutionId,
    before: ObservedStop,
    first_instruction: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
enum PendingWork {
    Fetch { task: TaskId, page: u64 },
    Guard { task: TaskId, pc: u64 },
}

struct PendingInvocation {
    token: PendingToken,
    stop: AdmissionStop,
    before: ObservedStop,
    input: SelectedInput,
    until: Instant,
}

fn control_remaining(until: Instant) -> Result<Duration, LaunchError> {
    until
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(LaunchError::Timeout("dynamic admission transaction"))
}
fn census_error(_: census::CensusError) -> GateError {
    GateError::Refused("dynamic continuation inventory or lifetime budget refused")
}

impl Owner {
    pub(super) fn execute_admission(
        &mut self,
        request: AdmissionRequest,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        if let Some(mut admission) = self.admission.take() {
            // A panic keeps all kernel pins/wait ownership in Owner. The outer
            // owner catch-unwind enters physical cleanup; no handle escapes.
            let result = admission.execute(self, request, until);
            self.admission = Some(admission);
            return result;
        }
        let AdmissionRequest::Start {
            initial,
            facts,
            options,
        } = request
        else {
            return Err(GateError::Refused("dynamic admission is not initialized"));
        };
        let (admission, ready) = AdmissionOwner::start(self, initial, facts, options, until)?;
        self.admission = Some(admission);
        Ok(AdmissionReply::Ready(ready))
    }
}

impl AdmissionOwner {
    fn start(
        owner: &mut Owner,
        initial: DynamicStop,
        facts: Vec<ImageFacts>,
        options: DynamicAdmissionOptions,
        until: Instant,
    ) -> Result<(Self, DynamicAdmissionState), GateError> {
        options.validate()?;
        crate::gate::domain::validate_image_count(&facts)?;
        // Validate every non-native configuration before bootstrap mutates the
        // owned process. Native authentication still occurs after real EXEC.
        let _oracle = crate::gate::domain::GateOracle::new(options.cache)?;
        let limits = census::Limits {
            epochs: options.limits.epochs,
            source_fact_bytes: options.limits.source_fact_bytes,
            reports: options.limits.reports,
            origins: options.limits.origins,
            witnesses: options.limits.witnesses,
            plan_history: options.limits.plan_history,
        }
        .validate()
        .map_err(census_error)?;
        // Establish a finite startup envelope before the initial entry patch,
        // island allocation or any original permission change. Actual retained
        // bootstrap/origin bytes are debited from this same lifetime budget.
        let initial_bytes = facts
            .iter()
            .try_fold(0_usize, |sum, fact| {
                sum.checked_add(fact.bytes.len())
                    .and_then(|value| value.checked_add(fact.heads.len().checked_mul(256)?))
            })
            .and_then(|value| value.checked_add(MAX_XSTATE.checked_mul(8)?))
            .and_then(|value| value.checked_add(64 * 1024))
            .ok_or(GateError::Refused(
                "dynamic initial evidence size overflows",
            ))?;
        if initial_bytes > limits.source_fact_bytes {
            return Err(GateError::Refused(
                "dynamic startup evidence exceeds its lifetime source budget",
            ));
        }
        let started = Instant::now();
        // SAFETY: the only public caller is the unsafe pristine launch wrapper,
        // which supplies the unchanged complete static-image ownership contract.
        let boot = unsafe { owner.bootstrap_admission(&initial, until)? };
        let native = owner.lifecycle.take().ok_or(GateError::Refused(
            "admission bootstrap lost native lifecycle ownership",
        ))?;
        let mut domain = Domain::new(
            facts,
            boot.original_executables,
            &options,
            |address, len| read_memory(boot.stop.token.tid, address, len),
        )?;
        for &page in domain.pages.keys() {
            if !boot.mappings.iter().any(|map| {
                map.start <= page
                    && page + crate::gate::domain::PAGE <= map.end
                    && map.permissions.as_bytes().get(1) == Some(&b'-')
                    && map.permissions.as_bytes().get(2) == Some(&b'-')
                    && map.permissions.as_bytes().get(3) == Some(&b'p')
            }) {
                return Err(GateError::Refused(
                    "dynamic bootstrap mapping receipt lacks an original immutable NX page",
                ));
            }
        }
        let raw = TaskStateSnapshot::read(boot.stop.token.tid)?;
        let state = DynamicAdmissionState {
            task: boot.stop.identity,
            registers: raw.registers,
            xstate: raw.xstate.clone(),
            signal_mask: raw.mask,
        };
        let observed = ObservedStop {
            token: boot.stop.token.clone(),
            task: boot.stop.identity,
            logical_pc: raw.registers.rip,
            registers: raw.registers,
            xstate: raw.xstate,
            signal_mask: raw.mask,
            phase: StopPhase::UserCheckpoint,
            signal: None,
        };
        domain.original_decode(observed.logical_pc)?;
        let mut census =
            ResumeCensus::new(owner.session, boot.stop.identity.address_space, 0, limits)
                .map_err(census_error)?;
        // Initial epoch is charged by ResumeCensus::new. Source, bootstrap and
        // origin payloads are additionally bounded before their retained copies.
        let reservation = census
            .reserve(BudgetCharge {
                source_fact_bytes: initial_bytes,
                origins: 1,
                ..BudgetCharge::default()
            })
            .map_err(census_error)?;
        let origin = census
            .insert(
                reservation,
                OriginKind::CurrentHeldPc,
                observed.logical_pc,
                observed,
            )
            .map_err(census_error)?;
        // Bootstrap keeps four full initialized native snapshots. This explicit
        // payload charge is independent of the original source-byte budget.
        let external = domain
            .images
            .iter()
            .try_fold(0_usize, |sum, image| {
                sum.checked_add(image.snapshot.bytes().len())
                    .and_then(|value| {
                        value.checked_add(image.entries.heads().len().checked_mul(256)?)
                    })
            })
            .and_then(|value| value.checked_add(boot.evidence.exec_event.xstate.len()))
            .and_then(|value| value.checked_add(boot.evidence.exec_exit.xstate.len()))
            .and_then(|value| value.checked_add(boot.evidence.entry_trap.xstate.len()))
            .and_then(|value| value.checked_add(boot.evidence.restored_entry.xstate.len()))
            .and_then(|value| value.checked_add(std::mem::size_of::<BootstrapEvidence>()))
            .ok_or(GateError::Refused(
                "dynamic retained bootstrap evidence size overflows",
            ))?;
        census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: external,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        let scopes = domain
            .images
            .iter()
            .map(|image| census::ImageScope {
                mapping: image.snapshot.mapping,
                range: image.snapshot.range(),
            })
            .collect::<Vec<_>>();
        let projections = census.project(&scopes).map_err(census_error)?;
        domain.images = domain.projected_images(0, &projections)?;
        census
            .validate_projection(
                &domain
                    .images
                    .iter()
                    .map(|image| image.entries.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(census_error)?;
        let mut metrics = DynamicAdmissionMetrics::default();
        metrics.pages.startup = started.elapsed();
        metrics.pages.untouched_pages = domain.pages.len();
        let root = boot.stop.identity.task;
        Ok((
            Self {
                native,
                island: boot.island,
                domain,
                census,
                origins: BTreeMap::from([(root, origin)]),
                ready: BTreeSet::from([root]),
                running: BTreeMap::new(),
                work: VecDeque::new(),
                diagnostics: VecDeque::new(),
                lifecycle_history: Vec::new(),
                bootstrap: boot.evidence,
                creation: options.lifecycle.creation,
                completion_history: Vec::new(),
                pending: None,
                next_execution: 1,
                metrics,
                closed: false,
            },
            state,
        ))
    }

    pub(super) fn provider_expired(&self, now: Instant) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| now >= pending.until)
    }

    fn execute(
        &mut self,
        owner: &mut Owner,
        request: AdmissionRequest,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        owner.time_left(until, "dynamic admission command")?;
        if self.closed || self.provider_expired(Instant::now()) {
            return Err(GateError::Refused(
                "dynamic admission owner is closed or expired",
            ));
        }
        if self.pending.is_some() && !matches!(request, AdmissionRequest::Complete { .. }) {
            return Err(GateError::Refused(
                "dynamic admission has an outstanding provider invocation",
            ));
        }
        match request {
            AdmissionRequest::Start { .. } => Err(GateError::Refused(
                "dynamic admission cannot restart an existing domain",
            )),
            AdmissionRequest::Advance => self.advance(owner, until),
            AdmissionRequest::Complete { token, decision } => {
                self.complete(owner, token, decision, until)
            }
            AdmissionRequest::State(task) => self.state(task).map(AdmissionReply::State),
            AdmissionRequest::Memory { task, address, len } => {
                let token = self.native.admission_held_token(task)?;
                read_memory(token.tid, address, len)
                    .map(AdmissionReply::Bytes)
                    .map_err(GateError::from)
            }
            AdmissionRequest::Metrics => {
                self.domain.audit_history()?;
                self.metrics.retained_origins = self.census.rows().count();
                self.metrics.continuation_history_records = self.census.history().len();
                self.metrics.charged_source_bytes = self.census.charged().source_fact_bytes;
                self.metrics.retained_source_bytes = self.census.used().source_fact_bytes;
                self.metrics.bootstrap_xstate_bytes = self.bootstrap.exec_event.xstate.len()
                    + self.bootstrap.exec_exit.xstate.len()
                    + self.bootstrap.entry_trap.xstate.len()
                    + self.bootstrap.restored_entry.xstate.len();
                self.metrics.oracle = self.domain.oracle.metrics();
                Ok(AdmissionReply::Metrics(self.metrics.clone()))
            }
        }
    }

    fn state(&self, task: TaskId) -> Result<DynamicAdmissionState, GateError> {
        let token = self.native.admission_held_token(task)?;
        let current = self
            .native
            .admission_snapshot()
            .tasks()
            .find(|record| record.id == task)
            .cloned()
            .ok_or(GateError::Refused(
                "dynamic inspected task is not registered",
            ))?;
        let raw = TaskStateSnapshot::read(token.tid)?;
        Ok(DynamicAdmissionState {
            task: DynamicTask {
                task,
                process: current.process,
                address_space: current.address_space,
                generation: self.island.generation,
            },
            registers: raw.registers,
            xstate: raw.xstate,
            signal_mask: raw.mask,
        })
    }

    fn execution_id(&mut self, session: u64) -> Result<(u64, ExecutionId), GateError> {
        let serial = self.next_execution;
        self.next_execution = serial
            .checked_add(1)
            .ok_or(GateError::Refused("dynamic execution identity exhausted"))?;
        Ok((
            serial,
            ExecutionId::from_owner(session, serial).map_err(census_error)?,
        ))
    }
}
