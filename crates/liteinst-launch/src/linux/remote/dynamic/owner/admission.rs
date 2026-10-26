//! Admission state machine on the original native tracer thread.
//!
//! This owns the raw lifecycle dispatcher after pristine EXEC bootstrap. Public
//! raw-session requests cannot bypass its source, census or release interlock.
use super::super::admission::{
    AdmissionReply, AdmissionRequest, ExecSourceBinding, PendingSourceToken, PendingToken,
    ProviderInput, SourceTransitionBinding,
};
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
mod runtime;
mod runtime_capture;
mod runtime_instruction;
mod runtime_native;
mod source_identity;
pub(in crate::linux::remote::dynamic::owner) use mapping::maps::{MapEntry, ParsedMaps};
pub(in crate::linux::remote::dynamic::owner) use runtime::RuntimeOwner;
pub(in crate::linux::remote::dynamic::owner) use source_identity::require_initial_task_identity;
mod completion;
mod domain;
mod drive;
mod exec;
#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
pub(in crate::linux::remote::dynamic::owner) use exec::oracle::{
    ExecBackingInspection, ExecFault, ExecOracle,
};
mod mapping;
#[cfg(test)]
mod panic_custody;
mod routes;
mod signals;
mod transitions;
use census::{
    BudgetCharge, ExecutionId, ObservedStop, OriginId, OriginKind, ResumeCensus, StopPhase,
};
use domain::Domain;
pub(in crate::linux::remote::dynamic::owner) use routes::MappingRevocation;

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
    signals: Option<signals::SignalTransaction>,
    mapping: Option<mapping::MappingState>,
    exec: Option<exec::ExecState>,
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

struct AdmissionProfiles {
    signal: Option<(DynamicSignalProfile, super::super::signal::SignalBudget)>,
    mapping: Option<DynamicMappingProfile>,
    exec: Option<DynamicExecProfile>,
}

fn control_remaining(until: Instant) -> Result<Duration, LaunchError> {
    until
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(LaunchError::Timeout("dynamic admission transaction"))
}
fn census_error(error: census::CensusError) -> GateError {
    GateError::Refused(match error {
        census::CensusError::InvalidLimits => "dynamic continuation invalid limits",
        census::CensusError::Capacity => "dynamic continuation lifetime capacity exhausted",
        census::CensusError::Allocation => "dynamic continuation allocation failed",
        census::CensusError::OutstandingReservation => {
            "dynamic continuation reservation already outstanding"
        }
        census::CensusError::StaleReservation => "dynamic continuation stale reservation",
        census::CensusError::ReservationExhausted => "dynamic continuation reservation exhausted",
        census::CensusError::UnknownOrigin => "dynamic continuation unknown origin",
        census::CensusError::InactiveOrigin => "dynamic continuation inactive origin",
        census::CensusError::IdentityMismatch => "dynamic continuation identity mismatch",
        census::CensusError::StaleObservation => "dynamic continuation stale observation",
        census::CensusError::InvalidObservation => "dynamic continuation invalid observation",
        census::CensusError::WrongOriginPhase => "dynamic continuation wrong origin phase",
        census::CensusError::PersistentUnknown => {
            "dynamic continuation unqualified persistent origin"
        }
        census::CensusError::InvalidConsumption => {
            "dynamic continuation invalid consumption evidence"
        }
        census::CensusError::GenerationNotAdvanced => {
            "dynamic continuation generation did not advance"
        }
        census::CensusError::MissingImage => "dynamic continuation missing source image",
        census::CensusError::OverlappingImages => "dynamic continuation overlapping source images",
        census::CensusError::ProjectionMismatch => "dynamic continuation entry projection mismatch",
    })
}

impl Owner {
    pub(super) fn execute_admission(
        &mut self,
        request: AdmissionRequest,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let _journal_unwind = self.kernel_journal.panic_scope();
        let _exec_unwind = self
            .exec_journal
            .as_ref()
            .map(|journal| journal.panic_scope());
        if self.runtime.is_some() || matches!(&request, AdmissionRequest::StartRuntime { .. }) {
            return self.execute_runtime(request, until);
        }
        if let Some(mut admission) = self.admission.take() {
            // Restore custody of the complete live and retired admission
            // history even when execution unwinds. The outer owner handler
            // still receives the original panic and owns physical cleanup.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                admission.execute(self, request, until)
            }));
            self.admission = Some(admission);
            let result = match outcome {
                Ok(result) => result,
                Err(payload) => std::panic::resume_unwind(payload),
            };
            if let Err(error) = &result {
                self.kernel_journal.fail_gate(error);
                if let Some(journal) = &self.exec_journal {
                    journal.fail_gate(error);
                }
                if let Some(journal) = &self.signal_journal {
                    match error {
                        GateError::Control(error) => journal.fail_error(error),
                        _ => {
                            journal.fail(super::signal_journal::SignalJournalFailure::InvalidState)
                        }
                    }
                }
            }
            return result;
        }
        let (initial, facts, options, signal, mapping, exec) = match request {
            AdmissionRequest::Start {
                initial,
                facts,
                options,
            } => (initial, facts, options, None, None, None),
            AdmissionRequest::StartSignals {
                initial,
                facts,
                options,
                profile,
                budget,
            } => (initial, facts, options, Some((profile, budget)), None, None),
            AdmissionRequest::StartMappings {
                initial,
                facts,
                options,
                profile,
            } => (initial, facts, options, None, Some(profile), None),
            AdmissionRequest::StartExec {
                initial,
                facts,
                options,
                profile,
            } => (initial, facts, options, None, None, Some(profile)),
            _ => return Err(GateError::Refused("dynamic admission is not initialized")),
        };
        let signal_enabled = signal.is_some();
        let mapping_enabled = mapping.is_some();
        let exec_enabled = exec.is_some();
        let (admission, ready) = AdmissionOwner::start(
            self,
            initial,
            facts,
            options,
            AdmissionProfiles {
                signal,
                mapping,
                exec,
            },
            until,
        )
        .inspect_err(|error| {
            if let Some(journal) = &self.exec_journal {
                journal.fail_gate(error);
            }
            if let Some(journal) = &self.signal_journal {
                match error {
                    GateError::Control(error) => journal.fail_error(error),
                    _ => journal.fail(super::signal_journal::SignalJournalFailure::InvalidState),
                }
            }
        })?;
        self.admission = Some(admission);
        Ok(if exec_enabled {
            AdmissionReply::ReadyExec(
                ready,
                self.kernel_journal.reader(),
                self.exec_journal
                    .as_ref()
                    .expect("exec startup archive")
                    .reader(),
            )
        } else if mapping_enabled {
            AdmissionReply::ReadyMappings(ready, self.kernel_journal.reader())
        } else if signal_enabled {
            AdmissionReply::ReadySignals(ready, self.kernel_journal.reader())
        } else {
            AdmissionReply::Ready(ready, self.kernel_journal.reader())
        })
    }
}

impl AdmissionOwner {
    fn start(
        owner: &mut Owner,
        initial: DynamicStop,
        facts: Vec<ImageFacts>,
        options: DynamicAdmissionOptions,
        profiles: AdmissionProfiles,
        until: Instant,
    ) -> Result<(Self, DynamicAdmissionState), GateError> {
        let AdmissionProfiles {
            signal,
            mapping,
            exec,
        } = profiles;
        options.validate()?;
        crate::gate::domain::validate_image_count(&facts)?;
        let exec = if let Some(profile) = exec {
            profile.validate(&options)?;
            if signal.is_some()
                || mapping.is_some()
                || owner.exec_policy != DynamicExecPolicy::ExecveOnce
                || owner.exec_journal.is_some()
            {
                return Err(GateError::Refused(
                    "exec startup requires its exclusive native profile",
                ));
            }
            owner.exec_journal = Some(super::exec_journal::ExecJournalWriter::new(owner.session));
            Some(exec::ExecState::new(profile, options.clone()))
        } else {
            if owner.exec_policy != DynamicExecPolicy::Refuse || owner.exec_journal.is_some() {
                return Err(GateError::Refused(
                    "ordinary admission has an exec-only native profile",
                ));
            }
            None
        };
        let exec_bound = exec.as_ref().map_or(0, |_| {
            std::mem::size_of::<exec::ExecState>()
                + owner
                    .exec_journal
                    .as_ref()
                    .expect("exec startup archive")
                    .allocated_bytes()
        });
        // The complete inline storage remains reserved at startup. Its retired
        // census header is debited by commit_exec_mm when the history moves;
        // charging it here as well would report the same retained bytes twice.
        let exec_bytes = if exec.is_some() {
            exec_bound
                .checked_sub(std::mem::size_of::<census::RetiredCensus>())
                .ok_or(GateError::Refused("exec embedded census header differs"))?
        } else {
            0
        };
        if let Some(profile) = &mapping {
            profile.validate(&options, &facts)?;
            if signal.is_some() {
                return Err(GateError::Refused(
                    "mapping and signal profiles need separate composition",
                ));
            }
            // Initial address envelopes may not include stack/TLS/island or
            // any original mapping. Original creation later repeats this check.
            let maps = read_maps(initial.tid)?;
            if profile.allowed_ranges.iter().any(|range| {
                maps.iter()
                    .any(|map| range.start < map.end && map.start < range.end)
            }) {
                return Err(GateError::Refused(
                    "mapping envelope overlaps initial address space",
                ));
            }
        }
        let mapping_bytes = mapping
            .as_ref()
            .map(mapping::MappingState::initial_bytes)
            .transpose()?
            .unwrap_or(0);
        if let Some((profile, budget)) = &signal {
            profile.validate(&options, &facts)?;
            if *budget != super::super::signal::SignalBudget::new(&facts, &options)?
                || owner.anchor_archive.is_none()
                || owner.signal_journal.is_none()
            {
                return Err(GateError::Refused(
                    "signal startup lacks its pre-clone reserved evidence",
                ));
            }
        } else if owner.anchor_archive.is_some() || owner.signal_journal.is_some() {
            return Err(GateError::Refused(
                "anchored launch requires its explicit signal owner",
            ));
        }
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
        let mapping_census = owner.admission_mapping_census(&initial)?;
        let mapping_catalog_bytes = Domain::mapping_catalog_bytes(&mapping_census)?;
        // Establish a finite startup envelope before the initial entry patch,
        // island allocation or any original permission change. Actual retained
        // bootstrap/origin bytes are debited from this same lifetime budget.
        let initial_bytes = facts
            .iter()
            .try_fold(0_usize, |sum, fact| {
                // Original domain facts plus the exact immutable resource
                // basis, both retained before any plan can be reserved.
                sum.checked_add(fact.bytes.len().checked_mul(2)?)
                    .and_then(|value| value.checked_add(fact.heads.len().checked_mul(512)?))
            })
            .and_then(|value| value.checked_add(MAX_XSTATE.checked_mul(8)?))
            .and_then(|value| value.checked_add(64 * 1024))
            .and_then(|value| value.checked_add(mapping_catalog_bytes))
            .and_then(|value| value.checked_add(mapping_bytes))
            .and_then(|value| value.checked_add(exec_bound))
            .and_then(|value| {
                value.checked_add(signal.as_ref().map_or(0, |(_, budget)| budget.bytes))
            })
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
        let boot = unsafe { owner.bootstrap_admission(&initial, &mapping_census, until)? };
        let signals = signal
            .map(|(profile, _)| signals::SignalTransaction::new(owner, profile, &boot, until))
            .transpose()?;
        let mapping = mapping
            .map(|profile| mapping::MappingState::new(owner, profile, &boot, until))
            .transpose()?;
        let retained_mapping_bytes = mapping
            .as_ref()
            .map(mapping::MappingState::retained_bytes)
            .transpose()?
            .unwrap_or(0);
        if retained_mapping_bytes > mapping_bytes {
            return Err(GateError::Refused(
                "mapping startup evidence exceeded its reservation",
            ));
        }
        let native = owner.lifecycle.take().ok_or(GateError::Refused(
            "admission bootstrap lost native lifecycle ownership",
        ))?;
        let mut domain = Domain::new(
            facts,
            boot.original_executables,
            &options,
            until,
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
        if let Some(signals) = &signals {
            signals.verify_extent(&boot.stop.token, boot.stop.identity, &raw)?;
        }
        if let Some(mapping) = &mapping {
            mapping.verify_extent(&boot.stop.token, boot.stop.identity, &raw)?;
        }
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
            .and_then(|value| value.checked_add(domain.resource_basis_bytes()))
            .and_then(|value| value.checked_add(retained_mapping_bytes))
            .and_then(|value| value.checked_add(exec_bytes))
            .and_then(|value| value.checked_add(boot.evidence.exec_event.xstate.len()))
            .and_then(|value| value.checked_add(boot.evidence.exec_exit.xstate.len()))
            .and_then(|value| value.checked_add(boot.evidence.entry_trap.xstate.len()))
            .and_then(|value| value.checked_add(boot.evidence.restored_entry.xstate.len()))
            .and_then(|value| value.checked_add(std::mem::size_of::<BootstrapEvidence>()))
            .and_then(|value| {
                value.checked_add(
                    owner
                        .anchor_archive
                        .as_ref()
                        .map_or(0, |archive| archive.retained_bytes()),
                )
            })
            .and_then(|value| {
                value.checked_add(if owner.signal_journal.is_some() {
                    super::signal_journal::evidence_bound()
                } else {
                    0
                })
            })
            .and_then(|value| {
                value.checked_add(
                    signals
                        .as_ref()
                        .map_or(0, |signal| signal.initial_storage_bytes()),
                )
            })
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
        metrics.resource_scan_decoded_starts = domain.resource_scan_decoded_starts();
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
                signals,
                mapping,
                exec,
                next_execution: 1,
                metrics,
                closed: false,
            },
            state,
        ))
    }

    pub(super) fn provider_expired(&self, now: Instant) -> bool {
        self.exec
            .as_ref()
            .and_then(|exec| exec.pending_until())
            .is_some_and(|until| now >= until)
            || self
                .mapping
                .as_ref()
                .and_then(|mapping| mapping.pending_until())
                .is_some_and(|until| now >= until)
            || self
                .pending
                .as_ref()
                .is_some_and(|pending| now >= pending.until)
            || self
                .signals
                .as_ref()
                .and_then(|signals| signals.pending_until())
                .is_some_and(|until| now >= until)
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
        if self.exec.as_ref().is_some_and(|exec| exec.has_pending())
            && !matches!(request, AdmissionRequest::ResolveSources { .. })
        {
            return Err(GateError::Refused(
                "exec source acquisition remains pending",
            ));
        }
        if self
            .mapping
            .as_ref()
            .is_some_and(|mapping| mapping.has_pending())
            && !matches!(request, AdmissionRequest::ResolveSources { .. })
        {
            return Err(GateError::Refused(
                "mapping source acquisition remains pending",
            ));
        }
        if self.pending.is_some() && !matches!(request, AdmissionRequest::Complete { .. }) {
            return Err(GateError::Refused(
                "dynamic admission has an outstanding provider invocation",
            ));
        }
        if self
            .signals
            .as_ref()
            .is_some_and(|signals| signals.has_pending())
            && !matches!(
                request,
                AdmissionRequest::DeliverSignal(_)
                    | AdmissionRequest::State(_)
                    | AdmissionRequest::Memory { .. }
                    | AdmissionRequest::Metrics
            )
        {
            return Err(GateError::Refused(
                "signal delivery remains pending at its original deadline",
            ));
        }
        match request {
            AdmissionRequest::StartRuntime { .. } | AdmissionRequest::CompleteRuntime { .. } => {
                Err(GateError::Refused(
                    "runtime command reached legacy admission custody",
                ))
            }
            AdmissionRequest::Start { .. }
            | AdmissionRequest::StartSignals { .. }
            | AdmissionRequest::StartExec { .. }
            | AdmissionRequest::StartMappings { .. } => Err(GateError::Refused(
                "dynamic admission cannot restart an existing domain",
            )),
            AdmissionRequest::Advance => self.advance(owner, until),
            AdmissionRequest::ResolveSources { token, facts } => match &token.transition {
                SourceTransitionBinding::Mapping => {
                    self.resolve_mapping_sources(owner, token, facts, until)
                }
                SourceTransitionBinding::Exec(_) => {
                    self.resolve_exec_sources(owner, token, facts, until)
                }
            },
            AdmissionRequest::DeliverSignal(token) => self.deliver_signal(owner, token, until),
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
                self.metrics.retained_call_obligations = self.domain.returns.obligations().count();
                self.metrics.oldest_call_generation = self
                    .domain
                    .returns
                    .obligations()
                    .map(|obligation| obligation.source_generation.0)
                    .min();
                self.metrics.charged_source_bytes = self.census.charged().source_fact_bytes;
                self.metrics.retained_source_bytes = self.census.used().source_fact_bytes;
                self.metrics.bootstrap_xstate_bytes = self.bootstrap.exec_event.xstate.len()
                    + self.bootstrap.exec_exit.xstate.len()
                    + self.bootstrap.entry_trap.xstate.len()
                    + self.bootstrap.restored_entry.xstate.len();
                self.metrics.oracle = self.domain.oracle.metrics();
                if let Some(exec) = &self.exec {
                    exec.add_retired_metrics(&self.census, &mut self.metrics)?;
                }
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
        let identity = DynamicTask {
            task,
            process: current.process,
            address_space: current.address_space,
            generation: self.island.generation,
        };
        if let Some(signals) = &self.signals {
            signals.verify_extent(&token, identity, &raw)?;
        }
        if let Some(mapping) = &self.mapping {
            mapping.verify_extent(&token, identity, &raw)?;
        }
        Ok(DynamicAdmissionState {
            task: identity,
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

#[cfg(feature = "dev-exec-backing-cleanup")]
pub(crate) use exec::exec_backing_cleanup_main;
