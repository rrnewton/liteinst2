//! Original syscall, immutable source reply, and one atomic live-mm handoff.
use super::super::super::bootstrap::{bootstrap_replaced_admission, original_executables};
use super::super::super::selected::{ExecInvocation, execute_exec};
use super::inputs::InputMemory;
use super::observer::{ExecObserver, read_input};
use super::sources::ExecSourceContext;
use super::*;

impl AdmissionOwner {
    pub(in super::super) fn resolve_exec_sources(
        &mut self,
        owner: &mut Owner,
        token: PendingSourceToken,
        facts: DynamicSourceFacts,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let result = self.finish_exec_sources(owner, token, facts, until);
        if let Err(error) = &result {
            if let Some(journal) = &owner.exec_journal {
                journal.fail_gate(error);
            }
            self.close_completion(owner);
        }
        result
    }

    fn finish_exec_sources(
        &mut self,
        owner: &mut Owner,
        token: PendingSourceToken,
        facts: DynamicSourceFacts,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        owner.time_left(until, "exec source reply")?;
        let state = self
            .exec
            .as_mut()
            .ok_or_else(|| refused("exec profile is absent"))?;
        let attempt = state
            .attempt
            .as_mut()
            .ok_or_else(|| refused("exec attempt is absent"))?;
        let request = attempt
            .request
            .as_ref()
            .ok_or_else(|| refused("exec source request is absent"))?;
        let ready = attempt
            .bootstrap
            .as_ref()
            .ok_or_else(|| refused("exec native bootstrap is absent"))?;
        if token != request.token
            || until != attempt.original.until
            || attempt.admitted
            || attempt.reply.is_some()
            || state.retired.is_some()
            || !self.running.is_empty()
            || !self.ready.is_empty()
            || !self.work.is_empty()
            || self.domain.generation != attempt.original.token.epoch
            || self.domain.generation != self.census.generation()
            || self.domain.generation != self.island.generation
            || self.native.admission_current(token.task.task)? != ready.bootstrap().stop
        {
            return Err(refused("exec source reply lost its exact pending identity"));
        }
        request.check_exec_binding(&attempt.original.token, &state.profile, until)?;
        request.check_facts(&facts)?;
        let journal = owner
            .exec_journal
            .as_ref()
            .ok_or_else(|| refused("exec archive is absent"))?;
        let context = ExecSourceContext {
            owner,
            native: &self.native,
            journal,
            attempt: attempt.journal,
            until,
        };
        attempt
            .captured
            .as_ref()
            .ok_or_else(|| refused("exec source capture is absent"))?
            .reauthenticate(&context, ready.bootstrap(), &mut attempt.scratch)?;
        let reply_bytes = budget::reply_payload(&facts)?;
        self.census
            .account_external(attempt.reservation, budget::bytes(reply_bytes))
            .map_err(census_error)?;
        let head_count = facts
            .images
            .iter()
            .try_fold(0_usize, |count, image| count.checked_add(image.heads.len()))
            .ok_or_else(|| refused("exec source reply head count overflows"))?;
        attempt.reply = Some(facts);
        journal.sources_accepted(attempt.journal, request.id().serial(), head_count)?;
        let mut images = Vec::new();
        images
            .try_reserve_exact(request.images.len())
            .map_err(|_| refused("exec image facts allocation failed"))?;
        for image in request.images.iter() {
            let heads = attempt
                .reply
                .as_ref()
                .unwrap()
                .images
                .iter()
                .find(|heads| heads.capture == image.id)
                .ok_or_else(|| refused("exec exact head reply disappeared"))?;
            images.push(ImageFacts {
                start: image.original.start,
                bytes: image.bytes.to_vec(),
                heads: heads.heads.clone(),
            });
        }
        // Runtime reads authenticate the immutable capture again while building
        // the ordinary per-mm Domain. The resolver supplied only complete heads.
        let domain = Domain::new(
            images,
            ready.bootstrap().original_executables.clone(),
            &state.options,
            until,
            |address, len| read_memory(owner.pid, address, len),
        )?;
        let pc = ready.bootstrap().evidence.restored_entry.registers.rip;
        domain.original_decode(pc)?;
        for &page in domain.pages.keys() {
            if !ready.bootstrap().mappings.iter().any(|map| {
                map.start <= page
                    && page + crate::gate::domain::PAGE <= map.end
                    && map.permissions.as_bytes().get(1) == Some(&b'-')
                    && map.permissions.as_bytes().get(2) == Some(&b'-')
                    && map.permissions.as_bytes().get(3) == Some(&b'p')
            }) {
                return Err(refused(
                    "exec new domain lacks its exact immutable NX pages",
                ));
            }
        }
        self.census
            .account_external(
                attempt.reservation,
                budget::bytes(budget::domain_bytes(&domain)?),
            )
            .map_err(census_error)?;
        // Callback and source construction cannot silently refresh the capture
        // token. All final checks remain read-only and use the original until.
        attempt.captured.as_ref().unwrap().reauthenticate(
            &context,
            ready.bootstrap(),
            &mut attempt.scratch,
        )?;
        let prepared = attempt
            .census
            .take()
            .ok_or_else(|| refused("exec census preparation is absent"))?;
        let seal = attempt
            .seal
            .take()
            .ok_or_else(|| refused("exec native seal preparation is absent"))?;
        let ready = attempt
            .bootstrap
            .take()
            .ok_or_else(|| refused("exec native proof was consumed"))?;
        let SealedExec {
            commit,
            transition,
            bootstrap,
            observed,
        } = seal.seal(owner, &self.native, ready, until)?;
        #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
        if let Some(oracle) = owner.exec_oracle.as_mut() {
            oracle.before_retire(oracle::BeforeRetire {
                domain: &self.domain,
                census: &self.census,
                island: &self.island,
                bootstrap: &self.bootstrap,
                origins: &self.origins,
                old_stop: &attempt.original.stop,
                initial: &observed,
                request,
                until,
            });
            owner.time_left(until, "private exec precommit inspection")?;
        }
        let previous_reservation = attempt.reservation;
        let (retired_census, reservation, origin) = self
            .census
            .commit_exec_mm(previous_reservation, prepared, commit, &observed)
            .map_err(census_error)?;
        // There is deliberately no fallible call, allocation or original
        // operation between the one-account handoff and retaining the entire
        // old mm. All old CALL/source/plan/census vectors move unchanged.
        let retired_domain = std::mem::replace(&mut self.domain, domain);
        let retired_island = std::mem::replace(&mut self.island, bootstrap.island);
        let retired_bootstrap = std::mem::replace(&mut self.bootstrap, bootstrap.evidence);
        let retired_origins = std::mem::take(&mut self.origins);
        state.retired = Some(RetiredMm {
            domain: retired_domain,
            census: retired_census,
            island: retired_island,
            bootstrap: retired_bootstrap,
            origins: retired_origins,
        });
        #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
        if let Some(oracle) = owner.exec_oracle.as_mut() {
            oracle.after_retire(oracle::AfterRetire {
                retired: state.retired.as_ref().unwrap(),
                live: &self.census,
                native: &self.native,
                initial: &observed,
                request,
                until,
            });
        }
        self.metrics.pages.admitted_pages = 0;
        self.metrics.pages.untouched_pages = self.domain.pages.len();
        attempt.transition = Some(transition);
        attempt.layout = Some(ExecBootstrapLayout {
            original_executables: bootstrap.original_executables,
            mappings: bootstrap.mappings,
            stop: bootstrap.stop,
        });
        attempt.reservation = reservation;
        self.origins.insert(observed.task.task, origin);
        let scopes = self
            .domain
            .images
            .iter()
            .map(|image| census::ImageScope {
                mapping: image.snapshot.mapping,
                range: image.snapshot.range(),
            })
            .collect::<Vec<_>>();
        let projections = self.census.project(&scopes).map_err(census_error)?;
        self.domain.images = self.domain.projected_images(0, &projections)?;
        self.census
            .validate_projection(
                &self
                    .domain
                    .images
                    .iter()
                    .map(|image| image.entries.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(census_error)?;
        self.domain.audit_history()?;
        state.retired.as_ref().unwrap().domain.audit_history()?;
        let raw = TaskStateSnapshot::read(owner.pid)?;
        let final_stop = &attempt.layout.as_ref().unwrap().stop;
        self.native.require_admission_stop(final_stop)?;
        if raw.registers != observed.registers
            || raw.xstate != observed.xstate
            || raw.mask != observed.signal_mask
            || observed.token != final_stop.token
        {
            return Err(refused(
                "exec source commit changed the actual first-user state",
            ));
        }
        let result = DynamicImageReplacement {
            before: DynamicAdmissionState {
                task: attempt.original.before.task,
                registers: attempt.original.before.registers,
                xstate: attempt.original.before.xstate.clone(),
                signal_mask: attempt.original.before.signal_mask,
            },
            ready: DynamicAdmissionState {
                task: observed.task,
                registers: observed.registers,
                xstate: observed.xstate,
                signal_mask: observed.signal_mask,
            },
            input: attempt.original.input.clone(),
            attempt: attempt.journal.id(),
        };
        let response_bytes = size_of::<DynamicImageReplacement>()
            .checked_add(result.before.xstate.capacity())
            .and_then(|bytes| bytes.checked_add(result.ready.xstate.capacity()))
            .and_then(|bytes| bytes.checked_add(result.input.instruction().bytes().len()))
            .ok_or_else(|| refused("exec completion response size overflows"))?;
        self.census
            .account_external(reservation, budget::bytes(response_bytes))
            .map_err(census_error)?;
        self.census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        owner.time_left(until, "exec admission completion")?;
        journal.admission_complete(attempt.journal, final_stop, &raw)?;
        attempt.admitted = true;
        self.ready.insert(result.ready.task.task);
        self.metrics.generation_changes = self
            .metrics
            .generation_changes
            .checked_add(1)
            .ok_or_else(|| refused("exec invalidation metric overflows"))?;
        self.metrics.resource_scan_decoded_starts = self
            .domain
            .resource_scan_decoded_starts()
            .checked_add(
                state
                    .retired
                    .as_ref()
                    .unwrap()
                    .domain
                    .resource_scan_decoded_starts(),
            )
            .ok_or_else(|| refused("exec resource scan metric overflows"))?;
        Ok(AdmissionReply::Event(DynamicAdmissionEvent::ImageReplaced(
            Box::new(result),
        )))
    }

    pub(in super::super) fn complete_exec(
        &mut self,
        owner: &mut Owner,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let state = self
            .exec
            .as_ref()
            .ok_or_else(|| refused("exec profile is absent"))?;
        if state.attempt.is_some()
            || state.retired.is_some()
            || self.signals.is_some()
            || self.mapping.is_some()
            || self.creation != DynamicCreationPolicy::Refuse
            || !self.running.is_empty()
            || !self.ready.is_empty()
            || !self.work.is_empty()
            || self.origins.len() != 1
            || self.census.active().count() != 1
            || !self.native.admission_events_empty()
        {
            return Err(refused(
                "exec requires its unused singleton admission profile",
            ));
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| refused("exec invocation is absent"))?;
        if pending.until != until || !is_exec(&pending.input) {
            return Err(refused("exec original input or deadline differs"));
        }
        let profile = state.profile.clone();
        let origin = *self
            .origins
            .get(&pending.token.task.task)
            .ok_or_else(|| refused("exec original origin is absent"))?;
        self.census
            .check_current_origin(origin, &pending.before)
            .map_err(census_error)?;
        let invocation = ExecutionId::from_owner(owner.session, pending.token.invocation)
            .map_err(census_error)?;
        let maps = read_maps(pending.token.stop.tid)?;
        if maps.len() > 512 {
            return Err(refused("exec old mapping inventory exceeds its bound"));
        }
        let count = self
            .domain
            .original_executables
            .len()
            .checked_add(1)
            .ok_or_else(|| refused("exec forbidden range count overflows"))?;
        let mut forbidden = Vec::new();
        forbidden
            .try_reserve_exact(count)
            .map_err(|_| refused("exec forbidden range allocation failed"))?;
        forbidden.extend(
            self.domain
                .original_executables
                .iter()
                .map(|map| map.start..map.end),
        );
        forbidden.push(self.island.range.clone());
        if forbidden.capacity() > count {
            return Err(refused(
                "exec forbidden range allocation exceeded its bound",
            ));
        }
        let journal = owner
            .exec_journal
            .as_mut()
            .ok_or_else(|| refused("exec archive is absent"))?;
        let previous_archive_bytes = journal.allocated_bytes();
        let prepared_journal = journal.prepare(
            &pending.token,
            &pending.input,
            &TaskStateSnapshot {
                registers: pending.before.registers,
                xstate: pending.before.xstate.clone(),
                mask: pending.before.signal_mask,
            },
            until,
        )?;
        let journal_increment = prepared_journal
            .allocated_bytes()
            .checked_sub(previous_archive_bytes)
            .ok_or_else(|| refused("exec archive allocation moved backwards"))?;
        let future = budget::future(&profile)?;
        let initial_bound = budget::initial_bound(&profile, count, &maps, journal_increment)?;
        let reservation = self.reserve_exec_transition(
            owner,
            budget::combine(future, budget::bytes(initial_bound))?,
        )?;
        let census = self
            .census
            .prepare_exec_mm(reservation, origin, invocation)
            .map_err(census_error)?;
        let pending = self
            .pending
            .as_ref()
            .expect("authenticated exec invocation");
        let seal = PreparedExecSeal::prepare(census.binding(), pending)?;
        let inputs = ExecInputs::prepare(&profile)?;
        let scratch = PreparedExecSources::new(&profile)?;
        let actual = budget::initial_attempt_bytes(
            &inputs,
            &seal,
            &scratch,
            &forbidden,
            &maps,
            journal_increment,
        )?;
        if actual > initial_bound {
            return Err(refused("exec preparation exceeded its reserved storage"));
        }
        self.census
            .account_external(reservation, budget::bytes(actual))
            .map_err(census_error)?;
        self.census
            .check_reserved(reservation, future)
            .map_err(census_error)?;
        let handle = owner
            .exec_journal
            .as_mut()
            .expect("exec archive")
            .attach(prepared_journal)?;
        let original = self.pending.take().expect("authenticated exec invocation");
        let task = original.token.task.task;
        // Install all input/preparation custody before reading original pointer
        // bytes or performing the first source restoration. Nested owner unwind
        // restores this exact AdmissionOwner before physical cleanup.
        self.exec.as_mut().expect("exec profile").attempt = Some(Box::new(ExecAttempt {
            original,
            reservation,
            future,
            journal: handle,
            census: Some(census),
            seal: Some(seal),
            inputs,
            forbidden,
            old_mappings: maps,
            window: None,
            scratch,
            bootstrap: None,
            layout: None,
            captured: None,
            request: None,
            reply: None,
            transition: None,
            admitted: false,
        }));
        {
            let attempt = self.exec.as_mut().unwrap().attempt.as_mut().unwrap();
            let pending = &attempt.original;
            self.native.require_admission_stop(&pending.stop)?;
            attempt.inputs.capture(
                &pending.input,
                InputMemory {
                    task: pending.stop.identity,
                    stop: &pending.stop.token,
                    mappings: &attempt.old_mappings,
                    forbidden: &attempt.forbidden,
                    until,
                },
                |address, destination| read_input(pending.stop.token.tid, address, destination),
            )?;
        }
        owner
            .exec_journal
            .as_ref()
            .unwrap()
            .original_restore_attempt(handle)?;
        {
            let pending = &self
                .exec
                .as_ref()
                .unwrap()
                .attempt
                .as_ref()
                .unwrap()
                .original;
            let mut held =
                HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
            let window = routes::restore_original(
                &mut held,
                &self.domain,
                pending.input.instruction().logical_pc(),
                pending.input.instruction().bytes(),
                until,
            )?;
            let window_bytes = window.retained_payload_bytes();
            self.exec.as_mut().unwrap().attempt.as_mut().unwrap().window = Some(window);
            self.census
                .account_external(reservation, budget::bytes(window_bytes))
                .map_err(census_error)?;
        }
        self.refresh_all_same_pc(owner, reservation, task, until)?;
        self.settle_private_controls(owner, reservation, until)?;
        let before = self.observe_current(owner, task)?;
        let current = self.native.admission_current(task)?;
        self.native
            .require_admission_exec_profile(owner, &current)?;
        self.exec
            .as_mut()
            .unwrap()
            .attempt
            .as_mut()
            .unwrap()
            .seal
            .as_mut()
            .unwrap()
            .bind_before(&before)?;
        self.census
            .check_current_origin(origin, &before)
            .map_err(census_error)?;
        self.census
            .check_reserved(reservation, future)
            .map_err(census_error)?;
        owner
            .exec_journal
            .as_ref()
            .unwrap()
            .original_restore_complete(handle)?;
        let before = TaskStateSnapshot {
            registers: before.registers,
            xstate: before.xstate,
            mask: before.signal_mask,
        };
        let ready = {
            let journal = owner.exec_journal.as_ref().unwrap().observer(handle)?;
            let attempt = self.exec.as_mut().unwrap().attempt.as_mut().unwrap();
            let mut observer = ExecObserver {
                journal,
                census: &self.census,
                reservation,
                future: attempt.future,
                inputs: &mut attempt.inputs,
                input: &attempt.original.input,
                forbidden: &attempt.forbidden,
                previous: attempt.original.token.task,
                until,
            };
            // SAFETY: original source/full state, singleton and input captures
            // are authenticated. The observer rechecks original inputs at real
            // ENTRY. All evidence/future charges precede this one release.
            let exit = unsafe {
                execute_exec(
                    owner,
                    &mut self.native,
                    &self.island,
                    ExecInvocation {
                        stop: &current,
                        input: &attempt.original.input,
                        before: &before,
                    },
                    &mut observer,
                    until,
                )?
            };
            // No old address is read after this call. Destruction of the old
            // mm is not inferred from syscall errno or a model generation.
            let journal = owner.exec_journal.as_ref().unwrap();
            journal.with_raw_maps(handle, 2, |record, raw| {
                if record.status != ExecMapsStatus::Complete {
                    return Err(refused("exec EXIT maps were not fully observed"));
                }
                super::super::mapping::maps::ParsedMaps::parse(raw, 512)
                    .map(|_| ())
                    .map_err(|_| refused("exec EXIT maps exceed the exact parsed bound"))
            })??;
            let maps = read_maps(owner.pid)?;
            if maps.len() > 512 {
                return Err(refused(
                    "exec replacement mapping inventory exceeds its bound",
                ));
            }
            let expected = original_executables(maps);
            // SAFETY: consumes actual EXEC/EXIT authority. Every original X
            // mapping is sized before the new-mm entry patch; the same future
            // reservation gates each bootstrap effect through this observer.
            unsafe {
                bootstrap_replaced_admission(
                    owner,
                    &mut self.native,
                    exit,
                    &expected,
                    &mut observer,
                    until,
                )?
            }
        };
        self.exec
            .as_mut()
            .unwrap()
            .attempt
            .as_mut()
            .unwrap()
            .bootstrap = Some(ready);
        self.census
            .account_external(
                reservation,
                budget::bytes(budget::native_payload(
                    self.exec
                        .as_ref()
                        .unwrap()
                        .attempt
                        .as_ref()
                        .unwrap()
                        .bootstrap
                        .as_ref()
                        .unwrap(),
                )?),
            )
            .map_err(census_error)?;
        self.capture_exec_sources(owner, until)
    }

    fn capture_exec_sources(
        &mut self,
        owner: &Owner,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let state = self
            .exec
            .as_mut()
            .ok_or_else(|| refused("exec profile is absent"))?;
        let attempt = state
            .attempt
            .as_mut()
            .ok_or_else(|| refused("exec attempt is absent"))?;
        let ready = attempt
            .bootstrap
            .as_ref()
            .ok_or_else(|| refused("exec bootstrap is absent"))?;
        if attempt.original.until != until
            || attempt.request.is_some()
            || attempt.captured.is_some()
        {
            return Err(refused(
                "exec source acquisition is repeated or has a different deadline",
            ));
        }
        let boot = ready.bootstrap();
        seal::authenticate_bootstrap(owner, &self.native, boot, until)?;
        if TaskStateSnapshot::read(owner.pid)? != boot.evidence.restored_entry {
            return Err(refused("exec full state changed before quarantine capture"));
        }
        let journal = owner
            .exec_journal
            .as_ref()
            .ok_or_else(|| refused("exec archive is absent"))?;
        // SAFETY: exact held native stop, live process pin, singleton membership
        // and full new-mm state were checked above; no native action follows
        // until that state is independently compared again below.
        unsafe {
            journal.capture_quarantined_maps(owner, attempt.journal, &boot.stop)?;
        }
        seal::authenticate_bootstrap(owner, &self.native, boot, until)?;
        if TaskStateSnapshot::read(owner.pid)? != boot.evidence.restored_entry {
            return Err(refused("exec quarantine capture changed full state"));
        }
        // This profile has exactly one source transaction and never composes
        // with mappings. Issuing these serials burns their complete finite
        // range, including unused image slots; a second exec is refused.
        let id = DynamicSourceRequestId {
            session: owner.session,
            serial: 1,
        };
        let context = ExecSourceContext {
            owner,
            native: &self.native,
            journal,
            attempt: attempt.journal,
            until,
        };
        attempt.captured = Some(attempt.scratch.capture(&context, ready, id, 1)?);
        let captured = attempt.captured.as_ref().unwrap();
        self.census
            .account_external(
                attempt.reservation,
                budget::bytes(budget::source_payload(captured)?),
            )
            .map_err(census_error)?;
        let request = DynamicSourceRequest {
            token: PendingSourceToken {
                id,
                original: attempt.original.token.clone(),
                transition: SourceTransitionBinding::Exec(Arc::new(ExecSourceBinding {
                    previous: ready.transition().previous(),
                    replacement: ready.transition().current(),
                    exec_stop: ready
                        .transition()
                        .exec_event()
                        .stop_token()
                        .unwrap()
                        .clone(),
                    exit_stop: ready.transition().exit().stop_token().unwrap().clone(),
                    bootstrap_stop: boot.stop.token.clone(),
                    attempt: attempt.journal.id(),
                })),
                capture_stop: boot.stop.token.clone(),
                task: boot.stop.identity,
                candidate_epoch: 0,
                until,
            },
            images: Arc::clone(captured.images()),
        };
        request.check_exec_binding(&attempt.original.token, &state.profile, until)?;
        journal.sources_requested(
            attempt.journal,
            id.serial,
            &boot.stop,
            request.images.len(),
            request.images.iter().map(|image| image.bytes.len()).sum(),
        )?;
        let returned = DynamicSourceRequest {
            token: request.token.clone(),
            images: Arc::clone(&request.images),
        };
        self.census
            .account_external(
                attempt.reservation,
                budget::bytes(budget::add(
                    size_of::<DynamicSourceRequest>(),
                    ExecSourceBinding::allocated_bytes()?,
                )?),
            )
            .map_err(census_error)?;
        attempt.request = Some(request);
        Ok(AdmissionReply::AcquireSources(Box::new(returned)))
    }
}
