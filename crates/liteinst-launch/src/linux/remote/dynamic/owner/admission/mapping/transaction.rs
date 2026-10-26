//! One original mapping invocation, followed by a held source-set transaction.
use super::super::completion::{CompletionEvidence, CompletionRecord, same_state};
use super::*;

impl AdmissionOwner {
    pub(in super::super) fn verify_mapping_completion_extent(
        &self,
        evidence: &CompletionEvidence,
    ) -> Result<(), GateError> {
        let mapping = self
            .mapping
            .as_ref()
            .ok_or_else(|| refused("mapping profile is absent"))?;
        let event_state = |event: &DynamicEvent, state: &TaskStateSnapshot| {
            let token = event
                .stop_token()
                .ok_or_else(|| refused("mapping extent event has no real stop"))?;
            let task = event
                .task
                .ok_or_else(|| refused("mapping extent event has no real identity"))?;
            mapping.verify_extent(token, task, state)
        };
        match evidence {
            CompletionEvidence::Native(completed) | CompletionEvidence::Collateral(completed) => {
                mapping.verify_extent(
                    &completed.stop.token,
                    completed.stop.identity,
                    &completed.state,
                )?;
                if !completed.newborns.is_empty() {
                    return Err(refused("mapping extent cannot certify new tasks"));
                }
                if let OriginalEvidence::Syscall(kernel) = &completed.evidence {
                    event_state(&kernel.entry, &kernel.entry_state)?;
                    event_state(&kernel.exit, &kernel.exit_state)?;
                    if !kernel.newborns.is_empty() {
                        return Err(refused("mapping extent cannot certify kernel newborns"));
                    }
                }
            }
            CompletionEvidence::Event(event) => {
                if let Some(state) = &event.state {
                    event_state(&event.event, state)?;
                }
            }
            // Scripted state is read through observe_current, which checks the
            // same certificate before producing a retained ObservedStop.
            CompletionEvidence::Scripted { .. } => {}
        }
        Ok(())
    }

    pub(in super::super) fn resolve_mapping_sources(
        &mut self,
        owner: &mut Owner,
        token: PendingSourceToken,
        facts: DynamicSourceFacts,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let result = self
            .check_mapping_reply(owner, &token, &facts, until)
            .and_then(|()| self.finish_mapping(owner, Some(facts), until));
        if let Err(error) = &result {
            owner.kernel_journal.fail_gate(error);
            self.close_completion(owner);
        }
        result
    }

    fn check_mapping_reply(
        &self,
        owner: &Owner,
        token: &PendingSourceToken,
        facts: &DynamicSourceFacts,
        until: Instant,
    ) -> Result<(), GateError> {
        owner.time_left(until, "mapping source resolution")?;
        let mapping = self
            .mapping
            .as_ref()
            .ok_or_else(|| refused("mapping profile is absent"))?;
        let pending = mapping
            .pending
            .as_ref()
            .ok_or_else(|| refused("mapping source request is absent"))?;
        let request = pending
            .request
            .as_ref()
            .ok_or_else(|| refused("mapping does not need a source reply"))?;
        let record = &mapping.records[pending.record];
        if token != &request.token
            || pending.until != until
            || pending.revoked.old_generation() != self.domain.generation
            || pending.revoked.old_version() != self.domain.entry_version
            || self.native.admission_current(token.task.task)?.token != token.capture_stop
        {
            return Err(refused(
                "mapping reply lost its original held capture and deadline",
            ));
        }
        request.check_mapping_binding(&record.original, &mapping.profile, until)?;
        request.check_facts(facts)
    }

    fn finish_mapping(
        &mut self,
        owner: &mut Owner,
        facts: Option<DynamicSourceFacts>,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        owner.time_left(until, "mapping source commit")?;
        let pending = self
            .mapping
            .as_mut()
            .and_then(|mapping| mapping.pending.take())
            .ok_or_else(|| refused("mapping transaction is absent"))?;
        let record = &self.mapping.as_ref().unwrap().records[pending.record];
        let task = record.original.task.task;
        let index = record
            .completion
            .ok_or_else(|| refused("mapping completion is absent"))?;
        if pending.until != until
            || pending.request.is_some() != facts.is_some()
            || !self.running.is_empty()
            || !self.native.admission_events_empty()
            || self.domain.generation != self.census.generation()
            || self.domain.generation != self.island.generation
            || pending.revoked.old_generation() != self.domain.generation
            || pending.revoked.old_version() != self.domain.entry_version
        {
            return Err(refused("mapping transaction differs before source commit"));
        }
        let next = self
            .domain
            .generation
            .checked_add(1)
            .ok_or_else(|| refused("mapping generation overflows"))?;
        let metric = self
            .metrics
            .generation_changes
            .checked_add(1)
            .ok_or_else(|| refused("mapping generation metric overflows"))?;
        {
            let held = HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
            pending.revoked.authenticate_quarantine(&held)?;
        }
        // Retain the exact keyed reply independently of the staged head copy.
        // Source bytes share the already-charged EXIT witness Arc allocation.
        let reply_bytes = facts
            .as_ref()
            .map(transitions::mapping_reply_storage_bytes)
            .transpose()?
            .unwrap_or(0);
        self.census
            .account_external(
                pending.reservation,
                BudgetCharge {
                    source_fact_bytes: reply_bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        let record = &mut self.mapping.as_mut().unwrap().records[pending.record];
        record.source_request = pending.request;
        record.source_facts = facts;
        let record = &self.mapping.as_ref().unwrap().records[pending.record];
        let staged = self.stage_mapping_sources(
            &record.range,
            record
                .source_request
                .as_ref()
                .zip(record.source_facts.as_ref()),
            pending.revoked.logical_executables().to_vec(),
            until,
        )?;
        let staged_bytes = transitions::mapping_staged_storage_bytes(&staged)?;
        self.census
            .account_external(
                pending.reservation,
                BudgetCharge {
                    source_fact_bytes: staged_bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        // A separate consuming native API checks the actual full quarantine,
        // original EXIT and fresh singleton immediately before advancing once.
        let (generation, revoked) = self.native.advance_mapping_generation(
            owner,
            &mut self.island,
            task,
            pending.revoked,
            until,
        )?;
        if generation != next || staged.identity().new_generation != generation {
            return Err(refused(
                "mapping native generation differs from staged source",
            ));
        }
        self.census
            .rebind_epoch(pending.reservation, generation)
            .map_err(census_error)?;
        self.refresh_all_same_pc(owner, pending.reservation, task, until)?;
        let (_retired, proof) = revoked.into_parts();
        self.mapping.as_mut().unwrap().records[pending.record].proof = Some(proof);
        {
            let held = HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
            let proof = self.mapping.as_ref().unwrap().records[pending.record]
                .proof
                .as_ref()
                .expect("retained mapping EXIT proof");
            let commit = proof.make_commit(&held, &staged, &self.census)?;
            self.domain
                .commit_replacement(staged, commit, &self.census)?;
        }
        self.mapping
            .as_mut()
            .unwrap()
            .commit_owned(pending.record)?;
        self.metrics.generation_changes = metric;
        self.metrics.resource_scan_decoded_starts = self.domain.resource_scan_decoded_starts();
        let tasks = self.native.check_admission_mm(owner, task)?.candidate.tasks;
        self.collect_interrupted_boundaries(owner, pending.reservation, &tasks, until)?;
        self.settle_private_controls(owner, pending.reservation, until)?;
        self.publish_page(owner, pending.reservation, task, pending.source_page, until)?;
        let state = self.observe_current(owner, task)?;
        if !same_state(&state, &pending.state) {
            return Err(refused(
                "mapping rearming changed the actual completed state",
            ));
        }
        self.completion_history[index].rearmed_generation = Some(self.domain.generation);
        self.ready.insert(task);
        self.completed_reply(owner, pending.reservation, index)
    }

    pub(in super::super) fn validated_mapping_completion(
        &self,
        index: usize,
        kernel: &native_selected::OriginalSyscallEvidence,
    ) -> Result<bool, GateError> {
        let Some(mapping) = &self.mapping else {
            return Ok(false);
        };
        let Some(record) = mapping
            .records
            .iter()
            .find(|record| record.completion == Some(index))
        else {
            return Ok(false);
        };
        if record.entry.as_ref() != Some(&kernel.entry)
            || record.exit.as_ref() != Some(&kernel.exit)
            || kernel.attempt.session != record.original.stop.session
            || kernel.attempt.invocation != record.original.invocation
            || record.result.is_none()
            || record.wait_count != 2
        {
            return Err(refused(
                "mapping completion differs from its retained original kernel result",
            ));
        }
        Ok(true)
    }

    pub(in super::super) fn complete_mapping(
        &mut self,
        owner: &mut Owner,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| refused("mapping has no pending invocation"))?;
        let task = pending.token.task.task;
        let members = self.native.check_admission_mm(owner, task)?;
        if self.signals.is_some()
            || members.candidate.tasks.as_slice() != [task]
            || !self.running.is_empty()
            || !self.native.admission_events_empty()
            || pending.until != until
        {
            return Err(refused(
                "mapping effect requires the original held singleton transaction",
            ));
        }
        let record = self
            .mapping
            .as_mut()
            .ok_or_else(|| refused("mapping profile is absent"))?
            .prepare(pending, &self.domain)?;
        self.mapping
            .as_ref()
            .unwrap()
            .evidence
            .verify_personality(pending.stop.token.tid, until)?;
        if self
            .census
            .active()
            .any(|origin| record.range.contains(&origin.current.logical_pc))
        {
            return Err(refused("mapping effect intersects an active continuation"));
        }
        let prepared = owner.kernel_journal.prepare_mapping(KernelAttemptBinding {
            pending: pending.token.clone(),
            original_stop: pending.stop.clone(),
            input: pending.input.clone(),
            before: TaskStateSnapshot {
                registers: pending.before.registers,
                xstate: pending.before.xstate.clone(),
                mask: pending.before.signal_mask,
            },
            until,
        })?;
        let journal_bytes = prepared.retained_bytes();
        let record_bytes = size_of::<MappingRecord>()
            .checked_add(
                record
                    .archive
                    .retained_bytes()
                    .checked_sub(size_of::<MappingCaptureArchive>())
                    .ok_or_else(|| refused("mapping archive retained header differs"))?,
            )
            .and_then(|value| {
                value.checked_add(
                    if matches!(record.operation, MappingOperation::Create { .. }) {
                        size_of::<OwnedMapping>()
                    } else {
                        0
                    },
                )
            })
            .ok_or_else(|| refused("mapping evidence size overflows"))?;
        let native_bound = native_storage_bound(
            &self.domain,
            (record.range.end - record.range.start) as usize,
        )?;
        let retirement_bytes = retirement_storage(&self.domain)?;
        let source_shape = if matches!(
            record.operation,
            MappingOperation::Protect {
                after: Protection::Executable,
                ..
            }
        ) {
            transitions::MappingSourceShape::MayAcquireRx {
                range_bytes: (record.range.end - record.range.start) as usize,
            }
        } else {
            transitions::MappingSourceShape::RetainedOnly
        };
        let mut remaining = self.mapping_source_budget(source_shape)?.charge()?;
        remaining.source_fact_bytes = remaining
            .source_fact_bytes
            .checked_add(native_bound)
            .ok_or_else(|| refused("mapping future evidence envelope overflows"))?;
        let mut prefix = remaining;
        prefix.source_fact_bytes = prefix
            .source_fact_bytes
            .checked_add(record_bytes)
            .and_then(|value| value.checked_add(journal_bytes))
            .and_then(|value| value.checked_add(retirement_bytes))
            .ok_or_else(|| refused("mapping transaction envelope overflows"))?;
        let reservation = self.reserve_transition_with_charge(owner, 1, true, 1, prefix)?;
        self.check_completion_budget(owner, reservation, 1, true, 1)?;
        self.domain.reserve_replacement_catalog_slot()?;
        self.reserve_completion_events()?;
        self.completion_history
            .try_reserve(1)
            .map_err(|_| refused("mapping completion history allocation failed"))?;
        self.census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: record_bytes + journal_bytes + retirement_bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        let attempt = owner.kernel_journal.attach(prepared)?;
        owner
            .kernel_journal
            .attach_mapping(attempt, record.archive.clone())?;
        let pending = self
            .pending
            .take()
            .expect("authenticated mapping invocation");
        let mapping_index = self.mapping.as_ref().unwrap().records.len();
        self.mapping.as_mut().unwrap().records.push(record);
        let window = {
            let mut held =
                HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
            routes::open_mapping_window(&mut held, &mut self.domain, until)?
        };
        self.refresh_all_same_pc(owner, reservation, task, until)?;
        let before = self.observe_current(owner, task)?;
        if before.registers != *pending.input.registers()
            || before.xstate != pending.before.xstate
            || before.signal_mask != pending.before.signal_mask
            || before.phase != StopPhase::UserCheckpoint
        {
            return Err(refused("mapping window changed original invocation state"));
        }
        let current = self.native.admission_current(task)?;
        if current != *window.opened_stop() {
            return Err(refused("mapping opening lost its exact native stop"));
        }
        let record = &mut self.mapping.as_mut().unwrap().records[mapping_index];
        record.logical_window.capture(current.token.tid)?;
        proof::check_opening_projection(record, &self.domain)?;
        // Preserve the ordinary pre-original remaining-capacity check, plus
        // the complete future mapping/source prefix. Retirement and the real
        // opening refresh have already debited their own reserved allocations.
        self.check_completion_budget_with_charge(owner, reservation, 1, true, 1, remaining)?;
        self.mapping
            .as_ref()
            .unwrap()
            .evidence
            .verify_personality(current.token.tid, until)?;
        let record = &mut self.mapping.as_mut().unwrap().records[mapping_index];
        // SAFETY: the non-cloneable window restored old original bytes and
        // logical permissions under a real singleton hold. The exact owned
        // range, syscall/arguments, every continuation and complete pre-effect
        // budget were checked above. Raw captures are preallocated and retained.
        let outcome = unsafe {
            native_selected::execute_mapping(
                owner,
                &mut self.native,
                &self.island,
                native_selected::OriginalInvocation {
                    stop: &current,
                    input: &pending.input,
                    before_xstate: &before.xstate,
                    before_mask: before.signal_mask,
                    journal: Some(attempt),
                },
                record,
                until,
            )?
        };
        let evidence = match outcome {
            OriginalOutcome::Completed(completed) => CompletionEvidence::Native(completed),
            OriginalOutcome::Event(event) => CompletionEvidence::Event(event),
        };
        self.verify_mapping_completion_extent(&evidence)?;
        let index = self.completion_history.len();
        let invocation = ExecutionId::from_owner(owner.session, pending.token.invocation)
            .map_err(census_error)?;
        self.completion_history.push(CompletionRecord {
            pending: Some(pending.token),
            invocation,
            before,
            original: pending.input.instruction().bytes().to_vec(),
            input: Some(pending.input),
            evidence,
            window: None,
            rearmed_generation: None,
            copied_events: 0,
            kernel_attempt: Some(attempt),
        });
        self.retain_completion_events(index)?;
        self.account_completion(reservation, index)?;
        if matches!(
            self.completion_history[index].evidence,
            CompletionEvidence::Event(_)
        ) {
            owner.kernel_journal.fail_active(
                super::super::super::kernel_journal::KernelFailureKind::AdmissionRejected,
            );
            return self.original_event_reply(owner, index);
        }
        let CompletionEvidence::Native(completed) = &self.completion_history[index].evidence else {
            unreachable!()
        };
        self.mapping.as_mut().unwrap().records[mapping_index].completion = Some(index);
        let verified = VerifiedMappingExit::from_completed(
            &self.mapping.as_ref().unwrap().records[mapping_index],
            &self.domain,
            completed,
        )?;
        let captured = verified.captured_source();
        let proof_bytes = verified.retained_bytes()?;
        let (source_page, state) = self.consume_completed(owner, reservation, index, until)?;
        let revoked = {
            let mut held =
                HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
            routes::close_mapping_window(&mut held, &self.domain, window, verified, until)?
        };
        self.refresh_all_same_pc(owner, reservation, task, until)?;
        let current = self.native.admission_current(task)?;
        if current != *revoked.closed_stop() {
            return Err(refused("mapping quarantine lost its exact native stop"));
        }
        // PendingMapping embeds the revocation, which embeds the proof. Moving
        // these values does not allocate another copy of their inline headers.
        let proof_payload = proof_bytes
            .checked_sub(size_of::<VerifiedMappingExit>())
            .ok_or_else(|| refused("mapping proof retained header differs"))?;
        let revocation_payload = revoked
            .retained_bytes()?
            .checked_sub(size_of::<routes::MappingRevocation>())
            .ok_or_else(|| refused("mapping quarantine retained header differs"))?;
        let native_bytes = size_of::<PendingMapping>()
            .checked_add(proof_payload)
            .and_then(|value| value.checked_add(revocation_payload))
            .and_then(|value| value.checked_add(state.xstate.len()))
            .ok_or_else(|| refused("mapping native retained size overflows"))?;
        if native_bytes > native_bound {
            return Err(refused(
                "mapping native evidence exceeded its pre-effect envelope",
            ));
        }
        self.census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: native_bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        let mapping = self.mapping.as_mut().unwrap();
        let record = &mut mapping.records[mapping_index];
        record.quarantined.capture(current.token.tid)?;
        let request = if record.result.is_some_and(|(_, error)| !error)
            && matches!(
                record.operation,
                MappingOperation::Protect {
                    after: Protection::Executable,
                    ..
                }
            ) {
            mapping.requests = mapping
                .requests
                .checked_add(1)
                .ok_or_else(|| refused("mapping source request identity overflows"))?;
            let id = DynamicSourceRequestId {
                session: owner.session,
                serial: mapping.requests,
            };
            let original =
                owned_descriptor(record.waits[1].capture.view()?, &record.range, *b"r-xp")?;
            let quarantined =
                owned_descriptor(record.quarantined.view()?, &record.range, *b"r--p")?;
            let bytes =
                captured.ok_or_else(|| refused("mapping RX lacks its held immutable bytes"))?;
            let request = DynamicSourceRequest {
                token: PendingSourceToken {
                    id,
                    original: record.original.clone(),
                    capture_stop: current.token.clone(),
                    task: current.identity,
                    candidate_epoch: current
                        .identity
                        .generation
                        .checked_add(1)
                        .ok_or_else(|| refused("mapping source epoch overflows"))?,
                    until,
                },
                images: Arc::from([DynamicSourceImage {
                    id: DynamicSourceCaptureId {
                        request: id,
                        index: 0,
                    },
                    mapping_incarnation: record.operation.incarnation(),
                    original,
                    quarantined,
                    bytes,
                    // Creation and every transition require a gap on each side;
                    // these are actual absent adjacent mappings, not guesses.
                    lower_neighbor: None,
                    upper_neighbor: None,
                }]),
            };
            request.check_mapping_binding(&record.original, &mapping.profile, until)?;
            Some(request)
        } else {
            None
        };
        if let Some(request) = &request {
            // PendingMapping already includes the internal request header. The
            // helper's one header accounts for the boxed client reply; its Arc
            // allocations are shared, and the source payload was charged above.
            let bytes = transitions::mapping_request_storage_bytes(request, false)?;
            self.census
                .account_external(
                    reservation,
                    BudgetCharge {
                        source_fact_bytes: bytes,
                        ..BudgetCharge::default()
                    },
                )
                .map_err(census_error)?;
        }
        let reply = request.as_ref().map(|request| {
            AdmissionReply::AcquireSources(Box::new(DynamicSourceRequest {
                token: request.token.clone(),
                images: Arc::clone(&request.images),
            }))
        });
        mapping.pending = Some(PendingMapping {
            record: mapping_index,
            reservation,
            revoked,
            request,
            source_page,
            state,
            until,
        });
        if let Some(reply) = reply {
            Ok(reply)
        } else {
            self.finish_mapping(owner, None, until)
        }
    }
}

// The original transition envelope already reserves retirement metadata. This
// mapping path retires before the original SYSCALL, so debit it at that boundary
// without charging a fictional copied live image or a second epoch transition.
fn retirement_storage(domain: &Domain) -> Result<usize, GateError> {
    let mut bytes = size_of::<super::super::domain::RetiredGeneration>();
    for (count, width) in [
        (
            domain
                .pages
                .values()
                .filter(|executable| **executable)
                .count(),
            size_of::<u64>(),
        ),
        (
            domain.guards.len(),
            size_of::<crate::trap_coverage::TrapGuard>(),
        ),
        (
            domain.sites.len(),
            size_of::<liteinst_admission::scan::Candidate>(),
        ),
    ] {
        bytes = count
            .checked_mul(width)
            .and_then(|extra| bytes.checked_add(extra))
            .ok_or_else(|| refused("mapping retirement size overflows"))?;
    }
    for guard in domain.guards.values() {
        bytes = bytes
            .checked_add(guard.original_bytes().len())
            .ok_or_else(|| refused("mapping retirement size overflows"))?;
    }
    Ok(bytes)
}

fn native_storage_bound(domain: &Domain, range_bytes: usize) -> Result<usize, GateError> {
    let mut bytes = MAP_CAPTURE_BYTES
        .checked_add(3 * 64 * 1024)
        .and_then(|value| value.checked_add(size_of::<VerifiedMappingExit>()))
        .and_then(|value| value.checked_add(size_of::<routes::MappingRevocation>()))
        .and_then(|value| value.checked_add(size_of::<PendingMapping>()))
        .and_then(|value| value.checked_add(range_bytes))
        .and_then(|value| value.checked_add("--xp".len() + "[vsyscall]".len()))
        .and_then(|value| {
            value.checked_add(
                size_of::<(u64, Arc<[u8]>)>()
                    + 2 * size_of::<usize>()
                    + size_of::<MemoryMapping>()
                    + 4,
            )
        })
        .ok_or_else(|| refused("mapping native evidence envelope overflows"))?;
    for image in &domain.images {
        bytes = bytes
            .checked_add(size_of::<(u64, Arc<[u8]>)>() + 2 * size_of::<usize>())
            .and_then(|value| value.checked_add(image.snapshot.bytes().len()))
            .ok_or_else(|| refused("mapping native evidence envelope overflows"))?;
    }
    for mapping in &domain.original_executables {
        bytes = bytes
            .checked_add(size_of::<MemoryMapping>())
            .and_then(|value| value.checked_add(mapping.permissions.len()))
            .and_then(|value| value.checked_add(mapping.pathname.as_ref().map_or(0, String::len)))
            .ok_or_else(|| refused("mapping native evidence envelope overflows"))?;
    }
    Ok(bytes)
}

fn owned_descriptor(
    maps: ParsedMaps<'_>,
    range: &Range<u64>,
    permissions: [u8; 4],
) -> Result<MemoryMapping, GateError> {
    let entry = maps
        .entries()
        .find(|entry| anonymous_identity(*entry, range) && entry.permissions.bytes() == permissions)
        .ok_or_else(|| refused("mapping source descriptor is not its exact captured VMA"))?;
    Ok(MemoryMapping {
        start: entry.start,
        end: entry.end,
        permissions: std::str::from_utf8(&permissions)
            .expect("literal permissions")
            .to_owned(),
        file_offset: entry.file_offset,
        pathname: None,
    })
}
