//! Root connection of real source, operand, native and consuming census proof.
use super::*;

impl RuntimeOwner {
    pub(super) fn stack(
        &mut self,
        owner: &mut Owner,
        index: usize,
        until: Instant,
    ) -> Result<(), GateError> {
        owner.time_left(until, "runtime owned stack preparation")?;
        if self.stage != RuntimeStage::Ready
            || self.selected_pending.is_some()
            || self.kernel_pending.is_some()
        {
            return Err(GateError::Refused("runtime stack operation is not ready"));
        }
        let origin = self
            .initial_origin
            .ok_or(GateError::Refused("runtime stack current origin absent"))?;
        let census = self
            .census
            .as_mut()
            .ok_or(GateError::Refused("runtime stack census absent"))?;
        let before = census.current_observation(origin).map_err(census_error)?;
        let native = self
            .native
            .as_mut()
            .ok_or(GateError::Refused("runtime stack native custody absent"))?;
        let stop = native.admission_current(before.task.task)?;
        let window = self
            .sources
            .window(index)
            .ok_or(GateError::Refused("runtime stack source window absent"))?;
        let candidate = classify(
            window.snapshot,
            &before.registers,
            DebugDisposition::Absent,
            &SyscallAliases::default(),
        )
        .map_err(|_| GateError::Refused("runtime stack classification differs"))?;
        if !stack_candidate(&candidate) {
            return Err(GateError::Refused(
                "runtime stack encoding is not qualified",
            ));
        }
        let geometry =
            maps::FetchGeometry::for_initial_source(window.initial_source(), candidate.range())?;
        geometry.projected_rows(self.sources.runtime_baseline_maps()?)?;
        let window_bytes = window.snapshot.bytes().len();
        let is_call = candidate.bytes()[0] == 0xe8;
        let charge = storage::attempt_charge(window_bytes, is_call)?;
        let serial = self.next_execution;
        let next = serial
            .checked_add(1)
            .ok_or(GateError::Refused("runtime execution identity exhausted"))?;
        ExecutionId::from_owner(stop.token.session, serial).map_err(census_error)?;
        let state = self
            .stack
            .as_mut()
            .ok_or(GateError::Refused("runtime stack profile is refused"))?;
        if !state.startup_complete
            || state.startup_settled != state.startup_actual
            || state.failure.is_some()
            || state.settlement_failure.is_some()
            || state.pending.is_some()
            || state.attempts.len() != state.capacity
            || state.count >= state.capacity
            || state.attempts[state.count].is_some()
            || state.count.checked_sub(1).is_some_and(|last| {
                state.attempts[last].as_ref().is_none_or(|attempt| {
                    attempt.stage != AttemptStage::Complete || attempt.failure.is_some()
                })
            })
        {
            return Err(GateError::Refused(
                "runtime stack retained attempt is not complete",
            ));
        }
        let next_slot = state
            .count
            .checked_add(1)
            .ok_or(GateError::Refused("runtime stack attempt serial overflows"))?;
        let reservation = census.reserve(charge).map_err(census_error)?;
        self.next_execution = next;
        state.pending = Some(PendingPreparation {
            reservation,
            origin,
            serial,
            until,
            stage: AttemptStage::Allocated,
            failure: None,
        });
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), GateError> {
                let before = census.current_observation(origin).map_err(census_error)?;
                let pending = state.pending.as_ref().expect("retained stack preparation");
                let empty = RuntimeStackAttempt::empty(
                    pending,
                    stop,
                    before,
                    geometry,
                    window_bytes,
                    is_call,
                );
                // Empty means no owned payload: a failed header allocation cannot
                // discard any earlier allocation. The pending reservation remains.
                #[cfg(test)]
                if state.fail_attempt_header {
                    return Err(GateError::Refused(
                        "injected stack attempt header allocation failure",
                    ));
                }
                let allocated = exact_storage::value(empty).map_err(allocation_error)?;
                state.attempts[state.count] = Some(allocated);
                state.count = next_slot;
                state.pending = None;
                let attempt = state.attempts[next_slot - 1]
                    .as_mut()
                    .expect("installed stack attempt");
                #[cfg(test)]
                if state.panic_after_attempt_header {
                    std::panic::panic_any(0x4845_4144_u32);
                }
                #[cfg(test)]
                if let Some(fault) = state
                    .allocation_config
                    .filter(|_| !state.allocation_config_used)
                {
                    attempt.configure_allocation(fault);
                    state.allocation_config_used = true;
                }
                attempt.allocate_and_settle(census)?;
                attempt.copy_before(census.current_observation(origin).map_err(census_error)?)?;
                #[cfg(test)]
                if let Some((point, kind)) = state.native_intervention.take() {
                    attempt.native.set_intervention(point, kind)?;
                }
                let island = &self
                    .bootstrap
                    .as_ref()
                    .and_then(PreparedInitialBootstrap::completed)
                    .ok_or(GateError::Refused("runtime stack bootstrap custody absent"))?
                    .island;
                let lineage = self
                    .control_lineage
                    .as_ref()
                    .ok_or(GateError::Refused("runtime stack control lineage absent"))?;
                let (original, progress) = self.sources.original_maps();
                let original = initial_maps_prefix(original, progress)?;
                attempt.stage = AttemptStage::Source;
                let proof = {
                    let reader = self.sources.runtime_read(
                        owner,
                        native,
                        island,
                        &attempt.stop,
                        &attempt.before,
                        until,
                    )?;
                    reader.verify_window(
                        index,
                        &mut attempt.source.bytes[0],
                        &mut attempt.source.progress[0],
                        &mut attempt.source.identity,
                    )?
                };
                let candidate = classify(
                    proof.window().snapshot,
                    &attempt.before.registers,
                    DebugDisposition::Absent,
                    &SyscallAliases::default(),
                )
                .map_err(|_| GateError::Refused("runtime stack source classification changed"))?;
                let initial = state.profile.identity()?;
                attempt.stage = AttemptStage::Operand;
                let request = StackRequest {
                    original_maps: original,
                    origin: attempt.origin,
                    serial: attempt.serial,
                    island,
                    lineage,
                };
                {
                    let context = StackBeforeContext::new(&proof, &candidate, census, request)?;
                    attempt.native.prepare_before_and_operand(
                        owner,
                        native,
                        &context,
                        &initial,
                        &mut attempt.operand,
                    )?;
                }
                let binding = RuntimeStackBinding::new(
                    proof,
                    candidate,
                    census,
                    request,
                    initial,
                    attempt.operand.operand()?,
                )?;
                attempt.stage = AttemptStage::Census;
                let prepared = attempt
                    .census
                    .as_mut()
                    .ok_or(GateError::Refused("runtime stack census storage absent"))?;
                census
                    .prepare_stack(reservation, &binding, prepared)
                    .map_err(census_error)?;
                let remaining = prepared.remaining_charge().map_err(census_error)?;
                census
                    .check_reserved(reservation, remaining)
                    .map_err(census_error)?;
                let recorded = if is_call {
                    let call = attempt
                        .call
                        .as_mut()
                        .ok_or(GateError::Refused("runtime stack CALL storage absent"))?;
                    state
                        .calls
                        .prepare(census, reservation, &binding, call)
                        .map_err(census_error)?;
                    Some(
                        state
                            .calls
                            .append_before_opening(census, &mut attempt.call, &binding)
                            .map_err(census_error)?,
                    )
                } else {
                    None
                };
                #[cfg(test)]
                if let Some(record) = &recorded {
                    if let Some(observe) = state.before_opening {
                        observe(
                            owner,
                            native,
                            record,
                            &binding,
                            &attempt.native,
                            census,
                            &self.sources,
                        )?;
                    }
                    if state.intervention == Some(RootIntervention::AfterCallRecordPanic) {
                        std::panic::panic_any(0x4341_4c4c_u32);
                    }
                }
                {
                    let mut observer = SourceObserver {
                        sources: &self.sources,
                        binding: &binding,
                        census,
                        reservation,
                        remaining,
                        storage: &mut attempt.source,
                        #[cfg(test)]
                        refuse_closed: state.intervention
                            == Some(RootIntervention::RefuseClosedObserver),
                    };
                    attempt.stage = AttemptStage::Native;
                    // SAFETY: the public opt-in supplies original-stack writer/alias
                    // custody. Native authenticates actual A/B/C/D, current source,
                    // full state and all seven real waits before issuing its seal.
                    unsafe {
                        runtime_stack_native::execute_owned_stack(
                            owner,
                            native,
                            &binding,
                            recorded,
                            &mut attempt.native,
                            &mut observer,
                        )?;
                    }
                }
                attempt.stage = AttemptStage::Commit;
                let completed = attempt.native.take_completed(&binding)?;
                let next_lineage = lineage.stack_successor(&completed)?;
                // Preflight the exact finish token before atomic census mutation.
                census
                    .check_reserved(reservation, BudgetCharge::default())
                    .map_err(census_error)?;
                let result = census
                    .commit_stack(
                        reservation,
                        completed,
                        prepared,
                        &state.calls,
                        &self.sources,
                    )
                    .map_err(census_error)?;
                // No allocation, native request, callback or fallible operation
                // separates census commitment from these two root installations.
                drop(binding);
                self.initial_origin = Some(result.current);
                self.control_lineage = Some(next_lineage);
                census
                    .finish_reservation(reservation)
                    .map_err(census_error)?;
                attempt.stage = AttemptStage::Complete;
                Ok(())
            }));
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                let failure = Failure::from_gate(&error);
                state.failure.get_or_insert(failure);
                if let Some(pending) = &mut state.pending {
                    pending.failure.get_or_insert(failure);
                }
                if let Some(attempt) = state.attempts[next_slot - 1].as_mut() {
                    attempt.settle_unstarted_header(census);
                    attempt.failure.get_or_insert(failure);
                }
                Err(error)
            }
            Err(panic) => {
                state.failure.get_or_insert(Failure::Unwound);
                if let Some(pending) = &mut state.pending {
                    pending.failure.get_or_insert(Failure::Unwound);
                }
                if let Some(attempt) = state.attempts[next_slot - 1].as_mut() {
                    attempt.settle_unstarted_header(census);
                    attempt.failure.get_or_insert(Failure::Unwound);
                    attempt.native.mark_aborted();
                    attempt.operand.mark_aborted();
                    if let Some(prepared) = &mut attempt.census {
                        prepared.mark_aborted();
                    }
                    if let Some(call) = &mut attempt.call {
                        call.mark_aborted();
                    }
                }
                std::panic::resume_unwind(panic)
            }
        }
    }
}
