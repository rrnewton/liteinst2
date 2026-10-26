//! Frame consumption requires the real original rt_sigreturn transaction.
use super::super::super::signal_return;
use super::super::census::{OwnerConsumption, SignalReturnWitness};
use super::*;
use crate::selected::{Operation, SyscallAbi};

impl AdmissionOwner {
    pub(super) fn complete_signal_return(
        &mut self,
        owner: &mut Owner,
        decision: ProviderDecision,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        if !matches!(decision, ProviderDecision::Native) {
            return Err(GateError::Refused(
                "signal frame consumption requires genuine native rt_sigreturn",
            ));
        }
        let transaction = self
            .signals
            .as_ref()
            .ok_or(GateError::Refused("signal return has no launch profile"))?;
        let live = transaction.live.as_ref().ok_or(GateError::Refused(
            "signal return has no complete delivered frame",
        ))?;
        let pending = self.pending.as_ref().ok_or(GateError::Refused(
            "signal return has no provider invocation",
        ))?;
        let task = pending.token.task.task;
        if transaction.returned
            || transaction.pending.is_some()
            || !transaction.delivered
            || task != live.interrupted.task.task
            || pending.input.instruction().operation()
                != (Operation::Syscall {
                    abi: SyscallAbi::LinuxX64,
                })
            || pending.input.instruction().bytes() != [0x0f, 0x05]
            || pending.before.logical_pc != transaction.profile.restorer + 5
            || pending.before.registers.rsp != live.facts.address + 8
            || pending.before.registers.rax != libc::SYS_rt_sigreturn as u64
        {
            return Err(GateError::Refused(
                "signal return input is outside its exact native restorer phase",
            ));
        }
        let reservation = self.reserve_signal_return(owner)?;
        self.refresh_signal_frames(owner, reservation, until)?;
        let transaction = self.signals.as_ref().unwrap();
        let live = transaction.live.as_ref().unwrap();
        // Final-only requires every declared edit actually present. Prospective
        // origins protected the target earlier; they did not prove these bytes.
        live.captured
            .validate_current(live.facts.bytes.clone(), true)?;
        let expected = live
            .captured
            .expected_return(&raw_state(&live.interrupted), &transaction.profile)?;
        let frame = live.facts.id;
        let version = live.facts.version;
        let frame_origins = live.origins.clone();
        let pending = self.pending.take().unwrap();
        let window = {
            let mut held =
                HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
            routes::restore_original(
                &mut held,
                &self.domain,
                pending.before.logical_pc,
                pending.input.instruction().bytes(),
                until,
            )?
        };
        self.refresh_all_same_pc(owner, reservation, task, until)?;
        let before = self.observe_current(owner, task)?;
        if before.registers != pending.before.registers
            || before.xstate != pending.before.xstate
            || before.signal_mask != pending.before.signal_mask
            || before.phase != StopPhase::UserCheckpoint
        {
            return Err(GateError::Refused(
                "signal return restoration changed provider input",
            ));
        }
        self.check_signal_return_budget(owner, reservation)?;
        let live = self.signals.as_ref().unwrap().live.as_ref().unwrap();
        live.captured
            .validate_current(live.facts.bytes.clone(), true)?;
        if live.facts.id != frame || live.facts.version != version {
            return Err(GateError::Refused(
                "signal return frame version changed during original restoration",
            ));
        }
        let current = self.native.admission_current(task)?;
        let extent = self.signals.as_ref().unwrap().xstate_extent();
        self.signals.as_ref().unwrap().verify_extent(
            &current.token,
            current.identity,
            &expected,
        )?;
        // SAFETY: exact full frame/version, both saved-PC routes, singleton
        // exclusion, original SYSCALL RX window, bounded archive/reservation and
        // one consumed provider invocation. No lease spans original execution.
        let returned = unsafe {
            signal_return::execute(
                owner,
                &mut self.native,
                &self.island,
                &current,
                &pending.input,
                signal_return::ReturnStates {
                    before: &raw_state(&before),
                    expected: &expected,
                    extent,
                },
                until,
            )?
        };
        // The owner journal already retained every raw state and info byte even
        // if any following model/accounting/native bridge step refuses.
        let transaction = self.signals.as_ref().unwrap();
        transaction.verify_event_extent(&returned.entry, &returned.entry_state)?;
        transaction.verify_event_extent(&returned.exit, &returned.returned)?;
        let entry = observation(
            &returned.entry,
            &returned.entry_state,
            StopPhase::SyscallEntry {
                syscall: libc::SYS_rt_sigreturn as u64,
            },
        )?;
        let actual = observation(&returned.exit, &returned.returned, StopPhase::SignalReturn)?;
        let mut expected_observation = actual.clone();
        expected_observation.registers = expected.registers;
        expected_observation.xstate = expected.xstate;
        expected_observation.signal_mask = expected.mask;
        let witness = SignalReturnWitness {
            frame,
            entry: entry.clone(),
            returned: actual.clone(),
            expected: expected_observation,
            syscall_bytes: returned.syscall_bytes,
            syscall_count: returned.syscall_count,
        };
        for origin in frame_origins {
            self.census
                .consume_frame(reservation, origin, witness.clone())
                .map_err(census_error)?;
        }
        let origin = self.origins[&task];
        self.census
            .consume(
                reservation,
                origin,
                OwnerConsumption::signal_return(before, witness).map_err(census_error)?,
            )
            .map_err(census_error)?;
        let successor = self
            .census
            .insert_signal_current(reservation, actual.clone())
            .map_err(census_error)?;
        self.origins.insert(task, successor);
        self.census
            .check_signal_obligations(
                &self
                    .native
                    .check_admission_mm(owner, task)?
                    .candidate
                    .obligations,
            )
            .map_err(census_error)?;
        let transaction = self.signals.as_mut().unwrap();
        transaction.retired = transaction.live.take();
        transaction.returned = true;
        let stop = signal_return::bridge(owner, &mut self.native, &self.island, &returned, until)?;
        if self.native.admission_current(task)? != stop {
            return Err(GateError::Refused(
                "signal return neutral checkpoint changed",
            ));
        }
        self.refresh_all_same_pc(owner, reservation, task, until)?;
        self.rebind(owner, reservation, task, Some(window), until)?;
        // Rebind leaves every original page NX. In particular no return landing
        // executes before a subsequent actual fetch and normal admission plan.
        if self.domain.pages.values().any(|executable| *executable) {
            return Err(GateError::Refused(
                "signal return rebind retained executable original pages",
            ));
        }
        let retired = self
            .signals
            .as_ref()
            .unwrap()
            .retired
            .as_ref()
            .ok_or(GateError::Refused(
                "signal return lost its retained completed frame",
            ))?;
        if retired.facts.id != frame
            || retired.facts.version != version
            || self.census.active_frames().next().is_some()
        {
            return Err(GateError::Refused(
                "signal return frame retirement is incomplete or changed",
            ));
        }
        self.ready.insert(task);
        let event = DynamicSignalReturn {
            frame,
            version,
            input: pending.input,
            entry: dynamic_state(&entry),
            returned: dynamic_state(&actual),
            information: returned.information,
        };
        self.census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: event.entry.xstate.len()
                        + event.returned.xstate.len()
                        + std::mem::size_of::<DynamicSignalReturn>(),
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        self.metrics.selected.native_completions = self
            .metrics
            .selected
            .native_completions
            .checked_add(1)
            .ok_or(GateError::Refused(
                "signal native completion counter exhausted",
            ))?;
        let journal = owner.signal_journal.as_ref().unwrap();
        journal.phase(SignalJournalPhase::ReturnRearmed)?;
        journal.append(SignalJournalFact::Validated {
            phase: SignalJournalPhase::ReturnRearmed,
        })?;
        self.census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        Ok(AdmissionReply::Event(
            DynamicAdmissionEvent::SignalReturned(Box::new(event)),
        ))
    }
}

fn observation(
    event: &DynamicEvent,
    state: &TaskStateSnapshot,
    phase: StopPhase,
) -> Result<ObservedStop, GateError> {
    let token = event
        .stop_token()
        .ok_or(GateError::Refused(
            "signal kernel observation lacks an actual stop token",
        ))?
        .clone();
    let task = event.task.ok_or(GateError::Refused(
        "signal kernel observation lacks its task identity",
    ))?;
    Ok(ObservedStop {
        token,
        task,
        logical_pc: state.registers.rip,
        registers: state.registers,
        xstate: state.xstate.clone(),
        signal_mask: state.mask,
        phase,
        signal: None,
    })
}
