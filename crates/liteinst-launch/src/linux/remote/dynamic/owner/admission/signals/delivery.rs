//! One original queued signal, delivered from a closed syscall-free boundary.
use super::super::super::trusted::{AdmissionPhase, TrapExpectation};
use super::super::census::{OwnerConsumption, Reservation};
use super::*;
use crate::gate::domain::PAGE;

impl AdmissionOwner {
    pub(super) fn prepare_signal_pending(
        &mut self,
        owner: &Owner,
        reservation: Reservation,
        event: DynamicEvent,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let transaction = self.signals.as_ref().ok_or(GateError::Refused(
            "signal transaction was not selected at launch",
        ))?;
        if !transaction.is_setup_ready()
            || transaction.delivered
            || transaction.returned
            || transaction.pending.is_some()
            || transaction.live.is_some()
            || self.pending.is_some()
            || self.running.len() != 1
            || !self.work.is_empty()
            || !self.ready.is_empty()
        {
            return Err(GateError::Refused(
                "signal arrived outside the single declared original boundary",
            ));
        }
        let task = event
            .task
            .ok_or(GateError::Refused("original signal lacks task identity"))?;
        let (held, obligation) = self.native.admission_original_signal(task.task)?;
        if held != event {
            return Err(GateError::Refused("original signal event is stale"));
        }
        let DynamicEventKind::SignalDelivery(signal) = &event.kind else {
            return Err(GateError::Refused(
                "signal transaction received another event",
            ));
        };
        let before = self.observe_current(owner, task.task)?;
        if signal.signal() != i32::from(transaction.profile.signal)
            || signal.code() != libc::SI_QUEUE
            || signal.errno() != 0
            || signal.value() != Some(transaction.profile.queued_value)
            || signal.sender_pid() != Some(unsafe { libc::getpid() })
            || signal.sender_uid() != Some(unsafe { libc::getuid() })
            || before.phase != StopPhase::OriginalSignal
            || before.logical_pc != transaction.profile.delivery_pc
            || before.registers.orig_rax != u64::MAX
            || before.registers.eflags & (0x100 | 0x10000) != 0
            || before.signal_mask & (1_u64 << (transaction.profile.signal - 1)) != 0
            || self.domain.original_decode(before.logical_pc)? != [0xeb, 0xfe]
            || read_memory(event.tid, before.logical_pc, 2)? != [0xeb, 0xfe]
        {
            return Err(GateError::Refused(
                "original signal identity, payload, source or exact boundary differs",
            ));
        }
        let members = self.native.check_admission_mm(owner, task.task)?;
        if members.candidate.tasks != vec![task.task]
            || members.candidate.obligations != vec![obligation.clone()]
        {
            return Err(GateError::Refused(
                "signal delivery has another task or unresolved obligation",
            ));
        }
        self.require_signal_pages_nx(event.tid)?;
        let permit = self
            .running
            .get(&task.task)
            .ok_or(GateError::Refused("signal has no original-run permit"))?;
        let old = *self.origins.get(&task.task).ok_or(GateError::Refused(
            "signal has no retained original register origin",
        ))?;
        self.census
            .check_current_origin(old, &permit.before)
            .map_err(census_error)?;
        let consumption = OwnerConsumption::signal_rendezvous(
            permit.id,
            permit.before.clone(),
            permit.first_instruction.clone(),
            before.clone(),
        )
        .map_err(census_error)?;
        self.census
            .consume(reservation, old, consumption)
            .map_err(census_error)?;
        let next = self
            .census
            .insert_signal_current(reservation, before.clone())
            .map_err(census_error)?;
        self.origins.insert(task.task, next);
        self.running.remove(&task.task);
        let (serial, _) = self.execution_id(owner.session)?;
        let token = SignalDeliveryToken {
            stop: before.token.clone(),
            task,
            plan: self.domain.generation,
            serial,
            until,
        };
        let reply = DynamicSignalPending {
            token: token.clone(),
            state: dynamic_state(&before),
            signal: signal.clone(),
        };
        self.census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: 2 * before.xstate.len()
                        + std::mem::size_of::<PendingDelivery>()
                        + std::mem::size_of::<DynamicSignalPending>(),
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        let journal = owner.signal_journal.as_ref().ok_or(GateError::Refused(
            "signal journal was not reserved before launch",
        ))?;
        journal.phase(SignalJournalPhase::DeliveryPending)?;
        journal.append(SignalJournalFact::Validated {
            phase: SignalJournalPhase::DeliveryPending,
        })?;
        self.signals.as_mut().unwrap().pending = Some(PendingDelivery {
            token,
            event,
            obligation,
            observed: before,
        });
        self.census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        Ok(AdmissionReply::Event(DynamicAdmissionEvent::SignalPending(
            Box::new(reply),
        )))
    }

    fn require_signal_pages_nx(&self, tid: i32) -> Result<(), GateError> {
        let profile = &self
            .signals
            .as_ref()
            .ok_or(GateError::Refused("signal profile absent"))?
            .profile;
        let maps = read_maps(tid)?;
        for pc in [
            Some(profile.handler),
            Some(profile.restorer),
            profile.frame_edits.as_ref().map(|edit| edit.landing_pc),
        ]
        .into_iter()
        .flatten()
        {
            let page = pc & !(PAGE - 1);
            if self.domain.pages.get(&page) != Some(&false)
                || !maps.iter().any(|map| {
                    map.start <= page
                        && page + PAGE <= map.end
                        && map.permissions.as_bytes().get(1) == Some(&b'-')
                        && map.permissions.as_bytes().get(2) == Some(&b'-')
                        && map.permissions.as_bytes().get(3) == Some(&b'p')
                })
            {
                return Err(GateError::Refused(
                    "declared signal target is not an original immutable NX page",
                ));
            }
        }
        for image in &self.domain.images {
            if read_memory(tid, image.mapping.start, image.snapshot.bytes().len())?
                != self.domain.expected_image(image)
            {
                return Err(GateError::Refused(
                    "signal delivery original source changed",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn deliver_signal(
        &mut self,
        owner: &mut Owner,
        token: SignalDeliveryToken,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let result = self.deliver_signal_inner(owner, token, until);
        if result.is_err() {
            self.closed = true;
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
        }
        result
    }

    fn deliver_signal_inner(
        &mut self,
        owner: &mut Owner,
        token: SignalDeliveryToken,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let transaction = self
            .signals
            .as_ref()
            .ok_or(GateError::Refused("signal transaction is absent"))?;
        let pending = transaction.pending.as_ref().ok_or(GateError::Refused(
            "signal delivery has no pending original event",
        ))?;
        if pending.token != token
            || token.until != until
            || token.plan != self.domain.generation
            || token.task.generation != self.domain.generation
            || !self.running.is_empty()
            || self.pending.is_some()
            || !self.work.is_empty()
            || !self.ready.is_empty()
            || !self.native.admission_events_empty()
        {
            return Err(GateError::Refused(
                "signal delivery token, deadline or held phase is stale",
            ));
        }
        owner.time_left(until, "original signal delivery")?;
        let current = self.observe_current(owner, token.task.task)?;
        if current != pending.observed
            || self.native.admission_original_signal(token.task.task)?
                != (pending.event.clone(), pending.obligation.clone())
        {
            return Err(GateError::Refused(
                "signal delivery full held state or obligation changed",
            ));
        }
        self.require_signal_pages_nx(token.stop.tid)?;
        let frame_origins = 1 + usize::from(transaction.profile.frame_edits.is_some());
        let reservation = self.reserve_signal_delivery(owner, frame_origins)?;
        let profile = self.signals.as_ref().unwrap().profile.clone();
        let metadata = self.signals.as_ref().unwrap().metadata;
        let mut origin_slots = Vec::new();
        origin_slots
            .try_reserve_exact(frame_origins)
            .map_err(|_| GateError::Refused("signal frame origin allocation failed"))?;
        let pending = self.signals.as_mut().unwrap().pending.take().unwrap();
        let frame_storage =
            self.signals
                .as_mut()
                .unwrap()
                .frame_storage
                .take()
                .ok_or(GateError::Refused(
                    "signal projection storage was already consumed",
                ))?;
        let journal = owner.signal_journal.as_ref().unwrap().clone();
        journal.phase(SignalJournalPhase::DeliveryRelease)?;
        journal.append(SignalJournalFact::ReleaseAttempt {
            token: (&token.stop).into(),
        })?;
        // SAFETY: exact singleton, original raw siginfo/token, immutable source,
        // still-NX handler/restorer/landing and pre-reserved entire transaction.
        // There is no publication lease or generic suppression/reclassification.
        unsafe {
            self.native.resume_admission_event(
                owner,
                &token.stop,
                DynamicResume::DeliverOriginal,
            )?;
        }
        journal.append(SignalJournalFact::Released {
            token: (&token.stop).into(),
        })?;
        let (tid, status) = owner.wait_raw(until, "original signal handler NX fetch")?;
        journal.phase(SignalJournalPhase::HandlerFetch)?;
        let (_, fetch_state) = journal.capture_signal_state(tid, status)?;
        if tid != token.stop.tid {
            return Err(GateError::Refused("signal delivery changed native task"));
        }
        let stop = self.native.observe_admission_owned(
            owner,
            tid,
            status,
            TrapExpectation::Fetch {
                pc: profile.handler,
                page: profile.handler & !(PAGE - 1),
            },
        )?;
        let fetch = self.observe_current(owner, token.task.task)?;
        if raw_state(&fetch) != fetch_state || stop.phase != AdmissionPhase::Fetch {
            return Err(GateError::Refused(
                "signal handler raw fetch changed during authentication",
            ));
        }
        self.metrics.fetch_faults = self
            .metrics
            .fetch_faults
            .checked_add(1)
            .ok_or(GateError::Refused("signal handler fetch counter exhausted"))?;
        let DynamicEventKind::SignalDelivery(signal) = pending.event.kind else {
            unreachable!()
        };
        let frame_id = SignalFrameId {
            session: owner.session,
            serial: token.serial,
        };
        journal.phase(SignalJournalPhase::FrameCapture)?;
        let captured = frame::CapturedFrame::read_with_storage(
            |address, length| Ok(journal.capture_frame(tid, address, length, until)?),
            frame_id,
            &profile,
            frame::DeliveryStates {
                interrupted: &raw_state(&pending.observed),
                fetch: &fetch_state,
            },
            &signal,
            metadata,
            frame_storage,
        )?;
        journal.phase(SignalJournalPhase::Projection)?;
        {
            let mut held = HeldMmStop::acquire(
                owner,
                &mut self.native,
                &mut self.island,
                token.task.task,
                until,
            )?;
            // The exception projection writes exactly the three native words.
            // All neighboring frame bytes are reread by the checked write.
            for offset in [200_usize, 208, 224] {
                held.write_memory_checked(
                    captured.raw.address + offset as u64,
                    &captured.raw.bytes[offset..offset + 8],
                    &captured.projected.bytes[offset..offset + 8],
                )?;
            }
        }
        if journal.capture_frame(
            tid,
            captured.projected.address,
            captured.projected.bytes.len(),
            until,
        )? != captured.projected.bytes
        {
            return Err(GateError::Refused(
                "signal exception projection changed another frame byte",
            ));
        }
        self.census
            .record_delivery(
                reservation,
                frame_id,
                pending.obligation.clone(),
                pending.observed.clone(),
                fetch.clone(),
            )
            .map_err(census_error)?;
        let old = self.origins[&token.task.task];
        self.census
            .consume(
                reservation,
                old,
                OwnerConsumption::signal_delivery(
                    frame_id,
                    pending.observed.clone(),
                    fetch.clone(),
                )
                .map_err(census_error)?,
            )
            .map_err(census_error)?;
        let current_origin = self
            .census
            .insert(
                reservation,
                OriginKind::CurrentHeldPc,
                fetch.logical_pc,
                fetch.clone(),
            )
            .map_err(census_error)?;
        self.origins.insert(token.task.task, current_origin);
        let facts = Arc::new(census::FrameFacts {
            id: frame_id,
            version: 1,
            address: captured.projected.address,
            bytes: captured.projected.bytes.clone(),
            original_pc: pending.observed.logical_pc,
            prospective_pc: profile.frame_edits.as_ref().map(|edit| edit.landing_pc),
            obligation: pending.obligation,
        });
        for prospective in [false, true].into_iter().take(frame_origins) {
            origin_slots.push(
                self.census
                    .insert_frame(reservation, Arc::clone(&facts), prospective, fetch.clone())
                    .map_err(census_error)?,
            );
        }
        self.signals.as_mut().unwrap().live = Some(LiveFrame {
            captured,
            facts,
            origins: origin_slots,
            interrupted: pending.observed.clone(),
        });
        self.signals.as_mut().unwrap().delivered = true;
        // Complete frame origins exist before the first private runner or X
        // publication can rely on their original or prospective saved PC.
        self.settle_private_controls(owner, reservation, until)?;
        self.rebind(owner, reservation, token.task.task, None, until)?;
        self.publish_page(
            owner,
            reservation,
            token.task.task,
            profile.handler & !(PAGE - 1),
            until,
        )?;
        self.reach_signal_handler_guard(
            owner,
            reservation,
            pending.observed,
            fetch_state,
            signal,
            until,
        )
    }

    fn reach_signal_handler_guard(
        &mut self,
        owner: &mut Owner,
        reservation: Reservation,
        interrupted: ObservedStop,
        fetch_state: TaskStateSnapshot,
        signal: DynamicSignalInfo,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let task = interrupted.task.task;
        let handler = self.signals.as_ref().unwrap().profile.handler;
        let journal = owner.signal_journal.as_ref().unwrap().clone();
        self.ready.insert(task);
        self.release_ready(owner, until)?;
        let (tid, status) = owner.wait_raw(until, "original signal handler owned guard")?;
        journal.phase(SignalJournalPhase::HandlerGuard)?;
        let (raw_siginfo, raw_guard) = journal.capture_signal_state(tid, status)?;
        if tid != interrupted.token.tid {
            return Err(GateError::Refused(
                "signal handler guard changed native task",
            ));
        }
        let stop = self.native.observe_admission_owned(
            owner,
            tid,
            status,
            TrapExpectation::Guard { address: handler },
        )?;
        let guard = self.observe_current(owner, task)?;
        if stop.phase != AdmissionPhase::Guard
            || guard.logical_pc != handler
            || raw_state(&guard) != raw_guard
            || guard.signal.as_ref().map(DynamicSignalInfo::raw_bytes) != Some(&raw_siginfo)
        {
            return Err(GateError::Refused(
                "signal handler guard raw identity differs",
            ));
        }
        self.metrics.guard_stops = self
            .metrics
            .guard_stops
            .checked_add(1)
            .ok_or(GateError::Refused("signal handler guard counter exhausted"))?;
        self.reconcile_running(owner, reservation, task, until)?;
        self.normalize_guards(owner, reservation, until)?;
        let ready = self.observe_current(owner, task)?;
        let mut expected = raw_guard.registers;
        expected.rip = handler;
        if ready.phase != StopPhase::UserCheckpoint
            || ready.registers != expected
            || ready.xstate != raw_guard.xstate
            || ready.signal_mask != raw_guard.mask
            || ready.registers.eflags & (0x100 | 0x10000) != 0
        {
            return Err(GateError::Refused(
                "signal handler logical checkpoint differs from its actual owned guard",
            ));
        }
        self.work
            .push_back(PendingWork::Guard { task, pc: handler });
        let live = self.signals.as_ref().unwrap().live.as_ref().unwrap();
        self.census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: live.captured.raw.bytes.len()
                        + live.captured.projected.bytes.len()
                        + interrupted.xstate.len()
                        + fetch_state.xstate.len()
                        + guard.xstate.len()
                        + ready.xstate.len()
                        + std::mem::size_of::<DynamicSignalEntry>()
                        + std::mem::size_of::<PendingWork>(),
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        let entry = DynamicSignalEntry {
            interrupted: dynamic_state(&interrupted),
            handler_fetch: DynamicAdmissionState {
                task: interrupted.task,
                registers: fetch_state.registers,
                xstate: fetch_state.xstate,
                signal_mask: fetch_state.mask,
            },
            handler_guard: dynamic_state(&guard),
            handler_guard_signal: DynamicSignalInfo { raw: raw_siginfo },
            handler: dynamic_state(&ready),
            signal,
            original_metadata: self.signals.as_ref().unwrap().metadata,
            raw_frame: live.captured.raw.clone(),
            projected_frame: live.captured.projected.clone(),
        };
        journal.phase(SignalJournalPhase::HandlerReady)?;
        journal.append(SignalJournalFact::Validated {
            phase: SignalJournalPhase::HandlerReady,
        })?;
        self.census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        Ok(AdmissionReply::SignalEntered(Box::new(entry)))
    }
}
