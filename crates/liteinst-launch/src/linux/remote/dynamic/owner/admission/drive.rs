//! Original-user event loop. Every release is separately sealed; all mutable
//! publication and continuation work takes place with the entire mm held.
use super::super::trusted::TrapExpectation;
use super::census::Reservation;
use super::*;
use crate::gate::domain::PAGE;
use crate::trap_coverage::TrapGuardRole;

/// Source lookup proposes an ownership class only. The native dispatcher then
/// independently checks raw siginfo, exact current task, permissions and bytes.
fn classify(
    domain: &Domain,
    tid: i32,
    status: i32,
) -> Result<Option<TrapExpectation>, LaunchError> {
    if !libc::WIFSTOPPED(status) || status >> 16 != 0 {
        return Ok(None);
    }
    let signal = libc::WSTOPSIG(status);
    if !matches!(signal, libc::SIGSEGV | libc::SIGTRAP) {
        return Ok(None);
    }
    let registers = read_registers(tid)?;
    let mut raw = [0_u8; 128];
    ptrace(libc::PTRACE_GETSIGINFO, tid, 0, raw.as_mut_ptr() as usize)?;
    let information = DynamicSignalInfo { raw };
    if signal == libc::SIGSEGV {
        // This finite route covers a fault whose head page is NX. A fault on a
        // later fetch page is not relabelled as one at the head and closes via
        // the original application-signal path until independently qualified.
        let page = registers.rip & !(PAGE - 1);
        if domain.pages.get(&page) != Some(&false) || information.code() != 2 {
            return Ok(None);
        }
        // SAFETY: GETSIGINFO initialized the complete native object.
        let native = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast::<libc::siginfo_t>()) };
        if unsafe { native.si_addr() } as usize as u64 != registers.rip {
            return Ok(None);
        }
        domain
            .original_decode(registers.rip)
            .map_err(|_| LaunchError::Invalid("owned fetch lacks its certified original head"))?;
        return Ok(Some(TrapExpectation::Fetch {
            pc: registers.rip,
            page,
        }));
    }
    if !matches!(information.code(), libc::SI_KERNEL | libc::TRAP_BRKPT) {
        return Ok(None);
    }
    let Some(pc) = registers.rip.checked_sub(1) else {
        return Ok(None);
    };
    let Some(guard) = domain.guards.get(&pc) else {
        return Ok(None);
    };
    if domain.pages.get(&(pc & !(PAGE - 1))) != Some(&true)
        || domain
            .original_decode(pc)
            .map_err(|_| LaunchError::Invalid("owned guard lacks original head"))?
            != guard.original_bytes()
        || read_memory(tid, pc, guard.original_bytes().len())?
            != domain.expected_instruction(pc, guard.original_bytes())
    {
        return Err(LaunchError::Invalid(
            "owned guard full source or permission metadata differs",
        ));
    }
    Ok(Some(TrapExpectation::Guard { address: pc }))
}

impl AdmissionOwner {
    /// Apply one pending plan while retaining the caller's pre-mutation lifetime
    /// reservation. Hidden island stops are immediately reflected in the census.
    pub(super) fn publish_page(
        &mut self,
        owner: &mut Owner,
        reservation: Reservation,
        selected: TaskId,
        page: u64,
        until: Instant,
    ) -> Result<(), GateError> {
        if self.domain.pages.get(&page) != Some(&false) {
            return Err(GateError::Refused(
                "dynamic requested publication page is not NX",
            ));
        }
        self.settle_private_controls(owner, reservation, until)?;
        let started = Instant::now();
        let plan = self.domain.plan(page, until)?;
        self.account_plan(reservation, &plan)?;
        let id = self.domain.allocate_plan_id()?;
        self.metrics.pages.first_touch.try_reserve(1).map_err(|_| {
            GateError::Refused("dynamic publication timing history allocation failed")
        })?;
        {
            let mut held =
                HeldMmStop::acquire(owner, &mut self.native, &mut self.island, selected, until)?;
            routes::publish(&mut held, &mut self.domain, &self.census, plan, id, until)?;
        }
        self.refresh_all_same_pc(owner, reservation, selected, until)?;
        self.metrics.pages.first_touch.push(started.elapsed());
        self.metrics.pages.admitted_pages =
            self.domain.pages.values().filter(|value| **value).count();
        self.metrics.pages.untouched_pages =
            self.domain.pages.len() - self.metrics.pages.admitted_pages;
        self.metrics.pages.covered_candidates = self
            .domain
            .guards
            .values()
            .filter(|guard| matches!(guard.role(), TrapGuardRole::Selected(_)))
            .count();
        self.metrics.pages.collateral_guards = self
            .domain
            .guards
            .values()
            .filter(|guard| guard.role() == TrapGuardRole::Collateral)
            .count();
        Ok(())
    }

    pub(super) fn advance(
        &mut self,
        owner: &mut Owner,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        loop {
            owner.time_left(until, "dynamic admission next event")?;
            if let Some(event) = self.diagnostics.pop_front() {
                return Ok(AdmissionReply::Event(DynamicAdmissionEvent::Lifecycle(
                    event,
                )));
            }
            if let Some(work) = self.work.pop_front() {
                match work {
                    PendingWork::Fetch { task, page } => {
                        if self.domain.pages.get(&page) == Some(&false) {
                            let reservation = self.reserve_transition(0, false, 1)?;
                            self.publish_page(owner, reservation, task, page, until)?;
                            self.census
                                .finish_reservation(reservation)
                                .map_err(census_error)?;
                        }
                        self.ready.insert(task);
                    }
                    PendingWork::Guard { task, pc } => {
                        // Only accept work produced below by a real owned INT3.
                        // Normalization and any full-domain rebind preserve that
                        // observation in the immutable census history. They do
                        // not create a second original invocation or callback.
                        let page = pc & !(PAGE - 1);
                        if self.domain.pages.get(&page) == Some(&false) {
                            let reservation = self.reserve_transition(0, false, 1)?;
                            self.publish_page(owner, reservation, task, page, until)?;
                            self.census
                                .finish_reservation(reservation)
                                .map_err(census_error)?;
                        }
                        let guard = self
                            .domain
                            .guards
                            .get(&pc)
                            .ok_or(GateError::Refused("dynamic queued guard was not rearmed"))?
                            .clone();
                        if guard.role() == TrapGuardRole::Collateral {
                            if let Some(reply) = self.complete_collateral(owner, task, pc, until)? {
                                return Ok(reply);
                            }
                            continue;
                        }
                        return self.prepare_provider(owner, task, pc, until);
                    }
                }
                continue;
            }
            if self.ready.is_empty() || !self.running.is_empty() {
                return Err(GateError::Refused(
                    "dynamic event loop has no complete held release set",
                ));
            }
            // Reserve every possible retained continuation, old/new state and
            // generation receipt before any original task can execute. Unused
            // lifetime budget is intentionally not refunded.
            let reservation = self.reserve_transition(2, true, 0)?;
            if self
                .ready
                .iter()
                .any(|task| self.native.admission_original_interrupt(*task).is_ok())
            {
                // A generic user interruption cannot run a private island. Give
                // it a real NX boundary while an existing qualified runner stays
                // held, even when no entry projection otherwise changed.
                let selected = self
                    .origins
                    .keys()
                    .copied()
                    .find(|task| self.native.admission_current(*task).is_ok())
                    .ok_or(GateError::Refused(
                        "dynamic release has no authenticated private runner",
                    ))?;
                let tasks = self
                    .native
                    .check_admission_mm(owner, selected)?
                    .candidate
                    .tasks;
                self.rebind(owner, reservation, selected, None, until)?;
                self.collect_interrupted_boundaries(owner, reservation, &tasks, until)?;
                self.settle_private_controls(owner, reservation, until)?;
                self.census
                    .finish_reservation(reservation)
                    .map_err(census_error)?;
                continue;
            }
            self.settle_private_controls(owner, reservation, until)?;
            self.release_ready(owner, until)?;
            let (tid, status) = owner.wait_raw(until, "dynamic original user execution")?;
            let first = if let Some(expected) = classify(&self.domain, tid, status)? {
                Some(
                    self.native
                        .observe_admission_owned(owner, tid, status, expected)?,
                )
            } else {
                let event = self
                    .native
                    .observe_admission_other(owner, tid, status)?
                    .ok_or(GateError::Refused(
                        "dynamic original run produced an unresolved native event",
                    ))?;
                if let Some(reply) = self.handle_generic(owner, reservation, event)? {
                    return Ok(reply);
                }
                None
            };
            let selected = first
                .as_ref()
                .map(|stop| stop.identity.task)
                .or_else(|| self.running.keys().copied().next())
                .ok_or(GateError::Refused(
                    "dynamic native stop has no issued original run",
                ))?;
            let (_, mut observed) =
                self.native
                    .collect_admission_mm(owner, selected, until, |tid, status| {
                        classify(&self.domain, tid, status)
                    })?;
            if let Some(first) = first {
                observed.insert(0, first);
            }
            while let Some(event) = self.native.take_admission_event() {
                if let Some(reply) = self.handle_generic(owner, reservation, event)? {
                    return Ok(reply);
                }
            }
            let tasks = self
                .native
                .check_admission_mm(owner, selected)?
                .candidate
                .tasks;
            // Reconcile every original-run origin before a private instruction
            // can change a stop sequence or normalize a raw guard RIP.
            for &task in &tasks {
                self.reconcile_running(owner, reservation, task, until)?;
            }
            if !self.running.is_empty() {
                return Err(GateError::Refused(
                    "dynamic collection did not retire every issued run permit",
                ));
            }
            // Capture the raw owned event before normalization. All producer
            // paths above independently authenticated the same source domain.
            self.work
                .try_reserve(observed.len())
                .map_err(|_| GateError::Refused("dynamic owned-event work allocation failed"))?;
            self.census
                .account_external(
                    reservation,
                    BudgetCharge {
                        source_fact_bytes: observed
                            .len()
                            .checked_mul(std::mem::size_of::<PendingWork>())
                            .ok_or(GateError::Refused(
                                "dynamic owned-event work size overflows",
                            ))?,
                        ..BudgetCharge::default()
                    },
                )
                .map_err(census_error)?;
            for stop in observed {
                let counter = match stop.phase {
                    AdmissionPhase::Fetch => &mut self.metrics.fetch_faults,
                    AdmissionPhase::Guard => &mut self.metrics.guard_stops,
                    _ => {
                        return Err(GateError::Refused(
                            "dynamic collected stop has no owned counter class",
                        ));
                    }
                };
                *counter = counter
                    .checked_add(1)
                    .ok_or(GateError::Refused("dynamic owned stop counter exhausted"))?;
                let raw = TaskStateSnapshot::read(stop.token.tid)?;
                let work = match stop.phase {
                    AdmissionPhase::Fetch => PendingWork::Fetch {
                        task: stop.identity.task,
                        page: raw.registers.rip & !(PAGE - 1),
                    },
                    AdmissionPhase::Guard => PendingWork::Guard {
                        task: stop.identity.task,
                        pc: raw
                            .registers
                            .rip
                            .checked_sub(1)
                            .ok_or(GateError::Refused("dynamic owned guard PC underflows"))?,
                    },
                    _ => {
                        return Err(GateError::Refused(
                            "dynamic collection returned another owned phase",
                        ));
                    }
                };
                self.work.push_back(work);
            }
            self.normalize_guards(owner, reservation, until)?;
            self.settle_private_controls(owner, reservation, until)?;
            // Entry facts are immutable at one mapping/generation/version. A
            // changed projection requires real NX/restore/sync before rebinding.
            let entries = self
                .domain
                .images
                .iter()
                .map(|image| image.entries.clone())
                .collect::<Vec<_>>();
            if self.census.validate_projection(&entries).is_err() {
                self.rebind(owner, reservation, selected, None, until)?;
            }
            self.collect_interrupted_boundaries(owner, reservation, &tasks, until)?;
            self.settle_private_controls(owner, reservation, until)?;
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
            self.census
                .finish_reservation(reservation)
                .map_err(census_error)?;
            for task in tasks {
                if !self.work.iter().any(|work| match work {
                    PendingWork::Fetch {
                        task: work_task, ..
                    }
                    | PendingWork::Guard {
                        task: work_task, ..
                    } => *work_task == task,
                }) {
                    self.ready.insert(task);
                }
            }
        }
    }

    /// An interrupt racing the second runnable task is not a second fetch
    /// fault. Before granting X to a shared page, let that exact same-PC user
    /// interruption reach its still-NX head while every other task stays held.
    /// On an already-X page an installed guard can likewise supply a real INT3
    /// without executing the selected original instruction or an extra callback.
    /// Each release receives a fresh seal/RunPermit; the bounded control-credit
    /// stops are recorded as interruptions, and only a real fault enters work.
    pub(super) fn collect_interrupted_boundaries(
        &mut self,
        owner: &mut Owner,
        reservation: Reservation,
        tasks: &[TaskId],
        until: Instant,
    ) -> Result<(), GateError> {
        for &task in tasks {
            let Ok(event) = self.native.admission_original_interrupt(task) else {
                continue;
            };
            let before = self.observe_current(owner, task)?;
            let page = before.logical_pc & !(PAGE - 1);
            let nx = self.domain.pages.get(&page) == Some(&false);
            let guarded = self.domain.pages.get(&page) == Some(&true)
                && self.domain.guards.contains_key(&before.logical_pc);
            if !nx && !guarded {
                continue;
            }
            let tid = event.tid;
            let saved_ready = std::mem::take(&mut self.ready);
            let mut fetched = false;
            // Native collection issued at most one interrupt with at most two
            // racing control-stop credits. No loop can replenish that credit.
            for _ in 0..3 {
                self.ready.insert(task);
                self.release_ready(owner, until)?;
                let (actual_tid, status) =
                    owner.wait_raw(until, "dynamic interrupted NX continuation")?;
                if actual_tid != tid {
                    return Err(GateError::Refused(
                        "dynamic NX continuation changed selected native task",
                    ));
                }
                let owned = match classify(&self.domain, tid, status)? {
                    Some(
                        expected @ TrapExpectation::Fetch {
                            pc,
                            page: actual_page,
                        },
                    ) if nx && pc == before.logical_pc && actual_page == page => Some(
                        self.native
                            .observe_admission_owned(owner, tid, status, expected)?,
                    ),
                    Some(expected @ TrapExpectation::Guard { address })
                        if guarded && address == before.logical_pc =>
                    {
                        Some(
                            self.native
                                .observe_admission_owned(owner, tid, status, expected)?,
                        )
                    }
                    Some(_) => {
                        return Err(GateError::Refused(
                            "dynamic held boundary produced another owned trap",
                        ));
                    }
                    None => {
                        let event = self
                            .native
                            .observe_admission_other(owner, tid, status)?
                            .ok_or(GateError::Refused(
                                "dynamic NX continuation has unresolved native state",
                            ))?;
                        if !matches!(event.kind, DynamicEventKind::Interrupted) {
                            return Err(GateError::Refused(
                                "dynamic NX continuation did not remain at its user boundary",
                            ));
                        }
                        self.handle_generic(owner, reservation, event)?;
                        None
                    }
                };
                self.reconcile_running(owner, reservation, task, until)?;
                let after = self.observe_current(owner, task)?;
                if after.logical_pc != before.logical_pc || !self.running.is_empty() {
                    return Err(GateError::Refused(
                        "dynamic NX continuation advanced without its admitted head",
                    ));
                }
                if let Some(stop) = owned {
                    if stop.identity.task != task
                        || (nx && stop.phase != AdmissionPhase::Fetch)
                        || (guarded && stop.phase != AdmissionPhase::Guard)
                    {
                        return Err(GateError::Refused(
                            "dynamic NX continuation lost exact owned fetch",
                        ));
                    }
                    self.work
                        .try_reserve(1)
                        .map_err(|_| GateError::Refused("dynamic NX work allocation failed"))?;
                    self.census
                        .account_external(
                            reservation,
                            BudgetCharge {
                                source_fact_bytes: std::mem::size_of::<PendingWork>(),
                                ..BudgetCharge::default()
                            },
                        )
                        .map_err(census_error)?;
                    let counter = if nx {
                        self.work.push_back(PendingWork::Fetch { task, page });
                        &mut self.metrics.fetch_faults
                    } else {
                        self.work.push_back(PendingWork::Guard {
                            task,
                            pc: before.logical_pc,
                        });
                        &mut self.metrics.guard_stops
                    };
                    *counter = counter.checked_add(1).ok_or(GateError::Refused(
                        "dynamic held boundary counter exhausted",
                    ))?;
                    fetched = true;
                    break;
                }
            }
            self.ready = saved_ready;
            if !fetched {
                return Err(GateError::Refused(
                    "dynamic NX continuation exhausted bounded interrupt settlement",
                ));
            }
        }
        self.normalize_guards(owner, reservation, until)?;
        Ok(())
    }

    fn release_ready(&mut self, owner: &mut Owner, until: Instant) -> Result<(), GateError> {
        let selected = *self
            .ready
            .first()
            .ok_or(GateError::Refused("empty dynamic release set"))?;
        let mut proposed = BTreeMap::new();
        for &task in &self.ready {
            let before = self.observe_current(owner, task)?;
            let id = self
                .origins
                .get(&task)
                .copied()
                .ok_or(GateError::Refused("dynamic release lacks its origin"))?;
            self.census
                .check_current_origin(id, &before)
                .map_err(census_error)?;
            let first_instruction = self.domain.original_decode(before.logical_pc)?;
            let serial = self.next_execution;
            self.next_execution = serial
                .checked_add(1)
                .ok_or(GateError::Refused("dynamic execution identity exhausted"))?;
            let execution = ExecutionId::from_owner(owner.session, serial).map_err(census_error)?;
            proposed.insert(
                task,
                RunPermit {
                    id: execution,
                    before,
                    first_instruction,
                },
            );
        }
        let held = HeldMmStop::acquire(owner, &mut self.native, &mut self.island, selected, until)?;
        let batch = routes::check_release(&held, &self.domain, &self.census, &self.ready)?;
        // Every proposed permit must refer to the exact state checked by the
        // consuming release seal, not merely the same numeric task or address.
        for before in batch.ready_observations() {
            if proposed
                .get(&before.task.task)
                .is_none_or(|permit| permit.before != *before)
            {
                return Err(GateError::Refused(
                    "dynamic release permit differs from sealed before-state",
                ));
            }
        }
        drop(held);
        self.running = proposed;
        self.ready.clear();
        batch.release(owner, &mut self.native, until)
    }

    /// Generic events cannot be used as an owned guard or a private runner.
    /// Internal interruption diagnostics are retained with their true tokens;
    /// an application signal closes with its exact original siginfo and state.
    fn handle_generic(
        &mut self,
        owner: &mut Owner,
        reservation: Reservation,
        event: DynamicEvent,
    ) -> Result<Option<AdmissionReply>, GateError> {
        self.census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: std::mem::size_of::<DynamicEvent>(),
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        self.lifecycle_history
            .try_reserve(1)
            .map_err(|_| GateError::Refused("dynamic lifecycle history allocation failed"))?;
        self.lifecycle_history.push(event.clone());
        match &event.kind {
            DynamicEventKind::Interrupted => {
                let task = event
                    .task
                    .ok_or(GateError::Refused("dynamic interrupt lacks task identity"))?;
                if self.native.admission_original_interrupt(task.task)? != event {
                    return Err(GateError::Refused(
                        "dynamic interrupt is not an original user stop",
                    ));
                }
                Ok(None)
            }
            DynamicEventKind::SignalDelivery(signal) => {
                let task = event
                    .task
                    .ok_or(GateError::Refused("dynamic signal lacks task identity"))?;
                let state = self.state(task.task)?;
                self.closed = true;
                owner.closing = true;
                owner.cancel.store(true, Ordering::Release);
                Ok(Some(AdmissionReply::Event(
                    DynamicAdmissionEvent::ApplicationSignal {
                        state: Box::new(state),
                        signal: signal.clone(),
                        input: None,
                    },
                )))
            }
            // In this profile every native SYSCALL is selected before kernel
            // entry. Creation, return, and terminal events belong only to the
            // single selected invocation's separate native completion driver.
            _ => Err(GateError::Refused(
                "dynamic original run produced an unqualified lifecycle phase",
            )),
        }
    }

    fn prepare_provider(
        &mut self,
        owner: &mut Owner,
        task: TaskId,
        pc: u64,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let before = self.observe_current(owner, task)?;
        if before.logical_pc != pc
            || before.registers.rip != pc
            || before.registers.eflags & (0x100 | 0x10000) != 0
        {
            return Err(GateError::Refused(
                "dynamic selected guard has no normalized certified logical state",
            ));
        }
        let origin = self.origins.get(&task).copied().ok_or(GateError::Refused(
            "dynamic selected guard lacks its origin",
        ))?;
        self.census
            .check_current_origin(origin, &before)
            .map_err(census_error)?;
        let guard = self.domain.guards.get(&pc).ok_or(GateError::Refused(
            "dynamic selected guard metadata is missing",
        ))?;
        let TrapGuardRole::Selected(site) = guard.role() else {
            return Err(GateError::Refused(
                "dynamic collateral guard cannot invoke a selected provider",
            ));
        };
        let plan = self
            .domain
            .plans
            .iter()
            .rev()
            .find(|plan| {
                plan.pending.snapshot().generation
                    == liteinst_admission::Generation(self.domain.generation)
                    && plan.pending.guards().get(&pc) == Some(guard)
            })
            .map(|plan| plan.id)
            .ok_or(GateError::Refused(
                "dynamic selected guard lacks a current installed plan",
            ))?;
        let instruction = crate::selected::decode(
            pc,
            guard.original_bytes(),
            &crate::selected::SyscallAliases::default(),
        )?;
        let input = SelectedInput::new(instruction, before.registers)?;
        let stop = self.native.admission_current(task)?;
        {
            let held = HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
            // An empty release set authenticates the entire mm and every route
            // without releasing anything. Provider work grants no native permit.
            let _proof =
                routes::check_release(&held, &self.domain, &self.census, &BTreeSet::new())?;
        }
        let reservation = self.reserve_transition(0, false, 0)?;
        self.census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: before
                        .xstate
                        .len()
                        .checked_add(std::mem::size_of::<PendingInvocation>())
                        .and_then(|value| value.checked_add(input.instruction().bytes().len()))
                        .ok_or(GateError::Refused(
                            "dynamic provider evidence size overflows",
                        ))?,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        let (invocation, _) = self.execution_id(owner.session)?;
        let token = PendingToken {
            stop: stop.token.clone(),
            task: stop.identity,
            epoch: self.domain.generation,
            plan,
            invocation,
        };
        self.pending = Some(PendingInvocation {
            token: token.clone(),
            stop,
            before,
            input: input.clone(),
            until,
        });
        self.ready.remove(&task);
        self.metrics.pages.observations = self
            .metrics
            .pages
            .observations
            .checked_add(1)
            .ok_or(GateError::Refused("dynamic observation counter exhausted"))?;
        let count = self
            .metrics
            .selected
            .callbacks
            .entry(site.class)
            .or_default();
        *count = count
            .checked_add(1)
            .ok_or(GateError::Refused("dynamic callback counter exhausted"))?;
        self.census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        Ok(AdmissionReply::Provider(Box::new(ProviderInput {
            token,
            input,
        })))
    }
}
