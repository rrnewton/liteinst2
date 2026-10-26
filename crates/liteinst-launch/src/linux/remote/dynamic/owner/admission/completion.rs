//! One provider decision or qualified collateral instruction, under the
//! original owner's closed release interlock. No publication lease spans an
//! original instruction. Actual completion evidence survives failed rearming.
use super::super::selected::{
    self as native_selected, OriginalCompletion, OriginalEvidence, OriginalOutcome,
};
use super::super::trusted::{self, StateTransform};
use super::census::{CompletedKernel, OwnerConsumption, Reservation};
use super::*;
use crate::gate::domain::PAGE;
use crate::gate::{SelectedCompletion, SelectedExecution};
use crate::lifecycle::TaskState;
use crate::selected::{CompletedInstruction, Operation, SyscallAbi};
use crate::trap_coverage::{TrapGuard, TrapGuardRole};

/// Append-only evidence of a single already-used execution identity. Retaining
/// this record does not authorize another invocation, source edit or release.
pub(super) struct CompletionRecord {
    pending: Option<PendingToken>,
    invocation: ExecutionId,
    before: ObservedStop,
    input: Option<SelectedInput>,
    original: Vec<u8>,
    evidence: CompletionEvidence,
    window: Option<routes::OriginalWindow>,
    rearmed_generation: Option<u64>,
    copied_events: usize,
}

enum CompletionEvidence {
    Scripted {
        completed: Box<CompletedInstruction>,
        after: Box<ObservedStop>,
    },
    Native(Box<OriginalCompletion>),
    Collateral(Box<OriginalCompletion>),
    Event(Box<native_selected::OriginalEvent>),
}

fn add_size(total: &mut usize, size: usize) -> Result<(), GateError> {
    *total = total.checked_add(size).ok_or(GateError::Refused(
        "dynamic completion evidence size overflows",
    ))?;
    Ok(())
}

impl CompletionRecord {
    fn retained_bytes(&self) -> Result<usize, GateError> {
        let mut bytes = std::mem::size_of::<Self>();
        let events = self
            .copied_events
            .checked_mul(std::mem::size_of::<DynamicEvent>())
            .ok_or(GateError::Refused(
                "dynamic completion event copy size overflows",
            ))?;
        add_size(&mut bytes, events)?;
        add_size(&mut bytes, self.before.xstate.len())?;
        // OriginalWindow owns another exact decode until revocation consumes it.
        add_size(&mut bytes, self.original.len())?;
        if self.window.is_some() {
            add_size(&mut bytes, self.original.len())?;
        }
        if let Some(input) = &self.input {
            add_size(&mut bytes, input.instruction().bytes().len())?;
        }
        match &self.evidence {
            CompletionEvidence::Scripted { completed, after } => {
                add_size(&mut bytes, std::mem::size_of::<CompletedInstruction>())?;
                add_size(&mut bytes, completed.instruction.bytes().len())?;
                add_size(&mut bytes, std::mem::size_of::<ObservedStop>())?;
                add_size(&mut bytes, after.xstate.len())?;
            }
            CompletionEvidence::Native(completed) | CompletionEvidence::Collateral(completed) => {
                add_size(&mut bytes, std::mem::size_of::<OriginalCompletion>())?;
                add_size(&mut bytes, completed.state.xstate.len())?;
                for _ in &completed.events {
                    add_size(&mut bytes, std::mem::size_of::<DynamicEvent>())?;
                }
                for _ in &completed.newborns {
                    add_size(&mut bytes, std::mem::size_of::<AdmissionStop>())?;
                }
                if let OriginalEvidence::Syscall(kernel) = &completed.evidence {
                    add_size(&mut bytes, std::mem::size_of_val(kernel.as_ref()))?;
                    add_size(&mut bytes, kernel.entry_state.xstate.len())?;
                    add_size(&mut bytes, kernel.exit_state.xstate.len())?;
                    for newborn in &kernel.newborns {
                        add_size(&mut bytes, std::mem::size_of_val(newborn))?;
                        add_size(&mut bytes, newborn.before_bridge.xstate.len())?;
                    }
                }
            }
            CompletionEvidence::Event(event) => {
                add_size(&mut bytes, std::mem::size_of_val(event.as_ref()))?;
                if let Some(state) = &event.state {
                    add_size(&mut bytes, state.xstate.len())?;
                }
                for _ in &event.events {
                    add_size(&mut bytes, std::mem::size_of::<DynamicEvent>())?;
                }
            }
        }
        Ok(bytes)
    }
}

impl AdmissionOwner {
    pub(super) fn complete(
        &mut self,
        owner: &mut Owner,
        token: PendingToken,
        decision: ProviderDecision,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let result = self.complete_inner(owner, token, decision, until);
        if result.is_err() {
            self.close_completion(owner);
        }
        result
    }

    fn close_completion(&mut self, owner: &mut Owner) {
        self.closed = true;
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
    }

    fn authenticate_pending(
        &mut self,
        owner: &mut Owner,
        token: &PendingToken,
        until: Instant,
    ) -> Result<(), GateError> {
        let pending = self.pending.as_ref().ok_or(GateError::Refused(
            "dynamic completion has no pending provider invocation",
        ))?;
        if pending.token != *token
            || pending.until != until
            || token.epoch != self.domain.generation
            || token.task.generation != self.domain.generation
            || token.stop != pending.stop.token
            || token.task != pending.stop.identity
            || token.invocation == 0
            || !self.running.is_empty()
        {
            return Err(GateError::Refused(
                "dynamic completion token, deadline or generation is stale",
            ));
        }
        owner.time_left(pending.until, "dynamic admission original transaction")?;
        self.native.require_admission_stop(&pending.stop)?;
        let actual = self.observe_current(owner, token.task.task)?;
        if actual != pending.before
            || actual.phase != StopPhase::UserCheckpoint
            || actual.registers != *pending.input.registers()
            || actual.logical_pc != pending.input.instruction().logical_pc()
            || actual.registers.eflags & (0x100 | 0x10000) != 0
        {
            return Err(GateError::Refused(
                "dynamic completion full before-state or phase differs",
            ));
        }
        let origin = self
            .origins
            .get(&token.task.task)
            .copied()
            .ok_or(GateError::Refused(
                "dynamic completion has no retained origin",
            ))?;
        self.census
            .check_current_origin(origin, &actual)
            .map_err(census_error)?;
        let guard = self
            .domain
            .guards
            .get(&actual.logical_pc)
            .ok_or(GateError::Refused(
                "dynamic completion lost its installed guard",
            ))?;
        let TrapGuardRole::Selected(site) = guard.role() else {
            return Err(GateError::Refused("dynamic completion guard is collateral"));
        };
        if guard.original_bytes() != pending.input.instruction().bytes()
            || site.class != pending.input.instruction().operation().class()
        {
            return Err(GateError::Refused(
                "dynamic completion original selected instruction differs",
            ));
        }
        self.authenticate_guard(
            owner,
            token.task.task,
            actual.logical_pc,
            Some(token.plan),
            until,
        )
    }

    fn authenticate_guard(
        &mut self,
        owner: &mut Owner,
        task: TaskId,
        pc: u64,
        expected_plan: Option<u64>,
        until: Instant,
    ) -> Result<(), GateError> {
        let guard = self.domain.guards.get(&pc).ok_or(GateError::Refused(
            "dynamic original guard metadata is missing",
        ))?;
        let image = self.domain.image(pc)?;
        if self.domain.original_decode(pc)? != guard.original_bytes()
            || !self.domain.plans.iter().any(|plan| {
                expected_plan.is_none_or(|id| plan.id == id)
                    && plan.pending.snapshot() == &image.snapshot
                    && plan.pending.entries() == &image.entries
                    && plan.pending.policy() == &self.domain.policy
                    && plan.pending.guards().get(&pc) == Some(guard)
            })
        {
            return Err(GateError::Refused(
                "dynamic original guard has no exact current plan",
            ));
        }
        // This acquires no execution permit and runs no island instruction.
        // Source, permissions, every current origin and the entire mm are
        // independently authenticated before a provider result can mutate state.
        let held = HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
        let _proof = routes::check_release(&held, &self.domain, &self.census, &BTreeSet::new())?;
        Ok(())
    }

    fn complete_inner(
        &mut self,
        owner: &mut Owner,
        token: PendingToken,
        decision: ProviderDecision,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        self.authenticate_pending(owner, &token, until)?;
        let pending = self.pending.as_ref().expect("authenticated pending");
        let scripted = match decision {
            ProviderDecision::Complete(result) => Some(Box::new(pending.input.complete(result)?)),
            ProviderDecision::Native => {
                self.check_native_policy(owner, &pending.input)?;
                None
            }
            ProviderDecision::Fault(fault) => {
                let event = DynamicAdmissionEvent::Fault {
                    task: token.task,
                    fault: Box::new(pending.input.fault(fault)),
                };
                self.metrics.selected.provider_faults =
                    self.metrics.selected.provider_faults.checked_add(1).ok_or(
                        GateError::Refused("dynamic provider fault counter exhausted"),
                    )?;
                // No original execution, semantic completion or census
                // consumption occurred. Keep the pending invocation as history.
                self.close_completion(owner);
                return Ok(AdmissionReply::Event(event));
            }
        };
        let clone = matches!(decision, ProviderDecision::Native)
            && matches!(
                pending.input.instruction().operation(),
                Operation::Syscall {
                    abi: SyscallAbi::LinuxX64
                }
            )
            && pending.input.registers().rax == libc::SYS_clone as u64;
        let successors = if clone { 2 } else { 1 };
        let reservation = self.reserve_transition(owner, successors, true, 1)?;
        self.check_completion_budget(owner, reservation, successors, true, 1)?;
        self.reserve_completion_events()?;
        self.completion_history
            .try_reserve(1)
            .map_err(|_| GateError::Refused("dynamic completion history allocation failed"))?;
        let pending = self.pending.take().expect("authenticated pending");
        let invocation = ExecutionId::from_owner(owner.session, pending.token.invocation)
            .map_err(census_error)?;
        let task = pending.token.task.task;
        let original = pending.input.instruction().bytes().to_vec();
        let mut before = pending.before.clone();
        let mut window = None;
        let evidence = if let Some(completed) = scripted {
            // SAFETY: complete() above checked the exact typed semantics; the
            // original before-state, whole mm, source and origins are current.
            // The neutral trap is a real stop, not invented kernel execution.
            unsafe {
                trusted::apply_scripted_completion(
                    owner,
                    &mut self.native,
                    &self.island,
                    &pending.stop,
                    StateTransform {
                        before: &before.registers,
                        after: &completed.after,
                        before_xstate: &before.xstate,
                        before_mask: before.signal_mask,
                    },
                    until,
                )?;
            }
            let after = self.observe_current(owner, task)?;
            CompletionEvidence::Scripted {
                completed,
                after: Box::new(after),
            }
        } else {
            {
                let mut held =
                    HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
                window = Some(routes::restore_original(
                    &mut held,
                    &self.domain,
                    pending.input.instruction().logical_pc(),
                    &original,
                    until,
                )?);
            }
            self.refresh_all_same_pc(owner, reservation, task, until)?;
            before = self.observe_current(owner, task)?;
            if before.registers != *pending.input.registers()
                || before.xstate != pending.before.xstate
                || before.signal_mask != pending.before.signal_mask
                || before.phase != StopPhase::UserCheckpoint
            {
                return Err(GateError::Refused(
                    "dynamic original restoration changed invocation input",
                ));
            }
            self.check_completion_budget(owner, reservation, successors, true, 1)?;
            let current = self.native.admission_current(task)?;
            // SAFETY: the exact finite syscall policy was checked before any
            // release. The whole decode is restored RX, all siblings are held,
            // and this owner retains the closed rearm interlock/window.
            match unsafe {
                native_selected::execute(
                    owner,
                    &mut self.native,
                    &self.island,
                    native_selected::OriginalInvocation {
                        stop: &current,
                        input: &pending.input,
                        before_xstate: &before.xstate,
                        before_mask: before.signal_mask,
                    },
                    until,
                )?
            } {
                OriginalOutcome::Completed(completed) => CompletionEvidence::Native(completed),
                OriginalOutcome::Event(event) => CompletionEvidence::Event(event),
            }
        };
        let index = self.completion_history.len();
        // Capacity was reserved before mutation. Preserve already-completed
        // kernel/user evidence before any fallible census, accounting or rebind.
        self.completion_history.push(CompletionRecord {
            pending: Some(pending.token),
            invocation,
            before,
            input: Some(pending.input),
            original,
            evidence,
            window,
            rearmed_generation: None,
            copied_events: 0,
        });
        self.retain_completion_events(index)?;
        self.account_completion(reservation, index)?;
        if matches!(
            &self.completion_history[index].evidence,
            CompletionEvidence::Event(_)
        ) {
            return self.original_event_reply(owner, index);
        }
        self.finish_completed(owner, reservation, index, until)?;
        let record = &self.completion_history[index];
        let input = record
            .input
            .clone()
            .expect("selected completion retains input");
        let state = self.state(task)?;
        if record.rearmed_generation != Some(state.task.generation) {
            return Err(GateError::Refused(
                "dynamic completion has no matching rearmed generation",
            ));
        }
        let execution = if matches!(&record.evidence, CompletionEvidence::Scripted { .. }) {
            SelectedExecution::Scripted
        } else {
            SelectedExecution::Native
        };
        let event = DynamicAdmissionCompletion {
            before_task: record.pending.as_ref().expect("provider record").task,
            after_task: state.task,
            selected: SelectedCompletion {
                input,
                after: state.registers,
                before_xstate: record.before.xstate.clone(),
                xstate: state.xstate,
                execution,
            },
            before_signal_mask: record.before.signal_mask,
            signal_mask: state.signal_mask,
        };
        let counter = if execution == SelectedExecution::Scripted {
            &mut self.metrics.selected.scripted_completions
        } else {
            &mut self.metrics.selected.native_completions
        };
        *counter = counter
            .checked_add(1)
            .ok_or(GateError::Refused("dynamic completion counter exhausted"))?;
        self.census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        Ok(AdmissionReply::Event(DynamicAdmissionEvent::Completed(
            Box::new(event),
        )))
    }

    fn check_native_policy(&self, owner: &Owner, input: &SelectedInput) -> Result<(), GateError> {
        let Operation::Syscall { abi } = input.instruction().operation() else {
            return Ok(());
        };
        if abi != SyscallAbi::LinuxX64 || input.registers().rax > i32::MAX as u64 {
            return Err(GateError::Refused(
                "dynamic selected syscall ABI is outside the finite profile",
            ));
        }
        let registers = input.registers();
        match registers.rax as libc::c_long {
            libc::SYS_getpid | libc::SYS_gettid | libc::SYS_exit | libc::SYS_exit_group => Ok(()),
            libc::SYS_clone => {
                if self.creation != DynamicCreationPolicy::ThreadClone
                    || registers.rdi != 0x10f00
                    || registers.rdx != 0
                    || registers.r10 != 0
                    || registers.r8 != 0
                    || owner.owned.len() != 1
                    || !owner.owned.contains(&owner.pid)
                    || self.native.admission_snapshot().tasks().count() != 1
                {
                    return Err(GateError::Refused(
                        "dynamic selected clone is outside the exact thread profile",
                    ));
                }
                let bottom = registers.rsi.checked_sub(128).ok_or(GateError::Refused(
                    "dynamic selected clone stack lacks writable storage",
                ))?;
                if !read_maps(owner.pid)?.iter().any(|map| {
                    map.start <= bottom
                        && registers.rsi <= map.end
                        && map.permissions.as_bytes().starts_with(b"rw")
                }) {
                    return Err(GateError::Refused(
                        "dynamic selected clone stack lacks writable storage",
                    ));
                }
                // Native lifecycle repeats these checks and proves CET, thread
                // pidfd support, ENTRY state and child inheritance before
                // releasing the actual kernel creation continuation.
                Ok(())
            }
            _ => Err(GateError::Refused(
                "dynamic selected syscall has unqualified effects",
            )),
        }
    }

    fn reserve_completion_events(&mut self) -> Result<(), GateError> {
        // The finite native profile can create one task, producing at most one
        // Created and one Newborn event. Allocate both immutable/public history
        // copies before original execution; their lifetime bytes are charged in
        // the same preflight envelope as the external CompletionRecord.
        self.diagnostics
            .try_reserve(2)
            .map_err(|_| GateError::Refused("dynamic completion diagnostic allocation failed"))?;
        self.lifecycle_history.try_reserve(2).map_err(|_| {
            GateError::Refused("dynamic completion lifecycle history allocation failed")
        })
    }

    fn retain_completion_events(&mut self, index: usize) -> Result<(), GateError> {
        let events = match &self.completion_history[index].evidence {
            CompletionEvidence::Native(completed) | CompletionEvidence::Collateral(completed) => {
                &completed.events[..]
            }
            CompletionEvidence::Event(observed) => &observed.events[..],
            CompletionEvidence::Scripted { .. } => &[],
        };
        if events.len() > 2
            || events.iter().any(|event| {
                !matches!(
                    &event.kind,
                    DynamicEventKind::Created { .. } | DynamicEventKind::Newborn { .. }
                )
            })
        {
            return Err(GateError::Refused(
                "dynamic completion lifecycle evidence exceeds its finite profile",
            ));
        }
        let mut copied = 0;
        for event in events {
            if !self.lifecycle_history.contains(event) {
                self.lifecycle_history.push(event.clone());
                self.diagnostics.push_back(event.clone());
                copied += 2;
            }
        }
        self.completion_history[index].copied_events = copied;
        Ok(())
    }

    fn account_completion(
        &mut self,
        reservation: Reservation,
        index: usize,
    ) -> Result<(), GateError> {
        let bytes = self.completion_history[index].retained_bytes()?;
        self.census
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)
    }

    /// Complete an actual selected/collateral result, consume precisely its
    /// old register continuation, then rebind and rearm its source page. A next
    /// page stays NX unless the complete source-decode closure requires it.
    fn finish_completed(
        &mut self,
        owner: &mut Owner,
        reservation: Reservation,
        index: usize,
        until: Instant,
    ) -> Result<(), GateError> {
        let record = &self.completion_history[index];
        let task = record.before.task.task;
        let invocation = record.invocation;
        let before = record.before.clone();
        let origin = self
            .origins
            .get(&task)
            .copied()
            .ok_or(GateError::Refused("dynamic completion origin is absent"))?;
        let after = self.observe_current(owner, task)?;
        let (consumption, successors) = match &record.evidence {
            CompletionEvidence::Scripted {
                completed,
                after: observed,
            } => {
                if observed.as_ref() != &after
                    || completed.after != after.registers
                    || after.xstate != before.xstate
                    || after.signal_mask != before.signal_mask
                {
                    return Err(GateError::Refused(
                        "dynamic scripted complete state differs",
                    ));
                }
                let mut selected = after.clone();
                selected.phase = StopPhase::SelectedComplete { invocation };
                (
                    OwnerConsumption::completed_selected(
                        invocation,
                        before.clone(),
                        record.input.clone().expect("script input"),
                        completed.as_ref().clone(),
                        selected,
                    )
                    .map_err(census_error)?,
                    vec![(OriginKind::CurrentHeldPc, after.clone())],
                )
            }
            CompletionEvidence::Native(completed) => {
                if completed.stop != self.native.admission_current(task)?
                    || !same_state(&after, &completed.state)
                {
                    return Err(GateError::Refused(
                        "dynamic native completion is no longer its actual held state",
                    ));
                }
                let input = record.input.as_ref().expect("native selected input");
                match &completed.evidence {
                    OriginalEvidence::CpuTrace { raw } => {
                        validate_cpu_trace(raw)?;
                        let typed = input.validate_native_completion(&after.registers)?;
                        let mut selected = after.clone();
                        selected.phase = StopPhase::SelectedComplete { invocation };
                        (
                            OwnerConsumption::completed_selected(
                                invocation,
                                before.clone(),
                                input.clone(),
                                typed,
                                selected,
                            )
                            .map_err(census_error)?,
                            vec![(OriginKind::CurrentHeldPc, after.clone())],
                        )
                    }
                    OriginalEvidence::Syscall(kernel) => {
                        let number = input.registers().rax;
                        let entry = kernel_observation(
                            &kernel.entry,
                            &kernel.entry_state,
                            StopPhase::SyscallEntry { syscall: number },
                        )?;
                        let (result, is_error) = match &kernel.exit.kind {
                            DynamicEventKind::SyscallExit { result, is_error } => {
                                (*result, *is_error)
                            }
                            _ => {
                                return Err(GateError::Refused(
                                    "dynamic completion lost actual syscall EXIT evidence",
                                ));
                            }
                        };
                        let parent = kernel_observation(
                            &kernel.exit,
                            &kernel.exit_state,
                            StopPhase::ParentSyscallExit {
                                syscall: number,
                                result,
                                is_error,
                            },
                        )?;
                        if number == libc::SYS_clone as u64 && !is_error {
                            if kernel.newborns.len() != 1 || completed.newborns.len() != 1 {
                                return Err(GateError::Refused(
                                    "dynamic clone completion lacks one raw newborn observation",
                                ));
                            }
                            let child = &kernel.newborns[0];
                            let newborn = kernel_observation(
                                &child.event,
                                &child.before_bridge,
                                StopPhase::NewbornReturnReady {
                                    parent: task,
                                    syscall: number,
                                },
                            )?;
                            let created = completed.events.iter().filter(|event| {
                                event.task == Some(before.task) && event.tid == before.token.tid
                                    && matches!(&event.kind, DynamicEventKind::Created { child } if *child == newborn.task)
                            }).count();
                            if completed.events.len() != 2
                                || created != 1
                                || completed
                                    .events
                                    .iter()
                                    .filter(|event| **event == child.event)
                                    .count()
                                    != 1
                                || completed.newborns[0] != child.after_bridge
                                || self.native.admission_current(newborn.task.task)?
                                    != child.after_bridge
                                || !same_state(
                                    &self.observe_current(owner, newborn.task.task)?,
                                    &child.before_bridge,
                                )
                            {
                                return Err(GateError::Refused(
                                    "dynamic clone newborn bridge evidence differs",
                                ));
                            }
                            let kernel = CompletedKernel::clone_from_owner(
                                invocation,
                                before.clone(),
                                input.clone(),
                                entry,
                                parent.clone(),
                                newborn.clone(),
                            )
                            .map_err(census_error)?;
                            (
                                OwnerConsumption::completed_kernel(kernel),
                                vec![
                                    (OriginKind::ParentSyscallReturn { syscall: number }, parent),
                                    (
                                        OriginKind::NewbornStart {
                                            parent: task,
                                            syscall: number,
                                        },
                                        newborn,
                                    ),
                                ],
                            )
                        } else {
                            if !kernel.newborns.is_empty()
                                || !completed.newborns.is_empty()
                                || !completed.events.is_empty()
                            {
                                return Err(GateError::Refused(
                                    "dynamic noncreation completion retained unexpected newborns",
                                ));
                            }
                            if (number == libc::SYS_getpid as u64
                                && (is_error || result != i64::from(owner.pid)))
                                || (number == libc::SYS_gettid as u64
                                    && (is_error || result != i64::from(before.token.tid)))
                                || !matches!(
                                    number as libc::c_long,
                                    libc::SYS_getpid | libc::SYS_gettid | libc::SYS_clone
                                )
                            {
                                return Err(GateError::Refused(
                                    "dynamic native syscall result differs from its finite identity profile",
                                ));
                            }
                            // ENTRY/EXIT and the real return bridge above retain
                            // actual orig_rax. This is native progress, not a
                            // fabricated pure scripted bookkeeping snapshot.
                            (
                                OwnerConsumption::original_progress(
                                    invocation,
                                    before.clone(),
                                    record.original.clone(),
                                    after.clone(),
                                )
                                .map_err(census_error)?,
                                vec![(OriginKind::ParentSyscallReturn { syscall: number }, parent)],
                            )
                        }
                    }
                }
            }
            CompletionEvidence::Collateral(completed) => {
                let OriginalEvidence::CpuTrace { raw } = &completed.evidence else {
                    return Err(GateError::Refused(
                        "dynamic collateral completion is not a native CPU trace",
                    ));
                };
                validate_cpu_trace(raw)?;
                if !completed.newborns.is_empty()
                    || !completed.events.is_empty()
                    || completed.stop != self.native.admission_current(task)?
                    || !same_state(&after, &completed.state)
                {
                    return Err(GateError::Refused(
                        "dynamic collateral completion lacks exact native trace evidence",
                    ));
                }
                (
                    OwnerConsumption::original_progress(
                        invocation,
                        before.clone(),
                        record.original.clone(),
                        after.clone(),
                    )
                    .map_err(census_error)?,
                    vec![(OriginKind::CurrentHeldPc, after.clone())],
                )
            }
            CompletionEvidence::Event(_) => {
                return Err(GateError::Refused(
                    "dynamic original event cannot be relabelled completed",
                ));
            }
        };
        let source_page = before.logical_pc & !(PAGE - 1);
        let expected_state = TaskStateSnapshot {
            registers: after.registers,
            xstate: after.xstate.clone(),
            mask: after.signal_mask,
        };
        self.census
            .consume(reservation, origin, consumption)
            .map_err(census_error)?;
        self.origins.remove(&task);
        for (kind, observed) in successors {
            let id = observed.task.task;
            if self.origins.contains_key(&id) {
                return Err(GateError::Refused(
                    "dynamic completed continuation already has another active origin",
                ));
            }
            let origin = self
                .census
                .insert(reservation, kind, observed.logical_pc, observed)
                .map_err(census_error)?;
            self.origins.insert(id, origin);
        }
        // Raw parent EXIT and newborn return-ready observations remain in their
        // immutable rows; refresh records bind them to the genuine neutral stops.
        self.refresh_all_same_pc(owner, reservation, task, until)?;
        let window = self.completion_history[index].window.take();
        self.rebind(owner, reservation, task, window, until)?;
        // All application pages are NX here. While the completed private task
        // remains held, materialize any generic sibling interruption as its
        // genuine same-PC fetch, before source publication could grant it X.
        let tasks = self.native.check_admission_mm(owner, task)?.candidate.tasks;
        self.collect_interrupted_boundaries(owner, reservation, &tasks, until)?;
        self.settle_private_controls(owner, reservation, until)?;
        self.publish_page(owner, reservation, task, source_page, until)?;
        let final_state = self.observe_current(owner, task)?;
        if !same_state(&final_state, &expected_state) {
            return Err(GateError::Refused(
                "dynamic rearming changed the actual completed state",
            ));
        }
        self.completion_history[index].rearmed_generation = Some(self.domain.generation);
        self.ready.insert(task);
        if let CompletionEvidence::Native(completed) = &self.completion_history[index].evidence {
            for newborn in &completed.newborns {
                self.ready.insert(newborn.identity.task);
            }
        }
        Ok(())
    }

    fn original_event_reply(
        &mut self,
        owner: &mut Owner,
        index: usize,
    ) -> Result<AdmissionReply, GateError> {
        let record = &self.completion_history[index];
        let CompletionEvidence::Event(observed) = &record.evidence else {
            return Err(GateError::Refused(
                "dynamic incomplete invocation has no actual event",
            ));
        };
        let task = observed.event.task.ok_or(GateError::Refused(
            "dynamic original event lost task identity",
        ))?;
        let event = match &observed.event.kind {
            DynamicEventKind::SignalDelivery(signal) => {
                let state = observed.state.as_ref().ok_or(GateError::Refused(
                    "dynamic original signal lacks held state",
                ))?;
                self.metrics.selected.native_signals =
                    self.metrics.selected.native_signals.checked_add(1).ok_or(
                        GateError::Refused("dynamic native signal counter exhausted"),
                    )?;
                DynamicAdmissionEvent::ApplicationSignal {
                    state: Box::new(DynamicAdmissionState {
                        task,
                        registers: state.registers,
                        xstate: state.xstate.clone(),
                        signal_mask: state.mask,
                    }),
                    signal: signal.clone(),
                    input: record.input.clone().map(Box::new),
                }
            }
            DynamicEventKind::TaskTerminal { status } => DynamicAdmissionEvent::TaskTerminal {
                task,
                status: *status,
                all_terminal: self
                    .native
                    .admission_snapshot()
                    .tasks()
                    .all(|task| matches!(task.state, TaskState::Terminal(_))),
            },
            _ => DynamicAdmissionEvent::Lifecycle(observed.event.clone()),
        };
        // This finite completion path cannot rearm arbitrary signal/control,
        // Exiting or terminal membership. Keep the original window/history and
        // all physical ownership, and close instead of claiming completion.
        self.close_completion(owner);
        Ok(AdmissionReply::Event(event))
    }

    pub(super) fn complete_collateral(
        &mut self,
        owner: &mut Owner,
        task: TaskId,
        pc: u64,
        until: Instant,
    ) -> Result<Option<AdmissionReply>, GateError> {
        let result = self.collateral_inner(owner, task, pc, until);
        if result.is_err() {
            self.close_completion(owner);
        }
        result
    }

    fn collateral_inner(
        &mut self,
        owner: &mut Owner,
        task: TaskId,
        pc: u64,
        until: Instant,
    ) -> Result<Option<AdmissionReply>, GateError> {
        if self.pending.is_some() || !self.running.is_empty() {
            return Err(GateError::Refused(
                "dynamic collateral invocation conflicts with existing execution",
            ));
        }
        owner.time_left(until, "dynamic collateral original transaction")?;
        let before = self.observe_current(owner, task)?;
        if before.logical_pc != pc || before.phase != StopPhase::UserCheckpoint {
            return Err(GateError::Refused(
                "dynamic collateral guard lacks normalized held state",
            ));
        }
        let origin = self
            .origins
            .get(&task)
            .copied()
            .ok_or(GateError::Refused("dynamic collateral origin is missing"))?;
        self.census
            .check_current_origin(origin, &before)
            .map_err(census_error)?;
        self.authenticate_guard(owner, task, pc, None, until)?;
        let guard: TrapGuard = self
            .domain
            .guards
            .get(&pc)
            .expect("authenticated guard")
            .clone();
        if guard.role() != TrapGuardRole::Collateral {
            return Err(GateError::Refused(
                "dynamic selected guard cannot bypass its provider",
            ));
        }
        crate::gate::domain::qualify_collateral(&guard)?;
        let reservation = self.reserve_transition(owner, 1, true, 1)?;
        self.check_completion_budget(owner, reservation, 1, true, 1)?;
        self.reserve_completion_events()?;
        self.completion_history
            .try_reserve(1)
            .map_err(|_| GateError::Refused("dynamic collateral history allocation failed"))?;
        let (_, invocation) = self.execution_id(owner.session)?;
        let window = {
            let mut held =
                HeldMmStop::acquire(owner, &mut self.native, &mut self.island, task, until)?;
            routes::restore_original(&mut held, &self.domain, pc, guard.original_bytes(), until)?
        };
        self.refresh_all_same_pc(owner, reservation, task, until)?;
        let actual = self.observe_current(owner, task)?;
        if actual.registers != before.registers
            || actual.xstate != before.xstate
            || actual.signal_mask != before.signal_mask
        {
            return Err(GateError::Refused(
                "dynamic collateral restoration changed its input",
            ));
        }
        self.check_completion_budget(owner, reservation, 1, true, 1)?;
        let current = self.native.admission_current(task)?;
        let state = TaskStateSnapshot {
            registers: actual.registers,
            xstate: actual.xstate.clone(),
            mask: actual.signal_mask,
        };
        // SAFETY: full source and exact MOV collateral qualification are held;
        // no provider is invoked and the closed interlock retains this window.
        let outcome = unsafe {
            native_selected::execute_collateral(
                owner,
                &mut self.native,
                &self.island,
                native_selected::CollateralInvocation {
                    stop: &current,
                    guard: &guard,
                    before: &state,
                },
                until,
            )?
        };
        let evidence = match outcome {
            OriginalOutcome::Completed(completed) => CompletionEvidence::Collateral(completed),
            OriginalOutcome::Event(event) => CompletionEvidence::Event(event),
        };
        let index = self.completion_history.len();
        self.completion_history.push(CompletionRecord {
            pending: None,
            invocation,
            before: actual,
            input: None,
            original: guard.original_bytes().to_vec(),
            evidence,
            window: Some(window),
            rearmed_generation: None,
            copied_events: 0,
        });
        self.retain_completion_events(index)?;
        self.account_completion(reservation, index)?;
        if matches!(
            &self.completion_history[index].evidence,
            CompletionEvidence::Event(_)
        ) {
            return self.original_event_reply(owner, index).map(Some);
        }
        self.finish_completed(owner, reservation, index, until)?;
        self.metrics.pages.collateral_completions = self
            .metrics
            .pages
            .collateral_completions
            .checked_add(1)
            .ok_or(GateError::Refused(
                "dynamic collateral completion counter exhausted",
            ))?;
        self.census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        Ok(None)
    }
}

fn validate_cpu_trace(raw: &[u8; 128]) -> Result<(), GateError> {
    let signal = DynamicSignalInfo { raw: *raw };
    if signal.signal() != libc::SIGTRAP || signal.code() != libc::TRAP_TRACE {
        return Err(GateError::Refused(
            "dynamic completion lost actual CPU trace provenance",
        ));
    }
    Ok(())
}

fn same_state(observed: &ObservedStop, state: &TaskStateSnapshot) -> bool {
    observed.registers == state.registers
        && observed.xstate == state.xstate
        && observed.signal_mask == state.mask
}

fn kernel_observation(
    event: &DynamicEvent,
    state: &TaskStateSnapshot,
    phase: StopPhase,
) -> Result<ObservedStop, GateError> {
    let token = event
        .stop_token()
        .ok_or(GateError::Refused(
            "dynamic kernel completion evidence lacks a true stop",
        ))?
        .clone();
    let task = event.task.ok_or(GateError::Refused(
        "dynamic kernel completion evidence lacks an incarnation",
    ))?;
    let valid = match (&event.kind, phase) {
        (DynamicEventKind::SyscallEntry { number, .. }, StopPhase::SyscallEntry { syscall }) => {
            *number == syscall
        }
        (
            DynamicEventKind::SyscallExit { result, is_error },
            StopPhase::ParentSyscallExit {
                result: expected,
                is_error: error,
                ..
            },
        ) => *result == expected && *is_error == error,
        (
            DynamicEventKind::Newborn { parent },
            StopPhase::NewbornReturnReady {
                parent: expected,
                syscall,
            },
        ) => parent.task == expected && syscall == libc::SYS_clone as u64,
        _ => false,
    };
    if !valid || token.task != Some(task.task) || token.tid != event.tid {
        return Err(GateError::Refused(
            "dynamic kernel completion event and phase differ",
        ));
    }
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
