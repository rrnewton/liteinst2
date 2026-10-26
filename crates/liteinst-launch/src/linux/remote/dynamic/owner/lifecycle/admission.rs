//! Narrow owner-thread phase and membership seams for actual admission.
//! None of these model records substitutes for the native stopped-task proof.
use super::super::trusted::{
    AdmissionPhase, AdmissionStop, OwnedSignal, TrapExpectation, TrustedIsland, authenticate_trap,
};
use super::*;
use crate::lifecycle::{
    AddressSpaceId, ExclusionCandidate, ProcessId, RegistrySnapshot, TaskState,
};

#[derive(Clone, Debug)]
pub(in crate::linux::remote::dynamic) struct MmMembership {
    pub(in crate::linux::remote::dynamic) address_space: AddressSpaceId,
    pub(in crate::linux::remote::dynamic) generation: u64,
    pub(in crate::linux::remote::dynamic) process: ProcessId,
    pub(in crate::linux::remote::dynamic) tgid: i32,
    pub(in crate::linux::remote::dynamic) tids: BTreeSet<i32>,
    pub(in crate::linux::remote::dynamic) candidate: ExclusionCandidate,
}

impl NativeLifecycle {
    pub(in crate::linux::remote::dynamic) fn admission_snapshot(&self) -> RegistrySnapshot {
        self.registry.snapshot()
    }

    pub(in crate::linux::remote::dynamic) fn admission_current(
        &self,
        id: TaskId,
    ) -> Result<AdmissionStop, LaunchError> {
        let record = recorded(self.registry.task(id))?;
        match self.tasks.get(&record.tid).map(|task| &task.state) {
            Some(State::AdmissionHeld(stop)) if stop.identity.task == id => Ok((**stop).clone()),
            _ => Err(LaunchError::Invalid(
                "task is not at an admission injection phase",
            )),
        }
    }

    pub(in crate::linux::remote::dynamic) fn require_admission_stop(
        &self,
        stop: &AdmissionStop,
    ) -> Result<(), LaunchError> {
        let current = self.admission_current(stop.identity.task)?;
        let record = recorded(self.registry.task(stop.identity.task))?;
        if current != *stop
            || record.sequence != stop.token.sequence
            || record.address_space != stop.identity.address_space
            || record.process != stop.identity.process
            || recorded(self.registry.address_space(record.address_space))?.generation
                != stop.identity.generation
            || !matches!(
                record.state,
                TaskState::Held {
                    reason: HoldReason::OwnedTrap,
                    ..
                }
            )
        {
            return Err(LaunchError::Invalid(
                "admission stop identity is stale or foreign",
            ));
        }
        Ok(())
    }

    /// Classify a domain-authenticated instrumentation trap before generic
    /// signal handling creates any application pending-signal obligation.
    pub(in crate::linux::remote::dynamic) fn observe_admission_owned(
        &mut self,
        owner: &Owner,
        tid: i32,
        status: i32,
        expected: TrapExpectation,
    ) -> Result<AdmissionStop, LaunchError> {
        let task = self
            .tasks
            .get(&tid)
            .ok_or(LaunchError::Invalid("owned trap has unknown task"))?;
        if !matches!(task.state, State::Running)
            || task.syscall_open
            || self.pending.is_some()
            || self.exec_pending.is_some()
        {
            return Err(LaunchError::Invalid(
                "owned trap is outside an original user phase",
            ));
        }
        let identity = task.identity;
        let (phase, raw, registers) = authenticate_trap(owner, tid, status, expected)?;
        self.consume_admission_interrupt(tid)?;
        recorded(self.registry.observe_stop(
            identity.task,
            self.sequence(tid)?,
            registers.rip,
            HoldReason::OwnedTrap,
        ))?;
        let sequence = recorded(self.registry.task(identity.task))?.sequence;
        // GETSIGINFO initialized the complete native siginfo object.
        let info = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast::<libc::siginfo_t>()) };
        let signal = OwnedSignal {
            raw,
            view: SignalStop {
                signal: info.si_signo,
                code: info.si_code,
                address: if matches!(info.si_signo, libc::SIGSEGV | libc::SIGBUS | libc::SIGILL) {
                    Some(unsafe { info.si_addr() } as usize as u64)
                } else {
                    None
                },
                instruction_pointer: registers.rip,
                pid: tid,
                sequence,
            },
        };
        let stop = AdmissionStop {
            token: DynamicStop {
                session: self.session,
                sequence,
                tid,
                task: Some(identity.task),
            },
            identity,
            phase,
            signal: Some(signal),
        };
        self.tasks.get_mut(&tid).unwrap().state = State::AdmissionHeld(Box::new(stop.clone()));
        Ok(stop)
    }

    /// Read the current generic event without reclassifying a signal/control
    /// stop as an injection phase. Historical queued tokens do not authenticate.
    pub(in crate::linux::remote::dynamic) fn admission_held_event(
        &self,
        id: TaskId,
    ) -> Result<DynamicEvent, LaunchError> {
        let record = recorded(self.registry.task(id))?;
        let task = self
            .tasks
            .get(&record.tid)
            .ok_or(LaunchError::Invalid("unknown held admission task"))?;
        let State::Held(event) = &task.state else {
            return Err(LaunchError::Invalid(
                "admission task has no current generic event",
            ));
        };
        let token = event
            .stop_token()
            .ok_or(LaunchError::Invalid("held admission event lacks token"))?;
        if task.identity.task != id
            || token.task != Some(id)
            || token.sequence != record.sequence
            || event.task != Some(task.identity)
            || !matches!(record.state, TaskState::Held { .. })
        {
            return Err(LaunchError::Invalid(
                "held admission event identity differs",
            ));
        }
        self.require_stop(token).cloned()
    }

    /// A generic interrupt can be a user release point only when no kernel
    /// syscall/creation/exec continuation is open. The event kind alone does
    /// not certify that phase. This accessor authenticates facts, not a permit.
    pub(in crate::linux::remote::dynamic) fn admission_original_interrupt(
        &self,
        id: TaskId,
    ) -> Result<DynamicEvent, LaunchError> {
        let event = self.admission_held_event(id)?;
        let task = self.tasks.get(&event.tid).ok_or(LaunchError::Invalid(
            "interrupted admission task is unknown",
        ))?;
        if event.kind != DynamicEventKind::Interrupted
            || task.syscall_open
            || task.fork_return.is_some()
            || self.pending.is_some()
            || self.exec_pending.is_some()
        {
            return Err(LaunchError::Invalid(
                "admission interrupt is not an original user phase",
            ));
        }
        Ok(event)
    }

    /// Exact current application signal in a closed user phase. The original
    /// Unknown registry record remains unchanged and must receive a separate
    /// delivery/frame resolution before any publication relies on it.
    pub(in crate::linux::remote::dynamic) fn admission_original_signal(
        &self,
        id: TaskId,
    ) -> Result<(DynamicEvent, crate::lifecycle::ObligationRecord), LaunchError> {
        let event = self.admission_held_event(id)?;
        let task = self
            .tasks
            .get(&event.tid)
            .ok_or(LaunchError::Invalid("signal admission task is unknown"))?;
        let DynamicEventKind::SignalDelivery(info) = &event.kind else {
            return Err(LaunchError::Invalid(
                "admission event is not an original signal",
            ));
        };
        let obligation = task
            .signal_obligation
            .and_then(|id| self.registry.obligations().find(|row| row.id == id))
            .ok_or(LaunchError::Invalid(
                "original signal lacks its exact retained obligation",
            ))?;
        if task.syscall_open
            || task.fork_return.is_some()
            || self.pending.is_some()
            || self.exec_pending.is_some()
            || obligation.task != task.identity.task
            || obligation.address_space != task.identity.address_space
            || obligation.inherited_from.is_some()
            || obligation.kind
                != (crate::lifecycle::ObligationKind::PendingSignal {
                    signal: info.signal() as u8,
                    code: info.code(),
                    scope: SignalScope::Unknown,
                })
        {
            return Err(LaunchError::Invalid(
                "signal admission is not the exact closed user delivery",
            ));
        }
        Ok((event, obligation.clone()))
    }

    pub(in crate::linux::remote::dynamic) fn admission_held_token(
        &self,
        id: TaskId,
    ) -> Result<DynamicStop, LaunchError> {
        let record = recorded(self.registry.task(id))?;
        match &self.tasks[&record.tid].state {
            State::Held(event) => event
                .stop
                .clone()
                .ok_or(LaunchError::Invalid("held event lacks token")),
            State::AdmissionHeld(stop) => Ok(stop.token.clone()),
            _ => Err(LaunchError::Invalid("admission task is not held")),
        }
    }

    pub(in crate::linux::remote::dynamic) fn admission_interrupt_credit(
        &self,
        tid: i32,
    ) -> Result<u8, LaunchError> {
        self.tasks
            .get(&tid)
            .map(|task| task.interrupt_stops_remaining)
            .ok_or(LaunchError::Invalid("unknown trusted task"))
    }
    pub(in crate::linux::remote::dynamic) fn consume_admission_interrupt(
        &mut self,
        tid: i32,
    ) -> Result<bool, LaunchError> {
        let task = self
            .tasks
            .get_mut(&tid)
            .ok_or(LaunchError::Invalid("unknown trusted task"))?;
        let present = task.interrupt_stops_remaining != 0;
        task.interrupt_stops_remaining = task.interrupt_stops_remaining.saturating_sub(1);
        Ok(present)
    }

    pub(in crate::linux::remote::dynamic) fn begin_admission_execution(
        &mut self,
        stop: &AdmissionStop,
    ) -> Result<(), LaunchError> {
        self.require_admission_stop(stop)?;
        recorded(
            self.registry
                .resume(stop.identity.task, stop.token.sequence),
        )?;
        self.tasks.get_mut(&stop.token.tid).unwrap().state = State::Running;
        Ok(())
    }

    /// Only a completed kernel return can use the neutral bridge. A signal
    /// delivery, syscall ENTRY, creation event or control interruption cannot.
    pub(in crate::linux::remote::dynamic) fn begin_admission_return_bridge(
        &mut self,
        token: &DynamicStop,
    ) -> Result<(), LaunchError> {
        let event = self.require_stop(token)?.clone();
        let task = &self.tasks[&token.tid];
        if self.pending.is_some()
            || self.exec_pending.is_some()
            || self.tasks.values().any(|task| task.fork_return.is_some())
            || task.syscall_open
            || !matches!(
                event.kind,
                DynamicEventKind::SyscallExit { .. } | DynamicEventKind::Newborn { .. }
            )
        {
            return Err(LaunchError::Invalid(
                "unqualified native return-bridge phase",
            ));
        }
        if let DynamicEventKind::SyscallExit { result, is_error } = event.kind {
            if [-512, -513, -514, -516].contains(&result) {
                return Err(LaunchError::Invalid(
                    "restartable kernel return cannot authorize injection",
                ));
            }
            let info = syscall_info(token.tid)?;
            let registers = read_registers(token.tid)?;
            if info.arch != AUDIT_ARCH_X86_64
                || info.op != libc::PTRACE_SYSCALL_INFO_EXIT
                || info.instruction_pointer != registers.rip
                || info.stack_pointer != registers.rsp
                || registers.rax as i64 != result
            {
                return Err(LaunchError::Invalid(
                    "return bridge lost its actual syscall exit",
                ));
            }
            // SAFETY: exact EXIT operation authenticated the initialized union member.
            let exit = unsafe { info.u.exit };
            if exit.sval != result
                || (exit.is_error != 0) != is_error
                || is_error != (-4095..=-1).contains(&result)
            {
                return Err(LaunchError::Invalid("return bridge syscall result differs"));
            }
        }
        let identity = task.identity;
        recorded(self.registry.resume(identity.task, token.sequence))?;
        self.tasks.get_mut(&token.tid).unwrap().state = State::Running;
        self.events
            .retain(|queued| queued.stop.as_ref() != Some(token));
        Ok(())
    }

    /// # Safety
    /// The signal transport observed the original rt_sigreturn ENTRY and this
    /// exact EXIT, and authenticated `expected` from the complete live frame.
    /// An arbitrary syscall EXIT cannot use this phase-specific bridge. Restored
    /// RAX is application state, including values in Linux's restart/errno range.
    pub(in crate::linux::remote::dynamic) unsafe fn begin_admission_sigreturn_bridge(
        &mut self,
        token: &DynamicStop,
        expected: &super::super::trusted::TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        let event = self.require_stop(token)?.clone();
        let task = &self.tasks[&token.tid];
        let DynamicEventKind::SyscallExit { result, is_error } = event.kind else {
            return Err(LaunchError::Invalid(
                "signal return bridge is not at actual syscall EXIT",
            ));
        };
        if self.tasks.len() != 1
            || task.syscall_open
            || self.pending.is_some()
            || self.exec_pending.is_some()
            || task.fork_return.is_some()
            || !self.events.is_empty()
            || expected.registers.orig_rax != u64::MAX
            || super::super::trusted::TaskStateSnapshot::read(token.tid)? != *expected
        {
            return Err(LaunchError::Invalid(
                "signal return bridge lost exact singleton restored state",
            ));
        }
        let info = syscall_info(token.tid)?;
        if info.op != libc::PTRACE_SYSCALL_INFO_EXIT
            || info.arch != AUDIT_ARCH_X86_64
            || info.instruction_pointer != expected.registers.rip
            || info.stack_pointer != expected.registers.rsp
        {
            return Err(LaunchError::Invalid(
                "signal return bridge lost native EXIT ABI",
            ));
        }
        let exit = unsafe { info.u.exit };
        if exit.is_error > 1
            || exit.sval != result
            || (exit.is_error != 0) != is_error
            || result as u64 != expected.registers.rax
        {
            return Err(LaunchError::Invalid(
                "signal return bridge raw result changed",
            ));
        }
        let id = task.identity.task;
        recorded(self.registry.resume(id, token.sequence))?;
        self.tasks.get_mut(&token.tid).unwrap().state = State::Running;
        Ok(())
    }

    /// Called only after the private runner authenticates a real stop, restores
    /// the exact intended original state and verifies its resulting PC.
    pub(in crate::linux::remote::dynamic) fn finish_admission_execution(
        &mut self,
        tid: i32,
        pc: u64,
        phase: AdmissionPhase,
    ) -> Result<AdmissionStop, LaunchError> {
        let identity = self
            .tasks
            .get(&tid)
            .ok_or(LaunchError::Invalid("unknown trusted completion"))?
            .identity;
        if read_registers(tid)?.rip != pc {
            return Err(LaunchError::Invalid(
                "trusted restored PC differs from registry update",
            ));
        }
        recorded(self.registry.observe_stop(
            identity.task,
            self.sequence(tid)?,
            pc,
            HoldReason::OwnedTrap,
        ))?;
        let sequence = recorded(self.registry.task(identity.task))?.sequence;
        let stop = AdmissionStop {
            token: DynamicStop {
                session: self.session,
                sequence,
                tid,
                task: Some(identity.task),
            },
            identity,
            phase,
            signal: None,
        };
        self.tasks.get_mut(&tid).unwrap().state = State::AdmissionHeld(Box::new(stop.clone()));
        Ok(stop)
    }

    /// Collect a complete native hold without first recording owned faults as
    /// application signals. The classifier is the sealed domain's exact page /
    /// source lookup; a positive expectation is still independently checked
    /// against native ownership, raw siginfo, permissions, bytes and PC.
    ///
    /// Generic sibling events remain in their original queue. Newly observed
    /// private stops are returned to the admission queue rather than discarded.
    pub(in crate::linux::remote::dynamic) fn collect_admission_mm(
        &mut self,
        owner: &mut Owner,
        selected: TaskId,
        until: Instant,
        mut classify: impl FnMut(i32, i32) -> Result<Option<TrapExpectation>, LaunchError>,
    ) -> Result<(MmMembership, Vec<AdmissionStop>), LaunchError> {
        owner.time_left(until, "collect admission mm")?;
        let record = recorded(self.registry.task(selected))?.clone();
        if self.pending.is_some()
            || self.exec_pending.is_some()
            || self.tasks.values().any(|task| task.fork_return.is_some())
        {
            return Err(LaunchError::Invalid(
                "admission cannot freeze unresolved lifecycle pairing",
            ));
        }
        let result = (|| {
            for (&tid, task) in &mut self.tasks {
                if task.identity.address_space != record.address_space {
                    return Err(LaunchError::Invalid(
                        "admission collection encountered another mm",
                    ));
                }
                match &task.state {
                    State::Running => {
                        ptrace(libc::PTRACE_INTERRUPT, tid, 0, 0)?;
                        task.interrupt_stops_remaining = 2;
                    }
                    State::Held(_) | State::AdmissionHeld(_) | State::Terminal => {}
                    _ => {
                        return Err(LaunchError::Invalid(
                            "mm contains an unheld or exiting native task",
                        ));
                    }
                }
            }
            let mut owned = Vec::new();
            while self
                .tasks
                .values()
                .any(|task| matches!(task.state, State::Running))
            {
                let (tid, status) = owner.wait_raw(until, "collect admission mm")?;
                if let Some(expected) = classify(tid, status)? {
                    owned.push(self.observe_admission_owned(owner, tid, status, expected)?);
                } else if let Some(event) = self.observe(owner, tid, status)? {
                    self.events.push_back(event);
                }
            }
            Ok((self.check_admission_mm(owner, selected)?, owned))
        })();
        if result.is_err() {
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
        }
        result
    }

    /// Retain original lifecycle/signal semantics after the domain has declined
    /// ownership of this exact raw stop. No pending signal is erased or forged.
    pub(in crate::linux::remote::dynamic) fn observe_admission_other(
        &mut self,
        owner: &mut Owner,
        tid: i32,
        status: i32,
    ) -> Result<Option<DynamicEvent>, LaunchError> {
        self.observe(owner, tid, status)
    }

    pub(in crate::linux::remote::dynamic) fn take_admission_event(
        &mut self,
    ) -> Option<DynamicEvent> {
        self.events.pop_front()
    }

    pub(in crate::linux::remote::dynamic) fn admission_events_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// # Safety
    /// This is the one-invocation original execution permit, separate from any
    /// publication lease. The frontend proved exact original bytes and RX,
    /// complete held sibling membership, allowed instruction/syscall policy,
    /// and a closed original-release/rearm interlock. It must not reuse the
    /// permit after any unexpected stop or count it as a completed instruction.
    pub(in crate::linux::remote::dynamic) unsafe fn begin_admission_original(
        &mut self,
        owner: &mut Owner,
        stop: &AdmissionStop,
        request: libc::c_uint,
    ) -> Result<(), LaunchError> {
        if !matches!(request, libc::PTRACE_SINGLESTEP | libc::PTRACE_SYSCALL) {
            return Err(LaunchError::Invalid(
                "invalid selected original resume mode",
            ));
        }
        self.require_admission_stop(stop)?;
        if self.admission_interrupt_credit(stop.token.tid)? != 0 {
            return Err(LaunchError::Invalid(
                "original execution retains interrupt uncertainty",
            ));
        }
        let result = (|| {
            recorded(
                self.registry
                    .resume(stop.identity.task, stop.token.sequence),
            )?;
            ptrace(request, stop.token.tid, 0, 0)?;
            owner.released(stop.token.tid);
            self.tasks.get_mut(&stop.token.tid).unwrap().state = State::Running;
            Ok(())
        })();
        if result.is_err() {
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
        }
        result
    }

    /// # Safety
    /// The admission dispatcher has checked writer/lifecycle policy, current
    /// page/source rearming, and every retained continuation before permitting
    /// this exact original event disposition. The generic public API cannot
    /// reach this method through an admission-owned session.
    pub(in crate::linux::remote::dynamic) unsafe fn resume_admission_event(
        &mut self,
        owner: &mut Owner,
        token: &DynamicStop,
        action: DynamicResume,
    ) -> Result<(), LaunchError> {
        self.resume(owner, token, action)
    }

    pub(in crate::linux::remote::dynamic) fn check_admission_mm(
        &self,
        owner: &Owner,
        selected: TaskId,
    ) -> Result<MmMembership, LaunchError> {
        if self.pending.is_some()
            || self.exec_pending.is_some()
            || self.tasks.values().any(|task| task.fork_return.is_some())
        {
            return Err(LaunchError::Invalid(
                "admission membership has pending lifecycle state",
            ));
        }
        let record = recorded(self.registry.task(selected))?;
        let selected_token = self.admission_held_token(selected)?;
        if selected_token.tid != record.tid {
            return Err(LaunchError::Invalid("selected held task identity differs"));
        }
        let generation = recorded(self.registry.address_space(record.address_space))?.generation;
        let mut tids = BTreeSet::new();
        for (&tid, task) in &self.tasks {
            if matches!(task.state, State::Terminal) {
                if owner.handles.get(&tid).is_none_or(|fd| !broker::hup(fd)) {
                    return Err(LaunchError::Invalid(
                        "terminal task lacks physical removal proof",
                    ));
                }
                continue;
            }
            if task.identity.address_space != record.address_space
                || task.identity.process != record.process
                || task.identity.generation != generation
                || !matches!(task.state, State::Held(_) | State::AdmissionHeld(_))
                || !owner.owned.contains(&tid)
                || !owner.stopped.contains_key(&tid)
                || owner.handles.get(&tid).is_none_or(broker::hup)
            {
                return Err(LaunchError::Invalid("mm membership is not completely held"));
            }
            let status = read_bounded(
                &std::path::PathBuf::from(format!("/proc/{tid}/status")),
                MAX_MEMORY_READ,
            )?;
            let status = std::str::from_utf8(&status)
                .map_err(|_| LaunchError::Invalid("held task status is not UTF-8"))?;
            let tgid = status
                .lines()
                .filter_map(|line| line.strip_prefix("Tgid:"))
                .collect::<Vec<_>>();
            if tgid.len() != 1 || tgid[0].trim().parse::<i32>().ok() != Some(owner.pid) {
                return Err(LaunchError::Invalid(
                    "held task is not in the authenticated thread group",
                ));
            }
            tids.insert(tid);
        }
        if tids.is_empty() || tids.len() > 2 || !tids.contains(&owner.pid) {
            return Err(LaunchError::Invalid(
                "admission requires the bounded original thread group",
            ));
        }
        let mut kernel = BTreeSet::new();
        for entry in std::fs::read_dir(format!("/proc/{}/task", owner.pid))
            .map_err(|e| io_error("read held kernel task set", e))?
        {
            let entry = entry.map_err(|e| io_error("read held kernel task member", e))?;
            let tid = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
                .ok_or(LaunchError::Invalid("malformed kernel task identity"))?;
            if kernel.len() >= 2 || !kernel.insert(tid) {
                return Err(LaunchError::Invalid(
                    "unexpected held kernel task membership",
                ));
            }
        }
        if kernel != tids || owner.owned != tids {
            return Err(LaunchError::Invalid(
                "kernel and retained mm membership differ",
            ));
        }
        let candidate = recorded(
            self.registry
                .exclusion_candidate(record.address_space, generation),
        )?;
        Ok(MmMembership {
            address_space: record.address_space,
            generation,
            process: record.process,
            tgid: owner.pid,
            tids,
            candidate,
        })
    }

    /// Advance an actually revoked, still-held mm to a new uncertified
    /// generation. This is a model transition, not a fabricated kernel stop:
    /// native stop sequences stay unchanged while current identity bindings
    /// acquire the new generation. Historical obligations are retained.
    ///
    /// # Safety
    /// The owner admission transaction interlock is closed. A completed real
    /// whole-mm publication hold authenticated every old armed byte, revoked
    /// all application X permissions, restored/migrated every old edit, and
    /// completed sync-core. That old guard has been dropped without original
    /// execution. Old metadata remains available until restoration is proven.
    /// Every earlier queued lifecycle event has been copied into immutable
    /// diagnostic history; callers cannot discard its obligations. No original
    /// release is allowed until a new generation is fully authenticated/armed.
    pub(in crate::linux::remote::dynamic) unsafe fn advance_admission_generation(
        &mut self,
        owner: &mut Owner,
        island: &mut TrustedIsland,
        selected: TaskId,
    ) -> Result<u64, LaunchError> {
        if !self.events.is_empty() {
            return Err(LaunchError::Invalid(
                "generation advance has undrained lifecycle events",
            ));
        }
        let old = self.check_admission_mm(owner, selected)?;
        if island.address_space != old.address_space || island.generation != old.generation {
            return Err(LaunchError::Invalid(
                "generation advance island identity differs",
            ));
        }
        island.verify(self.admission_held_token(selected)?.tid)?;
        let result = (|| {
            // There is deliberately no ptrace/resume operation between these
            // two checked transitions. Hidden island stops therefore cannot
            // invalidate this fresh candidate or outrun the native hold.
            let ticket = recorded(self.registry.begin_invalidation(&old.candidate))?;
            recorded(self.registry.finish_invalidation(&ticket))?;
            let generation = recorded(self.registry.address_space(old.address_space))?.generation;
            if generation
                != old
                    .generation
                    .checked_add(1)
                    .ok_or(LaunchError::Invalid("admission generation overflow"))?
            {
                return Err(LaunchError::Invalid(
                    "admission generation did not advance exactly once",
                ));
            }
            for task in self
                .tasks
                .values_mut()
                .filter(|task| task.identity.address_space == old.address_space)
            {
                if matches!(task.state, State::Terminal) {
                    continue;
                }
                task.identity.generation = generation;
                match &mut task.state {
                    State::AdmissionHeld(stop) => stop.identity = task.identity,
                    State::Held(event) => event.task = Some(task.identity),
                    _ => return Err(LaunchError::Invalid("generation advance lost native hold")),
                }
            }
            island.generation = generation;
            self.check_admission_mm(owner, selected)?;
            Ok(generation)
        })();
        if result.is_err() {
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
        }
        result
    }

    /// Admission's release interlock calls this only after source rearming,
    /// synchronization and all current continuation obligations are satisfied.
    pub(in crate::linux::remote::dynamic) unsafe fn release_admitted(
        &mut self,
        owner: &mut Owner,
        stop: &AdmissionStop,
    ) -> Result<(), LaunchError> {
        self.require_admission_stop(stop)?;
        let result = (|| {
            recorded(
                self.registry
                    .resume(stop.identity.task, stop.token.sequence),
            )?;
            ptrace(libc::PTRACE_SYSCALL, stop.token.tid, 0, 0)?;
            owner.released(stop.token.tid);
            self.tasks.get_mut(&stop.token.tid).unwrap().state = State::Running;
            Ok(())
        })();
        if result.is_err() {
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
        }
        result
    }
}
