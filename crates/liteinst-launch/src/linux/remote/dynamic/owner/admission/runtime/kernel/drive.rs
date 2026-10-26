//! One pending provider invocation, followed by a native sealed transaction.
use super::*;

impl RuntimeOwner {
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn kernel_deadline(
        &self,
    ) -> Option<Instant> {
        self.kernel_pending
            .and_then(|index| self.kernel_attempts.get(index))
            .map(|attempt| attempt.until)
    }

    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn prepare_kernel(
        &mut self,
        owner: &mut Owner,
        window_index: usize,
        until: Instant,
    ) -> Result<Box<RuntimeProviderInput>, GateError> {
        if self.stage != RuntimeStage::Ready
            || !self.ready_issued
            || self.kernel_profile != RuntimeKernelProfile::IdentityAndTermination
            || self.selected_pending.is_some()
            || self.kernel_pending.is_some()
            || self.pages.iter().any(|page| page.executable)
        {
            return Err(refused(
                "runtime kernel preparation profile or phase differs",
            ));
        }
        owner.time_left(until, "runtime kernel preparation")?;
        let origin = self
            .initial_origin
            .ok_or_else(|| refused("runtime kernel current origin absent"))?;
        let census = self
            .census
            .as_mut()
            .ok_or_else(|| refused("runtime kernel census absent"))?;
        if census.active().count() != 1 {
            return Err(refused("runtime kernel requires one active origin"));
        }
        let before = census.current_observation(origin).map_err(census_error)?;
        let stop = self
            .native
            .as_ref()
            .ok_or_else(|| refused("runtime kernel native custody absent"))?
            .admission_current(before.task.task)?;
        if before.token != stop.token
            || before.task != stop.identity
            || before.phase != StopPhase::UserCheckpoint
            || before.signal.is_some()
        {
            return Err(refused("runtime kernel original checkpoint differs"));
        }
        let window = self
            .sources
            .window(window_index)
            .ok_or_else(|| refused("runtime kernel source window absent"))?;
        let operation = RuntimeKernelOperation::from_number(before.registers.rax)
            .ok_or_else(|| refused("runtime kernel original number is outside profile"))?;
        let next_pc = before
            .logical_pc
            .checked_add(2)
            .ok_or_else(|| refused("runtime kernel PC overflows"))?;
        let range = liteinst_admission::AddressRange::new(before.logical_pc, next_pc)
            .ok_or_else(|| refused("runtime kernel instruction range differs"))?;
        let geometry = FetchGeometry::for_initial_source(window.initial_source(), range)?;
        geometry.projected_rows(self.sources.runtime_baseline_maps()?)?;
        let shape = RuntimeKernelShape::new(operation, &geometry)?;
        let source = window.id;
        let window_bytes = window.snapshot.bytes().len();
        let serial = self.next_execution;
        let next = serial
            .checked_add(1)
            .ok_or_else(|| refused("runtime kernel invocation exhausted"))?;
        let token = RuntimePendingToken {
            stop: stop.token.clone(),
            task: stop.identity,
            generation: window.snapshot.generation,
            mapping: window.snapshot.mapping,
            window: window_index,
            pc: before.logical_pc,
            invocation: serial,
        };
        let journal = owner.kernel_journal.runtime_shape()?;
        let replacement = if self.kernel_attempts.len() == self.kernel_attempts.capacity() {
            add(self.kernel_attempts.len(), 1)?
        } else {
            0
        };
        // All six axes are reserved together, before any new payload or query.
        // A full replacement index is charged; retired allocations are not refunded.
        let reservation = census
            .reserve(reservation_charge(
                window_bytes,
                replacement,
                operation,
                &journal,
            )?)
            .map_err(census_error)?;
        if replacement != 0 {
            let mut index = exact_vec(replacement)?;
            census
                .account_external(
                    reservation,
                    BudgetCharge {
                        source_fact_bytes: mul(
                            replacement,
                            size_of::<Box<RuntimeKernelAttempt>>(),
                        )?,
                        ..BudgetCharge::default()
                    },
                )
                .map_err(census_error)?;
            index.append(&mut self.kernel_attempts);
            self.kernel_attempts = index;
        }
        let before = census.current_observation(origin).map_err(census_error)?;
        let attempt = Box::new(RuntimeKernelAttempt {
            until,
            stage: KernelStage::Allocated,
            first_failure: None,
            reservation,
            origin,
            token,
            stop: stop.clone(),
            before: empty_observed(before),
            source,
            operation,
            identity: None,
            input: None,
            decision: None,
            checks: KernelSourceChecks {
                bytes: std::array::from_fn(|_| Vec::new()),
                progress: std::array::from_fn(|_| SourceReadProgress::default()),
                identity: Vec::new(),
                checkpoint: empty_observed(before),
                stop,
            },
            native: PreparedRuntimeKernel::new(shape, until),
            prepared: None,
            journal: None,
            handle: None,
            sink: None,
            public: None,
            transferred: 0,
            journal_bytes: 0,
            debited: 0,
        });
        let index = self.kernel_attempts.len();
        self.kernel_attempts.push(attempt);
        self.kernel_pending = Some(index);
        self.next_execution = next;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.prepare_kernel_inner(owner, index, window_bytes, journal)
        }));
        self.kernel_outcome(owner, index, outcome)
    }

    fn prepare_kernel_inner(
        &mut self,
        owner: &mut Owner,
        index: usize,
        window_bytes: usize,
        journal: RuntimeJournalShape,
    ) -> Result<Box<RuntimeProviderInput>, GateError> {
        let attempt = &mut self.kernel_attempts[index];
        let census = self
            .census
            .as_mut()
            .ok_or_else(|| refused("runtime kernel census absent"))?;
        // The installed shell retains each successful native allocation even
        // if a later allocation, observer, query or unwind fails.
        attempt.native.allocate_payloads()?;
        attempt.before.xstate = bytes(MAX_XSTATE)?;
        attempt.checks.checkpoint.xstate = bytes(MAX_XSTATE)?;
        let actual = census
            .current_observation(attempt.origin)
            .map_err(census_error)?;
        copy_state(&mut attempt.before.xstate, &actual.xstate)?;
        copy_state(&mut attempt.checks.checkpoint.xstate, &actual.xstate)?;
        for source in &mut attempt.checks.bytes {
            *source = bytes(window_bytes)?;
        }
        attempt.checks.identity = bytes(MAP_BYTES)?;
        let window = self
            .sources
            .window(attempt.token.window)
            .ok_or_else(|| refused("runtime kernel source lost"))?;
        let offset = attempt
            .before
            .logical_pc
            .checked_sub(window.snapshot.range().start())
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| refused("runtime kernel source offset differs"))?;
        let encoded = window
            .snapshot
            .bytes()
            .get(offset..)
            .ok_or_else(|| refused("runtime kernel source bytes absent"))?;
        let decoded = crate::selected::decode(
            attempt.before.logical_pc,
            encoded,
            &SyscallAliases::default(),
        )?;
        let input = SelectedInput::new(decoded, attempt.before.registers)?;
        if RuntimeKernelOperation::from_input(&input)? != attempt.operation {
            return Err(refused("runtime kernel original operation changed"));
        }
        attempt.input = Some(input);
        if attempt.operation.returns() {
            let mut before_xstate = bytes(MAX_XSTATE)?;
            copy_state(&mut before_xstate, &attempt.before.xstate)?;
            let mut xstate = bytes(MAX_XSTATE)?;
            copy_state(&mut xstate, &attempt.before.xstate)?;
            // Unpublished response storage. Actual EXIT/closed values replace
            // these placeholders before a completed event can leave the owner.
            attempt.public = Some(Box::new(DynamicAdmissionCompletion {
                before_task: attempt.before.task,
                after_task: attempt.before.task,
                selected: SelectedCompletion {
                    input: attempt.input.as_ref().expect("retained input").clone(),
                    after: attempt.before.registers,
                    before_xstate,
                    xstate,
                    execution: SelectedExecution::Native,
                },
                before_signal_mask: attempt.before.signal_mask,
                signal_mask: attempt.before.signal_mask,
            }));
        }
        attempt.account(census)?;
        attempt.stage = KernelStage::SourceBefore;
        let native = self
            .native
            .as_ref()
            .ok_or_else(|| refused("runtime kernel native custody absent"))?;
        let island = &self
            .bootstrap
            .as_ref()
            .and_then(PreparedInitialBootstrap::completed)
            .ok_or_else(|| refused("runtime kernel bootstrap absent"))?
            .island;
        let lineage = self
            .control_lineage
            .as_ref()
            .ok_or_else(|| refused("runtime kernel control lineage absent"))?;
        let proof = {
            let read = self.sources.runtime_read(
                owner,
                native,
                island,
                &attempt.stop,
                &attempt.before,
                attempt.until,
            )?;
            read.verify_window(
                attempt.token.window,
                &mut attempt.checks.bytes[0],
                &mut attempt.checks.progress[0],
                &mut attempt.checks.identity,
            )?
        };
        let input = attempt.input.as_ref().expect("retained input");
        let binding = RuntimeKernelBinding::new(
            proof,
            census,
            BindingRequest {
                input,
                pending: &attempt.token,
                origin: attempt.origin,
                island,
                lineage,
            },
        )?;
        if binding.source_id() != attempt.source || binding.operation() != attempt.operation {
            return Err(refused(
                "runtime kernel authenticated source identity differs",
            ));
        }
        attempt.identity = Some(binding.identity().clone());
        attempt.prepared = Some(
            census
                .prepare_runtime_kernel(attempt.reservation, &binding)
                .map_err(census_error)?,
        );
        let journal_bound = journal.reservation_bytes();
        let journal_peak = journal.allocation_peak_bytes()?;
        attempt.journal = Some(owner.kernel_journal.prepare_runtime(
            journal,
            binding.identity(),
            binding.stop(),
            input,
            RuntimeJournalBefore {
                registers: &attempt.before.registers,
                xstate: &attempt.before.xstate,
                mask: attempt.before.signal_mask,
            },
        )?);
        let journal_bytes = attempt
            .journal
            .as_ref()
            .expect("installed journal")
            .retained_bytes()
            .checked_sub(size_of::<PreparedRuntimeJournal>())
            .ok_or_else(|| refused("runtime kernel journal header differs"))?;
        attempt.journal_bytes = journal_bytes;
        let prepared_journal = attempt.journal.as_ref().expect("installed journal");
        if prepared_journal.retained_bytes() != journal_bound
            || prepared_journal.allocation_peak_bytes()? != journal_peak
        {
            return Err(refused(
                "runtime kernel journal allocation differs from its complete reservation",
            ));
        }
        census
            .account_external(
                attempt.reservation,
                BudgetCharge {
                    source_fact_bytes: journal_bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        attempt.debited = add(attempt.debited, journal_bytes)?;
        let (handle, sink) = owner
            .kernel_journal
            .attach_runtime(attempt.journal.take().expect("installed journal"))?;
        attempt.handle = Some(handle);
        attempt.sink = Some(sink);
        if handle.id() != binding.attempt() {
            return Err(refused(
                "runtime kernel attached journal invocation differs",
            ));
        }
        let remaining = attempt
            .prepared
            .as_ref()
            .expect("installed census")
            .remaining_charge()
            .map_err(census_error)?;
        census
            .check_reserved(attempt.reservation, remaining)
            .map_err(census_error)?;
        attempt.stage = KernelStage::Prepared;
        {
            let mut observer = KernelObserver {
                sources: &self.sources,
                binding: &binding,
                census,
                reservation: attempt.reservation,
                remaining,
                storage: &mut attempt.checks,
                pages: &mut self.pages,
                sink: attempt.sink.as_mut().expect("installed journal sink"),
            };
            attempt
                .native
                .before_provider(owner, native, &binding, &mut observer)?;
        }
        let public = Box::new(RuntimeProviderInput {
            token: binding.pending().clone(),
            input: input.clone(),
        });
        let issued = add(
            size_of::<RuntimeProviderInput>(),
            input_bytes(&public.input)?,
        )?;
        census
            .account_external(
                attempt.reservation,
                BudgetCharge {
                    source_fact_bytes: issued,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        attempt.transferred = add(attempt.transferred, issued)?;
        attempt.debited = add(attempt.debited, issued)?;
        owner.time_left(attempt.until, "runtime kernel provider delivery")?;
        let observations = self
            .metrics
            .pages
            .observations
            .checked_add(1)
            .ok_or_else(|| refused("runtime observation counter exhausted"))?;
        let count = self
            .metrics
            .selected
            .callbacks
            .entry(input.instruction().operation().class())
            .or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| refused("runtime callback counter exhausted"))?;
        self.metrics.pages.observations = observations;
        attempt.stage = KernelStage::Pending;
        Ok(public)
    }

    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn complete_kernel(
        &mut self,
        owner: &mut Owner,
        token: RuntimePendingToken,
        decision: ProviderDecision,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let index = self
            .kernel_pending
            .ok_or_else(|| refused("runtime kernel invocation is not pending"))?;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.complete_kernel_inner(owner, index, token, decision, until)
        }));
        self.kernel_outcome(owner, index, outcome)
    }

    fn kernel_outcome<T>(
        &mut self,
        owner: &mut Owner,
        index: usize,
        outcome: Result<Result<T, GateError>, Box<dyn std::any::Any + Send>>,
    ) -> Result<T, GateError> {
        let attempt = &mut self.kernel_attempts[index];
        // Account partial initialized allocations on every preparation error.
        // All effects require an earlier successful complete debit.
        let account = self
            .census
            .as_mut()
            .ok_or_else(|| refused("runtime kernel census lost"))
            .and_then(|census| attempt.account(census));
        match outcome {
            Ok(Ok(value)) => {
                if let Err(error) = account {
                    attempt.fail(Some(&error));
                    owner.kernel_journal.fail_gate(&error);
                    attempt.sync_journal();
                    owner.closing = true;
                    owner.cancel.store(true, Ordering::Release);
                    return Err(error);
                }
                Ok(value)
            }
            Ok(Err(error)) => {
                attempt.fail(Some(&error));
                // Preserve the actual failure phase before diagnostic copying
                // can advance the journal to a partially observed raw slot.
                owner.kernel_journal.fail_gate(&error);
                attempt.sync_journal();
                owner.closing = true;
                owner.cancel.store(true, Ordering::Release);
                Err(error)
            }
            Err(payload) => {
                attempt.fail(None);
                owner
                    .kernel_journal
                    .fail_active(KernelFailureKind::CaughtPanic);
                attempt.sync_journal();
                owner.closing = true;
                owner.cancel.store(true, Ordering::Release);
                std::panic::resume_unwind(payload)
            }
        }
    }

    fn complete_kernel_inner(
        &mut self,
        owner: &mut Owner,
        index: usize,
        token: RuntimePendingToken,
        decision: ProviderDecision,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let attempt = &mut self.kernel_attempts[index];
        if self.kernel_profile != RuntimeKernelProfile::IdentityAndTermination
            || self.selected_pending.is_some()
            || attempt.stage != KernelStage::Pending
            || attempt.first_failure.is_some()
            || attempt.token != token
            || attempt.until != until
            || attempt.decision.is_some()
            || self.initial_origin != Some(attempt.origin)
            || self.pages.iter().any(|page| page.executable)
        {
            return Err(refused(
                "runtime kernel pending identity or original deadline differs",
            ));
        }
        owner.time_left(until, "runtime kernel original invocation")?;
        let native = self
            .native
            .as_mut()
            .ok_or_else(|| refused("runtime kernel native custody absent"))?;
        native.require_admission_stop(&attempt.stop)?;
        let census = self
            .census
            .as_mut()
            .ok_or_else(|| refused("runtime kernel census absent"))?;
        census
            .check_current_origin(attempt.origin, &attempt.before)
            .map_err(census_error)?;
        let island = &self
            .bootstrap
            .as_ref()
            .and_then(PreparedInitialBootstrap::completed)
            .ok_or_else(|| refused("runtime kernel bootstrap absent"))?
            .island;
        let lineage = self
            .control_lineage
            .as_ref()
            .ok_or_else(|| refused("runtime kernel control lineage absent"))?;
        attempt.stage = KernelStage::SourceAfterProvider;
        let proof = {
            let read = self.sources.runtime_read(
                owner,
                native,
                island,
                &attempt.stop,
                &attempt.before,
                until,
            )?;
            read.verify_window(
                attempt.token.window,
                &mut attempt.checks.bytes[1],
                &mut attempt.checks.progress[1],
                &mut attempt.checks.identity,
            )?
        };
        let input = attempt
            .input
            .as_ref()
            .ok_or_else(|| refused("runtime kernel input lost"))?;
        let binding = RuntimeKernelBinding::new(
            proof,
            census,
            BindingRequest {
                input,
                pending: &attempt.token,
                origin: attempt.origin,
                island,
                lineage,
            },
        )?;
        if attempt.identity.as_ref() != Some(binding.identity()) {
            return Err(refused(
                "runtime kernel provider changed authenticated binding",
            ));
        }
        attempt.decision = Some(decision);
        match decision {
            ProviderDecision::Complete(_) => {
                return Err(refused(
                    "runtime kernel profile requires native execution or a provider fault",
                ));
            }
            ProviderDecision::Fault(fault) => {
                let fault = Box::new(input.fault(fault));
                let issued = add(
                    size_of::<crate::selected::FaultedInstruction>(),
                    input_bytes(&fault.input)?,
                )?;
                census
                    .account_external(
                        attempt.reservation,
                        BudgetCharge {
                            source_fact_bytes: issued,
                            ..BudgetCharge::default()
                        },
                    )
                    .map_err(census_error)?;
                attempt.transferred = add(attempt.transferred, issued)?;
                attempt.debited = add(attempt.debited, issued)?;
                self.metrics.selected.provider_faults = self
                    .metrics
                    .selected
                    .provider_faults
                    .checked_add(1)
                    .ok_or_else(|| refused("runtime provider fault counter exhausted"))?;
                attempt
                    .sink
                    .as_mut()
                    .ok_or_else(|| refused("runtime kernel journal sink lost"))?
                    .fail(
                        RuntimeKernelJournalStage::Prepared,
                        KernelFailureKind::Cancelled,
                    );
                census
                    .finish_reservation(attempt.reservation)
                    .map_err(census_error)?;
                attempt.stage = KernelStage::Fault;
                self.kernel_pending = None;
                owner.closing = true;
                owner.cancel.store(true, Ordering::Release);
                return Ok(AdmissionReply::Event(DynamicAdmissionEvent::Fault {
                    task: attempt.before.task,
                    fault,
                }));
            }
            ProviderDecision::Native => {}
        }
        let prepared = attempt
            .prepared
            .as_mut()
            .ok_or_else(|| refused("runtime kernel prepared census lost"))?;
        let remaining = prepared.remaining_charge().map_err(census_error)?;
        census
            .check_reserved(attempt.reservation, remaining)
            .map_err(census_error)?;
        let completions = if attempt.operation.returns() {
            Some(
                self.metrics
                    .selected
                    .native_completions
                    .checked_add(1)
                    .ok_or_else(|| refused("runtime native completion counter exhausted"))?,
            )
        } else {
            None
        };
        attempt.stage = KernelStage::Native;
        {
            let mut observer = KernelObserver {
                sources: &self.sources,
                binding: &binding,
                census,
                reservation: attempt.reservation,
                remaining,
                storage: &mut attempt.checks,
                pages: &mut self.pages,
                sink: attempt
                    .sink
                    .as_mut()
                    .ok_or_else(|| refused("runtime kernel journal sink lost"))?,
            };
            attempt
                .native
                .execute(owner, native, &binding, &mut observer)?;
        }
        let identity = attempt
            .identity
            .as_ref()
            .expect("bound native identity retained");
        let handle = attempt
            .handle
            .ok_or_else(|| refused("runtime kernel journal handle lost"))?;
        attempt.stage = KernelStage::Census;
        if attempt.operation.returns() {
            let sealed = attempt.native.take_returned()?;
            let next_lineage = lineage.kernel_successor(&sealed)?;
            let closed = sealed.closing()[2];
            let actual_exit = sealed.exit();
            if closed.state != actual_exit.state {
                return Err(refused(
                    "runtime kernel closed state differs from actual EXIT",
                ));
            }
            let public = attempt
                .public
                .as_mut()
                .ok_or_else(|| refused("runtime kernel return response lost"))?;
            public.after_task = closed.stop.identity;
            public.selected.after = closed.state.registers;
            copy_state(&mut public.selected.xstate, &closed.state.xstate)?;
            public.signal_mask = closed.state.mask;
            attempt
                .sink
                .as_mut()
                .expect("retained sink")
                .returned(identity, sealed.trace())?;
            let result = census
                .commit_runtime_kernel_return(attempt.reservation, sealed, prepared)
                .map_err(census_error)?;
            let current = result
                .current
                .ok_or_else(|| refused("runtime kernel return lacks successor origin"))?;
            owner
                .kernel_journal
                .finish_runtime_return(handle, result.receipt)?;
            census
                .finish_reservation(attempt.reservation)
                .map_err(census_error)?;
            self.initial_origin = Some(current);
            self.control_lineage = Some(next_lineage);
            self.kernel_pending = None;
            self.metrics.selected.native_completions = completions.expect("return count prepared");
            // Moving a prepaid public payload does not refund its lifetime debit.
            let public = attempt.public.take().expect("prepaid response retained");
            attempt.transferred = add(attempt.transferred, public_bytes(&public)?)?;
            attempt.stage = KernelStage::Returned;
            Ok(AdmissionReply::Event(DynamicAdmissionEvent::Completed(
                public,
            )))
        } else {
            let sealed = attempt.native.take_terminal()?;
            let event = sealed.terminal_event();
            let DynamicEventKind::TaskTerminal { status } = event.kind else {
                return Err(refused(
                    "runtime kernel terminal seal lacks actual terminal event",
                ));
            };
            let task = event
                .task
                .ok_or_else(|| refused("runtime kernel terminal task absent"))?;
            let result = census
                .commit_runtime_kernel_terminal(attempt.reservation, sealed, prepared)
                .map_err(census_error)?;
            if result.current.is_some() {
                return Err(refused("runtime kernel terminal fabricated a successor"));
            }
            owner
                .kernel_journal
                .finish_runtime_terminal(handle, result.receipt)?;
            census
                .finish_reservation(attempt.reservation)
                .map_err(census_error)?;
            self.initial_origin = None;
            self.control_lineage = None;
            self.kernel_pending = None;
            self.stage = RuntimeStage::Terminal;
            attempt.stage = KernelStage::Terminal;
            // The open-page diagnostic ledger is retained as last observed.
            // The destroyed mm has no synthetic NX-closing observation.
            Ok(AdmissionReply::Event(DynamicAdmissionEvent::TaskTerminal {
                task,
                status,
                all_terminal: true,
            }))
        }
    }
}
