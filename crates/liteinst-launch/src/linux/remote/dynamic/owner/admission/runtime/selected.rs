//! Selected CPU emulation at an authenticated actual PC. No Domain, installed
//! guard, complete-head assertion, or ordinary native execution is fabricated.
use super::super::census::{PreparedRuntimeSelected, Reservation};
use super::super::runtime_capture::{CapturedRuntimeRead, SourceWindowId};
use super::super::source_identity::SourceReadProgress;
use super::*;
use crate::gate::{SelectedCompletion, SelectedExecution};
use crate::linux::remote::dynamic::admission::{RuntimePendingToken, RuntimeProviderInput};
use crate::selected::{
    self, CompletedInstruction, Operation, ProviderDecision, SelectedInput, SelectedResult,
    SemanticsError, SyscallAliases,
};
use std::mem::size_of;

pub(in crate::linux::remote::dynamic::owner::admission) mod native;
use native::{NativeSelectedBinding, PreparedNativeSelected};
#[cfg(test)]
mod tests;

const MAP_BYTES: usize = 64 * 1024;
const READS: usize = 3; // before provider, after provider, after actual restoration
const FLAGS: u64 = 1 | 2 | 4 | 16 | 64 | 128 | 512 | 1024 | 2048 | (1 << 18) | (1 << 21);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SelectedPhase {
    Allocated,
    SourceBefore,
    Pending,
    SourceAfterProvider,
    Prepared,
    Native,
    SourceAfterNative,
    Census,
    Completed,
    Fault,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SelectedFailure {
    Refused(&'static str),
    Invalid(&'static str),
    System(&'static str, Option<i32>),
    Timeout(&'static str),
    Child(i32),
    Semantics(SemanticsError),
    Other,
    Unwound,
}

/// Append-only owner history. Diagnostic views cannot retry this transaction.
/// On any error or unwind Owner reinstalls RuntimeOwner before physical cleanup.
pub(super) struct RuntimeSelectedAttempt {
    until: Instant,
    phase: SelectedPhase,
    first_failure: Option<(SelectedPhase, SelectedFailure)>,
    reservation: Reservation,
    origin: OriginId,
    invocation: ExecutionId,
    source: SourceWindowId,
    token: RuntimePendingToken,
    stop: AdmissionStop,
    before: ObservedStop,
    successor: ObservedStop,
    input: Option<SelectedInput>,
    decision: Option<ProviderDecision>,
    completed: Option<CompletedInstruction>,
    source_bytes: [Vec<u8>; READS],
    source_progress: [SourceReadProgress; READS],
    identity_scratch: Vec<u8>,
    native: PreparedNativeSelected,
    prepared: Option<Box<PreparedRuntimeSelected>>,
    public: Option<Box<DynamicAdmissionCompletion>>,
}

fn refused(reason: &'static str) -> GateError {
    GateError::Refused(reason)
}
fn add(a: usize, b: usize) -> Result<usize, GateError> {
    a.checked_add(b)
        .ok_or_else(|| refused("runtime selected evidence size overflows"))
}
fn bytes(length: usize) -> Result<Vec<u8>, GateError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| refused("runtime selected allocation failed"))?;
    if bytes.capacity() != length {
        return Err(refused("runtime selected allocation exceeds reservation"));
    }
    bytes.resize(length, 0);
    Ok(bytes)
}
fn copy_observed(source: &ObservedStop) -> Result<ObservedStop, GateError> {
    let mut xstate = bytes(MAX_XSTATE)?;
    if !(512..MAX_XSTATE).contains(&source.xstate.len()) {
        return Err(refused("runtime selected XSTATE extent differs"));
    }
    xstate[..source.xstate.len()].copy_from_slice(&source.xstate);
    xstate.truncate(source.xstate.len());
    Ok(ObservedStop {
        token: source.token.clone(),
        task: source.task,
        logical_pc: source.logical_pc,
        registers: source.registers,
        xstate,
        signal_mask: source.signal_mask,
        phase: source.phase,
        signal: source.signal.clone(),
    })
}
fn instruction_capacity(input: &SelectedInput) -> Result<usize, GateError> {
    let capacity = input.instruction().retained_capacity();
    if input.instruction().bytes().is_empty() || capacity > 15 {
        return Err(refused("runtime selected instruction allocation differs"));
    }
    Ok(capacity)
}
fn cpu_input(input: &SelectedInput) -> Result<(), GateError> {
    if matches!(input.instruction().operation(), Operation::Syscall { .. }) {
        return Err(refused(
            "runtime selected syscall transport is not qualified",
        ));
    }
    let registers = input.registers();
    if registers.cs != 0x33
        || registers.eflags & (0x100 | 0x10000) != 0
        || registers.eflags & 2 == 0
        || registers.eflags & !FLAGS != 0
        || registers.orig_rax != u64::MAX
    {
        return Err(refused("runtime selected native64 control flags differ"));
    }
    Ok(())
}
fn model(input: &SelectedInput, result: SelectedResult) -> Result<CompletedInstruction, GateError> {
    cpu_input(input)?;
    // The original complete selected semantics are the sole result transform.
    // No opcode-specific rewrite, integer truncation or flag masking is added.
    Ok(input.complete(result)?)
}
/// Scripted CPU semantics with exact current sealed orig_rax provenance.
/// The legacy MAX-only model remains unchanged and is used for that branch.
pub(in crate::linux::remote::dynamic::owner::admission) fn model_with_lineage(
    input: &SelectedInput,
    result: SelectedResult,
    lineage: &super::super::runtime_native::ControlLineage,
    stop: &AdmissionStop,
) -> Result<CompletedInstruction, GateError> {
    if matches!(input.instruction().operation(), Operation::Syscall { .. }) {
        return Err(refused(
            "runtime selected syscall transport is not qualified",
        ));
    }
    lineage.require_orig_rax(stop, input.registers().orig_rax)?;
    if input.registers().orig_rax == u64::MAX {
        return model(input, result);
    }
    let registers = input.registers();
    if registers.cs != 0x33
        || registers.eflags & (0x100 | 0x10000) != 0
        || registers.eflags & 2 == 0
        || registers.eflags & !FLAGS != 0
    {
        return Err(refused("runtime selected native64 control flags differ"));
    }
    let completed = input.complete(result)?;
    if completed.after.orig_rax != registers.orig_rax {
        return Err(refused("runtime selected modeled orig_rax differs"));
    }
    Ok(completed)
}
fn budget(window_bytes: usize, history_growth: usize) -> Result<BudgetCharge, GateError> {
    if window_bytes == 0 || window_bytes > MAP_BYTES || history_growth > 1 {
        return Err(refused("runtime selected reservation geometry differs"));
    }
    let mut payload = size_of::<RuntimeSelectedAttempt>();
    payload = add(
        payload,
        history_growth * size_of::<Box<RuntimeSelectedAttempt>>(),
    )?;
    payload = add(payload, 2 * MAX_XSTATE + READS * window_bytes + MAP_BYTES)?;
    payload = add(payload, PreparedNativeSelected::payload_bound())?;
    payload = add(payload, size_of::<RuntimeProviderInput>() + 15)?;
    payload = add(
        payload,
        size_of::<DynamicAdmissionCompletion>() + 2 * MAX_XSTATE + 15,
    )?;
    payload = add(payload, 30)?; // retained input and modeled completion encodings
    payload = add(
        payload,
        size_of::<crate::selected::FaultedInstruction>() + 15,
    )?;
    // Authentication has bounded transient storage; reservation is retained
    // without misreporting this unused peak as newly retained payload.
    payload = add(payload, CapturedRuntimeRead::temporary_bytes())?;
    payload = add(
        payload,
        super::super::runtime_native::ControlProfile::temporary_bytes()?,
    )?;
    payload = add(payload, size_of::<native::NativeSelectedProof>())?;
    payload = add(
        payload,
        add(
            size_of::<super::super::runtime_native::ControlLineage>(),
            size_of::<super::super::runtime_native::ControlLineage>(),
        )?,
    )?;
    payload = add(payload, size_of::<CompletedInstruction>() + 15)?;
    // Both census prepare and commit may scan inherited kernel lineage. They
    // share this operation's prepaid peak, with no global/recycled credit.
    payload = add(
        payload,
        crate::linux::remote::dynamic::owner::admission::census::runtime_lineage_temporary_bytes()
            .map_err(census_error)?,
    )?;
    let prepared = PreparedRuntimeSelected::reservation_charge().map_err(census_error)?;
    Ok(BudgetCharge {
        source_fact_bytes: add(payload, prepared.source_fact_bytes)?,
        epochs: prepared.epochs,
        reports: prepared.reports,
        origins: prepared.origins,
        witnesses: prepared.witnesses,
        plan_history: prepared.plan_history,
    })
}
impl RuntimeSelectedAttempt {
    fn allocated_bytes(&self) -> Result<usize, GateError> {
        let mut total = size_of::<Self>();
        total = add(total, self.before.xstate.capacity())?;
        total = add(total, self.successor.xstate.capacity())?;
        total = add(total, self.identity_scratch.capacity())?;
        for bytes in &self.source_bytes {
            total = add(total, bytes.capacity())?;
        }
        add(total, self.native.payload_bytes()?)
    }
    fn fail(&mut self, error: Option<&GateError>) {
        if self.first_failure.is_some() {
            return;
        }
        let failure = match error {
            None => SelectedFailure::Unwound,
            Some(GateError::Refused(reason)) => SelectedFailure::Refused(reason),
            Some(GateError::Selected(error)) => SelectedFailure::Semantics(*error),
            Some(GateError::Control(LaunchError::Invalid(reason))) => {
                SelectedFailure::Invalid(reason)
            }
            Some(GateError::Control(LaunchError::System { operation, source })) => {
                SelectedFailure::System(operation, source.raw_os_error())
            }
            Some(GateError::Control(LaunchError::Timeout(operation))) => {
                SelectedFailure::Timeout(operation)
            }
            Some(GateError::Control(LaunchError::Child { status })) => {
                SelectedFailure::Child(*status)
            }
            Some(_) => SelectedFailure::Other,
        };
        self.first_failure = Some((self.phase, failure));
    }
}

impl RuntimeOwner {
    pub(super) fn selected_deadline(&self) -> Option<Instant> {
        self.selected_pending
            .and_then(|index| self.selected_attempts.get(index))
            .map(|attempt| attempt.until)
    }

    pub(super) fn prepare_selected(
        &mut self,
        owner: &mut Owner,
        window: usize,
        until: Instant,
    ) -> Result<Box<RuntimeProviderInput>, GateError> {
        if self.stage != RuntimeStage::Ready
            || !self.ready_issued
            || self.selected_pending.is_some()
            || self.pages.iter().any(|page| page.executable)
        {
            return Err(refused("runtime selected preparation phase differs"));
        }
        owner.time_left(until, "runtime selected preparation")?;
        let native = self
            .native
            .as_ref()
            .ok_or_else(|| refused("runtime selected native custody missing"))?;
        let census = self
            .census
            .as_ref()
            .ok_or_else(|| refused("runtime selected census missing"))?;
        let origin = self
            .initial_origin
            .ok_or_else(|| refused("runtime selected current origin missing"))?;
        if census.active().count() != 1 {
            return Err(refused(
                "runtime selected requires one active current origin",
            ));
        }
        let before = census.current_observation(origin).map_err(census_error)?;
        if before.phase != StopPhase::UserCheckpoint || before.signal.is_some() {
            return Err(refused(
                "runtime selected current observation phase differs",
            ));
        }
        let stop = native.admission_current(before.task.task)?;
        if stop.token != before.token || stop.identity != before.task {
            return Err(refused("runtime selected current stop differs"));
        }
        let source = self
            .sources
            .window(window)
            .ok_or_else(|| refused("runtime selected source window missing"))?;
        if !source.target.contains(before.logical_pc) {
            return Err(refused("runtime selected PC is outside target window"));
        }
        let source_id = source.id;
        let length = source.snapshot.bytes().len();
        let generation = source.snapshot.generation;
        let mapping = source.snapshot.mapping;
        let serial = self.next_execution;
        let next = serial
            .checked_add(1)
            .ok_or_else(|| refused("runtime selected invocation overflow"))?;
        let invocation = ExecutionId::from_owner(owner.session, serial).map_err(census_error)?;
        let old_capacity = self.selected_attempts.capacity();
        let growth = usize::from(self.selected_attempts.len() == old_capacity);
        let reservation = self
            .census
            .as_mut()
            .expect("census validated")
            .reserve(budget(length, growth)?)
            .map_err(census_error)?;
        self.selected_attempts
            .try_reserve_exact(1)
            .map_err(|_| refused("runtime selected history allocation failed"))?;
        if self.selected_attempts.capacity() > old_capacity + growth {
            return Err(refused(
                "runtime selected history allocation exceeds reservation",
            ));
        }
        let before = self
            .census
            .as_ref()
            .expect("census retained")
            .current_observation(origin)
            .map_err(census_error)?;
        let token = RuntimePendingToken {
            stop: stop.token.clone(),
            task: stop.identity,
            generation,
            mapping,
            window,
            pc: before.logical_pc,
            invocation: serial,
        };
        let attempt = Box::new(RuntimeSelectedAttempt {
            until,
            phase: SelectedPhase::Allocated,
            first_failure: None,
            reservation,
            origin,
            invocation,
            source: source_id,
            token,
            stop,
            before: copy_observed(before)?,
            successor: copy_observed(before)?,
            input: None,
            decision: None,
            completed: None,
            source_bytes: [bytes(length)?, bytes(length)?, bytes(length)?],
            source_progress: std::array::from_fn(|_| SourceReadProgress::default()),
            identity_scratch: bytes(MAP_BYTES)?,
            native: PreparedNativeSelected::allocate()?,
            prepared: None,
            public: None,
        });
        let retained = add(
            attempt.allocated_bytes()?,
            (self.selected_attempts.capacity() - old_capacity)
                * size_of::<Box<RuntimeSelectedAttempt>>(),
        )?;
        self.census
            .as_mut()
            .expect("census retained")
            .account_external(
                reservation,
                BudgetCharge {
                    source_fact_bytes: retained,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        let index = self.selected_attempts.len();
        self.selected_attempts.push(attempt);
        self.selected_pending = Some(index);
        self.next_execution = next;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.prepare_selected_inner(owner, index)
        }));
        self.selected_outcome(owner, index, outcome)
    }

    fn prepare_selected_inner(
        &mut self,
        owner: &Owner,
        index: usize,
    ) -> Result<Box<RuntimeProviderInput>, GateError> {
        let attempt = &mut self.selected_attempts[index];
        attempt.phase = SelectedPhase::SourceBefore;
        let native = self
            .native
            .as_ref()
            .ok_or_else(|| refused("runtime selected native custody missing"))?;
        let boot = self
            .bootstrap
            .as_ref()
            .and_then(PreparedInitialBootstrap::completed)
            .ok_or_else(|| refused("runtime selected bootstrap missing"))?;
        let read = self.sources.runtime_read(
            owner,
            native,
            &boot.island,
            &attempt.stop,
            &attempt.before,
            attempt.until,
        )?;
        let proof = read.verify_window(
            attempt.token.window,
            &mut attempt.source_bytes[0],
            &mut attempt.source_progress[0],
            &mut attempt.identity_scratch,
        )?;
        let snapshot = proof.window().snapshot;
        if proof.window().id != attempt.source
            || snapshot.mapping != attempt.token.mapping
            || snapshot.generation != attempt.token.generation
        {
            return Err(refused("runtime selected source binding changed"));
        }
        let offset = usize::try_from(
            attempt
                .before
                .logical_pc
                .checked_sub(snapshot.range().start())
                .ok_or_else(|| refused("runtime selected PC underflows source"))?,
        )
        .map_err(|_| refused("runtime selected PC exceeds host extent"))?;
        let decoded = selected::decode(
            attempt.before.logical_pc,
            &snapshot.bytes()[offset..],
            &SyscallAliases::new(),
        )?;
        let input = SelectedInput::new(decoded, attempt.before.registers)?;
        // SYSCALL remains selected and still reaches the provider; its decision
        // cannot enter this CPU-only native transport. No ordinary fallback.
        let input_bytes = instruction_capacity(&input)?;
        self.census
            .as_mut()
            .expect("census retained")
            .account_external(
                attempt.reservation,
                BudgetCharge {
                    source_fact_bytes: input_bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        // Retain only after its exact encoding allocation has been debited.
        // A later native profile failure still leaves this owned input charged.
        attempt.input = Some(input);
        let lineage = self
            .control_lineage
            .as_ref()
            .ok_or_else(|| refused("runtime selected control lineage missing"))?;
        attempt
            .native
            .before_provider(owner, native, &attempt.stop, lineage, attempt.until)?;
        let input = attempt.input.as_ref().expect("input retained");
        let public = Box::new(RuntimeProviderInput {
            token: attempt.token.clone(),
            input: input.clone(),
        });
        let copied = instruction_capacity(&public.input)?;
        self.census
            .as_mut()
            .expect("census retained")
            .account_external(
                attempt.reservation,
                BudgetCharge {
                    source_fact_bytes: add(size_of::<RuntimeProviderInput>(), copied)?,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        owner.time_left(attempt.until, "runtime selected provider delivery")?;
        let observations = self
            .metrics
            .pages
            .observations
            .checked_add(1)
            .ok_or_else(|| refused("dynamic observation counter exhausted"))?;
        let count = self
            .metrics
            .selected
            .callbacks
            .entry(input.instruction().operation().class())
            .or_default();
        let callbacks = count
            .checked_add(1)
            .ok_or_else(|| refused("dynamic callback counter exhausted"))?;
        *count = callbacks;
        self.metrics.pages.observations = observations;
        attempt.phase = SelectedPhase::Pending;
        Ok(public)
    }

    pub(super) fn complete_selected(
        &mut self,
        owner: &mut Owner,
        token: RuntimePendingToken,
        decision: ProviderDecision,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let index = self
            .selected_pending
            .ok_or_else(|| refused("runtime selected has no pending invocation"))?;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.complete_selected_inner(owner, index, token, decision, until)
        }));
        self.selected_outcome(owner, index, outcome)
    }
    fn selected_outcome<T>(
        &mut self,
        owner: &mut Owner,
        index: usize,
        outcome: Result<Result<T, GateError>, Box<dyn std::any::Any + Send>>,
    ) -> Result<T, GateError> {
        match outcome {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                self.selected_attempts[index].fail(Some(&error));
                owner.closing = true;
                owner.cancel.store(true, Ordering::Release);
                Err(error)
            }
            Err(payload) => {
                self.selected_attempts[index].fail(None);
                owner.closing = true;
                owner.cancel.store(true, Ordering::Release);
                std::panic::resume_unwind(payload)
            }
        }
    }
    fn complete_selected_inner(
        &mut self,
        owner: &mut Owner,
        index: usize,
        token: RuntimePendingToken,
        decision: ProviderDecision,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let attempt = &mut self.selected_attempts[index];
        if attempt.phase != SelectedPhase::Pending
            || attempt.first_failure.is_some()
            || attempt.token != token
            || attempt.until != until
            || attempt.decision.is_some()
            || self.initial_origin != Some(attempt.origin)
            || self.pages.iter().any(|page| page.executable)
        {
            return Err(refused(
                "runtime selected token or original deadline differs",
            ));
        }
        owner.time_left(attempt.until, "runtime selected original invocation")?;
        let native = self
            .native
            .as_mut()
            .ok_or_else(|| refused("runtime selected native custody missing"))?;
        native.require_admission_stop(&attempt.stop)?;
        let census = self
            .census
            .as_mut()
            .ok_or_else(|| refused("runtime selected census missing"))?;
        census
            .check_current_origin(attempt.origin, &attempt.before)
            .map_err(census_error)?;
        let boot = self
            .bootstrap
            .as_ref()
            .and_then(PreparedInitialBootstrap::completed)
            .ok_or_else(|| refused("runtime selected bootstrap missing"))?;
        attempt.phase = SelectedPhase::SourceAfterProvider;
        {
            let read = self.sources.runtime_read(
                owner,
                native,
                &boot.island,
                &attempt.stop,
                &attempt.before,
                until,
            )?;
            read.recheck_window(
                attempt.source,
                &mut attempt.source_bytes[1],
                &mut attempt.source_progress[1],
                &mut attempt.identity_scratch,
            )?;
        }
        attempt.decision = Some(decision);
        let input = attempt
            .input
            .as_ref()
            .ok_or_else(|| refused("runtime selected input absent"))?;
        match decision {
            ProviderDecision::Native => {
                return Err(refused(
                    "runtime selected Native transport is not qualified",
                ));
            }
            ProviderDecision::Fault(fault) => {
                let fault = Box::new(input.fault(fault));
                let retained = add(
                    size_of::<crate::selected::FaultedInstruction>(),
                    instruction_capacity(&fault.input)?,
                )?;
                census
                    .account_external(
                        attempt.reservation,
                        BudgetCharge {
                            source_fact_bytes: retained,
                            ..BudgetCharge::default()
                        },
                    )
                    .map_err(census_error)?;
                census
                    .finish_reservation(attempt.reservation)
                    .map_err(census_error)?;
                self.metrics.selected.provider_faults = self
                    .metrics
                    .selected
                    .provider_faults
                    .checked_add(1)
                    .ok_or_else(|| refused("dynamic provider fault counter exhausted"))?;
                attempt.phase = SelectedPhase::Fault;
                self.selected_pending = None;
                owner.closing = true;
                owner.cancel.store(true, Ordering::Release);
                return Ok(AdmissionReply::Event(DynamicAdmissionEvent::Fault {
                    task: attempt.before.task,
                    fault,
                }));
            }
            ProviderDecision::Complete(result) => {
                let lineage = self
                    .control_lineage
                    .as_ref()
                    .ok_or_else(|| refused("runtime selected control lineage missing"))?;
                let completed = model_with_lineage(input, result, lineage, &attempt.stop)?;
                let modeled_bytes = completed.instruction.retained_capacity();
                if modeled_bytes > 15 {
                    return Err(refused(
                        "runtime selected modeled instruction allocation differs",
                    ));
                }
                census
                    .account_external(
                        attempt.reservation,
                        BudgetCharge {
                            source_fact_bytes: modeled_bytes,
                            ..BudgetCharge::default()
                        },
                    )
                    .map_err(census_error)?;
                attempt.completed = Some(completed);
            }
        }
        let completed = attempt
            .completed
            .as_ref()
            .expect("checked modeled completion retained");
        // Every later source/history/public payload is allocated while the
        // original task is still untouched at its original held checkpoint.
        attempt.prepared = Some(
            census
                .prepare_runtime_selected(
                    attempt.reservation,
                    attempt.origin,
                    attempt.invocation,
                    input,
                    completed,
                )
                .map_err(census_error)?,
        );
        let mut before_xstate = bytes(MAX_XSTATE)?;
        before_xstate[..attempt.before.xstate.len()].copy_from_slice(&attempt.before.xstate);
        before_xstate.truncate(attempt.before.xstate.len());
        let mut xstate = bytes(MAX_XSTATE)?;
        xstate[..attempt.before.xstate.len()].copy_from_slice(&attempt.before.xstate);
        xstate.truncate(attempt.before.xstate.len());
        let public = Box::new(DynamicAdmissionCompletion {
            before_task: attempt.before.task,
            after_task: attempt.before.task,
            selected: SelectedCompletion {
                input: input.clone(),
                after: completed.after,
                before_xstate,
                xstate,
                execution: SelectedExecution::Scripted,
            },
            before_signal_mask: attempt.before.signal_mask,
            signal_mask: attempt.before.signal_mask,
        });
        let public_bytes = add(
            size_of::<DynamicAdmissionCompletion>(),
            add(
                public.selected.before_xstate.capacity(),
                public.selected.xstate.capacity(),
            )?,
        )?;
        let public_bytes = add(public_bytes, instruction_capacity(&public.selected.input)?)?;
        census
            .account_external(
                attempt.reservation,
                BudgetCharge {
                    source_fact_bytes: public_bytes,
                    ..BudgetCharge::default()
                },
            )
            .map_err(census_error)?;
        attempt.public = Some(public);
        let completion_count = self
            .metrics
            .selected
            .scripted_completions
            .checked_add(1)
            .ok_or_else(|| refused("dynamic completion counter exhausted"))?;
        census
            .check_reserved(
                attempt.reservation,
                attempt
                    .prepared
                    .as_ref()
                    .ok_or_else(|| refused("runtime selected prepared census absent"))?
                    .remaining_charge()
                    .map_err(census_error)?,
            )
            .map_err(census_error)?;
        attempt.phase = SelectedPhase::Prepared;
        owner.time_left(until, "runtime selected prepared effect")?;
        let lineage = self
            .control_lineage
            .as_ref()
            .ok_or_else(|| refused("runtime selected control lineage missing"))?;
        attempt.phase = SelectedPhase::Native;
        let proof = attempt.native.execute(
            owner,
            native,
            NativeSelectedBinding {
                stop: &attempt.stop,
                before: &attempt.before,
                input,
                completed,
                result: match decision {
                    ProviderDecision::Complete(result) => result,
                    _ => unreachable!("modeled completion only"),
                },
                island: &boot.island,
                baseline: self.sources.runtime_baseline_maps()?,
                lineage,
                until,
            },
        )?;
        let state = attempt.native.final_state()?;
        let stop = attempt.native.final_stop()?;
        if state.xstate.len() > attempt.successor.xstate.capacity() {
            return Err(refused(
                "runtime selected actual successor exceeds prepared storage",
            ));
        }
        attempt.successor.token = stop.token.clone();
        attempt.successor.task = stop.identity;
        attempt.successor.logical_pc = state.registers.rip;
        attempt.successor.registers = state.registers;
        attempt.successor.xstate.clear();
        attempt.successor.xstate.extend_from_slice(&state.xstate);
        attempt.successor.signal_mask = state.mask;
        attempt.successor.phase = StopPhase::UserCheckpoint;
        attempt.successor.signal = None;
        attempt.phase = SelectedPhase::SourceAfterNative;
        {
            let read = self.sources.runtime_read(
                owner,
                native,
                &boot.island,
                stop,
                &attempt.successor,
                until,
            )?;
            read.recheck_window(
                attempt.source,
                &mut attempt.source_bytes[2],
                &mut attempt.source_progress[2],
                &mut attempt.identity_scratch,
            )?;
        }
        let (before_profile, after_profile) = attempt.native.control_profiles();
        let next_lineage = lineage.selected_successor(proof, before_profile, after_profile)?;
        owner.time_left(until, "runtime selected census commit")?;
        attempt.successor.phase = StopPhase::SelectedComplete {
            invocation: attempt.invocation,
        };
        attempt.phase = SelectedPhase::Census;
        let next_origin = census
            .commit_runtime_selected(
                attempt
                    .prepared
                    .as_mut()
                    .ok_or_else(|| refused("runtime selected prepared census absent"))?,
                &attempt.successor,
            )
            .map_err(census_error)?;
        self.initial_origin = Some(next_origin);
        self.control_lineage = Some(next_lineage);
        census
            .finish_reservation(attempt.reservation)
            .map_err(census_error)?;
        self.metrics.selected.scripted_completions = completion_count;
        attempt.phase = SelectedPhase::Completed;
        self.selected_pending = None;
        let public = attempt
            .public
            .take()
            .ok_or_else(|| refused("runtime selected public completion absent"))?;
        Ok(AdmissionReply::Event(DynamicAdmissionEvent::Completed(
            public,
        )))
    }
}
