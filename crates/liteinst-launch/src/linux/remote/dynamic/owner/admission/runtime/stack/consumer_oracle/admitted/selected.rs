//! Actual selected exchange; payloads are installed before validation. The
//! terminal path retains the actual event and never requests an after-state.
use super::*;
use crate::gate::SelectedExecution;
use crate::lifecycle::ExitStatus;
use crate::selected::{Operation, SyscallAbi};

impl PreparedAdmitted {
    pub(super) fn selected(
        &mut self,
        owner: &mut Owner,
        plan: &ArtifactPlan,
        ordinal: usize,
        number: u64,
        until: Instant,
    ) -> Result<AdmittedBoundary, OracleError> {
        let segment = self.progress.segment;
        require(
            plan.syscalls[segment] == ordinal
                && number == [39, 186, 231][segment]
                && self.providers[segment].is_none()
                && self.completions[segment].is_none(),
            "admitted selected order or storage differs",
        )?;
        self.progress.phase = Phase::Provider;
        // dispatch performs actual source/current classification before Advance;
        // no ordinary operation can be silently folded into this exchange.
        self.steps[ordinal].provider_started = true;
        self.providers[segment] = Some(dispatch::prepare_kernel(
            owner,
            plan.instruction(ordinal)?,
            until,
        )?);
        self.steps[ordinal].provider_received = true;
        let input = self.providers[segment]
            .as_ref()
            .expect("actual provider response installed");
        require_input(input, &self.lane, plan, ordinal, number, owner)?;
        self.progress.phase = Phase::Completion;
        self.steps[ordinal].dispatch_started = true;
        self.completions[segment] = Some(dispatch::complete_kernel(owner, input, until)?);
        self.steps[ordinal].dispatched = true;
        if number == 231 {
            self.progress.phase = Phase::Terminal;
            let status = require_terminal(self, owner, plan)?;
            // Historical row comparison performs no native query after terminal.
            self.require_call(owner)?;
            self.steps[ordinal].compared = true;
            self.progress.next += 1;
            self.progress.segment += 1;
            self.progress.phase = Phase::Complete;
            return Ok(AdmittedBoundary::Terminal { status });
        }
        self.lane
            .capture(owner, plan, ordinal, true, DebugExpectation::Trace, until)?;
        self.steps[ordinal].after = true;
        checkpoints::require_current(owner, &self.lane.frame(ordinal, true)?.state.state, None)?;
        self.progress.phase = Phase::Comparison;
        require_return(self, owner, plan, segment)?;
        self.steps[ordinal].compared = true;
        self.progress.next += 1;
        self.progress.segment += 1;
        Ok(AdmittedBoundary::Returned { ordinal, number })
    }
}
fn require_input(
    input: &RuntimeProviderInput,
    lane: &PreparedLane,
    plan: &ArtifactPlan,
    ordinal: usize,
    number: u64,
    owner: &Owner,
) -> Result<(), OracleError> {
    let expected = plan.instruction(ordinal)?;
    let before = &lane.frame(ordinal, false)?.state.state;
    require(
        input.input.instruction().operation()
            == (Operation::Syscall {
                abi: SyscallAbi::LinuxX64,
            })
            && input.input.instruction().bytes() == expected.bytes()
            && input.input.instruction().logical_pc() == expected.pc()
            && input.input.instruction().next_pc() == expected.next_pc()
            && input.input.registers() == &before.registers
            && before.registers.rax == number
            && input.token.pc == expected.pc()
            && input.token.task.generation == 0
            && input.token.generation.0 == input.token.task.generation
            && input.token.stop.tid == owner.pid
            && input.token.stop.session == owner.anchor_session(),
        "admitted real provider input differs from exact full before",
    )?;
    if number == 231 {
        let stack = lane.metadata.stack.as_ref().ok_or(OracleError::Invalid(
            "admitted original stack metadata absent",
        ))?;
        require(
            before.registers.rdi == 7 && before.registers.rsp == stack.original_rsp,
            "admitted terminal argument or original RSP differs",
        )?;
    }
    Ok(())
}
fn require_return(
    p: &PreparedAdmitted,
    owner: &Owner,
    plan: &ArtifactPlan,
    segment: usize,
) -> Result<(), OracleError> {
    require(segment < 2, "admitted terminal is not a return")?;
    let ordinal = plan.syscalls[segment];
    let input = p.providers[segment]
        .as_ref()
        .ok_or(OracleError::Invalid("admitted provider owner absent"))?;
    let Some(AdmissionReply::Event(DynamicAdmissionEvent::Completed(event))) =
        &p.completions[segment]
    else {
        return Err(OracleError::Invalid(
            "admitted native syscall did not return Completed",
        ));
    };
    let before = &p.lane.frame(ordinal, false)?.state.state;
    let after = &p.lane.frame(ordinal, true)?.state.state;
    require(
        event.before_task == input.token.task
            && event.after_task == input.token.task
            && event.selected.execution == SelectedExecution::Native
            && event.selected.input == input.input
            && event.selected.after == after.registers
            && event.selected.before_xstate == before.xstate
            && event.selected.xstate == after.xstate
            && event.before_signal_mask == before.mask
            && event.signal_mask == after.mask,
        "admitted actual completion full evidence differs",
    )?;
    dataflow::compare_kernel_return(plan.instruction(ordinal)?, before, after, owner.pid)
}
fn require_terminal(
    p: &PreparedAdmitted,
    owner: &Owner,
    plan: &ArtifactPlan,
) -> Result<ExitStatus, OracleError> {
    let input = p.providers[2]
        .as_ref()
        .ok_or(OracleError::Invalid("admitted terminal provider absent"))?;
    require_input(input, &p.lane, plan, plan.syscalls[2], 231, owner)?;
    let Some(AdmissionReply::Event(DynamicAdmissionEvent::TaskTerminal {
        task,
        status,
        all_terminal,
    })) = &p.completions[2]
    else {
        return Err(OracleError::Invalid(
            "admitted actual terminal event absent",
        ));
    };
    let runtime = owner
        .runtime
        .as_ref()
        .ok_or(OracleError::Invalid("admitted terminal runtime absent"))?;
    let census = runtime
        .census
        .as_ref()
        .ok_or(OracleError::Invalid("admitted terminal census absent"))?;
    require(
        *task == input.token.task
            && *all_terminal
            && *status == ExitStatus::Code(7)
            && runtime.stage == RuntimeStage::Terminal
            && runtime.initial_origin.is_none()
            && runtime.kernel_pending.is_none()
            && runtime.selected_pending.is_none()
            && census.active().count() == 0
            && p.lane.frame(plan.syscalls[2], true).is_err(),
        "admitted real terminal status or retired census differs",
    )?;
    Ok(*status)
}
pub(super) fn require_replies(
    p: &PreparedAdmitted,
    owner: &Owner,
    plan: &ArtifactPlan,
) -> Result<(), OracleError> {
    for segment in 0..3 {
        let input = p.providers[segment]
            .as_ref()
            .ok_or(OracleError::Invalid("admitted retained input absent"))?;
        require_input(
            input,
            &p.lane,
            plan,
            plan.syscalls[segment],
            [39, 186, 231][segment],
            owner,
        )?;
        if segment < 2 {
            require_return(p, owner, plan, segment)?;
        }
    }
    require_terminal(p, owner, plan).map(|_| ())
}
