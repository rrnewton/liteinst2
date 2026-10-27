//! One real production operation at the observed current PC. The artifact plan
//! can only reject a mismatch; it never supplies a source/native binding.
use super::artifact::{PlannedInstruction, PlannedKind};
use super::*;
use crate::linux::remote::dynamic::admission::RuntimeProviderInput;
use crate::selected::{Operation, SyscallAbi};

fn actual_window(
    runtime: &RuntimeOwner,
    expected: &PlannedInstruction,
) -> Result<usize, GateError> {
    if runtime.stage != RuntimeStage::Ready
        || !runtime.ready_issued
        || runtime.selected_pending.is_some()
        || runtime.kernel_pending.is_some()
    {
        return Err(GateError::Refused(
            "oracle operation lacks ready runtime custody",
        ));
    }
    let census = runtime.census.as_ref().ok_or(GateError::Refused(
        "oracle operation lacks an actual census",
    ))?;
    let origin = runtime.initial_origin.ok_or(GateError::Refused(
        "oracle operation lacks its current origin",
    ))?;
    let before = census.current_observation(origin).map_err(census_error)?;
    if before.logical_pc != expected.pc() || before.registers.rip != expected.pc() {
        return Err(GateError::Refused("oracle planned and actual PC differ"));
    }
    let page = before.logical_pc & !4095;
    let entry = runtime
        .pages
        .binary_search_by_key(&page, |row| row.address)
        .ok()
        .and_then(|index| runtime.pages.get(index))
        .ok_or(GateError::Refused(
            "oracle current PC lacks a captured page",
        ))?;
    if entry.executable {
        return Err(GateError::Refused(
            "oracle current original page is executable",
        ));
    }
    let window = runtime
        .sources
        .window(entry.window)
        .ok_or(GateError::Refused(
            "oracle current source window is incomplete",
        ))?;
    let candidate = classify(
        window.snapshot,
        &before.registers,
        DebugDisposition::Absent,
        &SyscallAliases::default(),
    )
    .map_err(|_| GateError::Refused("oracle actual instruction is unqualified"))?;
    if candidate.bytes() != expected.bytes() {
        return Err(GateError::Refused(
            "oracle actual source differs from artifact plan",
        ));
    }
    let matches = match (expected.kind(), candidate.kind()) {
        (PlannedKind::Ordinary, CandidateKind::Ordinary(_)) => !stack_candidate(&candidate),
        (PlannedKind::Call, CandidateKind::Ordinary(instruction)) => {
            candidate.bytes().len() == 5
                && candidate.bytes()[0] == 0xe8
                && instruction.decoded().code() == Code::Call_rel32_64
        }
        (PlannedKind::Ret, CandidateKind::Ordinary(instruction)) => {
            candidate.bytes() == [0xc3] && instruction.decoded().code() == Code::Retnq
        }
        (PlannedKind::Syscall { number }, CandidateKind::Selected(selected)) => {
            runtime.kernel_profile == RuntimeKernelProfile::IdentityAndTermination
                && selected.bytes() == [0x0f, 0x05]
                && selected.operation()
                    == (Operation::Syscall {
                        abi: SyscallAbi::LinuxX64,
                    })
                && before.registers.rax == number
                && matches!(number, 39 | 186 | 231)
        }
        _ => false,
    };
    if !matches {
        return Err(GateError::Refused(
            "oracle planned and actual operation differ",
        ));
    }
    Ok(entry.window)
}

fn refuse(owner: &mut Owner, error: &GateError) {
    owner.kernel_journal.fail_gate(error);
    owner.closing = true;
    owner.cancel.store(true, Ordering::Release);
}

/// The same actual panic journals surround every operation, including its
/// preconditions. Custody-restoration catches inside the body run first; this
/// outer catch closes/cancels the owner before propagating the original error.
fn guarded<T>(
    owner: &mut Owner,
    body: impl FnOnce(&mut Owner) -> Result<T, GateError>,
) -> Result<T, GateError> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _journal_unwind = owner.kernel_journal.panic_scope();
        let _exec_unwind = owner
            .exec_journal
            .as_ref()
            .map(|journal| journal.panic_scope());
        if owner.closing || owner.cancel.load(Ordering::Acquire) {
            return Err(GateError::Refused("oracle owner is already closing"));
        }
        body(owner)
    }));
    match result {
        Ok(result) => {
            if let Err(error) = &result {
                refuse(owner, error);
            }
            result
        }
        Err(payload) => {
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
            std::panic::resume_unwind(payload)
        }
    }
}

/// Call only for a planned ordinary instruction, exact E8 or exact C3. The
/// caller supplies the unchanged selected-segment deadline, never a step timer.
pub(super) fn run_one(
    owner: &mut Owner,
    expected: &PlannedInstruction,
    until: Instant,
) -> Result<(), GateError> {
    guarded(owner, |owner| {
        owner.time_left(until, "oracle original operation")?;
        if owner.admission.is_some() {
            return Err(GateError::Refused(
                "oracle operation conflicts with legacy custody",
            ));
        }
        let mut runtime = owner.runtime.take().ok_or(GateError::Refused(
            "oracle operation lacks an installed runtime",
        ))?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let index = actual_window(&runtime, expected)?;
            match expected.kind() {
                PlannedKind::Ordinary => runtime.ordinary(owner, index, until),
                PlannedKind::Call | PlannedKind::Ret => runtime.stack(owner, index, until),
                PlannedKind::Syscall { .. } => Err(GateError::Refused(
                    "oracle selected operation requires its real pending exchange",
                )),
            }
        }));
        // No fallible action, formatting, callback or diagnostic occurs here.
        owner.runtime = Some(runtime);
        match result {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

pub(super) fn invoke(
    owner: &mut Owner,
    request: AdmissionRequest,
    until: Instant,
) -> Result<AdmissionReply, GateError> {
    guarded(owner, |owner| {
        owner.time_left(until, "oracle admission command")?;
        // Retain the production runtime-only interlock. The enclosing real
        // journal scopes and closing/cancel epilogue preserve the command
        // boundary without allocating transport-only Request/Response boxes.
        owner.execute_runtime(request, until)
    })
}

pub(super) fn prepare_kernel(
    owner: &mut Owner,
    expected: &PlannedInstruction,
    until: Instant,
) -> Result<Box<RuntimeProviderInput>, GateError> {
    guarded(owner, |owner| {
        owner.time_left(until, "oracle selected boundary")?;
        if !matches!(expected.kind(), PlannedKind::Syscall { .. }) {
            return Err(GateError::Refused(
                "oracle selected boundary is not a planned syscall",
            ));
        }
        let runtime = owner.runtime.as_ref().ok_or(GateError::Refused(
            "oracle selected boundary lacks an installed runtime",
        ))?;
        actual_window(runtime, expected)?;
        // Advance starts at the checked selected PC. Its classifier and
        // prepare_kernel independently reauthenticate the real pending token.
        match owner.execute_runtime(AdmissionRequest::Advance, until)? {
            AdmissionReply::RuntimeProvider(input) => Ok(input),
            _ => Err(GateError::Refused(
                "oracle syscall lacks its real pending invocation",
            )),
        }
    })
}

pub(super) fn complete_kernel(
    owner: &mut Owner,
    input: &RuntimeProviderInput,
    until: Instant,
) -> Result<AdmissionReply, GateError> {
    invoke(
        owner,
        AdmissionRequest::CompleteRuntime {
            token: input.token.clone(),
            decision: ProviderDecision::Native,
        },
        until,
    )
}
