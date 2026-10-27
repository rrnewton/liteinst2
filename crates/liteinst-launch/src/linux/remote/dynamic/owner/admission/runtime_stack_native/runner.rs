//! Actual sync/protect/sync, original stack instruction, sync/protect/sync.
use super::*;
use acquire::{
    FailedHeldStackRead, SettledStackRead, SettledWordPhase, StackCaptureAssociation,
    StackWordExpected, TraceStackRead,
};
use iced_x86::Code;

pub(super) fn require_state(state: &TaskStateSnapshot) -> Result<(), LaunchError> {
    if state.registers.cs != 0x33
        || state.registers.orig_rax != u64::MAX
        || state.registers.eflags & (0x100 | 0x10000) != 0
        || state.registers.eflags & 2 == 0
        || !(512..MAX_XSTATE).contains(&state.xstate.len())
    {
        return Err(LaunchError::Invalid(
            "owned instruction native state profile differs",
        ));
    }
    Ok(())
}
/// Only the exact current sealed lineage may explain a non-MAX original
/// syscall number before an ordinary instruction. The trace validator below
/// remains strict and cannot use this predicate.
pub(super) fn require_lineage_state(
    lineage: &ControlLineage,
    stop: &AdmissionStop,
    state: &TaskStateSnapshot,
) -> Result<(), LaunchError> {
    lineage.require_orig_rax(stop, state.registers.orig_rax)?;
    if state.registers.orig_rax == u64::MAX {
        return require_state(state);
    }
    if state.registers.cs != 0x33
        || state.registers.eflags & (0x100 | 0x10000) != 0
        || state.registers.eflags & 2 == 0
        || !(512..MAX_XSTATE).contains(&state.xstate.len())
    {
        return Err(LaunchError::Invalid(
            "owned instruction native state profile differs",
        ));
    }
    Ok(())
}
fn same_observation(state: &TaskStateSnapshot, observed: &ObservedStop) -> bool {
    state.registers == observed.registers
        && state.xstate == observed.xstate
        && state.mask == observed.signal_mask
}
pub(super) fn next_stop(before: &AdmissionStop, after: &AdmissionStop) -> Result<(), LaunchError> {
    if before.identity != after.identity
        || before.token.session != after.token.session
        || before.token.tid != after.token.tid
        || before.token.task != after.token.task
        || after.token.sequence <= before.token.sequence
        || after.signal.is_some()
    {
        return Err(LaunchError::Invalid(
            "owned instruction checkpoint lineage differs",
        ));
    }
    Ok(())
}
fn ready(
    owner: &Owner,
    native: &NativeLifecycle,
    original: &AdmissionStop,
    island: &TrustedIsland,
    p: &mut PreparedStackNative,
    stop: &AdmissionStop,
    from_step: bool,
) -> Result<(), LaunchError> {
    if from_step {
        // This branch is callable only for the first close, after our real
        // completed-step capsule was retained. Never widen the generic initial
        // predicate to an arbitrary NativeCompleted stop or failed signal.
        if p.stops[3].as_ref() != Some(stop)
            || !p.progress.instruction_completed
            || stop.phase != AdmissionPhase::NativeCompleted
            || p.trace.is_none()
        {
            return Err(LaunchError::Invalid(
                "owned close lacks actual step authority",
            ));
        }
        native.require_admission_stop(stop)?;
        require_initial_task_identity(
            owner,
            p.until.expect("installed stack deadline"),
            p.membership.as_mut_slice(),
        )?;
    } else {
        native.require_initial_source_mm(
            owner,
            stop,
            p.until.expect("installed stack deadline"),
            p.membership.as_mut_slice(),
        )?;
    }
    if native.admission_interrupt_credit(owner.pid)? != 0
        || stop.signal.is_some()
        || stop.identity != original.identity
        || stop.token.session != original.token.session
        || stop.token.tid != owner.pid
        || stop.identity.generation != 0
    {
        return Err(LaunchError::Invalid(
            "owned instruction singleton or interruption state differs",
        ));
    }
    if stop.identity.address_space != island.address_space
        || island.generation != 0
        || island.page_size != 4096
    {
        return Err(LaunchError::Invalid(
            "owned instruction island identity differs",
        ));
    }
    p.maps[WORK_MAP].capture(owner, p.until.expect("installed stack deadline"))?;
    let rows = ParsedMaps::parse(p.maps[WORK_MAP].bytes(), 512)
        .map_err(|_| LaunchError::Invalid("owned instruction maps malformed"))?;
    if !rows.entries().any(|row| {
        row.start <= island.range.start
            && island.range.end <= row.end
            && row.permissions.bytes() == *b"r-xp"
            && row.pathname.is_none()
    }) {
        return Err(LaunchError::Invalid(
            "immutable RX syscall island did not verify",
        ));
    }
    bootstrap::verify_memory(
        owner,
        island.range.start,
        &bootstrap::island_code_fixed(),
        &mut p.peek,
        p.until.expect("installed stack deadline"),
    )?;
    bootstrap::physical(owner, p.until.expect("installed stack deadline"))
}
fn begin_effect(
    owner: &Owner,
    native: &NativeLifecycle,
    p: &mut PreparedStackNative,
    observer: &mut dyn StackSourceObservation,
    current: &AdmissionStop,
    effect: InstructionEffect,
) -> Result<(), LaunchError> {
    if p.progress.first_failure.is_some()
        || p.progress.effects_len == EFFECTS
        || p.progress
            .effects_len
            .checked_sub(1)
            .and_then(|index| p.progress.effects[index])
            .is_some_and(|row| !row.complete)
    {
        return Err(LaunchError::Invalid(
            "owned instruction effect capacity or order differs",
        ));
    }
    owner.time_left(
        p.until.expect("installed stack deadline"),
        "owned instruction effect",
    )?;
    observer.before_effect(
        owner,
        native,
        effect,
        current,
        p.until.expect("installed stack deadline"),
    )?;
    owner.time_left(
        p.until.expect("installed stack deadline"),
        "owned instruction effect",
    )?;
    p.progress.effects[p.progress.effects_len] = Some(InstructionEffectRecord {
        effect,
        complete: false,
        result: None,
    });
    p.progress.effects_len += 1;
    Ok(())
}
fn finish_effect(p: &mut PreparedStackNative, result: Request) -> Result<(), LaunchError> {
    let row = p.progress.effects[p.progress.effects_len - 1]
        .as_mut()
        .expect("attempted effect");
    row.result = Some(result);
    checked(result, "owned instruction effect")?;
    row.complete = true;
    Ok(())
}
fn set_state_registers(
    owner: &Owner,
    native: &NativeLifecycle,
    p: &mut PreparedStackNative,
    observer: &mut dyn StackSourceObservation,
    current: &AdmissionStop,
    effect: InstructionEffect,
    registers: RegisterSnapshot,
) -> Result<(), LaunchError> {
    begin_effect(owner, native, p, observer, current, effect)?;
    let raw = libc::user_regs_struct::from(registers);
    let result = request(
        libc::PTRACE_SETREGS,
        owner.pid,
        0,
        (&raw const raw) as usize,
    );
    finish_effect(p, result)
}
fn restore(
    owner: &Owner,
    native: &NativeLifecycle,
    p: &mut PreparedStackNative,
    observer: &mut dyn StackSourceObservation,
    current: &AdmissionStop,
    wait: usize,
    canonical: usize,
) -> Result<(), LaunchError> {
    p.states[WORK].capture(owner, p.until.expect("installed stack deadline"))?;
    if p.states[WORK].state.xstate != p.states[canonical].state.xstate {
        begin_effect(
            owner,
            native,
            p,
            observer,
            current,
            InstructionEffect::RestoreXstate { wait },
        )?;
        let mut vector = libc::iovec {
            iov_base: p.states[canonical].state.xstate.as_ptr().cast_mut().cast(),
            iov_len: p.states[canonical].state.xstate.len(),
        };
        let result = request(
            libc::PTRACE_SETREGSET,
            owner.pid,
            NT_X86_XSTATE,
            (&raw mut vector) as usize,
        );
        finish_effect(p, result)?;
    }
    let expected = p.states[canonical].state.registers;
    set_state_registers(
        owner,
        native,
        p,
        observer,
        current,
        InstructionEffect::RestoreRegisters { wait },
        expected,
    )?;
    p.states[WORK].capture(owner, p.until.expect("installed stack deadline"))?;
    if p.states[WORK].state.registers != expected
        || p.states[WORK].state.xstate != p.states[canonical].state.xstate
    {
        return Err(LaunchError::Invalid(
            "trusted register/XSTATE restoration differs",
        ));
    }
    if p.states[WORK].state.mask != p.states[canonical].state.mask {
        begin_effect(
            owner,
            native,
            p,
            observer,
            current,
            InstructionEffect::RestoreMask { wait },
        )?;
        let result = request(
            libc::PTRACE_SETSIGMASK,
            owner.pid,
            8,
            (&raw const p.states[canonical].state.mask) as usize,
        );
        finish_effect(p, result)?;
    }
    p.states[WORK].capture(owner, p.until.expect("installed stack deadline"))?;
    if p.states[WORK].state != p.states[canonical].state {
        return Err(LaunchError::Invalid("trusted state restoration differs"));
    }
    Ok(())
}
fn wait_capture(
    owner: &mut Owner,
    p: &mut PreparedStackNative,
    ordinal: usize,
    map_slot: usize,
) -> Result<(i32, i32), LaunchError> {
    if p.progress.waits[ordinal].is_some() {
        return Err(LaunchError::Invalid(
            "owned instruction raw wait storage reused",
        ));
    }
    let (tid, status) = owner.wait_raw(
        p.until.expect("installed stack deadline"),
        "owned instruction actual wait",
    )?;
    p.progress.waits[ordinal] = Some((tid, status));
    p.progress.queries_started[ordinal] = false;
    bootstrap::raw_held(
        owner,
        tid,
        status,
        p.until.expect("installed stack deadline"),
    )?;
    p.progress.queries_started[ordinal] = true;
    // Attempt every independent initialized request before interpreting the
    // first failed request. An invalid held event remains diagnostic evidence.
    let signal_result = p.signals[ordinal].capture(tid);
    let state_result = p.states[ordinal + 1].capture_tid(tid);
    let debug_result = p.debug[ordinal].capture(tid);
    let map_result = p.maps[map_slot].capture(owner, p.until.expect("installed stack deadline"));
    signal_result?;
    state_result?;
    debug_result?;
    map_result?;
    owner.time_left(
        p.until.expect("installed stack deadline"),
        "owned instruction actual wait",
    )?;
    Ok((tid, status))
}
struct PrivateCall {
    ordinal: usize,
    number: libc::c_long,
    arguments: [u64; 6],
}
fn private_call(
    owner: &mut Owner,
    native: &mut NativeLifecycle,
    binding: &RuntimeStackBinding<'_, '_>,
    p: &mut PreparedStackNative,
    observer: &mut dyn StackSourceObservation,
    call: PrivateCall,
) -> Result<(), LaunchError> {
    let PrivateCall {
        ordinal,
        number,
        arguments,
    } = call;
    let canonical = if ordinal < 3 { BEFORE } else { STEP };
    let stop = native.admission_current(binding.stop().identity.task)?;
    ready(
        owner,
        native,
        binding.stop(),
        binding.island(),
        p,
        &stop,
        ordinal == 4,
    )?;
    p.states[WORK].capture(owner, p.until.expect("installed stack deadline"))?;
    if p.states[WORK].state != p.states[canonical].state {
        return Err(LaunchError::Invalid("owned private before-state differs"));
    }
    let pc = binding.island().range.start;
    let mut registers = trusted::temporary(&p.states[canonical].state.registers, pc);
    registers.rax = number as u64;
    registers.rdi = arguments[0];
    registers.rsi = arguments[1];
    registers.rdx = arguments[2];
    registers.r10 = arguments[3];
    registers.r8 = arguments[4];
    registers.r9 = arguments[5];
    bootstrap::verify_memory(
        owner,
        pc,
        &STUB,
        &mut p.peek,
        p.until.expect("installed stack deadline"),
    )?;
    if registers.rip != pc
        || registers.cs != 0x33
        || registers.orig_rax != u64::MAX
        || registers.eflags & (0x100 | 0x10000 | 0x40000) != 0
        || STUB.last() != Some(&0xcc)
    {
        return Err(LaunchError::Invalid(
            "trusted instruction setup is not exact",
        ));
    }
    set_state_registers(
        owner,
        native,
        p,
        observer,
        &stop,
        InstructionEffect::SetRegisters { wait: ordinal },
        registers,
    )?;
    p.states[WORK].capture(owner, p.until.expect("installed stack deadline"))?;
    if p.states[WORK].state.registers != registers
        || p.states[WORK].state.xstate != p.states[canonical].state.xstate
        || p.states[WORK].state.mask != p.states[canonical].state.mask
    {
        return Err(LaunchError::Invalid(
            "trusted setup changed unrelated state",
        ));
    }
    native.require_admission_stop(&stop)?;
    begin_effect(
        owner,
        native,
        p,
        observer,
        &stop,
        InstructionEffect::PrivateRelease { wait: ordinal },
    )?;
    native.begin_admission_execution(&stop)?;
    owner.time_left(
        p.until.expect("installed stack deadline"),
        "owned private release",
    )?;
    let result = request(libc::PTRACE_CONT, owner.pid, 0, 0);
    finish_effect(p, result)?;
    owner.released(owner.pid);
    let (tid, status) = wait_capture(owner, p, ordinal, WORK_MAP)?;
    if tid != owner.pid
        || native.consume_admission_interrupt(tid)?
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || status >> 16 != 0
    {
        return Err(LaunchError::Invalid(
            "owned private execution reached an unexpected stop",
        ));
    }
    p.signals[ordinal].validate()?;
    let observed = p.states[ordinal + 1].state.registers;
    let mut expected = registers;
    expected.rip = pc
        .checked_add(STUB.len() as u64)
        .ok_or(LaunchError::Invalid("trusted trap address overflow"))?;
    expected.rax = observed.rax;
    expected.rcx = pc + 2;
    expected.r11 = registers.eflags;
    if observed != expected || p.states[ordinal + 1].state.mask != p.states[canonical].state.mask {
        return Err(LaunchError::Invalid(
            "trusted completion identity or state differs",
        ));
    }
    bootstrap::verify_memory(
        owner,
        pc,
        &STUB,
        &mut p.peek,
        p.until.expect("installed stack deadline"),
    )?;
    // Both approved syscalls return exactly zero, not merely a non-error value.
    syscall_result(observed.rax, "owned private syscall")?;
    if observed.rax != 0 {
        return Err(LaunchError::Invalid(
            "owned private syscall returned nonzero",
        ));
    }
    restore(owner, native, p, observer, &stop, ordinal, canonical)?;
    let restored = native.finish_admission_execution(
        tid,
        p.states[canonical].state.registers.rip,
        AdmissionPhase::Restored,
    )?;
    next_stop(&stop, &restored)?;
    p.stops[ordinal] = Some(restored.clone());
    ready(
        owner,
        native,
        binding.stop(),
        binding.island(),
        p,
        &restored,
        false,
    )?;
    // Every actual protection operation receives an exact full-range map
    // readback; sync calls preserve the same phase-specific projection too.
    if !(1..5).contains(&ordinal) {
        verify_closed(p.maps[BASELINE_MAP].bytes(), p.maps[WORK_MAP].bytes()).map_err(mapped)?;
    } else {
        binding
            .geometry()
            .verify_open(p.maps[BASELINE_MAP].bytes(), p.maps[WORK_MAP].bytes())
            .map_err(mapped)?;
    }
    Ok(())
}
pub(super) fn validate_trace(
    tid: i32,
    expected_tid: i32,
    status: i32,
    bytes: [u8; 128],
    state: &TaskStateSnapshot,
    debug: &DebugRead,
) -> Result<NativeTrace, LaunchError> {
    if size_of::<libc::siginfo_t>() != 128
        || tid != expected_tid
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || status >> 16 != 0
    {
        return Err(LaunchError::Invalid(
            "owned original did not reach exact trace stop",
        ));
    }
    let info = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::siginfo_t>()) };
    if info.si_signo != libc::SIGTRAP
        || info.si_errno != 0
        || info.si_code != libc::TRAP_TRACE
        || unsafe { info.si_addr() } as usize as u64 != state.registers.rip
    {
        return Err(LaunchError::Invalid("owned original trace signal differs"));
    }
    debug.require(DR_TRACE)?;
    require_state(state)?;
    Ok(NativeTrace {
        ordinal: 3,
        tid,
        status,
        signal: bytes,
        dr6: debug.values[4],
    })
}
pub(super) fn prepare(
    owner: &Owner,
    native: &NativeLifecycle,
    context: &StackBeforeContext<'_, '_>,
    initial: &OriginalStackIdentity<'_>,
    p: &mut PreparedStackNative,
    operand: &mut PreparedStackOperandCapture,
) -> Result<(), LaunchError> {
    p.require_allocated()?;
    let until = p.deadline();
    owner.time_left(until, "owned stack preparation")?;
    if p.initial.is_some()
        || until != context.until()
        || p.shape != Some(StackNativeShape::from_geometry(context.geometry())?)
    {
        return Err(LaunchError::Invalid(
            "owned stack preparation shape differs",
        ));
    }
    stack_encoding(context.candidate())?;
    let stop = context.stop();
    if stop.token != context.before().token
        || stop.identity != context.before().task
        || stop.signal.is_some()
        || context.before().signal.is_some()
        || !matches!(
            stop.phase,
            AdmissionPhase::EntryReady | AdmissionPhase::Restored
        )
        || context.before().logical_pc != context.candidate().range().start()
        || context.before().registers != *context.candidate().registers()
        || context.geometry().instruction() != context.candidate().range()
        || context.source_id().identity().mapping != context.candidate().snapshot().mapping.0
        || context.source_id().identity().generation != context.candidate().snapshot().generation.0
    {
        return Err(LaunchError::Invalid(
            "owned stack source before binding differs",
        ));
    }
    p.progress.phase = StackPhase::BeforeCapture;
    ready(owner, native, stop, context.island(), p, stop, false)?;
    p.states[BEFORE].capture(owner, until)?;
    require_lineage_state(context.lineage(), stop, &p.states[BEFORE].state)?;
    if !same_observation(&p.states[BEFORE].state, context.before()) {
        return Err(LaunchError::Invalid("owned stack logical before differs"));
    }
    p.initial = Some(stop.clone());
    p.source = Some(context.source_id());
    p.origin = Some(context.origin());
    p.execution = Some(context.execution());
    let bytes = context.candidate().bytes();
    p.encoding[..bytes.len()].copy_from_slice(bytes);
    p.encoding_len = bytes.len();
    p.maps[BASELINE_MAP].capture(owner, until)?;
    if p.maps[BASELINE_MAP].bytes() != context.baseline_maps() {
        return Err(LaunchError::Invalid("owned stack baseline maps differ"));
    }
    context
        .geometry()
        .projected_rows(p.maps[BASELINE_MAP].bytes())
        .map_err(mapped)?;
    bootstrap::verify_memory(
        owner,
        context.candidate().range().start(),
        bytes,
        &mut p.peek,
        until,
    )?;
    p.profile.capture(owner, until)?;
    context.lineage().authenticate(stop, &p.profile)?;
    p.states[WORK].capture(owner, until)?;
    if p.states[WORK].state != p.states[BEFORE].state {
        return Err(LaunchError::Invalid(
            "owned stack profile changed original state",
        ));
    }
    let actual = NativeStackBeforeView {
        stop: p.initial.as_ref().expect("actual stack before"),
        state: &p.states[BEFORE],
        work: &p.states[WORK],
        baseline_maps: p.maps[BASELINE_MAP].bytes(),
        until,
    };
    operand.acquire(owner, native, initial, context, actual, &mut p.membership)?;
    #[cfg(test)]
    {
        let actual_a = operand.operand()?;
        let offset = tests::pkru_offset(actual_a.layout_evidence())?;
        tests::intervene(owner, native, p, stop, offset, InterventionPoint::AfterA)?;
    }
    p.progress.phase = StackPhase::BeforeCaptured;
    Ok(())
}
pub(super) fn stack_encoding(
    candidate: &super::super::runtime_instruction::InstructionCandidate<'_>,
) -> Result<StackOperation, LaunchError> {
    let CandidateKind::Ordinary(instruction) = candidate.kind() else {
        return Err(LaunchError::Invalid(
            "selected instruction cannot use owned stack execution",
        ));
    };
    match (candidate.bytes(), instruction.decoded().code()) {
        ([0xe8, _, _, _, _], Code::Call_rel32_64) => Ok(StackOperation::DirectCall),
        ([0xc3], Code::Retnq) => Ok(StackOperation::Return),
        _ => Err(LaunchError::Invalid("owned stack encoding is not E8/C3")),
    }
}
pub(super) fn require_binding(
    binding: &RuntimeStackBinding<'_, '_>,
    p: &PreparedStackNative,
) -> Result<(), LaunchError> {
    if p.until != Some(binding.until())
        || p.shape != Some(StackNativeShape::from_geometry(binding.geometry())?)
        || p.initial.as_ref() != Some(binding.stop())
        || p.source != Some(binding.source_id())
        || p.origin != Some(binding.origin())
        || p.execution != Some(binding.execution())
        || p.encoding.get(..p.encoding_len) != Some(binding.candidate().bytes())
        || !same_observation(&p.states[BEFORE].state, binding.before())
        || p.states[BEFORE].state != *binding.operand().before()
        || p.maps[BASELINE_MAP].bytes() != binding.baseline_maps()
        || binding.operand_description().geometry.operation != stack_encoding(binding.candidate())?
        || binding.operand_description() != binding.identity().operand_description()
        || binding.identity().source_id() != binding.source_id()
        || binding.identity().origin() != binding.origin()
        || binding.identity().execution() != binding.execution()
        || binding.identity().stop() != binding.stop()
        || binding.identity().until() != binding.until()
    {
        return Err(LaunchError::Invalid(
            "owned stack final binding differs from actual preparation",
        ));
    }
    binding
        .lineage()
        .require_orig_rax(binding.stop(), p.states[BEFORE].state.registers.orig_rax)?;
    let a = binding.operand().view();
    if !a.complete
        || a.first_failure.is_some()
        || a.association
            != Some(&StackCaptureAssociation::A {
                stop: binding.stop().clone(),
                source_id: binding.source_id(),
                until: binding.until(),
            })
    {
        return Err(LaunchError::Invalid(
            "owned stack A lacks actual acquisition",
        ));
    }
    a.word
        .validate(&binding.operand_description().geometry)
        .map_err(stack_error)?;
    Ok(())
}
pub(super) fn after_word(
    description: &OperandDescription,
    before: &[u8; 16],
) -> Result<[u8; 16], LaunchError> {
    let mut result = *before;
    if description.geometry.operation == StackOperation::DirectCall {
        let offset = usize::try_from(
            description
                .geometry
                .slot
                .start
                .checked_sub(description.geometry.envelope.start)
                .ok_or(LaunchError::Invalid("owned stack word offset underflows"))?,
        )
        .map_err(|_| LaunchError::Invalid("owned stack word offset overflows"))?;
        let end = offset
            .checked_add(8)
            .ok_or(LaunchError::Invalid("owned stack word extent overflows"))?;
        result
            .get_mut(offset..end)
            .ok_or(LaunchError::Invalid("owned stack word extent differs"))?
            .copy_from_slice(&description.geometry.next_pc.to_le_bytes());
    }
    Ok(result)
}
pub(super) fn execute(
    owner: &mut Owner,
    native: &mut NativeLifecycle,
    binding: &RuntimeStackBinding<'_, '_>,
    recorded: Option<RecordedCall<'_>>,
    p: &mut PreparedStackNative,
    observer: &mut dyn StackSourceObservation,
) -> Result<(), LaunchError> {
    if p.progress.phase != StackPhase::BeforeCaptured
        || p.progress.first_failure.is_some()
        || p.identity.is_some()
        || p.call_id.is_some()
        || p.progress.effects_len != 0
    {
        return Err(LaunchError::Invalid(
            "owned stack execution reused or not prepared",
        ));
    }
    require_binding(binding, p)?;
    match (
        binding.operand_description().geometry.operation,
        recorded.as_ref(),
    ) {
        (StackOperation::DirectCall, Some(row)) => {
            row.require(binding).map_err(|_| {
                LaunchError::Invalid("owned stack CALL lacks its exact pre-opening ledger row")
            })?;
            p.call_id = Some(row.id());
        }
        (StackOperation::Return, None) => {}
        _ => {
            return Err(LaunchError::Invalid(
                "owned stack CALL/RET ledger binding differs",
            ));
        }
    }
    p.identity = Some(binding.identity().clone());
    let stop = binding.stop();
    let bytes = binding.candidate().bytes();
    ready(
        owner,
        native,
        binding.stop(),
        binding.island(),
        p,
        stop,
        false,
    )?;
    p.progress.phase = StackPhase::Opening;
    private_call(
        owner,
        native,
        binding,
        p,
        observer,
        PrivateCall {
            ordinal: 0,
            number: libc::SYS_membarrier,
            arguments: [SYNC_CORE, 0, 0, 0, 0, 0],
        },
    )?;
    let range = binding.geometry().pages();
    let length = range.end() - range.start();
    private_call(
        owner,
        native,
        binding,
        p,
        observer,
        PrivateCall {
            ordinal: 1,
            number: libc::SYS_mprotect,
            arguments: [
                range.start(),
                length,
                (libc::PROT_READ | libc::PROT_EXEC) as u64,
                0,
                0,
                0,
            ],
        },
    )?;
    private_call(
        owner,
        native,
        binding,
        p,
        observer,
        PrivateCall {
            ordinal: 2,
            number: libc::SYS_membarrier,
            arguments: [SYNC_CORE, 0, 0, 0, 0, 0],
        },
    )?;
    let release = p.stops[2].as_ref().expect("actual opening stop").clone();
    p.maps[OPEN_MAP].capture(owner, p.until.expect("installed stack deadline"))?;
    binding
        .geometry()
        .verify_open(p.maps[BASELINE_MAP].bytes(), p.maps[OPEN_MAP].bytes())
        .map_err(mapped)?;
    bootstrap::verify_memory(
        owner,
        binding.candidate().range().start(),
        bytes,
        &mut p.peek,
        p.until.expect("installed stack deadline"),
    )?;
    p.states[WORK].capture(owner, p.until.expect("installed stack deadline"))?;
    if p.states[WORK].state != p.states[BEFORE].state {
        return Err(LaunchError::Invalid("owned opening changed original state"));
    }
    observer.opened(
        owner,
        native,
        &release,
        &p.states[BEFORE].state,
        p.maps[OPEN_MAP].bytes(),
        p.until.expect("installed stack deadline"),
    )?;
    owner.time_left(
        p.until.expect("installed stack deadline"),
        "owned original release",
    )?;
    ready(
        owner,
        native,
        binding.stop(),
        binding.island(),
        p,
        &release,
        false,
    )?;
    let until = p.deadline();
    let a_bytes = binding.operand().word().bytes;
    let expected_after = after_word(binding.operand_description(), &a_bytes)?;
    let b_read = SettledStackRead::acquire(owner, native, &release, &mut p.membership, until)?;
    p.words[0].capture_settled(
        b_read,
        SettledWordPhase::B,
        StackWordExpected {
            profile: binding.profile_description(),
            original_maps: binding.original_maps(),
            geometry: &binding.operand_description().geometry,
            state: &p.states[BEFORE],
            maps: p.maps[OPEN_MAP].bytes(),
            word: &a_bytes,
        },
    )?;
    p.progress.phase = StackPhase::Opened;
    begin_effect(
        owner,
        native,
        p,
        observer,
        &release,
        InstructionEffect::OriginalRelease,
    )?;
    #[cfg(test)]
    tests::intervene(
        owner,
        native,
        p,
        &release,
        tests::pkru_offset(binding.operand().layout_evidence())?,
        InterventionPoint::AfterB,
    )?;
    // Real existing registry transition and original ptrace request. The
    // journal's completion marks only successful request return, not a trap.
    unsafe {
        native.begin_admission_original(owner, &release, libc::PTRACE_SINGLESTEP)?;
    }
    // The existing lifecycle helper returns only Result<(), LaunchError>.
    // Preserve successful helper return distinctly; never invent raw rc=0.
    p.progress.effects[p.progress.effects_len - 1]
        .as_mut()
        .expect("original release attempt")
        .complete = true;
    p.progress.phase = StackPhase::Original;
    let (tid, status) = wait_capture(owner, p, 3, STEP_MAP)?;
    if native.consume_admission_interrupt(tid)? {
        return Err(LaunchError::Invalid(
            "owned original received interruption credit",
        ));
    }
    let trace = validate_trace(
        tid,
        owner.pid,
        status,
        p.signals[3].bytes,
        &p.states[STEP].state,
        &p.debug[3],
    )?;
    binding
        .geometry()
        .verify_open(p.maps[BASELINE_MAP].bytes(), p.maps[STEP_MAP].bytes())
        .map_err(mapped)?;
    bootstrap::verify_memory(
        owner,
        binding.candidate().range().start(),
        bytes,
        &mut p.peek,
        p.until.expect("installed stack deadline"),
    )?;
    // C is captured under the actual raw held ordinal3. No registry success
    // token exists yet, and its frozen word is never chosen from successor RSP.
    let held = NativeStackHeldView {
        original: &release,
        raw_wait: (tid, status),
        state: &p.states[STEP],
        maps: p.maps[STEP_MAP].bytes(),
        until,
    };
    let c_read = TraceStackRead::acquire(owner, native, held, &mut p.membership)?;
    p.words[1].capture_trace(
        c_read,
        StackWordExpected {
            profile: binding.profile_description(),
            original_maps: binding.original_maps(),
            geometry: &binding.operand_description().geometry,
            state: &p.states[STEP],
            maps: p.maps[STEP_MAP].bytes(),
            word: &expected_after,
        },
    )?;
    validate_effect(
        &p.states[BEFORE].state,
        &p.states[STEP].state,
        binding.operand_description(),
        &a_bytes,
        &p.words[1].view().word.bytes,
    )
    .map_err(stack_error)?;
    let step = native.finish_admission_execution(
        tid,
        p.states[STEP].state.registers.rip,
        AdmissionPhase::NativeCompleted,
    )?;
    next_stop(&release, &step)?;
    p.stops[3] = Some(step);
    p.trace = Some(trace);
    p.progress.instruction_completed = true;
    p.progress.phase = StackPhase::Closing;
    private_call(
        owner,
        native,
        binding,
        p,
        observer,
        PrivateCall {
            ordinal: 4,
            number: libc::SYS_membarrier,
            arguments: [SYNC_CORE, 0, 0, 0, 0, 0],
        },
    )?;
    private_call(
        owner,
        native,
        binding,
        p,
        observer,
        PrivateCall {
            ordinal: 5,
            number: libc::SYS_mprotect,
            arguments: [range.start(), length, libc::PROT_READ as u64, 0, 0, 0],
        },
    )?;
    private_call(
        owner,
        native,
        binding,
        p,
        observer,
        PrivateCall {
            ordinal: 6,
            number: libc::SYS_membarrier,
            arguments: [SYNC_CORE, 0, 0, 0, 0, 0],
        },
    )?;
    p.maps[CLOSED_MAP].capture(owner, p.until.expect("installed stack deadline"))?;
    verify_closed(p.maps[BASELINE_MAP].bytes(), p.maps[CLOSED_MAP].bytes()).map_err(mapped)?;
    let closed = p.stops[6].as_ref().expect("actual closing stop").clone();
    p.states[WORK].capture(owner, p.until.expect("installed stack deadline"))?;
    if p.states[WORK].state != p.states[STEP].state {
        return Err(LaunchError::Invalid(
            "owned close changed original successor state",
        ));
    }
    observer.closed(
        owner,
        native,
        &closed,
        &p.states[STEP].state,
        p.maps[CLOSED_MAP].bytes(),
        p.until.expect("installed stack deadline"),
    )?;
    let d_read = SettledStackRead::acquire(owner, native, &closed, &mut p.membership, until)?;
    p.words[2].capture_settled(
        d_read,
        SettledWordPhase::D,
        StackWordExpected {
            profile: binding.profile_description(),
            original_maps: binding.original_maps(),
            geometry: &binding.operand_description().geometry,
            state: &p.states[STEP],
            maps: p.maps[CLOSED_MAP].bytes(),
            word: &expected_after,
        },
    )?;
    owner.time_left(
        p.until.expect("installed stack deadline"),
        "owned instruction completion",
    )?;
    ready(
        owner,
        native,
        binding.stop(),
        binding.island(),
        p,
        &closed,
        false,
    )?;
    verify_closed(p.maps[BASELINE_MAP].bytes(), p.maps[WORK_MAP].bytes()).map_err(mapped)?;
    p.progress.nx_closed = true;
    p.progress.phase = StackPhase::Closed;
    Ok(())
}

pub(super) fn require_completed_words(
    binding: &RuntimeStackBinding<'_, '_>,
    p: &PreparedStackNative,
) -> Result<(), LaunchError> {
    let release = p.stops[2]
        .as_ref()
        .ok_or(LaunchError::Invalid("owned stack opening absent"))?;
    let closed = p.stops[6]
        .as_ref()
        .ok_or(LaunchError::Invalid("owned stack closing absent"))?;
    let raw = p.progress.waits[3].ok_or(LaunchError::Invalid("owned stack raw trace absent"))?;
    let expected = [
        StackCaptureAssociation::B {
            stop: release.clone(),
            until: binding.until(),
        },
        StackCaptureAssociation::C {
            original: release.clone(),
            raw_wait: raw,
            ordinal: 3,
            until: binding.until(),
        },
        StackCaptureAssociation::D {
            stop: closed.clone(),
            until: binding.until(),
        },
    ];
    for (word, phase) in p.words.iter().zip(&expected) {
        let view = word.view();
        if !view.complete || view.first_failure.is_some() || view.association != Some(phase) {
            return Err(LaunchError::Invalid(
                "owned stack completed word phase differs",
            ));
        }
    }
    let a = binding.operand().word().bytes;
    let b = p.words[0].view();
    let c = p.words[1].view();
    let d = p.words[2].view();
    if b.word.bytes != a
        || d.word.bytes != c.word.bytes
        || b.observation.state.state != p.states[BEFORE].state
        || c.observation.state.state != p.states[STEP].state
        || d.observation.state.state != p.states[STEP].state
    {
        return Err(LaunchError::Invalid(
            "owned stack completed observations differ",
        ));
    }
    validate_effect(
        &p.states[BEFORE].state,
        &p.states[STEP].state,
        binding.operand_description(),
        &a,
        &c.word.bytes,
    )
    .map_err(stack_error)
}
pub(super) fn failed_held(
    owner: &Owner,
    native: &NativeLifecycle,
    binding: &RuntimeStackBinding<'_, '_>,
    p: &mut PreparedStackNative,
) -> Result<(), LaunchError> {
    if p.progress.phase != StackPhase::Original
        || p.progress.instruction_completed
        || !p.progress.queries_started[3]
        || p.words[1].attempted()
    {
        return Ok(());
    }
    p.progress.failed_held_attempted = true;
    let raw_wait =
        p.progress.waits[3].ok_or(LaunchError::Invalid("failed stack raw wait absent"))?;
    let original = p.stops[2]
        .as_ref()
        .ok_or(LaunchError::Invalid("failed stack release absent"))?;
    // queries_started is set only after the unchanged raw_held accepted this
    // exact retained wait (including newborn discovery). The scoped diagnostic
    // gate rechecks physical ownership without rediscovering the same event.
    let held = NativeStackHeldView {
        original,
        raw_wait,
        state: &p.states[STEP],
        maps: p.maps[STEP_MAP].bytes(),
        until: p.deadline(),
    };
    let read = FailedHeldStackRead::acquire(owner, native, held, &mut p.membership)?;
    p.words[1].capture_failed_held(
        read,
        binding.profile_description(),
        binding.original_maps(),
        &binding.operand_description().geometry,
    )
}

/// Conservative sum of the concrete fixed producer locals, in addition to
/// acquisition's named temporary evidence. No retained payload is copied here.
pub(super) fn temporary_bytes() -> usize {
    2 * size_of::<PrivateCall>()
        + 8 * size_of::<AdmissionStop>()
        + 4 * size_of::<RegisterSnapshot>()
        + size_of::<libc::user_regs_struct>()
        + size_of::<libc::siginfo_t>()
        + size_of::<libc::iovec>()
        + 4 * size_of::<Request>()
        + 8 * size_of::<Result<(), LaunchError>>()
        + 4 * size_of::<StackCaptureAssociation>()
        + 4 * size_of::<acquire::StackWordExpected<'_>>()
        + 4 * size_of::<StackWordView<'_>>()
        + size_of::<NativeStackBeforeView<'_>>()
        + size_of::<NativeStackHeldView<'_>>()
        + 2 * size_of::<NativeTrace>()
        + 2 * size_of::<ParsedMaps<'_>>()
        + 2 * size_of::<MapEntries<'_>>()
        + 3 * size_of::<MapEntry<'_>>()
        + size_of::<[u8; 68]>()
        + 3 * size_of::<[u8; 16]>()
        + 2 * size_of::<[u8; 128]>()
        + size_of::<[u64; 6]>()
        + 16 * size_of::<usize>()
}
