//! Fixed sync/protect/sync, one original step, sync/protect/sync protocol.
use super::*;
use iced_x86::OpKind;

pub(super) fn no_memory(
    candidate: &super::super::runtime_instruction::InstructionCandidate<'_>,
) -> Result<(), LaunchError> {
    let CandidateKind::Ordinary(instruction) = candidate.kind() else {
        return Err(LaunchError::Invalid("owned ordinary request is selected"));
    };
    let family = instruction.family();
    match family {
        OrdinaryFamily::Move | OrdinaryFamily::Arithmetic | OrdinaryFamily::Compare => {
            if (0..instruction.decoded().op_count()).any(|index| {
                !matches!(
                    instruction.decoded().op_kind(index),
                    OpKind::Register
                        | OpKind::Immediate8
                        | OpKind::Immediate8_2nd
                        | OpKind::Immediate16
                        | OpKind::Immediate32
                        | OpKind::Immediate64
                        | OpKind::Immediate8to16
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64
                        | OpKind::Immediate32to64
                )
            }) {
                return Err(LaunchError::Invalid(
                    "owned ordinary memory access is unsupported",
                ));
            }
        }
        OrdinaryFamily::Address | OrdinaryFamily::Nop => {}
        OrdinaryFamily::ConditionalBranch | OrdinaryFamily::Jump
            if instruction.direct_target().is_some() => {}
        _ => {
            return Err(LaunchError::Invalid(
                "owned ordinary control family is unsupported",
            ));
        }
    }
    Ok(())
}
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
    binding: &RuntimeInstructionBinding<'_>,
    p: &mut PreparedInstructionAttempt,
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
        require_initial_task_identity(owner, p.until, p.membership.as_mut_slice())?;
    } else {
        native.require_initial_source_mm(owner, stop, p.until, p.membership.as_mut_slice())?;
    }
    if native.admission_interrupt_credit(owner.pid)? != 0
        || stop.signal.is_some()
        || stop.identity != binding.stop().identity
        || stop.token.session != binding.stop().token.session
        || stop.token.tid != owner.pid
        || stop.identity.generation != 0
    {
        return Err(LaunchError::Invalid(
            "owned instruction singleton or interruption state differs",
        ));
    }
    let island = binding.island();
    if stop.identity.address_space != island.address_space
        || island.generation != 0
        || island.page_size != 4096
    {
        return Err(LaunchError::Invalid(
            "owned instruction island identity differs",
        ));
    }
    p.maps[WORK_MAP].capture(owner, p.until)?;
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
        p.until,
    )?;
    bootstrap::physical(owner, p.until)
}
fn begin_effect(
    owner: &Owner,
    native: &NativeLifecycle,
    p: &mut PreparedInstructionAttempt,
    observer: &mut dyn InstructionObservation,
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
    owner.time_left(p.until, "owned instruction effect")?;
    observer.before_effect(owner, native, effect, current, p.until)?;
    owner.time_left(p.until, "owned instruction effect")?;
    p.progress.effects[p.progress.effects_len] = Some(InstructionEffectRecord {
        effect,
        complete: false,
        result: None,
    });
    p.progress.effects_len += 1;
    Ok(())
}
fn finish_effect(p: &mut PreparedInstructionAttempt, result: Request) -> Result<(), LaunchError> {
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
    p: &mut PreparedInstructionAttempt,
    observer: &mut dyn InstructionObservation,
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
    p: &mut PreparedInstructionAttempt,
    observer: &mut dyn InstructionObservation,
    current: &AdmissionStop,
    wait: usize,
    canonical: usize,
) -> Result<(), LaunchError> {
    p.states[WORK].capture(owner, p.until)?;
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
    p.states[WORK].capture(owner, p.until)?;
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
    p.states[WORK].capture(owner, p.until)?;
    if p.states[WORK].state != p.states[canonical].state {
        return Err(LaunchError::Invalid("trusted state restoration differs"));
    }
    Ok(())
}
fn wait_capture(
    owner: &mut Owner,
    p: &mut PreparedInstructionAttempt,
    ordinal: usize,
    map_slot: usize,
) -> Result<(i32, i32), LaunchError> {
    if p.progress.waits[ordinal].is_some() {
        return Err(LaunchError::Invalid(
            "owned instruction raw wait storage reused",
        ));
    }
    let (tid, status) = owner.wait_raw(p.until, "owned instruction actual wait")?;
    p.progress.waits[ordinal] = Some((tid, status));
    p.progress.queries_started[ordinal] = false;
    bootstrap::raw_held(owner, tid, status, p.until)?;
    p.progress.queries_started[ordinal] = true;
    // Attempt every independent initialized request before interpreting the
    // first failed request. An invalid held event remains diagnostic evidence.
    let signal_result = p.signals[ordinal].capture(tid);
    let state_result = p.states[ordinal + 1].capture_tid(tid);
    let debug_result = p.debug[ordinal].capture(tid);
    let map_result = p.maps[map_slot].capture(owner, p.until);
    signal_result?;
    state_result?;
    debug_result?;
    map_result?;
    owner.time_left(p.until, "owned instruction actual wait")?;
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
    binding: &RuntimeInstructionBinding<'_>,
    p: &mut PreparedInstructionAttempt,
    observer: &mut dyn InstructionObservation,
    call: PrivateCall,
) -> Result<(), LaunchError> {
    let PrivateCall {
        ordinal,
        number,
        arguments,
    } = call;
    let canonical = if ordinal < 3 { BEFORE } else { STEP };
    let stop = native.admission_current(binding.stop().identity.task)?;
    ready(owner, native, binding, p, &stop, ordinal == 4)?;
    p.states[WORK].capture(owner, p.until)?;
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
    bootstrap::verify_memory(owner, pc, &STUB, &mut p.peek, p.until)?;
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
    p.states[WORK].capture(owner, p.until)?;
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
    owner.time_left(p.until, "owned private release")?;
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
    bootstrap::verify_memory(owner, pc, &STUB, &mut p.peek, p.until)?;
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
    ready(owner, native, binding, p, &restored, false)?;
    // Every actual protection operation receives an exact full-range map
    // readback; sync calls preserve the same phase-specific projection too.
    if ordinal < 1 || ordinal >= 5 {
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
pub(super) fn control_unchanged(
    before: &TaskStateSnapshot,
    after: &TaskStateSnapshot,
) -> Result<(), LaunchError> {
    let left = before.registers;
    let right = after.registers;
    let arithmetic = 1 | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
    if before.xstate != after.xstate
        || before.mask != after.mask
        || (
            left.cs,
            left.ss,
            left.ds,
            left.es,
            left.fs,
            left.gs,
            left.fs_base,
            left.gs_base,
            left.orig_rax,
        ) != (
            right.cs,
            right.ss,
            right.ds,
            right.es,
            right.fs,
            right.gs,
            right.fs_base,
            right.gs_base,
            right.orig_rax,
        )
        || left.eflags & !arithmetic != right.eflags & !arithmetic
    {
        return Err(LaunchError::Invalid(
            "owned ordinary changed non-arithmetic control state",
        ));
    }
    Ok(())
}
pub(super) fn execute(
    owner: &mut Owner,
    native: &mut NativeLifecycle,
    binding: &RuntimeInstructionBinding<'_>,
    p: &mut PreparedInstructionAttempt,
    observer: &mut dyn InstructionObservation,
) -> Result<(), LaunchError> {
    owner.time_left(p.until, "owned instruction preparation")?;
    if p.progress.phase != InstructionPhase::Allocated
        || p.initial.is_some()
        || p.until != binding.until()
        || p.shape.fetch_start != binding.geometry().pages().start()
        || p.shape.fetch_end != binding.geometry().pages().end()
    {
        return Err(LaunchError::Invalid(
            "owned instruction storage or deadline differs",
        ));
    }
    no_memory(binding.candidate())?;
    let stop = binding.stop();
    if stop.token != binding.before().token
        || stop.identity != binding.before().task
        || stop.signal.is_some()
        || !matches!(
            stop.phase,
            AdmissionPhase::EntryReady | AdmissionPhase::Restored
        )
        || binding.before().signal.is_some()
        || binding.before().logical_pc != binding.candidate().range().start()
        || binding.before().registers != *binding.candidate().registers()
        || binding.geometry().instruction() != binding.candidate().range()
        || binding.source_id().identity().mapping != binding.candidate().snapshot().mapping.0
        || binding.source_id().identity().generation != binding.candidate().snapshot().generation.0
    {
        return Err(LaunchError::Invalid("owned instruction binding differs"));
    }
    ready(owner, native, binding, p, stop, false)?;
    p.states[BEFORE].capture(owner, p.until)?;
    require_state(&p.states[BEFORE].state)?;
    if !same_observation(&p.states[BEFORE].state, binding.before()) {
        return Err(LaunchError::Invalid(
            "owned instruction logical state differs",
        ));
    }
    p.initial = Some(stop.clone());
    p.source = Some(binding.source_id());
    p.origin = Some(binding.origin());
    p.execution = Some(binding.execution());
    let bytes = binding.candidate().bytes();
    if bytes.is_empty() || bytes.len() > p.encoding.len() {
        return Err(LaunchError::Invalid(
            "owned instruction encoding extent differs",
        ));
    }
    p.encoding[..bytes.len()].copy_from_slice(bytes);
    p.encoding_len = bytes.len();
    p.maps[BASELINE_MAP].capture(owner, p.until)?;
    if p.maps[BASELINE_MAP].bytes() != binding.baseline_maps() {
        return Err(LaunchError::Invalid(
            "owned instruction baseline map identity differs",
        ));
    }
    binding
        .geometry()
        .projected_rows(p.maps[BASELINE_MAP].bytes())
        .map_err(mapped)?;
    bootstrap::verify_memory(
        owner,
        binding.candidate().range().start(),
        bytes,
        &mut p.peek,
        p.until,
    )?;
    p.progress.phase = InstructionPhase::Profile;
    p.profile.capture(owner, p.until)?;
    binding.lineage().authenticate(stop, &p.profile)?;
    p.states[WORK].capture(owner, p.until)?;
    if p.states[WORK].state != p.states[BEFORE].state {
        return Err(LaunchError::Invalid("owned profile changed original state"));
    }
    ready(owner, native, binding, p, stop, false)?;
    p.progress.phase = InstructionPhase::Opening;
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
    p.maps[OPEN_MAP].capture(owner, p.until)?;
    binding
        .geometry()
        .verify_open(p.maps[BASELINE_MAP].bytes(), p.maps[OPEN_MAP].bytes())
        .map_err(mapped)?;
    bootstrap::verify_memory(
        owner,
        binding.candidate().range().start(),
        bytes,
        &mut p.peek,
        p.until,
    )?;
    p.states[WORK].capture(owner, p.until)?;
    if p.states[WORK].state != p.states[BEFORE].state {
        return Err(LaunchError::Invalid("owned opening changed original state"));
    }
    observer.opened(
        owner,
        native,
        &release,
        &p.states[BEFORE].state,
        p.maps[OPEN_MAP].bytes(),
        p.until,
    )?;
    owner.time_left(p.until, "owned original release")?;
    ready(owner, native, binding, p, &release, false)?;
    p.progress.phase = InstructionPhase::Opened;
    begin_effect(
        owner,
        native,
        p,
        observer,
        &release,
        InstructionEffect::OriginalRelease,
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
    p.progress.phase = InstructionPhase::Original;
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
    control_unchanged(&p.states[BEFORE].state, &p.states[STEP].state)?;
    binding
        .geometry()
        .verify_open(p.maps[BASELINE_MAP].bytes(), p.maps[STEP_MAP].bytes())
        .map_err(mapped)?;
    bootstrap::verify_memory(
        owner,
        binding.candidate().range().start(),
        bytes,
        &mut p.peek,
        p.until,
    )?;
    let step = native.finish_admission_execution(
        tid,
        p.states[STEP].state.registers.rip,
        AdmissionPhase::NativeCompleted,
    )?;
    next_stop(&release, &step)?;
    p.stops[3] = Some(step);
    p.trace = Some(trace);
    p.progress.instruction_completed = true;
    p.progress.phase = InstructionPhase::Closing;
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
    p.maps[CLOSED_MAP].capture(owner, p.until)?;
    verify_closed(p.maps[BASELINE_MAP].bytes(), p.maps[CLOSED_MAP].bytes()).map_err(mapped)?;
    let closed = p.stops[6].as_ref().expect("actual closing stop").clone();
    p.states[WORK].capture(owner, p.until)?;
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
        p.until,
    )?;
    owner.time_left(p.until, "owned instruction completion")?;
    ready(owner, native, binding, p, &closed, false)?;
    verify_closed(p.maps[BASELINE_MAP].bytes(), p.maps[WORK_MAP].bytes()).map_err(mapped)?;
    p.progress.nx_closed = true;
    p.progress.phase = InstructionPhase::Closed;
    Ok(())
}
