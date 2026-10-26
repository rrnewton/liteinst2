//! One original selected invocation on the existing owner thread.
//!
//! This transport holds siblings but has no publication lease while original
//! instructions run. The caller owns source restoration/rearming and policy;
//! every native stop, creation pairing and physical cleanup remains Owner's.
use super::kernel_journal::{
    KernelAttemptHandle, KernelAttemptId, KernelReleasePhase, KernelStateSlot,
};
use super::trusted::{AdmissionPhase, AdmissionStop, TaskStateSnapshot, TrustedIsland};
use super::*;
use crate::lifecycle::TaskId;
use crate::selected::{Operation, SelectedInput, SyscallAbi, SyscallAliases};
use crate::trap_coverage::{TrapGuard, TrapGuardRole};
use iced_x86::Register;

pub(in crate::linux::remote::dynamic) struct OriginalInvocation<'a> {
    pub(in crate::linux::remote::dynamic) stop: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic) input: &'a SelectedInput,
    pub(in crate::linux::remote::dynamic) before_xstate: &'a [u8],
    pub(in crate::linux::remote::dynamic) before_mask: u64,
    pub(in crate::linux::remote::dynamic) journal: Option<KernelAttemptHandle>,
}

pub(in crate::linux::remote::dynamic) enum OriginalOutcome {
    Completed(Box<OriginalCompletion>),
    /// The actual event remains held/terminal according to its exact native
    /// kind. Signal, control, anticipated exit and terminal are never completions.
    Event(Box<OriginalEvent>),
}

pub(in crate::linux::remote::dynamic) struct OriginalCompletion {
    pub(in crate::linux::remote::dynamic) stop: AdmissionStop,
    pub(in crate::linux::remote::dynamic) state: TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic) evidence: OriginalEvidence,
    /// Actual creation and newborn notifications, retained as historical facts.
    /// Their old stop tokens cannot authorize release after private bridges.
    pub(in crate::linux::remote::dynamic) events: Vec<DynamicEvent>,
    /// Actual neutral user-return stops for each newly authenticated shared-mm task.
    pub(in crate::linux::remote::dynamic) newborns: Vec<AdmissionStop>,
}

pub(in crate::linux::remote::dynamic) enum OriginalEvidence {
    CpuTrace { raw: [u8; 128] },
    Syscall(Box<OriginalSyscallEvidence>),
}

pub(in crate::linux::remote::dynamic) struct OriginalSyscallEvidence {
    pub(in crate::linux::remote::dynamic) attempt: KernelAttemptId,
    pub(in crate::linux::remote::dynamic) entry: DynamicEvent,
    pub(in crate::linux::remote::dynamic) entry_state: TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic) exit: DynamicEvent,
    pub(in crate::linux::remote::dynamic) exit_state: TaskStateSnapshot,
    /// Actual automatic return-ready observations made before any return
    /// bridge, each bound to its resulting private user-return checkpoint.
    pub(in crate::linux::remote::dynamic) newborns: Vec<OriginalNewbornEvidence>,
}

pub(in crate::linux::remote::dynamic) struct OriginalNewbornEvidence {
    pub(in crate::linux::remote::dynamic) event: DynamicEvent,
    pub(in crate::linux::remote::dynamic) before_bridge: TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic) after_bridge: AdmissionStop,
}

pub(in crate::linux::remote::dynamic) struct OriginalEvent {
    pub(in crate::linux::remote::dynamic) event: DynamicEvent,
    /// None only for a real terminal or internally resumed TaskExiting event.
    pub(in crate::linux::remote::dynamic) state: Option<TaskStateSnapshot>,
    pub(in crate::linux::remote::dynamic) events: Vec<DynamicEvent>,
}

/// # Safety
/// The frontend consumed one exact native provider invocation. It authenticated
/// every original instruction byte, made its complete fetch range executable,
/// kept all sibling application tasks held, and retains the closed rearm/release
/// interlock. No publication lease exists during this call. Its syscall policy
/// rejects all unqualified writers, mapping changes, signal restoration and
/// ownership changes before this permit; only the explicitly qualified same-mm
/// clone is supported here. TF/RF provenance at inserted guards is certified by
/// the frontend's unchanged entry contract. Every returned event/continuation
/// must be independently rearmed before any original release.
pub(in crate::linux::remote::dynamic) unsafe fn execute(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    island: &TrustedIsland,
    invocation: OriginalInvocation<'_>,
    until: Instant,
) -> Result<OriginalOutcome, LaunchError> {
    let result = execute_inner(owner, native, island, invocation, None, until);
    if let Err(error) = &result {
        owner
            .kernel_journal
            .fail_active(kernel_journal::failure_kind(error));
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
    }
    result
}

/// A private observer owned by the mapping transaction. Raw mapping and kernel
/// captures are independently attempted before dispatch. The typed callbacks
/// then require fully validated native ENTRY/EXIT. No observation grants
/// execution permission or replaces the original syscall.
pub(in crate::linux::remote::dynamic::owner) trait MappingObservation {
    fn raw(&mut self, tid: i32, status: i32) -> Result<(), LaunchError>;
    fn entry(&mut self, event: &DynamicEvent, state: &TaskStateSnapshot)
    -> Result<(), LaunchError>;
    fn exit(&mut self, event: &DynamicEvent, state: &TaskStateSnapshot) -> Result<(), LaunchError>;
}

/// Execute the one original mapping syscall in a separate sealed window.
///
/// # Safety
/// In addition to the state, instruction and sibling obligations of `execute`,
/// the caller owns the non-cloneable whole-domain mapping window. It restored
/// original source and logical permissions, checked this exact syscall's owned
/// affected range against every retained continuation, and reserved its raw
/// observations before effects. There is exactly one task in the mm. No
/// original return is released: the caller must quarantine the result and
/// commit a freshly authenticated source set before any ordinary release.
pub(in crate::linux::remote::dynamic::owner) unsafe fn execute_mapping(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    island: &TrustedIsland,
    invocation: OriginalInvocation<'_>,
    observation: &mut dyn MappingObservation,
    until: Instant,
) -> Result<OriginalOutcome, LaunchError> {
    let result = (|| {
        if !matches!(
            invocation.input.instruction().operation(),
            Operation::Syscall {
                abi: SyscallAbi::LinuxX64
            }
        ) || invocation.input.instruction().bytes() != [0x0f, 0x05]
            || !matches!(
                invocation.input.registers().rax as libc::c_long,
                libc::SYS_mmap | libc::SYS_mprotect | libc::SYS_munmap
            )
            || native
                .check_admission_mm(owner, invocation.stop.identity.task)?
                .candidate
                .tasks
                .len()
                != 1
        {
            return Err(LaunchError::Invalid(
                "mapping window lacks one native64 original syscall",
            ));
        }
        execute_inner(owner, native, island, invocation, Some(observation), until)
    })();
    if let Err(error) = &result {
        owner
            .kernel_journal
            .fail_active(kernel_journal::failure_kind(error));
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
    }
    result
}

fn execute_inner(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    island: &TrustedIsland,
    invocation: OriginalInvocation<'_>,
    observation: Option<&mut dyn MappingObservation>,
    until: Instant,
) -> Result<OriginalOutcome, LaunchError> {
    owner.time_left(until, "native selected invocation")?;
    native.require_admission_stop(invocation.stop)?;
    if !native.admission_events_empty() {
        return Err(LaunchError::Invalid(
            "native selected invocation has undrained lifecycle events",
        ));
    }
    let id = invocation.stop.identity.task;
    let membership = native.check_admission_mm(owner, id)?;
    if membership.address_space != island.address_space
        || membership.generation != island.generation
    {
        return Err(LaunchError::Invalid(
            "native selected island identity differs",
        ));
    }
    let input = invocation.input;
    let instruction = input.instruction();
    let before = input.registers();
    if before.rip != instruction.logical_pc()
        || before.cs != 0x33
        || before.eflags & 0x100 != 0
        || invocation.before_xstate.len() > MAX_XSTATE
    {
        return Err(LaunchError::Invalid(
            "native selected input ABI, PC or flags differ",
        ));
    }
    match instruction.operation() {
        Operation::Syscall {
            abi: SyscallAbi::LinuxX64,
        } => {
            if before.rax > i32::MAX as u64 || before.rax & 0x4000_0000 != 0 {
                return Err(LaunchError::Invalid(
                    "native selected syscall personality is unqualified",
                ));
            }
            if matches!(
                before.rax as libc::c_long,
                libc::SYS_fork
                    | libc::SYS_vfork
                    | libc::SYS_clone3
                    | libc::SYS_execve
                    | libc::SYS_execveat
                    | libc::SYS_rt_sigreturn
            ) {
                return Err(LaunchError::Invalid(
                    "native selected syscall changes an unsupported ownership profile",
                ));
            }
        }
        Operation::Syscall { .. } => {
            return Err(LaunchError::Invalid(
                "native selected syscall alias is unqualified",
            ));
        }
        _ => {}
    }
    // Re-decode the exact complete encoding, independently of a stored plan.
    let decoded = crate::selected::decode(
        instruction.logical_pc(),
        instruction.bytes(),
        &SyscallAliases::new(),
    )
    .map_err(|_| LaunchError::Invalid("native selected original decode differs"))?;
    if decoded != *instruction || decoded.bytes().len() != instruction.bytes().len() {
        return Err(LaunchError::Invalid(
            "native selected instruction is not exact and complete",
        ));
    }
    let saved = TaskStateSnapshot {
        registers: *before,
        xstate: invocation.before_xstate.to_vec(),
        mask: invocation.before_mask,
    };
    if TaskStateSnapshot::read(invocation.stop.token.tid)? != saved {
        return Err(LaunchError::Invalid(
            "native selected full before-state differs",
        ));
    }
    let mut siblings = Vec::new();
    for &task in &membership.candidate.tasks {
        if task != id {
            let token = native.admission_held_token(task)?;
            siblings.push((task, token.clone(), TaskStateSnapshot::read(token.tid)?));
        }
    }
    island.verify(invocation.stop.token.tid)?;
    verify_original(
        invocation.stop.token.tid,
        instruction.logical_pc(),
        instruction.bytes(),
    )?;
    let result = (|| {
        let mut current = invocation.stop.clone();
        // The upper-bound interrupt credit is settled only by fresh real neutral
        // stops. The original instruction is never replayed to settle control.
        while native.admission_interrupt_credit(current.token.tid)? != 0 {
            let setup = trusted::temporary(&saved.registers, island.trap());
            current = trusted::execute(
                owner,
                native,
                &current,
                (island.trap(), &[0xcc]),
                setup,
                true,
                until,
            )?
            .1;
        }
        if TaskStateSnapshot::read(current.token.tid)? != saved {
            return Err(LaunchError::Invalid(
                "native selected interruption settlement changed state",
            ));
        }
        verify_siblings(owner, native, &siblings)?;
        verify_original(
            current.token.tid,
            instruction.logical_pc(),
            instruction.bytes(),
        )?;
        let syscall = matches!(instruction.operation(), Operation::Syscall { .. });
        if syscall != invocation.journal.is_some() {
            return Err(LaunchError::Invalid(
                "native syscall journal binding is missing or unexpected",
            ));
        }
        if let Some(handle) = invocation.journal {
            owner
                .kernel_journal
                .check_invocation(handle, &current, input, &saved, until)?;
        }
        if let Some(handle) = invocation.journal {
            owner.kernel_journal.release_attempt(
                handle,
                KernelReleasePhase::Original,
                &current.token,
            )?;
        }
        owner.time_left(until, "native selected invocation")?;
        // SAFETY: the outer caller supplied the exact original permit; all
        // native membership/source/state checks above hold at this release.
        unsafe {
            native.begin_admission_original(
                owner,
                &current,
                if syscall {
                    libc::PTRACE_SYSCALL
                } else {
                    libc::PTRACE_SINGLESTEP
                },
            )?;
        }
        if let Some(handle) = invocation.journal {
            owner.kernel_journal.release_succeeded(
                handle,
                KernelReleasePhase::Original,
                &current.token,
            )?;
        }
        let outcome = if syscall {
            run_syscall(
                owner,
                native,
                island,
                (&current, &saved, invocation),
                observation,
                until,
            )?
        } else {
            run_cpu(owner, native, &current, &saved, until, |after| {
                input
                    .validate_native_completion(after)
                    .map(|_| ())
                    .map_err(|_| {
                        LaunchError::Invalid("native selected full register completion differs")
                    })
            })?
        };
        verify_siblings(owner, native, &siblings)?;
        // The caller has not yet rearmed these bytes. Unexpected changes do not
        // turn a native observation into a completed publication.
        if matches!(&outcome, OriginalOutcome::Completed(_))
            || matches!(&outcome, OriginalOutcome::Event(event) if event.state.is_some())
        {
            verify_original(
                current.token.tid,
                instruction.logical_pc(),
                instruction.bytes(),
            )?;
        }
        // A real terminal or internally resumed Exiting task has no readable
        // selected stop. Its outcome grants no publication/release authority.
        Ok(outcome)
    })();
    if result.is_err() {
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
    }
    result
}

pub(in crate::linux::remote::dynamic) struct CollateralInvocation<'a> {
    pub(in crate::linux::remote::dynamic) stop: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic) guard: &'a TrapGuard,
    pub(in crate::linux::remote::dynamic) before: &'a TaskStateSnapshot,
}

/// Execute only the existing explicitly qualified collateral immediate MOV
/// profile. There is no selected provider invocation or generic interpreter.
///
/// # Safety
/// The same whole-mm hold, exact original bytes/RX, saved-continuation and
/// closed rearm/release interlock required by `execute` apply. The current
/// private stop follows an authenticated owned collateral guard, with its RIP
/// normalized by a genuine neutral checkpoint and no invented kernel stop.
pub(in crate::linux::remote::dynamic) unsafe fn execute_collateral(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    island: &TrustedIsland,
    invocation: CollateralInvocation<'_>,
    until: Instant,
) -> Result<OriginalOutcome, LaunchError> {
    let result = (|| {
        owner.time_left(until, "native collateral invocation")?;
        native.require_admission_stop(invocation.stop)?;
        let guard = invocation.guard;
        if guard.role() != TrapGuardRole::Collateral || !native.admission_events_empty() {
            return Err(LaunchError::Invalid(
                "collateral invocation role or event queue differs",
            ));
        }
        crate::gate::domain::qualify_collateral(guard).map_err(|_| {
            LaunchError::Invalid("collateral instruction lacks native-step qualification")
        })?;
        let before = invocation.before;
        if before.registers.rip != guard.address()
            || before.registers.cs != 0x33
            || before.registers.orig_rax != u64::MAX
            || before.registers.eflags & (0x100 | 0x10000) != 0
            || before.xstate.len() > MAX_XSTATE
            || TaskStateSnapshot::read(invocation.stop.token.tid)? != *before
        {
            return Err(LaunchError::Invalid(
                "collateral full before-state or guard metadata differs",
            ));
        }
        let membership = native.check_admission_mm(owner, invocation.stop.identity.task)?;
        if membership.address_space != island.address_space
            || membership.generation != island.generation
        {
            return Err(LaunchError::Invalid("collateral island identity differs"));
        }
        let mut siblings = Vec::new();
        for &task in &membership.candidate.tasks {
            if task != invocation.stop.identity.task {
                let token = native.admission_held_token(task)?;
                siblings.push((task, token.clone(), TaskStateSnapshot::read(token.tid)?));
            }
        }
        let expected = collateral_after(guard, &before.registers)?;
        island.verify(invocation.stop.token.tid)?;
        verify_original(
            invocation.stop.token.tid,
            guard.address(),
            guard.original_bytes(),
        )?;
        let mut current = invocation.stop.clone();
        while native.admission_interrupt_credit(current.token.tid)? != 0 {
            let setup = trusted::temporary(&before.registers, island.trap());
            current = trusted::execute(
                owner,
                native,
                &current,
                (island.trap(), &[0xcc]),
                setup,
                true,
                until,
            )?
            .1;
        }
        if TaskStateSnapshot::read(current.token.tid)? != *before {
            return Err(LaunchError::Invalid(
                "collateral interruption settlement changed state",
            ));
        }
        verify_siblings(owner, native, &siblings)?;
        verify_original(current.token.tid, guard.address(), guard.original_bytes())?;
        owner.time_left(until, "native collateral invocation")?;
        // SAFETY: caller supplies the exact collateral-only permit; source,
        // complete native hold and before-state were independently checked.
        unsafe {
            native.begin_admission_original(owner, &current, libc::PTRACE_SINGLESTEP)?;
        }
        let outcome = run_cpu(owner, native, &current, before, until, |after| {
            if *after != expected {
                return Err(LaunchError::Invalid(
                    "collateral full register completion differs",
                ));
            }
            Ok(())
        })?;
        verify_siblings(owner, native, &siblings)?;
        if matches!(&outcome, OriginalOutcome::Completed(_))
            || matches!(&outcome, OriginalOutcome::Event(event) if event.state.is_some())
        {
            verify_original(current.token.tid, guard.address(), guard.original_bytes())?;
        }
        Ok(outcome)
    })();
    if result.is_err() {
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
    }
    result
}

fn collateral_after(
    guard: &TrapGuard,
    before: &RegisterSnapshot,
) -> Result<RegisterSnapshot, LaunchError> {
    let instruction = Decoder::with_ip(
        64,
        guard.original_bytes(),
        guard.address(),
        DecoderOptions::NONE,
    )
    .decode();
    if instruction.is_invalid() || instruction.len() != guard.original_bytes().len() {
        return Err(LaunchError::Invalid(
            "collateral decode is not exact and complete",
        ));
    }
    let (width, value) = match instruction.code() {
        Code::Mov_r16_imm16 => (16, u64::from(instruction.immediate16())),
        Code::Mov_r32_imm32 => (32, u64::from(instruction.immediate32())),
        Code::Mov_r64_imm64 => (64, instruction.immediate64()),
        _ => {
            return Err(LaunchError::Invalid(
                "collateral instruction is not a qualified immediate MOV",
            ));
        }
    };
    let mut after = *before;
    let destination = match instruction.op0_register() {
        Register::AX | Register::EAX | Register::RAX => &mut after.rax,
        Register::CX | Register::ECX | Register::RCX => &mut after.rcx,
        Register::DX | Register::EDX | Register::RDX => &mut after.rdx,
        Register::BX | Register::EBX | Register::RBX => &mut after.rbx,
        Register::SP | Register::ESP | Register::RSP => &mut after.rsp,
        Register::BP | Register::EBP | Register::RBP => &mut after.rbp,
        Register::SI | Register::ESI | Register::RSI => &mut after.rsi,
        Register::DI | Register::EDI | Register::RDI => &mut after.rdi,
        Register::R8W | Register::R8D | Register::R8 => &mut after.r8,
        Register::R9W | Register::R9D | Register::R9 => &mut after.r9,
        Register::R10W | Register::R10D | Register::R10 => &mut after.r10,
        Register::R11W | Register::R11D | Register::R11 => &mut after.r11,
        Register::R12W | Register::R12D | Register::R12 => &mut after.r12,
        Register::R13W | Register::R13D | Register::R13 => &mut after.r13,
        Register::R14W | Register::R14D | Register::R14 => &mut after.r14,
        Register::R15W | Register::R15D | Register::R15 => &mut after.r15,
        _ => {
            return Err(LaunchError::Invalid(
                "collateral MOV destination is not a full GPR",
            ));
        }
    };
    *destination = if width == 16 {
        (*destination & !0xffff) | value
    } else {
        value
    };
    after.rip = guard
        .address()
        .checked_add(guard.original_bytes().len() as u64)
        .ok_or(LaunchError::Invalid("collateral continuation overflow"))?;
    // Guard input has orig_rax=MAX and clear RF; the real debug trap must retain
    // all untouched flags, kernel metadata, segments and every other register.
    Ok(after)
}

fn verify_original(tid: i32, pc: u64, bytes: &[u8]) -> Result<(), LaunchError> {
    if bytes.is_empty() || bytes.len() > 15 || read_memory(tid, pc, bytes.len())? != bytes {
        return Err(LaunchError::Invalid(
            "native selected original bytes differ",
        ));
    }
    let end = pc
        .checked_add(bytes.len() as u64)
        .ok_or(LaunchError::Invalid("native selected range overflow"))?;
    let mut cursor = pc;
    for mapping in read_maps(tid)? {
        if mapping.end <= cursor || mapping.start >= end {
            continue;
        }
        if mapping.start > cursor || mapping.permissions != "r-xp" {
            return Err(LaunchError::Invalid(
                "native selected fetch range is not immutable private RX",
            ));
        }
        cursor = mapping.end.min(end);
    }
    if cursor != end {
        return Err(LaunchError::Invalid(
            "native selected fetch range contains a hole",
        ));
    }
    Ok(())
}

fn verify_siblings(
    owner: &Owner,
    native: &lifecycle::NativeLifecycle,
    siblings: &[(TaskId, DynamicStop, TaskStateSnapshot)],
) -> Result<(), LaunchError> {
    for (task, token, state) in siblings {
        if native.admission_held_token(*task)? != *token
            || !owner.stopped.contains_key(&token.tid)
            || !owner.owned.contains(&token.tid)
            || owner.handles.get(&token.tid).is_none_or(broker::hup)
            || TaskStateSnapshot::read(token.tid)? != *state
        {
            return Err(LaunchError::Invalid(
                "original selected invocation changed a held sibling",
            ));
        }
    }
    Ok(())
}

fn run_cpu(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    current: &AdmissionStop,
    before: &TaskStateSnapshot,
    until: Instant,
    validate: impl FnOnce(&RegisterSnapshot) -> Result<(), LaunchError>,
) -> Result<OriginalOutcome, LaunchError> {
    let (tid, status) = owner.wait_raw(until, "native selected CPU completion")?;
    if tid != current.token.tid {
        return Err(LaunchError::Invalid(
            "sibling event during native selected CPU instruction",
        ));
    }
    if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP && status >> 16 == 0 {
        let mut raw = [0_u8; 128];
        ptrace(libc::PTRACE_GETSIGINFO, tid, 0, raw.as_mut_ptr() as usize)?;
        let signal = DynamicSignalInfo { raw };
        if signal.signal() == libc::SIGTRAP && signal.code() == libc::TRAP_TRACE {
            let after = TaskStateSnapshot::read(tid)?;
            validate(&after.registers)?;
            if after.xstate != before.xstate || after.mask != before.mask {
                return Err(LaunchError::Invalid(
                    "native selected CPU changed XSTATE or signal mask",
                ));
            }
            let stop = native.finish_admission_execution(
                tid,
                after.registers.rip,
                AdmissionPhase::NativeCompleted,
            )?;
            return Ok(OriginalOutcome::Completed(Box::new(OriginalCompletion {
                stop,
                state: after,
                evidence: OriginalEvidence::CpuTrace { raw },
                events: Vec::new(),
                newborns: Vec::new(),
            })));
        }
    }
    let event = native
        .observe_admission_other(owner, tid, status)?
        .ok_or(LaunchError::Invalid(
            "selected CPU instruction has an unresolved lifecycle event",
        ))?;
    retained_event(owner, native, event, Vec::new())
}

fn next_syscall_event(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    journal: KernelAttemptHandle,
    observation: &mut Option<&mut dyn MappingObservation>,
    until: Instant,
) -> Result<DynamicEvent, LaunchError> {
    loop {
        if let Some(event) = native.take_admission_event() {
            return Ok(event);
        }
        let (tid, status) = owner.wait_raw(until, "native selected syscall lifecycle")?;
        // Attempt both independent raw captures before propagating either
        // failure. A failed state read must not erase the actual map receipt;
        // a failed proc read must not suppress the journal's raw wait/state.
        let mapping_capture = observation
            .as_deref_mut()
            .map_or(Ok(()), |observer| observer.raw(tid, status));
        let kernel_capture = owner.capture_kernel_raw(journal, tid, status);
        kernel_capture?;
        mapping_capture?;
        if let Some(event) = native.observe_admission_other(owner, tid, status)? {
            return Ok(event);
        }
    }
}

fn run_syscall(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    island: &TrustedIsland,
    original: (&AdmissionStop, &TaskStateSnapshot, OriginalInvocation<'_>),
    mut observation: Option<&mut dyn MappingObservation>,
    until: Instant,
) -> Result<OriginalOutcome, LaunchError> {
    let (current, before, invocation) = original;
    let input = invocation.input;
    let journal = invocation
        .journal
        .ok_or(LaunchError::Invalid("native syscall journal is absent"))?;
    let entry = next_syscall_event(owner, native, journal, &mut observation, until)?;
    let tid = entry.tid;
    let next = input.instruction().next_pc();
    let number = before.registers.rax;
    if tid != current.token.tid {
        return Err(LaunchError::Invalid(
            "sibling event before native selected syscall ENTRY",
        ));
    }
    if !matches!(entry.kind, DynamicEventKind::SyscallEntry { .. }) {
        return retained_event(owner, native, entry, Vec::new());
    }
    if entry.task != Some(current.identity) || tid != current.token.tid {
        return Err(LaunchError::Invalid(
            "native syscall entry identity differs",
        ));
    }
    let entry_state = TaskStateSnapshot::read(tid)?;
    let mut expected = before.registers;
    expected.rip = next;
    expected.orig_rax = number;
    expected.rax = (-i64::from(libc::ENOSYS)) as u64;
    expected.rcx = next;
    expected.r11 = before.registers.eflags & !0x10000;
    expected.eflags &= !0x10000;
    if entry.kind
        != (DynamicEventKind::SyscallEntry {
            number,
            arguments: arguments(&before.registers),
        })
        || entry_state.registers != expected
        || entry_state.xstate != before.xstate
        || entry_state.mask != before.mask
    {
        return Err(LaunchError::Invalid(
            "native selected syscall ENTRY full state differs",
        ));
    }
    owner
        .kernel_journal
        .validated_entry(journal, &entry, &entry_state)?;
    if let Some(observer) = observation.as_deref_mut() {
        observer.entry(&entry, &entry_state)?;
    }
    #[cfg(test)]
    owner.journal_fault_at(JournalFaultPoint::AfterValidatedEntry)?;
    let entry_token = entry
        .stop_token()
        .ok_or(LaunchError::Invalid("native syscall ENTRY lacks token"))?;
    // SAFETY: the outer original permit supplied policy and source/rearm bounds.
    // This uses the real lifecycle dispatcher, including its exact clone checks.
    owner.time_left(until, "native selected syscall ENTRY release")?;
    owner
        .kernel_journal
        .release_attempt(journal, KernelReleasePhase::Entry, entry_token)?;
    unsafe {
        native.resume_admission_event(owner, entry_token, DynamicResume::Continue)?;
    }
    owner
        .kernel_journal
        .release_succeeded(journal, KernelReleasePhase::Entry, entry_token)?;
    let mut events = Vec::new();
    let mut newborn_events = Vec::new();
    let exit = loop {
        let event = next_syscall_event(owner, native, journal, &mut observation, until)?;
        match &event.kind {
            DynamicEventKind::Created { .. } if event.tid == tid => {
                if number != libc::SYS_clone as u64 || !events.is_empty() {
                    return Err(LaunchError::Invalid(
                        "unexpected native selected creation event",
                    ));
                }
                let DynamicEventKind::Created { child } = &event.kind else {
                    unreachable!()
                };
                let newborn = native.admission_held_event(child.task)?;
                owner
                    .kernel_journal
                    .validated_creation(journal, &event, &newborn)?;
                let token = event
                    .stop_token()
                    .ok_or(LaunchError::Invalid("native creation lacks parent token"))?;
                owner.time_left(until, "native selected creation return")?;
                owner.kernel_journal.release_attempt(
                    journal,
                    KernelReleasePhase::Creation,
                    token,
                )?;
                unsafe {
                    native.resume_admission_event(owner, token, DynamicResume::Continue)?;
                }
                owner.kernel_journal.release_succeeded(
                    journal,
                    KernelReleasePhase::Creation,
                    token,
                )?;
                events.push(event);
            }
            DynamicEventKind::Newborn { .. }
                if number == libc::SYS_clone as u64 && event.tid != tid =>
            {
                if !newborn_events.is_empty() {
                    return Err(LaunchError::Invalid(
                        "native selected clone exceeded newborn bound",
                    ));
                }
                newborn_events.push(event.clone());
                events.push(event);
            }
            DynamicEventKind::SyscallExit { .. } if event.tid == tid => break event,
            _ if event.tid != tid => {
                return Err(LaunchError::Invalid(
                    "sibling event during native selected syscall",
                ));
            }
            _ => return retained_event(owner, native, event, events),
        }
    };
    let exit_state = TaskStateSnapshot::read(tid)?;
    let (result, is_error) = match &exit.kind {
        DynamicEventKind::SyscallExit { result, is_error } => (*result, *is_error),
        _ => {
            return Err(LaunchError::Invalid(
                "native selected return lacks an actual EXIT",
            ));
        }
    };
    expected.rax = result as u64;
    if exit_state.registers != expected
        || exit_state.xstate != before.xstate
        || exit_state.mask != before.mask
        || is_error != (-4095..=-1).contains(&result)
        || !native.admission_events_empty()
    {
        return Err(LaunchError::Invalid(
            "native selected syscall EXIT full state or queue differs",
        ));
    }
    if number == libc::SYS_clone as u64 {
        if is_error && !events.is_empty()
            || !is_error && (events.len() != 2 || newborn_events.len() != 1)
        {
            return Err(LaunchError::Invalid(
                "native selected clone evidence is incomplete",
            ));
        }
    } else if !events.is_empty() {
        return Err(LaunchError::Invalid(
            "non-creation syscall produced lifecycle events",
        ));
    }
    owner
        .kernel_journal
        .validated_exit(journal, &exit, &exit_state)?;
    if let Some(observer) = observation {
        observer.exit(&exit, &exit_state)?;
    }
    #[cfg(test)]
    owner.journal_fault_at(JournalFaultPoint::AfterValidatedExit)?;
    // Preserve the actual automatic newborn observation before either return
    // bridge. A later restored checkpoint cannot reconstruct this evidence.
    let mut newborn_observations = Vec::new();
    for event in newborn_events {
        let identity = event
            .task
            .ok_or(LaunchError::Invalid("native newborn lacks identity"))?;
        if native.admission_held_event(identity.task)? != event
            || !owner.stopped.contains_key(&event.tid)
        {
            return Err(LaunchError::Invalid(
                "native newborn observation is not its current held event",
            ));
        }
        let before_bridge = TaskStateSnapshot::read(event.tid)?;
        newborn_observations.push((event, before_bridge));
    }
    let exit_token = exit
        .stop_token()
        .ok_or(LaunchError::Invalid("native syscall EXIT lacks token"))?;
    owner
        .kernel_journal
        .bridge_begin(journal, current.identity, false)?;
    let stop = trusted::return_bridge(owner, native, island, exit_token, until)?;
    native.require_admission_stop(&stop)?;
    owner
        .kernel_journal
        .capture_bridge(journal, KernelStateSlot::ParentBridge, &stop)?;
    #[cfg(test)]
    owner.journal_fault_at(JournalFaultPoint::AfterParentBridge)?;
    let mut newborns = Vec::new();
    let mut newborn_evidence = Vec::new();
    for (event, before_bridge) in newborn_observations {
        let identity = event
            .task
            .ok_or(LaunchError::Invalid("native newborn lacks identity"))?;
        let token = event
            .stop_token()
            .ok_or(LaunchError::Invalid("native newborn lacks token"))?;
        if native.admission_held_event(identity.task)? != event
            || TaskStateSnapshot::read(event.tid)? != before_bridge
        {
            return Err(LaunchError::Invalid(
                "parent return bridge changed actual newborn state",
            ));
        }
        owner.kernel_journal.bridge_begin(journal, identity, true)?;
        let after_bridge = trusted::return_bridge(owner, native, island, token, until)?;
        native.require_admission_stop(&after_bridge)?;
        owner.kernel_journal.capture_bridge(
            journal,
            KernelStateSlot::NewbornBridge,
            &after_bridge,
        )?;
        #[cfg(test)]
        owner.journal_fault_at(JournalFaultPoint::AfterChildBridge)?;
        if after_bridge.identity != identity || TaskStateSnapshot::read(event.tid)? != before_bridge
        {
            return Err(LaunchError::Invalid(
                "newborn return bridge changed actual automatic-stop state",
            ));
        }
        newborns.push(after_bridge.clone());
        newborn_evidence.push(OriginalNewbornEvidence {
            event,
            before_bridge,
            after_bridge,
        });
    }
    if TaskStateSnapshot::read(tid)? != exit_state {
        return Err(LaunchError::Invalid(
            "native selected return bridges changed actual EXIT state",
        ));
    }
    owner
        .kernel_journal
        .transport_complete(journal, &stop, newborns.first())?;
    #[cfg(test)]
    owner.journal_fault_at(JournalFaultPoint::AfterTransport)?;
    Ok(OriginalOutcome::Completed(Box::new(OriginalCompletion {
        stop,
        state: exit_state.clone(),
        evidence: OriginalEvidence::Syscall(Box::new(OriginalSyscallEvidence {
            attempt: journal.id(),
            entry,
            entry_state,
            exit,
            exit_state,
            newborns: newborn_evidence,
        })),
        events,
        newborns,
    })))
}

fn retained_event(
    owner: &Owner,
    native: &lifecycle::NativeLifecycle,
    event: DynamicEvent,
    events: Vec<DynamicEvent>,
) -> Result<OriginalOutcome, LaunchError> {
    let state = if let Some(token) = event.stop_token() {
        let task = event.task.ok_or(LaunchError::Invalid(
            "native selected held event lacks task",
        ))?;
        if native.admission_held_token(task.task)? != *token
            || !owner.stopped.contains_key(&event.tid)
        {
            return Err(LaunchError::Invalid(
                "native selected event is not its current held stop",
            ));
        }
        Some(TaskStateSnapshot::read(event.tid)?)
    } else {
        if !matches!(
            event.kind,
            DynamicEventKind::TaskExiting { .. } | DynamicEventKind::TaskTerminal { .. }
        ) {
            return Err(LaunchError::Invalid(
                "native selected unheld event lacks terminal provenance",
            ));
        }
        None
    };
    Ok(OriginalOutcome::Event(Box::new(OriginalEvent {
        event,
        state,
        events,
    })))
}
