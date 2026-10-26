//! Owner-thread trusted execution. Numeric child addresses remain numeric.
//!
//! Only authenticated private phases enter this runner. It never constructs a
//! ChildOwner, transfers ptrace ownership, or executes an original instruction.
use super::*;
use crate::lifecycle::AddressSpaceId;

/// A private current stop, distinct from an application signal or syscall stop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic) struct AdmissionStop {
    pub(in crate::linux::remote::dynamic) token: DynamicStop,
    pub(in crate::linux::remote::dynamic) identity: DynamicTask,
    pub(in crate::linux::remote::dynamic) phase: AdmissionPhase,
    pub(in crate::linux::remote::dynamic) signal: Option<OwnedSignal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic) enum AdmissionPhase {
    /// Original entry state after an actual owned first-user INT3.
    EntryReady,
    /// An exact original instruction-fetch fault on a gated page.
    Fetch,
    /// A declared and byte-authenticated source or generated guard INT3.
    Guard,
    /// A private stop after exact application-state restoration.
    Restored,
    /// An authenticated CPU SINGLESTEP trap after the original selected instruction.
    NativeCompleted,
}

/// Full native identity is retained alongside the public signal projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic) struct OwnedSignal {
    pub(in crate::linux::remote::dynamic) raw: [u8; 128],
    pub(in crate::linux::remote::dynamic) view: SignalStop,
}

/// Expectation supplied by the sealed admission dispatcher after source/plan
/// lookup. A matching address alone does not authorize this classification.
#[derive(Clone, Copy, Debug)]
pub(in crate::linux::remote::dynamic) enum TrapExpectation {
    Fetch { pc: u64, page: u64 },
    Guard { address: u64 },
}

/// Restored architectural and kernel state at one held task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic) struct TaskStateSnapshot {
    pub(in crate::linux::remote::dynamic) registers: RegisterSnapshot,
    pub(in crate::linux::remote::dynamic) xstate: Vec<u8>,
    pub(in crate::linux::remote::dynamic) mask: u64,
}
impl TaskStateSnapshot {
    pub(in crate::linux::remote::dynamic) fn read(tid: i32) -> Result<Self, LaunchError> {
        Ok(Self {
            registers: read_registers(tid)?,
            xstate: xstate(tid)?,
            mask: launch::task_mask(tid)?,
        })
    }
    pub(in crate::linux::remote::dynamic) fn restore(&self, tid: i32) -> Result<(), LaunchError> {
        restore_state(tid, &self.registers, &self.xstate)?;
        if launch::task_mask(tid)? != self.mask {
            ptrace(
                libc::PTRACE_SETSIGMASK,
                tid,
                8,
                (&raw const self.mask) as usize,
            )?;
        }
        if Self::read(tid)? != *self {
            return Err(LaunchError::Invalid("trusted state restoration differs"));
        }
        Ok(())
    }
}

/// An immutable private island belonging to exactly one retained mm generation.
/// Original executable VMAs are kept separately by the admission domain.
pub(in crate::linux::remote::dynamic) struct TrustedIsland {
    pub(in crate::linux::remote::dynamic) address_space: AddressSpaceId,
    pub(in crate::linux::remote::dynamic) generation: u64,
    pub(in crate::linux::remote::dynamic) range: Range<u64>,
    pub(in crate::linux::remote::dynamic) page_size: usize,
}
impl TrustedIsland {
    pub(in crate::linux::remote::dynamic) fn verify(
        &self,
        tid: i32,
    ) -> Result<Vec<MemoryMapping>, LaunchError> {
        let mappings = read_maps(tid)?;
        verify_island(tid, &mappings, &self.range)?;
        Ok(mappings)
    }
    pub(in crate::linux::remote::dynamic) fn trap(&self) -> u64 {
        self.range.start + 2
    }
}

pub(in crate::linux::remote::dynamic) fn authenticate_trap(
    owner: &Owner,
    tid: i32,
    status: i32,
    expectation: TrapExpectation,
) -> Result<(AdmissionPhase, [u8; 128], RegisterSnapshot), LaunchError> {
    if owner.stopped.get(&tid) != Some(&status)
        || !owner.owned.contains(&tid)
        || owner.handles.get(&tid).is_none_or(broker::hup)
        || !libc::WIFSTOPPED(status)
        || status >> 16 != 0
    {
        return Err(LaunchError::Invalid(
            "admission trap lacks current native ownership",
        ));
    }
    let mut raw = [0_u8; 128];
    ptrace(libc::PTRACE_GETSIGINFO, tid, 0, raw.as_mut_ptr() as usize)?;
    let signal = DynamicSignalInfo { raw };
    let registers = read_registers(tid)?;
    if registers.cs != 0x33 || signal.signal() != libc::WSTOPSIG(status) {
        return Err(LaunchError::Invalid("admission trap ABI or signal differs"));
    }
    let phase = match expectation {
        TrapExpectation::Fetch { pc, page } => {
            let size = page_size()? as u64;
            // SAFETY: GETSIGINFO initialized all native siginfo bytes.
            let info = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast::<libc::siginfo_t>()) };
            let address = unsafe { info.si_addr() } as usize as u64;
            if page % size != 0
                || pc / size != page / size
                || registers.rip != pc
                || signal.signal() != libc::SIGSEGV
                || signal.code() != 2
                || address != pc
                || !read_maps(tid)?.iter().any(|m| {
                    m.start <= page
                        && page.checked_add(size).is_some_and(|end| end <= m.end)
                        && m.permissions.as_bytes().get(2) == Some(&b'-')
                        && m.permissions.as_bytes().get(3) == Some(&b'p')
                })
            {
                return Err(LaunchError::Invalid(
                    "fetch trap does not match its gated original page",
                ));
            }
            AdmissionPhase::Fetch
        }
        TrapExpectation::Guard { address } => {
            if signal.signal() != libc::SIGTRAP
                || !matches!(signal.code(), libc::SI_KERNEL | libc::TRAP_BRKPT)
                || address.checked_add(1) != Some(registers.rip)
                || read_memory(tid, address, 1)? != [0xcc]
            {
                return Err(LaunchError::Invalid(
                    "guard trap does not match its owned source",
                ));
            }
            AdmissionPhase::Guard
        }
    };
    Ok((phase, raw, registers))
}

/// Perform one checked private sequence. The caller has borrowed complete mm
/// exclusion and authenticated this exact code image. No application signal
/// stop or syscall-entry stop is accepted as an injection phase.
pub(in crate::linux::remote::dynamic) fn execute(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    token: &AdmissionStop,
    image: (u64, &[u8]),
    registers: RegisterSnapshot,
    exact_result: bool,
    until: Instant,
) -> Result<(u64, AdmissionStop), LaunchError> {
    owner.time_left(until, "trusted admission execution")?;
    let (code, bytes) = image;
    native.require_admission_stop(token)?;
    let tid = token.token.tid;
    let saved = TaskStateSnapshot::read(tid)?;
    if read_memory(tid, code, bytes.len())? != bytes
        || bytes.last() != Some(&0xcc)
        || registers.rip != code
        || registers.cs != 0x33
        || registers.orig_rax != u64::MAX
        || registers.eflags & (0x100 | 0x10000 | 0x40000) != 0
    {
        return Err(LaunchError::Invalid(
            "trusted instruction setup is not exact",
        ));
    }
    // The caller settles deferred INTERRUPT requests with a neutral INT3 before
    // a syscall or store. No request can be issued concurrently on this thread.
    if bytes != [0xcc] && native.admission_interrupt_credit(tid)? != 0 {
        return Err(LaunchError::Invalid(
            "trusted mutation has unresolved interruption credit",
        ));
    }
    let result = (|| {
        set_registers(tid, &registers)?;
        if read_registers(tid)? != registers
            || xstate(tid)? != saved.xstate
            || launch::task_mask(tid)? != saved.mask
        {
            return Err(LaunchError::Invalid(
                "trusted setup changed unrelated state",
            ));
        }
        let mut current = token.clone();
        loop {
            owner.time_left(until, "trusted admission execution")?;
            native.begin_admission_execution(&current)?;
            ptrace(libc::PTRACE_CONT, tid, 0, 0)?;
            owner.released(tid);
            let (observed, status) = owner.wait_raw(until, "trusted admission trap")?;
            if observed != tid {
                return Err(LaunchError::Invalid(
                    "sibling event during trusted execution",
                ));
            }
            let had_credit = native.consume_admission_interrupt(tid)?;
            if bytes == [0xcc]
                && had_credit
                && libc::WIFSTOPPED(status)
                && libc::WSTOPSIG(status) == libc::SIGTRAP
                && status >> 16 == libc::PTRACE_EVENT_STOP
            {
                if TaskStateSnapshot::read(tid)?
                    != (TaskStateSnapshot {
                        registers,
                        xstate: saved.xstate.clone(),
                        mask: saved.mask,
                    })
                {
                    return Err(LaunchError::Invalid(
                        "neutral interruption changed private setup",
                    ));
                }
                current = native.finish_admission_execution(
                    tid,
                    registers.rip,
                    AdmissionPhase::Restored,
                )?;
                continue;
            }
            if !libc::WIFSTOPPED(status)
                || libc::WSTOPSIG(status) != libc::SIGTRAP
                || status >> 16 != 0
            {
                return Err(LaunchError::Invalid(
                    "trusted execution reached an unexpected event",
                ));
            }
            let info = siginfo(tid)?;
            let observed = read_registers(tid)?;
            let mut expected = registers;
            expected.rip = code
                .checked_add(bytes.len() as u64)
                .ok_or(LaunchError::Invalid("trusted trap address overflow"))?;
            if !exact_result {
                if bytes != STUB {
                    return Err(LaunchError::Invalid(
                        "non-exact trusted result is not a syscall",
                    ));
                }
                expected.rax = observed.rax;
                expected.rcx = code + 2;
                expected.r11 = registers.eflags;
            }
            if info.si_signo != libc::SIGTRAP
                || !matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT)
                || observed.rip != expected.rip
                || observed != expected
                || read_memory(tid, code, bytes.len())? != bytes
                || launch::task_mask(tid)? != saved.mask
            {
                return Err(LaunchError::Invalid(
                    "trusted completion identity or state differs",
                ));
            }
            let value = observed.rax;
            saved.restore(tid)?;
            let restored = native.finish_admission_execution(
                tid,
                saved.registers.rip,
                AdmissionPhase::Restored,
            )?;
            return Ok((value, restored));
        }
    })();
    if result.is_err() {
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
        // Do not resume from an unexpected signal or repair an unowned running
        // state. Original ownership, pins and all observed statuses remain in
        // Owner for its existing physical/background cleanup path.
    }
    result
}

/// Exact application state transformation certified by the admission frontend.
/// The implementation below authenticates its before-state, native ownership,
/// and preservation; it does not infer selected-instruction semantics.
pub(in crate::linux::remote::dynamic) struct StateTransform<'a> {
    pub(in crate::linux::remote::dynamic) before: &'a RegisterSnapshot,
    pub(in crate::linux::remote::dynamic) after: &'a RegisterSnapshot,
    pub(in crate::linux::remote::dynamic) before_xstate: &'a [u8],
    pub(in crate::linux::remote::dynamic) before_mask: u64,
}

/// Apply a proved scripted result (or exact owned-guard RIP normalization), then
/// establish its continuation at a real neutral INT3. The semantic result is
/// supplied by the typed frontend; this is never reported as native execution of
/// the replaced original instruction.
///
/// # Safety
/// The original-release interlock remains closed and current source/page facts
/// and all retained continuations were authenticated under the real whole-mm
/// hold. `after` is exactly the typed SelectedInput completion of `before`, or
/// differs only by a proved owned source-guard RIP-to-head normalization. No
/// other arbitrary application-state edit is authorized. The frontend consumes
/// its pending semantic invocation before invoking this operation.
pub(in crate::linux::remote::dynamic) unsafe fn apply_scripted_completion(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    island: &TrustedIsland,
    current: &AdmissionStop,
    transform: StateTransform<'_>,
    until: Instant,
) -> Result<AdmissionStop, LaunchError> {
    owner.time_left(until, "scripted admission completion")?;
    native.require_admission_stop(current)?;
    let id = current.identity.task;
    let membership = native.check_admission_mm(owner, id)?;
    if membership.address_space != island.address_space
        || membership.generation != island.generation
    {
        return Err(LaunchError::Invalid(
            "scripted completion island identity differs",
        ));
    }
    island.verify(current.token.tid)?;
    if transform.before_xstate.len() > MAX_XSTATE {
        return Err(LaunchError::Invalid(
            "scripted completion XSTATE exceeds bound",
        ));
    }
    let before = TaskStateSnapshot {
        registers: *transform.before,
        xstate: transform.before_xstate.to_vec(),
        mask: transform.before_mask,
    };
    if transform.after.cs != 0x33
        || transform.before.cs != 0x33
        || TaskStateSnapshot::read(current.token.tid)? != before
    {
        return Err(LaunchError::Invalid(
            "scripted completion before-state differs",
        ));
    }
    let mut siblings = Vec::new();
    for &task in &membership.candidate.tasks {
        if task != id {
            let held = native.admission_held_token(task)?;
            siblings.push((task, held.clone(), TaskStateSnapshot::read(held.tid)?));
        }
    }
    let after = TaskStateSnapshot {
        registers: *transform.after,
        xstate: before.xstate,
        mask: before.mask,
    };
    let result = (|| {
        owner.time_left(until, "scripted admission completion")?;
        set_registers(current.token.tid, &after.registers)?;
        if TaskStateSnapshot::read(current.token.tid)? != after {
            return Err(LaunchError::Invalid("scripted state installation differs"));
        }
        let injected = temporary(&after.registers, island.trap());
        let (_, stop) = execute(
            owner,
            native,
            current,
            (island.trap(), &[0xcc]),
            injected,
            true,
            until,
        )?;
        if TaskStateSnapshot::read(current.token.tid)? != after {
            return Err(LaunchError::Invalid("scripted state restoration differs"));
        }
        let resulting = native.check_admission_mm(owner, id)?;
        if resulting.address_space != membership.address_space
            || resulting.generation != membership.generation
            || resulting.process != membership.process
            || resulting.tgid != membership.tgid
            || resulting.tids != membership.tids
            || resulting.candidate.tasks != membership.candidate.tasks
            || resulting.candidate.obligations != membership.candidate.obligations
        {
            return Err(LaunchError::Invalid(
                "scripted completion changed mm membership or obligations",
            ));
        }
        for (task, held, state) in &siblings {
            if native.admission_held_token(*task)? != *held
                || TaskStateSnapshot::read(held.tid)? != *state
            {
                return Err(LaunchError::Invalid(
                    "scripted completion changed a held sibling",
                ));
            }
        }
        island.verify(current.token.tid)?;
        Ok(stop)
    })();
    if result.is_err() {
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
    }
    result
}

/// Materialize a completed kernel return at an actual neutral user trap.
/// This accepts only the existing authenticated actual EXIT or distinct
/// newborn-return-ready phase. It never invents a child syscall EXIT, and does
/// not use an application signal/control stop as injection authority.
///
/// Unlike singleton initial exec bootstrap, a later return must preserve the
/// entire already established XSTATE image. An unsupported inheritance or
/// deferred-return difference refuses before any original instruction executes.
pub(in crate::linux::remote::dynamic) fn return_bridge(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    island: &TrustedIsland,
    token: &DynamicStop,
    until: Instant,
) -> Result<AdmissionStop, LaunchError> {
    owner.time_left(until, "admission return bridge")?;
    let id = token
        .task
        .ok_or(LaunchError::Invalid("return bridge lacks task identity"))?;
    let membership = native.check_admission_mm(owner, id)?;
    if membership.address_space != island.address_space
        || membership.generation != island.generation
        || native.admission_held_token(id)? != *token
    {
        return Err(LaunchError::Invalid(
            "return bridge identity is stale or foreign",
        ));
    }
    island.verify(token.tid)?;
    let mut siblings = Vec::new();
    for &task in &membership.candidate.tasks {
        if task != id {
            let held = native.admission_held_token(task)?;
            siblings.push((task, held.clone(), TaskStateSnapshot::read(held.tid)?));
        }
    }
    let saved = TaskStateSnapshot::read(token.tid)?;
    if saved.registers.cs != 0x33 {
        return Err(LaunchError::Invalid(
            "return bridge requires native x86-64 state",
        ));
    }
    let injected = temporary(&saved.registers, island.trap());
    let result = (|| {
        // Authenticate the real EXIT info before register injection can change
        // its instruction pointer or kernel syscall bookkeeping.
        native.begin_admission_return_bridge(token)?;
        set_registers(token.tid, &injected)?;
        let setup = TaskStateSnapshot {
            registers: injected,
            xstate: saved.xstate.clone(),
            mask: saved.mask,
        };
        if TaskStateSnapshot::read(token.tid)? != setup {
            return Err(LaunchError::Invalid(
                "return bridge setup changed unrelated state",
            ));
        }
        loop {
            owner.time_left(until, "admission return bridge")?;
            ptrace(libc::PTRACE_CONT, token.tid, 0, 0)?;
            owner.released(token.tid);
            let (tid, status) = owner.wait_raw(until, "admission return bridge")?;
            if tid != token.tid {
                return Err(LaunchError::Invalid("sibling event during return bridge"));
            }
            let had_credit = native.consume_admission_interrupt(tid)?;
            if had_credit
                && libc::WIFSTOPPED(status)
                && libc::WSTOPSIG(status) == libc::SIGTRAP
                && status >> 16 == libc::PTRACE_EVENT_STOP
            {
                if TaskStateSnapshot::read(tid)? != setup {
                    return Err(LaunchError::Invalid(
                        "return bridge interruption changed setup",
                    ));
                }
                let current = native.finish_admission_execution(
                    tid,
                    injected.rip,
                    AdmissionPhase::Restored,
                )?;
                native.begin_admission_execution(&current)?;
                continue;
            }
            if !libc::WIFSTOPPED(status)
                || libc::WSTOPSIG(status) != libc::SIGTRAP
                || status >> 16 != 0
            {
                return Err(LaunchError::Invalid(
                    "return bridge reached an unexpected event",
                ));
            }
            let signal = siginfo(tid)?;
            let mut expected = setup.clone();
            expected.registers.rip = island
                .trap()
                .checked_add(1)
                .ok_or(LaunchError::Invalid("return bridge trap overflow"))?;
            if signal.si_signo != libc::SIGTRAP
                || !matches!(signal.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT)
                || TaskStateSnapshot::read(tid)? != expected
                || read_memory(tid, island.trap(), 1)? != [0xcc]
            {
                return Err(LaunchError::Invalid(
                    "return bridge trap or full state differs",
                ));
            }
            saved.restore(tid)?;
            let current = native.finish_admission_execution(
                tid,
                saved.registers.rip,
                AdmissionPhase::Restored,
            )?;
            let after = native.check_admission_mm(owner, id)?;
            if after.address_space != membership.address_space
                || after.generation != membership.generation
                || after.process != membership.process
                || after.tgid != membership.tgid
                || after.tids != membership.tids
                || after.candidate.tasks != membership.candidate.tasks
                || after.candidate.obligations != membership.candidate.obligations
            {
                return Err(LaunchError::Invalid(
                    "return bridge changed mm membership or obligations",
                ));
            }
            for (task, held, state) in &siblings {
                if native.admission_held_token(*task)? != *held
                    || TaskStateSnapshot::read(held.tid)? != *state
                {
                    return Err(LaunchError::Invalid("return bridge changed a held sibling"));
                }
            }
            island.verify(tid)?;
            return Ok(current);
        }
    })();
    if result.is_err() {
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
    }
    result
}

pub(in crate::linux::remote::dynamic) fn temporary(
    saved: &RegisterSnapshot,
    pc: u64,
) -> RegisterSnapshot {
    let mut registers = *saved;
    registers.rip = pc;
    registers.orig_rax = u64::MAX;
    registers.eflags &= !(0x100 | 0x10000 | 0x40000);
    registers
}
