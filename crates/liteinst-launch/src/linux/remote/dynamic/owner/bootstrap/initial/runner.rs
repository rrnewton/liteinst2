//! Fresh singleton private SYSCALL/INT3 runner, retaining the exact generic
//! trusted::execute predicates. No neutral-interrupt loop or ordinary release.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Site<'a> {
    pub(super) root: TaskId,
    pub(super) pc: u64,
    pub(super) island: Option<&'a TrustedIsland>,
}
pub(super) fn ready(
    owner: &Owner,
    native: &lifecycle::NativeLifecycle,
    p: &mut PreparedInitialBootstrap,
    stop: &AdmissionStop,
    island: Option<&TrustedIsland>,
) -> Result<(), LaunchError> {
    native.require_initial_source_mm(owner, stop, p.until, p.membership.as_mut_slice())?;
    if native.admission_interrupt_credit(owner.pid)? != 0 {
        return Err(LaunchError::Invalid(
            "trusted mutation has unresolved interruption credit",
        ));
    }
    if let Some(island) = island {
        if stop.identity.address_space != island.address_space
            || stop.identity.generation != island.generation
            || island.page_size != PAGE
        {
            return Err(LaunchError::Invalid(
                "island belongs to another mm incarnation",
            ));
        }
        p.current_maps.capture(owner, p.until)?;
        if !parse(p.current_maps.bytes())?.entries().any(|row| {
            row.start <= island.range.start
                && island.range.end <= row.end
                && row.permissions.bytes() == *b"r-xp"
                && row.pathname.is_none()
        }) {
            return Err(LaunchError::Invalid(
                "immutable RX syscall island did not verify",
            ));
        }
        io::verify_memory(
            owner,
            island.range.start,
            &island_code_fixed(),
            &mut p.peek,
            p.until,
        )?;
    }
    physical(owner, p.until)
}
pub(super) fn call(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    p: &mut PreparedInitialBootstrap,
    site: Site<'_>,
    number: libc::c_long,
    arguments: [u64; 6],
) -> Result<u64, LaunchError> {
    let stop = native.admission_current(site.root)?;
    ready(owner, native, p, &stop, site.island)?;
    p.states[SAVED].capture(owner, p.until)?;
    let mut registers = trusted::temporary(&p.states[SAVED].state.registers, site.pc);
    registers.rax = number as u64;
    registers.rdi = arguments[0];
    registers.rsi = arguments[1];
    registers.rdx = arguments[2];
    registers.r10 = arguments[3];
    registers.r8 = arguments[4];
    registers.r9 = arguments[5];
    io::verify_memory(owner, site.pc, &STUB, &mut p.peek, p.until)?;
    if registers.rip != site.pc
        || registers.cs != 0x33
        || registers.orig_rax != u64::MAX
        || registers.eflags & (0x100 | 0x10000 | 0x40000) != 0
        || STUB.last() != Some(&0xcc)
    {
        return Err(LaunchError::Invalid(
            "trusted instruction setup is not exact",
        ));
    }
    owner.time_left(p.until, "trusted admission execution")?;
    set_registers(owner.pid, &registers)?;
    p.states[READBACK].capture(owner, p.until)?;
    if p.states[READBACK].state.registers != registers
        || p.states[READBACK].state.xstate != p.states[SAVED].state.xstate
        || p.states[READBACK].state.mask != p.states[SAVED].state.mask
    {
        return Err(LaunchError::Invalid(
            "trusted setup changed unrelated state",
        ));
    }
    native.require_admission_stop(&stop)?;
    owner.time_left(p.until, "trusted admission execution")?;
    native.begin_admission_execution(&stop)?;
    owner.time_left(p.until, "trusted admission release")?;
    ptrace(libc::PTRACE_CONT, owner.pid, 0, 0)?;
    owner.released(owner.pid);
    let (tid, status) = owner.wait_raw(p.until, "trusted admission trap")?;
    p.progress.retain_wait(WaitCapture::Runner, tid, status);
    raw_held(owner, tid, status, p.until)?;
    p.progress.runner_queries_started = true;
    let info_result = p.runner_signal.capture(tid);
    let state_result = p.states[READBACK].capture_tid(tid);
    info_result?;
    state_result?;
    owner.time_left(p.until, "trusted admission trap")?;
    if tid != owner.pid {
        return Err(LaunchError::Invalid(
            "sibling event during trusted execution",
        ));
    }
    if native.consume_admission_interrupt(tid)? {
        return Err(LaunchError::Invalid(
            "initial bootstrap received interruption credit",
        ));
    }
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP || status >> 16 != 0 {
        owner.discover_event_child(tid, status);
        return Err(LaunchError::Invalid(
            "trusted execution reached an unexpected event",
        ));
    }
    p.runner_signal.validate()?;
    let observed = p.states[READBACK].state.registers;
    let mut expected = registers;
    expected.rip = site
        .pc
        .checked_add(STUB.len() as u64)
        .ok_or(LaunchError::Invalid("trusted trap address overflow"))?;
    expected.rax = observed.rax;
    expected.rcx = site.pc + 2;
    expected.r11 = registers.eflags;
    if observed != expected || p.states[READBACK].state.mask != p.states[SAVED].state.mask {
        return Err(LaunchError::Invalid(
            "trusted completion identity or state differs",
        ));
    }
    io::verify_memory(owner, site.pc, &STUB, &mut p.peek, p.until)?;
    {
        let (saved, actual) = p.states.split_at_mut(READBACK);
        io::restore(owner, &saved[SAVED], &mut actual[0], p.until)?;
    }
    let restored = native.finish_admission_execution(
        tid,
        p.states[SAVED].state.registers.rip,
        AdmissionPhase::Restored,
    )?;
    ready(owner, native, p, &restored, site.island)?;
    Ok(observed.rax)
}

pub(super) fn private_range(
    raw: &[u8],
    island: &Range<u64>,
    address: u64,
    length: usize,
    expected: Option<i32>,
) -> Result<(), LaunchError> {
    let end = address
        .checked_add(length as u64)
        .ok_or(LaunchError::Invalid("publication range overflow"))?;
    if length == 0 || address < island.end && island.start < end {
        return Err(LaunchError::Invalid(
            "publication range overlaps private island",
        ));
    }
    let mut cursor = address;
    for row in parse(raw)?.entries() {
        if row.end <= cursor || row.start >= end {
            continue;
        }
        if row.start > cursor || row.permissions.bytes()[3] != b'p' {
            return Err(LaunchError::Invalid(
                "publication range is not continuously private",
            ));
        }
        if expected.is_some_and(|expected| protection(row) != expected) {
            return Err(LaunchError::Invalid("admission permissions did not verify"));
        }
        cursor = row.end.min(end);
    }
    if cursor != end {
        return Err(LaunchError::Invalid(
            "publication range is not continuously private",
        ));
    }
    Ok(())
}
fn protection(row: MapEntry<'_>) -> i32 {
    let bytes = row.permissions.bytes();
    (if bytes[0] == b'r' { libc::PROT_READ } else { 0 })
        | (if bytes[1] == b'w' {
            libc::PROT_WRITE
        } else {
            0
        })
        | (if bytes[2] == b'x' { libc::PROT_EXEC } else { 0 })
}
pub(super) fn protect(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    p: &mut PreparedInitialBootstrap,
    site: Site<'_>,
    range: Range<u64>,
    protection: i32,
) -> Result<(), LaunchError> {
    let island = site
        .island
        .ok_or(LaunchError::Invalid("initial quarantine lacks island"))?;
    let length = usize::try_from(
        range
            .end
            .checked_sub(range.start)
            .ok_or(LaunchError::Invalid("invalid permission range"))?,
    )
    .map_err(|_| LaunchError::Invalid("invalid permission range"))?;
    let stop = native.admission_current(site.root)?;
    ready(owner, native, p, &stop, Some(island))?;
    if length == 0
        || range.start % PAGE as u64 != 0
        || length % PAGE != 0
        || protection & !(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0
        || protection & (libc::PROT_WRITE | libc::PROT_EXEC) == (libc::PROT_WRITE | libc::PROT_EXEC)
    {
        return Err(LaunchError::Invalid(
            "invalid permission range or RWX protection",
        ));
    }
    private_range(
        p.current_maps.bytes(),
        &island.range,
        range.start,
        length,
        None,
    )?;
    syscall_result(
        call(
            owner,
            native,
            p,
            site,
            libc::SYS_mprotect,
            [range.start, length as u64, protection as u64, 0, 0, 0],
        )?,
        "admission mprotect",
    )?;
    private_range(
        p.current_maps.bytes(),
        &island.range,
        range.start,
        length,
        Some(protection),
    )
}
