//! Initial-only bounded bootstrap. Storage is reserved before effects; the
//! actual existing native lifecycle remains the only registry authority.
use super::super::admission::{MapEntry, ParsedMaps};
use super::*;
use std::mem::size_of;

mod io;
mod runner;
mod storage;
#[cfg(test)]
mod tests;

use io::SyscallObservation;
pub(in crate::linux::remote::dynamic::owner) use io::{
    MapBuffer, MemoryObservation, Request, SignalObservation, StateSlot, verify_memory,
};
pub(in crate::linux::remote::dynamic::owner) use storage::{
    InitialBootstrapShape, PreparedInitialBootstrap,
};
use storage::{descriptor_matches, fixed_buffer};

const PAGE: usize = 4096;
const MAP_BYTES: usize = 64 * 1024;
const MAP_ROWS: usize = 512;
const EFFECTS: usize = 78; // original EXEC resume + 13 fixed + <=64 quarantines
const EXEC: usize = 0;
const EXIT: usize = 1;
const ENTRY: usize = 2;
const RESTORED: usize = 3;
const SAVED: usize = 4;
const READBACK: usize = 5;

fn parse(bytes: &[u8]) -> Result<ParsedMaps<'_>, LaunchError> {
    if bytes.len() > MAP_BYTES {
        return Err(LaunchError::Invalid(
            "initial bootstrap maps exceed fixed bound",
        ));
    }
    ParsedMaps::parse(bytes, MAP_ROWS)
        .map_err(|_| LaunchError::Invalid("initial bootstrap maps are malformed"))
}
fn executable(row: MapEntry<'_>) -> bool {
    row.permissions.bytes()[2] == b'x' && row.pathname != Some(b"[vsyscall]".as_slice())
}
pub(in crate::linux::remote::dynamic::owner) fn island_code_fixed() -> [u8; 68] {
    let mut bytes = [0xcc; 68];
    bytes[..STUB.len()].copy_from_slice(&STUB);
    for (offset, stub) in STORE_STUBS {
        bytes[offset..offset + stub.len()].copy_from_slice(stub);
    }
    bytes
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum InitialBootstrapPhase {
    #[default]
    Allocated,
    OriginalExec,
    ActualExit,
    FirstUser,
    Restored,
    Quarantine,
    Complete,
    // Data-only movement control; runtime retains completed bootstrap in place.
    #[cfg(test)]
    Transferred,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum InitialBootstrapEffect {
    OriginalExecResume,
    Bootstrap(BootstrapEffect),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct InitialBootstrapEffectRecord {
    pub(in crate::linux::remote::dynamic::owner) effect: InitialBootstrapEffect,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
    pub(in crate::linux::remote::dynamic::owner) result: Option<u64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum InitialBootstrapFailureKind {
    Invalid(&'static str),
    System(&'static str, Option<i32>),
    Timeout(&'static str),
    Child(i32),
    Unwound,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct InitialBootstrapFailure {
    pub(in crate::linux::remote::dynamic::owner) phase: InitialBootstrapPhase,
    pub(in crate::linux::remote::dynamic::owner) effect: Option<InitialBootstrapEffect>,
    pub(in crate::linux::remote::dynamic::owner) kind: InitialBootstrapFailureKind,
}
#[derive(Debug)]
pub(in crate::linux::remote::dynamic::owner) struct InitialBootstrapProgress {
    pub(in crate::linux::remote::dynamic::owner) phase: InitialBootstrapPhase,
    pub(in crate::linux::remote::dynamic::owner) first_failure: Option<InitialBootstrapFailure>,
    pub(in crate::linux::remote::dynamic::owner) exec_wait: Option<(i32, i32)>,
    pub(in crate::linux::remote::dynamic::owner) first_user_wait: Option<(i32, i32)>,
    pub(in crate::linux::remote::dynamic::owner) runner_wait: Option<(i32, i32)>,
    pub(in crate::linux::remote::dynamic::owner) exec_queries_started: bool,
    pub(in crate::linux::remote::dynamic::owner) first_user_queries_started: bool,
    pub(in crate::linux::remote::dynamic::owner) runner_queries_started: bool,
    effects: [Option<InitialBootstrapEffectRecord>; EFFECTS],
    length: usize,
}
impl Default for InitialBootstrapProgress {
    fn default() -> Self {
        Self {
            phase: InitialBootstrapPhase::Allocated,
            first_failure: None,
            exec_wait: None,
            first_user_wait: None,
            runner_wait: None,
            exec_queries_started: false,
            first_user_queries_started: false,
            runner_queries_started: false,
            effects: [None; EFFECTS],
            length: 0,
        }
    }
}
#[derive(Clone, Copy)]
enum WaitCapture {
    ExecExit,
    FirstUser,
    Runner,
}
impl InitialBootstrapProgress {
    fn retain_wait(&mut self, capture: WaitCapture, tid: i32, status: i32) {
        // Reusable native buffers remain historical until a new held-stop
        // proof permits another read group. Never clear a retained prefix.
        match capture {
            WaitCapture::ExecExit => {
                self.exec_wait = Some((tid, status));
                self.exec_queries_started = false;
            }
            WaitCapture::FirstUser => {
                self.first_user_wait = Some((tid, status));
                self.first_user_queries_started = false;
            }
            WaitCapture::Runner => {
                self.runner_wait = Some((tid, status));
                self.runner_queries_started = false;
            }
        }
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner) fn effects(
        &self,
    ) -> &[Option<InitialBootstrapEffectRecord>] {
        &self.effects[..self.length]
    }
    fn begin(&mut self, effect: InitialBootstrapEffect) -> Result<(), LaunchError> {
        if self.first_failure.is_some()
            || self.length == EFFECTS
            || self
                .length
                .checked_sub(1)
                .and_then(|index| self.effects[index])
                .is_some_and(|record| !record.complete)
        {
            return Err(LaunchError::Invalid(
                "initial bootstrap effect storage or ordering differs",
            ));
        }
        self.effects[self.length] = Some(InitialBootstrapEffectRecord {
            effect,
            complete: false,
            result: None,
        });
        self.length += 1;
        Ok(())
    }
    fn finish(
        &mut self,
        effect: InitialBootstrapEffect,
        result: Option<u64>,
    ) -> Result<(), LaunchError> {
        let record = self
            .length
            .checked_sub(1)
            .and_then(|index| self.effects[index].as_mut())
            .ok_or(LaunchError::Invalid(
                "initial bootstrap effect was not attempted",
            ))?;
        if self.first_failure.is_some() || record.effect != effect || record.complete {
            return Err(LaunchError::Invalid(
                "initial bootstrap effect completion differs",
            ));
        }
        record.complete = true;
        record.result = result;
        Ok(())
    }
    fn fail(&mut self, error: Option<&LaunchError>) {
        if self.first_failure.is_some() {
            return;
        }
        let kind = match error {
            Some(LaunchError::Invalid(reason)) => InitialBootstrapFailureKind::Invalid(reason),
            Some(LaunchError::System { operation, source }) => {
                InitialBootstrapFailureKind::System(operation, source.raw_os_error())
            }
            Some(LaunchError::Timeout(operation)) => {
                InitialBootstrapFailureKind::Timeout(operation)
            }
            Some(LaunchError::Child { status }) => InitialBootstrapFailureKind::Child(*status),
            None => InitialBootstrapFailureKind::Unwound,
        };
        self.first_failure = Some(InitialBootstrapFailure {
            phase: self.phase,
            effect: self
                .length
                .checked_sub(1)
                .and_then(|index| self.effects[index])
                .map(|record| record.effect),
            kind,
        });
    }
}

/// Borrowed diagnostic substrates only. Successful state buffers move into
/// completed().evidence; the per-query outcome slots remain here. Neither
/// view can mutate or release the native owner.
#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner) struct InitialBootstrapDiagnostics<'a> {
    pub(in crate::linux::remote::dynamic::owner) states: &'a [StateSlot; 6],
    pub(in crate::linux::remote::dynamic::owner) exit_maps: &'a MapBuffer,
    pub(in crate::linux::remote::dynamic::owner) current_maps: &'a MapBuffer,
}

impl Owner {
    /// # Safety
    /// The runtime frontend supplies the same original-image ownership,
    /// no-external-writer and no-code-as-data contract as bootstrap_admission.
    /// The caller retains prepared and original capture through all failures.
    pub(in crate::linux::remote::dynamic::owner) unsafe fn bootstrap_initial_runtime(
        &mut self,
        initial: &DynamicStop,
        original_raw: &[u8],
        prepared: &mut PreparedInitialBootstrap,
    ) -> Result<(), LaunchError> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            begin(self, initial, original_raw, prepared)?;
            // syscall_event has already installed the actual EXIT lifecycle.
            let mut native = self.lifecycle.take().ok_or(LaunchError::Invalid(
                "initial bootstrap lacks actual EXIT lifecycle",
            ))?;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                finish(self, &mut native, original_raw, prepared)
            }));
            // No fallible hook or allocation occurs before custody is restored.
            self.lifecycle = Some(native);
            match result {
                Ok(result) => result,
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }));
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                prepared.progress.fail(Some(&error));
                self.closing = true;
                self.cancel.store(true, Ordering::Release);
                Err(error)
            }
            Err(payload) => {
                prepared.progress.fail(None);
                self.closing = true;
                self.cancel.store(true, Ordering::Release);
                std::panic::resume_unwind(payload)
            }
        }
    }
}

pub(in crate::linux::remote::dynamic::owner) fn physical(
    owner: &Owner,
    until: Instant,
) -> Result<(), LaunchError> {
    owner.time_left(until, "initial bootstrap physical ownership")?;
    if owner.owned.len() != 1
        || !owner.owned.contains(&owner.pid)
        || owner.pin_kinds.get(&owner.pid) != Some(&PinKind::Process)
        || owner.handles.get(&owner.pid).is_none_or(broker::hup)
        || owner
            .stopped
            .get(&owner.pid)
            .is_none_or(|status| !libc::WIFSTOPPED(*status))
        || owner.reaped.contains(&owner.pid)
        || owner.tracer_terminal.contains_key(&owner.pid)
        || owner.lost_wait
        || owner.missing_pin
    {
        return Err(LaunchError::Invalid(
            "initial bootstrap physical ownership differs",
        ));
    }
    Ok(())
}
/// A consumed terminal wait retires numeric authority in Owner::terminal.
/// Retain that wait, but never query it. Unexpected genuinely held stops may
/// still produce independent diagnostics before their phase is refused.
pub(in crate::linux::remote::dynamic::owner) fn raw_held(
    owner: &mut Owner,
    tid: i32,
    status: i32,
    until: Instant,
) -> Result<(), LaunchError> {
    owner.time_left(until, "initial bootstrap raw stop custody")?;
    let held = RawHeldFacts {
        stopped: libc::WIFSTOPPED(status),
        owned: owner.owned.contains(&tid),
        exact_status: owner.stopped.get(&tid) == Some(&status),
        live_pin: owner.handles.get(&tid).is_some_and(|pin| !broker::hup(pin)),
        retired: owner.reaped.contains(&tid) || owner.tracer_terminal.contains_key(&tid),
        lost_custody: owner.lost_wait || owner.missing_pin,
    };
    require_raw_held(held)?;
    // Event-message reads use the same authenticated live stopped parent.
    // Register any discovered child before later query/phase failures.
    owner.discover_event_child(tid, status);
    Ok(())
}
#[derive(Clone, Copy)]
struct RawHeldFacts {
    stopped: bool,
    owned: bool,
    exact_status: bool,
    live_pin: bool,
    retired: bool,
    lost_custody: bool,
}
fn require_raw_held(facts: RawHeldFacts) -> Result<(), LaunchError> {
    if !facts.stopped
        || !facts.owned
        || !facts.exact_status
        || !facts.live_pin
        || facts.retired
        || facts.lost_custody
    {
        return Err(LaunchError::Invalid(
            "initial bootstrap raw wait lacks pinned held custody",
        ));
    }
    Ok(())
}

fn original(
    owner: &Owner,
    initial: &DynamicStop,
    prepared: &mut PreparedInitialBootstrap,
) -> Result<(), LaunchError> {
    physical(owner, prepared.until)?;
    let event = owner.require_stop(initial)?;
    if !matches!(event.kind, DynamicEventKind::Exec { .. })
        || initial.session != owner.session
        || initial.tid != owner.pid
        || owner.lifecycle.is_some()
        || owner.lifecycle_options != Some(DynamicLifecycleOptions::default())
        || owner.exec_policy != DynamicExecPolicy::Refuse
        || owner.anchor_receipt.is_some()
        || owner.signal_journal.is_some()
        || owner.interrupt_stops_remaining != 0
    {
        return Err(LaunchError::Invalid(
            "initial runtime bootstrap requires original singleton EXEC",
        ));
    }
    admission::require_initial_task_identity(
        owner,
        prepared.until,
        prepared.membership.as_mut_slice(),
    )?;
    owner.require_stop(initial)?;
    physical(owner, prepared.until)
}
fn begin(
    owner: &mut Owner,
    initial: &DynamicStop,
    raw: &[u8],
    p: &mut PreparedInitialBootstrap,
) -> Result<(), LaunchError> {
    owner.time_left(p.until, "initial bootstrap preparation")?;
    p.validate_plan(raw)?;
    original(owner, initial, p)?;
    if page_size()? != PAGE {
        return Err(LaunchError::Invalid("admission requires 4096-byte pages"));
    }
    p.progress.phase = InitialBootstrapPhase::OriginalExec;
    p.states[EXEC].capture(owner, p.until)?;
    let registers = p.states[EXEC].state.registers;
    if owner.initial_exec != Some(registers)
        || registers.cs != 0x33
        || registers.orig_rax != libc::SYS_execve as u64
        || registers.rax != (-i64::from(libc::ENOSYS)) as u64
    {
        return Err(LaunchError::Invalid(
            "admission initial exec identity differs",
        ));
    }
    p.current_maps.capture(owner, p.until)?;
    if p.current_maps.bytes() != raw {
        return Err(LaunchError::Invalid(
            "initial bootstrap original raw maps changed",
        ));
    }
    original(owner, initial, p)?;
    let effect = InitialBootstrapEffect::OriginalExecResume;
    p.progress.begin(effect)?;
    owner.time_left(p.until, "initial bootstrap original EXEC release")?;
    owner.resume(initial, DynamicResume::Continue)?;
    p.progress.finish(effect, None)?;
    let (tid, status) = owner.wait_raw(p.until, "initial bootstrap actual exec EXIT")?;
    p.progress.retain_wait(WaitCapture::ExecExit, tid, status);
    raw_held(owner, tid, status, p.until)?;
    p.progress.exec_queries_started = true;
    // Independent initialized requests precede phase/event interpretation. A
    // failed syscall-info read cannot suppress the full state request.
    let info_result = p.syscall.capture(tid);
    let state_result = p.states[EXIT].capture_tid(tid);
    info_result?;
    state_result?;
    owner.time_left(p.until, "initial bootstrap actual exec EXIT")?;
    if tid != owner.pid
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != (libc::SIGTRAP | 0x80)
        || status >> 16 != 0
    {
        owner.discover_event_child(tid, status);
        return Err(LaunchError::Invalid(
            "admission did not reach actual exec EXIT",
        ));
    }
    p.syscall.validate_exit(&p.states[EXIT].state)?;
    let mut expected = p.states[EXEC].state.registers;
    expected.rax = 0;
    if p.states[EXIT].state.registers != expected
        || p.states[EXIT].state.xstate != p.states[EXEC].state.xstate
        || p.states[EXIT].state.mask != p.states[EXEC].state.mask
    {
        return Err(LaunchError::Invalid(
            "admission exec EXIT changed unrelated state",
        ));
    }
    let exit = owner.syscall_event()?; // actual existing native initialization
    if exit.tid != owner.pid
        || exit.kind
            != (DynamicEventKind::SyscallExit {
                result: 0,
                is_error: false,
            })
    {
        return Err(LaunchError::Invalid(
            "admission did not initialize actual exec EXIT",
        ));
    }
    p.exit_stop = Some(
        exit.stop_token()
            .ok_or(LaunchError::Invalid(
                "actual exec EXIT lacks its held token",
            ))?
            .clone(),
    );
    p.progress.phase = InitialBootstrapPhase::ActualExit;
    p.exit_maps.capture(owner, p.until)?;
    if p.exit_maps.bytes() != raw {
        return Err(LaunchError::Invalid(
            "bootstrap executable census changed after its resource reservation",
        ));
    }
    physical(owner, p.until)
}

fn before(
    owner: &Owner,
    p: &mut PreparedInitialBootstrap,
    effect: BootstrapEffect,
) -> Result<(), LaunchError> {
    owner.time_left(p.until, "initial bootstrap effect")?;
    p.progress
        .begin(InitialBootstrapEffect::Bootstrap(effect))?;
    owner.time_left(p.until, "initial bootstrap effect")
}
fn after(
    p: &mut PreparedInitialBootstrap,
    effect: BootstrapEffect,
    value: Option<u64>,
) -> Result<(), LaunchError> {
    p.progress
        .finish(InitialBootstrapEffect::Bootstrap(effect), value)
}

fn finish(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    original_raw: &[u8],
    p: &mut PreparedInitialBootstrap,
) -> Result<(), LaunchError> {
    let tid = owner.pid;
    let exit = p
        .exit_stop
        .as_ref()
        .ok_or(LaunchError::Invalid(
            "initial bootstrap lost actual EXIT token",
        ))?
        .clone();
    let pc = p.states[EXIT].state.registers.rip;
    let end = pc
        .checked_add(STUB.len() as u64)
        .ok_or(LaunchError::Invalid("bootstrap code overflow"))?;
    if !p
        .originals
        .iter()
        .any(|row| row.start <= pc && end <= row.end)
    {
        return Err(LaunchError::Invalid(
            "entry stub crosses executable mapping boundary",
        ));
    }
    p.envelope = pc & !7;
    let envelope_end = end
        .checked_add(7)
        .ok_or(LaunchError::Invalid("bootstrap envelope overflow"))?
        & !7;
    p.original_len = usize::try_from(envelope_end - p.envelope)
        .ok()
        .filter(|length| *length <= p.original_bytes.len())
        .ok_or(LaunchError::Invalid(
            "bootstrap envelope exceeds fixed storage",
        ))?;
    io::memory(
        owner,
        p.envelope,
        &mut p.original_bytes[..p.original_len],
        &mut p.peek,
        p.until,
    )?;
    before(owner, p, BootstrapEffect::PatchEntry)?;
    io::poke(owner, pc, &[0xcc], &mut p.peek, p.until)?;
    io::verify_memory(owner, pc, &[0xcc], &mut p.peek, p.until)?;
    after(p, BootstrapEffect::PatchEntry, None)?;
    before(owner, p, BootstrapEffect::FirstUserResume)?;
    if native.admission_interrupt_credit(tid)? != 0 {
        return Err(LaunchError::Invalid(
            "initial bootstrap has unresolved interruption credit",
        ));
    }
    native.begin_admission_return_bridge(&exit)?;
    owner.time_left(p.until, "initial bootstrap first-user release")?;
    ptrace(libc::PTRACE_CONT, tid, 0, 0)?;
    owner.released(tid);
    after(p, BootstrapEffect::FirstUserResume, None)?;
    let (observed, status) = owner.wait_raw(p.until, "admission first-user INT3")?;
    p.progress
        .retain_wait(WaitCapture::FirstUser, observed, status);
    raw_held(owner, observed, status, p.until)?;
    p.progress.first_user_queries_started = true;
    let signal_result = p.first_signal.capture(observed);
    let state_result = p.states[ENTRY].capture_tid(observed);
    signal_result?;
    state_result?;
    owner.time_left(p.until, "admission first-user INT3")?;
    if observed != tid
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || status >> 16 != 0
    {
        owner.discover_event_child(observed, status);
        return Err(LaunchError::Invalid(
            "admission entry reached an unexpected event",
        ));
    }
    if native.consume_admission_interrupt(tid)? {
        return Err(LaunchError::Invalid(
            "initial bootstrap received interruption credit",
        ));
    }
    p.first_signal.validate()?;
    let mut expected = p.states[EXIT].state.registers;
    expected.rip = pc
        .checked_add(1)
        .ok_or(LaunchError::Invalid("bootstrap entry overflow"))?;
    expected.orig_rax = u64::MAX;
    if p.states[ENTRY].state.registers != expected
        || p.states[ENTRY].state.mask != p.states[EXIT].state.mask
    {
        return Err(LaunchError::Invalid(
            "admission first-user state did not authenticate",
        ));
    }
    io::verify_memory(owner, pc, &[0xcc], &mut p.peek, p.until)?;
    p.progress.phase = InitialBootstrapPhase::FirstUser;
    before(owner, p, BootstrapEffect::RestoreEntry)?;
    io::poke(
        owner,
        p.envelope,
        &p.original_bytes[..p.original_len],
        &mut p.peek,
        p.until,
    )?;
    {
        let (observed, restored) = p.states.split_at_mut(RESTORED);
        restored[0].copy_from(&observed[ENTRY])?;
        restored[0].state.registers.rip = pc;
    }
    restore_original_state(owner, p)?;
    io::verify_memory(
        owner,
        p.envelope,
        &p.original_bytes[..p.original_len],
        &mut p.peek,
        p.until,
    )?;
    let entry = native.finish_admission_execution(tid, pc, AdmissionPhase::EntryReady)?;
    after(p, BootstrapEffect::RestoreEntry, None)?;
    p.progress.phase = InitialBootstrapPhase::Restored;
    let root = entry.identity.task;
    runner::ready(owner, native, p, &entry, None)?;
    before(owner, p, BootstrapEffect::WriteStub)?;
    io::poke(owner, pc, &STUB, &mut p.peek, p.until)?;
    io::verify_memory(owner, pc, &STUB, &mut p.peek, p.until)?;
    after(p, BootstrapEffect::WriteStub, None)?;
    let initial_site = runner::Site {
        root,
        pc,
        island: None,
    };
    before(owner, p, BootstrapEffect::MapIsland)?;
    let address = syscall_result(
        runner::call(
            owner,
            native,
            p,
            initial_site,
            libc::SYS_mmap,
            [
                0,
                PAGE as u64,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
        )?,
        "admission bootstrap mmap",
    )?;
    after(p, BootstrapEffect::MapIsland, Some(address))?;
    let island_end = address
        .checked_add(PAGE as u64)
        .ok_or(LaunchError::Invalid("island address overflow"))?;
    if address == 0
        || address % PAGE as u64 != 0
        || p.originals
            .iter()
            .any(|row| address < row.end && row.start < island_end)
    {
        return Err(LaunchError::Invalid(
            "bootstrap returned invalid island range",
        ));
    }
    let effect = BootstrapEffect::WriteIsland { address };
    before(owner, p, effect)?;
    io::poke(owner, address, &island_code_fixed(), &mut p.peek, p.until)?;
    after(p, effect, None)?;
    let effect = BootstrapEffect::ProtectIsland {
        address,
        length: PAGE,
    };
    before(owner, p, effect)?;
    syscall_result(
        runner::call(
            owner,
            native,
            p,
            initial_site,
            libc::SYS_mprotect,
            [
                address,
                PAGE as u64,
                (libc::PROT_READ | libc::PROT_EXEC) as u64,
                0,
                0,
                0,
            ],
        )?,
        "admission bootstrap RX",
    )?;
    after(p, effect, None)?;
    before(owner, p, BootstrapEffect::QueryMembarrier)?;
    let supported = syscall_result(
        runner::call(owner, native, p, initial_site, libc::SYS_membarrier, [0; 6])?,
        "admission membarrier query",
    )?;
    after(p, BootstrapEffect::QueryMembarrier, Some(supported))?;
    if supported & (SYNC_CORE | REGISTER_SYNC_CORE) != SYNC_CORE | REGISTER_SYNC_CORE {
        return Err(LaunchError::Invalid("admission target lacks sync-core"));
    }
    before(owner, p, BootstrapEffect::RegisterMembarrier)?;
    syscall_result(
        runner::call(
            owner,
            native,
            p,
            initial_site,
            libc::SYS_membarrier,
            [REGISTER_SYNC_CORE, 0, 0, 0, 0, 0],
        )?,
        "admission register sync-core",
    )?;
    after(p, BootstrapEffect::RegisterMembarrier, None)?;
    before(owner, p, BootstrapEffect::BootstrapSync)?;
    syscall_result(
        runner::call(
            owner,
            native,
            p,
            initial_site,
            libc::SYS_membarrier,
            [SYNC_CORE, 0, 0, 0, 0, 0],
        )?,
        "admission bootstrap sync-core",
    )?;
    after(p, BootstrapEffect::BootstrapSync, None)?;
    before(owner, p, BootstrapEffect::RestoreOriginal)?;
    io::poke(
        owner,
        p.envelope,
        &p.original_bytes[..p.original_len],
        &mut p.peek,
        p.until,
    )?;
    restore_original_state(owner, p)?;
    io::verify_memory(
        owner,
        p.envelope,
        &p.original_bytes[..p.original_len],
        &mut p.peek,
        p.until,
    )?;
    after(p, BootstrapEffect::RestoreOriginal, None)?;
    let island = TrustedIsland {
        address_space: entry.identity.address_space,
        generation: entry.identity.generation,
        range: address..island_end,
        page_size: PAGE,
    };
    let current = native.admission_current(root)?;
    runner::ready(owner, native, p, &current, Some(&island))?;
    let island_site = runner::Site {
        root,
        pc: address,
        island: Some(&island),
    };
    p.progress.phase = InitialBootstrapPhase::Quarantine;
    before(owner, p, BootstrapEffect::QuarantineSyncBefore)?;
    syscall_result(
        runner::call(
            owner,
            native,
            p,
            island_site,
            libc::SYS_membarrier,
            [SYNC_CORE, 0, 0, 0, 0, 0],
        )?,
        "admission sync-core",
    )?;
    after(p, BootstrapEffect::QuarantineSyncBefore, None)?;
    for index in 0..p.originals.len() {
        let row = &p.originals[index];
        let start = row.start;
        let end = row.end;
        let length = usize::try_from(end - start)
            .map_err(|_| LaunchError::Invalid("bootstrap permission length overflow"))?;
        let protection = super_protection(row)? & !libc::PROT_EXEC;
        let effect = BootstrapEffect::Quarantine { start, length };
        before(owner, p, effect)?;
        runner::protect(owner, native, p, island_site, start..end, protection)?;
        after(p, effect, None)?;
    }
    before(owner, p, BootstrapEffect::QuarantineSyncAfter)?;
    syscall_result(
        runner::call(
            owner,
            native,
            p,
            island_site,
            libc::SYS_membarrier,
            [SYNC_CORE, 0, 0, 0, 0, 0],
        )?,
        "admission sync-core",
    )?;
    after(p, BootstrapEffect::QuarantineSyncAfter, None)?;
    p.states[READBACK].capture(owner, p.until)?;
    if p.states[READBACK].state != p.states[RESTORED].state {
        return Err(LaunchError::Invalid(
            "initial NX gate changed original entry state",
        ));
    }
    io::verify_memory(
        owner,
        p.envelope,
        &p.original_bytes[..p.original_len],
        &mut p.peek,
        p.until,
    )?;
    let stop = native.admission_current(root)?;
    runner::ready(owner, native, p, &stop, Some(&island))?;
    final_inventory(original_raw, p.current_maps.bytes(), &island.range)?;
    install_descriptors(original_raw, p, &island)?;
    owner.time_left(p.until, "initial bootstrap completed evidence")?;
    if p.states[..4].iter().any(|state| !state.complete) || p.progress.first_failure.is_some() {
        return Err(LaunchError::Invalid(
            "initial bootstrap lacks complete state evidence",
        ));
    }
    // Everything below is infallible movement into retained prepared custody.
    // No post-effect allocation, native operation or callback intervenes.
    let evidence = BootstrapEvidence {
        exec_event: p.states[EXEC].move_state(),
        exec_exit: p.states[EXIT].move_state(),
        entry_trap: p.states[ENTRY].move_state(),
        restored_entry: p.states[RESTORED].move_state(),
    };
    p.ready = Some(BootstrapMm {
        island,
        stop,
        evidence,
        original_executables: std::mem::take(&mut p.originals),
        mappings: std::mem::take(&mut p.mappings),
    });
    p.progress.phase = InitialBootstrapPhase::Complete;
    Ok(())
}
fn restore_original_state(
    owner: &Owner,
    p: &mut PreparedInitialBootstrap,
) -> Result<(), LaunchError> {
    let (expected, actual) = p.states.split_at_mut(READBACK);
    io::restore(owner, &expected[RESTORED], &mut actual[0], p.until)
}
fn same_mapping(before: MapEntry<'_>, after: MapEntry<'_>, quarantine: bool) -> bool {
    let mut permissions = before.permissions.bytes();
    if quarantine && executable(before) {
        permissions[2] = b'-';
    }
    let executable_column = before
        .raw_line
        .iter()
        .position(|byte| *byte == b' ')
        .map(|index| index + 3);
    before.start == after.start
        && before.end == after.end
        && before.file_offset == after.file_offset
        && before.device_major == after.device_major
        && before.device_minor == after.device_minor
        && before.inode == after.inode
        && permissions == after.permissions.bytes()
        && before.pathname == after.pathname
        && before.pathname_column == after.pathname_column
        && before.raw_line.len() == after.raw_line.len()
        && before
            .raw_line
            .iter()
            .zip(after.raw_line)
            .enumerate()
            .all(|(index, (left, right))| {
                if quarantine && executable(before) && Some(index) == executable_column {
                    *left == b'x' && *right == b'-'
                } else {
                    left == right
                }
            })
}
fn final_inventory(
    original_raw: &[u8],
    current_raw: &[u8],
    island: &Range<u64>,
) -> Result<(), LaunchError> {
    let mut original = parse(original_raw)?.entries();
    let current = parse(current_raw)?;
    let mut island_seen = false;
    for row in current.entries() {
        if row.start == island.start && row.end == island.end {
            if island_seen
                || row.permissions.bytes() != *b"r-xp"
                || row.pathname.is_some()
                || row.file_offset != 0
                || row.inode != 0
                || row.device_major != 0
                || row.device_minor != 0
            {
                return Err(LaunchError::Invalid(
                    "initial bootstrap final island identity differs",
                ));
            }
            island_seen = true;
        } else {
            let old = original.next().ok_or(LaunchError::Invalid(
                "initial bootstrap final mapping was not original",
            ))?;
            if !same_mapping(old, row, true) {
                return Err(LaunchError::Invalid(
                    "initial bootstrap final mapping differs",
                ));
            }
        }
    }
    if !island_seen || original.next().is_some() {
        return Err(LaunchError::Invalid(
            "initial bootstrap final inventory differs",
        ));
    }
    Ok(())
}
fn install_descriptors(
    original_raw: &[u8],
    p: &mut PreparedInitialBootstrap,
    island: &TrustedIsland,
) -> Result<(), LaunchError> {
    if p.mappings.len() + 1 > p.mappings.capacity() {
        return Err(LaunchError::Invalid(
            "initial bootstrap final descriptor storage differs",
        ));
    }
    for (row, old) in p.mappings.iter_mut().zip(parse(original_raw)?.entries()) {
        if !descriptor_matches(row, old, false)? {
            return Err(LaunchError::Invalid(
                "initial bootstrap reserved descriptor changed",
            ));
        }
        if executable(old) {
            // Four bytes were reserved and initialized before effects.
            let mut permissions = old.permissions.bytes();
            permissions[2] = b'-';
            row.permissions.clear();
            row.permissions.push_str(
                std::str::from_utf8(&permissions)
                    .map_err(|_| LaunchError::Invalid("initial bootstrap permissions differ"))?,
            );
        }
    }
    let mut row = p.island_row.take().ok_or(LaunchError::Invalid(
        "initial bootstrap island descriptor was already used",
    ))?;
    row.start = island.range.start;
    row.end = island.range.end;
    p.mappings.push(row);
    p.mappings.sort_unstable_by_key(|row| row.start);
    let mut actual = parse(p.current_maps.bytes())?.entries();
    for row in &p.mappings {
        if !descriptor_matches(
            row,
            actual.next().ok_or(LaunchError::Invalid(
                "initial bootstrap final descriptor missing",
            ))?,
            false,
        )? {
            return Err(LaunchError::Invalid(
                "initial bootstrap final descriptor does not match observed maps",
            ));
        }
    }
    if actual.next().is_some() {
        return Err(LaunchError::Invalid(
            "initial bootstrap final descriptor count differs",
        ));
    }
    Ok(())
}
