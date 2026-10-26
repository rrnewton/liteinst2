//! Initial EXEC -> actual EXIT -> owned first-user INT3 -> private island/NX.
//! The temporary original-entry patch is an explicit singleton bootstrap
//! exception. It does not claim that the entry bytes were already RW/NX.
use super::publication::HeldMmStop;
use super::trusted::{AdmissionPhase, AdmissionStop, TaskStateSnapshot, TrustedIsland};
use super::*;
use crate::lifecycle::TaskId;
use crate::publication::PublicationStop;

mod replaced;
pub(in crate::linux::remote::dynamic::owner) use replaced::{
    BootstrapEffect, ExecBootstrapReady, ReplacedBootstrapObservation, bootstrap_replaced_admission,
};

pub(in crate::linux::remote::dynamic) struct BootstrapEvidence {
    pub(in crate::linux::remote::dynamic) exec_event: TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic) exec_exit: TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic) entry_trap: TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic) restored_entry: TaskStateSnapshot,
}
pub(in crate::linux::remote::dynamic) struct BootstrapMm {
    pub(in crate::linux::remote::dynamic) island: TrustedIsland,
    pub(in crate::linux::remote::dynamic) original_executables: Vec<MemoryMapping>,
    pub(in crate::linux::remote::dynamic) mappings: Vec<MemoryMapping>,
    pub(in crate::linux::remote::dynamic) stop: AdmissionStop,
    pub(in crate::linux::remote::dynamic) evidence: BootstrapEvidence,
}

impl Owner {
    /// Read-only sizing census at the original owned EXEC stop. Bootstrap must
    /// match it again at actual EXIT, before modifying any application byte.
    pub(in crate::linux::remote::dynamic) fn admission_mapping_census(
        &self,
        initial: &DynamicStop,
    ) -> Result<Vec<MemoryMapping>, LaunchError> {
        let event = self.require_stop(initial)?;
        if !matches!(event.kind, DynamicEventKind::Exec { .. })
            || self.lifecycle.is_some()
            || self.lifecycle_options.is_none()
            || self.owned.len() != 1
        {
            return Err(LaunchError::Invalid(
                "admission requires the original singleton EXEC event",
            ));
        }
        single_task(self.pid)?;
        Ok(original_executables(read_maps(self.pid)?))
    }

    /// # Safety
    /// The admission frontend supplies the whole-image ownership/no-external-
    /// writer/no-code-as-data contract before this first original-entry patch.
    /// Original execution must never enter fixed vsyscall or the private island.
    pub(in crate::linux::remote::dynamic) unsafe fn bootstrap_admission(
        &mut self,
        initial: &DynamicStop,
        expected_mappings: &[MemoryMapping],
        until: Instant,
    ) -> Result<BootstrapMm, LaunchError> {
        self.time_left(until, "admission bootstrap")?;
        let event = self.require_stop(initial)?;
        if !matches!(event.kind, DynamicEventKind::Exec { .. })
            || self.lifecycle.is_some()
            || self.lifecycle_options.is_none()
            || self.owned.len() != 1
        {
            return Err(LaunchError::Invalid(
                "admission requires the original singleton EXEC event",
            ));
        }
        single_task(self.pid)?;
        let exec_event = TaskStateSnapshot::read(self.pid)?;
        if self.initial_exec != Some(exec_event.registers)
            || exec_event.registers.cs != 0x33
            || exec_event.registers.orig_rax != libc::SYS_execve as u64
            || exec_event.registers.rax != (-i64::from(libc::ENOSYS)) as u64
        {
            return Err(LaunchError::Invalid(
                "admission initial exec identity differs",
            ));
        }
        let result = (|| {
            self.resume(initial, DynamicResume::Continue)?;
            let exit = self.wait_event(until)?;
            if exit.tid != self.pid
                || exit.kind
                    != (DynamicEventKind::SyscallExit {
                        result: 0,
                        is_error: false,
                    })
            {
                return Err(LaunchError::Invalid(
                    "admission did not reach actual exec EXIT",
                ));
            }
            let exec_exit = TaskStateSnapshot::read(self.pid)?;
            let mut expected = exec_event.clone();
            expected.registers.rax = 0;
            if exec_exit != expected {
                return Err(LaunchError::Invalid(
                    "admission exec EXIT changed unrelated state",
                ));
            }
            if let Some(receipt) = &self.anchor_receipt {
                receipt.authenticate_exec_exit(self.pid, &exec_exit)?;
                self.anchor_exit_authenticated = true;
            }
            let mut native = self.lifecycle.take().ok_or(LaunchError::Invalid(
                "admission lacks initialized lifecycle registry",
            ))?;
            let exit_token = exit.stop_token().ok_or(LaunchError::Invalid(
                "actual exec EXIT lacks its held token",
            ))?;
            let result = bootstrap_inner(
                self,
                &mut native,
                BootstrapRequest {
                    exit: exit_token,
                    exec_event,
                    exec_exit,
                    expected_mappings,
                    observation: None,
                },
                until,
            );
            self.lifecycle = Some(native);
            result
        })();
        if result.is_err() {
            if !self.anchor_exit_authenticated {
                if let (Some(archive), Err(error)) = (&self.anchor_archive, &result) {
                    archive.record_failure(error);
                }
            }
            self.closing = true;
            self.cancel.store(true, Ordering::Release);
        }
        result
    }
}

pub(in crate::linux::remote::dynamic::owner) fn original_executables(
    maps: Vec<MemoryMapping>,
) -> Vec<MemoryMapping> {
    maps.into_iter()
        .filter(|m| {
            m.permissions.as_bytes().get(2) == Some(&b'x')
                && m.pathname.as_deref() != Some("[vsyscall]")
        })
        .collect()
}

struct BootstrapRequest<'a> {
    exit: &'a DynamicStop,
    exec_event: TaskStateSnapshot,
    exec_exit: TaskStateSnapshot,
    expected_mappings: &'a [MemoryMapping],
    observation: Option<&'a mut dyn ReplacedBootstrapObservation>,
}

fn before_effect(
    observation: &mut Option<&mut dyn ReplacedBootstrapObservation>,
    owner: &Owner,
    effect: BootstrapEffect,
    until: Instant,
) -> Result<(), LaunchError> {
    if let Some(observer) = observation.as_deref_mut() {
        owner.time_left(until, "replacement bootstrap effect")?;
        observer.before_effect(effect)?;
        owner.time_left(until, "replacement bootstrap effect")?;
    }
    Ok(())
}

fn effect_complete(
    observation: &mut Option<&mut dyn ReplacedBootstrapObservation>,
    effect: BootstrapEffect,
    result: Option<u64>,
) -> Result<(), LaunchError> {
    if let Some(observer) = observation.as_deref_mut() {
        observer.effect_complete(effect, result)?;
    }
    Ok(())
}

fn bootstrap_inner(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    request: BootstrapRequest<'_>,
    until: Instant,
) -> Result<BootstrapMm, LaunchError> {
    let BootstrapRequest {
        exit,
        exec_event,
        exec_exit,
        expected_mappings,
        mut observation,
    } = request;
    let tid = owner.pid;
    let size = page_size()?;
    if size != 4096 {
        return Err(LaunchError::Invalid("admission requires 4096-byte pages"));
    }
    let originals = original_executables(read_maps(tid)?);
    if originals != expected_mappings {
        return Err(LaunchError::Invalid(
            "bootstrap executable census changed after its resource reservation",
        ));
    }
    let mut pages = 0_u64;
    for mapping in &originals {
        if mapping.end <= mapping.start
            || mapping.start % size as u64 != 0
            || mapping.end % size as u64 != 0
            || mapping.permissions.as_bytes().get(1) == Some(&b'w')
            || mapping.permissions.as_bytes().get(3) != Some(&b'p')
        {
            return Err(LaunchError::Invalid(
                "bootstrap requires aligned private immutable executable mappings",
            ));
        }
        pages = pages
            .checked_add((mapping.end - mapping.start) / size as u64)
            .ok_or(LaunchError::Invalid("bootstrap page inventory overflow"))?;
    }
    if originals.len() > 64 || pages > 16 * 1024 {
        return Err(LaunchError::Invalid(
            "bootstrap executable inventory exceeds bound",
        ));
    }
    let pc = exec_exit.registers.rip;
    let end = pc
        .checked_add(STUB.len() as u64)
        .ok_or(LaunchError::Invalid("bootstrap code overflow"))?;
    if !originals.iter().any(|m| m.start <= pc && end <= m.end) {
        return Err(LaunchError::Invalid(
            "entry stub crosses executable mapping boundary",
        ));
    }
    let envelope = pc & !7;
    let envelope_end = end
        .checked_add(7)
        .ok_or(LaunchError::Invalid("bootstrap envelope overflow"))?
        & !7;
    let original = read_memory(tid, envelope, (envelope_end - envelope) as usize)?;
    before_effect(&mut observation, owner, BootstrapEffect::PatchEntry, until)?;
    poke_bytes(tid, pc, &[0xcc])?;
    if read_memory(tid, pc, 1)? != [0xcc] {
        return Err(LaunchError::Invalid("bootstrap entry INT3 did not verify"));
    }
    effect_complete(&mut observation, BootstrapEffect::PatchEntry, None)?;
    before_effect(
        &mut observation,
        owner,
        BootstrapEffect::FirstUserResume,
        until,
    )?;
    native.begin_admission_return_bridge(exit)?;
    ptrace(libc::PTRACE_CONT, tid, 0, 0)?;
    owner.released(tid);
    effect_complete(&mut observation, BootstrapEffect::FirstUserResume, None)?;
    let (observed, status) = owner.wait_raw(until, "admission first-user INT3")?;
    if let Some(observer) = observation.as_deref_mut() {
        observer.raw(owner, observed, status)?;
        #[cfg(test)]
        owner.exec_oracle_first_user(observed, status, exit, until)?;
        owner.time_left(until, "replacement first-user raw observation")?;
    }
    if observed != tid
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || status >> 16 != 0
    {
        return Err(LaunchError::Invalid(
            "admission entry reached an unexpected event",
        ));
    }
    native.consume_admission_interrupt(tid)?;
    let signal = siginfo(tid)?;
    let entry_trap = TaskStateSnapshot::read(tid)?;
    let mut expected = exec_exit.registers;
    expected.rip += 1;
    expected.orig_rax = u64::MAX;
    if signal.si_signo != libc::SIGTRAP
        || !matches!(signal.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT)
        || entry_trap.registers != expected
        || entry_trap.mask != exec_exit.mask
        || read_memory(tid, pc, 1)? != [0xcc]
    {
        return Err(LaunchError::Invalid(
            "admission first-user state did not authenticate",
        ));
    }
    if let Some(observer) = observation.as_deref_mut() {
        observer.entry_trap(&entry_trap)?;
    }
    // Preserve the actual user-return XSTATE, including deferred initial PKRU.
    // Never replace it with the earlier EXEC/EXIT extended-state image.
    before_effect(
        &mut observation,
        owner,
        BootstrapEffect::RestoreEntry,
        until,
    )?;
    poke_bytes(tid, envelope, &original)?;
    // The real user boundary has cleared orig_rax. Preserve that observed
    // metadata along with its initialized XSTATE; undo only the owned INT3 RIP.
    let mut restored_entry = entry_trap.clone();
    restored_entry.registers.rip = pc;
    restored_entry.restore(tid)?;
    if TaskStateSnapshot::read(tid)? != restored_entry
        || read_memory(tid, envelope, original.len())? != original
    {
        return Err(LaunchError::Invalid("entry restoration did not verify"));
    }
    let entry = native.finish_admission_execution(tid, pc, AdmissionPhase::EntryReady)?;
    effect_complete(&mut observation, BootstrapEffect::RestoreEntry, None)?;
    if let Some(observer) = observation.as_deref_mut() {
        observer.restored_entry(&entry, &restored_entry)?;
    }
    let root = entry.identity.task;
    before_effect(&mut observation, owner, BootstrapEffect::WriteStub, until)?;
    poke_bytes(tid, pc, &STUB)?;
    if read_memory(tid, pc, STUB.len())? != STUB {
        return Err(LaunchError::Invalid("bootstrap syscall stub differs"));
    }
    effect_complete(&mut observation, BootstrapEffect::WriteStub, None)?;
    before_effect(&mut observation, owner, BootstrapEffect::MapIsland, until)?;
    let address = syscall_result(
        bootstrap_call(
            owner,
            native,
            root,
            pc,
            libc::SYS_mmap,
            [
                0,
                size as u64,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
            until,
        )?,
        "admission bootstrap mmap",
    )?;
    effect_complete(&mut observation, BootstrapEffect::MapIsland, Some(address))?;
    let island_end = address
        .checked_add(size as u64)
        .ok_or(LaunchError::Invalid("island address overflow"))?;
    if address == 0
        || address % size as u64 != 0
        || originals
            .iter()
            .any(|m| address < m.end && m.start < island_end)
    {
        return Err(LaunchError::Invalid(
            "bootstrap returned invalid island range",
        ));
    }
    let write_island = BootstrapEffect::WriteIsland { address };
    before_effect(&mut observation, owner, write_island, until)?;
    poke_bytes(tid, address, &island_code())?;
    effect_complete(&mut observation, write_island, None)?;
    let protect_island = BootstrapEffect::ProtectIsland {
        address,
        length: size,
    };
    before_effect(&mut observation, owner, protect_island, until)?;
    syscall_result(
        bootstrap_call(
            owner,
            native,
            root,
            pc,
            libc::SYS_mprotect,
            [
                address,
                size as u64,
                (libc::PROT_READ | libc::PROT_EXEC) as u64,
                0,
                0,
                0,
            ],
            until,
        )?,
        "admission bootstrap RX",
    )?;
    effect_complete(&mut observation, protect_island, None)?;
    before_effect(
        &mut observation,
        owner,
        BootstrapEffect::QueryMembarrier,
        until,
    )?;
    let supported = syscall_result(
        bootstrap_call(owner, native, root, pc, libc::SYS_membarrier, [0; 6], until)?,
        "admission membarrier query",
    )?;
    effect_complete(
        &mut observation,
        BootstrapEffect::QueryMembarrier,
        Some(supported),
    )?;
    if supported & (SYNC_CORE | REGISTER_SYNC_CORE) != SYNC_CORE | REGISTER_SYNC_CORE {
        return Err(LaunchError::Invalid("admission target lacks sync-core"));
    }
    before_effect(
        &mut observation,
        owner,
        BootstrapEffect::RegisterMembarrier,
        until,
    )?;
    syscall_result(
        bootstrap_call(
            owner,
            native,
            root,
            pc,
            libc::SYS_membarrier,
            [REGISTER_SYNC_CORE, 0, 0, 0, 0, 0],
            until,
        )?,
        "admission register sync-core",
    )?;
    effect_complete(&mut observation, BootstrapEffect::RegisterMembarrier, None)?;
    before_effect(
        &mut observation,
        owner,
        BootstrapEffect::BootstrapSync,
        until,
    )?;
    syscall_result(
        bootstrap_call(
            owner,
            native,
            root,
            pc,
            libc::SYS_membarrier,
            [SYNC_CORE, 0, 0, 0, 0, 0],
            until,
        )?,
        "admission bootstrap sync-core",
    )?;
    effect_complete(&mut observation, BootstrapEffect::BootstrapSync, None)?;
    before_effect(
        &mut observation,
        owner,
        BootstrapEffect::RestoreOriginal,
        until,
    )?;
    poke_bytes(tid, envelope, &original)?;
    restored_entry.restore(tid)?;
    if read_memory(tid, envelope, original.len())? != original {
        return Err(LaunchError::Invalid(
            "bootstrap original bytes did not restore",
        ));
    }
    effect_complete(&mut observation, BootstrapEffect::RestoreOriginal, None)?;
    let mut island = TrustedIsland {
        address_space: entry.identity.address_space,
        generation: entry.identity.generation,
        range: address..island_end,
        page_size: size,
    };
    island.verify(tid)?;
    let (mut mappings, stop) = {
        let mut held = HeldMmStop::acquire(owner, native, &mut island, root, until)?;
        before_effect(
            &mut observation,
            held.owner,
            BootstrapEffect::QuarantineSyncBefore,
            until,
        )?;
        held.sync_core(remaining(until)?)?;
        effect_complete(
            &mut observation,
            BootstrapEffect::QuarantineSyncBefore,
            None,
        )?;
        for mapping in &originals {
            let effect = BootstrapEffect::Quarantine {
                start: mapping.start,
                length: (mapping.end - mapping.start) as usize,
            };
            before_effect(&mut observation, held.owner, effect, until)?;
            held.mprotect(
                mapping.start,
                (mapping.end - mapping.start) as usize,
                super_protection(mapping)? & !libc::PROT_EXEC,
                remaining(until)?,
            )?;
            effect_complete(&mut observation, effect, None)?;
        }
        before_effect(
            &mut observation,
            held.owner,
            BootstrapEffect::QuarantineSyncAfter,
            until,
        )?;
        held.sync_core(remaining(until)?)?;
        effect_complete(&mut observation, BootstrapEffect::QuarantineSyncAfter, None)?;
        if TaskStateSnapshot::read(tid)? != restored_entry
            || held.read_memory(envelope, original.len())? != original
        {
            return Err(LaunchError::Invalid(
                "initial NX gate changed original entry state",
            ));
        }
        (held.mappings(), held.selected_stop()?)
    };
    for original in &originals {
        if mappings.iter().any(|m| {
            original.start < m.end
                && m.start < original.end
                && m.permissions.as_bytes().get(2) == Some(&b'x')
        }) {
            return Err(LaunchError::Invalid(
                "original executable range remained executable",
            ));
        }
    }
    mappings.sort_by_key(|mapping| mapping.start);
    Ok(BootstrapMm {
        island,
        original_executables: originals,
        mappings,
        stop,
        evidence: BootstrapEvidence {
            exec_event,
            exec_exit,
            entry_trap,
            restored_entry,
        },
    })
}

fn bootstrap_call(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    root: TaskId,
    pc: u64,
    number: libc::c_long,
    args: [u64; 6],
    until: Instant,
) -> Result<u64, LaunchError> {
    let stop = native.admission_current(root)?;
    let mut registers = trusted::temporary(&read_registers(stop.token.tid)?, pc);
    registers.rax = number as u64;
    registers.rdi = args[0];
    registers.rsi = args[1];
    registers.rdx = args[2];
    registers.r10 = args[3];
    registers.r8 = args[4];
    registers.r9 = args[5];
    trusted::execute(owner, native, &stop, (pc, &STUB), registers, false, until)
        .map(|(value, _)| value)
}
