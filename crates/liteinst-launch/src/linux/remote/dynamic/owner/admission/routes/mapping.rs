//! A singleton mapping syscall may temporarily see the application's original
//! logical X permissions. This is never an ordinary release or publication
//! lease. Exactly one authenticated original SYSCALL is allowed; the result is
//! quarantined before source acquisition or a generation transition.
use super::super::mapping::VerifiedMappingExit;
use super::*;
use crate::linux::remote::dynamic::owner::lifecycle::admission::MmMembership;
use crate::linux::remote::dynamic::owner::publication::HeldMmStop;
use crate::linux::remote::dynamic::owner::trusted::{
    AdmissionPhase, AdmissionStop, TaskStateSnapshot,
};

/// The only constructor performs actual whole-domain revocation/restoration,
/// then reopens logical X with every application task still held. Not Clone.
pub(in super::super) struct MappingWindow {
    revoked: RevokedDomain,
    opened: AdmissionStop,
    fixed_vsyscall: Option<MemoryMapping>,
}

impl MappingWindow {
    pub(in super::super) fn opened_stop(&self) -> &AdmissionStop {
        &self.opened
    }
}

/// An actual mapping EXIT, real return bridge, and completed NX quarantine.
/// This does not authorize ordinary execution. The new native generation
/// helper consumes it and returns it only after the exact model transition.
pub(in crate::linux::remote::dynamic::owner) struct MappingRevocation {
    revoked: RevokedDomain,
    closed: AdmissionStop,
    closed_state: TaskStateSnapshot,
    exit: VerifiedMappingExit,
    fixed_vsyscall: Option<MemoryMapping>,
}

impl MappingRevocation {
    pub(in super::super) fn retained_bytes(&self) -> Result<usize, GateError> {
        std::mem::size_of::<Self>()
            .checked_add(self.closed_state.xstate.len())
            .and_then(|bytes| {
                bytes.checked_add(self.fixed_vsyscall.as_ref().map_or(0, |mapping| {
                    mapping.permissions.len() + mapping.pathname.as_ref().map_or(0, String::len)
                }))
            })
            .ok_or(GateError::Refused(
                "mapping quarantine evidence size overflows",
            ))
    }
    pub(in super::super) fn logical_executables(&self) -> &[MemoryMapping] {
        self.exit.logical_executables()
    }
    pub(in crate::linux::remote::dynamic::owner) fn old_generation(&self) -> u64 {
        self.revoked.generation
    }

    pub(in crate::linux::remote::dynamic::owner) fn old_version(&self) -> u64 {
        self.revoked.entry_version
    }

    pub(in crate::linux::remote::dynamic::owner) fn closed_stop(&self) -> &AdmissionStop {
        &self.closed
    }

    /// Repeat quarantine/source authentication under a new actual native hold.
    /// Acquiring this hold performs no injected instruction or original resume.
    pub(in crate::linux::remote::dynamic::owner) fn authenticate_quarantine(
        &self,
        held: &HeldMmStop<'_>,
    ) -> Result<(), GateError> {
        let current = singleton(held, self.revoked.generation)?;
        let state = TaskStateSnapshot::read(current.token.tid)?;
        self.authenticate_advance(held.membership(), &current, &state)?;
        permissions(
            held,
            self.exit.logical_executables(),
            false,
            &self.fixed_vsyscall,
        )?;
        self.exit.authenticate_closed(held)
    }

    /// Called with fresh real membership, stop and full state immediately
    /// before begin/finish invalidation, with no native operation between them.
    pub(in crate::linux::remote::dynamic::owner) fn authenticate_advance(
        &self,
        membership: &MmMembership,
        current: &AdmissionStop,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        if *current != self.closed
            || *state != self.closed_state
            || membership.address_space != self.closed.identity.address_space
            || membership.process != self.closed.identity.process
            || membership.generation != self.revoked.generation
            || membership.generation != self.closed.identity.generation
            || membership.tgid != self.closed.token.tid
            || membership.tids.len() != 1
            || !membership.tids.contains(&self.closed.token.tid)
            || membership.candidate.tasks.len() != 1
            || !membership
                .candidate
                .tasks
                .contains(&self.closed.identity.task)
        {
            return Err(LaunchError::Invalid(
                "mapping revocation lacks its exact native singleton",
            ));
        }
        Ok(())
    }

    /// Used by the mapping commit path after the new native helper returned
    /// this consumed seal at old_generation+1. The catalog commit independently
    /// authenticates the new native generation/census and the retained EXIT.
    pub(in super::super) fn into_parts(self) -> (RevokedDomain, VerifiedMappingExit) {
        (self.revoked, self.exit)
    }
}

fn singleton(held: &HeldMmStop<'_>, generation: u64) -> Result<AdmissionStop, GateError> {
    let stop = held.selected_stop()?;
    let membership = held
        .native
        .check_admission_mm(held.owner, stop.identity.task)?;
    if membership.generation != generation
        || stop.identity.generation != generation
        || membership.address_space != stop.identity.address_space
        || membership.process != stop.identity.process
        || membership.tgid != stop.token.tid
        || membership.tids.len() != 1
        || !membership.tids.contains(&stop.token.tid)
        || membership.candidate.tasks.len() != 1
        || !membership.candidate.tasks.contains(&stop.identity.task)
        || stop.signal.is_some()
        || !matches!(
            stop.phase,
            AdmissionPhase::EntryReady | AdmissionPhase::Restored
        )
        || held.page_size() != PAGE as usize
    {
        return Err(GateError::Refused(
            "mapping window requires one normalized native64 task",
        ));
    }
    held.native.require_admission_stop(&stop)?;
    Ok(stop)
}

fn validate_inventory(inventory: &[MemoryMapping]) -> Result<(), GateError> {
    if inventory.is_empty() || inventory.len() > 64 {
        return Err(GateError::Refused(
            "mapping logical executable inventory exceeds bound",
        ));
    }
    let mut previous_end = 0;
    for map in inventory {
        if map.start >= map.end
            || map.start % PAGE != 0
            || map.end % PAGE != 0
            || map.start < previous_end
            || map.permissions != "r-xp"
        {
            return Err(GateError::Refused(
                "mapping logical executable inventory differs",
            ));
        }
        previous_end = map.end;
    }
    Ok(())
}

fn covered(inventory: &[MemoryMapping], start: u64, end: u64) -> bool {
    let mut cursor = start;
    for map in inventory {
        if map.end <= cursor || map.start >= end {
            continue;
        }
        if map.start > cursor {
            return false;
        }
        cursor = map.end.min(end);
    }
    cursor == end
}

// The existing admission contract already excludes execution in the fixed
// vsyscall page. Retain its exact baseline descriptor; do not mistake it for a
// mutable application mapping or permit a new extra executable range.
fn fixed_vsyscall(maps: &[MemoryMapping]) -> Result<Option<MemoryMapping>, GateError> {
    let mut result = None;
    for map in maps
        .iter()
        .filter(|map| map.pathname.as_deref() == Some("[vsyscall]"))
    {
        if result.is_some()
            || map.start != 0xffff_ffff_ff60_0000
            || map.end != 0xffff_ffff_ff60_1000
            || map.permissions != "--xp"
            || map.file_offset != 0
        {
            return Err(GateError::Refused(
                "mapping fixed vsyscall descriptor differs",
            ));
        }
        result = Some(map.clone());
    }
    Ok(result)
}

fn permissions(
    held: &HeldMmStop<'_>,
    inventory: &[MemoryMapping],
    executable: bool,
    fixed: &Option<MemoryMapping>,
) -> Result<(), GateError> {
    let maps = held.mappings();
    if fixed_vsyscall(&maps)? != *fixed {
        return Err(GateError::Refused(
            "mapping fixed executable inventory changed",
        ));
    }
    let expected = if executable { "r-xp" } else { "r--p" };
    for original in inventory {
        let mut cursor = original.start;
        for map in &maps {
            if map.end <= cursor || map.start >= original.end {
                continue;
            }
            if map.start > cursor || map.permissions != expected {
                return Err(GateError::Refused(
                    "mapping window permissions are not exact",
                ));
            }
            cursor = map.end.min(original.end);
        }
        if cursor != original.end {
            return Err(GateError::Refused(
                "mapping window permission inventory has a hole",
            ));
        }
    }
    for map in &maps {
        if map.permissions.as_bytes().get(2) != Some(&b'x') {
            continue;
        }
        if map.start == held.island.range.start && map.end == held.island.range.end {
            // HeldMmStop acquire/operations positively authenticate the island.
            continue;
        }
        if fixed.as_ref() == Some(map) {
            continue;
        }
        if !executable || !covered(inventory, map.start, map.end) {
            return Err(GateError::Refused(
                "mapping window has an unaccounted executable mapping",
            ));
        }
    }
    Ok(())
}

fn retired(domain: &Domain, revoked: &RevokedDomain) -> Result<(), GateError> {
    let last = domain
        .generations
        .last()
        .ok_or(GateError::Refused("mapping retirement is absent"))?;
    if domain.generation != revoked.generation
        || domain.entry_version != revoked.entry_version
        || last.generation != revoked.generation
        || last.entry_version != revoked.entry_version
        || last.source_binding != domain.source_binding
        || domain.pages.values().any(|executable| *executable)
        || !domain.guards.is_empty()
        || !domain.sites.is_empty()
    {
        return Err(GateError::Refused(
            "mapping retirement changed before commit",
        ));
    }
    Ok(())
}

pub(in super::super) fn open_mapping_window(
    held: &mut HeldMmStop<'_>,
    domain: &mut Domain,
    until: Instant,
) -> Result<MappingWindow, GateError> {
    let before = singleton(held, domain.generation)?;
    validate_inventory(&domain.original_executables)?;
    let fixed = fixed_vsyscall(&held.mappings())?;
    let state = TaskStateSnapshot::read(before.token.tid)?;
    // The selected instruction is still its authenticated guard here. This
    // operation restores every old edit; there is no separate OriginalWindow.
    let revoked = super::revoke_all(held, domain, None, until)?;
    retired(domain, &revoked)?;
    for map in &domain.original_executables {
        let len = usize::try_from(map.end - map.start)
            .map_err(|_| GateError::Refused("mapping executable range exceeds address space"))?;
        held.mprotect(
            map.start,
            len,
            libc::PROT_READ | libc::PROT_EXEC,
            super::super::control_remaining(until)?,
        )?;
    }
    held.sync_core(super::super::control_remaining(until)?)?;
    permissions(held, &domain.original_executables, true, &fixed)?;
    for image in &domain.images {
        super::super::control_remaining(until)?;
        if held.read_memory(image.mapping.start, image.snapshot.bytes().len())?
            != image.snapshot.bytes()
        {
            return Err(GateError::Refused(
                "mapping window did not retain exact original source",
            ));
        }
        super::super::control_remaining(until)?;
    }
    let opened = singleton(held, domain.generation)?;
    if opened.identity != before.identity
        || opened.token.session != before.token.session
        || opened.token.tid != before.token.tid
        || TaskStateSnapshot::read(opened.token.tid)? != state
    {
        return Err(GateError::Refused(
            "mapping window changed original full state",
        ));
    }
    super::super::control_remaining(until)?;
    Ok(MappingWindow {
        revoked,
        opened,
        fixed_vsyscall: fixed,
    })
}

pub(in super::super) fn close_mapping_window(
    held: &mut HeldMmStop<'_>,
    domain: &Domain,
    window: MappingWindow,
    exit: VerifiedMappingExit,
    until: Instant,
) -> Result<MappingRevocation, GateError> {
    retired(domain, &window.revoked)?;
    singleton(held, window.revoked.generation)?;
    // This private witness's constructor is owned by the actual mapping
    // transport. It proves real ENTRY/EXIT, the exact mapping diff, unchanged
    // controller/island/stack and full state, and the actual neutral bridge.
    exit.authenticate(held, &window.opened)?;
    validate_inventory(exit.logical_executables())?;
    permissions(
        held,
        exit.logical_executables(),
        true,
        &window.fixed_vsyscall,
    )?;
    let state = TaskStateSnapshot::read(held.selected_token()?.tid)?;
    for map in exit.logical_executables() {
        let len = usize::try_from(map.end - map.start)
            .map_err(|_| GateError::Refused("mapping quarantine range exceeds address space"))?;
        held.mprotect(
            map.start,
            len,
            libc::PROT_READ,
            super::super::control_remaining(until)?,
        )?;
    }
    held.sync_core(super::super::control_remaining(until)?)?;
    permissions(
        held,
        exit.logical_executables(),
        false,
        &window.fixed_vsyscall,
    )?;
    // The old target may now be writable or absent. Its retired source remains
    // historical evidence; do not reread it as if it were still the live image.
    exit.authenticate_closed(held)?;
    let closed = singleton(held, window.revoked.generation)?;
    let closed_state = TaskStateSnapshot::read(closed.token.tid)?;
    if closed_state != state {
        return Err(GateError::Refused(
            "mapping quarantine changed original full state",
        ));
    }
    super::super::control_remaining(until)?;
    Ok(MappingRevocation {
        revoked: window.revoked,
        closed,
        closed_state,
        exit,
        fixed_vsyscall: window.fixed_vsyscall,
    })
}
