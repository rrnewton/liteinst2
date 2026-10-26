//! Read-only authentication of an actual restored initial checkpoint before
//! BootstrapMm exists. The borrowed inputs alone confer no native authority.
use super::*;

/// Descriptive borrowed inputs; constructing this view grants no authority.
pub(in crate::linux::remote::dynamic::owner) struct InitialSourceCheckpoint<'a> {
    pub(in crate::linux::remote::dynamic::owner) island: &'a TrustedIsland,
    pub(in crate::linux::remote::dynamic::owner) stop: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner) state: &'a TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic::owner) maps: &'a [u8],
}

/// Read-only authority borrowed from an actual current owner/native stop.
/// It carries neither a bootstrap result nor an original-execution permit.
pub(in crate::linux::remote::dynamic::owner) struct InitialCheckpointSourceRead<'a> {
    context: SourceReadContext<'a>,
    native: &'a NativeLifecycle,
    island: &'a TrustedIsland,
    stop: &'a AdmissionStop,
    state: &'a TaskStateSnapshot,
    maps: &'a [u8],
    scratch: &'a InitialReadScratch,
}

fn require_pair_phase(phase: AdmissionPhase, signal: bool) -> Result<(), GateError> {
    if phase != AdmissionPhase::Restored || signal {
        return Err(refused(
            "initial pair read lacks the actual restored checkpoint",
        ));
    }
    Ok(())
}

impl<'a> InitialCheckpointSourceRead<'a> {
    /// Separate temporary peak for current-runtime authentication. The existing
    /// initial-capture reservation remains unchanged. Caller map/window/state
    /// payloads and the retained InitialReadScratch are counted separately.
    /// This is managed request storage, not allocator metadata or global RSS.
    pub(in crate::linux::remote::dynamic::owner) fn temporary_bytes() -> usize {
        let authentication = 2 * size_of::<SourceReadProgress>()
            + size_of::<RegisterSnapshot>()
            + size_of::<libc::iovec>()
            + 2 * size_of::<libc::statfs>()
            + 3 * size_of::<File>()
            + 2 * 68
            + 32
            + 11;
        size_of::<Self>()
            + size_of::<InitialSourceCheckpoint<'_>>()
            + authentication.max(backing::temporary_bytes())
    }

    pub(in crate::linux::remote::dynamic::owner) fn acquire(
        owner: &'a Owner,
        native: &'a NativeLifecycle,
        checkpoint: InitialSourceCheckpoint<'a>,
        scratch: &'a InitialReadScratch,
        until: Instant,
    ) -> Result<Self, GateError> {
        let InitialSourceCheckpoint {
            island,
            stop,
            state,
            maps,
        } = checkpoint;
        let read = Self {
            context: SourceReadContext {
                owner,
                until,
                bounded: true,
            },
            native,
            island,
            stop,
            state,
            maps,
            scratch,
        };
        read.reauthenticate()?;
        Ok(read)
    }

    pub(in crate::linux::remote::dynamic::owner) fn reauthenticate(&self) -> Result<(), GateError> {
        let context = &self.context;
        let mut scratch = self.scratch.bytes.try_borrow_mut().map_err(|_| {
            refused("initial checkpoint source authentication scratch is already borrowed")
        })?;
        // This predicate proves the unchanged gen0 initial singleton and its
        // actual current held phase. It accepts no pending syscall/frame/birth,
        // invalidation, interrupt uncertainty or lifecycle transition.
        self.native.require_initial_source_mm(
            context.owner,
            self.stop,
            context.until,
            scratch.as_mut_slice(),
        )?;
        require_pair_phase(self.stop.phase, self.stop.signal.is_some())?;
        if self.stop.identity.address_space != self.island.address_space
            || self.stop.identity.generation != 0
            || self.island.generation != 0
            || self.island.range.start == 0
            || self.island.range.start % PAGE != 0
            || self.island.range.end.checked_sub(self.island.range.start) != Some(PAGE)
            || self.state.registers.cs != 0x33
            || self.state.xstate.len() < 512
            || self.state.xstate.len() >= MAP_BYTES
            || self.maps.is_empty()
            || self.maps.len() > MAP_BYTES
        {
            return Err(refused(
                "initial checkpoint source current observation differs",
            ));
        }
        let mut progress = SourceReadProgress::default();
        let length = read::maps_capture(context, scratch.as_mut_slice(), &mut progress, || Ok(()))?;
        if scratch[..length] != *self.maps {
            return Err(refused(
                "initial checkpoint source complete map inventory differs",
            ));
        }
        let maps = parse(&scratch[..length])?;
        if !maps.entries().any(|row| {
            row.start == self.island.range.start
                && row.end == self.island.range.end
                && row.file_offset == 0
                && row.device_major == 0
                && row.device_minor == 0
                && row.permissions.bytes() == *b"r-xp"
                && row.pathname.is_none()
                && row.inode == 0
        }) {
            return Err(refused(
                "initial checkpoint source private island mapping differs",
            ));
        }
        let mut expected = [0xcc_u8; 68];
        expected[..STUB.len()].copy_from_slice(&STUB);
        for (offset, stub) in STORE_STUBS {
            expected[offset..offset + stub.len()].copy_from_slice(stub);
        }
        let mut actual = [0_u8; 68];
        let mut progress = SourceReadProgress::default();
        read::memory_capture(
            context,
            self.island.range.start,
            &mut actual,
            &mut progress,
            || Ok(()),
        )?;
        if actual != expected {
            return Err(refused(
                "initial checkpoint source private island bytes differ",
            ));
        }
        context.owner.time_left(
            context.until,
            "initial checkpoint source current-state authentication",
        )?;
        let registers = read_registers(context.owner.pid)?;
        scratch.fill(0);
        let pointer = scratch.as_mut_ptr().cast::<libc::c_void>();
        let mut vector = libc::iovec {
            iov_base: pointer,
            iov_len: scratch.len(),
        };
        ptrace(
            libc::PTRACE_GETREGSET,
            context.owner.pid,
            NT_X86_XSTATE,
            (&raw mut vector) as usize,
        )?;
        if vector.iov_base != pointer || vector.iov_len < 512 || vector.iov_len >= scratch.len() {
            return Err(LaunchError::Invalid("missing or truncated xstate image").into());
        }
        let mask = launch::task_mask(context.owner.pid)?;
        if registers != self.state.registers
            || scratch[..vector.iov_len] != self.state.xstate
            || mask != self.state.mask
        {
            return Err(refused(
                "initial checkpoint source complete current state differs",
            ));
        }
        self.native.require_admission_stop(self.stop)?;
        if context
            .owner
            .handles
            .get(&context.owner.pid)
            .is_none_or(broker::hup)
        {
            return Err(refused(
                "initial checkpoint source process pin is no longer live",
            ));
        }
        context.owner.time_left(
            context.until,
            "initial checkpoint source current-state authentication",
        )?;
        Ok(())
    }

    pub(in crate::linux::remote::dynamic::owner) fn read_memory_capture(
        &self,
        address: u64,
        storage: &mut [u8],
        progress: &mut SourceReadProgress,
    ) -> Result<(), GateError> {
        read::memory_capture(&self.context, address, storage, progress, || {
            self.reauthenticate()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_pair_read_description_refuses_every_non_restored_or_signal_phase() {
        require_pair_phase(AdmissionPhase::Restored, false).unwrap();
        for phase in [
            AdmissionPhase::EntryReady,
            AdmissionPhase::Fetch,
            AdmissionPhase::Guard,
            AdmissionPhase::NativeCompleted,
        ] {
            assert!(require_pair_phase(phase, false).is_err());
            assert!(require_pair_phase(phase, true).is_err());
        }
        assert!(require_pair_phase(AdmissionPhase::Restored, true).is_err());
    }
}
