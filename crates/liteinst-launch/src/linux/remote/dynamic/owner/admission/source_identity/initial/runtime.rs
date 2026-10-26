//! Current-state reads in the unchanged initial runtime mm. The historical
//! BootstrapMm is never relabelled with a later stop or application state.
use super::*;

/// Descriptive borrowed inputs; constructing this view grants no authority.
pub(in crate::linux::remote::dynamic::owner::admission) struct RuntimeReadCheckpoint<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) island: &'a TrustedIsland,
    pub(in crate::linux::remote::dynamic::owner::admission) stop: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner::admission) observed: &'a ObservedStop,
    pub(in crate::linux::remote::dynamic::owner::admission) maps: &'a [u8],
}

/// Read-only authority borrowed from an actual current owner/native stop.
/// It carries neither a bootstrap result nor an original-execution permit.
pub(in crate::linux::remote::dynamic::owner::admission) struct RuntimeSourceRead<'a> {
    context: SourceReadContext<'a>,
    native: &'a NativeLifecycle,
    island: &'a TrustedIsland,
    stop: &'a AdmissionStop,
    observed: &'a ObservedStop,
    maps: &'a [u8],
    scratch: &'a InitialReadScratch,
}

impl<'a> RuntimeSourceRead<'a> {
    /// Separate temporary peak for current-runtime authentication. The existing
    /// initial-capture reservation remains unchanged. Caller map/window/state
    /// payloads and the retained InitialReadScratch are counted separately.
    /// This is managed request storage, not allocator metadata or global RSS.
    pub(in crate::linux::remote::dynamic::owner::admission) fn temporary_bytes() -> usize {
        let authentication = 2 * size_of::<SourceReadProgress>()
            + size_of::<RegisterSnapshot>()
            + size_of::<libc::iovec>()
            + 2 * size_of::<libc::statfs>()
            + 3 * size_of::<File>()
            + 2 * 68
            + 32
            + 11;
        size_of::<Self>()
            + size_of::<RuntimeReadCheckpoint<'_>>()
            + authentication.max(backing::temporary_bytes())
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn acquire(
        owner: &'a Owner,
        native: &'a NativeLifecycle,
        checkpoint: RuntimeReadCheckpoint<'a>,
        scratch: &'a InitialReadScratch,
        until: Instant,
    ) -> Result<Self, GateError> {
        let RuntimeReadCheckpoint {
            island,
            stop,
            observed,
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
            observed,
            maps,
            scratch,
        };
        read.reauthenticate()?;
        Ok(read)
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn reauthenticate(
        &self,
    ) -> Result<(), GateError> {
        let context = &self.context;
        let mut scratch =
            self.scratch.bytes.try_borrow_mut().map_err(|_| {
                refused("runtime source authentication scratch is already borrowed")
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
        if self.stop.token != self.observed.token
            || self.stop.identity != self.observed.task
            || self.observed.logical_pc != self.observed.registers.rip
            || self.observed.phase != StopPhase::UserCheckpoint
            || self.observed.signal.is_some()
            || self.stop.signal.is_some()
            || self.stop.identity.address_space != self.island.address_space
            || self.stop.identity.generation != 0
            || self.island.generation != 0
            || self.observed.registers.cs != 0x33
            || self.observed.xstate.len() < 512
            || self.observed.xstate.len() >= MAP_BYTES
            || self.maps.is_empty()
            || self.maps.len() > MAP_BYTES
        {
            return Err(refused("runtime source current observation differs"));
        }
        let mut progress = SourceReadProgress::default();
        let length = read::maps_capture(context, scratch.as_mut_slice(), &mut progress, || Ok(()))?;
        if scratch[..length] != *self.maps {
            return Err(refused("runtime source complete map inventory differs"));
        }
        let maps = parse(&scratch[..length])?;
        if !maps.entries().any(|row| {
            row.start <= self.island.range.start
                && self.island.range.end <= row.end
                && row.permissions.bytes() == *b"r-xp"
                && row.pathname.is_none()
                && row.inode == 0
        }) {
            return Err(refused("runtime source private island mapping differs"));
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
            return Err(refused("runtime source private island bytes differ"));
        }
        context
            .owner
            .time_left(context.until, "runtime source current-state authentication")?;
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
        if registers != self.observed.registers
            || scratch[..vector.iov_len] != self.observed.xstate
            || mask != self.observed.signal_mask
        {
            return Err(refused("runtime source complete current state differs"));
        }
        self.native.require_admission_stop(self.stop)?;
        if context
            .owner
            .handles
            .get(&context.owner.pid)
            .is_none_or(broker::hup)
        {
            return Err(refused("runtime source process pin is no longer live"));
        }
        context
            .owner
            .time_left(context.until, "runtime source current-state authentication")?;
        Ok(())
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn executable_projection(
        &self,
        storage: &mut [u8],
    ) -> Result<ExecutableIdentity, GateError> {
        self.reauthenticate()?;
        let result = backing::observe(&self.context, storage)?;
        self.reauthenticate()?;
        Ok(result)
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn read_memory_into(
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
