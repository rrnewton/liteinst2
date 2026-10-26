//! Source reads at genuine original syscall ENTRY/EXIT in the initial mm.
//! The settled source reader and its predicates remain unchanged.
use super::*;
use crate::linux::remote::dynamic::owner::trusted::TaskStateSnapshot;

/// Descriptive borrowed inputs; constructing this view grants no authority.
pub(in crate::linux::remote::dynamic::owner::admission) struct RuntimeKernelReadCheckpoint<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) island: &'a TrustedIsland,
    pub(in crate::linux::remote::dynamic::owner::admission) original: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner::admission) event: &'a DynamicEvent,
    pub(in crate::linux::remote::dynamic::owner::admission) state: &'a TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic::owner::admission) maps: &'a [u8],
}

/// Read-only authority borrowed from an actual current owner/native stop.
/// It carries neither a bootstrap result nor an original-execution permit.
pub(in crate::linux::remote::dynamic::owner::admission) struct RuntimeKernelSourceRead<'a> {
    context: SourceReadContext<'a>,
    native: &'a NativeLifecycle,
    island: &'a TrustedIsland,
    original: &'a AdmissionStop,
    event: &'a DynamicEvent,
    state: &'a TaskStateSnapshot,
    maps: &'a [u8],
    scratch: &'a InitialReadScratch,
}

impl<'a> RuntimeKernelSourceRead<'a> {
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
            + size_of::<RuntimeKernelReadCheckpoint<'_>>()
            + authentication.max(backing::temporary_bytes())
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn acquire(
        owner: &'a Owner,
        native: &'a NativeLifecycle,
        checkpoint: RuntimeKernelReadCheckpoint<'a>,
        scratch: &'a InitialReadScratch,
        until: Instant,
    ) -> Result<Self, GateError> {
        let RuntimeKernelReadCheckpoint {
            island,
            original,
            event,
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
            original,
            event,
            state,
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
        // Actual ENTRY/EXIT authority is separate from settled owned traps.
        // No synthetic AdmissionStop or UserCheckpoint is created here.
        self.native.require_runtime_kernel_event(
            context.owner,
            self.original,
            self.event,
            context.until,
            scratch.as_mut_slice(),
        )?;
        let token = self
            .event
            .stop_token()
            .ok_or_else(|| refused("runtime kernel source event has no token"))?;
        if self.event.task != Some(self.original.identity)
            || token.session != self.original.token.session
            || token.tid != self.original.token.tid
            || self.original.identity.address_space != self.island.address_space
            || self.original.identity.generation != 0
            || self.island.generation != 0
            || self.state.registers.cs != 0x33
            || self.state.xstate.len() < 512
            || self.state.xstate.len() >= MAP_BYTES
            || self.maps.is_empty()
            || self.maps.len() > MAP_BYTES
        {
            return Err(refused("runtime kernel source current observation differs"));
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
        if registers != self.state.registers
            || scratch[..vector.iov_len] != self.state.xstate
            || mask != self.state.mask
        {
            return Err(refused("runtime source complete current state differs"));
        }
        self.native.require_runtime_kernel_event(
            context.owner,
            self.original,
            self.event,
            context.until,
            scratch.as_mut_slice(),
        )?;
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
