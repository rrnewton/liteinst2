//! Real borrowed whole-mm exclusion on the original dedicated tracer thread.
use super::lifecycle::admission::MmMembership;
use super::trusted::{AdmissionPhase, AdmissionStop, TaskStateSnapshot, TrustedIsland};
use super::*;
use crate::lifecycle::TaskId;
use crate::publication::{PublicationOperations, PublicationStop, sealed};

pub(in crate::linux::remote::dynamic) struct HeldMmStop<'a> {
    pub(in crate::linux::remote::dynamic) owner: &'a mut Owner,
    pub(in crate::linux::remote::dynamic) native: &'a mut lifecycle::NativeLifecycle,
    pub(in crate::linux::remote::dynamic) island: &'a mut TrustedIsland,
    selected: TaskId,
    runner: TaskId,
    membership: MmMembership,
    siblings: Vec<(TaskId, DynamicStop, TaskStateSnapshot)>,
    maps: Vec<MemoryMapping>,
    until: Instant,
    // Neither the real ptrace owner nor this borrowed authority may cross threads.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl<'a> HeldMmStop<'a> {
    /// Native execution exclusion only. The caller still certifies aliases,
    /// outside readers/writers, complete entries, and saved continuations.
    pub(in crate::linux::remote::dynamic) fn acquire(
        owner: &'a mut Owner,
        native: &'a mut lifecycle::NativeLifecycle,
        island: &'a mut TrustedIsland,
        selected: TaskId,
        until: Instant,
    ) -> Result<Self, LaunchError> {
        owner.time_left(until, "whole-mm admission hold")?;
        let membership = native.check_admission_mm(owner, selected)?;
        if membership.address_space != island.address_space
            || membership.generation != island.generation
        {
            return Err(LaunchError::Invalid(
                "island belongs to another mm incarnation",
            ));
        }
        let runner = if native.admission_current(selected).is_ok() {
            selected
        } else {
            membership
                .candidate
                .tasks
                .iter()
                .copied()
                .find(|task| native.admission_current(*task).is_ok())
                .ok_or(LaunchError::Invalid(
                    "held mm has no qualified trusted runner",
                ))?
        };
        let mut siblings = Vec::new();
        for &task in &membership.candidate.tasks {
            if task != runner {
                let token = native.admission_held_token(task)?;
                siblings.push((task, token.clone(), TaskStateSnapshot::read(token.tid)?));
            }
        }
        let maps = island.verify(native.admission_current(runner)?.token.tid)?;
        let mut held = Self {
            owner,
            native,
            island,
            selected,
            runner,
            membership,
            siblings,
            maps,
            until,
            _thread: std::marker::PhantomData,
        };
        held.ready()?;
        // Acquiring authority does not execute even a private instruction. In
        // particular an owned signal can be acknowledged at its exact current
        // stop before a later operation consumes that stop incarnation.
        Ok(held)
    }

    pub(in crate::linux::remote::dynamic) fn selected_stop(
        &self,
    ) -> Result<AdmissionStop, LaunchError> {
        self.native.admission_current(self.selected)
    }
    pub(in crate::linux::remote::dynamic) fn selected_token(
        &self,
    ) -> Result<DynamicStop, LaunchError> {
        self.native.admission_held_token(self.selected)
    }
    pub(in crate::linux::remote::dynamic) fn membership(&self) -> &MmMembership {
        &self.membership
    }

    fn operation_deadline(&self, timeout: Duration) -> Result<Instant, LaunchError> {
        if timeout.is_zero() || timeout > MAX_LAUNCH_TIMEOUT {
            return Err(LaunchError::Invalid(
                "operation timeout must be in (0, 30 seconds]",
            ));
        }
        Ok((Instant::now() + timeout).min(self.until))
    }
    fn ready(&mut self) -> Result<(), LaunchError> {
        self.owner.time_left(self.until, "held mm transaction")?;
        let current = self.native.check_admission_mm(self.owner, self.selected)?;
        if current.address_space != self.membership.address_space
            || current.generation != self.membership.generation
            || current.process != self.membership.process
            || current.tgid != self.membership.tgid
            || current.tids != self.membership.tids
            || current.candidate.tasks != self.membership.candidate.tasks
            || current.candidate.obligations != self.membership.candidate.obligations
        {
            return Err(LaunchError::Invalid(
                "held mm identity or obligations changed",
            ));
        }
        for (id, token, state) in &self.siblings {
            if self.native.admission_held_token(*id)? != *token
                || TaskStateSnapshot::read(token.tid)? != *state
            {
                return Err(LaunchError::Invalid(
                    "trusted execution changed a held sibling",
                ));
            }
        }
        self.maps = self
            .island
            .verify(self.native.admission_current(self.runner)?.token.tid)?;
        self.membership = current;
        Ok(())
    }
    fn settle_interrupts_before(&mut self, until: Instant) -> Result<(), LaunchError> {
        loop {
            let stop = self.native.admission_current(self.runner)?;
            if self.native.admission_interrupt_credit(stop.token.tid)? == 0 {
                return Ok(());
            }
            let registers =
                trusted::temporary(&read_registers(stop.token.tid)?, self.island.trap());
            trusted::execute(
                self.owner,
                self.native,
                &stop,
                (self.island.trap(), &[0xcc]),
                registers,
                true,
                until,
            )?;
            self.ready()?;
        }
    }
    /// Settle only this hold's already-qualified private runner. Each credit
    /// is consumed by actual neutral island stops; no generic Interrupted event
    /// is converted into an injection permit. Full sibling and runner state
    /// restoration remains the same as every other trusted operation.
    pub(in crate::linux::remote::dynamic) fn settle_owned_controls(
        &mut self,
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.ready()?;
        let until = self.operation_deadline(timeout)?;
        let result = (|| {
            let current = self.native.admission_current(self.runner)?;
            if current.phase == AdmissionPhase::Guard {
                return Err(LaunchError::Invalid(
                    "raw guard must be normalized before private control settlement",
                ));
            }
            // A captured NX fault cannot remain the current signal proof after
            // publication grants X. Retain its original observation in census,
            // then create an actual private checkpoint before changing source
            // permissions. Even zero interrupt credit needs this one real stop.
            if current.phase == AdmissionPhase::Fetch {
                let registers =
                    trusted::temporary(&read_registers(current.token.tid)?, self.island.trap());
                trusted::execute(
                    self.owner,
                    self.native,
                    &current,
                    (self.island.trap(), &[0xcc]),
                    registers,
                    true,
                    until,
                )?;
                self.ready()?;
            }
            self.settle_interrupts_before(until)?;
            self.ready()
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }
    fn syscall(
        &mut self,
        number: libc::c_long,
        arguments: [u64; 6],
        until: Instant,
    ) -> Result<u64, LaunchError> {
        self.ready()?;
        self.settle_interrupts_before(until)?;
        let stop = self.native.admission_current(self.runner)?;
        let mut registers =
            trusted::temporary(&read_registers(stop.token.tid)?, self.island.range.start);
        registers.rax = number as u64;
        registers.rdi = arguments[0];
        registers.rsi = arguments[1];
        registers.rdx = arguments[2];
        registers.r10 = arguments[3];
        registers.r8 = arguments[4];
        registers.r9 = arguments[5];
        let (value, _) = trusted::execute(
            self.owner,
            self.native,
            &stop,
            (self.island.range.start, &STUB),
            registers,
            false,
            until,
        )?;
        self.ready()?;
        Ok(value)
    }
    fn range(&self, address: u64, len: usize, expected: Option<&str>) -> Result<(), LaunchError> {
        let end = address
            .checked_add(len as u64)
            .ok_or(LaunchError::Invalid("publication range overflow"))?;
        if len == 0 || address < self.island.range.end && self.island.range.start < end {
            return Err(LaunchError::Invalid(
                "publication range overlaps private island",
            ));
        }
        let mut cursor = address;
        for mapping in &self.maps {
            if mapping.end <= cursor || mapping.start >= end {
                continue;
            }
            if mapping.start > cursor
                || mapping.permissions.as_bytes().get(3) != Some(&b'p')
                || expected.is_some_and(|expected| expected != mapping.permissions)
            {
                return Err(LaunchError::Invalid(
                    "publication range is not continuously private",
                ));
            }
            cursor = mapping.end.min(end);
        }
        if cursor != end {
            return Err(LaunchError::Invalid("publication range contains a hole"));
        }
        Ok(())
    }
    fn fail<T>(&mut self, error: LaunchError) -> Result<T, LaunchError> {
        self.owner.closing = true;
        self.owner.cancel.store(true, Ordering::Release);
        // This runs on the original tracer. Client timeout may return while
        // cleanup retains these actual pins/stops; no application release is
        // reachable. Return to the caller only after the existing owner finishes.
        let _ = self.owner.cleanup();
        Err(error)
    }

    pub(in crate::linux::remote::dynamic) fn write_memory_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<(), LaunchError> {
        self.ready()?;
        if expected.len() != replacement.len()
            || expected.is_empty()
            || expected.len() > MAX_MEMORY_READ
        {
            return Err(LaunchError::Invalid("invalid stopped publication write"));
        }
        let end = address
            .checked_add(expected.len() as u64)
            .ok_or(LaunchError::Invalid("publication write overflow"))?;
        let start = address & !7;
        let envelope_end = end
            .checked_add(7)
            .ok_or(LaunchError::Invalid("publication envelope overflow"))?
            & !7;
        self.range(start, (envelope_end - start) as usize, Some("rw-p"))?;
        let tid = self.selected_token()?.tid;
        let mut envelope = read_memory(tid, start, (envelope_end - start) as usize)?;
        let offset = (address - start) as usize;
        if &envelope[offset..offset + expected.len()] != expected {
            return Err(LaunchError::Invalid("publication expected bytes mismatch"));
        }
        envelope[offset..offset + replacement.len()].copy_from_slice(replacement);
        let result = (|| {
            poke_bytes(tid, address, replacement)?;
            if read_memory(tid, start, envelope.len())? != envelope {
                return Err(LaunchError::Invalid(
                    "publication write or neighbors differ",
                ));
            }
            self.ready()
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }

    pub(in crate::linux::remote::dynamic) fn map_private_code(
        &mut self,
        address: u64,
        image: &[u8],
        timeout: Duration,
    ) -> Result<Range<u64>, LaunchError> {
        self.ready()?;
        let until = self.operation_deadline(timeout)?;
        let end = address
            .checked_add(image.len() as u64)
            .ok_or(LaunchError::Invalid("private image overflow"))?;
        if address == 0
            || address % self.island.page_size as u64 != 0
            || image.is_empty()
            || image.len() > MAX_MEMORY_READ
            || image.len() % self.island.page_size != 0
            || self.maps.iter().any(|m| address < m.end && m.start < end)
        {
            return Err(LaunchError::Invalid("invalid or occupied private image"));
        }
        let result = (|| {
            let allocated = syscall_result(
                self.syscall(
                    libc::SYS_mmap,
                    [
                        address,
                        image.len() as u64,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE)
                            as u64,
                        u64::MAX,
                        0,
                    ],
                    until,
                )?,
                "admission private allocation",
            )?;
            if allocated != address {
                return Err(LaunchError::Invalid(
                    "private allocation returned another address",
                ));
            }
            self.range(address, image.len(), Some("rw-p"))?;
            if self
                .maps
                .iter()
                .any(|m| address < m.end && m.start < end && m.pathname.is_some())
            {
                return Err(LaunchError::Invalid("private allocation has backing"));
            }
            let before = read_memory(self.selected_token()?.tid, address, image.len())?;
            if before.iter().any(|byte| *byte != 0) {
                return Err(LaunchError::Invalid("private allocation is not zeroed"));
            }
            self.write_memory_checked(address, &before, image)?;
            self.mprotect(
                address,
                image.len(),
                libc::PROT_READ | libc::PROT_EXEC,
                remaining(until)?,
            )?;
            self.sync_core(remaining(until)?)?;
            if read_memory(self.selected_token()?.tid, address, image.len())? != image {
                return Err(LaunchError::Invalid(
                    "private code changed after finalization",
                ));
            }
            Ok(address..end)
        })();
        match result {
            Ok(range) => Ok(range),
            Err(error) => self.fail(error),
        }
    }

    pub(in crate::linux::remote::dynamic) fn exact_store_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.ready()?;
        let until = self.operation_deadline(timeout)?;
        let index = match expected.len() {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => return Err(LaunchError::Invalid("invalid exact store width")),
        };
        if expected.len() != replacement.len() {
            return Err(LaunchError::Invalid("exact store lengths differ"));
        }
        let end = address
            .checked_add(expected.len() as u64)
            .ok_or(LaunchError::Invalid("store overflow"))?;
        let start = address & !7;
        let envelope_end = end
            .checked_add(7)
            .ok_or(LaunchError::Invalid("store envelope overflow"))?
            & !7;
        self.range(start, (envelope_end - start) as usize, Some("rw-p"))?;
        let mut after = read_memory(
            self.selected_token()?.tid,
            start,
            (envelope_end - start) as usize,
        )?;
        let offset = (address - start) as usize;
        if &after[offset..offset + expected.len()] != expected {
            return Err(LaunchError::Invalid("exact store expected bytes mismatch"));
        }
        after[offset..offset + replacement.len()].copy_from_slice(replacement);
        let mut value = [0; 8];
        value[..replacement.len()].copy_from_slice(replacement);
        self.settle_interrupts_before(until)?;
        let stop = self.native.admission_current(self.runner)?;
        let (at, bytes) = STORE_STUBS[index];
        let pc = self.island.range.start + at as u64;
        let mut registers = trusted::temporary(&read_registers(stop.token.tid)?, pc);
        registers.rdi = address;
        registers.rax = u64::from_le_bytes(value);
        let result = (|| {
            trusted::execute(
                self.owner,
                self.native,
                &stop,
                (pc, bytes),
                registers,
                true,
                until,
            )?;
            if read_memory(self.selected_token()?.tid, start, after.len())? != after {
                return Err(LaunchError::Invalid("exact store changed unexpected bytes"));
            }
            self.ready()
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }
    pub(in crate::linux::remote::dynamic) fn mprotect(
        &mut self,
        address: u64,
        len: usize,
        protection: i32,
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.ready()?;
        let until = self.operation_deadline(timeout)?;
        if len == 0
            || address % self.island.page_size as u64 != 0
            || len % self.island.page_size != 0
            || protection & !(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0
            || protection & (libc::PROT_WRITE | libc::PROT_EXEC)
                == libc::PROT_WRITE | libc::PROT_EXEC
        {
            return Err(LaunchError::Invalid(
                "invalid permission range or RWX protection",
            ));
        }
        self.range(address, len, None)?;
        let result = (|| {
            syscall_result(
                self.syscall(
                    libc::SYS_mprotect,
                    [address, len as u64, protection as u64, 0, 0, 0],
                    until,
                )?,
                "admission mprotect",
            )?;
            self.range(address, len, None)?;
            let end = address + len as u64;
            if self
                .maps
                .iter()
                .filter(|m| address < m.end && m.start < end)
                .any(|m| super_protection(m).ok() != Some(protection))
            {
                return Err(LaunchError::Invalid("admission permissions did not verify"));
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }
    pub(in crate::linux::remote::dynamic) fn sync_core(
        &mut self,
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        let until = self.operation_deadline(timeout)?;
        let result = self
            .syscall(libc::SYS_membarrier, [SYNC_CORE, 0, 0, 0, 0, 0], until)
            .and_then(|result| syscall_result(result, "admission sync-core").map(|_| ()));
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }
}

struct MmOperations<'scope, 'borrow, 'owner> {
    held: &'scope RefCell<&'borrow mut HeldMmStop<'owner>>,
}
struct MmExclusion<'scope, 'borrow, 'owner> {
    held: &'scope RefCell<&'borrow mut HeldMmStop<'owner>>,
}
impl sealed::Sealed for HeldMmStop<'_> {}
impl sealed::Sealed for MmOperations<'_, '_, '_> {}
impl PublicationStop for HeldMmStop<'_> {
    fn pid(&self) -> i32 {
        self.membership.tgid
    }
    fn page_size(&self) -> usize {
        self.island.page_size
    }
    fn mappings(&self) -> Vec<MemoryMapping> {
        self.maps.clone()
    }
    fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        read_memory(self.selected_token()?.tid, address, len)
    }
    fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        read_registers(self.selected_token()?.tid)
    }
    fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        xstate(self.selected_token()?.tid)
    }
    fn acknowledge_owned_signal(&mut self, event: &SignalStop) -> Result<(), LaunchError> {
        let stop = self.selected_stop()?;
        self.native.require_admission_stop(&stop)?;
        let signal = stop.signal.as_ref().ok_or(LaunchError::Invalid(
            "selected admission stop has no pending owned signal",
        ))?;
        let mut raw = [0_u8; 128];
        ptrace(
            libc::PTRACE_GETSIGINFO,
            stop.token.tid,
            0,
            raw.as_mut_ptr() as usize,
        )?;
        if signal.view != *event || signal.raw != raw {
            return Err(LaunchError::Invalid(
                "owned signal differs from exact native admission stop",
            ));
        }
        Ok(())
    }
    unsafe fn with_publication_lease<T>(
        &mut self,
        identity: CodeIdentity,
        ranges: Vec<AddressRange>,
        action: impl FnOnce(
            &mut dyn PublicationOperations,
            &mut QuiescenceLease<'_>,
        ) -> Result<T, LaunchError>,
    ) -> Result<T, LaunchError> {
        if let Err(error) = self.ready() {
            return self.fail(error);
        }
        let outcome = {
            let held = RefCell::new(&mut *self);
            let mut guard = MmExclusion { held: &held };
            let mut operations = MmOperations { held: &held };
            // SAFETY: caller certifies the complete core contract. This guard
            // borrows actual held owner/control for the entire non-Send lease.
            let _actual_borrow = guard.held;
            let mut lease = unsafe { QuiescenceLease::new(&mut guard, identity, ranges) };
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match action(&mut operations, &mut lease) {
                    Ok(value) if lease.is_poisoned() => {
                        drop(value);
                        Err(LaunchError::Invalid(
                            "dynamic publication lease remained poisoned",
                        ))
                    }
                    result => result,
                }
            }))
        };
        match outcome {
            Ok(Ok(value)) => match self.ready() {
                Ok(()) => Ok(value),
                Err(error) => self.fail(error),
            },
            Ok(Err(error)) => self.fail(error),
            Err(payload) => {
                let _ = self.fail::<()>(LaunchError::Invalid("dynamic publication unwound"));
                std::panic::resume_unwind(payload)
            }
        }
    }
}
impl PublicationOperations for MmOperations<'_, '_, '_> {
    fn pid(&self) -> i32 {
        self.held.borrow().pid()
    }
    fn page_size(&self) -> usize {
        self.held.borrow().page_size()
    }
    fn mappings(&self) -> Vec<MemoryMapping> {
        self.held.borrow().mappings()
    }
    fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        self.held.borrow().read_memory(address, len)
    }
    fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        self.held.borrow().read_registers()
    }
    fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        self.held.borrow().read_xstate()
    }
    fn map_private_code(
        &mut self,
        address: u64,
        image: &[u8],
        timeout: Duration,
    ) -> Result<Range<u64>, LaunchError> {
        self.held
            .borrow_mut()
            .map_private_code(address, image, timeout)
    }
    fn exact_store_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.held
            .borrow_mut()
            .exact_store_checked(address, expected, replacement, timeout)
    }
    fn mprotect(
        &mut self,
        address: u64,
        len: usize,
        protection: i32,
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.held
            .borrow_mut()
            .mprotect(address, len, protection, timeout)
    }
    fn sync_core(&mut self, timeout: Duration) -> Result<(), LaunchError> {
        self.held.borrow_mut().sync_core(timeout)
    }
}
