//! Empty installed ownership and exact in-place capacities. These records are
//! descriptive storage, never a successful capture or an executable permit.
use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum AllocationState {
    #[default]
    Empty,
    Allocating,
    Ready,
    Failed,
    Aborted,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct AllocationProgress {
    pub(in crate::linux::remote::dynamic::owner::admission) state: AllocationState,
    pub(in crate::linux::remote::dynamic::owner::admission) retained_payload: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) failed_slot: Option<usize>,
    pub(in crate::linux::remote::dynamic::owner::admission) first_failure: Option<StackError>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ReadRecord {
    pub(in crate::linux::remote::dynamic::owner::admission) fd: i32,
    pub(in crate::linux::remote::dynamic::owner::admission) destination: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) count: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) request: Request,
}
/// One complete bounded metadata file. Intermediate successful requests are
/// represented by the retained concatenated prefix and count, not fictitious
/// per-call records. First and last exact requests are retained separately.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct FileCapture {
    pub(in crate::linux::remote::dynamic::owner::admission) started: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) complete: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) directory_open: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) directory_statfs: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) directory_filesystem: Option<i64>,
    pub(in crate::linux::remote::dynamic::owner::admission) file_open: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) file_statfs: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) file_filesystem: Option<i64>,
    pub(in crate::linux::remote::dynamic::owner::admission) first_read: Option<ReadRecord>,
    pub(in crate::linux::remote::dynamic::owner::admission) last_read: Option<ReadRecord>,
    pub(in crate::linux::remote::dynamic::owner::admission) read_calls: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) copied: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) overflow: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) file_close: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) directory_close: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) first_failure: Option<StackError>,
}
impl FileCapture {
    pub(in crate::linux::remote::dynamic::owner::admission) fn bytes<'a>(
        &self,
        initialized: &'a [u8],
    ) -> Result<&'a [u8], StackError> {
        let success = Some(Request {
            result: 0,
            errno: None,
        });
        let directory = self.directory_open.ok_or(StackError::Incomplete)?;
        let file = self.file_open.ok_or(StackError::Incomplete)?;
        let first = self.first_read.ok_or(StackError::Incomplete)?;
        let last = self.last_read.ok_or(StackError::Incomplete)?;
        if !self.started
            || !self.complete
            || self.first_failure.is_some()
            || self.overflow
            || initialized.len() != BYTES
            || self.copied == 0
            || self.copied > BYTES
            || !(2..=BYTES + 1).contains(&self.read_calls)
            || directory.errno.is_some()
            || directory.result < 0
            || directory.result > i64::from(i32::MAX)
            || file.errno.is_some()
            || file.result < 0
            || file.result > i64::from(i32::MAX)
            || directory.result == file.result
            || self.directory_statfs != success
            || self.file_statfs != success
            || self.directory_filesystem != Some(libc::PROC_SUPER_MAGIC)
            || self.file_filesystem != Some(libc::PROC_SUPER_MAGIC)
            || self.file_close != success
            || self.directory_close != success
            || i64::from(first.fd) != file.result
            || i64::from(last.fd) != file.result
            || first.destination != initialized.as_ptr() as usize
            || first.count != BYTES
            || first.request.errno.is_some()
            || first.request.result <= 0
            || first.request.result as usize > self.copied
            || last.request
                != (Request {
                    result: 0,
                    errno: None,
                })
            || last.count
                != (if self.copied == BYTES {
                    1
                } else {
                    BYTES - self.copied
                })
        {
            return Err(StackError::Request);
        }
        // All calls except the terminal EOF must make positive progress. The
        // concatenated prefix must be feasible even when intermediate positive
        // request records are deliberately summarized rather than duplicated.
        let remaining_calls = self.read_calls.checked_sub(2).ok_or(StackError::Request)?;
        let first_bytes = usize::try_from(first.request.result).map_err(|_| StackError::Request)?;
        let remaining_bytes = self
            .copied
            .checked_sub(first_bytes)
            .ok_or(StackError::Request)?;
        if (remaining_calls == 0) != (remaining_bytes == 0) || remaining_bytes < remaining_calls {
            return Err(StackError::Request);
        }
        if self.copied < BYTES && last.destination != initialized.as_ptr() as usize + self.copied {
            return Err(StackError::Request);
        }
        if self.copied == BYTES && last.destination == 0 {
            return Err(StackError::Request);
        }
        Ok(&initialized[..self.copied])
    }
}

pub(in crate::linux::remote::dynamic::owner::admission) struct StackObservationStorage {
    pub(in crate::linux::remote::dynamic::owner::admission) smaps: Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner::admission) maps: Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner::admission) state: StateSlot,
    pub(in crate::linux::remote::dynamic::owner::admission) smaps_capture: FileCapture,
    pub(in crate::linux::remote::dynamic::owner::admission) maps_capture: FileCapture,
    pub(in crate::linux::remote::dynamic::owner::admission) allocation: AllocationProgress,
    #[cfg(test)]
    fault: AllocationFault,
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) installed_pointers: [Option<usize>; 3],
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::linux::remote::dynamic::owner::admission) struct AllocationFault {
    pub(in crate::linux::remote::dynamic::owner::admission) fail_before: Option<usize>,
    pub(in crate::linux::remote::dynamic::owner::admission) panic_after: Option<usize>,
}
impl StackObservationStorage {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            smaps: Vec::new(),
            maps: Vec::new(),
            state: empty_state(),
            smaps_capture: FileCapture::default(),
            maps_capture: FileCapture::default(),
            allocation: AllocationProgress::default(),
            #[cfg(test)]
            fault: AllocationFault::default(),
            #[cfg(test)]
            installed_pointers: [None; 3],
        }
    }
    /// Exact owned header plus three independent MAX payloads. Root subtracts
    /// this header if embedded in a larger already-counted owner.
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_bytes()
    -> Result<usize, StackError> {
        add(size_of::<Self>(), 3 * BYTES)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_payloads(
        &mut self,
    ) -> Result<(), StackError> {
        if self.allocation != AllocationProgress::default()
            || self.smaps.capacity() != 0
            || self.maps.capacity() != 0
            || self.state.state.xstate.capacity() != 0
        {
            return Err(StackError::Reused);
        }
        self.allocation.state = AllocationState::Allocating;
        for slot in 0..3 {
            let next = match add(self.allocation.retained_payload, BYTES) {
                Ok(next) => next,
                Err(error) => return self.allocation_failed(slot, error),
            };
            #[cfg(test)]
            if self.fault.fail_before == Some(slot) {
                return self.allocation_failed(slot, StackError::Allocation);
            }
            let bytes = match exact_storage::empty_bytes(BYTES) {
                Ok(bytes) => bytes,
                Err(error) => return self.allocation_failed(slot, error.into()),
            };
            // Fixed slot selection cannot fail. Ownership is installed before
            // tally assignment and before any later allocation/test hook.
            let destination = match slot {
                0 => &mut self.smaps,
                1 => &mut self.maps,
                _ => &mut self.state.state.xstate,
            };
            *destination = bytes;
            self.allocation.retained_payload = next;
            // Capacity is exact BYTES, so initialization cannot reallocate.
            destination.resize(BYTES, 0);
            #[cfg(test)]
            {
                self.installed_pointers[slot] = Some(destination.as_ptr() as usize);
            }
            #[cfg(test)]
            if self.fault.panic_after == Some(slot) {
                panic!("owned stack allocation model unwind");
            }
        }
        self.allocation.state = AllocationState::Ready;
        Ok(())
    }
    fn allocation_failed(&mut self, slot: usize, error: StackError) -> Result<(), StackError> {
        self.allocation.state = AllocationState::Failed;
        self.allocation.failed_slot = Some(slot);
        self.allocation.first_failure.get_or_insert(error);
        Err(error)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        if self.allocation.state == AllocationState::Allocating {
            self.allocation.state = AllocationState::Aborted;
            self.allocation
                .first_failure
                .get_or_insert(StackError::Aborted);
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn payload_bytes(
        &self,
    ) -> Result<usize, StackError> {
        let capacities = [
            self.smaps.capacity(),
            self.maps.capacity(),
            self.state.state.xstate.capacity(),
        ];
        if capacities
            .iter()
            .any(|capacity| !matches!(*capacity, 0 | BYTES))
        {
            return Err(StackError::Capacity);
        }
        let bytes = add(add(capacities[0], capacities[1])?, capacities[2])?;
        if bytes != self.allocation.retained_payload {
            return Err(StackError::Capacity);
        }
        Ok(bytes)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocated_bytes(
        &self,
    ) -> Result<usize, StackError> {
        add(size_of::<Self>(), self.payload_bytes()?)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_ready(
        &self,
    ) -> Result<(), StackError> {
        if self.allocation.state != AllocationState::Ready
            || self.allocation.first_failure.is_some()
            || self.payload_bytes()? != 3 * BYTES
        {
            return Err(StackError::Incomplete);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn set_fault(
        &mut self,
        fault: AllocationFault,
    ) {
        assert_eq!(self.allocation.state, AllocationState::Empty);
        self.fault = fault;
    }
}

/// The existing raw reader's exact storage shape, without modifying its reader
/// or allocating a payload. No completed request is synthesized here.
fn empty_state() -> StateSlot {
    let registers = RegisterSnapshot {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        orig_rax: 0,
        rip: 0,
        cs: 0,
        eflags: 0,
        rsp: 0,
        ss: 0,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    };
    StateSlot {
        state: TaskStateSnapshot {
            registers,
            xstate: Vec::new(),
            mask: 0,
        },
        registers_request: None,
        xstate_request: None,
        mask_request: None,
        requested_pointer: 0,
        returned_pointer: 0,
        returned_length: 0,
        complete: false,
    }
}

/// The two separately owned startup index arrays. The concrete future attempt
/// and CALL types determine headers; these payloads are not hidden in profile.
pub(in crate::linux::remote::dynamic::owner::admission) fn history_payload_bytes<A, C>(
    count: usize,
) -> Result<usize, StackError> {
    let attempts = std::alloc::Layout::array::<Option<Box<A>>>(count)
        .map_err(|_| StackError::Capacity)?
        .size();
    let calls = std::alloc::Layout::array::<Option<Box<C>>>(count)
        .map_err(|_| StackError::Capacity)?
        .size();
    add(attempts, calls)
}
