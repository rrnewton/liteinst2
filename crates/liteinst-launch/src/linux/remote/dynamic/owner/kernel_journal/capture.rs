use super::*;

impl KernelJournalWriter {
    fn raw_header(
        &mut self,
        handle: KernelAttemptHandle,
        tid: i32,
        status: i32,
        pin: KernelPinKind,
    ) -> Result<u8, LaunchError> {
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        if self.active != Some(handle) {
            return Err(invalid("kernel journal raw attempt is not active"));
        }
        attempt.stage = KernelJournalStage::RawCapture;
        let record = attempt.raw_count;
        let next = record
            .checked_add(1)
            .ok_or(invalid("kernel journal raw count exhausted"))?;
        let task = (tid == attempt.binding.original_stop.token.tid)
            .then_some(attempt.binding.original_stop.identity);
        attempt.append(KernelJournalFact::RawStop {
            record,
            tid,
            status,
            pin,
            task,
        })?;
        attempt.raw_count = next;
        Ok(record)
    }

    fn parent_tid(&self, handle: KernelAttemptHandle) -> Result<i32, LaunchError> {
        Ok(Self::attempt_mut(&mut self.lock(), handle)?
            .binding
            .original_stop
            .token
            .tid)
    }

    // The buffer leaves the archive while ptrace runs. Readers see InProgress,
    // never partly initialized state. An unwind leaves that explicit status.
    fn capture_state(
        &mut self,
        handle: KernelAttemptHandle,
        slot: KernelStateSlot,
        tid: i32,
    ) -> Result<(), LaunchError> {
        let mut bytes = {
            let mut archive = self.lock();
            let attempt = Self::attempt_mut(&mut archive, handle)?;
            let state = &mut attempt.states[slot.index()];
            if state.status != KernelCaptureStatus::Unused {
                return Err(invalid("kernel journal state slot was already used"));
            }
            state.status = KernelCaptureStatus::InProgress;
            state
                .bytes
                .take()
                .ok_or(invalid("kernel journal reserved buffer is absent"))?
        };
        let result = read_complete_into(tid, &mut bytes);
        let mut archive = self.lock();
        let attempt = Self::attempt_mut(&mut archive, handle)?;
        let state = &mut attempt.states[slot.index()];
        state.bytes = Some(bytes);
        match result {
            Ok((registers, length, mask)) => {
                state.registers = Some(registers);
                state.length = length;
                state.mask = mask;
                state.status = KernelCaptureStatus::Complete;
                Ok(())
            }
            Err(error) => {
                let kind = failure_kind(&error);
                state.status = KernelCaptureStatus::Failed(kind);
                attempt.fail(kind);
                Err(error)
            }
        }
    }

    fn bind_raw_state(
        &mut self,
        handle: KernelAttemptHandle,
        record: u8,
        slot: KernelStateSlot,
        tid: i32,
    ) -> Result<(), LaunchError> {
        {
            let mut archive = self.lock();
            let attempt = Self::attempt_mut(&mut archive, handle)?;
            if attempt.raw_slots[slot.index()].is_some() {
                return Err(invalid("kernel journal raw phase repeated"));
            }
            attempt.raw_slots[slot.index()] = Some(record);
        }
        self.capture_state(handle, slot, tid)?;
        self.append(handle, KernelJournalFact::StateCaptured { record, slot })
    }

    pub(in crate::linux::remote::dynamic::owner) fn capture_bridge(
        &mut self,
        handle: KernelAttemptHandle,
        slot: KernelStateSlot,
        stop: &AdmissionStop,
    ) -> Result<(), LaunchError> {
        if !matches!(
            slot,
            KernelStateSlot::ParentBridge | KernelStateSlot::NewbornBridge
        ) {
            return Err(invalid("kernel journal bridge slot differs"));
        }
        self.capture_state(handle, slot, stop.token.tid)?;
        self.bridge_committed(handle, slot, stop)
    }
}

// This helper performs only read requests. Its caller already owns the held
// wait identity; it does not advance lifecycle phase or manufacture a token.
fn read_complete_into(
    tid: i32,
    bytes: &mut [u8],
) -> Result<(RegisterSnapshot, usize, u64), LaunchError> {
    if bytes.len() != MAX_XSTATE {
        return Err(invalid("kernel journal reserved state length differs"));
    }
    let registers = read_registers(tid)?;
    let pointer = bytes.as_mut_ptr();
    let mut iov = libc::iovec {
        iov_base: pointer.cast(),
        iov_len: bytes.len(),
    };
    ptrace(
        libc::PTRACE_GETREGSET,
        tid,
        0x202,
        (&mut iov as *mut libc::iovec) as usize,
    )?;
    if iov.iov_base != pointer.cast() || iov.iov_len < 512 || iov.iov_len >= MAX_XSTATE {
        return Err(invalid("kernel journal XSTATE read is incomplete"));
    }
    let mask = launch::task_mask(tid)?;
    Ok((registers, iov.iov_len, mask))
}

impl Owner {
    /// Called immediately after an actual wait, before lifecycle dispatch can
    /// reject ABI/CET/inheritance/phase. A queued event never calls this again.
    pub(in crate::linux::remote::dynamic::owner) fn capture_kernel_raw(
        &mut self,
        handle: KernelAttemptHandle,
        tid: i32,
        status: i32,
    ) -> Result<(), LaunchError> {
        let result = self.capture_kernel_raw_inner(handle, tid, status);
        if let Err(error) = &result {
            self.kernel_journal.fail_active(failure_kind(error));
        }
        result
    }

    fn capture_kernel_raw_inner(
        &mut self,
        handle: KernelAttemptHandle,
        tid: i32,
        status: i32,
    ) -> Result<(), LaunchError> {
        let held = self.owned.contains(&tid) && self.stopped.get(&tid) == Some(&status);
        let terminal = self.tracer_terminal.get(&tid) == Some(&status);
        if (!held && !terminal) || !self.handles.contains_key(&tid) {
            return Err(invalid(
                "kernel journal lacks the original wait incarnation",
            ));
        }
        let pin = match self.pin_kinds.get(&tid) {
            Some(PinKind::Process) => KernelPinKind::Process,
            Some(PinKind::Thread) => KernelPinKind::Thread,
            None => return Err(invalid("kernel journal wait has no pin kind")),
        };
        let record = self.kernel_journal.raw_header(handle, tid, status, pin)?;
        if !libc::WIFSTOPPED(status) {
            return Ok(());
        }
        let parent = self.kernel_journal.parent_tid(handle)?;
        let slot = if libc::WSTOPSIG(status) == (libc::SIGTRAP | 0x80) && status >> 16 == 0 {
            let mut initialized = [0_u8; 88];
            // SAFETY: initialized is a writable complete native ABI buffer;
            // this read-only request returns its actual kernel byte count.
            let returned = unsafe {
                libc::ptrace(
                    libc::PTRACE_GET_SYSCALL_INFO,
                    tid,
                    initialized.len(),
                    initialized.as_mut_ptr(),
                )
            };
            if returned == -1 {
                return Err(system("kernel journal GET_SYSCALL_INFO"));
            }
            let info = KernelSyscallInfo {
                returned_bytes: usize::try_from(returned)
                    .map_err(|_| invalid("kernel journal syscall length is negative"))?,
                initialized,
            };
            self.kernel_journal
                .append(handle, KernelJournalFact::SyscallInfo { record, info })?;
            match (tid == parent, info.operation(), info.returned_bytes) {
                (true, 1, 80..=88) => KernelStateSlot::Entry,
                (true, 2, 33..=88) => KernelStateSlot::Exit,
                _ => KernelStateSlot::Unexpected,
            }
        } else if tid == parent
            && libc::WSTOPSIG(status) == libc::SIGTRAP
            && status >> 16 == libc::PTRACE_EVENT_CLONE
        {
            let mut value = 0_u64;
            ptrace(
                libc::PTRACE_GETEVENTMSG,
                tid,
                0,
                (&mut value as *mut u64) as usize,
            )?;
            self.kernel_journal
                .append(handle, KernelJournalFact::EventMessage { record, value })?;
            KernelStateSlot::Creation
        } else if tid != parent
            && libc::WSTOPSIG(status) == libc::SIGTRAP
            && status >> 16 == libc::PTRACE_EVENT_STOP
        {
            KernelStateSlot::Newborn
        } else {
            KernelStateSlot::Unexpected
        };
        self.kernel_journal
            .bind_raw_state(handle, record, slot, tid)?;
        #[cfg(test)]
        self.journal_fault_at(match slot {
            KernelStateSlot::Entry => JournalFaultPoint::AfterRawEntry,
            KernelStateSlot::Newborn => JournalFaultPoint::AfterRawNewborn,
            _ => return Ok(()),
        })?;
        Ok(())
    }
}
