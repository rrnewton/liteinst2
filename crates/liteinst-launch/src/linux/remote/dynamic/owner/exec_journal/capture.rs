use super::*;

fn outcome(result: i64) -> ExecReadOutcome {
    ExecReadOutcome {
        result,
        errno: (result == -1)
            .then(|| io::Error::last_os_error().raw_os_error())
            .flatten(),
    }
}
fn checked(
    read: Option<ExecReadOutcome>,
    name: &'static str,
    zero: bool,
) -> Result<(), LaunchError> {
    let read = read.ok_or(invalid("exec journal required read was not attempted"))?;
    if read.result == -1 {
        return Err(io_error(
            name,
            io::Error::from_raw_os_error(read.errno.unwrap_or(libc::EIO)),
        ));
    }
    if read.result < 0 || (zero && read.result != 0) {
        return Err(invalid("exec journal read result differs"));
    }
    Ok(())
}
fn state_reads(record: &mut ExecRawRecord) {
    // SAFETY: initialized scalar storage and the actual held task are supplied
    // by the pinned-wait owner. Every call here is a read-only ptrace request.
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            record.tid,
            0,
            &mut regs as *mut libc::user_regs_struct,
        )
    };
    record.registers_read = Some(outcome(result));
    record.registers = regs.into();
    let pointer = record.initialized_xstate.as_mut_ptr();
    let mut iov = libc::iovec {
        iov_base: pointer.cast(),
        iov_len: MAX_XSTATE,
    };
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            record.tid,
            NT_X86_XSTATE,
            &mut iov as *mut libc::iovec,
        )
    };
    let result = outcome(result);
    record.xstate_query = Some(ExecXstateQuery {
        outcome: result,
        reported_bytes: iov.iov_len,
        pointer_unchanged: iov.iov_base == pointer.cast(),
    });
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETSIGMASK,
            record.tid,
            8,
            &mut record.signal_mask as *mut u64,
        )
    };
    record.mask_read = Some(outcome(result));
}
fn info_reads(record: &mut ExecRawRecord) {
    // These outcomes are independently retained even if another read failed.
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            record.tid,
            record.syscall_info.len(),
            record.syscall_info.as_mut_ptr(),
        )
    };
    record.syscall_read = Some(outcome(result));
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            record.tid,
            0,
            &mut record.event_message as *mut u64,
        )
    };
    record.event_read = Some(outcome(result));
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETSIGINFO,
            record.tid,
            0,
            record.siginfo.as_mut_ptr(),
        )
    };
    record.siginfo_read = Some(outcome(result));
}
fn maps_path(tid: i32) -> Result<[u8; 32], LaunchError> {
    if tid <= 0 {
        return Err(invalid("exec journal maps task is invalid"));
    }
    let mut path = [0; 32];
    path[..6].copy_from_slice(b"/proc/");
    let mut digits = [0; 10];
    let mut remaining = tid as u32;
    let mut used = 0;
    while remaining != 0 {
        digits[used] = b'0' + (remaining % 10) as u8;
        used += 1;
        remaining /= 10;
    }
    for index in 0..used {
        path[6 + index] = digits[used - index - 1];
    }
    path[6 + used..11 + used].copy_from_slice(b"/maps");
    Ok(path)
}
fn capture_maps(
    record: &mut ExecMapsRecord,
    tid: i32,
    status: i32,
    until: Instant,
) -> Result<(), LaunchError> {
    if record.status != ExecMapsStatus::Unused || record.initialized.len() != MAP_BYTES {
        return Err(invalid(
            "exec journal maps storage is repeated or incomplete",
        ));
    }
    record.status = ExecMapsStatus::InProgress;
    record.tid = tid;
    record.raw_status = status;
    let result = capture_maps_inner(record, until);
    if let Err(error) = &result {
        record.status = ExecMapsStatus::Failed(failure(error));
    }
    result
}
fn capture_maps_inner(record: &mut ExecMapsRecord, until: Instant) -> Result<(), LaunchError> {
    check_time(until)?;
    let path = maps_path(record.tid)?;
    // SAFETY: fixed NUL-terminated procfs path; no application pointer is used.
    let fd = unsafe {
        libc::open(
            path.as_ptr().cast(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    record.open = Some(outcome(i64::from(fd)));
    checked(record.open, "exec journal maps open", false)?;
    // Every success/error below closes this exact descriptor before returning.
    let read_result = (|| {
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::fstatfs(fd, &mut stat) };
        record.filesystem = Some(outcome(i64::from(result)));
        record.filesystem_type = stat.f_type;
        checked(record.filesystem, "exec journal maps filesystem", true)?;
        if stat.f_type != libc::PROC_SUPER_MAGIC {
            return Err(invalid("exec journal maps is not procfs"));
        }
        loop {
            check_time(until)?;
            let full = record.observed_bytes == MAP_BYTES;
            let (pointer, length) = if full {
                (&mut record.overflow_byte as *mut u8, 1)
            } else {
                (
                    record.initialized[record.observed_bytes..].as_mut_ptr(),
                    MAP_BYTES - record.observed_bytes,
                )
            };
            let result = unsafe { libc::read(fd, pointer.cast(), length) };
            record.last_read = Some(outcome(result as i64));
            record.read_calls += 1; // At most MAP_BYTES successful one-byte reads plus one terminal read.
            checked(record.last_read, "exec journal maps read", false)?;
            let count = usize::try_from(result)
                .map_err(|_| invalid("exec journal maps read count differs"))?;
            if count > length {
                return Err(invalid("exec journal maps read count exceeds buffer"));
            }
            if count == 0 {
                check_time(until)?;
                record.status = ExecMapsStatus::Complete;
                break;
            }
            if full {
                return Err(invalid("exec journal maps exceeds fixed capture"));
            }
            record.observed_bytes += count;
        }
        Ok(())
    })();
    let result = unsafe { libc::close(fd) };
    record.close = Some(outcome(i64::from(result)));
    // Preserve the original stream failure, while retaining close independently.
    read_result?;
    checked(record.close, "exec journal maps close", true)
}
pub(super) fn complete_reads(record: &ExecRawRecord) -> Result<(), LaunchError> {
    checked(record.registers_read, "exec journal GETREGS", true)?;
    let query = record
        .xstate_query
        .ok_or(invalid("exec journal XSTATE request absent"))?;
    checked(Some(query.outcome), "exec journal GETREGSET", true)?;
    if !query.pointer_unchanged || !(512..MAX_XSTATE).contains(&query.reported_bytes) {
        return Err(invalid("exec journal XSTATE request is incomplete"));
    }
    checked(record.mask_read, "exec journal GETSIGMASK", true)?;
    if libc::WSTOPSIG(record.status) == (libc::SIGTRAP | 0x80) && record.status >> 16 == 0 {
        checked(record.syscall_read, "exec journal GET_SYSCALL_INFO", false)?;
        let count = record.syscall_read.unwrap().result;
        let minimum = match record.syscall_info[0] {
            1 => 80,
            2 => 33,
            _ => return Err(invalid("exec journal syscall-info phase differs")),
        };
        if !(minimum..=88).contains(&count) {
            return Err(invalid("exec journal syscall-info length differs"));
        }
    } else if libc::WSTOPSIG(record.status) == libc::SIGTRAP
        && record.status >> 16 == libc::PTRACE_EVENT_EXEC
    {
        checked(record.event_read, "exec journal GETEVENTMSG", true)?;
    } else if libc::WSTOPSIG(record.status) == libc::SIGTRAP && record.status >> 16 == 0 {
        checked(record.siginfo_read, "exec journal GETSIGINFO", true)?;
    }
    Ok(())
}
fn pin(owner: &Owner, tid: i32, status: i32) -> Result<(KernelPinKind, bool), LaunchError> {
    let held = owner.owned.contains(&tid) && owner.stopped.get(&tid) == Some(&status);
    let terminal = owner.tracer_terminal.get(&tid) == Some(&status);
    if (!held && !terminal) || !owner.handles.contains_key(&tid) {
        return Err(invalid("exec journal lacks original pinned wait"));
    }
    let kind = match owner.pin_kinds.get(&tid) {
        Some(PinKind::Process) => KernelPinKind::Process,
        Some(PinKind::Thread) => KernelPinKind::Thread,
        None => return Err(invalid("exec journal wait pin kind is absent")),
    };
    Ok((
        kind,
        held && libc::WIFSTOPPED(status) && !owner.handles.get(&tid).is_none_or(broker::hup),
    ))
}
impl ExecJournalObserver {
    pub(super) fn capture_raw(
        &mut self,
        owner: &Owner,
        tid: i32,
        status: i32,
    ) -> Result<(), LaunchError> {
        let (kind, held) = pin(owner, tid, status)?;
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::RawCapture,
            |attempt| {
                if owner.session != attempt.id.session
                    || attempt.raw_count == RAW_SLOTS
                    || attempt.pending_raw.is_some()
                    || !(matches!(
                        attempt.native_phase,
                        NativePhase::OriginalReleased
                            | NativePhase::EntryReleased
                            | NativePhase::ExecReleased
                    ) || (attempt.native_phase == NativePhase::Bootstrapping
                        && attempt.effect_index == 2
                        && attempt.trap_raw.is_none()))
                {
                    return Err(invalid(
                        "exec journal raw capture order or capacity differs",
                    ));
                }
                let ordinal = attempt.raw_count as u8;
                attempt.append(ExecJournalFact::Raw { ordinal })?;
                attempt.raw_count += 1;
                attempt.pending_raw = Some(ordinal);
                let raw = &mut attempt.raw[usize::from(ordinal)].record;
                raw.ordinal = ordinal;
                raw.tid = tid;
                raw.status = status;
                raw.pin = kind;
                raw.held = held;
                if !held {
                    return Err(invalid(
                        "exec journal raw wait is not a live held observation",
                    ));
                }
                state_reads(raw);
                info_reads(raw);
                let maps_result = capture_maps(&mut raw.maps, tid, status, attempt.until);
                // Required-read gating deliberately occurs only after every independent
                // read family attempted. Failure preserves every initialized substrate.
                complete_reads(raw)?;
                maps_result?;
                check_time(attempt.until)?;
                if tid != attempt.pending.stop.tid || owner.session != attempt.id.session {
                    return Err(invalid("exec journal raw wait belongs to a different task"));
                }
                raw.complete = true;
                Ok(())
            },
        )
    }
}
impl ExecJournalWriter {
    /// # Safety
    /// The caller consumed genuine bootstrap success and currently holds its
    /// exact singleton new-mm stop. It reauthenticates full state/current token
    /// and mappings before and after this read; no native control may intervene.
    /// This method records evidence and does not construct that native proof.
    pub(in crate::linux::remote::dynamic::owner) unsafe fn capture_quarantined_maps(
        &self,
        owner: &Owner,
        handle: ExecAttemptHandle,
        stop: &AdmissionStop,
    ) -> Result<(), LaunchError> {
        let status = owner
            .stopped
            .get(&stop.token.tid)
            .copied()
            .ok_or(invalid("exec journal final maps lost held status"))?;
        let (kind, held) = pin(owner, stop.token.tid, status)?;
        mutate(
            &self.archive,
            handle,
            ExecJournalStage::QuarantinedMaps,
            |attempt| {
                check_time(attempt.until)?;
                if !held
                    || kind != KernelPinKind::Process
                    || owner.session != attempt.id.session
                    || owner.owned.len() != 1
                    || owner.pid != stop.token.tid
                    || stop.signal.is_some()
                    || attempt.native_phase != NativePhase::BootstrapComplete
                    || attempt.final_stop != Some((&stop.token).into())
                    || attempt.replacement != Some(stop.identity)
                {
                    return Err(invalid("exec journal quarantine capture binding differs"));
                }
                if attempt
                    .fact_count
                    .checked_add(2)
                    .is_none_or(|count| count > FACTS)
                {
                    return Err(invalid("exec journal final maps pair capacity exhausted"));
                }
                attempt.append(ExecJournalFact::QuarantinedMapsAttempt {
                    stop: (&stop.token).into(),
                })?;
                attempt.native_phase = NativePhase::MapsStarted;
                capture_maps(
                    &mut attempt.final_maps.record,
                    stop.token.tid,
                    status,
                    attempt.until,
                )?;
                let (_, still_held) = pin(owner, stop.token.tid, status)?;
                if !still_held {
                    return Err(invalid("exec journal quarantine capture lost original pin"));
                }
                check_time(attempt.until)?;
                attempt.append(ExecJournalFact::QuarantinedMapsComplete {
                    stop: (&stop.token).into(),
                })?;
                attempt.native_phase = NativePhase::MapsComplete;
                Ok(())
            },
        )
    }
}
