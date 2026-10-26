//! A fixed syscall script; no original application instruction is released here.
use super::*;

/// Exact initialized syscall-info bytes from an actual held stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallObservation {
    count: i64,
    error: Option<i32>,
    raw: [u8; 88],
}
impl SyscallObservation {
    /// Actual kernel-reported count, including a negative or invalid length.
    pub fn count(&self) -> i64 {
        self.count
    }
    /// Actual native errno when the observation request returned -1.
    pub fn errno(&self) -> Option<i32> {
        self.error
    }
    /// Initialized complete native buffer, including its zero-filled unused tail.
    pub fn raw_bytes(&self) -> &[u8; 88] {
        &self.raw
    }
    fn op(&self) -> u8 {
        self.raw[0]
    }
    fn word(&self, offset: usize) -> u64 {
        u64::from_ne_bytes(self.raw[offset..offset + 8].try_into().unwrap())
    }
    fn arch(&self) -> u32 {
        u32::from_ne_bytes(self.raw[4..8].try_into().unwrap())
    }
    fn pc(&self) -> u64 {
        self.word(8)
    }
    fn stack(&self) -> u64 {
        self.word(16)
    }
    fn number(&self) -> u64 {
        self.word(24)
    }
    fn args(&self) -> [u64; 6] {
        std::array::from_fn(|i| self.word(32 + i * 8))
    }
    fn result(&self) -> i64 {
        self.word(24) as i64
    }
    fn error(&self) -> u8 {
        self.raw[32]
    }
}

fn syscall(tid: i32) -> SyscallObservation {
    let mut value = SyscallObservation {
        count: 0,
        error: None,
        raw: [0; 88],
    };
    let count = unsafe {
        libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            tid,
            value.raw.len(),
            value.raw.as_mut_ptr(),
        )
    };
    value.count = count as i64;
    if count == -1 {
        value.error = io::Error::last_os_error().raw_os_error();
    }
    value
}
fn validate_syscall(value: &SyscallObservation) -> Result<(), LaunchError> {
    if value.count == -1 {
        return Err(io_error(
            "read anchor syscall observation",
            io::Error::from_raw_os_error(value.error.unwrap_or(libc::EIO)),
        ));
    }
    let minimum = match value.op() {
        0 => 24,
        1 => 80,
        2 => 33,
        _ => {
            return Err(LaunchError::Invalid(
                "anchor refuses unknown syscall-info phase",
            ));
        }
    };
    if value.count < minimum || value.count as usize > value.raw.len() {
        return Err(LaunchError::Invalid("anchor syscall-info length differs"));
    }
    Ok(())
}

/// Commit the actual delivered header first; a failed read never becomes a
/// complete state. The wait-domain owner already pinned this delivery. This
/// does not claim capture before wait_in_domain's fallible pin/consume steps.
pub(super) fn capture(
    archive: &AnchorArchive,
    root: i32,
    tid: i32,
    status: i32,
    phase: AnchorPhase,
) -> Result<usize, LaunchError> {
    capture_current(archive, root, tid, Some(status), phase)
}

pub(super) fn capture_current(
    archive: &AnchorArchive,
    root: i32,
    tid: i32,
    status: Option<i32>,
    phase: AnchorPhase,
) -> Result<usize, LaunchError> {
    let mut data = archive.data();
    if data.observed >= data.observations.len() || (data.complete && phase != AnchorPhase::ExecExit)
    {
        return Err(LaunchError::Invalid("anchor fixed stop capacity exhausted"));
    }
    let index = data.observed;
    if phase == AnchorPhase::ExecExit {
        if data.exec_exit_index.is_some() {
            return Err(LaunchError::Invalid(
                "duplicate anchor initial EXIT capture",
            ));
        }
        data.exec_exit_index = Some(index);
    }
    data.observed += 1;
    let row = &mut data.observations[index];
    row.phase = phase;
    row.tid = tid;
    row.status = status;
    if tid != root || status.is_some_and(|status| !libc::WIFSTOPPED(status)) {
        return Err(LaunchError::Child {
            status: status.unwrap_or(0),
        });
    }
    row.syscall = Some(syscall(tid));
    let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let result = ptrace(libc::PTRACE_GETREGS, tid, 0, (&raw mut registers) as usize);
    row.state.registers = registers.into();
    result?;
    row.capture.registers_read = true;
    let mut vector = libc::iovec {
        iov_base: row.state.xstate.as_mut_ptr().cast(),
        iov_len: row.state.xstate.len(),
    };
    let result =
        unsafe { libc::ptrace(libc::PTRACE_GETREGSET, tid, NT_X86_XSTATE, &raw mut vector) };
    row.capture.xstate_result = Some(result as i64);
    row.capture.xstate_length = Some(vector.iov_len);
    if result == -1 {
        let error = io::Error::last_os_error();
        row.capture.xstate_errno = error.raw_os_error();
        return Err(io_error("capture anchor XSTATE", error));
    }
    if vector.iov_len < 512 || vector.iov_len >= row.state.xstate.len() {
        return Err(LaunchError::Invalid("anchor XSTATE is absent or truncated"));
    }
    row.state.xstate.truncate(vector.iov_len);
    let result = ptrace(
        libc::PTRACE_GETSIGMASK,
        tid,
        8,
        (&raw mut row.state.mask) as usize,
    );
    result?;
    row.capture.mask_read = true;
    if read_registers(tid)? != row.state.registers {
        return Err(LaunchError::Invalid(
            "anchor registers changed during capture",
        ));
    }
    row.complete = true;
    validate_syscall(row.syscall.as_ref().unwrap())?;
    Ok(index)
}

fn resume(owner: &mut owner::Owner, until: Instant, signal: i32) -> Result<(), LaunchError> {
    owner.time_left(until, "initial anchor syscall script")?;
    ptrace(libc::PTRACE_SYSCALL, owner.pid, 0, signal as usize)?;
    owner.released(owner.pid);
    Ok(())
}

fn wait(
    owner: &mut owner::Owner,
    archive: &AnchorArchive,
    until: Instant,
    phase: AnchorPhase,
) -> Result<usize, LaunchError> {
    let (tid, status) = owner.wait_raw(until, "initial anchor syscall script")?;
    let index = capture(archive, owner.pid, tid, status, phase)?;
    owner.time_left(until, "initial anchor syscall script")?;
    Ok(index)
}

fn syscall_state(
    archive: &AnchorArchive,
    index: usize,
    call: raw::Call,
    op: u8,
) -> Result<(), LaunchError> {
    let mut data = archive.data();
    let row = &data.observations[index];
    let state = &row.state;
    let info = row
        .syscall
        .ok_or(LaunchError::Invalid("anchor syscall observation missing"))?;
    let status = row.status.ok_or(LaunchError::Invalid(
        "anchor scripted syscall lacks consumed wait",
    ))?;
    if !row.complete
        || status >> 16 != 0
        || libc::WSTOPSIG(status) != (libc::SIGTRAP | 0x80)
        || state.registers.cs != 0x33
        || state.registers.rip != call.pc
        || state.registers.orig_rax != call.number
        || info.op() != op
        || info.arch() != 0xc000_003e
        || info.pc() != call.pc
        || info.stack() != state.registers.rsp
        || call
            .args
            .into_iter()
            .zip(arguments(&state.registers))
            .any(|(expected, got)| expected.is_some_and(|v| v != got))
    {
        return Err(LaunchError::Invalid(
            "anchor actual syscall phase or input differs",
        ));
    }
    if op == 1
        && (info.number() != call.number
            || info.args() != arguments(&state.registers)
            || state.registers.rax != (-i64::from(libc::ENOSYS)) as u64)
    {
        return Err(LaunchError::Invalid("anchor actual syscall ENTRY differs"));
    }
    if op == 2
        && (info.result() != call.result
            || state.registers.rax != call.result as u64
            || info.error() != u8::from((-4095..=-1).contains(&call.result)))
    {
        return Err(LaunchError::Invalid("anchor actual syscall EXIT differs"));
    }
    data.observations[index].authenticated = true;
    Ok(())
}

fn paired_exit(
    archive: &AnchorArchive,
    entry: usize,
    exit: usize,
    call: raw::Call,
) -> Result<(), LaunchError> {
    syscall_state(archive, exit, call, 2)?;
    let data = archive.data();
    let before = &data.observations[entry].state;
    let after = &data.observations[exit].state;
    let mut expected = before.registers;
    expected.rax = call.result as u64;
    let mask = match call.kind {
        raw::CallKind::Unmask => BLOCKED & !(1_u64 << (PROBE_SIGNAL - 1)),
        raw::CallKind::Reblock => BLOCKED,
        _ => before.mask,
    };
    if after.registers != expected || after.xstate != before.xstate || after.mask != mask {
        return Err(LaunchError::Invalid(
            "anchor complete syscall ENTRY to EXIT state differs",
        ));
    }
    Ok(())
}

pub(super) fn receive(
    owner: &owner::Owner,
    socket: i32,
    expected: storage::Packet,
    until: Instant,
) -> Result<(), LaunchError> {
    #[repr(C, align(8))]
    struct Control([u8; 64]);
    loop {
        owner.time_left(until, "authenticated anchor packet")?;
        let mut packet: storage::Packet = unsafe { std::mem::zeroed() };
        let mut control = Control([0; 64]);
        let mut vector = libc::iovec {
            iov_base: (&raw mut packet).cast(),
            iov_len: std::mem::size_of_val(&packet),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &raw mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = control.0.len();
        let count = unsafe {
            libc::recvmsg(
                socket,
                &raw mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if count == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.raw_os_error() == Some(libc::EAGAIN) {
                let mut descriptor = libc::pollfd {
                    fd: socket,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // Bounded polling also preserves the owner's cancellation/deadline.
                if unsafe { libc::poll(&raw mut descriptor, 1, 1) } == -1
                    && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    return Err(system("wait for anchor packet"));
                }
                continue;
            }
            return Err(io_error("receive anchor packet", error));
        }
        let mut credentials = None;
        let mut invalid = false;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let length = (*header).cmsg_len;
                if length < libc::CMSG_LEN(0) as usize {
                    invalid = true;
                    break;
                }
                let payload = length - libc::CMSG_LEN(0) as usize;
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    // A malformed peer cannot leak received descriptors, even
                    // though no descriptor transfer is permitted by this wire.
                    for i in 0..payload / std::mem::size_of::<i32>() {
                        let fd =
                            std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>().add(i));
                        libc::close(fd);
                    }
                    invalid = true;
                } else if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_CREDENTIALS
                    && payload == std::mem::size_of::<libc::ucred>()
                    && credentials.is_none()
                {
                    credentials = Some(std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::ucred>(),
                    ));
                } else {
                    invalid = true;
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if count != 64
            || packet != expected
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || invalid
            || credentials.is_none_or(|cred| {
                cred.pid != owner.pid
                    || cred.uid != unsafe { libc::getuid() }
                    || cred.gid != unsafe { libc::getgid() }
            })
        {
            return Err(LaunchError::Invalid(
                "anchor packet credentials or closed payload differs",
            ));
        }
        return Ok(());
    }
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn capture_frame(
    archive: &AnchorArchive,
    tid: i32,
    c: &storage::Context,
    delivery: usize,
) -> Result<(), LaunchError> {
    let mut data = archive.data();
    let length = usize::try_from(
        c.stack_top
            .checked_sub(c.frame)
            .ok_or(LaunchError::Invalid("anchor frame lies above stack"))?,
    )
    .map_err(|_| LaunchError::Invalid("anchor frame size overflow"))?;
    if c.frame < c.stack_low
        || !(440..=FRAME_BYTES).contains(&length)
        || c.ucontext != c.frame + 8
        || c.siginfo != c.frame + 312
    {
        return Err(LaunchError::Invalid(
            "anchor frame pointers or extent differ",
        ));
    }
    data.frame_start = c.frame;
    {
        let archive::Data {
            frame,
            frame_length,
            ..
        } = &mut *data;
        storage::read_prefix(tid, c.frame, &mut frame[..length], frame_length)?;
    }
    let bytes = &data.frame[..length];
    let signal = data
        .raw_signal
        .ok_or(LaunchError::Invalid("anchor frame has no owned signal"))?;
    let interrupted = &data.observations[delivery].state;
    let r = interrupted.registers;
    // Native rt_sigframe/ucontext/sigcontext layout; every saved GPR is checked
    // against the real signal-delivery stop, not a zero or normalized baseline.
    let gprs = [
        r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.rdi, r.rsi, r.rbp, r.rbx, r.rdx,
        r.rax, r.rcx, r.rsp, r.rip, r.eflags,
    ];
    if word(bytes, 0) != c.probe_action.restorer
        || bytes[312..440] != signal
        || word(bytes, 8) != 7
        || word(bytes, 16) != 0
        || gprs
            .into_iter()
            .enumerate()
            .any(|(i, value)| word(bytes, 48 + i * 8) != value)
        || u16::from_ne_bytes(bytes[192..194].try_into().unwrap()) != r.cs as u16
        || bytes[194..198] != [0; 4]
        || u16::from_ne_bytes(bytes[198..200].try_into().unwrap()) != r.ss as u16
        || word(bytes, 24) != c.old_stack.address
        || word(bytes, 40) != c.old_stack.size
        || u32::from_ne_bytes(bytes[32..36].try_into().unwrap()) != c.old_stack.flags as u32
        || word(bytes, 216) != interrupted.mask
        || word(bytes, 304) != interrupted.mask
        || [word(bytes, 208), word(bytes, 200), word(bytes, 224)] != c.metadata
    {
        return Err(LaunchError::Invalid(
            "anchor genuine frame differs from delivered native state",
        ));
    }
    let fp = word(bytes, 232);
    let offset = usize::try_from(fp.checked_sub(c.frame).ok_or(LaunchError::Invalid(
        "anchor FP frame precedes native frame",
    ))?)
    .map_err(|_| LaunchError::Invalid("anchor FP offset overflow"))?;
    if fp % 64 != 0 || offset < 440 || offset.checked_add(512).is_none_or(|end| end > length) {
        return Err(LaunchError::Invalid(
            "anchor FP frame is outside bounded normal stack",
        ));
    }
    let magic = u32::from_ne_bytes(bytes[offset + 464..offset + 468].try_into().unwrap());
    let extent = u32::from_ne_bytes(bytes[offset + 468..offset + 472].try_into().unwrap()) as usize;
    let state_length =
        u32::from_ne_bytes(bytes[offset + 480..offset + 484].try_into().unwrap()) as usize;
    if magic != 0x4650_5853
        || state_length < 512
        || state_length > MAX_XSTATE
        || extent != state_length + 4
        || offset.checked_add(extent).is_none_or(|end| end > length)
        || u32::from_ne_bytes(
            bytes[offset + extent - 4..offset + extent]
                .try_into()
                .unwrap(),
        ) != 0x4650_5845
    {
        return Err(LaunchError::Invalid(
            "anchor extended signal frame format differs",
        ));
    }
    data.metadata = Some(ExceptionMetadata {
        trapno: c.metadata[0],
        error_code: c.metadata[1],
        cr2: c.metadata[2],
    });
    data.frame_complete = true;
    Ok(())
}

fn check_context(
    kind: raw::CallKind,
    initial: &storage::Context,
    c: &storage::Context,
) -> Result<(), LaunchError> {
    let valid = match kind {
        raw::CallKind::Read => c.release_byte == 0xa5,
        raw::CallKind::QueryInstalled => c.check_action == initial.probe_action,
        raw::CallKind::PendingBefore
        | raw::CallKind::PendingRestore
        | raw::CallKind::PendingAfter => c.pending == 0,
        raw::CallKind::QueryMask => c.current_mask == BLOCKED,
        raw::CallKind::QueryRestored => c.check_action == initial.old_action,
        raw::CallKind::QueryStack => c.check_stack == initial.old_stack,
        _ => true,
    };
    if !valid {
        return Err(LaunchError::Invalid(
            "anchor native query did not establish required restoration",
        ));
    }
    Ok(())
}

pub(super) fn run(
    owner: &mut owner::Owner,
    archive: &AnchorArchive,
    address: u64,
    context: &storage::Context,
    initial_stop: usize,
    socket: i32,
    until: Instant,
) -> Result<i32, LaunchError> {
    let calls = raw::calls(address, context);
    let r = archive.data().observations[initial_stop].state.registers;
    let pre_read = raw::read_prefix().contains(&r.rip) || r.rip == raw::read_instruction();
    let interrupted_read = r.rip == calls[0].pc
        && r.orig_rax == 0
        && r.rax == (-512_i64) as u64
        && calls[0]
            .args
            .into_iter()
            .zip(arguments(&r))
            .all(|(value, got)| value.is_none_or(|v| v == got));
    if !pre_read && !interrupted_read {
        return Err(LaunchError::Invalid(
            "anchor initial control is not before or inside release read",
        ));
    }
    let mut open_entry = None;
    let mut inherited_read = interrupted_read;
    let mut restarted = false;
    resume(owner, until, 0)?;
    loop {
        let index = wait(owner, archive, until, AnchorPhase::SyscallEntry)?;
        let op = archive.data().observations[index].syscall.unwrap().op();
        if op == 1 {
            if open_entry.is_some() {
                return Err(LaunchError::Invalid("duplicate anchor read ENTRY"));
            }
            syscall_state(archive, index, calls[0], 1)?;
            open_entry = Some(index);
            inherited_read = false;
        } else if op == 2 && (open_entry.is_some() || inherited_read) {
            archive.data().observations[index].phase = AnchorPhase::SyscallExit;
            let result = archive.data().observations[index].syscall.unwrap().result();
            if result == -512 && !restarted {
                let mut restart = calls[0];
                restart.result = -512;
                syscall_state(archive, index, restart, 2)?;
                if let Some(entry) = open_entry {
                    paired_exit(archive, entry, index, restart)?;
                }
                open_entry = None;
                inherited_read = false;
                restarted = true;
            } else if result == 1 {
                syscall_state(archive, index, calls[0], 2)?;
                if let Some(entry) = open_entry {
                    paired_exit(archive, entry, index, calls[0])?;
                }
                check_context(
                    raw::CallKind::Read,
                    context,
                    &storage::read_context(owner.pid, address)?,
                )?;
                break;
            } else {
                return Err(LaunchError::Invalid(
                    "anchor release read failed or restarted repeatedly",
                ));
            }
        } else {
            return Err(LaunchError::Invalid(
                "anchor release read has no actual phase lineage",
            ));
        }
        resume(owner, until, 0)?;
    }
    for call in calls.into_iter().skip(1) {
        // This ENTRY/EXIT is consumed immediately after the one real delivery
        // below; never issue a second reblock invocation.
        if call.kind == raw::CallKind::Reblock {
            continue;
        }
        resume(owner, until, 0)?;
        let entry = wait(owner, archive, until, AnchorPhase::SyscallEntry)?;
        syscall_state(archive, entry, call, 1)?;
        if call.kind == raw::CallKind::Exec {
            resume(owner, until, 0)?;
            let (tid, status) = owner.wait_raw(until, "initial anchor exec event")?;
            capture(archive, owner.pid, tid, status, AnchorPhase::ExecEvent)?;
            if tid != owner.pid
                || !libc::WIFSTOPPED(status)
                || status >> 16 != libc::PTRACE_EVENT_EXEC
                || libc::WSTOPSIG(status) != libc::SIGTRAP
            {
                return Err(LaunchError::Child { status });
            }
            {
                let mut data = archive.data();
                let last = data.observed - 1;
                data.observations[last].authenticated = true;
            }
            owner.time_left(until, "initial anchor exec event")?;
            return Ok(status);
        }
        resume(owner, until, 0)?;
        let phase = if call.kind == raw::CallKind::WriteAnchor {
            AnchorPhase::AnchorWriteExit
        } else {
            AnchorPhase::SyscallExit
        };
        let exit = wait(owner, archive, until, phase)?;
        paired_exit(archive, entry, exit, call)?;
        let current = storage::read_context(owner.pid, address)?;
        check_context(call.kind, context, &current)?;
        if call.kind == raw::CallKind::Unmask {
            resume(owner, until, 0)?;
            let index = wait(owner, archive, until, AnchorPhase::ProbeDelivery)?;
            let mut signal = [0_u8; 128];
            let signal_result = ptrace(
                libc::PTRACE_GETSIGINFO,
                owner.pid,
                0,
                signal.as_mut_ptr() as usize,
            );
            let expected =
                unsafe { std::slice::from_raw_parts(context.signal.as_ptr().cast::<u8>(), 128) };
            let mut data = archive.data();
            data.raw_signal = Some(signal);
            data.signal_read_complete = signal_result.is_ok();
            data.signal_read_errno = match &signal_result {
                Err(LaunchError::System { source, .. }) => source.raw_os_error(),
                _ => None,
            };
            signal_result?;
            let row = &data.observations[index];
            let previous = &data.observations[exit];
            let status = row
                .status
                .ok_or(LaunchError::Invalid("anchor signal lacks consumed wait"))?;
            if status >> 16 != 0
                || libc::WSTOPSIG(status) != PROBE_SIGNAL
                || signal != expected
                || row.state != previous.state
                || row.syscall.unwrap().op() != 0
            {
                return Err(LaunchError::Invalid("anchor self-signal delivery differs"));
            }
            data.observations[index].authenticated = true;
            drop(data);
            // This exact delivery is the only nonzero reinjected signal.
            resume(owner, until, PROBE_SIGNAL)?;
            // The loop's next iteration normally resumes from an EXIT. Here
            // delivery has already been resumed: collect Reblock ENTRY now.
            let entry = wait(owner, archive, until, AnchorPhase::SyscallEntry)?;
            let reblock = raw::calls(address, context)[7];
            syscall_state(archive, entry, reblock, 1)?;
            capture_frame(
                archive,
                owner.pid,
                &storage::read_context(owner.pid, address)?,
                index,
            )?;
            resume(owner, until, 0)?;
            let exit = wait(owner, archive, until, AnchorPhase::SyscallExit)?;
            paired_exit(archive, entry, exit, reblock)?;
        }
        if call.kind == raw::CallKind::WriteAnchor {
            if current.current_mask != BLOCKED
                || current.pending != 0
                || current.check_action != context.old_action
                || current.check_stack != context.old_stack
                || current.old_action != context.old_action
                || current.old_stack != context.old_stack
            {
                return Err(LaunchError::Invalid(
                    "anchor write lacks exact restored launch state",
                ));
            }
            receive(owner, socket, current.anchor, until)?;
            let mut data = archive.data();
            let start = data.frame_start;
            let length = data.frame_length;
            if length == 0 {
                return Err(LaunchError::Invalid("anchor write has no native frame"));
            }
            {
                let archive::Data {
                    frame_check,
                    frame_check_length,
                    ..
                } = &mut *data;
                storage::read_prefix(
                    owner.pid,
                    start,
                    &mut frame_check[..length],
                    frame_check_length,
                )?;
            }
            if data.frame_check[..length] != data.frame[..length]
                || current.metadata
                    != data
                        .metadata
                        .map(|m| [m.trapno, m.error_code, m.cr2])
                        .unwrap_or([u64::MAX; 3])
            {
                return Err(LaunchError::Invalid(
                    "anchor original signal frame changed before exec",
                ));
            }
            data.frame_check_complete = true;
            data.restored = Some(current);
        }
    }
    Err(LaunchError::Invalid(
        "anchor syscall script ended without exec",
    ))
}

pub(super) fn authenticate_exec_exit(row: &AnchorObservation) -> Result<(), LaunchError> {
    let info = row.syscall.ok_or(LaunchError::Invalid(
        "anchor actual exec EXIT lacks syscall information",
    ))?;
    validate_syscall(&info)?;
    if !row.complete
        || info.op() != 2
        || info.arch() != 0xc000_003e
        || info.result() != 0
        || info.error() != 0
        || info.pc() != row.state.registers.rip
        || info.stack() != row.state.registers.rsp
        || row.state.registers.orig_rax != libc::SYS_execve as u64
        || row.state.registers.rax != 0
    {
        return Err(LaunchError::Invalid(
            "anchor actual exec EXIT observation differs",
        ));
    }
    Ok(())
}
