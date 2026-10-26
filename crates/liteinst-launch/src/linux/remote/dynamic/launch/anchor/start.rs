//! Existing broker ancestry and atomic pins, with one opt-in helper script.
use super::*;

pub(in crate::linux::remote::dynamic) fn start(
    owner: &mut owner::Owner,
    command: &LaunchCommand,
    inherited_mask: u64,
    until: Instant,
    request: AnchorRequest,
) -> Result<(Ready, InitialExceptionMetadata), LaunchError> {
    let archive = owner.anchor_archive()?;
    if request.allowance != ANCHOR_EVIDENCE_BOUND
        || archive.session() != owner.anchor_session()
        || archive.retained_bytes() > request.allowance
    {
        return Err(LaunchError::Invalid(
            "anchor archive does not match pre-clone reservation",
        ));
    }
    let guard = archive.guard();
    let result = perform(owner, command, inherited_mask, until, &archive);
    if let Err(error) = &result {
        archive.record_failure(error);
    }
    if result.is_ok() {
        guard.commit();
    }
    result
}

fn pair(kind: i32, operation: &'static str) -> Result<(OwnedFd, OwnedFd), LaunchError> {
    let mut pair = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            kind | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(system(operation));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) })
}

fn perform(
    owner: &mut owner::Owner,
    command: &LaunchCommand,
    inherited_mask: u64,
    until: Instant,
    archive: &AnchorArchive,
) -> Result<(Ready, InitialExceptionMetadata), LaunchError> {
    owner.time_left(until, "initial anchor preparation")?;
    let executable = Elf::read_file(&command.program)?;
    let program = cstring(command.program.as_os_str())?;
    let mut arguments = vec![program.clone()];
    for argument in &command.args {
        arguments.push(cstring(argument)?);
    }
    let environment: Vec<CString> = std::env::vars_os()
        .map(|(key, value)| {
            let mut entry = key.into_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            CString::new(entry).map_err(|_| LaunchError::Invalid("NUL in environment"))
        })
        .collect::<Result<_, _>>()?;
    let argv = pointers(&arguments);
    let envp = pointers(&environment);
    let (release_child, release_parent) = pair(libc::SOCK_STREAM, "create anchor release channel")?;
    let (channel_child, channel_parent) = pair(
        libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK,
        "create anchor evidence channel",
    )?;
    let enable = 1_i32;
    if unsafe {
        libc::setsockopt(
            channel_parent.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&raw const enable).cast(),
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    } != 0
    {
        return Err(system("authenticate anchor evidence channel"));
    }
    let mut errors = [-1; 2];
    if unsafe { libc::pipe2(errors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(system("create anchor error channel"));
    }
    let error_read = unsafe { OwnedFd::from_raw_fd(errors[0]) };
    let error_write = unsafe { OwnedFd::from_raw_fd(errors[1]) };
    let mut bootstrap = Bootstrap {
        anchor: None,
        release: release_child.as_raw_fd(),
        parent_release: release_parent.as_raw_fd(),
        error_read: error_read.as_raw_fd(),
        error_write: error_write.as_raw_fd(),
        program: program.as_ptr(),
        argv: argv.as_ptr(),
        envp: envp.as_ptr(),
        #[cfg(test)]
        fail_before_ready: owner.fail_before_ready,
        #[cfg(test)]
        die_before_ready: owner.die_before_ready,
    };
    let storage = storage::Storage::new(
        owner.anchor_session(),
        bootstrap,
        channel_child.as_raw_fd(),
        channel_parent.as_raw_fd(),
    )?;
    let initial = storage.initial();
    let address = storage.context as u64;
    bootstrap.anchor =
        Some(storage.configuration(channel_child.as_raw_fd(), channel_parent.as_raw_fd()));
    owner.time_left(until, "initial anchor clone")?;
    if current_mask()? != BLOCKED {
        return Err(LaunchError::Invalid(
            "initial anchor tracer mask is not fully blocked",
        ));
    }
    // The opt-in reset path registers its transient S/R ownership before clone.
    // R becomes the existing private reaper only after S is physically reaped.
    owner.spawn_anchor_broker(bootstrap, until)?;
    drop(release_child);
    drop(channel_child);
    drop(error_write);
    owner.wait_broker_ready(until)?;
    let pid = owner.pid;
    let mut expected_packet = initial.prepared;
    expected_packet.tid = pid as u64;
    protocol::receive(owner, channel_parent.as_raw_fd(), expected_packet, until)?;
    owner.time_left(until, "initial anchor SEIZE")?;
    #[cfg(test)]
    if owner.fail_before_seize {
        owner.kill_bootstrap_for_test()?;
        return Err(LaunchError::Invalid("injected cancellation before SEIZE"));
    }
    #[cfg(test)]
    if owner.abort_before_seize {
        return Err(LaunchError::Invalid("injected abort before SEIZE"));
    }
    ptrace(libc::PTRACE_SEIZE, pid, 0, OPTIONS)?;
    owner.seized()?;
    ptrace(libc::PTRACE_INTERRUPT, pid, 0, 0)?;
    let (tid, status) = owner.wait_raw(until, "initial anchor seized interruption")?;
    let stop = protocol::capture(archive, pid, tid, status, AnchorPhase::InitialControl)?;
    if tid != pid
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || status >> 16 != libc::PTRACE_EVENT_STOP
    {
        return Err(child_error(error_read.as_raw_fd(), status));
    }
    archive.data().observations[stop].authenticated = true;
    owner.time_left(until, "initial anchor prerequisites")?;
    let prepared = storage::read_context(pid, address)?;
    {
        let mut data = archive.data();
        // Retain the actual fixed context before interpreting prerequisites.
        data.prepared = Some(prepared);
        let archive::Data {
            code,
            rseq_observations,
            ..
        } = &mut *data;
        let rseq = certificate::certify(
            owner,
            pid,
            address,
            &initial,
            &prepared,
            code,
            rseq_observations,
        )?;
        data.rseq = Some(rseq);
    }
    owner.time_left(until, "initial anchor release")?;
    let byte = 0xa5_u8;
    if unsafe {
        libc::send(
            release_parent.as_raw_fd(),
            (&raw const byte).cast(),
            1,
            libc::MSG_NOSIGNAL,
        )
    } != 1
    {
        return Err(system("release owned anchor helper"));
    }
    drop(release_parent);
    let status = protocol::run(
        owner,
        archive,
        address,
        &prepared,
        stop,
        channel_parent.as_raw_fd(),
        until,
    )?;
    let registers = read_registers(pid)?;
    if registers.cs != 0x33
        || registers.orig_rax != libc::SYS_execve as u64
        || registers.rax != (-i64::from(libc::ENOSYS)) as u64
    {
        return Err(LaunchError::Invalid(
            "anchor is not held at actual native EXEC",
        ));
    }
    let evidence = entry_evidence(pid, &executable, &registers)?;
    owner.time_left(until, "initial anchor application mask")?;
    ptrace(
        libc::PTRACE_SETSIGMASK,
        pid,
        KERNEL_SIGSET_BYTES,
        (&raw const inherited_mask) as usize,
    )?;
    if task_mask(pid)? != inherited_mask || read_registers(pid)? != registers {
        return Err(LaunchError::Invalid(
            "anchor application mask restoration differs",
        ));
    }
    let mask_stop = protocol::capture(archive, pid, pid, status, AnchorPhase::ExecMaskRestored)?;
    archive.data().observations[mask_stop].authenticated = true;
    owner.time_left(until, "initial anchor held EXEC")?;
    owner.initial_exec = Some(registers);
    let event = owner.hold(DynamicEventKind::Exec { evidence })?;
    let metadata = {
        let mut data = archive.data();
        let metadata = data.metadata.ok_or(LaunchError::Invalid(
            "anchor EXEC lacks genuine frame metadata",
        ))?;
        if data.restored.is_none() || data.rseq.is_none() {
            return Err(LaunchError::Invalid(
                "anchor EXEC lacks prerequisite or restoration evidence",
            ));
        }
        data.complete = true;
        metadata
    };
    let exec_event = archive.data().observed - 1;
    let receipt = InitialExceptionMetadata {
        session: owner.anchor_session(),
        tid: pid,
        metadata,
        exec_event,
        archive: archive.clone(),
    };
    Ok((Ready { pid, event }, receipt))
}
