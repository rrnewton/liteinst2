use super::*;

pub(super) fn current_mask() -> Result<u64, LaunchError> {
    let mut mask = 0_u64;
    // SAFETY: Linux x86-64 takes an eight-byte kernel mask, unlike libc sigset_t.
    if unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            std::ptr::null::<u64>(),
            &raw mut mask,
            KERNEL_SIGSET_BYTES,
        )
    } == -1
    {
        return Err(system("read native signal mask"));
    }
    Ok(mask)
}

pub(super) fn set_current_mask(mask: u64) -> Result<(), LaunchError> {
    // SAFETY: mask is an initialized, exact-size native kernel mask.
    if unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            &raw const mask,
            std::ptr::null::<u64>(),
            KERNEL_SIGSET_BYTES,
        )
    } == -1
    {
        return Err(system("set native signal mask"));
    }
    Ok(())
}

pub(super) struct BlockedSignals {
    original: u64,
    active: bool,
}

impl BlockedSignals {
    pub(super) fn new() -> Result<Self, LaunchError> {
        let all = u64::MAX;
        let mut original = 0_u64;
        // SAFETY: exchange and capture happen in one kernel operation. A host
        // signal handler cannot change the intended inherited mask between a
        // separate read and block operation.
        if unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &raw const all,
                &raw mut original,
                KERNEL_SIGSET_BYTES,
            )
        } == -1
        {
            return Err(system("block signals for tracer creation"));
        }
        Ok(Self {
            original,
            active: true,
        })
    }
    pub(super) fn original(&self) -> u64 {
        self.original
    }
    pub(super) fn restore(mut self) -> Result<(), LaunchError> {
        set_current_mask(self.original)?;
        if current_mask()? != self.original {
            return Err(LaunchError::Invalid(
                "launch caller signal mask did not restore",
            ));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for BlockedSignals {
    fn drop(&mut self) {
        if self.active {
            let _ = set_current_mask(self.original);
        }
    }
}

pub(super) fn task_mask(pid: libc::pid_t) -> Result<u64, LaunchError> {
    let mut mask = 0_u64;
    ptrace(
        libc::PTRACE_GETSIGMASK,
        pid,
        KERNEL_SIGSET_BYTES,
        (&raw mut mask) as usize,
    )?;
    Ok(mask)
}

pub(super) fn start(
    owner: &mut owner::Owner,
    command: &LaunchCommand,
    inherited_mask: u64,
    until: Instant,
) -> Result<Ready, LaunchError> {
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

    // A socket release channel permits MSG_NOSIGNAL: a concurrently killed child
    // must not send SIGPIPE into the embedding host when the parent releases it.
    let mut release = [-1; 2];
    // SAFETY: release contains two writable descriptor slots.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            release.as_mut_ptr(),
        )
    } == -1
    {
        return Err(system("create launch release channel"));
    }
    // SAFETY: each successful socketpair descriptor is adopted exactly once.
    let release_child = unsafe { OwnedFd::from_raw_fd(release[0]) };
    let release_parent = unsafe { OwnedFd::from_raw_fd(release[1]) };
    let mut errors = [-1; 2];
    // SAFETY: errors contains two writable descriptor slots.
    if unsafe { libc::pipe2(errors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == -1 {
        return Err(system("create launch error pipe"));
    }
    // SAFETY: each successful pipe descriptor is adopted exactly once.
    let error_read = unsafe { OwnedFd::from_raw_fd(errors[0]) };
    let error_write = unsafe { OwnedFd::from_raw_fd(errors[1]) };
    let child_fd = release_child.as_raw_fd();
    let parent_fd = release_parent.as_raw_fd();
    let error_fd = error_write.as_raw_fd();
    let error_reader = error_read.as_raw_fd();
    owner.time_left(until, "seized launch preparation")?;
    let all_blockable = !(1_u64 << (libc::SIGKILL - 1)) & !(1_u64 << (libc::SIGSTOP - 1));
    if current_mask()? != all_blockable {
        return Err(LaunchError::Invalid(
            "dynamic tracer does not block every blockable signal",
        ));
    }
    let bootstrap = Bootstrap {
        release: child_fd,
        parent_release: parent_fd,
        error_read: error_reader,
        error_write: error_fd,
        program: program.as_ptr(),
        argv: argv.as_ptr(),
        envp: envp.as_ptr(),
        #[cfg(test)]
        fail_before_ready: owner.fail_before_ready,
        #[cfg(test)]
        die_before_ready: owner.die_before_ready,
    };
    owner.spawn_broker(bootstrap)?;
    drop(release_child);
    drop(error_write);
    owner.wait_broker_ready(until)?;
    let pid = owner.pid;
    owner.time_left(until, "seize launch child")?;
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
    let (tid, status) = owner.wait_raw(until, "initial seized interruption")?;
    if tid != pid
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || status >> 16 != libc::PTRACE_EVENT_STOP
    {
        return Err(child_error(error_reader, status));
    }
    let release_byte = 0xa5_u8;
    // SAFETY: the one-byte message releases only this owned bootstrap. A dead
    // peer returns EPIPE without changing the host's SIGPIPE mask or queue.
    if unsafe {
        libc::send(
            parent_fd,
            (&raw const release_byte).cast(),
            1,
            libc::MSG_NOSIGNAL,
        )
    } != 1
    {
        return Err(system("release seized launch child"));
    }
    drop(release_parent);
    ptrace(libc::PTRACE_CONT, pid, 0, 0)?;
    owner.released(pid);
    let (tid, status) = owner.wait_raw(until, "seized exec event")?;
    if tid != pid
        || !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || status >> 16 != libc::PTRACE_EVENT_EXEC
    {
        return Err(child_error(error_reader, status));
    }
    let registers = read_registers(pid)?;
    if registers.cs != 0x33
        || registers.orig_rax != libc::SYS_execve as u64
        || registers.rax != (-i64::from(libc::ENOSYS)) as u64
    {
        return Err(LaunchError::Invalid(
            "seized launch is not a native exec event",
        ));
    }
    let evidence = entry_evidence(pid, &executable, &registers)?;
    ptrace(
        libc::PTRACE_SETSIGMASK,
        pid,
        KERNEL_SIGSET_BYTES,
        (&raw const inherited_mask) as usize,
    )?;
    if task_mask(pid)? != inherited_mask {
        return Err(LaunchError::Invalid(
            "initial application signal mask did not restore",
        ));
    }
    owner.initial_exec = Some(registers);
    let event = owner.hold(DynamicEventKind::Exec { evidence })?;
    Ok(Ready { pid, event })
}

#[derive(Clone, Copy)]
pub(super) struct Bootstrap {
    release: i32,
    parent_release: i32,
    error_read: i32,
    error_write: i32,
    program: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    #[cfg(test)]
    pub(super) fail_before_ready: bool,
    #[cfg(test)]
    pub(super) die_before_ready: bool,
}
impl Bootstrap {
    pub(super) unsafe fn close_all(self) {
        // SAFETY: this runs only in the raw helper's copied descriptor table.
        unsafe {
            libc::syscall(libc::SYS_close, self.release);
            libc::syscall(libc::SYS_close, self.parent_release);
            libc::syscall(libc::SYS_close, self.error_read);
            libc::syscall(libc::SYS_close, self.error_write);
        }
    }
}

pub(super) unsafe fn child_bootstrap(bootstrap: Bootstrap) -> ! {
    let Bootstrap {
        release,
        parent_release,
        error_read,
        error_write,
        program,
        argv,
        envp,
        ..
    } = bootstrap;
    // SAFETY: only raw syscalls touch the copied post-fork state.
    unsafe {
        libc::syscall(libc::SYS_close, parent_release);
        libc::syscall(libc::SYS_close, error_read);
        let mut byte = 0_u8;
        loop {
            let read = libc::syscall(libc::SYS_read, release, &raw mut byte, 1);
            if read == 1 && byte == 0xa5 {
                break;
            }
            if read == -1 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            child_error_exit(error_write, 1);
        }
        libc::syscall(libc::SYS_close, release);
        libc::syscall(libc::SYS_execve, program, argv, envp);
        child_error_exit(error_write, 2);
    }
}

unsafe fn child_error_exit(fd: i32, stage: i32) -> ! {
    // SAFETY: errno storage and this fixed stack record are valid after raw fork.
    unsafe {
        let record = [stage, *libc::__errno_location()];
        libc::syscall(
            libc::SYS_write,
            fd,
            record.as_ptr(),
            std::mem::size_of_val(&record),
        );
        libc::_exit(127)
    }
}

fn child_error(fd: i32, status: i32) -> LaunchError {
    let mut record = [0_i32; 2];
    // SAFETY: the nonblocking error pipe writes into initialized local storage.
    let count = unsafe {
        libc::read(
            fd,
            record.as_mut_ptr().cast(),
            std::mem::size_of_val(&record),
        )
    };
    if count == std::mem::size_of_val(&record) as isize {
        io_error(
            if record[0] == 2 {
                "seized child execve"
            } else {
                "seized child release"
            },
            io::Error::from_raw_os_error(record[1]),
        )
    } else {
        LaunchError::Child { status }
    }
}

fn entry_evidence(
    pid: libc::pid_t,
    executable: &Elf,
    registers: &RegisterSnapshot,
) -> Result<EntryEvidence, LaunchError> {
    let mappings = read_maps(pid)?;
    let auxv = read_auxv(pid)?;
    let entry = aux(&auxv, libc::AT_ENTRY)?;
    let base = aux(&auxv, libc::AT_BASE)?;
    if executable.runtime_entry(aux(&auxv, libc::AT_PHDR)?)? != entry
        || !mappings.iter().any(|m| m.contains_executable(entry))
    {
        return Err(LaunchError::Invalid(
            "seized AT_ENTRY disagrees with mapped ELF",
        ));
    }
    let (first_image, expected) = if executable.interpreter.is_some() {
        if base == 0 {
            return Err(LaunchError::Invalid("seized interpreter base is absent"));
        }
        let interpreter = Elf::header(&read_memory(pid, base, 64)?)?;
        if interpreter.kind != 3 {
            return Err(LaunchError::Invalid("seized interpreter is not ET_DYN"));
        }
        (
            FirstImage::Interpreter,
            base.checked_add(interpreter.entry)
                .ok_or(LaunchError::Invalid("seized interpreter entry overflow"))?,
        )
    } else {
        if base != 0 {
            return Err(LaunchError::Invalid("unexpected seized interpreter base"));
        }
        (FirstImage::Executable, entry)
    };
    if registers.rip != expected || !mappings.iter().any(|m| m.contains_executable(expected)) {
        return Err(LaunchError::Invalid(
            "seized initial RIP disagrees with ELF entry",
        ));
    }
    Ok(EntryEvidence {
        first_image,
        executable_entry: entry,
        interpreter_base: base,
        initial_instruction: expected,
        interpreter: executable.interpreter.clone(),
    })
}
