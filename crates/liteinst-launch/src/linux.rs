use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod remote;
pub use remote::*;

/// Largest permitted original-memory snapshot.
pub const MAX_MEMORY_READ: usize = 64 * 1024;
/// Largest accepted launch timeout.
pub const MAX_LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PROC_FILE: usize = 1024 * 1024;

/// An explicit executable path and its arguments, excluding argument zero.
#[derive(Clone, Debug)]
pub struct LaunchCommand {
    /// ELF executable path. `PATH` lookup is not performed.
    pub program: PathBuf,
    /// Arguments following the executable's argument zero.
    pub args: Vec<OsString>,
}

impl LaunchCommand {
    /// Creates a command with no additional arguments.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }
}

/// A launch, inspection, or cleanup failure.
#[derive(Debug)]
pub enum LaunchError {
    /// A checked input or stopped-image invariant was not satisfied.
    Invalid(&'static str),
    /// A system operation failed.
    System {
        /// Failed operation.
        operation: &'static str,
        /// Operating-system error.
        source: io::Error,
    },
    /// The owned child failed before reaching its exec checkpoint.
    Child {
        /// Kernel wait status, retained without reclassification.
        status: i32,
    },
    /// A child-specific wait exceeded its deadline.
    Timeout(&'static str),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid launch checkpoint: {reason}"),
            Self::System { operation, source } => write!(f, "{operation}: {source}"),
            Self::Child { status } => {
                write!(f, "child did not reach exec stop: status {status:#x}")
            }
            Self::Timeout(operation) => write!(f, "timed out waiting for {operation}"),
        }
    }
}

impl std::error::Error for LaunchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::System { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn system(operation: &'static str) -> LaunchError {
    LaunchError::System {
        operation,
        source: io::Error::last_os_error(),
    }
}

fn io_error(operation: &'static str, source: io::Error) -> LaunchError {
    LaunchError::System { operation, source }
}

macro_rules! registers {
    ($($field:ident),+ $(,)?) => {
        /// Complete x86-64 general-register snapshot from PTRACE_GETREGS.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct RegisterSnapshot {
            $(#[doc = concat!("The `", stringify!($field), "` register value.")]
            pub $field: u64,)+
        }

        impl From<libc::user_regs_struct> for RegisterSnapshot {
            fn from(raw: libc::user_regs_struct) -> Self {
                Self { $($field: raw.$field,)+ }
            }
        }

        impl From<RegisterSnapshot> for libc::user_regs_struct {
            fn from(snapshot: RegisterSnapshot) -> Self {
                Self { $($field: snapshot.$field,)+ }
            }
        }
    };
}

registers!(
    r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs,
    eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs,
);

/// One kernel mapping at the stopped exec checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryMapping {
    /// Inclusive start address.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Kernel mapping permissions, for example `r-xp`.
    pub permissions: String,
    /// Backing file offset.
    pub file_offset: u64,
    /// Descriptive pathname, when present; this is not a source identity.
    pub pathname: Option<String>,
}

impl MemoryMapping {
    fn contains_executable(&self, address: u64) -> bool {
        self.start <= address && address < self.end && self.permissions.as_bytes()[2] == b'x'
    }
}

/// Which image owns the process's first original instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstImage {
    /// A program without PT_INTERP starts at AT_ENTRY.
    Executable,
    /// A program with PT_INTERP starts at its interpreter's relocated entry.
    Interpreter,
}

/// Checked relationships between registers, auxiliary vector, and ELF images.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryEvidence {
    /// Image entered first by the kernel.
    pub first_image: FirstImage,
    /// Kernel AT_ENTRY, the main executable's entry.
    pub executable_entry: u64,
    /// Kernel AT_BASE; zero for a program without an interpreter.
    pub interpreter_base: u64,
    /// Initial RIP, checked against the owning ELF entry.
    pub initial_instruction: u64,
    /// PT_INTERP path recorded in the executable, if any.
    pub interpreter: Option<PathBuf>,
}

struct ChildOwner {
    pid: libc::pid_t,
    reaped: bool,
    reaper: Option<std::sync::mpsc::SyncSender<libc::pid_t>>,
}

fn prepare_reaper() -> Result<std::sync::mpsc::SyncSender<libc::pid_t>, LaunchError> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    // Reserve the cleanup thread before creating a child. A cleanup timeout
    // must not depend on being able to allocate a new thread under pressure.
    std::thread::Builder::new()
        .name("liteinst-launch-reaper".into())
        .spawn(move || {
            if let Ok(pid) = receiver.recv() {
                reap_child(pid);
            }
        })
        .map_err(|error| io_error("start child reaper", error))?;
    Ok(sender)
}

fn reap_child(pid: libc::pid_t) {
    loop {
        let mut status = 0;
        // SAFETY: the named child's owner transferred only its reaping duty.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if result == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            break;
        }
        if result == -1 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
}

impl ChildOwner {
    fn wait(&mut self, deadline: Instant, operation: &'static str) -> Result<i32, LaunchError> {
        loop {
            let mut status = 0;
            // SAFETY: this object exclusively owns the named child; status is writable.
            let result =
                unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WALL) };
            if result == self.pid {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.reaped = true;
                }
                return Ok(status);
            }
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.raw_os_error() == Some(libc::ECHILD) {
                    // An external reaper violates ownership; never signal a reused PID.
                    self.reaped = true;
                }
                return Err(io_error("waitpid", error));
            }
            if Instant::now() >= deadline {
                return Err(LaunchError::Timeout(operation));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn terminate(&mut self) -> Result<(), LaunchError> {
        if self.reaped {
            return Ok(());
        }
        // SAFETY: the unreaped child remains owned by this object.
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(io_error("kill child", error));
            }
        }
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !self.reaped {
            self.wait(deadline, "killed child exit")?;
        }
        Ok(())
    }
}

impl Drop for ChildOwner {
    fn drop(&mut self) {
        if self.terminate().is_err() && !self.reaped {
            // SIGKILL remains pending if the kernel delays exit. Transfer only the
            // child-specific reaping duty; never resume the stopped application.
            if self.reaper.take().unwrap().send(self.pid).is_err() {
                // The reserved worker has no panicking operations. Still retain
                // ownership if an unforeseen worker failure closes its channel.
                reap_child(self.pid);
            }
        }
    }
}

/// An owned child stopped before its first original user instruction.
///
/// Inspection does not resume the child. Explicit conversion through
/// [`Self::into_stopped_process`] adds restricted remote control; this
/// checkpoint alone is not an admission capability. Drop kills and reaps.
pub struct ExecCheckpoint {
    child: ChildOwner,
    initial_registers: RegisterSnapshot,
    entries: EntryEvidence,
    mappings: Vec<MemoryMapping>,
    // Linux ties the ptrace relationship to the launching tracer thread.
    _tracer_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ExecCheckpoint {
    /// Stops a native x86-64 ELF process at its exec event within `timeout`.
    pub fn launch(command: &LaunchCommand, timeout: Duration) -> Result<Self, LaunchError> {
        if timeout.is_zero() || timeout > MAX_LAUNCH_TIMEOUT {
            return Err(LaunchError::Invalid(
                "launch timeout must be in (0, 30 seconds]",
            ));
        }
        let deadline = Instant::now() + timeout;
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
        let reaper = prepare_reaper()?;
        let mut pipe = [-1; 2];
        // SAFETY: pipe points to two writable descriptor slots.
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == -1 {
            return Err(system("pipe2"));
        }
        // SAFETY: pipe2 returned two new descriptors, each owned exactly once.
        let error_read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        // SAFETY: the second new descriptor has not been adopted yet.
        let error_write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        // SAFETY: the child executes only raw libc operations then execve/_exit;
        // it never runs Rust allocation, locking, unwinding, or destructors.
        let pid = unsafe { libc::fork() };
        if pid == -1 {
            return Err(system("fork"));
        }
        if pid == 0 {
            // SAFETY: all pointers refer to immutable storage prepared before fork.
            unsafe {
                libc::close(error_read.as_raw_fd());
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    child_fail(error_write.as_raw_fd(), 1);
                }
                if libc::kill(libc::getpid(), libc::SIGSTOP) == -1 {
                    child_fail(error_write.as_raw_fd(), 2);
                }
                libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr());
                child_fail(error_write.as_raw_fd(), 3);
            }
        }
        drop(error_write);
        drop(fork_guard);
        let mut child = ChildOwner {
            pid,
            reaped: false,
            reaper: Some(reaper),
        };
        let status = child.wait(deadline, "pre-exec stop")?;
        if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP {
            return Err(child_failure(error_read.as_raw_fd(), status));
        }
        let options = libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL;
        ptrace(libc::PTRACE_SETOPTIONS, pid, 0, options as usize)?;
        ptrace(libc::PTRACE_CONT, pid, 0, 0)?;
        let status = child.wait(deadline, "exec event")?;
        if !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != libc::SIGTRAP
            || status >> 16 != libc::PTRACE_EVENT_EXEC
        {
            return Err(child_failure(error_read.as_raw_fd(), status));
        }
        let initial_registers = read_registers(pid)?;
        let mappings = read_maps(pid)?;
        let auxv = read_auxv(pid)?;
        let entry = aux(&auxv, libc::AT_ENTRY)?;
        let base = aux(&auxv, libc::AT_BASE)?;
        let phdr = aux(&auxv, libc::AT_PHDR)?;
        if executable.runtime_entry(phdr)? != entry {
            return Err(LaunchError::Invalid(
                "AT_ENTRY disagrees with executable ELF",
            ));
        }
        if !mappings
            .iter()
            .any(|mapping| mapping.contains_executable(entry))
        {
            return Err(LaunchError::Invalid(
                "AT_ENTRY is outside executable mappings",
            ));
        }
        let (first_image, expected) = if executable.interpreter.is_some() {
            if base == 0 {
                return Err(LaunchError::Invalid("ET_EXEC or absent interpreter base"));
            }
            let header = read_memory(pid, base, 64)?;
            let interpreter = Elf::header(&header)?;
            if interpreter.kind != 3 {
                return Err(LaunchError::Invalid("interpreter is not ET_DYN"));
            }
            let entry = base
                .checked_add(interpreter.entry)
                .ok_or(LaunchError::Invalid("interpreter entry overflow"))?;
            (FirstImage::Interpreter, entry)
        } else {
            if base != 0 {
                return Err(LaunchError::Invalid("unexpected interpreter base"));
            }
            (FirstImage::Executable, entry)
        };
        if initial_registers.rip != expected
            || !mappings
                .iter()
                .any(|mapping| mapping.contains_executable(expected))
        {
            return Err(LaunchError::Invalid(
                "initial RIP disagrees with executable ELF entry",
            ));
        }
        Ok(Self {
            child,
            initial_registers,
            entries: EntryEvidence {
                first_image,
                executable_entry: entry,
                interpreter_base: base,
                initial_instruction: expected,
                interpreter: executable.interpreter,
            },
            mappings,
            _tracer_thread: std::marker::PhantomData,
        })
    }

    /// Returns the owned child's PID for reporting; external tracing/reaping is unsupported.
    pub fn pid(&self) -> libc::pid_t {
        self.child.pid
    }

    /// Returns the initial general-register snapshot.
    pub fn initial_registers(&self) -> &RegisterSnapshot {
        &self.initial_registers
    }

    /// Reads the still-stopped general registers again without executing instructions.
    pub fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        read_registers(self.child.pid)
    }

    /// Returns checked initial-entry evidence.
    pub fn entries(&self) -> &EntryEvidence {
        &self.entries
    }

    /// Returns the mapping snapshot taken at the exec stop.
    pub fn mappings(&self) -> &[MemoryMapping] {
        &self.mappings
    }

    /// Reads at most [`MAX_MEMORY_READ`] bytes without changing the stopped image.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        read_memory(self.child.pid, address, len)
    }

    /// Kills and reaps this checkpoint, reporting cleanup failure.
    pub fn terminate(mut self) -> Result<(), LaunchError> {
        self.child.terminate()
    }
}

fn cstring(value: &OsStr) -> Result<CString, LaunchError> {
    CString::new(value.as_bytes()).map_err(|_| LaunchError::Invalid("NUL in command"))
}

fn pointers(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

unsafe fn child_fail(fd: i32, stage: i32) -> ! {
    // SAFETY: errno is thread-local and remains accessible after fork.
    let record = [stage, unsafe { *libc::__errno_location() }];
    // SAFETY: record is initialized; this short write fits in the initially empty pipe.
    unsafe { libc::write(fd, record.as_ptr().cast(), std::mem::size_of_val(&record)) };
    // SAFETY: exit without running any post-fork destructors or atexit handlers.
    unsafe { libc::_exit(127) }
}

fn child_failure(fd: i32, status: i32) -> LaunchError {
    let mut record = [0_i32; 2];
    // SAFETY: record is writable; fd is the nonblocking child-error pipe.
    let count = unsafe {
        libc::read(
            fd,
            record.as_mut_ptr().cast(),
            std::mem::size_of_val(&record),
        )
    };
    if count == std::mem::size_of_val(&record) as isize {
        let operation = match record[0] {
            1 => "child PTRACE_TRACEME",
            2 => "child pre-exec stop",
            _ => "child execve",
        };
        io_error(operation, io::Error::from_raw_os_error(record[1]))
    } else {
        LaunchError::Child { status }
    }
}

fn ptrace(request: u32, pid: libc::pid_t, address: usize, data: usize) -> Result<(), LaunchError> {
    // SAFETY: request-specific callers provide valid pointers or scalar values;
    // the named child is stopped and owned throughout the operation.
    if unsafe { libc::ptrace(request, pid, address, data) } == -1 {
        return Err(system("ptrace"));
    }
    Ok(())
}

fn read_registers(pid: libc::pid_t) -> Result<RegisterSnapshot, LaunchError> {
    let mut registers = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    ptrace(
        libc::PTRACE_GETREGS,
        pid,
        0,
        registers.as_mut_ptr() as usize,
    )?;
    // SAFETY: successful GETREGS initialized the complete structure.
    Ok(unsafe { registers.assume_init() }.into())
}

fn read_memory(pid: libc::pid_t, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
    if len > MAX_MEMORY_READ {
        return Err(LaunchError::Invalid("memory read exceeds limit"));
    }
    let end = address
        .checked_add(len as u64)
        .ok_or(LaunchError::Invalid("memory read address overflow"))?;
    let mut result = Vec::with_capacity(len);
    let mut cursor = address;
    while cursor < end {
        let aligned = cursor & !7;
        // SAFETY: errno is thread-local; PEEKDATA reads the owned stopped child.
        let word = unsafe {
            *libc::__errno_location() = 0;
            let value = libc::ptrace(libc::PTRACE_PEEKDATA, pid, aligned as usize, 0);
            if value == -1 && *libc::__errno_location() != 0 {
                return Err(system("PTRACE_PEEKDATA"));
            }
            value as u64
        };
        let start = (cursor - aligned) as usize;
        let count = (8 - start).min((end - cursor) as usize);
        result.extend_from_slice(&word.to_ne_bytes()[start..start + count]);
        cursor += count as u64;
    }
    Ok(result)
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, LaunchError> {
    let file = File::open(path).map_err(|error| io_error("open image metadata", error))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read image metadata", error))?;
    if bytes.len() > limit {
        return Err(LaunchError::Invalid("image metadata exceeds limit"));
    }
    Ok(bytes)
}

fn read_maps(pid: libc::pid_t) -> Result<Vec<MemoryMapping>, LaunchError> {
    let bytes = read_bounded(Path::new(&format!("/proc/{pid}/maps")), MAX_PROC_FILE)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| LaunchError::Invalid("non-UTF8 maps"))?;
    text.lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let range = fields
                .next()
                .ok_or(LaunchError::Invalid("missing mapping range"))?;
            let (start, end) = range
                .split_once('-')
                .ok_or(LaunchError::Invalid("mapping range"))?;
            let permissions = fields
                .next()
                .ok_or(LaunchError::Invalid("mapping permissions"))?;
            if permissions.len() != 4 {
                return Err(LaunchError::Invalid("mapping permission width"));
            }
            let offset = fields
                .next()
                .ok_or(LaunchError::Invalid("mapping offset"))?;
            fields
                .next()
                .ok_or(LaunchError::Invalid("mapping device"))?;
            fields.next().ok_or(LaunchError::Invalid("mapping inode"))?;
            let name = fields.collect::<Vec<_>>().join(" ");
            let mapping = MemoryMapping {
                start: hex(start)?,
                end: hex(end)?,
                permissions: permissions.to_owned(),
                file_offset: hex(offset)?,
                pathname: (!name.is_empty()).then_some(name),
            };
            if mapping.start >= mapping.end {
                return Err(LaunchError::Invalid("empty mapping"));
            }
            Ok(mapping)
        })
        .collect()
}

fn hex(value: &str) -> Result<u64, LaunchError> {
    u64::from_str_radix(value, 16).map_err(|_| LaunchError::Invalid("invalid hexadecimal metadata"))
}

fn read_auxv(pid: libc::pid_t) -> Result<Vec<(u64, u64)>, LaunchError> {
    let bytes = read_bounded(Path::new(&format!("/proc/{pid}/auxv")), MAX_MEMORY_READ)?;
    if bytes.len() % 16 != 0 {
        return Err(LaunchError::Invalid("truncated auxiliary vector"));
    }
    let mut result = Vec::new();
    for pair in bytes.chunks_exact(16) {
        let key = u64::from_ne_bytes(pair[..8].try_into().unwrap());
        let value = u64::from_ne_bytes(pair[8..].try_into().unwrap());
        if key == libc::AT_NULL {
            return Ok(result);
        }
        if result.iter().any(|(seen, _)| *seen == key) {
            return Err(LaunchError::Invalid("duplicate auxiliary vector key"));
        }
        result.push((key, value));
    }
    Err(LaunchError::Invalid("unterminated auxiliary vector"))
}

fn aux(auxv: &[(u64, u64)], key: u64) -> Result<u64, LaunchError> {
    auxv.iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| *value)
        .ok_or(LaunchError::Invalid("missing auxiliary vector entry"))
}

struct Elf {
    kind: u16,
    entry: u64,
    phoff: u64,
    phnum: usize,
    phdr_vaddr: Option<u64>,
    interpreter: Option<PathBuf>,
}

impl Elf {
    fn header(bytes: &[u8]) -> Result<Self, LaunchError> {
        if bytes.len() < 64 || &bytes[..7] != b"\x7fELF\x02\x01\x01" {
            return Err(LaunchError::Invalid("not a little-endian ELF64 image"));
        }
        let u16_at = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
        let u64_at = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let kind = u16_at(16);
        if !matches!(kind, 2 | 3) || u16_at(18) != 62 || u16_at(52) != 64 || u16_at(54) != 56 {
            return Err(LaunchError::Invalid(
                "unsupported ELF type, machine, or header size",
            ));
        }
        let phnum = usize::from(u16_at(56));
        if phnum == 0 || phnum > 1024 {
            return Err(LaunchError::Invalid("ELF program header count"));
        }
        if u64_at(32) < 64 {
            return Err(LaunchError::Invalid("ELF program headers overlap header"));
        }
        Ok(Self {
            kind,
            entry: u64_at(24),
            phoff: u64_at(32),
            phnum,
            phdr_vaddr: None,
            interpreter: None,
        })
    }

    fn read_file(path: &Path) -> Result<Self, LaunchError> {
        // Only a bounded header prefix is needed, regardless of executable size.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| io_error("open executable", error))?;
        if !file
            .metadata()
            .map_err(|error| io_error("stat executable", error))?
            .is_file()
        {
            return Err(LaunchError::Invalid("executable is not a regular file"));
        }
        let mut bytes = vec![0; 64];
        file.read_exact(&mut bytes)
            .map_err(|error| io_error("read ELF header", error))?;
        let mut elf = Self::header(&bytes)?;
        let end = elf
            .phoff
            .checked_add((elf.phnum * 56) as u64)
            .filter(|end| *end <= MAX_PROC_FILE as u64)
            .ok_or(LaunchError::Invalid("ELF program header bounds"))? as usize;
        if end < 64 {
            return Err(LaunchError::Invalid("ELF program headers overlap header"));
        }
        bytes.resize(end, 0);
        file.read_exact(&mut bytes[64..])
            .map_err(|error| io_error("read ELF program headers", error))?;
        for index in 0..elf.phnum {
            let offset = elf.phoff as usize + index * 56;
            let ph = &bytes[offset..offset + 56];
            let kind = u32::from_le_bytes(ph[..4].try_into().unwrap());
            let u64_at = |at| u64::from_le_bytes(ph[at..at + 8].try_into().unwrap());
            let file_offset = u64_at(8);
            let vaddr = u64_at(16);
            let filesz = u64_at(32);
            if kind == 6 {
                elf.phdr_vaddr = Some(vaddr);
            } else if kind == 1
                && elf.phdr_vaddr.is_none()
                && file_offset <= elf.phoff
                && file_offset
                    .checked_add(filesz)
                    .is_some_and(|bound| bound >= end as u64)
            {
                elf.phdr_vaddr = vaddr.checked_add(elf.phoff - file_offset);
            } else if kind == 3 {
                if elf.interpreter.is_some() || filesz == 0 || filesz > 4096 {
                    return Err(LaunchError::Invalid("ELF interpreter bounds"));
                }
                use std::io::{Seek, SeekFrom};
                file.seek(SeekFrom::Start(file_offset))
                    .map_err(|error| io_error("seek PT_INTERP", error))?;
                let mut name = vec![0; filesz as usize];
                file.read_exact(&mut name)
                    .map_err(|error| io_error("read PT_INTERP", error))?;
                if name.pop() != Some(0) || name.contains(&0) {
                    return Err(LaunchError::Invalid("unterminated ELF interpreter"));
                }
                elf.interpreter = Some(PathBuf::from(OsStr::from_bytes(&name)));
            }
        }
        Ok(elf)
    }

    fn runtime_entry(&self, runtime_phdr: u64) -> Result<u64, LaunchError> {
        if self.kind == 2 {
            return Ok(self.entry);
        }
        let relative_phdr = self
            .phdr_vaddr
            .ok_or(LaunchError::Invalid("unmapped ELF program headers"))?;
        runtime_phdr
            .checked_sub(relative_phdr)
            .and_then(|bias| bias.checked_add(self.entry))
            .ok_or(LaunchError::Invalid("PIE load bias or entry overflow"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_child_wait_timeout_keeps_ownership_until_kill_and_reap() {
        let reaper = prepare_reaper().unwrap();
        let fork_guard = crate::TEST_FILE_FORK.lock().unwrap();
        // SAFETY: the child uses only raw libc calls before exit, with no Rust
        // allocation, unwinding or destructors after fork.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: this is the new child. It stops before doing any work and
            // can only leave the stop through its owning tracer or SIGKILL.
            unsafe {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    libc::_exit(127);
                }
                libc::kill(libc::getpid(), libc::SIGSTOP);
                libc::_exit(126);
            }
        }
        let mut child = ChildOwner {
            pid,
            reaped: false,
            reaper: Some(reaper),
        };
        let status = child
            .wait(Instant::now() + Duration::from_secs(2), "fixture stop")
            .unwrap();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            0,
            libc::PTRACE_O_EXITKILL as usize,
        )
        .unwrap();
        // The only stop has been consumed. No resume occurs, so there can be no
        // further wait event until cleanup sends SIGKILL.
        assert!(matches!(
            child.wait(Instant::now() + Duration::from_millis(5), "forced timeout"),
            Err(LaunchError::Timeout("forced timeout"))
        ));
        assert!(!child.reaped);
        child.terminate().unwrap();
        assert!(child.reaped);
        let mut status = 0;
        // SAFETY: verifies this specific child's reaping; no unrelated child is waited.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}
