//! Fixed initialized request payloads. Collection never grants a held stop.
use super::super::mapping::maps::ParsedMaps;
use super::*;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(test)]
mod tests;

// Query substrates live in H. These are the bounded decoded/borrowed values
// and OS-handle wrappers created while interpreting those retained requests.
pub(super) fn temporary_bytes() -> Result<usize, LaunchError> {
    let terms = [
        (1, size_of::<libc::user_regs_struct>()),
        (1, size_of::<RegisterSnapshot>()),
        (1, size_of::<libc::ptrace_syscall_info>()),
        (1, size_of::<libc::siginfo_t>()),
        (2, size_of::<OwnedFd>()),
        (2, size_of::<Request>()),
        (3, size_of::<Result<(), LaunchError>>()),
        (1, size_of::<RuntimeStateReadView<'_>>()),
        (1, size_of::<RuntimeFixedReads<'_>>()),
        (1, size_of::<RuntimeMapsReadView<'_>>()),
        (1, size_of::<ParsedMaps<'_>>()),
        (1, size_of::<super::super::mapping::maps::MapEntry<'_>>()),
    ];
    terms
        .into_iter()
        .try_fold(0, |total, (count, bytes)| add(total, mul(count, bytes)?))
}

pub(super) fn request(operation: u32, tid: i32, address: usize, data: usize) -> Request {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let result = unsafe {
        libc::ptrace(
            operation,
            tid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    let error = unsafe { *libc::__errno_location() };
    Request {
        result,
        errno: (result == -1 && error != 0).then_some(error),
    }
}
pub(super) fn checked(actual: Request, operation: &'static str) -> Result<(), LaunchError> {
    if let Some(errno) = actual.errno {
        return Err(io_error(
            operation,
            std::io::Error::from_raw_os_error(errno),
        ));
    }
    if actual.result != 0 {
        return Err(LaunchError::Invalid(
            "runtime kernel request returned nonzero",
        ));
    }
    Ok(())
}
fn outcome(result: i64) -> Request {
    Request {
        result,
        errno: (result < 0).then(|| unsafe { *libc::__errno_location() }),
    }
}
fn successful(actual: Request, operation: &'static str) -> Result<i64, LaunchError> {
    if let Some(errno) = actual.errno {
        return Err(io_error(
            operation,
            std::io::Error::from_raw_os_error(errno),
        ));
    }
    if actual.result < 0 {
        return Err(LaunchError::Invalid(
            "runtime kernel negative request without errno",
        ));
    }
    Ok(actual.result)
}

pub(super) struct StateRead {
    pub(super) state: TaskStateSnapshot,
    registers: [u8; 216],
    registers_request: Option<Request>,
    xstate_request: Option<Request>,
    mask: [u8; 8],
    mask_request: Option<Request>,
    vector: libc::iovec,
    requested_pointer: usize,
    requested_length: usize,
    pub(super) complete: bool,
}
impl Default for StateRead {
    fn default() -> Self {
        Self {
            state: TaskStateSnapshot {
                registers: RegisterSnapshot::from(unsafe {
                    std::mem::zeroed::<libc::user_regs_struct>()
                }),
                xstate: Vec::new(),
                mask: 0,
            },
            registers: [0; 216],
            registers_request: None,
            xstate_request: None,
            mask: [0; 8],
            mask_request: None,
            vector: libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            requested_pointer: 0,
            requested_length: 0,
            complete: false,
        }
    }
}
impl StateRead {
    pub(super) fn allocate(&mut self) -> Result<(), LaunchError> {
        if self.capacity() != 0 {
            return Err(LaunchError::Invalid(
                "runtime kernel state allocation reused",
            ));
        }
        let layout = std::alloc::Layout::array::<u8>(MAX_XSTATE)
            .map_err(|_| LaunchError::Invalid("runtime kernel state layout differs"))?;
        let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
        if pointer.is_null() {
            return Err(LaunchError::Invalid(
                "runtime kernel state allocation failed",
            ));
        }
        // Exact u8 allocation, initialized throughout; ownership is installed
        // before any later allocation can fail. No allocator growth heuristic.
        self.state.xstate = unsafe { Vec::from_raw_parts(pointer, MAX_XSTATE, MAX_XSTATE) };
        Ok(())
    }
    pub(super) fn capacity(&self) -> usize {
        self.state.xstate.capacity()
    }
    pub(super) fn view(&self) -> RuntimeStateReadView<'_> {
        // All capacity bytes were zero-initialized at allocation and every
        // capture. Truncating a Vec<u8> never deinitializes its remaining bytes.
        let initialized = unsafe {
            std::slice::from_raw_parts(self.state.xstate.as_ptr(), self.state.xstate.capacity())
        };
        RuntimeStateReadView {
            registers: &self.registers,
            registers_request: self.registers_request,
            xstate_initialized: initialized,
            xstate_request: self.xstate_request,
            requested_pointer: self.requested_pointer,
            returned_pointer: self.vector.iov_base as usize,
            requested_length: self.requested_length,
            returned_length: self.vector.iov_len,
            mask: &self.mask,
            mask_request: self.mask_request,
            complete: self.complete,
            state: self.complete.then_some(&self.state),
        }
    }
    pub(super) fn capture(&mut self, owner: &Owner, until: Instant) -> Result<(), LaunchError> {
        self.reset_requests();
        bootstrap::physical(owner, until)?;
        let result = self.capture_tid(owner.pid);
        result?;
        bootstrap::physical(owner, until)
    }
    pub(super) fn capture_tid(&mut self, tid: i32) -> Result<(), LaunchError> {
        self.reset_requests();
        if self.capacity() != MAX_XSTATE
            || size_of::<libc::user_regs_struct>() != self.registers.len()
        {
            return Err(LaunchError::Invalid(
                "runtime kernel state storage or ABI differs",
            ));
        }
        self.complete = false;
        self.registers.fill(0);
        self.mask.fill(0);
        self.state.xstate.resize(MAX_XSTATE, 0);
        self.state.xstate.fill(0);
        self.registers_request = Some(request(
            libc::PTRACE_GETREGS,
            tid,
            0,
            self.registers.as_mut_ptr() as usize,
        ));
        self.requested_pointer = self.state.xstate.as_mut_ptr() as usize;
        self.requested_length = MAX_XSTATE;
        self.vector = libc::iovec {
            iov_base: self.state.xstate.as_mut_ptr().cast(),
            iov_len: MAX_XSTATE,
        };
        self.xstate_request = Some(request(
            libc::PTRACE_GETREGSET,
            tid,
            NT_X86_XSTATE,
            (&raw mut self.vector) as usize,
        ));
        self.mask_request = Some(request(
            libc::PTRACE_GETSIGMASK,
            tid,
            8,
            self.mask.as_mut_ptr() as usize,
        ));
        // No earlier request result suppresses either remaining request.
        self.state.registers = RegisterSnapshot::from(unsafe {
            std::ptr::read_unaligned(self.registers.as_ptr().cast::<libc::user_regs_struct>())
        });
        self.state.mask = u64::from_ne_bytes(self.mask);
        checked(
            self.registers_request.expect("attempted registers"),
            "PTRACE_GETREGS",
        )?;
        checked(
            self.xstate_request.expect("attempted xstate"),
            "PTRACE_GETREGSET",
        )?;
        checked(
            self.mask_request.expect("attempted mask"),
            "PTRACE_GETSIGMASK",
        )?;
        if !valid_xstate(
            self.requested_pointer,
            self.vector.iov_base as usize,
            self.vector.iov_len,
        ) {
            return Err(LaunchError::Invalid(
                "runtime kernel missing or truncated xstate",
            ));
        }
        self.state.xstate.truncate(self.vector.iov_len);
        self.complete = true;
        Ok(())
    }
    fn reset_requests(&mut self) {
        self.complete = false;
        self.registers_request = None;
        self.xstate_request = None;
        self.mask_request = None;
        self.requested_pointer = 0;
        self.requested_length = 0;
        self.vector = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
    }
}
pub(super) fn valid_xstate(requested: usize, returned: usize, length: usize) -> bool {
    requested != 0 && requested == returned && (512..MAX_XSTATE).contains(&length)
}

pub(super) struct FixedReads {
    syscall_info: [u8; 88],
    syscall_info_request: Option<Request>,
    pub(super) event_message: u64,
    pub(super) event_message_request: Option<Request>,
    signal: [u8; 128],
    signal_request: Option<Request>,
}
impl Default for FixedReads {
    fn default() -> Self {
        Self {
            syscall_info: [0; 88],
            syscall_info_request: None,
            event_message: 0,
            event_message_request: None,
            signal: [0; 128],
            signal_request: None,
        }
    }
}
impl FixedReads {
    pub(super) fn view(&self) -> RuntimeFixedReads<'_> {
        RuntimeFixedReads {
            syscall_info: &self.syscall_info,
            syscall_info_request: self.syscall_info_request,
            event_message: self.event_message,
            event_message_request: self.event_message_request,
            signal: &self.signal,
            signal_request: self.signal_request,
        }
    }
    pub(super) fn capture(&mut self, tid: i32) -> Result<(), LaunchError> {
        if self.syscall_info_request.is_some()
            || self.signal_request.is_some()
            || self.event_message_request.is_some()
        {
            return Err(LaunchError::Invalid(
                "runtime kernel fixed raw reads reused",
            ));
        }
        self.syscall_info_request = Some(request(
            libc::PTRACE_GET_SYSCALL_INFO,
            tid,
            self.syscall_info.len(),
            self.syscall_info.as_mut_ptr() as usize,
        ));
        self.event_message_request = Some(request(
            libc::PTRACE_GETEVENTMSG,
            tid,
            0,
            (&raw mut self.event_message) as usize,
        ));
        self.signal_request = Some(request(
            libc::PTRACE_GETSIGINFO,
            tid,
            0,
            self.signal.as_mut_ptr() as usize,
        ));
        let count = successful(
            self.syscall_info_request.expect("attempted info"),
            "PTRACE_GET_SYSCALL_INFO",
        )?;
        if !(24..=88).contains(&count) {
            return Err(LaunchError::Invalid(
                "runtime kernel syscall info extent differs",
            ));
        }
        checked(
            self.event_message_request.expect("attempted event message"),
            "PTRACE_GETEVENTMSG",
        )?;
        checked(
            self.signal_request.expect("attempted signal"),
            "PTRACE_GETSIGINFO",
        )
    }
    pub(super) fn syscall(
        &self,
        entry: bool,
        state: &TaskStateSnapshot,
        identity: &RuntimeKernelIdentity,
    ) -> Result<(), LaunchError> {
        let info = self.syscall_header(entry, state)?;
        if entry {
            let input = unsafe { info.u.entry };
            if input.nr != identity.number() || input.args != identity.arguments() {
                return Err(LaunchError::Invalid(
                    "runtime kernel actual ENTRY arguments differ",
                ));
            }
        } else {
            let output = unsafe { info.u.exit };
            if output.sval as u64 != state.registers.rax || output.is_error != 0 {
                return Err(LaunchError::Invalid(
                    "runtime kernel actual EXIT result differs",
                ));
            }
        }
        Ok(())
    }
    fn syscall_header(
        &self,
        entry: bool,
        state: &TaskStateSnapshot,
    ) -> Result<libc::ptrace_syscall_info, LaunchError> {
        let minimum = if entry { 80 } else { 33 };
        let actual = self.syscall_info_request.ok_or(LaunchError::Invalid(
            "runtime kernel syscall info unattempted",
        ))?;
        let count = successful(actual, "PTRACE_GET_SYSCALL_INFO")?;
        if !(minimum..=88).contains(&count) || size_of::<libc::ptrace_syscall_info>() != 88 {
            return Err(LaunchError::Invalid(
                "runtime kernel meaningful syscall info truncated",
            ));
        }
        let info = unsafe {
            std::ptr::read_unaligned(
                self.syscall_info
                    .as_ptr()
                    .cast::<libc::ptrace_syscall_info>(),
            )
        };
        if info.arch != 0xc000_003e
            || info.instruction_pointer != state.registers.rip
            || info.stack_pointer != state.registers.rsp
            || info.op
                != if entry {
                    libc::PTRACE_SYSCALL_INFO_ENTRY
                } else {
                    libc::PTRACE_SYSCALL_INFO_EXIT
                }
        {
            return Err(LaunchError::Invalid(
                "runtime kernel syscall info identity differs",
            ));
        }
        Ok(info)
    }
    pub(super) fn owned_trap(&self) -> Result<(), LaunchError> {
        checked(
            self.signal_request.ok_or(LaunchError::Invalid(
                "runtime kernel trap signal unattempted",
            ))?,
            "PTRACE_GETSIGINFO",
        )?;
        if size_of::<libc::siginfo_t>() != 128 {
            return Err(LaunchError::Invalid("runtime kernel signal ABI differs"));
        }
        let info =
            unsafe { std::ptr::read_unaligned(self.signal.as_ptr().cast::<libc::siginfo_t>()) };
        if info.si_signo != libc::SIGTRAP || info.si_errno != 0 || info.si_code != libc::SI_KERNEL {
            return Err(LaunchError::Invalid(
                "runtime kernel owned INT3 signal differs",
            ));
        }
        Ok(())
    }
}

pub(super) struct MapsRead {
    storage: Option<Box<[u8; MAP_BYTES]>>,
    length: usize,
    directory_open: Option<Request>,
    filesystem_request: Option<Request>,
    filesystem: Option<i64>,
    maps_open: Option<Request>,
    read_calls: usize,
    last_read: Option<Request>,
    overflow_probe: Option<Request>,
    complete: bool,
    path: [u8; 32],
    digits: [u8; 10],
    stat: libc::statfs,
    extra: u8,
}
impl Default for MapsRead {
    fn default() -> Self {
        Self {
            storage: None,
            length: 0,
            directory_open: None,
            filesystem_request: None,
            filesystem: None,
            maps_open: None,
            read_calls: 0,
            last_read: None,
            overflow_probe: None,
            complete: false,
            path: [0; 32],
            digits: [0; 10],
            stat: unsafe { std::mem::zeroed() },
            extra: 0,
        }
    }
}
impl MapsRead {
    pub(super) fn allocate(&mut self) -> Result<(), LaunchError> {
        if self.storage.is_some() {
            return Err(LaunchError::Invalid("runtime kernel map allocation reused"));
        }
        self.storage = Some(fixed_buffer()?);
        Ok(())
    }
    pub(super) fn capacity(&self) -> usize {
        usize::from(self.storage.is_some()) * MAP_BYTES
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.storage.as_ref().expect("preallocated maps")[..self.length]
    }
    pub(super) fn view(&self) -> Option<RuntimeMapsReadView<'_>> {
        Some(RuntimeMapsReadView {
            initialized: self.storage.as_ref()?.as_slice(),
            length: self.length,
            directory_open: self.directory_open,
            filesystem_request: self.filesystem_request,
            filesystem: self.filesystem,
            maps_open: self.maps_open,
            read_calls: self.read_calls,
            last_read: self.last_read,
            overflow_probe: self.overflow_probe,
            complete: self.complete,
        })
    }
    pub(super) fn capture(&mut self, owner: &Owner, until: Instant) -> Result<(), LaunchError> {
        let storage = self
            .storage
            .as_mut()
            .ok_or(LaunchError::Invalid("runtime kernel map storage absent"))?;
        storage.fill(0);
        self.length = 0;
        self.complete = false;
        self.directory_open = None;
        self.filesystem_request = None;
        self.filesystem = None;
        self.maps_open = None;
        self.read_calls = 0;
        self.last_read = None;
        self.overflow_probe = None;
        self.extra = 0;
        bootstrap::physical(owner, until)?;
        self.path.fill(0);
        self.path[..6].copy_from_slice(b"/proc/");
        self.digits.fill(0);
        let mut value = u32::try_from(owner.pid)
            .ok()
            .filter(|value| *value != 0)
            .ok_or(LaunchError::Invalid("runtime kernel map tid differs"))?;
        let mut start = self.digits.len();
        while value != 0 {
            start -= 1;
            self.digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        self.path[6..6 + self.digits.len() - start].copy_from_slice(&self.digits[start..]);
        let opened = outcome(unsafe {
            libc::open(
                self.path.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        } as i64);
        self.directory_open = Some(opened);
        let fd = successful(opened, "open runtime kernel proc directory")?;
        let directory = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        self.stat = unsafe { std::mem::zeroed() };
        let stated =
            outcome(unsafe { libc::fstatfs(directory.as_raw_fd(), &mut self.stat) } as i64);
        self.filesystem_request = Some(stated);
        checked(stated, "fstatfs runtime kernel proc directory")?;
        self.filesystem = Some(self.stat.f_type);
        if self.stat.f_type != libc::PROC_SUPER_MAGIC {
            return Err(LaunchError::Invalid("runtime kernel maps are not procfs"));
        }
        let opened = outcome(unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c"maps".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        } as i64);
        self.maps_open = Some(opened);
        let fd = successful(opened, "open runtime kernel maps")?;
        let maps = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        loop {
            owner.time_left(until, "runtime kernel maps capture")?;
            let full = self.length == MAP_BYTES;
            let (pointer, count) = if full {
                ((&raw mut self.extra), 1)
            } else {
                (storage[self.length..].as_mut_ptr(), MAP_BYTES - self.length)
            };
            let actual =
                outcome(unsafe { libc::read(maps.as_raw_fd(), pointer.cast(), count) } as i64);
            self.read_calls = self.read_calls.checked_add(1).ok_or(LaunchError::Invalid(
                "runtime kernel map read count overflow",
            ))?;
            self.last_read = Some(actual);
            if full {
                self.overflow_probe = Some(actual);
            }
            let read = successful(actual, "read runtime kernel maps")? as usize;
            if read > count || (full && read != 0) {
                return Err(LaunchError::Invalid(
                    "runtime kernel maps exceed fixed bound",
                ));
            }
            if !full {
                self.length += read;
            }
            // Retain every actually copied prefix before a deadline refusal.
            owner.time_left(until, "runtime kernel maps capture")?;
            if read == 0 {
                break;
            }
        }
        ParsedMaps::parse(&storage[..self.length], 512)
            .map_err(|_| LaunchError::Invalid("runtime kernel maps malformed"))?;
        bootstrap::physical(owner, until)?;
        self.complete = true;
        Ok(())
    }
}
