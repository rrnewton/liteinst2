//! Initialized, bounded request storage. No query here fabricates a held stop.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct Request {
    pub(in crate::linux::remote::dynamic::owner) result: i64,
    pub(in crate::linux::remote::dynamic::owner) errno: Option<i32>,
}
impl Request {
    fn result(self, operation: &'static str) -> Result<(), LaunchError> {
        if let Some(errno) = self.errno {
            return Err(io_error(
                operation,
                std::io::Error::from_raw_os_error(errno),
            ));
        }
        if self.result != 0 {
            return Err(LaunchError::Invalid(
                "initial bootstrap ptrace return differs",
            ));
        }
        Ok(())
    }
}
fn request(operation: u32, tid: i32, address: usize, data: usize) -> Request {
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
    let errno = if result == -1 {
        let value = unsafe { *libc::__errno_location() };
        (value != 0).then_some(value)
    } else {
        None
    };
    Request { result, errno }
}
fn empty_state() -> TaskStateSnapshot {
    TaskStateSnapshot {
        registers: RegisterSnapshot::from(unsafe { std::mem::zeroed::<libc::user_regs_struct>() }),
        xstate: Vec::new(),
        mask: 0,
    }
}

pub(in crate::linux::remote::dynamic::owner) struct StateSlot {
    pub(in crate::linux::remote::dynamic::owner) state: TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic::owner) registers_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) xstate_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) mask_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) requested_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner) returned_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner) returned_length: usize,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
}
impl StateSlot {
    pub(in crate::linux::remote::dynamic::owner) fn allocated_bytes(&self) -> usize {
        size_of::<Self>() + self.state.xstate.capacity()
    }
    pub(in crate::linux::remote::dynamic::owner) fn allocate() -> Result<Self, LaunchError> {
        let mut state = empty_state();
        state.xstate = storage::state_bytes()?;
        Ok(Self {
            state,
            registers_request: None,
            xstate_request: None,
            mask_request: None,
            requested_pointer: 0,
            returned_pointer: 0,
            returned_length: 0,
            complete: false,
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn initialized_state(&self) -> &TaskStateSnapshot {
        &self.state
    }
    pub(in crate::linux::remote::dynamic::owner) fn capture(
        &mut self,
        owner: &Owner,
        until: Instant,
    ) -> Result<(), LaunchError> {
        owner.time_left(until, "initial bootstrap state capture")?;
        let result = self.capture_tid(owner.pid);
        result?;
        owner.time_left(until, "initial bootstrap state capture")
    }
    pub(in crate::linux::remote::dynamic::owner) fn capture_tid(
        &mut self,
        tid: i32,
    ) -> Result<(), LaunchError> {
        if self.state.xstate.capacity() < MAX_XSTATE {
            return Err(LaunchError::Invalid(
                "initial bootstrap state storage was transferred",
            ));
        }
        self.complete = false;
        self.state.xstate.resize(MAX_XSTATE, 0);
        self.state.xstate.fill(0);
        self.state.mask = 0;
        let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let registers_request =
            request(libc::PTRACE_GETREGS, tid, 0, (&raw mut registers) as usize);
        self.registers_request = Some(registers_request);
        self.state.registers = registers.into();
        let pointer = self.state.xstate.as_mut_ptr().cast::<libc::c_void>();
        let mut vector = libc::iovec {
            iov_base: pointer,
            iov_len: MAX_XSTATE,
        };
        let xstate_request = request(
            libc::PTRACE_GETREGSET,
            tid,
            NT_X86_XSTATE,
            (&raw mut vector) as usize,
        );
        self.xstate_request = Some(xstate_request);
        self.requested_pointer = pointer as usize;
        self.returned_pointer = vector.iov_base as usize;
        self.returned_length = vector.iov_len;
        let mask_request = request(
            libc::PTRACE_GETSIGMASK,
            tid,
            8,
            (&raw mut self.state.mask) as usize,
        );
        self.mask_request = Some(mask_request);
        // Interpret only after all three independent requests. Full initialized
        // MAX substrate remains accessible even when an earlier request failed.
        registers_request.result("PTRACE_GETREGS")?;
        xstate_request.result("PTRACE_GETREGSET")?;
        mask_request.result("PTRACE_GETSIGMASK")?;
        if vector.iov_base != pointer || !(512..MAX_XSTATE).contains(&vector.iov_len) {
            return Err(LaunchError::Invalid("missing or truncated xstate image"));
        }
        self.state.xstate.truncate(vector.iov_len);
        self.complete = true;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner) fn copy_from(
        &mut self,
        other: &Self,
    ) -> Result<(), LaunchError> {
        if !other.complete || self.state.xstate.capacity() < MAX_XSTATE {
            return Err(LaunchError::Invalid(
                "initial bootstrap copied incomplete state",
            ));
        }
        self.state.registers = other.state.registers;
        self.state.mask = other.state.mask;
        self.state.xstate.clear();
        self.state.xstate.extend_from_slice(&other.state.xstate);
        // This is an explicit derived restoration expectation, not another
        // successful native request. Do not copy the observed request facts.
        self.registers_request = None;
        self.xstate_request = None;
        self.mask_request = None;
        self.requested_pointer = 0;
        self.returned_pointer = 0;
        self.returned_length = 0;
        self.complete = true;
        Ok(())
    }
    pub(super) fn move_state(&mut self) -> TaskStateSnapshot {
        std::mem::replace(&mut self.state, empty_state())
    }
}

pub(in crate::linux::remote::dynamic::owner) struct SyscallObservation {
    pub(in crate::linux::remote::dynamic::owner) bytes: [u8; 88],
    pub(in crate::linux::remote::dynamic::owner) request: Option<Request>,
}
impl Default for SyscallObservation {
    fn default() -> Self {
        Self {
            bytes: [0; 88],
            request: None,
        }
    }
}
impl SyscallObservation {
    pub(in crate::linux::remote::dynamic::owner) fn capture(
        &mut self,
        tid: i32,
    ) -> Result<(), LaunchError> {
        self.bytes.fill(0);
        let result = request(
            libc::PTRACE_GET_SYSCALL_INFO,
            tid,
            self.bytes.len(),
            self.bytes.as_mut_ptr() as usize,
        );
        self.request = Some(result);
        if let Some(errno) = result.errno {
            return Err(io_error(
                "PTRACE_GET_SYSCALL_INFO",
                std::io::Error::from_raw_os_error(errno),
            ));
        }
        if result.result < 33 {
            return Err(LaunchError::Invalid("truncated syscall-stop information"));
        }
        Ok(())
    }
    pub(super) fn validate_exit(&self, state: &TaskStateSnapshot) -> Result<(), LaunchError> {
        if size_of::<libc::ptrace_syscall_info>() != self.bytes.len() {
            return Err(LaunchError::Invalid(
                "initial bootstrap syscall-info ABI differs",
            ));
        }
        let info = unsafe {
            std::ptr::read_unaligned(self.bytes.as_ptr().cast::<libc::ptrace_syscall_info>())
        };
        if info.op != libc::PTRACE_SYSCALL_INFO_EXIT
            || info.arch != AUDIT_ARCH_X86_64
            || info.instruction_pointer != state.registers.rip
            || info.stack_pointer != state.registers.rsp
            || state.registers.cs != 0x33
        {
            return Err(LaunchError::Invalid(
                "initial bootstrap syscall EXIT identity differs",
            ));
        }
        let exit = unsafe { info.u.exit };
        if exit.sval != 0 || exit.is_error != 0 || state.registers.rax != 0 {
            return Err(LaunchError::Invalid(
                "initial bootstrap syscall EXIT result differs",
            ));
        }
        Ok(())
    }
}
pub(in crate::linux::remote::dynamic::owner) struct SignalObservation {
    pub(in crate::linux::remote::dynamic::owner) bytes: [u8; 128],
    pub(in crate::linux::remote::dynamic::owner) request: Option<Request>,
}
impl Default for SignalObservation {
    fn default() -> Self {
        Self {
            bytes: [0; 128],
            request: None,
        }
    }
}
impl SignalObservation {
    pub(in crate::linux::remote::dynamic::owner) fn capture(
        &mut self,
        tid: i32,
    ) -> Result<(), LaunchError> {
        self.bytes.fill(0);
        let result = request(
            libc::PTRACE_GETSIGINFO,
            tid,
            0,
            self.bytes.as_mut_ptr() as usize,
        );
        self.request = Some(result);
        result.result("PTRACE_GETSIGINFO")
    }
    pub(in crate::linux::remote::dynamic::owner) fn validate(&self) -> Result<(), LaunchError> {
        if size_of::<libc::siginfo_t>() != self.bytes.len() {
            return Err(LaunchError::Invalid(
                "initial bootstrap siginfo ABI differs",
            ));
        }
        let info =
            unsafe { std::ptr::read_unaligned(self.bytes.as_ptr().cast::<libc::siginfo_t>()) };
        if info.si_signo != libc::SIGTRAP
            || !matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT)
        {
            return Err(LaunchError::Invalid(
                "initial bootstrap trap signal differs",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(in crate::linux::remote::dynamic::owner) struct MemoryObservation {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Retained memory request evidence is inspected by native controls"
        )
    )]
    pub(in crate::linux::remote::dynamic::owner) address: u64,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Retained memory request evidence is inspected by native controls"
        )
    )]
    pub(in crate::linux::remote::dynamic::owner) requested: usize,
    pub(in crate::linux::remote::dynamic::owner) copied: usize,
    pub(in crate::linux::remote::dynamic::owner) last_word: [u8; 8],
    pub(in crate::linux::remote::dynamic::owner) bytes: [u8; 68],
    pub(in crate::linux::remote::dynamic::owner) last_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
}
impl Default for MemoryObservation {
    fn default() -> Self {
        Self {
            address: 0,
            requested: 0,
            copied: 0,
            last_word: [0; 8],
            bytes: [0; 68],
            last_request: None,
            complete: false,
        }
    }
}
pub(super) fn memory(
    owner: &Owner,
    address: u64,
    bytes: &mut [u8],
    observation: &mut MemoryObservation,
    until: Instant,
) -> Result<(), LaunchError> {
    *observation = MemoryObservation {
        address,
        requested: bytes.len(),
        ..MemoryObservation::default()
    };
    bytes.fill(0);
    if bytes.is_empty() || bytes.len() > observation.bytes.len() {
        return Err(LaunchError::Invalid("memory read exceeds limit"));
    }
    let end = address
        .checked_add(bytes.len() as u64)
        .ok_or(LaunchError::Invalid(
            "initial bootstrap memory range overflows",
        ))?;
    while observation.copied < bytes.len() {
        owner.time_left(until, "initial bootstrap memory read")?;
        let cursor = address + observation.copied as u64;
        let aligned = cursor & !7;
        let result = request(libc::PTRACE_PEEKDATA, owner.pid, aligned as usize, 0);
        observation.last_request = Some(result);
        observation.last_word = (result.result as u64).to_ne_bytes();
        if let Some(errno) = result.errno {
            return Err(io_error(
                "PTRACE_PEEKDATA",
                std::io::Error::from_raw_os_error(errno),
            ));
        }
        let offset = (cursor - aligned) as usize;
        let length = ((end - cursor) as usize).min(8 - offset);
        bytes[observation.copied..observation.copied + length]
            .copy_from_slice(&observation.last_word[offset..offset + length]);
        observation.bytes[observation.copied..observation.copied + length]
            .copy_from_slice(&bytes[observation.copied..observation.copied + length]);
        observation.copied += length;
        owner.time_left(until, "initial bootstrap memory read")?;
    }
    observation.complete = true;
    Ok(())
}
pub(in crate::linux::remote::dynamic::owner) fn verify_memory(
    owner: &Owner,
    address: u64,
    expected: &[u8],
    observation: &mut MemoryObservation,
    until: Instant,
) -> Result<(), LaunchError> {
    if expected.len() > 68 {
        return Err(LaunchError::Invalid(
            "initial bootstrap fixed read exceeds bound",
        ));
    }
    let mut actual = [0; 68];
    memory(
        owner,
        address,
        &mut actual[..expected.len()],
        observation,
        until,
    )?;
    if actual[..expected.len()] != *expected {
        return Err(LaunchError::Invalid(
            "initial bootstrap memory readback differs",
        ));
    }
    Ok(())
}
pub(super) fn poke(
    owner: &Owner,
    address: u64,
    bytes: &[u8],
    observation: &mut MemoryObservation,
    until: Instant,
) -> Result<(), LaunchError> {
    let end = address
        .checked_add(bytes.len() as u64)
        .ok_or(LaunchError::Invalid(
            "initial bootstrap write range overflows",
        ))?;
    let mut cursor = address;
    while cursor < end {
        let aligned = cursor & !7;
        let mut word = [0; 8];
        memory(owner, aligned, &mut word, observation, until)?;
        let offset = (cursor - aligned) as usize;
        let length = ((end - cursor) as usize).min(8 - offset);
        let source = (cursor - address) as usize;
        word[offset..offset + length].copy_from_slice(&bytes[source..source + length]);
        owner.time_left(until, "initial bootstrap memory write")?;
        ptrace(
            libc::PTRACE_POKEDATA,
            owner.pid,
            aligned as usize,
            u64::from_ne_bytes(word) as usize,
        )?;
        owner.time_left(until, "initial bootstrap memory write")?;
        cursor += length as u64;
    }
    Ok(())
}

pub(in crate::linux::remote::dynamic::owner) struct MapBuffer {
    storage: Box<[u8; MAP_BYTES]>,
    pub(in crate::linux::remote::dynamic::owner) length: usize,
    pub(in crate::linux::remote::dynamic::owner) request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) filesystem: Option<i64>,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
}
impl MapBuffer {
    pub(in crate::linux::remote::dynamic::owner) fn allocate() -> Result<Self, LaunchError> {
        Ok(Self {
            storage: fixed_buffer()?,
            length: 0,
            request: None,
            filesystem: None,
            complete: false,
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn bytes(&self) -> &[u8] {
        &self.storage[..self.length]
    }
    pub(in crate::linux::remote::dynamic::owner) fn capture(
        &mut self,
        owner: &Owner,
        until: Instant,
    ) -> Result<(), LaunchError> {
        physical(owner, until)?;
        self.storage.fill(0);
        self.length = 0;
        self.request = None;
        self.filesystem = None;
        self.complete = false;
        let mut path = [0_u8; 32];
        path[..6].copy_from_slice(b"/proc/");
        let mut digits = [0_u8; 10];
        let mut value = u32::try_from(owner.pid)
            .ok()
            .filter(|value| *value != 0)
            .ok_or(LaunchError::Invalid("initial bootstrap task id differs"))?;
        let mut start = digits.len();
        while value != 0 {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        let length = digits.len() - start;
        path[6..6 + length].copy_from_slice(&digits[start..]);
        let fd = unsafe {
            libc::open(
                path.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(system("open initial bootstrap proc directory"));
        }
        let directory = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } != 0 {
            return Err(system("stat initial bootstrap proc directory"));
        }
        self.filesystem = Some(stat.f_type);
        if stat.f_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t {
            return Err(LaunchError::Invalid(
                "initial bootstrap maps are not procfs",
            ));
        }
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c"maps".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(system("open initial bootstrap maps"));
        }
        let maps = unsafe { OwnedFd::from_raw_fd(fd) };
        loop {
            owner.time_left(until, "initial bootstrap map capture")?;
            let mut extra = 0_u8;
            let bound = self.length == MAP_BYTES;
            let (address, count) = if bound {
                (&mut extra as *mut u8, 1)
            } else {
                (
                    self.storage[self.length..].as_mut_ptr(),
                    MAP_BYTES - self.length,
                )
            };
            let result = unsafe { libc::read(maps.as_raw_fd(), address.cast(), count) };
            let errno = if result < 0 {
                Some(unsafe { *libc::__errno_location() })
            } else {
                None
            };
            self.request = Some(Request {
                result: result as i64,
                errno,
            });
            if let Some(errno) = errno {
                return Err(io_error(
                    "read initial bootstrap maps",
                    std::io::Error::from_raw_os_error(errno),
                ));
            }
            if result > 0 {
                if bound {
                    return Err(LaunchError::Invalid(
                        "initial bootstrap maps exceed fixed bound",
                    ));
                }
                self.length = self
                    .length
                    .checked_add(result as usize)
                    .filter(|length| *length <= MAP_BYTES)
                    .ok_or(LaunchError::Invalid("initial bootstrap map count differs"))?;
            }
            owner.time_left(until, "initial bootstrap map capture")?;
            if result == 0 {
                break;
            }
        }
        parse(self.bytes())?;
        physical(owner, until)?;
        self.complete = true;
        Ok(())
    }
}

pub(super) fn restore(
    owner: &Owner,
    expected: &StateSlot,
    actual: &mut StateSlot,
    until: Instant,
) -> Result<(), LaunchError> {
    if !expected.complete {
        return Err(LaunchError::Invalid(
            "initial bootstrap restoration state is incomplete",
        ));
    }
    actual.capture(owner, until)?;
    if actual.state.xstate != expected.state.xstate {
        let mut vector = libc::iovec {
            iov_base: expected.state.xstate.as_ptr().cast_mut().cast(),
            iov_len: expected.state.xstate.len(),
        };
        owner.time_left(until, "initial bootstrap restore XSTATE")?;
        ptrace(
            libc::PTRACE_SETREGSET,
            owner.pid,
            NT_X86_XSTATE,
            (&raw mut vector) as usize,
        )?;
    }
    owner.time_left(until, "initial bootstrap restore registers")?;
    set_registers(owner.pid, &expected.state.registers)?;
    actual.capture(owner, until)?;
    if actual.state.registers != expected.state.registers
        || actual.state.xstate != expected.state.xstate
    {
        return Err(LaunchError::Invalid(
            "trusted register/XSTATE restoration differs",
        ));
    }
    if actual.state.mask != expected.state.mask {
        owner.time_left(until, "initial bootstrap restore mask")?;
        ptrace(
            libc::PTRACE_SETSIGMASK,
            owner.pid,
            8,
            (&raw const expected.state.mask) as usize,
        )?;
    }
    actual.capture(owner, until)?;
    if actual.state != expected.state {
        return Err(LaunchError::Invalid("trusted state restoration differs"));
    }
    Ok(())
}
