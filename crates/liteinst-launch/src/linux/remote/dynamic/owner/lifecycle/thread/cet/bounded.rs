//! Fixed-storage adapter to the unchanged CET certificate. Read-only; the
//! caller must authenticate continuously held physical custody before entry.
use super::super::super::super::bootstrap::Request;
use super::*;
use std::mem::size_of;
use std::os::fd::{FromRawFd, OwnedFd};

#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner) struct CetQuery {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Retained CET request evidence is inspected by native controls"
        )
    )]
    pub(in crate::linux::remote::dynamic::owner) request: Request,
    pub(in crate::linux::remote::dynamic::owner) bytes: [u8; REGISTER_BYTES],
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Retained CET request evidence is inspected by native controls"
        )
    )]
    pub(in crate::linux::remote::dynamic::owner) requested_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner) returned_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner) returned_length: usize,
}
pub(in crate::linux::remote::dynamic::owner) struct CetStatus {
    pub(in crate::linux::remote::dynamic::owner) bytes: [u8; MAX_STATUS_BYTES + 1],
    pub(in crate::linux::remote::dynamic::owner) length: usize,
    pub(in crate::linux::remote::dynamic::owner) open: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) filesystem_request: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) last_read: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner) filesystem: Option<i64>,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
}
impl Default for CetStatus {
    fn default() -> Self {
        Self {
            bytes: [0; MAX_STATUS_BYTES + 1],
            length: 0,
            open: None,
            filesystem_request: None,
            last_read: None,
            filesystem: None,
            complete: false,
        }
    }
}
#[derive(Default)]
pub(in crate::linux::remote::dynamic::owner) struct BoundedCet {
    pub(in crate::linux::remote::dynamic::owner) queries: [Option<CetQuery>; 7],
    pub(in crate::linux::remote::dynamic::owner) status: [CetStatus; 2],
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
    proof: Option<DisabledProof>,
}
struct BoundedProbe<'a> {
    tid: i32,
    owner: &'a Owner,
    until: Instant,
    evidence: &'a mut BoundedCet,
    status_index: usize,
    registers_index: usize,
    filter_index: usize,
}
fn checked(request: Request, operation: &'static str) -> Result<(), LaunchError> {
    match request.errno {
        Some(errno) => Err(io_error(operation, io::Error::from_raw_os_error(errno))),
        None if request.result == 0 => Ok(()),
        None => Err(LaunchError::Invalid(
            "unexpected ptrace qualification return value",
        )),
    }
}
impl BoundedProbe<'_> {
    fn query(
        &mut self,
        slot: usize,
        operation: u32,
        address: usize,
        data: usize,
        output: (usize, usize),
    ) -> Result<(), LaunchError> {
        self.owner.time_left(self.until, "bounded CET query")?;
        unsafe {
            *libc::__errno_location() = 0;
        }
        let result = unsafe { libc::ptrace(operation, self.tid, address, data) };
        let errno = if result == -1 {
            Some(unsafe { *libc::__errno_location() })
        } else {
            None
        };
        self.evidence.queries[slot] = Some(CetQuery {
            request: Request { result, errno },
            bytes: [0; REGISTER_BYTES],
            requested_pointer: output.0,
            returned_pointer: output.0,
            returned_length: output.1,
        });
        checked(Request { result, errno }, "bounded CET ptrace")
    }
    fn word(&mut self, slot: usize, option: usize) -> WordRead {
        let mut value = SENTINEL;
        let pointer = (&raw mut value) as usize;
        let result = self.query(
            slot,
            PTRACE_ARCH_PRCTL,
            pointer,
            option,
            (pointer, WORD_BYTES),
        );
        if let Some(record) = &mut self.evidence.queries[slot] {
            record.bytes[..8].copy_from_slice(&value.to_ne_bytes());
        }
        WordRead { result, value }
    }
}
impl Probe for BoundedProbe<'_> {
    fn status(&mut self) -> WordRead {
        let slot = if self.status_index == 0 { 0 } else { 4 };
        self.status_index += 1;
        self.word(slot, ARCH_SHSTK_STATUS)
    }
    fn registers(&mut self) -> Result<RegisterSnapshot, LaunchError> {
        let slot = if self.registers_index == 0 { 1 } else { 6 };
        self.registers_index += 1;
        let mut raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let pointer = (&raw mut raw) as usize;
        let result = self.query(
            slot,
            libc::PTRACE_GETREGS,
            0,
            pointer,
            (pointer, REGISTER_BYTES),
        );
        if let Some(record) = &mut self.evidence.queries[slot] {
            // Exact initialized integer-only native structure, including on error.
            record.bytes.copy_from_slice(unsafe {
                std::slice::from_raw_parts(pointer as *const u8, REGISTER_BYTES)
            });
        }
        result?;
        Ok(raw.into())
    }
    fn prstatus(&mut self) -> RegsetRead<RegisterSnapshot> {
        let mut raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let base = (&raw mut raw).cast::<libc::c_void>();
        let mut vector = libc::iovec {
            iov_base: base,
            iov_len: REGISTER_BYTES,
        };
        let result = self.query(
            2,
            libc::PTRACE_GETREGSET,
            NT_PRSTATUS,
            (&raw mut vector) as usize,
            (base as usize, REGISTER_BYTES),
        );
        if let Some(record) = &mut self.evidence.queries[2] {
            record.returned_pointer = vector.iov_base as usize;
            record.returned_length = vector.iov_len;
            record.bytes.copy_from_slice(unsafe {
                std::slice::from_raw_parts(base.cast::<u8>(), REGISTER_BYTES)
            });
        }
        RegsetRead {
            result,
            value: raw.into(),
            length: vector.iov_len,
            base_unchanged: vector.iov_base == base,
        }
    }
    fn fsbase(&mut self) -> WordRead {
        self.word(3, ARCH_GET_FS)
    }
    fn shadow_stack(&mut self) -> RegsetRead<u64> {
        let mut value = SENTINEL;
        let base = (&raw mut value).cast::<libc::c_void>();
        let mut vector = libc::iovec {
            iov_base: base,
            iov_len: WORD_BYTES,
        };
        let result = self.query(
            5,
            libc::PTRACE_GETREGSET,
            NT_X86_SHSTK,
            (&raw mut vector) as usize,
            (base as usize, WORD_BYTES),
        );
        if let Some(record) = &mut self.evidence.queries[5] {
            record.returned_pointer = vector.iov_base as usize;
            record.returned_length = vector.iov_len;
            record.bytes[..8].copy_from_slice(&value.to_ne_bytes());
        }
        RegsetRead {
            result,
            value,
            length: vector.iov_len,
            base_unchanged: vector.iov_base == base,
        }
    }
    fn tracer_unfiltered(&mut self) -> Result<(), LaunchError> {
        self.owner
            .time_left(self.until, "bounded CET tracer status")?;
        let record = &mut self.evidence.status[self.filter_index];
        self.filter_index += 1;
        let fd = unsafe {
            libc::open(
                c"/proc/thread-self/status".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        let errno = if fd < 0 {
            Some(unsafe { *libc::__errno_location() })
        } else {
            None
        };
        record.open = Some(Request {
            result: i64::from(fd),
            errno,
        });
        if let Some(errno) = errno {
            return Err(io_error(
                "open tracer proc status",
                io::Error::from_raw_os_error(errno),
            ));
        }
        let file = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::fstatfs(file.as_raw_fd(), &raw mut filesystem) };
        let errno = if result != 0 {
            Some(unsafe { *libc::__errno_location() })
        } else {
            None
        };
        record.filesystem_request = Some(Request {
            result: i64::from(result),
            errno,
        });
        if let Some(errno) = errno {
            return Err(io_error(
                "authenticate tracer procfs",
                io::Error::from_raw_os_error(errno),
            ));
        }
        record.filesystem = Some(filesystem.f_type);
        if filesystem.f_type != PROC_SUPER_MAGIC {
            return Err(LaunchError::Invalid("tracer status is not on procfs"));
        }
        loop {
            self.owner
                .time_left(self.until, "bounded CET tracer status")?;
            if record.length == record.bytes.len() {
                return Err(LaunchError::Invalid("invalid tracer proc status"));
            }
            let result = unsafe {
                libc::read(
                    file.as_raw_fd(),
                    record.bytes[record.length..].as_mut_ptr().cast(),
                    record.bytes.len() - record.length,
                )
            };
            let errno = if result < 0 {
                Some(unsafe { *libc::__errno_location() })
            } else {
                None
            };
            record.last_read = Some(Request {
                result: result as i64,
                errno,
            });
            if let Some(errno) = errno {
                return Err(io_error(
                    "read tracer proc status",
                    io::Error::from_raw_os_error(errno),
                ));
            }
            record.length += result as usize;
            if result == 0 {
                break;
            }
        }
        let text = std::str::from_utf8(&record.bytes[..record.length])
            .map_err(|_| LaunchError::Invalid("tracer proc status is not UTF-8"))?;
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        let tid = i32::try_from(tid)
            .map_err(|_| LaunchError::Invalid("invalid tracer thread identifier"))?;
        status_unfiltered(text, tid)?;
        self.owner
            .time_left(self.until, "bounded CET tracer status")?;
        record.complete = true;
        Ok(())
    }
}
pub(in crate::linux::remote::dynamic::owner) fn certify_bounded_cet(
    owner: &Owner,
    evidence: &mut BoundedCet,
    until: Instant,
) -> Result<(), LaunchError> {
    if size_of::<libc::user_regs_struct>() != REGISTER_BYTES
        || evidence.complete
        || evidence.queries.iter().any(Option::is_some)
    {
        return Err(LaunchError::Invalid(
            "bounded CET storage or native ABI differs",
        ));
    }
    let proof = certify(&mut BoundedProbe {
        tid: owner.pid,
        owner,
        until,
        evidence,
        status_index: 0,
        registers_index: 0,
        filter_index: 0,
    })?;
    owner.time_left(until, "bounded CET completed certificate")?;
    evidence.proof = Some(proof);
    evidence.complete = true;
    Ok(())
}
