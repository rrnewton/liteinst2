//! Bounded actual I/O only. These records do not grant execution authority.
use super::super::super::Owner;
use super::super::super::bootstrap::{self, Request};
use super::super::runtime_stack::access::{
    CPUID_INPUTS, CpuidRecord, PagemapObservation, PkuLayoutEvidence,
};
use super::super::runtime_stack::operand::{OperandGeometry, PeekRecord, WordObservation};
use super::super::runtime_stack::storage::{FileCapture, ReadRecord};
use super::super::runtime_stack::{BYTES, PAGE, StackError};
use crate::LaunchError;
use std::ffi::CStr;
use std::io;
use std::mem::size_of;
use std::time::Instant;

#[cfg(test)]
mod raw_fixture;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission) use raw_fixture::{
    RawIoFault, RawIoRecord, RawStoppedIo,
};

/// The production implementation is exactly the existing singleton physical
/// gate. The test-only raw fixture implementation checks every actual pin and
/// consumed stop, but supplies no registry/current/source/operand authority.
trait IoContext {
    fn tid(&self) -> i32;
    fn require(&self, until: Instant) -> Result<(), LaunchError>;
    #[cfg(test)]
    fn basename<'a>(&self, name: &'a CStr) -> &'a CStr {
        name
    }
    #[cfg(test)]
    fn statfs_fd(&self, fd: i32) -> i32 {
        fd
    }
    #[cfg(test)]
    fn observed_statfs(&self, _fd: i32, _request: Request) {}
    #[cfg(test)]
    fn output(&self, _pread: bool, pointer: *mut u8, _count: usize) -> *mut u8 {
        pointer
    }
    #[cfg(test)]
    fn observed_read(&self, _pread: bool, _record: ReadRecord) {}
    #[cfg(test)]
    fn close_probe(&self) -> Result<(), LaunchError> {
        Ok(())
    }
}
impl IoContext for Owner {
    fn tid(&self) -> i32 {
        self.pid
    }
    fn require(&self, until: Instant) -> Result<(), LaunchError> {
        bootstrap::physical(self, until)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct PagemapAccess {
    pub(in crate::linux::remote::dynamic::owner::admission) started: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) complete: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) directory_open: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) directory_statfs: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) directory_filesystem: Option<i64>,
    pub(in crate::linux::remote::dynamic::owner::admission) file_open: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) file_statfs: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) file_filesystem: Option<i64>,
    pub(in crate::linux::remote::dynamic::owner::admission) file_close: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) directory_close: Option<Request>,
    pub(in crate::linux::remote::dynamic::owner::admission) first_failure: Option<StackError>,
}

impl PagemapAccess {
    /// Descriptive consistency only. The caller also checks the real pread.
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate(
        &self,
    ) -> Result<(), StackError> {
        let directory = self.directory_open.ok_or(StackError::Incomplete)?;
        let file = self.file_open.ok_or(StackError::Incomplete)?;
        if !self.started
            || !self.complete
            || self.first_failure.is_some()
            || !opened(directory)
            || !opened(file)
            || directory.result == file.result
            || self.directory_statfs != Some(success())
            || self.file_statfs != Some(success())
            || self.directory_filesystem != Some(libc::PROC_SUPER_MAGIC)
            || self.file_filesystem != Some(libc::PROC_SUPER_MAGIC)
            || self.file_close != Some(success())
            || self.directory_close != Some(success())
        {
            return Err(StackError::Request);
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate_for(
        &self,
        pagemap: &PagemapObservation,
    ) -> Result<(), StackError> {
        self.validate()?;
        if self.file_open.map(|request| request.result) != Some(i64::from(pagemap.fd)) {
            return Err(StackError::Request);
        }
        Ok(())
    }
}

fn success() -> Request {
    Request {
        result: 0,
        errno: None,
    }
}
fn opened(request: Request) -> bool {
    request.errno.is_none() && (0..=i64::from(i32::MAX)).contains(&request.result)
}
fn outcome(result: i64) -> Request {
    Request {
        result,
        errno: (result < 0)
            .then(|| io::Error::last_os_error().raw_os_error())
            .flatten(),
    }
}
fn checked(request: Request, operation: &'static str) -> Result<i64, LaunchError> {
    if request.result < 0 || request.errno.is_some() {
        Err(LaunchError::System {
            operation,
            source: io::Error::from_raw_os_error(request.errno.unwrap_or(libc::EIO)),
        })
    } else {
        Ok(request.result)
    }
}
fn invalid(reason: &'static str) -> LaunchError {
    LaunchError::Invalid(reason)
}
fn validate_error(error: StackError) -> LaunchError {
    match error {
        StackError::Pagemap => invalid("owned stack actual page is not resident and exclusive"),
        _ => invalid("owned stack native I/O record differs"),
    }
}

/// A descriptor is removed from this guard before close. Never retry a numeric
/// fd after an ambiguous close outcome. On unwind, retain rc/errno and abort
/// if cleanup cannot be established; do not replace a panic with another panic.
struct Descriptor<'a> {
    fd: Option<i32>,
    close: &'a mut Option<Request>,
}
impl<'a> Descriptor<'a> {
    fn new(fd: i32, close: &'a mut Option<Request>) -> Self {
        Self {
            fd: Some(fd),
            close,
        }
    }
    fn raw(&self) -> i32 {
        self.fd.expect("owned stack live descriptor")
    }
    fn close(mut self) -> Request {
        self.release()
    }
    fn release(&mut self) -> Request {
        let Some(fd) = self.fd.take() else {
            return self.close.expect("owned stack recorded close");
        };
        // SAFETY: this guard owns exactly the successful open's descriptor.
        let request = outcome(i64::from(unsafe { libc::close(fd) }));
        *self.close = Some(request);
        request
    }
}
impl Drop for Descriptor<'_> {
    fn drop(&mut self) {
        if self.fd.is_some() && self.release() != success() {
            std::process::abort();
        }
    }
}

fn proc_path(pid: i32, bytes: &mut [u8; 32]) -> Result<&CStr, LaunchError> {
    if pid <= 0 {
        return Err(invalid("owned stack proc TID differs"));
    }
    bytes.fill(0);
    bytes[..6].copy_from_slice(b"/proc/");
    let mut digits = [0_u8; 11];
    let mut cursor = digits.len();
    let mut value = pid as u32;
    while value != 0 {
        cursor -= 1;
        digits[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let length = digits.len() - cursor;
    bytes[6..6 + length].copy_from_slice(&digits[cursor..]);
    CStr::from_bytes_with_nul(&bytes[..7 + length])
        .map_err(|_| invalid("owned stack proc path differs"))
}
fn directory_open(owner: &impl IoContext, until: Instant) -> Result<Request, LaunchError> {
    owner.require(until)?;
    let mut path = [0_u8; 32];
    let path = proc_path(owner.tid(), &mut path)?;
    // SAFETY: initialized NUL-terminated bounded path, no output pointer.
    Ok(outcome(i64::from(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })))
}
fn file_open(
    owner: &impl IoContext,
    until: Instant,
    directory: i32,
    name: &CStr,
) -> Result<Request, LaunchError> {
    owner.require(until)?;
    #[cfg(test)]
    let name = owner.basename(name);
    // SAFETY: retained directory descriptor and fixed NUL-terminated basename.
    Ok(outcome(i64::from(unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })))
}
fn filesystem(
    owner: &impl IoContext,
    until: Instant,
    fd: i32,
) -> Result<(Request, i64), LaunchError> {
    owner.require(until)?;
    #[cfg(test)]
    let fd = owner.statfs_fd(fd);
    // SAFETY: fully initialized syscall output storage.
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    let request = outcome(i64::from(unsafe { libc::fstatfs(fd, &raw mut value) }));
    #[cfg(test)]
    owner.observed_statfs(fd, request);
    Ok((request, value.f_type))
}
fn require_filesystem(request: Request, kind: i64) -> Result<(), LaunchError> {
    checked(request, "owned stack procfs fstatfs")?;
    if kind != libc::PROC_SUPER_MAGIC {
        return Err(invalid("owned stack metadata is not procfs"));
    }
    Ok(())
}

pub(super) fn capture_file(
    owner: &Owner,
    until: Instant,
    name: &CStr,
    bytes: &mut [u8],
    capture: &mut FileCapture,
    eof: &mut u8,
) -> Result<(), LaunchError> {
    capture_file_with(owner, until, name, bytes, capture, eof)
}
pub(super) fn capture_pagemap(
    owner: &Owner,
    until: Instant,
    geometry: &OperandGeometry,
    word: &mut WordObservation,
    access: &mut PagemapAccess,
) -> Result<(), LaunchError> {
    capture_pagemap_with(owner, until, geometry, word, access)
}
pub(super) fn capture_word(
    owner: &Owner,
    until: Instant,
    geometry: &OperandGeometry,
    word: &mut WordObservation,
    access: &PagemapAccess,
) -> Result<(), LaunchError> {
    capture_word_with(owner, until, geometry, word, access)
}

fn capture_file_with(
    owner: &impl IoContext,
    until: Instant,
    name: &CStr,
    bytes: &mut [u8],
    capture: &mut FileCapture,
    eof: &mut u8,
) -> Result<(), LaunchError> {
    if bytes.len() != BYTES
        || *capture != FileCapture::default()
        || !matches!(name.to_bytes(), b"maps" | b"smaps")
    {
        return Err(invalid(
            "owned stack metadata capture is reused or unallocated",
        ));
    }
    capture.started = true;
    bytes.fill(0);
    *eof = 0;
    let result = (|| {
        let request = directory_open(owner, until)?;
        capture.directory_open = Some(request);
        let fd = checked(request, "open owned stack proc directory")? as i32;
        let directory = Descriptor::new(fd, &mut capture.directory_close);
        let (request, kind) = filesystem(owner, until, directory.raw())?;
        capture.directory_statfs = Some(request);
        capture.directory_filesystem = Some(kind);
        require_filesystem(request, kind)?;
        let request = file_open(owner, until, directory.raw(), name)?;
        capture.file_open = Some(request);
        let fd = checked(request, "open owned stack metadata")? as i32;
        let file = Descriptor::new(fd, &mut capture.file_close);
        let (request, kind) = filesystem(owner, until, file.raw())?;
        capture.file_statfs = Some(request);
        capture.file_filesystem = Some(kind);
        require_filesystem(request, kind)?;
        let read = (|| {
            loop {
                owner.require(until)?;
                if capture.read_calls == BYTES + 1 {
                    return Err(invalid("owned stack metadata request count exceeds bound"));
                }
                let (pointer, count) = if capture.copied == BYTES {
                    (eof as *mut u8, 1)
                } else {
                    (bytes[capture.copied..].as_mut_ptr(), BYTES - capture.copied)
                };
                #[cfg(test)]
                let pointer = owner.output(false, pointer, count);
                // SAFETY: exact initialized remaining slice or retained EOF byte.
                // Test-only null substitution requests a real EFAULT; it is never dereferenced here.
                let request =
                    outcome(unsafe { libc::read(file.raw(), pointer.cast(), count) } as i64);
                let record = ReadRecord {
                    fd: file.raw(),
                    destination: pointer as usize,
                    count,
                    request,
                };
                #[cfg(test)]
                owner.observed_read(false, record);
                capture.first_read.get_or_insert(record);
                capture.last_read = Some(record);
                capture.read_calls += 1;
                let copied = checked(request, "read owned stack metadata")? as usize;
                if copied > count {
                    return Err(invalid("owned stack metadata read exceeds request"));
                }
                if copied == 0 {
                    return Ok(());
                }
                if capture.copied == BYTES {
                    capture.overflow = true;
                    return Err(invalid("owned stack metadata exceeds complete bound"));
                }
                capture.copied += copied;
            }
        })();
        if read.is_err() {
            capture.first_failure.get_or_insert(StackError::Request);
        }
        #[cfg(test)]
        let injected_close = owner.close_probe();
        let file_close = file.close();
        let directory_close = directory.close();
        read?;
        #[cfg(test)]
        injected_close?;
        checked(file_close, "close owned stack metadata")?;
        checked(directory_close, "close owned stack proc directory")?;
        owner.require(until)?;
        capture.complete = true;
        capture.bytes(bytes).map_err(validate_error)?;
        Ok(())
    })();
    if result.is_err() {
        capture.first_failure.get_or_insert(StackError::Request);
    }
    result
}

fn pagemap_extent(geometry: &OperandGeometry) -> Result<(u64, usize), LaunchError> {
    let rebuilt = OperandGeometry::derive(
        geometry.pc,
        geometry
            .encoding
            .get(..geometry.length)
            .ok_or_else(|| invalid("owned stack encoding extent differs"))?,
        geometry.original_rsp,
        &geometry.stack,
        &geometry.island,
    )
    .map_err(validate_error)?;
    if rebuilt != *geometry {
        return Err(invalid("owned stack frozen geometry differs"));
    }
    let first = geometry.envelope.start / PAGE;
    let last = (geometry.envelope.end - 1) / PAGE;
    let offset = first
        .checked_mul(8)
        .filter(|offset| *offset <= i64::MAX as u64)
        .ok_or_else(|| invalid("owned stack pagemap offset overflows"))?;
    let count = usize::try_from(last - first + 1)
        .ok()
        .and_then(|pages| pages.checked_mul(8))
        .filter(|count| matches!(*count, 8 | 16))
        .ok_or_else(|| invalid("owned stack pagemap extent differs"))?;
    Ok((offset, count))
}

fn require_pagemap_read(request: Request, count: usize) -> Result<(), LaunchError> {
    let returned = checked(request, "read owned stack pagemap")?;
    if !matches!(count, 8 | 16) || returned != count as i64 {
        return Err(invalid("owned stack pagemap read is incomplete"));
    }
    Ok(())
}

fn capture_pagemap_with(
    owner: &impl IoContext,
    until: Instant,
    geometry: &OperandGeometry,
    word: &mut WordObservation,
    access: &mut PagemapAccess,
) -> Result<(), LaunchError> {
    if *access != PagemapAccess::default() || word.pagemap != Default::default() {
        return Err(invalid("owned stack pagemap capture is reused"));
    }
    let (offset, count) = pagemap_extent(geometry)?;
    access.started = true;
    let result =
        (|| {
            let request = directory_open(owner, until)?;
            access.directory_open = Some(request);
            let directory = Descriptor::new(
                checked(request, "open owned stack pagemap directory")? as i32,
                &mut access.directory_close,
            );
            let (request, kind) = filesystem(owner, until, directory.raw())?;
            access.directory_statfs = Some(request);
            access.directory_filesystem = Some(kind);
            require_filesystem(request, kind)?;
            let request = file_open(owner, until, directory.raw(), c"pagemap")?;
            access.file_open = Some(request);
            let file = Descriptor::new(
                checked(request, "open owned stack pagemap")? as i32,
                &mut access.file_close,
            );
            let (request, kind) = filesystem(owner, until, file.raw())?;
            access.file_statfs = Some(request);
            access.file_filesystem = Some(kind);
            require_filesystem(request, kind)?;
            owner.require(until)?;
            word.pagemap.fd = file.raw();
            word.pagemap.offset = offset;
            word.pagemap.requested = count;
            let pointer = word.pagemap.bytes.as_mut_ptr();
            #[cfg(test)]
            let pointer = owner.output(true, pointer, count);
            // SAFETY: initialized fixed 16-byte output, checked count and off_t.
            // A test-only null substitution requests an actual EFAULT.
            let request = outcome(unsafe {
                libc::pread(file.raw(), pointer.cast(), count, offset as libc::off_t)
            } as i64);
            #[cfg(test)]
            owner.observed_read(
                true,
                ReadRecord {
                    fd: file.raw(),
                    destination: pointer as usize,
                    count,
                    request,
                },
            );
            word.pagemap.request = Some(request);
            if (0..=count as i64).contains(&request.result) {
                word.pagemap.copied = request.result as usize;
            }
            let read = require_pagemap_read(request, count);
            if read.is_err() {
                access.first_failure.get_or_insert(StackError::Request);
            }
            #[cfg(test)]
            let injected_close = owner.close_probe();
            let file_close = file.close();
            let directory_close = directory.close();
            read?;
            #[cfg(test)]
            injected_close?;
            checked(file_close, "close owned stack pagemap")?;
            checked(directory_close, "close owned stack pagemap directory")?;
            owner.require(until)?;
            access.complete = true;
            access.validate_for(&word.pagemap).map_err(validate_error)?;
            // This eligibility check occurs before even one PEEK, avoiding a read
            // that could turn a nonresident/COW page into a passing observation.
            word.pagemap.validate(&geometry.envelope).map_err(|error| {
                access.first_failure.get_or_insert(error);
                validate_error(error)
            })
        })();
    if result.is_err() {
        access.first_failure.get_or_insert(StackError::Request);
    }
    result
}

fn capture_word_with(
    owner: &impl IoContext,
    until: Instant,
    geometry: &OperandGeometry,
    word: &mut WordObservation,
    access: &PagemapAccess,
) -> Result<(), LaunchError> {
    access.validate_for(&word.pagemap).map_err(validate_error)?;
    word.pagemap
        .validate(&geometry.envelope)
        .map_err(validate_error)?;
    if word.copied != 0
        || word.complete
        || word.peek.iter().any(Option::is_some)
        || word.bytes != [0; 16]
    {
        return Err(invalid("owned stack word capture is reused"));
    }
    pagemap_extent(geometry)?;
    for index in 0..geometry.envelope_length() / 8 {
        owner.require(until)?;
        let address = geometry.envelope.start + (index * 8) as u64;
        // SAFETY: a genuinely held owned task; PEEK returns a word, with errno
        // cleared so all-ones data is distinguished from an actual failure.
        unsafe { *libc::__errno_location() = 0 };
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKDATA,
                owner.tid(),
                address as usize,
                0_usize,
            )
        };
        let errno = io::Error::last_os_error()
            .raw_os_error()
            .filter(|value| *value != 0);
        let request = Request {
            result: result as i64,
            errno,
        };
        retain_peek(word, index, address, request)?;
    }
    owner.require(until)?;
    word.complete = true;
    word.validate(geometry).map_err(validate_error)?;
    Ok(())
}

/// Retain the immediate actual request before interpreting it. A failed second
/// request does not erase the initialized first word or advance its prefix.
fn retain_peek(
    word: &mut WordObservation,
    index: usize,
    address: u64,
    request: Request,
) -> Result<(), LaunchError> {
    if index >= 2 || word.copied != index * 8 || word.peek[index].is_some() || word.complete {
        return Err(invalid("owned stack PEEK prefix differs"));
    }
    word.peek[index] = Some(PeekRecord { address, request });
    if let Some(errno) = request.errno {
        return Err(LaunchError::System {
            operation: "read owned stack word",
            source: io::Error::from_raw_os_error(errno),
        });
    }
    word.bytes[index * 8..index * 8 + 8].copy_from_slice(&(request.result as u64).to_le_bytes());
    word.copied += 8;
    Ok(())
}

pub(super) fn capture_layout(
    owner: &Owner,
    until: Instant,
    layout: &mut PkuLayoutEvidence,
) -> Result<(), LaunchError> {
    if layout.records.iter().any(Option::is_some) {
        return Err(invalid("owned stack layout capture is reused"));
    }
    for (index, (leaf, subleaf)) in CPUID_INPUTS.into_iter().enumerate() {
        bootstrap::physical(owner, until)?;
        // SAFETY: native x86-64 provides CPUID. Unsupported leaves are retained
        // and rejected by the closed validator; no XGETBV/inactive synthesis.
        let value = unsafe { std::arch::x86_64::__cpuid_count(leaf, subleaf) };
        layout.records[index] = Some(CpuidRecord {
            leaf,
            subleaf,
            registers: [value.eax, value.ebx, value.ecx, value.edx],
        });
    }
    layout.validate().map_err(validate_error)?;
    bootstrap::physical(owner, until)
}

pub(super) fn temporary_bytes() -> Result<usize, LaunchError> {
    // Conservative sum, not a concurrency-sensitive subtraction. Includes
    // descriptor close result storage and every fixed local request/output.
    [
        3 * size_of::<Descriptor<'_>>(),
        2 * size_of::<libc::statfs>(),
        12 * size_of::<Request>(),
        3 * size_of::<ReadRecord>(),
        8 * size_of::<Result<(), LaunchError>>(),
        2 * size_of::<OperandGeometry>(),
        size_of::<std::arch::x86_64::CpuidResult>(),
        size_of::<CpuidRecord>(),
        32 + 11 + 16 + 1,
        16 * size_of::<usize>(),
        // Sum all three added wrapper argument bundles rather than assuming
        // inlining or subtracting mutually exclusive native call stacks.
        size_of::<(&Owner, Instant, &CStr, &mut [u8], &mut FileCapture, &mut u8)>(),
        size_of::<(
            &Owner,
            Instant,
            &OperandGeometry,
            &mut WordObservation,
            &mut PagemapAccess,
        )>(),
        size_of::<(
            &Owner,
            Instant,
            &OperandGeometry,
            &mut WordObservation,
            &PagemapAccess,
        )>(),
        // Explicit pread destination plus the context/require forwarding views.
        5 * size_of::<usize>(),
    ]
    .into_iter()
    .try_fold(0_usize, |total, bytes| {
        total
            .checked_add(bytes)
            .ok_or_else(|| invalid("owned stack I/O temporary bound overflows"))
    })
}
