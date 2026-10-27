//! Bounded independent observations. Every fd is guarded immediately after
//! open; every initialized prefix and raw result remains in its installed owner.
use super::super::OracleError;
use super::super::artifact::{Outcome, exact, outcome};
use crate::linux::remote::dynamic::owner::admission::exact_storage;
use crate::linux::remote::dynamic::owner::{Owner, bootstrap};
use std::ffi::CStr;
use std::time::Instant;

const READS: usize = 64;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in super::super) struct ReadOutcome {
    pub(in super::super) offset: usize,
    pub(in super::super) requested: usize,
    pub(in super::super) result: Outcome,
}
pub(in super::super) struct IoBuffer {
    pub(in super::super) bytes: Vec<u8>,
    pub(in super::super) copied: usize,
    pub(in super::super) opened: Option<Outcome>,
    pub(in super::super) directory_opened: Option<Outcome>,
    pub(in super::super) filesystem: Option<(Outcome, i64)>,
    pub(in super::super) directory_filesystem: Option<(Outcome, i64)>,
    pub(in super::super) closed: Option<Outcome>,
    pub(in super::super) directory_closed: Option<Outcome>,
    pub(in super::super) reads: [Option<ReadOutcome>; READS],
    pub(in super::super) count: usize,
    pub(in super::super) offset: u64,
    pub(in super::super) eof_byte: u8,
    pub(in super::super) eof: Option<Outcome>,
    pub(in super::super) started: bool,
    pub(in super::super) complete: bool,
}
impl IoBuffer {
    pub(in super::super) fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            copied: 0,
            opened: None,
            directory_opened: None,
            filesystem: None,
            directory_filesystem: None,
            closed: None,
            directory_closed: None,
            reads: [None; READS],
            count: 0,
            offset: 0,
            eof_byte: 0,
            eof: None,
            started: false,
            complete: false,
        }
    }
    pub(in super::super) fn allocate_payload(
        &mut self,
        capacity: usize,
    ) -> Result<(), OracleError> {
        if self.started || self.bytes.capacity() != 0 || capacity == 0 || capacity > 1024 * 1024 {
            return Err(OracleError::Invalid("oracle I/O allocation shape differs"));
        }
        self.bytes = exact_storage::empty_bytes(capacity)
            .map_err(|_| OracleError::Invalid("oracle I/O allocation failed"))?;
        self.bytes.resize(capacity, 0);
        Ok(())
    }
    pub(in super::super) fn prefix(&self) -> &[u8] {
        &self.bytes[..self.copied]
    }
    pub(in super::super) fn read_proc(
        &mut self,
        owner: &Owner,
        name: &CStr,
        until: Instant,
    ) -> Result<(), OracleError> {
        self.capture(owner, name, None, until)
    }
    pub(in super::super) fn read_memory(
        &mut self,
        owner: &Owner,
        address: u64,
        until: Instant,
    ) -> Result<(), OracleError> {
        self.capture(owner, c"mem", Some(address), until)
    }
    pub(in super::super) fn read_pagemap(
        &mut self,
        owner: &Owner,
        offset: u64,
        until: Instant,
    ) -> Result<(), OracleError> {
        self.capture(owner, c"pagemap", Some(offset), until)
    }
    fn capture(
        &mut self,
        owner: &Owner,
        name: &CStr,
        offset: Option<u64>,
        until: Instant,
    ) -> Result<(), OracleError> {
        if self.started || self.bytes.is_empty() || self.bytes.len() != self.bytes.capacity() {
            return Err(OracleError::Invalid("oracle I/O unallocated or reused"));
        }
        self.started = true;
        self.offset = offset.unwrap_or(0);
        bootstrap::physical(owner, until)?;
        let mut path = [0_u8; 48];
        let path = proc_name(owner.pid, b"", &mut path)?;
        let opened = outcome(|| {
            i64::from(unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            })
        });
        self.directory_opened = Some(opened);
        let fd = opened_fd(opened)?;
        let directory = CloseGuard::new(fd, &mut self.directory_closed);
        if opened.errno != 0 {
            return Err(OracleError::Invalid("oracle proc directory errno differs"));
        }
        bootstrap::physical(owner, until)?;
        let fs = statfs(fd);
        self.directory_filesystem = Some(fs);
        exact(fs.0, 0, "oracle proc directory filesystem")?;
        if fs.1 != libc::PROC_SUPER_MAGIC {
            return Err(OracleError::Invalid("oracle directory is not procfs"));
        }
        bootstrap::physical(owner, until)?;
        let opened = outcome(|| {
            i64::from(unsafe {
                libc::openat(
                    directory.fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            })
        });
        self.opened = Some(opened);
        let fd = opened_fd(opened)?;
        let file = CloseGuard::new(fd, &mut self.closed);
        if opened.errno != 0 {
            return Err(OracleError::Invalid("oracle proc file errno differs"));
        }
        bootstrap::physical(owner, until)?;
        let fs = statfs(fd);
        self.filesystem = Some(fs);
        exact(fs.0, 0, "oracle proc file filesystem")?;
        if fs.1 != libc::PROC_SUPER_MAGIC {
            return Err(OracleError::Invalid("oracle file is not procfs"));
        }
        if let Some(offset) = offset {
            let offset = i64::try_from(offset)
                .map_err(|_| OracleError::Invalid("oracle pread offset overflows"))?;
            bootstrap::physical(owner, until)?;
            let result = outcome(|| unsafe {
                libc::pread(
                    file.fd(),
                    self.bytes.as_mut_ptr().cast(),
                    self.bytes.len(),
                    offset,
                ) as i64
            });
            self.reads[0] = Some(ReadOutcome {
                offset: 0,
                requested: self.bytes.len(),
                result,
            });
            self.count = 1;
            self.copied = usize::try_from(result.result)
                .unwrap_or(0)
                .min(self.bytes.len());
            exact(result, self.bytes.len() as i64, "oracle exact pread")?;
        } else {
            loop {
                if self.count == READS {
                    return Err(OracleError::Invalid("oracle proc read count exceeds bound"));
                }
                bootstrap::physical(owner, until)?;
                if self.copied == self.bytes.len() {
                    let result = outcome(|| unsafe {
                        libc::read(file.fd(), (&raw mut self.eof_byte).cast(), 1) as i64
                    });
                    self.eof = Some(result);
                    exact(result, 0, "oracle bounded proc EOF")?;
                    break;
                }
                let requested = self.bytes.len() - self.copied;
                let at = self.copied;
                let result = outcome(|| unsafe {
                    libc::read(file.fd(), self.bytes[at..].as_mut_ptr().cast(), requested) as i64
                });
                self.reads[self.count] = Some(ReadOutcome {
                    offset: at,
                    requested,
                    result,
                });
                self.count += 1;
                if result.result >= 0 && result.result <= requested as i64 {
                    self.copied += result.result as usize;
                }
                if result.result < 0 || result.result > requested as i64 || result.errno != 0 {
                    return Err(OracleError::Io {
                        operation: "oracle proc read",
                        errno: (result.errno != 0).then_some(result.errno),
                    });
                }
                if result.result == 0 {
                    self.eof = Some(result);
                    break;
                }
            }
        }
        exact(file.close(), 0, "oracle proc file close")?;
        exact(directory.close(), 0, "oracle proc directory close")?;
        bootstrap::physical(owner, until)?;
        self.complete = true;
        Ok(())
    }
}
fn opened_fd(result: Outcome) -> Result<i32, OracleError> {
    if !(0..=i64::from(i32::MAX)).contains(&result.result) {
        return Err(OracleError::Io {
            operation: "oracle proc open",
            errno: (result.errno != 0).then_some(result.errno),
        });
    }
    Ok(result.result as i32)
}
fn statfs(fd: i32) -> (Outcome, i64) {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let result = outcome(|| i64::from(unsafe { libc::fstatfs(fd, &raw mut stat) }));
    (result, stat.f_type)
}
pub(in super::super) struct CloseGuard<'a> {
    fd: Option<i32>,
    record: &'a mut Option<Outcome>,
}
impl<'a> CloseGuard<'a> {
    pub(in super::super) fn new(fd: i32, record: &'a mut Option<Outcome>) -> Self {
        Self {
            fd: Some(fd),
            record,
        }
    }
    pub(in super::super) fn fd(&self) -> i32 {
        self.fd.expect("actual open fd")
    }
    fn release(&mut self) -> Outcome {
        let fd = self.fd.take().expect("one close only");
        let value = outcome(|| i64::from(unsafe { libc::close(fd) }));
        *self.record = Some(value);
        value
    }
    pub(in super::super) fn close(mut self) -> Outcome {
        self.release()
    }
}
impl Drop for CloseGuard<'_> {
    fn drop(&mut self) {
        if self.fd.is_some() {
            let value = self.release();
            if value.result != 0 || value.errno != 0 {
                std::process::abort()
            }
        }
    }
}
pub(in super::super) fn proc_name<'a>(
    pid: i32,
    suffix: &[u8],
    storage: &'a mut [u8; 48],
) -> Result<&'a CStr, OracleError> {
    if pid <= 0 || suffix.contains(&0) {
        return Err(OracleError::Invalid("oracle proc identity differs"));
    }
    storage.fill(0);
    storage[..6].copy_from_slice(b"/proc/");
    let mut digits = [0_u8; 10];
    let mut at = 10;
    let mut n = pid as u32;
    while n != 0 {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let length = 10 - at;
    let end = 6 + length + suffix.len();
    if end >= storage.len() {
        return Err(OracleError::Invalid("oracle proc path overflows"));
    }
    storage[6..6 + length].copy_from_slice(&digits[at..]);
    storage[6 + length..end].copy_from_slice(suffix);
    CStr::from_bytes_with_nul(&storage[..end + 1])
        .map_err(|_| OracleError::Invalid("oracle proc path invalid"))
}
