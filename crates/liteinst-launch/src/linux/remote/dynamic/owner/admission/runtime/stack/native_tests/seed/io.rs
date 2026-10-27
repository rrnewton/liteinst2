//! Fixture-owned raw prefixes. No read here certifies an admitted operand.
use super::*;
use std::ffi::{CStr, CString};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Outcome {
    pub(super) result: i64,
    pub(super) errno: i32,
}
pub(super) fn observe(call: impl FnOnce() -> i64) -> Outcome {
    // SAFETY: this is the calling thread's libc errno cell.
    unsafe { *libc::__errno_location() = 0 };
    let result = call();
    let errno = unsafe { *libc::__errno_location() };
    Outcome { result, errno }
}
pub(super) fn zero(value: Outcome) {
    assert_eq!(
        value,
        Outcome {
            result: 0,
            errno: 0
        }
    );
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Filesystem {
    outcome: Outcome,
    kind: i64,
}
fn filesystem(fd: i32) -> Filesystem {
    // SAFETY: statfs is an initialized native output, valid for the full call.
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    let outcome = observe(|| unsafe { libc::fstatfs(fd, &raw mut value) } as i64);
    Filesystem {
        outcome,
        kind: value.f_type,
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Descriptor {
    open: Option<Outcome>,
    filesystem: Option<Filesystem>,
    close: Option<Outcome>,
}
struct Guard<'a> {
    fd: i32,
    receipt: &'a mut Option<Outcome>,
}
impl Guard<'_> {
    fn close(mut self) -> Outcome {
        let result = observe(|| unsafe { libc::close(self.fd) } as i64);
        *self.receipt = Some(result);
        self.fd = -1;
        result
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // Close also during unwind; retain its result without a second panic.
            *self.receipt = Some(observe(|| unsafe { libc::close(self.fd) } as i64));
            self.fd = -1;
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Read {
    fd: i32,
    offset: Option<u64>,
    pointer: usize,
    requested: usize,
    result: Option<Outcome>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct FileCapture {
    started: bool,
    complete: bool,
    directory_path: Option<CString>,
    file_name: Option<&'static CStr>,
    offset: Option<u64>,
    directory: Descriptor,
    file: Descriptor,
    bytes: Vec<u8>,
    pointer: usize,
    copied: usize,
    overflow: [u8; 1],
    overflow_pointer: usize,
    reads: Vec<Read>,
}
impl FileCapture {
    pub(super) fn capture(
        &mut self,
        owner: &Owner,
        context: &Context,
        name: &'static CStr,
        offset: Option<u64>,
        limit: usize,
    ) {
        assert!(!self.started && !self.complete);
        assert!((1..=1024 * 1024).contains(&limit));
        if name == c"pagemap" {
            assert_eq!(limit, 8);
            assert!(offset.is_some());
        }
        self.started = true;
        self.file_name = Some(name);
        self.offset = offset;
        self.directory_path = Some(CString::new(format!("/proc/{}", owner.pid)).unwrap());
        // Install each allocation before the next request or fallible operation.
        self.bytes.try_reserve_exact(limit).unwrap();
        self.bytes.resize(limit, 0);
        self.pointer = self.bytes.as_ptr() as usize;
        self.overflow_pointer = self.overflow.as_ptr() as usize;
        context.require(owner);
        let opened = observe(|| unsafe {
            libc::open(
                self.directory_path.as_ref().unwrap().as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        } as i64);
        self.directory.open = Some(opened);
        assert!(opened.result >= 0);
        let directory = Guard {
            fd: opened.result as i32,
            receipt: &mut self.directory.close,
        };
        assert_eq!(opened.errno, 0);
        context.require(owner);
        self.directory.filesystem = Some(filesystem(directory.fd));
        let observed = self.directory.filesystem.as_ref().unwrap();
        zero(observed.outcome);
        assert_eq!(observed.kind, libc::PROC_SUPER_MAGIC);
        context.require(owner);
        let opened = observe(|| unsafe {
            libc::openat(
                directory.fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        } as i64);
        self.file.open = Some(opened);
        assert!(opened.result >= 0);
        let file = Guard {
            fd: opened.result as i32,
            receipt: &mut self.file.close,
        };
        assert_eq!(opened.errno, 0);
        context.require(owner);
        self.file.filesystem = Some(filesystem(file.fd));
        let observed = self.file.filesystem.as_ref().unwrap();
        zero(observed.outcome);
        assert_eq!(observed.kind, libc::PROC_SUPER_MAGIC);
        context.require(owner);
        loop {
            if offset.is_some() && self.copied == limit {
                break;
            }
            let overflow = self.copied == limit;
            let requested = if overflow { 1 } else { limit - self.copied };
            let pointer = if overflow {
                self.overflow.as_mut_ptr()
            } else {
                // SAFETY: copied is checked against the initialized fixed extent.
                unsafe { self.bytes.as_mut_ptr().add(self.copied) }
            };
            let cursor = offset.map(|start| start.checked_add(self.copied as u64).unwrap());
            let native_offset = cursor.map(|n| libc::off_t::try_from(n).unwrap());
            // The header is retained before issuing its request; allocation
            // failure cannot erase any earlier raw read or initialized prefix.
            self.reads.try_reserve(1).unwrap();
            self.reads.push(Read {
                fd: file.fd,
                offset: cursor,
                pointer: pointer as usize,
                requested,
                result: None,
            });
            context.require(owner);
            let result = observe(|| unsafe {
                match native_offset {
                    Some(cursor) => libc::pread(file.fd, pointer.cast(), requested, cursor),
                    None => libc::read(file.fd, pointer.cast(), requested),
                }
            } as i64);
            self.reads.last_mut().unwrap().result = Some(result);
            if (0..=requested as i64).contains(&result.result) && !overflow {
                self.copied += result.result as usize;
            }
            context.require(owner);
            assert_eq!(result.errno, 0);
            if name == c"pagemap" {
                assert_eq!(result.result, 8);
            }
            assert!((0..=requested as i64).contains(&result.result));
            if overflow {
                assert_eq!(
                    result.result, 0,
                    "fixture proc file exceeds fixed capture bound"
                );
                break;
            }
            if result.result == 0 {
                assert!(offset.is_none(), "fixture positional read ended early");
                break;
            }
        }
        let file_close = file.close();
        let directory_close = directory.close();
        zero(file_close);
        zero(directory_close);
        context.require(owner);
        self.complete = true;
        self.require_prefix();
    }
    pub(super) fn bytes(&self) -> &[u8] {
        assert!(self.complete);
        &self.bytes[..self.copied]
    }
    pub(super) fn retained(&self) -> impl Fn(&Self) + use<> {
        let snapshot = self.clone();
        let allocations = (
            self.bytes.as_ptr() as usize,
            self.bytes.capacity(),
            self.reads.as_ptr() as usize,
            self.reads.capacity(),
        );
        move |actual| {
            assert_eq!(*actual, snapshot);
            assert_eq!(
                (
                    actual.bytes.as_ptr() as usize,
                    actual.bytes.capacity(),
                    actual.reads.as_ptr() as usize,
                    actual.reads.capacity()
                ),
                allocations
            );
            actual.require_prefix();
        }
    }
    fn require_prefix(&self) {
        if !self.started {
            assert_eq!(*self, Self::default());
            return;
        }
        assert!(self.file_name.is_some() && self.directory_path.is_some());
        assert!(self.copied <= self.bytes.len());
        if self.pointer != 0 {
            assert_eq!(self.pointer, self.bytes.as_ptr() as usize);
        }
        if self.overflow_pointer != 0 {
            assert_eq!(self.overflow_pointer, self.overflow.as_ptr() as usize);
        }
        for descriptor in [&self.directory, &self.file] {
            if descriptor.open.is_some_and(|r| r.result >= 0) {
                assert!(descriptor.close.is_some());
            } else {
                assert!(descriptor.filesystem.is_none() && descriptor.close.is_none());
            }
            if self.complete {
                let open = descriptor.open.unwrap();
                assert!(open.result >= 0 && open.errno == 0);
                let fs = descriptor.filesystem.as_ref().unwrap();
                zero(fs.outcome);
                assert_eq!(fs.kind, libc::PROC_SUPER_MAGIC);
                zero(descriptor.close.unwrap());
            }
        }
        let mut copied = 0;
        for (index, read) in self.reads.iter().enumerate() {
            assert_eq!(Some(i64::from(read.fd)), self.file.open.map(|r| r.result));
            assert_eq!(
                read.offset,
                self.offset
                    .map(|start| start.checked_add(copied as u64).unwrap())
            );
            let overflow = copied == self.bytes.len();
            assert_eq!(
                read.pointer,
                if overflow {
                    self.overflow_pointer
                } else {
                    self.pointer + copied
                }
            );
            assert_eq!(
                read.requested,
                if overflow {
                    1
                } else {
                    self.bytes.len() - copied
                }
            );
            if let Some(result) = read.result {
                if (0..=read.requested as i64).contains(&result.result) && !overflow {
                    copied += result.result as usize;
                }
                if self.complete {
                    assert_eq!(result.errno, 0);
                    assert!((0..=read.requested as i64).contains(&result.result));
                }
                if result.result <= 0 || overflow {
                    assert_eq!(index + 1, self.reads.len());
                }
            } else {
                assert!(!self.complete);
                assert_eq!(index + 1, self.reads.len());
            }
        }
        assert_eq!(self.copied, copied);
        if self.complete {
            assert!(!self.reads.is_empty());
            if self.file_name == Some(c"pagemap") {
                assert_eq!(self.reads.len(), 1);
                assert_eq!(self.copied, 8);
            }
            if self.offset.is_some() {
                assert_eq!(self.copied, self.bytes.len());
            } else {
                zero(self.reads.last().unwrap().result.unwrap());
            }
        }
    }
}
