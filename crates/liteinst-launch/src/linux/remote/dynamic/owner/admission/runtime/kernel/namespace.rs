//! Positive namespace object comparison under the existing held process pin.
//! Every identity-query request and initialized fixed payload stays in its one record.
use super::*;
use crate::linux::remote::dynamic::owner::bootstrap::{self, Request};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NSFS_MAGIC: libc::__fsword_t = 0x6e73_6673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct NativeNamespaceIdentity {
    pub(in crate::linux::remote::dynamic::owner) device: u64,
    pub(in crate::linux::remote::dynamic::owner) inode: u64,
}

struct NamespaceRead {
    proc_open: Option<Request>,
    proc_fs_request: Option<Request>,
    proc_fs: libc::statfs,
    task_open: Option<Request>,
    namespace_open: Option<Request>,
    namespace_fs_request: Option<Request>,
    namespace_fs: libc::statfs,
    namespace_type: Option<Request>,
    namespace_stat_request: Option<Request>,
    namespace_stat: libc::stat,
    identity: Option<NativeNamespaceIdentity>,
}
impl Default for NamespaceRead {
    fn default() -> Self {
        Self {
            proc_open: None,
            proc_fs_request: None,
            proc_fs: unsafe { std::mem::zeroed() },
            task_open: None,
            namespace_open: None,
            namespace_fs_request: None,
            namespace_fs: unsafe { std::mem::zeroed() },
            namespace_type: None,
            namespace_stat_request: None,
            namespace_stat: unsafe { std::mem::zeroed() },
            identity: None,
        }
    }
}

/// Native attempt owns five separately charged records. No record is reused.
pub(in crate::linux::remote::dynamic::owner) struct NamespaceObservation {
    started: bool,
    complete: bool,
    // Task component is fixed numeric bytes; no host path or readlink result.
    task: [u8; 12],
    digits: [u8; 11],
    // Tracer active PID namespace, tracee active, tracee for-children.
    reads: [NamespaceRead; 3],
    identity: Option<NativeNamespaceIdentity>,
}
impl Default for NamespaceObservation {
    fn default() -> Self {
        Self {
            started: false,
            complete: false,
            task: [0; 12],
            digits: [0; 11],
            reads: std::array::from_fn(|_| NamespaceRead::default()),
            identity: None,
        }
    }
}

fn request(call: impl FnOnce() -> libc::c_long) -> Request {
    unsafe { *libc::__errno_location() = 0 };
    let result = call();
    let errno = unsafe { *libc::__errno_location() };
    Request {
        result,
        errno: (errno != 0).then_some(errno),
    }
}
fn check(value: Request, zero: bool) -> Result<(), LaunchError> {
    if let Some(errno) = value.errno {
        return Err(io_error(
            "runtime PID namespace observation",
            std::io::Error::from_raw_os_error(errno),
        ));
    }
    if value.result < 0 || (zero && value.result != 0) {
        return Err(LaunchError::Invalid(
            "runtime PID namespace native result differs",
        ));
    }
    Ok(())
}
fn descriptor(value: Request) -> Result<OwnedFd, LaunchError> {
    check(value, false)?;
    let fd = i32::try_from(value.result)
        .map_err(|_| LaunchError::Invalid("runtime PID namespace descriptor differs"))?;
    // The successful open/openat returned one fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn read_one(
    record: &mut NamespaceRead,
    task: &std::ffi::CStr,
    child: bool,
    tracer: bool,
) -> Result<NativeNamespaceIdentity, LaunchError> {
    let value = request(|| unsafe {
        libc::open(
            c"/proc".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        ) as libc::c_long
    });
    record.proc_open = Some(value);
    let proc = descriptor(value)?;
    let value = request(|| unsafe {
        libc::fstatfs(proc.as_raw_fd(), &raw mut record.proc_fs) as libc::c_long
    });
    record.proc_fs_request = Some(value);
    check(value, true)?;
    if record.proc_fs.f_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t {
        return Err(LaunchError::Invalid(
            "runtime PID namespace directory is not procfs",
        ));
    }
    // procfs's self link intentionally selects this tracer's active namespace.
    // Numeric tracee directories must not be symlink replacements.
    let value = request(|| unsafe {
        libc::openat(
            proc.as_raw_fd(),
            task.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | if tracer { 0 } else { libc::O_NOFOLLOW },
        ) as libc::c_long
    });
    record.task_open = Some(value);
    let directory = descriptor(value)?;
    let name = if child {
        c"ns/pid_for_children"
    } else {
        c"ns/pid"
    };
    let value = request(|| unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        ) as libc::c_long
    });
    record.namespace_open = Some(value);
    let namespace = descriptor(value)?;
    let value = request(|| unsafe {
        libc::fstatfs(namespace.as_raw_fd(), &raw mut record.namespace_fs) as libc::c_long
    });
    record.namespace_fs_request = Some(value);
    check(value, true)?;
    if record.namespace_fs.f_type != NSFS_MAGIC {
        return Err(LaunchError::Invalid(
            "runtime PID namespace object is not nsfs",
        ));
    }
    let value =
        request(|| unsafe { libc::ioctl(namespace.as_raw_fd(), NS_GET_NSTYPE) as libc::c_long });
    record.namespace_type = Some(value);
    check(value, false)?;
    if value.result != libc::CLONE_NEWPID as libc::c_long {
        return Err(LaunchError::Invalid(
            "runtime namespace object is not a PID namespace",
        ));
    }
    let value = request(|| unsafe {
        libc::fstat(namespace.as_raw_fd(), &raw mut record.namespace_stat) as libc::c_long
    });
    record.namespace_stat_request = Some(value);
    check(value, true)?;
    let identity = NativeNamespaceIdentity {
        device: record.namespace_stat.st_dev,
        inode: record.namespace_stat.st_ino,
    };
    record.identity = Some(identity);
    Ok(identity)
}

pub(in crate::linux::remote::dynamic::owner) fn capture_namespace(
    owner: &Owner,
    until: Instant,
    record: &mut NamespaceObservation,
) -> Result<NativeNamespaceIdentity, LaunchError> {
    if record.started {
        return Err(LaunchError::Invalid("runtime PID namespace record reused"));
    }
    record.started = true;
    bootstrap::physical(owner, until)?;
    let mut number = u32::try_from(owner.pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or(LaunchError::Invalid("runtime PID namespace task differs"))?;
    let mut start = record.digits.len();
    while number != 0 {
        start -= 1;
        record.digits[start] = b'0' + (number % 10) as u8;
        number /= 10;
    }
    let length = record.digits.len() - start;
    record.task[..length].copy_from_slice(&record.digits[start..]);
    let task = std::ffi::CStr::from_bytes_with_nul(&record.task[..length + 1])
        .map_err(|_| LaunchError::Invalid("runtime PID namespace task encoding differs"))?;
    let tracer = read_one(&mut record.reads[0], c"self", false, true)?;
    bootstrap::physical(owner, until)?;
    let active = read_one(&mut record.reads[1], task, false, false)?;
    bootstrap::physical(owner, until)?;
    let children = read_one(&mut record.reads[2], task, true, false)?;
    bootstrap::physical(owner, until)?;
    if active != tracer || children != tracer {
        return Err(LaunchError::Invalid(
            "runtime PID namespaces differ from tracer",
        ));
    }
    record.identity = Some(tracer);
    record.complete = true;
    record.validated_identity()
}

/// Fixed local response/handle storage used while retained namespace records
/// are filled. Includes seven open/stat/ioctl results plus nested result copies,
/// all three simultaneous RAII handles and the three compared identities.
/// Retained stat/statfs/path payloads are already inside NamespaceObservation.
/// This is managed query storage, not a promise about the complete call stack.
pub(super) fn temporary_bytes() -> usize {
    3 * size_of::<OwnedFd>()
        + 10 * size_of::<Request>()
        + 3 * size_of::<NativeNamespaceIdentity>()
        + 2 * size_of::<&std::ffi::CStr>()
}

impl NamespaceObservation {
    fn validated_identity(&self) -> Result<NativeNamespaceIdentity, LaunchError> {
        if !self.started || !self.complete {
            return Err(LaunchError::Invalid(
                "runtime PID namespace record incomplete",
            ));
        }
        let expected = self
            .identity
            .ok_or(LaunchError::Invalid("runtime PID namespace result absent"))?;
        for record in &self.reads {
            for value in [record.proc_open, record.task_open, record.namespace_open] {
                check(
                    value.ok_or(LaunchError::Invalid("runtime PID namespace open absent"))?,
                    false,
                )?;
            }
            for value in [
                record.proc_fs_request,
                record.namespace_fs_request,
                record.namespace_stat_request,
            ] {
                check(
                    value.ok_or(LaunchError::Invalid("runtime PID namespace stat absent"))?,
                    true,
                )?;
            }
            if record.namespace_type
                != Some(Request {
                    result: libc::CLONE_NEWPID as libc::c_long,
                    errno: None,
                })
                || record.proc_fs.f_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t
                || record.namespace_fs.f_type != NSFS_MAGIC
                || record.identity != Some(expected)
                || record.namespace_stat.st_dev != expected.device
                || record.namespace_stat.st_ino != expected.inode
            {
                return Err(LaunchError::Invalid(
                    "runtime PID namespace retained evidence differs",
                ));
            }
        }
        Ok(expected)
    }
}

#[cfg(test)]
mod tests;
