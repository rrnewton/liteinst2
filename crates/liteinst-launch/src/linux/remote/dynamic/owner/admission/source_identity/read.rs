//! New initial-capture reads retain caller-owned initialized prefixes. The
//! legacy exec Vec reads and complete-map error contract are unchanged.
use super::*;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum SourceReadOperation {
    Authenticate,
    Geometry,
    ProcDirectory,
    OpenMaps,
    MapsFilesystem,
    ReadMaps,
    MapsBound,
    ParseMaps,
    PeekMemory,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct SourceReadRequest {
    pub(in crate::linux::remote::dynamic::owner::admission) operation: SourceReadOperation,
    pub(in crate::linux::remote::dynamic::owner::admission) address: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) count: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) result: i64,
    pub(in crate::linux::remote::dynamic::owner::admission) errno: Option<i32>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct SourceReadFailure {
    pub(in crate::linux::remote::dynamic::owner::admission) operation: SourceReadOperation,
    pub(in crate::linux::remote::dynamic::owner::admission) timeout: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) errno: Option<i32>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct SourceReadProgress {
    pub(in crate::linux::remote::dynamic::owner::admission) started: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) attempted: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) requested_bytes: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) copied_bytes: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) complete: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) filesystem_type: Option<i64>,
    pub(in crate::linux::remote::dynamic::owner::admission) last_request: Option<SourceReadRequest>,
    pub(in crate::linux::remote::dynamic::owner::admission) failure: Option<SourceReadFailure>,
}
impl SourceReadProgress {
    fn begin(&mut self, requested: usize) -> Result<(), GateError> {
        if *self != Self::default() {
            return Err(refused("source read progress was already used"));
        }
        self.started = true;
        self.requested_bytes = requested;
        Ok(())
    }
    fn failed(&mut self, operation: SourceReadOperation, error: &GateError) {
        if self.failure.is_none() {
            self.failure = Some(SourceReadFailure {
                operation,
                timeout: matches!(error, GateError::Control(LaunchError::Timeout(_))),
                errno: match error {
                    GateError::Control(LaunchError::System { source, .. }) => source.raw_os_error(),
                    _ => None,
                },
            });
        }
    }
    fn observe(&mut self, request: SourceReadRequest) {
        self.attempted = true;
        self.last_request = Some(request);
    }
}

fn checked_geometry(address: u64, length: usize) -> Result<u64, GateError> {
    if length == 0 || length > crate::linux::MAX_MEMORY_READ {
        return Err(refused("source memory capture exceeds its read bound"));
    }
    address
        .checked_add(length as u64)
        .ok_or_else(|| refused("source memory capture range overflows"))
}

/// Consume an actual initialized PEEK word. Failed words never advance the
/// prefix. This pure step does not grant native or source authority.
fn accept_word(
    storage: &mut [u8],
    address: u64,
    end: u64,
    result: i64,
    errno: Option<i32>,
    progress: &mut SourceReadProgress,
) -> Result<(), GateError> {
    let cursor = address
        .checked_add(progress.copied_bytes as u64)
        .ok_or_else(|| refused("source memory capture cursor overflows"))?;
    let aligned = cursor & !7_u64;
    progress.observe(SourceReadRequest {
        operation: SourceReadOperation::PeekMemory,
        address: aligned,
        count: size_of::<u64>(),
        result,
        errno,
    });
    if let (-1, Some(errno)) = (result, errno) {
        return Err(io_error("PTRACE_PEEKDATA", std::io::Error::from_raw_os_error(errno)).into());
    }
    let offset = (cursor - aligned) as usize;
    let count = ((end - cursor) as usize).min(size_of::<u64>() - offset);
    let next = progress
        .copied_bytes
        .checked_add(count)
        .filter(|next| *next <= storage.len())
        .ok_or_else(|| refused("source memory capture prefix exceeds storage"))?;
    storage[progress.copied_bytes..next]
        .copy_from_slice(&(result as u64).to_ne_bytes()[offset..offset + count]);
    progress.copied_bytes = next;
    Ok(())
}

pub(super) fn memory_capture(
    context: &SourceReadContext<'_>,
    address: u64,
    storage: &mut [u8],
    progress: &mut SourceReadProgress,
    authenticate: impl Fn() -> Result<(), GateError>,
) -> Result<(), GateError> {
    progress.begin(storage.len())?;
    let mut operation = SourceReadOperation::Geometry;
    let result = (|| {
        let end = checked_geometry(address, storage.len())?;
        storage.fill(0);
        operation = SourceReadOperation::Authenticate;
        authenticate()?;
        while progress.copied_bytes < storage.len() {
            operation = SourceReadOperation::PeekMemory;
            context
                .owner
                .time_left(context.until, "initial source memory capture")?;
            let cursor = address + progress.copied_bytes as u64;
            let aligned = cursor & !7_u64;
            // PEEK may legitimately return all ones. Capture errno immediately;
            // no diagnostic call can overwrite the request's actual outcome.
            unsafe {
                *libc::__errno_location() = 0;
            }
            let value = unsafe {
                libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    context.owner.pid,
                    aligned as usize as *mut libc::c_void,
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            let errno = if value == -1 {
                let value = unsafe { *libc::__errno_location() };
                (value != 0).then_some(value)
            } else {
                None
            };
            accept_word(storage, address, end, value, errno, progress)?;
            // The successful bytes are retained even if this deadline check
            // refuses. They are incomplete observations, never accepted input.
            context
                .owner
                .time_left(context.until, "initial source memory capture")?;
        }
        operation = SourceReadOperation::Authenticate;
        authenticate()?;
        progress.complete = true;
        Ok(())
    })();
    if let Err(error) = &result {
        progress.failed(operation, error);
    }
    result
}

fn map_count(
    progress: &mut SourceReadProgress,
    capacity: usize,
    result: i64,
    bound: bool,
) -> Result<bool, GateError> {
    if result == 0 {
        return Ok(true);
    }
    if result < 0 {
        return Err(refused("source maps result lacks its native error"));
    }
    if bound {
        return Err(refused("exec source maps exceed fixed capture bound"));
    }
    let count = usize::try_from(result).map_err(|_| refused("source maps read count overflows"))?;
    progress.copied_bytes = progress
        .copied_bytes
        .checked_add(count)
        .filter(|length| *length <= capacity)
        .ok_or_else(|| refused("source maps read exceeds remaining storage"))?;
    Ok(false)
}

pub(super) fn maps_capture(
    context: &SourceReadContext<'_>,
    storage: &mut [u8],
    progress: &mut SourceReadProgress,
    authenticate: impl Fn() -> Result<(), GateError>,
) -> Result<usize, GateError> {
    progress.begin(storage.len())?;
    let mut operation = SourceReadOperation::Geometry;
    let result = (|| {
        if storage.len() != MAP_BYTES {
            return Err(refused("exec source maps scratch differs"));
        }
        storage.fill(0);
        operation = SourceReadOperation::Authenticate;
        authenticate()?;
        operation = SourceReadOperation::ProcDirectory;
        let directory = proc_directory(context)?;
        operation = SourceReadOperation::OpenMaps;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c"maps".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(system("open current exec source maps").into());
        }
        // SAFETY: this fd has one owner through all read/error/unwind paths.
        let file = unsafe { File::from_raw_fd(fd) };
        operation = SourceReadOperation::MapsFilesystem;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 {
            return Err(system("stat initial source maps filesystem").into());
        }
        progress.filesystem_type = Some(stat.f_type);
        if stat.f_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t {
            return Err(refused("initial source maps is not procfs"));
        }
        loop {
            let bound = progress.copied_bytes == storage.len();
            operation = if bound {
                SourceReadOperation::MapsBound
            } else {
                SourceReadOperation::ReadMaps
            };
            context
                .owner
                .time_left(context.until, "read current exec source maps")?;
            let mut extra = 0_u8;
            let (address, count) = if bound {
                (&mut extra as *mut u8, 1)
            } else {
                (
                    storage[progress.copied_bytes..].as_mut_ptr(),
                    storage.len() - progress.copied_bytes,
                )
            };
            let count_result = unsafe { libc::read(file.as_raw_fd(), address.cast(), count) };
            let error = (count_result < 0).then(|| system("read current exec source maps"));
            let errno = error.as_ref().and_then(|error| match error {
                LaunchError::System { source, .. } => source.raw_os_error(),
                _ => None,
            });
            progress.observe(SourceReadRequest {
                operation,
                address: address as usize as u64,
                count,
                result: count_result as i64,
                errno,
            });
            if let Some(error) = error {
                return Err(error.into());
            }
            let eof = map_count(progress, storage.len(), count_result as i64, bound)?;
            context
                .owner
                .time_left(context.until, "read current exec source maps")?;
            if eof {
                break;
            }
        }
        operation = SourceReadOperation::ParseMaps;
        parse(&storage[..progress.copied_bytes])?;
        operation = SourceReadOperation::Authenticate;
        authenticate()?;
        progress.complete = true;
        Ok(progress.copied_bytes)
    })();
    if let Err(error) = &result {
        progress.failed(operation, error);
    }
    result
}
