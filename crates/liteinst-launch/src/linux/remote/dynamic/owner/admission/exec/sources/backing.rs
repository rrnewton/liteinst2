//! Observe procfs's VMA identity projection for the exact held /proc/pid/exe
//! object. It is not necessarily the filesystem's fstat identity projection.
//! The temporary tracer mapping is never read, written, or executable.
#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
use super::super::oracle::{ExecFault, Probe, ProbeFd};
use super::*;
use std::os::fd::IntoRawFd;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DescriptorIdentity {
    pub(super) file: FileIdentity,
    pub(super) mode: u32,
    pub(super) length: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExecutableIdentity {
    pub(super) opened: DescriptorIdentity,
    pub(super) vma: FileIdentity,
}

// The existing 64 KiB maps scratch is reused, never duplicated. Include one
// transient page and every additional fixed descriptor/query/certificate
// object in the pre-effect peak. The page is not counted as retained payload.
pub(super) fn temporary_bytes() -> usize {
    PAGE as usize
        + 3 * size_of::<Descriptor>()
        + size_of::<Page<'_>>()
        + 2 * size_of::<libc::stat>()
        + size_of::<libc::statfs>()
        + 2 * size_of::<ExecutableIdentity>()
}

struct Descriptor {
    fd: Option<i32>,
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    probe: Option<(Probe, ProbeFd)>,
}
impl Descriptor {
    fn new(fd: i32) -> Self {
        Self {
            fd: Some(fd),
            #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
            probe: None,
        }
    }
    fn raw(&self) -> i32 {
        self.fd.expect("owned exec identity descriptor")
    }
    fn close(mut self) -> Result<(), GateError> {
        let fd = self.fd.take().expect("owned exec identity descriptor");
        // Linux releases a valid descriptor even when close later reports an
        // error. Never retry a numeric fd which another thread could reuse.
        let result = unsafe { libc::close(fd) };
        let error = (result != 0).then(|| system("close exec identity descriptor"));
        #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
        if let Some((probe, role)) = &self.probe {
            probe.closed(*role, fd, result, &error, true);
        }
        if let Some(error) = error {
            return Err(error.into());
        }
        Ok(())
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            // Drop cannot return a cleanup error. A failed emergency close is
            // a validation/process failure, never successful proof or a leak.
            let result = unsafe { libc::close(fd) };
            #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
            let error = (result != 0).then(|| system("close exec identity descriptor"));
            #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
            if let Some((probe, role)) = &self.probe {
                probe.closed(*role, fd, result, &error, false);
            }
            if result != 0 {
                std::process::abort();
            }
        }
    }
}

struct Page<'a> {
    address: Option<*mut libc::c_void>,
    _file: &'a Descriptor,
}
impl<'a> Page<'a> {
    fn new(file: &'a Descriptor) -> Result<Self, GateError> {
        // PROT_NONE avoids READ_IMPLIES_EXEC's PROT_READ promotion. No MAP_FIXED,
        // shared write, population, host dereference or child address is used.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE,
                file.raw(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(system("map exec identity projection").into());
        }
        // Install cleanup before any arithmetic, map parsing, or deadline check.
        let page = Self {
            address: Some(address),
            _file: file,
        };
        #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
        if let Some((probe, _)) = &file.probe {
            probe.mapped(file.raw(), address as usize as u64);
        }
        Ok(page)
    }
    fn address(&self) -> u64 {
        self.address.expect("owned exec identity mapping") as usize as u64
    }
    fn unmap(mut self) {
        self.release(true);
    }
    fn release(&mut self, _explicit: bool) {
        if let Some(address) = self.address.take() {
            // A failed unmap leaves cleanup unproved. Fail-stop instead of
            // returning a certificate or retrying an ambiguously reusable VA.
            let request = address;
            #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
            let request = self
                ._file
                .probe
                .as_ref()
                .map_or(request, |(probe, _)| probe.unmap_address(request));
            let result = unsafe { libc::munmap(request, PAGE as usize) };
            #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
            let errno = if result != 0 {
                std::io::Error::last_os_error().raw_os_error()
            } else {
                None
            };
            #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
            if let Some((probe, _)) = &self._file.probe {
                probe.unmapped(
                    self._file.raw(),
                    address as usize as u64,
                    request as usize as u64,
                    result,
                    errno,
                    _explicit,
                );
            }
            if result != 0 {
                std::process::abort();
            }
        }
    }
}
impl Drop for Page<'_> {
    fn drop(&mut self) {
        self.release(false);
    }
}

fn descriptor_value(stat: &libc::stat) -> Result<DescriptorIdentity, GateError> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_ino == 0 || stat.st_size <= 0 {
        return Err(refused(
            "exec identity descriptor is not an identified regular file",
        ));
    }
    Ok(DescriptorIdentity {
        file: FileIdentity {
            major: libc::major(stat.st_dev),
            minor: libc::minor(stat.st_dev),
            inode: stat.st_ino,
        },
        mode: stat.st_mode,
        length: u64::try_from(stat.st_size)
            .map_err(|_| refused("exec identity descriptor length overflows"))?,
    })
}
fn descriptor(file: &Descriptor) -> Result<DescriptorIdentity, GateError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.raw(), &mut stat) } != 0 {
        return Err(system("stat exec identity descriptor").into());
    }
    descriptor_value(&stat)
}

fn self_maps(context: &ExecSourceContext<'_>, storage: &mut [u8]) -> Result<usize, GateError> {
    let fd = unsafe {
        libc::open(
            c"/proc/self/maps".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(system("open exec identity self maps").into());
    }
    let file = Descriptor::new(fd);
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    let file = {
        let mut file = file;
        file.probe = Probe::current(context.owner).map(|probe| (probe, ProbeFd::Maps));
        file
    };
    let read: Result<usize, GateError> = (|| {
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.raw(), &mut stat) } != 0 {
            return Err(system("stat exec identity self maps").into());
        }
        if stat.f_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t {
            return Err(refused("exec identity self maps is not procfs"));
        }
        let mut length = 0;
        loop {
            context
                .owner
                .time_left(context.until, "exec identity maps capture")?;
            let mut extra = 0_u8;
            let (address, count) = if length == storage.len() {
                (&mut extra as *mut u8, 1)
            } else {
                (storage[length..].as_mut_ptr(), storage.len() - length)
            };
            let destination = address;
            #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
            let destination = if context.owner.take_exec_fault(ExecFault::MapsRead) {
                std::ptr::null_mut()
            } else {
                destination
            };
            #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
            let request = (file.raw(), destination as usize as u64, count);
            let count = unsafe { libc::read(file.raw(), destination.cast(), count) };
            let error = (count < 0).then(|| system("read exec identity self maps"));
            #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
            if let Some((probe, _)) = &file.probe {
                probe.maps_read(count, &error, request);
            }
            if let Some(error) = error {
                return Err(error.into());
            }
            context
                .owner
                .time_left(context.until, "exec identity maps capture")?;
            if count == 0 {
                return Ok(length);
            }
            if length == storage.len() || count as usize > storage.len() - length {
                return Err(refused("exec identity self maps exceed fixed capture"));
            }
            length += count as usize;
        }
    })();
    let close = file.close();
    // Preserve an earlier read error; either error prevents a certificate.
    let length = read?;
    close?;
    Ok(length)
}

fn projection(raw: &[u8], address: u64) -> Result<FileIdentity, GateError> {
    let end = address
        .checked_add(PAGE)
        .filter(|_| address != 0 && address % PAGE == 0)
        .ok_or_else(|| refused("exec identity probe geometry differs"))?;
    let maps = parse(raw)?;
    let row = maps
        .entries()
        .find(|row| row.start == address && row.end == end)
        .ok_or_else(|| refused("exec identity probe mapping is absent or merged"))?;
    if row.permissions.bytes() != *b"---p"
        || row.file_offset != 0
        || row.inode == 0
        || row.pathname.is_none_or(|path| path.is_empty())
    {
        return Err(refused("exec identity probe mapping differs"));
    }
    Ok(file_identity(row))
}

pub(super) fn observe(
    context: &ExecSourceContext<'_>,
    storage: &mut [u8],
) -> Result<ExecutableIdentity, GateError> {
    if storage.len() != MAP_BYTES {
        return Err(refused("exec identity maps scratch differs"));
    }
    storage.fill(0);
    context
        .owner
        .time_left(context.until, "exec identity probe")?;
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    let observation = Probe::begin(context.owner, context.until)?;
    let directory = Descriptor::new(proc_directory(context)?.into_raw_fd());
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    let directory = {
        let mut file = directory;
        file.probe = observation.clone().map(|probe| (probe, ProbeFd::Directory));
        file
    };
    // Follow the held task's actual executable object; no pathname is used as
    // an identity. O_PATH cannot be mapped. Read denial is a real refusal.
    let fd = unsafe {
        libc::openat(
            directory.raw(),
            c"exe".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(system("open actual exec identity object").into());
    }
    let file = Descriptor::new(fd);
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    let file = {
        let mut file = file;
        file.probe = observation
            .clone()
            .map(|probe| (probe, ProbeFd::Executable));
        file
    };
    directory.close()?;
    let opened = descriptor(&file)?;
    context
        .owner
        .time_left(context.until, "exec identity probe mapping")?;
    let page = Page::new(&file)?;
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    if context.owner.take_exec_fault(ExecFault::AfterMapPanic) {
        panic!("private exec backing post-map panic");
    }
    context
        .owner
        .time_left(context.until, "exec identity probe mapping")?;
    let length = self_maps(context, storage)?;
    let vma = projection(&storage[..length], page.address())?;
    if descriptor(&file)? != opened {
        return Err(refused("exec identity descriptor changed during mapping"));
    }
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    if let Some(probe) = &observation {
        probe.identity(
            [
                u64::from(opened.file.major),
                u64::from(opened.file.minor),
                opened.file.inode,
                u64::from(opened.mode),
                opened.length,
            ],
            [u64::from(vma.major), u64::from(vma.minor), vma.inode],
        );
    }
    context
        .owner
        .time_left(context.until, "exec identity probe cleanup")?;
    page.unmap();
    file.close()?;
    // No borrow of the self-map bytes escapes. A later child capture starts
    // from zero storage and independently compares its actual journal bytes.
    storage.fill(0);
    context
        .owner
        .time_left(context.until, "exec identity probe complete")?;
    Ok(ExecutableIdentity { opened, vma })
}

#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
pub(super) fn cleanup_leaf(owner: &Owner, path: &std::path::Path, until: Instant) {
    let opened = std::fs::OpenOptions::new().read(true).open(path).unwrap();
    let mut file = Descriptor::new(opened.into_raw_fd());
    file.probe = Probe::begin(owner, until)
        .unwrap()
        .map(|probe| (probe, ProbeFd::Executable));
    let page = Page::new(&file).unwrap();
    owner.exec_backing.as_ref().unwrap().check_mapped(0);
    owner
        .time_left(until, "private backing cleanup leaf")
        .unwrap();
    page.unmap();
    panic!("invalid munmap must abort before returning");
}
