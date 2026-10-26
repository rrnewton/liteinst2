//! Observe procfs's VMA identity projection for the exact held /proc/pid/exe
//! object. It is not necessarily the filesystem's fstat identity projection.
//! The temporary tracer mapping is never read, written, or executable.
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
}
impl Descriptor {
    fn new(fd: i32) -> Self {
        Self { fd: Some(fd) }
    }
    fn raw(&self) -> i32 {
        self.fd.expect("owned exec identity descriptor")
    }
    fn close(mut self) -> Result<(), GateError> {
        let fd = self.fd.take().expect("owned exec identity descriptor");
        // Linux releases a valid descriptor even when close later reports an
        // error. Never retry a numeric fd which another thread could reuse.
        if unsafe { libc::close(fd) } != 0 {
            return Err(system("close exec identity descriptor").into());
        }
        Ok(())
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            // Drop cannot return a cleanup error. A failed emergency close is
            // a validation/process failure, never successful proof or a leak.
            if unsafe { libc::close(fd) } != 0 {
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
        Ok(Self {
            address: Some(address),
            _file: file,
        })
    }
    fn address(&self) -> u64 {
        self.address.expect("owned exec identity mapping") as usize as u64
    }
    fn unmap(mut self) {
        self.release();
    }
    fn release(&mut self) {
        if let Some(address) = self.address.take() {
            // A failed unmap leaves cleanup unproved. Fail-stop instead of
            // returning a certificate or retrying an ambiguously reusable VA.
            if unsafe { libc::munmap(address, PAGE as usize) } != 0 {
                std::process::abort();
            }
        }
    }
}
impl Drop for Page<'_> {
    fn drop(&mut self) {
        self.release();
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
            let count = unsafe { libc::read(file.raw(), address.cast(), count) };
            if count < 0 {
                return Err(system("read exec identity self maps").into());
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
    let directory = Descriptor::new(proc_directory(context)?.into_raw_fd());
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
    directory.close()?;
    let opened = descriptor(&file)?;
    context
        .owner
        .time_left(context.until, "exec identity probe mapping")?;
    let page = Page::new(&file)?;
    context
        .owner
        .time_left(context.until, "exec identity probe mapping")?;
    let length = self_maps(context, storage)?;
    let vma = projection(&storage[..length], page.address())?;
    if descriptor(&file)? != opened {
        return Err(refused("exec identity descriptor changed during mapping"));
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
