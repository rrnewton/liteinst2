//! Private immutable artifact observations, never runtime execution authority.
use super::OracleError;
use crate::LaunchCommand;
use crate::linux::remote::dynamic::owner::admission::exact_storage;
use crate::linux::remote::dynamic::owner::{Owner, bootstrap};
use iced_x86::Instruction;
use std::cell::RefCell;
use std::ffi::{CStr, OsString};
use std::mem::size_of;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::time::Instant;

mod elf;
#[cfg(test)]
pub(super) mod tests;

pub(super) const FILE_CAP: usize = 1024 * 1024;
pub(super) const PLAN_CAP: usize = 35;
const CHECK_CAP: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PlannedKind {
    Ordinary,
    Call,
    Ret,
    Syscall { number: u64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PlannedInstruction {
    ordinal: usize,
    pc: u64,
    bytes: [u8; 15],
    length: usize,
    kind: PlannedKind,
    decoded: Instruction,
}
impl PlannedInstruction {
    pub(super) fn ordinal(&self) -> usize {
        self.ordinal
    }
    pub(super) fn pc(&self) -> u64 {
        self.pc
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    pub(super) fn kind(&self) -> PlannedKind {
        self.kind
    }
    pub(super) fn decoded(&self) -> &Instruction {
        &self.decoded
    }
    pub(super) fn next_pc(&self) -> u64 {
        self.pc + self.length as u64
    }
}

pub(super) struct ArtifactPlan {
    pub(super) entry: u64,
    pub(super) start: Range<u64>,
    pub(super) helper: Range<u64>,
    pub(super) read_load: Range<u64>,
    pub(super) text_load: Range<u64>,
    pub(super) read_filesz: usize,
    pub(super) text_filesz: usize,
    instructions: [Option<PlannedInstruction>; PLAN_CAP],
    count: usize,
    pub(super) call: usize,
    pub(super) ret: usize,
    pub(super) syscalls: [usize; 3],
}
impl ArtifactPlan {
    pub(super) fn instructions(&self) -> impl ExactSizeIterator<Item = &PlannedInstruction> {
        self.instructions[..self.count]
            .iter()
            .map(|i| i.as_ref().expect("complete artifact plan"))
    }
    pub(super) fn instruction(&self, ordinal: usize) -> Result<&PlannedInstruction, OracleError> {
        self.instructions
            .get(ordinal)
            .and_then(Option::as_ref)
            .filter(|_| ordinal < self.count)
            .ok_or(OracleError::Invalid("artifact ordinal is absent"))
    }
    pub(super) fn len(&self) -> usize {
        self.count
    }
    /// Only initialized segment bytes come from the file contract. The caller
    /// retains both complete actual pages and compares every tail byte later.
    pub(super) fn require_image(&self, file: &[u8], actual: &[u8]) -> Result<(), OracleError> {
        if actual.len() != 8192 {
            return Err(OracleError::Invalid("artifact live image length differs"));
        }
        for (offset, length) in [(0, self.read_filesz), (4096, self.text_filesz)] {
            let original = file
                .get(offset..offset + length)
                .ok_or(OracleError::Invalid("artifact image offset differs"))?;
            if actual[offset..offset + length] != *original {
                return Err(OracleError::Invalid(
                    "artifact initialized segment bytes differ",
                ));
            }
        }
        Ok(())
    }
}
pub(super) fn inspect_artifact(file: &PinnedArtifact) -> Result<ArtifactPlan, OracleError> {
    file.verify()?;
    elf::inspect(file.bytes()?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) mode: u32,
    pub(super) size: usize,
    links: u64,
}
impl FileIdentity {
    fn from(stat: &libc::stat) -> Result<Self, OracleError> {
        let size = usize::try_from(stat.st_size)
            .map_err(|_| OracleError::Invalid("artifact size is negative"))?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_mode & 0o7777 != 0o555
            || stat.st_nlink != 1
            || !(64..=FILE_CAP).contains(&size)
        {
            return Err(OracleError::Invalid(
                "artifact is not a bounded immutable-mode regular file",
            ));
        }
        Ok(Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            size,
            links: stat.st_nlink,
        })
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Outcome {
    pub(super) result: i64,
    pub(super) errno: i32,
}
pub(super) fn outcome(call: impl FnOnce() -> i64) -> Outcome {
    // SAFETY: errno belongs to this native thread; no call intervenes before its copy.
    unsafe {
        *libc::__errno_location() = 0;
    }
    let result = call();
    let errno = unsafe { *libc::__errno_location() };
    Outcome { result, errno }
}
pub(super) fn exact(
    value: Outcome,
    result: i64,
    operation: &'static str,
) -> Result<(), OracleError> {
    if value.result != result || value.errno != 0 {
        return Err(OracleError::Io {
            operation,
            errno: (value.errno != 0).then_some(value.errno),
        });
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct FileCheck {
    pub(super) started: bool,
    pub(super) directory_open: Option<Outcome>,
    pub(super) directory_statfs: Option<Outcome>,
    pub(super) directory_magic: Option<i64>,
    pub(super) directory_close: Option<Outcome>,
    pub(super) stat: Option<Outcome>,
    pub(super) identity: Option<FileIdentity>,
    pub(super) read: Option<Outcome>,
    pub(super) copied: usize,
    pub(super) eof: Option<Outcome>,
    pub(super) eof_byte: u8,
    pub(super) open: Option<Outcome>,
    pub(super) close: Option<Outcome>,
    pub(super) complete: bool,
}
pub(super) struct Verification {
    pub(super) bytes: Vec<u8>,
    pub(super) checks: [FileCheck; CHECK_CAP],
    pub(super) count: usize,
    pub(super) failed: bool,
}
/// The successful fd and every managed allocation stay in this installed owner.
/// RefCell allows read-only launch callers to append bounded forensic outcomes.
pub(super) struct PinnedArtifact {
    fd: Option<OwnedFd>,
    original: Vec<u8>,
    identity: Option<FileIdentity>,
    opened: Option<Outcome>,
    closed: Option<Outcome>,
    initial: FileCheck,
    verification: RefCell<Verification>,
    complete: bool,
}
impl PinnedArtifact {
    pub(super) fn empty() -> Self {
        Self {
            fd: None,
            original: Vec::new(),
            identity: None,
            opened: None,
            closed: None,
            initial: FileCheck::default(),
            verification: RefCell::new(Verification {
                bytes: Vec::new(),
                checks: [FileCheck::default(); CHECK_CAP],
                count: 0,
                failed: false,
            }),
            complete: false,
        }
    }
    pub(super) fn temporary_bytes() -> Result<usize, OracleError> {
        // Fixed input C-string storage, pinned-fd command text, actual stat records,
        // parser/decoder and exact-width symbolic temporaries are additive.
        (4096
            + 48
            + 10
            + 32
            + size_of::<&CStr>()
            + size_of::<LaunchCommand>()
            + 2 * size_of::<libc::stat>()
            + size_of::<libc::statfs>()
            + 2 * size_of::<FileCheck>()
            + size_of::<ArtifactPlan>()
            + size_of::<iced_x86::Decoder<'static>>()
            + size_of::<Instruction>()
            + 8 * size_of::<Range<u64>>()
            + 32 * size_of::<u64>())
        .checked_add(super::dataflow::temporary_bytes()?)
        .ok_or(OracleError::Invalid("artifact temporary overflow"))
    }
    pub(super) fn open_in_place(&mut self, path: &Path) -> Result<(), OracleError> {
        if self.opened.is_some() || !self.original.is_empty() {
            return Err(OracleError::Invalid("artifact owner reused"));
        }
        let path = path.as_os_str().as_bytes();
        if path.is_empty() || path.len() > 4095 {
            return Err(OracleError::Invalid("artifact path exceeds bound"));
        }
        let mut path_storage = [0_u8; 4096];
        path_storage[..path.len()].copy_from_slice(path);
        let path = CStr::from_bytes_with_nul(&path_storage[..path.len() + 1])
            .map_err(|_| OracleError::Invalid("artifact path contains NUL"))?;
        let opened = outcome(|| {
            i64::from(unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            })
        });
        self.opened = Some(opened);
        if (0..=i64::from(i32::MAX)).contains(&opened.result) {
            self.fd = Some(unsafe { OwnedFd::from_raw_fd(opened.result as i32) });
        }
        if self.fd.is_none() || opened.errno != 0 {
            return Err(OracleError::Io {
                operation: "open pinned artifact",
                errno: (opened.errno != 0).then_some(opened.errno),
            });
        }
        self.original = exact_storage::empty_bytes(FILE_CAP)
            .map_err(|_| OracleError::Invalid("artifact original allocation failed"))?;
        self.original.resize(FILE_CAP, 0);
        self.verification.get_mut().bytes = exact_storage::empty_bytes(FILE_CAP)
            .map_err(|_| OracleError::Invalid("artifact verification allocation failed"))?;
        self.verification.get_mut().bytes.resize(FILE_CAP, 0);
        let fd = self.fd.as_ref().unwrap().as_raw_fd();
        let identity = read_file(fd, &mut self.original, &mut self.initial)?;
        self.identity = Some(identity);
        self.complete = true;
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<&[u8], OracleError> {
        let identity = self.identity()?;
        if !self.complete {
            return Err(OracleError::Invalid("artifact capture incomplete"));
        }
        Ok(&self.original[..identity.size])
    }
    pub(super) fn identity(&self) -> Result<FileIdentity, OracleError> {
        self.identity
            .ok_or(OracleError::Invalid("artifact identity absent"))
    }
    pub(super) fn verify(&self) -> Result<(), OracleError> {
        let identity = self.identity()?;
        let mut v = self
            .verification
            .try_borrow_mut()
            .map_err(|_| OracleError::Invalid("artifact verification reentered"))?;
        if !self.complete || self.fd.is_none() || v.failed || v.count == CHECK_CAP {
            return Err(OracleError::Invalid(
                "artifact verification incomplete, failed or exhausted",
            ));
        }
        let index = v.count;
        v.count += 1;
        v.failed = true;
        let Verification { bytes, checks, .. } = &mut *v;
        let current = read_file(
            self.fd.as_ref().unwrap().as_raw_fd(),
            bytes,
            &mut checks[index],
        )?;
        if current != identity || bytes[..identity.size] != self.original[..identity.size] {
            return Err(OracleError::Invalid("artifact changed after pinning"));
        }
        v.failed = false;
        Ok(())
    }
    pub(super) fn command(&self) -> Result<LaunchCommand, OracleError> {
        self.verify()?;
        let mut command = exact_storage::empty_bytes(32)
            .map_err(|_| OracleError::Invalid("artifact command allocation failed"))?;
        let mut digits = [0_u8; 10];
        let mut at = digits.len();
        let mut fd = self.fd.as_ref().unwrap().as_raw_fd() as u32;
        loop {
            at -= 1;
            digits[at] = b'0' + (fd % 10) as u8;
            fd /= 10;
            if fd == 0 {
                break;
            }
        }
        command.extend_from_slice(b"/proc/self/fd/");
        command.extend_from_slice(&digits[at..]);
        Ok(LaunchCommand::new(OsString::from_vec(command)))
    }
    pub(super) fn close_in_place(&mut self) -> Result<(), OracleError> {
        if self.closed.is_some() {
            return Err(OracleError::Invalid("artifact close repeated"));
        }
        if let Some(fd) = self.fd.take() {
            let fd = fd.into_raw_fd();
            let result = outcome(|| i64::from(unsafe { libc::close(fd) }));
            self.closed = Some(result);
            exact(result, 0, "close pinned artifact")?;
        }
        Ok(())
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize, OracleError> {
        size_of::<Self>()
            .checked_add(self.original.capacity())
            .and_then(|n| n.checked_add(self.verification.borrow().bytes.capacity()))
            .ok_or(OracleError::Invalid("artifact capacity overflow"))
    }
    pub(super) fn verify_running(&self, owner: &Owner, until: Instant) -> Result<(), OracleError> {
        bootstrap::physical(owner, until)?;
        let mut v = self
            .verification
            .try_borrow_mut()
            .map_err(|_| OracleError::Invalid("artifact verification reentered"))?;
        if !self.complete || self.fd.is_none() || v.failed || v.count == CHECK_CAP {
            return Err(OracleError::Invalid("artifact verification exhausted"));
        }
        let index = v.count;
        v.count += 1;
        v.failed = true;
        let check = &mut v.checks[index];
        check.started = true;
        // This procfs magic link names the already-held original process. Its
        // target must equal the retained fd; it is not a new launch authority.
        let mut path = [0_u8; 48];
        let path = super::observe::io::proc_name(owner.pid, b"", &mut path)?;
        let opened = outcome(|| {
            i64::from(unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            })
        });
        check.directory_open = Some(opened);
        if !(0..=i64::from(i32::MAX)).contains(&opened.result) {
            return Err(OracleError::Io {
                operation: "open actual executable directory",
                errno: (opened.errno != 0).then_some(opened.errno),
            });
        }
        let directory =
            super::observe::io::CloseGuard::new(opened.result as i32, &mut check.directory_close);
        if opened.errno != 0 {
            return Err(OracleError::Invalid(
                "actual executable directory errno differs",
            ));
        }
        bootstrap::physical(owner, until)?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        let result =
            outcome(|| i64::from(unsafe { libc::fstatfs(directory.fd(), &raw mut filesystem) }));
        check.directory_statfs = Some(result);
        check.directory_magic = Some(filesystem.f_type);
        exact(result, 0, "actual executable procfs")?;
        if filesystem.f_type != libc::PROC_SUPER_MAGIC {
            return Err(OracleError::Invalid(
                "actual executable directory not procfs",
            ));
        }
        bootstrap::physical(owner, until)?;
        let opened = outcome(|| {
            i64::from(unsafe {
                libc::openat(
                    directory.fd(),
                    c"exe".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            })
        });
        check.open = Some(opened);
        if !(0..=i64::from(i32::MAX)).contains(&opened.result) {
            return Err(OracleError::Io {
                operation: "open actual executable",
                errno: (opened.errno != 0).then_some(opened.errno),
            });
        }
        let guard = super::observe::io::CloseGuard::new(opened.result as i32, &mut check.close);
        if opened.errno != 0 {
            return Err(OracleError::Invalid("actual executable open errno differs"));
        }
        bootstrap::physical(owner, until)?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let result = outcome(|| i64::from(unsafe { libc::fstat(guard.fd(), &raw mut stat) }));
        check.stat = Some(result);
        exact(result, 0, "stat actual executable")?;
        let identity = FileIdentity::from(&stat)?;
        check.identity = Some(identity);
        exact(guard.close(), 0, "close actual executable")?;
        exact(directory.close(), 0, "close actual executable directory")?;
        bootstrap::physical(owner, until)?;
        if identity != self.identity()? {
            return Err(OracleError::Invalid(
                "actual executable differs from pinned artifact",
            ));
        }
        check.complete = true;
        v.failed = false;
        Ok(())
    }
}
fn read_file(
    fd: i32,
    bytes: &mut [u8],
    record: &mut FileCheck,
) -> Result<FileIdentity, OracleError> {
    record.started = true;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result = outcome(|| i64::from(unsafe { libc::fstat(fd, &raw mut stat) }));
    record.stat = Some(result);
    exact(result, 0, "stat pinned artifact")?;
    let identity = FileIdentity::from(&stat)?;
    record.identity = Some(identity);
    if bytes.len() != FILE_CAP {
        return Err(OracleError::Invalid("artifact buffer capacity differs"));
    }
    bytes.fill(0);
    let read =
        outcome(|| unsafe { libc::pread(fd, bytes.as_mut_ptr().cast(), identity.size, 0) as i64 });
    record.read = Some(read);
    record.copied = usize::try_from(read.result).unwrap_or(0).min(identity.size);
    exact(read, identity.size as i64, "read pinned artifact")?;
    let eof = outcome(|| unsafe {
        libc::pread(
            fd,
            (&raw mut record.eof_byte).cast(),
            1,
            identity.size as i64,
        ) as i64
    });
    record.eof = Some(eof);
    exact(eof, 0, "pinned artifact EOF")?;
    record.complete = true;
    Ok(identity)
}

impl Drop for PinnedArtifact {
    fn drop(&mut self) {
        if self.fd.is_some() && self.close_in_place().is_err() {
            std::process::abort()
        }
    }
}
