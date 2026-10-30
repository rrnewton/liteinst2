//! Source-only observer for admitted kernel exec. Completion is not coverage.
#![forbid(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("this control requires the Linux x86-64 user ABI");

use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub mod wire;

const FILE_CAP: u64 = 16 * 1024 * 1024;
const MAP_CAP: usize = 1024 * 1024;
const XSTATE_CAP: usize = 16384;
const CAUSES: u64 = 15 | (1 << 13) | (1 << 14) | (1 << 15);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    AdmissionUnavailable,
    Shape,
    Custody,
    Io(i32),
    Deadline,
    Child,
    Event,
    DebugOwner,
    Readback,
    Entry,
    Completion,
    Cleanup,
}
type Result<T> = std::result::Result<T, Error>;
fn io_error(error: io::Error) -> Error {
    Error::Io(error.raw_os_error().unwrap_or(0))
}
fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePin {
    pub path: PathBuf,
    pub sha256: [u8; 32],
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub bytes: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}
impl FilePin {
    fn open(&self) -> Result<File> {
        if !self.path.is_absolute()
            || self.bytes > FILE_CAP
            || std::fs::canonicalize(&self.path).map_err(io_error)? != self.path
        {
            return Err(Error::Shape);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(io_error)?;
        self.check(&file)?;
        Ok(file)
    }
    fn check(&self, file: &File) -> Result<()> {
        let m = file.metadata().map_err(io_error)?;
        let actual = (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        );
        if !m.is_file()
            || actual
                != (
                    self.device,
                    self.inode,
                    self.mode,
                    self.bytes,
                    self.mtime_ns,
                    self.ctime_ns,
                )
        {
            return Err(Error::Custody);
        }
        Ok(())
    }
    fn contents(&self, file: &File) -> Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        self.check(file)?;
        let mut bytes = vec![0; usize::try_from(self.bytes).map_err(|_| Error::Shape)?];
        file.read_exact_at(&mut bytes, 0).map_err(io_error)?;
        let mut extra = [0];
        if file.read_at(&mut extra, self.bytes).map_err(io_error)? != 0
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != self.sha256
        {
            return Err(Error::Custody);
        }
        self.check(file)?;
        Ok(bytes)
    }
}

/// ELF LOAD pages already derived by the independent package checker. Every
/// byte of immutable pages is checked at both stops; mutable pages are owners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page {
    pub relative: u64,
    pub file_offset: u64,
    pub permissions_at_exec: [u8; 4],
    pub permissions_at_entry: [u8; 4],
    pub file_backed: bool,
    pub bytes: Option<Vec<u8>>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Object {
    pub file: FilePin,
    pub pages: Vec<Page>,
}

pub const KERNEL_BASIS_PROFILE: &str = "linux-x86_64-live-config-user-shstk-disabled-v1";
const KERNEL_GZIP_CAP: usize = 65536;
const KERNEL_DECODED_CAP: usize = 524288;
const KERNEL_QUERY_SENTINEL: u64 = 0x55aa55aa55aa55aa;
const KERNEL_CHECKS: u32 = 6;

/// This capsule binds an additional explicitly accepted unsafe kernel premise.
/// The hashes establish custody, never the authority of that premise.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelBasis {
    pub profile: String,
    pub basis_sha256: [u8; 32],
    pub release: String,
    pub config_gzip_bytes: u32,
    pub config_gzip_sha256: [u8; 32],
    pub config_decoded_bytes: u32,
    pub config_decoded_sha256: [u8; 32],
}
impl KernelBasis {
    fn validate(&self) -> Result<()> {
        if self.profile != KERNEL_BASIS_PROFILE
            || self.release.is_empty()
            || self.release.len() > 128
            || !self.release.bytes().all(|b| (33..=126).contains(&b))
            || self.config_gzip_bytes == 0
            || self.config_gzip_bytes as usize > KERNEL_GZIP_CAP
            || self.config_decoded_bytes == 0
            || self.config_decoded_bytes as usize > KERNEL_DECODED_CAP
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelQuery {
    pub result: libc::c_long,
    pub errno: i32,
    pub output: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub main: Object,
    pub loader: Object,
    pub bootstrap: Object,
    pub dependencies: Vec<Object>,
    pub dataset: FilePin,
    pub entry: u64,
    pub entry_bytes: Vec<u8>,
    pub completion_relative: u64,
    /// Captured by the independent resolver, never guessed from symbol text.
    pub completion_file_offset: Option<u64>,
    pub xstate_bytes: usize,
    pub kernel_basis: Option<KernelBasis>,
}

/// Safe unknown-authority admission remains unavailable. Only the documented
/// unsafe checked-launcher boundary can construct this whole-request binding.
pub struct AdmittedPackage {
    request: Request,
}
pub fn admit(
    _receipt: &[u8],
    _receipt_sha256: [u8; 32],
    _request: &Request,
) -> Result<AdmittedPackage> {
    Err(Error::AdmissionUnavailable)
}

/// Admit exactly the Request reconstructed by the separately pinned final checker.
///
/// # Safety
/// The caller must be the reviewed, pinned native launcher, after independently
/// authenticating the complete source/build/W01/bootstrap package and the exact
/// explicitly accepted unsafe platform contract. It must own lifetime custody,
/// supply the exact empty environment/argv, and verify stable identities before
/// and after this call. A digest, status flag, memfd name or set of seals proves
/// NONE of that authority. The standalone CLI is an unsafe caller boundary, not
/// an authentication service. Rust still checks all file/page/stop facts below.
/// If kernel_basis is present, the caller must additionally hold explicit unsafe
/// acceptance of that exact basis and independently validate the live bounded
/// gzip/decoded configuration. No legacy request can infer this authority.
pub unsafe fn admit_from_checked_launcher(request: &Request) -> Result<AdmittedPackage> {
    Ok(AdmittedPackage {
        request: request.clone(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Initial,
    Exec,
    Entry,
    Observed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    InitialStop,
    ExecStop,
    EntryTrap,
}
#[derive(Clone, Copy, Debug)]
pub struct Machine {
    phase: Phase,
}
impl Machine {
    pub fn new() -> Self {
        Self {
            phase: Phase::Initial,
        }
    }
    pub fn advance(&mut self, event: Event) -> Result<()> {
        self.phase = match (self.phase, event) {
            (Phase::Initial, Event::InitialStop) => Phase::Exec,
            (Phase::Exec, Event::ExecStop) => Phase::Entry,
            (Phase::Entry, Event::EntryTrap) => Phase::Observed,
            _ => return Err(Error::Event),
        };
        Ok(())
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
}
impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
enum DebugReg {
    Address,
    Status,
    Control,
}
impl DebugReg {
    fn offset(self) -> usize {
        let index = match self {
            Self::Address => 0,
            Self::Status => 6,
            Self::Control => 7,
        };
        core::mem::offset_of!(libc::user, u_debugreg) + index * core::mem::size_of::<u64>()
    }
}
trait DebugIo {
    fn read(&self, reg: DebugReg) -> Result<u64>;
    fn write(&self, reg: DebugReg, value: u64) -> Result<()>;
}
struct DebugOwner<'a, T: DebugIo> {
    io: &'a T,
    saved: [u64; 3],
    dirty: bool,
}
impl<'a, T: DebugIo> DebugOwner<'a, T> {
    fn capture(io: &'a T) -> Result<Self> {
        let saved = [
            io.read(DebugReg::Address)?,
            io.read(DebugReg::Status)?,
            io.read(DebugReg::Control)?,
        ];
        if saved[2] & (0xff | (1 << 13)) != 0 {
            return Err(Error::DebugOwner);
        }
        Ok(Self {
            io,
            saved,
            dirty: false,
        })
    }
    fn arm(&mut self, target: u64) -> Result<()> {
        self.dirty = true; // Before the first mutation, including failed write.
        self.io.write(DebugReg::Control, self.saved[2] & !0xff)?;
        self.io.write(DebugReg::Address, target)?;
        self.io.write(DebugReg::Status, self.saved[1] & !CAUSES)?;
        let control = (self.saved[2] & !(0xff | (15 << 16))) | 1;
        self.io.write(DebugReg::Control, control)?;
        if self.io.read(DebugReg::Address)? != target
            || self.io.read(DebugReg::Status)? != self.saved[1] & !CAUSES
            || self.io.read(DebugReg::Control)? != control
        {
            return Err(Error::Readback);
        }
        Ok(())
    }
    fn cause(&self) -> Result<()> {
        if self.io.read(DebugReg::Status)? & CAUSES == 1 {
            Ok(())
        } else {
            Err(Error::Event)
        }
    }
    fn event_at(&self, target: u64) -> Result<()> {
        self.cause()?;
        if self.io.read(DebugReg::Address)? != target
            || self.io.read(DebugReg::Control)? != (self.saved[2] & !(0xff | (15 << 16))) | 1
        {
            return Err(Error::DebugOwner);
        }
        Ok(())
    }
    fn restore(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        // Attempt every restoration even if one write fails. No continuation is
        // permitted after ANY restore/readback error; child is killed instead.
        let mut failed = false;
        for (reg, value) in [
            (DebugReg::Control, self.saved[2] & !0xff),
            (DebugReg::Address, self.saved[0]),
            (DebugReg::Status, self.saved[1]),
            (DebugReg::Control, self.saved[2]),
        ] {
            failed |= self.io.write(reg, value).is_err();
        }
        for (reg, value) in [
            (DebugReg::Address, self.saved[0]),
            (DebugReg::Status, self.saved[1]),
            (DebugReg::Control, self.saved[2]),
        ] {
            failed |= self.io.read(reg) != Ok(value);
        }
        if failed {
            Err(Error::Readback)
        } else {
            self.dirty = false;
            Ok(())
        }
    }
}

const CHILD_WAIT_FLAGS: libc::c_int = libc::WEXITED
    | libc::WSTOPPED
    | libc::WCONTINUED
    | libc::WNOHANG
    | libc::WNOWAIT
    | libc::__WALL;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildWait {
    Absent,
    Pending,
    Event { pid: libc::pid_t, code: libc::c_int },
}

// Pure result classification also serves controls without waiting on any test
// harness children. Successful no-event calls do NOT prove child absence.
fn child_wait_result(
    result: libc::c_int,
    error: libc::c_int,
    pid: libc::pid_t,
    code: libc::c_int,
) -> Result<ChildWait> {
    if result == -1 {
        return if error == libc::ECHILD {
            Ok(ChildWait::Absent)
        } else {
            Err(Error::Io(error))
        };
    }
    if result != 0 || pid < 0 {
        return Err(Error::Child);
    }
    if pid == 0 {
        return if code == 0 {
            Ok(ChildWait::Pending)
        } else {
            Err(Error::Child)
        };
    }
    if !matches!(
        code,
        libc::CLD_EXITED
            | libc::CLD_KILLED
            | libc::CLD_DUMPED
            | libc::CLD_TRAPPED
            | libc::CLD_STOPPED
            | libc::CLD_CONTINUED
    ) {
        return Err(Error::Child);
    }
    Ok(ChildWait::Event { pid, code })
}

fn child_wait() -> Result<ChildWait> {
    let mut info = unsafe { core::mem::zeroed::<libc::siginfo_t>() };
    unsafe {
        *libc::__errno_location() = 0;
    }
    let result = unsafe { libc::waitid(libc::P_ALL, 0, &mut info, CHILD_WAIT_FLAGS) };
    let error = errno();
    child_wait_result(result, error, unsafe { info.si_pid() }, info.si_code)
}

fn require_child_free(wait: ChildWait) -> Result<()> {
    if wait == ChildWait::Absent {
        Ok(())
    } else {
        Err(Error::Child)
    }
}

fn cleanup_deadline(saved: &Cell<Option<Instant>>, now: Instant) -> Instant {
    if let Some(end) = saved.get() {
        return end;
    }
    let end = now + Duration::from_secs(5);
    saved.set(Some(end));
    end
}

#[derive(Clone, Default)]
pub struct CleanupEvidence {
    pub direct_pid: Option<libc::pid_t>,
    pub terminal_statuses: Vec<(libc::pid_t, i32)>,
    pub unexpected_child: bool,
}
impl CleanupEvidence {
    fn note_event(&mut self, pid: libc::pid_t) {
        self.unexpected_child |= self.direct_pid != Some(pid);
    }
    fn note_terminal(&mut self, pid: libc::pid_t, status: i32) -> Result<()> {
        if pid <= 0
            || !(libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
            || self.terminal_statuses.len() >= 4096
        {
            return Err(Error::Cleanup);
        }
        self.note_event(pid);
        self.terminal_statuses.push((pid, status));
        Ok(())
    }
    fn finish(&self, direct_reaped: bool, expired: bool) -> Result<()> {
        if expired
            || !direct_reaped
            || self.unexpected_child
            || self.terminal_statuses.len() != 1
            || Some(self.terminal_statuses[0].0) != self.direct_pid
        {
            return Err(Error::Cleanup);
        }
        Ok(())
    }
}

struct Child {
    pid: libc::pid_t,
    deadline: Instant,
    reaped: Cell<bool>,
    cleanup_complete: Cell<bool>,
    cleanup_deadline: Cell<Option<Instant>>,
    cleanup_evidence: RefCell<CleanupEvidence>,
}
impl Child {
    fn deadline(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
    fn wait(&self) -> Result<i32> {
        loop {
            self.deadline()?;
            let mut status = 0;
            let got = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WALL) };
            if got == self.pid {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.reaped.set(true);
                    self.cleanup_evidence
                        .borrow_mut()
                        .note_terminal(self.pid, status)?;
                }
                return Ok(status);
            }
            if got == -1 && errno() != libc::EINTR {
                return Err(Error::Child);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn ptrace(&self, request: libc::c_uint, address: usize, data: usize) -> Result<()> {
        self.deadline()?;
        let got = unsafe { libc::ptrace(request, self.pid, address, data) };
        if got == 0 {
            Ok(())
        } else {
            Err(Error::Io(errno()))
        }
    }
    fn continue_child(&self) -> Result<()> {
        self.ptrace(libc::PTRACE_CONT, 0, 0)
    }
    fn memory(&self, address: u64, count: usize) -> Result<Vec<u8>> {
        if count > MAP_CAP || address.checked_add(count as u64).is_none() {
            return Err(Error::Shape);
        }
        let mut bytes = Vec::with_capacity(count);
        let begin = address & !7;
        let mut at = begin;
        while at < address + count as u64 {
            self.deadline()?;
            unsafe {
                *libc::__errno_location() = 0;
            }
            let word =
                unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, self.pid, at as usize, 0_usize) };
            if word == -1 && errno() != 0 {
                return Err(Error::Io(errno()));
            }
            for (index, byte) in (word as u64).to_ne_bytes().into_iter().enumerate() {
                let pos = at + index as u64;
                if address <= pos && pos < address + count as u64 {
                    bytes.push(byte);
                }
            }
            at = at.checked_add(8).ok_or(Error::Shape)?;
        }
        Ok(bytes)
    }
    fn regs(&self) -> Result<libc::user_regs_struct> {
        let mut regs = unsafe { core::mem::zeroed::<libc::user_regs_struct>() };
        self.ptrace(
            libc::PTRACE_GETREGS,
            0,
            (&mut regs as *mut libc::user_regs_struct) as usize,
        )?;
        Ok(regs)
    }
    fn siginfo(&self) -> Result<(libc::siginfo_t, Vec<u8>)> {
        // Keep the kernel-written byte buffer itself. Serializing a moved C
        // struct could read padding whose initialization Rust need not retain.
        let mut raw = vec![0_u8; core::mem::size_of::<libc::siginfo_t>()];
        self.ptrace(libc::PTRACE_GETSIGINFO, 0, raw.as_mut_ptr() as usize)?;
        let info = unsafe { core::ptr::read_unaligned(raw.as_ptr().cast::<libc::siginfo_t>()) };
        Ok((info, raw))
    }
    fn xstate(&self, expected: usize) -> Result<Vec<u8>> {
        if !(576..=XSTATE_CAP).contains(&expected) {
            return Err(Error::Shape);
        }
        let mut bytes = vec![0; XSTATE_CAP];
        let mut io = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        self.ptrace(
            libc::PTRACE_GETREGSET,
            0x202,
            (&mut io as *mut libc::iovec) as usize,
        )?;
        if io.iov_len != expected {
            return Err(Error::Entry);
        }
        bytes.truncate(expected);
        Ok(bytes)
    }
    fn cleanup(&self) -> Result<()> {
        if self.cleanup_complete.get() {
            return self
                .cleanup_evidence
                .borrow()
                .finish(self.reaped.get(), false);
        }
        // This dedicated single-threaded subreaper was child-free before fork.
        // Kill our still-unreaped direct child first. TRACEFORK/VFORK/CLONE
        // normally surface unexpected descendants as owned stop events. An
        // eventless child (e.g. CLONE_UNTRACED) is never guessed: Pending expires
        // with cleanup failure, leaving the outer owner responsible. Global
        // WNOWAIT authenticates event PIDs without proc enumeration; only exact
        // global ECHILD plus terminal direct-child evidence completes cleanup.
        // Drop shares this same five-second budget; it cannot start a retry.
        let end = cleanup_deadline(&self.cleanup_deadline, Instant::now());
        if Instant::now() >= end {
            return Err(Error::Cleanup);
        }
        if !self.reaped.get()
            && unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0
            && errno() != libc::ESRCH
        {
            return Err(Error::Cleanup);
        }
        let mut seen = std::collections::BTreeSet::new();
        loop {
            if Instant::now() >= end {
                return Err(Error::Cleanup);
            }
            let wait = child_wait().map_err(|_| Error::Cleanup)?;
            if Instant::now() >= end {
                return Err(Error::Cleanup);
            }
            match wait {
                ChildWait::Absent => {
                    if !self.reaped.get() {
                        return Err(Error::Cleanup);
                    }
                    self.cleanup_complete.set(true);
                    return self
                        .cleanup_evidence
                        .borrow()
                        .finish(self.reaped.get(), Instant::now() >= end);
                }
                ChildWait::Pending => {}
                ChildWait::Event { pid, code } => {
                    self.cleanup_evidence.borrow_mut().note_event(pid);
                    seen.insert(pid);
                    // Retain the old 4096-child bound, conservatively over all
                    // identities observed during this cleanup rather than one
                    // instantaneous proc snapshot.
                    if seen.len() > 4096 {
                        return Err(Error::Cleanup);
                    }
                    let terminal =
                        matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED);
                    // WNOWAIT and the sole waiter retain this owned identity
                    // until the exact-PID wait below; no candidate PID is used.
                    if !terminal
                        && unsafe { libc::kill(pid, libc::SIGKILL) } != 0
                        && errno() != libc::ESRCH
                    {
                        return Err(Error::Cleanup);
                    }
                    let mut status = 0;
                    let got = unsafe {
                        libc::waitpid(
                            pid,
                            &mut status,
                            libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED | libc::__WALL,
                        )
                    };
                    if got == -1 || (got != 0 && got != pid) {
                        return Err(Error::Cleanup);
                    }
                    if got == pid {
                        let reaped = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                        if terminal && !reaped {
                            return Err(Error::Cleanup);
                        }
                        if reaped {
                            if pid == self.pid {
                                self.reaped.set(true);
                            }
                            self.cleanup_evidence
                                .borrow_mut()
                                .note_terminal(pid, status)?;
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if !self.cleanup_complete.get() {
            let _ = self.cleanup();
        }
    }
}
impl DebugIo for Child {
    fn read(&self, reg: DebugReg) -> Result<u64> {
        self.deadline()?;
        unsafe {
            *libc::__errno_location() = 0;
        }
        let got = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, self.pid, reg.offset(), 0_usize) };
        if got == -1 && errno() != 0 {
            Err(Error::Io(errno()))
        } else {
            Ok(got as u64)
        }
    }
    fn write(&self, reg: DebugReg, value: u64) -> Result<()> {
        // The only write API in this module: typed DR0/DR6/DR7. No SETREGS,
        // SETREGSET, POKETEXT, POKEDATA, injected syscall or remote function call.
        self.ptrace(libc::PTRACE_POKEUSER, reg.offset(), value as usize)
    }
}

fn read_proc(pid: libc::pid_t, name: &str, cap: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(format!("/proc/{pid}/{name}"))
        .map_err(io_error)?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > cap {
        return Err(Error::Shape);
    }
    Ok(bytes)
}
#[derive(Debug)]
struct Mapping {
    start: u64,
    end: u64,
    offset: u64,
    device: u64,
    inode: u64,
    permissions: [u8; 4],
}
fn parse_maps(raw: &[u8]) -> Result<Vec<Mapping>> {
    let text = std::str::from_utf8(raw).map_err(|_| Error::Shape)?;
    if raw.len() > MAP_CAP || !text.ends_with('\n') {
        return Err(Error::Shape);
    }
    let hex = |s: &str| u64::from_str_radix(s, 16).map_err(|_| Error::Shape);
    let mut maps = Vec::new();
    for line in text.lines() {
        if maps.len() == 8192 {
            return Err(Error::Shape);
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5 {
            return Err(Error::Shape);
        }
        let (start, end) = fields[0].split_once('-').ok_or(Error::Shape)?;
        let (major, minor) = fields[3].split_once(':').ok_or(Error::Shape)?;
        let start = hex(start)?;
        let end = hex(end)?;
        let permissions: [u8; 4] = fields[1].as_bytes().try_into().map_err(|_| Error::Shape)?;
        if start >= end
            || start % 4096 != 0
            || end % 4096 != 0
            || !matches!(permissions[0], b'r' | b'-')
            || !matches!(permissions[1], b'w' | b'-')
            || !matches!(permissions[2], b'x' | b'-')
            || permissions[3] != b'p'
            || maps.last().is_some_and(|m: &Mapping| m.end > start)
        {
            return Err(Error::Shape);
        }
        maps.push(Mapping {
            start,
            end,
            offset: hex(fields[2])?,
            device: libc::makedev(
                u32::try_from(hex(major)?).map_err(|_| Error::Shape)?,
                u32::try_from(hex(minor)?).map_err(|_| Error::Shape)?,
            ),
            inode: fields[4].parse().map_err(|_| Error::Shape)?,
            permissions,
        });
    }
    Ok(maps)
}
fn auxv(raw: &[u8]) -> Result<(u64, u64)> {
    if raw.len() > 4096 || raw.len() % 16 != 0 {
        return Err(Error::Shape);
    }
    let mut entry = None;
    let mut base = None;
    let mut terminated = false;
    for row in raw.chunks_exact(16) {
        let tag = u64::from_ne_bytes(row[..8].try_into().map_err(|_| Error::Shape)?);
        let value = u64::from_ne_bytes(row[8..].try_into().map_err(|_| Error::Shape)?);
        if terminated {
            return Err(Error::Shape);
        }
        match tag {
            0 => {
                if value != 0 {
                    return Err(Error::Shape);
                }
                terminated = true;
            }
            7 if base.replace(value).is_some() => return Err(Error::Shape),
            9 if entry.replace(value).is_some() => return Err(Error::Shape),
            _ => (),
        }
    }
    if !terminated {
        return Err(Error::Shape);
    }
    Ok((entry.ok_or(Error::Shape)?, base.ok_or(Error::Shape)?))
}
fn secure_auxv(raw: &[u8]) -> Result<(u64, u64)> {
    let result = auxv(raw)?;
    let secure: Vec<_> = raw
        .chunks_exact(16)
        .filter(|row| u64::from_ne_bytes(row[..8].try_into().expect("exact auxv chunk")) == 23)
        .map(|row| u64::from_ne_bytes(row[8..].try_into().expect("exact auxv chunk")))
        .collect();
    if secure != [0] {
        return Err(Error::Entry);
    }
    Ok(result)
}
fn disabled_shstk(raw: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(raw).map_err(|_| Error::Shape)?;
    let mut seen = [false; 2];
    for line in text.lines() {
        for (index, name) in ["x86_Thread_features:", "x86_Thread_features_locked:"]
            .iter()
            .enumerate()
        {
            if let Some(value) = line.strip_prefix(name) {
                if seen[index] || !value.trim().is_empty() {
                    return Err(Error::Entry);
                }
                seen[index] = true;
            }
        }
    }
    if seen != [true, true] {
        return Err(Error::Entry);
    }
    Ok(())
}
fn controlled_signal_status(raw: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(raw).map_err(|_| Error::Shape)?;
    for name in ["SigBlk:", "SigIgn:"] {
        let values: Vec<_> = text
            .lines()
            .filter_map(|line| line.strip_prefix(name))
            .collect();
        if values.len() != 1 {
            return Err(Error::Entry);
        }
        let value = values[0].trim();
        if value.len() != 16 || u64::from_str_radix(value, 16) != Ok(0) {
            return Err(Error::Entry);
        }
    }
    Ok(())
}

// Only the separately accepted config-off mode calls these new guards. A
// missing proc field or a failed syscall never selects this mode.
fn seccomp_zero(raw: &[u8]) -> Result<()> {
    if raw.len() > 65536 || !raw.is_ascii() || !raw.ends_with(b"\n") || raw.contains(&0) {
        return Err(Error::Entry);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Error::Shape)?;
    let mut seen = false;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Seccomp:") {
            if seen || value.trim() != "0" {
                return Err(Error::Entry);
            }
            seen = true;
        } else if line.trim_start().starts_with("Seccomp:") {
            return Err(Error::Entry);
        }
    }
    if !seen {
        return Err(Error::Entry);
    }
    Ok(())
}
fn absent_shstk(raw: &[u8]) -> Result<()> {
    seccomp_zero(raw)?;
    let text = std::str::from_utf8(raw).map_err(|_| Error::Shape)?;
    if text
        .lines()
        .any(|line| line.trim_start().starts_with("x86_Thread_features"))
    {
        return Err(Error::Entry);
    }
    Ok(())
}
fn request_shstk(raw: &[u8], basis: Option<&KernelBasis>) -> Result<()> {
    if basis.is_some() {
        absent_shstk(raw)
    } else {
        disabled_shstk(raw)
    }
}
fn kernel_query_matches(query: KernelQuery) -> Result<()> {
    if query.result != -1 || query.errno != libc::EINVAL || query.output != KERNEL_QUERY_SENTINEL {
        return Err(Error::Entry);
    }
    Ok(())
}
fn kernel_config_matches(
    basis: &KernelBasis,
    raw: &[u8],
    procfs: bool,
    regular: bool,
    system: &str,
    release: &str,
    machine: &str,
) -> Result<()> {
    basis.validate()?;
    if !procfs
        || !regular
        || raw.len() != basis.config_gzip_bytes as usize
        || raw.len() > KERNEL_GZIP_CAP
        || <[u8; 32]>::from(Sha256::digest(raw)) != basis.config_gzip_sha256
        || system != "Linux"
        || machine != "x86_64"
        || release != basis.release
    {
        return Err(Error::Custody);
    }
    Ok(())
}
fn uname_field(raw: &[libc::c_char]) -> Result<String> {
    let end = raw.iter().position(|&b| b == 0).ok_or(Error::Custody)?;
    let bytes: Vec<_> = raw[..end].iter().map(|&b| b as u8).collect();
    if bytes.is_empty() || !bytes.iter().all(|b| (33..=126).contains(b)) {
        return Err(Error::Custody);
    }
    String::from_utf8(bytes).map_err(|_| Error::Custody)
}
fn live_kernel_config(basis: &KernelBasis) -> Result<()> {
    basis.validate()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/proc/config.gz")
        .map_err(io_error)?;
    let before = file.metadata().map_err(io_error)?;
    let mut fs = unsafe { core::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0 {
        return Err(Error::Io(errno()));
    }
    if fs.f_type != 0x9fa0 || !before.is_file() {
        return Err(Error::Custody);
    }
    let mut raw = Vec::new();
    (&mut file)
        .take(u64::from(basis.config_gzip_bytes) + 1)
        .read_to_end(&mut raw)
        .map_err(io_error)?;
    let after = file.metadata().map_err(io_error)?;
    if (before.dev(), before.ino(), before.mode()) != (after.dev(), after.ino(), after.mode()) {
        return Err(Error::Custody);
    }
    let mut uname = unsafe { core::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut uname) } != 0 {
        return Err(Error::Io(errno()));
    }
    // The checked launcher independently bounds/decodes the one gzip member.
    // This check binds the actual live compressed bytes to that accepted input;
    // it does not claim those bytes prove the trusted kernel's implementation.
    kernel_config_matches(
        basis,
        &raw,
        fs.f_type == 0x9fa0,
        after.is_file(),
        &uname_field(&uname.sysname)?,
        &uname_field(&uname.release)?,
        &uname_field(&uname.machine)?,
    )
}
fn query_kernel_status() -> KernelQuery {
    let mut output = KERNEL_QUERY_SENTINEL;
    // libc::syscall supplies the -1/errno convention. The opcode and output
    // width are the literal Linux x86-64 ABI, not a libc SHSTK wrapper.
    unsafe { *libc::__errno_location() = 0 };
    let result =
        unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005_u64, &mut output as *mut u64) };
    let error = errno();
    KernelQuery {
        result,
        errno: error,
        output,
    }
}
fn kernel_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}
fn kernel_checkpoint(
    basis: Option<&KernelBasis>,
    deadline: Instant,
    evidence: &mut Evidence,
) -> Result<()> {
    let Some(basis) = basis else { return Ok(()) };
    kernel_deadline(deadline)?;
    if evidence.kernel_checks >= KERNEL_CHECKS {
        return Err(Error::Shape);
    }
    live_kernel_config(basis)?;
    // This observer query checks consistency of an explicitly trusted,
    // kernel-global config-off premise. It is NOT a tracee-state query.
    seccomp_zero(&read_proc(
        std::process::id() as libc::pid_t,
        "status",
        65536,
    )?)?;
    let query = query_kernel_status();
    evidence.kernel_query = Some(query);
    kernel_query_matches(query)?;
    kernel_deadline(deadline)?;
    evidence.kernel_checks += 1;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
struct KernelSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}
impl KernelSigaction {
    const DEFAULT: Self = Self {
        handler: 0,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    const UNREAD: Self = Self {
        handler: u64::MAX,
        flags: u64::MAX,
        restorer: u64::MAX,
        mask: u64::MAX,
    };
}
fn reset_reserved_signals_with(
    mut call: impl FnMut(
        libc::c_int,
        Option<&KernelSigaction>,
        Option<&mut KernelSigaction>,
    ) -> libc::c_long,
) -> bool {
    for signal in [32, 33] {
        if call(signal, Some(&KernelSigaction::DEFAULT), None) != 0 {
            return false;
        }
        let mut actual = KernelSigaction::UNREAD;
        if call(signal, None, Some(&mut actual)) != 0 || actual != KernelSigaction::DEFAULT {
            return false;
        }
    }
    true
}
/// # Safety
/// Only the owned, single-threaded post-fork child may normalize NPTL-reserved
/// dispositions. Never call this on the parent or a shared test process.
unsafe fn reset_reserved_signals() -> bool {
    reset_reserved_signals_with(|signal, action, old| {
        let action = action.map_or(core::ptr::null(), |a| a as *const KernelSigaction);
        let old = old.map_or(core::ptr::null_mut(), |a| a as *mut KernelSigaction);
        unsafe { libc::syscall(libc::SYS_rt_sigaction, signal, action, old, 8_usize) }
    })
}

// stat(2) and proc maps need not use the same device-number namespace (for
// example, Btrfs subvolumes). Keep the full stat/hash pin and independently bind
// the proc namespace through an owned mapping of the already retained fd.
// Numeric proc identity alone is insufficient: subvolumes can reuse inodes.
#[derive(Clone, Debug, Eq, PartialEq)]
struct MappedFileIdentity {
    pin: FilePin,
    device: u64,
}
impl MappedFileIdentity {
    fn check_pin(&self, pin: &FilePin) -> Result<()> {
        if self.pin != *pin {
            return Err(Error::Custody);
        }
        Ok(())
    }
    fn matches(&self, mapping: &Mapping) -> bool {
        mapping.device == self.device && mapping.inode == self.pin.inode
    }
    fn check_target(&self, mapping: &Mapping, target: &[u8]) -> Result<()> {
        if !self.matches(mapping) {
            return Err(Error::Custody);
        }
        mapped_path_matches(target, &self.pin.path)
    }
}
fn mapped_path_matches(raw: &[u8], expected: &std::path::Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    // No deleted suffix stripping, aliases, basename matching or normalization.
    if raw.is_empty() || raw.len() > 4095 || raw != expected.as_os_str().as_bytes() {
        return Err(Error::Custody);
    }
    Ok(())
}
fn map_target_with(read: impl FnOnce(&mut [u8]) -> Result<usize>) -> Result<Vec<u8>> {
    let mut bytes = [0_u8; 4096];
    let size = read(&mut bytes)?;
    if size == 0 || size >= bytes.len() {
        return Err(Error::Custody);
    }
    Ok(bytes[..size].to_vec())
}
fn mapping_target(pid: libc::pid_t, mapping: &Mapping) -> Result<Vec<u8>> {
    let name = CString::new(format!(
        "/proc/{pid}/map_files/{:x}-{:x}",
        mapping.start, mapping.end
    ))
    .map_err(|_| Error::Shape)?;
    // readlink is unprivileged on the supported host; following this symlink
    // requires privileges. Any unavailable/denied link refuses, with no fallback.
    map_target_with(|bytes| {
        let size = unsafe { libc::readlink(name.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if size < 0 {
            Err(Error::Io(errno()))
        } else {
            Ok(size as usize)
        }
    })
}
fn calibrated_identity(
    pin: &FilePin,
    address: u64,
    maps: &[Mapping],
    target: &[u8],
) -> Result<MappedFileIdentity> {
    let end = address.checked_add(4096).ok_or(Error::Shape)?;
    let rows: Vec<_> = maps
        .iter()
        .filter(|m| m.start <= address && end <= m.end)
        .collect();
    if rows.len() != 1 {
        return Err(Error::Custody);
    }
    let row = rows[0];
    if row.start != address
        || row.end != end
        || row.offset != 0
        || row.permissions != *b"r--p"
        || row.inode != pin.inode
    {
        return Err(Error::Custody);
    }
    mapped_path_matches(target, &pin.path)?;
    Ok(MappedFileIdentity {
        pin: pin.clone(),
        device: row.device,
    })
}
fn release_probe_with(
    base: &mut Option<usize>,
    mut unmap: impl FnMut(usize, usize) -> Result<()>,
) -> Result<()> {
    if let Some(address) = *base {
        unmap(address, 3 * 4096)?;
        *base = None;
    }
    Ok(())
}
struct ProbeReservation {
    base: Option<usize>,
}
impl ProbeReservation {
    fn close(&mut self) -> Result<()> {
        release_probe_with(&mut self.base, |address, bytes| {
            // This entire three-page range is still exclusively owned here.
            if unsafe { libc::munmap(address as *mut libc::c_void, bytes) } != 0 {
                return Err(Error::Cleanup);
            }
            Ok(())
        })
    }
}
impl Drop for ProbeReservation {
    fn drop(&mut self) {
        // Explicit close is checked before fork; this is an error/unwind backstop.
        let _ = self.close();
    }
}
fn calibrate_file(pin: &FilePin, held: &File, deadline: Instant) -> Result<MappedFileIdentity> {
    kernel_deadline(deadline)?;
    pin.check(held)?;
    let base = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            3 * 4096,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(Error::Io(errno()));
    }
    let mut reservation = ProbeReservation {
        base: Some(base as usize),
    };
    let checked = (|| {
        let address = (base as usize).checked_add(4096).ok_or(Error::Shape)?;
        // MAP_FIXED replaces only the middle page of our own reservation. The
        // two PROT_NONE guards prevent VMA merging with another file mapping.
        let mapped = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                held.as_raw_fd(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(Error::Io(errno()));
        }
        if mapped as usize != address {
            return Err(Error::Custody);
        }
        let maps = parse_maps(&read_proc(
            std::process::id() as libc::pid_t,
            "maps",
            MAP_CAP,
        )?)?;
        let row = maps
            .iter()
            .find(|m| m.start == address as u64 && m.end == address as u64 + 4096)
            .ok_or(Error::Custody)?;
        let target = mapping_target(std::process::id() as libc::pid_t, row)?;
        let identity = calibrated_identity(pin, address as u64, &maps, &target)?;
        pin.check(held)?;
        pin.check(&pin.open()?)?;
        kernel_deadline(deadline)?;
        Ok(identity)
    })();
    // No probe mapping survives into fork, even on an unsuccessful calibration.
    reservation.close()?;
    kernel_deadline(deadline)?;
    checked
}

fn object_bias(
    object: &Object,
    maps: &[Mapping],
    identity: &MappedFileIdentity,
    mut target: impl FnMut(&Mapping) -> Result<Vec<u8>>,
) -> Result<u64> {
    identity.check_pin(&object.file)?;
    let first = object.pages.first().ok_or(Error::Shape)?;
    let possible: Vec<_> = maps
        .iter()
        .filter(|m| {
            identity.matches(m) && m.offset == first.file_offset && m.start >= first.relative
        })
        .collect();
    if !first.file_backed || possible.len() != 1 {
        return Err(Error::Custody);
    }
    identity.check_target(possible[0], &target(possible[0])?)?;
    Ok(possible[0].start - first.relative)
}
fn check_object(
    child: &Child,
    object: &Object,
    maps: &[Mapping],
    bias: u64,
    at_entry: bool,
    identity: &MappedFileIdentity,
) -> Result<()> {
    kernel_deadline(child.deadline)?;
    identity.check_pin(&object.file)?;
    let current = object.file.open()?;
    object.file.contents(&current)?;
    let mut verified_paths = Vec::new();
    if object.pages.is_empty() || object.pages.len() > 65536 {
        return Err(Error::Shape);
    }
    for p in &object.pages {
        let address = bias.checked_add(p.relative).ok_or(Error::Shape)?;
        let end = address.checked_add(4096).ok_or(Error::Shape)?;
        let permissions = if at_entry {
            p.permissions_at_entry
        } else {
            p.permissions_at_exec
        };
        let found: Vec<_> = maps
            .iter()
            .filter(|m| {
                m.start <= address
                    && end <= m.end
                    && (if p.file_backed {
                        identity.matches(m) && m.offset + address - m.start == p.file_offset
                    } else {
                        m.device == 0 && m.inode == 0
                    })
                    && m.permissions == permissions
            })
            .collect();
        if found.len() != 1 {
            return Err(Error::Custody);
        }
        if p.file_backed {
            let row = found[0];
            let range = (row.start, row.end);
            if !verified_paths.contains(&range) {
                // The sole child is stopped. The accepted lifetime contract
                // forbids path/input replacement; this is not pathname sealing.
                kernel_deadline(child.deadline)?;
                identity.check_target(row, &mapping_target(child.pid, row)?)?;
                kernel_deadline(child.deadline)?;
                verified_paths.push(range);
            }
        }
        if let Some(bytes) = &p.bytes {
            if bytes.len() != 4096 || child.memory(address, 4096)? != *bytes {
                return Err(Error::Custody);
            }
        }
    }
    object.file.contents(&current)?;
    object.file.contents(&object.file.open()?)?;
    kernel_deadline(child.deadline)?;
    Ok(())
}
fn stopped(status: i32, signal: i32, event: i32) -> bool {
    libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == signal && status >> 16 == event
}
fn cstring(path: &std::path::Path) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Shape)
}
fn string_at(child: &Child, address: u64, expected: &[u8]) -> Result<()> {
    let mut want = expected.to_vec();
    want.push(0);
    if child.memory(address, want.len())? != want {
        return Err(Error::Entry);
    }
    Ok(())
}
fn stack_args(child: &Child, rsp: u64, main: &CString, data: &CString) -> Result<()> {
    let words = child.memory(rsp, 40)?;
    let word = |n: usize| -> Result<u64> {
        Ok(u64::from_ne_bytes(
            words[n * 8..n * 8 + 8]
                .try_into()
                .map_err(|_| Error::Shape)?,
        ))
    };
    if word(0)? != 2 || word(3)? != 0 || word(4)? != 0 {
        return Err(Error::Entry);
    }
    string_at(child, word(1)?, main.as_bytes())?;
    string_at(child, word(2)?, data.as_bytes())
}

#[derive(Default)]
pub struct Evidence {
    pub kernel_basis: Option<KernelBasis>,
    pub kernel_checks: u32,
    pub kernel_query: Option<KernelQuery>,
    pub stops: Vec<StopEvidence>,
    pub exec_auxv: Vec<u8>,
    pub entry_auxv: Vec<u8>,
    pub exec_maps: Vec<u8>,
    pub entry_maps: Vec<u8>,
    pub exec_status: Vec<u8>,
    pub entry_status: Vec<u8>,
    pub entry_registers: Vec<u8>,
    pub entry_xstate: Vec<u8>,
    pub debug_restored: Option<bool>,
    pub restore_error: Option<Error>,
    pub primary_error: Option<Error>,
    pub cleanup_error: Option<Error>,
    pub cleanup: CleanupEvidence,
    pub absence_echild: bool,
    pub child_started: bool,
}
pub struct StopEvidence {
    pub kind: &'static str,
    pub status: i32,
    pub siginfo: Vec<u8>,
}
pub struct Observation {
    /// Raw registers and xstate. No RF/TF normalization, no write-back.
    pub registers: Vec<u8>,
    pub xstate: Vec<u8>,
    pub completion: u64,
    pub main_entry: u64,
    pub bootstrap_bias: u64,
    pub stopped_before_main_execution: bool,
    pub observer_killed_child: bool,
    pub absence_echild: bool,
    pub route_coverage_complete: bool,
}

/// A separate control, never one of the forty ordinary N01 executions.
/// Successful completion is still NOT production-route coverage.
pub fn observe(request: &Request, admitted: &AdmittedPackage) -> Result<Observation> {
    observe_with_evidence(request, admitted, &mut Evidence::default())
}
pub fn observe_with_evidence(
    request: &Request,
    admitted: &AdmittedPackage,
    evidence: &mut Evidence,
) -> Result<Observation> {
    evidence.kernel_basis = request.kernel_basis.clone();
    evidence.kernel_checks = 0;
    evidence.kernel_query = None;
    let result = observe_inner(request, admitted, evidence);
    if evidence.primary_error.is_none() {
        evidence.primary_error = result.as_ref().err().cloned();
    }
    result
}
fn observe_inner(
    request: &Request,
    admitted: &AdmittedPackage,
    evidence: &mut Evidence,
) -> Result<Observation> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(15);
    // The unsafe checker boundary binds the WHOLE typed request, never merely
    // a nonzero digest or a receipt boolean.
    if admitted.request != *request {
        return Err(Error::AdmissionUnavailable);
    }
    if request.entry_bytes.is_empty()
        || request.entry_bytes.len() > 15
        || request.completion_relative % 8 != 0
        || request.dependencies.len() > 16
        || request.entry >= 1 << 47
        || request.completion_relative >= (1 << 47) - 8
        || request.dataset.bytes > 65536
    {
        return Err(Error::Shape);
    }
    if let Some(basis) = &request.kernel_basis {
        basis.validate()?;
    }
    let objects: Vec<_> = [&request.main, &request.loader, &request.bootstrap]
        .into_iter()
        .chain(request.dependencies.iter())
        .collect();
    let mut owners = Vec::new();
    let mut mapped = 0_usize;
    for object in &objects {
        if object.pages.is_empty() || object.pages.len() > 65536 {
            return Err(Error::Shape);
        }
        mapped = mapped.checked_add(object.pages.len()).ok_or(Error::Shape)?;
        if mapped > 65536 {
            return Err(Error::Shape);
        }
        for (i, page) in object.pages.iter().enumerate() {
            if page.relative % 4096 != 0
                || page.relative >= (1 << 47) - 4096
                || page.file_offset % 4096 != 0
                || page.file_offset > FILE_CAP
                || i > 0 && object.pages[i - 1].relative >= page.relative
                || page.bytes.as_ref().is_some_and(|bytes| bytes.len() != 4096)
            {
                return Err(Error::Shape);
            }
        }
        let file = object.file.open()?;
        let bytes = object.file.contents(&file)?;
        owners.push((&object.file, file, bytes));
    }
    let data = request.dataset.open()?;
    let data_bytes = request.dataset.contents(&data)?;
    owners.push((&request.dataset, data, data_bytes));
    let main = cstring(&request.main.file.path)?;
    let dataset = cstring(&request.dataset.path)?;
    let argv = [main.as_ptr(), dataset.as_ptr(), core::ptr::null()];
    let envp: [*const libc::c_char; 1] = [core::ptr::null()];
    // Require one main thread before fork: only async-signal-safe libc calls in
    // child. All strings, descriptor limits and request owners already exist.
    let threads = std::fs::read_dir("/proc/self/task")
        .map_err(io_error)?
        .count();
    if threads != 1 || Instant::now() >= deadline {
        return Err(Error::Shape);
    }
    require_child_free(child_wait()?)?;
    let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
    if unsafe { libc::sigaction(libc::SIGCHLD, core::ptr::null(), &mut action) } != 0
        || action.sa_sigaction != libc::SIG_DFL
        || action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err(Error::Child);
    }
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(Error::Io(errno()));
    }
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/null")
        .map_err(io_error)?;
    let m = null.metadata().map_err(io_error)?;
    if m.mode() & libc::S_IFMT != libc::S_IFCHR || m.rdev() != libc::makedev(1, 3) {
        return Err(Error::Shape);
    }
    let null_fd = null.as_raw_fd();
    for (pin, held, bytes) in &owners {
        if pin.contents(held)? != *bytes || pin.contents(&pin.open()?)? != *bytes {
            return Err(Error::Custody);
        }
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
    }
    let mut mapping_identities = Vec::with_capacity(objects.len());
    for (pin, held, _) in &owners[..objects.len()] {
        mapping_identities.push(calibrate_file(pin, held, deadline)?);
    }
    kernel_checkpoint(request.kernel_basis.as_ref(), deadline, evidence)?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::Io(errno()));
    }
    if pid == 0 {
        // Normal exec, no injected loader. Close all inherited descriptors; the
        // control writes no streams. Parent retains the package descriptors.
        unsafe {
            for fd in 0..3 {
                if libc::dup2(null_fd, fd) != fd || libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    libc::_exit(126);
                }
            }
            if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) != 0 {
                libc::_exit(126);
            }
            let mut mask = core::mem::zeroed::<libc::sigset_t>();
            if libc::sigemptyset(&mut mask) != 0
                || libc::sigprocmask(libc::SIG_SETMASK, &mask, core::ptr::null_mut()) != 0
            {
                libc::_exit(126);
            }
            let mut action = core::mem::zeroed::<libc::sigaction>();
            action.sa_sigaction = libc::SIG_DFL;
            if libc::sigemptyset(&mut action.sa_mask) != 0 {
                libc::_exit(126);
            }
            for signal in 1..=64 {
                // glibc hides32/33. Their separate raw reset and readback below
                // use the exact kernel layout in this owned post-fork child.
                if matches!(signal, libc::SIGKILL | libc::SIGSTOP | 32 | 33) {
                    continue;
                }
                if libc::sigaction(signal, &action, core::ptr::null_mut()) != 0 {
                    libc::_exit(126);
                }
            }
            if !reset_reserved_signals() {
                libc::_exit(126);
            }
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize) != 0 {
                libc::_exit(126);
            }
            if libc::raise(libc::SIGSTOP) != 0 {
                libc::_exit(126);
            }
            libc::execve(main.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(126);
        }
    }
    evidence.child_started = true;
    let child = Child {
        pid,
        deadline,
        reaped: Cell::new(false),
        cleanup_complete: Cell::new(false),
        cleanup_deadline: Cell::new(None),
        cleanup_evidence: RefCell::new(CleanupEvidence {
            direct_pid: Some(pid),
            ..CleanupEvidence::default()
        }),
    };
    let result = (|| {
        let mut machine = Machine::new();
        let status = child.wait()?;
        evidence.stops.push(StopEvidence {
            kind: "initial",
            status,
            siginfo: Vec::new(),
        });
        if !stopped(status, libc::SIGSTOP, 0) {
            return Err(Error::Event);
        }
        let (info, raw_info) = child.siginfo()?;
        evidence.stops.last_mut().ok_or(Error::Event)?.siginfo = raw_info;
        if info.si_signo != libc::SIGSTOP
            || info.si_code != libc::SI_TKILL
            || unsafe { info.si_pid() } != pid
        {
            return Err(Error::Event);
        }
        machine.advance(Event::InitialStop)?;
        child.ptrace(
            libc::PTRACE_SETOPTIONS,
            0,
            (libc::PTRACE_O_TRACEEXEC
                | libc::PTRACE_O_EXITKILL
                | libc::PTRACE_O_TRACESYSGOOD
                | libc::PTRACE_O_TRACEFORK
                | libc::PTRACE_O_TRACEVFORK
                | libc::PTRACE_O_TRACECLONE) as usize,
        )?;
        kernel_checkpoint(request.kernel_basis.as_ref(), deadline, evidence)?;
        child.continue_child()?;
        let status = child.wait()?;
        evidence.stops.push(StopEvidence {
            kind: "exec",
            status,
            siginfo: Vec::new(),
        });
        if !stopped(status, libc::SIGTRAP, libc::PTRACE_EVENT_EXEC) {
            return Err(Error::Event);
        }
        let mut old_pid = 0_u64;
        child.ptrace(
            libc::PTRACE_GETEVENTMSG,
            0,
            (&mut old_pid as *mut u64) as usize,
        )?;
        if old_pid != pid as u64 {
            return Err(Error::Event);
        }
        let exe = std::fs::metadata(format!("/proc/{pid}/exe")).map_err(io_error)?;
        if (exe.dev(), exe.ino()) != (request.main.file.device, request.main.file.inode) {
            return Err(Error::Custody);
        }
        evidence.exec_auxv = read_proc(pid, "auxv", 4096)?;
        let (entry, loader_bias) = secure_auxv(&evidence.exec_auxv)?;
        evidence.exec_status = read_proc(pid, "status", 65536)?;
        kernel_checkpoint(request.kernel_basis.as_ref(), deadline, evidence)?;
        request_shstk(&evidence.exec_status, request.kernel_basis.as_ref())?;
        controlled_signal_status(&evidence.exec_status)?;
        if entry != request.entry {
            return Err(Error::Entry);
        }
        evidence.exec_maps = read_proc(pid, "maps", MAP_CAP)?;
        let maps = parse_maps(&evidence.exec_maps)?;
        check_object(
            &child,
            &request.main,
            &maps,
            0,
            false,
            &mapping_identities[0],
        )?;
        check_object(
            &child,
            &request.loader,
            &maps,
            loader_bias,
            false,
            &mapping_identities[1],
        )?;
        if child.memory(entry, request.entry_bytes.len())? != request.entry_bytes {
            return Err(Error::Entry);
        }
        machine.advance(Event::ExecStop)?;
        let mut debug = DebugOwner::capture(&child)?;
        let observed = (|| {
            debug.arm(entry)?; // Before FIRST post-exec loader continuation.
            kernel_checkpoint(request.kernel_basis.as_ref(), deadline, evidence)?;
            child.continue_child()?;
            let status = child.wait()?;
            evidence.stops.push(StopEvidence {
                kind: "entry",
                status,
                siginfo: Vec::new(),
            });
            if child.reaped.get() {
                return Err(Error::Child);
            }
            if !stopped(status, libc::SIGTRAP, 0) {
                return Err(Error::Event);
            }
            let (info, raw_info) = child.siginfo()?;
            evidence.stops.last_mut().ok_or(Error::Event)?.siginfo = raw_info;
            if info.si_signo != libc::SIGTRAP
                || info.si_code != libc::TRAP_HWBKPT
                || unsafe { info.si_addr() } as usize as u64 != entry
            {
                return Err(Error::Event);
            }
            debug.event_at(entry)?;
            let regs = child.regs()?;
            evidence.entry_registers = unsafe {
                core::slice::from_raw_parts(
                    (&regs as *const libc::user_regs_struct).cast::<u8>(),
                    core::mem::size_of::<libc::user_regs_struct>(),
                )
            }
            .to_vec();
            evidence.entry_xstate = child.xstate(request.xstate_bytes)?;
            evidence.entry_status = read_proc(pid, "status", 65536)?;
            kernel_checkpoint(request.kernel_basis.as_ref(), deadline, evidence)?;
            request_shstk(&evidence.entry_status, request.kernel_basis.as_ref())?;
            controlled_signal_status(&evidence.entry_status)?;
            evidence.entry_auxv = read_proc(pid, "auxv", 4096)?;
            if secure_auxv(&evidence.entry_auxv)? != (entry, loader_bias) {
                return Err(Error::Entry);
            }
            if regs.rip != entry
                || regs.eflags & (1 << 8) != 0
                || child.memory(entry, request.entry_bytes.len())? != request.entry_bytes
            {
                return Err(Error::Entry);
            }
            stack_args(&child, regs.rsp, &main, &dataset)?;
            evidence.entry_maps = read_proc(pid, "maps", MAP_CAP)?;
            let maps = parse_maps(&evidence.entry_maps)?;
            check_object(
                &child,
                &request.main,
                &maps,
                0,
                true,
                &mapping_identities[0],
            )?;
            check_object(
                &child,
                &request.loader,
                &maps,
                loader_bias,
                true,
                &mapping_identities[1],
            )?;
            let bootstrap_bias =
                object_bias(&request.bootstrap, &maps, &mapping_identities[2], |row| {
                    mapping_target(child.pid, row)
                })?;
            check_object(
                &child,
                &request.bootstrap,
                &maps,
                bootstrap_bias,
                true,
                &mapping_identities[2],
            )?;
            for (index, object) in request.dependencies.iter().enumerate() {
                let identity = &mapping_identities[index + 3];
                check_object(
                    &child,
                    object,
                    &maps,
                    object_bias(object, &maps, identity, |row| {
                        mapping_target(child.pid, row)
                    })?,
                    true,
                    identity,
                )?;
            }
            let status_address = bootstrap_bias
                .checked_add(request.completion_relative)
                .ok_or(Error::Shape)?;
            let owner: Vec<_> = maps
                .iter()
                .filter(|m| {
                    m.start <= status_address
                        && status_address + 8 <= m.end
                        && m.permissions == *b"rw-p"
                })
                .collect();
            let declared: Vec<_> = request
                .bootstrap
                .pages
                .iter()
                .filter(|p| {
                    p.relative <= request.completion_relative
                        && request.completion_relative + 8 <= p.relative + 4096
                })
                .collect();
            if declared.len() != 1 {
                return Err(Error::Completion);
            }
            if owner.len() != 1 {
                return Err(Error::Completion);
            }
            if let Some(offset) = request.completion_file_offset {
                if owner[0].offset + status_address - owner[0].start != offset {
                    return Err(Error::Completion);
                }
            }
            let completion = u64::from_ne_bytes(
                child
                    .memory(status_address, 8)?
                    .try_into()
                    .map_err(|_| Error::Shape)?,
            );
            if completion != 1 {
                return Err(Error::Completion);
            }
            let registers = evidence.entry_registers.clone();
            let xstate = evidence.entry_xstate.clone();
            Ok((registers, xstate, completion, bootstrap_bias))
        })();
        let restored = if child.reaped.get() {
            Err(Error::Child)
        } else {
            debug.restore()
        };
        evidence.debug_restored = Some(restored.is_ok());
        evidence.restore_error = restored.as_ref().err().cloned();
        evidence.primary_error = observed.as_ref().err().cloned();
        restored?;
        let (registers, xstate, completion, bootstrap_bias) = observed?;
        machine.advance(Event::EntryTrap)?;
        // Do not continue the original entry. This startup control observes no
        // production route and no program output; cleanup deliberately kills it.
        for (pin, held, bytes) in &owners {
            if pin.contents(held)? != *bytes || pin.contents(&pin.open()?)? != *bytes {
                return Err(Error::Custody);
            }
        }
        kernel_checkpoint(request.kernel_basis.as_ref(), deadline, evidence)?;
        if request.kernel_basis.is_some() && evidence.kernel_checks != KERNEL_CHECKS {
            return Err(Error::Entry);
        }
        Ok(Observation {
            registers,
            xstate,
            completion,
            main_entry: entry,
            bootstrap_bias,
            stopped_before_main_execution: true,
            observer_killed_child: true,
            absence_echild: false,
            route_coverage_complete: false,
        })
    })();
    if evidence.primary_error.is_none() {
        evidence.primary_error = result.as_ref().err().cloned();
    }
    let cleanup = child.cleanup();
    evidence.absence_echild = child.cleanup_complete.get();
    evidence.cleanup = child.cleanup_evidence.borrow().clone();
    evidence.cleanup_error = cleanup.as_ref().err().cloned();
    cleanup?;
    let mut result = result?;
    if evidence.cleanup.terminal_statuses != [(pid, libc::SIGKILL)] {
        evidence.cleanup_error = Some(Error::Cleanup);
        return Err(Error::Cleanup);
    }
    result.absence_echild = true;
    Ok(result)
}

#[cfg(test)]
mod tests;
