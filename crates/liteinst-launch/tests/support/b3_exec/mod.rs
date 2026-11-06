//! Independent complete-state, source and physical-ownership helpers.
use liteinst_launch::gate::ImageFacts;
use liteinst_launch::{
    DynamicAdmissionBackend, DynamicAdmissionOptions, DynamicAdmissionState, DynamicExecProfile,
    KernelCapturedState, RegisterSnapshot,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(test)]
use std::os::unix::fs::FileExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[cfg(test)]
pub mod archive;
pub mod compare;
pub mod fixture;
pub mod raw;
#[cfg(test)]
pub mod run;
pub use fixture::Fixture;
pub const PAGE: usize = 4096;
pub const CODE: usize = 2 * PAGE;
pub const DATA_LEN: usize = 4 * PAGE;
pub const OLD: u64 = 0x400000;
pub const OLD_DATA: u64 = 0x600000;
pub const INPUT: u64 = 0x700000;
pub const NEW: u64 = 0x800000;
pub const NEW_DATA: u64 = 0xa00000;
pub const FLAGS: u64 = 0x202;
pub const APP_MASK: u64 = (1 << (libc::SIGUSR1 - 1)) | (1 << (libc::SIGUSR2 - 1));
const TRACER_MASK: u64 = !((1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)));
pub const TIMEOUT: Duration = Duration::from_secs(3);
static NEXT: AtomicUsize = AtomicUsize::new(0);
static FILE_FORK: RwLock<()> = RwLock::new(());
pub fn sp(base: u64) -> u64 {
    base + DATA_LEN as u64 - 128
}

/// Format the one diagnostic line every abort path in this support module
/// writes before dying. Pure so the format is unit-pinned; the abort itself
/// is exercised only by the hosted legs.
fn abort_line(site: &str, detail: &str, errno: i32, nofile: (u64, u64), nproc: usize) -> String {
    format!(
        "B3_ABORT site={site} errno={errno} detail={detail} nofile={}/{} nproc={nproc}\n",
        nofile.0, nofile.1
    )
}

/// Write [`abort_line`] to fd 2 unbuffered, then abort. A bare `abort()`
/// leaves no site evidence in CI logs: libtest captures per-test output
/// and the capture dies with the process. Every abort path in this module
/// names itself first; the abort conditions themselves are unchanged.
pub fn abort_named(site: &'static str, detail: &str) -> ! {
    // errno first: the getrlimit below would clobber it.
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let nofile = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } == 0 {
        (limits.rlim_cur, limits.rlim_max)
    } else {
        (0, 0)
    };
    let nproc = std::thread::available_parallelism().map_or(0, |n| n.get());
    let line = abort_line(site, detail, errno, nofile, nproc);
    let mut rest = line.as_bytes();
    while !rest.is_empty() {
        let written = unsafe { libc::write(2, rest.as_ptr().cast(), rest.len()) };
        if written <= 0 {
            break;
        }
        rest = &rest[written as usize..];
    }
    std::process::abort()
}

#[cfg(test)]
mod abort_named_tests {
    use super::abort_line;

    #[test]
    fn abort_line_names_site_errno_detail_limits_and_nproc() {
        assert_eq!(
            abort_line("pin-pidfd-open", "pid=42", 24, (1024, 1_048_576), 8),
            "B3_ABORT site=pin-pidfd-open errno=24 detail=pid=42 nofile=1024/1048576 nproc=8\n"
        );
        assert_eq!(
            abort_line("raw-worker-recv", "err=Disconnected", 0, (0, 0), 0),
            "B3_ABORT site=raw-worker-recv errno=0 detail=err=Disconnected nofile=0/0 nproc=0\n"
        );
    }
}

#[cfg(test)]
struct Mask(u64);
#[cfg(test)]
impl Mask {
    fn set(value: u64) -> Self {
        let mut previous = 0_u64;
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    &value,
                    &mut previous,
                    8,
                )
            },
            0
        );
        assert_eq!(mask(), value);
        Self(previous)
    }
}
#[cfg(test)]
impl Drop for Mask {
    fn drop(&mut self) {
        let restore = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &self.0,
                std::ptr::null_mut::<u64>(),
                8,
            )
        };
        let got = if restore == 0 { Some(mask()) } else { None };
        if got != Some(self.0) {
            abort_named(
                "mask-drop-restore",
                &format!("want={:#x} got={got:?} restore={restore}", self.0),
            );
        }
    }
}
fn mask() -> u64 {
    let mut value = 0_u64;
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &mut value,
                8,
            )
        },
        0
    );
    value
}
#[cfg(test)]
pub fn spawn_masked<T: Send + 'static>(
    action: impl FnOnce() -> T + Send + 'static,
) -> std::thread::JoinHandle<T> {
    let caller = Mask::set(TRACER_MASK);
    let worker = std::thread::spawn(move || {
        // Reblock libc-reserved signals before claiming an exclusive wait domain.
        let blocked = Mask::set(TRACER_MASK);
        let result = action();
        drop(blocked);
        result
    });
    drop(caller);
    worker
}

#[cfg(test)]
pub fn pin(pid: i32) -> OwnedFd {
    let value = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    // A successful session exists, but no independently owned pin guard yet.
    // Abort the validation command on allocation failure; never detach cleanup.
    if value < 0 {
        abort_named("pin-pidfd-open", &format!("pid={pid}"));
    }
    unsafe { OwnedFd::from_raw_fd(value as i32) }
}
pub fn duplicate(pin: &OwnedFd) -> OwnedFd {
    let fd = unsafe { libc::fcntl(pin.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    assert!(fd >= 0);
    unsafe { OwnedFd::from_raw_fd(fd) }
}
pub fn alive(pin: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 0);
    assert_eq!(poll.revents, 0);
}
pub fn gone(pin: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    (unsafe { libc::poll(&mut poll, 1, 0) }) == 1 && poll.revents == (libc::POLLIN | libc::POLLHUP)
}
pub fn reaped(pin: &OwnedFd) {
    assert!(gone(pin));
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pin.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Architecture {
    pub registers: RegisterSnapshot,
    pub xstate: Vec<u8>,
    pub mask: u64,
}
impl Architecture {
    pub fn captured(value: &KernelCapturedState) -> Self {
        Self {
            registers: value.registers,
            xstate: value.xstate.clone(),
            mask: value.signal_mask,
        }
    }
    pub fn admitted(value: &DynamicAdmissionState) -> Self {
        Self {
            registers: value.registers,
            xstate: value.xstate.clone(),
            mask: value.signal_mask,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Map {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub path: Option<String>,
    pub line: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Maps {
    pub raw: Vec<u8>,
    pub rows: Vec<Map>,
}
impl Maps {
    pub fn read(pid: i32, pin: &OwnedFd) -> Self {
        alive(pin);
        let file = File::open(format!("/proc/{pid}/maps")).unwrap();
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) }, 0);
        assert_eq!(stat.f_type, libc::PROC_SUPER_MAGIC);
        let mut raw = Vec::new();
        file.take(65537).read_to_end(&mut raw).unwrap();
        let result = Self::parse(raw);
        alive(pin);
        result
    }
    pub fn parse(raw: Vec<u8>) -> Self {
        Self::parse_bound(raw, 512)
    }
    /// Tracer-self observation only. All byte/grammar/order checks remain;
    /// the independent complete capture supplies its measured newline count.
    pub fn parse_self(raw: Vec<u8>, observed_rows: usize) -> Self {
        assert_eq!(
            raw.iter().filter(|&&byte| byte == b'\n').count(),
            observed_rows
        );
        let result = Self::parse_bound(raw, observed_rows);
        assert_eq!(result.rows.len(), observed_rows);
        result
    }
    fn parse_bound(raw: Vec<u8>, row_bound: usize) -> Self {
        assert!(!raw.is_empty() && raw.len() <= 65536 && raw.ends_with(b"\n") && !raw.contains(&0));
        let text = std::str::from_utf8(&raw).unwrap();
        let mut rows: Vec<Map> = Vec::new();
        for line in text.lines() {
            let mut cursor = 0;
            let mut column = || {
                while line
                    .as_bytes()
                    .get(cursor)
                    .is_some_and(u8::is_ascii_whitespace)
                {
                    cursor += 1;
                }
                let start = cursor;
                while line
                    .as_bytes()
                    .get(cursor)
                    .is_some_and(|b| !b.is_ascii_whitespace())
                {
                    cursor += 1;
                }
                assert!(start < cursor);
                &line[start..cursor]
            };
            let range = column().split_once('-').unwrap();
            let start = u64::from_str_radix(range.0, 16).unwrap();
            let end = u64::from_str_radix(range.1, 16).unwrap();
            let permissions = column().to_owned();
            let offset = u64::from_str_radix(column(), 16).unwrap();
            let device = column().to_owned();
            let inode = column().parse().unwrap();
            while line
                .as_bytes()
                .get(cursor)
                .is_some_and(u8::is_ascii_whitespace)
            {
                cursor += 1;
            }
            let path = (cursor < line.len()).then(|| line[cursor..].to_owned());
            assert!(start < end && start % PAGE as u64 == 0 && end % PAGE as u64 == 0);
            assert_eq!(permissions.len(), 4);
            let p = permissions.as_bytes();
            assert!(
                matches!(p[0], b'r' | b'-')
                    && matches!(p[1], b'w' | b'-')
                    && matches!(p[2], b'x' | b'-')
                    && matches!(p[3], b'p' | b's')
            );
            let dev = device.split_once(':').unwrap();
            let _ = u32::from_str_radix(dev.0, 16).unwrap();
            let _ = u32::from_str_radix(dev.1, 16).unwrap();
            assert!(rows.last().is_none_or(|old| old.end <= start));
            rows.push(Map {
                start,
                end,
                permissions,
                offset,
                device,
                inode,
                path,
                line: line.to_owned(),
            });
            assert!(rows.len() <= row_bound);
        }
        Self { raw, rows }
    }
    pub fn covering(&self, address: u64, count: usize) -> &Map {
        let end = address.checked_add(count as u64).unwrap();
        self.rows
            .iter()
            .find(|m| m.start <= address && end <= m.end)
            .unwrap()
    }
}
#[cfg(test)]
mod self_maps_parser_tests {
    use super::Maps;
    fn rows(count: usize) -> Vec<u8> {
        (0..count)
            .map(|n| {
                format!(
                    "{:x}-{:x} ---p 00000000 00:01 1 /owned\n",
                    0x1000 + n * 0x2000,
                    0x2000 + n * 0x2000
                )
            })
            .collect::<String>()
            .into_bytes()
    }
    #[test]
    fn self_capture_uses_actual_rows_but_child_still_refuses_513() {
        let bytes = rows(513);
        assert!(bytes.len() < 65536);
        assert_eq!(Maps::parse_self(bytes.clone(), 513).rows.len(), 513);
        assert!(std::panic::catch_unwind(|| Maps::parse(bytes)).is_err());
        assert_eq!(Maps::parse(rows(512)).rows.len(), 512);
    }
    #[test]
    fn self_capture_still_requires_exact_count_complete_bytes_and_order() {
        assert!(std::panic::catch_unwind(|| Maps::parse_self(rows(2), 1)).is_err());
        assert!(std::panic::catch_unwind(|| Maps::parse_self(rows(2), 3)).is_err());
        let mut incomplete = rows(2);
        incomplete.pop();
        assert!(std::panic::catch_unwind(|| Maps::parse_self(incomplete, 1)).is_err());
        let duplicated = [rows(1), rows(1)].concat();
        assert!(std::panic::catch_unwind(|| Maps::parse_self(duplicated, 2)).is_err());
        let oversized = rows(2000);
        assert!(oversized.len() > 65536);
        assert!(std::panic::catch_unwind(|| Maps::parse_self(oversized, 2000)).is_err());
    }
}
/// Independent non-controlling read by the client while the owner holds the
/// original pin. It supplies no ptrace capability and reads no retired mm.
#[cfg(test)]
pub fn held_memory(pid: i32, pin: &OwnedFd, address: u64, count: usize) -> Vec<u8> {
    assert!(count <= 65536);
    alive(pin);
    let file = File::open(format!("/proc/{pid}/mem")).unwrap();
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) }, 0);
    assert_eq!(stat.f_type, libc::PROC_SUPER_MAGIC);
    let mut bytes = vec![0; count];
    file.read_exact_at(&mut bytes, address).unwrap();
    alive(pin);
    bytes
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub architecture: Architecture,
    pub source: Vec<u8>,
    pub data: Vec<u8>,
    pub maps: Maps,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stack {
    pub start: u64,
    pub bytes: Vec<u8>,
    pub map: Map,
}

/// Cross-capture xstate equality via the production semantic predicate.
///
/// Use ONLY where the two sides come from different capture paths or
/// different processes (journal/production records vs the independent
/// raw reference trajectory). Same-record internal consistency asserts
/// must keep raw equality so BV representation drift within one
/// capture path is still caught. This adapter contains no component
/// logic of its own: the single definition is
/// `SavedExtendedStateLayout::xstate_semantic_eq` in liteinst.
pub fn assert_xstate_eq_cross_capture(a: &[u8], b: &[u8]) {
    assert_eq!(
        liteinst::trampoline::SavedExtendedStateLayout::xstate_semantic_eq(a, b),
        liteinst::trampoline::XstateSemanticEq::Equal,
        "cross-capture xstate differs beyond BV init-state representation"
    );
}

/// Cross-capture Architecture equality: registers and mask raw, xstate
/// semantic (see [`assert_xstate_eq_cross_capture`]).
pub fn assert_architecture_eq_cross_capture(a: &Architecture, b: &Architecture) {
    assert_eq!(a.registers, b.registers);
    assert_eq!(a.mask, b.mask);
    assert_xstate_eq_cross_capture(&a.xstate, &b.xstate);
}
