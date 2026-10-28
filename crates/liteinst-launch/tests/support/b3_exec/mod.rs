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

struct Mask(u64);
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
impl Drop for Mask {
    fn drop(&mut self) {
        if unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &self.0,
                std::ptr::null_mut::<u64>(),
                8,
            )
        } != 0
            || mask() != self.0
        {
            std::process::abort();
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
        std::process::abort();
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
