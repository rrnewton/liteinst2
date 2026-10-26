//! Independent fixture data, architecture snapshots and physical ownership.
//! No production map parser, source planner or selected completer is used.
use liteinst_launch::gate::{GateError, ImageFacts, SelectedExecution};
use liteinst_launch::selected::{
    InstructionProvider, ProviderDecision, SelectedInput, SemanticsError,
};
use liteinst_launch::{
    DynamicAdmissionEvent, DynamicAdmissionOptions, DynamicAdmissionSession, DynamicMappingProfile,
    DynamicSourceCaptureId, DynamicSourceFacts, DynamicSourceHeads, DynamicSourceRequest,
    DynamicSourceResolver, DynamicSourceSession, KernelProgressReader, LaunchCommand, LaunchError,
    RegisterSnapshot,
};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub mod fixture;
pub mod raw;
pub mod run;
pub use fixture::{Fixture, Kind};

pub const PAGE: usize = 4096;
pub const BASE: u64 = 0x400000;
pub const SOURCE_BYTES: usize = 2 * PAGE;
pub const DATA: u64 = 0x600000;
pub const DATA_BYTES: usize = 4 * PAGE;
pub const SP: u64 = DATA + DATA_BYTES as u64 - 128;
pub const TARGET: u64 = 0x900000;
pub const FLAGS: u64 = 0x202;
pub const APP_MASK: u64 = (1 << (libc::SIGUSR1 - 1)) | (1 << (libc::SIGUSR2 - 1));
const TRACER_MASK: u64 = !((1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)));
pub const TIMEOUT: Duration = Duration::from_secs(3);
static NEXT: AtomicUsize = AtomicUsize::new(0);
static FILE_FORK: Mutex<()> = Mutex::new(());

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
fn spawn_masked<T: Send + 'static>(
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

pub fn pin(pid: i32) -> OwnedFd {
    let value = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    // A successful session exists, but no independently owned pin guard yet.
    // Abort the validation command on allocation failure; never detach cleanup.
    if value < 0 {
        std::process::abort();
    }
    unsafe { OwnedFd::from_raw_fd(value as i32) }
}
fn duplicate(pin: &OwnedFd) -> OwnedFd {
    let fd = unsafe { libc::fcntl(pin.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    assert!(fd >= 0);
    unsafe { OwnedFd::from_raw_fd(fd) }
}
fn alive(pin: &OwnedFd) {
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
        assert_eq!(stat.f_type, 0x9fa0);
        let mut raw = Vec::new();
        file.take(65537).read_to_end(&mut raw).unwrap();
        let result = Self::parse(raw);
        alive(pin);
        result
    }
    pub fn parse(raw: Vec<u8>) -> Self {
        assert!(!raw.is_empty() && raw.len() <= 65536 && raw.ends_with(b"\n") && !raw.contains(&0));
        let text = std::str::from_utf8(&raw).unwrap(); // This owned ASCII-named fixture refuses other paths.
        let mut rows = Vec::new();
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let range = fields.next().unwrap().split_once('-').unwrap();
            let start = u64::from_str_radix(range.0, 16).unwrap();
            let end = u64::from_str_radix(range.1, 16).unwrap();
            let permissions = fields.next().unwrap().to_owned();
            let offset = u64::from_str_radix(fields.next().unwrap(), 16).unwrap();
            let device = fields.next().unwrap().to_owned();
            let inode = fields.next().unwrap().parse().unwrap();
            let path = fields.next().map(str::to_owned);
            assert!(
                fields.next().is_none(),
                "fixture maps path unexpectedly contains whitespace"
            );
            assert!(start < end && start % PAGE as u64 == 0 && end % PAGE as u64 == 0);
            assert_eq!(permissions.len(), 4);
            if let Some(previous) = rows.last() {
                let previous: &Map = previous;
                assert!(previous.end <= start);
            }
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
        }
        Self { raw, rows }
    }
    pub fn target(&self) -> Option<&Map> {
        let mut overlaps = self
            .rows
            .iter()
            .filter(|map| map.start < TARGET + PAGE as u64 && TARGET < map.end);
        let result = overlaps.next();
        assert!(overlaps.next().is_none());
        if let Some(map) = result {
            assert_eq!((map.start, map.end), (TARGET, TARGET + PAGE as u64));
        }
        result
    }
    pub fn outside(&self) -> Vec<Map> {
        self.rows
            .iter()
            .filter(|map| {
                !(map.start < BASE + SOURCE_BYTES as u64 && BASE < map.end)
                    && !(map.start < TARGET + PAGE as u64 && TARGET < map.end)
            })
            .cloned()
            .collect()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub architecture: Architecture,
    pub data: Vec<u8>,
    pub source: Vec<u8>,
    pub target: Option<Vec<u8>>,
    pub maps: Maps,
}

fn assert_literal(frame: &Frame, fixture: &Fixture) {
    let r = &frame.architecture.registers;
    let actual = [
        r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12,
        r.r13, r.r14, r.r15,
    ];
    let mut expected = std::array::from_fn::<u64, 16, _>(|n| 0x1234_5678_0000_0000 | n as u64);
    expected[0] = libc::SYS_mmap as u64;
    expected[2] = 3;
    expected[4] = SP;
    expected[6] = PAGE as u64;
    expected[7] = TARGET;
    expected[8] = u64::MAX;
    expected[9] = 0;
    expected[10] = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64;
    assert_eq!(actual, expected);
    assert_eq!(r.rip, fixture.sites[0].pc);
    assert_eq!(r.orig_rax, u64::MAX);
    assert_eq!(r.eflags, FLAGS);
    assert_eq!(
        [r.cs, r.ss, r.ds, r.es, r.fs, r.gs, r.fs_base, r.gs_base],
        [0x33, 0x2b, 0, 0, 0, 0, 0, 0]
    );
    let x = &frame.architecture.xstate;
    assert_eq!(&x[0..2], &0x37f_u16.to_le_bytes());
    assert_eq!(&x[2..4], &0x3800_u16.to_le_bytes());
    assert_eq!(x[4], 0x80);
    assert_eq!(&x[24..28], &0x1f80_u32.to_le_bytes());
    assert_eq!(&x[32..42], &[0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f]);
    assert_eq!(&x[160..176], &[0xff; 16]);
    assert_eq!(frame.architecture.mask, APP_MASK);
    assert_eq!(frame.data, fixture.expected_data());
    assert_eq!(frame.source, fixture.source);
    assert!(frame.target.is_none());
}
