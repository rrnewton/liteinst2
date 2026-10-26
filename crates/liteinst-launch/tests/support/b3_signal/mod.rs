//! Independent fixed-image asynchronous-signal oracle. Nothing here invokes
//! the production signal parser, metadata anchor or projection implementation.
mod bootstrap;
pub mod compare;
pub mod image;
pub mod predecessor;
pub mod raw;

use image::*;
use liteinst_launch::RegisterSnapshot;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_secs(3);
pub static FILE_FORK: Mutex<()> = Mutex::new(());
pub const TRACER_MASK: u64 = !((1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)));

/// Changes only the caller's raw eight-byte mask. Establish it BEFORE spawn,
/// including libc-reserved signals, then retain it on the tracer until cleanup.
pub struct Mask {
    old: u64,
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Mask {
    pub fn set(chosen: u64) -> Self {
        let mut old = 0_u64;
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    &raw const chosen,
                    &raw mut old,
                    8_usize,
                )
            },
            0
        );
        let guard = Self {
            old,
            _same_thread: std::marker::PhantomData,
        };
        assert_eq!(mask(), chosen);
        guard
    }
}
impl Drop for Mask {
    fn drop(&mut self) {
        let result = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &raw const self.old,
                std::ptr::null_mut::<u64>(),
                8_usize,
            )
        };
        let mut actual = 0;
        let read = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &raw mut actual,
                8_usize,
            )
        };
        if result != 0 || read != 0 || actual != self.old {
            std::process::abort();
        }
    }
}
pub fn mask() -> u64 {
    let mut actual = 0_u64;
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &raw mut actual,
                8_usize,
            )
        },
        0
    );
    actual
}
pub fn spawn_masked<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> std::thread::JoinHandle<T> {
    let blocked = Mask::set(TRACER_MASK);
    let thread = std::thread::spawn(move || {
        let retained = Mask::set(TRACER_MASK);
        assert_eq!(mask(), TRACER_MASK);
        let result = f();
        drop(retained);
        result
    });
    drop(blocked);
    thread
}
pub fn duplicate(fd: &OwnedFd) -> OwnedFd {
    let next = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    assert!(
        next >= 3,
        "duplicate original pidfd: {}",
        io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(next) }
}
pub fn pin_live(pid: i32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(
        fd >= 0,
        "pin held admission child: {}",
        io::Error::last_os_error()
    );
    let pin = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    live(&pin);
    pin
}
pub fn live(pin: &OwnedFd) {
    let mut p = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut p, 1, 0) }, 0);
    assert_eq!(p.revents, 0);
}
pub fn reaped(pin: &OwnedFd) {
    let mut p = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut p, 1, 0) }, 1);
    assert_eq!(p.revents, libc::POLLIN | libc::POLLHUP);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pin.as_raw_fd() as u32,
                &raw mut info,
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

/// Numeric process_vm_readv is bracketed by the original retained live pidfd.
/// This read-only observer never becomes a ptrace owner or reopens an identity.
pub fn memory(pid: i32, pin: &OwnedFd, address: u64, len: usize) -> Vec<u8> {
    assert!(len <= 1024 * 1024);
    address.checked_add(len as u64).unwrap();
    live(pin);
    let mut bytes = vec![0; len];
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: len,
    };
    assert_eq!(
        unsafe { libc::process_vm_readv(pid, &raw const local, 1, &raw const remote, 1, 0) },
        len as isize,
        "read pinned original memory: {}",
        io::Error::last_os_error()
    );
    live(pin);
    bytes
}
pub fn wait_ready(pid: i32, pin: &OwnedFd, until: Instant) {
    loop {
        let ready = memory(pid, pin, READY, 8) == READY_VALUE.to_le_bytes();
        assert!(Instant::now() < until, "original ready marker deadline");
        if ready {
            return;
        }
        assert!(Instant::now() < until, "original ready marker deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
}
pub fn signal_bytes() -> [u8; 128] {
    let mut bytes = [0_u8; 128];
    bytes[..4].copy_from_slice(&SIGNAL.to_ne_bytes());
    bytes[8..12].copy_from_slice(&libc::SI_QUEUE.to_ne_bytes());
    bytes[16..20].copy_from_slice(&(unsafe { libc::getpid() }).to_ne_bytes());
    bytes[20..24].copy_from_slice(&(unsafe { libc::getuid() }).to_ne_bytes());
    bytes[24..32].copy_from_slice(&PAYLOAD.to_ne_bytes());
    bytes
}
pub fn queue(pin: &OwnedFd, info: &[u8; 128]) {
    live(pin);
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pin.as_raw_fd(),
                SIGNAL,
                info.as_ptr(),
                0,
            )
        },
        0,
        "queue original signal: {}",
        io::Error::last_os_error()
    );
    live(pin);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub registers: RegisterSnapshot,
    pub xstate: Vec<u8>,
    pub mask: u64,
    pub data: Vec<u8>,
    pub normal: Vec<u8>,
    pub alternate: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub address: u64,
    pub fpstate: u64,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub trap: u64,
    pub error: u64,
    pub cr2: u64,
}

pub fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
pub fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
impl Frame {
    /// Independent Linux UAPI validation. The full contiguous frame through
    /// FP_XSTATE_MAGIC2 is retained, including every pad/reserved byte.
    pub fn from_state(state: &State, address: u64) -> Self {
        let (start, stack) = if (NORMAL..NORMAL + STACK_LEN as u64).contains(&address) {
            (NORMAL, &state.normal)
        } else {
            (ALT, &state.alternate)
        };
        let offset = usize::try_from(address.checked_sub(start).unwrap()).unwrap();
        let fixed = &stack[offset..offset + FRAME_FIXED];
        assert_eq!(address % 16, 8);
        assert_eq!(word(fixed, 0), RESTORER);
        let fpstate = word(fixed, FRAME_UC + UC_CONTEXT + SC_FP);
        assert_eq!(fpstate % 64, 0);
        let fp = usize::try_from(fpstate.checked_sub(start).unwrap()).unwrap();
        assert!(fp >= offset + FRAME_FIXED);
        assert_eq!(dword(stack, fp + 464), 0x4650_5853);
        let extended = dword(stack, fp + 468) as usize;
        let xstate = dword(stack, fp + 480) as usize;
        assert!((576..=64 * 1024).contains(&xstate));
        assert_eq!(extended, xstate + 4);
        let end = fp.checked_add(extended).unwrap();
        assert!(end <= stack.len());
        assert_eq!(dword(stack, end - 4), 0x4650_5845);
        assert_eq!(word(fixed, FRAME_UC), 7); // FP_XSTATE|SIGCONTEXT_SS|STRICT_RESTORE_SS.
        assert_eq!(word(fixed, FRAME_UC + 8), 0);
        assert_eq!(
            word(fixed, FRAME_UC + UC_CONTEXT + 144),
            0x002b_0000_0000_0033
        );
        Self {
            address,
            fpstate,
            bytes: stack[offset..end].to_vec(),
        }
    }
    pub fn metadata(&self) -> Metadata {
        let base = FRAME_UC + UC_CONTEXT;
        Metadata {
            trap: word(&self.bytes, base + SC_TRAP),
            error: word(&self.bytes, base + SC_ERROR),
            cr2: word(&self.bytes, base + SC_CR2),
        }
    }
}
