//! Mandatory nonzero history control. Only the separately exec-isolated test
//! predecessor changes SIGSEGV disposition. Neither launched application is
//! given a matching fault; both inherit the one independently observed tuple.
use super::*;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

pub const FAULT_PAGE: u64 = 0x900000;
pub const EXPECTED: Metadata = Metadata {
    trap: 14,
    error: 7,
    cr2: FAULT_PAGE,
};
const ENV_KEY: &str = "LITEINST_SIGNAL_PREDECESSOR";
const ENV_VALUE: &str = "owned-nonzero-v1";
const RECEIPT_PATH: &str = "LITEINST_SIGNAL_PREDECESSOR_RECEIPT";
const RECEIPT_DEVICE: &str = "LITEINST_SIGNAL_PREDECESSOR_RECEIPT_DEVICE";
const RECEIPT_INODE: &str = "LITEINST_SIGNAL_PREDECESSOR_RECEIPT_INODE";
const TEST: &str = "inherited_nonzero_exception_metadata_matches_pristine_original";
static SEEN: AtomicU64 = AtomicU64::new(0);
static TRAP: AtomicU64 = AtomicU64::new(0);
static ERROR: AtomicU64 = AtomicU64::new(0);
static ADDRESS: AtomicU64 = AtomicU64::new(0);

fn completed_bytes() -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    bytes[..8].copy_from_slice(b"LITSIG01");
    // Version, exact case, independently established tuple, physically cleaned
    // application lanes and final body-completion tag. No raw frame is exported.
    for (index, value) in [1_u64, 1, 14, 7, FAULT_PAGE, 2, 1].into_iter().enumerate() {
        bytes[8 + index * 8..16 + index * 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// The inherited invocation cannot count merely by exiting zero: only this
/// private exact-test body receives and authenticates the original sink.
pub struct Completion {
    file: std::fs::File,
}
impl Completion {
    pub fn inherited() -> Self {
        assert!(is_inner());
        let path = std::env::var_os(RECEIPT_PATH).expect("owned predecessor receipt path");
        let device = std::env::var(RECEIPT_DEVICE)
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let inode = std::env::var(RECEIPT_INODE)
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .unwrap();
        let stat = file.metadata().unwrap();
        assert!(stat.is_file());
        assert_eq!(stat.nlink(), 1);
        assert_eq!(stat.len(), 0);
        assert_eq!((stat.dev(), stat.ino()), (device, inode));
        Self { file }
    }
    /// Called only after the genuine predecessor and both complete lane owners
    /// have returned successfully; consuming self prevents a second receipt.
    pub fn finish(mut self, actual: Metadata) {
        assert_eq!(actual, EXPECTED);
        assert_eq!(self.file.write(&completed_bytes()).unwrap(), 64);
        assert_eq!(self.file.metadata().unwrap().len(), 64);
    }
}

std::arch::global_asm!(
    ".text",
    ".global liteinst_signal_predecessor_write",
    ".type liteinst_signal_predecessor_write,@function",
    "liteinst_signal_predecessor_write:",
    "mov rax, 0x900000",
    ".global liteinst_signal_predecessor_fault",
    "liteinst_signal_predecessor_fault:",
    "mov byte ptr [rax], 0x7f",
    ".global liteinst_signal_predecessor_after",
    "liteinst_signal_predecessor_after:",
    "ret",
    ".size liteinst_signal_predecessor_write,.-liteinst_signal_predecessor_write",
    ".global liteinst_signal_predecessor_restorer",
    ".type liteinst_signal_predecessor_restorer,@function",
    "liteinst_signal_predecessor_restorer:",
    "mov eax, 15",
    "syscall",
    "ud2",
    ".size liteinst_signal_predecessor_restorer,.-liteinst_signal_predecessor_restorer",
);
unsafe extern "C" {
    fn liteinst_signal_predecessor_write();
    fn liteinst_signal_predecessor_restorer();
    static liteinst_signal_predecessor_fault: u8;
    static liteinst_signal_predecessor_after: u8;
}
// No allocation, locks, libc handler, panic or production parser is called.
extern "C" fn handler(signal: i32, info: *mut libc::c_void, context: *mut libc::c_void) {
    unsafe {
        let info = info.cast::<u8>();
        let context = context.cast::<u8>();
        let read64 = |at: usize| std::ptr::read_unaligned(context.add(at).cast::<u64>());
        let pc = read64(UC_CONTEXT + SC_RIP);
        let trap = read64(UC_CONTEXT + SC_TRAP);
        let error = read64(UC_CONTEXT + SC_ERROR);
        let address = read64(UC_CONTEXT + SC_CR2);
        let valid = signal==libc::SIGSEGV
            && std::ptr::read_unaligned(info.cast::<i32>())==libc::SIGSEGV
            && std::ptr::read_unaligned(info.add(4).cast::<i32>())==0
            && std::ptr::read_unaligned(info.add(8).cast::<i32>())==2 // SEGV_ACCERR.
            && std::ptr::read_unaligned(info.add(16).cast::<u64>())==FAULT_PAGE
            && pc==(&raw const liteinst_signal_predecessor_fault) as u64
            && trap==14 && error==7 && address==FAULT_PAGE
            && SEEN.load(Ordering::SeqCst)==0;
        if !valid {
            libc::syscall(libc::SYS_exit_group, 125);
            return;
        }
        TRAP.store(trap, Ordering::SeqCst);
        ERROR.store(error, Ordering::SeqCst);
        ADDRESS.store(address, Ordering::SeqCst);
        SEEN.store(1, Ordering::SeqCst);
        std::ptr::write_unaligned(
            context.add(UC_CONTEXT + SC_RIP).cast::<u64>(),
            (&raw const liteinst_signal_predecessor_after) as u64,
        );
    }
}
pub fn is_inner() -> bool {
    std::env::var_os(ENV_KEY).as_deref() == Some(std::ffi::OsStr::new(ENV_VALUE))
}
pub fn establish() -> Metadata {
    assert!(is_inner());
    assert_eq!(SEEN.load(Ordering::SeqCst), 0);
    let fault = unsafe { &raw const liteinst_signal_predecessor_fault };
    let after = unsafe { &raw const liteinst_signal_predecessor_after };
    assert_eq!((after as usize) - (fault as usize), 3);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(fault, 3) },
        [0xc6, 0x00, 0x7f]
    );
    let blocked = Mask::set(TRACER_MASK);
    let page = unsafe {
        libc::mmap(
            FAULT_PAGE as *mut libc::c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    assert_eq!(
        page as u64, FAULT_PAGE,
        "fixed independent predecessor page"
    );
    unsafe { std::ptr::write_volatile(page.cast::<u8>(), 0x39) };
    assert_eq!(unsafe { libc::mprotect(page, PAGE, libc::PROT_READ) }, 0);
    let mut old = [0_u64; 4];
    let installed = [
        handler as *const () as u64,
        0x0400_0004,
        liteinst_signal_predecessor_restorer as *const () as u64,
        0,
    ];
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                libc::SIGSEGV,
                &raw const installed,
                &raw mut old,
                8_usize,
            )
        },
        0
    );
    let mut observed = [0_u64; 4];
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                libc::SIGSEGV,
                std::ptr::null::<u64>(),
                &raw mut observed,
                8_usize,
            )
        },
        0
    );
    assert_eq!(observed, installed);
    let unblocked = Mask::set(TRACER_MASK & !(1_u64 << (libc::SIGSEGV - 1)));
    unsafe { liteinst_signal_predecessor_write() }; // Actual write-protection PF.
    drop(unblocked);
    assert_eq!(SEEN.load(Ordering::SeqCst), 1);
    assert_eq!(unsafe { std::ptr::read_volatile(page.cast::<u8>()) }, 0x39);
    let actual = Metadata {
        trap: TRAP.load(Ordering::SeqCst),
        error: ERROR.load(Ordering::SeqCst),
        cr2: ADDRESS.load(Ordering::SeqCst),
    };
    assert_eq!(actual, EXPECTED);
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                libc::SIGSEGV,
                &raw const old,
                std::ptr::null_mut::<u64>(),
                8_usize,
            )
        },
        0
    );
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                libc::SIGSEGV,
                std::ptr::null::<u64>(),
                &raw mut observed,
                8_usize,
            )
        },
        0
    );
    assert_eq!(observed, old);
    assert_eq!(mask(), TRACER_MASK);
    assert_eq!(unsafe { libc::munmap(page, PAGE) }, 0);
    drop(blocked);
    actual
}

// A separate exec-isolated process is the sole owner of its changed SIGSEGV
// disposition. It uses the independently authored VM-reset assembly bootstrap,
// atomic process pin and private stack, with no release barrier for this exec.
struct Isolated {
    pid: i32,
    pin: OwnedFd,
    reaped: bool,
    _bootstrap: bootstrap::Resources,
}
impl Isolated {
    fn wait(&mut self, until: Instant) -> Option<i32> {
        loop {
            let mut status = 0;
            let got =
                unsafe { libc::waitpid(self.pid, &raw mut status, libc::__WALL | libc::WNOHANG) };
            if got == self.pid {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.reaped = true;
                    return Some(status);
                }
                return None;
            }
            if got < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return None;
            }
            if Instant::now() >= until {
                return None;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Isolated {
    fn drop(&mut self) {
        if !self.reaped {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pin.as_raw_fd(),
                    libc::SIGKILL,
                    0,
                    0,
                )
            };
            if self.wait(Instant::now() + TIMEOUT).is_none() {
                std::process::abort();
            }
        }
        // All inner lane workers explicitly clean/join before their test can
        // return or rethrow. The outer protocol independently rejects adoptees.
        reaped(&self.pin);
    }
}
pub fn isolated(directory: &std::path::Path) {
    assert!(!is_inner());
    let mask_guard = Mask::set(TRACER_MASK);
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut action) },
        0
    );
    assert_ne!(action.sa_sigaction, libc::SIG_IGN);
    assert_eq!(action.sa_flags & libc::SA_NOCLDWAIT, 0);
    let path = std::env::current_exe().unwrap();
    let receipt_path = directory.join("predecessor-completion.bin");
    let receipt = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&receipt_path)
        .unwrap();
    let stat = receipt.metadata().unwrap();
    assert!(stat.is_file());
    assert_eq!(stat.nlink(), 1);
    assert_eq!(stat.len(), 0);
    let environment = [
        format!("{ENV_KEY}={ENV_VALUE}"),
        "LC_ALL=C".to_owned(),
        format!("{RECEIPT_PATH}={}", receipt_path.to_str().unwrap()),
        format!("{RECEIPT_DEVICE}={}", stat.dev()),
        format!("{RECEIPT_INODE}={}", stat.ino()),
    ];
    let bootstrap = bootstrap::Resources::new(
        &path,
        &["--exact", TEST, "--nocapture", "--test-threads=1"],
        &environment,
        false,
    );
    let fork = FILE_FORK.lock().unwrap();
    let until = Instant::now() + TIMEOUT * 8;
    let (pid, pin) = bootstrap.spawn();
    let mut owner = Isolated {
        pid,
        pin,
        reaped: false,
        _bootstrap: bootstrap,
    };
    drop(fork);
    // This process-level wall bound covers both concurrently owned lane
    // startup/transaction/cleanup phases; it does not renew any lane deadline.
    let status = owner.wait(until);
    if status.is_none() {
        drop(owner);
        panic!("isolated predecessor deadline");
    }
    let status = status.unwrap();
    reaped(&owner.pin);
    assert_eq!(status, 0, "isolated nonzero-history assertion failure");
    assert!(
        Instant::now() < until,
        "isolated predecessor receipt deadline"
    );
    let mut bytes = Vec::new();
    receipt.take(65).read_to_end(&mut bytes).unwrap();
    assert_eq!(
        bytes,
        completed_bytes(),
        "exact inner body and cleanup receipt"
    );
    assert!(
        Instant::now() < until,
        "isolated predecessor receipt deadline"
    );
    drop(owner);
    drop(mask_guard);
}
