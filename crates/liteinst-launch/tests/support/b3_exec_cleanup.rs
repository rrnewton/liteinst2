//! Private exec-isolation support for local backing-resource controls.
//! Reuses the independent atomic-pidfd assembly bootstrap without a new codec.
use crate::exec_oracle_support::duplicate;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[cfg(test)]
#[path = "b3_signal/bootstrap.rs"]
pub mod bootstrap;
#[cfg(not(test))]
#[path = "b3_signal/bootstrap.rs"]
mod bootstrap;
const PAGE: usize = 4096;
const STACK_LEN: usize = 128 * 1024;
const TRACER_MASK: u64 = !((1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)));
const COMPLETE: u64 = 0x4241434b444f4e45;
const ABORT: u64 = 0x4241434b41425254;
static NEXT: AtomicU64 = AtomicU64::new(1);
fn mask() -> u64 {
    let mut value = 0_u64;
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &raw mut value,
                8_usize,
            )
        },
        0
    );
    value
}
struct Mask {
    old: u64,
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Mask {
    fn set() -> Self {
        let mut old = 0_u64;
        let requested = TRACER_MASK;
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    &raw const requested,
                    &raw mut old,
                    8_usize,
                )
            },
            0
        );
        let result = Self {
            old,
            _same_thread: std::marker::PhantomData,
        };
        assert_eq!(mask(), TRACER_MASK);
        result
    }
}
impl Drop for Mask {
    fn drop(&mut self) {
        let mut actual = 0_u64;
        let set = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &raw const self.old,
                std::ptr::null_mut::<u64>(),
                8_usize,
            )
        };
        let get = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &raw mut actual,
                8_usize,
            )
        };
        if set != 0 || get != 0 || actual != self.old {
            std::process::abort();
        }
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Child {
    pid: i32,
    pin: OwnedFd,
    until: Instant,
    reaped: bool,
    proven: bool,
    _resources: bootstrap::Resources,
}
impl Child {
    fn wait(&mut self) -> i32 {
        loop {
            let mut status = 0;
            let got = unsafe {
                libc::waitpid(
                    self.pid,
                    &raw mut status,
                    libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                )
            };
            if got == self.pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                self.reaped = true;
                crate::exec_oracle_support::reaped(&self.pin);
                assert!(
                    Instant::now() < self.until,
                    "isolated backing control deadline"
                );
                return status;
            }
            if got < 0 || Instant::now() >= self.until {
                panic!("isolated backing control did not finish");
            }
            std::thread::yield_now();
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.proven {
            return;
        }
        if self.reaped {
            std::process::abort();
        }
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pin.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        let error = if sent != 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        if sent != 0 && error != Some(libc::ESRCH) {
            std::process::abort();
        }
        loop {
            let mut status = 0;
            let got = unsafe {
                libc::waitpid(
                    self.pid,
                    &raw mut status,
                    libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
                )
            };
            if got == self.pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                self.reaped = true;
                break;
            }
            if got < 0 || Instant::now() >= self.until {
                std::process::abort();
            }
            std::thread::yield_now();
        }
        // No fallible assertion can unwind past unreaped child ownership.
        let mut p = libc::pollfd {
            fd: self.pin.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&raw mut p, 1, 0) } != 1
            || p.revents != (libc::POLLIN | libc::POLLHUP)
        {
            std::process::abort();
        }
        // Direct-child reap cannot replace the missing connected-owner receipt.
        // Stop this validation command so its outer custodian handles failure.
        std::process::abort();
    }
}
fn receipt_file() -> File {
    let path = std::env::var_os("LITEINST_BACKING_RECEIPT").unwrap();
    let expected_dev: u64 = std::env::var("LITEINST_BACKING_DEVICE")
        .unwrap()
        .parse()
        .unwrap();
    let expected_inode: u64 = std::env::var("LITEINST_BACKING_INODE")
        .unwrap()
        .parse()
        .unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .unwrap();
    let stat = file.metadata().unwrap();
    assert!(stat.is_file());
    assert_eq!(
        (stat.dev(), stat.ino(), stat.nlink(), stat.len()),
        (expected_dev, expected_inode, 1, 0)
    );
    file
}
/// Closed child roles; no arbitrary entry or native authority is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Complete,
    ReadError,
    Unwind,
    InvalidUnmap,
    QueryError,
    Legacy,
}
impl Role {
    fn id(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ReadError => "read_error",
            Self::Unwind => "unwind",
            Self::InvalidUnmap => "invalid_unmap",
            Self::QueryError => "query_error",
            Self::Legacy => "legacy",
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Complete => 0,
            Self::ReadError => 1,
            Self::Unwind => 2,
            Self::InvalidUnmap => 3,
            Self::QueryError => 4,
            Self::Legacy => 5,
        }
    }
    fn probes(self) -> u64 {
        if matches!(self, Self::Complete | Self::Legacy) {
            6
        } else {
            1
        }
    }
    fn errno(self) -> u64 {
        match self {
            Self::ReadError | Self::QueryError => libc::EFAULT as u64,
            Self::InvalidUnmap => libc::EINVAL as u64,
            _ => 0,
        }
    }
    fn parse(text: &str) -> Self {
        match text {
            "complete" => Self::Complete,
            "read_error" => Self::ReadError,
            "unwind" => Self::Unwind,
            "invalid_unmap" => Self::InvalidUnmap,
            "query_error" => Self::QueryError,
            "legacy" => Self::Legacy,
            _ => panic!("unknown backing child role"),
        }
    }
}
const ROLES: [Role; 6] = [
    Role::Complete,
    Role::ReadError,
    Role::Unwind,
    Role::InvalidUnmap,
    Role::QueryError,
    Role::Legacy,
];
const PREFIX: &str = "LITEINST_BACKING_CLEANUP_V1 ";

/// Actual thread-group inventory, joined to the no-CLONE_VM/no-new-worker
/// production callgraph. This does not claim to enumerate external mm sharers.
pub(crate) fn assert_main_singleton() {
    let pid = unsafe { libc::syscall(libc::SYS_getpid) };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    assert!(pid > 0);
    assert_eq!(pid, tid);
    assert_eq!(mask(), TRACER_MASK);
    let fd = unsafe {
        libc::open(
            c"/proc/self/task".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    assert!(fd >= 0);
    let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::fstatfs(descriptor.as_raw_fd(), &raw mut fs) },
        0
    );
    assert_eq!(fs.f_type, libc::PROC_SUPER_MAGIC);
    let mut buffer = [0_u8; PAGE];
    let mut tasks = 0;
    let mut eof = false;
    for _ in 0..4 {
        let got = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                descriptor.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        assert!(got >= 0 && got as usize <= buffer.len());
        if got == 0 {
            eof = true;
            break;
        }
        let mut cursor = 0;
        while cursor < got as usize {
            let row = &buffer[cursor..got as usize];
            assert!(row.len() >= 20);
            let length = usize::from(u16::from_ne_bytes(row[16..18].try_into().unwrap()));
            assert!(length >= 20 && length <= row.len());
            let name = &row[19..length];
            let end = name.iter().position(|byte| *byte == 0).unwrap();
            let name = &name[..end];
            if name != b"." && name != b".." {
                assert_eq!(row[18], libc::DT_DIR);
                assert!(!name.is_empty());
                let observed = name
                    .iter()
                    .try_fold(0_i64, |value, byte| {
                        byte.is_ascii_digit().then_some(())?;
                        value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))
                    })
                    .unwrap();
                assert_eq!(observed, tid);
                tasks += 1;
                assert_eq!(tasks, 1);
            }
            cursor += length;
        }
    }
    assert!(eof);
    assert_eq!(tasks, 1);
    // Close before any native backing release/absence interval begins.
    use std::os::fd::IntoRawFd;
    assert_eq!(unsafe { libc::close(descriptor.into_raw_fd()) }, 0);
}

/// Only this fixed entry is reached by the development bridge.
pub(crate) fn main(action: fn(Role, &File)) -> std::process::ExitCode {
    let result = std::panic::catch_unwind(|| dispatch(action));
    if result.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
fn dispatch(action: fn(Role, &File)) {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let _blocked = Mask::set();
    assert_main_singleton();
    if args.first().is_some_and(|arg| arg == "--cleanup-child") {
        assert_eq!(args.len(), 2);
        let role = Role::parse(&args[1]);
        let file = receipt_file();
        action(role, &file);
        assert_ne!(role, Role::InvalidUnmap, "abort leaf must not return");
        let words = [
            COMPLETE,
            role.index() as u64,
            role.probes(),
            role.errno(),
            1,
            0,
            0,
            0,
        ];
        assert_eq!(
            unsafe {
                libc::write(
                    file.as_raw_fd(),
                    words.as_ptr().cast(),
                    std::mem::size_of_val(&words),
                )
            },
            64
        );
        return;
    }
    assert!(args.is_empty() || args == ["--test-threads=1", "--nocapture"]);
    println!(
        "{PREFIX}{{\"schema_version\":1,\"kind\":\"begin\",\"controls\":5,\"trajectories\":6}}"
    );
    for role in ROLES {
        run_child(role);
        let (control, outcome, terminal) = match role {
            Role::Complete => (
                "admitted_exec_native_backing_probes_close_exact_owned_resources",
                "complete",
                "exit0",
            ),
            Role::ReadError => (
                "admitted_exec_native_backing_read_and_unwind_preserve_cleanup",
                "native_read_error",
                "exit0",
            ),
            Role::Unwind => (
                "admitted_exec_native_backing_read_and_unwind_preserve_cleanup",
                "injected_unwind",
                "exit0",
            ),
            Role::QueryError => (
                "admitted_exec_native_backing_query_preserves_cleanup",
                "native_query_error",
                "exit0",
            ),
            Role::Legacy => (
                "admitted_exec_native_backing_enotty_uses_exact_legacy_projection",
                "native_enotty_fallback",
                "exit0",
            ),
            Role::InvalidUnmap => (
                "exec_backing_native_invalid_unmap_aborts_isolated_owner",
                "expected_fail_stop",
                "sigabrt",
            ),
        };
        println!(
            "{PREFIX}{{\"schema_version\":1,\"kind\":\"trajectory\",\"index\":{},\"id\":\"{}\",\"control\":\"{}\",\"outcome\":\"{}\",\"probes\":{},\"errno\":{},\"terminal\":\"{}\",\"owner_cleanup\":{},\"physical_cleanup\":true,\"receipt_authenticated\":true}}",
            role.index(),
            role.id(),
            control,
            outcome,
            role.probes(),
            role.errno(),
            terminal,
            role != Role::InvalidUnmap
        );
    }
    println!(
        "{PREFIX}{{\"schema_version\":1,\"kind\":\"complete\",\"controls\":5,\"trajectories\":6,\"physical_cleanup\":true}}"
    );
}
fn run_child(role: Role) {
    let budget = if role == Role::InvalidUnmap {
        crate::exec_oracle_support::TIMEOUT
    } else {
        6 * crate::exec_oracle_support::TIMEOUT
    };
    let until = Instant::now() + budget;
    let path = std::env::temp_dir().join(format!(
        "liteinst-backing-control-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    let _directory = Directory(path.clone());
    let receipt = path.join("receipt");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&receipt)
        .unwrap();
    let stat = file.metadata().unwrap();
    assert!(stat.is_file());
    assert_eq!((stat.nlink(), stat.len()), (1, 0));
    let environment = [
        "LC_ALL=C".to_owned(),
        format!("LITEINST_BACKING_RECEIPT={}", receipt.to_str().unwrap()),
        format!("LITEINST_BACKING_DEVICE={}", stat.dev()),
        format!("LITEINST_BACKING_INODE={}", stat.ino()),
    ];
    let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut disposition) },
        0
    );
    assert_ne!(disposition.sa_sigaction, libc::SIG_IGN);
    assert_eq!(disposition.sa_flags & libc::SA_NOCLDWAIT, 0);
    let resources = bootstrap::Resources::new(
        &std::env::current_exe().unwrap(),
        &["--cleanup-child", role.id()],
        &environment,
        false,
    );
    assert!(Instant::now() < until);
    let fork = crate::TEST_FILE_FORK.lock().unwrap();
    assert!(
        Instant::now() < until,
        "isolated backing control pre-clone deadline"
    );
    let (pid, pin) = resources.spawn();
    let mut child = Child {
        pid,
        pin,
        until,
        reaped: false,
        proven: false,
        _resources: resources,
    };
    drop(fork);
    let status = child.wait();
    if role == Role::InvalidUnmap {
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
    } else {
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.take(65).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len(), 64);
    let words = std::array::from_fn::<_, 8, _>(|i| {
        u64::from_ne_bytes(bytes[i * 8..][..8].try_into().unwrap())
    });
    if role == Role::InvalidUnmap {
        assert_eq!(words[0], ABORT);
        assert_eq!(words[1], 3);
        assert!(words[2] != 0 && words[2] % PAGE as u64 == 0);
        assert_eq!(words[3], words[2].checked_add(1).unwrap());
        assert_eq!(words[4], PAGE as u64);
        assert_eq!(words[5] as i64, -1);
        assert_eq!(words[6], libc::EINVAL as u64);
        assert_eq!(words[7], 7);
    } else {
        assert_eq!(
            words,
            [
                COMPLETE,
                role.index() as u64,
                role.probes(),
                role.errno(),
                1,
                0,
                0,
                0
            ]
        );
    }
    assert!(Instant::now() < until);
    child.proven = true;
}
/// Child-local policy; no process-global parent mutation or native fake result.
pub fn prepare_abort() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) },
        0
    );
    let mut actual: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut actual) },
        0
    );
    assert_eq!((actual.rlim_cur, actual.rlim_max), (0, 0));
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGABRT, std::ptr::null(), &raw mut action) },
        0
    );
    assert_eq!(action.sa_sigaction, libc::SIG_DFL);
}
