//! The tracee seam (internal and unstable): every request the remote
//! substrate (`remote`) makes of the traced thread it drives.
//!
//! [`Tracee`] carries register and memory access, the stop's
//! `siginfo`, the debug registers, the three resumptions (continue,
//! continue to the next syscall stop, single-step) and the wait for
//! the next stop. It carries nothing about what a system call means:
//! the substrate classifies every stop itself, from the raw wait
//! status, the registers and the `siginfo`.
//!
//! The in-crate implementation, `PtraceTracee`, is raw `ptrace(2)`,
//! `process_vm_readv(2)`/`process_vm_writev(2)` and `waitpid(2)` on
//! one pid: the requests the substrate made directly before this seam
//! existed, unchanged. The O1 oracle (`o1`) does not use this seam,
//! so that it stays independent of the code it checks.

/// The errno a failed request left, as the kernel reported it (0 if
/// the call failed without setting one).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Errno(pub i32);

impl Errno {
    /// The calling thread's errno now.
    fn last() -> Errno {
        Errno(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

/// One traced thread, as the remote substrate drives it.
///
/// What an implementation provides:
/// - every request addresses the same thread, and register, memory,
///   `siginfo`, debug-register and resume requests are made only
///   while it is in a ptrace-stop;
/// - a resume's `sig` is the signal to deliver, 0 for none, as the
///   `data` argument of `PTRACE_CONT`;
/// - [`Tracee::wait_stop`] returns the raw `waitpid(2)` status of the
///   thread's next state change, with syscall stops reported as
///   `SIGTRAP | 0x80` (`PTRACE_O_TRACESYSGOOD`);
/// - a memory request moves the whole buffer or fails, and callers
///   write only ranges the thread maps writable;
/// - a failed request returns the errno of the call that failed.
pub trait Tracee {
    /// The thread's id, for what the seam does not carry: the
    /// substrate's `/proc` reads, its own signals to the thread, and
    /// its checks that a guest call names this thread.
    fn pid(&self) -> i32;
    /// The general-purpose registers (`PTRACE_GETREGS`).
    fn get_regs(&self) -> Result<libc::user_regs_struct, Errno>;
    /// Replace the general-purpose registers (`PTRACE_SETREGS`).
    fn set_regs(&self, regs: &libc::user_regs_struct) -> Result<(), Errno>;
    /// Fill `buf` from the thread's memory at `addr`.
    fn read_mem(&self, addr: u64, buf: &mut [u8]) -> Result<(), Errno>;
    /// Write all of `buf` into the thread's memory at `addr`.
    fn write_mem(&self, addr: u64, buf: &[u8]) -> Result<(), Errno>;
    /// The stop's `siginfo` (`PTRACE_GETSIGINFO`).
    fn get_siginfo(&self) -> Result<libc::siginfo_t, Errno>;
    /// Replace the stop's `siginfo` (`PTRACE_SETSIGINFO`).
    fn set_siginfo(&self, info: &libc::siginfo_t) -> Result<(), Errno>;
    /// Debug register `n`, 0 to 7 (`PTRACE_PEEKUSER`).
    fn get_debugreg(&self, n: usize) -> Result<u64, Errno>;
    /// Set debug register `n`, 0 to 7 (`PTRACE_POKEUSER`).
    fn set_debugreg(&self, n: usize, value: u64) -> Result<(), Errno>;
    /// Resume until the next stop (`PTRACE_CONT`).
    fn cont(&self, sig: i32) -> Result<(), Errno>;
    /// Resume until the next stop, which may also be a syscall entry
    /// or exit stop (`PTRACE_SYSCALL`).
    fn cont_syscall(&self, sig: i32) -> Result<(), Errno>;
    /// Execute one instruction, then stop (`PTRACE_SINGLESTEP`).
    fn single_step(&self, sig: i32) -> Result<(), Errno>;
    /// Wait for the thread's next state change and return its raw
    /// wait status; an interrupted wait is retried.
    fn wait_stop(&self) -> Result<i32, Errno>;
}

/// The in-crate [`Tracee`]: raw `ptrace(2)` requests on a pid this
/// thread traces, `process_vm_readv(2)`/`process_vm_writev(2)` for
/// memory and `waitpid(2)` for stops.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PtraceTracee {
    pid: i32,
}

/// The `ptrace` request type of the target libc: glibc declares
/// `ptrace(c_uint, ...)` with `c_uint` `PTRACE_*` constants, musl
/// declares `ptrace(c_int, ...)` with `c_int` constants. Naming the
/// libc's own type lets call sites pass `PTRACE_*` constants with no
/// cast on either libc.
#[cfg(target_env = "musl")]
type PtraceRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type PtraceRequest = libc::c_uint;

fn ptrace(req: PtraceRequest, pid: i32, addr: *mut u8, data: *mut u8) -> i64 {
    // SAFETY: raw ptrace passthrough; callers pass valid operands
    // for the specific request.
    unsafe { libc::ptrace(req, pid, addr, data) }
}

fn ptrace_ok(req: PtraceRequest, pid: i32, addr: *mut u8, data: *mut u8) -> Result<(), Errno> {
    if ptrace(req, pid, addr, data) == 0 {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// `PTRACE_POKEUSER` offset of debug register `n`.
fn debugreg_offset(n: usize) -> usize {
    core::mem::offset_of!(libc::user, u_debugreg) + 8 * n
}

impl PtraceTracee {
    /// The thread `pid`, which the calling thread traces.
    pub(crate) fn new(pid: i32) -> PtraceTracee {
        PtraceTracee { pid }
    }

    /// `PTRACE_SETOPTIONS`. Part of the in-crate child's lifecycle,
    /// not of the seam.
    pub(crate) fn set_options(&self, options: libc::c_int) -> Result<(), Errno> {
        ptrace_ok(
            libc::PTRACE_SETOPTIONS,
            self.pid,
            core::ptr::null_mut(),
            options as usize as *mut u8,
        )
    }

    /// `PTRACE_KILL`, then reap; returns the reaped wait status. Both
    /// calls' results are ignored, as a teardown cannot act on them.
    /// Part of the in-crate child's lifecycle, not of the seam.
    pub(crate) fn kill_reap(&self) -> i32 {
        ptrace(
            libc::PTRACE_KILL,
            self.pid,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        let mut status: i32 = 0;
        // SAFETY: reaping our own traced child.
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);
        }
        status
    }
}

/// The attach-mode driver's tracee (test seams only): a [`Tracee`] over an
/// EXISTING traced pid, which the calling thread already traces (for
/// example a child that ran `PTRACE_TRACEME`). It performs no
/// `PTRACE_ATTACH` or `PTRACE_SEIZE`.
#[cfg(feature = "test-seams")]
#[derive(Clone, Copy, Debug)]
pub struct AttachTracee(pub(crate) PtraceTracee);

#[cfg(feature = "test-seams")]
impl AttachTracee {
    /// The traced thread `pid`, in a ptrace-stop, with
    /// `PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL` set, as the
    /// substrate's contract requires (syscall stops reported as
    /// `SIGTRAP | 0x80`; the thread killed if this tracer exits).
    /// It can fail only in `PTRACE_SETOPTIONS`.
    pub fn attach(pid: i32) -> Result<AttachTracee, Errno> {
        let inner = PtraceTracee::new(pid);
        inner.set_options(libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL)?;
        Ok(AttachTracee(inner))
    }
}

#[cfg(feature = "test-seams")]
impl Tracee for AttachTracee {
    fn pid(&self) -> i32 {
        self.0.pid()
    }
    fn get_regs(&self) -> Result<libc::user_regs_struct, Errno> {
        self.0.get_regs()
    }
    fn set_regs(&self, regs: &libc::user_regs_struct) -> Result<(), Errno> {
        self.0.set_regs(regs)
    }
    fn read_mem(&self, addr: u64, buf: &mut [u8]) -> Result<(), Errno> {
        self.0.read_mem(addr, buf)
    }
    fn write_mem(&self, addr: u64, buf: &[u8]) -> Result<(), Errno> {
        self.0.write_mem(addr, buf)
    }
    fn get_siginfo(&self) -> Result<libc::siginfo_t, Errno> {
        self.0.get_siginfo()
    }
    fn set_siginfo(&self, info: &libc::siginfo_t) -> Result<(), Errno> {
        self.0.set_siginfo(info)
    }
    fn get_debugreg(&self, n: usize) -> Result<u64, Errno> {
        self.0.get_debugreg(n)
    }
    fn set_debugreg(&self, n: usize, value: u64) -> Result<(), Errno> {
        self.0.set_debugreg(n, value)
    }
    fn cont(&self, sig: i32) -> Result<(), Errno> {
        self.0.cont(sig)
    }
    fn cont_syscall(&self, sig: i32) -> Result<(), Errno> {
        self.0.cont_syscall(sig)
    }
    fn single_step(&self, sig: i32) -> Result<(), Errno> {
        self.0.single_step(sig)
    }
    fn wait_stop(&self) -> Result<i32, Errno> {
        self.0.wait_stop()
    }
}

impl Tracee for PtraceTracee {
    fn pid(&self) -> i32 {
        self.pid
    }

    fn get_regs(&self) -> Result<libc::user_regs_struct, Errno> {
        let mut regs: libc::user_regs_struct = unsafe { core::mem::zeroed() };
        ptrace_ok(
            libc::PTRACE_GETREGS,
            self.pid,
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(regs).cast(),
        )?;
        Ok(regs)
    }

    fn set_regs(&self, regs: &libc::user_regs_struct) -> Result<(), Errno> {
        ptrace_ok(
            libc::PTRACE_SETREGS,
            self.pid,
            core::ptr::null_mut(),
            (regs as *const libc::user_regs_struct).cast_mut().cast(),
        )
    }

    fn read_mem(&self, addr: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let mut done = 0usize;
        while done < buf.len() {
            let local = libc::iovec {
                iov_base: buf[done..].as_mut_ptr().cast(),
                iov_len: buf.len() - done,
            };
            let remote = libc::iovec {
                iov_base: (addr + done as u64) as usize as *mut libc::c_void,
                iov_len: buf.len() - done,
            };
            // SAFETY: both iovecs describe the live remaining ranges.
            let n = unsafe { libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
            if n <= 0 {
                return Err(Errno::last());
            }
            done += n as usize;
        }
        Ok(())
    }

    fn write_mem(&self, addr: u64, buf: &[u8]) -> Result<(), Errno> {
        let mut done = 0usize;
        while done < buf.len() {
            let local = libc::iovec {
                iov_base: buf[done..].as_ptr().cast_mut().cast(),
                iov_len: buf.len() - done,
            };
            let remote = libc::iovec {
                iov_base: (addr + done as u64) as usize as *mut libc::c_void,
                iov_len: buf.len() - done,
            };
            // SAFETY: both iovecs describe the live remaining ranges;
            // the remote range is a writable child mapping by the
            // substrate setup contract.
            let n = unsafe { libc::process_vm_writev(self.pid, &local, 1, &remote, 1, 0) };
            if n <= 0 {
                return Err(Errno::last());
            }
            done += n as usize;
        }
        Ok(())
    }

    fn get_siginfo(&self) -> Result<libc::siginfo_t, Errno> {
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        ptrace_ok(
            libc::PTRACE_GETSIGINFO,
            self.pid,
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(info).cast(),
        )?;
        Ok(info)
    }

    fn set_siginfo(&self, info: &libc::siginfo_t) -> Result<(), Errno> {
        ptrace_ok(
            libc::PTRACE_SETSIGINFO,
            self.pid,
            core::ptr::null_mut(),
            (info as *const libc::siginfo_t).cast_mut().cast(),
        )
    }

    fn get_debugreg(&self, n: usize) -> Result<u64, Errno> {
        // SAFETY: errno is thread-local; cleared so a legitimate
        // all-ones value is told apart from a failed peek.
        unsafe { *libc::__errno_location() = 0 };
        let v = ptrace(
            libc::PTRACE_PEEKUSER,
            self.pid,
            debugreg_offset(n) as *mut u8,
            core::ptr::null_mut(),
        );
        // SAFETY: as above.
        let errno = unsafe { *libc::__errno_location() };
        if v != -1 || errno == 0 {
            Ok(v as u64)
        } else {
            Err(Errno(errno))
        }
    }

    fn set_debugreg(&self, n: usize, value: u64) -> Result<(), Errno> {
        ptrace_ok(
            libc::PTRACE_POKEUSER,
            self.pid,
            debugreg_offset(n) as *mut u8,
            value as usize as *mut u8,
        )
    }

    fn cont(&self, sig: i32) -> Result<(), Errno> {
        ptrace_ok(
            libc::PTRACE_CONT,
            self.pid,
            core::ptr::null_mut(),
            sig as usize as *mut u8,
        )
    }

    fn cont_syscall(&self, sig: i32) -> Result<(), Errno> {
        ptrace_ok(
            libc::PTRACE_SYSCALL,
            self.pid,
            core::ptr::null_mut(),
            sig as usize as *mut u8,
        )
    }

    fn single_step(&self, sig: i32) -> Result<(), Errno> {
        ptrace_ok(
            libc::PTRACE_SINGLESTEP,
            self.pid,
            core::ptr::null_mut(),
            sig as usize as *mut u8,
        )
    }

    fn wait_stop(&self) -> Result<i32, Errno> {
        loop {
            let mut status: i32 = 0;
            // SAFETY: waiting for our own traced child.
            let w = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if w == self.pid {
                return Ok(status);
            }
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINTR) {
                return Err(Errno(e.raw_os_error().unwrap_or(0)));
            }
        }
    }
}
