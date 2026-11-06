//! Cache maintenance for AArch64 code publication: dual-alias
//! clean/invalidate and environment detection.
//!
//! Data-side cleans use the RW (written) addresses and instruction-side
//! invalidates use the RX (executed) addresses of the same backing
//! range, per the design note; the two ranges are never conflated.

use crate::PatchError;

/// Data and instruction cache line sizes in bytes, from CTR_EL0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineSizes {
    /// D-cache line size used for `DC CVAU` stepping.
    pub data: usize,
    /// I-cache line size used for `IC IVAU` stepping.
    pub instruction: usize,
}

/// Proof token that EL0 cache maintenance was established (probed or
/// attested) before any store. Zero-sized; construction outside this
/// crate is impossible.
#[derive(Debug, Clone, Copy)]
pub struct CacheAttested(());

/// Read CTR_EL0 line geometry. `PatchError::Unsupported` off AArch64.
#[cfg(target_arch = "aarch64")]
pub fn line_sizes() -> Result<LineSizes, PatchError> {
    let ctr: u64;
    // SAFETY: CTR_EL0 is readable at EL0 and the read has no effects.
    unsafe { std::arch::asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    Ok(LineSizes {
        data: 4usize << ((ctr >> 16) & 0xf),
        instruction: 4usize << (ctr & 0xf),
    })
}

/// Read CTR_EL0 line geometry. `PatchError::Unsupported` off AArch64.
#[cfg(not(target_arch = "aarch64"))]
pub fn line_sizes() -> Result<LineSizes, PatchError> {
    Err(PatchError::Unsupported("cache line sizes require AArch64"))
}

/// Clean the written range to the point of unification via its RW
/// addresses and invalidate the same range via its RX addresses:
/// `DC CVAU` over `[rw, rw+len)`, `DSB ISH`, `IC IVAU` over
/// `[rx, rx+len)`, `DSB ISH`, `ISB`. The final `ISB` synchronizes only
/// the calling core; consuming threads owe their own context-sync
/// acknowledgement on resume (design lease contract). A zero-length
/// range is a no-op on every target.
///
/// # Safety
/// `rw` and `rx` must name the same `len` bytes of one shared backing
/// (writable through `rw`, executable through `rx`), both valid for
/// the full range, with no concurrent writer. EL0 cache maintenance
/// must be permitted (see [`probe_environment`]); where it traps, this
/// faults in the caller instead of returning an error.
#[cfg(target_arch = "aarch64")]
pub unsafe fn sync_icache(rw: *mut u8, rx: *mut u8, len: usize) -> Result<(), PatchError> {
    use std::arch::asm;
    if len == 0 {
        return Ok(());
    }
    let lines = line_sizes()?;
    let clean = |base: *mut u8, step: usize, op: &str| -> Result<(), PatchError> {
        let start = base as usize;
        let end = start.checked_add(len).ok_or(PatchError::RangeOverflow)?;
        let mut addr = start & !(step - 1);
        while addr < end {
            match op {
                // SAFETY: caller guarantees the alias range is valid.
                "dc" => unsafe { asm!("dc cvau, {0}", in(reg) addr, options(nostack)) },
                _ => unsafe { asm!("ic ivau, {0}", in(reg) addr, options(nostack)) },
            }
            addr = addr.checked_add(step).ok_or(PatchError::RangeOverflow)?;
        }
        Ok(())
    };
    clean(rw, lines.data, "dc")?;
    // SAFETY: barriers have no memory operands.
    unsafe { asm!("dsb ish", options(nostack)) };
    clean(rx, lines.instruction, "ic")?;
    unsafe {
        asm!("dsb ish", options(nostack));
        asm!("isb", options(nostack));
    }
    Ok(())
}

/// Clean/invalidate a dual-alias range (see the AArch64 form).
/// `PatchError::Unsupported` off AArch64 for any nonzero length.
///
/// # Safety
/// Same alias contract as the AArch64 form; no memory is touched when
/// this returns `Unsupported`.
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn sync_icache(_rw: *mut u8, _rx: *mut u8, len: usize) -> Result<(), PatchError> {
    if len == 0 {
        return Ok(());
    }
    Err(PatchError::Unsupported(
        "instruction cache maintenance requires AArch64",
    ))
}

/// Completion byte the probe child writes only after its sync has
/// returned. Exit status alone never attests: an inherited fault
/// handler that exits 0 early cannot have written this byte after a
/// maintenance sequence it skipped, and the child additionally resets
/// fault dispositions to `SIG_DFL` so a real trap kills it by signal.
/// Consumed by the AArch64 probe (and Linux verdict/reap tests).
#[cfg(target_os = "linux")]
#[allow(dead_code)]
const PROBE_MAGIC: u8 = 0xa5;

/// Attestation verdict from the probe child's completion byte and wait
/// status. Both are required; either alone refuses.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn probe_verdict(got_magic: bool, status: libc::c_int) -> bool {
    got_magic && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// One nonblocking wait attempt: `Ok(Some(status))` reaped,
/// `Ok(None)` still running or a retryable wait error (custody keeps
/// priority over error fidelity; `last_errno` records the cause),
/// `Err(CacheOpsUnavailable)` only for genuine `ECHILD` discharge.
#[cfg(target_os = "linux")]
fn wait_once(pid: libc::pid_t) -> Result<Option<libc::c_int>, PatchError> {
    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if waited == pid {
        return Ok(Some(status));
    }
    if waited < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
        return Err(PatchError::CacheOpsUnavailable);
    }
    Ok(None)
}

/// Kill `pid` and discharge custody: retry reaping through any wait
/// error short of `ECHILD` (already discharged) until a second bounded
/// window expires, after which custody is reported retained by name
/// instead of being silently lost.
#[cfg(target_os = "linux")]
fn kill_and_discharge(pid: libc::pid_t) -> Result<(), PatchError> {
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match wait_once(pid) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(PatchError::CacheOpsUnavailable) => return Ok(()),
            Err(e) => return Err(e),
        }
        if std::time::Instant::now() >= deadline {
            return Err(PatchError::ChildCustodyRetained { pid });
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Reap exactly `pid` within `timeout_ms`. Any wait error other than
/// genuine `ECHILD` discharge is retried until the deadline (custody
/// outranks error fidelity); on timeout the child is killed and
/// discharged via [`kill_and_discharge`] before the timeout error
/// returns, so no path — timeout, injected wait error, or final-wait
/// error — returns while still silently owning a live PID.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn reap_child(pid: libc::pid_t, timeout_ms: u64) -> Result<libc::c_int, PatchError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        if let Some(status) = wait_once(pid)? {
            return Ok(status);
        }
        if std::time::Instant::now() >= deadline {
            kill_and_discharge(pid)?;
            return Err(PatchError::CacheOpsUnavailable);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Unified probe-parent custody loop: completion-byte acquisition and
/// exact-child status share ONE deadline, so a child stopped before
/// writing cannot block the parent past the reaper timeout (the prior
/// blocking-read bypass). On timeout or any hard poll/read/wait error
/// the child is killed and discharged before the error returns.
/// Returns `(got_magic, status)` only with custody fully discharged.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn collect_probe_child(
    pid: libc::pid_t,
    read_fd: libc::c_int,
    timeout_ms: u64,
) -> Result<(bool, libc::c_int), PatchError> {
    let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let e = PatchError::os("fcntl(O_NONBLOCK)");
        return match kill_and_discharge(pid) {
            Ok(()) => Err(e),
            Err(retained) => Err(retained),
        };
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let mut byte: Option<u8> = None;
    let mut eof = false;
    loop {
        if let Some(status) = match wait_once(pid) {
            Ok(s) => s,
            Err(e) => {
                // ECHILD discharge without a status: byte (if any) is
                // still readable from the pipe, but no status exists
                // to attest from.
                return Err(e);
            }
        } {
            // Reaped: drain one last byte already in the pipe buffer.
            if byte.is_none() && !eof {
                let mut b = [0u8; 1];
                let n = unsafe { libc::read(read_fd, b.as_mut_ptr() as *mut libc::c_void, 1) };
                if n == 1 {
                    byte = Some(b[0]);
                }
            }
            return Ok((byte == Some(PROBE_MAGIC), status));
        }
        if std::time::Instant::now() >= deadline {
            kill_and_discharge(pid)?;
            return Err(PatchError::CacheOpsUnavailable);
        }
        if !eof && byte.is_none() {
            let mut pfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pfd, 1, 10) };
            if ready < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                let e = PatchError::os("poll");
                return match kill_and_discharge(pid) {
                    Ok(()) => Err(e),
                    Err(retained) => Err(retained),
                };
            }
            if ready > 0 && pfd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let mut b = [0u8; 1];
                let n = unsafe { libc::read(read_fd, b.as_mut_ptr() as *mut libc::c_void, 1) };
                if n == 1 {
                    byte = Some(b[0]);
                } else if n == 0 {
                    eof = true;
                } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
                    // Spurious readiness; loop re-checks the child.
                } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    let e = PatchError::os("read(probe pipe)");
                    return match kill_and_discharge(pid) {
                        Ok(()) => Err(e),
                        Err(retained) => Err(retained),
                    };
                }
            }
        } else {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

/// Establish that EL0 cache maintenance does not trap, without risking
/// the calling process and without trusting inherited signal state:
/// the forked child resets fault dispositions to `SIG_DFL`, unblocks
/// signals, runs the full sync over its own anonymous page, writes a
/// completion byte, and exits; the parent attests only on the byte
/// plus a clean exit (see [`probe_verdict`]). Call at initialization,
/// before extra threads exist (the child performs only
/// async-signal-safe calls). A passing probe says nothing about
/// cross-core acknowledgement.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub fn probe_environment() -> Result<CacheAttested, PatchError> {
    let page = crate::page_size()?;
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(PatchError::os("pipe2"));
    }
    // SAFETY: fork with an immediately-_exit-ing child that only calls
    // sigaction/sigprocmask/mmap/write/asm before exiting; no Rust
    // allocation after fork in the child.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(PatchError::os("fork"));
    }
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            // Inherited handlers must not convert a maintenance fault
            // into a clean exit: default dispositions, empty mask.
            // Every setup result is required: a denied reset or unblock
            // exits (without the completion byte) before maintenance,
            // so an inherited skipping handler can neither survive the
            // reset nor publish the magic for skipped work.
            let dfl: libc::sigaction = core::mem::zeroed();
            for sig in [
                libc::SIGILL,
                libc::SIGSEGV,
                libc::SIGBUS,
                libc::SIGTRAP,
                libc::SIGABRT,
            ] {
                if libc::sigaction(sig, &dfl, core::ptr::null_mut()) != 0 {
                    libc::_exit(5);
                }
                let mut seen: libc::sigaction = core::mem::zeroed();
                if libc::sigaction(sig, core::ptr::null(), &mut seen) != 0 || seen.sa_sigaction != 0
                {
                    libc::_exit(5);
                }
            }
            let mut empty: libc::sigset_t = core::mem::zeroed();
            if libc::sigemptyset(&mut empty) != 0 {
                libc::_exit(5);
            }
            // pthread_sigmask returns the error number itself, not -1.
            if libc::pthread_sigmask(libc::SIG_SETMASK, &empty, core::ptr::null_mut()) != 0 {
                libc::_exit(5);
            }
            let len = page as usize;
            let p = libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                libc::_exit(2);
            }
            let buf = p as *mut u8;
            buf.write_volatile(0x1f);
            if sync_icache(buf, buf, len).is_err() {
                libc::_exit(3);
            }
            let magic = [PROBE_MAGIC];
            let written = libc::write(fds[1], magic.as_ptr() as *const libc::c_void, 1);
            libc::_exit(if written == 1 { 0 } else { 4 });
        }
    }
    unsafe { libc::close(fds[1]) };
    // One bounded custody protocol for byte + status (see collect).
    let collected = collect_probe_child(pid, fds[0], 5_000);
    unsafe { libc::close(fds[0]) };
    let (got_magic, status) = collected?;
    if probe_verdict(got_magic, status) {
        Ok(CacheAttested(()))
    } else {
        Err(PatchError::CacheOpsUnavailable)
    }
}

/// Establish cache-op availability (see the AArch64 Linux form).
/// `PatchError::Unsupported` anywhere else.
#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
pub fn probe_environment() -> Result<CacheAttested, PatchError> {
    Err(PatchError::Unsupported(
        "cache environment probe requires AArch64 Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_length_sync_is_a_noop_everywhere() {
        let mut byte = 0u8;
        let p = std::ptr::addr_of_mut!(byte);
        assert_eq!(unsafe { sync_icache(p, p, 0) }, Ok(()));
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[test]
    fn off_aarch64_surfaces_refuse() {
        assert!(matches!(line_sizes(), Err(PatchError::Unsupported(_))));
        assert!(matches!(
            probe_environment(),
            Err(PatchError::Unsupported(_))
        ));
        let mut byte = 0u8;
        let p = std::ptr::addr_of_mut!(byte);
        assert!(matches!(
            unsafe { sync_icache(p, p, 4) },
            Err(PatchError::Unsupported(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_verdict_requires_completion_byte_and_clean_exit() {
        // The inherited-handler forgery shape: exit 0 without the
        // post-sync completion byte must never attest.
        assert!(!probe_verdict(false, 0));
        assert!(probe_verdict(true, 0));
        // Signaled (SIGILL=4 in the low status byte) never attests,
        // with or without a byte.
        assert!(!probe_verdict(true, 4));
        assert!(!probe_verdict(false, 4));
        // Nonzero exit never attests.
        assert!(!probe_verdict(true, 3 << 8));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reap_child_reaps_exactly_and_times_out_with_custody() {
        // Fast child: status returned, custody discharged.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::_exit(7) };
        }
        let status = reap_child(pid, 5_000).unwrap();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 7);

        // Hanging child: timeout kills and reaps it; a second wait
        // proves no zombie custody was lost (ECHILD).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            loop {
                unsafe { libc::pause() };
            }
        }
        assert_eq!(reap_child(pid, 50), Err(PatchError::CacheOpsUnavailable));
        let mut status: libc::c_int = 0;
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(again, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[test]
    fn probe_environment_attests_on_this_host() {
        // Exercises the full fork/reset/sync/completion-byte/reap path
        // where EL0 maintenance is permitted (metal/guest runs).
        probe_environment().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stopped_child_collect_times_out_with_custody() {
        // The exact stopped-child watchdog scenario: a child stopped
        // before writing must not bypass the bounded reaper. Collect
        // must time out, kill, and discharge custody (ECHILD proof).
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(fds[0]);
                libc::raise(libc::SIGSTOP);
                loop {
                    libc::pause();
                }
            }
        }
        unsafe { libc::close(fds[1]) };
        let started = std::time::Instant::now();
        let result = collect_probe_child(pid, fds[0], 150);
        let elapsed = started.elapsed();
        unsafe { libc::close(fds[0]) };
        assert_eq!(result.unwrap_err(), PatchError::CacheOpsUnavailable);
        assert!(elapsed < std::time::Duration::from_secs(3), "{elapsed:?}");
        let mut status: libc::c_int = 0;
        let again = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(again, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn line_sizes_are_powers_of_two() {
        let lines = line_sizes().unwrap();
        assert!(lines.data.is_power_of_two() && lines.data >= 4);
        assert!(lines.instruction.is_power_of_two() && lines.instruction >= 4);
    }
}
