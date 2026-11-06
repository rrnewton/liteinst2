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

/// Reap exactly `pid`, retrying interruptions, with a bounded wait: on
/// timeout the child is killed and reaped before the error returns, so
/// no error path loses custody of the PID.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn reap_child(pid: libc::pid_t, timeout_ms: u64) -> Result<libc::c_int, PatchError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return Ok(status);
        }
        if waited < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                // Already reaped elsewhere: custody is discharged but
                // no status exists to attest from; caller refuses.
                return Err(PatchError::CacheOpsUnavailable);
            }
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(PatchError::Os {
                    op: "waitpid",
                    errno: err.raw_os_error().unwrap_or(0),
                });
            }
        }
        if std::time::Instant::now() >= deadline {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                let mut kill_status: libc::c_int = 0;
                while libc::waitpid(pid, &mut kill_status, 0) < 0 {
                    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                        break;
                    }
                }
            }
            return Err(PatchError::CacheOpsUnavailable);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
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
            let dfl: libc::sigaction = core::mem::zeroed();
            for sig in [
                libc::SIGILL,
                libc::SIGSEGV,
                libc::SIGBUS,
                libc::SIGTRAP,
                libc::SIGABRT,
            ] {
                libc::sigaction(sig, &dfl, core::ptr::null_mut());
            }
            let mut empty: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::pthread_sigmask(libc::SIG_SETMASK, &empty, core::ptr::null_mut());
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
    let mut byte = [0u8; 1];
    let got = loop {
        let n = unsafe { libc::read(fds[0], byte.as_mut_ptr() as *mut libc::c_void, 1) };
        if n >= 0 {
            break n;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break -1;
        }
    };
    unsafe { libc::close(fds[0]) };
    let status = reap_child(pid, 5_000)?;
    if probe_verdict(got == 1 && byte[0] == PROBE_MAGIC, status) {
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

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn line_sizes_are_powers_of_two() {
        let lines = line_sizes().unwrap();
        assert!(lines.data.is_power_of_two() && lines.data >= 4);
        assert!(lines.instruction.is_power_of_two() && lines.instruction >= 4);
    }
}
