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

/// Establish that EL0 cache maintenance does not trap, without risking
/// the calling process: on AArch64 Linux a forked child runs the full
/// sync over its own anonymous page and the parent converts death by
/// signal into `CacheOpsUnavailable`. Call at initialization, before
/// extra threads exist (fork in a multithreaded process restricts the
/// child to async-signal-safe calls, which is all the child performs).
/// A passing probe says nothing about cross-core acknowledgement.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub fn probe_environment() -> Result<CacheAttested, PatchError> {
    let page = crate::page_size()?;
    // SAFETY: fork with an immediately-_exit-ing child that only calls
    // mmap/munmap/asm before exiting; no Rust allocation after fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(PatchError::os("fork"));
    }
    if pid == 0 {
        let len = page as usize;
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            unsafe { libc::_exit(2) };
        }
        let buf = p as *mut u8;
        unsafe { buf.write_volatile(0x1f) };
        let ok = unsafe { sync_icache(buf, buf, len) }.is_ok();
        unsafe { libc::_exit(if ok { 0 } else { 3 }) };
    }
    let mut status: libc::c_int = 0;
    // A signal may interrupt waitpid; retry so an interrupted probe
    // neither withholds attestation spuriously nor leaves the child
    // unreaped. A finished child guarantees this loop terminates.
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited >= 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(PatchError::Os {
                op: "waitpid",
                errno: err.raw_os_error().unwrap_or(0),
            });
        }
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
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

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn line_sizes_are_powers_of_two() {
        let lines = line_sizes().unwrap();
        assert!(lines.data.is_power_of_two() && lines.data >= 4);
        assert!(lines.instruction.is_power_of_two() && lines.instruction >= 4);
    }
}
