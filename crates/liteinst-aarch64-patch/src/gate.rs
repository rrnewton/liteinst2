//! The syscall gate: every OS call this crate makes goes through
//! one replaceable raw-syscall entry, so an embedding runtime whose
//! filter admits syscalls only from its trusted gate address (the
//! in-guest exact-address filter) can route them there. With no
//! gate installed, calls execute directly (`svc`/`syscall`
//! instruction at the call site), which is the correct behavior
//! for host processes and tests — and a trap inside a filtered
//! guest, which is why in-guest embeddings MUST install their
//! gate before any other call into this crate.

use crate::PatchError;

/// A raw six-argument syscall entry. Returns the kernel's raw
/// result (`-errno` on failure), exactly like the architecture's
/// syscall instruction leaves it.
///
/// # Safety
/// Implementations must issue exactly the named syscall with the
/// given arguments (through whatever whitelisted gate the embedding
/// requires) and nothing else. Callers in this crate rely on raw
/// `-errno` results, not `errno` thread-local state.
pub unsafe trait GateSyscall: Send + Sync {
    /// Issue syscall `nr` with `args`; raw kernel result.
    ///
    /// # Safety
    /// Same contract as the syscall itself: argument validity is
    /// the caller's (this crate's) responsibility.
    unsafe fn syscall6(&self, nr: i64, args: [u64; 6]) -> i64;
}

struct DirectGate;

// SAFETY: issues exactly the named syscall with the given args via
// the architecture instruction; no other observable effect.
unsafe impl GateSyscall for DirectGate {
    unsafe fn syscall6(&self, nr: i64, args: [u64; 6]) -> i64 {
        // SAFETY: forwarded to the arch entry with the same contract.
        unsafe { direct_syscall6(nr, args) }
    }
}

static DIRECT: DirectGate = DirectGate;
static INSTALLED: std::sync::OnceLock<&'static dyn GateSyscall> = std::sync::OnceLock::new();

/// Install the process-wide syscall gate (once). In-guest embeddings
/// call this before any other entry into this crate, with an
/// implementation that forwards to their trusted gate (the
/// instruction address their filter admits). Returns
/// `PatchError::Unsupported` if a different gate is already
/// installed; re-installing the same gate value is a no-op success.
///
/// # Safety
/// `gate` must keep the [`GateSyscall`] contract for the rest of
/// the process lifetime; concurrent in-flight calls during
/// installation are the caller's to exclude (install at init).
pub unsafe fn install_gate(gate: &'static dyn GateSyscall) -> Result<(), PatchError> {
    match INSTALLED.set(gate) {
        Ok(()) => Ok(()),
        Err(_) => {
            let existing = INSTALLED.get().expect("set failed but empty");
            if core::ptr::addr_eq(*existing, gate) {
                Ok(())
            } else {
                Err(PatchError::Unsupported(
                    "a different syscall gate is already installed",
                ))
            }
        }
    }
}

fn current() -> &'static dyn GateSyscall {
    INSTALLED.get().copied().unwrap_or(&DIRECT)
}

/// Issue one syscall through the installed (or direct) gate.
///
/// # Safety
/// Same contract as the syscall itself.
pub unsafe fn gate6(nr: i64, args: [u64; 6]) -> i64 {
    // SAFETY: forwarded under the caller's contract.
    unsafe { current().syscall6(nr, args) }
}

/// Map a raw gate result to `Ok(result)` or a named OS error.
pub fn check(ret: i64, op: &'static str) -> Result<i64, PatchError> {
    if (-4095..0).contains(&ret) {
        Err(PatchError::Os {
            op,
            errno: (ret.wrapping_neg()) as i32,
        })
    } else {
        Ok(ret)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe fn direct_syscall6(nr: i64, args: [u64; 6]) -> i64 {
    let ret: i64;
    // SAFETY: svc #0 with x8=nr, x0-x5=args; result in x0. Memory
    // effects are the syscall's own, per the caller's contract.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") args[0] as i64 => ret,
            in("x1") args[1],
            in("x2") args[2],
            in("x3") args[3],
            in("x4") args[4],
            in("x5") args[5],
            options(nostack)
        );
    }
    ret
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
unsafe fn direct_syscall6(nr: i64, args: [u64; 6]) -> i64 {
    let ret: i64;
    // SAFETY: syscall with rax=nr, rdi/rsi/rdx/r10/r8/r9=args;
    // rcx/r11 clobbered by the instruction. Memory effects are the
    // syscall's own, per the caller's contract.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    ret
}

#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "linux"),
    all(target_arch = "x86_64", target_os = "linux")
)))]
unsafe fn direct_syscall6(nr: i64, args: [u64; 6]) -> i64 {
    // SAFETY: libc's variadic syscall forwards the same contract.
    unsafe {
        libc::syscall(
            nr as libc::c_long,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
        ) as i64
    }
}

/// Monotonic milliseconds through the gate. Deadline arithmetic in
/// custody loops uses this (plus an iteration cap), never
/// `Instant::now` (an ungated libc clock call).
#[cfg(target_os = "linux")]
pub fn now_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out pointer for the call.
    let ret = unsafe {
        gate6(
            libc::SYS_clock_gettime,
            [
                libc::CLOCK_MONOTONIC as u64,
                core::ptr::addr_of_mut!(ts) as u64,
                0,
                0,
                0,
                0,
            ],
        )
    };
    if ret != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((ts.tv_nsec as u64) / 1_000_000)
}

/// Sleep `ms` milliseconds through the gate (EINTR-resumed).
#[cfg(target_os = "linux")]
pub fn sleep_ms(ms: u64) {
    let mut req = libc::timespec {
        tv_sec: (ms / 1000) as _,
        tv_nsec: ((ms % 1000) * 1_000_000) as _,
    };
    loop {
        let mut rem = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: req/rem are valid timespec pointers for the call.
        let ret = unsafe {
            gate6(
                libc::SYS_clock_nanosleep,
                [
                    libc::CLOCK_MONOTONIC as u64,
                    0,
                    core::ptr::addr_of!(req) as u64,
                    core::ptr::addr_of_mut!(rem) as u64,
                    0,
                    0,
                ],
            )
        };
        if ret == 0 {
            return;
        }
        if ret != -(libc::EINTR as i64) {
            return;
        }
        req = rem;
    }
}

/// `getpid` through the gate (fork checks must not use libc's
/// cached or wrapper-mediated value paths).
pub fn getpid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: getpid takes no arguments and cannot fail.
        unsafe { gate6(libc::SYS_getpid, [0; 6]) as u32 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_gate_getpid_matches_process_id() {
        assert_eq!(getpid(), std::process::id());
        // Raw -errno mapping: an invalid fd close is -EBADF.
        let ret = unsafe { gate6(libc::SYS_close, [u64::MAX - 1, 0, 0, 0, 0, 0]) };
        assert_eq!(
            check(ret, "close"),
            Err(PatchError::Os {
                op: "close",
                errno: libc::EBADF
            })
        );
    }

    #[cfg(target_os = "linux")]
    struct CountingGate {
        total: std::sync::atomic::AtomicU64,
        clocks: std::sync::atomic::AtomicU64,
        waits: std::sync::atomic::AtomicU64,
        clones: std::sync::atomic::AtomicU64,
    }
    #[cfg(target_os = "linux")]
    static COUNTING: CountingGate = CountingGate {
        total: std::sync::atomic::AtomicU64::new(0),
        clocks: std::sync::atomic::AtomicU64::new(0),
        waits: std::sync::atomic::AtomicU64::new(0),
        clones: std::sync::atomic::AtomicU64::new(0),
    };
    // SAFETY: forwards exactly to the direct entry after counting.
    #[cfg(target_os = "linux")]
    unsafe impl GateSyscall for CountingGate {
        unsafe fn syscall6(&self, nr: i64, args: [u64; 6]) -> i64 {
            use std::sync::atomic::Ordering;
            self.total.fetch_add(1, Ordering::SeqCst);
            if nr == libc::SYS_clock_gettime {
                self.clocks.fetch_add(1, Ordering::SeqCst);
            }
            if nr == libc::SYS_wait4 {
                self.waits.fetch_add(1, Ordering::SeqCst);
            }
            if nr == libc::SYS_clone {
                self.clones.fetch_add(1, Ordering::SeqCst);
            }
            // SAFETY: same contract, forwarded.
            unsafe { DirectGate.syscall6(nr, args) }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_gate_sees_every_call() {
        use std::sync::atomic::Ordering;
        // SAFETY: the counting gate is a static forwarding exactly
        // like the direct entry; installing it degrades nothing.
        let _ = unsafe { install_gate(&COUNTING) };
        let before = COUNTING.total.load(Ordering::SeqCst);
        let pid = getpid();
        assert_eq!(pid, std::process::id());
        let _ = now_ms();
        assert!(COUNTING.total.load(Ordering::SeqCst) >= before + 2);
        assert!(COUNTING.clocks.load(Ordering::SeqCst) >= 1);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[test]
    fn attested_issues_only_gated_syscalls() {
        use std::sync::atomic::Ordering;
        // SAFETY: as above; the counting gate forwards faithfully.
        let _ = unsafe { install_gate(&COUNTING) };
        let (c0, w0, k0) = (
            COUNTING.clocks.load(Ordering::SeqCst),
            COUNTING.waits.load(Ordering::SeqCst),
            COUNTING.clones.load(Ordering::SeqCst),
        );
        let _ = crate::Patcher::attested().unwrap();
        assert!(
            COUNTING.clones.load(Ordering::SeqCst) > k0,
            "probe clone ungated"
        );
        assert!(
            COUNTING.waits.load(Ordering::SeqCst) > w0,
            "probe wait ungated"
        );
        assert!(
            COUNTING.clocks.load(Ordering::SeqCst) > c0,
            "probe clock ungated"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gated_time_advances_and_sleep_waits() {
        let t0 = now_ms();
        sleep_ms(15);
        let t1 = now_ms();
        assert!(t1 >= t0 + 10, "sleep_ms(15) advanced only {}", t1 - t0);
    }
}
