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
            if core::ptr::eq(*existing, gate) {
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
}
