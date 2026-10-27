//! Handler-only native operations. No libc call, allocation, errno TLS, or lock.
use crate::GateError;
use core::arch::asm;

#[inline]
pub(crate) unsafe fn syscall3(number: usize, a: usize, b: usize, c: usize) -> isize {
    let result: isize;
    // SAFETY: this leaf only implements the register ABI; each caller owns the
    // concrete syscall's pointer and lifecycle contract.
    unsafe {
        asm!("syscall", inlateout("rax") number => result,
            in("rdi") a, in("rsi") b, in("rdx") c,
            lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    result
}

#[inline]
pub(crate) unsafe fn syscall4(number: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
    let result: isize;
    // SAFETY: callers own the concrete native syscall and pointer contracts.
    unsafe {
        asm!("syscall", inlateout("rax") number => result,
            in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d,
            lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    result
}

pub(crate) fn result(value: isize, operation: &'static str) -> Result<isize, GateError> {
    if (-4095..0).contains(&value) {
        Err(GateError::Os {
            operation,
            errno: (-value) as i32,
        })
    } else {
        Ok(value)
    }
}

pub(crate) fn tid() -> isize {
    // SAFETY: gettid has no pointer arguments.
    unsafe { syscall3(libc::SYS_gettid as usize, 0, 0, 0) }
}
pub(crate) fn pid() -> isize {
    // SAFETY: getpid has no pointer arguments.
    unsafe { syscall3(libc::SYS_getpid as usize, 0, 0, 0) }
}

pub(crate) fn protect(address: usize, len: usize, protection: i32) -> isize {
    // SAFETY: ownership and exact range are validated before arming.
    unsafe {
        syscall3(
            libc::SYS_mprotect as usize,
            address,
            len,
            protection as usize,
        )
    }
}

const SYNC: usize = 1 << 5;
const REGISTER: usize = 1 << 6;
pub(crate) fn prepare_sync() -> Result<(), GateError> {
    // SAFETY: membarrier takes integer arguments only.
    let available = result(
        unsafe { syscall3(libc::SYS_membarrier as usize, 0, 0, 0) },
        "membarrier query",
    )?;
    if available as usize & (SYNC | REGISTER) != (SYNC | REGISTER) {
        return Err(GateError::Invalid(
            "private expedited sync-core unavailable",
        ));
    }
    // SAFETY: process-local registration with zero flags/cpu.
    let registered = result(
        unsafe { syscall3(libc::SYS_membarrier as usize, REGISTER, 0, 0) },
        "membarrier registration",
    )?;
    if registered != 0 {
        return Err(GateError::Invalid("sync-core registration result"));
    }
    if result(synchronize(), "initial sync-core")? != 0 {
        return Err(GateError::Invalid("initial sync-core did not complete"));
    }
    Ok(())
}

pub(crate) fn synchronize() -> isize {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: registration has completed before the first NX transition.
    let result = unsafe { syscall3(libc::SYS_membarrier as usize, SYNC, 0, 0) };
    if result == 0 {
        // SAFETY: CPUID is a serializing x86-64 instruction; preserve RBX.
        unsafe {
            asm!("push rbx", "xor eax, eax", "cpuid", "pop rbx",
            out("eax") _, out("ecx") _, out("edx") _);
        }
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    result
}

#[repr(C)]
struct Time {
    seconds: i64,
    nanoseconds: i64,
}
pub(crate) fn now() -> Option<u64> {
    let mut time = Time {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: clock_gettime writes exactly one initialized native timespec.
    let result = unsafe {
        syscall3(
            libc::SYS_clock_gettime as usize,
            1,
            (&mut time as *mut Time) as usize,
            0,
        )
    };
    if result != 0 || time.seconds < 0 || !(0..1_000_000_000).contains(&time.nanoseconds) {
        return None;
    }
    (time.seconds as u64)
        .checked_mul(1_000_000_000)?
        .checked_add(time.nanoseconds as u64)
}

/// Never unwinds, returns, allocates, or releases an executable owner.
pub(crate) fn fatal() -> ! {
    const MESSAGE: &[u8] = b"liteinst-inprocess: poisoned gate; terminating\n";
    // SAFETY: immutable message and process termination; write outcome cannot
    // change the failure verdict or prevent the following termination request.
    unsafe {
        syscall3(
            libc::SYS_write as usize,
            2,
            MESSAGE.as_ptr() as usize,
            MESSAGE.len(),
        );
        syscall3(libc::SYS_exit_group as usize, 190, 0, 0);
        syscall3(libc::SYS_kill as usize, pid() as usize, 9, 0);
    }
    loop {
        // SAFETY: if termination was denied, never continue into application
        // code or drop the owners. A synchronous illegal instruction is fatal
        // under this crate's unchanged default/core SIGILL contract.
        unsafe {
            asm!("ud2", options(nostack));
        }
    }
}
