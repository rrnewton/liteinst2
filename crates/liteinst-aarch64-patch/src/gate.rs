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
pub fn now_ms() -> Option<u64> {
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
        return None;
    }
    Some(
        (ts.tv_sec as u64)
            .saturating_mul(1000)
            .saturating_add((ts.tv_nsec as u64) / 1_000_000),
    )
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
        fail_munmap: std::sync::atomic::AtomicBool,
        fail_clock: std::sync::atomic::AtomicBool,
        fail_clock_after: std::sync::atomic::AtomicU64,
        last_munmap_addr: std::sync::atomic::AtomicU64,
        munmaps: std::sync::atomic::AtomicU64,
        counts: [std::sync::atomic::AtomicU64; 512],
        seen: [std::sync::atomic::AtomicU64; 8],
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    impl CountingGate {
        fn reset(&self) {
            use std::sync::atomic::Ordering;
            self.total.store(0, Ordering::SeqCst);
            self.clocks.store(0, Ordering::SeqCst);
            self.waits.store(0, Ordering::SeqCst);
            self.clones.store(0, Ordering::SeqCst);
            self.fail_munmap.store(false, Ordering::SeqCst);
            self.fail_clock.store(false, Ordering::SeqCst);
            self.fail_clock_after.store(u64::MAX, Ordering::SeqCst);
            self.last_munmap_addr.store(0, Ordering::SeqCst);
            self.munmaps.store(0, Ordering::SeqCst);
            for count in &self.counts {
                count.store(0, Ordering::SeqCst);
            }
            for word in &self.seen {
                word.store(0, Ordering::SeqCst);
            }
        }
    }
    #[cfg(target_os = "linux")]
    static COUNTING: CountingGate = CountingGate {
        total: std::sync::atomic::AtomicU64::new(0),
        clocks: std::sync::atomic::AtomicU64::new(0),
        waits: std::sync::atomic::AtomicU64::new(0),
        clones: std::sync::atomic::AtomicU64::new(0),
        fail_munmap: std::sync::atomic::AtomicBool::new(false),
        fail_clock: std::sync::atomic::AtomicBool::new(false),
        fail_clock_after: std::sync::atomic::AtomicU64::new(u64::MAX),
        last_munmap_addr: std::sync::atomic::AtomicU64::new(0),
        munmaps: std::sync::atomic::AtomicU64::new(0),
        counts: [const { std::sync::atomic::AtomicU64::new(0) }; 512],
        seen: [const { std::sync::atomic::AtomicU64::new(0) }; 8],
    };
    // SAFETY: forwards exactly to the direct entry after counting.
    #[cfg(target_os = "linux")]
    unsafe impl GateSyscall for CountingGate {
        unsafe fn syscall6(&self, nr: i64, args: [u64; 6]) -> i64 {
            use std::sync::atomic::Ordering;
            self.total.fetch_add(1, Ordering::SeqCst);
            if (0..512).contains(&nr) {
                let nr = nr as usize;
                self.counts[nr].fetch_add(1, Ordering::SeqCst);
                self.seen[nr / 64].fetch_or(1u64 << (nr % 64), Ordering::SeqCst);
            }
            if nr == libc::SYS_clock_gettime {
                let clock_calls = self.clocks.fetch_add(1, Ordering::SeqCst) + 1;
                if self.fail_clock.load(Ordering::SeqCst)
                    || clock_calls > self.fail_clock_after.load(Ordering::SeqCst)
                {
                    return -(libc::EFAULT as i64);
                }
            }
            if nr == libc::SYS_wait4 {
                self.waits.fetch_add(1, Ordering::SeqCst);
            }
            if nr == libc::SYS_clone {
                self.clones.fetch_add(1, Ordering::SeqCst);
            }
            if nr == libc::SYS_munmap {
                self.munmaps.fetch_add(1, Ordering::SeqCst);
                self.last_munmap_addr.store(args[0], Ordering::SeqCst);
                if self.fail_munmap.load(Ordering::SeqCst) {
                    return -(libc::EACCES as i64);
                }
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
        // Fork-isolate the census: resetting and accounting
        // process-global counters is only deterministic when this
        // child is the only thread issuing gated calls. Only the
        // clone count below is asserted exactly; the rest is an
        // allowlist plus total accounting.
        // SAFETY: fork with an immediately-exiting child.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> i32 {
                if unsafe { install_gate(&COUNTING) }.is_err() {
                    return 10;
                }
                let before = COUNTING.total.load(Ordering::SeqCst);
                let _ = getpid();
                if COUNTING.total.load(Ordering::SeqCst) == before {
                    return 10;
                }
                COUNTING.reset();
                if crate::Patcher::attested().is_err() {
                    return 11;
                }
                let allowed: [i64; 11] = [
                    libc::SYS_pipe2,
                    libc::SYS_clone,
                    libc::SYS_close,
                    libc::SYS_wait4,
                    libc::SYS_kill,
                    libc::SYS_read,
                    libc::SYS_ppoll,
                    libc::SYS_fcntl,
                    libc::SYS_clock_gettime,
                    libc::SYS_clock_nanosleep,
                    libc::SYS_getpid,
                ];
                let mut accounted = 0u64;
                for nr in 0..512usize {
                    let count = COUNTING.counts[nr].load(Ordering::SeqCst);
                    if count != 0 && !allowed.contains(&(nr as i64)) {
                        return 12;
                    }
                    accounted += count;
                }
                if accounted != COUNTING.total.load(Ordering::SeqCst) {
                    return 13;
                }
                if COUNTING.clones.load(Ordering::SeqCst) != 1 {
                    return 14;
                }
                // Latent assumption, documented: only the clone
                // count is exact; waits/clocks assert presence, not
                // counts (the parent's first wait4 may or may not
                // miss the child depending on scheduling).
                if COUNTING.waits.load(Ordering::SeqCst) == 0
                    || COUNTING.clocks.load(Ordering::SeqCst) == 0
                {
                    return 15;
                }
                // A clock that fails only after the probe clone
                // must fail the collection custody path, not spin
                // or attest from an expired-on-arrival deadline.
                // Allow the pre-clone check and collection
                // deadline construction, then fail the next read.
                let clocks_before_post_clone = COUNTING.clocks.load(Ordering::SeqCst);
                COUNTING
                    .fail_clock_after
                    .store(clocks_before_post_clone + 2, Ordering::SeqCst);
                if crate::Patcher::attested().is_ok() {
                    return 18;
                }
                if COUNTING.clones.load(Ordering::SeqCst) != 2 {
                    return 19;
                }
                // Custody: the post-clone clock failure must still
                // REAP its probe child (MKD) — no child of this
                // process may remain, zombie or running.
                let mut reap_status: libc::c_int = 0;
                let reaped = unsafe { libc::waitpid(-1, &mut reap_status, libc::WNOHANG) };
                if reaped != -1
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD)
                {
                    return 20;
                }
                COUNTING.fail_clock_after.store(u64::MAX, Ordering::SeqCst);
                // A failing gated clock must make attestation fail
                // before another probe clone is issued.
                COUNTING.fail_clock.store(true, Ordering::SeqCst);
                if crate::Patcher::attested().is_ok() {
                    return 16;
                }
                if COUNTING.clones.load(Ordering::SeqCst) != 2 {
                    return 17;
                }
                0
            }))
            .unwrap_or(9);
            unsafe { libc::_exit(code) };
        }
        let mut status: libc::c_int = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "attested census child status={status:#x} (9=panic, 10=gate absent, 11=attested, 12=unexpected syscall, 13=accounting, 14=clone count, 15=wait/clock, 16=clock failure accepted, 17=clock failure cloned, 18=post-clone clock failure accepted, 19=post-clone clone count, 20=post-clone child unreaped)"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gated_time_advances_and_sleep_waits() {
        let t0 = now_ms().unwrap();
        sleep_ms(15);
        let t1 = now_ms().unwrap();
        assert!(t1 >= t0 + 10, "sleep_ms(15) advanced only {}", t1 - t0);
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[test]
    fn denied_unmap_at_publish_refuses_and_retains_ownership() {
        use std::sync::atomic::Ordering;
        // SAFETY: the counting gate forwards exactly like the
        // direct entry (test-only munmap denial aside).
        let _ = unsafe { install_gate(&COUNTING) };
        // Fork-isolated like the fd census: sibling tests reuse
        // addresses, so maps assertions are only deterministic in
        // a child whose address space is a frozen copy.
        // SAFETY: fork with an immediately-exiting child.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> i32 {
                // A panic after fork would otherwise unwind into the
                // copied libtest harness and can be reported as exit
                // 0. Every test-body assertion is inside this closure;
                // the catch below converts any panic to exit 9.
                if unsafe { install_gate(&COUNTING) }.is_err() {
                    return 10;
                }
                let before_gate_calls = COUNTING.total.load(Ordering::SeqCst);
                let _ = getpid();
                if COUNTING.total.load(Ordering::SeqCst) == before_gate_calls {
                    return 10;
                }
                fn rw_island_maps() -> Result<usize, ()> {
                    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|_| ())?;
                    Ok(maps
                        .lines()
                        .filter(|line| {
                            let mut fields = line.split_whitespace();
                            let _range = fields.next();
                            let perms = fields.next();
                            perms == Some("rw-s") && line.contains("memfd:liteinst-island")
                        })
                        .count())
                }
                let Ok(baseline) = rw_island_maps() else {
                    return 7;
                };
                let token = crate::cache::CacheAttested::for_test();
                let mut island = crate::island::Island::build(&[0xd400_0001, 0xd65f_03c0]).unwrap();
                let entry = island.entry_addr();
                let Ok(built) = rw_island_maps() else {
                    return 7;
                };
                if built != baseline + 1 {
                    return 11;
                }
                COUNTING.fail_munmap.store(true, Ordering::SeqCst);
                let err = island.publish(token).unwrap_err();
                COUNTING.fail_munmap.store(false, Ordering::SeqCst);
                if !matches!(err, PatchError::Os { op, errno } if op == "munmap island rw alias" && errno == libc::EACCES)
                {
                    return 3;
                }
                // The DENIED call named the RW alias (not the RX
                // entry): capture that exact address — its mapping
                // must still exist now and be gone after Drop.
                let rw = COUNTING.last_munmap_addr.load(Ordering::SeqCst);
                if rw == 0 || rw == entry {
                    return 8;
                }
                if island.read_rx_word(0) != Some(0xd400_0001) {
                    return 4;
                }
                let mapped = |e: u64| {
                    std::fs::read_to_string("/proc/self/maps")
                        .unwrap()
                        .lines()
                        .any(|l| l.starts_with(&format!("{e:x}-")))
                };
                let Ok(denied) = rw_island_maps() else {
                    return 7;
                };
                if denied != baseline + 1 || !mapped(entry) || !mapped(rw) {
                    return 5;
                }
                drop(island);
                let Ok(after) = rw_island_maps() else {
                    return 7;
                };
                if after != baseline || mapped(entry) || mapped(rw) {
                    return 6;
                }
                0
            }))
            .unwrap_or(9);
            unsafe { libc::_exit(code) };
        }
        let mut status: libc::c_int = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "denied-unmap child status={status:#x} (3=wrong error, 4=read, 5=not mapped, 6=leaked, 7=maps census, 8=wrong munmap address, 9=panic, 10=counting gate absent, 11=build map count)"
        );
    }
}
