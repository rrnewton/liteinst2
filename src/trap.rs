//! Process-wide SIGTRAP routing for WordPatch++ guards.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use core::ffi::c_void;
    use core::mem::MaybeUninit;
    use core::ptr;
    use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    const IDLE: u8 = 0;
    const WRITING: u8 = 1;

    static HEAD: AtomicPtr<TrapSite> = AtomicPtr::new(ptr::null_mut());
    static REGISTRY_LOCK: Mutex<()> = Mutex::new(());
    static INSTALL_RESULT: OnceLock<Result<(), i32>> = OnceLock::new();
    static PREVIOUS_ACTION: OnceLock<PreviousAction> = OnceLock::new();

    struct PreviousAction(libc::sigaction);

    // SAFETY: sigaction is immutable after publication through OnceLock.
    unsafe impl Send for PreviousAction {}
    // SAFETY: sigaction is immutable after publication through OnceLock.
    unsafe impl Sync for PreviousAction {}

    /// Process-lifetime entry for one executable patch site.
    pub(crate) struct TrapSite {
        execute_address: usize,
        reservation_start: usize,
        reservation_end: usize,
        guard_mask: u8,
        phase: AtomicU8,
        handled: AtomicU64,
        next: *mut TrapSite,
    }

    // SAFETY: immutable fields are published before HEAD's release store; phase
    // is atomic and nodes are never freed.
    unsafe impl Send for TrapSite {}
    // SAFETY: immutable fields are published before HEAD's release store; phase
    // is atomic and nodes are never freed.
    unsafe impl Sync for TrapSite {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum TrapError {
        Contended,
        Overlap,
        Install(i32),
        #[allow(dead_code)]
        Unsupported,
    }

    impl TrapSite {
        pub(crate) fn begin(&self) -> Result<(), TrapError> {
            self.phase
                .compare_exchange(IDLE, WRITING, Ordering::AcqRel, Ordering::Acquire)
                .map(|_| ())
                .map_err(|_| TrapError::Contended)
        }

        pub(crate) fn finish(&self) {
            self.phase.store(IDLE, Ordering::Release);
        }

        pub(crate) fn handled_traps(&self) -> u64 {
            self.handled.load(Ordering::Relaxed)
        }
    }

    pub(crate) fn register(
        execute_address: usize,
        reservation_start: usize,
        reservation_end: usize,
        guard_mask: u8,
    ) -> Result<&'static TrapSite, TrapError> {
        ensure_installed()?;
        let _guard = REGISTRY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let mut current = HEAD.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: published nodes are process-lifetime allocations.
            let site = unsafe { &*current };
            if site.execute_address == execute_address
                && site.reservation_start == reservation_start
                && site.reservation_end == reservation_end
                && site.guard_mask == guard_mask
            {
                return Ok(site);
            }
            if reservation_start < site.reservation_end && site.reservation_start < reservation_end
            {
                return Err(TrapError::Overlap);
            }
            current = site.next;
        }

        let site = Box::new(TrapSite {
            execute_address,
            reservation_start,
            reservation_end,
            guard_mask,
            phase: AtomicU8::new(IDLE),
            handled: AtomicU64::new(0),
            next: HEAD.load(Ordering::Relaxed),
        });
        let site = Box::into_raw(site);
        HEAD.store(site, Ordering::Release);
        // SAFETY: registry nodes are intentionally never freed.
        Ok(unsafe { &*site })
    }

    fn ensure_installed() -> Result<(), TrapError> {
        match *INSTALL_RESULT.get_or_init(install_handler) {
            Ok(()) => Ok(()),
            Err(errno) => Err(TrapError::Install(errno)),
        }
    }

    fn install_handler() -> Result<(), i32> {
        let mut previous = MaybeUninit::<libc::sigaction>::uninit();
        // SAFETY: querying SIGTRAP disposition writes a complete sigaction.
        if unsafe { libc::sigaction(libc::SIGTRAP, ptr::null(), previous.as_mut_ptr()) } != 0 {
            return Err(last_errno());
        }
        // SAFETY: successful sigaction initialized previous.
        let previous = unsafe { previous.assume_init() };
        let _ = PREVIOUS_ACTION.set(PreviousAction(previous));

        // SAFETY: zeroed sigaction is initialized below before installation.
        let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
        action.sa_sigaction = trap_handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        // SAFETY: action contains a valid signal set.
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        // SAFETY: installs a valid SA_SIGINFO handler.
        if unsafe { libc::sigaction(libc::SIGTRAP, &action, ptr::null_mut()) } != 0 {
            return Err(last_errno());
        }
        Ok(())
    }

    fn last_errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    extern "C" fn trap_handler(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut c_void,
    ) {
        // SAFETY: the kernel supplies siginfo and ucontext for SA_SIGINFO.
        unsafe { handle_trap(signal, info, context) };
    }

    unsafe fn handle_trap(signal: libc::c_int, info: *mut libc::siginfo_t, context: *mut c_void) {
        if signal == libc::SIGTRAP && !context.is_null() {
            // SAFETY: SA_SIGINFO supplies a mutable ucontext_t.
            let context = unsafe { &mut *context.cast::<libc::ucontext_t>() };
            let rip = context.uc_mcontext.gregs[libc::REG_RIP as usize] as usize;
            let trap_address = rip.wrapping_sub(1);

            let mut current = HEAD.load(Ordering::Acquire);
            while !current.is_null() {
                // SAFETY: published registry nodes are never freed.
                let site = unsafe { &*current };
                let relative = trap_address.wrapping_sub(site.execute_address);
                if relative < 8 && site.guard_mask & (1 << relative) != 0 {
                    site.handled.fetch_add(1, Ordering::Relaxed);
                    while site.phase.load(Ordering::Acquire) == WRITING {
                        core::hint::spin_loop();
                    }
                    context.uc_mcontext.gregs[libc::REG_RIP as usize] =
                        trap_address as libc::greg_t;
                    return;
                }
                current = site.next;
            }
        }

        // SAFETY: unknown traps are delegated to the disposition we replaced.
        unsafe { chain_previous(signal, info, context) };
    }

    unsafe fn chain_previous(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut c_void,
    ) {
        let Some(previous) = PREVIOUS_ACTION.get() else {
            // SAFETY: _exit is async-signal-safe and never returns.
            unsafe { libc::_exit(128 + signal) };
        };
        let handler = previous.0.sa_sigaction;
        if handler == libc::SIG_IGN {
            return;
        }
        if handler == libc::SIG_DFL {
            // SAFETY: restoring disposition and raising are async-signal-safe.
            unsafe {
                libc::sigaction(signal, &previous.0, ptr::null_mut());
                libc::raise(signal);
            }
            return;
        }

        if previous.0.sa_flags & libc::SA_SIGINFO != 0 {
            type Handler = unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut c_void);
            // SAFETY: SA_SIGINFO specifies the three-argument handler ABI.
            let handler: Handler = unsafe { core::mem::transmute(handler) };
            // SAFETY: arguments are the kernel-provided signal context.
            unsafe { handler(signal, info, context) };
        } else {
            type Handler = unsafe extern "C" fn(libc::c_int);
            // SAFETY: absence of SA_SIGINFO specifies the one-argument ABI.
            let handler: Handler = unsafe { core::mem::transmute(handler) };
            // SAFETY: signal number is kernel-provided.
            unsafe { handler(signal) };
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    pub(crate) struct TrapSite;

    #[allow(dead_code)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum TrapError {
        Contended,
        Overlap,
        Install(i32),
        Unsupported,
    }

    impl TrapSite {
        pub(crate) fn begin(&self) -> Result<(), TrapError> {
            Err(TrapError::Unsupported)
        }

        pub(crate) fn finish(&self) {}

        pub(crate) fn handled_traps(&self) -> u64 {
            0
        }
    }

    pub(crate) fn register(
        _execute_address: usize,
        _reservation_start: usize,
        _reservation_end: usize,
        _guard_mask: u8,
    ) -> Result<&'static TrapSite, TrapError> {
        Err(TrapError::Unsupported)
    }
}

pub(crate) use imp::{TrapError, TrapSite, register};
