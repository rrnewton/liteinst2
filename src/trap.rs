//! Process-wide SIGTRAP routing for WordPatch++ guards.

/// Kernel-layout signal action retained across guard-router installation.
///
/// Linux x86-64 consumes exactly these four machine words from `rt_sigaction`.
/// The type deliberately avoids libc's larger userspace `sigset_t` layout so a
/// host runtime can install and restore it through an exact trusted syscall.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct GuardSignalAction {
    /// Signal handler address, including `SIG_DFL` and `SIG_IGN` sentinels.
    pub handler: usize,
    /// Linux signal-action flags.
    pub flags: libc::c_ulong,
    /// Signal-restorer entry address when `SA_RESTORER` is present.
    pub restorer: usize,
    /// The exact 64-bit Linux x86-64 signal mask.
    pub mask: u64,
}

/// Three-argument handler ABI used by the guard router.
pub type GuardSignalHandler =
    unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut core::ffi::c_void);

/// Block the guard signal, install its router, and return the prior exact
/// kernel action while leaving the calling thread's signal mask blocked.
///
/// The callback must admit only prior `SIG_DFL` and `SIG_IGN` dispositions. It
/// must reject every custom handler before replacing it and leave the prior
/// action and signal mask unchanged on error. On success it must retain the
/// blocked mask until [`GuardSignalUnblocker`] restores the exact prior mask
/// after LiteInst2 has published the prior action. The guard router cannot
/// emulate the kernel's mask, reset, alternate-stack, or restart semantics for
/// a directly invoked custom handler.
///
/// The callback runs during single-threaded runtime preparation, before the
/// restrictive syscall filter is installed.
pub type GuardSignalInstaller = unsafe fn(
    libc::c_int,
    GuardSignalHandler,
    libc::c_int,
    *mut GuardSignalAction,
) -> Result<(), i32>;

/// Restore the exact signal mask retained by [`GuardSignalInstaller`].
///
/// The callback runs only after LiteInst2 has published the prior disposition,
/// so any pending guard signal can safely enter the newly installed router.
pub type GuardSignalUnblocker = unsafe fn(libc::c_int) -> Result<(), i32>;

/// Restore a prior default action and redeliver its signal through trusted raw
/// syscalls. Redelivery may remain pending until the current handler returns.
pub type GuardDefaultRestorer = unsafe fn(libc::c_int, &GuardSignalAction) -> Result<(), i32>;

/// Host-owned signal operations required by the guard router after a
/// restrictive syscall filter is active.
#[derive(Clone, Copy)]
pub struct GuardSignalRuntime {
    /// Exact-restorer installation callback that returns with SIGTRAP blocked.
    pub install_blocked: GuardSignalInstaller,
    /// Restore the exact signal mask held across prior-action publication.
    pub restore_mask: GuardSignalUnblocker,
    /// Async-signal-safe default-action restoration and redelivery callback.
    pub restore_default: GuardDefaultRestorer,
}

#[cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    allow(dead_code)
)]
#[derive(Debug)]
pub(crate) enum JumpError {
    Registry(TrapError),
    ExpectedBytesMismatch,
}

impl From<TrapError> for JumpError {
    fn from(error: TrapError) -> Self {
        Self::Registry(error)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use core::ffi::c_void;
    use core::mem::MaybeUninit;
    use core::ptr;
    use core::sync::atomic::AtomicPtr;
    use core::sync::atomic::AtomicU8;
    use core::sync::atomic::AtomicU64;
    use core::sync::atomic::AtomicUsize;
    use core::sync::atomic::Ordering;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::OnceLock;

    const IDLE: u8 = 0;
    const WRITING: u8 = 1;

    static HEAD: AtomicPtr<TrapSite> = AtomicPtr::new(ptr::null_mut());
    static PENDING_HEAD: AtomicPtr<PendingReservation> = AtomicPtr::new(ptr::null_mut());
    static REGISTRY_LOCK: Mutex<()> = Mutex::new(());
    static INSTALL_RESULT: OnceLock<Result<(), i32>> = OnceLock::new();
    static INSTALL_MODE: OnceLock<InstallMode> = OnceLock::new();
    static PREVIOUS_ACTION: OnceLock<PreviousAction> = OnceLock::new();

    #[derive(Clone, Copy)]
    enum InstallMode {
        Standalone,
        Runtime(super::GuardSignalRuntime),
    }

    struct PreviousAction(super::GuardSignalAction);

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
        displaced_end: AtomicUsize,
        word: Option<WordSite>,
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

    // Only single-cache-line MOV publishers participate in shared envelopes.
    // Split-word guards and Rapid's independent byte stores remain exclusive.
    struct WordSite {
        original: [u8; 8],
        committed: AtomicU64,
    }

    struct JumpRegistration {
        displaced_end: usize,
        original: Option<[u8; 8]>,
    }

    struct PendingReservation {
        execute_address: usize,
        reservation_start: usize,
        reservation_end: usize,
        guard_mask: u8,
        next: AtomicPtr<PendingReservation>,
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(#7): Review transactional overlap ownership and lock scope.
    pub(crate) struct PendingTrapSite {
        pending: Option<Box<PendingReservation>>,
    }

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

        pub(crate) fn begin_jump(
            &self,
            expected: &mut [u8; 8],
            replacement: &mut [u8; 8],
        ) -> Result<(), super::JumpError> {
            if self.word.is_none() {
                return self.begin().map_err(Into::into);
            }
            // This lock is released before touching live code. A signal that
            // interrupted a registrar must fail fast, never wait for itself.
            let _guard = lock_registry_for_registration()?;
            let mut current = HEAD.load(Ordering::Acquire);
            while !current.is_null() {
                // SAFETY: registry nodes are immutable and never freed.
                let other = unsafe { &*current };
                if overlaps(
                    self.reservation_start,
                    self.reservation_end,
                    other.reservation_start,
                    other.reservation_end,
                ) {
                    if other.phase.load(Ordering::Acquire) == WRITING {
                        return Err(TrapError::Contended.into());
                    }
                    if other.execute_address > self.execute_address {
                        // Registration proved that only a disjoint neighbor's
                        // jump bytes can occupy our tail, and authenticated the
                        // binding's original tail against that neighbor.
                        let word = other.word.as_ref().expect("shared word site");
                        let bytes = word.committed.load(Ordering::Relaxed).to_le_bytes();
                        let offset = other.execute_address - self.execute_address;
                        let count = (8 - offset).min(5);
                        // A neighbor may have registered after this particular
                        // handle was bound. Do not let its arrival authenticate
                        // a stale tail from a same-site rebind retroactively.
                        if expected[offset..offset + count] != word.original[..count] {
                            return Err(super::JumpError::ExpectedBytesMismatch);
                        }
                        expected[offset..offset + count].copy_from_slice(&bytes[..count]);
                        replacement[offset..offset + count].copy_from_slice(&bytes[..count]);
                    }
                }
                current = other.next;
            }
            // Holding the registry lock makes the overlap check and lease
            // acquisition indivisible with other writers and registrations.
            self.begin().map_err(Into::into)
        }

        pub(crate) fn finish_jump(&self, published: Option<[u8; 8]>) {
            if let (Some(word), Some(bytes)) = (&self.word, published) {
                word.committed
                    .store(u64::from_le_bytes(bytes), Ordering::Relaxed);
            }
            // Committed bytes become visible before any neighbor may compose
            // its next complete expected word. A failed write changes no state.
            self.finish();
        }

        pub(crate) fn handled_traps(&self) -> u64 {
            self.handled.load(Ordering::Relaxed)
        }
    }

    impl PendingTrapSite {
        pub(crate) fn commit(mut self) -> Result<&'static TrapSite, TrapError> {
            ensure_installed()?;
            let pending = self.pending.as_ref().expect("pending reservation missing");
            let mut site = Box::new(TrapSite {
                execute_address: pending.execute_address,
                reservation_start: pending.reservation_start,
                reservation_end: pending.reservation_end,
                guard_mask: pending.guard_mask,
                displaced_end: AtomicUsize::new(pending.reservation_end),
                word: None,
                phase: AtomicU8::new(IDLE),
                handled: AtomicU64::new(0),
                next: ptr::null_mut(),
            });

            let _guard = REGISTRY_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut pending = self.pending.take().expect("pending reservation missing");
            // SAFETY: the registry mutex serializes all pending-list access.
            unsafe { remove_pending(&mut *pending) };
            site.next = HEAD.load(Ordering::Relaxed);
            let site = Box::into_raw(site);
            HEAD.store(site, Ordering::Release);
            drop(_guard);
            drop(pending);
            // SAFETY: registry nodes are intentionally never freed.
            Ok(unsafe { &*site })
        }
    }

    impl Drop for PendingTrapSite {
        fn drop(&mut self) {
            let Some(mut pending) = self.pending.take() else {
                return;
            };
            let guard = REGISTRY_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // SAFETY: the registry mutex serializes all pending-list access.
            unsafe { remove_pending(&mut *pending) };
            drop(guard);
        }
    }

    pub(crate) fn reserve(
        execute_address: usize,
        reservation_start: usize,
        reservation_end: usize,
        guard_mask: u8,
    ) -> Result<PendingTrapSite, TrapError> {
        let mut pending = Box::new(PendingReservation {
            execute_address,
            reservation_start,
            reservation_end,
            guard_mask,
            next: AtomicPtr::new(ptr::null_mut()),
        });
        let _guard = REGISTRY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut current = HEAD.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: published nodes are process-lifetime allocations.
            let site = unsafe { &*current };
            if overlaps(
                reservation_start,
                reservation_end,
                site.reservation_start.min(site.execute_address),
                site.reservation_end
                    .max(site.displaced_end.load(Ordering::Relaxed)),
            ) {
                return Err(TrapError::Overlap);
            }
            current = site.next;
        }
        if pending_overlaps(reservation_start, reservation_end) {
            return Err(TrapError::Overlap);
        }
        pending
            .next
            .store(PENDING_HEAD.load(Ordering::Relaxed), Ordering::Relaxed);
        PENDING_HEAD.store(&mut *pending, Ordering::Relaxed);
        Ok(PendingTrapSite {
            pending: Some(pending),
        })
    }

    #[cfg(test)]
    pub(crate) fn register(
        execute_address: usize,
        reservation_start: usize,
        reservation_end: usize,
        guard_mask: u8,
    ) -> Result<&'static TrapSite, TrapError> {
        register_inner(
            execute_address,
            reservation_start,
            reservation_end,
            guard_mask,
            None,
        )
        .map(|(site, _)| site)
    }

    pub(crate) fn register_jump(
        execute_address: usize,
        reservation_start: usize,
        reservation_end: usize,
        guard_mask: u8,
        displaced_end: usize,
        original: Option<[u8; 8]>,
    ) -> Result<(&'static TrapSite, Option<[u8; 8]>), TrapError> {
        register_inner(
            execute_address,
            reservation_start,
            reservation_end,
            guard_mask,
            Some(JumpRegistration {
                displaced_end,
                original,
            }),
        )
    }

    fn register_inner(
        execute_address: usize,
        reservation_start: usize,
        reservation_end: usize,
        guard_mask: u8,
        jump: Option<JumpRegistration>,
    ) -> Result<(&'static TrapSite, Option<[u8; 8]>), TrapError> {
        ensure_installed()?;
        let _guard = lock_registry_for_registration()?;
        let mut original = jump.as_ref().and_then(|jump| jump.original);
        let mut displaced_end = jump
            .as_ref()
            .map_or(reservation_end, |jump| jump.displaced_end);
        let mut existing = None;
        let mut current = HEAD.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: registry nodes are immutable and never freed.
            let site = unsafe { &*current };
            if site.execute_address == execute_address
                && site.reservation_start == reservation_start
                && site.reservation_end == reservation_end
                && site.guard_mask == guard_mask
                && site.word.is_some() == original.is_some()
            {
                existing = Some(site);
                displaced_end = displaced_end.max(site.displaced_end.load(Ordering::Relaxed));
                if site.word.is_some() && site.phase.load(Ordering::Acquire) == WRITING {
                    return Err(TrapError::Contended);
                }
                // Same-site handles may preplan a redirect over a future E9.
                // Binding does not authenticate or publish their own prefix:
                // each operation still compares that exact expected prefix.
                break;
            }
            current = site.next;
        }

        current = HEAD.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: registry nodes are immutable and never freed.
            let site = unsafe { &*current };
            if existing.is_some_and(|old| ptr::eq(old, site)) {
                current = site.next;
                continue;
            }
            if overlaps(
                execute_address,
                displaced_end,
                site.execute_address,
                site.displaced_end.load(Ordering::Relaxed),
            ) {
                return Err(TrapError::Overlap);
            }
            if overlaps(
                reservation_start,
                reservation_end,
                site.reservation_start,
                site.reservation_end,
            ) {
                let (Some(bytes), Some(word)) = (&mut original, &site.word) else {
                    return Err(TrapError::Overlap);
                };
                if site.phase.load(Ordering::Acquire) == WRITING {
                    return Err(TrapError::Contended);
                }
                if execute_address < site.execute_address {
                    let offset = site.execute_address - execute_address;
                    let count = 8 - offset;
                    let committed = word.committed.load(Ordering::Relaxed).to_le_bytes();
                    let tail = &bytes[offset..];
                    if tail != &word.original[..count] && tail != &committed[..count] {
                        return Err(TrapError::Overlap);
                    }
                    // Remember the proof even if this neighbor changes state
                    // before the binding's first apply. Public plan bytes stay
                    // untouched; only the binding receives this canonical tail.
                    bytes[offset..].copy_from_slice(&word.original[..count]);
                } else {
                    let offset = execute_address - site.execute_address;
                    let canonical = existing
                        .and_then(|old| old.word.as_ref())
                        .map_or(*bytes, |old| old.original);
                    if canonical[..8 - offset] != word.original[offset..] {
                        return Err(TrapError::Overlap);
                    }
                }
            }
            current = site.next;
        }
        if pending_overlaps(
            reservation_start.min(execute_address),
            reservation_end.max(displaced_end),
        ) {
            return Err(TrapError::Overlap);
        }
        if let Some(site) = existing {
            // Replanning an active E9 must never shrink the original relocated
            // instruction interval. Expansion was checked against every owner.
            site.displaced_end.store(displaced_end, Ordering::Relaxed);
            return Ok((site, original));
        }
        let site = Box::new(TrapSite {
            execute_address,
            reservation_start,
            reservation_end,
            guard_mask,
            displaced_end: AtomicUsize::new(displaced_end),
            word: original.map(|bytes| WordSite {
                original: bytes,
                committed: AtomicU64::new(u64::from_le_bytes(bytes)),
            }),
            phase: AtomicU8::new(IDLE),
            handled: AtomicU64::new(0),
            next: HEAD.load(Ordering::Relaxed),
        });
        let site = Box::leak(site);
        HEAD.store(site, Ordering::Release);
        Ok((site, original))
    }

    fn overlaps(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
        a_start < b_end && b_start < a_end
    }

    fn lock_registry_for_registration() -> Result<MutexGuard<'static, ()>, TrapError> {
        #[cfg(test)]
        {
            // The unit-test binary exercises the process-wide registry from
            // otherwise independent tests in parallel. Wait for those tests
            // here so their incidental lock ownership cannot masquerade as a
            // registration failure in overlap and pending-list assertions.
            Ok(REGISTRY_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner))
        }
        #[cfg(not(test))]
        {
            // Runtime registration remains fail-fast: a caller must never
            // wait on a lock that could be owned by interrupted code.
            REGISTRY_LOCK.try_lock().map_err(|_| TrapError::Contended)
        }
    }

    fn pending_overlaps(reservation_start: usize, reservation_end: usize) -> bool {
        let mut current = PENDING_HEAD.load(Ordering::Relaxed);
        while !current.is_null() {
            // SAFETY: the registry mutex is held, so pending nodes remain live.
            let pending = unsafe { &*current };
            if reservation_start < pending.reservation_end
                && pending.reservation_start < reservation_end
            {
                return true;
            }
            current = pending.next.load(Ordering::Relaxed);
        }
        false
    }

    unsafe fn remove_pending(target: *mut PendingReservation) {
        let mut previous: *mut PendingReservation = ptr::null_mut();
        let mut current = PENDING_HEAD.load(Ordering::Relaxed);
        while !current.is_null() {
            if current == target {
                // SAFETY: current is a live node protected by the registry mutex.
                let next = unsafe { (*current).next.load(Ordering::Relaxed) };
                if previous.is_null() {
                    PENDING_HEAD.store(next, Ordering::Relaxed);
                } else {
                    // SAFETY: previous is a live node protected by the registry mutex.
                    unsafe { (*previous).next.store(next, Ordering::Relaxed) };
                }
                return;
            }
            previous = current;
            // SAFETY: current is a live node protected by the registry mutex.
            current = unsafe { (*current).next.load(Ordering::Relaxed) };
        }
        debug_assert!(false, "pending trap reservation was not registered");
    }

    pub(crate) fn prepare() -> Result<(), TrapError> {
        match INSTALL_MODE.set(InstallMode::Standalone) {
            Ok(()) => {}
            Err(_) if matches!(INSTALL_MODE.get(), Some(InstallMode::Standalone)) => {}
            Err(_) => return Err(TrapError::Install(libc::EALREADY)),
        }
        ensure_installed()
    }

    pub(crate) unsafe fn prepare_with_signal_runtime(
        runtime: super::GuardSignalRuntime,
    ) -> Result<(), TrapError> {
        if INSTALL_MODE.set(InstallMode::Runtime(runtime)).is_err() {
            return Err(TrapError::Install(libc::EALREADY));
        }
        ensure_installed()
    }

    fn ensure_installed() -> Result<(), TrapError> {
        let mode = *INSTALL_MODE.get_or_init(|| InstallMode::Standalone);
        match *INSTALL_RESULT.get_or_init(|| install_handler(mode)) {
            Ok(()) => Ok(()),
            Err(errno) => Err(TrapError::Install(errno)),
        }
    }

    fn install_handler(mode: InstallMode) -> Result<(), i32> {
        if let InstallMode::Runtime(runtime) = mode {
            let mut previous = MaybeUninit::<super::GuardSignalAction>::uninit();
            // SAFETY: the host callback blocks SIGTRAP, owns exact signal
            // installation, and initializes `previous` on success.
            unsafe {
                (runtime.install_blocked)(
                    libc::SIGTRAP,
                    trap_handler,
                    libc::SA_SIGINFO | libc::SA_RESTART,
                    previous.as_mut_ptr(),
                )
            }?;
            // SAFETY: the successful callback initialized the exact action.
            let previous = unsafe { previous.assume_init() };
            if !previous_action_is_admitted(&previous) {
                // SAFETY: a successful installer retains the exact prior mask
                // until this callback is invoked, even if its action result
                // violates the admission contract.
                let _ = unsafe { (runtime.restore_mask)(libc::SIGTRAP) };
                return Err(libc::EPERM);
            }
            let _ = PREVIOUS_ACTION.set(PreviousAction(previous));
            // SAFETY: the host retained the exact prior mask across handler
            // installation; the previous action is now visible to the router.
            unsafe { (runtime.restore_mask)(libc::SIGTRAP) }?;
            return Ok(());
        }

        let mut previous = MaybeUninit::<libc::sigaction>::uninit();
        // SAFETY: querying SIGTRAP disposition writes a complete sigaction.
        if unsafe { libc::sigaction(libc::SIGTRAP, ptr::null(), previous.as_mut_ptr()) } != 0 {
            return Err(last_errno());
        }
        // SAFETY: successful sigaction initialized previous.
        let previous = unsafe { previous.assume_init() };
        let previous = guard_action_from_libc(&previous);
        if !previous_action_is_admitted(&previous) {
            return Err(libc::EPERM);
        }
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

    fn previous_action_is_admitted(action: &super::GuardSignalAction) -> bool {
        matches!(action.handler, libc::SIG_DFL | libc::SIG_IGN)
    }

    fn guard_action_from_libc(action: &libc::sigaction) -> super::GuardSignalAction {
        super::GuardSignalAction {
            handler: action.sa_sigaction,
            flags: action.sa_flags as libc::c_ulong,
            restorer: action
                .sa_restorer
                .map(|restorer| restorer as usize)
                .unwrap_or(0),
            // SAFETY: Linux x86-64 consumes the first 64 bits of libc's larger
            // sigset_t and the source is a fully initialized sigaction.
            mask: unsafe { ptr::addr_of!(action.sa_mask).cast::<u64>().read_unaligned() },
        }
    }

    fn guard_action_into_libc(action: &super::GuardSignalAction) -> libc::sigaction {
        // SAFETY: every field used by libc::sigaction is initialized below.
        let mut converted: libc::sigaction = unsafe { core::mem::zeroed() };
        converted.sa_sigaction = action.handler;
        converted.sa_flags = action.flags as libc::c_int;
        converted.sa_restorer = if action.restorer == 0 {
            None
        } else {
            // SAFETY: the value came from a previously installed kernel action.
            Some(unsafe { core::mem::transmute::<usize, extern "C" fn()>(action.restorer) })
        };
        // SAFETY: converted owns its zeroed sigset_t; Linux uses its first word.
        unsafe {
            ptr::addr_of_mut!(converted.sa_mask)
                .cast::<u64>()
                .write_unaligned(action.mask)
        };
        converted
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
        if signal == libc::SIGTRAP && !info.is_null() && !context.is_null() {
            // SAFETY: SA_SIGINFO supplies initialized signal metadata.
            let info = unsafe { &*info };
            // SAFETY: SA_SIGINFO supplies a mutable ucontext_t.
            let context = unsafe { &mut *context.cast::<libc::ucontext_t>() };
            // Linux x86 INT3 delivers SI_KERNEL with exception vector 3 (#BP).
            // TRAP_BRKPT can instead describe #DB (for example ICEBP). The
            // vector alone is insufficient: an asynchronous application signal
            // can carry the thread's stale trap number from an earlier #BP.
            if info.si_code == libc::SI_KERNEL
                && context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] == 3
            {
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
                        // A genuine guard trap can arrive after publication
                        // finished, so neither IDLE nor restored live bytes
                        // invalidate its saved breakpoint origin.
                        context.uc_mcontext.gregs[libc::REG_RIP as usize] =
                            trap_address as libc::greg_t;
                        return;
                    }
                    current = site.next;
                }
            }
        }

        // SAFETY: unknown traps are delegated to the disposition we replaced.
        unsafe { chain_previous(signal) };
    }

    unsafe fn chain_previous(signal: libc::c_int) {
        let Some(previous) = PREVIOUS_ACTION.get() else {
            // SAFETY: _exit is async-signal-safe and never returns.
            unsafe { libc::_exit(128 + signal) };
        };
        let handler = previous.0.handler;
        if handler == libc::SIG_IGN {
            return;
        }
        if handler == libc::SIG_DFL {
            if let Some(InstallMode::Runtime(runtime)) = INSTALL_MODE.get().copied() {
                // SAFETY: the host callback is required to use only trusted,
                // async-signal-safe raw operations in this signal context.
                if unsafe { (runtime.restore_default)(signal, &previous.0) }.is_err() {
                    unsafe { libc::_exit(128 + signal) };
                }
                return;
            }
            let previous = guard_action_into_libc(&previous.0);
            // SAFETY: restoring disposition and raising are async-signal-safe.
            unsafe {
                libc::sigaction(signal, &previous, ptr::null_mut());
                libc::raise(signal);
            }
            return;
        }

        // Installation admits only the two kernel sentinel dispositions above.
        // Directly invoking an unexpected custom handler would omit the
        // kernel-applied mask, SA_NODEFER, SA_RESETHAND, SA_ONSTACK, and restart
        // semantics, so an invariant violation must fail closed.
        unsafe { libc::_exit(128 + signal) };
    }
    #[cfg(test)]
    mod tests {
        use core::ptr;
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;
        use std::process::Output;
        use std::process::Stdio;
        use std::sync::Arc;
        use std::sync::Barrier;
        use std::sync::Mutex;
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;
        use std::thread;
        use std::time::Duration;
        use std::time::Instant;

        use super::INSTALL_MODE;
        use super::InstallMode;
        use super::PREVIOUS_ACTION;
        use super::REGISTRY_LOCK;
        use super::TrapError;
        use super::guard_action_from_libc;
        use super::guard_action_into_libc;
        use super::install_handler;
        use super::pending_overlaps;
        use super::prepare;
        use super::prepare_with_signal_runtime;
        use super::register;
        use super::reserve;
        use super::trap_handler;

        const PENDING_LIST_RACE_ITERATIONS: usize = 64;
        const ADMISSION_CHILD_ENV: &str = "LITEINST2_TRAP_ADMISSION_CHILD";
        const ADMISSION_CHILD_MARKER: &str = "liteinst2-sigtrap-admission-child";
        const ADMISSION_CHILD_TEST: &str =
            "trap::imp::tests::standalone_install_accepts_only_default_and_ignore";
        const ADMISSION_CHILD_TIMEOUT: Duration = Duration::from_secs(10);
        static RUNTIME_INSTALLS: AtomicUsize = AtomicUsize::new(0);
        static RUNTIME_MASK_RESTORES: AtomicUsize = AtomicUsize::new(0);
        static RUNTIME_RESTORES: AtomicUsize = AtomicUsize::new(0);
        static RUNTIME_SIGNAL_DURING_INSTALL: AtomicBool = AtomicBool::new(false);
        static TEST_RUNTIME_PRIOR_MASK: Mutex<Option<libc::sigset_t>> = Mutex::new(None);

        unsafe extern "C" fn custom_trap_handler(
            _signal: libc::c_int,
            _info: *mut libc::siginfo_t,
            _context: *mut core::ffi::c_void,
        ) {
        }

        fn query_sigtrap_action() -> super::super::GuardSignalAction {
            let mut action = core::mem::MaybeUninit::<libc::sigaction>::uninit();
            // SAFETY: a null new-action pointer queries the current action and
            // initializes the output on success.
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGTRAP, core::ptr::null(), action.as_mut_ptr()) },
                0
            );
            // SAFETY: successful sigaction initialized the action.
            let action = unsafe { action.assume_init() };
            guard_action_from_libc(&action)
        }

        fn set_sigtrap_action(handler: usize, flags: libc::c_int, mask_signal: libc::c_int) {
            // SAFETY: every field consumed by sigaction is initialized below.
            let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
            action.sa_sigaction = handler;
            action.sa_flags = flags;
            // SAFETY: action owns a valid signal set.
            assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
            if mask_signal != 0 {
                // SAFETY: action owns a valid signal set and mask_signal is a
                // real signal number supplied by the test.
                assert_eq!(
                    unsafe { libc::sigaddset(&mut action.sa_mask, mask_signal) },
                    0
                );
            }
            // SAFETY: action is fully initialized for SIGTRAP installation.
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGTRAP, &action, core::ptr::null_mut()) },
                0
            );
        }

        unsafe fn test_runtime_install(
            signal: libc::c_int,
            handler: super::super::GuardSignalHandler,
            flags: libc::c_int,
            previous: *mut super::super::GuardSignalAction,
        ) -> Result<(), i32> {
            if signal != libc::SIGTRAP || previous.is_null() {
                return Err(libc::EINVAL);
            }
            // SAFETY: both signal sets are fully initialized before use. This
            // child is single-threaded at runtime preparation, so retaining the
            // calling thread's blocked mask closes the complete delivery gap.
            let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
            let mut prior_mask: libc::sigset_t = unsafe { core::mem::zeroed() };
            if unsafe { libc::sigemptyset(&mut blocked) } != 0
                || unsafe { libc::sigaddset(&mut blocked, libc::SIGTRAP) } != 0
            {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO));
            }
            let blocked_result =
                unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut prior_mask) };
            if blocked_result != 0 {
                return Err(blocked_result);
            }
            let exact_previous = query_sigtrap_action();
            if !matches!(exact_previous.handler, libc::SIG_DFL | libc::SIG_IGN) {
                // SAFETY: restore the exact mask retained above before refusing.
                let _ = unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &prior_mask, core::ptr::null_mut())
                };
                return Err(libc::EPERM);
            }
            // SAFETY: the caller supplied a nonnull output pointer and the
            // callback initializes it exactly once before returning success.
            unsafe { previous.write(exact_previous) };
            *TEST_RUNTIME_PRIOR_MASK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(prior_mask);
            set_sigtrap_action(handler as *const () as usize, flags, 0);
            RUNTIME_INSTALLS.fetch_add(1, Ordering::Relaxed);
            if RUNTIME_SIGNAL_DURING_INSTALL.load(Ordering::Relaxed)
                && unsafe { libc::raise(libc::SIGTRAP) } != 0
            {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO));
            }
            Ok(())
        }

        unsafe fn test_runtime_restore_mask(signal: libc::c_int) -> Result<(), i32> {
            if signal != libc::SIGTRAP {
                return Err(libc::EINVAL);
            }
            let prior_mask = TEST_RUNTIME_PRIOR_MASK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .ok_or(libc::EINVAL)?;
            // SAFETY: the mask is the exact value retained by the successful
            // installer in this single-threaded child.
            let result = unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &prior_mask, core::ptr::null_mut())
            };
            if result != 0 {
                return Err(result);
            }
            RUNTIME_MASK_RESTORES.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        unsafe fn test_runtime_restore_default(
            signal: libc::c_int,
            previous: &super::super::GuardSignalAction,
        ) -> Result<(), i32> {
            let previous = guard_action_into_libc(previous);
            // SAFETY: the saved action came from the kernel and conversion
            // initializes every field consumed by sigaction.
            if unsafe { libc::sigaction(signal, &previous, core::ptr::null_mut()) } != 0 {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO));
            }
            RUNTIME_RESTORES.fetch_add(1, Ordering::Relaxed);
            // SAFETY: raise is async-signal-safe and redelivers the same signal.
            if unsafe { libc::raise(signal) } != 0 {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO));
            }
            Ok(())
        }

        fn test_signal_runtime() -> super::super::GuardSignalRuntime {
            super::super::GuardSignalRuntime {
                install_blocked: test_runtime_install,
                restore_mask: test_runtime_restore_mask,
                restore_default: test_runtime_restore_default,
            }
        }

        fn prepare_test_signal_runtime() -> Result<(), TrapError> {
            // SAFETY: these test callbacks initialize every output, retain and
            // restore the exact mask, do not unwind, and run before filtering.
            unsafe { prepare_with_signal_runtime(test_signal_runtime()) }
        }

        fn run_admission_child(mode: &str) -> Output {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", ADMISSION_CHILD_TEST, "--nocapture"])
                .env(ADMISSION_CHILD_ENV, mode)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + ADMISSION_CHILD_TIMEOUT;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return child.wait_with_output().unwrap(),
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Ok(None) => {
                        let _ = child.kill();
                        let output = child.wait_with_output().unwrap();
                        panic!(
                            "{mode} admission child timed out after {ADMISSION_CHILD_TIMEOUT:?}:\nstdout:\n{}\nstderr:\n{}",
                            String::from_utf8_lossy(&output.stdout),
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("failed to poll {mode} admission child: {error}");
                    }
                }
            }
        }

        #[test]
        fn standalone_install_accepts_only_default_and_ignore() {
            let Some(mode) = std::env::var_os(ADMISSION_CHILD_ENV) else {
                for mode in [
                    "custom",
                    "default",
                    "ignore",
                    "runtime-custom",
                    "runtime-ignore",
                    "runtime-install-window",
                    "concurrent-modes",
                    "origin-and-late-retry",
                ] {
                    let output = run_admission_child(mode);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    assert!(
                        output.status.success(),
                        "{mode} admission child failed:\nstdout:\n{}\nstderr:\n{}",
                        stdout,
                        stderr
                    );
                    assert!(
                        stdout.contains(&format!("{ADMISSION_CHILD_MARKER}:{mode}")),
                        "{mode} admission child filter ran no matching test:\nstdout:\n{}\nstderr:\n{}",
                        stdout,
                        stderr
                    );
                }
                for mode in ["default-redelivery", "runtime-default-redelivery"] {
                    let output = run_admission_child(mode);
                    assert_eq!(
                        output.status.signal(),
                        Some(libc::SIGTRAP),
                        "{mode} did not restore and enact the prior default action:\nstdout:\n{}\nstderr:\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                return;
            };
            println!("{ADMISSION_CHILD_MARKER}:{}", mode.to_string_lossy());
            match mode.to_str().unwrap() {
                "custom" => {
                    set_sigtrap_action(
                        custom_trap_handler as *const () as usize,
                        libc::SA_SIGINFO
                            | libc::SA_NODEFER
                            | libc::SA_RESETHAND
                            | libc::SA_ONSTACK
                            | libc::SA_RESTART,
                        libc::SIGUSR1,
                    );
                    let before = query_sigtrap_action();
                    assert_eq!(install_handler(InstallMode::Standalone), Err(libc::EPERM));
                    assert_eq!(
                        query_sigtrap_action(),
                        before,
                        "rejecting a custom action must not replace or normalize it"
                    );
                    assert!(
                        PREVIOUS_ACTION.get().is_none(),
                        "a refused action must not be published as chainable"
                    );
                }
                "default" | "ignore" => {
                    let disposition = if mode == "default" {
                        libc::SIG_DFL
                    } else {
                        libc::SIG_IGN
                    };
                    set_sigtrap_action(disposition, 0, 0);
                    assert_eq!(install_handler(InstallMode::Standalone), Ok(()));
                    assert_eq!(PREVIOUS_ACTION.get().unwrap().0.handler, disposition);
                    let installed = query_sigtrap_action();
                    assert_eq!(installed.handler, trap_handler as *const () as usize);
                    assert_ne!(installed.flags & libc::SA_SIGINFO as libc::c_ulong, 0);
                    assert_ne!(installed.flags & libc::SA_RESTART as libc::c_ulong, 0);
                }
                "origin-and-late-retry" => {
                    set_sigtrap_action(libc::SIG_IGN, 0, 0);
                    assert_eq!(prepare(), Ok(()));
                    let storage = Box::leak(Box::new([0x90_u8; 64]));
                    let address = storage.as_ptr() as usize;
                    let site = register(address, address, address + 8, 0b1111).unwrap();
                    // Synthetic signal frames isolate routing semantics. Real
                    // kernel guard delivery remains covered by the concurrent
                    // and secondary-byte publication tests in patcher.rs.
                    let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
                    let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
                    info.si_signo = libc::SIGTRAP;
                    for (code, vector) in [
                        (libc::SI_TKILL, 3),
                        (libc::SI_USER, 3),
                        (libc::SI_QUEUE, 3),
                        (libc::SI_TIMER, 3),
                        (libc::SI_KERNEL, 1),
                        (libc::TRAP_BRKPT, 1),
                        (libc::TRAP_BRKPT, 3),
                        (libc::TRAP_TRACE, 1),
                        (libc::TRAP_HWBKPT, 1),
                        (6, 3), // Linux TRAP_PERF, even with a stale #BP vector.
                    ] {
                        info.si_code = code;
                        context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] = vector;
                        context.uc_mcontext.gregs[libc::REG_RIP as usize] = (address + 2) as _;
                        // SAFETY: both pointers refer to initialized test frames.
                        unsafe {
                            super::handle_trap(
                                libc::SIGTRAP,
                                &mut info,
                                ptr::from_mut(&mut context).cast(),
                            );
                        }
                        assert_eq!(
                            context.uc_mcontext.gregs[libc::REG_RIP as usize],
                            (address + 2) as _,
                            "code={code}, vector={vector}"
                        );
                        assert_eq!(site.handled_traps(), 0, "code={code}, vector={vector}");
                    }
                    info.si_code = libc::SI_KERNEL;
                    context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] = 3;
                    context.uc_mcontext.gregs[libc::REG_RIP as usize] = (address + 2) as _;
                    // Missing metadata must not authorize a retry either.
                    unsafe {
                        super::handle_trap(
                            libc::SIGTRAP,
                            ptr::null_mut(),
                            ptr::from_mut(&mut context).cast(),
                        );
                        super::handle_trap(libc::SIGTRAP, &mut info, ptr::null_mut());
                    }
                    assert_eq!(
                        context.uc_mcontext.gregs[libc::REG_RIP as usize],
                        (address + 2) as _
                    );
                    assert_eq!(site.handled_traps(), 0);
                    // Model a valid saved #BP delivered after the writer has
                    // restored the live NOP and already published IDLE.
                    assert_eq!(site.phase.load(Ordering::Acquire), super::IDLE);
                    assert_eq!(storage[1], 0x90);
                    unsafe {
                        super::handle_trap(
                            libc::SIGTRAP,
                            &mut info,
                            ptr::from_mut(&mut context).cast(),
                        );
                    }
                    assert_eq!(
                        context.uc_mcontext.gregs[libc::REG_RIP as usize],
                        (address + 1) as _
                    );
                    assert_eq!(site.handled_traps(), 1);
                    context.uc_mcontext.gregs[libc::REG_RIP as usize] = (address + 32) as _;
                    unsafe {
                        super::handle_trap(
                            libc::SIGTRAP,
                            &mut info,
                            ptr::from_mut(&mut context).cast(),
                        );
                    }
                    assert_eq!(
                        context.uc_mcontext.gregs[libc::REG_RIP as usize],
                        (address + 32) as _
                    );
                    assert_eq!(site.handled_traps(), 1);
                }
                "default-redelivery" => {
                    set_sigtrap_action(libc::SIG_DFL, 0, 0);
                    assert_eq!(install_handler(InstallMode::Standalone), Ok(()));
                    // SAFETY: the installed router must restore and enact the
                    // exact prior default disposition for an unknown trap.
                    assert_eq!(unsafe { libc::raise(libc::SIGTRAP) }, 0);
                    // SAFETY: reaching this point means default redelivery was
                    // lost; use a distinct authenticated failure status.
                    unsafe { libc::_exit(111) };
                }
                "runtime-custom" => {
                    set_sigtrap_action(
                        custom_trap_handler as *const () as usize,
                        libc::SA_SIGINFO | libc::SA_RESTART,
                        libc::SIGUSR1,
                    );
                    let before = query_sigtrap_action();
                    assert!(matches!(
                        prepare_test_signal_runtime(),
                        Err(TrapError::Install(libc::EPERM))
                    ));
                    assert_eq!(query_sigtrap_action(), before);
                    assert_eq!(RUNTIME_INSTALLS.load(Ordering::Relaxed), 0);
                    assert_eq!(RUNTIME_MASK_RESTORES.load(Ordering::Relaxed), 0);
                }
                "runtime-ignore" => {
                    set_sigtrap_action(libc::SIG_IGN, 0, 0);
                    assert_eq!(prepare_test_signal_runtime(), Ok(()));
                    assert_eq!(RUNTIME_INSTALLS.load(Ordering::Relaxed), 1);
                    assert_eq!(RUNTIME_MASK_RESTORES.load(Ordering::Relaxed), 1);
                    assert_eq!(RUNTIME_RESTORES.load(Ordering::Relaxed), 0);
                    assert_eq!(PREVIOUS_ACTION.get().unwrap().0.handler, libc::SIG_IGN);
                    assert_eq!(
                        query_sigtrap_action().handler,
                        trap_handler as *const () as usize
                    );
                }
                "runtime-install-window" => {
                    set_sigtrap_action(libc::SIG_IGN, 0, 0);
                    RUNTIME_SIGNAL_DURING_INSTALL.store(true, Ordering::Relaxed);
                    assert_eq!(prepare_test_signal_runtime(), Ok(()));
                    RUNTIME_SIGNAL_DURING_INSTALL.store(false, Ordering::Relaxed);
                    assert_eq!(RUNTIME_INSTALLS.load(Ordering::Relaxed), 1);
                    assert_eq!(RUNTIME_MASK_RESTORES.load(Ordering::Relaxed), 1);
                    assert_eq!(PREVIOUS_ACTION.get().unwrap().0.handler, libc::SIG_IGN);
                    assert_eq!(
                        query_sigtrap_action().handler,
                        trap_handler as *const () as usize
                    );
                }
                "concurrent-modes" => {
                    set_sigtrap_action(libc::SIG_IGN, 0, 0);
                    let start = Arc::new(Barrier::new(3));
                    let standalone_start = Arc::clone(&start);
                    let standalone = thread::spawn(move || {
                        standalone_start.wait();
                        prepare()
                    });
                    let runtime_start = Arc::clone(&start);
                    let runtime = thread::spawn(move || {
                        runtime_start.wait();
                        prepare_test_signal_runtime()
                    });
                    start.wait();
                    let standalone = standalone.join().unwrap();
                    let runtime = runtime.join().unwrap();
                    assert_eq!(
                        usize::from(standalone.is_ok()) + usize::from(runtime.is_ok()),
                        1
                    );
                    assert_eq!(
                        usize::from(matches!(
                            standalone,
                            Err(TrapError::Install(libc::EALREADY))
                        )) + usize::from(matches!(
                            runtime,
                            Err(TrapError::Install(libc::EALREADY))
                        )),
                        1
                    );
                    match INSTALL_MODE.get().unwrap() {
                        InstallMode::Standalone => {
                            assert!(standalone.is_ok());
                            assert_eq!(RUNTIME_INSTALLS.load(Ordering::Relaxed), 0);
                            assert_eq!(RUNTIME_MASK_RESTORES.load(Ordering::Relaxed), 0);
                        }
                        InstallMode::Runtime(_) => {
                            assert!(runtime.is_ok());
                            assert_eq!(RUNTIME_INSTALLS.load(Ordering::Relaxed), 1);
                            assert_eq!(RUNTIME_MASK_RESTORES.load(Ordering::Relaxed), 1);
                        }
                    }
                    assert_eq!(
                        query_sigtrap_action().handler,
                        trap_handler as *const () as usize
                    );
                }
                "runtime-default-redelivery" => {
                    set_sigtrap_action(libc::SIG_DFL, 0, 0);
                    assert_eq!(prepare_test_signal_runtime(), Ok(()));
                    assert_eq!(RUNTIME_INSTALLS.load(Ordering::Relaxed), 1);
                    // SAFETY: the host callback must restore and redeliver the
                    // prior default action through the runtime path.
                    assert_eq!(unsafe { libc::raise(libc::SIGTRAP) }, 0);
                    unsafe { libc::_exit(112) };
                }
                unexpected => panic!("unexpected admission mode {unexpected}"),
            }
        }

        #[test]
        fn atomic_word_admission_preserves_pending_and_complete_displacement_ownership() {
            for pending_first in [false, true] {
                for offset in [5, 10] {
                    let storage = Box::leak(Box::new([0x90_u8; 128]));
                    let base = storage.as_ptr() as usize;
                    if pending_first {
                        let pending =
                            reserve(base + offset, base + offset, base + offset + 5, 0).unwrap();
                        assert!(matches!(
                            super::register_jump(
                                base,
                                base,
                                base + 8,
                                0,
                                base + 12,
                                Some([0x90; 8])
                            ),
                            Err(TrapError::Overlap)
                        ));
                        drop(pending);
                        assert!(
                            super::register_jump(
                                base,
                                base,
                                base + 8,
                                0,
                                base + 12,
                                Some([0x90; 8])
                            )
                            .is_ok()
                        );
                    } else {
                        let (site, _) = super::register_jump(
                            base,
                            base,
                            base + 8,
                            0,
                            base + 12,
                            Some([0x90; 8]),
                        )
                        .unwrap();
                        assert!(matches!(
                            reserve(base + offset, base + offset, base + offset + 5, 0),
                            Err(TrapError::Overlap)
                        ));
                        // A five-byte active-E9 replan cannot shrink twelve
                        // bytes of complete original instruction ownership.
                        let (rebound, _) = super::register_jump(
                            base,
                            base,
                            base + 8,
                            0,
                            base + 5,
                            Some([0x90; 8]),
                        )
                        .unwrap();
                        assert!(std::ptr::eq(site, rebound));
                        assert!(matches!(
                            super::register_jump(
                                base + offset,
                                base + offset,
                                base + offset + 8,
                                0,
                                base + offset + 5,
                                Some([0x90; 8])
                            ),
                            Err(TrapError::Overlap)
                        ));
                        assert!(reserve(base + 12, base + 12, base + 17, 0).is_ok());
                    }
                }
            }
        }

        #[test]
        fn pending_reservation_blocks_only_overlapping_registrations() {
            let storage = Box::leak(Box::new([0_u8; 32]));
            let base = storage.as_ptr() as usize;
            let pending = reserve(base, base, base + 8, 0).unwrap();

            let disjoint = register(base + 16, base + 16, base + 24, 0);
            assert!(disjoint.is_ok());
            assert!(matches!(
                register(base + 4, base + 4, base + 12, 0),
                Err(TrapError::Overlap)
            ));

            drop(pending);
            assert!(
                register(base, base, base + 8, 0).is_ok(),
                "dropping a pending token must release its reservation"
            );
        }

        #[test]
        fn concurrent_pending_commit_and_drop_preserve_the_list() {
            for iteration in 0..PENDING_LIST_RACE_ITERATIONS {
                let storage = Box::leak(Box::new([0_u8; 32]));
                let base = storage.as_ptr() as usize;
                let dropped = reserve(base, base, base + 8, 0).unwrap();
                let committed = reserve(base + 16, base + 16, base + 24, 0).unwrap();
                let start = Arc::new(Barrier::new(3));

                let drop_start = Arc::clone(&start);
                let dropper = thread::spawn(move || {
                    drop_start.wait();
                    drop(dropped);
                });
                let commit_start = Arc::clone(&start);
                let committer = thread::spawn(move || {
                    commit_start.wait();
                    committed.commit()
                });
                start.wait();

                dropper.join().unwrap();
                committer.join().unwrap().unwrap();

                let _guard = REGISTRY_LOCK
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assert!(
                    !pending_overlaps(base, base + 8),
                    "iteration {iteration}: dropping a pending token leaked its reservation"
                );
                assert!(
                    !pending_overlaps(base + 16, base + 24),
                    "iteration {iteration}: committing a pending token leaked its reservation"
                );
            }
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    #[allow(dead_code)]
    pub(crate) struct PendingTrapSite;

    #[allow(dead_code)]
    impl PendingTrapSite {
        pub(crate) fn commit(self) -> Result<&'static TrapSite, TrapError> {
            unreachable!("pending trap sites are unavailable on this target")
        }
    }
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
        pub(crate) fn begin_jump(
            &self,
            _expected: &mut [u8; 8],
            _replacement: &mut [u8; 8],
        ) -> Result<(), super::JumpError> {
            Err(TrapError::Unsupported.into())
        }

        pub(crate) fn finish_jump(&self, _published: Option<[u8; 8]>) {}

        pub(crate) fn handled_traps(&self) -> u64 {
            0
        }
    }
    #[allow(dead_code)]
    pub(crate) fn reserve(
        _execute_address: usize,
        _reservation_start: usize,
        _reservation_end: usize,
        _guard_mask: u8,
    ) -> Result<PendingTrapSite, TrapError> {
        Err(TrapError::Unsupported)
    }
    pub(crate) fn prepare() -> Result<(), TrapError> {
        Err(TrapError::Unsupported)
    }

    pub(crate) unsafe fn prepare_with_signal_runtime(
        _runtime: super::GuardSignalRuntime,
    ) -> Result<(), TrapError> {
        Err(TrapError::Unsupported)
    }

    pub(crate) fn register_jump(
        _execute_address: usize,
        _reservation_start: usize,
        _reservation_end: usize,
        _guard_mask: u8,
        _displaced_end: usize,
        _original: Option<[u8; 8]>,
    ) -> Result<(&'static TrapSite, Option<[u8; 8]>), TrapError> {
        Err(TrapError::Unsupported)
    }
}

pub(crate) use imp::TrapError;
pub(crate) use imp::TrapSite;
pub(crate) use imp::prepare;
pub(crate) use imp::prepare_with_signal_runtime;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
pub(crate) use imp::register;
pub(crate) use imp::register_jump;
pub(crate) use imp::reserve;
