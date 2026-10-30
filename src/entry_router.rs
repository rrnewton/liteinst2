//! Quiescent, process-lifetime routing for owned Linux x86-64 invalid opcodes.
//!
//! Source bytes and ISA qualification belong to the publisher. Installing this
//! router does not establish a quiescence lease or make a marker encoding safe.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use crate::contracts::{EntryRoute, Refusal};
    use core::ffi::c_void;
    use core::ptr;
    use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    // Linux's asm-generic siginfo ABI: illegal operand, used for x86 #UD.
    // Some libc versions do not export ILL_ILLOPN on this target.
    const ILL_ILLOPN: libc::c_int = 2;
    static HEAD: AtomicPtr<RouteBatch> = AtomicPtr::new(ptr::null_mut());
    static REGISTRY: Mutex<()> = Mutex::new(());
    static INSTALLED: OnceLock<ActionFingerprint> = OnceLock::new();

    struct RouteBatch {
        routes: Box<[EntryRoute]>,
        active: AtomicBool,
        handled: AtomicU64,
        next: *mut RouteBatch,
    }

    // SAFETY: immutable fields are initialized before HEAD's Release store;
    // the other fields are atomic and published nodes are never freed.
    unsafe impl Send for RouteBatch {}
    // SAFETY: readers traverse only immutable fields and lock-free atomics.
    unsafe impl Sync for RouteBatch {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ActionFingerprint {
        handler: usize,
        flags: libc::c_int,
        restorer: usize,
        mask: u64,
    }

    fn fingerprint(action: &libc::sigaction) -> ActionFingerprint {
        ActionFingerprint {
            handler: action.sa_sigaction,
            flags: action.sa_flags,
            restorer: action.sa_restorer.map_or(0, |entry| entry as usize),
            mask: kernel_mask(&action.sa_mask),
        }
    }

    fn kernel_mask(mask: &libc::sigset_t) -> u64 {
        // SAFETY: Linux x86-64 consumes the first 64 bits of the initialized
        // libc sigset_t. Comparing those bits avoids unused libc padding.
        unsafe { ptr::read_unaligned(ptr::from_ref(mask).cast::<u64>()) }
    }

    fn action() -> Result<libc::sigaction, Refusal> {
        // SAFETY: all bytes are initialized even if libc writes only ABI fields.
        let mut current: libc::sigaction = unsafe { core::mem::zeroed() };
        // SAFETY: null new action queries the complete SIGILL disposition.
        if unsafe { libc::sigaction(libc::SIGILL, ptr::null(), &mut current) } != 0 {
            return Err(Refusal::SignalContract);
        }
        Ok(current)
    }

    fn current_mask() -> Result<libc::sigset_t, Refusal> {
        // SAFETY: zero initializes the complete signal-set storage.
        let mut mask: libc::sigset_t = unsafe { core::mem::zeroed() };
        // SAFETY: with a null input, pthread_sigmask only queries this thread.
        if unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, ptr::null(), &mut mask) } != 0 {
            return Err(Refusal::SignalContract);
        }
        Ok(mask)
    }

    struct BlockedSignal {
        prior: libc::sigset_t,
        restored: bool,
    }

    impl BlockedSignal {
        fn new() -> Result<Self, Refusal> {
            // SAFETY: zeroed signal sets are initialized by the following calls.
            let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
            // SAFETY: the output is initialized before its contents are read.
            let mut prior: libc::sigset_t = unsafe { core::mem::zeroed() };
            // SAFETY: both helpers receive live writable signal-set storage.
            if unsafe { libc::sigemptyset(&mut blocked) } != 0
                || unsafe { libc::sigaddset(&mut blocked, libc::SIGILL) } != 0
                // SAFETY: save the exact prior mask while blocking installation.
                || unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut prior) } != 0
            {
                return Err(Refusal::SignalContract);
            }
            Ok(Self {
                prior,
                restored: false,
            })
        }

        fn restore(&mut self) -> Result<(), Refusal> {
            // SAFETY: prior was returned by pthread_sigmask on this thread.
            if unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.prior, ptr::null_mut()) }
                != 0
            {
                return Err(Refusal::SignalContract);
            }
            self.restored = true;
            Ok(())
        }
    }

    impl Drop for BlockedSignal {
        fn drop(&mut self) {
            if !self.restored {
                let _ = self.restore();
            }
        }
    }

    /// Installs the reserved router only over SIG_DFL and preserves the mask.
    ///
    /// Preparation must precede publication. The caller's runtime must exclude
    /// competing disposition changes; the process mutex serializes only this
    /// module's own preparation/registration. Custom and ignored dispositions,
    /// a blocked calling-thread SIGILL, and a replaced router are refused.
    pub(crate) fn prepare() -> Result<(), Refusal> {
        let _guard = REGISTRY.lock().map_err(|_| Refusal::SignalContract)?;
        if INSTALLED.get().is_some() {
            return verify();
        }
        let mut blocked = BlockedSignal::new()?;
        // SAFETY: prior is an initialized set and SIGILL is a valid signal.
        if unsafe { libc::sigismember(&blocked.prior, libc::SIGILL) } != 0 {
            return Err(Refusal::SignalContract);
        }
        let prior = action()?;
        if prior.sa_sigaction != libc::SIG_DFL {
            return Err(Refusal::SignalContract);
        }
        // SAFETY: initialize every field before passing the action to libc.
        let mut requested: libc::sigaction = unsafe { core::mem::zeroed() };
        requested.sa_sigaction = handler as *const () as usize;
        requested.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        // SAFETY: requested.sa_mask is live writable storage.
        if unsafe { libc::sigemptyset(&mut requested.sa_mask) } != 0
            // SAFETY: requested has the required three-argument handler ABI.
            || unsafe { libc::sigaction(libc::SIGILL, &requested, ptr::null_mut()) } != 0
        {
            return Err(Refusal::SignalContract);
        }
        let installed = match action() {
            Ok(installed) => installed,
            Err(error) => {
                // SAFETY: no routes have been published; restore the exact prior
                // disposition while SIGILL remains blocked on this thread.
                unsafe { libc::sigaction(libc::SIGILL, &prior, ptr::null_mut()) };
                return Err(error);
            }
        };
        if INSTALLED.set(fingerprint(&installed)).is_err() {
            // SAFETY: preparation is serialized; this is a fail-closed rollback.
            unsafe { libc::sigaction(libc::SIGILL, &prior, ptr::null_mut()) };
            return Err(Refusal::SignalContract);
        }
        // Publish installation state before pending signals can enter the router.
        blocked.restore()?;
        verify()
    }

    /// Rechecks the exact action and this thread's unblocked SIGILL mask.
    ///
    /// The unsafe publication lease must independently cover every execution
    /// thread's mask and forbid disposition replacement for the route lifetime.
    pub(crate) fn verify() -> Result<(), Refusal> {
        let expected = INSTALLED.get().ok_or(Refusal::SignalContract)?;
        let actual = action()?;
        if actual.sa_sigaction != handler as *const () as usize || fingerprint(&actual) != *expected
        {
            return Err(Refusal::SignalContract);
        }
        let mask = current_mask()?;
        // SAFETY: mask is initialized and SIGILL is a valid signal.
        if unsafe { libc::sigismember(&mask, libc::SIGILL) } != 0 {
            return Err(Refusal::SignalContract);
        }
        Ok(())
    }

    /// A staged batch; its immutable storage remains valid for process lifetime.
    pub(crate) struct RouteRegistration {
        batch: &'static RouteBatch,
        committed: bool,
    }

    impl RouteRegistration {
        /// Keeps routes active when the handle drops after successful publication.
        pub(crate) fn commit(&mut self) {
            self.committed = true;
        }

        /// Disables routing after synchronized rollback or generation retirement.
        ///
        /// The owning publisher must exclude all execution and saved resumes
        /// that could still need these routes before calling this operation.
        /// Storage is never reclaimed, including after deactivation.
        pub(crate) fn deactivate(&self) {
            self.batch.active.store(false, Ordering::Release);
        }

        /// Number of native or injected owned fault deliveries handled by this batch.
        pub(crate) fn handled(&self) -> u64 {
            self.batch.handled.load(Ordering::Relaxed)
        }
    }

    impl Drop for RouteRegistration {
        fn drop(&mut self) {
            if !self.committed {
                self.deactivate();
            }
        }
    }

    /// Allocates and publishes immutable routes before any source-marker write.
    ///
    /// # Safety
    /// The publisher holds a quiescence lease over all source/generated ranges
    /// and saved continuations. Generated destinations are initialized, live,
    /// ISA-qualified executable entries equivalent to the original heads. Source
    /// markers remain unreachable until the complete transaction is published.
    /// Every executor has SIGILL unblocked, and the disposition cannot change.
    /// These obligations continue until synchronized rollback or retirement;
    /// committed generated code and routing storage cannot be reclaimed early.
    pub(crate) unsafe fn stage(routes: &[EntryRoute]) -> Result<RouteRegistration, Refusal> {
        let _guard = REGISTRY.lock().map_err(|_| Refusal::SignalContract)?;
        verify()?;
        if routes.is_empty()
            || routes.iter().any(|route| {
                route.original == 0 || route.generated == 0 || route.original == route.generated
            })
        {
            return Err(Refusal::InvalidPlan);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(routes.len())
            .map_err(|_| Refusal::AllocationUnavailable)?;
        owned.extend_from_slice(routes);
        owned.sort_unstable_by_key(|route| route.original);
        if owned
            .windows(2)
            .any(|pair| pair[0].original == pair[1].original)
        {
            return Err(Refusal::InvalidPlan);
        }
        let head = HEAD.load(Ordering::Acquire);
        let mut current = head;
        while !current.is_null() {
            // SAFETY: HEAD only contains fully initialized, leaked nodes.
            let other = unsafe { &*current };
            if other.active.load(Ordering::Acquire)
                && other.routes.iter().any(|route| {
                    owned
                        .binary_search_by_key(&route.original, |route| route.original)
                        .is_ok()
                })
            {
                return Err(Refusal::OwnershipConflict);
            }
            current = other.next;
        }
        let batch = Box::leak(Box::new(RouteBatch {
            routes: owned.into_boxed_slice(),
            active: AtomicBool::new(true),
            handled: AtomicU64::new(0),
            next: head,
        }));
        HEAD.store(ptr::from_mut(batch), Ordering::Release);
        Ok(RouteRegistration {
            batch,
            committed: false,
        })
    }

    unsafe fn owned_fault(
        signal: libc::c_int,
        info: *const libc::siginfo_t,
        context: *const libc::ucontext_t,
    ) -> Option<(&'static RouteBatch, u64)> {
        if signal != libc::SIGILL || info.is_null() || context.is_null() {
            return None;
        }
        // SAFETY: the signal ABI supplies live initialized native structures.
        let info = unsafe { &*info };
        // SAFETY: same signal-handler ABI contract as info above.
        let context = unsafe { &*context };
        let pc = context.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
        if info.si_signo != libc::SIGILL
            || info.si_code != ILL_ILLOPN
            || context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] != 6
            // SAFETY: ILL_ILLOPN selects the synchronous-fault siginfo variant.
            || unsafe { info.si_addr() } as usize as u64 != pc
        {
            return None;
        }
        let mut current = HEAD.load(Ordering::Acquire);
        while !current.is_null() {
            // SAFETY: nodes and route slices are immutable and never reclaimed.
            let batch = unsafe { &*current };
            let matched = if batch.active.load(Ordering::Acquire) {
                batch
                    .routes
                    .binary_search_by_key(&pc, |route| route.original)
                    .ok()
            } else {
                None
            };
            if let Some(index) = matched {
                return Some((batch, batch.routes[index].generated));
            }
            current = batch.next;
        }
        None
    }

    extern "C" fn handler(signal: libc::c_int, info: *mut libc::siginfo_t, raw: *mut c_void) {
        let context = raw.cast::<libc::ucontext_t>();
        // SAFETY: the kernel supplies this handler's native siginfo/ucontext ABI.
        if let Some((batch, generated)) = unsafe { owned_fault(signal, info, context) } {
            // SAFETY: owned_fault authenticated the nonnull context and exact PC.
            unsafe { (*context).uc_mcontext.gregs[libc::REG_RIP as usize] = generated as i64 };
            batch.handled.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // SIG_DFL was the only admitted prior action. Ask the kernel to perform
        // default termination; directly invoking a prior handler would not
        // reproduce signal masking, restoration, or default/core-dump semantics.
        // SAFETY: zero initialization creates complete writable action storage.
        let mut default: libc::sigaction = unsafe { core::mem::zeroed() };
        default.sa_sigaction = libc::SIG_DFL;
        // SAFETY: sigemptyset, sigaction, raise, and _exit are async-signal-safe.
        // SIGILL remains blocked during this handler, so raise becomes pending
        // and default delivery occurs when the kernel restores the signal mask.
        unsafe {
            if libc::sigemptyset(&mut default.sa_mask) != 0
                || libc::sigaction(signal, &default, ptr::null_mut()) != 0
                || libc::raise(signal) != 0
            {
                // A failed default-restoration syscall is fatal, never success.
                libc::_exit(128 + signal);
            }
        }
    }

    #[cfg(test)]
    mod routed_jmp_native_tests;

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write;
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        use std::process::{Command, Output, Stdio};
        use std::time::{Duration, Instant};

        const CHILD_ENV: &str = "LITEINST_ENTRY_ROUTER_CHILD";
        const CHILD_TEST: &str = "entry_router::imp::tests::quiescent_sigill_contract";
        const CHILD_MARKER: &str = "entry-router-child";

        unsafe extern "C" fn custom(_: libc::c_int) {}

        fn set_action(handler: usize, flags: libc::c_int) {
            // SAFETY: initialize complete native action storage before the call.
            let mut next: libc::sigaction = unsafe { core::mem::zeroed() };
            next.sa_sigaction = handler;
            next.sa_flags = flags;
            // SAFETY: storage is writable and SIGILL is a valid signal.
            assert_eq!(unsafe { libc::sigemptyset(&mut next.sa_mask) }, 0);
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGILL, &next, ptr::null_mut()) },
                0
            );
        }

        fn block(signal: libc::c_int) {
            // SAFETY: the following calls initialize the writable signal set.
            let mut mask: libc::sigset_t = unsafe { core::mem::zeroed() };
            assert_eq!(unsafe { libc::sigemptyset(&mut mask) }, 0);
            assert_eq!(unsafe { libc::sigaddset(&mut mask, signal) }, 0);
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, ptr::null_mut()) },
                0
            );
        }

        fn image() -> (extern "C" fn() -> u64, EntryRoute) {
            let bytes: [u8; 12] = [
                0xf3, 0x0f, 0x1e, 0xfa, // ENDBR64 for an ordinary indirect entry.
                0x0f, 0x0b, // UD2; owned native #UD.
                0xb8, 42, 0, 0, 0, 0xc3, // MOV EAX,42; RET.
            ];
            // SAFETY: anonymous mapping is owned by this isolated child.
            let memory = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(memory, libc::MAP_FAILED);
            // SAFETY: initialization precedes execution and the mapping is large
            // enough. No RWX mapping or concurrent code writer is introduced.
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), memory.cast(), bytes.len()) };
            assert_eq!(
                unsafe { libc::mprotect(memory, 4096, libc::PROT_READ | libc::PROT_EXEC) },
                0
            );
            let base = memory as usize as u64;
            // SAFETY: after routing the owned UD2, this implements the stated ABI.
            let function =
                unsafe { core::mem::transmute::<*mut c_void, extern "C" fn() -> u64>(memory) };
            (
                function,
                EntryRoute {
                    original: base + 4,
                    generated: base + 6,
                },
            )
        }

        fn run_child(mode: &str) -> Output {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD_ENV, mode)
                .env("RUST_BACKTRACE", "0")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0);
            // SAFETY: only async-signal-safe setrlimit runs after fork.
            unsafe {
                command.pre_exec(|| {
                    for (resource, value) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_FSIZE, 65536)] {
                        let limit = libc::rlimit {
                            rlim_cur: value,
                            rlim_max: value,
                        };
                        if libc::setrlimit(resource, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
            let mut child = command.spawn().unwrap();
            let start = Instant::now();
            while child.try_wait().unwrap().is_none() {
                if start.elapsed() >= Duration::from_secs(5) {
                    // SAFETY: this process group belongs to the still-live child.
                    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                    let output = child.wait_with_output().unwrap();
                    panic!("entry-router child {mode} timed out: {output:?}");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            child.wait_with_output().unwrap()
        }

        fn metadata_checks(route: EntryRoute) {
            // SAFETY: all native ABI fields are initialized before inspection.
            let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
            // SAFETY: same complete initialization for the saved context.
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            info.si_signo = libc::SIGILL;
            info.si_code = ILL_ILLOPN;
            context.uc_mcontext.gregs[libc::REG_RIP as usize] = route.original as i64;
            context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] = 6;
            // SAFETY: the Linux x86-64 siginfo fault-union address is at byte 16;
            // this private synthetic fixture never reaches the kernel.
            unsafe {
                ptr::write_unaligned(
                    ptr::from_mut(&mut info).cast::<u8>().add(16).cast::<u64>(),
                    route.original,
                );
            }
            // SAFETY: initialized synthetic ABI records remain live for each call.
            assert_eq!(
                unsafe { owned_fault(libc::SIGILL, &info, &context) }.map(|(_, pc)| pc),
                Some(route.generated)
            );
            for code in [libc::SI_USER, libc::SI_TKILL, libc::SI_KERNEL] {
                info.si_code = code;
                // A previous #UD can leave trapno=6 in a user-sent signal frame.
                assert!(unsafe { owned_fault(libc::SIGILL, &info, &context) }.is_none());
            }
            info.si_code = ILL_ILLOPN;
            context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] = 13;
            assert!(unsafe { owned_fault(libc::SIGILL, &info, &context) }.is_none());
            context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] = 6;
            // Keep RIP at an owned head: a wrong si_addr alone must refuse.
            unsafe {
                ptr::write_unaligned(
                    ptr::from_mut(&mut info).cast::<u8>().add(16).cast::<u64>(),
                    route.original + 1,
                );
            }
            assert!(unsafe { owned_fault(libc::SIGILL, &info, &context) }.is_none());
            unsafe {
                ptr::write_unaligned(
                    ptr::from_mut(&mut info).cast::<u8>().add(16).cast::<u64>(),
                    route.original,
                );
            }
            info.si_signo = libc::SIGSEGV;
            assert!(unsafe { owned_fault(libc::SIGILL, &info, &context) }.is_none());
        }

        #[test]
        fn quiescent_sigill_contract() {
            let Some(mode) = std::env::var_os(CHILD_ENV) else {
                for mode in [
                    "owned",
                    "ignored",
                    "custom",
                    "masked-before",
                    "masked-after",
                    "replaced-default",
                    "replaced-custom",
                    "replaced-flags",
                    "duplicate",
                ] {
                    let output = run_child(mode);
                    assert!(output.status.success(), "{mode}: {output:?}");
                    assert!(
                        String::from_utf8_lossy(&output.stdout)
                            .contains(&format!("{CHILD_MARKER}:{mode}")),
                        "child filter did not execute {mode}: {output:?}"
                    );
                }
                for mode in ["unowned", "user-sent", "drop", "retire"] {
                    let output = run_child(mode);
                    assert_eq!(
                        output.status.signal(),
                        Some(libc::SIGILL),
                        "{mode}: {output:?}"
                    );
                    assert!(
                        String::from_utf8_lossy(&output.stdout)
                            .contains(&format!("{CHILD_MARKER}:{mode}")),
                        "child did not reach the expected fault: {mode}: {output:?}"
                    );
                }
                return;
            };
            let mode = mode.to_str().unwrap();
            println!("{CHILD_MARKER}:{mode}");
            std::io::stdout().flush().unwrap();
            set_action(libc::SIG_DFL, 0);
            block(libc::SIGUSR2);
            let initial_mask = kernel_mask(&current_mask().unwrap());
            match mode {
                "ignored" | "custom" => {
                    let prior = if mode == "ignored" {
                        libc::SIG_IGN
                    } else {
                        custom as *const () as usize
                    };
                    set_action(prior, libc::SA_RESTART);
                    let expected = fingerprint(&action().unwrap());
                    assert_eq!(prepare(), Err(Refusal::SignalContract));
                    assert_eq!(fingerprint(&action().unwrap()), expected);
                    assert_eq!(kernel_mask(&current_mask().unwrap()), initial_mask);
                }
                "masked-before" => {
                    block(libc::SIGILL);
                    let expected = kernel_mask(&current_mask().unwrap());
                    assert_eq!(prepare(), Err(Refusal::SignalContract));
                    assert_eq!(action().unwrap().sa_sigaction, libc::SIG_DFL);
                    assert_eq!(kernel_mask(&current_mask().unwrap()), expected);
                }
                "masked-after" => {
                    prepare().unwrap();
                    block(libc::SIGILL);
                    assert_eq!(verify(), Err(Refusal::SignalContract));
                }
                "replaced-default" | "replaced-custom" | "replaced-flags" => {
                    prepare().unwrap();
                    match mode {
                        "replaced-default" => set_action(libc::SIG_DFL, 0),
                        "replaced-custom" => set_action(custom as *const () as usize, 0),
                        _ => set_action(
                            handler as *const () as usize,
                            libc::SA_SIGINFO | libc::SA_NODEFER,
                        ),
                    }
                    assert_eq!(verify(), Err(Refusal::SignalContract));
                    assert_eq!(prepare(), Err(Refusal::SignalContract));
                }
                _ => {
                    prepare().unwrap();
                    verify().unwrap();
                    prepare().unwrap();
                    assert_eq!(kernel_mask(&current_mask().unwrap()), initial_mask);
                    let (function, route) = image();
                    if mode == "unowned" {
                        function();
                        panic!("unowned native #UD returned");
                    }
                    // SAFETY: this isolated fixture owns initialized process-life
                    // code and excludes every other executor and disposition writer.
                    let mut registration = unsafe { stage(&[route]) }.unwrap();
                    assert_eq!(registration.handled(), 0);
                    match mode {
                        "owned" => {
                            metadata_checks(route);
                            assert_eq!(function(), 42);
                            assert_eq!(registration.handled(), 1);
                            registration.commit();
                            drop(registration);
                            assert_eq!(function(), 42, "committed route disappeared on Drop");
                        }
                        "duplicate" => {
                            assert!(matches!(
                                unsafe { stage(&[route]) },
                                Err(Refusal::OwnershipConflict)
                            ));
                            assert!(matches!(
                                unsafe { stage(&[route, route]) },
                                Err(Refusal::InvalidPlan)
                            ));
                            assert_eq!(function(), 42);
                            registration.deactivate();
                            let replacement = unsafe { stage(&[route]) }.unwrap();
                            assert_eq!(function(), 42);
                            assert_eq!(replacement.handled(), 1);
                            assert_eq!(registration.handled(), 1);
                        }
                        "user-sent" => {
                            assert_eq!(unsafe { libc::raise(libc::SIGILL) }, 0);
                            panic!("user-sent SIGILL returned");
                        }
                        "drop" => {
                            drop(registration);
                            function();
                            panic!("uncommitted route survived Drop");
                        }
                        "retire" => {
                            registration.commit();
                            assert_eq!(function(), 42);
                            registration.deactivate();
                            function();
                            panic!("retired route remained active");
                        }
                        _ => panic!("unknown router child mode {mode}"),
                    }
                }
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) use imp::{RouteRegistration, prepare, stage, verify};

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    use crate::contracts::{EntryRoute, Refusal};

    pub(crate) struct RouteRegistration;
    impl RouteRegistration {
        pub(crate) fn commit(&mut self) {}
        pub(crate) fn deactivate(&self) {}
        pub(crate) fn handled(&self) -> u64 {
            0
        }
    }
    pub(crate) fn prepare() -> Result<(), Refusal> {
        Err(Refusal::UnsupportedSemantics(
            "SIGILL entry routing requires Linux x86-64".into(),
        ))
    }
    pub(crate) fn verify() -> Result<(), Refusal> {
        prepare()
    }
    pub(crate) unsafe fn stage(_: &[EntryRoute]) -> Result<RouteRegistration, Refusal> {
        prepare()?;
        unreachable!()
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(crate) use imp::{RouteRegistration, prepare, stage, verify};
