use super::*;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicU64;

static SESSION: AtomicU64 = AtomicU64::new(980_000);
const TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct Before {
    pub(super) state: TaskStateSnapshot,
    pub(super) maps: Vec<u8>,
    pub(super) pair: maps::Pair,
    pub(super) bytes: Vec<u8>,
    memory: std::fs::File,
    stack_start: u64,
    stack: Vec<u8>,
}

fn diagnostic(label: &str, text: &str) {
    let bytes = text.as_bytes();
    let _ = writeln!(
        std::io::stderr().lock(),
        "coalescence {label}: {:?}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(8192)])
    );
}
fn panic_diagnostic(payload: &(dyn std::any::Any + Send)) {
    diagnostic(
        "panic",
        payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("non-string panic"),
    );
}
fn live(pin: &OwnedFd) {
    let mut event = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut event, 1, 0) }, 0);
    assert_eq!(event.revents, 0);
}

impl Before {
    pub(super) fn bytes_unchanged(&self, owner: &Owner, until: Instant) {
        owner
            .time_left(until, "coalescence full byte observation")
            .unwrap();
        let pin = owner.handles.get(&owner.pid).unwrap();
        live(pin);
        assert!(
            owner
                .stopped
                .get(&owner.pid)
                .is_some_and(|status| libc::WIFSTOPPED(*status))
        );
        let mut stack = vec![0; self.stack.len()];
        let mut pair = vec![0; 8192];
        self.memory
            .read_exact_at(&mut stack, self.stack_start)
            .unwrap();
        self.memory.read_exact_at(&mut pair, BASE).unwrap();
        assert_eq!(stack, self.stack, "entire original stack changed");
        assert_eq!(pair, self.bytes, "complete original R/RX pair changed");
        assert_eq!(memory(owner.pid, BASE, 8192), self.bytes);
        live(pin);
        owner
            .time_left(until, "coalescence full byte observation complete")
            .unwrap();
    }
    /// Observe the already-refused owner without asking it to authorize a new
    /// operation. Cancellation itself is required, and the original absolute
    /// deadline still brackets all read-only state/map/byte observations.
    pub(super) fn pristine_after_refusal(
        &self,
        owner: &Owner,
        initial: &DynamicStop,
        until: Instant,
    ) {
        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
        assert!(
            Instant::now() < until,
            "coalescence refusal observation expired"
        );
        owner.require_stop(initial).unwrap();
        assert_eq!(state(owner.pid), self.state);
        assert_eq!(read_maps(owner.pid), self.maps);
        let pin = owner.handles.get(&owner.pid).unwrap();
        live(pin);
        assert!(
            owner
                .stopped
                .get(&owner.pid)
                .is_some_and(|status| libc::WIFSTOPPED(*status))
        );
        let mut stack = vec![0; self.stack.len()];
        let mut pair = vec![0; 8192];
        self.memory
            .read_exact_at(&mut stack, self.stack_start)
            .unwrap();
        self.memory.read_exact_at(&mut pair, BASE).unwrap();
        assert_eq!(stack, self.stack, "entire original stack changed");
        assert_eq!(pair, self.bytes, "complete original R/RX pair changed");
        assert_eq!(memory(owner.pid, BASE, 8192), self.bytes);
        live(pin);
        assert!(
            Instant::now() < until,
            "coalescence refusal observation expired"
        );
        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
    }
    pub(super) fn pristine(&self, owner: &Owner, initial: &DynamicStop, until: Instant) {
        owner.require_stop(initial).unwrap();
        assert_eq!(state(owner.pid), self.state);
        assert_eq!(read_maps(owner.pid), self.maps);
        self.bytes_unchanged(owner, until);
    }
}

/// Dedicated geometry, original mm-bound memory FD, and physical cleanup.
/// No old helper that assumes one original 8192-byte RX row is called.
pub(super) fn with_owner<T>(
    action: impl FnOnce(&mut Owner, &DynamicStop, Instant, &Before) -> T,
    after_cleanup: impl FnOnce(&Owner, &T),
) -> T {
    let fixture = Fixture::coalescing_pair(CODE);
    let mut harness = Harness::new();
    *harness.owner() = Owner::new(
        SESSION.fetch_add(1, Ordering::Relaxed),
        Arc::new(AtomicBool::new(false)),
    );
    harness.owner().lifecycle_options = Some(DynamicLifecycleOptions::default());
    // Harness launch keeps its own old bound. This original operation deadline
    // starts first and is never replaced for startup or the single NOP.
    let until = Instant::now() + TIMEOUT;
    let launched = harness.launch(&fixture).unwrap();
    let pins = catch_unwind(AssertUnwindSafe(|| {
        (
            pin(launched.pid),
            pin(harness.owner().broker.as_ref().unwrap().pid),
        )
    }));
    let (app, broker_pin) = pins.unwrap_or_else(|payload| {
        panic_diagnostic(payload.as_ref());
        if let Err(error) = harness.owner().cleanup() {
            diagnostic("pin cleanup", &format!("{error:?}"));
        }
        std::process::abort()
    });
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        live(&app);
        live(&broker_pin);
        let original = read_maps(launched.pid);
        let pair = maps::original(&original);
        let all = rows(&original);
        let stack = all
            .iter()
            .filter(|row| row.raw.ends_with(b"[stack]"))
            .collect::<Vec<_>>();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].permissions, *b"rw-p");
        let size = usize::try_from(stack[0].end - stack[0].start).unwrap();
        assert!((1..=1024 * 1024).contains(&size));
        let memory_file = std::fs::File::open(format!("/proc/{}/mem", launched.pid)).unwrap();
        let mut stack_bytes = vec![0; size];
        memory_file
            .read_exact_at(&mut stack_bytes, stack[0].start)
            .unwrap();
        let before = Before {
            state: state(launched.pid),
            bytes: memory(launched.pid, BASE, 8192),
            maps: original,
            pair,
            memory: memory_file,
            stack_start: stack[0].start,
            stack: stack_bytes,
        };
        assert_eq!(before.state.registers.rip, ENTRY);
        assert_eq!(before.state.registers.orig_rax, libc::SYS_execve as u64);
        assert_eq!(
            before.state.registers.rax,
            (-i64::from(libc::ENOSYS)) as u64
        );
        assert_eq!(&before.bytes[4096..4096 + CODE.len()], CODE);
        assert_eq!(&before.bytes[..7], b"\x7fELF\x02\x01\x01");
        for (header, flags, offset, address, length) in [
            (64, 4_u32, 0_u64, BASE, 288_u64),
            (120, 5, 4096, ENTRY, 4096),
        ] {
            assert_eq!(
                u32::from_le_bytes(before.bytes[header..header + 4].try_into().unwrap()),
                1
            );
            assert_eq!(
                u32::from_le_bytes(before.bytes[header + 4..header + 8].try_into().unwrap()),
                flags
            );
            for (field, value) in [
                (8, offset),
                (16, address),
                (32, length),
                (40, length),
                (48, 4096),
            ] {
                assert_eq!(
                    u64::from_le_bytes(
                        before.bytes[header + field..header + field + 8]
                            .try_into()
                            .unwrap()
                    ),
                    value
                );
            }
        }
        let initial = launched.event.stop_token().unwrap().clone();
        before.pristine(harness.owner(), &initial, until);
        action(harness.owner(), &initial, until, &before)
    }));
    if let Err(payload) = &outcome {
        panic_diagnostic(payload.as_ref());
    }
    let cleanup = harness.owner().cleanup().unwrap_or_else(|error| {
        diagnostic("physical cleanup", &format!("{error:?}"));
        std::process::abort()
    });
    assert_eq!(cleanup.reaped, [launched.pid]);
    reaped(&app);
    reaped(&broker_pin);
    let outcome = match outcome {
        Ok(value) => catch_unwind(AssertUnwindSafe(|| {
            after_cleanup(harness.owner(), &value);
            value
        })),
        Err(payload) => Err(payload),
    };
    assert!(harness.finish().reaped.is_empty());
    match outcome {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    }
}

pub(super) fn profile(options: &DynamicRuntimeOptions) -> InitialCaptureProfile {
    InitialCaptureProfile {
        max_vmas: options.capture.max_vmas,
        max_windows: options.capture.max_windows,
        max_window_bytes: options.capture.max_window_bytes,
        max_total_capture_bytes: options.capture.max_total_capture_bytes,
    }
}

pub(super) fn allocate(options: &DynamicRuntimeOptions, until: Instant) -> RuntimeOwner {
    RuntimeOwner::allocate(
        RuntimeStartOptions {
            capture: profile(options),
            limits: options.limits,
            kernel: options.kernel,
        },
        until,
    )
    .unwrap()
}
