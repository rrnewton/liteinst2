//! Finite, flag-neutral BEFORE-taken-backedge clocks for four authored loops.
//!
//! The mapping and invocation constructors are unsafe ownership boundaries.
//! They do not hide source addresses already known to an installer. The caller
//! must exclude arbitrary external, recursive, signal-handler and fork entry.
//! These clocks count branch decisions, not retired branches or instructions.

use core::cell::{Cell, UnsafeCell};
use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::rc::Rc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::contracts::{AddressRange, CodeIdentity};
use crate::controls::{ControlWriter, ProbeControl};

/// Exact additional instrumentation data per instance, independent of code caps.
pub const CLOCK_PAGE_BYTES: usize = 4096;
/// Largest admitted work population in this finite profile.
pub const MAX_WORK: u64 = 32768;
/// Bytes outside the four generated words retain this value.
pub const CLOCK_CANARY: u8 = 0xa5;

/// Exact prefix read/written by generated code; all fields are aligned u64s.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClockWords {
    /// The application's RCX while the gate borrows that register.
    pub saved_rcx: u64,
    /// Number of visits, including untaken conditional branches.
    pub encounters: u64,
    /// Number of taken original branch decisions.
    pub counted: u64,
    /// Taken decisions left before the next synchronous stop.
    pub remaining: u64,
}
const _: () = assert!(core::mem::size_of::<ClockWords>() == 32);
const _: () = assert!(core::mem::offset_of!(ClockWords, saved_rcx) == 0);
const _: () = assert!(core::mem::offset_of!(ClockWords, encounters) == 8);
const _: () = assert!(core::mem::offset_of!(ClockWords, counted) == 16);
const _: () = assert!(core::mem::offset_of!(ClockWords, remaining) == 24);

/// Finite-profile admission or ownership refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    /// Unsupported platform or malformed/non-owned mapping geometry.
    Mapping,
    /// Fork, duplicate owner, or wrong actual thread.
    Owner,
    /// Invalid quantum, work population, or reentrant invocation.
    Invocation,
    /// Source or managed-control identity is outside this profile.
    Source,
}

struct Storage {
    page: NonNull<UnsafeCell<[u8; CLOCK_PAGE_BYTES]>>,
    pid: u32,
    active: AtomicBool,
}
// Unsafe constructors require sole mapping ownership. Generated writes and
// controller reads are serialized by the explicit lease/event handoff contract.
unsafe impl Send for Storage {}
unsafe impl Sync for Storage {}
impl Drop for Storage {
    fn drop(&mut self) {
        // An unproven active invocation retains its mapping. Executable owners
        // also retain this Arc through their existing process-lived path.
        if self.active.load(Ordering::Acquire) || self.pid != std::process::id() {
            return;
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        unsafe {
            libc::munmap(self.page.as_ptr().cast(), CLOCK_PAGE_BYTES);
        }
    }
}

/// Shared ownership of one separate RW, non-executable, non-aliased clock page.
#[derive(Clone)]
pub struct BackedgeClock {
    inner: Arc<Storage>,
}
impl fmt::Debug for BackedgeClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackedgeClock")
            .field("address", &self.address())
            .finish()
    }
}
impl PartialEq for BackedgeClock {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}
impl Eq for BackedgeClock {}
impl BackedgeClock {
    /// Adopt exactly one private, aligned RW page and initialize its canaries.
    /// Ownership transfers only on success; no new mapping is allocated here.
    ///
    /// # Safety
    /// The caller exclusively owns a live anonymous 4096-byte RW/non-X mapping
    /// at `address`, with no shared alias, Rust reference, other unmapping owner,
    /// or overlap with any source, executable image or application storage.
    /// Splitting an adjacent anonymous mapping must transfer this exact page.
    /// Every path entering generated code must use an exclusive run lease;
    /// arbitrary externally known source addresses remain the caller's duty.
    pub unsafe fn from_owned_mapping(address: u64, len: usize) -> Result<Self, ClockError> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64"))
            || len != CLOCK_PAGE_BYTES
            || address == 0
            || address % 4096 != 0
            || address.checked_add(4096).is_none()
            || usize::try_from(address).is_err()
        {
            return Err(ClockError::Mapping);
        }
        let page = NonNull::new(address as usize as *mut UnsafeCell<[u8; CLOCK_PAGE_BYTES]>)
            .ok_or(ClockError::Mapping)?;
        // SAFETY: exclusive mapping ownership is the constructor precondition.
        unsafe {
            page.as_ptr()
                .cast::<u8>()
                .write_bytes(CLOCK_CANARY, CLOCK_PAGE_BYTES);
            page.as_ptr()
                .cast::<ClockWords>()
                .write(ClockWords::default());
        }
        Ok(Self {
            inner: Arc::new(Storage {
                page,
                pid: std::process::id(),
                active: AtomicBool::new(false),
            }),
        })
    }
    /// Mapping address for checked code generation and ownership diagnostics.
    pub fn address(&self) -> u64 {
        self.inner.page.as_ptr() as usize as u64
    }
    /// Complete, separate instrumentation data range.
    pub fn range(&self) -> AddressRange {
        AddressRange::new(self.address(), CLOCK_PAGE_BYTES).expect("validated clock page")
    }
    /// Acquire/reset the clock before private callable entry on the current thread.
    ///
    /// # Safety
    /// The caller has excluded *every* external entry into code using this page,
    /// including signal handlers and addresses known before installation. The
    /// preceding worker, if any, has joined. `max_work` bounds every encounter
    /// and taken count during this lease. Source and control binding are checked
    /// separately by the finite runtime owner before exposing callable entry.
    pub unsafe fn acquire(&self, quantum: u64, max_work: u64) -> Result<ClockLease, ClockError> {
        if quantum == 0 || max_work == 0 || max_work > MAX_WORK {
            return Err(ClockError::Invocation);
        }
        if self.inner.pid != std::process::id()
            || self
                .inner
                .active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(ClockError::Owner);
        }
        let lease = ClockLease {
            clock: self.clone(),
            tid: thread_id(),
            in_call: Cell::new(false),
            _thread: PhantomData,
        };
        // SAFETY: idle-to-active ownership precedes any callable entry.
        unsafe {
            lease
                .clock
                .inner
                .page
                .as_ptr()
                .cast::<ClockWords>()
                .write(ClockWords {
                    remaining: quantum,
                    ..ClockWords::default()
                });
        }
        Ok(lease)
    }
    /// Read the generated words and complete canary tail at a proven safe handoff.
    ///
    /// # Safety
    /// No generated write may occur concurrently: the current exclusive worker
    /// is outside generated execution (including inside its slow callback), the
    /// exact worker is parked between its release/acquire event and matching
    /// resume, or no worker is active and the preceding worker, if any, joined.
    pub unsafe fn snapshot_parked(&self) -> (ClockWords, [u8; CLOCK_PAGE_BYTES - 32]) {
        let p = self.inner.page.as_ptr().cast::<u8>();
        // SAFETY: handoff exclusion is required above; no shared Rust references
        // alias the generated writes. Volatile does not itself supply a barrier.
        unsafe {
            (
                p.cast::<ClockWords>().read_volatile(),
                std::array::from_fn(|i| p.add(32 + i).read_volatile()),
            )
        }
    }
    /// Refill only the just-observed zero word before the slow callback returns.
    ///
    /// # Safety
    /// The exact active worker owns the callback and has authenticated the clock,
    /// site/control/PID/TID plus matching resume. Generated execution is stopped.
    pub unsafe fn refill_after_resume(&self, quantum: u64) -> Result<(), ClockError> {
        if quantum == 0
            || self.inner.pid != std::process::id()
            || !self.inner.active.load(Ordering::Acquire)
        {
            return Err(ClockError::Invocation);
        }
        let p = self.inner.page.as_ptr().cast::<ClockWords>();
        unsafe {
            if core::ptr::addr_of!((*p).remaining).read_volatile() != 0 {
                return Err(ClockError::Invocation);
            }
            core::ptr::addr_of_mut!((*p).remaining).write_volatile(quantum);
        }
        Ok(())
    }
}
fn thread_id() -> i64 {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        unsafe { libc::syscall(libc::SYS_gettid) }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        -1
    }
}

/// Non-Clone, non-Send worker lease. Drop is not an execution-drain proof.
///
/// ```compile_fail
/// use liteinst2::backedge_clock::ClockLease;
/// fn require_send<T: Send>() {}
/// require_send::<ClockLease>();
/// ```
///
/// ```compile_fail
/// use liteinst2::backedge_clock::ClockLease;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ClockLease>();
/// ```
pub struct ClockLease {
    clock: BackedgeClock,
    tid: i64,
    in_call: Cell<bool>,
    _thread: PhantomData<Rc<()>>,
}
impl ClockLease {
    /// Check and mark private invocation before the first generated spill.
    pub fn begin_call(&self) -> Result<ClockCall<'_>, ClockError> {
        if self.clock.inner.pid != std::process::id() || self.tid != thread_id() {
            return Err(ClockError::Owner);
        }
        if self.in_call.replace(true) {
            return Err(ClockError::Invocation);
        }
        Ok(ClockCall { lease: self })
    }
}
impl Drop for ClockLease {
    fn drop(&mut self) {
        if !self.in_call.get()
            && self.clock.inner.pid == std::process::id()
            && self.tid == thread_id()
        {
            self.clock.inner.active.store(false, Ordering::Release);
        }
    }
}
/// Retains the in-call guard until the exact native call has returned.
pub struct ClockCall<'a> {
    lease: &'a ClockLease,
}
impl Drop for ClockCall<'_> {
    fn drop(&mut self) {
        self.lease.in_call.set(false);
    }
}

/// Explicit hot-path flavor; no ordinary control changes interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockMode {
    /// Charge encounters/taken decisions, with no callback or decrement.
    Counter,
    /// Charge, decrement, and enter the full-save callback only at zero.
    Stop,
}

/// Actual encoded comparison boundaries; no callback instruction has run at either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockGateLayout {
    /// Original logical head's generated route, before the first RCX spill.
    pub entry: u64,
    /// Slow zero path immediately before the unchanged full-save helper.
    pub observing_entry: u64,
    /// Fast path immediately before the unchanged relocated original branch.
    pub original_body: u64,
}

/// Exact finite source, site, control and retained mapping supplied before emission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackedgeClockAction {
    pub(crate) identity: CodeIdentity,
    pub(crate) logical_pc: u64,
    pub(crate) control: ProbeControl,
    pub(crate) clock: BackedgeClock,
    pub(crate) mode: ClockMode,
    pub(crate) source: Vec<u8>,
    pub(crate) base: u64,
    pub(crate) condition: Option<u8>,
}
impl BackedgeClockAction {
    /// Bind one of the exact four authored functions, never an arbitrary loop.
    /// Consumes the exact unique writer so the clock callback cannot later be
    /// disabled by a planner-readable clone. The caller still owns mapping,
    /// callback and external-entry safety.
    pub fn new(
        identity: CodeIdentity,
        base: u64,
        source: &[u8],
        logical_pc: u64,
        managed: (ProbeControl, ControlWriter),
        clock: BackedgeClock,
        mode: ClockMode,
    ) -> Result<Self, ClockError> {
        let (control, writer) = managed;
        let (offset, condition) = authored_source(source).ok_or(ClockError::Source)?;
        if identity.mapping != base
            || identity.generation == 0
            || base.checked_add(offset as u64) != Some(logical_pc)
            || !control.is_managed_bound()
            || !writer.matches(&control)
            || !control.is_enabled()
            || AddressRange::new(base, source.len())
                .map_err(|_| ClockError::Source)?
                .overlaps(clock.range())
        {
            return Err(ClockError::Source);
        }
        Ok(Self {
            identity,
            logical_pc,
            control,
            clock,
            mode,
            source: source.to_vec(),
            base,
            condition,
        })
    }
    /// Retained exact clock owner (no generated-code lifetime transfer).
    pub fn clock(&self) -> &BackedgeClock {
        &self.clock
    }
    /// Exact managed callback binding.
    pub fn control(&self) -> &ProbeControl {
        &self.control
    }
}

// Independent literal source identities, copied from the four reviewed authored
// functions. No generic decoder predicate can silently enlarge this population.
fn authored_source(bytes: &[u8]) -> Option<(usize, Option<u8>)> {
    const COUNTDOWN: &[u8] = &[
        0x31, 0xc0, 0x31, 0xd2, 0x48, 0x89, 0xf9, 0x48, 0x01, 0xc8, 0x48, 0xff, 0xc2, 0x48, 0xff,
        0xc9, 0x48, 0x89, 0x06, 0x48, 0x89, 0x4e, 0x08, 0x48, 0x89, 0x56, 0x10, 0x0f, 0x85, 0xe6,
        0xff, 0xff, 0xff, 0xc3,
    ];
    const SIGNED: &[u8] = &[
        0x31, 0xc0, 0x31, 0xd2, 0x48, 0x89, 0xf9, 0x48, 0x01, 0xc8, 0x48, 0xff, 0xc2, 0x48, 0xff,
        0xc9, 0x48, 0x89, 0x06, 0x48, 0x89, 0x4e, 0x08, 0x48, 0x89, 0x56, 0x10, 0x0f, 0x8f, 0xe6,
        0xff, 0xff, 0xff, 0xc3,
    ];
    const UNSIGNED: &[u8] = &[
        0x31, 0xc0, 0x31, 0xd2, 0x31, 0xc9, 0x48, 0x83, 0xc0, 0x03, 0x48, 0xff, 0xc2, 0x48, 0xff,
        0xc1, 0x48, 0x89, 0x06, 0x48, 0x89, 0x4e, 0x08, 0x48, 0x89, 0x56, 0x10, 0x48, 0x39, 0xf9,
        0x0f, 0x82, 0xe2, 0xff, 0xff, 0xff, 0xc3,
    ];
    const DIRECT: &[u8] = &[
        0x31, 0xc0, 0x31, 0xd2, 0x48, 0x89, 0xf9, 0x48, 0x01, 0xc8, 0x48, 0xff, 0xc2, 0x48, 0xff,
        0xc9, 0x48, 0x89, 0x06, 0x48, 0x89, 0x4e, 0x08, 0x48, 0x89, 0x56, 0x10, 0x74, 0x05, 0xe9,
        0xe5, 0xff, 0xff, 0xff, 0xc3,
    ];
    if bytes == COUNTDOWN {
        Some((27, Some(5)))
    } else if bytes == SIGNED {
        Some((27, Some(15)))
    } else if bytes == UNSIGNED {
        Some((30, Some(2)))
    } else if bytes == DIRECT {
        Some((29, None))
    } else {
        None
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
