use crate::{
    GateError, fault,
    plan::{InstructionExtent, PageBundle, Plan},
    raw,
    signal::SignalOwner,
};
use core::{
    marker::PhantomData,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
use std::rc::Rc;

pub(crate) const PREPARED: u8 = 0;
pub(crate) const ARMED: u8 = 1;
pub(crate) const POISONED: u8 = 2;
pub(crate) const CLOSED: u8 = 3;
pub(crate) const PENDING: u8 = 0;
pub(crate) const READY: u8 = 1;
static CLAIMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GateMetrics {
    /// Validation/table construction only; earlier core patch publication is
    /// measured separately by the caller and is not claimed as lazy patching.
    pub preparation_ns: u64,
    pub arm_ns: u64,
    pub faults: u64,
    pub admitted_pages: u64,
    /// Handler-internal elapsed sum through completed RX/sync; excludes kernel
    /// signal delivery and return. External fixture timing measures those too.
    pub first_touch_ns: u64,
    pub max_first_touch_ns: u64,
}

pub(crate) struct State {
    pub(crate) base: usize,
    pub(crate) len: usize,
    pub(crate) expected: *const u8,
    pub(crate) plan: Plan,
    pub(crate) pages: Vec<AtomicU8>,
    pub(crate) tid: isize,
    pub(crate) phase: AtomicU8,
    pub(crate) handling: AtomicBool,
    pub(crate) faults: AtomicU64,
    pub(crate) admitted_pages: AtomicU64,
    pub(crate) first_touch_ns: AtomicU64,
    pub(crate) max_first_touch_ns: AtomicU64,
    preparation_ns: u64,
    arm_ns: u64,
}

impl State {
    pub(crate) fn poison(&self) -> ! {
        self.phase.store(POISONED, Ordering::Release);
        raw::fatal()
    }
    pub(crate) fn equal_bytes(&self, start: usize, len: usize) -> bool {
        let Some(end) = start.checked_add(len).filter(|end| *end <= self.len) else {
            return false;
        };
        // SAFETY: the unsafe owner contract retains the entire readable
        // source and independent borrowed snapshot. Bounds were checked.
        unsafe {
            crate::plan::bytes_equal(
                (self.base as *const u8).add(start),
                self.expected.add(start),
                end - start,
            )
        }
    }
    fn metrics(&self) -> GateMetrics {
        GateMetrics {
            preparation_ns: self.preparation_ns,
            arm_ns: self.arm_ns,
            faults: self.faults.load(Ordering::Acquire),
            admitted_pages: self.admitted_pages.load(Ordering::Acquire),
            first_touch_ns: self.first_touch_ns.load(Ordering::Acquire),
            max_first_touch_ns: self.max_first_touch_ns.load(Ordering::Acquire),
        }
    }
}

/// Prepared data, still RX and without installed signal ownership. Neither this
/// value nor its armed successor can cross threads or outlive the borrowed owner.
pub struct PreparedGate<'a> {
    state: Box<State>,
    _owner: PhantomData<&'a mut ()>,
    _snapshot: PhantomData<&'a [u8]>,
    _thread: PhantomData<Rc<()>>,
}

impl<'a> PreparedGate<'a> {
    /// Validates/copies descriptive tables and verifies the independent final
    /// source snapshot. It does not patch source bytes or activate a handler.
    ///
    /// # Safety
    /// `owner` must retain this entire live mapping and every reachable installed
    /// core patch/trampoline. The source is private RX, immutable, and disjoint
    /// from this runtime, all active stacks, tables, and the independent snapshot.
    /// The complete final instruction extents and dependency bundles must be
    /// certified by the caller's real publication/entry contract, including all
    /// saved resumes. No caller may execute/read/write an excluded source alias
    /// during publication/activation/teardown. While armed, only this singleton
    /// thread may execute the source; no new threads, fork, mapping, signal-state,
    /// code-byte or executable-owner changes are allowed. All source invocations
    /// must have returned before disarm/Drop. The snapshot stays immutable.
    /// Forgetting/leaking an armed gate does not discharge these obligations:
    /// its borrowed source, snapshot and installed owners must then stay alive
    /// while the registered handler remains reachable.
    pub unsafe fn new<O: ?Sized>(
        _owner: &'a mut O,
        address: NonNull<u8>,
        final_bytes: &'a [u8],
        instructions: &[InstructionExtent],
        bundles: &[PageBundle],
    ) -> Result<Self, GateError> {
        let started = raw::now().ok_or(GateError::Invalid("preparation clock"))?;
        let base = address.as_ptr() as usize;
        let len = final_bytes.len();
        let plan = Plan::new(base, len, instructions, bundles)?;
        let snapshot_start = final_bytes.as_ptr() as usize;
        let snapshot_end = snapshot_start
            .checked_add(len)
            .ok_or(GateError::Invalid("snapshot end overflow"))?;
        if snapshot_start < base + len && base < snapshot_end {
            return Err(GateError::Invalid("snapshot aliases source"));
        }
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(plan.pages)
            .map_err(|_| GateError::Invalid("page-state allocation"))?;
        pages.extend((0..plan.pages).map(|_| AtomicU8::new(PENDING)));
        let mut state = Box::new(State {
            base,
            len,
            expected: final_bytes.as_ptr(),
            plan,
            pages,
            tid: 0,
            phase: AtomicU8::new(PREPARED),
            handling: AtomicBool::new(false),
            faults: AtomicU64::new(0),
            admitted_pages: AtomicU64::new(0),
            first_touch_ns: AtomicU64::new(0),
            max_first_touch_ns: AtomicU64::new(0),
            preparation_ns: 0,
            arm_ns: 0,
        });
        if !state.equal_bytes(0, len) {
            return Err(GateError::Invalid("final source bytes differ"));
        }
        state.preparation_ns = raw::now()
            .and_then(|end| end.checked_sub(started))
            .ok_or(GateError::Invalid("preparation elapsed clock"))?;
        Ok(Self {
            state,
            _owner: PhantomData,
            _snapshot: PhantomData,
            _thread: PhantomData,
        })
    }

    /// Confirms the actual kernel task registry has exactly this main thread,
    /// retains all signal resources, and makes the complete owned region NX.
    ///
    /// # Safety
    /// The complete ownership/exclusion contract of `new` must still hold.
    /// No invocation may be inside the source or generated callback while this
    /// function changes permissions. Ownership continues through Drop/disarm.
    pub unsafe fn arm(self) -> Result<ArmedGate<'a>, GateError> {
        let started = raw::now().ok_or(GateError::Invalid("arm clock"))?;
        let mut gate = ArmedGate {
            state: self.state,
            signals: None,
            registered: false,
            nx_started: false,
            closed: false,
            _owner: PhantomData,
            _snapshot: PhantomData,
            _thread: PhantomData,
        };
        if CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(GateError::Invalid("another in-process gate is registered"));
        }
        gate.registered = true;
        gate.state.tid = singleton()?;
        mapping_rx(gate.state.base, gate.state.len)?;
        raw::prepare_sync()?;
        let pointer = &mut *gate.state as *mut State;
        if fault::ACTIVE
            .compare_exchange(
                core::ptr::null_mut(),
                pointer,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            gate.state.poison();
        }
        gate.signals = Some(SignalOwner::install()?);
        // Signals are blocked. Recheck the actual registry, metadata and final
        // bytes before the first permission mutation; no user callback occurs.
        if singleton()? != gate.state.tid {
            return Err(GateError::Invalid("task identity changed"));
        }
        mapping_rx(gate.state.base, gate.state.len)?;
        if !gate.state.equal_bytes(0, gate.state.len) {
            return Err(GateError::Invalid("source changed before NX"));
        }
        gate.nx_started = true;
        if raw::protect(gate.state.base, gate.state.len, libc::PROT_READ) != 0
            || raw::synchronize() != 0
        {
            gate.state.poison();
        }
        gate.state.arm_ns = raw::now()
            .and_then(|end| end.checked_sub(started))
            .unwrap_or_else(|| gate.state.poison());
        gate.state.phase.store(ARMED, Ordering::Release);
        let restored = match gate.signals.as_mut() {
            Some(signals) => signals.release_mask().is_ok(),
            None => false,
        };
        if !restored {
            gate.state.poison();
        }
        Ok(gate)
    }
}

/// Actual in-process gate. The immutable global handler pointer is removed
/// before this owning state can be released. No source or patch owner is moved.
pub struct ArmedGate<'a> {
    state: Box<State>,
    signals: Option<SignalOwner>,
    registered: bool,
    nx_started: bool,
    closed: bool,
    _owner: PhantomData<&'a mut ()>,
    _snapshot: PhantomData<&'a [u8]>,
    _thread: PhantomData<Rc<()>>,
}

impl ArmedGate<'_> {
    /// Read-only counters. On the admitted singleton thread, no source fetch
    /// can occur concurrently with this method; nested foreign faults terminate.
    pub fn metrics(&self) -> GateMetrics {
        self.state.metrics()
    }

    /// Restores RX and the actual prior SIGSEGV/mask/altstack state. All source
    /// invocations must already have returned under the constructor contract.
    /// Uncertain physical restoration is fail-stop, never ordinary success.
    pub fn disarm(mut self) -> Result<GateMetrics, GateError> {
        self.close();
        Ok(self.state.metrics())
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        if let Some(signals) = self.signals.as_mut() {
            if signals.block().is_err() {
                self.state.poison();
            }
        }
        if self.nx_started {
            if raw::tid() != self.state.tid
                || singleton().ok() != Some(self.state.tid)
                || self.state.phase.load(Ordering::Acquire) != ARMED
                || self.state.handling.load(Ordering::Acquire)
                || !self.state.equal_bytes(0, self.state.len)
            {
                self.state.poison();
            }
            if raw::protect(
                self.state.base,
                self.state.len,
                libc::PROT_READ | libc::PROT_EXEC,
            ) != 0
                || raw::synchronize() != 0
            {
                self.state.poison();
            }
            self.nx_started = false;
        }
        if let Some(signals) = self.signals.as_mut() {
            if signals.close().is_err() {
                self.state.poison();
            }
        }
        if self.registered {
            let pointer = &mut *self.state as *mut State;
            // A setup refusal before ACTIVE installation legitimately sees null.
            let active = fault::ACTIVE.load(Ordering::Acquire);
            if !active.is_null() && active != pointer {
                self.state.poison();
            }
            fault::ACTIVE.store(core::ptr::null_mut(), Ordering::Release);
            CLAIMED.store(false, Ordering::Release);
            self.registered = false;
        }
        self.state.phase.store(CLOSED, Ordering::Release);
        self.closed = true;
    }
}
impl Drop for ArmedGate<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

fn singleton() -> Result<isize, GateError> {
    let tid = raw::tid();
    if tid <= 0 || tid != raw::pid() {
        return Err(GateError::Invalid("not singleton main thread"));
    }
    let tasks = std::fs::read_dir("/proc/self/task")
        .map_err(|_| GateError::Invalid("kernel task registry unavailable"))?;
    let mut count = 0_usize;
    for task in tasks {
        let task = task.map_err(|_| GateError::Invalid("kernel task registry read"))?;
        let name = task.file_name();
        let found = name
            .to_str()
            .and_then(|name| name.parse::<isize>().ok())
            .ok_or(GateError::Invalid("invalid kernel task identity"))?;
        if found != tid {
            return Err(GateError::Invalid("additional kernel task"));
        }
        count += 1;
    }
    if count != 1 {
        return Err(GateError::Invalid("kernel singleton count"));
    }
    Ok(tid)
}

fn mapping_rx(base: usize, len: usize) -> Result<(), GateError> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|_| GateError::Invalid("kernel maps unavailable"))?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields
            .next()
            .ok_or(GateError::Invalid("kernel map range absent"))?;
        let permissions = fields
            .next()
            .ok_or(GateError::Invalid("kernel map permissions absent"))?;
        let (lo, hi) = range
            .split_once('-')
            .ok_or(GateError::Invalid("kernel map range shape"))?;
        let lo = usize::from_str_radix(lo, 16).map_err(|_| GateError::Invalid("kernel map low"))?;
        let hi =
            usize::from_str_radix(hi, 16).map_err(|_| GateError::Invalid("kernel map high"))?;
        if lo <= base && base < hi {
            if hi < base + len || permissions != "r-xp" {
                return Err(GateError::Invalid(
                    "source is not one private readable RX mapping",
                ));
            }
            return Ok(());
        }
    }
    Err(GateError::Invalid("source mapping absent"))
}
