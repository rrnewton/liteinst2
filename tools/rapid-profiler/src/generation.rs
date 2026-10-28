//! Bounded, ordinary-Rust generation bookkeeping. No probe or timer is installed.
//!
//! Tickets retain their admitting epoch. This is not signal-safe storage, a
//! physical code-change protocol, or a proof that nonlocal exits run Rust Drop.
#![deny(warnings)]
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

const CLOSED: usize = 1 << (usize::BITS - 1);
const COUNT_MASK: usize = CLOSED - 1;
/// Maximum functions admitted when constructing one epoch.
pub const MAX_FUNCTIONS: usize = 4096;
/// Maximum lifetime invocation records allocated for one epoch.
pub const MAX_RECORDS: usize = 1_048_576;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Process-local generation identity that is never intentionally reused.
pub struct GenerationId(u64);

impl GenerationId {
    /// Return the opaque numeric identity for diagnostics and record comparison.
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Caller-selected identity of one function within an epoch.
pub struct FunctionId(
    /// The caller's integer function key.
    pub u64,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Independent per-function retention and global storage limits.
pub struct Config {
    /// Maximum completed records retained for each function (K).
    pub retained_per_function: usize,
    /// Maximum simultaneous reservations across all functions (M).
    pub max_inflight: usize,
    /// Maximum lifetime admissions across all functions (A); slots are not recycled.
    pub max_invocations: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A constructor refusal before an epoch is returned.
pub enum CreateError {
    /// The requested function set is empty.
    EmptyFunctions,
    /// The function count exceeds [`MAX_FUNCTIONS`].
    TooManyFunctions,
    /// The requested function set contains duplicate identities.
    DuplicateFunction,
    /// The per-function retention budget is zero.
    ZeroRetainedBudget,
    /// The global reservation limit is zero or exceeds the counter range.
    InvalidInflightLimit,
    /// The lifetime record limit is zero or exceeds [`MAX_RECORDS`].
    InvalidInvocationLimit,
    /// Bounded storage allocation failed.
    Allocation,
    /// The process-local generation identity space is exhausted.
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A rejected admission that returns no ticket.
pub enum AdmissionRefusal {
    /// The function is absent from this epoch.
    UnknownFunction,
    /// This function has closed admission.
    FunctionClosed,
    /// The entire epoch has closed admission.
    EpochClosed,
    /// The global concurrent-reservation limit is reached.
    InflightLimit,
    /// Lifetime invocation storage is exhausted; the epoch is closed.
    StorageExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Immutable identity and caller value captured for one accepted invocation.
pub struct Admission {
    /// The epoch that admitted the invocation.
    pub generation: GenerationId,
    /// The invocation slot in that epoch; never reused within the epoch.
    pub invocation: usize,
    /// The caller-selected function identity.
    pub function: FunctionId,
    /// Opaque caller data; this component does not qualify a timestamp source.
    pub entry_value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Whether a completed invocation obtained a retention reservation.
pub enum Disposition {
    /// Zero-based rank in this function's successful retention reservations.
    Retained {
        /// The zero-based retained reservation index for this function.
        rank: usize,
    },
    /// The invocation completed after all retention reservations were taken.
    DroppedAfterBudget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// How a ticket reached cancellation instead of completion.
pub enum CancelReason {
    /// The owner explicitly called [`Ticket::cancel`].
    Explicit,
    /// An unfinished ticket was dropped through ordinary Rust cleanup.
    DroppedTicket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// The single terminal outcome published for an admitted invocation.
pub enum Terminal {
    /// A completed invocation and its independent retention disposition.
    Completed {
        /// Opaque caller-supplied completion data, not a qualified clock value.
        value: u64,
        /// Whether this completion obtained a retention reservation.
        disposition: Disposition,
    },
    /// Cancellation without consuming a retention reservation.
    Cancelled(CancelReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// An admission and its optional terminal observation.
pub struct Record {
    /// The immutable identity recorded at admission.
    pub admission: Admission,
    /// The terminal outcome, or `None` while its publication is not observed.
    pub terminal: Option<Terminal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A request to deactivate one function in its original generation.
pub struct DeactivationRequest {
    /// The generation to which this request belongs.
    pub generation: GenerationId,
    /// The function whose retention reservations reached K.
    pub function: FunctionId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Result of completing one ticket in its admitting epoch.
pub struct Completion {
    /// The identity retained by the completed ticket.
    pub admission: Admission,
    /// This completion's retention outcome.
    pub disposition: Disposition,
    /// A generation-scoped request, not evidence of any physical change.
    pub deactivate: Option<DeactivationRequest>,
    /// Global reservations observed after closing the function, excluding this
    /// still-held ticket. This is not the number of completions after K.
    pub other_reservations_after_close: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Counts derived from the published records for one function.
pub struct Population {
    /// Published admissions observed for this function.
    pub admitted: usize,
    /// Observed completed invocations, retained or dropped.
    pub completed: usize,
    /// Completed invocations that reserved retained storage.
    pub retained: usize,
    /// Completed invocations that did not reserve retained storage.
    pub dropped: usize,
    /// Observed explicit or drop cancellations.
    pub cancelled: usize,
    /// Admissions with no terminal outcome observed.
    pub unfinished: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A per-function record observation with an explicit finality flag.
pub struct PopulationObservation {
    /// The observed record population.
    pub population: Population,
    /// True only after closed+zero was acquired before reading the records.
    pub final_report: bool,
}

struct Function {
    id: FunctionId,
    retained: AtomicUsize,
    closed: AtomicBool,
}

struct Slot {
    admission: OnceLock<Admission>,
    terminal: OnceLock<Terminal>,
}

/// Immutable generation owner with bounded preallocated raw record storage.
/// Generation IDs are process-local; cross-fork/process identity is unqualified.
pub struct Epoch {
    id: GenerationId,
    config: Config,
    functions: Vec<Function>,
    slots: Vec<Slot>,
    state: AtomicUsize,
    assigned: AtomicUsize,
}

fn allocate_id(next: &AtomicU64) -> Result<GenerationId, CreateError> {
    next.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        if value == 0 || value == u64::MAX {
            None
        } else {
            Some(value + 1)
        }
    })
    .map(GenerationId)
    .map_err(|_| CreateError::GenerationExhausted)
}

impl Epoch {
    /// Allocate an epoch with distinct functions and validated finite limits.
    /// Returns a typed refusal if limits, identities or storage cannot be established.
    pub fn new(function_ids: &[FunctionId], config: Config) -> Result<Self, CreateError> {
        if function_ids.is_empty() {
            return Err(CreateError::EmptyFunctions);
        }
        if function_ids.len() > MAX_FUNCTIONS {
            return Err(CreateError::TooManyFunctions);
        }
        if function_ids
            .iter()
            .enumerate()
            .any(|(i, id)| function_ids[..i].contains(id))
        {
            return Err(CreateError::DuplicateFunction);
        }
        if config.retained_per_function == 0 {
            return Err(CreateError::ZeroRetainedBudget);
        }
        if config.max_inflight == 0 || config.max_inflight > COUNT_MASK {
            return Err(CreateError::InvalidInflightLimit);
        }
        if config.max_invocations == 0 || config.max_invocations > MAX_RECORDS {
            return Err(CreateError::InvalidInvocationLimit);
        }
        let mut functions = Vec::new();
        functions
            .try_reserve_exact(function_ids.len())
            .map_err(|_| CreateError::Allocation)?;
        for &id in function_ids {
            functions.push(Function {
                id,
                retained: AtomicUsize::new(0),
                closed: AtomicBool::new(false),
            });
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(config.max_invocations)
            .map_err(|_| CreateError::Allocation)?;
        for _ in 0..config.max_invocations {
            slots.push(Slot {
                admission: OnceLock::new(),
                terminal: OnceLock::new(),
            });
        }
        Ok(Self {
            id: allocate_id(&NEXT_GENERATION)?,
            config,
            functions,
            slots,
            state: AtomicUsize::new(0),
            assigned: AtomicUsize::new(0),
        })
    }

    /// Return this epoch's process-local identity.
    pub fn id(&self) -> GenerationId {
        self.id
    }

    /// Return the immutable limits with which this epoch was created.
    pub fn config(&self) -> Config {
        self.config
    }

    /// Reserve one invocation in this epoch and return its non-Clone ticket.
    /// The entry value is opaque data; acceptance does not qualify a clock or frontend.
    pub fn enter(
        &self,
        function: FunctionId,
        entry_value: u64,
    ) -> Result<Ticket<'_>, AdmissionRefusal> {
        let (function_index, slot) = self.reserve(function, entry_value)?;
        Ok(Ticket {
            epoch: self,
            function_index,
            slot,
            active: true,
        })
    }

    /// Reserve an invocation and retain its epoch without borrowing its caller.
    /// This capability retains only Epoch; frontend storage permits are separate.
    pub fn enter_owned(
        self: &Arc<Self>,
        function: FunctionId,
        entry_value: u64,
    ) -> Result<OwnedTicket, AdmissionRefusal> {
        let (function_index, slot) = self.reserve(function, entry_value)?;
        Ok(OwnedTicket {
            epoch: Arc::clone(self),
            function_index,
            slot,
            active: true,
        })
    }

    fn reserve(
        &self,
        function: FunctionId,
        entry_value: u64,
    ) -> Result<(usize, usize), AdmissionRefusal> {
        let index = self
            .functions
            .iter()
            .position(|row| row.id == function)
            .ok_or(AdmissionRefusal::UnknownFunction)?;
        let row = &self.functions[index];
        if row.closed.load(Ordering::Acquire) {
            return Err(AdmissionRefusal::FunctionClosed);
        }
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & CLOSED != 0 {
                return Err(AdmissionRefusal::EpochClosed);
            }
            if state & COUNT_MASK >= self.config.max_inflight {
                return Err(AdmissionRefusal::InflightLimit);
            }
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => state = observed,
            }
        }
        // A function close between the first check and the reservation may
        // conservatively refuse. Every accepted ticket reserved before close.
        if row.closed.load(Ordering::Acquire) {
            self.release();
            return Err(AdmissionRefusal::FunctionClosed);
        }
        let slot = match self
            .assigned
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                if value < self.config.max_invocations {
                    Some(value + 1)
                } else {
                    None
                }
            }) {
            Ok(slot) => slot,
            Err(_) => {
                self.close();
                self.release();
                return Err(AdmissionRefusal::StorageExhausted);
            }
        };
        let admission = Admission {
            generation: self.id,
            invocation: slot,
            function,
            entry_value,
        };
        assert!(self.slots[slot].admission.set(admission).is_ok());
        Ok((index, slot))
    }

    /// Close admission without cancelling any existing ticket. Returned count
    /// includes reservations that may still be creating/refusing a ticket.
    pub fn close(&self) -> usize {
        self.state.fetch_or(CLOSED, Ordering::AcqRel) & COUNT_MASK
    }

    /// Observe whether epoch-wide admission has been closed.
    pub fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) & CLOSED != 0
    }

    /// Observe the current count of global admission reservations.
    /// This includes reservations whose admission record is not yet published.
    pub fn reservations(&self) -> usize {
        self.state.load(Ordering::Acquire) & COUNT_MASK
    }

    /// Observe a known function's admission flag, or `None` for an unknown function.
    pub fn function_closed(&self, function: FunctionId) -> Option<bool> {
        self.functions
            .iter()
            .find(|row| row.id == function)
            .map(|row| row.closed.load(Ordering::Acquire))
    }

    /// A partial per-record observation, not a coherent instantaneous snapshot.
    /// Assigned but unpublished reservations appear only in reservations().
    pub fn records(&self) -> impl Iterator<Item = Record> + '_ {
        self.slots.iter().filter_map(|slot| {
            slot.admission.get().copied().map(|admission| Record {
                admission,
                terminal: slot.terminal.get().copied(),
            })
        })
    }

    /// Observe one function's records; only a final report is stable after drain.
    /// Concurrent partial fields need not form one instantaneous snapshot.
    pub fn population(&self, function: FunctionId) -> Option<PopulationObservation> {
        if !self.functions.iter().any(|row| row.id == function) {
            return None;
        }
        let final_report = self.state.load(Ordering::Acquire) == CLOSED;
        let mut population = Population::default();
        for record in self
            .records()
            .filter(|record| record.admission.function == function)
        {
            population.admitted += 1;
            match record.terminal {
                Some(Terminal::Completed { disposition, .. }) => {
                    population.completed += 1;
                    match disposition {
                        Disposition::Retained { .. } => population.retained += 1,
                        Disposition::DroppedAfterBudget => population.dropped += 1,
                    }
                }
                Some(Terminal::Cancelled(_)) => population.cancelled += 1,
                None => population.unfinished += 1,
            }
        }
        Some(PopulationObservation {
            population,
            final_report,
        })
    }

    /// Returns final access only after all record writes precede closed+zero.
    pub fn try_drain(&self) -> Option<Drained<'_>> {
        if self.state.load(Ordering::Acquire) == CLOSED {
            Some(Drained { epoch: self })
        } else {
            None
        }
    }

    fn complete_ticket(
        &self,
        function_index: usize,
        slot: usize,
        active: &mut bool,
        value: u64,
        before_close: impl FnOnce(),
    ) -> Completion {
        let epoch = self;
        let row = &epoch.functions[function_index];
        let rank = row
            .retained
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                if count < epoch.config.retained_per_function {
                    Some(count + 1)
                } else {
                    None
                }
            });
        let disposition = match rank {
            Ok(rank) => Disposition::Retained { rank },
            Err(_) => Disposition::DroppedAfterBudget,
        };
        let mut deactivate = None;
        let mut other_reservations_after_close = None;
        if rank.is_ok_and(|rank| rank + 1 == epoch.config.retained_per_function) {
            before_close();
            row.closed.store(true, Ordering::Release);
            let count = epoch.state.load(Ordering::Acquire) & COUNT_MASK;
            assert!(count >= 1 && count <= epoch.config.max_inflight);
            other_reservations_after_close = Some(count - 1);
            deactivate = Some(DeactivationRequest {
                generation: epoch.id,
                function: row.id,
            });
        }
        let admission = *epoch.slots[slot].admission.get().expect("published ticket");
        assert!(
            epoch.slots[slot]
                .terminal
                .set(Terminal::Completed { value, disposition })
                .is_ok()
        );
        *active = false;
        epoch.release();
        Completion {
            admission,
            disposition,
            deactivate,
            other_reservations_after_close,
        }
    }

    fn cancel_ticket(&self, slot: usize, active: &mut bool, reason: CancelReason) {
        assert!(
            self.slots[slot]
                .terminal
                .set(Terminal::Cancelled(reason))
                .is_ok()
        );
        *active = false;
        self.release();
    }

    fn release(&self) {
        let old = self.state.fetch_sub(1, Ordering::AcqRel);
        assert!(old & COUNT_MASK != 0);
    }
}

/// Read-only access established after epoch closure and zero reservations.
pub struct Drained<'a> {
    epoch: &'a Epoch,
}

impl Drained<'_> {
    /// Return the identity of the drained epoch.
    pub fn generation(&self) -> GenerationId {
        self.epoch.id
    }

    /// Iterate every published admission with its required terminal outcome.
    pub fn records(&self) -> impl Iterator<Item = (Admission, Terminal)> + '_ {
        self.epoch.records().map(|row| {
            (
                row.admission,
                row.terminal.expect("drain requires terminal records"),
            )
        })
    }

    /// Return a stable population for a known function after drain.
    pub fn population(&self, function: FunctionId) -> Option<Population> {
        self.epoch.population(function).map(|row| {
            assert!(row.final_report && row.population.unfinished == 0);
            row.population
        })
    }
}

/// A non-Clone capability for exactly one terminal outcome in its admitting
/// epoch. Forgetting a ticket intentionally prevents drain; Drop is ordinary
/// Rust cancellation only, not a signal/exception/longjmp frontend guarantee.
///
/// ```compile_fail
/// use rapid_profiler::generation::{Config, Epoch, FunctionId};
/// let e = Epoch::new(&[FunctionId(1)], Config { retained_per_function: 1, max_inflight: 1, max_invocations: 1 }).unwrap();
/// let t = e.enter(FunctionId(1), 0).unwrap();
/// let duplicate = t.clone();
/// ```
///
/// ```compile_fail
/// use rapid_profiler::generation::{Config, Epoch, FunctionId};
/// let e = Epoch::new(&[FunctionId(1)], Config { retained_per_function: 1, max_inflight: 1, max_invocations: 1 }).unwrap();
/// let t = e.enter(FunctionId(1), 0).unwrap();
/// t.complete(1);
/// t.complete(2);
/// ```
pub struct Ticket<'a> {
    epoch: &'a Epoch,
    function_index: usize,
    slot: usize,
    active: bool,
}

impl Ticket<'_> {
    /// Return the immutable identity held by this ticket.
    pub fn admission(&self) -> Admission {
        *self.epoch.slots[self.slot]
            .admission
            .get()
            .expect("published ticket")
    }

    /// Publish completion data and consume this ticket in its original epoch.
    /// Only the first K retention reservations per function are retained. The final
    /// reservation returns a generation-scoped deactivation request, not a code edit.
    pub fn complete(self, value: u64) -> Completion {
        self.complete_before_close(value, || {})
    }

    // Private no-op in ordinary builds; tests use the identical path to pause
    // the Kth reservation before closure. It is not a public callback surface.
    fn complete_before_close(mut self, value: u64, before_close: impl FnOnce()) -> Completion {
        self.epoch.complete_ticket(
            self.function_index,
            self.slot,
            &mut self.active,
            value,
            before_close,
        )
    }

    /// Publish explicit cancellation and consume the ticket without consuming K.
    pub fn cancel(mut self) {
        self.cancel_inner(CancelReason::Explicit);
    }

    fn cancel_inner(&mut self, reason: CancelReason) {
        self.epoch
            .cancel_ticket(self.slot, &mut self.active, reason);
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        if self.active {
            self.cancel_inner(CancelReason::DroppedTicket);
        }
    }
}

/// Non-Clone admission capability retaining only its original Epoch.
/// Forgetting it retains Epoch and its reservation, not a separate frontend permit.
///
/// ```compile_fail,E0599
/// use std::sync::Arc;
/// use rapid_profiler::generation::{Config, Epoch, FunctionId};
/// let e = Arc::new(Epoch::new(&[FunctionId(1)], Config { retained_per_function: 1, max_inflight: 1, max_invocations: 1 }).unwrap());
/// let t = e.enter_owned(FunctionId(1), 0).unwrap();
/// let duplicate = t.clone();
/// ```
///
/// ```compile_fail,E0382
/// use std::sync::Arc;
/// use rapid_profiler::generation::{Config, Epoch, FunctionId};
/// let e = Arc::new(Epoch::new(&[FunctionId(1)], Config { retained_per_function: 1, max_inflight: 1, max_invocations: 1 }).unwrap());
/// let t = e.enter_owned(FunctionId(1), 0).unwrap();
/// t.complete(1);
/// t.complete(2);
/// ```
pub struct OwnedTicket {
    epoch: Arc<Epoch>,
    function_index: usize,
    slot: usize,
    active: bool,
}

impl OwnedTicket {
    /// Return this ticket's immutable admitting identity.
    pub fn admission(&self) -> Admission {
        *self.epoch.slots[self.slot]
            .admission
            .get()
            .expect("published ticket")
    }

    /// Publish completion to the original owner and consume the capability.
    pub fn complete(self, value: u64) -> Completion {
        self.complete_before_close(value, || {})
    }

    // Same private pause seam as the borrowed ticket; ordinary callers pass no-op.
    pub(crate) fn complete_before_close(
        mut self,
        value: u64,
        before_close: impl FnOnce(),
    ) -> Completion {
        self.epoch.complete_ticket(
            self.function_index,
            self.slot,
            &mut self.active,
            value,
            before_close,
        )
    }

    /// Cancel explicitly without consuming the per-function retention budget.
    pub fn cancel(mut self) {
        self.epoch
            .cancel_ticket(self.slot, &mut self.active, CancelReason::Explicit);
    }
}

impl Drop for OwnedTicket {
    fn drop(&mut self) {
        if self.active {
            self.epoch
                .cancel_ticket(self.slot, &mut self.active, CancelReason::DroppedTicket);
        }
    }
}

#[cfg(test)]
mod owned_tests;

#[cfg(test)]
mod tests;

// Crate-private fixed-vector ownership, separate from legacy construction.
pub(crate) mod storage;
