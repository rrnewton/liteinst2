//! Fixed process-lifetime observations. No registry, TLS, reset or allocation.

use core::sync::atomic::{AtomicU64, Ordering};

use super::SelectedKind;

/// Actual callback observations for one selected class in this process.
///
/// Read while selected execution is excluded. Fields are separate atomics, not
/// a coherent concurrent snapshot. Counters never reset or wrap. Differences
/// between two quiescent snapshots describe the intervening actual callbacks;
/// they do not assert that the caller used only one logical site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedClassCounters {
    /// Callbacks entered, including ones that subsequently refused or faulted.
    pub entered: u64,
    /// Native results applied successfully to the saved context.
    pub completed: u64,
    /// Completed RDRAND/RDSEED operations whose actual carry was clear.
    pub carry_clear: u64,
    /// Genuine first callback's original instruction address, if any.
    pub first_logical_pc: Option<u64>,
    /// Genuine most recent callback's original instruction address, if any.
    pub last_logical_pc: Option<u64>,
}

pub(super) struct Counters {
    entered: AtomicU64,
    completed: AtomicU64,
    carry_clear: AtomicU64,
    first_pc: AtomicU64,
    last_pc: AtomicU64,
}

impl Counters {
    pub(super) const fn new() -> Self {
        Self {
            entered: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            carry_clear: AtomicU64::new(0),
            first_pc: AtomicU64::new(0),
            last_pc: AtomicU64::new(0),
        }
    }

    pub(super) fn enter(&self, pc: u64) -> bool {
        let Ok(previous) = self
            .entered
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
        else {
            return false;
        };
        if previous == 0 {
            self.first_pc.store(pc, Ordering::Relaxed);
        }
        self.last_pc.store(pc, Ordering::Relaxed);
        true
    }

    pub(super) fn complete(&self, carry_clear: bool) -> bool {
        // Caller exclusion makes each callback's transition indivisible with
        // respect to other callback writers. Refuse overflow before modifying
        // either completion field; no wrapped count can report success.
        let Some(completed) = self.completed.load(Ordering::Relaxed).checked_add(1) else {
            return false;
        };
        let failures = self.carry_clear.load(Ordering::Relaxed);
        let Some(failures) = failures.checked_add(u64::from(carry_clear)) else {
            return false;
        };
        if completed > self.entered.load(Ordering::Relaxed) {
            return false;
        }
        self.carry_clear.store(failures, Ordering::Relaxed);
        self.completed.store(completed, Ordering::Relaxed);
        true
    }

    pub(super) fn snapshot(&self) -> SelectedClassCounters {
        let entered = self.entered.load(Ordering::Relaxed);
        SelectedClassCounters {
            entered,
            completed: self.completed.load(Ordering::Relaxed),
            carry_clear: self.carry_clear.load(Ordering::Relaxed),
            first_logical_pc: (entered != 0).then(|| self.first_pc.load(Ordering::Relaxed)),
            last_logical_pc: (entered != 0).then(|| self.last_pc.load(Ordering::Relaxed)),
        }
    }
}

static COUNTERS: [Counters; 7] = [
    Counters::new(),
    Counters::new(),
    Counters::new(),
    Counters::new(),
    Counters::new(),
    Counters::new(),
    Counters::new(),
];

pub(super) fn for_kind(kind: SelectedKind) -> &'static Counters {
    &COUNTERS[kind.counter_index()]
}

/// Read actual process-lifetime class counters under caller-held exclusion.
/// The caller must establish that no callback is active for a coherent row.
pub fn selected_counters(kind: SelectedKind) -> SelectedClassCounters {
    for_kind(kind).snapshot()
}
