//! Bounded reuse of immutable scanner facts, with an unavoidable runtime fallback.
//!
//! This is an in-memory cache, not an offline artifact format or an execution
//! authority. A hit requires exact original bytes, boundaries, writer facts,
//! mapping generation, entry facts, policy and target. Nothing rebinds a report
//! to another mapping. Live callers must still authenticate facts under their
//! actual ownership/lease and invalidate every dependent publication.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::entries::LegalEntrySet;
use crate::scan::{AdmissionOracle, HALO_BYTES, Policy, RuntimeScan, ScanReport, Snapshot};
use crate::{AddressRange, MappingId};

/// Independent retained-data bounds. Fixed report overhead is bounded by entries;
/// snapshot bytes and every variable-size metadata collection have separate caps.
/// These are logical storage bounds, not allocator overhead or measured RSS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheLimits {
    pub max_entries: usize,
    pub max_snapshot_bytes: usize,
    pub max_metadata_items: usize,
}

impl CacheLimits {
    /// Runtime-only operation uses the same chain and cannot disable its scanner.
    pub const DISABLED: Self = Self {
        max_entries: 0,
        max_snapshot_bytes: 0,
        max_metadata_items: 0,
    };
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_entries: 128,
            max_snapshot_bytes: 8 * 1024 * 1024,
            max_metadata_items: 65_536,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidLimits {
    /// Either all bounds are positive or all are zero (runtime-only).
    PartiallyDisabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleReason {
    Mapping,
    Generation,
    Snapshot,
    Entries,
    Policy,
}

/// No serialized records are accepted by this foundation. Corruption currently
/// means lost integrity of the private cache lock, never a guessed file format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheCorruption {
    Poisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleMiss {
    NoEntry,
    Stale(StaleReason),
    Corrupt(CacheCorruption),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionSource {
    Cache,
    RuntimeScan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreOutcome {
    /// No insertion was needed for this inspection's hit.
    NotAttempted,
    Stored {
        replaced: bool,
        evicted: usize,
    },
    Disabled,
    TooLarge,
    MetadataCountOverflow,
    Unavailable(CacheCorruption),
}

/// Work performed by this inspection, separate from a reused report's historical
/// scanner metrics. No hashing is performed or credited by this cache.
#[derive(Clone, Debug, Default)]
pub struct InspectionWork {
    /// Includes waiting for the private cache lock.
    pub lookup_elapsed: Duration,
    /// Absent on a hit; otherwise measures the actual terminal scanner invocation.
    pub fresh_scan_elapsed: Option<Duration>,
    pub store_elapsed: Duration,
    /// Zero on a hit, even though the retained report has historical scan counts.
    pub decoded_starts: usize,
}

#[derive(Clone, Debug)]
pub struct Inspection {
    pub report: ScanReport,
    pub source: InspectionSource,
    pub miss: Option<OracleMiss>,
    pub store: StoreOutcome,
    pub work: InspectionWork,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheUsage {
    pub entries: usize,
    pub snapshot_bytes: usize,
    pub metadata_items: usize,
}

/// Cumulative observations while the cache lock remains intact. Poison returns
/// an error from `metrics`, rather than presenting possibly partial counters as
/// complete. Per-inspection evidence remains available through runtime fallback.
#[derive(Clone, Debug, Default)]
pub struct OracleMetrics {
    pub inspections: u64,
    pub hits: u64,
    pub runtime_scans: u64,
    pub no_entry: u64,
    pub stale: u64,
    pub insertions: u64,
    pub replacements: u64,
    pub capacity_evictions: u64,
    pub invalidated_entries: u64,
    pub not_stored: u64,
    pub decoded_starts: u64,
    pub lookup_elapsed: Duration,
    pub fresh_scan_elapsed: Duration,
    pub store_elapsed: Duration,
    /// Saturated counters/times are lower bounds, never exact counts.
    pub saturated: bool,
}

struct Entry {
    report: ScanReport,
    snapshot_bytes: usize,
    metadata_items: usize,
}

#[derive(Default)]
struct State {
    entries: VecDeque<Entry>,
    usage: CacheUsage,
    metrics: OracleMetrics,
}

/// Optional bounded report reuse followed by the built-in, total `RuntimeScan`.
/// There is no constructor accepting a replacement terminal oracle.
///
/// All operations serialize on a private lock, including a miss's scan and
/// insertion. An invalidation cannot complete and then be undone by an older
/// in-flight insertion. Poison permanently disables reuse, but never fallback.
pub struct OracleChain {
    limits: CacheLimits,
    state: Mutex<State>,
}

impl OracleChain {
    pub fn new(limits: CacheLimits) -> Result<Self, InvalidLimits> {
        let zeroes = [
            limits.max_entries == 0,
            limits.max_snapshot_bytes == 0,
            limits.max_metadata_items == 0,
        ];
        if zeroes.iter().any(|zero| *zero) && !zeroes.iter().all(|zero| *zero) {
            return Err(InvalidLimits::PartiallyDisabled);
        }
        Ok(Self {
            limits,
            state: Mutex::new(State::default()),
        })
    }

    pub fn limits(&self) -> CacheLimits {
        self.limits
    }

    pub fn usage(&self) -> Result<CacheUsage, CacheCorruption> {
        self.state
            .lock()
            .map(|state| state.usage)
            .map_err(|_| CacheCorruption::Poisoned)
    }

    pub fn metrics(&self) -> Result<OracleMetrics, CacheCorruption> {
        self.state
            .lock()
            .map(|state| state.metrics.clone())
            .map_err(|_| CacheCorruption::Poisoned)
    }

    /// Copies scanner-produced immutable facts. There is no raw-facts constructor
    /// or deserializer here. Oversized entries leave the existing cache intact.
    /// Successful replacement/eviction affects cached facts only.
    pub fn remember(&self, report: &ScanReport) -> StoreOutcome {
        let Ok(mut state) = self.state.lock() else {
            return StoreOutcome::Unavailable(CacheCorruption::Poisoned);
        };
        let started = Instant::now();
        let outcome = state.store(report, self.limits);
        state.record_store(outcome, started.elapsed());
        outcome
    }

    pub fn inspect_with_evidence(
        &self,
        snapshot: &Snapshot,
        target: AddressRange,
        entries: &LegalEntrySet,
        policy: &Policy,
    ) -> Inspection {
        let lookup_started = Instant::now();
        let Ok(mut state) = self.state.lock() else {
            let lookup_elapsed = lookup_started.elapsed();
            let scan_started = Instant::now();
            let report = RuntimeScan.inspect(snapshot, target, entries, policy);
            let fresh_scan_elapsed = Some(scan_started.elapsed());
            let decoded_starts = report.metrics().decoded_starts;
            return Inspection {
                report,
                source: InspectionSource::RuntimeScan,
                miss: Some(OracleMiss::Corrupt(CacheCorruption::Poisoned)),
                store: StoreOutcome::Unavailable(CacheCorruption::Poisoned),
                work: InspectionWork {
                    lookup_elapsed,
                    fresh_scan_elapsed,
                    store_elapsed: Duration::ZERO,
                    decoded_starts,
                },
            };
        };
        let lookup = state.lookup(snapshot, target, entries, policy);
        let lookup_elapsed = lookup_started.elapsed();
        let metrics = &mut state.metrics;
        metrics.saturated |= increment(&mut metrics.inspections, 1);
        metrics.saturated |= add_time(&mut metrics.lookup_elapsed, lookup_elapsed);
        let miss = match lookup {
            Ok(report) => {
                metrics.saturated |= increment(&mut metrics.hits, 1);
                return Inspection {
                    report,
                    source: InspectionSource::Cache,
                    miss: None,
                    store: StoreOutcome::NotAttempted,
                    work: InspectionWork {
                        lookup_elapsed,
                        ..InspectionWork::default()
                    },
                };
            }
            Err(miss) => miss,
        };
        match miss {
            OracleMiss::NoEntry => metrics.saturated |= increment(&mut metrics.no_entry, 1),
            OracleMiss::Stale(_) => metrics.saturated |= increment(&mut metrics.stale, 1),
            OracleMiss::Corrupt(_) => unreachable!("lock integrity checked before lookup"),
        }
        let scan_started = Instant::now();
        let report = RuntimeScan.inspect(snapshot, target, entries, policy);
        let fresh_scan_elapsed = scan_started.elapsed();
        let decoded_starts = report.metrics().decoded_starts;
        metrics.saturated |= increment(&mut metrics.runtime_scans, 1);
        metrics.saturated |= increment_usize(&mut metrics.decoded_starts, decoded_starts);
        metrics.saturated |= add_time(&mut metrics.fresh_scan_elapsed, fresh_scan_elapsed);
        let store_started = Instant::now();
        let store = state.store(&report, self.limits);
        let store_elapsed = store_started.elapsed();
        state.record_store(store, store_elapsed);
        Inspection {
            report,
            source: InspectionSource::RuntimeScan,
            miss: Some(miss),
            store,
            work: InspectionWork {
                lookup_elapsed,
                fresh_scan_elapsed: Some(fresh_scan_elapsed),
                store_elapsed,
                decoded_starts,
            },
        }
    }

    /// Removes facts for either snapshot or entry-set identity. This does not
    /// revoke executable pages, retire patches, or discharge saved continuations.
    pub fn invalidate_mapping(&self, mapping: MappingId) -> Result<usize, CacheCorruption> {
        self.invalidate(|report| {
            report.snapshot().mapping == mapping || report.entries().mapping() == mapping
        })
    }

    /// Removes facts whose full snapshot/entry scope or possible boundary bytes
    /// intersect a changed range. The extra halo includes negative boundary
    /// facts: a new adjacent mapping can invalidate an old NonExecutable edge.
    /// Live owners must separately invalidate their complete dependency closure.
    pub fn invalidate_range(&self, range: AddressRange) -> Result<usize, CacheCorruption> {
        self.invalidate(|report| {
            let snapshot = report.snapshot().range();
            let with_boundaries = AddressRange::new(
                snapshot.start().saturating_sub(HALO_BYTES),
                snapshot.end().saturating_add(HALO_BYTES),
            )
            .expect("expanding a nonempty range preserves nonemptiness");
            with_boundaries.overlaps(range)
                || report.entries().scope().overlaps(range)
                || report.target().overlaps(range)
        })
    }

    pub fn clear(&self) -> Result<usize, CacheCorruption> {
        self.invalidate(|_| true)
    }

    fn invalidate(&self, affected: impl Fn(&ScanReport) -> bool) -> Result<usize, CacheCorruption> {
        let mut state = self.state.lock().map_err(|_| CacheCorruption::Poisoned)?;
        let mut removed = 0;
        let mut index = 0;
        while index < state.entries.len() {
            if affected(&state.entries[index].report) {
                state.remove(index);
                removed += 1;
            } else {
                index += 1;
            }
        }
        let metrics = &mut state.metrics;
        metrics.saturated |= increment_usize(&mut metrics.invalidated_entries, removed);
        Ok(removed)
    }
}

impl Default for OracleChain {
    fn default() -> Self {
        Self::new(CacheLimits::default()).expect("default limits are positive")
    }
}

impl AdmissionOracle for OracleChain {
    fn inspect(
        &self,
        snapshot: &Snapshot,
        target: AddressRange,
        entries: &LegalEntrySet,
        policy: &Policy,
    ) -> ScanReport {
        self.inspect_with_evidence(snapshot, target, entries, policy)
            .report
    }
}

impl State {
    fn lookup(
        &mut self,
        snapshot: &Snapshot,
        target: AddressRange,
        entries: &LegalEntrySet,
        policy: &Policy,
    ) -> Result<ScanReport, OracleMiss> {
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.report.target() == target)
        else {
            return Err(OracleMiss::NoEntry);
        };
        let cached = &self.entries[index].report;
        let stale = if cached.snapshot().mapping != snapshot.mapping {
            Some(StaleReason::Mapping)
        } else if cached.snapshot().generation != snapshot.generation {
            Some(StaleReason::Generation)
        } else if cached.snapshot() != snapshot {
            Some(StaleReason::Snapshot)
        } else if cached.entries() != entries {
            Some(StaleReason::Entries)
        } else if cached.policy() != policy {
            Some(StaleReason::Policy)
        } else {
            None
        };
        if let Some(reason) = stale {
            self.remove(index);
            return Err(OracleMiss::Stale(reason));
        }
        // Exact target equality came from lookup, all other request facts above.
        let entry = self.entries.remove(index).expect("checked cache index");
        let report = entry.report.clone();
        self.entries.push_back(entry);
        Ok(report)
    }

    fn remove(&mut self, index: usize) {
        let entry = self.entries.remove(index).expect("checked cache index");
        self.usage.entries -= 1;
        self.usage.snapshot_bytes -= entry.snapshot_bytes;
        self.usage.metadata_items -= entry.metadata_items;
    }

    fn store(&mut self, report: &ScanReport, limits: CacheLimits) -> StoreOutcome {
        if limits == CacheLimits::DISABLED {
            return StoreOutcome::Disabled;
        }
        let snapshot_bytes = report.snapshot().bytes().len();
        let Some(metadata_items) = metadata_items(report) else {
            return StoreOutcome::MetadataCountOverflow;
        };
        if snapshot_bytes > limits.max_snapshot_bytes || metadata_items > limits.max_metadata_items
        {
            return StoreOutcome::TooLarge;
        }
        // Clone before removing any entry. This does not retain a caller's
        // deliberately oversized Vec capacity through a moved-in report.
        let entry = Entry {
            report: report.clone(),
            snapshot_bytes,
            metadata_items,
        };
        let replaced = if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.report.target() == report.target())
        {
            self.remove(index);
            true
        } else {
            false
        };
        let mut evicted = 0;
        while self.usage.entries >= limits.max_entries
            || self.usage.snapshot_bytes > limits.max_snapshot_bytes - snapshot_bytes
            || self.usage.metadata_items > limits.max_metadata_items - metadata_items
        {
            self.remove(0);
            evicted += 1;
        }
        self.usage.entries += 1;
        self.usage.snapshot_bytes += snapshot_bytes;
        self.usage.metadata_items += metadata_items;
        self.entries.push_back(entry);
        StoreOutcome::Stored { replaced, evicted }
    }

    fn record_store(&mut self, outcome: StoreOutcome, elapsed: Duration) {
        let metrics = &mut self.metrics;
        metrics.saturated |= add_time(&mut metrics.store_elapsed, elapsed);
        match outcome {
            StoreOutcome::Stored { replaced, evicted } => {
                metrics.saturated |= increment(&mut metrics.insertions, 1);
                metrics.saturated |= increment(&mut metrics.replacements, u64::from(replaced));
                metrics.saturated |= increment_usize(&mut metrics.capacity_evictions, evicted);
            }
            StoreOutcome::NotAttempted => {}
            _ => metrics.saturated |= increment(&mut metrics.not_stored, 1),
        }
    }
}

fn metadata_items(report: &ScanReport) -> Option<usize> {
    let entries = report.entries();
    let mut count = 1_usize;
    for len in [
        entries.heads().len(),
        entries.resumes().len(),
        report.policy().selected.len(),
        report.candidates().len(),
        report.obligations().len(),
        report.metrics().by_class.len(),
    ] {
        count = count.checked_add(len)?;
    }
    for provenances in entries.heads().values() {
        count = count.checked_add(provenances.len())?;
    }
    for kinds in entries.resumes().values() {
        count = count.checked_add(kinds.len())?;
    }
    Some(count)
}

fn increment(value: &mut u64, amount: u64) -> bool {
    if let Some(total) = value.checked_add(amount) {
        *value = total;
        false
    } else {
        *value = u64::MAX;
        true
    }
}

fn increment_usize(value: &mut u64, amount: usize) -> bool {
    match u64::try_from(amount) {
        Ok(amount) => increment(value, amount),
        Err(_) => {
            *value = u64::MAX;
            true
        }
    }
}

fn add_time(value: &mut Duration, amount: Duration) -> bool {
    if let Some(total) = value.checked_add(amount) {
        *value = total;
        false
    } else {
        *value = Duration::MAX;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Generation;
    use crate::entries::Completeness;
    use crate::scan::{Boundary, Verdict, WriteControl};

    #[test]
    fn poisoned_cache_remains_a_corrupt_miss_and_cannot_remove_runtime_fallback() {
        let chain = OracleChain::default();
        let scope = AddressRange::new(0x1000, 0x1010).unwrap();
        let snapshot = Snapshot::new(
            MappingId(1),
            Generation(1),
            scope.start(),
            vec![0x90; 16],
            Boundary::NonExecutable,
            Boundary::NonExecutable,
            WriteControl::Owned,
        )
        .unwrap();
        let entries = LegalEntrySet::new(
            snapshot.mapping,
            snapshot.generation,
            1,
            scope,
            Completeness::Partial,
            [],
            [],
        )
        .unwrap();
        let policy = Policy::default();
        chain.inspect(&snapshot, scope, &entries, &policy);
        let panic = std::panic::catch_unwind(|| {
            let _held = chain.state.lock().unwrap();
            panic!("intentional private-cache poison");
        });
        assert!(panic.is_err());
        for _ in 0..2 {
            let result = chain.inspect_with_evidence(&snapshot, scope, &entries, &policy);
            assert_eq!(result.source, InspectionSource::RuntimeScan);
            assert_eq!(
                result.miss,
                Some(OracleMiss::Corrupt(CacheCorruption::Poisoned))
            );
            assert_eq!(result.report.verdict(), Verdict::Clean);
            assert_eq!(result.work.decoded_starts, 16);
            assert!(result.work.fresh_scan_elapsed.is_some());
            assert_eq!(
                result.store,
                StoreOutcome::Unavailable(CacheCorruption::Poisoned)
            );
        }
        assert!(matches!(chain.metrics(), Err(CacheCorruption::Poisoned)));
        assert_eq!(chain.clear(), Err(CacheCorruption::Poisoned));
    }
}
