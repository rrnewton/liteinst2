//! Cache comparisons preserve every scanner fact. Only independently measured
//! elapsed durations differ between fresh scans; hit timing is recorded apart
//! from the retained report's original scanner measurements.

use std::sync::{Arc, Barrier};

use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet, ResumeKind};
use liteinst_admission::oracle_chain::{
    CacheLimits, CacheUsage, InspectionSource, InvalidLimits, OracleChain, OracleMiss, StaleReason,
    StoreOutcome,
};
use liteinst_admission::scan::{
    AdmissionOracle, Boundary, Policy, RuntimeScan, ScanReport, SiteClass, Snapshot, Verdict,
    WriteControl,
};
use liteinst_admission::{AddressRange, Generation, MappingId};

#[derive(Clone)]
struct Fixture {
    snapshot: Snapshot,
    target: AddressRange,
    entries: LegalEntrySet,
    policy: Policy,
}

impl Fixture {
    fn clean(base: u64, mapping: u64, len: usize) -> Self {
        Self::with_bytes(base, mapping, vec![0x90; len], (0..len).collect())
    }

    fn sites(base: u64, mapping: u64) -> Self {
        let mut bytes = vec![0x90; 64];
        bytes[20..22].copy_from_slice(&[0x0f, 0xa2]);
        Self::with_bytes(base, mapping, bytes, (0..64).filter(|n| *n != 21).collect())
    }

    fn with_bytes(base: u64, mapping: u64, bytes: Vec<u8>, heads: Vec<usize>) -> Self {
        let snapshot = Snapshot::new(
            MappingId(mapping),
            Generation(1),
            base,
            bytes,
            Boundary::NonExecutable,
            Boundary::NonExecutable,
            WriteControl::Owned,
        )
        .unwrap();
        let target = snapshot.range();
        let entries = LegalEntrySet::new(
            snapshot.mapping,
            snapshot.generation,
            1,
            target,
            Completeness::AllInstructionHeads,
            heads
                .into_iter()
                .map(|offset| (base + offset as u64, EntryProvenance::VerifiedInstruction)),
            [],
        )
        .unwrap();
        Self {
            snapshot,
            target,
            entries,
            policy: Policy::default(),
        }
    }

    fn scan(&self) -> ScanReport {
        RuntimeScan.inspect(&self.snapshot, self.target, &self.entries, &self.policy)
    }

    fn inspect(&self, chain: &OracleChain) -> liteinst_admission::oracle_chain::Inspection {
        chain.inspect_with_evidence(&self.snapshot, self.target, &self.entries, &self.policy)
    }

    fn heads(&self) -> Vec<(u64, EntryProvenance)> {
        self.entries
            .heads()
            .iter()
            .flat_map(|(&pc, sources)| sources.iter().map(move |&source| (pc, source)))
            .collect()
    }

    fn entries_with(
        &self,
        version: u64,
        scope: AddressRange,
        completeness: Completeness,
        heads: Vec<(u64, EntryProvenance)>,
        resumes: Vec<(u64, ResumeKind)>,
    ) -> LegalEntrySet {
        LegalEntrySet::new(
            self.snapshot.mapping,
            self.snapshot.generation,
            version,
            scope,
            completeness,
            heads,
            resumes,
        )
        .unwrap()
    }

    fn replace_bytes(&mut self, bytes: Vec<u8>) {
        self.snapshot = Snapshot::new(
            self.snapshot.mapping,
            self.snapshot.generation,
            self.snapshot.range().start(),
            bytes,
            self.snapshot.before,
            self.snapshot.after,
            self.snapshot.writes,
        )
        .unwrap();
    }
}

fn same_facts(actual: &ScanReport, expected: &ScanReport) {
    assert_eq!(actual.snapshot(), expected.snapshot());
    assert_eq!(actual.entries(), expected.entries());
    assert_eq!(actual.policy(), expected.policy());
    assert_eq!(actual.target(), expected.target());
    assert_eq!(actual.dependency(), expected.dependency());
    assert_eq!(actual.candidates(), expected.candidates());
    assert_eq!(actual.obligations(), expected.obligations());
    assert_eq!(actual.verdict(), expected.verdict());
    assert_eq!(
        actual.metrics().decoded_starts,
        expected.metrics().decoded_starts
    );
    assert_eq!(actual.metrics().known_sites, expected.metrics().known_sites);
    assert_eq!(
        actual.metrics().embedded_candidates,
        expected.metrics().embedded_candidates
    );
    assert_eq!(
        actual.metrics().unresolved_candidates,
        expected.metrics().unresolved_candidates
    );
    assert_eq!(actual.metrics().by_class, expected.metrics().by_class);
}

fn stale(original: &Fixture, changed: &Fixture, reason: StaleReason) {
    let chain = OracleChain::default();
    let original_report = original.scan();
    assert!(matches!(
        chain.remember(&original_report),
        StoreOutcome::Stored { .. }
    ));
    let result = changed.inspect(&chain);
    assert_eq!(result.source, InspectionSource::RuntimeScan);
    assert_eq!(result.miss, Some(OracleMiss::Stale(reason)));
    same_facts(&result.report, &changed.scan());
    let repeated = changed.inspect(&chain);
    assert_eq!(repeated.source, InspectionSource::Cache);
    same_facts(&repeated.report, &result.report);
    let metrics = chain.metrics().unwrap();
    assert_eq!(metrics.stale, 1);
    assert_eq!(metrics.runtime_scans, 1);
    assert_eq!(metrics.hits, 1);
}

#[test]
fn exact_hit_preserves_all_facts_and_separates_historical_scan_work() {
    let fixture = Fixture::sites(0x1000, 1);
    let chain = OracleChain::default();
    let first = fixture.inspect(&chain);
    assert_eq!(first.report.verdict(), Verdict::Sites);
    assert_eq!(first.source, InspectionSource::RuntimeScan);
    assert_eq!(first.miss, Some(OracleMiss::NoEntry));
    assert_eq!(first.work.decoded_starts, 64);
    assert!(first.work.fresh_scan_elapsed.is_some());
    let hit = fixture.inspect(&chain);
    assert_eq!(hit.source, InspectionSource::Cache);
    assert_eq!(hit.miss, None);
    assert_eq!(hit.store, StoreOutcome::NotAttempted);
    assert_eq!(hit.work.decoded_starts, 0);
    assert_eq!(hit.work.fresh_scan_elapsed, None);
    assert_eq!(hit.report.metrics().elapsed, first.report.metrics().elapsed);
    same_facts(&hit.report, &first.report);
    same_facts(&hit.report, &fixture.scan());
    let metrics = chain.metrics().unwrap();
    assert_eq!(
        (metrics.inspections, metrics.hits, metrics.runtime_scans),
        (2, 1, 1)
    );
    assert_eq!(
        (metrics.no_entry, metrics.stale, metrics.decoded_starts),
        (1, 0, 64)
    );
    assert!(!metrics.saturated);
}

#[test]
fn refused_embedded_candidates_are_cached_as_refusals_without_erasing_obligations() {
    let mut bytes = vec![0x90; 32];
    bytes[..5].copy_from_slice(&[0xb8, 0x0f, 0xa2, 0, 0]);
    let fixture = Fixture::with_bytes(0x1000, 1, bytes, [vec![0], (5..32).collect()].concat());
    let chain = OracleChain::default();
    let first = fixture.inspect(&chain);
    assert_eq!(first.report.verdict(), Verdict::Refused);
    assert_eq!(first.report.metrics().embedded_candidates, 1);
    let hit = fixture.inspect(&chain);
    assert_eq!(hit.source, InspectionSource::Cache);
    assert_eq!(hit.report.verdict(), Verdict::Refused);
    same_facts(&hit.report, &first.report);
}

#[test]
fn invalid_target_refusal_is_preserved_and_a_different_target_cannot_hit() {
    let mut fixture = Fixture::clean(0x1000, 1, 32);
    fixture.target = AddressRange::new(0x1000, 0x1030).unwrap();
    let chain = OracleChain::default();
    assert_eq!(fixture.inspect(&chain).report.verdict(), Verdict::Refused);
    assert_eq!(fixture.inspect(&chain).source, InspectionSource::Cache);
    fixture.target = fixture.snapshot.range();
    let fresh = fixture.inspect(&chain);
    assert_eq!(fresh.source, InspectionSource::RuntimeScan);
    assert_eq!(fresh.miss, Some(OracleMiss::NoEntry));
    assert_eq!(fresh.report.verdict(), Verdict::Clean);
}

#[test]
fn mapping_reuse_and_generation_changes_never_rebind_an_old_report() {
    let original = Fixture::sites(0x1000, 1);
    for generation_change in [false, true] {
        let mut changed = original.clone();
        if generation_change {
            changed.snapshot.generation = Generation(2);
        } else {
            changed.snapshot.mapping = MappingId(2);
        }
        changed.entries = changed.entries_with(
            1,
            changed.entries.scope(),
            changed.entries.completeness(),
            changed.heads(),
            vec![],
        );
        stale(
            &original,
            &changed,
            if generation_change {
                StaleReason::Generation
            } else {
                StaleReason::Mapping
            },
        );
    }
}

#[test]
fn every_snapshot_field_is_bound_even_with_the_same_mapping_and_generation() {
    let original = Fixture::sites(0x1000, 1);
    let mut changes = Vec::new();
    let mut bytes = original.clone();
    let mut changed_bytes = bytes.snapshot.bytes().to_vec();
    changed_bytes[63] = 0x91;
    bytes.replace_bytes(changed_bytes);
    changes.push(bytes);
    let mut before = original.clone();
    before.snapshot.before = Boundary::Unknown;
    changes.push(before);
    let mut after = original.clone();
    after.snapshot.after = Boundary::Unknown;
    changes.push(after);
    for control in [WriteControl::UnownedAlias, WriteControl::ExternalWriter] {
        let mut changed = original.clone();
        changed.snapshot.writes = control;
        changes.push(changed);
    }
    let mut extent = original.clone();
    extent.replace_bytes(extent.snapshot.bytes()[..63].to_vec());
    changes.push(extent);
    let mut base = original.clone();
    base.snapshot = Snapshot::new(
        base.snapshot.mapping,
        base.snapshot.generation,
        0x0fff,
        base.snapshot.bytes().to_vec(),
        base.snapshot.before,
        base.snapshot.after,
        base.snapshot.writes,
    )
    .unwrap();
    changes.push(base);
    for changed in changes {
        stale(&original, &changed, StaleReason::Snapshot);
    }
}

#[test]
fn full_snapshot_binding_includes_bytes_outside_the_current_target_and_halo() {
    let mut original = Fixture::clean(0x1000, 1, 64);
    original.target = AddressRange::new(0x1000, 0x1010).unwrap();
    let mut changed = original.clone();
    let mut bytes = changed.snapshot.bytes().to_vec();
    bytes[50] = 0x91;
    changed.replace_bytes(bytes);
    assert!(!original.scan().dependency().contains(0x1032));
    stale(&original, &changed, StaleReason::Snapshot);
}

#[test]
fn complete_entry_values_are_bound_not_only_their_version() {
    let original = Fixture::sites(0x1000, 1);
    let scope = original.entries.scope();
    let full = Completeness::AllInstructionHeads;
    let mut provenance = original.heads();
    provenance.push((0x1000, EntryProvenance::Function));
    let mut missing_head = original.heads();
    missing_head.retain(|(pc, _)| *pc != 0x1014);
    let mut variants = vec![
        original.entries_with(2, scope, full, original.heads(), vec![]),
        original.entries_with(1, scope, Completeness::Partial, original.heads(), vec![]),
        original.entries_with(
            1,
            AddressRange::new(0x0ff0, 0x1050).unwrap(),
            full,
            original.heads(),
            vec![],
        ),
        original.entries_with(1, scope, full, provenance, vec![]),
        original.entries_with(1, scope, full, missing_head, vec![]),
    ];
    for kind in [
        ResumeKind::ParkedThread,
        ResumeKind::SyscallReturn,
        ResumeKind::SignalFrame,
        ResumeKind::NonlocalJump,
    ] {
        variants.push(original.entries_with(
            1,
            scope,
            full,
            original.heads(),
            vec![(0x1014, kind)],
        ));
    }
    variants.push(
        LegalEntrySet::new(
            MappingId(999),
            Generation(1),
            1,
            scope,
            full,
            original.heads(),
            [],
        )
        .unwrap(),
    );
    variants.push(
        LegalEntrySet::new(
            MappingId(1),
            Generation(999),
            1,
            scope,
            full,
            original.heads(),
            [],
        )
        .unwrap(),
    );
    for entries in variants {
        let mut changed = original.clone();
        changed.entries = entries;
        stale(&original, &changed, StaleReason::Entries);
    }
}

#[test]
fn resume_kind_and_out_of_dependency_entry_changes_also_invalidate_reuse() {
    let mut original = Fixture::sites(0x1000, 1);
    original.target = AddressRange::new(0x1000, 0x1020).unwrap();
    original.entries = original.entries_with(
        1,
        original.entries.scope(),
        Completeness::AllInstructionHeads,
        original.heads(),
        vec![(0x103f, ResumeKind::SignalFrame)],
    );
    let mut changed = original.clone();
    changed.entries = changed.entries_with(
        1,
        changed.entries.scope(),
        Completeness::AllInstructionHeads,
        changed.heads(),
        vec![(0x103f, ResumeKind::NonlocalJump)],
    );
    assert!(!original.scan().dependency().contains(0x103f));
    stale(&original, &changed, StaleReason::Entries);
}

#[test]
fn both_policy_version_and_selected_classes_are_required_for_a_hit() {
    let original = Fixture::sites(0x1000, 1);
    let mut version = original.clone();
    version.policy.version += 1;
    stale(&original, &version, StaleReason::Policy);
    let mut remove = original.clone();
    remove.policy.selected.remove(&SiteClass::Cpuid);
    assert_eq!(remove.scan().verdict(), Verdict::Clean);
    stale(&original, &remove, StaleReason::Policy);
    let mut add = original.clone();
    add.policy.selected.insert(SiteClass::Int80);
    stale(&original, &add, StaleReason::Policy);
}

#[test]
fn runtime_only_mode_and_existing_trait_cannot_configure_away_the_scanner() {
    let fixture = Fixture::sites(0x1000, 1);
    let chain = OracleChain::new(CacheLimits::DISABLED).unwrap();
    for _ in 0..2 {
        let result = fixture.inspect(&chain);
        assert_eq!(result.source, InspectionSource::RuntimeScan);
        assert_eq!(result.miss, Some(OracleMiss::NoEntry));
        assert_eq!(result.store, StoreOutcome::Disabled);
        same_facts(&result.report, &fixture.scan());
    }
    let oracle: &dyn AdmissionOracle = &chain;
    let report = oracle.inspect(
        &fixture.snapshot,
        fixture.target,
        &fixture.entries,
        &fixture.policy,
    );
    same_facts(&report, &fixture.scan());
    assert_eq!(chain.usage().unwrap(), CacheUsage::default());
    let metrics = chain.metrics().unwrap();
    assert_eq!(
        (
            metrics.inspections,
            metrics.runtime_scans,
            metrics.not_stored
        ),
        (3, 3, 3)
    );
    assert_eq!(metrics.hits, 0);
}

#[test]
fn partially_zero_limits_are_rejected_instead_of_silently_disabling_a_bound() {
    for bits in 1..7 {
        let limits = CacheLimits {
            max_entries: usize::from(bits & 1 != 0),
            max_snapshot_bytes: usize::from(bits & 2 != 0),
            max_metadata_items: usize::from(bits & 4 != 0),
        };
        assert!(matches!(
            OracleChain::new(limits),
            Err(InvalidLimits::PartiallyDisabled)
        ));
    }
}

#[test]
fn entry_capacity_uses_lru_and_never_changes_the_result_after_eviction() {
    let chain = OracleChain::new(CacheLimits {
        max_entries: 2,
        ..CacheLimits::default()
    })
    .unwrap();
    let a = Fixture::clean(0x1000, 1, 16);
    let b = Fixture::clean(0x2000, 2, 16);
    let c = Fixture::clean(0x3000, 3, 16);
    a.inspect(&chain);
    b.inspect(&chain);
    assert_eq!(a.inspect(&chain).source, InspectionSource::Cache);
    let insert = c.inspect(&chain);
    assert_eq!(
        insert.store,
        StoreOutcome::Stored {
            replaced: false,
            evicted: 1
        }
    );
    assert_eq!(chain.usage().unwrap().entries, 2);
    assert_eq!(c.inspect(&chain).source, InspectionSource::Cache);
    assert_eq!(a.inspect(&chain).source, InspectionSource::Cache);
    let missing = b.inspect(&chain);
    assert_eq!(missing.source, InspectionSource::RuntimeScan);
    same_facts(&missing.report, &b.scan());
    assert_eq!(chain.metrics().unwrap().capacity_evictions, 2);
}

#[test]
fn snapshot_budget_is_aggregate_and_oversize_falls_back_without_storage() {
    let chain = OracleChain::new(CacheLimits {
        max_snapshot_bytes: 32,
        ..CacheLimits::default()
    })
    .unwrap();
    let a = Fixture::clean(0x1000, 1, 16);
    let b = Fixture::clean(0x2000, 2, 16);
    let c = Fixture::clean(0x3000, 3, 16);
    a.inspect(&chain);
    b.inspect(&chain);
    assert_eq!(
        c.inspect(&chain).store,
        StoreOutcome::Stored {
            replaced: false,
            evicted: 1
        }
    );
    assert_eq!(chain.usage().unwrap().snapshot_bytes, 32);
    assert_eq!(chain.usage().unwrap().entries, 2);
    let large = Fixture::sites(0x4000, 4);
    for _ in 0..2 {
        let result = large.inspect(&chain);
        assert_eq!(result.source, InspectionSource::RuntimeScan);
        assert_eq!(result.store, StoreOutcome::TooLarge);
        same_facts(&result.report, &large.scan());
        assert_eq!(chain.usage().unwrap().snapshot_bytes, 32);
    }
    assert_eq!(b.inspect(&chain).source, InspectionSource::Cache);
    assert_eq!(c.inspect(&chain).source, InspectionSource::Cache);
}

#[test]
fn metadata_budget_bounds_entry_provenance_even_when_bytes_fit() {
    let chain = OracleChain::new(CacheLimits {
        max_metadata_items: 8,
        ..CacheLimits::default()
    })
    .unwrap();
    let mut small = Fixture::clean(0x1000, 1, 64);
    small.entries = small.entries_with(1, small.target, Completeness::Partial, vec![], vec![]);
    assert_eq!(small.scan().verdict(), Verdict::Clean);
    assert!(matches!(
        small.inspect(&chain).store,
        StoreOutcome::Stored { .. }
    ));
    let before = chain.usage().unwrap();
    assert_eq!(before.metadata_items, 8);
    let rich = Fixture::clean(0x2000, 2, 64);
    assert_eq!(chain.remember(&rich.scan()), StoreOutcome::TooLarge);
    assert_eq!(chain.usage().unwrap(), before);
    assert_eq!(small.inspect(&chain).source, InspectionSource::Cache);
}

#[test]
fn aggregate_metadata_capacity_evicts_without_losing_accounting() {
    let a = Fixture::clean(0x1000, 1, 16);
    let b = Fixture::clean(0x2000, 2, 16);
    let c = Fixture::clean(0x3000, 3, 16);
    let measure = OracleChain::default();
    a.inspect(&measure);
    let per_entry = measure.usage().unwrap().metadata_items;
    let chain = OracleChain::new(CacheLimits {
        max_metadata_items: 2 * per_entry,
        ..CacheLimits::default()
    })
    .unwrap();
    a.inspect(&chain);
    b.inspect(&chain);
    assert_eq!(
        c.inspect(&chain).store,
        StoreOutcome::Stored {
            replaced: false,
            evicted: 1
        }
    );
    assert_eq!(chain.usage().unwrap().metadata_items, 2 * per_entry);
    assert_eq!(chain.clear().unwrap(), 2);
    assert_eq!(chain.usage().unwrap(), CacheUsage::default());
}

#[test]
fn explicit_replacement_keeps_one_target_and_updates_exact_storage_usage() {
    let original = Fixture::sites(0x1000, 1);
    let mut replacement = original.clone();
    replacement.policy.selected.remove(&SiteClass::Cpuid);
    let chain = OracleChain::default();
    chain.remember(&original.scan());
    assert_eq!(
        chain.remember(&replacement.scan()),
        StoreOutcome::Stored {
            replaced: true,
            evicted: 0
        }
    );
    assert_eq!(chain.usage().unwrap().entries, 1);
    assert_eq!(chain.usage().unwrap().snapshot_bytes, 64);
    let hit = replacement.inspect(&chain);
    assert_eq!(hit.source, InspectionSource::Cache);
    assert_eq!(hit.report.verdict(), Verdict::Clean);
    same_facts(&hit.report, &replacement.scan());
    assert_eq!(chain.metrics().unwrap().replacements, 1);
}

#[test]
fn mapping_invalidation_and_clear_remove_only_cache_facts() {
    let a = Fixture::clean(0x1000, 1, 16);
    let b = Fixture::clean(0x2000, 2, 16);
    let chain = OracleChain::default();
    a.inspect(&chain);
    b.inspect(&chain);
    assert_eq!(chain.invalidate_mapping(MappingId(1)).unwrap(), 1);
    assert_eq!(b.inspect(&chain).source, InspectionSource::Cache);
    let result = a.inspect(&chain);
    assert_eq!(result.source, InspectionSource::RuntimeScan);
    same_facts(&result.report, &a.scan());
    assert_eq!(chain.clear().unwrap(), 2);
    assert_eq!(chain.clear().unwrap(), 0);
    assert_eq!(chain.usage().unwrap(), CacheUsage::default());
    assert_eq!(chain.metrics().unwrap().invalidated_entries, 3);
}

#[test]
fn mismatched_entry_identity_in_a_refused_report_participates_in_invalidation() {
    let mut fixture = Fixture::sites(0x1000, 1);
    fixture.entries = LegalEntrySet::new(
        MappingId(2),
        Generation(1),
        1,
        fixture.target,
        Completeness::AllInstructionHeads,
        fixture.heads(),
        [],
    )
    .unwrap();
    let chain = OracleChain::default();
    assert_eq!(fixture.inspect(&chain).report.verdict(), Verdict::Refused);
    assert_eq!(chain.invalidate_mapping(MappingId(2)).unwrap(), 1);
    assert_eq!(chain.usage().unwrap(), CacheUsage::default());
}

#[test]
fn range_invalidation_includes_negative_boundaries_for_late_adjacent_code() {
    let mut fixture = Fixture::clean(0x1000, 1, 16);
    let mut bytes = fixture.snapshot.bytes().to_vec();
    bytes[15] = 0x0f;
    fixture.replace_bytes(bytes);
    fixture.entries =
        fixture.entries_with(1, fixture.target, Completeness::Partial, vec![], vec![]);
    let chain = OracleChain::default();
    assert_eq!(fixture.inspect(&chain).report.verdict(), Verdict::Clean);
    // A new adjacent page beginning A2 would complete the old trailing 0F.
    // Retire the old negative boundary fact before any new inspection.
    assert_eq!(
        chain
            .invalidate_range(AddressRange::new(0x1010, 0x2010).unwrap())
            .unwrap(),
        1
    );
    assert_eq!(chain.usage().unwrap(), CacheUsage::default());
    assert_eq!(
        fixture.inspect(&chain).source,
        InspectionSource::RuntimeScan
    );
}

#[test]
fn range_invalidation_covers_full_snapshot_and_entry_scope_but_not_unrelated_ranges() {
    let mut fixture = Fixture::clean(0x1000, 1, 64);
    fixture.target = AddressRange::new(0x1000, 0x1010).unwrap();
    fixture.entries = fixture.entries_with(
        1,
        AddressRange::new(0x1000, 0x1100).unwrap(),
        Completeness::AllInstructionHeads,
        fixture.heads(),
        vec![],
    );
    let chain = OracleChain::default();
    fixture.inspect(&chain);
    assert_eq!(
        chain
            .invalidate_range(AddressRange::new(0x2000, 0x2010).unwrap())
            .unwrap(),
        0
    );
    assert_eq!(fixture.inspect(&chain).source, InspectionSource::Cache);
    assert_eq!(
        chain
            .invalidate_range(AddressRange::new(0x103f, 0x1040).unwrap())
            .unwrap(),
        1
    );
    fixture.inspect(&chain);
    assert_eq!(
        chain
            .invalidate_range(AddressRange::new(0x10ff, 0x1100).unwrap())
            .unwrap(),
        1
    );
}

#[test]
fn concurrent_identical_requests_share_one_scan_without_altering_results() {
    let fixture = Arc::new(Fixture::sites(0x1000, 1));
    let chain = Arc::new(OracleChain::default());
    let barrier = Arc::new(Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let fixture = Arc::clone(&fixture);
            let chain = Arc::clone(&chain);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                fixture.inspect(&chain)
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let expected = fixture.scan();
    for result in &results {
        same_facts(&result.report, &expected);
    }
    assert_eq!(
        results
            .iter()
            .filter(|result| result.source == InspectionSource::RuntimeScan)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.source == InspectionSource::Cache)
            .count(),
        7
    );
    let metrics = chain.metrics().unwrap();
    assert_eq!(
        (metrics.inspections, metrics.runtime_scans, metrics.hits),
        (8, 1, 7)
    );
    assert_eq!(chain.usage().unwrap().entries, 1);
}
