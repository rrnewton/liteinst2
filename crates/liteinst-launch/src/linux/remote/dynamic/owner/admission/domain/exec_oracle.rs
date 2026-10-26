//! Private native-test comparison of the actual object before/after its move.
//! No copied fact here is a domain, source seal, plan or native permission.
use super::super::exec::oracle::{InspectionField, changed_snapshot, inspect};
use super::*;
use crate::gate::OraclePhaseMetrics;
use liteinst_admission::scan::ScanReport;

type Check<T> = Box<dyn Fn(&T)>;

fn phase(actual: &OraclePhaseMetrics, expected: &OraclePhaseMetrics) {
    assert_eq!(
        (
            actual.inspections,
            actual.hits,
            actual.runtime_scans,
            actual.no_entry,
            actual.stale,
            actual.corrupt,
            actual.refused,
            actual.decoded_starts
        ),
        (
            expected.inspections,
            expected.hits,
            expected.runtime_scans,
            expected.no_entry,
            expected.stale,
            expected.corrupt,
            expected.refused,
            expected.decoded_starts
        )
    );
    assert_eq!(
        (
            actual.lookup_elapsed,
            actual.fresh_scan_elapsed,
            actual.store_elapsed,
            actual.saturated
        ),
        (
            expected.lookup_elapsed,
            expected.fresh_scan_elapsed,
            expected.store_elapsed,
            expected.saturated
        )
    );
}

fn report(actual: &ScanReport, expected: &ScanReport) {
    inspect(
        InspectionField::PlanReport,
        expected.snapshot(),
        actual.snapshot(),
    )
    .unwrap();
    let changed = changed_snapshot(actual.snapshot());
    assert_eq!(
        inspect(InspectionField::PlanReport, expected.snapshot(), &changed),
        Err(InspectionField::PlanReport)
    );
    assert_eq!(actual.entries(), expected.entries());
    assert_eq!(actual.policy(), expected.policy());
    assert_eq!(actual.target(), expected.target());
    assert_eq!(actual.dependency(), expected.dependency());
    assert_eq!(actual.candidates(), expected.candidates());
    assert_eq!(actual.obligations(), expected.obligations());
    assert_eq!(actual.verdict(), expected.verdict());
    let a = actual.metrics();
    let e = expected.metrics();
    assert_eq!(
        (
            a.elapsed,
            a.decoded_starts,
            a.known_sites,
            a.embedded_candidates,
            a.unresolved_candidates
        ),
        (
            e.elapsed,
            e.decoded_starts,
            e.known_sites,
            e.embedded_candidates,
            e.unresolved_candidates
        )
    );
    assert_eq!(a.by_class, e.by_class);
}

fn plan(value: &InstalledPlan) -> Check<InstalledPlan> {
    let id = value.id;
    let binding = value.source_binding;
    let routes = value.routes.clone();
    let p = &value.pending;
    let backend = p.backend();
    let snapshot = p.snapshot().clone();
    let entries = p.entries().clone();
    let policy = p.policy().clone();
    let target = p.target();
    let page_size = p.page_size();
    let pages = p.pages().clone();
    let dependencies = p.dependencies().to_vec();
    let guards = p.guards().clone();
    let installed = p.installed_guards().clone();
    let decoded = p.decoded_heads().clone();
    let reports = p.reports().to_vec();
    let resumes = p.resume_requirements().to_vec();
    let calls = p.call_requirements().to_vec();
    let callers = p.planned_callers().to_vec();
    let planned = p.planned_calls().to_vec();
    let footprint = p.planned_source_footprint();
    let coverage = p.coverage().map(|coverage| coverage.resolutions().to_vec());
    Box::new(move |actual| {
        assert_eq!((actual.id, actual.source_binding), (id, binding));
        inspect(InspectionField::PlanRoutes, &routes, &actual.routes).unwrap();
        if !actual.routes.is_empty() {
            let mut changed = actual.routes.clone();
            changed.pop();
            assert_eq!(
                inspect(InspectionField::PlanRoutes, &routes, &changed),
                Err(InspectionField::PlanRoutes)
            );
        }
        let p = &actual.pending;
        assert_eq!(p.backend(), backend);
        assert_eq!(p.snapshot(), &snapshot);
        assert_eq!(p.entries(), &entries);
        assert_eq!(p.policy(), &policy);
        assert_eq!((p.target(), p.page_size()), (target, page_size));
        assert_eq!(p.pages(), &pages);
        assert_eq!(p.dependencies(), dependencies);
        assert_eq!(p.guards(), &guards);
        assert_eq!(p.installed_guards(), &installed);
        assert_eq!(p.decoded_heads(), &decoded);
        assert_eq!(p.reports().len(), reports.len());
        for (a, e) in p.reports().iter().zip(&reports) {
            report(a, e);
        }
        assert_eq!(p.resume_requirements(), resumes);
        assert_eq!(p.call_requirements(), calls);
        assert_eq!(p.planned_callers(), callers);
        assert_eq!(p.planned_calls(), planned);
        assert_eq!(p.planned_source_footprint(), footprint);
        assert_eq!(p.coverage().map(|c| c.resolutions()), coverage.as_deref());
    })
}

impl Domain {
    pub(in super::super) fn exec_oracle_check(&self) -> Check<Self> {
        self.audit_history().unwrap();
        let images = self
            .images
            .iter()
            .map(|image| {
                (
                    image.mapping.clone(),
                    image.snapshot.clone(),
                    image.entries.clone(),
                    image.core_identity,
                )
            })
            .collect::<Vec<_>>();
        let originals = self.original_executables.clone();
        let pages = self.pages.clone();
        let sites = self.sites.clone();
        let guards = self.guards.clone();
        let policy = self.policy.clone();
        let backend = self.backend;
        let scalar = (
            self.generation,
            self.entry_version,
            self.source_binding,
            self.next_plan,
        );
        let plans = self.plans.iter().map(plan).collect::<Vec<_>>();
        let generations = self
            .generations
            .iter()
            .map(|old| {
                (
                    old.generation,
                    old.entry_version,
                    old.source_binding,
                    old.executable_pages.clone(),
                    old.guards.clone(),
                    old.sites.clone(),
                )
            })
            .collect::<Vec<_>>();
        let catalog = self.resource_basis.exec_oracle_check();
        let obligations = self.returns.obligations().cloned().collect::<Vec<_>>();
        // Core's derived Debug includes latest_generation, every SourceFacts
        // snapshot/caller/entries and obligations. This is private exact opaque
        // field comparison, not a codec or an independently supplied history.
        let ledger = format!("{:?}", self.returns);
        let metrics = self.oracle.metrics();
        let usage = self.oracle.usage().unwrap();
        assert!(usage.entries > 0 && usage.snapshot_bytes > 0 && usage.metadata_items > 0);
        // The core cache exposes exact usage/metrics, not its private record vector.
        // Whole-object mem::replace preserves that opaque payload; this check
        // does not claim to enumerate it or disable the default cache.
        let allocation = (
            self.images.as_ptr() as usize,
            self.images.capacity(),
            self.original_executables.as_ptr() as usize,
            self.original_executables.capacity(),
            self.plans.as_ptr() as usize,
            self.plans.capacity(),
            self.generations.as_ptr() as usize,
            self.generations.capacity(),
        );
        Box::new(move |actual| {
            actual.audit_history().unwrap();
            assert_eq!(
                (
                    actual.images.as_ptr() as usize,
                    actual.images.capacity(),
                    actual.original_executables.as_ptr() as usize,
                    actual.original_executables.capacity(),
                    actual.plans.as_ptr() as usize,
                    actual.plans.capacity(),
                    actual.generations.as_ptr() as usize,
                    actual.generations.capacity()
                ),
                allocation
            );
            assert_eq!(actual.images.len(), images.len());
            for (a, (mapping, snapshot, entries, identity)) in actual.images.iter().zip(&images) {
                inspect(InspectionField::MappingFacts, mapping, &a.mapping).unwrap();
                let mut changed = a.mapping.clone();
                changed.file_offset ^= 4096;
                assert_eq!(
                    inspect(InspectionField::MappingFacts, mapping, &changed),
                    Err(InspectionField::MappingFacts)
                );
                inspect(InspectionField::SourceBytes, snapshot, &a.snapshot).unwrap();
                assert_eq!(
                    inspect(
                        InspectionField::SourceBytes,
                        snapshot,
                        &changed_snapshot(&a.snapshot)
                    ),
                    Err(InspectionField::SourceBytes)
                );
                inspect(InspectionField::EntryFacts, entries, &a.entries).unwrap();
                let changed = LegalEntrySet::new(
                    a.entries.mapping(),
                    a.entries.generation(),
                    a.entries.version().checked_add(1).unwrap(),
                    a.entries.scope(),
                    a.entries.completeness(),
                    a.entries
                        .heads()
                        .iter()
                        .flat_map(|(pc, values)| values.iter().map(move |value| (*pc, *value))),
                    a.entries
                        .resumes()
                        .iter()
                        .flat_map(|(pc, values)| values.iter().map(move |value| (*pc, *value))),
                )
                .unwrap();
                assert_eq!(
                    inspect(InspectionField::EntryFacts, entries, &changed),
                    Err(InspectionField::EntryFacts)
                );
                inspect(InspectionField::SourceIdentity, identity, &a.core_identity).unwrap();
                let mut changed = a.core_identity;
                changed.generation ^= 1;
                assert_eq!(
                    inspect(InspectionField::SourceIdentity, identity, &changed),
                    Err(InspectionField::SourceIdentity)
                );
            }
            assert_eq!(actual.original_executables, originals);
            assert_eq!(actual.pages, pages);
            assert_eq!(actual.sites, sites);
            assert_eq!(actual.guards, guards);
            assert_eq!(actual.policy, policy);
            assert_eq!(actual.backend, backend);
            assert_eq!(
                (
                    actual.generation,
                    actual.entry_version,
                    actual.source_binding,
                    actual.next_plan
                ),
                scalar
            );
            assert_eq!(actual.plans.len(), plans.len());
            for (a, check) in actual.plans.iter().zip(&plans) {
                check(a);
            }
            assert_eq!(actual.generations.len(), generations.len());
            for (a, (generation, version, binding, pages, guards, sites)) in
                actual.generations.iter().zip(&generations)
            {
                assert_eq!(
                    (a.generation, a.entry_version, a.source_binding),
                    (*generation, *version, *binding)
                );
                assert_eq!(&a.executable_pages, pages);
                assert_eq!(&a.guards, guards);
                assert_eq!(&a.sites, sites);
            }
            catalog(&actual.resource_basis);
            let observed = actual.returns.obligations().cloned().collect::<Vec<_>>();
            inspect(InspectionField::CallObligations, &obligations, &observed).unwrap();
            assert!(!observed.is_empty());
            for field in 0..3 {
                let mut changed = observed.clone();
                match field {
                    0 => changed[0].return_pc ^= 1,
                    1 => changed[0].call_bytes[0] ^= 1,
                    2 => changed[0].source_generation.0 ^= 1,
                    _ => unreachable!(),
                }
                assert_eq!(
                    inspect(InspectionField::CallObligations, &obligations, &changed),
                    Err(InspectionField::CallObligations)
                );
            }
            let observed = format!("{:?}", actual.returns);
            inspect(InspectionField::CallHistory, &ledger, &observed).unwrap();
            let mut changed = observed.clone();
            changed.push('!');
            assert_eq!(
                inspect(InspectionField::CallHistory, &ledger, &changed),
                Err(InspectionField::CallHistory)
            );
            assert_eq!(actual.oracle.usage().unwrap(), usage);
            let observed = actual.oracle.metrics();
            phase(&observed.preparation, &metrics.preparation);
            phase(&observed.demand, &metrics.demand);
        })
    }
}

// The original getpid panic fixture has no CALL. Its complete empty ledger
// still compares exactly; the exec fixture above keeps its nonempty controls.
impl Domain {
    pub(in super::super) fn panic_custody_check(&self) -> Check<Self> {
        self.audit_history().unwrap();
        assert!(
            self.returns.obligations().next().is_none(),
            "getpid fixture has no CALL obligation"
        );
        let images = self
            .images
            .iter()
            .map(|image| {
                (
                    image.mapping.clone(),
                    image.snapshot.clone(),
                    image.entries.clone(),
                    image.core_identity,
                )
            })
            .collect::<Vec<_>>();
        let originals = self.original_executables.clone();
        let pages = self.pages.clone();
        let sites = self.sites.clone();
        let guards = self.guards.clone();
        let policy = self.policy.clone();
        let backend = self.backend;
        let scalar = (
            self.generation,
            self.entry_version,
            self.source_binding,
            self.next_plan,
        );
        let plans = self.plans.iter().map(plan).collect::<Vec<_>>();
        let generations = self
            .generations
            .iter()
            .map(|old| {
                (
                    old.generation,
                    old.entry_version,
                    old.source_binding,
                    old.executable_pages.clone(),
                    old.guards.clone(),
                    old.sites.clone(),
                )
            })
            .collect::<Vec<_>>();
        let catalog = self.resource_basis.exec_oracle_check();
        let obligations = self.returns.obligations().cloned().collect::<Vec<_>>();
        // Core's derived Debug includes latest_generation, every SourceFacts
        // snapshot/caller/entries and obligations. This is private exact opaque
        // field comparison, not a codec or an independently supplied history.
        let ledger = format!("{:?}", self.returns);
        let metrics = self.oracle.metrics();
        let usage = self.oracle.usage().unwrap();
        assert!(usage.entries > 0 && usage.snapshot_bytes > 0 && usage.metadata_items > 0);
        // The core cache exposes exact usage/metrics, not its private record vector.
        // Whole-object mem::replace preserves that opaque payload; this check
        // does not claim to enumerate it or disable the default cache.
        let allocation = (
            self.images.as_ptr() as usize,
            self.images.capacity(),
            self.original_executables.as_ptr() as usize,
            self.original_executables.capacity(),
            self.plans.as_ptr() as usize,
            self.plans.capacity(),
            self.generations.as_ptr() as usize,
            self.generations.capacity(),
        );
        Box::new(move |actual| {
            actual.audit_history().unwrap();
            assert_eq!(
                (
                    actual.images.as_ptr() as usize,
                    actual.images.capacity(),
                    actual.original_executables.as_ptr() as usize,
                    actual.original_executables.capacity(),
                    actual.plans.as_ptr() as usize,
                    actual.plans.capacity(),
                    actual.generations.as_ptr() as usize,
                    actual.generations.capacity()
                ),
                allocation
            );
            assert_eq!(actual.images.len(), images.len());
            for (a, (mapping, snapshot, entries, identity)) in actual.images.iter().zip(&images) {
                inspect(InspectionField::MappingFacts, mapping, &a.mapping).unwrap();
                let mut changed = a.mapping.clone();
                changed.file_offset ^= 4096;
                assert_eq!(
                    inspect(InspectionField::MappingFacts, mapping, &changed),
                    Err(InspectionField::MappingFacts)
                );
                inspect(InspectionField::SourceBytes, snapshot, &a.snapshot).unwrap();
                assert_eq!(
                    inspect(
                        InspectionField::SourceBytes,
                        snapshot,
                        &changed_snapshot(&a.snapshot)
                    ),
                    Err(InspectionField::SourceBytes)
                );
                inspect(InspectionField::EntryFacts, entries, &a.entries).unwrap();
                let changed = LegalEntrySet::new(
                    a.entries.mapping(),
                    a.entries.generation(),
                    a.entries.version().checked_add(1).unwrap(),
                    a.entries.scope(),
                    a.entries.completeness(),
                    a.entries
                        .heads()
                        .iter()
                        .flat_map(|(pc, values)| values.iter().map(move |value| (*pc, *value))),
                    a.entries
                        .resumes()
                        .iter()
                        .flat_map(|(pc, values)| values.iter().map(move |value| (*pc, *value))),
                )
                .unwrap();
                assert_eq!(
                    inspect(InspectionField::EntryFacts, entries, &changed),
                    Err(InspectionField::EntryFacts)
                );
                inspect(InspectionField::SourceIdentity, identity, &a.core_identity).unwrap();
                let mut changed = a.core_identity;
                changed.generation ^= 1;
                assert_eq!(
                    inspect(InspectionField::SourceIdentity, identity, &changed),
                    Err(InspectionField::SourceIdentity)
                );
            }
            assert_eq!(actual.original_executables, originals);
            assert_eq!(actual.pages, pages);
            assert_eq!(actual.sites, sites);
            assert_eq!(actual.guards, guards);
            assert_eq!(actual.policy, policy);
            assert_eq!(actual.backend, backend);
            assert_eq!(
                (
                    actual.generation,
                    actual.entry_version,
                    actual.source_binding,
                    actual.next_plan
                ),
                scalar
            );
            assert_eq!(actual.plans.len(), plans.len());
            for (a, check) in actual.plans.iter().zip(&plans) {
                check(a);
            }
            assert_eq!(actual.generations.len(), generations.len());
            for (a, (generation, version, binding, pages, guards, sites)) in
                actual.generations.iter().zip(&generations)
            {
                assert_eq!(
                    (a.generation, a.entry_version, a.source_binding),
                    (*generation, *version, *binding)
                );
                assert_eq!(&a.executable_pages, pages);
                assert_eq!(&a.guards, guards);
                assert_eq!(&a.sites, sites);
            }
            catalog(&actual.resource_basis);
            let observed = actual.returns.obligations().cloned().collect::<Vec<_>>();
            inspect(InspectionField::CallObligations, &obligations, &observed).unwrap();
            assert!(observed.is_empty());
            let observed = format!("{:?}", actual.returns);
            inspect(InspectionField::CallHistory, &ledger, &observed).unwrap();
            let mut changed = observed.clone();
            changed.push('!');
            assert_eq!(
                inspect(InspectionField::CallHistory, &ledger, &changed),
                Err(InspectionField::CallHistory)
            );
            assert_eq!(actual.oracle.usage().unwrap(), usage);
            let observed = actual.oracle.metrics();
            phase(&observed.preparation, &metrics.preparation);
            phase(&observed.demand, &metrics.demand);
        })
    }
}
