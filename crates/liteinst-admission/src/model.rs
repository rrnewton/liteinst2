//! B0's explicitly MOCK publication seam and page/dependency ledger.
//!
//! This module never touches live code. A model lease excludes access only to
//! this ledger: it cannot justify calling an unsafe core publication API. An OS
//! gate must additionally control every executor, reader, writer and saved resume.
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_GATE: AtomicU64 = AtomicU64::new(1);

use crate::entries::LegalEntrySet;
use crate::scan::{
    AdmissionOracle, Policy, RuntimeScan, ScanReport, Snapshot, Verdict, WriteControl,
};
use crate::{AddressRange, Generation};

pub const PAGE_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageState {
    Unknown,
    Scanning,
    Certified,
    Admitted,
    Invalidated,
    Refused,
    /// Publication may have changed bytes. No reuse without verified recovery.
    Poisoned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelError {
    InvalidPage,
    DuplicatePage,
    BoundaryConflict,
    MissingPage(u64),
    ScanRefused,
    PlanningRefused,
    StalePlan,
    BytesChanged,
    WrongCoverage,
    UnsafeDependency(u64),
    StaleReceipt,
    PublicationFailed,
    Poisoned,
    GenerationNotAdvanced,
}

/// A proposed transaction, with exact source facts and dependency ranges.
/// This is a temporary model interface, not Agent A's shared PatchPlan.
#[derive(Clone, Debug)]
pub struct MockPlan {
    facts: ScanReport,
    dependencies: Vec<MockDependency>,
    covered_sites: BTreeSet<u64>,
}

/// Exact authenticated facts for each additional victim/read/write dependency.
/// Ranges alone are not sufficient: replanning must notice changed neighbor bytes
/// and entry facts even when the primary page is unchanged.
#[derive(Clone, Debug)]
pub struct MockDependency {
    range: AddressRange,
    snapshot: Snapshot,
    entries: LegalEntrySet,
    policy: Policy,
}

impl MockDependency {
    pub fn new(
        range: AddressRange,
        snapshot: Snapshot,
        entries: LegalEntrySet,
        policy: Policy,
    ) -> Result<Self, ModelError> {
        if !snapshot.range().covers(range)
            || entries.mapping() != snapshot.mapping
            || entries.generation() != snapshot.generation
            || !entries.scope().covers(range)
        {
            return Err(ModelError::StalePlan);
        }
        Ok(Self {
            range,
            snapshot,
            entries,
            policy,
        })
    }
    pub fn range(&self) -> AddressRange {
        self.range
    }
}

impl MockPlan {
    pub fn new(
        facts: &ScanReport,
        extra_dependencies: impl IntoIterator<Item = MockDependency>,
        covered_sites: impl IntoIterator<Item = u64>,
    ) -> Self {
        let mut dependencies: Vec<_> = extra_dependencies.into_iter().collect();
        dependencies.push(MockDependency {
            range: facts.dependency(),
            snapshot: facts.snapshot().clone(),
            entries: facts.entries().clone(),
            policy: facts.policy().clone(),
        });
        Self {
            facts: facts.clone(),
            dependencies,
            covered_sites: covered_sites.into_iter().collect(),
        }
    }
    pub fn facts(&self) -> &ScanReport {
        &self.facts
    }
    pub fn dependencies(&self) -> &[MockDependency] {
        &self.dependencies
    }
}

/// Deliberately non-Send, scoped token for an immutable model transaction.
/// It offers no live-memory quiescence proof.
pub struct ModelLease<'a> {
    gate_id: u64,
    serial: u64,
    generations: &'a BTreeMap<u64, Generation>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl ModelLease<'_> {
    /// Simulates a successful complete publication. There is deliberately no
    /// conversion from this receipt to an executable capability.
    pub fn receipt(&self) -> MockReceipt {
        MockReceipt {
            gate_id: self.gate_id,
            serial: self.serial,
            generations: self.generations.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MockReceipt {
    gate_id: u64,
    serial: u64,
    generations: BTreeMap<u64, Generation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationFailure {
    BeforeWrite,
    PossiblyWritten,
}

/// Stand-in until the core's checked plan/receipt/lease interface is available.
pub trait MockPublisher {
    fn plan(&mut self, facts: &ScanReport) -> Result<MockPlan, ModelError>;
    fn publish(
        &mut self,
        plan: &MockPlan,
        lease: &ModelLease<'_>,
    ) -> Result<MockReceipt, PublicationFailure>;
}

#[derive(Clone, Debug)]
struct Page {
    range: AddressRange,
    snapshot: Snapshot,
    entries: LegalEntrySet,
    policy: Policy,
    state: PageState,
    ever_admitted: bool,
    dependencies: BTreeSet<u64>,
}

#[derive(Default)]
struct Table {
    pages: BTreeMap<u64, Page>,
    serial: u64,
    publications: usize,
}

/// Serialized, in-memory ledger. Concurrent callers can model first-fault
/// deduplication; no signal handler should call this blocking API.
pub struct ModelGate {
    gate_id: u64,
    table: Mutex<Table>,
}

impl Default for ModelGate {
    fn default() -> Self {
        let gate_id = NEXT_GATE.fetch_add(1, Ordering::Relaxed);
        assert_ne!(gate_id, 0, "model gate identity exhausted");
        Self {
            gate_id,
            table: Mutex::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Published,
    AlreadyAdmitted,
}

impl ModelGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        range: AddressRange,
        snapshot: Snapshot,
        entries: LegalEntrySet,
        policy: Policy,
    ) -> Result<(), ModelError> {
        if range.start() % PAGE_BYTES != 0
            || range.end() - range.start() != PAGE_BYTES
            || !snapshot.range().covers(range)
        {
            return Err(ModelError::InvalidPage);
        }
        let mut table = self.table.lock().map_err(|_| ModelError::Poisoned)?;
        if table.pages.contains_key(&range.start()) {
            return Err(ModelError::DuplicatePage);
        }
        check_boundaries(&table, range, &snapshot)?;
        table.pages.insert(
            range.start(),
            Page {
                range,
                snapshot,
                entries,
                policy,
                state: PageState::Unknown,
                ever_admitted: false,
                dependencies: BTreeSet::new(),
            },
        );
        Ok(())
    }

    pub fn state(&self, page: u64) -> Result<PageState, ModelError> {
        let table = self.table.lock().map_err(|_| ModelError::Poisoned)?;
        Ok(table
            .pages
            .get(&page)
            .ok_or(ModelError::MissingPage(page))?
            .state)
    }

    pub fn publications(&self) -> Result<usize, ModelError> {
        Ok(self
            .table
            .lock()
            .map_err(|_| ModelError::Poisoned)?
            .publications)
    }

    pub fn admit(
        &self,
        address: u64,
        publisher: &mut impl MockPublisher,
    ) -> Result<Admission, ModelError> {
        let mut table = self.table.lock().map_err(|_| ModelError::Poisoned)?;
        let page = table
            .pages
            .get_mut(&address)
            .ok_or(ModelError::MissingPage(address))?;
        match page.state {
            PageState::Admitted => return Ok(Admission::AlreadyAdmitted),
            PageState::Poisoned => return Err(ModelError::Poisoned),
            PageState::Refused => return Err(ModelError::ScanRefused),
            _ => {}
        }
        // NX after earlier execution does not erase saved PCs. B0 has no drain
        // or relocation proof, so all republishing of previously admitted pages
        // is refused, even when a caller supplies an empty resume census.
        if page.ever_admitted {
            page.state = PageState::Refused;
            return Err(ModelError::UnsafeDependency(address));
        }
        page.state = PageState::Scanning;
        let facts = RuntimeScan.inspect(&page.snapshot, page.range, &page.entries, &page.policy);
        if facts.verdict() == Verdict::Refused {
            page.state = PageState::Refused;
            return Err(ModelError::ScanRefused);
        }
        let plan = match publisher.plan(&facts) {
            Ok(plan) => plan,
            Err(error) => {
                page.state = PageState::Refused;
                return Err(error);
            }
        };
        let dependencies = match validate_plan(&table, &facts, &plan) {
            Ok(dependencies) => dependencies,
            Err(error) => {
                table.pages.get_mut(&address).unwrap().state = PageState::Refused;
                return Err(error);
            }
        };
        table.serial = table.serial.checked_add(1).ok_or(ModelError::Poisoned)?;
        let serial = table.serial;
        let generations = dependencies
            .iter()
            .map(|address| (*address, table.pages[address].snapshot.generation))
            .collect();
        table.pages.get_mut(&address).unwrap().state = PageState::Certified;
        let lease = ModelLease {
            gate_id: self.gate_id,
            serial,
            generations: &generations,
            _thread_bound: PhantomData,
        };
        let receipt = publisher.publish(&plan, &lease);
        let uncertain = !matches!(receipt, Err(PublicationFailure::BeforeWrite));
        let result = match receipt {
            Ok(receipt)
                if receipt.gate_id == self.gate_id
                    && receipt.serial == serial
                    && receipt.generations == generations =>
            {
                table.publications += 1;
                let page = table.pages.get_mut(&address).unwrap();
                page.state = PageState::Admitted;
                page.ever_admitted = true;
                page.dependencies = dependencies;
                return Ok(Admission::Published);
            }
            Ok(_) => ModelError::StaleReceipt,
            Err(_) => ModelError::PublicationFailed,
        };
        if uncertain {
            // A late failure affects the complete bundle, not just its entry page.
            for dependency in dependencies {
                table.pages.get_mut(&dependency).unwrap().state = PageState::Poisoned;
            }
        } else {
            table.pages.get_mut(&address).unwrap().state = PageState::Refused;
        }
        Err(result)
    }

    /// Revoke dependents BEFORE installing a newer snapshot. This only models
    /// revocation. An OS backend must revoke actual execution and retain routes.
    /// Poisoned pages require a recovery mechanism not implemented in B0.
    pub fn invalidate(
        &self,
        address: u64,
        snapshot: Snapshot,
        entries: LegalEntrySet,
    ) -> Result<BTreeSet<u64>, ModelError> {
        let mut table = self.table.lock().map_err(|_| ModelError::Poisoned)?;
        let page = table
            .pages
            .get(&address)
            .ok_or(ModelError::MissingPage(address))?;
        if page.state == PageState::Poisoned {
            return Err(ModelError::Poisoned);
        }
        check_boundaries(&table, page.range, &snapshot)?;
        if snapshot.mapping != page.snapshot.mapping
            || snapshot.generation <= page.snapshot.generation
            || !snapshot.range().covers(page.range)
            || entries.mapping() != snapshot.mapping
            || entries.generation() != snapshot.generation
        {
            return Err(ModelError::GenerationNotAdvanced);
        }
        let links = table
            .pages
            .iter()
            .map(|(&base, page)| (base, page.dependencies.clone()))
            .collect();
        let invalidated = dependent_closure(address, &links);
        for base in &invalidated {
            let page = table.pages.get_mut(base).unwrap();
            if page.state != PageState::Poisoned {
                page.state = PageState::Invalidated;
            }
        }
        let page = table.pages.get_mut(&address).unwrap();
        page.snapshot = snapshot;
        page.entries = entries;
        Ok(invalidated)
    }
}

fn validate_plan(
    table: &Table,
    facts: &ScanReport,
    plan: &MockPlan,
) -> Result<BTreeSet<u64>, ModelError> {
    if plan.facts.snapshot() != facts.snapshot()
        || plan.facts.entries() != facts.entries()
        || plan.facts.policy() != facts.policy()
        || plan.facts.target() != facts.target()
    {
        return Err(ModelError::StalePlan);
    }
    let expected_sites = facts.candidates().iter().map(|site| site.address).collect();
    if plan.covered_sites != expected_sites {
        return Err(ModelError::WrongCoverage);
    }
    let mut dependencies = BTreeSet::new();
    for dependency in &plan.dependencies {
        let range = dependency.range;
        let mut cursor = range.start();
        while cursor < range.end() {
            let base = cursor / PAGE_BYTES * PAGE_BYTES;
            let page = table
                .pages
                .get(&base)
                .ok_or(ModelError::MissingPage(base))?;
            if page.ever_admitted
                || matches!(page.state, PageState::Poisoned | PageState::Refused)
                || page.snapshot.writes != WriteControl::Owned
                || !page.entries.resumes().is_empty()
                || table.pages.values().any(|other| {
                    other.state == PageState::Admitted && other.dependencies.contains(&base)
                })
            {
                return Err(ModelError::UnsafeDependency(base));
            }
            if page.snapshot.mapping != dependency.snapshot.mapping
                || page.snapshot.generation != dependency.snapshot.generation
                || page.entries != dependency.entries
                || page.policy != dependency.policy
            {
                return Err(ModelError::StalePlan);
            }
            let end = page.range.end().min(range.end());
            let expected_offset = (cursor - dependency.snapshot.range().start()) as usize;
            let observed_offset = (cursor - page.snapshot.range().start()) as usize;
            let len = (end - cursor) as usize;
            if dependency.snapshot.bytes()[expected_offset..expected_offset + len]
                != page.snapshot.bytes()[observed_offset..observed_offset + len]
            {
                return Err(ModelError::BytesChanged);
            }
            dependencies.insert(base);
            cursor = end;
        }
    }
    Ok(dependencies)
}

fn dependent_closure(address: u64, links: &BTreeMap<u64, BTreeSet<u64>>) -> BTreeSet<u64> {
    let mut invalidated = BTreeSet::from([address]);
    loop {
        let before = invalidated.len();
        for (&base, dependencies) in links {
            if !dependencies.is_disjoint(&invalidated) {
                invalidated.insert(base);
            }
        }
        if before == invalidated.len() {
            return invalidated;
        }
    }
}

fn check_boundaries(
    table: &Table,
    range: AddressRange,
    snapshot: &Snapshot,
) -> Result<(), ModelError> {
    use crate::scan::Boundary;
    let excludes = |source: &Snapshot, neighbor: AddressRange| {
        (source.before == Boundary::NonExecutable
            && source
                .range()
                .start()
                .checked_sub(1)
                .is_some_and(|pc| neighbor.contains(pc)))
            || (source.after == Boundary::NonExecutable && neighbor.contains(source.range().end()))
    };
    for page in table.pages.values().filter(|page| page.range != range) {
        if excludes(snapshot, page.range) || excludes(&page.snapshot, range) {
            return Err(ModelError::BoundaryConflict);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_dependency_closure_handles_chains_and_cycles() {
        let links = BTreeMap::from([
            (1, BTreeSet::from([2])),
            (2, BTreeSet::from([3])),
            (3, BTreeSet::from([1])),
            (4, BTreeSet::new()),
        ]);
        assert_eq!(dependent_closure(3, &links), BTreeSet::from([1, 2, 3]));
        assert_eq!(dependent_closure(4, &links), BTreeSet::from([4]));
    }
}
