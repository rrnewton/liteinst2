//! Pure placement proofs for explicit selected-instruction trap coverage.
//!
//! A plan does not authorize publication or execution. Its caller must still
//! authenticate live bytes, hold the complete dependency set, account for
//! dynamic resumes and aliases, and qualify every selected and collateral
//! instruction's execution. Original scanner reports remain unchanged.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions};
use liteinst_admission::AddressRange;
use liteinst_admission::entries::{Completeness, LegalEntrySet};
use liteinst_admission::scan::{
    AdmissionOracle, Candidate, Obligation, Policy, RuntimeScan, ScanReport, Snapshot,
};

/// Geometry and finite resource limits for one immutable coverage plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrapCoverageBudget {
    /// Power-of-two page size, at least the maximum x86 instruction length.
    pub page_size: u64,
    /// Maximum number of complete pages requiring admission.
    pub max_pages: usize,
    /// Maximum number of one-byte execution guards.
    pub max_guards: usize,
    /// Maximum supplied instruction heads plus saved-resume addresses.
    pub max_heads: usize,
    /// Maximum sum of original instruction bytes retained by guards.
    pub max_original_bytes: usize,
    /// Maximum authenticated source image size.
    pub max_snapshot_bytes: usize,
    /// Maximum fixed-point rounds, including the final stable round.
    pub max_rounds: usize,
}

impl Default for TrapCoverageBudget {
    fn default() -> Self {
        Self {
            page_size: 4096,
            max_pages: 64,
            max_guards: 4096,
            max_heads: 16384,
            max_original_bytes: 64 * 1024,
            max_snapshot_bytes: 4 * 1024 * 1024,
            max_rounds: 4096,
        }
    }
}

/// The resource whose declared planning budget was exhausted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapBudgetResource {
    /// Complete executable pages.
    Pages,
    /// Execution guard count.
    Guards,
    /// Supplied head and resume facts.
    Heads,
    /// Retained original instruction bytes.
    OriginalBytes,
    /// Authenticated source image bytes.
    SnapshotBytes,
    /// Fixed-point rounds.
    Rounds,
}

/// An explicit refusal; no variant grants partial publication authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrapCoverageRefusal {
    /// Zero limits or invalid page geometry.
    InvalidBudget,
    /// The image or requested target does not cover whole aligned pages.
    UnalignedRange,
    /// A target or required instruction page lies outside the snapshot.
    OutsideSnapshot,
    /// A finite planning limit was exhausted.
    BudgetExceeded(TrapBudgetResource),
    /// These original or additional safety obligations remain unproved.
    UnresolvedObligations {
        /// Page whose scan or dependency check reported the obligations.
        target: AddressRange,
        /// Exact obligations; none is silently discarded.
        obligations: Vec<Obligation>,
    },
    /// The immutable scan and original-byte decode disagree.
    CandidateDecodeMismatch(u64),
}

impl std::fmt::Display for TrapCoverageRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for TrapCoverageRefusal {}

/// Distinguishes a requested logical callback from an execution-only guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapGuardRole {
    /// An all-start selected candidate, preserving the scanner's classification.
    Selected(Candidate),
    /// A permitted enclosing decode that must execute without an extra callback.
    Collateral,
}

/// One required INT3 head and its exact unmodified original instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrapGuard {
    address: u64,
    original_bytes: Vec<u8>,
    role: TrapGuardRole,
}

impl TrapGuard {
    /// Original instruction address; only this byte receives the proposed guard.
    pub const fn address(&self) -> u64 {
        self.address
    }
    /// Entire original instruction, including any overlapping guard positions.
    pub fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }
    /// Logical selected callback or collateral execution only.
    pub const fn role(&self) -> TrapGuardRole {
        self.role
    }
    /// Complete original decode, required during temporary restoration.
    pub fn range(&self) -> AddressRange {
        AddressRange::from_len(self.address, self.original_bytes.len()).unwrap()
    }
}

/// Explicit guard evidence for one unchanged scanner obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTrapObligation {
    /// Original report's requested page.
    pub target: AddressRange,
    /// Original obligation, still present in the retained report.
    pub obligation: Obligation,
    /// The candidate/overlap head and every declared decode containing its byte.
    pub guards: Vec<u64>,
}

/// Immutable guard-placement proof, never a publication or execution receipt.
#[derive(Clone, Debug)]
pub struct TrapCoveragePlan {
    snapshot: Snapshot,
    entries: LegalEntrySet,
    policy: Policy,
    target: AddressRange,
    page_size: u64,
    pages: BTreeSet<u64>,
    dependencies: Vec<AddressRange>,
    guards: BTreeMap<u64, TrapGuard>,
    reports: Vec<ScanReport>,
    resolutions: Vec<ResolvedTrapObligation>,
}

impl TrapCoveragePlan {
    /// Computes guard closure over independently decoded permitted heads.
    ///
    /// Candidate and overlap obligations are resolved only by explicit guards.
    /// All other scan obligations, incomplete entry facts and saved resumes
    /// remain refusals. The caller must supply authenticated immutable facts;
    /// this pure operation cannot authenticate a remote process or its aliases.
    pub fn build(
        snapshot: &Snapshot,
        target: AddressRange,
        entries: &LegalEntrySet,
        policy: &Policy,
        budget: TrapCoverageBudget,
    ) -> Result<Self, TrapCoverageRefusal> {
        Builder::new(snapshot, target, entries, policy, budget)?.build()
    }
    /// Original immutable source and mapping identity/generation.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    /// Exact versioned entry facts used by the proof.
    pub fn entries(&self) -> &LegalEntrySet {
        &self.entries
    }
    /// Complete selected policy; no suffix class is deselected.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    /// Original requested whole-page target.
    pub const fn target(&self) -> AddressRange {
        self.target
    }
    /// Geometry used for complete-page closure.
    pub const fn page_size(&self) -> u64 {
        self.page_size
    }
    /// Every complete page required by a guard's original instruction.
    pub fn pages(&self) -> &BTreeSet<u64> {
        &self.pages
    }
    /// Merged read/restore/write dependencies, including non-admitted scan halos.
    pub fn dependencies(&self) -> &[AddressRange] {
        &self.dependencies
    }
    /// Required one-byte guards keyed by original address.
    pub fn guards(&self) -> &BTreeMap<u64, TrapGuard> {
        &self.guards
    }
    /// Original reports, including their still-refused scanner verdicts.
    pub fn reports(&self) -> &[ScanReport] {
        &self.reports
    }
    /// Separate evidence resolving only the stated candidate/overlap obligations.
    pub fn resolutions(&self) -> &[ResolvedTrapObligation] {
        &self.resolutions
    }
}

struct Builder<'a> {
    snapshot: &'a Snapshot,
    entries: &'a LegalEntrySet,
    policy: &'a Policy,
    target: AddressRange,
    budget: TrapCoverageBudget,
    pages: BTreeSet<u64>,
    scanned: BTreeSet<u64>,
    guards: BTreeMap<u64, TrapGuard>,
    decoded: BTreeMap<u64, Vec<u8>>,
    dependencies: Vec<AddressRange>,
    reports: Vec<ScanReport>,
    original_bytes: usize,
}

impl<'a> Builder<'a> {
    fn new(
        snapshot: &'a Snapshot,
        target: AddressRange,
        entries: &'a LegalEntrySet,
        policy: &'a Policy,
        budget: TrapCoverageBudget,
    ) -> Result<Self, TrapCoverageRefusal> {
        if !budget.page_size.is_power_of_two()
            || budget.page_size < 16
            || [
                budget.max_pages,
                budget.max_guards,
                budget.max_heads,
                budget.max_original_bytes,
                budget.max_snapshot_bytes,
                budget.max_rounds,
            ]
            .contains(&0)
        {
            return Err(TrapCoverageRefusal::InvalidBudget);
        }
        if [
            snapshot.range().start(),
            snapshot.range().end(),
            target.start(),
            target.end(),
        ]
        .iter()
        .any(|address| address % budget.page_size != 0)
        {
            return Err(TrapCoverageRefusal::UnalignedRange);
        }
        if !snapshot.range().covers(target) {
            return Err(TrapCoverageRefusal::OutsideSnapshot);
        }
        if snapshot.bytes().len() > budget.max_snapshot_bytes {
            return Err(TrapCoverageRefusal::BudgetExceeded(
                TrapBudgetResource::SnapshotBytes,
            ));
        }
        if entries
            .heads()
            .len()
            .saturating_add(entries.resumes().len())
            > budget.max_heads
        {
            return Err(TrapCoverageRefusal::BudgetExceeded(
                TrapBudgetResource::Heads,
            ));
        }
        if entries.completeness() != Completeness::AllInstructionHeads {
            return Err(unresolved(target, vec![Obligation::IncompleteEntries]));
        }
        let mut builder = Self {
            snapshot,
            entries,
            policy,
            target,
            budget,
            pages: BTreeSet::new(),
            scanned: BTreeSet::new(),
            guards: BTreeMap::new(),
            decoded: BTreeMap::new(),
            dependencies: Vec::new(),
            reports: Vec::new(),
            original_bytes: 0,
        };
        builder.add_pages(target)?;
        Ok(builder)
    }

    fn add_pages(&mut self, range: AddressRange) -> Result<(), TrapCoverageRefusal> {
        let mask = self.budget.page_size - 1;
        let first = range.start() & !mask;
        let last = (range.end() - 1) & !mask;
        let mut page = first;
        loop {
            let end = page
                .checked_add(self.budget.page_size)
                .ok_or(TrapCoverageRefusal::OutsideSnapshot)?;
            if !self
                .snapshot
                .range()
                .covers(AddressRange::new(page, end).unwrap())
            {
                return Err(TrapCoverageRefusal::OutsideSnapshot);
            }
            self.pages.insert(page);
            if self.pages.len() > self.budget.max_pages {
                return Err(TrapCoverageRefusal::BudgetExceeded(
                    TrapBudgetResource::Pages,
                ));
            }
            if page == last {
                break;
            }
            page = end;
        }
        Ok(())
    }

    fn decode_head(&mut self, address: u64) -> Result<Vec<u8>, TrapCoverageRefusal> {
        if let Some(bytes) = self.decoded.get(&address) {
            return Ok(bytes.clone());
        }
        if !self.snapshot.range().contains(address) {
            return Err(TrapCoverageRefusal::OutsideSnapshot);
        }
        let offset = (address - self.snapshot.range().start()) as usize;
        let available = &self.snapshot.bytes()[offset..];
        let instruction = Decoder::with_ip(
            64,
            &available[..available.len().min(15)],
            address,
            DecoderOptions::NONE,
        )
        .decode();
        if instruction.is_invalid() {
            return Err(unresolved(
                self.target,
                vec![Obligation::InvalidKnownInstruction(address)],
            ));
        }
        let bytes = available[..instruction.len()].to_vec();
        self.dependencies
            .push(AddressRange::from_len(address, bytes.len()).unwrap());
        self.decoded.insert(address, bytes.clone());
        Ok(bytes)
    }

    fn add_guard(&mut self, address: u64, role: TrapGuardRole) -> Result<(), TrapCoverageRefusal> {
        if let Some(existing) = self.guards.get_mut(&address) {
            if let TrapGuardRole::Selected(candidate) = role {
                if usize::from(candidate.len) != existing.original_bytes.len() {
                    return Err(TrapCoverageRefusal::CandidateDecodeMismatch(address));
                }
                match existing.role {
                    TrapGuardRole::Selected(prior) if prior.class != candidate.class => {
                        return Err(TrapCoverageRefusal::CandidateDecodeMismatch(address));
                    }
                    TrapGuardRole::Collateral => existing.role = role,
                    // Preserve the first report's classification. A later
                    // halo scan can have different enclosing-head visibility;
                    // every report and its original classification is retained.
                    TrapGuardRole::Selected(_) => {}
                }
            }
            return Ok(());
        }
        let original_bytes = self.decode_head(address)?;
        if let TrapGuardRole::Selected(candidate) = role {
            if usize::from(candidate.len) != original_bytes.len() {
                return Err(TrapCoverageRefusal::CandidateDecodeMismatch(address));
            }
        }
        if self.guards.len() >= self.budget.max_guards {
            return Err(TrapCoverageRefusal::BudgetExceeded(
                TrapBudgetResource::Guards,
            ));
        }
        self.original_bytes = self.original_bytes.saturating_add(original_bytes.len());
        if self.original_bytes > self.budget.max_original_bytes {
            return Err(TrapCoverageRefusal::BudgetExceeded(
                TrapBudgetResource::OriginalBytes,
            ));
        }
        self.add_pages(AddressRange::from_len(address, original_bytes.len()).unwrap())?;
        self.guards.insert(
            address,
            TrapGuard {
                address,
                original_bytes,
                role,
            },
        );
        Ok(())
    }

    fn build(mut self) -> Result<TrapCoveragePlan, TrapCoverageRefusal> {
        let mut stable = false;
        for _ in 0..self.budget.max_rounds {
            let before = (self.pages.len(), self.guards.len());
            let pending: Vec<_> = self.pages.difference(&self.scanned).copied().collect();
            for page in pending {
                let target = AddressRange::new(page, page + self.budget.page_size).unwrap();
                let report = RuntimeScan.inspect(self.snapshot, target, self.entries, self.policy);
                let unresolved_obligations: Vec<_> = report
                    .obligations()
                    .iter()
                    .filter(|obligation| {
                        !matches!(
                            obligation,
                            Obligation::EmbeddedCandidate(_)
                                | Obligation::UnresolvedCandidate(_)
                                | Obligation::OverlappingInstructions(_)
                        )
                    })
                    .cloned()
                    .collect();
                if !unresolved_obligations.is_empty() {
                    return Err(unresolved(target, report.obligations().to_vec()));
                }
                self.dependencies.push(report.dependency());
                // RuntimeScan also decodes declared heads in the trailing halo.
                // Retain their full byte ranges, even when they extend beyond
                // that halo, without accidentally granting X to those pages.
                let heads: Vec<_> = self
                    .entries
                    .heads()
                    .range(report.dependency().as_range())
                    .map(|(&pc, _)| pc)
                    .collect();
                for head in heads {
                    self.decode_head(head)?;
                }
                for candidate in report.candidates() {
                    self.add_guard(candidate.address, TrapGuardRole::Selected(*candidate))?;
                }
                self.reports.push(report);
                self.scanned.insert(page);
            }
            let guards: Vec<_> = self.guards.keys().copied().collect();
            for guard in guards {
                let first = guard.saturating_sub(14).max(self.snapshot.range().start());
                let heads: Vec<_> = self
                    .entries
                    .heads()
                    .range(first..=guard)
                    .map(|(&head, _)| head)
                    .collect();
                for head in heads {
                    let bytes = self.decode_head(head)?;
                    if AddressRange::from_len(head, bytes.len())
                        .unwrap()
                        .contains(guard)
                    {
                        self.add_guard(head, TrapGuardRole::Collateral)?;
                    }
                }
            }
            if before == (self.pages.len(), self.guards.len()) && self.pages == self.scanned {
                stable = true;
                break;
            }
        }
        if !stable {
            return Err(TrapCoverageRefusal::BudgetExceeded(
                TrapBudgetResource::Rounds,
            ));
        }
        let dependencies = merged(self.dependencies);
        if dependencies
            .iter()
            .any(|range| !self.entries.scope().covers(*range))
        {
            return Err(unresolved(
                self.target,
                vec![Obligation::EntryScopeTooSmall],
            ));
        }
        let saved: Vec<_> = self
            .entries
            .resumes()
            .keys()
            .copied()
            .filter(|pc| dependencies.iter().any(|range| range.contains(*pc)))
            .map(Obligation::SavedResume)
            .collect();
        if !saved.is_empty() {
            return Err(unresolved(self.target, saved));
        }
        let mut resolutions = Vec::new();
        for report in &self.reports {
            for obligation in report.obligations() {
                let address = match obligation {
                    Obligation::EmbeddedCandidate(address)
                    | Obligation::UnresolvedCandidate(address)
                    | Obligation::OverlappingInstructions(address) => *address,
                    _ => return Err(unresolved(report.target(), vec![obligation.clone()])),
                };
                let mut covering = BTreeSet::from([address]);
                for (&head, bytes) in &self.decoded {
                    if self.entries.heads().contains_key(&head)
                        && AddressRange::from_len(head, bytes.len())
                            .unwrap()
                            .contains(address)
                    {
                        covering.insert(head);
                    }
                }
                let selected_required =
                    !matches!(obligation, Obligation::OverlappingInstructions(_));
                if covering.iter().any(|head| !self.guards.contains_key(head))
                    || (selected_required
                        && !matches!(
                            self.guards.get(&address).map(TrapGuard::role),
                            Some(TrapGuardRole::Selected(_))
                        ))
                {
                    return Err(unresolved(report.target(), vec![obligation.clone()]));
                }
                resolutions.push(ResolvedTrapObligation {
                    target: report.target(),
                    obligation: obligation.clone(),
                    guards: covering.into_iter().collect(),
                });
            }
        }
        Ok(TrapCoveragePlan {
            snapshot: self.snapshot.clone(),
            entries: self.entries.clone(),
            policy: self.policy.clone(),
            target: self.target,
            page_size: self.budget.page_size,
            pages: self.pages,
            dependencies,
            guards: self.guards,
            reports: self.reports,
            resolutions,
        })
    }
}

fn unresolved(target: AddressRange, obligations: Vec<Obligation>) -> TrapCoverageRefusal {
    TrapCoverageRefusal::UnresolvedObligations {
        target,
        obligations,
    }
}

fn merged(mut ranges: Vec<AddressRange>) -> Vec<AddressRange> {
    ranges.sort_unstable();
    let mut result: Vec<AddressRange> = Vec::new();
    for range in ranges {
        if let Some(last) = result.last_mut() {
            if range.start() <= last.end() {
                *last = AddressRange::new(last.start(), last.end().max(range.end())).unwrap();
                continue;
            }
        }
        result.push(range);
    }
    result
}
