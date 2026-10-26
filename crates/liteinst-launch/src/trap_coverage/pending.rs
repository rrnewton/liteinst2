//! Unresolved geometry for the explicit dynamic saved-resume path.
//!
//! These values retain refused reports and every resume requirement. They are
//! deliberately not `TrapCoveragePlan`, cannot be converted into one, and have
//! no publication, native hold, generation, origin-census or release authority.
//! A consumer still needs each original resume's independently authenticated
//! origin and route. A deduplicated `(pc, kind)` is not an origin census.

use std::collections::{BTreeMap, BTreeSet};

use liteinst_admission::AddressRange;
use liteinst_admission::entries::{LegalEntrySet, ResumeKind};
use liteinst_admission::scan::{
    AdmissionOracle, Candidate, Obligation, Policy, ScanReport, Snapshot,
};

use super::{
    Builder, Geometry, ResolvedTrapObligation, ResumeMode, TrapCoverageBudget, TrapCoverageRefusal,
    TrapGuard, TrapGuardRole, merged, unresolved,
};

/// The original check which still requires an independently proved route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResumeRequirementSource {
    /// Exact indices into the retained original report and its obligations.
    Report {
        report_index: usize,
        obligation_index: usize,
    },
    /// The final merged read/restore dependency, including decoded tails and
    /// clean reports for which RuntimeScan did not emit SavedResume.
    Dependency { index: usize, range: AddressRange },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResumeRequirement {
    address: u64,
    kinds: BTreeSet<ResumeKind>,
    source: ResumeRequirementSource,
}

impl ResumeRequirement {
    pub(crate) const fn address(&self) -> u64 {
        self.address
    }

    pub(crate) fn kinds(&self) -> &BTreeSet<ResumeKind> {
        &self.kinds
    }

    pub(crate) const fn source(&self) -> ResumeRequirementSource {
        self.source
    }
}

/// Placement facts awaiting native backstops, never a completed placement plan.
/// All fields are immutable to consumers; even an empty requirement list does
/// not confer native publication or entry-census completeness authority.
pub(crate) struct PendingCoverage {
    geometry: Geometry,
    resumes: Vec<ResumeRequirement>,
}

impl PendingCoverage {
    /// Shares the exact candidate/overlap closure with the public builder.
    /// Only SavedResume is deferred. Original reports and verdicts are retained.
    pub(crate) fn build_with_oracle(
        snapshot: &Snapshot,
        target: AddressRange,
        entries: &LegalEntrySet,
        policy: &Policy,
        budget: TrapCoverageBudget,
        oracle: &impl AdmissionOracle,
    ) -> Result<Self, TrapCoverageRefusal> {
        let geometry = Builder::new(snapshot, target, entries, policy, budget)?
            .geometry(oracle, ResumeMode::Pending)?;
        Self::from_geometry(geometry)
    }

    /// Retains strict-domain reports after that domain's original inspection,
    /// deadline and candidate checks. This does not enable overlap resolution:
    /// every non-SavedResume report obligation is still an immediate refusal.
    /// It uses the same original-head decoder and complete-instruction geometry
    /// as explicit coverage, without another scan or a new selected decoder.
    pub(crate) fn from_strict_reports(
        source: (&Snapshot, &LegalEntrySet, &Policy),
        target: AddressRange,
        budget: TrapCoverageBudget,
        closure: (BTreeSet<u64>, BTreeMap<u64, Candidate>, Vec<ScanReport>),
    ) -> Result<Self, TrapCoverageRefusal> {
        let (snapshot, entries, policy) = source;
        let (pages, candidates, reports) = closure;
        let mut builder = Builder::new(snapshot, target, entries, policy, budget)?;
        for &page in &pages {
            let end = page
                .checked_add(budget.page_size)
                .ok_or(TrapCoverageRefusal::OutsideSnapshot)?;
            builder.add_pages(AddressRange::new(page, end).unwrap())?;
        }
        let mut observed_candidates = BTreeMap::new();
        for report in reports {
            if report.snapshot() != snapshot
                || report.entries() != entries
                || report.policy() != policy
                || report.target().end() - report.target().start() != budget.page_size
                || !pages.contains(&report.target().start())
                || !builder.scanned.insert(report.target().start())
            {
                return Err(TrapCoverageRefusal::OracleFactsMismatch);
            }
            if report
                .obligations()
                .iter()
                .any(|obligation| !matches!(obligation, Obligation::SavedResume(_)))
            {
                return Err(unresolved(report.target(), report.obligations().to_vec()));
            }
            builder.dependencies.push(report.dependency());
            let heads: Vec<_> = entries
                .heads()
                .range(report.dependency().as_range())
                .map(|(&pc, _)| pc)
                .collect();
            for head in heads {
                builder.decode_head(head)?;
            }
            for candidate in report.candidates() {
                observed_candidates.insert(candidate.address, *candidate);
                builder.add_guard(candidate.address, TrapGuardRole::Selected(*candidate))?;
            }
            builder.reports.push(report);
        }
        if builder.pages != pages || builder.scanned != pages || observed_candidates != candidates {
            return Err(TrapCoverageRefusal::OracleFactsMismatch);
        }
        let dependencies = merged(builder.dependencies);
        if dependencies
            .iter()
            .any(|range| !entries.scope().covers(*range))
        {
            return Err(unresolved(target, vec![Obligation::EntryScopeTooSmall]));
        }
        Self::from_geometry(Geometry {
            snapshot: snapshot.clone(),
            entries: entries.clone(),
            policy: policy.clone(),
            target,
            page_size: budget.page_size,
            pages,
            dependencies,
            guards: builder.guards,
            decoded: builder.decoded,
            reports: builder.reports,
            resolutions: Vec::new(),
        })
    }

    fn from_geometry(geometry: Geometry) -> Result<Self, TrapCoverageRefusal> {
        let mut resumes = Vec::new();
        for (report_index, report) in geometry.reports.iter().enumerate() {
            for (obligation_index, obligation) in report.obligations().iter().enumerate() {
                if let Obligation::SavedResume(address) = obligation {
                    let kinds = geometry
                        .entries
                        .resumes()
                        .get(address)
                        .ok_or(TrapCoverageRefusal::OracleFactsMismatch)?;
                    resumes.push(ResumeRequirement {
                        address: *address,
                        kinds: kinds.clone(),
                        source: ResumeRequirementSource::Report {
                            report_index,
                            obligation_index,
                        },
                    });
                }
            }
        }
        for (index, &range) in geometry.dependencies.iter().enumerate() {
            for (&address, kinds) in geometry.entries.resumes().range(range.as_range()) {
                resumes.push(ResumeRequirement {
                    address,
                    kinds: kinds.clone(),
                    source: ResumeRequirementSource::Dependency { index, range },
                });
            }
        }
        Ok(Self { geometry, resumes })
    }

    pub(crate) fn snapshot(&self) -> &Snapshot {
        &self.geometry.snapshot
    }
    pub(crate) fn entries(&self) -> &LegalEntrySet {
        &self.geometry.entries
    }
    pub(crate) fn policy(&self) -> &Policy {
        &self.geometry.policy
    }
    pub(crate) const fn target(&self) -> AddressRange {
        self.geometry.target
    }
    pub(crate) const fn page_size(&self) -> u64 {
        self.geometry.page_size
    }
    pub(crate) fn pages(&self) -> &BTreeSet<u64> {
        &self.geometry.pages
    }
    pub(crate) fn dependencies(&self) -> &[AddressRange] {
        &self.geometry.dependencies
    }
    pub(crate) fn guards(&self) -> &BTreeMap<u64, TrapGuard> {
        &self.geometry.guards
    }
    /// Full original decodes used by closure, including declared halo/tail heads.
    /// This includes selected alternate starts as well as declared heads; the
    /// unchanged entry set distinguishes them without relabelling either.
    pub(crate) fn decoded_heads(&self) -> &BTreeMap<u64, Vec<u8>> {
        &self.geometry.decoded
    }
    pub(crate) fn reports(&self) -> &[ScanReport] {
        &self.geometry.reports
    }
    /// Candidate/overlap resolutions only. SavedResume is never present here.
    pub(crate) fn resolutions(&self) -> &[ResolvedTrapObligation] {
        &self.geometry.resolutions
    }
    pub(crate) fn resume_requirements(&self) -> &[ResumeRequirement] {
        &self.resumes
    }
}

#[cfg(test)]
mod tests;
