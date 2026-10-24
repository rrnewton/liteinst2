//! Lossless fact export to the A0 core contract. This exports no execution
//! capability, never fabricates a quiescence lease and never publishes code.
use liteinst2::contracts as core;

use crate::entries::{Completeness, EntryProvenance};
use crate::scan::{Candidate, Policy, ScanReport, Verdict};

/// An empty recorded-resume list is not proof that no saved context exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeCoverage {
    Unresolved,
    /// The mapping owner has accounted for every saved context in the scope.
    Exhaustive,
}

#[derive(Clone, Debug)]
pub struct CoreFacts {
    pub entries: core::LegalEntrySet,
    pub expected: core::ExpectedBytes,
    pub entry_version: u64,
    pub policy: Policy,
    pub selected: Vec<Candidate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportError {
    Refused,
    IdentityMismatch,
    Range,
    UnverifiedResume(u64),
}

/// The owner authenticates `identity.source` against original content and policy.
/// It must advance identity.generation on *any* byte/entry/policy/alias change,
/// including entry-version changes. The exact expected bytes are retained here
/// for the publisher's separate prepublication comparison.
pub fn export(
    report: &ScanReport,
    identity: core::CodeIdentity,
    resumes: ResumeCoverage,
) -> Result<CoreFacts, ExportError> {
    if report.verdict() == Verdict::Refused {
        return Err(ExportError::Refused);
    }
    if identity.mapping != report.snapshot().mapping.0
        || identity.generation != report.snapshot().generation.0
    {
        return Err(ExportError::IdentityMismatch);
    }
    let source = report.entries();
    if resumes == ResumeCoverage::Exhaustive {
        for &pc in source.resumes().keys() {
            if !source.heads().contains_key(&pc) {
                return Err(ExportError::UnverifiedResume(pc));
            }
        }
    }
    let scope = core::AddressRange::new(
        source.scope().start(),
        usize::try_from(source.scope().end() - source.scope().start())
            .map_err(|_| ExportError::Range)?,
    )
    .map_err(|_| ExportError::Range)?;
    let entries = core::LegalEntrySet {
        identity,
        scope,
        provenance: core::EntryProvenance::Declared(format!(
            "admission entry version {}; provenance {:?}",
            source.version(),
            source.heads()
        )),
        completeness: match source.completeness() {
            Completeness::Partial => core::EntryCompleteness::Incomplete,
            Completeness::AllInstructionHeads => core::EntryCompleteness::AllInstructionHeads,
        },
        entries: source
            .heads()
            .iter()
            .map(|(&address, kinds)| core::LegalEntry {
                address,
                requires_endbr: kinds.contains(&EntryProvenance::Endbr64),
            })
            .collect(),
        resumes: match resumes {
            ResumeCoverage::Unresolved => core::ResumeObligation::Unresolved,
            ResumeCoverage::Exhaustive if source.resumes().is_empty() => {
                core::ResumeObligation::NoneExist
            }
            ResumeCoverage::Exhaustive => {
                core::ResumeObligation::Enumerated(source.resumes().keys().copied().collect())
            }
        },
    };
    let start = (report.dependency().start() - report.snapshot().range().start()) as usize;
    let end = (report.dependency().end() - report.snapshot().range().start()) as usize;
    Ok(CoreFacts {
        entries,
        expected: core::ExpectedBytes {
            address: report.dependency().start(),
            bytes: report.snapshot().bytes()[start..end].to_vec(),
        },
        entry_version: source.version(),
        policy: report.policy().clone(),
        selected: report.candidates().to_vec(),
    })
}
