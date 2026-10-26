//! Explicit input facts and prospective resource limits. None grants admission.
use formats::ContentId;
use li2core::contracts::{AddressRange, EntryCompleteness, LegalEntry, ResumeObligation};
use li2core::engine::Tactic;
use li2core::planner::HookSemantics;
use li2core::quiescent::{AllocationPolicy, SearchPolicy};
use li2core::trampoline::SavedExtendedStateLayout;

#[derive(Clone, Debug)]
pub struct Hook {
    pub id: u64,
    pub pc: u64,
    pub length: usize,
    pub expected: ContentId,
}

/// Caller-supplied original decode/entry facts, authenticated by selection bytes.
/// Linear decode checks consistency; it does not establish CFG completeness.
#[derive(Clone, Debug)]
pub struct SelectedSite {
    pub id: u64,
    pub pc: u64,
    pub length: u8,
    pub file_offset: u64,
    pub snapshot: AddressRange,
    pub function: AddressRange,
    pub block: AddressRange,
    pub hook: u64,
    pub semantics: HookSemantics,
    pub forced: Option<Tactic>,
    pub selected_allocation: AllocationPolicy,
    pub victim_allocation: AllocationPolicy,
    pub search: SearchPolicy,
    pub forced_victim: Option<u64>,
    pub max_victims: usize,
    pub max_pairs: usize,
    pub heads: Vec<LegalEntry>,
    pub completeness: EntryCompleteness,
    pub resumes: ResumeObligation,
    pub provenance: ContentId,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub input_bytes: usize,
    pub sites: usize,
    pub images: usize,
    pub image_bytes: usize,
    pub new_load_pages: u64,
    pub output_bytes: u64,
    pub added_file_bytes: u64,
    pub program_headers: usize,
    pub virtual_span: u64,
}

#[derive(Clone, Debug)]
pub struct Selection {
    /// Exact original file digest, never an ELF build ID or path.
    pub original: ContentId,
    /// Exact bytes consumed by the strict selection parser.
    pub manifest: Vec<u8>,
    pub target: SavedExtendedStateLayout,
    pub bias_domain: u64,
    pub carrier_pc: u64,
    pub limits: Limits,
    pub hooks: Vec<Hook>,
    pub sites: Vec<SelectedSite>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub stage: &'static str,
    pub detail: String,
}
impl Error {
    pub(crate) fn new(stage: &'static str, detail: impl std::fmt::Debug) -> Self {
        Self {
            stage,
            detail: format!("{detail:?}"),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{}: {}", self.stage, self.detail)
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub struct SiteReport {
    pub id: u64,
    pub pc: u64,
    pub file_offset: u64,
    pub length: u8,
    /// Successful core leaf may remain present after outer composition refusal.
    pub core_tactic: Option<Tactic>,
    /// True only if the complete selected set appears in the candidate carrier.
    /// This is a structural rewrite result, never readiness or admission.
    pub candidate_emitted: bool,
    pub refusal: Option<Error>,
    /// Stable vocabulary: raw core Refusal codes 1..15, tool codes >= 10_000.
    pub refusal_code: Option<u32>,
    pub diagnostics: String,
}

pub(crate) fn tactic_name(t: Tactic) -> &'static str {
    match t {
        Tactic::Relocation => "B1",
        Tactic::GeneralizedPun => "B2",
        Tactic::PrefixedPun => "T1",
        Tactic::SuccessorEviction => "T2",
        Tactic::NeighborEviction => "T3",
    }
}
pub(crate) fn format_tactic(t: Tactic) -> formats::Tactic {
    match t {
        Tactic::Relocation => formats::Tactic::Relocation,
        Tactic::GeneralizedPun => formats::Tactic::GeneralizedPun,
        Tactic::PrefixedPun => formats::Tactic::PrefixedPun,
        Tactic::SuccessorEviction => formats::Tactic::SuccessorEviction,
        Tactic::NeighborEviction => formats::Tactic::NeighborEviction,
    }
}
pub(crate) fn core_code(r: &li2core::contracts::Refusal) -> u32 {
    use li2core::contracts::Refusal::*;
    match r {
        InvalidRange => 1,
        InvalidPlan => 2,
        StaleGeneration => 3,
        ExpectedBytesChanged => 4,
        DependencyNotHeld => 5,
        LeasePoisoned => 6,
        UnresolvedEntry => 7,
        NotInstructionHead => 8,
        NoPatchWindow => 9,
        UnsupportedSemantics(_) => 10,
        AllocationUnavailable => 11,
        OwnershipConflict => 12,
        SignalContract => 13,
        Synchronization => 14,
        Backend(_) => 15,
    }
}
