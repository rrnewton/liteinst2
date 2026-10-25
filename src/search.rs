//! Additive evidence about bounded planning. No refusal is a coverage success.
//!
//! Generator certificates cover the existing finite schedules, not every possible
//! byte address. Unproved stops and whole-tactic aggregation remain incomplete.

use crate::contracts::Refusal;

/// Independently bounded portion of a tactic's search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchDomain {
    /// Original physical instruction heads.
    PhysicalSites,
    /// Original neighboring victim heads.
    Victims,
    /// Selected generated-image candidate slots.
    SelectedImages,
    /// Callback-free generated-image candidate slots.
    VictimImages,
    /// Total selected/victim combinations charged by the neighbor planner.
    JointPairs,
}

/// Context for one search run; absent fields carry no inferred identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SearchScope {
    /// Original physical source instruction, when known.
    pub physical_pc: Option<u64>,
    /// Fixed victim-image placement for a nested selected-image search.
    pub victim_target: Option<u64>,
    /// Selected pun prefix count; zero denotes a generalized pun.
    pub prefix_count: Option<usize>,
}

/// Why one specific search run stopped, independently of its raw refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchStop {
    /// A usable result was found in this domain; outer composition may still fail.
    Accepted,
    /// Every item in a known finite declared domain was examined.
    DomainComplete,
    /// The configured bound omitted at least this many known items.
    BudgetLimited {
        /// A positive lower bound, not an estimate of feasible placements.
        remaining_at_least: usize,
    },
    /// A configured loop ended, but its uncapped schedule endpoint is unproved.
    UnclassifiedBoundedStop,
    /// Qualification, another search or a backend error interrupted this run.
    Interrupted,
}

/// A later representable indexed slot omitted by the configured prefix.
/// Its address is not a claim that policy, ownership or emission will accept it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateWitness {
    /// Original zero-based candidate slot; no slots were skipped or reordered.
    pub slot: usize,
    /// Exact output of the unchanged indexed target generator at that slot.
    pub target: u64,
}

/// Mechanical work in one existing pun page walk, before deduplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageWalkEvidence {
    /// Index in the caller's unchanged allocation range list.
    pub range_index: usize,
    /// Entire finite page-boundary sequence length for this range and window.
    pub finite_slots: u64,
    /// Slots entered by the existing per-range bounded loop, including duplicates.
    pub examined: usize,
}

/// A certificate about the existing candidate schedule, not address feasibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateProof {
    /// A permanent seed-arithmetic endpoint. Initial invalid slots and invalid
    /// constrained choices before this endpoint keep their original indices.
    /// The endpoint is sufficient, not necessarily the earliest final None.
    Indexed {
        /// Every slot at or beyond this index is None. None means the endpoint
        /// could not be represented, not that the schedule is infinite.
        permanent_end_exclusive: Option<usize>,
        /// A later exact Some(target), when one of the bounded witness probes
        /// proves it. Absence alone proves neither completion nor truncation.
        omitted: Option<CandidateWitness>,
    },
    /// Preferred target plus the current page-boundary walks, after deduplication.
    /// None omitted means every distinct address in THAT schedule was returned.
    PageBoundary {
        /// Number of targets returned to the existing planner, in original order.
        returned: usize,
        /// A distinct unreturned scheduled target, not a feasible mapping claim.
        omitted: Option<u64>,
        /// Exact original range-walk work, preserving both candidate caps.
        walks: Vec<PageWalkEvidence>,
    },
}

/// One scoped loop's exact counters and independently established stop condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchRun {
    /// The kind of work bounded by this loop.
    pub domain: SearchDomain,
    /// Original geometry associated with this run.
    pub scope: SearchScope,
    /// Configured maximum number of work slots.
    pub limit: usize,
    /// Work slots actually entered, including unavailable or duplicate addresses.
    pub examined: usize,
    /// Complete finite domain size, when derived from the original candidate list.
    pub finite_total: Option<usize>,
    /// Termination is not derived from Refusal::AllocationUnavailable.
    pub stop: SearchStop,
    /// Independent generator proof, when this is an image-candidate search.
    pub candidates: Option<CandidateProof>,
}

/// The established category of one refusal, scoped to its actual decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalClass {
    /// An explicit original-instruction semantic qualifier refused.
    UnsupportedSemantics,
    /// Input, original window, entry or ownership prerequisites failed.
    Prerequisite,
    /// An explicit bytes/mappings/steps or aggregate resource capacity failed.
    ResourceCapacity,
    /// A locally tested range or occupied-address policy rejected this candidate.
    AddressPolicy,
    /// An explicitly observed lower-level encoding or backend error.
    Backend,
    /// This draft does not yet prove a narrower category at this decision.
    Unclassified,
}

/// A local refusal proof. No local proof implies all other candidates fail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefusalEvidence {
    /// Exact local reason, without changing the public final refusal precedence.
    pub reason: Refusal,
    /// Category established at the actual decision point.
    pub class: RefusalClass,
    /// Geometry to which this evidence applies.
    pub scope: SearchScope,
}

/// Additive planning evidence; existing attempts and geometry keep their meanings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SearchEvidence {
    /// True only when this leaf returned a plan, not merely an emitted image.
    pub accepted: bool,
    /// False in this implementation: some constrained witness searches and
    /// scoped whole-tactic proof aggregation remain unfinished.
    pub classification_complete: bool,
    /// Ordered scoped search runs; failed earlier runs survive later success.
    pub runs: Vec<SearchRun>,
    /// Local qualified reasons; an empty vector does not prove absence of failure.
    pub refusals: Vec<RefusalEvidence>,
}

impl SearchEvidence {
    pub(crate) fn begin(
        &mut self,
        domain: SearchDomain,
        scope: SearchScope,
        limit: usize,
        finite_total: Option<usize>,
    ) -> usize {
        let id = self.runs.len();
        self.runs.push(SearchRun {
            domain,
            scope,
            limit,
            examined: 0,
            finite_total,
            stop: SearchStop::Interrupted,
            candidates: None,
        });
        id
    }

    pub(crate) fn visit(&mut self, id: usize) {
        self.runs[id].examined += 1;
    }

    pub(crate) fn finish(&mut self, id: usize) {
        let run = &mut self.runs[id];
        run.stop = match run.finite_total {
            Some(total) if run.examined == total => SearchStop::DomainComplete,
            Some(total) if run.examined == run.limit && total > run.examined => {
                SearchStop::BudgetLimited {
                    remaining_at_least: total - run.examined,
                }
            }
            _ => SearchStop::UnclassifiedBoundedStop,
        };
    }

    pub(crate) fn finish_candidates(&mut self, id: usize, proof: CandidateProof) {
        let run = &mut self.runs[id];
        run.stop = match &proof {
            CandidateProof::Indexed {
                permanent_end_exclusive: Some(end),
                ..
            } if run.examined >= *end => SearchStop::DomainComplete,
            CandidateProof::Indexed {
                omitted: Some(witness),
                ..
            } => {
                assert!(witness.slot >= run.examined);
                SearchStop::BudgetLimited {
                    remaining_at_least: 1,
                }
            }
            CandidateProof::Indexed { .. } => SearchStop::UnclassifiedBoundedStop,
            CandidateProof::PageBoundary {
                omitted: None,
                returned,
                ..
            } => {
                assert_eq!(run.examined, *returned);
                run.finite_total = Some(*returned);
                SearchStop::DomainComplete
            }
            CandidateProof::PageBoundary {
                omitted: Some(_), ..
            } => SearchStop::BudgetLimited {
                remaining_at_least: 1,
            },
        };
        run.candidates = Some(proof);
    }

    pub(crate) fn accept(&mut self, id: usize) {
        self.runs[id].stop = SearchStop::Accepted;
    }

    pub(crate) fn known_limit_hit(&mut self, id: usize, remaining_at_least: usize) {
        assert!(remaining_at_least > 0);
        assert_eq!(self.runs[id].examined, self.runs[id].limit);
        self.runs[id].stop = SearchStop::BudgetLimited { remaining_at_least };
    }

    pub(crate) fn refusal(&mut self, scope: SearchScope, class: RefusalClass, reason: &Refusal) {
        self.refusals.push(RefusalEvidence {
            reason: reason.clone(),
            class,
            scope,
        });
    }

    pub(crate) fn qualification(&mut self, scope: SearchScope, reason: &Refusal) {
        let class = match reason {
            Refusal::UnsupportedSemantics(_) => RefusalClass::UnsupportedSemantics,
            Refusal::NoPatchWindow | Refusal::NotInstructionHead | Refusal::UnresolvedEntry => {
                RefusalClass::Prerequisite
            }
            Refusal::Backend(_) => RefusalClass::Backend,
            _ => RefusalClass::Unclassified,
        };
        self.refusal(scope, class, reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_with_limit_is_not_itself_exhaustion() {
        let mut evidence = SearchEvidence::default();
        let complete = evidence.begin(
            SearchDomain::PhysicalSites,
            SearchScope::default(),
            1,
            Some(1),
        );
        evidence.visit(complete);
        evidence.finish(complete);
        assert_eq!(evidence.runs[complete].stop, SearchStop::DomainComplete);
        let truncated = evidence.begin(SearchDomain::Victims, SearchScope::default(), 1, Some(2));
        evidence.visit(truncated);
        evidence.finish(truncated);
        assert_eq!(
            evidence.runs[truncated].stop,
            SearchStop::BudgetLimited {
                remaining_at_least: 1
            }
        );
        let unknown = evidence.begin(
            SearchDomain::SelectedImages,
            SearchScope::default(),
            1,
            None,
        );
        evidence.visit(unknown);
        evidence.finish(unknown);
        assert_eq!(
            evidence.runs[unknown].stop,
            SearchStop::UnclassifiedBoundedStop
        );
        assert!(!evidence.classification_complete);
    }
}
