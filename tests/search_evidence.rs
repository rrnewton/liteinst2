//! Fixed pure-planner evidence puzzles. No native coverage is claimed here.
use liteinst2::contracts::*;
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    self, AllocationPolicy, InstallRequest, PlannedInstall, PlanningFailure, SearchPolicy,
    TacticPolicy,
};
use liteinst2::search::{CandidateProof, RefusalClass, SearchDomain, SearchStop};

const PC: u64 = 0x2000_0000;
unsafe extern "C" fn noop(_: *mut liteinst2::trampoline::HookContext) {}

fn entries(code: &[u8]) -> LegalEntrySet {
    let identity = CodeIdentity {
        source: SourceIdentity([73; 32]),
        mapping: 73,
        generation: 1,
    };
    LegalEntrySet {
        identity,
        scope: AddressRange::new(PC, code.len()).unwrap(),
        provenance: EntryProvenance::Declared("fixed bounded-search evidence puzzle".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: vec![],
        resumes: ResumeObligation::NoneExist,
    }
}
fn policy(limit: usize) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![],
        preferred_address: Some(PC + 0x1_0000),
        max_candidates: limit,
        max_mappings: 1,
        max_mapped_bytes: 8192,
    }
}
fn plan(
    code: &[u8],
    block_len: usize,
    allocation: &AllocationPolicy,
    search: SearchPolicy,
) -> Result<PlannedInstall, PlanningFailure> {
    let entries = entries(code);
    let request = InstallRequest {
        identity: entries.identity,
        code,
        base_address: PC,
        function: entries.scope,
        block: AddressRange::new(PC, block_len).unwrap(),
        logical_pc: PC,
        entries: &entries,
        hook: noop,
        semantics: HookSemantics::Observe,
        allocation,
        search,
    };
    quiescent::plan_install_detailed(&request)
}
fn relocation() -> SearchPolicy {
    SearchPolicy {
        tactics: TacticPolicy::RelocationOnly,
        max_sites: 1,
        max_upstream_bytes: 0,
        ..SearchPolicy::default()
    }
}
const BODY: [u8; 6] = [0xb8, 7, 0, 0, 0, 0xc3];

#[test]
fn zero_site_and_zero_candidate_budgets_preserve_raw_refusals_and_known_work() {
    let no_site = plan(
        &BODY,
        5,
        &policy(1),
        SearchPolicy {
            max_sites: 0,
            ..relocation()
        },
    )
    .unwrap_err();
    assert_eq!(no_site.reason, Refusal::NoPatchWindow);
    assert!(no_site.attempts.is_empty());
    assert_eq!(no_site.search.runs.len(), 1);
    assert_eq!(no_site.search.runs[0].domain, SearchDomain::PhysicalSites);
    assert_eq!(no_site.search.runs[0].examined, 0);
    assert_eq!(
        no_site.search.runs[0].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    let no_image = plan(&BODY, 5, &policy(0), relocation()).unwrap_err();
    assert_eq!(no_image.reason, Refusal::AllocationUnavailable);
    assert_eq!(no_image.attempts.len(), 1);
    assert_eq!(
        no_image.attempts[0].refusal,
        Some(Refusal::AllocationUnavailable)
    );
    let run = no_image
        .search
        .runs
        .iter()
        .find(|run| run.domain == SearchDomain::SelectedImages)
        .unwrap();
    assert_eq!(run.examined, 0);
    assert_eq!(
        run.stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    let Some(CandidateProof::Indexed {
        omitted: Some(witness),
        ..
    }) = &run.candidates
    else {
        panic!("exact omitted slot required");
    };
    assert_eq!(witness.slot, 0);
    assert_eq!(witness.target, PC + 0x1_0000);
}

#[test]
fn same_allocation_refusal_and_equal_limit_do_not_conflate_complete_with_cutoff() {
    let cutoff = plan(&BODY, 5, &policy(1), relocation()).unwrap_err();
    let finite = AllocationPolicy {
        preferred_address: Some(PC + 5 + i32::MAX as u64),
        ..policy(1)
    };
    let complete = plan(&BODY, 5, &finite, relocation()).unwrap_err();
    for failure in [&cutoff, &complete] {
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(failure.attempts[0].physical_pc, PC);
        assert_eq!(
            failure.attempts[0].refusal,
            Some(Refusal::AllocationUnavailable)
        );
        assert_eq!(failure.search.runs[0].finite_total, Some(1));
        assert_eq!(failure.search.runs[0].stop, SearchStop::DomainComplete);
    }
    let image_run = |failure: &PlanningFailure| {
        failure
            .search
            .runs
            .iter()
            .find(|run| run.domain == SearchDomain::SelectedImages)
            .unwrap()
            .clone()
    };
    assert_eq!(image_run(&cutoff).examined, 1);
    assert_eq!(image_run(&complete).examined, 1);
    assert_eq!(
        image_run(&cutoff).stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    assert_eq!(image_run(&complete).stop, SearchStop::DomainComplete);
    assert!(matches!(
        image_run(&complete).candidates,
        Some(CandidateProof::Indexed {
            permanent_end_exclusive: Some(1),
            omitted: None
        })
    ));
}

#[test]
fn capacity_address_semantics_and_short_window_keep_distinct_local_evidence() {
    let capacity = plan(
        &BODY,
        5,
        &AllocationPolicy {
            max_mappings: 0,
            ..policy(1)
        },
        relocation(),
    )
    .unwrap_err();
    assert_eq!(capacity.reason, Refusal::AllocationUnavailable);
    assert!(
        capacity
            .search
            .refusals
            .iter()
            .any(|item| item.class == RefusalClass::ResourceCapacity)
    );
    assert!(
        !capacity
            .search
            .runs
            .iter()
            .any(|run| run.domain == SearchDomain::SelectedImages)
    );
    let address = plan(&BODY, 5, &policy(1), relocation()).unwrap_err();
    assert_eq!(address.reason, Refusal::AllocationUnavailable);
    assert!(
        address
            .search
            .refusals
            .iter()
            .any(|item| item.class == RefusalClass::AddressPolicy)
    );
    assert!(
        !address
            .search
            .refusals
            .iter()
            .any(|item| item.class == RefusalClass::ResourceCapacity)
    );
    let unsupported = plan(
        &[0x8e, 0xd8, 0x90, 0x90, 0x90, 0xc3],
        5,
        &policy(1),
        relocation(),
    )
    .unwrap_err();
    assert_eq!(
        unsupported.reason,
        Refusal::UnsupportedSemantics("Mov has no qualified A1 relocation contract".into())
    );
    assert!(
        unsupported
            .search
            .refusals
            .iter()
            .any(|item| item.class == RefusalClass::UnsupportedSemantics)
    );
    let short = plan(&[0x66, 0x90, 0xc3], 2, &policy(1), relocation()).unwrap_err();
    assert_eq!(short.reason, Refusal::NoPatchWindow);
    assert!(
        short
            .search
            .refusals
            .iter()
            .any(|item| item.class == RefusalClass::Prerequisite)
    );
    assert_eq!(short.search.runs[0].stop, SearchStop::DomainComplete);
}

#[test]
fn singleton_prefixed_pun_domain_completes_at_limit_one() {
    // L2/P1 fixes all four E9 displacement bytes: exactly one target exists.
    let code = [0x66, 0x90, 0, 0, 0x10, 0, 0xc3];
    let allocation = AllocationPolicy {
        preferred_address: Some(PC + 6 + 0x10_0000),
        ..policy(1)
    };
    let failure = plan(
        &code,
        2,
        &allocation,
        SearchPolicy {
            tactics: TacticPolicy::PrefixPunOnly,
            ..relocation()
        },
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    assert_eq!(
        failure.attempts[0].tactic,
        quiescent::PatchTactic::PrefixPun
    );
    let run = failure
        .search
        .runs
        .iter()
        .find(|run| run.domain == SearchDomain::SelectedImages)
        .unwrap();
    assert_eq!(run.examined, 1);
    assert_eq!(run.limit, 1);
    assert_eq!(run.finite_total, Some(1));
    assert_eq!(run.stop, SearchStop::DomainComplete);
    assert!(matches!(
        run.candidates,
        Some(CandidateProof::PageBoundary {
            omitted: None,
            returned: 1,
            ..
        })
    ));
}

#[test]
fn accepted_leaf_and_outer_capacity_refusal_remain_an_engine_failure() {
    let code = BODY;
    let entries = entries(&code);
    let allocation = AllocationPolicy {
        ranges: vec![AddressRange::new(PC + 0x1_0000, 0x1_0000).unwrap()],
        ..policy(1)
    };
    let request = InstallRequest {
        identity: entries.identity,
        code: &code,
        base_address: PC,
        function: entries.scope,
        block: AddressRange::new(PC, 5).unwrap(),
        logical_pc: PC,
        entries: &entries,
        hook: noop,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: relocation(),
    };
    let failure = liteinst2::engine::plan(
        &request,
        &allocation,
        liteinst2::engine::EnginePolicy {
            forced: Some(liteinst2::engine::Tactic::Relocation),
            bundle: liteinst2::bundle::BundleBudget {
                max_mappings: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    let attempt = &failure.attempts[0];
    assert_eq!(attempt.refusal, Some(Refusal::AllocationUnavailable));
    assert!(attempt.search.accepted);
    assert_eq!(
        attempt.outer_refusal.as_ref().unwrap().class,
        RefusalClass::ResourceCapacity
    );
    assert!(!attempt.search.classification_complete);
    assert_eq!(code, BODY);
}

#[test]
fn one_site_cutoff_then_two_site_success_preserves_order_and_positive_plan() {
    let code = [0xb8, 7, 0, 0, 0, 0x66, 0x90, 0xc3];
    let entries = entries(&code);
    let allocation = AllocationPolicy {
        ranges: vec![AddressRange::new(PC + 0x1_0000, 0x1_0000).unwrap()],
        ..policy(1)
    };
    let mut request = InstallRequest {
        identity: entries.identity,
        code: &code,
        base_address: PC,
        function: entries.scope,
        block: AddressRange::new(PC, 7).unwrap(),
        logical_pc: PC + 5,
        entries: &entries,
        hook: noop,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: SearchPolicy {
            max_upstream_bytes: 5,
            ..relocation()
        },
    };
    let failed = quiescent::plan_install_detailed(&request).unwrap_err();
    assert_eq!(failed.reason, Refusal::NoPatchWindow);
    assert_eq!(failed.attempts.len(), 1);
    assert_eq!(failed.attempts[0].physical_pc, PC + 5);
    assert_eq!(failed.attempts[0].refusal, Some(Refusal::NoPatchWindow));
    assert_eq!(failed.search.runs[0].finite_total, Some(2));
    assert_eq!(
        failed.search.runs[0].stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    request.search.max_sites = 2;
    let planned = quiescent::plan_install_detailed(&request).unwrap();
    assert_eq!(planned.plan().parts().physical_pc, PC);
    assert_eq!(planned.plan().parts().logical_pc, PC + 5);
    assert_eq!(planned.metrics().attempts.len(), 2);
    assert_eq!(planned.metrics().attempts[0].physical_pc, PC + 5);
    assert_eq!(
        planned.metrics().attempts[0].refusal,
        Some(Refusal::NoPatchWindow)
    );
    assert_eq!(planned.metrics().attempts[1].physical_pc, PC);
    assert_eq!(planned.metrics().attempts[1].refusal, None);
    assert_eq!(planned.metrics().search.runs[0].examined, 2);
    assert_eq!(planned.metrics().search.runs[0].stop, SearchStop::Accepted);
    assert!(planned.metrics().search.accepted);
}

#[test]
fn coalesced_zero_candidate_budget_uses_the_same_exact_generator_evidence() {
    use liteinst2::controls::{ControlledAction, ProbeControl};
    let code = [0xb8, 7, 0, 0, 0, 0xb8, 9, 0, 0, 0, 0xc3];
    let entries = entries(&code);
    let allocation = policy(0);
    let request = InstallRequest {
        identity: entries.identity,
        code: &code,
        base_address: PC,
        function: entries.scope,
        block: AddressRange::new(PC, 10).unwrap(),
        logical_pc: PC,
        entries: &entries,
        hook: noop,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: relocation(),
    };
    let actions = [
        ControlledAction {
            logical_pc: PC,
            control: ProbeControl::new(noop, false),
        },
        ControlledAction {
            logical_pc: PC + 5,
            control: ProbeControl::new(noop, true),
        },
    ];
    let failure = quiescent::plan_coalesced_detailed(&request, &actions).unwrap_err();
    assert_eq!(failure.reason, Refusal::AllocationUnavailable);
    assert_eq!(failure.attempts.len(), 1);
    let run = failure
        .search
        .runs
        .iter()
        .find(|run| run.domain == SearchDomain::SelectedImages)
        .unwrap();
    assert_eq!(run.examined, 0);
    assert_eq!(
        run.stop,
        SearchStop::BudgetLimited {
            remaining_at_least: 1
        }
    );
    assert_eq!(actions[0].logical_pc, PC);
    assert_eq!(actions[1].logical_pc, PC + 5);
    assert!(!actions[0].control.is_enabled());
    assert!(actions[1].control.is_enabled());
}

#[test]
fn zero_prefix_only_gate_does_not_invent_a_prefix_candidate() {
    let failure = plan(
        &[0x90, 0xc3],
        1,
        &policy(1),
        SearchPolicy {
            tactics: TacticPolicy::PrefixPunOnly,
            max_sites: 0,
            ..relocation()
        },
    )
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::NoPatchWindow);
    assert!(failure.attempts.is_empty());
    assert_eq!(failure.search.runs.len(), 1);
    assert_eq!(failure.search.runs[0].examined, 0);
    assert_eq!(
        failure.search.runs[0].stop,
        SearchStop::UnclassifiedBoundedStop
    );
    assert!(!failure.search.classification_complete);
}
