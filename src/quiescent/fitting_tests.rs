//! Pure fitting-path emission controls. No generated code is mapped or run.
use super::*;
use crate::emission::{
    ArtifactEmission, ArtifactRequest, PlanningSite, SymbolicHook, TargetProfile,
};
use crate::trampoline::SavedExtendedStateLayout;

fn install(
    code: &[u8],
    heads: &[u64],
    pc: u64,
    seed: u64,
    tactic: TacticPolicy,
    fitting: bool,
) -> Result<PlannedInstall, PlanningFailure> {
    let identity = CodeIdentity {
        source: SourceIdentity([17; 32]),
        mapping: 1,
        generation: 1,
    };
    let source = AddressRange::new(pc, code.len()).unwrap();
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared("pure fitting emission fixture".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: heads
            .iter()
            .map(|offset| LegalEntry {
                address: pc + offset,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    };
    let allocation = AllocationPolicy {
        ranges: vec![AddressRange::new(262144, 2147483648 - 262144).unwrap()],
        preferred_address: Some(seed),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            SavedExtendedStateLayout::describe_target_fxsave64(),
            7,
        )
        .unwrap(),
        SymbolicHook {
            identity: 11,
            address: Some(pc + 4096),
        },
        vec![AddressRange::new(pc & !4095, 4096).unwrap()],
    );
    let request = ArtifactRequest {
        site: PlanningSite {
            identity,
            code,
            base_address: pc,
            function: source,
            block: source,
            logical_pc: pc,
            entries: &entries,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: tactic,
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        },
        emission: &emission,
    };
    let request = PlanningRequest::artifact(&request);
    plan_install_core(&if fitting {
        request.with_fitting_placement()
    } else {
        request.with_current_placement()
    })
}

fn one_image(plan: &PlannedInstall) {
    assert_eq!(plan.metrics().allocation_attempts, 1);
    let runs: Vec<_> = plan
        .metrics()
        .search
        .runs
        .iter()
        .filter(|run| run.domain == crate::search::SearchDomain::SelectedImages)
        .collect();
    assert_eq!(runs.len(), 1);
    assert_eq!((runs[0].limit, runs[0].examined), (1, 1));
    assert_eq!(plan.plan().parts().generated.len(), 1);
    assert_eq!(plan.plan().parts().allocations.len(), 1);
    let allocation = plan.plan().parts().allocations[0].range;
    assert_eq!(allocation.len(), 4096);
    assert!(
        allocation
            .covers(AddressRange::new(plan.image().address(), plan.image().bytes().len()).unwrap())
    );
    assert!(
        !plan
            .image()
            .artifact_metadata()
            .unwrap()
            .qualification_complete()
    );
}

#[test]
fn fitting_b1_preserves_fitting_seed_and_avoids_known_single_image_capacity_failure() {
    let code = [0x53, 0x4c, 0x8b, 0x0f, 0x48, 0x89, 0xfb, 0xc3];
    let heads = [0, 1, 4, 7];
    let old = install(
        &code,
        &heads,
        11216,
        1905890,
        TacticPolicy::RelocationOnly,
        false,
    )
    .unwrap();
    let same = install(
        &code,
        &heads,
        11216,
        1905890,
        TacticPolicy::RelocationOnly,
        true,
    )
    .unwrap();
    assert_eq!(same.plan(), old.plan());
    assert_eq!(same.image().bytes(), old.image().bytes());
    assert_eq!(same.image().address(), 102569179);
    one_image(&same);
    let failed = install(
        &code,
        &heads,
        11216,
        12333056,
        TacticPolicy::RelocationOnly,
        false,
    )
    .unwrap_err();
    assert!(
        failed
            .search
            .refusals
            .iter()
            .any(|r| r.class == crate::search::RefusalClass::ResourceCapacity)
    );
    let fitting = install(
        &code,
        &heads,
        11216,
        12333056,
        TacticPolicy::RelocationOnly,
        true,
    )
    .unwrap();
    assert_eq!(fitting.image().address() % 4096, 219);
    assert_ne!(fitting.image().address(), 112996315);
    one_image(&fitting);
}

#[test]
fn fitting_b2_emits_once_at_certified_window_target_and_keeps_source_padding() {
    let pc = 0x400080;
    let code = [0x0f, 0x1f, 0, 0xb8, 42, 0, 0, 0, 0xc3];
    let low = pc + 5 + 0x2ab8_0000;
    let seed = (low & !4095) + 4080;
    let failed = install(
        &code,
        &[0, 3, 8],
        pc,
        seed,
        TacticPolicy::GeneralizedPunOnly,
        false,
    )
    .unwrap_err();
    assert!(
        failed
            .search
            .refusals
            .iter()
            .any(|r| r.class == crate::search::RefusalClass::ResourceCapacity)
    );
    let fitting = install(
        &code,
        &[0, 3, 8],
        pc,
        seed,
        TacticPolicy::GeneralizedPunOnly,
        true,
    )
    .unwrap();
    assert_eq!(fitting.image().address() % 4096, 0);
    assert!(
        AddressRange::new(low, 1 << 16)
            .unwrap()
            .contains(fitting.image().address())
    );
    one_image(&fitting);
    let parts = fitting.plan().parts();
    assert_eq!(
        parts.reads,
        [ExpectedBytes {
            address: pc,
            bytes: code.to_vec()
        }]
    );
    let PlanKind::GeneralizedPun(pun) = &parts.kind else {
        panic!("B2 required")
    };
    assert_eq!(pun.target_window, AddressRange::new(low, 1 << 16).unwrap());
    assert_eq!(pun.store.bytes.len(), 4);
    assert_eq!(pun.store.bytes.last(), Some(&0xb8));
    assert_eq!(parts.writes[0].bytes.len(), 3);
}

#[test]
fn fitting_t1_keeps_exact_singleton_and_refuses_uncertified_singleton() {
    let code = [0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3];
    let pc = 0x400080;
    let seed = pc + 6 + 0x2ab8;
    let old = install(
        &code,
        &[0, 2, 7],
        pc,
        seed,
        TacticPolicy::PrefixPunOnly,
        false,
    )
    .unwrap();
    let fitting = install(
        &code,
        &[0, 2, 7],
        pc,
        seed,
        TacticPolicy::PrefixPunOnly,
        true,
    )
    .unwrap();
    assert_eq!(fitting.plan(), old.plan());
    assert_eq!(fitting.image().bytes(), old.image().bytes());
    one_image(&fitting);
    let PlanKind::PrefixedPun(pun) = &fitting.plan().parts().kind else {
        panic!("T1 required")
    };
    assert_eq!(pun.target_window, AddressRange::new(seed, 1).unwrap());
    // One fixed address at offset 4095 cannot fit even the fixed return E9.
    let pc = 0x400000 + (4095 - (6 + 0x2ab8) % 4096);
    let seed = pc + 6 + 0x2ab8;
    assert_eq!(seed % 4096, 4095);
    assert!(
        install(
            &code,
            &[0, 2, 7],
            pc,
            seed,
            TacticPolicy::PrefixPunOnly,
            true
        )
        .is_err()
    );
}
