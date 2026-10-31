//! Pure artifact contracts; no generated code, mapping or host CPU discovery.
use super::*;
use crate::contracts::*;
use crate::quiescent::{TacticPolicy, plan_install_with_emission};

pub(crate) const BASE: u64 = 0x401000;
pub(crate) const GENERATED: u64 = 0x1000000;
pub(crate) const HOOK: u64 = BASE + 0x2000;
const DOMAIN: u64 = 29;
const ID: CodeIdentity = CodeIdentity {
    source: SourceIdentity([0x52; 32]),
    mapping: 7,
    generation: 5,
};

pub(crate) fn fixture(
    state: SavedExtendedStateLayout,
    semantics: HookSemantics,
) -> (ArtifactPlan, ArtifactEmission) {
    let code = [0x0f, 0x1f, 0x44, 0, 0, 0xc3];
    let function = AddressRange::new(BASE, code.len()).unwrap();
    let entries = LegalEntrySet {
        identity: ID,
        scope: function,
        provenance: EntryProvenance::Declared("pure artifact NOP5 frame model".into()),
        completeness: EntryCompleteness::Complete,
        entries: [BASE, BASE + 5]
            .map(|address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .to_vec(),
        resumes: ResumeObligation::NoneExist,
    };
    let allocation = AllocationPolicy {
        ranges: vec![AddressRange::new(GENERATED, 8192).unwrap()],
        preferred_address: Some(GENERATED),
        max_candidates: 256,
        max_mappings: 1,
        max_mapped_bytes: 8192,
    };
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(state, DOMAIN).unwrap(),
        SymbolicHook {
            identity: 41,
            address: Some(HOOK),
        },
        vec![AddressRange::new(BASE, 16384).unwrap()],
    );
    let plan = plan_install_with_emission(&ArtifactRequest {
        site: PlanningSite {
            identity: ID,
            code: &code,
            base_address: BASE,
            function,
            block: function,
            logical_pc: BASE,
            entries: &entries,
            semantics,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        },
        emission: &emission,
    })
    .unwrap();
    (plan, emission)
}

fn basic() -> (ArtifactPlan, ArtifactEmission) {
    fixture(
        SavedExtendedStateLayout::describe_target_fxsave64(),
        HookSemantics::Observe,
    )
}

#[test]
fn opaque_artifact_trace_preserves_exact_image_and_every_requirement() {
    let (plan, input) = basic();
    let traced = plan
        .frame_trace_nop5(&input, FrameTraceLimits::default())
        .unwrap();
    assert_eq!(traced.identity(), ID);
    assert_eq!(traced.source_step(), &plan.source_steps()[0]);
    assert_eq!(traced.symbolic_hook(), input.hook());
    assert_eq!(traced.bias_domain(), DOMAIN);
    assert_eq!(traced.exact_image(), &plan.images[0]);
    assert!(traced.trace().matches_image(&plan.images[0]));
    assert_eq!(
        traced.image().metadata(),
        plan.images().next().unwrap().metadata()
    );
    assert!(!plan.qualification_complete());
    assert!(!traced.image().metadata().qualification_complete());
    assert!(
        traced
            .image()
            .metadata()
            .requirements()
            .contains(&ArtifactRequirement::GeneratedUnwindInformation,)
    );
    assert!(
        traced
            .trace()
            .requirements()
            .contains(&crate::frame_trace::FrameTraceRequirement::FramePreservingHook,)
    );
    let [call] = traced.trace().calls() else {
        panic!("exactly one observer")
    };
    assert_eq!(call.original_pc(), BASE);
    assert_eq!(call.return_pc() - call.call_pc(), 5);
    let retained_step = plan.source_steps()[0].clone();
    drop(plan);
    assert_eq!(traced.source_step(), &retained_step);
}

#[test]
fn artifact_trace_rejects_changed_domain_hook_and_target_profile() {
    let (plan, input) = basic();
    let mut mutants = Vec::new();
    let mut changed = input.clone();
    changed.profile.bias_domain += 1;
    mutants.push(changed);
    let mut changed = input.clone();
    changed.hook.identity += 1;
    mutants.push(changed);
    let mut changed = input.clone();
    changed.hook.address = Some(HOOK + 1);
    mutants.push(changed);
    let mut changed = input.clone();
    changed.profile.state =
        SavedExtendedStateLayout::describe_target_xsave64(7, &[(4, 576, 256)]).unwrap();
    mutants.push(changed);
    for changed in mutants {
        assert!(matches!(
            plan.frame_trace_nop5(&changed, FrameTraceLimits::default()),
            Err(ArtifactFrameTraceRefusal::ImageMismatch)
        ));
    }
    let mut unresolved = input;
    unresolved.hook.address = None;
    assert!(matches!(
        plan.frame_trace_nop5(&unresolved, FrameTraceLimits::default()),
        Err(ArtifactFrameTraceRefusal::Reemission(
            TrampolineError::Artifact { .. }
        ))
    ));
}

#[test]
fn artifact_trace_rejects_each_changed_source_byte_and_missing_snapshot() {
    let (plan, input) = basic();
    for byte in 0..5 {
        let mut altered = plan.clone();
        let mut parts = altered.steps[0].parts().clone();
        let read = parts
            .reads
            .iter_mut()
            .find(|read| read.address <= BASE && read.address + read.bytes.len() as u64 >= BASE + 5)
            .unwrap();
        read.bytes[(BASE - read.address) as usize + byte] ^= 1;
        altered.steps[0] = PatchPlan::checked(parts).unwrap();
        assert!(matches!(
            altered.frame_trace_nop5(&input, FrameTraceLimits::default()),
            Err(ArtifactFrameTraceRefusal::SourceSnapshot)
        ));
    }
    let mut altered = plan.clone();
    let mut parts = altered.steps[0].parts().clone();
    // Remove writes too: PatchPlan::checked requires every retained write to
    // have a read expectation. This remains a structurally checked mock plan.
    parts.writes.clear();
    parts.reads.clear();
    altered.steps[0] = PatchPlan::checked(parts).unwrap();
    assert!(matches!(
        altered.frame_trace_nop5(&input, FrameTraceLimits::default()),
        Err(ArtifactFrameTraceRefusal::SourceSnapshot)
    ));
}

#[test]
fn artifact_trace_refuses_router_bundle_and_replacement_without_losing_image() {
    let (plan, input) = basic();
    let mut router = plan.clone();
    router.images[0].require_artifact_router();
    assert!(matches!(
        router.frame_trace_nop5(&input, FrameTraceLimits::default()),
        Err(ArtifactFrameTraceRefusal::UnsupportedPlan)
    ));
    let mut bundle = plan.clone();
    bundle.steps.push(bundle.steps[0].clone());
    bundle.images.push(bundle.images[0].clone());
    assert!(matches!(
        bundle.frame_trace_nop5(&input, FrameTraceLimits::default()),
        Err(ArtifactFrameTraceRefusal::UnsupportedPlan)
    ));
    let (replacement, input) = fixture(
        SavedExtendedStateLayout::describe_target_fxsave64(),
        HookSemantics::ReplaceFirst,
    );
    let before = replacement.images[0].clone();
    assert!(matches!(
        replacement.frame_trace_nop5(&input, FrameTraceLimits::default()),
        Err(ArtifactFrameTraceRefusal::ImageMismatch)
    ));
    assert_eq!(replacement.images[0], before);
}

#[test]
fn artifact_frame_limits_are_independent_and_exact() {
    let (plan, input) = basic();
    let before = plan.images[0].clone();
    let trace = plan
        .frame_trace_nop5(&input, FrameTraceLimits::default())
        .unwrap();
    let exact = FrameTraceLimits {
        instructions: trace.trace().instructions().len(),
        calls: 1,
    };
    assert!(plan.frame_trace_nop5(&input, exact).is_ok());
    for limits in [
        FrameTraceLimits {
            instructions: exact.instructions - 1,
            calls: 1,
        },
        FrameTraceLimits {
            instructions: exact.instructions,
            calls: 0,
        },
    ] {
        assert!(matches!(
            plan.frame_trace_nop5(&input, limits),
            Err(ArtifactFrameTraceRefusal::Metadata(
                FrameTraceRefusal::ResourceLimit
            ))
        ));
        assert_eq!(plan.images[0], before);
    }
}
