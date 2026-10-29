//! Actual pure decoder/planner controls. No loaded owner, opaque callback token,
//! executable mapping, publication receipt or native state authority is fabricated.
use super::*;
use crate::frontend_native::module::ordinary::admit_pair_for_planner_test;
const PAGE: u64 = 0x2800_0000;
fn parent_bytes(pe: u64, ce: u64) -> Vec<u8> {
    let mut b = vec![
        0x48, 0x83, 0xec, 24, 0x48, 0x89, 0x74, 0x24, 8, 0xe8, 0, 0, 0, 0, 0x48, 0x8b, 0x54, 0x24,
        8, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0x48, 0x83, 0xc4, 24, 0xc3,
    ];
    let delta = i32::try_from(i128::from(ce) - i128::from(pe + 14)).unwrap();
    b[10..14].copy_from_slice(&delta.to_le_bytes());
    b
}
fn child_bytes() -> Vec<u8> {
    vec![0x48, 0x89, 0xf0, 0x48, 0x83, 0xc0, 1, 0xc3]
}
fn branching_child() -> Vec<u8> {
    let mut b = vec![0x48, 0x85, 0xf6, 0x74, 79];
    for _ in 0..13 {
        b.extend_from_slice(&[0x48, 0x05, 1, 0, 0, 0]);
    }
    b.extend_from_slice(&[0xc3, 0xb8, 0, 0, 0, 0, 0xc3]);
    b
}
struct Fixture {
    pcode: Vec<u8>,
    ccode: Vec<u8>,
    parent: NormalCallPairParentCertificate,
    child: IntegerLeafCertificate,
    pages: Vec<ExpectedBytes>,
    identity: CodeIdentity,
}
impl Fixture {
    fn new(pe: u64, ce: u64, ccode: Vec<u8>) -> Self {
        let pcode = parent_bytes(pe, ce);
        Self::with_parent(pe, ce, pcode, ccode)
    }
    fn with_parent(pe: u64, ce: u64, pcode: Vec<u8>, ccode: Vec<u8>) -> Self {
        let (parent, child) = admit_pair_for_planner_test(&pcode, pe, &ccode, ce).unwrap();
        let mut pages = Vec::<ExpectedBytes>::new();
        for (entry, bytes) in [(pe, pcode.as_slice()), (ce, ccode.as_slice())] {
            for (offset, &byte) in bytes.iter().enumerate() {
                let at = entry + offset as u64;
                let page = at & !4095;
                if pages.iter().all(|p| p.address != page) {
                    pages.push(ExpectedBytes {
                        address: page,
                        bytes: vec![0xa5; 4096],
                    });
                }
                pages.iter_mut().find(|p| p.address == page).unwrap().bytes[(at - page) as usize] =
                    byte;
            }
        }
        pages.sort_by_key(|p| p.address);
        Self {
            pcode,
            ccode,
            parent,
            child,
            pages,
            identity: CodeIdentity {
                source: SourceIdentity([193; 32]),
                mapping: pe,
                generation: 1,
            },
        }
    }
    fn plan(&self) -> Result<(PlannedBundle, Arc<CallPairSite>), SiteError> {
        prepare(
            &self.pcode,
            &self.parent,
            &self.ccode,
            &self.child,
            &self.pages,
            self.identity,
        )
    }
}
fn first_member(f: &Fixture) -> liteinst2::quiescent::PlannedInstall {
    let scope = AddressRange::new(f.parent.entry(), f.pcode.len()).unwrap();
    let block = AddressRange::new(f.parent.entry(), 9).unwrap();
    let entries = LegalEntrySet {
        identity: f.identity,
        scope,
        provenance: EntryProvenance::Declared("pure admitted normal CALL-pair fixture".into()),
        completeness: EntryCompleteness::Complete,
        entries: f
            .parent
            .entries()
            .iter()
            .map(|&address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::Enumerated(vec![f.parent.call().continuation()]),
    };
    let (control, writer) = ProbeControl::new_managed_bound(unavailable, true);
    drop(writer);
    let actions = [ControlledAction {
        logical_pc: f.parent.entry(),
        control,
    }];
    let mut allocation = base_allocation(f.parent.entry()).unwrap();
    for page in &f.pages {
        exclude(
            &mut allocation.ranges,
            AddressRange::new(page.address, page.bytes.len()).unwrap(),
        )
        .unwrap();
    }
    let predecessor = Composition::new(f.identity, f.pages.clone()).unwrap();
    plan_coalesced_detailed_after_with_stack_profile(
        &InstallRequest {
            identity: f.identity,
            code: &f.pcode,
            base_address: f.parent.entry(),
            function: scope,
            block,
            logical_pc: f.parent.entry(),
            entries: &entries,
            hook: impossible_ordinary_dispatch,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_displaced_bytes: 80,
                max_sites: 1,
            },
        },
        &actions,
        &predecessor,
        ObservationStackProfile::CallPair240,
    )
    .unwrap()
}
#[test]
fn call_pair_plans_all_roles_with_original_call_and_full_reads() {
    for child in [child_bytes(), branching_child()] {
        let f = Fixture::new(PAGE + 128, PAGE + 512, child);
        let (bundle, site) = f.plan().unwrap();
        let edge = f.parent.call();
        let call = AddressRange::new(edge.call_pc(), 5).unwrap();
        assert_eq!(site.functions()[0].range(), f.parent.range());
        assert_eq!(site.functions()[1].range(), f.child.range());
        assert_eq!(site.child_stack_delta(), 32);
        assert_eq!(site.call_rsp_offset(), -24);
        let actual: Vec<_> = site.roles().map(|r| (r.kind, r.pc)).collect();
        use NormalCallPairRoleKind::*;
        let expected: Vec<_> = std::iter::once((ParentEntry, f.parent.entry()))
            .chain(std::iter::once((ChildEntry, f.child.entry())))
            .chain(f.child.returns().iter().map(|&pc| (ChildRet, pc)))
            .chain([
                (ChildAck, edge.continuation()),
                (ParentRet, f.parent.returns()[0]),
            ])
            .collect();
        assert_eq!(actual, expected);
        assert!(site.role_at(f.child.returns()[0], ParentRet).is_none());
        assert!(site.role_at(f.parent.returns()[0], ChildRet).is_none());
        assert!(site.role_at(edge.continuation(), ParentEntry).is_none());
        for (i, a) in site.roles.iter().enumerate() {
            assert!(a.control.is_enabled());
            assert!(site.roles[..i].iter().all(|b| a.control != b.control));
        }
        let mut overlay = f.pages.clone();
        let mut composition = Composition::new(f.identity, f.pages.clone()).unwrap();
        for (step, image) in bundle.plan().steps().iter().zip(bundle.images()) {
            let p = step.parts();
            assert_eq!(
                image.layout().observation_stack_profile,
                ObservationStackProfile::CallPair240
            );
            assert_eq!(p.kind, PlanKind::Relocation);
            assert_eq!(p.profile, ApplicationProfile::InstallOnce);
            assert_eq!(p.reads.len(), 1);
            if p.entries.scope.start() == f.parent.entry() {
                assert_eq!(p.reads[0].address, f.parent.entry());
                assert_eq!(p.reads[0].bytes.len(), f.pcode.len());
                assert_eq!(&p.reads[0].bytes[9..14], &f.pcode[9..14]);
                assert_eq!(
                    p.entries.resumes,
                    ResumeObligation::Enumerated(vec![edge.continuation()])
                );
            } else {
                assert_eq!(p.entries.resumes, ResumeObligation::NoneExist);
            }
            composition.append(step).unwrap();
            call_excluded(call, p, composition.locks()).unwrap();
            for edit in &p.writes {
                replace_projection(&mut overlay, edit.address, &edit.bytes).unwrap();
            }
        }
        assert_eq!(bundle.plan().originals(), f.pages);
        assert_eq!(bundle.plan().final_bytes(), overlay);
        assert_eq!(
            projection(&overlay, edge.call_pc(), 5).unwrap(),
            f.pcode[9..14]
        );
        assert_eq!(
            bundle
                .images()
                .iter()
                .map(|i| i.controls().len())
                .sum::<usize>(),
            site.roles.len()
        );
    }
}
#[test]
fn call_pair_sparse_pages_and_reversed_roles_keep_canonical_union() {
    for (pe, ce) in [
        (PAGE + 128, PAGE + 0x4000 + 128),
        (PAGE + 0x4000 + 128, PAGE + 128),
    ] {
        let f = Fixture::new(pe, ce, child_bytes());
        let (bundle, site) = f.plan().unwrap();
        assert_eq!(site.functions()[0].entry(), pe);
        assert_eq!(site.functions()[1].entry(), ce);
        assert_eq!(
            bundle
                .plan()
                .originals()
                .iter()
                .map(|p| p.address)
                .collect::<Vec<_>>(),
            [PAGE, PAGE + 0x4000]
        );
        assert_eq!(
            bundle
                .plan()
                .final_bytes()
                .iter()
                .map(|p| p.bytes.len())
                .sum::<usize>(),
            8192
        );
        assert_eq!(site.edge().callee_entry(), ce);
        assert_eq!(site.identity().mapping, pe);
        for step in bundle.plan().steps() {
            for a in &step.parts().allocations {
                assert!(a.range.len() <= 8192);
                assert!(f.pages.iter().all(|p| {
                    !AddressRange::new(p.address, p.bytes.len())
                        .unwrap()
                        .overlaps(a.range)
                }));
            }
        }
    }
}
#[test]
fn call_pair_refuses_source_identity_roles_and_short_regions() {
    let f = Fixture::new(PAGE + 128, PAGE + 512, child_bytes());
    for identity in [
        CodeIdentity {
            mapping: f.child.entry(),
            ..f.identity
        },
        CodeIdentity {
            generation: 0,
            ..f.identity
        },
    ] {
        assert!(prepare(&f.pcode, &f.parent, &f.ccode, &f.child, &f.pages, identity).is_err());
    }
    for offset in [128, 512] {
        let mut bad = f.pages.clone();
        bad[0].bytes[offset] ^= 1;
        assert!(prepare(&f.pcode, &f.parent, &f.ccode, &f.child, &bad, f.identity).is_err());
    }
    for bad in [
        vec![],
        vec![ExpectedBytes {
            address: PAGE + 4096,
            bytes: vec![0; 4096],
        }],
        vec![ExpectedBytes {
            address: PAGE,
            bytes: vec![0; 4095],
        }],
        [
            f.pages.clone(),
            vec![ExpectedBytes {
                address: PAGE + 4096,
                bytes: vec![0; 4096],
            }],
        ]
        .concat(),
    ] {
        assert!(prepare(&f.pcode, &f.parent, &f.ccode, &f.child, &bad, f.identity).is_err());
    }
    // PUSH RSI is a real initialized length spill and aligns CALL, but its one-byte
    // entry region has no legal five-byte relocation window. Do not pad/fallback.
    let pe = PAGE + 128;
    let ce = PAGE + 512;
    let mut short = vec![
        0x56, 0xe8, 0, 0, 0, 0, 0x5a, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0xc3,
    ];
    short[2..6].copy_from_slice(&i32::try_from(ce - pe - 6).unwrap().to_le_bytes());
    let f = Fixture::with_parent(pe, ce, short, child_bytes());
    assert!(matches!(
        f.plan(),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));
    let f = Fixture::new(pe, ce, vec![0x31, 0xc0, 0xc3]);
    assert!(matches!(
        f.plan(),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));
}
#[test]
fn call_pair_exclusion_refuses_displacement_write_and_lock_overlap() {
    let f = Fixture::new(PAGE + 128, PAGE + 512, child_bytes());
    let member = first_member(&f);
    let call = AddressRange::new(f.parent.call().call_pc(), 5).unwrap();
    let p = member.plan().parts();
    assert!(call_excluded(call, p, &[]).is_ok());
    let mut bad = p.clone();
    bad.displaced = call;
    assert!(call_excluded(call, &bad, &[]).is_err());
    for offset in 0..5 {
        let mut bad = p.clone();
        bad.writes.push(ByteEdit {
            address: call.start() + offset,
            bytes: vec![0xcc],
        });
        assert!(call_excluded(call, &bad, &[]).is_err());
        assert!(
            call_excluded(
                call,
                p,
                &[AddressRange::new(call.start() + offset, 1).unwrap()]
            )
            .is_err()
        );
    }
    assert!(call_excluded(call, p, &[AddressRange::new(call.end(), 1).unwrap()]).is_ok());
}
#[test]
fn call_pair_budget_refuses_excess_members_without_widening_old_paths() {
    let f = Fixture::new(PAGE + 128, PAGE + 512, child_bytes());
    let member = first_member(&f);
    // compose checks member-count before overlap; the exact allocation refusal is
    // the real ten-member guard, not a fabricated owner or mirrored success model.
    assert!(matches!(
        PlannedBundle::compose(f.pages.clone(), vec![member.clone(); 11], module_budget()),
        Err(Refusal::AllocationUnavailable)
    ));
    assert!(PlannedBundle::compose(f.pages.clone(), vec![member.clone()], module_budget()).is_ok());
    for budget in [
        liteinst2::bundle::BundleBudget {
            max_mappings: 0,
            ..module_budget()
        },
        liteinst2::bundle::BundleBudget {
            max_virtual_bytes: 0,
            ..module_budget()
        },
        liteinst2::bundle::BundleBudget {
            max_backing_bytes: 0,
            ..module_budget()
        },
        liteinst2::bundle::BundleBudget {
            max_virtual_span: 0,
            ..module_budget()
        },
    ] {
        assert!(PlannedBundle::compose(f.pages.clone(), vec![member.clone()], budget).is_err());
    }
    // The existing leaf groups still reject the same short RET region.
    assert!(matches!(
        groups(PAGE, &[PAGE + 2], &[(PAGE, PAGE + 3)], &[(PAGE, PAGE + 2)]),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));
    assert_eq!(module_budget().max_steps, 10);
}

#[test]
fn call_pair240_carries_exact_profile_for_every_planned_role() {
    let f = Fixture::new(PAGE + 128, PAGE + 512, branching_child());
    let (bundle, site) = f.plan().unwrap();
    let mut observed = Vec::new();
    for image in bundle.images() {
        let profile = image.layout().observation_stack_profile;
        assert_eq!(profile, ObservationStackProfile::CallPair240);
        assert_eq!(profile.reserved_bytes(), 240);
        assert_eq!(profile.context_stack_prefix_bytes(), 416);
        for control in image.controls() {
            let role = site.roles.iter().find(|r| r.control == *control).unwrap();
            observed.push(role.metadata);
        }
    }
    let expected: Vec<_> = site.roles().collect();
    assert_eq!(observed.len(), expected.len());
    for role in expected {
        assert_eq!(observed.iter().filter(|r| **r == role).count(), 1);
    }
    assert_eq!(
        projection(bundle.plan().final_bytes(), site.edge().call_pc(), 5).unwrap(),
        f.pcode[9..14]
    );
}
