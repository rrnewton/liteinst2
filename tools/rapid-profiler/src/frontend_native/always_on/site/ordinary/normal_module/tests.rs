//! Pure real scalar admission/planning. No loaded owner, executable map, fake
//! publication or callback identity is fabricated; no subject instruction runs.
use super::*;
use crate::frontend_native::module::ordinary::admit_for_planner_test;
use liteinst2::trampoline::ObservationStackProfile;

const PAGE: u64 = 0x2800_0000;
const ENTRIES: [u64; 2] = [PAGE + 128, PAGE + 512];
struct Fixture {
    code: [Vec<u8>; 2],
    certificates: [IntegerLeafCertificate; 2],
    originals: Vec<ExpectedBytes>,
}
impl Fixture {
    fn new(code: [Vec<u8>; 2]) -> Self {
        let certificates = [
            admit_for_planner_test(&code[0], ENTRIES[0]).unwrap(),
            admit_for_planner_test(&code[1], ENTRIES[1]).unwrap(),
        ];
        let mut bytes = vec![0xa5; 4096];
        for (entry, body) in ENTRIES.into_iter().zip(&code) {
            let offset = (entry - PAGE) as usize;
            bytes[offset..offset + body.len()].copy_from_slice(body);
        }
        Self {
            code,
            certificates,
            originals: vec![ExpectedBytes {
                address: PAGE,
                bytes,
            }],
        }
    }
    fn inputs(&self) -> [ModuleFunctionSource<'_>; 2] {
        [0, 1].map(|i| ModuleFunctionSource {
            code: &self.code[i],
            certificate: &self.certificates[i],
            source_range: (PAGE, PAGE + 4096),
        })
    }
    fn identity(&self) -> CodeIdentity {
        CodeIdentity {
            source: SourceIdentity([181; 32]),
            mapping: ENTRIES[0],
            generation: 1,
        }
    }
}
fn long_leaf() -> Vec<u8> {
    let mut code = vec![0x48, 0x85, 0xf6, 0x74, 79];
    for _ in 0..13 {
        code.extend_from_slice(&[0x48, 0x05, 1, 0, 0, 0]);
    }
    code.extend_from_slice(&[0xc3, 0xb8, 0, 0, 0, 0, 0xc3]);
    code
}
fn short_leaf() -> Vec<u8> {
    vec![0x48, 0x89, 0xf0, 0x48, 0x83, 0xc0, 1, 0xc3]
}

#[test]
fn module_composes_shared_page_two_scopes_all_roles_and_excluded_allocations() {
    let f = Fixture::new([long_leaf(), short_leaf()]);
    let (bundle, site) = prepare_module(
        f.inputs(),
        &f.originals,
        f.identity(),
        [PreparationPolicy::CertifiedBlocks; 2],
    )
    .unwrap();
    assert_eq!(bundle.images().len(), 4);
    assert_eq!(bundle.plan().identity(), f.identity());
    assert_eq!(bundle.plan().originals(), f.originals);
    assert_eq!(site.functions()[0].range(), (ENTRIES[0], ENTRIES[0] + 90));
    assert_eq!(site.functions()[1].range(), (ENTRIES[1], ENTRIES[1] + 8));
    let expected = [
        (0, NormalModuleRoleKind::Entry, ENTRIES[0]),
        (0, NormalModuleRoleKind::Return, ENTRIES[0] + 83),
        (0, NormalModuleRoleKind::Return, ENTRIES[0] + 89),
        (1, NormalModuleRoleKind::Entry, ENTRIES[1]),
        (1, NormalModuleRoleKind::Return, ENTRIES[1] + 7),
    ];
    assert_eq!(
        site.roles()
            .map(|r| (r.function_index, r.kind, r.pc))
            .collect::<Vec<_>>(),
        expected
    );
    let mut reserved = vec![AddressRange::new(PAGE, 4096).unwrap()];
    let mut independent = f.originals[0].bytes.clone();
    for (step, image) in bundle.plan().steps().iter().zip(bundle.images()) {
        let p = step.parts();
        let index = usize::from(p.entries.scope.start() == ENTRIES[1]);
        assert_eq!(p.identity, f.identity());
        assert_eq!(
            p.entries.scope,
            AddressRange::new(ENTRIES[index], f.code[index].len()).unwrap()
        );
        assert_eq!(p.entries.resumes, ResumeObligation::NoneExist);
        assert_eq!(
            image.layout().observation_stack_profile,
            ObservationStackProfile::Legacy128
        );
        assert_eq!(p.allocations.len(), 1);
        for allocation in &p.allocations {
            assert!(allocation.range.len() <= 8192);
            assert!(
                reserved
                    .iter()
                    .all(|prior| !prior.overlaps(allocation.range))
            );
            reserved.push(allocation.range);
        }
        for edit in &p.writes {
            let at = (edit.address - PAGE) as usize;
            independent[at..at + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
    }
    assert_eq!(
        bundle.plan().final_bytes(),
        [ExpectedBytes {
            address: PAGE,
            bytes: independent
        }]
    );
    // The old whole-function ceiling still refuses the same complete 90-byte body.
    assert!(matches!(
        whole::groups(
            AddressRange::new(ENTRIES[0], 90).unwrap(),
            f.certificates[0].returns(),
            f.certificates[0].blocks(),
            f.certificates[0].edges()
        ),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));
}

#[test]
fn module_refuses_wrong_identity_source_or_unpatchable_second_function() {
    let f = Fixture::new([short_leaf(), short_leaf()]);
    for identity in [
        CodeIdentity {
            mapping: ENTRIES[1],
            ..f.identity()
        },
        CodeIdentity {
            generation: 0,
            ..f.identity()
        },
    ] {
        assert!(matches!(
            prepare_module(
                f.inputs(),
                &f.originals,
                identity,
                [PreparationPolicy::CertifiedBlocks; 2]
            ),
            Err(SiteError::Correspondence)
        ));
    }
    let mut bad = f.originals.clone();
    bad[0].bytes[512] ^= 1;
    assert!(matches!(
        prepare_module(
            f.inputs(),
            &bad,
            f.identity(),
            [PreparationPolicy::CertifiedBlocks; 2]
        ),
        Err(SiteError::Correspondence)
    ));
    let mut extra = f.originals.clone();
    extra.push(ExpectedBytes {
        address: PAGE + 4096,
        bytes: vec![0; 4096],
    });
    extra.push(ExpectedBytes {
        address: PAGE + 8192,
        bytes: vec![0; 4096],
    });
    assert!(matches!(
        prepare_module(
            f.inputs(),
            &extra,
            f.identity(),
            [PreparationPolicy::CertifiedBlocks; 2]
        ),
        Err(SiteError::Correspondence)
    ));
    let f = Fixture::new([short_leaf(), vec![0x31, 0xc0, 0xc3]]);
    assert!(matches!(
        prepare_module(
            f.inputs(),
            &f.originals,
            f.identity(),
            [PreparationPolicy::CertifiedBlocks; 2]
        ),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));
    // Explicit mixed policy admits short RET blocks without altering either
    // policy or pretending that a certified-block refusal is a success.
    let short_returns = vec![
        0x48, 0x85, 0xf6, 0x74, 4, 0x48, 0x89, 0xf0, 0xc3, 0x31, 0xc0, 0xc3,
    ];
    let mixed = Fixture::new([long_leaf(), short_returns]);
    assert!(matches!(
        prepare_module(
            mixed.inputs(),
            &mixed.originals,
            mixed.identity(),
            [PreparationPolicy::CertifiedBlocks; 2]
        ),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));
    let (planned, site) = prepare_module(
        mixed.inputs(),
        &mixed.originals,
        mixed.identity(),
        [
            PreparationPolicy::CertifiedBlocks,
            PreparationPolicy::WholeFunction,
        ],
    )
    .unwrap();
    assert_eq!(planned.images().len(), 4);
    assert_eq!(
        planned.plan().steps().last().unwrap().parts().displaced,
        AddressRange::new(ENTRIES[1], 12).unwrap()
    );
    assert_eq!(
        site.functions()[1].returns(),
        [ENTRIES[1] + 8, ENTRIES[1] + 11]
    );
    let too_long = Fixture::new([short_leaf(), long_leaf()]);
    assert!(matches!(
        prepare_module(
            too_long.inputs(),
            &too_long.originals,
            too_long.identity(),
            [
                PreparationPolicy::CertifiedBlocks,
                PreparationPolicy::WholeFunction
            ]
        ),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));
    // Complete scalar admission, not a forged certificate, rejects an entry backedge.
    assert!(admit_for_planner_test(&[0xeb, 0xfe, 0xc3], ENTRIES[1]).is_err());
}

#[test]
fn module_role_table_keeps_each_function_and_mandatory_control_distinct() {
    let f = Fixture::new([short_leaf(), short_leaf()]);
    let (_, site) = prepare_module(
        f.inputs(),
        &f.originals,
        f.identity(),
        [PreparationPolicy::CertifiedBlocks; 2],
    )
    .unwrap();
    for (index, entry) in ENTRIES.into_iter().enumerate() {
        assert_eq!(
            site.role_at(entry, true).unwrap().metadata.function_index,
            index
        );
        assert_eq!(
            site.role_at(entry + 7, false)
                .unwrap()
                .metadata
                .function_index,
            index
        );
        assert!(site.role_at(entry, false).is_none());
        assert!(site.role_at(entry + 7, true).is_none());
        assert!(site.role_at(entry + 1, true).is_none());
        assert!(site.role_at(entry + 8, false).is_none());
    }
    for (index, role) in site.roles.iter().enumerate() {
        assert!(role.control.try_set_enabled(false).is_err());
        assert!(
            site.roles[..index]
                .iter()
                .all(|prior| prior.control != role.control)
        );
    }
    let synthetic = ModuleSite::synthetic(
        f.identity(),
        ENTRIES.map(|entry| (entry, entry + 8, vec![entry + 7])),
    );
    assert_eq!(
        synthetic.roles().collect::<Vec<_>>(),
        site.roles().collect::<Vec<_>>()
    );
    for (index, entry) in ENTRIES.into_iter().enumerate() {
        let control = synthetic.control_for(index, false, entry + 7).unwrap();
        assert_eq!(
            synthetic.resolve_control(entry + 7, control, false),
            Some(index)
        );
        assert!(synthetic.control_for(1 - index, false, entry + 7).is_none());
        assert!(
            synthetic
                .resolve_control(ENTRIES[1 - index] + 7, control, false)
                .is_none()
        );
        assert!(
            synthetic
                .resolve_control(entry + 7, &site.roles[2 * index + 1].control, false)
                .is_none()
        );
        assert!(
            synthetic
                .resolve_control(entry + 7, control, true)
                .is_none()
        );
    }
    // Opaque live ControlIdentity is tested by core/native dispatch, never
    // fabricated in these pure controls. resolve also requires has_identity.
}

#[test]
fn module_reaches_derived_ten_group_cap_without_larger_leaf_windows() {
    let mut code = Vec::new();
    for value in 0..3 {
        code.extend_from_slice(&[0x48, 0x83, 0xfe, value, 0x74, 18]);
    }
    for value in [4, 1, 2, 3] {
        code.extend_from_slice(&[0xb8, value, 0, 0, 0, 0xc3]);
    }
    let f = Fixture::new([code.clone(), code]);
    let (bundle, site) = prepare_module(
        f.inputs(),
        &f.originals,
        f.identity(),
        [PreparationPolicy::CertifiedBlocks; 2],
    )
    .unwrap();
    assert_eq!(bundle.images().len(), 10);
    assert_eq!(bundle.plan().memory().mappings, 10);
    assert_eq!(site.roles().len(), 10);
    assert_eq!(site.functions()[0].returns().len(), 4);
    assert_eq!(site.functions()[1].returns().len(), 4);
    assert!(bundle.plan().memory().virtual_bytes <= 81920);
    assert!(bundle.plan().memory().backing_bytes <= 81920);
    assert!(bundle.plan().memory().virtual_span <= 1 << 32);
    assert!(
        bundle
            .plan()
            .steps()
            .iter()
            .all(|step| step.parts().displaced.len() <= 80)
    );
    let mut fifth_return = Vec::new();
    for value in 0..4 {
        fifth_return.extend_from_slice(&[0x48, 0x83, 0xfe, value, 0x74, 24]);
    }
    for value in [5, 1, 2, 3, 4] {
        fifth_return.extend_from_slice(&[0xb8, value, 0, 0, 0, 0xc3]);
    }
    assert!(admit_for_planner_test(&fifth_return, ENTRIES[0]).is_err());
    // Projection crosses actual adjacent snapshots; it never fills a hole.
    let pages = [
        ExpectedBytes {
            address: PAGE,
            bytes: vec![1; 4096],
        },
        ExpectedBytes {
            address: PAGE + 4096,
            bytes: vec![2; 4096],
        },
    ];
    assert_eq!(projection(&pages, PAGE + 4094, 4).unwrap(), [1, 1, 2, 2]);
    let mut gap = pages;
    gap[1].address += 4096;
    assert!(matches!(
        projection(&gap, PAGE + 4094, 4),
        Err(SiteError::Core(Refusal::DependencyNotHeld))
    ));
    let before = gap.clone();
    assert!(replace_projection(&mut gap, PAGE + 4094, &[3; 4]).is_err());
    assert_eq!(gap, before);
}
