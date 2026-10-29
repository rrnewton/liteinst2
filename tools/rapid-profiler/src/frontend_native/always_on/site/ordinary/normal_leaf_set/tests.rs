//! Actual bounded scalar planner inputs; no fake loader/publication/ControlIdentity.
use super::*;
use crate::frontend_native::IntegerLeafCertificate;
use crate::frontend_native::module::ordinary::admit_for_planner_test;
const PAGE: u64 = 0x3800_0000;
fn short() -> Vec<u8> {
    vec![0x48, 0x89, 0xf0, 0x48, 0x83, 0xc0, 1, 0xc3]
}
fn long() -> Vec<u8> {
    let mut code = vec![0x48, 0x85, 0xf6, 0x74, 79];
    for _ in 0..13 {
        code.extend_from_slice(&[0x48, 0x05, 1, 0, 0, 0]);
    }
    code.extend_from_slice(&[0xc3, 0xb8, 0, 0, 0, 0, 0xc3]);
    code
}
struct Fixture {
    code: Vec<Vec<u8>>,
    certificates: Vec<IntegerLeafCertificate>,
    pages: Vec<ExpectedBytes>,
}
impl Fixture {
    fn new(code: Vec<Vec<u8>>) -> Self {
        let certificates: Vec<_> = code
            .iter()
            .enumerate()
            .map(|(i, c)| admit_for_planner_test(c, PAGE + 128 + i as u64 * 256).unwrap())
            .collect();
        let mut bytes = vec![0xa5; 4096];
        for (c, cert) in code.iter().zip(&certificates) {
            let at = (cert.entry() - PAGE) as usize;
            bytes[at..at + c.len()].copy_from_slice(c);
        }
        Self {
            code,
            certificates,
            pages: vec![ExpectedBytes {
                address: PAGE,
                bytes,
            }],
        }
    }
    fn identity(&self) -> CodeIdentity {
        CodeIdentity {
            source: SourceIdentity([184; 32]),
            mapping: PAGE + 128,
            generation: 1,
        }
    }
    fn inputs(&self) -> Vec<ModuleFunctionSource<'_>> {
        self.code
            .iter()
            .zip(&self.certificates)
            .map(|(code, certificate)| ModuleFunctionSource {
                code,
                certificate,
                source_range: (PAGE, PAGE + 4096),
            })
            .collect()
    }
    fn plan(
        &self,
        policies: &[PreparationPolicy],
    ) -> Result<(PlannedBundle, Arc<LeafSetSite>), SiteError> {
        let (plan, functions, roles) =
            prepare_functions(&self.inputs(), &self.pages, self.identity(), policies)?;
        Ok((
            plan,
            Arc::new(LeafSetSite {
                identity: self.identity(),
                functions,
                roles,
            }),
        ))
    }
}
#[test]
fn leaf_set_roles_and_policies_cover_all_members() {
    for n in 1..=4 {
        let mut code = vec![short(); n];
        if n > 1 {
            code[0] = long();
            code[n - 1] = vec![
                0x48, 0x85, 0xf6, 0x74, 4, 0x48, 0x89, 0xf0, 0xc3, 0x31, 0xc0, 0xc3,
            ];
        }
        let f = Fixture::new(code);
        let mut policies = vec![PreparationPolicy::CertifiedBlocks; n];
        if n > 1 {
            assert!(f.plan(&policies).is_err());
            policies[n - 1] = PreparationPolicy::WholeFunction;
        }
        let (plan, site) = f.plan(&policies).unwrap();
        assert_eq!(plan.plan().originals(), f.pages);
        for (index, cert) in f.certificates.iter().enumerate() {
            assert_eq!(site.functions()[index].range(), cert.range());
            assert_eq!(site.functions()[index].returns(), cert.returns());
            assert_eq!(
                site.role_at(cert.entry(), true)
                    .unwrap()
                    .metadata
                    .function_index,
                index
            );
            for &ret in cert.returns() {
                assert_eq!(
                    site.role_at(ret, false).unwrap().metadata.function_index,
                    index
                );
            }
        }
        assert_eq!(
            site.roles().len(),
            n + f
                .certificates
                .iter()
                .map(|c| c.returns().len())
                .sum::<usize>()
        );
        if n > 1 {
            policies[0] = PreparationPolicy::WholeFunction;
            assert!(f.plan(&policies).is_err());
        }
    }
}
#[test]
fn leaf_set_budget_refuses_aggregate_overflow() {
    let f = Fixture::new(vec![long(), long(), long(), short()]);
    let (plan, site) = f.plan(&[PreparationPolicy::CertifiedBlocks; 4]).unwrap();
    assert_eq!(plan.images().len(), 10);
    assert_eq!(plan.plan().memory().mappings, 10);
    assert_eq!(site.functions().len(), 4);
    assert!(plan.plan().memory().virtual_bytes <= 81920);
    assert!(plan.plan().memory().backing_bytes <= 81920);
    assert!(plan.plan().memory().virtual_span <= 1 << 32);
    assert!(
        Fixture::new(vec![long(); 4])
            .plan(&[PreparationPolicy::CertifiedBlocks; 4])
            .is_err()
    );
    assert!(f.plan(&[PreparationPolicy::CertifiedBlocks; 3]).is_err());
    let five = Fixture::new(vec![short(); 5]);
    assert!(five.plan(&[PreparationPolicy::CertifiedBlocks; 5]).is_err());
}
#[test]
fn leaf_set_identity_and_complete_union_are_required() {
    let f = Fixture::new(vec![short(); 4]);
    for identity in [
        CodeIdentity {
            mapping: PAGE + 384,
            ..f.identity()
        },
        CodeIdentity {
            generation: 0,
            ..f.identity()
        },
    ] {
        assert!(matches!(
            prepare_functions(
                &f.inputs(),
                &f.pages,
                identity,
                &[PreparationPolicy::CertifiedBlocks; 4]
            ),
            Err(SiteError::Correspondence)
        ));
    }
    for i in 0..4 {
        let mut pages = f.pages.clone();
        pages[0].bytes[128 + i * 256] ^= 1;
        assert!(matches!(
            prepare_functions(
                &f.inputs(),
                &pages,
                f.identity(),
                &[PreparationPolicy::CertifiedBlocks; 4]
            ),
            Err(SiteError::Correspondence)
        ));
    }
    let mut pages = f.pages.clone();
    pages.extend([
        ExpectedBytes {
            address: PAGE + 4096,
            bytes: vec![0; 4096],
        },
        ExpectedBytes {
            address: PAGE + 8192,
            bytes: vec![0; 4096],
        },
    ]);
    assert!(matches!(
        prepare_functions(
            &f.inputs(),
            &pages,
            f.identity(),
            &[PreparationPolicy::CertifiedBlocks; 4]
        ),
        Err(SiteError::Correspondence)
    ));
    let mut inputs = f.inputs();
    inputs.swap(2, 3);
    assert!(matches!(
        prepare_functions(
            &inputs,
            &f.pages,
            f.identity(),
            &[PreparationPolicy::CertifiedBlocks; 4]
        ),
        Err(SiteError::Correspondence)
    ));
}
#[test]
fn leaf_set_control_lookup_keeps_exact_function() {
    let f = Fixture::new(vec![short(); 4]);
    let (_, site) = f.plan(&[PreparationPolicy::CertifiedBlocks; 4]).unwrap();
    let geometry: Vec<_> = site
        .functions()
        .iter()
        .map(|f| (f.entry(), f.range().1, f.returns().to_vec()))
        .collect();
    let other = LeafSetSite::synthetic(f.identity(), &geometry);
    for (index, function) in site.functions().iter().enumerate() {
        for (entry, pc) in [(true, function.entry()), (false, function.returns()[0])] {
            let c = site.control_for(index, entry, pc).unwrap();
            assert_eq!(site.resolve_control(pc, c, entry), Some(index));
            assert!(site.resolve_control(pc, c, !entry).is_none());
            assert!(site.control_for((index + 1) % 4, entry, pc).is_none());
            assert!(other.resolve_control(pc, c, entry).is_none());
            assert!(c.try_set_enabled(false).is_err());
        }
    }
}
