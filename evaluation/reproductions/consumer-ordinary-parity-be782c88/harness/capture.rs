// Included identically under old_core and new_core aliases; public APIs only.
use crate::common::{Api, Image, Outcome, Record, Row, Scenario, Semantics, Shape};
use li::bundle::{BundleBudget, PlannedBundle};
use li::contracts::*;
use li::engine::{self, EnginePolicy, Tactic};
use li::neighbor::{self, NeighborSearch};
use li::planner::HookSemantics;
use li::quiescent::{self, AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy};
use li::trampoline::{HookCallback, TrampolineImage};
use std::fmt::Write as _;

fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}
fn allocation(target: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(target & !4095, 8192)],
        preferred_address: Some(target),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 8192,
    }
}
fn tactic(shape: Shape) -> Tactic {
    match shape {
        Shape::B1 | Shape::Upstream => Tactic::Relocation,
        Shape::B2 => Tactic::GeneralizedPun,
        Shape::T1 => Tactic::PrefixedPun,
        Shape::T2 => Tactic::SuccessorEviction,
        Shape::T3 => Tactic::NeighborEviction,
    }
}
struct Fixture {
    code: Vec<u8>,
    base: u64,
    selected_pc: u64,
    logical: u64,
    function: AddressRange,
    block: AddressRange,
    entries: LegalEntrySet,
    selected: AllocationPolicy,
    victim: AllocationPolicy,
    search: SearchPolicy,
    policy: EnginePolicy,
    semantics: HookSemantics,
    hook: HookCallback,
}
impl Fixture {
    fn new(row: Row, index: usize, callback: unsafe extern "C" fn(*mut std::ffi::c_void)) -> Self {
        let arena = crate::common::ARENA_BASE + index as u64 * crate::common::ARENA_STRIDE;
        let s = arena
            + crate::common::SELECTED_WITHIN_ARENA
            + if row.scenario == Scenario::T2Precedence {
                63
            } else {
                0
            };
        let (mut body, mut block_len) = match row.shape {
            Shape::B1 => (vec![0xb8, 42, 0, 0, 0, 0xc3], 6),
            Shape::B2 => (vec![0x0f, 0x1f, 0, 0xb8, 42, 0, 0, 0, 0xc3], 9),
            Shape::T1 => (vec![0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3], 8),
            Shape::T2 => (
                vec![
                    0x0f, 0x1f, 0, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3,
                ],
                17,
            ),
            Shape::T3 => (vec![0x75, 1, 0x90, 0xc3], 2),
            Shape::Upstream => (vec![0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x89, 0xc0, 0xc3], 10),
        };
        if matches!(row.shape, Shape::T2 | Shape::T3) {
            body.resize(64, 0x90);
            body.extend_from_slice(&[0x48, 0xb8, 42, 0, 0, 0, 0, 0, 0, 0, 0xc3]);
        }
        let mut selected_target = match row.shape {
            Shape::B1 | Shape::T3 | Shape::Upstream => s + 0x0400_0000,
            Shape::B2 => s + 5 + 0x2ab8_0000 + 0x8000,
            Shape::T1 => s + 6 + 0x2ab8,
            Shape::T2 => s + 5 + 0x56e9_0000 + 0x8000,
        };
        let mut victim_target = if row.shape == Shape::T2 {
            s + 3 + 5 + 0x0012_3456
        } else {
            s + 0x0600_0000
        };
        let mut tactics = match row.shape {
            Shape::B2 | Shape::T2 => TacticPolicy::GeneralizedPunOnly,
            Shape::T1 => TacticPolicy::PrefixPunOnly,
            _ => TacticPolicy::RelocationOnly,
        };
        match row.scenario {
            Scenario::Prefix { len, prefixes } => {
                body = match len {
                    2 => vec![0x89, 0xc0, 0x48, 0x8d, 0x4f, 8, 0xc3],
                    3 => vec![0x48, 0x8d, 7, 0x48, 0x89, 7, 0xc3],
                    4 => vec![0x48, 0x8d, 0x4f, 8, 0x48, 0x89, 0x0f, 0xc3],
                    _ => unreachable!(),
                };
                block_len = len;
                selected_target = pun_target(s, &body, len, prefixes);
            }
            Scenario::PunLength(len) => {
                body = match len {
                    1 => vec![0x90],
                    2 => vec![0x89, 0xc0],
                    4 => vec![0x48, 0x8d, 0x4f, 8],
                    _ => unreachable!(),
                };
                body.extend_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
                block_len = len;
                selected_target = pun_target(s, &body, len, 0);
            }
            Scenario::T2Prefix | Scenario::T2Precedence => {
                body = vec![
                    0x66, 0x90, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 0x82, 0x5a, 0x37, 0x19, 0xc3,
                ];
                block_len = 2;
                let mut overlay = body.clone();
                overlay[2..7].copy_from_slice(&[0xe9, 0x56, 0x34, 0x12, 0]);
                selected_target = pun_target(s, &overlay, 2, 1);
                victim_target = s + 2 + 5 + 0x0012_3456;
                tactics = TacticPolicy::PrefixPunOnly;
            }
            _ => {}
        }
        let function = range(s, body.len());
        let mut code = vec![0x90; 16];
        code.extend_from_slice(&body);
        let identity = CodeIdentity {
            source: SourceIdentity([0x59; 32]),
            mapping: index as u64 + 1,
            generation: 3,
        };
        // Both library ABIs accept one raw pointer. The real shared observer
        // treats it opaquely and must never be called by this pure planner gate.
        let hook: HookCallback = unsafe { std::mem::transmute(callback) };
        assert_eq!(hook as usize, callback as usize);
        let mut fixture = Self {
            code,
            base: s - 16,
            selected_pc: s,
            logical: s + if row.shape == Shape::Upstream { 7 } else { 0 },
            function,
            block: range(s, block_len),
            entries: LegalEntrySet {
                identity,
                scope: function,
                provenance: EntryProvenance::Declared(
                    "fixed legacy planner parity original heads".into(),
                ),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: vec![],
                resumes: ResumeObligation::NoneExist,
            },
            selected: allocation(selected_target),
            victim: allocation(victim_target),
            search: SearchPolicy {
                tactics,
                max_upstream_bytes: if row.shape == Shape::Upstream { 7 } else { 0 },
                max_displaced_bytes: 80,
                max_sites: if row.shape == Shape::Upstream { 2 } else { 1 },
            },
            policy: EnginePolicy {
                forced: Some(tactic(row.shape)),
                successor_puns: if matches!(
                    row.scenario,
                    Scenario::T2Prefix | Scenario::T2Precedence
                ) {
                    TacticPolicy::PrefixPunOnly
                } else {
                    TacticPolicy::GeneralizedPunOnly
                },
                neighbor: NeighborSearch {
                    forced_victim: Some(s + 64),
                    max_victims: 1,
                    max_pairs: 1,
                },
                bundle: BundleBudget::default(),
            },
            semantics: if row.semantics == Semantics::Observe {
                HookSemantics::Observe
            } else {
                HookSemantics::ReplaceFirst
            },
            hook,
        };
        match row.scenario {
            Scenario::Preferred => fixture.policy.forced = None,
            Scenario::Budget => match row.shape {
                Shape::B1 => fixture.search.max_sites = 0,
                Shape::B2 | Shape::T1 => fixture.selected.max_candidates = 0,
                Shape::T2 => fixture.victim.max_candidates = 0,
                Shape::T3 => fixture.policy.neighbor.max_pairs = 0,
                Shape::Upstream => unreachable!(),
            },
            Scenario::Incomplete => fixture.entries.completeness = EntryCompleteness::Incomplete,
            Scenario::Midpoint => fixture.entries.entries.push(LegalEntry {
                address: s + 1,
                requires_endbr: false,
            }),
            Scenario::Aggregate => fixture.policy.bundle.max_mappings = 0,
            Scenario::NoSubstitute => fixture.policy.forced = Some(Tactic::GeneralizedPun),
            Scenario::T2Precedence => {
                fixture.victim.max_candidates = 2;
                fixture.search.max_displaced_bytes = 8;
            }
            _ => {}
        }
        for allocation in [&fixture.selected, &fixture.victim] {
            for r in &allocation.ranges {
                assert!(arena <= r.start() && r.end() <= arena + crate::common::ARENA_STRIDE);
            }
            assert!(
                allocation
                    .ranges
                    .iter()
                    .all(|r| !r.overlaps(range(fixture.base, fixture.code.len())))
            );
        }
        assert!(
            fixture.selected.ranges.iter().all(|s| fixture
                .victim
                .ranges
                .iter()
                .all(|v| !s.overlaps(*v)))
        );
        fixture
    }
    fn request(&self) -> InstallRequest<'_> {
        InstallRequest {
            identity: self.entries.identity,
            code: &self.code,
            base_address: self.base,
            function: self.function,
            block: self.block,
            logical_pc: self.logical,
            entries: &self.entries,
            hook: self.hook,
            semantics: self.semantics,
            allocation: &self.selected,
            search: self.search,
        }
    }
    fn inputs(&self, row: Row) -> String {
        format!(
            "row={row:?}\nidentity={:?}\nbase={}\nlogical={}\nfunction={:?}\nblock={:?}\nentries={:?}\nobserver={}\nsemantics={:?}\nselected_allocation={:?}\nvictim_allocation={:?}\nsearch={:?}\nengine_policy={:?}\n",
            self.entries.identity,
            self.base,
            self.logical,
            self.function,
            self.block,
            self.entries,
            self.hook as usize,
            self.semantics,
            self.selected,
            self.victim,
            self.search,
            self.policy
        )
    }
}
fn pun_target(pc: u64, body: &[u8], len: usize, prefixes: usize) -> u64 {
    let free = len - prefixes - 1;
    let mut displacement = [0_u8; 4];
    displacement[free..].copy_from_slice(&body[len..5 + prefixes]);
    let low = u64::try_from(
        i128::from(pc + 5 + prefixes as u64) + i128::from(i32::from_le_bytes(displacement)),
    )
    .unwrap();
    low + (1_u64 << (8 * free)) / 2
}
fn image(image: &TrampolineImage) -> Image {
    assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
    assert!(image.controls().is_empty());
    Image {
        address: image.address(),
        bytes: image.bytes().to_vec(),
        metadata: format!(
            "layout={:?}\nprogram_counters={:?}\nentry_routes={:?}\ninstruction_boundaries={:?}\ncontrols={:?}\n",
            image.layout(),
            image.program_counter_mappings(),
            image.entry_routes(),
            image.instruction_boundaries(),
            image.controls()
        ),
    }
}
fn contract(plan: &PatchPlan, image: &TrampolineImage) -> String {
    // Exhaustive destructuring makes a contract addition a compile obligation.
    let PlanParts {
        identity,
        profile,
        kind,
        logical_pc,
        physical_pc,
        displaced,
        reads,
        writes,
        dependencies,
        entries,
        obligations,
        allocations,
        generated,
        requirements,
    } = plan.parts();
    assert_eq!(generated.len(), 1);
    assert_eq!(generated[0].address, image.address());
    assert_eq!(generated[0].bytes, image.bytes());
    assert_eq!(
        generated[0].program_counters,
        image.program_counter_mappings()
    );
    format!(
        "identity={identity:?}\nprofile={profile:?}\nkind={kind:?}\nlogical={logical_pc}\nphysical={physical_pc}\ndisplaced={displaced:?}\nreads={reads:?}\nwrites={writes:?}\ndependencies={dependencies:?}\nentries={entries:?}\nobligations={obligations:?}\nallocations={allocations:?}\ngenerated={generated:?}\nrequirements={requirements:?}\n"
    )
}
fn single(record: &mut Record, p: &quiescent::PlannedInstall) {
    record.result = format!(
        "accepted\nmetrics={:?}\n{}",
        p.metrics(),
        contract(p.plan(), p.image())
    );
    record.images.push(image(p.image()));
}
fn bundle(record: &mut Record, b: &PlannedBundle, diagnostics: String, logical: u64) {
    let p = b.plan();
    assert_eq!(p.steps().len(), b.images().len());
    assert_eq!(
        p.steps()
            .iter()
            .filter(|s| s.parts().logical_pc == logical)
            .count(),
        1
    );
    record.result = format!(
        "accepted\n{diagnostics}\nidentity={:?}\noriginals={:?}\nfinal_bytes={:?}\nlocks={:?}\nmemory={:?}\ngrouping={:?}\n",
        p.identity(),
        p.originals(),
        p.final_bytes(),
        p.locks(),
        p.memory(),
        b.grouping()
    );
    for (i, (step, img)) in p.steps().iter().zip(b.images()).enumerate() {
        writeln!(&mut record.result, "step={i}\n{}", contract(step, img)).unwrap();
        record.images.push(image(img));
    }
}
fn refused(record: &mut Record, reason: &Refusal, diagnostics: String) {
    let expected = match record.expected {
        Outcome::NoPatchWindow => Refusal::NoPatchWindow,
        Outcome::AllocationUnavailable => Refusal::AllocationUnavailable,
        Outcome::UnresolvedEntry => Refusal::UnresolvedEntry,
        Outcome::NotInstructionHead => Refusal::NotInstructionHead,
        Outcome::Success => panic!("required positive refused: {} {reason:?}", record.name),
    };
    assert_eq!(*reason, expected, "fixed required refusal {}", record.name);
    record.result = format!("refused={reason:?}\n{diagnostics}");
}
pub fn capture(
    row: Row,
    index: usize,
    observer: unsafe extern "C" fn(*mut std::ffi::c_void),
) -> Record {
    let f = Fixture::new(row, index, observer);
    let original = f.code.clone();
    let mut record = Record {
        name: row.name.into(),
        expected: row.expected,
        source: f.code.clone(),
        inputs: f.inputs(row),
        result: String::new(),
        images: vec![],
    };
    let request = f.request();
    if row.api == Api::Engine {
        match engine::plan(&request, &f.victim, f.policy) {
            Ok(p) => {
                assert_eq!(
                    row.expected,
                    Outcome::Success,
                    "unexpected success {}",
                    row.name
                );
                assert_eq!(p.tactic(), tactic(row.shape));
                if row.scenario == Scenario::Preferred {
                    let order = [
                        Tactic::GeneralizedPun,
                        Tactic::Relocation,
                        Tactic::PrefixedPun,
                        Tactic::SuccessorEviction,
                        Tactic::NeighborEviction,
                    ];
                    let n = order.iter().position(|x| *x == p.tactic()).unwrap() + 1;
                    assert_eq!(p.attempts().len(), n);
                    for (i, a) in p.attempts().iter().enumerate() {
                        assert_eq!(a.tactic, order[i]);
                        if i + 1 == n {
                            assert_eq!(a.refusal, None);
                        } else {
                            assert!(a.refusal.is_some());
                        }
                    }
                    if row.shape == Shape::T3 {
                        assert_eq!(
                            p.attempts()[0].refusal,
                            Some(Refusal::AllocationUnavailable)
                        );
                        assert_eq!(p.attempts()[1].refusal, Some(Refusal::NoPatchWindow));
                        assert_eq!(
                            p.attempts()[2].refusal,
                            Some(Refusal::AllocationUnavailable)
                        );
                        assert_eq!(p.attempts()[3].refusal, Some(Refusal::NoPatchWindow));
                    }
                } else {
                    assert_eq!(p.attempts().len(), 1);
                    assert_eq!(p.attempts()[0].refusal, None);
                }
                bundle(
                    &mut record,
                    p.bundle(),
                    format!(
                        "tactic={:?}\nmetrics={:?}\nordered_attempts={:?}",
                        p.tactic(),
                        p.metrics(),
                        p.attempts()
                    ),
                    f.logical,
                );
            }
            Err(e) => {
                assert_eq!(e.attempts.len(), 1);
                if row.scenario == Scenario::Aggregate
                    && matches!(row.shape, Shape::B1 | Shape::B2 | Shape::T1)
                {
                    assert!(e.attempts[0].search.accepted);
                    assert!(e.attempts[0].outer_refusal.is_some());
                }
                refused(&mut record, &e.reason, format!("failure={e:?}\n"));
            }
        }
    } else {
        match row.shape {
            Shape::T2 => {
                match li::eviction::plan_successor_detailed(&request, &f.victim, f.policy.bundle) {
                    Ok(p) => {
                        assert_eq!(row.expected, Outcome::Success);
                        let expected_victim = f.selected_pc
                            + if matches!(row.scenario, Scenario::T2Prefix) {
                                2
                            } else {
                                3
                            };
                        assert_eq!(
                            p.kind(),
                            li::eviction::EvictionKind::Successor {
                                victim: expected_victim
                            }
                        );
                        if row.scenario == Scenario::T2Prefix {
                            assert_eq!(p.metrics().attempts.len(), 1);
                            assert_eq!(p.metrics().attempts[0].prefix_count, Some(1));
                        }
                        bundle(
                            &mut record,
                            p.bundle(),
                            format!("kind={:?}\nmetrics={:?}", p.kind(), p.metrics()),
                            f.logical,
                        );
                    }
                    Err(e) => {
                        if row.scenario == Scenario::T2Precedence {
                            assert_eq!(e.attempts.len(), 2);
                            assert_eq!(e.attempts[0].prefix_count, Some(1));
                            assert_eq!(e.attempts[0].refusal, Some(Refusal::NoPatchWindow));
                            assert_eq!(e.attempts[1].prefix_count, None);
                            assert_eq!(e.attempts[1].refusal, Some(Refusal::AllocationUnavailable));
                            assert_eq!(
                                e.attempts[1].victim_target,
                                e.attempts[0].victim_target + 65536
                            );
                        }
                        refused(&mut record, &e.reason, format!("failure={e:?}\n"));
                    }
                }
            }
            Shape::T3 => match neighbor::plan_neighbor_detailed(
                &request,
                &f.victim,
                f.policy.neighbor,
                f.policy.bundle,
            ) {
                Ok(p) => {
                    assert_eq!(row.expected, Outcome::Success);
                    assert_eq!(p.geometry().victim, f.selected_pc + 64);
                    assert_eq!(p.geometry().rel8, 67);
                    bundle(
                        &mut record,
                        p.bundle(),
                        format!("geometry={:?}\nmetrics={:?}", p.geometry(), p.metrics()),
                        f.logical,
                    );
                }
                Err(e) => refused(&mut record, &e.reason, format!("failure={e:?}\n")),
            },
            _ => match quiescent::plan_install_detailed(&request) {
                Ok(p) => {
                    assert_eq!(row.expected, Outcome::Success);
                    assert_eq!(p.image().address(), f.selected.preferred_address.unwrap());
                    match row.shape {
                        Shape::B1 | Shape::Upstream => {
                            assert_eq!(p.plan().parts().kind, PlanKind::Relocation)
                        }
                        Shape::B2 => {
                            assert!(matches!(p.plan().parts().kind, PlanKind::GeneralizedPun(_)))
                        }
                        Shape::T1 => {
                            let expected = match row.scenario {
                                Scenario::Prefix { prefixes, .. } => prefixes,
                                _ => 1,
                            };
                            assert!(
                                matches!(&p.plan().parts().kind,PlanKind::PrefixedPun(pun) if usize::from(pun.prefix_count)==expected)
                            );
                        }
                        _ => unreachable!(),
                    }
                    if row.shape == Shape::Upstream {
                        assert_eq!(p.plan().parts().physical_pc, f.selected_pc);
                        assert_eq!(p.plan().parts().logical_pc, f.selected_pc + 7);
                        assert_eq!(p.metrics().upstream_bytes, 7);
                        assert_eq!(p.metrics().attempts.len(), 2);
                        assert_eq!(
                            p.metrics().attempts[0].refusal,
                            Some(Refusal::NoPatchWindow)
                        );
                    }
                    single(&mut record, &p);
                }
                Err(e) => refused(&mut record, &e.reason, format!("failure={e:?}\n")),
            },
        }
    }
    assert_eq!(
        record.images.len(),
        row.images,
        "fixed image inventory {}",
        row.name
    );
    assert_eq!(f.code, original);
    record
}
