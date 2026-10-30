//! Accepted-plan controls. All prospective; no runtime/corpus result is implied.
use super::*;
#[path = "fixture.rs"]
mod fixture;
use fixture::Family;

fn catalog(program: u64, family: Family) -> Catalog {
    let (input, plans) = fixture::accepted(program, family);
    let result = catalog_from_plans(input, &plans).unwrap();
    assert_eq!(
        result.input().steps.len(),
        plans
            .iter()
            .map(|(_, p)| p.source_steps().len())
            .sum::<usize>()
    );
    for (id, p) in &plans {
        let actual = result
            .input()
            .steps
            .iter()
            .filter(|s| s.selected_id == *id)
            .collect::<Vec<_>>();
        assert_eq!(actual.len(), p.source_steps().len());
        for (got, want) in actual.iter().zip(p.source_steps()) {
            assert_eq!(
                got.obligations,
                want.parts()
                    .obligations
                    .iter()
                    .map(|o| match o {
                        EntryObligation::Preserved(original) => Obligation {
                            original: *original,
                            generated: None
                        },
                        EntryObligation::Routed(r) => Obligation {
                            original: r.original,
                            generated: Some(r.generated)
                        },
                        EntryObligation::Unresolved { .. } =>
                            panic!("opaque accepted plan left unresolved entry"),
                    })
                    .collect::<Vec<_>>()
            );
        }
    }
    let bytes = result.encode().unwrap();
    assert_eq!(&bytes[8..16], &2u64.to_le_bytes());
    assert_eq!(Catalog::decode(&bytes).unwrap(), result);
    result
}
#[test]
fn actual_plan_families_preserve_both_complete_denominators_and_authored_stack_layout() {
    for family in [
        Family::B1,
        Family::B2,
        Family::T1,
        Family::T2,
        Family::Neighbor,
        Family::ShortNeighbor,
    ] {
        for program in [1, 2] {
            let c = catalog(program, family);
            let x = c.input();
            let (heads, selected) = if program == 1 { (80, 16) } else { (107, 26) };
            let extra = usize::from(matches!(
                family,
                Family::T2 | Family::Neighbor | Family::ShortNeighbor
            ));
            let compatibility = Compatibility {
                planner: 3,
                encoder: 1,
                hook_abi: 1,
                arena: 1,
                target: ContentId::of(&x.target),
                binding: ContentId::of(&x.selection),
            };
            let metadata = liteinst_artifact::Metadata::decode(
                &x.metadata,
                &compatibility,
                liteinst_artifact::Limits::default(),
            )
            .unwrap();
            let tactic = match family {
                Family::B1 => liteinst_artifact::Tactic::Relocation,
                Family::B2 => liteinst_artifact::Tactic::GeneralizedPun,
                Family::T1 => liteinst_artifact::Tactic::PrefixedPun,
                Family::T2 => liteinst_artifact::Tactic::SuccessorEviction,
                Family::Neighbor | Family::ShortNeighbor => {
                    liteinst_artifact::Tactic::NeighborEviction
                }
                Family::ShortOverlay => unreachable!(),
            };
            assert_eq!(
                metadata.sites()[0].outcome,
                liteinst_artifact::Outcome::Rewritten(tactic)
            );
            assert_eq!(
                (x.heads.len(), x.steps.len(), x.images.len()),
                (heads, selected + extra, selected + extra)
            );
            let old = c::parse(&x.original).unwrap();
            let main = c::parse(&x.main).unwrap();
            let stack = x.policy.app_stack;
            assert_eq!(
                (stack.start, stack.len),
                (fixture::STACK_START, fixture::STACK_BYTES as u64)
            );
            let rw = old
                .segments(liteinst_artifact::elf64::SegmentType::Load)
                .find(|p| p.flags.0 == 6)
                .unwrap();
            assert_eq!(
                (rw.vaddr.0, rw.offset.0, rw.file_size, rw.memory_size),
                (
                    fixture::RW_START,
                    16384,
                    fixture::RW_BYTES as u64,
                    fixture::RW_BYTES as u64
                )
            );
            let a = c::file_range(&old, stack.start, stack.len, 6).unwrap();
            let b = c::file_range(&main, stack.start, stack.len, 6).unwrap();
            assert_eq!(a, b);
            assert_eq!(x.original[a.clone()], vec![0x5a; 65536]);
            assert_eq!(x.main[b], x.original[a]);
            let selected_step = x
                .steps
                .iter()
                .find(|s| s.selected_id == 1 && s.logical == 0x401100)
                .unwrap();
            match family {
                Family::B2 | Family::T1 | Family::T2 => {
                    let p = match selected_step.kind {
                        c::Kind::GeneralizedPun(p) if family != Family::T1 => p,
                        c::Kind::PrefixedPun(p) if family == Family::T1 => p,
                        _ => panic!("forced tactic changed"),
                    };
                    assert!(p.consumed.len > selected_step.displaced.len);
                    assert_eq!(selected_step.obligations.len(), 2);
                    assert!(
                        selected_step
                            .obligations
                            .iter()
                            .all(|o| o.generated.is_none())
                    );
                    assert_eq!(
                        selected_step.obligations[1].original,
                        selected_step.displaced.end().unwrap()
                    );
                    if family == Family::T2 {
                        assert_eq!(x.steps[0].physical, 0x401102);
                        assert_eq!(x.steps[1].physical, 0x401100);
                        let prior = x.steps[1]
                            .reads
                            .iter()
                            .find(|r| r.address == 0x401100)
                            .unwrap();
                        assert_eq!(&prior.bytes[2..7], &[0xe9, 0x10, 0, 0, 6]);
                        assert_eq!(x.original[0x1102], 0xb8);
                        assert!(!x.images[0].requirements.contains(&(5, 1)));
                        assert!(x.images[1].requirements.contains(&(5, 1)));
                    }
                }
                Family::Neighbor | Family::ShortNeighbor => {
                    let n = selected_step.neighbor.unwrap();
                    assert_eq!(
                        (n.selected, n.victim, n.relay, n.rel8),
                        (0x401100, 0x401110, 0x401115, 19)
                    );
                    assert_eq!(
                        n.victim_len,
                        if family == Family::Neighbor { 10 } else { 9 }
                    );
                    assert_eq!(x.steps[0].neighbor, x.steps[1].neighbor);
                    assert_eq!(x.steps[0].physical, n.victim);
                    assert_eq!(x.steps[1].physical, n.selected);
                    assert!(
                        !x.images
                            .iter()
                            .find(|i| i.body.address == n.victim_target)
                            .unwrap()
                            .requirements
                            .contains(&(5, 1))
                    );
                    assert!(
                        x.images
                            .iter()
                            .find(|i| i.body.address == n.selected_target)
                            .unwrap()
                            .requirements
                            .contains(&(5, 1))
                    );
                }
                Family::ShortOverlay => unreachable!("separate exact overlap control"),
                Family::B1 => {
                    assert_eq!(selected_step.kind, c::Kind::Relocation);
                    assert!(selected_step.neighbor.is_none());
                }
            }
            assert!(c.routes().is_empty());
        }
    }
}
// Mutations operate on decoded typed input and rerun every catalog join. There
// is no stale outer checksum to cause an incidental Identity refusal. Original,
// selection and metadata are unchanged unless explicitly rebuilt below; source
// write mutants also update the exact final main bytes, so replay alone agrees.
fn route_refusal(x: Input) {
    assert_eq!(Catalog::new(x), Err(c::Error::Route));
}
fn selected_pun(x: &mut Input) -> &mut Step {
    x.steps
        .iter_mut()
        .find(|s| matches!(s.kind, c::Kind::GeneralizedPun(_) | c::Kind::PrefixedPun(_)))
        .unwrap()
}
fn alter_pun(s: &mut Step, f: impl FnOnce(&mut c::Pun)) {
    match &mut s.kind {
        c::Kind::GeneralizedPun(p) | c::Kind::PrefixedPun(p) => f(p),
        _ => panic!("pun required"),
    }
}
#[test]
fn accepted_pun_consumed_obligation_and_current_view_mutants_refuse() {
    for family in [Family::B2, Family::T1, Family::T2] {
        let base = catalog(1, family).input().clone();
        let mut x = base.clone();
        selected_pun(&mut x).obligations.pop();
        route_refusal(x);
        let mut x = base.clone();
        let o = selected_pun(&mut x).obligations[1];
        selected_pun(&mut x).obligations.push(o);
        route_refusal(x);
        let mut x = base.clone();
        selected_pun(&mut x).obligations[1].original = 0x401140;
        route_refusal(x);
        let mut x = base.clone();
        alter_pun(selected_pun(&mut x), |p| p.consumed.len -= 1);
        route_refusal(x);
        let mut x = base.clone();
        alter_pun(selected_pun(&mut x), |p| p.target_window.start += 1);
        route_refusal(x);
        let mut x = base.clone();
        alter_pun(selected_pun(&mut x), |p| p.store.start += 1);
        route_refusal(x);
        let mut x = base.clone();
        let stop = selected_pun(&mut x).displaced.end().unwrap();
        x.main[(stop - 0x400000) as usize] ^= 1;
        route_refusal(x);
        let mut x = base.clone();
        let s = selected_pun(&mut x);
        let at = s.physical;
        s.writes[0].bytes[0] ^= 1;
        s.writes[1].bytes[0] ^= 1;
        x.main[(at - 0x400000) as usize] ^= 1;
        route_refusal(x);
        if family == Family::T2 {
            let mut x = base.clone();
            let s = selected_pun(&mut x);
            s.reads[0].bytes[2] = 0xb8;
            assert_eq!(Catalog::new(x), Err(c::Error::Source));
        }
    }
}
fn edit_main_and_write(x: &mut Input, pc: u64, offset: usize, value: u8) {
    let s = x.steps.iter_mut().find(|s| s.physical == pc).unwrap();
    s.writes[0].bytes[offset] = value;
    x.main[(pc - 0x400000) as usize + offset] = value;
}
fn change_neighbors(x: &mut Input, f: impl Fn(&mut c::Neighbor)) {
    for s in &mut x.steps {
        if let Some(n) = &mut s.neighbor {
            f(n);
        }
    }
}
#[test]
fn accepted_neighbor_chain_and_owner_mutants_refuse() {
    for family in [Family::Neighbor, Family::ShortNeighbor] {
        let base = catalog(1, family).input().clone();
        let n = base.steps[0].neighbor.unwrap();
        let mut x = base.clone();
        x.steps[1].neighbor = None;
        route_refusal(x);
        let mut x = base.clone();
        x.steps[0].neighbor = None;
        x.steps[1].neighbor = None;
        route_refusal(x);
        let mut x = base.clone();
        change_neighbors(&mut x, |g| g.relay += 1);
        route_refusal(x);
        let mut x = base.clone();
        change_neighbors(&mut x, |g| g.selected_target += 1);
        route_refusal(x);
        let mut x = base.clone();
        change_neighbors(&mut x, |g| g.victim_target += 1);
        route_refusal(x);
        let mut x = base.clone();
        x.steps[0].selected_id = 2;
        route_refusal(x);
        let mut x = base.clone();
        change_neighbors(&mut x, |g| g.rel8 += 1);
        edit_main_and_write(&mut x, n.selected, 1, (n.rel8 + 1) as u8);
        route_refusal(x);
        let mut x = base.clone();
        edit_main_and_write(&mut x, n.victim, 5, 0x90);
        route_refusal(x);
        let mut x = base.clone();
        let b = x.steps[0].writes[0].bytes[6] ^ 1;
        edit_main_and_write(&mut x, n.victim, 6, b);
        route_refusal(x);
        let mut x = base.clone();
        let b = x.steps[0].writes[0].bytes[1] ^ 1;
        edit_main_and_write(&mut x, n.victim, 1, b);
        route_refusal(x);
        let mut x = base.clone();
        let image = x
            .images
            .iter_mut()
            .find(|i| i.body.address == n.victim_target)
            .unwrap();
        image.requirements.push((5, 1));
        assert_eq!(Catalog::new(x), Err(c::Error::Image));
        let mut x = base.clone();
        x.steps[0].obligations.push(Obligation {
            original: n.relay,
            generated: None,
        });
        route_refusal(x);
    }
}
fn rebind_original(x: &mut Input) {
    let compatibility = Compatibility {
        planner: 3,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&x.target),
        binding: ContentId::of(&x.selection),
    };
    let m = liteinst_artifact::Metadata::decode(
        &x.metadata,
        &compatibility,
        liteinst_artifact::Limits::default(),
    )
    .unwrap();
    x.metadata = liteinst_artifact::Metadata::new(
        &x.original,
        ContentId::of(&x.selection),
        compatibility,
        m.sites().to_vec(),
    )
    .unwrap()
    .encode(liteinst_artifact::Limits::default())
    .unwrap();
}
#[test]
fn file_backed_stack_preserves_full_original_owner_bytes_and_bounds() {
    let base = catalog(1, Family::B2).input().clone();
    let at = (fixture::STACK_START - 0x400000) as usize;
    for offset in [0, 1, 32768, 65535] {
        let mut x = base.clone();
        x.main[at + offset] ^= 1;
        assert_eq!(Catalog::new(x), Err(c::Error::Target));
    }
    let mut x = base.clone();
    x.original[at] ^= 1;
    rebind_original(&mut x);
    assert_eq!(Catalog::new(x), Err(c::Error::Target));
    let mut x = base.clone();
    x.original[at] ^= 1;
    x.main[at] ^= 1;
    rebind_original(&mut x);
    assert_eq!(Catalog::new(x), Err(c::Error::Target));
    let mut x = base.clone();
    x.policy.app_stack.start = fixture::RW_START;
    assert_eq!(Catalog::new(x), Err(c::Error::Target));
    let mut x = base.clone();
    x.policy.app_stack.len = 65535;
    assert_eq!(Catalog::new(x), Err(c::Error::Target));
    let mut x = base.clone();
    x.policy.app_stack.start += 1;
    assert_eq!(Catalog::new(x), Err(c::Error::Target));
    let mut x = base.clone();
    x.policy.app_stack.start = fixture::RW_START + fixture::RW_BYTES as u64 - 65520;
    assert_eq!(Catalog::new(x), Err(c::Error::Target));
}
#[test]
fn compiler_does_not_accept_caller_steps_images_omitted_or_aliased_plans() {
    let (input, plans) = fixture::accepted(1, Family::T2);
    let c = catalog_from_plans(input.clone(), &plans).unwrap();
    let mut x = input.clone();
    x.steps = c.input().steps.clone();
    assert_eq!(catalog_from_plans(x, &plans), Err(c::Error::Shape));
    let mut x = input.clone();
    x.images = c.input().images.clone();
    assert_eq!(catalog_from_plans(x, &plans), Err(c::Error::Shape));
    assert_eq!(
        catalog_from_plans(input.clone(), &plans[..plans.len() - 1]),
        Err(c::Error::Startup)
    );
    let mut duplicate = plans.clone();
    duplicate[1].0 = duplicate[0].0;
    assert_eq!(
        catalog_from_plans(input, &duplicate),
        Err(c::Error::Selection)
    );
}
use liteinst_artifact::Compatibility;

#[test]
fn short_neighbor_accepts_selected_eb_in_current_victim_fetch_suffix() {
    for program in [1, 2] {
        let c = catalog(program, Family::ShortOverlay);
        let x = c.input();
        let n = x.steps[0].neighbor.unwrap();
        assert_eq!(
            (
                n.selected,
                n.victim,
                n.victim_len,
                n.relay,
                n.rel8,
                n.selected_target
            ),
            (0x401106, 0x401100, 6, 0x401105, -3, 0x510ef5)
        );
        assert_eq!(
            (x.steps[0].physical, x.steps[1].physical),
            (n.selected, n.victim)
        );
        assert_eq!(&x.original[0x1106..0x110a], &[0xff, 0xc0, 0x10, 0]);
        let prior = &x.steps[1].reads[0];
        assert_eq!(prior.address, n.victim);
        assert_eq!(&prior.bytes[6..10], &[0xeb, 0xfd, 0x10, 0]);
        assert_eq!(&x.steps[1].writes[0].bytes[6..10], &[0xeb, 0xfd, 0x10, 0]);
        assert_eq!(&x.main[0x1106..0x110a], &[0xeb, 0xfd, 0x10, 0]);
        assert!(
            x.images
                .iter()
                .find(|i| i.body.address == n.selected_target)
                .unwrap()
                .requirements
                .contains(&(5, 1))
        );
        assert!(
            !x.images
                .iter()
                .find(|i| i.body.address == n.victim_target)
                .unwrap()
                .requirements
                .contains(&(5, 1))
        );
        let mut bad = x.clone();
        bad.steps[1].reads[0].bytes[6] = 0xff;
        assert_eq!(Catalog::new(bad), Err(c::Error::Source));
        let mut bad = x.clone();
        edit_main_and_write(&mut bad, n.victim, 8, 0x11);
        route_refusal(bad);
        let mut bad = x.clone();
        change_neighbors(&mut bad, |g| g.relay += 1);
        route_refusal(bad);
    }
}
