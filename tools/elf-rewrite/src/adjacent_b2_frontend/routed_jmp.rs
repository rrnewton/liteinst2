//! New controls exercise real sealed plans. No manufactured PlanParts.
use super::*;
use crate::disassembly::adjacent_routed_jmp::{AdjacentRoutedJmpDisassemblySelection, PROFILE};
#[path = "../../examples/fixtures/adjacent_routed_jmp_publication.rs"]
mod frozen;
const BASE: u64 = 0x401000;
const L: u64 = 0x401bfe;
const U: u64 = 0x401c00;
const F: u64 = 0x401c02;
const E: u64 = 0x401c05;
const Q: u64 = 0x401e00;
const EXTRA: &str =
    "adjacent-pairs original-geometry-jcc-or-routed-jmp-v1\nadjacent-pair-budgets 2 1 2\n";
const FAMILY: &str = "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\nadjacent_pairs\toriginal-geometry-jcc-or-routed-jmp-v1\n";

struct Mixed {
    fixture: Fixture,
}
impl Mixed {
    fn new(case: &frozen::Fixture) -> Self {
        let original = case.original();
        assert_eq!(digest(&original), case.original_sha256);
        assert_eq!(digest(case.ledger), case.ledger_sha256);
        assert_eq!(digest(case.policy), case.policy_sha256);
        assert_eq!(
            text(case.ledger)
                .lines()
                .filter(|l| l.starts_with("head "))
                .count(),
            case.heads
        );
        assert_eq!(
            text(case.policy)
                .lines()
                .filter(|l| l.starts_with("search "))
                .count(),
            case.selected
        );
        Self {
            fixture: Fixture {
                original,
                ledger: text(case.ledger).into(),
                policy: text(case.policy).into(),
                base: BASE,
            },
        }
    }
    fn bind(&self) -> AdjacentRoutedJmpDisassemblySelection {
        self.bind_policy(&self.fixture.policy)
            .expect("literal v6 binding")
    }
    fn bind_policy(&self, policy: &str) -> Result<AdjacentRoutedJmpDisassemblySelection, Error> {
        disassembly::import(
            &self.fixture.original,
            self.fixture.ledger.as_bytes(),
            ContentId::of(self.fixture.ledger.as_bytes()),
        )?
        .bind_adjacent_routed_jmp(policy.as_bytes(), ContentId::of(policy.as_bytes()))
    }
    fn planned(&self) -> (Selection, SelectionDraft) {
        let bound = self.bind();
        let s = bound.base.selection;
        let elf = Elf64::parse(
            &self.fixture.original,
            ParseLimits {
                max_program_headers: 128,
            },
        )
        .unwrap();
        let dynamic = carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default()).unwrap();
        let (identity, mut draft) = self.fixture.initial(&s);
        let mut ordered: Vec<_> = (0..s.sites.len()).collect();
        ordered.sort_by_key(|&i| std::cmp::Reverse(s.sites[i].pc));
        plan_profile(
            &elf,
            &dynamic,
            &s,
            identity,
            PairPolicy {
                limits: AdjacentB2Limits {
                    upper: bound.limits.upper,
                    lower: bound.limits.lower,
                    joint: bound.limits.joint,
                },
                profile: PairProfile::RoutedJmpUnion,
            },
            &ordered,
            &mut draft,
        )
        .unwrap();
        (s, draft)
    }
    fn run(&self) -> Product {
        routed_jmp::prepare_disassembly_adjacent_routed_jmp(&self.fixture.original, &self.bind())
            .unwrap()
    }
    fn replace(&mut self, a: &str, b: &str) {
        self.fixture.replace(a, b);
    }
    fn caps(&mut self, u: usize, l: usize, j: usize) {
        self.replace(
            "adjacent-pair-budgets 2 1 2",
            &format!("adjacent-pair-budgets {u} {l} {j}"),
        );
    }
}
fn mixed_pair(draft: &SelectionDraft) -> &li2core::quiescent::RoutedJmpArtifactPlan {
    assert_eq!(draft.routed.work.len(), 1);
    assert!(draft.work.is_empty());
    assert!(draft.routed.work[0].committed);
    draft.routed.work[0]
        .result
        .as_ref()
        .expect("real mixed artifact")
}
fn complete_mixed(m: &Mixed, ids: &[u64]) -> Product {
    let p = m.run();
    assert!(
        p.candidate_complete(),
        "frozen real whole candidate is mandatory: {:?}",
        p.reports()
            .iter()
            .map(|r| (r.id, &r.refusal))
            .collect::<Vec<_>>()
    );
    assert!(!p.qualification_complete());
    assert_eq!(p.reports().iter().map(|r| r.id).collect::<Vec<_>>(), ids);
    assert!(
        p.reports()
            .iter()
            .all(|r| r.candidate_emitted && r.refusal.is_none())
    );
    for file in [
        "candidate.elf",
        "source.li2sparse",
        "metadata.li2meta",
        "plan-ledger.tsv",
        "ledger.tsv",
        "report.tsv",
        "bundle-index.tsv",
        "adjacent-routed-jmp-evidence.txt",
    ] {
        assert!(p.files().contains_key(file), "missing {file}");
    }
    assert!(!p.files().contains_key("adjacent-b2-evidence.txt"));
    p
}
fn all_draft_eq(a: &SelectionDraft, b: &SelectionDraft) {
    draft_eq(a, b);
    assert_eq!(format!("{:?}", a.routed), format!("{:?}", b.routed));
    assert_eq!(
        format!("{:?}", a.blocked_groups),
        format!("{:?}", b.blocked_groups)
    );
}
fn expected_binding(case: &frozen::Fixture) -> (Vec<u8>, BTreeMap<String, Vec<u8>>) {
    let head_pcs: Vec<_> = text(case.ledger)
        .lines()
        .filter_map(|l| l.strip_prefix("head "))
        .map(|l| l.split_once(' ').unwrap().0)
        .collect();
    let mut rows = vec![(1, L, 2, 0x401bbe, 66), (2, U, 2, U, 2)];
    if case.selected == 3 {
        rows.push((3, Q, 5, 0x401c45, 448));
    }
    let mut sites = String::new();
    let mut inventory = String::new();
    for (id, pc, length, block, size) in rows {
        writeln!(sites, "site {id} {pc} {length} {} {BASE} 4096 {BASE} 4096 {block} {size} 1 observe original-decode", pc - 0x400000).unwrap();
        write!(sites, "entries {id} complete {}", case.ledger_sha256).unwrap();
        for head in &head_pcs {
            write!(sites, " {head}:0").unwrap();
        }
        writeln!(sites, "\nresumes {id} none").unwrap();
        writeln!(
            inventory,
            "{id}\t{pc}\t{length}\t{}\t{BASE}\t4096\t{block}\t{size}",
            pc - 0x400000
        )
        .unwrap();
    }
    let placement = text(case.policy)
        .lines()
        .filter(|l| l.starts_with("search ") || l.starts_with("allocation "))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let manifest = format!("LI2TOOL 1\noriginal {}\nneighbor-victims short-only\nneighbor-ownership inherited-t3\npending-selected full-instruction-ownership\n{EXTRA}target fxsave64\ndomain 1\ncarrier 4718592\nlimits 1048576 32 32 131072 128 2097152 1048576 128 2147483648\nhook 1 4202240 1 {}\n{sites}{placement}", case.original_sha256, digest(&[0xc3])).into_bytes();
    let inventory = format!(
        "LI2DISASSEMBLY-INVENTORY\t1\nprofile\t{PROFILE}\n{FAMILY}original_sha256\t{}\nledger_sha256\t{}\ncomplete_jump_count\t{}\nqualification_complete\tfalse\nid\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length\n{inventory}",
        case.original_sha256, case.ledger_sha256, case.selected
    );
    let planning = format!(
        "LI2PLANNING\t1\nprofile\t{PROFILE}\n{FAMILY}adjacent_upper\t2\nadjacent_lower\t1\nadjacent_joint\t2\nscope\tartifact-code-regions-not-functions\nentries\tall-verified-instruction-heads\noriginal_sha256\t{}\nledger_sha256\t{}\npolicy_sha256\t{}\nselection_sha256\t{}\ncomplete_jump_count\t{}\nqualification_complete\tfalse\n",
        case.original_sha256,
        case.ledger_sha256,
        case.policy_sha256,
        digest(&manifest),
        case.selected
    );
    (
        manifest,
        BTreeMap::from([
            ("disassembly.txt".into(), case.ledger.to_vec()),
            ("disassembly-policy.txt".into(), case.policy.to_vec()),
            ("disassembly-inventory.tsv".into(), inventory.into_bytes()),
            ("planning-profile.tsv".into(), planning.into_bytes()),
        ]),
    )
}

#[test]
fn rj01_full_independent_binding_and_strict_versions() {
    for case in [&frozen::PRIMARY, &frozen::PREDECESSOR] {
        let m = Mixed::new(case);
        let (expected, files) = expected_binding(case);
        let bound = m.bind();
        assert_eq!(bound.manifest(), expected);
        compare_complete(&files, &bound.base.files).unwrap();
        assert!(selection::parse(&expected).is_err());
        let import = || {
            disassembly::import(&m.fixture.original, case.ledger, ContentId::of(case.ledger))
                .unwrap()
        };
        assert!(
            import()
                .bind_adjacent_b2(case.policy, ContentId::of(case.policy))
                .is_err()
        );
        assert!(
            import()
                .bind_short_t3_pending(case.policy, ContentId::of(case.policy))
                .is_err()
        );
        for (a, b) in [
            ("LI2DISASM-POLICY 6", "LI2DISASM-POLICY 5"),
            ("LI2DISASM-POLICY 6", "LI2DISASM-POLICY 4"),
            (
                "adjacent-pairs original-geometry-jcc-or-routed-jmp-v1",
                "adjacent-pairs unknown",
            ),
            (
                "adjacent-pair-budgets 2 1 2",
                "adjacent-pair-budgets 02 1 2",
            ),
            ("adjacent-pair-budgets 2 1 2", "adjacent-pair-budgets 2 1 3"),
            (
                "adjacent-pair-budgets 2 1 2",
                "adjacent-pair-budgets 257 1 2",
            ),
        ] {
            assert!(m.bind_policy(&text(case.policy).replace(a, b)).is_err());
        }
        for tag in ["original", "ledger"] {
            let old = text(case.policy)
                .lines()
                .find(|l| l.starts_with(&format!("{tag} ")))
                .unwrap();
            assert!(
                m.bind_policy(
                    &text(case.policy).replace(old, &format!("{tag} {}", "0".repeat(64)))
                )
                .is_err()
            );
        }
        let missing = text(case.policy)
            .lines()
            .filter(|l| !l.starts_with("search 1 "))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert!(m.bind_policy(&missing).is_err());
        assert!(
            m.bind_policy(&(text(case.policy).to_owned() + "search 99 B2 0 2 1 none 0 0\n"))
                .is_err()
        );
        let duplicate = text(case.policy).replace(EXTRA, &(EXTRA.to_owned() + EXTRA));
        assert!(m.bind_policy(&duplicate).is_err());
        let mut huge = text(case.policy).to_owned();
        huge.push_str(&" ".repeat(disassembly::TEXT_LIMIT));
        assert!(m.bind_policy(&huge).is_err());
        assert!(
            import()
                .bind_adjacent_routed_jmp(case.policy, ContentId::of(b"wrong"))
                .is_err()
        );
    }
}

#[test]
fn rj02_rj03_real_primary_predecessor_and_routes() {
    for case in [&frozen::PRIMARY, &frozen::PREDECESSOR] {
        let m = Mixed::new(case);
        let (s, d) = m.planned();
        let p = mixed_pair(&d);
        assert_eq!(p.logical_pcs(), [U, L]);
        assert_eq!(p.evidence().suffix, Some(F));
        assert_eq!(
            p.evidence().counts,
            PairCounts {
                upper: 1,
                lower: 1,
                joint: 1
            }
        );
        assert_eq!(p.evidence().upper_slots, [(0, Some(0x5f2300))]);
        assert_eq!(
            p.evidence().lower_schedules[0].window,
            addr(0x073c0503, 256).unwrap()
        );
        assert_eq!(p.evidence().lower_schedules[0].targets, [0x073c0600]);
        assert!(matches!(
            p.members()[0].source_steps()[0].parts().kind,
            PlanKind::Relocation
        ));
        assert!(matches!(
            p.members()[1].source_steps()[0].parts().kind,
            PlanKind::GeneralizedPun(_)
        ));
        assert_eq!(
            p.members()[0].source_steps()[0].parts().writes[0].bytes,
            [0xe9, 0xfb, 0x06, 0x1f, 0]
        );
        assert_eq!(
            &m.fixture.original[0x1c00..0x1c05],
            &[0xeb, 0x43, 0x4c, 0x89, 0xe7]
        );
        let lower_read = p.members()[1].source_steps()[0]
            .parts()
            .reads
            .iter()
            .find(|r| r.address <= U && U + 3 <= r.address + r.bytes.len() as u64)
            .unwrap();
        let offset = (U - lower_read.address) as usize;
        assert_eq!(&lower_read.bytes[offset..offset + 3], &[0xe9, 0xfb, 0x06]);
        let composed = d.composition.final_bytes();
        let region = composed
            .iter()
            .find(|r| r.address <= L && E <= r.address + r.bytes.len() as u64)
            .unwrap();
        let offset = (L - region.address) as usize;
        assert_eq!(
            &region.bytes[offset..offset + 7],
            &[0xe9, 0xfd, 0xe9, 0xfb, 0x06, 0x1f, 0]
        );
        let upper = p.members()[0].images().next().unwrap();
        let route = upper
            .entry_routes()
            .iter()
            .find(|(original, _)| *original == F)
            .unwrap();
        assert!(route.1 > upper.address());
        assert!(
            upper
                .metadata()
                .requirements()
                .contains(&ArtifactRequirement::EntryRouterBootstrap)
        );
        assert!(p.members()[0].source_steps()[0].parts().obligations.iter().any(|o|
            matches!(o, EntryObligation::Routed(r) if r.original==F && r.generated==route.1)));
        let targets: Vec<_> = upper
            .metadata()
            .fields()
            .iter()
            .map(|f| (f.role.as_str(), f.target))
            .collect();
        assert!(targets.contains(&("LogicalPc", i128::from(U))));
        assert!(targets.contains(&("HookCall", 0x401f00)));
        assert!(targets.contains(&("OriginalBranch { original_pc: 4201472 }", 0x401c45)));
        assert!(targets.contains(&("Return", i128::from(E))));
        assert_eq!(d.baseline.len(), case.selected);
        assert!(d.pending.is_empty());
        assert_eq!(d.totals.steps, case.selected);
        assert_eq!(d.image_count, case.selected);
        assert_eq!(d.allocation_pages, case.selected as u64);
        assert_eq!(d.reports[0].core_tactic, Some(Tactic::GeneralizedPun));
        assert_eq!(d.reports[1].core_tactic, Some(Tactic::Relocation));
        let ids: Vec<_> = (1..=case.selected as u64).collect();
        let product = complete_mixed(&m, &ids);
        let expected_order = if case.selected == 3 {
            vec![3, 2, 1]
        } else {
            vec![2, 1]
        };
        assert_eq!(
            d.accepted.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            expected_order
        );
        assert_eq!(s.sites[0].heads.len(), case.heads);
        assert!(
            text(&product.files()["ledger.tsv"]).contains("entry-router-required\t2\t0\t4201474\t")
        );
        if case.selected == 3 {
            let elf = Elf64::parse(
                &m.fixture.original,
                ParseLimits {
                    max_program_headers: 128,
                },
            )
            .unwrap();
            let dynamic =
                carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default()).unwrap();
            let (identity, mut before) = m.fixture.initial(&s);
            baseline(&elf, &dynamic, &s, identity, &mut before, 2).unwrap();
            assert!(before.reports[2].refusal.is_none());
            image_eq(&before.accepted[0].1, &d.accepted[0].1);
            report_eq(&before.reports[2], &d.reports[2]);
            assert!(before.occupied.iter().all(|r| d.occupied.contains(r)));
            assert!(
                before
                    .dependencies
                    .iter()
                    .all(|r| d.dependencies.contains(r))
            );
        }
    }
}

#[test]
fn rj06_rj07_original_dispatch_exclusions_never_retry_another_family() {
    let m = Mixed::new(&frozen::PRIMARY);
    let (s, d) = m.planned();
    assert_eq!(d.routed.calls.len(), 1);
    assert_eq!(d.routed.calls[0].family, PairKind::RoutedJmp);
    assert!(d.work.is_empty());
    let elf = Elf64::parse(
        &m.fixture.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    assert_eq!(
        exclusion(&elf, &s.sites[0], &s.sites[1]),
        Some("branch-target")
    );
    assert!(routed_jmp::eligibility(&elf, &s, &s.sites[0], &s.sites[1]).is_ok());
    for mutation in 0..8 {
        let mut changed = s.clone();
        match mutation {
            0 => changed.sites[1].forced = Some(Tactic::GeneralizedPun),
            1 => changed.sites[0].forced = Some(Tactic::Relocation),
            2 => changed.sites[0].search.max_sites = 0,
            3 => changed.sites[0].heads[0].requires_endbr = true,
            4 => changed.sites[0].resumes = ResumeObligation::Unresolved,
            5 => changed.sites[0].hook = 2,
            6 => changed.sites[0].completeness = EntryCompleteness::Incomplete,
            _ => {
                let mut suffix = changed.sites[0].clone();
                suffix.id = 3;
                suffix.pc = F;
                suffix.length = 3;
                changed.sites.push(suffix);
            }
        }
        assert!(
            routed_jmp::eligibility(&elf, &changed, &changed.sites[0], &changed.sites[1]).is_err()
        );
    }
    for (offset, byte) in [
        (0x1bfe, 0x75),
        (0x1bff, 0),
        (0x1c00, 0x75),
        (0x1c01, 0),
        (0x1c04, 0xe6),
    ] {
        let mut bytes = m.fixture.original.clone();
        bytes[offset] = byte;
        let elf = Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: 128,
            },
        )
        .unwrap();
        assert!(routed_jmp::eligibility(&elf, &s, &s.sites[0], &s.sites[1]).is_err());
    }
    let mut refused = Mixed::new(&frozen::PRIMARY);
    refused.caps(0, 1, 0);
    let (_, d) = refused.planned();
    assert_eq!(d.routed.work.len(), 1);
    assert!(d.work.is_empty());
    assert!(!d.routed.work[0].committed);
    assert_eq!(
        d.routed.work[0]
            .result
            .as_ref()
            .unwrap_err()
            .evidence
            .counts,
        PairCounts::default()
    );
    no_candidate(&refused.run(), &[1, 2]);
}

#[test]
fn rj08_rj09_pending_and_original_identity_are_not_discharged() {
    let mut m = Mixed::new(&frozen::PREDECESSOR);
    m.replace(
        "allocation 3 selected 5242880 1 4096 5242880:4096",
        "allocation 3 selected 4194304 1 4096 4194304:4096",
    );
    let (s, d) = m.planned();
    assert!(d.routed.work[0].committed);
    assert_eq!(d.pending, vec![(2, addr(Q, 5).unwrap())]);
    assert!(d.reports[2].refusal.is_some());
    assert_eq!(d.baseline.len(), 3);
    assert_eq!(
        d.accepted.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [2, 1]
    );
    no_candidate(&m.run(), &[1, 2, 3]);
    let p = Mixed::new(&frozen::PRIMARY);
    let bound = p.bind();
    let mut original = p.fixture.original.clone();
    original[0x1bff] ^= 1;
    assert!(routed_jmp::prepare_disassembly_adjacent_routed_jmp(&original, &bound).is_err());
    let elf = Elf64::parse(
        &m.fixture.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let (identity, mut before) = m.fixture.initial(&s);
    let snapshot = before.clone();
    before.composition = d.composition.clone();
    let frozen = before.clone();
    let e = routed_jmp::call(
        &elf,
        &s,
        identity,
        AdjacentB2Limits {
            upper: 2,
            lower: 1,
            joint: 2,
        },
        &before,
        0,
        1,
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(e.reason, Refusal::OwnershipConflict);
    assert_eq!(e.evidence.counts, PairCounts::default());
    all_draft_eq(&before, &frozen);
    assert_ne!(
        snapshot.composition.final_bytes(),
        before.composition.final_bytes()
    );
    let mut stale = identity;
    stale.generation += 1;
    let refusal = routed_jmp::call(
        &elf,
        &s,
        stale,
        AdjacentB2Limits {
            upper: 2,
            lower: 1,
            joint: 2,
        },
        &snapshot,
        0,
        1,
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(refusal.reason, Refusal::StaleGeneration);
    assert_eq!(refusal.evidence.counts, PairCounts::default());
}

#[test]
fn rj10_rj11_independent_budgets_and_original_upper_prefix() {
    let base = Mixed::new(&frozen::PRIMARY);
    for (u, l, j) in [(0, 0, 0), (0, 1, 0), (2, 0, 2), (2, 1, 0), (256, 256, 256)] {
        let policy = base.fixture.policy.replace(
            "adjacent-pair-budgets 2 1 2",
            &format!("adjacent-pair-budgets {u} {l} {j}"),
        );
        assert!(base.bind_policy(&policy).is_ok());
    }
    for (u, l, j, stop) in [
        (0, 1, 0, li2core::quiescent::RoutedJmpStop::UpperBudget),
        (2, 0, 2, li2core::quiescent::RoutedJmpStop::LowerBudget),
        (2, 1, 0, li2core::quiescent::RoutedJmpStop::JointBudget),
    ] {
        let mut m = Mixed::new(&frozen::PRIMARY);
        m.caps(u, l, j);
        let (_, d) = m.planned();
        let e = d.routed.work[0].result.as_ref().unwrap_err();
        assert_eq!(e.stop, stop);
        assert_eq!(e.evidence.counts, PairCounts::default());
        assert_eq!(d.baseline.len(), 2);
        assert_eq!(d.routed.calls.len(), 1);
    }
    let mut second = Mixed::new(&frozen::PRIMARY);
    second.replace(
        "allocation 1 selected 121374208 1 4096 121372672:4096",
        "allocation 1 selected none 1 4096 138149888:4096",
    );
    let (_, d) = second.planned();
    let p = mixed_pair(&d);
    assert_eq!(
        p.evidence().counts,
        PairCounts {
            upper: 2,
            lower: 1,
            joint: 2
        }
    );
    assert_eq!(
        p.evidence().upper_slots,
        [(0, Some(0x5f2300)), (1, Some(0x5f2400))]
    );
    assert!(p.evidence().lower_schedules[0].targets.is_empty());
    assert_eq!(p.evidence().lower_schedules[1].targets, [0x083c0503]);
    complete_mixed(&second, &[1, 2]);
    second.caps(2, 1, 1);
    let (_, d) = second.planned();
    let e = d.routed.work[0].result.as_ref().unwrap_err();
    assert_eq!(e.stop, li2core::quiescent::RoutedJmpStop::JointBudget);
    assert_eq!(
        e.evidence.counts,
        PairCounts {
            upper: 1,
            lower: 0,
            joint: 1
        }
    );
    assert_eq!(d.routed.calls.len(), 1);
    second.replace("adjacent-pair-budgets 2 1 1", "adjacent-pair-budgets 1 1 1");
    let (_, d) = second.planned();
    let e = d.routed.work[0].result.as_ref().unwrap_err();
    assert_eq!(e.stop, li2core::quiescent::RoutedJmpStop::UpperBudget);
    assert_eq!(
        e.evidence.counts,
        PairCounts {
            upper: 1,
            lower: 0,
            joint: 1
        }
    );
    assert_eq!(e.unvisited_target, Some(0x5f2400));
    assert_eq!(d.routed.calls.len(), 1);
}

fn union_fixture(f: Fixture) -> Mixed {
    let mut m = Mixed { fixture: f };
    m.replace("LI2DISASM-POLICY 5", "LI2DISASM-POLICY 6");
    m.replace(
        "adjacent-b2 fallback-two-site-v1\nadjacent-b2-budgets 2 1 2\n",
        EXTRA,
    );
    m
}
#[test]
fn rj04_unchanged_forward_jcc_geometry_uses_only_original_api() {
    let original = Fixture::primary();
    let old = original.planned();
    let m = union_fixture(original);
    let (_, new) = m.planned();
    assert_eq!(new.routed.calls.len(), 1);
    assert_eq!(new.routed.calls[0].family, PairKind::ForwardJcc);
    assert!(new.routed.work.is_empty());
    assert_eq!(new.work.len(), 1);
    let a = pair(&old);
    let b = pair(&new);
    assert_eq!(a.logical_pcs(), b.logical_pcs());
    assert_eq!(format!("{:?}", a.evidence()), format!("{:?}", b.evidence()));
    for (a, b) in a.members().iter().zip(b.members()) {
        image_eq(a, b);
    }
    assert_eq!(old.composition.final_bytes(), new.composition.final_bytes());
    assert_eq!(old.occupied, new.occupied);
    assert_eq!(old.dependencies, new.dependencies);
    complete_mixed(&m, &[1, 2]);
}

// Use the existing literal old-baseline oracle, independently prescribing v6
// BEFORE looking at the new binder. No expected digest comes from its output.
fn union_expected_binding(f: &Fixture, old: &Product) -> ExpectedBinding {
    let old_binding = super::expected_binding(f, old);
    let manifest = text(&old_binding.manifest)
        .replace(
            "adjacent-b2 fallback-two-site-v1\nadjacent-b2-budgets 2 1 2\n",
            EXTRA,
        )
        .into_bytes();
    let mut files = old_binding.files;
    let policy = text(&files["disassembly-policy.txt"])
        .replace("LI2DISASM-POLICY 5", "LI2DISASM-POLICY 6")
        .replace(
            "adjacent-b2 fallback-two-site-v1\nadjacent-b2-budgets 2 1 2\n",
            EXTRA,
        )
        .into_bytes();
    let old_policy = digest(&files["disassembly-policy.txt"]);
    for name in ["disassembly-inventory.tsv", "planning-profile.tsv"] {
        let mut value = text(&files[name])
            .replace(
                "elf-disassembly-null-jumps-adjacent-b2-short-t3-pending-v1",
                PROFILE,
            )
            .replace(
                "adjacent_b2\tfallback-two-site-v1\n",
                "adjacent_pairs\toriginal-geometry-jcc-or-routed-jmp-v1\n",
            );
        if name == "planning-profile.tsv" {
            value = value
                .replace(
                    &format!("policy_sha256\t{old_policy}\n"),
                    &format!("policy_sha256\t{}\n", digest(&policy)),
                )
                .replace(
                    &format!("selection_sha256\t{}\n", digest(&old_binding.manifest)),
                    &format!("selection_sha256\t{}\n", digest(&manifest)),
                );
        }
        files.insert(name.into(), value.into_bytes());
    }
    files.insert("disassembly-policy.txt".into(), policy);
    ExpectedBinding {
        old_manifest: old_binding.old_manifest,
        manifest,
        files,
    }
}
#[test]
fn rj05_exact_no_fallback_all_files_and_mutants() {
    let mut f = Fixture::primary();
    f.replace(
        &format!("allocation 2 selected {H128}"),
        &format!("allocation 2 selected {H0}"),
    );
    let baseline = baseline_draft(&f);
    let old = prepare_disassembly(&f.original, &f.old()).unwrap();
    assert!(old.candidate_complete());
    let expected_binding = union_expected_binding(&f, &old);
    let m = union_fixture(f.clone());
    let bound = m.bind();
    assert_eq!(bound.manifest(), expected_binding.manifest);
    compare_complete(&expected_binding.files, &bound.base.files).unwrap();
    let mut expected = expected_files(&f, &old, &expected_binding, &baseline);
    expected.remove("adjacent-b2-evidence.txt");
    expected.remove("bundle-index.tsv");
    // Sole expected difference in pair evidence is the declared union schema.
    // Empty inventories and baseline resources are independently fixed here.
    let edges = vec![Edge {
        lower: 1,
        upper: 2,
        exclusion: None,
        visited_group: true,
    }];
    let union_edges = vec![routed_jmp::Edge {
        lower: 1,
        upper: 2,
        family: Some(PairKind::ForwardJcc),
        exclusion: None,
    }];
    let calls: Vec<routed_jmp::Dispatch> = Vec::new();
    let forward: Vec<Work> = Vec::new();
    let mixed: Vec<routed_jmp::Work> = Vec::new();
    let mut slots = 0;
    for b in &baseline.baseline {
        let ArtifactMetrics::Engine(_, _, attempts) = b.result.as_ref().unwrap().metrics() else {
            panic!("engine")
        };
        for attempt in attempts {
            for run in &attempt.search.runs {
                if matches!(
                    run.domain,
                    li2core::search::SearchDomain::SelectedImages
                        | li2core::search::SearchDomain::VictimImages
                ) {
                    slots += run.examined;
                }
            }
        }
    }
    let evidence=format!("LI2ADJACENT-ROUTED-JMP-EVIDENCE\t1\nselection_sha256\t{}\nselected_count\t2\nbaseline_calls\t2\npair_calls\t0\nadjacent_counts\t0\t0\t0\nforward_jcc_calls\t0\nforward_jcc_counts\t0\t0\t0\nrouted_jmp_calls\t0\nrouted_jmp_counts\t0\t0\t0\nqualification_complete\tfalse\nclassification_complete\tfalse\nlegacy_image_slots\t{slots}\ncombined_image_work_upper_bound\t{slots}\nresources\t{:#?}\nedges\t{:#?}\nbaseline\t{:#?}\nforward_pairs\t{:#?}\nrouted_pairs\t{:#?}\n",
        digest(&expected_binding.manifest),baseline.totals,(&edges,&union_edges,&calls),
        baseline.baseline,forward,mixed).into_bytes();
    expected.insert("adjacent-routed-jmp-evidence.txt".into(), evidence);
    let mut index = format!(
        "LI2BUNDLE\t1\noriginal_sha256\t{}\nqualification_complete\tfalse\nconsumer_action\tRuntimeScan-while-gated-until-qualified\n",
        digest(&f.original)
    );
    for (name, bytes) in &expected {
        writeln!(index, "file\t{name}\t{}\t{}", bytes.len(), digest(bytes)).unwrap();
    }
    expected.insert("bundle-index.tsv".into(), index.into_bytes());
    let (_, mut d) = m.planned();
    assert!(d.routed.calls.is_empty());
    assert!(d.work.is_empty());
    assert!(d.routed.work.is_empty());
    d.edges.clear();
    d.routed.edges.clear();
    all_draft_eq(&d, &baseline);
    let new = complete_mixed(&m, &[1, 2]);
    for (a, b) in old.reports().iter().zip(new.reports()) {
        report_eq(a, b);
    }
    compare_complete(&expected, new.files()).unwrap();
    // Every file, including the full ELF, participates. Keep all old F28 controls too.
    for name in expected.keys() {
        let mut mutant = new.files().clone();
        mutant.get_mut(name).unwrap().push(0);
        assert!(compare_complete(&expected, &mutant).is_err(), "{name}");
    }
    for (from, to) in [
        ("ForwardJcc", "RoutedJmp"),
        ("routed_jmp_calls\t0", "routed_jmp_calls\t1"),
        (
            "LI2ADJACENT-ROUTED-JMP-EVIDENCE\t1",
            "LI2ADJACENT-ROUTED-JMP-EVIDENCE\t2",
        ),
    ] {
        let mut mutant = new.files().clone();
        let name = "adjacent-routed-jmp-evidence.txt";
        let before = text(&mutant[name]);
        assert!(before.contains(from));
        mutant.insert(name.into(), before.replace(from, to).into_bytes());
        assert!(compare_complete(&expected, &mutant).is_err());
    }
    // Report tactic, route ledger and either carrier identity field cannot be exempted.
    for name in [
        "report.tsv",
        "ledger.tsv",
        "candidate.elf",
        "metadata.li2meta",
        "source.li2sparse",
    ] {
        let mut mutant = new.files().clone();
        mutant.get_mut(name).unwrap()[0] ^= 1;
        assert!(compare_complete(&expected, &mutant).is_err());
    }
}

#[test]
fn rj12_public_resources_include_real_predecessor_pair_and_carrier() {
    let m = Mixed::new(&frozen::PREDECESSOR);
    let (_, d) = m.planned();
    mixed_pair(&d);
    let bytes = d
        .accepted
        .iter()
        .flat_map(|(_, p)| p.images())
        .map(|i| i.bytes().len())
        .sum::<usize>();
    let mut exact = Mixed::new(&frozen::PREDECESSOR);
    exact.fixture.limits(3, bytes, 4, 2147483648);
    let product = complete_mixed(&exact, &[1, 2, 3]);
    assert!(text(&product.files()["ledger.tsv"]).contains("new_load_pages\t4\n"));
    let (s, d) = exact.planned();
    assert_eq!(d.totals, Resources::collect(&d.accepted).unwrap());
    assert_eq!(d.image_bytes, bytes);
    assert_eq!(d.image_count, 3);
    assert_eq!(d.allocation_pages, 3);
    let cap = Capacities::from_selection(&s).unwrap();
    assert_eq!(cap.steps, 6);
    assert_eq!(cap.mappings, 3);
    assert_eq!(d.totals.pair_budget(cap, 2).unwrap().bundle.max_steps, 2);
    for (images, payload, pages, span) in [
        (2, bytes, 4, 2147483648),
        (3, bytes - 1, 4, 2147483648),
        (3, bytes, 3, 2147483648),
        (3, bytes, 4, 0x06ec0fff),
        (3, bytes, 4, 0x06fc0fff),
    ] {
        let mut limited = Mixed::new(&frozen::PREDECESSOR);
        limited.fixture.limits(images, payload, pages, span);
        let (_, d) = limited.planned();
        assert_eq!(d.routed.calls.len(), 1);
        assert_eq!(d.routed.work.len(), 1);
        no_candidate(&limited.run(), &[1, 2, 3]);
    }
    // Internal accounting checks are not public policy knobs.
    let totals = d.totals.clone();
    let exact = Capacities {
        steps: totals.steps,
        mappings: totals.mappings,
        virtual_bytes: totals.virtual_bytes,
        backing_bytes: totals.backing_bytes,
        span: totals.end - totals.first.unwrap(),
    };
    totals.check(exact).unwrap();
    for field in 0..5 {
        let mut cap = exact;
        match field {
            0 => cap.steps -= 1,
            1 => cap.mappings -= 1,
            2 => cap.virtual_bytes -= 1,
            3 => cap.backing_bytes -= 1,
            _ => cap.span -= 1,
        }
        assert!(totals.check(cap).is_err());
    }
}

#[test]
fn rj13_atomic_stages_use_real_pair_and_restore_every_field() {
    let m = Mixed::new(&frozen::PREDECESSOR);
    complete_mixed(&m, &[1, 2, 3]);
    let bound = m.bind();
    let s = &bound.base.selection;
    let elf = Elf64::parse(
        &m.fixture.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let dynamic = carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default()).unwrap();
    let (identity, mut before) = m.fixture.initial(s);
    baseline(&elf, &dynamic, s, identity, &mut before, 2).unwrap();
    let pair = routed_jmp::call(
        &elf,
        s,
        identity,
        AdjacentB2Limits {
            upper: 2,
            lower: 1,
            joint: 2,
        },
        &before,
        0,
        1,
    )
    .unwrap()
    .unwrap();
    for point in ["upper-appended", "both-appended", "associations-built"] {
        let saved = before.clone();
        let mut reached = false;
        let result = stage_members(
            &elf,
            &dynamic,
            s,
            &before,
            PairAssociation {
                lower: 0,
                upper: 1,
                attempt: 0,
            },
            routed_jmp::view(&pair),
            |at, _| {
                if at == point {
                    reached = true;
                    Err(Error::new("injected-transaction-failure", point))
                } else {
                    Ok(())
                }
            },
        );
        assert!(reached);
        assert_eq!(result.unwrap_err().stage, "injected-transaction-failure");
        all_draft_eq(&before, &saved);
    }
    let mut hostile = s.clone();
    hostile.hooks[0].pc = U;
    let saved = before.clone();
    assert_eq!(
        stage_members(
            &elf,
            &dynamic,
            &hostile,
            &before,
            PairAssociation {
                lower: 0,
                upper: 1,
                attempt: 0
            },
            routed_jmp::view(&pair),
            |_, _| Ok(())
        )
        .unwrap_err()
        .stage,
        "hook-ownership"
    );
    all_draft_eq(&before, &saved);
}

#[test]
fn rj14_fatal_serialization_has_no_product_and_carrier_failure_keeps_roster() {
    let m = Mixed::new(&frozen::PREDECESSOR);
    complete_mixed(&m, &[1, 2, 3]);
    for point in [
        "evidence-serialization",
        "carrier-construction",
        "sparse-serialization",
        "complete-output-serialization",
    ] {
        let bound = m.bind();
        let mut reached = false;
        let result = prepare_selection_with_pair_gate(
            &m.fixture.original,
            bound.base.selection,
            false,
            disassembly::NeighborMode::ShortT3Pending,
            Some(AdjacentB2Limits {
                upper: 2,
                lower: 1,
                joint: 2,
            }),
            PairProfile::RoutedJmpUnion,
            |at| {
                if at == point {
                    reached = true;
                    Err(Error::new("injected-output-failure", point))
                } else {
                    Ok(())
                }
            },
        );
        assert!(reached);
        assert_eq!(result.unwrap_err().stage, "injected-output-failure");
    }
    let mut limited = Mixed::new(&frozen::PREDECESSOR);
    limited.replace("128 2097152 1048576 128", "128 4096 1048576 128");
    let p = limited.run();
    no_candidate(&p, &[1, 2, 3]);
    assert!(
        p.reports()
            .iter()
            .all(|r| r.refusal.as_ref().unwrap().stage == "carrier")
    );
    let e = text(&p.files()["adjacent-routed-jmp-evidence.txt"]);
    assert!(e.contains("selected_count\t3\nbaseline_calls\t3\npair_calls\t1\n"));
    assert!(e.contains("committed: true"));
}

#[test]
fn rj15_scalars_family_tactics_and_offsets_are_exact() {
    for (m, heads, selected, family) in [
        (
            Mixed::new(&frozen::PREDECESSOR),
            4078,
            3,
            PairKind::RoutedJmp,
        ),
        (
            union_fixture(Fixture::primary()),
            4,
            2,
            PairKind::ForwardJcc,
        ),
    ] {
        let (s, d) = m.planned();
        let p = complete_mixed(&m, &(1..=selected).collect::<Vec<_>>());
        assert_eq!(s.sites[0].heads.len(), heads);
        let e = text(&p.files()["adjacent-routed-jmp-evidence.txt"]);
        let rows: Vec<_> = e
            .lines()
            .take(14)
            .map(|l| l.split('\t').collect::<Vec<_>>())
            .collect();
        assert_eq!(rows[0], ["LI2ADJACENT-ROUTED-JMP-EVIDENCE", "1"]);
        assert_eq!(rows[1], ["selection_sha256", &digest(&s.manifest)]);
        assert_eq!(rows[2], ["selected_count", &selected.to_string()]);
        assert_eq!(rows[4], ["pair_calls", "1"]);
        assert_eq!(rows[10], ["qualification_complete", "false"]);
        assert_eq!(rows[11], ["classification_complete", "false"]);
        let c: Vec<usize> = rows[5][1..].iter().map(|s| s.parse().unwrap()).collect();
        let a: Vec<usize> = rows[7][1..].iter().map(|s| s.parse().unwrap()).collect();
        let b: Vec<usize> = rows[9][1..].iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(c, (0..3).map(|i| a[i] + b[i]).collect::<Vec<_>>());
        assert_eq!(
            rows[13][1].parse::<usize>().unwrap(),
            rows[12][1].parse::<usize>().unwrap() + c[0] + c[1]
        );
        for (ordinal, id) in [2_u64, 1].into_iter().enumerate() {
            let report = &d.reports[(id - 1) as usize];
            assert!(report.diagnostics.contains(family.name()));
            assert!(report.diagnostics.contains(&format!(
                "member={ordinal} role={} selected_id={id}",
                if ordinal == 0 { "upper" } else { "lower" }
            )));
            let offset = ordinal + if selected == 3 { 1 } else { 0 };
            assert!(report.diagnostics.contains(&format!(
                "image_start={offset} image_count=1 step_start={offset} step_count=1"
            )));
            assert_eq!(
                report.core_tactic,
                Some(if family == PairKind::RoutedJmp && ordinal == 0 {
                    Tactic::Relocation
                } else {
                    Tactic::GeneralizedPun
                })
            );
        }
    }
}

#[test]
fn rj17_real_importer_full_rosters_never_reduce_selected_denominator() {
    for (heads, jumps) in [(80, 16), (107, 26)] {
        // Authored structural fixture, not compiler output or a corpus outcome.
        // All heads are literal NOP, EB00 or C3; startup has61 heads/14 jumps,
        // kernel has heads-62 heads/jumps-14, and the final null hook is one C3.
        let mut code = Vec::new();
        let mut lengths = Vec::new();
        for i in 0..heads {
            let branch = i < 14 || (61..61 + jumps - 14).contains(&i);
            if branch {
                code.extend_from_slice(&[0xeb, 0]);
                lengths.push(2);
            } else {
                code.push(if i == heads - 1 { 0xc3 } else { 0x90 });
                lengths.push(1);
            }
        }
        let f = Fixture::source(0x400100, &code, &lengths, 0x500000, 0x600000);
        let mut m = union_fixture(f);
        // Prospective bounded refusal: each selected EB ends its two-byte block;
        // forced B1 with a two-byte displacement bound has no five-byte window.
        // This synthetic roster is not the production allocation policy or a positive.
        assert_eq!(
            m.fixture.policy.matches(" B2 0 2 1 none 0 0").count(),
            jumps
        );
        m.fixture.policy = m
            .fixture
            .policy
            .replace(" B2 0 2 1 none 0 0", " B1 0 2 1 none 0 0");
        let bound = m.bind();
        assert_eq!(bound.base.selection.sites.len(), jumps);
        assert!(
            bound
                .base
                .selection
                .sites
                .iter()
                .all(|s| s.heads.len() == heads)
        );
        let (s, d) = m.planned();
        assert_eq!(s.sites.len(), jumps);
        assert_eq!(d.baseline.len(), jumps);
        assert_eq!(d.reports.len(), jumps);
        assert!(d.routed.calls.is_empty());
        let p = m.run();
        assert_eq!(p.reports().len(), jumps);
        no_candidate(&p, &(1..=jumps as u64).collect::<Vec<_>>());
        assert!(!p.qualification_complete());
    }
}

fn rebind_original(m: &mut Mixed) {
    let old = m.fixture.ledger.lines().nth(1).unwrap().to_owned();
    m.fixture.ledger = m.fixture.ledger.replacen(
        &old,
        &format!("original {}", digest(&m.fixture.original)),
        1,
    );
    let old = m.fixture.policy.lines().nth(1).unwrap().to_owned();
    m.replace(&old, &format!("original {}", digest(&m.fixture.original)));
    let old = m.fixture.policy.lines().nth(2).unwrap().to_owned();
    m.replace(
        &old,
        &format!("ledger {}", digest(m.fixture.ledger.as_bytes())),
    );
}
#[test]
fn rj14_later_selected_failure_keeps_actual_pair_but_no_subset_candidate() {
    let mut m = Mixed::new(&frozen::PRIMARY);
    complete_mixed(&m, &[1, 2]);
    m.fixture.original[0x1100..0x1105].copy_from_slice(&[0xe9, 0xfb, 0xff, 0xff, 0xff]);
    m.fixture.ledger = m
        .fixture
        .ledger
        .replace("head 4198656 b807000000", "head 4198656 e9fbffffff");
    let mut rows = Vec::new();
    for row in m.fixture.policy.lines() {
        let mut fields: Vec<String> = row.split(' ').map(str::to_owned).collect();
        if matches!(fields[0].as_str(), "search" | "allocation") {
            fields[1] = (fields[1].parse::<u64>().unwrap() + 1).to_string();
        }
        rows.push(fields.join(" "));
    }
    m.fixture.policy = rows.join("\n")
        + "\nsearch 1 B2 0 2 1 none 0 0\nallocation 1 selected 9437184 1 4096 9437184:4096\nallocation 1 victim 9441280 1 4096 9441280:4096\n";
    rebind_original(&mut m);
    let (_, d) = m.planned();
    assert_eq!(
        d.baseline.iter().map(|b| b.id).collect::<Vec<_>>(),
        [3, 2, 1]
    );
    assert_eq!(
        d.accepted.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [3, 2]
    );
    assert_eq!(d.pending, [(0, addr(0x401100, 5).unwrap())]);
    assert!(d.routed.work[0].committed);
    no_candidate(&m.run(), &[1, 2, 3]);
}
#[test]
fn rj15_one_immutable_selection_contains_both_real_families() {
    // Full literal checkpoint caa27645... precedes any execution.
    let m = Mixed::new(&frozen::COMBINED);
    let (_, d) = m.planned();
    assert_eq!(d.baseline.len(), 4);
    assert_eq!(
        d.routed
            .calls
            .iter()
            .map(|c| (c.attempt, c.lower, c.upper, c.family))
            .collect::<Vec<_>>(),
        [
            (0, 3, 4, PairKind::ForwardJcc),
            (1, 1, 2, PairKind::RoutedJmp)
        ]
    );
    assert_eq!(d.work.len(), 1);
    assert_eq!(d.routed.work.len(), 1);
    assert!(d.work[0].committed && d.routed.work[0].committed);
    assert_eq!(
        d.accepted.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [4, 3, 2, 1]
    );
    assert!(d.pending.is_empty());
    let p = complete_mixed(&m, &[1, 2, 3, 4]);
    assert_combined_carrier(&m.fixture.original, &d, &p);
    let e = text(&p.files()["adjacent-routed-jmp-evidence.txt"]);
    assert!(e.contains("baseline_calls\t4\npair_calls\t2\nadjacent_counts\t3\t2\t3\nforward_jcc_calls\t1\nforward_jcc_counts\t2\t1\t2\nrouted_jmp_calls\t1\nrouted_jmp_counts\t1\t1\t1\n"));
}

fn assert_combined_carrier(original: &[u8], draft: &SelectionDraft, product: &Product) {
    use crate::carrier::elf64::{FileOffset, SegmentType, Storage};
    let old = Elf64::parse(original, ParseLimits::default()).unwrap();
    let candidate = &product.files()["candidate.elf"];
    let new = Elf64::parse(candidate, ParseLimits::default()).unwrap();
    assert_eq!(new.header().entry, old.header().entry);
    assert_eq!(new.header().program_offset, FileOffset(0x3000));
    assert_eq!(new.header().program_count, 8);
    let loads: Vec<_> = new.segments(SegmentType::Load).collect();
    assert_eq!(
        loads.iter().map(|h| h.vaddr.0).collect::<Vec<_>>(),
        [
            0x400000, 0x480000, 0x5f2000, 0x073c0000, 0x10000000, 0x11c07000, 0x7900f000
        ]
    );
    let mut previous = None;
    for header in old.segments(SegmentType::Load) {
        let matched: Vec<_> = loads.iter().filter(|h| h.vaddr == header.vaddr).collect();
        assert_eq!(matched.len(), 1);
        let index = matched[0].index;
        assert!(previous.is_none_or(|prior| prior < index));
        previous = Some(index);
        let before = old.header().program_offset.0 as usize + header.index * 56;
        let after = new.header().program_offset.0 as usize + index * 56;
        assert_eq!(
            &original[before..before + 56],
            &candidate[after..after + 56]
        );
    }
    assert_eq!(
        (loads[0].file_size, loads[0].memory_size),
        (0x2000, 0x56000)
    );
    assert_eq!(
        (loads[4].offset.0, loads[4].file_size, loads[4].memory_size),
        (0x2000, 0x1000, 0x1000)
    );
    let bss = new.virtual_to_storage(ElfVaddr(0x402000), 0x54000).unwrap();
    assert_eq!(bss.storage, Storage::ZeroFill);
    assert_eq!(bss.program_header, loads[0].index);
    let table = new.file_to_virtual(FileOffset(0x3000), 8 * 56).unwrap();
    assert_eq!(
        (
            table.program_header,
            table.virtual_range.start().0,
            table.flags.0
        ),
        (loads[1].index, 0x480000, 4)
    );
    assert_eq!(loads[1].flags.0, 4);
    assert_eq!(loads[1].file_size, loads[1].memory_size);
    let phdr: Vec<_> = new.segments(SegmentType::ProgramHeaders).collect();
    assert_eq!(phdr.len(), 1);
    assert_eq!(
        (
            phdr[0].index,
            phdr[0].offset.0,
            phdr[0].vaddr.0,
            phdr[0].file_size,
            phdr[0].memory_size
        ),
        (0, 0x3000, 0x480000, 8 * 56, 8 * 56)
    );
    assert!(phdr[0].index < loads[0].index);
    let pages: Vec<_> = loads
        .iter()
        .map(|h| {
            (
                h.vaddr.0 & !4095,
                (h.vaddr.0 + h.memory_size + 4095) & !4095,
            )
        })
        .collect();
    assert!(pages.windows(2).all(|w| w[0].1 <= w[1].0));
    assert_eq!(
        (pages[0].0, pages.last().unwrap().1),
        (0x400000, 0x79010000)
    );
    assert_eq!(pages.last().unwrap().1 - pages[0].0, 0x78c10000);
    let mut expected = original.to_vec();
    for source in draft.composition.final_bytes() {
        let Storage::FileBacked(range) = old
            .virtual_to_storage(ElfVaddr(source.address), source.bytes.len() as u64)
            .unwrap()
            .storage
        else {
            panic!("original source file owner");
        };
        expected[range.start().0 as usize..range.end().0 as usize].copy_from_slice(&source.bytes);
    }
    put64(&mut expected, 32, 0x3000);
    put16(&mut expected, 56, 8);
    assert_eq!(&candidate[..original.len()], expected);
    let mut images = 0;
    for (_, plan) in &draft.accepted {
        for image in plan.images() {
            images += 1;
            assert_eq!(
                new.executable_bytes(ElfVaddr(image.address()), image.bytes().len() as u64)
                    .unwrap(),
                image.bytes()
            );
        }
    }
    assert_eq!(images, 4);
}

#[test]
fn rj07_rj08_complete_original_domain_and_head_mutants_refuse() {
    let m = Mixed::new(&frozen::PRIMARY);
    let (s, d) = m.planned();
    mixed_pair(&d);
    let elf = Elf64::parse(
        &m.fixture.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    for mutation in 0..13 {
        let mut changed = s.clone();
        match mutation {
            0 => changed.sites[0].length = 3,
            1 => changed.sites[1].length = 5,
            2 => changed.sites[0].pc -= 1,
            3 => changed.sites[1].snapshot = addr(BASE, 4095).unwrap(),
            4 => changed.sites[0].function = addr(BASE, 4095).unwrap(),
            5 => changed.sites[0].semantics = HookSemantics::ReplaceFirst,
            6 => changed.sites[1].semantics = HookSemantics::ReplaceFirst,
            7 => changed.sites[0].provenance = ContentId::of(b"wrong original provenance"),
            8 => {
                for site in &mut changed.sites {
                    site.heads.retain(|h| h.address != F);
                }
            }
            9 => {
                for site in &mut changed.sites {
                    site.heads.retain(|h| h.address != E);
                }
            }
            10 => {
                for site in &mut changed.sites {
                    site.heads.retain(|h| h.address != 0x401bbe);
                }
            }
            11 => {
                for site in &mut changed.sites {
                    site.heads.retain(|h| h.address != 0x401c45);
                }
            }
            _ => {
                let mut extra = changed.sites[0].clone();
                extra.id = 3;
                extra.pc = F + 1;
                extra.length = 1;
                changed.sites.push(extra);
            }
        }
        assert!(
            routed_jmp::eligibility(&elf, &changed, &changed.sites[0], &changed.sites[1]).is_err()
        );
    }
    for kind in 0..3 {
        let mut bad = Mixed::new(&frozen::PRIMARY);
        let needle = "head 4201474 4c89e7\n";
        assert!(bad.fixture.ledger.contains(needle));
        bad.fixture.ledger = match kind {
            0 => bad.fixture.ledger.replace(needle, ""),
            1 => bad
                .fixture
                .ledger
                .replace(needle, &(needle.to_owned() + needle)),
            _ => bad.fixture.ledger.replace(
                "head 4201472 eb43\nhead 4201474 4c89e7\n",
                "head 4201474 4c89e7\nhead 4201472 eb43\n",
            ),
        };
        rebind_original(&mut bad);
        assert!(bad.bind_policy(&bad.fixture.policy).is_err());
    }
}
#[test]
fn rj14_real_loader_write_over_suffix_refuses_after_core_acceptance() {
    let mut m = Mixed::new(&frozen::PRIMARY);
    complete_mixed(&m, &[1, 2]);
    m.fixture.original.resize(12288, 0);
    put16(&mut m.fixture.original, 56, 3);
    put32(&mut m.fixture.original, 120, 1);
    put32(&mut m.fixture.original, 124, 6);
    for (at, value) in [
        (128, 8192),
        (136, 0x460000),
        (144, 0x460000),
        (152, 4096),
        (160, 4096),
        (168, 4096),
    ] {
        put64(&mut m.fixture.original, at, value);
    }
    put32(&mut m.fixture.original, 176, 2);
    put32(&mut m.fixture.original, 180, 6);
    for (at, value) in [
        (184, 0x2200),
        (192, 0x460200),
        (200, 0x460200),
        (208, 64),
        (216, 64),
        (224, 8),
    ] {
        put64(&mut m.fixture.original, at, value);
    }
    for (i, (tag, value)) in [(7, 0x460800), (8, 24), (9, 24)].into_iter().enumerate() {
        put64(&mut m.fixture.original, 0x2200 + i * 16, tag);
        put64(&mut m.fixture.original, 0x2208 + i * 16, value);
    }
    put64(&mut m.fixture.original, 0x2800, F);
    put64(&mut m.fixture.original, 0x2808, 10);
    put64(&mut m.fixture.original, 0x2810, 0x1234);
    rebind_original(&mut m);
    let (_, d) = m.planned();
    assert_eq!(d.routed.work.len(), 1);
    assert!(
        d.routed.work[0]
            .result
            .as_ref()
            .unwrap()
            .evidence()
            .accepted
    );
    assert_eq!(
        d.routed.work[0].frontend_refusal.as_ref().unwrap().stage,
        "source-relocation"
    );
    assert!(!d.routed.work[0].committed);
    assert!(d.accepted.is_empty());
    assert_eq!(d.pending.len(), 2);
    no_candidate(&m.run(), &[1, 2]);
}

#[test]
fn rj06_original_greedy_chains_preserve_groups_and_one_family_calls() {
    for n in [3, 4] {
        let mut code = Vec::new();
        let mut lengths = Vec::new();
        for i in 0..n {
            code.extend_from_slice(&[0x75, ((n - i - 1) * 2) as u8]);
            lengths.push(2);
        }
        code.extend_from_slice(&[0x69, 0xc0, 1, 0, 0, 0, 0xc3]);
        lengths.extend([6, 1]);
        let f = Fixture::source(B - 1, &code, &lengths, H128, LOW);
        let old = f.planned();
        let m = union_fixture(f);
        let (_, new) = m.planned();
        assert_eq!(
            new.baseline.iter().map(|b| b.id).collect::<Vec<_>>(),
            (1..=n as u64).rev().collect::<Vec<_>>()
        );
        assert_eq!(new.edges.len(), n - 1);
        assert_eq!(new.edges.iter().filter(|e| e.visited_group).count(), n / 2);
        assert_eq!(
            new.edges
                .iter()
                .map(|e| (e.lower, e.upper, e.visited_group))
                .collect::<Vec<_>>(),
            old.edges
                .iter()
                .map(|e| (e.lower, e.upper, e.visited_group))
                .collect::<Vec<_>>()
        );
        assert_eq!(new.work.len(), old.work.len());
        assert_eq!(new.routed.calls.len(), old.work.len());
        assert!(new.routed.work.is_empty());
        assert!(
            new.routed
                .calls
                .iter()
                .all(|c| c.family == PairKind::ForwardJcc)
        );
        assert_eq!(format!("{:?}", new.baseline), format!("{:?}", old.baseline));
        assert_eq!(new.composition, old.composition);
        assert_eq!(new.pending, old.pending);
        assert_eq!(new.reports.len(), n);
    }
}
