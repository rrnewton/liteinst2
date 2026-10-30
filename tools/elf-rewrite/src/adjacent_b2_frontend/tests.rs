//! Prospective controls. Every positive is a required actual artifact outcome.
use super::*;
use li2core::quiescent::{PairOutcome, PairStage};
use std::fmt::Write as _;

const B: u64 = 0x1000_06f9;
const H0: u64 = 0x11c0_7000;
const H128: u64 = H0 + 128;
const LOW: u64 = 0x7900_f000;
const PRIMARY: &[u8] = &[0x75, 2, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3];
fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn hex(b: &[u8]) -> String {
    ledger::hex(b)
}
fn digest(b: &[u8]) -> String {
    hex(&ContentId::of(b).0)
}
fn text(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap()
}
fn image_eq(a: &ArtifactPlan, b: &ArtifactPlan) {
    assert_eq!(a.source_steps(), b.source_steps());
    let a: Vec<_> = a.images().collect();
    let b: Vec<_> = b.images().collect();
    assert_eq!(a.len(), b.len());
    for (a, b) in a.iter().zip(&b) {
        assert_eq!(a.address(), b.address());
        assert_eq!(a.bytes(), b.bytes());
        assert_eq!(a.entry_routes(), b.entry_routes());
        assert_eq!(a.instruction_boundaries(), b.instruction_boundaries());
        assert_eq!(a.program_counter_mappings(), b.program_counter_mappings());
        assert_eq!(a.metadata(), b.metadata());
        assert!(!a.metadata().qualification_complete());
    }
}
fn report_eq(a: &SiteReport, b: &SiteReport) {
    assert_eq!(
        (a.id, a.pc, a.file_offset, a.length),
        (b.id, b.pc, b.file_offset, b.length)
    );
    assert_eq!(a.core_tactic, b.core_tactic);
    assert_eq!(a.candidate_emitted, b.candidate_emitted);
    assert_eq!(a.refusal, b.refusal);
    assert_eq!(a.refusal_code, b.refusal_code);
    assert_eq!(a.diagnostics, b.diagnostics);
}
fn draft_eq(a: &SelectionDraft, b: &SelectionDraft) {
    assert_eq!(a.composition, b.composition);
    assert_eq!(a.pending, b.pending);
    assert_eq!(a.occupied, b.occupied);
    assert_eq!(a.dependencies, b.dependencies);
    assert_eq!(
        (a.image_count, a.image_bytes, a.allocation_pages),
        (b.image_count, b.image_bytes, b.allocation_pages)
    );
    assert_eq!(a.totals, b.totals);
    assert_eq!(a.blocked_groups, b.blocked_groups);
    assert_eq!(a.reports.len(), b.reports.len());
    for (a, b) in a.reports.iter().zip(&b.reports) {
        report_eq(a, b);
    }
    assert_eq!(a.accepted.len(), b.accepted.len());
    for ((aid, a), (bid, b)) in a.accepted.iter().zip(&b.accepted) {
        assert_eq!(aid, bid);
        image_eq(a, b);
    }
    assert_eq!(format!("{:?}", a.baseline), format!("{:?}", b.baseline));
    assert_eq!(format!("{:?}", a.edges), format!("{:?}", b.edges));
    assert_eq!(format!("{:?}", a.work), format!("{:?}", b.work));
}
#[derive(Clone)]
struct Fixture {
    original: Vec<u8>,
    ledger: String,
    policy: String,
    base: u64,
}
impl Fixture {
    fn source(
        base: u64,
        code: &[u8],
        lengths: &[usize],
        upper_target: u64,
        lower_target: u64,
    ) -> Self {
        assert_eq!(lengths.iter().sum::<usize>(), code.len());
        let page = base & !4095;
        let offset = (base - page) as usize;
        let mut original = vec![0; 4096];
        original[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        put16(&mut original, 16, 2);
        put16(&mut original, 18, 62);
        put32(&mut original, 20, 1);
        put64(&mut original, 24, base);
        put64(&mut original, 32, 64);
        put16(&mut original, 52, 64);
        put16(&mut original, 54, 56);
        put16(&mut original, 56, 1);
        put32(&mut original, 64, 1);
        put32(&mut original, 68, 5);
        put64(&mut original, 80, page);
        put64(&mut original, 88, page);
        put64(&mut original, 96, 4096);
        put64(&mut original, 104, 4096);
        put64(&mut original, 112, 4096);
        original[offset..offset + code.len()].copy_from_slice(code);
        let mut ledger = format!(
            "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {base} {offset} {}\n",
            digest(&original),
            code.len()
        );
        let mut pc = base;
        let mut at = 0;
        for &n in lengths {
            writeln!(ledger, "head {pc} {}", hex(&code[at..at + n])).unwrap();
            at += n;
            pc += n as u64;
        }
        let imported = disassembly::import(
            &original,
            ledger.as_bytes(),
            ContentId::of(ledger.as_bytes()),
        )
        .unwrap();
        let mut offset = 0;
        let mut hook = None;
        for &n in lengths {
            if code[offset..offset + n] == [0xc3] && hook.is_none() {
                hook = Some(base + offset as u64);
            }
            offset += n;
        }
        let hook = hook.expect("original single-byte C3 fixture hook");
        let mut policy = format!(
            "LI2DISASM-POLICY 5\noriginal {}\nledger {}\nneighbor-victims short-only\nneighbor-ownership inherited-t3\npending-selected full-instruction-ownership\nadjacent-b2 fallback-two-site-v1\nadjacent-b2-budgets 2 1 2\ntarget fxsave64\ndomain 1\ncarrier {}\nlimits 1048576 32 32 131072 128 2097152 1048576 128 2147483648\nnull-hook {hook}\n",
            digest(&original),
            digest(ledger.as_bytes()),
            page + 4096
        );
        for site in imported.jumps() {
            let target = if site.id == 1 {
                lower_target
            } else if site.id == 2 {
                upper_target
            } else {
                0x12c0_7009
            };
            writeln!(policy, "search {} B2 0 2 1 none 0 0", site.id).unwrap();
            writeln!(
                policy,
                "allocation {} selected {target} 1 4096 {}:4096",
                site.id,
                target & !4095
            )
            .unwrap();
            writeln!(
                policy,
                "allocation {} victim {} 1 4096 {}:4096",
                site.id,
                0x15000000 + site.id * 4096,
                0x15000000 + site.id * 4096
            )
            .unwrap();
        }
        Self {
            original,
            ledger,
            policy,
            base,
        }
    }
    fn primary() -> Self {
        Self::source(B, PRIMARY, &[2, 2, 6, 1], H128, LOW)
    }
    fn prior() -> Self {
        let mut code = PRIMARY.to_vec();
        code.extend_from_slice(&[0x75, 0, 0x69, 0xc0, 2, 0, 0, 0, 0xc3]);
        Self::source(B, &code, &[2, 2, 6, 1, 2, 6, 1], H128, LOW)
    }
    fn bind(&self) -> AdjacentB2DisassemblySelection {
        self.bind_policy(&self.policy)
            .expect("frozen prospective binding")
    }
    fn bind_policy(&self, p: &str) -> Result<AdjacentB2DisassemblySelection, Error> {
        disassembly::import(
            &self.original,
            self.ledger.as_bytes(),
            ContentId::of(self.ledger.as_bytes()),
        )?
        .bind_adjacent_b2(p.as_bytes(), ContentId::of(p.as_bytes()))
    }
    fn old(&self) -> disassembly::DisassemblySelection {
        let p = self
            .policy
            .replacen("LI2DISASM-POLICY 5", "LI2DISASM-POLICY 4", 1)
            .lines()
            .filter(|l| !l.starts_with("adjacent-b2"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        disassembly::import(
            &self.original,
            self.ledger.as_bytes(),
            ContentId::of(self.ledger.as_bytes()),
        )
        .unwrap()
        .bind_short_t3_pending(p.as_bytes(), ContentId::of(p.as_bytes()))
        .unwrap()
    }
    fn replace(&mut self, from: &str, to: &str) {
        assert!(self.policy.contains(from));
        self.policy = self.policy.replacen(from, to, 1);
    }
    fn cap(&mut self, u: usize, l: usize, j: usize) {
        self.replace(
            "adjacent-b2-budgets 2 1 2",
            &format!("adjacent-b2-budgets {u} {l} {j}"),
        );
    }
    fn limits(&mut self, images: usize, bytes: usize, pages: u64, span: u64) {
        let old = self
            .policy
            .lines()
            .find(|l| l.starts_with("limits "))
            .unwrap()
            .to_owned();
        self.replace(
            &old,
            &format!("limits 1048576 32 {images} {bytes} {pages} 2097152 1048576 128 {span}"),
        );
    }
    fn run(&self) -> Product {
        prepare_disassembly_adjacent_b2(&self.original, &self.bind()).expect("prepared evidence")
    }
    fn initial(&self, s: &Selection) -> (CodeIdentity, SelectionDraft) {
        let elf = Elf64::parse(
            &self.original,
            ParseLimits {
                max_program_headers: s.limits.program_headers,
            },
        )
        .unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity(s.original.0),
            mapping: s.bias_domain,
            generation: 1,
        };
        let composition =
            Composition::new(identity, original_snapshots(&elf, &s.sites).unwrap()).unwrap();
        let mut occupied = Vec::new();
        for l in elf.segments(SegmentType::Load) {
            if l.memory_size != 0 {
                let end = round_page(l.vaddr.0 + l.memory_size).unwrap();
                occupied.push(addr(l.vaddr.0 & !4095, end - (l.vaddr.0 & !4095)).unwrap());
            }
        }
        occupied.push(
            addr(
                s.carrier_pc,
                round_page(s.limits.program_headers as u64 * 56 + 128).unwrap(),
            )
            .unwrap(),
        );
        let pending = s
            .sites
            .iter()
            .enumerate()
            .map(|(i, s)| (i, addr(s.pc, u64::from(s.length)).unwrap()))
            .collect();
        let dependencies = s
            .hooks
            .iter()
            .map(|h| translate(&elf, h.pc, h.length as u64).unwrap())
            .collect();
        let reports = s
            .sites
            .iter()
            .map(|s| SiteReport {
                id: s.id,
                pc: s.pc,
                file_offset: s.file_offset,
                length: s.length,
                core_tactic: None,
                candidate_emitted: false,
                refusal: None,
                refusal_code: None,
                diagnostics: String::new(),
            })
            .collect();
        (
            identity,
            SelectionDraft {
                composition,
                pending,
                reports,
                accepted: Vec::new(),
                occupied,
                dependencies,
                image_count: 0,
                image_bytes: 0,
                allocation_pages: 0,
                baseline: Vec::new(),
                work: Vec::new(),
                edges: Vec::new(),
                totals: Resources::default(),
                blocked_groups: Vec::new(),
                routed: Default::default(),
            },
        )
    }
    fn planned(&self) -> SelectionDraft {
        let selected = self.bind();
        let s = &selected.base.selection;
        let elf = Elf64::parse(
            &self.original,
            ParseLimits {
                max_program_headers: s.limits.program_headers,
            },
        )
        .unwrap();
        let dynamic = carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default()).unwrap();
        let (identity, mut draft) = self.initial(s);
        let mut ordered: Vec<_> = (0..s.sites.len()).collect();
        ordered.sort_by_key(|&i| std::cmp::Reverse(s.sites[i].pc));
        plan(
            &elf,
            &dynamic,
            s,
            identity,
            selected.limits,
            &ordered,
            &mut draft,
        )
        .unwrap();
        draft
    }
}
fn complete(f: &Fixture, ids: &[u64]) -> Product {
    let p = f.run();
    assert!(p.candidate_complete(), "required whole-selection positive");
    assert!(!p.qualification_complete());
    assert_eq!(p.reports().iter().map(|r| r.id).collect::<Vec<_>>(), ids);
    assert!(
        p.reports()
            .iter()
            .all(|r| r.candidate_emitted && r.refusal.is_none())
    );
    for name in [
        "candidate.elf",
        "source.li2sparse",
        "metadata.li2meta",
        "plan-ledger.tsv",
    ] {
        assert!(p.files().contains_key(name));
    }
    // Separate baseline control, never a retry inside the production attempt.
    let baseline = baseline_draft(f);
    for (id, _) in &baseline.accepted {
        let prior = baseline.reports.iter().find(|r| r.id == *id).unwrap();
        let now = p.reports().iter().find(|r| r.id == *id).unwrap();
        assert!(now.candidate_emitted, "successful baseline ID must survive");
        assert_eq!(
            (prior.pc, prior.file_offset, prior.length),
            (now.pc, now.file_offset, now.length)
        );
    }
    p
}
fn no_candidate(p: &Product, ids: &[u64]) {
    assert!(!p.candidate_complete());
    assert!(!p.qualification_complete());
    assert_eq!(p.reports().iter().map(|r| r.id).collect::<Vec<_>>(), ids);
    assert!(
        p.reports()
            .iter()
            .all(|r| !r.candidate_emitted && r.refusal.is_some())
    );
    for name in p.files().keys() {
        assert!(!name.starts_with("image-"));
        assert!(!["candidate.elf", "source.li2sparse", "plan-ledger.tsv"].contains(&name.as_str()));
    }
    assert!(text(&p.files()["ledger.tsv"]).starts_with("LI2ADJACENT-NO-CANDIDATE\t1\n"));
}
fn pair(d: &SelectionDraft) -> &AdjacentB2ArtifactPlan {
    assert_eq!(d.work.len(), 1);
    assert!(d.work[0].committed);
    assert!(d.work[0].frontend_refusal.is_none());
    d.work[0].result.as_ref().unwrap()
}
fn singleton(
    f: &Fixture,
    s: &Selection,
    draft: &SelectionDraft,
    index: usize,
    target: u64,
) -> ArtifactPlan {
    let elf = Elf64::parse(
        &f.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let site = &s.sites[index];
    let identity = CodeIdentity {
        source: SourceIdentity(s.original.0),
        mapping: s.bias_domain,
        generation: 1,
    };
    let e = entries(site, identity);
    let mut allocation = site.selected_allocation.clone();
    allocation.preferred_address = Some(target);
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(s.target, s.bias_domain).unwrap(),
        SymbolicHook {
            identity: site.hook,
            address: Some(s.hooks.iter().find(|h| h.id == site.hook).unwrap().pc),
        },
        draft.occupied.clone(),
    );
    let request = ArtifactRequest {
        site: PlanningSite {
            identity,
            code: elf
                .executable_bytes(ElfVaddr(site.snapshot.start()), site.snapshot.len())
                .unwrap(),
            base_address: site.snapshot.start(),
            function: site.function,
            block: addr(site.pc, 2).unwrap(),
            logical_pc: site.pc,
            entries: &e,
            semantics: site.semantics,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::GeneralizedPunOnly,
                max_upstream_bytes: 0,
                max_displaced_bytes: 2,
                max_sites: 1,
            },
        },
        emission: &emission,
    };
    let out = engine::plan_with_emission_after(
        &request,
        &draft.composition,
        &allocation,
        EnginePolicy {
            forced: Some(Tactic::GeneralizedPun),
            ..EnginePolicy::default()
        },
    )
    .expect("independent fixed-target singleton must succeed");
    assert_eq!(out.images().next().unwrap().address(), target);
    out
}
fn append_oracle(d: &mut SelectionDraft, id: u64, p: ArtifactPlan) {
    for step in p.source_steps() {
        d.composition.append(step).unwrap();
        d.occupied
            .extend(step.parts().allocations.iter().map(|a| a.range));
    }
    d.accepted.push((id, p));
}
fn independent_pair(f: &Fixture, upper: u64, lower: u64) -> (ArtifactPlan, ArtifactPlan) {
    let selected = f.bind();
    let s = &selected.base.selection;
    let (_, mut d) = f.initial(s);
    // The authored preceding selected operation is planned at its fixed target.
    if s.sites.len() == 3 {
        let prior = singleton(f, s, &d, 2, 0x12c07009);
        append_oracle(&mut d, 3, prior);
    }
    let a = singleton(f, s, &d, 1, upper);
    append_oracle(&mut d, 2, a.clone());
    let b = singleton(f, s, &d, 0, lower);
    (a, b)
}

#[test]
fn f02_f03_f08_primary_full_candidate_and_literal_cap1_baseline() {
    let f = Fixture::primary();
    let d = f.planned();
    let pair = pair(&d);
    assert_eq!(
        pair.evidence().counts,
        PairCounts {
            upper: 2,
            lower: 1,
            joint: 2
        }
    );
    assert_eq!(pair.evidence().lower_schedules.len(), 2);
    assert!(pair.evidence().lower_schedules[0].targets.is_empty());
    assert_eq!(pair.evidence().lower_schedules[1].targets, [LOW]);
    assert!(pair.evidence().events.iter().any(|e|e.stage==PairStage::LowerSchedule && e.outcome==PairOutcome::EmptySchedule));
    assert_eq!(
        d.composition.final_bytes()[0].bytes,
        [0xe9, 2, 0xe9, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3]
    );
    assert_eq!(d.composition.locks(), [addr(B, 7).unwrap()]);
    assert_eq!(
        d.accepted.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [2, 1]
    );
    let (a, b) = independent_pair(&f, H0, LOW);
    image_eq(&pair.members()[0], &a);
    image_eq(&pair.members()[1], &b);
    let old = f.old();
    assert!(
        old.selection
            .sites
            .iter()
            .all(|s| s.selected_allocation.max_candidates == 1)
    );
    assert_eq!(d.baseline.len(), 2);
    let old_upper = d.baseline[0].result.as_ref().unwrap();
    assert_eq!(old_upper.images().next().unwrap().address(), H128);
    assert_eq!(
        d.baseline[1].result.as_ref().unwrap_err().reason,
        Refusal::AllocationUnavailable
    );
    assert_eq!(d.work[0].baseline_reports[0].id, 2);
    assert!(d.work[0].baseline_reports[0].refusal.is_none());
    assert!(d.accepted.iter().any(|(id, _)| *id == 2));
    let p = complete(&f, &[1, 2]);
    assert_eq!(
        &p.files()["candidate.elf"][0x6f9..0x704],
        &[0xe9, 2, 0xe9, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3]
    );
    assert!(text(&p.files()["ledger.tsv"]).contains("new_load_pages\t3\n"));
}

#[test]
fn f04_f08_real_predecessor_retains_every_association() {
    let f = Fixture::prior();
    let d = f.planned();
    let p = pair(&d);
    assert_eq!(
        d.accepted.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [3, 2, 1]
    );
    let prior = d.baseline[0].result.as_ref().unwrap();
    assert_eq!(d.baseline[0].id, 3);
    image_eq(&d.accepted[0].1, prior);
    assert_eq!(prior.images().next().unwrap().address(), 0x12c07009);
    assert!(d.occupied.contains(&addr(0x12c07000, 4096).unwrap()));
    assert_eq!(d.totals.steps, 3);
    assert_eq!(d.totals.mappings, 3);
    assert_eq!(d.totals.virtual_bytes, 12288);
    assert_eq!(d.totals.backing_bytes, 12288);
    assert_eq!(
        p.evidence().counts,
        PairCounts {
            upper: 2,
            lower: 1,
            joint: 2
        }
    );
    assert_eq!(
        d.composition.originals()[0].bytes,
        &f.original[0x6f9..0x70d]
    );
    let (a, b) = independent_pair(&f, H0, LOW);
    image_eq(&p.members()[0], &a);
    image_eq(&p.members()[1], &b);
    let complete = complete(&f, &[1, 2, 3]);
    assert!(text(&complete.files()["ledger.tsv"]).contains("new_load_pages\t4\n"));
}

#[test]
fn f06_first_upper_fit_refusal_is_retained() {
    let mut f = Fixture::source(0x10000679, PRIMARY, &[2, 2, 6, 1], 0x11c06f80, 0x7980f000);
    // Preferred address is outside its unchanged complete permit, as in core control.
    f.replace(
        &format!(
            "allocation 2 selected {} 1 4096 {}:4096",
            0x11c06f80_u64, 0x11c06000_u64
        ),
        &format!("allocation 2 selected {} 1 4096 {H0}:4096", 0x11c06f80_u64),
    );
    f.cap(2, 1, 1);
    let d = f.planned();
    let p = pair(&d);
    assert_eq!(
        p.evidence().counts,
        PairCounts {
            upper: 2,
            lower: 1,
            joint: 1
        }
    );
    let events: Vec<_> = p
        .evidence()
        .events
        .iter()
        .filter(|e| e.stage == PairStage::UpperLeaf && e.search.is_some())
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].upper_target, Some(0x11c06f80));
    assert_eq!(
        events[0].outcome,
        PairOutcome::Refused(Refusal::AllocationUnavailable)
    );
    assert_eq!(
        d.composition.final_bytes()[0].bytes,
        [0xe9, 0x82, 0xe9, 0x80, 0x69, 0xc0, 1, 0, 0, 0, 0xc3]
    );
    let (a, b) = independent_pair(&f, H0, 0x7980f000);
    image_eq(&p.members()[0], &a);
    image_eq(&p.members()[1], &b);
    complete(&f, &[1, 2]);
}

#[test]
fn f07_frontend_aggregate_recovery_has_its_own_complete_envelope() {
    let code = [0x75, 2, 0x75, 0, 0x69, 0xc0, 0xff, 0, 0, 0, 0xc3];
    let upper = 0x0fc07000_u64;
    let mut f = Fixture::source(B, &code, &[2, 2, 6, 1], upper + 1, LOW + 0x10000);
    f.cap(2, 2, 2);
    let row = format!(
        "allocation 1 selected {} 1 4096 {}:4096",
        LOW + 0x10000,
        LOW + 0x10000
    );
    f.replace(&row, &format!("{row} {LOW}:4096"));
    f.limits(32, 131072, 128, 0x69409000);
    assert_eq!(LOW + 0x11000 - upper, 0x69419000);
    assert_eq!(LOW + 0x1000 - upper, 0x69409000);
    assert!(upper < B && B < LOW);
    let d = f.planned();
    let p = pair(&d);
    assert!(
        d.work[0]
            .baseline_reports
            .iter()
            .all(|r| r.refusal.is_none()),
        "new hull admission must not relabel legacy successes"
    );
    assert_eq!(
        d.work[0].group_admission_refusal.as_ref().unwrap().stage,
        "whole-budget"
    );
    assert_eq!(
        p.evidence().counts,
        PairCounts {
            upper: 2,
            lower: 2,
            joint: 2
        }
    );
    let events: Vec<_> = p
        .evidence()
        .events
        .iter()
        .filter(|e| e.stage == PairStage::Aggregate)
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].outcome,
        PairOutcome::Refused(Refusal::AllocationUnavailable)
    );
    assert_eq!(events[1].outcome, PairOutcome::LocalAccepted);
    assert_eq!(events[0].upper_target, Some(upper + 1));
    assert_eq!(events[0].lower_target, Some(LOW + 0x10000));
    assert_eq!(events[1].upper_target, Some(upper));
    assert_eq!(events[1].lower_target, Some(LOW));
    assert_eq!(
        d.composition.final_bytes()[0].bytes,
        [0xe9, 2, 0xe9, 0, 0x69, 0xc0, 0xff, 0, 0, 0, 0xc3]
    );
    let (a, b) = independent_pair(&f, upper, LOW);
    image_eq(&p.members()[0], &a);
    image_eq(&p.members()[1], &b);
    let p = complete(&f, &[1, 2]);
    assert!(text(&p.files()["ledger.tsv"]).contains("new_load_pages\t3\n"));
    let mut limited = f.clone();
    limited.replace("adjacent-b2-budgets 2 2 2", "adjacent-b2-budgets 1 2 1");
    let d = limited.planned();
    assert_eq!(d.work.len(), 1);
    assert!(!d.work[0].committed);
    assert!(
        d.work[0]
            .baseline_reports
            .iter()
            .all(|r| r.refusal.is_none())
    );
    assert_eq!(
        d.accepted.len(),
        2,
        "saved local baseline successes remain evidence"
    );
    assert_eq!(d.blocked_groups.len(), 1);
    assert_eq!(
        d.work[0].result.as_ref().unwrap_err().stop,
        PairStop::UpperScheduleBudget
    );
    let p = limited.run();
    no_candidate(&p, &[1, 2]);
    assert!(
        p.reports()
            .iter()
            .all(|r| r.refusal.as_ref().unwrap().stage == "adjacent-group-admission")
    );
}

#[test]
fn f09_independent_zeros_and_exact_boundaries_do_not_retry() {
    for (u, l, j, stop, counts) in [
        (
            0,
            1,
            0,
            PairStop::UpperImagesBudget,
            PairCounts {
                upper: 0,
                lower: 0,
                joint: 0,
            },
        ),
        (
            2,
            0,
            2,
            PairStop::LowerImagesBudget,
            PairCounts {
                upper: 0,
                lower: 0,
                joint: 0,
            },
        ),
        (
            2,
            1,
            0,
            PairStop::JointContinuationsBudget,
            PairCounts {
                upper: 0,
                lower: 0,
                joint: 0,
            },
        ),
        (
            1,
            1,
            1,
            PairStop::UpperScheduleBudget,
            PairCounts {
                upper: 1,
                lower: 0,
                joint: 1,
            },
        ),
        (
            2,
            1,
            1,
            PairStop::JointContinuationsBudget,
            PairCounts {
                upper: 1,
                lower: 0,
                joint: 1,
            },
        ),
    ] {
        let mut f = Fixture::primary();
        f.cap(u, l, j);
        let d = f.planned();
        assert_eq!(d.work.len(), 1);
        let failure = d.work[0].result.as_ref().unwrap_err();
        assert_eq!(failure.stop, stop);
        assert_eq!(failure.evidence.counts, counts);
        if u == 1 || j == 1 {
            assert_eq!(failure.unvisited_target, Some(H0));
        }
        assert_eq!(d.baseline.len(), 2);
        assert_eq!(d.accepted.len(), 1);
        no_candidate(&f.run(), &[1, 2]);
    }
    let mut invalid = Fixture::primary();
    invalid.cap(1, 1, 2);
    assert!(invalid.bind_policy(&invalid.policy).is_err());
}

fn cumulative_fixture() -> Fixture {
    let mut f = Fixture::primary();
    // Real separately selected predecessor, copied from the frozen core geometry.
    let prior = 0xe8715ffb_u64;
    let prior_page = prior & !4095;
    let file = 4096 + (prior - prior_page) as usize;
    f.original.resize(12288, 0);
    put16(&mut f.original, 56, 2);
    put32(&mut f.original, 120, 1);
    put32(&mut f.original, 124, 5);
    put64(&mut f.original, 128, 4096);
    put64(&mut f.original, 136, prior_page);
    put64(&mut f.original, 144, prior_page);
    put64(&mut f.original, 152, 8192);
    put64(&mut f.original, 160, 8192);
    put64(&mut f.original, 168, 4096);
    let code = [0x75, 0, 0x90, 0x90, 0x90, 0xc3];
    f.original[file..file + 6].copy_from_slice(&code);
    let old_original = f.ledger.lines().nth(1).unwrap().to_owned();
    f.ledger = f.ledger.replacen(
        &old_original,
        &format!("original {}", digest(&f.original)),
        1,
    );
    writeln!(f.ledger, "region {prior} {file} 6").unwrap();
    for (offset, bytes) in [
        (0, &code[0..2]),
        (2, &code[2..3]),
        (3, &code[3..4]),
        (4, &code[4..5]),
        (5, &code[5..6]),
    ] {
        writeln!(f.ledger, "head {} {}", prior + offset, hex(bytes)).unwrap();
    }
    let old = f.policy.lines().nth(1).unwrap().to_owned();
    f.replace(&old, &format!("original {}", digest(&f.original)));
    let old = f.policy.lines().nth(2).unwrap().to_owned();
    f.replace(&old, &format!("ledger {}", digest(f.ledger.as_bytes())));
    f.replace(
        &format!("carrier {}", 0x10001000_u64),
        &format!("carrier {}", prior_page + 8192),
    );
    f.replace(
        &format!("allocation 2 selected {H128}"),
        &format!("allocation 2 selected {}", H0 + 1),
    );
    let row = format!("allocation 1 selected {LOW} 1 4096 {LOW}:4096");
    f.replace(
        &row,
        &format!(
            "allocation 1 selected {} 1 4096 {}:4096 {LOW}:4096",
            LOW + 0x10000,
            LOW + 0x10000
        ),
    );
    writeln!(f.policy, "search 3 B2 0 2 1 none 0 0").unwrap();
    writeln!(
        f.policy,
        "allocation 3 selected {} 1 4096 {}:4096",
        LOW + 0x10000,
        LOW + 0x10000
    )
    .unwrap();
    writeln!(
        f.policy,
        "allocation 3 victim 352321536 1 4096 352321536:4096"
    )
    .unwrap();
    f.cap(2, 2, 2);
    f.limits(32, 131072, 128, 4294967296);
    f
}
#[test]
fn f07_cumulative_lower_work_uses_real_selected_predecessor() {
    let f = cumulative_fixture();
    let d = f.planned();
    let p = pair(&d);
    assert_eq!(d.accepted[0].0, 3);
    assert_eq!(
        d.accepted[0].1.images().next().unwrap().address(),
        LOW + 0x10000
    );
    assert_eq!(
        p.evidence().counts,
        PairCounts {
            upper: 2,
            lower: 2,
            joint: 2
        }
    );
    let calls: Vec<_> = p
        .evidence()
        .events
        .iter()
        .filter(|e| e.stage == PairStage::LowerLeaf)
        .collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].lower_target, Some(LOW + 0x10000));
    assert_eq!(
        calls[0].outcome,
        PairOutcome::Refused(Refusal::AllocationUnavailable)
    );
    assert_eq!(calls[1].lower_target, Some(LOW));
    assert_eq!(
        calls[1].counters_before,
        PairCounts {
            upper: 2,
            lower: 1,
            joint: 2
        }
    );
    complete(&f, &[1, 2, 3]);
    let mut limited = f.clone();
    limited.replace("adjacent-b2-budgets 2 2 2", "adjacent-b2-budgets 2 1 2");
    let d = limited.planned();
    let e = d.work[0].result.as_ref().unwrap_err();
    assert_eq!(e.stop, PairStop::LowerImagesBudget);
    assert_eq!(
        e.evidence.counts,
        PairCounts {
            upper: 1,
            lower: 1,
            joint: 1
        }
    );
    no_candidate(&limited.run(), &[1, 2, 3]);
}

#[test]
fn f10_public_limits_include_predecessor_and_carrier_page() {
    let f = Fixture::prior();
    let s = f.bind().base.selection;
    let (_, initial) = f.initial(&s);
    let prior = singleton(&f, &s, &initial, 2, 0x12c07009);
    let (a, b) = independent_pair(&f, H0, LOW);
    let bytes = [&prior, &a, &b]
        .into_iter()
        .flat_map(|p| p.images())
        .map(|i| i.bytes().len())
        .sum::<usize>();
    let mut exact = f.clone();
    exact.limits(3, bytes, 4, 2147483648);
    let p = complete(&exact, &[1, 2, 3]);
    assert!(text(&p.files()["ledger.tsv"]).contains("new_load_pages\t4\n"));
    let d = exact.planned();
    assert_eq!(d.image_count, 3);
    assert_eq!(d.image_bytes, bytes);
    assert_eq!(d.allocation_pages, 3);
    assert_eq!(d.totals.virtual_bytes, 12288);
    assert_eq!(d.totals.backing_bytes, 12288);
    let caps = Capacities::from_selection(&exact.bind().base.selection).unwrap();
    assert_eq!(caps.steps, 6);
    assert_eq!(caps.mappings, 3);
    assert_eq!(caps.virtual_bytes, 16384);
    assert_eq!(caps.backing_bytes, 16384);
    assert_eq!(d.totals.pair_budget(caps, 2).unwrap().bundle.max_steps, 2);
    for (images, payload, pages) in [(2, bytes, 4), (3, bytes - 1, 4), (3, bytes, 3)] {
        let mut limited = f.clone();
        limited.limits(images, payload, pages, 2147483648);
        let d = limited.planned();
        assert_eq!(d.work.len(), 1);
        let product = limited.run();
        no_candidate(&product, &[1, 2, 3]);
        if pages == 3 {
            assert!(d.work[0].committed, "planning pages are not carrier pages");
            assert!(
                product
                    .reports()
                    .iter()
                    .all(|r| r.refusal.as_ref().unwrap().stage == "carrier")
            );
        } else if payload < bytes {
            assert!(d.work[0].result.is_ok());
            assert_eq!(
                d.work[0].frontend_refusal.as_ref().unwrap().stage,
                "aggregate-budget"
            );
        } else {
            assert_eq!(
                d.work[0].result.as_ref().unwrap_err().stage,
                PairStage::Aggregate
            );
        }
    }
}

#[test]
fn f11_whole_generated_hull_and_carrier_hull_are_terminal() {
    let mut f = Fixture::prior();
    // Preserve the primary pair, move only the real predecessor's original
    // immediate to ff and its prospectively declared target below the pair.
    let at = 0x6f9 + 11 + 4;
    f.original[at] = 0xff;
    f.ledger = f.ledger.replace("69c002000000", "69c0ff000000");
    let old = f.ledger.lines().nth(1).unwrap().to_owned();
    f.ledger = f
        .ledger
        .replacen(&old, &format!("original {}", digest(&f.original)), 1);
    let old = f.policy.lines().nth(1).unwrap().to_owned();
    f.replace(&old, &format!("original {}", digest(&f.original)));
    let old = f.policy.lines().nth(2).unwrap().to_owned();
    f.replace(&old, &format!("ledger {}", digest(f.ledger.as_bytes())));
    f.replace(
        &format!(
            "allocation 3 selected {} 1 4096 {}:4096",
            0x12c07009_u64, 0x12c07000_u64
        ),
        &format!(
            "allocation 3 selected {} 1 4096 {}:4096",
            0x0fc07009_u64, 0x0fc07000_u64
        ),
    );
    f.limits(32, 131072, 128, 0x67409000);
    let d = f.planned();
    assert_eq!(d.work.len(), 1);
    let p = d.work[0].result.as_ref().unwrap();
    assert!(p.evidence().accepted);
    assert_eq!(p.memory().virtual_span, 0x67409000);
    assert_eq!(
        d.work[0].frontend_refusal.as_ref().unwrap().stage,
        "whole-budget"
    );
    assert!(!d.work[0].committed);
    assert!(d.accepted.iter().any(|(id, _)| *id == 3));
    no_candidate(&f.run(), &[1, 2, 3]);
    let mut carrier = Fixture::primary();
    carrier.limits(32, 131072, 128, 0x67409000);
    let d = carrier.planned();
    assert!(pair(&d).evidence().accepted);
    let p = carrier.run();
    no_candidate(&p, &[1, 2]);
    assert!(
        p.reports()
            .iter()
            .all(|r| r.refusal.as_ref().unwrap().stage == "carrier")
    );
    assert_eq!(LOW + 4096 - 0x10000000, 0x69010000);
}

#[test]
fn f17_f18_full_draft_rollback_after_actual_pair_stages() {
    let f = Fixture::primary();
    let selected = f.bind();
    let s = &selected.base.selection;
    let elf = Elf64::parse(
        &f.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let dynamic = carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default()).unwrap();
    let (identity, before) = f.initial(s);
    let p = call_pair(&elf, s, identity, selected.limits, &before, 0, 1)
        .unwrap()
        .unwrap();
    for point in ["upper-appended", "both-appended", "associations-built"] {
        let saved = before.clone();
        let mut reached = false;
        let result = stage_pair(
            &elf,
            &dynamic,
            s,
            &before,
            PairAssociation {
                lower: 0,
                upper: 1,
                attempt: 0,
            },
            &p,
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
        draft_eq(&before, &saved);
    }
    let mut limited = f.clone();
    limited.cap(1, 1, 1);
    let actual = limited.planned();
    let mut expected = before.clone();
    baseline(&elf, &dynamic, s, identity, &mut expected, 1).unwrap();
    baseline(&elf, &dynamic, s, identity, &mut expected, 0).unwrap();
    // Pair evidence is the sole addition after restoring the exact baseline state.
    let mut projected = actual.clone();
    projected.work.clear();
    projected.edges.clear();
    draft_eq(&projected, &expected);
    assert_eq!(actual.accepted.len(), 1);
    assert_eq!(actual.accepted[0].0, 2);
    assert!(actual.pending.iter().any(|(i, _)| *i == 0));
    assert!(!actual.pending.iter().any(|(i, _)| *i == 1));
    assert_eq!(actual.baseline.len(), 2);
}

#[test]
fn f19_later_selected_failure_discards_whole_artifact() {
    let mut f = Fixture::prior();
    // An earlier-address original jump is attempted after the admitted prior+pair.
    let pc = 0x10000300_u64;
    f.original[0x300..0x302].copy_from_slice(&[0xeb, 0xfe]);
    let original_line = f.ledger.lines().nth(1).unwrap().to_owned();
    f.ledger = f.ledger.replacen(
        &original_line,
        &format!("original {}", digest(&f.original)),
        1,
    );
    let insertion = format!("region {pc} 768 2\nhead {pc} ebfe\n");
    let pivot = format!("region {B}");
    f.ledger = f.ledger.replacen(&pivot, &format!("{insertion}{pivot}"), 1);
    let original_line = f.policy.lines().nth(1).unwrap().to_owned();
    f.replace(&original_line, &format!("original {}", digest(&f.original)));
    let ledger_line = f.policy.lines().nth(2).unwrap().to_owned();
    f.replace(
        &ledger_line,
        &format!("ledger {}", digest(f.ledger.as_bytes())),
    );
    // IDs are the importer order, not the pair API order.
    let mut rows = Vec::new();
    for row in f.policy.lines() {
        let mut fields: Vec<String> = row.split(' ').map(str::to_owned).collect();
        if matches!(fields[0].as_str(), "search" | "allocation") {
            fields[1] = (fields[1].parse::<u64>().unwrap() + 1).to_string();
        }
        rows.push(fields.join(" "));
    }
    f.policy = rows.join("\n") + "\n";
    f.policy.push_str("search 1 B2 0 2 1 none 0 0\nallocation 1 selected 352325632 1 4096 352325632:4096\nallocation 1 victim 352329728 1 4096 352329728:4096\n");
    let d = f.planned();
    assert_eq!(
        d.baseline.iter().map(|b| b.id).collect::<Vec<_>>(),
        [4, 3, 2, 1]
    );
    assert_eq!(
        d.accepted.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [4, 3, 2]
    );
    assert_eq!(pair(&d).logical_pcs(), [B + 2, B]);
    let product = f.run();
    no_candidate(&product, &[1, 2, 3, 4]);
    assert!(
        product.reports()[1..]
            .iter()
            .all(|r| r.refusal_code == Some(10_003))
    );
    assert!(text(&product.files()["adjacent-b2-evidence.txt"]).contains("committed: true"));
}

#[test]
fn f21_f25_member_bindings_and_remaining_authority_are_exact() {
    let f = Fixture::prior();
    let d = f.planned();
    let p = pair(&d);
    assert_eq!(p.logical_pcs(), [B + 2, B]);
    assert_eq!((d.work[0].lower, d.work[0].upper), (1, 2));
    for (ordinal, id) in [2_u64, 1].into_iter().enumerate() {
        let report = &d.reports[(id - 1) as usize];
        assert!(
            report
                .diagnostics
                .contains(&format!("adjacent_attempt=0 member={ordinal}"))
        );
        assert!(report.diagnostics.contains(&format!("selected_id={id}")));
        assert!(
            report
                .diagnostics
                .contains(&format!("image_start={}", ordinal + 1))
        );
        assert!(matches!(
            p.members()[ordinal].metrics(),
            ArtifactMetrics::Single(_)
        ));
        assert!(!p.members()[ordinal].qualification_complete());
        for image in p.members()[ordinal].images() {
            assert!(!image.metadata().qualification_complete());
            for requirement in [
                ArtifactRequirement::ArtifactIdentityAndAddressBinding,
                ArtifactRequirement::TargetCpuAndStateAtEntry,
                ArtifactRequirement::OriginalDynamicRelocationOwnership,
                ArtifactRequirement::OriginalImmediatePointerProvenance,
                ArtifactRequirement::HookAbiAndReadiness(1),
                ArtifactRequirement::GeneratedUnwindInformation,
                ArtifactRequirement::OriginalCodeAsDataContract,
            ] {
                assert!(image.metadata().requirements().contains(&requirement));
            }
            assert!(!image.metadata().fields().is_empty());
        }
    }
    assert!(!p.evidence().classification_complete);
    let product = complete(&f, &[1, 2, 3]);
    for name in [
        "report.tsv",
        "planning-profile.tsv",
        "disassembly-inventory.tsv",
        "bundle-index.tsv",
        "adjacent-b2-evidence.txt",
    ] {
        assert!(text(&product.files()[name]).contains("qualification_complete\tfalse\n"));
    }
}

fn baseline_draft(f: &Fixture) -> SelectionDraft {
    let old = f.old();
    let s = &old.selection;
    let elf = Elf64::parse(
        &f.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let dynamic = carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default()).unwrap();
    let (identity, mut d) = f.initial(s);
    for index in (0..s.sites.len()).rev() {
        attempt_singleton(
            SingletonContext {
                elf: &elf,
                dynamic: &dynamic,
                s,
                identity,
                owned_neighbors: false,
                mode: disassembly::NeighborMode::ShortT3Pending,
                record_baseline: true,
            },
            &mut d,
            index,
        );
    }
    d.totals = Resources::collect(&d.accepted).unwrap();
    d
}
fn replace_identity(bytes: &[u8], old: ContentId, new: ContentId) -> Vec<u8> {
    let before = format!("selection_sha256\t{}\n", hex(&old.0));
    let after = format!("selection_sha256\t{}\n", hex(&new.0));
    assert_eq!(text(bytes).matches(&before).count(), 1);
    assert_eq!(text(bytes).lines().nth(2), Some(before.trim_end()));
    text(bytes).replacen(&before, &after, 1).into_bytes()
}
fn read64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
// Independent fixture/profile declarations. Do not use the new binder as an oracle.
struct ExpectedBinding {
    old_manifest: Vec<u8>,
    manifest: Vec<u8>,
    files: BTreeMap<String, Vec<u8>>,
}
fn expected_binding(f: &Fixture, old: &Product) -> ExpectedBinding {
    const OLD_PROFILE: &str = "elf-disassembly-null-jumps-short-t3-pending-v1";
    const NEW_PROFILE: &str = "elf-disassembly-null-jumps-adjacent-b2-short-t3-pending-v1";
    const FAMILY: &str = "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\n";
    const NEW_FAMILY: &str = "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\nadjacent_b2\tfallback-two-site-v1\n";
    const MODE: &str = "neighbor-victims short-only\nneighbor-ownership inherited-t3\npending-selected full-instruction-ownership\n";
    const EXTRA: &str = "adjacent-b2 fallback-two-site-v1\nadjacent-b2-budgets 2 1 2\n";
    const LIMITS: &str = "limits 1048576 32 32 131072 128 2097152 1048576 128 2147483648\n";
    assert!(old.candidate_complete());
    assert_eq!(f.base, 0x1000_06f9);
    assert_eq!(f.original.len(), 4096);
    assert_eq!(
        &f.original[0x6f9..0x704],
        &[0x75, 2, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3]
    );
    let original_id = digest(&f.original);
    assert_eq!(
        original_id,
        "8270f32b43b0d478635c0dd5248cd3b2fae9d8f9adf17c980e65816e77bbb7cb"
    );
    // Four literal verified heads, two original selected jumps, no inventory from
    // the new binder. Region/block bounds follow the prospective original bytes.
    let ledger = format!(
        "LI2DISASM 1\noriginal {original_id}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {} 1785 11\nhead {} 7502\nhead {} 7500\nhead {} 69c001000000\nhead {} c3\n",
        B,
        B,
        B + 2,
        B + 4,
        B + 10
    );
    assert_eq!(f.ledger, ledger);
    let ledger_id = digest(ledger.as_bytes());
    let placement = format!(
        "search 1 B2 0 2 1 none 0 0\nallocation 1 selected {} 1 4096 {}:4096\nallocation 1 victim {} 1 4096 {}:4096\nsearch 2 B2 0 2 1 none 0 0\nallocation 2 selected {} 1 4096 {}:4096\nallocation 2 victim {} 1 4096 {}:4096\n",
        0x7900_f000_u64,
        0x7900_f000_u64,
        0x1500_1000_u64,
        0x1500_1000_u64,
        0x11c0_7000_u64,
        0x11c0_7000_u64,
        0x1500_2000_u64,
        0x1500_2000_u64
    );
    let common = format!("target fxsave64\ndomain 1\ncarrier 268439552\n{LIMITS}");
    let old_policy = format!(
        "LI2DISASM-POLICY 4\noriginal {original_id}\nledger {ledger_id}\n{MODE}{common}null-hook {}\n{placement}",
        B + 10
    );
    let policy = format!(
        "LI2DISASM-POLICY 5\noriginal {original_id}\nledger {ledger_id}\n{MODE}{EXTRA}{common}null-hook {}\n{placement}",
        B + 10
    );
    assert_eq!(f.policy, policy);
    let mut sites = String::new();
    let mut inventory_rows = String::new();
    for (id, pc, offset) in [(1, B, 1785), (2, B + 2, 1787)] {
        writeln!(
            sites,
            "site {id} {pc} 2 {offset} {B} 11 {B} 11 {pc} 2 1 observe original-decode"
        )
        .unwrap();
        writeln!(
            sites,
            "entries {id} complete {ledger_id} {B}:0 {}:0 {}:0 {}:0",
            B + 2,
            B + 4,
            B + 10
        )
        .unwrap();
        writeln!(sites, "resumes {id} none").unwrap();
        writeln!(inventory_rows, "{id}\t{pc}\t2\t{offset}\t{B}\t11\t{pc}\t2").unwrap();
    }
    let hook_id = digest(&[0xc3]);
    let tail = format!("{common}hook 1 {} 1 {hook_id}\n{sites}{placement}", B + 10);
    let old_manifest = format!("LI2TOOL 1\noriginal {original_id}\n{MODE}{tail}").into_bytes();
    let manifest = format!("LI2TOOL 1\noriginal {original_id}\n{MODE}{EXTRA}{tail}").into_bytes();
    let old_id = ContentId::of(&old_manifest);
    let new_id = ContentId::of(&manifest);
    assert_ne!(old_id, new_id);
    // Authenticate the entire old baseline against the independent declaration
    // before allowing its unchanged carrier/image/trace bytes into the oracle.
    assert_eq!(old.files()["selection.txt"], old_manifest);
    assert_eq!(f.old().manifest(), old_manifest);
    let compatibility = Compatibility {
        planner: CONTRACT_VERSION,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&old.files()["target.tsv"]),
        binding: old_id,
    };
    let metadata = Metadata::decode(
        &old.files()["metadata.li2meta"],
        &compatibility,
        formats::Limits::default(),
    )
    .unwrap();
    metadata.verify_original(&f.original).unwrap();
    metadata.verify_selection(old_id, &[1, 2]).unwrap();
    assert!(metadata.declares_complete_trampoline_coverage());
    let inventory_tail = format!(
        "original_sha256\t{original_id}\nledger_sha256\t{ledger_id}\ncomplete_jump_count\t2\nqualification_complete\tfalse\nid\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length\n{inventory_rows}"
    );
    let old_inventory =
        format!("LI2DISASSEMBLY-INVENTORY\t1\nprofile\t{OLD_PROFILE}\n{FAMILY}{inventory_tail}");
    let inventory = format!(
        "LI2DISASSEMBLY-INVENTORY\t1\nprofile\t{NEW_PROFILE}\n{NEW_FAMILY}{inventory_tail}"
    );
    let profile_tail =
        "scope\tartifact-code-regions-not-functions\nentries\tall-verified-instruction-heads\n";
    let old_profile = format!(
        "LI2PLANNING\t1\nprofile\t{OLD_PROFILE}\n{FAMILY}{profile_tail}original_sha256\t{original_id}\nledger_sha256\t{ledger_id}\npolicy_sha256\t{}\nselection_sha256\t{}\ncomplete_jump_count\t2\nqualification_complete\tfalse\n",
        digest(old_policy.as_bytes()),
        hex(&old_id.0)
    );
    let profile = format!(
        "LI2PLANNING\t1\nprofile\t{NEW_PROFILE}\n{NEW_FAMILY}adjacent_upper\t2\nadjacent_lower\t1\nadjacent_joint\t2\n{profile_tail}original_sha256\t{original_id}\nledger_sha256\t{ledger_id}\npolicy_sha256\t{}\nselection_sha256\t{}\ncomplete_jump_count\t2\nqualification_complete\tfalse\n",
        digest(policy.as_bytes()),
        hex(&new_id.0)
    );
    for (name, bytes) in [
        ("disassembly.txt", ledger.as_bytes()),
        ("disassembly-policy.txt", old_policy.as_bytes()),
        ("disassembly-inventory.tsv", old_inventory.as_bytes()),
        ("planning-profile.tsv", old_profile.as_bytes()),
    ] {
        assert_eq!(old.files()[name], bytes, "checked old wrapper: {name}");
    }
    let files = BTreeMap::from([
        ("disassembly.txt".into(), ledger.into_bytes()),
        ("disassembly-policy.txt".into(), policy.into_bytes()),
        ("disassembly-inventory.tsv".into(), inventory.into_bytes()),
        ("planning-profile.tsv".into(), profile.into_bytes()),
    ]);
    ExpectedBinding {
        old_manifest,
        manifest,
        files,
    }
}
fn expected_files(
    f: &Fixture,
    old: &Product,
    binding: &ExpectedBinding,
    baseline: &SelectionDraft,
) -> BTreeMap<String, Vec<u8>> {
    assert!(old.candidate_complete());
    let old_selection = f.old();
    let old_id = ContentId::of(&binding.old_manifest);
    let new_id = ContentId::of(&binding.manifest);
    assert_ne!(old_id, new_id);
    let policy = Compatibility {
        planner: CONTRACT_VERSION,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&old.files()["target.tsv"]),
        binding: old_id,
    };
    let original_meta = &old.files()["metadata.li2meta"];
    let decoded = Metadata::decode(original_meta, &policy, formats::Limits::default()).unwrap();
    decoded.verify_original(&f.original).unwrap();
    decoded.verify_selection(old_id, &[1, 2]).unwrap();
    assert!(decoded.declares_complete_trampoline_coverage());
    // Independently check the literal codec, not merely a successful decode.
    assert_eq!(&original_meta[0..8], b"LI2META\0");
    assert_eq!(&original_meta[8..16], &[1, 0, 0, 0, 0, 0, 0, 0]);
    let c = read64(original_meta, 216) as usize;
    let n = read64(original_meta, 224) as usize;
    assert_eq!(c, 1);
    assert_eq!(n, 2);
    assert_eq!(original_meta.len(), 232 + 32 * c + 40 * n);
    assert_eq!(
        read64(original_meta, 16),
        176 + 32 * c as u64 + 40 * n as u64
    );
    assert_eq!(read64(original_meta, 56), f.original.len() as u64);
    assert_eq!(&original_meta[64..96], &ContentId::of(&f.original).0);
    assert_eq!(&original_meta[96..128], &old_id.0);
    assert_eq!(&original_meta[176..208], &old_id.0);
    assert_eq!(&original_meta[208..216], &[0, 0, 1, 0, 0, 0, 0, 0]);
    for (ordinal, site) in old_selection.selection.sites.iter().enumerate() {
        let at = 232 + 32 * c + ordinal * 40;
        assert_eq!(read64(original_meta, at), site.id);
        assert_eq!(read64(original_meta, at + 8), site.pc);
        assert_eq!(read64(original_meta, at + 16), site.file_offset);
        assert_eq!(original_meta[at + 24], site.length);
        assert_eq!(original_meta[at + 25], 0);
        assert!((1..=5).contains(&original_meta[at + 26]));
        assert_eq!(&original_meta[at + 27..at + 40], &[0; 13]);
    }
    let mut zero = original_meta.clone();
    zero[24..56].fill(0);
    assert_eq!(&original_meta[24..56], &ContentId::of(&zero).0);
    let mut metadata = original_meta.clone();
    metadata[96..128].copy_from_slice(&new_id.0);
    metadata[176..208].copy_from_slice(&new_id.0);
    metadata[24..56].fill(0);
    let checksum = ContentId::of(&metadata);
    metadata[24..56].copy_from_slice(&checksum.0);
    let old_plan = &old.files()["plan-ledger.tsv"];
    assert!(text(old_plan).starts_with(&format!(
        "LI2LEDGER\t1\noriginal_sha256\t{}\n",
        digest(&f.original)
    )));
    let plan = replace_identity(old_plan, old_id, new_id);
    let mut old_payload = b"LI2TOOL-CANDIDATE-UNREADY-V1\0".to_vec();
    assert_eq!(old_payload.len(), 29);
    old_payload.extend_from_slice(&ContentId::of(original_meta).0);
    old_payload.extend_from_slice(&ContentId::of(old_plan).0);
    assert_eq!(old_payload.len(), 93);
    // Frozen one-original-LOAD plus inserted PHDR, carrier, two images.
    // Offset derives from that baseline layout, never from candidate differences.
    let p = 4096 + 5 * 56;
    let old_elf = &old.files()["candidate.elf"];
    assert_eq!(&old_elf[p..p + 93], old_payload);
    assert_eq!(old_elf.windows(93).filter(|w| *w == old_payload).count(), 1);
    let parsed = Elf64::parse(
        old_elf,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let owners: Vec<_> = parsed
        .segments(SegmentType::Load)
        .filter(|load| load.offset.0 <= p as u64 && p as u64 + 93 <= load.offset.0 + load.file_size)
        .collect();
    assert_eq!(owners.len(), 1);
    assert!(owners[0].flags.readable());
    assert!(!owners[0].flags.writable());
    assert!(!owners[0].flags.executable());
    assert_eq!(owners[0].vaddr.0, 0x10001000);
    let mut elf = old_elf.clone();
    elf[p + 29..p + 61].copy_from_slice(&ContentId::of(&metadata).0);
    elf[p + 61..p + 93].copy_from_slice(&ContentId::of(&plan).0);
    assert_eq!(elf.len(), old_elf.len());
    assert_eq!(&elf[..p + 29], &old_elf[..p + 29]);
    assert_eq!(&elf[p + 93..], &old_elf[p + 93..]);
    let old_ledger = &old.files()["ledger.tsv"];
    let projected = replace_identity(old_ledger, old_id, new_id);
    let mut ledger = String::new();
    let mut carrier_count = 0;
    for row in text(&projected).lines() {
        if row.starts_with("candidate_sha256\t") {
            assert_eq!(row, format!("candidate_sha256\t{}", digest(old_elf)));
            writeln!(ledger, "candidate_sha256\t{}", digest(&elf)).unwrap();
            carrier_count += 1;
        } else if row.starts_with("elf-change\t") {
            let fields: Vec<_> = row.split('\t').collect();
            assert_eq!(fields.len(), 5);
            let offset: usize = fields[2].parse().unwrap();
            let mut replacement = unhex(fields[4]);
            assert_eq!(&old_elf[offset..offset + replacement.len()], replacement);
            for (i, byte) in replacement.iter_mut().enumerate() {
                let absolute = offset + i;
                if (p + 29..p + 93).contains(&absolute) {
                    *byte = elf[absolute];
                }
            }
            writeln!(
                ledger,
                "{}\t{}\t{}\t{}\t{}",
                fields[0],
                fields[1],
                fields[2],
                fields[3],
                hex(&replacement)
            )
            .unwrap();
        } else {
            writeln!(ledger, "{row}").unwrap();
        }
    }
    assert_eq!(carrier_count, 1);
    let mut expected = old.files().clone();
    expected.remove("bundle-index.tsv");
    expected.extend(binding.files.clone()); // independent prospective bytes only
    expected.insert("selection.txt".into(), binding.manifest.clone());
    expected.insert("metadata.li2meta".into(), metadata);
    expected.insert("candidate.elf".into(), elf);
    expected.insert("plan-ledger.tsv".into(), plan);
    expected.insert("ledger.tsv".into(), ledger.into_bytes());
    expected.insert(
        "report.tsv".into(),
        replace_identity(&old.files()["report.tsv"], old_id, new_id),
    );
    let edges = vec![Edge {
        lower: 1,
        upper: 2,
        exclusion: None,
        visited_group: true,
    }];
    let mut slots = 0;
    for baseline in &baseline.baseline {
        let ArtifactMetrics::Engine(_, _, attempts) = baseline.result.as_ref().unwrap().metrics()
        else {
            panic!("baseline engine");
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
    // Independently expected new evidence contains only the frozen baseline.
    let empty: Vec<Work> = Vec::new();
    let sidecar = format!(
        "LI2ADJACENT-EVIDENCE\t1\nselection_sha256\t{}\nselected_count\t2\nbaseline_calls\t2\npair_calls\t0\nadjacent_counts\t0\t0\t0\nqualification_complete\tfalse\nclassification_complete\tfalse\nlegacy_image_slots\t{slots}\ncombined_image_work_upper_bound\t{slots}\nresources\t{:#?}\nedges\t{:#?}\nbaseline\t{:#?}\npairs\t{:#?}\n",
        hex(&new_id.0),
        baseline.totals,
        edges,
        baseline.baseline,
        empty
    );
    expected.insert("adjacent-b2-evidence.txt".into(), sidecar.into_bytes());
    let mut index = format!(
        "LI2BUNDLE\t1\noriginal_sha256\t{}\nqualification_complete\tfalse\nconsumer_action\tRuntimeScan-while-gated-until-qualified\n",
        digest(&f.original)
    );
    for (name, bytes) in &expected {
        writeln!(index, "file\t{name}\t{}\t{}", bytes.len(), digest(bytes)).unwrap();
    }
    expected.insert("bundle-index.tsv".into(), index.into_bytes());
    expected
}
fn compare_complete(
    expected: &BTreeMap<String, Vec<u8>>,
    actual: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    if expected.keys().ne(actual.keys()) {
        return Err("file population".into());
    }
    for (name, bytes) in expected {
        if actual.get(name) != Some(bytes) {
            return Err(format!("exact bytes: {name}"));
        }
    }
    Ok(())
}
fn no_fallback_setup() -> (Fixture, Product, Product, BTreeMap<String, Vec<u8>>) {
    let mut f = Fixture::primary();
    f.replace(
        &format!("allocation 2 selected {H128}"),
        &format!("allocation 2 selected {H0}"),
    );
    let before = baseline_draft(&f);
    let old = prepare_disassembly(&f.original, &f.old()).unwrap();
    assert!(old.candidate_complete());
    let binding = expected_binding(&f, &old);
    let bound = f.bind();
    // FIRST compare the complete binder manifest and complete wrapper file set.
    // Neither expected identity nor expected carrier bytes use bound output.
    assert_eq!(bound.manifest(), binding.manifest);
    compare_complete(&binding.files, &bound.base.files)
        .expect("independent complete binder expectation");
    let expected = expected_files(&f, &old, &binding, &before);
    let mut after = f.planned();
    assert!(after.work.is_empty());
    assert_eq!(after.baseline.len(), 2);
    after.edges.clear();
    draft_eq(&after, &before);
    let new = prepare_disassembly_adjacent_b2(&f.original, &bound).unwrap();
    assert!(new.candidate_complete());
    for (a, b) in old.reports().iter().zip(new.reports()) {
        report_eq(a, b);
    }
    (f, old, new, expected)
}
#[test]
fn f05_exact_no_fallback_comparator() {
    let (_, old, new, expected) = no_fallback_setup();
    assert_eq!(
        old.files()["source.li2sparse"],
        new.files()["source.li2sparse"]
    );
    assert_eq!(old.files()["target.tsv"], new.files()["target.tsv"]);
    compare_complete(&expected, new.files())
        .expect("exact independently expected whole-file result");
}
#[test]
fn f28_comparator_rejects_every_identity_and_nonidentity_mutation() {
    let (f, old, new, expected) = no_fallback_setup();
    compare_complete(&expected, new.files()).unwrap();
    let p = 4096 + 5 * 56;
    for at in [
        0,
        32,
        64,
        0x6f9,
        p,
        p + 28,
        p + 29,
        p + 60,
        p + 61,
        p + 92,
        p + 93,
        new.files()["candidate.elf"].len() - 1,
    ] {
        let mut changed = new.files().clone();
        changed.get_mut("candidate.elf").unwrap()[at] ^= 1;
        assert!(
            compare_complete(&expected, &changed).is_err(),
            "candidate offset {at}"
        );
    }
    for name in [
        "metadata.li2meta",
        "plan-ledger.tsv",
        "ledger.tsv",
        "bundle-index.tsv",
        "report.tsv",
        "selection.txt",
    ] {
        let mut changed = new.files().clone();
        let replacement = old.files().get(name).unwrap().clone();
        changed.insert(name.into(), replacement);
        assert!(
            compare_complete(&expected, &changed).is_err(),
            "stale {name}"
        );
    }
    for at in [24, 55, 96, 127, 176, 207] {
        let mut changed = new.files().clone();
        changed.get_mut("metadata.li2meta").unwrap()[at] ^= 1;
        assert!(compare_complete(&expected, &changed).is_err());
    }
    let mut moved = new.files().clone();
    moved.get_mut("candidate.elf").unwrap().insert(p, 0);
    assert!(compare_complete(&expected, &moved).is_err());
    let mut ambiguous = new.files().clone();
    let payload = ambiguous["candidate.elf"][p..p + 93].to_vec();
    ambiguous
        .get_mut("candidate.elf")
        .unwrap()
        .extend_from_slice(&payload);
    assert!(compare_complete(&expected, &ambiguous).is_err());
    let mut omitted = new.files().clone();
    omitted.remove("image-0000.bin");
    assert!(compare_complete(&expected, &omitted).is_err());
    // Independent identities come from full prospective bytes, never actual digest fields.
    assert!(text(&expected["selection.txt"]).contains("adjacent-b2-budgets 2 1 2\n"));
    let binding = expected_binding(&f, &old);
    assert_eq!(expected["selection.txt"], binding.manifest);
    let bound = f.bind();
    assert_eq!(bound.manifest(), binding.manifest);
    compare_complete(&binding.files, &bound.base.files).unwrap();
    for name in binding.files.keys() {
        let mut changed = bound.base.files.clone();
        changed.get_mut(name).unwrap()[0] ^= 1;
        assert!(
            compare_complete(&binding.files, &changed).is_err(),
            "wrapper mutation: {name}"
        );
    }
}

#[test]
fn f12_failed_pending_rows_and_full_intervals_remain_owned() {
    let mut f = Fixture::primary();
    f.cap(1, 1, 1);
    let d = f.planned();
    assert_eq!(d.pending, vec![(0, addr(B, 2).unwrap())]);
    assert!(d.reports[0].refusal.is_some());
    let selected = f.bind();
    let s = &selected.base.selection;
    let elf = Elf64::parse(
        &f.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let (identity, mut before) = f.initial(s);
    let saved = before.clone();
    // Internal guard boundary: preserve the full original IMUL interval, even
    // when every byte is unchanged. Public selected-roster cases also run the
    // unchanged pending frontend controls listed in controls.json.
    before.pending.push((2, addr(B + 4, 6).unwrap()));
    let failure = call_pair(
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
    .unwrap_err();
    assert_eq!(failure.reason, Refusal::OwnershipConflict);
    assert_eq!(failure.stage, PairStage::UpperPending);
    assert_eq!(
        failure.evidence.counts,
        PairCounts {
            upper: 2,
            lower: 0,
            joint: 0
        }
    );
    before.pending.pop();
    draft_eq(&before, &saved);
    let admitted = Fixture::primary().planned();
    assert_eq!(
        &admitted.composition.final_bytes()[0].bytes[4..10],
        &PRIMARY[4..10]
    );
    assert_eq!(
        admitted
            .composition
            .require_unclaimed_ranges(&[addr(B + 4, 6).unwrap()]),
        Err(Refusal::OwnershipConflict)
    );
}

#[test]
fn f13_original_bytes_and_identity_are_never_current_substitutes() {
    let f = Fixture::prior();
    let selected = f.bind();
    for at in [0x6f9, 0x6fb, 0x6fd, 0x70c, 0x350] {
        let mut changed = f.original.clone();
        changed[at] ^= 1;
        assert_eq!(
            prepare_disassembly_adjacent_b2(&changed, &selected)
                .unwrap_err()
                .stage,
            "original-identity"
        );
    }
    let current = complete(&f, &[1, 2, 3]).files()["candidate.elf"].clone();
    assert_eq!(
        prepare_disassembly_adjacent_b2(&current, &selected)
            .unwrap_err()
            .stage,
        "original-identity"
    );
    let d = f.planned();
    assert_eq!(
        d.composition.originals()[0].bytes,
        &f.original[0x6f9..0x70d]
    );
    let pair = pair(&d);
    assert_eq!(
        pair.members()[0].source_steps()[0].parts().identity.source,
        SourceIdentity(ContentId::of(&f.original).0)
    );
    assert_ne!(
        pair.members()[1].source_steps()[0].parts().reads[0].bytes,
        d.composition.originals()[0].bytes
    );
    // The unchanged raw API identity/domain mutation matrix is mandatory too;
    // sealed public wrappers provide no generation/head/region setters.
}
#[test]
fn f14_f15_static_exclusions_keep_every_selected_row_and_old_search() {
    for code in [
        vec![0xeb, 2, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3],
        vec![0xe3, 2, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3],
        vec![0xff, 0xe0, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3],
        vec![0x75, 0, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3],
        vec![0x75, 2, 0x75, 0xfe, 0x69, 0xc0, 1, 0, 0, 0, 0xc3],
    ] {
        let f = Fixture::source(B, &code, &[2, 2, 6, 1], H128, LOW);
        let d = f.planned();
        assert!(d.work.is_empty());
        assert_eq!(d.baseline.len(), 2);
        assert_eq!(d.reports.iter().map(|r| r.id).collect::<Vec<_>>(), [1, 2]);
        let old = baseline_draft(&f);
        let mut without_edges = d;
        without_edges.edges.clear();
        draft_eq(&without_edges, &old);
    }
    let f = Fixture::primary();
    let selected = f.bind();
    let s = &selected.base.selection;
    let elf = Elf64::parse(
        &f.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    for (name, mut lower, mut upper) in [
        ("nonadjacent", s.sites[0].clone(), s.sites[1].clone()),
        ("cet", s.sites[0].clone(), s.sites[1].clone()),
        ("replace", s.sites[0].clone(), s.sites[1].clone()),
        ("heads", s.sites[0].clone(), s.sites[1].clone()),
        ("resume", s.sites[0].clone(), s.sites[1].clone()),
        ("fetch", s.sites[0].clone(), s.sites[1].clone()),
    ] {
        match name {
            "nonadjacent" => upper.pc += 1,
            "cet" => {
                lower.heads[0].requires_endbr = true;
                upper.heads = lower.heads.clone();
            }
            "replace" => lower.semantics = HookSemantics::ReplaceFirst,
            "heads" => {
                lower.heads.pop();
            }
            "resume" => {
                lower.resumes = ResumeObligation::Enumerated(vec![B + 4, B]);
                upper.resumes = lower.resumes.clone();
            }
            "fetch" => {
                lower.snapshot = addr(B, 6).unwrap();
                lower.function = lower.snapshot;
                upper.snapshot = lower.snapshot;
                upper.function = lower.snapshot;
            }
            _ => unreachable!(),
        }
        assert!(exclusion(&elf, &lower, &upper).is_some(), "{name}");
    }
    for tactic in ["B1", "T1", "T2", "T3"] {
        let mut changed = Fixture::primary();
        changed.replace(
            "search 1 B2 0 2 1 none 0 0",
            &format!("search 1 {tactic} 0 2 1 none 0 0"),
        );
        let d = changed.planned();
        assert!(d.work.is_empty());
        assert_eq!(d.baseline.len(), 2);
        let old = baseline_draft(&changed);
        let mut without_edges = d;
        without_edges.edges.clear();
        draft_eq(&without_edges, &old);
    }
    let mut zero = Fixture::primary();
    zero.replace("search 1 B2 0 2 1 none 0 0", "search 1 B2 0 2 0 none 0 0");
    let d = zero.planned();
    assert!(d.work.is_empty());
    assert_eq!(d.baseline.len(), 2);
    assert!(
        d.edges
            .iter()
            .any(|e| e.exclusion == Some("singleton-zero-sites"))
    );
}

#[test]
fn f16_original_data_carrier_and_prior_allocations_stay_occupied() {
    let f = Fixture::primary();
    let selected = f.bind();
    let s = &selected.base.selection;
    let elf = Elf64::parse(
        &f.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let (identity, before) = f.initial(s);
    for occupied in [addr(H0, 4096).unwrap(), addr(LOW, 4096).unwrap()] {
        let mut denied = before.clone();
        denied.occupied.push(occupied);
        let saved = denied.clone();
        let failure = call_pair(&elf, s, identity, selected.limits, &denied, 0, 1)
            .unwrap()
            .unwrap_err();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        draft_eq(&denied, &saved);
    }
    let prior = Fixture::prior().planned();
    assert!(prior.occupied.contains(&addr(0x12c07000, 4096).unwrap()));
    assert!(prior.occupied.contains(&addr(0x10000000, 4096).unwrap()));
    assert!(
        prior.occupied.contains(&addr(0x10001000, 8192).unwrap()),
        "PHDR-cap reservation, not merely the final one carrier page"
    );
    // Real original non-executable LOAD at the upper mapping page.
    let mut data = Fixture::primary();
    data.original.resize(8192, 0);
    put16(&mut data.original, 56, 2);
    put32(&mut data.original, 120, 1);
    put32(&mut data.original, 124, 6);
    put64(&mut data.original, 128, 4096);
    put64(&mut data.original, 136, H0);
    put64(&mut data.original, 144, H0);
    put64(&mut data.original, 152, 4096);
    put64(&mut data.original, 160, 4096);
    put64(&mut data.original, 168, 4096);
    let old = data.ledger.lines().nth(1).unwrap().to_owned();
    data.ledger = data
        .ledger
        .replacen(&old, &format!("original {}", digest(&data.original)), 1);
    let old = data.policy.lines().nth(1).unwrap().to_owned();
    data.replace(&old, &format!("original {}", digest(&data.original)));
    let old = data.policy.lines().nth(2).unwrap().to_owned();
    data.replace(&old, &format!("ledger {}", digest(data.ledger.as_bytes())));
    data.replace(
        &format!("carrier {}", 0x10001000_u64),
        &format!("carrier {}", H0 + 4096),
    );
    let d = data.planned();
    assert!(d.occupied.contains(&addr(H0, 4096).unwrap()));
    assert!(d.work[0].result.is_err());
    no_candidate(&data.run(), &[1, 2]);
    let mut carrier = Fixture::primary();
    carrier.replace(
        &format!("carrier {}", 0x10001000_u64),
        &format!("carrier {H0}"),
    );
    let d = carrier.planned();
    assert!(d.work[0].result.is_err());
    no_candidate(&carrier.run(), &[1, 2]);
}

#[test]
fn f22_full_new_identity_strict_markers_and_real_bounds() {
    let f = Fixture::primary();
    let bound = f.bind();
    assert_eq!(bound.profile(), disassembly::adjacent_b2::PROFILE);
    assert!(selection::parse(bound.manifest()).is_err());
    assert!(selection::parse_short_t3_pending_projection(bound.manifest()).is_err());
    for wrong in [
        f.policy.replace("LI2DISASM-POLICY 5", "LI2DISASM-POLICY 4"),
        f.policy.replace("adjacent-b2-budgets 2 1 2\n", ""),
        f.policy
            .replace("adjacent-b2-budgets 2 1 2", "adjacent-b2-budgets 02 1 2"),
        f.policy
            .replace("adjacent-b2-budgets 2 1 2", "adjacent-b2-budgets 2 1 3"),
        f.policy
            .replace("adjacent-b2-budgets 2 1 2", "adjacent-b2-budgets 257 1 2"),
        f.policy.replace(
            "adjacent-b2 fallback-two-site-v1\nadjacent-b2-budgets 2 1 2",
            "adjacent-b2-budgets 2 1 2\nadjacent-b2 fallback-two-site-v1",
        ),
        f.policy.clone() + "adjacent-b2-budgets 2 1 2\n",
        f.policy.replace("1048576 32 32", "1048576 1025 32"),
        f.policy.replace("1048576 32 32", "1048576 1 32"),
        f.policy.replace("B2 0 2 1", "B2 0 65537 1"),
        f.policy.replace("none 0 0", "none 0 1048577"),
    ] {
        assert!(f.bind_policy(&wrong).is_err());
    }
    let imported = disassembly::import(
        &f.original,
        f.ledger.as_bytes(),
        ContentId::of(f.ledger.as_bytes()),
    )
    .unwrap();
    assert!(
        imported
            .clone()
            .bind_adjacent_b2(f.policy.as_bytes(), ContentId([0; 32]))
            .is_err()
    );
    assert!(
        imported
            .bind_short_t3_pending(f.policy.as_bytes(), ContentId::of(f.policy.as_bytes()))
            .is_err()
    );
    let padding = disassembly::TEXT_LIMIT - bound.manifest().len();
    let exact = f
        .policy
        .replacen("domain 1", &format!("domain {}1", "0".repeat(padding)), 1);
    let exact_bound = f
        .bind_policy(&exact)
        .expect("exact complete manifest 1 MiB");
    assert_eq!(exact_bound.manifest().len(), disassembly::TEXT_LIMIT);
    let over = exact.replacen("domain ", "domain 0", 1);
    assert!(
        f.bind_policy(&over)
            .unwrap_err()
            .detail
            .contains("whole selection")
    );
    let policy_exact = f.policy.replacen(
        "domain 1",
        &format!(
            "domain {}1",
            "0".repeat(disassembly::TEXT_LIMIT - f.policy.len())
        ),
        1,
    );
    assert_eq!(policy_exact.len(), disassembly::TEXT_LIMIT);
    assert!(
        f.bind_policy(&policy_exact)
            .unwrap_err()
            .detail
            .contains("whole selection")
    );
    let policy_over = policy_exact.replacen("domain ", "domain 0", 1);
    assert!(
        f.bind_policy(&policy_over)
            .unwrap_err()
            .detail
            .contains("policy size")
    );
}

#[test]
fn f23_chains_fixed_edges_and_every_baseline_attempt() {
    for n in [3, 4] {
        let mut code = Vec::new();
        let mut lengths = Vec::new();
        for i in 0..n {
            code.extend_from_slice(&[0x75, ((n - i - 1) * 2) as u8]);
            lengths.push(2);
        }
        code.extend_from_slice(&[0x69, 0xc0, 1, 0, 0, 0, 0xc3]);
        lengths.extend([6, 1]);
        // Keep all four two-byte stores within one cache line. At B the
        // fourth instruction begins at offset 63 and is correctly excluded.
        let base = B - 1;
        for i in 0..n {
            let pc = base + 2 * i as u64;
            assert_eq!(pc / 64, (pc + 1) / 64);
        }
        let f = Fixture::source(base, &code, &lengths, H128, LOW);
        let d = f.planned();
        assert_eq!(
            d.baseline.iter().map(|b| b.id).collect::<Vec<_>>(),
            (1..=n as u64).rev().collect::<Vec<_>>()
        );
        assert_eq!(d.edges.len(), n - 1);
        assert!(d.edges.iter().all(|e| e.exclusion.is_none()));
        assert_eq!(d.edges.iter().filter(|e| e.visited_group).count(), n / 2);
        assert_eq!(
            d.edges
                .iter()
                .filter(|e| !e.visited_group && e.exclusion.is_none())
                .count(),
            n - 1 - n / 2
        );
        assert_eq!(d.reports.len(), n);
        assert!(d.work.iter().all(|w| match &w.result {
            Ok(p) => !p.evidence().classification_complete,
            Err(e) => !e.evidence.classification_complete,
        }));
    }
    // Retain the original four-branch geometry as an explicit exclusion control.
    let crossing = [
        0x75, 6, 0x75, 4, 0x75, 2, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3,
    ];
    let f = Fixture::source(B, &crossing, &[2, 2, 2, 2, 6, 1], H128, LOW);
    assert_eq!((B + 6) % 64, 63);
    let d = f.planned();
    assert_eq!(
        d.baseline.iter().map(|b| b.id).collect::<Vec<_>>(),
        [4, 3, 2, 1]
    );
    assert_eq!(
        d.edges
            .iter()
            .map(|e| (e.lower, e.upper, e.exclusion, e.visited_group))
            .collect::<Vec<_>>(),
        [
            (3, 4, Some("fetch-store-domain"), false),
            (2, 3, None, true),
            (1, 2, None, false)
        ]
    );
    assert_eq!(d.reports.len(), 4);
    assert!(d.work.iter().all(|w| match &w.result {
        Ok(p) => !p.evidence().classification_complete,
        Err(e) => !e.evidence.classification_complete,
    }));
    // Two prospectively fixed independent groups and an intervening EB selection.
    let code = [
        0x75, 2, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3, 0xeb, 0, 0x75, 2, 0x75, 0, 0x69, 0xc0, 1,
        0, 0, 0, 0xc3,
    ];
    let f = Fixture::source(B, &code, &[2, 2, 6, 1, 2, 2, 2, 6, 1], H128, LOW);
    let d = f.planned();
    assert_eq!(
        d.baseline.iter().map(|b| b.id).collect::<Vec<_>>(),
        [5, 4, 3, 2, 1]
    );
    assert_eq!(
        d.edges
            .iter()
            .filter(|e| e.visited_group)
            .map(|e| (e.lower, e.upper))
            .collect::<Vec<_>>(),
        [(4, 5), (1, 2)]
    );
    assert!(
        d.edges
            .iter()
            .any(|e| e.lower == 3 && e.exclusion.is_some())
    );
}

#[test]
fn f27_independent_internal_accounting_caps_are_not_public_policy_knobs() {
    let totals = Resources {
        steps: 3,
        mappings: 3,
        virtual_bytes: 12288,
        backing_bytes: 12288,
        first: Some(H0),
        end: LOW + 4096,
    };
    let exact = Capacities {
        steps: 3,
        mappings: 3,
        virtual_bytes: 12288,
        backing_bytes: 12288,
        span: 0x67409000,
    };
    totals.check(exact).unwrap();
    for field in 0..5 {
        let mut cap = exact;
        match field {
            0 => cap.steps -= 1,
            1 => cap.mappings -= 1,
            2 => cap.virtual_bytes -= 1,
            3 => cap.backing_bytes -= 1,
            4 => cap.span -= 1,
            _ => unreachable!(),
        }
        assert_eq!(totals.check(cap).unwrap_err().stage, "whole-budget");
        assert_eq!(
            totals,
            Resources {
                steps: 3,
                mappings: 3,
                virtual_bytes: 12288,
                backing_bytes: 12288,
                first: Some(H0),
                end: LOW + 4096
            }
        );
    }
    let underflow = Resources {
        first: Some(2),
        end: 1,
        ..Resources::default()
    };
    assert!(underflow.check(exact).is_err());
    let f = Fixture::prior();
    let mut s = f.bind().base.selection;
    let derived = Capacities::from_selection(&s).unwrap();
    assert_eq!(derived.steps, 2 * s.sites.len());
    assert_eq!(derived.mappings, s.limits.images);
    assert_eq!(derived.virtual_bytes, s.limits.new_load_pages * 4096);
    assert_eq!(derived.backing_bytes, derived.virtual_bytes);
    assert_eq!(totals.pair_budget(derived, 2).unwrap().bundle.max_steps, 2);
    assert!(
        totals
            .pair_budget(
                Capacities {
                    mappings: 2,
                    ..derived
                },
                2
            )
            .is_err()
    );
    s.limits.new_load_pages = u64::MAX;
    assert!(
        Capacities::from_selection(&s)
            .unwrap_err()
            .detail
            .contains("overflow")
    );
}

#[test]
fn f20_actual_final_carrier_limits_and_construction_failures_do_not_dispatch() {
    let f = Fixture::prior();
    complete(&f, &[1, 2, 3]);
    for point in [
        "evidence-serialization",
        "carrier-construction",
        "sparse-serialization",
        "complete-output-serialization",
    ] {
        let selected = f.bind();
        let mut reached = false;
        let result = prepare_selection_with_adjacent_gate(
            &f.original,
            selected.base.selection,
            false,
            disassembly::NeighborMode::ShortT3Pending,
            Some(selected.limits),
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
        // No Product or its output buffers can escape through this error.
    }
    let mut limited = f.clone();
    limited.replace("128 2097152 1048576 128", "128 4096 1048576 128");
    let p = limited.run();
    no_candidate(&p, &[1, 2, 3]);
    assert!(
        p.reports()
            .iter()
            .all(|r| r.refusal.as_ref().unwrap().stage == "carrier")
    );
    // Internal post-core hook guard uses a real accepted pair and real source
    // edits; only the independently checked guard input is made hostile here.
    let selected = f.bind();
    let mut s = selected.base.selection;
    let elf = Elf64::parse(
        &f.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let dynamic = carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default()).unwrap();
    let (identity, before) = f.initial(&s);
    let pair = call_pair(&elf, &s, identity, selected.limits, &before, 0, 1)
        .unwrap()
        .unwrap();
    s.hooks[0].pc = B + 2;
    s.hooks[0].length = 1;
    let saved = before.clone();
    let result = stage_pair(
        &elf,
        &dynamic,
        &s,
        &before,
        PairAssociation {
            lower: 0,
            upper: 1,
            attempt: 0,
        },
        &pair,
        |_, _| Ok(()),
    );
    assert_eq!(result.unwrap_err().stage, "hook-ownership");
    draft_eq(&before, &saved);
}

#[test]
fn f14_prefix_fetch_cache_line_and_unverified_targets_keep_denominator() {
    let variants = [
        Fixture::source(
            B,
            &[0x66, 0x75, 2, 0x75, 0, 0x69, 0xc0, 1, 0, 0, 0, 0xc3],
            &[3, 2, 6, 1],
            H128,
            LOW,
        ),
        Fixture::source(B, &[0x75, 2, 0x75, 0, 0xc3], &[2, 2, 1], H128, LOW),
        Fixture::source(0x100006ff, PRIMARY, &[2, 2, 6, 1], H128, LOW),
    ];
    for f in variants {
        let d = f.planned();
        assert!(d.work.is_empty());
        assert_eq!(d.reports.len(), 2);
        assert_eq!(d.baseline.len(), 2);
    }
    for displacement in [3_u8, 127] {
        let mut f = Fixture::primary();
        f.original[0x6fa] = displacement;
        f.ledger = f.ledger.replace("7502", &format!("75{displacement:02x}"));
        let old = f.ledger.lines().nth(1).unwrap().to_owned();
        f.ledger = f
            .ledger
            .replacen(&old, &format!("original {}", digest(&f.original)), 1);
        let error = disassembly::import(
            &f.original,
            f.ledger.as_bytes(),
            ContentId::of(f.ledger.as_bytes()),
        )
        .unwrap_err();
        assert!(
            error
                .detail
                .contains("direct target contradicts complete ledger")
        );
    }
}

#[test]
fn f20_real_loader_dependency_refusal_after_core_pair_success() {
    let mut f = Fixture::primary();
    f.original.resize(8192, 0);
    put16(&mut f.original, 56, 3);
    // Original RW owner of dynamic table and one real four-byte RELA write.
    put32(&mut f.original, 120, 1);
    put32(&mut f.original, 124, 6);
    put64(&mut f.original, 128, 4096);
    put64(&mut f.original, 136, 0x10002000);
    put64(&mut f.original, 144, 0x10002000);
    put64(&mut f.original, 152, 4096);
    put64(&mut f.original, 160, 4096);
    put64(&mut f.original, 168, 4096);
    put32(&mut f.original, 176, 2);
    put32(&mut f.original, 180, 6);
    put64(&mut f.original, 184, 0x1200);
    put64(&mut f.original, 192, 0x10002200);
    put64(&mut f.original, 200, 0x10002200);
    put64(&mut f.original, 208, 64);
    put64(&mut f.original, 216, 64);
    put64(&mut f.original, 224, 8);
    for (i, (tag, value)) in [(7, 0x10002800_u64), (8, 24), (9, 24)]
        .into_iter()
        .enumerate()
    {
        put64(&mut f.original, 0x1200 + i * 16, tag);
        put64(&mut f.original, 0x1208 + i * 16, value);
    }
    put64(&mut f.original, 0x1800, B + 4);
    put64(&mut f.original, 0x1808, 10);
    put64(&mut f.original, 0x1810, 0x1234);
    let old = f.ledger.lines().nth(1).unwrap().to_owned();
    f.ledger = f
        .ledger
        .replacen(&old, &format!("original {}", digest(&f.original)), 1);
    let old = f.policy.lines().nth(1).unwrap().to_owned();
    f.replace(&old, &format!("original {}", digest(&f.original)));
    let old = f.policy.lines().nth(2).unwrap().to_owned();
    f.replace(&old, &format!("ledger {}", digest(f.ledger.as_bytes())));
    f.replace(
        &format!("carrier {}", 0x10001000_u64),
        &format!("carrier {}", 0x10003000_u64),
    );
    let elf = Elf64::parse(
        &f.original,
        ParseLimits {
            max_program_headers: 128,
        },
    )
    .unwrap();
    let dynamic = carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default()).unwrap();
    assert_eq!(dynamic.writes.len(), 1);
    assert_eq!(dynamic.writes[0].range.len(), 4);
    let d = f.planned();
    assert_eq!(d.work.len(), 1);
    assert!(d.work[0].result.as_ref().unwrap().evidence().accepted);
    assert_eq!(
        d.work[0].frontend_refusal.as_ref().unwrap().stage,
        "source-relocation"
    );
    assert!(!d.work[0].committed);
    assert!(d.accepted.is_empty());
    assert_eq!(d.pending.len(), 2);
    no_candidate(&f.run(), &[1, 2]);
}

#[path = "routed_jmp.rs"]
mod routed_tests;
