//! Separately invoked target / produce / verify / controls / run stages.
//! Ordinary tests never execute this example. Output bindings are written last.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
extern crate li2core as liteinst2;
#[allow(dead_code)]
#[path = "../../../tests/support/quiescent_oracle.rs"]
mod oracle;
use liteinst2::bundle::{BundleBudget, BundleMemory};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::emission::{
    ArtifactEmission, ArtifactPlan, ArtifactRequest, PlanningSite, SymbolicHook, TargetProfile,
};
use liteinst2::engine::{self, EnginePolicy, Tactic};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    self, AdjacentB2ArtifactPlan, AdjacentB2Budget, AdjacentB2Failure, AllocationPolicy,
    PairCounts, PairStage, PairStop, SearchPolicy, TacticPolicy,
};
use liteinst2::trampoline::SavedExtendedStateLayout;
use oracle::elf_exec_oracle::adjacent_b2::{self as native, fixture as f};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

fn hash(bytes: &[u8]) -> [u8; 32] {
    formats::ContentId::of(bytes).0
}
fn digest(bytes: &[u8]) -> String {
    f::hex(&hash(bytes))
}
fn name(s: &str) {
    assert!(!s.is_empty() && s.len() <= 128 && s != "." && s != ".." && s != "binding.tsv");
    assert!(
        s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    );
}
fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn read_bound(path: &Path, limit: usize) -> Vec<u8> {
    assert!(
        std::fs::symlink_metadata(path).unwrap().is_file(),
        "regular non-symlink member"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    let a = file.metadata().unwrap();
    assert!(
        a.is_file() && a.len() <= limit as u64 && a.nlink() == 1,
        "bounded unaliased regular member"
    );
    let mut b = Vec::new();
    (&file)
        .take((limit + 1) as u64)
        .read_to_end(&mut b)
        .unwrap();
    let z = file.metadata().unwrap();
    let p = std::fs::metadata(path).unwrap();
    assert_eq!(
        (
            a.dev(),
            a.ino(),
            a.len(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec()
        ),
        (
            z.dev(),
            z.ino(),
            z.len(),
            z.mtime(),
            z.mtime_nsec(),
            z.ctime(),
            z.ctime_nsec()
        )
    );
    assert_eq!((p.dev(), p.ino(), p.len()), (a.dev(), a.ino(), a.len()));
    assert_eq!(b.len() as u64, a.len());
    b
}
#[derive(Clone, Default, Eq, PartialEq)]
struct Packet {
    files: BTreeMap<String, Vec<u8>>,
    children: BTreeMap<String, Packet>,
}
impl Packet {
    fn file(&self, name: &str) -> &[u8] {
        self.files.get(name).expect("closed named member")
    }
    fn total(&self) -> usize {
        self.files.values().map(Vec::len).sum::<usize>()
            + self.children.values().map(Self::total).sum::<usize>()
    }
}
#[path = "adjacent_b2_support/packets.rs"]
mod packets;
use packets::{
    Budget, Tree, close_captures, close_in_empty, close_packet, read_campaign, read_packet,
};
#[path = "adjacent_b2_support/admission_controls.rs"]
mod admission_controls;
#[path = "adjacent_b2_support/ledger.rs"]
mod ledger;

fn range(pc: u64, len: usize) -> AddressRange {
    AddressRange::new(pc, len).unwrap()
}
fn identity(req: f::Request) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity(hash(&req.source())),
        mapping: 1,
        generation: 1,
    }
}
fn entries(req: f::Request) -> LegalEntrySet {
    LegalEntrySet {
        identity: identity(req),
        scope: range(f::B, 11),
        provenance: EntryProvenance::Declared("adjacent-b2-native-v2".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: f::HEADS
            .iter()
            .map(|&address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    }
}
fn allocation(upper: bool) -> AllocationPolicy {
    let pc = if upper { f::UPPER } else { f::LOWER };
    AllocationPolicy {
        ranges: vec![range(pc, 4096)],
        preferred_address: Some(pc + if upper { 128 } else { 0 }),
        max_candidates: if upper { 2 } else { 1 },
        max_mappings: 1,
        max_mapped_bytes: 4096,
    }
}
fn occupancy() -> Vec<AddressRange> {
    // Seven PRE-GENERATION owners only. Future image permits remain vacant.
    let mut out: Vec<_> = f::LOADS[..7]
        .iter()
        .map(|l| range(l.1, l.2 as usize))
        .collect();
    out.push(range(0x405000, 4096));
    out.sort_by_key(|r| r.start());
    assert_eq!(out.len(), 8);
    assert!(
        out.iter()
            .all(|r| !r.overlaps(range(f::UPPER, 4096)) && !r.overlaps(range(f::LOWER, 4096)))
    );
    out
}
fn request_text(req: f::Request, state: SavedExtendedStateLayout) -> Vec<u8> {
    let mut out = format!(
        "LI2ADJREQUEST\t2\nname\t{}\nsource\t{}\nidentity\t{}\t1\t1\nhook\t11\t{}\nbias_domain\t7\ntarget\t{}\n",
        req.name(),
        f::hex(&req.source()),
        digest(&req.source()),
        f::HOOK,
        digest(&f::target_text(state))
    );
    for pc in f::HEADS {
        writeln!(out, "head\t{pc}\tfalse").unwrap();
    }
    out.push_str("entries\tAllInstructionHeads\nresumes\tNoneExist\nexternal_pending\tEMPTY\nsearch\tGeneralizedPunOnly\t0\t2\t1\n");
    for (role, upper) in [("upper", true), ("lower", false)] {
        let a = allocation(upper);
        writeln!(
            out,
            "allocation\t{role}\t{}\t4096\t{}\t{}\t1\t4096",
            a.ranges[0].start(),
            a.preferred_address.unwrap(),
            a.max_candidates
        )
        .unwrap();
    }
    for r in occupancy() {
        writeln!(out, "occupied\t{}\t{}", r.start(), r.len()).unwrap();
    }
    out.push_str(
        "pair_budget\t2\t2\t2\t8192\t8192\t2147483648\nqualification_complete\tfalse\nEND\n",
    );
    out.into_bytes()
}
fn site<'a>(
    req: f::Request,
    source: &'a [u8],
    e: &'a LegalEntrySet,
    a: &'a AllocationPolicy,
    upper: bool,
) -> PlanningSite<'a> {
    let pc = f::B + if upper { 2 } else { 0 };
    PlanningSite {
        identity: identity(req),
        code: source,
        base_address: f::B,
        function: range(f::B, 11),
        block: range(pc, 2),
        logical_pc: pc,
        entries: e,
        semantics: HookSemantics::Observe,
        allocation: a,
        search: SearchPolicy {
            tactics: TacticPolicy::GeneralizedPunOnly,
            max_upstream_bytes: 0,
            max_displaced_bytes: 2,
            max_sites: 1,
        },
    }
}
fn singleton(
    site: PlanningSite<'_>,
    emission: &ArtifactEmission,
    predecessor: &Composition,
    target: u64,
) -> ArtifactPlan {
    let mut a = site.allocation.clone();
    a.preferred_address = Some(target);
    let before = predecessor.clone();
    let plan = engine::plan_with_emission_after(
        &ArtifactRequest {
            site: PlanningSite {
                allocation: &a,
                ..site
            },
            emission,
        },
        predecessor,
        &a,
        EnginePolicy {
            forced: Some(Tactic::GeneralizedPun),
            ..EnginePolicy::default()
        },
    )
    .expect("mandatory actual singleton positive");
    assert_eq!(predecessor, &before);
    assert_eq!(plan.images().count(), 1);
    assert_eq!(plan.images().next().unwrap().address(), target);
    plan
}
fn append(before: &Composition, plan: &ArtifactPlan) -> Composition {
    let mut c = before.clone();
    for p in plan.source_steps() {
        c.append(p).unwrap();
    }
    c
}
fn same(actual: &ArtifactPlan, expected: &ArtifactPlan) {
    assert_eq!(actual.source_steps(), expected.source_steps());
    let a: Vec<_> = actual.images().collect();
    let b: Vec<_> = expected.images().collect();
    assert_eq!(a.len(), b.len());
    for (a, b) in a.iter().zip(&b) {
        assert_eq!(a.address(), b.address());
        assert_eq!(a.bytes(), b.bytes());
        assert_eq!(a.entry_routes(), b.entry_routes());
        assert_eq!(a.instruction_boundaries(), b.instruction_boundaries());
        assert_eq!(a.program_counter_mappings(), b.program_counter_mappings());
        assert_eq!(a.metadata(), b.metadata());
    }
}
fn image_rows(out: &mut String, index: usize, image: liteinst2::emission::ArtifactImageView<'_>) {
    writeln!(
        out,
        "image\t{index}\t{}\t{}\t{}",
        image.address(),
        image.bytes().len(),
        digest(image.bytes())
    )
    .unwrap();
    for &(l, p) in image.entry_routes() {
        writeln!(out, "route\t{index}\t{l}\t{p}").unwrap();
    }
    for &(l, p) in image.instruction_boundaries() {
        writeln!(out, "boundary\t{index}\t{l}\t{p}").unwrap();
    }
    for m in image.program_counter_mappings() {
        writeln!(
            out,
            "pc-range\t{index}\t{}\t{}\t{}",
            m.generated_start(),
            m.generated_end(),
            m.logical_address()
        )
        .unwrap();
    }
    let mut fields: Vec<_> = image.metadata().fields().iter().collect();
    fields.sort_by_key(|field| field.offset);
    for field in fields {
        writeln!(
            out,
            "field\t{index}\t{}\t{}\t{:?}\t{}\t{}\t{}\t{}",
            field.offset,
            field.width,
            field.encoding,
            field.origin,
            field.target,
            field.bias_domain,
            f::hex(field.role.as_bytes())
        )
        .unwrap();
    }
    for requirement in image.metadata().requirements() {
        writeln!(out, "requirement\t{index}\t{requirement:?}").unwrap();
    }
    assert!(!image.metadata().qualification_complete());
}
fn expected_image_rows(out: &mut String, index: usize, w: &f::ImageWitness) {
    let base = w.code.base;
    let len = w.code.bytes.len();
    let logical = w.logical;
    writeln!(
        out,
        "image\t{index}\t{base}\t{len}\t{}",
        digest(&w.code.bytes)
    )
    .unwrap();
    writeln!(
        out,
        "route\t{index}\t{logical}\t{base}\nboundary\t{index}\t{logical}\t{}",
        w.body
    )
    .unwrap();
    writeln!(
        out,
        "pc-range\t{index}\t{base}\t{}\t{logical}\npc-range\t{index}\t{}\t{}\t{}",
        w.body + 6,
        w.body + 6,
        base + len as u64,
        logical + 2
    )
    .unwrap();
    for (offset, width, encoding, origin, target, role) in [
        (52, 8, "Delta", 50, logical, "LogicalPc".to_string()),
        (
            w.call - base + 1,
            4,
            "Relative",
            w.returned - base,
            f::HOOK,
            "HookCall".to_string(),
        ),
        (
            w.body - base + 2,
            4,
            "Relative",
            w.body - base + 6,
            w.branch_target,
            format!("OriginalBranch {{ original_pc: {logical} }}"),
        ),
        (
            w.body - base + 7,
            4,
            "Relative",
            w.body - base + 11,
            logical + 2,
            "Return".to_string(),
        ),
    ] {
        writeln!(
            out,
            "field\t{index}\t{offset}\t{width}\t{encoding}\t{origin}\t{target}\t7\t{}",
            f::hex(role.as_bytes())
        )
        .unwrap();
    }
    for r in [
        "ArtifactIdentityAndAddressBinding",
        "TargetCpuAndStateAtEntry",
        "OriginalDynamicRelocationOwnership",
        "OriginalImmediatePointerProvenance",
        "GeneratedUnwindInformation",
        "OriginalCodeAsDataContract",
        "HookAbiAndReadiness(11)",
    ] {
        writeln!(out, "requirement\t{index}\t{r}").unwrap();
    }
}
fn plan_prefix(req: f::Request, state: SavedExtendedStateLayout) -> String {
    format!(
        "LI2ADJPLAN\t2\nrequest\t{}\ncounts\t2\t1\t2\nmemory\t2\t2\t2\t8192\t8192\t1732284416\n",
        digest(&request_text(req, state))
    )
}
fn expected_plan(req: f::Request, state: SavedExtendedStateLayout) -> Vec<u8> {
    let mut out = plan_prefix(req, state);
    let mut current = req.source().to_vec();
    for (index, upper) in [true, false].into_iter().enumerate() {
        let pc = f::B + if upper { 2 } else { 0 };
        let target = if upper { f::UPPER } else { f::LOWER };
        let stored = if upper { vec![0xe9, 0] } else { vec![0xe9, 2] };
        writeln!(out,"step\t{index}\t{pc}\t{pc}\t2\t5\t{target}\t4096\nread\t{index}\t{}\t{}\nwrite\t{index}\t{pc}\t{}",f::B,f::hex(&current),f::hex(&stored)).unwrap();
        let at = (pc - f::B) as usize;
        current[at..at + 2].copy_from_slice(&stored);
        expected_image_rows(&mut out, index, &f::image_witness(req, state, upper));
    }
    assert_eq!(current, f::FINAL);
    writeln!(
        out,
        "final\t{}\nlock\t{}\t7\nqualification_complete\tfalse\nEND",
        f::hex(&current),
        f::B
    )
    .unwrap();
    out.into_bytes()
}
fn hashes(
    req: f::Request,
    state: SavedExtendedStateLayout,
    ledger: &[u8],
    images: [&[u8]; 2],
) -> [[u8; 32]; 7] {
    [
        hash(&req.source()),
        hash(images[0]),
        hash(images[1]),
        hash(&f::target_text(state)),
        hash(ledger),
        hash(&f::hook(req.recording).bytes),
        hash(&f::bootstrap().bytes),
    ]
}
fn planner_control_manifest() -> Vec<u8> {
    b"LI2ADJPLANNERCONTROLS\t2\npositive_h128\trequired\npositive_h0\trequired\npositive_lower_after_h0\trequired\npositive_pair\trequired\ncap_one\tUpperScheduleBudget\tAllocationUnavailable\t1\t0\t1\noccupied_upper\tUpperLeaf\tAllocationUnavailable\t2\t0\t0\nshort_lower_permit\tLowerLeaf\tAllocationUnavailable\t2\t1\t2\npending_imul\tUpperPending\tOwnershipConflict\t2\t0\t0\naggregate_steps\tAggregate\tAllocationUnavailable\t2\t1\t2\naggregate_mappings\tAggregate\tAllocationUnavailable\t2\t1\t2\naggregate_virtual_bytes\tAggregate\tAllocationUnavailable\t2\t1\t2\naggregate_backing_bytes\tAggregate\tAllocationUnavailable\t2\t1\t2\naggregate_span\tAggregate\tAllocationUnavailable\t2\t1\t2\npredecessor_unchanged\ttrue\nfull_failures\tactual-plan.txt\nEND\n".to_vec()
}
fn require_failure(
    result: Result<AdjacentB2ArtifactPlan, AdjacentB2Failure>,
    reason: Refusal,
    stop: PairStop,
    stage: PairStage,
    counts: PairCounts,
    label: &str,
    evidence: &mut String,
) -> AdjacentB2Failure {
    let failed = result.expect_err("declared native planner hostile control must refuse");
    assert_eq!(failed.reason, reason);
    assert_eq!(failed.stop, stop);
    assert_eq!(failed.stage, stage);
    assert_eq!(failed.evidence.counts, counts);
    assert!(!failed.evidence.accepted && !failed.evidence.classification_complete);
    writeln!(evidence, "Native planner control {label}:\n{failed:#?}").unwrap();
    failed
}
fn produce_one(req: f::Request, state: SavedExtendedStateLayout) -> Packet {
    let source = req.source();
    let e = entries(req);
    let upper = allocation(true);
    let lower = allocation(false);
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(state, 7).unwrap(),
        SymbolicHook {
            identity: 11,
            address: Some(f::HOOK),
        },
        occupancy(),
    );
    let original = Composition::new(
        identity(req),
        vec![ExpectedBytes {
            address: f::B,
            bytes: source.to_vec(),
        }],
    )
    .unwrap();
    let before = original.clone();
    let u = site(req, &source, &e, &upper, true);
    let l = site(req, &source, &e, &lower, false);
    let h128 = singleton(u, &emission, &original, f::UPPER + 128);
    let h0 = singleton(u, &emission, &original, f::UPPER);
    let after_upper = append(&original, &h0);
    let low = singleton(l, &emission, &after_upper, f::LOWER);
    let budget = AdjacentB2Budget {
        max_continuations: 2,
        bundle: BundleBudget {
            max_steps: 2,
            max_mappings: 2,
            max_virtual_bytes: 8192,
            max_backing_bytes: 8192,
            max_virtual_span: 1 << 31,
        },
    };
    let pair =
        quiescent::plan_adjacent_b2_with_emission_after([l, u], &emission, &original, &[], budget)
            .expect("required frozen native pair; no fallback");
    assert_eq!(original, before);
    assert_eq!(pair.logical_pcs(), [f::B + 2, f::B]);
    assert!(!pair.qualification_complete());
    same(&pair.members()[0], &h0);
    same(&pair.members()[1], &low);
    assert_eq!(
        pair.evidence().counts,
        PairCounts {
            upper: 2,
            lower: 1,
            joint: 2
        }
    );
    assert!(pair.evidence().accepted && !pair.evidence().classification_complete);
    assert_eq!(
        pair.memory(),
        BundleMemory {
            mappings: 2,
            virtual_pages: 2,
            backing_pages: 2,
            virtual_bytes: 8192,
            backing_bytes: 8192,
            virtual_span: 0x67409000
        }
    );
    let mut current = original.clone();
    let mut plan = plan_prefix(req, state);
    let mut images = Vec::new();
    for (i, member) in pair.members().iter().enumerate() {
        let pc = if i == 0 { f::B + 2 } else { f::B };
        let image_pc = if i == 0 { f::UPPER } else { f::LOWER };
        assert_eq!(member.source_steps().len(), 1);
        assert_eq!(member.images().count(), 1);
        let p = member.source_steps()[0].parts();
        let PlanKind::GeneralizedPun(pun) = &p.kind else {
            panic!("forced B2")
        };
        assert_eq!(p.profile, ApplicationProfile::InstallOnce);
        assert_eq!(p.identity, identity(req));
        assert_eq!(p.entries, e);
        assert_eq!(
            (p.logical_pc, p.physical_pc, p.displaced),
            (pc, pc, range(pc, 2))
        );
        assert_eq!(current.identity(), identity(req));
        assert_eq!(
            current.originals(),
            [ExpectedBytes {
                address: f::B,
                bytes: source.to_vec()
            }]
        );
        let final_blocks = current.final_bytes();
        assert_eq!(final_blocks.len(), 1);
        let final_block = &final_blocks[0];
        assert_eq!(
            (final_block.address, final_block.bytes.len()),
            (f::B, source.len())
        );
        assert_eq!(p.dependencies, [range(f::B, 11)]);
        assert_eq!(
            p.reads,
            [ExpectedBytes {
                address: f::B,
                bytes: final_block.bytes.clone()
            }]
        );
        assert_eq!(
            p.writes,
            [ByteEdit {
                address: pc,
                bytes: if i == 0 { vec![0xe9, 0] } else { vec![0xe9, 2] }
            }]
        );
        assert_eq!(pun.instruction_len, 2);
        assert_eq!(pun.consumed, range(pc, 5));
        assert_eq!(pun.store, p.writes[0]);
        assert_eq!(
            pun.target_window,
            range(if i == 0 { f::UPPER } else { f::LOWER - 2 }, 256)
        );
        assert_eq!(
            p.allocations,
            [AllocationRequest {
                range: range(image_pc, 4096),
                alignment: 4096
            }]
        );
        let required: Vec<_> = f::HEADS
            .iter()
            .copied()
            .filter(|h| pc <= *h && *h < pc + 5)
            .map(EntryObligation::Preserved)
            .collect();
        assert_eq!(p.obligations, required);
        assert!(
            p.requirements.quiescent && p.requirements.sync_core && !p.requirements.sigill_router
        );
        let image = member.images().next().unwrap();
        assert_eq!(image.address(), image_pc);
        assert_eq!(p.generated.len(), 1);
        assert_eq!(p.generated[0].address, image_pc);
        assert_eq!(p.generated[0].bytes, image.bytes());
        assert_eq!(
            p.generated[0].program_counters,
            image.program_counter_mappings()
        );
        writeln!(
            plan,
            "step\t{i}\t{}\t{}\t{}\t{}\t{}\t{}\nread\t{i}\t{}\t{}\nwrite\t{i}\t{}\t{}",
            p.logical_pc,
            p.physical_pc,
            p.displaced.len(),
            pun.consumed.len(),
            p.allocations[0].range.start(),
            p.allocations[0].range.len(),
            p.reads[0].address,
            f::hex(&p.reads[0].bytes),
            p.writes[0].address,
            f::hex(&p.writes[0].bytes)
        )
        .unwrap();
        images.push(image.bytes().to_vec());
        image_rows(&mut plan, i, image);
        current.append(&member.source_steps()[0]).unwrap();
    }
    assert_eq!(
        current.final_bytes(),
        [ExpectedBytes {
            address: f::B,
            bytes: f::FINAL.to_vec()
        }]
    );
    assert_eq!(current.locks(), [range(f::B, 7)]);
    writeln!(
        plan,
        "final\t{}\nlock\t{}\t7\nqualification_complete\tfalse\nEND",
        f::hex(&current.final_bytes()[0].bytes),
        f::B
    )
    .unwrap();
    // All fixed negative rows follow genuine singleton and pair positives. They
    // never substitute for or retry a failed native request.
    let mut negative_evidence = String::new();
    let mut negative_controls = Vec::new();
    let mut cap_one = upper.clone();
    cap_one.max_candidates = 1;
    let one_budget = AdjacentB2Budget {
        max_continuations: 1,
        ..budget
    };
    let failed = require_failure(
        quiescent::plan_adjacent_b2_with_emission_after(
            [
                l,
                PlanningSite {
                    allocation: &cap_one,
                    ..u
                },
            ],
            &emission,
            &original,
            &[],
            one_budget,
        ),
        Refusal::AllocationUnavailable,
        PairStop::UpperScheduleBudget,
        PairStage::UpperLeaf,
        PairCounts {
            upper: 1,
            lower: 0,
            joint: 1,
        },
        "cap_one",
        &mut negative_evidence,
    );
    negative_controls.push(ledger::Control {
        label: "cap_one".into(),
        upper: cap_one.clone(),
        lower: lower.clone(),
        occupied: emission.occupied().to_vec(),
        pending: vec![],
        budget: one_budget,
        failure: failed,
    });
    assert_eq!(original, before);
    let mut occupied = occupancy();
    occupied.push(range(f::UPPER, 4096));
    let held = ArtifactEmission::new(emission.profile().clone(), emission.hook(), occupied);
    let failed = require_failure(
        quiescent::plan_adjacent_b2_with_emission_after([l, u], &held, &original, &[], budget),
        Refusal::AllocationUnavailable,
        PairStop::Exhausted,
        PairStage::UpperLeaf,
        PairCounts {
            upper: 2,
            lower: 0,
            joint: 0,
        },
        "occupied_upper",
        &mut negative_evidence,
    );
    negative_controls.push(ledger::Control {
        label: "occupied_upper".into(),
        upper: upper.clone(),
        lower: lower.clone(),
        occupied: held.occupied().to_vec(),
        pending: vec![],
        budget,
        failure: failed,
    });
    assert_eq!(original, before);
    let mut short = lower.clone();
    short.ranges = vec![range(f::LOWER, 4095)];
    let failed = require_failure(
        quiescent::plan_adjacent_b2_with_emission_after(
            [
                PlanningSite {
                    allocation: &short,
                    ..l
                },
                u,
            ],
            &emission,
            &original,
            &[],
            budget,
        ),
        Refusal::AllocationUnavailable,
        PairStop::Exhausted,
        PairStage::LowerLeaf,
        PairCounts {
            upper: 2,
            lower: 1,
            joint: 2,
        },
        "short_lower_permit",
        &mut negative_evidence,
    );
    negative_controls.push(ledger::Control {
        label: "short_lower_permit".into(),
        upper: upper.clone(),
        lower: short.clone(),
        occupied: emission.occupied().to_vec(),
        pending: vec![],
        budget,
        failure: failed,
    });
    assert_eq!(original, before);
    let failed = require_failure(
        quiescent::plan_adjacent_b2_with_emission_after(
            [l, u],
            &emission,
            &original,
            &[range(f::B + 4, 6)],
            budget,
        ),
        Refusal::OwnershipConflict,
        PairStop::Exhausted,
        PairStage::UpperPending,
        PairCounts {
            upper: 2,
            lower: 0,
            joint: 0,
        },
        "pending_imul",
        &mut negative_evidence,
    );
    negative_controls.push(ledger::Control {
        label: "pending_imul".into(),
        upper: upper.clone(),
        lower: lower.clone(),
        occupied: emission.occupied().to_vec(),
        pending: vec![range(f::B + 4, 6)],
        budget,
        failure: failed,
    });
    assert_eq!(original, before);
    for field in 0..5 {
        let mut limited = budget;
        match field {
            0 => limited.bundle.max_steps = 1,
            1 => limited.bundle.max_mappings = 1,
            2 => limited.bundle.max_virtual_bytes = 8191,
            3 => limited.bundle.max_backing_bytes = 8191,
            4 => limited.bundle.max_virtual_span = 0x67408fff,
            _ => unreachable!(),
        }
        let failed = require_failure(
            quiescent::plan_adjacent_b2_with_emission_after(
                [l, u],
                &emission,
                &original,
                &[],
                limited,
            ),
            Refusal::AllocationUnavailable,
            PairStop::Exhausted,
            PairStage::Aggregate,
            PairCounts {
                upper: 2,
                lower: 1,
                joint: 2,
            },
            &format!("aggregate_{field}"),
            &mut negative_evidence,
        );
        negative_controls.push(ledger::Control {
            label: format!("aggregate_{field}"),
            upper: upper.clone(),
            lower: lower.clone(),
            occupied: emission.occupied().to_vec(),
            pending: vec![],
            budget: limited,
            failure: failed,
        });
        assert_eq!(original, before);
    }
    let mut p = Packet::default();
    p.files
        .insert("request.tsv".into(), request_text(req, state));
    p.files.insert("target.tsv".into(), f::target_text(state));
    p.files.insert("plan.tsv".into(), plan.into_bytes());
    p.files.insert("actual-plan.txt".into(),format!("Fresh actual singleton h128:\n{h128:#?}\nFresh actual singleton h0:\n{h0:#?}\nFresh lower singleton after h0:\n{low:#?}\nActual adjacent pair, including every prior attempt:\n{pair:#?}\nOriginal:\n{original:#?}\nFinal:\n{current:#?}\n{negative_evidence}").into_bytes());
    p.files
        .insert("planner-controls.tsv".into(), planner_control_manifest());
    let full_ledger = ledger::actual(
        req,
        state,
        p.file("plan.tsv"),
        ledger::Actual {
            before: &before,
            unchanged: &original,
            final_state: &current,
            singles: [&h128, &h0, &low],
            pair: &pair,
            controls: &negative_controls,
        },
    );
    p.files.insert("ledger.tsv".into(), full_ledger);
    let hs = hashes(req, state, p.file("ledger.tsv"), [&images[0], &images[1]]);
    for phase in 0..3 {
        let d = f::descriptor(req, state, phase, [images[0].len(), images[1].len()], hs);
        p.files.insert(
            format!("phase-{phase}.elf"),
            f::elf(req, phase, [&images[0], &images[1]], &d),
        );
    }
    p.files.insert("upper.bin".into(), images.remove(0));
    p.files.insert("lower.bin".into(), images.remove(0));
    p
}
fn verify_one(req: f::Request, p: &Packet) -> native::Input {
    assert!(p.children.is_empty());
    let allowed: std::collections::BTreeSet<_> = [
        "request.tsv",
        "target.tsv",
        "plan.tsv",
        "ledger.tsv",
        "actual-plan.txt",
        "planner-controls.tsv",
        "upper.bin",
        "lower.bin",
        "phase-0.elf",
        "phase-1.elf",
        "phase-2.elf",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(
        p.files
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        allowed
    );
    let state = f::parse_target(p.file("target.tsv"));
    assert_eq!(p.file("request.tsv"), request_text(req, state));
    let images = [p.file("upper.bin").to_vec(), p.file("lower.bin").to_vec()];
    for (i, upper) in [true, false].into_iter().enumerate() {
        assert_eq!(
            images[i],
            f::image_witness(req, state, upper).code.bytes,
            "independent exact helper and original branch"
        );
    }
    assert_eq!(
        p.file("plan.tsv"),
        expected_plan(req, state),
        "complete independent routes/boundaries/fields/requirements"
    );
    assert!(!p.file("actual-plan.txt").is_empty()); // Authenticated Debug diagnostics; the canonical ledger below carries semantic evidence.
    assert_eq!(p.file("planner-controls.tsv"), planner_control_manifest());
    assert_eq!(
        p.file("ledger.tsv"),
        ledger::expected(req, state, p.file("plan.tsv")),
        "complete canonical plan, chronological debit/search and control evidence"
    );
    let hs = hashes(req, state, p.file("ledger.tsv"), [&images[0], &images[1]]);
    let elves = std::array::from_fn(|phase| {
        let d = f::descriptor(req, state, phase, [images[0].len(), images[1].len()], hs);
        let expected = f::elf(req, phase, [&images[0], &images[1]], &d);
        assert_eq!(
            p.file(&format!("phase-{phase}.elf")),
            expected,
            "whole exact ELF, immutable padding, header and descriptor"
        );
        expected
    });
    native::Input {
        request: req,
        state,
        images,
        elves,
    }
}
fn campaign_tag(verified: bool) -> Vec<u8> {
    format!("LI2ADJCAMPAIGN\t2\nrequests\t4\nscenarios_per_request\t16\nphases\t3\nchild_traces_required\t192\nindependently_verified\t{verified}\nqualification_complete\tfalse\nlive_retirement\tNOT_COVERED\nEND\n").into_bytes()
}
fn verify_campaign(p: &Packet, verified: bool) {
    assert_eq!(p.files.len(), 1);
    assert_eq!(p.file("campaign.tsv"), campaign_tag(verified));
    assert_eq!(p.children.len(), 4);
    for req in f::Request::ALL {
        verify_one(req, p.children.get(&req.name()).unwrap());
    }
}
fn rejected(name: &str, call: impl FnOnce() + std::panic::UnwindSafe, report: &mut String) {
    f::expect_refusal(name, call);
    writeln!(report, "rejected\t{name}").unwrap();
}
fn controls(p: &Packet, directory: &Path, expected: &str, output: &Path) -> Packet {
    verify_campaign(p, true);
    let mut report = String::from("LI2ADJCONTROLS\t2\npositive_campaign_verified\ttrue\n");
    let mut wrong = expected.as_bytes().to_vec();
    wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
    let wrong = String::from_utf8(wrong).unwrap();
    rejected(
        "root-binding-sha256",
        || {
            read_campaign(directory, &wrong);
        },
        &mut report,
    );
    for req in f::Request::ALL {
        let positive = p.children[&req.name()].clone();
        let input = verify_one(req, &positive);
        for (n, file, at) in [
            ("image-byte", "upper.bin", 0),
            ("branch-condition", "upper.bin", input.images[0].len() - 10),
            ("branch-target", "upper.bin", input.images[0].len() - 9),
            ("image-padding", "phase-1.elf", 0x16fff),
            ("source-suffix", "phase-1.elf", 0x14703),
            ("load-offset", "phase-1.elf", 64 + 2 * 56 + 8),
            ("load-permission", "phase-1.elf", 64 + 2 * 56 + 4),
            ("journal-zero-tail", "phase-1.elf", 0x3fff),
            ("journal-overflow", "phase-1.elf", 0x3008),
            ("descriptor-tail", "phase-1.elf", 0x5ff),
            ("descriptor-overflow", "phase-1.elf", 0x44f),
            ("hook-drop", "phase-1.elf", 0x156f9),
        ] {
            let mut bad = positive.clone();
            bad.files.get_mut(file).unwrap()[at] ^= 1;
            rejected(
                &format!("{}-{n}", req.name()),
                || {
                    verify_one(req, &bad);
                },
                &mut report,
            );
        }
        let mut bypass = positive.clone();
        let call = (f::image_witness(req, input.state, true).call - f::UPPER) as usize;
        assert_eq!(bypass.files["upper.bin"][call], 0xe8);
        bypass.files.get_mut("upper.bin").unwrap()[call] = 0xe9;
        rejected(
            &format!("{}-helper-call-bypass", req.name()),
            || {
                verify_one(req, &bypass);
            },
            &mut report,
        );
        for token in [
            "boundary\t0\t",
            "route\t0\t",
            "field\t0\t",
            "requirement\t0\t",
        ] {
            let mut bad = positive.clone();
            let text = String::from_utf8(bad.files["plan.tsv"].clone()).unwrap();
            let changed = text
                .lines()
                .filter(|l| !l.starts_with(token))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            assert_ne!(changed.as_bytes(), positive.file("plan.tsv"));
            bad.files.insert("plan.tsv".into(), changed.into_bytes());
            rejected(
                &format!("{}-missing-{token:?}", req.name()),
                || {
                    verify_one(req, &bad);
                },
                &mut report,
            );
        }
        for token in [
            "head\t",
            "occupied\t",
            "external_pending\t",
            "allocation\t",
            "pair_budget\t",
        ] {
            let mut bad = positive.clone();
            let text = String::from_utf8(bad.files["request.tsv"].clone()).unwrap();
            let changed = text.replacen(token, "forged\t", 1);
            assert_ne!(changed, text);
            bad.files.insert("request.tsv".into(), changed.into_bytes());
            rejected(
                &format!("{}-request-{token:?}", req.name()),
                || {
                    verify_one(req, &bad);
                },
                &mut report,
            );
        }
        for mutation in 0..5 {
            let mut bad = positive.clone();
            let text = String::from_utf8(positive.file("ledger.tsv").to_vec()).unwrap();
            let changed = match mutation {
                0 => "x".to_string(),
                1 => text[..text.len() / 2].to_string(),
                2 => text.replacen(
                    "event\t1\tupper-leaf\taccepted\t0\t0\t0\t1\t0\t0",
                    "event\t1\tupper-leaf\taccepted\t0\t0\t0\t0\t0\t0",
                    1,
                ),
                3 => {
                    text.lines()
                        .filter(|line| !line.starts_with("event\t1\t"))
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n"
                }
                _ => text.replacen("proof\tpages\t2\t-\t1", "proof\tpages\t1\t-\t1", 1),
            };
            assert!(!changed.is_empty());
            assert_ne!(changed.as_bytes(), positive.file("ledger.tsv"));
            bad.files.insert("ledger.tsv".into(), changed.into_bytes());
            // Rebind descriptor hashes so refusal must establish ledger semantics.
            let hs = hashes(
                req,
                input.state,
                bad.file("ledger.tsv"),
                [&input.images[0], &input.images[1]],
            );
            for phase in 0..3 {
                let d = f::descriptor(
                    req,
                    input.state,
                    phase,
                    [input.images[0].len(), input.images[1].len()],
                    hs,
                );
                bad.files.insert(
                    format!("phase-{phase}.elf"),
                    f::elf(req, phase, [&input.images[0], &input.images[1]], &d),
                );
            }
            rejected(
                &format!("{}-ledger-{mutation}", req.name()),
                || {
                    verify_one(req, &bad);
                },
                &mut report,
            );
        }
        let mut bad = positive.clone();
        bad.files.insert("extra.bin".into(), vec![0]);
        rejected(
            &format!("{}-extra-member", req.name()),
            || {
                verify_one(req, &bad);
            },
            &mut report,
        );
    }
    let mut maps = String::new();
    for &(offset, pc, len, flags) in &f::LOADS {
        writeln!(
            maps,
            "{pc:x}-{:x} {} {offset:08x} 00:01 7 /fixture",
            pc + len,
            match flags {
                4 => "r--p",
                5 => "r-xp",
                6 => "rw-p",
                _ => unreachable!(),
            }
        )
        .unwrap();
    }
    f::close_owners(&maps, 7);
    report.push_str("positive_owner_closure\ttrue\n");
    for (name, extra) in [
        (
            "unknown-anonymous-executable",
            "80000000-80001000 r-xp 00000000 00:00 0\n",
        ),
        (
            "extra-own-file-page",
            "80000000-80001000 r--p 00018000 00:01 7 /fixture\n",
        ),
        (
            "foreign-file-owner",
            "80000000-80001000 r--p 00000000 00:02 8 /other\n",
        ),
        (
            "inode-zero-file-owner",
            "80000000-80001000 r--p 00000000 00:00 0 /inode-zero-file\n",
        ),
    ] {
        let bad = format!("{maps}{extra}");
        rejected(name, || f::close_owners(&bad, 7), &mut report);
    }
    admission_controls::run(p, output, &mut report);
    report.push_str("original_structural_refusals\t97\nadded_ledger_refusals\t20\nadded_filesystem_refusals\t33\nstructural_refusals_total\t150\n");
    report.push_str("execution_scope\tstructural_hostile_controls_only\nstate_log_and_native_controls\tSEPARATE_REQUIRED_RUN\nqualification_complete\tfalse\nEND\n");
    let mut result = Packet::default();
    result
        .files
        .insert("controls.tsv".into(), report.into_bytes());
    result
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert!(args.len() >= 3);
    let command = args[1].to_str().unwrap();
    if command == "target" {
        assert_eq!(args.len(), 3);
        let mut p = Packet::default();
        p.files
            .insert("target.tsv".into(), native::target_manifest());
        println!("{}", close_packet(&p, Path::new(&args[2]), Tree::Single));
        return;
    }
    assert_eq!(
        args.len(),
        5,
        "COMMAND INPUT_DIRECTORY INPUT_BINDING_SHA256 NEW_OUTPUT_DIRECTORY"
    );
    let directory = Path::new(&args[2]);
    let expected = args[3].to_str().unwrap();
    let output = PathBuf::from(&args[4]);
    assert!(!output.exists());
    match command {
        "produce" => {
            let mut budget = Budget::for_tree(Tree::Single);
            let target = read_packet(directory, expected, Tree::Single, 0, &mut budget);
            assert_eq!(budget.nodes, 0);
            assert!(target.children.is_empty() && target.files.len() == 1);
            let state = f::parse_target(target.file("target.tsv"));
            let mut p = Packet::default();
            p.files.insert("campaign.tsv".into(), campaign_tag(false));
            for req in f::Request::ALL {
                p.children.insert(req.name(), produce_one(req, state));
            }
            println!("{}", close_packet(&p, &output, Tree::Campaign));
        }
        "verify" => {
            let mut p = read_campaign(directory, expected);
            verify_campaign(&p, false);
            p.files.insert("campaign.tsv".into(), campaign_tag(true));
            println!("{}", close_packet(&p, &output, Tree::Campaign));
        }
        "controls" => {
            let p = read_campaign(directory, expected);
            std::fs::create_dir(&output).unwrap();
            let result = controls(&p, directory, expected, &output);
            println!("{}", close_in_empty(&result, &output));
        }
        "run" => {
            let p = read_campaign(directory, expected);
            verify_campaign(&p, true);
            std::fs::create_dir(&output).unwrap();
            for req in f::Request::ALL {
                let input = verify_one(req, &p.children[&req.name()]);
                native::run(input, &output.join(req.name()));
            }
            write_new(&output.join("campaign.tsv"),b"LI2ADJNATIVE\t2\nrequests\t4\nscenarios\t64\nchild_traces\t192\nhook_call_ret_events\t40\nrecorded_events\t20\nstate_mutants\t368\nimmutable_page_mutants\t24\njournal_mutants\t22\nqualification_complete\tfalse\nlive_retirement\tNOT_COVERED\nstatus\tpassed\n");
            println!("{}", close_captures(&output));
        }
        _ => panic!("target, produce, verify, controls or run only"),
    }
}
