//! Canonical actual facts and separately authored finite expectations.
//! No planner calls; no Debug parsing; native expected state never comes from here.
use super::{allocation, digest, f, occupancy, range, request_text};
use liteinst2::bundle::BundleBudget;
use liteinst2::composition::Composition;
use liteinst2::contracts::{
    AddressRange, ApplicationProfile, EntryCompleteness, EntryObligation, EntryProvenance,
    PlanKind, Refusal, ResumeObligation,
};
use liteinst2::emission::{
    ArtifactFieldEncoding, ArtifactImageView, ArtifactMetrics, ArtifactPlan, ArtifactRequirement,
};
use liteinst2::engine::{self, Tactic};
use liteinst2::quiescent::{
    AdjacentB2ArtifactPlan, AdjacentB2Budget, AdjacentB2Failure, AllocationPolicy, PairEvidence,
    PairOutcome, PairSchedule, PairStage, PairStop, PatchTactic, PlanMetrics, SiteAttempt,
};
use liteinst2::search::{CandidateProof, RefusalClass, SearchDomain, SearchEvidence, SearchStop};
use liteinst2::trampoline::SavedExtendedStateLayout;
use std::fmt::Write as _;

macro_rules! row {
    ($out:expr, $tag:expr $(, $value:expr)* $(,)?) => {{
        write!($out, "{}", $tag).unwrap();
        $( { let field = ($value).to_string(); assert!(!field.bytes().any(|c| b"\t\n\r".contains(&c))); write!($out, "\t{field}").unwrap(); } )*
        $out.push('\n');
    }};
}
fn option<T: ToString>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
}
fn reason(value: &Refusal) -> &'static str {
    match value {
        Refusal::AllocationUnavailable => "allocation",
        Refusal::OwnershipConflict => "ownership",
        _ => panic!("outside frozen refusal vocabulary"),
    }
}
fn stage(value: PairStage) -> &'static str {
    match value {
        PairStage::Preflight => "preflight",
        PairStage::UpperLeaf => "upper-leaf",
        PairStage::UpperAppend => "upper-append",
        PairStage::UpperPending => "upper-pending",
        PairStage::LowerSchedule => "lower-schedule",
        PairStage::LowerLeaf => "lower-leaf",
        PairStage::LowerAppend => "lower-append",
        PairStage::LowerPending => "lower-pending",
        PairStage::Aggregate => "aggregate",
    }
}
fn proof(out: &mut String, value: Option<&CandidateProof>) {
    match value {
        None => row!(out, "proof", "none"),
        Some(CandidateProof::Indexed {
            permanent_end_exclusive,
            omitted,
        }) => {
            row!(
                out,
                "proof",
                "indexed",
                option(*permanent_end_exclusive),
                option(omitted.map(|w| w.slot)),
                option(omitted.map(|w| w.target))
            );
        }
        Some(CandidateProof::PageBoundary {
            returned,
            omitted,
            walks,
        }) => {
            row!(
                out,
                "proof",
                "pages",
                returned,
                option(*omitted),
                walks.len()
            );
            for (i, walk) in walks.iter().enumerate() {
                row!(
                    out,
                    "walk",
                    i,
                    walk.range_index,
                    walk.finite_slots,
                    walk.examined
                );
            }
        }
    }
}
fn search(out: &mut String, value: &SearchEvidence) {
    row!(
        out,
        "search",
        value.accepted,
        value.classification_complete,
        value.runs.len(),
        value.refusals.len()
    );
    for (i, run) in value.runs.iter().enumerate() {
        assert_eq!(run.domain, SearchDomain::SelectedImages);
        let (stop, remaining) = match run.stop {
            SearchStop::Accepted => ("accepted", None),
            SearchStop::DomainComplete => ("complete", None),
            SearchStop::BudgetLimited { remaining_at_least } => {
                ("budget", Some(remaining_at_least))
            }
            SearchStop::UnclassifiedBoundedStop => ("unclassified", None),
            SearchStop::Interrupted => ("interrupted", None),
        };
        row!(
            out,
            "run",
            i,
            "selected-images",
            option(run.scope.physical_pc),
            option(run.scope.victim_target),
            option(run.scope.prefix_count),
            run.limit,
            run.examined,
            option(run.finite_total),
            stop,
            option(remaining)
        );
        proof(out, run.candidates.as_ref());
    }
    for (i, refusal) in value.refusals.iter().enumerate() {
        let class = match refusal.class {
            RefusalClass::UnsupportedSemantics => "unsupported",
            RefusalClass::Prerequisite => "prerequisite",
            RefusalClass::ResourceCapacity => "capacity",
            RefusalClass::AddressPolicy => "address",
            RefusalClass::Backend => "backend",
            RefusalClass::Unclassified => "unclassified",
        };
        row!(
            out,
            "refusal",
            i,
            reason(&refusal.reason),
            class,
            option(refusal.scope.physical_pc),
            option(refusal.scope.victim_target),
            option(refusal.scope.prefix_count)
        );
    }
}
fn expected_search(out: &mut String, pc: u64, limit: usize, refused: bool) {
    row!(out, "search", !refused, false, 1, usize::from(refused));
    row!(
        out,
        "run",
        0,
        "selected-images",
        pc,
        "-",
        0,
        limit,
        1,
        "-",
        if refused { "complete" } else { "accepted" },
        "-"
    );
    if refused {
        row!(out, "proof", "indexed", 1, "-", "-");
        row!(out, "refusal", 0, "allocation", "address", pc, "-", 0);
    } else {
        row!(out, "proof", "none");
    }
}
fn attempts(out: &mut String, items: &[SiteAttempt]) {
    row!(out, "site-attempts", items.len());
    for (i, attempt) in items.iter().enumerate() {
        assert_eq!(attempt.tactic, PatchTactic::GeneralizedPun);
        row!(
            out,
            "site",
            i,
            "b2",
            attempt.physical_pc,
            attempt.refusal.as_ref().map(reason).unwrap_or("-")
        );
    }
}
fn metrics(out: &mut String, m: &PlanMetrics) {
    row!(
        out,
        "metrics",
        m.upstream_bytes,
        m.displaced_bytes,
        m.prefix_instructions,
        m.allocation_attempts
    );
    search(out, &m.search);
    attempts(out, &m.attempts);
}
// Field roles are already typed String data in ArtifactField, so they are
// encoded byte-for-byte as hex. Enum names below are stable schema tags, never
// Debug output. The old plan index remains separately verified and hash-bound.
fn actual_image(out: &mut String, image: ArtifactImageView<'_>) {
    row!(
        out,
        "image",
        image.address(),
        f::hex(image.bytes()),
        image.metadata().qualification_complete()
    );
    row!(out, "routes", image.entry_routes().len());
    for &(logical, generated) in image.entry_routes() {
        row!(out, "route", logical, generated);
    }
    row!(out, "boundaries", image.instruction_boundaries().len());
    for &(logical, generated) in image.instruction_boundaries() {
        row!(out, "boundary", logical, generated);
    }
    row!(out, "pc-ranges", image.program_counter_mappings().len());
    for p in image.program_counter_mappings() {
        row!(
            out,
            "pc-range",
            p.generated_start(),
            p.generated_end(),
            p.logical_address()
        );
    }
    let mut fields: Vec<_> = image.metadata().fields().iter().collect();
    fields.sort_by_key(|field| field.offset);
    row!(out, "fields", fields.len());
    for field in fields {
        let encoding = match field.encoding {
            ArtifactFieldEncoding::Relative => "relative",
            ArtifactFieldEncoding::Delta => "delta",
        };
        row!(
            out,
            "field",
            field.offset,
            field.width,
            encoding,
            field.origin,
            field.target,
            field.bias_domain,
            f::hex(field.role.as_bytes())
        );
    }
    row!(out, "requirements", image.metadata().requirements().len());
    for requirement in image.metadata().requirements() {
        let (tag, hook) = match requirement {
            ArtifactRequirement::ArtifactIdentityAndAddressBinding => ("identity-address", None),
            ArtifactRequirement::TargetCpuAndStateAtEntry => ("target-state", None),
            ArtifactRequirement::OriginalDynamicRelocationOwnership => ("dynamic-relocation", None),
            ArtifactRequirement::OriginalImmediatePointerProvenance => {
                ("immediate-provenance", None)
            }
            ArtifactRequirement::HookAbiAndReadiness(id) => ("hook-readiness", Some(*id)),
            ArtifactRequirement::EntryRouterBootstrap => ("entry-router", None),
            ArtifactRequirement::GeneratedUnwindInformation => ("generated-unwind", None),
            ArtifactRequirement::OriginalCodeAsDataContract => ("code-as-data", None),
        };
        row!(out, "requirement", tag, option(hook));
    }
}
fn expected_image(out: &mut String, w: &f::ImageWitness) {
    let base = w.code.base;
    let end = base + w.code.bytes.len() as u64;
    row!(out, "image", base, f::hex(&w.code.bytes), false);
    row!(out, "routes", 1);
    row!(out, "route", w.logical, base);
    row!(out, "boundaries", 1);
    row!(out, "boundary", w.logical, w.body);
    row!(out, "pc-ranges", 2);
    row!(out, "pc-range", base, w.body + 6, w.logical);
    row!(out, "pc-range", w.body + 6, end, w.logical + 2);
    row!(out, "fields", 4);
    for (offset, width, encoding, origin, target, role) in [
        (52, 8, "delta", 50, w.logical, "LogicalPc".to_string()),
        (
            w.call - base + 1,
            4,
            "relative",
            w.returned - base,
            f::HOOK,
            "HookCall".to_string(),
        ),
        (
            w.body - base + 2,
            4,
            "relative",
            w.body - base + 6,
            w.branch_target,
            format!("OriginalBranch {{ original_pc: {} }}", w.logical),
        ),
        (
            w.body - base + 7,
            4,
            "relative",
            w.body - base + 11,
            w.logical + 2,
            "Return".to_string(),
        ),
    ] {
        row!(
            out,
            "field",
            offset,
            width,
            encoding,
            origin,
            target,
            7,
            f::hex(role.as_bytes())
        );
    }
    row!(out, "requirements", 7);
    for tag in [
        "identity-address",
        "target-state",
        "dynamic-relocation",
        "immediate-provenance",
        "generated-unwind",
        "code-as-data",
    ] {
        row!(out, "requirement", tag, "-");
    }
    row!(out, "requirement", "hook-readiness", 11);
}
fn actual_plan(out: &mut String, label: &str, p: &ArtifactPlan) {
    row!(
        out,
        "plan",
        label,
        p.source_steps().len(),
        p.images().count(),
        p.qualification_complete()
    );
    for (i, plan) in p.source_steps().iter().enumerate() {
        let p = plan.parts();
        assert_eq!(p.profile, ApplicationProfile::InstallOnce);
        row!(
            out,
            "source",
            i,
            f::hex(&p.identity.source.0),
            p.identity.mapping,
            p.identity.generation,
            "install-once",
            p.logical_pc,
            p.physical_pc,
            p.displaced.start(),
            p.displaced.len()
        );
        let PlanKind::GeneralizedPun(k) = &p.kind else {
            panic!("B2 only")
        };
        row!(
            out,
            "pun",
            k.instruction_len,
            k.consumed.start(),
            k.consumed.len(),
            k.target_window.start(),
            k.target_window.len(),
            k.store.address,
            f::hex(&k.store.bytes)
        );
        row!(out, "reads", p.reads.len());
        for r in &p.reads {
            row!(out, "read", r.address, f::hex(&r.bytes));
        }
        row!(out, "writes", p.writes.len());
        for r in &p.writes {
            row!(out, "write", r.address, f::hex(&r.bytes));
        }
        row!(out, "dependencies", p.dependencies.len());
        for r in &p.dependencies {
            row!(out, "dependency", r.start(), r.len());
        }
        let e = &p.entries;
        let EntryProvenance::Declared(provenance) = &e.provenance else {
            panic!("declared fixture entries")
        };
        assert_eq!(e.completeness, EntryCompleteness::AllInstructionHeads);
        assert_eq!(e.resumes, ResumeObligation::NoneExist);
        row!(
            out,
            "entries",
            f::hex(&e.identity.source.0),
            e.identity.mapping,
            e.identity.generation,
            e.scope.start(),
            e.scope.len(),
            "declared",
            f::hex(provenance.as_bytes()),
            "all-heads",
            "none",
            e.entries.len()
        );
        for entry in &e.entries {
            row!(out, "entry", entry.address, entry.requires_endbr);
        }
        row!(out, "obligations", p.obligations.len());
        for o in &p.obligations {
            let EntryObligation::Preserved(pc) = o else {
                panic!("preserved only")
            };
            row!(out, "preserved", pc);
        }
        row!(out, "allocations", p.allocations.len());
        for a in &p.allocations {
            row!(
                out,
                "allocation",
                a.range.start(),
                a.range.len(),
                a.alignment
            );
        }
        row!(out, "generated", p.generated.len());
        for g in &p.generated {
            row!(
                out,
                "generated-bytes",
                g.address,
                f::hex(&g.bytes),
                g.program_counters.len()
            );
            for m in &g.program_counters {
                row!(
                    out,
                    "generated-pc",
                    m.generated_start(),
                    m.generated_end(),
                    m.logical_address()
                );
            }
        }
        row!(
            out,
            "publication",
            p.requirements.quiescent,
            p.requirements.sync_core,
            p.requirements.sigill_router
        );
    }
    for image in p.images() {
        actual_image(out, image);
    }
    match p.metrics() {
        ArtifactMetrics::Single(m) => {
            row!(out, "metrics-kind", "single");
            metrics(out, m);
        }
        ArtifactMetrics::Engine(tactic, engine::SelectedMetrics::Single(m), outer) => {
            assert_eq!(*tactic, Tactic::GeneralizedPun);
            row!(out, "metrics-kind", "engine-b2", outer.len());
            metrics(out, m);
            for (i, attempt) in outer.iter().enumerate() {
                assert_eq!(attempt.tactic, Tactic::GeneralizedPun);
                row!(
                    out,
                    "engine-attempt",
                    i,
                    "b2",
                    attempt.refusal.as_ref().map(reason).unwrap_or("-"),
                    attempt.outer_refusal.is_some()
                );
                assert!(
                    attempt.outer_refusal.is_none(),
                    "mandatory accepted singleton has no outer refusal"
                );
                search(out, &attempt.search);
                let engine::CandidateEvidence::Single(candidates) = &attempt.candidates else {
                    panic!("B2 candidates")
                };
                attempts(out, candidates);
            }
        }
        _ => panic!("frozen B2 metrics variant"),
    }
    row!(out, "end-plan", label);
}
fn expected_plan_facts(
    out: &mut String,
    label: &str,
    req: f::Request,
    state: SavedExtendedStateLayout,
    upper: bool,
    address: u64,
    engine: bool,
) {
    let pc = f::B + if upper { 2 } else { 0 };
    let w = f::image_witness_at(req, state, upper, address);
    let mut source = req.source();
    if !upper {
        source[2..4].copy_from_slice(&[0xe9, 0]);
    }
    let write = if upper {
        vec![0xe9, (address - f::UPPER) as u8]
    } else {
        vec![0xe9, 2]
    };
    row!(out, "plan", label, 1, 1, false);
    row!(
        out,
        "source",
        0,
        digest(&req.source()),
        1,
        1,
        "install-once",
        pc,
        pc,
        pc,
        2
    );
    row!(
        out,
        "pun",
        2,
        pc,
        5,
        if upper { f::UPPER } else { f::LOWER - 2 },
        256,
        pc,
        f::hex(&write)
    );
    row!(out, "reads", 1);
    row!(out, "read", f::B, f::hex(&source));
    row!(out, "writes", 1);
    row!(out, "write", pc, f::hex(&write));
    row!(out, "dependencies", 1);
    row!(out, "dependency", f::B, 11);
    row!(
        out,
        "entries",
        digest(&req.source()),
        1,
        1,
        f::B,
        11,
        "declared",
        f::hex(b"adjacent-b2-native-v2"),
        "all-heads",
        "none",
        4
    );
    for entry in f::HEADS {
        row!(out, "entry", entry, false);
    }
    let preserved: Vec<_> = f::HEADS
        .iter()
        .copied()
        .filter(|&head| pc <= head && head < pc + 5)
        .collect();
    row!(out, "obligations", preserved.len());
    for p in preserved {
        row!(out, "preserved", p);
    }
    row!(out, "allocations", 1);
    row!(out, "allocation", address & !4095, 4096, 4096);
    row!(out, "generated", 1);
    row!(out, "generated-bytes", address, f::hex(&w.code.bytes), 2);
    row!(out, "generated-pc", address, w.body + 6, pc);
    row!(
        out,
        "generated-pc",
        w.body + 6,
        address + w.code.bytes.len() as u64,
        pc + 2
    );
    row!(out, "publication", true, true, false);
    expected_image(out, &w);
    if engine {
        row!(out, "metrics-kind", "engine-b2", 1);
    } else {
        row!(out, "metrics-kind", "single");
    }
    row!(out, "metrics", 0, 2, 0, 1);
    expected_search(out, pc, if upper { 2 } else { 1 }, false);
    row!(out, "site-attempts", usize::from(engine));
    if engine {
        row!(out, "site", 0, "b2", pc, "-");
    }
    if engine {
        row!(out, "engine-attempt", 0, "b2", "-", false);
        expected_search(out, pc, if upper { 2 } else { 1 }, false);
        row!(out, "site-attempts", 1);
        row!(out, "site", 0, "b2", pc, "-");
    }
    row!(out, "end-plan", label);
}
fn schedule(out: &mut String, label: &str, s: &PairSchedule) {
    row!(
        out,
        "schedule",
        label,
        option(s.upper_ordinal),
        option(s.upper_target),
        s.window.start(),
        s.window.len(),
        s.targets.len()
    );
    for (i, target) in s.targets.iter().enumerate() {
        row!(out, "target", i, target);
    }
    proof(out, Some(&s.proof));
}
fn evidence(out: &mut String, value: &PairEvidence) {
    row!(
        out,
        "evidence",
        value.lower_pc,
        value.upper_pc,
        value.counts.upper,
        value.counts.lower,
        value.counts.joint,
        value.accepted,
        value.classification_complete,
        value.events.len(),
        value.upper_schedule.is_some(),
        value.lower_schedules.len()
    );
    if let Some(s) = &value.upper_schedule {
        schedule(out, "upper", s);
    }
    for (i, s) in value.lower_schedules.iter().enumerate() {
        schedule(out, &format!("lower-{i}"), s);
    }
    for (i, event) in value.events.iter().enumerate() {
        let outcome = match &event.outcome {
            PairOutcome::LocalAccepted => "accepted",
            PairOutcome::EmptySchedule => "empty",
            PairOutcome::Refused(r) => reason(r),
        };
        row!(
            out,
            "event",
            i,
            stage(event.stage),
            outcome,
            event.counters_before.upper,
            event.counters_before.lower,
            event.counters_before.joint,
            event.counters_after.upper,
            event.counters_after.lower,
            event.counters_after.joint,
            option(event.upper_ordinal),
            option(event.upper_target),
            option(event.lower_ordinal),
            option(event.lower_target),
            event.search.is_some()
        );
        if let Some(s) = &event.search {
            search(out, s);
        }
    }
}
#[derive(Clone)]
pub(super) struct Control {
    pub label: String,
    pub upper: AllocationPolicy,
    pub lower: AllocationPolicy,
    pub occupied: Vec<AddressRange>,
    pub pending: Vec<AddressRange>,
    pub budget: AdjacentB2Budget,
    pub failure: AdjacentB2Failure,
}
fn config(
    out: &mut String,
    upper: &AllocationPolicy,
    lower: &AllocationPolicy,
    occupied: &[AddressRange],
    pending: &[AddressRange],
    budget: AdjacentB2Budget,
) {
    for (label, a) in [("upper", upper), ("lower", lower)] {
        row!(
            out,
            "policy",
            label,
            option(a.preferred_address),
            a.max_candidates,
            a.max_mappings,
            a.max_mapped_bytes,
            a.ranges.len()
        );
        for r in &a.ranges {
            row!(out, "permit", r.start(), r.len());
        }
    }
    row!(out, "occupied", occupied.len());
    for r in occupied {
        row!(out, "owner", r.start(), r.len());
    }
    row!(out, "pending", pending.len());
    for r in pending {
        row!(out, "range", r.start(), r.len());
    }
    let b = budget.bundle;
    row!(
        out,
        "budget",
        budget.max_continuations,
        b.max_steps,
        b.max_mappings,
        b.max_virtual_bytes,
        b.max_backing_bytes,
        b.max_virtual_span
    );
}
fn prefix(req: f::Request, state: SavedExtendedStateLayout, plan: &[u8]) -> String {
    let mut out = String::new();
    row!(out, "LI2ADJLEDGER", 1);
    row!(out, "request", digest(&request_text(req, state)));
    row!(out, "plan-index", digest(plan));
    row!(out, "target", digest(&f::target_text(state)));
    row!(out, "hook", 11, f::HOOK);
    out
}
pub(super) struct Actual<'a> {
    pub before: &'a Composition,
    pub unchanged: &'a Composition,
    pub final_state: &'a Composition,
    pub singles: [&'a ArtifactPlan; 3],
    pub pair: &'a AdjacentB2ArtifactPlan,
    pub controls: &'a [Control],
}
pub(super) fn actual(
    req: f::Request,
    state: SavedExtendedStateLayout,
    plan: &[u8],
    actual: Actual<'_>,
) -> Vec<u8> {
    let Actual {
        before,
        unchanged,
        final_state,
        singles,
        pair,
        controls,
    } = actual;
    let mut out = prefix(req, state, plan);
    row!(out, "predecessor-unchanged", before == unchanged);
    for (label, values) in [
        ("original", before.originals()),
        ("initial-final", before.final_bytes()),
        ("final", final_state.final_bytes()),
    ] {
        row!(out, label, values.len());
        for value in values {
            row!(out, "bytes", value.address, f::hex(&value.bytes));
        }
    }
    row!(out, "initial-locks", before.locks().len());
    for r in before.locks() {
        row!(out, "lock", r.start(), r.len());
    }
    row!(out, "final-locks", final_state.locks().len());
    for r in final_state.locks() {
        row!(out, "lock", r.start(), r.len());
    }
    row!(out, "plans", 5);
    for (label, p) in ["singleton-h128", "singleton-h0", "singleton-lower"]
        .into_iter()
        .zip(singles)
    {
        actual_plan(&mut out, label, p);
    }
    for (label, p) in ["pair-upper", "pair-lower"].into_iter().zip(pair.members()) {
        actual_plan(&mut out, label, p);
    }
    let m = pair.memory();
    row!(
        out,
        "pair",
        pair.logical_pcs()[0],
        pair.logical_pcs()[1],
        m.mappings,
        m.virtual_pages,
        m.backing_pages,
        m.virtual_bytes,
        m.backing_bytes,
        m.virtual_span,
        pair.qualification_complete()
    );
    evidence(&mut out, pair.evidence());
    row!(out, "controls", controls.len());
    for (i, c) in controls.iter().enumerate() {
        row!(out, "control", i, &c.label);
        config(
            &mut out,
            &c.upper,
            &c.lower,
            &c.occupied,
            &c.pending,
            c.budget,
        );
        let f = &c.failure;
        let stop = match f.stop {
            PairStop::UpperScheduleBudget => "upper-schedule-budget",
            PairStop::Exhausted => "exhausted",
            _ => panic!("frozen stop"),
        };
        row!(
            out,
            "terminal",
            reason(&f.reason),
            stop,
            stage(f.stage),
            option(f.unvisited_target)
        );
        evidence(&mut out, &f.evidence);
    }
    row!(out, "END");
    assert!(out.len() <= f::LIMIT);
    out.into_bytes()
}

// A fixed authored inventory, not a replay of the planner. Event indices and
// before/after counters are explicit; omission/reordering cannot compare equal.
fn expected_schedule(
    out: &mut String,
    label: &str,
    upper: Option<usize>,
    window: u64,
    targets: &[u64],
    omitted: Option<u64>,
    finite: usize,
) {
    let conditioning = upper.map(|i| if i == 0 { f::UPPER + 128 } else { f::UPPER });
    row!(
        out,
        "schedule",
        label,
        option(upper),
        option(conditioning),
        window,
        256,
        targets.len()
    );
    for (i, pc) in targets.iter().enumerate() {
        row!(out, "target", i, pc);
    }
    row!(out, "proof", "pages", targets.len(), option(omitted), 1);
    row!(out, "walk", 0, 0, finite, finite);
}
// Cases: 0 accepted; 1 cap-one; 2 occupied-upper; 3 short-lower;
// 4 pending-IMUL; 5 aggregate capacity refusal (five separately bound requests).
fn expected_evidence(out: &mut String, case: usize) {
    let counts = match case {
        1 => (1, 0, 1),
        2 | 4 => (2, 0, 0),
        _ => (2, 1, 2),
    };
    let count_events = match case {
        1 => 5,
        2 => 3,
        3 => 10,
        4 => 7,
        _ => 13,
    };
    let lower_schedules = match case {
        1 => 1,
        2 | 4 => 0,
        _ => 2,
    };
    row!(
        out,
        "evidence",
        f::B,
        f::B + 2,
        counts.0,
        counts.1,
        counts.2,
        case == 0,
        false,
        count_events,
        true,
        lower_schedules
    );
    expected_schedule(
        out,
        "upper",
        None,
        f::UPPER,
        if case == 1 {
            &[f::UPPER + 128]
        } else {
            &[f::UPPER + 128, f::UPPER]
        },
        if case == 1 { Some(f::UPPER) } else { None },
        1,
    );
    if lower_schedules > 0 {
        expected_schedule(out, "lower-0", Some(0), 0x7980effe, &[], None, 0);
    }
    if lower_schedules > 1 {
        expected_schedule(out, "lower-1", Some(1), f::LOWER - 2, &[f::LOWER], None, 1);
    }
    // stage, outcome, before(U,L,J), after(U,L,J), upper ordinal, lower ordinal.
    type E = (
        &'static str,
        &'static str,
        (usize, usize, usize),
        (usize, usize, usize),
        Option<usize>,
        Option<usize>,
    );
    let mut events: Vec<E> = vec![("preflight", "accepted", (0, 0, 0), (0, 0, 0), None, None)];
    if case == 2 {
        events.extend([
            (
                "upper-leaf",
                "allocation",
                (0, 0, 0),
                (1, 0, 0),
                Some(0),
                None,
            ),
            (
                "upper-leaf",
                "allocation",
                (1, 0, 0),
                (2, 0, 0),
                Some(1),
                None,
            ),
        ]);
    } else if case == 4 {
        events.extend([
            (
                "upper-leaf",
                "accepted",
                (0, 0, 0),
                (1, 0, 0),
                Some(0),
                None,
            ),
            (
                "upper-append",
                "accepted",
                (1, 0, 0),
                (1, 0, 0),
                Some(0),
                None,
            ),
            (
                "upper-pending",
                "ownership",
                (1, 0, 0),
                (1, 0, 0),
                Some(0),
                None,
            ),
            (
                "upper-leaf",
                "accepted",
                (1, 0, 0),
                (2, 0, 0),
                Some(1),
                None,
            ),
            (
                "upper-append",
                "accepted",
                (2, 0, 0),
                (2, 0, 0),
                Some(1),
                None,
            ),
            (
                "upper-pending",
                "ownership",
                (2, 0, 0),
                (2, 0, 0),
                Some(1),
                None,
            ),
        ]);
    } else {
        events.extend([
            (
                "upper-leaf",
                "accepted",
                (0, 0, 0),
                (1, 0, 0),
                Some(0),
                None,
            ),
            (
                "upper-append",
                "accepted",
                (1, 0, 0),
                (1, 0, 0),
                Some(0),
                None,
            ),
            (
                "upper-pending",
                "accepted",
                (1, 0, 0),
                (1, 0, 0),
                Some(0),
                None,
            ),
            (
                "lower-schedule",
                "empty",
                (1, 0, 0),
                (1, 0, 1),
                Some(0),
                None,
            ),
        ]);
        if case != 1 {
            events.extend([
                (
                    "upper-leaf",
                    "accepted",
                    (1, 0, 1),
                    (2, 0, 1),
                    Some(1),
                    None,
                ),
                (
                    "upper-append",
                    "accepted",
                    (2, 0, 1),
                    (2, 0, 1),
                    Some(1),
                    None,
                ),
                (
                    "upper-pending",
                    "accepted",
                    (2, 0, 1),
                    (2, 0, 1),
                    Some(1),
                    None,
                ),
                (
                    "lower-schedule",
                    "accepted",
                    (2, 0, 1),
                    (2, 0, 2),
                    Some(1),
                    None,
                ),
                (
                    "lower-leaf",
                    if case == 3 { "allocation" } else { "accepted" },
                    (2, 0, 2),
                    (2, 1, 2),
                    Some(1),
                    Some(0),
                ),
            ]);
            if case != 3 {
                events.extend([
                    (
                        "lower-append",
                        "accepted",
                        (2, 1, 2),
                        (2, 1, 2),
                        Some(1),
                        Some(0),
                    ),
                    (
                        "lower-pending",
                        "accepted",
                        (2, 1, 2),
                        (2, 1, 2),
                        Some(1),
                        Some(0),
                    ),
                    (
                        "aggregate",
                        if case == 5 { "allocation" } else { "accepted" },
                        (2, 1, 2),
                        (2, 1, 2),
                        Some(1),
                        Some(0),
                    ),
                ]);
            }
        }
    }
    assert_eq!(events.len(), count_events);
    for (i, (stage, outcome, before, after, upper, lower)) in events.into_iter().enumerate() {
        let leaf = stage == "upper-leaf" || stage == "lower-leaf";
        row!(
            out,
            "event",
            i,
            stage,
            outcome,
            before.0,
            before.1,
            before.2,
            after.0,
            after.1,
            after.2,
            option(upper),
            option(upper.map(|u| if u == 0 { f::UPPER + 128 } else { f::UPPER })),
            option(lower),
            option(lower.map(|_| f::LOWER)),
            leaf
        );
        if leaf {
            expected_search(
                out,
                if stage == "upper-leaf" {
                    f::B + 2
                } else {
                    f::B
                },
                if stage == "upper-leaf" && case != 1 {
                    2
                } else {
                    1
                },
                outcome == "allocation",
            );
        }
    }
}
pub(super) fn expected(req: f::Request, state: SavedExtendedStateLayout, plan: &[u8]) -> Vec<u8> {
    let mut out = prefix(req, state, plan);
    row!(out, "predecessor-unchanged", true);
    for (label, bytes) in [
        ("original", req.source()),
        ("initial-final", req.source()),
        ("final", f::FINAL),
    ] {
        row!(out, label, 1);
        row!(out, "bytes", f::B, f::hex(&bytes));
    }
    row!(out, "initial-locks", 0);
    row!(out, "final-locks", 1);
    row!(out, "lock", f::B, 7);
    row!(out, "plans", 5);
    for (label, upper, address, engine) in [
        ("singleton-h128", true, f::UPPER + 128, true),
        ("singleton-h0", true, f::UPPER, true),
        ("singleton-lower", false, f::LOWER, true),
        ("pair-upper", true, f::UPPER, false),
        ("pair-lower", false, f::LOWER, false),
    ] {
        expected_plan_facts(&mut out, label, req, state, upper, address, engine);
    }
    row!(
        out,
        "pair",
        f::B + 2,
        f::B,
        2,
        2,
        2,
        8192,
        8192,
        1732284416_u64,
        false
    );
    expected_evidence(&mut out, 0);
    row!(out, "controls", 9);
    for i in 0..9 {
        let label = match i {
            0 => "cap_one".into(),
            1 => "occupied_upper".into(),
            2 => "short_lower_permit".into(),
            3 => "pending_imul".into(),
            _ => format!("aggregate_{}", i - 4),
        };
        row!(out, "control", i, label);
        let mut upper = allocation(true);
        let mut lower = allocation(false);
        let mut occupied = occupancy();
        let mut pending = Vec::new();
        let mut budget = AdjacentB2Budget {
            max_continuations: 2,
            bundle: BundleBudget {
                max_steps: 2,
                max_mappings: 2,
                max_virtual_bytes: 8192,
                max_backing_bytes: 8192,
                max_virtual_span: 1 << 31,
            },
        };
        match i {
            0 => {
                upper.max_candidates = 1;
                budget.max_continuations = 1;
            }
            1 => occupied.push(range(f::UPPER, 4096)),
            2 => lower.ranges = vec![range(f::LOWER, 4095)],
            3 => pending.push(range(f::B + 4, 6)),
            4 => budget.bundle.max_steps = 1,
            5 => budget.bundle.max_mappings = 1,
            6 => budget.bundle.max_virtual_bytes = 8191,
            7 => budget.bundle.max_backing_bytes = 8191,
            8 => budget.bundle.max_virtual_span = 0x67408fff,
            _ => unreachable!(),
        }
        config(&mut out, &upper, &lower, &occupied, &pending, budget);
        row!(
            out,
            "terminal",
            if i == 3 { "ownership" } else { "allocation" },
            if i == 0 {
                "upper-schedule-budget"
            } else {
                "exhausted"
            },
            match i {
                0 | 1 => "upper-leaf",
                2 => "lower-leaf",
                3 => "upper-pending",
                _ => "aggregate",
            },
            if i == 0 {
                f::UPPER.to_string()
            } else {
                "-".into()
            }
        );
        expected_evidence(&mut out, if i < 4 { i + 1 } else { 5 });
    }
    row!(out, "END");
    assert!(out.len() <= f::LIMIT);
    out.into_bytes()
}
