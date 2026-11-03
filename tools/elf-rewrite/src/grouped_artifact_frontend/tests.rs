//! Actual sealed importer, core planner and carrier controls; no generated execution.
use super::*;
use crate::disassembly::{jump_stack, whole::policy};
use li2core::quiescent::TacticPolicy;

const BASE: u64 = 0x400000;
const PC: u64 = BASE + 0x1100;
const HOOK: u64 = BASE + 0x11f00;
fn put(bytes: &mut [u8], at: usize, width: usize, value: u64) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn source(chunks: &[&[u8]]) -> (Vec<u8>, disassembly::whole::JumpStackWholeSelection) {
    let mut original = vec![0; 0x12000];
    original[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, width, value) in [
        (16, 2, 2),
        (18, 2, 62),
        (20, 4, 1),
        (24, 8, PC),
        (32, 8, 64),
        (52, 2, 64),
        (54, 2, 56),
        (56, 2, 2),
    ] {
        put(&mut original, at, width, value);
    }
    for (i, (offset, size, flags)) in [(0, 4096, 4), (4096, 0x11000, 5)].into_iter().enumerate() {
        for (field, width, value) in [
            (0, 4, 1),
            (4, 4, flags),
            (8, 8, offset),
            (16, 8, BASE + offset),
            (24, 8, BASE + offset),
            (32, 8, size),
            (40, 8, size),
            (48, 8, 4096),
        ] {
            put(&mut original, 64 + 56 * i + field, width, value);
        }
    }
    let code: Vec<_> = chunks
        .iter()
        .flat_map(|bytes| bytes.iter())
        .copied()
        .collect();
    assert!(code.len() < 0x10000);
    original[0x1100..0x1100 + code.len()].copy_from_slice(&code);
    original[0x11f00] = 0xc3;
    let mut text = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {PC} 4352 {}\n",
        ledger::hex(&ContentId::of(&original).0),
        code.len()
    );
    let mut pc = PC;
    for bytes in chunks {
        writeln!(text, "head {pc} {}", ledger::hex(bytes)).unwrap();
        pc += bytes.len() as u64;
    }
    writeln!(text, "region {HOOK} 73472 1\nhead {HOOK} c3").unwrap();
    let imported =
        jump_stack::import(&original, text.as_bytes(), ContentId::of(text.as_bytes())).unwrap();
    let mut rows = String::new();
    for site in imported.sites() {
        let id = site.geometry().id;
        writeln!(rows, "search {id} preferred 64 256 64 none 256 4096\nallocation {id} selected none 1 4096 16777216:520093696\nallocation {id} victim none 1 4096 16777216:520093696").unwrap();
    }
    let spec = policy::spec_from_jump_stack_records(
        &imported,
        &original,
        policy::PolicyOptions {
            domain: 7,
            hook: policy::NullHook::Address(HOOK),
            carrier: policy::Carrier::AfterLoads,
            arena: AddressRange::new(0x01000000, 0x1f000000).unwrap(),
        },
        b"target fxsave64\n",
        rows.as_bytes(),
    )
    .unwrap();
    let policy = policy::build_jump_stack_policy(&imported, &original, &spec).unwrap();
    let selected = imported
        .bind_whole_program(&policy, ContentId::of(&policy))
        .unwrap();
    (original, selected)
}
fn cat() -> (Vec<u8>, disassembly::whole::JumpStackWholeSelection) {
    // The actual six-POP byte sequence from CLOSED cat, plus its following RET.
    source(&[
        &[0x5b],
        &[0x5d],
        &[0x83, 0xf0, 1],
        &[0x41, 0x5c],
        &[0x41, 0x5d],
        &[0x0f, 0xb6, 0xc0],
        &[0x41, 0x5e],
        &[0x41, 0x5f],
        &[0xc3],
    ])
}
fn elf(bytes: &[u8]) -> Elf64<'_> {
    Elf64::parse(
        bytes,
        ParseLimits {
            max_program_headers: 1170,
        },
    )
    .unwrap()
}
fn draft(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
) -> adjacent_b2_frontend::SelectionDraft {
    let s = &selected.selection;
    let elf = elf(original);
    let identity = CodeIdentity {
        source: SourceIdentity(s.original.0),
        mapping: 7,
        generation: 1,
    };
    adjacent_b2_frontend::SelectionDraft {
        composition: Composition::new(identity, original_snapshots(&elf, &s.sites).unwrap())
            .unwrap(),
        pending: s
            .sites
            .iter()
            .enumerate()
            .map(|(i, s)| (i, addr(s.pc, u64::from(s.length)).unwrap()))
            .collect(),
        reports: s
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
            .collect(),
        accepted: Vec::new(),
        occupied: Vec::new(),
        dependencies: Vec::new(),
        image_count: 0,
        image_bytes: 0,
        allocation_pages: 0,
        baseline: Vec::new(),
        work: Vec::new(),
        edges: Vec::new(),
        totals: Default::default(),
        blocked_groups: Vec::new(),
        routed: Default::default(),
    }
}
fn run_group(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    schedule: &Schedule,
    draft: &mut adjacent_b2_frontend::SelectionDraft,
) -> Vec<AcceptedGroup> {
    let elf = elf(original);
    let dynamic = carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default()).unwrap();
    let identity = draft.composition.identity();
    let binding = fixed_exec::bind(&elf, identity, selected.selection.bias_domain).unwrap();
    let mut accepted = Vec::new();
    let evidence = plan(
        SingletonContext {
            elf: &elf,
            dynamic: &dynamic,
            s: &selected.selection,
            identity,
            fixed_binding: Some(binding),
            owned_neighbors: false,
            mode: disassembly::NeighborMode::WholeOverlappingPending,
            record_baseline: false,
        },
        schedule,
        draft,
        &mut accepted,
    );
    assert_eq!(evidence.len(), schedule.groups.len());
    accepted
}

#[test]
fn grouped_six_pop_carrier_retains_all_members_routes_and_one_image() {
    let (original, selected) = cat();
    let product = prepare_disassembly_jump_stack_grouped_fixed_exec(&original, &selected).unwrap();
    assert!(product.candidate_complete(), "{:?}", product.reports());
    assert!(!product.qualification_complete());
    assert_eq!(product.reports().len(), 6);
    assert!(product.reports().iter().all(|r| r.candidate_emitted
        && r.refusal.is_none()
        && r.core_tactic == Some(li2core::engine::Tactic::Relocation)));
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|p| p.starts_with("image-"))
            .count(),
        1
    );
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|p| p.starts_with("group-"))
            .count(),
        1
    );
    let text = std::str::from_utf8(&product.files()["ledger.tsv"]).unwrap();
    assert!(text.starts_with("LI2GROUPED-LEDGER\t1\n"));
    assert_eq!(text.lines().filter(|r| r.starts_with("step\t")).count(), 1);
    assert_eq!(
        text.lines()
            .filter(|r| r.starts_with("allocation\t"))
            .count(),
        1
    );
    assert_eq!(
        text.lines().filter(|r| r.starts_with("member\t")).count(),
        6
    );
    assert!(text.contains("accepted_member_count\t6\ncomplete_site_count\t6\n"));
    let routes: Vec<_> = text
        .lines()
        .filter(|r| r.starts_with("route\t"))
        .map(|r| r.split('\t').nth(2).unwrap().parse::<u64>().unwrap())
        .collect();
    assert_eq!(routes, [0, 1, 2, 5, 7, 9, 12, 14].map(|offset| PC + offset));
    let observed: Vec<_> = text
        .lines()
        .filter(|r| r.starts_with("field\t"))
        .map(|r| r.split('\t').collect::<Vec<_>>())
        .filter(|r| r[8] == ledger::hex(b"LogicalPc"))
        .map(|r| r[6].parse::<u64>().unwrap())
        .collect();
    assert_eq!(observed, [0, 1, 5, 7, 12, 14].map(|offset| PC + offset));
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        selected.packed_overlapping_files()["disassembly-inventory.tsv"]
    );
    assert_eq!(product.files()["selection.txt"], selected.manifest());
    assert!(text.contains("fixed-output-readback\tchecked\n"));
}

#[test]
fn grouped_policy_and_both_metadata_forms_bind_total_partition() {
    let (original, selected) = cat();
    let product = prepare_disassembly_jump_stack_grouped_fixed_exec(&original, &selected).unwrap();
    assert!(product.candidate_complete());
    let ordinary = Compatibility {
        planner: li2core::contracts::CONTRACT_VERSION,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&product.files()["target.tsv"]),
        binding: ContentId::of(&fixed_exec::binding_policy(
            product.fixed_image_binding().unwrap(),
            ContentId::of(selected.manifest()),
        )),
    };
    let declared = Compatibility {
        binding: ContentId::of(&product.files()["binding-policy.tsv"]),
        ..ordinary.clone()
    };
    assert_ne!(ordinary.binding, declared.binding);
    assert!(matches!(
        Metadata::decode(
            &product.files()["metadata.li2meta"],
            &ordinary,
            formats::Limits::default()
        ),
        Err(formats::Error::Incompatible)
    ));
    let decoded = Metadata::decode(
        &product.files()["metadata.li2meta"],
        &declared,
        formats::Limits::default(),
    )
    .unwrap();
    decoded
        .verify_selection(ContentId::of(selected.manifest()), &[1, 2, 3, 4, 5, 6])
        .unwrap();
    let policy = &product.files()["grouping-policy.tsv"];
    assert!(
        std::str::from_utf8(&product.files()["binding-policy.tsv"])
            .unwrap()
            .contains(&format!(
                "grouping_policy_sha256\t{}\n",
                ledger::hex(&ContentId::of(policy).0)
            ))
    );
    let mut changed = policy.clone();
    changed.push(b'!');
    let wrong = Compatibility {
        binding: ContentId::of(&fixed_exec::grouped_binding_policy(
            product.fixed_image_binding().unwrap(),
            ContentId::of(selected.manifest()),
            ContentId::of(&changed),
        )),
        ..declared
    };
    assert!(matches!(
        Metadata::decode(
            &product.files()["metadata.li2meta"],
            &wrong,
            formats::Limits::default()
        ),
        Err(formats::Error::Incompatible)
    ));
    let marker = b"LI2TOOL-CANDIDATE-UNREADY-V1\0";
    let bytes = &product.files()["candidate.elf"];
    let positions: Vec<_> = bytes
        .windows(marker.len())
        .enumerate()
        .filter_map(|(at, b)| (b == marker).then_some(at))
        .collect();
    assert_eq!(positions.len(), 1);
    let at = positions[0] + marker.len();
    assert_eq!(
        &bytes[at..at + 32],
        &ContentId::of(&product.files()["metadata.li2meta"]).0
    );
    assert_eq!(
        &bytes[at + 32..at + 64],
        &ContentId::of(&product.files()["plan-ledger.tsv"]).0
    );
}

#[test]
fn grouped_membership_mutations_refuse_without_singleton_fallback() {
    let (original, selected) = cat();
    let schedule =
        Schedule::freeze(&elf(&original), &selected.selection, &selected.classes).unwrap();
    assert_eq!(schedule.groups.len(), 1);
    assert!(schedule.singletons.is_empty());
    for mutation in 0..3 {
        let mut wrong = schedule.clone();
        match mutation {
            0 => {
                wrong.groups[0].members.remove(1);
            }
            1 => {
                wrong.groups[0].members.insert(1, 0);
            }
            _ => {
                wrong.groups[0].window = addr(PC, 15).unwrap();
            }
        }
        let mut state = draft(&original, &selected);
        let before = state.composition.clone();
        let pending = state.pending.clone();
        let accepted = run_group(&original, &selected, &wrong, &mut state);
        assert!(accepted.is_empty() && state.accepted.is_empty());
        assert_eq!(state.composition, before);
        assert_eq!(state.pending, pending);
        assert_eq!(
            (state.image_count, state.image_bytes, state.allocation_pages),
            (0, 0, 0)
        );
        for &index in &wrong.groups[0].members {
            assert_eq!(
                state.reports[index].refusal.as_ref().unwrap().stage,
                "grouped-membership"
            );
            assert!(state.reports[index].core_tactic.is_none());
        }
    }
    let mut wrong = selected.clone();
    wrong.selection.sites[1].hook += 1;
    let product = prepare_disassembly_jump_stack_grouped_fixed_exec(&original, &wrong).unwrap();
    assert_eq!(product.reports().len(), 6);
    assert!(!product.candidate_complete());
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.refusal.as_ref().unwrap().stage == "grouped-policy"
                && r.core_tactic.is_none())
    );
    assert!(!product.files().contains_key("candidate.elf"));
}

#[test]
fn grouped_jump_member_is_never_filtered_and_refusal_is_atomic() {
    let (original, selected) = source(&[&[0x53], &[0x31, 0xc0], &[0x5b], &[0x75, 0], &[0xc3]]);
    let schedule =
        Schedule::freeze(&elf(&original), &selected.selection, &selected.classes).unwrap();
    assert_eq!(schedule.groups[0].members, [0, 1, 2]);
    assert_eq!(
        schedule.classes,
        [
            JumpStackClass::PushRegister64,
            JumpStackClass::PopRegister64,
            JumpStackClass::Jump
        ]
    );
    assert!(
        std::str::from_utf8(&schedule.policy)
            .unwrap()
            .contains("\tjump\n")
    );
    // Make the declared end extend beyond the conditional in a private
    // hostile fixture. The real collector must reject, never trim the JMP.
    let mut wrong = selected.clone();
    for site in &mut wrong.selection.sites {
        site.block = addr(PC, 7).unwrap();
    }
    let mut schedule = Schedule::freeze(&elf(&original), &wrong.selection, &wrong.classes).unwrap();
    schedule.groups[0].window = addr(PC, 7).unwrap();
    let mut state = draft(&original, &wrong);
    let before = state.composition.clone();
    let accepted = run_group(&original, &wrong, &schedule, &mut state);
    assert!(accepted.is_empty());
    assert_eq!(state.composition, before);
    assert_eq!(state.pending.len(), 3);
    assert!(
        state
            .reports
            .iter()
            .all(|r| r.refusal_code == Some(10) && !r.candidate_emitted)
    );
}

#[test]
fn grouped_pending_and_resource_failures_leave_complete_draft_unmodified() {
    let (original, selected) = cat();
    let schedule =
        Schedule::freeze(&elf(&original), &selected.selection, &selected.classes).unwrap();
    let mut state = draft(&original, &selected);
    // A foreign outstanding interval lies in the window. Core must reject
    // ownership even though that interval is not one of the group members.
    state.pending.push((usize::MAX, addr(PC + 2, 3).unwrap()));
    state.pending.sort_by_key(|(_, r)| r.start());
    let before = state.composition.clone();
    let pending = state.pending.clone();
    assert!(run_group(&original, &selected, &schedule, &mut state).is_empty());
    assert_eq!(state.composition, before);
    assert_eq!(state.pending, pending);
    assert!(state.reports.iter().all(|r| r.refusal_code == Some(12)));
    // Shared aggregate limits are not multiplied by six. Start with the
    // existing counter at its unchanged ceiling; local B1 remains evidence.
    let mut state = draft(&original, &selected);
    state.image_count = selected.selection.limits.images;
    let before = state.composition.clone();
    let pending = state.pending.clone();
    assert!(run_group(&original, &selected, &schedule, &mut state).is_empty());
    assert_eq!(state.composition, before);
    assert_eq!(state.pending, pending);
    assert_eq!(
        (state.image_count, state.image_bytes, state.allocation_pages),
        (selected.selection.limits.images, 0, 0)
    );
    assert!(state.reports.iter().all(|r| r.core_tactic
        == Some(li2core::engine::Tactic::Relocation)
        && r.refusal.as_ref().unwrap().stage == "aggregate-budget"));
    let mut state = draft(&original, &selected);
    let first = run_group(&original, &selected, &schedule, &mut state);
    assert_eq!(first.len(), 1);
    state.pending = draft(&original, &selected).pending; // hostile outstanding replay
    let current = state.composition.clone();
    let pages = state.allocation_pages;
    assert!(run_group(&original, &selected, &schedule, &mut state).is_empty());
    assert_eq!(state.composition, current);
    assert_eq!(state.allocation_pages, pages);
    assert!(state.reports.iter().all(|r| r.refusal_code == Some(4)));
    // A real 250-observer image cannot borrow 250 member pages. The source
    // interval itself is within256, so the one-page fitting cap is reached.
    let pop = [0x5b];
    let ret = [0xc3];
    let chunks: Vec<_> = std::iter::repeat_n(pop.as_slice(), 250)
        .chain(std::iter::once(ret.as_slice()))
        .collect();
    let (original, selected) = source(&chunks);
    let refused = prepare_disassembly_jump_stack_grouped_fixed_exec(&original, &selected).unwrap();
    assert_eq!(refused.reports().len(), 250);
    assert!(!refused.candidate_complete());
    assert!(
        refused
            .reports()
            .iter()
            .all(|r| r.refusal_code == Some(11) && !r.candidate_emitted)
    );
    assert!(
        !refused
            .files()
            .keys()
            .any(|name| name.starts_with("image-"))
    );
}

#[test]
fn grouped_carrier_refusal_withholds_all_six_and_preserves_original_identity() {
    let (original, mut selected) = cat();
    selected.selection.carrier_pc = BASE; // Actual original LOAD collision.
    let product = prepare_disassembly_jump_stack_grouped_fixed_exec(&original, &selected).unwrap();
    assert_eq!(product.reports().len(), 6);
    assert!(!product.candidate_complete());
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.refusal_code == Some(10_002)
                && !r.candidate_emitted
                && r.core_tactic == Some(li2core::engine::Tactic::Relocation))
    );
    assert!(
        !product.files().contains_key("candidate.elf")
            && !product.files().contains_key("source.li2sparse")
    );
    let mut changed = original.clone();
    changed[0x1100] ^= 1;
    let error = prepare_disassembly_jump_stack_grouped_fixed_exec(&changed, &selected).unwrap_err();
    assert_eq!(error.stage, "original-identity");
}

#[test]
fn grouped_nongroup_route_retains_legacy_images_edits_and_outcomes() {
    let (original, selected) = source(&[
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x54],
        &[0xc3],
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x5c],
        &[0xc3],
    ]);
    let schedule =
        Schedule::freeze(&elf(&original), &selected.selection, &selected.classes).unwrap();
    assert!(schedule.groups.is_empty());
    assert_eq!(schedule.singletons.len(), 2);
    let old = prepare_disassembly_jump_stack_fixed_exec_packed_overlapping_neighbors(
        &original, &selected,
    )
    .unwrap();
    let new = prepare_disassembly_jump_stack_grouped_fixed_exec(&original, &selected).unwrap();
    assert!(old.candidate_complete() && new.candidate_complete());
    for name in [
        "selection.txt",
        "target.tsv",
        "disassembly-inventory.tsv",
        "disassembly-policy.txt",
        "report.tsv",
        "source.li2sparse",
        "image-0000.bin",
        "image-0001.bin",
    ] {
        assert_eq!(old.files()[name], new.files()[name], "{name}");
    }
    assert!(!old.files().contains_key("grouping-policy.tsv"));
    assert!(
        std::str::from_utf8(&old.files()["ledger.tsv"])
            .unwrap()
            .starts_with("LI2LEDGER\t1\n")
    );
    assert!(
        std::str::from_utf8(&new.files()["ledger.tsv"])
            .unwrap()
            .starts_with("LI2GROUPED-LEDGER\t1\n")
    );
    // A forced pun-only policy cannot be silently reinterpreted as B1.
    let (original, mut selected) = cat();
    for site in &mut selected.selection.sites {
        site.search.tactics = TacticPolicy::GeneralizedPunOnly;
    }
    let refused = prepare_disassembly_jump_stack_grouped_fixed_exec(&original, &selected).unwrap();
    assert!(
        refused
            .reports()
            .iter()
            .all(|r| r.refusal.as_ref().unwrap().stage == "grouped-policy")
    );
}

// Sibling upstream controls reuse the existing source fixture, not its tests.
pub(super) const UPSTREAM_BASE: u64 = BASE;
pub(super) const UPSTREAM_PC: u64 = PC;
pub(super) fn upstream_source(
    chunks: &[&[u8]],
) -> (Vec<u8>, disassembly::whole::JumpStackWholeSelection) {
    source(chunks)
}
pub(super) fn upstream_elf(bytes: &[u8]) -> Elf64<'_> {
    elf(bytes)
}
pub(super) fn upstream_draft(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
) -> adjacent_b2_frontend::SelectionDraft {
    draft(original, selected)
}
pub(super) fn upstream_run_group(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    schedule: &Schedule,
    state: &mut adjacent_b2_frontend::SelectionDraft,
) -> Vec<AcceptedGroup> {
    run_group(original, selected, schedule, state)
}
