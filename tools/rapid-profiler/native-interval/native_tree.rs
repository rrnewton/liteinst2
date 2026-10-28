//! Qualify the exact private baseline caller against a real no-op rewrite.
use super::{Path, STATE_SEEDS, current_single_main, oracle, tree};
use liteinst2::bundle::{BundleBudget, PlannedBundle, WritableAlias};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy,
    plan_coalesced_detailed_after_with_stack_profile,
};
use liteinst2::trampoline::{HookContext, ObservationStackProfile};
use oracle::native_ordinary::{ChildContext, OrdinaryOracle, Profile, Ready, call_tree};
use rapid_profiler::frontend_native::{LoadedCallTree, TreeContract};
#[path = "../tree-work/native_call.rs"]
mod call;
use call::NativeCall;

core::arch::global_asm!(
    ".pushsection .text",
    ".balign 16",
    ".global __rapid_profiler_native_tree_noop_v1",
    ".hidden __rapid_profiler_native_tree_noop_v1",
    ".type __rapid_profiler_native_tree_noop_v1,@function",
    "__rapid_profiler_native_tree_noop_v1:",
    "ret",
    ".size __rapid_profiler_native_tree_noop_v1,.-__rapid_profiler_native_tree_noop_v1",
    ".popsection",
);
unsafe extern "C" {
    fn __rapid_profiler_native_tree_noop_v1(context: *mut HookContext);
}

fn exclude(ranges: &mut Vec<AddressRange>, owned: AddressRange) {
    let mut remaining = Vec::new();
    for &range in ranges.iter() {
        if !range.overlaps(owned) {
            remaining.push(range);
            continue;
        }
        if range.start() < owned.start() {
            remaining.push(
                AddressRange::new(range.start(), (owned.start() - range.start()) as usize).unwrap(),
            );
        }
        if owned.end() < range.end() {
            remaining.push(
                AddressRange::new(owned.end(), (range.end() - owned.end()) as usize).unwrap(),
            );
        }
    }
    *ranges = remaining;
}
fn plan(owner: &LoadedCallTree) -> PlannedBundle {
    let certificate = owner.certificate();
    let root = certificate.root().entry();
    let child = certificate.callee().entry();
    let source = AddressRange::new(owner.source_range().0, owner.original_source().len()).unwrap();
    assert_eq!((source.len(), child), (4096, root + 32));
    let call = AddressRange::new(root + 9, 5).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0x6e; 32]),
        mapping: root,
        generation: 1,
    };
    let originals = vec![ExpectedBytes {
        address: source.start(),
        bytes: owner.original_source().to_vec(),
    }];
    let mut predecessor = Composition::new(identity, originals.clone()).unwrap();
    let pcs = [root, child, child + 38, root + 14, root + 22];
    let controls: [_; 5] = std::array::from_fn(|_| {
        let (control, writer) =
            ProbeControl::new_managed(__rapid_profiler_native_tree_noop_v1, true);
        drop(writer);
        control
    });
    let groups: [(usize, u64, usize, &[usize]); 4] = [
        (0, root, 9, &[0]),
        (0, root + 14, 9, &[3, 4]),
        (1, child, 8, &[1]),
        (1, child + 25, 14, &[2]),
    ];
    let mut reserved = vec![source];
    let mut overlays = [owner.root_code().to_vec(), owner.callee_code().to_vec()];
    let mut members = Vec::new();
    for (index, (function, start, length, roles)) in groups.into_iter().enumerate() {
        let (entry, code, heads, legal) = if function == 0 {
            (
                root,
                owner.root_code(),
                certificate.root().heads(),
                certificate.root().entries(),
            )
        } else {
            (
                child,
                owner.callee_code(),
                certificate.callee().heads(),
                certificate.callee().entries(),
            )
        };
        let scope = AddressRange::new(entry, code.len()).unwrap();
        let block = AddressRange::new(start, length).unwrap();
        let actions: Vec<_> = roles
            .iter()
            .map(|&i| ControlledAction {
                logical_pc: pcs[i],
                control: controls[i].clone(),
            })
            .collect();
        let logical = actions[0].logical_pc;
        let entries = LegalEntrySet {
            identity,
            scope,
            provenance: EntryProvenance::Declared(
                "closed native tree; sole external root; real E8 and root+14 saved continuation"
                    .into(),
            ),
            completeness: EntryCompleteness::Complete,
            entries: legal
                .iter()
                .map(|&address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: if function == 0 {
                ResumeObligation::Enumerated(vec![root + 14])
            } else {
                ResumeObligation::NoneExist
            },
        };
        let mut allocation = AllocationPolicy::near(root).unwrap();
        assert_eq!(
            (
                allocation.max_candidates,
                allocation.max_mappings,
                allocation.max_mapped_bytes
            ),
            (256, 1, 8192)
        );
        allocation.preferred_address = Some(
            (root & !4095)
                .checked_add(0x10_0000 + index as u64 * 0x1_0000)
                .unwrap(),
        );
        for &prior in &reserved {
            exclude(&mut allocation.ranges, prior);
        }
        let member = plan_coalesced_detailed_after_with_stack_profile(
            &InstallRequest {
                identity,
                code,
                base_address: entry,
                function: scope,
                block,
                logical_pc: logical,
                entries: &entries,
                hook: __rapid_profiler_native_tree_noop_v1,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: if logical == start { 0 } else { 64 },
                    max_displaced_bytes: 80,
                    max_sites: if logical == start { 1 } else { 65 },
                },
            },
            &actions,
            &predecessor,
            ObservationStackProfile::Tree144,
        )
        .unwrap();
        let p = member.plan().parts();
        assert_eq!(
            (p.kind.clone(), p.profile, p.identity),
            (
                PlanKind::Relocation,
                ApplicationProfile::InstallOnce,
                identity
            )
        );
        assert_eq!(p.entries, entries);
        assert_eq!(
            (p.logical_pc, p.physical_pc, p.displaced.end()),
            (
                logical,
                start,
                [root + 9, root + 23, child + 6, child + 39][index]
            )
        );
        assert!(block.covers(p.displaced) && !p.displaced.overlaps(call));
        assert_eq!(
            p.reads,
            [ExpectedBytes {
                address: entry,
                bytes: overlays[function].clone()
            }]
        );
        assert_eq!(p.writes.len(), 1);
        assert_eq!(
            (p.writes[0].address, p.writes[0].bytes.len() as u64),
            (start, p.displaced.len())
        );
        assert_eq!(
            member.image().layout().observation_stack_profile,
            ObservationStackProfile::Tree144
        );
        assert_eq!(
            member.image().controls(),
            actions
                .iter()
                .map(|a| a.control.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            member
                .image()
                .instruction_boundaries()
                .iter()
                .map(|&(p, _)| p)
                .collect::<Vec<_>>(),
            heads
                .iter()
                .copied()
                .filter(|&pc| p.displaced.contains(pc))
                .collect::<Vec<_>>()
        );
        assert!(actions.iter().all(|a| p.displaced.contains(a.logical_pc)));
        predecessor.append(member.plan()).unwrap();
        assert!(predecessor.locks().iter().all(|r| !r.overlaps(call)));
        for request in &p.allocations {
            assert!(reserved.iter().all(|r| !r.overlaps(request.range)));
            reserved.push(request.range);
        }
        for edit in &p.writes {
            assert!(
                !AddressRange::new(edit.address, edit.bytes.len())
                    .unwrap()
                    .overlaps(call)
            );
            let at = (edit.address - entry) as usize;
            assert_eq!(
                &overlays[function][at..at + edit.bytes.len()],
                &code[at..at + edit.bytes.len()]
            );
            overlays[function][at..at + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        members.push(member);
    }
    let planned = PlannedBundle::compose(
        originals,
        members,
        BundleBudget {
            max_steps: 4,
            max_mappings: 4,
            max_virtual_bytes: 4 * 8192,
            max_backing_bytes: 4 * 8192,
            max_virtual_span: 1 << 32,
        },
    )
    .unwrap();
    assert_eq!(planned.images().len(), 4);
    assert_eq!(planned.plan().final_bytes().len(), 1);
    let final_source = &planned.plan().final_bytes()[0];
    assert_eq!(final_source.address, source.start());
    assert_eq!(final_source.bytes.len(), 4096);
    let at = (root + 9 - source.start()) as usize;
    assert_eq!(&final_source.bytes[at..at + 5], &[0xe8, 0x12, 0, 0, 0]);
    planned
}
fn publish(planned: &PlannedBundle) {
    let bytes = &planned.plan().originals()[0];
    let source = AddressRange::new(bytes.address, bytes.bytes.len()).unwrap();
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|s| s.parts().allocations.iter().map(|a| a.range)),
    );
    let mut exclusive = planned;
    tree::protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    // SAFETY: sole actual child, exclusive original page and all generated
    // ranges; no entry, signal, writer, fork or resume during publication.
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let mut lease =
        unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
    let result = unsafe {
        planned.publish_with(&[alias], &mut lease, || {
            tree::protect(source, libc::PROT_READ | libc::PROT_EXEC)
        })
    };
    match result {
        Ok((installed, receipt)) => {
            assert!(!lease.is_poisoned());
            std::mem::forget((installed, receipt)); // Actual process-lifetime owners.
        }
        Err(error) => {
            eprintln!("native tree publication FAILED: {error:?}");
            std::process::abort();
        }
    }
}
fn child(candidate: bool, context: ChildContext<'_>, subject: &Path, expected: &[u8]) {
    current_single_main();
    let (case, seed) = context.tree_case().unwrap();
    assert_eq!(context.input(), call_tree::truth::input(case, seed));
    // SAFETY: closed fixed ABI and retained loader; sole calling thread, no
    // writers/foreign entry/CET/signal/nonlocal exit/fork/unload through return.
    let owner = unsafe {
        LoadedCallTree::load(
            subject,
            expected,
            c"call_tree_root",
            c"call_tree_child",
            TreeContract {
                root_only_external_entry: true,
                ordinary_ret_only: true,
                no_active_cet: true,
            },
        )
    }
    .unwrap();
    call_tree::truth::check_bytes(owner.root_code(), owner.callee_code()).unwrap();
    let mut call = unsafe { NativeCall::new(owner) };
    let owner = call.owner();
    let root = owner.certificate().root().entry();
    let heads: Vec<_> = owner
        .certificate()
        .root()
        .heads()
        .iter()
        .chain(owner.certificate().callee().heads())
        .copied()
        .collect();
    let original_source = owner.original_source().to_vec();
    let mut immutable = vec![(owner.source_range().0, original_source.clone())];
    let mut boundaries: Vec<_> = heads.iter().map(|&pc| (pc, pc)).collect();
    let planned = candidate.then(|| plan(owner));
    if let Some(planned) = &planned {
        let final_source = &planned.plan().final_bytes()[0];
        immutable[0] = (final_source.address, final_source.bytes.clone());
        boundaries.clear();
        for image in planned.images() {
            immutable.push((image.address(), image.bytes().to_vec()));
            boundaries.extend_from_slice(image.instruction_boundaries());
        }
        for &pc in &heads {
            if !boundaries.iter().any(|&(head, _)| head == pc) {
                boundaries.push((pc, pc));
            }
        }
        publish(planned);
    }
    let ready = Ready {
        profile: Profile::NativeCall,
        entry: root,
        gate: NativeCall::gate(),
        continuation: NativeCall::gate() + 13,
        heads,
        returns: vec![root + 22, root + 70],
        boundaries,
        immutable,
        original_source,
    };
    let data = context.input().as_ptr();
    let length = context.input().len();
    context.ready(&ready);
    // SAFETY: same exact qualified stencil, immutable inherited input; optional
    // candidate owns only fully preserving Tree144 no-op rewrites and real RETs.
    let value = unsafe { call.invoke(std::slice::from_raw_parts(data, length)) };
    assert_eq!(value, call_tree::truth::scalar(case, seed));
    assert_eq!(
        unsafe { std::slice::from_raw_parts(data, length) },
        call_tree::truth::input(case, seed)
    );
    for (address, bytes) in &ready.immutable {
        assert_eq!(
            unsafe { std::slice::from_raw_parts(*address as usize as *const u8, bytes.len()) },
            bytes
        );
    }
    if !candidate {
        call.verify_original();
    }
    std::mem::forget((call, planned));
}
pub fn run(subject: &Path, expected: &Path, output: &Path) {
    current_single_main();
    let expected = tree::expected_bytes(subject, expected);
    let noop = __rapid_profiler_native_tree_noop_v1 as *const () as usize as u64;
    let mut csv = String::from(
        "seed,case,status,children,comparisons,visits,original_steps,candidate_steps,value,outer_calls,subject_transfers,outer_returns,callback_visits\n",
    );
    for case in call_tree::truth::ALL {
        for seed in STATE_SEEDS {
            let oracle = OrdinaryOracle::new_tree(case, seed);
            let deadline = oracle.tree_deadline();
            let result = oracle.pair_tree_native_call(
                noop,
                |candidate, context| child(candidate, context, subject, &expected),
                |observed| {
                    let stats = call_tree::inspect_native(case, seed, observed);
                    assert_eq!(stats.counts, call_tree::truth::counts(case));
                },
            );
            assert_eq!(
                (result.comparisons, result.visits, result.value),
                (339, 332, call_tree::truth::scalar(case, seed))
            );
            assert_eq!(result.returns, result.declared_returns);
            assert_eq!(result.returns.len(), 2);
            assert!(std::time::Instant::now() < deadline);
            csv.push_str(&format!(
                "{seed},{},PASS,2,{},{},{},{},{},2,6,2,5\n",
                case.name(),
                result.comparisons,
                result.visits,
                result.original_steps,
                result.candidate_steps,
                result.value
            ));
        }
    }
    std::fs::write(output.join("native-tree.csv"), csv).unwrap();
    current_single_main();
    println!(
        "native-call-tree:required=4:pairs=4:children=8:comparisons=1356:outer-calls=8:subject-transfers=24:real-outer-ret=8:callback-visits=20:complete"
    );
}
