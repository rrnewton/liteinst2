//! Handwritten original heads, lengths, target deltas and final source bytes.
//! No production decoder or planner computes the expected geometry.
use liteinst2::bundle::BundleBudget;
use liteinst2::contracts::*;
use liteinst2::eviction_chain::{ChainSearch, PlannedChain};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy};
use liteinst2::trampoline::HookCallback;

pub struct Case {
    pub name: &'static str,
    pub code: &'static [u8],
    pub heads: &'static [usize],
    pub lengths: &'static [usize],
    pub prefixes: &'static [usize],
    pub target_deltas: &'static [i64],
    pub final_bytes: &'static [u8],
}

pub const CASES: [Case; 3] = [
    Case {
        name: "chain-depth2-B2-1-and-3-byte-victims",
        // MOV EAX,EAX; NOP; LEA RCX,[RDI]; MOV EAX,imm32; MOV [RDI],RAX; RET.
        code: &[
            0x89, 0xc0, 0x90, 0x48, 0x8d, 0x0f, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0x07,
            0xc3,
        ],
        heads: &[0, 2, 3, 6, 11, 14],
        lengths: &[2, 1, 3, 5],
        prefixes: &[0, 0, 0],
        target_deltas: &[0x00e9e985, -0x167fff10, 0x56e98008, 0x04123461],
        final_bytes: &[
            0xe9, 0x80, 0xe9, 0xe9, 0x00, 0x80, 0xe9, 0x56, 0x34, 0x12, 0x04, 0x48, 0x89, 0x07,
            0xc3,
        ],
    },
    Case {
        name: "chain-depth3-B2-4-2-and-1-byte-victims",
        // LEA RCX,[RDI]; LEA RCX,[RDI+8]; MOV EAX,EAX; NOP;
        // LEA RDX,[RDI+0x11223344]; MOV [RDI],RCX; RET.
        code: &[
            0x48, 0x8d, 0x0f, 0x48, 0x8d, 0x4f, 0x08, 0x89, 0xc0, 0x90, 0x48, 0x8d, 0x97, 0x44,
            0x33, 0x22, 0x11, 0x48, 0x89, 0x0f, 0xc3,
        ],
        heads: &[0, 3, 7, 9, 10, 17, 20],
        lengths: &[3, 4, 2, 1, 7],
        prefixes: &[0, 0, 0, 0],
        target_deltas: &[0x00e98005, -0x167ffff8, 0x56e9e98c, 0x223456f7, 0x04223465],
        final_bytes: &[
            0xe9, 0x00, 0x80, 0xe9, 0x00, 0x00, 0x80, 0xe9, 0x80, 0xe9, 0xe9, 0x56, 0x34, 0x22,
            0x04, 0x22, 0x11, 0x48, 0x89, 0x0f, 0xc3,
        ],
    },
    Case {
        name: "chain-depth2-T1-P1-at-every-short-node",
        // MOV EAX,EAX; MOV ECX,ECX; MOV EDX,EDX; MOV EAX,imm32; MOV [RDI],RAX; RET.
        code: &[
            0x89, 0xc0, 0x89, 0xc9, 0x89, 0xd2, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0x07,
            0xc3,
        ],
        heads: &[0, 2, 4, 6, 11, 14],
        lengths: &[2, 2, 2, 5],
        prefixes: &[1, 1, 1],
        target_deltas: &[-0x16d116cc, 0x56e9e936, 0x323456f3, 0x04323461],
        final_bytes: &[
            0x2e, 0xe9, 0x2e, 0xe9, 0x2e, 0xe9, 0xe9, 0x56, 0x34, 0x32, 0x04, 0x48, 0x89, 0x07,
            0xc3,
        ],
    },
];

pub struct Fixture<'a> {
    pub case: &'a Case,
    pub base: u64,
    pub code: Vec<u8>,
    pub entries: LegalEntrySet,
    pub policies: Vec<AllocationPolicy>,
    pub targets: Vec<u64>,
    pub forced: Vec<u64>,
}

impl<'a> Fixture<'a> {
    pub fn new(case: &'a Case, base: u64) -> Self {
        let source = AddressRange::new(base, case.code.len()).unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity([0xc7; 32]),
            mapping: base,
            generation: 1,
        };
        let targets: Vec<_> = case
            .target_deltas
            .iter()
            .map(|&d| u64::try_from(i128::from(base) + i128::from(d)).unwrap())
            .collect();
        let policies = targets
            .iter()
            .map(|&target| AllocationPolicy {
                ranges: vec![AddressRange::new(target & !4095, 8192).unwrap()],
                preferred_address: Some(target),
                max_candidates: 1,
                max_mappings: 1,
                max_mapped_bytes: 8192,
            })
            .collect();
        Self {
            case,
            base,
            code: case.code.to_vec(),
            policies,
            targets,
            forced: case.heads[1..case.lengths.len()]
                .iter()
                .map(|&h| base + h as u64)
                .collect(),
            entries: LegalEntrySet {
                identity,
                scope: source,
                provenance: EntryProvenance::Declared(case.name.into()),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: case
                    .heads
                    .iter()
                    .map(|&h| LegalEntry {
                        address: base + h as u64,
                        requires_endbr: false,
                    })
                    .collect(),
                resumes: ResumeObligation::NoneExist,
            },
        }
    }
    pub fn request(&self, hook: HookCallback) -> InstallRequest<'_> {
        InstallRequest {
            identity: self.entries.identity,
            code: &self.code,
            base_address: self.base,
            function: AddressRange::new(self.base, self.code.len()).unwrap(),
            block: AddressRange::new(self.base, self.case.lengths[0]).unwrap(),
            logical_pc: self.base,
            entries: &self.entries,
            hook,
            semantics: HookSemantics::Observe,
            allocation: &self.policies[0],
            search: SearchPolicy {
                tactics: self.tactic(),
                max_upstream_bytes: 0,
                max_sites: 1,
                max_displaced_bytes: 15,
            },
        }
    }
    pub fn tactic(&self) -> TacticPolicy {
        if self.case.prefixes[0] == 0 {
            TacticPolicy::GeneralizedPunOnly
        } else {
            TacticPolicy::PrefixPunOnly
        }
    }
    pub fn search(&self) -> ChainSearch<'_> {
        ChainSearch {
            forced_successors: Some(&self.forced),
            max_short_successors: self.case.lengths.len() - 2,
            max_candidate_trials: self.case.lengths.len(),
            auxiliary_puns: self.tactic(),
        }
    }
    pub fn budget(&self) -> BundleBudget {
        BundleBudget {
            max_steps: self.case.lengths.len(),
            max_mappings: self.case.lengths.len(),
            max_virtual_bytes: self.case.lengths.len() as u64 * 8192,
            max_backing_bytes: self.case.lengths.len() as u64 * 8192,
            max_virtual_span: 1 << 32,
        }
    }
    pub fn assert_plan(&self, planned: &PlannedChain) {
        let n = self.case.lengths.len();
        let bundle = planned.bundle();
        assert_eq!(planned.nodes().len(), n);
        assert_eq!(bundle.plan().steps().len(), n);
        assert_eq!(bundle.images().len(), n);
        assert_eq!(
            bundle.plan().final_bytes(),
            &[ExpectedBytes {
                address: self.base,
                bytes: self.case.final_bytes.to_vec()
            }]
        );
        assert_eq!(bundle.plan().identity(), self.entries.identity);
        assert_eq!(planned.metrics().candidate_trials, n);
        assert!(!planned.metrics().global_cutoff);
        assert!(!planned.metrics().classification_complete);
        assert_eq!(
            planned.metrics().auxiliary_fallthrough_redirects,
            2 * (n - 1)
        );
        assert_eq!(
            planned
                .metrics()
                .attempts
                .iter()
                .filter(|a| a.complete_chain)
                .count(),
            1
        );
        assert_eq!(
            planned.metrics().discovery.short_successors,
            self.forced[..n - 2]
        );
        assert_eq!(planned.metrics().discovery.anchor, Some(self.forced[n - 2]));
        let mut overlay = self.code.clone();
        for (order, (step, image)) in bundle
            .plan()
            .steps()
            .iter()
            .zip(bundle.images())
            .enumerate()
        {
            let i = n - 1 - order;
            let pc = self.base + self.case.heads[i] as u64;
            let parts = step.parts();
            assert_eq!(parts.physical_pc, pc);
            assert_eq!(parts.logical_pc, pc);
            assert_eq!(
                parts.displaced,
                AddressRange::new(pc, self.case.lengths[i]).unwrap()
            );
            assert_eq!(
                parts.reads.as_slice(),
                &[ExpectedBytes {
                    address: self.base,
                    bytes: overlay.clone()
                }]
            );
            assert_eq!(image.address(), self.targets[i]);
            assert_eq!(image.entry_routes(), &[(pc, self.targets[i])]);
            assert_eq!(image.instruction_boundaries().len(), 1);
            assert_eq!(image.instruction_boundaries()[0].0, pc);
            assert_eq!(parts.generated[0].bytes, image.bytes());
            assert!(!parts.requirements.sigill_router);
            assert!(
                parts
                    .obligations
                    .iter()
                    .all(|item| matches!(item, EntryObligation::Preserved(_)))
            );
            let expected_prefix = if i + 1 == n {
                None
            } else {
                Some(self.case.prefixes[i] as u8)
            };
            assert_eq!(planned.nodes()[i].prefix_count, expected_prefix);
            assert_eq!(planned.nodes()[i].original, pc);
            assert_eq!(planned.nodes()[i].original_len, self.case.lengths[i]);
            assert_eq!(planned.nodes()[i].has_selected_hook, i == 0);
            assert_eq!(planned.nodes()[i].target, self.targets[i]);
            let attempt = &planned.metrics().attempts[order];
            assert_eq!(attempt.original, pc);
            assert_eq!(attempt.target, Some(self.targets[i]));
            assert_eq!(attempt.refusal, None);
            assert_eq!(attempt.leaf_search.accepted, i + 1 != n);
            let p = if i + 1 == n { 0 } else { self.case.prefixes[i] };
            let (store, consumed) = match &parts.kind {
                PlanKind::Relocation => {
                    assert_eq!(i, n - 1);
                    (None, AddressRange::new(pc, 5).unwrap())
                }
                PlanKind::GeneralizedPun(pun) => {
                    assert_eq!(p, 0);
                    (Some(&pun.store), pun.consumed)
                }
                PlanKind::PrefixedPun(pun) => {
                    assert_eq!(usize::from(pun.prefix_count), p);
                    (Some(&pun.store), pun.consumed)
                }
            };
            assert_eq!(consumed, AddressRange::new(pc, 5 + p).unwrap());
            let locked = if i + 1 == n {
                parts.displaced
            } else {
                consumed
            };
            assert!(
                bundle
                    .plan()
                    .locks()
                    .iter()
                    .any(|range| range.covers(locked)),
                "entire original/consumed interval must remain locked"
            );
            if let Some(store) = store {
                let span = AddressRange::new(store.address, store.bytes.len()).unwrap();
                assert!(
                    bundle.plan().locks().iter().any(|range| range.covers(span)),
                    "entire actual MOV span including padding must remain locked"
                );
            }
            for edit in &parts.writes {
                let start = (edit.address - self.base) as usize;
                overlay[start..start + edit.bytes.len()].copy_from_slice(&edit.bytes);
            }
            let h = self.case.heads[i];
            assert!(overlay[h..h + p].iter().all(|&b| b == 0x2e));
            assert_eq!(overlay[h + p], 0xe9);
            let displacement =
                i32::from_le_bytes(overlay[h + p + 1..h + p + 5].try_into().unwrap());
            assert_eq!(
                i128::from(pc) + 5 + p as i128 + i128::from(displacement),
                i128::from(self.targets[i])
            );
            if let Some(store) = store {
                let start = (store.address - self.base) as usize;
                assert_eq!(store.bytes, &overlay[start..start + store.bytes.len()]);
                assert_eq!(store.bytes.len(), self.case.lengths[i].next_power_of_two());
            }
        }
        assert_eq!(overlay, self.case.final_bytes);
        let memory = bundle.plan().memory();
        let ranges: Vec<_> = bundle
            .plan()
            .steps()
            .iter()
            .flat_map(|s| s.parts().allocations.iter().map(|a| a.range))
            .collect();
        assert_eq!(memory.mappings, n);
        assert_eq!(
            memory.virtual_bytes,
            ranges.iter().map(|r| r.len()).sum::<u64>()
        );
        assert_eq!(memory.backing_bytes, memory.virtual_bytes);
        assert_eq!(memory.virtual_pages as u64, memory.virtual_bytes / 4096);
        assert_eq!(
            memory.virtual_span,
            ranges.iter().map(|r| r.end()).max().unwrap()
                - ranges.iter().map(|r| r.start()).min().unwrap()
        );
        for i in 0..ranges.len() {
            for j in i + 1..ranges.len() {
                assert!(!ranges[i].overlaps(ranges[j]));
            }
        }
        for h in &self.case.heads[..n] {
            assert!(
                bundle
                    .plan()
                    .locks()
                    .iter()
                    .any(|range| range.contains(self.base + *h as u64))
            );
        }
    }
}
